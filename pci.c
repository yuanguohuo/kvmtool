#include "kvm/devices.h"
#include "kvm/pci.h"
#include "kvm/ioport.h"
#include "kvm/irq.h"
#include "kvm/util.h"
#include "kvm/kvm.h"

#include <linux/err.h>
#include <assert.h>

static u32 pci_config_address_bits;

/* This is within our PCI gap - in an unused area.
 * Note this is a PCI *bus address*, is used to assign BARs etc.!
 * (That's why it can still 32bit even with 64bit guests-- 64bit
 * PCI isn't currently supported.)
 */
static u32 mmio_blocks			= KVM_PCI_MMIO_AREA;
static u16 io_port_blocks		= PCI_IOPORT_START;

u16 pci_get_io_port_block(u32 size)
{
	u16 port = ALIGN(io_port_blocks, PCI_IO_SIZE);

	io_port_blocks = port + size;
	return port;
}

/*
 * BARs must be naturally aligned, so enforce this in the allocator.
 */
u32 pci_get_mmio_block(u32 size)
{
	u32 block = ALIGN(mmio_blocks, size);
	mmio_blocks = block + size;
	return block;
}

void *pci_find_cap(struct pci_device_header *hdr, u8 cap_type)
{
	u8 pos;
	struct pci_cap_hdr *cap;

	pci_for_each_cap(pos, cap, hdr) {
		if (cap->type == cap_type)
			return cap;
	}

	return NULL;
}

int pci__assign_irq(struct pci_device_header *pci_hdr)
{
	/*
	 * PCI supports only INTA#,B#,C#,D# per device.
	 *
	 * A#,B#,C#,D# are allowed for multifunctional devices so stick
	 * with A# for our single function devices.
	 */
	pci_hdr->irq_pin	= 1;
	pci_hdr->irq_line	= irq__alloc_line();

	if (!pci_hdr->irq_type)
		pci_hdr->irq_type = IRQ_TYPE_LEVEL_HIGH;

	return pci_hdr->irq_line;
}

static bool pci_bar_is_implemented(struct pci_device_header *pci_hdr, int bar_num)
{
	return pci__bar_size(pci_hdr, bar_num);
}

static bool pci_bar_is_active(struct pci_device_header *pci_hdr, int bar_num)
{
	return  pci_hdr->bar_active[bar_num];
}

static void *pci_config_address_ptr(u16 port)
{
	unsigned long offset;
	void *base;

	offset	= port - PCI_CONFIG_ADDRESS;
	base	= &pci_config_address_bits;

	return base + offset;
}

static void pci_config_address_mmio(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				    u32 len, u8 is_write, void *ptr)
{
	void *p = pci_config_address_ptr(addr);

	if (is_write)
		memcpy(p, data, len);
	else
		memcpy(data, p, len);
}
static bool pci_device_exists(u8 bus_number, u8 device_number, u8 function_number)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);

	if (pci_config_address.bus_number != bus_number)
		return false;

	if (pci_config_address.function_number != function_number)
		return false;

	return !IS_ERR_OR_NULL(device__find_dev(DEVICE_BUS_PCI, device_number));
}

static void pci_config_data_mmio(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				 u32 len, u8 is_write, void *kvm)
{
	union pci_config_address pci_config_address;

	pci_config_address.w = ioport__read32(&pci_config_address_bits);
	/*
	 * If someone accesses PCI configuration space offsets that are not
	 * aligned to 4 bytes, it uses ioports to signify that.
	 */
	pci_config_address.reg_offset = addr - PCI_CONFIG_DATA;

	/* Ensure the access does not cross a 4-byte boundary */
	len = min(len, 4U - pci_config_address.reg_offset);

	if (is_write)
		pci__config_wr(vcpu->kvm, pci_config_address, data, len);
	else
		pci__config_rd(vcpu->kvm, pci_config_address, data, len);
}

static int pci_activate_bar(struct kvm *kvm, struct pci_device_header *pci_hdr,
			    int bar_num)
{
	int r = 0;

	if (pci_bar_is_active(pci_hdr, bar_num))
		goto out;

	r = pci_hdr->bar_activate_fn(kvm, pci_hdr, bar_num, pci_hdr->data);
	if (r < 0) {
		pci_dev_warn(pci_hdr, "Error activating emulation for BAR %d",
			     bar_num);
		goto out;
	}
	pci_hdr->bar_active[bar_num] = true;

out:
	return r;
}

static int pci_deactivate_bar(struct kvm *kvm, struct pci_device_header *pci_hdr,
			      int bar_num)
{
	int r = 0;

	if (!pci_bar_is_active(pci_hdr, bar_num))
		goto out;

	r = pci_hdr->bar_deactivate_fn(kvm, pci_hdr, bar_num, pci_hdr->data);
	if (r < 0) {
		pci_dev_warn(pci_hdr, "Error deactivating emulation for BAR %d",
			     bar_num);
		goto out;
	}
	pci_hdr->bar_active[bar_num] = false;

out:
	return r;
}

static void pci_config_command_wr(struct kvm *kvm,
				  struct pci_device_header *pci_hdr,
				  u16 new_command)
{
	int i;
	bool toggle_io, toggle_mem;

	toggle_io = (pci_hdr->command ^ new_command) & PCI_COMMAND_IO;
	toggle_mem = (pci_hdr->command ^ new_command) & PCI_COMMAND_MEMORY;

	for (i = 0; i < 6; i++) {
		if (!pci_bar_is_implemented(pci_hdr, i))
			continue;

		if (toggle_io && pci__bar_is_io(pci_hdr, i)) {
			if (__pci__io_space_enabled(new_command))
				pci_activate_bar(kvm, pci_hdr, i);
			else
				pci_deactivate_bar(kvm, pci_hdr, i);
		}

		if (toggle_mem && pci__bar_is_memory(pci_hdr, i)) {
			if (__pci__memory_space_enabled(new_command))
				pci_activate_bar(kvm, pci_hdr, i);
			else
				pci_deactivate_bar(kvm, pci_hdr, i);
		}
	}

	pci_hdr->command = new_command;
}

static int pci_toggle_bar_regions(bool activate, struct kvm *kvm, u32 start, u32 size)
{
	struct device_header *dev_hdr;
	struct pci_device_header *tmp_hdr;
	u32 tmp_start, tmp_size;
	int i, r;

	dev_hdr = device__first_dev(DEVICE_BUS_PCI);
	while (dev_hdr) {
		tmp_hdr = dev_hdr->data;
		for (i = 0; i < 6; i++) {
			if (!pci_bar_is_implemented(tmp_hdr, i))
				continue;

			tmp_start = pci__bar_address(tmp_hdr, i);
			tmp_size = pci__bar_size(tmp_hdr, i);
			if (tmp_start + tmp_size <= start ||
			    tmp_start >= start + size)
				continue;

			if (activate)
				r = pci_activate_bar(kvm, tmp_hdr, i);
			else
				r = pci_deactivate_bar(kvm, tmp_hdr, i);
			if (r < 0)
				return r;
		}
		dev_hdr = device__next_dev(dev_hdr);
	}

	return 0;
}

static inline int pci_activate_bar_regions(struct kvm *kvm, u32 start, u32 size)
{
	return pci_toggle_bar_regions(true, kvm, start, size);
}

static inline int pci_deactivate_bar_regions(struct kvm *kvm, u32 start, u32 size)
{
	return pci_toggle_bar_regions(false, kvm, start, size);
}

static void pci_config_bar_wr(struct kvm *kvm,
			      struct pci_device_header *pci_hdr, int bar_num,
			      u32 value)
{
	u32 old_addr, new_addr, bar_size;
	u32 mask;
	int r;

	if (pci__bar_is_io(pci_hdr, bar_num))
		mask = (u32)PCI_BASE_ADDRESS_IO_MASK;
	else
		mask = (u32)PCI_BASE_ADDRESS_MEM_MASK;

	/*
	 * If the kernel masks the BAR, it will expect to find the size of the
	 * BAR there next time it reads from it. After the kernel reads the
	 * size, it will write the address back.
	 *
	 * According to the PCI local bus specification REV 3.0: The number of
	 * upper bits that a device actually implements depends on how much of
	 * the address space the device will respond to. A device that wants a 1
	 * MB memory address space (using a 32-bit base address register) would
	 * build the top 12 bits of the address register, hardwiring the other
	 * bits to 0.
	 *
	 * Furthermore, software can determine how much address space the device
	 * requires by writing a value of all 1's to the register and then
	 * reading the value back. The device will return 0's in all don't-care
	 * address bits, effectively specifying the address space required.
	 *
	 * Software computes the size of the address space with the formula
	 * S =  ~B + 1, where S is the memory size and B is the value read from
	 * the BAR. This means that the BAR value that kvmtool should return is
	 * B = ~(S - 1).
	 */
    //Yuanguo:
    //  在真实环境下，PCI设备的每个BAR region的size是hard wired的，BIOS想要查
    //  一个BAR region的size，就往对应BAR寄存处写0xffffffff，然后再读回该BAR寄
    //  存器。
    //  若BAR region的size是S，那么读回的值B = ~(S - 1)
    //  BIOS就知道S = ~B + 1
	if (value == 0xffffffff) {
		value = ~(pci__bar_size(pci_hdr, bar_num) - 1);
		/* Preserve the special bits. */
		value = (value & mask) | (pci_hdr->bar[bar_num] & ~mask);
		pci_hdr->bar[bar_num] = value;
		return;
	}

	value = (value & mask) | (pci_hdr->bar[bar_num] & ~mask);

	/* Don't toggle emulation when region type access is disbled. */
	if (pci__bar_is_io(pci_hdr, bar_num) &&
	    !pci__io_space_enabled(pci_hdr)) {
		pci_hdr->bar[bar_num] = value;
		return;
	}

	if (pci__bar_is_memory(pci_hdr, bar_num) &&
	    !pci__memory_space_enabled(pci_hdr)) {
		pci_hdr->bar[bar_num] = value;
		return;
	}

	/*
	 * BAR reassignment can be done while device access is enabled and
	 * memory regions for different devices can overlap as long as no access
	 * is made to the overlapping memory regions. To implement BAR
	 * reasignment, we deactivate emulation for the region described by the
	 * BAR value that the guest is changing, we disable emulation for the
	 * regions that overlap with the new one (by scanning through all PCI
	 * devices), we enable emulation for the new BAR value and finally we
	 * enable emulation for all device regions that were overlapping with
	 * the old value.
	 */
	old_addr = pci__bar_address(pci_hdr, bar_num);
	new_addr = __pci__bar_address(value);
	bar_size = pci__bar_size(pci_hdr, bar_num);

	r = pci_deactivate_bar(kvm, pci_hdr, bar_num);
	if (r < 0)
		return;

	r = pci_deactivate_bar_regions(kvm, new_addr, bar_size);
	if (r < 0) {
		/*
		 * We cannot update the BAR because of an overlapping region
		 * that failed to deactivate emulation, so keep the old BAR
		 * value and re-activate emulation for it.
		 */
		pci_activate_bar(kvm, pci_hdr, bar_num);
		return;
	}

	pci_hdr->bar[bar_num] = value;
	r = pci_activate_bar(kvm, pci_hdr, bar_num);
	if (r < 0) {
		/*
		 * New region cannot be emulated, re-enable the regions that
		 * were overlapping.
		 */
		pci_activate_bar_regions(kvm, new_addr, bar_size);
		return;
	}

	pci_activate_bar_regions(kvm, old_addr, bar_size);
}

/*
 * Bits that are writable in the config space header.
 * Write-1-to-clear Status bits are missing since we never set them.
 */
static const u8 pci_config_writable[PCI_STD_HEADER_SIZEOF] = {
	[PCI_COMMAND] =
		PCI_COMMAND_IO |
		PCI_COMMAND_MEMORY |
		PCI_COMMAND_MASTER |
		PCI_COMMAND_PARITY,
	[PCI_COMMAND + 1] =
		(PCI_COMMAND_SERR |
		 PCI_COMMAND_INTX_DISABLE) >> 8,
	[PCI_INTERRUPT_LINE] = 0xff,
	[PCI_BASE_ADDRESS_0 ... PCI_BASE_ADDRESS_5 + 3] = 0xff,
	[PCI_CACHE_LINE_SIZE] = 0xff,
};

void pci__config_wr(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	void *base;
	u8 bar;
	u16 offset;
	struct pci_device_header *pci_hdr;
	u8 dev_num = addr.device_number;
	u32 value = 0, mask = 0;

	if (!pci_device_exists(addr.bus_number, dev_num, 0))
		return;

	offset = addr.w & PCI_DEV_CFG_MASK;
	base = pci_hdr = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;

	/* We don't sanity-check capabilities for the moment */
	if (offset < PCI_STD_HEADER_SIZEOF) {
		memcpy(&mask, pci_config_writable + offset, size);
		if (!mask)
			return;
	}

	if (pci_hdr->cfg_ops.write)
		pci_hdr->cfg_ops.write(kvm, pci_hdr, offset, data, size);

	if (offset == PCI_COMMAND) {
		memcpy(&value, data, size);
		pci_config_command_wr(kvm, pci_hdr, (u16)value & mask);
		return;
	}

	bar = (offset - PCI_BAR_OFFSET(0)) / sizeof(u32);
	if (bar < 6) {
		memcpy(&value, data, size);
		pci_config_bar_wr(kvm, pci_hdr, bar, value);
		return;
	}

	memcpy(base + offset, data, size);
}

void pci__config_rd(struct kvm *kvm, union pci_config_address addr, void *data, int size)
{
	u16 offset;
	struct pci_device_header *pci_hdr;
	u8 dev_num = addr.device_number;

	if (pci_device_exists(addr.bus_number, dev_num, 0)) {
		pci_hdr = device__find_dev(DEVICE_BUS_PCI, dev_num)->data;
		offset = addr.w & PCI_DEV_CFG_MASK;

		if (pci_hdr->cfg_ops.read)
			pci_hdr->cfg_ops.read(kvm, pci_hdr, offset, data, size);

		memcpy(data, (void *)pci_hdr + offset, size);
	} else {
		memset(data, 0xff, size);
	}
}

static void pci_config_mmio_access(struct kvm_cpu *vcpu, u64 addr, u8 *data,
				   u32 len, u8 is_write, void *kvm)
{
	union pci_config_address cfg_addr;

	addr			-= KVM_PCI_CFG_AREA;
	cfg_addr.w		= (u32)addr;
	cfg_addr.enable_bit	= 1;

	/*
	 * To prevent some overflows, reject accesses that cross a 4-byte
	 * boundary. The PCIe specification says:
	 *
	 *  "Root Complex implementations are not required to support the
	 *  generation of Configuration Requests from accesses that cross DW
	 *  [4 bytes] boundaries."
	 */
	if ((addr & 3) + len > 4)
		return;

	if (is_write)
		pci__config_wr(kvm, cfg_addr, data, len);
	else
		pci__config_rd(kvm, cfg_addr, data, len);
}

struct pci_device_header *pci__find_dev(u8 dev_num)
{
	struct device_header *hdr = device__find_dev(DEVICE_BUS_PCI, dev_num);

	if (IS_ERR_OR_NULL(hdr))
		return NULL;

	return hdr->data;
}

int pci__register_bar_regions(struct kvm *kvm, struct pci_device_header *pci_hdr,
			      bar_activate_fn_t bar_activate_fn,
			      bar_deactivate_fn_t bar_deactivate_fn, void *data)
{
	int i, r;

	assert(bar_activate_fn && bar_deactivate_fn);

	pci_hdr->bar_activate_fn = bar_activate_fn;
	pci_hdr->bar_deactivate_fn = bar_deactivate_fn;
	pci_hdr->data = data;

	for (i = 0; i < 6; i++) {
		if (!pci_bar_is_implemented(pci_hdr, i))
			continue;

		assert(!pci_bar_is_active(pci_hdr, i));

		if (pci__bar_is_io(pci_hdr, i) &&
		    pci__io_space_enabled(pci_hdr)) {
			r = pci_activate_bar(kvm, pci_hdr, i);
			if (r < 0)
				return r;
		}

		if (pci__bar_is_memory(pci_hdr, i) &&
		    pci__memory_space_enabled(pci_hdr)) {
			r = pci_activate_bar(kvm, pci_hdr, i);
			if (r < 0)
				return r;
		}
	}

	return 0;
}

int pci__init(struct kvm *kvm)
{
	int r;

    //Yuanguo:
    //
    // 一个物理PCI设备(物理卡)可能包含多个PCI function，一个PCI function是一个逻辑PCI设备，对OS而言，就是一个PCI设备。所以
    // 每个PCI function有自己独立的configuration space。
    // 下面说PCI设备，要是说它的configuration space，其实是指逻辑设备，即PCI function; 要是说硬件设备，其实是指物理卡。
    //
    // 真实环境下，BIOS/OS通过PCI_CONFIG_ADDRESS和PCI_CONFIG_DATA这两个port读写所有PCI function的所有configuration space
    // 寄存器，包括endpoint设备、PCI-to-PCI bridge(switch的port)。PCI_CONFIG_ADDRESS和PCI_CONFIG_DATA是PCI specification
    // 定义的，所以值是固定的。
    //
    // 具体地，
    //
    //     1. 先往 PCI_CONFIG_ADDRESS 写入目标寄存器的地址。
    //        因为目标寄存器可能是任何PCI function的任何寄存器，所以地址
    //        必须包含Bus#, Device#, Function#以及Register#
    //
    //         31                     24 23                    16 15           11 10      8 7                2   1   0
    //        +---+---------------------+------------------------+---------------+---------+------------------+---+---+
    //        |   |     Reserved        |          Bus#          |    Device#    |  Func#  |    Register#     | 0 | 0 |
    //        +---+---------------------+------------------------+---------------+---------+------------------+---+---+
    //          ^
    //          |
    //          Enable bit: 1=enabled 0=disbled
    //
    //     2. 然后读写PCI_CONFIG_DATA，就是读写目标寄存器。
    //
    // Bus enumeration也是通过这两个port完成的。
    //
    // 引用维基百科：
    //     When the computer is powered on, the PCI bus(es) and device(s) must be enumerated by BIOS or operating system.
    //     Bus enumeration is performed by attempting to access the PCI configuration space registers for each buses, devices
    //     and functions. Note that device number, different from VID and DID, is merely a device's sequential number on that
    //     bus. Moreover, after a new bridge is detected, a new bus number is defined, and device enumeration restarts at device
    //     number zero.
    //     If no response is received from the device's function #0, the bus master performs an abort and returns an all-bits-on
    //     value (FFFFFFFF in hexadecimal), which is an invalid VID/DID value, thus the BIOS or operating system can tell that the
    //     specified combination bus/device_number/function (B/D/F) is not present. In this case, reads to the remaining functions
    //     numbers (1–7) are not necessary as they also will not exist.
    //
    // BIOS/OS遍历各个bus以及bus上的slot；同时顺序分配bus#和device# (即从bus0开始，对于每个bus，从device0开始，以此循环...)
    // 对于一个bus上的一个slot，当前分配到busX, deviceY:
    //
    //     - 往PCI_CONFIG_ADDRESS 写入 0x80000000 | busX << 16 | deviceY << 11 | 0(function#) | VendorID-DeviceID Register#
    //     - 读PCI_CONFIG_DATA
    //
    // 若slot上没有设备，读到的数据是0xFFFFFFFF(非法VendorID/DeviceID)，继续下一个slot ...
    // 若slot上有设备(设备必须有function0，PCI规范要求的)，它就会响应，返回自己的VendorID/DeviceID。表示扫描到一个PCI设备，这个PCI设备
    // 也就被分配到busX:deviceY；它若有多个function, function#分别是0, 1, 2, ... 它也可能是一个PCI-to-PCI bridge(switch的port)，这样就
    // 产生一个新的bus。
    //
    // 问：slot上的设备如何决定自己要不要响应呢？这时设备还不知道自己将要分配到busX:deviceY，它响应之后才算分配到。这不是
    //       "鸡生蛋-蛋生鸡"的问题吗？
    // 答：这是硬件实现的。设备决定是否响应，不是看busX:deviceY是否指向自己(因为还没分配)，而是靠物理信号Initialization Device Select (IDSEL)，
    //     应该是此时硬件保证只有这个slot的IDSEL被点亮。设备只解析0-10bit，看目标是哪个function的哪个register。
    //     不止Bus enumeration时，以后任何对configuration space register的访问，设备都不是看busX:deviceY是否指向自己，都是靠IDSEL信号。
    //
    // 在虚拟环境下:
    //     1. VMM kvmtool根据user的命令行参数直接虚拟好PCI设备列表(相当于物理连接)，等着guest(BIOS/OS)来enumerate；
    //     2. 确实是靠对比bus#:device#判断指向哪个PCI设备(因为事先分配好了bus#:device#)，见pci__config_rd()和pci__config_wr()函数。
    //
    // kvmtool只虚拟出一条PCI bus，也没有明确bus#; 对比的时候，肯定是匹配的.
    // 为每个PCI设备(PCI function)分配device#，见devices.c : device__register().
    //
    // Bus enumeration的时候:
    //     - guest BIOS/OS往PCI_CONFIG_ADDRESS写入bus#:device#:function#:register#，会调用下面注册的pci_config_address_mmio()，保存到全局
    //       变量pci_config_address_bits.
    //     - 然后来读PCI_CONFIG_DATA，会调用下面注册的pci_config_data_mmio()，进而调用pci__config_rd(). 若有匹配的bus#:device#，则返回对应
    //       的configuration space register的值；否则返回0xffffffff. 注意：bus#的匹配实际上是拿pci_config_address_bits中的bus_number自己
    //       和自己匹配(因为kvmtool没有模拟多个bus).

    //Yuanguo:
    //  注册一个callback：[PCI_CONFIG_DATA, PCI_CONFIG_DATA+4字节) => pci_config_data_mmio
    //  当VM对这个地址空间发生读写时，就会导致vmexit；进而进入VMM(kvmtool)，调用pci_config_data_mmio函数.
	r = kvm__register_pio(kvm, PCI_CONFIG_DATA, 4,
				 pci_config_data_mmio, NULL);
	if (r < 0)
		return r;
    //Yuanguo:
    //  注册一个callback：[PCI_CONFIG_ADDRESS, PCI_CONFIG_ADDRESS+4字节) => pci_config_address_mmio
    //  当VM对这个地址空间发生读写时，就会导致vmexit；进而进入VMM(kvmtool)，调用pci_config_address_mmio函数.
    //  看pci_config_address_mmio的实现：
    //      - 拿全局变量pci_config_address_bits模拟VM的[PCI_CONFIG_ADDRESS, PCI_CONFIG_ADDRESS+4字节)区间；
    //      - VM写[PCI_CONFIG_ADDRESS, PCI_CONFIG_ADDRESS+4字节)里的第几字节，就写到pci_config_address_bits里的第几字节；
    //      - 读也一样；
	r = kvm__register_pio(kvm, PCI_CONFIG_ADDRESS, 4,
				 pci_config_address_mmio, NULL);
	if (r < 0)
		goto err_unregister_data;

    //Yuanguo:
    //  上面说，BIOS/OS读写任意PCI设备的任意configuration space register需要两次port io：先写PCI_CONFIG_ADDRESS锁定目标，再写数据PCI_CONFIG_DATA。
    //  这是legacy method，是original PCI的方式。因为一次读写要两次port io，所以it is referred to as "indirection".
    //  这种方式也叫做Configuration Access Mechanism (CAM).
    //
    //  下面这种方式was created for PCI Express，是一种新的方式，叫做Enhanced Configuration Access Mechanism (ECAM)。效果和上面的方法等价，都是读写
    //  任意PCI设备(PCI function)的任意configuration space register。只不过
    //     - ECAM是通过一次IO完成的，更便捷;
    //     - ECAM能访问更大的空间。对于一个PCI设备(PCI function)，Legacy CAM只能访问256B  configuration space (因为PCI的设备，configuration就是256B).
    //       PCIe设备(PCIe function)的configuration space是4K，所以要访问256B之后的部分，只能通过ECAM;
    //
    //  Enhanced Configuration Access Mechanism (ECAM):
    //      - 通过内存映射的方式，直接读写任意PCI设备(PCI function)的任意register；要访问某个PCI function的某个register, 直接读写它的address;
    //      - 关键是address怎么来的？大概是这样：
    //          - On x86 and x64 platforms, ACPI(Advanced Configuration and Power Interface)有一个'MCFG' table, table中有MMIO_Starting_Physical_Address，
    //            这就是base address of the ECAM region.
    //          - 有了base address，给定PCI function的给定register的address = MMIO_Starting_Physical_Address + ((Bus) << 20 | Device << 15 | Function << 12)
    //
    //  对于kvmtool：貌似KVM_PCI_CFG_AREA就是MMIO_Starting_Physical_Address，对于x86而言，定义在x86/include/kvm/kvm-arch.h中。
    //  遗留问题：guest怎么知道这个地址的？它需要这个base address来构造configuration space register的address。可能是架构定死的？arm和riscv也有这个宏的定义。
	r = kvm__register_mmio(kvm, KVM_PCI_CFG_AREA, PCI_CFG_SIZE, false,
			       pci_config_mmio_access, kvm);
	if (r < 0)
		goto err_unregister_addr;

	return 0;

    //Yuanguo:
    //
    //  小结:
    //     - 真实环境中，BIOS/OS需要能够读写系统中任意PCI设备(PCI function)的任意configuration space register, 就是通过CAM/ECAM完成的。能够读写所有configuration
    //       space register，就能够enumerate系统中所有PCI设备(PCI function)，并对它们进行配置，包括配置它们的BAR region。
    //     - 本函数模拟CAM/ECAM功能。有了这个功能，虚拟的guest BIOS/OS也就可以读写任意虚拟PCI设备的任意configuration space register，进而能够enumerate虚拟系统中的
    //       虚拟PCI设备，并对它们进行配置。不过，虚拟PCI设备的BAR region好像是kvmtool预先设置的，而不是guest BIOS/OS配置的，见 virtio/pci.c : virtio_pci__init()
    //
    //  注意本函数和virtio/pci.c : virtio_pci__init()的关系：
    //     - 相同点：都注册了一些callback，在guest访问某些memory的时候触发；
    //     - 不同点：本函数针对的是虚拟guest中所有虚拟PCI设备(PCI function)的configuration space; virtio_pci__init针对的是PCI设备的bar region; 即
    //         - guest系统enumerate或者配置PCI设备，触发本函数注册的callback；
    //         - guest系统访问某个PCI设备，例如访问网卡，触发virtio_pci__init注册的callback;
    //     - 另外：virtio_pci__init构造虚拟PCI设备，等着guest来enumerate, 顺序是这样的：
    //         1. 调用本函数注册CAM/ECAM callback;
    //         2. 调用virtio_pci__init：
    //              - 构造虚拟PCI设备；
    //              - 为虚拟PCI设备注册BAR region callback：用于设备的中断配置、正常读写。
    //         3. 本函数注册的CAM/ECAM callback被触发，完成enumerate以及一些配置；
    //         4. virtio_pci__init注册的BAR region callback被触发，完成PCI设备的中断配置、正常读写。

err_unregister_addr:
	kvm__deregister_pio(kvm, PCI_CONFIG_ADDRESS);
err_unregister_data:
	kvm__deregister_pio(kvm, PCI_CONFIG_DATA);
	return r;
}
dev_base_init(pci__init);

int pci__exit(struct kvm *kvm)
{
	kvm__deregister_pio(kvm, PCI_CONFIG_DATA);
	kvm__deregister_pio(kvm, PCI_CONFIG_ADDRESS);
	kvm__deregister_mmio(kvm, KVM_PCI_CFG_AREA);

	return 0;
}
dev_base_exit(pci__exit);
