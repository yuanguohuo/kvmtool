#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/kvm.h>
#include <errno.h>

#include "kvm/kvm.h"
#include "kvm/irq.h"
#include "kvm/kvm-arch.h"

static u8 next_line = KVM_IRQ_OFFSET;
static int allocated_gsis = 0;

int next_gsi;

struct msi_routing_ops irq__default_routing_ops;
struct msi_routing_ops *msi_routing_ops = &irq__default_routing_ops;

//Yuanguo:
//  irq_routing是这样一张表。构建好之后，通过ioctl(vm_fd, KVM_SET_GSI_ROUTING, irq_routing)设置到内核kvm module中。以后要发起中断:
//
//    1. irqchip方式(8259A或者IOAPIC):
//        ioctl(kvm->vm_fd, KVM_IRQ_LINE, {.irq=gsi});
//        见x86/kvm.c : kvm__irq_trigger()
//
//    2. msi方式:
//        ioctl(kvm->vm_fd, KVM_SIGNAL_MSI, {.address_lo=x .address_hi=y, data=z});
//        见irq.c : irq__signal_msi()
//
//    所以中断虚拟化主要工作是kvm内核模块完成的，kvmtool只负责构建这张表。
//        - 对于irqchip方式，kvm内核模块模拟芯片(8259A或者IOAPIC)行为，更新芯片的相关寄存器，并唤醒guest vcpu，注入中断；
//        - 对于msi方式，kvm内核模块往guest的内存addr写data；内存addr映射的是vcpu的Local-APIC的寄存器；
//
//        | gsi | type                     | u.irqchip.irqchip            | u.irqchip.pin |
//        |-----|--------------------------|------------------------------|---------------|
//        | 0   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 0             |
//        | 1   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 1             |
//        |     |                          |                              |               |
//        | 3   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 3             |
//        | 4   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 4             |
//        | 5   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 5             |
//        | 6   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 6             |
//        | 7   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_MASTER(Master-8259A) | 7             |
//        | 8   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 0             |
//        | 9   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 1             |
//        | 10  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 2             |
//        | 11  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 3             |
//        | 12  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 4             |
//        | 13  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 5             |
//        | 14  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 6             |
//        | 15  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_SLAVE(Slave-8259A)   | 7             |
//        | 0   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 2             |
//        | 1   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 1             |
//        |     |                          |                              |               |
//        | 3   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 3             |
//        | 4   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 4             |
//        | 5   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 5             |
//        | 6   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 6             |
//        | 7   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 7             |
//        | 8   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 8             |
//        | 9   | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 9             |
//        | 10  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 10            |
//        | 11  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 11            |
//        | 12  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 12            |
//        | 13  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 13            |
//        | 14  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 14            |
//        | 15  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 15            |
//        | 16  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 16            |
//        | 17  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 17            |
//        | 18  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 18            |
//        | 19  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 19            |
//        | 20  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 20            |
//        | 21  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 21            |
//        | 22  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 22            |
//        | 23  | KVM_IRQ_ROUTING_IRQCHIP  | IRQCHIP_IOAPIC               | 23            |
//
//        | gsi | type                     | u.msi.address_hi | u.msi.address_lo | u.msi.data |
//        |-----|--------------------------|------------------|------------------|------------|
//        | 24  | KVM_IRQ_ROUTING_MSI      | 0x0              | 0xfee00000       | 0x4022     |
//        | 25  | KVM_IRQ_ROUTING_MSI      | 0x0              | 0xfee1f000       | 0x4021     |
//        | 26  | KVM_IRQ_ROUTING_MSI      | 0x0              | 0xfee01000       | 0x4022     |
//        | 27  | KVM_IRQ_ROUTING_MSI      | 0x0              | 0xfee02000       | 0x4022     |
//        | ... | ...                      | ...              | ...              | ...        |
struct kvm_irq_routing *irq_routing = NULL;

int irq__alloc_line(void)
{
	return next_line++;
}

int irq__get_nr_allocated_lines(void)
{
	return next_line - KVM_IRQ_OFFSET;
}

//Yuanguo:
//  本函数被调用之后，保证irq_routing->nr指向的entry可用，它就是新创建的entry;
//  所以，调用者可以通过
//        &irq_routing->entries[irq_routing->nr]
//  得到新建的entry。
//  可想而知，调用者还需要"递增irq_routing->nr"，表示他已经占用了irq_routing->nr指向的entry, 后续调用者只能占用下一个entry；
int irq__allocate_routing_entry(void)
{
	size_t table_size = sizeof(struct kvm_irq_routing);
	size_t old_size = table_size;
	int nr_entries = 0;

	if (irq_routing)
		nr_entries = irq_routing->nr;

	if (nr_entries < allocated_gsis)
		return 0;

	old_size += sizeof(struct kvm_irq_routing_entry) * allocated_gsis;
	allocated_gsis = ALIGN(nr_entries + 1, 32);
	table_size += sizeof(struct kvm_irq_routing_entry) * allocated_gsis;
	irq_routing = realloc(irq_routing, table_size);

	if (irq_routing == NULL)
		return -ENOMEM;
	memset((void *)irq_routing + old_size, 0, table_size - old_size);

	irq_routing->nr = nr_entries;
	irq_routing->flags = 0;

	return 0;
}

static bool check_for_irq_routing(struct kvm *kvm)
{
	static int has_irq_routing = 0;

	if (has_irq_routing == 0) {
		if (kvm__supports_extension(kvm, KVM_CAP_IRQ_ROUTING))
			has_irq_routing = 1;
		else
			has_irq_routing = -1;
	}

	return has_irq_routing > 0;
}

static int irq__update_msix_routes(struct kvm *kvm,
				   struct kvm_irq_routing_entry *entry)
{
	return ioctl(kvm->vm_fd, KVM_SET_GSI_ROUTING, irq_routing);
}

static bool irq__default_can_signal_msi(struct kvm *kvm)
{
	return kvm__supports_extension(kvm, KVM_CAP_SIGNAL_MSI);
}

static int irq__default_signal_msi(struct kvm *kvm, struct kvm_msi *msi)
{
	return ioctl(kvm->vm_fd, KVM_SIGNAL_MSI, msi);
}

struct msi_routing_ops irq__default_routing_ops = {
	.update_route	= irq__update_msix_routes,
	.signal_msi	= irq__default_signal_msi,
	.can_signal_msi	= irq__default_can_signal_msi,
};

bool irq__can_signal_msi(struct kvm *kvm)
{
	return msi_routing_ops->can_signal_msi(kvm);
}

int irq__signal_msi(struct kvm *kvm, struct kvm_msi *msi)
{
	return msi_routing_ops->signal_msi(kvm, msi);
}

int irq__add_msix_route(struct kvm *kvm, struct msi_msg *msg, u32 device_id)
{
	int r;
	struct kvm_irq_routing_entry *entry;

	if (!check_for_irq_routing(kvm))
		return -ENXIO;

	r = irq__allocate_routing_entry();
	if (r)
		return r;

	entry = &irq_routing->entries[irq_routing->nr];
	*entry = (struct kvm_irq_routing_entry) {
		.gsi = next_gsi,
		.type = KVM_IRQ_ROUTING_MSI,
		.u.msi.address_hi = msg->address_hi,
		.u.msi.address_lo = msg->address_lo,
		.u.msi.data = msg->data,
	};

	if (kvm->msix_needs_devid) {
		entry->flags = KVM_MSI_VALID_DEVID;
		entry->u.msi.devid = device_id;
	}

	irq_routing->nr++;

	r = msi_routing_ops->update_route(kvm, entry);
	if (r)
		return r;

	return next_gsi++;
}

static bool update_data(u32 *ptr, u32 newdata)
{
	if (*ptr == newdata)
		return false;

	*ptr = newdata;
	return true;
}

void irq__update_msix_route(struct kvm *kvm, u32 gsi, struct msi_msg *msg)
{
	struct kvm_irq_routing_msi *entry;
	unsigned int i;
	bool changed;

	for (i = 0; i < irq_routing->nr; i++)
		if (gsi == irq_routing->entries[i].gsi)
			break;
	if (i == irq_routing->nr)
		return;

	entry = &irq_routing->entries[i].u.msi;

	changed  = update_data(&entry->address_hi, msg->address_hi);
	changed |= update_data(&entry->address_lo, msg->address_lo);
	changed |= update_data(&entry->data, msg->data);

	if (!changed)
		return;

	if (msi_routing_ops->update_route(kvm, &irq_routing->entries[i]))
		die_perror("KVM_SET_GSI_ROUTING");
}

//Yuanguo: 原本device要给guest发中断是通过ioctl完成的：
//    1. irqchip方式(8259A或者IOAPIC):
//        ioctl(kvm->vm_fd, KVM_IRQ_LINE, {.irq=gsi});
//        见x86/kvm.c : kvm__irq_trigger()
//
//    2. msi方式:
//        ioctl(kvm->vm_fd, KVM_SIGNAL_MSI, {.address_lo=x .address_hi=y, data=z});
//        见irq.c : irq__signal_msi()
//函数irq__common_add_irqfd()是告诉kvm：发中断不再通过ioctl系统调用了，而是通过fd(即queue->irqfd)的写操作来完成：
//    - 用户态(例如vhost-user device?)发起中断：直接write(fd);
//    - 内核态(例如vhost device?)发起中断：eventfd_signal(...);
//
//问：virtio/vhost.c : virtio_vhost_signal_vq()函数中，为什么要read(queue->irqfd)呢？中断是发给guest的，又不是发给kvmtool的.
//答：猜测是起一个补漏的作用。当kvm或者guest没有poll queue->irqfd的时候，virtio_vhost_signal_vq()就会读到，
//    然后使用ioctl方式重发。
int irq__common_add_irqfd(struct kvm *kvm, unsigned int gsi, int trigger_fd,
			   int resample_fd)
{
	struct kvm_irqfd irqfd = {
		.fd		= trigger_fd,
		.gsi		= gsi,
		.flags		= resample_fd > 0 ? KVM_IRQFD_FLAG_RESAMPLE : 0,
		.resamplefd	= resample_fd,
	};

	/* If we emulate MSI routing, translate the MSI to the corresponding IRQ */
	if (msi_routing_ops->translate_gsi)
		irqfd.gsi = msi_routing_ops->translate_gsi(kvm, gsi);

	return ioctl(kvm->vm_fd, KVM_IRQFD, &irqfd);
}

void irq__common_del_irqfd(struct kvm *kvm, unsigned int gsi, int trigger_fd)
{
	struct kvm_irqfd irqfd = {
		.fd		= trigger_fd,
		.gsi		= gsi,
		.flags		= KVM_IRQFD_FLAG_DEASSIGN,
	};

	if (msi_routing_ops->translate_gsi)
		irqfd.gsi = msi_routing_ops->translate_gsi(kvm, gsi);

	ioctl(kvm->vm_fd, KVM_IRQFD, &irqfd);
}

int __attribute__((weak)) irq__exit(struct kvm *kvm)
{
	free(irq_routing);
	return 0;
}
dev_base_exit(irq__exit);
