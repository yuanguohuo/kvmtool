#ifndef LKVM_MSI_H
#define LKVM_MSI_H

//Yuanguo: https://en.wikipedia.org/wiki/Message_Signaled_Interrupts
//
//  The device is programmed with an address to write to (this address is generally a control register in an interrupt controller), and a 16-bit
//  data word to identify it. The interrupt number is added to the data word to identify the interrupt.
//
//  BIOS或者OS对pci设备编程(即读写PCI设备的registers)，往pci设备的MSI-X table中写入一些struct msi_msg结构体。一个struct msi_msg结构体represents one
//  interrupt vector，所以一个PCI设备可以触发多个number不同的interrupt；每个interrupt vector对应PCI设备的一个queue.
//
//  一个struct msi_msg结构体包含：
//     - address (address_hi:address_lo): 映射到CPU的Local APIC的寄存器；
//     - 16-bit data word to identify it: 应该是queue的ID.
//
// PCI设备发起中断时:
//     - 往给定address写: (queue的ID(16-bit) << 16) | interrupt-number(16-bit)；即写到Local APIC的寄存器中。这样OS就知道是哪个queue发起的中断以及中断号。
//     - 若对应的interrupt vector被masked，就置位PBA中的对应bit；当interrupt unmask时，就往给定address写，并清除PBA中的对应bit；
struct msi_msg {
	u32	address_lo;	/* low 32 bits of msi message address */
	u32	address_hi;	/* high 32 bits of msi message address */
	u32	data;		/* 16 bits of msi message data */
};

#endif /* LKVM_MSI_H */
