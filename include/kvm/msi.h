#ifndef LKVM_MSI_H
#define LKVM_MSI_H

//Yuanguo: https://en.wikipedia.org/wiki/Message_Signaled_Interrupts
//
//  The device is programmed with an address to write to (this address is generally a control register in an interrupt controller), and a 16-bit
//  data word to identify it. The interrupt number is added to the data word to identify the interrupt.
//
// BIOS或者OS对pci设备编程(即读写pci设备的registers)，往pci设备的register中写入一个msi_msg结构体，告诉pci设备：
//     - address (address_hi:address_lo)
//     - 16-bit data word to identify it
// 以后，pci设备要发起中断，就往address处写数据。
struct msi_msg {
	u32	address_lo;	/* low 32 bits of msi message address */
	u32	address_hi;	/* high 32 bits of msi message address */
	u32	data;		/* 16 bits of msi message data */
};

#endif /* LKVM_MSI_H */
