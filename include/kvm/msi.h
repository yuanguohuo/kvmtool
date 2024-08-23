#ifndef LKVM_MSI_H
#define LKVM_MSI_H

//Yuanguo: https://en.wikipedia.org/wiki/Message_Signaled_Interrupts
//
//  - MSI (first defined in PCI 2.2) permits a device to allocate 1, 2, 4, 8, 16 or 32 interrupts. The device is programmed with an address
//    to write to (this address is generally a control register in an interrupt controller), and a 16-bit data word to identify it. The interrupt
//    number is added to the data word to identify the interrupt. Some platforms such as Windows do not use all 32 interrupts but only use up to
//    16 interrupts.
//
//  - MSI-X (first defined in PCI 3.0) permits a device to allocate up to 2048 interrupts. The single address used by original MSI was found to be
//    restrictive for some architectures. In particular, it made it difficult to target individual interrupts to different processors, which is helpful
//    in some high-speed networking applications. MSI-X allows a larger number of interrupts and gives each one a separate target address and data word.
//    Devices with MSI-X do not necessarily support 2048 interrupts. Optional features in MSI (64-bit addressing and interrupt masking) are also mandatory
//    with MSI-X.
//
//BIOS或者OS对pci设备编程(即读写PCI设备的registers)，往pci设备的MSI-X table中写入一些struct msi_msg结构体。一个struct msi_msg结构体represents one
//interrupt vector，所以一个PCI设备可以触发多个number不同的interrupt；每个interrupt vector对应PCI设备的一个queue.
//
//注意一个区别：
//
//  - 对于MSI，data是用于identify PCI设备的数字，是系统分配的————系统对PCI设备编程，告诉PCI设备这个数字。PCI设备发中断时，拿data加上interrupt number(应该就是
//    interrupt vector)得到一个新的数字，然后往给定地址上写这个新数字。
//
//  - 对于MSI-X，data是系统分配的，直接对应一个中断；PCI设备发中断时，直接往给定地址写这个数字。这一点在kvmtool实验中可以证实。
struct msi_msg {
	u32	address_lo;	/* low 32 bits of msi message address */
	u32	address_hi;	/* high 32 bits of msi message address */
	u32	data;		/* 16 bits of msi message data */
};

#endif /* LKVM_MSI_H */
