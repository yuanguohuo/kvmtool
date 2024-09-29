#include "kvm/irq.h"
#include "kvm/virtio.h"
#include "kvm/epoll.h"

#include <linux/kvm.h>
#include <linux/vhost.h>
#include <linux/list.h>

#include <sys/eventfd.h>

static struct kvm__epoll epoll;

static void virtio_vhost_signal_vq(struct kvm *kvm, struct epoll_event *ev)
{
	int r;
	u64 tmp;
	struct virt_queue *queue = ev->data.ptr;

    //Yuanguo: queue->irqfd是向guest发起中断用的，vhost device通过write(queue->irqfd)向guest发起中断。
    //问：这里为什么要read(queue->irqfd)呢？中断是发给guest的，又不是发给kvmtool的；
    //答：猜测是起一个补漏的作用。当kvm或者guest没有poll queue->irqfd的时候，这里就会读到，
    //    然后使用ioctl方式重发。
	if (read(queue->irqfd, &tmp, sizeof(tmp)) < 0)
		pr_warning("%s: failed to read eventfd", __func__);

	r = queue->vdev->ops->signal_vq(kvm, queue->vdev, queue->index);
	if (r)
		pr_warning("%s failed to signal virtqueue", __func__);
}

static int virtio_vhost_start_poll(struct kvm *kvm)
{
	if (epoll.fd)
		return 0;

	if (epoll__init(kvm, &epoll, "vhost-irq-worker",
			virtio_vhost_signal_vq))
		return -1;

	return 0;
}

static int virtio_vhost_stop_poll(struct kvm *kvm)
{
	if (epoll.fd)
		epoll__exit(&epoll);
	return 0;
}
base_exit(virtio_vhost_stop_poll);

void virtio_vhost_init(struct kvm *kvm, int vhost_fd)
{
	struct kvm_mem_bank *bank;
	struct vhost_memory *mem;
	int i = 0, r;

	r = virtio_vhost_start_poll(kvm);
	if (r)
		die("Unable to start vhost polling thread\n");

	mem = calloc(1, sizeof(*mem) +
		     kvm->mem_slots * sizeof(struct vhost_memory_region));
	if (mem == NULL)
		die("Failed allocating memory for vhost memory map");

	list_for_each_entry(bank, &kvm->mem_banks, list) {
		mem->regions[i] = (struct vhost_memory_region) {
			.guest_phys_addr = bank->guest_phys_addr,
			.memory_size	 = bank->size,
			.userspace_addr	 = (unsigned long)bank->host_addr,
		};
		i++;
	}
	mem->nregions = i;

	r = ioctl(vhost_fd, VHOST_SET_OWNER);
	if (r != 0)
		die_perror("VHOST_SET_OWNER failed");

	r = ioctl(vhost_fd, VHOST_SET_MEM_TABLE, mem);
	if (r != 0)
		die_perror("VHOST_SET_MEM_TABLE failed");

	free(mem);
}

static int virtio_vhost_get_irqfd(struct virt_queue *queue)
{
	if (!queue->irqfd) {
		queue->irqfd = eventfd(0, 0);
		if (queue->irqfd < 0)
			die_perror("eventfd()");
	}
	return queue->irqfd;
}

void virtio_vhost_set_vring(struct kvm *kvm, int vhost_fd, u32 index,
			    struct virt_queue *queue)
{
	int r;
	struct vhost_vring_addr addr = {
		.index = index,
		.desc_user_addr = (u64)(unsigned long)queue->vring.desc,
		.avail_user_addr = (u64)(unsigned long)queue->vring.avail,
		.used_user_addr = (u64)(unsigned long)queue->vring.used,
	};
	struct vhost_vring_state state = { .index = index };
	struct vhost_vring_file file = {
		.index	= index,
		.fd	= virtio_vhost_get_irqfd(queue),
	};
	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = queue,
	};

	queue->index = index;

	if (queue->endian != VIRTIO_ENDIAN_HOST)
		die("VHOST requires the same endianness in guest and host");

	state.num = queue->vring.num;
	r = ioctl(vhost_fd, VHOST_SET_VRING_NUM, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_NUM failed");

	state.num = 0;
	r = ioctl(vhost_fd, VHOST_SET_VRING_BASE, &state);
	if (r < 0)
		die_perror("VHOST_SET_VRING_BASE failed");

	r = ioctl(vhost_fd, VHOST_SET_VRING_ADDR, &addr);
	if (r < 0)
		die_perror("VHOST_SET_VRING_ADDR failed");

	r = ioctl(vhost_fd, VHOST_SET_VRING_CALL, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_CALL failed");

	r = epoll_ctl(epoll.fd, EPOLL_CTL_ADD, file.fd, &event);
	if (r < 0)
		die_perror("EPOLL_CTL_ADD vhost call fd");
}

void virtio_vhost_set_vring_kick(struct kvm *kvm, int vhost_fd,
				 u32 index, int event_fd)
{
	int r;
	struct vhost_vring_file file = {
		.index	= index,
		.fd	= event_fd,
	};

	r = ioctl(vhost_fd, VHOST_SET_VRING_KICK, &file);
	if (r < 0)
		die_perror("VHOST_SET_VRING_KICK failed");
}

void virtio_vhost_set_vring_irqfd(struct kvm *kvm, u32 gsi,
				  struct virt_queue *queue)
{
	int r;
	int fd = virtio_vhost_get_irqfd(queue);

	if (queue->gsi)
		irq__del_irqfd(kvm, queue->gsi, fd);
	else
		/* Disconnect user polling thread */
		epoll_ctl(epoll.fd, EPOLL_CTL_DEL, fd, NULL);

    //Yuanguo: 原本device要给guest发中断是通过ioctl完成的：
    //    1. irqchip方式(8259A或者IOAPIC):
    //        ioctl(kvm->vm_fd, KVM_IRQ_LINE, {.irq=gsi});
    //        见x86/kvm.c : kvm__irq_trigger()
    //
    //    2. msi方式:
    //        ioctl(kvm->vm_fd, KVM_SIGNAL_MSI, {.address_lo=x .address_hi=y, data=z});
    //        见irq.c : irq__signal_msi()
    // 这里Connect the direct IRQFD route，就是告诉kvm：发中断不再通过ioctl系统调用了，而是通过fd(即queue->irqfd)的写操作来完成：
    //    - 用户态(例如vhost-user device?)发起中断：直接write(fd);
    //    - 内核态(例如vhost device?)发起中断：eventfd_signal(...);
    //
    //问：virtio_vhost_signal_vq()函数中，为什么要read(queue->irqfd)呢？中断是发给guest的，又不是发给kvmtool的.
    //答：猜测是起一个补漏的作用。当kvm或者guest没有poll queue->irqfd的时候，virtio_vhost_signal_vq()就会读到，
    //    然后使用ioctl方式重发。
	/* Connect the direct IRQFD route */
	r = irq__add_irqfd(kvm, gsi, fd, -1);
	if (r < 0)
		die_perror("KVM_IRQFD failed");

	queue->gsi = gsi;
}

void virtio_vhost_reset_vring(struct kvm *kvm, int vhost_fd, u32 index,
			      struct virt_queue *queue)

{
	struct vhost_vring_file file = {
		.index	= index,
		.fd	= -1,
	};

	if (!queue->irqfd)
		return;

	if (queue->gsi) {
		irq__del_irqfd(kvm, queue->gsi, queue->irqfd);
		queue->gsi = 0;
	}

	epoll_ctl(epoll.fd, EPOLL_CTL_DEL, queue->irqfd, NULL);

	if (ioctl(vhost_fd, VHOST_SET_VRING_CALL, &file))
		perror("SET_VRING_CALL");
	close(queue->irqfd);
	queue->irqfd = 0;
}

int virtio_vhost_set_features(int vhost_fd, u64 features)
{
	/*
	 * vhost interprets VIRTIO_F_ACCESS_PLATFORM as meaning there is an
	 * iotlb. Since this is not the case for kvmtool, mask it.
	 */
	u64 masked_feat = features & ~(1ULL << VIRTIO_F_ACCESS_PLATFORM);

	return ioctl(vhost_fd, VHOST_SET_FEATURES, &masked_feat);
}
