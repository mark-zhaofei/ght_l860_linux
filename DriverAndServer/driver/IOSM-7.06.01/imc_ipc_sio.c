/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <stdbool.h>		/* C99 bool: true, false.  */

#include "imc_ipc_dbg.h"
#include "imc_ipc_util.h"
#include "imc_ipc_sio.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_params.h"
#include "imc_ipc_completion.h"

#define IPC_READ_TIMEOUT	500

/* maximum length of the SIO devices names */
#define IPC_SIO_DEVNAME_LEN	32

/* The delay in ms for defering the unregister
 */
#define SIO_UNREGISTER_DEFER_DELAY_MS	1

/* State of the char driver layer.
 */
struct ipc_sio {
	/* OS misc device component */
	struct miscdevice   misc;

	/* OS work_struct component to defer removal to process */
	struct work_struct  work;

	/* Device name */
	char                devname[IPC_SIO_DEVNAME_LEN];

	/* Callback interface */
	struct ipc_sio_ops  ops;
	void               *ops_instance;

	/* debug log component */
	struct ipc_dbg    *dbg;

	/* PCIe component */
	struct ipc_pcie    *pcie;

	/* Params component */
	struct ipc_params  *params;

	/* channel ID as received from ipc_sio_ops.open */
	int                 channel_id;

	/* Downlink skbuf list received from CP. */
	struct sk_buff_head rx_list;

	/* storage for skb when its data has not been fully read */
	struct sk_buff     *rx_pending_buf;

	/* Needed for the blocking read or downlink transfer. */
	struct ipc_completion read_sem;

	/* Read and write queues to support the poll system call. */
	wait_queue_head_t   poll_inq;
	wait_queue_head_t   poll_outq;

	/* reference counting to make sure we wait after unregister until
	 * all file operations have finished.
	 */
	struct ipc_util_refcount refcount;

	/* Open count. When negative, struct ipc_sio is freed.
	 * Also, restricts number of concurrent open operations to one
	 */
	atomic_t            open_count;

	/* Flag indicates that dtor has been called. This makes sure dtor is
	 * only executed once.
	 */
	atomic_t            dtor_called;
};


static void ipc_sio_free_worker(struct work_struct *work);
static void ipc_sio_free_if_unused(struct ipc_sio *this);


/* Configure the CP control device.
 */
static long ipc_sio_fop_unlocked_ioctl(struct file *filp, unsigned int cmd,
	unsigned long arg)
{
	switch (cmd) {
	case TCGETS:
	case TCSETS:
		return 0;
	default:
		return -ENOTTY;
	}
}

/* Open a shared memory device and initialize the head of the rx skbuf list.
 */
static int ipc_sio_fop_open(struct inode *inode, struct file *filp)
{
	struct ipc_sio *this = NULL;
	int rc = 0;

	if (unlikely(!inode || !filp)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this = container_of(filp->private_data, struct ipc_sio, misc);

	if (unlikely(!this || !this->ops.open || !this->ops_instance)) {
		ipc_err("invalid ops pointer");
		return -EINVAL;
	}

	if (unlikely(atomic_read(&this->open_count) > 0 ||
		!ipc_util_refcount_try_get(&this->refcount)))
		return -EPERM;

	this->channel_id = this->ops.open(this->ops_instance);
	if (this->channel_id >=  0)
		atomic_inc(&this->open_count); /* Success. */
	else
		rc = -EPERM;

	ipc_util_refcount_put(&this->refcount);

	return rc;
}

/* Close a shared memory control device and free the rx skbuf list.
 */
static int ipc_sio_fop_release(struct inode *inode, struct file *filp)
{
	struct ipc_sio *this = NULL;

	if (unlikely(!inode || !filp)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this = container_of(filp->private_data, struct ipc_sio, misc);

	if (unlikely(!this)) {
		ipc_err("invalid this pointer");
		return -EINVAL;
	}

	if (likely(ipc_util_refcount_try_get(&this->refcount))) {
		if (this->ops.close && this->ops_instance &&
			this->channel_id >= 0)
			this->ops.close(this->ops_instance, this->channel_id);
		this->channel_id = -1;
		ipc_util_refcount_put(&this->refcount);
	}

	ipc_sio_free_if_unused(this);

	return 0;
}

/* Copy the rx data to the user space buffer and free the skbuf.
 */
static ssize_t ipc_sio_copy_to_user(struct ipc_sio *this, char *buf,
	size_t size, struct sk_buff *skb)
{
	unsigned char *src_buf;
	char *dest_buf, *dest_end;
	size_t copied_b, dest_len, src_len;

	if (unlikely(!this)) {
		ipc_err("invalid args");
		return -1;
	}

	/* Prepare the destination space.
	 */
	dest_buf = buf;
	dest_end = dest_buf + size;
	copied_b = 0;

	/* Copy the accumulated rx packets.
	 */
	while (skb) {
		/* Prepare the source elements.
		 */
		src_buf = skb->data;
		src_len = skb->len;

		/* Calculate the current size of the destination buffer.
		 */
		dest_len = dest_end - dest_buf;

		/* Compute the number of bytes to copy.
		 */
		copied_b = (dest_len < src_len) ? dest_len : src_len;

		/* Copy the chars into the user space buffer.
		 */
		if (copy_to_user(dest_buf, src_buf, copied_b) != 0) {
			ipc_err("chid[%d] userspace copy failed n=%zu",
				this->channel_id, copied_b);
			ipc_pcie_kfree_skb(this->pcie, skb);
			return -1;
		}

		/* Update the source elements.
		 */
		skb->data = src_buf + copied_b;
		skb->len -= copied_b;

		/* Update the desctination pointer.
		 */
		dest_buf += copied_b;

		/* Test the fill level of the user buffer.
		 */
		if (dest_buf >= dest_end) {
			/* Free the consumed skbuf or save the pending skbuf
			 * to consume it in the read call.
			 */
			if (skb->len == 0)
				ipc_pcie_kfree_skb(this->pcie, skb);
			else
				this->rx_pending_buf = skb;

			/* Return the number of saved chars.
			 */
			break;
		}

		/* Free the consumed skbuf.
		 */
		ipc_pcie_kfree_skb(this->pcie, skb);

		/* Get the next skbuf element.
		 */
		skb = skb_dequeue(&this->rx_list);
	}			/* end while */

	/* Return the number of saved chars.
	 */
	copied_b = dest_buf - buf;
	return copied_b;
}

/* Get the first element of the skbuf list, copy the data to the user buffer
 * and free the skbuf.
 */
static ssize_t ipc_sio_fop_read(struct file *filp,
	char *buf, size_t size, loff_t *l)
{
	struct ipc_sio *this = NULL;
	bool is_blocking;
	struct sk_buff *skb = NULL;
	ssize_t len;

	if (unlikely(!filp || !buf)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this = container_of(filp->private_data, struct ipc_sio, misc);

	if (unlikely(!this)) {
		ipc_err("invalid argument");
		return -EINVAL;
	}

	is_blocking = (filp->f_flags & O_NONBLOCK) == 0;

	/* only log in blocking mode to reduce flooding the log */
	if (is_blocking)
		ipc_dbg("chid[%d] size=%zu", this->channel_id, size);

	if (unlikely(!ipc_util_refcount_try_get(&this->refcount)))
		return -EPERM;

	/* First provide the pending skbuf to the user.
	 */
	if (this->rx_pending_buf) {
		skb = this->rx_pending_buf;
		this->rx_pending_buf = NULL;
	}

	/* Check rx queue until skb is available */
	while (!skb) {
		skb = skb_dequeue(&this->rx_list);
		if (skb)
			break;

		if (!is_blocking) {
			len = -EAGAIN;
			goto done;
		}

		/* Suspend the user app and wait a certain time for data
		 * from CP.
		 */
		if (ipc_completion_wait_interruptible_timeout_ms(
			&this->read_sem, IPC_READ_TIMEOUT) < 0) {
			len = -EINTR;
			goto done;
		}

		ipc_util_refcount_put(&this->refcount);
		if (unlikely(!ipc_util_refcount_try_get(&this->refcount)))
			return -EPERM;
	}

	len = ipc_sio_copy_to_user(this, buf, size, skb);

	ipc_dbg("chid[%d] to user: len=%zd", this->channel_id, len);

done:
	ipc_util_refcount_put(&this->refcount);

	return len;
}

/* Route the user data to the shared memory layer.
 */
static ssize_t ipc_sio_fop_write(struct file *filp, const char *buf,
	size_t size, loff_t *l)
{
	struct ipc_sio *this = NULL;
	bool blocking;
	ssize_t rc = 0;

	if (unlikely(!filp || !buf)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this = container_of(filp->private_data, struct ipc_sio, misc);
	blocking = (filp->f_flags & O_NONBLOCK) == 0;

	if (unlikely(!this)) {
		ipc_err("invalid this pointer");
		return -EINVAL;
	}

	ipc_dbg("chid[%d] size=%d", this->channel_id, (int)size);

	if (unlikely(!this->ops.write || this->channel_id < 0))
		return -EPERM;

	if (unlikely(!ipc_util_refcount_try_get(&this->refcount)))
		return -EPERM;

	rc = this->ops.write(this->ops_instance, this->channel_id,
		(const unsigned char *)buf, size, blocking);

	ipc_util_refcount_put(&this->refcount);

	return rc;
}

/* Applications that use nonblocking I/O often use the poll, select, and epoll
 * system calls as well. poll, select, and epoll have essentially the same
 * functionality: each allow a process to determine whether it can read from or
 * write to one or more open files without blocking.
 * This support (for all three calls) is provided through the driver's poll
 * method.
 *
 * The device method is in charge of these two steps:
 * Call poll_wait on one or more wait queues that could indicate a change in
 * the poll status. If no file descriptors are currently available for I/O, the
 * kernel causes the process to wait on the wait queues for all file descriptors
 * passed to the system call.
 * Return a bit mask describing the operations (if any) that could be
 * immediately performed without blocking.
 * POLLIN
 *    This bit must be set if the device can be read without blocking.
 * POLLRDNORM
 *    This bit must be set if "normal" data is available for reading. A readable
 *    device returns (POLLIN | POLLRDNORM).
 * POLLOUT
 *    This bit is set in the return value if the device can be written to
 *    without blocking.
 * POLLWRNORM
 *    This bit has the same meaning as POLLOUT, and sometimes it actually is the
 *     same number. A writable device returns (POLLOUT | POLLWRNORM).
 */
static unsigned int ipc_sio_fop_poll(struct file *filp, poll_table *wait)
{
	struct ipc_sio *this = NULL;
	unsigned int mask = POLLOUT | POLLWRNORM; /* writable */

	if (unlikely(!filp)) {
		ipc_err("invalid arguments");
		return -EINVAL;
	}

	this = container_of(filp->private_data,	struct ipc_sio, misc);

	if (unlikely(!this)) {
		ipc_err("invalid this pointer");
		return -EINVAL;
	}

	if (unlikely(!ipc_util_refcount_try_get(&this->refcount)))
		return -EINVAL;

	/* Just registers wait_queue hook. This doesn't really wait.
	 */
	poll_wait(filp, &this->poll_inq, wait);

	/* Test the fill level of the skbuf rx queue.
	 */
	if (!skb_queue_empty(&this->rx_list) || this->rx_pending_buf)
		mask |= POLLIN | POLLRDNORM;	/* readable */

	ipc_util_refcount_put(&this->refcount);

	return mask;
}


/**
 * Refer to header file for description
 */
int ipc_sio_receive(struct ipc_sio *this, struct sk_buff *skb)
{
	if (unlikely(!this || !skb)) {
		ipc_err("invalid argument");
		return -EINVAL;
	}

	ipc_dbg("[c-id:%d]: %d", this->channel_id, skb->len);

	skb_queue_tail(&this->rx_list, skb);

	ipc_completion_signal(&this->read_sem);
	wake_up_interruptible(&this->poll_inq);

	return 0;
}

/* Ipc sio constructor function
 */
static int ipc_sio_ctor(struct ipc_sio *this, struct ipc_dbg *dbg,
	struct ipc_pcie *pcie, struct ipc_params *params,
	struct ipc_sio_ops *ops, void *ops_instance, const char *name)
{
	static const struct file_operations fops = {
		.owner          = THIS_MODULE,
		.open           = ipc_sio_fop_open,
		.release        = ipc_sio_fop_release,
		.read           = ipc_sio_fop_read,
		.write          = ipc_sio_fop_write,
		.poll           = ipc_sio_fop_poll,
		.unlocked_ioctl = ipc_sio_fop_unlocked_ioctl,
	};

	if (unlikely(!ops || !ops->open || !ops->close ||
		!ops->write || !ops_instance || !pcie)) {
		ipc_err("invalid args");
		return -1;
	}

	this->dbg = dbg;
	this->pcie = pcie;
	this->params = params;
	this->ops = *ops;
	this->ops_instance = ops_instance;

	this->channel_id = -1;
	atomic_set(&this->open_count, 0);
	atomic_set(&this->dtor_called, 0);

	ipc_completion_init(&this->read_sem);

	skb_queue_head_init(&this->rx_list);
	this->rx_pending_buf = NULL;
	init_waitqueue_head(&this->poll_inq);
	init_waitqueue_head(&this->poll_outq);

	INIT_WORK(&this->work, ipc_sio_free_worker);

	strncpy(this->devname, name, sizeof(this->devname) - 1);
	this->devname[IPC_SIO_DEVNAME_LEN-1] = '\0';

	memset(&this->misc, 0, sizeof(this->misc));
	this->misc.minor = MISC_DYNAMIC_MINOR;
	this->misc.name = this->devname;
	this->misc.fops = &fops;
	this->misc.mode = IPC_CHAR_DEVICE_DEFAULT_MODE;

	ipc_util_refcount_ctor(&this->refcount);

	if (misc_register(&this->misc) != 0) {
		ipc_err("misc_register failed");
		return -1;
	}

	ipc_dbg("devname='%s' minor=%d", this->misc.name, this->misc.minor);

	return 0;
}

/* Ipc sio destructor, remove the char driver.
 */
static void ipc_sio_dtor(struct ipc_sio *this)
{
	struct sk_buff *skb;

	if (unlikely(atomic_cmpxchg(&this->dtor_called, 0, 1) != 0)) {
		ipc_dbg("already called");
		return;
	}

	ipc_dbg("deregistering '%s'", this->devname);
	misc_deregister(&this->misc);

	/* This will wait until all callbacks have returned */
	ipc_util_refcount_dtor(&this->refcount);

	this->ops_instance = NULL;
	this->dbg = NULL;

	/* Wakeup the user app.
	 */
	ipc_completion_signal(&this->read_sem);

	ipc_pcie_kfree_skb(this->pcie, this->rx_pending_buf);
	this->rx_pending_buf = NULL;

	while ((skb = skb_dequeue(&this->rx_list)))
		dev_kfree_skb(skb);
}

/**
 * Refer to header file for description
 */
struct ipc_sio *ipc_sio_alloc(struct ipc_dbg *dbg, struct ipc_pcie *pcie,
	struct ipc_params *params, struct ipc_sio_ops *ops, void *ops_instance,
	const char *name)
{
	struct ipc_sio *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		return NULL;
	}

	if (ipc_sio_ctor(this, dbg, pcie, params, ops, ops_instance, name)) {
		ipc_util_kfree(this);
		this = NULL;
	}

	return this;
}

/* release ipc_sio structure when it is no longer in use */
static void ipc_sio_free_if_unused(struct ipc_sio *this)
{
	if (atomic_dec_return(&this->open_count) == -1) {
		ipc_util_kfree(this);
		this = NULL;
		ipc_pr_dbg("freed");
	} else {
		ipc_dbg("deferred");
	}
}

/**
 * Refer to header file for description
 */
void ipc_sio_dealloc(struct ipc_sio **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_sio_dtor(*this_pp);
		ipc_sio_free_if_unused(*this_pp);
		*this_pp = NULL;
	}

	/* Make sure ipc_sio_free_deferred() has finished before the module is
	 * unloaded.
	 */
	flush_scheduled_work();
}

/* Ipc sio free worker function
 */
static void ipc_sio_free_worker(struct work_struct *work)
{
	struct ipc_sio *this = container_of(work, struct ipc_sio, work);

	ipc_dbg("called");
	ipc_sio_dtor(this);
	ipc_sio_free_if_unused(this);
}

 /**
  * Refer to header file for description
  */
void ipc_sio_free_deferred(struct ipc_sio **this_pp)
{
	if (this_pp && *this_pp) {
		struct ipc_sio *this = *this_pp;

		schedule_work(&this->work);
		*this_pp = NULL;
	}
}


/* imc_ipc_sio.c ends here */
