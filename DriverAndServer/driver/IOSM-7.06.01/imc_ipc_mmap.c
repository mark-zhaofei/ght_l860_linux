/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/sockios.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#include "imc_ipc_mmap.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_params.h"
#include "imc_ipc_util.h"
#include "imc_ipc_export.h"
#include "imc_ipc_dbg.h"

struct ipc_mmap;

#define IPC_MMAP_INVALID_REGION_ID (UINT_MAX)

/* This structure describes a mapped region and will live as long as
 * a mapping exists. Note that the mapping is not removed when the device
 * is removed from the bus. In this case, ipc_mmap will be freed and the mmap
 * reference will be invalidated. The ipc_pcie structure needs to remain valid
 * as long as the driver is loaded.
 */
struct ipc_mmap_region {
	struct list_head node;    /* Node to enqueue region in region list */
	struct ipc_mmap *mmap;    /* pointer to the mmap device */
	struct vm_area_struct *vma; /* Pointer to associated vma */
	unsigned int     id;      /* region_id */
	void            *kmem;    /* pointer to allocated kernel memory */
	size_t           size;    /* size of allocated kmem */
	u64              mapping; /* PCIe address of allocated kmem */
	struct ipc_dbg  *dbg;     /* pointer to ipc_dbg structure */
};

/* Represents one misc device /dev/imc_ipc[n]_mmap0 to support a mmap
 * operation to map a contiguous region of memory into both user
 * and pcie address space.
 *
 * A region id can be configured by the user space application via
 * ioctl(SIOC_IPC_REGION_ID_SET).

 * mmap/munmap messages will be sent to the device to indicate the availability
 * of the mapped region.
 */
struct ipc_mmap {
	struct miscdevice       misc;
	char                    devname[32];
	struct ipc_mmap_ops     ops;
	void                   *ops_instance;
	struct ipc_pcie        *pcie;
	struct list_head        regions; /* list of all mmap regions */
	spinlock_t              regions_lock; /* region list access spinlock */
	atomic_t                open_count; /* free object when negative */
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

static void ipc_mmap_free_if_unused(struct ipc_mmap *this);

/**
 * mmap region memory allocation function
 */
static void *ipc_mmap_region_kmem_alloc(struct ipc_mmap_region *this)
{
	return ipc_pcie_kzalloc(this->mmap->pcie, this->size, &this->mapping);
}

/**
 * mmap region memory deallocation function
 */
static void ipc_mmap_region_kmem_free(struct ipc_mmap_region *this)
{
	if (this->kmem) {
		/* Unmap the memory from user space.
		 */
		if (this->vma) {
			/* invalidate memory range */
			zap_vma_ptes(this->vma, this->vma->vm_start,
				this->vma->vm_end - this->vma->vm_start);

			this->vma = NULL;
		}

		if (this->mmap)
			ipc_pcie_kfree(this->mmap->pcie, this->kmem, this->size,
				this->mapping);

		this->kmem = NULL;
	}
}

/**
 * mmap region destructor function
 */
static void ipc_mmap_region_dtor(struct ipc_mmap_region *this)
{
	struct ipc_mmap *mmap = this->mmap;

	/* if a region id was defined and the mmap device is still present,
	 * send ummap message
	 */
	if (this->id != IPC_MMAP_INVALID_REGION_ID &&
		mmap && mmap->ops.send_unmap_msg)
		mmap->ops.send_unmap_msg(mmap->ops_instance, this->id);

	ipc_mmap_region_kmem_free(this);
}

/**
 * Free mmap region function
 */
static void ipc_mmap_region_dealloc(struct ipc_mmap_region **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_mmap_region_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/**
 * Find matching ipc_mmap_region for given vma.
 */
static struct ipc_mmap_region *ipc_mmap_find_region_for_vma(
	struct ipc_mmap *this, struct vm_area_struct *vma)
{
	struct list_head *entry;

	if (unlikely(!this || !vma))
		return NULL;

	list_for_each(entry, &this->regions) {
		struct ipc_mmap_region *region =
			list_entry(entry, struct ipc_mmap_region, node);

		if (region->vma == vma)
			return region;
	}

	return NULL;
}

/**
 * mmap vm operation close function
 */
static void ipc_mmap_vmop_close(struct vm_area_struct *vma)
{
	struct ipc_mmap *this;
	struct ipc_mmap_region *region;

	if (unlikely(!vma))
		return;

	this = vma->vm_private_data;
	if (unlikely(!this))
		return;

	spin_lock(&this->regions_lock);

	region = ipc_mmap_find_region_for_vma(this, vma);
	if (likely(region))
		list_del(&region->node);

	spin_unlock(&this->regions_lock);


	ipc_mmap_region_dealloc(&region);

	ipc_mmap_free_if_unused(this);
}

/**
 * mmap region constructor function
 */
static int ipc_mmap_region_ctor(struct ipc_mmap_region *this,
	struct ipc_mmap *mmap, struct vm_area_struct *vma)
{
	static const struct vm_operations_struct vm_ops = {
		.close = ipc_mmap_vmop_close,
	};

	if (unlikely(!this || !mmap || !vma)) {
		ipc_err("invalid arguments");
		return -1;
	}

	this->mmap = mmap;
	this->dbg = mmap->dbg;
	this->id   = IPC_MMAP_INVALID_REGION_ID;
	this->size = vma->vm_end - vma->vm_start;
	this->kmem = ipc_mmap_region_kmem_alloc(this);
	INIT_LIST_HEAD(&this->node);

	if (unlikely(!this->kmem)) {
		ipc_err("failed to allocate shared memory area");
		return -1;
	}

	vma->vm_private_data = mmap;
	vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND;
	vma->vm_ops = &vm_ops;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (vm_iomap_memory(vma, virt_to_phys(this->kmem), this->size) != 0) {
		ipc_err("vm_iomap_memory failed");
		ipc_mmap_region_kmem_free(this);
		return -1;
	}

	this->vma = vma;

	return 0;
}

/**
 * mmap region allocation function
 */
static struct ipc_mmap_region *ipc_mmap_region_alloc(struct ipc_mmap *mmap,
	struct vm_area_struct *vma)
{
	struct ipc_mmap_region *this = ipc_util_kzalloc(sizeof(*this));

	if (this) {
		if (ipc_mmap_region_ctor(this, mmap, vma)) {
			ipc_err("mmap region constructor failed!");
			ipc_mmap_region_dealloc(&this);
			return NULL;
		}
	}

	return this;
}

/**
 * File operation mmap function
 */
static int ipc_mmap_fop_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ipc_mmap *this;
	struct ipc_mmap_region *region;

	if (unlikely(!filp))
		return -EINVAL;

	this = container_of(filp->private_data,	struct ipc_mmap, misc);

	region = ipc_mmap_region_alloc(this, vma);

	if (unlikely(!region)) {
		ipc_err("failed to allocate region");
		return -ENOMEM;
	}

	spin_lock(&this->regions_lock);

	list_add(&region->node, &this->regions);

	spin_unlock(&this->regions_lock);

	atomic_inc(&this->open_count);

	return 0;
}

/**
 * File operation mmap ioctl function
 */
static long ipc_mmap_fop_ioctl(struct file *filp, unsigned int cmd,
	unsigned long arg)
{
	int status;
	struct ipc_mmap_region *region;
	struct ipc_mmap *this;

	if (unlikely(!filp))
		return -EINVAL;

	this = container_of(filp->private_data, struct ipc_mmap, misc);
	if (unlikely(cmd != SIOC_IPC_REGION_ID_SET)) {
		ipc_err("command %d not supported", cmd);
		return -EINVAL;
	}

	if (unlikely(arg >= IPC_MMAP_INVALID_REGION_ID)) {
		ipc_err("region id invalid");
		return -EINVAL;
	}

	if (unlikely(list_empty(&this->regions))) {
		ipc_err("no mapped region available");
		return -ENOMEM;
	}

	/* region points to the latest created memory region */
	region = list_entry(this->regions.next, struct ipc_mmap_region, node);

	if (unlikely(region->id != IPC_MMAP_INVALID_REGION_ID)) {
		ipc_err("memory map request already sent for this region");
		return -EEXIST;
	}

	if (unlikely(!this->ops.send_map_msg)) {
		ipc_err("no send_map_msg op");
		return -ENOENT;
	}

	status = this->ops.send_map_msg(this->ops_instance, arg, region->size,
		region->mapping);

	if (unlikely(status < 0)) {
		ipc_err("device rejected map message, status=%d", status);
		return -EIO;
	}

	region->id = arg;

	return 0;
}

/**
 * mmap constructor function
 */
static int ipc_mmap_ctor(struct ipc_mmap *this,
			const struct ipc_mmap_ops *ops,
			void *ops_instance, struct ipc_pcie *pcie,
			unsigned int instance_nr, struct ipc_dbg *dbg)
{
	static const struct file_operations fops = {
		.owner = THIS_MODULE,
		.mmap = ipc_mmap_fop_mmap,
		.unlocked_ioctl = ipc_mmap_fop_ioctl,
	};

	if (unlikely(!ops || !ops_instance || !pcie)) {
		ipc_err("invalid args");
		return -1;
	}

	this->dbg = dbg;
	this->pcie = pcie;
	this->ops = *ops;
	this->ops_instance = ops_instance;

	INIT_LIST_HEAD(&this->regions);
	spin_lock_init(&this->regions_lock);

	snprintf(this->devname, sizeof(this->devname), "imc_ipc%d_mmap",
		instance_nr);

	memset(&this->misc, 0, sizeof(this->misc));
	this->misc.minor = MISC_DYNAMIC_MINOR;
	this->misc.name = this->devname;
	this->misc.fops = &fops;
	this->misc.mode = IPC_CHAR_DEVICE_DEFAULT_MODE;

	atomic_set(&this->open_count, 0);

	if (misc_register(&this->misc) != 0) {
		ipc_err("misc_register failed");
		return -1;
	}

	ipc_dbg("devname='%s' minor=%d", this->misc.name, this->misc.minor);

	return 0;
}

/**
 * mmap destructor function
 */
static void ipc_mmap_dtor(struct ipc_mmap *this)
{
	struct list_head *entry, *tmp;

	ipc_dbg("deregistering '%s'", this->devname);

	misc_deregister(&this->misc);

	spin_lock(&this->regions_lock);

	/* Remove reference to mmap from any existing region
	 * The region will be freed when the mapping is removed
	 */
	list_for_each_safe(entry, tmp, &this->regions) {
		struct ipc_mmap_region *region =
			list_entry(entry, struct ipc_mmap_region, node);

		ipc_dbg("removing reference towards region %d",
			region->id);

		ipc_mmap_region_kmem_free(region);

		region->mmap = NULL;
		region->dbg = NULL;

		list_del(entry);
	}

	spin_unlock(&this->regions_lock);

	this->ops_instance = NULL;
	memset(&this->ops, 0, sizeof(this->ops));

	this->dbg = NULL;
}

/*
 * Refer to header file for description
 */
struct ipc_mmap *ipc_mmap_alloc(const struct ipc_mmap_ops *ops,
	void *ops_instance, struct ipc_pcie *pcie, unsigned int instance_nr,
	struct ipc_dbg *dbg)
{
	struct ipc_mmap *this = ipc_util_kzalloc(sizeof(*this));

	if (this) {
		if (ipc_mmap_ctor(this, ops, ops_instance, pcie,
					instance_nr, dbg)) {
			ipc_err("mmap constructor failed!");
			ipc_mmap_dealloc(&this);
			return NULL;
		}
	}

	return this;
}

static void ipc_mmap_free_if_unused(struct ipc_mmap *this)
{
	if (atomic_dec_return(&this->open_count) == -1) {
		ipc_util_kfree(this);
		this = NULL;
		ipc_pr_dbg("freed");
	} else {
		ipc_dbg("deferred");
	}
}

/*
 * Refer to header file for description
 */
void ipc_mmap_dealloc(struct ipc_mmap **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_mmap_dtor(*this_pp);
		ipc_mmap_free_if_unused(*this_pp);
		*this_pp = NULL;
	}
}
