/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/stat.h>
#include <linux/debugfs.h>

#include "imc_ipc_debugfs.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_hrtimer.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"

/*
 *  Instance data of a ipc_debugfs_hpu_stress object
 */
struct ipc_debugfs_hpu_stress {
	/* reference to the parent debugfs component */
	struct ipc_debugfs *debugfs;

	/* directory entry of the debugfs attribute file */
	struct dentry *dentry;

	/* timer component used for triggering irqs */
	struct ipc_hrtimer *timer;

	/* period in ns between hpu irqs */
	unsigned long period;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};


/* Callback routine for HPU test timer. This will trigger an HPU IRQ
 */
static void ipc_debugfs_hpu_stress_timer_cb(void *instance)
{
	struct ipc_pcie *pcie = instance;

	ipc_cp_irq_hpda_update(pcie, IPC_HP_STRESSTEST);
}

/* debugfs read callback for getting a value. file inode private data is
 * expected to point to ipc_debugfs_hpu_stress instance data
 */
static ssize_t ipc_debugfs_hpu_stress_get(struct file *file,
	char __user *data, size_t size, loff_t *offset)
{
	char buffer[25];
	int num_bytes;
	struct ipc_debugfs_hpu_stress *this = file_inode(file)->i_private;

	/* convert unsigned long to string */
	num_bytes = snprintf(buffer, 25, "%lu\n", this->period);
	num_bytes++;

	/* copy to user. */
	return simple_read_from_buffer(data, size, offset, buffer, num_bytes);
}

/* debugfs write callback for setting a value. file inode private data is
 * expected to point to ipc_debugfs_hpu_stress instance data
 */
static ssize_t ipc_debugfs_hpu_stress_set(struct file *file,
	const char __user *data, size_t size, loff_t *offset)
{
	int ret;
	unsigned long val;
	struct ipc_debugfs_hpu_stress *this = file_inode(file)->i_private;

	ret = kstrtoul_from_user(data, size, 0, &val);
	if (ret)
		return ret;

	this->period = val;

	ipc_hrtimer_config(this->timer, this->period);

	return size;
}

/* defines file operations for debugfs attribute file */
static const struct file_operations ipc_debugfs_hpu_stress_fops = {
	.owner = THIS_MODULE,
	.read = ipc_debugfs_hpu_stress_get,
	.write = ipc_debugfs_hpu_stress_set,
};

/*
 * ipc_debugfs_hpu_stress constructor, takes reference to debugfs and pcie
 * component as argument.
 * return 0 on success else -1
 */
static int ipc_debugfs_hpu_stress_ctor(
			struct ipc_debugfs_hpu_stress *this,
			struct ipc_debugfs *debugfs,
			struct ipc_pcie *pcie, struct ipc_dbg *dbg)
{
	if (unlikely(!debugfs || !pcie)) {
		ipc_err("Invalid argument");
		return -1;
	}

	this->dbg = dbg;
	this->period = 0;
	this->debugfs = debugfs;
	this->timer = ipc_hrtimer_alloc(pcie, dbg,
			ipc_debugfs_hpu_stress_timer_cb,
			"hpu stress", true, NULL);

	if (unlikely(!this->timer)) {
		ipc_err("failed to allocated timer");
		return -1;
	}

	this->dentry = debugfs_create_file("hpu_stress_period_us",
		0664,
		ipc_debugfs_get_root_folder(debugfs),
		this,
		&ipc_debugfs_hpu_stress_fops);

	if (unlikely(!this->dentry)) {
		ipc_err("failed to allocated dentry");
		ipc_hrtimer_dealloc(&this->timer);
		return -1;
	}

	return 0;
}

/*
 * ipc_debugfs_hpu_stress destructor
 */
static void ipc_debugfs_hpu_stress_dtor(struct ipc_debugfs_hpu_stress *this)
{
	/* Handle NULL ptr gracefully similar to free() */
	if (!this)
		return;

	/* remove file system entry */
	debugfs_remove(this->dentry);

	/* free timer */
	ipc_hrtimer_dealloc(&this->timer);
}

/*
 * ipc_debugfs_hpu_stress allocator, returns pointer to new debugfs_hpu_stress
 * instance or NULL on failure
 */
struct ipc_debugfs_hpu_stress *ipc_debugfs_hpu_stress_alloc(
				struct ipc_debugfs *debugfs,
				struct ipc_pcie *pcie, struct ipc_dbg *dbg)
{
	struct ipc_debugfs_hpu_stress *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_hpu_stress_ctor(this, debugfs, pcie, dbg)) {
		ipc_err("ctor failed");
		goto ctor_fail;
	}

	return this;

ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/*
 * Free ipc_debugfs_hpu_stress, invalidating pointer to object
 */
void ipc_debugfs_hpu_stress_dealloc(
	struct ipc_debugfs_hpu_stress **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_hpu_stress_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
