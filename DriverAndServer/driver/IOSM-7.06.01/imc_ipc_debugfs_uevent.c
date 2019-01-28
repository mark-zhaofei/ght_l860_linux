/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>

#include "imc_ipc_util.h"
#include "imc_ipc_uevent.h"
#include "imc_ipc_debugfs.h"
#include "imc_ipc_dbg.h"


struct ipc_debugfs_uevent {
	/* struct ipc_uevent pointer */
	struct ipc_uevent *uevent;
	/* debugfs for last file system event */
	struct dentry *mdm_state;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};


/**
 * uevent debugfs read function to provide latest uevent state to userspace
 */
static ssize_t ipc_debugfs_uevent_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct ipc_debugfs_uevent *this = NULL;
	char buf[MAX_UEVENT_LEN];

	if (unlikely(!file || !file->private_data)) {
		ipc_err("invalid params");
		return -1;
	}

	this = file->private_data;

	if (ipc_uevent_get_state(this->uevent, buf, sizeof(buf))) {
		ipc_err("failed to read uevent state");
		return -EINVAL;
	}

	return simple_read_from_buffer(ubuf, count, ppos, buf, sizeof(buf));
}


/**
 * uevent debugfs open functon
 */
static int ipc_debugfs_uevent_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	file->private_data = inode->i_private;
	return 0;
}

/* defines file operations for uevent debugfs attribute file */
static const struct file_operations ipc_debugfs_uevent_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_uevent_open,
	.read = ipc_debugfs_uevent_read,
};


/**
 * uevent debugfs constructor
 * @this: pointer to struct ipc_debugfs_uevent
 * @uevent: pointer to struct ipc_uevent
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * return 0 on sucess else -1
 */
static int ipc_debugfs_uevent_ctor(struct ipc_debugfs_uevent *this,
		struct ipc_uevent *uevent, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg)
{
	if (unlikely(!uevent ||
			!ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("invalid params");
		return -1;
	}

	this->dbg = dbg;

	/* store uevent pointer */
	this->uevent = uevent;

	/* create modem state file */
	this->mdm_state = debugfs_create_file("mdm_state",
				0444, ipc_debugfs_get_root_folder(dbgfs),
				this, &ipc_debugfs_uevent_fops);
	if (unlikely(!this->mdm_state)) {
		ipc_err("mdm_state debugfs failed");
		return -1;
	}
	return 0;
}

/**
 * Refer to header file for description
 */
struct ipc_debugfs_uevent *ipc_debugfs_uevent_alloc(
		struct ipc_uevent *uevent, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg)
{
	struct ipc_debugfs_uevent *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_uevent_ctor(this, uevent, dbgfs, dbg)) {
		ipc_err("ctor failed");
		goto ctor_fail;
	}
	return this;

ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/**
 * uevent debugfs destructor
 * @this: pointer to struct ipc_debugfs_uevent
 */
static void ipc_debugfs_uevent_dtor(struct ipc_debugfs_uevent *this)
{
	debugfs_remove(this->mdm_state);
}

/**
 * Refer to header file for description
 */
void ipc_debugfs_uevent_dealloc(struct ipc_debugfs_uevent **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_uevent_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

