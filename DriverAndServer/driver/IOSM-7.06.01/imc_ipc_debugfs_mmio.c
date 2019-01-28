/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include "imc_ipc_util.h"
#include "imc_ipc_mmio.h"
#include "imc_ipc_debugfs.h"
#include "imc_ipc_dbg.h"


struct ipc_debugfs_mmio {
	/* pointer to structure to mmio area */
	struct ipc_mmio *mmio;

	/* pointer to structure of debugfs file system */
	struct dentry *dfilp;

	/* last scratchpad debug offset */
	u32 dbg_sp_offset;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/**
 * debugfs file read function for MMIO
 *
 * Usage:
 * To Read MMIO at offset 0x24 (default is 0).
 * echo 0x24 >  /sys/kernel/debug/imc_ipc0/scratchpad \
 * && cat /sys/kernel/debug/imc_ipc0/scratchpad
 */
static ssize_t ipc_debugfs_mmio_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct ipc_debugfs_mmio *this;
	char buf[64] = {0};
	unsigned int len;
	u32 value;
	u64 sp_addr = 0;

	/* avoid function enter again */
	if (*ppos > 0)
		return 0;

	if (unlikely(!file || !file->private_data))
		return -1;

	this = file->private_data;

	value = ipc_mmio_scratchpad_read(this->mmio,
			this->dbg_sp_offset, &sp_addr);
	len = scnprintf(buf, sizeof(buf), "addr:0x%llx, value:0x%08X\n",
		sp_addr + this->dbg_sp_offset, value);
	ipc_dbg("Reading to address %llx offset %08X value %08X",
		sp_addr + this->dbg_sp_offset, this->dbg_sp_offset, value);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

/**
 * debugfs file write function for MMIO
 *
 * Usage:
 * To Write MMIO at offset 0x24 with value 0x1.
 * echo 0x24 0x1 > /sys/kernel/debug/imc_ipc0/scratchpad
 *
 * To Write with value 0x1 & Read MMIO at offset 0x24.
 * echo 0x24 0x1 > /sys/kernel/debug/imc_ipc0/scratchpad \
 * && cat /sys/kernel/debug/imc_ipc0/scratchpad
 */
static ssize_t ipc_debugfs_mmio_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct ipc_debugfs_mmio *this;
	char buf[32] = {0};
	unsigned int value;
	unsigned int offset;
	int cnt;

	if (unlikely(!file || !file->private_data))
		return -1;

	this = file->private_data;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count))) {
		ipc_err("copy from user failed");
		return -EINVAL;
	}

	cnt = sscanf(buf, "%i %i", &offset, &value);
	if (cnt != 2 && cnt != 1) {
		ipc_err("write: echo <offset> <value> > scratchpad");
		ipc_err("read: echo <offset> > scratchpad && cat scratchpad");
		return -EINVAL;
	}

	if (cnt == 2)
		ipc_mmio_scratchpad_write(this->mmio, offset, value);

	this->dbg_sp_offset = offset;

	return count;
}

/**
 * debugfs file open function for MMIO
 */
static int ipc_debugfs_mmio_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	file->private_data = inode->i_private;
	return 0;
}

static const struct file_operations ipc_debugfs_mmio_sp = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_mmio_open,
	.read = ipc_debugfs_mmio_read,
	.write = ipc_debugfs_mmio_write,
};


/**
 * MMIO debugfs constructor
 * @this: pointer to struct ipc_debugfs_mmio
 * @mmio: pointer to struct ipc_mmio
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 * return 0 on success else -1
 */
static int ipc_debugfs_mmio_ctor(struct ipc_debugfs_mmio *this,
		struct ipc_mmio *mmio, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg)
{
	if (unlikely(!mmio || !ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("Invalid args");
		return -1;
	}

	this->dbg = dbg;
	/* store mmio structure information */
	this->mmio = mmio;

	/* create scratchpad file */
	this->dfilp = debugfs_create_file("scratchpad",
				0664, ipc_debugfs_get_root_folder(dbgfs),
				this, &ipc_debugfs_mmio_sp);
	if (unlikely(!this->dfilp)) {
		ipc_err("debugfs create scratchpad file failed");
		return -1;
	}

	return 0;
}

/**
 * Refer to header file for description
 */
struct ipc_debugfs_mmio *ipc_debugfs_mmio_alloc(
		struct ipc_mmio *mmio, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg)
{
	struct ipc_debugfs_mmio *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_mmio_ctor(this, mmio, dbgfs, dbg)) {
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
 * MMIO debugfs destructor
 * @this: pointer to struct ipc_debugfs_mmio
 */
static void ipc_debugfs_mmio_dtor(struct ipc_debugfs_mmio *this)
{
	debugfs_remove(this->dfilp);
}

/**
 * Refer to header file for description
 */
void ipc_debugfs_mmio_dealloc(struct ipc_debugfs_mmio **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_mmio_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
