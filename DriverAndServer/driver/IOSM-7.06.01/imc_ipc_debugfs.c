/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/dcache.h>

#include "imc_ipc_dbg.h"
#include "imc_ipc_util.h"
#include "imc_ipc_debugfs.h"


/* debugfs root directory name */
#define ROOT_DIR_NAME		"imc_ipc"
/* maximum debugfs root directory name length */
#define ROOT_DIR_NAME_LEN	15


struct ipc_debugfs {
	/* Root folder */
	struct dentry *root_folder;

	/* Is debugfs initialized */
	bool is_available;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/*
 * debugfs constructor
 *
 * @this: pointer to struct ipc_debugfs
 * @instance_nr: modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * return 0 on success else -1
 */
static int ipc_debugfs_ctor(struct ipc_debugfs *this,
		unsigned int instance_nr, struct ipc_dbg *dbg)
{
	char root_dir_name[ROOT_DIR_NAME_LEN];

	this->dbg = dbg;

	if (!debugfs_initialized()) {
		ipc_err("Debugfs not initialized");
		return -1;
	}

	snprintf(root_dir_name, sizeof(root_dir_name), "%s%d",
		ROOT_DIR_NAME, instance_nr);
	this->root_folder = debugfs_create_dir(root_dir_name, NULL);

	if (!this->root_folder) {
		ipc_err("Unable to create root folder");
		return -1;
	}

	this->is_available = true;

	return 0;
}

/*
 * debugfs destructor
 * @this: pointer to struct ipc_debgufs
 */
static void ipc_debugfs_dtor(struct ipc_debugfs *this)
{
	debugfs_remove_recursive(this->root_folder);
	this->root_folder = NULL;
}

/*
 * Refer to header file for description
 */
struct dentry *ipc_debugfs_get_root_folder(struct ipc_debugfs *this)
{
	return this ? this->root_folder : NULL;
}

/*
 * Refer to header file for description
 */
bool ipc_debugfs_is_available(struct ipc_debugfs *this)
{
	return this ? this->is_available : false;
}

/*
 * Refer to header file for description
 */
struct ipc_debugfs *ipc_debugfs_alloc(unsigned int instance_nr,
				struct ipc_dbg *dbg)
{
	struct ipc_debugfs *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_ctor(this, instance_nr, dbg)) {
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
 * Refer to header file for description
 */
void ipc_debugfs_dealloc(struct ipc_debugfs **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
