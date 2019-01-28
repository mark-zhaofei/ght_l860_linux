/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>

#include "imc_ipc_util.h"
#include "imc_ipc_uevent.h"
#include "imc_ipc_dbg.h"

#include "imc_ipc_debugfs.h"

/**
 * Data structure for sending IPC events to userspace
 */
struct ipc_uevent {
	/* last mdm state information */
	char mdm_state[MAX_UEVENT_LEN];

	/* uevent debugfs */
	struct ipc_debugfs_uevent *dbgfs;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/**
 * Uevent information structure
 */
struct ipc_uevent_info {
	/* pointer to device structure */
	struct device *dev;

	/* uevent information */
	char uevent[MAX_UEVENT_LEN];

	/* uevent work struct */
	struct work_struct work;
};

/**
 * Send uevent to the userspace
 */
static void ipc_uevent_work(struct work_struct *data)
{
	struct ipc_uevent_info *info;
	char *envp[2] = {NULL, NULL};

	if (unlikely(!data)) {
		ipc_err("invalid arguments");
		return;
	}

	info = container_of(data, struct ipc_uevent_info, work);
	if (unlikely(!info)) {
		ipc_err("no uevent info");
		return;
	}
	if (unlikely(!info->dev)) {
		ipc_err("no such device");
		ipc_util_kfree(info);
		return;
	}

	envp[0] = info->uevent;
	if (kobject_uevent_env(&info->dev->kobj, KOBJ_CHANGE, envp))
		ipc_err("uevent %s failed to sent", info->uevent);

	ipc_util_kfree(info);
}

/**
 * Refer to header file for description
 */
int ipc_uevent_get_state(struct ipc_uevent *this, char *uevent, size_t len)
{
	if (unlikely(!this || !uevent ||
				(len < MAX_UEVENT_LEN))) {
		ipc_err("invalid arguments");
		return -1;
	}

	/* Save it as a last sent event. */
	strncpy(uevent, this->mdm_state, MAX_UEVENT_LEN);
	uevent[MAX_UEVENT_LEN-1] = '\0';

	return 0;
}

/**
 * Refer to header file for description
 *
 * FIXME: As soon as we have dynamic allocation of all the instances
 * supported we should get rid of the struct device *dev parameter
 * passed in the ipc_uevent_send() function as this does not fall in
 * coding compliance of using instance pointer which should get
 * device parameter reference itself, while doing ipc_uevent_alloc().
 * This is a temporary solution avoid having any extra function
 * to "bind" ipc_uevent instance to the device.
 */
int ipc_uevent_send(struct ipc_uevent *this, struct device *dev, char *uevent)
{
	struct ipc_uevent_info *info = NULL;

	if (unlikely(!this || !dev || !uevent)) {
		ipc_err("invalid arguments");
		return -1;
	}

	/* Save it as a last sent event. */
	strncpy(this->mdm_state, uevent, MAX_UEVENT_LEN-1);
	this->mdm_state[MAX_UEVENT_LEN-1] = '\0';

	/* Send device uevent */
	if (unlikely(!dev)) {
		ipc_err("No such device, so can not send uevent");
		return -1;
	}

	info = ipc_util_kzalloc_atomic(sizeof(*info));
	if (unlikely(!info)) {
		ipc_err("unable to allocate ipc_uevent_info");
		return -1;
	}

	/* Initialize the kernel work queue */
	INIT_WORK(&info->work, ipc_uevent_work);

	/* Store the device and event information */
	info->dev = dev;
	snprintf(info->uevent, MAX_UEVENT_LEN, "%s: %s", dev_name(dev), uevent);

	/* Schedule uevent in process context using work queue */
	schedule_work(&info->work);

	return 0;
}


/**
 * IPC uevent constructor
 *
 * @this: pointer to struct ipc_uevent
 * @dbgfs: pointer to struct ipc_debugfs
 * @instance_nr: Modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * return 0 on success else -1
 */
static int ipc_uevent_ctor(struct ipc_uevent *this, struct ipc_debugfs *dbgfs,
			unsigned int instance_nr, struct ipc_dbg *dbg)
{
	this->dbg = dbg;

	/* Allocate uevent debugfs */
	this->dbgfs = ipc_debugfs_uevent_alloc(this, dbgfs, this->dbg);
	if (unlikely(!this->dbgfs))
		ipc_dbg("uevent debugfs not allocated");

	return 0;
}

/**
 * Refer to header file for description
 */
struct ipc_uevent *ipc_uevent_alloc(unsigned int instance_nr,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_uevent *this = NULL;

	this = ipc_util_kzalloc(sizeof(*this));
	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto alloc_fail;
	}

	if (ipc_uevent_ctor(this, dbgfs, instance_nr, dbg)) {
		ipc_err("ctor failed");
		goto ctor_fail;
	}

	return this;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}

/**
 * IPC uevent destructor
 * @this: pointer struct ipc_uevent
 */
static void ipc_uevent_dtor(struct ipc_uevent *this)
{
	ipc_debugfs_uevent_dealloc(&this->dbgfs);
}


/**
 * Refer to header file for description
 */
void ipc_uevent_dealloc(struct ipc_uevent **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_uevent_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
