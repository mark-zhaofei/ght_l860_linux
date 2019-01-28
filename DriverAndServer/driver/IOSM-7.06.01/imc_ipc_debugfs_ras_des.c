/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include "imc_ipc_debugfs.h"
#include "imc_ipc_ras_des.h"
#include "imc_ipc_util.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_dbg.h"


/* RAS DES Debugfs directory name
 */
#define IMC_IPC_RAS_DES_DIR "ras_des"
#define IMC_IPC_RAS_DES_EVENT_DIR "events"
#define IMC_IPC_RAS_DES_TIMER_DIR "timer"

#define IMC_IPC_RAS_DES_TIMER_ACTION "start_stop"
#define IMC_IPC_RAS_DES_TIMER_NODE "timer"
#define IMC_IPC_RAS_DES_TIMER_STATUS "status"


struct ipc_debugfs_ras_des {
	struct ipc_pcie *pcie;
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
	struct ipc_debugfs *dbgfs;
	struct ipc_pcie_ras_des *ras_des;
	struct ipc_dbgfs_ras_des_event *events;
	u8 timer_cnt;
	struct dentry *ras_des_root_dbgfs;
};

struct ipc_dbgfs_ras_des_event {
	struct ipc_debugfs_ras_des *parent;
	u16 event;
};


/**
 * Helper function change the event config when write
 * to imc_ipc/ras_des/timer/start_stop is called
 *
 * returns 0 on success, -1 on failure
 */
static ssize_t debugfs_ras_des_timer_write(struct file *file,
	const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct ipc_debugfs_ras_des *this = NULL;
	struct ipc_pcie_ras_des *ras_des;
	char buf[16] = { 0 };
	char str[16] = { 0 };
	char tmp[16] = { 0 };
	u8 timer;
	int cnt;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("RAS DES DebugFS timer write call param error");
		return -1;
	}

	this = file->private_data;
	ras_des = this->ras_des;

	if (unlikely(!ras_des)) {
		ipc_err("RAS DES capability missing");
		return -1;
	}

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count))) {
		ipc_err("Copy from user failed");
		return -1;
	}

	cnt = sscanf(buf, "%s%[ \t\n]", str, tmp);
	if (cnt < 0) {
		ipc_err("invalid arguments");
		return -1;
	}

	timer = ipc_pcie_ras_des_look_up_timer(ras_des, str);

	if (timer == 0) {
		ipc_err("Invalid timer given");
		return -1;
	}

	this->timer_cnt = timer;

	return count;
};


/**
 * Helper function change the event config when write
 * to imc_ipcX/ras_des/timer/start_stop is called
 *
 * returns 0 on success, -1 on failure
 */
static ssize_t debugfs_ras_des_timer_action_write(struct file *file,
	const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct ipc_debugfs_ras_des *this = NULL;
	struct ipc_pcie_ras_des *ras_des;
	char buf[16] = { 0 };
	u32 timeout_int;
	enum intel_ras_des_timeout timeout;
	int ret_code;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("RAS DES DebugFS timer write call param error");
		return -1;
	}

	this = file->private_data;
	ras_des = this->ras_des;

	if (unlikely(!ras_des)) {
		ipc_err("RAS DES capability missing");
		return -1;
	}

	if (this->timer_cnt == 0) {
		ipc_err("No timer selected");
		return -1;
	}

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count))) {
		ipc_err("Copy from user failed");
		return -1;
	}

	ret_code = kstrtouint(buf, 10, &timeout_int);
	if (ret_code < 0) {
		ipc_err("Invalid timeout arg");
		return -1;
	} else if (timeout_int > INTEL_RAS_DES_TIMEOUT_4S) {
		ipc_err("Timeout to big");
		return -1;
	} else if (timeout_int == 0) {
		ipc_err("Manual mode not supported");
		return -1;
	}

	timeout = (enum intel_ras_des_timeout) timeout_int;
	ipc_pcie_ras_des_start_timer(ras_des, this->timer_cnt, timeout);

	return count;
};


/**
 * Helper function to read the timer results when read
 * to imc_ipc/ras_des/timer/status is called
 *
 * returns 0 on success, -1 on failure
 */
static ssize_t debugfs_ras_des_timer_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct ipc_debugfs_ras_des *this = NULL;
	struct ipc_pcie_ras_des *ras_des;
	u32 running = 0;
	u32 counter = 0;
	char buf[64] = {0};
	u32 len = 0;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("RAS DES DebugFS timer read call param error");
		return -1;
	}

	this = file->private_data;
	ras_des = this->ras_des;

	if (unlikely(!ras_des)) {
		ipc_err("RAS DES capability missing");
		return -1;
	}

	if (this->timer_cnt) {
		ipc_pcie_ras_des_timer_status(ras_des, &running);
		ipc_pcie_ras_des_timer_counter(ras_des, &counter);

		len += scnprintf(buf + len,
				sizeof(buf) - len,
				"Timer: 0x%02X\n", this->timer_cnt);
		len += scnprintf(buf + len,
				sizeof(buf) - len,
				"Running: %d\n", running);
		len += scnprintf(buf + len,
				sizeof(buf) - len,
				"Counter: 0x%08X\n", counter);
	} else {
		len += scnprintf(buf + len,
				sizeof(buf) - len,
				"No timer enabled\n");
	}

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
};


/**
 * Helper function change the event config when write
 * to imc_ipc/ras_des/event/<event> is called
 *
 * returns 0 on success, -1 on failure
 */
static ssize_t debugfs_ras_des_event_write(struct file *file,
				const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct ipc_dbgfs_ras_des_event *event_p;
	struct ipc_debugfs_ras_des *this = NULL;
	struct ipc_pcie_ras_des *ras_des;
	char buf[16] = { 0 };
	u32 cnt = 0;
	char cmd;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("RAS DES DebugFS event write call param error");
		return -1;
	}

	event_p = file->private_data;
	this = event_p->parent;

	if (unlikely(!this)) {
		ipc_err("RAS DES DebugFS event write param error");
		return -1;
	}

	ras_des = this->ras_des;

	if (unlikely(!ras_des)) {
		ipc_err("RAS DES capability missing");
		return -1;
	}


	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count))) {
		ipc_err("Copy from user failed");
		return -1;
	}

	cnt = sscanf(buf, "%c", &cmd);
	if (cnt != 1) {
		ipc_err("Command not recognized");
		return -1;
	}

	switch (cmd) {
	case '1': /* fall-through */
	case 'e':
		ipc_pcie_ras_des_enable_event(ras_des, event_p->event);
		break;
	case '0': /* fall-through */
	case 'd':
		/* Disable event reporting */
		ipc_pcie_ras_des_disable_event(ras_des, event_p->event);
		break;
	case 'c':
		/* clear event counter to zero */
		ipc_pcie_ras_des_clear_event(ras_des, event_p->event);
		break;
	default:
		ipc_err("Command not recognized");
	}

	return count;
}


/**
 * Helper function to log RAS DES event data in verbose when read
 * to imc_ipc/ras_des/event/<event> is called
 *
 * returns 0 on success, -1 on failure
 */
static ssize_t debugfs_ras_des_event_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct ipc_dbgfs_ras_des_event *event_p;
	struct ipc_debugfs_ras_des *this = NULL;
	struct ipc_pcie_ras_des *ras_des;
	u32 enabled = 0;
	u32 counter = 0;
	char buf[64] = { 0 };
	u32 len = 0;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("RAS DES DebugFS event read call param error");
		return -1;
	}

	event_p = file->private_data;
	this = event_p->parent;

	if (unlikely(!this)) {
		ipc_err("RAS DES DebugFS event read call param error");
		return -1;
	}

	ras_des = this->ras_des;

	if (unlikely(!ras_des)) {
		ipc_err("RAS DES capability missing");
		return -1;
	}

	ipc_pcie_ras_des_event_status(ras_des, event_p->event, &enabled);

	len += scnprintf(buf + len,
			sizeof(buf) - len,
			"Number: 0x%04X\n", event_p->event);
	len += scnprintf(buf + len,
			sizeof(buf) - len,
			"Enabled: %d\n", enabled);

	if (enabled) {
		ipc_pcie_ras_des_get_event_counter(ras_des,
			event_p->event, &counter);
		len += scnprintf(buf + len, sizeof(buf) - len,
				"Counter: 0x%08X\n", counter);
	} else {
		len += scnprintf(buf + len, sizeof(buf) - len,
				"Counter: 0x0000000\n");
	}

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}


/**
 * Open function for imc_ipc/ras_des/info
 *
 * @inode: inode pointer for "info" file
 * @file: file pointer for "info" file.
 *
 * returns 0 on success, Error number on failure
 */
static int debugfs_ras_des_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	file->private_data = inode->i_private;
	return 0;
}


static const struct file_operations ipc_ras_des_timer_read_fops = {
	.owner = THIS_MODULE,
	.open = debugfs_ras_des_open,
	.read = debugfs_ras_des_timer_read
};


static const struct file_operations ipc_ras_des_timer_action_fops = {
	.owner = THIS_MODULE,
	.open = debugfs_ras_des_open,
	.write = debugfs_ras_des_timer_action_write
};


static const struct file_operations ipc_ras_des_timer_fops = {
	.owner = THIS_MODULE,
	.open = debugfs_ras_des_open,
	.write = debugfs_ras_des_timer_write
};


static const struct file_operations ipc_ras_des_event_fops = {
	.owner = THIS_MODULE,
	.open = debugfs_ras_des_open,
	.read = debugfs_ras_des_event_read,
	.write = debugfs_ras_des_event_write
};


/*
 * Refer to header file for description
 */
static int ipc_debugfs_ras_des_stats_ctor(struct ipc_debugfs_ras_des *this,
	struct ipc_debugfs *dbgfs, struct ipc_pcie_ras_des *ras_des,
	struct ipc_pcie *pcie, struct ipc_dbg *dbg)
{
	struct dentry *p_debugfs_ras_des_event_dentry = NULL;
	struct dentry *p_debugfs_ras_des_timer_dentry = NULL;
	struct ipc_pcie_ras_des_event *events = 0;
	int number_of_events = 0;
	int i;

	if (unlikely(!this || !ipc_debugfs_get_root_folder(dbgfs) ||
			!pcie || !ras_des)) {
		ipc_err("RAS DES DebugFS alloc fail");
		return -1;
	}

	this->ras_des = ras_des;
	this->pcie = pcie;
	this->dbgfs = dbgfs;
	this->dbg = dbg,

	number_of_events = ipc_pcie_ras_des_number_of_events(this->ras_des);

	if (unlikely(number_of_events <= 0)) {
		ipc_err("RAS DES contains no events");
		return -1;
	}

	events = ipc_pcie_ras_des_events(this->ras_des);

	if (unlikely(events == 0)) {
		ipc_err("Invalid events descriptor");
		return -1;
	}

	this->events = ipc_util_kzalloc(sizeof(struct ipc_dbgfs_ras_des_event) *
		number_of_events);

	if (unlikely(this->events == 0)) {
		ipc_err("Allocation of event descriptors failed");
		return -1;
	}

	this->ras_des_root_dbgfs = debugfs_create_dir(IMC_IPC_RAS_DES_DIR,
					ipc_debugfs_get_root_folder(dbgfs));

	if (unlikely(!this->ras_des_root_dbgfs)) {
		ipc_err(" Creation of entry in debugfs failed");
		return -1;
	}

	p_debugfs_ras_des_event_dentry = debugfs_create_dir(
			IMC_IPC_RAS_DES_EVENT_DIR, this->ras_des_root_dbgfs);

	if (unlikely(!p_debugfs_ras_des_event_dentry)) {
		ipc_err(" Creation of directory entry in debugfs failed");
		return -1;
	}

	for (i = 0; i < number_of_events; i++) {
		this->events[i].parent = this;
		this->events[i].event = events[i].number;
		debugfs_create_file(events[i].name, 0664,
				p_debugfs_ras_des_event_dentry,
				&this->events[i], &ipc_ras_des_event_fops);
	}

	this->timer_cnt = 0;

	p_debugfs_ras_des_timer_dentry = debugfs_create_dir(
			IMC_IPC_RAS_DES_TIMER_DIR, this->ras_des_root_dbgfs);

	if (unlikely(!p_debugfs_ras_des_timer_dentry)) {
		ipc_err(" Creation timer entry in debugfs failed ");
		return -1;
	}

	debugfs_create_file(IMC_IPC_RAS_DES_TIMER_NODE, 0220,
				p_debugfs_ras_des_timer_dentry, this,
				&ipc_ras_des_timer_fops);

	debugfs_create_file(IMC_IPC_RAS_DES_TIMER_ACTION, 0220,
				p_debugfs_ras_des_timer_dentry, this,
				&ipc_ras_des_timer_action_fops);

	debugfs_create_file(IMC_IPC_RAS_DES_TIMER_STATUS, 0444,
				p_debugfs_ras_des_timer_dentry, this,
				&ipc_ras_des_timer_read_fops);

	return 0;
}

/*
 * Refer to header file for description
 */
static void ipc_debugfs_ras_des_stats_dtor(struct ipc_debugfs_ras_des *this)
{
	ipc_util_kfree(this->events);
	this->events = NULL;
	debugfs_remove_recursive(this->ras_des_root_dbgfs);
	this->ras_des_root_dbgfs = NULL;
}

/*
 * Refer to header file for description
 */
struct ipc_debugfs_ras_des *ipc_debugfs_ras_des_alloc(struct ipc_debugfs *dbgfs,
		struct ipc_pcie_ras_des *ras_des, struct ipc_pcie *pcie,
		struct ipc_dbg *dbg)

{
	struct ipc_debugfs_ras_des *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto alloc_fail;
	}

	if (ipc_debugfs_ras_des_stats_ctor(this, dbgfs, ras_des, pcie, dbg)) {
		ipc_err("ras des debugfs ctor failed");
		goto ctor_fail;
	}

	return this;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}

/*
 * Refer to header file for description
 */
void ipc_debugfs_ras_des_dealloc(struct ipc_debugfs_ras_des **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_ras_des_stats_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

