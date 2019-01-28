/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "imc_ipc_debugfs.h"
#include "imc_ipc_imem.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"


#define IMC_IPC_STATS_INFO "info"
#define IMC_IPC_STATS_SLEEP "sleep"
#define IMC_IPC_STATS_SLEEP_HISTORY "sleep_history"
#define IMC_IPC_STATS_DEVICE_SLEEP "device_sleep"
#define IMC_IPC_STATS_EXEC_STAGE "exec_stage_unbuffered"

#define IMC_IPC_STATS_SLEEP_ENTRIES 21

/* Request the driver configuration about the channel open operation.
 */
struct ipc_debugfs_stats {
	unsigned int sleep_idx;
	struct ipc_sleep_stats {
		struct timeval ts;
		bool sleep; /* true = sleep, false = active */
	} sleep_history[IMC_IPC_STATS_SLEEP_ENTRIES];

	bool sleep; /* true = sleep, false = active */
	unsigned long long sleep_time;
	unsigned long long active_time;
	unsigned long long last_sleep_time;
	unsigned long long last_active_time;

	struct imc_ipc_device_wake {
		bool active;
		unsigned long count;
		struct timeval ts;
		unsigned long long min_time;
		unsigned long long max_time;
		unsigned long long sum_time;
	} device_wake;

	struct dentry *dbgfs_sleep;
	struct dentry *dbgfs_sleep_history;
	struct dentry *info;
	struct dentry *dbgfs_device_sleep;
	struct dentry *dbgfs_exec_stage;

	struct ipc_pcie *pcie;
	struct ipc_imem *imem;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

static const char *device_sleep_str[3] = {
		"IPC_HOST_SLEEP_ENTER_SLEEP",
		"IPC_HOST_SLEEP_EXIT_SLEEP",
		"IPC_HOST_SLEEP_ENTER_SLEEP_NO_PROTOCOL"
};

/* imc_ipc/info -> print overall information */
static int ipc_debugfs_stats_info_show(struct seq_file *m, void *v)
{
	struct ipc_debugfs_stats *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	seq_printf(m, "\n***** %s *****\n\n", ipc_imem_version());

	ipc_imem_active_protocol_string(this->imem, m);
	ipc_hal_device(this->pcie, m);
	ipc_hal_stats(this->pcie, m);
	ipc_imem_stats(this->imem, m);
	return 0;
}

/* imc_ipc/info -> open funcion */
static int ipc_debugfs_stats_info_open(struct inode *inode,
			struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_stats_info_show,
				inode->i_private);
}

/* defines file operations for stats info debugfs attribute file */
static const struct file_operations ipc_debugfs_stats_info_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_stats_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* imc_ipc/sleep_history -> print sleep history */
static int ipc_debugfs_stats_sleep_history(
			struct seq_file *m, void *v)
{
	struct ipc_sleep_stats *entry;
	int i;
	unsigned long long prev;
	unsigned long long delta_ms, delta_us;
	unsigned long long usec;
	unsigned long long average;
	struct ipc_debugfs_stats *this = NULL;
	int idx;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -ENOENT;
	}

	this = m->private;
	idx = this->sleep_idx;

	seq_printf(m, "%20s  %13s  state\n", "timestamp (sec)", "delta (msec)");

	for (i = 0; i < IMC_IPC_STATS_SLEEP_ENTRIES - 1; i++) {
		entry = &this->sleep_history[idx];
		prev = IMC_IPC_STATS_TS2USEC(&entry->ts);
		if (++idx >= IMC_IPC_STATS_SLEEP_ENTRIES)
			idx = 0;

		entry = &this->sleep_history[idx];
		usec = IMC_IPC_STATS_TS2USEC(&entry->ts);
		if (usec == 0)
			continue;

		delta_ms = usec - prev;

		/* do_div() performs 64-bit/32-bit division and returns
		 * reminder. This macro shall be used to resolve "__udivdi3"
		 * and "__umoddi3" errors on 32-bit machines due to 64-bit
		 * division.
		 */
		if (prev)
			delta_us = do_div(delta_ms, 1000);
		else {
			delta_us = 0;
			delta_ms = 0;
		}

		seq_printf(m, "%13d.%06d  %9llu.%03llu  %s\n",
			   (int)entry->ts.tv_sec, (int)entry->ts.tv_usec,
			   delta_ms, delta_us,
			   entry->sleep ? "SLEEP" : "ACTIVE");
	}

	if (this->device_wake.count > 0) {
		average = this->device_wake.sum_time;
		(void)do_div(average, this->device_wake.count);

		seq_printf(m, "\nDEVICE WAKE min:%5llu",
			   this->device_wake.min_time);
		seq_printf(m, "\tmax:%5llu\taverage:%5llu (usec)\n",
			   this->device_wake.max_time, average);
	}
	return 0;
}

/* imc_ipc/sleep_history -> open funcion */
static int ipc_debugfs_stats_sleep_history_open(
			struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_stats_sleep_history,
				inode->i_private);
}

/* defines file operations for stats sleep history debugfs attribute file */
static const struct file_operations ipc_debugfs_stats_sleep_history_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_stats_sleep_history_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* imc_ipc/sleep -> print sleep information */
static int ipc_debugfs_stats_sleep(struct seq_file *m, void *v)
{
	struct timeval te;
	unsigned long long msec;
	unsigned long long active_time_ms, active_time_us;
	unsigned long long sleep_time_ms, sleep_time_us;
	struct ipc_debugfs_stats *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -ENOENT;
	}

	this = m->private;
	do_gettimeofday(&te);
	msec = IMC_IPC_STATS_TS2MSEC(&te);

	active_time_ms = this->active_time;
	sleep_time_ms = this->sleep_time;
	if (this->sleep)
		sleep_time_ms += msec - this->last_sleep_time;
	else
		active_time_ms += msec - this->last_active_time;

	/* do_div() performs 64-bit/32-bit division and returns reminder.
	 * This macro shall be used to resolve "__udivdi3" and "__umoddi3"
	 * errors on 32-bit machines due to 64-bit division.
	 */
	active_time_us = do_div(active_time_ms, 1000);
	sleep_time_us = do_div(sleep_time_ms, 1000);

	seq_printf(m, "ACTIVE\t%5llu.%03llu sec\n",
		   active_time_ms, active_time_us);

	seq_printf(m, "SLEEP\t%5llu.%03llu sec\n", sleep_time_ms,
		   sleep_time_us);

	return 0;
}

/* imc_ipc/sleep -> open funcion */
static int ipc_debugfs_stats_sleep_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_stats_sleep, inode->i_private);
}

/* defines file operations for stats sleep debugfs attribute file */
static const struct file_operations ipc_debugfs_stats_sleep_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_stats_sleep_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/*
 * Refer to header file for description
 */
void ipc_debugfs_stats_device_wake_event(struct ipc_debugfs_stats *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid params");
		return;
	}

	this->device_wake.active = true;
	do_gettimeofday(&this->device_wake.ts);
}

/*
 * Refer to header file for description
 */
void ipc_debugfs_stats_device_sleep_event(
		struct ipc_debugfs_stats *this, bool sleep)
{
	struct ipc_sleep_stats *entry;
	unsigned int idx;
	unsigned long long delta;
	unsigned long long msec;

	if (unlikely(!this)) {
		ipc_err("invalid params");
		return;
	}

	idx = this->sleep_idx;
	entry = &this->sleep_history[idx];

	do_gettimeofday(&entry->ts);
	msec = IMC_IPC_STATS_TS2MSEC(&entry->ts);
	entry->sleep = sleep;

	if (++idx >= IMC_IPC_STATS_SLEEP_ENTRIES)
		idx = 0;
	this->sleep_idx = idx;

	if (sleep != this->sleep) {
		if (sleep) {
			delta = msec - this->last_active_time;
			this->active_time += delta;
			this->last_sleep_time = msec;
		} else {
			delta = msec - this->last_sleep_time;
			this->sleep_time += delta;
			this->last_active_time = msec;
		}

		this->sleep = sleep;
	}

	/* device wake statistic */
	if (this->device_wake.active) {
		unsigned long long delta;

		this->device_wake.active = false;

		delta = IMC_IPC_STATS_TS2USEC(&entry->ts) -
			IMC_IPC_STATS_TS2USEC(&this->device_wake.ts);

		this->device_wake.sum_time += delta;
		this->device_wake.count++;

		if (delta < this->device_wake.min_time)
			this->device_wake.min_time = delta;

		if (delta > this->device_wake.max_time)
			this->device_wake.max_time = delta;
	}
}

/* imc_ipc/device_sleep -> open funcion */
static int ipc_debugfs_stats_device_sleep_open(
			struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file)) {
		ipc_err("invalid params");
		return -ENOENT;
	}

	file->private_data = inode->i_private;
	return 0;
}

/* imc_ipc/device_sleep -> update device sleep status funcion */
static ssize_t ipc_debugfs_stats_device_sleep_update(struct file *file,
			const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct ipc_debugfs_stats *this = NULL;
	char buf[32] = {0};
	unsigned int value;
	int rc;

	if (unlikely(!file || !file->private_data))
		return -1;

	this = file->private_data;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count))) {
		ipc_err("copy from user failed");
		return -EINVAL;
	}

	rc = kstrtouint(buf, 0, &value);
	if (rc) {
		ipc_err("write: echo <value> > send_device_sleep");
		return -EINVAL;
	}

	if (value > IPC_HOST_SLEEP_ENTER_SLEEP_NO_PROTOCOL) {
		ipc_err("<value> must be 0, 1, or 2.");
		return -EINVAL;
	}

	/* Send sleep message to CP */
	if (imem_msg_send_device_sleep(this->imem, value, false) == 0) {
		ipc_dbg("%s(%d) was sent", device_sleep_str[value], value);
	} else {
		ipc_dbg("%s(%d) sent fail", device_sleep_str[value], value);
		return -EPERM;
	}

	return count;
}

/* imc_ipc/device_sleep -> get device sleep status funcion */
static ssize_t ipc_debugfs_stats_device_sleep_get(
	struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	struct ipc_debugfs_stats *this = NULL;
	char buf[70] = {0};
	unsigned int len = 0;
	int device_sleep;

	/* avoid function enter again */
	if (*ppos > 0)
		return 0;

	if (unlikely(!file || !file->private_data)) {
		ipc_err("invalid params");
		return -1;
	}

	this = file->private_data;

	device_sleep = imem_get_device_sleep_state(this->imem);

	len = scnprintf(buf, sizeof(buf), "device_sleep = %s(%d)\n",
			device_sleep_str[device_sleep], device_sleep);
	ipc_dbg("device_sleep = %s(%d)", device_sleep_str[device_sleep],
		device_sleep);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

/* defines file operations for stats device sleep debugfs attribute file */
static const struct file_operations ipc_debugfs_stats_device_sleep_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_stats_device_sleep_open,
	.read = ipc_debugfs_stats_device_sleep_get,
	.write = ipc_debugfs_stats_device_sleep_update,
};

/* Display unbuffered exec stage
 */
static int ipc_debugfs_stats_exec_stage_show(struct seq_file *m, void *v)
{
	struct ipc_debugfs_stats *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	seq_printf(m, "%s\n", ipc_imem_get_exec_stage_string(this->imem));

	return 0;
}

/* imc_ipc/exec_stage_unbuffered -> open funcion */
static int ipc_debugfs_stats_exec_stage_open(
			struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_stats_exec_stage_show,
				inode->i_private);
}

/* defines file operations for stats exec stage debugfs attribute file */
static const struct file_operations ipc_debugfs_stats_exec_stage_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_stats_exec_stage_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/* Constructor function
 */
static int ipc_debugfs_stats_ctor(
			struct ipc_debugfs_stats *this,
			struct ipc_debugfs *dbgfs,
			struct ipc_imem *imem, struct ipc_pcie *pcie,
			struct ipc_dbg *dbg)
{
	struct timeval te;

	if (unlikely(!pcie || !imem ||
		!ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("Invalid args");
		goto info_fail;
	}

	this->imem = imem;
	this->pcie = pcie;
	this->dbg = dbg;

	this->info = debugfs_create_file(IMC_IPC_STATS_INFO, 0444,
			    ipc_debugfs_get_root_folder(dbgfs), this,
			    &ipc_debugfs_stats_info_fops);
	if (!this->info) {
		ipc_err("failed to create dbgfs info file");
		goto info_fail;
	}

	this->dbgfs_sleep = debugfs_create_file(IMC_IPC_STATS_SLEEP,
				0444, ipc_debugfs_get_root_folder(dbgfs),
				this, &ipc_debugfs_stats_sleep_fops);
	if (!this->dbgfs_sleep) {
		ipc_err("failed to create dbgfs sleep");
		goto sleep_fail;
	}

	this->dbgfs_sleep_history = debugfs_create_file(
			IMC_IPC_STATS_SLEEP_HISTORY, 0444,
			ipc_debugfs_get_root_folder(dbgfs),
			this, &ipc_debugfs_stats_sleep_history_fops);

	if (!this->dbgfs_sleep_history) {
		ipc_err("failed to create dbgfs sleep history");
		goto sleep_history_fail;
	}

	this->dbgfs_device_sleep = debugfs_create_file(
			IMC_IPC_STATS_DEVICE_SLEEP, 0664,
			ipc_debugfs_get_root_folder(dbgfs),
			this, &ipc_debugfs_stats_device_sleep_fops);

	if (!this->dbgfs_device_sleep) {
		ipc_err("failed to create dbgfs device sleep");
		goto device_sleep_fail;
	}

	this->dbgfs_exec_stage = debugfs_create_file(IMC_IPC_STATS_EXEC_STAGE,
		0444, ipc_debugfs_get_root_folder(dbgfs), this,
		&ipc_debugfs_stats_exec_stage_fops);

	if (!this->dbgfs_exec_stage) {
		ipc_err("failed to create dbgfs exec stage");
		goto exec_stage_fail;
	}


	/* get time stamp for active time */
	do_gettimeofday(&te);
	this->last_active_time = IMC_IPC_STATS_TS2MSEC(&te);

	/* device wake timing */
	this->device_wake.count = 0;
	this->device_wake.min_time = (unsigned long long)-1;

	return 0;

exec_stage_fail:
	debugfs_remove(this->dbgfs_device_sleep);
device_sleep_fail:
	debugfs_remove(this->dbgfs_sleep_history);
sleep_history_fail:
	debugfs_remove(this->dbgfs_sleep);
sleep_fail:
	debugfs_remove(this->info);
info_fail:
	return -1;
}

/*
 * Refer to header file for description
 */
struct ipc_debugfs_stats *ipc_debugfs_stats_alloc(struct ipc_pcie *pcie,
			struct ipc_debugfs *dbgfs, struct ipc_imem *imem,
			struct ipc_dbg *dbg)
{
	struct ipc_debugfs_stats *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("stats alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_stats_ctor(this, dbgfs, imem, pcie, dbg)) {
		ipc_err("stats ctor failed");
		goto ctor_fail;
	}
	return this;

ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/* Destructor function
 */
static void ipc_debugfs_stats_dtor(struct ipc_debugfs_stats *this)
{
	debugfs_remove(this->info);
	debugfs_remove(this->dbgfs_sleep);
	debugfs_remove(this->dbgfs_sleep_history);
	debugfs_remove(this->dbgfs_device_sleep);
	debugfs_remove(this->dbgfs_exec_stage);
}

/*
 * Refer to header file for description
 */
void ipc_debugfs_stats_dealloc(struct ipc_debugfs_stats **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_stats_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
