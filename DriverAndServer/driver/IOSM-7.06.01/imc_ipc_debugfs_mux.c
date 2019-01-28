/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "imc_ipc_debugfs.h"
#include "imc_ipc_imem.h"
#include "imc_ipc_mux.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"


#define IMC_IPC_STATS_INFO "mux"
#define MUX_DBG_ENTRIES 512


/* Structure for MUX debug logging infos
 */
struct dbg_session_data {
	struct timeval ts;
	bool flow_ctl_enabled;
	int transaction_id;
	unsigned long long accumulated_adb_size;
	unsigned long long accumulated_payload;
	int ul_flow_credits;
};


/* Structure for maintaining the MUX debug logging info
 */
struct ipc_debugfs_mux {
	unsigned int dbg_idx[IPC_IMEM_MUX_SESSION_ENTRIES];
	struct dbg_session_data
			data[IPC_IMEM_MUX_SESSION_ENTRIES][MUX_DBG_ENTRIES];

	struct dentry *mux_dentry;

	char dbgfs_entry_name[10];

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};


/* imc_ipc/mux -> print overall information */
static int ipc_debugfs_mux_show(struct seq_file *m, void *v)
{
	struct dbg_session_data *p_entry;
	int if_id, i, idx;
	unsigned long long prev;
	unsigned long long delta_ms;
	unsigned long long msec;
	struct ipc_debugfs_mux *this;

	if (unlikely(!m || !m->private))
		return -ENOENT;

	this = m->private;

	for (if_id = 0; if_id < IPC_IMEM_MUX_SESSION_ENTRIES; if_id++) {
		idx = this->dbg_idx[if_id];

		seq_printf(m, "SESSION:%d\n", if_id);
		seq_puts(m, "---------\n");
		seq_printf(m, "Current Index:%d\n",
				this->dbg_idx[if_id]);

		seq_printf(m, "%4s  %20s  %13s  %10s  %8s  %16s  %18s  %10s\n",
			"idx", "timestamp (sec)", "delta (msec)", "Flow_Ctrl",
			"Txn_id", "Acc. ADB Size", "Acc. Payload Size",
			"UL Credits");
		for (i = 0; i < MUX_DBG_ENTRIES - 1; i++) {
			p_entry = &this->data[if_id][idx];
			prev = IMC_IPC_STATS_TS2MSEC(&p_entry->ts);

			if (++idx >= MUX_DBG_ENTRIES)
				idx = 0;

			p_entry = &this->data[if_id][idx];
			msec = IMC_IPC_STATS_TS2MSEC(&p_entry->ts);

			if (msec == 0)
				continue;

			delta_ms = msec - prev;

			if (!prev)
				delta_ms = 0;

			seq_printf(m,
				"%4d %14d.%06d  %13llu  %10s  %8d  %16llu  %18llu  %10d\n",
				idx, (int)p_entry->ts.tv_sec,
				(int)p_entry->ts.tv_usec, delta_ms,
				p_entry->flow_ctl_enabled ? "ON" : "OFF",
				p_entry->transaction_id,
				p_entry->accumulated_adb_size,
				p_entry->accumulated_payload,
				p_entry->ul_flow_credits);

			prev = msec;
		}
		seq_puts(m, "\n#########\n\n");
	}

	return 0;

}


/* Open function
 */
static int ipc_debugfs_mux_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_mux_show, inode->i_private);
}

/* defines file operations for debugfs attribute file */
static const struct file_operations ipc_debugfs_mux_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_mux_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/* Logs the events in buffer
 */
void ipc_debugfs_mux_log_event(
		struct ipc_debugfs_mux *this,
		int session_id, bool flow_ctl,
		int transaction_id,
		unsigned long long adb_size,
		unsigned long long payload_size,
		int ul_credits)
{
	struct dbg_session_data *p_entry;
	unsigned int idx;

	if (unlikely(!this))
		return;

	idx = this->dbg_idx[session_id];
	p_entry = &this->data[session_id][idx];

	/* get time stamp for active time */
	do_gettimeofday(&p_entry->ts);
	p_entry->flow_ctl_enabled = flow_ctl;
	p_entry->transaction_id = transaction_id;
	p_entry->accumulated_adb_size = adb_size;
	p_entry->accumulated_payload = payload_size;
	p_entry->ul_flow_credits = ul_credits;

	if (++idx >= MUX_DBG_ENTRIES)
		idx = 0;

	this->dbg_idx[session_id] = idx;

}


/* MUX debugfs constructor function
 */
static int ipc_debugfs_mux_ctor(struct ipc_debugfs_mux *this,
			struct ipc_debugfs *dbgfs, int mux_inst_nr,
			struct ipc_dbg *dbg)
{
	/* NOTE: adapt mux_inst_nr check if Multi MUX is needed
	 * in future for one device
	 */
	if (unlikely((mux_inst_nr != 0) ||
			!ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("invalid arguments");
		return -1;
	}

	this->dbg = dbg;

	snprintf(this->dbgfs_entry_name, sizeof(this->dbgfs_entry_name),
			"%s%d",	IMC_IPC_STATS_INFO, mux_inst_nr);

	this->mux_dentry = debugfs_create_file(this->dbgfs_entry_name,
				0444, ipc_debugfs_get_root_folder(dbgfs),
				this, &ipc_debugfs_mux_fops);
	if (unlikely(!this->mux_dentry)) {
		ipc_err("debugfs file can't be created");
		return -1;
	}

	return 0;
}


/**
 * Refer to header file for description
 */
struct ipc_debugfs_mux *ipc_debugfs_mux_alloc(struct ipc_debugfs *dbgfs,
				int mux_inst_nr, struct ipc_dbg *dbg)
{
	struct ipc_debugfs_mux *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("allocator failed");
		goto ret_fail;
	}

	if (ipc_debugfs_mux_ctor(this, dbgfs, mux_inst_nr, dbg))
		goto ctor_fail;
	return this;

ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/**
 * MUX stats destructor
 * @this: pointer to MUX debug stats
 */
static void ipc_debugfs_mux_dtor(struct ipc_debugfs_mux *this)
{
	debugfs_remove(this->mux_dentry);
}


/**
 * Refer to header file for description
 */
void ipc_debugfs_mux_dealloc(struct ipc_debugfs_mux **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_mux_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
