/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include "imc_ipc_params.h"
#include "imc_ipc_util.h"
#include "imc_ipc_debugfs.h"
#include "imc_ipc_dbg.h"


struct ipc_debugfs_params {
	/* Params directory in debugfs */
	struct dentry *param_dir;
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/**
 * IPC params ctor debugfs function
 *
 * @this: pointer to struct ipc_debugfs_params
 * @params: pointer to struct ipc_params
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * return 0 on success else -1
 */
static int ipc_debugfs_params_ctor(
	struct ipc_debugfs_params *this, struct ipc_params *params,
	struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct dentry *param_dir;

	if (unlikely(!params ||
			!ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("Invalid arguments");
		return -1;
	}

	this->dbg = dbg;

	/* Create the params directory */
	this->param_dir = debugfs_create_dir("params",
					ipc_debugfs_get_root_folder(dbgfs));
	if (unlikely(!this->param_dir)) {
		ipc_err("create param debugfs directory failed");
		return -1;
	}

	param_dir = this->param_dir;

	/* Control blocking mode of the sio char read entry point. */
	if (!debugfs_create_u32("sio_read_unblock", 0664, param_dir,
			&(params->sio_read_unblock)))
		goto error;

	/* TD upate timeout in usec */
	if (!debugfs_create_u32("td_update_tmo", 0664, param_dir,
			&(params->td_update_tmo)))
		goto error;

	/* force update timeout in usec */
	if (!debugfs_create_u32("fast_update_tmo", 0664, param_dir,
			&(params->fast_update_tmo)))
		goto error;

	/* sleep_stress */
	if (!debugfs_create_u32("wakeup_test", 0664, param_dir,
			&(params->wakeup_test)))
		goto error;

	/* concurrent wake stress */
	if (!debugfs_create_u32("concurrent_wake_test", 0664, param_dir,
			&(params->concurrent_wake_test)))
		goto error;

	/* Blocks providing TDs to CP for the set bits in the Mask.
	 * Works only for DL pipes
	 */
	if (!debugfs_create_u32("block_td_pipe_mask", 0664, param_dir,
			&(params->block_td_pipe_mask)))
		goto error;

	/* Unblocks specified number of TDs if tds_ctrl_mask is set */
	if (!debugfs_create_u32("nr_of_tds_to_unblock", 0664, param_dir,
			&(params->nr_of_tds_to_unblock)))
		goto error;

	/* Unblocks providing nr_of_tds_to_unblock TDs to CP for
	 * the set bits in the Mask. Works only for DL pipes
	 */
	if (!debugfs_create_u32("tds_ctrl_mask", 0664, param_dir,
			&(params->tds_ctrl_mask)))
		goto error;


	/* Host wake counter while block_td_pipe_mask is non-zero */
	if (!debugfs_create_u32("host_wakeup_cnt", 0664, param_dir,
			&(params->host_wakeup_cnt)))
		goto error;

	/* Enables HP update identifiers */
	if (!debugfs_create_u32("hp_update_debug", 0664,
			param_dir, &(params->hp_update_debug)))
		goto error;

	/* Mux Aggregation UL ADB size */
	if (!debugfs_create_u32("mux_ul_adb_size", 0664,
			param_dir, &(params->mux_ul_adb_size)))
		goto error;


	/* Lower threshold value in bytes for IP MUX data to inform network
	 * stack to restart transfer
	 */
	if (!debugfs_create_u32("mux_flow_ctrl_low_thresh_b", 0664,
			param_dir, &(params->mux_flow_ctrl_low_thresh_b)))
		goto error;


	/* High threshold value in bytes for IP MUX data to inform network
	 * stack to stop transfer
	 */
	if (!debugfs_create_u32("mux_flow_ctrl_high_thresh_b", 0664,
			param_dir, &(params->mux_flow_ctrl_high_thresh_b)))
		goto error;

	/* MUX flow control enable/disable */
	if (!debugfs_create_u32("mux_flow_ctrl_en", 0664, param_dir,
			&(params->mux_flow_ctrl_en)))
		goto error;

	if (!debugfs_create_u32("psi_start_timeout", 0664, param_dir,
			&(params->psi_start_timeout)))
		goto error;

	if (!debugfs_create_u32("boot_check_timeout", 0664, param_dir,
			&(params->boot_check_timeout)))
		goto error;

	if (!debugfs_create_u64("mux_cmd_run_timeout", 0664, param_dir,
			&(params->mux_cmd_run_timeout)))
		goto error;

	if (!debugfs_create_u32("in_band_crash_signal", 0664, param_dir,
			&(params->in_band_crash_signal)))
		goto error;

	if (!debugfs_create_u32("mux_netdev_flow_ctrl_threshold", 0664,
				param_dir,
				&(params->mux_netdev_flow_ctrl_threshold)))
		goto error;

	if (!debugfs_create_u32("mux_lite_buf_size", 0664,
				param_dir,
				&(params->mux_lite_buf_size)))
		goto error;

	if (!debugfs_create_u32("trace_td_numbers", 0664,
				param_dir,
				&(params->trace_td_numbers)))
		goto error;

	return 0;

error:
	ipc_err("create param debugfs files failed");
	debugfs_remove_recursive(this->param_dir);
	return -1;
}


/**
 * IPC params destructor
 * this: pointer to struct ipc_params
 */
static void ipc_debugfs_params_dtor(struct ipc_debugfs_params *this)
{
	debugfs_remove_recursive(this->param_dir);
}


/**
 * Refer to header file for description
 */
struct ipc_debugfs_params *ipc_debugfs_params_alloc(struct ipc_params *params,
			struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_debugfs_params *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_params_ctor(this, params, dbgfs, dbg)) {
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
 * Refer to header file for description
 */
void ipc_debugfs_params_dealloc(struct ipc_debugfs_params **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_params_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

