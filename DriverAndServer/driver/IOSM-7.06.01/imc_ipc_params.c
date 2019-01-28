/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include "imc_ipc_imem.h"
#include "imc_ipc_mux.h"
#include "imc_ipc_params.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_debugfs.h"

struct ipc_params_priv {

	/* IPC parameters */
	struct ipc_params ipc_params;

	/* Params directory in debugfs */
	struct ipc_debugfs_params *params_dbgfs;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/**
 * IPC params constructor
 *
 * @this: pointer to struct ipc_params
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * return 0 on success else -1
 */
static int ipc_params_ctor(struct ipc_params *this,
			struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_params_priv *priv = container_of(this,
					struct ipc_params_priv, ipc_params);

	priv->dbg = dbg;

	/* Initialize default values of all configurable parameters */
	this->td_update_tmo = TD_UPDATE_DEFAULT_TIMEOUT_USEC;
	this->fast_update_tmo = FORCE_UPDATE_DEFAULT_TIMEOUT_USEC;
	this->wakeup_test = 0;
	this->concurrent_wake_test = 0;
	this->block_td_pipe_mask = 0;
	this->nr_of_tds_to_unblock = 0;
	this->tds_ctrl_mask = 0;
	this->host_wakeup_cnt = 0;
	this->hp_update_debug = 1;
	this->mux_ul_adb_size = IPC_MEM_MAX_UL_ADB_BUF_SIZE;
	this->mux_flow_ctrl_low_thresh_b = IPC_MEM_MUX_UL_FLOWCTRL_LOW_B;
	this->mux_flow_ctrl_high_thresh_b =
		IPC_MEM_MUX_UL_FLOWCTRL_HIGH_B;
	this->mux_flow_ctrl_en = 1;
	this->sio_read_unblock = 0;
	this->psi_start_timeout = PSI_START_DEFAULT_TIMEOUT;
	this->boot_check_timeout = BOOT_CHECK_DEFAULT_TIMEOUT;
	this->mux_cmd_run_timeout =
		IPC_MUX_CMD_RUN_DEFAULT_TIMEOUT;
	this->in_band_crash_signal = 1;
	this->mux_netdev_flow_ctrl_threshold =
		IPC_MEM_MUX_UL_SESS_FCON_THRESHOLD;
	this->mux_lite_buf_size = IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE;
	this->trace_td_numbers = IPC_MEM_TDS_TRC;
	this->trace_td_buff_size = IPC_MEM_MAX_DL_TRC_BUF_SIZE;

	/* create params debugfs */
	priv->params_dbgfs = ipc_debugfs_params_alloc(this, dbgfs, dbg);

	return 0;
}


/**
 * Refer to header file for description
 */
struct ipc_params *ipc_params_alloc(struct ipc_debugfs *dbgfs,
				struct ipc_dbg *dbg)
{
	struct ipc_params_priv *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto alloc_fail;
	}

	if (ipc_params_ctor(&this->ipc_params, dbgfs, dbg)) {
		ipc_err("params ctor failed");
		goto ctor_fail;
	}

	return &this->ipc_params;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}


/**
 * IPC params destructor
 * this: pointer to struct ipc_params
 */
static void ipc_params_dtor(struct ipc_params *this)
{
	struct ipc_params_priv __maybe_unused *priv = container_of(this,
					struct ipc_params_priv, ipc_params);

	ipc_debugfs_params_dealloc(&priv->params_dbgfs);
}

/**
 * Refer to header file for description
 */
void ipc_params_dealloc(struct ipc_params **this_pp)
{
	if (this_pp && *this_pp) {
		struct ipc_params_priv *priv = container_of(*this_pp,
				struct ipc_params_priv, ipc_params);
		ipc_params_dtor(*this_pp);
		ipc_util_kfree(priv);
		*this_pp = NULL;
	}
}

