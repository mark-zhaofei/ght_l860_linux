/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef _IMC_IPC_PARAMS_H
#define _IMC_IPC_PARAMS_H

struct ipc_debugfs;
struct ipc_dbg;

/* Default value for TD timeout. */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define TD_UPDATE_DEFAULT_TIMEOUT_USEC 19000
#else
#define TD_UPDATE_DEFAULT_TIMEOUT_USEC 1900
#endif

/* Force update default timeout. */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define FORCE_UPDATE_DEFAULT_TIMEOUT_USEC 5000
#else
#define FORCE_UPDATE_DEFAULT_TIMEOUT_USEC 500
#endif

/* MUX UL flow control lower threshold in bytes */
#define IPC_MEM_MUX_UL_FLOWCTRL_LOW_B	10240	/* 10KB */

/* MUX UL flow control higher threshold in bytes */
#define IPC_MEM_MUX_UL_FLOWCTRL_HIGH_B	(110 * 1024)	/* 5ms worth of data*/

/* MUX UL session threshold in number of packets */
#define IPC_MEM_MUX_UL_SESS_FCON_THRESHOLD	(64)

/* MUX UL session threshold factor */
#define IPC_MEM_MUX_UL_SESS_FCOFF_THRESHOLD_FACTOR	(4)

/* MUX UL session threshold for low TPUT platform */
#define IPC_MEM_MUX_UL_SESS_FCON_THRESHOLD_IBIS		(12)

/* Legacy trace configuration */
/* Number of TDs on the trace channel */
#define IPC_MEM_TDS_TRC_LEGACY				32
/* Trace TD buffer size. */
#define IPC_MEM_MAX_DL_TRC_BUF_SIZE_LEGACY		8192

/* Number of TDs on the trace channel */
#define IPC_MEM_TDS_TRC					64
/* Trace TD buffer size. */
#define IPC_MEM_MAX_DL_TRC_BUF_SIZE			16384

/*
 * Default delay till CP PSI image is running and modem updates the
 * execution stage.
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define PSI_START_DEFAULT_TIMEOUT 10000
#else
#define PSI_START_DEFAULT_TIMEOUT 3000
#endif

/*
 * Default time out when closing SIO, till the modem is in
 * running state.
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define BOOT_CHECK_DEFAULT_TIMEOUT 4000
#else
#define BOOT_CHECK_DEFAULT_TIMEOUT 400
#endif

/*
 * Default time out for sending IPC session commands like
 * open session, close session etc
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_MUX_CMD_RUN_DEFAULT_TIMEOUT 10000
#else
#define IPC_MUX_CMD_RUN_DEFAULT_TIMEOUT  1000   /* 1 second */
#endif

/* IPC char. device default mode */
#ifdef IPC_EXTERNAL_BUILD
#define IPC_CHAR_DEVICE_DEFAULT_MODE 0600
#else
#define IPC_CHAR_DEVICE_DEFAULT_MODE 0666
#endif

/**
 * @struct ipc_parameters
 *
 * Contains all configurable parameters
 *
 * @var	ipc_parameters::mux_cmd_run_timeout
 *		Timeout for mux command messages in run mode
 *		(RUN). For example open session, flow control
 *		etc.
 *		unit: milliseconds.
 *
 * @var	ipc_parameters::td_update_tmo
 *		TD upate timeout.
 *		unit : useconds
 *
 * @var	ipc_parameters::fast_update_tmo
 *		force HP update timeout.
 *		unit : useconds
 *
 * @var	ipc_parameters::device_sleep
 *		Disable device sleep support when set
 *		to zero, otherwise enabled.
 *
 * @var	ipc_parameters::wakeup_test
 *		sleep stress, disabled when zero, enabled
 *		otherwise.
 *
 * @var	ipc_parameters::concurrent_wake_test
 *		concurrent wake test, disabled when zero,
 *		enabled otherwise.
 *
 * @var	ipc_parameters::block_td_pipe_mask
 *		Blocks providing TDs to CP for the set
 *		bits in the Mask. Supported only for
 *		DL pipes.
 *
 * @var	ipc_parameters::nr_of_tds_to_unblock
 *		Unblocks specified number of TDs if
 *		tds_ctrl_mask is set.
 *
 * @var	ipc_parameters::tds_ctrl_mask
 *		Unblocks providing nr_of_tds_to_unblock
 *		TDs to CP for the set bits in the Mask.
 *		Supported only for DL pipes.
 *
 * @var	ipc_parameters::host_wakeup_cnt
 *		Host wake counter while block_td_pipe_mask
 *		is non-zero.
 *
 * @var	ipc_parameters::hp_update_debug
 *		Enables HP update identifiers.
 *
 * @var	ipc_parameters::mux_ul_adb_size
 *		MUX UL ADB size.
 *
 * @var	ipc_parameters::mux_flow_ctrl_low_thresh_b
 *		Lower threshold value in bytes for IP MUX
 *		data to inform network stack to restart
 *		transfer.
 *
 * @var	ipc_parameters::mux_flow_ctrl_high_thresh_b
 *		High threshold value in bytes for IP MUX
 *		data to inform network stack to stop transfer.
 *
 * @var	ipc_parameters::mux_flow_ctrl_en
 *		Flow control throttle disabled if set to zero,
 *		enabled otherwise.
 *
 * @var	ipc_parameters::sio_read_unblock
 *		Controls blocking mode of the sio char
 *		read entry point. Zero is for blocking
 *		otherwise non-blocking.
 *
 * @var	ipc_parameters::psi_start_timeout
 *		Wait for psi_start_timeout milliseconds until
 *		the CP PSI image is running and updates the
 *		execution_stage field. If the CP is fast enough
 *		to run PSI update the execution stage then we
 *		break the wait loop.
 *		unit : milliseconds
 *
 * @var	ipc_parameters::boot_check_timeout
 *		In case of flashless configuration, when closing
 *		the SIO channel, delay the close until modem is
 *		RUNNING.
 *		unit : milliseconds
 *
 * @var	ipc_parameters::in_band_crash_signal
 *		Modem crash notification configuration. If this value is
 *		non-zero then FEATURE_SET message will be sent to the Modem
 *		as a result the  Modem will signal Crash via Execution Stage
 *		register. If this value is zero then Modem will use
 *		out-of-band method to notify about it's Crash.
 *
 * @var ipc_parameters::mux_netdev_flow_ctrl_threshold
 *		Threshold for netdev stop when flow control is On
 *
 * @var ipc_parameters::mux_lite_buf_size
 *		Set the TD size for mux lite
 *
 * @var ipc_parameters::trace_td_numbers
 *		Number of TDs for trace channel
 *
 * @var ipc_parameters::trace_td_buff_size
 *		Trace TD buffer size
 */
struct ipc_params {
	u64 mux_cmd_run_timeout;
	u32 td_update_tmo;
	u32 fast_update_tmo;
	u32 wakeup_test;
	u32 concurrent_wake_test;
	u32 block_td_pipe_mask;
	u32 nr_of_tds_to_unblock;
	u32 tds_ctrl_mask;
	u32 host_wakeup_cnt;
	u32 hp_update_debug;
	u32 mux_ul_adb_size;
	u32 mux_flow_ctrl_low_thresh_b;
	u32 mux_flow_ctrl_high_thresh_b;
	u32 mux_flow_ctrl_en;
	u32 sio_read_unblock;
	u32 psi_start_timeout;
	u32 boot_check_timeout;
	u32 in_band_crash_signal;
	u32 mux_netdev_flow_ctrl_threshold;
	u32 mux_lite_buf_size;
	u32 trace_td_numbers;
	u32 trace_td_buff_size;
};

/*
 * Frees all the memory allocated for the IPC parameters structure.
 *
 * @this_pp: pointer to the IPC parameters data-struct
 */
void ipc_params_dealloc(struct ipc_params **this_pp);

/*
 * Allocates memory for the IPC parameters structure.
 *
 * @dbgfs: pointer to the debugfs data-struct
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_params *ipc_params_alloc(struct ipc_debugfs *dbgfs,
				struct ipc_dbg *dbg);


#endif /* _IMC_IPC_PARAMS_H */
