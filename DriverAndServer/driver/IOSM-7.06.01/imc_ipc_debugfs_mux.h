/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_MUX_H
#define IMC_IPC_DEBUGFS_MUX_H

struct ipc_debugfs_mux;

/*
 * Allocates memory for the mux stats structure.
 *
 * @dbgfs: pointer to global struct ipc_debugfs
 * @mux_inst_nr: mux channel instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs_mux *ipc_debugfs_mux_alloc(
			struct ipc_debugfs *dbgfs,
			int mux_inst_nr, struct ipc_dbg *dbg);

/*
 * Frees all the memory allocated for the mux stats
 * structure.
 *
 * @this_pp: pointer to the mux stats data-struct
 */
void ipc_debugfs_mux_dealloc(struct ipc_debugfs_mux **this_pp);


/* Logging function for the flow control data
 *
 * @this: Pointer to mux stats data-struct
 * @session_id: session id of the event
 * @flow_ctrl: flow control enabled / disabled
 * @transaction_id: transaction id
 * @adb_size: aggregate data block size
 * @payload_size: payload size
 * @ul_credits: available credits
 */
void ipc_debugfs_mux_log_event(
		struct ipc_debugfs_mux *this,
		int session_id, bool flow_ctl,
		int transaction_id,
		unsigned long long adb_size,
		unsigned long long payload_size,
		int ul_credits);

#endif /* IMC_IPC_DEBUGFS_MUX_H */
