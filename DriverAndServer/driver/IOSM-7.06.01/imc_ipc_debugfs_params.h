/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_PARAMS_H
#define IMC_IPC_DEBUGFS_PARAMS_H

struct ipc_params;
struct ipc_debugfs;
struct ipc_debugfs_params;


/*
 * Frees all the memory allocated for the IPC parameters structure.
 *
 * @this_pp: pointer to the IPC parameters data-struct
 */
void ipc_debugfs_params_dealloc(struct ipc_debugfs_params **this_pp);

/*
 * Allocates memory for the IPC parameters structure.
 *
 * @params: pointer to the struct ipc_params
 * @dbgfs: pointer to the debugfs data-struct
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs_params *ipc_debugfs_params_alloc(struct ipc_params *params,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg);

#endif /* IMC_IPC_DEBUGFS_PARAMS_H */
