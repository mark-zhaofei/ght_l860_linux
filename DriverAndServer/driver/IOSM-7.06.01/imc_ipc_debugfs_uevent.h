/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_UEVENT_H
#define IMC_IPC_DEBUGFS_UEVENT_H


struct ipc_uevent;
struct ipc_debugfs;
struct ipc_debugfs_uevent;

/*
 * Allocates memory for the uevent structure.
 *
 * @uevent: pointer to struct ipc_uevent
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs_uevent *ipc_debugfs_uevent_alloc(
		struct ipc_uevent *uevent, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg);

/*
 * Frees all the memory allocated for the uevent
 * structure.
 *
 * @this_pp: pointer to the struct ipc_debugfs_uevent data-struct
 */
void ipc_debugfs_uevent_dealloc(struct ipc_debugfs_uevent **this_pp);

#endif
