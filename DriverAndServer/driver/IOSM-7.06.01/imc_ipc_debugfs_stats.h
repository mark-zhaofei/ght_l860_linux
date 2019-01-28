/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_STATS_H
#define IMC_IPC_DEBUGFS_STATS_H

struct ipc_debugfs;
struct ipc_debugfs_stats;
struct ipc_imem;
struct ipc_pcie;
struct ipc_dbg;
struct ipc_dbgfs;

/*
 * Frees all the memory allocated for the stats
 * structure.
 *
 * @this_pp: pointer to the stats data-struct
 */
void ipc_debugfs_stats_dealloc(struct ipc_debugfs_stats **this_pp);

/*
 * Allocates memory for the stats structure.
 *
 * @pcie: pointer to core driver data-struct
 * @dbgfs: pointer to debugfs data-struct
 * @imem: pointer to imem data-struct
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs_stats *ipc_debugfs_stats_alloc(
		struct ipc_pcie *pcie,
		struct ipc_debugfs *dbgfs, struct ipc_imem *imem,
		struct ipc_dbg *dbg);

/* add sleep/wake up event.
 *
 * @this: pointer to ipc stats data-struct
 * @sleep: sleep=true -> device sleep, sleep=false -> device active
 */
void ipc_debugfs_stats_device_sleep_event(
		struct ipc_debugfs_stats *this, bool sleep);

/*
 * execute device wake statistic
 *
 * @this: pointer to ipc stats data-struct
 */
void ipc_debugfs_stats_device_wake_event(
		struct ipc_debugfs_stats *this);

#endif				/* IMC_IPC_DEBUGFS_STATS_H */
