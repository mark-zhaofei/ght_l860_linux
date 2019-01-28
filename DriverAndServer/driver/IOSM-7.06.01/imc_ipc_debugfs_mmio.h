/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_MMIO_H
#define IMC_IPC_DEBUGFS_MMIO_H

struct ipc_mmio;
struct ipc_debugfs;
struct ipc_debugfs_mmio;

/**
 * Allocate MMIO debugfs
 * @mmio: pointer to struct ipc_mmio
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to instance on success else NULL
 */
struct ipc_debugfs_mmio *ipc_debugfs_mmio_alloc(
		struct ipc_mmio *mmio, struct ipc_debugfs *dbgfs,
		struct ipc_dbg *dbg);

/**
 * dealloc MMIO debugfs
 * @this_pp: pointer to pointer to MMIO debugfs instance data
 */
void ipc_debugfs_mmio_dealloc(struct ipc_debugfs_mmio **this_pp);

#endif /* !defined(IMC_IPC_DEBUGFS_MMIO_H) */

