/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_HPU_STRESS_H
#define IMC_IPC_DEBUGFS_HPU_STRESS_H

struct ipc_dbg;
struct ipc_pcie;
struct ipc_debugfs;
struct ipc_debugfs_hpu_stress;

/**
 * Allocate a debugfs_hpu_stress component, providing a debugfs entry
 * for periodically triggering head pointer interrupts
 *
 * @debugfs: pointer to debugfs component
 * @pcie: pointer to pcie component
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated debugfs_hpu_stress data-struct
 * or NULL on failure.
 */
struct ipc_debugfs_hpu_stress *ipc_debugfs_hpu_stress_alloc(
				struct ipc_debugfs *debugfs,
				struct ipc_pcie *pcie, struct ipc_dbg *dbg);

/**
 * Free a debugfs_hpu_stress component, invalidating its pointer.
 *
 * @this_pp pointer to pointer to debugfs_hpu_stress component
 */
void ipc_debugfs_hpu_stress_dealloc(
	struct ipc_debugfs_hpu_stress **this_pp);

#endif /* IMC_IPC_DEBUGFS_HPU_STRESS_H */
