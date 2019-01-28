/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_RAS_DES_H
#define IMC_IPC_DEBUGFS_RAS_DES_H


struct ipc_debugfs_ras_des;
struct ipc_pcie;
struct ipc_pcie_ras_des;
struct ipc_debugfs;
struct ipc_dbg;

/*
 * Frees all the memory allocated for the RAS DES structure.
 *
 * @this_pp: pointer to the stats data-struct
 */
void ipc_debugfs_ras_des_dealloc(struct ipc_debugfs_ras_des **this_pp);

/*
 * Allocates memory for the RAS DES structure.
 *
 * @dbgfs: pointer to struct ipc_debugfs.
 * @ras_des: pointer to struct ipc_pcie_ras_des.
 * @pcie: pointer to struct ipc_pcie
 * @dbg: pointer to debug component
 *
 * returns pointer to allocated structure or NULL on failure.
 */
struct ipc_debugfs_ras_des *ipc_debugfs_ras_des_alloc(struct ipc_debugfs *dbgfs,
		struct ipc_pcie_ras_des *ras_des, struct ipc_pcie *pcie,
		struct ipc_dbg *dbg);

#endif /* IMC_IPC_DEBUGFS_RAS_DES_H */

