/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_PARC_H
#define IMC_IPC_DEBUGFS_PARC_H

struct ipc_debugfs_parc;
struct ipc_pcie_parc;
struct ipc_debugfs;
struct ipc_dbg;


/*
 * Frees all the memory allocated for the parc structure.
 *
 * @this_pp: pointer to the stats data-struct
 */
void ipc_debugfs_parc_dealloc(struct ipc_debugfs_parc **this_pp);

/*
 * Allocates memory for the parc structure.
 * @dbgfs: Pointer to debugfs data-struct
 * @parc: Pointer to pcie parc handler data-struct
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs_parc *ipc_debugfs_parc_alloc(struct ipc_debugfs *dbgfs,
			struct ipc_pcie_parc *parc, struct ipc_dbg *dbg);


/*
 * Get the exec stage set for testing PARC
 *
 * @this: pointer to the stats data-struct
 *
 *returns current parc_test_mode value.
 */
u32 ipc_debugfs_parc_get_test_mode(struct ipc_debugfs_parc *this);


/*
 * Get the exec stage set for testing PARC through MSI
 *
 * @this: pointer to the stats data-struct
 *
 *returns current parc_msi_test_mode value.
 */
u32 ipc_debugfs_parc_get_msi_test_mode(struct ipc_debugfs_parc *this);


#endif /* IMC_IPC_DEBUGFS_PARC_H */
