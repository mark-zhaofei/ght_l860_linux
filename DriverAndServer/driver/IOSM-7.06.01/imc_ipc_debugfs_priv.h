/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUG_H
#define IMC_IPC_DEBUG_H

#include "imc_ipc_debugfs_stats.h"
#include "imc_ipc_debugfs_hpu_stress.h"
#include "imc_ipc_debugfs_mux.h"
#include "imc_ipc_debugfs_parc.h"
#include "imc_ipc_debugfs_uevent.h"
#include "imc_ipc_debugfs_ras_des.h"
#include "imc_ipc_debugfs_params.h"
#include "imc_ipc_debugfs_mmio.h"
#include "imc_ipc_debugfs_mux.h"
#ifdef IPC_GPIO_MDM_CTRL
#include "imc_ipc_debugfs_l2test.h"
#endif

#define IMC_IPC_STATS_TS2MSEC(ts) ((ts)->tv_sec * 1000LL + (ts)->tv_usec / 1000)
#define IMC_IPC_STATS_TS2USEC(ts) ((ts)->tv_sec * 1000000LL + (ts)->tv_usec)

/*
 * Get debugfs root folder pointer
 *
 * @this: Pointer to debugfs data-struct
 *
 * returns pointer to struct dentry else NULL
 */
struct dentry *ipc_debugfs_get_root_folder(struct ipc_debugfs *this);

/*
 * Check if debugfs is available
 *
 * @this: Pointer to debugfs data-struct
 *
 * returns true if debugfs is available and initialized else false
 */
bool ipc_debugfs_is_available(struct ipc_debugfs *this);

/*
 * Allocates memory for the debugfs structure.
 *
 * @instance_nr: Modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_debugfs *ipc_debugfs_alloc(unsigned int instance_nr,
				struct ipc_dbg *dbg);

/*
 * Frees the memory allocated for the debugfs
 * component.
 *
 * @this: pointer to the debugfs data-struct
 */
void ipc_debugfs_dealloc(struct ipc_debugfs **this_pp);

#endif /* IMC_IPC_DEBUG_H */

