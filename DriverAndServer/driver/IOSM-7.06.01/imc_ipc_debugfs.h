/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DEBUGFS_H
#define IMC_IPC_DEBUGFS_H

#ifdef IPC_EXTERNAL_BUILD

/* Stubbed functions for non-debug version */
#define ipc_debugfs_alloc(a, b) NULL
#define ipc_debugfs_dealloc(a)
#define ipc_debugfs_get_root_folder(x) NULL
#define ipc_debugfs_is_available(x) false
#define ipc_debugfs_stats_dealloc(x)
#define ipc_debugfs_stats_alloc(a, b, c, d) NULL
#define ipc_debugfs_stats_device_sleep_event(a, b)
#define ipc_debugfs_hpu_stress_alloc(a, b, c) NULL
#define ipc_debugfs_hpu_stress_dealloc(a)
#define ipc_debugfs_mux_alloc(a, b, c) NULL
#define ipc_debugfs_mux_dealloc(a)
#define ipc_debugfs_mux_log_event(a, b, c, d, e, f, g)
#define ipc_debugfs_stats_device_wake_event(a)
#define ipc_debugfs_mmio_alloc(a, b, c) NULL
#define ipc_debugfs_mmio_dealloc(a)
#define ipc_debugfs_params_dealloc(a)
#define ipc_debugfs_params_alloc(a, b, c) NULL
#define ipc_debugfs_parc_dealloc(a)
#define ipc_debugfs_parc_alloc(a, b, c) NULL
#define ipc_debugfs_parc_get_test_mode(a) -1
#define ipc_debugfs_parc_get_msi_test_mode(a) -1
#define ipc_debugfs_ras_des_dealloc(a)
#define ipc_debugfs_ras_des_alloc(a, b, c, d) NULL
#define ipc_debugfs_uevent_alloc(a, b, c) NULL
#define ipc_debugfs_uevent_dealloc(a)
#else

#include "imc_ipc_debugfs_priv.h"

#endif


#endif /* IMC_IPC_DEBUGFS_H */
