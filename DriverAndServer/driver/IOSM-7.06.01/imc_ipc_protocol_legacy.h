/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#if !defined(IMC_IPC_PROTOCOL_LEGACY_H)
#define IMC_IPC_PROTOCOL_LEGACY_H

struct ipc_pm;


/**
 * Allocates IPC Legacy protocol instance
 *
 * @p_pcie: Instance pointer  of PCIe module.
 * @p_stats: Instance pointer to Stats module.
 * @p_mmio: Instance pointer of MMIO module.
 * @p_params: Instance pointer to Params module
 * @p_pm: Instance pointer to PM module
 * @ops: Pointer to structure of function pointers to support protocol
 * @dbg: pointer to ipc_dbg structure
 *
 * returns address of ipc converged protocol instance data
 */
void *ipc_protocol_legacy_alloc(struct ipc_pcie *p_pcie,
		struct ipc_debugfs_stats *p_stats, struct ipc_mmio *p_mmio,
		struct ipc_params *p_params, struct ipc_pm *p_pm,
		struct ipc_protocol_ops *ops, struct ipc_dbg *dbg);



#endif	/* IMC_IPC_PROTOCOL_LEGACY_H */
