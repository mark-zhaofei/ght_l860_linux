/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_CHNL_CFG_H
#define IMC_IPC_CHNL_CFG_H


/* Type of the WWAN ID */
enum ipc_wwan_id {
	IPC_WWAN_DSS_ID_0 = 257,
	IPC_WWAN_DSS_ID_1,
	IPC_WWAN_DSS_ID_2,
	IPC_WWAN_DSS_ID_3,
	IPC_WWAN_DSS_ID_4,
	IPC_WWAN_DSS_ID_5,
	IPC_WWAN_DSS_ID_6,
	IPC_WWAN_DSS_ID_7,
};

/* IPC channel configuration structure.
 */
struct ipc_chnl_cfg {
	int id;
	u32 ul_pipe;
	u32 dl_pipe;
	u32 ul_nr_of_entries;
	u32 dl_nr_of_entries;
	u32 dl_buf_size;
	u32 accumulation_backoff;
};


/*
 * Get pipe configuration.
 *
 * @chnl_cfg: array of ipc_chnl_cfg struct
 * @index: channel index (upto MAX_CHANNELS), -1 is default for download channel
 * @device_id: PCI device ID
 * @cp_version: modem IPC version get from MMIO
 * @dbg: pointer to ipc_dbg structure
 * @params: pointer to debug params structure
 * returns zero on success
 */
int ipc_chnl_cfg_get(struct ipc_chnl_cfg *chnl_cfg, int index,
		unsigned int device_id, int cp_version,
		enum imem_mux_protocol mux_protocol,
		struct ipc_dbg *dbg,
		struct ipc_params *params);

#endif /* IMC_IPC_CHNL_CFG_H */
