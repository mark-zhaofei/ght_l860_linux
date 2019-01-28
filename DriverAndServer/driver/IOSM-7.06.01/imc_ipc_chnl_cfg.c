/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 *  SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/types.h>

#include "imc_ipc_imem.h"
#include "imc_ipc_mux.h"	/* MUX definitions */
#include "imc_ipc_chnl_cfg.h"
#include "imc_ipc_imem.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_util.h"
#include "imc_ipc_mmio.h"
#include "imc_ipc_protocol.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_params.h"

/* Max. size of a downlink buffer.
 */
#define IPC_MEM_MAX_DL_FLASH_BUF_SIZE	(16 * 1024)
#define IPC_MEM_MAX_DL_LOOPBACK_SIZE	(1 * 1024 * 1024)
#define IPC_MEM_MAX_DL_AT_BUF_SIZE	2048
#define IPC_MEM_MAX_DL_RPC_BUF_SIZE	(32 * 1024)
#define IPC_MEM_MAX_DL_GNSS_BUF_SIZE IPC_MEM_MAX_DL_RPC_BUF_SIZE
#define IPC_MEM_MAX_DL_TSYNC_BUF_SIZE   (32 * 1024)
#define IPC_MEM_MAX_DL_VOLTE_BUF_SIZE   1600
#define IPC_MEM_MAX_DL_TRC_BUF_SIZE	16384
#define IPC_MEM_MAX_DL_NET_BUF_SIZE	1600

/* Max. transfer descriptors for a pipe.
 */
#define IPC_MEM_MAX_TDS_FLASH_DL	3
#define IPC_MEM_MAX_TDS_FLASH_UL	6
#define IPC_MEM_MAX_TDS_AT		4
#define IPC_MEM_MAX_TDS_RPC		4
#define IPC_MEM_MAX_TDS_GNSS	IPC_MEM_MAX_TDS_RPC
#define IPC_MEM_MAX_TDS_TSYNC		32
#define IPC_MEM_MAX_TDS_VOLTE		32
#define IPC_MEM_MAX_TDS_NET_UL		50
#define IPC_MEM_MAX_TDS_NET_DL		300
#define IPC_MEM_MAX_TDS_LOOPBACK	11
#define IPC_MEM_MAX_TDS_NET_LWA_UL	300
#define IPC_MEM_MAX_TDS_NET_LWA_DL	50

/* accumulation backoff usec
 */
#define IRQ_ACC_BACKOFF_OFF		0	/* acc backoff off */

#define IRQ_ACC_BACKOFF_MUX		1000	/* MUX acc backoff 1ms */

enum ipc_ll_wwan_id {
	IPC_LL_WWAN_ID_0 = 513,
	IPC_LL_WWAN_ID_1,
};

/* Type of the channel */
enum ipc_chnl_cfg_type {
	IPC_FLASH,
	IPC_MEDIA_DATA,
	IPC_MUX,
	IPC_IAT,
	IPC_RPC,
	IPC_TSYNC,
	IPC_TRC,
	IPC_LPBK,
	IPC_GNSS,
};

struct ipc_chnl_cfg_priv {
	enum ipc_chnl_cfg_type ch_type;
	int id;
	u32 ul_pipe;
	u32 dl_pipe;
};

/* Always reserve element zero for flash channel. */
struct ipc_chnl_cfg_priv common_modem_config[] = {
	/* FLASH Channel */
	{IPC_FLASH, -1, IPC_MEM_PIPE_0, IPC_MEM_PIPE_1},
	/* RPC - 0 */
	{IPC_RPC, IPC_WWAN_DSS_ID_0, IPC_MEM_PIPE_2, IPC_MEM_PIPE_3},
	/* IAT0 */
	{IPC_IAT, IPC_WWAN_DSS_ID_1, IPC_MEM_PIPE_4, IPC_MEM_PIPE_5},
	/* Trace */
	{IPC_TRC, IPC_WWAN_DSS_ID_4, IPC_MEM_PIPE_6, IPC_MEM_PIPE_7},
	/* IAT1 */
	{IPC_IAT, IPC_WWAN_DSS_ID_2, IPC_MEM_PIPE_8, IPC_MEM_PIPE_9},
	/* Loopback */
	{IPC_LPBK, IPC_WWAN_DSS_ID_3, IPC_MEM_PIPE_10, IPC_MEM_PIPE_11},
	/* RPC - 1 */
	{IPC_RPC, IPC_WWAN_DSS_ID_5, IPC_MEM_PIPE_12, IPC_MEM_PIPE_13},
	/* GNSS */
	{IPC_GNSS, IPC_WWAN_DSS_ID_6, IPC_MEM_PIPE_14, IPC_MEM_PIPE_15},
	/* TSync */
	{IPC_TSYNC, IPC_WWAN_DSS_ID_7, IPC_MEM_PIPE_16, IPC_MEM_PIPE_17},
	/* MEDIA DATA - 0 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_0, IPC_MEM_PIPE_18, IPC_MEM_PIPE_19},
	/* MEDIA DATA - 1 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_1, IPC_MEM_PIPE_20, IPC_MEM_PIPE_21},
	/* IP Mux */
	{IPC_MUX, -1, IPC_MEM_PIPE_0, IPC_MEM_PIPE_1},
};

struct ipc_chnl_cfg_priv ibis_new_config[] = {
	/* FLASH Channel */
	{IPC_FLASH, -1, IPC_MEM_PIPE_0, IPC_MEM_PIPE_1},
	/* MEDIA DATA - 0 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_0, IPC_MEM_PIPE_0, IPC_MEM_PIPE_1},
	/* MEDIA DATA - 1 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_1, IPC_MEM_PIPE_2, IPC_MEM_PIPE_3},
	/* RPC */
	{IPC_RPC, IPC_WWAN_DSS_ID_0, IPC_MEM_PIPE_6, IPC_MEM_PIPE_7},
	/* TSync */
	{IPC_TSYNC, IPC_WWAN_DSS_ID_7, IPC_MEM_PIPE_8, IPC_MEM_PIPE_9},
	/* Trace */
	{IPC_TRC, IPC_WWAN_DSS_ID_4, IPC_MEM_PIPE_10, IPC_MEM_PIPE_11},
	/* IAT0 */
	{IPC_IAT, IPC_WWAN_DSS_ID_1, IPC_MEM_PIPE_12, IPC_MEM_PIPE_13},
	/* IAT1 */
	{IPC_IAT, IPC_WWAN_DSS_ID_2, IPC_MEM_PIPE_14, IPC_MEM_PIPE_15},
	/* Loopback */
	{IPC_LPBK, IPC_WWAN_DSS_ID_3, IPC_MEM_PIPE_16, IPC_MEM_PIPE_17},
	/* GNSS */
	{IPC_GNSS, IPC_WWAN_DSS_ID_6, IPC_MEM_PIPE_18, IPC_MEM_PIPE_19},
	/* IP Mux */
	{IPC_MUX, -1, IPC_MEM_PIPE_4, IPC_MEM_PIPE_5}
};

/* Always reserve element zero for flash channel. */
struct ipc_chnl_cfg_priv xg766_modem_config[] = {
	/* FLASH Channel */
	{IPC_FLASH, -1, IPC_MEM_PIPE_2, IPC_MEM_PIPE_3},
	/* RPC - 0 */
	{IPC_RPC, IPC_WWAN_DSS_ID_0, IPC_MEM_PIPE_4, IPC_MEM_PIPE_5},
	/* IAT0 */
	{IPC_IAT, IPC_WWAN_DSS_ID_1, IPC_MEM_PIPE_6, IPC_MEM_PIPE_7},
	/* Trace */
	{IPC_TRC, IPC_WWAN_DSS_ID_4, IPC_MEM_PIPE_8, IPC_MEM_PIPE_9},
	/* IAT1 */
	{IPC_IAT, IPC_WWAN_DSS_ID_2, IPC_MEM_PIPE_10, IPC_MEM_PIPE_11},
	/* Loopback */
	{IPC_LPBK, IPC_WWAN_DSS_ID_3, IPC_MEM_PIPE_12, IPC_MEM_PIPE_13},
	/* RPC - 1 */
	{IPC_RPC, IPC_WWAN_DSS_ID_5, IPC_MEM_PIPE_14, IPC_MEM_PIPE_15},
	/* GNSS */
	{IPC_GNSS, IPC_WWAN_DSS_ID_6, IPC_MEM_PIPE_16, IPC_MEM_PIPE_17},
	/* TSync */
	{IPC_TSYNC, IPC_WWAN_DSS_ID_7, IPC_MEM_PIPE_18, IPC_MEM_PIPE_19},
	/* MEDIA DATA - 0 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_0, IPC_MEM_PIPE_20, IPC_MEM_PIPE_21},
	/* MEDIA DATA - 1 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_1, IPC_MEM_PIPE_22, IPC_MEM_PIPE_23},
	/* IP Mux */
	{IPC_MUX, -1, IPC_MEM_PIPE_2, IPC_MEM_PIPE_3},
};

struct ipc_chnl_cfg_priv xg766_modem_new_config[] = {
	/* FLASH Channel */
	{IPC_FLASH, -1, IPC_MEM_PIPE_1, IPC_MEM_PIPE_2},
	/* MEDIA DATA - 0 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_0, IPC_MEM_PIPE_1, IPC_MEM_PIPE_2},
	/* RPC - 0 */
	{IPC_RPC, IPC_WWAN_DSS_ID_0, IPC_MEM_PIPE_5, IPC_MEM_PIPE_6},
	/* GNSS */
	{IPC_GNSS, IPC_WWAN_DSS_ID_6, IPC_MEM_PIPE_7, IPC_MEM_PIPE_8},
	/* OGRS - reservation - TBD */
	/* {NULL, NULL, IPC_MEM_PIPE_9, IPC_MEM_PIPE_10}, */
	/* Trace */
	{IPC_TRC, IPC_WWAN_DSS_ID_4, IPC_MEM_PIPE_11, IPC_MEM_PIPE_12},
	/* IAT0 */
	{IPC_IAT, IPC_WWAN_DSS_ID_1, IPC_MEM_PIPE_13, IPC_MEM_PIPE_14},
	/* Loopback */
	{IPC_LPBK, IPC_WWAN_DSS_ID_3, IPC_MEM_PIPE_15, IPC_MEM_PIPE_16},
	/* IAT1 */
	{IPC_IAT, IPC_WWAN_DSS_ID_2, IPC_MEM_PIPE_17, IPC_MEM_PIPE_18},
	/* IP Mux */
	{IPC_MUX, -1, IPC_MEM_PIPE_3, IPC_MEM_PIPE_4},
};

struct ipc_chnl_cfg_priv xg766_modem_new_config_version2[] = {
	/* FLASH Channel */
	{IPC_FLASH, -1, IPC_MEM_PIPE_1, IPC_MEM_PIPE_2},
	/* MEDIA DATA - 0 */
	{IPC_MEDIA_DATA, IPC_LL_WWAN_ID_0, IPC_MEM_PIPE_1, IPC_MEM_PIPE_2},
	/* RPC - 0 */
	{IPC_RPC, IPC_WWAN_DSS_ID_0, IPC_MEM_PIPE_5, IPC_MEM_PIPE_6},
	/* GNSS */
	{IPC_GNSS, IPC_WWAN_DSS_ID_6, IPC_MEM_PIPE_7, IPC_MEM_PIPE_8},
	/* OGRS - reservation - TBD */
	/* {NULL, NULL, IPC_MEM_PIPE_9, IPC_MEM_PIPE_10}, */
	/* Trace */
	{IPC_TRC, IPC_WWAN_DSS_ID_4, IPC_MEM_PIPE_11, IPC_MEM_PIPE_12},
	/* IAT0 */
	{IPC_IAT, IPC_WWAN_DSS_ID_1, IPC_MEM_PIPE_17, IPC_MEM_PIPE_18},
	/* Loopback */
	{IPC_LPBK, IPC_WWAN_DSS_ID_3, IPC_MEM_PIPE_15, IPC_MEM_PIPE_16},
	/* IAT1 */
	{IPC_IAT, IPC_WWAN_DSS_ID_2, IPC_MEM_PIPE_13, IPC_MEM_PIPE_14},
	/* IP Mux */
	{IPC_MUX, -1, IPC_MEM_PIPE_3, IPC_MEM_PIPE_4},
};

/* get selected type of channel's configuration */
static void ipc_chnl_cfg_select(struct ipc_chnl_cfg *chnl_cfg,
		enum ipc_chnl_cfg_type type,
		enum imem_mux_protocol mux_protocol,
		struct ipc_params *params,
		struct ipc_dbg *dbg)
{
	/* Over-riding backoff only for MUX. */
	chnl_cfg->accumulation_backoff = IRQ_ACC_BACKOFF_OFF;

	switch (type) {
	case IPC_FLASH:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_FLASH_UL;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_FLASH_DL;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_FLASH_BUF_SIZE;
		break;

	case IPC_MEDIA_DATA:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_VOLTE;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_VOLTE;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_VOLTE_BUF_SIZE;
		break;

	case IPC_RPC:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_RPC;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_RPC;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_RPC_BUF_SIZE;
		break;

	case IPC_TSYNC:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_TSYNC;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_TSYNC;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_TSYNC_BUF_SIZE;
		break;

	case IPC_TRC:
		chnl_cfg->ul_nr_of_entries = params->trace_td_numbers;
		chnl_cfg->dl_nr_of_entries = params->trace_td_numbers;
		chnl_cfg->dl_buf_size = params->trace_td_buff_size;
		break;

	case IPC_IAT:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_AT;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_AT;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_AT_BUF_SIZE;
		break;

	case IPC_LPBK:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_LOOPBACK;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_LOOPBACK;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_LOOPBACK_SIZE;
		break;

	case IPC_GNSS:
		chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_GNSS;
		chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_GNSS;
		chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_GNSS_BUF_SIZE;
		break;

	case IPC_MUX:
		chnl_cfg->accumulation_backoff = IRQ_ACC_BACKOFF_MUX;

		if (mux_protocol == MUX_AGGREGATION) {
			chnl_cfg->ul_nr_of_entries = IPC_MEM_MAX_TDS_MUX_UL;
			chnl_cfg->dl_nr_of_entries = IPC_MEM_MAX_TDS_MUX_DL;
			chnl_cfg->dl_buf_size = IPC_MEM_MAX_DL_MUX_BUF_SIZE;
		} else if (mux_protocol == MUX_LITE) {

			if (params->mux_lite_buf_size  >
					IPC_MEM_MUX_LITE_MAX_JUMBO_BUF_SIZE) {
				ipc_err("Invalid param value configured for params->mux_lite_dl_buf_size,setting it to default");
				params->mux_lite_buf_size =
					IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE;
			}

			if (params->mux_lite_buf_size >
					IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE) {
				chnl_cfg->ul_nr_of_entries =
					IPC_MEM_MUX_LITE_MAX_JUMBO_TDS;
				chnl_cfg->dl_nr_of_entries =
					IPC_MEM_MUX_LITE_MAX_JUMBO_TDS;
				chnl_cfg->dl_buf_size =
					params->mux_lite_buf_size;
			} else {
				chnl_cfg->ul_nr_of_entries =
					IPC_MEM_MAX_TDS_MUX_LITE_UL;
				chnl_cfg->dl_nr_of_entries =
					IPC_MEM_MAX_TDS_MUX_LITE_DL;
				chnl_cfg->dl_buf_size =
					IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE;
			}
		}

		ipc_pr_dbg("chnl_cfg->dl_buf_size = %d",
				chnl_cfg->dl_buf_size);

			break;
	}
}

int ipc_chnl_cfg_get(struct ipc_chnl_cfg *chnl_cfg, int index,
		unsigned int device_id, int cp_version,
		enum imem_mux_protocol mux_protocol,
		struct ipc_dbg *dbg,
		struct ipc_params *params)
{
	int array_size;
	struct ipc_chnl_cfg_priv *chnl_cfg_priv;

	if (unlikely((!chnl_cfg))) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* Exclude the check for flash channel. */
	if (index != 0 && mux_protocol != MUX_AGGREGATION
			&& mux_protocol != MUX_LITE) {
		ipc_err("Unknown protocol: %d", mux_protocol);
		return -1;
	}

	/* IBIS CP IPC version 0x0101 pipe configuration */
	if (device_id == INTEL_CP_DEVICE_IBIS_ID &&
			cp_version >= IOSM_IBIS_CP_VERSION1) {
		array_size = ARRAY_SIZE(ibis_new_config);
		chnl_cfg_priv = ibis_new_config;
	/* 766 CP IPC version 0x0120 pipe configuration */
	} else if (device_id == INTEL_CP_DEVICE_7660_ID &&
			cp_version >= IOSM_7660_CP_VERSION2) {
		array_size = ARRAY_SIZE(xg766_modem_new_config_version2);
		chnl_cfg_priv = xg766_modem_new_config_version2;
	} else if (device_id == INTEL_CP_DEVICE_7660_ID &&
			cp_version >= IOSM_7660_CP_VERSION1) {
		array_size = ARRAY_SIZE(xg766_modem_new_config);
		chnl_cfg_priv = xg766_modem_new_config;
	} else if (!imem_force_legacy_protocol() &&
		(device_id == INTEL_CP_DEVICE_7660_ID)) {
		array_size = ARRAY_SIZE(xg766_modem_config);
		chnl_cfg_priv = xg766_modem_config;
	} else {
		ipc_pr_dbg("Using default configuration");

		/* Use default configuration for CP version
		 * greater than or equal to IOSM_CP_VERSION, or
		 * if any other version. It maintains same functional
		 * behavior with earlier driver version.
		 */
		array_size = ARRAY_SIZE(common_modem_config);
		chnl_cfg_priv = common_modem_config;
	}

	/* Invalid index or index meet the max channel number */
	if (index >= array_size) {
		ipc_pr_dbg("index: %d and array_size %d",
				index, array_size);
		return -1;
	}

	/* Get the selected configuration */
	ipc_chnl_cfg_select(chnl_cfg, chnl_cfg_priv[index].ch_type,
			mux_protocol, params, dbg);

	chnl_cfg->id = chnl_cfg_priv[index].id;
	chnl_cfg->ul_pipe = chnl_cfg_priv[index].ul_pipe;
	chnl_cfg->dl_pipe = chnl_cfg_priv[index].dl_pipe;

	return 0;
}
