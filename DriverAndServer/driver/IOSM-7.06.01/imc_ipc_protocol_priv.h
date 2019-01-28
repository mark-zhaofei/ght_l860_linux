/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#if !defined(IMC_IPC_PROTOCOL_PRIV_H)
#define IMC_IPC_PROTOCOL_PRIV_H

#include<linux/types.h>

/**
 * Size of the message queue to CP.
 * Define this as a power of two so that index wrap around operations can
 * be optimized.
 */
#define IPC_MEM_MSG_ENTRIES           128

/**
 * Structure of ops function pointers.
 */
struct ipc_protocol_ops {
	/* msg_prep is expected to return 0 on success,
	 * -1 on failure or -2 on success but no message to be sent:
	 */
	int (*msg_prep)(void *this, enum ipc_msg_prep_type msg_type,
		union ipc_msg_prep_args *args);

	/* Function pointer for head pointer update of message ring */
	void (*msg_hp_update)(void *this);

	/* Function pointer for processing responses to IPC messages */
	bool (*msg_process)(void *this, int irq, struct ipc_rsp **rsp_ring);

	/* Function pointer for sending the data to CP */
	bool (*ul_td_send)(void *this_p, struct ipc_pipe *p_pipe,
			struct imem_ul_queue *p_ul_list);

	/* Function pointer for processing the sent data */
	struct sk_buff *(*ul_td_process)(void *this,
			struct ipc_pipe *p_pipe);

	/* Function pointer for providing DL TDs to CP */
	bool (*dl_td_prepare)(void *this, struct ipc_pipe *p_pipe);

	/* Function pointer for processing the DL data */
	struct sk_buff *(*dl_td_process)(void *this, struct ipc_pipe *p_pipe);

	/* Function pointer for getting Head and Tail pointer index of given
	 * pipe
	 */
	void (*get_head_tail_index)(void *this_p,
			struct ipc_pipe *p_pipe, u32 *p_head, u32 *p_tail);

	/* Function pointer for getting the IPC Status */
	enum ipc_mem_device_ipc_state (*get_ipc_status)(void *this_p);

	/* Function pointer for Pipe cleanup */
	void (*pipe_cleanup)(void *this_p, struct ipc_pipe *p_pipe);

	/* Function pointer for getting Exec Stage */
	enum ipc_mem_exec_stage (*get_ap_exec_stage)(void *this_p);

	/* Function pointer for getting Device Sleep notification */
	u32 (*pm_dev_get_sleep_notification)(void *this_p);

	/* Function pointer for printing stats */
	void (*print_stats)(void *this_p, struct seq_file *m);

	/* Dealloc */
	void (*protocol_dealloc)(void **this_pp);

	/* Function pointer for updating Message Completion Ring(MCR)
	 * CP capability
	 */
	void (*update_mcr_cp_cap)(void *this, bool mcr_support);

	/* Waits for completion object to get device/remote timestamp */
	int (*wait_for_remote_ts)(void *this, int timeout_ms,
		u64 *p_remote_time_ns, u32 *p_remote_ts_id,
		u32 *p_remote_time_unit, bool *p_ts_db_trig);
};

#endif	/* IMC_IPC_PROTOCOL_PRIV_H */
