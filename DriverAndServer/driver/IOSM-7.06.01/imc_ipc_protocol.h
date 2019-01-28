/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#if !defined(IMC_IPC_PROTOCOL_H)
#define IMC_IPC_PROTOCOL_H

#include "imc_ipc_completion.h"

struct ipc_protocol;
struct ipc_mmio;
struct ipc_pcie;
struct ipc_debugfs_stats;
struct ipc_params;
struct ipc_tasklet;
struct ipc_dbg;
struct imem_ul_queue;
enum ipc_pm_unit;
enum ipc_mem_exec_stage;


/**
 * Trigger the doorbell interrupt on CP.
 */
#define IPC_DOORBELL_IRQ_HPDA             0
#define IPC_DOORBELL_IRQ_IPC              1
#define IPC_DOORBELL_IRQ_SLEEP            2
#define IPC_DOORBELL_IRQ_TIME_SYNC_LEGACY 3
#define IPC_DOORBELL_IRQ_TIME_SYNC        6


/**
 * IRQ vector number.
 */
#define IPC_DEVICE_IRQ_VECTOR  0
#define IPC_MSG_IRQ_VECTOR     0
#define IPC_UL_PIPE_IRQ_VECTOR 0
#define IPC_DL_PIPE_IRQ_VECTOR 0


/**
 * Completion status of IPC Message
 */
enum ipc_mem_msg_cs {
	IPC_MEM_MSG_CS_INVALID = 0,
	IPC_MEM_MSG_CS_SUCCESS = 1,
	IPC_MEM_MSG_CS_ERROR = 2
};

/**
 * Pipe direction.
 */
enum ipc_mem_pipe_dir {
	IPC_MEM_DIR_UL,
	IPC_MEM_DIR_DL
};


/**
 * Structure for Pipe.
 */
struct ipc_pipe {
	/* Circular buffer for skbuf and the buffer reference in a
	 * tdr_start entry.
	 */
	struct sk_buff **skbr_start;
	/* Legacy protocol Transfer Descriptor Ring */
	struct ipc_legacy_td *p_tdr_start;

	/* Converged Protocol Transfer Ring */
	struct ipc_converged_td *p_tr_start;
	u64 phy_tdr_start;

	bool is_open;

	/* last head pointer reported to CP.
	 */
	u32 old_head;

	/* AP read position before CP moves the read position to
	 * write/head. If CP has consumed the buffers, AP has to freed
	 * the skbuf starting at tdr_start[old_tail].
	 */
	u32 old_tail;

	/* Number of elements of skb_start and tdr_start.
	 */
	u32 nr_of_entries;

	/* max. number of queued entries in a TDR
	 */
	u32 max_nr_of_queued_entries;

	/* queued number of entries (<=max_nr_of_queued_entries)
	 */
	u32 nr_of_queued_entries;

	/* accumulation in usec for accumulation_backoff (0 = no acc backoff)
	 */
	u32 accumulation_backoff;

	/* timer in usec for irq_moderation (0=no irq moderation)
	 */
	u32 irq_moderation;

	/* Id of the sio device, set by imem_sio_open, needed to
	 * pass downlink characters to the user terminal.
	 */
	struct ipc_mem_channel *channel;
	u32 pipe_nr;
	u32 irq;
	enum ipc_mem_pipe_dir dir;

	/* 1 means lock the pipe/channel to avoid invalid UL/DL buffer.
	 */
	u32 locked;
	u32 is_busy;
	u32 td_tag;

	/* Buffer size (in bytes) for preallocated buffers (for DL pipes)
	 */
	u32 buf_size;
};

/**
 * Structures for argument passing towards the actual message preparation
 */

struct ipc_msg_prep_args_pipe {
	struct ipc_pipe *pipe; /* pipe to open/close */
};

struct ipc_msg_prep_args_sleep {
	unsigned int target;	/* 0=host, 1=device */
	unsigned int state;	/* 0=enter sleep, 1=exit sleep */
};

struct ipc_msg_prep_feature_set {
	/* 0 = out-of-band, 1 = in-band-crash notification */
	unsigned int reset_enable;
};

struct ipc_msg_prep_map {
	unsigned int region_id;
	unsigned long addr;
	size_t size;
};

struct ipc_msg_prep_unmap {
	unsigned int region_id;
};

/**
 * Union for message to handle the message to CP in the tasklet context.
 */
union ipc_msg_prep_args {
	struct ipc_msg_prep_args_pipe   pipe_open;
	struct ipc_msg_prep_args_pipe   pipe_close;
	struct ipc_msg_prep_args_sleep  sleep;
	struct ipc_msg_prep_feature_set feature_set;
	struct ipc_msg_prep_map         map;
	struct ipc_msg_prep_unmap       unmap;
};

enum ipc_msg_prep_type {
	/* prepare a sleep message */
	IPC_MSG_PREP_SLEEP,
	/* prepare a pipe open message */
	IPC_MSG_PREP_PIPE_OPEN,
	/* prepare a pipe close message */
	IPC_MSG_PREP_PIPE_CLOSE,
	/* prepare a feature set message */
	IPC_MSG_PREP_FEATURE_SET,
	/* prepare a memory map message */
	IPC_MSG_PREP_MAP,
	/* prepare a memory unmap message */
	IPC_MSG_PREP_UNMAP
};

/* Response for message to CP */
struct ipc_rsp {
	struct ipc_completion completion; /* for waking up requestor */
	enum ipc_mem_msg_cs status; /* completion status */
};

/* Call message preparation function and Send msg to CP
 *
 * @this: Pointer to ipc_protocol instance
 * @prep: Message type
 * @prep_args: Message arguments
 * @response: pointer to a response object which has a completion object
 *		and return code. Can be NULL if response not required.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_protocol_tl_msg_send(struct ipc_protocol *this,
	enum ipc_msg_prep_type msg_type,
	union ipc_msg_prep_args *prep_args, struct ipc_rsp *response);

/**
 * Send a message to CP and wait for response
 *
 * @this: Pointer to ipc_protocol instance
 * @prep: Message type
 * @prep_args: Message arguments
 *
 *	## prepare a sleep message ##
 *
 *	prep: IPC_MSG_PREP_SLEEP
 *	prep_args:
 *		prep_args->sleep.target: 0 = host, 1 = device
 *		prep_args->sleep.state : 0 = enter sleep, 1 = exit sleep
 *
 *	## prepare a pipe open message ##
 *
 *	prep: IPC_MSG_PREP_PIPE_OPEN
 *	prep_args:
 *		prep_args->pipe_open.pipe : Pointer to pipe structure
 *
 *	## prepare a pipe close message ##
 *
 *	prep: IPC_MSG_PREP_PIPE_CLOSE
 *	prep_args:
 *		prep_args->pipe_close.pipe : Pointer to pipe structure
 *
 *	## prepare a feature set message ##
 *
 *	prep: IPC_MSG_PREP_FEATURE_SET
 *	prep_args:
 *		prep_args->feature_set.reset_enable :
 *			0 = out-of-band, 1 = in-band-crash notification
 *
 *	## prepare a memory map message ##
 *
 *	prep: IPC_MSG_PREP_MAP
 *	prep_args:
 *		prep_args->map.region_id : region to map
 *		prep_args->map.size : size of the region to map
 *		prep_args->map.addr : pcie addr of region to map
 *
 *	## prepare a memory unmap message ##
 *
 *	prep: IPC_MSG_PREP_UNMAP
 *	prep_args:
 *		prep_args->map.region_id : region to unmap
 *
 * returns 0 on success, -1 on failure
 */
int ipc_protocol_msg_send(struct ipc_protocol *this,
	enum ipc_msg_prep_type prep, union ipc_msg_prep_args *prep_args);

/**
 * Signal to CP that host wants to go to sleep (suspend).
 *
 * @this: Pointer to ipc_protocol instance
 *
 * returns true if host can suspend, false if suspend must be aborted.
 */
bool ipc_protocol_suspend(struct ipc_protocol *this);

/**
 * Signal to CP that host wants to resume operation.
 *
 * @this: Pointer to ipc_protocol instance
 *
 * returns true if host can resume, false if there is a problem.
 */
bool ipc_protocol_resume(struct ipc_protocol *this);

/**
 * Processes responses to IPC messages that were sent to CP.
 * This is expected to be called from tasklet context.
 *
 * @this: Pointer to ipc_protocol instance.
 * @irq: IRQ number
 *
 */
void ipc_protocol_msg_process(struct ipc_protocol *this, int irq);


/**
 * Sends data to CP for the provided pipe.
 * This is expected to be called from tasklet context.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 * @p_list: Pointer to list of data to be sent to CP
 *
 * returns true: if any data sent to Modem false otherwise
 */
bool ipc_protocol_ul_td_send(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe, struct imem_ul_queue *p_list);


/**
 * Processes the data consumed CP for the provided pipe.
 * This is expected to be called from tasklet context.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 *
 * returns pointer of struct sk_buff if CP consumed data or NULL otherwise.
 */
struct sk_buff *ipc_protocol_ul_td_process(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe);


/**
 * Allocates an SKB for CP to send data.
 * This is expected to be called from tasklet context.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 *
 * returns True if CP gets a new TD or False otherwise.
 */
bool ipc_protocol_dl_skb_alloc(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe);


/**
 * Processes the TD sent from CP.
 * This is expected to be called from tasklet context.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 *
 * returns pointer of struct sk_buff if CP has sent data or NULL otherwise.
 */
struct sk_buff *ipc_protocol_dl_td_process(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe);


/**
 * Frees the TDs given to CP.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 *
 * returns none.
 */
void ipc_protocol_pipe_cleanup(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe);


/**
 * Gives the Head and Tail index of given pipe.
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_pipe: Pointer to pipe
 * @p_head: Pointer to get Head index. Passing NULL means caller is not
 *          interested.
 * @p_tail: Pointer to get Tail index. Passing NULL means caller is not
 *          interested.
 *
 * returns none.
 */
void ipc_protocol_get_head_tail_index(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe, u32 *p_head, u32 *p_tail);


/**
 * Get IPC status.
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns IPC status.
 */
enum ipc_mem_device_ipc_state ipc_protocol_get_ipc_status(
		struct ipc_protocol *this);


/**
 * Get Execution stage from AP shared memory.
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns execution stage.
 */
enum ipc_mem_exec_stage ipc_protocol_get_ap_exec_stage(
		struct ipc_protocol *this);


/**
 * Handles the Device Sleep state change notification.
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns True if sleep notification handled, False otherwise.
 */
bool ipc_protocol_pm_dev_sleep_handle(struct ipc_protocol *this);


/**
 * Wrapper for PM function which acquires a specific pm_unit before use.
 *
 * @this: Pointer to ipc_protocol instance.
 * @unit: PM unit to aquire
 *
 * returns True if device is active, False otherwise.
 */
bool ipc_protocol_pm_dev_acquire(struct ipc_protocol *this,
		enum ipc_pm_unit unit);


/**
 * Wrapper for PM function which release a specific pm_unit after use
 *
 * @this: Pointer to ipc_protocol instance.
 * @unit: PM unit to aquire
 *
 * returns True if device is active, False otherwise.
 */
bool ipc_protocol_pm_dev_release(struct ipc_protocol *this,
		enum ipc_pm_unit unit);


/**
 * Returns Device sleep notification as string
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns pointer to the string.
 */
const char *ipc_protocol_pm_dev_sleep_notification_str(
		struct ipc_protocol *this);


/**
 * Checks whether device is in Sleep or Active
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns True if device is in Sleep, False otherwise
 */
bool ipc_protocol_pm_dev_is_in_sleep(struct ipc_protocol *this);


/**
 * Checks whether device sleep handling is ongoing or not
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns True if device Sleep handling is ongoing. False otherwise
 */
bool ipc_protocol_pm_dev_is_sleep_handling(struct ipc_protocol *this);


/**
 * Updates the Protocol and PM related stats to seq_file file descriptor.
 *
 * @this: Pointer to ipc_protocol instance.
 * @m: seq_file to print statistics into.
 *
 * returns none
 */
void ipc_protocol_print_stats(struct ipc_protocol *this, struct seq_file *m);


/**
 * Returns string of active IPC protocol
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns pointer to string of the protocol.
 */
const char *ipc_protocol_get_str(struct ipc_protocol *this);


/**
 * Wrapper for  PM function which wake up the device if it is in low power mode
 * and trigger a head pointer update interrupt.
 *
 * @this: Pointer to ipc_protocol instance.
 * @identifier: specifies what component triggered hpda update irq
 *
 * returns none
 */
void ipc_protocol_doorbell_trigger(struct ipc_protocol *this, u32 identifier);


/**
 * Returns last Sleep Notification as string.
 *
 * @this: Instance pointer of Protocol module.
 *
 * returns pointer to string.
 */
const char *ipc_protocol_sleep_notification_string(struct ipc_protocol *this);


/**
 * Updates the device's Message Completion Ring(MCR) support in protocol
 * instance with the capabiliy read from MMIO for all supported protocols.
 *
 * @this: Instance pointer of Protocol module.
 * @mcr_supported: true if MCR supported false otherwise.
 *
 * returns none.
 */
void ipc_protocol_update_mcr_cp_cap(struct ipc_protocol *this,
		bool mcr_supported);


/**
 * Allocates IPC protocol instance data
 *
 * @dbg: pointer to ipc_dbg structure
 * @p_mmio: Instance pointer of MMIO module.
 * @p_pcie: Instance pointer  of PCIe module.
 * @p_stats: Instance pointer to Stats module.
 * @p_params: Instance pointer to Params module
 * @device_id: Device ID of the Modem
 * @tasklet: Pointer to tasklet instance
 *
 * returns address of ipc protocol instance data
 */
struct ipc_protocol *ipc_protocol_alloc(
		struct ipc_dbg *dbg, struct ipc_mmio *p_mmio,
		struct ipc_pcie *p_pcie, struct ipc_debugfs_stats *p_stats,
		struct ipc_params *p_params, unsigned int device_id,
		struct ipc_tasklet *tasklet);

/**
 * Deallocates IPC protocol instance data
 *
 * @this_pp: Pointer to the pointer to the IPC protocol instance data.
 *
 * returns None
 */
void ipc_protocol_dealloc(struct ipc_protocol **this_pp);


/**
 * This function waits for device timestamp in case of Converged protocol.
 * Otherwise it returns immediately without wait.
 *
 * @this: Instance pointer of Protocol module.
 * @timeout_ms: Timeout in ms to wait for completion object to return.
 * @p_remote_time: Pointer to get the device timestamp.
 * @p_remote_ts_id: Pointer to get last reported remote time ID
 * @p_remote_time_unit: Pointer to get last reported timestamp unit.
 * @p_ts_db_trig: Pointer to get the info whether timesync doorbell triggered
 *                and user app is waiting or not.
 *
 * returns 0 on success, -1 on failure, EPROTONOSUPPORT on Functionality not
 * supported by protocol
 */
int ipc_protocol_wait_for_remote_ts(struct ipc_protocol *this, int timeout_ms,
		u64 *p_remote_time, u32 *p_remote_ts_id,
		u32 *p_remote_time_unit, bool *p_ts_db_trig);


#endif	/* IMC_IPC_PROTOCOL_H */
