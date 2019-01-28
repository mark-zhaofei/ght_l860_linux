/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/module.h>
#include <linux/etherdevice.h>	/* ETH_HLEN */
#include <linux/delay.h>	/* msleep() */
#include <linux/if_vlan.h>
#include <linux/ctype.h>
#include <linux/seq_file.h>

#include <stdbool.h>		/* C99 bool: true, false.  */

#include "imc_ipc_imem.h"
#include "imc_ipc_tasklet.h"	/* IPC tasklet layer */
#include "imc_ipc_sio.h"	/* sio layer */
#include "imc_ipc_version.h"	/* Version info */
#include "imc_ipc_mux.h"	/* MUX definitions */
#include "imc_ipc_export.h"	/* Exported definitions */
#include "imc_ipc_util.h"	/* IPC configuration */
#include "imc_ipc_pm.h"
#include "imc_ipc_rtpm.h"
#include "imc_ipc_wwan.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_mmio.h"
#include "imc_ipc_params.h"
#include "imc_ipc_hrtimer.h"
#include "imc_ipc_chnl_cfg.h"
#include "imc_ipc_protocol.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_version.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_debugfs.h"
#include "imc_ipc_completion.h"
#include "imc_ipc_gpio_handler.h"

#ifndef IPC_EXTERNAL_BUILD
#include "imc_ipc_mmap.h"
#endif

/* Queue level size and reporting
 * >1 is enable, 0 is disable
 */
#define MUX_QUEUE_LEVEL  1

/* IRQ moderation in usec
 */
#define IRQ_MOD_OFF			0	/* moderation off */
#define IRQ_MOD_NET			1000	/* NET/MUX moderation 1ms */
#define IRQ_MOD_TRC			4000	/* TRC moderation 4 ms */

#ifdef IPC_SIO_UL_REQ_SPLIT
#define IMC_IPC_SIO_MAX_UL_SIZE		(32 * 1024)
#endif


/* Workaround for a lost or spurious interrupt, see
 * "spurious APIC interrupt on CPU#0, should never happen."
 *
 * unit : milliseconds
 */
#define IPC_SPURIOUS_IRQ_TIMEOUT  10

/* Either the PSI image is accepted by CP or the suspended flash tool
 * is waken informed that the CP ROM driver is not ready to process
 * the PSI image.
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_PSI_TRANSFER_TIMEOUT  60000
#else
#define IPC_PSI_TRANSFER_TIMEOUT  3000
#endif

/* Timeout in 20 msec to wait for the modem to boot up to
 * IPC_MEM_DEVICE_IPC_INIT state.
 *
 * unit : milliseconds (500 * msleep(20))
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_MODEM_BOOT_TIMEOUT 5000
#else
#define IPC_MODEM_BOOT_TIMEOUT 500
#endif

/* Wait timeout for ipc status reflects IPC_MEM_DEVICE_IPC_UNINIT
 *
 * unit : milliseconds
 */
 #if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_MODEM_UNINIT_TIMEOUT_MS 3000
#else
#define IPC_MODEM_UNINIT_TIMEOUT_MS 30
#endif

/* MUX finish timer timeout,
 *
 * unit : microseconds
 */
#define IPC_MUX_FINISH_TIMEOUT 500

/*
 * Pending time for processing data.
 *
 * unit : milliseconds
 */
 #if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_PEND_DATA_TIMEOUT	5000
#else
#define IPC_PEND_DATA_TIMEOUT	500
#endif

/*
 * The timeout in milliseconds for application to wait for remote time.
 */
#define IPC_REMOTE_TS_TIMOUT_MS 10

/*
 * Timeout for TD allocation retry.
 *
 * unit : milliseconds
 */
#define IPC_TD_ALLOC_TIMER_PERIOD_MS	100


/* Channel Index for SW download */
#define IPC_CHANNEL_INDEX_FLASH	(0)

/**
 * Enum defining channel states.
 */
enum ipc_channel_state {
	IMEM_CHANNEL_FREE,
	IMEM_CHANNEL_RESERVED,
	IMEM_CHANNEL_ACTIVE,
	IMEM_CHANNEL_CLOSING
};

/**
 * Enum defining supported channel type needed to control the CP or to transfer
 * IP packets.
 */
enum ipc_ctype {
	IPC_CTYPE_FLASH,	/* Used for flashing to RAM */
	IPC_CTYPE_WWAN		/* Used for Control and IP data */
};


/**
 * Structure for Channel.
 */
struct ipc_mem_channel {
	/* Instance of the channel list and is return to the user at the end of
	 * the open operation.
	 */
	int channel_id;

	/* Control or netif channel.
	 */
	enum ipc_ctype ctype;

	/* unique index per ctype
	 */
	int index;

	/* pipe objects
	 */
	struct ipc_pipe ul_pipe;
	struct ipc_pipe dl_pipe;

	/* Id of the sio device, set by imem_sio_open, needed to
	 * pass downlink characters to user terminal.
	 */
	int sio_id;

	/**
	 * VLAN ID
	 */
	int vlan_id;

	/* Number of downlink errors returned by ipc_wwan_receive interface at
	 * the entry point of the IP stack.
	 */
	u32 net_err_count;

	/* Free, reserved or busy (in use).
	 */
	enum ipc_channel_state state;

	/* Needed for the blocking write or uplink transfer.
	 */
	struct ipc_completion ul_sem;

	/* Uplink accumulator which is filled by the uplink
	 * char app or IP stack.
	 * The socket buffer pointer are added to the descriptor
	 * list in the kthread context.
	 */
	struct imem_ul_queue ul_list;
};
/* Workaround for a lost or spurious interrupt, see
 * "spurious APIC interrupt on CPU#0, should never happen."
 */
struct imem_spurious_irq {
	/* The use of the spurious IRQ simulation depends on the driver flag
	 * spurious_irq.
	 */
	bool in_use;

	/* Spurious IRQ timer.
	 */
	struct ipc_hrtimer *timer;
};

/* Different AP and CP phases.
 * The enums defined after "IPC_P_ROM" and before "IPC_P_RUN" indicates the
 * operating state where CP can respond to any requests. So while introducing
 * new phase this shall be taken into consideration.
 */
enum ipc_phase {
	/* On host PC, the PCIe device link settings are known about the
	 * combined power on. PC is running, the driver is loaded and CP is in
	 * power off mode. The PCIe bus driver call the device power mode
	 * D3hot. In this phase the driver the polls the device, until the
	 * device is in the power on state and signals the power mode D0.
	 */
	IPC_P_OFF,

	/* The intermediate phase between cleanup activity starts and ends.
	 */
	IPC_P_OFF_REQ,

	/* The phase indicating CP crash
	 */
	IPC_P_CRASH,

	/* The phase indicating CP core dump is ready
	 */
	IPC_P_CD_READY,

	/* After power on, CP starts in ROM mode and the IPC ROM driver
	 * is waiting 150 ms for the AP active notification
	 * saved in the PCI link status register.
	 */
	IPC_P_ROM,
	IPC_P_PSI,
	IPC_P_EBL,

	/* The phase after flashing to RAM is the RUNTIME phase.
	 */
	IPC_P_RUN,
};

/* Current state of the IPC shared memory.
 */
struct ipc_imem {

	/* mmio instance to access CP MMIO area / doorbell scratchpad.
	 */
	struct ipc_mmio *mmio;

	/* IPC Protocol instance
	 */
	struct ipc_protocol *p_protocol;

	/* Reserved channel id for flashing to RAM.
	 */
	int flash_channel_id;

	/* Workaround for a lost IRQ interrupt, see
	 * "spurious APIC interrupt on CPU#0, should never happen."
	 */
	struct imem_spurious_irq spurious_irq;

	/* Expected IPC state on CP.
	 */
	enum ipc_mem_device_ipc_state ipc_requested_state;

	/* Channel list with UL/DL pipe pairs.
	 */
	struct ipc_mem_channel channels[IPC_MEM_MAX_CHANNELS];

	/* local ipc_status */
	u32 ipc_status;

	/* number of configured channels
	 */
	u32 nr_of_channels;

	/* startup timer for NAND support.
	 */
	struct ipc_hrtimer *startup_timer;

	/* Delay the TD update doorbell.
	 */
	struct ipc_hrtimer *td_update_timer;
	int td_update_timer_suspended;

	/* forced head pointer update delay timer.
	 */
	struct ipc_hrtimer *fast_update_timer;

	/* Timer for forcefully finishing the ADB even it is not full.
	 */
	struct ipc_hrtimer *mux_finish_adb_timer;

	/* Timer for DL pipe TD allocation retry
	 */
	struct ipc_hrtimer *td_alloc_timer;

	/* Suspend the message sender.
	 */
	struct ipc_completion msg_sender_suspend;

	/* Mapped boot rom exit code.
	 */
	enum rom_exit_code rom_exit_code;

	/* 0 means inform the IPC tasklet to proces the irq actions.
	 */
	bool ev_irq_pending[IPC_IRQ_VECTORS];

	/* 0 means inform the IPC tasklet to pass the accumulated uplink
	 * buffers to CP.
	 */
	bool ev_sio_write_pending;

	/* 0 means inform the IPC tasklet to pass the accumulated uplink
	 * ADB to CP.
	 */
	bool ev_mux_net_transmit_pending;

	/* 1 means the transition to runtime phase was executed.
	 */
	u32 enter_runtime;

	/* 1 means msg_sender_suspend was initialized.
	 */
	u32 msg_sender_suspend_init;

	/* tasklet activations triggered by IRQ
	 */
	u32 ev_irq_count;

	/* Fast updates executed
	 */
	u32 ev_fast_update;

	/* Semaphore to wait/complete of UL TDs before closing pipe.
	 */
	struct ipc_completion ul_pend_sem;
	u32 app_notify_ul_pend;

	/* Semaphore to wait/complete of DL TDs before closing pipe.
	 */
	struct ipc_completion dl_pend_sem;
	u32 app_notify_dl_pend;

	/* Operating phase like runtime. */
	enum ipc_phase phase;

	/* tasklet for serialized work offload
	 * from interrupts and OS callbacks
	 */
	struct ipc_tasklet *tasklet;

	/*
	 * WWAN device pointer
	 */
	struct ipc_wwan *wwan;

	/* Data aggregation and IP multiplexing state. */
	struct imem_mux mux;

	/* Debugfs data structure pointer */
	struct ipc_debugfs *dbgfs;

	/* IPC SIO data structure pointer */
	struct ipc_sio *sio;

	/* IPC PCIe */
	struct ipc_pcie *pcie;

	/* IPC stats */
	struct ipc_debugfs_stats *stats;

	/* IPC parameters which can be configured by user */
	struct ipc_params *params;

	/* IPC HP update stress test debugfs node */
	struct ipc_debugfs_hpu_stress *hpu_stress;

	/* Device ID */
	u16 pci_device_id;

	/* CP version */
	int cp_version;

	/* Device sleep state */
	int device_sleep;

	/* IPC RTPM */
	struct ipc_rtpm *rtpm;

	/* MMAP */
	struct ipc_mmap *mmap;

	/* Device sleep without protocol capability */
	bool dev_slp_no_prot_capability;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	/* Status variable to keep Timesync Doorbell triggered and waiting
	 * for remote time.
	 */
	bool timesync_db_trig;

	/* reset detect flag */
	bool reset_det_n;

	/* pcie wake flag */
	bool pcie_wake_n;
};


/* These global exported variables are mapped to
 * /sys/module/imc_ipc/parameters
 */

/* REVERT_ME:: Module parameter to choose 7660 active Protocol.
 * Default value is zero.
 */
static uint force_legacy_proto;
module_param(force_legacy_proto, uint, 0664);
MODULE_PARM_DESC(force_legacy_proto, "choose Legacy Protocol");


/* =============================================================================
 * Forward declaration start.
 */

/* pipe and channel functions */
static bool imem_pipe_open(struct ipc_imem *this, struct ipc_pipe *pipe);
static void imem_pipe_close(struct ipc_imem *this, struct ipc_pipe *pipe);
static void imem_pipe_cleanup(struct ipc_imem *this, struct ipc_pipe *pipe);
static int imem_channel_free(struct ipc_mem_channel *channel);
static int imem_channel_alloc(struct ipc_imem *this, int id,
		enum ipc_ctype ctype);
static void ipc_imem_channel_update(struct ipc_imem *this,
	int id, u32 ul_nr_of_entries, u32 dl_nr_of_entries, u32 dl_buf_size,
	u32 ul_pipe, u32 dl_pipe, u32 irq_moderation, u32 accumulation_backoff);

/* wwan functions */
static void wwan_channel_init(struct ipc_imem *this,
		enum imem_mux_protocol protocol);
static int imem_wwan_open_cb(void *instance, int vlan_id);
static void imem_wwan_close_cb(void *instance, int vlan_id, int channel_id);
static int imem_wwan_transmit_cb(void *instance, int vlan_id, int channel_id,
	struct sk_buff *skb);
/* stage and phase functions */
static enum ipc_phase imem_ap_phase_update(struct ipc_imem *this);
static const char *ipc_ap_phase_get_string(enum ipc_phase phase);
static enum ipc_phase ipc_ap_phase_set(struct ipc_imem *this,
		enum ipc_phase phase);
static enum ipc_phase ipc_ap_phase_get(struct ipc_imem *this);
static enum ipc_mem_exec_stage ipc_imem_get_exec_stage(struct ipc_imem *this);
/* skb functions */
static void imem_ul_list_init(struct imem_ul_queue *ul_list);
static void imem_ul_list_add(struct imem_ul_queue *ul_list,
			     struct sk_buff *skb);
/* tasklet and irq functions */
static bool imem_dl_skb_alloc(struct ipc_imem *this, struct ipc_pipe *pipe);
static void imem_tl_td_update_timer_cb(void *instance);
static int imem_tl_irq_cb(void *instance, int arg, void *msg, size_t size);
static void imem_handle_irq(struct ipc_imem *this, int irq);
static int  imem_trigger_chip_info(struct ipc_imem *this);

static bool ipc_imem_syscall_enter(struct ipc_imem *this);
static void ipc_imem_syscall_leave(struct ipc_imem *this);

/* IP MUX functions */
static int mux_init(struct ipc_imem *this, struct imem_mux *mux);
static void mux_cleanup(struct ipc_imem *this,
		struct imem_mux *mux);
static int mux_schedule(struct ipc_imem *this,
		struct imem_mux *mux, union imem_mux_msg *msg_p);
static void mux_dl_process(struct ipc_imem *this,
		struct imem_mux *mux, struct sk_buff *skb);
static int mux_net_transmit(struct ipc_imem *this, struct imem_mux *mux,
			     int if_id, struct sk_buff *skb);
static bool mux_ul_data_encode(struct ipc_imem *this, struct imem_mux *mux);
static void mux_ul_adb_free(struct ipc_imem *this, struct imem_mux *mux,
		struct sk_buff *skb);
static void mux_ul_adb_finish(struct ipc_imem *this, struct imem_mux *mux);
static void mux_ul_adgh_finish(struct ipc_imem *this, struct imem_mux *mux);
static void mux_restart_tx_for_all_sessions(struct imem_mux *p_mux);
static void mux_stop_tx_for_all_sessions(struct imem_mux *p_mux);
static void mux_stop_netif_for_all_sessions(struct imem_mux *p_mux);
static int mux_dl_acb_send_cmds(struct ipc_imem *this,
		struct imem_mux *mux, u32 cmd_type,
		u8 if_id, u32 transaction_id, union ipc_mem_cmd_param *param,
		size_t res_size, bool blocking, bool respond);
static void mux_trigger_receive_trace(struct ipc_imem *this,
		struct imem_mux *mux, u32 cnt);

/* =============================================================================
 * Forward declaration end.
 */


/* Check the wwan ips if it is valid with Channel as input.
 */
static inline int ipc_imem_check_wwan_ips(struct ipc_mem_channel *c)
{
	return c ? (c->ctype == IPC_CTYPE_WWAN && c->vlan_id == -1) : 0;
}

/* Wrapper function to send the uevent.
 */
static inline void ipc_imem_uevent_send(struct ipc_imem *this, char *uevent)
{
	ipc_pcie_uevent_send(this->pcie, uevent);
}

/* Function to send the modem timeout uevent.
 */
static inline void ipc_imem_report_timeout(struct ipc_imem *this)
{
	ipc_pcie_uevent_send(this->pcie, NL_EVENT_MDM_TIMEOUT);
}

/*
 * Refer to header file for description
 */
int imem_msg_send_device_sleep(struct ipc_imem *this, u32 state,
		bool atomic_ctx)
{
	union ipc_msg_prep_args prep_args = {
			.sleep.target = 1, .sleep.state = state
		};

	if (unlikely(!this)) {
		ipc_err("invalid args");
		return -1;
	}

	this->device_sleep = state;

	if (atomic_ctx)
		return ipc_protocol_tl_msg_send(this->p_protocol,
			IPC_MSG_PREP_SLEEP, &prep_args, NULL);
	else
		return ipc_protocol_msg_send(this->p_protocol,
			IPC_MSG_PREP_SLEEP, &prep_args);
}

/*
 * Refer to header file for description
 */
int imem_get_device_sleep_state(struct ipc_imem *this)
{
	return this ? this->device_sleep : 0;
}

/*
 * Send feature set message to modem
 */
static int imem_msg_send_feature_set(struct ipc_imem *this,
	unsigned int reset_enable, bool atomic_ctx)
{
	union ipc_msg_prep_args prep_args = {
				.feature_set.reset_enable = reset_enable
			};

	if (atomic_ctx)
		return ipc_protocol_tl_msg_send(this->p_protocol,
			IPC_MSG_PREP_FEATURE_SET, &prep_args, NULL);
	else
		return ipc_protocol_msg_send(this->p_protocol,
			IPC_MSG_PREP_FEATURE_SET, &prep_args);
}

/* Start TD alloc timer if not already started
 */
static void ipc_imem_start_td_alloc_timer(struct ipc_imem *this)
{
	if (!ipc_hrtimer_is_active(this->td_alloc_timer))
		ipc_hrtimer_config(this->td_alloc_timer,
			IPC_TD_ALLOC_TIMER_PERIOD_MS * 1000);
}

/* This timer handler will retry DL buffer allocation if a pipe has no
 * free buffers or if the block_td_pipe_mask test feature is in use
 */
static void imem_tl_td_alloc_timer_cb(void *instance)
{
	struct ipc_imem *this = instance;
	bool retry_allocation = false;
	bool new_buffers_available = false;
	int i;

	for (i = 0; i < IPC_MEM_MAX_CHANNELS; i++) {
		struct ipc_pipe *pipe = &this->channels[i].dl_pipe;
		u32 mask = 1 << pipe->pipe_nr;

		/* Skip closed and locked pipes. Also skip pipes that are not
		 * empty when their bit in block_td_pipe_mask is not set.
		 */
		if (!pipe->is_open || pipe->locked ||
			(pipe->nr_of_queued_entries > 0 &&
				!(this->params->block_td_pipe_mask & mask)))
			continue;

		pipe->is_busy = true;

		while (imem_dl_skb_alloc(this, pipe))
			new_buffers_available = true;

		if (pipe->nr_of_queued_entries == 0)
			retry_allocation = true;

		pipe->is_busy = false;
	}

	if (new_buffers_available)
		ipc_protocol_doorbell_trigger(this->p_protocol,
			IPC_HP_DL_PROCESS);

	if (retry_allocation || this->params->block_td_pipe_mask)
		ipc_imem_start_td_alloc_timer(this);
}


/* restart the TD update timer.
 */
static void imem_td_update_timer_restart(struct ipc_imem *this)
{
	ipc_hrtimer_config(this->td_update_timer, this->params->td_update_tmo);
}

/* stop the TD update timer.
 */
static void imem_td_update_timer_stop(struct ipc_imem *this)
{
	ipc_trc_td_stop_timer(ipc_hrtimer_is_active(this->td_update_timer));

	ipc_hrtimer_config(this->td_update_timer, 0);
}				/* imem_td_update_timer_stop */

/* Delay the doorbell irq.
 */
static void imem_td_update_timer_start(struct ipc_imem *this)
{
	/* Use the UL timer only in the runtime phase and
	 * trigger the doorbell irq on CP directly.
	 */
	if (!this->enter_runtime || this->td_update_timer_suspended) {
		ipc_protocol_doorbell_trigger(this->p_protocol,
			IPC_HP_TD_UPD_TMR_START);
		return;
	}

	if (!ipc_hrtimer_is_active(this->td_update_timer))
		ipc_hrtimer_config(this->td_update_timer,
			this->params->td_update_tmo);

	ipc_trc_td_start_timer(ipc_hrtimer_is_active(this->td_update_timer));
}

/* Fast update timer tasklet handler to trigger HP udpate..
 */
static int imem_tl_fast_update_timer_cb(void *instance, int arg,
			void *msg, size_t size)
{
	struct ipc_imem *this = instance;

	if (unlikely(!this)) {
		ipc_err("Unexpected NULL pointer from Timer callback to Tasklet handler");
		return 0;
	}

	ipc_protocol_doorbell_trigger(this->p_protocol,
			IPC_HP_FAST_TD_UPD_TMR);

	return 0;
}


/* Callback for the force update timer.
 */
static void imem_fast_update_timer_cb(void *instance_p)
{
	struct ipc_imem *this = instance_p;

	if (ipc_protocol_pm_dev_is_sleep_handling(this->p_protocol))
		/* Post an async tasklet event to trigger HP update Doorbell */
		ipc_tasklet_call_async(this->tasklet,
			imem_tl_fast_update_timer_cb, this, 0, NULL, 0);
	else
		ipc_protocol_doorbell_trigger(this->p_protocol,
				IPC_HP_FAST_TD_UPD_TMR);
	this->ev_fast_update++;
}

/* stop the force update timer.
 */
static void imem_fast_update_timer_stop(struct ipc_imem *this)
{
	ipc_hrtimer_config(this->fast_update_timer, 0);
}

/* Delay the doorbell irq.
 */
static void imem_fast_update_timer_start(struct ipc_imem *this)
{
	if (!ipc_hrtimer_is_active(this->fast_update_timer))
		ipc_hrtimer_config(this->fast_update_timer,
			this->params->fast_update_tmo);
}

/* MUX UL ADB timer callback in Tasklet context.
 */
static void imem_tl_mux_finish_adb_timer_cb(void *instance)
{
	struct ipc_imem *this = instance;
	/* ADB Finish shall be called if Modem is Running &
	 * MUX layer is initialized & is in ACTIVE state
	 */
	if (this->enter_runtime &&
			this->mux.initialized &&
			this->mux.state == MUX_S_ACTIVE &&
			this->mux.protocol == MUX_AGGREGATION)
		/* Finish the ADB */
		mux_ul_adb_finish(this, &this->mux);
}

/* Timer start function for the MUX UL ADB forcefully finishing even
 * if it is not full.
 */
static void imem_mux_finish_adb_timer_start(struct ipc_imem *this, u32 delay)
{
	ipc_hrtimer_config(this->mux_finish_adb_timer, delay);
}

/* Timer stop function for the MUX UL ADB  timer.
 */
static void imem_mux_finish_adb_timer_stop(struct ipc_imem *this)
{
	ipc_hrtimer_config(this->mux_finish_adb_timer, 0);
}

/* fill UL TD with queue UL data
 */
static bool imem_ul_write_td(struct ipc_imem *this)
{
	struct ipc_pipe *pipe;
	struct ipc_mem_channel *channel;
	struct imem_ul_queue *ul_list;
	bool hpda_pending = false;
	bool forced_hpdu = false;
	int i;

	/* Analyze the uplink pipe of all active channels.
	 */
	for (i = 0; i < this->nr_of_channels; i++) {
		u32 __maybe_unused nr_of_queued_entries;

		/* Get the reference of the channel definition.
		 */
		channel = &this->channels[i];

		/* Test the channel state.
		 */
		if (channel->state != IMEM_CHANNEL_ACTIVE)
			continue;

		/* get pointer to pipe object */
		pipe = &channel->ul_pipe;

		/* Get the reference to the skbuf accumulator list.
		 */
		ul_list = &channel->ul_list;

		nr_of_queued_entries = pipe->nr_of_queued_entries;

		/* Fill the transfer descriptor with the uplink buffer
		 * information.
		 */
		hpda_pending |= ipc_protocol_ul_td_send(this->p_protocol,
			pipe, ul_list);

		/* Trace channel stats for MUX pipe. */
		if (ipc_imem_check_wwan_ips(pipe->channel))
			ipc_trc_ul_chnl_stats(pipe->pipe_nr,
					(nr_of_queued_entries -
						pipe->nr_of_queued_entries),
					pipe->nr_of_entries,
					pipe->max_nr_of_queued_entries,
					pipe->nr_of_queued_entries,
					ul_list->nr_of_bytes, true);

		/* forced HP update needed for non data channels */
		if (hpda_pending && !ipc_imem_check_wwan_ips(channel))
			forced_hpdu = true;
	} /* for */

	if (forced_hpdu) {
		hpda_pending = false;
		ipc_protocol_doorbell_trigger(this->p_protocol,
				IPC_HP_UL_WRITE_TD);
	}

	return hpda_pending;
}				/* imem_ul_write_td */


/**
 * Setup the version of CP, supported capabilities and initialize
 * accordingly
 */
static int imem_setup_cp_ver_cap_init(struct ipc_imem *this)
{
	/* By default MUX DL UL Aggregation support and UL TX even without
	 * credits
	 */
	this->mux.protocol = ipc_mmio_cp_has_mux_lite(this->mmio) ?
		MUX_LITE : MUX_AGGREGATION;

	this->mux.ul_flow = ipc_mmio_cp_has_ul_flow_credit(this->mmio) ?
		MUX_UL_ON_CREDITS : MUX_UL_LEGACY;

	/* Fetch and save the CP sleep without protocol capability.
	 */
	this->dev_slp_no_prot_capability =
		ipc_mmio_cp_has_sleep_no_prot(this->mmio);

	ipc_dbg("IOSM CP sleep no protocol:%s",
		(this->dev_slp_no_prot_capability ?
		"TRUE" : "FALSE"));

	ipc_dbg("IOSM CP protocol:%s",
		(this->mux.protocol == MUX_LITE ? "MUX_LITE" :
			"MUX_AGGREGATION"));

	ipc_dbg("Ul flow type: %s",
			this->mux.ul_flow == MUX_UL_ON_CREDITS ?
			"ON_CREDITS" : "LEGACY");

	return 0;
}



/* Send the init event to CP, wait a certain time and set CP to runtime with
 * the context information.
 */
static void imem_ipc_init_check(struct ipc_imem *this)
{
	int i;

	/* Trigger the CP interrupt to enter the init state.
	 */
	this->ipc_requested_state = IPC_MEM_DEVICE_IPC_INIT;

	ipc_cp_irq_ipc_control(this->pcie, IPC_MEM_DEVICE_IPC_INIT);

	/* Wait for the CP update.
	 */
	for (i = 0; i < IPC_MODEM_BOOT_TIMEOUT; i++) {

		if (ipc_mmio_get_ipc_state(this->mmio) ==
			this->ipc_requested_state) {

			/* Prepare the MMIO space */
			ipc_mmio_init(this->mmio);

			/* Trigger the CP interrupt to enter the running state.
			 */
			this->ipc_requested_state =
			    IPC_MEM_DEVICE_IPC_RUNNING;
			ipc_cp_irq_ipc_control(this->pcie,
					IPC_MEM_DEVICE_IPC_RUNNING);

			/* Protocol is set to RUN state. Now good to read
			 * Message Completion Support and update protocol
			 * instance.
			 */
			ipc_protocol_update_mcr_cp_cap(this->p_protocol,
				ipc_mmio_cp_has_mcr_support(this->mmio));
			return;
		}
		msleep(20);
	}

	/* timeout
	 */
	ipc_err("%s: ipc_status(%d) ne. IPC_MEM_DEVICE_IPC_INIT",
		ipc_ap_phase_get_string(this->phase),
		ipc_mmio_get_ipc_state(this->mmio));

	ipc_imem_report_timeout(this);
}


/* Allocate a downlink skbuf.
 */
static bool imem_dl_skb_alloc(struct ipc_imem *this, struct ipc_pipe *pipe)
{
	struct ipc_params *params = this->params;
	u32 mask = 1 << pipe->pipe_nr;

	/* limit max. nr of entries */
	if (pipe->nr_of_queued_entries >= pipe->max_nr_of_queued_entries)
		return false;

	/* limit # of allocated DL buffers for test purposes */
	if (unlikely(params->block_td_pipe_mask & mask)) {
		if ((params->tds_ctrl_mask & mask) &&
			params->nr_of_tds_to_unblock > 0)
			params->nr_of_tds_to_unblock--;
		else
			return false;
	}

	return ipc_protocol_dl_skb_alloc(this->p_protocol, pipe);
}				/* imem_dl_skb_alloc */

/* Callback for the timer to simulate a lost IRQ.
 */
static void imem_tl_spurious_irq_cb(void *instance_p)
{
	struct ipc_imem *this = instance_p;

	(void) imem_handle_irq(this, IMEM_IRQ_DONT_CARE);
}

/* Workaround for a lost or spurious interrupt, see
 * "spurious APIC interrupt on CPU#0, should never happen."
 */
static void imem_trigger_spurious_irq(struct ipc_imem *this)
{
	if (!this->spurious_irq.in_use)
		return; /* Spurious irq handling is inactive. */

	/* Ignore the recovery timer if the device link state is in sleep mode.
	 */
	if (ipc_protocol_pm_dev_is_in_sleep(this->p_protocol))
		return;

	/* Start the timer only in D0 and in runtime phase.
	 */
	if (ipc_ap_phase_get(this) != IPC_P_RUN)
		return;

	/* Start the timer to simulate a lost IRQ.
	 */
	ipc_hrtimer_config(this->spurious_irq.timer,
		IPC_SPURIOUS_IRQ_TIMEOUT * 1000ULL);
}

/* Analyze the packet type and distribute it.
 */
static void imem_dl_skb_process(struct ipc_imem *this,
		struct ipc_pipe *pipe, struct sk_buff *skb)
{
	if (unlikely(!this || !skb)) {
		ipc_err("invalid args");
		return;
	}

	/* An AT/control or IP packet is exepected.
	 */
	switch (pipe->channel->ctype) {

	case IPC_CTYPE_FLASH:
		/* Pass the packet to the char layer.
		 */
		if (ipc_sio_receive(this->sio, skb)) {
			ipc_err("pipe(%d): rejected ctrl packet",
				pipe->pipe_nr);
			ipc_pcie_kfree_skb(this->pcie, skb);
		}
		return;

	case IPC_CTYPE_WWAN:

		/* drop the packet if vlan id = 0 */
		if (pipe->channel->vlan_id == 0) {
			ipc_pcie_kfree_skb(this->pcie, skb);
			return;
		}

		/* set data session if vlan_id between 256 and 512 */
		if (pipe->channel->vlan_id > 256
		&& pipe->channel->vlan_id < 768) {
			if (unlikely(pipe->channel->state !=
				IMEM_CHANNEL_ACTIVE)) {
				ipc_err("pipe(%d): reject ip packet",
					pipe->pipe_nr);
				ipc_pcie_kfree_skb(this->pcie, skb);
				return;
			}
			skb_push(skb, ETH_HLEN);

			/* map session to vlan */
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
						pipe->channel->vlan_id);

			/* unmap skb from address mapping */
			ipc_pcie_unmap_skb(this->pcie, skb);

			if (ipc_wwan_receive(this->wwan, skb,
						(pipe->channel->vlan_id < 513)))
				pipe->channel->net_err_count++;
			return;
		}

		/* DL packet through the IP MUX layer */
		if (ipc_imem_check_wwan_ips(pipe->channel))
			mux_dl_process(this, &this->mux, skb);
		return;
	default:
		ipc_dbg("channel type do not exist");
		return;
	}			/* end switch */
}				/* imem_dl_skb_process */

/* Process the downlink data and pass them to the char or net layer.
 */
static bool imem_dl_pipe_process(struct ipc_imem *this,
		struct ipc_pipe *pipe)
{
	struct ipc_mem_channel *channel;
	u32 head = 0, tail = 0;
	struct sk_buff *skb;
	bool processed = false;
	s32 cnt = 0, processed_td_cnt = 0;

	/* Consider channel reconfiguration phase.
	 */
	if (pipe->locked)
		return false;

	pipe->is_busy = 1;

	/* get channel instance
	 */
	channel = pipe->channel;

	ipc_protocol_get_head_tail_index(this->p_protocol, pipe, &head, &tail);

	if (pipe->old_tail != tail) {
		if (pipe->old_tail < tail)
			cnt = tail - pipe->old_tail;
		else
			cnt = pipe->nr_of_entries - pipe->old_tail + tail;


		/* Trigger MUX trace if packets received on mux channel.
		 * Trace out packets that have been DMAed to HP
		 */
		if (ipc_imem_check_wwan_ips(channel) && (cnt > 0))
			mux_trigger_receive_trace(this, &this->mux, cnt);

		ipc_dbg(">> pipe(%d): old_tail=%d, tail=%d, head=%d, cnt=%d",
			 pipe->pipe_nr, pipe->old_tail, tail, head, cnt);
	}

	processed_td_cnt = cnt;

	/* Seek for pipes with pending DL data.
	 */
	while (cnt--) {
		skb = ipc_protocol_dl_td_process(this->p_protocol, pipe);

		/* Analyze the packet type and distribute it.
		 */
		imem_dl_skb_process(this, pipe, skb);
	}			/* eof while */

	/* Trigger MUX trace if packets received on mux channel.
	 * After DMAed packets have been delivered to netif
	 */
	if (ipc_imem_check_wwan_ips(channel))
		mux_trigger_receive_trace(this, &this->mux,
				(tail - pipe->old_tail));

	/* try to allocate new empty DL SKbs from head..tail - 1*/
	while (imem_dl_skb_alloc(this, pipe))
		processed = true;

	/* flush net interfaces if needed
	 */
	if (processed && !ipc_imem_check_wwan_ips(channel)) {
		/* Force HP update for non IP channels */
		ipc_protocol_doorbell_trigger(this->p_protocol,
			IPC_HP_DL_PROCESS);
		processed = false;

		/* If Fast Update timer is already running then stop */
		if (ipc_hrtimer_is_active(this->fast_update_timer))
			imem_fast_update_timer_stop(this);
	}

	/* Any control channel process will get immediate HP udpate.
	 * Start Fast update timer only for IP channel if all the TDs were
	 * used in last process.
	 */
	if (processed && (processed_td_cnt == pipe->nr_of_entries - 1))
		imem_fast_update_timer_start(this);


	if (this->app_notify_dl_pend)
		ipc_completion_signal(&this->dl_pend_sem);

	pipe->is_busy = 0;

	return processed;
}				/* imem_dl_pipe_process */

#ifdef IPC_INCLUDE_FTRACE_SYMBOL
EXPORT_SYMBOL(imem_dl_pipe_process);
#endif

/* Free the uplink buffer.
 */
static bool imem_ul_pipe_process(struct ipc_imem *this, struct ipc_pipe *pipe)
{
	struct sk_buff *skb;
	u32 tail = 0, head = 0;
	struct ipc_skb_cb *skb_cb;
	struct ipc_mem_channel *channel;
	bool processed = false;
	s32 cnt = 0;
	s32 __maybe_unused processed_cnt;

	/* Consider channel reconfiguration phase.
	 */
	pipe->is_busy = 1;
	if (pipe->locked)
		goto imem_ul_pipe_process_l;

	/* Get the reference to the channel description to resume the user app.
	 */
	channel = pipe->channel;

	/* Get the internal phase.
	 */
	ipc_protocol_get_head_tail_index(this->p_protocol, pipe, &head, &tail);

	if (pipe->old_tail != tail) {
		if (pipe->old_tail < tail)
			cnt = tail - pipe->old_tail;
		else
			cnt = pipe->nr_of_entries - pipe->old_tail + tail;

		ipc_dbg(">> pipe(%d): old_tail=%d, tail=%d, head=%d, cnt=%d",
			 pipe->pipe_nr, pipe->old_tail, tail, head, cnt);
	}

	/* check if something has to be processed
	 */
	processed = (pipe->old_tail != tail) ? true : false;

	if (pipe->old_tail != tail) {
		if (head != tail)
			/* If some pending data still be processed then return
			 * false so that TD Update timer will not be stopped.
			 */
			processed = false;
		else
			processed = true;
	}

	processed_cnt = cnt;
	/* Free UL buffers.
	 */
	while (cnt--) {
		skb = ipc_protocol_ul_td_process(this->p_protocol, pipe);

		if (!skb)
			continue;

		/* Get the operation type.
		 */
		skb_cb = (struct ipc_skb_cb *)skb->cb;

		/* If the user app was suspended in uplink direction - blocking
		 * write, resume it.
		 */
		if (skb_cb->op_type == UL_USR_OP_BLOCKED)
			ipc_completion_signal(&channel->ul_sem);

		/* Free the skbuf element.
		 */
		if (skb_cb->op_type == UL_MUX_OP_ADB)
			mux_ul_adb_free(this, &this->mux, skb);
		else
			ipc_pcie_kfree_skb(this->pcie, skb);
	}			/* eof while */

	/* Trace channel stats for UL0 pipe. */
	if (ipc_imem_check_wwan_ips(pipe->channel))
		ipc_trc_ul_chnl_stats(pipe->pipe_nr,
				processed_cnt, pipe->nr_of_entries,
				pipe->max_nr_of_queued_entries,
				pipe->nr_of_queued_entries,
				channel->ul_list.nr_of_bytes, false);

	if ((this->mux.ul_flow == MUX_UL_LEGACY) &&
			this->params->mux_flow_ctrl_en &&
			(this->mux.ul_data_pend_bytes <
				this->params->mux_flow_ctrl_low_thresh_b)) {
		/* Legacy flow control allows tx now */
		mux_restart_tx_for_all_sessions(&this->mux);

		ipc_trc_ul_mux_flowctrl(0,
				this->params->mux_flow_ctrl_high_thresh_b,
				this->mux.ul_data_pend_bytes,
				pipe->pipe_nr, pipe->nr_of_entries,
				pipe->max_nr_of_queued_entries,
				pipe->nr_of_queued_entries,
				channel->ul_list.nr_of_bytes);
	}

	if (this->app_notify_ul_pend)
		ipc_completion_signal(&this->ul_pend_sem);

imem_ul_pipe_process_l:
	pipe->is_busy = 0;

	return processed;
}				/* imem_ul_pipe_process */

/* Before CP ROM driver starts the PSI image, it sets the exit_code field on
 * the doorbell scratchpad and triggers the irq.
 */
static void imem_rom_irq_exec(struct ipc_imem *this)
{
	struct ipc_mem_channel *channel;

	/* Test the presence of the flash app.
	 */
	if (unlikely(this->flash_channel_id < 0)) {
		this->rom_exit_code = IMEM_ROM_EXIT_FAIL;
		ipc_err("missing the flash app:%d", this->flash_channel_id);
		return;
	}

	/* Copy the CP ROM exit code.
	 */
	this->rom_exit_code = ipc_mmio_get_rom_exit_code(this->mmio);

	/* Wake up the flash app to continue or to terminate depending
	 * on the CP ROM exit code.
	 */
	channel = &this->channels[this->flash_channel_id];
	ipc_completion_signal(&channel->ul_sem);
}				/* imem_rom_irq_exec */

/* Consider link power management in the runtime phase.
 */
static void imem_slp_control_exec(struct ipc_imem *this)
{
	if (ipc_protocol_pm_dev_sleep_handle(this->p_protocol)) {
		/* link will go down */
		/* Test pending UL packets.
		 */
		if (ipc_hrtimer_is_active(this->td_update_timer)) {
			/* Generate the doorbell irq. */
			imem_tl_td_update_timer_cb(this);
			/* Deactivate the TD update timer. */
			imem_td_update_timer_stop(this);
			/* Deactivate the force update timer. */
			imem_fast_update_timer_stop(this);
		}
	}
}


/* Execute startup timer and wait for delayed start (e.g. NAND)
 */
static void imem_tl_startup_timer_cb(void *instance)
{
	struct ipc_imem *this = instance;

	/* Update & check the current operation phase.
	 */
	if (imem_ap_phase_update(this) != IPC_P_RUN)
		return;

	if (ipc_mmio_get_ipc_state(this->mmio) == IPC_MEM_DEVICE_IPC_UNINIT) {
		this->ipc_requested_state = IPC_MEM_DEVICE_IPC_INIT;
		ipc_cp_irq_ipc_control(this->pcie, IPC_MEM_DEVICE_IPC_INIT);

		/* reduce period to 100 ms to check for mmio init state */
		ipc_hrtimer_config(this->startup_timer, 100 * 1000UL);
	}

	if (ipc_mmio_get_ipc_state(this->mmio) == IPC_MEM_DEVICE_IPC_INIT) {
		/* Startup complete  - disable timer */
		ipc_hrtimer_config(this->startup_timer, 0);

		/* Prepare the MMIO space */
		ipc_mmio_init(this->mmio);
		this->ipc_requested_state = IPC_MEM_DEVICE_IPC_RUNNING;
		ipc_cp_irq_ipc_control(this->pcie, IPC_MEM_DEVICE_IPC_RUNNING);

		/* Protocol is set to RUN state. Now good to read Message
		 * Completion Support and update protocol instance.
		 */
		ipc_protocol_update_mcr_cp_cap(this->p_protocol,
			ipc_mmio_cp_has_mcr_support(this->mmio));
	}
}

/* Execute the UL bundle timer actions.
 */
static void imem_tl_td_update_timer_cb(void *instance)
{
	struct ipc_imem *this = instance;

	ipc_protocol_doorbell_trigger(this->p_protocol, IPC_HP_TD_UPD_TMR);

	if (this->mux.channel)
		ipc_trc_td_update_timer_cb(
				this->mux.channel->ul_pipe.nr_of_queued_entries,
				this->mux.channel->ul_list.nr_of_bytes);
}

/* Execute the irq operations.
 */
static void imem_handle_irq(struct ipc_imem *this, int irq)
{
	enum ipc_phase old_phase, phase;
	int i;
	bool ul_processed = false;
	bool dl_processed = false;
	bool ul_pending = false;
	enum ipc_mem_device_ipc_state curr_ipc_status;
	bool retry_allocation = false;

	if (irq != IMEM_IRQ_DONT_CARE)
		this->ev_irq_pending[irq] = false;

	/* Get the internal phase.
	 */
	old_phase = ipc_ap_phase_get(this);

	if (old_phase == IPC_P_OFF_REQ) {
		ipc_dbg("[%s]: Ignoring MSI. Deinit sequence in progress!",
				ipc_ap_phase_get_string(old_phase));
		return;
	}

	/* Update the phase controlled by CP.
	 */
	phase = imem_ap_phase_update(this);

	/* Test the phase.
	 */
	switch (phase) {
	case IPC_P_RUN:
		if (!this->enter_runtime) {
			/* Excute the transition from flashing/booting
			 * to runtime.
			 */
			this->enter_runtime = 1;

			/* allow device to sleep, default value is
			 * IPC_HOST_SLEEP_ENTER_SLEEP
			 */
			imem_msg_send_device_sleep(this, this->device_sleep,
				true);

			/* send feature set message */
			imem_msg_send_feature_set(this,
				this->params->in_band_crash_signal, true);
		}

		curr_ipc_status = ipc_protocol_get_ipc_status(this->p_protocol);

		/* check ipc_status change */
		if (this->ipc_status != curr_ipc_status) {
			this->ipc_status = curr_ipc_status;

			if (this->ipc_status == IPC_MEM_DEVICE_IPC_RUNNING) {
				/* Setup CP version, capabilities */
				imem_setup_cp_ver_cap_init(this);

				wwan_channel_init(this, this->mux.protocol);
				mux_init(this, &this->mux);

				ipc_dbg(">>>>> MODEM IS READY  %d <<<<<",
						__LINE__);
				ipc_imem_uevent_send(this, NL_EVENT_MDM_READY);

				/* Remove boot sio device */
				ipc_sio_free_deferred(&this->sio);
			}
		}

		/* Consider power management in the runtime phase.
		 */
		imem_slp_control_exec(this);
		break;		/* Continue with skbuf processing. */

		/* Unexpected phases.
		 */
	case IPC_P_OFF:
	case IPC_P_OFF_REQ:
		ipc_err("confused phase %s",
				ipc_ap_phase_get_string(phase));
		return;

	case IPC_P_PSI:
		if (old_phase != IPC_P_ROM)
			break;

		/* Fall through
		 * On CP the PSI phase is already active.
		 */

	case IPC_P_ROM:
		/* Before CP ROM driver starts the PSI image, it sets
		 * the exit_code field on the doorbell scratchpad and
		 * triggers the irq.
		 */
		imem_rom_irq_exec(this);
		return;

	default:
		break;

	}			/* switch */

	/* process message ring */
	ipc_protocol_msg_process(this->p_protocol, irq);

	/* process all open pipes
	 */
	for (i = 0; i < IPC_MEM_MAX_CHANNELS; i++) {
		struct ipc_pipe *ul_pipe = &this->channels[i].ul_pipe;
		struct ipc_pipe *dl_pipe = &this->channels[i].dl_pipe;

		if ((dl_pipe->is_open)
		&& (irq == IMEM_IRQ_DONT_CARE || irq == dl_pipe->irq)) {
			dl_processed |= imem_dl_pipe_process(this, dl_pipe);

			if (dl_pipe->nr_of_queued_entries == 0)
				retry_allocation = true;
		}

		/* && irq == IMEM_IRQ_DONT_CARE || irq == ul_pipe->irq */
		if (ul_pipe->is_open)
			ul_processed |= imem_ul_pipe_process(this, ul_pipe);

	}			/* eof for */

	/* Try to generate new ADB or ADGH. */
	ul_pending = mux_ul_data_encode(this, &this->mux);
	if (ul_pending) {
		/* Do not restart the timer if already running */
		imem_td_update_timer_start(this);
		if (this->mux.protocol == MUX_AGGREGATION)
			imem_mux_finish_adb_timer_start(this,
					IPC_MUX_FINISH_TIMEOUT);
	}

	/* Continue the send procedure with accumulated SIO or NETIF packets.
	 * Reset the debounce flags.
	 */
	ul_pending |= imem_ul_write_td(this);

	if (dl_processed || ul_processed)
		ipc_rtpm_mark_last_busy(this->rtpm);

	/* if UL data is processed restart TD update timer
	 */
	if (ul_pending)
		imem_td_update_timer_restart(this);

	if (phase == IPC_P_PSI || phase == IPC_P_EBL) {
		/* If CP has executed the transition
		 * from IPC_INIT to IPC_RUNNING in the PSI
		 * phase, wake up the flash app to open the pipes.
		 */

		/* Test the state.
		 */
		if (this->ipc_requested_state == IPC_MEM_DEVICE_IPC_RUNNING &&
			ipc_mmio_get_ipc_state(this->mmio) ==
				IPC_MEM_DEVICE_IPC_RUNNING) {
			/* Test the presence of the flash app.
			 */
			if (this->flash_channel_id < 0) {
				ipc_err("missing the flash app");
			} else {
				/* Wake up the flash app to open the pipes.
				 */
				ipc_completion_signal(&this->channels
					 [this->flash_channel_id].ul_sem);
			}
		}
	}

	/* Reset the expected CP state.
	 */
	this->ipc_requested_state = IPC_MEM_DEVICE_IPC_DONT_CARE;

	if (retry_allocation || this->params->block_td_pipe_mask)
		ipc_imem_start_td_alloc_timer(this);
}

/* tasklet callback for interrupt handler.
 * arg contains the interrupt number, msg and size are unused.
 */
static int imem_tl_irq_cb(void *instance, int arg, void *msg, size_t size)
{
	struct ipc_imem *this = instance;

	imem_handle_irq(this, arg);

	/* Workaround for a lost interrupt, see
	 * "spurious APIC interrupt on CPU#0, should never happen."
	 */
	imem_trigger_spurious_irq(this);

	return 0;
}

/* Verify the CP execution save, copy the chip info,
 * change the execution pahse to ROM and resume the
 * flash app.
 */
static int imem_tl_trigger_chip_info_cb(void *instance, int arg, void *msg,
	size_t msgsize)
{
	struct ipc_imem *this = instance;
	struct sk_buff *skb;
	size_t size;
	enum ipc_mem_exec_stage stage;

	/* Test the CP execution state.
	 */
	stage = ipc_mmio_get_exec_stage(this->mmio);
	if (unlikely(stage != IPC_MEM_EXEC_STAGE_BOOT)) {
		ipc_err("execution_stage: expected BOOT, received=%X",
			stage);
		return -1;
	}

	/* Allocate a new sk buf for the chip info.
	 */
	size = ipc_mmio_get_chip_info_size(this->mmio);
	skb = ipc_pcie_alloc_local_skb(this->pcie, GFP_ATOMIC, size);
	if (unlikely(!skb)) {
		ipc_err("exhausted skbuf kernel DL memory");
		return -1;
	}

	/* Copy the chip info characters into the sk_buff.
	 */
	ipc_mmio_copy_chip_info(this->mmio, skb_put(skb, size), size);

	/* First change to the ROM boot phase.
	 */
	ipc_dbg("execution_stage[%X] eq. BOOT", stage);
	ipc_ap_phase_set(this, IPC_P_ROM);

	/* Inform the flash app, that the chip info are present.
	 */
	if (ipc_sio_receive(this->sio, skb)) {
		ipc_err("rejected downlink data");
		ipc_pcie_kfree_skb(this->pcie, skb);
		return -1;
	}

	return 0;
}

/* Translate the CP execution stage to string format
 */
static const char *ipc_imem_exec_stage_to_string(
	struct ipc_imem *this, enum ipc_mem_exec_stage exec_stage)
{
	switch (exec_stage) {
	case IPC_MEM_EXEC_STAGE_BOOT:
		return "C-BOOT";

	case IPC_MEM_EXEC_STAGE_PSI:
		return "C-PSI";

	case IPC_MEM_EXEC_STAGE_EBL:
		return "C-EBL";

	case IPC_MEM_EXEC_STAGE_RUN:
		return "C-RUN";

	case IPC_MEM_EXEC_STAGE_CRASH:
		return "C-CRASH";

	case IPC_MEM_EXEC_STAGE_CD_READY:
		return "C-CD_READY";

	default:
		ipc_err("invalid CP execution stage %X", exec_stage);
		return "C-INVALID";
	}
}


/* Return the CP execution stage by directly reading the MMIO area via the
 * PCIe bus.
 */
static enum ipc_mem_exec_stage ipc_imem_get_exec_stage(struct ipc_imem *this)
{
	return ipc_mmio_get_exec_stage(this->mmio);
}

/* Return the CP execution stage either from AP local device info if
 * ipc is up and running, or directly from the CP MMIO area via the
 * PCIe bus.
 */
static enum ipc_mem_exec_stage ipc_imem_get_exec_stage_buffered(
	struct ipc_imem *this)
{
	return (ipc_ap_phase_get(this) == IPC_P_RUN &&
		this->ipc_status == IPC_MEM_DEVICE_IPC_RUNNING) ?
			ipc_protocol_get_ap_exec_stage(this->p_protocol) :
			ipc_imem_get_exec_stage(this);
}

/* Activate the CP link in non-blocking mode.
 * If it is active start with the uplink transfer.
 */
static void imem_ul_send(struct ipc_imem *this)
{
	/* start doorbell irq delay timer if UL is pending */
	if (imem_ul_write_td(this))
		imem_td_update_timer_start(this);
}

/* Tasklet call to do uplink transfer.
 */
static int imem_tl_sio_write(void *instance, int arg, void *msg, size_t size)
{
	struct ipc_imem *this = instance;

	this->ev_sio_write_pending = false;
	imem_ul_send(this);

	return 0;
}

/* Test the link power state and send a MUX command in blocking mode.
 */
static int imem_tl_mux_cmd_send(void *instance, int arg, void *msg, size_t size)
{
	struct ipc_imem *this = instance;
	const struct imem_mux_acb *acb = msg;

	if (unlikely(!acb || !this)) {
		ipc_err("Invalid  arguments");
		return -1;
	}

	if (acb->cmd == IPC_MEM_CMD_CLOSE_SESSION) {
		ipc_dbg("Close session request. Finishing ADB");
		mux_ul_adb_finish(this, &this->mux);
		imem_mux_finish_adb_timer_stop(this);
	}

	imem_ul_list_add(&this->mux.channel->ul_list, acb->skb);
	imem_ul_send(this);

	return 0;
}

/* Test the link power state and start the NETIF uplink send transfer in
 * MUX mode.
 */
static int imem_tl_mux_net_transmit(void *instance, int arg, void *msg,
	size_t size)
{
	struct ipc_imem *this = instance;
	bool ul_data_pend = false;

	/* Add session UL data to a ADB and ADGH
	 */
	ul_data_pend = mux_ul_data_encode(this, &this->mux);
	if (ul_data_pend) {
		if (this->mux.protocol == MUX_AGGREGATION)
			/* Start the MUX finish timer if any packet is added to
			 * ADB.
			 */
			imem_mux_finish_adb_timer_start(this,
					IPC_MUX_FINISH_TIMEOUT);

		/* Delay the doorbell irq */
		imem_td_update_timer_start(this);
	}

	/* reset the debounce flag */
	this->ev_mux_net_transmit_pending = false;

	return 0;
}

/* tasklet context: Initiate time synchronization
 */
static int imem_tl_timesync_cb(void *instance, int arg, void *msg, size_t size)
{
	static u32 tsync_id;
	struct ipc_imem *this = instance;
	struct ipc_timesync *ts = msg;

	ipc_protocol_pm_dev_acquire(this->p_protocol, IPC_PM_UNIT_IRQ);

	ts->id = tsync_id++;
	ipc_cp_irq_time_sync(this->pcie, ts->id, &ts->local_time,
			&ts->local_time_unit);

	ipc_protocol_pm_dev_release(this->p_protocol, IPC_PM_UNIT_IRQ);

	this->timesync_db_trig = true;

	return 0;
}


/* Initiate time synchronization via tasklet and waits for completion.
 */
static int imem_sys_timesync(struct ipc_imem *this, struct ipc_timesync *ts)
{
	int ret;
	u32 remote_ts_id = 0;

	/* Check if modem is running */
	if (ipc_protocol_get_ap_exec_stage(this->p_protocol)
	!= IPC_MEM_EXEC_STAGE_RUN)
		return -EPERM;

	/* Post an async tasklet event to trigger Time Sync Doorbell */
	ret = ipc_tasklet_call(this->tasklet, imem_tl_timesync_cb,
		this, 0, ts, 0);

	if (ret) {
		ipc_err("Failed to post Tasklet event");
		return -1;
	}

	/* Wait for device timestamp */
	ret = ipc_protocol_wait_for_remote_ts(this->p_protocol,
			IPC_REMOTE_TS_TIMOUT_MS, &ts->remote_time,
			&remote_ts_id, &ts->remote_time_unit,
			&this->timesync_db_trig);

	switch (ret) {
	case 0:
		/* Success */
		if (remote_ts_id != ts->id) {
			ipc_err("Time ID mismatch. Expected: %u Reported: %u",
				ts->id, remote_ts_id);
			ret = -1;
			break;
		}
		/* Pass through for success */
	case EPROTONOSUPPORT:
		/* Protocols that don't support Wait for Time Sync
		 * implement other mechanisms to get target info.
		 * The Time Sync was triggered succesfully
		 */
		ret = 0;
		break;
	case -1:
		/* Failure */
		/* Pass Through */
	default:
		ipc_err("Either timeout or mismatch in device reported TS ID: %u. Device reported time: %llu",
			remote_ts_id, ts->remote_time);
	}

	return ret;
}


/* Callback function triggered by ipc_wwan: serializes the request and
 * initiate time synchronization via tasklet, waiting for completion.
 */
static int imem_timesync_cb(void *instance, struct ipc_timesync *ts)

{
	struct ipc_imem *this = instance;
	int ret = -1;

	if (!this)
		return ret;

	ipc_rtpm_get_hw(this->rtpm);

	if (ipc_imem_syscall_enter(this)) {
		ret = imem_sys_timesync(this, ts);
		ipc_imem_syscall_leave(this);
	}

	ipc_rtpm_put_hw(this->rtpm);

	return ret;
}

/* check the runtime PM is enabled or not
 */
bool ipc_imem_is_runtime_pm_enabled(struct ipc_imem *this)
{
	return this && this->rtpm && ipc_rtpm_is_enabled(this->rtpm);
}

/* Check the execution stage and update the AP phase
 */
static enum ipc_phase imem_ap_phase_update_check(struct ipc_imem *this,
		enum ipc_mem_exec_stage stage)
{
	ipc_rtpm_enable(this->rtpm, stage == IPC_MEM_EXEC_STAGE_RUN);

	/* Check whether the PARC ranges needs to be cleared for testing. */
	ipc_pcie_addr_ranges_test(this->pcie, stage,
			(stage == IPC_MEM_EXEC_STAGE_CRASH));

	switch (stage) {
	case IPC_MEM_EXEC_STAGE_BOOT:
		if (ipc_ap_phase_get(this) != IPC_P_ROM) {
			/* Send this event only once */
			ipc_imem_uevent_send(this, NL_EVENT_ROM_READY);
		}

		return ipc_ap_phase_set(this, IPC_P_ROM);

	case IPC_MEM_EXEC_STAGE_PSI:
		return ipc_ap_phase_set(this, IPC_P_PSI);

	case IPC_MEM_EXEC_STAGE_EBL:
		return ipc_ap_phase_set(this, IPC_P_EBL);

	case IPC_MEM_EXEC_STAGE_RUN:
		if (ipc_ap_phase_get(this) != IPC_P_RUN) {
			if (this->ipc_status == IPC_MEM_DEVICE_IPC_RUNNING) {
				ipc_dbg(">>>>> MODEM IS READY <<<<<");
				ipc_imem_uevent_send(this, NL_EVENT_MDM_READY);
			}
		}
		return ipc_ap_phase_set(this, IPC_P_RUN);

	case IPC_MEM_EXEC_STAGE_CRASH:
		if (ipc_ap_phase_get(this) != IPC_P_CRASH)
			ipc_imem_uevent_send(this, NL_EVENT_CRASH);
		return ipc_ap_phase_set(this, IPC_P_CRASH);

	case IPC_MEM_EXEC_STAGE_CD_READY:
		if (ipc_ap_phase_get(this) != IPC_P_CD_READY)
			ipc_imem_uevent_send(this, NL_EVENT_CD_READY);
		return ipc_ap_phase_set(this, IPC_P_CD_READY);

	default:
		/* unknown exec stage:
		 * assume that link is down and send info to listeners
		 */
		ipc_imem_uevent_send(this, NL_EVENT_CD_READY_LINK_DOWN);
		break;
	}			/* switch */

	return ipc_ap_phase_get(this);
}

/* Get the CP execution state and map it to the AP phase.
 */
static enum ipc_phase imem_ap_phase_update(struct ipc_imem *this)
{
	enum ipc_phase phase = ipc_ap_phase_get(this);

	/* If the CP stage is undefined, return the internal
	 * precalculated phase.
	 */
	if (phase == IPC_P_OFF_REQ)
		return phase;

	return imem_ap_phase_update_check(this,
		ipc_imem_get_exec_stage_buffered(this));
}				/* imem_ap_phase_update */



void ipc_imem_gpio_notification(struct ipc_imem *this,
				enum ipc_mdm_ctrl_gpio_signal signal)
{
	enum ipc_mem_exec_stage stage;

	if (unlikely(this == NULL)) {
		ipc_err("Invalid arguments");
		return;
	}

	/* Check if Modem is not turned OFF */
	if (!ipc_pcie_check_data_link_active(this->pcie))
		return;

	stage = ipc_imem_get_exec_stage(this);

	if (stage != IPC_MEM_EXEC_STAGE_RUN
	&& stage != IPC_MEM_EXEC_STAGE_PSI && stage != IPC_MEM_EXEC_STAGE_EBL
	&& stage != IPC_MEM_EXEC_STAGE_CD_READY
	&& stage != IPC_MEM_EXEC_STAGE_CRASH) {
		ipc_dbg("Modem is not in PSI/EBL/RUN %s",
				ipc_imem_get_exec_stage_string(this));
		ipc_dbg("ap mem execution stage %s",
				ipc_imem_exec_stage_to_string(this,
				ipc_imem_get_exec_stage_buffered(this)));

		this->pcie_wake_n = false;
		return;
	}

	if (this->params->in_band_crash_signal != 0) {
		ipc_dbg("In band signalling enabled");
		return;
	}

	switch (signal) {
	case IPC_MDM_CTRL_RESET_DET:
		ipc_dbg("reset detect GPIO - falling EDGE detected");
		/**
		 * RESET DETECT in falling edge when modem is in RUN stage
		 * meaning modem crashed so update AP phase to CRASH
		 */
		if (stage == IPC_MEM_EXEC_STAGE_RUN
		|| stage == IPC_MEM_EXEC_STAGE_CRASH) {
			this->reset_det_n = true;
			imem_ap_phase_update_check(this,
						IPC_MEM_EXEC_STAGE_CRASH);
		}
		break;

	case IPC_MDM_CTRL_WAKE:
		ipc_dbg("PCIe WAKE GPIO - falling EDGE detected");

		/**
		 * WAKE in falling edge when modem is in RUN stage with
		 * reset detection flag set meaning modem Coredump
		 * collection completed so update AP phase to CD_READY
		 */
		if ((stage == IPC_MEM_EXEC_STAGE_RUN
		|| stage == IPC_MEM_EXEC_STAGE_CRASH
		|| stage == IPC_MEM_EXEC_STAGE_CD_READY)
		&& this->reset_det_n == true) {
			this->pcie_wake_n = true;
			imem_ap_phase_update_check(this,
						IPC_MEM_EXEC_STAGE_CD_READY);
		} else if (stage == IPC_MEM_EXEC_STAGE_CRASH
		|| stage == IPC_MEM_EXEC_STAGE_CD_READY) {
			/**
			 * WAKE in falling edge when modem is in PSI/EBL stage
			 * with meaning modem Coredump collection completed so
			 * need to update AP phase to CRASH and then to CD_READY
			 */
			this->pcie_wake_n = true;
			imem_ap_phase_update_check(this,
						IPC_MEM_EXEC_STAGE_CRASH);
			mdelay(10);
			imem_ap_phase_update_check(this,
						IPC_MEM_EXEC_STAGE_CD_READY);
		}
		break;

	default:
		ipc_err("Unsupported notification:%d", signal);
		break;
	}

}


/* Change the operation phase.
 */
static enum ipc_phase ipc_ap_phase_set(struct ipc_imem *this,
		enum ipc_phase phase)
{
	return this->phase = phase;
}

/* Get the operation phase.
 */
static enum ipc_phase ipc_ap_phase_get(struct ipc_imem *this)
{
	return this->phase;
}

/* Return the current operation phase as string.
 */
static const char *ipc_ap_phase_get_string(enum ipc_phase phase)
{
	switch (phase) {
	case IPC_P_RUN:
		return "A-RUN";

	case IPC_P_OFF:
		return "A-OFF";

	case IPC_P_ROM:
		return "A-ROM";

	case IPC_P_PSI:
		return "A-PSI";

	case IPC_P_EBL:
		return "A-EBL";

	case IPC_P_CRASH:
		return "A-CRASH";

	case IPC_P_CD_READY:
		return "A-CD_READY";

	case IPC_P_OFF_REQ:
		return "A-OFF_REQ";

	default:
		return "A-???";
	}
}

/* Send msg to device to open pipe
 */
static bool imem_pipe_open(struct ipc_imem *this, struct ipc_pipe *pipe)
{
	union ipc_msg_prep_args prep_args = {
			.pipe_open.pipe = pipe
		};

	if (ipc_protocol_msg_send(this->p_protocol, IPC_MSG_PREP_PIPE_OPEN,
		&prep_args) == IPC_OK)
		pipe->is_open = true;

	return pipe->is_open;
}

/* Send msg to device to close pipe
 */
static void imem_pipe_close(struct ipc_imem *this, struct ipc_pipe *pipe)
{
	union ipc_msg_prep_args prep_args = {
			.pipe_close.pipe = pipe
		};

	pipe->is_open = false;
	ipc_protocol_msg_send(this->p_protocol, IPC_MSG_PREP_PIPE_CLOSE,
			&prep_args);

	imem_pipe_cleanup(this, pipe);
}

/* Wait until there is no channel access.
 */
static void imem_channel_busy_wait(struct ipc_mem_channel *channel)
{
	struct ipc_pipe *ul_pipe, *dl_pipe;

	ul_pipe = &channel->ul_pipe;
	dl_pipe = &channel->dl_pipe;

	ul_pipe->locked = 1;
	dl_pipe->locked = 1;

	while (ul_pipe->is_busy || dl_pipe->is_busy)
		msleep(20);
}				/* imem_channel_busy_wait */

/* Lock the channel to avoid invalid UL/DL buffer access
 */
static void imem_channel_lock(struct ipc_mem_channel *channel)
{
	channel->ul_pipe.locked = 1;
	channel->dl_pipe.locked = 1;

	channel->ul_pipe.is_busy = 0;
	channel->dl_pipe.is_busy = 0;
}				/* imem_channel_lock */

/* Allows UL/DL transfer.
 */
static void imem_channel_unlock(struct ipc_mem_channel *channel)
{
	channel->ul_pipe.locked = 0;
	channel->dl_pipe.locked = 0;
}				/* imem_channel_unlock */

/* Release the channel resources.
 */
static void imem_channel_close(struct ipc_imem *this, int channel_id)
{
	struct ipc_mem_channel *channel;

	/* Test the channel id.
	 */
	if (channel_id < 0 || channel_id >= this->nr_of_channels) {
		ipc_err("invalid channel id %d", channel_id);
		return;
	}

	/* Get the reference of the channel definition.
	 */
	channel = &this->channels[channel_id];

	/* Test the channel state.
	 */
	if (channel->state == IMEM_CHANNEL_FREE) {
		ipc_err("ch[%d]: invalid channel state %d",
			channel_id, channel->state);
		return;
	}

	/* Free only the channel id in the CP power off mode.
	 */
	if (channel->state == IMEM_CHANNEL_RESERVED) {
		/* Release only the channel id.
		 */
		imem_channel_free(channel);
		return;
	}

	if (ipc_ap_phase_get(this) == IPC_P_RUN) {

		/* Wait until there is no channel access.
		 */
		imem_channel_busy_wait(channel);

		/* Release the pipe resources.
		 */
		imem_pipe_close(this, &channel->ul_pipe);
		imem_pipe_close(this, &channel->dl_pipe);
	}

	imem_pipe_cleanup(this, &channel->ul_pipe);
	imem_pipe_cleanup(this, &channel->dl_pipe);


	/* Release the channel id.
	 */
	imem_channel_free(channel);
}				/* imem_channel_close */

/* Release a net link to CP.
 */
static void imem_sys_wwan_stop(struct ipc_imem *this, int vlan_id,
		int channel_id)
{

	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	ipc_dbg("%s[vlan id:%d]",
			ipc_ap_phase_get_string(this->phase), vlan_id);

	if (vlan_id > 0 && vlan_id <= IPC_IMEM_MUX_SESSION_ENTRIES) {
		union imem_mux_msg mux_msg;
		struct mux_session_close *session_close_p;

		session_close_p = &mux_msg.session_close;
		session_close_p->event = MUX_E_MUX_SESSION_CLOSE;
		/* interface id needs to be one less than actual vlan tag
		 * to start MUX session from 0 as vlan tag would start from 1
		 * so map it to if_id = vlan_id - 1
		 */
		session_close_p->if_id = vlan_id - 1;
		mux_schedule(this, &this->mux, &mux_msg);
		this->mux.session[vlan_id - 1].flags &= ~IPC_MEM_WWAN_MUX;
		return;
	/* Control channels and Low latency  data channel for VoLTE*/
	} else if ((vlan_id > 256 && vlan_id < 768)) {
		/* Release the channel resources.
		 */
		imem_channel_close(this, channel_id);
		return;
	}				/* imem_sys_wwan_stop */
}
/* Establish the pipes.
 */
static bool imem_channel_open(struct ipc_imem *this, int channel_id, u32 db_id)
{
	struct ipc_mem_channel *channel;
	bool processed = false;
	int i;

	if (unlikely(channel_id < 0 || channel_id >= IPC_MEM_MAX_CHANNELS))
		return false;

	channel = &this->channels[channel_id];

	/* Lock the channel to avoid invalid UL/DL buffer access
	 */
	imem_channel_lock(channel);

	channel->state = IMEM_CHANNEL_ACTIVE;

	if (!imem_pipe_open(this, &channel->ul_pipe)) {
		imem_channel_free(channel);
		return false;
	}

	if (!imem_pipe_open(this, &channel->dl_pipe)) {
		imem_pipe_close(this, &channel->ul_pipe);
		imem_channel_free(channel);
		return false;
	}

	/* Allocate the downlink buffers and inform CP.
	 */
	for (i = 0; i < channel->dl_pipe.nr_of_entries - 1; i++)
		processed |= imem_dl_skb_alloc(this, &channel->dl_pipe);

	/* Allows UL/DL transfer.
	 */
	imem_channel_unlock(channel);

	/* Trigger the doorbell irq to inform CP that new downlink buffers are
	 * available.
	 */
	if (processed)
		ipc_protocol_doorbell_trigger(this->p_protocol, db_id);

	return true;		/* Active channel. */
}

/* Open a packet data online channel between the network layer and CP.
 */
static int imem_sys_wwan_open(struct ipc_imem *this, int vlan_id)
{
	enum ipc_phase phase;

	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return -1;
	}

	ipc_dbg("%s[vlan id:%d]",
			ipc_ap_phase_get_string(this->phase), vlan_id);

	/* Update the current operation phase.
	 */
	phase = imem_ap_phase_update(this);

	/* The network interface is only supported in the runtime phase.
	 */
	if (phase != IPC_P_RUN) {
		ipc_dbg("[net:%d]: refused phase %s",
			vlan_id, ipc_ap_phase_get_string(this->phase));
		return -1;
	}

	/* check for the vlan tag
	 * if tag 257 to 511 then create dss channel
	 * if tag 1 to 256 then create IP MUX channel sessions
	 */
	if (vlan_id > 0 && vlan_id <= IPC_IMEM_MUX_SESSION_ENTRIES) {
		union imem_mux_msg mux_msg;
		struct mux_session_open *session_open_p;

		session_open_p = &mux_msg.session_open;
		session_open_p->event = MUX_E_MUX_SESSION_OPEN;
		/* interface id needs to be one less than actual vlan tag
		 * to start MUX session from 0 as vlan tag would start from 1
		 * so map it to if_id = vlan_id - 1
		 */
		session_open_p->if_id = vlan_id - 1;
		this->mux.session[vlan_id - 1].flags |= IPC_MEM_WWAN_MUX;
		return mux_schedule(this, &this->mux, &mux_msg);
	/* Control channels and Low latency  data channel for VoLTE*/
	} else if (vlan_id > 256 && vlan_id < 768) {
		int ch_id = imem_channel_alloc(this, vlan_id, IPC_CTYPE_WWAN);

		if (imem_channel_open(this, ch_id, IPC_HP_NET_CHANNEL_INIT))
			return ch_id;
	}

	return -1;
}				/* imem_sys_wwan_open */

/* Release a sio link to CP.
 */
static void imem_sys_sio_close(struct ipc_imem *this, int channel_id)
{
	struct ipc_mem_channel *channel;
	int status = 0;
	u32 tail = 0;
	enum ipc_phase curr_phase;
	int boot_check_timeout;

	if (unlikely(!this || !this->params)) {
		ipc_err("invalid arguments");
		return;
	}

	/* Test the channel id.
	 */
	if (channel_id < 0 || channel_id >= this->nr_of_channels) {
		ipc_err("invalid channel id %d", channel_id);
		return;
	}

	boot_check_timeout = this->params->boot_check_timeout;

	/* Get the reference of the channel definition.
	 */
	channel = &this->channels[channel_id];

	curr_phase = ipc_ap_phase_get(this);

	/* If current phase is IPC_P_OFF or SIO ID is -ve then
	 * channel is already freed. Nothing to do.
	 */
	if (curr_phase == IPC_P_OFF || channel->sio_id < 0) {
		ipc_err("Nothing to do. Current Phase: %s SIO ID: %d",
			ipc_ap_phase_get_string(curr_phase),
			channel->sio_id);
		return;
	}

	ipc_dbg("%s[sio:%d]",
			ipc_ap_phase_get_string(curr_phase), channel->sio_id);

	/* Test the channel state.
	 */
	if (channel->state == IMEM_CHANNEL_FREE) {
		ipc_err("ch[%d]: invalid channel state %d",
			channel_id, channel->state);
		return;
	}

	/* Free only the channel id in the CP power off mode.
	 */
	if (channel->state == IMEM_CHANNEL_RESERVED) {
		/* Release only the channel id.
		 */
		imem_channel_free(channel);
		return;
	}

	/* In case of flashless: delay the close until modem is RUNNING */
	if (this->flash_channel_id >= 0) {
		int i;
		enum ipc_mem_exec_stage exec_stage;

		/* Increase the total wait time to boot_check_timeout
		 * which can be set from debugfs for debugging.
		 */
		for (i = 0; i < boot_check_timeout; i++) {
			/*
			 * user space can terminate either the modem is
			 * finished with Downloading or finished
			 * transferring Coredump.
			 */
			exec_stage = ipc_imem_get_exec_stage(this);
			if (exec_stage == IPC_MEM_EXEC_STAGE_RUN
			|| exec_stage == IPC_MEM_EXEC_STAGE_PSI) {
				break;
			}

			msleep(20);
		}

		/* The delay of 100ms here is the workaround for the Kernel
		 * Panic while processing the Message Completion status. The
		 * fix for root cause will be provided as a part of
		 * SMS13312748.
		 */
		msleep(100);
	}

	/* If there are any pending TDs then wait for Timeout/Completion before
	 * closing pipe.
	 */
	if (channel->ul_pipe.old_tail != channel->ul_pipe.old_head) {
		this->app_notify_ul_pend = 1;

		/* Suspend the user app and wait a certain time for processing
		 * UL Data.
		 */
		status = ipc_completion_wait_interruptible_timeout_ms
		    (&this->ul_pend_sem, IPC_PEND_DATA_TIMEOUT);

		if (status == 0) {
			ipc_dbg("On UL-Pipe:%d Head:%d Tail:%d",
				 channel->ul_pipe.pipe_nr,
				 channel->ul_pipe.old_head,
				 channel->ul_pipe.old_tail);
			ipc_dbg("Pending data Timeout on UL Pipe:%d!",
				 channel->ul_pipe.pipe_nr);
		}

		this->app_notify_ul_pend = 0;
	}

	/* If there are any pending TDs then wait for Timeout/Completion before
	 * closing pipe.
	 */
	ipc_protocol_get_head_tail_index(this->p_protocol, &channel->dl_pipe,
				NULL, &tail);

	if (tail != channel->dl_pipe.old_tail) {
		this->app_notify_dl_pend = 1;

		/* Suspend the user app and wait a certain time for processing
		 * DL Data.
		 */
		status = ipc_completion_wait_interruptible_timeout_ms
		    (&this->dl_pend_sem, IPC_PEND_DATA_TIMEOUT);

		if (status == 0) {
			ipc_dbg("On DL-Pipe:%d Head:%d Tail:%d",
				 channel->dl_pipe.pipe_nr,
				 channel->dl_pipe.old_head,
				 channel->dl_pipe.old_tail);
			ipc_dbg("Pending data Timeout on DL Pipe:%d!",
				 channel->dl_pipe.pipe_nr);
		}

		this->app_notify_dl_pend = 0;
	}

	/* Lock the channel to avoid invalid UL/DL buffer.
	 */
	imem_channel_busy_wait(channel);

	/* Due to wait for completion in messages, there is a small window
	 * between closing the pipe and updating the channel is closed. In this
	 * small window there could be HP update from Host Driver. Hence update
	 * the channel state as CLOSING to aviod unnecessary interrupt
	 * towards CP.
	 */
	channel->state = IMEM_CHANNEL_CLOSING;

	/* Release the pipe resources
	 */
	if (this->flash_channel_id != -1) {
		/* don't send close for software download pipes, as
		 * the device is already rebooting
		 */
		imem_pipe_cleanup(this, &channel->ul_pipe);
		imem_pipe_cleanup(this, &channel->dl_pipe);
	} else {
		imem_pipe_close(this, &channel->ul_pipe);
		imem_pipe_close(this, &channel->dl_pipe);
	}

	/* Release the channel id.
	 */
	imem_channel_free(channel);

	/* Reset the global flash channel id.
	 */
	this->flash_channel_id = -1;
}				/* imem_sys_sio_close */

/* Open a sio link to CP and return the channel id.
 */
static int imem_sys_sio_open(struct ipc_imem *this)
{
	int channel_id;
	enum ipc_phase phase;
	struct ipc_chnl_cfg chnl_cfg = { 0 };

	if (unlikely(!this)) {
		ipc_err("invalid args");
		return -1;
	}

	phase = imem_ap_phase_update(this);

	/* The control link to CP is only supported in the power off, psi or
	 * run phase.
	 */
	switch (phase) {
	case IPC_P_OFF:
	case IPC_P_ROM:
		/* Get a channel id as flash id and reserve it.
		 */
		channel_id = imem_channel_alloc(this, IPC_CHANNEL_INDEX_FLASH,
			IPC_CTYPE_FLASH);
		if (channel_id < 0) {
			ipc_err("reservation of a flash id failed");
			return -1;
		}

		/* Enqueue chip info data to be read
		 */
		if (unlikely(imem_trigger_chip_info(this))) {
			ipc_err("failed to provide chip info");
			imem_channel_close(this, channel_id);
			return -1;
		}

		/* Save the flash channel id to execute the ROM interworking.
		 */
		this->flash_channel_id = channel_id;

		return channel_id;

	case IPC_P_PSI:
	case IPC_P_EBL:
		/* The channel id used as flash id shall be already
		 * present as reserved.
		 */
		if (this->flash_channel_id < 0) {
			ipc_err("missing a valid flash channel id");
			return -1;
		}
		channel_id = this->flash_channel_id;

		this->cp_version = ipc_mmio_get_cp_version(this->mmio);

		ipc_dbg("CP version: 0x%04x", this->cp_version);

		/* PSI may have changed the CP version field, which may
		 * result in a different channel configuration.
		 *
		 * Fetch and update the flash channel config
		 */
		if (ipc_chnl_cfg_get(&chnl_cfg, channel_id, this->pci_device_id,
			this->cp_version, MUX_UNKNOWN,
			this->dbg, this->params)) {
			ipc_err("Failed to get flash pipe configuration");
			return -1;
		}

		ipc_imem_channel_update(this, channel_id,
			chnl_cfg.ul_nr_of_entries, chnl_cfg.dl_nr_of_entries,
			chnl_cfg.dl_buf_size, chnl_cfg.ul_pipe,
			chnl_cfg.dl_pipe, IRQ_MOD_OFF,
			chnl_cfg.accumulation_backoff);

		if (!imem_channel_open(this, channel_id, IPC_HP_SIO_OPEN))
			return -1;

		return channel_id;

	default:
		/* CP is in the wrong state (e.g. CRASH or CD_READY) */
		ipc_err("refused phase %d", phase);
		return -1;
	}			/* phase */
}				/* imem_sys_sio_open */

/* Enter critical section for system calls.
 * Returns true if call can proceed, false when the call shall be aborted
 * e.g. during driver shutdown.
 */
static bool ipc_imem_syscall_enter(struct ipc_imem *this)
{
	return ipc_completion_wait_interruptible(&this->msg_sender_suspend)
		== 0;
}

/* Leave Critical section for system calls.
 */
static void ipc_imem_syscall_leave(struct ipc_imem *this)
{
	ipc_completion_signal(&this->msg_sender_suspend);
}

/* The HAL shall ask the shared memory layer whether D3 is allowed.
 */
int ipc_imem_pm_suspend(struct ipc_imem *this)
{
	int rc;

	if (!ipc_imem_syscall_enter(this))
		return -1;

	rc = ipc_protocol_suspend(this->p_protocol) ? 0 : -1;

	ipc_imem_syscall_leave(this);

	return rc;
}

/* The HAL shall inform the shared memory layer that the device is
 * active.
 */
void ipc_imem_pm_resume(struct ipc_imem *this)
{
	if (!ipc_imem_syscall_enter(this))
		return;

	if (ipc_protocol_resume(this->p_protocol)) {

		if (this->params->block_td_pipe_mask)
			this->params->host_wakeup_cnt++;

		/* check in execution stage if CP crashed
		 */
		imem_ap_phase_update_check(this, ipc_imem_get_exec_stage(this));
	}

	ipc_imem_syscall_leave(this);
}

/* Open a sio link to CP and return the channel id.
 */
static int imem_sio_open(void *instance)
{
	struct ipc_imem *this = instance;
	int rc = -1;

	if (!this)
		return -1;

	ipc_rtpm_get_hw(this->rtpm);

	if (ipc_imem_syscall_enter(this)) {
		rc = imem_sys_sio_open(this);
		ipc_imem_syscall_leave(this);
	}

	ipc_rtpm_put_hw(this->rtpm);

	return rc;
}

/* Release a sio link to CP.
 */
static void imem_sio_close(void *instance, int channel_id)
{
	struct ipc_imem *this = instance;

	if (!this)
		return;

	ipc_rtpm_get_hw(this->rtpm);

	if (ipc_imem_syscall_enter(this)) {
		imem_sys_sio_close(this, channel_id);
		ipc_imem_syscall_leave(this);
	}

	ipc_rtpm_put_hw(this->rtpm);
}

#ifndef IPC_EXTERNAL_BUILD
/* Send prepare memory map msg to CP.
 */
static int imem_send_map_msg(void *instance, unsigned int region_id,
	size_t size, unsigned long addr)
{
	struct ipc_imem *this = instance;
	union ipc_msg_prep_args prep_args = {
			.map.region_id = region_id, .map.addr = addr,
			.map.size = size };

	if (!this)
		return -1;


	return ipc_protocol_msg_send(this->p_protocol, IPC_MSG_PREP_MAP,
			&prep_args);
}

/* Send prepare memory unmap msg to CP.
 */
static int imem_send_unmap_msg(void *instance, unsigned int region_id)
{
	struct ipc_imem *this = instance;
	union ipc_msg_prep_args prep_args = {
			.unmap.region_id = region_id
		};

	if (!this)
		return -1;

	ipc_dbg("region_id=%d", region_id);

	return ipc_protocol_msg_send(this->p_protocol, IPC_MSG_PREP_UNMAP,
		&prep_args);
}
#endif

/* Save the complete PSI image in a specific imem region, prepare the doorbell
 * scratchpad and inform* the ROM driver. The flash app is suspended until the
 * CP has processed the information. After the start of the PSI image, CP shall
 * set the execution state to PSI and generate the irq, then the flash app
 * is resumed or timeout.
 */
static int imem_psi_transfer(struct ipc_imem *this,
	struct ipc_mem_channel *channel, const unsigned char *buf, int count)
{
	void *dest_buf = NULL;
	int status, result;
	u64 mapping = 0;
	int psi_start_timeout = this->params->psi_start_timeout;
	enum ipc_mem_exec_stage exec_stage = IPC_MEM_EXEC_STAGE_INVALID;

	/* stop a running startup timer */
	ipc_hrtimer_config(this->startup_timer, 0);

	/* Allocate the buffer for the PSI image.
	 */
	dest_buf = ipc_pcie_kzalloc(this->pcie, count, &mapping);
	if (!dest_buf) {
		ipc_err("ch[%d] cannot allocate %d bytes",
			channel->channel_id, count);
		goto return_err_l;
	}

	/* Copy the PSI image from user to kernel space.
	 */
	if (copy_from_user(dest_buf, buf, count) != 0) {
		ipc_err("ch[%d] userspace --> kernel copy failed",
			channel->channel_id);
		goto return_err_l;
	}

	/* Save the PSI information for the CP ROM driver on the doorbell
	 * scratchpad.
	 */

	ipc_mmio_set_psi_addr_and_size(this->mmio, mapping, count);

	/* ipc_pcie_addr_ranges_test() is 0xFEEDB007 then clear
	 * the address ranges so that can be tested in Boot ROM phase.
	 */
	ipc_pcie_addr_ranges_test(this->pcie, IPC_MEM_EXEC_STAGE_BOOT, false);

	/* Trigger the CP interrupt to process the PSI information.
	 */
	ipc_cp_irq_rom(this->pcie, ipc_mmio_is_v2_exec_stage(this->mmio) ?
		IPC_MEM_EXEC_STAGE_V2_SECONDARY_BOOT : IPC_MEM_EXEC_STAGE_BOOT);

	/* Suspend the flash app and wait for irq.
	 */
	status = ipc_completion_wait_interruptible_timeout_ms(&channel->ul_sem,
		IPC_PSI_TRANSFER_TIMEOUT);
	if (status <= 0) {
		ipc_err("ch[%d] timeout, failed PSI transfer to CP",
			channel->channel_id);
		ipc_imem_report_timeout(this);
		goto return_err_l;
	}

	/* CP should have copied the PSI image.
	 */
	ipc_pcie_kfree(this->pcie, dest_buf, count, mapping);

	/* If the PSI download fails, return the CP boot ROM exit code to the
	 * flash app received about the doorbell scratchpad.
	 */
	if (this->rom_exit_code != IMEM_ROM_EXIT_OPEN_EXT &&
	    this->rom_exit_code != IMEM_ROM_EXIT_CERT_EXT)
		return (-1) * ((int)this->rom_exit_code);

	ipc_dbg("PSI image successfully downloaded");

	/* Wait psi_start_timeout milliseconds until the CP PSI image is
	 * running and updates the execution_stage field with
	 * IPC_MEM_EXEC_STAGE_PSI. Verify the execution stage.
	 */
	while (psi_start_timeout > 0) {
		exec_stage = ipc_imem_get_exec_stage(this);

		if (exec_stage == IPC_MEM_EXEC_STAGE_PSI)
			break;

		msleep(20);
		psi_start_timeout -= 20;
	}

	if (exec_stage != IPC_MEM_EXEC_STAGE_PSI)
		return -1;	/* Unknown status of the CP PSI process. */

	/* Enter the PSI phase.
	 */
	ipc_dbg("execution_stage[%X] eq. PSI", exec_stage);

	ipc_ap_phase_set(this, IPC_P_PSI);

	/* Request the RUNNING state from CP and wait until it was reached
	 * or timeout.
	 */
	imem_ipc_init_check(this);

	/* Suspend the flash app, wait for irq
	 * and evaluate the CP IPC state.
	 */
	status = ipc_completion_wait_interruptible_timeout_ms(&channel->ul_sem,
		IPC_PSI_TRANSFER_TIMEOUT);
	if (status <= 0) {
		ipc_err("ch[%d] timeout, failed PSI RUNNING state on CP",
			channel->channel_id);
		ipc_imem_report_timeout(this);
		return -1;
	}

	/* Test the CP IPC state.
	 */
	if (unlikely(ipc_mmio_get_ipc_state(this->mmio) !=
		IPC_MEM_DEVICE_IPC_RUNNING)) {
		ipc_err("ch[%d] %s: unexpected CP IPC state %d, not RUNNING",
			channel->channel_id,
			ipc_ap_phase_get_string(this->phase),
			ipc_mmio_get_ipc_state(this->mmio));

		return -1;
	}

	/* Create the flash channel for the transfer of the images.
	 */
	result = imem_sio_open(this);
	if (result < 0) {
		ipc_err("can't open flash_channel");
		return -1;
	}

	/* Inform the flash app that the PSI was sent and start on CP.
	 */

	/* The flash app shall wait for the CP status in blocking read
	 * entry point.
	 */
	return count;

 return_err_l:
	if (dest_buf)
		ipc_pcie_kfree(this->pcie, dest_buf, count, mapping);

	return -1;

}				/* imem_psi_transfer */

/* Test the entry condtion for the char write entry point and return NULL or the
 * channel pointer, if elements for the uplink skbuf list shall be generated.
 */
static struct ipc_mem_channel *imem_sio_write_channel(
		struct ipc_imem *this, int ch, char *buf,
		int size)
{
	struct ipc_mem_channel *channel;
	enum ipc_phase phase;

	/* Test the channel id.
	 */
	if (ch < 0 || ch >= this->nr_of_channels) {
		ipc_err("invalid channel id %d", ch);
		return NULL;
	}

	/* Ignore invalid arguments.
	 */
	if (size <= 0 || !buf) {
		ipc_err("ch[%d]: invalid arguments", ch);
		return NULL;
	}

	/* Get the reference of the channel definition.
	 */
	channel = &this->channels[ch];

	/* Test the channel state.
	 */
	if (channel->state == IMEM_CHANNEL_FREE) {
		ipc_err("ch[%d]: invalid channel state %d", ch, channel->state);
		return NULL;
	}

	/* Update the current operation phase.
	 */
	phase = ipc_ap_phase_get(this);

	/* Select the operation depending on the execution stage.
	 */
	switch (phase) {
	case IPC_P_RUN:
	case IPC_P_PSI:
	case IPC_P_EBL:
		break;

	case IPC_P_ROM:
		/* Prepare the PSI image for the CP ROM driver and
		 * suspend the flash app.
		 */
		if (channel->state != IMEM_CHANNEL_RESERVED) {
			ipc_err
			    ("ch[%d]: invalid channel state %d, expected %d",
			     ch, channel->state, IMEM_CHANNEL_RESERVED);
			return NULL;
		}
		return channel;

	default:
		/* XXX Ignore uplink actions in all other phases.
		 */
		ipc_err("ch[%d]: confused phase %d", ch, phase);
		return NULL;

	}			/* switch */

	/* Test the fully availability of the channel.
	 */
	if (channel->state != IMEM_CHANNEL_ACTIVE) {
		ipc_err("ch[%d]: confused channel state %d",
			ch, channel->state);
		return NULL;
	}

	return channel;
}				/* imem_sio_write_channel */

/* Allocates the skb using non-atomic and copies the data from user space
 * if allocation was successful.
 */
struct sk_buff *imem_sio_copy_from_user_to_skb(
		struct ipc_imem *this, int channel_id,
		const unsigned char *buf, int size, int is_blocking)
{
	struct sk_buff *skb = NULL;
	struct ipc_skb_cb *skb_cb;
	u64 mapping;

	/* Allocate skb memory for the uplink buffer.
	 */
	skb = ipc_pcie_alloc_ul_skb_nonatomic(this->pcie, size, &mapping);
	if (unlikely(!skb)) {
		ipc_err("ch[%d]: skbuf allocation failed", channel_id);
		goto error;
	}

	/* Copy the characters from user to kernel space.
	 */
	if (copy_from_user(skb_put(skb, size), buf, size) != 0) {
		ipc_err("ch[%d]: userspace --> kernel copy failed", channel_id);
		goto error;
	}

	skb_cb = (struct ipc_skb_cb *)skb->cb;

	skb_cb->op_type = (u8)(is_blocking ? UL_USR_OP_BLOCKED : UL_DEFAULT);

	return skb;

error:
	ipc_pcie_kfree_skb(this->pcie, skb);

	return NULL;
}				/* imem_sio_copy_from_user_to_skb */

/* Through tasklet to do sio write.
 */
static bool imem_call_sio_write(struct ipc_imem *this)
{
	if (this->ev_sio_write_pending)
		return false;

	this->ev_sio_write_pending = true;

	(void) ipc_tasklet_call_async(this->tasklet, imem_tl_sio_write,
		this, 0, NULL, 0);

	return true;
}

/* Further fucntion to route the uplink buffer to CP about the tasklet
 */
static int imem_sio_write_sub(struct ipc_imem *this, int channel_id,
		const unsigned char *buf, int count, int blocking_write)
{
	struct ipc_mem_channel *channel = imem_sio_write_channel(this,
		channel_id, (char *)buf, count);

	if (!channel || ipc_ap_phase_get(this) == IPC_P_OFF_REQ)
		return -1;

	/* In the ROM phase the PSI image is passed to CP about a specific
	 * shared memory area and doorbell scratchpad directly.
	 */
	if (ipc_ap_phase_get(this) == IPC_P_ROM) {
		int ret = imem_psi_transfer(this, channel, buf, count);

		/* If the PSI transfer is successful then send Feature
		 * Set message
		 */
		if (ret > 0)
			imem_msg_send_feature_set(this, 0, false);

		return ret;
	}

#ifdef IPC_SIO_UL_REQ_SPLIT
	if (count > IMC_IPC_SIO_MAX_UL_SIZE) {
		int i;
		int residue = 0;
		int loop_cnt;
		int block = 0;

		loop_cnt = count/IMC_IPC_SIO_MAX_UL_SIZE;
		residue = count % IMC_IPC_SIO_MAX_UL_SIZE;

		for (i = 0; i < loop_cnt; i++) {
			struct sk_buff *skb;

			if (blocking_write && (i == loop_cnt - 1) && !residue)
				block = blocking_write;

			/* Allocate skb memory for the uplink buffer.
			 */
			skb = imem_sio_copy_from_user_to_skb(this,
					channel_id, buf,
					IMC_IPC_SIO_MAX_UL_SIZE,
					block);
			if (!skb)
				return 0;

			/* Add skb to the uplink skbuf accumulator.
			 */
			imem_ul_list_add(&channel->ul_list, skb);

			buf += IMC_IPC_SIO_MAX_UL_SIZE;

		}

		if (residue) {
			/* Allocate skb memory for the uplink buffer.
			 */
			struct sk_buff *skb = imem_sio_copy_from_user_to_skb(
				this, channel_id, buf, residue, blocking_write);
			if (!skb)
				return 0;

			/* Add skb to the uplink skbuf accumulator.
			 */
			imem_ul_list_add(&channel->ul_list, skb);
		}
	} else
#endif		/* IPC_SIO_UL_REQ_SPLIT */
	{
		/* Allocate skb memory for the uplink buffer.
		 */
		struct sk_buff *skb = imem_sio_copy_from_user_to_skb(this,
			channel_id, buf, count, blocking_write);
		if (!skb)
			return 0;

		/* Add skb to the uplink skbuf accumulator.
		 */
		imem_ul_list_add(&channel->ul_list, skb);
	}

	/* Inform the IPC tasklet to pass uplink IP packets to CP.
	 * Blocking write waits for UL completion notification,
	 * non-blocking write simply returns the count.
	 */
	if (imem_call_sio_write(this) && blocking_write) {
		/* Suspend the app and wait for UL data completion.
		 */
		int status = ipc_completion_wait_interruptible(
			&channel->ul_sem);

		if (status < 0) {
			ipc_err("ch[%d] no CP confirmation, status=%d",
				channel->channel_id, status);
			return -1;
		}
	}

	return count;
}				/* imem_sio_write */

/* Route the uplink buffer to CP about the tasklet.
 */
static int imem_sio_write(void *instance, int channel_id,
		const unsigned char *buf, int count, bool blocking_write)
{
	struct ipc_imem *this = instance;
	int status;

	if (unlikely(!this || !buf)) {
		ipc_err("invalid arguments");
		return -1;
	}

	ipc_rtpm_get_hw(this->rtpm);

	status = imem_sio_write_sub(this, channel_id, buf, count,
		blocking_write);

	ipc_rtpm_put_hw(this->rtpm);

	return status;
}


/* Inform the char that the chip information are available if the
 * flashing to RAM interworking shall be executed.
 */
static int imem_trigger_chip_info(struct ipc_imem *this)
{
	return ipc_tasklet_call(this->tasklet, imem_tl_trigger_chip_info_cb,
		this, 0, NULL, 0);
}

/* append a skb to the ul list of a specific channel
 */
static void imem_ul_list_init(struct imem_ul_queue *ul_list)
{
	skb_queue_head_init(&ul_list->list);
	ul_list->nr_of_bytes = 0;
}				/* imem_ul_list_init */

/* append a skb to the ul list of a specific channel
 */
static void imem_ul_list_add(struct imem_ul_queue *ul_list, struct sk_buff *skb)
{
	unsigned long flags;

	spin_lock_irqsave(&ul_list->list.lock, flags);
	__skb_queue_tail(&ul_list->list, skb);
	ul_list->nr_of_bytes += skb->len;
	spin_unlock_irqrestore(&ul_list->list.lock, flags);
}				/* imem_ul_list_add */


/*
 * Refer to header file for description
 */
struct sk_buff *imem_ul_list_dequeue(struct imem_ul_queue *ul_list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&ul_list->list.lock, flags);
	result = __skb_dequeue(&ul_list->list);

	if (result)
		ul_list->nr_of_bytes -= result->len;
	spin_unlock_irqrestore(&ul_list->list.lock, flags);

	return result;
}				/* imem_ul_list_dequeue */

/* Free an IPC channel.
 */
static int imem_channel_free(struct ipc_mem_channel *channel)
{
	/* Reset dynamic channel elements.
	 */
	channel->sio_id = -1;
	channel->state = IMEM_CHANNEL_FREE;

	return 0;
}				/* imem_channel_free */

/* Allocate a channel.
 */
static int imem_channel_alloc(struct ipc_imem *this, int index,
		enum ipc_ctype ctype)
{
	int i;
	struct ipc_mem_channel *channel;

	/* Find channel of given type/index */
	for (i = 0; i < this->nr_of_channels; i++) {
		channel = &this->channels[i];
		if (channel->ctype == ctype && channel->index == index)
			break;
	}

	/* channel was not found */
	if (i >= this->nr_of_channels) {
		ipc_dbg("no channel definition for index=%d ctype=%d",
			index, ctype);
		return -1;
	}

	/* The ctype & index was found. Check if channel is free.
	 */
	if (this->channels[i].state != IMEM_CHANNEL_FREE) {
		ipc_dbg("channel is in use");
		return -1;
	}

	/* Initialize the reserved channel element.
	 */
	channel->sio_id = index;
	/* set vlan id here only for dss channels */
	if (channel->ctype == IPC_CTYPE_WWAN && index > 256 && index < 768)
		channel->vlan_id = index;
	else if (channel->ctype == IPC_CTYPE_WWAN && index == -1)
		channel->vlan_id = -1; /* set -1 for the MUX vlan id */

	channel->state = IMEM_CHANNEL_RESERVED;

	return i;
}				/* imem_channel_alloc */

/* Initialize the channel list with UL/DL pipe pairs.
 */
static void imem_channel_init(
		struct ipc_imem *this,
		enum ipc_ctype ctype,
		int id,
		u32 ul_nr_of_entries,
		u32 dl_nr_of_entries,
		u32 dl_buf_size,
		u32 ul_pipe,
		u32 dl_pipe,
		u32 irq_moderation,
		u32 accumulation_backoff)
{
	struct ipc_mem_channel *channel;

	if (ul_pipe >= IPC_MEM_MAX_PIPES || dl_pipe >= IPC_MEM_MAX_PIPES) {
		ipc_err("invalid or pipe: (ul_pipe=%d, dl_pipe=%d)",
			ul_pipe, dl_pipe);
		return;
	}

	if (this->nr_of_channels + 1 >= IPC_MEM_MAX_CHANNELS) {
		ipc_err("too many channels");
		return;
	}

	/* Initialize a channel elements.
	 */
	channel = &this->channels[this->nr_of_channels];
	channel->channel_id = this->nr_of_channels;
	channel->ctype = ctype;
	channel->index = id;
	channel->sio_id = -1;
	channel->net_err_count = 0;
	channel->state = IMEM_CHANNEL_FREE;

	this->nr_of_channels++;

	ipc_imem_channel_update(this, channel->channel_id,
		ul_nr_of_entries, dl_nr_of_entries,
		dl_buf_size, ul_pipe, dl_pipe, irq_moderation,
		accumulation_backoff);

	/* Initialize the uplink skb accumulator.
	 */
	imem_ul_list_init(&channel->ul_list);

	/* Initialize the semaphore for the blocking write or uplink transfer.
	 */
	ipc_completion_init(&channel->ul_sem);
}				/* imem_channel_init */

/*
 * Set or modify pipe config of an existing channel
 */
static void ipc_imem_channel_update(struct ipc_imem *this,
	int id, u32 ul_nr_of_entries, u32 dl_nr_of_entries, u32 dl_buf_size,
	u32 ul_pipe, u32 dl_pipe, u32 irq_moderation, u32 accumulation_backoff)
{
	struct ipc_mem_channel *channel;

	if (unlikely(id < 0 || id >= this->nr_of_channels)) {
		ipc_err("invalid id %d", id);
		return;
	}

	channel = &this->channels[id];

	/* Only allow channel modification when channel is not in use */
	if (unlikely(channel->state != IMEM_CHANNEL_FREE &&
		channel->state != IMEM_CHANNEL_RESERVED)) {
		ipc_err("invalid channel state %d", channel->state);
		return;
	}

	channel->ul_pipe.nr_of_entries = ul_nr_of_entries;
	channel->ul_pipe.pipe_nr = ul_pipe;
	channel->ul_pipe.is_open = false;
	channel->ul_pipe.irq = IPC_UL_PIPE_IRQ_VECTOR;
	channel->ul_pipe.channel = channel;
	channel->ul_pipe.dir = IPC_MEM_DIR_UL;
	channel->ul_pipe.accumulation_backoff = accumulation_backoff;
	channel->ul_pipe.irq_moderation = irq_moderation;
	channel->ul_pipe.buf_size = 0;

	channel->dl_pipe.nr_of_entries = dl_nr_of_entries;
	channel->dl_pipe.pipe_nr = dl_pipe;
	channel->dl_pipe.is_open = false;
	channel->dl_pipe.irq = IPC_DL_PIPE_IRQ_VECTOR;
	channel->dl_pipe.channel = channel;
	channel->dl_pipe.dir = IPC_MEM_DIR_DL;
	channel->dl_pipe.accumulation_backoff = accumulation_backoff;
	channel->dl_pipe.irq_moderation = irq_moderation;
	channel->dl_pipe.buf_size = dl_buf_size;
}

/* reset volatile pipe content for all channels
 */
static void imem_channel_reset(struct ipc_imem *this)
{
	int i;

	for (i = 0; i < this->nr_of_channels; i++) {
		struct ipc_mem_channel *channel;

		channel = &this->channels[i];

		imem_pipe_cleanup(this, &channel->dl_pipe);
		imem_pipe_cleanup(this, &channel->ul_pipe);

		channel->sio_id = -1;
		channel->state = IMEM_CHANNEL_FREE;
	}
}

/* reset volatile pipe content for all channels
 */
static void imem_pipe_cleanup(struct ipc_imem *this, struct ipc_pipe *pipe)
{
	struct sk_buff *skb;

	/* Force pipe to closed state also when not explicitly closed through
	 * imem_pipe_close()
	 */
	pipe->is_open = false;

	/* Empty the uplink skb accumulator.
	 */
	while ((skb = imem_ul_list_dequeue(&pipe->channel->ul_list)) != NULL) {
		/* Free the skbuf element.
		 */
		ipc_pcie_kfree_skb(this->pcie, skb);
	}

	ipc_protocol_pipe_cleanup(this->p_protocol, pipe);
}				/* imem_pipe_cleanup */


void ipc_imem_dealloc(struct ipc_imem **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/**
 * Send IPC protocol uninit to the modem when Link is active.
 */
static void ipc_imem_device_ipc_uninit(struct ipc_imem *this)
{
	int timeout = IPC_MODEM_UNINIT_TIMEOUT_MS;
	enum ipc_mem_device_ipc_state ipc_state;

	/**
	 * When PCIe link is up set IPC_UNINIT
	 * of the modem otherwise ignore it when PCIe link down happens.
	 */
	if (ipc_pcie_check_data_link_active(this->pcie)) {
		/* set modem to UNINIT
		 * (in case we want to reload the AP driver without resetting
		 * the modem)
		 */
		ipc_cp_irq_ipc_control(this->pcie, IPC_MEM_DEVICE_IPC_UNINIT);
		ipc_state = ipc_mmio_get_ipc_state(this->mmio);

		/* Wait for maximum 30ms to allow the Modem to uninitialize the
		 * protocol.
		 */
		while ((ipc_state <= IPC_MEM_DEVICE_IPC_DONT_CARE)
		&& (ipc_state != IPC_MEM_DEVICE_IPC_UNINIT) && (timeout > 0)) {
			udelay(1000);
			timeout--;
			ipc_state = ipc_mmio_get_ipc_state(this->mmio);
		}
	}
}

/* Free the memory information base.
 */
void ipc_imem_cleanup(struct ipc_imem *this)
{

	/* Check if a valid pointer. */
	if (unlikely(!this)) {
		ipc_err("NULL imem pointer");
		return;
	}

	/* forward MDM_NOT_READY to listeners */
	ipc_imem_uevent_send(this, NL_EVENT_MDM_NOT_READY);

	ipc_ap_phase_set(this, IPC_P_OFF_REQ);

	/* Stop all the UL traffic */
	mux_stop_tx_for_all_sessions(&this->mux);
	mux_stop_netif_for_all_sessions(&this->mux);

	ipc_imem_device_ipc_uninit(this);

	/* Deactivate the TD allocation timer
	 */
	ipc_hrtimer_dealloc(&this->td_alloc_timer);

	/* Deactivate the TD Update timer.
	 */
	ipc_hrtimer_dealloc(&this->td_update_timer);

	/* Deactivate the fast Update timer.
	 */
	ipc_hrtimer_dealloc(&this->fast_update_timer);

	/* Deactivate the MUX UL ADB finish timer.
	 */
	ipc_hrtimer_dealloc(&this->mux_finish_adb_timer);

	/* Deactivate the startup timer.
	 */
	ipc_hrtimer_dealloc(&this->startup_timer);

	/* Deactivate the spurious timer.
	 */
	ipc_hrtimer_dealloc(&this->spurious_irq.timer);

#ifndef IPC_EXTERNAL_BUILD
	/* Free MMAP component. */
	ipc_mmap_dealloc(&this->mmap);
#endif

	/* Free the resources of the IP MUX channel.
	 */
	mux_cleanup(this, &this->mux);


	ipc_completion_signal(&this->msg_sender_suspend);

	ipc_completion_signal(&this->ul_pend_sem);

	ipc_completion_signal(&this->dl_pend_sem);

	/* Remove the wwan driver.
	 */
	ipc_wwan_dealloc(&this->wwan);

	/* reset the channel content
	 */
	imem_channel_reset(this);

	/* Uninstall the char driver.
	 */
	ipc_sio_dealloc(&this->sio);

	/* Free the Protocol instance */
	ipc_protocol_dealloc(&this->p_protocol);

	/* Remove tasklet */
	ipc_tasklet_dealloc(&this->tasklet);

	/* Cleanup stats
	 */
	ipc_debugfs_stats_dealloc(&this->stats);

	/* Cleanup params
	 */
	ipc_params_dealloc(&this->params);

	/* cleanup hpu stress test
	 */
	ipc_debugfs_hpu_stress_dealloc(&this->hpu_stress);

	ipc_mmio_dealloc(&this->mmio);

	ipc_rtpm_dealloc(&this->rtpm);

	ipc_ap_phase_set(this, IPC_P_OFF);

	/* make sure these are no longer used after cleanup */
	this->pcie = NULL;
	this->dbgfs = NULL;
	this->dbg = NULL;
}				/* ipc_imem_cleanup */

/* return the driver version string.
 */
const char *ipc_imem_version(void)
{
	return IPC_DRIVER_DESC " " IPC_DRIVER_VERSION " " IPC_DRIVER_FEATURE;
}

/* After CP has unblocked the PCIe link, save the start address of the doorbell
 * scratchpad and prepare the shared memory region. If the flashing to RAM
 * procedure shall be executed, copy the chip information from the doorbell
 * scratchtpad to the application buffer and wake up the flash app.
 */
static int ipc_imem_init(struct ipc_imem *this)
{
	enum ipc_phase phase;

	if (unlikely(!this)) {
		ipc_err("NULL imem pointer");
		return -1;
	}

	/* Status of the spurious simulation.
	 */
	this->spurious_irq.in_use = false;

	/* Initialize the semaphore for the blocking read or downlink transfer.
	 */
	ipc_completion_init(&this->ul_pend_sem);

	ipc_completion_init(&this->dl_pend_sem);

	/* clear internal flags */
	this->ipc_status = IPC_MEM_DEVICE_IPC_UNINIT;
	this->enter_runtime = 0;

	/* Create the semaphore for the message queue.
	 */
	ipc_completion_init(&this->msg_sender_suspend);
	ipc_completion_signal(&this->msg_sender_suspend);
	this->msg_sender_suspend_init = 1;

	/* Update the current operation phase.
	 */
	phase = imem_ap_phase_update(this);

	/* Either CP shall be in the power off or power on phase.
	 */
	switch (phase) {
	case IPC_P_ROM:
		/* poll execution stage (for delayed start, e.g. NAND) */
		ipc_hrtimer_config(this->startup_timer, 1000 * 1000);
		return 0;

	case IPC_P_PSI:
	case IPC_P_EBL:
	case IPC_P_RUN:
		/* The initial IPC state is IPC_MEM_DEVICE_IPC_UNINIT.
		 */
		this->ipc_requested_state = IPC_MEM_DEVICE_IPC_UNINIT;

		/* Verify the exepected initial state.
		 */
		if (this->ipc_requested_state ==
				ipc_mmio_get_ipc_state(this->mmio)) {
			imem_ipc_init_check(this);

			/* Protocol is set to RUN state. Now good to read
			 * Message Completion Support and update protocol
			 * instance.
			 */
			ipc_protocol_update_mcr_cp_cap(this->p_protocol,
				ipc_mmio_cp_has_mcr_support(this->mmio));

			return 0;
		}

		ipc_err("ipc_status(%d) != IPC_MEM_DEVICE_IPC_UNINIT",
				ipc_mmio_get_ipc_state(this->mmio));
		break;
	case IPC_P_CRASH:
	case IPC_P_CD_READY:
		ipc_dbg("Modem is in phase %d,reset Modem to collect CD",
				phase);
		return 0;
	default:
		ipc_err("unexpected operation phase %d", phase);
		break;
	}

	ipc_completion_signal(&this->dl_pend_sem);
	ipc_completion_signal(&this->ul_pend_sem);
	ipc_ap_phase_set(this, IPC_P_OFF);
	return -1;
}

/**
 * allocate ipc_imem structure
 */
struct ipc_imem *ipc_imem_alloc(void)
{
	return ipc_util_kzalloc(sizeof(struct ipc_imem));
}

/* Pass the device pointer to the shared memory driver and request the
 * entry points.
 */
int ipc_imem_mount(struct ipc_imem *this,
		struct device *dev,
		struct ipc_pcie *pcie,
		unsigned int device_id,
		struct ipc_debugfs *dbgfs,
		void *mmio,
		unsigned int instance_nr,
		struct ipc_dbg *dbg)
{
	/* note that dev == NULL is valid for fastsim targets */
	if (unlikely(!this || !pcie ||  !mmio)) {
		ipc_err("invalid argument");
		goto invalid_args;
	}

	/* Save the device address.
	 */
	this->pcie = pcie;
	this->dbgfs = dbgfs;
	this->dbg = dbg;

	/* Save the device ID.
	 */
	this->pci_device_id = device_id;

	/* initialize event flags */
	memset(this->ev_irq_pending, false, sizeof(this->ev_irq_pending));
	this->ev_sio_write_pending = false;
	this->ev_mux_net_transmit_pending = false;
	this->ev_irq_count = 0;
	this->ev_fast_update = 0;
	this->cp_version = 0;
	this->device_sleep = IPC_HOST_SLEEP_ENTER_SLEEP;

	this->rtpm = ipc_rtpm_alloc(dev, this->dbg);
	if (unlikely(!this->rtpm)) {
		ipc_err("Failed to allocate rtpm structure");
		goto rtpm_alloc_fail;
	}

	/* Reset the flash channel id.
	 */
	this->flash_channel_id = -1;

	/* Reset the max number of configured channels
	 */
	this->nr_of_channels = 0;

	/* allocate IPC MMIO */
	this->mmio = ipc_mmio_alloc(mmio, this->dbgfs, this->dbg);
	if (unlikely(!this->mmio)) {
		ipc_err("Failed to allocate mmio structure");
		goto mmio_alloc_fail;
	}

	/* Allocate Stats */
	this->stats = ipc_debugfs_stats_alloc(this->pcie,
				this->dbgfs, this, this->dbg);

	/* Allocate params */
	this->params = ipc_params_alloc(this->dbgfs, this->dbg);
	if (unlikely(!this->params)) {
		ipc_err("Failed to allocate IPC parameters");
		goto params_alloc_fail;
	}

	/* Update parameters For low TPUT platform like IBIS */
	if (this->pci_device_id == INTEL_CP_DEVICE_IBIS_ID) {
		ipc_dbg("Updating parameters for low TPUT platform");
		this->params->mux_netdev_flow_ctrl_threshold =
			IPC_MEM_MUX_UL_SESS_FCON_THRESHOLD_IBIS;
	}

	/* For all legacy platforms use a legacy trace configuration. */
	if ((this->pci_device_id == INTEL_CP_DEVICE_7260_ID) ||
			(this->pci_device_id == INTEL_CP_DEVICE_7360_ID) ||
			(this->pci_device_id == INTEL_CP_DEVICE_7460_ID) ||
			(this->pci_device_id == INTEL_CP_DEVICE_7480_ID) ||
			(this->pci_device_id == INTEL_CP_DEVICE_7560_ID) ||
			(this->pci_device_id == INTEL_CP_DEVICE_IBIS_ID)) {
		this->params->trace_td_numbers = IPC_MEM_TDS_TRC_LEGACY;
		this->params->trace_td_buff_size =
			IPC_MEM_MAX_DL_TRC_BUF_SIZE_LEGACY;
	}


	/* Create tasklet for event handling*/
	this->tasklet = ipc_tasklet_alloc(this->dbg);

	if (unlikely(!this->tasklet)) {
		ipc_err("Failed to allocate tasklet");
		goto tasklet_alloc_fail;
	}

	/* Get the protocol instance */
	this->p_protocol = ipc_protocol_alloc(this->dbg,
					this->mmio, this->pcie,
					this->stats, this->params,
					this->pci_device_id,
					this->tasklet);

	if (unlikely(!this->p_protocol)) {
		ipc_err("Failed to get IPC Protocol instance");
		goto protocol_alloc_fail;
	}

	this->hpu_stress = ipc_debugfs_hpu_stress_alloc(this->dbgfs,
							 pcie, this->dbg);

#ifndef IPC_EXTERNAL_BUILD
	{
		static const struct ipc_mmap_ops ops = {
			.send_map_msg = imem_send_map_msg,
			.send_unmap_msg = imem_send_unmap_msg
		};

		this->mmap = ipc_mmap_alloc(&ops, this, this->pcie,
				instance_nr, this->dbg);
		if (unlikely(!this->mmap)) {
			ipc_err("Failed to allocate mmap component");
			goto mmap_alloc_fail;
		}
	}
#endif

	/* The phase is set to power off.
	 */
	ipc_ap_phase_set(this, IPC_P_OFF);

	/* Initialize flash channel.
	 * The actual pipe configuration will be set once PSI has executed
	 */
	imem_channel_init(this, IPC_CTYPE_FLASH, 0, 0, 0, 0, 0, 0, 0, 0);

	/* Character device creation */
	{
		struct ipc_sio_ops ops = {
			.open = imem_sio_open,
			.close = imem_sio_close,
			.write = imem_sio_write
		};

		char name[32] = { 0 };

		if (instance_nr == 0) {
			snprintf(name, sizeof(name) - 1, "iat");
		} else
			snprintf(name, sizeof(name) - 1, "iat0_%d",
				instance_nr);

		this->sio = ipc_sio_alloc(this->dbg, this->pcie, this->params,
			&ops, this, name);

		if (unlikely(!this->sio)) {
			ipc_err("failed to register the ipc sio mem interfaces");
			goto sio_alloc_fail;
		}
	}

	/* WWAN registration. */
	{
		static const struct ipc_wwan_ops ops = {
			.open = imem_wwan_open_cb,
			.close = imem_wwan_close_cb,
			.transmit = imem_wwan_transmit_cb
		};

		this->wwan = ipc_wwan_alloc(&ops, this,
						instance_nr, this->dbg);
		if (!this->wwan) {
			ipc_err("failed to register the ipc_wwan interfaces");
			goto wwan_register_fail;
		}

		if ((device_id == INTEL_CP_DEVICE_IBIS_ID) ||
				(device_id == INTEL_CP_DEVICE_7660_ID) ||
				(device_id == INTEL_CP_DEVICE_8060_ID)) {
			/* register timesync callback */
			ipc_wwan_register_timesync(this->wwan,
					imem_timesync_cb, this);
		}
	}

	this->startup_timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_tl_startup_timer_cb, "startup timer", true,
		this->tasklet);
	if (unlikely(!this->startup_timer)) {
		ipc_err("failed to allocate startup_timer");
		goto startup_timer_alloc_fail;
	}

	this->spurious_irq.timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_tl_spurious_irq_cb, "spurious irq", false,
		this->tasklet);
	if (unlikely(!this->spurious_irq.timer)) {
		ipc_err("failed to allocate spurious_irq.timer");
		goto spurious_irq_timer_alloc_fail;
	}

	this->td_update_timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_tl_td_update_timer_cb, "td update timer", false,
		this->tasklet);
	if (unlikely(!this->td_update_timer)) {
		ipc_err("failed to allocate td_update_timer");
		goto td_update_timer_alloc_fail;
	}

	this->fast_update_timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_fast_update_timer_cb, "fast update timer", false,
		NULL);
	if (unlikely(!this->fast_update_timer)) {
		ipc_err("failed to allocate fast_update_timer");
		goto fast_update_timer_alloc_fail;
	}

	this->mux_finish_adb_timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_tl_mux_finish_adb_timer_cb, "mux finish adb timer", false,
		this->tasklet);
	if (unlikely(!this->mux_finish_adb_timer)) {
		ipc_err("failed to allocate mux_finish_adb_timer");
		goto mux_finish_adb_timer_alloc_fail;
	}

	this->td_alloc_timer = ipc_hrtimer_alloc(this, this->dbg,
		imem_tl_td_alloc_timer_cb, "td alloc timer", false,
		this->tasklet);
	if (unlikely(!this->td_alloc_timer)) {
		ipc_err("failed to allocate td alloc timer");
		goto td_alloc_timer_alloc_fail;
	}

	if (ipc_imem_init(this)) {
		ipc_err("failed to initialize the imem layer");
		goto imem_init_fail;
	}

	return 0;

imem_init_fail:
	ipc_hrtimer_dealloc(&this->td_alloc_timer);
td_alloc_timer_alloc_fail:
	ipc_hrtimer_dealloc(&this->mux_finish_adb_timer);
mux_finish_adb_timer_alloc_fail:
	ipc_hrtimer_dealloc(&this->fast_update_timer);
fast_update_timer_alloc_fail:
	ipc_hrtimer_dealloc(&this->td_update_timer);
td_update_timer_alloc_fail:
	ipc_hrtimer_dealloc(&this->spurious_irq.timer);
spurious_irq_timer_alloc_fail:
	ipc_hrtimer_dealloc(&this->startup_timer);
startup_timer_alloc_fail:
	ipc_wwan_dealloc(&this->wwan);
wwan_register_fail:
	ipc_sio_dealloc(&this->sio);
sio_alloc_fail:
	imem_channel_reset(this);
#ifndef IPC_EXTERNAL_BUILD
	ipc_mmap_dealloc(&this->mmap);
mmap_alloc_fail:
#endif
	ipc_debugfs_hpu_stress_dealloc(&this->hpu_stress);
	ipc_protocol_dealloc(&this->p_protocol);
protocol_alloc_fail:
	ipc_tasklet_dealloc(&this->tasklet);
tasklet_alloc_fail:
	ipc_params_dealloc(&this->params);
params_alloc_fail:
	ipc_debugfs_stats_dealloc(&this->stats);
	ipc_mmio_dealloc(&this->mmio);
mmio_alloc_fail:
	ipc_rtpm_dealloc(&this->rtpm);
rtpm_alloc_fail:
	this->dbg = NULL;
	this->pcie = NULL;
	this->dbgfs = NULL;
invalid_args:
	return IPC_FAIL;
}				/* ipc_imem_mount */

/* Open a packet data online channel between the network layer and CP. */
static int imem_wwan_open_cb(void *instance, int vlan_id)
{
	struct ipc_imem *this = instance;
	int rc = -1;

	ipc_rtpm_get_hw(this->rtpm);

	if (ipc_imem_syscall_enter(this)) {
		rc = imem_sys_wwan_open(this, vlan_id);
		ipc_imem_syscall_leave(this);
	}

	ipc_rtpm_put_hw(this->rtpm);

	return rc;
}

/* Release a net link to CP. */
static void imem_wwan_close_cb(void *instance, int vlan_id, int channel_id)
{
	struct ipc_imem *this = instance;

	ipc_rtpm_get_hw(this->rtpm);

	if (ipc_imem_syscall_enter(this)) {
		imem_sys_wwan_stop(this, vlan_id, channel_id);
		ipc_imem_syscall_leave(this);
	}

	ipc_rtpm_put_hw(this->rtpm);
}

/* add to the ul list skb */
static int imem_wwan_transmit(struct ipc_imem *this, int vlan_id,
		int channel_id,	struct sk_buff *skb)
{
	struct ipc_mem_channel *channel;

	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return -1;
	}

	ipc_dbg("%s[vlan id:%d] skb_data:%p skb_len:%d",
			ipc_ap_phase_get_string(this->phase), vlan_id,
			skb->data, skb->len);

	/* get the reference to the channel */
	channel = &this->channels[channel_id];

	/* Test the channel state */
	if (channel->state != IMEM_CHANNEL_ACTIVE) {
		ipc_err("invalid state on channel %d", channel_id);
		return -1;
	}

	if (unlikely(ipc_pcie_map_skb(this->pcie, skb))) {
		ipc_err("failed to map skb");
		return -1;
	}

	/* Add skb to the uplink skbuf accumulator */
	imem_ul_list_add(&channel->ul_list, skb);
	imem_call_sio_write(this);

	return 0;
}

/*
 * callback function for transfer UL data
 *
 * WWAN layer must free the packet in case if imem fails to transmit.
 * In case of success, imem layer will free it.
 */
static int imem_wwan_transmit_cb(void *instance, int vlan_id, int channel_id,
	struct sk_buff *skb)
{
	struct ipc_imem *this = instance;
	int ret = 0;

	if (unlikely(!this || (channel_id < 0) || !skb)) {
		ipc_err("invalid parameter");
		return -EINVAL;
	}

	/* Is CP Running? */
	if (ipc_ap_phase_get(this) != IPC_P_RUN) {
		ipc_dbg("%s[vlanid:%d]",
				ipc_ap_phase_get_string(this->phase),
				vlan_id);
		return -1;
	}

	/* CB is called from atomic context, no sleep possible! */
	ipc_rtpm_get_hw_no_sleep(this->rtpm);

	if (this->channels[channel_id].ctype == IPC_CTYPE_WWAN) {
		/* check vlan id and transfer the data accordingly
		 * 1 to MAX_MUX_SESSIONS vlan id = IP sessions
		 * 257 to 768 vlan id = data session
		 * greater than 768 vlan id = unsupported session
		 */
		if (vlan_id > 0 && vlan_id <= IPC_IMEM_MUX_SESSION_ENTRIES) {
			/* Route the UL packet through IP MUX Layer */
			ret = mux_net_transmit(this,
					&this->mux,
					vlan_id - 1, skb);
		/* Control channels and Low latency data channel for VoLTE*/
		} else if (vlan_id > 256 && vlan_id < 768) {
			ret = imem_wwan_transmit(this, vlan_id,
					channel_id, skb);
		}
	} else {
		ipc_err("invalid channel type on channel %d: ctype: %d",
			channel_id,
			this->channels[channel_id].ctype);
	}

	ipc_rtpm_put_hw(this->rtpm);

	return ret;		/* imem_wwan_transmit */
}

/* Shift the IRQ actions to the IPC thread. */
void ipc_imem_irq_process(struct ipc_imem *this, int irq)
{
	/* Debounce IPC_EV_IRQ. */
	if (likely(this && this->tasklet && !this->ev_irq_pending[irq])) {
		this->ev_irq_pending[irq] = true;
		this->ev_irq_count++;
		(void) ipc_tasklet_call_async(this->tasklet, imem_tl_irq_cb,
			this, irq, NULL, 0);
	}
}				/* ipc_imem_irq_process */

/* =============================================================================
 * Operations for IP data aggregation and multiplexing over a single channel.
 */

/* Initializes WWAN channels and the channel for MUX.
 */
static void wwan_channel_init(struct ipc_imem *this,
		enum imem_mux_protocol protocol)
{
	struct ipc_chnl_cfg chnl_cfg;

	memset(&chnl_cfg, 0, sizeof(struct ipc_chnl_cfg));

	this->cp_version =  ipc_mmio_get_cp_version(this->mmio);

	ipc_dbg("CP version: 0x%04x", this->cp_version);

	while (this->nr_of_channels < IPC_MEM_MAX_CHANNELS &&
			!ipc_chnl_cfg_get(&chnl_cfg, this->nr_of_channels,
				this->pci_device_id,
				this->cp_version,
				protocol, this->dbg, this->params)) {

		ipc_dbg("initializing entry :%d id:%d ul_td:%d dl_td:%d buff:%d ul_pipe:%d dl_pipe:%d acc:%d",
			this->nr_of_channels, chnl_cfg.id,
			chnl_cfg.ul_nr_of_entries,
			chnl_cfg.dl_nr_of_entries,
			chnl_cfg.dl_buf_size,
			chnl_cfg.ul_pipe, chnl_cfg.dl_pipe,
			chnl_cfg.accumulation_backoff);

		imem_channel_init(this, IPC_CTYPE_WWAN, chnl_cfg.id,
			chnl_cfg.ul_nr_of_entries,
			chnl_cfg.dl_nr_of_entries,
			chnl_cfg.dl_buf_size,
			chnl_cfg.ul_pipe, chnl_cfg.dl_pipe,
			IRQ_MOD_OFF,
			chnl_cfg.accumulation_backoff);
	}
}				/* wwan_channel_init */

/* Get flow control enable cmd depending on protocol.
 */
static inline int mux_get_flow_ctrl_en_cmd(struct imem_mux *mux)
{
	return mux->protocol != MUX_LITE ? IPC_MEM_CMD_FLOW_CTL_ENABLE :
					IPC_MEM_CMD_LITE_FLOW_CTL;
}

/* Check flow control mask for MUX.
 */
static inline int mux_check_flow_ctrl_mask(struct imem_mux *mux,
						u32 param_mask, u32 mask)
{
	return mux->protocol != MUX_LITE || param_mask == mask;
}

/* Calculate the cmd header depending on protocol.
 */
static inline int mux_get_offset_of_cmd_params(struct imem_mux *mux)
{
	return mux->protocol == MUX_LITE ?
		offsetof(struct ipc_mem_lite_cmdh, param) :
		offsetof(struct ipc_mem_cmdh, param);
}

/* Get flow control disable cmd depending on protocol.
 */
static inline int mux_get_flow_ctrl_dis_cmd(struct imem_mux *mux)
{
	return mux->protocol == MUX_LITE ? IPC_MEM_CMD_LITE_FLOW_CTL :
		IPC_MEM_CMD_FLOW_CTL_DISABLE;
}

#if defined(IMC_IPC_FLOW_CTRL_TEST)
/* Get flow control ACK cmd depending on protocol.
 */
static inline int mux_get_flow_ctrl_ack(struct imem_mux *mux)
{
	return mux->protocol == MUX_LITE ? IPC_MEM_CMD_LITE_FLOW_CTL_ACK :
		IPC_MEM_CMD_FLOW_CTL_ACK;
}
#endif	/* IMC_IPC_FLOW_CTRL_TEST */

/* Get uplink adb size depending on protocol.
 */
static inline int mux_get_ul_adb_size(struct ipc_params *params,
		enum imem_mux_protocol protocol)
{
	return protocol == MUX_LITE ?
		params->mux_lite_buf_size :
		params->mux_ul_adb_size;
}

/* Enable/Disable TX flow control on MUX sessions if required.
 */
static void mux_netif_tx_flowctrl(struct imem_mux_session *session,
		int idx, bool on)
{
	if (session) {
		/* Inform the network interface to start/stop flow ctrl */
		if (ipc_wwan_is_tx_stopped(session->wwan, idx) != on)
			ipc_wwan_tx_flowctrl(session->wwan, idx, on);
	}
}

/* At the begin of the runtime phase the IP MUX
 * channel shall created.
 */
static void mux_channel_create(struct ipc_imem *this, struct imem_mux *mux)
{
	int channel_id;

	/* Get MUX channel id. */
	channel_id = imem_channel_alloc(this, -1, IPC_CTYPE_WWAN);

	if (channel_id < 0) {
		ipc_err("allocation of the MUX channel id failed");

		/* Set the MUX error state. */
		mux->state = MUX_S_ERROR;
		mux->event = MUX_E_NOT_APPLICABLE;
		return;		/* MUX channel is not available. */
	}

	/* Establish the MUX channel in blocking mode. */
	if (!imem_channel_open(this, channel_id, IPC_HP_NET_CHANNEL_INIT)) {
		ipc_err("imem_channel_open failed");
		/* Set the MUX error state. */
		mux->state = MUX_S_ERROR;
		mux->event = MUX_E_NOT_APPLICABLE;
		return;		/* MUX channel is not available. */
	}

	/* Save the reference to the MUX channel. */
	mux->channel = &this->channels[channel_id];

	/* Define the MUX active state properties. */
	mux->state = MUX_S_ACTIVE;
	mux->event = MUX_E_NO_ORDERS;

	/* alloc mux stats */
	if (!mux->dbg_stats)
		mux->dbg_stats = ipc_debugfs_mux_alloc(
						this->dbgfs, 0, this->dbg);
}				/* mux_channel_create */

/* Search for a free session interface id. */
static int mux_session_alloc(struct ipc_imem *this,
				struct imem_mux *mux, int if_id)
{
	/* Test the range. */
	if (if_id < 0 || if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
		ipc_err("invalid interface id=%d", if_id);
		return -1;
	}
	/* Return the session id. */
	return if_id;
}				/* mux_session_alloc */

/* Reset the session/if id state. */
static void mux_session_free(struct imem_mux *mux, int if_id)
{
	struct imem_mux_session *if_entry_p;

	if_entry_p = &mux->session[if_id];
	/* Reset the session state. */
	if_entry_p->wwan = NULL;
}				/* mux_session_free */

/* Allocate a skbuf for an IP MUX command. */
static int mux_acb_alloc(struct ipc_imem *this, struct imem_mux *mux)
{
	struct sk_buff *skb;
	u64 mapping;
	struct imem_mux_acb *acb = &(mux->acb);

	/* Allocate skb memory for the uplink buffer. */
	skb = ipc_pcie_alloc_ul_skb(this->pcie, IPC_MEM_MAX_UL_ACB_BUF_SIZE,
		&mapping);
	if (!skb) {
		ipc_err("skbuf allocation failed");
		return 0;
	}

	/* Save the skb address. */
	acb->skb = skb;

	/* Initialize the command buffer. */
	memset(skb->data, 0, IPC_MEM_MAX_UL_ACB_BUF_SIZE);

	/* Save the start address of the buffer. */
	acb->buf_p = skb->data;
	return 1;
}				/* mux_acb_alloc */

/* Initialze the command header. */
static void mux_acb_init(struct imem_mux *mux)
{
	struct ipc_mem_acbh *header;
	struct imem_mux_acb *acb = &(mux->acb);

	header = (struct ipc_mem_acbh *)acb->buf_p;
	header->block_length = sizeof(struct ipc_mem_acbh);
	header->first_command_index = header->block_length;
	header->signature = IPC_MEM_SIG_ACBH;
	header->sequence_nr = mux->acb_tx_sequence_nr++;
}				/* mux_acb_init */

/* Add a command to the ACB. */
static struct ipc_mem_cmdh *mux_acb_add_cmd(struct ipc_imem *this,
		u32 cmd, struct imem_mux *mux, void *param, u32 param_size)
{
	struct ipc_mem_acbh *header;
	struct ipc_mem_cmdh *cmdh;
	struct imem_mux_acb *acb = &(mux->acb);

	ipc_dbg("cmd=%u, param_size=%u", cmd, param_size);

	/* Start address of the command. */
	header = (struct ipc_mem_acbh *)acb->buf_p;
	cmdh =
	    (struct ipc_mem_cmdh *)(acb->buf_p + header->block_length);

	cmdh->signature = IPC_MEM_SIG_CMDH;
	cmdh->command_type = cmd;	/* Command type. */
	cmdh->if_id = acb->if_id;	/* Interface id, */

	/* Store the command type */
	acb->cmd = cmd;

	/* Used cmd len (header + param_size). */
	cmdh->cmd_len = offsetof(struct ipc_mem_cmdh, param) + param_size;
	cmdh->transaction_id = mux->tx_transaction_id++;
	if (param)
		/* Copy param content to buffer. */
		memcpy(&cmdh->param, param, param_size);

	/* Set the length field in skbuf. */
	skb_put(acb->skb, header->block_length + cmdh->cmd_len);

	return cmdh;
}				/* mux_acb_add_cmd */

/**
 * Prepare ADAM-Lite Command
 */
static struct ipc_mem_lite_cmdh *mux_lite_add_cmd(
		struct ipc_imem *this, u32 cmd, struct imem_mux *mux,
		struct imem_mux_acb *p_acb, void *param, u32 param_size)
{

	struct ipc_mem_lite_cmdh *cmdh = NULL;

	if (!mux || !p_acb)
		return NULL;

	ipc_dbg("cmd=%u, param_size=%u", cmd, param_size);

	/* fill the command */
	cmdh = (struct ipc_mem_lite_cmdh *)p_acb->buf_p;
	cmdh->signature = IPC_MEM_SIG_CMDH;
	cmdh->command_type = cmd;	/* Command type. */
	cmdh->if_id = p_acb->if_id; /* Interface id */

	/* store the command type */
	p_acb->cmd = cmd;

	/* Use cmd len */
	cmdh->cmd_len = offsetof(struct ipc_mem_lite_cmdh, param) + param_size;
	cmdh->transaction_id = mux->tx_transaction_id++;

	if (param)
		/* Copy param content to buffer */
		memcpy(&cmdh->param, param, param_size);

	/* set the length field in skbuf */
	skb_put(p_acb->skb, cmdh->cmd_len);

	return cmdh;
}

/* Finish and transfer ACB. */
static int mux_acb_send(struct ipc_imem *this, struct imem_mux *mux,
		bool blocking)
{
	struct ipc_mem_channel *channel;

	if (unlikely(!mux || !mux->channel)) {
		ipc_err("invalid mux pointer");
		return IPC_FAIL;
	}

	if (IS_IPC_FAIL(ipc_tasklet_call_async(this->tasklet,
		imem_tl_mux_cmd_send, this, 0, &(mux->acb),
		sizeof(struct imem_mux_acb)))) {
		ipc_err("Unable to send mux command");
		return IPC_FAIL;
	}

	channel = mux->channel;

	/* if blocking, suspend the app and wait for irq in the flash or
	 * crash phase. return false on timeout to indicate failure.
	 */
	if (blocking) {
		u64 wait_time_milliseconds =
			(this->mmio &&
			(ipc_imem_get_exec_stage(this) ==
			 IPC_MEM_EXEC_STAGE_RUN)) ?
			this->params->mux_cmd_run_timeout :
			IPC_MUX_CMD_RUN_DEFAULT_TIMEOUT;

		ipc_completion_reinit(&channel->ul_sem);

		if (ipc_completion_wait_interruptible_timeout_ms(
			&channel->ul_sem, wait_time_milliseconds) == 0) {
			ipc_err("ch[%d] timeout", channel->channel_id);
			ipc_imem_report_timeout(this);
			return IPC_TIMEOUT;
		}
	}

	/* success */
	return IPC_OK;
}				/* mux_acb_send */

/* Create and send the session open command. */
static struct ipc_mem_cmd_open_session_resp *mux_session_open_send(
		struct ipc_imem *this, struct imem_mux *mux, int if_id)
{
	union ipc_mem_cmd_param param;
	struct ipc_mem_cmd_open_session_resp *open_session_resp;
	struct imem_mux_acb *acb = &(mux->acb);

	/* open_session commands to one ACB and start transmission. */
	param.open_session.flow_ctrl = 0;
	param.open_session.reserved = 0;
	param.open_session.ipv4v6_hints = 0;
	param.open_session.reserved2 = 0;
	param.open_session.dl_head_pad_len = IPC_MEM_DL_ETH_OFFSET;

	/* Finish and transfer ACB. The user thread is suspended.
	 * It is a blocking function call, until CP responds or timeout.
	 */
	acb->wanted_response = IPC_MEM_CMD_OPEN_SESSION_RESP;
	if (mux_dl_acb_send_cmds(this, mux, IPC_MEM_CMD_OPEN_SESSION,
				if_id, 0, &param,
				sizeof(param.open_session), true, false)) {
		ipc_err("if_id %d: OPEN_SESSION send failed", if_id);
		return NULL;
	}

	/* Analzse the received message type. */
	if (acb->got_response != IPC_MEM_CMD_OPEN_SESSION_RESP) {
		ipc_err("if_id %d, Got wrong response OPEN_SESSION %d",
			if_id, acb->got_response);
		return NULL;	/* Wrong CP response type. */
	}

	/* Analyze the result code. */
	open_session_resp = &(mux->acb.got_param.open_session_resp);
	if (open_session_resp->response != IPC_MEM_CMD_RESP_SUCCESS) {
		ipc_err("if_id %d, session open failed, response=%d",
			if_id, (int)open_session_resp->response);
		return NULL;
	}

	ipc_dbg("Open session on %d", if_id);

#if defined(IMC_IPC_FLOW_CTRL_TEST)
	/* Flow Control Enable Command */
	param.flow_ctl.mask = ~0;
	ipc_dbg("Sending IPC_MEM_CMD FLOW_CTL command. Mask: 0x%X",
		      param.flow_ctl.mask);

	/* Finish and transfer ACB. The user thread is suspended.
	 * It is a blocking function call, until CP responds or timeout.
	 */
	acb.wanted_response = mux_get_flow_ctrl_ack(mux);
	if (mux_dl_acb_send_cmds(this, mux,
				mux_get_flow_ctrl_en_cmd(mux), if_id,
				0, &param, sizeof(param.flow_ctl),
				true, false)) {
		ipc_dbg("Sending FLOW_CTL_CMD Failed!");
		return NULL;
	}

	/* Analzse the received message type. */
	if (acb.got_response != mux_get_flow_ctrl_ack(mux)) {
		ipc_dbg("Got wrong response for FLOW_CTL_CMD! %d",
		       acb.got_response);
		return NULL;	/* Wrong CP response type. */
	}

	/* flow_ctl command to one ACB and start transmission. */
	param.flow_ctl.mask = 0;
	ipc_dbg("Sending IPC_MEM_CMD FLOW_CTL Command. Mask: 0x%X",
		      param.flow_ctl.mask);

	if (mux_dl_acb_send_cmds(mux, mux_get_flow_ctrl_dis_cmd(mux), if_id,
			0, &param, sizeof(param.flow_ctl), true, false)) {
		ipc_dbg("Sending FLOW_CTL_CMD Failed!");
		return NULL;
	}

	/* Analzse the received message type. */
	if (acb.got_response != mux_get_flow_ctrl_ack(mux)) {
		ipc_dbg("Got wrong response for FLOW_CTL_CMD! %d",
		       acb.got_response);
		return NULL;	/* Wrong CP response type. */
	}

#endif	/* IMC_IPC_FLOW_CTRL_TEST */

	/* The requested session was established. */
	return open_session_resp;
}				/* mux_session_open_send */

/* Open the first IP session. */
static bool mux_session_open(struct ipc_imem *this,
		struct imem_mux *mux, struct mux_session_open *session_open_p)
{
	int if_id;
	struct ipc_mem_cmd_open_session_resp *open_session_resp;

	/* Search for a free session interface id. */
	if_id = mux_session_alloc(this, mux, session_open_p->if_id);
	if (if_id < 0 || if_id >= IPC_IMEM_MUX_SESSION_ENTRIES)
		return false;		/* No session interface id. */

	/* Create and send the session open command.
	 * It is a blocking function call, until CP responds or timeout.
	 */
	open_session_resp = mux_session_open_send(this, mux, if_id);
	if (!open_session_resp) {
		/* Open session failed, free the interface id. */
		mux_session_free(mux, if_id);
		session_open_p->if_id = -1;
		return false;
	}

	/* Initialize the uplink skb accumulator. */
	imem_ul_list_init(&mux->session[if_id].ul_list);

	/* Activate the session. */
	mux->session[if_id].dl_head_pad_len = IPC_MEM_DL_ETH_OFFSET;
	mux->session[if_id].ul_head_pad_len =
	    open_session_resp->ul_head_pad_len;
	mux->session[if_id].wwan = this->wwan;

	/* Reset the flow ctrl stats of the session */
	mux->session[if_id].flow_ctl_en_cnt = 0;
	mux->session[if_id].flow_ctl_dis_cnt = 0;
	mux->session[if_id].ul_flow_credits = 0;
	mux->session[if_id].net_tx_stop = false;
	mux->session[if_id].flow_ctl_mask = 0;

	/* Log the MUX Debug event */
	ipc_debugfs_mux_log_event(mux->dbg_stats,
			if_id, false, -1, mux->acc_adb_size,
			mux->acc_payload_size,
			mux->session[if_id].ul_flow_credits);

	/* Save and return the assigned if id. */
	session_open_p->if_id = if_id;

	ipc_dbg("if_id=%d, wwan=%p, ul_head_pad_len=%u", if_id,
		 mux->session[if_id].wwan,
		 mux->session[if_id].ul_head_pad_len);

	/* Session successfully opened */
	return true;

}				/* mux_session_open */

/* Create and send the session close command. */
static int mux_session_close_send(struct ipc_imem *this,
		struct imem_mux *mux, int if_id)
{
	struct ipc_mem_cmd_close_session_resp *close_session_resp;
	struct imem_mux_acb *acb = &(mux->acb);

	acb->wanted_response = IPC_MEM_CMD_CLOSE_SESSION_RESP;
	if (mux_dl_acb_send_cmds(this, mux, IPC_MEM_CMD_CLOSE_SESSION,
						if_id, 0, NULL, 0, true,
						false))
		return 0;	/* Command timeout */

	/* Analzse the received message type. */
	if (acb->got_response != IPC_MEM_CMD_CLOSE_SESSION_RESP)
		return 0;	/* Wrong CP response type. */

	/* Analyze the result code. */
	close_session_resp = &(acb->got_param.close_session_resp);
	if (close_session_resp->response != IPC_MEM_CMD_RESP_SUCCESS) {
		ipc_err("session close failed, response=%d",
			(int)close_session_resp->response);
		return 0;
	}

	/* The requested session was released. */
	return 1;
}				/* mux_session_close_send */

/* Free pending session UL packet. */
static void mux_session_reset(struct imem_mux *mux, int if_id)
{
	struct sk_buff *skb;

	/* Reset the session/if id state. */
	mux_session_free(mux, if_id);

	/* Empty the uplink skb accumulator. */
	for (;;) {
		/* Remove from the head of the downlink queue. */
		skb = imem_ul_list_dequeue(&mux->session[if_id].ul_list);
		if (!skb)
			break;

		/* Free the skbuf element. */
		dev_kfree_skb(skb);
	}
}				/* mux_session_reset */

/* Release an IP session. */
static void mux_session_close(struct ipc_imem *this,
		struct imem_mux *mux, struct mux_session_close *msg)
{
	int if_id;

	/* Copy the session interface id. */
	if_id = msg->if_id;

	/* Entry condition. */
	if (if_id < 0 || if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
		ipc_err("invalid session id %d", if_id);
		return;
	}

	/* Create and send the session close command.
	 * It is a blocking function call, until CP responds or timeout.
	 */
	mux_session_close_send(this, mux, if_id);

	/* Reset the flow ctrl stats of the session */
	mux->session[if_id].flow_ctl_en_cnt = 0;
	mux->session[if_id].flow_ctl_dis_cnt = 0;
	mux->session[if_id].flow_ctl_mask = 0;

	/* Free pending session UL packet. */
	mux_session_reset(mux, if_id);
}				/* mux_session_close */

/* Release an IP session. */
static void mux_channel_close(struct ipc_imem *this,
		struct imem_mux *mux, struct mux_channel_close *channel_close_p)
{
	int i;

	/* Free pending session UL packet. */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++)
		if (mux->session[i].wwan)
			mux_session_reset(mux, i);

	/* Release the pipe and channel resources. */
	imem_channel_close(this, mux->channel->channel_id);

	/* Reset the MUX object. */
	mux->state = MUX_S_INACTIVE;
	mux->event = MUX_E_INACTIVE;
}				/* mux_channel_close */

/* CP has interrupted AP. If AP is in IP MUX mode, execute the pending
 * operation.
 */
#define MUX_ERR() ipc_err("unexpected MUX transition: state=%d, event=%d", \
			mux->state, mux->event)

static int mux_schedule(struct ipc_imem *this,
		struct imem_mux *mux, union imem_mux_msg *msg_p)
{
	enum imem_mux_event order;
	bool success;

	/* Entry condition. */
	if (!mux->initialized)
		return -1;	/* Shall be used as normal IP channel. */

	/* Decode the message. */
	order = msg_p->common.event;

	/* Select the right action. */
	switch (mux->state) {
	case MUX_S_INACTIVE:
		if (order != MUX_E_MUX_SESSION_OPEN)
			/* Wait for the request to open a session */
			return -1;

		if (mux->event == MUX_E_INACTIVE)
			/* Establish the MUX channel and the new state. */
			mux_channel_create(this, mux);

		if (mux->state != MUX_S_ACTIVE)
			/* Missing the MUX channel. */
			return -1;

		/* Disable the TD update timer and open the first IP
		 * session.
		 */
		this->td_update_timer_suspended = 1;
		mux->event = MUX_E_MUX_SESSION_OPEN;
		success = mux_session_open(this, mux, &msg_p->session_open);

		this->td_update_timer_suspended = 0;
		return success ? mux->channel->channel_id : -1;

	case MUX_S_ACTIVE:
		switch (order) {
		case MUX_E_MUX_SESSION_OPEN:
			/* Disable the TD upate timer and o
			 * pen a follow session.
			 */
			this->td_update_timer_suspended = 1;
			mux->event = MUX_E_MUX_SESSION_OPEN;
			success = mux_session_open(this, mux,
				&msg_p->session_open);
			this->td_update_timer_suspended = 0;
			return success ? mux->channel->channel_id : -1;

		case MUX_E_MUX_SESSION_CLOSE:
			/* Release an IP session. */
			mux->event = MUX_E_MUX_SESSION_CLOSE;
			mux_session_close(this, mux, &msg_p->session_close);
			return mux->channel->channel_id;

		case MUX_E_MUX_CHANNEL_CLOSE:
			/* Close the MUX channel pipes. */
			mux->event = MUX_E_MUX_CHANNEL_CLOSE;
			mux_channel_close(this, mux, &msg_p->channel_close);
			return mux->channel->channel_id;

		default:
			/* Invalid order. */
			return -1;
		}		/* end switch */

	default:
		MUX_ERR();
		return -1;
	}			/* end switch */
}				/* mux_schedule */

/* Initialize the MUX object.
 */
static int mux_init(struct ipc_imem *this, struct imem_mux *mux)
{
	int i, qlt_size = 0;
	struct imem_mux_session *session;
	struct sk_buff_head *free_list;
	struct sk_buff *skb;
	int ul_tds, ul_td_size;

	if (unlikely(!this || !mux)) {
		ipc_err("Invalid argument");
		return -1;
	}

	mux->params = this->params;

	/* Get the reference to the id list. */
	session = mux->session;

	/* Calculate the size of Queue Level Table */
	qlt_size = offsetof(struct ipc_mem_qlth, ql) +
			       MUX_QUEUE_LEVEL * sizeof(struct ipc_mem_qlth_ql);

	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {
		/* Set the if id. */
		session[i].if_id = i;

		/* Reset the flags */
		session[i].net_tx_stop = false;

		if (mux->protocol == MUX_LITE) {
			mux->ul_adb.p_qlt[i] = NULL;
		} else {
			/* Allocate memory for QLTs for all sessions.
			 * This QLT memory is not shared to Modem/CP.
			 * So no need to adjust the start and end addresses.
			 */
			mux->ul_adb.p_qlt[i] =
				ipc_util_kzalloc_atomic(qlt_size);

			if (!mux->ul_adb.p_qlt[i]) {
				ipc_err("QLT alloc failed");
				return -1;
			}
		}
	}

	/* Get the reference to the UL ADB list. */
	free_list = &mux->ul_adb.free_list;

	/* Initialize the list with free ADB. */
	skb_queue_head_init(free_list);

	ul_td_size = mux_get_ul_adb_size(mux->params, mux->protocol);

	ul_tds = mux->protocol ==
			MUX_LITE ? ((ul_td_size >
			IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE) ?
			IPC_MEM_MUX_LITE_MAX_JUMBO_TDS :
			IPC_MEM_MAX_TDS_MUX_LITE_UL)
			: IPC_MEM_MAX_TDS_MUX_UL;

	ipc_dbg("Updating the UL TD  Size = %d , UL TDs = %d",
			ul_td_size, ul_tds);

	/* Allocate the list of UL ADB. */
	for (i = 0; i < ul_tds; i++) {
		u64 mapping;

		skb = ipc_pcie_alloc_ul_skb(this->pcie, ul_td_size, &mapping);
		if (!skb) {
			ipc_err("skb allocation failed");
			return -1;
		}

		/* Extend the UL ADB list. */
		skb_queue_tail(free_list, skb);
	}

	/* Initialize dest_adb to NULL */
	mux->ul_adb.dest_skb = NULL;

	mux->initialized = true;
	mux->adb_prep_ongoing = false;
	mux->size_needed = 0;
	mux->ul_data_pend_bytes = 0;
	mux->acc_adb_size = 0;
	mux->acc_payload_size = 0;

	return 0;

}				/* mux_init */

/**
 * Process the Command responses
 */
static int mux_dl_cmdresps_decode_process(struct ipc_imem *this,
		struct imem_mux *mux, u32 cmd_type,
		int if_id, u32 transaction_id,
		union ipc_mem_cmd_param param)
{
	struct imem_mux_acb *acb = &(mux->acb);

	ipc_trc_dl_mux_resp(cmd_type, transaction_id, if_id, mux);

	switch (cmd_type) {
	case IPC_MEM_CMD_OPEN_SESSION_RESP:
	case IPC_MEM_CMD_CLOSE_SESSION_RESP:
		/* Resume the control application. */
		ipc_dbg("cmd=%d, rsp-code=%d, resume the ctrl app",
			 cmd_type, param.close_session_resp.response);
		acb->got_param = param;
		break;

	case IPC_MEM_CMD_LITE_FLOW_CTL_ACK:
		/* This command type is not expected as response for
		 * Aggregation version of the protocol. So return non-zero.
		 */
		if (mux->protocol != MUX_LITE)
			return -EINVAL;

		ipc_dbg("if[%u] FLOW_CTL_ACK(%u) received",
			   if_id, transaction_id);
		break;

	case IPC_MEM_CMD_FLOW_CTL_ACK:
		/* This command type is not expected as response for
		 * Lite version of the protocol. So return non-zero.
		 */
		if (mux->protocol == MUX_LITE)
			return -EINVAL;

		ipc_dbg("if[%u] FLOW_CTL_ACK(%u) received",
			   if_id, transaction_id);
		break;

	default:
		return -EINVAL;
	}

	acb->wanted_response = IPC_MEM_CMD_INVALID;
	acb->got_response = cmd_type;
	ipc_completion_signal(&mux->channel->ul_sem);

	return 0;
}

/**
 * Process Downlink Commands and take actions accordingly
 */
static int mux_dl_dlcmds_decode_process(struct ipc_imem *this,
		struct imem_mux *mux, u32 cmd_type, int if_id,
		u32 transaction_id, u32 len, union ipc_mem_cmd_param *param)
{
	struct imem_mux_session *session;
	int new_size;

	if (unlikely(!this)) {
		ipc_err("invalid args");
		return -1;
	}
	ipc_dbg("if_id[%d]: dlcmds decode process %d", if_id, cmd_type);

	ipc_trc_dl_mux_cmd(cmd_type, transaction_id, if_id, mux);

	switch (cmd_type) {
	case IPC_MEM_CMD_FLOW_CTL_DISABLE:
	case IPC_MEM_CMD_FLOW_CTL_ENABLE:

		if (if_id < 0 || if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
			ipc_err("if_id [%d] not valid", if_id);
			return -EINVAL;		/* No session interface id. */
		}

		session = &mux->session[if_id];

		new_size = mux_get_offset_of_cmd_params(mux) +
						sizeof(param->flow_ctl);
		if (cmd_type == mux_get_flow_ctrl_en_cmd(mux)
		&& mux_check_flow_ctrl_mask(mux,
				param->flow_ctl.mask, 0xFFFFFFFF)) {
			if (this->params->mux_flow_ctrl_en) {
				/* Backward Compatibility */
				if (len == new_size)
					session->flow_ctl_mask =
						    param->flow_ctl.mask;
				else
					session->flow_ctl_mask = ~0;

				/**
				 * if CP asks for FLOW CTRL Enable
				 * then set our internal flow control Tx flag
				 * to limit uplink session queueing
				 */
				session->net_tx_stop = true;

				/* We have to call Finish ADB here.
				 * Otherwise any already queued data
				 * will be sent to CP when ADB is full
				 * for some other sessions.
				 */
				if (mux->protocol == MUX_AGGREGATION)
					mux_ul_adb_finish(this, mux);

				/* Stop the ADB Finish timer if
				 * running
				 */
				imem_mux_finish_adb_timer_stop(this);
			}
			/* Update the stats */
			session->flow_ctl_en_cnt++;
		} else if (cmd_type == mux_get_flow_ctrl_dis_cmd(mux)
			&& mux_check_flow_ctrl_mask(mux,
					param->flow_ctl.mask, 0)) {
			if (this->params->mux_flow_ctrl_en) {
				/* Backward Compatibility */

				/* Just reset the Flow control mask and let
				 * mux_flow_ctrl_low_thre_b take control on
				 * our internal Tx flag and enabling kernel
				 * flow control
				 */

				if (len == new_size)
					session->flow_ctl_mask =
						    param->flow_ctl.mask;
				else
					session->flow_ctl_mask = 0;

			}
			/* Update the stats */
			session->flow_ctl_dis_cnt++;
		} else {
			break;
		}

		ipc_debugfs_mux_log_event(mux->dbg_stats,
				if_id,
				param->flow_ctl.mask ? true : false,
				transaction_id, mux->acc_adb_size,
				mux->acc_payload_size,
				mux->session[if_id].ul_flow_credits);

		/* Reset the stats */
		mux->acc_adb_size = 0;
		mux->acc_payload_size = 0;
		ipc_dbg("if[%u] FLOW CTRL 0x%08X",
					   if_id, param->flow_ctl.mask);
		break;

	case IPC_MEM_CMD_LITE_LINK_STATUS_REPORT:
	case IPC_MEM_CMD_LINK_STATUS_REPORT:
		if ((mux->protocol == MUX_AGGREGATION &&
			cmd_type == IPC_MEM_CMD_LINK_STATUS_REPORT)
		|| (mux->protocol == MUX_LITE &&
			cmd_type == IPC_MEM_CMD_LITE_LINK_STATUS_REPORT))  {
#if defined(IPC_DEBUG)
			u8 *payload;
			char line[200];
			char asc[32];
			u32 tmp;
			u32 i, n;

			tmp = len - mux_get_offset_of_cmd_params(mux);
			ipc_dbg("Link Status Report (%u bytes)", tmp);
			payload = param->link_status.payload;
			if (tmp > len) {
				ipc_dbg("tmp invalid, len:%u", len);
				break;
			}
			for (i = 0, n = 0; i < tmp; i++) {
				if (i % 16 == 0 && n > 0) {
					ipc_dbg("%-48s %s", line, asc);
					n = 0;
				}
				n += sprintf(&line[n], "%02X ", payload[i]);
				asc[i%16] = isprint(payload[i]) ?
						payload[i] : '.';
				asc[(i%16)+1] = 0;
			}
			if (n > 0)
				ipc_dbg("%-48s %s", line, asc);
#endif	/* IPC_DEBUG */
		}
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/**
 * Respond to the Command blocks
 */
static int mux_dl_acb_send_cmds(
		struct ipc_imem *this, struct imem_mux *mux,
		u32 cmd_type, u8 if_id, u32 transaction_id,
		union ipc_mem_cmd_param *param, size_t res_size,
		bool blocking, bool respond)
{
	struct ipc_mem_cmdh *ack = NULL;
	struct ipc_mem_lite_cmdh *ack_lite = NULL;
	struct imem_mux_acb *acb = &(mux->acb);

	/* Allocate a skbuf for an IP MUX command. */
	acb->if_id = if_id;
	if (!mux_acb_alloc(this, mux)) {
		ipc_err("mux_acb_alloc returned NULL");
		return -ENOMEM;	/* No memory. */
	}

	if (mux->protocol == MUX_LITE) {
		/* ADAM-Lite does not need ACB header */
		ack_lite = mux_lite_add_cmd(this, cmd_type, mux, acb,
					param, res_size);

		if (!ack_lite)
			return -EINVAL;

		if (respond)
			ack_lite->transaction_id = (u32)transaction_id;
	} else {
		/* Initialize the ACB header. */
		mux_acb_init(mux);
		ack = mux_acb_add_cmd(this, cmd_type, mux, param, res_size);
		if (respond)
			ack->transaction_id = (u32)transaction_id;
	}

	/* Send the command */
	if (mux_acb_send(this, mux, blocking) != IPC_OK)
		return -ETIMEDOUT; /* This could be -EIO too ?? */

	/* trace the responses sent to CP */
	ipc_trc_dl_mux_sndresp(cmd_type, transaction_id, if_id, mux);

	return 0;
}

/* Decode an aggregated command block. */
static void mux_dl_acb_decode(struct ipc_imem *this, struct imem_mux *mux,
		struct sk_buff *skb)
{
	struct ipc_mem_acbh *acbh = NULL;
	struct ipc_mem_cmdh *cmdh = NULL;
	u8 *block = NULL;
	u32 next_command_index = 0;

	if (!skb || !skb->data) {
		ipc_err("invalid skb parameters");
		return;
	}
	/* Define local data. */
	acbh = (struct ipc_mem_acbh *)skb->data;
	block = (u8 *) skb->data;

	/* Loop thru all commands. */
	next_command_index = acbh->first_command_index;
	while (next_command_index != 0) {
		cmdh = (struct ipc_mem_cmdh *)&block[next_command_index];
		next_command_index = cmdh->next_command_index;
		if (mux_dl_cmdresps_decode_process(this, mux,
			cmdh->command_type, cmdh->if_id,
			cmdh->transaction_id, cmdh->param)) {
			if (!mux_dl_dlcmds_decode_process(this, mux,
					cmdh->command_type, cmdh->if_id,
					cmdh->transaction_id,
					cmdh->cmd_len, &cmdh->param)) {
				union ipc_mem_cmd_param *cmd_p = NULL;
				size_t size = 0;
				u32 cmd = IPC_MEM_CMD_LINK_STATUS_REPORT_RESP;

				if (cmdh->command_type ==
					IPC_MEM_CMD_LINK_STATUS_REPORT) {
					cmd_p = &cmdh->param;
					cmd_p->link_status_resp.response =
						IPC_MEM_CMD_RESP_SUCCESS;
					/* response field is u32 */
					size = sizeof(u32);
				} else if ((cmdh->command_type ==
					IPC_MEM_CMD_FLOW_CTL_ENABLE)
				|| (cmdh->command_type ==
					IPC_MEM_CMD_FLOW_CTL_DISABLE))
					cmd = IPC_MEM_CMD_FLOW_CTL_ACK;
				else
					continue;

				/* Respond to the Downlink commands */
				mux_dl_acb_send_cmds(this, mux,
					cmd, cmdh->if_id, cmdh->transaction_id,
					cmd_p, size, false, true);
			}
		}
	}			/* end while */
}				/* mux_dl_acb_decode */

/**
 * Decode and Send approriate response to a command block.
 */
static void mux_dl_cmd_decode(struct ipc_imem *this, struct imem_mux *mux,
		struct sk_buff *skb)
{
	struct ipc_mem_lite_cmdh *cmdh = NULL;

	if (!skb || !skb->data) {
		ipc_err("invalid skb parameters");
		return;
	}
	/* Define local data. */
	cmdh = (struct ipc_mem_lite_cmdh *)skb->data;

	if (mux_dl_cmdresps_decode_process(this, mux, cmdh->command_type,
		cmdh->if_id, cmdh->transaction_id, cmdh->param)) {
		/* Unable to decode command response indicates the cmd_type
		 * may be a command instead of response. So try to decoding it.
		 */
		if (!mux_dl_dlcmds_decode_process(this, mux,
				cmdh->command_type, cmdh->if_id,
				cmdh->transaction_id, cmdh->cmd_len,
				&cmdh->param)) {
			/* Decoded command may need a response. Give the
			 * response according to the command type.
			 */
			union ipc_mem_cmd_param *cmd_p = NULL;
			size_t size = 0;
			u32 cmd = IPC_MEM_CMD_LITE_LINK_STATUS_REPORT_RESP;

			if (cmdh->command_type ==
				IPC_MEM_CMD_LITE_LINK_STATUS_REPORT) {
				cmd_p = &cmdh->param;
				cmd_p->link_status_resp.response =
						IPC_MEM_CMD_RESP_SUCCESS;
				/* response field is u32 */
				size = sizeof(u32);
			} else if (cmdh->command_type ==
					IPC_MEM_CMD_LITE_FLOW_CTL)
				cmd = IPC_MEM_CMD_LITE_FLOW_CTL_ACK;
			else
				return;

			mux_dl_acb_send_cmds(this, mux, cmd, cmdh->if_id,
						cmdh->transaction_id,
						cmd_p, size, false, true);
		}
	}
}				/* mux_dl_cmd_decode */

static void mux_trigger_receive_trace(struct ipc_imem *this,
		struct imem_mux *mux, u32 cnt)
{
	int i;
	unsigned long rx_packets, rx_bytes;


	/* Trace out dl rcv stats for all active sessions */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {

		/* Is the session opened. */
		if (!mux->session[i].wwan ||
				mux->session[i].flow_ctl_mask)
			continue;

		if (ipc_wwan_get_vlan_stats(this->wwan, i, false, &rx_packets,
					&rx_bytes) == 0)

			ipc_trc_dl_rx_stat(i, mux->session[i].dl_head_pad_len,
					mux->channel->dl_pipe.pipe_nr,
					mux->channel->dl_pipe.nr_of_entries,
				mux->channel->dl_pipe.max_nr_of_queued_entries,
				cnt, rx_packets, rx_bytes);
	}
}

/* Pass the DL packet to the netif layer.
 */
static int mux_net_receive(struct ipc_imem *this, int if_id,
	struct ipc_wwan *wwan, void *buf,
	int len, u8 service_class, struct sk_buff *skb)
{
	struct sk_buff *dest_skb;
	unsigned char *dest_skb_tail_tmp;

	if (skb) {
		/* for "zero copy" use clone */
		dest_skb = skb_clone(skb, GFP_ATOMIC);
		if (!dest_skb) {
			ipc_err("skb clone fail");
			return 0;
		}
		dest_skb->truesize = SKB_TRUESIZE(len);
		dest_skb->data = buf;
		dest_skb->len = len;
		skb_set_tail_pointer(dest_skb, len);
		/* Goto the start of the Ethernet header. */
		skb_push(dest_skb, ETH_HLEN);
	} else {
		/* XXX Allocate a skbuf and copy the payload,
		 * shall be optimized by skb_clone.
		 * This skb is not a shared memory skb so
		 * no need to reconfigure for PARC address ranges
		 */
		dest_skb = ipc_pcie_alloc_local_skb(this->pcie, GFP_ATOMIC,
							len);
		if (!dest_skb) {
			ipc_trc_dl_mem_alloc_fail(len + IPC_MEM_DL_ETH_OFFSET);
			ipc_err("no memory for DL packet");
			return 0;
		}

		/* Reserve space for the Ethernet header and copy the packet. */
		skb_reserve(dest_skb, IPC_MEM_DL_ETH_OFFSET);
		dest_skb_tail_tmp = skb_put(dest_skb, len);
		if (dest_skb_tail_tmp)
			memcpy(dest_skb_tail_tmp, buf, len);

		/* Goto the start of the Ethernet header. */
		skb_push(dest_skb, ETH_HLEN);
	}
	/* map session to vlan */
	__vlan_hwaccel_put_tag(dest_skb, htons(ETH_P_8021Q), if_id + 1);

	/* Pass the packet to the netif layer. */
	dest_skb->priority = service_class;
	ipc_wwan_receive(wwan, dest_skb, false);
	return 1;
}				/* mux_net_receive */

/**
 * Decode Flow Credit Table in the block
 */
static void mux_dl_fcth_decode(struct ipc_imem *this,
		struct imem_mux *mux, void *p_block)
{
	int if_id = 0;
	struct ipc_wwan *wwan = NULL;
	int ul_credits = 0;
	struct ipc_mem_lite_gen_tbl *p_fct;

	if (!mux || !p_block) {
		ipc_err("Invalid arguments");
		return;
	}

	/* Decode the flow credit.
	 */
	p_fct = (struct ipc_mem_lite_gen_tbl *)p_block;

	if (p_fct->vfl_length != sizeof(p_fct->vfl[0].nr_of_bytes)) {
		ipc_err("Unexpected FCT length: %d", p_fct->vfl_length);
		return;
	}

	if_id = p_fct->if_id;
	if (if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
		ipc_err("Not supported if_id: %d", if_id);
		return;
	}

	/* Is the session active ? */
	wwan = mux->session[if_id].wwan;
	if (!wwan) {
		ipc_err("Session Net ID is NULL");
		return;
	}

	ul_credits = p_fct->vfl[0].nr_of_bytes;

	ipc_dbg("Flow_Credit:: if_id[%d] Old: %d Grants: %d",
		if_id, mux->session[if_id].ul_flow_credits, ul_credits);

	/* Update the Flow Credit information from ADB */
	mux->session[if_id].ul_flow_credits += ul_credits;

	/* Check whether the TX can be started */
	if (mux->session[if_id].ul_flow_credits > 0) {
		mux->session[if_id].net_tx_stop = false;
		mux_netif_tx_flowctrl(&mux->session[if_id],
				mux->session[if_id].if_id, false);
	}

	/* Trace the current queue status */
	ipc_trc_ul_mux_crd_fc(if_id, mux->channel->ul_pipe.pipe_nr, 1,
			mux->channel->ul_pipe.nr_of_entries,
			mux->channel->ul_pipe.max_nr_of_queued_entries,
			mux->channel->ul_pipe.nr_of_queued_entries,
			mux->channel->ul_list.nr_of_bytes, mux);

	/* Log the MUX Debug event */
	ipc_debugfs_mux_log_event(mux->dbg_stats, if_id,
		mux->session[if_id].flow_ctl_mask != 0,
		-1 /* Use this txn id to log ul credits */,
		mux->acc_adb_size, mux->acc_payload_size,
		mux->session[if_id].ul_flow_credits);
}				/* mux_dl_fcth_decode */

/* Decode an aggregated data block. */
static void mux_dl_adb_decode(struct ipc_imem *this,
			struct imem_mux *mux, struct sk_buff *skb)
{
	struct ipc_mem_adbh *adbh;
	struct ipc_mem_adth *adth;
	u8 *block;
	u32 adth_index;
	u32 dl_head_pad_len;
	u32 dg_cnt;
	u32 if_cnt;
	u32 payload_size;

	struct ipc_mem_adth_dg *dg;
	int nr_of_dg, i, if_id, rc;
	struct ipc_wwan *wwan;

	/* Initialize the local data. */
	block = skb->data;
	adbh = (struct ipc_mem_adbh *)block;

	/* Process the aggregated datagram tables. */
	adth_index = adbh->first_table_index;

	/* Has CP sent an empty ADB ? */
	if (adth_index < 1)
		ipc_err("unexpected empty ADB");

	/* Loop thru mixed session tables. */
	dg_cnt = 0;
	if_cnt = 0;
	payload_size = 0;
	while (adth_index) {
		/* Get the reference to the table header. */
		adth = (struct ipc_mem_adth *)(block + adth_index);

		/* Get the interface id and map it to the netif id. */
		if_id = adth->if_id;
		if (if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
			ipc_err("decode error at line %d", __LINE__);
			return;
		}

		dl_head_pad_len = mux->session[if_id].dl_head_pad_len;

		/* Is the session active ? */
		wwan = mux->session[if_id].wwan;
		if (!wwan) {
			ipc_err("Session Net ID is NULL");
			return;
		}

		/* Consistency checks for aggregated datagram table. */
		if (adth->signature != IPC_MEM_SIG_ADTH) {
			ipc_err("ADTH signature not matching");
			return;
		}

		if (adth->table_length < (sizeof(struct ipc_mem_adth) -
				sizeof(struct ipc_mem_adth_dg))) {
			ipc_err("ADTH Table Legth not matching the spec");
			return;
		}

		/* Calculate the number of datagrams. */
		nr_of_dg = (adth->table_length -
					sizeof(struct ipc_mem_adth) +
					sizeof(struct ipc_mem_adth_dg)) /
					sizeof(struct ipc_mem_adth_dg);

		ipc_dbg("if=%u, nr_of_dg=%u", if_id, nr_of_dg);

		/* Is the datagram table empty ? */
		if (nr_of_dg < 1) {
			ipc_err("empty ADT:if=%u,blklen=%u,tblen=%hu",
				if_id, adbh->block_length,
				adth->table_length);
			ipc_err("adthidx=%u,nr_of_dg=%d,next_tblidx=%u",
				adth_index, nr_of_dg, adth->next_table_index);

			/* Move to the next aggregated datagram table. */
			adth_index = adth->next_table_index;
			continue;
		}

		/* New aggregated datagram table. */
		dg = &adth->dg[0];

		/* Process the aggregated datagram table. */
		if_cnt++;
		dg_cnt += nr_of_dg;
		for (i = 0; i < nr_of_dg; i++, dg++) {
			if (dg->datagram_index < sizeof(struct ipc_mem_adbh)) {
				ipc_err("decode error at line %d", __LINE__);
				return;
			}

			/* Is the packet inside of the ADB ? */
			if (dg->datagram_index >= adbh->block_length) {

				ipc_err("wrong dgidx: if=%u,blk=%u,tbl=%hu",
					if_id, adbh->block_length,
					adth->table_length);
				ipc_err("adthidx=%u,dgs=%d,i=%d,dgidx=%u,dglen=%hu",
					adth_index, nr_of_dg, i,
					dg->datagram_index,
					dg->datagram_length);

			} else {
				/* Pass the packet to the netif layer. */
				rc = mux_net_receive(this, if_id, wwan,
						block + dg->datagram_index
						+ dl_head_pad_len,
						dg->datagram_length
						- dl_head_pad_len,
						dg->service_class, skb);
				if (!rc) {
					ipc_err("decode error at line %d",
						__LINE__);
					return;
				}

				payload_size += dg->datagram_length -
						dl_head_pad_len;
			}
		}		/* end for */

		/* mark session for final flush */
		mux->session[if_id].flush = 1;

		/* Move to the next aggregated datagram table. */
		adth_index = adth->next_table_index;
	}			/* end while */

	ipc_dbg(
	"DL ADB: seq_nr = %hu, size=%u, if_cnt=%u, dg_cnt=%u, payload=%u",
		adbh->sequence_nr, adbh->block_length, if_cnt, dg_cnt,
		payload_size);
}				/* mux_dl_adb_decode */

/**
 * Decode non-aggregated datagram
 */
static void mux_dl_adgh_decode(struct ipc_imem *this,
			struct imem_mux *mux, struct sk_buff *skb)
{
	struct ipc_mem_adgh *adgh;
	u8 *block;
	u8 if_id;
	u32 pad_len, packet_offset;
	struct ipc_wwan *wwan;
	int rc = 0;

	if (!skb || !skb->data) {
		ipc_err("skb not valid");
		return;
	}

	block = skb->data;
	adgh = (struct ipc_mem_adgh *)block;

	if (adgh->signature != IPC_MEM_SIG_ADGH) {
		ipc_err("Invalid ADGH signature received");
		return;
	}

	/* Get the interface id and map it to the netif id */
	if_id = adgh->if_id;
	if (if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
		ipc_err("invalid if_id while decoding %d", if_id);
		return;
	}

	/* Is the session active ? */
	wwan = mux->session[if_id].wwan;
	if (!wwan) {
		ipc_err("Session Net ID is NULL");
		return;
	}

	/* Store the pad len for the correspoding session
	 * Pad bytes as negotiated in the open session less the header size
	 * (see session management chapter for details).
	 * If resulting padding is zero or less, the additional head padding is
	 * omitted. For e.g., if HEAD_PAD_LEN = 16 or less, this field is
	 * omitted if HEAD_PAD_LEN = 20, then this field will have 4 bytes
	 * set to zero
	 */
	pad_len = mux->session[if_id].dl_head_pad_len - IPC_MEM_DL_ETH_OFFSET;
	packet_offset = sizeof(struct ipc_mem_adgh) + pad_len;

	ipc_dbg("DL ADGH: if_id = %d, size = %u, payload = %d",
			if_id, adgh->length, adgh->length -  packet_offset);

	/* Pass the packet to the netif layer */
	rc = mux_net_receive(this, if_id, wwan,
			block + packet_offset,
			adgh->length - packet_offset,
			adgh->service_class, skb);
	if (!rc) {
		ipc_err("mux adgh decoding error");
		return;
	}
	mux->session[if_id].flush = 1;
}


/* Route the DL packet through the IP MUX layer. */
static void mux_dl_process(struct ipc_imem *this, struct imem_mux *mux,
		struct sk_buff *skb)
{
	u32 *signature;

	if (unlikely(!skb || !skb->data || !this)) {
		ipc_err("invalid parameters");
		return;
	}

	/* Decode the MUX header type. */
	signature = (u32 *)skb->data;

	switch (*signature) {
	case IPC_MEM_SIG_ADBH:	/* Aggregated Data Block Header */
		mux_dl_adb_decode(this, mux, skb);
		break;

	case IPC_MEM_SIG_ADGH:
		mux_dl_adgh_decode(this, mux, skb);
		break;

	case IPC_MEM_SIG_FCTH:
		mux_dl_fcth_decode(this, mux, skb->data);
		break;

	case IPC_MEM_SIG_ACBH:	/* Aggregated Command Block Header */
		/* Decode an aggregated command block. */
		mux_dl_acb_decode(this, mux, skb);
		break;

	case IPC_MEM_SIG_CMDH:
		mux_dl_cmd_decode(this, mux, skb);
		break;

	default:
		ipc_err("invalid ABH signature");
	}			/* end switch */

	ipc_pcie_kfree_skb(this->pcie, skb);
}				/* mux_dl_process */

#ifdef IPC_INCLUDE_FTRACE_SYMBOL
EXPORT_SYMBOL(mux_dl_process);
#endif

/* Route the UL packet through the IP MUX layer. */
static int mux_net_transmit(struct ipc_imem *this,
		struct imem_mux *mux, int if_id, struct sk_buff *skb)
{
	struct ipc_mem_channel *channel;
	struct imem_mux_session *session;

	/* Entry condition. */
	if (if_id < 0 || if_id >= IPC_IMEM_MUX_SESSION_ENTRIES) {
		ipc_err("interface error at line %d: (if_id=%d)",
			__LINE__, if_id);
		return -1;
	}

	if (!skb) {
		ipc_err("SKB is NULL");
		return -1;
	}

	/* Get the reference to the active channel.  */
	channel = mux->channel;
	if (!channel) {
		ipc_err("Channel is NULL");
		return -1;
	}

	/* Test the channel state. */
	if (channel->state != IMEM_CHANNEL_ACTIVE) {
		ipc_err("Channel state is not IMEM_CHANNEL_ACTIVE");
		return  -1;
	}

	/* Test the session state. */
	session = &mux->session[if_id];
	if (!session->wwan) {
		ipc_err("Session net ID is NULL");
		return -1;
	}

	/* Session is under flow control.
	 * Check if packet can be queued in session list, if not
	 * suspend net tx
	 */
	if (skb_queue_len(&session->ul_list.list)
			>= (session->net_tx_stop ?
				this->params->mux_netdev_flow_ctrl_threshold :
				(this->params->mux_netdev_flow_ctrl_threshold *
				 IPC_MEM_MUX_UL_SESS_FCOFF_THRESHOLD_FACTOR))) {
		mux_netif_tx_flowctrl(session, session->if_id, true);
		return -2;
	}

	/* Add skb to the uplink skb accumulator. */
	imem_ul_list_add(&session->ul_list, skb);

	/* Inform the IPC kthread to pass uplink IP packets to CP. */
	if (!this->ev_mux_net_transmit_pending) {
		this->ev_mux_net_transmit_pending = true;
		(void) ipc_tasklet_call_async(this->tasklet,
			imem_tl_mux_net_transmit, this, 0, NULL, 0);
	}

	ipc_dbg("if[%d] qlen=%d/%u, len=%d/%d, prio=%d",
		if_id, skb_queue_len(&session->ul_list.list),
		session->ul_list.nr_of_bytes, skb->len, skb->truesize,
		skb->priority);

	return 0;
}				/* mux_net_transmit */


/* Allocate  the destination skb and the datagram table. */
static int mux_ul_skb_alloc(struct ipc_imem *this,
		struct imem_mux_adb *ul_adb, u32 type)
{
	struct imem_mux *mux = NULL;
	struct ipc_skb_cb *skb_cb;
	struct sk_buff *skb;
	u32 if_id = 0;
	int qlt_size;

	/* Take the first element of the free list. */
	skb = skb_dequeue(&ul_adb->free_list);
	if (!skb)
		return -1;	/* Wait for a free ADB skb. */

	mux = container_of(ul_adb, struct imem_mux, ul_adb);
	if (!mux) {
		ipc_err("invalid mux pointer");
		return -1;
	}

	/* Mark it as UL ADB to select the right free operation. */
	skb_cb = (struct ipc_skb_cb *)skb->cb;
	skb_cb->op_type = (u8) UL_MUX_OP_ADB;

	switch (type) {
	case IPC_MEM_SIG_ADBH:
		/* Save the ADB memory settings. */
		ul_adb->dest_skb = skb;
		ul_adb->buf = skb->data;
		ul_adb->size = mux_get_ul_adb_size(mux->params, mux->protocol);

		/* reset statistic counter */
		ul_adb->if_cnt = 0;
		ul_adb->payload_size = 0;
		ul_adb->dg_cnt_total = 0;

		/* Initialize the ADBH. */
		ul_adb->adbh = (struct ipc_mem_adbh *)ul_adb->buf;

		memset(ul_adb->adbh, 0, sizeof(struct ipc_mem_adbh));
		ul_adb->adbh->signature = IPC_MEM_SIG_ADBH;
		ul_adb->adbh->block_length = sizeof(struct ipc_mem_adbh);
		ul_adb->next_table_index = &ul_adb->adbh->first_table_index;

		/* Clear the local copy of DGs for new ADB */
		memset(ul_adb->dg, 0, sizeof(ul_adb->dg));

		/* Clear the DG count and QLT updated status for new ADB */
		for (if_id = 0; if_id < IPC_IMEM_MUX_SESSION_ENTRIES; if_id++) {
			ul_adb->dg_count[if_id] = 0;
			ul_adb->qlt_updated[if_id] = 0;
		}
		break;

	case IPC_MEM_SIG_ADGH:
		/* Save the ADB memory settings. */
		ul_adb->dest_skb = skb;
		ul_adb->buf = skb->data;
		ul_adb->size = mux_get_ul_adb_size(mux->params, mux->protocol);

		/* reset statistic counter */
		ul_adb->if_cnt = 0;
		ul_adb->payload_size = 0;
		ul_adb->dg_cnt_total = 0;

		ul_adb->adgh = (struct ipc_mem_adgh *)skb->data;
		memset(ul_adb->adgh, 0, sizeof(struct ipc_mem_adgh));
		break;

	case IPC_MEM_SIG_QLTH:
		qlt_size = offsetof(struct ipc_mem_lite_gen_tbl, vfl) +
			(MUX_QUEUE_LEVEL * sizeof(struct ipc_mem_lite_vfl));

		if (qlt_size > mux->params->mux_lite_buf_size) {
			ipc_err("Can't support. QLT size:%d SKB size: %d",
				qlt_size, mux->params->mux_lite_buf_size);
			return -1;
		}

		ul_adb->qlth_skb = skb;
		memset(ul_adb->qlth_skb->data, 0, qlt_size);
		skb_put(skb, qlt_size);
		break;
	}

	return 0;
}				/* mux_ul_skb_alloc */

/* Add the TD of the aggregated session packets to the TDR. */
static void mux_ul_adb_finish(struct ipc_imem *this, struct imem_mux *mux)
{
	struct imem_mux_adb *ul_adb;
	int offset, i, adth_dg_size, qlt_size;
	struct ipc_mem_adth_dg *dg;
	struct ipc_mem_adth *adth;
	struct ipc_mem_qlth *p_adb_qlt;
	bool ul_data_pend = false;

	if (unlikely(!this || !mux)) {
		ipc_err("invalid args");
		return;
	}

	/* Get the reference to UL ADB state. */
	ul_adb = &mux->ul_adb;

	/* Entry condition. */
	if (!ul_adb->dest_skb)
		return;

	offset = *ul_adb->next_table_index;

	qlt_size = offsetof(struct ipc_mem_qlth, ql) +
		   MUX_QUEUE_LEVEL * sizeof(struct ipc_mem_qlth_ql);


	/* Walk through all open sessions to update ADT and QLT. */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {

		if (ul_adb->dg_count[i] > 0) {
			/* At least one packet for the session is added
			 *  - store the session_id to the table header
			 *  - store the size of the dg table to the table header
			 *  - DG bulk initialization: copy DG to skb
			 *  - extend the next_table_index "linked list"
			 *  - save the pointer to next_table_index
			 *    (for next_table_index "linked list")
			 */
			adth_dg_size = offsetof(struct ipc_mem_adth, dg) +
					ul_adb->dg_count[i] * sizeof(*dg);

			*ul_adb->next_table_index = offset;

			/* Define the position of the ADTH and fill it. */
			adth = (struct ipc_mem_adth *)&ul_adb->buf[offset];
			ul_adb->next_table_index = &adth->next_table_index;
			offset += adth_dg_size;
			adth->signature = IPC_MEM_SIG_ADTH;
			adth->if_id = i;
			adth->table_length = adth_dg_size;
			adth_dg_size -= offsetof(struct ipc_mem_adth, dg);

			/* Update the local copy of Aggregated Data Tabel(ADT)
			 * to ADB
			 */
			memcpy(adth->dg, ul_adb->dg[i], adth_dg_size);

			/* statistic */
			ul_adb->if_cnt++;
		}

		/* Update local copy of Queue Level Table (QLT) to ADB */
		if (ul_adb->qlt_updated[i]) {
			*ul_adb->next_table_index = offset;
			p_adb_qlt = (struct ipc_mem_qlth *)&ul_adb->buf[offset];
			ul_adb->next_table_index = &p_adb_qlt->next_table_index;

			memcpy(p_adb_qlt, ul_adb->p_qlt[i], qlt_size);

			offset += qlt_size;
		}
	}

	/* Update the ADB block length after adding ADT and QLT */
	ul_adb->adbh->block_length = offset;

	if (ul_adb->adbh->block_length > ul_adb->size) {
		ipc_err("ADB block_length:%d is > %d",
		  ul_adb->adbh->block_length, ul_adb->size);

		ul_adb->dest_skb = NULL;
		return;
	}

	/* - terminate TH "linked list"
	 * - clear the interface mask field
	 * - set ADBH sequence number
	 * - set the length
	 * - add the SKB to the transfer
	 */
	*ul_adb->next_table_index = 0;
	ul_adb->adbh->sequence_nr = mux->adb_tx_sequence_nr++;
	skb_put(ul_adb->dest_skb, ul_adb->adbh->block_length);
	imem_ul_list_add(&mux->channel->ul_list, ul_adb->dest_skb);

	ul_adb->dest_skb = NULL;

	/* Updates the TDs with ul_list */
	ul_data_pend = imem_ul_write_td(this);

	/* Delay the doorbell irq */
	if (ul_data_pend)
		imem_td_update_timer_start(this);

	/* Report ADB information */
	ipc_dbg(
	"UL ADB: size=%d, if_cnt=%u, dg_cnt_total=%u, payload=%u, seq_nr=%d",
		ul_adb->adbh->block_length, ul_adb->if_cnt,
		ul_adb->dg_cnt_total, ul_adb->payload_size,
		ul_adb->adbh->sequence_nr);

	mux->acc_adb_size +=  ul_adb->adbh->block_length;
	mux->acc_payload_size += ul_adb->payload_size;

	/* If any of the opened session has set the Flow control ON then start
	 * calculating the UL data sent to limit the UL data to
	 * mux_flow_ctrl_high_thresh_b bytes
	 */
	if (this->params->mux_flow_ctrl_en) {
		mux->ul_data_pend_bytes += ul_adb->payload_size;

		ipc_dbg("acc_adb_size:%llu, acc_payload_size: %llu",
				mux->acc_adb_size, mux->acc_payload_size);
		ipc_dbg("ul_data_pend_bytes:%lld",
				mux->ul_data_pend_bytes);
	}
}				/* mux_ul_adb_finish */

/* finish ADGH */
void mux_ul_adgh_finish(struct ipc_imem *this, struct imem_mux *mux)
{
	struct imem_mux_adb *ul_adb;
	char *p_str = NULL;
	long long bytes;

	if (!mux) {
		ipc_err("Invalid argument");
		return;
	}

	/* Get the reference to UL ADB state. */
	ul_adb = &mux->ul_adb;

	/* Entry condition. */
	if (!ul_adb || !ul_adb->dest_skb) {
		ipc_err("No dest skb");
		return;
	}
	mux->acc_adb_size +=  ul_adb->adgh->length;
	mux->acc_payload_size += ul_adb->payload_size;
	skb_put(ul_adb->dest_skb, ul_adb->adgh->length);
	imem_ul_list_add(&mux->channel->ul_list, ul_adb->dest_skb);
	ul_adb->dest_skb = NULL;

	if (mux->ul_flow == MUX_UL_ON_CREDITS) {
		struct imem_mux_session *p_session;

		p_session = &mux->session[ul_adb->adgh->if_id];
		p_str = "available_credits";
		bytes = (long long)(p_session ? p_session->ul_flow_credits : 0);

	} else {
		p_str = "pend_bytes";
		bytes = mux->ul_data_pend_bytes;

		if (mux->params->mux_flow_ctrl_en)
			mux->ul_data_pend_bytes += ul_adb->adgh->length;
	}

	ipc_dbg("UL ADGH: size=%d, if_id=%d, payload=%d, %s=%lld",
			ul_adb->adgh->length,
			ul_adb->adgh->if_id,
			ul_adb->payload_size,
			p_str, bytes);
}

/* Adds Queue Level Table and Queue Level to ADB */
void mux_ul_adb_update_ql(struct ipc_imem *this, struct imem_mux_adb *p_adb,
		int session_id, int qlth_n_ql_size, int qlevel)
{
	struct ipc_mem_qlth *p_qlt;
	int ql_idx;

	/* Update local copy of Queue Level Tabel */
	if (MUX_QUEUE_LEVEL > 0) {
		p_qlt = (struct ipc_mem_qlth *)p_adb->p_qlt[session_id];

		/* Initialize QLTH if not been done */
		if (p_adb->qlt_updated[session_id] == 0) {
			p_qlt->signature = IPC_MEM_SIG_QLTH;
			p_qlt->if_id = session_id;
			p_qlt->table_length = qlth_n_ql_size;
			p_qlt->reserved = 0;
			p_qlt->reserved2 = 0;
		}

		/* Update Queue Level information awlays */
		for (ql_idx = 0; ql_idx < MUX_QUEUE_LEVEL; ql_idx++) {
			p_qlt->ql[ql_idx].nr_of_bytes = qlevel;
			ipc_dbg("if[%d] queue_level[%u]=%u",
				   session_id, ql_idx, qlevel);
		}

		p_adb->qlt_updated[session_id] = 1;
	}

}				/* mux_ul_adb_update_ql */


/* Allocates an ADB from the free list and initializes it with ADBH  */
bool mux_ul_adb_allocate(struct ipc_imem *this,
		struct imem_mux_adb *p_adb, int *p_size_needed,
			u32 type)
{
	int status;
	bool ret_val = false;

	/* Test the presence of ADB memory. */
	if (!p_adb->dest_skb) {
		/* Allocate memory for the ADB including of the
		 * datagram table header.
		 */
		status = mux_ul_skb_alloc(this, p_adb, type);
		if (status != 0) {
			/* Is a pending ADB available ? */
			ret_val = true;	/* None. */
		}

		/* Update size need to zero only for new ADB memory */
		*p_size_needed = 0;
	}

	return ret_val;
}				/* mux_ul_adb_allocate */


/* Informs the network stack to restart transmission for all opened session if
 * Flow Control is not ON for that session.
 */
static void mux_restart_tx_for_all_sessions(struct imem_mux *p_mux)
{
	struct imem_mux_session *p_session;
	int idx;

	for (idx = 0; idx < IPC_IMEM_MUX_SESSION_ENTRIES; idx++) {
		p_session = &p_mux->session[idx];

		/* Check if session is opened */
		if (!p_session->wwan)
			continue;

		/* If flow control of the session is OFF and if there was tx
		 * stop then restart. Inform the network interface to restart
		 * sending data.
		 */
		if (p_session->flow_ctl_mask == 0) {
			p_session->net_tx_stop = false;
			mux_netif_tx_flowctrl(p_session, idx, false);
		}
	}
}				/* mux_restart_tx_for_all_sessions */


/* Informs the network stack to stop sending further packets for all opened
 * sessions
 */
static void mux_stop_tx_for_all_sessions(struct imem_mux *p_mux)
{
	struct imem_mux_session *p_session;
	int idx;

	for (idx = 0; idx < IPC_IMEM_MUX_SESSION_ENTRIES; idx++) {
		p_session = &p_mux->session[idx];

		/* Check if session is opened */
		if (!p_session->wwan)
			continue;

		p_session->net_tx_stop = true;
	}
}				/* mux_stop_tx_for_all_sessions */

/* Informs the network stack to stop sending further packets for all opened
 * sessions
 */
static void mux_stop_netif_for_all_sessions(struct imem_mux *p_mux)
{
	struct imem_mux_session *p_session;
	int idx;

	for (idx = 0; idx < IPC_IMEM_MUX_SESSION_ENTRIES; idx++) {
		p_session = &p_mux->session[idx];

		/* Check if session is opened */
		if (p_session->wwan == NULL)
			continue;

		mux_netif_tx_flowctrl(p_session, p_session->if_id, true);
	}
}				/* mux_stop_netif_for_all_sessions */

/* Inline function to log and stop UL TX queue.
 */
static inline void mux_stop_ul_data_encoding(struct ipc_imem *this,
				struct imem_mux *p_mux)
{
	ipc_dbg("Stopping encoding. PendBytes: %llu, high_thresh: %d",
		p_mux->ul_data_pend_bytes,
		p_mux->params->mux_flow_ctrl_high_thresh_b);

	mux_stop_tx_for_all_sessions(p_mux);
}				/* mux_stop_ul_data_encoding */

/**
 * Process encode session UL data to ADB
 */
static int mux_ul_adb_encode(
		struct ipc_imem *this,
		struct imem_mux *mux, int session_id,
		struct imem_mux_session *session,
		struct imem_ul_queue *ul_list,
		struct imem_mux_adb *adb,
		int pkt_to_send)
{
	struct ipc_mem_adth_dg *dg;
	struct sk_buff *src_skb;
	int nr_of_skb = 0;
	int aligned_size;
	int offset;
	int head_pad_len;
	u32 qlth_n_ql_size;
	int adb_updated = -EINVAL;
	unsigned long tx_packets, tx_bytes;

	/* If any of the opened session has set Flow Control ON then limit the
	 * UL data to mux_flow_ctrl_high_thresh_b bytes
	 */
	if (this->params->mux_flow_ctrl_en &&
		mux->ul_data_pend_bytes >=
		this->params->mux_flow_ctrl_high_thresh_b) {

		mux_stop_ul_data_encoding(this, mux);
		return 0;
	}

	qlth_n_ql_size = offsetof(struct ipc_mem_qlth, ql) +
			 MUX_QUEUE_LEVEL * sizeof(struct ipc_mem_qlth_ql);

	/* Read configured UL head_pad_length for session.*/
	head_pad_len = session->ul_head_pad_len;

	if (mux_ul_adb_allocate(this, adb, &mux->size_needed,
		IPC_MEM_SIG_ADBH)) {
		ipc_err("No reserved memory for ADB");
		return -ENOMEM;
	}

	/* Load next available offset in buffer. */
	offset = adb->adbh->block_length;

	/* Calculate the size needed to prepare an ADB
	 * considering offset, QLTH and QL size.
	 */
	if (mux->size_needed == 0)
		mux->size_needed = offset;

	/* Calculate the size needed for ADTH, QLTH and QL
	 * if not have been considered already.
	 */
	if (adb->dg_count[session_id] == 0) {
		mux->size_needed += offsetof(struct ipc_mem_adth, dg);
		mux->size_needed += qlth_n_ql_size;
	}

	/* Load pointer to next available datagram entry. */
	dg = adb->dg[session_id] + adb->dg_count[session_id];

	/* Process all pending UL packets for this session
	 * depending on the allocated datagram table size.
	 */
	while (pkt_to_send > 0) {

		/* Peek at the head of the list. */
		src_skb = skb_peek(&ul_list->list);
		if (!src_skb) {
			ipc_err("skb peek return NULL with count : %d",
					pkt_to_send);
			break;
		}

		/* Calculate the memory value. */
		aligned_size = MUX_ALIGN32(head_pad_len + src_skb->len);

		/* Reserve the space for Payload and Datagram
		 * of ADT in ADB
		 */
		mux->size_needed += sizeof(*dg) + aligned_size;

		/* Check if there is enough space left */
		if (mux->size_needed > adb->size
		|| (this->params->mux_flow_ctrl_en
		&& (mux->size_needed + mux->ul_data_pend_bytes)
		>= this->params->mux_flow_ctrl_high_thresh_b)) {
			/* Update the next table index */
			*adb->next_table_index = offset;

			mux_ul_adb_update_ql(this, adb, session_id,
						qlth_n_ql_size,
						ul_list->nr_of_bytes);

			mux_ul_adb_finish(this, mux);

			if (this->params->mux_flow_ctrl_en &&
				(mux->ul_data_pend_bytes >=
				this->params->mux_flow_ctrl_high_thresh_b)) {
				ipc_dbg("No ADB Preperation");
				ipc_dbg("PendBytes:%llu, high_thresh:%d",
						mux->ul_data_pend_bytes,
				this->params->mux_flow_ctrl_high_thresh_b);
				/* Trace flow control condition */
				ipc_trc_ul_mux_flowctrl(1,
				this->params->mux_flow_ctrl_high_thresh_b,
					mux->ul_data_pend_bytes,
					mux->channel->ul_pipe.pipe_nr,
					mux->channel->ul_pipe.nr_of_entries,
				mux->channel->ul_pipe.max_nr_of_queued_entries,
				mux->channel->ul_pipe.nr_of_queued_entries,
				mux->channel->ul_list.nr_of_bytes);
				return 1;
			}

			/* If there are still pending data then start
			 * preparing new ADB
			 */
			if (pkt_to_send > 0) {
				if (mux_ul_adb_allocate(this, adb,
							&mux->size_needed,
							IPC_MEM_SIG_ADBH)) {
					ipc_err("No memory for ADB");
					return -ENOMEM;
				}

				offset = adb->adbh->block_length;
				mux->size_needed = adb->adbh->block_length;

				/* Calculate the size needed for
				 * ADTH, QLTH and QL and reserve
				 * the space in	ADB.
				 */
				mux->size_needed +=
					offsetof(struct ipc_mem_adth, dg);
				mux->size_needed += qlth_n_ql_size;
				/* Reserve the space for Payload
				 * and Datagram of ADT in ADB.
				 */
				mux->size_needed += sizeof(*dg) + aligned_size;

				nr_of_skb = 0;

				/* Load pointer to next available datagram
				 * entry.
				 */
				dg = adb->dg[session_id] +
						adb->dg_count[session_id];

			}

		}

		ipc_wwan_update_stats(session->wwan, session_id,
					src_skb->len, true);
		/* Add buffer (without head padding to next pending transfer.
		 */
		memcpy(adb->buf + offset + head_pad_len,
					src_skb->data, src_skb->len);
		/* Setup datagram entry. */
		dg->datagram_index = offset;
		dg->datagram_length = src_skb->len + head_pad_len;
		dg->service_class = src_skb->priority;
		dg->reserved = 0;
		adb->dg_cnt_total++;
		adb->payload_size += dg->datagram_length;
		dg++;
		adb->dg_count[session_id]++;

		/* Increment buffer offset by aligned buffer
		 * length and head_pad_len.
		 */
		offset += aligned_size;

		/* Remove the processed elements and free it. */
		src_skb = imem_ul_list_dequeue(ul_list);
		dev_kfree_skb(src_skb);

		nr_of_skb++;
		pkt_to_send--;
	}		/* end of while */

	if (nr_of_skb > 0) {
		adb_updated = 1;

		/* Update the next table index */
		*adb->next_table_index = offset;
		mux_ul_adb_update_ql(this, adb, session_id, qlth_n_ql_size,
						ul_list->nr_of_bytes);

		/* - save new offset. */
		adb->adbh->block_length = offset;


		if (ipc_wwan_get_vlan_stats(this->wwan, session_id, true,
					&tx_packets, &tx_bytes) == 0) {

			ipc_trc_ul_sess_tx_stat(session_id, nr_of_skb,
					mux->channel->ul_pipe.pipe_nr,
					mux->channel->ul_pipe.nr_of_entries,
				mux->channel->ul_pipe.max_nr_of_queued_entries,
				mux->channel->ul_pipe.nr_of_queued_entries,
				head_pad_len, mux->channel->ul_list.nr_of_bytes,
				tx_packets, tx_bytes, mux);
		}

	}
	return adb_updated;
}

/* Sends Queue Level Table of all opened sessions according to the
 * MUX Lite protocol.
 */
static bool mux_lite_send_qlt(struct ipc_imem *this, struct imem_mux *p_mux)
{
	int i, ql_idx;
	struct imem_mux_session *p_session;
	int qlt_size;
	struct ipc_mem_lite_gen_tbl *p_qlt;
	bool qlt_updated = false;

	if (unlikely(!this)) {
		ipc_err("invalid args");
		return false;
	}

	/* Entry condition */
	if (!p_mux->initialized || (ipc_ap_phase_get(this) != IPC_P_RUN) ||
	   p_mux->state != MUX_S_ACTIVE)
		return qlt_updated;

	qlt_size = offsetof(struct ipc_mem_lite_gen_tbl, vfl) +
			MUX_QUEUE_LEVEL * sizeof(struct ipc_mem_lite_vfl);

	/* Walk through all open sessions. */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {
		p_session = &p_mux->session[i];

		/* Is the session opened. Or Flow Control is ON?
		 */
		if (!p_session->wwan || p_session->flow_ctl_mask != 0)
			/* Try next session id. */
			continue;

		if (mux_ul_skb_alloc(this, &p_mux->ul_adb, IPC_MEM_SIG_QLTH)) {
			ipc_err("No reserved mem to send QLT of if_id: %d", i);
			break;
		}

		/* Prepare QLT */
		p_qlt = (struct ipc_mem_lite_gen_tbl *)
			p_mux->ul_adb.qlth_skb->data;
		p_qlt->signature = IPC_MEM_SIG_QLTH;
		p_qlt->length = qlt_size;
		p_qlt->if_id = i;
		p_qlt->vfl_length = MUX_QUEUE_LEVEL *
					sizeof(struct ipc_mem_lite_vfl);
		p_qlt->reserved = 0;

		for (ql_idx = 0; ql_idx < MUX_QUEUE_LEVEL; ql_idx++) {
			p_qlt->vfl[ql_idx].nr_of_bytes =
						p_session->ul_list.nr_of_bytes;
			ipc_dbg("if[%d] queue_level[%u]=%u", i, ql_idx,
					p_qlt->vfl[ql_idx].nr_of_bytes);
		}

		/* Add QLT to the transfer list.
		 */
		imem_ul_list_add(&p_mux->channel->ul_list,
				p_mux->ul_adb.qlth_skb);

		qlt_updated = true;
		p_mux->ul_adb.qlth_skb = NULL;
	}

	if (qlt_updated)
		/* Updates the TDs with ul_list */
		(void)imem_ul_write_td(this);

	return qlt_updated;
}				/* mux_lite_send_qlt */

/* Checks the available credits for the specified session and returns
 * number of packets for which credits are available.
 */
static int mux_ul_bytes_credits_check(struct ipc_imem *this,
		struct imem_mux *mux, struct imem_mux_session *session,
		struct imem_ul_queue *ul_list, int max_nr_of_pkts)
{
	int credits = 0;
	struct sk_buff *skb;
	int pkts_to_send = 0;

	if (!mux || !session || !ul_list) {
		ipc_err("Invalid arguments");
		return 0;
	}

	if (mux->ul_flow == MUX_UL_ON_CREDITS) {
		credits = session->ul_flow_credits;
		if (credits <= 0) {
			ipc_dbg("FC::if_id[%d] Insuff. Credits/Qlen:%d/%u",
					session->if_id,
					session->ul_flow_credits,
					session->ul_list.nr_of_bytes);
			return 0;
		}
	} else {
		credits = this->params->mux_flow_ctrl_high_thresh_b -
			mux->ul_data_pend_bytes;
		if (credits <= 0) {

			mux_stop_ul_data_encoding(this, mux);

			ipc_dbg("if_id[%d] Not encoding. PendBytes: %llu, high_thresh: %d",
				session->if_id, mux->ul_data_pend_bytes,
				this->params->mux_flow_ctrl_high_thresh_b);
			return 0;
		}
	}

	/* Peek at the head of the list. */
	skb = skb_peek(&ul_list->list);

	/* Check if there are enough credits/bytes available to send the
	 *  requested max_nr_of_pkts. Otherwise restrict the nr_of_pkts
	 *  depending on available credits.
	 */
	while (skb && credits >= skb->len
	&& pkts_to_send < max_nr_of_pkts) {
		credits -= skb->len;
		pkts_to_send++;
		skb = skb_peek_next(skb, &ul_list->list);
	}

	return pkts_to_send;
}

/**
 * Encode the UL IP packet according to to Lite spec.
 */
static int mux_ul_adgh_encode(
		struct ipc_imem *this,
		struct imem_mux *mux,
		int session_id,
		struct imem_mux_session *session,
		struct imem_ul_queue *ul_list,
		struct imem_mux_adb *adb,
		int nr_of_pkts)
{
	struct sk_buff *src_skb = NULL;
	int adb_updated = -EINVAL;
	int offset = 0;
	int nr_of_skb = 0;
	u32 pad_len = 0;
	int aligned_size = 0;
	unsigned long tx_packets, tx_bytes;

	/* Re-calculate the number of packets depending on number of bytes to be
	 * processed/available credits.
	 */
	nr_of_pkts = mux_ul_bytes_credits_check(this, mux, session, ul_list,
			nr_of_pkts);

	/* If calculated nr_of_pkts from available credits is <= 0
	 * then nothing to do.
	 */
	if (nr_of_pkts <= 0) {
		/* Trace insufficient credits */
		ipc_trc_ul_mux_crd_fc(session_id,
				mux->channel->ul_pipe.pipe_nr, 0,
				mux->channel->ul_pipe.nr_of_entries,
				mux->channel->ul_pipe.max_nr_of_queued_entries,
				mux->channel->ul_pipe.nr_of_queued_entries,
				mux->channel->ul_list.nr_of_bytes, mux);
		return 0;
	}

	/* Read configured UL head_pad_length for session.*/
	if (session->ul_head_pad_len > IPC_MEM_DL_ETH_OFFSET)
		pad_len = session->ul_head_pad_len - IPC_MEM_DL_ETH_OFFSET;

	/* get the adgh length */
	offset = sizeof(struct ipc_mem_adgh);

	/* Process all pending UL packets for this session
	 * depending on the allocated datagram table size.
	 */
	while (nr_of_pkts > 0) {
		/* get destination skb allocated */
		if (mux_ul_adb_allocate(this, adb, &mux->size_needed,
					IPC_MEM_SIG_ADGH)) {
			ipc_err("No reserved memory for ADGH");
			return -ENOMEM;
		}

		/* Peek at the head of the list. */
		src_skb = skb_peek(&ul_list->list);
		if (!src_skb) {
			ipc_err("skb peek return NULL with count : %d",
					nr_of_pkts);
			break;
		}

		/* Calculate the memory value. */
		aligned_size = MUX_ALIGN32(pad_len + src_skb->len);

		mux->size_needed = sizeof(struct ipc_mem_adgh) + aligned_size;

		if (mux->size_needed > adb->size) {
			ipc_dbg("size needed %d, adgh size %d",
				mux->size_needed, adb->size);
			/* Return 1 if any IP packet is added to the transfer
			 * list.
			 */
			return nr_of_skb ? 1 : 0;
		}

		ipc_wwan_update_stats(session->wwan, session_id,
					src_skb->len, true);
		/* Add buffer (without head padding to next pending transfer.
		 */
		memcpy(adb->buf + offset + pad_len, src_skb->data,
			src_skb->len);

		adb->adgh->signature = IPC_MEM_SIG_ADGH;
		adb->adgh->if_id = session_id;
		adb->adgh->length = sizeof(struct ipc_mem_adgh) +
						pad_len + src_skb->len;
		adb->adgh->service_class = src_skb->priority;
		adb->adgh->next_count = --nr_of_pkts;
		adb->dg_cnt_total++;
		adb->payload_size += src_skb->len;

		if (mux->ul_flow == MUX_UL_ON_CREDITS)
			/* Decrement the credit value as we are processing the
			 * datagram from the UL list.
			 */
			session->ul_flow_credits -= src_skb->len;

		/* Remove the processed elements and free it. */
		src_skb = imem_ul_list_dequeue(ul_list);
		dev_kfree_skb(src_skb);
		nr_of_skb++;

		mux_ul_adgh_finish(this, mux);
	}

	if (nr_of_skb) {
		/* Send QLT info to modem if pending bytes > low watermark
		 * in case of mux lite
		 */
		if (mux->ul_flow == MUX_UL_ON_CREDITS ||
			mux->ul_data_pend_bytes >=
			this->params->mux_flow_ctrl_low_thresh_b) {
			adb_updated = mux_lite_send_qlt(this, mux);
		} else
			adb_updated = 1;

		/* Updates the TDs with ul_list */
		(void)imem_ul_write_td(this);

		if (ipc_wwan_get_vlan_stats(this->wwan, session_id, true,
					&tx_packets, &tx_bytes) == 0)
			ipc_trc_ul_sess_tx_stat(session_id, nr_of_skb,
				mux->channel->ul_pipe.pipe_nr,
				mux->channel->ul_pipe.nr_of_entries,
				mux->channel->ul_pipe.max_nr_of_queued_entries,
				mux->channel->ul_pipe.nr_of_queued_entries,
				session->ul_head_pad_len,
				mux->channel->ul_list.nr_of_bytes, tx_packets,
				tx_bytes, mux);
	}

	return adb_updated;
}

/* Add session UL data to an ADB. */
static bool mux_ul_data_encode(struct ipc_imem *this, struct imem_mux *mux)
{
	struct imem_mux_session *session;
	struct imem_ul_queue *ul_list;
	int i;
	int dg_n;
	int session_id;
	int updated = 0;

	/* Entry condition. */
	if (!mux || !mux->initialized || !this->enter_runtime
	|| mux->state != MUX_S_ACTIVE || mux->adb_prep_ongoing)
		return false;

	/* Initialize the local data. */
	mux->adb_prep_ongoing = true;

	/* Walk through all open sessions. */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {
		/* Initialize the local session state. */
		session_id = mux->rr_next_session;
		session = &mux->session[session_id];

		/* Go to next handle rr_next_session overflow */
		mux->rr_next_session++;
		if (mux->rr_next_session >= IPC_IMEM_MUX_SESSION_ENTRIES)
			mux->rr_next_session = 0;

		/* Is the session opened. */
		if (!session->wwan || session->flow_ctl_mask ||
				session->net_tx_stop)
			/* Try next session id. */
			continue;

		/* Reference to the UL packet list. */
		ul_list = &session->ul_list;

		/* Is something pending in UL and flow ctrl off */
		dg_n = skb_queue_len(&ul_list->list);
		if (dg_n > IPC_MEM_MAX_UL_DG_ENTRIES)
			dg_n = IPC_MEM_MAX_UL_DG_ENTRIES;

		/* ToDo: Need to check bits set in Mask per Queue */
		if (dg_n == 0)
			/* Nothing to do for this session
			 * -> try next session id.
			 */
			continue;

		if (mux->protocol == MUX_LITE)
			updated = mux_ul_adgh_encode(this, mux,
					session_id, session,
					ul_list, &mux->ul_adb, dg_n);
		else
			updated = mux_ul_adb_encode(this, mux,
					session_id, session,
					ul_list, &mux->ul_adb, dg_n);

		ipc_trc_ul_mux_encode(session_id, dg_n,
				session->ul_list.nr_of_bytes, updated);

	}

	mux->adb_prep_ongoing = false;
	return updated == 1;
}				/* mux_ul_data_encode */

/* Calculates the Payload from any given ADB
 */
static int mux_get_payload_from_adb(struct ipc_imem *this,
			struct ipc_mem_adbh *p_adbh)
{
	u32 next_table_idx;
	u32 payload_size = 0;
	struct ipc_mem_adth *adth;
	int nr_of_dg, i;
	struct ipc_mem_adth_dg *dg;

	if (IS_ERR_OR_NULL(p_adbh))
		return 0;

	/* Process the aggregated datagram tables. */
	next_table_idx = p_adbh->first_table_index;

	/* Has CP sent an empty ADB ? */
	if (next_table_idx < sizeof(struct ipc_mem_adbh))
		ipc_err("unexpected empty ADB");

	while (next_table_idx != 0) {
		/* Get the reference to the table header. */
		adth = (struct ipc_mem_adth *)((u8 *)p_adbh + next_table_idx);

		if (adth->signature == IPC_MEM_SIG_ADTH) {
			/* Calculate the number of datagrams. */
			nr_of_dg = (adth->table_length -
					sizeof(struct ipc_mem_adth) +
					sizeof(struct ipc_mem_adth_dg)) /
					sizeof(struct ipc_mem_adth_dg);

			/* Is the datagram table empty ? */
			if (nr_of_dg <= 0)
				return payload_size;

			/* New aggregated datagram table. */
			dg = &adth->dg[0];

			/* Process the aggregated datagram table. */
			for (i = 0; i < nr_of_dg; i++, dg++) {
				if (dg->datagram_index <
					sizeof(struct ipc_mem_adbh)) {
					ipc_err("decode error at line %d",
						__LINE__);
					return payload_size;
				}

				payload_size += dg->datagram_length;
			}		/* end for */
		}

		/* Move to the next aggregated datagram table. */
		next_table_idx = adth->next_table_index;
	}

	return payload_size;
}

/* Add the processed ADB to the free list .*/
static void mux_ul_adb_free(struct ipc_imem *this, struct imem_mux *mux,
		struct sk_buff *skb)
{
	if (!mux || !skb || !skb->data) {
		ipc_err("Invalid arguments");
		return;
	}

	if (this->params->mux_flow_ctrl_en) {
		if (this->mux.protocol == MUX_LITE) {
			struct ipc_mem_adgh *p_adgh;

			p_adgh = (struct ipc_mem_adgh *)skb->data;

			if (p_adgh->signature == IPC_MEM_SIG_ADGH &&
			mux->ul_flow == MUX_UL_LEGACY)
				mux->ul_data_pend_bytes -= p_adgh->length;
		} else {
			struct ipc_mem_adbh *p_adbh;
			int payload;

			p_adbh = (struct ipc_mem_adbh *)skb->data;

			payload = mux_get_payload_from_adb(this, p_adbh);
			mux->ul_data_pend_bytes -= payload;
		}

		if (mux->ul_flow == MUX_UL_LEGACY)
			ipc_dbg("ul_data_pend_bytes: %lld",
					mux->ul_data_pend_bytes);
	}

	/* Reset the skb settings. */
	skb->len = 0;
	skb->tail = 0;

	/* Add the consumed ADB to the free list. */
	skb_queue_tail(&mux->ul_adb.free_list, skb);

}				/* mux_ul_adb_free */

/* Free the resources of the IP MUX channel.
 */
static void mux_cleanup(struct ipc_imem *this, struct imem_mux *mux)
{
	union imem_mux_msg mux_msg;
	struct mux_channel_close *channel_close_p;
	struct sk_buff_head *free_list;
	struct sk_buff *skb;
	int idx;

	if (unlikely(!this || !mux)) {
		ipc_err("invalid argument");
		return;
	}

	if (!mux->initialized)
		return;		/* The IP MUX layer is inactive. */

	/* Prepare and execute the close action
	 */
	channel_close_p = &mux_msg.channel_close;
	channel_close_p->event = MUX_E_MUX_CHANNEL_CLOSE;
	mux_schedule(this, mux, &mux_msg);

	/* Empty the ADB free list. */
	free_list = &mux->ul_adb.free_list;

	for (;;) {
		/* Remove from the head of the downlink queue. */
		skb = skb_dequeue(free_list);
		if (!skb)
			break;

		/* Free the skb element. */
		ipc_pcie_kfree_skb(this->pcie, skb);
	}

	/* Free the QLT */
	for (idx = 0; idx < IPC_IMEM_MUX_SESSION_ENTRIES; idx++)
		ipc_util_kfree(mux->ul_adb.p_qlt[idx]);

	/* Remove the MUX stats */
	ipc_debugfs_mux_dealloc(&mux->dbg_stats);

	if (mux->channel) {
		mux->channel->ul_pipe.is_open = false;
		mux->channel->dl_pipe.is_open = false;
	}

	mux->initialized = false;

}				/* mux_cleanup */


/* Print internal information
 */
static void ipc_imem_pipe_stats(struct ipc_imem *this,
		struct seq_file *m, struct ipc_pipe *pipe)
{
	unsigned int free_cnt;
	u32 head = 0, tail = 0;
	char *txt_dir;
	char *txt_free;
	int i;

	if (unlikely(!this))
		return;

	ipc_protocol_get_head_tail_index(this->p_protocol, pipe, &head, &tail);

	if (tail <= head)
		free_cnt = head - tail;
	else
		free_cnt = pipe->nr_of_entries - tail + head;

	txt_dir = pipe->dir == IPC_MEM_DIR_UL ? "UL" : "DL";
	txt_free = pipe->dir == IPC_MEM_DIR_UL ? "pending" : "ready";

	seq_printf(m,
		   "%s pipe %2u........: %s=%3u / %s=%3u / %s=%3u / %-7s=%3u\n",
		   txt_dir, pipe->pipe_nr,
		   "head", head, "tail", tail,
		   "entries", pipe->nr_of_entries, txt_free, free_cnt);

	if (!ipc_imem_check_wwan_ips(pipe->channel))
		return;

	/* dump sessions */
	for (i = 0; i < IPC_IMEM_MUX_SESSION_ENTRIES; i++) {
		struct imem_mux_session *session =
			&this->mux.session[i];

		if (!session->wwan)
			continue;

		if (pipe->dir == IPC_MEM_DIR_UL) {
			seq_printf(m, "%3sSession-%d: ", "", i);
			seq_printf(m,
			"UL Credit: %d head padding %d, UL pending %d/%u,\n",
				session->ul_flow_credits,
				session->ul_head_pad_len,
				skb_queue_len(&session->ul_list.list),
				session->ul_list.nr_of_bytes);
		} else {
			seq_printf(m,
				"%3sSession-%d: head padding %d,\n",
				"", i, session->dl_head_pad_len);
		}

		seq_printf(m,
			"%14sFLOW_CTRL:: MASK: 0x%X, EN_CNT:%d, DIS_CNT:%d\n",
			"",
			session->flow_ctl_mask,
			session->flow_ctl_en_cnt,
			session->flow_ctl_dis_cnt);

	}
}


/*
 * Refer to header file for description
 */
void ipc_imem_active_protocol_string(struct ipc_imem *this,
			struct seq_file *m)
{
	if (unlikely(!this || !m)) {
		ipc_err("Invalid arguments");
		return;
	}

	seq_printf(m, "IPC Protocol.........: %s\n\n",
			ipc_protocol_get_str(this->p_protocol));

}


void ipc_imem_stats(struct ipc_imem *this, struct seq_file *m)
{
	int i;

	if (unlikely(!this || !m)) {
		ipc_err("Invalid arguments");
		return;
	}

	seq_puts(m, "\n>>>>> IMC IMEM\n");
	seq_printf(m, "CP Version...: 0x%04x\n", this->cp_version);
	seq_printf(m, "AP execution stage...: %s\n",
			ipc_ap_phase_get_string(this->phase));
	seq_printf(m, "CP execution stage...: %s\n",
		ipc_imem_exec_stage_to_string(this,
			ipc_imem_get_exec_stage_buffered(this)));
	seq_printf(m, "CP sleep notification: %s\n\n",
		ipc_protocol_pm_dev_sleep_notification_str(this->p_protocol));

	seq_printf(m, "IRQ activations......: %u\n\n", this->ev_irq_count);
	seq_printf(m, "Fast updates.........: %u\n\n",
			this->ev_fast_update);

	ipc_protocol_print_stats(this->p_protocol, m);

	seq_printf(m, "Active Mux Version...: %s\n",
			this->mux.protocol == MUX_LITE ?
				"MUX_LITE" : "MUX_AGGREGATION");
	seq_printf(m, "UL Flow..............: %s\n\n",
			this->mux.ul_flow == MUX_UL_ON_CREDITS ?
				"ON_CREDITS" : "LEGACY");

	seq_printf(m, "param:td_update_tmo...............: %u usec\n",
				this->params->td_update_tmo);
	seq_printf(m, "param:fast_update_tmo.............: %u usec\n\n",
				this->params->fast_update_tmo);
	seq_printf(m, "param:mux_ul_adb_size.............: %d\n",
				this->params->mux_ul_adb_size);
	seq_printf(m, "param:mux_flow_ctrl_en............: %d\n",
				this->params->mux_flow_ctrl_en);
	seq_printf(m, "param:mux_flow_ctrl_high_thresh_b.: %d\n",
				this->params->mux_flow_ctrl_high_thresh_b);
	seq_printf(m, "param:mux_flow_ctrl_low_thresh_b..: %d\n",
				this->params->mux_flow_ctrl_low_thresh_b);
	seq_printf(m, "param:mux_lite_buf_size..: %d\n",
				this->params->mux_lite_buf_size);


	/* print open pipe information */
	for (i = 0; i < IPC_MEM_MAX_CHANNELS; i++) {
		if (this->channels[i].state != IMEM_CHANNEL_ACTIVE)
			continue;

		seq_puts(m, "\n");
		ipc_imem_pipe_stats(this, m,
				&this->channels[i].ul_pipe);
		ipc_imem_pipe_stats(this, m,
				&this->channels[i].dl_pipe);
	}
}

/*
 * Retrieve a string representation of the (unbuffered) execution stage
 *
 * @this: instance pointer
 *
 * returns execution stage string
 */
const char *ipc_imem_get_exec_stage_string(struct ipc_imem *this)
{
	return ipc_imem_exec_stage_to_string(this,
				ipc_imem_get_exec_stage(this));
}


/*
 * Returns true if user module parameter force_legacy_proto is non-zero.
 * false otherwise.
 *
 */
bool imem_force_legacy_protocol(void)
{
	return force_legacy_proto ? true : false;
}


/* imc_ipc_imem.c ends here */
