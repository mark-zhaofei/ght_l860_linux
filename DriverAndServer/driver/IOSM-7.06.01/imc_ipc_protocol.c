/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/skbuff.h>
#include <linux/pci.h>
#include <linux/seq_file.h>

#include "stdbool.h"

#include "imc_ipc_tasklet.h"
#include "imc_ipc_export.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_util.h"
#include "imc_ipc_mmio.h"
#include "imc_ipc_imem.h"
#include "imc_ipc_pm.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_protocol.h"
#include "imc_ipc_protocol_priv.h"
#include "imc_ipc_protocol_legacy.h"
#include "imc_ipc_protocol_converged.h"


/*
 * Default time out for sending IPC messages like open pipe, close pipe etc.
 * during run mode.
 *
 * If the message interface lock to CP times out, the link to CP is broken.
 *
 * mode : run mode (IPC_MEM_EXEC_STAGE_RUN)
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_MSG_COMPLETE_RUN_DEFAULT_TIMEOUT 10000	/* 10 seconds */
#else
#define IPC_MSG_COMPLETE_RUN_DEFAULT_TIMEOUT 500	/* 0.5 seconds */
#endif
/*
 * Default time out for sending IPC messages like open pipe, close pipe etc.
 * during boot mode.
 *
 * If the message interface lock to CP times out, the link to CP is broken.
 *
 * mode : boot mode
 * (IPC_MEM_EXEC_STAGE_BOOT | IPC_MEM_EXEC_STAGE_PSI | IPC_MEM_EXEC_STAGE_EBL)
 *
 * unit : milliseconds
 */
#if defined(IPC_FASTSIM) || defined(IPC_EMULATOR)
#define IPC_MSG_COMPLETE_BOOT_DEFAULT_TIMEOUT 10000	/* 10 seconds */
#else
#define IPC_MSG_COMPLETE_BOOT_DEFAULT_TIMEOUT 500	/* 0.5 seconds */
#endif


/**
 * Enum defining the supported IPC protocol.
 */
enum ipc_protocol_dev {
	IPC_PROTOCOL_CONVERGED,
	IPC_PROTOCOL_LEGACY
};

/**
 * Structure for IPC protocol.
 */
struct ipc_protocol {

	void *priv_data;

	enum ipc_protocol_dev prot;

	struct ipc_pm *pm;
	struct ipc_pcie *pcie;
	struct ipc_tasklet *tasklet;

	struct ipc_protocol_ops ops;

	/* Array of OS completion objects to be triggered once CP
	 * acknowledges a request in the message ring
	 */
	struct ipc_rsp *rsp_ring[IPC_MEM_MSG_ENTRIES];

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

struct ipc_call_msg_send_args {
	/* Function to call in TL context for message sending */
	enum ipc_msg_prep_type msg_type;

	/* Arguments for message preparation function */
	union ipc_msg_prep_args *prep_args;

	/* Pointer to response, can be NULL if result can be ignored */
	struct ipc_rsp *response;
};


/*
 * Variable to describe timeout for message completion in boot mode. For
 * example open pipe, close pipe, sleep messages etc.
 *
 * unit: milliseconds.
 */
static ulong msg_complete_boot_timeout = IPC_MSG_COMPLETE_BOOT_DEFAULT_TIMEOUT;
module_param(msg_complete_boot_timeout, ulong, 0664);
MODULE_PARM_DESC(msg_complete_boot_timeout,
	"timeout for message completion of command messages in boot (BOOT|PSI|EBL) mode");

/*
 * Variable to describe timeout for message completion in run mode. For
 * example open pipe, close pipe, sleep messages etc.
 *
 * unit: milliseconds.
 */
static ulong msg_complete_run_timeout = IPC_MSG_COMPLETE_RUN_DEFAULT_TIMEOUT;
module_param(msg_complete_run_timeout, ulong, 0664);
MODULE_PARM_DESC(msg_complete_run_timeout,
	"timeout for message completion of command messages in run (RUN) mode");


/* Send netlink event of modem timeout
 */
static void  ipc_protocol_report_timeout(struct ipc_protocol *this)
{
	ipc_pcie_uevent_send(this->pcie, NL_EVENT_MDM_TIMEOUT);
}

/* Call message preparation function and Send msg to CP
 */
int ipc_protocol_tl_msg_send(struct ipc_protocol *this,
	enum ipc_msg_prep_type msg_type,
	union ipc_msg_prep_args *prep_args, struct ipc_rsp *response)
{
	int index;

	if (unlikely(!this || !prep_args)) {
		ipc_err("invalids args");
		return -1;
	}

	index = this->ops.msg_prep(this->priv_data, msg_type, prep_args);

	/* Store reference towards caller specified response in response ring
	 * and signal CP
	 */
	if (index >= 0 && index < IPC_MEM_MSG_ENTRIES) {
		this->rsp_ring[index] = response;
		this->ops.msg_hp_update(this->priv_data);
	}

	return index;
}


/* Tasklet message send call back function
 */
static int ipc_protocol_tl_msg_send_cb(void *instance, int arg, void *msg,
	size_t size)
{
	struct ipc_protocol *this = instance;
	struct ipc_call_msg_send_args *send_args = msg;

	return ipc_protocol_tl_msg_send(this, send_args->msg_type,
		send_args->prep_args, send_args->response);
}

/* Remove reference to a response. This is typically used when a requestor timed
 * out and is no longer interested in the response.
 */
static int ipc_protocol_tl_msg_remove(void *instance, int arg, void *msg,
	size_t size)
{
	struct ipc_protocol *this = instance;

	this->rsp_ring[arg] = NULL;
	return 0;
}

/**
 * Prepare and send a message to the device, wait for either the device to
 * complete the message or the message complete timeout to expire.
 *
 * @this: protocol instance
 * @prep: enum for preparing type of message
 * @prep_args: arguments for message preparation function
 *
 * returns 0/IPC_OK on success, -1/IPC_FAIL on failure
 */
int ipc_protocol_msg_send(struct ipc_protocol *this,
	enum ipc_msg_prep_type prep, union ipc_msg_prep_args *prep_args)
{
	int result = IPC_FAIL;
	struct ipc_rsp response;
	struct ipc_call_msg_send_args send_args;
	int index;
	unsigned int timeout;

	if (unlikely(!this || !prep_args)) {
		ipc_err("invalid args");
		return result;
	}

	timeout =
		ipc_protocol_get_ap_exec_stage(this) == IPC_MEM_EXEC_STAGE_RUN ?
			msg_complete_run_timeout : msg_complete_boot_timeout;

	/* Trap if called from non-preemptible context */
	might_sleep();

	response.status = IPC_MEM_MSG_CS_INVALID;
	ipc_completion_init(&response.completion);

	send_args.msg_type = prep;
	send_args.prep_args = prep_args;
	send_args.response = &response;

	/* Allocate and prepare message to be sent in tasklet context.
	 * A positive index returned form tasklet_call references the message
	 * in case it needs to be cancelled when there is a timeout.
	 */
	index = ipc_tasklet_call(this->tasklet, ipc_protocol_tl_msg_send_cb,
		this, 0, &send_args, 0);

	if (index == -2)
		return IPC_OK; /* good case, but no message was sent */

	if (unlikely(index < 0)) {
		ipc_err("%d failed", prep);
		return IPC_FAIL;
	}

	/* Wait for the device to respond to the message */

	switch (ipc_completion_wait_timeout_ms(&response.completion, timeout)) {
	case 0:
		/* Timeout, there was no response from the device.
		 * Remove the reference to the local response completion
		 * object as we are no longer interested in the response.
		 */
		(void) ipc_tasklet_call(this->tasklet,
			ipc_protocol_tl_msg_remove, this, index, NULL, 0);
		ipc_err("timeout");
		ipc_protocol_report_timeout(this);
		break;
	default:
		/* We got a response in time; check completion status:
		 */
		if (response.status == IPC_MEM_MSG_CS_SUCCESS)
			result = IPC_OK;
		else
			ipc_err("msg completion status shows error %d",
				response.status);
		break;
	}

	return result;
}


/**
 * Send a "host sleep" message to CP and wait for response
 *
 * @this: Pointer to ipc_protocol instance
 * @state: sleep state: 0 = enter sleep, 1 = exit sleep
 *
 * returns 0 on success, -1 on failure
 */

static int ipc_protocol_msg_send_host_sleep(struct ipc_protocol *this,
	u32 state)
{
	union ipc_msg_prep_args prep_args = {
		.sleep.target = 0, .sleep.state = state
	};

	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return -1;
	}

	return ipc_protocol_msg_send(this, IPC_MSG_PREP_SLEEP, &prep_args);
}

/*
 * Refer to header file for description
 */
void ipc_protocol_msg_process(struct ipc_protocol *this, int irq)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	this->ops.msg_process(this->priv_data, irq, this->rsp_ring);
}

/*
 * Refer to header file for description
 */
bool ipc_protocol_ul_td_send(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe, struct imem_ul_queue *p_list)
{
	if (unlikely(!this || !p_pipe || !p_list)) {
		ipc_err("Invalid args");
		return false;
	}

	return this->ops.ul_td_send(this->priv_data,  p_pipe, p_list);
}


/*
 * Refer to header file for description
 */
struct sk_buff *ipc_protocol_ul_td_process(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe)
{
	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid args");
		return NULL;
	}

	return this->ops.ul_td_process(this->priv_data,  p_pipe);
}

/*
 * Refer to header file for description
 */
bool ipc_protocol_dl_skb_alloc(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe)
{
	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid argument");
		return NULL;
	}

	return this->ops.dl_td_prepare(this->priv_data, p_pipe);
}


/*
 * Refer to header file for description
 */
struct sk_buff *ipc_protocol_dl_td_process(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe)
{
	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid argument");
		return NULL;
	}

	return this->ops.dl_td_process(this->priv_data,  p_pipe);
}


/*
 * Refer to header file for description
 */
void ipc_protocol_pipe_cleanup(struct ipc_protocol *this,
	struct ipc_pipe *p_pipe)
{
	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid argument");
		return;
	}

	this->ops.pipe_cleanup(this->priv_data, p_pipe);
}


/*
 * Refer to header file for description
 */
void ipc_protocol_get_head_tail_index(struct ipc_protocol *this,
		struct ipc_pipe *p_pipe, u32 *p_head, u32 *p_tail)
{
	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid argument");
		return;
	}

	this->ops.get_head_tail_index(this->priv_data, p_pipe,
			p_head, p_tail);
}


/*
 * Refer to header file for description
 */
void ipc_protocol_doorbell_trigger(struct ipc_protocol *this, u32 identifier)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	ipc_pm_signal_hpda_doorbell(this->pm, identifier);
}


/*
 * Refer to header file for description
 */
enum ipc_mem_device_ipc_state ipc_protocol_get_ipc_status(
		struct ipc_protocol *this)
{
	return this ? this->ops.get_ipc_status(this->priv_data) :
		IPC_MEM_DEVICE_IPC_INVALID;
}


/*
 * Refer to header file for description
 */
enum ipc_mem_exec_stage ipc_protocol_get_ap_exec_stage(
	struct ipc_protocol *this)
{
	return this ? this->ops.get_ap_exec_stage(this->priv_data) :
		IPC_MEM_EXEC_STAGE_INVALID;
}


/*
 * Refer to header file for description
 */
bool ipc_protocol_pm_dev_sleep_handle(struct ipc_protocol *this)
{
	u32 requested;
	u32 ipc_status;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return false;
	}

	/* Test the CP IPC state.
	 */
	ipc_status = ipc_protocol_get_ipc_status(this);

	if (ipc_status != IPC_MEM_DEVICE_IPC_RUNNING) {
		ipc_err("irq ignored, CP IPC state is %d, should be RUNNING",
			ipc_status);

		/* Stop further processing. */
		return false;
	}

	/* Get a copy of the requested PM state by the device and the local
	 * device PM state.
	 */
	requested = this->ops.pm_dev_get_sleep_notification(this->priv_data);

	if (this->prot == IPC_PROTOCOL_CONVERGED
	&& !ipc_pm_host_slp_notification(this->pm, requested))
		/* In the process of Host sleep if execution reached here means
		 * we can ignore Device sleep check.
		 */
		return false;

	return ipc_pm_dev_slp_notification(this->pm, requested);
}


/*
 * Refer to header file for description
 */
bool ipc_protocol_pm_dev_release(struct ipc_protocol *this,
		enum ipc_pm_unit unit)
{
	return this ? ipc_pm_unit_release(this->pm, unit) : false;
}


/*
 * Refer to header file for description
 */
bool ipc_protocol_pm_dev_acquire(struct ipc_protocol *this,
		enum ipc_pm_unit unit)
{
	return this ? ipc_pm_unit_acquire(this->pm, unit) : false;
}


/*
 * Refer to header file for description
 */
const char *ipc_protocol_pm_dev_sleep_notification_str(
		struct ipc_protocol *this)
{
	u32 sleep_state;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return "???";
	}

	sleep_state = this->ops.pm_dev_get_sleep_notification(this->priv_data);

	return ipc_pm_get_sleep_notification_string(sleep_state);

}


/*
 * Refer to header file for description
 */
bool ipc_protocol_pm_dev_is_in_sleep(struct ipc_protocol *this)
{
	return this ? ipc_pm_is_device_in_sleep(this->pm) : false;
}


/*
 * Refer to header file for description
 */
bool ipc_protocol_pm_dev_is_sleep_handling(struct ipc_protocol *this)
{
	return this ? ipc_pm_is_device_sleep_handling(this->pm) : false;
}


/**
 * For the Converged Protocol this function waits for 500ms for CP to give
 * acknowledgement for Host Sleep request.
 * For Legacy protocol this returns immediately because Host Sleep request
 * will be handles as Messages.
 *
 * @this: Pointer to ipc_protocol instance.
 *
 * returns 0 on Success, non-zero otherwise.
 */
static int ipc_protocol_pm_host_wait_for_ack(struct ipc_protocol *this)
{
	int ret = -1;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return ret;
	}

	if (this->prot == IPC_PROTOCOL_CONVERGED)
		ret = ipc_pm_host_sleep_wait_for_ack(this->pm);
	else
		/* There is no need to wait for Legacy protocol */
		ret = 0;

	return ret;
}

/*
 * Refer to header file for description
 */
void ipc_protocol_print_stats(struct ipc_protocol *this, struct seq_file *m)
{
	if (unlikely(!this || !m)) {
		ipc_err("Invalid argument");
		return;
	}

	this->ops.print_stats(this->priv_data, m);
	ipc_pm_print_stats(this->pm, m);
}


/*
 * Refer to header file for description
 */
const char *ipc_protocol_get_str(struct ipc_protocol *this)
{
	char *p_str = NULL;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return "UNKNOWN";
	}

	if (this->prot == IPC_PROTOCOL_CONVERGED)
		p_str = "CONVERGED";
	else
		p_str = "LEGACY";

	return p_str;
}

bool ipc_protocol_suspend(struct ipc_protocol *this)
{
	if (!ipc_pm_prepare_host_sleep(this->pm))
		return false;

	ipc_protocol_pm_dev_acquire(this, IPC_PM_UNIT_HS);

	if (!ipc_pm_wait_for_device_active(this->pm)) {
		ipc_protocol_report_timeout(this);
		return false;
	}

	ipc_protocol_pm_dev_release(this, IPC_PM_UNIT_HS);

	/* Send the sleep message for sync sys calls.
	 */
	ipc_dbg("send (TARGET_HOST, ENTER_SLEEP)");
	if (IS_IPC_FAIL(ipc_protocol_msg_send_host_sleep(this,
		IPC_HOST_SLEEP_ENTER_SLEEP))) {
		/* Sending ENTER_SLEEP message failed, we are still active */
		ipc_pm_set_host_active(this->pm);

		return false;
	}

	if (ipc_protocol_pm_host_wait_for_ack(this)) {
		ipc_err("Didn't get ACK from Modem");
		return false;
	}

	/* CP has acknowledged the Sleep message */
	ipc_pm_set_host_sleep(this->pm);

	return true;
}


/* resume
 */
bool ipc_protocol_resume(struct ipc_protocol *this)
{
	if (!ipc_pm_prepare_host_active(this->pm))
		return false;

	/* Send the sleep message.
	 */
	ipc_dbg("send (TARGET_HOST, EXIT_SLEEP)");
	if (IS_IPC_FAIL(ipc_protocol_msg_send_host_sleep(this,
		IPC_HOST_SLEEP_EXIT_SLEEP))) {
		ipc_pm_set_host_sleep(this->pm);
		return false;
	}

	if (ipc_protocol_pm_host_wait_for_ack(this)) {
		ipc_err("Didn't get ACK from Modem");
		return false;
	}

	/* CP has acknowledged the Sleep Exit message */
	ipc_pm_set_host_active(this->pm);

	return true;
}


/*
 * Refer to header file for description
 */
void ipc_protocol_update_mcr_cp_cap(struct ipc_protocol *this,
		bool mcr_supported)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	/* Protocol which doesn't support this will have function pointer set
	 * to NULL.
	 */
	if (this->ops.update_mcr_cp_cap)
		this->ops.update_mcr_cp_cap(this->priv_data, mcr_supported);
}


/*
 * Refer to header file for description
 */
int ipc_protocol_wait_for_remote_ts(struct ipc_protocol *this, int timeout_ms,
		u64 *p_remote_time, u32 *p_remote_ts_id,
		u32 *p_remote_time_unit, bool *p_ts_db_trig)
{
	int ret = -1;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return ret;
	}

	/* Protocol which doesn't support this will have function pointer set
	 * to NULL.
	 */
	if (this->ops.wait_for_remote_ts) {
		ret = this->ops.wait_for_remote_ts(this->priv_data, timeout_ms,
				p_remote_time, p_remote_ts_id,
				p_remote_time_unit, p_ts_db_trig);
	} else
		/* Protocol doesn't support Wait for remote TS */
		ret = EPROTONOSUPPORT;

	return ret;
}


/**
 * Constructor for IPC protocol instance data
 *
 * @this: Pointer to ipc_protocol instance.
 * @p_mmio: Instance pointer of MMIO module.
 * @p_pcie: Instance pointer  of PCIe module.
 * @p_stats: Instance pointer to Stats module.
 * @p_params: Instance pointer to Params module
 * @dbg: pointer to ipc_dbg structure
 * @device_id: Device ID of the Modem
 * @tasklet: Pointer to tasklet instance
 *
 * returns none
 */
static int ipc_protocol_ctor(struct ipc_protocol *this,
		struct ipc_mmio *p_mmio, struct ipc_pcie *p_pcie,
		struct ipc_debugfs_stats *p_stats, struct ipc_params *p_params,
		struct ipc_dbg *dbg, unsigned int device_id,
		struct ipc_tasklet *tasklet)
{
	if (unlikely(!p_mmio || !p_pcie || !tasklet)) {
		ipc_err("Invalid args");
		return  -1;
	}

	this->dbg = dbg;
	this->pcie = p_pcie;
	this->tasklet = tasklet;

	this->pm = ipc_pm_alloc(p_pcie, p_stats, p_params, dbg, tasklet);
	if (!this->pm) {
		ipc_err("Unable to allocate PM");
		return -1;
	}

	if (imem_force_legacy_protocol()) {
		ipc_dbg("IPC Protocol Legacy is active.");
		this->prot = IPC_PROTOCOL_LEGACY;

		this->priv_data = ipc_protocol_legacy_alloc(p_pcie, p_stats,
				p_mmio,	p_params, this->pm, &this->ops, dbg);

	} else {
		switch (device_id) {
		case INTEL_CP_DEVICE_7660_ID:
		case INTEL_CP_DEVICE_8060_ID:
			ipc_dbg("IPC Protocol Converged is active.");
			this->prot = IPC_PROTOCOL_CONVERGED;

			this->priv_data = ipc_protocol_converged_alloc(p_pcie,
					p_stats, p_mmio, p_params, this->pm,
					&this->ops, dbg);
			break;

		case INTEL_CP_DEVICE_7260_ID:
		case INTEL_CP_DEVICE_7360_ID:
		case INTEL_CP_DEVICE_7460_ID:
		case INTEL_CP_DEVICE_7480_ID:
		case INTEL_CP_DEVICE_7560_ID:
		case INTEL_CP_DEVICE_IBIS_ID:
			ipc_dbg("IPC Protocol Legacy is active.");
			this->prot = IPC_PROTOCOL_LEGACY;

			this->priv_data = ipc_protocol_legacy_alloc(p_pcie,
					p_stats, p_mmio, p_params, this->pm,
					&this->ops, dbg);
			break;

		default:
			ipc_err("Not a known device to choose protocol");
			return -1;
		}
	}

	if (!this->priv_data) {
		ipc_err("Alloc of (%d) protocol failed", this->prot);
		return -1;
	}

	/* Check for function pointers which are common to all protocols.
	 * Protocol specific function pointers need to check individually.
	 */
	if (unlikely(!this->ops.msg_prep            ||
		!this->ops.msg_hp_update                 ||
		!this->ops.msg_process                   ||
		!this->ops.ul_td_send                    ||
		!this->ops.ul_td_process                 ||
		!this->ops.dl_td_prepare                 ||
		!this->ops.dl_td_process                 ||
		!this->ops.get_head_tail_index           ||
		!this->ops.get_ipc_status                ||
		!this->ops.pipe_cleanup                  ||
		!this->ops.get_ap_exec_stage             ||
		!this->ops.pm_dev_get_sleep_notification ||
		!this->ops.print_stats                   ||
		!this->ops.protocol_dealloc)) {
		ipc_err("Invalid ops");
		return -1;
	}

	return 0;
}


/**
 * Distructor for IPC protocol instance data
 *
 * @this: Pointer to ipc_protocol instance..
 *
 * returns none
 */
static void ipc_protocol_dtor(struct ipc_protocol *this)
{
	if (this->ops.protocol_dealloc)
		this->ops.protocol_dealloc(&this->priv_data);

	/* Free PM component. Must be freed before pcie, stats, params */
	ipc_pm_dealloc(&this->pm);
}


/*
 * Refer to header file for description
 */
void ipc_protocol_dealloc(struct ipc_protocol **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_protocol_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/*
 * Refer to header file for description
 */
struct ipc_protocol *ipc_protocol_alloc(
		struct ipc_dbg *dbg, struct ipc_mmio *p_mmio,
		struct ipc_pcie *p_pcie, struct ipc_debugfs_stats *p_stats,
		struct ipc_params *p_params, unsigned int device_id,
		struct ipc_tasklet *tasklet)
{
	struct ipc_protocol *this = ipc_util_kzalloc(sizeof(*this));

	if (this) {
		if (ipc_protocol_ctor(this, p_mmio, p_pcie, p_stats,
			p_params, dbg, device_id, tasklet)) {
			ipc_err("Protocol Constructor Failed!");
			ipc_protocol_dealloc(&this);
			return NULL;
		}
	}

	return this;
}

