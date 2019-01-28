/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/delay.h>
#include <linux/seq_file.h>

#include "imc_ipc_pm.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_util.h"
#include "imc_ipc_params.h"
#include "imc_ipc_hrtimer.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_debugfs.h"
#include "imc_ipc_completion.h"


/* Timeout value in MS for the PM to wait for device to reach active state
 */
#define IPC_PM_ACTIVE_TIMEOUT_MS  (500)

/* Value definitions for union ipc_pm_cond members.
 *
 * Note that here "active" has the value 1, as compared to the enums
 * ipc_mem_host_pm_state or ipc_mem_dev_pm_state, where "active" is 0
 */
#define IPC_PM_SLEEP  (0)
#define IPC_PM_ACTIVE (1)

/* Conditions for D3 and the sleep message to CP.
 */
union ipc_pm_cond {
	unsigned int raw; /* raw/combined value for faster check */

	struct {
		unsigned int irq:1;       /* IRQ towards CP */
		unsigned int wakeup:1;    /* WAKEUP towards CP */
		unsigned int hs:1;        /* Host Sleep */
		unsigned int link:1;      /* Device link state. */
	};
};

/* Possible states of the SLEEP finite state machine.
 */
enum ipc_mem_host_pm_state {
	/**< Host is active */
	IPC_MEM_HOST_PM_ACTIVE,
	/**< Intermediate state before going to active */
	IPC_MEM_HOST_PM_ACTIVE_WAIT,
	/**< Intermediate state to wait for idle before going into sleep */
	IPC_MEM_HOST_PM_SLEEP_WAIT_IDLE,
	/**< Intermediate state to wait for D3 before going to sleep */
	IPC_MEM_HOST_PM_SLEEP_WAIT_D3,

	/* after this state the interface is not accessible */
	/**< host is in suspend to RAM */
	IPC_MEM_HOST_PM_SLEEP,
	/**< Intermediate state before exiting sleep */
	IPC_MEM_HOST_PM_SLEEP_WAIT_EXIT_SLEEP,
};

/* Possible states of the SLEEP finite state machine.
 */
enum ipc_mem_dev_pm_state {
	/* IPC_MEM_DEV_PM_ACTIVE is the initial power management state.
	 */

	/* IRQ(struct ipc_mem_device_info.device_sleep_notification) and
	 * DOORBELL-IRQ-HPDA(data) values.
	 */
	IPC_MEM_DEV_PM_ACTIVE = 0,
	IPC_MEM_DEV_PM_SLEEP = 1,

	/* DOORBELL-IRQ-DEVICE_WAKE(data).
	 */
	IPC_MEM_DEV_PM_WAKEUP = 2,

	/* DOORBELL-IRQ-HOST_SLEEP(data).
	 */
	IPC_MEM_DEV_PM_HOST_SLEEP = 3,

	/* Local intermediate states.
	 */

	/* Before AP triggers DOORBELL-IRQ-SLEEP(data) either
	 * the intermediate device link state is SYNC_ACTIVE_WAIT i.e.
	 * the user is blocked until the link interworking was finished
	 * about IRQ and DOORBELL-IRQ-HPDA or the the intermediate device
	 * link state is ACTIVE_WAIT i.e. the data transfer starts after
	 * the DOORBELL-IRQ-HPDA(IPC_MEM_DEV_PM_ACTIVE).
	 */
	IPC_MEM_DEV_PM_ACTIVE_WAIT
};

/* Power management instance data
 */
struct ipc_pm {
	struct ipc_pcie *pcie;

	struct ipc_debugfs_stats *stats;

	struct ipc_params *params;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	enum ipc_mem_host_pm_state host_pm_state;

	/* Variable to indicate Host Sleep Pending
	 */
	atomic_t host_sleep_pend;

	/* Generic wait-for-completion used in case of Host Sleep
	 */
	struct ipc_completion host_sleep_complete;

	/* Variable to indiacate Host Sleep Pending
	 */
	atomic_t host_sleep_ack_waiting;

	atomic_t sleep_handling;

	/* Generic wait-for-completion used in case of Host Sleep
	 */
	struct ipc_completion host_sleep_ack_complete;

	/* Conditions for power management
	 */
	union ipc_pm_cond pm_cond;

	/* is a HPDA update pending?
	 */
	bool pending_hpda_update;

	/* Current power management state, the initial state is
	 * IPC_MEM_DEV_PM_ACTIVE eq. 0.
	 */
	enum ipc_mem_dev_pm_state ap_state;
	enum ipc_mem_dev_pm_state cp_state;

	/* A driver entry point is in use or data are on the way.
	 */
	bool ap_is_busy;

	/* last handled device_sleep_notfication
	 */
	u32 device_sleep_notification;

	/* wakeup Timer for debugging
	 */
	struct ipc_hrtimer *wakeup_timer;

	/* concurrent wake test
	 */
	u32 concurrent_wake_tmo;

	/* Counter for next device wake timeout
	 */
	u32 wakeup_tmo;

	/* tasklet for scheduling a wakeup in task context */
	struct ipc_tasklet *tasklet;
};



/* wakeup timer execution
 */
static void ipc_pm_tl_wakeup_timer_cb(void *instance)
{
	struct ipc_pm *this = instance;

	/* trigger link activation */
	ipc_pm_unit_acquire(this, IPC_PM_UNIT_WAKEUP);
	ipc_pm_unit_release(this, IPC_PM_UNIT_WAKEUP);
}

/* Wakeup start timer.
 */
static void ipc_pm_wakeup_timer_start(struct ipc_pm *this, u32 delay)
{
	if (!ipc_hrtimer_is_active(this->wakeup_timer))
		ipc_hrtimer_config(this->wakeup_timer, delay);
}

/* Get pm state in string.
 */
static char *ipc_pm_host_pm_state_to_string(enum ipc_mem_host_pm_state state)
{
	switch (state) {
	case IPC_MEM_HOST_PM_ACTIVE:
		return "HOST_ACTIVE";

	case IPC_MEM_HOST_PM_ACTIVE_WAIT:
		return "HOST_ACTIVE_WAIT";

	case IPC_MEM_HOST_PM_SLEEP_WAIT_IDLE:
		return "HOST_SLEEP_WAIT_IDLE";

	case IPC_MEM_HOST_PM_SLEEP_WAIT_D3:
		return "HOST_SLEEP_WAIT_D3";

	case IPC_MEM_HOST_PM_SLEEP:
		return "HOST_SLEEP";

	case IPC_MEM_HOST_PM_SLEEP_WAIT_EXIT_SLEEP:
		return "HOST_SLEEP_WAIT_EXIT_SLEEP";

	default:
		return "UNKNOWN";
	}
}

/**
 * Refer to header file for description
 */
void ipc_pm_signal_hpda_doorbell(struct ipc_pm *this, u32 identifier)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	if (!ipc_pm_unit_acquire(this, IPC_PM_UNIT_IRQ)) {
		this->pending_hpda_update = true;
		ipc_dbg("Pending HPDA update set. identifier:%d", identifier);
		return;
	}

	this->pending_hpda_update = false;

	/* Trigger the irq towards CP
	 */
	ipc_cp_irq_hpda_update(this->pcie, this->params->hp_update_debug ?
		identifier : 0);

	ipc_pm_unit_release(this, IPC_PM_UNIT_IRQ);
}

/* Wake up the device if it is in low power mode.
 */
static bool ipc_pm_link_activate(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return false;
	}

	ipc_dbg("cp=%d, ap=%d", this->cp_state, this->ap_state);

	if (this->cp_state == IPC_MEM_DEV_PM_ACTIVE)
		return true;

	if (this->cp_state == IPC_MEM_DEV_PM_SLEEP) {
		if (this->ap_state == IPC_MEM_DEV_PM_SLEEP) {
			/* Wake up the device.
			 */
			ipc_cp_irq_sleep_control(this->pcie,
				IPC_MEM_DEV_PM_WAKEUP);
			this->ap_state = IPC_MEM_DEV_PM_ACTIVE_WAIT;

			ipc_debugfs_stats_device_wake_event(this->stats);

			return false;
		}

		if (this->ap_state == IPC_MEM_DEV_PM_ACTIVE_WAIT)
			return false;

		return true;
	}

	/* link is not ready
	 */
	return false;
}

/**
 * Refer to header file for description
 */
bool ipc_pm_wait_for_device_active(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return false;
	}

	if (this->ap_state != IPC_MEM_DEV_PM_ACTIVE) {

		atomic_set(&this->host_sleep_pend, 1);

		/* Wait for IPC_PM_ACTIVE_TIMEOUT_MS for Device sleep state
		 * machine to enter ACTIVE state so that it can run in its own
		 * sleep state machine during Host suspend.
		 */
		ipc_completion_reinit(&this->host_sleep_complete);

		if (!ipc_completion_wait_interruptible_timeout_ms(
			&this->host_sleep_complete, IPC_PM_ACTIVE_TIMEOUT_MS)) {
			ipc_err("Timeout. Expected State:%d. Actual: %d",
				IPC_MEM_DEV_PM_ACTIVE,
				this->ap_state);
			return false;
		}
	}

	return true;
}

/*
 * Refer to header file for description
 */
int ipc_pm_host_sleep_wait_for_ack(struct ipc_pm *this)
{
	int status;

	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return -1;
	}

	atomic_set(&this->host_sleep_ack_waiting, 1);

	/* Wait for 500ms for Device sleep statemachine to enter ACTIVE
	 * state so that it can run in its own sleep statemachine during
	 * Host suspend.
	 */
	ipc_completion_reinit(&this->host_sleep_ack_complete);

	status = ipc_completion_wait_interruptible_timeout_ms(
		&this->host_sleep_ack_complete, 500);

	if (status == 0) {
		ipc_err("Timeout. Expected State:%d. Actual: %d",
			IPC_MEM_DEV_PM_ACTIVE,
			this->ap_state);

		atomic_set(&this->host_sleep_ack_waiting, 0);
	}

	return !status;
}


/* On link sleep function.
 */
static void ipc_pm_on_link_sleep(struct ipc_pm *this, bool ack)
{
	/* pending sleep ack and all conditions are cleared
	 * -> signal SLEEP__ACK to CP
	 */
	if (ack) {
		this->cp_state = IPC_MEM_DEV_PM_SLEEP;
		this->ap_state = IPC_MEM_DEV_PM_SLEEP;

		ipc_cp_irq_sleep_control(this->pcie, IPC_MEM_DEV_PM_SLEEP);

		/* sleep stress test enabled ? */
		if (this->params->wakeup_test > 0) {
			this->wakeup_tmo++;
			if (this->wakeup_tmo > this->params->wakeup_test)
				this->wakeup_tmo = 1;

			ipc_pm_wakeup_timer_start(this, this->wakeup_tmo);
		}
	}
}

/* On link wake up function.
 */
static void ipc_pm_on_link_wake(struct ipc_pm *this, bool ack)
{
	this->ap_state = IPC_MEM_DEV_PM_ACTIVE;

	if (ack) {
		this->cp_state = IPC_MEM_DEV_PM_ACTIVE;

		ipc_cp_irq_sleep_control(this->pcie, IPC_MEM_DEV_PM_ACTIVE);

		/* check the consume state !!! */
		if (atomic_cmpxchg(&this->host_sleep_pend, 1, 0))
			ipc_completion_signal(&this->host_sleep_complete);
	}

	/* Check for pending HPDA update.
	 * Pending HP update could be because of sending message was
	 * put on hold due to Device sleep state or due to TD update
	 * which could be because of Device Sleep and Host Sleep
	 * states.
	 */
	if (this->pending_hpda_update
	&& this->host_pm_state == IPC_MEM_HOST_PM_ACTIVE) {
		ipc_pm_signal_hpda_doorbell(this, IPC_HP_PM_TRIGGER);
	}
}

/* Update power manager and wake up the link if needed
 * return true if link is accessible
 */
static bool ipc_pm_trigger(struct ipc_pm *this, enum ipc_pm_unit unit,
		bool active)
{
	union ipc_pm_cond old_cond;
	union ipc_pm_cond new_cond;
	const char *unit_s;
	bool link_active;

	atomic_set(&this->sleep_handling, 1);

	/* Save the current D3 state.
	 */
	new_cond = old_cond = this->pm_cond;

	/* Calculate the power state only in the runtime phase.
	 */
	switch (unit) {
	case IPC_PM_UNIT_IRQ:	/* CP irq */
		unit_s = "IRQ";
		new_cond.irq = active;
		break;

	case IPC_PM_UNIT_LINK:	/* Device link state. */
		unit_s = "LINK";
		new_cond.link = active;
		break;

	case IPC_PM_UNIT_WAKEUP:	/* WAKEUP timer */
		unit_s = "WAKEUP";
		new_cond.wakeup = active;
		break;

	case IPC_PM_UNIT_HS:	/* Host sleep trigger requires Link. */
		unit_s = "HS";
		new_cond.hs = active;
		break;

	default:
		unit_s = "???";
		break;
	}			/* switch */

	/* Something changed ?
	 */
	if (old_cond.raw == new_cond.raw) {
		/* Stay in the current PM state.
		 */
		link_active = old_cond.link == IPC_PM_ACTIVE;
		goto ret;
	}

	this->pm_cond = new_cond;

	ipc_dbg("[%s->%s,%d%d%d%d]",
		unit_s,
		active ? "ACTIVE" : "SLEEP",
		new_cond.irq, new_cond.wakeup, new_cond.hs, new_cond.link);

	if (new_cond.link)
		ipc_pm_on_link_wake(this, unit == IPC_PM_UNIT_LINK);
	else
		ipc_pm_on_link_sleep(this, unit == IPC_PM_UNIT_LINK);

	ipc_trc_pm_state(this->cp_state,
			this->ap_state,
			old_cond.raw, new_cond.raw,
			unit_s, active ? "ACTIVE" : "SLEEP");

	if (old_cond.link == IPC_PM_SLEEP && new_cond.raw != 0) {
		link_active = ipc_pm_link_activate(this);
		goto ret;
	}

	link_active = old_cond.link == IPC_PM_ACTIVE;

ret:
	atomic_set(&this->sleep_handling, 0);
	return link_active;
}


/*
 * Refer to header file for description
 */
bool ipc_pm_unit_acquire(struct ipc_pm *this, enum ipc_pm_unit unit)
{
	return this ? ipc_pm_trigger(this, unit, true) : false;
}


/*
 * Refer to header file for description
 */
bool ipc_pm_unit_release(struct ipc_pm *this, enum ipc_pm_unit unit)
{
	return this ? ipc_pm_trigger(this, unit, false) : false;
}

/**
 * Refer to header file for description
 */
bool ipc_pm_prepare_host_sleep(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return false;
	}

	/* suspend not allowed if host_pm_state is not IPC_MEM_HOST_PM_ACTIVE */
	if (this->host_pm_state != IPC_MEM_HOST_PM_ACTIVE) {
		ipc_err("host_pm_state=%d\tExpected to be: %d",
			this->host_pm_state, IPC_MEM_HOST_PM_ACTIVE);
		return false;
	}

	this->host_pm_state = IPC_MEM_HOST_PM_SLEEP_WAIT_D3;

	return true;
}

/*
 * Refer to header file for description
 */
void ipc_pm_trigger_host_sleep(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("Invalid arguments");
		return;
	}

	ipc_pm_unit_acquire(this, IPC_PM_UNIT_HS);

	ipc_cp_irq_sleep_control(this->pcie, IPC_MEM_DEV_PM_HOST_SLEEP);

	ipc_pm_unit_release(this, IPC_PM_UNIT_HS);
}

/**
 * Refer to header file for description
 */
bool ipc_pm_prepare_host_active(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return false;
	}

	if (this->host_pm_state != IPC_MEM_HOST_PM_SLEEP) {
		ipc_err("host_pm_state=%d\tExpected to be: %d",
			this->host_pm_state, IPC_MEM_HOST_PM_SLEEP);
		return false;
	}

	/* Sending Sleep Exit message to CP. Update the state */
	this->host_pm_state = IPC_MEM_HOST_PM_ACTIVE_WAIT;

	return true;
}

/**
 * Refer to header file for description
 */
void ipc_pm_trigger_host_active(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("Invalid arguments");
		return;
	}

	ipc_cp_irq_sleep_control(this->pcie, IPC_MEM_DEV_PM_ACTIVE);
}

/**
 * Refer to header file for description
 */
void ipc_pm_set_host_sleep(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	this->host_pm_state = IPC_MEM_HOST_PM_SLEEP;
}

/**
 * Refer to header file for description
 */
void ipc_pm_set_host_active(struct ipc_pm *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	this->host_pm_state = IPC_MEM_HOST_PM_ACTIVE;
}

/**
 * Refer to header file for description
 */
void ipc_pm_print_stats(struct ipc_pm *this, struct seq_file *m)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	seq_printf(m, "PM IRQ...............: %u\n", this->pm_cond.irq);
	seq_printf(m, "PM HOST SLEEP........: %u\n", this->pm_cond.hs);
	seq_printf(m, "PM LINK..............: %u\n\n", this->pm_cond.link);
}

/**
 * Refer to header file for description
 */
bool ipc_pm_host_slp_notification(struct ipc_pm *this, u32 cp_pm_req)
{
	char *host_pm_state_str = NULL;

	if (unlikely(!this)) {
		ipc_err("Invalid arguments");
		return false;
	}

	/* If Host Sleep state machine is in ACTIVE state then the device sleep
	 * notification is not for Host Sleep.
	 */
	if (this->host_pm_state == IPC_MEM_HOST_PM_ACTIVE)
		return true;

	host_pm_state_str = ipc_pm_host_pm_state_to_string(this->host_pm_state);

	ipc_dbg("Host PM: %s, Requested: %s",
		host_pm_state_str,
		ipc_pm_get_sleep_notification_string(cp_pm_req));


	switch (this->host_pm_state) {
	case IPC_MEM_HOST_PM_SLEEP_WAIT_D3:

		switch (cp_pm_req) {
		case IPC_MEM_DEV_PM_HOST_SLEEP:
			/* Inform waiting for suspend semaphore */
			if (atomic_cmpxchg(&this->host_sleep_ack_waiting, 1, 0))
				ipc_completion_signal(
					&this->host_sleep_ack_complete);

			return false;

		case IPC_MEM_DEV_PM_SLEEP:
			ipc_dbg("Waiting for Host Sleep Ack. Ignoring device sleep req");
			return false;

		case IPC_MEM_DEV_PM_ACTIVE:
			ipc_dbg("Waiting for Host Sleep Ack. CP req ACTIVE received");
			break;
		}
		break;

	case IPC_MEM_HOST_PM_ACTIVE_WAIT:
		switch (cp_pm_req) {
		case IPC_MEM_DEV_PM_ACTIVE:
			/* Inform waiting for suspend semaphore */
			if (atomic_cmpxchg(&this->host_sleep_ack_waiting, 1, 0))
				ipc_completion_signal(
					&this->host_sleep_ack_complete);

			return false;

		case IPC_MEM_DEV_PM_SLEEP:
			ipc_dbg("Waiting for Host Sleep exit ack. Got dev PM sleep req");
			/* Inform waiting for resume semaphore */
			if (atomic_cmpxchg(&this->host_sleep_ack_waiting, 1, 0))
				ipc_completion_signal(
					&this->host_sleep_ack_complete);
			break;
		}
		break;

	case IPC_MEM_HOST_PM_SLEEP:
		/* Do not expect any state change */
		return false;

	default:
		ipc_err("confused loc-host_pm=%d, req-pm=%d",
			this->host_pm_state, cp_pm_req);

		return false;
	}

	return true;
}

/**
 * Refer to header file for description
 */
bool ipc_pm_dev_slp_notification(struct ipc_pm *this, u32 cp_pm_req)
{
	if (unlikely(!this)) {
		ipc_err("Invalid arguments");
		return false;
	}

	if (cp_pm_req == this->device_sleep_notification)
		return false;

	this->device_sleep_notification = cp_pm_req;

	ipc_dbg("Device PM: %s, Requested: %s",
		ipc_pm_get_sleep_notification_string(this->cp_state),
		ipc_pm_get_sleep_notification_string(cp_pm_req));

	ipc_trc_pm_dev_sleep_state(cp_pm_req, this->cp_state);

	/* Evaluate the PM request.
	 */
	switch (this->cp_state) {
	case IPC_MEM_DEV_PM_ACTIVE:
		switch (cp_pm_req) {
		case IPC_MEM_DEV_PM_ACTIVE:
			break;

		case IPC_MEM_DEV_PM_SLEEP:
			/* link will go down */
			ipc_debugfs_stats_device_sleep_event(this->stats, true);

			/* Inform the PM that the device link can go down. */
			ipc_pm_unit_release(this, IPC_PM_UNIT_LINK);

			return true;

		default:
			ipc_err("loc-pm=(%d=active): confused req-pm=%d",
				this->cp_state, cp_pm_req);
			break;
		}		/* switch */
		break;

	case IPC_MEM_DEV_PM_SLEEP:
		switch (cp_pm_req) {
		case IPC_MEM_DEV_PM_ACTIVE:
			ipc_debugfs_stats_device_sleep_event(this->stats,
				false);

			if (this->params->concurrent_wake_test > 0) {
				ipc_dbg("concurrent_wake: %u usec",
					this->concurrent_wake_tmo);

				ipc_cp_irq_sleep_control(this->pcie,
					IPC_MEM_DEV_PM_WAKEUP);

				udelay(this->concurrent_wake_tmo);
				this->concurrent_wake_tmo++;
				if (this->concurrent_wake_tmo >
					this->params->concurrent_wake_test)
					this->concurrent_wake_tmo = 1;
			}

			/* Inform the PM that the device link is active. */
			ipc_pm_unit_acquire(this, IPC_PM_UNIT_LINK);
			break;

		case IPC_MEM_DEV_PM_SLEEP:
			break;

		default:
			ipc_err("loc-pm=(%d=sleep): confused req-pm=%d",
				this->cp_state, cp_pm_req);
			break;
		}		/* switch */
		break;

	default:
		ipc_err("confused loc-pm=%d, req-pm=%d", this->cp_state,
			cp_pm_req);
		break;
	}			/* switch */

	return false;
}


/**
 * Refer to header file for description
 */
const char *ipc_pm_get_sleep_notification_string(
	u32 device_sleep_notification)
{
	switch (device_sleep_notification) {
	case IPC_MEM_DEV_PM_ACTIVE:
		return "ACTIVE";

	case IPC_MEM_DEV_PM_SLEEP:
		return "SLEEP";

	case IPC_MEM_DEV_PM_WAKEUP:
		return "WAKEUP";

	case IPC_MEM_DEV_PM_HOST_SLEEP:
		return "HOST_SLEEP";

	case IPC_MEM_DEV_PM_ACTIVE_WAIT:
		return "ACTIVE WAIT";

	default:
		return "???";
	}
}

/*
 * Refer to header file for description
 */
bool ipc_pm_is_device_in_sleep(struct ipc_pm *this)
{
	return this && this->pm_cond.link == IPC_PM_SLEEP;
}


/*
 * Refer to header file for description
 */
bool ipc_pm_is_device_sleep_handling(struct ipc_pm *this)
{
	return this && atomic_read(&this->sleep_handling);
}


/*
 * Refer to header file for description
 */
u32 ipc_pm_get_device_sleep_notification(struct ipc_pm *this)
{
	return this ? this->device_sleep_notification : -1;
}


/*
 * Check if PCIe link is down.
 *
 * returns true if link is down.
 *
 * @this: pointer to power management component
 */
static int ipc_pm_ctor(struct ipc_pm *this, struct ipc_pcie *pcie,
	struct ipc_debugfs_stats *stats, struct ipc_params *params,
	struct ipc_dbg *dbg, struct ipc_tasklet *tasklet)
{
	this->pcie = pcie;
	this->stats = stats;
	this->params = params;
	this->dbg = dbg;

	/* Initialize the PM conditions.
	 */
	this->pm_cond.irq = IPC_PM_SLEEP;
	this->pm_cond.hs = IPC_PM_SLEEP;
	this->pm_cond.link = IPC_PM_ACTIVE;

	this->cp_state = IPC_MEM_DEV_PM_ACTIVE;
	this->ap_state = IPC_MEM_DEV_PM_ACTIVE;
	this->host_pm_state = IPC_MEM_HOST_PM_ACTIVE;

	this->concurrent_wake_tmo = 0;
	this->wakeup_tmo = 0;
	this->tasklet = tasklet;

	/* Create generic wait-for-completion handler for Host Sleep
	 * and device sleep coordination.
	 */
	ipc_completion_init(&this->host_sleep_complete);

	atomic_set(&this->host_sleep_pend, 0);
	atomic_set(&this->sleep_handling, 0);

	/* Completion objects for Host sleep wait for ack if Messages are not
	 * used for communication.
	 */
	ipc_completion_init(&this->host_sleep_ack_complete);

	if (unlikely(!pcie || !params || !tasklet)) {
		ipc_err("invalid arguments");
		return -1;
	}

	this->wakeup_timer = ipc_hrtimer_alloc(this, this->dbg,
		ipc_pm_tl_wakeup_timer_cb, "wakeup timer", false, tasklet);

	if (unlikely(!this->wakeup_timer)) {
		ipc_err("failed to allocated timer");
		return -1;
	}

	return 0;
}

/* Ipc pm destructor.
 */
static void ipc_pm_dtor(struct ipc_pm *this)
{
	ipc_hrtimer_dealloc(&this->wakeup_timer);

	ipc_completion_signal(&this->host_sleep_complete);
	ipc_completion_signal(&this->host_sleep_ack_complete);
}


/**
 * Refer to header file for description
 */
struct ipc_pm *ipc_pm_alloc(struct ipc_pcie *pcie,
	struct ipc_debugfs_stats *stats,
	struct ipc_params *params, struct ipc_dbg *dbg,
	struct ipc_tasklet *tasklet)
{
	struct ipc_pm *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		return NULL;
	}

	if (ipc_pm_ctor(this, pcie, stats, params, dbg, tasklet)) {
		ipc_err("pm ctor failed");
		ipc_pm_dealloc(&this);
		return NULL;
	}

	return this;
}

/**
 * Refer to header file for description
 */
void ipc_pm_dealloc(struct ipc_pm **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_pm_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
