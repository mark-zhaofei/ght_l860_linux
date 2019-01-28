/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/kernel.h>
#include <linux/hrtimer.h>

#include "imc_ipc_hrtimer.h"
#include "imc_ipc_tasklet.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"

struct ipc_hrtimer {
	struct hrtimer timer;                          /* OS timer object */
	ktime_t        period;                         /* period as ktime_t */
	void         (*callback)(void *callback_data); /* callback */
	void          *callback_data;                  /* callback data */
	const char    *name;                           /* time name */
	bool           is_periodic;                    /* periodicity */
	bool           is_shutting_down;     /* Timer is about to be deleted */
	struct ipc_tasklet *tasklet; /* if set: run cb in tasklet context */
	struct ipc_dbg *dbg;	/* pointer to ipc_dbg structure */
};


/* Common timer callback for tasklet context
 */
static int ipc_hrtimer_tl_cb(void *instance, int arg, void *msg, size_t size)
{
	struct ipc_hrtimer *this = instance;

	if (unlikely(!this || !this->callback)) {
		ipc_err("invalid arguments");
		return -1;
	}

	ipc_dbg("%s expired, calling tasklet %pf", this->name, this->callback);
	this->callback(this->callback_data);

	return 0;
}

/* Common timer callback - updates expiration time for periodic timers
 * and calls user defined code.
 */
static enum hrtimer_restart ipc_hrtimer_cb(struct hrtimer *hr_timer)
{
	enum hrtimer_restart result = HRTIMER_NORESTART;

	struct ipc_hrtimer *this =
		container_of(hr_timer, struct ipc_hrtimer, timer);

	if (this->is_periodic && ktime_to_ns(this->period) != 0) {
		hrtimer_forward(&this->timer, ktime_get(), this->period);
		result = HRTIMER_RESTART;
	} else {
		this->period = ktime_set(0, 0);
	}

	if (!this->callback)
		return result;

	if (this->tasklet) {
		ipc_tasklet_call_async(this->tasklet, ipc_hrtimer_tl_cb,
			this, 0, NULL, 0);
	} else {
		ipc_dbg("%s expired, calling cb=%pf", this->name,
			this->callback);
		this->callback(this->callback_data);
	}

	return result;
}

/* Configure and start (period != 0) or stop (period == 0) timer.
 *
 *  @this: timer instance
 *  @period_us: timer period in us or 0 to disable timer;
 */
void ipc_hrtimer_config(struct ipc_hrtimer *this, unsigned long period_us)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return;
	}

	if (hrtimer_cancel(&this->timer))
		ipc_dbg("name='%s' stopped", this->name);

	this->period = ktime_set(0, period_us * 1000ULL);

	if (!this->is_shutting_down && period_us != 0) {
		hrtimer_start(&this->timer, this->period, HRTIMER_MODE_REL);
		ipc_dbg("name='%s' started, period=%lu us",
			this->name, period_us);
	}
}

/* Check if timer is currently active
 *
 * @this: timer instance to check
 *
 * returns true if timer is active
 */
bool ipc_hrtimer_is_active(struct ipc_hrtimer *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid arguments");
		return false;
	}
	return hrtimer_active(&this->timer);
}

/* Timer constructor
 */
static void ipc_hrtimer_ctor(struct ipc_hrtimer *this, struct ipc_dbg *dbg,
	void *callback_data, void (*callback)(void *), const char *name,
	bool is_periodic, struct ipc_tasklet *tasklet)
{
	memset(this, 0, sizeof(*this));

	this->dbg = dbg;

	ipc_dbg("name='%s' cb=%pf, is_periodic=%d",
		name, callback, is_periodic);

	hrtimer_init(&this->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	this->timer.function = ipc_hrtimer_cb;
	this->period = ktime_set(0, 0);
	this->callback = callback;
	this->callback_data = callback_data;
	this->name = name ? name : "<anonymous>";
	this->is_periodic = is_periodic;
	this->is_shutting_down = false;
	this->tasklet = tasklet;
}


/* Callback function for synchronization with tasklet context
 * during timer shutdown
 */
static int ipc_hrtimer_tl_sync_cb(void *instance, int arg, void *msg,
	size_t size)
{
	return 0;
}

/* Timer destructor
 */
static void ipc_hrtimer_dtor(struct ipc_hrtimer *this)
{
	/* prevent restart */
	this->is_shutting_down = true;

	/* stop timer */
	ipc_hrtimer_config(this, 0);

	/* Issue a synchronous tasklet call to make sure that any previously
	 * enqueued but not yet executed tasklet callbacks are finished before
	 * the data structure is freed.
	 */
	if (this->tasklet)
		ipc_tasklet_call(this->tasklet, ipc_hrtimer_tl_sync_cb,
			this, 0, NULL, 0);

	this->callback = NULL;
	this->callback_data = NULL;
}

/*
 * Allocate a timer, providing a callback that will be triggered when it
 * expires.
 *
 * @instance_p: pointer argument to callback routine instance
 * @dbg: pointer to ipc_dbg structure
 * @callback: callback routine to be called when timer expires
 * @name: optional identifier, used for logging.
 * @is_cyclic: if true, timer is cyclic, otherwise timer is one shot.
 * @tasklet: when non NULL: execute callback in tasklet context
 *
 * returns pointer to allocated timer data-struct
 * or NULL on failure.
 */
struct ipc_hrtimer *ipc_hrtimer_alloc(void *instance_p,
	struct ipc_dbg *dbg, void (*callback)(void *instance_p),
	const char *name, bool is_cyclic, struct ipc_tasklet *tasklet)
{
	struct ipc_hrtimer *this = ipc_util_kzalloc(sizeof(*this));

	if (this)
		ipc_hrtimer_ctor(this, dbg, instance_p,
			callback, name, is_cyclic, tasklet);
	else
		ipc_err("kmalloc failed");

	return this;
}

/* Free a timer, invalidating its pointer.
 *
 * @this_pp: pointer to timer pointer that was allocated with
 *                ipc_hrtimer_alloc.
 */
void ipc_hrtimer_dealloc(struct ipc_hrtimer **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_hrtimer_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
