/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/pm_runtime.h>
#include <stddef.h>

#include "imc_ipc_util.h"
#include "imc_ipc_rtpm.h"
#include "imc_ipc_dbg.h"


struct ipc_rtpm {
	struct device           *device;
	bool                     is_enabled;
	spinlock_t               lock_runtime_pm;
	struct workqueue_struct *runtime_pm_workqueue;
	struct work_struct       runtime_disable_task;
	struct ipc_dbg *dbg;
};

#if defined(IPC_RUNTIME_PM)

/* Refer to header file for function description
 */
void ipc_rtpm_enable(struct ipc_rtpm *this, bool enable)
{
	unsigned long flags;

	if (unlikely(!this || !this->device)) {
		ipc_err("invalid params");
		return;
	}

	if (enable == this->is_enabled) {
		ipc_dbg("already enabled");
		return;
	}

	this->is_enabled = enable;

	ipc_dbg("enable=%d", enable);

	spin_lock_irqsave(&this->lock_runtime_pm, flags);

	/* This may also be called from interrupt context;
	 * Only pm_runtime_enable() can be called from atomic context,
	 * use workqueue context for pm_runtime_disable();
	 */
	if (enable)
		pm_runtime_enable(this->device);
	else
		queue_work(this->runtime_pm_workqueue,
			&this->runtime_disable_task);

	spin_unlock_irqrestore(&this->lock_runtime_pm, flags);
}


/* Refer to header file for function description
 */
void ipc_rtpm_get_hw(struct ipc_rtpm *this)
{
	if (likely(this && this->device))
		pm_runtime_get_sync(this->device);
}


/* Refer to header file for function description
 */
void ipc_rtpm_get_hw_no_sleep(struct ipc_rtpm *this)
{
	if (likely(this && this->device))
		pm_runtime_get(this->device);
}


/* Refer to header file for function description
 */
void ipc_rtpm_put_hw(struct ipc_rtpm *this)
{
	if (unlikely(!this || !this->device)) {
		ipc_err("invalid params");
		return;
	}

	pm_runtime_mark_last_busy(this->device);
	pm_runtime_put_autosuspend(this->device);
}


/* Refer to header file for function description
 */
void ipc_rtpm_mark_last_busy(struct ipc_rtpm *this)
{
	if (unlikely(!this || !this->device)) {
		ipc_err("invalid params");
		return;
	}

	pm_runtime_mark_last_busy(this->device);
}


/* Refer to header file for function description
 */
bool ipc_rtpm_is_enabled(struct ipc_rtpm *this)
{
	return this && this->is_enabled;
}

/* Runtime PM disable work function
 */
static void runtime_pm_disable_work(struct work_struct *work)
{
	struct ipc_rtpm *this = container_of(work, struct ipc_rtpm,
		runtime_disable_task);

	if (unlikely(!this || !this->device)) {
		ipc_err("invalid params");
		return;
	}

	pm_runtime_disable(this->device);
}

#endif /* IPC_RUNTIME_PM */


/* Runtime PM constructor function
 */
static int ipc_rtpm_ctor(struct ipc_rtpm *this, struct device *device,
			struct ipc_dbg *dbg)
{
	this->is_enabled = false;
	this->device = device;
	this->dbg = dbg;

#if defined(IPC_RUNTIME_PM)
	/* Initialize Runtime PM work */
	INIT_WORK(&this->runtime_disable_task, runtime_pm_disable_work);

	/* Create RTPM workqueue */
	spin_lock_init(&this->lock_runtime_pm);
	this->runtime_pm_workqueue = create_workqueue("imc_ipc/rtpm");
	if (unlikely(!this->runtime_pm_workqueue)) {
		ipc_err("create work queue failed");
		return -1;
	}

	pm_runtime_set_active(device);
	pm_runtime_set_autosuspend_delay(device, 5000);
	pm_runtime_use_autosuspend(device);
	pm_runtime_allow(device);
	pm_runtime_mark_last_busy(device);
	pm_runtime_put_noidle(device);
	pm_runtime_disable(device);

#endif /* IPC_RUNTIME_PM */

	return 0;
}


/* Runtime PM destructor function
 */
static void ipc_rtpm_dtor(struct ipc_rtpm *this)
{
	this->is_enabled = false;

#if defined(IPC_RUNTIME_PM)
	pm_runtime_get_noresume(this->device);

	cancel_work_sync(&this->runtime_disable_task);
	if (this->runtime_pm_workqueue) {
		destroy_workqueue(this->runtime_pm_workqueue);
		this->runtime_pm_workqueue = NULL;
	}

#endif /* IPC_RUNTIME_PM */
}


/* Refer to header file for function description
 */
struct ipc_rtpm *ipc_rtpm_alloc(struct device *device, struct ipc_dbg *dbg)
{
	struct ipc_rtpm *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		return NULL;
	}

	if (ipc_rtpm_ctor(this, device, dbg)) {
		ipc_err("ctor failed");
		ipc_rtpm_dealloc(&this);
		return NULL;
	}

	return this;
}


/* Refer to header file for function description
 */
void ipc_rtpm_dealloc(struct ipc_rtpm **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_rtpm_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}
