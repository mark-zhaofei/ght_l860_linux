/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_PM_H
#define IMC_IPC_PM_H

struct ipc_pm;
struct ipc_pcie;
struct ipc_debugfs_stats;
struct ipc_params;
struct ipc_tasklet;
struct ipc_dbg;

/* Power management units.
 */
enum ipc_pm_unit {
	IPC_PM_UNIT_IRQ,	/* IRQ towards CP */
	IPC_PM_UNIT_WAKEUP,	/* WAKEUP towards CP */
	IPC_PM_UNIT_HS,		/* Host Sleep for converged protocol */
	IPC_PM_UNIT_LINK	/* Link state controlled by CP. */
};

/*
 * Allocate power management component
 *
 * @cb_instance: instance pointer for callback interface
 * @cb: callback interface
 * @pcie: pointer to pcie component, will be used for triggering interrupts
 * @stats: pointer to stats component, will be used for counting sleep and
 *         activation events
 * @params: pointer to params component
 * @dbg: pointer to ipc_dbg structure
 * @tasklet: pointer to tasklet component
 *
 * Returns pointer to allocated PM component or NULL on failure.
 */
struct ipc_pm *ipc_pm_alloc(struct ipc_pcie *pcie,
	struct ipc_debugfs_stats *stats,
	struct ipc_params *params, struct ipc_dbg *dbg,
	struct ipc_tasklet *tasklet);

/*
 * Free power management component, invalidating its pointer.
 *
 * @this_pp: pointer to pm component pointer
 */
void ipc_pm_dealloc(struct ipc_pm **this_pp);

/*
 * Acquire a specific pm_unit before use.
 *
 * If any unit is acquired and modem requests sleep, an immediate wake
 * signal is sent to the modem after the sleep signal was acknowledged.
 *
 * @this: pointer to power management component
 * @unit: actual PM unit to aquire
 *
 * returns true if link is accessible false otherwise.
 */
bool ipc_pm_unit_acquire(struct ipc_pm *this, enum ipc_pm_unit unit);

/*
 * Release a specific pm_unit after use.
 *
 * If all units (except IPC_PM_UNIT_LINK) are released, no immediate wake
 * signal is sent to the modem after acknowledging a modem requested sleep.
 *
 * @this: pointer to power management component
 * @unit: actual PM unit to release
 *
 * returns true if link is accessible false otherwise.
 */
bool ipc_pm_unit_release(struct ipc_pm *this, enum ipc_pm_unit unit);


/*
 * Handle a sleep notification change from the device.
 * This can be called from interrupt context. This function handles Host Sleep
 * requests only.
 *
 * @this: pointer to power management component
 * @sleep_notification: actual notification from device
 *
 * returns true if host sleep state has to be checked, false otherwise.
 */
bool ipc_pm_host_slp_notification(struct ipc_pm *this, u32 cp_pm_req);


/*
 * Handle a sleep notification message from the device.
 * This can be called from interrupt state. This function handles Host Sleep
 * requests too if the Host Sleep protocol is register based.
 *
 * @this: pointer to power management component
 * @sleep_notification: actual notification from device
 *
 * returns true if dev sleep state has to be checked, false otherwise.
 */
bool ipc_pm_dev_slp_notification(struct ipc_pm *this,
	u32 sleep_notification);

/*
 * Get a string describing a sleep notification message
 *
 * @sleep_notification: actual notification from device
 *
 * returns the string of the sleep notification
 */
const char *ipc_pm_get_sleep_notification_string(u32 sleep_notification);

/*
 * Prepare the PM for sleep by entering IPC_MEM_HOST_PM_SLEEP_WAIT_D3 state.
 *
 * @this: pointer to power management component
 *
 * Returns true on success, false if the host was not active.
 */
bool ipc_pm_prepare_host_sleep(struct ipc_pm *this);


/*
 * If the host sleep is based on registers then this function will set
 * sleep control register SLEEP which is called during Host Sleep enter.
 * This function also takes care of waking up the device sleep if it is in
 * sleep.
 *
 * @this: pointer to power management component
 *
 * returns none
 */
void ipc_pm_trigger_host_sleep(struct ipc_pm *this);


/*
 * Set the PM to sleep by entering IPC_MEM_HOST_PM_SLEEP state.
 *
 * @this: pointer to power management component
 */
void ipc_pm_set_host_sleep(struct ipc_pm *this);


/*
 * Prepare the PM for wakeup by entering IPC_MEM_HOST_PM_ACTIVE_WAIT state.
 *
 * @this: pointer to power management component
 *
 * Returns true on success, false if the host was not sleeping.
 */
bool ipc_pm_prepare_host_active(struct ipc_pm *this);


/*
 * If the host sleep is based on registers then this function will set
 * sleep control register ACTIVE which is called during Host Sleep exit.
 *
 * @this: pointer to power management component
 *
 * returns none
 */
void ipc_pm_trigger_host_active(struct ipc_pm *this);


/*
 * Set the PM to active by entering IPC_MEM_HOST_PM_ACTIVE state.
 *
 * @this: pointer to power management component
 */
void ipc_pm_set_host_active(struct ipc_pm *this);

/*
 * Check if device is sleeping.
 *
 * @this: pointer to power management component
 *
 * returns true if device is sleeping
 */
bool ipc_pm_is_device_in_sleep(struct ipc_pm *this);

/*
 * Check if device sleep handling already in progress.
 *
 * @this: pointer to power management component
 *
 * returns true if device sleep handling ongoing false otherwise
 */
bool ipc_pm_is_device_sleep_handling(struct ipc_pm *this);

/*
 * Wait for up to IPC_PM_ACTIVE_TIMEOUT_MS milliseconds for the device to reach
 * active state
 *
 * @this: pointer to power management component
 *
 * returns true if device is active
 */
bool ipc_pm_wait_for_device_active(struct ipc_pm *this);


/*
 * Wait for up to 500 milliseconds for the device to acknowledge
 * host sleep request
 *
 * @this: pointer to power management component
 *
 * returns 0 if CP gives ack within timeout, non-zero value otherwise
 */
int ipc_pm_host_sleep_wait_for_ack(struct ipc_pm *this);


/*
 *  Wake up the device if it is in low power mode and trigger a
 *  head pointer update interrupt.
 *
 * This may be postponed if this was not triggered by a is_mr_update
 * and the AP is currently in state IPC_MEM_HOST_PM_SLEEP_WAIT_IDLE,
 * IPC_MEM_HOST_PM_SLEEP_WAIT_D3, IPC_MEM_HOST_PM_SLEEP or
 * IPC_MEM_HOST_PM_SLEEP_WAIT_EXIT_SLEEP,
 * or if
 * the AP is currently in state IPC_MEM_DEV_PM_ACTIVE_WAIT or
 * IPC_MEM_DEV_PM_SLEEP
 *
 * @this: pointer to power management component
 * @identifier: specifies what component triggered hpda update irq
 */
void ipc_pm_signal_hpda_doorbell(struct ipc_pm *this, u32 identifier);

/*
 * Prints internal statistics into seq_file.
 *
 * @this: pointer to power management component
 * @m: seq_file to print statistics into.
 */
void ipc_pm_print_stats(struct ipc_pm *this, struct seq_file *m);

#endif				/* IMC_IPC_PM_H */
