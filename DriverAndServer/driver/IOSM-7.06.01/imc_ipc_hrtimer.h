/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_HRTIMER_H
#define IMC_IPC_HRTIMER_H

struct ipc_tasklet;
struct ipc_hrtimer;
struct ipc_dbg;

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
	const char *name, bool is_cyclic, struct ipc_tasklet *tasklet);

/* Free a timer, invalidating its pointer.
 *
 * @this_pp: pointer to timer pointer that was allocated with
 *                ipc_hrtimer_alloc.
 */
void ipc_hrtimer_dealloc(struct ipc_hrtimer **this_pp);

/* Configure and start (period != 0) or stop (period == 0) timer.
 *
 *  @this: timer instance
 *  @period_us: timer period in us or 0 to disable timer;
 */
void ipc_hrtimer_config(struct ipc_hrtimer *this, unsigned long period_us);

/* Check if timer is currently active
 *
 * @this: timer instance to check
 *
 * returns true if timer is active
 */
bool ipc_hrtimer_is_active(struct ipc_hrtimer *this);

#endif /* IMC_IPC_HRTIMER_H */
