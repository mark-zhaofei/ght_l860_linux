/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_RTPM_H
#define IMC_IPC_RTPM_H

struct ipc_rtpm;
struct device;
struct ipc_dbg;

/**
 * Allocate a RTPM instance
 *
 * @device: pointer to actual device. May be NULL for virtual hardware.
 * @dbg: pointer to ipc_dbg structure.
 */
struct ipc_rtpm *ipc_rtpm_alloc(struct device *device, struct ipc_dbg *dbg);

/**
 * Free a RTPM instance, freeing its pointer.
 *
 * @this_pp: pointer to RTPM pointer.
 */
void ipc_rtpm_dealloc(struct ipc_rtpm **this_pp);

/**
 * Enable runtime power management function
 *
 * @this: pointer to allocated ipc_rtpm structure
 * @enable: true if RTPM shall be enabled, false otherwise
 */
void ipc_rtpm_enable(struct ipc_rtpm *this, bool enable);

/**
 * Check whether runtime power management is enabled
 *
 * @this: pointer to allocated ipc_rtpm structure
 *
 */
bool ipc_rtpm_is_enabled(struct ipc_rtpm *this);

/**
 * Increment HW usage counter, resuming hw operation.
 * This operation may put the caller to sleep, therefore this may not
 * be called from atomic contexts.
 *
 * @this: pointer to allocated ipc_rtpm structure
 */
void ipc_rtpm_get_hw(struct ipc_rtpm *this);

/**
 * Increment HW usage counter, resuming hw operation.
 * This will not sleep and is safe to call from atomic context.
 *
 * @this: pointer to allocated ipc_rtpm structure
 */
void ipc_rtpm_get_hw_no_sleep(struct ipc_rtpm *this);


/**
 * Decrement HW usage counter, putting device to idle if it reaches 0
 *
 * @this: pointer to allocated ipc_rtpm structure
 */
void ipc_rtpm_put_hw(struct ipc_rtpm *this);

/**
 * Call this after carrying out I/O to mark last busy operation.
 * This (re)starts an inactivity timeout, after which the device
 * may be suspended.
 *
 * @this: pointer to allocated ipc_rtpm structure
 */
void ipc_rtpm_mark_last_busy(struct ipc_rtpm *this);


/* Remove calls to RTPM functions when IPC_RUNTIME_PM is not defined */
#if !defined(IPC_RUNTIME_PM)
#define ipc_rtpm_enable(this, enable)
#define ipc_rtpm_get_hw(this)
#define ipc_rtpm_get_hw_no_sleep(this)
#define ipc_rtpm_put_hw(this)
#define ipc_rtpm_mark_last_busy(this)
#define ipc_rtpm_is_enabled(this) (false)
#endif /* IPC_RUNTIME_PM */

#endif /* IMC_IPC_RTPM_H */
