/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_COMPLETION_H
#define IMC_IPC_COMPLETION_H

#include <linux/completion.h>

/* Completion object - Allows to wait for object to be signaled  */

struct ipc_completion {
	struct completion c;
};

/*
 *  Initialize completion object.
 *
 *  @completion: pointer to completion object
 */
void ipc_completion_init(struct ipc_completion *completion);

/*
 *  Re-Initializes completion object. The wait queue is not touched.
 *
 *  @completion: pointer to completion object
 */
void ipc_completion_reinit(struct ipc_completion *completion);

/*
 * Signal a completion object, waking all processes waiting for this completion.
 *
 * @completion: pointer to completion object.
 */
void ipc_completion_signal(struct ipc_completion *completion);

/*
 * Wait for a completion to be signaled.
 * This may sleep and can therefore only be called from process context.
 *
 * @completion: pointer to completion object
 */
void ipc_completion_wait(struct ipc_completion *completion);

/*
 * Wait for a completion to be signaled.
 * This may sleep and can therefore only be called from process context.
 * This may return early if the process is interrupted.
 *
 * @completion: pointer to completion object
 *
 * @returns: < 0 if the waiting process got interrupted
 *             0 otherwise
 */
int ipc_completion_wait_interruptible(struct ipc_completion *completion);

/*
 * Wait for a completion to be signaled or a timeout occurs.
 * This may sleep and can therefore only be called from process context.
 *
 * @completion: pointer to completion object
 * @timeout: timeout in milliseconds
 *
 * @returns:   0 if the completion timed out
 *           > 0 if the completion was signaled
 */
int ipc_completion_wait_timeout_ms(
	struct ipc_completion *completion, unsigned int timeout);
/*
 * Wait for a completion to be signaled or a timeout occurs.
 * This may sleep and can therefore only be called from process context.
 * This may return early if the process is interrupted.
 *
 * @completion: pointer to completion object
 * @timeout: timeout in milliseconds
 *
 * @returns: < 0 if the waiting process got interrupted
 *             0 if the completion timed out
 *           > 0 if the completion was signaled
 */
int ipc_completion_wait_interruptible_timeout_ms(
	struct ipc_completion *completion, unsigned int timeout);


#endif
