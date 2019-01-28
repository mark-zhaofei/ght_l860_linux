/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_TASKLET_H
#define IMC_IPC_TASKLET_H

struct ipc_tasklet;
struct ipc_dbg;

/*
 * Allocate a tasklet
 *
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated tasklet data-struct
 * or NULL on failure.
 */
struct ipc_tasklet *ipc_tasklet_alloc(struct ipc_dbg *dbg);

/* Free a tasklet, invalidating its pointer.
 *
 * @this_pp: pointer to tasklet instance
 */
void ipc_tasklet_dealloc(struct ipc_tasklet **this_pp);

/* Asynchronously call a function that will be executed in tasklet context.
 * The message argument will be copied, when msg != NULL and size > 0
 * The tasklet message handler will not be called.
 *
 * @this: pointer to tasklet instance
 * @func: function to be called in tasklet context
 * @instance: instance pointer argument for func
 * @arg:      integer argument for func
 * @msg:      message pointer argument for func. if != NULL and size > 0,
 *            message will be copied before calling tasklet
 * @size:     size argument. If > 0 and msg != NULL, message will be copied.
 *
 * @returns: 0, if call was successfully scheduled, -1 otherwise.
 *
 */
int ipc_tasklet_call_async(struct ipc_tasklet *this,
	int (*func)(void *instance, int arg, void *msg, size_t size),
	void *instance, int arg, void *msg, size_t size);

/* Synchronously call a function in tasklet context and wait for the result.
 * The tasklet message handler will not be called.
 *
 * @this: pointer to tasklet instance
 * @func: function to be called in tasklet context
 * @instance: instance pointer argument for func
 * @arg:      integer argument for func
 * @msg:      message pointer argument for func
 * @size:     size argument for func
 *
 * @returns: result value returned by func or -1 if func could not be called.
 */
int ipc_tasklet_call(struct ipc_tasklet *this,
	int (*func)(void *instance, int arg, void *msg, size_t size),
	void *instance, int arg, void *msg, size_t size);


#endif				/* IMC_IPC_TASKLET_H */
