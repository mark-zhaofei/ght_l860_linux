/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_UTIL_H
#define IMC_IPC_UTIL_H

#include <linux/compiler.h>

/* Return codes for internal IPC functions */
#define IPC_OK       (0)
#define IPC_FAIL    (-1)
#define IPC_TIMEOUT (-2)

/* Macros for checking return codes of functions returning any of the IPC error
 * codes above.
 *
 * Usage:
 *
 * if (IS_IPC_OK(function(x)) {
 *		do_stuff();
 * }
 *
 * if (IS_IPC_FAIL(function(x)) {
 *		do_other_stuff();
 */
#define IS_IPC_OK(x)   (likely((x) == IPC_OK))
#define IS_IPC_FAIL(x) (unlikely((x) != IPC_OK))



/* Structure to keep the address range variables together.
 */
struct ipc_util_addr_range {
	/* Variables to store Start and End address.
	 */
	u64 start;
	u64 end;
};

/* Structure for reference counting:
 *
 * Count usage and wait for last user to vacate before shutdown.
 */

struct ipc_util_refcount {
	atomic_t           count; /* usage count. Negative on shutdown */
	struct completion *completion; /* dtor waits for last user to vacate */
};

/**
 * Function to reset the address range variables.
 * addresses if PCIe Address Range Check (PARC) is supported.
 *
 * @p_range: pointer to the address range structure
 *
 * returns none.
 */
void ipc_util_reset_addr_range(struct ipc_util_addr_range *p_range);

/**
 * Allocate generic, zero initialized, local memory that does not need to be
 * shared with other devices.
 *
 * @size: size of memory to allocate
 *
 * returns pointer to allocated memory or NULL on failure
 */
__must_check void *ipc_util_kzalloc(size_t size);

/**
 * Allocate generic, zero initialized, local memory that does not need to be
 * shared with other devices. Does not wait and can be called from tasklet and
 * interrupt context.
 *
 * @size: size of memory to allocate
 *
 * returns pointer to allocated memory or NULL on failure
 */
__must_check void *ipc_util_kzalloc_atomic(size_t size);

/**
 * Free memory allocated with any of the ipc_util_kzalloc* functions
 *
 * @memory_p: pointer to memory to be freed
 *
 */
void ipc_util_kfree(const void *memory_p);


/**
 * Increment reference count and check for shutdown
 *
 * @refcount: pointer to ipc_util_refcount component
 *
 * returns true if count was increased, false if shutdown was requested
 */
bool __must_check ipc_util_refcount_try_get(struct ipc_util_refcount *refcount);

/**
 * Decrement reference count and trigger completion if waiting for shutdown
 *
 * @refcount: pointer to ipc_util_refcount component
 */
void ipc_util_refcount_put(struct ipc_util_refcount *refcount);

/**
 * Initialize reference count
 *
 * @refcount: pointer to ipc_util_refcount component
 */
void ipc_util_refcount_ctor(struct ipc_util_refcount *refcount);

/**
 * Destroy reference count, waiting until last user is gone
 *
 * @refcount: pointer to ipc_util_refcount component
 */

void ipc_util_refcount_dtor(struct ipc_util_refcount *refcount);

#endif				/* IMC_IPC_UTIL_H */
