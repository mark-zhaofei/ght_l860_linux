/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/slab.h>

#include "imc_ipc_dbg.h"
#include "imc_ipc_util.h"

/**
 * Global functions
 */


/* Refer to header file for function description
 */
void ipc_util_reset_addr_range(struct ipc_util_addr_range *p_range)
{
	if (!p_range)
		return;

	/* For the reconfigure logic the reset value of Start address is
	 * 0xFFFF FFFF FFFF FFFF and the End address is 0 initialized.
	 */
	p_range->start = ~0;
	p_range->end = 0;
}


/* Refer to header file for function description
 */
__must_check void *ipc_util_kzalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}


/* Refer to header file for function description
 */
__must_check void *ipc_util_kzalloc_atomic(size_t size)
{
	return kzalloc(size, GFP_ATOMIC);
}


/* Refer to header file for function description
 */
void ipc_util_kfree(const void *memory_p)
{
	kzfree(memory_p);
}


/* Refer to header file for function description
 */
bool __must_check ipc_util_refcount_try_get(struct ipc_util_refcount *refcount)
{
	return atomic_inc_unless_negative(&refcount->count) != 0;
}

/* Refer to header file for function description
 */
void ipc_util_refcount_put(struct ipc_util_refcount *refcount)
{
	/* if count is INT_MIN, we were the last user and
	 * ipc_refcount_dtor is waiting for the last user to vacate
	 */
	if (atomic_dec_return(&refcount->count) == INT_MIN) {
		if (refcount->completion) {
			ipc_pr_dbg("waking up dtor");
			complete(refcount->completion);
		} else {
			ipc_err("no completion");
		}
	}
}

/* Refer to header file for function description
 */
void ipc_util_refcount_ctor(struct ipc_util_refcount *refcount)
{
	atomic_set(&refcount->count, 0);
	refcount->completion = NULL;
}

/* Refer to header file for function description
 */
void ipc_util_refcount_dtor(struct ipc_util_refcount *refcount)
{
	DECLARE_COMPLETION_ONSTACK(completion);

	might_sleep();

	if (atomic_read(&refcount->count) < 0) {
		ipc_err("dtor was called before");
		return;
	}

	refcount->completion = &completion;

	/* Adding INT_MIN to a count in range 0..INT_MAX will always
	 * result in a negative number; This is the indication that we
	 * will shut down and ipc_refcount_inc will return false.
	 * (INT_MIN + 0 is INT_MIN,  INT_MIN + INT_MAX == -1 )
	 */
	if (atomic_add_return(INT_MIN, &refcount->count) != INT_MIN) {
		ipc_pr_dbg("waiting for count to reach zero");
		wait_for_completion(&completion);
	}

	refcount->completion = NULL;
}
