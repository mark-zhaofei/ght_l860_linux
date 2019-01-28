/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/stddef.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include "imc_ipc_util.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_tasklet.h"	/* IPC tasklet layer */
#include "imc_ipc_dbg.h"
#include "imc_ipc_completion.h"

/* Number of available element for the input message queue
 * of the IPC tasklet.
 */
#define IPC_THREAD_QUEUE_SIZE  256


struct ipc_tasklet_msg {
	/* Function to be called in tasklet (tl) context */
	int (*func)(void *instance, int arg, void *msg, size_t size);

	/* Instance pointer for function to be called in tasklet context */
	void *instance;

	/* OS object used to wait for the tasklet function to finish for
	 * synchronous calls.
	 */
	struct ipc_completion *completion;

	/* Message argument for tasklet function. (optional, can be NULL) */
	void *msg;

	/* Message size argument for tasklet function (optional) */
	size_t size;

	/* Generic integer argument for tasklet function (optional) */
	int arg;

	/* Is true if msg contains a pointer to a copy of the original message
	 * for asynchronous calls that needs to be freed once the tasklet
	 * returns.
	 */
	bool is_copy;

	/* Return code of tasklet function for synchronous calls */
	int response;
};

struct ipc_tasklet {
	/* Protect the message queue of the ipc tasklet.
	 */
	spinlock_t q_lock;

	/* tasklet */
	struct tasklet_struct tasklet;

	/* Message queue of the IPC tasklet.
	 */
	struct ipc_tasklet_msg queue[IPC_THREAD_QUEUE_SIZE];

	/* First queue element to process. */
	unsigned int q_rpos;

	/* First free element of the input queue. */
	unsigned int q_wpos;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};


/* Actual tasklet function, will be called whenever tasklet is scheduled.
 * Calls event handler callback for each element in the message queue
 */
static void ipc_tasklet_handler(unsigned long data)
{
	struct ipc_tasklet *this = (struct ipc_tasklet *)data;
	unsigned int q_rpos = this->q_rpos;

	/* Loop over the input queue contents.
	 */
	while (q_rpos != this->q_wpos) {
		/* Get the current first queue element.
		 */
		struct ipc_tasklet_msg *msg = &this->queue[q_rpos];

		/* Process the input message.
		 */
		if (msg->func)
			msg->response = msg->func(msg->instance, msg->arg,
				msg->msg, msg->size);

		/* Signal completion for synchronous calls
		 */
		if (msg->completion)
			ipc_completion_signal(msg->completion);

		/* Free message if copy was allocated.
		 */
		if (msg->is_copy)
			ipc_util_kfree(msg->msg);

		/* Set invalid queue element. Technically
		 * spin_lock_irqsave is not required here as
		 * the array element has been processed already
		 * so we can assume that immediately after processing
		 * this element, queue will not rotate again to
		 * this same element within such short time.
		 */
		msg->completion = NULL;
		msg->func = NULL;
		msg->msg = NULL;
		msg->size = 0;
		msg->is_copy = false;

		/* calculate the new read pointer and
		 * update the volatile read pointer
		 */
		q_rpos = (q_rpos + 1) % IPC_THREAD_QUEUE_SIZE;
		this->q_rpos = q_rpos;
	}
}

/* Free memory allocations and trigger completions left in the queue
 * during dtor.
 */
static void ipc_tasklet_cleanup_queue(struct ipc_tasklet *this)
{
	unsigned int q_rpos = this->q_rpos;

	while (q_rpos != this->q_wpos) {
		struct ipc_tasklet_msg *msg = &this->queue[q_rpos];

		if (msg->completion) {
			ipc_completion_signal(msg->completion);
			msg->completion = NULL;
		}

		if (msg->is_copy) {
			ipc_util_kfree(msg->msg);
			msg->is_copy = false;
			msg->msg = NULL;
		}

		q_rpos = (q_rpos + 1) % IPC_THREAD_QUEUE_SIZE;
		this->q_rpos = q_rpos;
	}
}

/* Add a message to the queue and trigger the tasklet.
 * returns true on success.
 */
static int ipc_tasklet_send(struct ipc_tasklet *this, int arg, void *arg_p,
	int (*func)(void *instance, int arg, void *msg_p, size_t size),
	void *instance, size_t size, bool is_copy, bool wait)
{
	unsigned long flags;
	unsigned int pos, nextpos;
	int result = IPC_FAIL;
	struct ipc_completion completion;

	ipc_completion_init(&completion);

	/* tasklet send may be called from both interrupt or thread
	 * context, therefore protect queue operation by spinlock
	 */
	spin_lock_irqsave(&this->q_lock, flags);

	pos = this->q_wpos;
	nextpos = (pos + 1) % IPC_THREAD_QUEUE_SIZE;

	/* Get next queue position. */
	if (nextpos != this->q_rpos) {
		/* Get the reference to the queue element and save the
		 * passed values.
		 */
		this->queue[pos].arg = arg;
		this->queue[pos].msg = arg_p;
		this->queue[pos].func = func;
		this->queue[pos].instance = instance;
		this->queue[pos].size = size;
		this->queue[pos].is_copy = is_copy;
		this->queue[pos].completion = wait ? &completion : NULL;
		this->queue[pos].response = IPC_FAIL;

		/* apply write barrier so that this->q_rpos elements are
		 * updated before this->q_wpos is being updated.
		 */
		smp_wmb();

		/* Update the status of the free queue space. */
		this->q_wpos = nextpos;
		result = IPC_OK;
	}

	spin_unlock_irqrestore(&this->q_lock, flags);

	ipc_trc_tasklet_queue(this->q_rpos, this->q_wpos, func, wait ? 1 : 0);

	if (IS_IPC_OK(result)) {
		tasklet_schedule(&this->tasklet);

		if (wait) {
			ipc_completion_wait(&completion);
			result = this->queue[pos].response;
		}
	} else {
		ipc_err("queue is full");
	}

	return result;
}


/**
 * Refer to header file for description
 */
int ipc_tasklet_call_async(struct ipc_tasklet *this,
	int (*func)(void *instance, int arg, void *msg, size_t size),
	void *instance, int arg, void *msg, size_t size)
{
	void *copy = msg;
	bool is_copy = false;

	if (unlikely(!this || !func || !instance)) {
		ipc_err("invalid arguments");
		return IPC_FAIL;
	}

	if (size > 0) {
		copy = ipc_util_kzalloc_atomic(size);
		if (unlikely(!copy))  {
			ipc_err("failed to allocate memory");
			/* This tracepoint is required for throughput testing.
			 * Tracepoints are generally not used for error logging.
			 */
			ipc_trc_evnt_err("failed to alloc mem.");
			return IPC_FAIL;
		}

		memcpy(copy, msg, size);
		is_copy = true;
	}

	if (IS_IPC_FAIL(ipc_tasklet_send(this, arg, copy, func, instance, size,
		is_copy, false))) {
		ipc_err("failed for %pf(%p, %d, %p, %zu, %d)", func, instance,
			arg, copy, size, is_copy);
		/* This tracepoint is required for throughput testing.
		 * Tracepoints are generally not used for error logging.
		 */
		ipc_trc_evnt_err("ipc_tasklet_send failed");
		ipc_util_kfree(copy);
		return IPC_FAIL;
	}

	return IPC_OK;
}

/**
 * Refer to header file for description
 */
int ipc_tasklet_call(struct ipc_tasklet *this,
	int (*func)(void *instance, int arg, void *msg, size_t size),
	void *instance, int arg, void *msg, size_t size)
{
	if (unlikely(!this || !func || !instance)) {
		ipc_err("invalid arguments");
		return IPC_FAIL;
	}

	return ipc_tasklet_send(this, arg, msg, func, instance, size,
		false, true);
}


/*
 * ipc_tasklet constructor, takes message handling callback as argument
 */
static int ipc_tasklet_ctor(struct ipc_tasklet *this, struct ipc_dbg *dbg)
{
	memset(this, 0, sizeof(*this));

	this->dbg = dbg;

	/* Initialize the spinlock needed to protect the message queue of the
	 * IPC tasklet.
	 */
	spin_lock_init(&this->q_lock);

	tasklet_init(&this->tasklet, ipc_tasklet_handler, (unsigned long)this);

	return 0;
}

/*
 * ipc_tasklet destructor
 */
static void ipc_tasklet_dtor(struct ipc_tasklet *this)
{
	/* Handle NULL ptr gracefully similar to free() */
	if (unlikely(!this))
		return;

	ipc_dbg("Tasklet kill");
	tasklet_kill(&this->tasklet);

	/* This will free/complete any outstanding messages,
	 * without calling the actual handler
	 */
	ipc_dbg("Freeing queue");
	ipc_tasklet_cleanup_queue(this);

	ipc_dbg("Done");
}

/**
 * Refer to header file for description
 */
struct ipc_tasklet *ipc_tasklet_alloc(struct ipc_dbg *dbg)
{
	struct ipc_tasklet *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("kmalloc failed");
	} else if (ipc_tasklet_ctor(this, dbg)) {
		ipc_util_kfree(this);
		this = NULL;
	}

	return this;
}

/**
 * Refer to header file for description
 */
void ipc_tasklet_dealloc(struct ipc_tasklet **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_tasklet_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

/* imc_ipc_tasklet.c ends here */
