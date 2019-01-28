/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include "imc_ipc_completion.h"

#include <linux/jiffies.h>
#include <linux/completion.h>

/* Refer to header file for function description
 */
void ipc_completion_init(struct ipc_completion *completion)
{
	init_completion(&completion->c);
}

/* Refer to header file for function description
 */
void ipc_completion_reinit(struct ipc_completion *completion)
{
	reinit_completion(&completion->c);
}

/* Refer to header file for function description
 */
void ipc_completion_signal(struct ipc_completion *completion)
{
	complete(&completion->c);
}

/* Refer to header file for function description
 */
void ipc_completion_wait(struct ipc_completion *completion)
{
	wait_for_completion(&completion->c);
}

/* Refer to header file for function description
 */
int ipc_completion_wait_interruptible(struct ipc_completion *completion)
{
	return wait_for_completion_interruptible(&completion->c);
}

/* Refer to header file for function description
 */
int ipc_completion_wait_timeout_ms(
	struct ipc_completion *completion, unsigned int timeout)
{
	return wait_for_completion_timeout(&completion->c,
		msecs_to_jiffies(timeout));
}

/* Refer to header file for function description
 */
int ipc_completion_wait_interruptible_timeout_ms(
	struct ipc_completion *completion, unsigned int timeout)
{
	return wait_for_completion_interruptible_timeout(&completion->c,
		msecs_to_jiffies(timeout));
}
