/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */


#include <linux/kernel.h>

#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"

/*
 * ipc dbg constructor
 *
 * @this: pointer to struct ipc_dbg
 * @dev: pointer to struct system device
 *
 * return 0 on success else -1
 */
static int ipc_dbg_ctor(struct ipc_dbg *this, struct device *dev)
{
	if (unlikely(!this || !dev))
		return -1;

	this->dev = dev;
	return 0;
}

/*
 * ipc dbg destructor
 * @this: pointer to struct ipc_dbg
 */
static void ipc_dbg_dtor(struct ipc_dbg *this)
{
	this->dev = NULL;
}


/*
 * Refer to header file for description
 */
struct ipc_dbg *ipc_dbg_alloc(struct device *dev)
{
	struct ipc_dbg *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this))
		goto alloc_fail;

	if (ipc_dbg_ctor(this, dev))
		goto ctor_fail;

	return this;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}


/*
 * Refer to header file for description
 */
void ipc_dbg_dealloc(struct ipc_dbg **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_dbg_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/* Refer to header file for function description
 */
struct device *ipc_dbg_get_dev(struct ipc_dbg *this)
{
	return this->dev;
}

