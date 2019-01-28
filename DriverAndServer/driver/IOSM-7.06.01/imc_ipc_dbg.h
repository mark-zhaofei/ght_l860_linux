/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_DBG_H
#define IMC_IPC_DBG_H

#include <linux/device.h>

struct ipc_dbg {
	/* pointer to device structure */
	struct device *dev;
};

/* Dummy instance data for utility functions without own dbg element */
struct ipc_dbg_this {
	struct ipc_dbg *dbg;
};

/* An IMC-IPC status line start with *IMC-IPC* in the kernel log file.
 */
#define IPC_PROMPT  "imc_ipc"

/* The IMC-IPC status information are saved in the kernel log file with the
 * macro ip_debug(), which is mapped to printk() on the target.
 * Type the shell command
 * dmesg
 * to read the latest kernel messages including the IMC-IPC status information
 * on standard output.
 */

/* These IPC_DBG_FUNC_* Macros are wrappers for calling system
 * logging interfaces.
 * the "this" pointer which is pointing to each component's structure
 * and using its "dbg" member passed and initialized from pcie structure.
 * Finally could print both device information and modem instance in
 * the dev_*() IOSM logging.
 * If "this" or "this->dbg" is NULL then using pr_*() to print the logs
 * without device and instance information.
 */
#define IPC_DBG_FUNC_ERR(fmt, args...) \
	pr_err(IPC_PROMPT "-E- %s(%d): " fmt "\n", __func__, __LINE__, ##args)

#if !defined(IPC_DEBUG)

#define IPC_DBG_FUNC_DBG(fmt, args...)

#define ipc_hex_dump(msg, buf, len)

#define IPC_DBG_PR_DBG(fmt, args...)

#else

#define IPC_DBG_FUNC_DBG(fmt, args...) \
	dev_dbg(this && this->dbg ? this->dbg->dev : NULL, \
		"%s: " fmt, __func__, ##args)

#define ipc_hex_dump(msg, buf, len) \
	print_hex_dump(KERN_INFO, msg, \
		DUMP_PREFIX_OFFSET, 16, 1, buf, len, true)

#define IPC_DBG_PR_DBG(fmt, args...) \
	pr_debug(IPC_PROMPT " %s: " fmt "\n", __func__, ##args)

#endif

#define ipc_pr_dbg(fmt, args...)\
	IPC_DBG_PR_DBG(fmt, ##args)

#define ipc_dbg(fmt, args...) \
	IPC_DBG_FUNC_DBG(fmt, ##args)

#define ipc_err(fmt, args...) \
	IPC_DBG_FUNC_ERR(fmt, ##args)

/**
 * Get currenct modem system device pointer
 *
 * @this: pointer to ipc_dbg structure
 *
 * returns system device pointer or NULL
 */
struct device *ipc_dbg_get_dev(struct ipc_dbg *this);


/*
 * Allocates memory for the ipc_dbg.
 *
 * @dev: Modem system device pointer
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_dbg *ipc_dbg_alloc(struct device *dev);


/*
 * Frees the memory allocated for the ipc_dbg
 * component.
 *
 * @this_pp: pointer to the ipc_dbg data-struct
 */
void ipc_dbg_dealloc(struct ipc_dbg **this_pp);

#endif				/* IMC_IPC_DBG_H */
