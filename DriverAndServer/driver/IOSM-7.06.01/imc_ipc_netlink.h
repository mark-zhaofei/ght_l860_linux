/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_NETLINK_H
#define IMC_IPC_NETLINK_H

struct ipc_netlink;
struct ipc_dbg;

/*
 * send an event to all listners
 *
 * @this: pointer to netlink data-struct
 * @event: netlink event string
 * @dbg: pointer to ipc_dbg structure
 *
 * returns 0 if write was successfuly else negative error code
 */
int ipc_netlink_event(struct ipc_netlink *this, char *event,
				struct ipc_dbg *dbg);

/*
 * Allocates memory for the netlink structure.
 *
 * @instance_nr: Modem instance number
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_netlink *ipc_netlink_alloc(void);

/*
 * Frees all the memory allocated for the netlink
 * structure.
 *
 * @this_pp: pointer to the netlink data-struct
 */

void ipc_netlink_dealloc(struct ipc_netlink **this_pp);


#endif				/* IMC_IPC_NETLINK_H */
