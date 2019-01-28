/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_UEVENT_H
#define IMC_IPC_UEVENT_H

struct ipc_uevent;
struct ipc_debugfs;
struct ipc_dbg;


/* maximum length of user events */
#define MAX_UEVENT_LEN	64

/*
 * Send modem event to user space
 *
 * @this: pointer to ipc uevent data struct
 * @dev: device instance pointer
 * @uevent: user event string
 *
 * returns zero on success otherwise error code
 */
int ipc_uevent_send(struct ipc_uevent *this, struct device *dev, char *uevent);

/*
 * Allocates memory for the uevent structure.
 *
 * @instance_nr: Modem instance number
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_uevent *ipc_uevent_alloc(unsigned int instance_nr,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg);

/*
 * Frees all the memory allocated for the uevent
 * structure.
 *
 * @this_pp: pointer to the event data-struct
 */
void ipc_uevent_dealloc(struct ipc_uevent **this_pp);

/*
 * Get the last event str sent by driver
 *
 * @this: pointer to uevent instance
 * @uevent: uevent string to be returned
 * @len: size of the uevent string buffer
 *
 * returns zero on success
 */
int ipc_uevent_get_state(struct ipc_uevent *this, char *uevent, size_t len);

#endif /* IMC_IPC_UEVENT_H */
