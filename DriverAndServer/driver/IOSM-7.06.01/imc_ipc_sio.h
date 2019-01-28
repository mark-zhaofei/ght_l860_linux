/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_SIO_H
#define IMC_IPC_SIO_H

struct ipc_dbg;
struct ipc_sio;
struct ipc_pcie;
struct ipc_params;

struct ipc_sio_ops {
	/* Open a channel, @instance is ops_instance given at ipc_sio_alloc
	 * expected to return a positive channel id or negative status on
	 * failure
	 */
	int (*open)(void *instance);

	/* Close a channel, @instance is ops_instance given at ipc_sio_alloc,
	 * @channel_id is the id returned by open callback.
	 */
	void (*close)(void *instance, int channel_id);

	/* Write @count @data bytes to a channel. @instance is ops_instance
	 * given at ipc_sio_alloc,
	 * @channel_id is the id returned by open callback.
	 * expected to return the number of bytes written, or a negatie status
	 * on failure.
	 */
	int (*write)(void *instace, int channel_id, const unsigned char *data,
		int count, bool blocking);
};

/* Receive downlink characters from CP, the downlink skbuf is added
 * at end the end of the downlink or rx list.
 *
 * @this:  pointer to ipc char data-struct
 * @skb: pointer to sk buffer
 *
 * returns zero on success
 */
int ipc_sio_receive(struct ipc_sio *this, struct sk_buff *skb);

/*
 * Allocate and create a character device
 *
 * @dbg: pointer to debug log component
 * @pcie: pointer to pcie data-struct
 * @params: pointer to ipc parameters
 * @ops: pointer to operation callbacks
 * @ops_instance:  operation callback instance data;
 * name: pointer to character device name
 *
 * returns zero on success
 */
struct ipc_sio *ipc_sio_alloc(struct ipc_dbg *dbg, struct ipc_pcie *pcie,
	struct ipc_params *params, struct ipc_sio_ops *ops, void *ops_instance,
	const char *name);
/*
 * Frees all the memory allocated for the ipc sio
 * structure.
 *
 * @this_pp: pointer to the ipc sio data-struct
 */
void ipc_sio_dealloc(struct ipc_sio **this_pp);

/*
 * Frees all the memory allocated for the ipc sio
 * structure. Can be called from tasklet.
 * therefore schedule the actual work to be run
 * in a thread context.
 *
 * @this: pointer to the ipc sio data-struct
 */
void ipc_sio_free_deferred(struct ipc_sio **this);

#endif				/* IMC_IPC_SIO_H */
