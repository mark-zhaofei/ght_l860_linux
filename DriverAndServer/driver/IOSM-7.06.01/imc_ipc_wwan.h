/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_WWAN_H
#define IMC_IPC_WWAN_H

#define IMEM_WWAN_DATA_VLAN_ID_START	1
#define IMEM_WWAN_DATA_VLAN_ID_END	IPC_IMEM_MUX_SESSION_ENTRIES
#define IMEM_WWAN_CTRL_VLAN_ID_START	257
#define IMEM_WWAN_CTRL_VLAN_ID_END	512
#define IMEM_WWAN_DATA_LLC_ID_START	513
#define IMEM_WWAN_DATA_LLC_ID_END	768

struct ipc_wwan;
struct ipc_dbg;


struct ipc_wwan_ops {
	/* open channel for vlan id vid, return channel id or -1 on failure */
	int (*open)(void *instance, int vid);

	/* close channel ch_id */
	void (*close)(void *instance, int vid, int ch_id);

	/* transmit data on channel ch_id */
	int (*transmit)(void *instance, int vid, int ch_id,
		struct sk_buff *skb);
};


/* timesync request, used to return data to caller after timesync request
 * has been triggered on the modem.
 */
struct ipc_timesync {
	u32 id;        /* t-sync id */
	u64 local_time; /* local timestamp */
	u64 remote_time; /* Remote timestamp */
	u32 local_time_unit; /* Time unit of local timestamp */
	u32 remote_time_unit; /* Time unit of remote timestamp */
};

/**
 * Allocate and register WWAN device
 * @ops: pointer to callback functions
 * @ops_instance: instance pointer for callback
 * @instance_nr: Modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to instance on success else NULL
 */
struct ipc_wwan *ipc_wwan_alloc(const struct ipc_wwan_ops *ops,
	void *ops_instance, unsigned int instance_nr,
	struct ipc_dbg *dbg);

/**
 * Unregister and free WWAN device, clear pointer
 * @this_pp: pointer to pointer to wwan instance data
 */
void ipc_wwan_dealloc(struct ipc_wwan **this_pp);

/**
 * Receive a downlink packet from CP.
 * @this: pointer to wwan instance
 * @skb: pointer to struct sk_buff
 * @dss: set to true if vlan id is greate than IMEM_WWAN_CTRL_VLAN_ID_START
 *       else false
 *
 * return 0 on success else error code
 */
int ipc_wwan_receive(struct ipc_wwan *this, struct sk_buff *skb, bool dss);

/**
 * Flush WWAN device
 * @this: pointer to wwan instance
 */
void ipc_wwan_flush(struct ipc_wwan *this);

/**
 * Update device statistics
 * @dev: pointer to the actual device
 * @id: ipc mux channel session id
 * @len: number of bytes to update
 * @tx: true if statistics needs to be updated for transmit else false
 *
 * return 0 on success else error code
 */
int ipc_wwan_update_stats(struct ipc_wwan *this, int id, size_t len, bool tx);

/**
 * Enable/Disable TX flow control
 * @this: pointer to wwan instance
 * @id: ipc mux channel session id
 * @on: if true then flow control would be enabled else disable
 *
 * return 0 on success else error code
 */
int ipc_wwan_tx_flowctrl(struct ipc_wwan *this, int id, bool on);

/**
 * Register a callback for time synchronization requests. This will be
 * called when the device specific ioctl has been issued towards the
 * modem root device.
 *
 * @this: pointer to wwan instance
 * @timesync_cb: function pointer to callback
 * @instance: instance pointer for the callback
 *
 */
void ipc_wwan_register_timesync(struct ipc_wwan *this,
	int (*timesync_cb)(void *, struct ipc_timesync *),  void *instance);


/*
 * Get network device statistics
 *
 * @this:  pointer to wwan instance
 * @id: ipc mux channel session id
 * @tx: True for Tx, False for Rx
 * @packets: number of packets Rx'ed or Tx'ed
 * @bytes: number of bytes Rx'ed or Tx'ed
 *
 * return 0 on success else error code
 */
int ipc_wwan_get_vlan_stats(struct ipc_wwan *this, int id,
		bool tx, unsigned long *packets,
		unsigned long *bytes);

/*
 * Checks if Tx stopped for a VLAN id.
 *
 * return true if stopped, false otherwise
 */
bool ipc_wwan_is_tx_stopped(struct ipc_wwan *this, int id);

#endif

