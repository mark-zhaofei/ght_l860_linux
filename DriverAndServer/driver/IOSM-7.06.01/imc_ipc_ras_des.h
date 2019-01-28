/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_RAS_DES_H
#define IMC_IPC_RAS_DES_H


struct ipc_pcie_ras_des;
struct ipc_pcie;
struct ipc_debugfs;
struct ipc_dbg;

/* Vendor Specific ID of RAS DES capability
 */
#define INTEL_RAS_DES_VSEC_ID		0x02

#define INTEL_RAS_DES_INVALID_EVENT     0xFFFF
#define INTEL_RAS_DES_INVALID_INDEX     0xFFFFFFFF


enum intel_ras_des_timeout {
	INTEL_RAS_DES_TIMEOUT_MANUAL	= 0,
	INTEL_RAS_DES_TIMEOUT_1MS	= 1,
	INTEL_RAS_DES_TIMEOUT_10MS	= 2,
	INTEL_RAS_DES_TIMEOUT_100MS	= 3,
	INTEL_RAS_DES_TIMEOUT_1S	= 4,
	INTEL_RAS_DES_TIMEOUT_2S	= 5,
	INTEL_RAS_DES_TIMEOUT_4S	= 6
};


/* Event definition with name and event number */
struct ipc_pcie_ras_des_event {
	/* Name of the event */
	const char *name;
	/* Number of the event group & event */
	const u16 number;
};


/* Timer definition with name and timer number */
struct ipc_pcie_ras_des_timer {
	/* Name of the timer */
	const char *name;
	/* Number of the timer group & timer */
	const u8 number;
};


/**
 * Return the VSEC ID and Revision of the RAS DES Vendor Capability.
 *
 * @this: pointer to RAS DES handler.
 * @id: pointer to vsec id.
 * @rev: version of Vsec
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_vsec_id_rev(struct ipc_pcie_ras_des *this,
	u32 *id, u32 *rev);

/**
 * Returns the number of events available.
 *
 * @this: pointer to RAS DES handler.
 *
 * returns 0 or a positive number on sucess, -1 on failure
 */
int ipc_pcie_ras_des_number_of_events(struct ipc_pcie_ras_des *this);

/**
 * Returns a pointer to the events descriptor array.
 *
 * @this: pointer to RAS DES handler.
 *
 * returns a pointer to the events array.
 */
struct ipc_pcie_ras_des_event *ipc_pcie_ras_des_events(
	struct ipc_pcie_ras_des *this);

/**
 * Enables the selected event by writing to Control register.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the event
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_enable_event(struct ipc_pcie_ras_des *this, u16 event);

/**
 * Disables the selected event by writing to Control register.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the event
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_disable_event(struct ipc_pcie_ras_des *this, u16 event);

/**
 * Get counter value for the selected event.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the event
 * @p_counter: pointer to buffer for the value of the counter
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_get_event_counter(struct ipc_pcie_ras_des *this,
	u16 event, u32 *p_counter);

/**
 * Clear counter value for the selected event.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the event
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_clear_event(struct ipc_pcie_ras_des *this, u16 event);

/**
 * Function for reading the enabled status for the specified event.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the event
 * @p_status: on success status value will be updated in the address pointed
 *            in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_ras_des_event_status(struct ipc_pcie_ras_des *this,
	u16 event, u32 *p_status);


/* Lookup the index of the timer in the timer descriptor array.
 * @this: pointer to RAS DES handler.
 * @timer: pointer to timer name
 * returns the index of the timer on sucess,
 * INTEL_RAS_DES_INVALID_INDEX on failure
 */
u8 ipc_pcie_ras_des_look_up_timer(struct ipc_pcie_ras_des *this, char *timer);


/**
 * Starts the selected timer with given timeout.
 *
 * @this: pointer to RAS DES handler.
 * @event: numerical value of the timer event
 * @timeout: timeout representation
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_start_timer(struct ipc_pcie_ras_des *this,
	u8 timer, enum intel_ras_des_timeout timeout);

/**
 * Stop the last started timer.
 *
 * @this: pointer to RAS DES handler.
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_stop_timer(struct ipc_pcie_ras_des *this);

/**
 * Get counter value for the last started timer.
 *
 * @this: pointer to RAS DES handler.
 * @p_counter: pointer to buffer for the value of the counter
 *
 * returns 0 on sucess, -1 on failure
 */
int ipc_pcie_ras_des_timer_counter(struct ipc_pcie_ras_des *this,
	u32 *p_counter);

/**
 * Function for reading the running status for last started timer.
 *
 * @this: pointer to RAS DES handler.
 * @p_status: on success status value will be updated in the address pointed
 *            in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_ras_des_timer_status(struct ipc_pcie_ras_des *this,
	u32 *p_status);

/**
 * Function for saving the RAS DES Vendor Specific Extended Capability locally
 *
 * @this: pointer to RAS DES handler.
 *
 * returns none
 */
void ipc_pcie_ras_des_save_cap(struct ipc_pcie_ras_des *this);

/**
 * Function for restoring the RAS DES Vendor Specific Extended Capability
 * locally
 *
 * @this: pointer to RAS DES handler.
 *
 * returns none
 */
void ipc_pcie_ras_des_restore_cap(struct ipc_pcie_ras_des *this);

/*
 * Function for opening the RAS DES instance.
 * @pcie: pointer to struct ipc_pcie.
 * @dbgfs: pointer to struct ipc_debugfs.
 * @dbg: pointer to debug component
 *
 * returns pointer to RAS DES handler.
 */
struct ipc_pcie_ras_des *ipc_pcie_ras_des_alloc(struct ipc_pcie *pcie,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg);

/**
 * Function for closing the RAS DES instance.
 *
 * @this_pp: pointer to RAS DES handler.
 *
 * returns none
 */
void ipc_pcie_ras_des_dealloc(struct ipc_pcie_ras_des **this_pp);



#endif /* !defined (IMC_IPC_RAS_DES_H) */

