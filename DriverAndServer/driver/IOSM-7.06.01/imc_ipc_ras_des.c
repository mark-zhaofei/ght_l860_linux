/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/types.h>
#include <linux/delay.h> /* usleep_range() */

#include "imc_ipc_ras_des.h"
#include "imc_ipc_util.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_debugfs.h"

/* RAS DES Enhanced Capability Header
 */
#define INTEL_RAS_DES_ECH		0x000

#define INTEL_RAS_DES_VSH		0x004

#define INTEL_RAS_DES_EVENT_CONTROL_REG	0x008
#define INTEL_RAS_DES_EVENT_STATUS_REG	0x00C

#define INTEL_RAS_DES_TB_CONTROL_REG	0x010
#define INTEL_RAS_DES_TB_STATUS_REG	0x014


#define INTEL_RAS_DES_PER_EVENT_DISABLE	0x1 /* 0b001 */
#define INTEL_RAS_DES_PER_EVENT_ENABLE	0x3 /* 0b011 */
#define INTEL_RAS_DES_ALL_EVENT_DISABLE	0x5 /* 0b101 */
#define INTEL_RAS_DES_ALL_EVENT_ENABLE	0x7 /* 0b111 */


#define INTEL_RAS_DES_PER_EVENT_CLEAR	0x1 /* 0b01 */
#define INTEL_RAS_DES_ALL_EVENT_CLEAR	0x3 /* 0b11 */

#define INTEL_RAS_DES_RETRY_COUNT	3 /* Read Retry count */
/* Min Back off time in us */
#define INTEL_RAS_DES_RETRY_WAIT_TIME_MIN	1000
/* Max Back off time in us */
#define INTEL_RAS_DES_RETRY_WAIT_TIME_MAX	1500


/* Private structures
 */
/* Structure for RAS DES handler
 */
struct ipc_pcie_ras_des {
	/* Structure hold VSEC variables */
	struct ipc_pcie_vsec pcie_vsec;
	/* IPC PCIe */
	struct ipc_pcie *pcie;
	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	/* Debugfs */
	struct ipc_debugfs_ras_des *dbgfs;
};

/* Event Counter Control Register
 */
union ipc_pcie_event_counter_control {
	u32 raw;
	struct {
		u32 clear:2;		/* Clear selected or all events */
		u32 enable:3;	/* Enable/disable selected or all events  */
		u32:2;			/* reserved */
		u32 status:1;		/* Enable status of the event counter */
		u32 lane_select:4;	/* Lane for the event counter */
		u32:4;			/* reserved */
		u32 event_select:12;	/* Event select */
		u32:4;			/* reserved */
	} control;
};

/* Timer Based Analysis Control Register
 */
union ipc_pcie_timer_control {
	u32 raw;
	struct {
		u32 running:1;	/* Timer start / running*/
		u32:7;		/* reserved */
		u32 duration:8;	/* Timer duration */
		u32:8;		/* reserved */
		u32 timer:8;	/* Timer select */
	} control;
};

/* Event Counter Data Register
 */
union ipc_pcie_timer_data {
	u32 raw;
	struct {
		u32 data:32;	/* Event data of the configured event */
	} data;
};


/* Static array of the event description and numbers */
static struct ipc_pcie_ras_des_event event_descriptors[] = {
	/* group 0 */
	{"EBUF_OVERFLOW",		0x0000},
	{"EBUF_UNDERRUN",		0x0001},
	{"DECODE_ERROR",		0x0002},
	{"RUNNING_DISPARITY_ERROR",	0x0003},
	{"SKP_OS_PARITY_ERROR",		0x0004},
	{"SYNC_HEADER_ERROR",		0x0005},
	{"RX_VALID_DEASSERTION",	0x0006},
	/* group 1 - events 0 to 4 are reserved */
	{"DETECT_EI_INFER",		0x0105},
	{"RECEIVER_ERROR",		0x0106},
	{"RX_RECOVERY_REQUEST",		0x0107},
	{"N_FTS_TIMEOUT",		0x0108},
	{"FRAMING_ERROR",		0x0109},
	{"DESKEW_ERROR",		0x010A},
	/* group 2 */
	{"BAD_TLP",			0x0200},
	{"LCRC_ERROR",			0x0201},
	{"BAD_DLLP",			0x0202},
	{"REPLAY_NUMBER_ROLLOVER",	0x0203},
	{"REPLAY_TIMEOUT",		0x0204},
	{"RX_NAK_DLLP",			0x0205},
	{"RX_NAK_DLLP",			0x0206},
	{"RETRY_TLP",			0x0207},
	/* group 3 */
	{"FC_TIMEOUT",			0x0300},
	{"POISONED_TLP",		0x0301},
	{"ECRC_ERROR",			0x0302},
	{"UNSUPPORTED_REQUEST",		0x0303},
	{"COMPLETER_ABORT",		0x0304},
	{"COMPLETION_TIMEOUT",		0x0305},
	/* group 4 */
	{"EBUF_SKP_ADD",		0x0400},
	{"EBUF_SKP_DEL",		0x0401},
	/* group 5 */
	{"L0_TO_RECOVERY_ENTRY",	0x0500},
	{"L1_TO_RECOVERY_ENTRY",	0x0501},
	{"TX_L0_ENTRY",			0x0502},
	{"RX_L0_ENTRY",			0x0503},
	{"ASPM_L1_REJECT",		0x0504},
	{"L1_ENTRY",			0x0505},
	{"L1_CPM",			0x0506},
	{"L11_ENTRY",			0x0507},
	{"L12_ENTRY",			0x0508},
	{"L1_SHORT_DURATION",		0x0509},
	{"L12_ABORT",			0x050A},
	{"L2_ENTRY",			0x050B},
	{"SPEED_CHANGE",		0x050C},
	{"LINK_WIDTH_CHANGE",		0x050D},
	/* group 6 */
	{"TX_ACK_DLLP",			0x0600},
	{"TX_UPDATE_FC_DLLP",		0x0601},
	{"RX_ACK_DLLP",			0x0602},
	{"RX_UPDATE_FC_DLLP",		0x0603},
	{"RX_NULLIFIED_TLP",		0x0604},
	{"TX_NULLIFIED_TLP",		0x0605},
	{"RX_DUPLICATE_TLP",		0x0606},
	/* group 7 */
	{"TX_MEMORY_WRITE",		0x0700},
	{"TX_MEMORY_READ",		0x0701},
	/* group 7 - event 2 & 3 reserved */
	{"TX_IO_WRITE",			0x0704},
	{"TX_IO_READ",			0x0705},
	{"TX_COMPLETION_WITHOUT_DATA", 0x0706},
	{"TX_COMPLETION_WITH_DATA",	0x0707},
	{"TX_MESSAGE_TLP",		0x0708},
	{"TX_ATOMIC",			0x0709},
	{"TX_TLP_WITH_PREFIX",		0x070A},
	{"RX_MEMORY_WRITE",		0x070B},
	{"RX_MEMORY_READ",		0x070C},
	{"RX_CONFIG_WRITE",		0x070D},
	{"RX_CONFIG_READ",		0x070E},
	{"RX_TX_IO_WRITE",		0x070F},
	{"RX_IO_READ",			0x0710},
	{"RX_COMPLETION_WITHOUT_DATA",	0x0711},
	{"RX_COMPLETION_WITH_DATA",	0x0712},
	{"RX_MESSAGE_TLP",		0x0713},
	{"RX_ATOMIC",			0x0714},
	{"RX_TLP_WITH_PREFIX",		0x0715}
};


/* Static array of the timer description and numbers */
static struct ipc_pcie_ras_des_timer timer_descriptors[] = {
	/* group 0 */
	{"TX_L0S",		0x01},
	{"RX_L0S",		0x02},
	{"L0",			0x03},
	{"L1",			0x04},
	{"L11",			0x05},
	{"L12",			0x06},
	{"CONFIG_REVOVERY",	0x07},
	/* group 1 */
	{"TX_TLP_DATA",		0x20},
	{"RX_TLP_DATA",		0x21}
};


/* Local functions
 */

/**
 * Helper function for finding the Vendor Specific Extended Capability
 * with with Extended Capability ID as 0x0B
 * and Vendor Specific Capability ID as 0x02.
 *
 * @this: pointer to RAS DES handler.
 * @pcie: pointer to the core driver data-struct of pcie.
 *
 *             If find is successful then base_addr, vsec_id and
 *             vsec_ver will be initialized otherwise they will have
 *             0xFFFF
 *
 * returns 0 on sucess, -1 on failure
 */
static int ipc_pcie_ras_des_find_vsec(struct ipc_pcie_ras_des *this,
	struct ipc_pcie *pcie)
{
	int ret_val = -1;
	struct pcie_extended_cap vsec_cap = {0};
	int offset = 0;

	if (unlikely(!this || !pcie)) {
		ipc_err("Invalid arguments");
		return ret_val;
	}

	/* Save the pcie address.
	 */
	this->pcie = pcie;

	/* Reset the value to 0xFFFF
	 */
	this->pcie_vsec.base_addr = -1;
	this->pcie_vsec.vsec_id = -1;
	this->pcie_vsec.vsec_ver = -1;

	if (ipc_pcie_find_vsec_id(this->pcie, &vsec_cap,
				&offset, INTEL_RAS_DES_VSEC_ID)) {
		ipc_dbg("RAS DES is not supported");
		return ret_val;
	}

	this->pcie_vsec.base_addr = offset;
	this->pcie_vsec.vsec_id = vsec_cap.cap_id;
	this->pcie_vsec.vsec_len = vsec_cap.next_offset;
	this->pcie_vsec.vsec_ver = vsec_cap.cap_ver;

	ipc_dbg("RAS DES supported! Offset:0x%x, VSEC ID:0x%x, VSEC Len: %d",
		this->pcie_vsec.base_addr, this->pcie_vsec.vsec_id,
		this->pcie_vsec.vsec_len);


	/* Allocate memory to save VSEC extended capability during
	 * suspend/hibernate. The fist 12 bytes of VSEC is RO registers.
	 */
	this->pcie_vsec.p_save_cap =
		ipc_util_kzalloc_atomic(this->pcie_vsec.vsec_len);

	/* RAS DES is found
	 */
	ret_val = 0;

	return ret_val;
}


/* Returns if the given event number is a valid event.
 *
 * @this: pointer to RAS DES handler.
 * @event: event number to be checked.
 *
 * returns 0 or a positive number on sucess, -1 on failure
 */
static bool ipc_pcie_ras_des_is_event_valid(struct ipc_pcie_ras_des *this,
	u16 event)
{
	int i;
	const u32 number_of_events = ipc_pcie_ras_des_number_of_events(this);

	for (i = 0; i < number_of_events; i++) {
		if (event == event_descriptors[i].number)
			return true;
	}

	return false;
}


/**
 * Returns the number of timers available.
 *
 * @this: pointer to RAS DES handler.
 *
 * returns 0 or a positive number on sucess, -1 on failure
 */
static int ipc_pcie_ras_des_number_of_timers(struct ipc_pcie_ras_des *this)
{
	return sizeof(timer_descriptors) /
		sizeof(struct ipc_pcie_ras_des_timer);
}


/**
 * Returns if the given timer number is a valid timer.
 *
 * @this: pointer to RAS DES handler.
 * @timer: timer number to be checked.
 *
 * returns 0 or a positive number on sucess, -1 on failure
 */
static bool ipc_pcie_ras_des_is_timer_valid(struct ipc_pcie_ras_des *this,
	u8 timer)
{
	int i;
	const int number_of_timers = ipc_pcie_ras_des_number_of_timers(this);

	for (i = 0; i < number_of_timers; i++) {
		if (timer == timer_descriptors[i].number)
			return true;
	}

	return false;
}


/* Global functions
 */

/* Refer to header file for function description
 */
int ipc_pcie_ras_des_vsec_id_rev(struct ipc_pcie_ras_des *this,
	u32 *id, u32 *rev)
{
	if (unlikely(!this || !id || !rev)) {
		ipc_err("Invalid argument");
		return -1;
	}

	*id = this->pcie_vsec.vsec_id;
	*rev = this->pcie_vsec.vsec_ver;

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_number_of_events(struct ipc_pcie_ras_des *this)
{
	return sizeof(event_descriptors) /
		sizeof(struct ipc_pcie_ras_des_event);
}


/* Refer to header file for function description
 */
struct ipc_pcie_ras_des_event *ipc_pcie_ras_des_events(
	struct ipc_pcie_ras_des *this)
{
	return event_descriptors;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_enable_event(struct ipc_pcie_ras_des *this, u16 event)
{
	union ipc_pcie_event_counter_control event_ctrl_reg;
	u32 enabled = 0;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_event_valid(this, event))) {
		ipc_err("Invalid event");
		return -1;
	}

	ipc_pcie_ras_des_event_status(this, event, &enabled);

	if (!enabled) {
		event_ctrl_reg.control.lane_select = 0;
		event_ctrl_reg.control.event_select = event;
		event_ctrl_reg.control.enable = INTEL_RAS_DES_PER_EVENT_ENABLE;

		ipc_pcie_config_write32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_CONTROL_REG,
					event_ctrl_reg.raw);
	}

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_disable_event(struct ipc_pcie_ras_des *this, u16 event)
{
	union ipc_pcie_event_counter_control event_ctrl_reg;
	u32 enabled = 0;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_event_valid(this, event))) {
		ipc_err("Invalid event");
		return -1;
	}

	ipc_pcie_ras_des_event_status(this, event, &enabled);

	if (enabled) {
		event_ctrl_reg.raw = 0;
		event_ctrl_reg.control.lane_select = 0;
		event_ctrl_reg.control.event_select = event;
		event_ctrl_reg.control.enable = INTEL_RAS_DES_PER_EVENT_DISABLE;

		ipc_pcie_config_write32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_CONTROL_REG,
					event_ctrl_reg.raw);
	}

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_get_event_counter(struct ipc_pcie_ras_des *this,
	u16 event, u32 *p_counter)
{
	union ipc_pcie_event_counter_control event_ctrl_reg,
		event_ctrl_reg_readback;
	u32 enabled = 0;
	u32 retry_count = INTEL_RAS_DES_RETRY_COUNT;

	if (unlikely(!this || !p_counter)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_event_valid(this, event))) {
		ipc_err("Invalid event");
		return -1;
	}

	ipc_pcie_ras_des_event_status(this, event, &enabled);

	if (!enabled) {
		ipc_err("event enable failed");
		return -1;
	}

	event_ctrl_reg.raw = 0;
	event_ctrl_reg.control.lane_select = 0;
	event_ctrl_reg.control.event_select = event;

	while (retry_count != 0) {
		ipc_pcie_config_write32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_CONTROL_REG,
					event_ctrl_reg.raw);
		ipc_pcie_config_read32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_STATUS_REG,
					p_counter);
		ipc_pcie_config_read32(this->pcie,
				this->pcie_vsec.base_addr +
					INTEL_RAS_DES_EVENT_CONTROL_REG,
					&event_ctrl_reg_readback.raw);
		if (event_ctrl_reg.control.event_select !=
				event_ctrl_reg_readback.control.event_select) {
			/* concurrent CP access backoff */
			usleep_range(INTEL_RAS_DES_RETRY_WAIT_TIME_MIN,
					INTEL_RAS_DES_RETRY_WAIT_TIME_MAX);
			retry_count--;
			ipc_dbg("Retries RAS DES Event Control register access: %d",
					retry_count);
		} else
			break;
	}

	if (retry_count == 0) {
		/* Race condition on register access */
		ipc_err("Race condition on RAS DES Event control register access");
		return -1;
	}
	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_clear_event(struct ipc_pcie_ras_des *this, u16 event)
{
	union ipc_pcie_event_counter_control event_ctrl_reg;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_event_valid(this, event))) {
		ipc_err("Invalid event");
		return -1;
	}

	event_ctrl_reg.raw = 0;
	event_ctrl_reg.control.lane_select = 0;
	event_ctrl_reg.control.event_select = event;
	event_ctrl_reg.control.clear = INTEL_RAS_DES_PER_EVENT_CLEAR;

	ipc_pcie_config_write32(this->pcie,
				this->pcie_vsec.base_addr +
					INTEL_RAS_DES_EVENT_CONTROL_REG,
				event_ctrl_reg.raw);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_event_status(struct ipc_pcie_ras_des *this,
	u16 event, u32 *p_status)
{
	union ipc_pcie_event_counter_control event_ctrl_reg,
		event_ctrl_reg_readback;
	u32 retry_count = INTEL_RAS_DES_RETRY_COUNT;

	if (unlikely(!this || !p_status)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_event_valid(this, event))) {
		ipc_err("Invalid event");
		return -1;
	}

	event_ctrl_reg.raw = 0;
	event_ctrl_reg.control.lane_select = 0;
	event_ctrl_reg.control.event_select = event;

	while (retry_count != 0) {
		ipc_pcie_config_write32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_CONTROL_REG,
					event_ctrl_reg.raw);

		ipc_pcie_config_read32(this->pcie,
					this->pcie_vsec.base_addr +
						INTEL_RAS_DES_EVENT_CONTROL_REG,
					&event_ctrl_reg_readback.raw);
		if (event_ctrl_reg.control.event_select !=
				event_ctrl_reg_readback.control.event_select) {
			/* concurrent CP access backoff */
			usleep_range(INTEL_RAS_DES_RETRY_WAIT_TIME_MIN,
					INTEL_RAS_DES_RETRY_WAIT_TIME_MAX);
			retry_count--;
			ipc_dbg("Retries RAS DES Event Control register access: %d",
					retry_count);
		} else {
			*p_status = event_ctrl_reg_readback.control.status;
			break;
		}
	}

	if (retry_count == 0) {
		/* Race condition on register access */
		ipc_err("Race condition on RAS DES Event control register access");
		return -1;
	}
	return 0;
}


/* Lookup the timer number in the timer descriptor array.
 *
 * returns the number of the timer on sucess, NULL on failure
 */
u8 ipc_pcie_ras_des_look_up_timer(struct ipc_pcie_ras_des *this, char *timer)
{
	int i;
	int number_of_timers;

	if (unlikely(!this || !timer)) {
		ipc_err("Invalid argument");
		return -1;
	}

	number_of_timers = ipc_pcie_ras_des_number_of_timers(this);

	for (i = 0; i < number_of_timers; i++) {
		if (!strcmp(timer_descriptors[i].name,
				timer)) {
			return timer_descriptors[i].number;
		}
	}

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_start_timer(struct ipc_pcie_ras_des *this,
	u8 timer, enum intel_ras_des_timeout timeout)
{
	union ipc_pcie_timer_control timer_ctrl_reg;
	u32 running;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -1;
	}

	if (unlikely(!ipc_pcie_ras_des_is_timer_valid(this, timer))) {
		ipc_err("Invalid evnt time");
		return -1;
	}

	if (unlikely(timeout > INTEL_RAS_DES_TIMEOUT_4S)) {
		ipc_err("timeout is more than max timeout");
		return -1;
	}

	ipc_pcie_ras_des_timer_status(this, &running);

	if (running) {
		ipc_err("Timer already running");
		return -1;
	}

	timer_ctrl_reg.control.timer = timer;
	timer_ctrl_reg.control.duration = timeout;
	timer_ctrl_reg.control.running = 1;

	ipc_pcie_config_write32(this->pcie,
			this->pcie_vsec.base_addr +
			INTEL_RAS_DES_TB_CONTROL_REG, timer_ctrl_reg.raw);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_stop_timer(struct ipc_pcie_ras_des *this)
{
	union ipc_pcie_timer_control timer_ctrl_reg;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return -1;
	}

	ipc_pcie_config_read32(this->pcie,
			this->pcie_vsec.base_addr +
			INTEL_RAS_DES_TB_CONTROL_REG, &timer_ctrl_reg.raw);

	timer_ctrl_reg.control.running = 0;

	ipc_pcie_config_write32(this->pcie,
			this->pcie_vsec.base_addr +
			INTEL_RAS_DES_TB_CONTROL_REG, timer_ctrl_reg.raw);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_timer_counter(struct ipc_pcie_ras_des *this,
	u32 *p_counter)
{
	if (unlikely(!this || !p_counter)) {
		ipc_err("Invalid argument");
		return -1;
	}

	ipc_pcie_config_read32(this->pcie,
			this->pcie_vsec.base_addr +
			INTEL_RAS_DES_TB_STATUS_REG, p_counter);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_ras_des_timer_status(struct ipc_pcie_ras_des *this,
	u32 *p_status)
{
	union ipc_pcie_timer_control timer_ctrl_reg;

	if (unlikely(!this || !p_status)) {
		ipc_err("Invalid argument");
		return -1;
	}

	ipc_pcie_config_read32(this->pcie,
			this->pcie_vsec.base_addr +
			INTEL_RAS_DES_TB_CONTROL_REG, &timer_ctrl_reg.raw);

	*p_status = timer_ctrl_reg.control.running;

	return 0;
}


/* Refer to header file for function description
 */
void ipc_pcie_ras_des_save_cap(struct ipc_pcie_ras_des *this)
{
	int i;
	u32 *p_data;

	/* If RAS DES is supported then save the Vendor Specific Extended
	 * Capability. Otherwise nothing to do.
	 */
	if (!this || this->pcie_vsec.vsec_id != INTEL_RAS_DES_VSEC_ID
		|| !this->pcie_vsec.p_save_cap)
		return;

	p_data = this->pcie_vsec.p_save_cap;

	for (i = 0; i < this->pcie_vsec.vsec_len; i += 4) {
		ipc_pcie_config_read32(this->pcie,
					this->pcie_vsec.base_addr + i, p_data);
					p_data++;
	}
}


/* Refer to header file for function description
 */
void ipc_pcie_ras_des_restore_cap(struct ipc_pcie_ras_des *this)
{
	int i;
	u32 *p_data;

	/* If RAS DES is supported then restore the Vendor Specific Extended
	 * Capability. Otherwise nothing to do.
	 */
	if (!this || this->pcie_vsec.vsec_id != INTEL_RAS_DES_VSEC_ID
		|| !this->pcie_vsec.p_save_cap)
		return;

	p_data = this->pcie_vsec.p_save_cap;

	for (i = 0; i < this->pcie_vsec.vsec_len; i += 4) {
		ipc_pcie_config_write32(this->pcie,
					this->pcie_vsec.base_addr + i, *p_data);
					p_data++;
	}
}

static int ipc_pcie_ras_des_ctor(struct ipc_pcie_ras_des *this,
	struct ipc_debugfs *dbgfs, struct ipc_pcie *pcie, struct ipc_dbg *dbg)
{
	if (unlikely(!this || !pcie)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	this->dbg = dbg;

	if (ipc_pcie_ras_des_find_vsec(this, pcie) == -1) {
		ipc_dbg("RAS not supported");
		return -1;
	}

	/* Init RAS DES stats */
	this->dbgfs = ipc_debugfs_ras_des_alloc(dbgfs, this, pcie, dbg);

	return 0;
}


/* Refer to header file for function description
 */
struct ipc_pcie_ras_des *ipc_pcie_ras_des_alloc(struct ipc_pcie *pcie,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_pcie_ras_des *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto alloc_fail;
	}

	if (ipc_pcie_ras_des_ctor(this, dbgfs, pcie, dbg))
		goto ctor_fail;

	return this;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}

static void ipc_pcie_ras_des_dtor(struct ipc_pcie_ras_des *this)
{
	ipc_debugfs_ras_des_dealloc(&this->dbgfs);
	ipc_util_kfree(this->pcie_vsec.p_save_cap);
	this->pcie_vsec.p_save_cap = NULL;
}


/* Refer to header file for function description
 */
void ipc_pcie_ras_des_dealloc(struct ipc_pcie_ras_des **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_pcie_ras_des_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


