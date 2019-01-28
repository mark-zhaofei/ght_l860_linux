/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_IMEM_H
#define IMC_IPC_IMEM_H

#include <linux/skbuff.h>

#include "imc_ipc_gpio_handler.h"

struct ipc_imem;
struct ipc_pcie;
struct ipc_debugfs;
struct ipc_dbg;

/* Host sleep target & state. */

/* Host sleep target is host
 */
#define IPC_HOST_SLEEP_HOST          0
/* Host sleep target is device
 */
#define IPC_HOST_SLEEP_DEVICE        1

/* <Sleep message> target host: AP enters sleep / target device: CP is
 * allowed to enter sleep and shall use the device sleep protocol
 */
#define IPC_HOST_SLEEP_ENTER_SLEEP    0
/* < Sleep_message> target host: AP exits  sleep / target device: CP is
 * NOT allowed to enter sleep
 */
#define IPC_HOST_SLEEP_EXIT_SLEEP     1
/* < Sleep_message> target host: not applicable  / target device: CP is
 * allowed to enter sleep and shall NOT use the device sleep protocol
 */
#define IPC_HOST_SLEEP_ENTER_SLEEP_NO_PROTOCOL     2

/* Define the argument for IRQ don't care.
 */
#define IMEM_IRQ_DONT_CARE	(-1)

/* Max. nr of channels.
 */
#define IPC_MEM_MAX_CHANNELS	13

/* List of the supported UL/DL pipes.
 */
enum ipc_mem_pipes {
	IPC_MEM_PIPE_0 = 0,
	IPC_MEM_PIPE_1,
	IPC_MEM_PIPE_2,
	IPC_MEM_PIPE_3,
	IPC_MEM_PIPE_4,
	IPC_MEM_PIPE_5,
	IPC_MEM_PIPE_6,
	IPC_MEM_PIPE_7,
	IPC_MEM_PIPE_8,
	IPC_MEM_PIPE_9,
	IPC_MEM_PIPE_10,
	IPC_MEM_PIPE_11,
	IPC_MEM_PIPE_12,
	IPC_MEM_PIPE_13,
	IPC_MEM_PIPE_14,
	IPC_MEM_PIPE_15,
	IPC_MEM_PIPE_16,
	IPC_MEM_PIPE_17,
	IPC_MEM_PIPE_18,
	IPC_MEM_PIPE_19,
	IPC_MEM_PIPE_20,
	IPC_MEM_PIPE_21,
	IPC_MEM_PIPE_22,
	IPC_MEM_PIPE_23,
	IPC_MEM_MAX_PIPES
};


/**
 * Time Unit
 */
enum ipc_time_unit {
	IPC_SEC = 0,
	IPC_MILLI_SEC = 1,
	IPC_MICRO_SEC = 2,
	IPC_NANO_SEC = 3,
	IPC_PICO_SEC = 4,
	IPC_FEMTO_SEC = 5,
	IPC_ATTO_SEC = 6,
};


/* External shared memory system settings.
 */
struct ipc_imem_config {
	int spurious_msi;
	unsigned int num_net_dev;
};


/**
 * Queue containing the SKBs and the sum of bytes in the list
 */
struct imem_ul_queue {
	u32 nr_of_bytes;
	struct sk_buff_head list;
};


/* return the driver version string.
 */
const char *ipc_imem_version(void);

/*
 * Install the shared memory system.
 *
 * @this: pointer to imem data-struct
 * @dev: pointer to os device
 * @pcie: pointer to core driver data-struct
 * @device_id: PCI device ID
 * @dbgfs: pointer to debugfs data-struct
 * @mmio: pointer to the mmio area
 * @instance_nr: modem instance number
 * @dbg: pointer to ipc_dbg structure
 *
 * returns zero on success
 */
int ipc_imem_mount(struct ipc_imem *this,
		struct device *dev,
		struct ipc_pcie *pcie,
		unsigned int device_id,
		struct ipc_debugfs *dbgfs,
		void *mmio,
		unsigned int instance_nr,
		struct ipc_dbg *dbg);

/*
 * The HAL shall ask the shared memory layer whether D3 is allowed.
 *
 * @this: pointer to imem data-struct
 */
int ipc_imem_pm_suspend(struct ipc_imem *this);

/*
 * The HAL shall inform the shared memory layer that the device is
 * active.
 *
 * @this: pointer to imem data-struct
 */
void ipc_imem_pm_resume(struct ipc_imem *this);

/*
 * Inform CP and free the shared memory resources.
 *
 * @this: pointer to imem data-struct
 */
void ipc_imem_cleanup(struct ipc_imem *this);

/* The user controls the execution of the D3 interworking: 0 eq. inactive,
 * otherwise active.
 */
void ipc_imem_pm_configure(int setting);

/*
 * Shift the IRQ actions to the IPC thread.
 *
 * @this: pointer to imem data-struct
 */
void ipc_imem_irq_process(struct ipc_imem *this, int irq);


/**
 * Writes the active protocol version in use to seq_file object m.
 *
 * @this: pointer to imem data-struct
 * @m : pointer to debugfs seq. file for imem stats
 *
 */
void ipc_imem_active_protocol_string(struct ipc_imem *this,
			struct seq_file *m);

/*
 * Print internal information
 *
 * @this: pointer to imem data-struct
 * @m : pointer to debugfs seq. file for imem stats
 */
void ipc_imem_stats(struct ipc_imem *this, struct seq_file *m);

/*
 * Retrieve a string representation of the (unbuffered) execution stage
 *
 * @this: instance pointer
 *
 * returns execution stage string
 */

const char *ipc_imem_get_exec_stage_string(struct ipc_imem *this);

/*
 * check if runtime power managment is enabled by imem
 *
 * @this: pointer to imem data-struct
 *
 * returns true if runtime pm is enabled
 */
bool ipc_imem_is_runtime_pm_enabled(struct ipc_imem *this);

/*
 * Frees all the memory allocated for the ipc imem
 * structure.
 *
 * @this_pp: pointer to the ipc imem data-struct
 */
void ipc_imem_dealloc(struct ipc_imem **this_pp);

/*
 * Allocates memory for the ipc imem structure.
 *
 * returns pointer to allocated structure
 * or NULL on failure.
 */
struct ipc_imem *ipc_imem_alloc(void);

/**
 * PM send device sleep message
 *
 * @this: pointer to imem data-struct
 * @state: sleep state want to enter to
 * @atomic_ctx: true if atomic context else false
 *
 * returns 0 on success negative value on failure
 */
int imem_msg_send_device_sleep(struct ipc_imem *this, u32 state,
		bool atomic_ctx);

/**
 * Get the device sleep state value.
 *
 * @this: pointer to imem instance
 *
 * returns device sleep state
 */
int imem_get_device_sleep_state(struct ipc_imem *this);

/**
 * Dequeue the head element from the the ul list
 *
 * @ul_list: list of type imem_ul_queue
 *
 * returns poniter to sk_buff if list is not empty, NULL otherwise.
 */
struct sk_buff *imem_ul_list_dequeue(struct imem_ul_queue *ul_list);

/*
 * Enforce legacy protocol
 */
bool imem_force_legacy_protocol(void);

void ipc_imem_gpio_notification(struct ipc_imem *this,
				enum ipc_mdm_ctrl_gpio_signal signal);

#endif				/* IMC_IPC_IMEM_H */
