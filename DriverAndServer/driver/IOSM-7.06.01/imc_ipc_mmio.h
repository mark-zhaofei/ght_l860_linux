/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_MMIO_H
#define IMC_IPC_MMIO_H

struct ipc_mmio;
struct ipc_pcie;
struct ipc_debugfs;
struct ipc_dbg;


/* Minimal IOSM CP VERSION which has valid CP_CAPABILITIES field */
#define IOSM_CP_VERSION			0x0100UL

/* IBIS CP version with changed pipe configuration. */
#define IOSM_IBIS_CP_VERSION1		0x0101UL

/* 7660 CP version with changed pipe configuration.1.0 */
#define IOSM_7660_CP_VERSION1		0x0120UL

/* 7660 CP version with changed pipe configuration.2.0  */
#define IOSM_7660_CP_VERSION2		0x0121UL

/**
 * Possible states of the IPC finite state machine.
 */
enum ipc_mem_device_ipc_state {
	IPC_MEM_DEVICE_IPC_UNINIT,
	IPC_MEM_DEVICE_IPC_INIT,
	IPC_MEM_DEVICE_IPC_RUNNING,
	IPC_MEM_DEVICE_IPC_RECOVERY,
	IPC_MEM_DEVICE_IPC_ERROR,
	IPC_MEM_DEVICE_IPC_DONT_CARE,
	IPC_MEM_DEVICE_IPC_INVALID = -1
};

/**
 * Boot ROM exit status.
 */
enum rom_exit_code {
	IMEM_ROM_EXIT_OPEN_EXT = 0x01,
	IMEM_ROM_EXIT_OPEN_MEM = 0x02,
	IMEM_ROM_EXIT_CERT_EXT = 0x10,
	IMEM_ROM_EXIT_CERT_MEM = 0x20,
	IMEM_ROM_EXIT_FAIL = 0xFF
};

/**
 * @enum ipc_mem_exec_stage
 * @brief boot stage
 */
enum ipc_mem_exec_stage {
	IPC_MEM_EXEC_STAGE_V2_ROM = 0,
	IPC_MEM_EXEC_STAGE_V2_SECONDARY_BOOT = 1,
	IPC_MEM_EXEC_STAGE_V2_OS = 2,
	IPC_MEM_EXEC_STAGE_V2_ABORT = 3,

	/* Vendor specific boot stages */
	IPC_MEM_EXEC_STAGE_BOOT = 0xFEEDB007,
	IPC_MEM_EXEC_STAGE_PSI = 0xFEEDBEEF,
	IPC_MEM_EXEC_STAGE_EBL = 0xFEEDCAFE,
	IPC_MEM_EXEC_STAGE_RUN = 0x600DF00D,
	IPC_MEM_EXEC_STAGE_CRASH = 0x8BADF00D,
	IPC_MEM_EXEC_STAGE_CD_READY = 0xBADC0DED,

	IPC_MEM_EXEC_STAGE_INVALID = 0xFFFFFFFF
};

/**
 * Allocate mmio instance data
 *
 * @mmio_addr: mapped AP base address of the MMIO area.
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns address of mmio instance data
 */
struct ipc_mmio *ipc_mmio_alloc(void __iomem *mmio_addr,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg);

/**
 * Free allocated mmio instance date, invalidating the pointer.
 *
 * @this_pp: pointer to pointer to mmio instance
 */
void ipc_mmio_dealloc(struct ipc_mmio **this_pp);


/**
 * Set start address and size of the primary system image (PSI) for the
 * boot rom dowload app.
 *
 * @this: pointer to mmio instance
 */
void ipc_mmio_set_psi_addr_and_size(struct ipc_mmio *this, u64 addr, u32 size);


/*
 * Stores the Context Info Adddress in MMIO instance to share it with CP during
 * mmio_init.
 *
 * @this: pointer to mmio instance
 * @addr: 64-bit address of AP context information.
 */
void ipc_mmio_set_contex_info_addr(struct ipc_mmio *this, u64 addr);

/*
 * Write context info and AP memory range addresses.
 * This needs to be called when CP is in IPC_MEM_DEVICE_IPC_INIT state
 *
 * @this: pointer to mmio instance
 *
 * returns cp version else -1
 */
int ipc_mmio_get_cp_version(struct ipc_mmio *this);



/**
 * Get the CP IPC version
 *
 * @this: pointer to mmio instance
 *
 * returns version number on success and -1 on failure.
 */
int ipc_mmio_get_cp_version(struct ipc_mmio *this);


/**
 * Get the version of the MMIO
 *
 * @this: pointer to mmio instance
 *
 * returns version number on success and -1 on failure.
 */
int ipc_mmio_get_version(struct ipc_mmio *this);


/**
 * Get the Capability of the MMIO
 *
 * @this: pointer to mmio instance
 *
 * returns capability value on success and -1 on failure.
 */
int ipc_mmio_get_capability(struct ipc_mmio *this);


/**
 * Get exit code from CP boot rom download app
 *
 * @this: pointer to mmio instance
 *
 * returns exit code from CP boot rom download APP
 */
enum rom_exit_code ipc_mmio_get_rom_exit_code(struct ipc_mmio *this);


/**
 * Query CP execution stage
 *
 * @this: pointer to mmio instance
 *
 * returns CP execution stage
 */
enum ipc_mem_exec_stage ipc_mmio_get_exec_stage(struct ipc_mmio *this);


/**
 * Query CP IPC state
 *
 * @this: pointer to mmio instance
 *
 * returns CP IPC state
 */
enum ipc_mem_device_ipc_state ipc_mmio_get_ipc_state(struct ipc_mmio *this);


/**
 * Query size of CP chip info structure
 *
 * @this: pointer to mmio instance
 *
 * returns size of CP chip info structure
 */
size_t ipc_mmio_get_chip_info_size(struct ipc_mmio *this);


/**
 * Copy size bytes of CP chip info structure into caller provided buffer
 *
 * @this: pointer to mmio instance
 * @dest: pointer to caller provided buffer, at least size bytes large
 * @size: number of bytes to copy
 */
void ipc_mmio_copy_chip_info(struct ipc_mmio *this, void *dest, size_t size);


/**
 * Query CP use of mux lite multiplex protocol
 *
 * @this: pointer to mmio instance
 *
 * returns true when CP advertises mux lite multiplex protocol
 */

bool ipc_mmio_cp_has_mux_lite(struct ipc_mmio *this);


/**
 * Query CP uplink credit based flow control capability
 *
 * @this: pointer to mmio instance
 *
 * returns true when CP advertises uplink credit flow control capability
 */
bool ipc_mmio_cp_has_ul_flow_credit(struct ipc_mmio *this);


/**
 * Query CP sleep no protocol capability
 *
 * @this: pointer to mmio instance
 *
 * returns true when CP have sleep no protocol capability
 */
bool ipc_mmio_cp_has_sleep_no_prot(struct ipc_mmio *this);


/**
 * Query CP Message Completion Ring(MCR) support capability
 *
 * @this: pointer to mmio instance
 *
 * returns true when CP supports MCR false otherwise.
 */
bool ipc_mmio_cp_has_mcr_support(struct ipc_mmio *this);


/**
 * To read the value of the scratchpad at certain offset
 *
 * @mmio: pointer to struct ipc_mmio
 * @offset: offset in the scratchpad
 * @addr: return the address of scratchpad
 *
 * returns scratchpad value at specified offset
 */
u32 ipc_mmio_scratchpad_read(struct ipc_mmio *this, u32 offset, u64 *addr);


/**
 * To write value into the scratchpad at certain offset
 *
 * @mmio: pointer to struct ipc_mmio
 * @offset: offset in the scratchpad
 * @value: value need set to the scratchpad
 *
 * returns 0 if write was successfuly else negative error code
 */
int ipc_mmio_scratchpad_write(struct ipc_mmio *this, u32 offset, u32 value);


/*
 * Write context info and AP memory range addresses.
 * This needs to be called when CP is in IPC_MEM_DEVICE_IPC_INIT state
 *
 * @this: pointer to mmio instance
 */
void ipc_mmio_init(struct ipc_mmio *this);

/*
 * Check if converged exec stage values are used.
 *
 * @this: pointer to struct ipc_mmio
 *
 * @returns true when the device is using execution stages according to the
 * converged protocol specification
 */
bool ipc_mmio_is_v2_exec_stage(struct ipc_mmio *this);

#endif /* !defined(IMC_IPC_MMIO_H) */
