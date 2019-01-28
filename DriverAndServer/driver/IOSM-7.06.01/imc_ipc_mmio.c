/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/delay.h>

#include "imc_ipc_mmio.h"
#include "imc_ipc_util.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_debugfs.h"

/*
 * Definition of MMIO offsets
 * note that MMIO_CI offsets are relative to end of chip info structure
 */

/* MMIO chip info size in bytes */
#define MMIO_CHIP_INFO_SIZE		60

/* MMIO V1 chip info size in bytes */
#define MMIO_V1_CHIP_INFO_SIZE		92

/* CP execution stage */
#define MMIO_OFFSET_EXECUTION_STAGE	0x00

/* Boot ROM Chip Info struct */
#define MMIO_OFFSET_CHIP_INFO		0x04

/* PSI Address offset */
#define MMIO_OFFSET_PSI_ADDRESS		0x54
#define MMIO_V1_OFFSET_PSI_ADDRESS	0x80

/* PSI Size offset */
#define MMIO_OFFSET_PSI_SIZE		0x5C
#define MMIO_V1_OFFSET_PSI_SIZE		0x88

/* IPC Status offset */
#define MMIO_OFFSET_IPC_STATUS		0x60
#define MMIO_V1_OFFSET_IPC_STATUS	0x8C

/* Context Info offset */
#define MMIO_OFFSET_CONTEXT_INFO	0x64
#define MMIO_V1_OFFSET_CONTEXT_INFO	0x90

/* Base Address offset */
#define MMIO_OFFSET_BASE_ADDR		0x6C
#define MMIO_V1_OFFSET_BASE_ADDR	0x98

/* End Address offset */
#define MMIO_OFFSET_END_ADDR		0x74
#define MMIO_V1_OFFSET_END_ADDR		0xA0

/* New with V1 */
/* MMIO Version offset */
#define MMIO_OFFSET_VERSION		0xA8

/* MMIO Capability offset */
#define MMIO_CAPABILITY_OFFSET		0xAC

/* CP driver SW version */
#define MMIO_OFFSET_CP_VERSION		0xF0

/* CP driver capabilities */
#define MMIO_OFFSET_CP_CAPABILITIES	0xF4

/* Vendor execution stage */
#define MMIO_OFFSET_VENDOR_EXEC_STAGE	0xF8

/* CP scratchpad area end */
#define MMIO_OFFSET_CP_END		0xFF

/* Timeout in 20 msec to wait for the modem boot code to write a valid
 * execution stage into mmio area
 */
#define IPC_MMIO_EXEC_STAGE_TIMEOUT 50

/**
 * IOSM CP capabilities union
 * capabilities are advertised by modem, MMIO structure should
 * include this union and read the modem capabilities while entering run
 * stage and set the appropriate support
 */
union ipc_cp_cap {
	u32 all;
	struct {
		u32 dev_slp_no_prot:1;  /* Device sleep no protocol support */
		u32 reserved_1:7;      /* Reserved for future use, default 0 */
		u32 dl_aggr:1;        /* Aggregation in DL direction support */
		u32 ul_aggr:1;        /* Aggregation in UL direction support */
		u32 ul_flow_credit:1; /* UL flow credits supported */
		u32 mcr_support:1;    /* Usage of MCR supported */
		u32 reserved_2:20;    /* reserved for future use, default 0 */
	} cap;
};

struct mmio_offset {
	int exec_stage;
	int chip_info;
	int rom_exit_code;
	int debug_info;
	int psi_address;
	int psi_size;
	int ipc_status;
	int context_info;
	int ap_win_base;
	int ap_win_end;
	int version;
	int capability;
	int cp_version;
	int cp_capability;
	int vendor_exec_stage;
};

/* MMIO region mapped to the doorbell scratchpad.
 */
struct ipc_mmio {
	/* base address of MMIO region */
	unsigned char __iomem *base;

	struct mmio_offset offset;

	/* physical base address of context info structure */
	u64 context_info_addr;

	/* version of chip info structure */
	unsigned int chip_info_version;

	/* size of chip info structure */
	unsigned int chip_info_size;

	/* Start address for CP address check */
	unsigned long kernel_start;

	/* End address for CP address check (0=no address check) */
	unsigned long kernel_end;

	/* End of the MMIO scratchpad area */
	unsigned int mmio_end;

	/* struct ipc_debugfs_mmio */
	struct ipc_debugfs_mmio *mmio_dbgfs;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	/* True when new exec stage values are detected, false for legacy */
	bool is_v2_exec_stage;
};


/* check if exec stage has one of the valid values */
static bool ipc_mmio_is_valid_exec_stage(enum ipc_mem_exec_stage stage)
{
	switch (stage) {
	case IPC_MEM_EXEC_STAGE_BOOT:
	case IPC_MEM_EXEC_STAGE_PSI:
	case IPC_MEM_EXEC_STAGE_EBL:
	case IPC_MEM_EXEC_STAGE_RUN:
	case IPC_MEM_EXEC_STAGE_CRASH:
	case IPC_MEM_EXEC_STAGE_CD_READY:
		return true;
	default:
		return false;
	}
}

/**
 * IPC mmio constructor
 *
 * @this: pointer to struct ipc_mmio
 * @mmio: mapped AP base address of the MMIO area.
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns true on success else false
 */
static int ipc_mmio_ctor(struct ipc_mmio *this,
			void __iomem *mmio, struct ipc_debugfs *dbgfs,
			struct ipc_dbg *dbg)
{
	int retries = IPC_MMIO_EXEC_STAGE_TIMEOUT;
	enum ipc_mem_exec_stage stage;

	if (unlikely(!mmio)) {
		ipc_err("Invalid args");
		return -1;
	}

	this->dbg = dbg;

	this->is_v2_exec_stage = false;

	ipc_dbg("mmio=%p", mmio);

	this->base = mmio;

	this->offset.exec_stage = MMIO_OFFSET_EXECUTION_STAGE;
	this->offset.vendor_exec_stage = MMIO_OFFSET_VENDOR_EXEC_STAGE;
	/* Check for a valid execution stage to make sure that the boot code
	 * has correctly initialized the MMIO area.
	 */
	do {
		stage = ipc_mmio_get_exec_stage(this);
		if (ipc_mmio_is_valid_exec_stage(stage))
			break;

		msleep(20);
	} while (retries-- > 0);

	if (unlikely(!ipc_mmio_is_valid_exec_stage(stage))) {
		ipc_err("invalid exec stage %X", stage);
		return -1;
	}

	this->offset.chip_info = MMIO_OFFSET_CHIP_INFO;

	/* read chip info size and version from chip info structure */
	this->chip_info_version = ioread8(this->base + this->offset.chip_info);

	/* Increment of 2 is needed as the size value in the chip info
	 * excludes the version and size field, which are always present
	 */
	this->chip_info_size = ioread8(this->base
				+ this->offset.chip_info + 1) + 2;

	if (unlikely(this->chip_info_size != MMIO_CHIP_INFO_SIZE
	&& this->chip_info_size != MMIO_V1_CHIP_INFO_SIZE)) {
		ipc_err("Unexpected Chip Info Size: %d",
			this->chip_info_size);
		return -1;
	}

	/* ToDo: ROM exit code & debug info offsets are still calculated
	 * because VP environment has MMIO version number as 0 but increased'
	 * 'chip_info size. When VP support is no longer needed, we can hard
	 * code the offsets depending on version number
	 */
	this->offset.rom_exit_code = this->offset.chip_info
					+ this->chip_info_size;

	/* Exit code is 4 bytes long and debug info is next to exit code */
	this->offset.debug_info = this->offset.rom_exit_code + 4;

	this->offset.version = MMIO_OFFSET_VERSION;

	ipc_dbg("Chip info rev 0x%02x, size %02d",
		this->chip_info_version, this->chip_info_size);

	if (this->chip_info_size == MMIO_CHIP_INFO_SIZE) {
		ipc_dbg("Legacy MMIO layout");
		this->offset.psi_address = MMIO_OFFSET_PSI_ADDRESS;
		this->offset.psi_size = MMIO_OFFSET_PSI_SIZE;
		this->offset.ipc_status = MMIO_OFFSET_IPC_STATUS;
		this->offset.context_info = MMIO_OFFSET_CONTEXT_INFO;
		this->offset.ap_win_base = MMIO_OFFSET_BASE_ADDR;
		this->offset.ap_win_end = MMIO_OFFSET_END_ADDR;
	} else {
		ipc_dbg("MMIO version 1 layout");
		this->offset.psi_address = MMIO_V1_OFFSET_PSI_ADDRESS;
		this->offset.psi_size = MMIO_V1_OFFSET_PSI_SIZE;
		this->offset.ipc_status = MMIO_V1_OFFSET_IPC_STATUS;
		this->offset.context_info = MMIO_V1_OFFSET_CONTEXT_INFO;
		this->offset.ap_win_base = MMIO_V1_OFFSET_BASE_ADDR;
		this->offset.ap_win_end = MMIO_V1_OFFSET_END_ADDR;
	}

	this->offset.capability = MMIO_CAPABILITY_OFFSET;
	this->offset.cp_version = MMIO_OFFSET_CP_VERSION;
	this->offset.cp_capability = MMIO_OFFSET_CP_CAPABILITIES;

	/* store the end of MMIO scratchpad region */
	this->mmio_end = MMIO_OFFSET_CP_END;

	this->mmio_dbgfs = ipc_debugfs_mmio_alloc(this, dbgfs, this->dbg);

	this->kernel_start = 0;
	this->kernel_end = 0;

	return 0;
}

/**
 * IPC mmio destructor
 *
 * @this: pointer to struct ipc_mmio
 */
static void ipc_mmio_dtor(struct ipc_mmio *this)
{
	ipc_debugfs_mmio_dealloc(&this->mmio_dbgfs);
}

/* Refer to header file for function description
 */
struct ipc_mmio *ipc_mmio_alloc(void __iomem *mmio_addr,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_mmio *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto alloc_fail;
	}

	if (ipc_mmio_ctor(this, mmio_addr, dbgfs, dbg)) {
		ipc_err("params ctor failed");
		goto ctor_fail;
	}

	return this;

ctor_fail:
	ipc_util_kfree(this);
alloc_fail:
	return NULL;
}

/* Refer to header file for function description
 */
void ipc_mmio_dealloc(struct ipc_mmio **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_mmio_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

/* Refer to header file for function description
 */
int ipc_mmio_get_version(struct ipc_mmio *this)
{
	return this ? readl(this->base + this->offset.version) : -1;
}

/* Refer to header file for function description
 */
int ipc_mmio_get_capability(struct ipc_mmio *this)
{
	return this ? readl(this->base + this->offset.capability) : -1;
}

/* Refer to header file for function description
 */
enum ipc_mem_exec_stage ipc_mmio_get_exec_stage(struct ipc_mmio *this)
{
	u32 stage;

	if (unlikely(!this))
		return IPC_MEM_EXEC_STAGE_INVALID;

	stage = readl(this->base + this->offset.exec_stage);

	/* Map converged exec stage values to legacy */
	switch (stage) {

	case IPC_MEM_EXEC_STAGE_V2_ROM:
		this->is_v2_exec_stage = true;
		return IPC_MEM_EXEC_STAGE_BOOT;

	case IPC_MEM_EXEC_STAGE_V2_OS:
		this->is_v2_exec_stage = true;
		return IPC_MEM_EXEC_STAGE_RUN;

	case IPC_MEM_EXEC_STAGE_V2_SECONDARY_BOOT:
	case IPC_MEM_EXEC_STAGE_V2_ABORT:
		this->is_v2_exec_stage = true;
		return (enum ipc_mem_exec_stage) readl(this->base +
				this->offset.vendor_exec_stage);

	default:
		this->is_v2_exec_stage = false;
		return (enum ipc_mem_exec_stage) stage;
	}
}

/* Refer to header file for function description
 */
bool ipc_mmio_is_v2_exec_stage(struct ipc_mmio *this)
{
	return this ? this->is_v2_exec_stage : false;
}

/* Refer to header file for function description
 */
size_t ipc_mmio_get_chip_info_size(struct ipc_mmio *this)
{
	return this ? this->chip_info_size : 0;
}

/* Refer to header file for function description
 */
void ipc_mmio_copy_chip_info(struct ipc_mmio *this, void *dest, size_t size)
{
	if (this && dest)
		memcpy_fromio(dest, this->base + this->offset.chip_info, size);
}

/* Refer to header file for function description
 */
enum ipc_mem_device_ipc_state ipc_mmio_get_ipc_state(struct ipc_mmio *this)
{
	u32 state;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return IPC_MEM_DEVICE_IPC_INVALID;
	}

	state = readl(this->base + this->offset.ipc_status);

	ipc_dbg("ipc_status=%d", state);

	return (enum ipc_mem_device_ipc_state) state;
}

/* Refer to header file for function description
 */
enum rom_exit_code ipc_mmio_get_rom_exit_code(struct ipc_mmio *this)
{
	u32 code;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return IMEM_ROM_EXIT_FAIL;
	}

	code = readl(this->base + this->offset.rom_exit_code);

	ipc_dbg("rom_exit_code=%d", code);

	return (enum rom_exit_code)code;
}

/**
 * IPC mmio translate iowrite64 to iowrite32 function for compatibility
 * of 32 bit system.
 *
 * @value: the 64 bit value to be wrote
 * @addr: the address to write to
 */
static void ipc_mmio_iowrite64(u64 value, void __iomem *addr)
{
	iowrite32((u32)value, addr);
	iowrite32((u32)(value >> 32), addr + 4);
}

/* Refer to header file for function description
 */
void ipc_mmio_init(struct ipc_mmio *this)
{
	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return;
	}

	ipc_dbg("context_info=%llx", this->context_info_addr);

	/*
	 * AP memory window (full window is open and active
	 * so that modem checks each AP address)
	 * 0 means don't check on modem side.
	 */
	ipc_mmio_iowrite64(this->kernel_start,
			this->base + this->offset.ap_win_base);
	ipc_mmio_iowrite64(this->kernel_end,
			this->base + this->offset.ap_win_end);

	ipc_mmio_iowrite64(this->context_info_addr,
			this->base + this->offset.context_info);
}

/* Refer to header file for function description
 */
void ipc_mmio_set_psi_addr_and_size(struct ipc_mmio *this, u64 addr, u32 size)
{
	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return;
	}

	ipc_dbg("psi_size=%x", size);

	ipc_mmio_iowrite64(addr, this->base + this->offset.psi_address);
	writel(size, this->base + this->offset.psi_size);
}

/* Refer to header file for function description
 */
void ipc_mmio_set_contex_info_addr(struct ipc_mmio *this, u64 addr)
{
	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return;
	}

	/* store context_info address. This will be stored in the mmio area
	 * during IPC_MEM_DEVICE_IPC_INIT state via ipc_mmio_init()
	 */
	this->context_info_addr = addr;

}

/* Refer to header file for function description
 */
int ipc_mmio_get_cp_version(struct ipc_mmio *this)
{
	return this ? readl(this->base + this->offset.cp_version) : -1;
}

/**
 * function to get the CP version from mmio
 *
 * @this: pointer to struct ipc_mmio
 *
 * returns the value of CP version
 */
static u32 ipc_mmio_read_cp_cap(struct ipc_mmio *this)
{
	return readl(this->base + this->offset.cp_capability);
}

/* Refer to header file for function description
 */
bool ipc_mmio_cp_has_mux_lite(struct ipc_mmio *this)
{
	unsigned int v;
	union ipc_cp_cap c;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return false;
	}

	v = ipc_mmio_get_cp_version(this);
	c.all = ipc_mmio_read_cp_cap(this);

	return v >= IOSM_CP_VERSION && !c.cap.dl_aggr && !c.cap.ul_aggr;
}

/* Refer to header file for function description
 */
bool ipc_mmio_cp_has_ul_flow_credit(struct ipc_mmio *this)
{
	unsigned int v;
	union ipc_cp_cap c;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return false;
	}

	v = ipc_mmio_get_cp_version(this);
	c.all = ipc_mmio_read_cp_cap(this);

	return v >= IOSM_CP_VERSION && c.cap.ul_flow_credit;
}

/*
 * Refer to header file for description
 */
bool ipc_mmio_cp_has_sleep_no_prot(struct ipc_mmio *this)
{
	union ipc_cp_cap c;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return false;
	}

	c.all = ipc_mmio_read_cp_cap(this);

	return c.cap.dev_slp_no_prot == 1;
}


/*
 * Refer to header file for description
 */
bool ipc_mmio_cp_has_mcr_support(struct ipc_mmio *this)
{
	union ipc_cp_cap c;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return false;
	}

	c.all = ipc_mmio_read_cp_cap(this);

	return c.cap.mcr_support == 1;
}


/*
 * Refer to header file for description
 */
u32 ipc_mmio_scratchpad_read(struct ipc_mmio *this, u32 offset, u64 *addr)
{
	if (unlikely(!this || !addr))
		return -1;

	/* Return the address of the scratchpad */
	*addr = (u64)this->base;

	/* Return the value in the scratchpad */
	return ioread32(this->base + offset);
}

/*
 * Refer to header file for description
 */
int ipc_mmio_scratchpad_write(struct ipc_mmio *this, u32 offset, u32 value)
{
	if (unlikely(!this))
		return -1;

	/* Verify the offset is valid or not */
	if (offset > this->mmio_end) {
		ipc_err("Offset must be between 0 & 0x%08x", this->mmio_end);
		ipc_err("echo <offset> <value> > scratchpad");
		return -EINVAL;
	}

	/* Write the value to the scratchpad */
	iowrite32(value, this->base + offset);

	ipc_dbg("Writing to address %llx offset %08X value %08X",
		(u64)this->base + offset, offset, value);

	return 0;
}

