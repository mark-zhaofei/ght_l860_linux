/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/types.h>

#include "imc_ipc_parc.h"
#include "imc_ipc_util.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_dbg.h"

#include "imc_ipc_debugfs.h"

/* Structure for PARC handler
 */
struct ipc_pcie_parc {
	u32 max_bm_win;	/* Holds the max. supported BM windows */
	u32 max_sl_win;	/* Holds the max. supported SL windows */
	u32 max_dw_win;	/* Holds the max. supported DW windows */

	/* Holds vsec parameters */
	struct ipc_pcie_vsec pcie_vsec;

	/* IPC PCIe */
	struct ipc_pcie *pcie;

	/* Debugfs */
	struct ipc_debugfs_parc *dbgfs;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};

/* Intel PARC supports the following,
 * Base/Mask method: 2 Windows
 * Start/Limit method: 4 Windows
 * Dword method: 2.
 */


/* PARC Enhanced Capability Header
 */
#define INTEL_PARC_ECH			0x000

#define INTEL_PARC_VSH			0x004

#define INTEL_PARC_STATUS_REG		0x008

#define INTEL_PARC_CONTROL_REG		0x00C

#define INTEL_PARC_1ST_ERRLOG_L		0x010
#define INTEL_PARC_1ST_ERRLOG_H		0x014

#define INTEL_PARC_INT_VIOLATOR_ID	0x018
#define INTEL_PARC_INT_VIOLATOR_LOG	0x01C

/* Macro for extracting the Base_L register address for given window.
 */
#define INTEL_PARC_BASE_L(idx) (0x020 + (0x10 * (idx)))

/* Macro for extracting the Base_H register address for given window.
 */
#define INTEL_PARC_BASE_H(idx) (0x024 + (0x10 * (idx)))

/* Macro for extracting the Mask_L register address for given window.
 */
#define INTEL_PARC_MASK_L(idx) (0x028 + (0x10 * (idx)))

/* Macro for extracting the Mask_H register address for given window.
 */
#define INTEL_PARC_MASK_H(idx) (0x02C + (0x10 * (idx)))


/* Macro for extracting the DW_M register address for given window.
 */
#define INTEL_PARC_DW_M(idx) (0x040 + (0x10 * (idx)))

/* Macro for extracting the DW_H register address for given window.
 */
#define INTEL_PARC_DW_H(idx) (0x044 + (0x10 * (idx)))

/* Macro for extracting the DW_STAT register address for given window.
 */
#define INTEL_PARC_DW_STAT(idx) (0x048 + (0x10 * (idx)))

/* Macro for extracting the DW_L register address for given window.
 */
#define INTEL_PARC_DW_L(idx) (0x04C + (0x10 * (idx)))


/* Macro for extracting the START_L register address for given window.
 */
#define INTEL_PARC_START_L(idx) (0x060 + (0x10 * (idx)))

/* Macro for extracting the START_H register address for given window.
 */
#define INTEL_PARC_START_H(idx) (0x064 + (0x10 * (idx)))

/* Macro for extracting the LIMIT_L register address for given window.
 */
#define INTEL_PARC_LIMIT_L(idx) (0x068 + (0x10 * (idx)))

/* Macro for extracting the LIMIT_H register address for given window.
 */
#define INTEL_PARC_LIMIT_H(idx) (0x06C + (0x10 * (idx)))


#define INTEL_PARC_MISC_CTRL		0x14C


/* Lock window bit position
 */
#define PARC_LW_BIT		1


/* Word size in PARC
 */
#define PARC_WORD_SIZE		32


/* Macro for Window range Violation occured bit position
 */
#define PARC_WV_BIT		0


/* Macro for Multiple Window range Violation occured bit position
 */
#define PARC_MWV_BIT		1


/* Macro for Address Low bits 31:12 of BM, DW and SL scheme
 */
#define PARC_ADDR_BITS_31_12	0xFFFFF000

/* Macro for Address Low bits 31:2 of BM, DW and SL scheme
 */
#define PARC_ADDR_BITS_31_2	0xFFFFFFFC


/* PARC Window Type Control bit position
 */
#define PARC_WT_BIT		2


/* Returns non-zero value if the bit at the given position is set.
 */
#define IS_BIT_SET(val, pos) ((val) & (0x1 << (pos)))


/* Sets the bit at given position.
 */
#define SET_BIT(val, pos) ((val) | (0x1 << (pos)))


/* Clears the bit at given position.
 */
#define CLEAR_BIT(val, pos) ((val) & (~(0x1 << (pos))))


/* Window type enums.
 */
enum parc_window_type {
	PARC_WINDOW_INCLUSIVE = 0,
	PARC_WINDOW_EXCLUSIVE
};


/**
 * Function for populating Window range Violation(WV) and Multiple Window
 * Violations(MWV) bits.
 *
 * @this: pointer to PARC handler.
 * @win_type: Window type inclusive or exclusive
 * @p_data: pointer to get the populated bits.
 *
 * returns none
 */
static void ipc_pcie_parc_config_window_violations(
	struct ipc_pcie_parc *this,
	enum parc_window_type win_type, u32 *p_data)
{
	if (!p_data)
		return;

	/* Clear/Set Bit-0 depending on window type
	 */
	switch (win_type) {
	case PARC_WINDOW_INCLUSIVE:
		*p_data = 0;
		break;

	case PARC_WINDOW_EXCLUSIVE:
		/* Bit-0 WV(Window Violation) and Bit-1 MWV(Multiple Window
		 * Violation) needs to be set only for Exclusive Window type.
		 */
		*p_data = (0x1 << PARC_WV_BIT) | (0x1 << PARC_MWV_BIT);
		break;

	default:
		ipc_err("Unknown window type: %d", win_type);
		return;
	}
}


/**
 * Function for populating Window Type Control bit for given window type.
 *
 * @this: pointer to PARC handler.
 * @win_type: Window type inclusive or exclusive
 * @p_data: pointer to get the populated bits.
 *
 * returns none
 */
static void ipc_pcie_parc_config_window_type_control(
	struct ipc_pcie_parc *this,
	enum parc_window_type win_type, u32 *p_data)
{
	if (!p_data)
		return;

	/* Set/clear Bit-2: Window Type depending on the requirement.
	 */
	switch (win_type) {
	case PARC_WINDOW_INCLUSIVE:
		*p_data = CLEAR_BIT(*p_data, PARC_WT_BIT);
		break;

	case PARC_WINDOW_EXCLUSIVE:
		*p_data = SET_BIT(*p_data, PARC_WT_BIT);
		break;

	default:
		ipc_err("Unknown window type: %d", win_type);
		return;
	}
}


/**
 * Function checking whether the Global Lock is enabled or not in Control
 * register.
 *
 * @this: pointer to PARC handler.
 *
 * returns 1: Global Lock enabled, 0 otherwise
 */
static int ipc_pcie_parc_is_global_lock_enabled(
		struct ipc_pcie_parc *this)
{
	union ipc_pcie_parc_control ctrl_reg;

	ipc_pcie_config_read32(this->pcie,
			this->pcie_vsec.base_addr + INTEL_PARC_CONTROL_REG,
			&ctrl_reg.raw);

	return ctrl_reg.parc_control.gl;
}


/* These functions ipc_pcie_parc_bm_set_base_n_mask() and
 * ipc_pcie_parc_dw_set_addr() are intentionally made inactive
 * to avoid compilation warning about unusued functions.
 * In future if these methods are needed then just remove the
 * #if 0 statement in code.
 */
#if 0

/**
 * Function for configuring Base and Mask values and type for a given window.
 *
 * @this: pointer to PARC handler.
 * @window_nr: Window number to configure.
 * @base: 64-bit Base register value to configure.
 * @mask: 64-bit Mask register value to configure.
 * @win_type: Window type Inclusive/Exclusive.
 *
 * returns 0 on sucess, -1 on failure
 */
static int ipc_pcie_parc_bm_set_base_n_mask(
		struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_bm window_nr, u64 base,
		u64 mask, enum parc_window_type win_type)
{
	u32 offset_base_l = 0;
	u32 offset_base_h = 0;
	u32 offset_mask_l = 0;
	u32 offset_mask_h = 0;
	u32 addr_h;
	u32 addr_l;
	u32 mask_h;
	u32 mask_l;


	if (unlikely(!this || window_nr >= this->max_bm_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* If the Global Lock bit is set then can't change the windows.
	 */
	if (ipc_pcie_parc_is_global_lock_enabled(this)) {
		ipc_err("Can't change the window ranges if GL bit is set");
		return -1;
	}

	offset_base_l = this->base_addr + INTEL_PARC_BASE_L(window_nr);
	offset_base_h = this->base_addr + INTEL_PARC_BASE_H(window_nr);

	offset_mask_l = this->base_addr + INTEL_PARC_MASK_L(window_nr);
	offset_mask_h = this->base_addr + INTEL_PARC_MASK_H(window_nr);

	/* Clear Bit-1: Lock Window for writes (have effect only if GL bit
	 * is 0)
	 */
	ipc_pcie_config_read32(this->pcie, offset_base_l, &addr_l);
	if (IS_BIT_SET(addr_l, PARC_LW_BIT)) {
		addr_l = CLEAR_BIT(addr_l, PARC_LW_BIT);
		ipc_pcie_config_write32(this->pcie, offset_base_l, addr_l);
	}

	/* Extract the bits 63:32 from base and write to Base_H register.
	 */
	addr_h = (u32)(base >> PARC_WORD_SIZE);
	(void)ipc_pcie_config_write32(this->pcie, offset_base_h, addr_h);

	/*  Extract the bits 63:32 from mask and write to Mask_H register.
	 */
	mask_h = (u32)(mask >> PARC_WORD_SIZE);
	ipc_pcie_config_write32(this->pcie, offset_mask_h, mask_h);

	/* Populates the value of MV and MWV for given window type
	 */
	ipc_pcie_parc_config_window_violations(this, win_type, &mask_l);

	/* Extract mask_low bits 31:12 from 64-bit value and write to Mask_L
	 * register.
	 */
	mask_l = (mask & PARC_ADDR_BITS_31_12) | mask_l;
	(void)ipc_pcie_config_write32(this->pcie, offset_mask_l, mask_l);

	/* Set the Bit-0: Enable Range check.
	 * Clear the Bit-1: Lock Window for writes (have effect only if GL
	 * bit is 0). This allows to reconfigure the Base/Mask registers.
	 */
	addr_l = 1;

	/* Populate the Bit-2: WT bit for given window type.
	 */
	ipc_pcie_parc_config_window_type_control(this, win_type, &addr_l);

	/* Extract Base Address Bit-31:12 from 64-bit value and write to
	 * Base_L register.
	 */
	addr_l = (u32)((base & PARC_ADDR_BITS_31_12) | addr_l);
	(void)ipc_pcie_config_write32(this->pcie, offset_base_l, addr_l);

	return 0;
}

#endif	/* #if 0 */

/**
 * Function for configuring DW values and type for a given window.
 *
 * @this: pointer to PARC handler.
 * @window_nr: Window number to configure.
 * @addr: 64-bit DW value to configure.
 * @win_type: Window type Inclusive/Exclusive.
 *
 * returns 0 on sucess, -1 on failure
 */
static int ipc_pcie_parc_dw_set_addr(
		struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_dw window_nr, u64 addr,
		enum parc_window_type win_type)
{
	u32 offset_l = 0;
	u32 offset_m = 0;
	u32 offset_h = 0;
	u32 offset_stat = 0;
	u32 addr_l;
	u32 addr_m = 0;
	u32 addr_h;
	u32 addr_stat;

	if (unlikely(!this || window_nr >= this->max_dw_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* If the Global Lock bit is set then can't change the windows.
	 */
	if (ipc_pcie_parc_is_global_lock_enabled(this)) {
		ipc_err("Can't change the window ranges if GL bit is set");
		return -1;
	}

	offset_l = this->pcie_vsec.base_addr + INTEL_PARC_DW_L(window_nr);
	offset_m = this->pcie_vsec.base_addr + INTEL_PARC_DW_M(window_nr);
	offset_h = this->pcie_vsec.base_addr + INTEL_PARC_DW_H(window_nr);
	offset_stat = this->pcie_vsec.base_addr + INTEL_PARC_DW_STAT(window_nr);

	/* Clear Bit-1: Lock Window for writes (have effect only if GL bit
	 *  is 0)
	 */
	ipc_pcie_config_read32(this->pcie, offset_m, &addr_m);
	if (IS_BIT_SET(addr_m, PARC_LW_BIT)) {
		addr_m = CLEAR_BIT(addr_m, PARC_LW_BIT);
		ipc_pcie_config_write32(this->pcie, offset_m, addr_m);
	}

	/* Extract DW Address Low Bits-31:2 from 64-bit value and write to
	 * Addr_L register.
	 */
	addr_l = (u32)(addr & PARC_ADDR_BITS_31_2);
	(void)ipc_pcie_config_write32(this->pcie, offset_l, addr_l);

	/* Extract DW Address High Bits-63:32 from 64-bit value and write to
	 * Addr_H register.
	 */
	addr_h = (u32)(addr >> PARC_WORD_SIZE);
	(void)ipc_pcie_config_write32(this->pcie, offset_h, addr_h);

	/* Configure the value of MV and MWV for given window type
	 */
	ipc_pcie_parc_config_window_violations(this, win_type, &addr_stat);
	(void)ipc_pcie_config_write32(this->pcie, offset_stat, addr_stat);

	/* Set Bit-0: Enable Range Check
	 */
	addr_m = 1;

	/* Set Bit-1: Lock Window for writes (have effect only if GL
	 * bit is 0). Setting this bit doesn't allow to reconfigure the DW
	 * address.
	 */
	addr_m = SET_BIT(addr_m, PARC_LW_BIT);

	/* Populate the Bit-2: WT bit for given window type.
	 */
	ipc_pcie_parc_config_window_type_control(this, win_type, &addr_m);

	/* Extract DW Address Bit-31:12 from 64-bit value and write to
	 * Addr_M register.
	 */
	addr_m = (u32)((addr & PARC_ADDR_BITS_31_12) | addr_m);
	(void)ipc_pcie_config_write32(this->pcie, offset_m, addr_m);

	return 0;
}


/**
 * Function for configuring Start and Limit values and type for a given window.
 *
 * @this: pointer to PARC handler.
 * @window_nr: Window number to configure.
 * @start: 64-bit start address
 * @limit: 64-bit limit address
 * @win_type: Window type Inclusive/Exclusive.
 *
 * returns 0 on sucess, -1 on failure
 */
static int parc_sl_set_start_n_limit(struct ipc_pcie_parc *this,
				enum ipc_pcie_parc_win_sl window_nr, u64 start,
				u64 limit, enum parc_window_type win_type)
{
	u32 offset_start_l;
	u32 offset_start_h;
	u32 offset_limit_l;
	u32 offset_limit_h;
	u32 addr_start_l = 0;
	u32 addr_start_h;
	u32 addr_limit_l;
	u32 addr_limit_h;

	if (unlikely(!this || window_nr >= this->max_sl_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* If the Global Lock bit is set then can't change the windows.
	 */
	if (ipc_pcie_parc_is_global_lock_enabled(this)) {
		ipc_err("Can't change the window ranges if GL bit is set");
		return -1;
	}

	offset_start_l = this->pcie_vsec.base_addr +
		INTEL_PARC_START_L(window_nr);

	offset_start_h = this->pcie_vsec.base_addr +
		INTEL_PARC_START_H(window_nr);

	offset_limit_l = this->pcie_vsec.base_addr +
		INTEL_PARC_LIMIT_L(window_nr);

	offset_limit_h = this->pcie_vsec.base_addr +
		INTEL_PARC_LIMIT_H(window_nr);

	/* Clear Bit-1: Lock Window for writes (have effect only if GL bit
	 *  is 0)
	 */
	ipc_pcie_config_read32(this->pcie, offset_start_l, &addr_start_l);
	if (IS_BIT_SET(addr_start_l, PARC_LW_BIT)) {
		addr_start_l = CLEAR_BIT(addr_start_l, PARC_LW_BIT);
		ipc_pcie_config_write32(this->pcie,
						offset_start_l, addr_start_l);
	}

	/* Extract the Bits-63:32: Start Address high from 64-bit value and
	 * write to Start_H register.
	 */
	addr_start_h = (u32)(start >> PARC_WORD_SIZE);
	ipc_pcie_config_write32(this->pcie, offset_start_h, addr_start_h);

	/* Extract the Bits-63:32: Limit High from 64-bit value and
	 * write to Limit_H register.
	 */
	addr_limit_h = (u32)(limit >> PARC_WORD_SIZE);
	ipc_pcie_config_write32(this->pcie, offset_limit_h, addr_limit_h);

	/* Populates the value of MV and MWV for given window type
	 */
	ipc_pcie_parc_config_window_violations(this, win_type, &addr_limit_l);

	/* Extract Bits-31:12: Limit Addr Low from 64-bit value and
	 * write to Limit_L register.
	 */
	addr_limit_l = (u32)((limit & PARC_ADDR_BITS_31_12) | addr_limit_l);
	(void)ipc_pcie_config_write32(this->pcie, offset_limit_l, addr_limit_l);

	/* Set Bit-0: Enable Range Check
	 * Clear the Bit-1: Lock Window for writes (have effect only if GL
	 * bit is 0). This allows to reconfigure the Start/Limit registers.
	 */
	addr_start_l = 1;

	/* Populate the WT bit for given window type.
	 */
	ipc_pcie_parc_config_window_type_control(this, win_type, &addr_start_l);

	/* Extract Bits-31:12: Start Addr Low from 64-bit value and wirte to
	 * Start_L register.
	 */
	addr_start_l = (u32)((start & PARC_ADDR_BITS_31_12) | addr_start_l);
	(void)ipc_pcie_config_write32(this->pcie, offset_start_l, addr_start_l);

	return 0;
}


/**
 * Function for finding the Vendor Specific Extended Capability with with
 * Extended Capability ID as 0x0B and Vendor Specific Capability ID as 0x24.
 *
 * @this: pointer to PARC handler.
 * @pcie: pointer to the core driver data-struct of pcie.
 *
 *             If find is successful then base_addr, vsec_id and
 *             vsec_ver will be initialized otherwise they will have
 *             0xFFFF
 *
 * returns 0 on sucess, -1 on failure
 */
static int ipc_pcie_parc_find_vsec(struct ipc_pcie_parc *this,
				struct ipc_pcie *pcie)
{
	int ret_val = -1;
	struct pcie_extended_cap vsec_cap = {0};
	union ipc_pcie_parc_status status;
	int offset = 0;

	/* Save the pcie address.
	 */
	this->pcie = pcie;

	/* Reset the value to 0xFFFF
	 */
	this->pcie_vsec.base_addr = -1;
	this->pcie_vsec.vsec_id = -1;
	this->pcie_vsec.vsec_ver = -1;

	/* Reset the max window numbers.
	 */
	this->max_bm_win = 0;
	this->max_sl_win = 0;
	this->max_dw_win = 0;

	if (ipc_pcie_find_vsec_id(this->pcie, &vsec_cap,
			&offset, INTEL_PARC_VSEC_ID)) {
		ipc_dbg("PARC is not supported");
		return ret_val;
	}

	this->pcie_vsec.base_addr = offset;
	this->pcie_vsec.vsec_id = vsec_cap.cap_id;
	this->pcie_vsec.vsec_len = vsec_cap.next_offset;
	this->pcie_vsec.vsec_ver = vsec_cap.cap_ver;

	ipc_dbg("PARC supported! Offset:0x%x, VSEC ID:0x%x, VSEC Len: %d",
		this->pcie_vsec.base_addr, this->pcie_vsec.vsec_id,
		this->pcie_vsec.vsec_len);

	/* Initialize the PARC handler with the max. supported windows
	 * of all supported schemes.
	 */
	if (ipc_pcie_parc_read_status_reg(this, &status.raw)) {
		ipc_err("Couldn't read status reg!");
		goto err_read_status;
	}

	this->max_bm_win = status.parc_status.n_bm;
	this->max_sl_win = status.parc_status.n_sl;
	this->max_dw_win = status.parc_status.n_dw;

	/* Allocate memory to save VSEC extended capability during
	 * suspend/hibernate. The fist 12 bytes of VSEC is RO registers.
	 */
	this->pcie_vsec.p_save_cap = ipc_util_kzalloc(this->pcie_vsec.vsec_len);
	if (unlikely(!this->pcie_vsec.p_save_cap)) {
		ipc_err("PARC capability allocation failed");
		goto err_read_status;
	}

	/* PARC is found */
	return 0;

err_read_status:
	this->pcie_vsec.vsec_id = -1;
	return ret_val;
}


/**
 * IPC pcie parc constructor
 *
 * @this: pointer to PARC handler.
 * @pcie: pointer to the core driver data-struct of pcie.
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns 0 on sucess, -1 on failure
 */
static int ipc_pcie_parc_ctor(struct ipc_pcie_parc *this,
			struct ipc_pcie *pcie, struct ipc_debugfs *dbgfs,
			struct ipc_dbg *dbg)
{
	if (unlikely(!pcie)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	this->dbg = dbg;

	if (ipc_pcie_parc_find_vsec(this, pcie))
		return -1;

	/* Allocate PARC */
	this->dbgfs = ipc_debugfs_parc_alloc(dbgfs, this, this->dbg);

	return 0;
}

/**
 * IPC pcie parc destructor
 *
 * @this: pointer to PARC handler
 */
static void ipc_pcie_parc_dtor(struct ipc_pcie_parc *this)
{
	/* free PARC capabilities */
	ipc_util_kfree(this->pcie_vsec.p_save_cap);
	this->pcie_vsec.p_save_cap = NULL;

	/* free debugfs */
	ipc_debugfs_parc_dealloc(&(this->dbgfs));
}

/* Global functions
 */
/* Refer to header file for function description
 */
struct ipc_pcie_parc *ipc_pcie_parc_alloc(struct ipc_pcie *pcie,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg)
{
	struct ipc_pcie_parc *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this))
		goto ret_fail;

	if (ipc_pcie_parc_ctor(this, pcie, dbgfs, dbg))
		goto ctor_fail;
	return this;
ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}

/* Refer to header file for function description
 */
void ipc_pcie_parc_dealloc(struct ipc_pcie_parc **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_pcie_parc_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/* Refer to header file for function description
 */
void ipc_pcie_parc_configure_dw_window(struct ipc_pcie_parc *this,
				enum ipc_pcie_parc_win_dw window_nr, u64 addr)
{
	/* Configure and enable DW
	 */
	if (!ipc_pcie_parc_dw_set_addr(this, window_nr, addr,
			PARC_WINDOW_INCLUSIVE))
		ipc_dbg("Win: %d, Address: 0x%llx", window_nr, addr);
}


/* Refer to header file for function description
 */
void ipc_pcie_parc_configure_sl_window(struct ipc_pcie_parc *this,
				enum ipc_pcie_parc_win_sl window_nr,
				u64 start_addr, u64 end_addr)
{
	/* Configure and enable SL window
	 */
	if (!parc_sl_set_start_n_limit(this, window_nr, start_addr,
			end_addr, PARC_WINDOW_INCLUSIVE))
		ipc_dbg("Win: %d, START: 0x%llx, END: 0x%llx", window_nr,
				start_addr, end_addr);
}


/* Refer to header file for function description
 */
void ipc_pcie_parc_enable(struct ipc_pcie_parc *this)
{
	union ipc_pcie_parc_control ctrl_reg;
	int offset;

	/* Get the offset of PARC Control register */
	offset = this->pcie_vsec.base_addr + INTEL_PARC_CONTROL_REG;

	ipc_pcie_config_read32(this->pcie, offset, &ctrl_reg.raw);

	/* Enabling this Local Interrupt bit will generate an interrupt on
	 * Endpoint upon out of bound access.
	 */
	ctrl_reg.parc_control.lie = 1;

	/* Stop on Error/Violation Enable
	 */
	ctrl_reg.parc_control.se = 1;

	/* Disable Lock Tocken capability
	 */
	ctrl_reg.parc_control.lt = 1;

	/* Enable Violator ID capability
	 */
	ctrl_reg.parc_control.vie = 1;

	/* Nullify the out-of-bound TLPs
	 */
	ctrl_reg.parc_control.nue = 1;

	/* Drop out-of-bound TLPs
	 */
	ctrl_reg.parc_control.de = 1;

	/* Count number of violations
	 */
	ctrl_reg.parc_control.ce = 1;

	/* Global enable
	 */
	ctrl_reg.parc_control.ge = 1;

	/* Disable Global Lock
	 */
	ctrl_reg.parc_control.gl = 0;

	/* Write the control register */
	(void)ipc_pcie_config_write32(this->pcie, offset, ctrl_reg.raw);
}

/**
 * Disables the PARC Globally by writing to Control register.
 *
 * @this: pointer to PARC handler.
 *
 * returns none
 */
static void ipc_pcie_parc_disable(struct ipc_pcie_parc *this)
{
	union ipc_pcie_parc_control ctrl_reg;
	int offset;

	/* Get the offset of PARC Control register */
	offset = this->pcie_vsec.base_addr + INTEL_PARC_CONTROL_REG;

	ipc_pcie_config_read32(this->pcie, offset, &ctrl_reg.raw);

	/* Disable the range check */
	ctrl_reg.parc_control.ge = 0;

	/* Write the control register */
	(void)ipc_pcie_config_write32(this->pcie, offset, ctrl_reg.raw);
}

/* Refer to header file for function description
 */
int ipc_pcie_parc_read_status_reg(struct ipc_pcie_parc *this, u32 *p_status)
{
	int offset;

	if (unlikely(!this || !p_status)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	offset = this->pcie_vsec.base_addr + INTEL_PARC_STATUS_REG;

	ipc_pcie_config_read32(this->pcie, offset, p_status);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_control_reg(struct ipc_pcie_parc *this, u32 *p_control)
{
	int offset;

	if (unlikely(!this || !p_control)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	offset = this->pcie_vsec.base_addr + INTEL_PARC_CONTROL_REG;

	ipc_pcie_config_read32(this->pcie, offset, p_control);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_err_log64(struct ipc_pcie_parc *this, u64 *p_err_log)
{
	int offset;
	u32 err_log32 = 0;

	if (unlikely(!this || !p_err_log)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* Read the higher 32-bits of Error Log
	 */
	offset = this->pcie_vsec.base_addr + INTEL_PARC_1ST_ERRLOG_H;
	ipc_pcie_config_read32(this->pcie, offset, &err_log32);

	*p_err_log = err_log32;
	*p_err_log <<= PARC_WORD_SIZE;

	/* Read the lower 32-bits of Error log
	 */
	offset = this->pcie_vsec.base_addr + INTEL_PARC_1ST_ERRLOG_L;
	ipc_pcie_config_read32(this->pcie, offset, &err_log32);

	*p_err_log |= (u64)err_log32;

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_violation_log(struct ipc_pcie_parc *this, u32 *p_vlog)
{
	int offset;

	if (unlikely(!this || !p_vlog)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* Read the Viloator log
	 */
	offset = this->pcie_vsec.base_addr + INTEL_PARC_INT_VIOLATOR_LOG;
	ipc_pcie_config_read32(this->pcie, offset, p_vlog);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_bm(struct ipc_pcie_parc *this,
			enum ipc_pcie_parc_win_bm win, u32 *p_base_l,
			u32 *p_base_h, u32 *p_mask_l, u32 *p_mask_h)
{
	u32 offset_base_l, offset_base_h, offset_mask_l, offset_mask_h;

	if (unlikely(!this || !p_base_l || !p_base_h || !p_mask_l
		|| !p_mask_h || win >= this->max_bm_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	offset_base_l = this->pcie_vsec.base_addr + INTEL_PARC_BASE_L(win);
	offset_base_h = this->pcie_vsec.base_addr + INTEL_PARC_BASE_H(win);

	offset_mask_l = this->pcie_vsec.base_addr + INTEL_PARC_MASK_L(win);
	offset_mask_h = this->pcie_vsec.base_addr + INTEL_PARC_MASK_H(win);

	/* Read Base_L, Base_H, Mask_L and Mask_H registers.
	 */
	ipc_pcie_config_read32(this->pcie, offset_base_l, p_base_l);
	ipc_pcie_config_read32(this->pcie, offset_base_h, p_base_h);
	ipc_pcie_config_read32(this->pcie, offset_mask_l, p_mask_l);
	ipc_pcie_config_read32(this->pcie, offset_mask_h, p_mask_h);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_dw(struct ipc_pcie_parc *this,
			enum ipc_pcie_parc_win_dw win, u32 *p_dw_l,
			u32 *p_dw_m, u32 *p_dw_h, u32 *p_dw_stat)
{
	u32 offset_dw_l, offset_dw_m, offset_dw_h, offset_dw_stat;

	if (unlikely(!this || !p_dw_l || !p_dw_m || !p_dw_h
		|| !p_dw_stat || win >= this->max_dw_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	offset_dw_l = this->pcie_vsec.base_addr + INTEL_PARC_DW_L(win);
	offset_dw_m = this->pcie_vsec.base_addr + INTEL_PARC_DW_M(win);
	offset_dw_h = this->pcie_vsec.base_addr + INTEL_PARC_DW_H(win);
	offset_dw_stat = this->pcie_vsec.base_addr + INTEL_PARC_DW_STAT(win);

	/* Read DW_L, DW_M, DW_H and DW_STAT registers
	 */
	ipc_pcie_config_read32(this->pcie, offset_dw_m, p_dw_m);
	ipc_pcie_config_read32(this->pcie, offset_dw_h, p_dw_h);
	ipc_pcie_config_read32(this->pcie, offset_dw_stat, p_dw_stat);
	ipc_pcie_config_read32(this->pcie, offset_dw_l, p_dw_l);

	return 0;
}


/* Refer to header file for function description
 */
int ipc_pcie_parc_read_sl(struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_sl win, u32 *p_start_l, u32 *p_start_h,
		u32 *p_limit_l, u32 *p_limit_h)
{
	u32 offset_start_l, offset_start_h, offset_limit_l, offset_limit_h;

	if (unlikely(!this || !p_start_l || !p_start_h || !p_limit_l
		|| !p_limit_h || win >= this->max_sl_win)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	offset_start_l = this->pcie_vsec.base_addr + INTEL_PARC_START_L(win);
	offset_start_h = this->pcie_vsec.base_addr + INTEL_PARC_START_H(win);

	offset_limit_l = this->pcie_vsec.base_addr + INTEL_PARC_LIMIT_L(win);
	offset_limit_h = this->pcie_vsec.base_addr + INTEL_PARC_LIMIT_H(win);

	/* Read Start_L, Start_H, Limit_L and Limit_H registers.
	 */
	ipc_pcie_config_read32(this->pcie, offset_start_l, p_start_l);
	ipc_pcie_config_read32(this->pcie, offset_start_h, p_start_h);
	ipc_pcie_config_read32(this->pcie, offset_limit_l, p_limit_l);
	ipc_pcie_config_read32(this->pcie, offset_limit_h, p_limit_h);

	return 0;
}

/* Refer to header file for function description
 */
u32 ipc_pcie_parc_get_vsec_ver(struct ipc_pcie_parc *this)
{
	return this ? this->pcie_vsec.vsec_ver : -1;
}

/* Refer to header file for function description
 */
u32 ipc_pcie_parc_get_vsec_id(struct ipc_pcie_parc *this)
{
	return this ? this->pcie_vsec.vsec_id : -1;
}

/* Refer to header file for function description
 */
bool ipc_pcie_parc_is_supported(struct ipc_pcie_parc *this)
{
	return this && (this->pcie_vsec.vsec_id == INTEL_PARC_VSEC_ID);
}

/* Refer to header file for function description
 */
void ipc_pcie_parc_save_cap(struct ipc_pcie_parc *this)
{
	int i;
	u32 *p_data;

	/* If PARC is supported then save the Vendor Specific Extended
	 * Capability. Otherwise nothing to do.
	 */
	if (!this || !this->pcie_vsec.p_save_cap
		|| this->pcie_vsec.vsec_id != INTEL_PARC_VSEC_ID)
		return;

	p_data = this->pcie_vsec.p_save_cap;

	/* Save VSEC to local memory. Start saving from end to start because
	 * restoring should be done in that order otherwise PARC Control GL
	 * bit might block register writes during restore.
	 */
	for (i = this->pcie_vsec.vsec_len - 4; i >= 0; i -= 4) {
		ipc_pcie_config_read32(this->pcie,
		this->pcie_vsec.base_addr + i, p_data);
		p_data++;
	}
}


/* Refer to header file for function description
 */
void ipc_pcie_parc_restore_cap(struct ipc_pcie_parc *this)
{
	int i;
	u32 *p_data;

	/* If PARC is supported then restore the Vendor Specific Extended
	 * Capability. Otherwise nothing to do.
	 */
	if (!this || !this->pcie_vsec.p_save_cap
		|| this->pcie_vsec.vsec_id != INTEL_PARC_VSEC_ID)
		return;

	p_data = this->pcie_vsec.p_save_cap;

	/* Restore the VSEC. Start restoring from end to start otherwise
	 * if at all the PARC Control GL is set then register writes will be
	 * blocked.
	 */
	for (i = this->pcie_vsec.vsec_len - 4; i >= 0; i -= 4) {
		ipc_pcie_config_write32(this->pcie,
			this->pcie_vsec.base_addr + i, *p_data);
		p_data++;
	}
}

static void ipc_pcie_parc_reset_addrs(struct ipc_pcie_parc *this,
					bool addr_ranges, bool addr_msi)
{
	unsigned int i;

	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	if (addr_ranges) {
		for (i = 0; i < IPC_PCIE_MEM_TYPE_MAX; i++) {
			ipc_pcie_parc_configure_sl_window(this,
				(enum ipc_pcie_parc_win_sl)i, 0, 0);
		}
	}
	if (addr_msi)
		ipc_pcie_parc_configure_dw_window(this, PARC_WIN_DW_0, 0);
}

/* Refer to header file for function description
 */
void ipc_pcie_parc_test_mode(struct ipc_pcie_parc *this, u32 exec_stage,
				bool crash)
{
	u32 test_mode, msi_test_mode;
	union ipc_pcie_parc_violater_log vlog;

	if (unlikely(!this || this->pcie_vsec.vsec_id != INTEL_PARC_VSEC_ID))
		return;

	/* Get the Parc test mode and MSI test mode */
	test_mode = ipc_debugfs_parc_get_test_mode(this->dbgfs);
	msi_test_mode = ipc_debugfs_parc_get_msi_test_mode(this->dbgfs);

	if (test_mode == exec_stage || msi_test_mode == exec_stage) {

		/* Get the Parc violation log */
		if (ipc_pcie_parc_read_violation_log(this, &vlog.raw)) {
			ipc_err("Error in reading Viloation log");
			return;
		}

		/* If Parc violation already triggered then disable Parc */
		if (vlog.parc_violater_log.viloation_cnt > 0) {
			ipc_pcie_parc_disable(this);
			return;
		}

		if (crash) {
			ipc_pcie_parc_reset_addrs(this, true, true);
			return;
		}

		if (msi_test_mode == exec_stage)
			ipc_pcie_parc_reset_addrs(this, false, true);

		if (test_mode == exec_stage)
			ipc_pcie_parc_reset_addrs(this, true, false);
	}
}
