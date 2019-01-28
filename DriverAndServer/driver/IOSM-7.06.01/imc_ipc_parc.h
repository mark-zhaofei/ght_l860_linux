/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#if !defined(IMC_IPC_PARC_H)
#define IMC_IPC_PARC_H

struct ipc_pcie;
struct ipc_pcie_parc;
struct ipc_debugfs;
struct ipc_dbg;


/* Vendor Specific ID of PARC capability
 */
#define INTEL_PARC_VSEC_ID		0x24

/* PARC Status Register
 */
union ipc_pcie_parc_status {
	u32 raw;
	struct {
		u32 mc:1;	/* MSI/MSI-X on Error Capability */
		u32 lic:1;	/* Local Interrupt Capability */
		u32 sc:1;	/* Stop on Error/Violation Capability */
		u32 lc:1;	/* Lock Token Capability */
		u32 vic:1;	/* Violator ID and 1st violation Log Cap. */
		u32 nuc:1;	/* Capability to nullify out-of-bounds TLPs */
		u32 dc:1;	/* Capability to internally drop o-o-b TLPs */
		u32 cc:1;	/* Count number of violations capability */
		u32 res:4;	/* Reserved */
		u32 n_dw:4;	/* Nr. of supported Dwords TLPs windows */
		u32 n_bm:8;	/* Nr. of supported windows using Base/Mask */
		u32 n_sl:8;	/* Nr. of supported windows using Start/Limit */
	} parc_status;
};


/* PARC Control Register
 */
union ipc_pcie_parc_control {
	u32 raw;
	struct {
		u32 me:1;	/* MSI/MSI-X on Error Enable */
		u32 lie:1;	/* Local Interrupt Capability Enable */
		u32 se:1;	/* Stop on Error/Violation Enable */
		u32 lt:1;	/* Lock Token Enable */
		u32 vie:1;	/* Violator ID and 1st violation Log Cap. */
		u32 nue:1;	/* Capability to nullify o-o-b TLPs Enable */
		u32 de:1;	/* Cap. to internally drop o-o-b TLPs Enable */
		u32 ce:1;	/* Count nr. of violations capability enable */
		u32 res1:8;	/* Reserved */
		u32 ge:1;	/* Global Enable */
		u32 gl:1;	/* Global Lock */
		u32 te:1;	/* Tocken enable */
		u32 res2:1;	/* Reserved */
		u32 lock_token:12; /* If implemented, GE, GL, TE, can only be
				    * modified after TE was reset using the
				    * captured value at time of setting TE.
				    */
	} parc_control;
};


/* PARC internal Violator Log
 */
union ipc_pcie_parc_violater_log {
	u32 raw;
	struct {
		u32 vs:1;		/* Single Violation indicator */
		u32 vm:1;		/* Multiple Violations indicator */
		u32 res:14;		/* Reserved */
		u32 viloation_cnt:16;	/* Violation counter */
	} parc_violater_log;
};


/******************************
 * BASE/MASK Method
 ******************************/

/* Low part of Base address for window definition */
union ipc_pcie_parc_base_lo {
	u32 raw;
	struct {
		u32 ec:1; /* Enable Range Check (individual) */
		u32 lw:1; /* Lock Window for Writes(relevant if GL=0) */
		u32 wt:1; /* Window Type Control */
		u32 res:9; /* Reserved */
		u32 addr_window_low:20; /* Base Addr. win. def. Range: 31:12 */
	} bm_base_l;
};

/* Low part of Mask address for window definition */
union ipc_pcie_parc_mask_lo {
	u32 raw;
	struct {
		u32 wv:1; /* Win. range Violation occured (individual) */
		u32 mwv:1; /* Multiple Win range Violation occured (ind.) */
		u32 res:10; /* Reserved */
		u32 addr_window_low:20; /* Mask Addr. win. def. Range: 31:12 */
	} bm_mask_l;
};


/* Enums for BM Window numbers.
 */
enum ipc_pcie_parc_win_bm {
	PARC_WIN_BM_0 = 0,	/* Free to use */
	PARC_WIN_BM_1		/* Free to use */
};


/****************************************
 * DWord TLP
 ****************************************/
union ipc_pcie_parc_dw_mi {
	u32 raw;
	struct {
		u32 ec:1; /* Enable Range Check (individual) */
		u32 lw:1; /* Lock Window for Writes(relevant if GL=0) */
		u32 wt:1; /* Window Type Control */
		u32 res:9; /* Reserved */
		u32 addr_window_mid:20; /* DW Addr. win. def. Range: 31:12 */
	} mid;
};

/* Status register range check */
union ipc_pcie_parc_dw_stat {
	u32 raw;
	struct {
		u32 wv:1; /* Win. range Violation occured (individual) */
		u32 mwv:1; /* Multiple Win range Violation occured (ind.) */
		u32 res:30; /* Reserved */
	} stat;
};


/* Enums for DW Window numbers.
 */
enum ipc_pcie_parc_win_dw {
	PARC_WIN_DW_0 = 0,	/* In use for MSI address */
	PARC_WIN_DW_1		/* Free to use */
};


/********************************************
 * START/LIMIT Approach
 ********************************************/

/* Low part of Start Address for Window Definition */
union ipc_pcie_parc_start_lo {
	u32 raw;
	struct {
		u32 ec:1; /* Enable Range Check (individual) */
		u32 lw:1; /* Lock Window for Writes(relevant if GL=0) */
		u32 wt:1; /* Window Type Control */
		u32 res:9; /* Reserved */
		u32 addr_window_low:20; /* Start Addr. win. def. Range-31:12 */
	} sl_start_l;
};


/* Low part of Mask address for window definition */
union ipc_pcie_parc_limit_lo {
	u32 raw;
	struct {
		u32 wv:1; /* Win. range Violation occured (individual) */
		u32 mwv:1; /* Multiple Win range Violation occured (ind.) */
		u32 res:10; /* Reserved */
		u32 addr_window_low:20; /* Limit Addr. win. def. Range-31:12 */
	} sl_limit_l;
};


/* Enums for SL Window numbers.
 */
enum ipc_pcie_parc_win_sl {
	PARC_WIN_SL_0 = 0,	/* In use for SKB memory range */
	PARC_WIN_SL_1,		/* In use for dynamic memory range */
	PARC_WIN_SL_2,		/* Free to use */
	PARC_WIN_SL_3		/* Free to use */
};


/**
 * Enables the PARC Globally by writing to Control register.
 *
 * @this: pointer to PARC handler.
 *
 * returns none
 */
void ipc_pcie_parc_enable(struct ipc_pcie_parc *this);


/**
 * Configures the PARC DW registers for a given window.
 *
 * @this: pointer to PARC handler.
 * @window_nr: window number to be configured
 * @addr: 64-bit start address
 *
 * returns none
 */
void ipc_pcie_parc_configure_dw_window(struct ipc_pcie_parc *this,
			enum ipc_pcie_parc_win_dw window_nr, u64 addr);


/**
 * Configures the PARC Start and Limit registers for a given window.
 *
 * @this: pointer to PARC handler.
 * @window_nr: window number to be configured
 * @start_addr: 64-bit start address
 * @end_addr: 64-bit end address
 *
 * returns none
 */
void ipc_pcie_parc_configure_sl_window(struct ipc_pcie_parc *this,
			enum ipc_pcie_parc_win_sl window_nr, u64 start_addr,
			u64 end_addr);


/**
 * Function for reading the PARC Status register.
 *
 * @this: pointer to PARC handler.
 * @p_status: on success status value will be updated in the address pointed
 *            in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_status_reg(struct ipc_pcie_parc *this, u32 *p_status);


/**
 * Function for reading the PARC Control register.
 *
 * @this: pointer to PARC handler.
 * @p_control: on success control register value will be updated in the address
 *             pointed in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_control_reg(struct ipc_pcie_parc *this, u32 *p_control);


/**
 * Function for reading the PARC Error log register.
 *
 * @this: pointer to PARC handler.
 * @p_err_log: on success error log register value will be updated in the
 *             address pointed in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_err_log64(struct ipc_pcie_parc *this, u64 *p_err_log);


/**
 * Function for reading the PARC Violation log register.
 *
 * @this: pointer to PARC handler.
 * @p_vlog: on success Violation log register value will be updated in the
 *          address pointed in this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_violation_log(struct ipc_pcie_parc *this, u32 *p_vlog);


/**
 * Function for reading the PARC Base Mask registers for a given window.
 *
 * @this: pointer to PARC handler.
 * @win: Window number the read required for
 * On success
 * @p_base_l: Base_L register value will be updated in the address pointed in
 *            this variable.
 * @p_base_h: Base_H register value will be updated in the address pointed in
 *            this variable.
 * @p_mask_l: Mask_L register value will be updated in the address pointed in
 *            this variable.
 * @p_mask_h: Mask_H register value will be updated in the address pointed in
 *            this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_bm(struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_bm win, u32 *p_base_l, u32 *p_base_h,
		u32 *p_mask_l, u32 *p_mask_h);


/**
 * Function for reading the PARC DW registers for a given window.
 *
 * @this: pointer to PARC handler.
 * @win: Window number the read required for
 * On success
 * @p_dw_l: DW_L register value will be updated in the address pointed in
 *          this variable.
 * @p_dw_m: DW_M register value will be updated in the address pointed in
 *          this variable.
 * @p_dw_h: DW_H register value will be updated in the address pointed in
 *          this variable.
 * @p_dw_stat: DW_Stat register value will be updated in the address pointed in
 *             this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_dw(struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_dw win, u32 *p_dw_l, u32 *p_dw_m,
		u32 *p_dw_h, u32 *p_dw_stat);


/**
 * Function for reading the PARC Start/Limit registers for a given window.
 *
 * @this: pointer to PARC handler.
 * @win: Window number the read required for
 * On success
 * @p_start_l: Start_L register value will be updated in the address pointed in
 *             this variable.
 * @p_start_h: Start_H register value will be updated in the address pointed in
 *             this variable.
 * @p_limit_l: Limit_L register value will be updated in the address pointed in
 *             this variable.
 * @p_limit_h: Limit_H register value will be updated in the address pointed in
 *             this variable.
 *
 * returns 0 on success, -1 on failure
 */
int ipc_pcie_parc_read_sl(struct ipc_pcie_parc *this,
		enum ipc_pcie_parc_win_sl win, u32 *p_start_l, u32 *p_start_h,
		u32 *p_limit_l, u32 *p_limit_h);


/**
 * Function for saving the PARC Vendor Specific Extended Capability locally
 *
 * @this: pointer to PARC handler.
 *
 * returns none
 */
void ipc_pcie_parc_save_cap(struct ipc_pcie_parc *this);


/**
 * Function for restoring the PARC Vendor Specific Extended Capability
 *
 * @this: pointer to PARC handler.
 *
 * returns none
 */
void ipc_pcie_parc_restore_cap(struct ipc_pcie_parc *this);


/**
 * Function for freeing the PARC allocated memory.
 *
 * @this: pointer to PARC handler.
 *
 * returns none
 */
void ipc_pcie_parc_cleanup(struct ipc_pcie_parc *this);

/**
 * Function for PARC test mode
 *
 * @this: pointer to PARC handler.
 * @exec_stage: CP execution stage
 * @crash: If CP is in crash stage then true else false
 *
 * returns none
 */
void ipc_pcie_parc_test_mode(struct ipc_pcie_parc *this, u32 exec_stage,
			bool crash);

/**
 * Gets the PARC VSEC id
 *
 * @this: pointer to PARC handler.
 *
 * returns PARC VSEC id
 */
u32 ipc_pcie_parc_get_vsec_id(struct ipc_pcie_parc *this);

/**
 * Gets the PARC VSEC version
 *
 * @this: pointer to PARC handler.
 *
 * returns PARC VSEC version
 */
u32 ipc_pcie_parc_get_vsec_ver(struct ipc_pcie_parc *this);

/**
 * PARC is supported or not
 *
 * @this: pointer to PARC handler.
 *
 * returns true if PARC is supported else false
 */
bool ipc_pcie_parc_is_supported(struct ipc_pcie_parc *this);


/**
 * Allocates and initializes PARC component
 *
 * @pcie: pointer to struct ipc_pcie
 * @dbgfs: pointer to struct ipc_debugfs
 * @dbg: pointer to ipc_dbg structure
 *
 * returns pointer to PARC handler
 */
struct ipc_pcie_parc *ipc_pcie_parc_alloc(struct ipc_pcie *pcie,
		struct ipc_debugfs *dbgfs, struct ipc_dbg *dbg);

/**
 * De-initializes and de-allocates PARC component
 *
 * @this_pp: pointer to PARC handler.
 *
 * returns None
 */
void ipc_pcie_parc_dealloc(struct ipc_pcie_parc **this_pp);

#endif /* !defined (IMC_IPC_PARC_H) */
