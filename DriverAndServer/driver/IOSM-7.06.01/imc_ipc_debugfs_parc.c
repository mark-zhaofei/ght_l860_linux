/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "imc_ipc_debugfs.h"
#include "imc_ipc_parc.h"
#include "imc_ipc_util.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_dbg.h"


/* PARC Debugfs directory name
 */
#define IMC_IPC_PARC_DIR "parc"

/* Debugfs file name for PARC info
 */
#define IMC_IPC_PARC_INFO "info"

/* Debugfs file name for PARC Base/Mask scheme
 */
#define IMC_IPC_PARC_BM "bm"

/* Debugfs file name for PARC Start/Limit scheme
 */
#define IMC_IPC_PARC_SL "sl"

/* Debugfs file name for Double Word scheme
 */
#define IMC_IPC_PARC_DW "dw"

/* Debugfs file name for testing PARC
 */
#define IMC_IPC_PARC_TEST_MODE "test_mode"

/* Debugfs file name for testing PARC through MSI
 */
#define IMC_IPC_PARC_MSI_TEST_MODE "msi_test_mode"

/* Bit-0 to Bit-1 Mask
 */
#define MASK_2_BITS	0x3

/* Bit-0 to Bit-3 Mask
 */
#define MASK_3_BITS	0x7


struct ipc_debugfs_parc {
	struct ipc_pcie_parc *parc_h;
	struct dentry *parc_root_dbgfs;

/* This parc_test_mode can have one of the enum ipc_mem_exec_stage values.
 *
 * - If user sets 0xFEEDB007 then the PARC ranges will be cleared just
 *  before forcing Modem to read PSI. This will result in PSI transfer failure
 *  and PARC error logs shows violation address and count. During this test
 *  since Modem will be in BootROM the trap due to PARC interrupt is not
 *  expected but PARC feature will be verified (i.e. PSI transfer should will
 *  fail).
 *
 * - If the value is 0xFEEDBEEF then driver clears the range when Modem informs
 *  about the execution stage change to PSI. After this point any transfer
 *  in PSI will cause trap on Modem in PSI stage.
 *
 * - If value is 0xFEEDCAFE then driver clears the range when Modem informs
 *  about the execution stage change to EBL. This way we could force Modem
 *  trap in EBL due to PARC.
 *
 * - If value is 0x600DF00D then driver clears the range when Modem informs
 *  about the execution stage change to RUN. This way we could force Modem
 *  trap in RUN phase due to PARC.
 *
 * - If value is 0x8BADF00D then MSI address is removed from valid address
 *  ranges in PARC configuration. This way we will force PARC interrupt in
 *  Crash phase.
 */
	u32 parc_test_mode;
/*
 * Refer to parc_test_mode description which is similar
 */
	u32 parc_msi_test_mode;

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;
};


/**
 * Function logs the PARC status register data in verbose.
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_status_reg(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	union ipc_pcie_parc_status stat_reg;

	if (ipc_pcie_parc_read_status_reg(this->parc_h, &stat_reg.raw)) {
		ipc_err("Error in reading status register");
		return;
	}

	seq_printf(m, "\n>>>>> PARC Status Reg: 0x%X\n", stat_reg.raw);

	seq_printf(m,
		"\tMSI/MSI-X on Error Capability....................: %s\n",
		stat_reg.parc_status.mc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tLocal Interrupt Capability.......................: %s\n",
		stat_reg.parc_status.lic ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tStop on Error/Violation Capability...............: %s\n",
		stat_reg.parc_status.sc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tLock Token Capability............................: %s\n",
		stat_reg.parc_status.lc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tViolator ID and 1st violation Log Capability.....: %s\n",
		stat_reg.parc_status.vic ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tCapability to nullify out-of-bounds TLPs.........: %s\n",
		stat_reg.parc_status.nuc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tCapability to internally drop out-of-bounds TLPs.: %s\n",
		stat_reg.parc_status.dc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tCount number of violations capability............: %s\n",
		stat_reg.parc_status.cc ? "SUPPORTED" : "NOT-SUPPORTED");

	seq_printf(m,
		"\tNumber of supported DW Scheme Windows............: %d\n",
		stat_reg.parc_status.n_dw);

	seq_printf(m,
		"\tNumber of supported Base/Mask Scheme Windows.....: %d\n",
		stat_reg.parc_status.n_bm);

	seq_printf(m,
		"\tNumber of supported Start/Limit Scheme Windows...: %d\n",
		stat_reg.parc_status.n_sl);
}


/**
 * Function logs the PARC control register data in verbose.
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_control_reg(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	union ipc_pcie_parc_control ctrl_reg;

	if (ipc_pcie_parc_read_control_reg(this->parc_h, &ctrl_reg.raw)) {
		ipc_err("Error in reading status register");
		return;
	}

	seq_printf(m, "\n>>>>> PARC Control Reg: 0x%X\n", ctrl_reg.raw);

	seq_printf(m, "\tMSI/MSI-X on Error................: %s\n",
		ctrl_reg.parc_control.me ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tLocal Interrupt Enable............: %s\n",
		ctrl_reg.parc_control.lie ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tStop on Error/Violation Enable....: %s\n",
		ctrl_reg.parc_control.se ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tLock Token Enable.................: %s\n",
		ctrl_reg.parc_control.lt ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tViolator ID and 1st Vilation log..: %s\n",
		ctrl_reg.parc_control.vie ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tNullify o-o-b TLPs enable.........: %s\n",
		ctrl_reg.parc_control.nue ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tInternally drop o-o-b TLPs enable.: %s\n",
		ctrl_reg.parc_control.de ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tCount Nr. of violation enable.....: %s\n",
		ctrl_reg.parc_control.ce ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tGlobal enable.....................: %s\n",
		ctrl_reg.parc_control.ge ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tGlobal lock.......................: %s\n",
		ctrl_reg.parc_control.gl ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tToken enable......................: %s\n",
		ctrl_reg.parc_control.te ? "ENABLED" : "NOT-ENABLED");

	seq_printf(m, "\tLock Token........................: %d\n",
		ctrl_reg.parc_control.lock_token);
}


/**
 * Function logs the PARC error log register data in verbose.
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_err_reg(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	u64 tlp_address;
	union ipc_pcie_parc_violater_log vlog;

	if (ipc_pcie_parc_read_err_log64(this->parc_h, &tlp_address)) {
		ipc_err("Error in reading TLP address");
		return;
	}

	if (ipc_pcie_parc_read_violation_log(this->parc_h, &vlog.raw)) {
		ipc_err("Error in reading Viloation log");
		return;
	}

	seq_printf(m, "\n>>>>> PARC Error Log: 0x%X\n", vlog.raw);

	seq_printf(m, "\tFirst TLP Error Address........: 0x%llX\n",
		tlp_address);

	seq_printf(m, "\tViolation Count................: %d\n",
		vlog.parc_violater_log.viloation_cnt);

	seq_printf(m, "\tMultiple Violations............: %s\n",
		vlog.parc_violater_log.vm ? "YES" : "NO");

	seq_printf(m, "\tSingle Violation...............: %s\n",
		vlog.parc_violater_log.vs ? "YES" : "NO");
}


/**
 * Function logs the PARC Base/Mask configurations of all windows in verbose.
 * imc_ipc/parc/bm --> prints this information
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_bm_regs(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	union ipc_pcie_parc_base_lo base_lo;
	u32 base_hi = 0, mask_hi = 0;
	union ipc_pcie_parc_mask_lo mask_lo;
	enum ipc_pcie_parc_win_bm win;
	union ipc_pcie_parc_status stat_reg;

	if (ipc_pcie_parc_read_status_reg(this->parc_h, &stat_reg.raw)) {
		ipc_err("Error in reading status register");
		return;
	}

	for (win = PARC_WIN_BM_0; win < stat_reg.parc_status.n_bm; win++) {
		if (ipc_pcie_parc_read_bm(this->parc_h, win, &base_lo.raw,
				&base_hi, &mask_lo.raw, &mask_hi)) {
			ipc_err("Error in reading BM registers");
			return;
		}
		seq_printf(m, "\n>>>>> PARC BM Window: %d\n", win);

		seq_printf(m, "\tBase: 0x%llX\n",
			((u64)base_hi << 32) | (base_lo.raw & ~MASK_3_BITS));

		seq_printf(m, "\tMask: 0x%llX\n",
			((u64)mask_hi << 32) | (mask_lo.raw & ~MASK_2_BITS));

		seq_printf(m, "\t\tEnable range check................: %d\n",
			base_lo.bm_base_l.ec);

		seq_printf(m, "\t\tLock window for write.............: %d\n",
			base_lo.bm_base_l.lw);

		seq_printf(m, "\t\tWindow type control...............: %s\n",
			base_lo.bm_base_l.wt ? "EXCLUSIVE" : "INCLUSIVE");

		seq_printf(m,
			"\t\tWindow Range violation occured..........: %d\n",
			mask_lo.bm_mask_l.wv);

		seq_printf(m,
			"\t\tMultiple window range violation occurred: %d\n\n",
			mask_lo.bm_mask_l.mwv);

	}
}


/**
 * Function logs the PARC Start/Limit configurations of all windows in verbose.
 * imc_ipc/parc/sl --> prints this information
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_sl_regs(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	union ipc_pcie_parc_start_lo start_lo;
	u32 start_hi = 0, limit_hi = 0;
	union ipc_pcie_parc_limit_lo limit_lo;
	enum ipc_pcie_parc_win_sl win;
	union ipc_pcie_parc_status stat_reg;

	if (ipc_pcie_parc_read_status_reg(this->parc_h, &stat_reg.raw)) {
		ipc_err("Error in reading status register");
		return;
	}

	for (win = PARC_WIN_SL_0; win < stat_reg.parc_status.n_sl; win++) {
		if (ipc_pcie_parc_read_sl(this->parc_h, win, &start_lo.raw,
				&start_hi, &limit_lo.raw, &limit_hi)) {
			ipc_err("Error in reading SL registers");
			return;
		}

		seq_printf(m, "\n>>>>> PARC SL Window: %d\n", win);

		seq_printf(m, "\tStart: 0x%llX\n",
			((u64)start_hi << 32) | (start_lo.raw & ~MASK_3_BITS));

		seq_printf(m, "\tLimit: 0x%llX\n",
			((u64)limit_hi << 32) | (limit_lo.raw & ~MASK_2_BITS));

		seq_printf(m, "\t\tEnable range check................: %d\n",
			start_lo.sl_start_l.ec);

		seq_printf(m, "\t\tLock window for write.............: %d\n",
			start_lo.sl_start_l.lw);

		seq_printf(m, "\t\tWindow type control...............: %s\n",
			start_lo.sl_start_l.wt ? "EXCLUSIVE" : "INCLUSIVE");

		seq_printf(m,
			"\t\tWindow Range violation occured..........: %d\n",
			limit_lo.sl_limit_l.wv);

		seq_printf(m,
			"\t\tMultiple window range violation occurred: %d\n\n",
			limit_lo.sl_limit_l.mwv);
	}
}


/**
 * Function logs the PARC DW configurations of all windows in verbose.
 * imc_ipc/parc/dw --> prints this information
 *
 * @this: pointer to parc debugfs pointer
 * @m: the seq_file handle
 *
 * returns none
 */
static void ipc_debugfs_parc_log_dw_regs(struct ipc_debugfs_parc *this,
			struct seq_file *m)
{
	u32 dw_lo = 0, dw_hi = 0;
	union ipc_pcie_parc_dw_mi dw_mi;
	union ipc_pcie_parc_dw_stat dw_stat;
	enum ipc_pcie_parc_win_dw win;
	union ipc_pcie_parc_status stat_reg;
	u64 dw_addr;

	if (ipc_pcie_parc_read_status_reg(this->parc_h, &stat_reg.raw)) {
		ipc_err("Error in reading status register");
		return;
	}

	for (win = PARC_WIN_DW_0; win < stat_reg.parc_status.n_dw; win++) {
		if (ipc_pcie_parc_read_dw(this->parc_h, win, &dw_lo,
					&dw_mi.raw, &dw_hi, &dw_stat.raw)) {
			ipc_err("Error in reading SL registers");
			return;
		}

		seq_printf(m, "\n>>>>> PARC DW Window: %d\n", win);

		dw_addr = dw_hi;
		dw_addr = (dw_addr << 32) | (dw_mi.raw & ~MASK_3_BITS) | dw_lo;

		seq_printf(m, "\tDW Addr: 0x%llX\n", dw_addr);

		seq_printf(m, "\t\tEnable range check................: %d\n",
			dw_mi.mid.ec);

		seq_printf(m, "\t\tLock window for write.............: %d\n",
			dw_mi.mid.lw);

		seq_printf(m, "\t\tWindow type control...............: %s\n",
			dw_mi.mid.wt ? "EXCLUSIVE" : "INCLUSIVE");

		seq_printf(m,
			"\t\tWindow Range violation occured..........: %d\n",
			dw_stat.stat.wv);

		seq_printf(m,
			"\t\tMultiple window range violation occurred: %d\n\n",
			dw_stat.stat.mwv);
	}
}


/**
 * Helper function to log PARC information in verbose when open on
 * imc_ipc/parc/info is called
 *
 * @m: the seq_file handle
 * @v: unused void pointer data.
 *
 * returns 0 on success, -1 on failure
 */
static int ipc_debugfs_parc_info(struct seq_file *m, void *v)
{
	struct ipc_debugfs_parc *this = NULL;
	u32 vsec_id, vsec_ver;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	if (!ipc_pcie_parc_is_supported(this->parc_h)) {
		ipc_err("Don't have Intel PARC capability");
		return -1;
	}

	vsec_id = ipc_pcie_parc_get_vsec_id(this->parc_h);
	vsec_ver = ipc_pcie_parc_get_vsec_ver(this->parc_h);

	seq_puts(m, "\n>>>>> PARC Info\n");

	seq_printf(m, "\tVSEC ID: 0x%X\tRev: 0x%X\n\n",
			vsec_id, vsec_ver);

	ipc_debugfs_parc_log_status_reg(this, m);

	ipc_debugfs_parc_log_control_reg(this, m);

	ipc_debugfs_parc_log_err_reg(this, m);

	return 0;
}


/**
 * Open function for imc_ipc/parc/info
 *
 * @inode: inode pointer for "info" file
 * @file: file pointer for "info" file.
 *
 * returns 0 on success, Error number on failure
 */
static int ipc_debugfs_parc_info_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_parc_info, inode->i_private);
}

/* defines file operations for parc info debugfs attribute file */
static const struct file_operations ipc_debugfs_parc_info_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_parc_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/**
 * Helper function to log PARC BM configuration in verbose when open on
 * imc_ipc/parc/bm is called.
 *
 * @m: the seq_file handle
 * @v: unused void pointer data.
 *
 * returns 0 on success, -1 on failure
 */
static int ipc_debugfs_parc_bm(struct seq_file *m, void *v)
{
	struct ipc_debugfs_parc *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	if (!ipc_pcie_parc_is_supported(this->parc_h)) {
		ipc_err("Don't have Intel PARC capability");
		return -1;
	}

	ipc_debugfs_parc_log_bm_regs(this, m);

	return 0;
}


/**
 * Open function for imc_ipc/parc/bm
 *
 * @inode: inode pointer for "bm" file
 * @file: file pointer for "bm" file.
 *
 * returns 0 on success, Error number on failure
 */
static int ipc_debugfs_parc_bm_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_parc_bm, inode->i_private);
}

/* defines file operations for parc bm debugfs attribute file */
static const struct file_operations ipc_debugfs_parc_bm_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_parc_bm_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/**
 * Helper function to log PARC SL configuration in verbose when open on
 * imc_ipc/parc/sl is called.
 *
 * @m: the seq_file handle
 * @v: unused void pointer data.
 *
 * returns 0 on success, -1 on failure
 */
static int ipc_debugfs_parc_sl(struct seq_file *m, void *v)
{
	struct ipc_debugfs_parc *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	if (!ipc_pcie_parc_is_supported(this->parc_h)) {
		ipc_err("Don't have Intel PARC capability");
		return -1;
	}
	ipc_debugfs_parc_log_sl_regs(this, m);

	return 0;
}


/**
 * Open function for imc_ipc/parc/sl
 *
 * @inode: inode pointer for "sl" file
 * @file: file pointer for "sl" file.
 *
 * returns 0 on success, Error number on failure
 */
static int ipc_debugfs_parc_sl_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_parc_sl, inode->i_private);
}

/* defines file operations for parc sl debugfs attribute file */
static const struct file_operations ipc_debugfs_parc_sl_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_parc_sl_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/**
 * Helper function to log PARC DW configuration in verbose when open on
 * imc_ipc/parc/dw is called.
 *
 * @m: the seq_file handle
 * @v: unused void pointer data.
 *
 * returns 0 on success, -1 on failure
 */
static int ipc_debugfs_parc_dw(struct seq_file *m, void *v)
{
	struct ipc_debugfs_parc *this = NULL;

	if (unlikely(!m || !m->private)) {
		ipc_err("invalid params");
		return -1;
	}

	this = m->private;

	if (!ipc_pcie_parc_is_supported(this->parc_h)) {
		ipc_err("Don't have Intel PARC capability");
		return -1;
	}

	ipc_debugfs_parc_log_dw_regs(this, m);

	return 0;
}


/**
 * Open function for imc_ipc/parc/dw
 *
 * @inode: inode pointer for "dw" file
 * @file: file pointer for "dw" file.
 *
 * returns 0 on success, Error number on failure
 */
static int ipc_debugfs_parc_dw_open(struct inode *inode, struct file *file)
{
	if (unlikely(!inode || !file))
		return -ENOENT;

	return single_open(file, ipc_debugfs_parc_dw, inode->i_private);
}

/* defines file operations for parc dw debugfs attribute file */
static const struct file_operations ipc_debugfs_parc_dw_fops = {
	.owner = THIS_MODULE,
	.open = ipc_debugfs_parc_dw_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


/*
 * Refer to header file for description
 */
u32 ipc_debugfs_parc_get_test_mode(struct ipc_debugfs_parc *this)
{
	return this->parc_test_mode;
}


/*
 * Refer to header file for description
 */
u32 ipc_debugfs_parc_get_msi_test_mode(struct ipc_debugfs_parc *this)
{
	return this->parc_msi_test_mode;
}


/*
 * PARC debugfs constructor function
 *
 * @this: Pointer to parc debugfs data-struct
 * @dbgfs: Pointer to debugfs data-struct
 * @parc: Pointer to pcie parc handler data-struct
 * @dbg: pointer to ipc_dbg structure
 *
 * returns zero on success
 */

static int ipc_debugfs_parc_ctor(struct ipc_debugfs_parc *this,
		struct ipc_debugfs *dbgfs, struct ipc_pcie_parc *parc,
		struct ipc_dbg *dbg)
{
	if (unlikely(!parc ||
			!ipc_debugfs_get_root_folder(dbgfs))) {
		ipc_err("invalid params");
		return -1;
	}

	this->parc_h = parc;
	this->dbg = dbg;

	this->parc_root_dbgfs = debugfs_create_dir(IMC_IPC_PARC_DIR,
					ipc_debugfs_get_root_folder(dbgfs));
	if (!this->parc_root_dbgfs) {
		ipc_err("parc root debugfs directory failed");
		return -1;
	}

	if (!debugfs_create_u32(IMC_IPC_PARC_TEST_MODE, 0664,
			this->parc_root_dbgfs, &this->parc_test_mode))
		goto cleanup_root;

	if (!debugfs_create_u32(IMC_IPC_PARC_MSI_TEST_MODE, 0664,
			this->parc_root_dbgfs, &this->parc_msi_test_mode))
		goto cleanup_root;

	if (!debugfs_create_file(IMC_IPC_PARC_INFO, 0444,
			this->parc_root_dbgfs, this,
			&ipc_debugfs_parc_info_fops))
		goto cleanup_root;

	if (!debugfs_create_file(IMC_IPC_PARC_BM, 0444,
			this->parc_root_dbgfs, this,
			&ipc_debugfs_parc_bm_fops))
		goto cleanup_root;

	if (!debugfs_create_file(IMC_IPC_PARC_SL, 0444,
			this->parc_root_dbgfs, this,
			&ipc_debugfs_parc_sl_fops))
		goto cleanup_root;

	if (!debugfs_create_file(IMC_IPC_PARC_DW, 0444,
			this->parc_root_dbgfs, this,
			&ipc_debugfs_parc_dw_fops))
		goto cleanup_root;

	return 0;

cleanup_root:
	ipc_err("parc create debugfs files failed");
	debugfs_remove_recursive(this->parc_root_dbgfs);
	return -1;
}

/* Refer to header file for function description
 */
struct ipc_debugfs_parc *ipc_debugfs_parc_alloc(struct ipc_debugfs *dbgfs,
			struct ipc_pcie_parc *parc, struct ipc_dbg *dbg)
{
	struct ipc_debugfs_parc *this = ipc_util_kzalloc(sizeof(*this));

	if (unlikely(!this)) {
		ipc_err("alloc failed");
		goto ret_fail;
	}

	if (ipc_debugfs_parc_ctor(this, dbgfs, parc, dbg)) {
		ipc_err("ctor failed");
		goto ctor_fail;
	}

	return this;
ctor_fail:
	ipc_util_kfree(this);
ret_fail:
	return NULL;
}


/**
 * IPC PARC debugfs destructor
 * @this: pointer to struct ipc_parc_debugfs
 */
static void ipc_debugfs_parc_dtor(struct ipc_debugfs_parc *this)
{
	debugfs_remove_recursive(this->parc_root_dbgfs);
}


/* Refer to header file for function description
 */
void ipc_debugfs_parc_dealloc(struct ipc_debugfs_parc **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_debugfs_parc_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}

