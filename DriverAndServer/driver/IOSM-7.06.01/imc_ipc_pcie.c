/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/msi.h>
#include <linux/interrupt.h>
#include <linux/dma_remapping.h>
#include <linux/spinlock.h>
#include <linux/pci_regs.h>
#include <linux/pci-aspm.h>
#include <linux/delay.h>

#include <linux/timer.h>
#include <linux/hrtimer.h>	/* ktime_get */
#include <linux/pm_runtime.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include <stdbool.h>		/* C99 bool: true, false.  */

#include "imc_ipc_util.h"	/* IPC configuration */
#include "imc_ipc_dbg.h"
#include "imc_ipc_pcie.h"	/* PCIe configuration */
#include "imc_ipc_imem.h"	/* Shared memory layer  */
#include "imc_ipc_version.h"	/* Version info */
#include "imc_ipc_export.h"	/* exported definitions */
#include "imc_ipc_sio.h"
#include "imc_ipc_parc.h"
#include "imc_ipc_uevent.h"
#include "imc_ipc_netlink.h"
#include "imc_ipc_protocol.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_ras_des.h"
#include "imc_ipc_gpio_handler.h"

#ifdef IPC_FASTSIM
#include "imc_ipc_fastsim.h"
#endif
#include "imc_ipc_debugfs.h"

MODULE_VERSION(IPC_DRIVER_VERSION);
MODULE_AUTHOR(IPC_DRIVER_AUTHOR);
MODULE_DESCRIPTION(IPC_DRIVER_DESC " " IPC_DRIVER_FEATURE);
MODULE_LICENSE("Dual BSD/GPL");

#define IPC_DEVEL_MODE		/* XXX */

/* ASPM L1 supported */
#define  PCIE_ASPM_L1_SUPPORTED	2

/* MSI-X first entry */
#define IPC_MSIX_FIRST_ENTRY	0
/* Define MSIX entry */
#define IPC_MSIX_ENTRY(i)	(IPC_MSIX_FIRST_ENTRY + i)

/*
 * Define for BAR area usage
 */
#define IPC_DOORBELL_BAR0		0
#define IPC_SCRATCHPAD_BAR1		1
#define IPC_SCRATCHPAD_BAR2		2


/**
 * defines for DOORBELL registers information
 */
#define IPC_DOORBELL_CH_OFFSET		0x20
#define IPC_CAPTURE_PTR_REG_0		0x08
#define IPC_WRITE_PTR_REG_0		0x10

#define IPC_DOORBELL_CH_OFFSET_7660	0x10
#define IPC_CAPTURE_PTR_REG_0_7660	0x04
#define IPC_WRITE_PTR_REG_0_7660	0x80

#define IPC_DOORBELL_CH_OFFSET_8060	0x10
#define IPC_CAPTURE_PTR_REG_0_8060	0x404
#define IPC_WRITE_PTR_REG_0_8060	0x380

#define IPC_RAS_PARC_VSH                0x004

#define IPC_DOORBELL_REG(ipc_reg_, ptr, channel_, offset) \
	(((u8 *) (ipc_reg_)) + ptr + ((channel_) * offset))

#define IPC_SUSPENDED			BIT(0)

static LIST_HEAD(ipc_pcie_mdm_list);
static struct ipc_netlink *ipc_pcie_netlink;

/* IPC_PCIE state.
 */
struct ipc_pcie {
	struct pci_dev *pci;	/* Address of the device description. */

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	/* Remapped CP doorbell address of the irq register set, to fire the
	 * doorbell irq.
	 */
	void __iomem *ipc_regs;

	/*
	 * BAR number to be used for IPC doorbell
	 */
	int ipc_regs_bar_nr;

	/* Remapped CP scratchpad address, to send the configuration
	 * tuple and the IPC descriptors to CP in the ROM phase. The config
	 * tuple information are saved on the MSI scratchpad.
	 */
	void __iomem *scratchpad;

	/*
	 * BAR number to be used for Scratchpad
	 */
	int scratchpad_bar_nr;

	/* number of requested irq vectors
	 */
	u32 nvec;

	/* MSI-X entry
	 */
	struct msix_entry msix[IPC_MSIX_VECTORS];

	/* number of requested MSI-X irq vectors
	 */
	u32 msix_nvec;

	/* 1 means the PCI configuration registers are reserved for
	 * the IMC IPC device.
	 */
	u32 pci_regions_requested:1;

	/* 1 means the MSI irq was requested by request_irq() and
	 * free_irq() shall be executed in ipc_cleanup().
	 */
	u32 is_irq_requested:1;

	/* 1 means the bus mastering for the IMC_IPC device was enabled.
	 */
	u32 is_master:1;

	/* statistic counter
	 */
	unsigned long ipc_irq_count;
	unsigned long slp_irq_count;
	unsigned long hpu_irq_count;
	unsigned long time_sync_irq_count;
	unsigned long ap_msi_irq_count[IPC_MSI_VECTORS];
	unsigned long ap_msix_irq_count[IPC_MSIX_VECTORS];

	/* PCIe Address Range Check (PARC) handler */
	struct ipc_pcie_parc *pcie_parc;

	/* Address range structure contains start and end addresses for SKB
	 * and Dynamic memory allocations.
	 */
	struct ipc_util_addr_range ranges[IPC_PCIE_MEM_TYPE_MAX];

	/* Pointer to imem data struct */
	struct ipc_imem *imem;

	/* Pointer to Root debugfs */
	struct ipc_debugfs *root_dbgfs;

#ifdef IPC_FASTSIM
	/* Fastsim component, allows to connect a simulated, virtual device */
	struct ipc_fastsim *fastsim;
#endif
	/* doorbell registers */
	u32 doorbell_reg_offset;
	u32 doorbell_write_ptr;
	u32 doorbell_capture_ptr;

	/* IPC events*/
	struct ipc_uevent *uevent;

	/* pointer to netlink data-struct */
	struct ipc_netlink *netlink;

	spinlock_t parc_lock;
	/* component for RAS DES counters */
	struct ipc_pcie_ras_des *ras_des;

	/* intel iommu flag */
	int iommu_enabled;

	/* doorbell irq# used for initiating time synchronization mechanism */
	int timesync_doorbell;

	/* GPIO handler */
	struct ipc_gpio_handler *gpio_handler;

	/* L2 test debugfs only for GPIO */
	struct ipc_debugfs_l2test *l2test_dbgfs;

	/* flags for the Power Management */
	unsigned long pm_flags;

};	/* struct ipc_pcie ends here. */

static int ipc_pcie_resources_request(struct ipc_pcie *this);
static void ipc_pcie_enable_device_caps(struct ipc_pcie *this);
static void ipc_pcie_config_aspm(struct ipc_pcie *this,
		struct pci_dev *pdev, bool enable);
static bool ipc_pcie_check_aspm_enabled(struct ipc_pcie *this,
		struct pci_dev *pdev);
static void ipc_pcie_resources_release(struct ipc_pcie *this);
static void ipc_pcie_dealloc(struct ipc_pcie **this);
static struct ipc_pcie *ipc_pcie_alloc(unsigned int instance_nr,
		struct ipc_netlink *netlink);

struct ipc_pcie_instance_map {
	char *slot_name; /* PCI Slot name */
	int index;
	struct list_head list; /* kernel's list structure */
};

/**
 * Fire the doorbell irq of CP
 */
static void ipc_doorbell_fire(struct ipc_pcie *this, int irq_n, u32 data)
{
	void __iomem *write_p_reg;

	if (unlikely(!this || !this->ipc_regs)) {
		ipc_err("invalid arguments");
		return;
	}

	/* Select the first doorbell register, which is only currently needed by
	 * CP.
	 */
	write_p_reg = IPC_DOORBELL_REG(this->ipc_regs,
					this->doorbell_write_ptr, irq_n,
					this->doorbell_reg_offset);

	/* Fire the doorbell irq by writing data on the doorbell write pointer
	 * register.
	 */
	iowrite32(data, write_p_reg);

#ifdef IPC_FASTSIM
	if (this->fastsim)
		ipc_fastsim_trigger_interrupt(this->fastsim,
			this->doorbell_write_ptr +
			this->doorbell_reg_offset * irq_n, data);
#endif
}				/* ipc_doorbell_fire */


/**
 * This is one IBIS ES0.5 fire doorbell workaround wrapper function
 */
static void ipc_doorbell_fire_with_capture(
		struct ipc_pcie *this, int irq_n, u32 data)
{
	void __iomem *write_p_reg;

	if (unlikely(!this || !this->ipc_regs)) {
		ipc_err("invalid arguments");
		return;
	}

	/* IBIS ES0.5 hardware has an issue in hardware, there is some delay
	 * updating capture register, due to which the value read from it
	 * is found to be zero. As a workaround update the capture register,
	 * before writing into write_reg.
	 */
	write_p_reg = IPC_DOORBELL_REG(this->ipc_regs,
					this->doorbell_capture_ptr,
					irq_n, this->doorbell_reg_offset);
	iowrite32(data, write_p_reg);

	/* fire the doorbell */
	ipc_doorbell_fire(this, irq_n, data);
}				/* ipc_doorbell_fire_with_capture */


/* Refer to header file for function description
 */
void ipc_cp_irq_rom(struct ipc_pcie *this, u32 data)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	ipc_dbg("0x%X", data);

	if (this->pci &&
			(this->pci->device == INTEL_CP_DEVICE_IBIS_ID))
		ipc_doorbell_fire_with_capture(this, 0, data);
	else
		ipc_doorbell_fire(this, 0, data);
}				/* ipc_cp_irq_rom */


/* Refer to header file for function description
 */
void ipc_cp_irq_ipc_control(struct ipc_pcie *this, u32 data)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	ipc_dbg("%d", data);
	ipc_doorbell_fire(this, IPC_DOORBELL_IRQ_IPC, data);
	this->ipc_irq_count++;
}				/* ipc_cp_irq_ipc_control */


/* Refer to header file for function description
 */
void ipc_cp_irq_sleep_control(struct ipc_pcie *this, u32 data)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	ipc_dbg("%d", data);
	ipc_doorbell_fire(this, IPC_DOORBELL_IRQ_SLEEP, data);
	this->slp_irq_count++;
}				/* ipc_cp_irq_sleep_control */


/* Refer to header file for function description
 */
void ipc_cp_irq_hpda_update(struct ipc_pcie *this, u32 data)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}

	ipc_dbg("%d", data);
	ipc_trc_ul_hpda_doorbell_fire(data);
	ipc_doorbell_fire(this, IPC_DOORBELL_IRQ_HPDA, data);
	this->hpu_irq_count++;
}				/* ipc_cp_irq_hpda_update */


/* Refer to header file for function description
 */
void ipc_cp_irq_time_sync(struct ipc_pcie *this, u32 data, u64 *timestamp,
		u32 *time_unit)
{
	unsigned long flags;
	ktime_t ktime;
	bool aspm_enabled;

	if (unlikely(!this || !timestamp || !time_unit)) {
		ipc_err("Invalid argument");
		return;
	}

	if (unlikely(this->timesync_doorbell < 0)) {
		ipc_err("timesync_doorbell not initialized");
		return;
	}

	/* check if ASPM is already disabled on the device.
	 * If it is disabled, then we don't disable and enable
	 * it again.
	 */
	aspm_enabled = ipc_pcie_check_aspm_enabled(this, this->pci);

	/* Disable only if enabled. */
	if (aspm_enabled)
		ipc_pcie_config_aspm(this, this->pci, false);

	ipc_dbg("timesync_doorbell=%d data=0x%08x",
		this->timesync_doorbell, data);

	/* make collection of timestamp and trigger of time sync irq
	 * uninterruptable
	 */
	local_irq_save(flags);

	ipc_doorbell_fire(this, this->timesync_doorbell, data);
	ktime = ktime_get();

	local_irq_restore(flags);

	/* Enable ASPM */
	if (aspm_enabled)
		ipc_pcie_config_aspm(this, this->pci, true);

	this->time_sync_irq_count++;

	*timestamp = ktime_to_ns(ktime);
	*time_unit = IPC_NANO_SEC;
}


/**
 * Function to get the 64-bit MSI address.
 *
 * @this: pointer to pci device structure.
 * @p_msi_addr: pointer to get the MSI address.
 *
 * returns 0 on Success, non-zero on Failure.
 */
static int ipc_pcie_get_msi_address(struct ipc_pcie *this, u64 *p_msi_addr)
{
	u32 msi_addr_lo = 0, msi_addr_hi = 0;
	int ret_val = -1;

	if (unlikely(!this || !p_msi_addr)) {
		ipc_err("Invalid parameters");
		return -1;
	}

	/* Check if MSI is enabled
	 */
	if (this->pci->msi_enabled) {
		int offset = 0;

		ipc_dbg("MSI CAP offset: 0x%x", this->pci->msi_cap);

		offset = this->pci->msi_cap + PCI_MSI_ADDRESS_LO;
		ret_val = ipc_pcie_config_read32(this, offset, &msi_addr_lo);

		offset = this->pci->msi_cap + PCI_MSI_ADDRESS_HI;
		ret_val |= ipc_pcie_config_read32(this, offset, &msi_addr_hi);

		*p_msi_addr = msi_addr_hi;
		*p_msi_addr = (*p_msi_addr << 32) | msi_addr_lo;
	}
	return ret_val;
}


/**
 * Function to get the 64-bit MSI-X entry address.
 *
 * @this: pointer to pci device structure
 * @p_msix_addr: pointer to get the MSI-X table address.
 * @entry_nr: MSI-X entry number
 *
 * return 0 on success, non-zero on failure.
 */
static int ipc_pcie_get_msix_address(struct ipc_pcie *this, u64 *p_msix_addr,
					int entry_nr)
{
	struct msi_desc *entry = NULL;
	int i = 0;
	int ret = -1;

	if (unlikely(!this || !p_msix_addr)) {
		ipc_err("Invalid parameters");
		return ret;
	}

	/*
	 * Check if MSI-X is enabled
	 */
	if (!this->pci->msix_enabled)
		return ret;

#if (KERNEL_VERSION(3, 19, 0) <= LINUX_VERSION_CODE)
	for_each_pci_msi_entry(entry, this->pci) {
#else
	list_for_each_entry(entry, &this->pci->msi_list, list) {
#endif
		if (entry->irq) {
			for (i = 0; i < entry->nvec_used; i++) {
				void __iomem *base;
				u32 addr_lo, addr_hi;

				/* Check if MSI-X */
				if (!entry->msi_attrib.is_msix)
					continue;

				/* Check if this is requested MSI-X entry
				 * for which address reading is required.
				 */
				if (entry_nr != entry->msi_attrib.entry_nr)
					continue;
				base = entry->mask_base +
						entry->msi_attrib.entry_nr
						* PCI_MSIX_ENTRY_SIZE;
				ipc_dbg("MSI-X table entry %d, offset %p",
						entry->nvec_used, base);
				addr_lo = ioread32(base +
						PCI_MSIX_ENTRY_LOWER_ADDR);
				addr_hi = ioread32(base +
						PCI_MSIX_ENTRY_UPPER_ADDR);
				*p_msix_addr = ((u64)addr_hi << 32) | addr_lo;
				ret = 0;
			}
		}
	}
	return ret;
}


/**
 * The MSI interrupt handler is still called in hard interrupt
 * context. ipc_irq_handler is called when the IRQ occurs.
 */
static irqreturn_t ipc_irq_handler(int irq, void *dev_id)
{
	return IRQ_WAKE_THREAD;
}				/* ipc_irq_hanlder */

/**
 * Threaded Interrupt handler for MSI interrupts
 */
static irqreturn_t ipc_msi_interrupt(int irq, void *dev_id)
{
	struct ipc_pcie *this = dev_id;
	int instance;

	/* Check if a valid pcie pointer. */
	if (unlikely(!this))
		return IRQ_NONE;

	instance = irq - this->pci->irq;
	if (instance >= this->nvec) {
		ipc_dbg("MSI %d not for our device", instance);
		return IRQ_NONE;
	}

	this->ap_msi_irq_count[instance]++;

	/* Shift the MSI irq actions to the IPC tasklet.
	 * IRQ_NONE means the irq was not from the IPC device or
	 * could not be served.
	 */
	ipc_dbg("MSI %d", instance);
	ipc_imem_irq_process(this->imem, instance);

	/* The MSI irq was processed.
	 */
	return IRQ_HANDLED;
}				/* ipc_msi_interrupt */


/**
 * Threaded Interrupt handler for MSI-X interrupts
 */
static irqreturn_t ipc_msix_interrupt(int irq, void *dev_id)
{
	struct ipc_pcie *this = dev_id;
	int i = 0;

	/* Check if a valid pcie pointer. */
	if (unlikely(!this))
		return IRQ_NONE;

	for (i = 0; i < this->msix_nvec; i++)
		if (this->msix[i].vector == irq)
			break;

	if (i >= this->msix_nvec) {
		ipc_dbg("MSI-X %d not for our device", i);
		return IRQ_NONE;
	}

	this->ap_msix_irq_count[this->msix[i].entry]++;

	/* Shift the MSI irq actions to the IPC tasklet.
	 * IRQ_NONE means the irq was not from the IPC device or
	 * could not be served.
	 */
	ipc_dbg("MSI-X %d", this->msix[i].entry);
	ipc_imem_irq_process(this->imem, this->msix[i].entry);

	/* The MSI irq was processed.
	 */
	return IRQ_HANDLED;
}				/* ipc_msix_interrupt */


/**
 * NOTE: https://www.kernel.org/doc/Documentation/PCI/MSI-HOWTO.txt
 * Suggests pci_enable_msi() and pci_enable_msix_range() should
 * not used as they will be deprecated and rather use
 * pci_alloc_irq_vectors().
 * As pci_alloc_irq_vectors() is introduced only after kernel version
 * v4.9, to work with current distributions we need to still use
 * pci_enable_msi() and pci_enable_msix_range().
 */

/**
 * request MSI interrupt
 */
static int ipc_setup_msi_interrupt(struct ipc_pcie *this)
{
	struct pci_dev *pci = this->pci;
	int rc;
	int i, j;

	/* Configure MSI capability structure of the device.
	 * Enable only first MSI
	 */
	this->nvec = IPC_MSI_VECTORS;
	rc = pci_enable_msi(pci);
	if (rc) {
		ipc_dbg("enabling the MSI vector failed (rc=%d) !", rc);
		goto enable_msi_fail;
	}

	/* Allocate interrupt resources for MSI irq and enable the
	 * interrupt and IRQ handling.
	 */
	if (pci->msi_enabled) {
		for (i = 0; i < this->nvec; ++i) {
			rc = request_threaded_irq(pci->irq + i,
					ipc_irq_handler, ipc_msi_interrupt, 0,
					KBUILD_MODNAME, this);
			if (rc) {
				ipc_err("unable to grab IRQ %d, rc=%d",
					pci->irq, rc);
				goto irq_alloc_fail;
			}
		}
	}

	return 0;

irq_alloc_fail:
	/* Free the allocated IRQ. */
	for (j = 0; j < i; j++)
		free_irq(pci->irq + j, this);
	pci_disable_msi(pci);
enable_msi_fail:
	return -1;
}

/**
 * reqeust MSI-X interrupt
 */
static int ipc_setup_msix_interrupt(struct ipc_pcie *this)
{
	struct pci_dev *pci = this->pci;
	int rc, i, j;

	this->msix_nvec = IPC_MSIX_VECTORS;
	for (i = IPC_MSIX_FIRST_ENTRY; i < this->msix_nvec; i++)
		this->msix[i].entry = IPC_MSIX_ENTRY(i);

	/* Enable first MSI-X. Currently CP uses only first MSI-X Vector
	 * so no need to enable all the MSI-X vectors.
	 */
	rc = pci_enable_msix_range(this->pci, this->msix,
				IPC_MSIX_VECTORS, IPC_MSIX_VECTORS);
	if (rc < 0) {
		ipc_dbg("No MSI-X irq allocated %d", rc);
		goto range_enable_fail;
	}

	/* Allocate interrupt resources for MSI-X irq and enable the
	 * interrupt and IRQ handling
	 */
	if (pci->msix_enabled) {
		for (i = 0; i < this->msix_nvec; ++i) {
			rc = request_threaded_irq(this->msix[i].vector,
					ipc_irq_handler, ipc_msix_interrupt, 0,
					KBUILD_MODNAME, this);
			if (rc) {
				ipc_err("unable to grab IRQ %d, rc=%d",
					this->msix[i].vector, rc);
				goto irq_alloc_fail;
			}
		}
	}

	return 0;

irq_alloc_fail:
	/* Free the allocated IRQ. */
	for (j = 0; j < i; j++)
		free_irq(this->msix[j].vector, this);
	pci_disable_msix(pci);
range_enable_fail:
	return -1;
}

/* Remove the IRQ handler */
static void ipc_release_irq(struct ipc_pcie *this)
{
	struct pci_dev *pci = this->pci;
	int i;

	if (pci->msix_enabled) {
		for (i = 0; i < this->msix_nvec; i++)
			free_irq(this->msix[i].vector, this);
		pci_disable_msix(pci);
	} else if (pci->msi_enabled) {
		for (i = 0; i < this->nvec; i++)
			free_irq(pci->irq + i, this);
		pci_disable_msi(pci);
	}
}

/**
 * Install the IPC irq handler.
 */
static int ipc_acquire_irq(struct ipc_pcie *this)
{
	struct pci_dev *pci = this->pci;

	this->is_irq_requested = 0;
	/* Try to enable MSI-X and if it can't then try to enable MSI */
	if (ipc_setup_msix_interrupt(this))
		if (ipc_setup_msi_interrupt(this))
			return -1;
	/* return if MSI and MSIX both are failed to be enabled */
	if (!pci->msi_enabled && !pci->msix_enabled) {
		ipc_err("MSI or MSI-X enable failed");
		return -1;
	}
	this->is_irq_requested = 1;
	return 0;
}				/* ipc_acquire_irq */


/* Free the PCI resources.
 */
static void ipc_cleanup(struct ipc_pcie *this)
{
	struct pci_dev *pci;

	if (unlikely(!this || !this->pci)) {
		ipc_err("pcie pointer is NULL");
		return;
	}

	pci = this->pci;

	ipc_dbg("execute the IPC cleanup operations");

	/* if PCIe device was in D3Cold then we need to resume it */
	if (test_and_clear_bit(IPC_SUSPENDED, &this->pm_flags))
		ipc_gpio_handler_resume(this->gpio_handler);

	/* Activate the PCIe device.
	 */
	if (pci->current_state != PCI_D0) {
		if (pci_enable_device(pci)) {
			ipc_err("failed to enable the AP PCIe device");
			return;
		}
	}

	/**
	 * if Link down was received then disable ASPM on Root port,
	 * earlier, Normally kernel does that after removing the device
	 * entry by calling pcie_aspm_exit_link_state(), which sometimes
	 * generates a race with the Link up event if it comes quickly.
	 * In that case, BIOS SMI is triggered which enables ASPM while
	 * kernel processing Link down disables ASPM. Race is seen
	 * in a way that root port ASPM gets disabled but Device ASPM
	 * stays enabled and this can cause unexpected Link down.
	 * (this causes undefined behaviour as per
	 * PCIe Base Specification 3-0 Chapter 5.4.3.1 - ASPM configuration)
	 * So disabling ASPM early stage of Link down we can be sure
	 * that kernel will not re-disable it as per pcie_aspm_exit_link_state()
	 * implementation.
	 */
	if (!ipc_pcie_check_data_link_active(this)) {
		pci_disable_link_state(this->pci, PCI_EXP_LNKCTL_ASPM_L1 |
					PCI_EXP_LNKCTL_ASPM_L0S);
	}

	/* Free the shared memory resources.
	 */
	ipc_imem_cleanup(this->imem);

	/* uevent cleanup */
	ipc_uevent_dealloc(&this->uevent);

	/* RAS DES cleanup */
	ipc_pcie_ras_des_dealloc(&this->ras_des);

	/* remove debugfs
	 */
	ipc_debugfs_dealloc(&(this->root_dbgfs));

	/* Disable bus-mastering for the device.
	 */
	if (this->is_master)
		pci_clear_master(pci);

	this->is_master = 0;

	/* Free the MSI resources.
	 */
	ipc_dbg("free the MSI and irq resources");

	/* Free the interrupt allocated with request_irq.
	 */
	if (pci->msix_enabled) {
		if (this->is_irq_requested) {
			int i;

			for (i = 0; i < this->msix_nvec; i++)
				free_irq(this->msix[i].vector, this);
		}
		pci_disable_msix(pci);
	} else if (pci->msi_enabled) {
		if (this->is_irq_requested) {
			int i;

			for (i = 0; i < this->nvec; i++)
				free_irq(pci->irq + i, this);
		}
		pci_disable_msi(pci);
	}

	this->is_irq_requested = 0;
	ipc_dbg("unmap the IPC registers and the doorbell scratchpad");

	/* Free mapped doorbell scratchpad bus memory into CPU space.
	 */
	if (this->scratchpad)
		iounmap(this->scratchpad);

	/* Free mapped IPC_REGS bus memory into CPU space.
	 */
	if (this->ipc_regs)
		iounmap(this->ipc_regs);

	/* Release reserved PCI I/O and memory resources.
	 * Releases all PCI I/O and memory resources previously reserved by a
	 * successful call to pci_request_regions.  Call this function only
	 * after all use of the PCI regions has ceased.
	 */
	if (this->pci_regions_requested)
		pci_release_regions(pci);

	this->pci_regions_requested = 0;

	ipc_dbg("disable the PCI device and I/O and memory resources");

	/* Signal to the system that the PCI device is not in use.
	 */
	if (this->pci)
		pci_disable_device(pci);

	ipc_dbg("cleanup done.");

	/* dbg cleanup */
	ipc_dbg_dealloc(&this->dbg);
}				/* ipc_cleanup */
/* Free the IMC IPC resources.
 */
static void imc_ipc_remove(struct pci_dev *pci)
{
	/* Prepare the use of many CP.
	 */
	struct ipc_pcie *this = pci_get_drvdata(pci);

	if (unlikely(!this)) {
		ipc_err("pcie pointer is NULL");
		return;
	}

	ipc_dbg("-------------------- remove ------------------");

	/* Validate the pointer to the PCI description.
	 */
	if (this->pci && this->pci != pci) {
		ipc_err("PCI dev  mismatch: this->pci(%p) != pci(%p)",
			this->pci, pci);
		return;
	}
#ifdef IPC_GPIO_MDM_CTRL
	ipc_pcie_destroy_l2test_dealloc(this->l2test_dbgfs);
#endif
	ipc_pcie_parc_dealloc(&(this->pcie_parc));

	/* Set the driver specific data. */
	pci_set_drvdata(pci, NULL);

	/* Free the PCI and kthread resources.
	 */
	ipc_cleanup(this);

	/* De-allocate PCIe */
	pci_set_drvdata(pci, NULL);
	ipc_pcie_dealloc(&this);

	ipc_pr_dbg("-------------------- BYE BYE -----------------");
}				/* imc_ipc_remove */


/* Write back the BAR0-3 register values physically.
 * Needed during the developement phase. The BAR0-3 addresses are asigned by
 * the host and are visible on the CP EP. On CP BAR0-1 are linked to the IPC
 * irq regs about the internal translation unit - iATS and BAR2-3 are linked
 * to the doorbell scratchpad. If CP is reset, on CP BAR0-3 are lost, therefore
 * BAR refresh is needed.
 */
static void ipc_pci_bar_refresh(struct ipc_pcie *this)
{
/* Use CONFIG_X86 to disable when ARM Cross compiler used for VP */
#if defined(IPC_DEVEL_MODE) && defined(CONFIG_X86)
	struct pci_dev *pci = this->pci;
	int i;
	u32 val;

	ipc_dbg("refresh BAR0-3");

	for (i = 0; i < 4; i++) {
		val = pci_resource_start(pci, i);

		ipc_dbg("pci_write_config_dword = 0x%X", val);

		/* 0x10 is the configuration offset for BAR0 and the register
		 * size is 4 bytes.
		 */
		pci_write_config_dword(pci, 0x10 + i * 4, val);
	}
#endif				/* IPC_DEVEL_MODE && CONFIG_X86 */
}				/* ipc_pci_bar_refresh */

/* Release all acquired resources */
static void ipc_pcie_resources_release(struct ipc_pcie *this)
{
	if (unlikely(!this)) {
		ipc_err("invalid args");
		return;
	}

	/* Free the MSI resources. */
	ipc_dbg("free the MSI and irq resources");
	ipc_release_irq(this);

	ipc_dbg("unmap the IPC registers and the doorbell scratchpad");

	/* Free mapped doorbell scratchpad bus memory into CPU space. */
	iounmap(this->scratchpad);
	this->scratchpad = NULL;

	/* Free mapped IPC_REGS bus memory into CPU space. */
	iounmap(this->ipc_regs);
	this->ipc_regs = NULL;

	/* Release reserved PCI I/O and memory resources.
	 * Releases all PCI I/O and memory resources previously reserved by a
	 * successful call to pci_request_regions.  Call this function only
	 * after all use of the PCI regions has ceased.
	 */
	pci_release_regions(this->pci);
}

/* Request the PCIe resources.
 */
static int ipc_pcie_resources_request(struct ipc_pcie *this)
{
	struct pci_dev *pci;

	/* Pointer to PCIe devices state.
	 */
	pci = this->pci;

	/* Reserved PCI I/O and memory resources.
	 * Mark all PCI regions associated with PCI device pci as
	 * being reserved by owner IMC_IPC.  Do not access any
	 * address inside the PCI regions unless this call returns
	 * successfully.
	 */
	if (pci_request_regions(pci, "IMC_IPC")) {
		ipc_err("failed pci request regions");
		goto pci_request_region_fail;
	}

	this->pci_regions_requested = 1;

	/* Write back the BAR0-3 register values physically.
	 * Needed during the developement phase.
	 */
	ipc_pci_bar_refresh(this);

	/* Print the physical start address of the IPC_REGS from BAR 0,
	 * which is assigned by AP and linked to the IPC doorbell
	 * interrupt register about the EP PCI controller. CP publishes
	 * the irq region as inbound.
	 */
	ipc_dbg("CP doorbell IPC REGS address=0x%X",
		 (u32) pci_resource_start(pci, this->ipc_regs_bar_nr));

	/* Reserve the doorbell IPC REGS memory resources.
	 * Remap the memory into CPU space. Arrange for the physical address
	 * (BAR) to be visible from this driver.
	 * pci_ioremap_bar() ensures that the memory is marked uncachable.
	 */
	this->ipc_regs = pci_ioremap_bar(pci, this->ipc_regs_bar_nr);

	if (unlikely(!this->ipc_regs)) {
		ipc_err("IPC REGS ioremap error");
		goto ipc_regs_remap_fail;
	}

	/* Print the physical start address of the doorbell scratchpad
	 * from IPC BAR 2, which is assigned by AP and linked to the IPC
	 * doorbell scratchpad about the EP PCI controller. CP publishes
	 * the scratchbad as inbound.
	 */
	ipc_dbg("CP doorbell scratchpad address=0x%X",
		 (u32) pci_resource_start(pci, this->scratchpad_bar_nr));


	/* Reserve the MMIO scratchpad memory resources.
	 * Remap the memory into CPU space. Arrange for the physical address
	 * (BAR) to be visible from this driver.
	 * pci_ioremap_bar() ensures that the memory is marked uncachable.
	 */
	this->scratchpad = pci_ioremap_bar(pci, this->scratchpad_bar_nr);

	if (unlikely(!this->scratchpad)) {
		ipc_err("doorbell scratchpad ioremap error");
		goto scratch_remap_fail;
	}
	/* Install the irq handler triggered by CP.
	 */
	if (ipc_acquire_irq(this)) {
		ipc_err("acquiring MSI irq failed!");
		goto irq_acquire_fail;
	}

	/* Enable bus-mastering for the IMC IPC device.
	 */
	pci_set_master(pci);

	/* Enable device capabilities
	 */
	ipc_pcie_enable_device_caps(this);

	ipc_dbg("link between AP and CP is fully on");

	return 0;

irq_acquire_fail:
	iounmap(this->scratchpad);
	this->scratchpad = NULL;
scratch_remap_fail:
	iounmap(this->ipc_regs);
	this->ipc_regs = NULL;
ipc_regs_remap_fail:
	pci_release_regions(pci);
pci_request_region_fail:
	return -1;
}				/* ipc_pcie_resources_request */

/**
 * Check if ASPM L1 is already enabled
 *
 * @this: pointer to the core driver data-struct
 * @pdev: pointer to pci device structure
 *
 * returns true if ASPM is already enabled else false
 */
static bool ipc_pcie_check_aspm_enabled(struct ipc_pcie *this,
			struct pci_dev *pdev)
{
	u32 enabled = 0;
	u16 value = 0;

	if (this && pdev) {
		pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &value);
		enabled = value & PCI_EXP_LNKCTL_ASPMC;
		ipc_dbg("ASPM L1: 0x%04X 0x%03X", pdev->device, value);
		if (enabled == PCI_EXP_LNKCTL_ASPM_L1
		|| enabled == PCI_EXP_LNKCTL_ASPMC) {
			return true;
		}
	}

	return false;
}

/**
 * Check Data Link Layer Active
 */
bool ipc_pcie_check_data_link_active(struct ipc_pcie *this)
{
	u16 link_status = 0;
	bool ret;
	struct pci_dev *parent = NULL;

	if (!this || !this->pci) {
		ipc_dbg("device not found");
		return false;
	}


	if (!this->pci->bus || !this->pci->bus->self) {
		ipc_err("root port not found");
		return false;
	}

	parent = this->pci->bus->self;

	pcie_capability_read_word(parent, PCI_EXP_LNKSTA, &link_status);
	ret = !!(link_status & PCI_EXP_LNKSTA_DLLLA);
	ipc_dbg("Link status: 0x%04X", link_status);
	return ret;
}

struct pci_dev *ipc_pci_get_pci_dev(struct ipc_pcie *this)
{

	return this->pci;
}

/**
 * Check if ASPM L1 is supported or not
 *
 * @this: pointer to the core driver data-struct
 * @pdev: pointer to pci device structure
 * returns true if ASPM is supported by device else false
 */
static bool ipc_pcie_check_aspm_supported(struct ipc_pcie *this,
			struct pci_dev *pdev)
{
	u32 support = 0;
	u32 cap = 0;

	pcie_capability_read_dword(pdev, PCI_EXP_LNKCAP, &cap);
	support = (cap & PCI_EXP_LNKCAP_ASPMS) >> 10;
	if (support < PCIE_ASPM_L1_SUPPORTED) {
		ipc_dbg("ASPM L1 not supported: 0x%04X", pdev->device);
		return false;
	}
	return true;
}

/*
 * Configure PCIe link control register to enable / disable ASPM
 *
 * @this: pointer to the core driver data-struct
 * @pdev: pci device
 * @enable: True-enable, False-disable
 */
static void ipc_pcie_write_aspm_reg(struct ipc_pcie *this,
			struct pci_dev *pdev, bool enable)
{
	u16 value = enable ? PCI_EXP_LNKCTL_ASPM_L1 : 0;

	pcie_capability_clear_and_set_word(pdev, PCI_EXP_LNKCTL,
				PCI_EXP_LNKCTL_ASPMC, value);

	ipc_dbg("ASPM force %s for 0x%04X device",
			enable ? "enabled" : "disabled", pdev->device);
}

/*
 * Enable / disable ASPM on all child devices of a parent.
 *
 * @this: pointer to the core driver data-struct
 * @parent: parent device
 * @enable: True-enable, False-disable
 */
static void ipc_pcie_child_config_aspm(struct ipc_pcie *this,
			struct pci_dev *parent, bool enable)
{
	struct pci_bus *linkbus = parent->subordinate;
	struct pci_dev *child = NULL;

	if (!linkbus) {
		ipc_err("no link to pci bus");
		return;
	}

	/* Loop through all child nodes */
	list_for_each_entry(child, &linkbus->devices, bus_list)
		ipc_pcie_write_aspm_reg(this, child, enable);
}

/*
 * Configure ASPM L1
 *
 * @this: pointer to the core driver data-struct
 * @pdev: pointer to pci device structure
 * @enable: Enable ASPM if true, otherwise disable ASPM
 */
static void ipc_pcie_config_aspm(struct ipc_pcie *this,
			struct pci_dev *pdev, bool enable)
{
	struct pci_dev *parent = NULL;
	bool parent_aspm_enabled, dev_aspm_enabled;


	if (!pdev) {
		ipc_err("no such device");
		return;
	}
	if (!pci_is_pcie(pdev)) {
		ipc_err("not a PCIe device");
		return;
	}

	if (!pdev->bus || !pdev->bus->self) {
		ipc_err("root port not found");
		return;
	}

	parent = pdev->bus->self;

	/* check if both root port and child supports ASPM L1 */
	if (!ipc_pcie_check_aspm_supported(this, parent)
	|| !ipc_pcie_check_aspm_supported(this, pdev))
		return;

	parent_aspm_enabled = ipc_pcie_check_aspm_enabled(this, parent);
	dev_aspm_enabled = ipc_pcie_check_aspm_enabled(this, pdev);

	ipc_dbg("ASPM parent: %s device: %s",
			parent_aspm_enabled ? "Enabled" : "Disabled",
			dev_aspm_enabled ? "Enabled" : "Disabled");

	if (enable) {
		/*
		 * Check if ASPM L1 is already enabled on Root port and child,
		 * if on one of them is disabled then enable it on Both again
		 */
		if (parent_aspm_enabled && dev_aspm_enabled)
			return;

		/*
		 * Spec 2.0 suggests all functions should be configured the
		 * same setting for ASPM. Enabling ASPM L1 should be done in
		 * upstream component first and then downstream.
		 */

		/* Enable ASPM of parent */
		ipc_pcie_write_aspm_reg(this, parent, true);

		/* Enable ASPM of all child devices */
		ipc_pcie_child_config_aspm(this, parent, true);

	} else {
		/*
		 * Check if ASPM L1 is already disabled on Root port and child,
		 * if on one of them is enabled then disable it on Both again
		 */
		if (!parent_aspm_enabled && !dev_aspm_enabled)
			return;

		/*
		 * Spec 2.0 suggests all functions should be configured the
		 * same setting for ASPM. Disabling ASPM L1 should be done in
		 * downstream component first and then upstream.
		 */

		/* Disable ASPM of all child devices */
		ipc_pcie_child_config_aspm(this, parent, false);

		/* Disable ASPM of parent */
		ipc_pcie_write_aspm_reg(this, parent, false);
	}
}

/*
 * Function initializes PCIe endpoint configuration
 */
static void ipc_pcie_config_init(struct ipc_pcie *this, unsigned int device)
{
	/* BAR0 is used for doorbell */
	this->ipc_regs_bar_nr = IPC_DOORBELL_BAR0;

	/* update HW configuration */
	switch (device) {
	case INTEL_CP_DEVICE_7660_ID:
		this->scratchpad_bar_nr = IPC_SCRATCHPAD_BAR1;
		this->doorbell_reg_offset = IPC_DOORBELL_CH_OFFSET_7660;
		this->doorbell_write_ptr = IPC_WRITE_PTR_REG_0_7660;
		this->doorbell_capture_ptr = IPC_CAPTURE_PTR_REG_0_7660;
		this->timesync_doorbell = IPC_DOORBELL_IRQ_TIME_SYNC;

		break;
	case INTEL_CP_DEVICE_8060_ID:
		this->scratchpad_bar_nr = IPC_SCRATCHPAD_BAR1;
		this->doorbell_reg_offset = IPC_DOORBELL_CH_OFFSET_8060;
		this->doorbell_write_ptr = IPC_WRITE_PTR_REG_0_8060;
		this->doorbell_capture_ptr = IPC_CAPTURE_PTR_REG_0_8060;
		this->timesync_doorbell = IPC_DOORBELL_IRQ_TIME_SYNC;
		break;
	default:
		this->scratchpad_bar_nr = IPC_SCRATCHPAD_BAR2;
		this->doorbell_reg_offset = IPC_DOORBELL_CH_OFFSET;
		this->doorbell_write_ptr = IPC_WRITE_PTR_REG_0;
		this->doorbell_capture_ptr = IPC_CAPTURE_PTR_REG_0;
		this->timesync_doorbell = IPC_DOORBELL_IRQ_TIME_SYNC_LEGACY;
		break;
	}

}

static int imc_ipc_get_instance(const char *slot_name)
{
	struct ipc_pcie_instance_map *tmp;
	int max_index = -1;
	int len;

	/* Search for the instance index. */
	list_for_each_entry(tmp, &ipc_pcie_mdm_list, list) {

		/* Save max index. */
		max_index = (tmp->index > max_index) ? tmp->index : max_index;

		if (strcmp(tmp->slot_name, slot_name) == 0)
			return tmp->index;
	}

	/* Not found, allocate a new index. */
	tmp = ipc_util_kzalloc(sizeof(struct ipc_pcie_instance_map));
	if (!tmp)
		return -1;

	len = strlen(slot_name) + 1;
	tmp->slot_name = ipc_util_kzalloc(len);

	if (!tmp->slot_name) {
		ipc_util_kfree(tmp);
		return -1;
	}

	strncpy(tmp->slot_name, slot_name, len);

	tmp->index = ++max_index;

	/* Add to list */
	list_add_tail(&tmp->list, &ipc_pcie_mdm_list);

	return max_index;
}

/* The PCI bus has recognized the IMC IPC device and invokes
 * imc_ipc_probe with the assigned resources. pci_id contains
 * the identification, which need not be verified.
 */
static int imc_ipc_probe(struct pci_dev *pci,
			 const struct pci_device_id *pci_id)
{
	struct ipc_pcie *this = NULL;
	int instance_index;
	const char *slot_name = dev_name(&pci->dev);

	ipc_pr_dbg("-------------------- probe -----------------");
	ipc_pr_dbg("%s", ipc_imem_version());
	ipc_pr_dbg("probe the device 0x%X from the vendor 0x%X slot:%s",
		 pci_id->device, pci_id->vendor, slot_name);

	instance_index = imc_ipc_get_instance(slot_name);
	if (instance_index < 0) {
		ipc_err("Failed to get instance index.");
		goto ret_fail;
	}

	ipc_pr_dbg("instance allocated: %d", instance_index);

	this = ipc_pcie_alloc(instance_index, ipc_pcie_netlink);
	if  (!this) {
		ipc_err("Failed to allocated PCIe.");
		goto ret_fail;
	}

	/* Initialize ipc dbg component for the PCIe device
	 */
	this->dbg = ipc_dbg_alloc(&pci->dev);
	if (!this->dbg) {
		ipc_err("dbg allocation failed");
		goto dbg_fail;
	}

	/* Set the driver specific data. */
	pci_set_drvdata(pci, this);

	/* Save the address of the PCI device configuration.
	 */
	this->pci = pci;

	/* Update platform configuration
	 */
	ipc_pcie_config_init(this, pci->device);

	/* Check if intel iommu is supported */
#ifdef CONFIG_X86
	this->iommu_enabled = intel_iommu_enabled;
#else
	this->iommu_enabled = 0;
#endif

	ipc_dbg("iommu_enabled = %d", this->iommu_enabled);

	/* Initialize the device before it is used. Ask low-level code
	 * to enable I/O and memory. Wake up the device if it was suspended.
	 */
	if (pci_enable_device(pci)) {

		ipc_err("failed to enable the AP PCIe device");
		/* If enable of PCIe device has failed then calling ipc_cleanup
		 * will panic the system. More over ipc_cleanup() is required to
		 * be called after ipc_imem_mount()
		 */
		goto pci_enable_fail;
	}

	/* Reset the address ranges before any allocations
	 */
	ipc_util_reset_addr_range(&this->ranges[IPC_PCIE_SKB_MEM]);
	ipc_util_reset_addr_range(&this->ranges[IPC_PCIE_DYNAMIC_MEM]);

	ipc_pcie_config_aspm(this, pci, true);
	ipc_dbg("PCIe device enabled.");

	/* Print the power state.
	 */
	ipc_dbg("initial power state: %d=%s",
		 pci->current_state, pci_power_name(pci->current_state));

	/* Request the PCIe resources.
	 */
	if (ipc_pcie_resources_request(this))
		goto resources_req_fail;

	/* Initialize root debugfs component for the PCIe device
	 */
	this->root_dbgfs = ipc_debugfs_alloc(instance_index, this->dbg);
	if (!this->root_dbgfs)
		ipc_dbg("no debugfs allocated");

	/* Allocate IPC uevent */
	this->uevent = ipc_uevent_alloc(instance_index,
					this->root_dbgfs, this->dbg);
	if (unlikely(!this->uevent)) {
		ipc_err("uevent allocation failed");
		goto uevent_alloc_fail;
	}

	this->pcie_parc = ipc_pcie_parc_alloc(this,
					this->root_dbgfs, this->dbg);

	/* allocated RAS DES counters component */
	this->ras_des = ipc_pcie_ras_des_alloc(this, this->root_dbgfs,
			this->dbg);

	/* Find PARC VSEC
	 */
	if (this->pcie_parc) {
		u64 addr = 0;

		/**
		 * if MSI is enabled then will get a valid address
		 * and DW window should be configured.
		 */
		if (!ipc_pcie_get_msi_address(this, &addr)) {

			/* Configure the MSI address using DW window.
			 */
			ipc_pcie_parc_configure_dw_window(this->pcie_parc,
						PARC_WIN_DW_0, addr);
		}
		/* read the first MSI-X entry */
		if (!ipc_pcie_get_msix_address(this, &addr,
						IPC_MSIX_FIRST_ENTRY)) {

			/* Configure the MSI-X address using DW window.
			 */
			ipc_pcie_parc_configure_dw_window(this->pcie_parc,
						PARC_WIN_DW_1, addr);
		}

		ipc_pcie_parc_enable(this->pcie_parc);
	} else {
		ipc_dbg("PARC not supported!");
	}

	/* Establish the link to the imem layer.
	 */

	this->imem = ipc_imem_alloc();
	if (unlikely(!this->imem)) {
		ipc_err("imem allocation failed");
		goto imem_alloc_fail;
	}


	if (ipc_imem_mount(this->imem, &pci->dev, this, pci->device,
			this->root_dbgfs, this->scratchpad,
			instance_index, this->dbg)) {
		ipc_err("failed to execute ipc_imem_mount()");
		goto imem_mount_fail;
	}

	clear_bit(IPC_SUSPENDED, &this->pm_flags);

#ifdef IPC_GPIO_MDM_CTRL
	this->l2test_dbgfs = ipc_debugfs_l2test_alloc(this->root_dbgfs, this,
			this->dbg);
#endif
	return 0;		/* OK, init done */

imem_mount_fail:
	ipc_imem_dealloc(&this->imem);
imem_alloc_fail:
	ipc_pcie_ras_des_dealloc(&this->ras_des);
	ipc_pcie_parc_dealloc(&(this->pcie_parc));
	ipc_uevent_dealloc(&(this->uevent));
uevent_alloc_fail:
	ipc_debugfs_dealloc(&(this->root_dbgfs));
	ipc_pcie_resources_release(this);
resources_req_fail:
	pci_disable_device(pci);
pci_enable_fail:
	this->pci = NULL;
	ipc_dbg_dealloc(&this->dbg);
dbg_fail:
	ipc_pcie_dealloc(&this);
ret_fail:
	return -1;		/* ERROR: insmod:-1 Operation not permitted */
}				/* imc_ipc_probe */

/* Enable PCIe device capabilities
 */
static void ipc_pcie_enable_device_caps(struct ipc_pcie *this)
{
	u32 cap;

	/* Enable LTR if possible
	 * This is needed for L1.2!
	 */
	pcie_capability_read_dword(this->pci, PCI_EXP_DEVCAP2, &cap);
	if (cap & PCI_EXP_DEVCAP2_LTR)
		pcie_capability_set_word(this->pci, PCI_EXP_DEVCTL2,
					 PCI_EXP_DEVCTL2_LTR_EN);
}				/* ipc_pcie_enable_device_caps */

/* PCI IDs
 */
/* The IMC IPC driver waits for a device with the
 * device identifier INTEL_CP_DEVICE_ID from the
 * vendor INTEL_VENDOR_ID.
 */
const struct pci_device_id imc_ipc_ids_imc[] = {
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_7360_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_7460_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_7480_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_7560_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_7660_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_IBIS_ID) },
	{ PCI_DEVICE(INTEL_VENDOR_ID, INTEL_CP_DEVICE_8060_ID) },
	{ } /* end of list */
};

#ifdef CONFIG_PM

/* Callback invoked by pm_runtime_suspend: entry point for runtime put/suspend
 * operations. It decrements the device's usage count and return immediately if
 * it is larger than zero. Then carry out a suspend, either synchronous or
 * asynchronous.
 */
int imc_ipc_suspend(struct device *dev)
{
	struct pci_dev *pdev;
	int rc;
	/* To compliance with the ipc_dbg logging module design.
	 */
	struct ipc_pcie *this = NULL;

	ipc_pr_dbg("");
	if (IS_ERR_OR_NULL(dev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Get the reference to the device description.
	 */
	pdev = to_pci_dev(dev);
	if (IS_ERR_OR_NULL(pdev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Execute D3 one time.
	 */
	if (pdev->current_state != PCI_D0) {
		ipc_pr_dbg("done for PM=%d", pdev->current_state);
		return 0;
	}

	this = pci_get_drvdata(pdev);
	if (unlikely(!this)) {
		ipc_err("pcie pointer is NULL");
		return -ENODEV;
	}

	/* The HAL shall ask the shared memory layer whether D3 is allowed.
	 */
	if (ipc_imem_pm_suspend(this->imem)) {
		ipc_dbg("try again");
		return -EAGAIN;
	}

	/* Save the PCI configuration space of a device before suspending.
	 */
	rc = pci_save_state(pdev);

	if (rc) {
		ipc_err("pci_save_state error=%d", rc);
		return -EAGAIN;
	}

	/* Save the Vendor Specific Extended Capability if supported.
	 */
	ipc_pcie_parc_save_cap(this->pcie_parc);

	ipc_pcie_ras_des_save_cap(this->ras_des);

	/* Set the power state of a PCI device.
	 * Transition a device to a new power state, using the device's PCI PM
	 * registers.
	 */
	rc = pci_set_power_state(pdev, PCI_D3cold);
	if (rc) {
		ipc_err("pci_set_power_state error=%d", rc);
		return -EBUSY;
	}

	ipc_gpio_handler_suspend(this->gpio_handler);
	set_bit(IPC_SUSPENDED, &this->pm_flags);

	ipc_dbg("done");
	return 0;

}				/* imc_ipc_suspend */

/* Callback invoked by pm_runtime_resume: entry point for runtime resume
 * operations. It increments the device's usage count. Then carry out a resume,
 * either synchronous or asynchronous.
 */
int imc_ipc_resume(struct device *dev)
{
	struct pci_dev *pdev;
	int rc;
	/* To compliance with the ipc_dbg logging module design.
	 */
	struct ipc_pcie *this = NULL;

	ipc_pr_dbg("");
	if (IS_ERR_OR_NULL(dev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Get the reference to the device description.
	 */
	pdev = to_pci_dev(dev);
	if (IS_ERR_OR_NULL(pdev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Set the power state of a PCI device.
	 * Transition a device to a new power state, using the device's PCI PM
	 * registers.
	 */
	rc = pci_set_power_state(pdev, PCI_D0);

	if (rc) {
		ipc_err("pci_set_power_state error=%d", rc);
		return -EAGAIN;
	}

	/* Restore the saved state of a PCI device.
	 */
	pci_restore_state(pdev);

	this = pci_get_drvdata(pdev);

	/* Restore the Vendor Specific Extended Capability if supported
	 */
	ipc_pcie_parc_restore_cap(this->pcie_parc);

	/* Restore the RAS DES Counters */
	ipc_pcie_ras_des_restore_cap(this->ras_des);

	if (unlikely(!this)) {
		ipc_err("pcie pointer is NULL");
		return -ENODEV;
	}

	ipc_gpio_handler_resume(this->gpio_handler);
	clear_bit(IPC_SUSPENDED, &this->pm_flags);

	/* The HAL shall inform the shared memory layer that the device is
	 * active.
	 */
	ipc_imem_pm_resume(this->imem);

	ipc_dbg("done");
	return 0;
}				/* imc_ipc_runtime_resume_cb */

static int imc_ipc_suspend_cb(struct device *dev)
{

	ipc_pr_dbg("");

	return imc_ipc_suspend(dev);
}				/*imc_ipc_suspend_cb */

static int imc_ipc_resume_cb(struct device *dev)
{

	ipc_pr_dbg("");
	return imc_ipc_resume(dev);
}				/* imc_ipc_resume_cb */

#ifdef IPC_RUNTIME_PM
static int imc_ipc_rt_suspend_cb(struct device *dev)
{
	struct pci_dev *pdev;
	/* To compliance with the ipc_dbg logging module design.
	 */
	struct ipc_pcie *this = NULL;

	ipc_pr_dbg("");
	if (IS_ERR_OR_NULL(dev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Get the reference to the device description.
	 */
	pdev = to_pci_dev(dev);
	if (IS_ERR_OR_NULL(pdev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Execute D3 one time.
	 */
	if (pdev->current_state != PCI_D0) {
		ipc_pr_dbg("done for PM=%d", pdev->current_state);
		return 0;
	}

	this = pci_get_drvdata(pdev);
	if (unlikely(!this)) {
		ipc_err("pcie pointer is NULL");
		return -ENODEV;
	}

	if (unlikely(!ipc_imem_is_runtime_pm_enabled(this->imem))) {
		/* This shouldn't happen as we cannot communicate with modem
		 * for PM related action when we are not in RUN state.
		 * We do nothing and return an error
		 */
		ipc_err("rt_suspend is called while runtime_pm is disabled");
		return -EAGAIN;
	}

	/* The HAL shall ask the shared memory layer whether D3 is allowed.
	 */
	if (ipc_imem_pm_suspend(this->imem)) {
		ipc_dbg("try again");
		return -EAGAIN;
	}

	/* Save the Vendor Specific Extended Capability if supported.
	 */
	ipc_pcie_parc_save_cap(this->pcie_parc);

	ipc_dbg("done");
	return 0;
}				/*imc_ipc_rt_suspend_cb */

static int imc_ipc_rt_resume_cb(struct device *dev)
{
	struct pci_dev *pdev;
	struct ipc_pcie *this = NULL;

	ipc_pr_dbg("");

	if (IS_ERR_OR_NULL(dev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* Get the reference to the device description.
	 */
	pdev = to_pci_dev(dev);
	if (IS_ERR_OR_NULL(pdev)) {
		ipc_err("no such device");
		return -ENODEV;
	}

	/* if state not switched to D0 do not execute
	 * iosm protocol
	 */
	if (pdev->current_state != PCI_D0) {
		ipc_pr_dbg("done for PM=%d", pdev->current_state);
		return 0;
	}

	this = pci_get_drvdata(pdev);
	if (unlikely(!this)) {
		ipc_err("pcie pointer is NULL");
		return -ENODEV;
	}

	 /* The HAL shall inform the shared memory layer that the device is
	  * active.
	  */
	if (!ipc_imem_is_runtime_pm_enabled(this->imem)) {
		/* This shouldn't happen we are not in RUN state ...
		 * we cannot comunicate with modem
		 * for PM related action. we do nothing and return an error
		 */
		ipc_err("rt_resume is called while runtime_pm is disabled");
		return -1;
	}

	/* Restore the Vendor Specific Extended Capability if supported
	 */
	ipc_pcie_parc_restore_cap(this->pcie_parc);

	ipc_imem_pm_resume(this->imem);

	ipc_dbg("done");
	return 0;

}				/*imc_ipc_rt_resume_cb */

static int imc_ipc_rt_idle_cb(struct device *dev)
{

	ipc_pr_dbg("");
	return 0;

}				/*imc_ipc_rt_idle_cb */
#endif

static int imc_ipc_freeze_cb(struct device *dev)
{

	ipc_pr_dbg("");
	return imc_ipc_suspend(dev);
}				/*imc_ipc_freeze_cb */

static int imc_ipc_restore_cb(struct device *dev)
{

	ipc_pr_dbg("");
	return imc_ipc_resume(dev);
}				/* imc_ipc_restore_cb */

/* struct dev_pm_ops - device PM callbacks
 */
static const struct dev_pm_ops imc_ipc_pm = {
	.suspend = imc_ipc_suspend_cb,
	.resume = imc_ipc_resume_cb,
#ifdef IPC_RUNTIME_PM
	.runtime_suspend = imc_ipc_rt_suspend_cb,
	.runtime_resume = imc_ipc_rt_resume_cb,
	.runtime_idle = imc_ipc_rt_idle_cb,
#endif
	.freeze = imc_ipc_freeze_cb,
	.restore = imc_ipc_restore_cb,
};

#define IMC_IPC_PM_OPS      (&imc_ipc_pm)
#else
#define IMC_IPC_PM_OPS      NULL
#endif				/* CONFIG_PM */


/* struct of pci driver - device probe and remove
 */
static struct pci_driver imc_ipc_driver = {
	.name = KBUILD_MODNAME,
	.probe = imc_ipc_probe,
	.remove = imc_ipc_remove,
	.driver = {
		   .pm = IMC_IPC_PM_OPS,
		   },
	.id_table = imc_ipc_ids_imc,
};

/* Either register the PCI driver or start in the test mode for test
 * and developement.
 */
static int ipc_register_driver(struct ipc_pcie **this_pp)
{
#ifndef IPC_FASTSIM
	/* Register the IMC IPC pci driver.
	 */
	if (pci_register_driver(&imc_ipc_driver)) {
		ipc_err("registering of the AP PCIe driver failed !");
		return -1;	/* ERROR: insmod:-1 Operation not permitted */
	}
#endif

	ipc_pr_dbg("registering of the AP PCIe driver done !");

	return 0;		/* OK, init done */

}				/* ipc_register_driver */

/* Either deregister the PCI driver or terminate only the test mode for test
 * and developement.
 */
static void ipc_unregister_driver(void)
{
#ifndef IPC_FASTSIM
	/* Unregister the IMC IPC pci driver.
	 * Deletes the driver structure from the list of registered PCI drivers,
	 * gives it a chance to clean up by calling its remove() function for
	 * each device it was responsible for, and marks those devices as
	 * driverless.
	 */
	pci_unregister_driver(&imc_ipc_driver);
#endif
}				/* ipc_unregister_driver */


#ifdef IPC_FASTSIM
static int ipc_pcie_fastsim_probe(void *data, int index, unsigned int device,
	void __iomem *bar0, size_t size0, void __iomem *bar1, size_t size1)
{
	struct ipc_pcie *this = data;

	/* Set ipc_dbg pointer to NULL */
	this->dbg = NULL;

	ipc_pr_dbg("----------------- fastsim probe ----------------");
	ipc_pr_dbg("probe the net device with index %d", index);

	/* Reset the address ranges before any allocations */
	ipc_util_reset_addr_range(&this->ranges[IPC_PCIE_SKB_MEM]);
	ipc_util_reset_addr_range(&this->ranges[IPC_PCIE_DYNAMIC_MEM]);

	/* Update platform configuration
	 */
	ipc_pcie_config_init(this, device);

	this->ipc_regs = bar0;
	this->scratchpad = bar1;

	/* Initialize root debugfs component for the PCIe device
	 */
	this->root_dbgfs = ipc_debugfs_alloc(index, this->dbg);
	if (!this->root_dbgfs)
		ipc_err("no debugfs allocated");

	/* Allocate IPC uevent */
	this->uevent = ipc_uevent_alloc(index, this->root_dbgfs, this->dbg);
	if (unlikely(!this->uevent)) {
		ipc_err("uevent allocation failed");
		return -1;
	}

	/* Establish the link to the imem layer.
	 */
	if (ipc_imem_mount(this->imem, NULL, this, device,
		this->root_dbgfs, this->scratchpad, index, this->dbg)) {
		ipc_err("failed to execute ipc_imem_mount()");
		return -1;
	}

	return 0;
}

static void ipc_pcie_fastsim_remove(void *data)
{
	struct ipc_pcie *this = data;

	ipc_dbg("----------------- fastsim remove -----------------");

	/* Free the shared memory resources.
	 */
	ipc_imem_cleanup(this->imem);

	/* uevent cleanup */
	ipc_uevent_dealloc(&this->uevent);

	/* remove debugfs */
	ipc_debugfs_dealloc(&(this->root_dbgfs));

	this->ipc_regs = NULL;
	this->scratchpad = NULL;

	ipc_pr_dbg("-------------------- BYE BYE -----------------");
}

static void ipc_pcie_fastsim_trigger_msi(void *data, unsigned int vector)
{
	struct ipc_pcie *this = data;

	ipc_dbg("vector=%u", vector);

	ipc_imem_irq_process(this->imem, vector);
}
#endif /* IPC_FASTSIM */

static bool ipc_pcie_ctor(struct ipc_pcie *this, unsigned int instance_nr,
		struct ipc_netlink *netlink)
{
#ifdef IPC_FASTSIM
	static const struct ipc_fastsim_cb cb = {
		.probe = ipc_pcie_fastsim_probe,
		.remove = ipc_pcie_fastsim_remove,
		.trigger_msi = ipc_pcie_fastsim_trigger_msi
	};

	ipc_dbg("ipc_fastsim_alloc");
	this->fastsim = ipc_fastsim_alloc(instance_nr, &cb, this);
	if (unlikely(!this->fastsim))
		return -1;
#endif

	this->dbg = NULL;

	/* Register GPIO handler */
	this->gpio_handler = ipc_gpio_handler_alloc(instance_nr, this, NULL);
#ifdef IPC_GPIO_MDM_CTRL
	if (instance_nr == 0 && !this->gpio_handler)
		return false;
#endif

	this->timesync_doorbell = -1;

	/* Note: netlink is NULL for instances greater than zero. */
	this->netlink = ((instance_nr == 0) ? netlink : NULL);

	/* initialize spin lock for range updates */
	spin_lock_init(&this->parc_lock);

	ipc_pr_dbg("pcie ctor done.");

	return 0;
}

static void ipc_pcie_dtor(struct ipc_pcie *this)
{
#ifdef IPC_FASTSIM
	ipc_fastsim_dealloc(&this->fastsim);
#endif
	ipc_imem_dealloc(&this->imem);

	/* Cleanup GPIO handler */
	ipc_gpio_handler_dealloc(&this->gpio_handler);
}


/* Deallocates a IPC PCIe instance
 */
static void ipc_pcie_dealloc(struct ipc_pcie **this_pp)
{
	if (this_pp && *this_pp) {
		ipc_pcie_dtor(*this_pp);
		ipc_util_kfree(*this_pp);
		*this_pp = NULL;
	}
}


/* Allocates IPC PCIe devices instances
 */
static struct ipc_pcie *ipc_pcie_alloc(unsigned int instance_nr,
		struct ipc_netlink *netlink)
{
	/* Allocate memory for core driver data-struct. */
	struct ipc_pcie *this = ipc_util_kzalloc(sizeof(*this));

	if (this && ipc_pcie_ctor(this, instance_nr, netlink)) {
		ipc_pcie_dealloc(&this);
		return NULL;
	}

	return this;
}


/* Install the IMC IPC driver.
 */
int init_module(void)
{
	struct ipc_pcie *this = NULL;

	ipc_pr_dbg("=================== init module ===============");
	ipc_pr_dbg("%s", ipc_imem_version());

	/* Allocate netlink only for modem instance zero. */
	ipc_pcie_netlink = ipc_netlink_alloc();
	if (!ipc_pcie_netlink) {
		ipc_err("Unable to allocate netlink.");
		return -1;
	}

	/* Register the IMC IPC pci driver. */
	if (ipc_register_driver(&this)) {
		ipc_netlink_dealloc(&ipc_pcie_netlink);
		ipc_err("Failed to register IPC driver");
		return -1;
	}

	return 0;
}				/* init_module */

/* Uninstall the IMC IPC driver.
 */
void cleanup_module(void)
{
	struct ipc_pcie_instance_map *tmp, *n;

	ipc_pr_dbg("=================== exit_module ===============");

	/* Clean dynamic memory for instance index. */
	list_for_each_entry_safe(tmp, n, &ipc_pcie_mdm_list, list) {
		list_del(&tmp->list);
		ipc_util_kfree(tmp->slot_name);
		ipc_util_kfree(tmp);
	}


	/* Deregister the IMC IPC pci driver */
	ipc_unregister_driver();

	/* De-allocate netlink */
	ipc_netlink_dealloc(&ipc_pcie_netlink);

	ipc_pr_dbg("De-allocate all the modem instances and free memory done");
	ipc_pr_dbg("=================== exit_module done ===============");
}				/* cleanup_module */

/* print interface information
 */
void ipc_hal_stats(struct ipc_pcie *this, struct seq_file *m)
{
	int i;

	if (unlikely(!this || !m))
		return;

	seq_puts(m, ">>>>> PCIe HAL\n");
	seq_printf(m, "CP IPC IRQs..........: %lu\n", this->ipc_irq_count);
	seq_printf(m, "CP SLP IRQs..........: %lu\n", this->slp_irq_count);
	seq_printf(m, "CP HPU IRQs..........: %lu\n", this->hpu_irq_count);
	seq_printf(m, "CP Time Sync IRQs....: %lu\n",
			this->time_sync_irq_count);
	if (this->pci && this->pci->msi_enabled) {
		for (i = 0; i < this->nvec; i++)
			seq_printf(m, "AP MSI irq(%d)'s..........: %lu\n",
				   i, this->ap_msi_irq_count[i]);
	}
	if (this->pci && this->pci->msix_enabled) {
		for (i = 0; i < this->msix_nvec; i++)
			seq_printf(m, "AP MSI-X irq(%d)'s..........: %lu\n",
				   i, this->ap_msix_irq_count[i]);
	}
}

/* print IPC PCIe device information
 */
void ipc_hal_device(struct ipc_pcie *this, struct seq_file *m)
{
	if (unlikely(!this || !m || !this->pci))
		return;

	seq_puts(m, ">>>>> PCIe Device Information\n");
	seq_printf(m, "Slot Name: %s: %04X: %04X\n",
			dev_name(&this->pci->dev), this->pci->vendor,
			this->pci->device);
	seq_printf(m, "IOMMU................: %s\n\n",
			(this->iommu_enabled ? "enabled" : "disabled"));
}


/*
 * Refer to header file for description
 */
int ipc_pcie_config_read32(struct ipc_pcie *this, int addr, u32 *p_val)
{
	if (!p_val)
		return -1;

	return pci_read_config_dword(this->pci, addr, p_val);
}


/*
 * Refer to header file for description
 */
int ipc_pcie_config_write32(struct ipc_pcie *this, int addr, u32 val)
{
	return pci_write_config_dword(this->pci, addr, val);
}


/*
 * Refer to header file for description
 */
int ipc_pcie_find_next_ext_capability(struct ipc_pcie *this, int offset)
{
	int cap_offset;

	cap_offset = pci_find_next_ext_capability(this->pci, offset,
						PCI_EXT_CAP_ID_VNDR);

	return cap_offset;
}


/**
 * Function to adjust the Start and End addresses depending on the new memory
 * allocated address and its size.
 *
 * @this: pointer to the core driver data-struct
 * @new_start_addr: the new Start Address
 * @size: size of newly allocated memory.
 * @mem_type: enum defining the memory allocation is for SKB or Dynamic
 *            allocation. For SKB memory Start/Limit Window-0 is used
 *            and for Dynamic memory Start/Limit Window-1 is used.
 *
 * returns none
 */
static void ipc_pcie_reconfigure_range(struct ipc_pcie *this,
	u64 new_start_addr, size_t size, enum ipc_pcie_mem_type mem_type)
{
	struct ipc_util_addr_range *p_range;
	bool range_updated = false;
	bool parc_supported;
	unsigned long flags;

	if (unlikely(!this))
		return;

	/* Check if PARC supported */
	parc_supported = ipc_pcie_parc_is_supported(this->pcie_parc);
	if (!parc_supported)
		return;

	/* as range updates can be done from different contexts
	 * perform it with spin lock
	 */
	spin_lock_irqsave(&this->parc_lock, flags);

	p_range = &this->ranges[mem_type];

	/* If the old start address is greater than new start address then
	 * the old start address needs to be adjusted to the new address.
	 */
	if (p_range->start > new_start_addr) {
		p_range->start = new_start_addr;
		range_updated = true;
	}

	/* If the old end address is less than the new address + size - 1 then
	 * adjust the end address to include the new memory allocation between
	 * Start and End addresses.
	 */
	if (p_range->end < (new_start_addr + size - 1)) {
		p_range->end = new_start_addr + size - 1;
		range_updated = true;
	}

	/* Update the PARC ranges only if the range got changed.
	 */
	if (range_updated) {
		if (mem_type == IPC_PCIE_SKB_MEM)
			ipc_pcie_parc_configure_sl_window(this->pcie_parc,
			PARC_WIN_SL_0, p_range->start, p_range->end);
		else if (mem_type == IPC_PCIE_DYNAMIC_MEM)
			ipc_pcie_parc_configure_sl_window(this->pcie_parc,
			PARC_WIN_SL_1, p_range->start, p_range->end);
	}

	spin_unlock_irqrestore(&this->parc_lock, flags);
}


/**
 * Function maps the kernel's virtual address to either IOVA
 * address space or Physical address space.
 *
 * @this: pointer to struct ipc_pcie
 * @p_mem: pointer to the memory we want to mapping.
 * @size: size of the kmem required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 * @direction: direction of the DMA data
 *
 * returns 0 on Success, error code on failure.
 */
static int ipc_pcie_addr_map(struct ipc_pcie *this, void *p_mem, size_t size,
	u64 *mapping, int direction)
{
	if (unlikely(!this || !mapping))
		return -EINVAL;

#ifdef CONFIG_X86
	if (this->iommu_enabled && this->pci) {
		*mapping = pci_map_single(this->pci, p_mem, size, direction);
		if (pci_dma_mapping_error(this->pci, *mapping)) {
			ipc_err("dma mapping failed");
			return -EINVAL;
		}
	} else {
		*mapping = virt_to_phys(p_mem);
	}
#else
	if (this->pci) {
		*mapping = dma_map_single(&this->pci->dev,
					p_mem, size, direction);
		if (dma_mapping_error(&this->pci->dev, *mapping)) {
			ipc_err("dma mapping failed");
			return -EINVAL;
		}
	} else {
		*mapping = virt_to_phys(p_mem);
	}
#endif

#ifdef IPC_FASTSIM
	if (this->fastsim)
		ipc_fastsim_map(this->fastsim, *mapping, size, direction,
			p_mem);
#endif
	return 0;
}


/**
 * Function un-maps IOVA address space or Physical address space
 * which did by map by ipc_pcie_addr_map() function.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the kmem required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 * @direction: direction of the DMA data
 *
 * returns 0 on Success, error code on failure.
 */
static void ipc_pcie_addr_unmap(struct ipc_pcie *this, size_t size,
	u64 mapping, int direction)
{
	if (unlikely(!this || !mapping))
		return;

#ifdef CONFIG_X86
	if (this->iommu_enabled && this->pci)
		pci_unmap_single(this->pci, mapping, size, direction);
#else
	if (this->pci)
		dma_unmap_single(&this->pci->dev,
			mapping, size, direction);
#endif

#ifdef IPC_FASTSIM
	if (this->fastsim)
		ipc_fastsim_unmap(this->fastsim, mapping, size);
#endif
}


/* Refer to header file for function description
 */
int ipc_pcie_map_skb(struct ipc_pcie *this, struct sk_buff *skb)
{
	struct ipc_skb_cb *skb_cb = (struct ipc_skb_cb *)skb->cb;

	int result = ipc_pcie_addr_map(this, skb->data, skb->len,
		&skb_cb->mapping, PCI_DMA_TODEVICE);

	if (!result) {
		skb_cb->direction = PCI_DMA_TODEVICE;
		skb_cb->len = skb->len;
		skb_cb->op_type = UL_DEFAULT;
		ipc_pcie_reconfigure_range(this, skb_cb->mapping, skb->len,
			IPC_PCIE_SKB_MEM);
	}

	return result;
}


/* Refer to header file for function description
 */
void ipc_pcie_unmap_skb(struct ipc_pcie *this, struct sk_buff *skb)
{
	struct ipc_skb_cb *skb_cb = (struct ipc_skb_cb *)skb->cb;

	ipc_pcie_addr_unmap(this, skb_cb->len, skb_cb->mapping,
		skb_cb->direction);

	skb_cb->mapping = 0;
}


 /* Refer to header file for function description
  */
void ipc_pcie_sync_skb_for_device(struct ipc_pcie *this,
		struct sk_buff *skb)
{
#if !defined(CONFIG_X86)
	struct ipc_skb_cb *skb_cb = (struct ipc_skb_cb *)skb->cb;

	dma_sync_single_for_device(&this->pci->dev, skb_cb->mapping,
		skb_cb->len, PCI_DMA_TODEVICE);
#endif
}


/* Refer to header file for function description
 */
void ipc_pcie_sync_skb_for_cpu(struct ipc_pcie *this,
		struct sk_buff *skb)
{
#if !defined(CONFIG_X86)
	struct ipc_skb_cb *skb_cb = (struct ipc_skb_cb *)skb->cb;

	dma_sync_single_for_cpu(&this->pci->dev, skb_cb->mapping,
		skb_cb->len, PCI_DMA_FROMDEVICE);
#endif
}


/*
 * Refer to header file for description
 */
void ipc_pcie_addr_ranges_test(struct ipc_pcie *this, u32 exec_stage,
				bool crash)
{
	if (unlikely(!this)) {
		ipc_err("Invalid argument");
		return;
	}
	ipc_pcie_parc_test_mode(this->pcie_parc, exec_stage, crash);
}

/**
 * Refer to header file for function description
 */
void ipc_pcie_uevent_send(struct ipc_pcie *this, char *uevent)
{
	struct device *dev = NULL;

	if (unlikely(!this || !uevent)) {
		ipc_err("Invalid arguments");
		return;
	}

	if (this->pci)
		dev = &this->pci->dev;

	(void) ipc_uevent_send(this->uevent, dev, uevent);

	/* Send netlink event */
	if (this->netlink)
		if (ipc_netlink_event(this->netlink, uevent, this->dbg) != 0)
			ipc_dbg("Unable to send netlink event");
}

/**
 * Refer to header file for function description
 */
void ipc_pcie_gpio_notification(struct ipc_pcie *this,
				enum ipc_mdm_ctrl_gpio_signal signal)
{

	if (unlikely(this == NULL)) {
		ipc_err("Invalid arguments");
		return;
	}

	if (ipc_pcie_check_aspm_enabled(this, this->pci))
		ipc_dbg("ASPM is enabled");

	ipc_imem_gpio_notification(this->imem, signal);
}


/* Refer to header file for function description
 */
struct sk_buff *ipc_pcie_alloc_local_skb(struct ipc_pcie *this,
					gfp_t flags, size_t size)
{
	struct sk_buff *skb;
	struct ipc_skb_cb *skb_cb;

	if (unlikely(!this || !size)) {
		ipc_err("invalid arguments");
		return NULL;
	}

	skb = __netdev_alloc_skb(NULL, size, flags);
	if (unlikely(!skb))
		return NULL;

	/* Initialize op_type
	 */
	skb_cb = (struct ipc_skb_cb *)skb->cb;
	skb_cb->op_type = (u8) UL_DEFAULT;
	skb_cb->mapping = 0;

	return skb;
}


/**
 * Function to allocate an SKB for the given size. This also re-calculates the
 * Start and End addresses if PCIe Address Range Check (PARC) is supported.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the SKB required.
 * @flags: allocator flags
 * @mapping: copies either mapped IOVA address or converted Physical address
 * @direction: direction of the DMA data
 * @headroom: number of bytes to be reserved at begin of skb
 *
 * returns pointer to sk_buff on Success, NULL on failure.
 */
static struct sk_buff *ipc_pcie_alloc_skb(struct ipc_pcie *this, size_t size,
	gfp_t flags, u64 *mapping, int direction, size_t headroom)
{
	struct sk_buff *skb = ipc_pcie_alloc_local_skb(this, flags,
			size + headroom);
	struct ipc_skb_cb *skb_cb;

	if (unlikely(!skb))
		return NULL;

	if (headroom)
		skb_reserve(skb, headroom);

	if (ipc_pcie_addr_map(this, skb->data, size, mapping, direction)) {
		dev_kfree_skb(skb);
		return NULL;
	}

	/* Store the mapping address in skb scratch pad for later usage */
	skb_cb = (struct ipc_skb_cb *)skb->cb;
	skb_cb->mapping = *mapping;
	skb_cb->direction = direction;
	skb_cb->len = size;

	/* Adjust the start and end addresses if PARC is supported.
	 */
	ipc_pcie_reconfigure_range(this, *mapping, size,
				IPC_PCIE_SKB_MEM);
	return skb;
}


/* Refer to header file for function description
 */
struct sk_buff *ipc_pcie_alloc_ul_skb(struct ipc_pcie *this, size_t size,
	u64 *mapping)
{
	if (unlikely(!this || !size || !mapping)) {
		ipc_err("invalid arguments");
		return NULL;
	}

	return ipc_pcie_alloc_skb(this, size, GFP_ATOMIC, mapping,
		PCI_DMA_TODEVICE, 0);
}

/* Refer to header file for function description
 */
struct sk_buff *ipc_pcie_alloc_ul_skb_nonatomic(struct ipc_pcie *this,
	size_t size, u64 *mapping)
{
	if (unlikely(!this || !size || !mapping)) {
		ipc_err("invalid arguments");
		return NULL;
	}

	return ipc_pcie_alloc_skb(this, size, GFP_KERNEL, mapping,
		PCI_DMA_TODEVICE, 0);
}

/* Refer to header file for function description
 */
struct sk_buff *ipc_pcie_alloc_dl_skb(struct ipc_pcie *this, size_t size,
	u64 *mapping)
{
	if (unlikely(!this || !size || !mapping)) {
		ipc_err("invalid arguments");
		return NULL;
	}

	return ipc_pcie_alloc_skb(this, size, GFP_ATOMIC, mapping,
		PCI_DMA_FROMDEVICE, IPC_MEM_DL_ETH_OFFSET);
}


/* Refer to header file for function description
 */
void ipc_pcie_kfree_skb(struct ipc_pcie *this, struct sk_buff *skb)
{
	struct ipc_skb_cb *skb_cb;

	if (!skb)
		return;

	skb_cb = (struct ipc_skb_cb *)skb->cb;
	ipc_pcie_addr_unmap(this, skb_cb->len, skb_cb->mapping,
		skb_cb->direction);

	dev_kfree_skb(skb);
}



/* Refer to header file for function description
 */
void *ipc_pcie_kzalloc(struct ipc_pcie *this, size_t size, u64 *mapping)
{
	void *p_mem;
	dma_addr_t addr = { 0 };

	if (unlikely(!this || !size || !mapping)) {
		ipc_err("invalid arguments");
		return NULL;
	}

	p_mem = pci_alloc_consistent(this->pci, size, &addr);

	/* Adjust the start and end addresses if PARC is supported.
	 */
	if (p_mem) {
		memset(p_mem, 0, size);

		*mapping = (u64) addr;

		ipc_pcie_reconfigure_range(this, *mapping, size,
			IPC_PCIE_DYNAMIC_MEM);

#ifdef IPC_FASTSIM
		if (this->fastsim)
			ipc_fastsim_map(this->fastsim, *mapping, size,
				PCI_DMA_BIDIRECTIONAL, p_mem);
#endif
	}

	return p_mem;
}


/* Refer to header file for function description
 */
void ipc_pcie_kfree(struct ipc_pcie *this, void *p_mem, size_t size,
			u64 mapping)
{
	if (unlikely(!this || !size)) {
		ipc_err("invalid arguments");
		return;
	}

#ifdef IPC_FASTSIM
	if (this->fastsim)
		ipc_fastsim_unmap(this->fastsim, mapping, size);
#endif

	return pci_free_consistent(this->pci, size, p_mem,
		(dma_addr_t)mapping);
}

int ipc_pcie_find_vsec_id(struct ipc_pcie *this,
		struct pcie_extended_cap *vsec_cap,
		int *offset, int vsec_id)
{

	if (unlikely(!this || !vsec_cap || !offset)) {
		ipc_err("Invalid arguments");
		return -1;
	}

	/* Traverse through extended capabilities and read Vsec_id */
	do {
		*offset = ipc_pcie_find_next_ext_capability(this, *offset);
		if (*offset == 0)
			break;
		ipc_pcie_config_read32(this,
			*offset + IPC_RAS_PARC_VSH, (u32 *)vsec_cap);
	} while (vsec_cap->cap_id != vsec_id);

	if (vsec_cap->cap_id != vsec_id)
		return -1;
	return 0;
}
