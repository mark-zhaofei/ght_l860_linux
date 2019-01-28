/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_PCIE_H
#define IMC_IPC_PCIE_H

#include <linux/stddef.h>
#include <linux/device.h>
#include "imc_ipc_gpio_handler.h"

struct seq_file;

/*
 * Vender ID and Device ID
 */
#define INTEL_VENDOR_ID          0x8086
#define INTEL_CP_DEVICE_7260_ID  0x7260
#define INTEL_CP_DEVICE_7360_ID  0x7360
#define INTEL_CP_DEVICE_7460_ID  0x7460
#define INTEL_CP_DEVICE_7480_ID  0x7480
#define INTEL_CP_DEVICE_7560_ID  0x7560
#define INTEL_CP_DEVICE_7660_ID  0x7660
#define INTEL_CP_DEVICE_IBIS_ID  0x4247
#define INTEL_CP_DEVICE_8060_ID  0x8060

/*
 * number of MSI used for IPC
 */
#define IPC_MSI_VECTORS		1

/*
 * number of MSI-X used for IPC
 */
#define IPC_MSIX_VECTORS	1

/*
 * Findout greater number out of two numbers
 */
#define IPC_MAX(t1, t2)		((t1 > t2) ? t1 : t2)

/*
 * total number of Maximum IPC IRQ vectors used for IPC
 */
#define IPC_IRQ_VECTORS		IPC_MAX(IPC_MSI_VECTORS, IPC_MSIX_VECTORS)


/* Extra headroom to be allocated for DL SKBs to allow addition of Ethernet
 * header
 */
#define IPC_MEM_DL_ETH_OFFSET  16

struct sk_buff;
struct ipc_pcie;

struct ipc_pcie_vsec {
	u32 vsec_id;    /* Holds the VSEC ID */
	u32 vsec_ver;   /* Holds the VSEC version */
	u32 vsec_len;   /* Size of the VSEC */
	u32 base_addr;  /* Holds the base address of RAS DES */
	u32 *p_save_cap;
};

/* Structure representing fields of Extended Capability register.
 */
struct pcie_extended_cap {
	u32 cap_id:16;
	u32 cap_ver:4;
	u32 next_offset:12;
};

/* HP update identifier. To be used as data for ipc_cp_irq_hpda_update()
 */
enum ipc_hp_identifier {
	IPC_HP_STRESSTEST = -1,
	IPC_HP_MR = 0,
	IPC_HP_PM_TRIGGER,
	IPC_HP_WAKEUP_SPEC_TMR,
	IPC_HP_TD_UPD_TMR_START,
	IPC_HP_TD_UPD_TMR,
	IPC_HP_FAST_TD_UPD_TMR,
	IPC_HP_UL_WRITE_TD,
	IPC_HP_DL_PROCESS,
	IPC_HP_NET_CHANNEL_INIT,
	IPC_HP_SIO_OPEN
};

/* Enum type to define type of memory allocation
 */
enum ipc_pcie_mem_type {
	IPC_PCIE_SKB_MEM = 0,
	IPC_PCIE_DYNAMIC_MEM,
	IPC_PCIE_MEM_TYPE_MAX
};

/* State definition of the socket buffer which is mapped to the cb field of
 * sbk.
 */
struct ipc_skb_cb {
	/* Expected values are defined about enum ipc_ul_usr_op. */
	u8 op_type;

	/* store physical or IOVA mapped address of skb virtual address */
	u64 mapping;

	/* DMA direction */
	int direction;

	/* length of the DMA mapped region */
	int len;
};

/* Control information to execute the right operation on the user interface.
 */
enum ipc_ul_usr_op {
	/* The uplink app was blocked until CP confirms that the uplink buffer
	 * was consumed triggered by the IRQ irq.
	 */
	UL_USR_OP_BLOCKED,

	/* In MUX mode the UL ADB shall be addedd to the free list. */
	UL_MUX_OP_ADB,

	/* SKB in non muxing mode */
	UL_DEFAULT
};


/**
 *Trigger the doorbell interrupt 0 on CP to processsing
 * the PSI information.
 *
 * @this: pointer to the core driver data-struct
 * @data: ipc_mem_exec_stage
 */
void ipc_cp_irq_rom(struct ipc_pcie *this, u32 data);

/**
 *Trigger the doorbell interrupt IPC_DOORBELL_IRQ_IPC
 * on CP to change the IPC stage.
 *
 * @this: pointer to the core driver data-struct
 * @data: ipc_mem_device_ipc_state
 */
void ipc_cp_irq_ipc_control(struct ipc_pcie *this, u32 data);

/**
 *Trigger the doorbell interrupt IPC_DOORBELL_IRQ_SLEEP
 * on CP to change the PM sleep/active status.
 *
 * @this: pointer to the core driver data-struct
 * @data: ipc_mem_dev_pm_state
 */
void ipc_cp_irq_sleep_control(struct ipc_pcie *this, u32 data);

/**
 *Trigger the doorbell interrupt IPC_DOORBELL_IRQ_HPDA
 * on CP to do hpda update.
 *
 * @this: pointer to the core driver data-struct
 * @data: ipc_hp_identifier
 */
void ipc_cp_irq_hpda_update(struct ipc_pcie *this, u32 data);

/**
 *Trigger the doorbell interrupt IPC_DOORBELL_IRQ_TIME_SYNC
 * on CP to do the time sync up.
 *
 * @this: pointer to the core driver data-struct
 * @data: time sync id in ipc_timesync
 * @timestamp: local_time of ipc_timesync
 * @time_unit: time unit of local_time
 */
void ipc_cp_irq_time_sync(struct ipc_pcie *this, u32 data, u64 *timestamp,
		u32 *time_unit);

/* Gets the PCIe HAL stats
 *
 * @this: pointer to the core driver data-struct
 * @m: pointer to sysfs log file
 */
void ipc_hal_stats(struct ipc_pcie *this, struct seq_file *m);

/*
 * Gets the PCIe device information
 * @this: pointer to the core driver data-struct
 * @m: pointer to sysfs log file
 */
void ipc_hal_device(struct ipc_pcie *this, struct seq_file *m);

/**
 * Wrapper for pci_read_config_dword() API.
 *
 * @this: pointer to the core driver data-struct
 * @addr: specifies the address where the dwork to be read from.
 * @p_val: pointer to get the value from the specified address.
 *
 * returns 0 on Success, non-zero value on Failure.
 */
int ipc_pcie_config_read32(struct ipc_pcie *this, int addr, u32 *p_val);


/**
 * Wrapper for pci_write_config_dword() API.
 *
 * @this: pointer to the core driver data-struct
 * @addr: specifies the address where the dword to be written to.
 * @val: value to be written in the specified address.
 *
 * returns 0 on Success, non-zero value on Failure.
 */
int ipc_pcie_config_write32(struct ipc_pcie *this, int addr, u32 val);


/**
 * Wrapper for pci_find_next_ext_capability() API.
 *
 * @this: pointer to the core driver data-struct
 * @offset: offset to start finding extended capability.
 *
 * returns 0 on Success, non-zero value on Failure.
 */
int ipc_pcie_find_next_ext_capability(struct ipc_pcie *this, int offset);

/**
 * Function maps the kernel's virtual address to either IOVA
 * address space or Physical address space, the mapping is stored
 * in the skb's cb.
 *
 * @this: pointer to struct ipc_pcie
 * @skb: pointer to struct sk_buff
 *
 * returns 0 on success else error code
 */
int ipc_pcie_map_skb(struct ipc_pcie *this, struct sk_buff *skb);


/**
 * Function unmaps the skb memory region from IOVA address space
 *
 * @this: pointer to struct ipc_pcie
 * @skb: pointer to struct sk_buff
 *
 * returns 0 on success else error code
 */
void ipc_pcie_unmap_skb(struct ipc_pcie *this, struct sk_buff *skb);

/**
 * Function to sync the skb memory region with DMA buffer before
 * send to device, called after dma_map_* is used
 *
 * @this: pointer to struct ipc_pcie
 * @skb: pointer to struct sk_buff
 */
void ipc_pcie_sync_skb_for_device(struct ipc_pcie *this,
		struct sk_buff *skb);

/**
 * Function to sync the skb memory region with DMA buffer before
 * CPU read and use, called before dma_unmap_* is used
 *
 * @this: pointer to struct ipc_pcie
 * @skb: pointer to struct sk_buff
 */
void ipc_pcie_sync_skb_for_cpu(struct ipc_pcie *this,
		struct sk_buff *skb);

/**
 * reset the PCIe address ranges
 *
 * @this: pointer to PCIe pointer.
 * @exec_stage: CP execution stage.
 * @crash: If CP is in crash stage then set to true else false
 *
 */
void ipc_pcie_addr_ranges_test(struct ipc_pcie *this, u32 exec_stage,
				bool crash);
/*
 * Send modem events to user space
 *
 * @this: pointer to PCIe pointer.
 * @uevent: user event string
 *
 */
void ipc_pcie_uevent_send(struct ipc_pcie *this, char *uevent);

/**
 * Function to allocate an uplink SKB for the given size.
 * This also re-calculates the Start and End addresses
 * if PCIe Address Range Check (PARC) is supported.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the SKB required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 *
 * returns pointer to sk_buff on Success, NULL on failure.
 */
struct sk_buff *ipc_pcie_alloc_ul_skb(struct ipc_pcie *this, size_t size,
	u64 *mapping);

/**
 * Function to allocate an uplink SKB in a nonatomic way for the given size.
 * This also re-calculates the Start and End addresses
 * if PCIe Address Range Check (PARC) is supported.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the SKB required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 *
 * returns pointer to sk_buff on Success, NULL on failure.
 */
struct sk_buff *ipc_pcie_alloc_ul_skb_nonatomic(struct ipc_pcie *this,
	size_t size, u64 *mapping);


/**
 * Function to allocate a downlink SKB for the given size.
 * Additional headroom for the Ethernet header will be added.
 * This also re-calculates the Start and End addresses
 * if PCIe Address Range Check (PARC) is supported.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the SKB required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 *
 * returns pointer to sk_buff on Success, NULL on failure.
 */
struct sk_buff *ipc_pcie_alloc_dl_skb(struct ipc_pcie *this, size_t size,
	u64 *mapping);


/**
 * Function to allocate a local SKB for the given size.
 *
 * @this: pointer to struct ipc_pcie
 * @flags: allocation flags
 * @size: size of the SKB required.
 *
 * returns pointer to sk_buff on Success, NULL on failure.
 */
struct sk_buff *ipc_pcie_alloc_local_skb(struct ipc_pcie *this,
					gfp_t flags, size_t size);

/**
 * Free skb allocated by ipc_pcie_alloc_*_skb().
 * Using ipc_pcie_kfree_skb() could cause potential Kernel panic
 * if used on skb not allocated by ipc_util_alloc_skb() function.
 *
 * @this: pointer to struct ipc_pcie
 * @skb: pointer to the skb
 */
void ipc_pcie_kfree_skb(struct ipc_pcie *this, struct sk_buff *skb);


/**
 * Allocate zero initialized memory that can be read and written from the PCIe
 * bus in a coherent way.
 * This also re-calculates the Start and End addresses if PCIe Address Range
 * Check (PARC) is supported.
 *
 * @this: pointer to struct ipc_pcie
 * @size: size of the kmem required.
 * @mapping: copies either mapped IOVA address or converted Physical address
 *
 * returns pointer to requested on Success, NULL on failure.
 */
void *ipc_pcie_kzalloc(struct ipc_pcie *this, size_t size, u64 *mapping);

/**
 * Free memory allocated with ipc_pcie_kzalloc.
 *
 * @this: pointer to struct ipc_pcie
 * @p_mem: pointer to the memory to be freed
 * @size: size of the elements.
 * @mapping: Either mapped IOVA address or converted Physical address
 */
void ipc_pcie_kfree(struct ipc_pcie *this, void *p_mem, size_t size,
	u64 mapping);
/**
 * Read extended capability registers
 * @this: pointer to struct ipc_pcie
 * @vsec_cap: pointer to pcie_extended_cap struct
 * @vsec_id: value of Vendor ID
 * @offset: pointer to return the offset
 *
 * returns the status of vsec read, 0 on Success and -1 on failure.
 */
int ipc_pcie_find_vsec_id(struct ipc_pcie *this,
		struct pcie_extended_cap *vsec_cap,
		int *offset, int vsec_id);

/**
 * @this: struct ipc_pcie
 * @signal: signal indication of type ipc_mdm_ctrl_gpio_signal
 * called to trigger AP phase updation and indicate user space event triggers
 * for coredump
 */
void ipc_pcie_gpio_notification(struct ipc_pcie *this,
				enum ipc_mdm_ctrl_gpio_signal signal);

bool ipc_pcie_check_data_link_active(struct ipc_pcie *this);

int imc_ipc_suspend(struct device *dev);

int imc_ipc_resume(struct device *dev);

struct pci_dev *ipc_pci_get_pci_dev(struct ipc_pcie *this);

#endif /* IMC_IPC_PCIE_H */

