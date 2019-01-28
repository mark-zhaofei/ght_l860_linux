/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/seq_file.h>

#include "imc_ipc_protocol.h"
#include "imc_ipc_protocol_priv.h"
#include "imc_ipc_protocol_converged.h"
#include "imc_ipc_pm.h"
#include "imc_ipc_trace.h"
#include "imc_ipc_dbg.h"
#include "imc_ipc_pcie.h"
#include "imc_ipc_util.h"
#include "imc_ipc_mmio.h"
#include "imc_ipc_imem.h"


/**
 * Transfer Ring (TR/CR) Head Index type
 */
#define ipc_converged_hia_t	u16


/**
 * Transfer Ring (TR/CR) Tail Index type
 */
#define ipc_converged_tia_t	u16


/**
 * Transfer Ring Head Index Array size.
 * It should be IPC_MEM_MAX_PIPES + 2 because Messages will use index-0.
 */
#define IPC_CONVERGED_TR_HIA_SIZE	(IPC_MEM_MAX_PIPES)

/**
 * Completion Ring Head Index Array size.
 */
#define IPC_CONVERGED_CR_HIA_SIZE	1


/**
 * Completion Rng Tail Index Array size.
 */
#define IPC_CONVERGED_CR_TIA_SIZE	1


/**
 * Transfer Ring Tail Index Array size.
 * It should be IPC_MEM_MAX_PIPES + 2 because Messages will use index-0.
 * Index-1 is reserved (CP requirement).
 */
#define IPC_CONVERGED_TR_TIA_SIZE	(IPC_MEM_MAX_PIPES)


/**
 * Message Transfer Ring Index in Converged Spec is always 0
 */
#define MSG_TR_IDX	0


/**
 * Message Completion Ring Index in Converged Spec is always 0
 */
#define MSG_CR_IDX	0


/**
 * Message Completion Ring should be big enough to hold MTR entries + async CDs
 * Number of async CDs are 128
 */
#define MSG_CR_ENTRIES	(IPC_MEM_MSG_ENTRIES + 128)


/**
 * Completion Status
 */
enum ipc_converged_cs {
	IPC_CONVERGED_CS_INVALID = 0,
	IPC_CONVERGED_CS_PARTIAL_TRANSFER = 1,
	IPC_CONVERGED_CS_END_TRANSFER = 2,
	IPC_CONVERGED_CS_OVERFLOW = 3,
	IPC_CONVERGED_CS_BLOCK_OVERFLOW = 4,
	IPC_CONVERGED_CS_ABORTED = 5,
	IPC_CONVERGED_CS_ERROR = 6
};


/**
 * Message Type.
 */
enum ipc_converged_msg {
	/* Transfer Ring Open */
	IPC_CONVERGED_TR_OPEN = 1,

	/* Completion Ring Close (not supported now)
	 * IPC_CONVERGED_CR_CLOSE = 2,
	 */

	/* Transfer Ring Close */
	IPC_CONVERGED_TR_CLOSE = 3,

	/* Completion Ring Close (not supported now)
	 * IPC_CONVERGED_CR_CLOSE = 4,
	 */

	/* Transfer Ring Abort */
	IPC_CONVERGED_TR_ABORT = 5,

	/* Transfer Ring Update */
	IPC_CONVERGED_TR_UPDATE = 6,

	/* Completion Ring Update (not supported now)
	 * IPC_CONVERGED_CR_UPDATE = 7,
	 */

	/* Memory Map */
	IPC_CONVERGED_MEMORY_MAP = 8,

	/* Memory Unmap */
	IPC_CONVERGED_MEMORY_UNMAP = 9,

	/* Memory Update */
	IPC_CONVERGED_MEMORY_UPDATE = 10,

	/* Memory Notification */
	IPC_CONVERGED_MEMORY_NOTIFICATION = 11,

	/* Sleep */
	IPC_CONVERGED_SLEEP = 12,

	/* Vendor */
	IPC_CONVERGED_VENDOR = 13,

	/* Signal */
	IPC_CONVERGED_SIGNAL = 14,

	/* Snapshot */
	IPC_CONVERGED_SNAPSHOT = 15,

	/* Trap */
	IPC_CONVERGED_TRAP = 16,

	/* Time sync */
	IPC_CONVERGED_TIME_SYNC = 17,
};

enum ipc_converged_vendor_code {
	/**< AP ->CP: Intel feature configuration */
	IPC_FEATURE_SET = 0x01,
};


/**
 * Domain.
 */
enum ipc_converged_domain {
	IPC_CONVERGED_HOST = 0,
	IPC_CONVERGED_PERIPHERAL = 1,
};


/**
 * Time Unit
 */
enum ipc_converged_time_unit {
	IPC_CONVERGED_SEC = 0,
	IPC_CONVERGED_MILLI_SEC = 1,
	IPC_CONVERGED_MICRO_SEC = 2,
	IPC_CONVERGED_NANO_SEC = 3,
	IPC_CONVERGED_PICO_SEC = 4,
	IPC_CONVERGED_FEMTO_SEC = 5,
	IPC_CONVERGED_ATTO_SEC = 6,
	IPC_CONVERGED_TIME_UNIT_INVALID = 0xFFFFFFFF,
};


/**
 * Boot Stage
 */
enum ipc_converged_boot_stage {
	IPC_CONVERGED_ROM = 0,
	IPC_CONVERGED_SECONDARY_BOOT = 1,
	IPC_CONVERGED_OS = 2,
	IPC_CONVERGED_ABORT_HANDLER = 3,
	/* Vendor Specific 0x10000 To 0xFFFFFFFF */
	IPC_CONVERGED_VENDOR_SPECIFIC = 0x10000,
};


/**
 * IPC State
 */
enum ipc_converged_protocol_state {
	IPC_CONVERGED_UNINIT = 0,
	IPC_CONVERGED_INIT = 1,
	IPC_CONVERGED_RUNNING = 2,
	IPC_CONVERGED_RECOVERY = 3,
	IPC_CONVERGED_ERROR = 4,
};


/**
 * Sleep State
 */
enum ipc_converged_sleep_state {
	IPC_CONVERGED_SLEEP_ACTIVE = 0,
	IPC_CONVERGED_SLEEP_PERIPHERAL_SLEEP = 1,
	IPC_CONVERGED_SLEEP_PERIPHERAL_WAKE = 2,
	IPC_CONVERGED_SLEEP_HOST_SLEEP = 3
};


/**
 * Completion Type
 */
enum ipc_converged_completion_type {
	IPC_CONVERGED_COMPLETION_RING = 0,
	IPC_CONVERGED_COMPLETION_GROUP = 1,
};


/**
 * Descriptor Type Bitmask
 */
enum ipc_converged_desc_type_mask {
	DESC_TYPE_EXT_BUF_VALID = 1UL << 0,
	DESC_TYPE_OPT_FOOTER_VALLID = 1UL << 1,
	DESC_TYPE_NULL_DESCRIPTOR = 1UL << 2,
	DESC_TYPE_ASYNC_DESCRIPTOR = 1UL << 3
};


/**
 * Async Descriptor Type.
 */
enum ipc_converged_async_desc_type {
	ASYNC_DESC_TYPE_DOORBELL = 0,
	ASYNC_DESC_TYPE_TIME_EVENT = 1,
	ASYNC_DESC_TYPE_MEMORY_EVENT = 2
};


/* Completion status */
struct completion_status {
	/* Optimized completion */
	u8 optimized_completion:1;
	/* Status code from enum completion_status */
	u8 code:3;
	/* Not interpreted by converged IPC protocol */
	u8 not_interested:4;
} __attribute__ ((__packed__));


/**
 * Transfer descriptor definition for in place completion.
 */
struct ipc_converged_td {
	/* 7:0 Descriptor type: Bit mask of Descriptor type */
	u32 type:8;
	/* 8:31 Size of the buffer queued */
	u32 size:24;

	/* 64-bit address of a buffer in host memory */
	u64 address;

	/* Unique tag of thge buffer queued */
	u16 tag;

	/* Number of remaining TDs to describe the complete IO */
	u8 remaining_count;

	/* Completion status */
	struct completion_status status;
} __attribute__ ((__packed__));


/**
 * Completion descriptor definition for in place completion.
 */
struct ipc_converged_cd {
	/* 7:0 Descriptor type: Bit mask of Descriptor type */
	u32 type:8;
	/* 8:15 Completion status */
	struct completion_status status;
	/* 16:31 ID of the TR that the completion corresponds to. */
	u32 tr_id:16;

	/* 32:47 Unique tag of the buffer completed. */
	u64 tag:16;
	/* 48:71 Size of data transferred. */
	u64 size:24;
	/* 72:87 Count of number of descriptors completed when using optimized
	 * completion or Status of Block Overflow. When optimized completion of
	 * Status of Block Overflow is used with out of order completions or CG
	 * count is always nonzero. Otherwise, count must be zero.
	 */
	u64 completion_count:16;
	/* 95:88 Reserved */
	u64 reserved:8;

	/* 127:96 Describing data specific to client. Its not interpreted by
	 * the IPC.
	 */
	u32 client_data;

	/* 128:n Optional footer. Define member only if required */
} __attribute__ ((__packed__));


struct time_domain {
	/* Bit 0: If set, peripheral time. Else, host time */
	u8 peripheral:1;
	/* Bits 6:1: Enumeration of clock source */
	u8 source:7;
} __attribute__ ((__packed__));


/**
 * Completion Descriptor - Time Event
 */
struct ipc_converged_time_event_cd {
	/* 7:0 Descriptor type: Bit mask of Descriptor type */
	u32 type:8;
	/* 8:15 Async Descriptor of type ipc_converged_async_desc_type */
	u32 async_type:8;
	/* 16:23 Indicates the time domain and clock being used */
	struct time_domain domain;
	/* 31:24 Time unit of type ipc_converged_time_unit */
	u32 unit:8;

	/* 63:32 Sequence number */
	u32 sequence_nr;

	/* 127:64 Time */
	u64 time;

	/* 128:n Optional footer. Define member only if required */
} __attribute__ ((__packed__));


/**
 * Union of all type of Completion descriptors
 */
union ipc_completion_desc {
	struct ipc_converged_cd cd;
	struct ipc_converged_time_event_cd time_evt;
};


/**
 * Transfer Ring (TR) Open Message
 */
struct ipc_converged_tr_open {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u8 type;
	/* Size of optional header in TD */
	u8 optional_header_size;
	/* Size of optional Footer in TD */
	u8 optional_footer_size;
	u8 reserved;

	/* Ring ID this message is for */
	u16 ring_id;
	/* Index array vector to use for the Ring */
	u16 index_array_vector;

	/* 64-bit address of Ring in host memory */
	u64 ring_address;

	/* 64-bit address of Buffer size ring in host memory.
	 * Value 0 in this field means it is unused for this TR.
	 */
	u64 buf_size_ring_addr;

	/* Number of TDs in the ring */
	u16 entries;
	/* ID of the completion ring which corresponds to the TR */
	u16 completion_id;

	/* The Doorbell Vector associated with the TR.
	 * 0xFF (all 1's in this field) means not Doorbell Vector associated
	 * with this ring.
	 */
	u32 doorbell_vector:16;
	/* Provides the peripheral the PCIe Traffic Class associated with
	 * the TR
	 */
	u32 pcie_traffic_class:3;
	/* Opimized completion enabled/disabled */
	u32 optimized_completion:1;
	/* Reliable TR */
	u32 reliable:1;
	/* Out of Order Completion */
	u32 out_of_order_completion:1;
	/* Indicates whether in place completion is used for th TR */
	u32 in_place_completion:1;
	/* Indicates whether this is a Virtual TR */
	u32 virtual_tr:1;
	/* Indicates whether TR is associated with Synchronized UL DL. */
	u32 synchronized:1;
	/* Indicates whether a Completion ID is associated with a Ring. */
	u32 completion_type:1;
	/* Indicates whether Buffer Size Ring Entry shall indicate chanied TDs
	 * via most significant bit.
	 */
	u32 buf_size_ring_entry_chain:1;
	/* Indicates size in bytes of each entry in Buffer with max
	 * value of 4
	 */
	u32 buf_size_ring_entry_width:3;
	u32 reserved1:2;

	/* This field provides the peripheral the priority with which data
	 * shall be dequeued from the TR
	 */
	u32 priority;

	/* The MSI which shall be generated by the peripheral after updating
	 * TR TIA entry. Max value (all bits 1) means no MSI vector associated
	 * with the ring
	 */
	u16 msi_vector;
	/* After updating the TR TIA, the maximum time, in usec, after which
	 * an MSI shall be gernated by peripheral.
	 *  -- 0 means MSI moderation disabled
	 *  -- All bits 1's timer value is infinite
	 */
	u16 msi_moderation_delay;

	/* AFter updating the TR TIA entry, the maximum number of bytes
	 * corresponding to the TD, after which an MSI shall be generated.
	 * All bits 1's means value is infinite.
	 */
	u32 msi_moderation_bytes;

	/* Accumulation delay. After receiving DL data, the maximum time,
	 * usec, after which the peripheral shall transfer the data over the
	 * link and complete the buffer.
	 * -- All bits 1 means timer value is infinite.
	 * -- 0 means accumulation is diabled.
	 */
	u16 accumulation_delay;

	/* The maximum number of bytes of DL data accumulated after
	 * which the peripheral shall transfer the data over the link and
	 * complete the buffer
	 */
	u32 accumulation_bytes;

	u16 reserved2;

	/* Optional field, describing data specific to client. Its not
	 * interpreted by the IPC. Size is indicated by the TD pointing to the
	 * message.
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));


/**
 * Transfer Ring (TR) Close Message
 */
struct ipc_converged_tr_close {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* Ring ID this message is for */
	u32 ring_id:16;
} __attribute__ ((__packed__));


/**
 * Transfer Ring (TR) Abort Message
 */
struct ipc_converged_tr_abort {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* Ring ID this message is for */
	u32 ring_id:16;

	/* Indicates if aborting a specific buffer or all the buffers
	 * associated with TR.
	 */
	u32 valid_tag:1;
	u32 reserved1:15;
	/* Unique tag of the buffer to be aborted. */
	u32 tag:16;
} __attribute__ ((__packed__));


/**
 * Transfer Ring (TR) Update Message
 */
struct ipc_converged_tr_update {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:24;

	/* Ring ID this message is for */
	u16 ring_id;
	/* 24 Bytes reserved */
	u8 reserved1[24];
	/* Provides the peripheral the PCIe Traffic Class associated with
	 * the TR
	 */
	u16 pcie_traffic_class:3;
	u16 reserved2:13;

	/* This field provides the peripheral the priority with which data
	 * shall be dequeued from the TR
	 */
	u32 priority;


	u16 reserved3;
	/* After updating the TR TIA, the maximum time, in usec, after which
	 * an MSI shall be gernated by peripheral.
	 *  -- 0 means MSI moderation disabled
	 *  -- All bits 1's timer value is infinite
	 */
	u16 msi_moderation_delay;

	/* AFter updating the TR TIA entry, the maximum number of bytes
	 * corresponding to the TD, after which an MSI shall be generated.
	 * All bits 1's means value is infinite.
	 */
	u32 msi_moderation_bytes;

	/* Accumulation delay. After receiving DL data, the maximum time,
	 * usec, after which the peripheral shall transfer the data over the
	 * link and complete the buffer.
	 * -- All bits 1 means timer value is infinite.
	 * -- 0 means accumulation is diabled.
	 */
	u16 accumulation_delay;

	/* The maximum number of bytes of DL data accumulated after
	 * which the peripheral shall transfer the data over the link and
	 * complete the buffer
	 */
	u32 accumulation_bytes;

	u16 reserved4;

	/* Optional field, describing data specific to client. Its not
	 * interpreted by the IPC. Size is indicated by the TD pointing to the
	 * message.
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));


/**
 * Memory Map Message
 */
struct ipc_converged_memory_map {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* ID of the shared memory region this message is for. */
	u32 region_id:16;

	/* Size of the shared memory region. */
	u32 size;

	/* 64-bit address of shared memory region in host memory */
	u64 address;

	/* This field provides the peripheral the priority with which data
	 * shall be processed in the shared memory region.
	 */
	u32 priority;

	/* Provides the peripheral the PCIe Traffic Class associated with
	 * the shared memory region
	 */
	u32 pcie_traffic_class:3;
	u32 reserved2:29;

	/* Optional field, describing data specific to client. Its not
	 * interpreted by the IPC. Size is indicated by the descriptor pointing
	 * to the message.
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));


/**
 * Memory Unmap Message
 */
struct ipc_converged_memory_unmap {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* ID of the shared memory region this message is for. */
	u32 region_id:16;
} __attribute__ ((__packed__));


/**
 * Memory Notification Message
 */
struct ipc_converged_memory_notification {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* ID of the shared memory region this message is for. */
	u32 region_id:16;

	/* Optional field, describing data specific to client. Its not
	 * interpreted by the IPC. Size is indicated by the descriptor pointing
	 * to the message.
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));


/**
 * Sleep Message
 */
struct ipc_converged_sleep {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	/* This field is used by the host to indicate whether this message
	 * is targeting the host or the peripheral. Possible value are from
	 * the enum ipc_converged_domain.
	 */
	u32 domain:8;
	/* This field is used to indicate enter or exit sleep.
	 *  Possible values are from enum ipc_converged_sleep_type.
	 */
	u32 sleep_type:8;
	u32 reserved:8;

} __attribute__ ((__packed__));

/**
 * Vendor Message
 */
struct ipc_converged_vendor {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	/* Identifying the unique vendor message. */
	u32 code:8;
	u32 reserved:16;
	/* Optional field, describing data specific to message code.
	 * Size is indicated by the descriptor pointing to the message.
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));


/**
 * Signal Message
 */
struct ipc_converged_signal {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	/* This field is used by host to indicate signal state. */
	u32 state:8;
	/* This field is used by host to identify the signal */
	u32 signal:16;
} __attribute__ ((__packed__));

/**
 * Snapshot Message
 */
struct ipc_converged_snapshot {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:24;

	/* Size of the buffer in host memory. Peripheral prior to completing
	 * the message, updates this to indicate amount of valid data in buffer.
	 */
	u32 size;

	/* 64-bit address of buffer in host memory. */
	u64 address;
} __attribute__ ((__packed__));

/**
 * Trap Message
 */
struct ipc_converged_trap {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:24;
} __attribute__ ((__packed__));


/**
 * Time Sync Message
 */
struct ipc_converged_tsync {
	/* Type of the message. Supported messages are defined in
	 * enum ipc_converged_msg
	 */
	u32 type:8;
	u32 reserved:8;
	/* Indicates the time domain and clock being used.
	 * Bit 0: If set, peripheral time. Else, host time.
	 * Bits 6:1: Enumeration of clock source
	 */
	u32 time_domain:8;
	/* This field is used to indicate the time unit.
	 * Possible values are from enum ipc_converged_time_unit
	 */
	u32 time_unit:8;

	/* This field contains the sequence number */
	u32 sequence_number;

	/* This field contains the time payload. */
	u64 time;

	/* Optional field, describing data specific to message code.
	 * Size is indicated by the TD pointing to the message
	 */
	u32 client_data[1];
} __attribute__ ((__packed__));

/**
 * Context Information
 */
struct ipc_converged_ci {
	/* The host provides the version of the Context Information being
	 * used.
	 */
	u32 version:16;
	/* The host provides the size of the Context Information */
	u32 size:16;

	/* The host provides the Configuration with which wants the peripheral
	 * to execute. This is subset of Capability register published by the
	 * peripheral.
	 */
	u32 configuration;

	/* The host provides the address of the Peripheral Information structure
	 * in this field.
	 */
	u64 peripheral_info_addr;

	/* The host provides the address of the CR Head Index Array in this
	 * field.
	 */
	u64 cr_hia_addr;

	/* The host provides the address of the TR Tail Index Array in this
	 * field.
	 */
	u64 tr_tia_addr;

	/* The host provides the address of the CR Tail Index Array in this
	 * field.
	 */
	u64 cr_tia_addr;

	/* The host provides the address of the TR Head Index Array in this
	 * field.
	 */
	u64 tr_hia_addr;

	/* The host provides num entries in the CR index arrays. */
	u32 cr_index_array_entries:16;
	/* The host provides num entries in the TR index arrays. */
	u32 tr_index_array_entries:16;

	/* The host provides the address of the message completion ring
	 * in this field.
	 */
	u64 message_cr_addr;

	/* The host provides the address of the message transfer ring in
	 * this field.
	 */
	u64 message_tr_addr;

	/* This field provides the number of entries which the MTR can hold. */
	u32 message_tr_entries:16;
	/* This field provides the number of entries which the MCR can hold. */
	u32 message_cr_entries:16;

	/* The Doorbell Vector associated with the MTR. */
	u32 msg_tr_doorbell_vector:16;
	/* The Doorbell Vector associated with the MCR. */
	u32 msg_cr_doorbell_vector:16;

	/* This field provides the MSI which shall be generated by the
	 * peripheral after completing a TD in the MTR.
	 */
	u32 msg_tr_msi_vector:16;
	/* This field provides the MSI which shall be generated by the
	 * peripheral when queuing a CD in the MCR.
	 */
	u32 msg_cr_msi_vector:16;

	/* Size of the Optional Header in the TD associated with the MTR. Value
	 * is in multiple of 4 bytes i.e. value of 0 means no optional header,
	 * value 1 means optional header of 4bytes etc
	 */
	u32 msg_tr_opt_header_size:8;
	/* Size of the Optional Footer in the TD associated with the MTR. Value
	 * is in multiple of 4 bytes i.e. value of 0 means no optional data,
	 * value 1 means optional data of 4bytes etc.
	 */
	u32 msg_tr_opt_footer_size:8;
	/* Size of the Optional Header in the CD associated with the MCR. Value
	 * is in multiple of 4 bytes i.e. value of 0 means no optional header,
	 * value 1 means optional header of 4bytes etc
	 */
	u32 msg_cr_opt_header_size:8;
	/* Size of the Optional Footer in the CD associated with the MCR. Value
	 * is in multiple of 4 bytes i.e. value of 0 means no optional data,
	 * value 1 means optional data of 4bytes etc
	 */
	u32 msg_cr_opt_footer_size:8;

	/* Indicates whether out of order completions allowed for the MTR. */
	u32 out_of_order_completion:1;
	/* Indicates whether in place completion is used */
	u32 in_place_completion:1;
	u32 reserved:14;
	/* This field provides the MSI which shall be generated by the
	 * peripheral after updating the Peripheral Information structure.
	 */
	u32 peripheral_info_msi_vector:16;

	/* This field provides the address of the scratch space available for
	 *the peripheral.
	 */
	u64 scratch_space_addr;

	/* This field provides the size of the scratch space available for the
	 * peripheral.
	 */
	u32 scratch_space_size;

	/* Reserved */
	u32 reserved1;
} __attribute__ ((__packed__));


/**
 * Peripheral Information
 */
struct ipc_converged_peripheral_info {
	/* This field reflects the value in the boot stage register in MMIO.
	 * Possible values are from enum ipc_converged_boot_stage
	 */
	u32 boot_stage_mirror;

	/* This field reflects the value in the IPC Status register in MMIO.
	 * Possible values are from enum ipc_converged_protocol_state.
	 */
	u32 ipc_status_mirror;

	/* This field indicates the peripheral’s sleep request.
	 * Possible values are from enum ipc_converged_sleep_state
	 */
	u32 sleep_notification;

	u32 reserved;
} __attribute__ ((__packed__));


/* Converged Protocol Shared Memory Structure
 */
struct ipc_converged_ap_shm {
	struct ipc_converged_ci context_info;
	struct ipc_converged_peripheral_info peripheral_info;
	ipc_converged_hia_t cr_hia[IPC_CONVERGED_CR_HIA_SIZE];
	ipc_converged_tia_t tr_tia[IPC_CONVERGED_TR_TIA_SIZE];
	ipc_converged_tia_t cr_tia[IPC_CONVERGED_CR_TIA_SIZE];
	ipc_converged_hia_t tr_hia[IPC_CONVERGED_TR_HIA_SIZE];
	struct ipc_converged_td msg_ring[IPC_MEM_MSG_ENTRIES];
	union ipc_completion_desc msg_compl_ring[MSG_CR_ENTRIES];
};


/* Data structure for storage of allocated/mapped CP messages */
struct ipc_converged_local_msg {
	void      *msg;
	u64        addr;
	size_t	   size;
	u32        id;
};

/* Converged Protocol instance data
 */
struct ipc_converged {
	struct ipc_converged_ap_shm *p_ap_shm;
	/* Physical/Mapped representation of the shared memory information.
	 */
	u64 phy_ap_shm;
	ipc_converged_tia_t msg_tr_old_tail_index;
	ipc_converged_hia_t msg_tr_old_head_index;
	ipc_converged_hia_t msg_cr_old_head_index;
	u32 msg_td_tag;

	/* Power management */
	struct ipc_pm *pm;

	struct ipc_pcie *p_pcie;
	struct ipc_debugfs_stats *p_stats;

	struct ipc_converged_local_msg local_msg_ring[IPC_MEM_MSG_ENTRIES];

	/* pointer to ipc_dbg structure */
	struct ipc_dbg *dbg;

	struct ipc_mmio *mmio;

	/* Device supports MCR or not */
	bool mcr_supported;

	/* Timestamp completion object */
	struct ipc_completion ts_completion;

	/* Last reported remote time ID */
	u32 last_ts_id;

	/* Pointer to hold client's address interested in device timestamp. */
	u64 last_remote_time;

	/* Time unit of last reported remote timestamp */
	enum ipc_converged_time_unit last_time_unit;

	/* Crtitical section lock used while getting remote timestamp */
	spinlock_t ts_lock;

	/* Pointer of variable that gives Timesync Doorbell triggered or not */
	bool *p_ts_db_trig;
};


/**
 * Allocate a new message element
 *
 * @this: Pointer to ipc_converged instance
 * @size: size of the message to allocate
 * @index: Pointer to index result.
 *         On success, will be set to index of the allocated message
 *
 * returns Pointer to ipc_mem_msg_entry or NULL if no space is available
 */
static void *ipc_converged_msg_alloc(struct ipc_converged *this,
	size_t size, int *index)
{
	ipc_converged_hia_t head = this->msg_tr_old_head_index;
	ipc_converged_hia_t new_head = (head + 1) % IPC_MEM_MSG_ENTRIES;
	struct ipc_converged_td *p_td = &this->p_ap_shm->msg_ring[head];
	u64 addr = 0;
	void *msg;

	if (unlikely(new_head == this->p_ap_shm->tr_tia[MSG_TR_IDX])) {
		ipc_err("message ring is full");
		return NULL;
	}

	msg = ipc_pcie_kzalloc(this->p_pcie, size, &addr);

	if (unlikely(!msg)) {
		ipc_err("kzalloc failed");
		return NULL;
	}

	/* Store location and size of allocated message */
	this->local_msg_ring[head].addr = addr;
	this->local_msg_ring[head].msg = msg;
	this->local_msg_ring[head].size = size;
	this->local_msg_ring[head].id = this->msg_td_tag;

	/* Preset common message fields */
	p_td->type = DESC_TYPE_EXT_BUF_VALID;
	p_td->size = size;
	p_td->address = addr;
	p_td->tag = this->msg_td_tag;
	p_td->status.code = IPC_CONVERGED_CS_INVALID;
	p_td->remaining_count = 0;

	/* update unique message tag */
	this->msg_td_tag++;

	ipc_dbg("index=%d, tag=%d, size=%d", head, p_td->tag, p_td->size);

	/* return index */
	*index = head;

	return msg;
}

/**
 * Send a message to the device by increasing the head pointer index
 * in the message ring and triggering a hpda doorbell interrupt
 */
static void ipc_converged_msg_hp_update(void *instance)
{
	struct ipc_converged *this = instance;
	ipc_converged_hia_t head = this->msg_tr_old_head_index;
	ipc_converged_hia_t new_head = (head + 1) % IPC_MEM_MSG_ENTRIES;

	ipc_dbg("old_head=%d, new_head=%d, tail_tia=%d",
		this->msg_tr_old_head_index, new_head,
		this->p_ap_shm->tr_tia[MSG_TR_IDX]);

	/* Update head pointer and fire doorbell.
	 */
	this->p_ap_shm->tr_hia[MSG_TR_IDX] = new_head;
	this->msg_tr_old_head_index = new_head;

	/* Trigger the irq on CP if link accessible.
	 */
	ipc_pm_signal_hpda_doorbell(this->pm, IPC_HP_MR);
}

/**
 * Allocate and prepare a TR_OPEN message.
 * This also allocates the memory for the new TR structure and
 * updates the pipe structure referenced in the preparation arguments.
 */
static int ipc_converged_msg_prep_pipe_open(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_converged_tr_open *msg;
	struct ipc_pipe *p_pipe = args->pipe_open.pipe;
	struct ipc_converged_td *p_tr;
	struct sk_buff **pp_skbr;

	if (unlikely(p_pipe->pipe_nr == 0)) {
		ipc_err("RingID 0 reserved for Message Ring");
		return -1;
	}

	/* Allocate the skbuf elements for the skbuf which are on the way.
	 * SKB ring is internal memory allocation for driver. No need to
	 * re-calculate the start and end addresses.
	 */
	pp_skbr = ipc_util_kzalloc_atomic(
			p_pipe->nr_of_entries * sizeof(*pp_skbr));
	if (unlikely(!pp_skbr)) {
		ipc_err("alloc failed");
		return -1;
	}

	p_tr = ipc_pcie_kzalloc(this->p_pcie,
		p_pipe->nr_of_entries * sizeof(*p_tr), &p_pipe->phy_tdr_start);
	if (unlikely(!p_tr)) {
		ipc_err("tdr alloc error");
		goto tr_fail;
	}

	msg = ipc_converged_msg_alloc(this,  sizeof(*msg), &index);
	if (unlikely(!msg)) {
		ipc_err("failed to allocated message");
		goto msg_fail;
	}

	p_pipe->max_nr_of_queued_entries = p_pipe->nr_of_entries - 1;
	p_pipe->nr_of_queued_entries = 0;
	p_pipe->p_tr_start = p_tr;
	p_pipe->skbr_start = pp_skbr;

	msg->type = IPC_CONVERGED_TR_OPEN;

	/* As per the alignment with CP team the Ring ID and Pipe# are same */
	msg->ring_id = p_pipe->pipe_nr;

	/* It is not necessary the index_array_vector to be same as ring_id.
	 * But it can be used for index_array_vector for convenient.
	 */
	msg->index_array_vector = msg->ring_id;

	msg->ring_address = p_pipe->phy_tdr_start;
	msg->entries = p_pipe->nr_of_entries;
	msg->doorbell_vector = -1;
	msg->optimized_completion = 1;
	msg->reliable = 1;
	msg->in_place_completion = 1;

	/* UL DL Synchronization is not supported from Modem at the Moment.
	 * Instead of this DL bundling timer is used.
	 */
	msg->synchronized = 0;
	msg->completion_type = IPC_CONVERGED_COMPLETION_RING;
	msg->msi_vector = p_pipe->irq;
	msg->msi_moderation_delay = p_pipe->irq_moderation;
	msg->msi_moderation_bytes = -1;
	msg->accumulation_delay = p_pipe->accumulation_backoff;
	msg->client_data[0] = 0;

	ipc_dbg("IPC_CONVERGED_TR_OPEN(ring_id=%d, entries=%d, msi_vector=%d)",
		msg->ring_id, msg->entries, msg->msi_vector);

	return index;

msg_fail:
	ipc_pcie_kfree(this->p_pcie, p_tr,
		p_pipe->nr_of_entries * sizeof(struct ipc_converged_td),
		p_pipe->phy_tdr_start);
tr_fail:
	ipc_util_kfree(pp_skbr);

	return -1;
}

/**
 *  Allocate and prepare a TR_CLOSE message
 */
static int ipc_converged_msg_prep_pipe_close(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_pipe *p_pipe = args->pipe_close.pipe;
	struct ipc_converged_tr_close *msg;

	if (unlikely(p_pipe->pipe_nr == 0 || p_pipe->pipe_nr == 1)) {
		ipc_err("RingID 0 & 1 reserved for Message Ring");
		return -1;
	}

	msg = ipc_converged_msg_alloc(this, sizeof(*msg), &index);
	if (unlikely(!msg)) {
		ipc_err("failed to allocated message");
		return -1;
	}

	msg->type = IPC_CONVERGED_TR_CLOSE;

	/* As per the alignment with CP team the Ring ID and Pipe# are same */
	msg->ring_id = p_pipe->pipe_nr;

	ipc_dbg("IPC_CONVERGED_TR_CLOSE(ring_id=%d)", msg->ring_id);

	return index;
}

/**
 *  Trigger host sleep signaling. This is not sending any messages in the
 *  converged protocol implementation.
 */
static int ipc_converged_msg_prep_host_sleep(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	/* host sleep does not trigger any messages */
	if (args->sleep.state == IPC_HOST_SLEEP_ENTER_SLEEP) {
		ipc_pm_trigger_host_sleep(this->pm);
		return -2;
	}

	if (args->sleep.state == IPC_HOST_SLEEP_EXIT_SLEEP) {
		ipc_pm_trigger_host_active(this->pm);
		return -2;
	}

	ipc_err("state=%d unsupported", args->sleep.state);

	return -1;
}

/**
 * Allocate and prepare a SLEEP/PERIPHERAL message
 */
static int ipc_converged_msg_prep_target_sleep(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_converged_sleep *msg =
		ipc_converged_msg_alloc(this, sizeof(*msg), &index);

	if (unlikely(!msg)) {
		ipc_err("Couldn't alloc memory for Sleep msg");
		return -1;
	}

	msg->type = IPC_CONVERGED_SLEEP;
	msg->domain = IPC_CONVERGED_PERIPHERAL;
	msg->sleep_type = args->sleep.state;

	ipc_dbg("IPC_CONVERGED_SLEEP(type=%d, domain=%d, sleep_type=%d)",
		msg->type, msg->domain, msg->sleep_type);

	return index;
}

/**
 * Handle both host and device sleep message preparation.
 */
static int ipc_converged_msg_prep_sleep(struct ipc_converged *this,
		union ipc_msg_prep_args *args)
{
	return args->sleep.target == IPC_HOST_SLEEP_HOST ?
		ipc_converged_msg_prep_host_sleep(this, args) :
		ipc_converged_msg_prep_target_sleep(this, args);
}

/**
 * Allocate and prepare a VENDOR/FEATURE_SET message
 */
static int ipc_converged_msg_prep_feature_set(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_converged_vendor *msg =
		ipc_converged_msg_alloc(this, sizeof(*msg), &index);

	if (unlikely(!msg)) {
		ipc_err("failed to allocated new message");
		return -1;
	}

	msg->type = IPC_CONVERGED_VENDOR;
	msg->code = IPC_FEATURE_SET;
	msg->client_data[0] = args->feature_set.reset_enable;

	ipc_dbg("IPC_CONVERGED_VENDOR(code=%d, client_data[0]=%d)",
		msg->code, msg->client_data[0]);

	return index;
}

/**
 * Allocate and prepare a MEMORY_MAP message
 */
static int ipc_converged_msg_prep_map(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_converged_memory_map *msg =
		ipc_converged_msg_alloc(this, sizeof(*msg), &index);

	if (unlikely(!msg)) {
		ipc_err("failed to allocated new message");
		return -1;
	}

	msg->type = IPC_CONVERGED_MEMORY_MAP;
	msg->region_id = args->map.region_id;
	msg->size = args->map.size;
	msg->address = args->map.addr;
	msg->priority = 0;
	msg->pcie_traffic_class = 0;
	msg->client_data[0] = 0;

	ipc_dbg("IPC_CONVERGED_MEMORY_MAP(region_id=%u, size=%u, address=%llx",
		msg->region_id, msg->size, msg->address);

	return index;
}

/**
 * Allocate and prepare a MEMORY_UNMAP message
 */
static int ipc_converged_msg_prep_unmap(struct ipc_converged *this,
	union ipc_msg_prep_args *args)
{
	int index = -1;
	struct ipc_converged_memory_unmap *msg =
		ipc_converged_msg_alloc(this, sizeof(*msg), &index);

	if (unlikely(!msg)) {
		ipc_err("failed to allocated new message");
		return -1;
	}

	msg->type = IPC_CONVERGED_MEMORY_UNMAP;
	msg->region_id = args->unmap.region_id;

	ipc_dbg("IPC_CONVERGED_MEMORY_UNMAP(region_id=%u", msg->region_id);

	return index;
}

static int ipc_converged_msg_prep(void *instance,
	enum ipc_msg_prep_type msg_type, union ipc_msg_prep_args *args)
{
	struct ipc_converged *this = instance;

	if (unlikely(!this || !args)) {
		ipc_err("invalid arguments");
		return -1;
	}

	switch (msg_type) {

	case IPC_MSG_PREP_SLEEP:
		return ipc_converged_msg_prep_sleep(this, args);

	case IPC_MSG_PREP_PIPE_OPEN:
		return ipc_converged_msg_prep_pipe_open(this, args);

	case IPC_MSG_PREP_PIPE_CLOSE:
		return ipc_converged_msg_prep_pipe_close(this, args);

	case IPC_MSG_PREP_FEATURE_SET:
		return ipc_converged_msg_prep_feature_set(this, args);

	case IPC_MSG_PREP_MAP:
		return ipc_converged_msg_prep_map(this, args);

	case IPC_MSG_PREP_UNMAP:
		return ipc_converged_msg_prep_unmap(this, args);

	default:
		ipc_err("unsupported message type:%d in converged protocol",
			msg_type);
		return -1;
	}
}

/* Convert converged spec message status into old IPC_MEM_MSG_CS status
 */
static enum ipc_mem_msg_cs ipc_converged_status_to_msg_cs(
			struct ipc_converged *this, unsigned int status)
{
	switch (status) {
	case IPC_CONVERGED_CS_END_TRANSFER:
		return IPC_MEM_MSG_CS_SUCCESS;
	case IPC_CONVERGED_CS_ERROR:
		return IPC_MEM_MSG_CS_ERROR;
	default:
		ipc_err("invalid status %d", status);
		return IPC_MEM_MSG_CS_INVALID;
	}
}


/**
 * This function processes Time Event async completion descriptor.
 *
 * @this: Pointer to ipc_converged instance.
 * @p_cd: Pointer to completion descriptor.
 *
 * @returns None
 */
static void ipc_converged_process_time_evt_cd(struct ipc_converged *this,
		union ipc_completion_desc *p_cd)
{

	if (unlikely(!this || !p_cd)) {
		ipc_err("Invalid args");
		return;
	}

	if (p_cd->time_evt.domain.peripheral == 0) {
		ipc_err("Expected Time Event for Peripheral Time domain but got Host");
		return;
	}

	ipc_dbg("Time Unit: %u, Seq Nr.: %u, Time: %llu",
		p_cd->time_evt.unit,
		p_cd->time_evt.sequence_nr,
		p_cd->time_evt.time);

	/* Try lock returns non-zero if it succeeds in getting the lock. If the
	 * lock is already taken then it returns 0. Return 0 means the
	 * completion object might have timedout. If so then no need to update
	 * anything.
	 */
	if (spin_trylock(&this->ts_lock)) {
		this->last_remote_time = p_cd->time_evt.time;
		this->last_ts_id = p_cd->time_evt.sequence_nr;
		this->last_time_unit = (enum ipc_converged_time_unit)
			p_cd->time_evt.unit;

		/* Inform waiting app that device timestamp is available only
		 * if any user app is waiting after Timesync Doorbell is
		 * triggered.
		 */
		if (this->p_ts_db_trig && *this->p_ts_db_trig)
			ipc_completion_signal(&this->ts_completion);

		spin_unlock(&this->ts_lock);
	}
}


/**
 * This function processes async completion descriptors.
 *
 * @this: Pointer to ipc_converged instance.
 * @p_cd: Pointer to completion descriptor.
 *
 * @returns None
 */
static void ipc_converged_process_async_cd(struct ipc_converged *this,
		union ipc_completion_desc *p_cd)
{
	if (p_cd->time_evt.async_type == ASYNC_DESC_TYPE_TIME_EVENT)
		ipc_converged_process_time_evt_cd(this, p_cd);
}


/**
 * Function looks for Completion Status in MTR if MCR is not supported.
 * If MCR is supported then waiting for Completion object will be notified
 * if the CD tag matches with any of the pending TD tag to be processed.
 *
 * @this: Pointer to ipc_converged instance.
 * @p_cd: Pointer to completion descriptor.
 * @tr_tail_idx: Tail index of Message Transfer Ring.
 * @rsp_ring: pointer to response ring array
 *
 * @returns true if any of the message is processed false otherwise
 */
static bool ipc_converged_process_msg_cs(struct ipc_converged *this,
		union ipc_completion_desc *p_cd,
		ipc_converged_tia_t tr_tail_idx, struct ipc_rsp **rsp_ring)
{
	ipc_converged_tia_t i;
	struct ipc_converged_td *p_td = NULL;
	struct ipc_converged_local_msg *p_local_msg = NULL;
	struct completion_status cs;
	bool processed = false;

	if (unlikely(tr_tail_idx >= IPC_MEM_MSG_ENTRIES)) {
		ipc_err("msg ring tail index out of range: %u", tr_tail_idx);
		return false;
	}

	if (this->mcr_supported) {
		if (!p_cd) {
			ipc_err("Invalid arguments");
			return false;
		}

		if (p_cd->cd.tr_id != MSG_TR_IDX)
			/* CD is not for MSG Ring */
			return false;
	}

	for (i = this->msg_tr_old_tail_index; i != tr_tail_idx;
	i = (i + 1) % IPC_MEM_MSG_ENTRIES) {
		p_td = &this->p_ap_shm->msg_ring[i];
		p_local_msg = &this->local_msg_ring[i];

		/* Update response with status and wake up waiting requestor */
		if (this->mcr_supported) {
			if (p_td->tag != p_cd->cd.tag)
				continue;

			if (p_td->size != p_cd->cd.size) {
				ipc_err("TD size(%d) not matching with CD size(%d)",
					p_td->size, p_cd->cd.size);

				/* Deliberately not processing CD */
				/* continue; */
			}

			/* Completion Descriptor TD tag is matching with one of
			 * pending Transfer descriptor TD tag.
			 */
			cs.code = p_cd->cd.status.code;
		} else {
			cs.code = p_td->status.code;
		}

		ipc_dbg("TR ID: %d, Tag: %u, CS: %u", MSG_TR_IDX,
			p_td->tag, cs.code);

		if (rsp_ring[i]) {
			rsp_ring[i]->status = ipc_converged_status_to_msg_cs(
				this, cs.code);
			ipc_completion_signal(&rsp_ring[i]->completion);
			rsp_ring[i] = NULL;
		}

		/* Free allocated message */
		ipc_pcie_kfree(this->p_pcie, p_local_msg->msg,
				p_local_msg->size, p_local_msg->addr);

		memset(p_local_msg, 0, sizeof(*p_local_msg));

		processed = true;

		/* If MCR supported then no need to further scan the pending
		 * TDs. We can exit the loop
		 */
		if (this->mcr_supported)
			break;
	}

	return processed;
}


/**
 * Function for processing the consumed message from Message Completion Ring
 *
 * @this: Pointer to ipc_converged instance.
 * @tr_tail_idx: Tail index of Message Transfer Ring.
 * @rsp_ring: pointer to response ring array
 *
 * @returns true if any of the message is processed false otherwise
 */
static bool ipc_converged_msg_cr_process(struct ipc_converged *this,
	ipc_converged_tia_t tr_tail_idx, struct ipc_rsp **rsp_ring)
{
	ipc_converged_hia_t old_head = this->msg_cr_old_head_index;
	ipc_converged_hia_t head = this->p_ap_shm->cr_hia[MSG_CR_IDX];
	ipc_converged_tia_t tail = this->p_ap_shm->cr_tia[MSG_CR_IDX];
	union ipc_completion_desc *p_cd;
	bool processed = false;

	if (unlikely(head >= MSG_CR_ENTRIES)) {
		ipc_err("MCR Head index out of range: %u", head);
		return false;
	}

	while (old_head != head) {
		p_cd = &this->p_ap_shm->msg_compl_ring[old_head];

		switch (p_cd->cd.type) {
		case (DESC_TYPE_ASYNC_DESCRIPTOR):
			/* Process Async CDs of type Time Event, Doorbell
			 * Control or Memory event.
			 */
			ipc_converged_process_async_cd(this, p_cd);
			processed = true;
			break;

		case (DESC_TYPE_EXT_BUF_VALID):
			/* Process Completion Descriptor corresponding to MTRs
			 */
			processed |= ipc_converged_process_msg_cs(this, p_cd,
					tr_tail_idx, rsp_ring);
			break;

		default:
			ipc_err("Unknown CD Type: %d", p_cd->cd.type);
			break;
		}

		tail++;
		old_head = (old_head + 1) % MSG_CR_ENTRIES;
	}

	if (processed) {
		/* Provide the CDs back to Modem */
		this->p_ap_shm->cr_tia[MSG_CR_IDX] = tail % MSG_CR_ENTRIES;

		ipc_dbg("MCR:: old_head=%u, head=%u, tail=%u",
			this->msg_cr_old_head_index, head, tail);

		this->msg_cr_old_head_index = old_head;
	}

	return processed;
}


/**
 * Function for processing the consumed message from Message Transfer Ring
 *
 * @this: Pointer to ipc_converged instance.
 * @tr_tail_idx: Tail index of Message Transfer Ring.
 * @rsp_ring: pointer to response ring array
 *
 * @returns true if any of the message is processed false otherwise
 */
static bool ipc_converged_msg_tr_process(void *instance,
	ipc_converged_tia_t tr_tail_idx, struct ipc_rsp **rsp_ring)
{
	struct ipc_converged *this = instance;
	bool processed = false;

	if (unlikely(tr_tail_idx >= IPC_MEM_MSG_ENTRIES)) {
		ipc_err("MTR Tail Index out of range: %u", tr_tail_idx);
		return false;
	}

	/* If MCR is supported by device then Completion Status is already
	 * processed during MCR processing. No need to check here.
	 */
	if (!this->mcr_supported)
		processed = ipc_converged_process_msg_cs(this, NULL,
				tr_tail_idx, rsp_ring);

	this->msg_tr_old_tail_index = tr_tail_idx;

	return processed;
}


/**
 * Function for processing the consumed message from CP.
 * Message Completion Ring will be looked for Completion Status if device
 * supports MCR.
 *
 * @this: Pointer to ipc_converged instance.
 * @irq: IRQ number
 * @rsp_ring: pointer to response ring array
 *
 * returns true if any of the message processed otherwise false
 */
static bool ipc_converged_msg_process(void *instance, int irq,
	struct ipc_rsp **rsp_ring)
{
	bool msg_processed = false;
	struct ipc_converged *this = instance;
	int msi_vector;
	ipc_converged_tia_t tr_tail_idx;

	if (unlikely(!this || !rsp_ring)) {
		ipc_err("Invalid arguments");
		return false;
	}

	msi_vector = this->mcr_supported ?
		this->p_ap_shm->context_info.msg_cr_msi_vector :
		this->p_ap_shm->context_info.msg_tr_msi_vector;

	if (irq != IMEM_IRQ_DONT_CARE && irq != msi_vector)
		return false;

	tr_tail_idx = this->p_ap_shm->tr_tia[MSG_TR_IDX];

	if (this->mcr_supported)
		msg_processed = ipc_converged_msg_cr_process(instance,
					tr_tail_idx, rsp_ring);

	msg_processed |= ipc_converged_msg_tr_process(instance, tr_tail_idx,
				rsp_ring);

	return msg_processed;
}


/**
 * Sends data from UL list to CP for the provided pipe by updating the Head
 * pointer of given pipe.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 * @p_list: Pointer to list of data to be sent to CP
 *
 * returns true: if any data sent to Modem false otherwise
 */
static bool ipc_converged_ul_td_send(void *this_p,
		struct ipc_pipe *p_pipe, struct imem_ul_queue *p_ul_list)
{
	ipc_converged_hia_t head;
	ipc_converged_tia_t tail;
	struct ipc_converged_td *p_td;
	struct sk_buff *skb;
	struct ipc_skb_cb *skb_cb;
	s32 free_elements = 0;
	bool hpda_pending = false;
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe || !p_ul_list)) {
		ipc_err("Invalid arg(s)");
		return false;
	}

	if (!this->p_ap_shm) {
		ipc_err("Driver is not initialized");
		return false;
	}

	/* Get head and tail of the td list and calculate
	 * the number of free elements.
	 */
	head = this->p_ap_shm->tr_hia[p_pipe->pipe_nr];
	tail = p_pipe->old_tail;

	while (!skb_queue_empty(&p_ul_list->list)) {
		if (head < tail)
			free_elements = tail - head - 1;
		else
			free_elements = p_pipe->nr_of_entries - head +
				((s32) tail - 1);

		/* Test the number of free elements.
		 */
		if (free_elements <= 0) {
			ipc_dbg("no free td elements for UL pipe %d",
				p_pipe->pipe_nr);
			break;
		}

		/* Get the td address.
		 */
		p_td = &p_pipe->p_tr_start[head];

		/* Take the first element of the uplink list and add it
		 * to the td list.
		 */
		skb = imem_ul_list_dequeue(p_ul_list);
		if (!skb) {
			ipc_dbg("ul_list is empty!");
			break;
		}

		/* DMA sync for ARM based platform only.
		 */
		ipc_pcie_sync_skb_for_device(this->p_pcie, skb);

		/* get the skb control buffer */
		skb_cb = (struct ipc_skb_cb *)skb->cb;

		/* Save the reference to the uplink skbuf. */
		p_pipe->skbr_start[head] = skb;

		p_td->type = DESC_TYPE_EXT_BUF_VALID;
		p_td->size = skb->len;
		p_td->address = skb_cb->mapping;
		p_td->tag = p_pipe->td_tag;
		p_td->status.code = IPC_CONVERGED_CS_INVALID;
		p_pipe->td_tag++;
		p_td->remaining_count = 0;

		p_pipe->nr_of_queued_entries++;

		/* Calculate the new head and save it.
		 */
		head++;
		if (head >= p_pipe->nr_of_entries)
			head = 0;

		this->p_ap_shm->tr_hia[p_pipe->pipe_nr] = head;
	}

	if (p_pipe->old_head != head) {
		ipc_dbg("New UL TDs: pipe=%d, old_head=%u, new_head=%u, tail=%u, free=%d",
			p_pipe->pipe_nr, p_pipe->old_head, head,
			p_pipe->old_tail, free_elements);

		p_pipe->old_head = head;
		/* Trigger doorbell because of pending UL packets. */
		hpda_pending = true;
	}

	return hpda_pending;
}


/**
 * Checks for Tail pointer update from CP and returns the data as SKB.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 *
 * returns pointer of struct sk_buff if CP consumed data or NULL otherwise.
 */
static struct sk_buff *ipc_converged_ul_td_process(void *this_p,
		struct ipc_pipe *p_pipe)
{
	struct ipc_converged_td *p_td;
	struct sk_buff *skb;
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe || !p_pipe->p_tr_start
	|| !p_pipe->skbr_start)) {
		ipc_err("Invalid arg(s)");
		return NULL;
	}

	/* Get the reference to the defined td and corresponding skbuf.
	 */
	p_td = &p_pipe->p_tr_start[p_pipe->old_tail];
	skb = p_pipe->skbr_start[p_pipe->old_tail];

	p_pipe->nr_of_queued_entries--;
	p_pipe->old_tail++;
	if (p_pipe->old_tail >= p_pipe->nr_of_entries)
		p_pipe->old_tail = 0;

	if (!p_td || !skb || !p_td->address) {
		ipc_err("Either of the pointer is NULL");
		return NULL;
	}

	if (p_td->address != ((struct ipc_skb_cb *)(skb->cb))->mapping) {
		ipc_err("pipe(%d): invalid buf_addr=%llx or skb->data=%llx",
			p_pipe->pipe_nr, p_td->address,
			skb ? ((struct ipc_skb_cb *)(skb->cb))->mapping : 0);
		return NULL;
	}

	return skb;
}


/**
 * Allocates an SKB for CP to send data and updates the Head Pointer
 * of the given Pipe#.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 *
 * returns True if CP gets a new TD or False otherwise.
 */
static bool ipc_converged_dl_td_prepare(void *this_p, struct ipc_pipe *p_pipe)
{
	struct ipc_converged_td *p_td;
	ipc_converged_hia_t head, new_head;
	ipc_converged_tia_t tail;
	struct sk_buff *skb;
	u64 mapping = 0;
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid arg(s)");
		return false;
	}

	/* Get head and tail of the td list and calculate
	 * the number of free elements.
	 */
	head = this->p_ap_shm->tr_hia[p_pipe->pipe_nr];
	tail = this->p_ap_shm->tr_tia[p_pipe->pipe_nr];

	new_head = head + 1;
	if (new_head >= p_pipe->nr_of_entries)
		new_head = 0;

	if (new_head == tail) {
		ipc_err("New head == tail");
		return false;
	}

	/* Get the td address.
	 */
	p_td = &p_pipe->p_tr_start[head];

	/* Allocate the skbuf for the descriptor. */
	skb = ipc_pcie_alloc_dl_skb(this->p_pcie, p_pipe->buf_size, &mapping);
	if (!skb) {
		ipc_err("pipe(%d): exhausted skbuf DL memory",
			p_pipe->pipe_nr);
		ipc_trc_dl_mem_alloc_fail(p_pipe->buf_size);
		return false;
	}

	p_td->type = DESC_TYPE_EXT_BUF_VALID;
	p_td->size = p_pipe->buf_size;
	p_td->address = mapping;
	p_td->tag = p_pipe->td_tag;
	p_td->status.code = IPC_CONVERGED_CS_INVALID;
	p_pipe->td_tag++;
	p_td->remaining_count = 0;

	/* store the new head value.
	 */
	this->p_ap_shm->tr_hia[p_pipe->pipe_nr] = new_head;
	ipc_dbg("pipe=%d old_head=%d, head=%d, tail=%d", p_pipe->pipe_nr,
			head, new_head, tail);

	/* Save the reference to the skbuf.
	 */
	p_pipe->skbr_start[head] = skb;

	p_pipe->nr_of_queued_entries++;

	return true;
}


/**
 * Processes the TD processed from CP by checking the Tail Pointer for given
 * pipe.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 *
 * returns pointer of struct sk_buff if CP has processed tail pinter or NULL
 * otherwise.
 */
static struct sk_buff *ipc_converged_dl_td_process(void *this_p,
		struct ipc_pipe *p_pipe)
{
	struct ipc_converged_td *p_td;
	ipc_converged_tia_t tail;
	struct sk_buff *skb;
	struct ipc_skb_cb *skb_cb = NULL;
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid arg(s)");
		return NULL;
	}

	tail = this->p_ap_shm->tr_tia[p_pipe->pipe_nr];

	if (!p_pipe->p_tr_start)
		return NULL;

	/* Copy the reference to the downlink buffer.
	 */
	p_td = &p_pipe->p_tr_start[p_pipe->old_tail];
	skb = p_pipe->skbr_start[p_pipe->old_tail];

	/* Reset the ring elements.
	 */
	p_pipe->skbr_start[p_pipe->old_tail] = NULL;

	/* decrement nr of queued entries.
	 */
	p_pipe->nr_of_queued_entries--;

	p_pipe->old_tail++;

	if (p_pipe->old_tail >= p_pipe->nr_of_entries)
		p_pipe->old_tail = 0;

	if (!skb || !skb->data) {
		ipc_err("skb is null");
		goto ret;
	} else if (!p_td || !p_td->address) {
		ipc_err("td/buffer address is null");
		ipc_pcie_kfree_skb(this->p_pcie, skb);
		skb = NULL;
		goto ret;
	}

	skb_cb = (struct ipc_skb_cb *)skb->cb;
	if (!skb_cb) {
		ipc_err("pipe=%d tail=%d skb_cb is NULL", p_pipe->pipe_nr,
			tail);
		ipc_pcie_kfree_skb(this->p_pcie, skb);
		skb = NULL;
		goto ret;
	}

	if (p_td->address != skb_cb->mapping) {
		ipc_err("invalid buf=%llX or skb=%p",
			p_td->address, skb->data);
		ipc_pcie_kfree_skb(this->p_pcie, skb);
		skb = NULL;
		goto ret;
	} else if (p_td->size > p_pipe->buf_size) {
		ipc_err("invalid buffer size %d > %d",
			p_td->size, p_pipe->buf_size);
		ipc_pcie_kfree_skb(this->p_pcie, skb);
		skb = NULL;
		goto ret;
	} else if (p_td->status.code == IPC_CONVERGED_CS_ABORTED) {
		/* Discard aborted buffers.
		 */
		ipc_dbg("discard 'aborted' buffers");
		ipc_pcie_kfree_skb(this->p_pcie, skb);
		skb = NULL;
		goto ret;
	}
	/* TODO: Need to check the DL Completion status for IP and data?
	 */

	/* Set the length field an truesize in skbuf.
	 */
	skb_put(skb, p_td->size);
	skb->truesize = SKB_TRUESIZE(p_td->size);

	/* DMA sync for ARM based platform only.
	 */
	ipc_pcie_sync_skb_for_cpu(this->p_pcie, skb);

ret:
	return skb;
}


/**
 * Returns the Head and Tail index of given pipe.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 * @p_head: Pointer to get Head index. Passing NULL means caller is not
 *          interested.
 * @p_tail: Pointer to get Tail index. Passing NULL means caller is not
 *          interested.
 *
 * returns none.
 */
static void ipc_converged_get_head_tail_index(void *this_p,
		struct ipc_pipe *p_pipe, u32 *p_head, u32 *p_tail)
{
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid arg(s)");
		return;
	}

	if (p_head)
		*p_head = this->p_ap_shm->tr_hia[p_pipe->pipe_nr];

	if (p_tail)
		*p_tail = this->p_ap_shm->tr_tia[p_pipe->pipe_nr];
}


/**
 * Frees the TDs given to CP.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @p_pipe: Pointer to pipe
 *
 * returns none.
 */
static void ipc_converged_pipe_cleanup(void *this_p, struct ipc_pipe *p_pipe)
{
	struct sk_buff *skb;
	ipc_converged_hia_t head;
	ipc_converged_tia_t tail;
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !p_pipe)) {
		ipc_err("Invalid arg(s)");
		return;
	}

	if (unlikely(!this->phy_ap_shm)) {
		ipc_err("p_ap_shm is NULL");
		return;
	}

	/* Get the start and the end of the buffer list.
	 */
	head = this->p_ap_shm->tr_hia[p_pipe->pipe_nr];
	tail = p_pipe->old_tail;

	/* Reset tail and head, means set head and tail to 0.
	 */
	this->p_ap_shm->tr_tia[p_pipe->pipe_nr] = 0;
	this->p_ap_shm->tr_hia[p_pipe->pipe_nr] = 0;

	/* Free pending uplink and downlink buffers.
	 */
	if (p_pipe->skbr_start) {
		while (head != tail) {
			/* Get the reference to the skbuf,
			 * which is on the way and free it.
			 */
			skb = p_pipe->skbr_start[tail];
			if (skb)
				ipc_pcie_kfree_skb(this->p_pcie, skb);

			tail++;
			if (tail >= p_pipe->nr_of_entries)
				tail = 0;
		}

		ipc_util_kfree(p_pipe->skbr_start);
		p_pipe->skbr_start = NULL;
	}

	p_pipe->old_tail = 0;
	p_pipe->old_head = 0;
	p_pipe->td_tag = 0;

	/* Free and reset the td and skbuf circular buffers. kfree is save!
	 */
	if (p_pipe->p_tr_start) {
		ipc_pcie_kfree(this->p_pcie, p_pipe->p_tr_start,
			sizeof(struct ipc_converged_td) * p_pipe->nr_of_entries,
			p_pipe->phy_tdr_start);

		p_pipe->p_tr_start = NULL;
	}
}


/**
 * Get IPC status.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 *
 * returns IPC status from AP shared memory peripheral info.
 */
static enum ipc_mem_device_ipc_state ipc_converged_get_ipc_status(void *this_p)
{
	struct ipc_converged *this = this_p;

	return (enum ipc_mem_device_ipc_state)
		this->p_ap_shm->peripheral_info.ipc_status_mirror;
}


/**
 * Get Execution stage from AP shared memory.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 *
 * returns execution stage from AP shared memory peripheral info.
 */
static enum ipc_mem_exec_stage ipc_converged_get_ap_exec_stage(
		void *this_p)
{
	struct ipc_converged *this = this_p;
	u32 stage = this->p_ap_shm->peripheral_info.boot_stage_mirror;

	switch (stage) {
	case IPC_MEM_EXEC_STAGE_V2_ROM:
		return IPC_MEM_EXEC_STAGE_BOOT;

	case IPC_MEM_EXEC_STAGE_V2_SECONDARY_BOOT:
		return IPC_MEM_EXEC_STAGE_PSI;

	case IPC_MEM_EXEC_STAGE_V2_OS:
		return IPC_MEM_EXEC_STAGE_RUN;

	case IPC_MEM_EXEC_STAGE_V2_ABORT:
		return IPC_MEM_EXEC_STAGE_CRASH;

	default:
		return (enum ipc_mem_exec_stage)stage;
	}
}


/**
 * Returns Device sleep notification
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 *
 * returns device sleep notification value from AP shared memory peripheral
 *         info.
 */
static u32 ipc_converged_pm_dev_get_sleep_notification(void *this_p)
{
	struct ipc_converged *this = this_p;

	return this->p_ap_shm->peripheral_info.sleep_notification;
}


/*
 * Prints Message ring statistics into seq_file.
 *
 * @this_p: Valid pointer which can be typecasted to ipc_converged.
 * @m: seq_file to print statistics into.
 *
 * returns none
 */
static void ipc_converged_print_stats(void *this_p, struct seq_file *m)
{
	struct ipc_converged *this = this_p;

	if (unlikely(!this || !m)) {
		ipc_err("Invalid argument(s)");
		return;
	}

	seq_printf(m, "MSG TR head.............: %u\n",
		this->p_ap_shm->tr_hia[MSG_TR_IDX]);
	seq_printf(m, "MSG TR tail.............: %u\n",
		this->p_ap_shm->tr_tia[MSG_TR_IDX]);
	seq_printf(m, "MSG TR entries..........: %u\n\n", IPC_MEM_MSG_ENTRIES);

	if (this->mcr_supported) {
		seq_printf(m, "MSG CR head.............: %u\n",
			this->p_ap_shm->cr_hia[MSG_CR_IDX]);
		seq_printf(m, "MSG CR tail.............: %u\n",
			this->p_ap_shm->cr_tia[MSG_CR_IDX]);
		seq_printf(m, "MSG CR entries..........: %u\n\n",
			MSG_CR_ENTRIES);
	}
}


/**
 * Destructor for Converged protocol instance
 *
 * @this: ipc_converged instance pointer
 *
 * returns none
 */
static void ipc_converged_dtor(struct ipc_converged *this)
{
	if (unlikely(!this || !this->p_ap_shm)) {
		ipc_err("Invalid args");
		return;
	}

	ipc_completion_signal(&this->ts_completion);

	ipc_pcie_kfree(this->p_pcie, this->p_ap_shm,
		sizeof(struct ipc_converged_ap_shm), this->phy_ap_shm);

	this->p_ap_shm = NULL;
}


/**
 * Deallocates IPC Converged protocol instance
 *
 * @this: Pointer to the pointer to the IPC Converged protocol instance
 *
 * returns None
 */
static void ipc_protocol_converged_dealloc(void **this_pp)
{
	struct ipc_converged **this = (struct ipc_converged **)this_pp;

	if (this && *this) {
		ipc_converged_dtor(*this);
		ipc_util_kfree(*this);
		*this = NULL;
	}
}


/**
 * Updates the device's Message Completion Ring(MCR) support in protocol
 * instance with the capabiliy read from MMIO.
 *
 * @this: Instance pointer of Converged module.
 * @mcr_supported: true if MCR supported false otherwise.
 *
 * returns none.
 */
static void ipc_protocol_converged_update_mcr_cp_cap(
		void *this_p, bool mcr_supported)
{
	struct ipc_converged *this = this_p;
	int cp_version;

	if (unlikely(!this)) {
		ipc_err("Invalid args");
		return;
	}

	cp_version = ipc_mmio_get_cp_version(this->mmio);
	ipc_dbg("CP Version: %x", cp_version);

	if (cp_version >= IOSM_7660_CP_VERSION1)
		ipc_dbg("Modem Supports 16 bit head/tail pointers");
	else {
		ipc_err("Unsupported old modem version with 32-bit head/tail pointers.");
		return;
	}

	this->mcr_supported = mcr_supported;
	ipc_dbg("Device capability MCR %s", mcr_supported ?
			"supported" : "not-supported");
}


/**
 * Waits for timeout_ms ms for device to report its timestamp.
 * In case of timeout, the value at p_dev_time will be -1.
 *
 * @this: Instance pointer of Converged module.
 * @timeout_ms: Timeout in ms to wait for completion object to return.
 * @p_remote_time: Pointer to get the device timestamp in ns.
 * @p_remote_ts_id: Pointer to get last reported remote time ID.
 * @p_remote_time_unit: Pointer to get last reported timestamp unit.
 * @p_ts_db_trig: Pointer to get the info whether timesync doorbell triggered
 *                and user app is waiting or not.
 *
 * returns 0 on success, -1 on failure.
 */
static int ipc_protocol_converged_wait_for_remote_ts(void *this_p,
		int timeout_ms,	u64 *p_remote_time, u32 *p_remote_ts_id,
		u32 *p_remote_time_unit, bool *p_ts_db_trig)
{
	struct ipc_converged *this = this_p;
	int status;
	unsigned long flags;

	if (unlikely(!this || !p_remote_time || !p_remote_ts_id
	|| !p_remote_time_unit || !p_ts_db_trig)) {
		ipc_err("Invalid args");
		return -1;
	}

	spin_lock_irqsave(&this->ts_lock, flags);
	this->p_ts_db_trig = p_ts_db_trig;
	spin_unlock_irqrestore(&this->ts_lock, flags);

	/* Suspend the app and wait for Time Event CD from device. */
	status = ipc_completion_wait_interruptible_timeout_ms(
			&this->ts_completion, timeout_ms);

	/* To avoid any race condition in timeout and device notifying
	 * timestamp, check and update remote time in critical secion.
	 */
	spin_lock_irqsave(&this->ts_lock, flags);

	if (status > 0) {
		*p_remote_time = this->last_remote_time;
		*p_remote_ts_id = this->last_ts_id;
		*p_remote_time_unit = this->last_time_unit;
	} else {
		*p_remote_time = -1;
		*p_remote_ts_id = -1;
		*p_remote_time_unit = IPC_CONVERGED_TIME_UNIT_INVALID;
	}

	*this->p_ts_db_trig = false;

	/* Reinitialize completion object. */
	ipc_completion_reinit(&this->ts_completion);

	/* End of critical section */
	spin_unlock_irqrestore(&this->ts_lock, flags);

	/* If completion object returned before timeout then status will be
	 * positive non-zero value.
	 */
	return (status > 0) ? 0 : -1;
}


/*
 * Constructor for Converged protocol instance
 *
 * @this: ipc_converged instance pointer
 * @p_pcie: Instance pointer  of PCIe module.
 * @p_stats: Instance pointer to Stats module.
 * @p_mmio: Instance pointer of MMIO module.
 * @p_params: Instance pointer to Params module
 * @p_pm: Instance pointer to PM module
 * @ops: Pointer to structure of function pointers to support protocol
 * @dbg: pointer to ipc_dbg structure
 *
 * returns 0 on Success and -1 on failure
 */
static int ipc_converged_ctor(struct ipc_converged *this,
		struct ipc_pcie *p_pcie, struct ipc_debugfs_stats *p_stats,
		struct ipc_mmio *p_mmio, struct ipc_params *p_params,
		struct ipc_pm *p_pm, struct ipc_protocol_ops *ops,
		struct ipc_dbg *dbg)
{
	u64 addr;
	struct ipc_converged_ci *p_ci = NULL;

	if (unlikely(!p_pcie || !p_mmio || !p_params || !p_pm || !ops)) {
		ipc_err("Invalid args");
		return -1;
	}


	this->p_pcie = p_pcie;
	this->p_stats = p_stats;
	this->pm = p_pm;
	this->dbg = dbg;
	this->mmio = p_mmio;

	this->p_ap_shm = ipc_pcie_kzalloc(p_pcie,
		sizeof(struct ipc_converged_ap_shm), &this->phy_ap_shm);

	if (!this->p_ap_shm) {
		ipc_err("alloc error");
		return -1;
	}

	p_ci = &this->p_ap_shm->context_info;

	/* Prepare the context info for CP.
	 */
	addr = this->phy_ap_shm;

	/* Modem is not interested in Version#.
	 * So let's start with 0.
	 */
	p_ci->version = 0x00;
	p_ci->size = sizeof(*p_ci);
	p_ci->configuration = ipc_mmio_get_capability(p_mmio);
	p_ci->peripheral_info_addr = addr +
		offsetof(struct ipc_converged_ap_shm, peripheral_info);

	p_ci->cr_hia_addr = addr +
		offsetof(struct ipc_converged_ap_shm, cr_hia);

	p_ci->tr_tia_addr = addr +
		offsetof(struct ipc_converged_ap_shm, tr_tia);

	p_ci->cr_tia_addr = addr +
		offsetof(struct ipc_converged_ap_shm, cr_tia);

	p_ci->tr_hia_addr = addr +
		offsetof(struct ipc_converged_ap_shm, tr_hia);

	p_ci->cr_index_array_entries = IPC_CONVERGED_CR_HIA_SIZE;
	p_ci->tr_index_array_entries = IPC_CONVERGED_TR_TIA_SIZE;

	p_ci->message_cr_addr = addr +
		offsetof(struct ipc_converged_ap_shm, msg_compl_ring);

	p_ci->message_tr_addr = addr +
		offsetof(struct ipc_converged_ap_shm, msg_ring);

	p_ci->message_tr_entries = IPC_MEM_MSG_ENTRIES;
	p_ci->message_cr_entries = MSG_CR_ENTRIES;
	p_ci->msg_tr_doorbell_vector = IPC_DOORBELL_IRQ_HPDA;
	p_ci->msg_tr_msi_vector = IPC_MSG_IRQ_VECTOR;
	p_ci->msg_cr_msi_vector = IPC_MSG_IRQ_VECTOR;

	/* With MCR support in-place-completion should be 0 */
	p_ci->in_place_completion = 0;

	p_ci->peripheral_info_msi_vector = IPC_DEVICE_IRQ_VECTOR;

	/* Set the Context info address in MMIO */
	ipc_mmio_set_contex_info_addr(p_mmio, addr);

	/* By default Message Ring (Ring ID-0) will be in opened state */
	this->msg_tr_old_head_index = 0;
	this->msg_tr_old_tail_index = 0;
	this->msg_cr_old_head_index = 0;

	this->msg_td_tag = 0;

	/* Update the MCR tail index to make CDs available to Modem.
	 */
	this->p_ap_shm->cr_tia[MSG_CR_IDX] = MSG_CR_ENTRIES - 1;

	ops->msg_prep = ipc_converged_msg_prep;
	ops->msg_hp_update = ipc_converged_msg_hp_update;
	ops->msg_process = ipc_converged_msg_process;
	ops->ul_td_process = ipc_converged_ul_td_process;
	ops->dl_td_process = ipc_converged_dl_td_process;
	ops->ul_td_send = ipc_converged_ul_td_send;
	ops->dl_td_prepare = ipc_converged_dl_td_prepare;
	ops->get_head_tail_index = ipc_converged_get_head_tail_index;
	ops->get_ipc_status = ipc_converged_get_ipc_status;
	ops->pipe_cleanup = ipc_converged_pipe_cleanup;
	ops->get_ap_exec_stage = ipc_converged_get_ap_exec_stage;
	ops->pm_dev_get_sleep_notification =
		ipc_converged_pm_dev_get_sleep_notification;
	ops->print_stats = ipc_converged_print_stats;
	ops->protocol_dealloc = ipc_protocol_converged_dealloc;
	ops->update_mcr_cp_cap = ipc_protocol_converged_update_mcr_cp_cap;
	ops->wait_for_remote_ts = ipc_protocol_converged_wait_for_remote_ts;

	/* initialize spin lock for time sync */
	spin_lock_init(&this->ts_lock);

	ipc_completion_init(&this->ts_completion);
	this->last_remote_time = -1;
	this->last_ts_id = -1;
	this->last_time_unit = IPC_CONVERGED_TIME_UNIT_INVALID;

	return 0;
}


/*
 * Refer to header file for description
 */
void *ipc_protocol_converged_alloc(struct ipc_pcie *p_pcie,
		struct ipc_debugfs_stats *p_stats, struct ipc_mmio *p_mmio,
		struct ipc_params *p_params, struct ipc_pm *p_pm,
		struct ipc_protocol_ops *ops, struct ipc_dbg *dbg)
{
	struct ipc_converged *this = ipc_util_kzalloc(sizeof(*this));

	if (this) {
		if (ipc_converged_ctor(this, p_pcie, p_stats, p_mmio,
					p_params, p_pm, ops, dbg)) {
			ipc_err("Protocol converged constructor failed!");
			ipc_protocol_converged_dealloc((void **)&this);
			return NULL;
		}
	}

	return this;
}

