/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_MUX_H
#define IMC_IPC_MUX_H

struct imem_ul_queue;

/* Size of the buffer for the IP MUX data buffer. */
#define IPC_MEM_MAX_DL_MUX_BUF_SIZE		(16 * 1024)
#define IPC_MEM_MAX_UL_ADB_BUF_SIZE		IPC_MEM_MAX_DL_MUX_BUF_SIZE

/* TD counts for IP MUX */
#define IPC_MEM_MAX_TDS_MUX_UL			60
#define IPC_MEM_MAX_TDS_MUX_DL			60


/* Size of the buffer for the IP MUX Lite data buffer. */
#define IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE	(2 * 1024)
#define IPC_MEM_MAX_UL_MUX_LITE_ADB_BUF_SIZE	IPC_MEM_MAX_DL_MUX_LITE_BUF_SIZE

/* TD counts for IP MUX Lite */
#define IPC_MEM_MAX_TDS_MUX_LITE_UL		800
#define IPC_MEM_MAX_TDS_MUX_LITE_DL		1200

/* Maximum configurable Buffer Size for IP MUX Lite */
/* for UL and DL */
#define IPC_MEM_MUX_LITE_MAX_JUMBO_BUF_SIZE	(64 * 1024)

/* TD counts for Maximum configurable Buffer Size for IP MUX Lite */
/* for UL and DL */
#define IPC_MEM_MUX_LITE_MAX_JUMBO_TDS		200



#define MUX_ALIGN32(x)               (((x)+0x03) & ~0x03)

/* Number of supported sessions. */
#define IPC_IMEM_MUX_SESSION_ENTRIES  8

/* Size of the buffer for the IP MUX commands. */
#define IPC_MEM_MAX_UL_ACB_BUF_SIZE  256

/* Maximum number of packets in a go per session */
#define IPC_MEM_MAX_UL_DG_ENTRIES      100

/* Aggregation signatures. */

/* ADBH: Signature of the Aggregated Data Block Header. */
#define IPC_MEM_SIG_ADBH                0x48424441

/* ADTH: Signature of the Aggregated Datagram Table Header. */
#define IPC_MEM_SIG_ADTH                0x48544441

/* ADGH: Signature of the Datagram Header. */
#define IPC_MEM_SIG_ADGH                0x48474441

/* ACBH: Signature of the Aggregated Command Block Header. */
#define IPC_MEM_SIG_ACBH                0x48424341

/* CMDH: Signature of the Command Header. */
#define IPC_MEM_SIG_CMDH                0x48444D43

/* QLTH: Signature of the Queue Level Table */
#define IPC_MEM_SIG_QLTH                0x48544C51

/* FCTH: Signature of the Flow Credit Table */
#define IPC_MEM_SIG_FCTH                0x48544346


/* Aggregation command types. */

/* open session request (AP->CP) */
#define IPC_MEM_CMD_OPEN_SESSION			1

/* response to open session request (CP->AP) */
#define IPC_MEM_CMD_OPEN_SESSION_RESP			2

/* close session request (AP->CP) */
#define IPC_MEM_CMD_CLOSE_SESSION			3

/* response to close session request (CP->AP) */
#define IPC_MEM_CMD_CLOSE_SESSION_RESP			4

/* Flow control command with mask of the flow per queue/flow.
 * For ADAM-Lite.
 */
#define IPC_MEM_CMD_LITE_FLOW_CTL			5

/* Enables the flow control (Flow is not allowed) */
#define IPC_MEM_CMD_FLOW_CTL_ENABLE			5

/* Disables the flow control (Flow is allowed) */
#define IPC_MEM_CMD_FLOW_CTL_DISABLE			6

/* ACK the flow control command. Shall have the same Transaction ID as the
 * matching FLOW_CTL command. For ADAM-Lite.
 */
#define IPC_MEM_CMD_LITE_FLOW_CTL_ACK			6

/* ACK the flow control command. Shall have the same Transaction ID as the
 * matching FLOW_CTL command
 */
#define IPC_MEM_CMD_FLOW_CTL_ACK			7

/* Command for report packet indicating link quality metrics. For ADAM-Lite. */
#define IPC_MEM_CMD_LITE_LINK_STATUS_REPORT		7

/* Response to a report packet */
#define IPC_MEM_CMD_LITE_LINK_STATUS_REPORT_RESP	8

/* Response to a report packet */
#define IPC_MEM_CMD_LINK_STATUS_REPORT_RESP		9

/* Command for report packet indicating link quality metrics. For ADAM-Lite. */
#define IPC_MEM_CMD_LINK_STATUS_REPORT			8

/* Used to reset a command/response state. */
#define IPC_MEM_CMD_INVALID           255

/* Aggregation and lite commands responses. */

/* Rresult: command processed successfully */
#define IPC_MEM_CMD_RESP_SUCCESS        0

/* Result: not ready to process command */
#define IPC_MEM_CMD_RESP_NOT_READY      1

/* Result: command contains invalid parameters */
#define IPC_MEM_CMD_RESP_INVALID_PARAMS 2

/* Result: internal error occured */
#define IPC_MEM_CMD_RESP_INTERNAL_ERROR 3

/* Result: unclassified error */
#define IPC_MEM_CMD_RESP_UNKNOWN_ERROR  4

/* Result: unclassified error lite */
#define IPC_MEM_LITE_CMD_RESP_UNKNOWN_ERROR  0xFFFFFFFFUL


/* Initiated actions to change the state of the MUX object.
 */
enum imem_mux_event {
	MUX_E_INACTIVE,		/* No initiated actions. */
	MUX_E_MUX_SESSION_OPEN,	/* Create the MUX channel and a session. */
	MUX_E_MUX_SESSION_CLOSE,	/* Release a session. */
	MUX_E_MUX_CHANNEL_CLOSE,	/* Release the MUX channel. */
	MUX_E_NO_ORDERS,	/* No MUX order. */
	MUX_E_NOT_APPLICABLE	/* Defect IP MUX. */
};

/* MUX session open command.
 */
struct ipc_wwan;

struct mux_session_open {
	enum imem_mux_event event;
	int if_id;		/* Return value. */
};

/* MUX session close command.
 */
struct mux_session_close {
	enum imem_mux_event event;
	int if_id;
};

/* MUX channel close command.
 */
struct mux_channel_close {
	enum imem_mux_event event;
};

/* Default message type to find out the right message type.
 */
struct mux_common {
	enum imem_mux_event event;
};

/* List of the MUX orders.
 */
union imem_mux_msg {
	struct mux_session_open session_open;
	struct mux_session_close session_close;
	struct mux_channel_close channel_close;
	struct mux_common common;
};

/* Type-definition of the Aggregated Command Block Header. */
struct ipc_mem_acbh {
	/* Signature of the Aggregated Command Block Header.
	 * Value: 0x48424341 (ASCII characters: ACBH)
	 */
	u32 signature;

	/* Reserved bytes. Set to zero. */
	u16 reserved;

	/* Block sequence number. Single sourced for data and command paths.
	 * Used for debug.
	 */
	u16 sequence_nr;

	/* Length (in bytes) of the Aggregated Command Block. This length
	 * shall include header size. Minimum value:0x20
	 */
	u32 block_length;

	/* Index (in bytes) to the first command in the buffer. Index shall
	 * count from the start of the block including the 16-byte header.
	 * Minimum value: 0x10 (first index after the header)
	 */
	u32 first_command_index;
};

/* Type-definition of the Aggregated Block Header. */
struct ipc_mem_abh {
	/* Signature of the Block */
	u32 signature;

	/* Reserved bytes. Set to zero. */
	u16 reserved;

	/* Block sequence number. Single sourced for data and command paths.
	 * Used for debug.
	 */
	u16 sequence_nr;

	/* Length (in bytes) of the Aggregated Block. This length shall
	 * include header size. Minimum value:0x20
	 */
	u32 block_length;

	/* Index (in bytes) to the first header in the buffer. Index shall count
	 * from the start of the block including the 16-byte header. Minimum
	 * value: 0x10 (first index after the header)
	 */
	u32 first_index;
};

/* Parameter definition of the open session command. */
struct ipc_mem_cmd_open_session {
	u32 flow_ctrl:1;	/* 0: Flow control disabled (flow allowed).
				 * 1: Flow control enabled (flow not allowed)
				 */
	u32 reserved:7;		/* Reserved. Set to zero. */
	u32 ipv4v6_hints:1;	/* 0: IPv4/IPv6 hints not supported.
				 * 1: IPv4/IPv6 hints supported
				 */
	u32 reserved2:23;	/* Reserved. Set to zero. */
	u32 dl_head_pad_len;	/* Maximum length supported
				 * for DL head padding on a datagram.
				 */
};

/* Parameter definition of the open session response. */
struct ipc_mem_cmd_open_session_resp {
	u32 response;		/* Resonse code (see IPC_MEM_CMD_RESPONSE_xxx */
	u32 flow_ctrl:1;	/* 0: Flow control disabled (flow allowed).
				 * 1: Flow control enabled (flow not allowed)
				 */
	u32 reserved:7;		/* Reserved. Set to zero. */
	u32 ipv4v6_hints:1;	/* 0: IPv4/IPv6 hints not supported
				 * 1: IPv4/IPv6 hints supported
				 */
	u32 reserved2:23;	/* Reserved. Set to zero. */
	u32 ul_head_pad_len;	/* Actual length supported for
				 * UL head padding on adatagram.
				 */
};

/* Parameter definition of the close session response. */
struct ipc_mem_cmd_close_session_resp {
	u32 response;		/* resonse code (see IPC_MEM_CMD_RESPONSE_xxx */
};

/* Parameter definition of the flow control command. */
struct ipc_mem_cmd_flow_ctl {
	u32 mask;		/* indicating  the  desired  flow  control
				 * state  for various flows/queues
				 */
};


/* Parameter definition of the link status report response. */
struct ipc_mem_cmd_link_status_report {
	u8 payload[1];		/* resonse code (see IPC_MEM_CMD_RESPONSE_xxx */
};


/* Parameter definition of the link status report response. */
struct ipc_mem_cmd_link_status_report_resp {
	u32 response;		/* resonse code (see IPC_MEM_CMD_RESPONSE_xxx */
};


/* Union-definition of the command parameters. */
union ipc_mem_cmd_param {
	/* Inband command for open session. */
	struct ipc_mem_cmd_open_session open_session;

	/* Inband command for open session response. */
	struct ipc_mem_cmd_open_session_resp open_session_resp;

	/* Inband command for close session response. */
	struct ipc_mem_cmd_close_session_resp close_session_resp;

	/* In-band flow control on the opened interfaces */
	struct ipc_mem_cmd_flow_ctl flow_ctl;

	/* In-band Link Status Report */
	struct ipc_mem_cmd_link_status_report link_status;

	/* In-band command for link status report response */
	struct ipc_mem_cmd_link_status_report_resp link_status_resp;
};

/* Type-definition of Command Header. */
struct ipc_mem_cmdh {
	/* Signature of the Command Header.
	 * Value: 0x48444D43 (ASCII characters: CMDH.
	 */
	u32 signature;

	/* Length (in bytes) of the Aggregated Command Block. This length shall
	 * include header size. Minimum value: 0x14
	 */
	u16 cmd_len;

	/* ID of the interface the commands in the table belong to. */
	u8 if_id;

	/* Reserved. Set to zero. */
	u8 reserved;

	/* Index (in bytes) to the next command in the buffer. Index shall count
	 * from the start of the block including the 16-byte header. Value of
	 * zero indicates end of the list.
	 */
	u32 next_command_index;

	/* Command Enum. See table Session Management chapter for details. */
	u32 command_type;

	/* 4 byte value shall be generated and sent along with a command.
	 * Responses and ACKs shall have the same Transaction ID as their
	 * commands. The Transaction ID shall be unique to the command
	 * transaction on the given interface.
	 */
	u32 transaction_id;

	/* Optional parameters used with the command. */
	union ipc_mem_cmd_param param;
};

/* Type-definition of the Aggregated Data Block Header. */
struct ipc_mem_adbh {
	/* Signature of the Aggregated Data Block Header.
	 * Value: 0x48424441 (ASCII characters: ADBH)
	 */
	u32 signature;

	/* Reserved bytes. Set to zero. */
	u16 reserved;

	/* Block sequence number. Single sourced for data and command paths.
	 * Used for debug.
	 */
	u16 sequence_nr;

	/* Length (in bytes) of the Aggregated Data Block.
	 * This length shall include header size. Minimum value:0x20
	 */
	u32 block_length;

	/* Index (in bytes) to the first Datagram Table in the buffer.
	 * Index shall count from the start of the block including
	 * the 16-byte header.
	 * Minimum value: 0x10 (first index after the header)
	 */
	u32 first_table_index;
};

/* Type-definition of the datagram in the Aggregated Datagram Table Header. */
struct ipc_mem_adth_dg {
	/* Index (in bytes) to the k-th datagram in the table.
	 * Index shall count from the start of the block including
	 * the 16-byte header. This value shall be non-zero.
	 */
	u32 datagram_index;

	/* Length of the k-th datagram including the head padding.
	 * This value shall be non-zero.
	 */
	u16 datagram_length;

	/* Service class identifier for the datagram.
	 */
	u8 service_class;

	/* Reserved bytes. Set to zero */
	u8 reserved;
};

/* Type-definition of the Aggregated Datagram Table Header. */
struct ipc_mem_adth {
	/* Signature of the Aggregated Datagram Table Header.
	 * Value: 0x48544441 (ASCII characters: ADTH)
	 */
	u32 signature;

	/* Length (in bytes) of the datagram table.
	 * This length shall include the datagram table header size.
	 * Minimum value:0x10
	 */
	u16 table_length;

	/* ID of the interface the datagrams in the table belong to. */
	u8 if_id;

	/* Indicates IPv4(=0)/IPv6(=1) hint. Supporting this hint is optional
	 * and each interface may negotiate support
	 * for this hint through open session command.
	 * When this hint is not supported it is set to zero.
	 */
	u8 opt_ipv4v6:1;

	/* Reserved bits. Set to zero. */
	u8 reserved:7;

	/* Index (in bytes) to the next Datagram Table in the buffer.
	 * Index shall count from the start of the block including
	 * the 16-byte header. Value of zero indicates end of the list.
	 */
	u32 next_table_index;

	/* Reserved bytes. Set to zero */
	u32 reserved2;

	/* datagramm table with variable length */
	struct ipc_mem_adth_dg dg[1];
};

/* Type-definition of the queue level in the Aggregated Datagram Queue Level
 * Table Header.
 */
struct ipc_mem_qlth_ql {
	/* Number of bytes available to transmit in the queue.
	 */
	u32 nr_of_bytes;
};

/* Type-definition of the Aggregated Datagram Queue Level Table Header. */
struct ipc_mem_qlth {
	/* Signature of the Queue Level Table Header.
	 * Value: 0x48544C51 (ASCII characters: 'Q' 'L' 'T' 'H')
	 */
	u32 signature;

	/* Length (in bytes) of the datagram table. This length shall include
	 * the queue level table header size. Minimum value:0x10
	 */
	u16 table_length;

	/* ID of the interface the queue levels in the table belong to.
	 */
	u8 if_id;

	/* Reserved byte. Set to zero.
	 */
	u8 reserved;

	/* Index (in bytes) to the next table in the buffer. Index shall count
	 * from the start of the block including the 16-byte header.
	 * Value of zero indicates end of the list.
	 */
	u32 next_table_index;

	/* Reserved bytes. Set to zero */
	u32 reserved2;

	/* Queue level table with variable length */
	struct ipc_mem_qlth_ql ql[1];
};

/* Mux Lite Data Structures begins here
 */

/* Type-definition of the Aggregated Datagram Header. */
struct ipc_mem_adgh {
	/* Signature of the Aggregated Datagram Header.
	 * Value: 0x48474441 (ASCII characters: ADGH)
	 */
	u32 signature;

	/* Length (in bytes) of the datagram header.
	 * This length shall include the datagram header size.
	 * Minimum value:0x10
	 */
	u16 length;

	/* ID of the interface the datagrams belong to. */
	u8 if_id;

	/* Indicates IPv4(=0)/IPv6(=1) hint. Supporting this hint is optional
	 * and each interface may negotiate support
	 * for this hint through open session command.
	 * When this hint is not supported it is set to zero.
	 */
	u8 opt_ipv4v6:1;

	/* Reserved bits. Set to zero. */
	u8 reserved:7;

	/* Service class identifier for the datagram.
	 */
	u8 service_class;

	/* Count of the datagrams that shall be following this datagrams for
	 * this interface. A count of zero means the next datagram may not
	 *  belong to this interface.
	 */
	u8 next_count;

	/* Reserved bytes. Set to zero */
	u8 reserved1[6];
};

/* Type-definition of MUX Lite Command Header. */
struct ipc_mem_lite_cmdh {
	/* Signature of the Command Header.
	 * Value: 0x48444D43 (ASCII characters: CMDH.
	 */
	u32 signature;

	/* Length (in bytes) of the command. This length shall include
	 * the header size. Minimum value: 0x10
	 */
	u16 cmd_len;

	/* ID of the interface the commands in the table belong to. */
	u8 if_id;

	/* Reserved. Set to zero. */
	u8 reserved;

	/* Command Enum. See table Session Management chapter for details. */
	u32 command_type;

	/* 4 byte value shall be generated and sent along with a command.
	 * Responses and ACKs shall have the same Transaction ID as their
	 * commands. The Transaction ID shall be unique to the command
	 * transaction on the given interface.
	 */
	u32 transaction_id;

	/* Optional parameters used with the command. */
	union ipc_mem_cmd_param param;
};

/* Type-definition of the value field in generic table
 */
struct ipc_mem_lite_vfl {
	/* Number of bytes available to transmit in the queue.
	 */
	u32 nr_of_bytes;
};

/* Generic table format for Queue Level and Flow Credit
 */
struct ipc_mem_lite_gen_tbl {
	/* Signature of the table
	 */
	u32 signature;

	/* Length of the table
	 */
	u16 length;

	/* ID of the interface the table belongs to
	 */
	u8 if_id;

	/* Value field length
	 */
	u8 vfl_length;

	/* Reserved
	 */
	u64 reserved;

	/* Value field of variable length
	 */
	struct ipc_mem_lite_vfl vfl[1];

};

/* Mux Lite Data Structures ends here
 */

/* States of the MUX object.. */
enum imem_mux_state {
	MUX_S_INACTIVE,		/* IP MUX is unused. */
	MUX_S_ACTIVE,		/* IP MUX channel is available. */
	MUX_S_ERROR		/* Defect IP MUX. */
};

/* Supported MUX protocols.
 */
enum imem_mux_protocol {
	MUX_UNKNOWN,
	MUX_AGGREGATION,	/* IP packets aggregated */
	MUX_LITE		/* No aggregation of IP packets */
};

/* Supported UL data transfer methods.
 */
enum imem_mux_ul_flow {
	MUX_UL_UNKNOWN,
	MUX_UL_LEGACY,		/* Normal UL data transfer */
	MUX_UL_ON_CREDITS	/* UL data transfer will be based on credits */
};


/* List of the MUX session. */
struct imem_mux_session {
	int if_id;		/* Interface id for session open message. */
	struct ipc_wwan *wwan;  /* Network interface used for communication */
	/* MUX for vlan devices */
	#define IPC_MEM_WWAN_MUX	BIT(0)
	u32 flags;

	u32 ul_head_pad_len;	/* Nr of bytes for UL head padding. */
	u32 dl_head_pad_len;	/* Nr of bytes for DL head padding. */

	/* skb entries for an ADT. */
	struct imem_ul_queue ul_list;

	u32 flow_ctl_mask;	/* UL flow control */
	u32 flow_ctl_en_cnt;	/* Count for Flow control Enable commands */
	u32 flow_ctl_dis_cnt;	/* Count for Flow Control Disable commands */
	int ul_flow_credits;	/* UL flow credits */
	bool net_tx_stop;
	u32 flush:1;		/* flush net interface ? */
};

/* State of a single UL aggegated data block. */
struct imem_mux_adb {
	/* Datagram table. */
	struct ipc_mem_adth_dg
		    dg[IPC_IMEM_MUX_SESSION_ENTRIES][IPC_MEM_MAX_UL_DG_ENTRIES];

	/* Pointers to hold Queue Level Tables of session */
	struct ipc_mem_qlth *p_qlt[IPC_IMEM_MUX_SESSION_ENTRIES];

	/* List of allocated ADB for the UL sessions. */
	struct sk_buff_head free_list;

	/* Current UL skb for the aggregated data block. */
	struct sk_buff *dest_skb;

	/* ADB memory. */
	u8 *buf;

	/* Size of the ADB memory. */
	int size;

	/* ADBH pointer */
	struct ipc_mem_adbh *adbh;

	/* ADGH pointer */
	struct ipc_mem_adgh *adgh;

	/* QLTH pointer */
	struct sk_buff *qlth_skb;

	/* Pointer to next table index. */
	u32 *next_table_index;

	/* Statistic counter */
	u32 if_cnt;
	u32 dg_cnt_total;
	u32 payload_size;

	u32 dg_count[IPC_IMEM_MUX_SESSION_ENTRIES];
	u32 qlt_updated[IPC_IMEM_MUX_SESSION_ENTRIES];
};

/* Temporary ACB state. */
struct imem_mux_acb {
	int if_id;		/* Session id. */
	struct sk_buff *skb;	/* Used UL skb. */
	u8 *buf_p;		/* Command buffer. */
	u32 wanted_response;
	u32 got_response;
	u32 cmd;

	/* Received command/response parameter. */
	union ipc_mem_cmd_param got_param;
};


/* State of the data aggregation and multiplexing over an IP channel. */
struct imem_mux {
	/* MUX object is initialized */
	bool initialized;

	/* Reference to the IP MUX channel. */
	struct ipc_mem_channel *channel;

	/* States of the MUX object. */
	enum imem_mux_state state;

	/* Initiated actions to change the state of the MUX object. */
	enum imem_mux_event event;

	/* List of the MUX sessions. */
	struct imem_mux_session session[IPC_IMEM_MUX_SESSION_ENTRIES];

	/* Sequence number for the ACB header. */
	u16 acb_tx_sequence_nr;

	/* Transaction id for the ACB command. */
	u32 tx_transaction_id;

	/* Next session number for round robin. */
	int rr_next_session;

	/* Seuence number for ADB header */
	u16 adb_tx_sequence_nr;

	/* State of the UL ADB/ADGH. */
	struct imem_mux_adb ul_adb;

	/* Flag for ADB preparation status */
	bool adb_prep_ongoing;

	/* Variable to store the size needed during ADB preperation */
	int size_needed;

	/* Pending UL data to be processed in bytes*/
	long long ul_data_pend_bytes;

	/* Statistic data for logging */
	unsigned long long acc_adb_size;
	unsigned long long acc_payload_size;

	/* Active MUX protocol */
	enum imem_mux_protocol protocol;

	/* UL flow method */
	enum imem_mux_ul_flow ul_flow;

	/* Temporary ACB state */
	struct imem_mux_acb acb;

	/* IPC mux stats */
	struct ipc_debugfs_mux *dbg_stats;

	/* user configurable parameters */
	struct ipc_params *params;
};

#endif
