/*
 * Copyright (C) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 */

#ifndef IMC_IPC_TRACE_H
#define IMC_IPC_TRACE_H

struct imem_mux;

#ifdef IPC_TRACING

/*
 * Tracepoint for change in PM state
 *
 * @ap_state: current AP state
 * @cp_state: current CP state
 * @old_cond: Old PM condition for change in PM state
 * @new_cond: New PM condition for change in PM state
 * @unit: string indicating component that voted PM change
 * @active: "ACTIVE" or "SLEEP" vote
 *
 */
void ipc_trc_pm_state(unsigned int ap_state, unsigned int cp_state,
		unsigned int old_cond, unsigned int new_cond,
		const char *unit, const char *active);

/*
 * Tracepoint to PM device sleep notification
 *
 * @req_state: requested CP state
 * @cp_state:  current CP state
 *
 */
void ipc_trc_pm_dev_sleep_state(unsigned int req_state, unsigned int cp_state);

/*
 * Tracepoint for error event
 *
 * @error: error string
 *
 */
void ipc_trc_evnt_err(char *error);

/*
 * Tracepoint for tasklet enqueue event
 *
 * @q_rpos: queue read position
 * @q_wpos: queue write position
 * @func: function pointer being enqueued
 * @wait: 1:wait for completion, 0:asynchronous enqueue
 *
 */
void ipc_trc_tasklet_queue(unsigned int q_rpos, unsigned int q_wpos,
		void *func, unsigned int wait);

/*
 * Tracepoint for TD timer callback trigger
 *
 * @nr_of_queued_entries: number of entries in UL queue
 * @list_qbytes: number of bytes in the UL queue
 *
 */
void ipc_trc_td_update_timer_cb(unsigned long nr_of_queued_entries,
		int list_qbytes);

/*
 * Tracepoint for TD update timer stopped
 *
 * @timer_running: status of the timer 1:active 0:inactive
 */
void ipc_trc_td_stop_timer(unsigned int timer_running);

/*
 * Tracepoint for TD update timer stopped
 *
 * @timer_running: status of the timer 1:active 0:inactive
 */
void ipc_trc_td_start_timer(unsigned int timer_running);

/*
 * Tracepoint for UL pipe of a channel
 *
 * @pipe_nr: UL pipe number
 * @tx_proc_pkt_cnt:
 * @nr_of_entries: Number of elements of skb_start and tdr_start
 * @max_nr_of_queued_entries: max. number of queued entries in a TDR
 * @nr_of_queued_entries: queued number of entries
 * @list_qbytes: sum of bytes in the UL list
 * @enqueue: true is packet being enqueued, false otherwise
 *
 */
void ipc_trc_ul_chnl_stats(unsigned int pipe_nr,
		unsigned long tx_proc_pkt_cnt, unsigned long nr_of_entries,
		unsigned long max_nr_of_queued_entries,
		unsigned long nr_of_queued_entries, unsigned long list_qbytes,
		bool enqueue);
/*
 * Tracepoint for mux credit flow control event
 *
 * @fc_state: Flow control state 0:inactive 1:active
 * @fcthreshold: Flow control threshold
 * @data_pend_bytes: Pending bytes in UL pipe
 * @pipe_nr: UL pipe number
 * @max_nr_of_queued_entries: max. number of queued entries in a TDR
 * @nr_of_queued_entries: queued number of entries
 * @list_qbytes: sum of bytes in the UL list
 *
 */
void ipc_trc_ul_mux_flowctrl(unsigned int fc_state, unsigned int fcthreshold,
		unsigned long data_pend_bytes, unsigned int pipe_nr,
		unsigned long nr_of_entries,
		unsigned long max_nr_of_queued_entries,
		unsigned long nr_of_queued_entries, unsigned long list_qbytes);
/*
 * Tracepoint for mux credit flow control status
 *
 * @if_id: mux session id
 * @pipe_nr: UL pipe number
 * @crdfc_state: credit flow control state
 * @nr_of_entries: Number of elements of skb_start and tdr_start
 * @max_nr_of_queued_entries: max. number of queued entries in a TDR
 * @nr_of_queued_entries: queued number of entries
 * @list_qbytes: sum of bytes in the UL list
 * @mux: Pointer to MUX component
 *
 */
void ipc_trc_ul_mux_crd_fc(unsigned int if_id, unsigned int pipe_nr,
		unsigned int crdfc_state, unsigned long nr_of_entries,
		unsigned long max_nr_of_queued_entries,
		unsigned long nr_of_queued_entries, unsigned long list_qbytes,
		struct imem_mux *mux);

/*
 * Tracepoint for
 *
 * @if_id: mux session id
 * @tx_proc_pkt_cnt: number of packets transmitted
 * @pipe_nr: UL pipe number
 * @nr_of_entries: Number of elements of skb_start and tdr_start
 * @max_nr_of_queued_entries: max. number of queued entries in a TDR
 * @nr_of_queued_entries: queued number of entries
 * @head_pad_len: UL head padding on datagram
 * @list_qbytes: sum of bytes in the UL list
 * @tx_packets: packets transmitted on this mux session
 * @tx_bytes: bytes transmitted on this mux session
 * @mux: Pointer to MUX component
 *
 */
void ipc_trc_ul_sess_tx_stat(unsigned int if_id, unsigned long tx_proc_pkt_cnt,
		unsigned int pipe_nr, unsigned long nr_of_entries,
		unsigned long max_nr_of_queued_entries,
		unsigned long nr_of_queued_entries, unsigned long head_pad_len,
		unsigned long list_qbytes, unsigned long tx_packets,
		unsigned long tx_bytes,	struct imem_mux *mux);

/*
 * Tracepoint for doorbell fire
 *
 * @id: Doorbell fired
 * @data: data sent via doorbell
 *
 */
void ipc_trc_ul_hpda_doorbell_fire(unsigned int data);

/*
 * Tracepoint for netqueue mux flow control
 *
 * @id: vlan id
 * @fc_state: 1:enable, 0:disable
 *
 */
void ipc_trc_ul_flowctrl_event(unsigned int id, unsigned int fc_state);

/*
 * Tracepoint for mux net transmit event
 *
 * @if_id: mux session id
 * @skb_queue_len: length of the UL queue
 * @nr_of_bytes: sum of bytes in the UL list
 * @adb_updated: 1:ADB update successful, 0:otherwise
 *
 */
void ipc_trc_ul_mux_encode(unsigned int session_id, unsigned int skb_queue_len,
		unsigned int nr_of_bytes, unsigned int adb_updated);

/*
 * Tracepoint for DL mem allocation failure
 *
 * @size: size of memory requested
 *
 */
void ipc_trc_dl_mem_alloc_fail(unsigned int size);

/*
 * Tracepoint for mux response being processed
 *
 * @cmd_type: mux command
 * @transaction_id: transaction id
 * @if_id: mux session id
 * @mux: pointer to MUX component
 *
 */
void ipc_trc_dl_mux_resp(unsigned int cmd_type, unsigned int transaction_id,
		unsigned int if_id, struct imem_mux *mux);

/*
 * Tracepoint for DL mux command process
 *
 * @cmd_type: mux command
 * @transaction_id: transaction id
 * @if_id: mux session id
 * @mux: pointer to MUX component
 *
 */
void ipc_trc_dl_mux_cmd(unsigned int cmd_type, unsigned int transaction_id,
		unsigned int if_id, struct imem_mux *mux);

/*
 * Tracepoint for MUX command response sent to CP
 *
 * @cmd_type: mux command
 * @transaction_id: transaction id
 * @if_id: mux session id
 * @mux: pointer to MUX component
 *
 */
void ipc_trc_dl_mux_sndresp(unsigned int cmd_type, unsigned int transaction_id,
		unsigned int if_id, struct imem_mux *mux);

/*
 * Tracepoint for received packets in DL
 *
 * @if_id: mux session id
 * @head_pad_len: DL head padding on datagram
 * @pipe_nr: UL pipe number
 * @nr_of_entries: Number of elements of skb_start and tdr_start
 * @max_nr_of_queued_entries: max. number of queued entries in a TDR
 * @nr_of_queued_entries: queued number of entries
 * @rx_packets: packets received on this mux session
 * @tx_bytes: bytes received on this mux session
 *
 */
void ipc_trc_dl_rx_stat(unsigned int if_id, unsigned long head_pad_len,
		unsigned int pipe_nr, unsigned long nr_of_entries,
		unsigned long max_nr_of_queued_entries,
		unsigned long nr_of_queued_entries, unsigned long rx_packets,
		unsigned long rx_bytes);

#else

/* Stubbed functions when Tracing is not defined. */
#define ipc_trc_pm_state(ap_state, cp_state, old_cond, new_cond, unit, active)
#define ipc_trc_pm_dev_sleep_state(req_state, cp_state)
#define ipc_trc_evnt_err(error)
#define ipc_trc_tasklet_queue(q_rpos, q_wpos, func, wait)
#define ipc_trc_td_update_timer_cb(nr_of_queued_entries, list_qbytes)
#define ipc_trc_td_stop_timer(timer_running)
#define ipc_trc_td_start_timer(timer_running)
#define ipc_trc_ul_chnl_stats(pipe_nr, tx_proc_pkt_cnt, nr_of_entries,\
		max_nr_of_queued_entries, nr_of_queued_entries, list_qbytes,\
		enqueue)
#define ipc_trc_ul_mux_flowctrl(fc_state, fcthreshold, data_pend_bytes, \
		pipe_nr, nr_of_entries, max_nr_of_queued_entries, \
		nr_of_queued_entries, list_qbytes)
#define ipc_trc_ul_mux_crd_fc(if_id, pipe_nr, crdfc_state, nr_of_entries, \
		max_nr_of_queued_entries, nr_of_queued_entries, list_qbytes, \
		mux)
#define ipc_trc_ul_sess_tx_stat(if_id, tx_proc_pkt_cnt, pipe_nr, \
		nr_of_entries, max_nr_of_queued_entries, nr_of_queued_entries, \
		head_pad_len, list_qbytes, tx_packets, tx_bytes, mux)
#define ipc_trc_ul_hpda_doorbell_fire(data)
#define ipc_trc_ul_flowctrl_event(id, fc_state)
#define ipc_trc_ul_mux_encode(session_id, skb_queue_len, nr_of_bytes,\
		adb_updated)
#define ipc_trc_dl_mem_alloc_fail(size)
#define ipc_trc_dl_mux_resp(cmd_type, transaction_id, if_id, mux)
#define ipc_trc_dl_mux_cmd(cmd_type, transaction_id, if_id, mux)
#define ipc_trc_dl_mux_sndresp(cmd_type, transaction_id, if_id, mux)
#define ipc_trc_dl_rx_stat(if_id, head_pad_len, pipe_nr, nr_of_entries, \
		max_nr_of_queued_entries, nr_of_queued_entries, rx_packets, \
		rx_bytes)

#endif /* IPC_TRACING */

#endif /* IMC_IPC_TRACE_H */

