// SPDX-FileCopyrightText: 2026 Cosinium
// SPDX-License-Identifier: Apache-2.0

package main

import "noir:engine"

// Names that the daemon and the server use from the client engine (engine/).
// This file holds names only. Names that exist on one system only are in the files
// engine_names_<system>.odin.
//
// The offload settings are one variable for the process, so `OFF` is a pointer to
// it (a field reads the same: `OFF.tun`).

OFF := &engine.OFF

// acl_rules.odin
acl_change_names :: engine.acl_change_names
acl_config_details :: engine.acl_config_details
acl_reload :: engine.acl_reload
acl_write_reload :: engine.acl_write_reload
op_acl_get :: engine.op_acl_get

// block6.odin
is_ipv6 :: engine.is_ipv6

// client_bus.odin
client_state_write :: engine.client_state_write
client_stats_arm :: engine.client_stats_arm
mask_bits :: engine.mask_bits

// client_ops.odin
Auth_Supply :: engine.Auth_Supply
cli_stopping :: engine.cli_stopping
op_auth_supply :: engine.op_auth_supply
op_connect :: engine.op_connect
op_disconnect :: engine.op_disconnect
op_profile_clear :: engine.op_profile_clear
op_shutdown :: engine.op_shutdown
op_stats :: engine.op_stats
op_status :: engine.op_status
profile_precheck :: engine.profile_precheck
profile_run :: engine.profile_run
service_denied :: engine.service_denied

// client_text.odin
ip4_str :: engine.ip4_str
ip6_str :: engine.ip6_str
state_reason :: engine.state_reason
stop_state_reason :: engine.stop_state_reason
write_u64_fields :: engine.write_u64_fields

// cred.odin
CRED_MAX :: engine.CRED_MAX
Cred_Error :: engine.Cred_Error
Creds :: engine.Creds
cred_error_text :: engine.cred_error_text
cred_parse :: engine.cred_parse
cred_set :: engine.cred_set
cred_wipe :: engine.cred_wipe
cred_wipe_password :: engine.cred_wipe_password

// crl.odin
Crl_Stat :: engine.Crl_Stat
Crl_State :: engine.Crl_State
crl_decide :: engine.crl_decide
crl_destroy :: engine.crl_destroy
crl_init :: engine.crl_init
crl_log_start :: engine.crl_log_start
crl_poll :: engine.crl_poll
crl_server_config :: engine.crl_server_config

// crypto_worker.odin
WK_JOBS :: engine.WK_JOBS
Wk_Job :: engine.Wk_Job
Wk_Pool :: engine.Wk_Pool
Wk_Worker :: engine.Wk_Worker
job_add :: engine.job_add
lane_recycle :: engine.lane_recycle
lane_run :: engine.lane_run
pool_attach :: engine.pool_attach
pool_start :: engine.pool_start
pool_stop :: engine.pool_stop
pool_text :: engine.pool_text
pool_write_bus :: engine.pool_write_bus

// daemon.odin
DEFAULT_TUN_MTU :: engine.DEFAULT_TUN_MTU
Daemon :: engine.Daemon
RX_BATCH :: engine.RX_BATCH
RX_SLOT :: engine.RX_SLOT
SOCKET_BUFFER :: engine.SOCKET_BUFFER
Stats :: engine.Stats
TX_BATCH :: engine.TX_BATCH
Timer :: engine.Timer
daemon_destroy :: engine.daemon_destroy
daemon_init :: engine.daemon_init
daemon_print_status :: engine.daemon_print_status
daemon_reconnect_now :: engine.daemon_reconnect_now
daemon_run :: engine.daemon_run
daemon_stop_signal :: engine.daemon_stop_signal
local_endpoint :: engine.local_endpoint

// datapath.odin
tun_name :: engine.tun_name
write_tun :: engine.write_tun

// datapath_workers.odin
RX_COPY_AT :: engine.RX_COPY_AT

// dco.odin
DCO_ECONNREFUSED :: engine.DCO_ECONNREFUSED
DCO_ENODEV :: engine.DCO_ENODEV
DCO_PROV_CLIENT :: engine.DCO_PROV_CLIENT
DCO_PROV_TOP :: engine.DCO_PROV_TOP
DCO_STATS_FAST :: engine.DCO_STATS_FAST
DCO_STATS_KERNEL :: engine.DCO_STATS_KERNEL
DCO_STATS_SLOW :: engine.DCO_STATS_SLOW
DCO_TUN_RETRY :: engine.DCO_TUN_RETRY
DCO_TUN_TRIES :: engine.DCO_TUN_TRIES
DCO_WAIT_SECS :: engine.DCO_WAIT_SECS
Dco_Act :: engine.Dco_Act
Dco_Client :: engine.Dco_Client
Dco_Link :: engine.Dco_Link
Dco_Owner :: engine.Dco_Owner
Dco_Path :: engine.Dco_Path
client_datapath :: engine.client_datapath
daemon_datapath :: engine.daemon_datapath
dco_attach :: engine.dco_attach
dco_attempt_ended :: engine.dco_attempt_ended
dco_classify :: engine.dco_classify
dco_client_filter :: engine.dco_client_filter
dco_client_init :: engine.dco_client_init
dco_close_device :: engine.dco_close_device
dco_connect_text :: engine.dco_connect_text
dco_ctrl_receive :: engine.dco_ctrl_receive
dco_ctrl_send :: engine.dco_ctrl_send
dco_datapath_name :: engine.dco_datapath_name
dco_early_ok :: engine.dco_early_ok
dco_epoch_ok :: engine.dco_epoch_ok
dco_err_text :: engine.dco_err_text
dco_fail :: engine.dco_fail
dco_filter_call :: engine.dco_filter_call
dco_filter_ok :: engine.dco_filter_ok
dco_filter_poll :: engine.dco_filter_poll
dco_for_attempt :: engine.dco_for_attempt
dco_in_process_name :: engine.dco_in_process_name
dco_in_process_on :: engine.dco_in_process_on
dco_link_close :: engine.dco_link_close
dco_mode_name :: engine.dco_mode_name
dco_open_flags :: engine.dco_open_flags
dco_owner_init :: engine.dco_owner_init
dco_owns_id :: engine.dco_owns_id
dco_path_of :: engine.dco_path_of
dco_peer_addr :: engine.dco_peer_addr
dco_peer_create :: engine.dco_peer_create
dco_peer_create_stream :: engine.dco_peer_create_stream
dco_peer_delete :: engine.dco_peer_delete
dco_peer_dropped :: engine.dco_peer_dropped
dco_peer_rename :: engine.dco_peer_rename
dco_peer_set :: engine.dco_peer_set
dco_peer_set_addr :: engine.dco_peer_set_addr
dco_pick :: engine.dco_pick
dco_pick_report :: engine.dco_pick_report
dco_prov_id :: engine.dco_prov_id
dco_server_early_ok :: engine.dco_server_early_ok
dco_sockaddr :: engine.dco_sockaddr
dco_start_text :: engine.dco_start_text
dco_stats :: engine.dco_stats
dco_status_text :: engine.dco_status_text
dco_submit :: engine.dco_submit
dco_tcp_ok :: engine.dco_tcp_ok
dco_try_open :: engine.dco_try_open
dco_who :: engine.dco_who
dco_who_short :: engine.dco_who_short
dco_why :: engine.dco_why
endpoint_peer_addr :: engine.endpoint_peer_addr
sub0 :: engine.sub0

// dco_launch.odin
dco_launch_start :: engine.dco_launch_start
dco_launch_stop :: engine.dco_launch_stop
dco_launch_uid :: engine.dco_launch_uid

// host.odin
Caller :: engine.Caller
Host :: engine.Host
Reply :: engine.Reply
Sys_Hooks :: engine.Sys_Hooks
reply_err :: engine.reply_err
reply_err_details :: engine.reply_err_details
reply_ok :: engine.reply_ok

// keys_unlock.odin
Key_Ask :: engine.Key_Ask
Key_Slot :: engine.Key_Slot
key_unlock :: engine.key_unlock
keys_unlock :: engine.keys_unlock

// leaf_rules.odin
leaf_rules_free :: engine.leaf_rules_free
leaf_rules_of :: engine.leaf_rules_of
leaf_rules_problems :: engine.leaf_rules_problems
tls_range_of :: engine.tls_range_of

// log.odin
Level :: engine.Level
log_enabled :: engine.log_enabled
log_get_verb :: engine.log_get_verb
log_set_sink :: engine.log_set_sink
log_set_verb :: engine.log_set_verb
logf :: engine.logf

// mssfix.odin
MSS_NOT_APPLIED :: engine.MSS_NOT_APPLIED
client_mss_line :: engine.client_mss_line
mss_for_session :: engine.mss_for_session
mtu_fit_warning :: engine.mtu_fit_warning
srv_mss_text :: engine.srv_mss_text

// offload.odin
Off_Config :: engine.Off_Config
Offload_Stats :: engine.Offload_Stats
RX_MSGS_GRO :: engine.RX_MSGS_GRO
TUN_BUF_SIZE :: engine.TUN_BUF_SIZE
TUN_TX_ARENA :: engine.TUN_TX_ARENA
Tun_Tx :: engine.Tun_Tx
UDP_GRO_SLOT :: engine.UDP_GRO_SLOT
inside :: engine.inside
off_load_config :: engine.off_load_config
off_note_tun :: engine.off_note_tun
off_parse_config :: engine.off_parse_config
off_rx_layout :: engine.off_rx_layout
off_sock :: engine.off_sock
off_status_line :: engine.off_status_line
off_sync_batches :: engine.off_sync_batches
rx_vlen :: engine.rx_vlen
tun_tx_flush :: engine.tun_tx_flush
tun_tx_push :: engine.tun_tx_push

// outcome.odin
Exit :: engine.Exit
close_outcome :: engine.close_outcome
close_reason_stops :: engine.close_reason_stops

// records.odin
rec_end :: engine.rec_end
rec_save :: engine.rec_save
rec_start :: engine.rec_start

// ring.odin
MAX_TUN_PACKET :: engine.MAX_TUN_PACKET
SLOT_SIZE :: engine.SLOT_SIZE

// settings.odin
Settings :: engine.Settings
format_settings_notes :: engine.format_settings_notes
has_directive :: engine.has_directive
read_key_source :: engine.read_key_source
settings_destroy :: engine.settings_destroy
settings_load :: engine.settings_load
tun_name_of :: engine.tun_name_of

// status.odin
log_counters :: engine.log_counters
rss_kb :: engine.rss_kb

// sys_*.odin
crl_stat :: engine.crl_stat
crl_stat_why :: engine.crl_stat_why

// testknob.odin
test_aead_limit :: engine.test_aead_limit
test_outer_rekey_bytes :: engine.test_outer_rekey_bytes

// tls_transport.odin
classify_first_bytes :: engine.classify_first_bytes
outer_server_ctx :: engine.outer_server_ctx
proto_name :: engine.proto_name
rekey_size_text :: engine.rekey_size_text

// webauth.odin
web_auth_read :: engine.web_auth_read

// ws.odin
WS_HEADER_MAX :: engine.WS_HEADER_MAX
WS_OP_CLOSE :: engine.WS_OP_CLOSE
WS_OP_PONG :: engine.WS_OP_PONG
WS_REPLY_400 :: engine.WS_REPLY_400
WS_REPLY_404 :: engine.WS_REPLY_404
Ws_Out :: engine.Ws_Out
Ws_Rx :: engine.Ws_Rx
classify_plain :: engine.classify_plain
http_head_end :: engine.http_head_end
ws_close_payload :: engine.ws_close_payload
ws_out_ctl :: engine.ws_out_ctl
ws_out_destroy :: engine.ws_out_destroy
ws_out_init :: engine.ws_out_init
ws_out_next :: engine.ws_out_next
ws_out_pending :: engine.ws_out_pending
ws_refusal :: engine.ws_refusal
ws_reply_build :: engine.ws_reply_build
ws_request_check :: engine.ws_request_check
ws_rx_next :: engine.ws_rx_next
