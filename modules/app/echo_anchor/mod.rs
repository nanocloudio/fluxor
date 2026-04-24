//! echo_anchor — demonstration transport anchor.
//!
//! Pairs with `echo_worker` to demonstrate the anchor / worker split
//! described in `docs/architecture/protocol_surfaces.md`. This module
//! plays the **transport anchor** role: it owns the client-visible TCP
//! attachment (bound listener + accepted client conn via net_proto /
//! Stream Surface v1 against the IP module or linux_net), and forwards
//! cleartext bytes over a channel to a session worker.
//!
//! The worker in turn owns the session state (trivial here: uppercase
//! each byte) and replies through a second data channel back to the
//! anchor, which relays the reply on the client's TCP stream.
//!
//! Channel topology:
//!
//!   linux_net.net_out  →  anchor.net_in    (net_proto events)
//!   anchor.net_out      →  linux_net.net_in (net_proto commands)
//!   anchor.ctrl_out    →  worker.ctrl_in    (SessionCtrlV1)
//!   worker.ctrl_out    →  anchor.ctrl_in    (SessionCtrlV1 replies)
//!   anchor.data_out    →  worker.data_in    (client bytes → worker)
//!   worker.data_out    →  anchor.data_in    (worker bytes → client)
//!
//! Handles a single client at a time. If a new client arrives while a
//! session is active, the new connection is immediately closed on the
//! TCP side — not rejected silently. Extending to multi-session needs
//! a per-session table keyed by `session_id` and a session-tagged
//! data-plane framing.
//!
//! # Parameters (TLV v2)
//!
//! | Tag | Name        | Type | Default | Description             |
//! |-----|-------------|------|---------|-------------------------|
//! | 1   | listen_port | u16  | 9000    | TCP port to bind.       |
//!
//! # Wire format
//!
//! See `modules/sdk/contracts/net/session_ctrl.rs` for SessionCtrlV1
//! and `modules/sdk/contracts/net/net_proto.rs` for Stream Surface v1.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Stream Surface v1 opcodes (subset we use — see net_proto.rs)
// ============================================================================

const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_ERROR: u8 = 0x06;

const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;

// ============================================================================
// SessionCtrlV1 opcodes (subset we use — see session_ctrl.rs)
// ============================================================================

const SC_CMD_ATTACH: u8 = 0x71;
const SC_CMD_DETACH: u8 = 0x72;

const SC_MSG_ATTACHED: u8 = 0x91;
const SC_MSG_DETACHED: u8 = 0x92;
const SC_MSG_ERROR: u8 = 0x9F;

const SC_CC_EDGE_ANCHORED: u8 = 4;

const SC_DETACH_NORMAL: u8 = 0;
const SC_DETACH_CLIENT_GONE: u8 = 4;

const SESSION_ID_BYTES: usize = 16;
const ANCHOR_ID_BYTES: usize = 8;
const WORKER_ID_BYTES: usize = 8;
const EPOCH_BYTES: usize = 4;

/// Fixed anchor identifier. A real deployment sets this from a
/// manifest parameter or cluster-assigned value; hardcoding here keeps
/// the demo self-contained.
const ANCHOR_ID: [u8; ANCHOR_ID_BYTES] = *b"DEMO-A01";

// ============================================================================
// Config / buffers
// ============================================================================

/// Max net_proto frame we handle (3-byte header + up to 1024 payload).
const NET_BUF_SIZE: usize = 1 + 1024 + 16;

/// Max SessionCtrlV1 frame (identity + a few fields).
const CTRL_BUF_SIZE: usize = 128;

/// Raw-data chunk buffer (one tick's worth of forwarded bytes).
const DATA_BUF_SIZE: usize = 512;

/// Scratch for `dev_mon_session` line rendering.
const MON_BUF_SIZE: usize = 192;

// ============================================================================
// State machine
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum AnchorPhase {
    Init = 0,
    BindingNet = 1,
    WaitBoundNet = 2,
    Listening = 3,
    Attaching = 4,
    WaitAttached = 5,
    Active = 6,
    Detaching = 7,
    WaitDetached = 8,
    Error = 255,
}

#[repr(C)]
struct AnchorState {
    syscalls: *const SyscallTable,

    // Channels
    net_in: i32,
    net_out: i32,
    ctrl_in: i32,
    ctrl_out: i32,
    data_in: i32,
    data_out: i32,

    // Config
    listen_port: u16,
    phase: AnchorPhase,
    _pad0: u8,

    // net_proto state
    /// Server (listener) conn_id assigned by IP module. Only meaningful
    /// once we've seen MSG_BOUND.
    server_conn_id: u8,
    /// Accepted-client conn_id (0xFF = no active client).
    client_conn_id: u8,
    _pad1: [u8; 2],

    // Session identity
    session_id: [u8; SESSION_ID_BYTES],
    session_epoch: u32,
    /// Monotonic counter used to mint a fresh session_id per attach.
    session_counter: u64,

    /// Cached scheduler index from `dev_self_index` for MON_SESSION
    /// emission. `0xFF` until first resolved.
    self_idx: u8,
    _pad2: [u8; 3],

    // Buffers
    net_buf: [u8; NET_BUF_SIZE],
    ctrl_buf: [u8; CTRL_BUF_SIZE],
    data_buf: [u8; DATA_BUF_SIZE],
    mon_buf: [u8; MON_BUF_SIZE],
}

impl AnchorState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in = -1;
        self.net_out = -1;
        self.ctrl_in = -1;
        self.ctrl_out = -1;
        self.data_in = -1;
        self.data_out = -1;
        self.listen_port = 9000;
        self.phase = AnchorPhase::Init;
        self._pad0 = 0;
        self.server_conn_id = 0;
        self.client_conn_id = 0xFF;
        self._pad1 = [0; 2];
        self.session_id = [0; SESSION_ID_BYTES];
        self.session_epoch = 0;
        self.session_counter = 0;
        self.self_idx = 0xFF;
        self._pad2 = [0; 3];
    }
}

/// Lazy-resolve and cache `self_idx`, then emit a `MON_SESSION` line.
unsafe fn mon_emit(s: &mut AnchorState, event: u8, reason: &[u8], status: &[u8]) {
    let sys_ptr = s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(&*sys_ptr);
        if idx >= 0 { s.self_idx = idx as u8; }
    }
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let session_ptr = s.session_id.as_ptr();
    let anchor_ptr = ANCHOR_ID.as_ptr();
    let _ = dev_mon_session(
        &*sys_ptr,
        s.self_idx, event,
        session_ptr, s.session_epoch,
        anchor_ptr, core::ptr::null(), // worker_id unknown to anchor
        reason, status,
        mon_ptr, MON_BUF_SIZE,
    );
}

// ============================================================================
// Parameter definitions
// ============================================================================

mod params_def {
    use super::AnchorState;
    use super::p_u16;
    use super::SCHEMA_MAX;

    define_params! {
        AnchorState;

        1, listen_port, u16, 9000
            => |s, d, len| { s.listen_port = p_u16(d, len, 0, 9000); };
    }
}

// ============================================================================
// net_proto emitters
// ============================================================================

unsafe fn net_send_bind(s: &mut AnchorState) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.net_out;
    if out_chan < 0 { return false; }
    let port = s.listen_port.to_le_bytes();
    let payload = [port[0], port[1]];
    let scratch = s.net_buf.as_mut_ptr();
    let wrote = net_write_frame(
        &*sys_ptr, out_chan, NET_CMD_BIND,
        payload.as_ptr(), 2,
        scratch, NET_BUF_SIZE,
    );
    wrote > 0
}

/// Emit CMD_SEND. Payload: `[conn_id:1][data:n]`.
unsafe fn net_send_data(s: &mut AnchorState, conn_id: u8, data: *const u8, data_len: usize) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.net_out;
    if out_chan < 0 || data_len + 1 + NET_FRAME_HDR > NET_BUF_SIZE {
        return false;
    }
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 1 + data_len;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(NET_FRAME_HDR) = conn_id;
    core::ptr::copy_nonoverlapping(data, scratch.add(NET_FRAME_HDR + 1), data_len);
    let total = NET_FRAME_HDR + payload_len;
    let wrote = ((*sys_ptr).channel_write)(out_chan, scratch, total);
    wrote > 0
}

unsafe fn net_send_close(s: &mut AnchorState, conn_id: u8) {
    let sys_ptr = s.syscalls;
    let out_chan = s.net_out;
    if out_chan < 0 { return; }
    let payload = [conn_id];
    let scratch = s.net_buf.as_mut_ptr();
    net_write_frame(
        &*sys_ptr, out_chan, NET_CMD_CLOSE,
        payload.as_ptr(), 1,
        scratch, NET_BUF_SIZE,
    );
}

// ============================================================================
// SessionCtrlV1 emitters
// ============================================================================

/// Mint a fresh session_id = anchor_id (8 bytes) || counter (8 bytes BE).
unsafe fn mint_session_id(s: &mut AnchorState) {
    s.session_counter = s.session_counter.wrapping_add(1);
    let mut id = [0u8; SESSION_ID_BYTES];
    id[..ANCHOR_ID_BYTES].copy_from_slice(&ANCHOR_ID);
    let ctr = s.session_counter.to_be_bytes();
    id[ANCHOR_ID_BYTES..].copy_from_slice(&ctr);
    s.session_id = id;
    s.session_epoch = 1;
}

/// Emit CMD_SC_ATTACH.
///   [session_id:16 BE][anchor_id:8 BE][epoch:4 LE][cc:1][worker_hint:8 BE=all-zero]
unsafe fn sc_send_attach(s: &mut AnchorState) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out;
    if out_chan < 0 { return false; }
    let mut payload = [0u8;
        SESSION_ID_BYTES + ANCHOR_ID_BYTES + EPOCH_BYTES + 1 + WORKER_ID_BYTES];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + ANCHOR_ID_BYTES]
        .copy_from_slice(&ANCHOR_ID);
    let epoch_le = s.session_epoch.to_le_bytes();
    payload[SESSION_ID_BYTES + ANCHOR_ID_BYTES
        ..SESSION_ID_BYTES + ANCHOR_ID_BYTES + EPOCH_BYTES]
        .copy_from_slice(&epoch_le);
    payload[SESSION_ID_BYTES + ANCHOR_ID_BYTES + EPOCH_BYTES] = SC_CC_EDGE_ANCHORED;
    // worker_hint left all-zero — "let the worker accept"
    let scratch = s.ctrl_buf.as_mut_ptr();
    let wrote = net_write_frame(
        &*sys_ptr, out_chan, SC_CMD_ATTACH,
        payload.as_ptr(), payload.len(),
        scratch, CTRL_BUF_SIZE,
    );
    wrote > 0
}

/// Emit CMD_SC_DETACH. Payload: `[session_id:16][epoch:4 LE][reason:1]`.
unsafe fn sc_send_detach(s: &mut AnchorState, reason: u8) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out;
    if out_chan < 0 { return false; }
    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 1];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    let epoch_le = s.session_epoch.to_le_bytes();
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES].copy_from_slice(&epoch_le);
    payload[SESSION_ID_BYTES + EPOCH_BYTES] = reason;
    let scratch = s.ctrl_buf.as_mut_ptr();
    let wrote = net_write_frame(
        &*sys_ptr, out_chan, SC_CMD_DETACH,
        payload.as_ptr(), payload.len(),
        scratch, CTRL_BUF_SIZE,
    );
    wrote > 0
}

// ============================================================================
// Event handlers
// ============================================================================

/// Drain one net_proto frame. Updates phase and session state.
unsafe fn poll_net_in(s: &mut AnchorState) {
    if s.net_in < 0 { return; }
    let sys_ptr = s.syscalls;
    let chan = s.net_in;
    let poll = ((*sys_ptr).channel_poll)(chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(&*sys_ptr, chan, buf, NET_BUF_SIZE);

    match msg_type {
        NET_MSG_BOUND => {
            // Two shapes exist on the wire:
            //   bare-metal IP module: [conn_id:1][local_port:2 LE]
            //   linux_net provider:   (empty payload)
            // Both mean "listener is ready". We store conn_id if present,
            // otherwise leave `server_conn_id` at its init value (0).
            if s.phase == AnchorPhase::WaitBoundNet {
                if payload_len >= 1 {
                    s.server_conn_id = *buf.add(NET_FRAME_HDR);
                }
                s.phase = AnchorPhase::Listening;
                dev_log(&*sys_ptr, 3, b"[echo_anc] bound".as_ptr(), 16);
            }
        }
        NET_MSG_ACCEPTED => {
            // [conn_id:1]
            if payload_len >= 1 {
                let new_id = *buf.add(NET_FRAME_HDR);
                if s.client_conn_id == 0xFF && s.phase == AnchorPhase::Listening {
                    s.client_conn_id = new_id;
                    mint_session_id(s);
                    s.phase = AnchorPhase::Attaching;
                    dev_log(&*sys_ptr, 3, b"[echo_anc] accepted, attaching".as_ptr(), 30);
                } else {
                    // Already serving a client — reject the new one by
                    // immediately closing it.
                    net_send_close(s, new_id);
                    dev_log(&*sys_ptr, 2, b"[echo_anc] busy: closed new client".as_ptr(), 33);
                }
            }
        }
        NET_MSG_DATA => {
            // [conn_id:1][data:n]. Forward cleartext to data_out.
            if payload_len >= 2 && s.phase == AnchorPhase::Active {
                let id = *buf.add(NET_FRAME_HDR);
                if id == s.client_conn_id {
                    let data_len = payload_len - 1;
                    let data = buf.add(NET_FRAME_HDR + 1);
                    // Best-effort forward — drop on data_out full. A
                    // real anchor would buffer; this is a demo.
                    if s.data_out >= 0 {
                        let _ = ((*sys_ptr).channel_write)(s.data_out, data, data_len);
                    }
                }
            }
        }
        NET_MSG_CLOSED => {
            // [conn_id:1]. Client gone → detach worker, return to Listening.
            if payload_len >= 1 {
                let id = *buf.add(NET_FRAME_HDR);
                if id == s.client_conn_id {
                    match s.phase {
                        AnchorPhase::Active
                        | AnchorPhase::Attaching
                        | AnchorPhase::WaitAttached => {
                            sc_send_detach(s, SC_DETACH_CLIENT_GONE);
                            s.phase = AnchorPhase::WaitDetached;
                            mon_emit(s, MON_EV_DETACH_REQ, b"client_gone", b"");
                        }
                        _ => {
                            s.client_conn_id = 0xFF;
                            s.phase = AnchorPhase::Listening;
                        }
                    }
                }
            }
        }
        NET_MSG_ERROR => {
            dev_log(&*sys_ptr, 1, b"[echo_anc] net error".as_ptr(), 20);
            s.phase = AnchorPhase::Error;
        }
        _ => { /* ignore unknown upstream opcodes */ }
    }
}

/// Drain one SessionCtrlV1 frame from worker.
unsafe fn poll_ctrl_in(s: &mut AnchorState) {
    if s.ctrl_in < 0 { return; }
    let sys_ptr = s.syscalls;
    let chan = s.ctrl_in;
    let poll = ((*sys_ptr).channel_poll)(chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.ctrl_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(&*sys_ptr, chan, buf, CTRL_BUF_SIZE);

    match msg_type {
        SC_MSG_ATTACHED => {
            // [session_id:16][epoch:4][status:1]. Only go Active on status=OK
            // AND session_id matches.
            if payload_len >= SESSION_ID_BYTES + EPOCH_BYTES + 1
                && s.phase == AnchorPhase::WaitAttached
            {
                let p = buf.add(NET_FRAME_HDR);
                // Match session_id — a stale worker reply for an
                // earlier session is dropped.
                let mut i = 0;
                let mut match_ok = true;
                while i < SESSION_ID_BYTES {
                    if *p.add(i) != s.session_id[i] { match_ok = false; break; }
                    i += 1;
                }
                let status = *p.add(SESSION_ID_BYTES + EPOCH_BYTES);
                if match_ok && status == 0 {
                    s.phase = AnchorPhase::Active;
                    dev_log(&*sys_ptr, 3, b"[echo_anc] active".as_ptr(), 17);
                } else {
                    // Worker refused or session mismatch — drop the client.
                    if s.client_conn_id != 0xFF {
                        net_send_close(s, s.client_conn_id);
                    }
                    s.phase = AnchorPhase::Detaching;
                }
            }
        }
        SC_MSG_DETACHED => {
            // Worker acknowledged detach. Close client if still open
            // and return to Listening; the IP module preserves the
            // listener slot across accepted connections.
            if payload_len >= SESSION_ID_BYTES + EPOCH_BYTES {
                if s.client_conn_id != 0xFF {
                    net_send_close(s, s.client_conn_id);
                    s.client_conn_id = 0xFF;
                }
                s.session_id = [0; SESSION_ID_BYTES];
                s.session_epoch = 0;
                s.phase = AnchorPhase::Listening;
                dev_log(&*sys_ptr, 3, b"[echo_anc] listening".as_ptr(), 20);
            }
        }
        SC_MSG_ERROR => {
            dev_log(&*sys_ptr, 1, b"[echo_anc] worker error".as_ptr(), 23);
            if s.client_conn_id != 0xFF {
                net_send_close(s, s.client_conn_id);
            }
            s.phase = AnchorPhase::Detaching;
        }
        _ => { /* ignore unknown opcodes */ }
    }
}

/// Forward worker output (data_in) back to client via CMD_SEND.
unsafe fn poll_data_in(s: &mut AnchorState) {
    if s.data_in < 0 || s.phase != AnchorPhase::Active || s.client_conn_id == 0xFF {
        return;
    }
    let sys_ptr = s.syscalls;
    let poll = ((*sys_ptr).channel_poll)(s.data_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }
    let buf = s.data_buf.as_mut_ptr();
    let read = ((*sys_ptr).channel_read)(s.data_in, buf, DATA_BUF_SIZE);
    if read <= 0 {
        return;
    }
    let client = s.client_conn_id;
    net_send_data(s, client, buf, read as usize);
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<AnchorState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<AnchorState>() { return -6; }

        let s = &mut *(state as *mut AnchorState);
        s.init(syscalls as *const SyscallTable);

        // Ports: in[0]=net_in, in[1]=ctrl_in, in[2]=data_in;
        //        out[0]=net_out, out[1]=ctrl_out, out[2]=data_out.
        s.net_in = in_chan;
        s.net_out = out_chan;
        let sys_ptr = s.syscalls;
        let ctrl_in = dev_channel_port(&*sys_ptr, 0, 1);
        if ctrl_in >= 0 { s.ctrl_in = ctrl_in; }
        let data_in = dev_channel_port(&*sys_ptr, 0, 2);
        if data_in >= 0 { s.data_in = data_in; }
        let ctrl_out = dev_channel_port(&*sys_ptr, 1, 1);
        if ctrl_out >= 0 { s.ctrl_out = ctrl_out; }
        let data_out = dev_channel_port(&*sys_ptr, 1, 2);
        if data_out >= 0 { s.data_out = data_out; }

        // Parse TLV params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        dev_log(&*sys_ptr, 3, b"[echo_anc] init".as_ptr(), 15);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut AnchorState);
        if s.syscalls.is_null() { return -1; }

        match s.phase {
            AnchorPhase::Init => {
                s.phase = AnchorPhase::BindingNet;
            }
            AnchorPhase::BindingNet => {
                if net_send_bind(s) {
                    s.phase = AnchorPhase::WaitBoundNet;
                    return 2;
                }
            }
            AnchorPhase::WaitBoundNet => {
                poll_net_in(s);
            }
            AnchorPhase::Listening => {
                poll_net_in(s);
            }
            AnchorPhase::Attaching => {
                if sc_send_attach(s) {
                    s.phase = AnchorPhase::WaitAttached;
                    mon_emit(s, MON_EV_ATTACH_REQ, b"", b"");
                    return 2;
                }
            }
            AnchorPhase::WaitAttached => {
                poll_ctrl_in(s);
                poll_net_in(s); // client may still disconnect during attach
            }
            AnchorPhase::Active => {
                poll_net_in(s);
                poll_ctrl_in(s);
                poll_data_in(s);
            }
            AnchorPhase::Detaching => {
                if sc_send_detach(s, SC_DETACH_NORMAL) {
                    s.phase = AnchorPhase::WaitDetached;
                    mon_emit(s, MON_EV_DETACH_REQ, b"normal", b"");
                    return 2;
                }
            }
            AnchorPhase::WaitDetached => {
                poll_ctrl_in(s);
            }
            AnchorPhase::Error => {
                return 1;
            }
        }

        0
    }
}
