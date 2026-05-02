//! echo_worker — demonstration SessionCtrlV1 session worker.
//!
//! Pairs with `echo_anchor` to demonstrate the anchor / worker split
//! described in `docs/architecture/protocol_surfaces.md`. The anchor
//! owns the client-visible TCP transport; this worker owns the session
//! state (trivial here: uppercase each byte). Two channel pairs link
//! them:
//!
//!   anchor.ctrl_out  →  worker.ctrl_in    (SessionCtrlV1)
//!   worker.ctrl_out  →  anchor.ctrl_in    (SessionCtrlV1 replies)
//!   anchor.data_out  →  worker.data_in    (client bytes → worker)
//!   worker.data_out  →  anchor.data_in    (worker bytes → client)
//!
//! The worker handles a single session at a time (the demo models one
//! client). Extending to multi-session needs a per-session table keyed
//! by `session_id`.
//!
//! # Protocol flow
//!
//!   anchor → worker : CMD_SC_HELLO (ROLE_ANCHOR)
//!   worker → anchor : MSG_SC_HELLO_ACK (ROLE_WORKER)
//!   (client connects to anchor)
//!   anchor → worker : CMD_SC_ATTACH (session_id, epoch=1, anchor_id, cc=CC_EDGE_ANCHORED)
//!   worker → anchor : MSG_SC_ATTACHED (status=OK)
//!   (data flows bidirectionally — worker uppercases each byte)
//!   anchor → worker : CMD_SC_DETACH (reason)
//!   worker → anchor : MSG_SC_DETACHED
//!
//! # Wire format
//!
//! See `modules/sdk/contracts/net/session_ctrl.rs`. session_id is 16
//! bytes big-endian; anchor_id / worker_id are 8 bytes big-endian;
//! session_epoch is 4 bytes little-endian.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// SessionCtrlV1 opcodes (see modules/sdk/contracts/net/session_ctrl.rs)
// ============================================================================

const SC_CMD_HELLO: u8 = 0x70;
const SC_CMD_ATTACH: u8 = 0x71;
const SC_CMD_DETACH: u8 = 0x72;
const SC_CMD_DRAIN: u8 = 0x73;

const SC_MSG_HELLO_ACK: u8 = 0x90;
const SC_MSG_ATTACHED: u8 = 0x91;
const SC_MSG_DETACHED: u8 = 0x92;
const SC_MSG_DRAINED: u8 = 0x93;

const SC_ROLE_WORKER: u8 = 2;

const SC_STATUS_OK: u8 = 0;

const SESSION_ID_BYTES: usize = 16;
const ANCHOR_ID_BYTES: usize = 8;
const WORKER_ID_BYTES: usize = 8;
const EPOCH_BYTES: usize = 4;

/// Fixed worker identifier. A real worker would take this from a
/// manifest parameter or a cluster directory assignment.
const WORKER_ID: [u8; WORKER_ID_BYTES] = *b"DEMO-W01";

/// Control frame buffer — large enough for ATTACH (+ fields) and
/// chunked export/import (if we ever hook it up). Keep conservative.
const CTRL_BUF_SIZE: usize = 128;

/// Data byte buffer — arbitrary chunk size for one step's worth of
/// bytes flowing through the worker.
const DATA_BUF_SIZE: usize = 512;

/// Scratch for `dev_mon_session` line rendering. Sized at the SDK
/// helper's documented minimum so the caller side doesn't have to
/// reason about it.
const MON_BUF_SIZE: usize = 192;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum WorkerPhase {
    /// No anchor has said hello yet.
    Dormant = 0,
    /// Handshaked with anchor; ready for ATTACH.
    Idle = 1,
    /// An ATTACH has bound a session_id; data flows.
    Active = 2,
    /// DRAIN received — stop pulling data_in, flush data_out.
    Draining = 3,
}

#[repr(C)]
struct WorkerState {
    syscalls: *const SyscallTable,

    ctrl_in: i32,
    ctrl_out: i32,
    data_in: i32,
    data_out: i32,

    phase: WorkerPhase,
    _pad0: [u8; 3],

    /// Current bound session. All zero when Idle/Dormant.
    session_id: [u8; SESSION_ID_BYTES],
    anchor_id: [u8; ANCHOR_ID_BYTES],
    session_epoch: u32,

    /// Statistics (readable via memory dump).
    bytes_processed: u32,

    /// Cached scheduler index from `dev_self_index` for MON_SESSION
    /// emission. `0xFF` until first resolved (we lazy-resolve on the
    /// first transition to avoid spending the syscall when the
    /// monitor path is unused).
    self_idx: u8,
    _pad1: [u8; 3],

    ctrl_buf: [u8; CTRL_BUF_SIZE],
    data_buf: [u8; DATA_BUF_SIZE],
    mon_buf: [u8; MON_BUF_SIZE],
}

impl WorkerState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.ctrl_in = -1;
        self.ctrl_out = -1;
        self.data_in = -1;
        self.data_out = -1;
        self.phase = WorkerPhase::Dormant;
        self._pad0 = [0; 3];
        self.session_id = [0; SESSION_ID_BYTES];
        self.anchor_id = [0; ANCHOR_ID_BYTES];
        self.session_epoch = 0;
        self.bytes_processed = 0;
        self.self_idx = 0xFF;
        self._pad1 = [0; 3];
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// SessionCtrlV1 emitters
// ============================================================================

/// Write a SessionCtrlV1 frame: `[msg_type][len:2 LE][payload...]`.
/// Frame assembly reuses `ctrl_buf`; caller provides the payload slice
/// fully formed. Uses raw syscall-pointer deref to avoid holding an
/// immutable borrow of `s` while mutably touching `ctrl_buf`.
unsafe fn sc_write(s: &mut WorkerState, msg_type: u8, payload: *const u8, payload_len: usize) {
    if s.ctrl_out < 0 || payload_len + NET_FRAME_HDR > CTRL_BUF_SIZE {
        return;
    }
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out;
    let scratch = s.ctrl_buf.as_mut_ptr();
    net_write_frame(
        &*sys_ptr, out_chan, msg_type,
        payload, payload_len,
        scratch, CTRL_BUF_SIZE,
    );
}

/// Lazy-resolve and cache `self_idx`, then emit a `MON_SESSION` line
/// for the currently bound session.
unsafe fn mon_emit(s: &mut WorkerState, event: u8, reason: &[u8], status: &[u8]) {
    let sys_ptr = s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(&*sys_ptr);
        if idx >= 0 { s.self_idx = idx as u8; }
    }
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let session_ptr = s.session_id.as_ptr();
    let anchor_ptr = s.anchor_id.as_ptr();
    let worker_ptr = WORKER_ID.as_ptr();
    let _ = dev_mon_session(
        &*sys_ptr,
        s.self_idx, event,
        session_ptr, s.session_epoch,
        anchor_ptr, worker_ptr,
        reason, status,
        mon_ptr, MON_BUF_SIZE,
    );
}

/// Emit MSG_SC_HELLO_ACK: [role: u8] [worker_id: 8 BE] [flags: u8].
unsafe fn send_hello_ack(s: &mut WorkerState) {
    let mut payload = [0u8; 1 + WORKER_ID_BYTES + 1];
    payload[0] = SC_ROLE_WORKER;
    payload[1..1 + WORKER_ID_BYTES].copy_from_slice(&WORKER_ID);
    payload[1 + WORKER_ID_BYTES] = 0; // flags reserved
    sc_write(s, SC_MSG_HELLO_ACK, payload.as_ptr(), payload.len());
}

/// Emit MSG_SC_ATTACHED / MSG_SC_DETACHED / MSG_SC_DRAINED.
/// All three share the shape [session_id: 16 BE][epoch: 4 LE][...],
/// with an optional trailing status byte for ATTACHED.
unsafe fn send_session_event(
    s: &mut WorkerState,
    msg_type: u8,
    include_status: bool,
    status: u8,
) {
    let base = SESSION_ID_BYTES + EPOCH_BYTES;
    let total = if include_status { base + 1 } else { base };
    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 1];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    let epoch_le = s.session_epoch.to_le_bytes();
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES].copy_from_slice(&epoch_le);
    if include_status {
        payload[base] = status;
    }
    sc_write(s, msg_type, payload.as_ptr(), total);
}

// ============================================================================
// Control frame processing
// ============================================================================

unsafe fn handle_ctrl(s: &mut WorkerState) {
    if s.ctrl_in < 0 {
        return;
    }
    let sys_ptr = s.syscalls;
    let ctrl_in = s.ctrl_in;
    let poll = ((*sys_ptr).channel_poll)(ctrl_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.ctrl_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(&*sys_ptr, ctrl_in, buf, CTRL_BUF_SIZE);

    match msg_type {
        SC_CMD_HELLO => {
            // Payload: [role: u8] [peer_id: 8 BE] [flags: u8]. We only
            // care that the anchor has pinged us — reply with
            // HELLO_ACK and transition to Idle.
            if payload_len >= 1 + ANCHOR_ID_BYTES {
                if s.phase == WorkerPhase::Dormant {
                    s.phase = WorkerPhase::Idle;
                }
                send_hello_ack(s);
            }
        }
        SC_CMD_ATTACH => {
            // Payload: [session_id:16][anchor_id:8][epoch:4 LE][cc:1][worker_id_hint:8].
            // Accept ATTACH from Dormant or Idle — HELLO handshake is
            // optional in the protocol, so a worker that never received
            // a HELLO still honors a direct ATTACH.
            let expected = SESSION_ID_BYTES + ANCHOR_ID_BYTES + EPOCH_BYTES + 1 + WORKER_ID_BYTES;
            let can_attach = s.phase == WorkerPhase::Dormant || s.phase == WorkerPhase::Idle;
            if payload_len >= expected && can_attach {
                let p = buf.add(NET_FRAME_HDR);
                let mut i = 0;
                while i < SESSION_ID_BYTES {
                    s.session_id[i] = *p.add(i);
                    i += 1;
                }
                let mut j = 0;
                while j < ANCHOR_ID_BYTES {
                    s.anchor_id[j] = *p.add(SESSION_ID_BYTES + j);
                    j += 1;
                }
                s.session_epoch = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES + ANCHOR_ID_BYTES),
                    *p.add(SESSION_ID_BYTES + ANCHOR_ID_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + ANCHOR_ID_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + ANCHOR_ID_BYTES + 3),
                ]);
                s.bytes_processed = 0;
                s.phase = WorkerPhase::Active;
                send_session_event(s, SC_MSG_ATTACHED, true, SC_STATUS_OK);
                mon_emit(s, MON_EV_ATTACHED, b"", b"ok");
            }
        }
        SC_CMD_DRAIN => {
            // Drain: stop consuming data_in, flush what we've already emitted.
            if s.phase == WorkerPhase::Active {
                s.phase = WorkerPhase::Draining;
                send_session_event(s, SC_MSG_DRAINED, false, 0);
                mon_emit(s, MON_EV_DRAINED, b"", b"");
            }
        }
        SC_CMD_DETACH => {
            // Detach: clear state, back to Idle.
            if s.phase == WorkerPhase::Active || s.phase == WorkerPhase::Draining {
                send_session_event(s, SC_MSG_DETACHED, false, 0);
                mon_emit(s, MON_EV_DETACHED, b"normal", b"");
                s.session_id = [0; SESSION_ID_BYTES];
                s.anchor_id = [0; ANCHOR_ID_BYTES];
                s.session_epoch = 0;
                s.phase = WorkerPhase::Idle;
            }
        }
        _ => {
            // Unknown opcode — ignore silently. The anchor is the
            // authoritative speaker here; we don't emit errors for
            // opcodes we haven't opted into.
        }
    }
}

// ============================================================================
// Data path: read data_in, uppercase ASCII letters, write data_out.
// ============================================================================

unsafe fn handle_data(s: &mut WorkerState) {
    if s.data_in < 0 || s.data_out < 0 {
        return;
    }
    // Only pull new data while Active — Draining means anchor has
    // asked us to stop adding new work.
    if s.phase != WorkerPhase::Active {
        return;
    }
    let sys_ptr = s.syscalls;
    let data_in = s.data_in;
    let data_out = s.data_out;

    // Gate on output readiness so we don't drop bytes.
    let out_poll = ((*sys_ptr).channel_poll)(data_out, POLL_OUT);
    if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 {
        return;
    }

    let in_poll = ((*sys_ptr).channel_poll)(data_in, POLL_IN);
    if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.data_buf.as_mut_ptr();
    let read = ((*sys_ptr).channel_read)(data_in, buf, DATA_BUF_SIZE);
    if read <= 0 {
        return;
    }
    let n = read as usize;

    // In-place ASCII upper-case.
    let mut i = 0;
    while i < n {
        let b = *buf.add(i);
        if b >= b'a' && b <= b'z' {
            *buf.add(i) = b - 32;
        }
        i += 1;
    }

    let written = ((*sys_ptr).channel_write)(data_out, buf, n);
    if written > 0 {
        s.bytes_processed = s.bytes_processed.wrapping_add(written as u32);
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<WorkerState>() as u32
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
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<WorkerState>() { return -6; }

        let s = &mut *(state as *mut WorkerState);
        s.init(syscalls as *const SyscallTable);

        // Ports: in[0] = ctrl_in, in[1] = data_in;
        //        out[0] = ctrl_out, out[1] = data_out.
        s.ctrl_in = in_chan;
        s.ctrl_out = out_chan;
        let sys_ptr = s.syscalls;
        let data_in = dev_channel_port(&*sys_ptr, 0, 1);
        if data_in >= 0 { s.data_in = data_in; }
        let data_out = dev_channel_port(&*sys_ptr, 1, 1);
        if data_out >= 0 { s.data_out = data_out; }

        dev_log(&*sys_ptr, 3, b"[echo_wkr] init".as_ptr(), 15);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut WorkerState);
        if s.syscalls.is_null() { return -1; }

        handle_ctrl(s);
        handle_data(s);

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
