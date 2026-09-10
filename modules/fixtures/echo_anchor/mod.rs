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
//! # Anchor-preserved worker handoff
//!
//! When a SECOND worker is wired (ports `ctrl2_*` / `data2_*`) and
//! `handoff_after_bytes` is non-zero, the anchor swaps the live session
//! between the two workers every N client bytes while the client's TCP
//! stream stays open — the edge_anchored maintenance pattern:
//!
//!   1. CMD_SC_DRAIN → active worker (it stops consuming; in this demo
//!      drain implies handoff-export)
//!   2. check EXPORT_BEGIN's delivery cursors against what this anchor
//!      forwarded and relayed — a disagreement means the blob and the
//!      client have seen different prefixes of the session, so the swap
//!      is refused and the session stays put — then relay the
//!      CMD_SC_EXPORT_BEGIN/CHUNK…/END frames verbatim to the standby
//!      worker (the blob itself stays opaque, §13.2)
//!   3. standby replies MSG_SC_IMPORT_BEGIN / MSG_SC_IMPORT_END
//!   4. CMD_SC_RESUME(epoch+1) → standby; MSG_SC_RESUMED flips the
//!      anchor's forwarding target and bumps `session_epoch`
//!   5. CMD_SC_DETACH → old worker (session continues on the new one)
//!
//! Client bytes arriving during the rebinding window are held in a
//! bounded ingress buffer and flushed to the new worker after RESUMED —
//! the explicit rebinding buffer §11.2 requires anchors to declare
//! (`HOLD_BUF_SIZE`; overflow is dropped with a log line).
//!
//! A handoff the anchor cannot make safe is REFUSED, not turned into a
//! client-visible failure: cursors that disagree, an import the standby
//! rejects, a worker error mid-handoff, or a drain that outlives
//! `DRAIN_DEADLINE_MS` all leave the session on the exporting worker.
//! The anchor detaches the standby, sends the exporting worker
//! CMD_SC_RESUME at the session's CURRENT epoch (nothing advanced — no
//! blob was committed anywhere), waits for its MSG_SC_RESUMED, and only
//! then releases the held ingress. The client saw a pause bounded by the
//! deadline and nothing else. Refusing costs a maintenance window;
//! proceeding would cost the client bytes nobody would learn were lost.
//!
//! # Parameters (TLV v2)
//!
//! | Tag | Name                | Type | Default | Description                          |
//! |-----|---------------------|------|---------|--------------------------------------|
//! | 1   | listen_port         | u16  | 9000    | TCP port to bind.                    |
//! | 2   | handoff_after_bytes | u32  | 0       | Swap workers every N client bytes (0 = never). |
//!
//! # Wire format
//!
//! See `modules/sdk/contracts/net/session_ctrl.rs` for SessionCtrlV1
//! and `modules/sdk/contracts/net/net_proto.rs` for Stream Surface v1.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]


use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

// Delivery-cursor admission (§Delivery cursors). The anchor mounts the
// handoff core for this alone — the blob itself stays opaque to it.
include!("../../sdk/cores/session_handoff.rs");

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

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
const SC_CMD_DRAIN: u8 = 0x73;
const SC_CMD_EXPORT_BEGIN: u8 = 0x74;
const SC_CMD_EXPORT_CHUNK: u8 = 0x75;
const SC_CMD_EXPORT_END: u8 = 0x76;
const SC_CMD_RESUME: u8 = 0x77;

const SC_MSG_ATTACHED: u8 = 0x91;
const SC_MSG_DETACHED: u8 = 0x92;
const SC_MSG_DRAINED: u8 = 0x93;
const SC_MSG_IMPORT_BEGIN: u8 = 0x94;
const SC_MSG_IMPORT_END: u8 = 0x96;
const SC_MSG_RESUMED: u8 = 0x97;
const SC_MSG_ERROR: u8 = 0x9F;

const SC_STATUS_OK: u8 = 0;

const SC_CC_EDGE_ANCHORED: u8 = 4;

const SC_DETACH_NORMAL: u8 = 0;
const SC_DETACH_CLIENT_GONE: u8 = 4;

const SESSION_ID_BYTES: usize = 16;
const ANCHOR_ID_BYTES: usize = 8;
const WORKER_ID_BYTES: usize = 8;
const EPOCH_BYTES: usize = 4;

/// Shortest status-carrying reply we act on:
/// `[session_id:16][epoch:4][status:1]`.
const STATUS_REPLY_MIN_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES + 1;

/// Fixed anchor identifier. A real deployment sets this from a
/// manifest parameter or cluster-assigned value; hardcoding here keeps
/// the demo self-contained.
const ANCHOR_ID: [u8; ANCHOR_ID_BYTES] = *b"DEMO-A01";

// ============================================================================
// Config / buffers
// ============================================================================

/// Max net_proto frame we handle (3-byte header + up to 1024 payload).
const NET_BUF_SIZE: usize = 1 + 1024 + 16;
/// No accepted client.
const NO_CONN: u16 = 0xFFFF;

/// The `conn_id` at the head of a net_proto payload (`u16 LE`).
#[inline(always)]
unsafe fn conn_id_at(p: *const u8) -> u16 {
    (*p as u16) | ((*p.add(1) as u16) << 8)
}

/// Max SessionCtrlV1 frame (identity + a few fields).
const CTRL_BUF_SIZE: usize = 128;

/// Raw-data chunk buffer (one tick's worth of forwarded bytes).
const DATA_BUF_SIZE: usize = 512;

/// Scratch for `dev_mon_session` line rendering.
const MON_BUF_SIZE: usize = 192;

/// Bounded ingress rebinding buffer (§11.2): client bytes arriving
/// while a worker handoff is in flight are held here and flushed to
/// the new worker after MSG_SC_RESUMED. Overflow policy: drop + log.
const HOLD_BUF_SIZE: usize = 512;

/// Scratch for relaying export frames old-worker → new-worker without
/// clobbering the ctrl frame being parsed.
const RELAY_BUF_SIZE: usize = 128;

/// Drain deadline handed to the outgoing worker (CMD_SC_DRAIN payload).
const DRAIN_DEADLINE_MS: u32 = 1000;

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

/// Worker-handoff sub-machine, orthogonal to `AnchorPhase::Active`
/// (the client transport stays live throughout — that is the point).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum HandoffPhase {
    /// No handoff in flight.
    Idle = 0,
    /// CMD_SC_DRAIN sent to the active worker; waiting MSG_SC_DRAINED.
    DrainWait = 1,
    /// Relaying EXPORT_BEGIN/CHUNK/END frames to the standby worker;
    /// waiting for its MSG_SC_IMPORT_END.
    ImportWait = 2,
    /// CMD_SC_RESUME sent to the standby; waiting MSG_SC_RESUMED.
    ResumeWait = 3,
    /// Swap recorded (active_w flipped, old worker detached) but the
    /// RETIRING worker's output channel may still hold replies the
    /// client must see FIRST. Until that channel polls empty, held
    /// ingress stays held and only the retiring slot is drained —
    /// otherwise a new-worker reply could overtake queued old-worker
    /// output whenever the new worker occupies a lower slot index
    /// (client-visible stream reordering under backpressure).
    RetireDrain = 4,
    /// The handoff was refused (cursors, import, error, deadline):
    /// standby detached, CMD_SC_RESUME at the CURRENT epoch sent to the
    /// exporting worker; waiting for its MSG_SC_RESUMED before the held
    /// ingress is released back to it.
    RefuseWait = 5,
}

#[repr(C)]
struct AnchorState {
    syscalls: *const SyscallTable,

    // Channels
    net_in: i32,
    net_out: i32,
    /// Worker channel pairs, indexed by worker slot (0 = primary,
    /// 1 = optional standby). Unwired slots hold -1.
    ctrl_in: [i32; 2],
    ctrl_out: [i32; 2],
    data_in: [i32; 2],
    data_out: [i32; 2],

    // Config
    listen_port: u16,
    phase: AnchorPhase,
    /// Which worker slot currently owns the session.
    active_w: u8,

    /// Handoff orchestration (see HandoffPhase).
    handoff: HandoffPhase,
    /// Swap workers every N forwarded client bytes (0 = never).
    /// Parameter tag 2; needs the second worker pair wired.
    handoff_after_bytes: u32,
    /// Session-scoped delivery cursors (§Delivery cursors): client
    /// bytes handed to the serving worker, and worker bytes put on the
    /// client transport. They count the session, not the worker, so a
    /// handoff carries them across unchanged.
    forwarded: u64,
    relayed: u64,
    /// Client bytes forwarded since the last swap.
    bytes_since_handoff: u32,
    /// `dev_millis` when the current handoff's DRAIN was sent; the
    /// deadline handed to the worker is enforced against it.
    handoff_started_ms: u64,
    /// Set while the old worker's MSG_SC_DETACHED (post-swap) is
    /// outstanding, so it is not mistaken for session-ending detach.
    detach_old_pending: bool,
    /// Set when a refusal's CMD_SC_RESUME could not be written (ctrl_out
    /// full); the step loop retries it.
    refuse_resume_pending: bool,
    _pad0: [u8; 2],

    /// Rebinding hold buffer (§11.2) + fill level.
    hold_len: u16,
    _pad3: [u8; 2],

    // net_proto state
    /// Server (listener) conn_id assigned by IP module. Only meaningful
    /// once we've seen MSG_BOUND.
    server_conn_id: u16,
    /// Accepted-client conn_id (`NO_CONN` = no active client).
    client_conn_id: u16,

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
    hold_buf: [u8; HOLD_BUF_SIZE],
    relay_buf: [u8; RELAY_BUF_SIZE],
}

impl AnchorState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in = -1;
        self.net_out = -1;
        self.ctrl_in = [-1; 2];
        self.ctrl_out = [-1; 2];
        self.data_in = [-1; 2];
        self.data_out = [-1; 2];
        self.forwarded = 0;
        self.relayed = 0;
        self.listen_port = 9000;
        self.phase = AnchorPhase::Init;
        self.active_w = 0;
        self.handoff = HandoffPhase::Idle;
        self.handoff_after_bytes = 0;
        self.bytes_since_handoff = 0;
        self.handoff_started_ms = 0;
        self.detach_old_pending = false;
        self.refuse_resume_pending = false;
        self._pad0 = [0; 2];
        self.hold_len = 0;
        self._pad3 = [0; 2];
        self.server_conn_id = 0;
        self.client_conn_id = NO_CONN;
        self.session_id = [0; SESSION_ID_BYTES];
        self.session_epoch = 0;
        self.session_counter = 0;
        self.self_idx = 0xFF;
        self._pad2 = [0; 3];
    }

    /// The standby worker slot (only meaningful when wired).
    #[inline]
    fn standby_w(&self) -> usize {
        1 - self.active_w as usize
    }

    /// True when a second worker channel pair is wired.
    #[inline]
    fn has_standby(&self) -> bool {
        self.ctrl_out[self.standby_w()] >= 0 && self.data_out[self.standby_w()] >= 0
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
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        AnchorState;

        1, listen_port, u16, 9000
            => |s, d, len| { s.listen_port = p_u16(d, len, 0, 9000); };

        2, handoff_after_bytes, u32, 0
            => |s, d, len| { s.handoff_after_bytes = p_u32(d, len, 0, 0); };
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

/// Emit CMD_SEND. Payload: `[conn_id:2 LE][data:n]`.
unsafe fn net_send_data(s: &mut AnchorState, conn_id: u16, data: *const u8, data_len: usize) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.net_out;
    if out_chan < 0 || data_len + 2 + NET_FRAME_HDR > NET_BUF_SIZE {
        return false;
    }
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 2 + data_len;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    let cb = conn_id.to_le_bytes();
    *scratch.add(NET_FRAME_HDR) = cb[0];
    *scratch.add(NET_FRAME_HDR + 1) = cb[1];
    core::ptr::copy_nonoverlapping(data, scratch.add(NET_FRAME_HDR + 2), data_len);
    let total = NET_FRAME_HDR + payload_len;
    let wrote = ((*sys_ptr).channel_write)(out_chan, scratch, total);
    wrote > 0
}

unsafe fn net_send_close(s: &mut AnchorState, conn_id: u16) {
    let sys_ptr = s.syscalls;
    let out_chan = s.net_out;
    if out_chan < 0 { return; }
    let payload = conn_id.to_le_bytes();
    let scratch = s.net_buf.as_mut_ptr();
    net_write_frame(
        &*sys_ptr, out_chan, NET_CMD_CLOSE,
        payload.as_ptr(), 2,
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
    s.bytes_since_handoff = 0;
    s.hold_len = 0;
    s.handoff = HandoffPhase::Idle;
}

/// Emit CMD_SC_ATTACH to worker slot `w`.
///   [session_id:16 BE][anchor_id:8 BE][epoch:4 LE][cc:1][worker_hint:8 BE=all-zero]
unsafe fn sc_send_attach(s: &mut AnchorState, w: usize) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out[w];
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

/// Emit CMD_SC_DETACH to worker slot `w`.
/// Payload: `[session_id:16][epoch:4 LE][reason:1]`.
unsafe fn sc_send_detach(s: &mut AnchorState, w: usize, reason: u8) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out[w];
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

/// Emit CMD_SC_DRAIN to worker slot `w`.
/// Payload: `[session_id:16][epoch:4 LE][deadline_ms:4 LE]`.
unsafe fn sc_send_drain(s: &mut AnchorState, w: usize) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out[w];
    if out_chan < 0 { return false; }
    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 4];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES]
        .copy_from_slice(&s.session_epoch.to_le_bytes());
    payload[SESSION_ID_BYTES + EPOCH_BYTES..]
        .copy_from_slice(&DRAIN_DEADLINE_MS.to_le_bytes());
    let scratch = s.ctrl_buf.as_mut_ptr();
    let wrote = net_write_frame(
        &*sys_ptr, out_chan, SC_CMD_DRAIN,
        payload.as_ptr(), payload.len(),
        scratch, CTRL_BUF_SIZE,
    );
    wrote > 0
}

/// Emit CMD_SC_RESUME to worker slot `w`.
/// Payload: `[session_id:16][new_epoch:4 LE]`.
unsafe fn sc_send_resume(s: &mut AnchorState, w: usize, new_epoch: u32) -> bool {
    let sys_ptr = s.syscalls;
    let out_chan = s.ctrl_out[w];
    if out_chan < 0 { return false; }
    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    payload[SESSION_ID_BYTES..].copy_from_slice(&new_epoch.to_le_bytes());
    let scratch = s.ctrl_buf.as_mut_ptr();
    let wrote = net_write_frame(
        &*sys_ptr, out_chan, SC_CMD_RESUME,
        payload.as_ptr(), payload.len(),
        scratch, CTRL_BUF_SIZE,
    );
    wrote > 0
}

/// Relay a just-parsed ctrl frame (sitting in `ctrl_buf`) verbatim to
/// worker slot `w`. The export blob stays opaque to the anchor —
/// only the TLV header is re-derived (§13.2).
unsafe fn sc_relay_frame(s: &mut AnchorState, w: usize, msg_type: u8, payload_len: usize) {
    let out_chan = s.ctrl_out[w];
    if out_chan < 0 || payload_len + NET_FRAME_HDR > RELAY_BUF_SIZE {
        return;
    }
    let sys_ptr = s.syscalls;
    let src = s.ctrl_buf.as_ptr().add(NET_FRAME_HDR);
    let scratch = s.relay_buf.as_mut_ptr();
    net_write_frame(
        &*sys_ptr, out_chan, msg_type,
        src, payload_len,
        scratch, RELAY_BUF_SIZE,
    );
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
            // net_proto MSG_BOUND: `[conn_id:2 LE][local_port:2 LE]`. The
            // `local_port` echoes our CMD_BIND port (the IP module and the
            // Linux host adapter both carry it now). On a fanned `net_out`
            // we claim ONLY the bound for our own `listen_port`, so a
            // neighbour anchor's listen completing first can't flip us to
            // Listening. A port-less (legacy) frame is accepted as
            // sole-consumer.
            if s.phase == AnchorPhase::WaitBoundNet {
                let ours = payload_len < 4 || {
                    let lo = *buf.add(NET_FRAME_HDR + 2);
                    let hi = *buf.add(NET_FRAME_HDR + 3);
                    ((lo as u16) | ((hi as u16) << 8)) == s.listen_port
                };
                if ours {
                    if payload_len >= 2 {
                        s.server_conn_id = conn_id_at(buf.add(NET_FRAME_HDR));
                    }
                    s.phase = AnchorPhase::Listening;
                    dev_log(&*sys_ptr, 3, b"[echo_anc] bound".as_ptr(), 16);
                }
            }
        }
        NET_MSG_ACCEPTED => {
            // `[conn_id:2 LE][local_port:2 LE]`. Multi-anchor demux: claim
            // only accepts on our `listen_port` (a port-less frame is
            // accepted). An accept on another anchor's port belongs to
            // that anchor — ignore it (do NOT close it).
            if payload_len >= 2 {
                let new_id = conn_id_at(buf.add(NET_FRAME_HDR));
                let ours = payload_len < 4 || {
                    let lo = *buf.add(NET_FRAME_HDR + 2);
                    let hi = *buf.add(NET_FRAME_HDR + 3);
                    ((lo as u16) | ((hi as u16) << 8)) == s.listen_port
                };
                if !ours {
                    // Not for this anchor — leave it for the owning anchor.
                } else if s.client_conn_id == NO_CONN && s.phase == AnchorPhase::Listening {
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
            // [conn_id:1][data:n]. Forward cleartext to the active
            // worker's data_out — or, while the session is still
            // attaching or a handoff is rebinding, into the bounded
            // hold buffer (§11.2), flushed when the worker is live.
            let attach_window = s.phase == AnchorPhase::Attaching
                || s.phase == AnchorPhase::WaitAttached;
            if payload_len >= 3 && (s.phase == AnchorPhase::Active || attach_window) {
                let id = conn_id_at(buf.add(NET_FRAME_HDR));
                if id == s.client_conn_id {
                    let data_len = payload_len - 2;
                    let data = buf.add(NET_FRAME_HDR + 2);
                    if s.phase == AnchorPhase::Active && s.handoff == HandoffPhase::Idle {
                        let out = s.data_out[s.active_w as usize];
                        // Best-effort forward — drop on data_out full.
                        // A real anchor would buffer; this is a demo.
                        if out >= 0 {
                            let wrote = ((*sys_ptr).channel_write)(out, data, data_len);
                            if wrote > 0 {
                                s.forwarded = s.forwarded.wrapping_add(wrote as u64);
                            }
                        }
                        s.bytes_since_handoff =
                            s.bytes_since_handoff.wrapping_add(data_len as u32);
                    } else {
                        // Attach or rebinding window: hold, flush once
                        // the (new) worker is live.
                        let free = HOLD_BUF_SIZE - s.hold_len as usize;
                        let take = if data_len < free { data_len } else { free };
                        if take > 0 {
                            core::ptr::copy_nonoverlapping(
                                data,
                                s.hold_buf.as_mut_ptr().add(s.hold_len as usize),
                                take,
                            );
                            s.hold_len += take as u16;
                        }
                        if take < data_len {
                            dev_log(&*sys_ptr, 2,
                                b"[echo_anc] hold overflow: dropped".as_ptr(), 33);
                        }
                    }
                }
            }
        }
        NET_MSG_CLOSED => {
            // [conn_id:2 LE]. Client gone → detach worker, return to Listening.
            if payload_len >= 2 {
                let id = conn_id_at(buf.add(NET_FRAME_HDR));
                if id == s.client_conn_id {
                    match s.phase {
                        AnchorPhase::Active
                        | AnchorPhase::Attaching
                        | AnchorPhase::WaitAttached => {
                            // Abort any in-flight handoff — the session
                            // is ending, both workers get detached.
                            if s.handoff != HandoffPhase::Idle {
                                let standby = s.standby_w();
                                sc_send_detach(s, standby, SC_DETACH_CLIENT_GONE);
                                s.handoff = HandoffPhase::Idle;
                                s.hold_len = 0;
                            }
                            let aw = s.active_w as usize;
                            sc_send_detach(s, aw, SC_DETACH_CLIENT_GONE);
                            s.phase = AnchorPhase::WaitDetached;
                            mon_emit(s, MON_EV_DETACH_REQ, b"client_gone", b"");
                        }
                        _ => {
                            s.client_conn_id = NO_CONN;
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

/// Flush the rebinding hold buffer to the active worker's data_out
/// (client bytes that arrived while no worker was live: during the
/// initial ATTACH round-trip or a handoff rebinding window).
unsafe fn flush_hold(s: &mut AnchorState) {
    if s.hold_len == 0 {
        return;
    }
    let sys_ptr = s.syscalls;
    let out = s.data_out[s.active_w as usize];
    if out >= 0 {
        let held = s.hold_buf.as_ptr();
        let wrote = ((*sys_ptr).channel_write)(out, held, s.hold_len as usize);
        if wrote > 0 {
            s.forwarded = s.forwarded.wrapping_add(wrote as u64);
        }
        s.bytes_since_handoff = s.bytes_since_handoff.wrapping_add(s.hold_len as u32);
    }
    s.hold_len = 0;
}

/// Refuse a handoff that cannot be made safe, leaving the session on
/// the exporting worker (§Delivery cursors: "refuses the handoff ...
/// and leaves the session on the exporting worker").
///
/// The standby is detached (it discards whatever it half-imported) and
/// the exporting worker is returned to service with CMD_SC_RESUME at
/// the session's CURRENT epoch — no blob was committed anywhere, so
/// nothing advanced. Held ingress stays held until that worker answers
/// MSG_SC_RESUMED; the client sees a pause bounded by the deadline and
/// nothing else. `status` names the cause on the MON_SESSION line.
unsafe fn handoff_refuse(s: &mut AnchorState, status: &[u8]) {
    let sys_ptr = s.syscalls;
    dev_log(&*sys_ptr, 1, b"[echo_anc] handoff refused".as_ptr(), 26);
    let standby = s.standby_w();
    sc_send_detach(s, standby, SC_DETACH_NORMAL);
    mon_emit(s, MON_EV_ERROR, b"", status);
    let aw = s.active_w as usize;
    let epoch = s.session_epoch;
    if sc_send_resume(s, aw, epoch) {
        s.handoff = HandoffPhase::RefuseWait;
        mon_emit(s, MON_EV_RESUME_REQ, b"", b"");
    } else {
        // ctrl_out full: retry from the step loop until it takes.
        s.handoff = HandoffPhase::RefuseWait;
        s.detach_old_pending = false;
        s.refuse_resume_pending = true;
    }
}

/// Drain one SessionCtrlV1 frame from worker slot `w`.
unsafe fn poll_ctrl_in(s: &mut AnchorState, w: usize) {
    let chan = s.ctrl_in[w];
    if chan < 0 { return; }
    let sys_ptr = s.syscalls;
    let poll = ((*sys_ptr).channel_poll)(chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.ctrl_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(&*sys_ptr, chan, buf, CTRL_BUF_SIZE);
    let is_active = w == s.active_w as usize;

    match msg_type {
        SC_MSG_ATTACHED => {
            // [session_id:16][epoch:4][status:1]. Only go Active on status=OK
            // AND session_id matches.
            if payload_len >= STATUS_REPLY_MIN_LEN
                && s.phase == AnchorPhase::WaitAttached
                && is_active
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
                    flush_hold(s);
                    dev_log(&*sys_ptr, 3, b"[echo_anc] active".as_ptr(), 17);
                } else {
                    // Worker refused or session mismatch — drop the client.
                    if s.client_conn_id != NO_CONN {
                        net_send_close(s, s.client_conn_id);
                    }
                    s.phase = AnchorPhase::Detaching;
                }
            }
        }
        SC_MSG_DRAINED => {
            // Outgoing worker stopped consuming; its EXPORT_* frames
            // follow on this same ctrl channel.
            if is_active && s.handoff == HandoffPhase::DrainWait {
                s.handoff = HandoffPhase::ImportWait;
            }
        }
        SC_CMD_EXPORT_BEGIN | SC_CMD_EXPORT_CHUNK | SC_CMD_EXPORT_END => {
            // Relay the opaque export verbatim to the standby worker
            // (§13.2 — the anchor never interprets the blob). The
            // cursors on EXPORT_BEGIN are the one part the anchor does
            // read: they must match what it delivered to and relayed
            // from this worker, or the blob and the client have seen
            // different prefixes of the session and the handoff is not
            // safe to make.
            if is_active
                && (s.handoff == HandoffPhase::DrainWait
                    || s.handoff == HandoffPhase::ImportWait)
            {
                if msg_type == SC_CMD_EXPORT_BEGIN {
                    let off = SESSION_ID_BYTES + EPOCH_BYTES + 4;
                    let cursors = if payload_len >= off + CURSOR_PAIR_LEN {
                        SessionCursors::decode(core::slice::from_raw_parts(
                            buf.add(NET_FRAME_HDR + off),
                            CURSOR_PAIR_LEN,
                        ))
                    } else {
                        None
                    };
                    let admit = match cursors {
                        Some(c) => cursors_admit(&c, s.forwarded, s.relayed),
                        None => HANDOFF_CURSOR_MISMATCH,
                    };
                    if admit != HANDOFF_OK {
                        dev_log(&*sys_ptr, 1,
                            b"[echo_anc] export cursors disagree".as_ptr(), 34);
                        handoff_refuse(s, b"cursor_mismatch");
                        return;
                    }
                }
                let standby = s.standby_w();
                sc_relay_frame(s, standby, msg_type, payload_len);
            }
        }
        SC_MSG_IMPORT_BEGIN => {
            // [sid:16][epoch:4][status:1] from the standby worker.
            if !is_active && s.handoff == HandoffPhase::ImportWait && payload_len > SESSION_ID_BYTES + EPOCH_BYTES {
                let status = *buf.add(NET_FRAME_HDR + SESSION_ID_BYTES + EPOCH_BYTES);
                if status != SC_STATUS_OK {
                    handoff_refuse(s, b"no_capacity");
                }
            }
        }
        SC_MSG_IMPORT_END => {
            // Standby committed (or rejected) the imported state.
            if !is_active && s.handoff == HandoffPhase::ImportWait && payload_len > SESSION_ID_BYTES + EPOCH_BYTES {
                let status = *buf.add(NET_FRAME_HDR + SESSION_ID_BYTES + EPOCH_BYTES);
                if status == SC_STATUS_OK {
                    let new_epoch = s.session_epoch + 1;
                    if sc_send_resume(s, w, new_epoch) {
                        s.handoff = HandoffPhase::ResumeWait;
                        mon_emit(s, MON_EV_RESUME_REQ, b"", b"");
                    } else {
                        handoff_refuse(s, b"not_ready");
                    }
                } else {
                    handoff_refuse(s, b"corrupt");
                }
            }
        }
        SC_MSG_RESUMED => {
            // A refused handoff's RESUMED comes from the ACTIVE worker,
            // at the unchanged epoch: it is back in service, so the held
            // ingress goes to it and the session carries on as if the
            // swap had never been attempted.
            if is_active && s.handoff == HandoffPhase::RefuseWait {
                s.handoff = HandoffPhase::Idle;
                s.bytes_since_handoff = 0;
                flush_hold(s);
                dev_log(&*sys_ptr, 3, b"[echo_anc] handoff refused, session kept".as_ptr(), 39);
                return;
            }
            // Swap recorded: bump the epoch, flip the forwarding
            // target, detach the old worker. The hold buffer is NOT
            // flushed yet — the retiring worker's output channel may
            // still carry replies (client-side CMD_SEND backpressure)
            // that must reach the client before any new-worker output.
            // poll_data_in completes the retire once that channel is
            // observed empty.
            if !is_active && s.handoff == HandoffPhase::ResumeWait {
                let old = s.active_w as usize;
                s.session_epoch += 1;
                s.active_w = w as u8;
                s.handoff = HandoffPhase::RetireDrain;
                s.bytes_since_handoff = 0;
                s.detach_old_pending = true;
                sc_send_detach(s, old, SC_DETACH_NORMAL);
                mon_emit(s, MON_EV_EPOCH_BUMP, b"", b"ok");
                mon_emit(s, MON_EV_RELOCATED, b"", b"ok");
                dev_log(&*sys_ptr, 3, b"[echo_anc] worker swapped".as_ptr(), 25);
            }
        }
        SC_MSG_DETACHED => {
            if !is_active && s.detach_old_pending {
                // Post-swap detach of the OLD worker — the session
                // itself continues on the new active worker.
                s.detach_old_pending = false;
            } else if !is_active && s.handoff == HandoffPhase::RefuseWait {
                // The standby acknowledging a refusal's detach: the
                // session never left the active worker.
            } else if payload_len >= SESSION_ID_BYTES + EPOCH_BYTES {
                // Session-ending detach. Close client if still open
                // and return to Listening; the IP module preserves the
                // listener slot across accepted connections.
                if s.client_conn_id != NO_CONN {
                    net_send_close(s, s.client_conn_id);
                    s.client_conn_id = NO_CONN;
                }
                s.session_id = [0; SESSION_ID_BYTES];
                s.session_epoch = 0;
                s.phase = AnchorPhase::Listening;
                dev_log(&*sys_ptr, 3, b"[echo_anc] listening".as_ptr(), 20);
            }
        }
        SC_MSG_ERROR => {
            dev_log(&*sys_ptr, 1, b"[echo_anc] worker error".as_ptr(), 23);
            if s.handoff != HandoffPhase::Idle && s.handoff != HandoffPhase::RefuseWait {
                handoff_refuse(s, b"error");
            } else if s.handoff == HandoffPhase::RefuseWait {
                // The exporting worker refused to resume: the session is
                // unrecoverable on either side, so this IS the end of it.
                s.handoff = HandoffPhase::Idle;
                s.hold_len = 0;
                if s.client_conn_id != NO_CONN {
                    net_send_close(s, s.client_conn_id);
                }
                s.phase = AnchorPhase::Detaching;
            } else {
                if s.client_conn_id != NO_CONN {
                    net_send_close(s, s.client_conn_id);
                }
                s.phase = AnchorPhase::Detaching;
            }
        }
        _ => { /* ignore unknown opcodes */ }
    }
}

/// Drain SessionCtrlV1 frames from both worker slots.
unsafe fn poll_ctrl_all(s: &mut AnchorState) {
    poll_ctrl_in(s, 0);
    poll_ctrl_in(s, 1);
}

/// Forward worker output (data_in) back to client via CMD_SEND.
///
/// Ordering rule: while a swap is retiring (`RetireDrain`), ONLY the
/// retiring worker's slot is drained; the new worker cannot have
/// produced output yet (nothing has been forwarded to it), and the
/// retiring channel must be seen empty before the hold buffer flushes
/// (see `HandoffPhase::RetireDrain` for the invariant). Outside a
/// retire, both slots are polled (a draining worker still flushes
/// trailing output while the standby imports).
unsafe fn poll_data_in(s: &mut AnchorState) {
    if s.phase != AnchorPhase::Active || s.client_conn_id == NO_CONN {
        return;
    }
    let sys_ptr = s.syscalls;

    if s.handoff == HandoffPhase::RetireDrain {
        // After the swap flip, the retiring worker is the standby slot.
        let retiring = s.standby_w();
        let chan = s.data_in[retiring];
        if chan >= 0 {
            let poll = ((*sys_ptr).channel_poll)(chan, POLL_IN);
            if poll > 0 && ((poll as u32) & POLL_IN) != 0 {
                let buf = s.data_buf.as_mut_ptr();
                let read = ((*sys_ptr).channel_read)(chan, buf, DATA_BUF_SIZE);
                if read > 0 {
                    let client = s.client_conn_id;
                    net_send_data(s, client, buf, read as usize);
                    s.relayed = s.relayed.wrapping_add(read as u64);
                }
                // More may remain — keep retiring next step.
                return;
            }
        }
        // Retiring channel empty (or unwired): the old worker is
        // detached and can produce nothing further. Release the held
        // ingress to the new active worker and go quiescent.
        s.handoff = HandoffPhase::Idle;
        flush_hold(s);
        return;
    }

    let mut w = 0;
    while w < 2 {
        let chan = s.data_in[w];
        if chan >= 0 {
            let poll = ((*sys_ptr).channel_poll)(chan, POLL_IN);
            if poll > 0 && ((poll as u32) & POLL_IN) != 0 {
                let buf = s.data_buf.as_mut_ptr();
                let read = ((*sys_ptr).channel_read)(chan, buf, DATA_BUF_SIZE);
                if read > 0 {
                    let client = s.client_conn_id;
                    net_send_data(s, client, buf, read as usize);
                }
            }
        }
        w += 1;
    }
}

/// Kick a worker swap when the byte-count trigger fires (demo stand-in
/// for a real maintenance signal — a drain request from the control
/// plane, a directory rebind, an operator action).
unsafe fn maybe_start_handoff(s: &mut AnchorState) {
    if s.handoff != HandoffPhase::Idle
        || s.handoff_after_bytes == 0
        || s.bytes_since_handoff < s.handoff_after_bytes
        || s.phase != AnchorPhase::Active
        || !s.has_standby()
        || s.detach_old_pending
    {
        return;
    }
    let aw = s.active_w as usize;
    if sc_send_drain(s, aw) {
        s.handoff = HandoffPhase::DrainWait;
        let sys_ptr = s.syscalls;
        s.handoff_started_ms = dev_millis(&*sys_ptr);
        mon_emit(s, MON_EV_EXPORT_REQ, b"", b"");
        dev_log(&*sys_ptr, 3, b"[echo_anc] handoff: drain sent".as_ptr(), 30);
    }
}

/// Enforce the deadline the DRAIN carried. A swap still short of
/// RESUMED when `DRAIN_DEADLINE_MS` has passed since the DRAIN is
/// refused: the session stays on the exporting worker rather than
/// holding the client's bytes for as long as a slow standby likes.
/// Also retries a refusal's CMD_SC_RESUME that ctrl_out refused.
unsafe fn enforce_handoff_deadline(s: &mut AnchorState) {
    let sys_ptr = s.syscalls;
    if s.handoff == HandoffPhase::RefuseWait && s.refuse_resume_pending {
        let aw = s.active_w as usize;
        let epoch = s.session_epoch;
        if sc_send_resume(s, aw, epoch) {
            s.refuse_resume_pending = false;
            mon_emit(s, MON_EV_RESUME_REQ, b"", b"");
        }
        return;
    }
    let in_flight = matches!(
        s.handoff,
        HandoffPhase::DrainWait | HandoffPhase::ImportWait | HandoffPhase::ResumeWait
    );
    if !in_flight {
        return;
    }
    let now = dev_millis(&*sys_ptr);
    if now.saturating_sub(s.handoff_started_ms) > DRAIN_DEADLINE_MS as u64 {
        dev_log(&*sys_ptr, 1, b"[echo_anc] handoff deadline".as_ptr(), 27);
        handoff_refuse(s, b"drain_timeout");
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<AnchorState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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

        // Ports: in[0]=net_in, in[1]=ctrl_in, in[2]=data_in,
        //        in[3]=ctrl2_in, in[4]=data2_in (optional standby);
        //        out[0]=net_out, out[1]=ctrl_out, out[2]=data_out,
        //        out[3]=ctrl2_out, out[4]=data2_out (optional standby).
        s.net_in = in_chan;
        s.net_out = out_chan;
        let sys_ptr = s.syscalls;
        s.ctrl_in[0] = dev_channel_port(&*sys_ptr, 0, 1);
        s.data_in[0] = dev_channel_port(&*sys_ptr, 0, 2);
        s.ctrl_in[1] = dev_channel_port(&*sys_ptr, 0, 3);
        s.data_in[1] = dev_channel_port(&*sys_ptr, 0, 4);
        s.ctrl_out[0] = dev_channel_port(&*sys_ptr, 1, 1);
        s.data_out[0] = dev_channel_port(&*sys_ptr, 1, 2);
        s.ctrl_out[1] = dev_channel_port(&*sys_ptr, 1, 3);
        s.data_out[1] = dev_channel_port(&*sys_ptr, 1, 4);

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

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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
                let aw = s.active_w as usize;
                if sc_send_attach(s, aw) {
                    s.phase = AnchorPhase::WaitAttached;
                    mon_emit(s, MON_EV_ATTACH_REQ, b"", b"");
                    return 2;
                }
            }
            AnchorPhase::WaitAttached => {
                poll_ctrl_all(s);
                poll_net_in(s); // client may still disconnect during attach
            }
            AnchorPhase::Active => {
                poll_net_in(s);
                poll_ctrl_all(s);
                poll_data_in(s);
                enforce_handoff_deadline(s);
                maybe_start_handoff(s);
            }
            AnchorPhase::Detaching => {
                let aw = s.active_w as usize;
                if sc_send_detach(s, aw, SC_DETACH_NORMAL) {
                    s.phase = AnchorPhase::WaitDetached;
                    mon_emit(s, MON_EV_DETACH_REQ, b"normal", b"");
                    return 2;
                }
            }
            AnchorPhase::WaitDetached => {
                poll_ctrl_all(s);
            }
            AnchorPhase::Error => {
                return 1;
            }
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
