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
//! # Anchor-preserved handoff (export / import / resume)
//!
//! The worker also implements both halves of the SessionCtrlV1 opaque
//! state handoff (`session_handoff` core), so an anchor can swap a
//! session between two worker instances while the client transport
//! stays open:
//!
//!   OUTGOING worker (drain implies handoff-export in this demo —
//!   a real deployment may gate export on directory policy):
//!     anchor → worker : CMD_SC_DRAIN
//!     worker → anchor : MSG_SC_DRAINED, then
//!     worker → anchor : CMD_SC_EXPORT_BEGIN (blob length + the
//!                       session's delivery cursors) / CHUNK… / END (CRC32)
//!     anchor → worker : CMD_SC_DETACH   (after the peer resumed)
//!     worker → anchor : MSG_SC_DETACHED
//!
//!   INCOMING worker (import IS the attach):
//!     anchor → worker : CMD_SC_EXPORT_BEGIN / CHUNK… / END (relayed)
//!     worker → anchor : MSG_SC_IMPORT_BEGIN / MSG_SC_IMPORT_END
//!     anchor → worker : CMD_SC_RESUME (new_epoch)
//!     worker → anchor : MSG_SC_RESUMED
//!
//!   REFUSED handoff (the anchor found the cursors disagreeing, the
//!   import failed, or the drain deadline passed): the session stays
//!   on the outgoing worker, which is returned to service in place —
//!     anchor → worker : CMD_SC_RESUME (the session's CURRENT epoch)
//!     worker → anchor : MSG_SC_RESUMED
//!   A draining worker still holds its state, so nothing is imported;
//!   it simply resumes consuming. The standby that half-imported is
//!   detached and discards the partial blob.
//!
//! The exported blob is opaque to the anchor and the kernel (§13.2):
//! `[magic "EWS1":4][bytes_processed:4 LE][origin worker_id:8][pad:4]`,
//! chunked at 8 bytes so the demo exercises real multi-chunk reassembly.
//!
//! # Wire format
//!
//! See `modules/sdk/contracts/net/session_ctrl.rs`. session_id is 16
//! bytes big-endian; anchor_id / worker_id are 8 bytes big-endian;
//! session_epoch is 4 bytes little-endian.

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

include!("../../sdk/runtime.rs");
include!("../../sdk/cores/session_handoff.rs");

// ============================================================================
// SessionCtrlV1 opcodes (see modules/sdk/contracts/net/session_ctrl.rs)
// ============================================================================

const SC_CMD_HELLO: u8 = 0x70;
const SC_CMD_ATTACH: u8 = 0x71;
const SC_CMD_DETACH: u8 = 0x72;
const SC_CMD_DRAIN: u8 = 0x73;
const SC_CMD_EXPORT_BEGIN: u8 = 0x74;
const SC_CMD_EXPORT_CHUNK: u8 = 0x75;
const SC_CMD_EXPORT_END: u8 = 0x76;
const SC_CMD_RESUME: u8 = 0x77;

const SC_MSG_HELLO_ACK: u8 = 0x90;
const SC_MSG_ATTACHED: u8 = 0x91;
const SC_MSG_DETACHED: u8 = 0x92;
const SC_MSG_DRAINED: u8 = 0x93;
const SC_MSG_IMPORT_BEGIN: u8 = 0x94;
const SC_MSG_IMPORT_END: u8 = 0x96;
const SC_MSG_RESUMED: u8 = 0x97;
const SC_MSG_ERROR: u8 = 0x9F;

const SC_ROLE_WORKER: u8 = 2;

const SC_STATUS_OK: u8 = 0;
const SC_STATUS_STALE_EPOCH: u8 = 1;

/// Opaque state blob: magic + bytes_processed + origin worker_id + pad.
const BLOB_MAGIC: [u8; 4] = *b"EWS1";
const BLOB_LEN: usize = 20;
/// Chunk cap chosen deliberately small so the 20-byte blob crosses
/// three EXPORT_CHUNK frames — the demo exercises real reassembly.
const EXPORT_CHUNK_CAP: u32 = 8;

const SESSION_ID_BYTES: usize = 16;
const ANCHOR_ID_BYTES: usize = 8;
const WORKER_ID_BYTES: usize = 8;
const EPOCH_BYTES: usize = 4;

/// Shortest HELLO we act on: `[role: u8][peer_id: 8 BE]`. The trailing
/// flags byte is optional, so a HELLO one byte shorter than the
/// contract's nominal layout still names its sender.
const HELLO_MIN_LEN: usize = 1 + ANCHOR_ID_BYTES;

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
    /// DRAIN received — finish the in-flight data_in tail, then send
    /// MSG_SC_DRAINED and (in this demo) export the session state.
    /// New anchor-forwarded traffic stops at the anchor's hold buffer,
    /// so the tail is bounded.
    Draining = 3,
    /// EXPORT_BEGIN received — reassembling the peer's state blob.
    Importing = 4,
    /// Import committed (CRC verified) — waiting for CMD_SC_RESUME.
    Imported = 5,
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

    /// Statistics (readable via memory dump). Survives handoff via the
    /// exported blob — the importing worker resumes the count.
    bytes_processed: u32,
    /// Session-scoped delivery cursors (§Delivery cursors): inbound
    /// bytes this worker has consumed, and outbound bytes it has
    /// emitted. They travel on EXPORT_BEGIN so the anchor can confirm
    /// the exported state accounts for exactly what it delivered.
    in_consumed: u64,
    out_produced: u64,

    /// Cached scheduler index from `dev_self_index` for MON_SESSION
    /// emission. `0xFF` until first resolved (we lazy-resolve on the
    /// first transition to avoid spending the syscall when the
    /// monitor path is unused).
    self_idx: u8,
    /// Non-zero once MSG_SC_DRAINED + the export have been emitted for
    /// the current drain (they fire only after data_in runs dry).
    drained_sent: u8,
    _pad1: [u8; 2],

    /// Import reassembly state machine (session_handoff core).
    import: HandoffImport,
    /// Destination buffer the import commits into.
    import_buf: [u8; BLOB_LEN],
    /// Epoch carried by the inbound EXPORT_* frames; RESUME must not
    /// regress below it (stale-epoch rejection).
    import_epoch: u32,

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
        self.in_consumed = 0;
        self.out_produced = 0;
        self.self_idx = 0xFF;
        self.drained_sent = 0;
        self._pad1 = [0; 2];
        self.import = HandoffImport::new();
        self.import_buf = [0; BLOB_LEN];
        self.import_epoch = 0;
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

/// Emit MSG_SC_IMPORT_BEGIN / MSG_SC_IMPORT_END:
/// [session_id:16][epoch:4 LE][status:1].
unsafe fn send_import_event(s: &mut WorkerState, msg_type: u8, status: u8) {
    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 1];
    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES]
        .copy_from_slice(&s.import_epoch.to_le_bytes());
    payload[SESSION_ID_BYTES + EPOCH_BYTES] = status;
    sc_write(s, msg_type, payload.as_ptr(), payload.len());
}

/// Build the opaque state blob:
/// `[magic:4][bytes_processed:4 LE][origin worker_id:8][pad:4]`.
fn build_blob(s: &WorkerState) -> [u8; BLOB_LEN] {
    let mut blob = [0u8; BLOB_LEN];
    blob[..4].copy_from_slice(&BLOB_MAGIC);
    blob[4..8].copy_from_slice(&s.bytes_processed.to_le_bytes());
    blob[8..16].copy_from_slice(&WORKER_ID);
    blob
}

/// Export the session state blob: CMD_SC_EXPORT_BEGIN, then CHUNK
/// frames capped at EXPORT_CHUNK_CAP bytes, then EXPORT_END with the
/// blob CRC32. Frames are small enough to emit inline in one step —
/// a worker with a large blob would walk `HandoffExport` across steps.
unsafe fn export_state(s: &mut WorkerState) {
    let blob = build_blob(s);
    let sid_epoch = |s: &WorkerState, payload: &mut [u8]| {
        payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
        payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES]
            .copy_from_slice(&s.session_epoch.to_le_bytes());
    };

    // EXPORT_BEGIN: [sid:16][epoch:4][total_len:4 LE][cursors:16]
    let mut begin = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 4 + CURSOR_PAIR_LEN];
    sid_epoch(s, &mut begin);
    let len_at = SESSION_ID_BYTES + EPOCH_BYTES;
    begin[len_at..len_at + 4].copy_from_slice(&(BLOB_LEN as u32).to_le_bytes());
    let mut cursors = [0u8; CURSOR_PAIR_LEN];
    SessionCursors::new(s.in_consumed, s.out_produced).encode(&mut cursors);
    begin[len_at + 4..].copy_from_slice(&cursors);
    sc_write(s, SC_CMD_EXPORT_BEGIN, begin.as_ptr(), begin.len());

    // EXPORT_CHUNK: [sid:16][epoch:4][offset:4 LE][data...]
    let mut exp = HandoffExport::new(BLOB_LEN as u32);
    while let Some((off, len)) = exp.next_chunk(EXPORT_CHUNK_CAP) {
        let mut chunk = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 4 + EXPORT_CHUNK_CAP as usize];
        sid_epoch(s, &mut chunk);
        chunk[SESSION_ID_BYTES + EPOCH_BYTES..SESSION_ID_BYTES + EPOCH_BYTES + 4]
            .copy_from_slice(&off.to_le_bytes());
        let base = SESSION_ID_BYTES + EPOCH_BYTES + 4;
        chunk[base..base + len as usize]
            .copy_from_slice(&blob[off as usize..(off + len) as usize]);
        sc_write(s, SC_CMD_EXPORT_CHUNK, chunk.as_ptr(), base + len as usize);
        exp.advance(len);
    }

    // EXPORT_END: [sid:16][epoch:4][crc32:4 LE]
    let mut end = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 4];
    sid_epoch(s, &mut end);
    end[SESSION_ID_BYTES + EPOCH_BYTES..]
        .copy_from_slice(&handoff_crc32(&blob).to_le_bytes());
    sc_write(s, SC_CMD_EXPORT_END, end.as_ptr(), end.len());

    mon_emit(s, MON_EV_EXPORTED, b"", b"");
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
            if payload_len >= HELLO_MIN_LEN {
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
            // Drain: finish the in-flight data_in tail first — bytes
            // forwarded before the anchor entered its rebinding hold
            // must not be dropped. MSG_SC_DRAINED and the export fire
            // from module_step once data_in runs dry. In this demo
            // drain implies handoff-export (// "the worker drains/exports"); a real deployment may gate
            // export on directory policy.
            if s.phase == WorkerPhase::Active {
                s.phase = WorkerPhase::Draining;
                s.drained_sent = 0;
            }
        }
        SC_CMD_DETACH => {
            // Detach: clear state, back to Idle. A standby detached
            // mid-import (the anchor refused the handoff) discards the
            // partial blob the same way — it was never the session's.
            match s.phase {
                WorkerPhase::Active | WorkerPhase::Draining => {
                    send_session_event(s, SC_MSG_DETACHED, false, 0);
                    mon_emit(s, MON_EV_DETACHED, b"normal", b"");
                    s.session_id = [0; SESSION_ID_BYTES];
                    s.anchor_id = [0; ANCHOR_ID_BYTES];
                    s.session_epoch = 0;
                    s.drained_sent = 0;
                    s.phase = WorkerPhase::Idle;
                }
                WorkerPhase::Importing | WorkerPhase::Imported => {
                    send_session_event(s, SC_MSG_DETACHED, false, 0);
                    mon_emit(s, MON_EV_DETACHED, b"normal", b"");
                    s.import.reset();
                    s.session_id = [0; SESSION_ID_BYTES];
                    s.session_epoch = 0;
                    s.import_epoch = 0;
                    s.phase = WorkerPhase::Idle;
                }
                _ => {}
            }
        }
        SC_CMD_EXPORT_BEGIN => {
            // Import IS the attach for the incoming worker: accept a
            // relayed export from Dormant / Idle.
            // Payload: [sid:16][epoch:4 LE][total_len:4 LE].
            let expected = SESSION_ID_BYTES + EPOCH_BYTES + 4 + CURSOR_PAIR_LEN;
            let can_import = s.phase == WorkerPhase::Dormant || s.phase == WorkerPhase::Idle;
            if payload_len >= expected && can_import {
                let p = buf.add(NET_FRAME_HDR);
                let mut i = 0;
                while i < SESSION_ID_BYTES {
                    s.session_id[i] = *p.add(i);
                    i += 1;
                }
                s.import_epoch = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES),
                    *p.add(SESSION_ID_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + 3),
                ]);
                let total = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 3),
                ]);
                // Resume the session's cursors where the exporting
                // worker left them; the anchor has already confirmed
                // they match what it delivered.
                let cur_at = SESSION_ID_BYTES + EPOCH_BYTES + 4;
                if let Some(c) = SessionCursors::decode(core::slice::from_raw_parts(
                    p.add(cur_at),
                    CURSOR_PAIR_LEN,
                )) {
                    s.in_consumed = c.in_consumed;
                    s.out_produced = c.out_produced;
                }
                let status = s.import.begin(total, BLOB_LEN as u32);
                if status == HANDOFF_OK {
                    s.phase = WorkerPhase::Importing;
                }
                send_import_event(s, SC_MSG_IMPORT_BEGIN, status);
            }
        }
        SC_CMD_EXPORT_CHUNK => {
            // Payload: [sid:16][epoch:4 LE][offset:4 LE][data...].
            let hdr = SESSION_ID_BYTES + EPOCH_BYTES + 4;
            if payload_len > hdr && s.phase == WorkerPhase::Importing {
                let p = buf.add(NET_FRAME_HDR);
                let offset = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 3),
                ]);
                let data = core::slice::from_raw_parts(p.add(hdr), payload_len - hdr);
                let mut dest = s.import_buf;
                let status = s.import.chunk(offset, data, &mut dest);
                s.import_buf = dest;
                if status != HANDOFF_OK {
                    // Gap / overrun: abort the import loudly.
                    s.phase = WorkerPhase::Idle;
                    send_import_event(s, SC_MSG_IMPORT_END, status);
                    mon_emit(s, MON_EV_IMPORTED, b"", b"corrupt");
                }
            }
        }
        SC_CMD_EXPORT_END => {
            // Payload: [sid:16][epoch:4 LE][crc32:4 LE].
            let expected = SESSION_ID_BYTES + EPOCH_BYTES + 4;
            if payload_len >= expected && s.phase == WorkerPhase::Importing {
                let p = buf.add(NET_FRAME_HDR);
                let crc = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + EPOCH_BYTES + 3),
                ]);
                let status = s.import.end(crc);
                let magic_ok = s.import_buf[..4] == BLOB_MAGIC;
                if status == HANDOFF_OK && magic_ok {
                    // Commit: resume the exporter's counters. The blob
                    // is opaque to everyone but this module.
                    s.bytes_processed = u32::from_le_bytes([
                        s.import_buf[4],
                        s.import_buf[5],
                        s.import_buf[6],
                        s.import_buf[7],
                    ]);
                    s.session_epoch = s.import_epoch;
                    s.phase = WorkerPhase::Imported;
                    send_import_event(s, SC_MSG_IMPORT_END, HANDOFF_OK);
                    mon_emit(s, MON_EV_IMPORTED, b"", b"ok");
                } else {
                    s.phase = WorkerPhase::Idle;
                    let st = if status == HANDOFF_OK { HANDOFF_CORRUPT } else { status };
                    send_import_event(s, SC_MSG_IMPORT_END, st);
                    mon_emit(s, MON_EV_IMPORTED, b"", b"corrupt");
                }
            }
        }
        SC_CMD_RESUME => {
            // Payload: [sid:16][new_epoch:4 LE]. Two meanings, told
            // apart by the phase the worker is in:
            //
            //   Imported — the normal handoff. The new epoch must
            //   advance past the imported one (stale-epoch rejection,
            //   §10.2).
            //
            //   Draining — the anchor refused or timed out the
            //   handoff and is returning this worker to service. The
            //   epoch must be the session's CURRENT one: nothing was
            //   imported anywhere, so nothing advanced. The state this
            //   worker exported is still its own; it resumes consuming
            //   from where the drain left it.
            let expected = SESSION_ID_BYTES + EPOCH_BYTES;
            if payload_len >= expected && s.phase == WorkerPhase::Draining {
                let p = buf.add(NET_FRAME_HDR);
                let epoch = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES),
                    *p.add(SESSION_ID_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + 3),
                ]);
                if epoch == s.session_epoch {
                    s.phase = WorkerPhase::Active;
                    s.drained_sent = 0;
                    send_session_event(s, SC_MSG_RESUMED, false, 0);
                    mon_emit(s, MON_EV_RESUMED, b"", b"ok");
                } else {
                    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 1];
                    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
                    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES]
                        .copy_from_slice(&epoch.to_le_bytes());
                    payload[SESSION_ID_BYTES + EPOCH_BYTES] = SC_STATUS_STALE_EPOCH;
                    sc_write(s, SC_MSG_ERROR, payload.as_ptr(), payload.len());
                    mon_emit(s, MON_EV_REJECTED, b"stale_epoch", b"");
                }
            } else if payload_len >= expected && s.phase == WorkerPhase::Imported {
                let p = buf.add(NET_FRAME_HDR);
                let new_epoch = u32::from_le_bytes([
                    *p.add(SESSION_ID_BYTES),
                    *p.add(SESSION_ID_BYTES + 1),
                    *p.add(SESSION_ID_BYTES + 2),
                    *p.add(SESSION_ID_BYTES + 3),
                ]);
                if new_epoch > s.import_epoch {
                    s.session_epoch = new_epoch;
                    s.phase = WorkerPhase::Active;
                    // MSG_SC_RESUMED: [sid:16][new_epoch:4 LE].
                    send_session_event(s, SC_MSG_RESUMED, false, 0);
                    mon_emit(s, MON_EV_RESUMED, b"", b"ok");
                } else {
                    let mut payload = [0u8; SESSION_ID_BYTES + EPOCH_BYTES + 1];
                    payload[..SESSION_ID_BYTES].copy_from_slice(&s.session_id);
                    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + EPOCH_BYTES]
                        .copy_from_slice(&new_epoch.to_le_bytes());
                    payload[SESSION_ID_BYTES + EPOCH_BYTES] = SC_STATUS_STALE_EPOCH;
                    sc_write(s, SC_MSG_ERROR, payload.as_ptr(), payload.len());
                    mon_emit(s, MON_EV_REJECTED, b"stale_epoch", b"");
                }
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
    // Pull data while Active, and keep pulling while Draining until
    // the in-flight tail is gone (the anchor holds NEW client bytes in
    // its rebinding buffer, so the tail is bounded). Once data_in runs
    // dry in Draining, declare DRAINED and export the session state.
    if s.phase != WorkerPhase::Active && s.phase != WorkerPhase::Draining {
        return;
    }
    let sys_ptr = s.syscalls;
    let data_in = s.data_in;
    let data_out = s.data_out;

    if s.phase == WorkerPhase::Draining {
        // DRAINED means "no new frames until resume": once declared, the
        // exported blob accounts for everything consumed, and consuming
        // more would advance the inbound cursor past it — the anchor
        // would then refuse the handoff for a disagreement this worker
        // caused. Bytes that arrive now wait for RESUME or DETACH.
        if s.drained_sent != 0 {
            return;
        }
        let pending = ((*sys_ptr).channel_poll)(data_in, POLL_IN);
        if pending <= 0 || ((pending as u32) & POLL_IN) == 0 {
            s.drained_sent = 1;
            send_session_event(s, SC_MSG_DRAINED, false, 0);
            mon_emit(s, MON_EV_DRAINED, b"", b"");
            export_state(s);
            return;
        }
    }

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
    s.in_consumed = s.in_consumed.wrapping_add(n as u64);

    // In-place ASCII upper-case.
    let mut i = 0;
    while i < n {
        let b = *buf.add(i);
        if b.is_ascii_lowercase() {
            *buf.add(i) = b.to_ascii_uppercase();
        }
        i += 1;
    }

    let written = ((*sys_ptr).channel_write)(data_out, buf, n);
    if written > 0 {
        s.bytes_processed = s.bytes_processed.wrapping_add(written as u32);
        s.out_produced = s.out_produced.wrapping_add(written as u64);
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<WorkerState>() as u32
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

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
