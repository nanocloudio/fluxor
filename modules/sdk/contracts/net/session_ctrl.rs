// Contract: session_ctrl — SessionCtrlV1 control-plane sideband.
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Session Control Metadata
// and .context/rfc_protocols.md §7, §8.
//
// SessionCtrlV1 is the control-plane sideband exchanged between
// **transport anchors**, **session workers**, and **session
// directories** to coordinate session attach, detach, drain,
// export/import handoff, resume, epoch advancement, and worker
// relocation. It is the scaffolding that continuity classes above
// `drain_only` (see protocol_surfaces.md §Continuity Classes) rely on.
//
// Status: envelope reserved. No module consumes SessionCtrlV1 today;
// the first consumers are planned to be the Phase 5 anchor/worker
// prototype (Quantum edge, Chronicle watch streams) and the Phase 4
// reconfigure / handoff hooks that preserve the anchor-facing channel
// while the worker relocates. The fields below derive directly from
// the RFC; minor revisions are possible before the first .fmod ships
// against this contract.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto, datagram, and packet so the shared SDK
// helpers (net_read_frame, net_write_frame) work unchanged. Opcode
// ranges are disjoint from the other three contracts:
//
//     net_proto     0x01..0x13   (Stream Surface v1)
//     datagram   0x20..0x43   (Datagram Surface v1)
//     packet     0x50..0x63   (Packet Surface v1)
//     session_ctrl  0x70..0x9F   (this file)
//
// so a single channel pair may carry multiple contracts without
// ambiguity. In practice SessionCtrlV1 flows over its own channels
// between anchor/worker/directory modules — often over remote channels
// when those three roles are on different nodes.
//
// ─── Session identity ────────────────────────────────────────────
//
// The identity model has three distinct identifiers:
//
//   session_id     16 bytes (128-bit opaque)  stable logical session
//   anchor_id       8 bytes ( 64-bit opaque)  stable front-door anchor
//   session_epoch   4 bytes LE                monotonic per session_id
//
// `session_id` is minted by the protocol owner at the continuity
// boundary (anchor at first attach; resumption layer on reconnect).
// It is scoped to a tenant or cluster continuity domain, not globally
// unique across deployments. It does not have to appear on the public
// wire.
//
// `anchor_id` identifies the anchor currently serving the session.
// When the anchor itself moves (rare; usually only for paired-anchor
// HA or QUIC-class migration) the directory binds the new anchor_id.
//
// `session_epoch` advances on every authoritative rebind. Messages
// carrying a stale epoch are rejected by the directory and the
// receiving worker.
//
// All identity bytes travel **big-endian** (wire order) so raw byte
// comparison matches the cluster's canonical identity representation.
// Ports / lengths / status codes remain little-endian for consistency
// with the other net contracts.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

// ─── Identity field sizes ──────────────────────────────────────────

/// Bytes of `session_id` carried on every session-scoped message.
pub const SESSION_ID_BYTES: usize = 16;
/// Bytes of `anchor_id`.
pub const ANCHOR_ID_BYTES: usize = 8;
/// Bytes of `worker_id` (symmetric with `anchor_id`).
pub const WORKER_ID_BYTES: usize = 8;
/// Bytes of `session_epoch` (little-endian u32).
pub const EPOCH_BYTES: usize = 4;

// ─── Roles (HELLO) ─────────────────────────────────────────────────

/// Transport anchor role: owns the client-visible transport attachment.
pub const ROLE_ANCHOR: u8 = 1;
/// Session worker role: owns movable application session state.
pub const ROLE_WORKER: u8 = 2;
/// Session directory role: owns placement metadata.
pub const ROLE_DIRECTORY: u8 = 3;

// ─── Continuity classes (on the wire) ──────────────────────────────

/// Corresponds to `reroutable` in protocol_surfaces.md.
pub const CC_REROUTABLE: u8 = 1;
/// Corresponds to `drain_only`.
pub const CC_DRAIN_ONLY: u8 = 2;
/// Corresponds to `resumable`.
pub const CC_RESUMABLE: u8 = 3;
/// Corresponds to `edge_anchored`.
pub const CC_EDGE_ANCHORED: u8 = 4;
/// Corresponds to `transport_migratable`.
pub const CC_TRANSPORT_MIGRATABLE: u8 = 5;

// ─── Detach reasons ────────────────────────────────────────────────

pub const DETACH_NORMAL: u8 = 0;
pub const DETACH_DRAIN_TIMEOUT: u8 = 1;
pub const DETACH_STALE_EPOCH: u8 = 2;
pub const DETACH_ERROR: u8 = 3;
pub const DETACH_CLIENT_GONE: u8 = 4;

// ─── Status codes (IMPORT_END / ATTACHED / RELOCATED / etc.) ───────

pub const STATUS_OK: u8 = 0;
pub const STATUS_STALE_EPOCH: u8 = 1;
pub const STATUS_UNKNOWN_SESSION: u8 = 2;
pub const STATUS_NO_CAPACITY: u8 = 3;
pub const STATUS_CORRUPT: u8 = 4;
pub const STATUS_NOT_READY: u8 = 5;

// ─── Opcodes: commands (peer → peer) ───────────────────────────────

/// Role discovery handshake. Payload:
///   [role: u8] [self_id: 8 bytes] [flags: u8]
/// Where `self_id` is the sender's `anchor_id` / `worker_id` depending
/// on role. `flags` is reserved (must be 0 on the wire today).
pub const CMD_SC_HELLO: u8 = 0x70;

/// Anchor → directory (or anchor → worker) attach notification.
/// Payload:
///   [session_id: 16 BE]
///   [anchor_id:   8 BE]
///   [epoch:       4 LE]
///   [cc:          1]                  continuity class (CC_*)
///   [worker_id:   8 BE or zero]       suggested worker or all-zero
pub const CMD_SC_ATTACH: u8 = 0x71;

/// Detach notification (session removed).
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [reason:      1]                  DETACH_*
pub const CMD_SC_DETACH: u8 = 0x72;

/// Begin draining outbound delivery for a session. Anchor may still
/// service wire-liveness traffic (keepalive) while drain is active.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [deadline_ms: 4 LE]               max ms before forced timeout
pub const CMD_SC_DRAIN: u8 = 0x73;

/// Begin opaque state export. Starts a multi-chunk transfer of worker-
/// owned session state for handoff.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [total_len:   4 LE]               total bytes to follow
pub const CMD_SC_EXPORT_BEGIN: u8 = 0x74;

/// A single chunk of exported state.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [offset:      4 LE]               byte offset in the blob
///   [data: ...]                        chunk bytes
pub const CMD_SC_EXPORT_CHUNK: u8 = 0x75;

/// End of export. Confirms total_len was delivered.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [crc32:       4 LE]               CRC32 of the concatenated blob
pub const CMD_SC_EXPORT_END: u8 = 0x76;

/// Mark a new worker ready to take over. Paired with the directory
/// advancing the session binding. Anchor flips its forwarding target
/// to the new worker after MSG_SC_RESUMED is received.
/// Payload:
///   [session_id: 16 BE]
///   [new_epoch:   4 LE]
pub const CMD_SC_RESUME: u8 = 0x77;

/// Epoch bump (generation advance). Used to invalidate stale writers.
/// Payload:
///   [session_id: 16 BE]
///   [old_epoch:   4 LE]
///   [new_epoch:   4 LE]
pub const CMD_SC_EPOCH_BUMP: u8 = 0x78;

/// Directory → anchor notification that the session's worker binding
/// has moved. Anchor re-resolves the forwarding channel.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [new_worker:  8 BE]
pub const CMD_SC_RELOCATE: u8 = 0x79;

// ─── Opcodes: events / acknowledgements (peer → peer) ──────────────

/// Acknowledge CMD_SC_HELLO.
/// Payload:
///   [role: u8] [peer_id: 8 BE]
pub const MSG_SC_HELLO_ACK: u8 = 0x90;

/// Acknowledge CMD_SC_ATTACH.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [status:      1]                  STATUS_*
pub const MSG_SC_ATTACHED: u8 = 0x91;

/// Acknowledge CMD_SC_DETACH.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
pub const MSG_SC_DETACHED: u8 = 0x92;

/// Drain completed (outbound queue empty, no new frames until resume).
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
pub const MSG_SC_DRAINED: u8 = 0x93;

/// Acknowledge CMD_SC_EXPORT_BEGIN; importer is ready to receive.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [status:      1]                  STATUS_*
pub const MSG_SC_IMPORT_BEGIN: u8 = 0x94;

/// Per-chunk acknowledgement (optional; implementations may batch).
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [offset:      4 LE]
pub const MSG_SC_IMPORT_CHUNK: u8 = 0x95;

/// Import completed; state committed on the receiving worker.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [status:      1]                  STATUS_* (CORRUPT if CRC mismatched)
pub const MSG_SC_IMPORT_END: u8 = 0x96;

/// Worker has declared ready for the new epoch. Anchor may now flip
/// its forwarding target.
/// Payload:
///   [session_id: 16 BE]
///   [new_epoch:   4 LE]
pub const MSG_SC_RESUMED: u8 = 0x97;

/// Directory confirms epoch advance.
/// Payload:
///   [session_id: 16 BE]
///   [new_epoch:   4 LE]
pub const MSG_SC_EPOCH_CONFIRMED: u8 = 0x98;

/// Acknowledge CMD_SC_RELOCATE.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [status:      1]                  STATUS_*
pub const MSG_SC_RELOCATED: u8 = 0x99;

/// Generic session-scoped error. Mirror of MSG_DG_ERROR for the
/// control-plane surface.
/// Payload:
///   [session_id: 16 BE]
///   [epoch:       4 LE]
///   [errno:       i8]
pub const MSG_SC_ERROR: u8 = 0x9F;

// ─── Payload layout helpers ────────────────────────────────────────

/// Byte offset of the epoch field after the session_id prefix on any
/// session-scoped message:
///   `[session_id:16] [epoch:4] ...`
pub const SESSION_HEADER: usize = SESSION_ID_BYTES + EPOCH_BYTES;

/// Fixed-size ATTACH payload length: session_id + anchor_id + epoch +
/// cc + suggested worker_id.
pub const ATTACH_PAYLOAD_LEN: usize =
    SESSION_ID_BYTES + ANCHOR_ID_BYTES + EPOCH_BYTES + 1 + WORKER_ID_BYTES;

/// Fixed-size DETACH payload length: session_id + epoch + reason.
pub const DETACH_PAYLOAD_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES + 1;

/// Fixed-size DRAIN payload length: session_id + epoch + deadline_ms.
pub const DRAIN_PAYLOAD_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES + 4;

/// Fixed-size RESUME / RESUMED payload length: session_id + new_epoch.
pub const RESUME_PAYLOAD_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES;

/// Fixed-size EPOCH_BUMP payload length: session_id + old_epoch + new_epoch.
pub const EPOCH_BUMP_PAYLOAD_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES + EPOCH_BYTES;

/// Fixed-size RELOCATE payload length: session_id + epoch + new_worker_id.
pub const RELOCATE_PAYLOAD_LEN: usize = SESSION_ID_BYTES + EPOCH_BYTES + WORKER_ID_BYTES;
