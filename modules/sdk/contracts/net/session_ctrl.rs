// Contract: session_ctrl — SessionCtrlV1 control-plane sideband.
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Session Control Metadata.
//
// SessionCtrlV1 is the control-plane sideband exchanged between
// **transport anchors**, **session workers**, and **session
// directories** to coordinate session attach, detach, drain,
// export/import handoff, resume, epoch advancement, worker
// relocation, and — for the transport providers — checkpoint, delta
// and cut-over of the transport itself (§Transport continuity). It is the scaffolding that continuity classes above
// `drain_only` (see protocol_surfaces.md §Continuity Classes) rely on.
//
// Status: LIVE. Consumers: `echo_anchor` + `echo_worker` exercise the
// full surface — HELLO/ATTACH/DETACH/DRAIN plus the handoff half
// (EXPORT_BEGIN/CHUNK/END → IMPORT_BEGIN/END → RESUME/RESUMED with
// epoch bump). Wiring the anchor with an active + standby worker pair
// gives an anchor-preserved worker swap on a live TCP session.
// The chunking/CRC logic is the
// reusable `session_handoff` core in `modules/sdk/cores/`.
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
//
// ─── Delivery cursors ─────────────────────────────────────────────
//
// A worker's exported state is opaque, but its *position* is not. Two
// counters place the blob in the session's byte streams, both counted
// from the session's first byte and carried on EXPORT_BEGIN:
//
//   in_consumed    inbound bytes the anchor forwarded that the blob
//                  accounts for
//   out_produced   outbound bytes the blob has already emitted toward
//                  the client
//
// The anchor keeps the same two counters for the worker it is feeding:
// what it has forwarded, and what it has relayed onto the client
// transport. At export both pairs must be equal. Equality is what makes
// a handoff lossless — it says the blob accounts for every byte the
// anchor delivered and claims no byte it did not, and it gives the
// importing worker the exact offsets to resume from.
//
// Inequality is a real fault, not a race to retry:
//
//   in_consumed < forwarded    the worker exported before its inbound
//                              tail ran dry; those bytes are in no blob
//   in_consumed > forwarded    the worker is accounting for a stream it
//                              was not fed — a misbound session
//   out_produced != relayed    the drain did not finish; the client has
//                              seen a different prefix than the blob
//                              believes
//
// So an anchor validates the cursors on the EXPORT_BEGIN it relays and,
// on any mismatch, refuses the handoff with STATUS_CURSOR_MISMATCH and
// leaves the session on the exporting worker. Refusing costs a
// maintenance window; proceeding costs the client bytes it will never
// learn were dropped, or a request served twice. The sequencing that
// keeps the cursors equal — the anchor holding new client bytes from
// the moment it issues DRAIN, and the worker consuming its inbound tail
// to dry before it declares DRAINED — is the anchor's and worker's
// side of the same obligation.

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
/// Bytes of a delivery cursor (little-endian u64).
pub const CURSOR_BYTES: usize = 8;

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
/// The provider cannot offer what was asked on this composition — a
/// profile it cannot make safe here, as opposed to one it cannot make
/// safe yet. Retrying does not change the answer.
pub const STATUS_UNSUPPORTED: u8 = 6;
/// The exported state does not account for exactly what the anchor
/// delivered: the cursors on EXPORT_BEGIN disagree with the anchor's
/// own counters (see §Delivery cursors). The handoff is refused and the
/// session stays on the exporting worker.
pub const STATUS_CURSOR_MISMATCH: u8 = 7;

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
/// owned session state for handoff, and states where in the session's
/// two byte streams that state sits (§Delivery cursors).
/// Payload:
///   [session_id:   16 BE]
///   [epoch:         4 LE]
///   [total_len:     4 LE]             total blob bytes to follow
///   [in_consumed:   8 LE]             inbound bytes folded into the blob
///   [out_produced:  8 LE]             outbound bytes the blob has emitted
pub const CMD_SC_EXPORT_BEGIN: u8 = 0x74;

/// Payload bytes of CMD_SC_EXPORT_BEGIN.
pub const EXPORT_BEGIN_LEN: usize =
    SESSION_ID_BYTES + EPOCH_BYTES + 4 + CURSOR_BYTES + CURSOR_BYTES;

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

// ─── Transport continuity (TRANSPORT_CONTINUITY) ──────────────────
//
// The checkpoint, delta and cut-over surface a transport provider
// (ip for TCP, tls for the record layer, quic for the mux) answers on
// its `cont_in` / `cont_out` port pair. A mirror and a failover
// coordinator drive it; the provider owns the codec, the
// buffers, the vault bridge and the emission gate. Key bytes never
// cross this surface: a checkpoint carries vault-sealed continuity
// objects, and only a vault that holds the same labelled sealing key
// (`security.key_wrap`) opens them.
//
// Every message names the flow (16-byte opaque `flow_id`, the
// provider's identity for one connection) and the ownership epoch it
// was issued under. A command carrying an epoch below the provider's
// current one is refused `STATUS_STALE_EPOCH`; a future epoch is
// refused too — epochs advance only through ACTIVATE.
//
// Records and deltas bind: flow, epoch, checkpoint generation, ordered
// delta number, previous digest, length and a content digest (CRC32 on
// the chunk stream, SHA-256 over the whole record in the manifest). A
// retry of an identical record is idempotent; a gap, a conflicting
// duplicate, an oversized record or an unsupported layout is refused
// before anything is mutated. Import stages into a non-emitting shadow
// and becomes eligible atomically at CUT_IMPORT; EMISSION_ARM proves
// the shadow is ready and leaves transmission disabled; ACTIVATE
// requires a strictly higher epoch and a fence generation.
//
// Lifecycle (planned migration):
//
//   PAIR_PREPARE(standby)      → CONTINUITY{PAIR_PREPARED}
//   QUIESCE_BEGIN(primary)     → CONTINUITY{QUIESCED} when drained
//   CUT_EXPORT(primary)        → primary emits CHECKPOINT_BEGIN /
//                                CHECKPOINT_NEXT* / CHECKPOINT_COMMIT
//                                on cont_out, then CONTINUITY{CUT}
//   (coordinator relays the checkpoint frames to the standby's cont_in;
//    the standby answers CONTINUITY{CHECKPOINT_ACK|CHECKPOINT_COMMITTED})
//   CUT_IMPORT(standby)        → CONTINUITY{IMPORTED}: the shadow is
//                                validated and published, still silent
//   EMISSION_ARM(standby)      → CONTINUITY{ARMED}
//   fence the primary (net::identity ADDR_FENCE, or RETIRE)
//   ACTIVATE(standby, epoch+1, fence_gen) → CONTINUITY{ACTIVATED}
//   RETIRE(primary)            → CONTINUITY{RETIRED}: keys and buffers
//                                destroyed
//
// Mirroring (between checkpoint and cut): the primary emits DELTA_APPLY
// on cont_out for every externally visible transition; the standby
// applies it into the shadow and answers DELTA_ACK. In the strict
// (crash-continuous) profile the primary withholds the transition —
// the TCP ACK advance, the TLS record hand-off, the QUIC packet — until
// the DELTA_ACK covering it has returned; that is the receive / send
// horizon. In the planned profile deltas are asynchronous and the
// synchronous cut at CUT_EXPORT is what makes the standby exact.

/// Transport codes carried by PAIR_PREPARE and the checkpoint manifest.
pub const CT_TCP: u8 = 1;
pub const CT_TLS: u8 = 2;
pub const CT_QUIC: u8 = 3;

/// Continuity profile carried by PAIR_PREPARE.
/// Deltas are asynchronous; the cut at CUT_EXPORT is exact.
pub const PROFILE_PLANNED: u8 = 1;
/// Every externally visible transition waits for its DELTA_ACK.
pub const PROFILE_CRASH_CONTINUOUS: u8 = 2;

/// Delta kinds (`DELTA_APPLY` `kind`).
/// TCP: a send-side transition — bytes allocated to sequence space,
/// with the segment bytes so retransmission is byte-identical.
pub const DELTA_TCP_SEND: u8 = 1;
/// TCP: a receive-side transition — bytes accepted in order, and the
/// acknowledgement the peer is about to be shown.
pub const DELTA_TCP_RECV: u8 = 2;
/// TCP: acknowledgement from the peer reclaimed send bytes / window.
pub const DELTA_TCP_ACKED: u8 = 3;
/// TCP: timer or congestion-state change without bytes.
pub const DELTA_TCP_TIMERS: u8 = 4;
/// TLS: a record is about to be handed to the transport — its
/// ciphertext, write epoch and sequence, so the standby retransmits the
/// same bytes and never re-encrypts under the same counter.
pub const DELTA_TLS_RECORD_OUT: u8 = 5;
/// TLS: inbound record consumed — read sequence advanced, partial
/// record bytes retained.
pub const DELTA_TLS_RECORD_IN: u8 = 6;
/// TLS: key update barrier — new secret installed (sealed) and the
/// counters reset; the primary does not emit in the new epoch until
/// this is acknowledged.
pub const DELTA_TLS_KEY_UPDATE: u8 = 7;
/// QUIC: packet-number allocation from the reservation and the
/// packet's ciphertext.
pub const DELTA_QUIC_SEND: u8 = 8;
/// QUIC: inbound packet consumed — ACK state, stream offsets, flow
/// control credit.
pub const DELTA_QUIC_RECV: u8 = 9;
/// QUIC: key-phase flip (RFC 9001 §6) — barrier like the TLS one.
pub const DELTA_QUIC_KEY_PHASE: u8 = 10;
/// TLS: the peer acknowledged the primary's TCP stream up to a sequence,
/// so the retransmit window slid. Mirrored so the standby's window is the
/// primary's and a replay after takeover sends the right bytes.
///   [acked_seq: 4 LE]
pub const DELTA_TLS_RETX_ACK: u8 = 11;
/// TLS, strict profile: inbound bytes received but not yet forming a whole
/// record. Mirrored on arrival so a takeover between two records does not
/// lose the head of the next one.
///   [recv_len: 4 LE][bytes: recv_len]
pub const DELTA_TLS_RECV_BYTES: u8 = 12;

/// Abort reasons (`ABORT` `reason`, `CONTINUITY{ABORTED}` body).
pub const ABORT_COORDINATOR: u8 = 1;
pub const ABORT_IMPORT_FAILED: u8 = 2;
pub const ABORT_MIRROR_LOST: u8 = 3;
pub const ABORT_UNSUPPORTED_STATE: u8 = 4;

/// Prepare a standby slot for `flow_id` — reserves the shadow and its
/// buffers before the connection is promised migration. Refused
/// `STATUS_NO_CAPACITY` when no shadow slot is free.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [transport:     1]                 CT_*
///   [profile:       1]                 PROFILE_*
///   [codec_digest: 32]                 SHA-256 of the codec layout the
///                                      primary will emit; mismatch is
///                                      refused before any bytes move
pub const CMD_SC_PAIR_PREPARE: u8 = 0x7A;

/// Open a checkpoint transfer into a prepared shadow. A generation the
/// shadow already holds is idempotent; a lower generation is refused.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]              checkpoint generation
///   [total_len:     4 LE]              record bytes to follow
///   [record_digest:32]                 SHA-256 of the whole record
pub const CMD_SC_CHECKPOINT_BEGIN: u8 = 0x7B;

/// One chunk of the checkpoint record, in offset order.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]
///   [offset:        4 LE]
///   [data: ...]
pub const CMD_SC_CHECKPOINT_NEXT: u8 = 0x7C;

/// Close the checkpoint transfer. The shadow verifies length, CRC32 and
/// the record digest, decodes the record, opens the sealed continuity
/// objects and answers `CHECKPOINT_COMMITTED` — or `STATUS_CORRUPT`, in
/// which case the shadow is discarded whole.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]
///   [crc32:         4 LE]
pub const CMD_SC_CHECKPOINT_COMMIT: u8 = 0x7D;

/// Ordered delta against a committed checkpoint.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]
///   [delta_no:      4 LE]              1-based, strictly consecutive
///   [prev_digest:  32]                 SHA-256 of the previous delta
///                                      (zero for delta 1)
///   [kind:          1]                 DELTA_*
///   [data: ...]
pub const CMD_SC_DELTA_APPLY: u8 = 0x7E;

/// The standby has applied `delta_no` into the shadow — the horizon
/// the primary may now cross.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]
///   [delta_no:      4 LE]
pub const CMD_SC_DELTA_ACK: u8 = 0x7F;

/// Stop admitting new application delivery on the primary and drain
/// in-flight work so a byte-exact cut can be taken.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [deadline_ms:   4 LE]
pub const CMD_SC_QUIESCE_BEGIN: u8 = 0x80;

/// Ask whether the quiesce has completed.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
pub const CMD_SC_QUIESCE_STATUS: u8 = 0x81;

/// Produce the full checkpoint now. The provider emits
/// CHECKPOINT_BEGIN / NEXT* / COMMIT on `cont_out`, then
/// `CONTINUITY{CUT}` carrying the manifest.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
pub const CMD_SC_CUT_EXPORT: u8 = 0x82;

/// Publish the committed shadow as the eligible import for `flow_id`:
/// the manifest digest must match what CHECKPOINT_COMMIT verified.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [ckpt_gen:      4 LE]
///   [manifest_digest: 32]
pub const CMD_SC_CUT_IMPORT: u8 = 0x83;

/// Prove the import is ready to emit — timers converted, secrets
/// open, route identity present — without enabling transmission.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
pub const CMD_SC_EMISSION_ARM: u8 = 0x84;

/// Make the armed shadow the live connection under a strictly higher
/// epoch. `fence_gen` is the fence generation the coordinator observed
/// confirmed for the old emitter; zero is refused.
/// Payload:
///   [flow_id:      16 BE]
///   [new_epoch:     4 LE]
///   [fence_gen:     4 LE]
///   [conn_id:       2 LE]              optional: the live connection id
///                                      a layered provider (tls over the
///                                      standby's ip) binds the imported
///                                      session to — the id the lower
///                                      provider reported in its own
///                                      CR_ACTIVATED. Absent, the id the
///                                      checkpoint was taken under.
pub const CMD_SC_ACTIVATE: u8 = 0x85;

/// Destroy the old connection's keys and replicated buffers after the
/// new anchor's stability horizon.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
pub const CMD_SC_RETIRE: u8 = 0x86;

/// Discard a shadow or an in-progress export.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [reason:        1]                 ABORT_*
pub const CMD_SC_ABORT: u8 = 0x87;

/// A reservation grant from a `session.reservation` provider for a flow's
/// egress counter: a block of counter values the transport may emit from.
///
/// The grant is what makes a takeover safe. A transport emits only values
/// from a block it holds, and a takeover resumes past the end of every
/// block the dead host was ever granted — so no counter value is ever put
/// on the wire twice under one key. Making a grant durable across hosts is
/// the provider's job; the record below is all the transport needs to see.
///
/// Payload:
///   [flow_id:      16 BE]
///   [grant:        38]                 the record below
///
/// Grant record:
///   [op:            1]                 GRANT_OP_RESERVE
///   [status:        1]                 GRANT_STATUS_OK, or a refusal
///   [session_id:   16]                 the provider's name for the flow
///   [epoch:         4 LE]              fencing epoch; only ever advances
///   [start:         8 LE]              first counter value in the block
///   [len:           8 LE]              values in the block
pub const CMD_SC_RESERVATION_GRANT: u8 = 0x88;

/// Bytes in a reservation-grant record.
pub const GRANT_LEN: usize = 1 + 1 + 16 + 4 + 8 + 8;
/// Grant opcode: a block of counter values reserved for one flow.
pub const GRANT_OP_RESERVE: u8 = 3;
/// Grant status: the block that follows is the caller's to emit from.
pub const GRANT_STATUS_OK: u8 = 0;

/// Every continuity reply. The reply space has five opcodes left, so
/// one carries a discriminated record.
/// Payload:
///   [flow_id:      16 BE]
///   [epoch:         4 LE]
///   [record:        1]                 CR_*
///   [status:        1]                 STATUS_*
///   [body: ...]                        per record type, below
pub const MSG_SC_CONTINUITY: u8 = 0x9A;

/// `CONTINUITY` record types and their bodies.
/// Body: [transport:1][profile:1][shadow_slot:2 LE]
pub const CR_PAIR_PREPARED: u8 = 1;
/// Body: [ckpt_gen:4 LE][offset:4 LE] — bytes accepted so far.
pub const CR_CHECKPOINT_ACK: u8 = 2;
/// Body: [ckpt_gen:4 LE][record_digest:32]
pub const CR_CHECKPOINT_COMMITTED: u8 = 3;
/// Body: [ckpt_gen:4 LE][delta_no:4 LE] — the shadow's horizon.
pub const CR_DELTA_APPLIED: u8 = 4;
/// Body: [drained:1][pending_out:4 LE][pending_in:4 LE]
pub const CR_QUIESCED: u8 = 5;
/// Body — the cut manifest:
///   [ckpt_gen:4 LE][record_len:4 LE][record_digest:32]
///   [transport:1][sealed_len:2 LE][sealed: ...]
/// where `sealed` is the vault-sealed continuity object (the traffic
/// secrets) the record refers to, never the secrets themselves.
pub const CR_CUT: u8 = 6;
/// Body: [ckpt_gen:4 LE][delta_no:4 LE] — the generation published.
pub const CR_IMPORTED: u8 = 7;
/// Body: [expired_timers:1]
pub const CR_ARMED: u8 = 8;
/// Body: [new_epoch:4 LE][conn_id:2 LE] — the live connection id.
pub const CR_ACTIVATED: u8 = 9;
/// Body: empty.
pub const CR_RETIRED: u8 = 10;
/// Body: [reason:1]
pub const CR_ABORTED: u8 = 11;

/// Fixed-size continuity payload lengths.
pub const FLOW_ID_BYTES: usize = 16;
pub const PAIR_PREPARE_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 1 + 1 + 32;
pub const CHECKPOINT_BEGIN_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 4 + 32;
pub const CHECKPOINT_NEXT_HEADER_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 4;
pub const CHECKPOINT_COMMIT_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 4;
pub const DELTA_APPLY_HEADER_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 4 + 32 + 1;
pub const DELTA_ACK_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 4;
pub const QUIESCE_BEGIN_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4;
pub const FLOW_HEADER_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES;
pub const CUT_IMPORT_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4 + 32;
pub const ACTIVATE_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 4;
pub const ABORT_PAYLOAD_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 1;
pub const CONTINUITY_HEADER_LEN: usize = FLOW_ID_BYTES + EPOCH_BYTES + 1 + 1;
/// Largest checkpoint chunk a provider emits on `cont_out`.
pub const CHECKPOINT_CHUNK_MAX: usize = 1024;

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
