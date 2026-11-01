// Transport continuity for the TLS record layer: the CT_TLS checkpoint
// codec, the shadow import lifecycle and the mirrored emission horizon on
// the `cont_in` / `cont_out` port pair. The wire contract is
// `contracts/net/session_ctrl.rs` §Transport continuity.
//
// ── What the strict horizon covers ──────────────────────────────────
//
// A TLS 1.3 record is sealed under a counter neither peer puts on the
// wire, so a takeover cannot skip forward the way an on-wire-sequence
// transport can: it has to resume on the counter the peer is actually at.
// That is what the horizon is for. Under PROFILE_CRASH_CONTINUOUS an
// outbound record is held rather than written, and an inbound record is
// held rather than decrypted and delivered, until the standby has
// acknowledged that exact transition; a write-side key update is a
// barrier on the same footing. What the peer has seen is therefore never
// ahead of what the standby holds.
//
// A standby that stops answering does not hold the connection silent for
// ever. Past `CONT_HORIZON_MS` the pair is abandoned — but what the
// horizon was holding is ordered behind the abort that tells the
// coordinator so, because a coordinator that has not been told may still
// activate the shadow, and those records are exactly what it would be
// missing. Only when the abort is away, or its own budget has run out
// too, do they go to the peer.
//
// ── Canonical record (CT_TLS) ───────────────────────────────────────
//
// A logical record, not a memory image. Scalars are little-endian; one
// cursor walks it front to back with no padding:
//
//   [layout:1]            TLS_CKPT_LAYOUT — anything else is refused
//   [protocol_version:2]  0x0304
//   [cipher_suite:2]      IANA id of the negotiated suite
//   [role:1]              1 = server, 0 = client
//   [conn_id:2]           the primary's net_proto connection id
//   [alpn_len:1][alpn:16] negotiated ALPN, zero-padded
//   [sni_len:1][sni:64]   the identity a client session expects of its
//                         peer: a DNS name, or an address (4 or 16 bytes)
//                         when the length byte's high bit is set
//   [peer_verified:1]     1 when the peer presented a credential that
//                         the session's profile accepted
//   [peer_profile:1]      the peer-authentication profile in force; a
//                         standby enforcing another refuses the record
//   [peer:19]             the transport peer as `ip`'s MSG_PEER reported it,
//                         `[family][addr:16][port:2]`, all zero when none was
//   [requester_tag:2]     a client session's requester tag (0 when accepted)
//   [id_result:1][id_credential:1][id_flags:4]
//   [id_not_before:8][id_not_after:8]
//   [id_fp_len:1][id_fp:32][id_principal_len:1][id_principal:128]
//                         what the handshake established about the peer, as
//                         its `peer_identity` record carries it; zero-padded,
//                         held to the shapes a handshake produces. An
//                         activated session emits that record, its held
//                         accept or connect (on the requester tag), then
//                         MSG_PEER, as one this module opened would
//   [exporter_ctx:48]     transcript hash at the server Finished — the
//                         exporter context input (RFC 8446 §7.5)
//   [read_epoch:4][write_epoch:4]     traffic epochs (key updates seen)
//   [sealed_read_epoch:4][sealed_write_epoch:4]
//                         the epochs the sealed set below is at; the
//                         record may be up to CONT_DERIVE_MAX key updates
//                         past them in each direction
//   [read_seq:8][write_seq:8]         next AEAD record sequence numbers
//   [key_update:1]        bit 0: an update we requested is outstanding;
//                         bit 1: the peer requested one and our answer is
//                         owed (a standby activated from such a record
//                         sends it before anything else)
//   [close_notify:1]      bit 0: our own close_notify is sealed (a
//                         `Closing` session); bit 1: the peer's
//                         close_notify arrived; bit 2: the transport
//                         reported the peer done (FIN) — bits 1 and 2 are a
//                         half-closed session (`half_close`), still ours to
//                         write on; bit 3: our transport close has gone to
//                         `ip` (only with bit 0)
//   [pending_alert:1]     0 none (alerts are emitted, never queued)
//   [ticket:1]            0 none (no resumption state is retained)
//   [delivered_in:8]      records whose plaintext reached clear_out
//   [emitted_out:8]       records whose ciphertext reached cipher_out
//   [out_bytes:8]         the consumer's clear bytes through the last
//                         record emitted (`net_proto::MSG_HORIZON`)
//   [consumer_cursor:8]   the cursor the consumer's last `CMD_DELIVERED`
//                         carried (0 for none), opaque here: a standby's
//                         consumer is handed it at activation
//                         (`net_proto::MSG_RESUMED`)
//   [cursor_at:8]         the clear byte that acknowledgement carried
//                         (`in_bytes`): the consumer had consumed the
//                         stream's first `cursor_at` bytes (0 for none)
//   [in_bytes:8]          the clear bytes of the `delivered_in` records,
//                         where the first unconsumed delivery below starts;
//                         a standby redelivers from byte
//                         max(cursor_at, in_bytes), the first delivery
//                         trimmed by the difference
//   [recv_expected:4][recv_len:4]         partial inbound record bytes
//   [retx_base_seq:4][retx_anchored:1][retx_len:2]
//                         retained outbound ciphertext (byte-identical
//                         retransmission unit) and its TCP anchor
//   [sealed_len:2]        TLS_SEALED_LEN
//   [deliv_count:1][deliv_len:4]
//                         records already opened and handed to the worker
//                         that it has not consumed: a standby
//                         hands them to its own worker again, in order,
//                         before anything else; `delivered_in` counts what
//                         was consumed. A primary's own export carries none
//                         (it keeps no plaintext it handed up); a record
//                         composed from a mirror of the whole connection
//                         (TRANSPORT_CONTINUITY over this module) does, and
//                         a strict shadow here holds them the same way.
//   [recv: recv_len]      recv_buf[..recv_len]
//   [retx: retx_len]      retx_buf[..retx_len]
//   [deliv: deliv_len]    deliv_count × [len:2][plaintext]
//   [sealed: sealed_len]  the SECRET SET, vault-sealed (below)
//
// The secret set never appears in the clear. It is
//   [hash_len:1][client_app_secret:48][server_app_secret:48]
//   [read_key_len:1][read_key:32][read_iv:12]
//   [write_key_len:1][write_key:32][write_iv:12]
//   [read_seq_floor:8][write_seq_floor:8]
// sealed by the kernel vault under the flow's sealing key — an AEAD key
// derived in the vault from the continuity master (`tls-continuity-master`)
// for that flow and ownership epoch — with AAD = flow_id ‖ epoch ‖ CT_TLS ‖
// the two sealed epochs, so a sealed object binds to one flow, one
// ownership epoch and one pair of key epochs, and only a vault holding that
// flow's key opens it: one that derives it from the same master, or one the
// key reached by custody transfer (`CMD_SC_CUSTODY`: the standby's vault
// attests a fresh recipient, the primary's checks the evidence and wraps
// the key to it, the standby's unwraps it; the key is never in a frame).
// The record sequences at the seal are floors inside it: a record whose
// counters were rewound below them does not import, while one whose
// counters a strict mirror's deltas have since moved forward does — the
// same keys, nonces never reused. A record whose epochs are past the sealed
// ones (a crash-continuous mirror's KeyUpdates) derives the secrets forward
// from the sealed set at import, exactly as the primary derived them; no
// newer secret is ever sealed for it. The record carries the sealed set and
// the `CONTINUITY{CUT}` manifest repeats it as the record's continuity
// object.
//
// Admission: an established TLS 1.3 session (`SessionState::Ready`) is
// exportable, and so is one its own consumer closed with continuity wired
// (`Closing`, its close_notify sealed and its retransmit window kept). A
// session mid-handshake, closed by the peer, failed, or with a transition
// still held or stalled is refused `ABORT_UNSUPPORTED_STATE` — a checkpoint
// of a transcript in flight is a hole, not a smaller record. No session
// holds early data (there is no PSK, so no 0-RTT) or a post-handshake
// authentication (a CertificateRequest after the handshake fails the
// session), so neither has a place in the record.
//
// ── Identity ────────────────────────────────────────────────────────
//
// `flow_id` is the coordinator's 16-byte key for one connection. A live
// session adopts the flow id and epoch of the first continuity command
// that names it; until then a flow id whose bytes 2..16 are zero
// resolves by the connection id in bytes 0..2. An imported session keeps
// the flow id it was checkpointed under, so the same key follows the
// connection across every takeover.
//
// ── Roles ───────────────────────────────────────────────────────────
//
// Primary (exporter): PAIR_PREPARE records the profile on the live
// session; QUIESCE_BEGIN stops taking clear-side data; CUT_EXPORT emits
// the record as CHECKPOINT_BEGIN / NEXT* / COMMIT then CONTINUITY{CUT};
// the relayed CONTINUITY{CHECKPOINT_COMMITTED} turns mirroring on, and
// from then every externally visible record transition goes out as a
// DELTA_APPLY. In PROFILE_CRASH_CONTINUOUS the transition waits for its
// DELTA_ACK: an outbound record is held (`tx_hold`) and not written to
// cipher_out until acknowledged; an inbound record is decrypted, its
// RECORD_IN carries its content type and — up to `DELIV_CARRY_MAX` bytes —
// its plaintext, and the plaintext is held (in `record_scratch`, as for a
// full clear_out) and not delivered until the RECORD_IN is acknowledged;
// a write-side key update is a barrier — nothing is emitted in the new
// epoch until the KEY_UPDATE delta is acknowledged, and the retired
// keys are destroyed only then. While any hold is outstanding neither
// cipher_in nor clear_in is drained, so back-pressure reaches the
// producer and the TCP window instead of a queue. What the clear-side
// consumer has consumed is mirrored too, as DELTA_TLS_DELIVERED: when
// `delivery_ack` is set the consumer acknowledges its deliveries
// (`CMD_DELIVERED`) and the count moves only then; otherwise a delivery is
// consumed when it is handed up. Under the strict profile the committed
// checkpoint ends a quiesce: from then on the horizons, not a closed
// window, keep the standby exact. PROFILE_PLANNED mirrors asynchronously;
// the cut at CUT_EXPORT is what is exact.
//
// Standby (importer): PAIR_PREPARE reserves one of `MAX_TLS_SHADOWS`
// shadows; the checkpoint stages into it chunk by chunk (CRC32 on the
// chunk stream, SHA-256 over the record at COMMIT), decodes, opens the
// sealed set, then advances by deltas in a strict digest chain. Any gap,
// conflicting duplicate, digest mismatch, oversize or unknown layout
// discards the shadow whole. CUT_IMPORT publishes, EMISSION_ARM proves
// readiness, and ACTIVATE — a strictly higher epoch and a non-zero
// fence generation — turns the shadow into a live `Ready` session bound
// to the connection id the coordinator names (trailing `[conn_id:2 LE]`
// on ACTIVATE; the record's own conn_id when absent). The new session
// forwards the ordinary accept/connect completion to its clear side so
// the consumer learns of the connection.

use abi::contracts::net::session_ctrl as sc;

/// Standby shadows one instance holds. Each is a staging record plus a
/// decoded checkpoint — about twice the record maximum.
#[cfg(target_arch = "aarch64")]
const MAX_TLS_SHADOWS: usize = 2;
#[cfg(target_arch = "wasm32")]
const MAX_TLS_SHADOWS: usize = 1;
/// The MCU-class targets hold no standby: a shadow is ~17 KiB of a state
/// arena the one session and the wifi stack already fill, and no graph
/// there runs the transport-continuity pair.
#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
const MAX_TLS_SHADOWS: usize = 0;

/// Write an empty shadow in place. Every byte of one is zero but its
/// import's CRC seed, so it is zeroed and that is set — a static empty
/// shadow to copy from would put its buffers (the record staging and the
/// deliveries a record may carry) in the module's read-only data.
unsafe fn shadow_init_in_place(sh: *mut TlsShadow) {
    core::ptr::write_bytes(sh, 0, 1);
    core::ptr::addr_of_mut!((*sh).phase).write(ShadowPhase::Idle);
    core::ptr::addr_of_mut!((*sh).import).write(HandoffImport::new());
}

/// The record's layout byte, its only layout.
const TLS_CKPT_LAYOUT: u8 = 1;
/// Identity of the codec layout; its SHA-256 is the `codec_digest` a
/// PAIR_PREPARE must carry.
const TLS_CODEC_LABEL: [u8; 28] = *b"fluxor.tls.continuity.ct_tls";
/// Vault label of the continuity master: a KDF key that never seals
/// anything itself. Each flow's sealing key is derived from it per
/// ownership epoch (`CONT_KEY_LABEL`, context `flow_id ‖ epoch`), so the key
/// a custody transfer moves opens that flow's objects at that epoch and
/// nothing else.
const TLS_CONTINUITY_LABEL: [u8; 21] = *b"tls-continuity-master";
/// DERIVE label of a flow's sealing key.
const CONT_KEY_LABEL: &[u8] = b"tls/continuity";
/// Vault label of this host's custody identity: the P-256 key its custody
/// evidence is signed by (`CMD_SC_CUSTODY` ATTEST).
const CUSTODY_ID_LABEL: &[u8] = b"tls-custody";
/// Continuity keys one instance holds: flows' sealing keys (derived here,
/// or unwrapped from a custody transfer) and custody recipients — a
/// recipient and a key per shadow, and two primaries' keys.
const CONT_KEYS: usize = 2 + 2 * MAX_TLS_SHADOWS;
/// Key updates a decoded record may be ahead of its sealed secret set by:
/// each is derived forward from the sealed set at import (RFC 8446 §7.2).
const CONT_DERIVE_MAX: u32 = 16;
/// TLS 1.3 on the wire.
const TLS_PROTOCOL_VERSION: u16 = 0x0304;

/// Secret-set plaintext, as laid out above.
const TLS_SECRET_SET_LEN: usize = 1 + 48 + 48 + 1 + 32 + 12 + 1 + 32 + 12 + 8 + 8;
/// The vault's AEAD framing: nonce and tag.
const VAULT_SEAL_OVERHEAD: usize = 12 + 16;
/// Sealed secret set.
const TLS_SEALED_LEN: usize = TLS_SECRET_SET_LEN + VAULT_SEAL_OVERHEAD;
/// The longest AAD a seal here binds: flow, ownership epoch, transport,
/// record kind, and — for a checkpoint — both traffic epochs and both
/// record sequence numbers. What a seal binds is what a forger cannot
/// substitute in the cleartext beside it.
const CONT_AAD_LEN: usize = sc::FLOW_ID_BYTES + sc::EPOCH_BYTES + 1 + 1 + 4 + 4 + 8 + 8;
/// AAD kind: a whole-session checkpoint.
const AAD_KIND_CHECKPOINT: u8 = 1;
/// AAD kind: a key-update delta, one direction.
const AAD_KIND_KEY_UPDATE: u8 = 2;
/// ALPN and SNI fields.
const CKPT_ALPN_MAX: usize = 16;
const CKPT_SNI_MAX: usize = 64;
/// High bit of the SNI length byte: the field holds the address the
/// session expects as an `iPAddress` (4 or 16 bytes), not a name.
const CKPT_SNI_IS_IP: u8 = 0x80;

/// The record's peer block: the transport peer, the requester tag and the
/// peer identity (`PeerIdFacts`).
const CKPT_PEER_LEN: usize = PEER_TAIL
    + 2
    + 1
    + 1
    + 4
    + 8
    + 8
    + 1
    + PEER_IDENTITY_MAX_FINGERPRINT
    + 1
    + PEER_IDENTITY_MAX_PRINCIPAL;

/// Fixed part of the record.
const CKPT_FIXED_LEN: usize = 1
    + 2
    + 2
    + 1
    + 2
    + 1
    + CKPT_ALPN_MAX
    + 1
    + CKPT_SNI_MAX
    + 1
    + 1
    + CKPT_PEER_LEN
    + 48
    + 4
    + 4
    + 4
    + 4
    + 8
    + 8
    + 1
    + 1
    + 1
    + 1
    + 8
    + 8
    + 8
    + 8
    + 8
    + 8
    + 4
    + 4
    + 4
    + 1
    + 2
    + 2
    + 1
    + 4;
/// Unconsumed deliveries a record may carry for a standby to hand its
/// worker again, as `[len:2][plaintext]` entries: four whole records where
/// a whole record is received (aarch64), eight of up to 512 bytes elsewhere.
#[cfg(target_arch = "aarch64")]
const CONT_REDELIVER_MAX: usize = 4 * 2 + 4 * 16384;
#[cfg(not(target_arch = "aarch64"))]
const CONT_REDELIVER_MAX: usize = 8 * 2 + 8 * 512;
/// And at most this many of them.
const CONT_REDELIVER_COUNT: u8 = 8;
/// Records handed up and not yet consumed a primary keeps account of
/// (`delivery_ack`): a strict pair never lets more than
/// `CONT_REDELIVER_COUNT` stand (`continuity_rx_gate`); beyond these the
/// oldest is counted consumed, which only an unmirrored session reaches.
const PEND_MAX: usize = 16;
const _: () = assert!(PEND_MAX >= CONT_REDELIVER_COUNT as usize);
/// Largest CT_TLS record this build emits or accepts.
const TLS_CKPT_RECORD_MAX: usize =
    CKPT_FIXED_LEN + RECV_BUF_SIZE + RETX_BUF_SIZE + CONT_REDELIVER_MAX + TLS_SEALED_LEN;

/// Delta payloads.
/// RECORD_OUT: `[write_epoch:4][write_seq:8][ct_len:2][ct...]`.
const DELTA_OUT_HDR: usize = 4 + 8 + 2;
/// RECORD_IN: `[read_epoch:4][read_seq:8][recv_expected:4][partial_len:4][partial...]`,
/// and under the strict profile `[content_type:1][plain_len:2][plain...]`
/// after it: the record's inner type and its plaintext, or
/// `RECORD_IN_NOT_CARRIED` with no bytes for plaintext longer than
/// `DELIV_CARRY_MAX`.
const DELTA_IN_HDR: usize = 4 + 8 + 4 + 4;
/// The most plaintext a RECORD_IN carries: a whole record's (2^14) where a
/// whole record is received (aarch64), which TRANSPORT_CONTINUITY carries
/// as one delivery, and 512 on the small targets.
#[cfg(target_arch = "aarch64")]
const DELIV_CARRY_MAX: usize = 16384;
#[cfg(target_arch = "aarch64")]
const _: () = assert!(DELIV_CARRY_MAX == MAX_PLAINTEXT);
#[cfg(not(target_arch = "aarch64"))]
const DELIV_CARRY_MAX: usize = 512;
/// RECORD_IN content type: the plaintext was longer than `DELIV_CARRY_MAX`.
const RECORD_IN_NOT_CARRIED: u8 = 0xFF;
/// The strict RECORD_IN trailer, at its largest.
const DELTA_IN_TRAILER_MAX: usize = 1 + 2 + DELIV_CARRY_MAX;
/// `session_ctrl`'s `DELTA_TLS_DELIVERED`: the deliveries the clear-side
/// consumer has consumed, `[delivered:8 LE][consumer_cursor:8 LE]
/// [cursor_at:8 LE]`, a cumulative count of the records handed up whose
/// plaintext ends at or before `cursor_at`, and the cursor and clear byte
/// the consumer's acknowledgement carried.
pub const DELTA_TLS_DELIVERED: u8 = sc::DELTA_TLS_DELIVERED;
/// KEY_UPDATE: `[direction:1][epoch:4][sealed_len:2][sealed...]`.
const DELTA_KU_LEN: usize = 1 + 4 + 2 + TLS_SEALED_LEN;
const DELTA_DIR_WRITE: u8 = 0;
const DELTA_DIR_READ: u8 = 1;
/// Largest delta payload (a RECORD_IN carrying a full partial record and
/// its plaintext).
const DELTA_PAYLOAD_MAX: usize = DELTA_IN_HDR + RECV_BUF_SIZE + DELTA_IN_TRAILER_MAX;
/// Offset of a DELTA_APPLY payload in the assembly scratch.
const DELTA_PAYLOAD_OFF: usize = sc::FRAME_HDR + sc::DELTA_APPLY_HEADER_LEN;
/// Assembly scratch for every frame this surface reads or writes.
const CONT_SCRATCH_SIZE: usize = DELTA_PAYLOAD_OFF + DELTA_PAYLOAD_MAX;
/// Delta bytes a strict mirror lets stand unacknowledged on `cont_out`:
/// three quarters of the channel the manifest asks for — 64 KiB on aarch64,
/// and off-host the smallest it asks for, thumbv8m's 16 KiB.
#[cfg(target_arch = "aarch64")]
const CONT_OUT_BUDGET: usize = 48 * 1024;
#[cfg(not(target_arch = "aarch64"))]
const CONT_OUT_BUDGET: usize = 12 * 1024;
/// The most a strict mirror leaves on `cont_out` unread: what the inputs
/// are held to (`CONT_OUT_BUDGET`, asked before each frame they give up),
/// then the RECORD_OUTs of one `CMD_SEND`'s records held for their horizon
/// (the clear side is frozen while they are), then an owed KeyUpdate
/// answer. A strict pairing needs a `cont_out` ring that holds it
/// (`cont_out_admits_strict`): a delta the channel refused would end the
/// pair.
const CONT_OUT_NEED: usize = CONT_OUT_BUDGET
    + abi::contracts::net::net_proto::MAX_CMD_DATA
    + TX_HOLD_RECORDS
        * (DELTA_PAYLOAD_OFF + DELTA_OUT_HDR + 8 + (WIRE_RECORD_MAX - CLEAR_CHUNK_MAX))
    + DELTA_PAYLOAD_OFF
    + DELTA_KU_LEN;
// The ring the manifest asks for on aarch64 holds it.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(CONT_OUT_NEED <= 64 * 1024);
// What a strict pair's provider holds of a connection (`session_ctrl`'s
// strict bounds) holds each buffer of this module's a delta carries: the
// retransmit window, the partial record, a record's plaintext.
const _: () = assert!(RETX_BUF_SIZE <= sc::STRICT_SEND_BYTES);
const _: () = assert!(RECV_BUF_SIZE <= sc::STRICT_RECV_BYTES);
const _: () = assert!(DELIV_CARRY_MAX <= sc::STRICT_DELIVERY_BYTES);
/// `TlsSession::retx_head` of a window whose record boundaries are not
/// known (installed from a checkpoint, which carries the bytes and not
/// where its records start).
pub(crate) const RETX_HEAD_UNKNOWN: u16 = u16::MAX;
/// CUT manifest body.
const CUT_BODY_LEN: usize = 4 + 4 + 32 + 1 + 2 + TLS_SEALED_LEN;
/// The largest reply body: a CUT manifest, or custody evidence.
const REPLY_BODY_MAX: usize = if CUT_BODY_LEN > 2 + sc::custody::EVIDENCE_MAX {
    CUT_BODY_LEN
} else {
    2 + sc::custody::EVIDENCE_MAX
};
/// Reply assembly: header, continuity header, the largest body.
const REPLY_MAX: usize = sc::FRAME_HDR + sc::CONTINUITY_HEADER_LEN + REPLY_BODY_MAX;
/// Frames drained from cont_in per step.
const CONT_DRAIN_BUDGET: u32 = 8;
/// Outbound records one session may hold for its send horizon: every
/// record one `CMD_SEND` (`MAX_CMD_DATA` bytes) can produce, since the
/// clear-side frame is consumed whole.
const TX_HOLD_RECORDS: usize =
    abi::contracts::net::net_proto::MAX_CMD_DATA.div_ceil(CLEAR_CHUNK_MAX);
const TX_HOLD_SIZE: usize = TX_HOLD_RECORDS * WIRE_RECORD_MAX;
/// Milliseconds a strict horizon may stay unconfirmed before the mirror is
/// abandoned. The inputs are one channel for every session, so a horizon
/// freezes them all; a standby that has stopped answering must not hold
/// the whole instance hostage. Generous against any real round trip — a
/// mirror across hosts, its channel reconnecting once — so a slow standby
/// is tolerated and only a dead one is given up on. Wall-clock, not steps:
/// how many steps a second holds depends on the graph's tick and load,
/// and a budget that shrinks as the scheduler speeds up would abandon a
/// healthy cross-host pair.
pub const CONT_HORIZON_MS: u64 = 2000;
/// `shadow_slot` reported to a primary, which reserves no shadow.
const NO_SHADOW_SLOT: u16 = 0xFFFF;

const _: () = assert!(
    sc::CHECKPOINT_CHUNK_MAX + sc::FRAME_HDR + sc::CHECKPOINT_NEXT_HEADER_LEN <= CONT_SCRATCH_SIZE
);
const _: () = assert!(DELTA_OUT_HDR + WIRE_RECORD_MAX <= DELTA_PAYLOAD_MAX);
const _: () = assert!(DELTA_KU_LEN <= DELTA_PAYLOAD_MAX);
const _: () = assert!(TLS_CKPT_RECORD_MAX <= u32::MAX as usize);

// ── Secret set ──────────────────────────────────────────────────────

/// Everything that must never cross the surface in the clear.
struct SecretSet {
    hash_len: u8,
    client_app: [u8; 48],
    server_app: [u8; 48],
    read_key_len: u8,
    read_key: [u8; 32],
    read_iv: [u8; 12],
    write_key_len: u8,
    write_key: [u8; 32],
    write_iv: [u8; 12],
    /// The record sequences when sealed: an import may resume at or past
    /// them, never before.
    read_seq_floor: u64,
    write_seq_floor: u64,
}

impl SecretSet {
    const fn empty() -> Self {
        Self {
            hash_len: 0,
            client_app: [0; 48],
            server_app: [0; 48],
            read_key_len: 0,
            read_key: [0; 32],
            read_iv: [0; 12],
            write_key_len: 0,
            write_key: [0; 32],
            write_iv: [0; 12],
            read_seq_floor: 0,
            write_seq_floor: 0,
        }
    }

    /// Take another set's contents, byte for byte, leaving the other to be
    /// wiped by its owner: a move would leave its bytes on the stack.
    fn copy_from(&mut self, o: &SecretSet) {
        self.hash_len = o.hash_len;
        self.client_app = o.client_app;
        self.server_app = o.server_app;
        self.read_key_len = o.read_key_len;
        self.read_key = o.read_key;
        self.read_iv = o.read_iv;
        self.write_key_len = o.write_key_len;
        self.write_key = o.write_key;
        self.write_iv = o.write_iv;
        self.read_seq_floor = o.read_seq_floor;
        self.write_seq_floor = o.write_seq_floor;
    }

    fn wipe(&mut self) {
        cont_wipe(&mut self.client_app);
        cont_wipe(&mut self.server_app);
        cont_wipe(&mut self.read_key);
        cont_wipe(&mut self.read_iv);
        cont_wipe(&mut self.write_key);
        cont_wipe(&mut self.write_iv);
        self.hash_len = 0;
        self.read_key_len = 0;
        self.write_key_len = 0;
        self.read_seq_floor = 0;
        self.write_seq_floor = 0;
    }

    fn encode(&self, out: &mut [u8; TLS_SECRET_SET_LEN]) {
        let mut e = Enc::new(out.as_mut_ptr(), TLS_SECRET_SET_LEN);
        e.u8(self.hash_len);
        e.bytes(&self.client_app);
        e.bytes(&self.server_app);
        e.u8(self.read_key_len);
        e.bytes(&self.read_key);
        e.bytes(&self.read_iv);
        e.u8(self.write_key_len);
        e.bytes(&self.write_key);
        e.bytes(&self.write_iv);
        e.u64(self.read_seq_floor);
        e.u64(self.write_seq_floor);
    }

    fn decode(&mut self, pt: &[u8]) -> bool {
        if pt.len() != TLS_SECRET_SET_LEN {
            return false;
        }
        let mut d = Dec::new(pt.as_ptr(), pt.len());
        let hl = d.u8();
        let mut ok = true;
        ok &= d.take_into(&mut self.client_app);
        ok &= d.take_into(&mut self.server_app);
        let rkl = d.u8();
        ok &= d.take_into(&mut self.read_key);
        ok &= d.take_into(&mut self.read_iv);
        let wkl = d.u8();
        ok &= d.take_into(&mut self.write_key);
        ok &= d.take_into(&mut self.write_iv);
        let (rf, wf) = (d.u64(), d.u64());
        match (hl, rkl, wkl, rf, wf) {
            (Some(hl), Some(rkl), Some(wkl), Some(rf), Some(wf)) if ok => {
                if !(hl == 32 || hl == 48) || rkl as usize > 32 || wkl as usize > 32 {
                    return false;
                }
                self.hash_len = hl;
                self.read_key_len = rkl;
                self.write_key_len = wkl;
                self.read_seq_floor = rf;
                self.write_seq_floor = wf;
                true
            }
            _ => false,
        }
    }

    /// One KeyUpdate of one direction (RFC 8446 §7.2): the next
    /// application traffic secret, and the keys from it. A server reads the
    /// client's secret and writes its own.
    fn advance(&mut self, suite: CipherSuite, is_server: bool, inbound: bool) {
        let hl = self.hash_len as usize;
        let secret = if inbound != is_server {
            &mut self.server_app
        } else {
            &mut self.client_app
        };
        advance_traffic_secret(suite.hash_alg(), hl, secret);
        let mut fresh = TrafficKeys::from_secret(suite, &secret[..hl]);
        if inbound {
            self.read_key = fresh.key;
            self.read_iv = fresh.iv;
            self.read_key_len = fresh.key_len as u8;
        } else {
            self.write_key = fresh.key;
            self.write_iv = fresh.iv;
            self.write_key_len = fresh.key_len as u8;
        }
        cont_wipe(&mut fresh.key);
        cont_wipe(&mut fresh.iv);
    }

    /// Snapshot the session's live secrets.
    fn from_session(sess: &TlsSession) -> Option<Self> {
        let ks = sess.driver.key_schedule.as_ref()?;
        let mut set = Self::empty();
        set.hash_len = ks.hash_len as u8;
        set.client_app = ks.client_app_secret;
        set.server_app = ks.server_app_secret;
        set.read_key_len = sess.read_keys.key_len as u8;
        set.read_key = sess.read_keys.key;
        set.read_iv = sess.read_keys.iv;
        set.write_key_len = sess.write_keys.key_len as u8;
        set.write_key = sess.write_keys.key;
        set.write_iv = sess.write_keys.iv;
        set.read_seq_floor = sess.read_keys.seq;
        set.write_seq_floor = sess.write_keys.seq;
        Some(set)
    }
}

// ── Decoded checkpoint ──────────────────────────────────────────────

/// A record after validation: what a shadow advances by deltas and
/// what ACTIVATE turns into a session.
struct TlsCheckpoint {
    suite: u16,
    is_server: bool,
    conn_id: u16,
    alpn: [u8; CKPT_ALPN_MAX],
    alpn_len: u8,
    sni: [u8; CKPT_SNI_MAX],
    sni_len: u8,
    sni_is_ip: bool,
    peer_verified: u8,
    peer_profile: u8,
    /// The transport peer as `MSG_PEER` reports it (`[family][addr][port]`),
    /// family 0 when none was reported.
    peer: [u8; PEER_TAIL],
    /// A client session's requester tag (0 for a server session).
    requester_tag: u16,
    /// What the handshake established about the peer.
    peer_id: PeerIdFacts,
    exporter_ctx: [u8; 48],
    read_epoch: u32,
    write_epoch: u32,
    read_seq: u64,
    write_seq: u64,
    key_update: u8,
    /// Bit 1: the peer's close_notify arrived; bit 2: its transport FIN.
    close_notify: u8,
    delivered_in: u64,
    emitted_out: u64,
    /// The consumer's clear bytes through the last record emitted: its
    /// output horizon, in its numbering (`net_proto::MSG_HORIZON`).
    out_bytes: u64,
    /// The cursor the consumer's last `CMD_DELIVERED` carried, and the
    /// clear byte it stood at.
    consumer_cursor: u64,
    cursor_at: u64,
    /// The clear bytes of the `delivered_in` records: where the first
    /// unconsumed delivery starts.
    in_bytes: u64,
    recv_expected: u32,
    recv_len: u32,
    recv: [u8; RECV_BUF_SIZE],
    retx_base_seq: u32,
    retx_anchored: bool,
    retx_len: u16,
    retx: [u8; RETX_BUF_SIZE],
    /// Unconsumed deliveries, `[len:2][plaintext]` each.
    deliv_count: u8,
    deliv_len: u32,
    deliv: [u8; CONT_REDELIVER_MAX],
    secrets: SecretSet,
}

impl TlsCheckpoint {
    const fn empty() -> Self {
        Self {
            suite: 0,
            is_server: false,
            conn_id: 0,
            alpn: [0; CKPT_ALPN_MAX],
            alpn_len: 0,
            sni: [0; CKPT_SNI_MAX],
            sni_len: 0,
            sni_is_ip: false,
            peer_verified: 0,
            peer_profile: 0,
            peer: [0; PEER_TAIL],
            requester_tag: 0,
            peer_id: PeerIdFacts::empty(),
            exporter_ctx: [0; 48],
            read_epoch: 0,
            write_epoch: 0,
            read_seq: 0,
            write_seq: 0,
            key_update: 0,
            close_notify: 0,
            delivered_in: 0,
            emitted_out: 0,
            out_bytes: 0,
            consumer_cursor: 0,
            cursor_at: 0,
            in_bytes: 0,
            recv_expected: 0,
            recv_len: 0,
            recv: [0; RECV_BUF_SIZE],
            retx_base_seq: 0,
            retx_anchored: false,
            retx_len: 0,
            retx: [0; RETX_BUF_SIZE],
            deliv_count: 0,
            deliv_len: 0,
            deliv: [0; CONT_REDELIVER_MAX],
            secrets: SecretSet::empty(),
        }
    }

    fn wipe(&mut self) {
        self.secrets.wipe();
        cont_wipe(&mut self.recv);
        cont_wipe(&mut self.retx);
        cont_wipe(&mut self.deliv[..self.deliv_len as usize]);
        self.deliv_count = 0;
        self.deliv_len = 0;
        self.recv_len = 0;
        self.retx_len = 0;
        // Nothing identifying survives a release: the suite, the connection,
        // the traffic epochs and the exporter context are all facts about a
        // session this slot no longer holds.
        self.suite = 0;
        self.conn_id = 0;
        self.read_epoch = 0;
        self.write_epoch = 0;
        self.exporter_ctx = [0; 48];
        self.peer = [0; PEER_TAIL];
        self.requester_tag = 0;
        self.peer_id = PeerIdFacts::empty();
        self.emitted_out = 0;
        self.out_bytes = 0;
        self.consumer_cursor = 0;
        self.cursor_at = 0;
        self.in_bytes = 0;
        self.delivered_in = 0;
        self.read_seq = 0;
        self.write_seq = 0;
    }
}

// ── Shadow ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShadowPhase {
    Idle,
    Prepared,
    Receiving,
    Committed,
    Published,
    Armed,
}

struct TlsShadow {
    phase: ShadowPhase,
    flow_id: [u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    profile: u8,
    ckpt_gen: u32,
    record_len: u32,
    record_digest: [u8; 32],
    import: HandoffImport,
    /// Chunk staging; wiped once the record is decoded.
    record: [u8; TLS_CKPT_RECORD_MAX],
    ck: TlsCheckpoint,
    /// Delta horizon: the last delta applied and its digest.
    delta_no: u32,
    last_digest: [u8; 32],
}

impl TlsShadow {
    const fn empty() -> Self {
        Self {
            phase: ShadowPhase::Idle,
            flow_id: [0; sc::FLOW_ID_BYTES],
            epoch: 0,
            profile: 0,
            ckpt_gen: 0,
            record_len: 0,
            record_digest: [0; 32],
            import: HandoffImport::new(),
            record: [0; TLS_CKPT_RECORD_MAX],
            ck: TlsCheckpoint::empty(),
            delta_no: 0,
            last_digest: [0; 32],
        }
    }

    /// Discard the transfer and the decoded state; keep the reservation.
    fn discard_to_prepared(&mut self) {
        self.import.reset();
        cont_wipe(&mut self.record);
        self.ck.wipe();
        self.record_len = 0;
        self.delta_no = 0;
        self.last_digest = [0; 32];
        self.phase = ShadowPhase::Prepared;
    }

    /// Release the slot entirely.
    fn release(&mut self) {
        self.discard_to_prepared();
        self.phase = ShadowPhase::Idle;
        self.flow_id = [0; sc::FLOW_ID_BYTES];
        self.epoch = 0;
        self.profile = 0;
        self.ckpt_gen = 0;
        self.record_digest = [0; 32];
    }

    fn holds_record(&self) -> bool {
        matches!(
            self.phase,
            ShadowPhase::Committed | ShadowPhase::Published | ShadowPhase::Armed
        )
    }
}

// ── Per-session continuity state (primary side) ─────────────────────

struct SessionContinuity {
    flow_id: [u8; sc::FLOW_ID_BYTES],
    flow_bound: bool,
    epoch: u32,
    profile: u8,
    /// A standby holds a committed checkpoint: deltas flow.
    mirror: bool,
    /// CUT emitted, CHECKPOINT_COMMITTED awaited: inputs frozen.
    cut_pending: bool,
    /// The mirror was abandoned and the abort has not yet left `cont_out`,
    /// and why (`sc::ABORT_*`): the record ceiling, the redelivery caps or
    /// the horizon budget, each by name, else the mirror lost.
    abandon_pending: bool,
    abandon_reason: u8,
    /// `dev_millis` when a strict horizon (or an undelivered abort) began
    /// to wait with no answer from the standby since — each acknowledgement
    /// restarts it (`apply_delta_ack`) — 0 while nothing does. A horizon is a promise the standby
    /// confirms within a bounded time; one it never confirms would
    /// otherwise freeze this instance's inputs for every session.
    horizon_since_ms: u64,
    quiescing: bool,
    ckpt_gen: u32,
    next_delta: u32,
    acked_delta: u32,
    /// Bytes of deltas written to `cont_out` since every delta was last
    /// acknowledged: a bound on what the channel may still hold unread.
    delta_unacked_bytes: u32,
    /// The peer asked for a KeyUpdate (update_requested) and our own has not
    /// been sent: between the inbound rotation and the answer at a primary,
    /// or at a standby activated from a record that owed it, until it goes.
    ku_answer_owed: bool,
    last_digest: [u8; 32],
    /// Outbound records awaiting their send horizon, back to back, each
    /// self-delimited by its record header.
    tx_hold: [u8; TX_HOLD_SIZE],
    tx_hold_len: u16,
    /// Bytes of the hold already carried by a delta.
    tx_hold_mirrored: u16,
    /// Delta carrying the last mirrored held record.
    tx_hold_delta: u32,
    /// Every held record is acknowledged; the writes are pending.
    tx_hold_released: bool,
    /// SHA-256 of the record CUT_EXPORT emitted, awaiting its commit.
    ckpt_digest: [u8; 32],
    /// Inbound record awaiting its receive horizon.
    rx_hold_pending: bool,
    rx_hold_delta: u32,
    rx_released: bool,
    /// A decrypted inbound record whose RECORD_IN `cont_out` refused: its
    /// content type and plaintext length (the plaintext is in
    /// `record_scratch`), offered again each step.
    rx_owed: bool,
    rx_owed_type: u8,
    rx_owed_len: u16,
    /// Deliveries the clear-side consumer has consumed — the records
    /// handed up whose plaintext ends at or before the clear byte its last
    /// `CMD_DELIVERED` carried — and the count last mirrored as
    /// DELTA_TLS_DELIVERED.
    consumed: u64,
    consumed_told: u64,
    /// The cursor the consumer's last `CMD_DELIVERED` carried (opaque, 0
    /// for none) and its clear byte (`in_bytes`), and the ones last
    /// mirrored with the count.
    consumer_cursor: u64,
    cursor_told: u64,
    cursor_at: u64,
    cursor_at_told: u64,
    /// The clear byte the last record handed up ends at, in the consumer's
    /// numbering (from the stream's start, across takeovers).
    handed_bytes: u64,
    /// The records handed up and not yet consumed (`delivery_ack`): where
    /// each ends, oldest first, and their plaintext bytes in all.
    pend_end: [u64; PEND_MAX],
    pend_len: [u16; PEND_MAX],
    pend_n: u8,
    pend_bytes: u32,
    /// `dev_millis` when the redelivery caps began holding the next record
    /// back with no consumption since (0 while they do not).
    cap_since_ms: u64,
    /// `dev_millis` when the record ceiling (`sc::STRICT_TX_RECORDS`) began
    /// holding the next outbound record back with no acknowledgement from
    /// the peer's transport since (0 while it does not).
    pub(crate) txrec_since_ms: u64,
    /// Activated here: `MSG_RESUMED` (`[cursor][in_bytes][out_bytes]`) is
    /// owed to the consumer, after the peer report and before any data.
    resumed_owed: bool,
    resumed_cursor: u64,
    resumed_in: u64,
    resumed_out: u64,
    /// Write-side key-update barrier.
    write_barrier_pending: bool,
    write_barrier_delta: u32,
    /// Keys of the retired write epoch, kept until their ciphertext is
    /// acknowledged.
    retired_write: TrafficKeys,
    retired_pending: bool,
    /// The session moved here: what its peer was established as where it
    /// was opened came with it (`moved_id`), since the credential itself
    /// does not — its `peer_identity` record and a later export say that.
    peer_moved: bool,
    moved_id: PeerIdFacts,
    /// The session was activated from a shadow and has not been named as a
    /// primary since: an ABORT at its epoch undoes the activation.
    activated: bool,
    /// Delivery horizons.
    delivered_in: u64,
    emitted_out: u64,
}

impl SessionContinuity {
    const fn empty() -> Self {
        Self {
            flow_id: [0; sc::FLOW_ID_BYTES],
            flow_bound: false,
            epoch: 0,
            profile: 0,
            mirror: false,
            cut_pending: false,
            abandon_pending: false,
            abandon_reason: 0,
            horizon_since_ms: 0,
            quiescing: false,
            ckpt_gen: 0,
            next_delta: 1,
            acked_delta: 0,
            delta_unacked_bytes: 0,
            ku_answer_owed: false,
            last_digest: [0; 32],
            tx_hold: [0; TX_HOLD_SIZE],
            tx_hold_len: 0,
            tx_hold_mirrored: 0,
            tx_hold_delta: 0,
            tx_hold_released: false,
            ckpt_digest: [0; 32],
            rx_hold_pending: false,
            rx_hold_delta: 0,
            rx_released: false,
            rx_owed: false,
            rx_owed_type: 0,
            rx_owed_len: 0,
            consumed: 0,
            consumed_told: 0,
            consumer_cursor: 0,
            cursor_told: 0,
            cursor_at: 0,
            cursor_at_told: 0,
            handed_bytes: 0,
            pend_end: [0; PEND_MAX],
            pend_len: [0; PEND_MAX],
            pend_n: 0,
            pend_bytes: 0,
            cap_since_ms: 0,
            txrec_since_ms: 0,
            resumed_owed: false,
            resumed_cursor: 0,
            resumed_in: 0,
            resumed_out: 0,
            write_barrier_pending: false,
            write_barrier_delta: 0,
            retired_write: TrafficKeys::empty(),
            retired_pending: false,
            peer_moved: false,
            moved_id: PeerIdFacts::empty(),
            activated: false,
            delivered_in: 0,
            emitted_out: 0,
        }
    }

    fn reset(&mut self) {
        // Field by field: assigning `Self::empty()` would build a struct the
        // size of the hold on the stack of every connection close.
        cont_wipe(&mut self.tx_hold);
        cont_wipe(&mut self.retired_write.key);
        cont_wipe(&mut self.retired_write.iv);
        self.flow_id = [0; sc::FLOW_ID_BYTES];
        self.flow_bound = false;
        self.epoch = 0;
        self.profile = 0;
        self.mirror = false;
        self.cut_pending = false;
        self.abandon_pending = false;
        self.abandon_reason = 0;
        self.horizon_since_ms = 0;
        self.quiescing = false;
        self.ckpt_gen = 0;
        self.next_delta = 0;
        self.acked_delta = 0;
        self.delta_unacked_bytes = 0;
        self.ku_answer_owed = false;
        self.last_digest = [0; 32];
        self.tx_hold_len = 0;
        self.tx_hold_mirrored = 0;
        self.tx_hold_delta = 0;
        self.tx_hold_released = false;
        self.ckpt_digest = [0; 32];
        self.rx_hold_pending = false;
        self.rx_hold_delta = 0;
        self.rx_released = false;
        self.rx_owed = false;
        self.rx_owed_type = 0;
        self.rx_owed_len = 0;
        self.consumed = 0;
        self.consumed_told = 0;
        self.consumer_cursor = 0;
        self.cursor_told = 0;
        self.cursor_at = 0;
        self.cursor_at_told = 0;
        self.handed_bytes = 0;
        self.pend_n = 0;
        self.pend_bytes = 0;
        self.cap_since_ms = 0;
        self.txrec_since_ms = 0;
        self.resumed_owed = false;
        self.resumed_cursor = 0;
        self.resumed_in = 0;
        self.resumed_out = 0;
        self.write_barrier_pending = false;
        self.write_barrier_delta = 0;
        self.retired_pending = false;
        self.peer_moved = false;
        self.moved_id = PeerIdFacts::empty();
        self.activated = false;
        self.delivered_in = 0;
        self.emitted_out = 0;
    }

    fn strict(&self) -> bool {
        self.profile == sc::PROFILE_CRASH_CONTINUOUS
    }

    /// A transition of this session is waiting on the standby.
    fn horizon_outstanding(&self) -> bool {
        self.tx_hold_len != 0 || self.rx_hold_pending || self.rx_owed || self.write_barrier_pending
    }

    /// Decrypted plaintext is held for the receive horizon: it may not be
    /// handed up yet.
    fn rx_held(&self) -> bool {
        self.rx_hold_pending || self.rx_owed
    }

    /// A strict mirror was abandoned and the coordinator has not yet been
    /// told. Until it has, nothing of the session moves — no record is
    /// written, no input read — because a coordinator that has not been
    /// told may still activate the shadow, and any record the peer saw in
    /// the meantime would be one the shadow then seals again under the same
    /// key and sequence.
    fn abandon_blocks(&self) -> bool {
        self.abandon_pending && self.strict()
    }
}

// ── Byte cursors ────────────────────────────────────────────────────

/// Bounded writer over a raw buffer. A write past the end clears `ok`
/// and writes nothing; the caller checks once at the end.
struct Enc {
    p: *mut u8,
    cap: usize,
    pos: usize,
    ok: bool,
}

impl Enc {
    fn new(p: *mut u8, cap: usize) -> Self {
        Self {
            p,
            cap,
            pos: 0,
            ok: true,
        }
    }
    fn raw(&mut self, src: *const u8, n: usize) {
        if !self.ok || n > self.cap - self.pos {
            self.ok = false;
            return;
        }
        // SAFETY: `pos + n <= cap` was checked; `p` covers `cap` bytes.
        unsafe { core::ptr::copy_nonoverlapping(src, self.p.add(self.pos), n) };
        self.pos += n;
    }
    fn bytes(&mut self, b: &[u8]) {
        self.raw(b.as_ptr(), b.len());
    }
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
}

/// Bounded reader; every accessor is `None` past the end.
struct Dec {
    p: *const u8,
    len: usize,
    pos: usize,
}

impl Dec {
    fn new(p: *const u8, len: usize) -> Self {
        Self { p, len, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.len - self.pos
    }
    fn take(&mut self, n: usize) -> Option<*const u8> {
        if n > self.remaining() {
            return None;
        }
        // SAFETY: `pos + n <= len`; `p` covers `len` bytes.
        let q = unsafe { self.p.add(self.pos) };
        self.pos += n;
        Some(q)
    }
    fn take_into(&mut self, out: &mut [u8]) -> bool {
        match self.take(out.len()) {
            Some(q) => {
                // SAFETY: `q` is valid for `out.len()` bytes (checked in `take`).
                unsafe { core::ptr::copy_nonoverlapping(q, out.as_mut_ptr(), out.len()) };
                true
            }
            None => false,
        }
    }
    fn u8(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        self.take_into(&mut b).then_some(b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let mut b = [0u8; 2];
        self.take_into(&mut b).then_some(u16::from_le_bytes(b))
    }
    fn u32(&mut self) -> Option<u32> {
        let mut b = [0u8; 4];
        self.take_into(&mut b).then_some(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Option<u64> {
        let mut b = [0u8; 8];
        self.take_into(&mut b).then_some(u64::from_le_bytes(b))
    }
}

/// Volatile zero fill.
fn cont_wipe(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: `i < buf.len()`.
        unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(i), 0) };
        i += 1;
    }
}

/// SHA-256 of the codec layout identity — the `codec_digest` of a
/// PAIR_PREPARE for this transport.
fn tls_codec_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&TLS_CODEC_LABEL);
    // A record's shape depends on these, and they differ between builds,
    // so two instances agree on the codec only if they agree on them: a
    // mismatch is refused at pairing, not discovered at the first chunk.
    h.update(&(RECV_BUF_SIZE as u32).to_le_bytes());
    h.update(&(RETX_BUF_SIZE as u32).to_le_bytes());
    h.update(&(MAX_TLS_SHADOWS as u32).to_le_bytes());
    h.finalize()
}

fn flow_eq(a: &[u8; sc::FLOW_ID_BYTES], b: &[u8]) -> bool {
    if b.len() != sc::FLOW_ID_BYTES {
        return false;
    }
    let mut i = 0;
    while i < sc::FLOW_ID_BYTES {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn digest_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// ── Vault bridge ────────────────────────────────────────────────────
//
// `KEY_VAULT` is a kernel contract class every module may call. Nothing
// here holds a key: the master, each flow's sealing key, the custody
// identity and a recipient are vault handles, and what leaves the module is
// sealed objects, evidence and wrapped keys.

/// A continuity key this instance holds (`TlsState::cont_keys`).
#[derive(Clone, Copy)]
struct ContKey {
    kind: u8,
    /// The flow (a recipient: the name ATTEST was given) and epoch.
    flow: [u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    handle: i32,
    /// Insertion order, for eviction.
    stamp: u32,
    /// An unwrapped key a shadow has opened with.
    used: bool,
}

const KEY_FREE: u8 = 0;
/// A flow's sealing key, derived here from the master.
const KEY_DERIVED: u8 = 1;
/// A flow's sealing key, unwrapped from a custody transfer.
const KEY_IMPORTED: u8 = 2;
/// A custody recipient: a fresh P-256 agreement key, until its UNWRAP.
const KEY_RECIPIENT: u8 = 3;

const EMPTY_CONT_KEY: ContKey = ContKey {
    kind: KEY_FREE,
    flow: [0; sc::FLOW_ID_BYTES],
    epoch: 0,
    handle: -1,
    stamp: 0,
    used: false,
};

/// `OPEN_OR_GENERATE` a key under `label`; the handle, or -1. `pub_out`
/// receives the public half when the suite has one.
unsafe fn cont_vault_open_or_generate(
    sys: &SyscallTable,
    suite: u16,
    usage: u32,
    label: &[u8],
    pub_out: &mut [u8],
) -> i32 {
    let mut arg = [0u8; 8 + kv::MAX_LABEL + 12];
    if label.len() > kv::MAX_LABEL {
        return -1;
    }
    arg[0..2].copy_from_slice(&suite.to_le_bytes());
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[6] = 0;
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let t = 8 + label.len();
    arg[t..t + 8].copy_from_slice(&(pub_out.as_mut_ptr() as u64).to_le_bytes());
    arg[t + 8..t + 10].copy_from_slice(&(pub_out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(-1, kv::OPEN_OR_GENERATE, arg.as_mut_ptr(), t + 12);
    if rc < 0 {
        -1
    } else {
        rc
    }
}

/// `AEAD_SEAL` `pt` under `handle` with `aad`; bytes written to `out`, or 0.
unsafe fn cont_vault_seal(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + CONT_AAD_LEN + 2 + TLS_SECRET_SET_LEN + 12];
    if aad.len() > CONT_AAD_LEN || pt.len() > TLS_SECRET_SET_LEN {
        return 0;
    }
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + aad.len()].copy_from_slice(aad);
    p += aad.len();
    arg[p..p + 2].copy_from_slice(&(pt.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + pt.len()].copy_from_slice(pt);
    p += pt.len();
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 10].copy_from_slice(&(out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(handle, kv::AEAD_SEAL, arg.as_mut_ptr(), p + 12);
    let n = u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize;
    cont_wipe(&mut arg);
    if rc < 0 {
        return 0;
    }
    n
}

/// `AEAD_OPEN` `blob` under `handle` with `aad`; bytes written to `out`, or 0.
unsafe fn cont_vault_open(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + CONT_AAD_LEN + 2 + TLS_SEALED_LEN + 12];
    if aad.len() > CONT_AAD_LEN || blob.len() > TLS_SEALED_LEN {
        return 0;
    }
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + aad.len()].copy_from_slice(aad);
    p += aad.len();
    arg[p..p + 2].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + blob.len()].copy_from_slice(blob);
    p += blob.len();
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 10].copy_from_slice(&(out.len() as u16).to_le_bytes());
    let rc = (sys.provider_call)(handle, kv::AEAD_OPEN, arg.as_mut_ptr(), p + 12);
    if rc < 0 {
        return 0;
    }
    u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize
}

/// Free a vault handle.
unsafe fn cont_vault_destroy(sys: &SyscallTable, handle: i32) {
    if handle >= 0 {
        let _ = (sys.provider_call)(handle, kv::DESTROY, core::ptr::null_mut(), 0);
    }
}

/// The continuity master's handle, opening (or generating) it on first
/// use. -1 when no vault answers: continuity that cannot be sealed is not
/// offered.
unsafe fn cont_vault_handle(s: &mut TlsState) -> i32 {
    if s.cont_vault_handle >= 0 {
        return s.cont_vault_handle;
    }
    let sys = &*s.syscalls;
    s.cont_vault_handle = cont_vault_open_or_generate(
        sys,
        kv::suite::KDF_KEY,
        kv::usage::DERIVE | kv::usage::PERSIST,
        &TLS_CONTINUITY_LABEL,
        &mut [],
    );
    s.cont_vault_handle
}

/// Derive `flow`'s sealing key at `epoch` from the master: an AEAD key that
/// seals, opens and may leave this vault wrapped to an attested recipient.
unsafe fn cont_derive_key(s: &mut TlsState, flow: &[u8; sc::FLOW_ID_BYTES], epoch: u32) -> i32 {
    let master = cont_vault_handle(s);
    if master < 0 {
        return -1;
    }
    use kv::derive as d;
    let ctx_len = sc::FLOW_ID_BYTES + 4;
    let mut arg = [0u8; d::LABEL + 16 + sc::FLOW_ID_BYTES + 4];
    arg[d::TARGET_SUITE..d::TARGET_SUITE + 2].copy_from_slice(&kv::suite::AEAD_KEY.to_le_bytes());
    let usage = kv::usage::SEAL | kv::usage::OPEN | kv::usage::WRAP;
    arg[d::TARGET_USAGE..d::TARGET_USAGE + 4].copy_from_slice(&usage.to_le_bytes());
    arg[d::LABEL_LEN] = CONT_KEY_LABEL.len() as u8;
    arg[d::CONTEXT_LEN..d::CONTEXT_LEN + 2].copy_from_slice(&(ctx_len as u16).to_le_bytes());
    let l = d::LABEL;
    arg[l..l + CONT_KEY_LABEL.len()].copy_from_slice(CONT_KEY_LABEL);
    let c = l + CONT_KEY_LABEL.len();
    arg[c..c + sc::FLOW_ID_BYTES].copy_from_slice(flow);
    arg[c + sc::FLOW_ID_BYTES..c + ctx_len].copy_from_slice(&epoch.to_le_bytes());
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(master, kv::DERIVE, arg.as_mut_ptr(), c + ctx_len);
    if rc < 0 {
        -1
    } else {
        rc
    }
}

/// Whether a live session or a shadow of this instance is `(flow, epoch)`.
fn cont_key_referenced(s: &TlsState, k: &ContKey) -> bool {
    let mut i = 0;
    while i < s.sessions.len() {
        let sess = &s.sessions[i];
        if sess.state != SessionState::Idle
            && sess.cont.flow_bound
            && sess.cont.epoch == k.epoch
            && flow_eq(&sess.cont.flow_id, &k.flow)
        {
            return true;
        }
        i += 1;
    }
    s.shadows
        .iter()
        .any(|sd| sd.phase != ShadowPhase::Idle && sd.epoch == k.epoch && sd.flow_id == k.flow)
}

/// The key entry of `kind` (a mask of kinds) for `(flow, epoch)`.
fn cont_key_find(s: &TlsState, kinds: &[u8], flow: &[u8], epoch: u32) -> Option<usize> {
    s.cont_keys
        .iter()
        .position(|k| kinds.contains(&k.kind) && k.epoch == epoch && flow_eq(&k.flow, flow))
}

/// A free key entry: an empty one, else the one least worth keeping — a
/// derived key nothing references (it can be derived again), then the
/// oldest entry nothing references. `None` when every one is in use.
unsafe fn cont_key_alloc(s: &mut TlsState) -> Option<usize> {
    if let Some(i) = s.cont_keys.iter().position(|k| k.kind == KEY_FREE) {
        return Some(i);
    }
    let mut pick: Option<usize> = None;
    let mut i = 0;
    while i < CONT_KEYS {
        let k = s.cont_keys[i];
        if !cont_key_referenced(s, &k) {
            let better = match pick {
                None => true,
                Some(p) => {
                    let q = &s.cont_keys[p];
                    (k.kind == KEY_DERIVED && q.kind != KEY_DERIVED)
                        || ((k.kind == KEY_DERIVED) == (q.kind == KEY_DERIVED) && k.stamp < q.stamp)
                }
            };
            if better {
                pick = Some(i);
            }
        }
        i += 1;
    }
    let p = pick?;
    cont_key_free(s, p);
    Some(p)
}

unsafe fn cont_key_free(s: &mut TlsState, i: usize) {
    let sys = &*s.syscalls;
    cont_vault_destroy(sys, s.cont_keys[i].handle);
    s.cont_keys[i] = EMPTY_CONT_KEY;
}

unsafe fn cont_key_put(
    s: &mut TlsState,
    i: usize,
    kind: u8,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    handle: i32,
) {
    s.cont_key_stamp = s.cont_key_stamp.wrapping_add(1);
    s.cont_keys[i] = ContKey {
        kind,
        flow: *flow,
        epoch,
        handle,
        stamp: s.cont_key_stamp,
        used: false,
    };
}

/// The sealing key of `(flow, epoch)`: one a custody transfer brought, else
/// this vault's derivation from its master. -1 when neither is possible.
unsafe fn cont_flow_key(s: &mut TlsState, flow: &[u8; sc::FLOW_ID_BYTES], epoch: u32) -> i32 {
    if let Some(i) = cont_key_find(s, &[KEY_IMPORTED], flow, epoch) {
        s.cont_keys[i].used = true;
        return s.cont_keys[i].handle;
    }
    if let Some(i) = cont_key_find(s, &[KEY_DERIVED], flow, epoch) {
        return s.cont_keys[i].handle;
    }
    let Some(i) = cont_key_alloc(s) else {
        return -1;
    };
    let h = cont_derive_key(s, flow, epoch);
    if h < 0 {
        return -1;
    }
    cont_key_put(s, i, KEY_DERIVED, flow, epoch, h);
    h
}

/// Let go of keys nothing needs: a derived key no session or shadow is
/// keyed by, and an unwrapped one whose shadow has opened with it and gone.
/// A recipient waits for its UNWRAP (or for eviction).
unsafe fn cont_keys_sweep(s: &mut TlsState) {
    let mut i = 0;
    while i < CONT_KEYS {
        let k = s.cont_keys[i];
        let stale = match k.kind {
            KEY_DERIVED => !cont_key_referenced(s, &k),
            KEY_IMPORTED => k.used && !cont_key_referenced(s, &k),
            _ => false,
        };
        if stale {
            cont_key_free(s, i);
        }
        i += 1;
    }
}

/// AAD for a checkpoint's secret set. The traffic epochs the set was
/// sealed at travel in the clear beside it, so they are bound here; the sequence numbers are
/// sealed inside the set as floors (`read_seq_floor`, `write_seq_floor`),
/// so a record whose counters were rewound below them does not import.
/// Without either a standby could be made to resume at a sequence the peer
/// has already seen under the same key. The sequence fields of the AAD are
/// zero.
fn ckpt_aad(
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    read_epoch: u32,
    write_epoch: u32,
) -> [u8; CONT_AAD_LEN] {
    let mut a = [0u8; CONT_AAD_LEN];
    let mut e = Enc::new(a.as_mut_ptr(), CONT_AAD_LEN);
    e.bytes(flow);
    e.u32(epoch);
    e.u8(sc::CT_TLS);
    e.u8(AAD_KIND_CHECKPOINT);
    e.u32(read_epoch);
    e.u32(write_epoch);
    e.u64(0);
    e.u64(0);
    a
}

/// AAD for a key-update delta's secret set: the direction being rotated
/// and the traffic epoch it rotates into. A delta whose direction byte was
/// flipped would otherwise reset the other direction's counter to zero
/// under a key that direction already used from zero.
fn ku_aad(
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    direction: u8,
    dir_epoch: u32,
) -> [u8; CONT_AAD_LEN] {
    let mut a = [0u8; CONT_AAD_LEN];
    let mut e = Enc::new(a.as_mut_ptr(), CONT_AAD_LEN);
    e.bytes(flow);
    e.u32(epoch);
    e.u8(sc::CT_TLS);
    e.u8(AAD_KIND_KEY_UPDATE);
    e.u8(direction);
    e.u32(dir_epoch);
    a
}

/// Seal a session's secret set; `out` receives `TLS_SEALED_LEN` bytes.
unsafe fn seal_secret_set(
    s: &mut TlsState,
    idx: usize,
    aad: &[u8; CONT_AAD_LEN],
    out: &mut [u8; TLS_SEALED_LEN],
) -> bool {
    let (flow, epoch) = (s.sessions[idx].cont.flow_id, s.sessions[idx].cont.epoch);
    let handle = cont_flow_key(s, &flow, epoch);
    if handle < 0 {
        return false;
    }
    let mut set = match SecretSet::from_session(&s.sessions[idx]) {
        Some(set) => set,
        None => return false,
    };
    let mut pt = [0u8; TLS_SECRET_SET_LEN];
    set.encode(&mut pt);
    set.wipe();
    let sys = &*s.syscalls;
    let n = cont_vault_seal(sys, handle, aad, &pt, out);
    cont_wipe(&mut pt);
    n == TLS_SEALED_LEN
}

/// Open a sealed secret set of `(flow, epoch)` into `set`.
unsafe fn open_secret_set(
    s: &mut TlsState,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    aad: &[u8; CONT_AAD_LEN],
    sealed: &[u8],
    set: &mut SecretSet,
) -> bool {
    if sealed.len() != TLS_SEALED_LEN {
        return false;
    }
    let handle = cont_flow_key(s, flow, epoch);
    if handle < 0 {
        return false;
    }
    let mut pt = [0u8; TLS_SECRET_SET_LEN];
    let sys = &*s.syscalls;
    let n = cont_vault_open(sys, handle, aad, sealed, &mut pt);
    let ok = n == TLS_SECRET_SET_LEN && set.decode(&pt);
    cont_wipe(&mut pt);
    if !ok {
        // A set that opened but did not decode is still secret bytes.
        set.wipe();
    }
    ok
}

// ── Record codec ────────────────────────────────────────────────────

/// Encode the session's checkpoint into `s.cont_record`; the record
/// length, or 0 when the session is not exportable or cannot be sealed.
unsafe fn encode_checkpoint(
    s: &mut TlsState,
    idx: usize,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
) -> usize {
    let aad = {
        let sess = &s.sessions[idx];
        ckpt_aad(flow, epoch, sess.read_epoch, sess.write_epoch)
    };
    let mut sealed = [0u8; TLS_SEALED_LEN];
    if !seal_secret_set(s, idx, &aad, &mut sealed) {
        return 0;
    }
    let rec: *mut u8 = s.cont_record.as_mut_ptr();
    let sess = &s.sessions[idx];
    let mut e = Enc::new(rec, TLS_CKPT_RECORD_MAX);
    e.u8(TLS_CKPT_LAYOUT);
    e.u16(TLS_PROTOCOL_VERSION);
    e.u16(sess.driver.suite.id());
    e.u8(sess.driver.is_server as u8);
    e.u16(sess.conn_id);
    let alpn_len = (sess.driver.alpn_selected_len as usize).min(CKPT_ALPN_MAX);
    e.u8(alpn_len as u8);
    let mut alpn = [0u8; CKPT_ALPN_MAX];
    alpn[..alpn_len].copy_from_slice(&sess.driver.alpn_selected[..alpn_len]);
    e.bytes(&alpn);
    // The session's expected peer identity: a name, or (high bit of the
    // length) an address. A server session expects nothing.
    let sni_len = if sess.driver.is_server {
        0
    } else {
        (sess.expected_len as usize).min(CKPT_SNI_MAX)
    };
    let sni_kind = if sess.expected_is_ip && sni_len > 0 {
        CKPT_SNI_IS_IP
    } else {
        0
    };
    e.u8(sni_len as u8 | sni_kind);
    let mut sni = [0u8; CKPT_SNI_MAX];
    sni[..sni_len].copy_from_slice(&sess.expected[..sni_len]);
    e.bytes(&sni);
    let id = peer_id_facts(s, idx);
    let sess = &s.sessions[idx];
    e.u8(u8::from(id.kind != peer_credential::NONE));
    e.u8(s.peer_auth);
    e.bytes(&if sess.peer_have {
        sess.peer
    } else {
        [0; PEER_TAIL]
    });
    e.u16(if sess.driver.is_server {
        0
    } else {
        sess.downstream_tag
    });
    e.u8(id.result);
    e.u8(id.kind);
    e.u32(id.flags);
    e.u64(id.not_before);
    e.u64(id.not_after);
    e.u8(id.fp_len);
    e.bytes(&id.fp);
    e.u8(id.principal_len);
    e.bytes(&id.principal);
    e.bytes(&sess.driver.server_finished_hash);
    e.u32(sess.read_epoch);
    e.u32(sess.write_epoch);
    // Sealed just now, at the epochs the session is at.
    e.u32(sess.read_epoch);
    e.u32(sess.write_epoch);
    e.u64(sess.read_keys.seq);
    e.u64(sess.write_keys.seq);
    // key_update: no request of ours outstanding; bit 1 when the peer's
    // request is still unanswered.
    e.u8(u8::from(sess.cont.ku_answer_owed) << 1);
    // close_notify: bit 0 our own close_notify is sealed (a `Closing`
    // session's), bit 1 the peer's arrived, bit 2 the transport reported the
    // peer done (a half-closed session), bit 3 our transport close has gone
    // to `ip`.
    e.u8(u8::from(sess.local_close & LOCAL_CLOSE_SENT != 0)
        | (u8::from(sess.peer_closed & PEER_CLOSE_NOTIFY != 0) << 1)
        | (u8::from(sess.peer_closed & PEER_FIN != 0) << 2)
        | (u8::from(sess.local_close & LOCAL_CLOSE_FWD != 0) << 3));
    e.u8(0); // pending_alert
    e.u8(0); // ticket
    e.u64(sess.cont.delivered_in);
    e.u64(sess.cont.emitted_out);
    e.u64(sess.wh.through);
    e.u64(sess.cont.consumer_cursor);
    e.u64(sess.cont.cursor_at);
    // Everything handed up counts as delivered here: the record carries no
    // deliveries of its own.
    e.u64(sess.cont.handed_bytes);
    e.u32(sess.recv_expected as u32);
    e.u32(sess.recv_len as u32);
    e.u32(sess.retx_base_seq);
    e.u8(sess.retx_seq_anchored as u8);
    e.u16(sess.retx_len);
    e.u16(TLS_SEALED_LEN as u16);
    // No deliveries: what was handed up is the worker's, and this module
    // keeps no copy of it.
    e.u8(0);
    e.u32(0);
    e.raw(sess.recv_buf.as_ptr(), sess.recv_len);
    e.raw(sess.retx_buf.as_ptr(), sess.retx_len as usize);
    e.bytes(&sealed);
    cont_wipe(&mut sealed);
    if e.ok {
        e.pos
    } else {
        0
    }
}

/// A transport peer field: none (all zero), an IPv4 address (the rest of
/// the address zero) or an IPv6 one.
fn peer_tail_ok(p: &[u8; PEER_TAIL]) -> bool {
    match p[0] {
        0 => p.iter().all(|&b| b == 0),
        net_proto::AF_INET => p[5..17].iter().all(|&b| b == 0),
        net_proto::AF_INET6 => true,
        _ => false,
    }
}

/// The peer identity block, held to the only shapes a handshake produces:
/// no credential (every field zero but the result), or an accepted
/// certificate — its fingerprint, the checks that ran, and a principal only
/// where SAN was checked. Padding is zero.
fn decode_peer_id(d: &mut Dec, f: &mut PeerIdFacts) -> bool {
    let (Some(result), Some(kind), Some(flags), Some(nb), Some(na), Some(fp_len)) =
        (d.u8(), d.u8(), d.u32(), d.u64(), d.u64(), d.u8())
    else {
        return false;
    };
    let mut fp = [0u8; PEER_IDENTITY_MAX_FINGERPRINT];
    if !d.take_into(&mut fp) {
        return false;
    }
    let Some(pl) = d.u8() else {
        return false;
    };
    let mut principal = [0u8; PEER_IDENTITY_MAX_PRINCIPAL];
    if !d.take_into(&mut principal) {
        return false;
    }
    let pl_us = usize::from(pl);
    if pl_us > PEER_IDENTITY_MAX_PRINCIPAL || principal[pl_us..].iter().any(|&b| b != 0) {
        return false;
    }
    let ok = match kind {
        peer_credential::NONE => {
            result == peer_result::NO_CREDENTIAL
                && flags == 0
                && nb == 0
                && na == 0
                && fp_len == 0
                && fp.iter().all(|&b| b == 0)
                && pl == 0
        }
        peer_credential::X509_MTLS => {
            let need = peer_check::CHAIN | peer_check::KEY_POSSESSION | peer_check::EKU;
            let known = need | peer_check::VALIDITY | peer_check::SAN;
            result == peer_result::OK
                && flags & need == need
                && flags & !known == 0
                && usize::from(fp_len) == PEER_IDENTITY_MAX_FINGERPRINT
                && ((flags & peer_check::SAN != 0) == (pl > 0))
        }
        _ => false,
    };
    if !ok {
        return false;
    }
    *f = PeerIdFacts {
        result,
        kind,
        flags,
        not_before: nb,
        not_after: na,
        fp_len,
        fp,
        principal_len: pl,
        principal,
    };
    true
}

/// Decode and validate a staged record into the shadow's checkpoint.
/// `false` leaves the checkpoint wiped.
unsafe fn decode_checkpoint(s: &mut TlsState, sh: usize) -> bool {
    let shadow: *mut TlsShadow = &mut s.shadows[sh];
    let len = (*shadow).record_len as usize;
    let mut d = Dec::new((*shadow).record.as_ptr(), len);
    let ck: *mut TlsCheckpoint = &mut (*shadow).ck;
    let ok = decode_into(s, &(*shadow).flow_id, (*shadow).epoch, &mut d, &mut *ck);
    if !ok {
        (*ck).wipe();
    }
    ok
}

unsafe fn decode_into(
    s: &mut TlsState,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    d: &mut Dec,
    ck: &mut TlsCheckpoint,
) -> bool {
    if d.u8() != Some(TLS_CKPT_LAYOUT) {
        return false;
    }
    if d.u16() != Some(TLS_PROTOCOL_VERSION) {
        return false;
    }
    let suite = match d.u16() {
        Some(id) if CipherSuite::from_id(id).is_some() => id,
        _ => return false,
    };
    let role = match d.u8() {
        Some(r) if r <= 1 => r,
        _ => return false,
    };
    let conn_id = match d.u16() {
        Some(c) => c,
        None => return false,
    };
    let alpn_len = match d.u8() {
        Some(n) if n as usize <= CKPT_ALPN_MAX => n,
        _ => return false,
    };
    let mut alpn = [0u8; CKPT_ALPN_MAX];
    if !d.take_into(&mut alpn) {
        return false;
    }
    let (sni_len, sni_is_ip) = match d.u8() {
        Some(n) if (n & !CKPT_SNI_IS_IP) as usize <= CKPT_SNI_MAX => {
            (n & !CKPT_SNI_IS_IP, n & CKPT_SNI_IS_IP != 0)
        }
        _ => return false,
    };
    let mut sni = [0u8; CKPT_SNI_MAX];
    if !d.take_into(&mut sni) {
        return false;
    }
    let peer_verified = match d.u8() {
        Some(v) if v <= 1 => v,
        _ => return false,
    };
    let peer_profile = match d.u8() {
        Some(p) => p,
        None => return false,
    };
    let mut peer = [0u8; PEER_TAIL];
    if !d.take_into(&mut peer) || !peer_tail_ok(&peer) {
        return false;
    }
    let requester_tag = match d.u16() {
        // An accepted connection answers no request.
        Some(t) if role == 0 || t == 0 => t,
        _ => return false,
    };
    let mut peer_id = PeerIdFacts::empty();
    if !decode_peer_id(d, &mut peer_id)
        || peer_verified != u8::from(peer_id.kind != peer_credential::NONE)
    {
        return false;
    }
    let mut exporter_ctx = [0u8; 48];
    if !d.take_into(&mut exporter_ctx) {
        return false;
    }
    let (read_epoch, write_epoch) = match (d.u32(), d.u32()) {
        (Some(r), Some(w)) => (r, w),
        _ => return false,
    };
    // The sealed set's epochs: at most CONT_DERIVE_MAX key updates behind.
    let (sealed_read, sealed_write) = match (d.u32(), d.u32()) {
        (Some(r), Some(w))
            if r <= read_epoch
                && w <= write_epoch
                && read_epoch - r <= CONT_DERIVE_MAX
                && write_epoch - w <= CONT_DERIVE_MAX =>
        {
            (r, w)
        }
        _ => return false,
    };
    let (read_seq, write_seq) = match (d.u64(), d.u64()) {
        (Some(r), Some(w)) => (r, w),
        _ => return false,
    };
    let key_update = match d.u8() {
        Some(k) if k <= 3 => k,
        _ => return false,
    };
    // close_notify: bit 0 our own close_notify, bit 1 the peer's, bit 2 its
    // transport FIN, bit 3 our transport close forwarded (only after bit 0).
    let close_notify = match d.u8() {
        Some(c) if c & !0x0F == 0 && (c & 8 == 0 || c & 1 != 0) => c,
        _ => return false,
    };
    // pending_alert, ticket: only the empty state is a representable one.
    if d.u8() != Some(0) || d.u8() != Some(0) {
        return false;
    }
    let (delivered_in, emitted_out, out_bytes, consumer_cursor) =
        match (d.u64(), d.u64(), d.u64(), d.u64()) {
            (Some(a), Some(b), Some(c), Some(k)) => (a, b, c, k),
            _ => return false,
        };
    let (cursor_at, in_bytes) = match (d.u64(), d.u64()) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    let (recv_expected, recv_len) = match (d.u32(), d.u32()) {
        (Some(a), Some(b)) if b as usize <= RECV_BUF_SIZE => (a, b),
        _ => return false,
    };
    let retx_base_seq = match d.u32() {
        Some(v) => v,
        None => return false,
    };
    let retx_anchored = match d.u8() {
        Some(v) if v <= 1 => v == 1,
        _ => return false,
    };
    let retx_len = match d.u16() {
        Some(n) if n as usize <= RETX_BUF_SIZE => n,
        _ => return false,
    };
    let sealed_len = match d.u16() {
        Some(n) if n as usize == TLS_SEALED_LEN => n as usize,
        _ => return false,
    };
    let (deliv_count, deliv_len) = match (d.u8(), d.u32()) {
        (Some(c), Some(l)) if c <= CONT_REDELIVER_COUNT && l as usize <= CONT_REDELIVER_MAX => {
            (c, l as usize)
        }
        _ => return false,
    };
    // Every variable range must be present, and nothing may follow.
    if d.remaining() != recv_len as usize + retx_len as usize + deliv_len + sealed_len {
        return false;
    }
    let recv_p = match d.take(recv_len as usize) {
        Some(p) => p,
        None => return false,
    };
    let retx_p = match d.take(retx_len as usize) {
        Some(p) => p,
        None => return false,
    };
    let deliv_p = match d.take(deliv_len) {
        Some(p) => p,
        None => return false,
    };
    // The deliveries tile their range exactly, each a record's plaintext.
    {
        let dv = core::slice::from_raw_parts(deliv_p, deliv_len);
        let (mut at, mut n) = (0usize, 0u8);
        while at < dv.len() {
            if at + 2 > dv.len() {
                return false;
            }
            let l = usize::from(u16::from_le_bytes([dv[at], dv[at + 1]]));
            if l > MAX_PLAINTEXT || at + 2 + l > dv.len() {
                return false;
            }
            at += 2 + l;
            n += 1;
        }
        if n != deliv_count {
            return false;
        }
    }
    let sealed_p = match d.take(sealed_len) {
        Some(p) => p,
        None => return false,
    };
    let sealed = core::slice::from_raw_parts(sealed_p, sealed_len);
    let aad = ckpt_aad(flow, epoch, sealed_read, sealed_write);
    if !open_secret_set(s, flow, epoch, &aad, sealed, &mut ck.secrets) {
        return false;
    }
    // Resumed at or past where it was sealed, never before: in the sealed
    // epoch the sequences are floors; a later epoch starts at zero.
    if (read_epoch == sealed_read && read_seq < ck.secrets.read_seq_floor)
        || (write_epoch == sealed_write && write_seq < ck.secrets.write_seq_floor)
    {
        ck.secrets.wipe();
        return false;
    }
    // The suite's key length must be what the sealed set carries.
    let cs = match CipherSuite::from_id(suite) {
        Some(cs) => cs,
        None => return false,
    };
    let suite_kl = cs.key_len() as u8;
    if ck.secrets.read_key_len != suite_kl
        || ck.secrets.write_key_len != suite_kl
        || ck.secrets.hash_len as usize != cs.hash_len()
    {
        ck.secrets.wipe();
        return false;
    }
    // KeyUpdates the record is past its seal by: each derived here, in
    // order, as the primary derived it (RFC 8446 §7.2).
    let mut k = sealed_read;
    while k < read_epoch {
        ck.secrets.advance(cs, role == 1, true);
        k += 1;
    }
    let mut k = sealed_write;
    while k < write_epoch {
        ck.secrets.advance(cs, role == 1, false);
        k += 1;
    }
    ck.suite = suite;
    ck.is_server = role == 1;
    ck.conn_id = conn_id;
    ck.alpn = alpn;
    ck.alpn_len = alpn_len;
    ck.sni = sni;
    ck.sni_len = sni_len;
    ck.sni_is_ip = sni_is_ip;
    ck.peer_verified = peer_verified;
    ck.peer_profile = peer_profile;
    ck.peer = peer;
    ck.requester_tag = requester_tag;
    ck.peer_id = peer_id;
    ck.exporter_ctx = exporter_ctx;
    ck.read_epoch = read_epoch;
    ck.write_epoch = write_epoch;
    ck.read_seq = read_seq;
    ck.write_seq = write_seq;
    ck.key_update = key_update;
    ck.close_notify = close_notify;
    ck.delivered_in = delivered_in;
    ck.emitted_out = emitted_out;
    ck.out_bytes = out_bytes;
    ck.consumer_cursor = consumer_cursor;
    ck.cursor_at = cursor_at;
    ck.in_bytes = in_bytes;
    ck.recv_expected = recv_expected;
    ck.recv_len = recv_len;
    core::ptr::copy_nonoverlapping(recv_p, ck.recv.as_mut_ptr(), recv_len as usize);
    ck.retx_base_seq = retx_base_seq;
    ck.retx_anchored = retx_anchored;
    ck.retx_len = retx_len;
    core::ptr::copy_nonoverlapping(retx_p, ck.retx.as_mut_ptr(), retx_len as usize);
    ck.deliv_count = deliv_count;
    ck.deliv_len = deliv_len as u32;
    core::ptr::copy_nonoverlapping(deliv_p, ck.deliv.as_mut_ptr(), deliv_len);
    true
}

// ── Lookup ──────────────────────────────────────────────────────────

/// The live session a flow id names: one bound to it, else — for an
/// id whose bytes 2..16 are zero — the unbound session on the
/// connection id in bytes 0..2.
fn find_session_by_flow(s: &TlsState, flow: &[u8]) -> i32 {
    if flow.len() != sc::FLOW_ID_BYTES {
        return -1;
    }
    let mut i = 0;
    while i < s.sessions.len() {
        let sess = &s.sessions[i];
        if sess.state != SessionState::Idle
            && sess.cont.flow_bound
            && flow_eq(&sess.cont.flow_id, flow)
        {
            return i as i32;
        }
        i += 1;
    }
    let mut k = 2;
    while k < sc::FLOW_ID_BYTES {
        if flow[k] != 0 {
            return -1;
        }
        k += 1;
    }
    let conn_id = u16::from_le_bytes([flow[0], flow[1]]);
    let si = find_session_by_conn_id(s, conn_id);
    if si >= 0 && !s.sessions[si as usize].cont.flow_bound {
        si
    } else {
        -1
    }
}

fn find_shadow(s: &TlsState, flow: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TLS_SHADOWS {
        if s.shadows[i].phase != ShadowPhase::Idle && flow_eq(&s.shadows[i].flow_id, flow) {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn free_shadow(s: &TlsState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TLS_SHADOWS {
        if s.shadows[i].phase == ShadowPhase::Idle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Bind a live session to the command's flow and epoch on first
/// contact; afterwards the epoch must match exactly.
fn session_epoch_ok(sess: &mut TlsSession, flow: &[u8], epoch: u32) -> bool {
    if !sess.cont.flow_bound {
        sess.cont.flow_id.copy_from_slice(flow);
        sess.cont.flow_bound = true;
        sess.cont.epoch = epoch;
        return true;
    }
    // Named as a primary at its epoch: an activation, if it was one, stands.
    let ok = sess.cont.epoch == epoch;
    if ok {
        sess.cont.activated = false;
    }
    ok
}

// ── Frame writers ───────────────────────────────────────────────────

/// Write `s.cont_scratch[..len]` to cont_out whole.
unsafe fn cont_write_scratch(s: &mut TlsState, len: usize) -> bool {
    if s.cont_out < 0 || len > CONT_SCRATCH_SIZE {
        return false;
    }
    let sys = &*s.syscalls;
    let n = (sys.channel_write)(s.cont_out, s.cont_scratch.as_ptr(), len);
    let ok = n as usize == len;
    if !ok {
        s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
    }
    ok
}

/// Frame header for a payload of `len` bytes at `scratch[3..]`.
fn cont_frame_header(scratch: &mut [u8], msg_type: u8, len: usize) {
    scratch[0] = msg_type;
    scratch[1] = len as u8;
    scratch[2] = (len >> 8) as u8;
}

/// `CONTINUITY{record, status, body}` for `flow` at `epoch`.
unsafe fn cont_reply(
    s: &mut TlsState,
    flow: &[u8],
    epoch: u32,
    record: u8,
    status: u8,
    body: &[u8],
) -> bool {
    if s.cont_out < 0 || flow.len() != sc::FLOW_ID_BYTES || body.len() > REPLY_BODY_MAX {
        return false;
    }
    let mut frame = [0u8; REPLY_MAX];
    let plen = sc::CONTINUITY_HEADER_LEN + body.len();
    cont_frame_header(&mut frame, sc::MSG_SC_CONTINUITY, plen);
    let mut e = Enc::new(
        frame.as_mut_ptr().add(sc::FRAME_HDR),
        REPLY_MAX - sc::FRAME_HDR,
    );
    e.bytes(flow);
    e.u32(epoch);
    e.u8(record);
    e.u8(status);
    e.bytes(body);
    let total = sc::FRAME_HDR + plen;
    let sys = &*s.syscalls;
    let n = (sys.channel_write)(s.cont_out, frame.as_ptr(), total);
    let ok = n as usize == total;
    if !ok {
        s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
    }
    ok
}

/// `DELTA_ACK` from a shadow: the horizon it now holds.
unsafe fn cont_delta_ack(s: &mut TlsState, sh: usize) -> bool {
    let (flow, epoch, gen, no) = {
        let sd = &s.shadows[sh];
        (sd.flow_id, sd.epoch, sd.ckpt_gen, sd.delta_no)
    };
    let plen = sc::DELTA_ACK_PAYLOAD_LEN;
    cont_frame_header(&mut s.cont_scratch, sc::CMD_SC_DELTA_ACK, plen);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(sc::FRAME_HDR),
        CONT_SCRATCH_SIZE - sc::FRAME_HDR,
    );
    e.bytes(&flow);
    e.u32(epoch);
    e.u32(gen);
    e.u32(no);
    cont_write_scratch(s, sc::FRAME_HDR + plen)
}

// ── Primary: deltas ─────────────────────────────────────────────────

/// Open a DELTA_APPLY in the scratch for the session's next delta
/// number. The caller fills the payload at `DELTA_PAYLOAD_OFF` and
/// calls `delta_finish`.
unsafe fn delta_begin(s: &mut TlsState, idx: usize, kind: u8) -> u32 {
    let c = &s.sessions[idx].cont;
    let no = c.next_delta;
    let flow = c.flow_id;
    let (epoch, gen, prev) = (c.epoch, c.ckpt_gen, c.last_digest);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(sc::FRAME_HDR),
        CONT_SCRATCH_SIZE - sc::FRAME_HDR,
    );
    e.bytes(&flow);
    e.u32(epoch);
    e.u32(gen);
    e.u32(no);
    e.bytes(&prev);
    e.u8(kind);
    no
}

/// Digest the delta, put it on cont_out and advance the chain. `false`
/// leaves the chain untouched so the caller can retry the same number.
unsafe fn delta_finish(s: &mut TlsState, idx: usize, payload_len: usize) -> bool {
    let plen = sc::DELTA_APPLY_HEADER_LEN + payload_len;
    if payload_len > DELTA_PAYLOAD_MAX {
        return false;
    }
    cont_frame_header(&mut s.cont_scratch, sc::CMD_SC_DELTA_APPLY, plen);
    let mut h = Sha256::new();
    h.update(&s.cont_scratch[sc::FRAME_HDR..sc::FRAME_HDR + plen]);
    let digest = h.finalize();
    if !cont_write_scratch(s, sc::FRAME_HDR + plen) {
        return false;
    }
    let c = &mut s.sessions[idx].cont;
    c.last_digest = digest;
    c.next_delta = c.next_delta.wrapping_add(1);
    c.delta_unacked_bytes = c
        .delta_unacked_bytes
        .saturating_add((sc::FRAME_HDR + plen) as u32);
    true
}

/// The mirror could not carry a transition. From here the primary runs
/// unmirrored, and the standby's shadow is stale from this record on: a
/// takeover onto it would resume at counters the peer has already seen.
/// So the pair is over, and the abort is owed to the coordinator whatever
/// the channel's state — it is the very channel that just refused a delta
/// — so it is marked and sent from the step until it goes.
///
/// Under the strict profile nothing moves until that abort is away: what
/// the horizons hold stays held, and no new record is written or input read
/// (`abandon_blocks`). A coordinator that has not been told the pair is
/// over may still fence and activate the shadow, and records shown to the
/// peer in the meantime are exactly the ones the shadow would then be
/// missing — and would seal again under the same key and sequence.
/// Ordering the abort ahead of them leaves the coordinator no window in
/// which it could believe the shadow current. An abort that cannot leave
/// within its own budget ends the session (`continuity_step`).
unsafe fn mirror_abandon(s: &mut TlsState, idx: usize) {
    mirror_abandon_for(s, idx, sc::ABORT_MIRROR_LOST);
}

/// `mirror_abandon`, naming why (`sc::ABORT_*`), which the abort carries.
unsafe fn mirror_abandon_for(s: &mut TlsState, idx: usize, reason: u8) {
    mirror_lost(s, idx);
    s.sessions[idx].cont.abandon_pending = true;
    s.sessions[idx].cont.abandon_reason = reason;
    // Delivering the abort is a promise of its own, and gets its own
    // budget: a horizon that has just run out must not spend the abort's
    // as well, or the records it is ordered ahead of would go at once.
    s.sessions[idx].cont.horizon_since_ms = 0;
    flush_abandon(s, idx);
}

/// Send the owed abort for an abandoned mirror; answers whether it went.
/// Its departure is what releases the holds.
unsafe fn flush_abandon(s: &mut TlsState, idx: usize) -> bool {
    if !s.sessions[idx].cont.abandon_pending {
        return true;
    }
    let (flow, epoch, reason) = {
        let c = &s.sessions[idx].cont;
        (c.flow_id, c.epoch, c.abandon_reason)
    };
    if cont_reply(s, &flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]) {
        s.sessions[idx].cont.abandon_pending = false;
        release_after_abort(s, idx);
        true
    } else {
        false
    }
}

/// Let go of what the horizons were holding, the pair being over and the
/// coordinator told. Idempotent: a hold already released stays released.
unsafe fn release_after_abort(s: &mut TlsState, idx: usize) {
    let c = &mut s.sessions[idx].cont;
    c.rx_released = c.rx_released || c.rx_hold_delta != 0;
    if c.tx_hold_len != 0 {
        c.tx_hold_mirrored = c.tx_hold_len;
        c.tx_hold_released = true;
    }
}

/// A session in a pairing ends here — failed, closed by the peer, reset by
/// its consumer, or its connection gone (`why`, `sc::END_*`). A shadow of it
/// is of a session that no longer exists, so the coordinator is told the
/// pair is over; best effort, as the slot does not outlive this step. A
/// session whose mirror was abandoned may be behind what the peer saw: that
/// is the abort it owed, by its reason. Any other ended with its connection
/// — the flow is over, which is no loss of the pairing: `CR_ENDED`, after
/// every delta it emitted.
unsafe fn continuity_session_ending(s: &mut TlsState, idx: usize, why: u8) {
    let c = &s.sessions[idx].cont;
    if !c.flow_bound || !(c.mirror || c.cut_pending || c.abandon_pending) {
        return;
    }
    let (flow, epoch) = (c.flow_id, c.epoch);
    if c.abandon_pending {
        let reason = c.abandon_reason;
        let _ = cont_reply(s, &flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
    } else {
        let _ = cont_reply(s, &flow, epoch, sc::CR_ENDED, sc::STATUS_OK, &[why]);
    }
}

unsafe fn mirror_lost(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let msg: &[u8] = b"[tls] continuity mirror lost; connection continues unmirrored";
    dev_log(sys, 2, msg.as_ptr(), msg.len());
    let c = &mut s.sessions[idx].cont;
    c.mirror = false;
    c.cut_pending = false;
    c.rx_hold_pending = false;
    c.rx_owed = false;
    c.write_barrier_pending = false;
    if c.retired_pending {
        cont_wipe(&mut c.retired_write.key);
        cont_wipe(&mut c.retired_write.iv);
        c.retired_pending = false;
    }
}

/// Mirror an outbound record: its ciphertext, write epoch and the
/// sequence number it was sealed under.
unsafe fn mirror_record_out(s: &mut TlsState, idx: usize, rec: *const u8, total: usize) -> u32 {
    let seq = s.sessions[idx].write_keys.seq.wrapping_sub(1);
    // Written already: the horizon's tag for it is the one just popped.
    let out_bytes = s.sessions[idx].wh.through;
    mirror_record_out_at(s, idx, rec, total, seq, out_bytes)
}

/// `mirror_record_out` for a record sealed under write sequence `seq`: a
/// held record is mirrored after later ones may have been sealed.
unsafe fn mirror_record_out_at(
    s: &mut TlsState,
    idx: usize,
    rec: *const u8,
    total: usize,
    seq: u64,
    out_bytes: u64,
) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RECORD_OUT);
    let epoch = s.sessions[idx].write_epoch;
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u32(epoch);
    e.u64(seq);
    e.u16(total as u16);
    e.raw(rec, total);
    e.u64(out_bytes);
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Retain an emitted record for retransmission. The window's base names
/// the sequence of its first byte, so a record the window cannot take
/// empties the window first rather than being skipped: a skipped record
/// would leave every later offset naming the wrong sequence, and a replay
/// would send bytes the peer authenticates under a different record.
///
/// One definition: the primary's window and the shadow's must move
/// identically, or a takeover replays from a window the peer never saw.
fn retx_push_window(buf: &mut [u8], len: &mut u16, base: &mut u32, rec: &[u8]) {
    if rec.len() > buf.len() {
        // Nothing of it can be held: the window restarts after it.
        *base = base
            .wrapping_add(u32::from(*len))
            .wrapping_add(rec.len() as u32);
        *len = 0;
        return;
    }
    if rec.len() > buf.len() - usize::from(*len) {
        *base = base.wrapping_add(u32::from(*len));
        *len = 0;
    }
    let at = usize::from(*len);
    buf[at..at + rec.len()].copy_from_slice(rec);
    *len += rec.len() as u16;
}

/// Whether the window can take a `total`-byte record without dropping
/// bytes it holds. Only an anchored window is held to it: until the
/// transport reports acknowledgements nothing ever frees the window, and a
/// transport that reports none (host sockets) retransmits by itself.
fn retx_room(len: u16, anchored: bool, cap: usize, total: usize) -> bool {
    !anchored || total > cap || usize::from(len) + total <= cap
}

/// Drop retained bytes up to `acked_seq`. Until the first acknowledgement
/// the base counts stream bytes — the offset from the stream's first byte
/// of what the window holds — because the transport names absolute
/// sequences and the window was filled before the first one arrived. The
/// first acknowledgement anchors it by `isn`, the sequence of the stream's
/// first byte, which `ip`'s `MSG_ACK` carries.
fn retx_slide(
    buf: &mut [u8],
    len: &mut u16,
    base: &mut u32,
    anchored: &mut bool,
    acked_seq: u32,
    isn: u32,
) {
    if !*anchored {
        *base = isn.wrapping_add(*base);
        *anchored = true;
    }
    let delta = acked_seq.wrapping_sub(*base);
    if delta == 0 || delta > u32::from(*len) {
        return;
    }
    let d = delta as usize;
    let remain = usize::from(*len) - d;
    buf.copy_within(d..d + remain, 0);
    *len = remain as u16;
    *base = acked_seq;
}

/// Where the first record boundary sits after `d` bytes leave the front of
/// `window` (records pushed whole; its first `head` bytes end a record
/// whose head already left). `RETX_HEAD_UNKNOWN` stays unknown until the
/// window empties, and a window whose headers do not walk becomes unknown.
fn retx_head_after(window: &[u8], head: u16, d: usize) -> u16 {
    if d >= window.len() {
        return 0;
    }
    if head == RETX_HEAD_UNKNOWN {
        return RETX_HEAD_UNKNOWN;
    }
    let head = usize::from(head);
    if d < head {
        return (head - d) as u16;
    }
    let mut at = head;
    while at < d {
        let rl = held_record_len(window, at, window.len());
        if rl == 0 {
            return RETX_HEAD_UNKNOWN;
        }
        at += rl;
    }
    (at - d) as u16
}

/// Records with a byte in the retransmit window — those the peer's
/// transport has not wholly acknowledged — or `None` when its boundaries
/// are not known.
fn retx_records(window: &[u8], head: u16) -> Option<usize> {
    if head == RETX_HEAD_UNKNOWN {
        return None;
    }
    let head = usize::from(head).min(window.len());
    let mut n = usize::from(head > 0);
    let mut at = head;
    while at < window.len() {
        let rl = held_record_len(window, at, window.len());
        if rl == 0 {
            return None;
        }
        n += 1;
        at += rl;
    }
    Some(n)
}

/// Outbound records of session `idx` the canonical record of a strict pair
/// holds: those in the retransmit window and those held for their horizon
/// (`None` when the window's boundaries are not known).
fn strict_tx_records(s: &TlsState, idx: usize) -> Option<usize> {
    let sess = &s.sessions[idx];
    let mut n = retx_records(&sess.retx_buf[..usize::from(sess.retx_len)], sess.retx_head)?;
    let len = usize::from(sess.cont.tx_hold_len);
    let mut at = 0;
    while at < len {
        let rl = held_record_len(&sess.cont.tx_hold, at, len);
        if rl == 0 {
            return None;
        }
        n += 1;
        at += rl;
    }
    Some(n)
}

/// Under a strict pair: may one more outbound record be written or held?
/// Only while the records the peer's transport has not acknowledged, with
/// this one, stay within what the canonical record holds
/// (`sc::STRICT_TX_RECORDS`, its `TS_TXREC_MAX`); otherwise the record waits
/// (`EmitOutcome::Blocked`) and the acknowledgement that slides the window
/// releases it. A peer that acknowledges nothing for `CONT_HORIZON_MS` while
/// the ceiling holds would hold the connection for ever: the pair is
/// abandoned then and the connection goes on unmirrored
/// (`txrec_cap_abandoned`).
unsafe fn strict_tx_room(s: &mut TlsState, idx: usize) -> bool {
    if matches!(strict_tx_records(s, idx), Some(n) if n < sc::STRICT_TX_RECORDS) {
        s.sessions[idx].cont.txrec_since_ms = 0;
        return true;
    }
    let now = dev_millis(&*s.syscalls).max(1);
    let since = s.sessions[idx].cont.txrec_since_ms;
    if since == 0 {
        s.sessions[idx].cont.txrec_since_ms = now;
        return false;
    }
    if now.wrapping_sub(since) <= CONT_HORIZON_MS {
        return false;
    }
    let sys = &*s.syscalls;
    let msg: &[u8] =
        b"[tls] continuity record ceiling held with no acknowledgement; mirror abandoned";
    dev_log(sys, 2, msg.as_ptr(), msg.len());
    s.txrec_cap_abandoned = s.txrec_cap_abandoned.wrapping_add(1);
    s.sessions[idx].cont.txrec_since_ms = 0;
    mirror_abandon_for(s, idx, sc::ABORT_TXREC_CAP);
    false
}

/// Whether `cont_out` — empty: this runs at `module_new` — holds what a
/// strict mirror may leave on it (`CONT_OUT_NEED`). A ring the kernel
/// measures smaller (a mailbox measures 0) is refused strict pairing; an
/// unwired port, or a channel the kernel does not measure, claims nothing
/// and is not.
unsafe fn cont_out_admits_strict(sys: &SyscallTable, ch: i32) -> bool {
    if ch < 0 {
        return true;
    }
    let mut free = [0u8; 4];
    if dev_channel_ioctl(sys, ch, IOCTL_WRITABLE, free.as_mut_ptr(), 4) < 0 {
        return true;
    }
    u32::from_le_bytes(free) as usize >= CONT_OUT_NEED
}

/// Mirror the retransmit window sliding on a transport acknowledgement.
unsafe fn mirror_retx_ack(s: &mut TlsState, idx: usize, acked_seq: u32, isn: u32) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RETX_ACK);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u32(acked_seq);
    e.u32(isn);
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Mirror inbound bytes that do not yet form a record, under the strict
/// profile, so a takeover between two records holds the head of the next
/// one rather than misframing everything after it.
unsafe fn mirror_recv_bytes(s: &mut TlsState, idx: usize) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RECV_BYTES);
    let scratch: *mut u8 = s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF);
    let sess = &s.sessions[idx];
    let mut e = Enc::new(scratch, DELTA_PAYLOAD_MAX);
    e.u32(sess.recv_len as u32);
    e.raw(sess.recv_buf.as_ptr(), sess.recv_len);
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// After bytes were appended to a session's inbound buffer.
unsafe fn continuity_after_recv_append(s: &mut TlsState, idx: usize) {
    let (mirror, strict) = {
        let c = &s.sessions[idx].cont;
        (c.mirror, c.strict())
    };
    if mirror && strict && mirror_recv_bytes(s, idx) == 0 {
        mirror_abandon(s, idx);
    }
}

/// After the transport acknowledged the session's stream up to `acked_seq`.
unsafe fn continuity_after_retx_ack(s: &mut TlsState, idx: usize, acked_seq: u32, isn: u32) {
    if s.sessions[idx].cont.mirror && mirror_retx_ack(s, idx, acked_seq, isn) == 0 {
        mirror_abandon(s, idx);
    }
}

/// Mirror the consumption of the inbound record at the head of
/// recv_buf (`rec_len` payload bytes), planned profile: the read sequence
/// it advances to and the partial record left behind it.
unsafe fn mirror_record_in(s: &mut TlsState, idx: usize, rec_len: usize) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RECORD_IN);
    let scratch: *mut u8 = s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF);
    let sess = &s.sessions[idx];
    let consumed = RECORD_HEADER_LEN + rec_len;
    if consumed > sess.recv_len {
        return 0;
    }
    let partial = sess.recv_len - consumed;
    let mut e = Enc::new(scratch, DELTA_PAYLOAD_MAX);
    e.u32(sess.read_epoch);
    e.u64(sess.read_keys.seq.wrapping_add(1));
    e.u32(sess.recv_expected as u32);
    e.u32(partial as u32);
    e.raw(sess.recv_buf.as_ptr().add(consumed), partial);
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Mirror the consumption of the record just opened, strict profile:
/// sequence and partial record as `mirror_record_in` (the record already
/// out of recv_buf, the read sequence already past it), then its inner
/// type and plaintext from `record_scratch`.
unsafe fn mirror_record_in_plain(s: &mut TlsState, idx: usize, ctype: u8, pt_len: usize) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RECORD_IN);
    let scratch: *mut u8 = s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF);
    let plain = core::ptr::addr_of!(s.record_scratch) as *const u8;
    let sess = &s.sessions[idx];
    let mut e = Enc::new(scratch, DELTA_PAYLOAD_MAX);
    e.u32(sess.read_epoch);
    e.u64(sess.read_keys.seq);
    e.u32(sess.recv_expected as u32);
    e.u32(sess.recv_len as u32);
    e.raw(sess.recv_buf.as_ptr(), sess.recv_len);
    if pt_len <= DELIV_CARRY_MAX {
        e.u8(ctype);
        e.u16(pt_len as u16);
        e.raw(plain, pt_len);
    } else {
        e.u8(RECORD_IN_NOT_CARRIED);
        e.u16(0);
    }
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Mirror a key rotation: the sealed secret set after it and the
/// epoch of the rotated direction.
unsafe fn mirror_key_update(s: &mut TlsState, idx: usize, direction: u8) -> u32 {
    let (flow, epoch, dir_epoch) = {
        let sess = &s.sessions[idx];
        let de = if direction == DELTA_DIR_WRITE {
            sess.write_epoch
        } else {
            sess.read_epoch
        };
        (sess.cont.flow_id, sess.cont.epoch, de)
    };
    let aad = ku_aad(&flow, epoch, direction, dir_epoch);
    let mut sealed = [0u8; TLS_SEALED_LEN];
    if !seal_secret_set(s, idx, &aad, &mut sealed) {
        return 0;
    }
    let no = delta_begin(s, idx, sc::DELTA_TLS_KEY_UPDATE);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u8(direction);
    e.u32(dir_epoch);
    e.u16(TLS_SEALED_LEN as u16);
    e.bytes(&sealed);
    cont_wipe(&mut sealed);
    if direction == DELTA_DIR_READ {
        // `[owed:1]`: the peer's update asked for ours, which is owed until
        // the write rotation's own delta.
        e.u8(u8::from(s.sessions[idx].cont.ku_answer_owed));
    }
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Outcome of handing a sealed record toward cipher_out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EmitOutcome {
    /// On cipher_out and retained for retransmission.
    Sent,
    /// Held for its send horizon; released by the DELTA_ACK.
    Held,
    /// Not written. The AEAD sequence has moved, so the caller fails
    /// the session.
    Failed,
    /// Not written: `cipher_out` had no room, or an earlier record of the
    /// session is still waiting for it. Nothing is on the wire, so a
    /// caller that keeps the record and writes it first stays in step.
    Blocked,
}

/// Write an already-sealed record to cipher_out, retaining it for
/// retransmission, under the session's continuity discipline.
unsafe fn emit_record(s: &mut TlsState, idx: usize, rec: *const u8, total: usize) -> EmitOutcome {
    if total > WIRE_RECORD_MAX {
        return EmitOutcome::Failed;
    }
    let (mirror, strict) = {
        let c = &s.sessions[idx].cont;
        (c.mirror, c.strict())
    };
    if mirror && strict {
        if !strict_tx_room(s, idx) {
            return EmitOutcome::Blocked;
        }
        {
            // What is held goes into the window when it is released: the
            // window must have room for it, and for this record, now.
            let sess = &s.sessions[idx];
            let held = usize::from(sess.cont.tx_hold_len);
            let busy = sess.retx_len.saturating_add(held as u16);
            if !retx_room(busy, sess.retx_seq_anchored, RETX_BUF_SIZE, total) {
                return EmitOutcome::Blocked;
            }
            let c = &mut s.sessions[idx].cont;
            let len = c.tx_hold_len as usize;
            if c.tx_hold_released || total > TX_HOLD_SIZE - len {
                return EmitOutcome::Failed;
            }
            core::ptr::copy_nonoverlapping(rec, c.tx_hold.as_mut_ptr().add(len), total);
            c.tx_hold_len = (len + total) as u16;
        }
        // In the wire order now, behind the hold.
        s.sessions[idx].wh.push();
        mirror_tx_hold(s, idx);
        return EmitOutcome::Held;
    }
    // A record may not overtake the session's stalled one.
    if tx_stalled(s, idx) {
        return EmitOutcome::Blocked;
    }
    s.sessions[idx].wh.push();
    if !write_record_now(s, idx, rec, total) {
        s.sessions[idx].wh.unpush();
        return EmitOutcome::Blocked;
    }
    if mirror && mirror_record_out(s, idx, rec, total) == 0 {
        mirror_abandon(s, idx);
    }
    EmitOutcome::Sent
}

/// Whether session `idx` has a sealed record waiting for `cipher_out`.
fn tx_stalled(s: &TlsState, idx: usize) -> bool {
    s.tx_stall_len > 0 && s.tx_stall_idx as usize == idx
}

/// Write the sealed record `cipher_out` last had no room for. True once
/// nothing is stalled. A stalled session that is no longer ready drops
/// the record and the unread rest of its clear frame.
unsafe fn flush_tx_stall(s: &mut TlsState) -> bool {
    let n = s.tx_stall_len as usize;
    if n == 0 {
        return true;
    }
    let idx = s.tx_stall_idx as usize;
    if !session_movable(&s.sessions[idx]) {
        s.tx_stall_len = 0;
        let left = s.clear_left as usize;
        s.clear_left = 0;
        if left > 0 {
            tls_discard(&*s.syscalls, s.clear_in, left);
        }
        return true;
    }
    let rec = s.tx_stall.as_ptr();
    if s.sessions[idx].cont.mirror && s.sessions[idx].cont.strict() {
        // Under the strict horizon a stalled record joins the hold behind
        // the records sealed before it: written now it would overtake them
        // on the wire, and the peer would open it under the wrong sequence.
        return match emit_record(s, idx, rec, n) {
            EmitOutcome::Held | EmitOutcome::Sent => {
                s.tx_stall_len = 0;
                true
            }
            EmitOutcome::Blocked => false,
            EmitOutcome::Failed => {
                s.tx_stall_len = 0;
                s.sessions[idx].state = SessionState::Error;
                true
            }
        };
    }
    s.sessions[idx].wh.push();
    if !write_record_now(s, idx, rec, n) {
        s.sessions[idx].wh.unpush();
        return false;
    }
    s.tx_stall_len = 0;
    if s.sessions[idx].cont.mirror && mirror_record_out(s, idx, rec, n) == 0 {
        mirror_abandon(s, idx);
    }
    true
}

/// The write: cipher_out, byte accounting, retention. Refused, like a
/// full `cipher_out`, while the retransmit window has no room for the
/// record: a record the window could not hold could never be resent, and
/// `ip` keeps no copy of it. Refused too while an abandoned strict mirror's
/// abort is still owed (`abandon_blocks`).
unsafe fn write_record_now(s: &mut TlsState, idx: usize, rec: *const u8, total: usize) -> bool {
    {
        let sess = &s.sessions[idx];
        if sess.cont.abandon_blocks() {
            return false;
        }
        if !retx_room(sess.retx_len, sess.retx_seq_anchored, RETX_BUF_SIZE, total) {
            s.retx_full = s.retx_full.wrapping_add(1);
            return false;
        }
    }
    let conn_id = s.sessions[idx].conn_id;
    let sys = &*s.syscalls;
    let sent = tls_write_frame(
        sys,
        s.cipher_out,
        NET_CMD_SEND,
        conn_id,
        rec,
        total as u16,
        &mut s.net_scratch,
    );
    if !sent {
        s.frame_write_dropped = s.frame_write_dropped.wrapping_add(1);
        return false;
    }
    s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(4 + total as u32);
    retx_push(&mut s.sessions[idx], rec, total as u16);
    s.sessions[idx].wh.pop();
    let c = &mut s.sessions[idx].cont;
    c.emitted_out = c.emitted_out.wrapping_add(1);
    true
}

/// Length of the record at `off` in a hold, from its header; 0 when the
/// bytes there do not describe one.
fn held_record_len(hold: &[u8], off: usize, len: usize) -> usize {
    if off + RECORD_HEADER_LEN > len {
        return 0;
    }
    let total = RECORD_HEADER_LEN + (((hold[off + 3] as usize) << 8) | hold[off + 4] as usize);
    if off + total > len {
        0
    } else {
        total
    }
}

/// Carry every held record not yet mirrored in its own RECORD_OUT delta.
unsafe fn mirror_tx_hold(s: &mut TlsState, idx: usize) {
    loop {
        let (off, len) = {
            let c = &s.sessions[idx].cont;
            (c.tx_hold_mirrored as usize, c.tx_hold_len as usize)
        };
        if off >= len {
            return;
        }
        let total = held_record_len(&s.sessions[idx].cont.tx_hold, off, len);
        if total == 0 {
            return;
        }
        // Its write sequence: one per record held from here to the hold's
        // end, counted back from the next to be sealed.
        let mut after = 0u64;
        let mut at = off;
        while at < len {
            let t = held_record_len(&s.sessions[idx].cont.tx_hold, at, len);
            if t == 0 {
                break;
            }
            after += 1;
            at += t;
        }
        let seq = s.sessions[idx].write_keys.seq.wrapping_sub(after);
        // Its horizon tag: the hold is the tail of the wire order, so the
        // record `after` from the end of the hold is that far from the
        // queue's end.
        let out_bytes = s.sessions[idx].wh.tag_from_end(after);
        let mut local = [0u8; WIRE_RECORD_MAX];
        local[..total].copy_from_slice(&s.sessions[idx].cont.tx_hold[off..off + total]);
        let no = mirror_record_out_at(s, idx, local.as_ptr(), total, seq, out_bytes);
        cont_wipe(&mut local[..total]);
        if no == 0 {
            return;
        }
        let c = &mut s.sessions[idx].cont;
        c.tx_hold_mirrored = (off + total) as u16;
        c.tx_hold_delta = no;
    }
}

/// Put held records on the wire once their horizon is confirmed, in
/// order; a bounced write keeps the rest for the next step.
unsafe fn release_tx_hold(s: &mut TlsState, idx: usize) {
    if !s.sessions[idx].cont.tx_hold_released {
        return;
    }
    loop {
        let len = s.sessions[idx].cont.tx_hold_len as usize;
        if len == 0 {
            let c = &mut s.sessions[idx].cont;
            c.tx_hold_mirrored = 0;
            c.tx_hold_delta = 0;
            c.tx_hold_released = false;
            return;
        }
        let total = held_record_len(&s.sessions[idx].cont.tx_hold, 0, len);
        if total == 0 {
            // Not a record: the hold is unusable and is dropped, and with
            // it the horizon's account of what is on the wire.
            s.sessions[idx].wh.lost = true;
            let c = &mut s.sessions[idx].cont;
            cont_wipe(&mut c.tx_hold[..len]);
            c.tx_hold_len = 0;
            continue;
        }
        let mut local = [0u8; WIRE_RECORD_MAX];
        local[..total].copy_from_slice(&s.sessions[idx].cont.tx_hold[..total]);
        let ok = write_record_now(s, idx, local.as_ptr(), total);
        cont_wipe(&mut local[..total]);
        if !ok {
            return;
        }
        let c = &mut s.sessions[idx].cont;
        let remain = len - total;
        core::ptr::copy(
            c.tx_hold.as_ptr().add(total),
            c.tx_hold.as_mut_ptr(),
            remain,
        );
        cont_wipe(&mut c.tx_hold[remain..len]);
        c.tx_hold_len = remain as u16;
        c.tx_hold_mirrored = c.tx_hold_mirrored.saturating_sub(total as u16);
    }
}

/// Advance the session's acknowledged horizon and release what it covers.
unsafe fn apply_delta_ack(s: &mut TlsState, idx: usize, delta_no: u32) {
    {
        let c = &mut s.sessions[idx].cont;
        if delta_no > c.acked_delta {
            c.acked_delta = delta_no;
            // The standby answered: the budget measures a standby that has
            // stopped answering, not a connection busy for longer than it.
            // Under sustained traffic one hold follows the next with no step
            // between them free of a horizon, and a budget counted from the
            // first would abandon a healthy pair.
            if c.mirror && !c.abandon_pending && !c.cut_pending {
                c.horizon_since_ms = 0;
            }
        }
        if c.acked_delta.wrapping_add(1) >= c.next_delta {
            c.delta_unacked_bytes = 0;
        }
        let acked = c.acked_delta;
        if c.rx_hold_pending && c.rx_hold_delta <= acked {
            c.rx_hold_pending = false;
            c.rx_released = true;
        }
        if c.write_barrier_pending && c.write_barrier_delta <= acked {
            c.write_barrier_pending = false;
            if c.retired_pending {
                cont_wipe(&mut c.retired_write.key);
                cont_wipe(&mut c.retired_write.iv);
                c.retired_pending = false;
            }
        }
        // The hold waits for the barrier as well as for its own records: the
        // KeyUpdate record is sealed in the old epoch and acknowledged on its
        // own, but once the peer has it the peer reads in the new one, and a
        // standby that holds the record without the rotation behind it would
        // answer in an epoch the peer has left.
        if c.tx_hold_len != 0
            && c.tx_hold_mirrored == c.tx_hold_len
            && c.tx_hold_delta <= acked
            && !c.write_barrier_pending
        {
            c.tx_hold_released = true;
        }
    }
    release_tx_hold(s, idx);
}

/// The record at the head of recv_buf (`rec_len` payload bytes) may be
/// consumed now. `false` leaves it in place for a later step. Under the
/// strict profile it is decrypted first and mirrored after
/// (`continuity_after_decrypt`): here it only waits for the session's one
/// inbound horizon, and for its send horizon and barrier, to be free.
unsafe fn continuity_rx_gate(s: &mut TlsState, idx: usize, rec_len: usize) -> bool {
    let (mirror, strict, released, pending, tx_busy, barrier) = {
        let c = &s.sessions[idx].cont;
        (
            c.mirror,
            c.strict(),
            c.rx_released,
            c.rx_held(),
            c.tx_hold_len != 0,
            c.write_barrier_pending,
        )
    };
    if !mirror {
        return true;
    }
    if strict {
        s.sessions[idx].cont.rx_released = false;
        // One horizon in flight per session: a key-update answer to this
        // record needs the hold slot free.
        if pending || tx_busy || barrier {
            return false;
        }
        return redelivery_room(s, idx, rec_len);
    }
    if released {
        s.sessions[idx].cont.rx_released = false;
        return true;
    }
    if pending {
        return false;
    }
    if mirror_record_in(s, idx, rec_len) == 0 {
        mirror_abandon(s, idx);
    }
    true
}

/// Under a strict pair whose consumer acknowledges (`delivery_ack`): may
/// the record at the head of recv_buf (`rec_len` payload bytes) be opened
/// and handed up? Only while what stands unconsumed with it fits what the
/// standby holds for a takeover to redeliver — fewer than
/// `CONT_REDELIVER_COUNT` records, and their entries with this one's within
/// `CONT_REDELIVER_MAX` — and the consumption that made room has been
/// mirrored ahead of it. Otherwise the record stays in recv_buf and the
/// back-pressure reaches the TCP window. A consumer that cannot free room
/// (a message of its own spanning more records than the caps) would hold
/// the connection for ever: when no consumption has come for
/// `CONT_HORIZON_MS` while the caps hold, the pair is abandoned and the
/// connection goes on unmirrored (`redeliver_cap_abandoned`).
unsafe fn redelivery_room(s: &mut TlsState, idx: usize, rec_len: usize) -> bool {
    // Without `delivery_ack` a delivery is consumed when it is handed up,
    // and its consumption is mirrored here too, before the next is opened:
    // the standby never holds more deliveries than the caps either way.
    mirror_consumed(s, idx);
    let (fits, told) = {
        let c = &s.sessions[idx].cont;
        // The record's plaintext is at most its payload less the tag and
        // the inner content type.
        let pt_max = rec_len.saturating_sub(17);
        let n = usize::from(c.pend_n) + 1;
        let fits = n <= usize::from(CONT_REDELIVER_COUNT)
            && 2 * n + c.pend_bytes as usize + pt_max <= CONT_REDELIVER_MAX;
        (fits, c.consumed == c.consumed_told)
    };
    if fits && told {
        s.sessions[idx].cont.cap_since_ms = 0;
        return true;
    }
    if !told {
        // The consumption is still to leave `cont_out`: the horizon budget
        // covers a standby that stopped answering.
        return false;
    }
    let now = dev_millis(&*s.syscalls).max(1);
    let since = s.sessions[idx].cont.cap_since_ms;
    if since == 0 {
        s.sessions[idx].cont.cap_since_ms = now;
        return false;
    }
    if now.wrapping_sub(since) <= CONT_HORIZON_MS {
        return false;
    }
    let sys = &*s.syscalls;
    let msg: &[u8] = b"[tls] continuity redelivery caps held with no consumption; mirror abandoned";
    dev_log(sys, 2, msg.as_ptr(), msg.len());
    s.redeliver_cap_abandoned = s.redeliver_cap_abandoned.wrapping_add(1);
    s.sessions[idx].cont.cap_since_ms = 0;
    mirror_abandon_for(s, idx, sc::ABORT_REDELIVER_CAP);
    false
}

/// Under the strict profile, after the record at the head of recv_buf was
/// consumed and opened (`ctype` its inner type, `pt_len` bytes of
/// plaintext in `record_scratch`): mirror the consumption with what it
/// opened to. True when the plaintext must stay where it is, undelivered,
/// until the RECORD_IN is acknowledged. A RECORD_IN `cont_out` refuses is
/// owed and offered again each step; for a record that delivers nothing a
/// refusal ends the pair.
unsafe fn continuity_after_decrypt(s: &mut TlsState, idx: usize, ctype: u8, pt_len: usize) -> bool {
    let (mirror, strict) = {
        let c = &s.sessions[idx].cont;
        (c.mirror, c.strict())
    };
    if !mirror || !strict {
        return false;
    }
    // What the record hands up: application data before the peer's
    // close_notify (RFC 8446 §6.1: anything after it is ignored).
    let delivers = ctype == CT_APPLICATION_DATA
        && pt_len > 0
        && s.sessions[idx].peer_closed & PEER_CLOSE_NOTIFY == 0;
    let no = mirror_record_in_plain(s, idx, ctype, pt_len);
    if no == 0 {
        if delivers {
            let c = &mut s.sessions[idx].cont;
            c.rx_owed = true;
            c.rx_owed_type = ctype;
            c.rx_owed_len = pt_len as u16;
            return true;
        }
        mirror_abandon(s, idx);
        return false;
    }
    let c = &mut s.sessions[idx].cont;
    c.rx_hold_pending = true;
    c.rx_hold_delta = no;
    delivers
}

/// Offer an owed RECORD_IN again.
unsafe fn continuity_rx_owed(s: &mut TlsState, idx: usize) {
    let (ctype, len) = {
        let c = &s.sessions[idx].cont;
        if !c.rx_owed {
            return;
        }
        (c.rx_owed_type, c.rx_owed_len as usize)
    };
    let no = mirror_record_in_plain(s, idx, ctype, len);
    if no != 0 {
        let c = &mut s.sessions[idx].cont;
        c.rx_owed = false;
        c.rx_hold_pending = true;
        c.rx_hold_delta = no;
    }
}

/// A record's `len` bytes of plaintext reached clear_out. Without
/// `delivery_ack` that is also its consumption; with it the record waits,
/// by where it ends, for the consumer's acknowledgement to reach that byte.
fn note_delivered(s: &mut TlsState, idx: usize, len: usize) {
    let worker_acks = s.delivery_ack != 0;
    let c = &mut s.sessions[idx].cont;
    c.delivered_in = c.delivered_in.wrapping_add(1);
    c.handed_bytes = c.handed_bytes.wrapping_add(len as u64);
    if !worker_acks {
        // Consumed as handed up: the consumer stands at its end.
        c.consumed = c.delivered_in;
        c.cursor_at = c.handed_bytes;
        return;
    }
    if usize::from(c.pend_n) == PEND_MAX {
        // Only an unmirrored session gets here (a strict pair stops at
        // `CONT_REDELIVER_COUNT`): the oldest is counted consumed.
        c.pend_bytes -= u32::from(c.pend_len[0]);
        c.pend_end.copy_within(1.., 0);
        c.pend_len.copy_within(1.., 0);
        c.pend_n -= 1;
        c.consumed = c.consumed.wrapping_add(1);
    }
    let n = usize::from(c.pend_n);
    c.pend_end[n] = c.handed_bytes;
    c.pend_len[n] = len as u16;
    c.pend_n += 1;
    c.pend_bytes += len as u32;
}

/// The clear-side consumer has consumed the stream's first `in_bytes`
/// clear bytes and stands at `cursor` there (`CMD_DELIVERED`, under
/// `delivery_ack`). The records whose plaintext ends at or before that byte
/// are consumed; one it falls inside is not, and a takeover redelivers it
/// from that byte. An acknowledgement behind the last, or past what was
/// handed up (with the part of a record still going out), is ignored.
fn note_consumed(s: &mut TlsState, idx: usize, cursor: u64, in_bytes: u64) {
    let partial = if s.clear_pending_len > 0 && s.clear_pending_idx as usize == idx {
        s.clear_pending_off as u64
    } else {
        0
    };
    let c = &mut s.sessions[idx].cont;
    if in_bytes < c.cursor_at || in_bytes > c.handed_bytes.wrapping_add(partial) {
        return;
    }
    let mut k = 0usize;
    while k < usize::from(c.pend_n) && c.pend_end[k] <= in_bytes {
        c.pend_bytes -= u32::from(c.pend_len[k]);
        k += 1;
    }
    if k > 0 {
        c.pend_end.copy_within(k.., 0);
        c.pend_len.copy_within(k.., 0);
        c.pend_n -= k as u8;
        c.consumed = c.consumed.wrapping_add(k as u64);
        c.cap_since_ms = 0;
    }
    c.consumer_cursor = cursor;
    c.cursor_at = in_bytes;
}

/// Mirror what the consumer has consumed since it was last mirrored.
unsafe fn mirror_consumed(s: &mut TlsState, idx: usize) {
    let (mirror, strict, consumed, told, cursor, cursor_told, at, at_told) = {
        let c = &s.sessions[idx].cont;
        (
            c.mirror,
            c.strict(),
            c.consumed,
            c.consumed_told,
            c.consumer_cursor,
            c.cursor_told,
            c.cursor_at,
            c.cursor_at_told,
        )
    };
    if !mirror || !strict || (consumed == told && cursor == cursor_told && at == at_told) {
        return;
    }
    let _ = delta_begin(s, idx, DELTA_TLS_DELIVERED);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u64(consumed);
    e.u64(cursor);
    e.u64(at);
    if e.ok && delta_finish(s, idx, e.pos) {
        let c = &mut s.sessions[idx].cont;
        c.consumed_told = consumed;
        c.cursor_told = cursor;
        c.cursor_at_told = at;
    }
}

/// After `rotate_traffic_keys`: mirror the new secret set. A write-side
/// rotation in the strict profile is a barrier — nothing is emitted in
/// the new epoch until the delta is acknowledged.
unsafe fn continuity_after_key_rotation(s: &mut TlsState, idx: usize, inbound: bool) {
    if !s.sessions[idx].cont.mirror {
        let c = &mut s.sessions[idx].cont;
        if c.retired_pending {
            cont_wipe(&mut c.retired_write.key);
            cont_wipe(&mut c.retired_write.iv);
            c.retired_pending = false;
        }
        return;
    }
    let dir = if inbound {
        DELTA_DIR_READ
    } else {
        DELTA_DIR_WRITE
    };
    // A held record's RECORD_OUT names the epoch and sequence it was sealed
    // under from the session's current write state, so every record of the
    // retiring epoch must already be mirrored: one the channel refused would
    // be offered later under the new epoch, after this rotation, and the
    // standby would refuse it. The pair ends here instead, in order.
    if !inbound && {
        let c = &s.sessions[idx].cont;
        c.tx_hold_mirrored != c.tx_hold_len
    } {
        mirror_abandon(s, idx);
        return;
    }
    let no = mirror_key_update(s, idx, dir);
    if no == 0 {
        mirror_abandon(s, idx);
        return;
    }
    let c = &mut s.sessions[idx].cont;
    if !inbound && c.strict() {
        c.write_barrier_pending = true;
        c.write_barrier_delta = no;
    } else if c.retired_pending {
        cont_wipe(&mut c.retired_write.key);
        cont_wipe(&mut c.retired_write.iv);
        c.retired_pending = false;
    }
}

/// Retain the write keys about to be rotated out, until the barrier
/// covering their last record is acknowledged.
fn retain_retired_write_keys(sess: &mut TlsSession) {
    let c = &mut sess.cont;
    c.retired_write.key = sess.write_keys.key;
    c.retired_write.iv = sess.write_keys.iv;
    c.retired_write.key_len = sess.write_keys.key_len;
    c.retired_write.seq = sess.write_keys.seq;
    c.retired_pending = true;
}

/// Inputs frozen: a transition of some session is waiting on the
/// standby, or a cut is awaiting its commit.
fn continuity_gate_cipher_in(s: &TlsState) -> bool {
    let mut i = 0;
    while i < s.sessions.len() {
        let c = &s.sessions[i].cont;
        if s.sessions[i].state != SessionState::Idle
            && (c.horizon_outstanding() || c.cut_pending || c.abandon_blocks())
        {
            return true;
        }
        i += 1;
    }
    continuity_cont_out_full(s)
}

/// A strict mirror's deltas must always find room on `cont_out`: a delta
/// the channel refuses ends the pair. Each inbound segment writes one (the
/// partial record as it now stands — up to a whole protected record), so
/// none is read while what was written and not yet acknowledged, and one
/// more at its largest, could exceed what the channel holds. Asked before
/// every frame `cipher_in` gives up, not once a step.
fn continuity_cont_out_full(s: &TlsState) -> bool {
    let mut i = 0;
    while i < s.sessions.len() {
        let c = &s.sessions[i].cont;
        if c.mirror
            && c.strict()
            && c.delta_unacked_bytes as usize + CONT_SCRATCH_SIZE > CONT_OUT_BUDGET
        {
            return true;
        }
        i += 1;
    }
    false
}

/// The clear side is additionally frozen while a session quiesces.
fn continuity_gate_clear_in(s: &TlsState) -> bool {
    let mut i = 0;
    while i < s.sessions.len() {
        let c = &s.sessions[i].cont;
        if s.sessions[i].state != SessionState::Idle
            && (c.horizon_outstanding()
                || c.cut_pending
                || c.quiescing
                || c.ku_answer_owed
                || c.abandon_blocks())
        {
            return true;
        }
        i += 1;
    }
    false
}

// ── Primary: lifecycle handlers ─────────────────────────────────────

/// Zeroize a session's secrets and buffers and free the slot.
unsafe fn retire_session(sess: &mut TlsSession) {
    if let Some(ks) = sess.driver.key_schedule.as_mut() {
        cont_wipe(&mut ks.client_app_secret);
        cont_wipe(&mut ks.server_app_secret);
        cont_wipe(&mut ks.master_secret);
        cont_wipe(&mut ks.handshake_secret);
        cont_wipe(&mut ks.client_hs_secret);
        cont_wipe(&mut ks.server_hs_secret);
    }
    cont_wipe(&mut sess.read_keys.key);
    cont_wipe(&mut sess.read_keys.iv);
    cont_wipe(&mut sess.write_keys.key);
    cont_wipe(&mut sess.write_keys.iv);
    cont_wipe(&mut sess.recv_buf);
    cont_wipe(&mut sess.retx_buf);
    sess.cont.reset();
    sess.reset();
}

unsafe fn handle_pair_prepare(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::PAIR_PREPARE_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let transport = p[20];
    let profile = p[21];
    let digest = &p[22..54];
    let ok_shape = transport == sc::CT_TLS
        && (profile == sc::PROFILE_PLANNED || profile == sc::PROFILE_CRASH_CONTINUOUS)
        && digest_eq(&tls_codec_digest(), digest);
    let mut body = [0u8; 4];
    body[0] = sc::CT_TLS;
    body[1] = profile;
    body[2..4].copy_from_slice(&NO_SHADOW_SLOT.to_le_bytes());
    if !ok_shape {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_CORRUPT,
            &body,
        );
        return;
    }
    // The primary half: the live session learns its profile and epoch.
    let si = find_session_by_flow(s, flow);
    if si >= 0 {
        let idx = si as usize;
        if !session_epoch_ok(&mut s.sessions[idx], flow, epoch) {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_STALE_EPOCH,
                &body,
            );
            return;
        }
        if profile == sc::PROFILE_CRASH_CONTINUOUS && !s.cont_out_strict_ok {
            // The graph's `cont_out` is smaller than what a strict mirror
            // may leave on it: a delta it refused would end the pair.
            let sys = &*s.syscalls;
            let msg: &[u8] =
                b"[tls] continuity: cont_out holds less than a strict mirror needs; strict pairing refused";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_NO_CAPACITY,
                &body,
            );
            return;
        }
        s.sessions[idx].cont.profile = profile;
        cont_reply(s, flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_OK, &body);
        return;
    }
    // The standby half: reserve a shadow, idempotently.
    let sh = match find_shadow(s, flow) {
        Some(sh) => {
            if s.shadows[sh].epoch != epoch {
                cont_reply(
                    s,
                    flow,
                    epoch,
                    sc::CR_PAIR_PREPARED,
                    sc::STATUS_STALE_EPOCH,
                    &body,
                );
                return;
            }
            sh
        }
        None => match free_shadow(s) {
            Some(sh) => {
                let sd = &mut s.shadows[sh];
                sd.release();
                sd.flow_id.copy_from_slice(flow);
                sd.epoch = epoch;
                sd.phase = ShadowPhase::Prepared;
                sh
            }
            None => {
                cont_reply(
                    s,
                    flow,
                    epoch,
                    sc::CR_PAIR_PREPARED,
                    sc::STATUS_NO_CAPACITY,
                    &body,
                );
                return;
            }
        },
    };
    s.shadows[sh].profile = profile;
    body[2..4].copy_from_slice(&(sh as u16).to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_OK, &body);
}

unsafe fn handle_quiesce(s: &mut TlsState, p: &[u8], begin: bool) {
    let need = if begin {
        sc::QUIESCE_BEGIN_PAYLOAD_LEN
    } else {
        sc::FLOW_HEADER_LEN
    };
    if p.len() != need {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let si = find_session_by_flow(s, flow);
    let mut body = [0u8; 9];
    if si < 0 {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_QUIESCED,
            sc::STATUS_UNKNOWN_SESSION,
            &body,
        );
        return;
    }
    let idx = si as usize;
    if !session_epoch_ok(&mut s.sessions[idx], flow, epoch) {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_QUIESCED,
            sc::STATUS_STALE_EPOCH,
            &body,
        );
        return;
    }
    if begin {
        s.sessions[idx].cont.quiescing = true;
    }
    let sess = &s.sessions[idx];
    // A sealed record `cipher_out` had no room for is output the peer is
    // owed: the write sequence has moved past it, so a cut taken now would
    // hand the standby a sequence the peer never saw the record for.
    let pending_out: u32 = (sess.cont.tx_hold_len != 0 || tx_stalled(s, idx)) as u32;
    let head_complete = sess.recv_len >= RECORD_HEADER_LEN && {
        let rl = ((sess.recv_buf[3] as usize) << 8) | sess.recv_buf[4] as usize;
        sess.recv_len >= RECORD_HEADER_LEN + rl
    };
    // Inbound not yet settled: a whole record still to open, or opened
    // plaintext not yet handed up (`record_scratch`, or an activation's
    // redeliveries).
    let undelivered = (s.clear_pending_len > 0 && s.clear_pending_idx as usize == idx)
        || redelivery_pending(s, idx);
    let pending_in: u32 = head_complete as u32 + undelivered as u32;
    let drained = pending_out == 0 && pending_in == 0 && !sess.cont.horizon_outstanding();
    body[0] = drained as u8;
    body[1..5].copy_from_slice(&pending_out.to_le_bytes());
    body[5..9].copy_from_slice(&pending_in.to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_QUIESCED, sc::STATUS_OK, &body);
}

unsafe fn handle_cut_export(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::FLOW_HEADER_LEN {
        return;
    }
    let mut flow = [0u8; sc::FLOW_ID_BYTES];
    flow.copy_from_slice(&p[..16]);
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let si = find_session_by_flow(s, &flow);
    if si < 0 {
        cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_UNKNOWN_SESSION, &[]);
        return;
    }
    let idx = si as usize;
    if !session_epoch_ok(&mut s.sessions[idx], &flow, epoch) {
        cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_STALE_EPOCH, &[]);
        return;
    }
    // Plaintext opened and not yet handed up (`record_scratch`), or
    // deliveries an activation still owes its worker, are past the read
    // sequence the record would carry and in no field of it: a cut now
    // would lose them.
    let undelivered = (s.clear_pending_len > 0 && s.clear_pending_idx as usize == idx)
        || redelivery_pending(s, idx);
    if !session_movable(&s.sessions[idx])
        || s.sessions[idx].cont.horizon_outstanding()
        || s.sessions[idx].cont.abandon_pending
        || tx_stalled(s, idx)
        || undelivered
    {
        cont_reply(
            s,
            &flow,
            epoch,
            sc::CR_ABORTED,
            sc::STATUS_NOT_READY,
            &[sc::ABORT_UNSUPPORTED_STATE],
        );
        return;
    }
    let len = encode_checkpoint(s, idx, &flow, epoch);
    if len == 0 {
        cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_NOT_READY, &[]);
        return;
    }
    let mut h = Sha256::new();
    h.update(&s.cont_record[..len]);
    let digest = h.finalize();
    let crc = handoff_crc32(&s.cont_record[..len]);
    let gen = s.sessions[idx].cont.ckpt_gen.wrapping_add(1);

    // CHECKPOINT_BEGIN
    {
        let plen = sc::CHECKPOINT_BEGIN_PAYLOAD_LEN;
        cont_frame_header(&mut s.cont_scratch, sc::CMD_SC_CHECKPOINT_BEGIN, plen);
        let mut e = Enc::new(
            s.cont_scratch.as_mut_ptr().add(sc::FRAME_HDR),
            CONT_SCRATCH_SIZE - sc::FRAME_HDR,
        );
        e.bytes(&flow);
        e.u32(epoch);
        e.u32(gen);
        e.u32(len as u32);
        e.bytes(&digest);
        if !cont_write_scratch(s, sc::FRAME_HDR + plen) {
            cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_NO_CAPACITY, &[]);
            return;
        }
    }
    // CHECKPOINT_NEXT*
    let mut walk = HandoffExport::new(len as u32);
    while let Some((off, n)) = walk.next_chunk(sc::CHECKPOINT_CHUNK_MAX as u32) {
        let plen = sc::CHECKPOINT_NEXT_HEADER_LEN + n as usize;
        cont_frame_header(&mut s.cont_scratch, sc::CMD_SC_CHECKPOINT_NEXT, plen);
        let rec: *const u8 = s.cont_record.as_ptr();
        let mut e = Enc::new(
            s.cont_scratch.as_mut_ptr().add(sc::FRAME_HDR),
            CONT_SCRATCH_SIZE - sc::FRAME_HDR,
        );
        e.bytes(&flow);
        e.u32(epoch);
        e.u32(gen);
        e.u32(off);
        e.raw(rec.add(off as usize), n as usize);
        if !e.ok || !cont_write_scratch(s, sc::FRAME_HDR + plen) {
            cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_NO_CAPACITY, &[]);
            return;
        }
        walk.advance(n);
    }
    // CHECKPOINT_COMMIT
    {
        let plen = sc::CHECKPOINT_COMMIT_PAYLOAD_LEN;
        cont_frame_header(&mut s.cont_scratch, sc::CMD_SC_CHECKPOINT_COMMIT, plen);
        let mut e = Enc::new(
            s.cont_scratch.as_mut_ptr().add(sc::FRAME_HDR),
            CONT_SCRATCH_SIZE - sc::FRAME_HDR,
        );
        e.bytes(&flow);
        e.u32(epoch);
        e.u32(gen);
        e.u32(crc);
        if !cont_write_scratch(s, sc::FRAME_HDR + plen) {
            cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_NO_CAPACITY, &[]);
            return;
        }
    }
    // CONTINUITY{CUT}: the manifest, with the sealed continuity object.
    let mut body = [0u8; CUT_BODY_LEN];
    {
        let mut e = Enc::new(body.as_mut_ptr(), CUT_BODY_LEN);
        e.u32(gen);
        e.u32(len as u32);
        e.bytes(&digest);
        e.u8(sc::CT_TLS);
        e.u16(TLS_SEALED_LEN as u16);
        e.raw(
            s.cont_record.as_ptr().add(len - TLS_SEALED_LEN),
            TLS_SEALED_LEN,
        );
    }
    cont_wipe(&mut s.cont_record[..len]);
    let c = &mut s.sessions[idx].cont;
    c.ckpt_gen = gen;
    c.ckpt_digest = digest;
    c.cut_pending = true;
    c.mirror = false;
    c.next_delta = 1;
    c.acked_delta = 0;
    c.delta_unacked_bytes = 0;
    c.last_digest = [0; 32];
    cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_OK, &body);
}

/// `CONTINUITY{CHECKPOINT_COMMITTED}` relayed from the standby: the
/// cut is held; mirroring begins.
unsafe fn handle_continuity_reply(s: &mut TlsState, p: &[u8]) {
    if p.len() < sc::CONTINUITY_HEADER_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let record = p[20];
    let status = p[21];
    let body = &p[sc::CONTINUITY_HEADER_LEN..];
    if record == sc::CR_ABORTED || record == sc::CR_ENDED {
        // The primary abandoned the pair, or its session ended with its
        // connection. Whatever this shadow holds is stale (or of a session
        // that no longer exists) from that moment, so it is released here
        // rather than left armed for a coordinator to activate.
        if let Some(sh) = find_shadow(s, flow) {
            if s.shadows[sh].epoch == epoch {
                s.shadows[sh].release();
            }
        }
        return;
    }
    if record == sc::CR_DELTA_APPLIED && status != sc::STATUS_OK {
        // The standby discarded its shadow; nothing will confirm the next
        // horizon. Waiting for it would hold the inputs forever.
        let si = find_session_by_flow(s, flow);
        if si >= 0 && s.sessions[si as usize].cont.epoch == epoch {
            mirror_abandon(s, si as usize);
        }
        return;
    }
    if record != sc::CR_CHECKPOINT_COMMITTED || status != sc::STATUS_OK || body.len() != 36 {
        return;
    }
    let si = find_session_by_flow(s, flow);
    if si < 0 {
        return;
    }
    let idx = si as usize;
    let gen = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let c = &mut s.sessions[idx].cont;
    if !c.flow_bound
        || c.epoch != epoch
        || !c.cut_pending
        || c.ckpt_gen != gen
        || !digest_eq(&c.ckpt_digest, &body[4..36])
    {
        return;
    }
    // The chain starts at delta 1 with a zero previous digest.
    c.last_digest = [0; 32];
    c.cut_pending = false;
    c.mirror = true;
    c.consumed_told = c.consumed;
    c.cursor_told = c.consumer_cursor;
    c.cursor_at_told = c.cursor_at;
    if c.strict() {
        // From here every transition waits on the standby: the horizons
        // keep it exact, and the clear side may move again.
        c.quiescing = false;
    }
}

unsafe fn handle_delta_ack(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::DELTA_ACK_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let no = u32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let si = find_session_by_flow(s, flow);
    if si < 0 {
        return;
    }
    let idx = si as usize;
    let c = &s.sessions[idx].cont;
    if !c.flow_bound || c.epoch != epoch || c.ckpt_gen != gen || !c.mirror {
        return;
    }
    // An acknowledgement of a delta not yet sent confirms nothing: taken,
    // it would release a horizon the standby does not hold.
    if no >= c.next_delta {
        return;
    }
    apply_delta_ack(s, idx, no);
}

unsafe fn handle_retire(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::FLOW_HEADER_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let si = find_session_by_flow(s, flow);
    if si >= 0 {
        let idx = si as usize;
        if !session_epoch_ok(&mut s.sessions[idx], flow, epoch) {
            cont_reply(s, flow, epoch, sc::CR_RETIRED, sc::STATUS_STALE_EPOCH, &[]);
            return;
        }
        retire_session(&mut s.sessions[idx]);
        cont_reply(s, flow, epoch, sc::CR_RETIRED, sc::STATUS_OK, &[]);
        return;
    }
    if let Some(sh) = find_shadow(s, flow) {
        if s.shadows[sh].epoch != epoch {
            cont_reply(s, flow, epoch, sc::CR_RETIRED, sc::STATUS_STALE_EPOCH, &[]);
            return;
        }
        s.shadows[sh].release();
        cont_reply(s, flow, epoch, sc::CR_RETIRED, sc::STATUS_OK, &[]);
        return;
    }
    cont_reply(
        s,
        flow,
        epoch,
        sc::CR_RETIRED,
        sc::STATUS_UNKNOWN_SESSION,
        &[],
    );
}

unsafe fn handle_abort(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::ABORT_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let reason = p[20];
    if let Some(sh) = find_shadow(s, flow) {
        if s.shadows[sh].epoch != epoch {
            // A delayed abort from a superseded epoch must not tear down
            // the standby a later pairing armed.
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_ABORTED,
                sc::STATUS_STALE_EPOCH,
                &[reason],
            );
            return;
        }
        s.shadows[sh].release();
        cont_reply(s, flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
        return;
    }
    let si = find_session_by_flow(s, flow);
    if si >= 0 {
        let idx = si as usize;
        if s.sessions[idx].cont.flow_bound && s.sessions[idx].cont.epoch != epoch {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_ABORTED,
                sc::STATUS_STALE_EPOCH,
                &[reason],
            );
            return;
        }
        if s.sessions[idx].cont.activated {
            // An ABORT at the epoch a session was activated with, before
            // any pairing of it, undoes the activation: `ip` resets the
            // connection it activated at that epoch, so the session ends
            // too. The consumer hears of it from `ip`'s MSG_CLOSED
            // (`CLOSED_GONE`), which ends the session itself when it comes
            // first and is passed on when it comes after.
            retire_session(&mut s.sessions[idx]);
            cont_reply(s, flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
            return;
        }
        // The coordinator ended the pair itself, so it is told: what the
        // horizons held is owed to the peer from here.
        mirror_lost(s, idx);
        s.sessions[idx].cont.abandon_pending = false;
        s.sessions[idx].cont.quiescing = false;
        release_after_abort(s, idx);
        release_tx_hold(s, idx);
        cont_reply(s, flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
        return;
    }
    cont_reply(
        s,
        flow,
        epoch,
        sc::CR_ABORTED,
        sc::STATUS_UNKNOWN_SESSION,
        &[reason],
    );
}

// ── Standby: checkpoint import ──────────────────────────────────────

unsafe fn ckpt_ack(s: &mut TlsState, flow: &[u8], epoch: u32, gen: u32, offset: u32, status: u8) {
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&gen.to_le_bytes());
    body[4..].copy_from_slice(&offset.to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_CHECKPOINT_ACK, status, &body);
}

unsafe fn handle_checkpoint_begin(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::CHECKPOINT_BEGIN_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let total = u32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let digest = &p[28..60];
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            ckpt_ack(s, flow, epoch, gen, 0, sc::STATUS_UNKNOWN_SESSION);
            return;
        }
    };
    if s.shadows[sh].epoch != epoch || gen < s.shadows[sh].ckpt_gen {
        ckpt_ack(s, flow, epoch, gen, 0, sc::STATUS_STALE_EPOCH);
        return;
    }
    if gen == s.shadows[sh].ckpt_gen && s.shadows[sh].holds_record() {
        // Already held: the retry is idempotent.
        let off = s.shadows[sh].record_len;
        ckpt_ack(s, flow, epoch, gen, off, sc::STATUS_OK);
        return;
    }
    if total as usize > TLS_CKPT_RECORD_MAX {
        ckpt_ack(s, flow, epoch, gen, 0, sc::STATUS_NO_CAPACITY);
        return;
    }
    if (total as usize) < CKPT_FIXED_LEN + TLS_SEALED_LEN {
        ckpt_ack(s, flow, epoch, gen, 0, sc::STATUS_CORRUPT);
        return;
    }
    let sd = &mut s.shadows[sh];
    sd.discard_to_prepared();
    sd.ckpt_gen = gen;
    sd.record_len = total;
    sd.record_digest.copy_from_slice(digest);
    let rc = sd.import.begin(total, TLS_CKPT_RECORD_MAX as u32);
    if rc != HANDOFF_OK {
        ckpt_ack(s, flow, epoch, gen, 0, rc);
        return;
    }
    sd.phase = ShadowPhase::Receiving;
    ckpt_ack(s, flow, epoch, gen, 0, sc::STATUS_OK);
}

unsafe fn handle_checkpoint_next(s: &mut TlsState, p: &[u8]) {
    if p.len() < sc::CHECKPOINT_NEXT_HEADER_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let offset = u32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let data = &p[sc::CHECKPOINT_NEXT_HEADER_LEN..];
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            ckpt_ack(s, flow, epoch, gen, offset, sc::STATUS_UNKNOWN_SESSION);
            return;
        }
    };
    if s.shadows[sh].epoch != epoch || gen != s.shadows[sh].ckpt_gen {
        ckpt_ack(s, flow, epoch, gen, offset, sc::STATUS_STALE_EPOCH);
        return;
    }
    if s.shadows[sh].holds_record() {
        let ok = offset as usize + data.len() <= s.shadows[sh].record_len as usize;
        let st = if ok {
            sc::STATUS_OK
        } else {
            sc::STATUS_CORRUPT
        };
        ckpt_ack(
            s,
            flow,
            epoch,
            gen,
            offset.wrapping_add(data.len() as u32),
            st,
        );
        return;
    }
    if s.shadows[sh].phase != ShadowPhase::Receiving {
        ckpt_ack(s, flow, epoch, gen, offset, sc::STATUS_NOT_READY);
        return;
    }
    let sd: *mut TlsShadow = &mut s.shadows[sh];
    let rc = (*sd).import.chunk(offset, data, &mut (*sd).record);
    if rc != HANDOFF_OK {
        (*sd).discard_to_prepared();
        ckpt_ack(s, flow, epoch, gen, offset, rc);
        return;
    }
    let received = (*sd).import.received();
    ckpt_ack(s, flow, epoch, gen, received, sc::STATUS_OK);
}

unsafe fn handle_checkpoint_commit(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::CHECKPOINT_COMMIT_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let crc = u32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let mut body = [0u8; 36];
    body[..4].copy_from_slice(&gen.to_le_bytes());
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                sc::STATUS_UNKNOWN_SESSION,
                &body,
            );
            return;
        }
    };
    if s.shadows[sh].epoch != epoch || gen != s.shadows[sh].ckpt_gen {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_STALE_EPOCH,
            &body,
        );
        return;
    }
    if s.shadows[sh].holds_record() {
        body[4..].copy_from_slice(&s.shadows[sh].record_digest);
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_OK,
            &body,
        );
        return;
    }
    if s.shadows[sh].phase != ShadowPhase::Receiving {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_NOT_READY,
            &body,
        );
        return;
    }
    let rc = s.shadows[sh].import.end(crc);
    let mut ok = rc == HANDOFF_OK;
    if ok {
        let len = s.shadows[sh].record_len as usize;
        let mut h = Sha256::new();
        h.update(&s.shadows[sh].record[..len]);
        let d = h.finalize();
        ok = digest_eq(&d, &s.shadows[sh].record_digest);
    }
    if ok {
        ok = decode_checkpoint(s, sh);
    }
    if !ok {
        s.shadows[sh].discard_to_prepared();
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_CORRUPT,
            &body,
        );
        return;
    }
    // A session authenticated its peer under the profile of the instance
    // that opened it. One that would live here under another is not a
    // session this instance could have opened, and is not taken.
    if s.shadows[sh].ck.peer_profile != s.peer_auth {
        s.shadows[sh].discard_to_prepared();
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_UNSUPPORTED,
            &body,
        );
        return;
    }
    let sd = &mut s.shadows[sh];
    // The staging bytes carry the sealed object; the decoded state is
    // what lives on.
    cont_wipe(&mut sd.record);
    sd.import.reset();
    sd.delta_no = 0;
    sd.last_digest = [0; 32];
    sd.phase = ShadowPhase::Committed;
    body[4..].copy_from_slice(&sd.record_digest);
    cont_reply(
        s,
        flow,
        epoch,
        sc::CR_CHECKPOINT_COMMITTED,
        sc::STATUS_OK,
        &body,
    );
}

/// Apply one delta's payload to the shadow's checkpoint: `STATUS_OK`, or
/// why the shadow is discarded — `STATUS_CORRUPT` for a contradiction with
/// the state held, `STATUS_NO_CAPACITY` for a delivery it cannot hold for a
/// takeover to hand on. Nothing is applied unless it all is.
unsafe fn shadow_apply_delta(s: &mut TlsState, sh: usize, kind: u8, data: &[u8]) -> u8 {
    let (flow, epoch) = (s.shadows[sh].flow_id, s.shadows[sh].epoch);
    let ck: *mut TlsCheckpoint = &mut s.shadows[sh].ck;
    let ck = &mut *ck;
    let strict = s.shadows[sh].profile == sc::PROFILE_CRASH_CONTINUOUS;
    let mut d = Dec::new(data.as_ptr(), data.len());
    match kind {
        sc::DELTA_TLS_RECORD_OUT => {
            let (ep, seq, n) = match (d.u32(), d.u64(), d.u16()) {
                (Some(a), Some(b), Some(c)) => (a, b, c as usize),
                _ => return sc::STATUS_CORRUPT,
            };
            // Nothing is sealed after our own close_notify.
            if ep != ck.write_epoch
                || seq != ck.write_seq
                || d.remaining() != n + 8
                || n == 0
                || ck.close_notify & 1 != 0
            {
                return sc::STATUS_CORRUPT;
            }
            let src = match d.take(n) {
                Some(p) => p,
                None => return sc::STATUS_CORRUPT,
            };
            // The consumer's clear bytes through this record: never back.
            let out_bytes = match d.u64() {
                Some(b) if b >= ck.out_bytes => b,
                _ => return sc::STATUS_CORRUPT,
            };
            ck.out_bytes = out_bytes;
            ck.write_seq = seq.wrapping_add(1);
            ck.emitted_out = ck.emitted_out.wrapping_add(1);
            let rec = core::slice::from_raw_parts(src, n);
            retx_push_window(&mut ck.retx, &mut ck.retx_len, &mut ck.retx_base_seq, rec);
            sc::STATUS_OK
        }
        sc::DELTA_TLS_RECORD_IN => {
            let (ep, seq, expected, n) = match (d.u32(), d.u64(), d.u32(), d.u32()) {
                (Some(a), Some(b), Some(c), Some(e)) => (a, b, c, e as usize),
                _ => return sc::STATUS_CORRUPT,
            };
            if ep != ck.read_epoch
                || seq != ck.read_seq.wrapping_add(1)
                || n > RECV_BUF_SIZE
                || d.remaining() < n
            {
                return sc::STATUS_CORRUPT;
            }
            let src = match d.take(n) {
                Some(p) => p,
                None => return sc::STATUS_CORRUPT,
            };
            // Under the strict profile the record was opened first and its
            // inner type and plaintext follow, always; under the planned one
            // it is mirrored before it is opened, nothing follows, and the
            // shadow cannot tell a delivery from any other record, so each
            // counts as consumed. A strict delivery is kept, plaintext and
            // all, until DELTA_TLS_DELIVERED says the worker consumed it: the
            // primary hands it up only after this acknowledgement, so a
            // crash between the two leaves it with the standby alone, which
            // hands it to its own worker at activation.
            let mut delivers = true;
            let mut carry: &[u8] = &[];
            if strict {
                let (Some(ctype), Some(pl)) = (d.u8(), d.u16()) else {
                    return sc::STATUS_CORRUPT;
                };
                let pl = usize::from(pl);
                let shape_ok = match ctype {
                    RECORD_IN_NOT_CARRIED => pl == 0,
                    CT_ALERT => pl == 2,
                    CT_HANDSHAKE | CT_APPLICATION_DATA => pl <= DELIV_CARRY_MAX,
                    _ => false,
                };
                if !shape_ok || d.remaining() != pl {
                    return sc::STATUS_CORRUPT;
                }
                let plain = match d.take(pl) {
                    Some(p) => core::slice::from_raw_parts(p, pl),
                    None => return sc::STATUS_CORRUPT,
                };
                // What the primary hands up: application data before the
                // peer's close_notify. A record too long to carry is
                // application data or a post-handshake message; only the
                // former is long in practice, and it is counted as one.
                let open = ck.close_notify & 2 == 0;
                delivers = open
                    && match ctype {
                        CT_APPLICATION_DATA => pl > 0,
                        RECORD_IN_NOT_CARRIED => true,
                        _ => false,
                    };
                if delivers {
                    // A delivery the record cannot hold (too long to carry,
                    // or past the deliveries a record holds) would be lost
                    // at a takeover: the pair cannot promise it.
                    if ctype == RECORD_IN_NOT_CARRIED
                        || ck.deliv_count >= CONT_REDELIVER_COUNT
                        || ck.deliv_len as usize + 2 + pl > CONT_REDELIVER_MAX
                    {
                        return sc::STATUS_NO_CAPACITY;
                    }
                    carry = plain;
                }
                if ctype == CT_ALERT && plain[1] == ALERT_CLOSE_NOTIFY {
                    ck.close_notify |= 2;
                }
            } else if d.remaining() != 0 {
                return sc::STATUS_CORRUPT;
            }
            ck.read_seq = seq;
            if strict && delivers {
                let at = ck.deliv_len as usize;
                ck.deliv[at..at + 2].copy_from_slice(&(carry.len() as u16).to_le_bytes());
                ck.deliv[at + 2..at + 2 + carry.len()].copy_from_slice(carry);
                ck.deliv_len = (at + 2 + carry.len()) as u32;
                ck.deliv_count += 1;
            } else if delivers {
                ck.delivered_in = ck.delivered_in.wrapping_add(1);
            }
            ck.recv_expected = expected;
            cont_wipe(&mut ck.recv[..ck.recv_len as usize]);
            core::ptr::copy_nonoverlapping(src, ck.recv.as_mut_ptr(), n);
            ck.recv_len = n as u32;
            sc::STATUS_OK
        }
        // Strict-profile deltas only. `[consumed:8][consumer_cursor:8]
        // [cursor_at:8]`, cumulative: the deliveries it covers leave the
        // shadow, oldest first, their bytes counted into `in_bytes`, and the
        // cursor and its clear byte are the latest the consumer gave. A
        // count below the record's is of deliveries handed up before the
        // checkpoint, which the record never held.
        DELTA_TLS_DELIVERED if strict => {
            let (Some(n), Some(cursor), Some(at)) = (d.u64(), d.u64(), d.u64()) else {
                return sc::STATUS_CORRUPT;
            };
            if d.remaining() != 0 {
                return sc::STATUS_CORRUPT;
            }
            if at < ck.cursor_at {
                return sc::STATUS_OK;
            }
            ck.consumer_cursor = cursor;
            ck.cursor_at = at;
            if n <= ck.delivered_in {
                return sc::STATUS_OK;
            }
            if n - ck.delivered_in > u64::from(ck.deliv_count) {
                return sc::STATUS_CORRUPT;
            }
            let k = (n - ck.delivered_in) as u8;
            let len = ck.deliv_len as usize;
            let mut at_b = 0usize;
            let mut bytes = 0u64;
            let mut i = 0u8;
            while i < k {
                let l = usize::from(u16::from_le_bytes([ck.deliv[at_b], ck.deliv[at_b + 1]]));
                bytes += l as u64;
                at_b += 2 + l;
                i += 1;
            }
            ck.deliv.copy_within(at_b..len, 0);
            cont_wipe(&mut ck.deliv[len - at_b..len]);
            ck.deliv_len = (len - at_b) as u32;
            ck.deliv_count -= k;
            ck.delivered_in = n;
            ck.in_bytes = ck.in_bytes.wrapping_add(bytes);
            // Whole records only: the acknowledgement may stand inside the
            // first one still held, never past it.
            if ck.in_bytes > at {
                return sc::STATUS_CORRUPT;
            }
            sc::STATUS_OK
        }
        sc::DELTA_TLS_RETX_ACK => {
            let Some(acked) = d.u32() else {
                return sc::STATUS_CORRUPT;
            };
            let Some(isn) = d.u32() else {
                return sc::STATUS_CORRUPT;
            };
            if d.remaining() != 0 {
                return sc::STATUS_CORRUPT;
            }
            retx_slide(
                &mut ck.retx,
                &mut ck.retx_len,
                &mut ck.retx_base_seq,
                &mut ck.retx_anchored,
                acked,
                isn,
            );
            sc::STATUS_OK
        }
        sc::DELTA_TLS_RECV_BYTES if strict => {
            let Some(n) = d.u32() else {
                return sc::STATUS_CORRUPT;
            };
            let n = n as usize;
            if n > RECV_BUF_SIZE || d.remaining() != n {
                return sc::STATUS_CORRUPT;
            }
            let Some(src) = d.take(n) else {
                return sc::STATUS_CORRUPT;
            };
            cont_wipe(&mut ck.recv[..ck.recv_len as usize]);
            core::ptr::copy_nonoverlapping(src, ck.recv.as_mut_ptr(), n);
            ck.recv_len = n as u32;
            sc::STATUS_OK
        }
        sc::DELTA_TLS_KEY_UPDATE => {
            let (dir, ep, n) = match (d.u8(), d.u32(), d.u16()) {
                (Some(a), Some(b), Some(c)) => (a, b, c as usize),
                _ => return sc::STATUS_CORRUPT,
            };
            // A read rotation ends with `[owed:1]`, 0 or 1; a write rotation
            // with the sealed set.
            let trailer = usize::from(dir == DELTA_DIR_READ);
            if n != TLS_SEALED_LEN || d.remaining() != n + trailer {
                return sc::STATUS_CORRUPT;
            }
            let expected = match dir {
                DELTA_DIR_WRITE => ck.write_epoch.wrapping_add(1),
                DELTA_DIR_READ => ck.read_epoch.wrapping_add(1),
                _ => return sc::STATUS_CORRUPT,
            };
            if ep != expected {
                return sc::STATUS_CORRUPT;
            }
            let sealed = match d.take(n) {
                Some(p) => core::slice::from_raw_parts(p, n),
                None => return sc::STATUS_CORRUPT,
            };
            let owed = if dir == DELTA_DIR_READ {
                match d.u8() {
                    Some(o) if o <= 1 => o == 1,
                    _ => return sc::STATUS_CORRUPT,
                }
            } else {
                false
            };
            let mut set = SecretSet::empty();
            let aad = ku_aad(&flow, epoch, dir, ep);
            if !open_secret_set(s, &flow, epoch, &aad, sealed, &mut set) {
                return sc::STATUS_CORRUPT;
            }
            ck.secrets.wipe();
            ck.secrets.copy_from(&set);
            set.wipe();
            if dir == DELTA_DIR_WRITE {
                ck.write_epoch = ep;
                ck.write_seq = 0;
                // Any rotation of ours answers the peer's request.
                ck.key_update &= !2;
            } else {
                ck.read_epoch = ep;
                ck.read_seq = 0;
                ck.key_update = (ck.key_update & !2) | (u8::from(owed) << 1);
            }
            sc::STATUS_OK
        }
        // Our own close: its alert was the RECORD_OUT before this.
        sc::DELTA_TLS_CLOSE_SENT if data.is_empty() && ck.close_notify & 1 == 0 => {
            ck.close_notify |= 1;
            sc::STATUS_OK
        }
        _ => sc::STATUS_CORRUPT,
    }
}

unsafe fn handle_delta_apply(s: &mut TlsState, p: &[u8]) {
    if p.len() < sc::DELTA_APPLY_HEADER_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let no = u32::from_le_bytes([p[24], p[25], p[26], p[27]]);
    let prev = &p[28..60];
    let kind = p[60];
    let data = &p[sc::DELTA_APPLY_HEADER_LEN..];
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&gen.to_le_bytes());
    body[4..].copy_from_slice(&no.to_le_bytes());
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_DELTA_APPLIED,
                sc::STATUS_UNKNOWN_SESSION,
                &body,
            );
            return;
        }
    };
    if s.shadows[sh].epoch != epoch || gen != s.shadows[sh].ckpt_gen {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_STALE_EPOCH,
            &body,
        );
        return;
    }
    if !s.shadows[sh].holds_record() {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_NOT_READY,
            &body,
        );
        return;
    }
    let mut h = Sha256::new();
    h.update(p);
    let digest = h.finalize();
    let held = s.shadows[sh].delta_no;
    if no <= held {
        // An identical retry of the last delta is idempotent; anything
        // else is a conflicting duplicate.
        if no == held && digest_eq(&s.shadows[sh].last_digest, &digest) {
            cont_delta_ack(s, sh);
            return;
        }
        s.shadows[sh].discard_to_prepared();
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_CORRUPT,
            &body,
        );
        return;
    }
    if no != held.wrapping_add(1) || !digest_eq(&s.shadows[sh].last_digest, prev) {
        s.shadows[sh].discard_to_prepared();
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_CORRUPT,
            &body,
        );
        return;
    }
    let st = shadow_apply_delta(s, sh, kind, data);
    if st != sc::STATUS_OK {
        s.shadows[sh].discard_to_prepared();
        cont_reply(s, flow, epoch, sc::CR_DELTA_APPLIED, st, &body);
        return;
    }
    let sd = &mut s.shadows[sh];
    sd.delta_no = no;
    sd.last_digest = digest;
    cont_delta_ack(s, sh);
}

unsafe fn handle_cut_import(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::CUT_IMPORT_PAYLOAD_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let digest = &p[24..56];
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&gen.to_le_bytes());
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_IMPORTED,
                sc::STATUS_UNKNOWN_SESSION,
                &body,
            );
            return;
        }
    };
    if s.shadows[sh].epoch != epoch || gen != s.shadows[sh].ckpt_gen {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_IMPORTED,
            sc::STATUS_STALE_EPOCH,
            &body,
        );
        return;
    }
    if !s.shadows[sh].holds_record() {
        cont_reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_NOT_READY, &body);
        return;
    }
    if !digest_eq(&s.shadows[sh].record_digest, digest) {
        cont_reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_CORRUPT, &body);
        return;
    }
    if s.shadows[sh].phase == ShadowPhase::Committed {
        s.shadows[sh].phase = ShadowPhase::Published;
    }
    body[4..].copy_from_slice(&s.shadows[sh].delta_no.to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_OK, &body);
}

unsafe fn handle_emission_arm(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::FLOW_HEADER_LEN {
        return;
    }
    let flow = &p[..16];
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_ARMED,
                sc::STATUS_UNKNOWN_SESSION,
                &[0],
            );
            return;
        }
    };
    if s.shadows[sh].epoch != epoch {
        cont_reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_STALE_EPOCH, &[0]);
        return;
    }
    match s.shadows[sh].phase {
        ShadowPhase::Published | ShadowPhase::Armed => {
            s.shadows[sh].phase = ShadowPhase::Armed;
            // The record layer holds no timers: nothing has expired.
            cont_reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_OK, &[0]);
        }
        _ => {
            cont_reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_NOT_READY, &[0]);
        }
    }
}

/// Turn an armed shadow into the live session on `conn_id`.
unsafe fn activate_shadow(s: &mut TlsState, sh: usize, new_epoch: u32, conn_id: u16) -> bool {
    let idx = match alloc_session_for_conn(s, conn_id) {
        Some(idx) => idx,
        None => return false,
    };
    let (profile, flow, gen) = {
        let sd = &s.shadows[sh];
        (sd.profile, sd.flow_id, sd.ckpt_gen)
    };
    let ck: *const TlsCheckpoint = &s.shadows[sh].ck;
    let ck = &*ck;
    let suite = match CipherSuite::from_id(ck.suite) {
        Some(cs) => cs,
        None => {
            s.sessions[idx].reset();
            return false;
        }
    };
    let sess = &mut s.sessions[idx];
    sess.cont.reset();
    sess.driver.reset();
    sess.driver.is_server = ck.is_server;
    sess.driver.suite = suite;
    sess.driver.hs_state = HandshakeState::Complete;
    sess.driver.alpn_selected = ck.alpn;
    sess.driver.alpn_selected_len = ck.alpn_len;
    sess.expected = [0; MAX_EXPECTED_DNS];
    sess.expected[..ck.sni_len as usize].copy_from_slice(&ck.sni[..ck.sni_len as usize]);
    sess.expected_len = ck.sni_len;
    sess.expected_is_ip = ck.sni_is_ip;
    sess.driver.server_finished_hash = ck.exporter_ctx;
    let mut ks = KeySchedule::new(suite);
    ks.client_app_secret = ck.secrets.client_app;
    ks.server_app_secret = ck.secrets.server_app;
    sess.driver.key_schedule = Some(ks);
    sess.read_keys = TrafficKeys::empty();
    sess.read_keys.key = ck.secrets.read_key;
    sess.read_keys.iv = ck.secrets.read_iv;
    sess.read_keys.key_len = ck.secrets.read_key_len as usize;
    sess.read_keys.seq = ck.read_seq;
    sess.write_keys = TrafficKeys::empty();
    sess.write_keys.key = ck.secrets.write_key;
    sess.write_keys.iv = ck.secrets.write_iv;
    sess.write_keys.key_len = ck.secrets.write_key_len as usize;
    sess.write_keys.seq = ck.write_seq;
    sess.read_epoch = ck.read_epoch;
    sess.write_epoch = ck.write_epoch;
    let rl = (ck.recv_len as usize).min(RECV_BUF_SIZE);
    sess.recv_buf[..rl].copy_from_slice(&ck.recv[..rl]);
    sess.recv_len = rl;
    sess.recv_expected = ck.recv_expected as usize;
    let xl = (ck.retx_len as usize).min(RETX_BUF_SIZE);
    sess.retx_buf[..xl].copy_from_slice(&ck.retx[..xl]);
    sess.retx_len = xl as u16;
    sess.retx_head = if xl == 0 { 0 } else { RETX_HEAD_UNKNOWN };
    sess.retx_base_seq = ck.retx_base_seq;
    sess.retx_seq_anchored = ck.retx_anchored;
    sess.ccs_seen = MAX_COMPAT_CCS;
    sess.cont.flow_id = flow;
    sess.cont.flow_bound = true;
    sess.cont.epoch = new_epoch;
    sess.cont.profile = profile;
    sess.cont.ckpt_gen = gen;
    sess.cont.delivered_in = ck.delivered_in;
    sess.cont.emitted_out = ck.emitted_out;
    // The connection's output horizon moves with it: the consumer here
    // continues the old one's numbering, and is told at once how far the
    // old one's output reached (every record held here reaches the peer).
    sess.wh = WriteHorizon::empty();
    sess.wh.clear_total = ck.out_bytes;
    sess.wh.through = ck.out_bytes;
    sess.wh.owed = true;
    sess.cont.peer_moved = true;
    sess.cont.moved_id = ck.peer_id;
    sess.cont.activated = true;
    // The transport peer and the requester, as the session opened with them.
    sess.peer = ck.peer;
    sess.peer_have = ck.peer[0] != 0;
    sess.downstream_tag = ck.requester_tag;
    // The peer's KeyUpdate request the old owner never answered: answered
    // here, before any record of ours (continuity_step sends it; the clear
    // side stays frozen until it has gone).
    sess.cont.ku_answer_owed = ck.key_update & 2 != 0;
    // A half-closed session moves half-closed: its new consumer is told the
    // peer is done, after the accept (and anything owed before it).
    sess.peer_closed = (if ck.close_notify & 2 != 0 {
        PEER_CLOSE_NOTIFY
    } else {
        0
    }) | (if ck.close_notify & 4 != 0 {
        PEER_FIN
    } else {
        0
    });
    if sess.peer_closed != 0 {
        sess.peer_closed |= PEER_CLOSED_OWED;
    }
    // Everything delivered was consumed, as far as the record says; what it
    // carries beyond that is handed to this worker again, first.
    sess.cont.consumed = ck.delivered_in;
    sess.cont.consumed_told = ck.delivered_in;
    // The consumer here is told where its predecessor stood — the cursor
    // and clear byte of the last acknowledgement, and the output horizon —
    // before any data. Redelivery starts at exactly that byte: the first
    // delivery held is trimmed by what of it was consumed. Bytes the record
    // counts delivered past the acknowledgement (a primary's own export
    // carries none of its deliveries) are not handed up again, and the
    // stream resumes after them.
    sess.cont.consumer_cursor = ck.consumer_cursor;
    sess.cont.cursor_told = ck.consumer_cursor;
    let first = if ck.deliv_count > 0 {
        u64::from(u16::from_le_bytes([ck.deliv[0], ck.deliv[1]]))
    } else {
        0
    };
    let trim = if ck.cursor_at > ck.in_bytes {
        (ck.cursor_at - ck.in_bytes).min(first.saturating_sub(1))
    } else {
        0
    };
    let resume_at = ck.in_bytes.wrapping_add(trim);
    sess.cont.cursor_at = resume_at.min(ck.cursor_at.max(ck.in_bytes));
    sess.cont.cursor_at_told = sess.cont.cursor_at;
    sess.cont.handed_bytes = ck.in_bytes;
    sess.cont.pend_n = 0;
    sess.cont.pend_bytes = 0;
    sess.cont.resumed_cursor = ck.consumer_cursor;
    sess.cont.resumed_in = resume_at;
    sess.cont.resumed_out = ck.out_bytes;
    sess.cont.resumed_owed = ck.close_notify & 1 == 0;
    let dl = ck.deliv_len as usize;
    if dl > 0 {
        core::ptr::copy_nonoverlapping(ck.deliv.as_ptr(), s.redeliver.as_mut_ptr(), dl);
        s.redeliver_len = dl as u32;
        s.redeliver_off = 0;
        s.redeliver_trim = trim as u16;
        s.redeliver_idx = idx as u8;
        s.redeliver_conn = s.sessions[idx].conn_id;
    }
    let sess = &mut s.sessions[idx];
    if ck.close_notify & 1 != 0 {
        // Our own close moved: the consumer that closed it was the
        // primary's, so this one is never told of it; the session finishes
        // the close — its alert resent from the window if unacknowledged,
        // the transport close forwarded if the primary had not yet — and
        // ends with `ip`'s MSG_CLOSED. Nothing the peer sends now is
        // delivered.
        sess.held_msg_type = 0;
        sess.peer_closed &= !PEER_CLOSED_OWED;
        sess.local_close = LOCAL_CLOSE_SENT
            | if ck.close_notify & 8 != 0 {
                LOCAL_CLOSE_FWD
            } else {
                0
            };
        sess.state = SessionState::Closing;
        s.shadows[sh].release();
        let _ = local_close_step(s, idx);
        return true;
    }
    // The clear-side consumer learns of the connection as of one this
    // module opened: the peer's identity record, then the held accept or
    // connect (a client's on the requester's tag), then the peer report,
    // before any data.
    sess.held_msg_type = if ck.is_server {
        NET_MSG_ACCEPTED
    } else {
        NET_MSG_CONNECTED
    };
    sess.state = SessionState::Ready;
    sess.peer_pending = sess.peer_have;
    s.sess_ready_total = s.sess_ready_total.wrapping_add(1);
    s.shadows[sh].release();
    emit_peer_identity(s, idx);
    true
}

unsafe fn handle_activate(s: &mut TlsState, p: &[u8]) {
    if p.len() != sc::ACTIVATE_PAYLOAD_LEN && p.len() != sc::ACTIVATE_PAYLOAD_LEN + 2 {
        return;
    }
    let flow = &p[..16];
    let new_epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let fence_gen = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    let named_conn = if p.len() == sc::ACTIVATE_PAYLOAD_LEN + 2 {
        Some(u16::from_le_bytes([p[24], p[25]]))
    } else {
        None
    };
    let mut body = [0u8; 6];
    body[..4].copy_from_slice(&new_epoch.to_le_bytes());
    let sh = match find_shadow(s, flow) {
        Some(sh) => sh,
        None => {
            let st = if find_session_by_flow(s, flow) >= 0 {
                sc::STATUS_NOT_READY
            } else {
                sc::STATUS_UNKNOWN_SESSION
            };
            cont_reply(s, flow, new_epoch, sc::CR_ACTIVATED, st, &body);
            return;
        }
    };
    if new_epoch <= s.shadows[sh].epoch {
        cont_reply(
            s,
            flow,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_STALE_EPOCH,
            &body,
        );
        return;
    }
    if fence_gen == 0 || s.shadows[sh].phase != ShadowPhase::Armed {
        cont_reply(
            s,
            flow,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_NOT_READY,
            &body,
        );
        return;
    }
    let conn_id = named_conn.unwrap_or(s.shadows[sh].ck.conn_id);
    body[4..].copy_from_slice(&conn_id.to_le_bytes());
    // Redeliveries go out for one session at a time: a shadow that carries
    // some waits until another activation's have gone, rather than
    // overwrite them.
    if find_session_by_conn_id(s, conn_id) >= 0
        || (s.shadows[sh].ck.deliv_len > 0 && s.redeliver_len > 0)
    {
        cont_reply(
            s,
            flow,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_NO_CAPACITY,
            &body,
        );
        return;
    }
    if !activate_shadow(s, sh, new_epoch, conn_id) {
        cont_reply(
            s,
            flow,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_NO_CAPACITY,
            &body,
        );
        return;
    }
    cont_reply(s, flow, new_epoch, sc::CR_ACTIVATED, sc::STATUS_OK, &body);
}

// ── Custody: vault-to-vault transfer of a flow's sealing key ────────
//
// `CMD_SC_CUSTODY` (session_ctrl.rs). A standby's ATTEST makes a fresh
// P-256 agreement key (never persisted, never wrappable) and has the vault
// attest it (`ATTEST_KEY`) over the transfer's challenge, signed by this
// host's custody identity (`tls-custody`, P-256, persisted). A primary's WRAP
// checks the evidence — it answers the challenge, names an ephemeral
// agreement key whose thumbprint is the public key carried, and its
// signature verifies under its signer in the vault — and wraps the flow's
// sealing key to that recipient, bound to the composition the record
// attests (`KEY_WRAP`). The standby's UNWRAP opens it with the recipient
// (`KEY_UNWRAP`: only that key, and only while this composition is the one
// attested) into a key this instance holds for the flow until its shadow
// has imported with it. Whether the signer is the host the transfer was
// decided for is not this module's question: the coordinator's authority
// answers it before a WRAP is sent.

/// `CONTINUITY{CUSTODY}`: `[op][reason][bytes]`.
unsafe fn custody_reply(
    s: &mut TlsState,
    flow: &[u8],
    epoch: u32,
    op: u8,
    status: u8,
    reason: u8,
    bytes: &[u8],
) {
    let mut body = [0u8; 2 + sc::custody::EVIDENCE_MAX];
    let n = bytes.len().min(sc::custody::EVIDENCE_MAX);
    body[0] = op;
    body[1] = reason;
    body[2..2 + n].copy_from_slice(&bytes[..n]);
    let _ = cont_reply(s, flow, epoch, sc::CR_CUSTODY, status, &body[..2 + n]);
}

/// This host's custody identity and its public key, opened on first use.
unsafe fn custody_signer(s: &mut TlsState) -> i32 {
    if s.custody_signer_open {
        return s.custody_signer;
    }
    let sys = &*s.syscalls;
    let mut pubk = [0u8; sc::custody::PUB_LEN];
    let h = cont_vault_open_or_generate(
        sys,
        kv::suite::P256,
        kv::usage::SIGN | kv::usage::EXPORT_PUBLIC | kv::usage::PERSIST,
        CUSTODY_ID_LABEL,
        &mut pubk,
    );
    if h < 0 {
        return -1;
    }
    s.custody_signer = h;
    s.custody_signer_pub = pubk;
    s.custody_signer_open = true;
    h
}

unsafe fn handle_custody(s: &mut TlsState, p: &[u8]) {
    use sc::custody as cu;
    if p.len() < sc::FLOW_HEADER_LEN + 1 {
        return;
    }
    let mut flow = [0u8; sc::FLOW_ID_BYTES];
    flow.copy_from_slice(&p[..16]);
    let epoch = u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
    let op = p[20];
    let body = &p[21..];
    let r = match op {
        cu::ATTEST => custody_attest(s, &flow, epoch, body),
        cu::WRAP => custody_wrap(s, &flow, epoch, body),
        cu::UNWRAP => custody_unwrap(s, &flow, epoch, body),
        _ => Err((sc::STATUS_UNSUPPORTED, 0)),
    };
    if let Err((status, reason)) = r {
        custody_reply(s, &flow, epoch, op, status, reason, &[]);
    }
}

type CustodyResult = Result<(), (u8, u8)>;

/// ATTEST `[challenge:32]`: a fresh recipient under `name`, attested.
unsafe fn custody_attest(
    s: &mut TlsState,
    name: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    let vault = (sc::STATUS_NO_CAPACITY, cu::why::VAULT);
    if body.len() != 32 {
        return Err((sc::STATUS_CORRUPT, cu::why::EVIDENCE));
    }
    let signer = custody_signer(s);
    if signer < 0 {
        return Err(vault);
    }
    // A later ATTEST under the same name replaces the recipient.
    if let Some(i) = cont_key_find(s, &[KEY_RECIPIENT], name, epoch) {
        cont_key_free(s, i);
    }
    let Some(slot) = cont_key_alloc(s) else {
        return Err(vault);
    };
    let sys = &*s.syscalls;
    // GENERATE: [suite:u16][usage:u32][flags:u8][_pad:u8]
    //           [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
    let mut rpub = [0u8; cu::PUB_LEN];
    let mut g = [0u8; 20];
    g[0..2].copy_from_slice(&kv::suite::P256.to_le_bytes());
    let usage = kv::usage::AGREE | kv::usage::EXPORT_PUBLIC;
    g[2..6].copy_from_slice(&usage.to_le_bytes());
    g[8..16].copy_from_slice(&(rpub.as_mut_ptr() as u64).to_le_bytes());
    g[16..18].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    let recipient = (sys.provider_call)(-1, kv::GENERATE, g.as_mut_ptr(), g.len());
    if recipient < 0 || u16::from_le_bytes([g[18], g[19]]) as usize != cu::PUB_LEN {
        cont_vault_destroy(sys, recipient);
        return Err(vault);
    }
    // ATTEST_KEY: [challenge:32][signer:i32][_pad:u32][out_ptr:u64]
    //             [out_cap:u32][out_len_out:u32]
    let mut ev = [0u8; cu::EVIDENCE_MAX];
    let mut rec = [0u8; cu::RECORD_LEN + cu::SIG_MAX];
    let mut a = [0u8; kv::attest_key::ARG_LEN];
    a[..32].copy_from_slice(body);
    a[kv::attest_key::SIGNER..kv::attest_key::SIGNER + 4].copy_from_slice(&signer.to_le_bytes());
    a[kv::attest_key::OUT_PTR..kv::attest_key::OUT_PTR + 8]
        .copy_from_slice(&(rec.as_mut_ptr() as u64).to_le_bytes());
    a[kv::attest_key::OUT_CAP..kv::attest_key::OUT_CAP + 4]
        .copy_from_slice(&(rec.len() as u32).to_le_bytes());
    let rc = (sys.provider_call)(recipient, kv::ATTEST_KEY, a.as_mut_ptr(), a.len());
    let n = u32::from_le_bytes([
        a[kv::attest_key::OUT_LEN],
        a[kv::attest_key::OUT_LEN + 1],
        a[kv::attest_key::OUT_LEN + 2],
        a[kv::attest_key::OUT_LEN + 3],
    ]) as usize;
    if rc < 0 || n <= cu::RECORD_LEN || n > rec.len() {
        cont_vault_destroy(sys, recipient);
        return Err(vault);
    }
    let sig_len = n - cu::RECORD_LEN;
    ev[..cu::RECORD_LEN].copy_from_slice(&rec[..cu::RECORD_LEN]);
    ev[cu::RECIPIENT..cu::RECIPIENT + cu::PUB_LEN].copy_from_slice(&rpub);
    ev[cu::SIGNER..cu::SIGNER + cu::PUB_LEN].copy_from_slice(&s.custody_signer_pub);
    ev[cu::SIG_LEN..cu::SIG_LEN + 2].copy_from_slice(&(sig_len as u16).to_le_bytes());
    ev[cu::SIG..cu::SIG + sig_len].copy_from_slice(&rec[cu::RECORD_LEN..n]);
    cont_key_put(s, slot, KEY_RECIPIENT, name, epoch, recipient);
    custody_reply(
        s,
        name,
        epoch,
        cu::ATTEST,
        sc::STATUS_OK,
        0,
        &ev[..cu::SIG + sig_len],
    );
    Ok(())
}

/// WRAP `[challenge:32][evidence]`: the flow's sealing key, wrapped to the
/// attested recipient.
unsafe fn custody_wrap(
    s: &mut TlsState,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    let refuse = |why| Err((sc::STATUS_CORRUPT, why));
    if body.len() < 32 + cu::SIG + 1 || body.len() > 32 + cu::EVIDENCE_MAX {
        return refuse(cu::why::EVIDENCE);
    }
    let (challenge, ev) = body.split_at(32);
    let sig_len = u16::from_le_bytes([ev[cu::SIG_LEN], ev[cu::SIG_LEN + 1]]) as usize;
    if sig_len != cu::SIG_MAX || cu::SIG + sig_len != ev.len() {
        return refuse(cu::why::EVIDENCE);
    }
    let record = &ev[..cu::RECORD_LEN];
    let recipient = &ev[cu::RECIPIENT..cu::RECIPIENT + cu::PUB_LEN];
    let signer = &ev[cu::SIGNER..cu::SIGNER + cu::PUB_LEN];
    let sig = &ev[cu::SIG..];
    use kv::attest_key as ak;
    if record[..4] != ak::MAGIC {
        return refuse(cu::why::EVIDENCE);
    }
    if record[ak::R_CHALLENGE..ak::R_CHALLENGE + 32] != *challenge {
        return refuse(cu::why::CHALLENGE);
    }
    let usage = u32::from_le_bytes([
        record[ak::R_USAGE],
        record[ak::R_USAGE + 1],
        record[ak::R_USAGE + 2],
        record[ak::R_USAGE + 3],
    ]);
    let suite = u16::from_le_bytes([record[ak::R_SUITE], record[ak::R_SUITE + 1]]);
    if suite != kv::suite::P256
        || usage & kv::usage::AGREE == 0
        || usage & (kv::usage::PERSIST | kv::usage::WRAP) != 0
        || record[ak::R_PERSISTED] != 0
        || record[ak::R_THUMBPRINT..ak::R_THUMBPRINT + 32] != sha256(recipient)
    {
        return refuse(cu::why::RECIPIENT);
    }
    let sys = &*s.syscalls;
    // VERIFY with the signer's public key: [hash_len:u16][sig_len:u16]
    // [pub_len:u16][_pad:u16][hash][sig][pub].
    let digest = sha256(record);
    let mut v = [0u8; 8 + 32 + cu::SIG_MAX + cu::PUB_LEN];
    v[0..2].copy_from_slice(&32u16.to_le_bytes());
    v[2..4].copy_from_slice(&(cu::SIG_MAX as u16).to_le_bytes());
    v[4..6].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    v[8..40].copy_from_slice(&digest);
    v[40..40 + cu::SIG_MAX].copy_from_slice(sig);
    v[40 + cu::SIG_MAX..].copy_from_slice(signer);
    if (sys.provider_call)(-1, kv::VERIFY, v.as_mut_ptr(), v.len()) != 1 {
        return refuse(cu::why::SIGNATURE);
    }
    // The flow must be a live session of this instance: the key it seals
    // under is what moves.
    let si = find_session_by_flow(s, flow);
    if si < 0 || !session_movable(&s.sessions[si as usize]) {
        return Err((sc::STATUS_UNKNOWN_SESSION, cu::why::NO_FLOW));
    }
    let idx = si as usize;
    if !session_epoch_ok(&mut s.sessions[idx], flow, epoch) {
        return Err((sc::STATUS_STALE_EPOCH, cu::why::NO_FLOW));
    }
    let (kf, ke) = (s.sessions[idx].cont.flow_id, s.sessions[idx].cont.epoch);
    let key = cont_flow_key(s, &kf, ke);
    if key < 0 {
        return Err((sc::STATUS_NO_CAPACITY, cu::why::VAULT));
    }
    // KEY_WRAP: [dest_pub_len:u16][dest_pub][attest_digest:32]
    //           [out_ptr:u64][out_cap:u16][out_len_out:u16]
    let mut blob = [0u8; cu::WRAPPED_LEN];
    let mut w = [0u8; 2 + cu::PUB_LEN + 32 + 12];
    w[0..2].copy_from_slice(&(cu::PUB_LEN as u16).to_le_bytes());
    w[2..2 + cu::PUB_LEN].copy_from_slice(recipient);
    let c = 2 + cu::PUB_LEN;
    w[c..c + 32].copy_from_slice(&record[ak::R_COMPOSITION..ak::R_COMPOSITION + 32]);
    w[c + 32..c + 40].copy_from_slice(&(blob.as_mut_ptr() as u64).to_le_bytes());
    w[c + 40..c + 42].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(key, kv::KEY_WRAP, w.as_mut_ptr(), w.len());
    let n = u16::from_le_bytes([w[c + 42], w[c + 43]]) as usize;
    if rc < 0 || n != cu::WRAPPED_LEN {
        return Err((sc::STATUS_NO_CAPACITY, cu::why::VAULT));
    }
    custody_reply(s, flow, epoch, cu::WRAP, sc::STATUS_OK, 0, &blob);
    Ok(())
}

/// UNWRAP `[name:16][wrapped]`: the key the recipient `name` was attested
/// for, held for `(flow, epoch)` until a shadow imports with it.
unsafe fn custody_unwrap(
    s: &mut TlsState,
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    body: &[u8],
) -> CustodyResult {
    use sc::custody as cu;
    if body.len() != 16 + cu::WRAPPED_LEN {
        return Err((sc::STATUS_CORRUPT, cu::why::EVIDENCE));
    }
    let (name, blob) = body.split_at(16);
    let Some(ri) = cont_key_find(s, &[KEY_RECIPIENT], name, epoch) else {
        return Err((sc::STATUS_UNKNOWN_SESSION, cu::why::NO_RECIPIENT));
    };
    let recipient = s.cont_keys[ri].handle;
    let sys = &*s.syscalls;
    // KEY_UNWRAP: [blob_len:u16][blob]
    let mut u = [0u8; 2 + cu::WRAPPED_LEN];
    u[0..2].copy_from_slice(&(cu::WRAPPED_LEN as u16).to_le_bytes());
    u[2..].copy_from_slice(blob);
    let key = (sys.provider_call)(recipient, kv::KEY_UNWRAP, u.as_mut_ptr(), u.len());
    if key < 0 {
        return Err((sc::STATUS_CORRUPT, cu::why::VAULT));
    }
    // It must be a sealing key, as the primary's are; DESCRIBE:
    // [suite_out:u16][usage_out:u32][tier_out:u8][persisted_out:u8].
    let mut d = [0u8; 8];
    let rc = (sys.provider_call)(key, kv::DESCRIBE, d.as_mut_ptr(), d.len());
    let suite = u16::from_le_bytes([d[0], d[1]]);
    let usage = u32::from_le_bytes([d[2], d[3], d[4], d[5]]);
    if rc < 0
        || suite != kv::suite::AEAD_KEY
        || usage & (kv::usage::SEAL | kv::usage::OPEN) != kv::usage::SEAL | kv::usage::OPEN
    {
        cont_vault_destroy(sys, key);
        return Err((sc::STATUS_CORRUPT, cu::why::VAULT));
    }
    // The recipient is spent; the slot holds the flow's key now.
    cont_vault_destroy(sys, recipient);
    s.cont_keys[ri] = EMPTY_CONT_KEY;
    while let Some(i) = cont_key_find(s, &[KEY_IMPORTED, KEY_DERIVED], flow, epoch) {
        cont_key_free(s, i);
    }
    cont_key_put(s, ri, KEY_IMPORTED, flow, epoch, key);
    custody_reply(s, flow, epoch, cu::UNWRAP, sc::STATUS_OK, 0, &[]);
    Ok(())
}

unsafe fn continuity_dispatch(s: &mut TlsState, msg_type: u8, payload: &[u8]) {
    match msg_type {
        sc::CMD_SC_PAIR_PREPARE => handle_pair_prepare(s, payload),
        sc::CMD_SC_CHECKPOINT_BEGIN => handle_checkpoint_begin(s, payload),
        sc::CMD_SC_CHECKPOINT_NEXT => handle_checkpoint_next(s, payload),
        sc::CMD_SC_CHECKPOINT_COMMIT => handle_checkpoint_commit(s, payload),
        sc::CMD_SC_DELTA_APPLY => handle_delta_apply(s, payload),
        sc::CMD_SC_DELTA_ACK => handle_delta_ack(s, payload),
        sc::CMD_SC_QUIESCE_BEGIN => handle_quiesce(s, payload, true),
        sc::CMD_SC_QUIESCE_STATUS => handle_quiesce(s, payload, false),
        sc::CMD_SC_CUT_EXPORT => handle_cut_export(s, payload),
        sc::CMD_SC_CUT_IMPORT => handle_cut_import(s, payload),
        sc::CMD_SC_EMISSION_ARM => handle_emission_arm(s, payload),
        sc::CMD_SC_ACTIVATE => handle_activate(s, payload),
        sc::CMD_SC_RETIRE => handle_retire(s, payload),
        sc::CMD_SC_ABORT => handle_abort(s, payload),
        sc::MSG_SC_CONTINUITY => handle_continuity_reply(s, payload),
        sc::CMD_SC_CUSTODY => handle_custody(s, payload),
        _ => {}
    }
}

/// Whether session `idx` still has deliveries to hand its worker again.
fn redelivery_pending(s: &TlsState, idx: usize) -> bool {
    s.redeliver_off < s.redeliver_len && s.redeliver_idx as usize == idx
}

/// Hand an activated standby's worker the deliveries the record carried,
/// in order, each through the ordinary clear-side path (`record_scratch`
/// and its pending drain), once the worker knows of the connection.
unsafe fn redeliver_step(s: &mut TlsState) -> bool {
    let mut did = false;
    while s.redeliver_off < s.redeliver_len {
        let idx = s.redeliver_idx as usize;
        let live = idx < s.sessions.len()
            && s.sessions[idx].state == SessionState::Ready
            && s.sessions[idx].conn_id == s.redeliver_conn;
        if !live {
            // The session is gone: so is what it owed its worker.
            cont_wipe(&mut s.redeliver[..s.redeliver_len as usize]);
            s.redeliver_len = 0;
            s.redeliver_off = 0;
            return did;
        }
        if s.sessions[idx].held_msg_type != 0
            || s.sessions[idx].peer_pending
            || s.sessions[idx].cont.resumed_owed
            || s.clear_pending_len > 0
        {
            return did;
        }
        let at = s.redeliver_off as usize;
        let l = usize::from(u16::from_le_bytes([s.redeliver[at], s.redeliver[at + 1]]));
        core::ptr::copy_nonoverlapping(
            s.redeliver.as_ptr().add(at + 2),
            core::ptr::addr_of_mut!(s.record_scratch) as *mut u8,
            l,
        );
        s.redeliver_off = (at + 2 + l) as u32;
        did = true;
        let conn = s.redeliver_conn;
        // The first delivery starts at the byte the consumer's predecessor
        // had consumed up to; the rest are whole.
        let mut off = usize::from(s.redeliver_trim).min(l);
        s.redeliver_trim = 0;
        if drain_clear_record(s, idx, conn, &mut off, l) {
            note_delivered(s, idx, l);
        } else {
            // The rest goes out with the ordinary pending drain, which
            // counts it delivered when it has.
            s.clear_pending_idx = idx as u16;
            s.clear_pending_off = off;
            s.clear_pending_len = l;
            s.clear_pending_conn = conn;
            return did;
        }
    }
    if s.redeliver_len > 0 {
        cont_wipe(&mut s.redeliver[..s.redeliver_len as usize]);
        s.redeliver_len = 0;
        s.redeliver_off = 0;
    }
    did
}

/// A session whose connection this module can move: an established one, or
/// one whose consumer closed it with continuity wired (`local_close`), its
/// close_notify sealed and its retransmit window kept.
fn session_movable(sess: &TlsSession) -> bool {
    sess.state == SessionState::Ready
        || (sess.state == SessionState::Closing && sess.local_close & LOCAL_CLOSE_SENT != 0)
}

/// Mirror our own close: the alert's RECORD_OUT went first (or is held and
/// mirrored with the hold); this delta says the close_notify is ours.
unsafe fn mirror_close_sent(s: &mut TlsState, idx: usize) {
    if !s.sessions[idx].cont.mirror {
        return;
    }
    if s.sessions[idx].cont.tx_hold_len != 0 {
        mirror_tx_hold(s, idx);
    }
    // The alert's RECORD_OUT must be ahead of this delta in the chain; an
    // alert still stalled for `cipher_out` has none yet.
    let unmirrored = {
        let c = &s.sessions[idx].cont;
        c.tx_hold_mirrored != c.tx_hold_len || tx_stalled(s, idx)
    };
    if unmirrored {
        mirror_abandon(s, idx);
        return;
    }
    let _ = delta_begin(s, idx, sc::DELTA_TLS_CLOSE_SENT);
    if !delta_finish(s, idx, 0) {
        mirror_abandon(s, idx);
    }
}

/// Our own close's transport half: `CMD_CLOSE` goes to `ip` only once every
/// record sealed before the alert — and the alert — has gone to
/// `cipher_out`, so `ip`'s FIN follows them. Under a strict horizon that is
/// after the standby acknowledged them.
unsafe fn local_close_step(s: &mut TlsState, idx: usize) -> bool {
    let sess = &s.sessions[idx];
    if sess.state != SessionState::Closing
        || sess.local_close != LOCAL_CLOSE_SENT
        || sess.cont.tx_hold_len != 0
        || tx_stalled(s, idx)
    {
        return false;
    }
    let conn_id = sess.conn_id;
    if !tls_write_or_count(
        s,
        s.cipher_out,
        NET_CMD_CLOSE,
        conn_id,
        core::ptr::null(),
        0,
    ) {
        return false;
    }
    s.sessions[idx].local_close |= LOCAL_CLOSE_FWD;
    true
}

// ── Step entry ──────────────────────────────────────────────────────

/// Drain cont_in and service outstanding holds. Runs before the data
/// ports so an acknowledgement releases a horizon in the same step.
unsafe fn continuity_step(s: &mut TlsState) -> bool {
    let mut did_work = false;
    let now = dev_millis(&*s.syscalls).max(1);
    cont_keys_sweep(s);
    if s.redeliver_len > 0 && redeliver_step(s) {
        did_work = true;
    }
    // Held records whose horizon is confirmed but whose write bounced.
    let mut i = 0;
    while i < s.sessions.len() {
        if session_movable(&s.sessions[i]) {
            if s.sessions[i].state == SessionState::Ready
                && s.sessions[i].cont.ku_answer_owed
                && s.sessions[i].cont.tx_hold_len == 0
                && !tx_stalled(s, i)
            {
                // `Blocked` leaves it owed for a later step.
                match send_key_update(s, i, KEY_UPDATE_NOT_REQUESTED) {
                    EmitOutcome::Sent | EmitOutcome::Held => {
                        let m = b"[tls] owed key update answered";
                        dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
                        did_work = true;
                    }
                    EmitOutcome::Blocked => {}
                    EmitOutcome::Failed => {
                        s.sessions[i].state = SessionState::Error;
                        did_work = true;
                    }
                }
            }
            if s.sessions[i].cont.mirror && s.sessions[i].cont.tx_hold_len != 0 {
                mirror_tx_hold(s, i);
            }
            release_tx_hold(s, i);
            if s.sessions[i].cont.mirror {
                continuity_rx_owed(s, i);
                mirror_consumed(s, i);
            }
            if local_close_step(s, i) {
                did_work = true;
            }
        }
        if s.sessions[i].cont.abandon_pending && flush_abandon(s, i) {
            did_work = true;
        }
        {
            let c = &mut s.sessions[i].cont;
            // Three promises are counted on the same budget: a horizon the
            // standby has not answered, a cut whose commit has not come
            // back, and a strict mirror's abort the coordinator has not
            // taken.
            let waiting = (c.mirror && c.strict() && c.horizon_outstanding())
                || c.cut_pending
                || c.abandon_blocks();
            if !waiting {
                c.horizon_since_ms = 0;
            } else if c.horizon_since_ms == 0 {
                c.horizon_since_ms = now;
            }
        }
        let since = s.sessions[i].cont.horizon_since_ms;
        if since != 0 && now.wrapping_sub(since) > CONT_HORIZON_MS {
            if s.sessions[i].cont.abandon_blocks() {
                // The abort cannot reach the coordinator, and the session
                // cannot wait on it for ever. Nor may it go on: whatever it
                // wrote now could be sealed again by a shadow the coordinator
                // still believes current. The connection ends instead, its
                // held records never written; the end of the session offers
                // the abort once more.
                let sys = &*s.syscalls;
                let msg: &[u8] =
                    b"[tls] continuity abort undeliverable; the strict session ends unsent";
                dev_log(sys, 1, msg.as_ptr(), msg.len());
                if s.sessions[i].state != SessionState::Idle {
                    s.sessions[i].state = SessionState::Error;
                }
                s.sessions[i].cont.horizon_since_ms = 0;
            } else {
                mirror_abandon_for(s, i, sc::ABORT_HORIZON_BUDGET);
            }
            did_work = true;
        }
        i += 1;
    }
    if s.cont_in < 0 {
        return did_work;
    }
    let sys = &*s.syscalls;
    let mut drained = 0u32;
    while drained < CONT_DRAIN_BUDGET {
        let poll = (sys.channel_poll)(s.cont_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let (msg_type, payload_len) = tls_read_header(sys, s.cont_in);
        if msg_type == 0 {
            break;
        }
        drained += 1;
        did_work = true;
        let pl = payload_len as usize;
        if pl > CONT_SCRATCH_SIZE {
            tls_discard(sys, s.cont_in, pl);
            continue;
        }
        let mut got = 0usize;
        while got < pl {
            let n = (sys.channel_read)(s.cont_in, s.cont_inbox.as_mut_ptr().add(got), pl - got);
            if n <= 0 {
                break;
            }
            got += n as usize;
        }
        if got != pl {
            continue;
        }
        // SAFETY: `cont_inbox` is written only here; every handler reads
        // its command from it and assembles replies in `cont_scratch`.
        let payload = core::slice::from_raw_parts(s.cont_inbox.as_ptr(), pl);
        continuity_dispatch(s, msg_type, payload);
    }
    did_work
}
