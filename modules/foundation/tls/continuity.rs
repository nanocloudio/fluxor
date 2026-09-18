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
// ever. Past `CONT_HORIZON_STEPS` the pair is abandoned — but what the
// horizon was holding is ordered behind the abort that tells the
// coordinator so, because a coordinator that has not been told may still
// activate the shadow, and those records are exactly what it would be
// missing. Only when the abort is away, or its own budget has run out
// too, do they go to the peer.
//
// ── Canonical record (CT_TLS, layout 1) ─────────────────────────────
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
//   [sni_len:1][sni:64]   the DNS identity a client sent as SNI
//   [peer_verified:1]     1 when the peer presented a credential that
//                         the session's profile accepted
//   [peer_profile:1]      the peer-authentication profile in force
//   [exporter_ctx:48]     transcript hash at the server Finished — the
//                         exporter context input (RFC 8446 §7.5)
//   [read_epoch:4][write_epoch:4]     traffic epochs (key updates seen)
//   [read_seq:8][write_seq:8]         next AEAD record sequence numbers
//   [key_update:1]        bit 0: an update we requested is outstanding
//   [close_notify:1]      0 none; only 0 is exportable
//   [pending_alert:1]     0 none (alerts are emitted, never queued)
//   [ticket:1]            0 none (no resumption state is retained)
//   [delivered_in:8]      records whose plaintext reached clear_out
//   [emitted_out:8]       records whose ciphertext reached cipher_out
//   [recv_expected:4][recv_len:4]         partial inbound record bytes
//   [retx_base_seq:4][retx_anchored:1][retx_len:2]
//                         retained outbound ciphertext (byte-identical
//                         retransmission unit) and its TCP anchor
//   [sealed_len:2]        TLS_SEALED_LEN
//   [recv: recv_len]      recv_buf[..recv_len]
//   [retx: retx_len]      retx_buf[..retx_len]
//   [sealed: sealed_len]  the SECRET SET, vault-sealed (below)
//
// The secret set never appears in the clear. It is
//   [hash_len:1][client_app_secret:48][server_app_secret:48]
//   [read_key_len:1][read_key:32][read_iv:12]
//   [write_key_len:1][write_key:32][write_iv:12]
// sealed by the kernel vault's AEAD key under the label
// `tls-continuity`, with AAD = flow_id ‖ epoch ‖ CT_TLS, so a sealed
// object binds to one flow and one ownership epoch and only a vault
// holding the same labelled key opens it. The record carries it and
// the `CONTINUITY{CUT}` manifest repeats it as the record's continuity
// object.
//
// Admission: only an established TLS 1.3 session (`SessionState::Ready`)
// is exportable. A session mid-handshake, closing, or in early data is
// refused `ABORT_UNSUPPORTED_STATE` — a checkpoint of a transcript in
// flight is a hole, not a smaller record.
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
// cipher_out until acknowledged; an inbound record is left at the head
// of recv_buf and not decrypted until its RECORD_IN is acknowledged;
// a write-side key update is a barrier — nothing is emitted in the new
// epoch until the KEY_UPDATE delta is acknowledged, and the retired
// keys are destroyed only then. While any hold is outstanding neither
// cipher_in nor clear_in is drained, so back-pressure reaches the
// producer and the TCP window instead of a queue. PROFILE_PLANNED
// mirrors asynchronously; the cut at CUT_EXPORT is what is exact.
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

/// The empty shadow, copied in place (see `EMPTY_SESSION`).
static EMPTY_SHADOW: TlsShadow = TlsShadow::empty();

/// Record layout admitted by the codec.
const TLS_CKPT_LAYOUT: u8 = 1;
/// Identity of the codec layout; its SHA-256 is the `codec_digest` a
/// PAIR_PREPARE must carry.
const TLS_CODEC_LABEL: [u8; 37] = *b"fluxor.tls.continuity.ct_tls.layout.1";
/// Vault label of the sealing key.
const TLS_CONTINUITY_LABEL: [u8; 14] = *b"tls-continuity";
/// TLS 1.3 on the wire.
const TLS_PROTOCOL_VERSION: u16 = 0x0304;

/// Secret-set plaintext, as laid out above.
const TLS_SECRET_SET_LEN: usize = 1 + 48 + 48 + 1 + 32 + 12 + 1 + 32 + 12;
/// The vault's AEAD framing: nonce and tag.
const VAULT_SEAL_OVERHEAD: usize = 12 + 16;
/// Sealed secret set.
const TLS_SEALED_LEN: usize = TLS_SECRET_SET_LEN + VAULT_SEAL_OVERHEAD;
/// AAD of a sealed object: flow_id ‖ epoch ‖ CT_TLS.
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
    + 48
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
    + 4
    + 4
    + 4
    + 1
    + 2
    + 2;
/// Largest CT_TLS record this build emits or accepts.
const TLS_CKPT_RECORD_MAX: usize = CKPT_FIXED_LEN + RECV_BUF_SIZE + RETX_BUF_SIZE + TLS_SEALED_LEN;

/// Delta payloads.
/// RECORD_OUT: `[write_epoch:4][write_seq:8][ct_len:2][ct...]`.
const DELTA_OUT_HDR: usize = 4 + 8 + 2;
/// RECORD_IN: `[read_epoch:4][read_seq:8][recv_expected:4][partial_len:4][partial...]`.
const DELTA_IN_HDR: usize = 4 + 8 + 4 + 4;
/// KEY_UPDATE: `[direction:1][epoch:4][sealed_len:2][sealed...]`.
const DELTA_KU_LEN: usize = 1 + 4 + 2 + TLS_SEALED_LEN;
const DELTA_DIR_WRITE: u8 = 0;
const DELTA_DIR_READ: u8 = 1;
/// Largest delta payload (a RECORD_IN carrying a full partial record).
const DELTA_PAYLOAD_MAX: usize = DELTA_IN_HDR + RECV_BUF_SIZE;
/// Offset of a DELTA_APPLY payload in the assembly scratch.
const DELTA_PAYLOAD_OFF: usize = sc::FRAME_HDR + sc::DELTA_APPLY_HEADER_LEN;
/// Assembly scratch for every frame this surface reads or writes.
const CONT_SCRATCH_SIZE: usize = DELTA_PAYLOAD_OFF + DELTA_PAYLOAD_MAX;
/// CUT manifest body.
const CUT_BODY_LEN: usize = 4 + 4 + 32 + 1 + 2 + TLS_SEALED_LEN;
/// Reply assembly: header, continuity header, the largest body.
const REPLY_MAX: usize = sc::FRAME_HDR + sc::CONTINUITY_HEADER_LEN + CUT_BODY_LEN;
/// Frames drained from cont_in per step.
const CONT_DRAIN_BUDGET: u32 = 8;
/// Outbound records one session may hold for its send horizon: every
/// record one `CMD_SEND` (`MAX_CMD_DATA` bytes) can produce, since the
/// clear-side frame is consumed whole.
const TX_HOLD_RECORDS: usize =
    abi::contracts::net::net_proto::MAX_CMD_DATA.div_ceil(CLEAR_CHUNK_MAX);
const TX_HOLD_SIZE: usize = TX_HOLD_RECORDS * WIRE_RECORD_MAX;
/// Steps a strict horizon may stay unconfirmed before the mirror is
/// abandoned. The inputs are one channel for every session, so a horizon
/// freezes them all; a standby that has stopped answering must not hold
/// the whole instance hostage. Generous against any real round trip, so a
/// slow standby is tolerated and only a dead one is given up on.
const CONT_HORIZON_STEPS: u32 = 2000;
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
        match (hl, rkl, wkl) {
            (Some(hl), Some(rkl), Some(wkl)) if ok => {
                if !(hl == 32 || hl == 48) || rkl as usize > 32 || wkl as usize > 32 {
                    return false;
                }
                self.hash_len = hl;
                self.read_key_len = rkl;
                self.write_key_len = wkl;
                true
            }
            _ => false,
        }
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
    peer_verified: u8,
    peer_profile: u8,
    exporter_ctx: [u8; 48],
    read_epoch: u32,
    write_epoch: u32,
    read_seq: u64,
    write_seq: u64,
    key_update: u8,
    delivered_in: u64,
    emitted_out: u64,
    recv_expected: u32,
    recv_len: u32,
    recv: [u8; RECV_BUF_SIZE],
    retx_base_seq: u32,
    retx_anchored: bool,
    retx_len: u16,
    retx: [u8; RETX_BUF_SIZE],
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
            peer_verified: 0,
            peer_profile: 0,
            exporter_ctx: [0; 48],
            read_epoch: 0,
            write_epoch: 0,
            read_seq: 0,
            write_seq: 0,
            key_update: 0,
            delivered_in: 0,
            emitted_out: 0,
            recv_expected: 0,
            recv_len: 0,
            recv: [0; RECV_BUF_SIZE],
            retx_base_seq: 0,
            retx_anchored: false,
            retx_len: 0,
            retx: [0; RETX_BUF_SIZE],
            secrets: SecretSet::empty(),
        }
    }

    fn wipe(&mut self) {
        self.secrets.wipe();
        cont_wipe(&mut self.recv);
        cont_wipe(&mut self.retx);
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
        self.emitted_out = 0;
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
    /// The mirror was abandoned and the abort has not yet left `cont_out`.
    abandon_pending: bool,
    /// Steps a strict horizon has been outstanding. A horizon is a promise
    /// the standby confirms within a bounded time; one it never confirms
    /// would otherwise freeze this instance's inputs for every session.
    horizon_steps: u32,
    quiescing: bool,
    ckpt_gen: u32,
    next_delta: u32,
    acked_delta: u32,
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
    /// Write-side key-update barrier.
    write_barrier_pending: bool,
    write_barrier_delta: u32,
    /// Keys of the retired write epoch, kept until their ciphertext is
    /// acknowledged.
    retired_write: TrafficKeys,
    retired_pending: bool,
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
            horizon_steps: 0,
            quiescing: false,
            ckpt_gen: 0,
            next_delta: 1,
            acked_delta: 0,
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
            write_barrier_pending: false,
            write_barrier_delta: 0,
            retired_write: TrafficKeys::empty(),
            retired_pending: false,
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
        self.horizon_steps = 0;
        self.quiescing = false;
        self.ckpt_gen = 0;
        self.next_delta = 0;
        self.acked_delta = 0;
        self.last_digest = [0; 32];
        self.tx_hold_len = 0;
        self.tx_hold_mirrored = 0;
        self.tx_hold_delta = 0;
        self.tx_hold_released = false;
        self.ckpt_digest = [0; 32];
        self.rx_hold_pending = false;
        self.rx_hold_delta = 0;
        self.rx_released = false;
        self.write_barrier_pending = false;
        self.write_barrier_delta = 0;
        self.retired_pending = false;
        self.delivered_in = 0;
        self.emitted_out = 0;
    }

    fn strict(&self) -> bool {
        self.profile == sc::PROFILE_CRASH_CONTINUOUS
    }

    /// A transition of this session is waiting on the standby.
    fn horizon_outstanding(&self) -> bool {
        self.tx_hold_len != 0 || self.rx_hold_pending || self.write_barrier_pending
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
// `KEY_VAULT` is a kernel contract class every module may call. The
// sealing key is opened by label so a standby's vault yields the same
// key; the handle is cached and re-opened on demand.

/// `OPEN_OR_GENERATE` an AEAD key under `label`; the handle, or -1.
unsafe fn cont_vault_open_or_generate_aead(sys: &SyscallTable, label: &[u8]) -> i32 {
    let mut arg = [0u8; 8 + 64 + 12];
    arg[0..2].copy_from_slice(&8u16.to_le_bytes()); // suite::AEAD_KEY
    let usage: u32 = (1 << 6) | (1 << 7) | (1 << 4) | (1 << 5); // SEAL|OPEN|PERSIST|WRAP
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[6] = 0;
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let n = 8 + label.len() + 12;
    let rc = (sys.provider_call)(-1, 0x1009, arg.as_mut_ptr(), n);
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
    let rc = (sys.provider_call)(handle, 0x1012, arg.as_mut_ptr(), p + 12);
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
    let rc = (sys.provider_call)(handle, 0x1013, arg.as_mut_ptr(), p + 12);
    if rc < 0 {
        return 0;
    }
    u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize
}

/// The sealing-key handle, opening it on first use. -1 when no vault
/// answers: continuity that cannot be sealed is not offered.
unsafe fn cont_vault_handle(s: &mut TlsState) -> i32 {
    if s.cont_vault_handle >= 0 {
        return s.cont_vault_handle;
    }
    let sys = &*s.syscalls;
    s.cont_vault_handle = cont_vault_open_or_generate_aead(sys, &TLS_CONTINUITY_LABEL);
    s.cont_vault_handle
}

/// AAD for a checkpoint's secret set. The sequence numbers and traffic
/// epochs travel in the clear beside the seal, so they are bound here:
/// a record whose counters were rewritten carries a seal made under the
/// originals, and does not open. Without this a standby could be made to
/// resume at a sequence the peer has already seen under the same key.
fn ckpt_aad(
    flow: &[u8; sc::FLOW_ID_BYTES],
    epoch: u32,
    read_epoch: u32,
    write_epoch: u32,
    read_seq: u64,
    write_seq: u64,
) -> [u8; CONT_AAD_LEN] {
    let mut a = [0u8; CONT_AAD_LEN];
    let mut e = Enc::new(a.as_mut_ptr(), CONT_AAD_LEN);
    e.bytes(flow);
    e.u32(epoch);
    e.u8(sc::CT_TLS);
    e.u8(AAD_KIND_CHECKPOINT);
    e.u32(read_epoch);
    e.u32(write_epoch);
    e.u64(read_seq);
    e.u64(write_seq);
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
    let handle = cont_vault_handle(s);
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

/// Open a sealed secret set into `set`.
unsafe fn open_secret_set(
    s: &mut TlsState,
    aad: &[u8; CONT_AAD_LEN],
    sealed: &[u8],
    set: &mut SecretSet,
) -> bool {
    if sealed.len() != TLS_SEALED_LEN {
        return false;
    }
    let handle = cont_vault_handle(s);
    if handle < 0 {
        return false;
    }
    let mut pt = [0u8; TLS_SECRET_SET_LEN];
    let sys = &*s.syscalls;
    let n = cont_vault_open(sys, handle, aad, sealed, &mut pt);
    let ok = n == TLS_SECRET_SET_LEN && set.decode(&pt);
    cont_wipe(&mut pt);
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
        ckpt_aad(
            flow,
            epoch,
            sess.read_epoch,
            sess.write_epoch,
            sess.read_keys.seq,
            sess.write_keys.seq,
        )
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
    let sni_len = if sess.driver.is_server {
        0
    } else {
        s.expected_dns_len.min(CKPT_SNI_MAX)
    };
    e.u8(sni_len as u8);
    let mut sni = [0u8; CKPT_SNI_MAX];
    sni[..sni_len].copy_from_slice(&s.expected_dns[..sni_len]);
    e.bytes(&sni);
    e.u8((sess.driver.peer_cert_pubkey_len != 0) as u8);
    e.u8(s.peer_auth);
    e.bytes(&sess.driver.server_finished_hash);
    e.u32(sess.read_epoch);
    e.u32(sess.write_epoch);
    e.u64(sess.read_keys.seq);
    e.u64(sess.write_keys.seq);
    e.u8(0); // key_update: no request of ours outstanding
    e.u8(0); // close_notify: a Ready session has neither sent nor received one
    e.u8(0); // pending_alert
    e.u8(0); // ticket
    e.u64(sess.cont.delivered_in);
    e.u64(sess.cont.emitted_out);
    e.u32(sess.recv_expected as u32);
    e.u32(sess.recv_len as u32);
    e.u32(sess.retx_base_seq);
    e.u8(sess.retx_seq_anchored as u8);
    e.u16(sess.retx_len);
    e.u16(TLS_SEALED_LEN as u16);
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
    let sni_len = match d.u8() {
        Some(n) if n as usize <= CKPT_SNI_MAX => n,
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
    let mut exporter_ctx = [0u8; 48];
    if !d.take_into(&mut exporter_ctx) {
        return false;
    }
    let (read_epoch, write_epoch) = match (d.u32(), d.u32()) {
        (Some(r), Some(w)) => (r, w),
        _ => return false,
    };
    let (read_seq, write_seq) = match (d.u64(), d.u64()) {
        (Some(r), Some(w)) => (r, w),
        _ => return false,
    };
    let key_update = match d.u8() {
        Some(k) if k <= 1 => k,
        _ => return false,
    };
    // close_notify, pending_alert, ticket: only the empty state is a
    // representable one.
    if d.u8() != Some(0) || d.u8() != Some(0) || d.u8() != Some(0) {
        return false;
    }
    let (delivered_in, emitted_out) = match (d.u64(), d.u64()) {
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
    // Every variable range must be present, and nothing may follow.
    if d.remaining() != recv_len as usize + retx_len as usize + sealed_len {
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
    let sealed_p = match d.take(sealed_len) {
        Some(p) => p,
        None => return false,
    };
    let sealed = core::slice::from_raw_parts(sealed_p, sealed_len);
    let aad = ckpt_aad(flow, epoch, read_epoch, write_epoch, read_seq, write_seq);
    if !open_secret_set(s, &aad, sealed, &mut ck.secrets) {
        return false;
    }
    // The suite's key length must be what the sealed set carries.
    let suite_kl = match CipherSuite::from_id(suite) {
        Some(cs) => cs.key_len() as u8,
        None => return false,
    };
    if ck.secrets.read_key_len != suite_kl || ck.secrets.write_key_len != suite_kl {
        ck.secrets.wipe();
        return false;
    }
    ck.suite = suite;
    ck.is_server = role == 1;
    ck.conn_id = conn_id;
    ck.alpn = alpn;
    ck.alpn_len = alpn_len;
    ck.sni = sni;
    ck.sni_len = sni_len;
    ck.peer_verified = peer_verified;
    ck.peer_profile = peer_profile;
    ck.exporter_ctx = exporter_ctx;
    ck.read_epoch = read_epoch;
    ck.write_epoch = write_epoch;
    ck.read_seq = read_seq;
    ck.write_seq = write_seq;
    ck.key_update = key_update;
    ck.delivered_in = delivered_in;
    ck.emitted_out = emitted_out;
    ck.recv_expected = recv_expected;
    ck.recv_len = recv_len;
    core::ptr::copy_nonoverlapping(recv_p, ck.recv.as_mut_ptr(), recv_len as usize);
    ck.retx_base_seq = retx_base_seq;
    ck.retx_anchored = retx_anchored;
    ck.retx_len = retx_len;
    core::ptr::copy_nonoverlapping(retx_p, ck.retx.as_mut_ptr(), retx_len as usize);
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
    sess.cont.epoch == epoch
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
    if s.cont_out < 0 || flow.len() != sc::FLOW_ID_BYTES || body.len() > CUT_BODY_LEN {
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
    true
}

/// The mirror could not carry a transition. From here the primary runs
/// unmirrored, and the standby's shadow is stale from this record on: a
/// takeover onto it would resume at counters the peer has already seen.
/// So the pair is over, and the abort is owed to the coordinator whatever
/// the channel's state — it is the very channel that just refused a delta
/// — so it is marked and sent from the step until it goes.
///
/// What the horizons hold is not let go until that abort is away. A
/// coordinator that has not been told the pair is over may still fence and
/// activate the shadow, and records shown to the peer in the meantime are
/// exactly the ones the shadow would then be missing. Ordering the abort
/// ahead of them leaves the coordinator no window in which it could
/// believe the shadow current.
unsafe fn mirror_abandon(s: &mut TlsState, idx: usize) {
    mirror_lost(s, idx);
    s.sessions[idx].cont.abandon_pending = true;
    // Delivering the abort is a promise of its own, and gets its own
    // budget: a horizon that has just run out must not spend the abort's
    // as well, or the records it is ordered ahead of would go at once.
    s.sessions[idx].cont.horizon_steps = 0;
    flush_abandon(s, idx);
}

/// Send the owed abort for an abandoned mirror; answers whether it went.
/// Its departure is what releases the holds.
unsafe fn flush_abandon(s: &mut TlsState, idx: usize) -> bool {
    if !s.sessions[idx].cont.abandon_pending {
        return true;
    }
    let (flow, epoch) = {
        let c = &s.sessions[idx].cont;
        (c.flow_id, c.epoch)
    };
    if cont_reply(
        s,
        &flow,
        epoch,
        sc::CR_ABORTED,
        sc::STATUS_OK,
        &[sc::ABORT_MIRROR_LOST],
    ) {
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

unsafe fn mirror_lost(s: &mut TlsState, idx: usize) {
    let sys = &*s.syscalls;
    let msg: &[u8] = b"[tls] continuity mirror lost; connection continues unmirrored";
    dev_log(sys, 2, msg.as_ptr(), msg.len());
    let c = &mut s.sessions[idx].cont;
    c.mirror = false;
    c.cut_pending = false;
    c.rx_hold_pending = false;
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
    let no = delta_begin(s, idx, sc::DELTA_TLS_RECORD_OUT);
    let (epoch, seq) = {
        let sess = &s.sessions[idx];
        (sess.write_epoch, sess.write_keys.seq.wrapping_sub(1))
    };
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u32(epoch);
    e.u64(seq);
    e.u16(total as u16);
    e.raw(rec, total);
    if !e.ok {
        return 0;
    }
    if delta_finish(s, idx, e.pos) {
        no
    } else {
        0
    }
}

/// Mirror the consumption of the inbound record at the head of
/// recv_buf (`rec_len` payload bytes): the read sequence it advances
/// to and the partial record left behind it.
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
        *base = base.wrapping_add(u32::from(*len));
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

/// Drop retained bytes up to `acked_seq`. Anchors the base on the first
/// acknowledgement, because the transport names absolute sequences and
/// the window was filled before the first one arrived.
fn retx_slide(buf: &mut [u8], len: &mut u16, base: &mut u32, anchored: &mut bool, acked_seq: u32) {
    if !*anchored {
        *base = acked_seq.wrapping_sub(u32::from(*len));
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

/// Mirror the retransmit window sliding on a transport acknowledgement.
unsafe fn mirror_retx_ack(s: &mut TlsState, idx: usize, acked_seq: u32) -> u32 {
    let no = delta_begin(s, idx, sc::DELTA_TLS_RETX_ACK);
    let mut e = Enc::new(
        s.cont_scratch.as_mut_ptr().add(DELTA_PAYLOAD_OFF),
        DELTA_PAYLOAD_MAX,
    );
    e.u32(acked_seq);
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
unsafe fn continuity_after_retx_ack(s: &mut TlsState, idx: usize, acked_seq: u32) {
    if s.sessions[idx].cont.mirror && mirror_retx_ack(s, idx, acked_seq) == 0 {
        mirror_abandon(s, idx);
    }
}

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
        {
            let c = &mut s.sessions[idx].cont;
            let len = c.tx_hold_len as usize;
            if c.tx_hold_released || total > TX_HOLD_SIZE - len {
                return EmitOutcome::Failed;
            }
            core::ptr::copy_nonoverlapping(rec, c.tx_hold.as_mut_ptr().add(len), total);
            c.tx_hold_len = (len + total) as u16;
        }
        mirror_tx_hold(s, idx);
        return EmitOutcome::Held;
    }
    if mirror && mirror_record_out(s, idx, rec, total) == 0 {
        mirror_abandon(s, idx);
    }
    if write_record_now(s, idx, rec, total) {
        EmitOutcome::Sent
    } else {
        EmitOutcome::Failed
    }
}

/// The unconditional write: cipher_out, byte accounting, retention.
unsafe fn write_record_now(s: &mut TlsState, idx: usize, rec: *const u8, total: usize) -> bool {
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
        let mut local = [0u8; WIRE_RECORD_MAX];
        local[..total].copy_from_slice(&s.sessions[idx].cont.tx_hold[off..off + total]);
        let no = mirror_record_out(s, idx, local.as_ptr(), total);
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
            // Not a record: the hold is unusable and is dropped.
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
        }
        let acked = c.acked_delta;
        if c.tx_hold_len != 0 && c.tx_hold_mirrored == c.tx_hold_len && c.tx_hold_delta <= acked {
            c.tx_hold_released = true;
        }
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
    }
    release_tx_hold(s, idx);
}

/// The record at the head of recv_buf (`rec_len` payload bytes) may be
/// consumed now. `false` leaves it in place for a later step.
unsafe fn continuity_rx_gate(s: &mut TlsState, idx: usize, rec_len: usize) -> bool {
    let (mirror, strict, released, pending, tx_busy, barrier) = {
        let c = &s.sessions[idx].cont;
        (
            c.mirror,
            c.strict(),
            c.rx_released,
            c.rx_hold_pending,
            c.tx_hold_len != 0,
            c.write_barrier_pending,
        )
    };
    if !mirror {
        return true;
    }
    if released {
        s.sessions[idx].cont.rx_released = false;
        return true;
    }
    if pending {
        return false;
    }
    if strict && (tx_busy || barrier) {
        // One horizon in flight per session: a key-update answer to
        // this record needs the hold slot free.
        return false;
    }
    let no = mirror_record_in(s, idx, rec_len);
    if no == 0 {
        if strict {
            return false;
        }
        mirror_abandon(s, idx);
        return true;
    }
    if strict {
        let c = &mut s.sessions[idx].cont;
        c.rx_hold_pending = true;
        c.rx_hold_delta = no;
        return false;
    }
    true
}

/// A record's plaintext reached clear_out.
fn note_delivered(sess: &mut TlsSession) {
    sess.cont.delivered_in = sess.cont.delivered_in.wrapping_add(1);
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
        if s.sessions[i].state != SessionState::Idle && (c.horizon_outstanding() || c.cut_pending) {
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
            && (c.horizon_outstanding() || c.cut_pending || c.quiescing)
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
    let pending_out: u32 = (sess.cont.tx_hold_len != 0) as u32;
    let head_complete = sess.recv_len >= RECORD_HEADER_LEN && {
        let rl = ((sess.recv_buf[3] as usize) << 8) | sess.recv_buf[4] as usize;
        sess.recv_len >= RECORD_HEADER_LEN + rl
    };
    let pending_in: u32 = head_complete as u32;
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
    if s.sessions[idx].state != SessionState::Ready || s.sessions[idx].cont.horizon_outstanding() {
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
    if record == sc::CR_ABORTED {
        // The primary abandoned the pair. Whatever this shadow holds is
        // stale from that moment, so it is released here rather than left
        // armed for a coordinator to activate.
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
        mirror_lost(s, idx);
        s.sessions[idx].cont.quiescing = false;
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
        ckpt_ack(s, flow, epoch, gen, offset + data.len() as u32, st);
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

/// Apply one delta's payload to the shadow's checkpoint. `false` is a
/// contradiction with the state held — the shadow is discarded.
unsafe fn shadow_apply_delta(s: &mut TlsState, sh: usize, kind: u8, data: &[u8]) -> bool {
    let (flow, epoch) = (s.shadows[sh].flow_id, s.shadows[sh].epoch);
    let ck: *mut TlsCheckpoint = &mut s.shadows[sh].ck;
    let ck = &mut *ck;
    let mut d = Dec::new(data.as_ptr(), data.len());
    match kind {
        sc::DELTA_TLS_RECORD_OUT => {
            let (ep, seq, n) = match (d.u32(), d.u64(), d.u16()) {
                (Some(a), Some(b), Some(c)) => (a, b, c as usize),
                _ => return false,
            };
            if ep != ck.write_epoch || seq != ck.write_seq || d.remaining() != n || n == 0 {
                return false;
            }
            let src = match d.take(n) {
                Some(p) => p,
                None => return false,
            };
            ck.write_seq = seq.wrapping_add(1);
            ck.emitted_out = ck.emitted_out.wrapping_add(1);
            let rec = core::slice::from_raw_parts(src, n);
            retx_push_window(&mut ck.retx, &mut ck.retx_len, &mut ck.retx_base_seq, rec);
            true
        }
        sc::DELTA_TLS_RECORD_IN => {
            let (ep, seq, expected, n) = match (d.u32(), d.u64(), d.u32(), d.u32()) {
                (Some(a), Some(b), Some(c), Some(e)) => (a, b, c, e as usize),
                _ => return false,
            };
            if ep != ck.read_epoch
                || seq != ck.read_seq.wrapping_add(1)
                || n > RECV_BUF_SIZE
                || d.remaining() != n
            {
                return false;
            }
            let src = match d.take(n) {
                Some(p) => p,
                None => return false,
            };
            ck.read_seq = seq;
            ck.delivered_in = ck.delivered_in.wrapping_add(1);
            ck.recv_expected = expected;
            cont_wipe(&mut ck.recv[..ck.recv_len as usize]);
            core::ptr::copy_nonoverlapping(src, ck.recv.as_mut_ptr(), n);
            ck.recv_len = n as u32;
            true
        }
        sc::DELTA_TLS_RETX_ACK => {
            let Some(acked) = d.u32() else {
                return false;
            };
            if d.remaining() != 0 {
                return false;
            }
            retx_slide(
                &mut ck.retx,
                &mut ck.retx_len,
                &mut ck.retx_base_seq,
                &mut ck.retx_anchored,
                acked,
            );
            true
        }
        sc::DELTA_TLS_RECV_BYTES => {
            let Some(n) = d.u32() else {
                return false;
            };
            let n = n as usize;
            if n > RECV_BUF_SIZE || d.remaining() != n {
                return false;
            }
            let Some(src) = d.take(n) else {
                return false;
            };
            cont_wipe(&mut ck.recv[..ck.recv_len as usize]);
            core::ptr::copy_nonoverlapping(src, ck.recv.as_mut_ptr(), n);
            ck.recv_len = n as u32;
            true
        }
        sc::DELTA_TLS_KEY_UPDATE => {
            let (dir, ep, n) = match (d.u8(), d.u32(), d.u16()) {
                (Some(a), Some(b), Some(c)) => (a, b, c as usize),
                _ => return false,
            };
            if n != TLS_SEALED_LEN || d.remaining() != n {
                return false;
            }
            let expected = match dir {
                DELTA_DIR_WRITE => ck.write_epoch.wrapping_add(1),
                DELTA_DIR_READ => ck.read_epoch.wrapping_add(1),
                _ => return false,
            };
            if ep != expected {
                return false;
            }
            let sealed = match d.take(n) {
                Some(p) => core::slice::from_raw_parts(p, n),
                None => return false,
            };
            let mut set = SecretSet::empty();
            let aad = ku_aad(&flow, epoch, dir, ep);
            if !open_secret_set(s, &aad, sealed, &mut set) {
                return false;
            }
            ck.secrets.wipe();
            ck.secrets.copy_from(&set);
            set.wipe();
            if dir == DELTA_DIR_WRITE {
                ck.write_epoch = ep;
                ck.write_seq = 0;
            } else {
                ck.read_epoch = ep;
                ck.read_seq = 0;
            }
            true
        }
        _ => false,
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
    if !shadow_apply_delta(s, sh, kind, data) {
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
    // The clear-side consumer learns of the connection the ordinary way.
    sess.held_msg_type = if ck.is_server {
        NET_MSG_ACCEPTED
    } else {
        NET_MSG_CONNECTED
    };
    sess.state = SessionState::Ready;
    s.sess_ready_total = s.sess_ready_total.wrapping_add(1);
    s.shadows[sh].release();
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
    if find_session_by_conn_id(s, conn_id) >= 0 {
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

// ── Step entry ──────────────────────────────────────────────────────

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
        _ => {}
    }
}

/// Drain cont_in and service outstanding holds. Runs before the data
/// ports so an acknowledgement releases a horizon in the same step.
unsafe fn continuity_step(s: &mut TlsState) -> bool {
    let mut did_work = false;
    // Held records whose horizon is confirmed but whose write bounced.
    let mut i = 0;
    while i < s.sessions.len() {
        if s.sessions[i].state == SessionState::Ready {
            if s.sessions[i].cont.mirror && s.sessions[i].cont.tx_hold_len != 0 {
                mirror_tx_hold(s, i);
            }
            release_tx_hold(s, i);
        }
        if s.sessions[i].cont.abandon_pending && flush_abandon(s, i) {
            did_work = true;
        }
        {
            let c = &mut s.sessions[i].cont;
            // Two promises are counted on the same budget: a horizon the
            // standby has not answered, and an abort the coordinator has
            // not taken.
            let waiting = (c.mirror && c.strict() && c.horizon_outstanding()) || c.abandon_pending;
            if waiting {
                c.horizon_steps = c.horizon_steps.saturating_add(1);
            } else {
                c.horizon_steps = 0;
            }
        }
        if s.sessions[i].cont.horizon_steps > CONT_HORIZON_STEPS {
            if s.sessions[i].cont.abandon_pending {
                // The abort cannot reach the coordinator and the records
                // cannot wait on it for ever. They go, and the log says
                // what a takeover would be resuming behind. The abort
                // stays owed, and the step keeps offering it.
                if !s.sessions[i].cont.tx_hold_released {
                    let sys = &*s.syscalls;
                    let msg: &[u8] =
                        b"[tls] continuity abort undeliverable; releasing held records,                           any shadow is now behind the peer";
                    dev_log(sys, 1, msg.as_ptr(), msg.len());
                }
                release_after_abort(s, i);
                s.sessions[i].cont.horizon_steps = 0;
            } else {
                mirror_abandon(s, i);
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
