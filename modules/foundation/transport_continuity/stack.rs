// transport_continuity / stack — TRANSPORT_CONTINUITY realised over the
// halves `ip` and `tls` already checkpoint, rather than over state of its own.
//
// Include after `contracts/net/transport_continuity.rs`,
// `cores/transport_continuity.rs` and `cores/session_handoff.rs`, with
// `sha256` / `Sha256` in scope and `sc` naming `contracts/net/session_ctrl.rs`.
// Pure: no syscalls, no allocation; the module around it moves frames.
//
// ── Two surfaces, one connection ──────────────────────────────────────────
//
// `ip` and `tls` each answer the per-layer continuity surface
// (session_ctrl.rs §Transport continuity) for their half of a connection:
// `ip` checkpoints its TCP control block (`FXTC`), `tls` its record layer
// (`CT_TLS`) with the secret set sealed by the kernel vault.
// `TRANSPORT_CONTINUITY` is the single-flow surface an anchor drives,
// with both halves in ONE canonical record (`TsState`). This file is the
// bridge: an anchor's operations become per-layer commands to the two
// modules, and the record is COMPOSED from the two per-layer records the
// primary exports and DECOMPOSED back into two per-layer records the standby
// imports. Neither half's state is duplicated here — the bridge holds the
// canonical record of a flow only while it is moving (the primary's export,
// the standby's shadow), and the live connection stays the modules'.
//
// What maps how (compose; decompose inverts it):
//
// - tuple: FXTC local/remote address and ports → `service_*` / `client_*`
//   (IPv4). The flow is named by `ip`'s tuple identity
//   (`[local_ip][remote_ip][local_port][remote_port][0;4]`, big-endian), on
//   both hosts — the tuple is what survives a move of a VIP's connection.
// - sequence space, windows, congestion, recovery, out-of-order segments:
//   FXTC, field for field (`u16` widened). IRS is not in FXTC; it is
//   `RCV.NXT − 1 − delivered`, `ip`'s count of in-order bytes handed up.
// - timers: FXTC holds the RTT estimator and the retransmit timer's
//   remainder in milliseconds (RFC 6298 fixed point: SRTT × 8, RTTVAR × 4)
//   and its other remaining durations in 50 ms ticks; the record holds
//   milliseconds. The RTO travels as `rto_ms` (the standby waits one full
//   RTO before retransmitting, the conservative reading), the idle timer as
//   `keepalive_ms` (0 = disabled). SRTT/RTTVAR scale exactly.
// - the send buffer: `ip` holds no unacknowledged bytes — `tls` retains the
//   exact ciphertext it handed down (its retransmit window) — so
//   `send[SND.UNA..SND.NXT)` comes from `tls`'s window, and the outbound
//   records tiling it from parsing that window's record headers, numbered
//   back from the write sequence. The window must be anchored to sequence
//   space and cover exactly what is in flight, or the state is not
//   exported. `ip`'s `MSG_ACK` anchors it (with the stream's first sequence
//   number) and slides it to SND.UNA, so a quiesced cut carries the bytes
//   in flight; the standby's `tls` resends them on `ip`'s MSG_RETRANSMIT.
// - the receive buffer: `tls`'s partial inbound record (bytes `ip` delivered
//   that do not yet form a record).
// - TLS: suite, epochs (the record counts the first application epoch as 3
//   — TLS 1.3's numbering — `tls`
//   counts key updates from 0), record sequences, peer verification,
//   delivery and production cursors (at a checkpoint, what `tls` has handed
//   up counts as consumed: `delivery_acked = next_delivery − 1`; after it,
//   a crash-continuous stream carries each delivery and its consumption).
// - keys: never here. The secret set stays sealed by `tls`'s vault under the
//   flow's sealing key (derived in the vault from its continuity master for
//   the tls flow and ownership epoch), bound by AAD to the tls flow, the
//   ownership epoch and the two epochs it was sealed at, with the record
//   sequences at the seal inside it as floors (CT_TLS carries them): the record
//   may resume past them — a standby's, moved on by deltas, KeyUpdates
//   included, which `tls` derives forward at import — never before. It
//   travels as the WRAPPED CONTINUITY OBJECT (`TcsWrapped`, below) with the
//   sealed epochs, beside the identity the record names only by digest —
//   ALPN, SNI, the exporter context, the peer-auth profile and the peer
//   block (the transport peer, a client's requester tag, the peer identity,
//   `CT_PEER_LEN`) — and
//   `wrapped_digest` binds the record to it. `read_key` / `write_key` name
//   it: backend `TCS_VAULT_BACKEND`, object = the wrapped digest's head,
//   generation = the ownership epoch it was sealed under, epoch = the record's
//   (a KeyUpdate moves the reference, never the object). A standby "holds" a
//   key exactly when it holds that object; it opens where the vault holds the
//   flow's sealing key — derived from a shared master, or moved there by
//   CUSTODY_* (below).
// - custody: CUSTODY_ATTEST at a standby has its `tls` attest a fresh
//   recipient over the transfer's challenge (named by the record's flow: `tls`
//   holds no session for it yet); CUSTODY_WRAP at a primary checks the
//   evidence's shape and challenge, asks the authority (`TCS_MSG_CUSTODY_*`)
//   and on its verdict has `tls` verify the signature and wrap the flow's key
//   to the recipient; CUSTODY_UNWRAP at the standby has `tls` unwrap it for
//   the session the wrapped object names. Only evidence and a wrapped key
//   cross.
// - carried: the anchor's service id, mirror generation and the generations
//   no module half keeps (route, binding, session epoch, address
//   generation, interface) ride with the flow through every hop.
//
// Every composition is checked by decomposing it again: a state whose
// per-layer records would not come back as the modules exported them is
// refused rather than moved approximately.
//
// ── What the bridge enforces, and what it does not ────────────────────────
//
// In: PAIR_PREPARE (both roles), the quiesced planned cut (QUIESCE_BEGIN /
// STATUS — quiescent is both halves drained; bytes in flight move —
// CHECKPOINT_BEGIN after the quiesce, CUT_EXPORT re-exporting both halves
// and reporting the checkpoint's digest only if nothing moved),
// the standby's whole import (chunks, publish, ordered deltas into the
// shadow, CUT_IMPORT, EMISSION_ARM importing both halves into silent
// per-layer shadows), ACTIVATE (fail-closed checks, then the authority's
// verdict on the per-flow token this provider rebuilds for its own anchor,
// then `ip` and `tls` activated, `tls` bound to the connection `ip` names;
// a `tls` that refuses after `ip` took the connection has `ip` reset it),
// EMISSION_DISABLE (the enforceable cutoff: both modules drop the
// connection silently, so `ip` never emits for it again; STATUS value the
// custody generation; one-way, as in the core), RETIRE and ABORT. `ip`
// drops a segment for a flow it holds as a shadow or retired within its
// tombstone window instead of resetting it, and installs the anchor's
// TOMBSTONE for a flow it never held (`TCS_IP_TOMBSTONE`).
//
// Crash continuity: a CrashContinuous primary pairs both halves under the
// strict per-layer profile. Its checkpoint is taken quiesced, as a planned
// one; then each half is told its checkpoint is held, which turns its
// mirror on and ends its quiesce, and from then on every per-layer delta
// becomes deltas on this primary's stream (`layer_delta`):
//
// - `tls` RECV_BYTES — the partial record as it now stands — is the
//   `RxSegment` of what it holds past the record's receive buffer; `ip`'s RECV
//   carries no bytes and waits for the receive horizon to reach its
//   RCV.NXT.
// - `tls` RECORD_IN, which under the strict profile carries the record's
//   inner type and plaintext (`tls` opens the record, holds the plaintext
//   and mirrors it), is an `RxRecord` delivering it; `tls`'s private
//   DELIVERED delta (its consumer's acknowledgement) is the `DeliveryAck`.
// - `tls` RECORD_OUT is a `TxRecord`, the next production; `ip`'s SEND
//   waits for the emission horizon to cover it; `ip`'s ACKED is a
//   `PeerAck` (`tls`'s window slide is that same acknowledgement); `ip`'s
//   TIMERS is a `Timers`.
// - `tls` KEY_UPDATE is a `KeyUpdate`: the direction's next epoch and a
//   reference to its secret in the wrapped object (the sealed set it carries
//   is not forwarded — the standby's `tls` derives the secret at import); a
//   write rotation is `tls`'s barrier, released when the gate covers it.
//
// Each delta is applied to the flow's record and journaled in the
// horizon gate (`MdGate`, `TCS_GATE_J`); a half's delta is acknowledged to
// that half only once the gate covers it, so the ACK `ip` shows, the
// segment it sends, the delivery `tls` makes and the record it writes all
// wait for the standby (DELTA_ACK → HORIZON). The standby needs nothing new:
// it applies the stream into its shadow and, after a crash, arms both halves
// from it — `ip` counting the whole send buffer sent, so its RTO resends what
// the peer has not acknowledged. A transition this stream cannot carry —
// KeyUpdates past what `tls` derives forward, plaintext past
// `TS_DELIV_BYTES`, a per-layer delta that contradicts the record, a gap, a
// half ending its own pairing — ends the pairing (both halves ABORTed,
// STATUS of op ABORT with `tcs_why::MIRROR | tcs_lost`); the connection
// runs on unprotected.
//
// A full table is not such a transition: it holds. Every bound of the
// record a delta fills is one the halves keep their own within
// (`session_ctrl`'s `STRICT_*`: `tls` holds its next record while
// `STRICT_TX_RECORDS` stand unacknowledged by the peer, and opens the next
// inbound record only once the consumption before it is mirrored), and the
// provider takes a half's next frame only while the gate, the half's queue
// and the anchor's event queue have room for what it can become, and a
// record out only while the record's outbound table has room
// (`TcStack::layer_room`); a frame it does not take stays on the half's
// port, where the half's own horizons and budgets hold the connection. A
// bound reached anyway is named (`tcs_lost::BOUNDS`, with the record's
// tables as the STATUS value), not reported as a divergence.
//
// Also in: unconsumed deliveries (the CT_TLS record carries them for the
// standby's `tls` to hand its worker again), the answer to a KeyUpdate the
// primary owed (CT_TLS `key_update` bit 1; an inbound `KeyUpdate` delta
// carries it), and a connection the peer half-closed (FXTC CLOSE_WAIT,
// CT_TLS `close_notify` bits 1 and 2; under crash continuity the peer's FIN
// is a `Fin` deferred until the record has the bytes before it).
//
// Also in: our own close (FIN-WAIT-1/2, CLOSING, LAST-ACK with our
// close_notify), IPv6 (FXTC's IPv6 layout) and a client session
// (`local_client`). Not in: TIME-WAIT, which is the connection over, and a
// KeyUpdate delta naming another object than the one the standby holds,
// refused DERIVE. `TCS_CAPS` reports exactly the rest, and a refused export
// or import says why (`tcs_why`).
//
// ── Ports (as the module wires them) ──────────────────────────────────────
//
// `Evt` (events to the anchor), `Ip` / `Tls` (per-layer commands to each
// module's `cont_in`), `Key` (the wrapped object, on the custody path) and
// `Auth` (`TCS_MSG_TOKEN_CHECK` and `TCS_MSG_CUSTODY_CHECK` to the
// authority). The module feeds back anchor operations, each module's `cont_out`,
// wrapped objects and verdicts.

// ── constants ─────────────────────────────────────────────────────────────

/// Flows one instance moves at once.
pub const TCS_FLOWS: usize = 2;

/// STATUS `reason` when an export or import is refused here (`UNSUPPORTED`
/// / `INVALID`): which half and why; a per-layer refusal carries the
/// module's own `STATUS_*` instead.
pub mod tcs_why {
    /// A checkpoint frame from a module that does not assemble.
    pub const LAYER_FRAME: u8 = 0x50;
    /// The FXTC record does not parse (low bits: `CkptError`).
    pub const FXTC: u8 = 0x30;
    /// The CT_TLS record does not parse (low bits: `CkptError`).
    pub const CT_TLS: u8 = 0x40;
    /// The halves are not a state the record represents.
    pub const UNSUPPORTED: u8 = 0x11;
    /// The retransmit window does not cover what is in flight.
    pub const SEND_RANGE: u8 = 0x12;
    /// The halves name different connections.
    pub const MISMATCH: u8 = 0x13;
    /// The composed record does not validate or decompose (low bits:
    /// `CkptError`).
    pub const CODEC: u8 = 0x60;
    /// The record cannot be imported into `ip` and `tls`.
    pub const IMPORT: u8 = 0x70;
    /// A crash-continuous pairing ended (STATUS of op `ABORT`, unsolicited):
    /// the primary runs on unprotected. Low bits: `tcs_lost`.
    pub const MIRROR: u8 = 0x80;
}

/// Why a crash-continuous pairing ended (`tcs_why::MIRROR | …`).
pub mod tcs_lost {
    /// A half's delta stream skipped a number.
    pub const GAP: u8 = 1;
    /// A transition the stream does not represent over these halves (a
    /// KeyUpdate past the derivable horizon, a record not carried or whose
    /// plaintext is past `TS_DELIV_BYTES`, a TCP state the timers delta
    /// does not name).
    pub const UNREPRESENTABLE: u8 = 2;
    /// The horizon gate's journal, a half's queue of unacknowledged
    /// deltas, or the anchor's event queue had no room for a delta. Not
    /// reached on the normal path: a half's input is held while any of
    /// them lacks room for what its next frame can produce
    /// (`TcStack::layer_room`); kept as the invariant's own name.
    pub const FULL: u8 = 3;
    /// A half ended its own pairing (`CONTINUITY{ABORTED}`), or a frame of
    /// it overran this module.
    pub const LAYER: u8 = 4;
    /// A half's delta contradicts the state the deltas so far built.
    pub const DIVERGED: u8 = 5;
    /// A half's delta is past a bound of the canonical record (`TsState`'s
    /// tables and buffers: `TS_TXREC_MAX`, `TS_SEND_MAX`, `TS_DELIV_MAX`,
    /// `TS_RECV_MAX`, the out-of-order slots). The halves hold each of their
    /// own within the strict bounds (`session_ctrl`'s `STRICT_*`), and the
    /// provider holds a record past a full table until the peer's
    /// acknowledgement frees it, so this names a layer that did not. The
    /// STATUS value is the detail (`tcs_bounds_detail`).
    pub const BOUNDS: u8 = 6;
}

/// The STATUS value of a pairing lost to `tcs_lost::BOUNDS`: the delta kind
/// in the low byte, then the record's tables as they stood — outbound
/// records (bits 8..16), deliveries (16..24), out-of-order segments
/// (24..32), the send buffer's bytes (32..48) and the receive buffer's
/// (48..64).
pub fn tcs_bounds_detail(kind: MdKind, st: &TsState) -> u64 {
    u64::from(kind as u8)
        | u64::from(st.tx_count) << 8
        | u64::from(st.deliv_count) << 16
        | u64::from(st.ooo_count) << 24
        | u64::from(st.send_len) << 32
        | u64::from(st.recv_len) << 48
}

impl TcsRefuse {
    pub fn why(self) -> u8 {
        match self {
            Self::Unsupported => tcs_why::UNSUPPORTED,
            Self::SendRange => tcs_why::SEND_RANGE,
            Self::Mismatch => tcs_why::MISMATCH,
            Self::Codec(e) => tcs_why::CODEC | (e as u8 & 0x0F),
        }
    }
}

/// What this provider enforces (`tc_cap`), and nothing it does not.
pub const TCS_CAPS: u32 = tc_cap::TCP_CODEC
    | tc_cap::TLS13_CODEC
    | tc_cap::HORIZON_GATE
    | tc_cap::VAULT_TRANSFER
    | tc_cap::FLOW_IMPORT_ARM
    | tc_cap::EMISSION_DISABLE
    | tc_cap::RESET_SUPPRESSION;

/// Unacknowledged deltas a crash-continuous flow journals.
pub const TCS_GATE_J: usize = 32;
/// A half's deltas awaiting the horizon that covers them.
pub const TCS_PEND: usize = 48;
/// The most deltas one frame of a half becomes: a `tls` RECV_BYTES is one
/// `RxSegment` (its partial record fits one) and the peer's FIN deferred to
/// it, a RECORD_IN an `RxRecord` and the peer's close_notify.
pub const TCS_FRAME_DELTAS: usize = 2;
/// Room the anchor's event queue must have before a half's frame is taken:
/// its deltas at their largest, and the STATUS a lost pairing reports.
pub const TCS_FRAME_EVT: usize =
    TCS_FRAME_DELTAS * (TCS_HDR + TC_HANDLE_LEN + MD_FRAME_MAX) + TCS_HDR + TC_STATUS_LEN;
// The canonical record's bounds are the strict profile's (`session_ctrl`),
// the ones `ip` and `tls` hold their own buffers and tables to.
const _: () = assert!(TS_TXREC_MAX == sc::STRICT_TX_RECORDS);
const _: () = assert!(TS_SEND_MAX == sc::STRICT_SEND_BYTES);
const _: () = assert!(TS_RECV_MAX == sc::STRICT_RECV_BYTES);
const _: () = assert!(TS_OOO_MAX == sc::STRICT_OOO_SEGS);
const _: () = assert!(TS_OOO_SEG == sc::STRICT_OOO_SEG);
const _: () = assert!(TS_DELIV_BYTES == sc::STRICT_DELIVERY_BYTES);
/// `ip`'s tombstone command on `cont_in` (`session_ctrl`'s
/// `CMD_SC_TOMBSTONE`): `[flow_id:16][epoch:4][ttl_ms:4]`, answered
/// `CONTINUITY{RETIRED}`.
pub const TCS_IP_TOMBSTONE: u8 = sc::CMD_SC_TOMBSTONE;
/// `tls`'s consumption delta (`session_ctrl`'s `DELTA_TLS_DELIVERED`):
/// `[consumed:8][consumer_cursor:8][cursor_at:8]`, the deliveries its
/// clear-side consumer has consumed and where its acknowledgement stood.
pub const TCS_TLS_DELIVERED: u8 = sc::DELTA_TLS_DELIVERED;
/// `tls`'s strict RECORD_IN content type for plaintext it did not carry.
const TCS_NOT_CARRIED: u8 = 0xFF;
/// TLS inner content types.
const TCS_CT_ALERT: u8 = 21;
const TCS_CT_APPLICATION: u8 = 23;
/// KeyUpdates `tls` derives forward from a sealed set at import
/// (`tls/continuity.rs` `CONT_DERIVE_MAX`).
const TCS_DERIVE_MAX: u32 = 16;
/// The most bytes one `RxSegment` carries here: a whole protected record.
const TCS_SEG_CHUNK: usize = TS_RECV_MAX;
// A partial record `tls` holds (at most `sc::STRICT_RECV_BYTES`) is one
// segment: `TCS_FRAME_DELTAS` counts it so.
const _: () = assert!(TCS_SEG_CHUNK >= sc::STRICT_RECV_BYTES);

/// The per-layer layouts the codecs below read and write; their SHA-256 is
/// what each module's PAIR_PREPARE binds, so a layout change in `ip` or
/// `tls` is refused at pairing rather than misread.
pub const TCS_FXTC_LABEL: [u8; 42] = *b"fluxor.ip.tcp-checkpoint:FXTC:reorder:ipv6";
pub const TCS_CT_TLS_LABEL: [u8; 28] = *b"fluxor.tls.continuity.ct_tls";

/// Module-defined frames, `[type][len u16 LE][payload]` like every other
/// frame here. The wrapped continuity object (custody path, both ways).
pub const TCS_MSG_WRAPPED: u8 = 0xC1;
/// `[token 48]`: is this the per-flow emission token the authority minted?
pub const TCS_MSG_TOKEN_CHECK: u8 = 0xC2;
/// `[token 48][verdict u8]`: 0 accepts; anything else is the authority's
/// refusal code, reported as STATUS `UNAUTHORIZED` with it as `reason`.
pub const TCS_MSG_TOKEN_VERDICT: u8 = 0xC3;

/// `[flow 16][epoch u32][challenge 32][evidence]` (`tc_custody`): may the
/// recipient this evidence attests receive this flow's continuity key? The
/// authority answers with the verdict below. The provider asks before it
/// wraps; what it checks itself (the challenge, the recipient's shape, the
/// signature under its signer) is checked again, in the vault, by `tls`.
pub const TCS_MSG_CUSTODY_CHECK: u8 = 0xC4;
/// `[flow 16][sha256(evidence) 32][verdict u8]`: 0 accepts; anything else
/// is the authority's refusal, reported as STATUS `UNAUTHORIZED`.
pub const TCS_MSG_CUSTODY_VERDICT: u8 = 0xC5;

/// `TsVaultRef::backend` of a key named through the wrapped object.
pub const TCS_VAULT_BACKEND: u8 = 1;

/// The frame header both surfaces share.
pub const TCS_HDR: usize = 3;

/// `ip`'s MSS (`tcp::MSS`); it negotiates no options.
const TCS_IP_MSS: u16 = 1460;
/// The record's number for the first application-traffic epoch (TLS 1.3's
/// epoch 3; `tls` counts key updates from 0).
const TCS_EPOCH_BASE: u32 = 3;
/// FXTC timer tick (TIME-WAIT, idle, CLOSE-WAIT remainders).
const TCS_TICK_MS: u32 = 50;
/// FXTC's RTT estimator scales (ms fixed point): SRTT × 8, RTTVAR × 4, so
/// one unit is this many µs.
const TCS_SRTT_UNIT_US: u32 = 1000 / 8;
const TCS_RTTVAR_UNIT_US: u32 = 1000 / 4;
/// FXTC's "idle timer disabled".
const TCS_IDLE_OFF: u16 = u16::MAX;
/// FXTC's TIME-WAIT length (ticks), exported full.
const TCS_TIMEWAIT_TICKS: u16 = 41;
/// `ip`'s RTO clamps (ms; RFC 6298's one-second floor).
const TCS_RTO_MIN: u16 = 1000;
const TCS_RTO_MAX: u16 = 60_000;
/// A per-layer reply that does not come within this fails the operation.
pub const TCS_JOB_MS: u64 = 5_000;
/// A quiesce's per-layer deadline (ms).
const TCS_QUIESCE_MS: u32 = 10_000;

// ── the TCP half: FXTC ────────────────────────────────────────────────────

const FXTC_MAGIC: [u8; 4] = *b"FXTC";
/// FXTC's layout byte for an IPv4 connection.
const FXTC_LAYOUT: u8 = 1;
const FXTC_FIXED: usize = 108;
/// Out-of-order slots and bytes (aarch64 `ip`: four of 512).
const FXTC_REORDER: usize = TS_OOO_MAX;
pub const FXTC_MAX: usize = FXTC_FIXED + FXTC_REORDER * (6 + TS_OOO_SEG);

/// FXTC's state codes, of which this bridge moves ESTABLISHED and
/// CLOSE_WAIT (the peer half-closed; ours is still open).
const FXTC_ESTABLISHED: u8 = 1;
const FXTC_CLOSE_WAIT: u8 = 2;
/// Our own close (`ip`'s numbering, continuity.rs): FIN-WAIT-1 and -2,
/// CLOSING, LAST-ACK.
const FXTC_FIN_WAIT_1: u8 = 3;
const FXTC_FIN_WAIT_2: u8 = 4;
const FXTC_CLOSING: u8 = 5;
const FXTC_LAST_ACK: u8 = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcpHalf {
    pub state: u8,
    pub local_ip: u32,
    pub remote_ip: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub prefix_len: u8,
    pub iss: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub rcv_nxt: u32,
    pub rcv_wnd: u16,
    pub cwnd: u16,
    pub ssthresh: u16,
    pub dup_acks: u8,
    pub in_recovery: u8,
    pub recover_seq: u32,
    pub srtt: u16,
    pub rttvar: u16,
    pub rto: u16,
    pub retx_rem: u16,
    pub tw_rem: u16,
    pub idle_rem: u16,
    pub cw_rem: u16,
    pub delivered: u32,
    pub consumed: u32,
    pub ooo_count: u8,
    pub ooo: [TsOoo; FXTC_REORDER],
    /// An IPv6 connection (`FXTC_LAYOUT_V6`, the IPv4 fields zero), its
    /// addresses `local_ip6` and `remote_ip6`; both zero for IPv4.
    pub v6: bool,
    pub local_ip6: [u8; 16],
    pub remote_ip6: [u8; 16],
}

/// FXTC's layout byte for an IPv6 connection: the IPv4 record with both
/// IPv4 address fields zero and the two IPv6 addresses after the reorder
/// slots.
const FXTC_LAYOUT_V6: u8 = 2;

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Parse an FXTC record into `h` (strict: every slot whole, nothing after).
pub fn fxtc_decode(b: &[u8], h: &mut TcpHalf) -> Result<(), CkptError> {
    if b.len() < FXTC_FIXED {
        return Err(CkptError::Truncated);
    }
    if b[..4] != FXTC_MAGIC {
        return Err(CkptError::BadMagic);
    }
    let b = match b[4] {
        FXTC_LAYOUT => {
            h.v6 = false;
            h.local_ip6 = [0; 16];
            h.remote_ip6 = [0; 16];
            b
        }
        FXTC_LAYOUT_V6 if b.len() >= FXTC_FIXED + 32 => {
            let t = b.len() - 32;
            if be32(b, 6) != 0 || be32(b, 10) != 0 {
                return Err(CkptError::SequenceImpossible);
            }
            h.v6 = true;
            h.local_ip6.copy_from_slice(&b[t..t + 16]);
            h.remote_ip6.copy_from_slice(&b[t + 16..]);
            &b[..t]
        }
        _ => return Err(CkptError::Version),
    };
    h.state = b[5];
    h.local_ip = be32(b, 6);
    h.remote_ip = be32(b, 10);
    h.local_port = le16(b, 14);
    h.remote_port = le16(b, 16);
    if le16(b, 18) != 0 {
        return Err(CkptError::Reserved);
    }
    h.prefix_len = b[20];
    h.iss = le32(b, 22);
    h.snd_una = le32(b, 26);
    h.snd_nxt = le32(b, 30);
    h.snd_wnd = le16(b, 34);
    h.snd_wl1 = le32(b, 36);
    h.snd_wl2 = le32(b, 40);
    h.rcv_nxt = le32(b, 44);
    h.rcv_wnd = le16(b, 48);
    h.cwnd = le16(b, 50);
    h.ssthresh = le16(b, 52);
    h.dup_acks = b[54];
    h.in_recovery = b[55];
    h.recover_seq = le32(b, 56);
    h.srtt = le16(b, 60);
    h.rttvar = le16(b, 62);
    h.rto = le16(b, 64);
    h.retx_rem = le16(b, 66);
    h.tw_rem = le16(b, 68);
    h.idle_rem = le16(b, 70);
    h.cw_rem = le16(b, 72);
    h.delivered = le32(b, 74);
    h.consumed = le32(b, 78);
    // trace_id[16] span_id[8] sampled[1] are the old anchor's observability
    // and do not move.
    let n = usize::from(b[107]);
    if n > FXTC_REORDER {
        return Err(CkptError::Bounds);
    }
    let mut p = FXTC_FIXED;
    for i in 0..n {
        if p + 6 > b.len() {
            return Err(CkptError::Truncated);
        }
        let seq = le32(b, p);
        let len = usize::from(le16(b, p + 4));
        p += 6;
        if len == 0 || len > TS_OOO_SEG || p + len > b.len() {
            return Err(CkptError::Bounds);
        }
        h.ooo[i].seq = seq;
        h.ooo[i].len = len as u16;
        h.ooo[i].bytes[..len].copy_from_slice(&b[p..p + len]);
        p += len;
    }
    for o in &mut h.ooo[n..] {
        o.seq = 0;
        o.len = 0;
    }
    h.ooo_count = n as u8;
    if p != b.len() {
        return Err(CkptError::Trailing);
    }
    Ok(())
}

/// Write `h` as an FXTC record; its length.
pub fn fxtc_encode(h: &TcpHalf, out: &mut [u8]) -> Option<usize> {
    let mut w = TcW::new(out);
    w.bytes(&FXTC_MAGIC)?;
    w.u8(if h.v6 { FXTC_LAYOUT_V6 } else { FXTC_LAYOUT })?;
    w.u8(h.state)?;
    let (l4, r4) = if h.v6 {
        (0, 0)
    } else {
        (h.local_ip, h.remote_ip)
    };
    w.bytes(&l4.to_be_bytes())?;
    w.bytes(&r4.to_be_bytes())?;
    w.u16(h.local_port)?;
    w.u16(h.remote_port)?;
    w.u16(0)?;
    w.u8(h.prefix_len)?;
    w.u8(0)?;
    w.u32(h.iss)?;
    w.u32(h.snd_una)?;
    w.u32(h.snd_nxt)?;
    w.u16(h.snd_wnd)?;
    w.u32(h.snd_wl1)?;
    w.u32(h.snd_wl2)?;
    w.u32(h.rcv_nxt)?;
    w.u16(h.rcv_wnd)?;
    w.u16(h.cwnd)?;
    w.u16(h.ssthresh)?;
    w.u8(h.dup_acks)?;
    w.u8(h.in_recovery)?;
    w.u32(h.recover_seq)?;
    w.u16(h.srtt)?;
    w.u16(h.rttvar)?;
    w.u16(h.rto)?;
    w.u16(h.retx_rem)?;
    w.u16(h.tw_rem)?;
    w.u16(h.idle_rem)?;
    w.u16(h.cw_rem)?;
    w.u32(h.delivered)?;
    w.u32(h.consumed)?;
    w.bytes(&[0; 16 + 8 + 1])?;
    w.u8(h.ooo_count)?;
    for o in &h.ooo[..usize::from(h.ooo_count)] {
        w.u32(o.seq)?;
        w.u16(o.len)?;
        w.bytes(&o.bytes[..usize::from(o.len)])?;
    }
    if h.v6 {
        w.bytes(&h.local_ip6)?;
        w.bytes(&h.remote_ip6)?;
    }
    Some(w.at)
}

// ── the TLS half: CT_TLS ──────────────────────────────────────────────────
//
// The record carries, beside its traffic epochs and sequences, the
// epochs the sealed secret set is at, and binds those in the seal: a
// decomposed record may be past them by KeyUpdates (a crash-continuous
// standby's, moved on by deltas), and `tls` derives the secrets forward from
// the sealed set at import and resumes past the sealed record sequences. It
// also carries the deliveries the worker has not consumed.

/// CT_TLS's layout byte, its only layout.
const CT_LAYOUT: u8 = 1;

/// `tls`'s peer block, after `peer_profile`: the transport peer
/// (`[family][addr 16][port 2]`), a client session's requester tag, and the
/// peer identity its `peer_identity` record carries (result, credential
/// kind, flags, validity, `[fp_len][fp 32]`, `[principal_len][principal
/// 128]`). The bridge carries it whole, in the wrapped object; `tls` holds
/// it to its exact shapes at import.
pub const CT_PEER_LEN: usize = 19 + 2 + 1 + 1 + 4 + 8 + 8 + 1 + 32 + 1 + 128;

const CT_FIXED: usize = 246 + CT_PEER_LEN;
/// The unconsumed deliveries a CT_TLS record carries for a standby's `tls`
/// to hand its worker again (`tls`'s `CONT_REDELIVER_MAX`: four whole
/// records' plaintext, each `[len:2][plaintext]`, at most eight).
#[cfg(target_arch = "aarch64")]
pub const TCS_REDELIVER_MAX: usize = 4 * (2 + 16 * 1024);
#[cfg(not(target_arch = "aarch64"))]
pub const TCS_REDELIVER_MAX: usize = 8 * (2 + 512);
/// `tls`'s sealed secret set: `[hash_len 1][2 × 48][2 × (1 + 32 + 12)]`,
/// the two sequence floors `[2 × 8]` and the vault's nonce and tag.
pub const TCS_SEALED_LEN: usize = 203 + 28;
/// The largest CT_TLS record the bridge moves: no more partial inbound
/// record than the record represents, a full retransmit window.
pub const CT_TLS_MAX: usize =
    CT_FIXED + TS_RECV_MAX + TS_SEND_MAX + TCS_REDELIVER_MAX + TCS_SEALED_LEN;

/// The canonical record a flow holds while it moves.
pub type TcsState = TsState;

/// A CT_TLS record, parsed in place: the scalars, and where the variable
/// ranges sit in the record bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TlsHalf {
    pub suite: u16,
    pub role: u8,
    pub conn_id: u16,
    pub alpn_len: u8,
    pub alpn: [u8; 16],
    pub sni: u8,
    pub sni_bytes: [u8; 64],
    pub peer_verified: u8,
    pub peer_profile: u8,
    pub peer_block: [u8; CT_PEER_LEN],
    pub exporter_ctx: [u8; 48],
    pub read_epoch: u32,
    pub write_epoch: u32,
    /// The epochs the sealed set is at.
    pub sealed_read_epoch: u32,
    pub sealed_write_epoch: u32,
    pub read_seq: u64,
    pub write_seq: u64,
    pub key_update: u8,
    /// Bit 1 the peer's close_notify arrived, bit 2 its transport FIN.
    pub close_notify: u8,
    pub delivered_in: u64,
    pub emitted_out: u64,
    /// The consumer's clear bytes through the last record emitted (its
    /// output horizon, `TsState::out_bytes`).
    pub out_bytes: u64,
    /// The consumer's cursor its last acknowledgement carried
    /// (`net_proto::CMD_DELIVERED`; `TsState::consumer_cursor`).
    pub consumer_cursor: u64,
    /// The clear byte it carried (`TsState::cursor_at`).
    pub cursor_at: u64,
    /// The clear bytes of the `delivered_in` records (`TsState::in_bytes`).
    pub in_bytes: u64,
    pub recv_expected: u32,
    pub recv_len: u32,
    pub retx_base: u32,
    pub retx_anchored: u8,
    pub retx_len: u16,
    /// Offsets of `recv`, `retx` and `sealed` in the record.
    pub recv_at: usize,
    pub retx_at: usize,
    pub sealed_at: usize,
    /// Unconsumed deliveries: how many, their bytes, where.
    pub deliv_count: u8,
    pub deliv_len: u32,
    pub deliv_at: usize,
}

impl TlsHalf {
    pub const fn zero() -> Self {
        Self {
            suite: 0,
            role: 0,
            conn_id: 0,
            alpn_len: 0,
            alpn: [0; 16],
            sni: 0,
            sni_bytes: [0; 64],
            peer_verified: 0,
            peer_profile: 0,
            peer_block: [0; CT_PEER_LEN],
            exporter_ctx: [0; 48],
            read_epoch: 0,
            write_epoch: 0,
            sealed_read_epoch: 0,
            sealed_write_epoch: 0,
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
            retx_base: 0,
            retx_anchored: 0,
            retx_len: 0,
            recv_at: 0,
            retx_at: 0,
            sealed_at: 0,
            deliv_count: 0,
            deliv_len: 0,
            deliv_at: 0,
        }
    }
}

pub fn ct_tls_decode(b: &[u8]) -> Result<TlsHalf, CkptError> {
    use CkptError::*;
    if b.len() < CT_FIXED {
        return Err(Truncated);
    }
    let mut r = TcR::new(b);
    if r.u8() != Some(CT_LAYOUT) {
        return Err(Version);
    }
    if r.u16() != Some(0x0304) {
        return Err(Version);
    }
    let mut h = TlsHalf {
        suite: r.u16().ok_or(Truncated)?,
        role: r.u8().ok_or(Truncated)?,
        conn_id: r.u16().ok_or(Truncated)?,
        alpn_len: r.u8().ok_or(Truncated)?,
        ..TlsHalf::zero()
    };
    h.alpn = r.arr().ok_or(Truncated)?;
    h.sni = r.u8().ok_or(Truncated)?;
    h.sni_bytes = r.arr().ok_or(Truncated)?;
    h.peer_verified = r.u8().ok_or(Truncated)?;
    h.peer_profile = r.u8().ok_or(Truncated)?;
    h.peer_block = r.arr().ok_or(Truncated)?;
    h.exporter_ctx = r.arr().ok_or(Truncated)?;
    h.read_epoch = r.u32().ok_or(Truncated)?;
    h.write_epoch = r.u32().ok_or(Truncated)?;
    h.sealed_read_epoch = r.u32().ok_or(Truncated)?;
    h.sealed_write_epoch = r.u32().ok_or(Truncated)?;
    if h.sealed_read_epoch > h.read_epoch || h.sealed_write_epoch > h.write_epoch {
        return Err(SequenceImpossible);
    }
    h.read_seq = r.u64().ok_or(Truncated)?;
    h.write_seq = r.u64().ok_or(Truncated)?;
    h.key_update = r.u8().ok_or(Truncated)?;
    // close_notify: the peer's only (a half-closed session); pending_alert,
    // ticket: only the empty state exports.
    h.close_notify = r.u8().ok_or(Truncated)?;
    // Bit 0 our own close_notify sealed, bit 3 its transport close gone to
    // `ip` (only after it).
    if h.close_notify & !0x0F != 0
        || (h.close_notify & 8 != 0 && h.close_notify & 1 == 0)
        || r.u8() != Some(0)
        || r.u8() != Some(0)
    {
        return Err(UnsupportedState);
    }
    h.delivered_in = r.u64().ok_or(Truncated)?;
    h.emitted_out = r.u64().ok_or(Truncated)?;
    h.out_bytes = r.u64().ok_or(Truncated)?;
    h.consumer_cursor = r.u64().ok_or(Truncated)?;
    h.cursor_at = r.u64().ok_or(Truncated)?;
    h.in_bytes = r.u64().ok_or(Truncated)?;
    h.recv_expected = r.u32().ok_or(Truncated)?;
    h.recv_len = r.u32().ok_or(Truncated)?;
    h.retx_base = r.u32().ok_or(Truncated)?;
    h.retx_anchored = r.u8().ok_or(Truncated)?;
    h.retx_len = r.u16().ok_or(Truncated)?;
    let sealed_len = usize::from(r.u16().ok_or(Truncated)?);
    h.deliv_count = r.u8().ok_or(Truncated)?;
    h.deliv_len = r.u32().ok_or(Truncated)?;
    if h.alpn_len > 16
        || (h.sni & 0x7F) > 64
        || sealed_len != TCS_SEALED_LEN
        || usize::from(h.deliv_count) > TS_DELIV_MAX
        || h.deliv_len as usize > TCS_REDELIVER_MAX
    {
        return Err(Bounds);
    }
    h.recv_at = r.at;
    h.retx_at = h.recv_at + h.recv_len as usize;
    h.deliv_at = h.retx_at + usize::from(h.retx_len);
    h.sealed_at = h.deliv_at + h.deliv_len as usize;
    if h.sealed_at + sealed_len != b.len() {
        return Err(RangeMissing);
    }
    // The deliveries tile their range: `[len:2][plaintext]` each.
    let dv = &b[h.deliv_at..h.sealed_at];
    let (mut at, mut n) = (0usize, 0u8);
    while at < dv.len() {
        if at + 2 > dv.len() || n == h.deliv_count {
            return Err(RangeMissing);
        }
        let l = usize::from(le16(dv, at));
        if at + 2 + l > dv.len() {
            return Err(RangeMissing);
        }
        at += 2 + l;
        n += 1;
    }
    if n != h.deliv_count {
        return Err(RangeMissing);
    }
    Ok(h)
}

/// The bytes `st`'s deliveries take in a CT_TLS record.
fn tcs_deliv_bytes(st: &TcsState) -> usize {
    st.deliveries().iter().map(|d| 2 + usize::from(d.len)).sum()
}

/// Write the CT_TLS record for `st` with the identity `wr` carries.
pub fn ct_tls_encode(st: &TcsState, wr: &TcsWrapped, out: &mut [u8]) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u8(CT_LAYOUT)?;
    w.u16(0x0304)?;
    w.u16(st.suite)?;
    // The role: a client session (`local_client`) or the server.
    w.u8(u8::from(!st.local_client))?;
    w.bytes(&wr.tls_flow[0..2])?;
    w.u8(wr.alpn_len)?;
    w.bytes(&wr.alpn)?;
    w.u8(wr.sni)?;
    w.bytes(&wr.sni_bytes)?;
    w.u8(u8::from(st.peer_verified))?;
    w.u8(wr.peer_profile)?;
    w.bytes(&wr.peer_block)?;
    w.bytes(&wr.exporter_ctx)?;
    w.u32(st.read_epoch - TCS_EPOCH_BASE)?;
    w.u32(st.write_epoch - TCS_EPOCH_BASE)?;
    // The sealed set stays at the epochs it was sealed at; `tls` derives
    // forward to the record's.
    w.u32(wr.sealed_read_epoch)?;
    w.u32(wr.sealed_write_epoch)?;
    w.u64(st.read_seq)?;
    w.u64(st.write_seq)?;
    // key_update: bit 1 when the peer's request is still unanswered.
    w.u8(u8::from(st.key_update_owed) << 1)?;
    // close_notify: the peer's (bit 1) and its FIN (bit 2), half-closed.
    // ...and ours (bit 0), its transport close forwarded once `ip` holds
    // our FIN (bit 3).
    let our_fin = matches!(
        st.tcp,
        TsTcp::FinWait1 | TsTcp::FinWait2 | TsTcp::Closing | TsTcp::LastAck
    );
    w.u8(u8::from(st.close_notify_sent)
        | (u8::from(st.close_notify_rcvd) << 1)
        | (u8::from(st.fin_rcvd) << 2)
        | (u8::from(st.close_notify_sent && our_fin) << 3))?;
    w.bytes(&[0, 0])?;
    w.u64(st.delivery_acked)?;
    w.u64(st.next_production - 1)?;
    w.u64(st.out_bytes)?;
    w.u64(st.consumer_cursor)?;
    w.u64(st.cursor_at)?;
    w.u64(st.in_bytes)?;
    w.u32(tcs_recv_expected(&st.recv[..usize::from(st.recv_len)]))?;
    w.u32(u32::from(st.recv_len))?;
    w.u32(st.snd_una)?;
    w.u8(1)?;
    w.u16(st.send_len)?;
    w.u16(TCS_SEALED_LEN as u16)?;
    // The deliveries the worker has not consumed: the standby's `tls` hands
    // them to its own worker again, before anything it opens itself.
    w.u8(st.deliv_count)?;
    w.u32(tcs_deliv_bytes(st) as u32)?;
    w.bytes(&st.recv[..usize::from(st.recv_len)])?;
    w.bytes(&st.send[..usize::from(st.send_len)])?;
    for d in st.deliveries() {
        w.u16(d.len)?;
        w.bytes(&d.bytes[..usize::from(d.len)])?;
    }
    w.bytes(&wr.sealed)?;
    Some(w.at)
}

/// `tls`'s `recv_expected` for a partial record: the payload length its
/// header names once the header is whole, 0 while it is still arriving.
fn tcs_recv_expected(recv: &[u8]) -> u32 {
    if recv.len() >= 5 {
        u32::from(u16::from_be_bytes([recv[3], recv[4]]))
    } else {
        0
    }
}

// ── the wrapped continuity object ─────────────────────────────────────────

/// The TLS half's secret set, still sealed by `tls`'s vault, with the
/// identity the record names only by digest. `wrapped_digest` in the record is
/// `sha256` of its encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcsWrapped {
    pub flow_id: [u8; 16],
    /// `tls`'s identity for the session: what the seal's AAD binds.
    pub tls_flow: [u8; 16],
    /// The ownership epoch the set was sealed under.
    pub layer_epoch: u32,
    /// `tls`'s traffic epochs the set was sealed at.
    pub sealed_read_epoch: u32,
    pub sealed_write_epoch: u32,
    pub alpn_len: u8,
    pub alpn: [u8; 16],
    pub sni: u8,
    pub sni_bytes: [u8; 64],
    pub peer_profile: u8,
    /// The record's peer block (`CT_PEER_LEN`).
    pub peer_block: [u8; CT_PEER_LEN],
    pub exporter_ctx: [u8; 48],
    pub sealed: [u8; TCS_SEALED_LEN],
}

pub const TCS_WRAPPED_LEN: usize =
    16 + 16 + 4 + 4 + 4 + 1 + 16 + 1 + 64 + 1 + CT_PEER_LEN + 48 + 2 + TCS_SEALED_LEN;

impl TcsWrapped {
    pub const fn empty() -> Self {
        Self {
            flow_id: [0; 16],
            tls_flow: [0; 16],
            layer_epoch: 0,
            sealed_read_epoch: 0,
            sealed_write_epoch: 0,
            alpn_len: 0,
            alpn: [0; 16],
            sni: 0,
            sni_bytes: [0; 64],
            peer_profile: 0,
            peer_block: [0; CT_PEER_LEN],
            exporter_ctx: [0; 48],
            sealed: [0; TCS_SEALED_LEN],
        }
    }

    pub fn encode(&self, out: &mut [u8; TCS_WRAPPED_LEN]) {
        let mut w = TcW::new(out);
        let _ = (|| {
            w.bytes(&self.flow_id)?;
            w.bytes(&self.tls_flow)?;
            w.u32(self.layer_epoch)?;
            w.u32(self.sealed_read_epoch)?;
            w.u32(self.sealed_write_epoch)?;
            w.u8(self.alpn_len)?;
            w.bytes(&self.alpn)?;
            w.u8(self.sni)?;
            w.bytes(&self.sni_bytes)?;
            w.u8(self.peer_profile)?;
            w.bytes(&self.peer_block)?;
            w.bytes(&self.exporter_ctx)?;
            w.u16(TCS_SEALED_LEN as u16)?;
            w.bytes(&self.sealed)
        })();
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != TCS_WRAPPED_LEN {
            return None;
        }
        let mut r = TcR::new(b);
        let mut w = Self::empty();
        w.flow_id = r.arr()?;
        w.tls_flow = r.arr()?;
        w.layer_epoch = r.u32()?;
        w.sealed_read_epoch = r.u32()?;
        w.sealed_write_epoch = r.u32()?;
        w.alpn_len = r.u8()?;
        w.alpn = r.arr()?;
        w.sni = r.u8()?;
        w.sni_bytes = r.arr()?;
        w.peer_profile = r.u8()?;
        w.peer_block = r.arr()?;
        w.exporter_ctx = r.arr()?;
        if usize::from(r.u16()?) != TCS_SEALED_LEN || w.alpn_len > 16 || (w.sni & 0x7F) > 64 {
            return None;
        }
        w.sealed = r.arr()?;
        Some(w)
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut b = [0u8; TCS_WRAPPED_LEN];
        self.encode(&mut b);
        sha256(&b)
    }
}

/// The record's 16-bit ALPN code for a protocol name: 0 for none, else the head of
/// its digest with the top bit set (the name itself is in the wrapped
/// object).
fn tcs_alpn_code(name: &[u8]) -> u16 {
    if name.is_empty() {
        return 0;
    }
    let d = sha256(name);
    0x8000 | (u16::from_be_bytes([d[0], d[1]]) & 0x7FFF)
}

// ── compose and decompose ─────────────────────────────────────────────────

/// What the anchor and earlier hops carry beside the two halves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcsCarried {
    pub flow_id: [u8; 16],
    pub service_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub session_epoch: u32,
    pub route_generation: u64,
    pub binding_epoch: u32,
    pub local_addr_gen: u32,
    pub iface: u32,
}

impl TcsCarried {
    pub fn of(s: &TcsState) -> Self {
        Self {
            flow_id: s.flow_id,
            service_id: s.service_id,
            flow_epoch: s.flow_epoch,
            mirror_generation: s.mirror_generation,
            session_epoch: s.session_epoch,
            route_generation: s.route_generation,
            binding_epoch: s.binding_epoch,
            local_addr_gen: s.local_addr_gen,
            iface: s.iface,
        }
    }
}

/// Why a pair of halves could not be one record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcsRefuse {
    /// A half the record does not represent (not ESTABLISHED or a closing
    /// state, a key update of ours outstanding, more partial record than it
    /// holds).
    Unsupported,
    /// The retransmit window does not cover exactly what is in flight.
    SendRange,
    /// The halves name different connections.
    Mismatch,
    /// The composition did not validate, or would not decompose back.
    Codec(CkptError),
}

/// Build the canonical record of one connection from `ip`'s and `tls`'s
/// halves and the wrapped object. `tls_rec` is the CT_TLS record `th`
/// was parsed from.
pub fn tcs_compose(
    tcp: &TcpHalf,
    th: &TlsHalf,
    tls_rec: &[u8],
    wr: &TcsWrapped,
    carried: &TcsCarried,
    st: &mut TcsState,
) -> Result<(), TcsRefuse> {
    // A client session: this host opened the connection.
    let client = th.role == 0;
    if !matches!(
        tcp.state,
        FXTC_ESTABLISHED
            | FXTC_CLOSE_WAIT
            | FXTC_FIN_WAIT_1
            | FXTC_FIN_WAIT_2
            | FXTC_CLOSING
            | FXTC_LAST_ACK
    ) || (tcp.state >= FXTC_FIN_WAIT_1 && th.close_notify & 1 == 0)
        || th.role > 1
        || th.key_update & !2 != 0
        || th.sealed_read_epoch != th.read_epoch
        || th.sealed_write_epoch != th.write_epoch
        || wr.sealed_read_epoch != th.read_epoch
        || wr.sealed_write_epoch != th.write_epoch
        || th.recv_len as usize > TS_RECV_MAX
        || th.read_epoch > u32::MAX - TCS_EPOCH_BASE
        || th.write_epoch > u32::MAX - TCS_EPOCH_BASE
    {
        return Err(TcsRefuse::Unsupported);
    }
    // Our FIN, sent and not yet acknowledged, takes the sequence number past
    // the last byte in flight; FIN-WAIT-2 has had it acknowledged.
    let fin_out = matches!(tcp.state, FXTC_FIN_WAIT_1 | FXTC_CLOSING | FXTC_LAST_ACK);
    let in_flight = tcp
        .snd_nxt
        .wrapping_sub(tcp.snd_una)
        .wrapping_sub(u32::from(fin_out)) as usize;
    if in_flight > TS_SEND_MAX {
        return Err(TcsRefuse::SendRange);
    }
    // Where SND.UNA sits in the retransmit window. A window that never saw
    // an acknowledgement is not anchored; it can stand for nothing in
    // flight only.
    let retx = &tls_rec[th.retx_at..th.retx_at + usize::from(th.retx_len)];
    let (from, base) = if in_flight == 0 {
        (retx.len(), tcp.snd_una.wrapping_sub(retx.len() as u32))
    } else {
        if th.retx_anchored == 0 {
            return Err(TcsRefuse::SendRange);
        }
        let off = tcp.snd_una.wrapping_sub(th.retx_base) as usize;
        if off > retx.len() || retx.len() - off != in_flight {
            return Err(TcsRefuse::SendRange);
        }
        (off, th.retx_base)
    };

    // Every field is set below; slots past a count are not part of the
    // encoding.
    st.flow_id = carried.flow_id;
    st.service_id = carried.service_id;
    // `service_*` is the server's end, `client_*` the client's: this host's
    // is whichever its role is (`local_client`). An IPv6 connection's are
    // its whole addresses (FXTC's IPv6 layout).
    let (local16, remote16, family) = if tcp.v6 {
        (tcp.local_ip6, tcp.remote_ip6, 6)
    } else {
        let mut l = [0u8; 16];
        let mut r = [0u8; 16];
        l[..4].copy_from_slice(&tcp.local_ip.to_be_bytes());
        r[..4].copy_from_slice(&tcp.remote_ip.to_be_bytes());
        (l, r, 4)
    };
    st.family = family;
    let (cl_ip, cl_port, sv_ip, sv_port) = if client {
        (local16, tcp.local_port, remote16, tcp.remote_port)
    } else {
        (remote16, tcp.remote_port, local16, tcp.local_port)
    };
    st.local_client = client;
    st.client_ip = cl_ip;
    st.client_port = cl_port;
    st.service_ip = sv_ip;
    st.service_port = sv_port;
    st.local_addr_gen = carried.local_addr_gen;
    st.iface = carried.iface;
    st.mss = TCS_IP_MSS;
    st.wscale_snd = 0;
    st.wscale_rcv = 0;
    st.sack_ok = false;
    st.ts_ok = false;
    // CLOSE_WAIT: the peer's FIN took a sequence number past what `ip`
    // delivered.
    let fin = matches!(tcp.state, FXTC_CLOSE_WAIT | FXTC_CLOSING | FXTC_LAST_ACK);
    st.tcp = match tcp.state {
        FXTC_CLOSE_WAIT => TsTcp::CloseWait,
        FXTC_FIN_WAIT_1 => TsTcp::FinWait1,
        FXTC_FIN_WAIT_2 => TsTcp::FinWait2,
        FXTC_CLOSING => TsTcp::Closing,
        FXTC_LAST_ACK => TsTcp::LastAck,
        _ => TsTcp::Established,
    };
    st.iss = tcp.iss;
    st.irs = tcp
        .rcv_nxt
        .wrapping_sub(1)
        .wrapping_sub(tcp.delivered)
        .wrapping_sub(u32::from(fin));
    st.snd_una = tcp.snd_una;
    st.snd_nxt = tcp.snd_nxt;
    st.snd_wnd = u32::from(tcp.snd_wnd);
    st.snd_wl1 = tcp.snd_wl1;
    st.snd_wl2 = tcp.snd_wl2;
    st.rcv_nxt = tcp.rcv_nxt;
    st.rcv_wnd = u32::from(tcp.rcv_wnd);
    st.fin_queued = fin_out;
    st.fin_rcvd = fin;
    st.send_len = in_flight as u16;
    st.send[..in_flight].copy_from_slice(&retx[from..from + in_flight]);
    let rl = th.recv_len as usize;
    st.recv_len = rl as u16;
    st.recv[..rl].copy_from_slice(&tls_rec[th.recv_at..th.recv_at + rl]);
    // The record keeps the out-of-order segments sorted; `ip`'s slots are not.
    let mut ooo = tcp.ooo;
    let n = usize::from(tcp.ooo_count);
    ooo[..n].sort_unstable_by(|a, b| {
        if a.seq == b.seq {
            core::cmp::Ordering::Equal
        } else if ts_seq_lt(a.seq, b.seq) {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Greater
        }
    });
    st.ooo_count = n as u8;
    st.ooo[..n].copy_from_slice(&ooo[..n]);
    st.ts_recent = 0;
    st.dupacks = tcp.dup_acks;
    st.in_recovery = tcp.in_recovery != 0;
    st.recovery_point = tcp.recover_seq;
    st.rto_ms = u32::from(tcp.rto).min(TS_TIMER_MAX_MS);
    st.persist_ms = 0;
    st.keepalive_ms = if tcp.idle_rem == TCS_IDLE_OFF {
        0
    } else {
        (u32::from(tcp.idle_rem) * TCS_TICK_MS).clamp(1, TS_TIMER_MAX_MS)
    };
    st.timewait_ms = 0;
    st.srtt_us = u32::from(tcp.srtt) * TCS_SRTT_UNIT_US;
    st.rttvar_us = u32::from(tcp.rttvar) * TCS_RTTVAR_UNIT_US;
    st.cwnd = u32::from(tcp.cwnd).max(1);
    st.ssthresh = if tcp.ssthresh == u16::MAX {
        u32::MAX
    } else {
        u32::from(tcp.ssthresh)
    };

    st.tls_phase = TsTlsPhase::Established;
    st.suite = th.suite;
    st.read_epoch = th.read_epoch + TCS_EPOCH_BASE;
    st.read_seq = th.read_seq;
    st.write_epoch = th.write_epoch + TCS_EPOCH_BASE;
    st.write_seq = th.write_seq;
    st.key_update_owed = th.key_update & 2 != 0;
    st.close_notify_sent = th.close_notify & 1 != 0;
    st.close_notify_rcvd = th.close_notify & 2 != 0;
    st.peer_verified = th.peer_verified != 0;
    st.alpn = tcs_alpn_code(&th.alpn[..usize::from(th.alpn_len)]);
    let sni_len = usize::from(th.sni & 0x7F);
    st.sni_digest = if sni_len == 0 {
        [0; 32]
    } else {
        sha256(&th.sni_bytes[..sni_len])
    };
    st.exporter_digest = sha256(&th.exporter_ctx);
    let wd = wr.digest();
    st.wrapped_digest = wd;
    let object = u32::from_le_bytes([wd[0], wd[1], wd[2], wd[3]]);
    st.read_key = TsVaultRef {
        backend: TCS_VAULT_BACKEND,
        purpose: TS_VAULT_READ,
        object,
        generation: wr.layer_epoch,
        epoch: st.read_epoch,
    };
    st.write_key = TsVaultRef {
        backend: TCS_VAULT_BACKEND,
        purpose: TS_VAULT_WRITE,
        object,
        generation: wr.layer_epoch,
        epoch: st.write_epoch,
    };

    // The outbound records tiling the send buffer, from the window's record
    // headers: every one whole, the last numbered just below the write
    // sequence, productions numbered back from the records emitted.
    let mut starts = [0usize; TS_TXREC_MAX];
    let mut count = 0usize;
    let mut at = 0usize;
    while at < retx.len() {
        if at + 5 > retx.len() || count == TS_TXREC_MAX {
            return Err(TcsRefuse::SendRange);
        }
        let len = 5 + usize::from(u16::from_be_bytes([retx[at + 3], retx[at + 4]]));
        if at + len > retx.len() {
            return Err(TcsRefuse::SendRange);
        }
        if at + len > from {
            starts[count] = at;
            count += 1;
        }
        at += len;
    }
    if (count as u64) > th.write_seq || (count as u64) > th.emitted_out {
        return Err(TcsRefuse::SendRange);
    }
    for (k, &s) in starts[..count].iter().enumerate() {
        let back = (count - k) as u64;
        let len = 5 + u16::from_be_bytes([retx[s + 3], retx[s + 4]]);
        st.tx[k] = TsTxRec {
            tcp_seq: base.wrapping_add(s as u32),
            len,
            epoch: st.write_epoch,
            record_seq: th.write_seq - back,
            production_id: th.emitted_out + 1 - back,
        };
    }
    st.tx_count = count as u8;

    // Deliveries a record carries follow what was consumed, in order (a
    // primary's own export carries none: `tls` keeps no plaintext it handed
    // up).
    st.delivery_acked = th.delivered_in;
    let dv = &tls_rec[th.deliv_at..th.sealed_at];
    let mut at = 0usize;
    let mut n = 0usize;
    while at < dv.len() {
        let l = usize::from(le16(dv, at));
        if l > TS_DELIV_BYTES {
            return Err(TcsRefuse::Unsupported);
        }
        let d = &mut st.deliv[n];
        d.id = th.delivered_in + 1 + n as u64;
        d.len = l as u16;
        d.bytes[..l].copy_from_slice(&dv[at + 2..at + 2 + l]);
        at += 2 + l;
        n += 1;
    }
    st.deliv_count = n as u8;
    st.next_delivery = th.delivered_in + 1 + n as u64;
    st.next_production = th.emitted_out + 1;
    st.out_bytes = th.out_bytes;
    st.consumer_cursor = th.consumer_cursor;
    st.cursor_at = th.cursor_at;
    st.in_bytes = th.in_bytes;
    st.flow_epoch = carried.flow_epoch;
    st.session_epoch = carried.session_epoch;
    st.route_generation = carried.route_generation;
    st.mirror_generation = carried.mirror_generation;
    st.binding_epoch = carried.binding_epoch;
    ts_validate(st).map_err(TcsRefuse::Codec)?;

    // Decomposed again, the halves must be what the modules exported, in
    // every field the connection runs on.
    let mut back = *tcp;
    tcs_tcp_half(st, &mut back);
    let same_tcp = back.state == tcp.state
        && back.local_ip == tcp.local_ip
        && back.remote_ip == tcp.remote_ip
        && back.local_port == tcp.local_port
        && back.remote_port == tcp.remote_port
        && back.iss == tcp.iss
        && back.snd_una == tcp.snd_una
        && back.snd_nxt == tcp.snd_nxt
        && back.snd_wnd == tcp.snd_wnd
        && back.snd_wl1 == tcp.snd_wl1
        && back.snd_wl2 == tcp.snd_wl2
        && back.rcv_nxt == tcp.rcv_nxt
        && back.rcv_wnd == tcp.rcv_wnd
        && back.cwnd == tcp.cwnd
        && back.ssthresh == tcp.ssthresh
        && back.srtt == tcp.srtt
        && back.rttvar == tcp.rttvar
        && back.delivered == tcp.delivered
        && back.ooo_count == tcp.ooo_count;
    let same_tls = st.read_epoch - TCS_EPOCH_BASE == th.read_epoch
        && st.write_epoch - TCS_EPOCH_BASE == th.write_epoch
        && tcs_recv_expected(&st.recv[..rl]) == th.recv_expected
        && st.delivery_acked == th.delivered_in
        && st.next_production - 1 == th.emitted_out;
    if !same_tcp || !same_tls {
        return Err(TcsRefuse::Codec(CkptError::SequenceImpossible));
    }
    Ok(())
}

/// `st`'s TCP half as `ip` imports it.
pub fn tcs_tcp_half(st: &TcsState, h: &mut TcpHalf) {
    h.state = match st.tcp {
        TsTcp::CloseWait => FXTC_CLOSE_WAIT,
        TsTcp::FinWait1 => FXTC_FIN_WAIT_1,
        TsTcp::FinWait2 => FXTC_FIN_WAIT_2,
        TsTcp::Closing => FXTC_CLOSING,
        TsTcp::LastAck => FXTC_LAST_ACK,
        _ => FXTC_ESTABLISHED,
    };
    let sv = u32::from_be_bytes([
        st.service_ip[0],
        st.service_ip[1],
        st.service_ip[2],
        st.service_ip[3],
    ]);
    let cl = u32::from_be_bytes([
        st.client_ip[0],
        st.client_ip[1],
        st.client_ip[2],
        st.client_ip[3],
    ]);
    // This host's end is the client's for a session it opened.
    (h.local_ip, h.remote_ip, h.local_port, h.remote_port) = if st.local_client {
        (cl, sv, st.client_port, st.service_port)
    } else {
        (sv, cl, st.service_port, st.client_port)
    };
    h.v6 = st.family == 6;
    (h.local_ip6, h.remote_ip6) = if !h.v6 {
        ([0; 16], [0; 16])
    } else if st.local_client {
        (st.client_ip, st.service_ip)
    } else {
        (st.service_ip, st.client_ip)
    };
    if h.v6 {
        h.local_ip = 0;
        h.remote_ip = 0;
    }
    // The connection's owner and prefix are the importing host's: the
    // owner of the address it lands on owns it, its own address table
    // routes it.
    h.prefix_len = 0;
    h.iss = st.iss;
    h.snd_una = st.snd_una;
    // Everything the send buffer holds may already be on the wire (a
    // crash-continuous record learns of a record before its segment is
    // sent): the importing `ip` counts it sent, and its RTO resends what
    // the peer has not acknowledged. After a quiesced cut the two agree.
    h.snd_nxt = st.send_end();
    h.snd_wnd = st.snd_wnd.min(u32::from(u16::MAX)) as u16;
    h.snd_wl1 = st.snd_wl1;
    h.snd_wl2 = st.snd_wl2;
    h.rcv_nxt = st.rcv_nxt;
    h.rcv_wnd = st.rcv_wnd.min(u32::from(u16::MAX)) as u16;
    h.cwnd = st.cwnd.min(u32::from(u16::MAX)) as u16;
    h.ssthresh = if st.ssthresh >= u32::from(u16::MAX) {
        u16::MAX
    } else {
        st.ssthresh as u16
    };
    h.dup_acks = st.dupacks;
    h.in_recovery = u8::from(st.in_recovery);
    h.recover_seq = st.recovery_point;
    h.srtt = (st.srtt_us / TCS_SRTT_UNIT_US).min(u32::from(u16::MAX)) as u16;
    h.rttvar = (st.rttvar_us / TCS_RTTVAR_UNIT_US).min(u32::from(u16::MAX)) as u16;
    let rto = st
        .rto_ms
        .clamp(u32::from(TCS_RTO_MIN), u32::from(TCS_RTO_MAX));
    h.rto = rto as u16;
    // One full RTO before the first retransmission here.
    h.retx_rem = h.rto;
    h.tw_rem = TCS_TIMEWAIT_TICKS;
    h.idle_rem = if st.keepalive_ms == 0 {
        TCS_IDLE_OFF
    } else {
        (st.keepalive_ms / TCS_TICK_MS).clamp(1, u32::from(u16::MAX - 1)) as u16
    };
    h.cw_rem = u16::MAX;
    let delivered = st
        .rcv_nxt
        .wrapping_sub(1)
        .wrapping_sub(st.irs)
        .wrapping_sub(u32::from(st.fin_rcvd));
    h.delivered = delivered;
    h.consumed = delivered;
    let n = usize::from(st.ooo_count);
    h.ooo_count = n as u8;
    h.ooo[..n].copy_from_slice(&st.ooo[..n]);
}

/// Whether a standby can follow the KeyUpdate `payload` names: its new
/// secret is a reference into the wrapped object this flow holds (the next
/// one `tls` derives from the sealed set), no further from the seal than
/// `tls` derives forward.
fn tcs_derivable(st: &TcsState, wr: &TcsWrapped, payload: &[u8]) -> bool {
    let mut r = TcR::new(payload);
    let (Some(dir), Some(ep)) = (r.u8(), r.u32()) else {
        return false;
    };
    let Ok(vref) = TsVaultRef::get(&mut r) else {
        return false;
    };
    let Some(wd) = r.arr::<32>() else {
        return false;
    };
    let object = st.read_key.object;
    let (sealed, at) = match dir {
        MD_DIR_IN => (wr.sealed_read_epoch, st.read_epoch),
        MD_DIR_OUT => (wr.sealed_write_epoch, st.write_epoch),
        _ => return false,
    };
    vref.backend == TCS_VAULT_BACKEND
        && vref.object == object
        && vref.generation == wr.layer_epoch
        && wd == st.wrapped_digest
        && ep == at + 1
        && ep >= TCS_EPOCH_BASE
        && ep - TCS_EPOCH_BASE >= sealed
        && ep - TCS_EPOCH_BASE - sealed <= TCS_DERIVE_MAX
}

/// Why a record cannot be imported into `ip` and `tls`.
pub fn tcs_importable(st: &TcsState, wr: &TcsWrapped) -> Result<(), TcsRefuse> {
    // What the per-layer halves cannot hold: more unconsumed deliveries than
    // `tls` hands its worker again (`TCS_REDELIVER_MAX`), or ones not
    // following the consumed cursor, a FIN, a closing state, a record of a
    // write epoch the sealed set is past or beyond what `tls` derives
    // forward, IPv6. A record of an earlier write epoch still in flight is
    // only resent, byte for byte: no key is needed for it. A KeyUpdate
    // answer owed rides CT_TLS (`key_update` bit 1).
    // Our own close moves (FIN-WAIT-1/2, CLOSING, LAST-ACK, with our
    // close_notify sealed); TIME-WAIT is the connection over.
    let our_close = matches!(
        st.tcp,
        TsTcp::FinWait1 | TsTcp::FinWait2 | TsTcp::Closing | TsTcp::LastAck
    );
    if !matches!(st.tcp, TsTcp::Established | TsTcp::CloseWait) && !our_close
        || (our_close && !st.close_notify_sent)
        || !matches!(st.family, 4 | 6)
        || tcs_deliv_bytes(st) > TCS_REDELIVER_MAX
        || st
            .deliveries()
            .iter()
            .enumerate()
            .any(|(k, d)| d.id != st.delivery_acked + 1 + k as u64)
        || st.read_epoch < TCS_EPOCH_BASE
        || st.write_epoch < TCS_EPOCH_BASE
        || st.tx_records().iter().any(|t| t.epoch > st.write_epoch)
        || st.read_epoch - TCS_EPOCH_BASE < wr.sealed_read_epoch
        || st.write_epoch - TCS_EPOCH_BASE < wr.sealed_write_epoch
        || st.read_epoch - TCS_EPOCH_BASE - wr.sealed_read_epoch > TCS_DERIVE_MAX
        || st.write_epoch - TCS_EPOCH_BASE - wr.sealed_write_epoch > TCS_DERIVE_MAX
        || st.wscale_snd != 0
        || st.wscale_rcv != 0
        || st.sack_ok
        || st.ts_ok
    {
        return Err(TcsRefuse::Unsupported);
    }
    if st.wrapped_digest != wr.digest() || wr.flow_id != st.flow_id {
        return Err(TcsRefuse::Mismatch);
    }
    Ok(())
}

// ── the provider ──────────────────────────────────────────────────────────

/// Where a frame goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcsPort {
    Evt,
    Ip,
    Tls,
    Key,
    Auth,
}

/// The module's side of the ports: queue one whole frame, or refuse it now
/// (the provider then fails the operation rather than splitting a frame).
pub trait TcsOut {
    fn send(&mut self, port: TcsPort, frame: &[u8]) -> bool;
    /// Bytes `port` can queue now; a port that never fills need not say.
    fn room(&self, _port: TcsPort) -> usize {
        usize::MAX
    }
}

/// The per-layer exchange a flow is waiting on. `Idle` is the all-zero value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TcsStep {
    Idle,
    // primary
    PrepIp,
    PrepTls,
    QuiesceIp,
    QuiesceTls,
    StatusIp,
    StatusTls,
    ExportIp,
    ExportTls,
    RetireIp,
    RetireTls,
    AbortIp,
    AbortTls,
    // standby
    ShadowIp,
    ImportIp,
    CutIp,
    ArmIp,
    ShadowTls,
    ImportTls,
    CutTls,
    ArmTls,
    Token,
    ActivateIp,
    ActivateTls,
    // custody (either role)
    CustodyAttest,
    CustodyAuth,
    CustodyWrap,
    CustodyUnwrap,
}

/// One flow: its pairing and, while it moves, its canonical record.
#[derive(PartialEq)]
pub struct TcsFlow {
    pub live: bool,
    pub role: TcRole,
    pub handle: TcHandle,
    pub mode: TcMode,
    /// The ownership epoch both per-layer halves are keyed under.
    pub layer_epoch: u32,
    pub carried: TcsCarried,
    pub st: TcsState,
    pub has_state: bool,
    pub checkpoint_id: u64,
    pub asm: CkptAssembler,
    /// The peer's FIN `ip` reported, waiting for the bytes before it to
    /// reach the record (`fin_held`), and its sequence number.
    pub fin_held: bool,
    pub fin_at: u32,
    pub order: MdOrder,
    pub shadow_valid: bool,
    pub armed: bool,
    pub active: bool,
    pub wrapped: TcsWrapped,
    pub wrapped_held: bool,
    /// `tls`'s identity for the session (`[conn_id LE][0;14]` at the
    /// first pairing; kept across hops, since the seal binds it).
    pub tls_flow: [u8; 16],
    pub conn_id: u16,
    // the operation in progress
    pub step: TcsStep,
    pub op: u8,
    pub deadline: u64,
    pub arg: u64,
    pub new_epoch: u32,
    pub fence_gen: u32,
    pub token: [u8; TC_FLOW_TOKEN_LEN],
    pub drained: bool,
    /// A re-pair of a connection this host already holds: a refused
    /// PAIR_PREPARE leaves it as it was.
    pub kept: bool,
    /// EMISSION_DISABLE cut the connection off here, at `custody_gen`.
    pub fenced: bool,
    pub custody_gen: u32,
    /// Crash-continuous mirroring is live: every delta of the halves
    /// becomes deltas under the horizon gate, and a half's transition is
    /// released only when the delta covering it is acknowledged.
    pub mirroring: bool,
    pub gate: MdGate<TCS_GATE_J>,
    /// The delta stream this primary emits: last sequence, its digest.
    pub delta_seq: u64,
    pub last_digest: [u8; 32],
    /// The halves' own streams: checkpoint generation, the next delta
    /// number expected, the highest acknowledged to them, and their deltas
    /// waiting on the gate.
    pub ip: TcsHalfStream,
    pub tls: TcsHalfStream,
    /// A CUSTODY_WRAP waiting on the authority: its challenge and evidence.
    pub custody_challenge: [u8; 32],
    pub custody_ev: [u8; tc_custody::EVIDENCE_MAX],
    pub custody_ev_len: usize,
    /// The flow's continuity key reached this host's vault by CUSTODY_UNWRAP.
    pub key_unwrapped: bool,
}

/// What a half's delta waits for before it is acknowledged to that half.
/// `Free` is the all-zero value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TcsCond {
    /// Nothing the peer sees.
    Free,
    /// The delta of this sequence.
    Seq(u64),
    /// The receive horizon at this RCV.NXT (`ip`'s exposed ACK).
    Rx(u32),
    /// The emission horizon at this sequence (`ip`'s segment).
    Tx(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcsPend {
    pub no: u32,
    pub cond: TcsCond,
}

/// One half's per-layer delta stream, seen from the primary's bridge.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcsHalfStream {
    pub gen: u32,
    /// The last delta number applied (0 before the first, numbered 1).
    pub last: u32,
    /// The highest delta the gate covers, and the highest acknowledged to
    /// the half (behind it only while the acknowledgement waits for room).
    pub covered: u32,
    pub acked: u32,
    pub pend: [TcsPend; TCS_PEND],
    pub pend_n: usize,
}

impl TcsHalfStream {
    pub const fn empty() -> Self {
        Self {
            gen: 0,
            last: 0,
            covered: 0,
            acked: 0,
            pend: [TcsPend {
                no: 0,
                cond: TcsCond::Free,
            }; TCS_PEND],
            pend_n: 0,
        }
    }

    fn at(gen: u32) -> Self {
        Self {
            gen,
            ..Self::empty()
        }
    }

    fn push(&mut self, no: u32, cond: TcsCond) -> bool {
        if self.pend_n == TCS_PEND {
            return false;
        }
        self.pend[self.pend_n] = TcsPend { no, cond };
        self.pend_n += 1;
        true
    }

    /// Move `covered` to the highest delta number every one of whose
    /// predecessors' horizons is met (those leave the queue); the number to
    /// acknowledge to the half, if it is past what was acknowledged.
    fn settle(&mut self, g: &MdGate<TCS_GATE_J>) -> Option<u32> {
        let mut k = 0;
        while k < self.pend_n && tcs_met(g, self.pend[k].cond) {
            k += 1;
        }
        if k > 0 {
            self.covered = self.covered.max(self.pend[k - 1].no);
            self.pend.copy_within(k..self.pend_n, 0);
            self.pend_n -= k;
        }
        (self.covered > self.acked).then_some(self.covered)
    }
}

fn tcs_met(g: &MdGate<TCS_GATE_J>, c: TcsCond) -> bool {
    match c {
        TcsCond::Free => true,
        TcsCond::Seq(s) => s <= g.acked_seq,
        TcsCond::Rx(a) => g.may_ack(a),
        TcsCond::Tx(e) => g.may_emit(e),
    }
}

const TCS_EFFECT0: MdEffect = MdEffect {
    seq: 0,
    rx_upto: 0,
    tx_upto: 0,
    deliver_upto: 0,
    write_epoch: 0,
};

/// The gate before a checkpoint.
const TCS_GATE0: MdGate<TCS_GATE_J> = MdGate {
    strict: false,
    journal: [TCS_EFFECT0; TCS_GATE_J],
    head: 0,
    count: 0,
    acked_seq: 0,
    last_seq: 0,
    limits: TCS_EFFECT0,
};

impl TcsFlow {
    /// An unpaired slot. All-zero memory is this value, so a provider's
    /// state is initialised by zeroing it.
    pub const fn empty() -> Self {
        Self {
            live: false,
            role: TcRole::Standby,
            handle: TcHandle {
                slot: 0,
                generation: 0,
            },
            mode: TcMode::PlannedOnly,
            layer_epoch: 0,
            carried: TcsCarried {
                flow_id: [0; 16],
                service_id: [0; 16],
                flow_epoch: 0,
                mirror_generation: 0,
                session_epoch: 0,
                route_generation: 0,
                binding_epoch: 0,
                local_addr_gen: 0,
                iface: 0,
            },
            st: TcsState::zero(),
            has_state: false,
            checkpoint_id: 0,
            asm: CkptAssembler::new([0; 16], 0),
            fin_held: false,
            fin_at: 0,
            order: MdOrder {
                flow_id: [0; 16],
                flow_epoch: 0,
                mirror_generation: 0,
                base_checkpoint: 0,
                applied_seq: 0,
                last_digest: [0; 32],
                recent: [[0; 32]; MD_DUP_WINDOW],
            },
            shadow_valid: false,
            armed: false,
            active: false,
            wrapped: TcsWrapped::empty(),
            wrapped_held: false,
            tls_flow: [0; 16],
            conn_id: 0,
            step: TcsStep::Idle,
            op: 0,
            deadline: 0,
            arg: 0,
            new_epoch: 0,
            fence_gen: 0,
            token: [0; TC_FLOW_TOKEN_LEN],
            drained: false,
            kept: false,
            fenced: false,
            custody_gen: 0,
            mirroring: false,
            gate: TCS_GATE0,
            delta_seq: 0,
            last_digest: [0; 32],
            ip: TcsHalfStream::empty(),
            tls: TcsHalfStream::empty(),
            custody_challenge: [0; 32],
            custody_ev: [0; tc_custody::EVIDENCE_MAX],
            custody_ev_len: 0,
            key_unwrapped: false,
        }
    }

    fn flow_id(&self) -> [u8; 16] {
        self.carried.flow_id
    }
}

/// A per-layer record arriving from a primary's export.
#[derive(PartialEq)]
pub struct TcsLayerRx {
    pub total: usize,
    pub got: usize,
    pub digest: [u8; 32],
    pub committed: bool,
    /// The checkpoint generation the half numbered it with.
    pub gen: u32,
}

impl Default for TcsLayerRx {
    fn default() -> Self {
        Self::new()
    }
}

impl TcsLayerRx {
    pub const fn new() -> Self {
        Self {
            total: 0,
            got: 0,
            digest: [0; 32],
            committed: false,
            gen: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcsCounters {
    pub rejected: u32,
    pub refused_compose: u32,
    pub refused_import: u32,
    pub layer_refusals: u32,
    pub timeouts: u32,
    pub out_full: u32,
    pub activations: u32,
    /// Activations ended after `ip` took the connection and before `tls`
    /// did, whose connection was reset.
    pub unwound: u32,
    pub last_refusal: u8,
    /// The send side of the last export refused: SND.UNA, SND.NXT, the
    /// retransmit window's base, length and anchoring.
    pub last_send: [u32; 5],
    /// Deltas a crash-continuous primary emitted, and pairings it lost.
    pub deltas_out: u32,
    pub mirrors_lost: u32,
    /// Times a half's frame was left on its port for want of room
    /// (`layer_room`): back-pressure, where a full table once ended the
    /// pairing.
    pub layer_holds: u32,
}

/// Operations a busy provider holds until the flow's current one finishes.
const TCS_PENDING: usize = 4;
const TCS_PENDING_MAX: usize = TCS_HDR + TC_HANDLE_LEN + 64;

/// One host's provider over its `ip` and `tls`.
#[derive(PartialEq)]
pub struct TcStack {
    pub anchor_id: [u8; 8],
    /// The custody generation EMISSION_DISABLE reports, advanced per cutoff.
    pub custody_gen: u32,
    pub flows: [TcsFlow; TCS_FLOWS],
    /// The generation of the handle last issued (0 before the first).
    pub last_gen: u32,
    pub counters: TcsCounters,
    pending: [[u8; TCS_PENDING_MAX]; TCS_PENDING],
    pending_len: [usize; TCS_PENDING],
    pending_n: usize,
    scratch: TcsState,
    rec: [u8; TS_CKPT_MAX],
    tcp_half: TcpHalf,
    tcp_rec: [u8; FXTC_MAX],
    tcp_rx: TcsLayerRx,
    tls_rec: [u8; CT_TLS_MAX],
    tls_rx: TcsLayerRx,
    frame: [u8; TCS_HDR + sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX],
    /// One encoded delta.
    md: [u8; MD_FRAME_MAX],
    /// An anchor TOMBSTONE waiting on `ip`: the flow, and when it fails.
    tomb_flow: [u8; 16],
    tomb_deadline: u64,
    /// The STATUS value the next lost pairing reports (`tcs_bounds_detail`
    /// for `tcs_lost::BOUNDS`, else 0).
    lost_detail: u64,
}

/// A STATUS frame.
fn tcs_status<O: TcsOut>(
    out: &mut O,
    op: u8,
    status: u8,
    reason: u8,
    handle: TcHandle,
    value: u64,
    flow: [u8; 16],
) -> bool {
    let mut b = [0u8; TC_STATUS_LEN];
    TcStatus {
        op,
        status,
        reason,
        handle,
        value,
        flow_id: flow,
    }
    .encode(&mut b);
    let mut f = [0u8; TCS_HDR + TC_STATUS_LEN];
    match tc_frame(&mut f, tc_evt::STATUS, &[&b]) {
        Some(n) => out.send(TcsPort::Evt, &f[..n]),
        None => false,
    }
}

fn tcs_evt_h<O: TcsOut>(out: &mut O, evt: u8, h: TcHandle, body: &[u8]) -> bool {
    let mut hb = [0u8; TC_HANDLE_LEN];
    h.put(&mut hb);
    let mut f = [0u8; TC_FRAME_MAX];
    match tc_frame(&mut f, evt, &[&hb, body]) {
        Some(n) => out.send(TcsPort::Evt, &f[..n]),
        None => false,
    }
}

/// One per-layer command `[type][len][flow][epoch][rest…]`.
fn tcs_layer<O: TcsOut>(
    out: &mut O,
    port: TcsPort,
    msg: u8,
    flow: &[u8; 16],
    epoch: u32,
    rest: &[&[u8]],
) -> bool {
    let mut f = [0u8; TCS_HDR + sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX];
    let mut len = 20usize;
    for r in rest {
        len += r.len();
    }
    if TCS_HDR + len > f.len() {
        return false;
    }
    f[0] = msg;
    f[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    f[3..19].copy_from_slice(flow);
    f[19..23].copy_from_slice(&epoch.to_le_bytes());
    let mut at = 23;
    for r in rest {
        f[at..at + r.len()].copy_from_slice(r);
        at += r.len();
    }
    out.send(port, &f[..at])
}

/// Send a whole per-layer record as CHECKPOINT_BEGIN / NEXT* / COMMIT.
fn tcs_send_record<O: TcsOut>(
    out: &mut O,
    port: TcsPort,
    flow: &[u8; 16],
    epoch: u32,
    gen: u32,
    rec: &[u8],
) -> Option<[u8; 32]> {
    let digest = sha256(rec);
    let ok = tcs_layer(
        out,
        port,
        sc::CMD_SC_CHECKPOINT_BEGIN,
        flow,
        epoch,
        &[
            &gen.to_le_bytes(),
            &(rec.len() as u32).to_le_bytes(),
            &digest,
        ],
    );
    if !ok {
        return None;
    }
    let mut off = 0usize;
    while off < rec.len() {
        let n = (rec.len() - off).min(sc::CHECKPOINT_CHUNK_MAX);
        let ok = tcs_layer(
            out,
            port,
            sc::CMD_SC_CHECKPOINT_NEXT,
            flow,
            epoch,
            &[
                &gen.to_le_bytes(),
                &(off as u32).to_le_bytes(),
                &rec[off..off + n],
            ],
        );
        if !ok {
            return None;
        }
        off += n;
    }
    let crc = handoff_crc32(rec);
    let ok = tcs_layer(
        out,
        port,
        sc::CMD_SC_CHECKPOINT_COMMIT,
        flow,
        epoch,
        &[&gen.to_le_bytes(), &crc.to_le_bytes()],
    );
    if ok {
        Some(digest)
    } else {
        None
    }
}

/// ABORT a per-layer pairing (the coordinator's reason). The parts are
/// built here, at run time: a constant slice of slices would be data
/// holding pointers, which a module loaded anywhere cannot carry.
fn tcs_abort<O: TcsOut>(out: &mut O, port: TcsPort, flow: &[u8; 16], epoch: u32) -> bool {
    let reason = [sc::ABORT_COORDINATOR];
    let parts: [&[u8]; 1] = [&reason];
    tcs_layer(out, port, sc::CMD_SC_ABORT, flow, epoch, &parts)
}

/// The per-layer profile a pairing asks its halves for: strict for a
/// crash-continuous primary, whose halves hold each transition for the
/// horizon; planned otherwise (a standby's halves only ever import).
fn tcs_profile(role: TcRole, mode: TcMode) -> u8 {
    if role == TcRole::Primary && mode == TcMode::CrashContinuous {
        sc::PROFILE_CRASH_CONTINUOUS
    } else {
        sc::PROFILE_PLANNED
    }
}

/// HORIZON: the gate's acknowledged delta, both limits, its credit and
/// whether the window is closed (as the core reports it).
fn tcs_horizon<O: TcsOut>(c: &TcsFlow, out: &mut O) -> bool {
    let g = &c.gate;
    let mut hz = [0u8; 20];
    hz[0..8].copy_from_slice(&g.acked_seq.to_le_bytes());
    hz[8..12].copy_from_slice(&g.limits.rx_upto.to_le_bytes());
    hz[12..16].copy_from_slice(&g.limits.tx_upto.to_le_bytes());
    hz[16..18].copy_from_slice(&(g.credits() as u16).to_le_bytes());
    hz[18..20].copy_from_slice(&u16::from(g.credits() == 0).to_le_bytes());
    tcs_evt_h(out, tc_evt::HORIZON, c.handle, &hz)
}

/// `tls`'s codec digest also binds the build's record-layer sizes (its
/// receive buffer, retransmit window and shadow count), so two instances
/// agree only when built alike. This bridge is built for the targets `tls`
/// sizes these for (aarch64), and states them.
#[cfg(target_arch = "aarch64")]
const TCS_TLS_BUILD: [u32; 3] = [16704, 4096, 2];
#[cfg(not(target_arch = "aarch64"))]
const TCS_TLS_BUILD: [u32; 3] = [4096, 4096, 0];

fn tcs_fxtc_digest() -> [u8; 32] {
    sha256(&TCS_FXTC_LABEL)
}

fn tcs_ct_tls_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&TCS_CT_TLS_LABEL);
    for v in TCS_TLS_BUILD {
        h.update(&v.to_le_bytes());
    }
    h.finalize()
}

impl TcStack {
    /// All-zero but for `anchor_id`: zeroed memory with the anchor written
    /// is this value.
    pub const fn new(anchor_id: [u8; 8]) -> Self {
        Self {
            anchor_id,
            custody_gen: 0,
            flows: [const { TcsFlow::empty() }; TCS_FLOWS],
            last_gen: 0,
            counters: TcsCounters {
                rejected: 0,
                refused_compose: 0,
                refused_import: 0,
                layer_refusals: 0,
                timeouts: 0,
                out_full: 0,
                activations: 0,
                unwound: 0,
                last_refusal: 0,
                last_send: [0; 5],
                deltas_out: 0,
                mirrors_lost: 0,
                layer_holds: 0,
            },
            pending: [[0; TCS_PENDING_MAX]; TCS_PENDING],
            pending_len: [0; TCS_PENDING],
            pending_n: 0,
            scratch: TcsState::zero(),
            rec: [0; TS_CKPT_MAX],
            tcp_half: TcpHalf {
                state: 0,
                local_ip: 0,
                remote_ip: 0,
                local_port: 0,
                remote_port: 0,
                prefix_len: 0,
                iss: 0,
                snd_una: 0,
                snd_nxt: 0,
                snd_wnd: 0,
                snd_wl1: 0,
                snd_wl2: 0,
                rcv_nxt: 0,
                rcv_wnd: 0,
                cwnd: 0,
                ssthresh: 0,
                dup_acks: 0,
                in_recovery: 0,
                recover_seq: 0,
                srtt: 0,
                rttvar: 0,
                rto: 0,
                retx_rem: 0,
                tw_rem: 0,
                idle_rem: 0,
                cw_rem: 0,
                delivered: 0,
                consumed: 0,
                ooo_count: 0,
                ooo: [TsOoo {
                    seq: 0,
                    len: 0,
                    bytes: [0; TS_OOO_SEG],
                }; FXTC_REORDER],
                v6: false,
                local_ip6: [0; 16],
                remote_ip6: [0; 16],
            },
            tcp_rec: [0; FXTC_MAX],
            tcp_rx: TcsLayerRx::new(),
            tls_rec: [0; CT_TLS_MAX],
            tls_rx: TcsLayerRx::new(),
            frame: [0; TCS_HDR + sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX],
            md: [0; MD_FRAME_MAX],
            tomb_flow: [0; 16],
            tomb_deadline: 0,
            lost_detail: 0,
        }
    }

    pub fn capabilities(&self) -> u32 {
        TCS_CAPS
    }

    fn slot_of(&self, flow: &[u8; 16]) -> Option<usize> {
        self.flows
            .iter()
            .position(|c| c.live && c.carried.flow_id == *flow)
    }

    pub fn flow(&self, flow: &[u8; 16]) -> Option<&TcsFlow> {
        self.slot_of(flow).map(|i| &self.flows[i])
    }

    /// Whether any flow is waiting on a per-layer exchange.
    pub fn busy(&self) -> bool {
        self.flows.iter().any(|c| c.live && c.step != TcsStep::Idle)
    }

    // ── input: the anchor ────────────────────────────────────────────────

    /// One frame from the anchor (`tc_ctl`): an operation. Anything else
    /// on this port — a wrapped object, a verdict — is not the anchor's to
    /// give, and is ignored.
    pub fn ctl<O: TcsOut>(&mut self, frame: &[u8], now_ms: u64, out: &mut O) {
        let Some((op, len)) = tc_frame_hdr(frame) else {
            return;
        };
        if frame.len() != TCS_HDR + len
            || !(tc_op::PAIR_PREPARE..=tc_op::CUSTODY_UNWRAP).contains(&op)
        {
            return;
        }
        let p = &frame[TCS_HDR..];
        let creates_job = !matches!(
            op,
            tc_op::CHECKPOINT_NEXT
                | tc_op::CHECKPOINT_COMMIT
                | tc_op::DELTA_APPLY
                | tc_op::CUT_IMPORT
                | tc_op::DELTA_ACK
                | tc_op::TOMBSTONE
        );
        if creates_job && self.busy() {
            if self.pending_n < TCS_PENDING && frame.len() <= TCS_PENDING_MAX {
                let k = self.pending_n;
                self.pending[k][..frame.len()].copy_from_slice(frame);
                self.pending_len[k] = frame.len();
                self.pending_n += 1;
            } else {
                let h = TcHandle::get(p).unwrap_or_default();
                self.counters.rejected += 1;
                tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, [0; 16]);
            }
            return;
        }
        self.op(op, p, now_ms, out);
    }

    /// A wrapped continuity object arriving on the custody path (`key_in`).
    pub fn wrapped_in(&mut self, frame: &[u8]) {
        if frame.len() != TCS_HDR + TCS_WRAPPED_LEN || frame[0] != TCS_MSG_WRAPPED {
            return;
        }
        let Some(w) = TcsWrapped::decode(&frame[TCS_HDR..]) else {
            return;
        };
        if let Some(i) = self.slot_of(&w.flow_id) {
            let c = &mut self.flows[i];
            if c.role == TcRole::Standby && !c.active {
                c.wrapped = w;
                c.wrapped_held = true;
            }
        }
    }

    /// The authority's verdict on a token, or on custody evidence, this
    /// provider asked about.
    pub fn verdict_in<O: TcsOut>(&mut self, frame: &[u8], now_ms: u64, out: &mut O) {
        if frame.first() == Some(&TCS_MSG_CUSTODY_VERDICT) {
            return self.custody_verdict(frame, now_ms, out);
        }
        if frame.len() != TCS_HDR + TC_FLOW_TOKEN_LEN + 1 || frame[0] != TCS_MSG_TOKEN_VERDICT {
            return;
        }
        let token = &frame[TCS_HDR..TCS_HDR + TC_FLOW_TOKEN_LEN];
        let verdict = frame[TCS_HDR + TC_FLOW_TOKEN_LEN];
        let Some(i) = self
            .flows
            .iter()
            .position(|c| c.live && c.step == TcsStep::Token && c.token[..] == *token)
        else {
            return;
        };
        if verdict != 0 {
            let c = &mut self.flows[i];
            let (h, flow) = (c.handle, c.flow_id());
            c.step = TcsStep::Idle;
            self.counters.rejected += 1;
            tcs_status(
                out,
                tc_op::ACTIVATE,
                tc_st::UNAUTHORIZED,
                verdict,
                h,
                0,
                flow,
            );
            self.drain_pending(now_ms, out);
            return;
        }
        let c = &mut self.flows[i];
        let flow = c.flow_id();
        let (ne, fg) = (c.new_epoch, c.fence_gen);
        c.step = TcsStep::ActivateIp;
        c.deadline = now_ms + TCS_JOB_MS;
        if !tcs_layer(
            out,
            TcsPort::Ip,
            sc::CMD_SC_ACTIVATE,
            &flow,
            ne,
            &[&fg.to_le_bytes()],
        ) {
            // Never sent: nothing below changed.
            self.flows[i].step = TcsStep::Idle;
            self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
        }
    }

    // ── input: the modules ───────────────────────────────────────────────

    /// May `frame`, whole at the head of a half's port, be taken now? A
    /// crash-continuous flow's half is held — its frame left on the port, so
    /// the half's own horizons and budgets back-pressure the connection —
    /// while the horizon gate lacks credits for what one frame can become
    /// (`TCS_FRAME_DELTAS`), the half's queue of unacknowledged deltas is
    /// full, or the anchor's event queue lacks room for them
    /// (`TCS_FRAME_EVT`); and a `tls` record out waits while the record's
    /// outbound table or send buffer is full, for `ip`'s acknowledgement on
    /// the other port to free it. Each is room the standby's or the peer's
    /// acknowledgement makes, so a full table is a wait, never the end of
    /// the pairing. Any other frame is taken at once.
    pub fn layer_room<O: TcsOut>(&mut self, port: TcsPort, frame: &[u8], out: &O) -> bool {
        if frame.len() < TCS_HDR + sc::FLOW_HEADER_LEN {
            return true;
        }
        let p = &frame[TCS_HDR..];
        let on_ip = port == TcsPort::Ip;
        let Some(c) = self.flows.iter().find(|c| {
            let named = if on_ip { c.flow_id() } else { c.tls_flow };
            c.live && c.mirroring && named[..] == p[..16]
        }) else {
            return true;
        };
        let half = if on_ip { &c.ip } else { &c.tls };
        let mut room = c.gate.credits() >= TCS_FRAME_DELTAS
            && half.pend_n < TCS_PEND
            && out.room(TcsPort::Evt) >= TCS_FRAME_EVT;
        if room
            && !on_ip
            && frame[0] == sc::CMD_SC_DELTA_APPLY
            && p.len() >= sc::DELTA_APPLY_HEADER_LEN + 14
            && p[60] == sc::DELTA_TLS_RECORD_OUT
        {
            let ct = usize::from(le16(p, sc::DELTA_APPLY_HEADER_LEN + 12));
            room = usize::from(c.st.tx_count) < TS_TXREC_MAX
                && usize::from(c.st.send_len) + ct <= TS_SEND_MAX;
        }
        if !room {
            self.counters.layer_holds = self.counters.layer_holds.wrapping_add(1);
        }
        room
    }

    /// One frame from a module's `cont_out`.
    pub fn layer<O: TcsOut>(&mut self, port: TcsPort, frame: &[u8], now_ms: u64, out: &mut O) {
        if frame.len() < TCS_HDR + sc::FLOW_HEADER_LEN {
            return;
        }
        let msg = frame[0];
        let p = &frame[TCS_HDR..];
        let mut f = [0u8; 16];
        f.copy_from_slice(&p[..16]);
        let epoch = le32(p, 16);
        let on_ip = port == TcsPort::Ip;
        let reply = msg == sc::MSG_SC_CONTINUITY && p.len() >= sc::CONTINUITY_HEADER_LEN;
        if on_ip
            && reply
            && p[20] == sc::CR_RETIRED
            && self.tomb_deadline != 0
            && f == self.tomb_flow
        {
            // `ip`'s answer to an anchor TOMBSTONE.
            self.tomb_deadline = 0;
            let (st, v) = match p[21] {
                sc::STATUS_OK => (tc_st::OK, 1),
                sc::STATUS_NO_CAPACITY => (tc_st::CAPACITY, 0),
                _ => (tc_st::NOT_READY, 0),
            };
            tcs_status(out, tc_op::TOMBSTONE, st, 0, TcHandle::default(), v, f);
            return;
        }
        // A crash-continuous primary's halves: their deltas, and their own
        // end of the pairing.
        if let Some(i) = self.flows.iter().position(|c| {
            let named = if on_ip { c.flow_id() } else { c.tls_flow };
            c.live && c.mirroring && named == f
        }) {
            if msg == sc::CMD_SC_DELTA_APPLY {
                return self.layer_delta(i, on_ip, p, out);
            }
            if reply && p[20] == sc::CR_ABORTED && self.flows[i].step == TcsStep::Idle {
                return self.lose_mirror(i, tcs_lost::LAYER, out);
            }
        }
        let Some(i) = self.flows.iter().position(|c| {
            let named = if on_ip { c.flow_id() } else { c.tls_flow };
            // A standby's recipient is named by the record's flow: `tls` holds no
            // session or shadow for it yet.
            let attest = !on_ip && c.step == TcsStep::CustodyAttest && c.flow_id() == f;
            c.live && c.step != TcsStep::Idle && (named == f || attest)
        }) else {
            return;
        };
        match msg {
            sc::CMD_SC_CHECKPOINT_BEGIN
            | sc::CMD_SC_CHECKPOINT_NEXT
            | sc::CMD_SC_CHECKPOINT_COMMIT => self.export_frame(i, port, msg, p, now_ms, out),
            sc::MSG_SC_CONTINUITY if p.len() >= sc::CONTINUITY_HEADER_LEN => {
                let (record, status) = (p[20], p[21]);
                self.reply(i, port, epoch, record, status, &p[22..], now_ms, out);
            }
            _ => {}
        }
    }

    /// A frame on a half's port was too large to read: whatever it was,
    /// a crash-continuous stream from that half has a hole now.
    pub fn layer_overrun<O: TcsOut>(&mut self, port: TcsPort, out: &mut O) {
        for i in 0..TCS_FLOWS {
            if self.flows[i].live && self.flows[i].mirroring && port != TcsPort::Evt {
                self.lose_mirror(i, tcs_lost::LAYER, out);
            }
        }
    }

    /// Per-layer operations whose reply never came.
    pub fn poll<O: TcsOut>(&mut self, now_ms: u64, out: &mut O) {
        if self.tomb_deadline != 0 && now_ms >= self.tomb_deadline {
            self.tomb_deadline = 0;
            self.counters.timeouts += 1;
            let f = self.tomb_flow;
            tcs_status(
                out,
                tc_op::TOMBSTONE,
                tc_st::NOT_READY,
                0,
                TcHandle::default(),
                0,
                f,
            );
        }
        for i in 0..TCS_FLOWS {
            let c = &self.flows[i];
            if c.live && c.step != TcsStep::Idle && now_ms >= c.deadline {
                self.counters.timeouts += 1;
                self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
            }
            let c = &self.flows[i];
            if c.live && c.mirroring && (c.ip.covered > c.ip.acked || c.tls.covered > c.tls.acked) {
                self.settle(i, out);
            }
        }
    }

    // ── the operations ───────────────────────────────────────────────────

    fn op<O: TcsOut>(&mut self, op: u8, p: &[u8], now_ms: u64, out: &mut O) {
        let h = TcHandle::get(p).unwrap_or_default();
        let body = if p.len() >= TC_HANDLE_LEN {
            &p[TC_HANDLE_LEN..]
        } else {
            &[][..]
        };
        match op {
            tc_op::PAIR_PREPARE => return self.pair_prepare(body, now_ms, out),
            tc_op::TOMBSTONE => {
                // `[flow 16][epoch u32][ttl_ms u32]`, for a flow this host
                // may never have held: `ip` installs it (CMD_TOMBSTONE)
                // and answers; a RETIRE leaves one of its own.
                let mut flow = [0u8; 16];
                if body.len() != 24 || !h.is_null() {
                    if body.len() >= 16 {
                        flow.copy_from_slice(&body[..16]);
                    }
                    tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                    return;
                }
                flow.copy_from_slice(&body[..16]);
                if self.tomb_deadline != 0 {
                    tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                    return;
                }
                let (epoch, ttl) = (le32(body, 16), le32(body, 20));
                if !tcs_layer(
                    out,
                    TcsPort::Ip,
                    TCS_IP_TOMBSTONE,
                    &flow,
                    epoch,
                    &[&ttl.to_le_bytes()],
                ) {
                    tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                    return;
                }
                self.tomb_flow = flow;
                self.tomb_deadline = now_ms.max(1) + TCS_JOB_MS;
                return;
            }
            _ => {}
        }
        let slot = h.slot as usize;
        let Some(i) = slot
            .checked_sub(1)
            .filter(|&i| i < TCS_FLOWS && self.flows[i].live)
        else {
            self.counters.rejected += 1;
            tcs_status(out, op, tc_st::STALE_HANDLE, 0, h, 0, [0; 16]);
            return;
        };
        let flow = self.flows[i].flow_id();
        if self.flows[i].handle != h || h.is_null() {
            self.counters.rejected += 1;
            tcs_status(out, op, tc_st::STALE_HANDLE, 0, h, 0, flow);
            return;
        }
        let role = self.flows[i].role;
        let e = self.flows[i].layer_epoch;
        let tls_flow = self.flows[i].tls_flow;
        if matches!(op, tc_op::RETIRE | tc_op::ABORT | tc_op::EMISSION_DISABLE) {
            // The halves' pairing ends with the operation, and with it their
            // delta streams.
            self.flows[i].mirroring = false;
        }
        match (op, role) {
            (tc_op::QUIESCE_BEGIN, TcRole::Primary) => {
                self.begin(i, op, TcsStep::QuiesceIp, now_ms);
                let ok = tcs_layer(
                    out,
                    TcsPort::Ip,
                    sc::CMD_SC_QUIESCE_BEGIN,
                    &flow,
                    e,
                    &[&TCS_QUIESCE_MS.to_le_bytes()],
                );
                if !ok {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::QUIESCE_STATUS, TcRole::Primary) => {
                self.begin(i, op, TcsStep::StatusIp, now_ms);
                if !tcs_layer(out, TcsPort::Ip, sc::CMD_SC_QUIESCE_STATUS, &flow, e, &[]) {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::CUT_EXPORT, TcRole::Primary) if self.flows[i].mirroring => {
                // The deltas made the record the standby holds; the cut is
                // that record, once every one of them is acknowledged.
                let c = &self.flows[i];
                if !c.gate.covered() {
                    tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                    return;
                }
                let Some(digest) = tc_state_digest(&c.st, &mut self.rec) else {
                    tcs_status(out, op, tc_st::UNSUPPORTED, 0, h, 0, flow);
                    return;
                };
                let cut = TcCut {
                    flow_id: flow,
                    flow_epoch: c.st.flow_epoch,
                    mirror_generation: c.carried.mirror_generation,
                    last_seq: c.delta_seq,
                    state_digest: digest,
                };
                let mut b = [0u8; TC_CUT_LEN];
                cut.encode(&mut b);
                tcs_evt_h(out, tc_evt::CUT, h, &b);
                tcs_status(out, op, tc_st::OK, 0, h, 0, flow);
            }
            (tc_op::DELTA_ACK, TcRole::Primary) if self.flows[i].mirroring => {
                let Some(seq) = body.get(0..8).map(|b| le64(b, 0)) else {
                    tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                    return;
                };
                self.flows[i].gate.ack(seq);
                self.settle(i, out);
                tcs_horizon(&self.flows[i], out);
            }
            (tc_op::CHECKPOINT_BEGIN | tc_op::CUT_EXPORT, TcRole::Primary) => {
                // A new checkpoint starts the halves' streams afresh.
                self.flows[i].mirroring = false;
                let id = if op == tc_op::CHECKPOINT_BEGIN {
                    match body.get(0..8) {
                        Some(b) => le64(b, 0),
                        None => {
                            tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                            return;
                        }
                    }
                } else {
                    if !self.flows[i].has_state {
                        tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                        return;
                    }
                    0
                };
                self.begin(i, op, TcsStep::ExportIp, now_ms);
                self.flows[i].arg = id;
                self.tcp_rx = TcsLayerRx::new();
                if !tcs_layer(out, TcsPort::Ip, sc::CMD_SC_CUT_EXPORT, &flow, e, &[]) {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::RETIRE, TcRole::Primary) if self.flows[i].fenced => {
                // The cutoff already dropped the connection from both
                // modules; nothing is left here but the pairing.
                self.flows[i].live = false;
                tcs_status(out, op, tc_st::OK, 0, h, 0, flow);
            }
            (tc_op::EMISSION_DISABLE, TcRole::Primary) => {
                // The enforceable cutoff: both modules drop the connection
                // silently, so `ip` can never emit for it again, and a late
                // segment meets its tombstone instead of a reset. One-way,
                // as the cutoff is in the core: an aborted takeover does
                // not bring the old emitter back.
                if self.flows[i].fenced {
                    let g = u64::from(self.flows[i].custody_gen);
                    tcs_status(out, op, tc_st::OK, 0, h, g, flow);
                    return;
                }
                self.begin(i, op, TcsStep::RetireIp, now_ms);
                if !tcs_layer(out, TcsPort::Ip, sc::CMD_SC_RETIRE, &flow, e, &[]) {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::RETIRE, TcRole::Primary) => {
                self.begin(i, op, TcsStep::RetireIp, now_ms);
                if !tcs_layer(out, TcsPort::Ip, sc::CMD_SC_RETIRE, &flow, e, &[]) {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::ABORT | tc_op::RETIRE, _) => {
                // A primary's pairing dropped (it continues unprotected), or
                // a standby's shadows discarded.
                self.begin(i, op, TcsStep::AbortIp, now_ms);
                let ok = tcs_abort(out, TcsPort::Ip, &flow, e);
                if !ok {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
                let _ = tls_flow;
            }
            (tc_op::CHECKPOINT_NEXT, TcRole::Standby) => {
                let c = &mut self.flows[i];
                if c.armed || c.asm.offer(body).is_err() {
                    c.shadow_valid = false;
                    self.counters.rejected += 1;
                    tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::CHUNK]);
                }
            }
            (tc_op::CHECKPOINT_COMMIT, TcRole::Standby) => self.commit(i, h, body, out),
            (tc_op::DELTA_APPLY, TcRole::Standby) => self.delta(i, h, body, out),
            (tc_op::CUT_IMPORT, TcRole::Standby) => {
                let Some(cut) = TcCut::decode(body) else {
                    tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                    return;
                };
                let c = &self.flows[i];
                let d = tc_state_digest(&c.st, &mut self.rec);
                let ok = c.shadow_valid
                    && cut.flow_id == flow
                    && cut.last_seq == c.order.applied()
                    && d == Some(cut.state_digest);
                let st = if ok { tc_st::OK } else { tc_st::INVALID };
                tcs_status(out, op, st, 0, h, 0, flow);
            }
            (tc_op::EMISSION_ARM, TcRole::Standby) => self.arm(i, h, now_ms, out),
            (tc_op::CUSTODY_ATTEST, TcRole::Standby) => {
                // A fresh recipient for this flow's key, attested over the
                // transfer's challenge. Named by the record's flow: the session's
                // own name at `tls` is learnt only with the wrapped object.
                if body.len() != 32 || self.flows[i].active {
                    tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                    return;
                }
                self.begin(i, op, TcsStep::CustodyAttest, now_ms);
                let ok = tcs_layer(
                    out,
                    TcsPort::Tls,
                    sc::CMD_SC_CUSTODY,
                    &flow,
                    e,
                    &[&[sc::custody::ATTEST], body],
                );
                if !ok {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::CUSTODY_WRAP, TcRole::Primary) => self.custody_wrap(i, h, body, now_ms, out),
            (tc_op::CUSTODY_UNWRAP, TcRole::Standby) => {
                // The wrapped key goes to the vault that attested its
                // recipient, for the session the wrapped object names.
                let c = &self.flows[i];
                if body.len() != tc_custody::WRAPPED_LEN || c.active {
                    tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                    return;
                }
                if !c.wrapped_held {
                    tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                    return;
                }
                let tf = c.wrapped.tls_flow;
                let le = c.wrapped.layer_epoch;
                self.begin(i, op, TcsStep::CustodyUnwrap, now_ms);
                self.flows[i].tls_flow = tf;
                let ok = tcs_layer(
                    out,
                    TcsPort::Tls,
                    sc::CMD_SC_CUSTODY,
                    &tf,
                    le,
                    &[&[sc::custody::UNWRAP], &flow, body],
                );
                if !ok {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (tc_op::ACTIVATE, TcRole::Standby) => self.activate(i, h, body, now_ms, out),
            _ => {
                // DELTA_ACK: no delta stream over the modules
                // (see the head of this file); anything else is the wrong
                // role for the operation.
                let st = if op == tc_op::DELTA_ACK {
                    tc_st::UNSUPPORTED
                } else {
                    tc_st::INVALID
                };
                tcs_status(out, op, st, 0, h, 0, flow);
            }
        }
    }

    /// CUSTODY_WRAP `[challenge 32][evidence]`: checked here for its shape,
    /// then put to the authority; `tls` wraps only on its verdict.
    fn custody_wrap<O: TcsOut>(
        &mut self,
        i: usize,
        h: TcHandle,
        body: &[u8],
        now_ms: u64,
        out: &mut O,
    ) {
        let op = tc_op::CUSTODY_WRAP;
        let flow = self.flows[i].flow_id();
        if body.len() < 32 {
            tcs_status(
                out,
                op,
                tc_st::INVALID,
                tc_custody::why::EVIDENCE,
                h,
                0,
                flow,
            );
            return;
        }
        let (ch, ev) = body.split_at(32);
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(ch);
        if let Err(why) = TcCustodyEvidence::check(ev, &challenge) {
            self.counters.rejected += 1;
            tcs_status(out, op, tc_st::INVALID, why, h, 0, flow);
            return;
        }
        let e = self.flows[i].layer_epoch;
        self.begin(i, op, TcsStep::CustodyAuth, now_ms);
        let c = &mut self.flows[i];
        c.custody_challenge = challenge;
        c.custody_ev[..ev.len()].copy_from_slice(ev);
        c.custody_ev_len = ev.len();
        let mut f = [0u8; TCS_HDR + 16 + 4 + 32 + tc_custody::EVIDENCE_MAX];
        let len = 16 + 4 + 32 + ev.len();
        f[0] = TCS_MSG_CUSTODY_CHECK;
        f[1..3].copy_from_slice(&(len as u16).to_le_bytes());
        f[3..19].copy_from_slice(&flow);
        f[19..23].copy_from_slice(&e.to_le_bytes());
        f[23..55].copy_from_slice(&challenge);
        f[55..55 + ev.len()].copy_from_slice(ev);
        if !out.send(TcsPort::Auth, &f[..TCS_HDR + len]) {
            self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
        }
    }

    /// The authority's verdict on custody evidence.
    fn custody_verdict<O: TcsOut>(&mut self, frame: &[u8], now_ms: u64, out: &mut O) {
        if frame.len() != TCS_HDR + 16 + 32 + 1 {
            return;
        }
        let p = &frame[TCS_HDR..];
        let Some(i) = self.flows.iter().position(|c| {
            c.live
                && c.step == TcsStep::CustodyAuth
                && c.flow_id()[..] == p[..16]
                && sha256(&c.custody_ev[..c.custody_ev_len])[..] == p[16..48]
        }) else {
            return;
        };
        let verdict = p[48];
        if verdict != 0 {
            self.counters.rejected += 1;
            return self.fail(i, tc_st::UNAUTHORIZED, verdict, now_ms, out);
        }
        let c = &mut self.flows[i];
        let (tf, e) = (c.tls_flow, c.layer_epoch);
        c.step = TcsStep::CustodyWrap;
        c.deadline = now_ms + TCS_JOB_MS;
        let (ch, ev, n) = (c.custody_challenge, c.custody_ev, c.custody_ev_len);
        let ok = tcs_layer(
            out,
            TcsPort::Tls,
            sc::CMD_SC_CUSTODY,
            &tf,
            e,
            &[&[sc::custody::WRAP], &ch, &ev[..n]],
        );
        if !ok {
            self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
        }
    }

    fn begin(&mut self, i: usize, op: u8, step: TcsStep, now_ms: u64) {
        let c = &mut self.flows[i];
        c.op = op;
        c.step = step;
        c.deadline = now_ms + TCS_JOB_MS;
        c.drained = true;
    }

    /// End flow `i`'s operation with `status`, and run what waited on it.
    fn fail<O: TcsOut>(&mut self, i: usize, status: u8, reason: u8, now_ms: u64, out: &mut O) {
        match self.flows[i].step {
            TcsStep::ActivateIp => self.unwind_activation(i, true, out),
            TcsStep::ActivateTls => self.unwind_activation(i, false, out),
            _ => {}
        }
        let c = &mut self.flows[i];
        let (op, h, flow) = (c.op, c.handle, c.flow_id());
        c.step = TcsStep::Idle;
        if op == tc_op::PAIR_PREPARE && !c.kept {
            // The pairing never existed.
            c.live = false;
        }
        self.counters.last_refusal = reason;
        self.counters.layer_refusals += 1;
        tcs_status(out, op, status, reason, h, 0, flow);
        self.drain_pending(now_ms, out);
    }

    /// ACTIVATE ended after `ip` may have taken the connection and before
    /// `tls` answered: `ip` may hold a live connection no session serves,
    /// with its shadow spent, so the activation cannot be retried. `ip`
    /// resets the connection it activated at the new epoch (and, when its
    /// answer never came — `ip_unanswered` — discards a shadow still held
    /// at the old one), `tls` lets go of its shadow at the old epoch and
    /// ends a session it activated after all at the new one, and the flow
    /// is no longer armed: the connection ends here rather than running on
    /// half-served.
    fn unwind_activation<O: TcsOut>(&mut self, i: usize, ip_unanswered: bool, out: &mut O) {
        let c = &mut self.flows[i];
        let (flow, tf, ne, e) = (c.flow_id(), c.tls_flow, c.new_epoch, c.layer_epoch);
        c.armed = false;
        c.shadow_valid = false;
        self.counters.unwound += 1;
        let ip = tcs_abort(out, TcsPort::Ip, &flow, ne)
            && (!ip_unanswered || tcs_abort(out, TcsPort::Ip, &flow, e));
        let tls = tcs_abort(out, TcsPort::Tls, &tf, e) && tcs_abort(out, TcsPort::Tls, &tf, ne);
        if !(ip && tls) {
            self.counters.out_full += 1;
        }
    }

    fn done<O: TcsOut>(&mut self, i: usize, value: u64, now_ms: u64, out: &mut O) {
        let c = &mut self.flows[i];
        let (op, h, flow) = (c.op, c.handle, c.flow_id());
        c.step = TcsStep::Idle;
        if !tcs_status(out, op, tc_st::OK, 0, h, value, flow) {
            self.counters.out_full += 1;
        }
        self.drain_pending(now_ms, out);
    }

    fn drain_pending<O: TcsOut>(&mut self, now_ms: u64, out: &mut O) {
        while self.pending_n > 0 && !self.busy() {
            let mut f = [0u8; TCS_PENDING_MAX];
            let n = self.pending_len[0];
            f[..n].copy_from_slice(&self.pending[0][..n]);
            for k in 1..self.pending_n {
                self.pending[k - 1] = self.pending[k];
                self.pending_len[k - 1] = self.pending_len[k];
            }
            self.pending_n -= 1;
            self.ctl(&f[..n], now_ms, out);
        }
    }

    fn pair_prepare<O: TcsOut>(&mut self, body: &[u8], now_ms: u64, out: &mut O) {
        let op = tc_op::PAIR_PREPARE;
        let null = TcHandle::default();
        let Some(pair) = TcPair::decode(body) else {
            let mut f = [0u8; 16];
            if body.len() >= 16 {
                f.copy_from_slice(&body[..16]);
            }
            tcs_status(out, op, tc_st::INVALID, 0, null, 0, f);
            return;
        };
        let flow = pair.flow_id;
        if pair.transport != TcTransport::TcpTls {
            tcs_status(out, op, tc_st::UNSUPPORTED, 0, null, 0, flow);
            return;
        }
        let Some(i) = self
            .slot_of(&flow)
            .or_else(|| self.flows.iter().position(|c| !c.live))
        else {
            tcs_status(out, op, tc_st::CAPACITY, 0, null, 0, flow);
            return;
        };
        // A re-pair keeps what the flow carried through earlier hops.
        let keep = self.flows[i].live && self.flows[i].active;
        let c = &mut self.flows[i];
        if !keep {
            c.carried = TcsCarried {
                flow_id: flow,
                service_id: pair.service_id,
                flow_epoch: pair.flow_epoch,
                mirror_generation: pair.mirror_generation,
                session_epoch: 1,
                route_generation: 1,
                binding_epoch: 1,
                local_addr_gen: 0,
                iface: 0,
            };
            c.tls_flow = [0; 16];
            c.wrapped_held = false;
        }
        c.carried.service_id = pair.service_id;
        c.carried.flow_epoch = pair.flow_epoch;
        c.carried.mirror_generation = pair.mirror_generation;
        c.kept = keep;
        c.fenced = false;
        c.live = true;
        c.role = pair.role;
        c.mode = pair.mode;
        c.layer_epoch = pair.flow_epoch;
        self.last_gen = self.last_gen.wrapping_add(1);
        c.handle = TcHandle {
            slot: i as u32 + 1,
            generation: self.last_gen,
        };
        c.has_state = false;
        c.checkpoint_id = 0;
        c.shadow_valid = false;
        c.armed = false;
        c.active = pair.role == TcRole::Primary;
        c.asm.reset(flow, pair.flow_epoch);
        c.mirroring = false;
        c.key_unwrapped = false;
        c.custody_ev_len = 0;
        // A crash-continuous primary pairs its halves strict: each holds
        // its transitions until the delta covering them is acknowledged.
        let profile = tcs_profile(pair.role, pair.mode);
        let step = if pair.role == TcRole::Primary {
            TcsStep::PrepIp
        } else {
            TcsStep::ShadowIp
        };
        self.begin(i, op, step, now_ms);
        let ok = tcs_layer(
            out,
            TcsPort::Ip,
            sc::CMD_SC_PAIR_PREPARE,
            &flow,
            pair.flow_epoch,
            &[&[sc::CT_TCP, profile], &tcs_fxtc_digest()],
        );
        if !ok {
            self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
        }
    }

    fn commit<O: TcsOut>(&mut self, i: usize, h: TcHandle, body: &[u8], out: &mut O) {
        let Some(id) = body.get(0..8).map(|b| le64(b, 0)) else {
            tcs_status(
                out,
                tc_op::CHECKPOINT_COMMIT,
                tc_st::INVALID,
                0,
                h,
                0,
                self.flows[i].flow_id(),
            );
            return;
        };
        let Self {
            flows,
            scratch,
            counters,
            ..
        } = self;
        let c = &mut flows[i];
        let chain = c.asm.verifier.chain;
        let vid = c.asm.verifier.id;
        // A checkpoint of this pairing only, into a shadow not yet armed:
        // the armed halves are what activation emits from.
        let r = if !c.armed
            && vid.checkpoint_id == id
            && vid.mirror_generation == c.carried.mirror_generation
        {
            c.asm.publish(scratch, &mut c.st)
        } else {
            Err(CkptError::RangeMissing)
        };
        if r.is_err() {
            counters.rejected += 1;
            tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::COMMIT]);
            return;
        }
        // The keys the shadow names are the wrapped object this host holds.
        let held = c.wrapped_held
            && c.wrapped.digest() == c.st.wrapped_digest
            && c.st.read_key.backend == TCS_VAULT_BACKEND
            && c.st.write_key.backend == TCS_VAULT_BACKEND
            && c.st.read_key.generation == c.wrapped.layer_epoch;
        if !held {
            c.shadow_valid = false;
            counters.rejected += 1;
            tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::KEYS]);
            return;
        }
        c.asm.verifier.seal();
        c.shadow_valid = true;
        c.has_state = true;
        c.checkpoint_id = id;
        c.order = MdOrder::after_checkpoint(
            c.flow_id(),
            c.st.flow_epoch,
            c.carried.mirror_generation,
            id,
            chain,
        );
        let mut a = [0u8; 16];
        a[0..8].copy_from_slice(&id.to_le_bytes());
        tcs_evt_h(out, tc_evt::APPLIED, h, &a);
    }

    fn delta<O: TcsOut>(&mut self, i: usize, h: TcHandle, body: &[u8], out: &mut O) {
        let Self {
            flows,
            scratch,
            counters,
            ..
        } = self;
        let c = &mut flows[i];
        if !c.shadow_valid || c.armed {
            counters.rejected += 1;
            tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::NO_SHADOW]);
            return;
        }
        let Ok((hd, payload)) = md_parse(body) else {
            counters.rejected += 1;
            tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::MALFORMED]);
            return;
        };
        match c.order.verify(&hd) {
            Ok(MdVerdict::Duplicate) => {
                let mut a = [0u8; 16];
                a[0..8].copy_from_slice(&c.checkpoint_id.to_le_bytes());
                a[8..16].copy_from_slice(&c.order.applied().to_le_bytes());
                tcs_evt_h(out, tc_evt::APPLIED, h, &a);
            }
            Ok(MdVerdict::Apply) => {
                // A KeyUpdate names the next secret by reference; `tls`
                // derives it in this host's record layer from the sealed set
                // the wrapped object holds when the halves are imported
                // (from the CT_TLS record). It must name that object, and stay
                // within what `tls` derives forward.
                if hd.kind == MdKind::KeyUpdate && !tcs_derivable(&c.st, &c.wrapped, payload) {
                    c.shadow_valid = false;
                    counters.rejected += 1;
                    tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::DERIVE]);
                    return;
                }
                if md_apply(&mut c.st, scratch, hd.kind, payload).is_err() {
                    c.shadow_valid = false;
                    counters.rejected += 1;
                    tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::TRANSITION]);
                    return;
                }
                c.order.commit(&hd);
                let mut a = [0u8; 16];
                a[0..8].copy_from_slice(&c.checkpoint_id.to_le_bytes());
                a[8..16].copy_from_slice(&hd.seq.to_le_bytes());
                tcs_evt_h(out, tc_evt::APPLIED, h, &a);
            }
            Err(MdReject::Stale) => {}
            Err(_) => {
                c.shadow_valid = false;
                counters.rejected += 1;
                tcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::ORDER]);
            }
        }
    }

    fn arm<O: TcsOut>(&mut self, i: usize, h: TcHandle, now_ms: u64, out: &mut O) {
        let op = tc_op::EMISSION_ARM;
        let flow = self.flows[i].flow_id();
        if !self.flows[i].shadow_valid {
            tcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
            return;
        }
        if self.flows[i].armed {
            tcs_status(out, op, tc_st::OK, 0, h, 0, flow);
            return;
        }
        if let Err(why) = tcs_importable(&self.flows[i].st, &self.flows[i].wrapped) {
            self.counters.refused_import += 1;
            tcs_status(
                out,
                op,
                tc_st::UNSUPPORTED,
                tcs_why::IMPORT | why.why() & 0x0F,
                h,
                0,
                flow,
            );
            return;
        }
        // The TCP half into `ip`'s shadow (prepared at PAIR_PREPARE).
        let Self {
            flows,
            tcp_half,
            tcp_rec,
            ..
        } = self;
        let c = &mut flows[i];
        c.tls_flow = c.wrapped.tls_flow;
        tcs_tcp_half(&c.st, tcp_half);
        let Some(n) = fxtc_encode(tcp_half, tcp_rec) else {
            return self.fail_op(i, op, tc_st::INVALID, now_ms, out);
        };
        let e = c.layer_epoch;
        self.begin(i, op, TcsStep::ImportIp, now_ms);
        match tcs_send_record(out, TcsPort::Ip, &flow, e, 1, &self.tcp_rec[..n]) {
            Some(d) => self.tcp_rx.digest = d,
            None => self.fail(i, tc_st::NOT_READY, 0, now_ms, out),
        }
    }

    fn fail_op<O: TcsOut>(&mut self, i: usize, op: u8, status: u8, now_ms: u64, out: &mut O) {
        self.flows[i].op = op;
        self.flows[i].step = TcsStep::ArmIp;
        self.fail(i, status, 0, now_ms, out);
    }

    fn activate<O: TcsOut>(
        &mut self,
        i: usize,
        h: TcHandle,
        body: &[u8],
        now_ms: u64,
        out: &mut O,
    ) {
        let op = tc_op::ACTIVATE;
        let flow = self.flows[i].flow_id();
        let (Some(new_epoch), Some(fence_gen), Some(cap)) = (
            body.get(0..4).map(|b| le32(b, 0)),
            body.get(4..8).map(|b| le32(b, 0)),
            body.get(8..24).and_then(|b| <[u8; 16]>::try_from(b).ok()),
        ) else {
            tcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
            return;
        };
        let c = &self.flows[i];
        // Fail closed, cheapest first; then the authority's check of the
        // token it minted for THIS anchor.
        let refusal = if !c.armed {
            Some(tc_act::NOT_ARMED)
        } else if fence_gen == 0 {
            Some(tc_act::NO_FENCE)
        } else if new_epoch <= c.st.flow_epoch || new_epoch <= c.layer_epoch {
            Some(tc_act::EPOCH_NOT_HIGHER)
        } else {
            None
        };
        if let Some(why) = refusal {
            self.counters.rejected += 1;
            tcs_status(out, op, tc_st::UNAUTHORIZED, why, h, 0, flow);
            return;
        }
        let mut t = [0u8; TC_FLOW_TOKEN_LEN];
        TcFlowToken {
            flow_id: flow,
            epoch: new_epoch,
            anchor: self.anchor_id,
            fence_gen,
            capability: cap,
        }
        .encode(&mut t);
        self.begin(i, op, TcsStep::Token, now_ms);
        let c = &mut self.flows[i];
        c.new_epoch = new_epoch;
        c.fence_gen = fence_gen;
        c.token = t;
        let mut f = [0u8; TCS_HDR + TC_FLOW_TOKEN_LEN];
        f[0] = TCS_MSG_TOKEN_CHECK;
        f[1..3].copy_from_slice(&(TC_FLOW_TOKEN_LEN as u16).to_le_bytes());
        f[3..].copy_from_slice(&t);
        if !out.send(TcsPort::Auth, &f) {
            self.fail(i, tc_st::UNAUTHORIZED, 0, now_ms, out);
        }
    }

    // ── a crash-continuous primary's delta stream ────────────────────────

    /// One delta from a half of a mirroring flow `i`
    /// (`[flow][epoch][gen][no][prev][kind][body]`): the deltas it is,
    /// emitted under the gate, and what acknowledging it to that half waits
    /// for. A half's transition the stream cannot carry ends the pairing.
    fn layer_delta<O: TcsOut>(&mut self, i: usize, on_ip: bool, p: &[u8], out: &mut O) {
        if p.len() < sc::DELTA_APPLY_HEADER_LEN {
            return;
        }
        let (epoch, gen, no, kind) = (le32(p, 16), le32(p, 20), le32(p, 24), p[60]);
        let body = &p[sc::DELTA_APPLY_HEADER_LEN..];
        if epoch != self.flows[i].layer_epoch {
            // A delta of another epoch of the flow.
            return;
        }
        let half = if on_ip {
            &mut self.flows[i].ip
        } else {
            &mut self.flows[i].tls
        };
        if gen != half.gen {
            // A stream of an earlier checkpoint.
            return;
        }
        if no != half.last.wrapping_add(1) {
            return self.lose_mirror(i, tcs_lost::GAP, out);
        }
        half.last = no;
        let cond = if on_ip {
            self.ip_delta(i, kind, body, out)
        } else {
            self.tls_delta(i, kind, body, out)
        };
        let Ok(cond) = cond else {
            let why = cond.unwrap_err();
            return self.lose_mirror(i, why, out);
        };
        let c = &mut self.flows[i];
        let half = if on_ip { &mut c.ip } else { &mut c.tls };
        if !half.push(no, cond) {
            return self.lose_mirror(i, tcs_lost::FULL, out);
        }
        self.settle(i, out);
    }

    /// `ip`'s delta: the receive and emission horizons it waits on, or the
    /// delta it is.
    fn ip_delta<O: TcsOut>(
        &mut self,
        i: usize,
        kind: u8,
        b: &[u8],
        out: &mut O,
    ) -> Result<TcsCond, u8> {
        use tcs_lost::*;
        let mut pl = [0u8; 32];
        match kind {
            // `[seq 4][len 2][after 4][fin 1]`: the ACK `ip` may show is
            // the receive horizon reaching `after` (the bytes come as
            // `tls`'s RECV_BYTES).
            sc::DELTA_TCP_RECV if b.len() == 11 => {
                let after = le32(b, 6);
                if b[10] != 0 {
                    // The peer's FIN, one sequence number past its last
                    // byte. Those bytes come as `tls`'s RECV_BYTES, maybe
                    // later: the `Fin` is deferred until the record's
                    // RCV.NXT reaches it, and the ACK `ip` shows for it
                    // waits on the horizon past it.
                    let c = &mut self.flows[i];
                    if c.st.fin_rcvd || c.fin_held {
                        return Err(DIVERGED);
                    }
                    c.fin_held = true;
                    c.fin_at = after.wrapping_sub(1);
                    self.deferred_fin(i, out)?;
                }
                Ok(TcsCond::Rx(after))
            }
            // `[seq 4][len 2][fin 1]`: the bytes are in the record's send buffer
            // since `tls`'s RECORD_OUT; the segment waits for its horizon.
            sc::DELTA_TCP_SEND if b.len() == 7 => {
                let end = le32(b, 0).wrapping_add(u32::from(le16(b, 4)));
                if b[6] != 0 {
                    // Our FIN, one sequence number past the bytes before it:
                    // a `Fin` out (once, after our close_notify), and the
                    // segment waits for the horizon past it.
                    let st = &self.flows[i].st;
                    if st.fin_queued
                        || !st.close_notify_sent
                        || !matches!(st.tcp, TsTcp::Established | TsTcp::CloseWait)
                        || end != st.send_end()
                    {
                        return Err(DIVERGED);
                    }
                    let m = md_dir(&mut pl, MD_DIR_OUT).ok_or(DIVERGED)?;
                    self.md_emit(i, MdKind::Fin, &pl[..m], out)?;
                    return Ok(TcsCond::Tx(end.wrapping_add(1)));
                }
                Ok(TcsCond::Tx(end))
            }
            // `[snd_una 4][snd_wnd 2][cwnd 2][ssthresh 2]`.
            sc::DELTA_TCP_ACKED if b.len() == 10 => {
                let n = md_peer_ack(&mut pl, le32(b, 0), u32::from(le16(b, 4))).ok_or(DIVERGED)?;
                self.md_emit(i, MdKind::PeerAck, &pl[..n], out)
            }
            // `[state 1][rto 2][srtt 2][rttvar 2][cwnd 2][ssthresh 2]`.
            sc::DELTA_TCP_TIMERS if b.len() == 11 => {
                // The state itself moves by the `Fin` delta.
                if !matches!(
                    b[0],
                    FXTC_ESTABLISHED
                        | FXTC_CLOSE_WAIT
                        | FXTC_FIN_WAIT_1
                        | FXTC_FIN_WAIT_2
                        | FXTC_CLOSING
                        | FXTC_LAST_ACK
                ) {
                    return Err(UNREPRESENTABLE);
                }
                let st = &self.flows[i].st;
                let ss = le16(b, 9);
                let t = MdTimers {
                    rto_ms: u32::from(le16(b, 1)).min(TS_TIMER_MAX_MS),
                    persist_ms: st.persist_ms,
                    keepalive_ms: st.keepalive_ms,
                    timewait_ms: st.timewait_ms,
                    srtt_us: u32::from(le16(b, 3)) * TCS_SRTT_UNIT_US,
                    rttvar_us: u32::from(le16(b, 5)) * TCS_RTTVAR_UNIT_US,
                    cwnd: u32::from(le16(b, 7)).max(1),
                    ssthresh: if ss == u16::MAX {
                        u32::MAX
                    } else {
                        u32::from(ss)
                    },
                };
                let n = md_timers(&mut pl, &t).ok_or(DIVERGED)?;
                self.md_emit(i, MdKind::Timers, &pl[..n], out)
            }
            _ => Err(UNREPRESENTABLE),
        }
    }

    /// The peer's FIN `ip` reported, as a `Fin` once the record has every
    /// byte before it.
    fn deferred_fin<O: TcsOut>(&mut self, i: usize, out: &mut O) -> Result<(), u8> {
        let c = &self.flows[i];
        if c.fin_held && c.fin_at == c.st.rcv_nxt {
            let mut pl = [0u8; 4];
            let m = md_dir(&mut pl, MD_DIR_IN).ok_or(tcs_lost::DIVERGED)?;
            self.md_emit(i, MdKind::Fin, &pl[..m], out)?;
            self.flows[i].fin_held = false;
        }
        Ok(())
    }

    /// `tls`'s delta: the deltas it is.
    fn tls_delta<O: TcsOut>(
        &mut self,
        i: usize,
        kind: u8,
        b: &[u8],
        out: &mut O,
    ) -> Result<TcsCond, u8> {
        use tcs_lost::*;
        let mut pl = [0u8; MD_PAYLOAD_MAX];
        match kind {
            // `[recv_len 4][bytes]`: the partial record as it now stands;
            // what it holds past the record's receive buffer is new from `ip`.
            sc::DELTA_TLS_RECV_BYTES if b.len() >= 4 => {
                let n = le32(b, 0) as usize;
                let bytes = b.get(4..).filter(|x| x.len() == n).ok_or(DIVERGED)?;
                let (have, held) = {
                    let st = &self.flows[i].st;
                    (usize::from(st.recv_len), st.recv)
                };
                if n < have || bytes[..have] != held[..have] {
                    return Err(DIVERGED);
                }
                let mut cond = TcsCond::Free;
                let mut at = have;
                while at < n {
                    let k = (n - at).min(TCS_SEG_CHUNK);
                    let seq = self.flows[i].st.rcv_nxt;
                    let m = md_rx_segment(&mut pl, seq, &bytes[at..at + k]).ok_or(DIVERGED)?;
                    cond = self.md_emit(i, MdKind::RxSegment, &pl[..m], out)?;
                    at += k;
                }
                self.deferred_fin(i, out)?;
                Ok(cond)
            }
            // `[read_epoch 4][read_seq 8][recv_expected 4][partial_len 4]
            //  [partial][type 1][plain_len 2][plain]`: one record consumed,
            // its sequence already past it, and what it opened to.
            sc::DELTA_TLS_RECORD_IN if b.len() >= 20 => {
                let (ep, next_seq, part) = (le32(b, 0), le64(b, 4), le32(b, 16) as usize);
                let partial = b.get(20..20 + part).ok_or(DIVERGED)?;
                let t = b
                    .get(20 + part..)
                    .filter(|t| t.len() >= 3)
                    .ok_or(UNREPRESENTABLE)?;
                let (ctype, plen) = (t[0], usize::from(le16(t, 1)));
                let plain = t.get(3..).filter(|x| x.len() == plen).ok_or(DIVERGED)?;
                if ctype == TCS_NOT_CARRIED || plen > TS_DELIV_BYTES {
                    return Err(UNREPRESENTABLE);
                }
                let st = &self.flows[i].st;
                let have = usize::from(st.recv_len);
                if part >= have || st.recv[have - part..have] != *partial || next_seq == 0 {
                    return Err(DIVERGED);
                }
                let consume = (have - part) as u16;
                // Application data after the peer's close_notify is not
                // handed up (RFC 8446 §6.1), so it is no delivery.
                let delivers = ctype == TCS_CT_APPLICATION && plen > 0 && !st.close_notify_rcvd;
                let deliv = if delivers { st.next_delivery } else { 0 };
                let body: &[u8] = if delivers { plain } else { &[] };
                let m = md_rx_record(
                    &mut pl,
                    consume,
                    ep.wrapping_add(TCS_EPOCH_BASE),
                    next_seq - 1,
                    deliv,
                    body,
                )
                .ok_or(DIVERGED)?;
                let mut cond = self.md_emit(i, MdKind::RxRecord, &pl[..m], out)?;
                if ctype == TCS_CT_ALERT && plain.get(1) == Some(&0) {
                    // close_notify.
                    let m = md_dir(&mut pl, MD_DIR_IN).ok_or(DIVERGED)?;
                    cond = self.md_emit(i, MdKind::CloseNotify, &pl[..m], out)?;
                }
                Ok(cond)
            }
            // `[write_epoch 4][write_seq 8][ct_len 2][ct][out_bytes 8]`: a
            // record about to be written, the next production, and the
            // consumer's clear bytes through it.
            sc::DELTA_TLS_RECORD_OUT if b.len() >= 14 + 8 => {
                let (ep, seq, n) = (le32(b, 0), le64(b, 4), usize::from(le16(b, 12)));
                let ct = b.get(14..14 + n).ok_or(DIVERGED)?;
                if b.len() != 14 + n + 8 {
                    return Err(DIVERGED);
                }
                let out_bytes = le64(b, 14 + n);
                let prod = self.flows[i].st.next_production;
                let m = md_tx_record(
                    &mut pl,
                    prod,
                    ep.wrapping_add(TCS_EPOCH_BASE),
                    seq,
                    ct,
                    out_bytes,
                )
                .ok_or(UNREPRESENTABLE)?;
                self.md_emit(i, MdKind::TxRecord, &pl[..m], out)
            }
            // The window slid; the record's send buffer slides on `ip`'s ACKED.
            sc::DELTA_TLS_RETX_ACK => Ok(TcsCond::Free),
            // Our close_notify, its ciphertext the RECORD_OUT before it.
            sc::DELTA_TLS_CLOSE_SENT if b.is_empty() => {
                if self.flows[i].st.close_notify_sent {
                    return Err(DIVERGED);
                }
                let m = md_dir(&mut pl, MD_DIR_OUT).ok_or(DIVERGED)?;
                self.md_emit(i, MdKind::CloseNotify, &pl[..m], out)
            }
            // `[consumed 8][consumer_cursor 8][cursor_at 8]`: what the
            // consumer has consumed (the records ending at or before
            // `cursor_at`), and the cursor and clear byte its
            // acknowledgement carried. A count behind the record's is of
            // deliveries consumed before it; the cursor still moves.
            TCS_TLS_DELIVERED if b.len() == 24 => {
                let (n, cc, at) = (le64(b, 0), le64(b, 8), le64(b, 16));
                let st = &self.flows[i].st;
                let n = n.max(st.delivery_acked);
                if at < st.cursor_at
                    || (n == st.delivery_acked && cc == st.consumer_cursor && at == st.cursor_at)
                {
                    return Ok(TcsCond::Free);
                }
                if n >= st.next_delivery {
                    return Err(DIVERGED);
                }
                let m = md_delivery_ack(&mut pl, n, cc, at).ok_or(DIVERGED)?;
                self.md_emit(i, MdKind::DeliveryAck, &pl[..m], out)
            }
            // `[direction 1][epoch 4][sealed_len 2][sealed]`: a direction
            // rotated (0 write, 1 read) into `epoch`. The new secret never
            // crosses: the record names it by reference into the wrapped object the
            // standby holds, and the standby's `tls` derives it from the
            // sealed set at import. A write rotation is `tls`'s barrier —
            // nothing goes out under it until this delta is covered.
            sc::DELTA_TLS_KEY_UPDATE if b.len() >= 7 => {
                let (dir, ep) = (b[0], le32(b, 1));
                let st = &self.flows[i].st;
                let wr = &self.flows[i].wrapped;
                let (md_dir, purpose, sealed, at) = match dir {
                    0 => (
                        MD_DIR_OUT,
                        TS_VAULT_WRITE,
                        wr.sealed_write_epoch,
                        st.write_epoch,
                    ),
                    1 => (
                        MD_DIR_IN,
                        TS_VAULT_READ,
                        wr.sealed_read_epoch,
                        st.read_epoch,
                    ),
                    _ => return Err(DIVERGED),
                };
                let new_epoch = ep.wrapping_add(TCS_EPOCH_BASE);
                if new_epoch != at.wrapping_add(1) || ep < sealed {
                    return Err(DIVERGED);
                }
                if ep - sealed > TCS_DERIVE_MAX {
                    return Err(UNREPRESENTABLE);
                }
                let vref = TsVaultRef {
                    backend: TCS_VAULT_BACKEND,
                    purpose,
                    object: st.read_key.object,
                    generation: wr.layer_epoch,
                    epoch: new_epoch,
                };
                let wd = st.wrapped_digest;
                // `[dir][epoch][sealed_len][sealed]`, and after an inbound
                // rotation `[owed]`: the peer asked for ours.
                let sealed_len = usize::from(le16(b, 5));
                let owed = match (dir, b.get(7 + sealed_len..)) {
                    (0, Some([])) => false,
                    (1, Some([o @ (0 | 1)])) => *o == 1,
                    _ => return Err(DIVERGED),
                };
                let m =
                    md_key_update(&mut pl, md_dir, new_epoch, &vref, &wd, owed).ok_or(DIVERGED)?;
                self.md_emit(i, MdKind::KeyUpdate, &pl[..m], out)
            }
            _ => Err(UNREPRESENTABLE),
        }
    }

    /// Apply one delta to the flow's record, journal its effect in the
    /// gate and emit it; what acknowledging the half's delta waits for.
    fn md_emit<O: TcsOut>(
        &mut self,
        i: usize,
        kind: MdKind,
        payload: &[u8],
        out: &mut O,
    ) -> Result<TcsCond, u8> {
        let Self {
            flows,
            scratch,
            md,
            counters,
            lost_detail,
            ..
        } = self;
        let c = &mut flows[i];
        if c.gate.credits() == 0 {
            return Err(tcs_lost::FULL);
        }
        let mut h = MdHdr {
            kind,
            flow_id: c.st.flow_id,
            flow_epoch: c.st.flow_epoch,
            mirror_generation: c.carried.mirror_generation,
            base_checkpoint: c.checkpoint_id,
            seq: c.delta_seq + 1,
            prev: c.last_digest,
            payload_len: 0,
            digest: [0; 32],
        };
        let n = md_encode(&mut h, payload, md).ok_or(tcs_lost::UNREPRESENTABLE)?;
        match md_apply(&mut c.st, scratch, kind, payload) {
            Ok(()) => {}
            Err(CkptError::Bounds) => {
                *lost_detail = tcs_bounds_detail(kind, &c.st);
                return Err(tcs_lost::BOUNDS);
            }
            Err(_) => return Err(tcs_lost::DIVERGED),
        }
        c.delta_seq += 1;
        c.last_digest = h.digest;
        if c.gate.record(MdEffect::of(c.delta_seq, &c.st)).is_err() {
            return Err(tcs_lost::FULL);
        }
        if !tcs_evt_h(out, tc_evt::DELTA, c.handle, &md[..n]) {
            counters.out_full += 1;
            return Err(tcs_lost::FULL);
        }
        counters.deltas_out += 1;
        Ok(TcsCond::Seq(c.delta_seq))
    }

    /// Acknowledge to each half what the gate now covers. An
    /// acknowledgement the port has no room for stays owed and goes out on
    /// a later step (`poll`): the half holds its transitions until it does.
    fn settle<O: TcsOut>(&mut self, i: usize, out: &mut O) {
        let c = &mut self.flows[i];
        let (flow, tf, e) = (c.flow_id(), c.tls_flow, c.layer_epoch);
        if let Some(no) = c.ip.settle(&c.gate) {
            let g = c.ip.gen;
            if tcs_layer(
                out,
                TcsPort::Ip,
                sc::CMD_SC_DELTA_ACK,
                &flow,
                e,
                &[&g.to_le_bytes(), &no.to_le_bytes()],
            ) {
                c.ip.acked = no;
            } else {
                self.counters.out_full += 1;
            }
        }
        let c = &mut self.flows[i];
        if let Some(no) = c.tls.settle(&c.gate) {
            let g = c.tls.gen;
            if tcs_layer(
                out,
                TcsPort::Tls,
                sc::CMD_SC_DELTA_ACK,
                &tf,
                e,
                &[&g.to_le_bytes(), &no.to_le_bytes()],
            ) {
                c.tls.acked = no;
            } else {
                self.counters.out_full += 1;
            }
        }
    }

    /// The crash-continuous pairing of flow `i` cannot go on: both halves
    /// end theirs (and let go of what they hold), and the anchor is told.
    /// The connection runs on here, unprotected.
    fn lose_mirror<O: TcsOut>(&mut self, i: usize, why: u8, out: &mut O) {
        let c = &mut self.flows[i];
        if !c.mirroring {
            return;
        }
        c.mirroring = false;
        c.has_state = false;
        let (flow, tf, e, h) = (c.flow_id(), c.tls_flow, c.layer_epoch, c.handle);
        let reason = [sc::ABORT_MIRROR_LOST];
        let parts: [&[u8]; 1] = [&reason];
        let _ = tcs_layer(out, TcsPort::Ip, sc::CMD_SC_ABORT, &flow, e, &parts);
        let _ = tcs_layer(out, TcsPort::Tls, sc::CMD_SC_ABORT, &tf, e, &parts);
        self.counters.mirrors_lost += 1;
        self.counters.last_refusal = tcs_why::MIRROR | why;
        let detail = core::mem::take(&mut self.lost_detail);
        tcs_status(
            out,
            tc_op::ABORT,
            tc_st::UNSUPPORTED,
            tcs_why::MIRROR | why,
            h,
            if why == tcs_lost::BOUNDS { detail } else { 0 },
            flow,
        );
    }

    // ── the primary's export ─────────────────────────────────────────────

    /// A checkpoint frame from a primary module's CUT_EXPORT, landing in
    /// that layer's record buffer.
    fn export_frame<O: TcsOut>(
        &mut self,
        i: usize,
        port: TcsPort,
        msg: u8,
        p: &[u8],
        now_ms: u64,
        out: &mut O,
    ) {
        let step = self.flows[i].step;
        let (rx, buf): (&mut TcsLayerRx, &mut [u8]) = match (port, step) {
            (TcsPort::Ip, TcsStep::ExportIp) => (&mut self.tcp_rx, &mut self.tcp_rec[..]),
            (TcsPort::Tls, TcsStep::ExportTls) => (&mut self.tls_rx, &mut self.tls_rec[..]),
            _ => return,
        };
        let bad = match msg {
            sc::CMD_SC_CHECKPOINT_BEGIN if p.len() == sc::CHECKPOINT_BEGIN_PAYLOAD_LEN => {
                let total = le32(p, 24) as usize;
                *rx = TcsLayerRx::new();
                rx.total = total;
                rx.gen = le32(p, 20);
                rx.digest.copy_from_slice(&p[28..60]);
                total > buf.len()
            }
            sc::CMD_SC_CHECKPOINT_NEXT if p.len() >= sc::CHECKPOINT_NEXT_HEADER_LEN => {
                let off = le32(p, 24) as usize;
                let data = &p[sc::CHECKPOINT_NEXT_HEADER_LEN..];
                if off != rx.got || off + data.len() > rx.total.min(buf.len()) {
                    true
                } else {
                    buf[off..off + data.len()].copy_from_slice(data);
                    rx.got += data.len();
                    false
                }
            }
            sc::CMD_SC_CHECKPOINT_COMMIT if p.len() == sc::CHECKPOINT_COMMIT_PAYLOAD_LEN => {
                let crc = le32(p, 24);
                let whole = rx.got == rx.total
                    && handoff_crc32(&buf[..rx.total]) == crc
                    && sha256(&buf[..rx.total]) == rx.digest;
                rx.committed = whole;
                !whole
            }
            _ => true,
        };
        if bad {
            self.counters.refused_compose += 1;
            self.fail(i, tc_st::UNSUPPORTED, tcs_why::LAYER_FRAME, now_ms, out);
        }
    }

    /// Both halves are in: compose, check, and either chunk the record out
    /// (CHECKPOINT_BEGIN) or report the cut (CUT_EXPORT).
    fn exported<O: TcsOut>(&mut self, i: usize, now_ms: u64, out: &mut O) {
        let op = self.flows[i].op;
        let Self {
            flows,
            scratch,
            rec,
            tcp_half,
            tcp_rec,
            tcp_rx,
            tls_rec,
            tls_rx,
            ..
        } = self;
        let c = &mut flows[i];
        let (tl, ll) = (tcp_rx.total, tls_rx.total);
        let th = match (
            fxtc_decode(&tcp_rec[..tl], tcp_half),
            ct_tls_decode(&tls_rec[..ll]),
        ) {
            (Ok(()), Ok(th)) => th,
            (Err(e), _) => {
                self.counters.refused_compose += 1;
                let why = tcs_why::FXTC | (e as u8 & 0x0F);
                return self.fail(i, tc_st::UNSUPPORTED, why, now_ms, out);
            }
            (_, Err(e)) => {
                self.counters.refused_compose += 1;
                let why = tcs_why::CT_TLS | (e as u8 & 0x0F);
                return self.fail(i, tc_st::UNSUPPORTED, why, now_ms, out);
            }
        };
        let mut wr = TcsWrapped::empty();
        wr.flow_id = c.flow_id();
        wr.tls_flow = c.tls_flow;
        wr.layer_epoch = c.layer_epoch;
        wr.sealed_read_epoch = th.sealed_read_epoch;
        wr.sealed_write_epoch = th.sealed_write_epoch;
        wr.alpn_len = th.alpn_len;
        wr.alpn = th.alpn;
        wr.sni = th.sni;
        wr.sni_bytes = th.sni_bytes;
        wr.peer_profile = th.peer_profile;
        wr.peer_block = th.peer_block;
        wr.exporter_ctx = th.exporter_ctx;
        wr.sealed
            .copy_from_slice(&tls_rec[th.sealed_at..th.sealed_at + TCS_SEALED_LEN]);
        if op == tc_op::CUT_EXPORT {
            // The seal is randomised per export; the secrets it seals are
            // fixed by the epochs and sequences the record already names.
            // So the cut keeps the checkpoint's object, and holds only if
            // nothing else moved.
            let mut same = c.wrapped;
            same.sealed = wr.sealed;
            if same != wr {
                return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
            }
            wr = c.wrapped;
        }
        let carried = c.carried;
        if let Err(why) = tcs_compose(tcp_half, &th, &tls_rec[..ll], &wr, &carried, scratch) {
            self.counters.last_send = [
                tcp_half.snd_una,
                tcp_half.snd_nxt,
                th.retx_base,
                u32::from(th.retx_len),
                u32::from(th.retx_anchored),
            ];
            self.counters.refused_compose += 1;
            return self.fail(i, tc_st::UNSUPPORTED, why.why(), now_ms, out);
        }
        if op == tc_op::CUT_EXPORT {
            let now = tc_state_digest(scratch, rec);
            let Some(digest) = tc_state_digest(&c.st, rec) else {
                return self.fail(i, tc_st::UNSUPPORTED, 0, now_ms, out);
            };
            if now != Some(digest) {
                // The connection moved since the checkpoint: take another.
                return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
            }
            let cut = TcCut {
                flow_id: c.flow_id(),
                flow_epoch: c.st.flow_epoch,
                mirror_generation: c.carried.mirror_generation,
                last_seq: 0,
                state_digest: digest,
            };
            let mut b = [0u8; TC_CUT_LEN];
            cut.encode(&mut b);
            let h = c.handle;
            tcs_evt_h(out, tc_evt::CUT, h, &b);
            return self.done(i, 0, now_ms, out);
        }
        // CHECKPOINT_BEGIN: the object on the custody path first, then the
        // record's chunks.
        c.st = *scratch;
        c.wrapped = wr;
        c.has_state = true;
        let id = c.arg;
        c.checkpoint_id = id;
        let mut wf = [0u8; TCS_HDR + TCS_WRAPPED_LEN];
        wf[0] = TCS_MSG_WRAPPED;
        wf[1..3].copy_from_slice(&(TCS_WRAPPED_LEN as u16).to_le_bytes());
        let mut wb = [0u8; TCS_WRAPPED_LEN];
        wr.encode(&mut wb);
        wf[3..].copy_from_slice(&wb);
        if !out.send(TcsPort::Key, &wf) {
            self.counters.out_full += 1;
            return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
        }
        let n = match ts_encode(&c.st, rec) {
            Ok(n) => n,
            Err(_) => return self.fail(i, tc_st::UNSUPPORTED, 0, now_ms, out),
        };
        let cid = CkptId {
            checkpoint_id: id,
            flow_id: c.flow_id(),
            flow_epoch: c.st.flow_epoch,
            mirror_generation: c.carried.mirror_generation,
            total: n as u32,
        };
        let mut chain = ckpt_chain_seed(&cid);
        let h = c.handle;
        for k in 0..ckpt_chunk_count(n) {
            let mut chunk = [0u8; CKPT_CHUNK_MAX];
            if let Some(m) = ckpt_write_chunk(&cid, &rec[..n], k, &mut chain, &mut chunk) {
                if !tcs_evt_h(out, tc_evt::CHUNK, h, &chunk[..m]) {
                    self.counters.out_full += 1;
                    return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
        }
        if c.mode == TcMode::CrashContinuous {
            // Mirroring starts here: each half learns its checkpoint is
            // held (which, strict, also ends its quiesce), and from now on
            // its deltas become this stream's.
            c.mirroring = true;
            c.fin_held = false;
            c.gate = MdGate::at_checkpoint(true, &c.st);
            c.delta_seq = 0;
            c.last_digest = chain;
            c.ip = TcsHalfStream::at(tcp_rx.gen);
            c.tls = TcsHalfStream::at(tls_rx.gen);
            let (flow, tf, e) = (c.flow_id(), c.tls_flow, c.layer_epoch);
            let committed = [sc::CR_CHECKPOINT_COMMITTED, sc::STATUS_OK];
            let (ig, id_, tg, td) = (tcp_rx.gen, tcp_rx.digest, tls_rx.gen, tls_rx.digest);
            let ok = tcs_layer(
                out,
                TcsPort::Ip,
                sc::MSG_SC_CONTINUITY,
                &flow,
                e,
                &[&committed, &ig.to_le_bytes(), &id_],
            ) && tcs_layer(
                out,
                TcsPort::Tls,
                sc::MSG_SC_CONTINUITY,
                &tf,
                e,
                &[&committed, &tg.to_le_bytes(), &td],
            );
            if !ok {
                self.counters.out_full += 1;
                self.flows[i].mirroring = false;
                return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
            }
        }
        self.done(i, id, now_ms, out);
    }

    // ── per-layer replies ────────────────────────────────────────────────

    #[allow(
        clippy::too_many_arguments,
        reason = "a reply is its flow slot, layer, epoch, record, status and body"
    )]
    fn reply<O: TcsOut>(
        &mut self,
        i: usize,
        port: TcsPort,
        epoch: u32,
        record: u8,
        status: u8,
        body: &[u8],
        now_ms: u64,
        out: &mut O,
    ) {
        let step = self.flows[i].step;
        let flow = self.flows[i].flow_id();
        let tls_flow = self.flows[i].tls_flow;
        let e = self.flows[i].layer_epoch;
        let ok = status == sc::STATUS_OK;
        use TcsStep::*;
        let on_ip = port == TcsPort::Ip;
        // A layer's refusal ends the operation; a reply for another step
        // (a late duplicate, an unsolicited quiesce report) is not this
        // one's.
        macro_rules! next {
            ($step:expr, $port:expr, $msg:expr, $flow:expr, $rest:expr) => {{
                self.flows[i].step = $step;
                self.flows[i].deadline = now_ms + TCS_JOB_MS;
                if !tcs_layer(out, $port, $msg, $flow, e, $rest) {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }};
        }
        match (step, on_ip, record) {
            (PrepIp, true, sc::CR_PAIR_PREPARED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                if body.len() < 6 {
                    // `ip` holds no live connection on that tuple and
                    // reserved a shadow: undo it, the flow is not here.
                    let _ = tcs_abort(out, TcsPort::Ip, &flow, e);
                    return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
                let conn = le16(body, 4);
                let c = &mut self.flows[i];
                c.conn_id = conn;
                if c.tls_flow == [0; 16] {
                    c.tls_flow[0..2].copy_from_slice(&conn.to_le_bytes());
                }
                let tf = c.tls_flow;
                let profile = tcs_profile(c.role, c.mode);
                next!(
                    PrepTls,
                    TcsPort::Tls,
                    sc::CMD_SC_PAIR_PREPARE,
                    &tf,
                    &[&[sc::CT_TLS, profile], &tcs_ct_tls_digest()]
                );
            }
            (PrepTls, false, sc::CR_PAIR_PREPARED) => {
                if !ok {
                    let _ = tcs_abort(out, TcsPort::Ip, &flow, e);
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                self.done(i, 0, now_ms, out);
            }
            (ShadowIp, true, sc::CR_PAIR_PREPARED) => {
                if !ok || body.len() >= 6 {
                    // Refused, or the tuple is live here: no standby.
                    return self.fail(i, tc_st::CAPACITY, status, now_ms, out);
                }
                self.done(i, 0, now_ms, out);
            }
            (QuiesceIp, true, sc::CR_QUIESCED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                next!(
                    QuiesceTls,
                    TcsPort::Tls,
                    sc::CMD_SC_QUIESCE_BEGIN,
                    &tls_flow,
                    &[&TCS_QUIESCE_MS.to_le_bytes()]
                );
            }
            (QuiesceTls, false, sc::CR_QUIESCED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                self.done(i, 0, now_ms, out);
            }
            (StatusIp, true, sc::CR_QUIESCED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                // Quiescent is drained: nothing stashed below `ip`'s send
                // window, nothing gated. Bytes in flight are not waited on —
                // `tls`'s retransmit window, anchored by `ip`'s `MSG_ACK`,
                // holds exactly `[SND.UNA, SND.NXT)` and the cut carries it.
                self.flows[i].drained = body.first() == Some(&1);
                next!(
                    StatusTls,
                    TcsPort::Tls,
                    sc::CMD_SC_QUIESCE_STATUS,
                    &tls_flow,
                    &[]
                );
            }
            (StatusTls, false, sc::CR_QUIESCED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                let c = &self.flows[i];
                let both =
                    c.drained && body.first() == Some(&1) && (!c.mirroring || c.gate.covered());
                self.done(i, u64::from(both), now_ms, out);
            }
            (ExportIp, true, sc::CR_CUT) => {
                if !ok || !self.tcp_rx.committed {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                self.tls_rx = TcsLayerRx::new();
                next!(
                    ExportTls,
                    TcsPort::Tls,
                    sc::CMD_SC_CUT_EXPORT,
                    &tls_flow,
                    &[]
                );
            }
            (ExportTls, false, sc::CR_CUT) => {
                if !ok || !self.tls_rx.committed {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                self.exported(i, now_ms, out);
            }
            (ExportIp, true, sc::CR_ABORTED) | (ExportTls, false, sc::CR_ABORTED) => {
                self.counters.refused_compose += 1;
                self.fail(i, tc_st::UNSUPPORTED, status, now_ms, out);
            }
            (RetireIp, true, sc::CR_RETIRED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                next!(RetireTls, TcsPort::Tls, sc::CMD_SC_RETIRE, &tls_flow, &[]);
            }
            (RetireTls, false, sc::CR_RETIRED) => {
                // `ip` has dropped the connection silently; whatever `tls`
                // answers, the flow emits nothing from this host again.
                let cutoff = self.flows[i].op == tc_op::EMISSION_DISABLE;
                if cutoff {
                    self.custody_gen += 1;
                    self.flows[i].fenced = true;
                    self.flows[i].custody_gen = self.custody_gen;
                } else {
                    self.flows[i].live = false;
                }
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                let value = if cutoff {
                    u64::from(self.custody_gen)
                } else {
                    0
                };
                self.done(i, value, now_ms, out);
            }
            (AbortIp, true, sc::CR_ABORTED) if epoch == e => {
                if tls_flow == [0; 16] {
                    self.flows[i].live = false;
                    return self.done(i, 0, now_ms, out);
                }
                let reason = [sc::ABORT_COORDINATOR];
                next!(
                    AbortTls,
                    TcsPort::Tls,
                    sc::CMD_SC_ABORT,
                    &tls_flow,
                    &[&reason]
                );
            }
            (AbortTls, false, sc::CR_ABORTED) if epoch == e => {
                self.flows[i].live = false;
                self.done(i, 0, now_ms, out);
            }
            // ── the standby's import ──
            (ImportIp, true, sc::CR_CHECKPOINT_ACK) if ok => {}
            (ImportIp, true, sc::CR_CHECKPOINT_COMMITTED) => {
                if !ok {
                    self.counters.refused_import += 1;
                    return self.fail(i, tc_st::INVALID, status, now_ms, out);
                }
                let d = self.tcp_rx.digest;
                next!(
                    CutIp,
                    TcsPort::Ip,
                    sc::CMD_SC_CUT_IMPORT,
                    &flow,
                    &[&1u32.to_le_bytes(), &d]
                );
            }
            (CutIp, true, sc::CR_IMPORTED) => {
                if !ok {
                    return self.fail(i, tc_st::INVALID, status, now_ms, out);
                }
                next!(ArmIp, TcsPort::Ip, sc::CMD_SC_EMISSION_ARM, &flow, &[]);
            }
            (ArmIp, true, sc::CR_ARMED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                next!(
                    ShadowTls,
                    TcsPort::Tls,
                    sc::CMD_SC_PAIR_PREPARE,
                    &tls_flow,
                    &[&[sc::CT_TLS, sc::PROFILE_PLANNED], &tcs_ct_tls_digest()]
                );
            }
            (ShadowTls, false, sc::CR_PAIR_PREPARED) => {
                if !ok {
                    return self.fail(i, tc_st::CAPACITY, status, now_ms, out);
                }
                let Self { flows, tls_rec, .. } = self;
                let c = &flows[i];
                let Some(n) = ct_tls_encode(&c.st, &c.wrapped, tls_rec) else {
                    return self.fail(i, tc_st::INVALID, 0, now_ms, out);
                };
                self.flows[i].step = ImportTls;
                self.flows[i].deadline = now_ms + TCS_JOB_MS;
                match tcs_send_record(out, TcsPort::Tls, &tls_flow, e, 1, &self.tls_rec[..n]) {
                    Some(d) => self.tls_rx.digest = d,
                    None => self.fail(i, tc_st::NOT_READY, 0, now_ms, out),
                }
            }
            (ImportTls, false, sc::CR_CHECKPOINT_ACK) if ok => {}
            (ImportTls, false, sc::CR_CHECKPOINT_COMMITTED) => {
                if !ok {
                    // `tls` could not open the sealed set: this vault does
                    // not hold the labelled key.
                    self.counters.refused_import += 1;
                    return self.fail(i, tc_st::INVALID, status, now_ms, out);
                }
                let d = self.tls_rx.digest;
                next!(
                    CutTls,
                    TcsPort::Tls,
                    sc::CMD_SC_CUT_IMPORT,
                    &tls_flow,
                    &[&1u32.to_le_bytes(), &d]
                );
            }
            (CutTls, false, sc::CR_IMPORTED) => {
                if !ok {
                    return self.fail(i, tc_st::INVALID, status, now_ms, out);
                }
                next!(
                    ArmTls,
                    TcsPort::Tls,
                    sc::CMD_SC_EMISSION_ARM,
                    &tls_flow,
                    &[]
                );
            }
            (ArmTls, false, sc::CR_ARMED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                self.flows[i].armed = true;
                self.done(i, 0, now_ms, out);
            }
            (CustodyAttest | CustodyWrap | CustodyUnwrap, false, sc::CR_CUSTODY) => {
                // `[op][reason][bytes]`.
                if body.len() < 2 {
                    return self.fail(i, tc_st::INVALID, 0, now_ms, out);
                }
                let (cop, reason, bytes) = (body[0], body[1], &body[2..]);
                let want = match step {
                    CustodyAttest => sc::custody::ATTEST,
                    CustodyWrap => sc::custody::WRAP,
                    _ => sc::custody::UNWRAP,
                };
                if cop != want {
                    return;
                }
                if !ok {
                    // The vault's refusal, by its reason.
                    let why = match reason {
                        sc::custody::why::CHALLENGE => tc_custody::why::CHALLENGE,
                        sc::custody::why::SIGNATURE => tc_custody::why::SIGNATURE,
                        sc::custody::why::RECIPIENT => tc_custody::why::RECIPIENT,
                        sc::custody::why::NO_RECIPIENT => tc_custody::why::NO_RECIPIENT,
                        sc::custody::why::EVIDENCE => tc_custody::why::EVIDENCE,
                        _ => tc_custody::why::VAULT,
                    };
                    self.counters.rejected += 1;
                    return self.fail(i, tc_st::INVALID, why, now_ms, out);
                }
                let h = self.flows[i].handle;
                let kind = match step {
                    CustodyAttest if bytes.len() >= tc_custody::EVIDENCE_MIN => {
                        Some(tc_custody::EVIDENCE)
                    }
                    CustodyWrap if bytes.len() == tc_custody::WRAPPED_LEN => {
                        Some(tc_custody::WRAPPED)
                    }
                    CustodyUnwrap => None,
                    _ => return self.fail(i, tc_st::INVALID, 0, now_ms, out),
                };
                if let Some(k) = kind {
                    let mut b = [0u8; 1 + tc_custody::EVIDENCE_MAX];
                    let n = bytes.len().min(tc_custody::EVIDENCE_MAX);
                    b[0] = k;
                    b[1..1 + n].copy_from_slice(&bytes[..n]);
                    if !tcs_evt_h(out, tc_evt::CUSTODY, h, &b[..1 + n]) {
                        self.counters.out_full += 1;
                        return self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                    }
                } else {
                    self.flows[i].key_unwrapped = true;
                }
                self.done(i, 0, now_ms, out);
            }
            (ActivateIp, true, sc::CR_ACTIVATED) => {
                if !ok {
                    // `ip` refused: its shadow stands, nothing to undo.
                    self.flows[i].step = Idle;
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                if body.len() < 6 {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                let conn = le16(body, 4);
                let c = &mut self.flows[i];
                c.conn_id = conn;
                let (ne, fg) = (c.new_epoch, c.fence_gen);
                c.step = ActivateTls;
                c.deadline = now_ms + TCS_JOB_MS;
                let ok = tcs_layer(
                    out,
                    TcsPort::Tls,
                    sc::CMD_SC_ACTIVATE,
                    &tls_flow,
                    ne,
                    &[&fg.to_le_bytes(), &conn.to_le_bytes()],
                );
                if !ok {
                    self.fail(i, tc_st::NOT_READY, 0, now_ms, out);
                }
            }
            (ActivateTls, false, sc::CR_ACTIVATED) => {
                if !ok {
                    return self.fail(i, tc_st::NOT_READY, status, now_ms, out);
                }
                // The connection is this host's now: a live, unpaired
                // primary at the new epoch, carrying what it carried.
                let c = &mut self.flows[i];
                c.role = TcRole::Primary;
                c.active = true;
                c.armed = false;
                c.shadow_valid = false;
                c.layer_epoch = c.new_epoch;
                c.carried = TcsCarried::of(&c.st);
                c.carried.flow_epoch = c.new_epoch;
                self.counters.activations += 1;
                self.done(i, 0, now_ms, out);
            }
            _ => {}
        }
    }
}
