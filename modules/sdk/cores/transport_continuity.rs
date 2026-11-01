// transport_continuity_core — the TRANSPORT_CONTINUITY provider for one
// host's TCP/TLS connections (`contracts/net/transport_continuity.rs`).
//
// Include after the contract, with `sha256` / `Sha256` in scope. The
// provider owns, per flow, the canonical `TsState` the contract encodes,
// and answers the anchor's operations on it:
//
// - **Checkpoint export and import.** CHECKPOINT_BEGIN encodes the record
//   and emits it as chained chunks; the standby assembles them into an
//   inactive buffer and publishes into its shadow only a whole, validated
//   record whose every key reference this host's vault holds.
// - **Ordered mirror deltas.** Every transition of a paired primary's
//   state — a peer ACK, received bytes, a consumed or sealed record, a
//   KeyUpdate, a FIN, a delivery acknowledgement — is applied locally and
//   emitted as the next chained delta, and the standby applies the same
//   transition (`md_apply`) under `MdOrder`. Equal histories are equal
//   bytes.
// - **The receive-ACK and emission horizon gate** (`MdGate`). Under
//   `CrashContinuous` the ACK the peer is shown never passes RCV.NXT as of
//   the last delta the standby acknowledged, no byte goes on the wire past
//   the send end it acknowledged, no delivery reaches the worker before the
//   standby holds it, and no record is sealed under a write epoch the
//   standby has not installed (the KeyUpdate barrier, with `TcEpochs`).
//   The journal is bounded: when it is full the window closes to zero and
//   the producer is refused, never queued.
// - **Import, arm, activate.** An imported shadow is silent. EMISSION_ARM
//   holds early segments in a bounded buffer (overflow counted). ACTIVATE
//   needs an armed shadow, a non-zero fence generation, a strictly higher
//   epoch, and a per-flow emission token the authority minted for THIS
//   anchor — checked by the `TcTokenVerifier` the provider is handed — and
//   then re-arms timers on this host's clock with a conservative
//   congestion restart.
// - **The local emission-disable hook.** EMISSION_DISABLE stops every
//   segment, delivery and production for the flow at once and reports the
//   custody generation of the cutoff.
// - **Reset suppression.** A migrated flow's tombstone (TOMBSTONE, or the
//   one RETIRE leaves behind) makes `classify` answer `DropSilently` for a
//   segment that finds no connection here, instead of `Reset`.
//
// Keys never enter this core. The record layer and the vault behind it
// are `TcRecords`: it seals and opens records under the flow's traffic
// secrets, derives a KeyUpdate in-vault and destroys retired epochs, and
// the state names those secrets only by `TsVaultRef`. The emission token
// is checked by the authority's own verifier (the ownership directory's
// token check against its replicated flow state and the group seed),
// which a host binds when it wires the provider; Fluxor carries no
// authority's code.
//
// `no_std`, zero-alloc: the caller owns the provider (it is large: one
// `TsState` per flow slot and a checkpoint buffer) and supplies the clock.

// ── the primary's horizons ────────────────────────────────────────────────

/// One emitted delta's effect on the externally visible horizons.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MdEffect {
    pub seq: u64,
    /// RCV.NXT after the delta (the ACK it would permit).
    pub rx_upto: u32,
    /// Sequence one past the last byte buffered after the delta (the
    /// emission it would permit).
    pub tx_upto: u32,
    /// The next delivery id after the delta.
    pub deliver_upto: u64,
    /// The TLS write epoch after the delta (the KeyUpdate barrier).
    pub write_epoch: u32,
}

impl MdEffect {
    pub fn of(seq: u64, s: &TsState) -> Self {
        Self {
            seq,
            rx_upto: s.rcv_nxt,
            tx_upto: s.send_end(),
            deliver_upto: s.next_delivery,
            write_epoch: s.write_epoch,
        }
    }
}

/// The gate refused to journal another delta: the provider must close its
/// receive window and stop its producer until acknowledgements free room.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MdBackpressure;

/// The strict receive and send horizons over a bounded journal of `J`
/// unacknowledged deltas.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MdGate<const J: usize> {
    /// Strict (crash-continuous): both horizons enforced. Off for an
    /// unprotected or planned-only flow, which a cut synchronises instead.
    pub strict: bool,
    pub journal: [MdEffect; J],
    pub head: usize,
    pub count: usize,
    /// Highest delta the standby acknowledged, and the horizons it carries.
    pub acked_seq: u64,
    pub last_seq: u64,
    pub limits: MdEffect,
}

impl<const J: usize> MdGate<J> {
    /// The horizons are exactly the checkpoint's until a delta is acked.
    pub fn at_checkpoint(strict: bool, s: &TsState) -> Self {
        Self {
            strict,
            journal: [MdEffect::default(); J],
            head: 0,
            count: 0,
            acked_seq: 0,
            last_seq: 0,
            limits: MdEffect::of(0, s),
        }
    }

    pub fn credits(&self) -> usize {
        J - self.count
    }

    /// Journal the effect of the next delta; `Err` is backpressure.
    pub fn record(&mut self, e: MdEffect) -> Result<(), MdBackpressure> {
        if self.count == J || e.seq != self.last_seq + 1 {
            return Err(MdBackpressure);
        }
        self.journal[(self.head + self.count) % J] = e;
        self.count += 1;
        self.last_seq = e.seq;
        Ok(())
    }

    /// The standby acknowledged every delta through `seq`. An ack past
    /// what was sent, or behind one already seen, changes nothing.
    pub fn ack(&mut self, seq: u64) -> bool {
        if seq <= self.acked_seq || seq > self.last_seq {
            return false;
        }
        while self.count > 0 {
            let e = self.journal[self.head];
            if e.seq > seq {
                break;
            }
            self.limits = e;
            self.head = (self.head + 1) % J;
            self.count -= 1;
        }
        self.acked_seq = seq;
        true
    }

    /// The peer may see a cumulative ACK of `ack`.
    pub fn may_ack(&self, ack: u32) -> bool {
        !self.strict || ts_seq_le(ack, self.limits.rx_upto)
    }

    /// Bytes ending at `end` may be put on the wire.
    pub fn may_emit(&self, end: u32) -> bool {
        !self.strict || ts_seq_le(end, self.limits.tx_upto)
    }

    /// Delivery `id` may be handed to the worker.
    pub fn may_deliver(&self, id: u64) -> bool {
        !self.strict || id < self.limits.deliver_upto
    }

    /// A record may be emitted under write epoch `epoch` (the KeyUpdate
    /// barrier: the standby has the new epoch's state installed).
    pub fn may_use_epoch(&self, epoch: u32) -> bool {
        !self.strict || epoch <= self.limits.write_epoch
    }

    /// Every externally visible transition is covered: nothing journaled.
    pub fn covered(&self) -> bool {
        self.count == 0
    }
}

// ── the KeyUpdate barrier and retirement ──────────────────────────────────

/// Write epochs a flow tracks at once: the current one and those retiring.
pub const TC_EPOCHS: usize = 4;

/// One retiring epoch: the sequence just past its last sealed record.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcRetiring {
    pub epoch: u32,
    pub end_seq: u32,
    pub live: bool,
}

/// What a flow may do with its write epochs. A KeyUpdate's new epoch is
/// sealable only once the standby installed it; a retired epoch's secret
/// is destroyed only once the peer acknowledged every record under it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcEpochs {
    /// The epoch new records are sealed under.
    pub current: u32,
    /// The highest epoch the standby has installed.
    pub standby_installed: u32,
    /// A KeyUpdate requested and not yet installed at the standby.
    pub pending: Option<u32>,
    pub retiring: [TcRetiring; TC_EPOCHS],
}

/// Why a KeyUpdate was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcEpochRefuse {
    /// Another update is still waiting for the standby.
    Pending,
    /// Too many epochs retiring: wait for acknowledgements.
    Retiring,
}

impl TcEpochs {
    pub const fn new(epoch: u32) -> Self {
        Self {
            current: epoch,
            standby_installed: epoch,
            pending: None,
            retiring: [TcRetiring {
                epoch: 0,
                end_seq: 0,
                live: false,
            }; TC_EPOCHS],
        }
    }

    /// A KeyUpdate is wanted; `last_end` is the sequence just past the last
    /// record sealed under the current epoch. Returns the new epoch.
    pub fn request(&mut self, last_end: u32) -> Result<u32, TcEpochRefuse> {
        if self.pending.is_some() {
            return Err(TcEpochRefuse::Pending);
        }
        let Some(slot) = self.retiring.iter_mut().find(|r| !r.live) else {
            return Err(TcEpochRefuse::Retiring);
        };
        *slot = TcRetiring {
            epoch: self.current,
            end_seq: last_end,
            live: true,
        };
        let next = self.current + 1;
        self.pending = Some(next);
        Ok(next)
    }

    /// The standby acknowledged installing `epoch`.
    pub fn installed(&mut self, epoch: u32) {
        if Some(epoch) == self.pending {
            self.pending = None;
            self.current = epoch;
        }
        self.standby_installed = self.standby_installed.max(epoch);
    }

    /// A record may be sealed under `epoch`.
    pub fn may_seal(&self, epoch: u32) -> bool {
        epoch == self.current && epoch <= self.standby_installed
    }

    /// The retired epochs whose records the peer acknowledged below
    /// `snd_una`; the caller destroys them.
    pub fn release(&mut self, snd_una: u32, out: &mut [u32; TC_EPOCHS]) -> usize {
        let mut n = 0;
        for r in self.retiring.iter_mut() {
            if r.live && ts_seq_le(r.end_seq, snd_una) {
                out[n] = r.epoch;
                n += 1;
                r.live = false;
            }
        }
        n
    }
}

// ── cutover: early segments, restart, deadlines, tombstones ──────────────

/// Segments an armed standby holds until activation, and the bytes of each
/// (`[seq u32][ack u32][fin u8][payload]`).
pub const TC_EARLY_MAX: usize = 32;
pub const TC_EARLY_BYTES: usize = 1600;

#[derive(PartialEq)]
pub struct TcEarly {
    pub lens: [u16; TC_EARLY_MAX],
    pub bytes: [[u8; TC_EARLY_BYTES]; TC_EARLY_MAX],
    pub count: usize,
    /// Segments that found no room: the declared overflow policy applies,
    /// and it is counted, never hidden.
    pub overflows: u64,
}

impl TcEarly {
    pub const fn new() -> Self {
        Self {
            lens: [0; TC_EARLY_MAX],
            bytes: [[0; TC_EARLY_BYTES]; TC_EARLY_MAX],
            count: 0,
            overflows: 0,
        }
    }

    fn push(&mut self, seq: u32, ack: u32, fin: bool, payload: &[u8]) -> bool {
        if self.count == TC_EARLY_MAX || payload.len() + 9 > TC_EARLY_BYTES {
            self.overflows += 1;
            return false;
        }
        let b = &mut self.bytes[self.count];
        b[0..4].copy_from_slice(&seq.to_le_bytes());
        b[4..8].copy_from_slice(&ack.to_le_bytes());
        b[8] = u8::from(fin);
        b[9..9 + payload.len()].copy_from_slice(payload);
        self.lens[self.count] = (payload.len() + 9) as u16;
        self.count += 1;
        true
    }
}

impl Default for TcEarly {
    fn default() -> Self {
        Self::new()
    }
}

/// The conservative congestion restart, applied at activation:
/// sequence numbers and the RTT estimator kept, the window capped at the
/// admitted restart window, ambiguous recovery state cleared.
pub fn tc_restart(s: &mut TsState, restart_window: u32) {
    s.cwnd = s.cwnd.min(restart_window).max(u32::from(s.mss));
    s.in_recovery = false;
    s.dupacks = 0;
    s.recovery_point = s.snd_una;
}

/// The retransmission deadline of an imported state on this host's
/// monotonic clock: armed whenever anything is outstanding (everything in
/// the send buffer may already have been emitted by the old primary) — at
/// what remains of the record's retransmission timer, a whole interval when
/// the record ran none — and due at once when no time is left.
pub fn tc_rto_deadline(s: &TsState, now_ms: u64) -> u64 {
    if s.send_len > 0 || s.fin_queued {
        let left = if s.retx_rem_ms != 0 {
            s.retx_rem_ms
        } else {
            s.rto_ms
        };
        now_ms + u64::from(left)
    } else {
        0
    }
}

/// What the stack does with a segment for a flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcDisposition {
    /// A live (or armed) connection here: take it.
    Deliver,
    /// A migrated flow: drop silently — no RST, no new connection.
    DropSilently,
    /// Unknown here and not migrated: the ordinary path (a reset).
    Reset,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcTomb {
    pub used: bool,
    pub flow_id: [u8; 16],
    pub epoch: u32,
    pub expires_ms: u64,
}

/// Migrated-flow tombstones. Bounded; a full table refuses an install
/// rather than evict a live tombstone.
pub struct TcTombstones<const N: usize> {
    pub slots: [TcTomb; N],
    pub live: usize,
    /// Segments dropped silently because their flow had migrated.
    pub suppressed: u64,
}

impl<const N: usize> TcTombstones<N> {
    pub const fn new() -> Self {
        Self {
            slots: [TcTomb {
                used: false,
                flow_id: [0; 16],
                epoch: 0,
                expires_ms: 0,
            }; N],
            live: 0,
            suppressed: 0,
        }
    }

    fn expire(&mut self, now_ms: u64) {
        for s in self.slots.iter_mut() {
            if s.used && now_ms >= s.expires_ms {
                *s = TcTomb::default();
                self.live -= 1;
            }
        }
    }

    /// Install (or extend) the tombstone of `flow_id` under `epoch`.
    pub fn install(&mut self, flow_id: &[u8; 16], epoch: u32, ttl_ms: u64, now_ms: u64) -> bool {
        self.expire(now_ms);
        let expires_ms = now_ms.saturating_add(ttl_ms);
        if let Some(s) = self
            .slots
            .iter_mut()
            .find(|s| s.used && s.flow_id == *flow_id)
        {
            s.epoch = s.epoch.max(epoch);
            s.expires_ms = s.expires_ms.max(expires_ms);
            return true;
        }
        let Some(s) = self.slots.iter_mut().find(|s| !s.used) else {
            return false;
        };
        *s = TcTomb {
            used: true,
            flow_id: *flow_id,
            epoch,
            expires_ms,
        };
        self.live += 1;
        true
    }

    pub fn is_tombstoned(&self, flow_id: &[u8; 16], now_ms: u64) -> bool {
        self.slots
            .iter()
            .any(|s| s.used && s.flow_id == *flow_id && now_ms < s.expires_ms)
    }
}

impl<const N: usize> Default for TcTombstones<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ── what the provider is handed ───────────────────────────────────────────

/// TLS record content types the provider acts on.
pub const TC_RT_ALERT: u8 = 21;
pub const TC_RT_APP: u8 = 23;
pub const TC_RT_KEY_UPDATE: u8 = 24;

/// The record layer over the key vault, behind references. Every secret
/// stays on the far side of this trait: the provider hands it a flow, a
/// purpose (`TS_VAULT_READ` / `TS_VAULT_WRITE`), an epoch and a record
/// number, and gets back ciphertext, plaintext or a new reference.
pub trait TcRecords {
    /// The vault holds the flow's secret for `purpose` at `epoch`.
    fn holds(&self, flow: &[u8; 16], purpose: u8, epoch: u32) -> bool;
    /// The length of the complete record at the front of `buf`, if one is.
    fn record_len(&self, buf: &[u8]) -> Option<usize>;
    /// Seal `pt` as one record of type `rtype` under the write secret at
    /// `(epoch, seq)` into `out`; the record's length.
    fn seal(
        &self,
        flow: &[u8; 16],
        epoch: u32,
        seq: u64,
        rtype: u8,
        pt: &[u8],
        out: &mut [u8],
    ) -> Option<usize>;
    /// Open one record under the read secret at `(epoch, seq)` into `out`:
    /// its type and plaintext length; `None` when it does not authenticate.
    fn open(
        &self,
        flow: &[u8; 16],
        epoch: u32,
        seq: u64,
        rec: &[u8],
        out: &mut [u8],
    ) -> Option<(u8, usize)>;
    /// Derive the next epoch's secret in-vault (KeyUpdate) from the one at
    /// `epoch`; the new secret's reference.
    fn derive_next(&mut self, flow: &[u8; 16], purpose: u8, epoch: u32) -> Option<TsVaultRef>;
    /// Destroy one epoch's secret.
    fn destroy(&mut self, flow: &[u8; 16], purpose: u8, epoch: u32);
    /// Destroy every secret of the flow.
    fn destroy_flow(&mut self, flow: &[u8; 16]);
}

/// The authority's check of a per-flow emission token (`TcFlowToken`, its
/// 48-byte wire layout): `Ok` only for the token the committed takeover
/// minted for this flow, epoch, anchor and fence generation; otherwise the
/// authority's refusal code, which ACTIVATE reports as STATUS `reason`.
pub trait TcTokenVerifier {
    fn verify(&self, token: &[u8; TC_FLOW_TOKEN_LEN]) -> Result<(), u8>;
}

/// ACTIVATE refusals the provider makes before asking the verifier
/// (STATUS `reason` with `UNAUTHORIZED`).
pub mod tc_act {
    /// The shadow is not armed.
    pub const NOT_ARMED: u8 = 0xE1;
    /// No fence generation: a takeover without a confirmed fence.
    pub const NO_FENCE: u8 = 0xE2;
    /// The epoch is not strictly higher than the flow's.
    pub const EPOCH_NOT_HIGHER: u8 = 0xE3;
}

/// What this provider enforces, for the host's capability report.
pub const TC_PROVIDER_CAPS: u32 = tc_cap::TCP_CODEC
    | tc_cap::TLS13_CODEC
    | tc_cap::HORIZON_GATE
    | tc_cap::FLOW_IMPORT_ARM
    | tc_cap::EMISSION_DISABLE
    | tc_cap::RESET_SUPPRESSION;

/// A segment from the peer.
#[derive(Clone, Copy, Debug)]
pub struct TcSegIn<'a> {
    pub seq: u32,
    pub ack: u32,
    pub wnd: u32,
    pub fin: bool,
    pub payload: &'a [u8],
}

/// A segment for the wire, under the flow epoch it is emitted in.
#[derive(Clone, Copy, Debug)]
pub struct TcSegOut<'a> {
    pub seq: u32,
    pub ack: u32,
    pub wnd: u32,
    pub fin: bool,
    pub flow_epoch: u32,
    pub payload: &'a [u8],
}

/// What a production submission did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcProduced {
    /// Sealed and journaled; accepted once mirrored.
    Pending,
    /// Already in the output horizon (a retry): accepted.
    Duplicate,
    /// Not now (backpressure, barrier, quiesce, not emitting).
    NotReady,
}

// ── one flow ──────────────────────────────────────────────────────────────

/// Journal depth of the horizon gate: unacknowledged deltas per flow.
pub const TC_GATE_J: usize = 16;
/// Productions whose delta the standby has not acknowledged yet.
pub const TC_PROD_MAX: usize = 64;
/// Receive window advertised while open.
pub const TC_RCV_WND: u32 = 8192;
/// Largest payload one emitted segment carries.
pub const TC_SEG_MAX: u32 = 1000;
/// The floor under a retransmission timeout (ms).
pub const TC_RTO_MIN_MS: u32 = 200;
/// How long RETIRE's own tombstone suppresses resets (ms).
pub const TC_RETIRE_TOMBSTONE_MS: u64 = 5_000;

/// One flow slot.
pub struct TcFlow {
    pub live: bool,
    pub st: TsState,
    pub role: TcRole,
    pub handle: TcHandle,
    pub mode: TcMode,
    pub paired: bool,
    pub strict: bool,
    pub gate: MdGate<TC_GATE_J>,
    pub delta_seq: u64,
    pub last_digest: [u8; 32],
    pub checkpoint_id: u64,
    pub mirror_generation: u64,
    // standby
    pub asm: CkptAssembler,
    pub order: MdOrder,
    pub shadow_valid: bool,
    pub armed: bool,
    // data path
    pub emitting: bool,
    pub fenced: bool,
    pub quiescing: bool,
    pub retired: bool,
    pub tx_next: u32,
    pub last_ack_sent: u32,
    pub rto_at: u64,
    /// The highest delivery id handed to the worker.
    pub handed: u64,
    pub prod_seq: [(u64, u64); TC_PROD_MAX],
    pub prod_count: usize,
    pub epochs: TcEpochs,
    pub early: TcEarly,
    pub backpressure_events: u64,
    pub activated_at: u64,
}

impl TcFlow {
    pub const fn empty() -> Self {
        Self {
            live: false,
            st: TsState::zero(),
            role: TcRole::Standby,
            handle: TcHandle {
                slot: 0,
                generation: 0,
            },
            mode: TcMode::PlannedOnly,
            paired: false,
            strict: false,
            gate: MdGate {
                strict: false,
                journal: [MdEffect {
                    seq: 0,
                    rx_upto: 0,
                    tx_upto: 0,
                    deliver_upto: 0,
                    write_epoch: 0,
                }; TC_GATE_J],
                head: 0,
                count: 0,
                acked_seq: 0,
                last_seq: 0,
                limits: MdEffect {
                    seq: 0,
                    rx_upto: 0,
                    tx_upto: 0,
                    deliver_upto: 0,
                    write_epoch: 0,
                },
            },
            delta_seq: 0,
            last_digest: [0; 32],
            checkpoint_id: 0,
            mirror_generation: 0,
            asm: CkptAssembler::new([0; 16], 0),
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
            emitting: false,
            fenced: false,
            quiescing: false,
            retired: false,
            tx_next: 0,
            last_ack_sent: 0,
            rto_at: 0,
            handed: 0,
            prod_seq: [(0, 0); TC_PROD_MAX],
            prod_count: 0,
            epochs: TcEpochs::new(0),
            early: TcEarly::new(),
            backpressure_events: 0,
            activated_at: 0,
        }
    }

    /// (Re)open this slot for `st` in `role`.
    fn open(&mut self, st: &TsState, role: TcRole) {
        self.live = true;
        self.st = *st;
        self.role = role;
        self.handle = TcHandle::default();
        self.mode = TcMode::PlannedOnly;
        self.paired = false;
        self.strict = false;
        self.gate = MdGate::at_checkpoint(false, st);
        self.delta_seq = 0;
        self.last_digest = [0; 32];
        self.checkpoint_id = 0;
        self.mirror_generation = st.mirror_generation;
        self.asm.reset(st.flow_id, 0);
        self.order = MdOrder::after_checkpoint(st.flow_id, 0, 0, 0, [0; 32]);
        self.shadow_valid = false;
        self.armed = false;
        self.emitting = role == TcRole::Primary;
        self.fenced = false;
        self.quiescing = false;
        self.retired = false;
        self.tx_next = st.snd_una;
        self.last_ack_sent = 0;
        self.rto_at = 0;
        self.handed = st.delivery_acked;
        self.prod_count = 0;
        self.epochs = TcEpochs::new(st.write_epoch);
        self.early.count = 0;
        self.early.overflows = 0;
        self.backpressure_events = 0;
        self.activated_at = 0;
    }

    /// Takes segments: a live primary, or an activated standby.
    pub fn takes_segments(&self) -> bool {
        self.live && !self.retired && (self.role == TcRole::Primary || self.emitting)
    }

    /// An armed standby (holding early segments).
    pub fn is_armed(&self) -> bool {
        self.live && self.armed && !self.emitting
    }

    /// The highest production id accepted into the mirrored output horizon.
    pub fn accepted_through(&self) -> u64 {
        let all = self.st.next_production - 1;
        if !self.paired {
            return all;
        }
        let mut through = all;
        for (pid, seq) in &self.prod_seq[..self.prod_count] {
            if *seq > self.gate.acked_seq {
                through = through.min(pid - 1);
            }
        }
        through
    }
}

/// An event frame for the anchor.
fn tc_emit(ev: &mut dyn FnMut(&[u8]), op: u8, parts: &[&[u8]]) {
    let mut f = [0u8; TC_FRAME_MAX];
    if let Some(n) = tc_frame(&mut f, op, parts) {
        ev(&f[..n]);
    }
}

fn tc_status(
    ev: &mut dyn FnMut(&[u8]),
    op: u8,
    status: u8,
    reason: u8,
    handle: TcHandle,
    value: u64,
    flow_id: [u8; 16],
) {
    let mut b = [0u8; TC_STATUS_LEN];
    TcStatus {
        op,
        status,
        reason,
        handle,
        value,
        flow_id,
    }
    .encode(&mut b);
    tc_emit(ev, tc_evt::STATUS, &[&b]);
}

fn tc_evt_h(ev: &mut dyn FnMut(&[u8]), op: u8, h: TcHandle, body: &[u8]) {
    let mut hb = [0u8; TC_HANDLE_LEN];
    h.put(&mut hb);
    tc_emit(ev, op, &[&hb, body]);
}

/// HORIZON: the gate's acknowledged delta, both limits, its credit and
/// whether the window is closed.
fn tc_horizon(c: &TcFlow, ev: &mut dyn FnMut(&[u8])) {
    let mut hz = [0u8; 20];
    hz[0..8].copy_from_slice(&c.gate.acked_seq.to_le_bytes());
    hz[8..12].copy_from_slice(&c.gate.limits.rx_upto.to_le_bytes());
    hz[12..16].copy_from_slice(&c.gate.limits.tx_upto.to_le_bytes());
    hz[16..18].copy_from_slice(&(c.gate.credits() as u16).to_le_bytes());
    hz[18..20].copy_from_slice(&u16::from(c.gate.credits() == 0).to_le_bytes());
    tc_evt_h(ev, tc_evt::HORIZON, c.handle, &hz);
}

/// Counters the host reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcCounters {
    /// Operations refused (stale handle, rejected stream, unauthorized).
    pub rejected: u32,
    /// Local transitions the state refused.
    pub delta_refused: u64,
    /// Peer records that did not authenticate.
    pub open_failures: u64,
    /// Segments offered to `rx`.
    pub rx_calls: u64,
}

/// One host's provider: `F` flow slots and `T` tombstones. `new` is a
/// `const fn`, so a module holds it in its static state. It is large: per
/// slot a `TsState`, a checkpoint assembler and the early-segment buffer,
/// plus a scratch state, a shadow and one encoded record.
pub struct TcProvider<const F: usize, const T: usize> {
    pub anchor_id: [u8; 8],
    pub flows: [TcFlow; F],
    pub tombs: TcTombstones<T>,
    pub next_gen: u32,
    /// The custody generation EMISSION_DISABLE reports, advanced per cutoff.
    pub custody_gen: u32,
    /// The admitted congestion restart window (bytes).
    pub restart_window: u32,
    pub counters: TcCounters,
    /// The last local transition refused, and why.
    pub last_refusal: Option<(MdKind, CkptError)>,
    scratch: TsState,
    shadow: TsState,
    rec: [u8; TS_CKPT_MAX],
}

/// Apply one local transition to flow `c`: here, and — when paired —
/// journaled in the gate and emitted as the next delta. `false` is
/// backpressure or a refused transition (nothing changed).
fn tc_delta(
    c: &mut TcFlow,
    scratch: &mut TsState,
    counters: &mut TcCounters,
    last_refusal: &mut Option<(MdKind, CkptError)>,
    kind: MdKind,
    payload: &[u8],
    ev: &mut dyn FnMut(&[u8]),
) -> bool {
    if !c.paired {
        let r = md_apply(&mut c.st, scratch, kind, payload);
        if let Err(e) = r {
            counters.delta_refused += 1;
            *last_refusal = Some((kind, e));
        }
        return r.is_ok();
    }
    if c.gate.credits() == 0 {
        c.backpressure_events += 1;
        if c.backpressure_events == 1 || c.backpressure_events.is_multiple_of(16) {
            tc_horizon(c, ev);
        }
        return false;
    }
    // Encoded first: the header names the state before the transition, and
    // a transition that cannot be sent is not applied.
    let mut h = MdHdr {
        kind,
        flow_id: c.st.flow_id,
        flow_epoch: c.st.flow_epoch,
        mirror_generation: c.mirror_generation,
        base_checkpoint: c.checkpoint_id,
        seq: c.delta_seq + 1,
        prev: c.last_digest,
        payload_len: 0,
        digest: [0; 32],
    };
    let mut out = [0u8; MD_FRAME_MAX];
    let Some(n) = md_encode(&mut h, payload, &mut out) else {
        return false;
    };
    if let Err(e) = md_apply(&mut c.st, scratch, kind, payload) {
        counters.delta_refused += 1;
        *last_refusal = Some((kind, e));
        return false;
    }
    c.delta_seq += 1;
    c.last_digest = h.digest;
    let eff = MdEffect::of(c.delta_seq, &c.st);
    if c.gate.record(eff).is_err() {
        return false;
    }
    tc_evt_h(ev, tc_evt::DELTA, c.handle, &out[..n]);
    true
}

/// One segment of `c`'s send buffer, `[from, to)`, on the wire.
#[allow(
    clippy::too_many_arguments,
    reason = "a segment is its range, flags and the exposed ack/window/epoch; a struct would only rename them"
)]
fn tc_seg(
    c: &TcFlow,
    from: u32,
    to: u32,
    fin: bool,
    ack: u32,
    wnd: u32,
    flow_epoch: u32,
    emit: &mut dyn FnMut(&TcSegOut<'_>),
) {
    let off = from.wrapping_sub(c.st.snd_una) as usize;
    let len = to.wrapping_sub(from) as usize;
    emit(&TcSegOut {
        seq: from,
        ack,
        wnd,
        fin,
        flow_epoch,
        payload: &c.st.send[off..off + len],
    });
}

fn tc_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(0..8)?.try_into().ok()?))
}

fn tc_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

impl<const F: usize, const T: usize> TcProvider<F, T> {
    /// A provider for the anchor `anchor_id`, its custody generations
    /// counting up from `custody_base`.
    pub const fn new(anchor_id: [u8; 8], custody_base: u32, restart_window: u32) -> Self {
        Self {
            anchor_id,
            flows: [const { TcFlow::empty() }; F],
            tombs: TcTombstones::new(),
            next_gen: 1,
            custody_gen: custody_base,
            restart_window,
            counters: TcCounters {
                rejected: 0,
                delta_refused: 0,
                open_failures: 0,
                rx_calls: 0,
            },
            last_refusal: None,
            scratch: TsState::zero(),
            shadow: TsState::zero(),
            rec: [0; TS_CKPT_MAX],
        }
    }

    pub fn capabilities(&self) -> u32 {
        TC_PROVIDER_CAPS
    }

    fn slot_of(&self, flow: &[u8; 16]) -> Option<usize> {
        self.flows
            .iter()
            .position(|c| c.live && c.st.flow_id == *flow)
    }

    pub fn flow(&self, flow: &[u8; 16]) -> Option<&TcFlow> {
        self.slot_of(flow).map(|i| &self.flows[i])
    }

    pub fn flow_mut(&mut self, flow: &[u8; 16]) -> Option<&mut TcFlow> {
        self.slot_of(flow).map(move |i| &mut self.flows[i])
    }

    /// A connection the stack established (its handshake complete): the
    /// flow is a live, unpaired primary.
    pub fn establish(&mut self, st: &TsState) -> Result<(), CkptError> {
        ts_validate(st)?;
        let i = self
            .slot_of(&st.flow_id)
            .or_else(|| self.flows.iter().position(|c| !c.live))
            .ok_or(CkptError::Bounds)?;
        self.flows[i].open(st, TcRole::Primary);
        Ok(())
    }

    /// What the stack does with a segment for `flow`: take it, drop it
    /// silently (a migrated flow), or answer it with a reset.
    pub fn classify(&mut self, flow: &[u8; 16], now_ms: u64) -> TcDisposition {
        if self
            .flow(flow)
            .is_some_and(|c| c.takes_segments() || c.is_armed())
        {
            return TcDisposition::Deliver;
        }
        if self.tombs.is_tombstoned(flow, now_ms) {
            self.tombs.suppressed += 1;
            return TcDisposition::DropSilently;
        }
        TcDisposition::Reset
    }

    // ── anchor operations ────────────────────────────────────────────────

    /// Answer every operation frame in `raw`.
    pub fn ctl(
        &mut self,
        raw: &[u8],
        records: &mut dyn TcRecords,
        verifier: &dyn TcTokenVerifier,
        now_ms: u64,
        ev: &mut dyn FnMut(&[u8]),
    ) {
        let mut at = 0;
        while let Some((op, len)) = tc_frame_hdr(&raw[at..]) {
            let end = at + TC_FRAME_HDR + len;
            if end > raw.len() {
                break;
            }
            self.op(
                op,
                &raw[at + TC_FRAME_HDR..end],
                records,
                verifier,
                now_ms,
                ev,
            );
            at = end;
        }
    }

    fn op(
        &mut self,
        op: u8,
        p: &[u8],
        records: &mut dyn TcRecords,
        verifier: &dyn TcTokenVerifier,
        now_ms: u64,
        ev: &mut dyn FnMut(&[u8]),
    ) {
        let h = TcHandle::get(p).unwrap_or_default();
        let body = if p.len() >= TC_HANDLE_LEN {
            &p[TC_HANDLE_LEN..]
        } else {
            &[][..]
        };
        match op {
            tc_op::PAIR_PREPARE => return self.pair_prepare(body, ev),
            tc_op::TOMBSTONE => return self.tombstone(body, now_ms, ev),
            _ => {}
        }
        let slot = h.slot as usize;
        let Some(c) = slot
            .checked_sub(1)
            .and_then(|i| self.flows.get(i))
            .filter(|c| c.live)
        else {
            self.counters.rejected += 1;
            return tc_status(ev, op, tc_st::STALE_HANDLE, 0, h, 0, [0; 16]);
        };
        let flow = c.st.flow_id;
        if c.handle != h || h.is_null() {
            self.counters.rejected += 1;
            return tc_status(ev, op, tc_st::STALE_HANDLE, 0, h, 0, flow);
        }
        let i = slot - 1;
        // Each operation belongs to one side of the pair; an activated
        // standby is a primary, so nothing more reaches its shadow.
        let side = match op {
            tc_op::CHECKPOINT_BEGIN
            | tc_op::DELTA_ACK
            | tc_op::QUIESCE_BEGIN
            | tc_op::QUIESCE_STATUS
            | tc_op::CUT_EXPORT
            | tc_op::EMISSION_DISABLE => Some(TcRole::Primary),
            tc_op::CHECKPOINT_NEXT
            | tc_op::CHECKPOINT_COMMIT
            | tc_op::DELTA_APPLY
            | tc_op::CUT_IMPORT
            | tc_op::EMISSION_ARM
            | tc_op::ACTIVATE => Some(TcRole::Standby),
            _ => None,
        };
        if side.is_some_and(|r| r != c.role) {
            self.counters.rejected += 1;
            return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
        }
        let Self {
            flows,
            tombs,
            counters,
            scratch,
            shadow,
            rec,
            custody_gen,
            restart_window,
            anchor_id,
            ..
        } = self;
        let c = &mut flows[i];
        match op {
            tc_op::CHECKPOINT_BEGIN => {
                let Some(id) = tc_u64(body) else {
                    return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
                };
                c.checkpoint_id = id;
                c.st.mirror_generation = c.mirror_generation;
                let n = match ts_encode(&c.st, rec) {
                    Ok(n) => n,
                    Err(_) => return tc_status(ev, op, tc_st::UNSUPPORTED, 0, h, 0, flow),
                };
                let cid = CkptId {
                    checkpoint_id: id,
                    flow_id: flow,
                    flow_epoch: c.st.flow_epoch,
                    mirror_generation: c.mirror_generation,
                    total: n as u32,
                };
                let mut chain = ckpt_chain_seed(&cid);
                for k in 0..ckpt_chunk_count(n) {
                    let mut out = [0u8; CKPT_CHUNK_MAX];
                    if let Some(m) = ckpt_write_chunk(&cid, &rec[..n], k, &mut chain, &mut out) {
                        tc_evt_h(ev, tc_evt::CHUNK, h, &out[..m]);
                    }
                }
                c.delta_seq = 0;
                c.last_digest = chain;
                c.paired = true;
                c.strict = c.mode == TcMode::CrashContinuous;
                c.gate = MdGate::at_checkpoint(c.strict, &c.st);
                c.prod_count = 0;
                tc_status(ev, op, tc_st::OK, 0, h, id, flow);
            }
            tc_op::DELTA_ACK => {
                let Some(seq) = tc_u64(body) else {
                    return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
                };
                c.gate.ack(seq);
                // The KeyUpdate barrier: an epoch the standby acknowledged
                // is sealable.
                let we = c.gate.limits.write_epoch;
                c.epochs.installed(we);
                tc_horizon(c, ev);
            }
            tc_op::QUIESCE_BEGIN => {
                c.quiescing = true;
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            tc_op::QUIESCE_STATUS => {
                let q = c.gate.covered();
                tc_status(ev, op, tc_st::OK, 0, h, u64::from(q), flow);
            }
            tc_op::CUT_EXPORT => {
                let Some(digest) = tc_state_digest(&c.st, rec) else {
                    return tc_status(ev, op, tc_st::UNSUPPORTED, 0, h, 0, flow);
                };
                let cut = TcCut {
                    flow_id: flow,
                    flow_epoch: c.st.flow_epoch,
                    mirror_generation: c.mirror_generation,
                    last_seq: c.delta_seq,
                    state_digest: digest,
                };
                let mut b = [0u8; TC_CUT_LEN];
                cut.encode(&mut b);
                tc_evt_h(ev, tc_evt::CUT, h, &b);
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            tc_op::EMISSION_DISABLE => {
                c.emitting = false;
                c.fenced = true;
                *custody_gen += 1;
                let g = *custody_gen;
                tc_status(ev, op, tc_st::OK, 0, h, u64::from(g), flow);
            }
            tc_op::CHECKPOINT_NEXT => {
                if c.armed || c.asm.offer(body).is_err() {
                    c.shadow_valid = false;
                    counters.rejected += 1;
                    tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::CHUNK]);
                }
            }
            tc_op::CHECKPOINT_COMMIT => {
                let Some(id) = tc_u64(body) else {
                    return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
                };
                let chain = c.asm.verifier.chain;
                let vid = c.asm.verifier.id;
                // A checkpoint of this pairing only, into a shadow not yet
                // armed (the armed one is what activation emits from).
                let r = if !c.armed
                    && vid.checkpoint_id == id
                    && vid.mirror_generation == c.mirror_generation
                {
                    c.asm.publish(scratch, shadow)
                } else {
                    Err(CkptError::RangeMissing)
                };
                if r.is_err() {
                    counters.rejected += 1;
                    return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::COMMIT]);
                }
                // Every key the shadow names must resolve here.
                let ok = records.holds(&flow, TS_VAULT_READ, shadow.read_epoch)
                    && records.holds(&flow, TS_VAULT_WRITE, shadow.write_epoch);
                if !ok {
                    counters.rejected += 1;
                    return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::KEYS]);
                }
                c.st = *shadow;
                c.asm.verifier.seal();
                c.shadow_valid = true;
                c.checkpoint_id = id;
                c.order = MdOrder::after_checkpoint(
                    flow,
                    c.st.flow_epoch,
                    c.mirror_generation,
                    id,
                    chain,
                );
                let mut a = [0u8; 16];
                a[0..8].copy_from_slice(&id.to_le_bytes());
                tc_evt_h(ev, tc_evt::APPLIED, h, &a);
            }
            tc_op::DELTA_APPLY => {
                if !c.shadow_valid || c.armed {
                    counters.rejected += 1;
                    return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::NO_SHADOW]);
                }
                let Ok((hd, payload)) = md_parse(body) else {
                    counters.rejected += 1;
                    return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::MALFORMED]);
                };
                match c.order.verify(&hd) {
                    Ok(MdVerdict::Duplicate) => {
                        let mut a = [0u8; 16];
                        a[0..8].copy_from_slice(&c.checkpoint_id.to_le_bytes());
                        a[8..16].copy_from_slice(&c.order.applied().to_le_bytes());
                        tc_evt_h(ev, tc_evt::APPLIED, h, &a);
                    }
                    Ok(MdVerdict::Apply) => {
                        // KeyUpdate: this vault derives the new epoch from
                        // the secret it holds before the standby acks.
                        let mut derived = None;
                        if hd.kind == MdKind::KeyUpdate {
                            let e = tc_u32(payload, 1).unwrap_or(0);
                            let (purpose, cur) = if payload.first() == Some(&MD_DIR_IN) {
                                (TS_VAULT_READ, c.st.read_epoch)
                            } else {
                                (TS_VAULT_WRITE, c.st.write_epoch)
                            };
                            // Only the direction's next epoch is derived: a
                            // secret this vault already holds is never
                            // re-derived, nor destroyed below.
                            if Some(e) != cur.checked_add(1)
                                || records.derive_next(&flow, purpose, cur).is_none()
                            {
                                counters.rejected += 1;
                                return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::DERIVE]);
                            }
                            derived = Some((purpose, e));
                        }
                        if md_apply(&mut c.st, scratch, hd.kind, payload).is_err() {
                            // A secret derived for a transition that did not
                            // apply is not kept.
                            if let Some((purpose, e)) = derived {
                                records.destroy(&flow, purpose, e);
                            }
                            c.shadow_valid = false;
                            counters.rejected += 1;
                            return tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::TRANSITION]);
                        }
                        c.order.commit(&hd);
                        let mut a = [0u8; 16];
                        a[0..8].copy_from_slice(&c.checkpoint_id.to_le_bytes());
                        a[8..16].copy_from_slice(&hd.seq.to_le_bytes());
                        tc_evt_h(ev, tc_evt::APPLIED, h, &a);
                    }
                    Err(MdReject::Stale) => {}
                    Err(_) => {
                        c.shadow_valid = false;
                        counters.rejected += 1;
                        tc_evt_h(ev, tc_evt::REJECTED, h, &[tc_rej::ORDER]);
                    }
                }
            }
            tc_op::CUT_IMPORT => {
                let Some(cut) = TcCut::decode(body) else {
                    return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
                };
                let d = tc_state_digest(&c.st, rec);
                let ok = c.shadow_valid
                    && cut.flow_id == flow
                    && cut.last_seq == c.order.applied()
                    && d == Some(cut.state_digest);
                let st = if ok { tc_st::OK } else { tc_st::INVALID };
                tc_status(ev, op, st, 0, h, 0, flow);
            }
            tc_op::EMISSION_ARM => {
                if !c.shadow_valid {
                    return tc_status(ev, op, tc_st::NOT_READY, 0, h, 0, flow);
                }
                c.armed = true;
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            tc_op::ACTIVATE => {
                let (Some(new_epoch), Some(fence_gen), Some(cap)) = (
                    tc_u32(body, 0),
                    tc_u32(body, 4),
                    body.get(8..24).and_then(|b| <[u8; 16]>::try_from(b).ok()),
                ) else {
                    return tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow);
                };
                // Fail closed, cheapest first; then the authority's check
                // of the token it minted for THIS anchor.
                let refusal = if !c.armed {
                    Some(tc_act::NOT_ARMED)
                } else if fence_gen == 0 {
                    Some(tc_act::NO_FENCE)
                } else if new_epoch <= c.st.flow_epoch {
                    Some(tc_act::EPOCH_NOT_HIGHER)
                } else {
                    let mut t = [0u8; TC_FLOW_TOKEN_LEN];
                    TcFlowToken {
                        flow_id: flow,
                        epoch: new_epoch,
                        anchor: *anchor_id,
                        fence_gen,
                        capability: cap,
                    }
                    .encode(&mut t);
                    verifier.verify(&t).err()
                };
                if let Some(why) = refusal {
                    counters.rejected += 1;
                    return tc_status(ev, op, tc_st::UNAUTHORIZED, why, h, 0, flow);
                }
                c.st.flow_epoch = new_epoch;
                tc_restart(&mut c.st, *restart_window);
                c.rto_at = tc_rto_deadline(&c.st, now_ms);
                c.tx_next = c.st.snd_una;
                c.last_ack_sent = 0;
                c.handed = c.st.delivery_acked;
                c.emitting = true;
                c.role = TcRole::Primary;
                c.paired = false;
                c.strict = false;
                c.armed = false;
                c.activated_at = now_ms;
                c.epochs = TcEpochs::new(c.st.write_epoch);
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            tc_op::RETIRE => {
                let epoch = c.st.flow_epoch;
                c.retired = true;
                c.emitting = false;
                c.live = false;
                records.destroy_flow(&flow);
                // This host keeps no state for the flow now; a late segment
                // must not be answered with a reset.
                tombs.install(&flow, epoch, TC_RETIRE_TOMBSTONE_MS, now_ms);
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            tc_op::ABORT => {
                if c.role == TcRole::Standby {
                    c.live = false;
                } else {
                    // Unprotected from here: no horizon holds anything
                    // back, and a KeyUpdate waiting for the standby is
                    // this side's alone.
                    c.paired = false;
                    c.strict = false;
                    c.gate = MdGate::at_checkpoint(false, &c.st);
                    c.prod_count = 0;
                    if let Some(e) = c.epochs.pending {
                        c.epochs.installed(e);
                    }
                }
                tc_status(ev, op, tc_st::OK, 0, h, 0, flow);
            }
            _ => tc_status(ev, op, tc_st::INVALID, 0, h, 0, flow),
        }
    }

    fn pair_prepare(&mut self, body: &[u8], ev: &mut dyn FnMut(&[u8])) {
        let op = tc_op::PAIR_PREPARE;
        let Some(pair) = TcPair::decode(body) else {
            let flow = if body.len() >= 16 {
                tc_id16(body, 0)
            } else {
                [0; 16]
            };
            return tc_status(ev, op, tc_st::INVALID, 0, TcHandle::default(), 0, flow);
        };
        let flow = pair.flow_id;
        if pair.transport != TcTransport::TcpTls {
            return tc_status(ev, op, tc_st::UNSUPPORTED, 0, TcHandle::default(), 0, flow);
        }
        let i = match pair.role {
            TcRole::Primary => {
                let Some(i) = self.slot_of(&flow).filter(|&i| !self.flows[i].retired) else {
                    return tc_status(ev, op, tc_st::NOT_READY, 0, TcHandle::default(), 0, flow);
                };
                i
            }
            TcRole::Standby => {
                // A re-pair replaces whatever this host held for the flow.
                let free = self
                    .slot_of(&flow)
                    .or_else(|| self.flows.iter().position(|c| !c.live));
                let Some(i) = free else {
                    return tc_status(ev, op, tc_st::CAPACITY, 0, TcHandle::default(), 0, flow);
                };
                let mut st = TsState::established();
                st.flow_id = flow;
                self.flows[i].open(&st, TcRole::Standby);
                self.flows[i].emitting = false;
                i
            }
        };
        let handle = TcHandle {
            slot: i as u32 + 1,
            generation: self.next_gen,
        };
        self.next_gen += 1;
        let c = &mut self.flows[i];
        c.handle = handle;
        c.mode = pair.mode;
        c.mirror_generation = pair.mirror_generation;
        c.paired = false;
        c.strict = false;
        tc_status(ev, op, tc_st::OK, 0, handle, 0, flow);
    }

    fn tombstone(&mut self, body: &[u8], now_ms: u64, ev: &mut dyn FnMut(&[u8])) {
        let op = tc_op::TOMBSTONE;
        let null = TcHandle::default();
        if body.len() != 24 {
            return tc_status(ev, op, tc_st::INVALID, 0, null, 0, [0; 16]);
        }
        let flow = tc_id16(body, 0);
        let epoch = tc_le_u32(body, 16);
        let ttl = u64::from(tc_le_u32(body, 20));
        if self.tombs.install(&flow, epoch, ttl, now_ms) {
            tc_status(ev, op, tc_st::OK, 0, null, 1, flow);
        } else {
            tc_status(ev, op, tc_st::CAPACITY, 0, null, 0, flow);
        }
    }

    // ── the data path ────────────────────────────────────────────────────

    /// A segment from the peer for `flow`. A flow that is not here (or not
    /// yet active) takes nothing; an armed standby holds it for activation.
    pub fn rx(
        &mut self,
        flow: &[u8; 16],
        s: &TcSegIn<'_>,
        records: &mut dyn TcRecords,
        ev: &mut dyn FnMut(&[u8]),
    ) {
        self.counters.rx_calls += 1;
        let Some(i) = self.slot_of(flow) else {
            return;
        };
        let Self {
            flows,
            counters,
            last_refusal,
            scratch,
            ..
        } = self;
        let c = &mut flows[i];
        if c.armed && !c.emitting {
            c.early.push(s.seq, s.ack, s.fin, s.payload);
            return;
        }
        if c.retired || (c.role == TcRole::Standby && !c.emitting) {
            return;
        }
        let (una, end) = (c.st.snd_una, c.st.send_end());
        if ts_seq_lt(una, s.ack) && ts_seq_le(s.ack, end) {
            let mut p = [0u8; 8];
            if md_peer_ack(&mut p, s.ack, s.wnd).is_some() {
                tc_delta(c, scratch, counters, last_refusal, MdKind::PeerAck, &p, ev);
            }
            let mut out = [0u32; TC_EPOCHS];
            let n = c.epochs.release(c.st.snd_una, &mut out);
            for e in &out[..n] {
                records.destroy(flow, TS_VAULT_WRITE, *e);
            }
        }
        if !s.payload.is_empty() && !c.quiescing && !c.fenced {
            let rcv = c.st.rcv_nxt;
            let len = s.payload.len() as u32;
            let seg_end = s.seq.wrapping_add(len);
            let room = TS_RECV_MAX - usize::from(c.st.recv_len);
            let mut p = [0u8; MD_PAYLOAD_MAX];
            if ts_seq_le(s.seq, rcv) && ts_seq_lt(rcv, seg_end) {
                let from = rcv.wrapping_sub(s.seq) as usize;
                let part = &s.payload[from..];
                if part.len() <= room {
                    if let Some(n) = md_rx_segment(&mut p, rcv, part) {
                        tc_delta(
                            c,
                            scratch,
                            counters,
                            last_refusal,
                            MdKind::RxSegment,
                            &p[..n],
                            ev,
                        );
                    }
                }
            } else if ts_seq_lt(rcv, s.seq) && s.payload.len() <= TS_OOO_SEG {
                // Overlapping or out of room: dropped, the peer retransmits.
                if let Some(n) = md_rx_segment(&mut p, s.seq, s.payload) {
                    tc_delta(
                        c,
                        scratch,
                        counters,
                        last_refusal,
                        MdKind::RxSegment,
                        &p[..n],
                        ev,
                    );
                }
            }
        }
        if s.fin && !c.st.fin_rcvd && !c.quiescing && !c.fenced {
            let fin_at = s.seq.wrapping_add(s.payload.len() as u32);
            if fin_at == c.st.rcv_nxt && c.st.ooo_count == 0 {
                let mut p = [0u8; 1];
                if md_dir(&mut p, MD_DIR_IN).is_some() {
                    tc_delta(c, scratch, counters, last_refusal, MdKind::Fin, &p, ev);
                }
            }
        }
        // Open every complete record in the receive buffer.
        loop {
            let used = usize::from(c.st.recv_len);
            let Some(n) = records
                .record_len(&c.st.recv[..used])
                .filter(|&n| n > 0 && n <= used)
            else {
                return;
            };
            let (re, rs) = (c.st.read_epoch, c.st.read_seq);
            let mut rec = [0u8; TS_RECV_MAX];
            rec[..n].copy_from_slice(&c.st.recv[..n]);
            let mut pt = [0u8; TS_RECV_MAX];
            let Some((rtype, m)) = records.open(flow, re, rs, &rec[..n], &mut pt) else {
                counters.open_failures += 1;
                return;
            };
            let app = rtype == TC_RT_APP;
            let did = if app { c.st.next_delivery } else { 0 };
            let plain: &[u8] = if app { &pt[..m] } else { &[] };
            // A KeyUpdate's last byte is its request_update (RFC 8446 §4.6.3).
            let requested = rtype == TC_RT_KEY_UPDATE && m >= 1 && pt[m - 1] == 1;
            let mut p = [0u8; MD_PAYLOAD_MAX];
            let Some(k) = md_rx_record(&mut p, n as u16, re, rs, did, plain) else {
                return;
            };
            // A KeyUpdate is consumed only together with the rotation it
            // asks for: the next epoch's secret first, and room for both
            // deltas, or the record stays for a later pass.
            let derived = if rtype == TC_RT_KEY_UPDATE {
                if c.paired && c.gate.credits() < 2 {
                    return;
                }
                let Some(r) = records.derive_next(flow, TS_VAULT_READ, re) else {
                    return;
                };
                Some(r)
            } else {
                None
            };
            if !tc_delta(
                c,
                scratch,
                counters,
                last_refusal,
                MdKind::RxRecord,
                &p[..k],
                ev,
            ) {
                if derived.is_some() {
                    records.destroy(flow, TS_VAULT_READ, re + 1);
                }
                return;
            }
            if let Some(r) = derived {
                let mut q = [0u8; 54];
                let Some(k) = md_key_update(&mut q, MD_DIR_IN, re + 1, &r, &[0; 32], requested)
                else {
                    return;
                };
                if !tc_delta(
                    c,
                    scratch,
                    counters,
                    last_refusal,
                    MdKind::KeyUpdate,
                    &q[..k],
                    ev,
                ) {
                    return;
                }
            }
            if rtype == TC_RT_ALERT {
                let mut q = [0u8; 1];
                if md_dir(&mut q, MD_DIR_IN).is_some() {
                    tc_delta(
                        c,
                        scratch,
                        counters,
                        last_refusal,
                        MdKind::CloseNotify,
                        &q,
                        ev,
                    );
                }
            }
        }
    }

    /// Segments to put on the wire for `flow` now: retransmission from
    /// SND.UNA (byte-identical) when the RTO fired, new bytes up to the send
    /// horizon, the FIN once covered, and a pure ACK when the exposed ACK
    /// moved. Nothing at all unless the flow may emit.
    pub fn tx(&mut self, flow: &[u8; 16], now_ms: u64, emit: &mut dyn FnMut(&TcSegOut<'_>)) {
        let Some(i) = self.slot_of(flow) else {
            return;
        };
        let c = &mut self.flows[i];
        if !c.emitting {
            return;
        }
        let ack = if c.strict && ts_seq_lt(c.gate.limits.rx_upto, c.st.rcv_nxt) {
            c.gate.limits.rx_upto
        } else {
            c.st.rcv_nxt
        };
        let wnd = if c.quiescing || c.gate.credits() == 0 {
            0
        } else {
            TC_RCV_WND
        };
        let data_end = c.st.snd_una.wrapping_add(u32::from(c.st.send_len));
        let limit = if c.strict && ts_seq_lt(c.gate.limits.tx_upto, data_end) {
            c.gate.limits.tx_upto
        } else {
            data_end
        };
        let epoch = c.st.flow_epoch;
        let mut any = false;
        let rto = u64::from(c.st.rto_ms.max(TC_RTO_MIN_MS));
        if c.rto_at != 0 && now_ms >= c.rto_at && c.tx_next != c.st.snd_una {
            let mut at = c.st.snd_una;
            let to = c.tx_next.min(limit.max(c.st.snd_una));
            let to = if ts_seq_lt(data_end, to) {
                data_end
            } else {
                to
            };
            while ts_seq_lt(at, to) {
                let e = if to.wrapping_sub(at) > TC_SEG_MAX {
                    at.wrapping_add(TC_SEG_MAX)
                } else {
                    to
                };
                tc_seg(c, at, e, false, ack, wnd, epoch, emit);
                any = true;
                at = e;
            }
            c.rto_at = now_ms + rto;
        }
        if ts_seq_lt(c.tx_next, c.st.snd_una) {
            c.tx_next = c.st.snd_una;
        }
        while ts_seq_lt(c.tx_next, limit) {
            let e = if limit.wrapping_sub(c.tx_next) > TC_SEG_MAX {
                c.tx_next.wrapping_add(TC_SEG_MAX)
            } else {
                limit
            };
            tc_seg(c, c.tx_next, e, false, ack, wnd, epoch, emit);
            any = true;
            c.tx_next = e;
            if c.rto_at == 0 {
                c.rto_at = now_ms + rto;
            }
        }
        if c.st.fin_queued
            && c.tx_next == data_end
            && (!c.strict || ts_seq_le(c.st.send_end(), c.gate.limits.tx_upto))
        {
            tc_seg(c, data_end, data_end, true, ack, wnd, epoch, emit);
            any = true;
        }
        if c.st.snd_una == c.st.send_end() {
            c.rto_at = 0;
        }
        if !any && ack != c.last_ack_sent {
            tc_seg(c, c.tx_next, c.tx_next, false, ack, wnd, epoch, emit);
            any = true;
        }
        if any {
            c.last_ack_sent = ack;
        }
    }

    /// Deliveries the worker may be handed now, in id order.
    pub fn deliver(&mut self, flow: &[u8; 16], out: &mut dyn FnMut(u64, &[u8])) {
        let Some(i) = self.slot_of(flow) else {
            return;
        };
        let c = &mut self.flows[i];
        if !c.emitting || c.quiescing || c.fenced {
            return;
        }
        let mut handed = c.handed;
        for d in c.st.deliveries() {
            if d.id > c.handed && c.gate.may_deliver(d.id) {
                out(d.id, &d.bytes[..usize::from(d.len)]);
                handed = d.id;
            }
        }
        c.handed = handed;
    }

    /// The worker acknowledged deliveries through `cursor` — each whole,
    /// its plaintext ending at or before clear byte `cursor_at` — and
    /// stands at its own `consumer_cursor` (opaque here; 0 for none) at
    /// that byte (`net_proto::CMD_DELIVERED`).
    pub fn worker_ack(
        &mut self,
        flow: &[u8; 16],
        cursor: u64,
        consumer_cursor: u64,
        cursor_at: u64,
        ev: &mut dyn FnMut(&[u8]),
    ) {
        let Some(i) = self.slot_of(flow) else {
            return;
        };
        let Self {
            flows,
            counters,
            last_refusal,
            scratch,
            ..
        } = self;
        let c = &mut flows[i];
        let same = cursor == c.st.delivery_acked
            && consumer_cursor == c.st.consumer_cursor
            && cursor_at == c.st.cursor_at;
        if cursor < c.st.delivery_acked
            || cursor_at < c.st.cursor_at
            || same
            || cursor >= c.st.next_delivery
            || !c.emitting
        {
            return;
        }
        let mut p = [0u8; 24];
        if md_delivery_ack(&mut p, cursor, consumer_cursor, cursor_at).is_some() {
            tc_delta(
                c,
                scratch,
                counters,
                last_refusal,
                MdKind::DeliveryAck,
                &p,
                ev,
            );
        }
    }

    /// The worker offers production `pid`: sealed as one record under the
    /// current write epoch, only in order and only past the barrier.
    pub fn produce(
        &mut self,
        flow: &[u8; 16],
        pid: u64,
        pt: &[u8],
        records: &dyn TcRecords,
        ev: &mut dyn FnMut(&[u8]),
    ) -> TcProduced {
        let Some(i) = self.slot_of(flow) else {
            return TcProduced::NotReady;
        };
        let Self {
            flows,
            counters,
            last_refusal,
            scratch,
            ..
        } = self;
        let c = &mut flows[i];
        if !c.emitting || c.quiescing || c.fenced {
            return TcProduced::NotReady;
        }
        if pid < c.st.next_production {
            return TcProduced::Duplicate;
        }
        if pid > c.st.next_production {
            return TcProduced::NotReady;
        }
        let we = c.st.write_epoch;
        if !c.epochs.may_seal(we) || !c.gate.may_use_epoch(we) {
            return TcProduced::NotReady;
        }
        let mut rec = [0u8; MD_PAYLOAD_MAX];
        let Some(n) = records.seal(flow, we, c.st.write_seq, TC_RT_APP, pt, &mut rec) else {
            return TcProduced::NotReady;
        };
        let mut p = [0u8; MD_PAYLOAD_MAX];
        // The consumer's clear bytes through this record: its output horizon.
        let out_bytes = c.st.out_bytes.wrapping_add(pt.len() as u64);
        let Some(m) = md_tx_record(&mut p, pid, we, c.st.write_seq, &rec[..n], out_bytes) else {
            return TcProduced::NotReady;
        };
        if c.paired {
            // Only productions the standby has not acknowledged are kept.
            let acked = c.gate.acked_seq;
            let mut k = 0;
            for j in 0..c.prod_count {
                if c.prod_seq[j].1 > acked {
                    c.prod_seq[k] = c.prod_seq[j];
                    k += 1;
                }
            }
            c.prod_count = k;
            if c.prod_count == TC_PROD_MAX {
                return TcProduced::NotReady;
            }
        }
        if !tc_delta(
            c,
            scratch,
            counters,
            last_refusal,
            MdKind::TxRecord,
            &p[..m],
            ev,
        ) {
            return TcProduced::NotReady;
        }
        if c.paired {
            c.prod_seq[c.prod_count] = (pid, c.delta_seq);
            c.prod_count += 1;
        }
        TcProduced::Pending
    }

    /// The highest production id accepted into the mirrored output horizon.
    pub fn accepted_through(&self, flow: &[u8; 16]) -> u64 {
        self.flow(flow).map_or(0, |c| c.accepted_through())
    }

    /// A server-initiated KeyUpdate: the record under the old epoch, then
    /// the new epoch's state; sealing under it waits for the standby.
    pub fn key_update(
        &mut self,
        flow: &[u8; 16],
        records: &mut dyn TcRecords,
        ev: &mut dyn FnMut(&[u8]),
    ) -> bool {
        let Some(i) = self.slot_of(flow) else {
            return false;
        };
        let Self {
            flows,
            counters,
            last_refusal,
            scratch,
            ..
        } = self;
        let c = &mut flows[i];
        if !c.emitting || c.quiescing || c.fenced {
            return false;
        }
        let (we, ws) = (c.st.write_epoch, c.st.write_seq);
        // Everything that could refuse comes before the KeyUpdate record is
        // sealed: once it is in the send buffer the peer rotates, so this
        // side must rotate with it — the barrier, a retiring slot, room for
        // both deltas and the next epoch's secret.
        if !c.epochs.may_seal(we)
            || c.epochs.pending.is_some()
            || c.epochs.retiring.iter().all(|r| r.live)
            || (c.paired && c.gate.credits() < 2)
        {
            return false;
        }
        let Some(r) = records.derive_next(flow, TS_VAULT_WRITE, we) else {
            return false;
        };
        let mut rec = [0u8; MD_PAYLOAD_MAX];
        let mut p = [0u8; MD_PAYLOAD_MAX];
        let framed = records
            .seal(flow, we, ws, TC_RT_KEY_UPDATE, &[0], &mut rec)
            .and_then(|n| {
                Some((
                    n,
                    md_tx_record(&mut p, 0, we, ws, &rec[..n], c.st.out_bytes)?,
                ))
            });
        let last_end_before = c.st.send_end();
        let sent = match framed {
            Some((n, m)) => tc_delta(
                c,
                scratch,
                counters,
                last_refusal,
                MdKind::TxRecord,
                &p[..m],
                ev,
            )
            .then_some(n),
            None => None,
        };
        let Some(n) = sent else {
            records.destroy(flow, TS_VAULT_WRITE, we + 1);
            return false;
        };
        let mut k = [0u8; 53];
        let Some(m) = md_key_update(&mut k, MD_DIR_OUT, we + 1, &r, &[0; 32], false) else {
            return false;
        };
        let end = last_end_before.wrapping_add(n as u32);
        if c.epochs.request(end).is_err() {
            return false;
        }
        if !c.paired {
            c.epochs.installed(we + 1);
        }
        tc_delta(
            c,
            scratch,
            counters,
            last_refusal,
            MdKind::KeyUpdate,
            &k[..m],
            ev,
        )
    }

    /// Replay what an armed standby held early, once it is active.
    pub fn replay_early(
        &mut self,
        flow: &[u8; 16],
        records: &mut dyn TcRecords,
        ev: &mut dyn FnMut(&[u8]),
    ) {
        let Some(i) = self.slot_of(flow) else {
            return;
        };
        if !self.flows[i].emitting || self.flows[i].early.count == 0 {
            return;
        }
        let count = self.flows[i].early.count;
        self.flows[i].early.count = 0;
        for k in 0..count {
            let len = usize::from(self.flows[i].early.lens[k]);
            let mut b = [0u8; TC_EARLY_BYTES];
            b[..len].copy_from_slice(&self.flows[i].early.bytes[k][..len]);
            let s = TcSegIn {
                seq: tc_le_u32(&b, 0),
                ack: tc_le_u32(&b, 4),
                wnd: TC_RCV_WND,
                fin: b[8] != 0,
                payload: &b[9..len],
            };
            self.rx(flow, &s, records, ev);
        }
    }
}
