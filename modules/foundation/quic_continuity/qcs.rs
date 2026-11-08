// qcs — TRANSPORT_CONTINUITY over this graph's `quic` (`TcTransport::Quic`):
// the anchor's operations become the per-layer continuity commands `quic`
// answers on `cont_in` / `cont_out` (`session_ctrl.rs` §Transport
// continuity, `CT_QUIC`), and the canonical record is `WHQ1` — the anchor's
// view, then `quic`'s own record (`QKRC`) whole (transport_continuity.rs,
// the QUIC section).
//
// Primary: PAIR_PREPARE pairs the connection `quic` names by
// `tc_flow_id_quic` (it binds an established connection by its ID);
// CHECKPOINT_BEGIN is `quic`'s CUT_EXPORT, its record assembled from the
// per-layer chunk stream, checked (SHA-256 and CRC32), viewed and sent as
// `WHCC` chunks; a crash-continuous pair then tells `quic` its checkpoint
// is held, which turns its mirror on, and every per-layer delta becomes the
// next `QuicDelta` on this stream, numbered as `quic` numbers it (a delta
// this stream cannot carry, or out of number, ends the pairing: STATUS of
// op ABORT, unsolicited, reason `0x80 | qcs_lost`); DELTA_ACK is `quic`'s, so its strict
// horizons (a packet withheld until the standby holds it, an ACK not shown
// before) wait on the anchor's standby; CUT_EXPORT names the record's
// digest and the stream's last chain digest; EMISSION_DISABLE and RETIRE
// are `quic`'s RETIRE.
//
// Standby: the chunks assemble and verify (`CkptAssembler`), the record
// parses and its view must match the record it carries, and `quic` imports
// it as its own per-layer checkpoint stream; each `QuicDelta` is checked in
// order and applied by `quic` (its own chain re-made from the data); a cut
// is checked against the record and the stream before `quic`'s CUT_IMPORT;
// EMISSION_ARM imports first when no cut came (a crash); ACTIVATE is
// refused unarmed, with a zero fence or an epoch not strictly higher, and
// otherwise goes to `quic` only on the authority's verdict on the per-flow
// token this provider rebuilds for its own anchor. `quic` then validates
// the client's path before it trusts it.

/// The flows one instance moves at once: a table as long as its `flows`
/// param, taken from the module's heap at instantiation (`[capacities]
/// heap_per_param`). Zeroed memory is the empty table; a pairing past it is
/// refused `CAPACITY`.
pub type QcsFlows = HeapTable<QcsFlow>;
/// A whole `WHQ1` record.
pub const QCS_REC_MAX: usize = TC_QUIC_HDR + TC_QUIC_LAYER_MAX;
/// Why a crash-continuous pairing ended here (STATUS of op ABORT,
/// unsolicited, reason `0x80 | …`; `quic`'s own end is `0x80 | its
/// status`).
pub mod qcs_lost {
    /// A per-layer delta out of number.
    pub const GAP: u8 = 0x41;
    /// A per-layer delta past what one delta carries.
    pub const UNREPRESENTABLE: u8 = 0x42;
    /// The anchor's event queue is full.
    pub const FULL: u8 = 0x43;
}
/// How long a per-layer reply is waited for (ms).
pub const QCS_LAYER_MS: u64 = 2000;
/// Deltas `quic` holds unanswered at a standby.
const QCS_INFLIGHT: usize = 32;

/// The authority's token check (as `transport_continuity`'s).
pub const QCS_MSG_TOKEN_CHECK: u8 = 0xC2;
pub const QCS_MSG_TOKEN_VERDICT: u8 = 0xC3;
/// The authority's custody check: `[flow 16][epoch u32][challenge 32]
/// [evidence]`, verdict `[flow 16][sha256(evidence) 32][verdict u8]`.
pub const QCS_MSG_CUSTODY_CHECK: u8 = 0xC4;
pub const QCS_MSG_CUSTODY_VERDICT: u8 = 0xC5;

/// Where a frame goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QcsPort {
    Evt,
    Quic,
    Auth,
}

pub trait QcsOut {
    fn send(&mut self, port: QcsPort, frame: &[u8]) -> bool;
}

/// The exchange a flow is waiting on. `Idle` is the all-zero value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum QcsStep {
    Idle,
    Prepare,
    Export,
    Import,
    Quiesce,
    CutImport,
    ArmImport,
    Arm,
    Token,
    Activate,
    Retire,
    CustodyAttest,
    CustodyAuth,
    CustodyWrap,
    CustodyUnwrap,
}

#[derive(PartialEq)]
pub struct QcsFlow {
    pub live: bool,
    pub role: TcRole,
    pub mode: TcMode,
    pub handle: TcHandle,
    pub flow: [u8; 16],
    pub epoch: u32,
    pub mirror_gen: u64,
    pub service: [u8; 16],
    pub step: QcsStep,
    pub op: u8,
    pub deadline: u64,
    pub ckpt_id: u64,
    // the provider record, as `quic` exported it or will import it
    pub layer: [u8; TC_QUIC_LAYER_MAX],
    pub layer_len: usize,
    pub layer_got: usize,
    pub layer_gen: u32,
    pub layer_digest: [u8; 32],
    pub layer_crc: u32,
    pub rec_digest: [u8; 32],
    // the stream
    pub chain: [u8; 32],
    pub delta_seq: u64,
    pub mirroring: bool,
    // standby
    pub asm: CkptAssembler<QCS_REC_MAX>,
    pub order: MdOrder,
    pub layer_prev: [u8; 32],
    pub inflight: [u64; QCS_INFLIGHT],
    pub inflight_n: usize,
    pub shadow: bool,
    pub imported: bool,
    pub armed: bool,
    pub new_epoch: u32,
    pub fence_gen: u32,
    pub token: [u8; TC_FLOW_TOKEN_LEN],
    pub custody_challenge: [u8; 32],
    pub custody_ev: [u8; tc_custody::EVIDENCE_MAX],
    pub custody_ev_len: usize,
}

impl QcsFlow {
    /// An unpaired slot. All-zero memory is this value, so a provider's
    /// state is initialised by zeroing it.
    pub const fn empty() -> Self {
        Self {
            live: false,
            role: TcRole::Standby,
            mode: TcMode::PlannedOnly,
            handle: TcHandle {
                slot: 0,
                generation: 0,
            },
            flow: [0; 16],
            epoch: 0,
            mirror_gen: 0,
            service: [0; 16],
            step: QcsStep::Idle,
            op: 0,
            deadline: 0,
            ckpt_id: 0,
            layer: [0; TC_QUIC_LAYER_MAX],
            layer_len: 0,
            layer_got: 0,
            layer_gen: 0,
            layer_digest: [0; 32],
            layer_crc: 0,
            rec_digest: [0; 32],
            chain: [0; 32],
            delta_seq: 0,
            mirroring: false,
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
            layer_prev: [0; 32],
            inflight: [0; QCS_INFLIGHT],
            inflight_n: 0,
            shadow: false,
            imported: false,
            armed: false,
            new_epoch: 0,
            fence_gen: 0,
            token: [0; TC_FLOW_TOKEN_LEN],
            custody_challenge: [0; 32],
            custody_ev: [0; tc_custody::EVIDENCE_MAX],
            custody_ev_len: 0,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct QcsCounters {
    pub rejected: u32,
    pub timeouts: u32,
    pub deltas_out: u64,
    pub deltas_in: u64,
}

#[derive(PartialEq)]
pub struct QcStack {
    pub anchor_id: [u8; 8],
    pub flows: QcsFlows,
    /// The generation of the handle last issued (0 before the first).
    pub last_gen: u32,
    pub custody_gen: u32,
    pub counters: QcsCounters,
    rec: [u8; QCS_REC_MAX],
}

fn qle32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn qle64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// One `[type][len][payload]` frame from parts, sent on `port`.
fn qcs_frame<O: QcsOut>(out: &mut O, port: QcsPort, t: u8, parts: &[&[u8]]) -> bool {
    let mut f = [0u8; TC_FRAME_MAX];
    match tc_frame(&mut f, t, parts) {
        Some(n) => out.send(port, &f[..n]),
        None => false,
    }
}

fn qcs_status<O: QcsOut>(
    out: &mut O,
    op: u8,
    status: u8,
    reason: u8,
    h: TcHandle,
    value: u64,
    flow: [u8; 16],
) {
    let mut b = [0u8; TC_STATUS_LEN];
    TcStatus {
        op,
        status,
        reason,
        handle: h,
        value,
        flow_id: flow,
    }
    .encode(&mut b);
    let _ = qcs_frame(out, QcsPort::Evt, tc_evt::STATUS, &[&b]);
}

fn qcs_evt_h<O: QcsOut>(out: &mut O, evt: u8, h: TcHandle, body: &[u8]) -> bool {
    let mut hb = [0u8; TC_HANDLE_LEN];
    h.put(&mut hb);
    qcs_frame(out, QcsPort::Evt, evt, &[&hb, body])
}

/// A per-layer command to `quic`: `[flow][epoch]` then `rest`, built in
/// place (no table of slices: a PIC module holds no relocated constants).
fn qcs_layer<O: QcsOut>(out: &mut O, t: u8, flow: &[u8; 16], epoch: u32, rest: &[&[u8]]) -> bool {
    let mut f = [0u8; TC_FRAME_MAX];
    let mut at = TC_FRAME_HDR;
    f[at..at + 16].copy_from_slice(flow);
    at += 16;
    f[at..at + 4].copy_from_slice(&epoch.to_le_bytes());
    at += 4;
    for r in rest {
        if at + r.len() > f.len() {
            return false;
        }
        f[at..at + r.len()].copy_from_slice(r);
        at += r.len();
    }
    let len = at - TC_FRAME_HDR;
    if len > usize::from(u16::MAX) {
        return false;
    }
    f[0] = t;
    f[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    out.send(port_quic(), &f[..at])
}

fn port_quic() -> QcsPort {
    QcsPort::Quic
}

/// The anchor's view of a `QKRC` record, read along `quic`'s own layout
/// (`quic/continuity.rs`): magic, flow, epoch, flags, then our, the peer's
/// and the original destination CID (each `[len][len bytes]`), the peer's
/// sixteen-byte address and port, the CID sequences and spares, stream
/// numbering, the negotiated idle timeout and its remainder, eleven
/// transport parameters and flow limits, then the 1-RTT reservation high-water and
/// largest received number, key-update progress, the unacknowledged CRYPTO,
/// the ACK ranges, the other spaces' counters, flow control and congestion,
/// and the key phase. `None` when the record ends before it.
pub fn qcs_view(layer: &[u8]) -> Option<TcQuicView> {
    let mut r = TcR::new(layer);
    if r.take(4)? != b"QKRC" {
        return None;
    }
    r.take(16 + 4 + 1)?;
    let mut v = TcQuicView::default();
    (v.our_cid_len, v.our_cid) = qcs_cid(&mut r)?;
    (v.peer_cid_len, v.peer_cid) = qcs_cid(&mut r)?;
    qcs_cid(&mut r)?;
    v.peer_ip = r.arr()?;
    v.peer_port = r.u16()?;
    v.family = if v.peer_ip[..10] == [0; 10] && v.peer_ip[10..12] == [0xFF, 0xFF] {
        4
    } else {
        6
    };
    // our_cid_seq, next_cid_seq; the spare we issued, its sequence and
    // reset token, the issue flags; the peer's CID sequence, its spare,
    // that one's sequence and token, the peer DCID sequence; retirements.
    r.take(16)?;
    qcs_cid(&mut r)?;
    r.take(8 + 16 + 1 + 8)?;
    qcs_cid(&mut r)?;
    r.take(8 + 16 + 8)?;
    let retire = usize::from(r.u8()?);
    r.take(8 * retire)?;
    // Stream numbering (six u64 and the handle counter), the idle timeout
    // and its remainder, eleven transport parameters and flow limits.
    r.take(6 * 8 + 4 + 2 * 8 + 11 * 8)?;
    v.next_send_pn = r.u64()?;
    v.largest_recv_pn = r.u64()?;
    // Key-update progress; the 1-RTT CRYPTO still unacknowledged.
    r.take(1 + 8 + 4 + 8 + 8)?;
    let crypto = usize::from(r.u16()?);
    r.take(crypto + 8)?;
    let ranges = usize::from(r.u8()?);
    // The ACK ranges; Initial/Handshake counters, flow control, congestion.
    r.take(16 * ranges + 2 * 8 + 3 * 8 + 3 * 8)?;
    v.key_phase = r.u8()?;
    Some(v)
}

/// One `[len][len bytes]` CID of a `QKRC` record, zero-padded.
fn qcs_cid(r: &mut TcR<'_>) -> Option<(u8, [u8; TC_QUIC_CID_MAX])> {
    let n = r.u8()?;
    if usize::from(n) > TC_QUIC_CID_MAX {
        return None;
    }
    let mut a = [0u8; TC_QUIC_CID_MAX];
    a[..usize::from(n)].copy_from_slice(r.take(usize::from(n))?);
    Some((n, a))
}

/// The view a record's header names agrees with the record it carries.
fn qcs_view_matches(v: &TcQuicView, own: &TcQuicView) -> bool {
    v.our_cid_len == own.our_cid_len
        && v.our_cid == own.our_cid
        && v.peer_cid_len == own.peer_cid_len
        && v.peer_cid == own.peer_cid
        && v.peer_ip == own.peer_ip
        && v.peer_port == own.peer_port
        && v.family == own.family
        && v.key_phase == own.key_phase
        && v.next_send_pn == own.next_send_pn
        && v.largest_recv_pn == own.largest_recv_pn
}

impl Default for QcStack {
    fn default() -> Self {
        Self::new([0; 8])
    }
}

impl QcStack {
    /// All-zero but for `anchor_id`: zeroed memory with the anchor written
    /// is this value.
    pub const fn new(anchor_id: [u8; 8]) -> Self {
        Self {
            anchor_id,
            flows: QcsFlows::EMPTY,
            last_gen: 0,
            custody_gen: 0,
            counters: QcsCounters {
                rejected: 0,
                timeouts: 0,
                deltas_out: 0,
                deltas_in: 0,
            },
            rec: [0; QCS_REC_MAX],
        }
    }

    fn by_handle(&self, h: TcHandle) -> Option<usize> {
        let i = (h.slot as usize).checked_sub(1)?;
        (i < self.flows.len() && self.flows[i].live && self.flows[i].handle == h).then_some(i)
    }

    fn by_flow(&self, flow: &[u8]) -> Option<usize> {
        self.flows
            .iter()
            .position(|c| c.live && c.flow[..] == *flow)
    }

    fn begin(&mut self, i: usize, op: u8, step: QcsStep, now: u64) {
        let c = &mut self.flows[i];
        c.op = op;
        c.step = step;
        c.deadline = now + QCS_LAYER_MS;
    }

    fn done<O: QcsOut>(&mut self, i: usize, status: u8, reason: u8, value: u64, out: &mut O) {
        let c = &mut self.flows[i];
        let (op, h, flow) = (c.op, c.handle, c.flow);
        c.step = QcsStep::Idle;
        qcs_status(out, op, status, reason, h, value, flow);
    }

    /// The deadlines of per-layer replies.
    pub fn tick<O: QcsOut>(&mut self, now: u64, out: &mut O) {
        for i in 0..self.flows.len() {
            let c = &self.flows[i];
            if c.live && c.step != QcsStep::Idle && c.step != QcsStep::Token && now > c.deadline {
                self.counters.timeouts += 1;
                self.done(i, tc_st::NOT_READY, 0, 0, out);
            }
        }
    }

    // ── the anchor's operations ──────────────────────────────────────────

    pub fn ctl<O: QcsOut>(&mut self, frame: &[u8], now: u64, out: &mut O) {
        let Some((op, len)) = tc_frame_hdr(frame) else {
            return;
        };
        let p = &frame[TC_FRAME_HDR..];
        if p.len() != len || p.len() < TC_HANDLE_LEN {
            return;
        }
        let Some(h) = TcHandle::get(&p[..TC_HANDLE_LEN]) else {
            return;
        };
        let body = &p[TC_HANDLE_LEN..];
        // A frame that is not an operation (an authority's verdict sharing
        // the anchor's pipe) is not this port's.
        if op >= 0x80 {
            return;
        }
        if op == tc_op::PAIR_PREPARE {
            return self.pair_prepare(body, now, out);
        }
        // A reservation granted before the flow is paired: the null handle,
        // the grant naming its flow (`[op][status][flow 16]…`). A crash pair
        // needs it first — `quic` refuses crash continuity on a connection
        // whose packet numbers only it grants itself.
        if op == tc_op::RESERVATION_GRANT && h.is_null() {
            if body.len() != sc::GRANT_LEN {
                return qcs_status(out, op, tc_st::INVALID, 0, h, 0, [0; 16]);
            }
            let mut flow = [0u8; 16];
            flow.copy_from_slice(&body[2..18]);
            let ok = qcs_frame(
                out,
                QcsPort::Quic,
                sc::CMD_SC_RESERVATION_GRANT,
                &[&flow, body],
            );
            let st = if ok { tc_st::OK } else { tc_st::NOT_READY };
            return qcs_status(out, op, st, 0, h, 0, flow);
        }
        let Some(i) = self.by_handle(h) else {
            self.counters.rejected += 1;
            let flow = self
                .flows
                .iter()
                .find(|c| c.live && c.handle.slot == h.slot)
                .map_or([0; 16], |c| c.flow);
            return qcs_status(out, op, tc_st::STALE_HANDLE, 0, h, 0, flow);
        };
        let busy = self.flows[i].step != QcsStep::Idle;
        let (flow, epoch) = (self.flows[i].flow, self.flows[i].epoch);
        let role = self.flows[i].role;
        match op {
            tc_op::CHECKPOINT_NEXT if role == TcRole::Standby => {
                let c = &mut self.flows[i];
                if c.armed || c.imported || c.asm.offer(body).is_err() {
                    self.counters.rejected += 1;
                    let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::CHUNK]);
                }
            }
            tc_op::DELTA_APPLY if role == TcRole::Standby => self.delta_apply(i, body, out),
            // The anchor's acknowledgement of delta `seq` is `quic`'s of its
            // delta `seq`: only for a delta this stream emitted, so no
            // horizon is released for one the standby never received.
            tc_op::DELTA_ACK
                if body.len() == 8
                    && role == TcRole::Primary
                    && self.flows[i].mirroring
                    && (1..=self.flows[i].delta_seq).contains(&qle64(body, 0)) =>
            {
                let seq = qle64(body, 0);
                let c = &self.flows[i];
                let gen = c.layer_gen.to_le_bytes();
                let no = (seq.min(u64::from(u32::MAX)) as u32).to_le_bytes();
                let _ = qcs_layer(out, sc::CMD_SC_DELTA_ACK, &flow, epoch, &[&gen, &no]);
                let mut hz = [0u8; 20];
                hz[0..8].copy_from_slice(&seq.to_le_bytes());
                let _ = qcs_evt_h(out, tc_evt::HORIZON, h, &hz);
            }
            tc_op::CUT_EXPORT if role == TcRole::Primary => {
                let c = &self.flows[i];
                let cut = TcCut {
                    flow_id: flow,
                    flow_epoch: epoch,
                    mirror_generation: c.mirror_gen,
                    last_seq: c.delta_seq,
                    state_digest: tc_quic_state_digest(&c.rec_digest, &c.chain),
                };
                let mut b = [0u8; TC_CUT_LEN];
                cut.encode(&mut b);
                let _ = qcs_evt_h(out, tc_evt::CUT, h, &b);
                qcs_status(out, op, tc_st::OK, 0, h, 0, flow);
            }
            _ if busy => qcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow),
            tc_op::CHECKPOINT_BEGIN if body.len() == 8 && self.flows[i].role == TcRole::Primary => {
                let c = &mut self.flows[i];
                c.ckpt_id = qle64(body, 0);
                c.layer_len = 0;
                c.layer_got = 0;
                self.begin(i, op, QcsStep::Export, now);
                let _ = qcs_layer(out, sc::CMD_SC_CUT_EXPORT, &flow, epoch, &[]);
            }
            tc_op::CHECKPOINT_COMMIT
                if body.len() == 8 && self.flows[i].role == TcRole::Standby =>
            {
                self.commit(i, qle64(body, 0), now, out);
            }
            tc_op::QUIESCE_BEGIN | tc_op::QUIESCE_STATUS => {
                self.begin(i, op, QcsStep::Quiesce, now);
                let t = if op == tc_op::QUIESCE_BEGIN {
                    sc::CMD_SC_QUIESCE_BEGIN
                } else {
                    sc::CMD_SC_QUIESCE_STATUS
                };
                let _ = qcs_layer(
                    out,
                    t,
                    &flow,
                    epoch,
                    &[&(QCS_LAYER_MS as u32).to_le_bytes()],
                );
            }
            tc_op::CUT_IMPORT => {
                let Some(cut) = TcCut::decode(body) else {
                    return qcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                };
                let c = &self.flows[i];
                let ok = c.shadow
                    && cut.flow_id == flow
                    && cut.flow_epoch == epoch
                    && cut.mirror_generation == c.mirror_gen
                    && cut.last_seq == c.order.applied()
                    && cut.state_digest
                        == tc_quic_state_digest(&c.rec_digest, &c.order.last_digest);
                if !ok {
                    self.counters.rejected += 1;
                    return qcs_status(out, op, tc_st::INVALID, 0, h, 0, flow);
                }
                self.begin(i, op, QcsStep::CutImport, now);
                self.layer_cut_import(i, out);
            }
            tc_op::EMISSION_ARM => {
                if !self.flows[i].shadow {
                    return qcs_status(out, op, tc_st::NOT_READY, 0, h, 0, flow);
                }
                if self.flows[i].imported {
                    self.begin(i, op, QcsStep::Arm, now);
                    let _ = qcs_layer(out, sc::CMD_SC_EMISSION_ARM, &flow, epoch, &[]);
                } else {
                    // No cut came (a crash): the shadow as the stream left it.
                    self.begin(i, op, QcsStep::ArmImport, now);
                    self.layer_cut_import(i, out);
                }
            }
            tc_op::ACTIVATE if body.len() == 4 + 4 + 16 => {
                let (ne, fg) = (qle32(body, 0), qle32(body, 4));
                let c = &self.flows[i];
                let why = if !c.armed {
                    Some(tc_act::NOT_ARMED)
                } else if fg == 0 {
                    Some(tc_act::NO_FENCE)
                } else if ne <= epoch {
                    Some(tc_act::EPOCH_NOT_HIGHER)
                } else {
                    None
                };
                if let Some(why) = why {
                    self.counters.rejected += 1;
                    return qcs_status(out, op, tc_st::UNAUTHORIZED, why, h, 0, flow);
                }
                let mut cap = [0u8; 16];
                cap.copy_from_slice(&body[8..24]);
                let mut t = [0u8; TC_FLOW_TOKEN_LEN];
                TcFlowToken {
                    flow_id: flow,
                    epoch: ne,
                    anchor: self.anchor_id,
                    fence_gen: fg,
                    capability: cap,
                }
                .encode(&mut t);
                self.begin(i, op, QcsStep::Token, now);
                let c = &mut self.flows[i];
                c.new_epoch = ne;
                c.fence_gen = fg;
                c.token = t;
                if !qcs_frame(out, QcsPort::Auth, QCS_MSG_TOKEN_CHECK, &[&t]) {
                    self.done(i, tc_st::UNAUTHORIZED, 0, 0, out);
                }
            }
            tc_op::EMISSION_DISABLE | tc_op::RETIRE => {
                self.begin(i, op, QcsStep::Retire, now);
                let _ = qcs_layer(out, sc::CMD_SC_RETIRE, &flow, epoch, &[]);
            }
            tc_op::ABORT => {
                let reason = [0u8; 1];
                let _ = qcs_layer(out, sc::CMD_SC_ABORT, &flow, epoch, &[&reason]);
                let c = &mut self.flows[i];
                c.live = false;
                qcs_status(out, op, tc_st::OK, 0, h, 0, flow);
            }
            // Vault-to-vault custody of the flow's continuity key, as for
            // `tls` (`quic/custody.rs`): the standby attests a recipient,
            // the primary's vault wraps the key to it on the authority's
            // verdict, the standby's unwraps it.
            tc_op::CUSTODY_ATTEST if body.len() == 32 && self.flows[i].role == TcRole::Standby => {
                self.begin(i, op, QcsStep::CustodyAttest, now);
                let _ = qcs_layer(
                    out,
                    sc::CMD_SC_CUSTODY,
                    &flow,
                    epoch,
                    &[&[sc::custody::ATTEST], body],
                );
            }
            tc_op::CUSTODY_WRAP if self.flows[i].role == TcRole::Primary => {
                if body.len() < 32 {
                    return qcs_status(
                        out,
                        op,
                        tc_st::INVALID,
                        tc_custody::why::EVIDENCE,
                        h,
                        0,
                        flow,
                    );
                }
                let (ch, ev) = body.split_at(32);
                let mut challenge = [0u8; 32];
                challenge.copy_from_slice(ch);
                if let Err(why) = TcCustodyEvidence::check(ev, &challenge) {
                    self.counters.rejected += 1;
                    return qcs_status(out, op, tc_st::INVALID, why, h, 0, flow);
                }
                self.begin(i, op, QcsStep::CustodyAuth, now);
                let c = &mut self.flows[i];
                c.custody_challenge = challenge;
                c.custody_ev[..ev.len()].copy_from_slice(ev);
                c.custody_ev_len = ev.len();
                let e = epoch.to_le_bytes();
                if !qcs_frame(
                    out,
                    QcsPort::Auth,
                    QCS_MSG_CUSTODY_CHECK,
                    &[&flow, &e, &challenge, ev],
                ) {
                    self.done(i, tc_st::NOT_READY, 0, 0, out);
                }
            }
            tc_op::CUSTODY_UNWRAP
                if body.len() == tc_custody::WRAPPED_LEN
                    && self.flows[i].role == TcRole::Standby =>
            {
                self.begin(i, op, QcsStep::CustodyUnwrap, now);
                let _ = qcs_layer(
                    out,
                    sc::CMD_SC_CUSTODY,
                    &flow,
                    epoch,
                    &[&[sc::custody::UNWRAP], &flow, body],
                );
            }
            tc_op::RESERVATION_GRANT if body.len() == sc::GRANT_LEN => {
                let ok = qcs_frame(
                    out,
                    QcsPort::Quic,
                    sc::CMD_SC_RESERVATION_GRANT,
                    &[&flow, body],
                );
                let st = if ok { tc_st::OK } else { tc_st::NOT_READY };
                qcs_status(out, op, st, 0, h, 0, flow);
            }
            _ => qcs_status(out, op, tc_st::INVALID, 0, h, 0, flow),
        }
    }

    fn pair_prepare<O: QcsOut>(&mut self, body: &[u8], now: u64, out: &mut O) {
        let op = tc_op::PAIR_PREPARE;
        let null = TcHandle::default();
        let Some(pair) = TcPair::decode(body) else {
            return qcs_status(out, op, tc_st::INVALID, 0, null, 0, [0; 16]);
        };
        let flow = pair.flow_id;
        if pair.transport != TcTransport::Quic {
            return qcs_status(out, op, tc_st::UNSUPPORTED, 0, null, 0, flow);
        }
        let Some(i) = self
            .by_flow(&flow)
            .or_else(|| self.flows.iter().position(|c| !c.live))
        else {
            return qcs_status(out, op, tc_st::CAPACITY, 0, null, 0, flow);
        };
        self.last_gen = self.last_gen.wrapping_add(1);
        let handle = TcHandle {
            slot: i as u32 + 1,
            generation: self.last_gen,
        };
        let c = &mut self.flows[i];
        c.live = true;
        c.role = pair.role;
        c.mode = pair.mode;
        c.handle = handle;
        c.flow = flow;
        c.epoch = pair.flow_epoch;
        c.mirror_gen = pair.mirror_generation;
        c.service = pair.service_id;
        c.delta_seq = 0;
        c.chain = [0; 32];
        c.mirroring = false;
        c.shadow = false;
        c.imported = false;
        c.armed = false;
        c.inflight_n = 0;
        c.layer_prev = [0; 32];
        c.asm.reset(flow, 0);
        self.begin(i, op, QcsStep::Prepare, now);
        let profile = if pair.mode == TcMode::CrashContinuous {
            sc::PROFILE_CRASH_CONTINUOUS
        } else {
            sc::PROFILE_PLANNED
        };
        let _ = qcs_layer(
            out,
            sc::CMD_SC_PAIR_PREPARE,
            &flow,
            pair.flow_epoch,
            &[&[sc::CT_QUIC, profile], &[0; 32]],
        );
    }

    /// A standby's whole checkpoint: assembled, viewed, handed to `quic`.
    fn commit<O: QcsOut>(&mut self, i: usize, id: u64, now: u64, out: &mut O) {
        let h = self.flows[i].handle;
        let c = &mut self.flows[i];
        let vid = c.asm.verifier.id;
        // A whole checkpoint, into a shadow `quic` has not imported or armed.
        if !c.asm.verifier.complete || vid.checkpoint_id != id || c.imported || c.armed {
            self.counters.rejected += 1;
            let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::COMMIT]);
            return;
        }
        let total = vid.total as usize;
        let chain = c.asm.verifier.chain;
        let parsed = tc_quic_parse(&c.asm.buf[..total])
            .ok()
            .and_then(|(v, layer)| {
                let own = qcs_view(layer)?;
                let same = v.flow_id == c.flow
                    && v.flow_epoch == c.epoch
                    && v.mirror_generation == c.mirror_gen
                    && qcs_view_matches(&v, &own);
                same.then_some((v.layer_gen, layer.len()))
            });
        let Some((gen, n)) = parsed else {
            self.counters.rejected += 1;
            let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::MALFORMED]);
            return;
        };
        c.rec_digest = sha256(&c.asm.buf[..total]);
        let lo = TC_QUIC_HDR;
        c.layer[..n].copy_from_slice(&c.asm.buf[lo..lo + n]);
        c.layer_len = n;
        c.layer_gen = gen;
        c.layer_digest = sha256(&c.layer[..n]);
        c.layer_crc = handoff_crc32(&c.layer[..n]);
        c.ckpt_id = id;
        c.order = MdOrder::after_checkpoint(c.flow, c.epoch, c.mirror_gen, id, chain);
        c.layer_prev = [0; 32];
        self.begin(i, tc_op::CHECKPOINT_COMMIT, QcsStep::Import, now);
        let c = &self.flows[i];
        let (flow, epoch, g) = (c.flow, c.epoch, gen.to_le_bytes());
        let ok = qcs_layer(
            out,
            sc::CMD_SC_CHECKPOINT_BEGIN,
            &flow,
            epoch,
            &[&g, &(n as u32).to_le_bytes(), &c.layer_digest],
        );
        let mut off = 0;
        let mut ok = ok;
        while ok && off < n {
            let k = (n - off).min(sc::CHECKPOINT_CHUNK_MAX);
            ok = qcs_layer(
                out,
                sc::CMD_SC_CHECKPOINT_NEXT,
                &flow,
                epoch,
                &[&g, &(off as u32).to_le_bytes(), &c.layer[off..off + k]],
            );
            off += k;
        }
        let crc = c.layer_crc.to_le_bytes();
        if !ok || !qcs_layer(out, sc::CMD_SC_CHECKPOINT_COMMIT, &flow, epoch, &[&g, &crc]) {
            self.done(i, tc_st::NOT_READY, 0, 0, out);
        }
    }

    fn layer_cut_import<O: QcsOut>(&mut self, i: usize, out: &mut O) {
        let c = &self.flows[i];
        let (flow, epoch) = (c.flow, c.epoch);
        let g = c.layer_gen.to_le_bytes();
        let d = c.layer_digest;
        let _ = qcs_layer(out, sc::CMD_SC_CUT_IMPORT, &flow, epoch, &[&g, &d]);
    }

    fn delta_apply<O: QcsOut>(&mut self, i: usize, body: &[u8], out: &mut O) {
        let h = self.flows[i].handle;
        let c = &self.flows[i];
        // Deltas build the shadow until it is imported for activation.
        if !c.shadow || c.imported || c.armed {
            self.counters.rejected += 1;
            let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::NO_SHADOW]);
            return;
        }
        let Ok((hd, payload)) = md_parse(body) else {
            self.counters.rejected += 1;
            let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::MALFORMED]);
            return;
        };
        let c = &mut self.flows[i];
        match c.order.verify(&hd) {
            Ok(MdVerdict::Duplicate) => {
                let mut a = [0u8; 16];
                a[0..8].copy_from_slice(&c.ckpt_id.to_le_bytes());
                a[8..16].copy_from_slice(&c.order.applied().to_le_bytes());
                let _ = qcs_evt_h(out, tc_evt::APPLIED, h, &a);
            }
            Ok(MdVerdict::Apply) if hd.kind == MdKind::QuicDelta && payload.len() >= 5 => {
                if c.inflight_n == QCS_INFLIGHT {
                    self.counters.rejected += 1;
                    let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::ORDER]);
                    return;
                }
                let no = qle32(payload, 0).to_le_bytes();
                let data = &payload[4..];
                let prev = c.layer_prev;
                let (flow, epoch, g) = (c.flow, c.epoch, c.layer_gen.to_le_bytes());
                if !qcs_layer(
                    out,
                    sc::CMD_SC_DELTA_APPLY,
                    &flow,
                    epoch,
                    &[&g, &no, &prev, data],
                ) {
                    let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::TRANSITION]);
                    return;
                }
                let c = &mut self.flows[i];
                c.layer_prev = sha256(&data[1..]);
                c.order.commit(&hd);
                c.inflight[c.inflight_n] = hd.seq;
                c.inflight_n += 1;
                self.counters.deltas_in += 1;
            }
            Err(MdReject::Stale) => {}
            _ => {
                c.shadow = false;
                self.counters.rejected += 1;
                let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::ORDER]);
            }
        }
    }

    /// The authority's verdict on a token this provider asked about.
    ///
    /// The authority is also where a flow's durable packet-number
    /// reservation comes from (the directory grants it): a
    /// `RESERVATION_GRANT` frame here (`[0x14][len][grant record]`) is the
    /// null-handle grant `tc_ctl` takes, answered on `tc_evt` as that is.
    pub fn verdict_in<O: QcsOut>(&mut self, frame: &[u8], now: u64, out: &mut O) {
        if frame.first() == Some(&QCS_MSG_CUSTODY_VERDICT) {
            return self.custody_verdict(frame, now, out);
        }
        if frame.first() == Some(&tc_op::RESERVATION_GRANT) {
            let mut f = [0u8; TC_FRAME_HDR + TC_HANDLE_LEN + sc::GRANT_LEN];
            if frame.len() != TC_FRAME_HDR + sc::GRANT_LEN {
                return;
            }
            let Some(n) = tc_frame(
                &mut f,
                tc_op::RESERVATION_GRANT,
                &[&[0u8; TC_HANDLE_LEN], &frame[TC_FRAME_HDR..]],
            ) else {
                return;
            };
            return self.ctl(&f[..n], now, out);
        }
        if frame.len() != TC_FRAME_HDR + TC_FLOW_TOKEN_LEN + 1 || frame[0] != QCS_MSG_TOKEN_VERDICT
        {
            return;
        }
        let token = &frame[TC_FRAME_HDR..TC_FRAME_HDR + TC_FLOW_TOKEN_LEN];
        let verdict = frame[TC_FRAME_HDR + TC_FLOW_TOKEN_LEN];
        let Some(i) = self
            .flows
            .iter()
            .position(|c| c.live && c.step == QcsStep::Token && c.token[..] == *token)
        else {
            return;
        };
        if verdict != 0 {
            self.counters.rejected += 1;
            return self.done(i, tc_st::UNAUTHORIZED, verdict, 0, out);
        }
        self.begin(i, tc_op::ACTIVATE, QcsStep::Activate, now);
        let c = &self.flows[i];
        let (flow, ne, fg) = (c.flow, c.new_epoch, c.fence_gen);
        let _ = qcs_layer(out, sc::CMD_SC_ACTIVATE, &flow, ne, &[&fg.to_le_bytes()]);
    }

    fn custody_verdict<O: QcsOut>(&mut self, frame: &[u8], now: u64, out: &mut O) {
        if frame.len() != TC_FRAME_HDR + 16 + 32 + 1 {
            return;
        }
        let p = &frame[TC_FRAME_HDR..];
        let Some(i) = self.flows.iter().position(|c| {
            c.live
                && c.step == QcsStep::CustodyAuth
                && c.flow[..] == p[..16]
                && sha256(&c.custody_ev[..c.custody_ev_len])[..] == p[16..48]
        }) else {
            return;
        };
        if p[48] != 0 {
            self.counters.rejected += 1;
            return self.done(i, tc_st::UNAUTHORIZED, p[48], 0, out);
        }
        self.begin(i, tc_op::CUSTODY_WRAP, QcsStep::CustodyWrap, now);
        let c = &self.flows[i];
        let (flow, epoch, ch, ev, n) = (
            c.flow,
            c.epoch,
            c.custody_challenge,
            c.custody_ev,
            c.custody_ev_len,
        );
        let _ = qcs_layer(
            out,
            sc::CMD_SC_CUSTODY,
            &flow,
            epoch,
            &[&[sc::custody::WRAP], &ch, &ev[..n]],
        );
    }

    // ── what `quic` says ─────────────────────────────────────────────────

    pub fn layer_in<O: QcsOut>(&mut self, frame: &[u8], now: u64, out: &mut O) {
        if frame.len() < TC_FRAME_HDR + sc::FLOW_HEADER_LEN {
            return;
        }
        let t = frame[0];
        let p = &frame[TC_FRAME_HDR..];
        let Some(i) = self.by_flow(&p[..16]) else {
            return;
        };
        match t {
            sc::MSG_SC_CONTINUITY if p.len() >= sc::CONTINUITY_HEADER_LEN => {
                self.reply(i, p[20], p[21], &p[22..], now, out)
            }
            sc::CMD_SC_CHECKPOINT_BEGIN if p.len() >= sc::CHECKPOINT_BEGIN_PAYLOAD_LEN => {
                let c = &mut self.flows[i];
                if c.step == QcsStep::Export {
                    c.layer_gen = qle32(p, 20);
                    c.layer_len = qle32(p, 24) as usize;
                    c.layer_got = 0;
                    c.layer_digest.copy_from_slice(&p[28..60]);
                    if c.layer_len > TC_QUIC_LAYER_MAX {
                        c.layer_len = 0;
                    }
                }
            }
            sc::CMD_SC_CHECKPOINT_NEXT if p.len() >= sc::CHECKPOINT_NEXT_HEADER_LEN => {
                let c = &mut self.flows[i];
                let off = qle32(p, 24) as usize;
                let bytes = &p[sc::CHECKPOINT_NEXT_HEADER_LEN..];
                if c.step == QcsStep::Export
                    && off == c.layer_got
                    && off + bytes.len() <= c.layer_len
                {
                    c.layer[off..off + bytes.len()].copy_from_slice(bytes);
                    c.layer_got += bytes.len();
                }
            }
            sc::CMD_SC_CHECKPOINT_COMMIT if p.len() >= sc::CHECKPOINT_COMMIT_PAYLOAD_LEN => {
                let c = &mut self.flows[i];
                if c.step == QcsStep::Export {
                    c.layer_crc = qle32(p, 24);
                }
            }
            sc::CMD_SC_DELTA_APPLY if p.len() >= sc::DELTA_APPLY_HEADER_LEN => {
                self.delta_out(i, p, out)
            }
            _ => {}
        }
    }

    /// A mirroring primary's per-layer delta: the next `QuicDelta`. The
    /// anchor's DELTA_ACK of sequence `n` is `quic`'s of its delta `n`, so
    /// a delta that cannot go out as exactly the next one ends the pairing
    /// rather than shift every later acknowledgement onto the wrong delta.
    fn delta_out<O: QcsOut>(&mut self, i: usize, p: &[u8], out: &mut O) {
        if !self.flows[i].mirroring {
            return;
        }
        // `[layer_no u32][kind u8][data]` of `[flow][epoch][gen][no][prev][kind][data]`.
        let no = &p[24..28];
        let rest = &p[60..];
        let c = &self.flows[i];
        if u64::from(qle32(no, 0)) != c.delta_seq + 1 {
            return self.lose(i, qcs_lost::GAP, out);
        }
        let mut pl = [0u8; MD_PAYLOAD_MAX];
        if 4 + rest.len() > pl.len() {
            return self.lose(i, qcs_lost::UNREPRESENTABLE, out);
        }
        let c = &mut self.flows[i];
        pl[..4].copy_from_slice(no);
        pl[4..4 + rest.len()].copy_from_slice(rest);
        let mut hd = MdHdr {
            kind: MdKind::QuicDelta,
            flow_id: c.flow,
            flow_epoch: c.epoch,
            mirror_generation: c.mirror_gen,
            base_checkpoint: c.ckpt_id,
            seq: c.delta_seq + 1,
            prev: c.chain,
            payload_len: 0,
            digest: [0; 32],
        };
        let mut f = [0u8; MD_FRAME_MAX];
        let Some(n) = md_encode(&mut hd, &pl[..4 + rest.len()], &mut f) else {
            return self.lose(i, qcs_lost::UNREPRESENTABLE, out);
        };
        let h = c.handle;
        if !qcs_evt_h(out, tc_evt::DELTA, h, &f[..n]) {
            return self.lose(i, qcs_lost::FULL, out);
        }
        let c = &mut self.flows[i];
        c.delta_seq += 1;
        c.chain = hd.digest;
        self.counters.deltas_out += 1;
    }

    /// End a crash-continuous pairing whose stream broke: `quic` stops
    /// mirroring and holding its horizons, and the anchor is told,
    /// unsolicited; the connection runs on unprotected.
    fn lose<O: QcsOut>(&mut self, i: usize, why: u8, out: &mut O) {
        let c = &mut self.flows[i];
        c.mirroring = false;
        let (h, flow, epoch) = (c.handle, c.flow, c.epoch);
        let _ = qcs_layer(out, sc::CMD_SC_ABORT, &flow, epoch, &[&[why]]);
        qcs_status(out, tc_op::ABORT, tc_st::OK, 0x80 | why, h, 0, flow);
    }

    fn reply<O: QcsOut>(
        &mut self,
        i: usize,
        record: u8,
        status: u8,
        body: &[u8],
        now: u64,
        out: &mut O,
    ) {
        let step = self.flows[i].step;
        let ok = status == sc::STATUS_OK;
        match (step, record) {
            (QcsStep::Prepare, sc::CR_PAIR_PREPARED) => {
                if ok {
                    let c = &mut self.flows[i];
                    c.shadow = false;
                    self.done(i, tc_st::OK, 0, 0, out);
                } else {
                    self.flows[i].live = false;
                    self.done(i, tc_st::UNSUPPORTED, status, 0, out);
                }
            }
            (QcsStep::Prepare, sc::CR_ABORTED) => {
                self.flows[i].live = false;
                self.done(i, tc_st::UNSUPPORTED, status, 0, out);
            }
            (QcsStep::Export, sc::CR_CUT) => {
                if !ok {
                    return self.done(i, tc_st::UNSUPPORTED, status, 0, out);
                }
                self.export(i, now, out);
            }
            (QcsStep::Export, sc::CR_ABORTED) => self.done(i, tc_st::UNSUPPORTED, status, 0, out),
            (QcsStep::Import, sc::CR_CHECKPOINT_COMMITTED) => {
                if ok {
                    let c = &mut self.flows[i];
                    c.shadow = true;
                    c.asm.verifier.seal();
                    let (h, id) = (c.handle, c.ckpt_id);
                    c.step = QcsStep::Idle;
                    let mut a = [0u8; 16];
                    a[0..8].copy_from_slice(&id.to_le_bytes());
                    let _ = qcs_evt_h(out, tc_evt::APPLIED, h, &a);
                } else {
                    let h = self.flows[i].handle;
                    self.flows[i].step = QcsStep::Idle;
                    self.counters.rejected += 1;
                    let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::KEYS]);
                }
            }
            (_, sc::CR_DELTA_APPLIED) => {
                let c = &mut self.flows[i];
                if c.inflight_n == 0 {
                    return;
                }
                let seq = c.inflight[0];
                c.inflight.copy_within(1..c.inflight_n, 0);
                c.inflight_n -= 1;
                let h = c.handle;
                if ok {
                    let mut a = [0u8; 16];
                    a[0..8].copy_from_slice(&c.ckpt_id.to_le_bytes());
                    a[8..16].copy_from_slice(&seq.to_le_bytes());
                    let _ = qcs_evt_h(out, tc_evt::APPLIED, h, &a);
                } else {
                    c.shadow = false;
                    self.counters.rejected += 1;
                    let _ = qcs_evt_h(out, tc_evt::REJECTED, h, &[tc_rej::TRANSITION]);
                }
            }
            (QcsStep::Quiesce, sc::CR_QUIESCED) => {
                // `[drained u8][pending_out u32][pending_in u32]` — quiescent
                // when both are drained.
                let drained =
                    body.len() >= 9 && body[0] == 1 && qle32(body, 1) == 0 && qle32(body, 5) == 0;
                let st = if ok { tc_st::OK } else { tc_st::NOT_READY };
                self.done(i, st, 0, u64::from(drained), out);
            }
            (QcsStep::CutImport, sc::CR_IMPORTED) | (QcsStep::ArmImport, sc::CR_IMPORTED) => {
                if !ok {
                    return self.done(i, tc_st::INVALID, status, 0, out);
                }
                self.flows[i].imported = true;
                if step == QcsStep::CutImport {
                    self.done(i, tc_st::OK, 0, 0, out);
                } else {
                    let c = &self.flows[i];
                    let (flow, epoch) = (c.flow, c.epoch);
                    self.begin(i, tc_op::EMISSION_ARM, QcsStep::Arm, now);
                    let _ = qcs_layer(out, sc::CMD_SC_EMISSION_ARM, &flow, epoch, &[]);
                }
            }
            (QcsStep::Arm, sc::CR_ARMED) => {
                self.flows[i].armed = ok;
                let st = if ok { tc_st::OK } else { tc_st::NOT_READY };
                self.done(i, st, status, 0, out);
            }
            (QcsStep::Activate, sc::CR_ACTIVATED) => {
                if ok {
                    let c = &mut self.flows[i];
                    c.epoch = c.new_epoch;
                    c.role = TcRole::Primary;
                    c.armed = false;
                    let conn = if body.len() >= 6 {
                        u64::from(u16::from_le_bytes([body[4], body[5]]))
                    } else {
                        0
                    };
                    self.done(i, tc_st::OK, 0, conn, out);
                } else {
                    self.done(i, tc_st::NOT_READY, status, 0, out);
                }
            }
            (QcsStep::Retire, sc::CR_RETIRED) => {
                let value = if self.flows[i].op == tc_op::EMISSION_DISABLE {
                    self.custody_gen += 1;
                    u64::from(self.custody_gen)
                } else {
                    0
                };
                let st = if ok { tc_st::OK } else { tc_st::NOT_READY };
                if self.flows[i].op == tc_op::RETIRE {
                    self.flows[i].live = false;
                }
                self.done(i, st, status, value, out);
            }
            (
                QcsStep::CustodyAttest | QcsStep::CustodyWrap | QcsStep::CustodyUnwrap,
                sc::CR_CUSTODY,
            ) => {
                if body.len() < 2 {
                    return self.done(i, tc_st::INVALID, 0, 0, out);
                }
                let (reason, bytes) = (body[1], &body[2..]);
                if !ok {
                    let why = match reason {
                        sc::custody::why::CHALLENGE => tc_custody::why::CHALLENGE,
                        sc::custody::why::SIGNATURE => tc_custody::why::SIGNATURE,
                        sc::custody::why::RECIPIENT => tc_custody::why::RECIPIENT,
                        sc::custody::why::NO_RECIPIENT => tc_custody::why::NO_RECIPIENT,
                        sc::custody::why::EVIDENCE => tc_custody::why::EVIDENCE,
                        _ => tc_custody::why::VAULT,
                    };
                    self.counters.rejected += 1;
                    return self.done(i, tc_st::INVALID, why, 0, out);
                }
                let kind = match step {
                    QcsStep::CustodyAttest if bytes.len() >= tc_custody::EVIDENCE_MIN => {
                        Some(tc_custody::EVIDENCE)
                    }
                    QcsStep::CustodyWrap if bytes.len() == tc_custody::WRAPPED_LEN => {
                        Some(tc_custody::WRAPPED)
                    }
                    QcsStep::CustodyUnwrap => None,
                    _ => return self.done(i, tc_st::INVALID, 0, 0, out),
                };
                if let Some(k) = kind {
                    let h = self.flows[i].handle;
                    let n = bytes.len().min(tc_custody::EVIDENCE_MAX);
                    let mut b = [0u8; 1 + tc_custody::EVIDENCE_MAX];
                    b[0] = k;
                    b[1..1 + n].copy_from_slice(&bytes[..n]);
                    let _ = qcs_evt_h(out, tc_evt::CUSTODY, h, &b[..1 + n]);
                }
                self.done(i, tc_st::OK, 0, 0, out);
            }
            (_, sc::CR_ABORTED) if self.flows[i].mirroring => {
                // `quic` ended its own pairing: the anchor is told, unsolicited.
                let c = &mut self.flows[i];
                c.mirroring = false;
                let (h, flow) = (c.handle, c.flow);
                qcs_status(out, tc_op::ABORT, tc_st::OK, 0x80 | status, h, 0, flow);
            }
            _ => {}
        }
    }

    /// The primary's record, from `quic`'s export: checked, viewed, chunked.
    fn export<O: QcsOut>(&mut self, i: usize, _now: u64, out: &mut O) {
        let c = &self.flows[i];
        let n = c.layer_len;
        let whole = n > 0
            && c.layer_got == n
            && sha256(&c.layer[..n]) == c.layer_digest
            && handoff_crc32(&c.layer[..n]) == c.layer_crc;
        let view = if whole { qcs_view(&c.layer[..n]) } else { None };
        let Some(mut v) = view else {
            return self.done(i, tc_st::UNSUPPORTED, tc_rej::MALFORMED, 0, out);
        };
        v.flow_id = c.flow;
        v.flow_epoch = c.epoch;
        v.mirror_generation = c.mirror_gen;
        v.service_id = c.service;
        v.layer_gen = c.layer_gen;
        v.layer_len = n as u32;
        v.layer_digest = c.layer_digest;
        let Some(total) = tc_quic_encode(&v, &c.layer[..n], &mut self.rec) else {
            return self.done(i, tc_st::UNSUPPORTED, 0, 0, out);
        };
        let c = &self.flows[i];
        let cid = CkptId {
            checkpoint_id: c.ckpt_id,
            flow_id: c.flow,
            flow_epoch: c.epoch,
            mirror_generation: c.mirror_gen,
            total: total as u32,
        };
        let mut chain = ckpt_chain_seed(&cid);
        let h = c.handle;
        for k in 0..ckpt_chunk_count(total) {
            let mut chunk = [0u8; CKPT_CHUNK_MAX];
            if let Some(m) = ckpt_write_chunk(&cid, &self.rec[..total], k, &mut chain, &mut chunk) {
                if !qcs_evt_h(out, tc_evt::CHUNK, h, &chunk[..m]) {
                    return self.done(i, tc_st::NOT_READY, 0, 0, out);
                }
            }
        }
        let rd = sha256(&self.rec[..total]);
        let c = &mut self.flows[i];
        c.rec_digest = rd;
        c.chain = chain;
        c.delta_seq = 0;
        if c.mode == TcMode::CrashContinuous {
            // Mirroring starts here: `quic` learns its checkpoint is held and
            // from now on its deltas are this stream's, each acknowledged to
            // it only as the anchor's standby acknowledges it.
            c.mirroring = true;
            let (flow, epoch, gen) = (c.flow, c.epoch, c.layer_gen);
            let committed = [sc::CR_CHECKPOINT_COMMITTED, sc::STATUS_OK];
            let _ = qcs_layer(
                out,
                sc::MSG_SC_CONTINUITY,
                &flow,
                epoch,
                &[&committed, &gen.to_le_bytes()],
            );
        }
        let id = self.flows[i].ckpt_id;
        self.done(i, tc_st::OK, 0, id, out);
    }
}
