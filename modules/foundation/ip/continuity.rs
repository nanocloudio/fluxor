//! TCP transport continuity: the checkpoint codec, the mirror stream and
//! the cut-over lifecycle of `contracts/net/session_ctrl.rs`
//! §Transport continuity, for connections this module owns end to end.
//!
//! Two roles, one port pair (`cont_in` / `cont_out`):
//!
//! - **Exporter.** A live connection is *mirrored*: on `CUT_EXPORT` its
//!   canonical record is emitted as a chunked checkpoint, and from then
//!   on every externally visible transition is emitted as an ordered
//!   delta. Under `PROFILE_CRASH_CONTINUOUS` the transition waits for its
//!   `DELTA_ACK` — the acknowledgement shown to the peer never runs ahead
//!   of the receive horizon the standby has confirmed, and a data segment
//!   or FIN is not handed to the wire before its send delta is confirmed.
//! - **Importer.** A *shadow* is prepared, receives the checkpoint into a
//!   staging buffer, validates it whole, applies deltas, and becomes the
//!   live connection only at `ACTIVATE` under a strictly higher epoch
//!   with a confirmed fence generation. It emits nothing before that.
//!
//! The flow identity is a pure function of the tuple, so a coordinator
//! that knows the connection can name it on both sides:
//!
//! ```text
//! flow_id = [local_ip:4 BE][remote_ip:4 BE][local_port:2 BE][remote_port:2 BE][0;4]
//! ```
//!
//! # Canonical record (`CT_TCP`)
//!
//! Little-endian unless stated; timers are REMAINING durations in the
//! module's 50 ms timer ticks, never timestamps.
//!
//! ```text
//! [magic "FXTC"][layout u8 = 1][state u8]
//! [local_ip u32 BE][remote_ip u32 BE][local_port u16][remote_port u16]
//! [owner_tag u16][prefix_len u8][pad u8]
//! [iss u32][snd_una u32][snd_nxt u32][snd_wnd u16][snd_wl1 u32][snd_wl2 u32]
//! [rcv_nxt u32][rcv_wnd u16]
//! [cwnd u16][ssthresh u16][dup_ack_count u8][in_recovery u8][recover_seq u32]
//! [srtt u16][rttvar u16][rto u16]
//! [retransmit_remaining u16][timewait_remaining u16][idle_remaining u16][closewait_remaining u16]
//! [delivered_bytes u32][consumed_bytes u32]
//! [trace_id 16][span_id 8][sampled_flags u8]
//! [reorder_count u8] then per slot: [seq u32][len u16][bytes]
//! ```
//!
//! Unacknowledged send bytes are not in the record: this module never
//! holds them. The consumer above (`tls`, or the application) retains the
//! exact bytes it handed down and replays them on `MSG_RETRANSMIT`, and
//! its own checkpoint carries them. What the record fixes is the sequence
//! allocation those bytes occupy, so a takeover retransmits the same
//! ranges and never allocates a number twice.
//!
//! The layout digest a pair agrees on at `PAIR_PREPARE` is the SHA-256 of
//! `TCP_CODEC_LAYOUT`; a standby built from a different layout refuses
//! before any byte moves.

use super::*;

/// Port indices on this module.
pub const CONT_IN_PORT: u8 = 4;
pub const CONT_OUT_PORT: u8 = 6;

/// Shadows and mirrors this module holds at once.
pub use abi::config::ip::MAX_TCP_SHADOWS;

/// Record header: magic, layout, state.
const REC_MAGIC: [u8; 4] = *b"FXTC";
const REC_LAYOUT: u8 = 1;
/// Fixed part of the record, before the reorder slots.
const REC_FIXED_LEN: usize = 4
    + 1
    + 1
    + 4
    + 4
    + 2
    + 2
    + 2
    + 1
    + 1
    + 4 * 3
    + 2
    + 4
    + 4
    + 4
    + 2
    + 2
    + 2
    + 1
    + 1
    + 4
    + 2
    + 2
    + 2
    + 2 * 4
    + 4
    + 4
    + 16
    + 8
    + 1
    + 1;
/// Largest record: the fixed part plus every reorder slot full.
pub const TCP_RECORD_MAX: usize =
    REC_FIXED_LEN + tcp::REORDER_SLOTS * (4 + 2 + tcp::REORDER_SLOT_BYTES);

/// What `PAIR_PREPARE` binds: the layout of the record above.
const TCP_CODEC_LAYOUT: &[u8] = b"fluxor.ip.tcp-checkpoint:1:FXTC:reorder";

/// TIME-WAIT length in timer ticks, as the sweep enforces it.
const TIMEWAIT_TICKS: u16 = 41;
/// Handshake and closing-state ceiling in timer ticks, as the sweep
/// enforces it.
const HANDSHAKE_TICKS: u16 = 300;
/// A disabled idle timer exports as this and imports back as disabled.
const IDLE_DISABLED: u16 = u16::MAX;

/// Shadow phases.
const SH_PREPARED: u8 = 1;
const SH_RECEIVING: u8 = 2;
const SH_COMMITTED: u8 = 3;
const SH_IMPORTED: u8 = 4;
const SH_ARMED: u8 = 5;

/// Send gate kinds on a mirror.
const GATE_NONE: u8 = 0;
const GATE_SEND: u8 = 1;
const GATE_FIN: u8 = 2;

/// Outstanding receive deltas a strict mirror tracks; acknowledgements
/// are cumulative, so the ring only needs to cover what one ack window
/// can hold.
const RECV_RING: usize = 8;

/// Distinguishes a slot reserved for a shadow from a free one.
pub const NOTIFY_SHADOW_RESERVED: u8 = 9;

use abi::contracts::net::session_ctrl as sc;

/// One connection staged for import.
#[repr(C)]
pub struct TcpShadow {
    pub in_use: u8,
    pub phase: u8,
    pub profile: u8,
    pub expired_timers: u8,
    pub flow_id: [u8; 16],
    pub epoch: u32,
    pub ckpt_gen: u32,
    pub delta_no: u32,
    pub conn_idx: u32,
    pub armed_ms: u32,
    pub record_len: u32,
    pub record_digest: [u8; 32],
    pub last_delta_digest: [u8; 32],
    pub import: HandoffImport,
    pub record: [u8; TCP_RECORD_MAX],
    pub conn: tcp::TcpConn,
}

impl TcpShadow {
    /// Zero in place; no temporary the size of the record on the stack.
    pub fn clear(&mut self) {
        // SAFETY: every field is plain data; the all-zero image is then
        // fixed up where zero is not the empty value.
        unsafe { core::ptr::write_bytes(self as *mut Self, 0, 1) };
        self.conn_idx = u32::MAX;
        self.import = HandoffImport::new();
        self.conn.state = tcp::TcpState::Closed;
        self.conn.local_slot = tcp::LOCAL_SLOT_ANY;
    }

    pub const fn empty() -> Self {
        Self {
            in_use: 0,
            phase: 0,
            profile: 0,
            expired_timers: 0,
            flow_id: [0; 16],
            epoch: 0,
            ckpt_gen: 0,
            delta_no: 0,
            conn_idx: u32::MAX,
            armed_ms: 0,
            record_len: 0,
            record_digest: [0; 32],
            last_delta_digest: [0; 32],
            import: HandoffImport::new(),
            record: [0; TCP_RECORD_MAX],
            conn: tcp::TcpConn::new(),
        }
    }
}

/// One live connection being mirrored out.
#[repr(C)]
pub struct TcpMirror {
    pub in_use: u8,
    pub profile: u8,
    /// The standby holds a committed checkpoint: deltas flow, and under
    /// the strict profile the horizons are enforced.
    pub live: u8,
    pub quiescing: u8,
    pub flow_id: [u8; 16],
    pub epoch: u32,
    pub ckpt_gen: u32,
    pub conn_idx: u32,
    pub delta_no: u32,
    pub prev_digest: [u8; 32],
    /// Highest acknowledgement number the peer may be shown.
    pub recv_horizon: u32,
    /// Receive deltas awaiting acknowledgement: (delta_no, rcv_nxt after).
    pub recv_ring: [[u32; 2]; RECV_RING],
    pub recv_ring_len: u8,
    /// A receive delta that could not be emitted yet.
    pub recv_pending: u8,
    pub gate_kind: u8,
    pub gate_open: u8,
    pub recv_pending_seq: u32,
    pub recv_pending_len: u16,
    pub recv_pending_fin: u8,
    pub _pad: u8,
    pub recv_pending_after: u32,
    pub gate_seq: u32,
    pub gate_len: u16,
    pub _pad2: [u8; 2],
    pub gate_delta: u32,
    pub quiesce_deadline_ms: u32,
    pub export_active: u8,
    pub _pad3: [u8; 3],
    pub export_off: u32,
    pub export_len: u32,
    pub export_digest: [u8; 32],
    pub export_buf: [u8; TCP_RECORD_MAX],
    pub deltas_dropped: u32,
}

impl TcpMirror {
    /// Zero in place; no temporary the size of the record on the stack.
    pub fn clear(&mut self) {
        // SAFETY: every field is plain data and zero is its empty value,
        // except the slot index.
        unsafe { core::ptr::write_bytes(self as *mut Self, 0, 1) };
        self.conn_idx = u32::MAX;
    }

    pub const fn empty() -> Self {
        Self {
            in_use: 0,
            profile: 0,
            live: 0,
            quiescing: 0,
            flow_id: [0; 16],
            epoch: 0,
            ckpt_gen: 0,
            conn_idx: u32::MAX,
            delta_no: 0,
            prev_digest: [0; 32],
            recv_horizon: 0,
            recv_ring: [[0; 2]; RECV_RING],
            recv_ring_len: 0,
            recv_pending: 0,
            gate_kind: GATE_NONE,
            gate_open: 0,
            recv_pending_seq: 0,
            recv_pending_len: 0,
            recv_pending_fin: 0,
            _pad: 0,
            recv_pending_after: 0,
            gate_seq: 0,
            gate_len: 0,
            _pad2: [0; 2],
            gate_delta: 0,
            quiesce_deadline_ms: 0,
            export_active: 0,
            _pad3: [0; 3],
            export_off: 0,
            export_len: 0,
            export_digest: [0; 32],
            export_buf: [0; TCP_RECORD_MAX],
            deltas_dropped: 0,
        }
    }
}

/// Continuity state carried by `IpState`.
#[repr(C)]
pub struct Continuity {
    pub in_chan: i32,
    pub out_chan: i32,
    /// One reply that could not be written yet; while it is held no new
    /// command is read, so replies stay in order.
    pub reply_len: u16,
    pub _pad: [u8; 2],
    pub reply: [u8; 3 + sc::CONTINUITY_HEADER_LEN + 64],
    pub shadows: [TcpShadow; MAX_TCP_SHADOWS],
    pub mirrors: [TcpMirror; MAX_TCP_SHADOWS],
    pub stats: ContStats,
}

/// Counters a harness and the heartbeat read.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ContStats {
    pub checkpoints_out: u32,
    pub checkpoints_in: u32,
    pub deltas_out: u32,
    pub deltas_in: u32,
    pub deltas_dropped: u32,
    pub activations: u32,
    pub refusals: u32,
    pub horizon_waits: u32,
}

impl Continuity {
    pub const fn empty() -> Self {
        const SH: TcpShadow = TcpShadow::empty();
        const MI: TcpMirror = TcpMirror::empty();
        Self {
            in_chan: -1,
            out_chan: -1,
            reply_len: 0,
            _pad: [0; 2],
            reply: [0; 3 + sc::CONTINUITY_HEADER_LEN + 64],
            shadows: [SH; MAX_TCP_SHADOWS],
            mirrors: [MI; MAX_TCP_SHADOWS],
            stats: ContStats {
                checkpoints_out: 0,
                checkpoints_in: 0,
                deltas_out: 0,
                deltas_in: 0,
                deltas_dropped: 0,
                activations: 0,
                refusals: 0,
                horizon_waits: 0,
            },
        }
    }
}

/// Bring the continuity state up at construct: ports resolved, every
/// shadow and mirror empty. In place, field by field.
pub(super) unsafe fn init(s: &mut IpState) {
    let sys = &*s.syscalls;
    s.cont.in_chan = dev_channel_port(sys, 0, CONT_IN_PORT);
    s.cont.out_chan = dev_channel_port(sys, 1, CONT_OUT_PORT);
    s.cont.reply_len = 0;
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        s.cont.shadows[i].clear();
        s.cont.mirrors[i].clear();
        i += 1;
    }
    s.cont.stats = ContStats::default();
}

/// Whether the continuity ports are wired.
pub(super) fn wired(s: &IpState) -> bool {
    s.cont.in_chan >= 0 && s.cont.out_chan >= 0
}

/// Called once per admitted segment on `idx`, after its actions ran:
/// turns what changed into deltas.
pub(super) unsafe fn after_segment(
    s: &mut IpState,
    idx: usize,
    state_before: tcp::TcpState,
    rcv_before: u32,
    acked_new: bool,
) {
    if mirror_of_conn(s, idx).is_none() {
        return;
    }
    let (state_after, rcv_after) = {
        let c = &*s.tcp_conns.as_ptr().add(idx);
        (c.state, c.rcv_nxt)
    };
    let fin_before = matches!(
        state_before,
        tcp::TcpState::CloseWait
            | tcp::TcpState::Closing
            | tcp::TcpState::TimeWait
            | tcp::TcpState::LastAck
    );
    let fin_after = matches!(
        state_after,
        tcp::TcpState::CloseWait
            | tcp::TcpState::Closing
            | tcp::TcpState::TimeWait
            | tcp::TcpState::LastAck
    );
    let fin = fin_after && !fin_before;
    if rcv_after != rcv_before {
        let total = rcv_after.wrapping_sub(rcv_before);
        let len = total.saturating_sub(fin as u32).min(u32::from(u16::MAX)) as u16;
        on_rx_advance(s, idx, rcv_before, len, fin, rcv_after);
    }
    if acked_new {
        on_acked(s, idx);
    }
    if state_after != state_before {
        on_state(s, idx);
    }
}

/// The layout digest a pair agrees on.
pub fn codec_digest() -> [u8; 32] {
    sha256(TCP_CODEC_LAYOUT)
}

/// The flow identity of connection `idx`.
pub(super) unsafe fn flow_id_of(s: &IpState, idx: usize) -> [u8; 16] {
    let c = &*s.tcp_conns.as_ptr().add(idx);
    let local = local_ip_for_slot(s, c.local_slot);
    let mut f = [0u8; 16];
    f[..4].copy_from_slice(&local.to_be_bytes());
    f[4..8].copy_from_slice(&c.remote_ip.to_be_bytes());
    f[8..10].copy_from_slice(&c.local_port.to_be_bytes());
    f[10..12].copy_from_slice(&c.remote_port.to_be_bytes());
    f
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd_u32_be(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Which mirror (if any) covers connection `idx`.
pub(super) fn mirror_of_conn(s: &IpState, idx: usize) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        let m = &s.cont.mirrors[i];
        if m.in_use != 0 && m.conn_idx as usize == idx {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_mirror(s: &IpState, flow: &[u8; 16]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        let m = &s.cont.mirrors[i];
        if m.in_use != 0 && m.flow_id == *flow {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_shadow(s: &IpState, flow: &[u8; 16]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        let sh = &s.cont.shadows[i];
        if sh.in_use != 0 && sh.flow_id == *flow {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn free_shadow(s: &IpState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        if s.cont.shadows[i].in_use == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn free_mirror(s: &IpState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        if s.cont.mirrors[i].in_use == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The live connection a flow names on this module, if it is one this
/// module could export.
unsafe fn conn_of_flow(s: &IpState, flow: &[u8; 16]) -> Option<usize> {
    let local = rd_u32_be(flow, 0);
    let remote = rd_u32_be(flow, 4);
    let lport = u16::from_be_bytes([flow[8], flow[9]]);
    let rport = u16::from_be_bytes([flow[10], flow[11]]);
    let slot = local_slot_for_dst(s, local)?;
    find_conn_indexed(s, remote, rport, lport, slot)
}

// ── Replies ───────────────────────────────────────────────────────

/// Queue a `MSG_SC_CONTINUITY` reply. One is held at a time; the caller
/// has checked `reply_len == 0` before taking a command.
unsafe fn reply(s: &mut IpState, flow: &[u8; 16], epoch: u32, record: u8, status: u8, body: &[u8]) {
    let plen = sc::CONTINUITY_HEADER_LEN + body.len();
    let r = &mut s.cont.reply;
    r[0] = sc::MSG_SC_CONTINUITY;
    r[1] = plen as u8;
    r[2] = (plen >> 8) as u8;
    r[3..19].copy_from_slice(flow);
    r[19..23].copy_from_slice(&epoch.to_le_bytes());
    r[23] = record;
    r[24] = status;
    r[25..25 + body.len()].copy_from_slice(body);
    s.cont.reply_len = (3 + plen) as u16;
    if status != sc::STATUS_OK {
        s.cont.stats.refusals = s.cont.stats.refusals.wrapping_add(1);
    }
    flush_reply(s);
}

unsafe fn flush_reply(s: &mut IpState) -> bool {
    if s.cont.reply_len == 0 {
        return true;
    }
    if s.cont.out_chan < 0 {
        s.cont.reply_len = 0;
        return true;
    }
    let sys = &*s.syscalls;
    let len = s.cont.reply_len as usize;
    let n = (sys.channel_write)(s.cont.out_chan, s.cont.reply.as_ptr(), len);
    if n == len as i32 {
        s.cont.reply_len = 0;
        true
    } else {
        false
    }
}

/// Write one command-shaped frame (checkpoint chunk or delta) on
/// `cont_out`. Atomic: all or nothing.
unsafe fn emit_frame(s: &mut IpState, msg_type: u8, payload: &[u8]) -> bool {
    if s.cont.out_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let total = 3 + payload.len();
    if total > s.net_scratch.len() {
        return false;
    }
    let p = s.net_scratch.as_mut_ptr();
    *p = msg_type;
    *p.add(1) = payload.len() as u8;
    *p.add(2) = (payload.len() >> 8) as u8;
    core::ptr::copy_nonoverlapping(payload.as_ptr(), p.add(3), payload.len());
    (sys.channel_write)(s.cont.out_chan, p, total) == total as i32
}

// ── Record codec ──────────────────────────────────────────────────

fn put(out: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    out[*pos..*pos + bytes.len()].copy_from_slice(bytes);
    *pos += bytes.len();
}

/// Whether `state` is one a checkpoint admits: synchronised, and not a
/// state whose remaining life is a quiet period this side owns.
fn state_exportable(state: tcp::TcpState) -> bool {
    matches!(
        state,
        tcp::TcpState::Established
            | tcp::TcpState::CloseWait
            | tcp::TcpState::FinWait1
            | tcp::TcpState::FinWait2
            | tcp::TcpState::Closing
            | tcp::TcpState::LastAck
    )
}

fn state_code(state: tcp::TcpState) -> u8 {
    match state {
        tcp::TcpState::Established => 1,
        tcp::TcpState::CloseWait => 2,
        tcp::TcpState::FinWait1 => 3,
        tcp::TcpState::FinWait2 => 4,
        tcp::TcpState::Closing => 5,
        tcp::TcpState::LastAck => 6,
        _ => 0,
    }
}

fn state_of_code(code: u8) -> Option<tcp::TcpState> {
    Some(match code {
        1 => tcp::TcpState::Established,
        2 => tcp::TcpState::CloseWait,
        3 => tcp::TcpState::FinWait1,
        4 => tcp::TcpState::FinWait2,
        5 => tcp::TcpState::Closing,
        6 => tcp::TcpState::LastAck,
        _ => return None,
    })
}

/// Encode connection `idx` into `out`; the record length.
pub(super) unsafe fn encode_record(
    s: &IpState,
    idx: usize,
    out: &mut [u8; TCP_RECORD_MAX],
) -> usize {
    let c = &*s.tcp_conns.as_ptr().add(idx);
    let local = local_ip_for_slot(s, c.local_slot);
    let slot = if c.local_slot == tcp::LOCAL_SLOT_ANY {
        0
    } else {
        c.local_slot as usize
    };
    let prefix_len = s.local_addrs[slot].prefix_len;
    let mut p = 0usize;
    put(out, &mut p, &REC_MAGIC);
    put(out, &mut p, &[REC_LAYOUT, state_code(c.state)]);
    put(out, &mut p, &local.to_be_bytes());
    put(out, &mut p, &c.remote_ip.to_be_bytes());
    put(out, &mut p, &c.local_port.to_le_bytes());
    put(out, &mut p, &c.remote_port.to_le_bytes());
    put(out, &mut p, &c.owner_tag.to_le_bytes());
    put(out, &mut p, &[prefix_len, 0]);
    put(out, &mut p, &c.iss.to_le_bytes());
    put(out, &mut p, &c.snd_una.to_le_bytes());
    put(out, &mut p, &c.snd_nxt.to_le_bytes());
    put(out, &mut p, &c.snd_wnd.to_le_bytes());
    put(out, &mut p, &c.snd_wl1.to_le_bytes());
    put(out, &mut p, &c.snd_wl2.to_le_bytes());
    put(out, &mut p, &c.rcv_nxt.to_le_bytes());
    put(out, &mut p, &c.rcv_wnd.to_le_bytes());
    put(out, &mut p, &c.cwnd.to_le_bytes());
    put(out, &mut p, &c.ssthresh.to_le_bytes());
    put(out, &mut p, &[c.dup_ack_count, c.in_recovery as u8]);
    put(out, &mut p, &c.recover_seq.to_le_bytes());
    put(out, &mut p, &c.srtt.to_le_bytes());
    put(out, &mut p, &c.rttvar.to_le_bytes());
    put(out, &mut p, &c.rto.to_le_bytes());
    let retx_rem = if c.snd_nxt != c.snd_una {
        c.rto.saturating_sub(c.retransmit_timer)
    } else {
        0
    };
    let tw_rem = TIMEWAIT_TICKS.saturating_sub(c.timewait_timer);
    let idle_rem = if s.tcp_idle_ticks == 0 {
        IDLE_DISABLED
    } else {
        s.tcp_idle_ticks.saturating_sub(c.idle_timer)
    };
    let cw_rem = CLOSE_WAIT_TICKS.saturating_sub(c.closewait_timer);
    put(out, &mut p, &retx_rem.to_le_bytes());
    put(out, &mut p, &tw_rem.to_le_bytes());
    put(out, &mut p, &idle_rem.to_le_bytes());
    put(out, &mut p, &cw_rem.to_le_bytes());
    put(out, &mut p, &c.delivered_bytes.to_le_bytes());
    put(out, &mut p, &c.consumed_bytes.to_le_bytes());
    put(out, &mut p, &c.trace_id);
    put(out, &mut p, &c.span_id);
    put(out, &mut p, &[c.sampled_flags]);
    let count_pos = p;
    put(out, &mut p, &[0u8]);
    let mut n = 0u8;
    let mut i = 0;
    while i < tcp::REORDER_SLOTS {
        let sl = &c.reorder_slots[i];
        if sl.valid && sl.len > 0 {
            let len = sl.len as usize;
            put(out, &mut p, &sl.seq.to_le_bytes());
            put(out, &mut p, &(len as u16).to_le_bytes());
            let base = i * tcp::REORDER_SLOT_BYTES;
            put(out, &mut p, &c.reorder_buf[base..base + len]);
            n += 1;
        }
        i += 1;
    }
    out[count_pos] = n;
    p
}

/// Decode a record into a connection, or the status refusing it.
/// `elapsed_ticks` is the transfer age charged against every timer.
unsafe fn decode_record(s: &IpState, rec: &[u8], conn: &mut tcp::TcpConn) -> Result<(), u8> {
    if rec.len() < REC_FIXED_LEN || rec[..4] != REC_MAGIC || rec[4] != REC_LAYOUT {
        return Err(sc::STATUS_CORRUPT);
    }
    let state = state_of_code(rec[5]).ok_or(sc::STATUS_CORRUPT)?;
    let mut p = 6usize;
    let local = rd_u32_be(rec, p);
    p += 4;
    let remote = rd_u32_be(rec, p);
    p += 4;
    let lport = rd_u16(rec, p);
    p += 2;
    let rport = rd_u16(rec, p);
    p += 2;
    let owner_tag = rd_u16(rec, p);
    p += 2;
    p += 2; // prefix_len, pad
    if remote == 0 || lport == 0 || rport == 0 {
        return Err(sc::STATUS_CORRUPT);
    }
    // Route identity: the address must be one this module holds.
    let slot = local_slot_for_dst(s, local).ok_or(sc::STATUS_NOT_READY)?;
    *conn = tcp::TcpConn::new();
    conn.state = state;
    conn.local_port = lport;
    conn.remote_port = rport;
    conn.remote_ip = remote;
    conn.local_slot = slot;
    conn.owner_tag = owner_tag;
    conn.iss = rd_u32(rec, p);
    p += 4;
    conn.snd_una = rd_u32(rec, p);
    p += 4;
    conn.snd_nxt = rd_u32(rec, p);
    p += 4;
    conn.snd_wnd = rd_u16(rec, p);
    p += 2;
    conn.snd_wl1 = rd_u32(rec, p);
    p += 4;
    conn.snd_wl2 = rd_u32(rec, p);
    p += 4;
    conn.rcv_nxt = rd_u32(rec, p);
    p += 4;
    conn.rcv_wnd = rd_u16(rec, p);
    p += 2;
    conn.cwnd = rd_u16(rec, p);
    p += 2;
    conn.ssthresh = rd_u16(rec, p);
    p += 2;
    conn.dup_ack_count = rec[p];
    conn.in_recovery = rec[p + 1] != 0;
    p += 2;
    conn.recover_seq = rd_u32(rec, p);
    p += 4;
    conn.srtt = rd_u16(rec, p);
    p += 2;
    conn.rttvar = rd_u16(rec, p);
    p += 2;
    conn.rto = rd_u16(rec, p);
    p += 2;
    let retx_rem = rd_u16(rec, p);
    p += 2;
    let tw_rem = rd_u16(rec, p);
    p += 2;
    let idle_rem = rd_u16(rec, p);
    p += 2;
    let cw_rem = rd_u16(rec, p);
    p += 2;
    conn.delivered_bytes = rd_u32(rec, p);
    p += 4;
    conn.consumed_bytes = rd_u32(rec, p);
    p += 4;
    conn.trace_id.copy_from_slice(&rec[p..p + 16]);
    p += 16;
    conn.span_id.copy_from_slice(&rec[p..p + 8]);
    p += 8;
    conn.sampled_flags = rec[p];
    p += 1;
    let n = rec[p] as usize;
    p += 1;
    // Impossible relations fail import.
    if !tcp::seq_leq(conn.snd_una, conn.snd_nxt)
        || conn.snd_nxt.wrapping_sub(conn.snd_una) > u32::from(u16::MAX) * 4
        || conn.rcv_wnd > tcp::MAX_RCV_WND
        || conn.rto < tcp::RTO_MIN
        || conn.rto > tcp::RTO_MAX
        || n > tcp::REORDER_SLOTS
    {
        return Err(sc::STATUS_CORRUPT);
    }
    let mut i = 0;
    while i < n {
        if p + 6 > rec.len() {
            return Err(sc::STATUS_CORRUPT);
        }
        let seq = rd_u32(rec, p);
        let len = rd_u16(rec, p + 4) as usize;
        p += 6;
        if len == 0 || len > tcp::REORDER_SLOT_BYTES || p + len > rec.len() {
            return Err(sc::STATUS_CORRUPT);
        }
        // Every buffered range sits ahead of the receive position and
        // inside the window.
        if !tcp::seq_lt(conn.rcv_nxt, seq)
            || !tcp::seq_leq(
                seq.wrapping_add(len as u32),
                conn.rcv_nxt.wrapping_add(u32::from(tcp::MAX_RCV_WND)),
            )
        {
            return Err(sc::STATUS_CORRUPT);
        }
        conn.reorder_slots[i].seq = seq;
        conn.reorder_slots[i].len = len as u16;
        conn.reorder_slots[i].valid = true;
        let base = i * tcp::REORDER_SLOT_BYTES;
        conn.reorder_buf[base..base + len].copy_from_slice(&rec[p..p + len]);
        p += len;
        i += 1;
    }
    if p != rec.len() {
        return Err(sc::STATUS_CORRUPT);
    }
    // Timers are stored as remaining durations until activation converts
    // them; the conversion needs the transfer age, known only then.
    conn.retransmit_timer = retx_rem;
    conn.timewait_timer = tw_rem;
    conn.idle_timer = idle_rem;
    conn.closewait_timer = cw_rem;
    Ok(())
}

/// Turn the remaining durations held in a decoded shadow into the
/// counters the sweep drives, charging `age_ticks` of transfer time
/// conservatively. Expired timers are set to fire on the next sweep.
/// Returns how many had expired.
fn convert_timers(s: &IpState, conn: &mut tcp::TcpConn, age_ticks: u16) -> u8 {
    let mut expired = 0u8;
    let retx_rem = conn.retransmit_timer.saturating_sub(age_ticks);
    if conn.snd_nxt != conn.snd_una {
        if retx_rem == 0 {
            expired += 1;
        }
        conn.retransmit_timer = conn.rto.saturating_sub(retx_rem);
    } else {
        conn.retransmit_timer = 0;
    }
    let tw_rem = conn.timewait_timer.saturating_sub(age_ticks);
    conn.timewait_timer = TIMEWAIT_TICKS.saturating_sub(tw_rem);
    if conn.idle_timer == IDLE_DISABLED || s.tcp_idle_ticks == 0 {
        conn.idle_timer = 0;
    } else {
        let rem = conn.idle_timer.saturating_sub(age_ticks);
        if rem == 0 {
            expired += 1;
        }
        conn.idle_timer = s.tcp_idle_ticks.saturating_sub(rem);
    }
    let cw_rem = conn.closewait_timer.saturating_sub(age_ticks);
    if conn.state == tcp::TcpState::CloseWait && cw_rem == 0 {
        expired += 1;
    }
    conn.closewait_timer = CLOSE_WAIT_TICKS.saturating_sub(cw_rem);
    // A closing state's wait restarts from what remains of the ceiling.
    if matches!(conn.state, tcp::TcpState::Closing | tcp::TcpState::LastAck) {
        conn.retransmit_timer = HANDSHAKE_TICKS.saturating_sub(retx_rem.max(1));
    }
    // Conservative congestion restart: the path is not proven the same.
    conn.cwnd = conn.cwnd.min(tcp::INITIAL_CWND).max(tcp::cwnd_min());
    conn.in_recovery = false;
    conn.dup_ack_count = 0;
    conn.rtt_active = false;
    expired
}

// ── Delta emission (exporter) ─────────────────────────────────────

/// Emit one delta for mirror `mi`. `false` when the channel refused it;
/// nothing is consumed then.
unsafe fn emit_delta(s: &mut IpState, mi: usize, kind: u8, body: &[u8]) -> bool {
    let (flow, epoch, gen, next_no, prev) = {
        let m = &s.cont.mirrors[mi];
        (
            m.flow_id,
            m.epoch,
            m.ckpt_gen,
            m.delta_no.wrapping_add(1),
            m.prev_digest,
        )
    };
    let mut buf = [0u8; sc::DELTA_APPLY_HEADER_LEN + 64];
    let mut p = 0usize;
    put(&mut buf, &mut p, &flow);
    put(&mut buf, &mut p, &epoch.to_le_bytes());
    put(&mut buf, &mut p, &gen.to_le_bytes());
    put(&mut buf, &mut p, &next_no.to_le_bytes());
    put(&mut buf, &mut p, &prev);
    put(&mut buf, &mut p, &[kind]);
    put(&mut buf, &mut p, body);
    if !emit_frame(s, sc::CMD_SC_DELTA_APPLY, &buf[..p]) {
        return false;
    }
    let digest = sha256(&buf[..p]);
    let m = &mut s.cont.mirrors[mi];
    m.delta_no = next_no;
    m.prev_digest = digest;
    s.cont.stats.deltas_out = s.cont.stats.deltas_out.wrapping_add(1);
    true
}

/// The acknowledgement number connection `idx` may show the peer for a
/// receive position of `rcv_nxt`: the confirmed horizon under a live
/// strict mirror, `rcv_nxt` otherwise.
pub(super) fn ack_exposed(s: &IpState, idx: usize, rcv_nxt: u32) -> u32 {
    if let Some(mi) = mirror_of_conn(s, idx) {
        let m = &s.cont.mirrors[mi];
        if m.live != 0
            && m.profile == sc::PROFILE_CRASH_CONTINUOUS
            && tcp::seq_lt(m.recv_horizon, rcv_nxt)
        {
            return m.recv_horizon;
        }
    }
    rcv_nxt
}

/// The receive window connection `idx` advertises: closed while quiescing.
pub(super) fn rcv_wnd_exposed(s: &IpState, idx: usize, wnd: u16) -> u16 {
    if let Some(mi) = mirror_of_conn(s, idx) {
        if s.cont.mirrors[mi].quiescing != 0 {
            return 0;
        }
    }
    wnd
}

/// In-order bytes were accepted on `idx`: `seq..seq+len` (and a FIN when
/// `fin`), receive position now `after`. Emits the receive delta; under
/// the strict profile the acknowledgement stays at the horizon until the
/// standby confirms.
pub(super) unsafe fn on_rx_advance(
    s: &mut IpState,
    idx: usize,
    seq: u32,
    len: u16,
    fin: bool,
    after: u32,
) {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return;
    };
    if s.cont.mirrors[mi].live == 0 {
        return;
    }
    let m = &mut s.cont.mirrors[mi];
    if m.recv_pending != 0 {
        // One receive delta may wait for the channel; a second in the
        // same window coalesces into it — the range is contiguous.
        m.recv_pending_len = m.recv_pending_len.saturating_add(len);
        m.recv_pending_fin |= fin as u8;
        m.recv_pending_after = after;
        return;
    }
    m.recv_pending = 1;
    m.recv_pending_seq = seq;
    m.recv_pending_len = len;
    m.recv_pending_fin = fin as u8;
    m.recv_pending_after = after;
    flush_recv_delta(s, mi);
}

unsafe fn flush_recv_delta(s: &mut IpState, mi: usize) {
    let (seq, len, fin, after, strict) = {
        let m = &s.cont.mirrors[mi];
        if m.recv_pending == 0 {
            return;
        }
        (
            m.recv_pending_seq,
            m.recv_pending_len,
            m.recv_pending_fin,
            m.recv_pending_after,
            m.profile == sc::PROFILE_CRASH_CONTINUOUS,
        )
    };
    if strict && s.cont.mirrors[mi].recv_ring_len as usize >= RECV_RING {
        // The standby is behind; the horizon holds until it catches up.
        s.cont.stats.horizon_waits = s.cont.stats.horizon_waits.wrapping_add(1);
        return;
    }
    let mut body = [0u8; 11];
    body[..4].copy_from_slice(&seq.to_le_bytes());
    body[4..6].copy_from_slice(&len.to_le_bytes());
    body[6..10].copy_from_slice(&after.to_le_bytes());
    body[10] = fin;
    if !emit_delta(s, mi, sc::DELTA_TCP_RECV, &body) {
        return;
    }
    let m = &mut s.cont.mirrors[mi];
    m.recv_pending = 0;
    if strict {
        let n = m.recv_ring_len as usize;
        m.recv_ring[n] = [m.delta_no, after];
        m.recv_ring_len += 1;
    }
}

/// May `len` bytes at `seq` be handed to the wire on `idx` now? Under a
/// live strict mirror the send delta goes first and the segment waits
/// for its acknowledgement; the caller retries next step.
pub(super) unsafe fn send_gate(s: &mut IpState, idx: usize, seq: u32, len: u16) -> bool {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return true;
    };
    {
        let m = &s.cont.mirrors[mi];
        if m.live == 0 || m.profile != sc::PROFILE_CRASH_CONTINUOUS {
            return true;
        }
        if m.gate_kind == GATE_SEND && m.gate_seq == seq && m.gate_len == len {
            return m.gate_open != 0;
        }
        if m.gate_kind != GATE_NONE {
            // A different transition is already waiting.
            return false;
        }
    }
    let mut body = [0u8; 7];
    body[..4].copy_from_slice(&seq.to_le_bytes());
    body[4..6].copy_from_slice(&len.to_le_bytes());
    body[6] = 0;
    if !emit_delta(s, mi, sc::DELTA_TCP_SEND, &body) {
        return false;
    }
    let m = &mut s.cont.mirrors[mi];
    m.gate_kind = GATE_SEND;
    m.gate_seq = seq;
    m.gate_len = len;
    m.gate_delta = m.delta_no;
    m.gate_open = 0;
    s.cont.stats.horizon_waits = s.cont.stats.horizon_waits.wrapping_add(1);
    false
}

/// Bytes at `seq` were handed to the wire on `idx`. Clears a strict gate;
/// under the planned profile this is where the send delta is emitted.
pub(super) unsafe fn on_sent(s: &mut IpState, idx: usize, seq: u32, len: u16, fin: bool) {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return;
    };
    let (live, strict, gated) = {
        let m = &s.cont.mirrors[mi];
        (
            m.live != 0,
            m.profile == sc::PROFILE_CRASH_CONTINUOUS,
            m.gate_kind != GATE_NONE && m.gate_seq == seq,
        )
    };
    if !live {
        return;
    }
    if strict {
        if gated {
            let m = &mut s.cont.mirrors[mi];
            m.gate_kind = GATE_NONE;
            m.gate_open = 0;
        }
        return;
    }
    let mut body = [0u8; 7];
    body[..4].copy_from_slice(&seq.to_le_bytes());
    body[4..6].copy_from_slice(&len.to_le_bytes());
    body[6] = fin as u8;
    if !emit_delta(s, mi, sc::DELTA_TCP_SEND, &body) {
        let m = &mut s.cont.mirrors[mi];
        m.deltas_dropped = m.deltas_dropped.wrapping_add(1);
        s.cont.stats.deltas_dropped = s.cont.stats.deltas_dropped.wrapping_add(1);
    }
}

/// May a FIN be sent on `idx` now? As `send_gate`, for the FIN byte.
pub(super) unsafe fn fin_gate(s: &mut IpState, idx: usize) -> bool {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return true;
    };
    let seq = (*s.tcp_conns.as_ptr().add(idx)).snd_nxt;
    {
        let m = &s.cont.mirrors[mi];
        if m.live == 0 || m.profile != sc::PROFILE_CRASH_CONTINUOUS {
            return true;
        }
        if m.gate_kind == GATE_FIN && m.gate_seq == seq {
            return m.gate_open != 0;
        }
        if m.gate_kind != GATE_NONE {
            return false;
        }
    }
    let mut body = [0u8; 7];
    body[..4].copy_from_slice(&seq.to_le_bytes());
    body[6] = 1;
    if !emit_delta(s, mi, sc::DELTA_TCP_SEND, &body) {
        return false;
    }
    let m = &mut s.cont.mirrors[mi];
    m.gate_kind = GATE_FIN;
    m.gate_seq = seq;
    m.gate_len = 0;
    m.gate_delta = m.delta_no;
    m.gate_open = 0;
    s.cont.stats.horizon_waits = s.cont.stats.horizon_waits.wrapping_add(1);
    false
}

/// The peer acknowledged up to `snd_una` on `idx`: send-side reclaim.
pub(super) unsafe fn on_acked(s: &mut IpState, idx: usize) {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return;
    };
    if s.cont.mirrors[mi].live == 0 {
        return;
    }
    let c = &*s.tcp_conns.as_ptr().add(idx);
    let mut body = [0u8; 10];
    body[..4].copy_from_slice(&c.snd_una.to_le_bytes());
    body[4..6].copy_from_slice(&c.snd_wnd.to_le_bytes());
    body[6..8].copy_from_slice(&c.cwnd.to_le_bytes());
    body[8..10].copy_from_slice(&c.ssthresh.to_le_bytes());
    if !emit_delta(s, mi, sc::DELTA_TCP_ACKED, &body) {
        s.cont.mirrors[mi].deltas_dropped = s.cont.mirrors[mi].deltas_dropped.wrapping_add(1);
        s.cont.stats.deltas_dropped = s.cont.stats.deltas_dropped.wrapping_add(1);
    }
}

/// Connection `idx` changed state or timers without bytes moving.
pub(super) unsafe fn on_state(s: &mut IpState, idx: usize) {
    let Some(mi) = mirror_of_conn(s, idx) else {
        return;
    };
    if s.cont.mirrors[mi].live == 0 {
        return;
    }
    let c = &*s.tcp_conns.as_ptr().add(idx);
    let mut body = [0u8; 11];
    body[0] = state_code(c.state);
    body[1..3].copy_from_slice(&c.rto.to_le_bytes());
    body[3..5].copy_from_slice(&c.srtt.to_le_bytes());
    body[5..7].copy_from_slice(&c.rttvar.to_le_bytes());
    body[7..9].copy_from_slice(&c.cwnd.to_le_bytes());
    body[9..11].copy_from_slice(&c.ssthresh.to_le_bytes());
    if !emit_delta(s, mi, sc::DELTA_TCP_TIMERS, &body) {
        s.cont.mirrors[mi].deltas_dropped = s.cont.mirrors[mi].deltas_dropped.wrapping_add(1);
        s.cont.stats.deltas_dropped = s.cont.stats.deltas_dropped.wrapping_add(1);
    }
}

/// Connection slot `idx` is being released: forget any mirror or shadow
/// reservation on it.
pub(super) fn on_conn_released(s: &mut IpState, idx: usize) {
    let mut i = 0;
    while i < MAX_TCP_SHADOWS {
        if s.cont.mirrors[i].in_use != 0 && s.cont.mirrors[i].conn_idx as usize == idx {
            s.cont.mirrors[i].clear();
        }
        if s.cont.shadows[i].in_use != 0 && s.cont.shadows[i].conn_idx as usize == idx {
            s.cont.shadows[i].conn_idx = u32::MAX;
        }
        i += 1;
    }
}

/// Whether `idx` is quiescing (new application delivery refused).
pub(super) fn quiescing(s: &IpState, idx: usize) -> bool {
    match mirror_of_conn(s, idx) {
        Some(mi) => s.cont.mirrors[mi].quiescing != 0,
        None => false,
    }
}

/// Whether the mirror has nothing in flight for its connection.
unsafe fn mirror_drained(s: &IpState, mi: usize) -> bool {
    let m = &s.cont.mirrors[mi];
    let idx = m.conn_idx as usize;
    let stashed = s.pending_cmd_valid != 0 && s.pending_cmd_conn as usize == idx;
    let closing = s.pending_close_valid != 0 && s.pending_close_conn as usize == idx;
    !stashed && !closing && s.pending_tx_len == 0 && m.gate_kind == GATE_NONE && m.recv_pending == 0
}

// ── Command service ───────────────────────────────────────────────

/// Read and answer continuity commands, bounded per step.
pub(super) unsafe fn service(s: &mut IpState) {
    if s.cont.in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut count = 0;
    while count < MAX_TCP_SHADOWS * 4 {
        if !flush_reply(s) {
            return;
        }
        let mut buf = [0u8; sc::DELTA_APPLY_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX];
        let (msg_type, plen) = ip_net_read_frame(sys, s.cont.in_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 {
            break;
        }
        let plen = plen as usize;
        if plen < sc::FLOW_HEADER_LEN {
            count += 1;
            continue;
        }
        let mut flow = [0u8; 16];
        flow.copy_from_slice(&buf[..16]);
        let epoch = rd_u32(&buf, 16);
        let p = &buf[..plen];
        match msg_type {
            sc::CMD_SC_PAIR_PREPARE if plen >= sc::PAIR_PREPARE_PAYLOAD_LEN => {
                cmd_pair_prepare(s, &flow, epoch, p);
            }
            sc::CMD_SC_CHECKPOINT_BEGIN if plen >= sc::CHECKPOINT_BEGIN_PAYLOAD_LEN => {
                cmd_checkpoint_begin(s, &flow, epoch, p);
            }
            sc::CMD_SC_CHECKPOINT_NEXT if plen >= sc::CHECKPOINT_NEXT_HEADER_LEN => {
                cmd_checkpoint_next(s, &flow, epoch, p);
            }
            sc::CMD_SC_CHECKPOINT_COMMIT if plen >= sc::CHECKPOINT_COMMIT_PAYLOAD_LEN => {
                cmd_checkpoint_commit(s, &flow, epoch, p);
            }
            sc::CMD_SC_DELTA_APPLY if plen >= sc::DELTA_APPLY_HEADER_LEN => {
                cmd_delta_apply(s, &flow, epoch, p);
            }
            sc::CMD_SC_DELTA_ACK if plen >= sc::DELTA_ACK_PAYLOAD_LEN => {
                cmd_delta_ack(s, &flow, epoch, p);
            }
            sc::CMD_SC_QUIESCE_BEGIN if plen >= sc::QUIESCE_BEGIN_PAYLOAD_LEN => {
                cmd_quiesce_begin(s, &flow, epoch, p);
            }
            sc::CMD_SC_QUIESCE_STATUS => cmd_quiesce_status(s, &flow, epoch),
            sc::CMD_SC_CUT_EXPORT => cmd_cut_export(s, &flow, epoch),
            sc::CMD_SC_CUT_IMPORT if plen >= sc::CUT_IMPORT_PAYLOAD_LEN => {
                cmd_cut_import(s, &flow, epoch, p);
            }
            sc::CMD_SC_EMISSION_ARM => cmd_emission_arm(s, &flow, epoch),
            sc::CMD_SC_ACTIVATE if plen >= sc::ACTIVATE_PAYLOAD_LEN => {
                cmd_activate(s, &flow, epoch, p);
            }
            sc::CMD_SC_RETIRE => cmd_retire(s, &flow, epoch),
            sc::CMD_SC_ABORT if plen >= sc::ABORT_PAYLOAD_LEN => cmd_abort(s, &flow, epoch, p),
            sc::MSG_SC_CONTINUITY if plen >= sc::CONTINUITY_HEADER_LEN => {
                // A relayed standby reply: the exporter learns its
                // checkpoint is held.
                if p[20] == sc::CR_CHECKPOINT_COMMITTED && p[21] == sc::STATUS_OK {
                    if let Some(mi) = find_mirror(s, &flow) {
                        if s.cont.mirrors[mi].epoch == epoch {
                            s.cont.mirrors[mi].live = 1;
                        }
                    }
                }
            }
            _ => {}
        }
        count += 1;
    }
}

/// Per-step continuation: pending reply, an export in progress, pending
/// receive deltas, quiesce deadlines.
pub(super) unsafe fn step(s: &mut IpState) {
    if s.cont.out_chan < 0 {
        return;
    }
    let _ = flush_reply(s);
    let mut mi = 0;
    while mi < MAX_TCP_SHADOWS {
        if s.cont.mirrors[mi].in_use != 0 {
            if s.cont.mirrors[mi].export_active != 0 {
                continue_export(s, mi);
            }
            if s.cont.mirrors[mi].recv_pending != 0 {
                flush_recv_delta(s, mi);
            }
            if s.cont.mirrors[mi].quiescing != 0 {
                let now = dev_millis(&*s.syscalls) as u32;
                let deadline = s.cont.mirrors[mi].quiesce_deadline_ms;
                if deadline != 0
                    && now.wrapping_sub(deadline) < 0x8000_0000
                    && !mirror_drained(s, mi)
                {
                    // Past the deadline and still not drained: the cut
                    // cannot be exact, so the coordinator is told.
                    let (flow, epoch) = (s.cont.mirrors[mi].flow_id, s.cont.mirrors[mi].epoch);
                    if s.cont.reply_len == 0 {
                        reply(
                            s,
                            &flow,
                            epoch,
                            sc::CR_QUIESCED,
                            sc::STATUS_NOT_READY,
                            &[0, 0, 0, 0, 0, 0, 0, 0, 0],
                        );
                        s.cont.mirrors[mi].quiesce_deadline_ms = 0;
                    }
                }
            }
        }
        mi += 1;
    }
}

unsafe fn cmd_pair_prepare(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let transport = p[20];
    let profile = p[21];
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&p[22..54]);
    if transport != sc::CT_TCP || digest != codec_digest() {
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_CORRUPT,
            &[transport, profile, 0, 0],
        );
        return;
    }
    if profile != sc::PROFILE_PLANNED && profile != sc::PROFILE_CRASH_CONTINUOUS {
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_CORRUPT,
            &[transport, profile, 0, 0],
        );
        return;
    }
    // A flow this module owns live prepares to export; any other prepares
    // a shadow to import.
    if let Some(idx) = conn_of_flow(s, flow) {
        if let Some(mi) = find_mirror(s, flow) {
            let m = &s.cont.mirrors[mi];
            if m.epoch > epoch {
                reply(
                    s,
                    flow,
                    epoch,
                    sc::CR_PAIR_PREPARED,
                    sc::STATUS_STALE_EPOCH,
                    &[transport, profile, 0, 0],
                );
                return;
            }
            // Idempotent re-prepare.
            let slot = (mi as u16).to_le_bytes();
            reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_OK,
                &[transport, profile, slot[0], slot[1]],
            );
            return;
        }
        let Some(mi) = free_mirror(s) else {
            reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_NO_CAPACITY,
                &[transport, profile, 0, 0],
            );
            return;
        };
        let state = (*s.tcp_conns.as_ptr().add(idx)).state;
        if !state_exportable(state) {
            reply(
                s,
                flow,
                epoch,
                sc::CR_ABORTED,
                sc::STATUS_NOT_READY,
                &[sc::ABORT_UNSUPPORTED_STATE],
            );
            return;
        }
        let rcv_nxt = (*s.tcp_conns.as_ptr().add(idx)).rcv_nxt;
        s.cont.mirrors[mi].clear();
        let m = &mut s.cont.mirrors[mi];
        m.in_use = 1;
        m.profile = profile;
        m.flow_id = *flow;
        m.epoch = epoch;
        m.conn_idx = idx as u32;
        m.recv_horizon = rcv_nxt;
        let slot = (mi as u16).to_le_bytes();
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_OK,
            &[transport, profile, slot[0], slot[1]],
        );
        return;
    }
    if let Some(si) = find_shadow(s, flow) {
        let sh = &s.cont.shadows[si];
        if sh.epoch > epoch {
            reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_STALE_EPOCH,
                &[transport, profile, 0, 0],
            );
            return;
        }
        let slot = (si as u16).to_le_bytes();
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_OK,
            &[transport, profile, slot[0], slot[1]],
        );
        return;
    }
    let Some(si) = free_shadow(s) else {
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_NO_CAPACITY,
            &[transport, profile, 0, 0],
        );
        return;
    };
    // Reserve the connection slot now, so activation cannot fail for
    // want of one.
    let Some(idx) = alloc_free_slot(s) else {
        reply(
            s,
            flow,
            epoch,
            sc::CR_PAIR_PREPARED,
            sc::STATUS_NO_CAPACITY,
            &[transport, profile, 0, 0],
        );
        return;
    };
    (*s.tcp_conns.as_mut_ptr().add(idx)).pending_close_notify = NOTIFY_SHADOW_RESERVED;
    s.cont.shadows[si].clear();
    let sh = &mut s.cont.shadows[si];
    sh.in_use = 1;
    sh.phase = SH_PREPARED;
    sh.profile = profile;
    sh.flow_id = *flow;
    sh.epoch = epoch;
    sh.conn_idx = idx as u32;
    let slot = (si as u16).to_le_bytes();
    reply(
        s,
        flow,
        epoch,
        sc::CR_PAIR_PREPARED,
        sc::STATUS_OK,
        &[transport, profile, slot[0], slot[1]],
    );
}

/// The shadow for a flow at `epoch`, or the refusal to answer with.
fn shadow_for(s: &IpState, flow: &[u8; 16], epoch: u32) -> Result<usize, u8> {
    let si = find_shadow(s, flow).ok_or(sc::STATUS_UNKNOWN_SESSION)?;
    let sh = &s.cont.shadows[si];
    if epoch < sh.epoch {
        return Err(sc::STATUS_STALE_EPOCH);
    }
    if epoch > sh.epoch {
        return Err(sc::STATUS_STALE_EPOCH);
    }
    Ok(si)
}

fn mirror_for(s: &IpState, flow: &[u8; 16], epoch: u32) -> Result<usize, u8> {
    let mi = find_mirror(s, flow).ok_or(sc::STATUS_UNKNOWN_SESSION)?;
    if epoch != s.cont.mirrors[mi].epoch {
        return Err(sc::STATUS_STALE_EPOCH);
    }
    Ok(mi)
}

unsafe fn discard_shadow(s: &mut IpState, si: usize) {
    let idx = s.cont.shadows[si].conn_idx;
    if (idx as usize) < tcp::MAX_TCP_CONNS {
        let c = &mut *s.tcp_conns.as_mut_ptr().add(idx as usize);
        if c.pending_close_notify == NOTIFY_SHADOW_RESERVED {
            c.pending_close_notify = NOTIFY_NONE;
        }
    }
    s.cont.shadows[si].clear();
}

unsafe fn cmd_checkpoint_begin(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let total = rd_u32(p, 24);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&p[28..60]);
    let body_gen = gen.to_le_bytes();
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_ACK,
                st,
                &[
                    body_gen[0],
                    body_gen[1],
                    body_gen[2],
                    body_gen[3],
                    0,
                    0,
                    0,
                    0,
                ],
            );
            return;
        }
    };
    let sh = &mut s.cont.shadows[si];
    if sh.phase >= SH_COMMITTED && gen <= sh.ckpt_gen {
        // Already held: idempotent.
        let off = sh.record_len.to_le_bytes();
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_OK,
            &[
                body_gen[0],
                body_gen[1],
                body_gen[2],
                body_gen[3],
                off[0],
                off[1],
                off[2],
                off[3],
            ],
        );
        return;
    }
    if sh.phase == SH_RECEIVING && gen < sh.ckpt_gen {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_STALE_EPOCH,
            &[
                body_gen[0],
                body_gen[1],
                body_gen[2],
                body_gen[3],
                0,
                0,
                0,
                0,
            ],
        );
        return;
    }
    if total as usize > TCP_RECORD_MAX || total < REC_FIXED_LEN as u32 {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_NO_CAPACITY,
            &[
                body_gen[0],
                body_gen[1],
                body_gen[2],
                body_gen[3],
                0,
                0,
                0,
                0,
            ],
        );
        return;
    }
    sh.import.reset();
    let st = sh.import.begin(total, TCP_RECORD_MAX as u32);
    if st != HANDOFF_OK {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            st,
            &[
                body_gen[0],
                body_gen[1],
                body_gen[2],
                body_gen[3],
                0,
                0,
                0,
                0,
            ],
        );
        return;
    }
    sh.phase = SH_RECEIVING;
    sh.ckpt_gen = gen;
    sh.record_len = total;
    sh.record_digest = digest;
    sh.delta_no = 0;
    sh.last_delta_digest = [0; 32];
    reply(
        s,
        flow,
        epoch,
        sc::CR_CHECKPOINT_ACK,
        sc::STATUS_OK,
        &[
            body_gen[0],
            body_gen[1],
            body_gen[2],
            body_gen[3],
            0,
            0,
            0,
            0,
        ],
    );
}

unsafe fn cmd_checkpoint_next(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let off = rd_u32(p, 24);
    let data = &p[sc::CHECKPOINT_NEXT_HEADER_LEN..];
    let bg = gen.to_le_bytes();
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_ACK,
                st,
                &[bg[0], bg[1], bg[2], bg[3], 0, 0, 0, 0],
            );
            return;
        }
    };
    let sh = &mut s.cont.shadows[si];
    if sh.phase != SH_RECEIVING || gen != sh.ckpt_gen {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_NOT_READY,
            &[bg[0], bg[1], bg[2], bg[3], 0, 0, 0, 0],
        );
        return;
    }
    // A retried chunk (offset already covered, same bytes) is accepted.
    if off < sh.import.received() {
        let end = off as usize + data.len();
        if end <= sh.import.received() as usize && sh.record[off as usize..end] == *data {
            let r = sh.import.received().to_le_bytes();
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_ACK,
                sc::STATUS_OK,
                &[bg[0], bg[1], bg[2], bg[3], r[0], r[1], r[2], r[3]],
            );
            return;
        }
    }
    let st = sh.import.chunk(off, data, &mut sh.record);
    if st != HANDOFF_OK {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_CORRUPT,
            &[bg[0], bg[1], bg[2], bg[3], 0, 0, 0, 0],
        );
        discard_shadow_to_prepared(s, si);
        return;
    }
    let r = sh.import.received().to_le_bytes();
    reply(
        s,
        flow,
        epoch,
        sc::CR_CHECKPOINT_ACK,
        sc::STATUS_OK,
        &[bg[0], bg[1], bg[2], bg[3], r[0], r[1], r[2], r[3]],
    );
}

/// A failed transfer returns the shadow to PREPARED with its slot kept.
fn discard_shadow_to_prepared(s: &mut IpState, si: usize) {
    let sh = &mut s.cont.shadows[si];
    sh.phase = SH_PREPARED;
    sh.import.reset();
    sh.record_len = 0;
    sh.delta_no = 0;
}

unsafe fn cmd_checkpoint_commit(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let crc = rd_u32(p, 24);
    let bg = gen.to_le_bytes();
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                st,
                &[bg[0], bg[1], bg[2], bg[3]],
            );
            return;
        }
    };
    {
        let sh = &s.cont.shadows[si];
        if sh.phase >= SH_COMMITTED && gen == sh.ckpt_gen {
            let mut body = [0u8; 36];
            body[..4].copy_from_slice(&bg);
            body[4..].copy_from_slice(&sh.record_digest);
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                sc::STATUS_OK,
                &body,
            );
            return;
        }
        if sh.phase != SH_RECEIVING || gen != sh.ckpt_gen {
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                sc::STATUS_NOT_READY,
                &[bg[0], bg[1], bg[2], bg[3]],
            );
            return;
        }
    }
    let ok = {
        let sh = &mut s.cont.shadows[si];
        let st = sh.import.end(crc);
        let len = sh.record_len as usize;
        st == HANDOFF_OK && sha256(&sh.record[..len]) == sh.record_digest
    };
    if !ok {
        reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_CORRUPT,
            &[bg[0], bg[1], bg[2], bg[3]],
        );
        discard_shadow_to_prepared(s, si);
        return;
    }
    let mut conn = tcp::TcpConn::new();
    let decoded = {
        let sh = &s.cont.shadows[si];
        let len = sh.record_len as usize;
        decode_record(s, &sh.record[..len], &mut conn)
    };
    match decoded {
        Ok(()) => {
            // The tuple must not already be live here.
            let live = find_conn_indexed(
                s,
                conn.remote_ip,
                conn.remote_port,
                conn.local_port,
                conn.local_slot,
            );
            if live.is_some() {
                reply(
                    s,
                    flow,
                    epoch,
                    sc::CR_CHECKPOINT_COMMITTED,
                    sc::STATUS_NOT_READY,
                    &[bg[0], bg[1], bg[2], bg[3]],
                );
                discard_shadow_to_prepared(s, si);
                return;
            }
            let sh = &mut s.cont.shadows[si];
            sh.conn = conn;
            sh.phase = SH_COMMITTED;
            let mut body = [0u8; 36];
            body[..4].copy_from_slice(&bg);
            body[4..].copy_from_slice(&sh.record_digest);
            s.cont.stats.checkpoints_in = s.cont.stats.checkpoints_in.wrapping_add(1);
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                sc::STATUS_OK,
                &body,
            );
        }
        Err(st) => {
            reply(
                s,
                flow,
                epoch,
                sc::CR_CHECKPOINT_COMMITTED,
                st,
                &[bg[0], bg[1], bg[2], bg[3]],
            );
            discard_shadow_to_prepared(s, si);
        }
    }
}

unsafe fn cmd_delta_apply(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let no = rd_u32(p, 24);
    let mut prev = [0u8; 32];
    prev.copy_from_slice(&p[28..60]);
    let kind = p[60];
    let body = &p[sc::DELTA_APPLY_HEADER_LEN..];
    let mut ack = [0u8; 8];
    ack[..4].copy_from_slice(&gen.to_le_bytes());
    ack[4..].copy_from_slice(&no.to_le_bytes());
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_DELTA_APPLIED, st, &ack);
            return;
        }
    };
    let digest = sha256(p);
    {
        let sh = &s.cont.shadows[si];
        if sh.phase < SH_COMMITTED || gen != sh.ckpt_gen {
            reply(
                s,
                flow,
                epoch,
                sc::CR_DELTA_APPLIED,
                sc::STATUS_NOT_READY,
                &ack,
            );
            return;
        }
        if no == sh.delta_no && no != 0 {
            // A retry of the delta just applied is idempotent only if it
            // is the same delta.
            let st = if digest == sh.last_delta_digest {
                sc::STATUS_OK
            } else {
                sc::STATUS_CORRUPT
            };
            reply(s, flow, epoch, sc::CR_DELTA_APPLIED, st, &ack);
            return;
        }
        if no != sh.delta_no.wrapping_add(1) || prev != sh.last_delta_digest {
            reply(
                s,
                flow,
                epoch,
                sc::CR_DELTA_APPLIED,
                sc::STATUS_CORRUPT,
                &ack,
            );
            return;
        }
    }
    let applied = {
        let sh = &mut s.cont.shadows[si];
        apply_delta(&mut sh.conn, kind, body)
    };
    if !applied {
        reply(
            s,
            flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_CORRUPT,
            &ack,
        );
        return;
    }
    let sh = &mut s.cont.shadows[si];
    sh.delta_no = no;
    sh.last_delta_digest = digest;
    s.cont.stats.deltas_in = s.cont.stats.deltas_in.wrapping_add(1);
    reply(s, flow, epoch, sc::CR_DELTA_APPLIED, sc::STATUS_OK, &ack);
}

fn apply_delta(c: &mut tcp::TcpConn, kind: u8, body: &[u8]) -> bool {
    match kind {
        sc::DELTA_TCP_SEND if body.len() >= 7 => {
            let seq = rd_u32(body, 0);
            let len = u32::from(rd_u16(body, 4));
            let fin = body[6] != 0;
            if seq != c.snd_nxt {
                return false;
            }
            c.snd_nxt = seq.wrapping_add(len).wrapping_add(fin as u32);
            if fin {
                c.state = match c.state {
                    tcp::TcpState::Established => tcp::TcpState::FinWait1,
                    tcp::TcpState::CloseWait => tcp::TcpState::LastAck,
                    st => st,
                };
            }
            true
        }
        sc::DELTA_TCP_RECV if body.len() >= 11 => {
            let seq = rd_u32(body, 0);
            let after = rd_u32(body, 6);
            let fin = body[10] != 0;
            if seq != c.rcv_nxt || !tcp::seq_leq(seq, after) {
                return false;
            }
            c.rcv_nxt = after;
            if fin && c.state == tcp::TcpState::Established {
                c.state = tcp::TcpState::CloseWait;
            }
            // Bytes the primary delivered are behind the receive position;
            // any buffered range now covered is dropped.
            let mut i = 0;
            while i < tcp::REORDER_SLOTS {
                if c.reorder_slots[i].valid && !tcp::seq_lt(c.rcv_nxt, c.reorder_slots[i].seq) {
                    c.reorder_slots[i].len = 0;
                    c.reorder_slots[i].valid = false;
                }
                i += 1;
            }
            true
        }
        sc::DELTA_TCP_ACKED if body.len() >= 10 => {
            let una = rd_u32(body, 0);
            if !tcp::seq_leq(c.snd_una, una) || !tcp::seq_leq(una, c.snd_nxt) {
                return false;
            }
            c.snd_una = una;
            c.snd_wnd = rd_u16(body, 4);
            c.cwnd = rd_u16(body, 6);
            c.ssthresh = rd_u16(body, 8);
            true
        }
        sc::DELTA_TCP_TIMERS if body.len() >= 11 => {
            let Some(st) = state_of_code(body[0]) else {
                return false;
            };
            c.state = st;
            c.rto = rd_u16(body, 1);
            c.srtt = rd_u16(body, 3);
            c.rttvar = rd_u16(body, 5);
            c.cwnd = rd_u16(body, 7);
            c.ssthresh = rd_u16(body, 9);
            true
        }
        _ => false,
    }
}

unsafe fn cmd_delta_ack(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let no = rd_u32(p, 24);
    let Ok(mi) = mirror_for(s, flow, epoch) else {
        return;
    };
    if s.cont.mirrors[mi].ckpt_gen != gen {
        return;
    }
    let mut ack_moved = false;
    let idx;
    {
        let m = &mut s.cont.mirrors[mi];
        idx = m.conn_idx as usize;
        if m.gate_kind != GATE_NONE && m.gate_delta != 0 && no >= m.gate_delta {
            m.gate_open = 1;
        }
        // Cumulative: every receive delta at or below `no` is confirmed.
        let mut kept = 0usize;
        let mut i = 0;
        while i < m.recv_ring_len as usize {
            let [d, after] = m.recv_ring[i];
            if d <= no {
                m.recv_horizon = after;
                ack_moved = true;
            } else {
                m.recv_ring[kept] = [d, after];
                kept += 1;
            }
            i += 1;
        }
        m.recv_ring_len = kept as u8;
    }
    if ack_moved && idx < tcp::MAX_TCP_CONNS {
        // The horizon moved: show the peer the acknowledgement it earns.
        send_tcp_control(s, idx, tcp::ACK, false);
    }
    if s.cont.mirrors[mi].recv_pending != 0 {
        flush_recv_delta(s, mi);
    }
}

unsafe fn cmd_quiesce_begin(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let deadline = rd_u32(p, 20);
    let mi = match mirror_for(s, flow, epoch) {
        Ok(mi) => mi,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_QUIESCED, st, &[0; 9]);
            return;
        }
    };
    let idx = s.cont.mirrors[mi].conn_idx as usize;
    let now = dev_millis(&*s.syscalls) as u32;
    let m = &mut s.cont.mirrors[mi];
    m.quiescing = 1;
    m.quiesce_deadline_ms = now.wrapping_add(deadline).max(1);
    // Close the receive window so the peer stops sending into the cut.
    (*s.tcp_conns.as_mut_ptr().add(idx)).rcv_wnd = 0;
    send_tcp_control(s, idx, tcp::ACK, false);
    quiesce_reply(s, mi);
}

unsafe fn quiesce_reply(s: &mut IpState, mi: usize) {
    let (flow, epoch) = (s.cont.mirrors[mi].flow_id, s.cont.mirrors[mi].epoch);
    let drained = mirror_drained(s, mi);
    let idx = s.cont.mirrors[mi].conn_idx as usize;
    let c = &*s.tcp_conns.as_ptr().add(idx);
    let pending_out = c.snd_nxt.wrapping_sub(c.snd_una);
    let pending_in = if s.pending_cmd_valid != 0 && s.pending_cmd_conn as usize == idx {
        u32::from(s.pending_cmd_len)
    } else {
        0
    };
    let mut body = [0u8; 9];
    body[0] = drained as u8;
    body[1..5].copy_from_slice(&pending_out.to_le_bytes());
    body[5..9].copy_from_slice(&pending_in.to_le_bytes());
    reply(s, &flow, epoch, sc::CR_QUIESCED, sc::STATUS_OK, &body);
}

unsafe fn cmd_quiesce_status(s: &mut IpState, flow: &[u8; 16], epoch: u32) {
    match mirror_for(s, flow, epoch) {
        Ok(mi) => quiesce_reply(s, mi),
        Err(st) => reply(s, flow, epoch, sc::CR_QUIESCED, st, &[0; 9]),
    }
}

unsafe fn cmd_cut_export(s: &mut IpState, flow: &[u8; 16], epoch: u32) {
    let mi = match mirror_for(s, flow, epoch) {
        Ok(mi) => mi,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_CUT, st, &[0; 4]);
            return;
        }
    };
    let idx = s.cont.mirrors[mi].conn_idx as usize;
    let state = (*s.tcp_conns.as_ptr().add(idx)).state;
    if !state_exportable(state) {
        reply(
            s,
            flow,
            epoch,
            sc::CR_ABORTED,
            sc::STATUS_NOT_READY,
            &[sc::ABORT_UNSUPPORTED_STATE],
        );
        return;
    }
    if s.cont.mirrors[mi].export_active != 0 {
        // Still emitting the previous cut.
        reply(s, flow, epoch, sc::CR_CUT, sc::STATUS_NOT_READY, &[0; 4]);
        return;
    }
    let mut buf = [0u8; TCP_RECORD_MAX];
    let len = encode_record(s, idx, &mut buf);
    let digest = sha256(&buf[..len]);
    let m = &mut s.cont.mirrors[mi];
    m.ckpt_gen = m.ckpt_gen.wrapping_add(1);
    m.delta_no = 0;
    m.prev_digest = [0; 32];
    m.live = 0;
    m.gate_kind = GATE_NONE;
    m.recv_ring_len = 0;
    m.recv_pending = 0;
    m.export_buf[..len].copy_from_slice(&buf[..len]);
    m.export_len = len as u32;
    m.export_off = 0;
    m.export_digest = digest;
    m.export_active = 1;
    m.recv_horizon = (*s.tcp_conns.as_ptr().add(idx)).rcv_nxt;
    // BEGIN goes out now; chunks and COMMIT follow as the channel admits.
    let (gen, flow_id) = (s.cont.mirrors[mi].ckpt_gen, s.cont.mirrors[mi].flow_id);
    let mut hdr = [0u8; sc::CHECKPOINT_BEGIN_PAYLOAD_LEN];
    let mut q = 0usize;
    put(&mut hdr, &mut q, &flow_id);
    put(&mut hdr, &mut q, &epoch.to_le_bytes());
    put(&mut hdr, &mut q, &gen.to_le_bytes());
    put(&mut hdr, &mut q, &(len as u32).to_le_bytes());
    put(&mut hdr, &mut q, &digest);
    if emit_frame(s, sc::CMD_SC_CHECKPOINT_BEGIN, &hdr) {
        s.cont.mirrors[mi].export_active = 2;
        continue_export(s, mi);
    }
}

/// Export phases: 1 = BEGIN owed, 2 = chunks in progress, 3 = COMMIT
/// owed, 4 = CUT manifest owed.
unsafe fn continue_export(s: &mut IpState, mi: usize) {
    let (flow, epoch, gen) = {
        let m = &s.cont.mirrors[mi];
        (m.flow_id, m.epoch, m.ckpt_gen)
    };
    if s.cont.mirrors[mi].export_active == 1 {
        let (len, digest) = (
            s.cont.mirrors[mi].export_len,
            s.cont.mirrors[mi].export_digest,
        );
        let mut hdr = [0u8; sc::CHECKPOINT_BEGIN_PAYLOAD_LEN];
        let mut q = 0usize;
        put(&mut hdr, &mut q, &flow);
        put(&mut hdr, &mut q, &epoch.to_le_bytes());
        put(&mut hdr, &mut q, &gen.to_le_bytes());
        put(&mut hdr, &mut q, &len.to_le_bytes());
        put(&mut hdr, &mut q, &digest);
        if !emit_frame(s, sc::CMD_SC_CHECKPOINT_BEGIN, &hdr) {
            return;
        }
        s.cont.mirrors[mi].export_active = 2;
    }
    if s.cont.mirrors[mi].export_active == 2 {
        loop {
            let (off, len) = (
                s.cont.mirrors[mi].export_off as usize,
                s.cont.mirrors[mi].export_len as usize,
            );
            if off >= len {
                s.cont.mirrors[mi].export_active = 3;
                break;
            }
            let n = (len - off).min(sc::CHECKPOINT_CHUNK_MAX);
            let mut frame = [0u8; sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX];
            let mut q = 0usize;
            put(&mut frame, &mut q, &flow);
            put(&mut frame, &mut q, &epoch.to_le_bytes());
            put(&mut frame, &mut q, &gen.to_le_bytes());
            put(&mut frame, &mut q, &(off as u32).to_le_bytes());
            let chunk = &s.cont.mirrors[mi].export_buf[off..off + n];
            frame[q..q + n].copy_from_slice(chunk);
            q += n;
            if !emit_frame(s, sc::CMD_SC_CHECKPOINT_NEXT, &frame[..q]) {
                return;
            }
            s.cont.mirrors[mi].export_off = (off + n) as u32;
        }
    }
    if s.cont.mirrors[mi].export_active == 3 {
        let len = s.cont.mirrors[mi].export_len as usize;
        let crc = handoff_crc32(&s.cont.mirrors[mi].export_buf[..len]);
        let mut frame = [0u8; sc::CHECKPOINT_COMMIT_PAYLOAD_LEN];
        let mut q = 0usize;
        put(&mut frame, &mut q, &flow);
        put(&mut frame, &mut q, &epoch.to_le_bytes());
        put(&mut frame, &mut q, &gen.to_le_bytes());
        put(&mut frame, &mut q, &crc.to_le_bytes());
        if !emit_frame(s, sc::CMD_SC_CHECKPOINT_COMMIT, &frame) {
            return;
        }
        s.cont.mirrors[mi].export_active = 4;
        s.cont.stats.checkpoints_out = s.cont.stats.checkpoints_out.wrapping_add(1);
    }
    if s.cont.mirrors[mi].export_active == 4 && s.cont.reply_len == 0 {
        let (len, digest) = (
            s.cont.mirrors[mi].export_len,
            s.cont.mirrors[mi].export_digest,
        );
        let mut body = [0u8; 4 + 4 + 32 + 1 + 2];
        body[..4].copy_from_slice(&gen.to_le_bytes());
        body[4..8].copy_from_slice(&len.to_le_bytes());
        body[8..40].copy_from_slice(&digest);
        body[40] = sc::CT_TCP;
        // No sealed object: TCP holds no secret.
        body[41] = 0;
        body[42] = 0;
        reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_OK, &body);
        s.cont.mirrors[mi].export_active = 0;
    }
}

unsafe fn cmd_cut_import(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let gen = rd_u32(p, 20);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&p[24..56]);
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_IMPORTED, st, &[0; 8]);
            return;
        }
    };
    let sh = &mut s.cont.shadows[si];
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&sh.ckpt_gen.to_le_bytes());
    body[4..].copy_from_slice(&sh.delta_no.to_le_bytes());
    if sh.phase < SH_COMMITTED {
        reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_NOT_READY, &body);
        return;
    }
    if gen != sh.ckpt_gen || digest != sh.record_digest {
        reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_CORRUPT, &body);
        return;
    }
    if sh.phase == SH_COMMITTED {
        sh.phase = SH_IMPORTED;
    }
    reply(s, flow, epoch, sc::CR_IMPORTED, sc::STATUS_OK, &body);
}

unsafe fn cmd_emission_arm(s: &mut IpState, flow: &[u8; 16], epoch: u32) {
    let si = match shadow_for(s, flow, epoch) {
        Ok(si) => si,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_ARMED, st, &[0]);
            return;
        }
    };
    let now = dev_millis(&*s.syscalls) as u32;
    let (phase, conn_idx, local_slot) = {
        let sh = &s.cont.shadows[si];
        (sh.phase, sh.conn_idx as usize, sh.conn.local_slot)
    };
    if phase < SH_IMPORTED {
        reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_NOT_READY, &[0]);
        return;
    }
    if conn_idx >= tcp::MAX_TCP_CONNS || !slot_is_reserved(s, conn_idx) {
        reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_NO_CAPACITY, &[0]);
        return;
    }
    // Route identity must still hold.
    if local_slot_for_dst(s, local_ip_for_slot(s, local_slot)).is_none() {
        reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_NOT_READY, &[0]);
        return;
    }
    // SAFETY: a bitwise copy of a plain record with no drop glue.
    let mut probe: tcp::TcpConn = core::ptr::read(&s.cont.shadows[si].conn);
    let expired = convert_timers(s, &mut probe, 0);
    let sh = &mut s.cont.shadows[si];
    sh.expired_timers = expired;
    sh.armed_ms = now;
    sh.phase = SH_ARMED;
    reply(s, flow, epoch, sc::CR_ARMED, sc::STATUS_OK, &[expired]);
}

unsafe fn cmd_activate(s: &mut IpState, flow: &[u8; 16], epoch_new: u32, p: &[u8]) {
    let fence_gen = rd_u32(p, 20);
    let Some(si) = find_shadow(s, flow) else {
        reply(
            s,
            flow,
            epoch_new,
            sc::CR_ACTIVATED,
            sc::STATUS_UNKNOWN_SESSION,
            &[0; 6],
        );
        return;
    };
    let (phase, epoch_old, idx) = {
        let sh = &s.cont.shadows[si];
        (sh.phase, sh.epoch, sh.conn_idx as usize)
    };
    if phase != SH_ARMED {
        reply(
            s,
            flow,
            epoch_new,
            sc::CR_ACTIVATED,
            sc::STATUS_NOT_READY,
            &[0; 6],
        );
        return;
    }
    if epoch_new <= epoch_old {
        reply(
            s,
            flow,
            epoch_new,
            sc::CR_ACTIVATED,
            sc::STATUS_STALE_EPOCH,
            &[0; 6],
        );
        return;
    }
    if fence_gen == 0 {
        reply(
            s,
            flow,
            epoch_new,
            sc::CR_ACTIVATED,
            sc::STATUS_NOT_READY,
            &[0; 6],
        );
        return;
    }
    if idx >= tcp::MAX_TCP_CONNS || !slot_is_reserved(s, idx) {
        reply(
            s,
            flow,
            epoch_new,
            sc::CR_ACTIVATED,
            sc::STATUS_NO_CAPACITY,
            &[0; 6],
        );
        return;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    let age_ticks =
        (now.wrapping_sub(s.cont.shadows[si].armed_ms) / 50).min(u32::from(u16::MAX)) as u16;
    // SAFETY: a bitwise copy of a plain record with no drop glue.
    let mut conn: tcp::TcpConn = core::ptr::read(&s.cont.shadows[si].conn);
    let _ = convert_timers(s, &mut conn, age_ticks);
    conn.pending_close_notify = NOTIFY_NONE;
    *s.tcp_conns.as_mut_ptr().add(idx) = conn;
    conn_index_insert(s, idx);
    let remote_ip = (*s.tcp_conns.as_ptr().add(idx)).remote_ip;
    arp::pin(&mut s.arp_table, remote_ip);
    // The window the primary advertised at its cut was closed for the
    // quiesce; this side's consumer decides the window from here.
    update_rcv_wnd(s, idx);
    s.cont.shadows[si].clear();
    s.cont.stats.activations = s.cont.stats.activations.wrapping_add(1);
    log_info(s, b"[ip] tcp activated from checkpoint");
    let mut body = [0u8; 6];
    body[..4].copy_from_slice(&epoch_new.to_le_bytes());
    body[4..6].copy_from_slice(&(idx as u16).to_le_bytes());
    reply(s, flow, epoch_new, sc::CR_ACTIVATED, sc::STATUS_OK, &body);
}

fn slot_is_reserved(s: &IpState, idx: usize) -> bool {
    let c = unsafe { &*s.tcp_conns.as_ptr().add(idx) };
    c.state == tcp::TcpState::Closed && c.pending_close_notify == NOTIFY_SHADOW_RESERVED
}

unsafe fn cmd_retire(s: &mut IpState, flow: &[u8; 16], epoch: u32) {
    let mi = match mirror_for(s, flow, epoch) {
        Ok(mi) => mi,
        Err(st) => {
            reply(s, flow, epoch, sc::CR_RETIRED, st, &[]);
            return;
        }
    };
    let idx = s.cont.mirrors[mi].conn_idx as usize;
    // The connection leaves silently: no FIN, no RST, no consumer event —
    // the peer is talking to the new anchor now.
    if s.pending_cmd_valid != 0 && s.pending_cmd_conn as usize == idx {
        s.pending_cmd_valid = 0;
    }
    if s.pending_close_valid != 0 && s.pending_close_conn as usize == idx {
        s.pending_close_valid = 0;
    }
    if idx < tcp::MAX_TCP_CONNS {
        let remote_ip = (*s.tcp_conns.as_ptr().add(idx)).remote_ip;
        if remote_ip != 0 {
            arp::unpin(&mut s.arp_table, remote_ip);
        }
        conn_reset(s, idx);
    }
    s.cont.mirrors[mi].clear();
    reply(s, flow, epoch, sc::CR_RETIRED, sc::STATUS_OK, &[]);
}

unsafe fn cmd_abort(s: &mut IpState, flow: &[u8; 16], epoch: u32, p: &[u8]) {
    let reason = p[20];
    if let Some(si) = find_shadow(s, flow) {
        if s.cont.shadows[si].epoch == epoch {
            discard_shadow(s, si);
            reply(s, flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
            return;
        }
    }
    if let Some(mi) = find_mirror(s, flow) {
        if s.cont.mirrors[mi].epoch == epoch {
            let idx = s.cont.mirrors[mi].conn_idx as usize;
            let quiescing = s.cont.mirrors[mi].quiescing != 0;
            s.cont.mirrors[mi].clear();
            if quiescing && idx < tcp::MAX_TCP_CONNS {
                // Reopen what the quiesce closed.
                update_rcv_wnd(s, idx);
            }
            reply(s, flow, epoch, sc::CR_ABORTED, sc::STATUS_OK, &[reason]);
            return;
        }
    }
    reply(
        s,
        flow,
        epoch,
        sc::CR_ABORTED,
        sc::STATUS_UNKNOWN_SESSION,
        &[reason],
    );
}
