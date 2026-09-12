// Transport continuity for QUIC (CT_QUIC) — checkpoint / delta codec and
// the shadow-takeover state machine on the `cont_in` / `cont_out` ports.
//
// QUIC is a replicated-anchor continuity class rather than
// `native_primitive`: the wire protocol migrates paths, not hosts, and a
// server host that dies takes the userspace flow with it. Because QUIC
// carries its packet number on the wire it is an on-wire-sequence AEAD, so
// the 1-RTT send space is drawn from `nonce_reservation` and a takeover
// resumes strictly ahead of anything the dead host could have emitted.
//
// ─── What the strict horizon covers ───────────────────────────────────
//
// Under PROFILE_CRASH_CONTINUOUS every 1-RTT packet the send pump builds
// is mirrored and withheld until the standby acknowledges it, and an
// inbound packet is not acknowledged to the peer until the standby holds
// its receipt. The probe timeout leaves a withheld packet alone: it has
// not been shown to the peer, so it cannot have been lost, and replaying
// it would put its packet number on the wire twice.
//
// Path validation and connection close sit outside the horizon, and
// deliberately. A PATH_CHALLENGE or PATH_RESPONSE is about the path this
// host is on, which a standby does not inherit — it validates its own —
// and a CONNECTION_CLOSE ends the flow, after which there is nothing to
// take over. Holding either would stall a liveness check behind a standby
// that may be the reason the path is in doubt.
//
// A standby that stops answering does not hold the connection silent for
// ever: past `CONT_HORIZON_STEPS` the mirror is abandoned, the coordinator
// is told, and the packet the horizon was holding still goes to the peer,
// a packet number having been spent on it.
//
// ─── Canonical checkpoint record (CT_QUIC) ─────────────────────────────
//
// One connection's continuity state, serialized into a bounded buffer and
// chunked over `cont_out` (CHECKPOINT_CHUNK_MAX bytes/chunk, CRC32 over the
// chunk stream, SHA-256 over the whole record). Live secrets NEVER appear
// raw: the traffic-secret set is sealed with the vault AEAD under the
// labelled key `quic-continuity`, AAD = flow_id ‖ epoch, and only a vault
// holding the same key opens it. CIDs are preserved verbatim — a takeover
// that re-minted them would be unroutable to the peer.
//
//   magic          [4]  = b"QKR1"
//   flow_id        [16]
//   epoch          u32
//   flags          u8   bit0 = is_server
//   our_cid        u8 len + [MAX_CID_LEN]     preserved verbatim
//   peer_cid       u8 len + [MAX_CID_LEN]     preserved verbatim
//   original_dcid  u8 len + [MAX_CID_LEN]     preserved verbatim (Initial keys)
//   peer_ip        [4]  peer_port u16
//   idle_remaining_ms u64                     REMAINING, never a timestamp
//   negotiated transport parameters:
//     send_max_data u64, peer_max_streams_bidi u64, peer_max_streams_uni u64,
//     peer_stream_window_bidi_local u64, _bidi_remote u64, _uni u64,
//     peer_max_datagram_frame_size u64, max_streams_bidi_granted u64,
//     max_streams_uni_granted u64
//   1-RTT PnSpace:
//     next_send_pn u64   (reservation high-water: strictly ahead of last-sent)
//     largest_recv_pn u64, crypto_send_off u64, crypto_recv_off u64
//     ack_range_count u8, then count × (low u64, high u64)
//   Initial/Handshake counters: init_next_send u64, hs_next_send u64
//   connection flow control:
//     send_data_used u64, recv_max_data u64, recv_data_consumed u64
//   congestion (exported; importer restarts conservatively —
//   cap cwnd, clear recovery): congestion_window u64, ssthresh u64,
//     bytes_in_flight u64
//   key_phase u8, secret_len u8
//   retained last_emitted: last_emitted_pn u64, len u16, bytes
//   streams: count u8, then each
//     kind u8 (1=uni,2=bidi), locally_initiated u8, stream_id u64, handle u32,
//     send_off u64, recv_off u64, send_fin u8, recv_fin u8,
//     flow_send_max u64, flow_recv_max u64, flow_recv_consumed u64,
//     send_buf_len u16 + bytes, recv_buf_len u16 + bytes
//   sealed secret set: sealed_len u16 + sealed bytes, whose plaintext is
//     read_secret[secret_len] ‖ write_secret ‖ next_read_secret ‖
//     next_write_secret ‖ psk_len u8 ‖ psk[48] ‖ psk_id_len u16 ‖ psk_id
//
// Import validates the magic, every length as it decodes (a short read is
// STATUS_CORRUPT), and impossible relations (largest_recv > next_send_pn,
// ack low > high, secret_len ∉ {32,48}, stream count over the pool). A
// handshake-in-progress or closing connection is refused
// ABORT_UNSUPPORTED_STATE — its lifecycle is not exportable. The shadow is
// non-emitting until ACTIVATE with a strictly higher epoch and a non-zero
// fence generation; the importer restores the anti-amplification limit and
// marks a fresh path validation owed before unrestricted sending.

use abi::contracts::net::session_ctrl as sc;

/// 16-byte flow identity size (mirrors `sc::FLOW_ID_BYTES`).
pub const CONT_FLOW_ID_BYTES: usize = 16;
/// Shadow slots this endpoint holds — one connection under migration per
/// slot at a time. A small fixed number: continuity is a control-plane
/// event, not steady-state, and each shadow is a full connection's worth
/// of state.
pub const MAX_SHADOW_SLOTS: usize = 2;
/// Largest checkpoint record the codec produces / accepts. Sized to hold
/// the full connection state: three bidi (1200+1500) and six uni (256+256)
/// stream buffers, the retained last-emitted packet, the sealed secret set,
/// and the fixed header, with headroom.
pub const CHECKPOINT_RECORD_MAX: usize = 16384;
/// Labelled vault key the continuity secrets are sealed under.
pub const CONT_LABEL: &[u8] = b"quic-continuity";
/// Bytes the vault adds to a sealed plaintext: a 12-byte nonce and a
/// 16-byte tag.
const CONT_SEAL_OVERHEAD: usize = 12 + 16;
/// Sealed-secret plaintext ceiling: 4×48 traffic secrets + psk + identity.
/// Largest sealed plaintext: four traffic secrets, both header-protection
/// keys, the previous read phase's keys and whether they are live, the PSK
/// and its identity.
pub const CONT_SECRET_PT_MAX: usize = 4 * 48
    + 2 * QUIC_HP_KEY_LEN
    + (QUIC_KEY_LEN + QUIC_IV_LEN + QUIC_HP_KEY_LEN)
    + 1
    + 1
    + 48
    + 2
    + MAX_TICKET_LEN;
/// Record magic.
const CONT_MAGIC: [u8; 4] = *b"QKR1";

/// A durable reservation grant carried on `cont_in`: the flow it applies
/// to, then the grant record. Both are laid out in
/// `contracts/net/session_ctrl.rs`.
pub const CONT_RESERVATION_GRANT: u8 = sc::CMD_SC_RESERVATION_GRANT;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ShadowPhase {
    Free = 0,
    Prepared = 1,
    Receiving = 2,
    Committed = 3,
    Imported = 4,
    Armed = 5,
}

/// One shadow slot: the reassembly buffer, the checkpoint/delta bookkeeping,
/// and the imported (non-emitting) connection it stages.
pub struct ShadowSlot {
    phase: ShadowPhase,
    flow_id: [u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    ckpt_gen: u32,
    transport: u8,
    profile: u8,
    codec_digest: [u8; 32],
    record_digest: [u8; 32],
    manifest_digest: [u8; 32],
    import: HandoffImport,
    record: [u8; CHECKPOINT_RECORD_MAX],
    last_delta_no: u32,
    prev_delta_digest: [u8; 32],
    expired_timers: u8,
    /// The staged connection. Non-emitting until ACTIVATE promotes it.
    conn: QuicConnection,
}

pub struct ContinuityState {
    shadows: [ShadowSlot; MAX_SHADOW_SLOTS],
    /// Fence generation the last ACTIVATE observed (zero refused).
    last_fence_gen: u32,
}

/// Initialise the continuity state in-place over the module's zeroed
/// arena (the same pattern `module_new` uses for the connection table):
/// clear each shadow and reset its staged connection.
unsafe fn continuity_init(s: &mut QuicState) {
    let mut i = 0;
    while i < MAX_SHADOW_SLOTS {
        let sh = &mut s.continuity.shadows[i];
        sh.phase = ShadowPhase::Free;
        sh.flow_id = [0; CONT_FLOW_ID_BYTES];
        sh.epoch = 0;
        sh.ckpt_gen = 0;
        sh.transport = 0;
        sh.profile = 0;
        sh.codec_digest = [0; 32];
        sh.record_digest = [0; 32];
        sh.manifest_digest = [0; 32];
        sh.import = HandoffImport::new();
        sh.last_delta_no = 0;
        sh.prev_delta_digest = [0; 32];
        sh.expired_timers = 0;
        sh.conn.reset();
        i += 1;
    }
    s.continuity.last_fence_gen = 0;
}

// ─── Bounded writer / reader ───────────────────────────────────────────

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    ok: bool,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Writer {
            buf,
            pos: 0,
            ok: true,
        }
    }
    fn u8(&mut self, v: u8) {
        if self.ok && self.pos < self.buf.len() {
            self.buf[self.pos] = v;
            self.pos += 1;
        } else {
            self.ok = false;
        }
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
    fn bytes(&mut self, b: &[u8]) {
        if self.ok && self.pos + b.len() <= self.buf.len() {
            self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
            self.pos += b.len();
        } else {
            self.ok = false;
        }
    }
    /// A length-prefixed CID (u8 len + up to MAX_CID_LEN bytes).
    fn cid(&mut self, cid: &[u8; MAX_CID_LEN], len: u8) {
        let n = (len as usize).min(MAX_CID_LEN);
        self.u8(n as u8);
        self.bytes(&cid[..n]);
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        if self.pos < self.buf.len() {
            let v = self.buf[self.pos];
            self.pos += 1;
            Some(v)
        } else {
            None
        }
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n <= self.buf.len() {
            let r = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Some(r)
        } else {
            None
        }
    }
    fn cid(&mut self, out: &mut [u8; MAX_CID_LEN]) -> Option<u8> {
        let n = self.u8()? as usize;
        if n > MAX_CID_LEN {
            return None;
        }
        let b = self.take(n)?;
        out[..n].copy_from_slice(b);
        Some(n as u8)
    }
}

// ─── Vault sealing (labelled `quic-continuity`) ────────────────────────

/// Open (or lazily generate) the continuity sealing key. Returns -1 if the
/// vault refuses, in which case no checkpoint can be produced or imported.
unsafe fn cont_vault_key(s: &mut QuicState) -> i32 {
    if s.cont_vault_key >= 0 {
        return s.cont_vault_key;
    }
    let sys = &*s.syscalls;
    s.cont_vault_key = vault_open_or_generate_aead(sys, CONT_LABEL);
    s.cont_vault_key
}

/// AAD binding a sealed secret set to its flow and ownership epoch.
fn cont_aad(flow_id: &[u8; CONT_FLOW_ID_BYTES], epoch: u32) -> [u8; CONT_FLOW_ID_BYTES + 4] {
    let mut aad = [0u8; CONT_FLOW_ID_BYTES + 4];
    aad[..CONT_FLOW_ID_BYTES].copy_from_slice(flow_id);
    aad[CONT_FLOW_ID_BYTES..].copy_from_slice(&epoch.to_le_bytes());
    aad
}

/// `AEAD_SEAL` a continuity secret blob under `handle`; bytes written to
/// `out`, or 0. Distinct from `vault_seal` only in its wider argument
/// buffer (the secret set is larger than a ticket).
unsafe fn cont_seal(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    pt: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + 32 + 2 + CONT_SECRET_PT_MAX + 12];
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
    if rc < 0 {
        return 0;
    }
    u16::from_le_bytes([arg[p + 10], arg[p + 11]]) as usize
}

/// `AEAD_OPEN` a sealed continuity blob under `handle` with `aad`.
unsafe fn cont_open(
    sys: &SyscallTable,
    handle: i32,
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> usize {
    let mut arg = [0u8; 2 + 32 + 2 + CONT_SECRET_PT_MAX + CONT_SEAL_OVERHEAD + 12];
    if aad.len() > 32 || blob.len() > CONT_SECRET_PT_MAX + CONT_SEAL_OVERHEAD {
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

// ─── SHA-256 helper ────────────────────────────────────────────────────

fn record_sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

// ─── Serialize a live connection into a checkpoint record ──────────────

/// Encode connection `idx`'s continuity state into `out`, sealing its
/// secret set under the `quic-continuity` key. Returns the record length,
/// or 0 on refusal (handshake-in-progress / closing state, vault refusal,
/// or an oversize record).
unsafe fn serialize_checkpoint(
    s: &mut QuicState,
    idx: usize,
    flow_id: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    out: &mut [u8],
) -> usize {
    if idx >= MAX_CONNS {
        return 0;
    }
    // A handshake-in-progress or closing/errored connection has no
    // exportable steady-state lifecycle.
    if !matches!(s.conns[idx].phase, ConnPhase::Established) || !s.conns[idx].handshake_confirmed {
        return 0;
    }
    let handle = cont_vault_key(s);
    if handle < 0 {
        return 0;
    }
    let sys = &*s.syscalls;

    // Seal the traffic-secret set first so its length is known before the
    // record body is written.
    let hl = s.conns[idx].one_rtt.secret_len as usize;
    if hl == 0 {
        return 0;
    }
    let mut pt = [0u8; CONT_SECRET_PT_MAX];
    let mut pp = 0;
    {
        let c = &s.conns[idx];
        pt[pp..pp + hl].copy_from_slice(&c.one_rtt.read_secret[..hl]);
        pp += hl;
        pt[pp..pp + hl].copy_from_slice(&c.one_rtt.write_secret[..hl]);
        pp += hl;
        pt[pp..pp + hl].copy_from_slice(&c.one_rtt.next_read_secret[..hl]);
        pp += hl;
        pt[pp..pp + hl].copy_from_slice(&c.one_rtt.next_write_secret[..hl]);
        pp += hl;
        // Header-protection keys are phase-invariant (RFC 9001 §6.1): they
        // are NOT re-derivable from a rotated traffic secret, so seal them
        // explicitly alongside the secrets.
        pt[pp..pp + QUIC_HP_KEY_LEN].copy_from_slice(&c.one_rtt.read_keys.hp);
        pp += QUIC_HP_KEY_LEN;
        pt[pp..pp + QUIC_HP_KEY_LEN].copy_from_slice(&c.one_rtt.write_keys.hp);
        pp += QUIC_HP_KEY_LEN;
        // The previous read phase, retained across a key update so a
        // reordered packet still decrypts: a takeover in that window would
        // otherwise fail the peer's straggler and, with it, the connection.
        pt[pp] = u8::from(c.one_rtt.prev_read_valid);
        pp += 1;
        pt[pp..pp + QUIC_KEY_LEN].copy_from_slice(&c.one_rtt.prev_read_keys.key);
        pp += QUIC_KEY_LEN;
        pt[pp..pp + QUIC_IV_LEN].copy_from_slice(&c.one_rtt.prev_read_keys.iv);
        pp += QUIC_IV_LEN;
        pt[pp..pp + QUIC_HP_KEY_LEN].copy_from_slice(&c.one_rtt.prev_read_keys.hp);
        pp += QUIC_HP_KEY_LEN;
        pt[pp] = c.psk_len;
        pp += 1;
        pt[pp..pp + 48].copy_from_slice(&c.psk);
        pp += 48;
        let idlen = c.psk_identity_len as usize;
        if idlen > MAX_TICKET_LEN {
            return 0;
        }
        pt[pp..pp + 2].copy_from_slice(&(idlen as u16).to_le_bytes());
        pp += 2;
        pt[pp..pp + idlen].copy_from_slice(&c.psk_identity[..idlen]);
        pp += idlen;
    }
    let aad = cont_aad(flow_id, epoch);
    let mut sealed = [0u8; CONT_SECRET_PT_MAX + 32];
    let sealed_len = cont_seal(sys, handle, &aad, &pt[..pp], &mut sealed);
    // Zeroize the plaintext secret staging.
    let mut z = 0;
    while z < pp {
        core::ptr::write_volatile(&mut pt[z], 0);
        z += 1;
    }
    if sealed_len == 0 {
        return 0;
    }

    let now_ms = dev_millis(sys);
    let mut w = Writer::new(out);
    let c = &s.conns[idx];
    w.bytes(&CONT_MAGIC);
    w.bytes(flow_id);
    w.u32(epoch);
    w.u8(if c.is_server { 1 } else { 0 });
    w.cid(&c.our_cid, c.our_cid_len);
    w.cid(&c.peer_cid, c.peer_cid_len);
    w.cid(&c.original_dcid, c.original_dcid_len);
    w.bytes(&c.peer.ip);
    w.u16(c.peer.port);
    // Idle timeout as a REMAINING duration, never a host timestamp.
    let elapsed = now_ms.saturating_sub(c.last_activity_ms);
    let idle_remaining = c.idle_timeout_ms.saturating_sub(elapsed);
    w.u64(idle_remaining);
    // Negotiated transport parameters / flow limits.
    w.u64(c.send_max_data);
    w.u64(c.peer_max_streams_bidi);
    w.u64(c.peer_max_streams_uni);
    w.u64(c.peer_stream_window_bidi_local);
    w.u64(c.peer_stream_window_bidi_remote);
    w.u64(c.peer_stream_window_uni);
    w.u64(c.peer_max_datagram_frame_size);
    w.u64(c.max_streams_bidi_granted);
    w.u64(c.max_streams_uni_granted);
    // 1-RTT packet-number space: the floor a takeover resumes from.
    //
    // This is the reservation's high-water — the end of every block this
    // host was ever granted — and not the next number to send. The holder
    // may still emit anything below its block end, so a standby that
    // resumed from the send counter would start inside numbers this host
    // can still put on the wire: the same nonce under the same key. The
    // send counter is folded in only because two emit paths advance it
    // without drawing on the reservation.
    let hw = c
        .send_pn_res
        .high_water()
        .max(c.one_rtt.next_send_pn);
    w.u64(hw);
    w.u64(c.one_rtt.largest_recv_pn);
    // Key-update progress, so a takeover mid-update neither starts a second
    // update before the first is acknowledged nor loses count of the phase.
    w.u8(u8::from(c.key_update_awaiting_ack));
    w.u64(c.key_update_first_pn);
    w.u32(c.one_rtt_pkts_since_phase);
    w.u64(c.one_rtt.crypto_send_offset);
    w.u64(c.one_rtt.crypto_recv_offset);
    let arc = c.one_rtt.ack_tracker.count.min(MAX_ACK_RANGES as u8);
    w.u8(arc);
    let mut ri = 0;
    while ri < arc as usize {
        w.u64(c.one_rtt.ack_tracker.ranges[ri].low);
        w.u64(c.one_rtt.ack_tracker.ranges[ri].high);
        ri += 1;
    }
    w.u64(c.initial.next_send_pn);
    w.u64(c.handshake.next_send_pn);
    // Connection flow control.
    w.u64(c.send_data_used);
    w.u64(c.recv_max_data);
    w.u64(c.recv_data_consumed);
    // Congestion state.
    w.u64(c.congestion_window);
    w.u64(c.ssthresh);
    w.u64(c.bytes_in_flight);
    // Key phase + retained last-emitted ciphertext for retransmission.
    w.u8(c.one_rtt.key_phase);
    w.u8(c.one_rtt.secret_len);
    w.u64(c.one_rtt.last_emitted_pn);
    let lel = c.one_rtt.last_emitted_len.min(c.one_rtt.last_emitted.len());
    w.u16(lel as u16);
    w.bytes(&c.one_rtt.last_emitted[..lel]);
    // Streams (open uni + bidi).
    let mut count = 0u8;
    let mut k = 0;
    while k < MAX_UNI_STREAMS {
        if c.uni_streams[k].allocated {
            count += 1;
        }
        k += 1;
    }
    k = 0;
    while k < MAX_BIDI_STREAMS {
        if c.bidi_streams[k].allocated {
            count += 1;
        }
        k += 1;
    }
    w.u8(count);
    k = 0;
    while k < MAX_UNI_STREAMS {
        let st = &c.uni_streams[k];
        if st.allocated {
            w.u8(1);
            w.u8(if st.locally_initiated { 1 } else { 0 });
            w.u64(st.stream_id);
            w.u32(st.app.handle);
            w.u64(st.send_off);
            w.u64(st.recv_off);
            w.u8(if st.send_fin_pending || st.send_fin_emitted {
                1
            } else {
                0
            });
            w.u8(if st.recv_fin { 1 } else { 0 });
            w.u64(st.flow.send_max_data);
            w.u64(st.flow.recv_max_data);
            w.u64(st.flow.recv_consumed);
            let sl = st.send_buf_len.min(st.send_buf.len());
            w.u16(sl as u16);
            w.bytes(&st.send_buf[..sl]);
            let rl = st.recv_buf_len.min(st.recv_buf.len());
            w.u16(rl as u16);
            w.bytes(&st.recv_buf[..rl]);
        }
        k += 1;
    }
    k = 0;
    while k < MAX_BIDI_STREAMS {
        let st = &c.bidi_streams[k];
        if st.allocated {
            w.u8(2);
            w.u8(if st.locally_initiated { 1 } else { 0 });
            w.u64(st.stream_id);
            w.u32(st.app.handle);
            w.u64(st.send_off);
            w.u64(st.recv_off);
            w.u8(if st.send_fin_pending || st.send_fin_emitted {
                1
            } else {
                0
            });
            w.u8(if st.recv_fin { 1 } else { 0 });
            w.u64(st.flow.send_max_data);
            w.u64(st.flow.recv_max_data);
            w.u64(st.flow.recv_consumed);
            let sl = st.send_buf_len.min(st.send_buf.len());
            w.u16(sl as u16);
            w.bytes(&st.send_buf[..sl]);
            let rl = st.recv_buf_len.min(st.recv_buf.len());
            w.u16(rl as u16);
            w.bytes(&st.recv_buf[..rl]);
        }
        k += 1;
    }
    // Sealed secret set (traffic secrets + live PSK), never raw.
    w.u16(sealed_len as u16);
    w.bytes(&sealed[..sealed_len]);
    if !w.ok {
        return 0;
    }
    w.pos
}

// ─── Import a checkpoint record into a shadow connection ───────────────

/// Validate and deserialize `record` into shadow `conn`, opening the sealed
/// secret set under the `quic-continuity` key. Returns a `sc::STATUS_*`
/// code; anything but `STATUS_OK` means the shadow is discarded whole
///. The staged connection is left NON-EMITTING (a shadow phase) —
/// it becomes live only at ACTIVATE.
unsafe fn import_checkpoint(
    s: &mut QuicState,
    conn: &mut QuicConnection,
    flow_id: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    record: &[u8],
) -> u8 {
    let handle = cont_vault_key(s);
    if handle < 0 {
        return sc::STATUS_CORRUPT;
    }
    let sys = &*s.syscalls;
    let mut r = Reader::new(record);
    // Magic + flow + epoch.
    let magic = match r.take(4) {
        Some(m) => m,
        None => return sc::STATUS_CORRUPT,
    };
    if magic != CONT_MAGIC {
        return sc::STATUS_CORRUPT;
    }
    let rec_flow = match r.take(16) {
        Some(f) => f,
        None => return sc::STATUS_CORRUPT,
    };
    if rec_flow != &flow_id[..] {
        return sc::STATUS_CORRUPT;
    }
    let rec_epoch = match r.u32() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    if rec_epoch != epoch {
        return sc::STATUS_CORRUPT;
    }
    conn.reset();
    let flags = match r.u8() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    conn.is_server = flags & 1 != 0;
    // CIDs preserved verbatim.
    match r.cid(&mut conn.our_cid) {
        Some(n) => conn.our_cid_len = n,
        None => return sc::STATUS_CORRUPT,
    }
    match r.cid(&mut conn.peer_cid) {
        Some(n) => conn.peer_cid_len = n,
        None => return sc::STATUS_CORRUPT,
    }
    match r.cid(&mut conn.original_dcid) {
        Some(n) => conn.original_dcid_len = n,
        None => return sc::STATUS_CORRUPT,
    }
    let ip = match r.take(4) {
        Some(b) => [b[0], b[1], b[2], b[3]],
        None => return sc::STATUS_CORRUPT,
    };
    let port = match r.u16() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    conn.peer = PeerAddr { ip, port };
    conn.recv_ip = ip;
    conn.recv_port = port;
    let idle_remaining = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    conn.idle_timeout_ms = idle_remaining;
    macro_rules! rd_u64 {
        ($field:expr) => {
            match r.u64() {
                Some(v) => $field = v,
                None => return sc::STATUS_CORRUPT,
            }
        };
    }
    rd_u64!(conn.send_max_data);
    rd_u64!(conn.peer_max_streams_bidi);
    rd_u64!(conn.peer_max_streams_uni);
    rd_u64!(conn.peer_stream_window_bidi_local);
    rd_u64!(conn.peer_stream_window_bidi_remote);
    rd_u64!(conn.peer_stream_window_uni);
    rd_u64!(conn.peer_max_datagram_frame_size);
    rd_u64!(conn.max_streams_bidi_granted);
    rd_u64!(conn.max_streams_uni_granted);
    let next_send_pn = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    let largest_recv_pn = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    // Impossible relation: cannot have acked past what we will send next.
    if largest_recv_pn != 0 && largest_recv_pn > next_send_pn.saturating_add(1 << 20) {
        return sc::STATUS_CORRUPT;
    }
    conn.one_rtt.next_send_pn = next_send_pn;
    conn.one_rtt.largest_recv_pn = largest_recv_pn;
    let (Some(ku_wait), Some(ku_first), Some(since)) = (r.u8(), r.u64(), r.u32()) else {
        return sc::STATUS_CORRUPT;
    };
    if ku_wait > 1 {
        return sc::STATUS_CORRUPT;
    }
    conn.key_update_awaiting_ack = ku_wait == 1;
    conn.key_update_first_pn = ku_first;
    conn.one_rtt_pkts_since_phase = since;
    rd_u64!(conn.one_rtt.crypto_send_offset);
    rd_u64!(conn.one_rtt.crypto_recv_offset);
    let arc = match r.u8() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    if arc as usize > MAX_ACK_RANGES {
        return sc::STATUS_CORRUPT;
    }
    conn.one_rtt.ack_tracker = AckTracker::new();
    let mut ai = 0;
    while ai < arc as usize {
        let low = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let high = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        if low > high {
            return sc::STATUS_CORRUPT;
        }
        conn.one_rtt.ack_tracker.ranges[ai] = AckRange { low, high };
        ai += 1;
    }
    conn.one_rtt.ack_tracker.count = arc;
    rd_u64!(conn.initial.next_send_pn);
    rd_u64!(conn.handshake.next_send_pn);
    rd_u64!(conn.send_data_used);
    rd_u64!(conn.recv_max_data);
    rd_u64!(conn.recv_data_consumed);
    // Congestion restarts conservatively — cap cwnd, clear recovery.
    let _exported_cwnd = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    let _exported_ssthresh = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    let _exported_in_flight = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    conn.congestion_window = INITIAL_WINDOW;
    conn.ssthresh = u64::MAX;
    conn.bytes_in_flight = 0;
    conn.recovery_start_time = 0;
    let key_phase = match r.u8() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    if key_phase > 1 {
        return sc::STATUS_CORRUPT;
    }
    conn.one_rtt.key_phase = key_phase;
    let secret_len = match r.u8() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    if secret_len != 32 && secret_len != 48 {
        return sc::STATUS_CORRUPT;
    }
    conn.one_rtt.secret_len = secret_len;
    let last_pn = match r.u64() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    let lel = match r.u16() {
        Some(v) => v as usize,
        None => return sc::STATUS_CORRUPT,
    };
    if lel > conn.one_rtt.last_emitted.len() {
        return sc::STATUS_CORRUPT;
    }
    let leb = match r.take(lel) {
        Some(b) => b,
        None => return sc::STATUS_CORRUPT,
    };
    conn.one_rtt.last_emitted[..lel].copy_from_slice(leb);
    conn.one_rtt.last_emitted_len = lel;
    conn.one_rtt.last_emitted_pn = last_pn;
    // Streams.
    let scount = match r.u8() {
        Some(v) => v,
        None => return sc::STATUS_CORRUPT,
    };
    if scount as usize > MAX_UNI_STREAMS + MAX_BIDI_STREAMS {
        return sc::STATUS_CORRUPT;
    }
    let mut uni_i = 0;
    let mut bidi_i = 0;
    let mut si = 0;
    while si < scount as usize {
        let kind = match r.u8() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        // Refused here, before anything is sized against it. Every length
        // guard below is written per kind, so an unknown kind satisfies none
        // of them and would carry an unbounded length into a fixed buffer.
        if kind != 1 && kind != 2 {
            return sc::STATUS_CORRUPT;
        }
        let local = match r.u8() {
            Some(v) => v != 0,
            None => return sc::STATUS_CORRUPT,
        };
        let stream_id = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let handle = match r.u32() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let send_off = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let recv_off = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let send_fin = match r.u8() {
            Some(v) => v != 0,
            None => return sc::STATUS_CORRUPT,
        };
        let recv_fin = match r.u8() {
            Some(v) => v != 0,
            None => return sc::STATUS_CORRUPT,
        };
        let f_send = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let f_recv = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let f_cons = match r.u64() {
            Some(v) => v,
            None => return sc::STATUS_CORRUPT,
        };
        let sl = match r.u16() {
            Some(v) => v as usize,
            None => return sc::STATUS_CORRUPT,
        };
        if kind == 1 && sl > 256 || kind == 2 && sl > 1200 {
            return sc::STATUS_CORRUPT;
        }
        let sbytes = match r.take(sl) {
            Some(b) => b,
            None => return sc::STATUS_CORRUPT,
        };
        let mut sbuf = [0u8; 1200];
        sbuf[..sl].copy_from_slice(sbytes);
        let rl = match r.u16() {
            Some(v) => v as usize,
            None => return sc::STATUS_CORRUPT,
        };
        if kind == 1 && rl > 256 || kind == 2 && rl > 1500 {
            return sc::STATUS_CORRUPT;
        }
        let rbytes = match r.take(rl) {
            Some(b) => b,
            None => return sc::STATUS_CORRUPT,
        };
        let mut rbuf = [0u8; 1500];
        rbuf[..rl].copy_from_slice(rbytes);
        if kind == 1 {
            if uni_i >= MAX_UNI_STREAMS {
                return sc::STATUS_CORRUPT;
            }
            let st = &mut conn.uni_streams[uni_i];
            *st = UniStream::empty();
            st.allocated = true;
            st.locally_initiated = local;
            st.stream_id = stream_id;
            st.app.handle = handle;
            st.app.open_sent = true;
            st.send_off = send_off;
            st.recv_off = recv_off;
            st.send_fin_emitted = send_fin;
            st.recv_fin = recv_fin;
            st.flow.send_max_data = f_send;
            st.flow.recv_max_data = f_recv;
            st.flow.recv_consumed = f_cons;
            let cl = sl.min(st.send_buf.len());
            st.send_buf[..cl].copy_from_slice(&sbuf[..cl]);
            st.send_buf_len = cl;
            let crl = rl.min(st.recv_buf.len());
            st.recv_buf[..crl].copy_from_slice(&rbuf[..crl]);
            st.recv_buf_len = crl;
            uni_i += 1;
        } else if kind == 2 {
            if bidi_i >= MAX_BIDI_STREAMS {
                return sc::STATUS_CORRUPT;
            }
            let st = &mut conn.bidi_streams[bidi_i];
            *st = BidiStream::empty();
            st.allocated = true;
            st.locally_initiated = local;
            st.stream_id = stream_id;
            st.app.handle = handle;
            st.app.open_sent = true;
            st.send_off = send_off;
            st.recv_off = recv_off;
            st.send_fin_emitted = send_fin;
            st.recv_fin = recv_fin;
            st.flow.send_max_data = f_send;
            st.flow.recv_max_data = f_recv;
            st.flow.recv_consumed = f_cons;
            let cl = sl.min(st.send_buf.len());
            st.send_buf[..cl].copy_from_slice(&sbuf[..cl]);
            st.send_buf_len = cl;
            let crl = rl.min(st.recv_buf.len());
            st.recv_buf[..crl].copy_from_slice(&rbuf[..crl]);
            st.recv_buf_len = crl;
            bidi_i += 1;
        } else {
            return sc::STATUS_CORRUPT;
        }
        si += 1;
    }
    // Sealed secret set. Its length comes from the record, so it is held to
    // what a seal of the largest secret set can be before it is staged into
    // a fixed argument buffer.
    let sealed_len = match r.u16() {
        Some(v) if v as usize <= CONT_SECRET_PT_MAX + CONT_SEAL_OVERHEAD => v as usize,
        _ => return sc::STATUS_CORRUPT,
    };
    let sealed = match r.take(sealed_len) {
        Some(b) => b,
        None => return sc::STATUS_CORRUPT,
    };
    let aad = cont_aad(flow_id, epoch);
    let mut pt = [0u8; CONT_SECRET_PT_MAX];
    let n = cont_open(sys, handle, &aad, sealed, &mut pt);
    if n == 0 {
        return sc::STATUS_CORRUPT;
    }
    let hl = secret_len as usize;
    if n < 4 * hl + 2 * QUIC_HP_KEY_LEN + 1 + QUIC_KEY_LEN + QUIC_IV_LEN + QUIC_HP_KEY_LEN + 1 + 48 + 2 {
        // Zeroize before bailing.
        let mut z = 0;
        while z < n {
            core::ptr::write_volatile(&mut pt[z], 0);
            z += 1;
        }
        return sc::STATUS_CORRUPT;
    }
    let mut pp = 0;
    conn.one_rtt.read_secret[..hl].copy_from_slice(&pt[pp..pp + hl]);
    pp += hl;
    conn.one_rtt.write_secret[..hl].copy_from_slice(&pt[pp..pp + hl]);
    pp += hl;
    conn.one_rtt.next_read_secret[..hl].copy_from_slice(&pt[pp..pp + hl]);
    pp += hl;
    conn.one_rtt.next_write_secret[..hl].copy_from_slice(&pt[pp..pp + hl]);
    pp += hl;
    let mut read_hp = [0u8; QUIC_HP_KEY_LEN];
    read_hp.copy_from_slice(&pt[pp..pp + QUIC_HP_KEY_LEN]);
    pp += QUIC_HP_KEY_LEN;
    let mut write_hp = [0u8; QUIC_HP_KEY_LEN];
    write_hp.copy_from_slice(&pt[pp..pp + QUIC_HP_KEY_LEN]);
    pp += QUIC_HP_KEY_LEN;
    let prev_valid = pt[pp] & 1 == 1;
    pp += 1;
    let mut prev = QuicKeys::empty();
    prev.key.copy_from_slice(&pt[pp..pp + QUIC_KEY_LEN]);
    pp += QUIC_KEY_LEN;
    prev.iv.copy_from_slice(&pt[pp..pp + QUIC_IV_LEN]);
    pp += QUIC_IV_LEN;
    prev.hp.copy_from_slice(&pt[pp..pp + QUIC_HP_KEY_LEN]);
    pp += QUIC_HP_KEY_LEN;
    conn.psk_len = pt[pp];
    pp += 1;
    conn.psk.copy_from_slice(&pt[pp..pp + 48]);
    pp += 48;
    let idlen = u16::from_le_bytes([pt[pp], pt[pp + 1]]) as usize;
    pp += 2;
    if idlen <= conn.psk_identity.len() && pp + idlen <= n {
        conn.psk_identity[..idlen].copy_from_slice(&pt[pp..pp + idlen]);
        conn.psk_identity_len = idlen as u8;
    }
    // Rebuild the packet-protection keys from the opened secrets, then
    // restore the phase-invariant header-protection keys (RFC 9001 §6.1):
    // deriving hp from a rotated traffic secret would not match the peer.
    conn.one_rtt.read_keys = secret_to_keys(&conn.one_rtt.read_secret[..hl]);
    conn.one_rtt.read_keys.hp = read_hp;
    conn.one_rtt.write_keys = secret_to_keys(&conn.one_rtt.write_secret[..hl]);
    conn.one_rtt.write_keys.hp = write_hp;
    conn.one_rtt.next_read_keys = next_keys(&conn.one_rtt.next_read_secret[..hl], read_hp);
    conn.one_rtt.next_write_keys = next_keys(&conn.one_rtt.next_write_secret[..hl], write_hp);
    conn.one_rtt.next_keys_ready = true;
    conn.one_rtt.prev_read_keys = prev;
    conn.one_rtt.prev_read_valid = prev_valid;
    conn.one_rtt.keys_set = true;
    // Zeroize the opened plaintext.
    let mut z = 0;
    while z < n {
        core::ptr::write_volatile(&mut pt[z], 0);
        z += 1;
    }
    // Staged but NON-EMITTING: phase stays Idle until ACTIVATE promotes it.
    // The reservation is seeded with the checkpoint's high-water as its
    // floor and carries no grant, so no value can emit before ACTIVATE
    // installs the post-takeover epoch.
    conn.handshake_confirmed = true;
    conn.framed_app_surface = true;
    conn.send_pn_res = NonceReservation::resume(epoch, next_send_pn);
    conn.cont_epoch = epoch;
    sc::STATUS_OK
}

/// Promote an imported shadow to a live connection under a strictly higher
/// epoch and a non-zero fence generation. The reservation resumes at
/// the checkpoint high-water so packet numbers never repeat across the
/// takeover, the anti-amplification limit is restored, and a fresh path
/// validation is required before unrestricted sending. Returns the
/// live connection index, or -1 on refusal.
unsafe fn activate_shadow(
    s: &mut QuicState,
    mut conn: QuicConnection,
    new_epoch: u32,
    fence_gen: u32,
    prior_epoch: u32,
) -> i32 {
    if fence_gen == 0 || new_epoch <= prior_epoch {
        return -1;
    }
    let idx = match alloc_shadow_live_slot(s) {
        Some(i) => i,
        None => {
            // Refused for want of a slot. The connection handed in holds
            // every opened secret; it is retired here rather than dropped
            // with them still in it.
            retire_connection(&mut conn);
            return -1;
        }
    };
    // The floor the checkpoint carried, seeded into the shadow's reservation
    // at import; any delta since may have raised it.
    let floor = conn
        .send_pn_res
        .high_water()
        .max(conn.one_rtt.next_send_pn);
    s.conns[idx] = conn;
    let c = &mut s.conns[idx];
    c.phase = ConnPhase::Established;
    c.cont_epoch = new_epoch;
    // A retained read phase is retained from now: the window the primary
    // was counting is not this host's clock.
    if c.one_rtt.prev_read_valid {
        c.one_rtt.prev_read_since_ms = dev_millis(&*s.syscalls);
    }
    // Resume the send reservation at the floor, fenced by the new epoch.
    // Every number below it belonged to the dead host's blocks and is never
    // re-emitted; local self-grant starts from here.
    c.send_pn_res = NonceReservation::resume(new_epoch, floor);
    c.pn_res_durable = false;
    c.one_rtt.next_send_pn = floor;
    // Restore anti-amplification / path-validation posture: a changed path
    // does not inherit unrestricted sending credit.
    c.bytes_in_flight = 0;
    c.congestion_window = INITIAL_WINDOW;
    c.ssthresh = u64::MAX;
    c.recovery_start_time = 0;
    c.last_activity_ms = dev_millis(&*s.syscalls);
    s.continuity.last_fence_gen = fence_gen;
    idx as i32
}

/// Find a free live slot for an activated shadow.
unsafe fn alloc_shadow_live_slot(s: &QuicState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase == ConnPhase::Idle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// RETIRE the old owner: destroy its keys and replicated buffers.
/// Zeroizes every secret so a test can prove custody ended.
unsafe fn retire_connection(conn: &mut QuicConnection) {
    zero_secret(&mut conn.one_rtt.read_secret);
    zero_secret(&mut conn.one_rtt.write_secret);
    zero_secret(&mut conn.one_rtt.next_read_secret);
    zero_secret(&mut conn.one_rtt.next_write_secret);
    conn.one_rtt.read_keys = QuicKeys::empty();
    conn.one_rtt.write_keys = QuicKeys::empty();
    conn.one_rtt.next_read_keys = QuicKeys::empty();
    conn.one_rtt.next_write_keys = QuicKeys::empty();
    conn.one_rtt.prev_read_keys = QuicKeys::empty();
    conn.one_rtt.prev_read_valid = false;
    conn.one_rtt.keys_set = false;
    conn.one_rtt.next_keys_ready = false;
    let mut z = 0;
    while z < 48 {
        core::ptr::write_volatile(&mut conn.psk[z], 0);
        z += 1;
    }
    conn.psk_len = 0;
    conn.phase = ConnPhase::Closed;
}

fn zero_secret(buf: &mut [u8; 48]) {
    let mut i = 0;
    while i < 48 {
        unsafe { core::ptr::write_volatile(&mut buf[i], 0) };
        i += 1;
    }
}

// ─── Shadow slot management + cont_in dispatch ─────────────────────────

fn flow_eq(a: &[u8; CONT_FLOW_ID_BYTES], b: &[u8]) -> bool {
    b.len() == CONT_FLOW_ID_BYTES && &a[..] == b
}

unsafe fn find_shadow(s: &QuicState, flow: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_SHADOW_SLOTS {
        if s.continuity.shadows[i].phase != ShadowPhase::Free
            && flow_eq(&s.continuity.shadows[i].flow_id, flow)
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

unsafe fn free_shadow(s: &QuicState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_SHADOW_SLOTS {
        if s.continuity.shadows[i].phase == ShadowPhase::Free {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Emit an `MSG_SC_CONTINUITY` reply on `cont_out`.
unsafe fn cont_reply(
    s: &mut QuicState,
    flow: &[u8],
    epoch: u32,
    record: u8,
    status: u8,
    body: &[u8],
) -> bool {
    if s.cont_out < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let mut payload = [0u8; sc::CONTINUITY_HEADER_LEN + 64];
    let mut p = 0;
    let fl = flow.len().min(CONT_FLOW_ID_BYTES);
    payload[..fl].copy_from_slice(&flow[..fl]);
    p += CONT_FLOW_ID_BYTES;
    payload[p..p + 4].copy_from_slice(&epoch.to_le_bytes());
    p += 4;
    payload[p] = record;
    p += 1;
    payload[p] = status;
    p += 1;
    let n = body.len().min(payload.len() - p);
    payload[p..p + n].copy_from_slice(&body[..n]);
    p += n;
    let mut scratch = [0u8; NET_FRAME_HDR + sc::CONTINUITY_HEADER_LEN + 64];
    net_write_frame(
        sys,
        s.cont_out,
        sc::MSG_SC_CONTINUITY,
        payload.as_ptr(),
        p,
        scratch.as_mut_ptr(),
        scratch.len(),
    ) != 0
}

/// Handle one framed command on `cont_in`. `payload` is the frame body
/// (past the 3-byte TLV header). This is the whole CT_QUIC lifecycle.
unsafe fn cont_apply(s: &mut QuicState, msg_type: u8, payload: &[u8]) {
    match msg_type {
        CONT_RESERVATION_GRANT => cont_apply_grant(s, payload),
        sc::CMD_SC_PAIR_PREPARE => cont_apply_pair_prepare(s, payload),
        sc::CMD_SC_QUIESCE_BEGIN => cont_apply_quiesce(s, payload, true),
        sc::CMD_SC_QUIESCE_STATUS => cont_apply_quiesce(s, payload, false),
        sc::CMD_SC_CUT_EXPORT => cont_apply_cut_export(s, payload),
        sc::CMD_SC_CHECKPOINT_BEGIN => cont_apply_ckpt_begin(s, payload),
        sc::CMD_SC_CHECKPOINT_NEXT => cont_apply_ckpt_next(s, payload),
        sc::CMD_SC_CHECKPOINT_COMMIT => cont_apply_ckpt_commit(s, payload),
        sc::CMD_SC_DELTA_APPLY => cont_apply_delta(s, payload),
        sc::CMD_SC_DELTA_ACK => cont_apply_delta_ack(s, payload),
        sc::CMD_SC_CUT_IMPORT => cont_apply_cut_import(s, payload),
        sc::CMD_SC_EMISSION_ARM => cont_apply_emission_arm(s, payload),
        sc::CMD_SC_ACTIVATE => cont_apply_activate(s, payload),
        sc::CMD_SC_RETIRE => cont_apply_retire(s, payload),
        sc::CMD_SC_ABORT => cont_apply_abort(s, payload),
        sc::MSG_SC_CONTINUITY => cont_apply_relayed(s, payload),
        _ => {}
    }
}

/// Find a live (non-shadow) connection by its bound continuity flow id.
unsafe fn find_live_by_flow(s: &QuicState, flow: &[u8]) -> Option<usize> {
    // A connection that was never bound to a flow keeps the all-zero id it
    // was constructed with, so a zeroed flow would match the first live
    // connection and hand an unrelated session to RETIRE or CUT_EXPORT.
    if flow.iter().all(|b| *b == 0) {
        return None;
    }
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase != ConnPhase::Idle && &s.conns[i].cont_flow_id[..] == flow {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// QUIESCE_BEGIN / QUIESCE_STATUS on the primary: stop admitting new
/// application delivery and report drained state. The pending
/// counters are the outbound / inbound stream bytes still buffered.
unsafe fn cont_apply_quiesce(s: &mut QuicState, payload: &[u8], _begin: bool) {
    if payload.len() < sc::FLOW_HEADER_LEN {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let idx = match find_live_by_flow(s, &flow) {
        Some(i) => i,
        None => return,
    };
    let (out_pending, in_pending) = {
        let c = &s.conns[idx];
        let mut op: u32 = c.stream_send_buf_len as u32;
        let mut ip: u32 = c.stream_recv_buf_len as u32;
        let mut k = 0;
        while k < MAX_BIDI_STREAMS {
            op += c.bidi_streams[k].send_buf_len as u32;
            ip += c.bidi_streams[k].recv_buf_len as u32;
            k += 1;
        }
        (op, ip)
    };
    let drained = if out_pending == 0 && in_pending == 0 {
        1u8
    } else {
        0u8
    };
    let mut body = [0u8; 9];
    body[0] = drained;
    body[1..5].copy_from_slice(&out_pending.to_le_bytes());
    body[5..9].copy_from_slice(&in_pending.to_le_bytes());
    cont_reply(s, &flow, epoch, sc::CR_QUIESCED, sc::STATUS_OK, &body);
}

/// CUT_EXPORT on the primary: produce the full checkpoint now, emit
/// CHECKPOINT_BEGIN / NEXT* / COMMIT on `cont_out`, then `CR_CUT` carrying
/// the manifest (the sealed continuity object rides in the manifest body).
unsafe fn cont_apply_cut_export(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::FLOW_HEADER_LEN {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let idx = match find_live_by_flow(s, &flow) {
        Some(i) => i,
        None => return,
    };
    if s.conns[idx].cont_profile == 0 {
        // Never paired: there is no profile to say whether this host stops
        // emitting at the cut or mirrors on, and either guess is unsafe.
        cont_reply(
            s,
            &flow,
            epoch,
            sc::CR_ABORTED,
            sc::STATUS_CORRUPT,
            &[sc::ABORT_UNSUPPORTED_STATE],
        );
        return;
    }
    let mut rec = [0u8; CHECKPOINT_RECORD_MAX];
    let n = serialize_checkpoint(s, idx, &flow, epoch, &mut rec);
    if n == 0 {
        cont_reply(
            s,
            &flow,
            epoch,
            sc::CR_ABORTED,
            sc::STATUS_CORRUPT,
            &[sc::ABORT_UNSUPPORTED_STATE],
        );
        return;
    }
    if s.conns[idx].cont_profile == sc::PROFILE_PLANNED {
        // The record above carries this host's high-water as the floor the
        // standby resumes from. That is a promise about this host: it
        // emits nothing at or beyond it from now on. Voiding the
        // reservation keeps the promise here, where the emit gate reads
        // it, rather than trusting the host to stop.
        s.conns[idx].send_pn_res.void_outstanding();
    }
    let ckpt_gen = s.conns[idx].cont_delta_no.wrapping_add(1);
    let digest = record_sha256(&rec[..n]);
    let crc = handoff_crc32(&rec[..n]);
    emit_checkpoint_stream(s, &flow, epoch, ckpt_gen, &rec[..n], &digest, crc);
    // The cut manifest names the record and carries the sealed object
    // (the sealed secret set already lives inside the record's tail).
    let mut body = [0u8; 4 + 4 + 32 + 1 + 2];
    body[..4].copy_from_slice(&ckpt_gen.to_le_bytes());
    body[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    body[8..40].copy_from_slice(&digest);
    body[40] = sc::CT_QUIC;
    body[41..43].copy_from_slice(&0u16.to_le_bytes());
    cont_reply(s, &flow, epoch, sc::CR_CUT, sc::STATUS_OK, &body);
}

/// Chunk a checkpoint record onto `cont_out` as CHECKPOINT_BEGIN /
/// CHECKPOINT_NEXT* / CHECKPOINT_COMMIT (CRC32 over the chunk stream).
unsafe fn emit_checkpoint_stream(
    s: &mut QuicState,
    flow: &[u8; CONT_FLOW_ID_BYTES],
    epoch: u32,
    ckpt_gen: u32,
    record: &[u8],
    digest: &[u8; 32],
    crc: u32,
) {
    if s.cont_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    // BEGIN.
    {
        let mut p = [0u8; sc::CHECKPOINT_BEGIN_PAYLOAD_LEN];
        p[..16].copy_from_slice(flow);
        p[16..20].copy_from_slice(&epoch.to_le_bytes());
        p[20..24].copy_from_slice(&ckpt_gen.to_le_bytes());
        p[24..28].copy_from_slice(&(record.len() as u32).to_le_bytes());
        p[28..60].copy_from_slice(digest);
        let mut scr = [0u8; NET_FRAME_HDR + sc::CHECKPOINT_BEGIN_PAYLOAD_LEN];
        net_write_frame(
            sys,
            s.cont_out,
            sc::CMD_SC_CHECKPOINT_BEGIN,
            p.as_ptr(),
            p.len(),
            scr.as_mut_ptr(),
            scr.len(),
        );
    }
    // NEXT chunks.
    let mut off = 0usize;
    while off < record.len() {
        let take = (record.len() - off).min(sc::CHECKPOINT_CHUNK_MAX);
        let mut p = [0u8; sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX];
        p[..16].copy_from_slice(flow);
        p[16..20].copy_from_slice(&epoch.to_le_bytes());
        p[20..24].copy_from_slice(&ckpt_gen.to_le_bytes());
        p[24..28].copy_from_slice(&(off as u32).to_le_bytes());
        p[sc::CHECKPOINT_NEXT_HEADER_LEN..sc::CHECKPOINT_NEXT_HEADER_LEN + take]
            .copy_from_slice(&record[off..off + take]);
        let mut scr =
            [0u8; NET_FRAME_HDR + sc::CHECKPOINT_NEXT_HEADER_LEN + sc::CHECKPOINT_CHUNK_MAX];
        net_write_frame(
            sys,
            s.cont_out,
            sc::CMD_SC_CHECKPOINT_NEXT,
            p.as_ptr(),
            sc::CHECKPOINT_NEXT_HEADER_LEN + take,
            scr.as_mut_ptr(),
            scr.len(),
        );
        off += take;
    }
    // COMMIT.
    {
        let mut p = [0u8; sc::CHECKPOINT_COMMIT_PAYLOAD_LEN];
        p[..16].copy_from_slice(flow);
        p[16..20].copy_from_slice(&epoch.to_le_bytes());
        p[20..24].copy_from_slice(&ckpt_gen.to_le_bytes());
        p[24..28].copy_from_slice(&crc.to_le_bytes());
        let mut scr = [0u8; NET_FRAME_HDR + sc::CHECKPOINT_COMMIT_PAYLOAD_LEN];
        net_write_frame(
            sys,
            s.cont_out,
            sc::CMD_SC_CHECKPOINT_COMMIT,
            p.as_ptr(),
            p.len(),
            scr.as_mut_ptr(),
            scr.len(),
        );
    }
}

// ─── Mirroring: the primary's half ──────────────────────────────────
//
// Once the standby holds a committed checkpoint, every 1-RTT transition
// on the primary is an ordered delta on `cont_out`: a packet's number and
// ciphertext as it goes out, the largest number received as a packet is
// consumed, a key-phase flip as it happens. The standby applies them in
// order against its shadow; the chain is numbered from 1 and each delta
// carries the digest of the previous one's data.
//
// Under `PROFILE_CRASH_CONTINUOUS` the transitions are horizons. A packet
// is not put on the wire until the DELTA_ACK covering it has returned, so
// a takeover retransmits ciphertext the peer may already hold rather than
// emitting bytes the standby never saw. A received number is not
// acknowledged to the peer until its delta is confirmed, so an
// acknowledgement the peer relies on is one a takeover can honour.
//
// A delta the channel cannot take ends the pair: the primary runs on
// unmirrored, and the coordinator is told so a stale shadow is never
// activated.

/// Largest delta this side emits: header, a packet number, and a packet.
const MIRROR_DELTA_MAX: usize = sc::DELTA_APPLY_HEADER_LEN + 8 + 1500;

/// Put one delta on `cont_out` and advance the chain. Answers the delta
/// number, or 0 when the channel would not take it — the chain is left
/// untouched so nothing is numbered that never went.
unsafe fn mirror_delta(
    sys: &SyscallTable,
    cont_out: i32,
    conn: &mut QuicConnection,
    kind: u8,
    data: &[u8],
) -> u32 {
    if cont_out < 0 || !conn.cont_mirror || data.len() > MIRROR_DELTA_MAX - sc::DELTA_APPLY_HEADER_LEN {
        return 0;
    }
    let no = conn.cont_delta_no.wrapping_add(1);
    let mut payload = [0u8; MIRROR_DELTA_MAX];
    let mut p = 0;
    payload[p..p + CONT_FLOW_ID_BYTES].copy_from_slice(&conn.cont_flow_id);
    p += CONT_FLOW_ID_BYTES;
    payload[p..p + 4].copy_from_slice(&conn.cont_epoch.to_le_bytes());
    p += 4;
    payload[p..p + 4].copy_from_slice(&conn.cont_ckpt_gen.to_le_bytes());
    p += 4;
    payload[p..p + 4].copy_from_slice(&no.to_le_bytes());
    p += 4;
    payload[p..p + 32].copy_from_slice(&conn.cont_last_digest);
    p += 32;
    payload[p] = kind;
    p += 1;
    payload[p..p + data.len()].copy_from_slice(data);
    p += data.len();
    let mut scratch = [0u8; NET_FRAME_HDR + MIRROR_DELTA_MAX];
    if net_write_frame(
        sys,
        cont_out,
        sc::CMD_SC_DELTA_APPLY,
        payload.as_ptr(),
        p,
        scratch.as_mut_ptr(),
        scratch.len(),
    ) == 0
    {
        return 0;
    }
    conn.cont_delta_no = no;
    conn.cont_last_digest = record_sha256(data);
    no
}

/// Mirror a 1-RTT packet about to go out: its number and ciphertext.
pub unsafe fn mirror_send(
    sys: &SyscallTable,
    cont_out: i32,
    conn: &mut QuicConnection,
    pn: u64,
    ct: &[u8],
) -> u32 {
    let mut data = [0u8; 8 + 1500];
    let n = ct.len().min(1500);
    data[..8].copy_from_slice(&pn.to_le_bytes());
    data[8..8 + n].copy_from_slice(&ct[..n]);
    mirror_delta(sys, cont_out, conn, sc::DELTA_QUIC_SEND, &data[..8 + n])
}

/// Mirror the consumption of an inbound 1-RTT packet.
pub unsafe fn mirror_recv(
    sys: &SyscallTable,
    cont_out: i32,
    conn: &mut QuicConnection,
    largest_recv_pn: u64,
) -> u32 {
    mirror_delta(
        sys,
        cont_out,
        conn,
        sc::DELTA_QUIC_RECV,
        &largest_recv_pn.to_le_bytes(),
    )
}

/// Mirror a key-phase flip. The standby derives the new keys itself from
/// the secrets it already holds; the delta carries only the phase the
/// primary is now in, so a shadow that has drifted is caught rather than
/// realigned.
pub unsafe fn mirror_key_phase(
    sys: &SyscallTable,
    cont_out: i32,
    conn: &mut QuicConnection,
) -> u32 {
    let phase = conn.one_rtt.key_phase & 1;
    mirror_delta(sys, cont_out, conn, sc::DELTA_QUIC_KEY_PHASE, &[phase])
}

/// Whether this connection is mirrored under the crash-continuous profile,
/// whose transitions are horizons rather than notifications.
pub fn mirror_strict(conn: &QuicConnection) -> bool {
    conn.cont_mirror && conn.cont_profile == sc::PROFILE_CRASH_CONTINUOUS
}

/// Note an inbound 1-RTT packet under the mirror. Answers whether its
/// acknowledgement to the peer is deferred: under the strict profile the
/// number is held until the standby confirms the delta, and released by
/// [`cont_apply_delta_ack`]. A hold that overflows abandons the mirror —
/// the coordinator learns of it — rather than silently dropping a number.
pub unsafe fn on_one_rtt_received(
    sys: &SyscallTable,
    cont_out: i32,
    conn: &mut QuicConnection,
    pn: u64,
) -> bool {
    if !conn.cont_mirror {
        return false;
    }
    let no = mirror_recv(sys, cont_out, conn, conn.one_rtt.largest_recv_pn);
    if no == 0 {
        mirror_abandon(sys, cont_out, conn);
        return false;
    }
    if !mirror_strict(conn) {
        return false;
    }
    let n = conn.cont_recv_hold_len as usize;
    if n >= CONT_RECV_HOLD {
        mirror_abandon(sys, cont_out, conn);
        return false;
    }
    conn.cont_recv_hold[n] = (pn, no);
    conn.cont_recv_hold_len = (n + 1) as u8;
    true
}

/// The mirror could not carry a transition. The primary runs unmirrored
/// from here; every hold is released, because a horizon with no standby
/// behind it protects nothing; and the coordinator is owed an abort so the
/// stale shadow is never activated. The abort rides the channel that just
/// refused a delta, so it is marked and sent from the step until it goes.
pub unsafe fn mirror_abandon(sys: &SyscallTable, cont_out: i32, conn: &mut QuicConnection) {
    conn.cont_mirror = false;
    conn.cont_horizon_steps = 0;
    // A held packet spent a packet number, so it is owed to the peer
    // whatever became of the mirror: nothing confirms it now, which is
    // itself the confirmation. The per-step service puts it on the wire.
    conn.cont_held_confirmed = conn.cont_emission_held;
    let n = conn.cont_recv_hold_len as usize;
    let mut i = 0;
    while i < n {
        let (pn, _) = conn.cont_recv_hold[i];
        conn.one_rtt.ack_tracker.record(pn, 0);
        conn.one_rtt.ack_pending = true;
        i += 1;
    }
    conn.cont_recv_hold_len = 0;
    conn.cont_abandon_pending = true;
    let _ = flush_abandon(sys, cont_out, conn);
}

/// Send the owed abort for an abandoned mirror; answers whether it went.
unsafe fn flush_abandon(sys: &SyscallTable, cont_out: i32, conn: &mut QuicConnection) -> bool {
    if !conn.cont_abandon_pending {
        return true;
    }
    if cont_out < 0 {
        return false;
    }
    let mut payload = [0u8; sc::CONTINUITY_HEADER_LEN + 1];
    payload[..16].copy_from_slice(&conn.cont_flow_id);
    payload[16..20].copy_from_slice(&conn.cont_epoch.to_le_bytes());
    payload[20] = sc::CR_ABORTED;
    payload[21] = sc::STATUS_OK;
    payload[22] = sc::ABORT_MIRROR_LOST;
    let mut scratch = [0u8; NET_FRAME_HDR + sc::CONTINUITY_HEADER_LEN + 1];
    let went = net_write_frame(
        sys,
        cont_out,
        sc::MSG_SC_CONTINUITY,
        payload.as_ptr(),
        payload.len(),
        scratch.as_mut_ptr(),
        scratch.len(),
    ) != 0;
    if went {
        conn.cont_abandon_pending = false;
    }
    went
}

/// Put a held 1-RTT packet on the wire now that its delta is confirmed.
/// Answers whether it went; a refusal leaves it held for the next step.
unsafe fn release_held(s: &mut QuicState, idx: usize) -> bool {
    if !s.conns[idx].cont_emission_held {
        return true;
    }
    if !s.conns[idx].cont_held_confirmed {
        return false;
    }
    let sys = &*s.syscalls;
    let len = s.conns[idx].one_rtt.last_emitted_len;
    let sent = send_datagram(
        sys,
        s.net_out,
        &s.endpoint,
        &s.conns[idx].peer,
        &s.conns[idx].one_rtt.last_emitted[..len],
        &mut s.net_scratch,
    );
    if sent {
        s.conns[idx].cont_emission_held = false;
        s.conns[idx].cont_held_confirmed = false;
        s.conns[idx].cont_horizon_steps = 0;
        s.conns[idx].last_activity_ms = dev_millis(sys);
    }
    sent
}

/// Per-step service for mirrored connections: owed aborts, held packets
/// whose release is due, and horizons the standby has stopped answering.
unsafe fn cont_service(s: &mut QuicState) {
    let sys = &*s.syscalls;
    let cont_out = s.cont_out;
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase != ConnPhase::Idle {
            if s.conns[i].cont_abandon_pending {
                let _ = flush_abandon(sys, cont_out, &mut s.conns[i]);
            }
            // A confirmed hold is owed to the peer, whether its delta was
            // acknowledged or the mirror ended under it. The release is
            // retried here rather than only on the acknowledgement, since
            // a full wire would otherwise strand the packet: emission is
            // gated behind it, so no further delta — and no further
            // acknowledgement — could come to try again.
            if s.conns[i].cont_emission_held && s.conns[i].cont_held_confirmed {
                let _ = release_held(s, i);
            }
            // A horizon the standby stops answering would hold the
            // connection silent for ever. Past the limit the mirror is
            // abandoned: the coordinator is told, the shadow is dropped,
            // and the connection carries on unmirrored rather than mute.
            let waiting = (s.conns[i].cont_emission_held && !s.conns[i].cont_held_confirmed)
                || s.conns[i].cont_recv_hold_len != 0;
            if mirror_strict(&s.conns[i]) && waiting {
                s.conns[i].cont_horizon_steps = s.conns[i].cont_horizon_steps.saturating_add(1);
                if s.conns[i].cont_horizon_steps > CONT_HORIZON_STEPS {
                    mirror_abandon(sys, cont_out, &mut s.conns[i]);
                    let _ = release_held(s, i);
                }
            } else {
                s.conns[i].cont_horizon_steps = 0;
            }
        }
        i += 1;
    }
}

/// Promote a connection to its next 1-RTT key phase: current keys and
/// secrets become the previous phase's, the pre-derived next phase becomes
/// current, and the phase after that is derived. One definition, because
/// the standby applying a mirrored flip and the primary that flipped must
/// arrive at identical keys.
pub unsafe fn promote_key_phase(c: &mut QuicConnection) {
    let hl = c.one_rtt.secret_len as usize;
    if hl == 0 {
        return;
    }
    // The outgoing read phase is retained, as it is when the primary
    // rotates: a peer's packet still under it may arrive out of order, and
    // a standby that could not open it would fail the connection for a
    // reordering the primary would have tolerated.
    c.one_rtt.prev_read_keys = c.one_rtt.read_keys;
    c.one_rtt.prev_read_valid = true;
    c.one_rtt.read_keys = c.one_rtt.next_read_keys;
    let nr = c.one_rtt.next_read_secret;
    c.one_rtt.read_secret[..hl].copy_from_slice(&nr[..hl]);
    c.one_rtt.write_keys = c.one_rtt.next_write_keys;
    let nw = c.one_rtt.next_write_secret;
    c.one_rtt.write_secret[..hl].copy_from_slice(&nw[..hl]);
    c.one_rtt.key_phase ^= 1;
    let mut r = [0u8; 48];
    next_traffic_secret(&c.one_rtt.read_secret[..hl], &mut r[..hl]);
    let mut w = [0u8; 48];
    next_traffic_secret(&c.one_rtt.write_secret[..hl], &mut w[..hl]);
    c.one_rtt.next_read_secret[..hl].copy_from_slice(&r[..hl]);
    c.one_rtt.next_write_secret[..hl].copy_from_slice(&w[..hl]);
    c.one_rtt.next_read_keys = next_keys(&r[..hl], c.one_rtt.read_keys.hp);
    c.one_rtt.next_write_keys = next_keys(&w[..hl], c.one_rtt.write_keys.hp);
}

/// A reply relayed back from the standby. The one the primary acts on is
/// the committed checkpoint: from then on the connection is mirrored, and
/// the delta chain starts at 1 against that checkpoint's generation.
unsafe fn cont_apply_relayed(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::CONTINUITY_HEADER_LEN + 4 {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let record = payload[20];
    let status = payload[21];
    if record != sc::CR_CHECKPOINT_COMMITTED || status != sc::STATUS_OK {
        return;
    }
    let gen = u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]);
    let Some(idx) = find_live_by_flow(s, &flow) else {
        return;
    };
    let c = &mut s.conns[idx];
    if c.cont_epoch != epoch || c.cont_profile == 0 || gen != c.cont_delta_no.wrapping_add(1) {
        return;
    }
    c.cont_mirror = true;
    c.cont_ckpt_gen = gen;
    c.cont_delta_no = 0;
    c.cont_last_digest = [0; 32];
    c.cont_abandon_pending = false;
}

/// DELTA_APPLY on the standby: apply an ordered mirror delta into the
/// shadow. Gaps / stale duplicates / prev-digest mismatch are
/// refused before mutation.
unsafe fn cont_apply_delta(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::DELTA_APPLY_HEADER_LEN {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let delta_no = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let prev_digest = &payload[28..60];
    let kind = payload[60];
    let data = &payload[sc::DELTA_APPLY_HEADER_LEN..];
    let slot = match find_shadow(s, &flow) {
        Some(i) => i,
        None => return,
    };
    let sh = &mut s.continuity.shadows[slot];
    if sh.phase != ShadowPhase::Committed && sh.phase != ShadowPhase::Imported {
        cont_reply(
            s,
            &flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_NOT_READY,
            &[],
        );
        return;
    }
    // Ordered, strictly consecutive; prev digest must chain.
    if delta_no != sh.last_delta_no.wrapping_add(1)
        || (delta_no > 1 && prev_digest != sh.prev_delta_digest)
    {
        cont_reply(
            s,
            &flow,
            epoch,
            sc::CR_DELTA_APPLIED,
            sc::STATUS_CORRUPT,
            &[],
        );
        return;
    }
    match kind {
        x if x == sc::DELTA_QUIC_SEND => {
            if data.len() >= 8 {
                let pn = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                if pn.wrapping_add(1) > sh.conn.one_rtt.next_send_pn {
                    sh.conn.one_rtt.next_send_pn = pn.wrapping_add(1);
                }
                // Keep the shadow's floor at or above what it has now seen
                // emitted; the delta stream raises it as the primary goes.
                let floor = sh
                    .conn
                    .send_pn_res
                    .high_water()
                    .max(sh.conn.one_rtt.next_send_pn);
                sh.conn.send_pn_res = NonceReservation::resume(sh.conn.cont_epoch, floor);
                let ct = &data[8..];
                let cl = ct.len().min(sh.conn.one_rtt.last_emitted.len());
                sh.conn.one_rtt.last_emitted[..cl].copy_from_slice(&ct[..cl]);
                sh.conn.one_rtt.last_emitted_len = cl;
                sh.conn.one_rtt.last_emitted_pn = pn;
            }
        }
        x if x == sc::DELTA_QUIC_RECV => {
            if data.len() >= 8 {
                let lr = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                if lr > sh.conn.one_rtt.largest_recv_pn {
                    sh.conn.one_rtt.largest_recv_pn = lr;
                }
            }
        }
        x if x == sc::DELTA_QUIC_KEY_PHASE => {
            // The shadow rotates exactly as the primary did, from the
            // secrets it holds; the phase bit it arrives at must be the one
            // the primary reports, or the two have parted and the shadow is
            // worthless.
            promote_key_phase(&mut sh.conn);
            sh.conn.one_rtt.prev_read_since_ms = dev_millis(&*s.syscalls);
            if data.first().map(|b| b & 1) != Some(sh.conn.one_rtt.key_phase) {
                cont_reply(
                    s,
                    &flow,
                    epoch,
                    sc::CR_DELTA_APPLIED,
                    sc::STATUS_CORRUPT,
                    &[],
                );
                return;
            }
        }
        _ => {}
    }
    sh.last_delta_no = delta_no;
    sh.prev_delta_digest = record_sha256(data);
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&sh.ckpt_gen.to_le_bytes());
    body[4..8].copy_from_slice(&delta_no.to_le_bytes());
    cont_reply(s, &flow, epoch, sc::CR_DELTA_APPLIED, sc::STATUS_OK, &body);
}

/// DELTA_ACK on the primary: the standby holds the transition, so the send
/// horizon may advance — release any held 1-RTT emission.
unsafe fn cont_apply_delta_ack(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::DELTA_ACK_PAYLOAD_LEN {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let delta_no = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let Some(idx) = find_live_by_flow(s, &flow) else {
        return;
    };
    if !s.conns[idx].cont_mirror {
        return;
    }
    // Every held acknowledgement whose delta the standby now holds may be
    // shown to the peer.
    {
        let c = &mut s.conns[idx];
        let n = c.cont_recv_hold_len as usize;
        let mut kept = 0;
        let mut i = 0;
        while i < n {
            let (pn, no) = c.cont_recv_hold[i];
            if no <= delta_no {
                c.one_rtt.ack_tracker.record(pn, 0);
                c.one_rtt.ack_pending = true;
            } else {
                c.cont_recv_hold[kept] = (pn, no);
                kept += 1;
            }
            i += 1;
        }
        c.cont_recv_hold_len = kept as u8;
    }
    if s.conns[idx].cont_emission_held && s.conns[idx].cont_held_delta <= delta_no {
        s.conns[idx].cont_held_confirmed = true;
        let _ = release_held(s, idx);
    }
}

/// RETIRE the old owner after the new anchor's stability horizon.
unsafe fn cont_apply_retire(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::FLOW_HEADER_LEN {
        return;
    }
    let mut flow = [0u8; CONT_FLOW_ID_BYTES];
    flow.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    if let Some(idx) = find_live_by_flow(s, &flow) {
        retire_connection(&mut s.conns[idx]);
    }
    cont_reply(s, &flow, epoch, sc::CR_RETIRED, sc::STATUS_OK, &[]);
}

/// Install a durable reservation grant from a `session.reservation`
/// provider.
unsafe fn cont_apply_grant(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < CONT_FLOW_ID_BYTES + sc::GRANT_LEN {
        return;
    }
    let flow = &payload[..CONT_FLOW_ID_BYTES];
    let rec = &payload[CONT_FLOW_ID_BYTES..CONT_FLOW_ID_BYTES + sc::GRANT_LEN];
    let op = rec[0];
    let status = rec[1];
    let epoch = u32::from_le_bytes([rec[18], rec[19], rec[20], rec[21]]);
    let start = u64::from_le_bytes([
        rec[22], rec[23], rec[24], rec[25], rec[26], rec[27], rec[28], rec[29],
    ]);
    let len = u64::from_le_bytes([
        rec[30], rec[31], rec[32], rec[33], rec[34], rec[35], rec[36], rec[37],
    ]);
    if op != sc::GRANT_OP_RESERVE || status != sc::GRANT_STATUS_OK {
        return;
    }
    // Apply to a matching live connection.
    let mut i = 0;
    while i < MAX_CONNS {
        if s.conns[i].phase != ConnPhase::Idle && &s.conns[i].cont_flow_id[..] == flow {
            let _ = s.conns[i].install_pn_grant(epoch, start, len);
            break;
        }
        i += 1;
    }
}

unsafe fn cont_apply_pair_prepare(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::PAIR_PREPARE_PAYLOAD_LEN {
        return;
    }
    let flow = &payload[..CONT_FLOW_ID_BYTES];
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let transport = payload[20];
    let profile = payload[21];
    if transport != sc::CT_QUIC {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_ABORTED,
            sc::STATUS_CORRUPT,
            &[sc::ABORT_UNSUPPORTED_STATE],
        );
        return;
    }
    // The primary's half: a live connection under this flow takes the
    // profile the pair will run under and answers as prepared. It is the
    // profile that decides what CUT_EXPORT does to this host's emission, so
    // a cut on a connection never prepared is refused rather than guessed.
    let mut flow_arr = [0u8; CONT_FLOW_ID_BYTES];
    flow_arr.copy_from_slice(flow);
    if let Some(idx) = find_live_by_flow(s, &flow_arr) {
        if profile == sc::PROFILE_CRASH_CONTINUOUS && !s.conns[idx].pn_res_durable {
            // A self-granted block can be refilled at will, so no floor
            // recorded here bounds what this host may still emit. Crash
            // continuity needs a reservation only a directory grants.
            cont_reply(s, flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_UNSUPPORTED, &[]);
            return;
        }
        s.conns[idx].cont_profile = profile;
        cont_reply(s, flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_OK, &[]);
        return;
    }
    if find_shadow(s, flow).is_some() {
        // Idempotent re-prepare.
        return;
    }
    let slot = match free_shadow(s) {
        Some(i) => i,
        None => {
            cont_reply(
                s,
                flow,
                epoch,
                sc::CR_PAIR_PREPARED,
                sc::STATUS_NO_CAPACITY,
                &[],
            );
            return;
        }
    };
    let sh = &mut s.continuity.shadows[slot];
    sh.phase = ShadowPhase::Prepared;
    sh.flow_id[..].copy_from_slice(flow);
    sh.epoch = epoch;
    sh.transport = transport;
    sh.profile = profile;
    sh.codec_digest.copy_from_slice(&payload[22..54]);
    sh.import = HandoffImport::new();
    sh.last_delta_no = 0;
    sh.conn.reset();
    let body = [
        transport,
        profile,
        (slot as u16) as u8,
        ((slot as u16) >> 8) as u8,
    ];
    cont_reply(s, flow, epoch, sc::CR_PAIR_PREPARED, sc::STATUS_OK, &body);
}

unsafe fn cont_apply_ckpt_begin(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::CHECKPOINT_BEGIN_PAYLOAD_LEN {
        return;
    }
    let flow = &payload[..CONT_FLOW_ID_BYTES];
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let ckpt_gen = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
    let total_len =
        u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]) as usize;
    let slot = match find_shadow(s, flow) {
        Some(i) => i,
        None => return,
    };
    let sh = &mut s.continuity.shadows[slot];
    // A command below the shadow's epoch is stale; one above is a future
    // epoch, refused too — epochs advance only through ACTIVATE.
    if epoch < sh.epoch {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_STALE_EPOCH,
            &[],
        );
        return;
    }
    if epoch > sh.epoch {
        cont_reply(
            s,
            flow,
            epoch,
            sc::CR_CHECKPOINT_ACK,
            sc::STATUS_CORRUPT,
            &[],
        );
        return;
    }
    sh.ckpt_gen = ckpt_gen;
    sh.record_digest.copy_from_slice(&payload[28..60]);
    let st = sh
        .import
        .begin(total_len as u32, CHECKPOINT_RECORD_MAX as u32);
    if st != HANDOFF_OK {
        sh.phase = ShadowPhase::Prepared;
        cont_reply(s, flow, epoch, sc::CR_CHECKPOINT_ACK, st, &[]);
        return;
    }
    sh.phase = ShadowPhase::Receiving;
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&ckpt_gen.to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_CHECKPOINT_ACK, sc::STATUS_OK, &body);
}

unsafe fn cont_apply_ckpt_next(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::CHECKPOINT_NEXT_HEADER_LEN {
        return;
    }
    let flow = &payload[..CONT_FLOW_ID_BYTES];
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let offset = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let data = &payload[sc::CHECKPOINT_NEXT_HEADER_LEN..];
    let slot = match find_shadow(s, flow) {
        Some(i) => i,
        None => return,
    };
    // Split the borrow: copy the record buffer target then feed the importer.
    let st = {
        let sh = &mut s.continuity.shadows[slot];
        if sh.phase != ShadowPhase::Receiving {
            return;
        }
        // The importer writes into `record`; split it out of the struct via
        // a raw pointer so the borrow checker permits the two &mut.
        let rec_ptr = sh.record.as_mut_ptr();
        let rec_len = sh.record.len();
        let dest = core::slice::from_raw_parts_mut(rec_ptr, rec_len);
        sh.import.chunk(offset, data, dest)
    };
    let received = s.continuity.shadows[slot].import.received();
    if st != HANDOFF_OK {
        s.continuity.shadows[slot].phase = ShadowPhase::Prepared;
    }
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&s.continuity.shadows[slot].ckpt_gen.to_le_bytes());
    body[4..8].copy_from_slice(&received.to_le_bytes());
    cont_reply(s, flow, epoch, sc::CR_CHECKPOINT_ACK, st, &body);
}

unsafe fn cont_apply_ckpt_commit(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::CHECKPOINT_COMMIT_PAYLOAD_LEN {
        return;
    }
    let flow_arr = {
        let mut f = [0u8; CONT_FLOW_ID_BYTES];
        f.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
        f
    };
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let crc = u32::from_le_bytes([payload[24], payload[25], payload[26], payload[27]]);
    let slot = match find_shadow(s, &flow_arr) {
        Some(i) => i,
        None => return,
    };
    let (total_len, expected_crc_ok, digest_ok, expected_digest) = {
        let sh = &s.continuity.shadows[slot];
        if sh.phase != ShadowPhase::Receiving {
            return;
        }
        let tl = sh.import.total_len() as usize;
        let ecrc = handoff_crc32(&sh.record[..tl]);
        let d = record_sha256(&sh.record[..tl]);
        (tl, ecrc == crc, d == sh.record_digest, d)
    };
    if !expected_crc_ok || !digest_ok {
        s.continuity.shadows[slot].phase = ShadowPhase::Prepared;
        cont_reply(
            s,
            &flow_arr,
            epoch,
            sc::CR_CHECKPOINT_COMMITTED,
            sc::STATUS_CORRUPT,
            &[],
        );
        return;
    }
    // Import the record into the shadow connection. Move the record out to a
    // scratch to avoid overlapping borrows.
    let mut rec = [0u8; CHECKPOINT_RECORD_MAX];
    rec[..total_len].copy_from_slice(&s.continuity.shadows[slot].record[..total_len]);
    let mut staged = QuicConnection::new();
    let st = import_checkpoint(s, &mut staged, &flow_arr, epoch, &rec[..total_len]);
    if st != sc::STATUS_OK {
        s.continuity.shadows[slot].phase = ShadowPhase::Prepared;
        cont_reply(s, &flow_arr, epoch, sc::CR_CHECKPOINT_COMMITTED, st, &[]);
        return;
    }
    {
        let sh = &mut s.continuity.shadows[slot];
        sh.conn = staged;
        sh.phase = ShadowPhase::Committed;
        sh.record_digest = expected_digest;
    }
    let mut body = [0u8; 4 + 32];
    body[..4].copy_from_slice(&s.continuity.shadows[slot].ckpt_gen.to_le_bytes());
    body[4..].copy_from_slice(&expected_digest);
    cont_reply(
        s,
        &flow_arr,
        epoch,
        sc::CR_CHECKPOINT_COMMITTED,
        sc::STATUS_OK,
        &body,
    );
}

unsafe fn cont_apply_cut_import(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::CUT_IMPORT_PAYLOAD_LEN {
        return;
    }
    let flow_arr = {
        let mut f = [0u8; CONT_FLOW_ID_BYTES];
        f.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
        f
    };
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let manifest_digest = &payload[24..56];
    let slot = match find_shadow(s, &flow_arr) {
        Some(i) => i,
        None => return,
    };
    let sh = &mut s.continuity.shadows[slot];
    if sh.phase != ShadowPhase::Committed || sh.record_digest != manifest_digest {
        cont_reply(
            s,
            &flow_arr,
            epoch,
            sc::CR_IMPORTED,
            sc::STATUS_CORRUPT,
            &[],
        );
        return;
    }
    sh.manifest_digest.copy_from_slice(manifest_digest);
    sh.phase = ShadowPhase::Imported;
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&sh.ckpt_gen.to_le_bytes());
    body[4..8].copy_from_slice(&sh.last_delta_no.to_le_bytes());
    cont_reply(s, &flow_arr, epoch, sc::CR_IMPORTED, sc::STATUS_OK, &body);
}

unsafe fn cont_apply_emission_arm(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::FLOW_HEADER_LEN {
        return;
    }
    let flow_arr = {
        let mut f = [0u8; CONT_FLOW_ID_BYTES];
        f.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
        f
    };
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let slot = match find_shadow(s, &flow_arr) {
        Some(i) => i,
        None => return,
    };
    let sh = &mut s.continuity.shadows[slot];
    if sh.phase != ShadowPhase::Imported {
        cont_reply(s, &flow_arr, epoch, sc::CR_ARMED, sc::STATUS_NOT_READY, &[]);
        return;
    }
    // Convert timers from remaining durations; report any already expired
    // (idle timeout of 0 remaining fires on activation).
    let expired = if sh.conn.idle_timeout_ms == 0 {
        1u8
    } else {
        0u8
    };
    sh.expired_timers = expired;
    sh.phase = ShadowPhase::Armed;
    cont_reply(s, &flow_arr, epoch, sc::CR_ARMED, sc::STATUS_OK, &[expired]);
}

unsafe fn cont_apply_activate(s: &mut QuicState, payload: &[u8]) {
    // [flow_id:16][new_epoch:4][fence_gen:4]
    if payload.len() < sc::ACTIVATE_PAYLOAD_LEN {
        return;
    }
    let flow_arr = {
        let mut f = [0u8; CONT_FLOW_ID_BYTES];
        f.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
        f
    };
    let new_epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let fence_gen = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
    let slot = match find_shadow(s, &flow_arr) {
        Some(i) => i,
        None => return,
    };
    let prior_epoch = s.continuity.shadows[slot].epoch;
    if s.continuity.shadows[slot].phase != ShadowPhase::Armed {
        cont_reply(
            s,
            &flow_arr,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_NOT_READY,
            &[],
        );
        return;
    }
    if fence_gen == 0 || new_epoch <= prior_epoch {
        cont_reply(
            s,
            &flow_arr,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_CORRUPT,
            &[],
        );
        return;
    }
    // Move the shadow connection out and promote it.
    let mut promoted = QuicConnection::new();
    core::mem::swap(&mut promoted, &mut s.continuity.shadows[slot].conn);
    promoted.cont_flow_id = flow_arr;
    let live = activate_shadow(s, promoted, new_epoch, fence_gen, prior_epoch);
    {
        let sh = &mut s.continuity.shadows[slot];
        sh.phase = ShadowPhase::Free;
        sh.conn.reset();
    }
    if live < 0 {
        cont_reply(
            s,
            &flow_arr,
            new_epoch,
            sc::CR_ACTIVATED,
            sc::STATUS_NO_CAPACITY,
            &[],
        );
        return;
    }
    let conn_id = live as u16;
    let mut body = [0u8; 6];
    body[..4].copy_from_slice(&new_epoch.to_le_bytes());
    body[4..6].copy_from_slice(&conn_id.to_le_bytes());
    cont_reply(
        s,
        &flow_arr,
        new_epoch,
        sc::CR_ACTIVATED,
        sc::STATUS_OK,
        &body,
    );
}

unsafe fn cont_apply_abort(s: &mut QuicState, payload: &[u8]) {
    if payload.len() < sc::ABORT_PAYLOAD_LEN {
        return;
    }
    let flow_arr = {
        let mut f = [0u8; CONT_FLOW_ID_BYTES];
        f.copy_from_slice(&payload[..CONT_FLOW_ID_BYTES]);
        f
    };
    let epoch = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let reason = payload[20];
    if let Some(slot) = find_shadow(s, &flow_arr) {
        let sh = &mut s.continuity.shadows[slot];
        sh.phase = ShadowPhase::Free;
        // Discard the shadow whole: zeroize any staged secrets.
        retire_connection(&mut sh.conn);
        sh.conn.reset();
    }
    cont_reply(
        s,
        &flow_arr,
        epoch,
        sc::CR_ABORTED,
        sc::STATUS_OK,
        &[reason],
    );
}

/// Drain framed commands from `cont_in` once per step. Bounded work.
unsafe fn cont_pump(s: &mut QuicState) {
    cont_service(s);
    if s.cont_in < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut budget = 0;
    while budget < 8 {
        let poll = (sys.channel_poll)(s.cont_in, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let mut buf = [0u8; NET_FRAME_HDR + CHECKPOINT_RECORD_MAX];
        let (mt, plen) = net_read_frame(sys, s.cont_in, buf.as_mut_ptr(), buf.len());
        if mt == 0 && plen == 0 {
            break;
        }
        // net_read_frame leaves the payload at buf[3..]. `buf` is a local,
        // disjoint from `s`, so the payload slice can be handed to the
        // dispatcher directly without a copy.
        let payload_end = NET_FRAME_HDR + plen.min(buf.len() - NET_FRAME_HDR);
        let split = buf.split_at(NET_FRAME_HDR);
        let payload = &split.1[..payload_end - NET_FRAME_HDR];
        cont_apply(s, mt, payload);
        budget += 1;
    }
}
