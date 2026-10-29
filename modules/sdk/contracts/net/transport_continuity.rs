// TRANSPORT_CONTINUITY — the TCP/TLS continuity surface: one
// established TCP connection carrying TLS 1.3, checkpointed, mirrored and
// moved between hosts as ONE canonical logical record, driven by an anchor
// over generation-checked handles.
//
// Layer: contracts (portable wire vocabulary). The provider that answers it
// is `cores/transport_continuity.rs`; a consumer includes this file, then
// that one, with `sha256(&[u8]) -> [u8; 32]` and `Sha256`
// (`crypto/sha256.rs`) in scope.
//
// What it carries, in order:
//
// - the canonical record (`TsState`, magic `WHTC`): the four-tuple and
//   local-address generation, which end opened the connection, negotiated
//   TCP options, the TCP state and every sequence variable, unacknowledged
//   send bytes at their exact range, accepted-but-undelivered receive bytes
//   and out-of-order segments, SACK/timestamp and recovery state, timers as
//   bounded REMAINING durations, congestion state, the TLS 1.3 record layer
//   (suite, read/write epochs and record numbers, the KeyUpdate answer owed
//   and close-notify state), the pending outbound records with their
//   production ids, the delivery cursor and pending deliveries with their
//   delivery ids, and the flow, session, route, mirror and binding
//   generations. There is no field a key can occupy: traffic secrets are
//   `TsVaultRef`s, opaque references meaningful only to the vault that
//   issued them;
// - its chunked transfer (`WHCC`) and the standby's shadow assembler, which
//   publishes only a whole, validated record;
// - the ordered mirror deltas (`WHMD`), the deterministic transition each
//   applies (`md_apply`) and the standby's ordering rule (`MdOrder`);
// - the provider frames: anchor → provider operations (`tc_op`), provider
//   → anchor events (`tc_evt`), statuses, the handle, the planned cut and
//   the capability bits a provider reports.
//
// The bounds are TLS 1.3's record limit, so a crash-continuous pair over a
// stock peer keeps its protection for every record the peer may send: a
// delivery holds a record's whole plaintext (2^14 bytes), the receive buffer
// a whole protected record (`TS_RECV_MAX`), a delta's payload either of them
// with its fields (`MD_PAYLOAD_MAX`), and a checkpoint of up to
// `TS_CKPT_MAX` crosses in chunks of 16 KiB. The record names which end
// opened the connection (`TS_FLAG_CLIENT`): a client session's `client_*`
// is this host and `service_*` the remote server.
//
// The bytes are fixed: this provider and the anchors that drive it hold the
// same reference vector (`tools/src/transport_continuity.rs` pins the record
// digest), and every decoder refuses a version byte other than
// `TS_VERSION` / `MD_VERSION`.
//
// How this relates to session_ctrl.rs §Transport continuity: that surface
// is per layer — `ip` checkpoints its TCP control block (`FXTC`), `tls` its
// record layer, `quic` its connection — for a Fluxor-side mirror that moves
// a connection a stack owns end to end. This one is the single-flow surface
// an anchor drives, with the TCP and TLS halves of one connection in
// one record so that a delta is one atomic transition of both. Two
// providers answer it: `cores/transport_continuity.rs` owns the state it
// checkpoints (a host feeds it segments and records), and the
// `transport_continuity` module realises it over a graph's `ip` and `tls`,
// composing this record from the two per-layer halves they export and
// splitting it back into the two they import
// (`modules/foundation/transport_continuity/stack.rs`).
//
// Pure, `no_std`, allocation-free.

// ── byte cursors and wire enums ───────────────────────────────────────────

/// A wire enum: each variant names the byte it is on the wire (`wire`,
/// `from_u8`). In memory a variant is its position, so the first one listed
/// is the all-zero value: a zeroed slot holds it.
macro_rules! tc_wire_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident = $v:expr),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[repr(u8)]
        pub enum $name { $($variant),+ }

        impl $name {
            /// The byte this variant is on the wire.
            pub const fn wire(self) -> u8 {
                match self {
                    $(Self::$variant => $v,)+
                }
            }

            pub fn from_u8(v: u8) -> Option<Self> {
                match v {
                    $($v => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

/// A bounded little-endian writer. Every `put` returns `None` once the
/// buffer is exhausted, so an encoding is whole or absent, never truncated.
pub struct TcW<'a> {
    pub buf: &'a mut [u8],
    pub at: usize,
}

impl<'a> TcW<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn bytes(&mut self, b: &[u8]) -> Option<()> {
        let end = self.at.checked_add(b.len())?;
        if end > self.buf.len() {
            return None;
        }
        self.buf[self.at..end].copy_from_slice(b);
        self.at = end;
        Some(())
    }

    pub fn u8(&mut self, v: u8) -> Option<()> {
        self.bytes(&[v])
    }

    pub fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }
}

/// A bounded little-endian reader; `None` past the end.
pub struct TcR<'a> {
    pub buf: &'a [u8],
    pub at: usize,
}

impl<'a> TcR<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.at..end];
        self.at = end;
        Some(s)
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_le_bytes(a))
    }

    pub fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Some(a)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }
}

fn tc_le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn tc_le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn tc_le_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn tc_id16(b: &[u8], at: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    a
}

tc_wire_enum!(
    /// The transport a pairing moves. This record is `TcpTls`'s.
    TcTransport { TcpTls = 1, Quic = 2, Datagram = 3 }
);

tc_wire_enum!(
    /// `PlannedOnly` may mirror asynchronously and take a synchronous cut
    /// at quiesce; only `CrashContinuous` survives unexpected primary
    /// loss, and only with both strict horizons.
    TcMode { PlannedOnly = 1, CrashContinuous = 2 }
);

tc_wire_enum!(
    /// Which side of the pair a provider's flow holds. `Standby` is listed
    /// first: an unpaired slot's role.
    TcRole { Standby = 2, Primary = 1 }
);

/// TLS 1.3 cipher suites whose established state the record carries.
pub const TC_TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TC_TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TC_TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub fn tc_suite_supported(s: u16) -> bool {
    matches!(
        s,
        TC_TLS_AES_128_GCM_SHA256 | TC_TLS_AES_256_GCM_SHA384 | TC_TLS_CHACHA20_POLY1305_SHA256
    )
}

// ── the canonical record ──────────────────────────────────────────────────

// ── bounds ────────────────────────────────────────────────────────────────

/// Unacknowledged plus queued outbound ciphertext one flow may hold.
pub const TS_SEND_MAX: usize = 32 * 1024;
/// In-order received bytes not yet consumed by the record layer: a whole
/// protected TLS 1.3 record (2^14 + 256 + 5 = 16 645) fits.
pub const TS_RECV_MAX: usize = 16_704;
/// Out-of-order segments held, and the bytes of each.
pub const TS_OOO_MAX: usize = 4;
pub const TS_OOO_SEG: usize = 512;
/// Pending deliveries (decrypted, handed or to be handed to the worker),
/// and the plaintext of each: one record's (2^14).
pub const TS_DELIV_MAX: usize = 8;
pub const TS_DELIV_BYTES: usize = 16 * 1024;
/// Outbound TLS records still in the send buffer.
pub const TS_TXREC_MAX: usize = 32;
/// Remaining-duration ceiling for any imported timer (ms).
pub const TS_TIMER_MAX_MS: u32 = 120_000;
/// Largest encoded checkpoint: every buffer above full, and the fields.
pub const TS_CKPT_MAX: usize = 192 * 1024;

pub const TS_MAGIC: [u8; 4] = *b"WHTC";
pub const TS_VERSION: u8 = 1;
/// Record flags (the header's u16): the local end opened the connection.
pub const TS_FLAG_CLIENT: u16 = 1;

// Each buffer's length is a u16 field of the record: `send_len`,
// `recv_len` and a delivery's `len` must each hold its bound.
const _: () = assert!(TS_SEND_MAX <= u16::MAX as usize);
const _: () = assert!(TS_RECV_MAX <= u16::MAX as usize);
const _: () = assert!(TS_DELIV_BYTES <= u16::MAX as usize);
// A record at every bound fits a checkpoint (`ts_put`'s fields, then the
// digest).
const _: () = assert!(
    TS_CKPT_MAX
        >= 512
            + TS_SEND_MAX
            + TS_RECV_MAX
            + TS_OOO_MAX * (6 + TS_OOO_SEG)
            + TS_TXREC_MAX * 26
            + TS_DELIV_MAX * (10 + TS_DELIV_BYTES)
            + 32
);

tc_wire_enum!(
    /// The TCP states a checkpoint represents (RFC 9293 numbering).
    /// LISTEN, SYN-SENT and SYN-RECEIVED have no established transport to
    /// migrate and are not representable.
    TsTcp {
        Established = 4,
        CloseWait = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        Closing = 8,
        LastAck = 9,
        TimeWait = 10,
    }
);

tc_wire_enum!(
    /// The TLS phase. Only `Established` is admitted.
    TsTlsPhase { Established = 1, Handshake = 2, EarlyData = 3, PostHandshakeAuth = 4 }
);

/// An opaque, owner-scoped vault object reference: which backend, which
/// object, which generation of it and which traffic epoch it keys. Only the
/// vault that issued it can resolve it; to anyone else it is 16 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TsVaultRef {
    pub backend: u8,
    /// 1 = read (peer → us) traffic secret, 2 = write.
    pub purpose: u8,
    pub object: u32,
    pub generation: u32,
    pub epoch: u32,
}

pub const TS_VAULT_READ: u8 = 1;
pub const TS_VAULT_WRITE: u8 = 2;

impl TsVaultRef {
    fn put(&self, w: &mut TcW<'_>) -> Option<()> {
        w.u8(self.backend)?;
        w.u8(self.purpose)?;
        w.u16(0)?;
        w.u32(self.object)?;
        w.u32(self.generation)?;
        w.u32(self.epoch)
    }

    fn get(r: &mut TcR<'_>) -> Result<Self, CkptError> {
        let backend = r.u8().ok_or(CkptError::Truncated)?;
        let purpose = r.u8().ok_or(CkptError::Truncated)?;
        if r.u16().ok_or(CkptError::Truncated)? != 0 {
            return Err(CkptError::Reserved);
        }
        Ok(Self {
            backend,
            purpose,
            object: r.u32().ok_or(CkptError::Truncated)?,
            generation: r.u32().ok_or(CkptError::Truncated)?,
            epoch: r.u32().ok_or(CkptError::Truncated)?,
        })
    }
}

/// One outbound TLS record still in the send buffer: where its ciphertext
/// sits in sequence space and what it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TsTxRec {
    pub tcp_seq: u32,
    pub len: u16,
    pub epoch: u32,
    pub record_seq: u64,
    /// The worker production id the record carries (0 = a record the TLS
    /// layer made itself: KeyUpdate, close_notify, an alert).
    pub production_id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TsOoo {
    pub seq: u32,
    pub len: u16,
    pub bytes: [u8; TS_OOO_SEG],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TsDelivery {
    pub id: u64,
    pub len: u16,
    pub bytes: [u8; TS_DELIV_BYTES],
}

/// The canonical replicated state of one TCP/TLS connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TsState {
    pub flow_id: [u8; 16],
    pub service_id: [u8; 16],
    /// 4 or 6. An IPv4 address is the first four bytes of its field, the
    /// other twelve zero.
    pub family: u8,
    pub client_ip: [u8; 16],
    pub client_port: u16,
    pub service_ip: [u8; 16],
    pub service_port: u16,
    pub local_addr_gen: u32,
    pub iface: u32,
    pub mss: u16,
    pub wscale_snd: u8,
    pub wscale_rcv: u8,
    pub sack_ok: bool,
    pub ts_ok: bool,

    pub tcp: TsTcp,
    pub iss: u32,
    pub irs: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    /// The local FIN is queued after the send buffer's last byte.
    pub fin_queued: bool,
    /// The peer's FIN was received (and consumed one sequence number).
    pub fin_rcvd: bool,
    pub send_len: u16,
    pub send: [u8; TS_SEND_MAX],
    pub recv_len: u16,
    pub recv: [u8; TS_RECV_MAX],
    pub ooo_count: u8,
    pub ooo: [TsOoo; TS_OOO_MAX],
    pub ts_recent: u32,
    pub dupacks: u8,
    pub in_recovery: bool,
    pub recovery_point: u32,

    pub rto_ms: u32,
    pub persist_ms: u32,
    pub keepalive_ms: u32,
    pub timewait_ms: u32,
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub cwnd: u32,
    pub ssthresh: u32,

    pub tls_phase: TsTlsPhase,
    pub suite: u16,
    pub read_epoch: u32,
    pub read_seq: u64,
    pub write_epoch: u32,
    pub write_seq: u64,
    /// The peer asked for a KeyUpdate we have not answered.
    pub key_update_owed: bool,
    pub close_notify_sent: bool,
    pub close_notify_rcvd: bool,
    pub peer_verified: bool,
    pub alpn: u16,
    pub sni_digest: [u8; 32],
    pub exporter_digest: [u8; 32],
    pub read_key: TsVaultRef,
    pub write_key: TsVaultRef,
    /// Digest of the destination-bound wrapped continuity object the last
    /// transfer moved (zero before one).
    pub wrapped_digest: [u8; 32],
    pub tx_count: u8,
    pub tx: [TsTxRec; TS_TXREC_MAX],

    pub next_delivery: u64,
    pub delivery_acked: u64,
    pub deliv_count: u8,
    pub deliv: [TsDelivery; TS_DELIV_MAX],
    pub next_production: u64,

    pub flow_epoch: u32,
    pub session_epoch: u32,
    pub route_generation: u64,
    pub mirror_generation: u64,
    pub binding_epoch: u32,

    /// The local end opened the connection (`TS_FLAG_CLIENT`), so
    /// `service_*` is the remote server and `client_*` this host.
    pub local_client: bool,
}

impl TsState {
    /// Every field zero (the first variant of each enum): an unused
    /// slot's state, and what a decode starts from. All-zero memory is this
    /// value.
    pub const fn zero() -> Self {
        Self {
            flow_id: [0; 16],
            service_id: [0; 16],
            family: 0,
            client_ip: [0; 16],
            client_port: 0,
            service_ip: [0; 16],
            service_port: 0,
            local_addr_gen: 0,
            iface: 0,
            mss: 0,
            wscale_snd: 0,
            wscale_rcv: 0,
            sack_ok: false,
            ts_ok: false,
            tcp: TsTcp::Established,
            iss: 0,
            irs: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            fin_queued: false,
            fin_rcvd: false,
            send_len: 0,
            send: [0; TS_SEND_MAX],
            recv_len: 0,
            recv: [0; TS_RECV_MAX],
            ooo_count: 0,
            ooo: [TsOoo {
                seq: 0,
                len: 0,
                bytes: [0; TS_OOO_SEG],
            }; TS_OOO_MAX],
            ts_recent: 0,
            dupacks: 0,
            in_recovery: false,
            recovery_point: 0,
            rto_ms: 0,
            persist_ms: 0,
            keepalive_ms: 0,
            timewait_ms: 0,
            srtt_us: 0,
            rttvar_us: 0,
            cwnd: 0,
            ssthresh: 0,
            tls_phase: TsTlsPhase::Established,
            suite: 0,
            read_epoch: 0,
            read_seq: 0,
            write_epoch: 0,
            write_seq: 0,
            key_update_owed: false,
            close_notify_sent: false,
            close_notify_rcvd: false,
            peer_verified: false,
            alpn: 0,
            sni_digest: [0; 32],
            exporter_digest: [0; 32],
            read_key: TsVaultRef {
                backend: 0,
                purpose: 0,
                object: 0,
                generation: 0,
                epoch: 0,
            },
            write_key: TsVaultRef {
                backend: 0,
                purpose: 0,
                object: 0,
                generation: 0,
                epoch: 0,
            },
            wrapped_digest: [0; 32],
            tx_count: 0,
            tx: [TsTxRec {
                tcp_seq: 0,
                len: 0,
                epoch: 0,
                record_seq: 0,
                production_id: 0,
            }; TS_TXREC_MAX],
            next_delivery: 0,
            delivery_acked: 0,
            deliv_count: 0,
            deliv: [TsDelivery {
                id: 0,
                len: 0,
                bytes: [0; TS_DELIV_BYTES],
            }; TS_DELIV_MAX],
            next_production: 0,
            flow_epoch: 0,
            session_epoch: 0,
            route_generation: 0,
            mirror_generation: 0,
            binding_epoch: 0,
            local_client: false,
        }
    }

    /// An established TLS 1.3 connection before any byte moved: sequence
    /// numbers at 1, a 1460-byte MSS, 65 535-byte windows, the application
    /// traffic epochs (3), every counter at its first value. A
    /// `TcProvider` standby holds it until its first checkpoint.
    pub const fn established() -> Self {
        Self {
            flow_id: [0; 16],
            service_id: [0; 16],
            family: 4,
            client_ip: [0; 16],
            client_port: 0,
            service_ip: [0; 16],
            service_port: 0,
            local_addr_gen: 0,
            iface: 0,
            mss: 1460,
            wscale_snd: 0,
            wscale_rcv: 0,
            sack_ok: false,
            ts_ok: false,
            tcp: TsTcp::Established,
            iss: 0,
            irs: 0,
            snd_una: 1,
            snd_nxt: 1,
            snd_wnd: 65535,
            snd_wl1: 0,
            snd_wl2: 0,
            rcv_nxt: 1,
            rcv_wnd: 65535,
            fin_queued: false,
            fin_rcvd: false,
            send_len: 0,
            send: [0; TS_SEND_MAX],
            recv_len: 0,
            recv: [0; TS_RECV_MAX],
            ooo_count: 0,
            ooo: [TsOoo {
                seq: 0,
                len: 0,
                bytes: [0; TS_OOO_SEG],
            }; TS_OOO_MAX],
            ts_recent: 0,
            dupacks: 0,
            in_recovery: false,
            recovery_point: 0,
            rto_ms: 1000,
            persist_ms: 0,
            keepalive_ms: 0,
            timewait_ms: 0,
            srtt_us: 0,
            rttvar_us: 0,
            cwnd: 14600,
            ssthresh: 0xFFFF_FFFF,
            tls_phase: TsTlsPhase::Established,
            suite: TC_TLS_AES_128_GCM_SHA256,
            read_epoch: 3,
            read_seq: 0,
            write_epoch: 3,
            write_seq: 0,
            key_update_owed: false,
            close_notify_sent: false,
            close_notify_rcvd: false,
            peer_verified: false,
            alpn: 0,
            sni_digest: [0; 32],
            exporter_digest: [0; 32],
            read_key: TsVaultRef {
                backend: 0,
                purpose: TS_VAULT_READ,
                object: 0,
                generation: 0,
                epoch: 3,
            },
            write_key: TsVaultRef {
                backend: 0,
                purpose: TS_VAULT_WRITE,
                object: 0,
                generation: 0,
                epoch: 3,
            },
            wrapped_digest: [0; 32],
            tx_count: 0,
            tx: [TsTxRec {
                tcp_seq: 0,
                len: 0,
                epoch: 0,
                record_seq: 0,
                production_id: 0,
            }; TS_TXREC_MAX],
            next_delivery: 1,
            delivery_acked: 0,
            deliv_count: 0,
            deliv: [TsDelivery {
                id: 0,
                len: 0,
                bytes: [0; TS_DELIV_BYTES],
            }; TS_DELIV_MAX],
            next_production: 1,
            flow_epoch: 1,
            session_epoch: 1,
            route_generation: 1,
            mirror_generation: 1,
            binding_epoch: 1,
            local_client: false,
        }
    }

    /// Sequence number one past the last byte (and FIN) the send buffer
    /// holds: everything up to here may already have been emitted.
    pub fn send_end(&self) -> u32 {
        self.snd_una
            .wrapping_add(u32::from(self.send_len))
            .wrapping_add(u32::from(self.fin_queued))
    }

    pub fn deliveries(&self) -> &[TsDelivery] {
        &self.deliv[..usize::from(self.deliv_count)]
    }

    pub fn tx_records(&self) -> &[TsTxRec] {
        &self.tx[..usize::from(self.tx_count)]
    }
}

/// `a` precedes `b` in sequence space (RFC 9293 §3.4 arithmetic).
pub fn ts_seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn ts_seq_le(a: u32, b: u32) -> bool {
    a == b || ts_seq_lt(a, b)
}

/// Why a checkpoint (or a delta applied to one) was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CkptError {
    Truncated = 1,
    BadMagic = 2,
    Version = 3,
    Reserved = 4,
    /// A discriminant outside its domain.
    UnknownField = 5,
    /// A state the record does not migrate (handshake, early data, PHA).
    UnsupportedState = 6,
    /// Sequence variables that cannot describe one connection.
    SequenceImpossible = 7,
    /// A buffer that does not cover the range its variables name.
    RangeMissing = 8,
    /// Past a declared bound.
    Bounds = 9,
    /// A suite the codec does not represent.
    Suite = 10,
    Digest = 11,
    Trailing = 12,
    /// The output buffer cannot hold the encoding.
    Buffer = 13,
}

// ── encoding ──────────────────────────────────────────────────────────────

/// Encode `s` canonically into `out`; refuses (never truncates) state past
/// its bounds or that would not validate.
pub fn ts_encode(s: &TsState, out: &mut [u8]) -> Result<usize, CkptError> {
    ts_validate(s)?;
    let n = {
        let mut w = TcW::new(out);
        ts_put(s, &mut w).ok_or(CkptError::Buffer)?;
        w.at
    };
    if n + 32 > out.len() || n + 32 > TS_CKPT_MAX {
        return Err(CkptError::Buffer);
    }
    let d = sha256(&out[..n]);
    out[n..n + 32].copy_from_slice(&d);
    Ok(n + 32)
}

fn ts_put(s: &TsState, w: &mut TcW<'_>) -> Option<()> {
    w.bytes(&TS_MAGIC)?;
    w.u8(TS_VERSION)?;
    w.u8(TcTransport::TcpTls.wire())?;
    w.u16(if s.local_client { TS_FLAG_CLIENT } else { 0 })?;
    w.bytes(&s.flow_id)?;
    w.bytes(&s.service_id)?;
    w.u8(s.family)?;
    w.bytes(&s.client_ip)?;
    w.u16(s.client_port)?;
    w.bytes(&s.service_ip)?;
    w.u16(s.service_port)?;
    w.u32(s.local_addr_gen)?;
    w.u32(s.iface)?;
    w.u16(s.mss)?;
    w.u8(s.wscale_snd)?;
    w.u8(s.wscale_rcv)?;
    w.u8(s.sack_ok as u8 | (s.ts_ok as u8) << 1)?;

    w.u8(s.tcp.wire())?;
    for v in [
        s.iss, s.irs, s.snd_una, s.snd_nxt, s.snd_wnd, s.snd_wl1, s.snd_wl2, s.rcv_nxt, s.rcv_wnd,
    ] {
        w.u32(v)?;
    }
    w.u8(s.fin_queued as u8 | (s.fin_rcvd as u8) << 1 | (s.in_recovery as u8) << 2)?;
    w.u32(s.ts_recent)?;
    w.u8(s.dupacks)?;
    w.u32(s.recovery_point)?;
    w.u16(s.send_len)?;
    w.bytes(&s.send[..usize::from(s.send_len)])?;
    w.u16(s.recv_len)?;
    w.bytes(&s.recv[..usize::from(s.recv_len)])?;
    w.u8(s.ooo_count)?;
    for o in &s.ooo[..usize::from(s.ooo_count)] {
        w.u32(o.seq)?;
        w.u16(o.len)?;
        w.bytes(&o.bytes[..usize::from(o.len)])?;
    }

    for v in [
        s.rto_ms,
        s.persist_ms,
        s.keepalive_ms,
        s.timewait_ms,
        s.srtt_us,
        s.rttvar_us,
        s.cwnd,
        s.ssthresh,
    ] {
        w.u32(v)?;
    }

    w.u8(s.tls_phase.wire())?;
    w.u16(s.suite)?;
    w.u32(s.read_epoch)?;
    w.u64(s.read_seq)?;
    w.u32(s.write_epoch)?;
    w.u64(s.write_seq)?;
    w.u8(s.key_update_owed as u8
        | (s.close_notify_sent as u8) << 1
        | (s.close_notify_rcvd as u8) << 2
        | (s.peer_verified as u8) << 3)?;
    w.u16(s.alpn)?;
    w.bytes(&s.sni_digest)?;
    w.bytes(&s.exporter_digest)?;
    s.read_key.put(w)?;
    s.write_key.put(w)?;
    w.bytes(&s.wrapped_digest)?;
    w.u8(s.tx_count)?;
    for t in s.tx_records() {
        w.u32(t.tcp_seq)?;
        w.u16(t.len)?;
        w.u32(t.epoch)?;
        w.u64(t.record_seq)?;
        w.u64(t.production_id)?;
    }

    w.u64(s.next_delivery)?;
    w.u64(s.delivery_acked)?;
    w.u8(s.deliv_count)?;
    for d in s.deliveries() {
        w.u64(d.id)?;
        w.u16(d.len)?;
        w.bytes(&d.bytes[..usize::from(d.len)])?;
    }
    w.u64(s.next_production)?;

    w.u32(s.flow_epoch)?;
    w.u32(s.session_epoch)?;
    w.u64(s.route_generation)?;
    w.u64(s.mirror_generation)?;
    w.u32(s.binding_epoch)
}

/// Decode and validate one whole checkpoint record.
pub fn ts_decode(b: &[u8], out: &mut TsState) -> Result<(), CkptError> {
    if b.len() > TS_CKPT_MAX {
        return Err(CkptError::Bounds);
    }
    if b.len() < 4 + 32 {
        return Err(CkptError::Truncated);
    }
    let body = b.len() - 32;
    if sha256(&b[..body]) != b[body..] {
        return Err(CkptError::Digest);
    }
    let mut r = TcR::new(&b[..body]);
    let s = out;
    *s = TsState::zero();
    ts_get(&mut r, s)?;
    if r.remaining() != 0 {
        return Err(CkptError::Trailing);
    }
    ts_validate(s)
}

fn ts_bits(v: u8, allowed: u8) -> Result<u8, CkptError> {
    if v & !allowed != 0 {
        return Err(CkptError::Reserved);
    }
    Ok(v)
}

fn ts_get(r: &mut TcR<'_>, s: &mut TsState) -> Result<(), CkptError> {
    use CkptError::*;
    if r.take(4).ok_or(Truncated)? != TS_MAGIC {
        return Err(BadMagic);
    }
    if r.u8().ok_or(Truncated)? != TS_VERSION {
        return Err(Version);
    }
    if r.u8().ok_or(Truncated)? != TcTransport::TcpTls.wire() {
        return Err(UnknownField);
    }
    let flags = r.u16().ok_or(Truncated)?;
    if flags & !TS_FLAG_CLIENT != 0 {
        return Err(Reserved);
    }
    s.local_client = flags & TS_FLAG_CLIENT != 0;
    s.flow_id = r.arr().ok_or(Truncated)?;
    s.service_id = r.arr().ok_or(Truncated)?;
    s.family = r.u8().ok_or(Truncated)?;
    s.client_ip = r.arr().ok_or(Truncated)?;
    s.client_port = r.u16().ok_or(Truncated)?;
    s.service_ip = r.arr().ok_or(Truncated)?;
    s.service_port = r.u16().ok_or(Truncated)?;
    s.local_addr_gen = r.u32().ok_or(Truncated)?;
    s.iface = r.u32().ok_or(Truncated)?;
    s.mss = r.u16().ok_or(Truncated)?;
    s.wscale_snd = r.u8().ok_or(Truncated)?;
    s.wscale_rcv = r.u8().ok_or(Truncated)?;
    let opt = ts_bits(r.u8().ok_or(Truncated)?, 0b11)?;
    s.sack_ok = opt & 1 != 0;
    s.ts_ok = opt & 2 != 0;

    s.tcp = TsTcp::from_u8(r.u8().ok_or(Truncated)?).ok_or(UnknownField)?;
    s.iss = r.u32().ok_or(Truncated)?;
    s.irs = r.u32().ok_or(Truncated)?;
    s.snd_una = r.u32().ok_or(Truncated)?;
    s.snd_nxt = r.u32().ok_or(Truncated)?;
    s.snd_wnd = r.u32().ok_or(Truncated)?;
    s.snd_wl1 = r.u32().ok_or(Truncated)?;
    s.snd_wl2 = r.u32().ok_or(Truncated)?;
    s.rcv_nxt = r.u32().ok_or(Truncated)?;
    s.rcv_wnd = r.u32().ok_or(Truncated)?;
    let f = ts_bits(r.u8().ok_or(Truncated)?, 0b111)?;
    s.fin_queued = f & 1 != 0;
    s.fin_rcvd = f & 2 != 0;
    s.in_recovery = f & 4 != 0;
    s.ts_recent = r.u32().ok_or(Truncated)?;
    s.dupacks = r.u8().ok_or(Truncated)?;
    s.recovery_point = r.u32().ok_or(Truncated)?;
    s.send_len = r.u16().ok_or(Truncated)?;
    if usize::from(s.send_len) > TS_SEND_MAX {
        return Err(Bounds);
    }
    let n = usize::from(s.send_len);
    s.send[..n].copy_from_slice(r.take(n).ok_or(Truncated)?);
    s.recv_len = r.u16().ok_or(Truncated)?;
    if usize::from(s.recv_len) > TS_RECV_MAX {
        return Err(Bounds);
    }
    let n = usize::from(s.recv_len);
    s.recv[..n].copy_from_slice(r.take(n).ok_or(Truncated)?);
    s.ooo_count = r.u8().ok_or(Truncated)?;
    if usize::from(s.ooo_count) > TS_OOO_MAX {
        return Err(Bounds);
    }
    for i in 0..usize::from(s.ooo_count) {
        let seq = r.u32().ok_or(Truncated)?;
        let len = r.u16().ok_or(Truncated)?;
        if len == 0 || usize::from(len) > TS_OOO_SEG {
            return Err(Bounds);
        }
        let o = &mut s.ooo[i];
        o.seq = seq;
        o.len = len;
        o.bytes[..usize::from(len)].copy_from_slice(r.take(usize::from(len)).ok_or(Truncated)?);
    }

    s.rto_ms = r.u32().ok_or(Truncated)?;
    s.persist_ms = r.u32().ok_or(Truncated)?;
    s.keepalive_ms = r.u32().ok_or(Truncated)?;
    s.timewait_ms = r.u32().ok_or(Truncated)?;
    s.srtt_us = r.u32().ok_or(Truncated)?;
    s.rttvar_us = r.u32().ok_or(Truncated)?;
    s.cwnd = r.u32().ok_or(Truncated)?;
    s.ssthresh = r.u32().ok_or(Truncated)?;

    s.tls_phase = TsTlsPhase::from_u8(r.u8().ok_or(Truncated)?).ok_or(UnknownField)?;
    s.suite = r.u16().ok_or(Truncated)?;
    s.read_epoch = r.u32().ok_or(Truncated)?;
    s.read_seq = r.u64().ok_or(Truncated)?;
    s.write_epoch = r.u32().ok_or(Truncated)?;
    s.write_seq = r.u64().ok_or(Truncated)?;
    let t = ts_bits(r.u8().ok_or(Truncated)?, 0b1111)?;
    s.key_update_owed = t & 1 != 0;
    s.close_notify_sent = t & 2 != 0;
    s.close_notify_rcvd = t & 4 != 0;
    s.peer_verified = t & 8 != 0;
    s.alpn = r.u16().ok_or(Truncated)?;
    s.sni_digest = r.arr().ok_or(Truncated)?;
    s.exporter_digest = r.arr().ok_or(Truncated)?;
    s.read_key = TsVaultRef::get(r)?;
    s.write_key = TsVaultRef::get(r)?;
    s.wrapped_digest = r.arr().ok_or(Truncated)?;
    s.tx_count = r.u8().ok_or(Truncated)?;
    if usize::from(s.tx_count) > TS_TXREC_MAX {
        return Err(Bounds);
    }
    for i in 0..usize::from(s.tx_count) {
        s.tx[i] = TsTxRec {
            tcp_seq: r.u32().ok_or(Truncated)?,
            len: r.u16().ok_or(Truncated)?,
            epoch: r.u32().ok_or(Truncated)?,
            record_seq: r.u64().ok_or(Truncated)?,
            production_id: r.u64().ok_or(Truncated)?,
        };
    }

    s.next_delivery = r.u64().ok_or(Truncated)?;
    s.delivery_acked = r.u64().ok_or(Truncated)?;
    s.deliv_count = r.u8().ok_or(Truncated)?;
    if usize::from(s.deliv_count) > TS_DELIV_MAX {
        return Err(Bounds);
    }
    for i in 0..usize::from(s.deliv_count) {
        let id = r.u64().ok_or(Truncated)?;
        let len = r.u16().ok_or(Truncated)?;
        if usize::from(len) > TS_DELIV_BYTES {
            return Err(Bounds);
        }
        let d = &mut s.deliv[i];
        d.id = id;
        d.len = len;
        d.bytes[..usize::from(len)].copy_from_slice(r.take(usize::from(len)).ok_or(Truncated)?);
    }
    s.next_production = r.u64().ok_or(Truncated)?;

    s.flow_epoch = r.u32().ok_or(Truncated)?;
    s.session_epoch = r.u32().ok_or(Truncated)?;
    s.route_generation = r.u64().ok_or(Truncated)?;
    s.mirror_generation = r.u64().ok_or(Truncated)?;
    s.binding_epoch = r.u32().ok_or(Truncated)?;
    Ok(())
}

/// Everything that must hold of a state for it to describe one
/// established TLS 1.3 connection.
pub fn ts_validate(s: &TsState) -> Result<(), CkptError> {
    use CkptError::*;
    if s.tls_phase != TsTlsPhase::Established {
        return Err(UnsupportedState);
    }
    if !tc_suite_supported(s.suite) {
        return Err(Suite);
    }
    if !matches!(s.family, 4 | 6) || s.client_port == 0 || s.service_port == 0 {
        return Err(UnknownField);
    }
    if s.family == 4 && (s.client_ip[4..] != [0; 12] || s.service_ip[4..] != [0; 12]) {
        return Err(Reserved);
    }
    if s.wscale_snd > 14 || s.wscale_rcv > 14 || s.mss == 0 {
        return Err(Bounds);
    }
    if usize::from(s.send_len) > TS_SEND_MAX
        || usize::from(s.recv_len) > TS_RECV_MAX
        || usize::from(s.ooo_count) > TS_OOO_MAX
        || usize::from(s.tx_count) > TS_TXREC_MAX
        || usize::from(s.deliv_count) > TS_DELIV_MAX
        || s.deliveries()
            .iter()
            .any(|d| usize::from(d.len) > TS_DELIV_BYTES)
    {
        return Err(Bounds);
    }
    for t in [s.rto_ms, s.persist_ms, s.keepalive_ms, s.timewait_ms] {
        if t > TS_TIMER_MAX_MS {
            return Err(Bounds);
        }
    }
    if s.cwnd == 0 || s.rcv_wnd > (1 << 30) || s.snd_wnd > (1 << 30) {
        return Err(Bounds);
    }

    // Send side: ISS < SND.UNA <= SND.NXT <= send_end.
    if !ts_seq_lt(s.iss, s.snd_una) || !ts_seq_le(s.snd_una, s.snd_nxt) {
        return Err(SequenceImpossible);
    }
    if !ts_seq_le(s.snd_nxt, s.send_end()) {
        return Err(RangeMissing);
    }
    // Receive side: IRS < RCV.NXT, and out-of-order segments strictly after
    // it (one at RCV.NXT would be in order), sorted and disjoint — one may
    // start where the one before it ends.
    if !ts_seq_lt(s.irs, s.rcv_nxt) {
        return Err(SequenceImpossible);
    }
    let mut floor = s.rcv_nxt;
    for (k, o) in s.ooo[..usize::from(s.ooo_count)].iter().enumerate() {
        let after = if k == 0 {
            ts_seq_lt(floor, o.seq)
        } else {
            ts_seq_le(floor, o.seq)
        };
        if o.len == 0 || !after {
            return Err(SequenceImpossible);
        }
        floor = o.seq.wrapping_add(u32::from(o.len));
    }
    // State flags agree with the TCP state.
    let fin_state = matches!(
        s.tcp,
        TsTcp::CloseWait | TsTcp::Closing | TsTcp::LastAck | TsTcp::TimeWait
    );
    if s.fin_rcvd != fin_state {
        return Err(SequenceImpossible);
    }
    let local_fin = matches!(
        s.tcp,
        TsTcp::FinWait1 | TsTcp::FinWait2 | TsTcp::Closing | TsTcp::LastAck | TsTcp::TimeWait
    );
    if s.fin_queued && !local_fin {
        return Err(SequenceImpossible);
    }

    // The outbound records tile the send buffer exactly: contiguous from the
    // first record to the buffer's data end, each inside the buffer, record
    // numbers strictly increasing within an epoch and epochs non-decreasing,
    // and the last record of the write epoch numbered just below write_seq.
    let data_end = s.snd_una.wrapping_add(u32::from(s.send_len));
    let recs = s.tx_records();
    if let Some(first) = recs.first() {
        // The first record may have been partly acknowledged.
        let first_end = first.tcp_seq.wrapping_add(u32::from(first.len));
        if !ts_seq_le(first.tcp_seq, s.snd_una) || !ts_seq_lt(s.snd_una, first_end) {
            return Err(RangeMissing);
        }
        let mut at = first.tcp_seq;
        let mut prev: Option<&TsTxRec> = None;
        for t in recs {
            if t.tcp_seq != at || t.len == 0 {
                return Err(RangeMissing);
            }
            if let Some(p) = prev {
                if t.epoch < p.epoch || (t.epoch == p.epoch && t.record_seq <= p.record_seq) {
                    return Err(SequenceImpossible);
                }
                if p.production_id != 0
                    && t.production_id != 0
                    && t.production_id <= p.production_id
                {
                    return Err(SequenceImpossible);
                }
            }
            if t.epoch > s.write_epoch || (t.epoch == s.write_epoch && t.record_seq >= s.write_seq)
            {
                return Err(SequenceImpossible);
            }
            if t.production_id >= s.next_production {
                return Err(SequenceImpossible);
            }
            at = at.wrapping_add(u32::from(t.len));
            prev = Some(t);
        }
        if at != data_end {
            return Err(RangeMissing);
        }
    } else if s.send_len != 0 {
        return Err(RangeMissing);
    }

    // Deliveries: ids strictly increasing, above the acknowledged cursor and
    // below the next to be issued.
    let mut last = s.delivery_acked;
    for d in s.deliveries() {
        if d.id <= last || d.id >= s.next_delivery {
            return Err(SequenceImpossible);
        }
        last = d.id;
    }
    if s.delivery_acked >= s.next_delivery || s.next_delivery == 0 || s.next_production == 0 {
        return Err(SequenceImpossible);
    }
    if s.read_key.purpose != TS_VAULT_READ
        || s.write_key.purpose != TS_VAULT_WRITE
        || s.read_key.epoch != s.read_epoch
        || s.write_key.epoch != s.write_epoch
    {
        return Err(SequenceImpossible);
    }
    if s.flow_epoch == 0 || s.mirror_generation == 0 {
        return Err(SequenceImpossible);
    }
    Ok(())
}

// ── chunked transfer ──────────────────────────────────────────────────────

/// Payload bytes one checkpoint chunk carries: a power of two, so chunk
/// arithmetic is shifts and masks, never a division (a PIC module on a core
/// without a divide instruction cannot link one).
pub const CKPT_CHUNK_SHIFT: u32 = 14;
pub const CKPT_CHUNK_PAYLOAD: usize = 1 << CKPT_CHUNK_SHIFT;
/// Chunks one checkpoint may span.
pub const CKPT_MAX_CHUNKS: usize = TS_CKPT_MAX.div_ceil(CKPT_CHUNK_PAYLOAD);
pub const CKPT_CHUNK_MAGIC: [u8; 4] = *b"WHCC";
/// `magic[4] checkpoint_id u64 flow_id[16] flow_epoch u32
///  mirror_generation u64 index u16 count u16 offset u32 total u32 len u16
///  reserved u16 chain[32]`, then `len` payload bytes.
pub const CKPT_CHUNK_HDR: usize = 4 + 8 + 16 + 4 + 8 + 2 + 2 + 4 + 4 + 2 + 2 + 32;
pub const CKPT_CHUNK_MAX: usize = CKPT_CHUNK_HDR + CKPT_CHUNK_PAYLOAD;
/// The chunk chain's domain.
const CKPT_DOMAIN: &[u8; 7] = b"wh-ckpt";

/// The fields every chunk of one checkpoint shares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CkptId {
    pub checkpoint_id: u64,
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub total: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CkptChunkHdr {
    pub id: CkptId,
    pub index: u16,
    pub count: u16,
    pub offset: u32,
    pub len: u16,
    /// Running digest through this chunk.
    pub chain: [u8; 32],
}

/// The chain's seed: binds the chain to the checkpoint's identity.
pub fn ckpt_chain_seed(id: &CkptId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CKPT_DOMAIN);
    h.update(&id.checkpoint_id.to_le_bytes());
    h.update(&id.flow_id);
    h.update(&id.flow_epoch.to_le_bytes());
    h.update(&id.mirror_generation.to_le_bytes());
    h.update(&id.total.to_le_bytes());
    h.finalize()
}

fn ckpt_chain_next(prev: &[u8; 32], index: u16, offset: u32, payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(&index.to_le_bytes());
    h.update(&offset.to_le_bytes());
    h.update(payload);
    h.finalize()
}

/// Chunks a record of `total` bytes spans (an empty one is one chunk).
pub fn ckpt_chunk_count(total: usize) -> u16 {
    let mask = CKPT_CHUNK_PAYLOAD - 1;
    (((total + mask) >> CKPT_CHUNK_SHIFT).max(1)) as u16
}

/// Write chunk `index` of the encoded checkpoint `record` into `out`; the
/// running chain comes in through `chain` and leaves advanced.
pub fn ckpt_write_chunk(
    id: &CkptId,
    record: &[u8],
    index: u16,
    chain: &mut [u8; 32],
    out: &mut [u8],
) -> Option<usize> {
    if record.len() > TS_CKPT_MAX || record.len() != id.total as usize {
        return None;
    }
    let count = ckpt_chunk_count(record.len());
    if index >= count {
        return None;
    }
    let off = usize::from(index) << CKPT_CHUNK_SHIFT;
    let end = (off + CKPT_CHUNK_PAYLOAD).min(record.len());
    let payload = &record[off..end];
    let mut w = TcW::new(out);
    w.bytes(&CKPT_CHUNK_MAGIC)?;
    w.u64(id.checkpoint_id)?;
    w.bytes(&id.flow_id)?;
    w.u32(id.flow_epoch)?;
    w.u64(id.mirror_generation)?;
    w.u16(index)?;
    w.u16(count)?;
    w.u32(off as u32)?;
    w.u32(id.total)?;
    w.u16(payload.len() as u16)?;
    w.u16(0)?;
    let next = ckpt_chain_next(chain, index, off as u32, payload);
    w.bytes(&next)?;
    w.bytes(payload)?;
    *chain = next;
    Some(w.at)
}

/// Parse a chunk's header (strict: length agrees, reserved zero, index in
/// count, count agrees with total, offset agrees with index).
pub fn ckpt_parse_chunk(b: &[u8]) -> Result<(CkptChunkHdr, &[u8]), CkptError> {
    if b.len() < CKPT_CHUNK_HDR {
        return Err(CkptError::Truncated);
    }
    let mut r = TcR::new(b);
    if r.take(4).ok_or(CkptError::Truncated)? != CKPT_CHUNK_MAGIC {
        return Err(CkptError::BadMagic);
    }
    let t = CkptError::Truncated;
    let checkpoint_id = r.u64().ok_or(t)?;
    let flow_id = r.arr().ok_or(t)?;
    let flow_epoch = r.u32().ok_or(t)?;
    let mirror_generation = r.u64().ok_or(t)?;
    let index = r.u16().ok_or(t)?;
    let count = r.u16().ok_or(t)?;
    let offset = r.u32().ok_or(t)?;
    let total = r.u32().ok_or(t)?;
    let len = r.u16().ok_or(t)?;
    if r.u16().ok_or(t)? != 0 {
        return Err(CkptError::Reserved);
    }
    let chain = r.arr().ok_or(t)?;
    if b.len() != CKPT_CHUNK_HDR + usize::from(len) {
        return Err(CkptError::Truncated);
    }
    if total as usize > TS_CKPT_MAX
        || count != ckpt_chunk_count(total as usize)
        || index >= count
        || offset as usize != usize::from(index) << CKPT_CHUNK_SHIFT
    {
        return Err(CkptError::Bounds);
    }
    let expect = (total as usize - offset as usize).min(CKPT_CHUNK_PAYLOAD);
    if usize::from(len) != expect {
        return Err(CkptError::Bounds);
    }
    Ok((
        CkptChunkHdr {
            id: CkptId {
                checkpoint_id,
                flow_id,
                flow_epoch,
                mirror_generation,
                total,
            },
            index,
            count,
            offset,
            len,
            chain,
        },
        &b[CKPT_CHUNK_HDR..],
    ))
}

/// What a chunk did to an assembly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CkptOffer {
    /// The next chunk, accepted.
    Accepted,
    /// A byte-identical retry of a chunk already accepted.
    Duplicate,
    /// The last chunk, accepted: the record is whole and chain-verified.
    Complete,
}

/// Why a chunk was refused. `Stale`, `WrongFlow` and a malformed chunk
/// leave the assembly in progress as it was; the others discard it, and the
/// standby restarts from a full checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CkptReject {
    /// Malformed header.
    Malformed(CkptError),
    /// An older mirror generation or checkpoint than the one last assembled
    /// or assembling, or a flow epoch behind the one admitted: ignored,
    /// nothing discarded.
    Stale,
    /// A chunk out of order (a gap): discarded, restart required.
    Gap,
    /// A chunk whose chain does not verify, or an index reused with other
    /// bytes: discarded, restart required.
    Conflict,
    /// A flow other than the one being assembled.
    WrongFlow,
}

/// Streaming verification of one checkpoint's chunks: order, identity and
/// the running chain, without buffering the record. `transport_mirror`
/// keeps one per flow so nothing out of order or unauthenticated reaches a
/// standby anchor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CkptVerifier {
    pub flow_id: [u8; 16],
    /// The lowest flow epoch admitted.
    pub min_epoch: u32,
    pub active: bool,
    pub id: CkptId,
    pub next: u16,
    pub count: u16,
    pub chain: [u8; 32],
    /// Chain value after each accepted chunk (for duplicate recognition).
    pub chains: [[u8; 32]; CKPT_MAX_CHUNKS],
    pub complete: bool,
    /// `id` is the checkpoint last published: a chunk of it again is a
    /// replay, refused like an older one.
    pub sealed: bool,
}

impl CkptVerifier {
    pub const fn new(flow_id: [u8; 16], min_epoch: u32) -> Self {
        Self {
            flow_id,
            min_epoch,
            active: false,
            id: CkptId {
                checkpoint_id: 0,
                flow_id: [0; 16],
                flow_epoch: 0,
                mirror_generation: 0,
                total: 0,
            },
            next: 0,
            count: 0,
            chain: [0; 32],
            chains: [[0; 32]; CKPT_MAX_CHUNKS],
            complete: false,
            sealed: false,
        }
    }

    pub fn discard(&mut self) {
        self.active = false;
        self.complete = false;
        self.next = 0;
    }

    /// The checkpoint assembled was published: nothing of it, or older, is
    /// taken again, so a replay cannot roll the shadow back to it.
    pub fn seal(&mut self) {
        self.discard();
        self.sealed = true;
    }

    /// Offer one chunk.
    pub fn offer(&mut self, h: &CkptChunkHdr, payload: &[u8]) -> Result<CkptOffer, CkptReject> {
        if h.id.flow_id != self.flow_id {
            return Err(CkptReject::WrongFlow);
        }
        if h.id.flow_epoch < self.min_epoch {
            return Err(CkptReject::Stale);
        }
        // Older than the checkpoint last assembled (or assembling), or the
        // one last published: a replay, ignored.
        let key = (h.id.mirror_generation, h.id.checkpoint_id);
        let ours = (self.id.mirror_generation, self.id.checkpoint_id);
        if key < ours || (self.sealed && key == ours) {
            return Err(CkptReject::Stale);
        }
        if self.active {
            if h.id == self.id {
                if h.index < self.next {
                    // A retry: identical exactly when its bytes chain to
                    // the value recorded for that index, from the one
                    // before it.
                    let prev = if h.index == 0 {
                        ckpt_chain_seed(&self.id)
                    } else {
                        self.chains[usize::from(h.index) - 1]
                    };
                    let c = ckpt_chain_next(&prev, h.index, h.offset, payload);
                    let recorded = self.chains[usize::from(h.index)];
                    return if c == recorded && h.chain == recorded {
                        Ok(CkptOffer::Duplicate)
                    } else {
                        self.discard();
                        Err(CkptReject::Conflict)
                    };
                }
                if self.complete || h.index != self.next {
                    self.discard();
                    return Err(CkptReject::Gap);
                }
            } else if h.index != 0 {
                // A newer checkpoint, joined mid-way: nothing to resume.
                self.discard();
                return Err(CkptReject::Gap);
            } else {
                self.discard();
            }
        } else if h.index != 0 {
            return Err(CkptReject::Gap);
        }
        if !self.active {
            self.active = true;
            self.complete = false;
            self.sealed = false;
            self.id = h.id;
            self.count = h.count;
            self.next = 0;
            self.chain = ckpt_chain_seed(&h.id);
        }
        let c = ckpt_chain_next(&self.chain, h.index, h.offset, payload);
        if c != h.chain {
            self.discard();
            return Err(CkptReject::Conflict);
        }
        self.chain = c;
        self.chains[usize::from(h.index)] = c;
        self.next += 1;
        if self.next == self.count {
            self.complete = true;
            Ok(CkptOffer::Complete)
        } else {
            Ok(CkptOffer::Accepted)
        }
    }
}

/// The standby's shadow arena: chunks land in an INACTIVE buffer and the
/// record is published (decoded and validated into the active shadow) only
/// once every chunk verified. A gap, conflict or crash discards the
/// inactive buffer; the active shadow is never patched with another
/// generation's bytes. `MAX` is the largest record it takes: a
/// `TsState`'s by default, less for a provider whose record is smaller
/// (a QUIC pairing's).
#[derive(PartialEq)]
pub struct CkptAssembler<const MAX: usize = TS_CKPT_MAX> {
    pub verifier: CkptVerifier,
    pub buf: [u8; MAX],
}

impl<const MAX: usize> CkptAssembler<MAX> {
    pub const fn new(flow_id: [u8; 16], min_epoch: u32) -> Self {
        Self {
            verifier: CkptVerifier::new(flow_id, min_epoch),
            buf: [0; MAX],
        }
    }

    /// Start over for `flow_id` (a new pairing), in place: the buffer is
    /// written before it is read, so only the verifier is reset.
    pub fn reset(&mut self, flow_id: [u8; 16], min_epoch: u32) {
        self.verifier = CkptVerifier::new(flow_id, min_epoch);
    }

    pub fn offer(&mut self, chunk: &[u8]) -> Result<CkptOffer, CkptReject> {
        let (h, payload) = ckpt_parse_chunk(chunk).map_err(CkptReject::Malformed)?;
        if h.id.total as usize > MAX {
            return Err(CkptReject::Malformed(CkptError::Bounds));
        }
        let o = self.verifier.offer(&h, payload)?;
        if o != CkptOffer::Duplicate {
            let off = h.offset as usize;
            self.buf[off..off + payload.len()].copy_from_slice(payload);
        }
        Ok(o)
    }

    /// Publish a complete record into `shadow`: decoded, validated, and
    /// bound to the identity its chunks named. On any failure `shadow` is
    /// left as it was.
    pub fn publish(
        &mut self,
        scratch: &mut TsState,
        shadow: &mut TsState,
    ) -> Result<(), CkptError> {
        if !self.verifier.complete {
            return Err(CkptError::RangeMissing);
        }
        let id = self.verifier.id;
        let r = ts_decode(&self.buf[..id.total as usize], scratch);
        self.verifier.discard();
        r?;
        if scratch.flow_id != id.flow_id
            || scratch.flow_epoch != id.flow_epoch
            || scratch.mirror_generation != id.mirror_generation
        {
            return Err(CkptError::SequenceImpossible);
        }
        *shadow = *scratch;
        Ok(())
    }
}

// ── ordered mirror deltas ─────────────────────────────────────────────────

pub const MD_MAGIC: [u8; 4] = *b"WHMD";
pub const MD_VERSION: u8 = 1;
/// `magic[4] version u8 kind u8 reserved u16 flow_id[16] flow_epoch u32
///  mirror_generation u64 base_checkpoint u64 seq u64 prev[32]
///  payload_len u16 reserved u16 digest[32]`, then the payload.
pub const MD_HDR: usize = 4 + 1 + 1 + 2 + 16 + 4 + 8 + 8 + 8 + 32 + 2 + 2 + 32;
/// Largest delta payload: a whole protected record, or a record's whole
/// plaintext, and their fields.
pub const MD_PAYLOAD_MAX: usize = 17 * 1024;
pub const MD_FRAME_MAX: usize = MD_HDR + MD_PAYLOAD_MAX;
/// The delta digest's domain.
const MD_DOMAIN: &[u8; 8] = b"wh-delta";
const _: () = assert!(MD_PAYLOAD_MAX >= 24 + TS_RECV_MAX && MD_PAYLOAD_MAX >= 24 + TS_DELIV_BYTES);

tc_wire_enum!(
    /// Delta kinds. Values are wire-stable. `QuicDelta` is a QUIC pairing's
    /// transition (`TcTransport::Quic`): the provider's own per-layer
    /// delta, `[layer_no u32][kind u8][data]`, carried whole (the QUIC
    /// section below); not a TCP/TLS transition — `md_apply` refuses it,
    /// and a relay checks its order and chain like any delta's.
    MdKind {
        RxSegment = 1,
        RxRecord = 2,
        DeliveryAck = 3,
        TxRecord = 4,
        PeerAck = 5,
        RcvWindow = 6,
        KeyUpdate = 7,
        Fin = 8,
        CloseNotify = 9,
        Timers = 10,
        QuicDelta = 12,
    }
);

/// `Fin` / `CloseNotify` / `KeyUpdate` direction: the peer's (inbound) or
/// ours (outbound).
pub const MD_DIR_IN: u8 = 1;
pub const MD_DIR_OUT: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MdHdr {
    pub kind: MdKind,
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub base_checkpoint: u64,
    pub seq: u64,
    pub prev: [u8; 32],
    pub payload_len: u16,
    pub digest: [u8; 32],
}

fn md_digest(h: &MdHdr, payload: &[u8]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(MD_DOMAIN);
    d.update(&[h.kind.wire()]);
    d.update(&h.flow_id);
    d.update(&h.flow_epoch.to_le_bytes());
    d.update(&h.mirror_generation.to_le_bytes());
    d.update(&h.base_checkpoint.to_le_bytes());
    d.update(&h.seq.to_le_bytes());
    d.update(&h.prev);
    d.update(&h.payload_len.to_le_bytes());
    d.update(payload);
    d.finalize()
}

/// Encode a delta: the header's digest is computed here.
pub fn md_encode(h: &mut MdHdr, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if payload.len() > MD_PAYLOAD_MAX {
        return None;
    }
    h.payload_len = payload.len() as u16;
    h.digest = md_digest(h, payload);
    let mut w = TcW::new(out);
    w.bytes(&MD_MAGIC)?;
    w.u8(MD_VERSION)?;
    w.u8(h.kind.wire())?;
    w.u16(0)?;
    w.bytes(&h.flow_id)?;
    w.u32(h.flow_epoch)?;
    w.u64(h.mirror_generation)?;
    w.u64(h.base_checkpoint)?;
    w.u64(h.seq)?;
    w.bytes(&h.prev)?;
    w.u16(h.payload_len)?;
    w.u16(0)?;
    w.bytes(&h.digest)?;
    w.bytes(payload)?;
    Some(w.at)
}

/// Parse and authenticate one delta frame (its own digest; ordering and
/// the chain are `MdOrder`'s).
pub fn md_parse(b: &[u8]) -> Result<(MdHdr, &[u8]), CkptError> {
    if b.len() < MD_HDR {
        return Err(CkptError::Truncated);
    }
    let mut r = TcR::new(b);
    let t = CkptError::Truncated;
    if r.take(4).ok_or(t)? != MD_MAGIC {
        return Err(CkptError::BadMagic);
    }
    if r.u8().ok_or(t)? != MD_VERSION {
        return Err(CkptError::Version);
    }
    let kind = MdKind::from_u8(r.u8().ok_or(t)?).ok_or(CkptError::UnknownField)?;
    if r.u16().ok_or(t)? != 0 {
        return Err(CkptError::Reserved);
    }
    let flow_id = r.arr().ok_or(t)?;
    let flow_epoch = r.u32().ok_or(t)?;
    let mirror_generation = r.u64().ok_or(t)?;
    let base_checkpoint = r.u64().ok_or(t)?;
    let seq = r.u64().ok_or(t)?;
    let prev = r.arr().ok_or(t)?;
    let payload_len = r.u16().ok_or(t)?;
    if r.u16().ok_or(t)? != 0 {
        return Err(CkptError::Reserved);
    }
    let digest = r.arr().ok_or(t)?;
    if usize::from(payload_len) > MD_PAYLOAD_MAX || b.len() != MD_HDR + usize::from(payload_len) {
        return Err(CkptError::Truncated);
    }
    let h = MdHdr {
        kind,
        flow_id,
        flow_epoch,
        mirror_generation,
        base_checkpoint,
        seq,
        prev,
        payload_len,
        digest,
    };
    let payload = &b[MD_HDR..];
    if md_digest(&h, payload) != digest {
        return Err(CkptError::Digest);
    }
    Ok((h, payload))
}

// ── payload builders ──────────────────────────────────────────────────────

pub fn md_rx_segment(out: &mut [u8], seq: u32, bytes: &[u8]) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u32(seq)?;
    w.u16(bytes.len() as u16)?;
    w.bytes(bytes)?;
    Some(w.at)
}

pub fn md_rx_record(
    out: &mut [u8],
    consume: u16,
    epoch: u32,
    record_seq: u64,
    delivery_id: u64,
    plaintext: &[u8],
) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u16(consume)?;
    w.u32(epoch)?;
    w.u64(record_seq)?;
    w.u64(delivery_id)?;
    w.u16(plaintext.len() as u16)?;
    w.bytes(plaintext)?;
    Some(w.at)
}

pub fn md_tx_record(
    out: &mut [u8],
    production_id: u64,
    epoch: u32,
    record_seq: u64,
    ciphertext: &[u8],
) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u64(production_id)?;
    w.u32(epoch)?;
    w.u64(record_seq)?;
    w.u16(ciphertext.len() as u16)?;
    w.bytes(ciphertext)?;
    Some(w.at)
}

pub fn md_u64(out: &mut [u8], v: u64) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u64(v)?;
    Some(w.at)
}

pub fn md_peer_ack(out: &mut [u8], ack: u32, wnd: u32) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u32(ack)?;
    w.u32(wnd)?;
    Some(w.at)
}

pub fn md_u32(out: &mut [u8], v: u32) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u32(v)?;
    Some(w.at)
}

/// A KeyUpdate: the direction's next epoch, its secret's reference and the
/// wrapped object's digest; an inbound one then `[requested u8]` — the peer
/// asked for ours, which the record then owes (`key_update_owed`) until our
/// own write rotation (RFC 8446 §4.6.3).
pub fn md_key_update(
    out: &mut [u8],
    dir: u8,
    new_epoch: u32,
    vref: &TsVaultRef,
    wrapped_digest: &[u8; 32],
    requested: bool,
) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u8(dir)?;
    w.u32(new_epoch)?;
    vref.put(&mut w)?;
    w.bytes(wrapped_digest)?;
    if dir == MD_DIR_IN {
        w.u8(u8::from(requested))?;
    }
    Some(w.at)
}

pub fn md_dir(out: &mut [u8], dir: u8) -> Option<usize> {
    let mut w = TcW::new(out);
    w.u8(dir)?;
    Some(w.at)
}

/// The timer snapshot, as remaining durations at the primary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MdTimers {
    pub rto_ms: u32,
    pub persist_ms: u32,
    pub keepalive_ms: u32,
    pub timewait_ms: u32,
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub cwnd: u32,
    pub ssthresh: u32,
}

pub fn md_timers(out: &mut [u8], t: &MdTimers) -> Option<usize> {
    let mut w = TcW::new(out);
    for v in [
        t.rto_ms,
        t.persist_ms,
        t.keepalive_ms,
        t.timewait_ms,
        t.srtt_us,
        t.rttvar_us,
        t.cwnd,
        t.ssthresh,
    ] {
        w.u32(v)?;
    }
    Some(w.at)
}

// ── the transition ────────────────────────────────────────────────────────

fn md_end(r: &TcR<'_>) -> Result<(), CkptError> {
    if r.remaining() != 0 {
        Err(CkptError::Trailing)
    } else {
        Ok(())
    }
}

/// Apply one delta to `s` (unchecked: see `md_apply`).
fn md_apply_raw(s: &mut TsState, kind: MdKind, p: &[u8]) -> Result<(), CkptError> {
    use CkptError::*;
    let mut r = TcR::new(p);
    match kind {
        MdKind::RxSegment => {
            let seq = r.u32().ok_or(Truncated)?;
            let len = r.u16().ok_or(Truncated)?;
            let bytes = r.take(usize::from(len)).ok_or(Truncated)?;
            md_end(&r)?;
            if len == 0 || s.fin_rcvd {
                return Err(SequenceImpossible);
            }
            if seq == s.rcv_nxt {
                let at = usize::from(s.recv_len);
                if at + bytes.len() > TS_RECV_MAX {
                    return Err(Bounds);
                }
                s.recv[at..at + bytes.len()].copy_from_slice(bytes);
                s.recv_len += len;
                s.rcv_nxt = s.rcv_nxt.wrapping_add(u32::from(len));
                // Pull in every out-of-order segment the new bytes reach:
                // a covered one is dropped, one that extends past RCV.NXT
                // contributes its tail (reassembly, deterministically).
                while s.ooo_count > 0 && ts_seq_le(s.ooo[0].seq, s.rcv_nxt) {
                    let o = s.ooo[0];
                    let o_end = o.seq.wrapping_add(u32::from(o.len));
                    if ts_seq_lt(s.rcv_nxt, o_end) {
                        let skip = s.rcv_nxt.wrapping_sub(o.seq) as usize;
                        let tail = &o.bytes[skip..usize::from(o.len)];
                        let at = usize::from(s.recv_len);
                        if at + tail.len() > TS_RECV_MAX {
                            return Err(Bounds);
                        }
                        s.recv[at..at + tail.len()].copy_from_slice(tail);
                        s.recv_len += tail.len() as u16;
                        s.rcv_nxt = o_end;
                    }
                    let n = usize::from(s.ooo_count);
                    for i in 1..n {
                        s.ooo[i - 1] = s.ooo[i];
                    }
                    s.ooo[n - 1] = TsOoo {
                        seq: 0,
                        len: 0,
                        bytes: [0; TS_OOO_SEG],
                    };
                    s.ooo_count -= 1;
                }
                Ok(())
            } else if ts_seq_lt(s.rcv_nxt, seq) {
                if usize::from(len) > TS_OOO_SEG || usize::from(s.ooo_count) == TS_OOO_MAX {
                    return Err(Bounds);
                }
                let end = seq.wrapping_add(u32::from(len));
                let n = usize::from(s.ooo_count);
                let mut pos = n;
                for i in 0..n {
                    let o = &s.ooo[i];
                    let o_end = o.seq.wrapping_add(u32::from(o.len));
                    if ts_seq_lt(seq, o_end) && ts_seq_lt(o.seq, end) {
                        return Err(SequenceImpossible);
                    }
                    if pos == n && ts_seq_lt(seq, o.seq) {
                        pos = i;
                    }
                }
                let mut i = n;
                while i > pos {
                    s.ooo[i] = s.ooo[i - 1];
                    i -= 1;
                }
                let o = &mut s.ooo[pos];
                o.seq = seq;
                o.len = len;
                o.bytes[..bytes.len()].copy_from_slice(bytes);
                s.ooo_count += 1;
                Ok(())
            } else {
                Err(SequenceImpossible)
            }
        }
        MdKind::RxRecord => {
            let consume = r.u16().ok_or(Truncated)?;
            let epoch = r.u32().ok_or(Truncated)?;
            let record_seq = r.u64().ok_or(Truncated)?;
            let delivery_id = r.u64().ok_or(Truncated)?;
            let plen = r.u16().ok_or(Truncated)?;
            let plain = r.take(usize::from(plen)).ok_or(Truncated)?;
            md_end(&r)?;
            if consume == 0 || consume > s.recv_len {
                return Err(RangeMissing);
            }
            if epoch != s.read_epoch || record_seq != s.read_seq {
                return Err(SequenceImpossible);
            }
            s.read_seq += 1;
            let rest = usize::from(s.recv_len - consume);
            let c = usize::from(consume);
            for i in 0..rest {
                s.recv[i] = s.recv[c + i];
            }
            for i in rest..rest + c {
                s.recv[i] = 0;
            }
            s.recv_len -= consume;
            if delivery_id == 0 {
                if plen != 0 {
                    return Err(SequenceImpossible);
                }
                return Ok(());
            }
            // Nothing is delivered after the peer's close_notify
            // (RFC 8446 §6.1).
            if s.close_notify_rcvd
                || delivery_id != s.next_delivery
                || usize::from(s.deliv_count) == TS_DELIV_MAX
                || usize::from(plen) > TS_DELIV_BYTES
            {
                return Err(Bounds);
            }
            let d = &mut s.deliv[usize::from(s.deliv_count)];
            d.id = delivery_id;
            d.len = plen;
            d.bytes[..plain.len()].copy_from_slice(plain);
            s.deliv_count += 1;
            s.next_delivery += 1;
            Ok(())
        }
        MdKind::DeliveryAck => {
            let cursor = r.u64().ok_or(Truncated)?;
            md_end(&r)?;
            if cursor < s.delivery_acked || cursor >= s.next_delivery {
                return Err(SequenceImpossible);
            }
            s.delivery_acked = cursor;
            let n = usize::from(s.deliv_count);
            let mut keep = 0;
            for i in 0..n {
                if s.deliv[i].id > cursor {
                    s.deliv[keep] = s.deliv[i];
                    keep += 1;
                }
            }
            for d in s.deliv[keep..n].iter_mut() {
                *d = TsDelivery {
                    id: 0,
                    len: 0,
                    bytes: [0; TS_DELIV_BYTES],
                };
            }
            s.deliv_count = keep as u8;
            Ok(())
        }
        MdKind::TxRecord => {
            let production_id = r.u64().ok_or(Truncated)?;
            let epoch = r.u32().ok_or(Truncated)?;
            let record_seq = r.u64().ok_or(Truncated)?;
            let len = r.u16().ok_or(Truncated)?;
            let ct = r.take(usize::from(len)).ok_or(Truncated)?;
            md_end(&r)?;
            if len == 0 || s.fin_queued {
                return Err(SequenceImpossible);
            }
            if epoch != s.write_epoch || record_seq != s.write_seq {
                return Err(SequenceImpossible);
            }
            if production_id != 0 && production_id != s.next_production {
                return Err(SequenceImpossible);
            }
            let at = usize::from(s.send_len);
            if at + ct.len() > TS_SEND_MAX || usize::from(s.tx_count) == TS_TXREC_MAX {
                return Err(Bounds);
            }
            s.send[at..at + ct.len()].copy_from_slice(ct);
            s.tx[usize::from(s.tx_count)] = TsTxRec {
                tcp_seq: s.snd_una.wrapping_add(at as u32),
                len,
                epoch,
                record_seq,
                production_id,
            };
            s.tx_count += 1;
            s.send_len += len;
            s.write_seq += 1;
            if production_id != 0 {
                s.next_production += 1;
            }
            Ok(())
        }
        MdKind::PeerAck => {
            let ack = r.u32().ok_or(Truncated)?;
            let wnd = r.u32().ok_or(Truncated)?;
            md_end(&r)?;
            if !ts_seq_le(s.snd_una, ack) || !ts_seq_le(ack, s.send_end()) {
                return Err(SequenceImpossible);
            }
            let n = ack.wrapping_sub(s.snd_una);
            let data = n.min(u32::from(s.send_len)) as usize;
            let fin_acked = s.fin_queued && n as usize > data;
            let rest = usize::from(s.send_len) - data;
            for i in 0..rest {
                s.send[i] = s.send[data + i];
            }
            for i in rest..rest + data {
                s.send[i] = 0;
            }
            s.send_len = rest as u16;
            let end_of = |t: &TsTxRec| t.tcp_seq.wrapping_add(u32::from(t.len));
            let m = usize::from(s.tx_count);
            let mut keep = 0;
            for i in 0..m {
                if ts_seq_lt(ack, end_of(&s.tx[i])) {
                    s.tx[keep] = s.tx[i];
                    keep += 1;
                }
            }
            for t in s.tx[keep..m].iter_mut() {
                *t = TsTxRec::default();
            }
            s.tx_count = keep as u8;
            s.snd_una = ack;
            if ts_seq_lt(s.snd_nxt, ack) {
                s.snd_nxt = ack;
            }
            s.snd_wnd = wnd;
            if fin_acked {
                s.fin_queued = false;
                s.tcp = match s.tcp {
                    TsTcp::FinWait1 => TsTcp::FinWait2,
                    TsTcp::Closing => TsTcp::TimeWait,
                    other => other,
                };
            }
            Ok(())
        }
        MdKind::RcvWindow => {
            let wnd = r.u32().ok_or(Truncated)?;
            md_end(&r)?;
            s.rcv_wnd = wnd;
            Ok(())
        }
        MdKind::KeyUpdate => {
            let dir = r.u8().ok_or(Truncated)?;
            let new_epoch = r.u32().ok_or(Truncated)?;
            let vref = TsVaultRef::get(&mut r)?;
            let wrapped: [u8; 32] = r.arr().ok_or(Truncated)?;
            let requested = if dir == MD_DIR_IN {
                match r.u8().ok_or(Truncated)? {
                    0 => false,
                    1 => true,
                    _ => return Err(UnknownField),
                }
            } else {
                false
            };
            md_end(&r)?;
            if vref.epoch != new_epoch {
                return Err(SequenceImpossible);
            }
            match dir {
                MD_DIR_IN
                    if Some(new_epoch) == s.read_epoch.checked_add(1)
                        && vref.purpose == TS_VAULT_READ =>
                {
                    s.read_epoch = new_epoch;
                    s.read_seq = 0;
                    s.read_key = vref;
                    // An answer owed stays owed until our own rotation, even
                    // across a later update that asks for none.
                    s.key_update_owed |= requested;
                }
                MD_DIR_OUT
                    if Some(new_epoch) == s.write_epoch.checked_add(1)
                        && vref.purpose == TS_VAULT_WRITE =>
                {
                    s.write_epoch = new_epoch;
                    s.write_seq = 0;
                    s.write_key = vref;
                    s.key_update_owed = false;
                }
                _ => return Err(SequenceImpossible),
            }
            s.wrapped_digest = wrapped;
            Ok(())
        }
        MdKind::Fin => {
            let dir = r.u8().ok_or(Truncated)?;
            md_end(&r)?;
            match dir {
                MD_DIR_IN if !s.fin_rcvd && s.ooo_count == 0 => {
                    s.fin_rcvd = true;
                    s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                    s.tcp = match s.tcp {
                        TsTcp::Established => TsTcp::CloseWait,
                        TsTcp::FinWait1 => TsTcp::Closing,
                        TsTcp::FinWait2 => TsTcp::TimeWait,
                        _ => return Err(SequenceImpossible),
                    };
                }
                MD_DIR_OUT if !s.fin_queued => {
                    s.fin_queued = true;
                    s.tcp = match s.tcp {
                        TsTcp::Established => TsTcp::FinWait1,
                        TsTcp::CloseWait => TsTcp::LastAck,
                        _ => return Err(SequenceImpossible),
                    };
                }
                _ => return Err(SequenceImpossible),
            }
            Ok(())
        }
        MdKind::CloseNotify => {
            let dir = r.u8().ok_or(Truncated)?;
            md_end(&r)?;
            match dir {
                MD_DIR_IN => s.close_notify_rcvd = true,
                MD_DIR_OUT => s.close_notify_sent = true,
                _ => return Err(UnknownField),
            }
            Ok(())
        }
        MdKind::Timers => {
            let mut v = [0u32; 8];
            for x in &mut v {
                *x = r.u32().ok_or(Truncated)?;
            }
            md_end(&r)?;
            s.rto_ms = v[0];
            s.persist_ms = v[1];
            s.keepalive_ms = v[2];
            s.timewait_ms = v[3];
            s.srtt_us = v[4];
            s.rttvar_us = v[5];
            s.cwnd = v[6];
            s.ssthresh = v[7];
            Ok(())
        }
        MdKind::QuicDelta => Err(UnknownField),
    }
}

/// Apply one delta to `s`, through `scratch`: `s` changes only when the
/// result validates as a whole connection state.
pub fn md_apply(
    s: &mut TsState,
    scratch: &mut TsState,
    kind: MdKind,
    payload: &[u8],
) -> Result<(), CkptError> {
    *scratch = *s;
    md_apply_raw(scratch, kind, payload)?;
    ts_validate(scratch)?;
    *s = *scratch;
    Ok(())
}

// ── ordering at the standby ───────────────────────────────────────────────

/// Digests of the last deltas accepted, for duplicate recognition.
pub const MD_DUP_WINDOW: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MdVerdict {
    /// The next delta: apply it, then `commit`.
    Apply,
    /// A byte-identical retry of one already applied: acknowledge again.
    Duplicate,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MdReject {
    WrongFlow,
    /// Older generation, base or epoch, or older than the duplicate window:
    /// ignored, nothing changes.
    Stale,
    /// A newer generation or base, or a newer flow epoch: the stream this
    /// side holds is not that one; a full checkpoint is required.
    NeedCheckpoint,
    /// A gap: the delta before it never arrived.
    Gap,
    /// A different delta under a number already used, or a chain that does
    /// not follow: the history is not this side's.
    Conflict,
}

/// The ordering state of one flow's delta stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MdOrder {
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub base_checkpoint: u64,
    /// The highest sequence number applied (0 = only the checkpoint): the
    /// next delta carries one more.
    pub applied_seq: u64,
    pub last_digest: [u8; 32],
    pub recent: [[u8; 32]; MD_DUP_WINDOW],
}

impl MdOrder {
    /// The stream after checkpoint `base` (whose final chain is `chain`).
    pub fn after_checkpoint(
        flow_id: [u8; 16],
        flow_epoch: u32,
        mirror_generation: u64,
        base: u64,
        chain: [u8; 32],
    ) -> Self {
        Self {
            flow_id,
            flow_epoch,
            mirror_generation,
            base_checkpoint: base,
            applied_seq: 0,
            last_digest: chain,
            recent: [[0; 32]; MD_DUP_WINDOW],
        }
    }

    pub fn verify(&self, h: &MdHdr) -> Result<MdVerdict, MdReject> {
        if h.flow_id != self.flow_id {
            return Err(MdReject::WrongFlow);
        }
        let key = (h.mirror_generation, h.base_checkpoint);
        let ours = (self.mirror_generation, self.base_checkpoint);
        if key < ours || h.flow_epoch < self.flow_epoch {
            return Err(MdReject::Stale);
        }
        if key > ours || h.flow_epoch > self.flow_epoch {
            return Err(MdReject::NeedCheckpoint);
        }
        if h.seq == 0 {
            return Err(MdReject::Conflict);
        }
        if h.seq <= self.applied_seq {
            if self.applied_seq - h.seq >= MD_DUP_WINDOW as u64 {
                return Err(MdReject::Stale);
            }
            return if self.recent[(h.seq as usize) % MD_DUP_WINDOW] == h.digest {
                Ok(MdVerdict::Duplicate)
            } else {
                Err(MdReject::Conflict)
            };
        }
        if h.seq - 1 > self.applied_seq {
            return Err(MdReject::Gap);
        }
        if h.prev != self.last_digest {
            return Err(MdReject::Conflict);
        }
        Ok(MdVerdict::Apply)
    }

    /// The delta `verify` admitted was applied.
    pub fn commit(&mut self, h: &MdHdr) {
        self.recent[(h.seq as usize) % MD_DUP_WINDOW] = h.digest;
        self.last_digest = h.digest;
        self.applied_seq = h.seq;
    }

    /// The highest sequence number applied (0 = only the checkpoint).
    pub fn applied(&self) -> u64 {
        self.applied_seq
    }
}

// ── provider frames ───────────────────────────────────────────────────────
//
// `[op u8][len u16 LE][payload]` frames on the anchor ↔ provider port pair
// (`tc_ctl` in, `tc_evt` out). Every payload after PAIR_PREPARE and
// TOMBSTONE leads with the handle the provider issued; a handle the
// provider no longer holds is refused `STALE_HANDLE` before anything is
// mutated.

/// Anchor → provider operations.
pub mod tc_op {
    /// `[null handle 8][TcPair]` → STATUS carries the handle it issues.
    /// A primary pairs a connection it holds; a standby reserves an empty,
    /// non-emitting shadow.
    pub const PAIR_PREPARE: u8 = 1;
    /// Primary: `[handle][checkpoint_id u64]` → CHUNK… then STATUS.
    pub const CHECKPOINT_BEGIN: u8 = 2;
    /// Standby: `[handle][chunk bytes]`.
    pub const CHECKPOINT_NEXT: u8 = 3;
    /// Standby: `[handle][checkpoint_id u64]` → publish the shadow; APPLIED(0).
    pub const CHECKPOINT_COMMIT: u8 = 4;
    /// Standby: `[handle][delta frame]` → APPLIED(seq) or REJECTED.
    pub const DELTA_APPLY: u8 = 5;
    /// Primary: `[handle][acked seq u64]` → HORIZON.
    pub const DELTA_ACK: u8 = 6;
    /// Primary: `[handle]`: close the window, stop new application
    /// delivery, finish in-progress record construction.
    pub const QUIESCE_BEGIN: u8 = 7;
    /// Primary: `[handle]` → STATUS (value 1 once quiescent).
    pub const QUIESCE_STATUS: u8 = 8;
    /// Primary: `[handle]` → CUT (the final manifest).
    pub const CUT_EXPORT: u8 = 9;
    /// Standby: `[handle][cut manifest]` → STATUS (verified against shadow).
    pub const CUT_IMPORT: u8 = 10;
    /// Standby: `[handle]` → imported state and route identity ready,
    /// transmission still disabled.
    pub const EMISSION_ARM: u8 = 11;
    /// Standby: `[handle][new_epoch u32][fence_gen u32][capability 16]`:
    /// the provider rebuilds the per-flow emission token (`TcFlowToken`,
    /// naming its own anchor) and enables emission only if the verifier it
    /// was handed accepts it.
    pub const ACTIVATE: u8 = 12;
    /// `[handle]`: destroy transport keys and replicated buffers.
    pub const RETIRE: u8 = 13;
    /// `[handle]`: drop the pairing; a primary continues unprotected.
    pub const ABORT: u8 = 14;
    /// Primary: `[handle]`: the enforceable local emission-disable hook;
    /// STATUS value = the custody generation of the cutoff.
    pub const EMISSION_DISABLE: u8 = 15;
    /// `[null handle 8][flow_id 16][epoch u32][ttl_ms u32]`: suppress
    /// resets for a migrated flow. Until the tombstone expires a
    /// segment for `flow_id` that finds no live connection here is dropped
    /// silently — no RST, no new connection. A host may hold no pairing
    /// for the flow, hence the null handle. STATUS value 1 = installed;
    /// `CAPACITY` when the table is full of live tombstones (never
    /// evicted).
    pub const TOMBSTONE: u8 = 16;
    /// Standby: `[handle][challenge 32]`: its vault makes a fresh P-256
    /// recipient key for this flow and attests it (`key_vault`
    /// `ATTEST_KEY`) over the challenge → CUSTODY (`tc_custody::EVIDENCE`),
    /// then STATUS. The challenge is the transfer's, chosen by whoever
    /// decides it, so the evidence is good for that transfer alone.
    pub const CUSTODY_ATTEST: u8 = 17;
    /// Primary: `[handle][challenge 32][evidence]`: the evidence goes to the
    /// authority the provider was handed; on its verdict the provider's
    /// vault checks the evidence answers `challenge`, names an ephemeral
    /// agreement key and is signed by its signer, and wraps the flow's
    /// continuity key to that recipient, bound to the composition it
    /// attests (`KEY_WRAP`) → CUSTODY (`tc_custody::WRAPPED`), then STATUS.
    /// A refusal is STATUS `UNAUTHORIZED` (the authority's code as
    /// `reason`) or `INVALID` (`tc_custody::why`).
    pub const CUSTODY_WRAP: u8 = 18;
    /// Standby: `[handle][wrapped]`: its vault unwraps the key with the
    /// recipient CUSTODY_ATTEST made (`KEY_UNWRAP`; only that recipient, and
    /// only while its composition is the one attested, opens it) and keeps it
    /// for the flow's import → STATUS.
    pub const CUSTODY_UNWRAP: u8 = 19;
    /// A QUIC primary (the QUIC section below): `[handle][grant record]` — the durable
    /// packet-number reservation grant (`session_ctrl.rs`
    /// `CMD_SC_RESERVATION_GRANT`) a crash-continuous QUIC pairing emits
    /// under, passed to the provider's QUIC layer → STATUS.
    pub const RESERVATION_GRANT: u8 = 20;
}

/// Provider → anchor events.
pub mod tc_evt {
    /// `[op u8][status u8][reason u8][reserved u8][handle 8][value u64]
    ///  [flow_id 16]` (`TcStatus`).
    pub const STATUS: u8 = 0x81;
    /// Primary: `[handle][chunk bytes]`.
    pub const CHUNK: u8 = 0x82;
    /// Primary: `[handle][delta frame]`.
    pub const DELTA: u8 = 0x83;
    /// Standby: `[handle][checkpoint_id u64][applied seq u64]`.
    pub const APPLIED: u8 = 0x84;
    /// Standby: `[handle][reason u8]`: the stream cannot be applied; a
    /// full checkpoint is required (`tc_rej`).
    pub const REJECTED: u8 = 0x85;
    /// Primary: `[handle][acked u64][rx_limit u32][tx_limit u32]
    ///  [credits u16][flags u16]` (flags bit 0: the window is closed).
    pub const HORIZON: u8 = 0x86;
    /// Primary: `[handle][cut manifest]`.
    pub const CUT: u8 = 0x87;
    /// `[handle][kind u8][bytes]` (`tc_custody`): a standby's evidence, a
    /// primary's wrapped key.
    pub const CUSTODY: u8 = 0x88;
}

/// The vault-to-vault transfer CUSTODY_* carries: opaque to an anchor, which
/// relays the standby's evidence to the primary and the primary's wrapped
/// key back, and to the authority, which decides whether this recipient may
/// receive this flow's key. No byte of either is a key.
///
/// Evidence: `[record 148][recipient_pub 65][signer_pub 65][sig_len u16]
/// [sig]` — `record` is `key_vault` `ATTEST_KEY`'s `FXHA` record for the
/// recipient key (challenge, composition digest, backend, tier, persistence,
/// suite, uses, owner namespace, commitment, public thumbprint) and `sig`
/// the signer's P-256 `r‖s` over its SHA-256. The signer is the standby
/// host's custody identity; that it is the host the transfer was decided
/// for is the authority's question, not the provider's. Wrapped: the 168-byte
/// `key_vault` `FXKW` blob of the 32-byte continuity key.
pub mod tc_custody {
    /// CUSTODY event kinds.
    pub const EVIDENCE: u8 = 1;
    pub const WRAPPED: u8 = 2;

    pub const RECORD_LEN: usize = 148;
    pub const PUB_LEN: usize = 65;
    pub const RECIPIENT: usize = RECORD_LEN;
    pub const SIGNER: usize = RECIPIENT + PUB_LEN;
    pub const SIG_LEN: usize = SIGNER + PUB_LEN;
    pub const SIG: usize = SIG_LEN + 2;
    pub const SIG_MAX: usize = 64;
    pub const EVIDENCE_MIN: usize = SIG + 1;
    pub const EVIDENCE_MAX: usize = SIG + SIG_MAX;
    pub const WRAPPED_LEN: usize = 4 + 65 + 32 + 12 + 7 + 32 + 16;

    /// The `FXHA` record's fields (`key_vault::attest_key`).
    pub const R_MAGIC: [u8; 4] = *b"FXHA";
    pub const R_CHALLENGE: usize = 4;
    pub const R_COMPOSITION: usize = 36;
    pub const R_BACKEND: usize = 68;
    pub const R_TIER: usize = 69;
    pub const R_PERSISTED: usize = 70;
    pub const R_SUITE: usize = 72;
    pub const R_USAGE: usize = 76;
    pub const R_THUMBPRINT: usize = 116;
    /// `key_vault` suite P-256 and the uses a recipient must and must not
    /// have.
    pub const SUITE_P256: u16 = 1;
    pub const USAGE_AGREE: u32 = 1 << 2;
    pub const USAGE_PERSIST: u32 = 1 << 4;

    /// Why the evidence was refused (STATUS `reason` with `INVALID`).
    pub mod why {
        /// It does not parse.
        pub const EVIDENCE: u8 = 0xD1;
        /// It answers another challenge.
        pub const CHALLENGE: u8 = 0xD2;
        /// Its signature does not verify under its signer.
        pub const SIGNATURE: u8 = 0xD3;
        /// Its recipient is not an ephemeral P-256 agreement key, or its
        /// thumbprint is not the recipient's public key's.
        pub const RECIPIENT: u8 = 0xD4;
        /// No recipient is held for the flow (UNWRAP before ATTEST).
        pub const NO_RECIPIENT: u8 = 0xD5;
        /// The vault refused the wrap or the unwrap.
        pub const VAULT: u8 = 0xD6;
    }
}

/// Evidence, split into its parts.
#[derive(Clone, Copy, Debug)]
pub struct TcCustodyEvidence<'a> {
    pub record: &'a [u8],
    pub recipient: &'a [u8],
    pub signer: &'a [u8],
    pub sig: &'a [u8],
}

impl<'a> TcCustodyEvidence<'a> {
    /// The structural checks anyone can make of evidence for `challenge`:
    /// it parses, answers that challenge, and attests an ephemeral P-256
    /// agreement key whose thumbprint is the recipient public key carried.
    /// Whether the signature verifies, and whether its signer is the host
    /// the transfer is for, are a vault's and an authority's questions.
    pub fn check(b: &'a [u8], challenge: &[u8; 32]) -> Result<Self, u8> {
        use tc_custody::*;
        if b.len() < EVIDENCE_MIN || b.len() > EVIDENCE_MAX {
            return Err(why::EVIDENCE);
        }
        let sig_len = usize::from(tc_le_u16(b, SIG_LEN));
        if sig_len == 0 || SIG + sig_len != b.len() {
            return Err(why::EVIDENCE);
        }
        let record = &b[..RECORD_LEN];
        if record[..4] != R_MAGIC {
            return Err(why::EVIDENCE);
        }
        if record[R_CHALLENGE..R_CHALLENGE + 32] != challenge[..] {
            return Err(why::CHALLENGE);
        }
        let recipient = &b[RECIPIENT..RECIPIENT + PUB_LEN];
        let usage = tc_le_u32(record, R_USAGE);
        if tc_le_u16(record, R_SUITE) != SUITE_P256
            || usage & USAGE_AGREE == 0
            || usage & USAGE_PERSIST != 0
            || record[R_PERSISTED] != 0
            || recipient[0] != 0x04
            || record[R_THUMBPRINT..R_THUMBPRINT + 32] != sha256(recipient)[..]
        {
            return Err(why::RECIPIENT);
        }
        Ok(Self {
            record,
            recipient,
            signer: &b[SIGNER..SIGNER + PUB_LEN],
            sig: &b[SIG..],
        })
    }

    /// The composition digest the recipient's vault attested, which a wrap
    /// to it binds.
    pub fn composition(&self) -> [u8; 32] {
        let mut c = [0u8; 32];
        c.copy_from_slice(&self.record[tc_custody::R_COMPOSITION..tc_custody::R_COMPOSITION + 32]);
        c
    }
}

/// Provider statuses (STATUS `status`).
pub mod tc_st {
    pub const OK: u8 = 0;
    pub const STALE_HANDLE: u8 = 1;
    pub const STALE_EPOCH: u8 = 2;
    pub const NOT_READY: u8 = 3;
    pub const INVALID: u8 = 4;
    pub const CAPACITY: u8 = 5;
    /// ACTIVATE refused: the token does not name the committed binding
    /// (STATUS `reason` carries the verifier's refusal code).
    pub const UNAUTHORIZED: u8 = 6;
    pub const UNSUPPORTED: u8 = 7;
}

/// REJECTED reasons: why a standby discarded its shadow.
pub mod tc_rej {
    /// A checkpoint chunk out of order, conflicting or malformed.
    pub const CHUNK: u8 = 1;
    /// The published shadow names a key the vault here does not hold.
    pub const KEYS: u8 = 2;
    /// CHECKPOINT_COMMIT of an incomplete or unvalidated record.
    pub const COMMIT: u8 = 3;
    /// A delta before any checkpoint was published.
    pub const NO_SHADOW: u8 = 4;
    /// A delta frame that does not parse.
    pub const MALFORMED: u8 = 5;
    /// A KeyUpdate the vault here could not derive.
    pub const DERIVE: u8 = 6;
    /// A delta whose transition would leave the state invalid.
    pub const TRANSITION: u8 = 7;
    /// A gap, a conflicting duplicate, a broken chain or a newer history.
    pub const ORDER: u8 = 8;
}

/// Provider capability bits, reported for the active generation. Each
/// names one enforceable surface; a provider reports only what it
/// enforces.
pub mod tc_cap {
    /// Canonical TCP checkpoint/delta codec.
    pub const TCP_CODEC: u32 = 1 << 0;
    /// Canonical TLS 1.3 established-state codec.
    pub const TLS13_CODEC: u32 = 1 << 1;
    /// QUIC 1-RTT connection-state export/import.
    pub const QUIC_CODEC: u32 = 1 << 2;
    /// The receive-ACK and outbound-emission horizon gate.
    pub const HORIZON_GATE: u32 = 1 << 3;
    /// Owner-scoped destination-bound vault transfer of continuity secrets
    /// (CUSTODY_ATTEST / WRAP / UNWRAP).
    pub const VAULT_TRANSFER: u32 = 1 << 4;
    /// Per-flow import / arm / activate.
    pub const FLOW_IMPORT_ARM: u32 = 1 << 5;
    /// Cross-host authenticated ordered remote channel.
    pub const REMOTE_CHANNEL: u32 = 1 << 6;
    /// Enforceable local emission-disable hook.
    pub const EMISSION_DISABLE: u32 = 1 << 7;
    /// Migrated-flow reset suppression (tombstones).
    pub const RESET_SUPPRESSION: u32 = 1 << 8;
    /// Authority counter/key custody (reservations, floors, transfer grants).
    pub const COUNTER_CUSTODY: u32 = 1 << 9;
    /// Native QUIC path validation after takeover.
    pub const PATH_VALIDATION: u32 = 1 << 10;
    /// A protocol adapter for an on-wire-sequence datagram protocol.
    pub const DATAGRAM_ADAPTER: u32 = 1 << 11;
    /// Every bit this version defines; a report with another is refused.
    pub const ALL: u32 = (1 << 12) - 1;
}

/// The generation-checked opaque handle a provider issues per pairing.
/// Generation zero is the null handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcHandle {
    pub slot: u32,
    pub generation: u32,
}

pub const TC_HANDLE_LEN: usize = 8;

impl TcHandle {
    pub fn put(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.slot.to_le_bytes());
        out[4..8].copy_from_slice(&self.generation.to_le_bytes());
    }

    pub fn get(b: &[u8]) -> Option<Self> {
        if b.len() < TC_HANDLE_LEN {
            return None;
        }
        Some(Self {
            slot: tc_le_u32(b, 0),
            generation: tc_le_u32(b, 4),
        })
    }

    pub fn is_null(&self) -> bool {
        self.generation == 0
    }
}

pub const TC_FRAME_HDR: usize = 3;

pub const fn tc_const_max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// The largest provider frame: a handle and a delta or chunk.
pub const TC_FRAME_MAX: usize =
    TC_FRAME_HDR + TC_HANDLE_LEN + 8 + 3 + tc_const_max(MD_FRAME_MAX, CKPT_CHUNK_MAX);
const _: () = assert!(TC_FRAME_MAX - TC_FRAME_HDR <= u16::MAX as usize);

/// Write one frame from `parts`; `None` when it does not fit.
pub fn tc_frame(out: &mut [u8], op: u8, parts: &[&[u8]]) -> Option<usize> {
    let mut len = 0usize;
    for p in parts {
        len += p.len();
    }
    if len > u16::MAX as usize || out.len() < TC_FRAME_HDR + len {
        return None;
    }
    out[0] = op;
    out[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    let mut at = TC_FRAME_HDR;
    for p in parts {
        out[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    Some(at)
}

/// `(op, payload length)` of a frame header.
pub fn tc_frame_hdr(b: &[u8]) -> Option<(u8, usize)> {
    if b.len() < TC_FRAME_HDR {
        return None;
    }
    Some((b[0], usize::from(u16::from_le_bytes([b[1], b[2]]))))
}

/// The PAIR_PREPARE body after the null handle, fixed 47 bytes:
/// `flow_id[16] flow_epoch u32 role u8 mode u8 transport u8
///  mirror_generation u64 service_id[16]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcPair {
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub role: TcRole,
    pub mode: TcMode,
    pub transport: TcTransport,
    pub mirror_generation: u64,
    pub service_id: [u8; 16],
}

pub const TC_PAIR_LEN: usize = 16 + 4 + 3 + 8 + 16;

// ── QUIC (`TcTransport::Quic`) ───────────────────────────────────────────
//
// A QUIC connection is one layer — its packet-number spaces, streams, flow
// control, CIDs and sealed secrets are the QUIC provider's own canonical record (Fluxor's `quic`
// module: `CT_QUIC`, `QKRC`) — so the canonical record here is that record
// whole, behind a header an anchor reads without the provider's codec:
//
//   magic "WHQ1"[4] version u8 = 1 reserved u8 reserved u16
//   flow_id[16] flow_epoch u32 mirror_generation u64 service_id[16]
//   layer_gen u32 layer_len u32 layer_digest[32]   (SHA-256 of the record)
//   our_cid_len u8 our_cid[20] peer_cid_len u8 peer_cid[20]
//   peer_ip[16] peer_port u16 family u8 key_phase u8
//   next_send_pn u64 largest_recv_pn u64
//   then layer_len bytes: the provider's record
//
// A CID's bytes past its length are zero, and an IPv4 path is its
// IPv4-mapped address with family 4. The anchor's view (CIDs, path,
// packet-number high-water, key phase) is read from the record by the
// provider and checked against it at the standby: a header that disagrees
// with the record it carries is refused.
// A QUIC pairing's record crosses in the same `WHCC` chunks, and its deltas
// are `MdKind::QuicDelta`, each the provider's own per-layer transition
// carried whole: `[layer_no u32][kind u8][data]`
// (`session_ctrl.rs` `DELTA_QUIC_SEND` / `_RECV` / `_KEY_PHASE`), so the
// standby's QUIC layer applies exactly what the primary's emitted. The
// packet-number rule is the provider's: a takeover resumes strictly above
// every number the primary could have used (its reservation's high-water,
// raised by every send delta), so no number is reused under a key phase.
// The flow is named `tc_flow_id_quic` of the connection's server CID.
// ACTIVATE is the same fail-closed check and authority verdict as TCP's;
// an activated QUIC standby validates the client's path before it trusts it
// (RFC 9000 §8.2: a PATH_CHALLENGE, and three times what the path sent
// until it answers). The cut's `state_digest` is SHA-256 over the record's
// digest and the last delta's chain digest.

pub const TC_QUIC_MAGIC: [u8; 4] = *b"WHQ1";
pub const TC_QUIC_VERSION: u8 = 1;
pub const TC_QUIC_CID_MAX: usize = 20;
pub const TC_QUIC_HDR: usize = 4
    + 4
    + 16
    + 4
    + 8
    + 16
    + 4
    + 4
    + 32
    + 1
    + TC_QUIC_CID_MAX
    + 1
    + TC_QUIC_CID_MAX
    + 16
    + 2
    + 1
    + 1
    + 8
    + 8;
/// The largest provider record a QUIC pairing carries.
pub const TC_QUIC_LAYER_MAX: usize = 48 * 1024;
const _: () = assert!(TC_QUIC_HDR + TC_QUIC_LAYER_MAX <= TS_CKPT_MAX);

/// The anchor's view of a QUIC record.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TcQuicView {
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub service_id: [u8; 16],
    pub layer_gen: u32,
    pub layer_len: u32,
    pub layer_digest: [u8; 32],
    pub our_cid_len: u8,
    pub our_cid: [u8; TC_QUIC_CID_MAX],
    pub peer_cid_len: u8,
    pub peer_cid: [u8; TC_QUIC_CID_MAX],
    pub peer_ip: [u8; 16],
    pub peer_port: u16,
    pub family: u8,
    pub key_phase: u8,
    pub next_send_pn: u64,
    pub largest_recv_pn: u64,
}

/// Write the record: `v`'s header, then `layer` (whose length and digest
/// the header must already name).
pub fn tc_quic_encode(v: &TcQuicView, layer: &[u8], out: &mut [u8]) -> Option<usize> {
    if layer.len() != v.layer_len as usize || layer.len() > TC_QUIC_LAYER_MAX {
        return None;
    }
    let mut w = TcW::new(out);
    w.bytes(&TC_QUIC_MAGIC)?;
    w.u8(TC_QUIC_VERSION)?;
    w.u8(0)?;
    w.u16(0)?;
    w.bytes(&v.flow_id)?;
    w.u32(v.flow_epoch)?;
    w.u64(v.mirror_generation)?;
    w.bytes(&v.service_id)?;
    w.u32(v.layer_gen)?;
    w.u32(v.layer_len)?;
    w.bytes(&v.layer_digest)?;
    w.u8(v.our_cid_len)?;
    w.bytes(&v.our_cid)?;
    w.u8(v.peer_cid_len)?;
    w.bytes(&v.peer_cid)?;
    w.bytes(&v.peer_ip)?;
    w.u16(v.peer_port)?;
    w.u8(v.family)?;
    w.u8(v.key_phase)?;
    w.u64(v.next_send_pn)?;
    w.u64(v.largest_recv_pn)?;
    w.bytes(layer)?;
    Some(w.at)
}

/// Parse a record: its view and the provider record, the digest checked.
pub fn tc_quic_parse(b: &[u8]) -> Result<(TcQuicView, &[u8]), CkptError> {
    use CkptError::*;
    if b.len() < TC_QUIC_HDR {
        return Err(Truncated);
    }
    let mut r = TcR::new(b);
    if r.take(4).ok_or(Truncated)? != TC_QUIC_MAGIC {
        return Err(BadMagic);
    }
    if r.u8().ok_or(Truncated)? != TC_QUIC_VERSION {
        return Err(Version);
    }
    if r.u8().ok_or(Truncated)? != 0 || r.u16().ok_or(Truncated)? != 0 {
        return Err(Reserved);
    }
    let mut v = TcQuicView {
        flow_id: r.arr().ok_or(Truncated)?,
        flow_epoch: r.u32().ok_or(Truncated)?,
        mirror_generation: r.u64().ok_or(Truncated)?,
        service_id: r.arr().ok_or(Truncated)?,
        layer_gen: r.u32().ok_or(Truncated)?,
        layer_len: r.u32().ok_or(Truncated)?,
        layer_digest: r.arr().ok_or(Truncated)?,
        ..TcQuicView::default()
    };
    v.our_cid_len = r.u8().ok_or(Truncated)?;
    v.our_cid = r.arr().ok_or(Truncated)?;
    v.peer_cid_len = r.u8().ok_or(Truncated)?;
    v.peer_cid = r.arr().ok_or(Truncated)?;
    v.peer_ip = r.arr().ok_or(Truncated)?;
    v.peer_port = r.u16().ok_or(Truncated)?;
    v.family = r.u8().ok_or(Truncated)?;
    v.key_phase = r.u8().ok_or(Truncated)?;
    v.next_send_pn = r.u64().ok_or(Truncated)?;
    v.largest_recv_pn = r.u64().ok_or(Truncated)?;
    if usize::from(v.our_cid_len) > TC_QUIC_CID_MAX
        || usize::from(v.peer_cid_len) > TC_QUIC_CID_MAX
        || !matches!(v.family, 4 | 6)
        || v.key_phase > 1
        || v.flow_epoch == 0
    {
        return Err(Bounds);
    }
    // One encoding per view: a CID's bytes past its length are zero, and an
    // IPv4 path is exactly the IPv4-mapped address (family 4).
    let mapped = v.peer_ip[..10] == [0; 10] && v.peer_ip[10..12] == [0xFF, 0xFF];
    if v.our_cid[usize::from(v.our_cid_len)..]
        .iter()
        .any(|&x| x != 0)
        || v.peer_cid[usize::from(v.peer_cid_len)..]
            .iter()
            .any(|&x| x != 0)
        || (v.family == 4) != mapped
    {
        return Err(Reserved);
    }
    let layer = &b[TC_QUIC_HDR..];
    if layer.len() != v.layer_len as usize || layer.len() > TC_QUIC_LAYER_MAX {
        return Err(Bounds);
    }
    if sha256(layer) != v.layer_digest {
        return Err(Digest);
    }
    Ok((v, layer))
}

/// The flow identity of a QUIC connection: `0xF7`, then the first fifteen
/// bytes of SHA-256 over `"fxqc.flow" ‖ the server's connection ID`.
pub fn tc_flow_id_quic(server_cid: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"fxqc.flow");
    h.update(server_cid);
    let d = h.finalize();
    let mut f = [0u8; 16];
    f[0] = 0xF7;
    f[1..16].copy_from_slice(&d[..15]);
    f
}

/// The cut's state digest for a QUIC pairing: the record's digest and the
/// last delta's chain digest (its checkpoint's final chain before any).
pub fn tc_quic_state_digest(record_digest: &[u8; 32], last_chain: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"whq1.cut");
    h.update(record_digest);
    h.update(last_chain);
    h.finalize()
}

/// The flow identity `ip` names an IPv6 connection by (its IPv4 identity is
/// the tuple, `[local_ip][remote_ip][local_port][remote_port][0;4]`; an IPv6
/// tuple does not fit sixteen bytes): `0xF6` then the first fifteen bytes of
/// SHA-256 over `"fxtc.v6.flow" ‖ local ‖ remote ‖ local_port BE ‖
/// remote_port BE`, the same on every host that holds the connection. An
/// IPv4 identity never starts `0xF6` (no local address is in 246.0.0.0/8).
pub fn tc_flow_id_v6(
    local: &[u8; 16],
    remote: &[u8; 16],
    local_port: u16,
    remote_port: u16,
) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"fxtc.v6.flow");
    h.update(local);
    h.update(remote);
    h.update(&local_port.to_be_bytes());
    h.update(&remote_port.to_be_bytes());
    let d = h.finalize();
    let mut f = [0u8; 16];
    f[0] = 0xF6;
    f[1..16].copy_from_slice(&d[..15]);
    f
}

impl TcPair {
    pub fn encode(&self, out: &mut [u8; TC_PAIR_LEN]) {
        out[0..16].copy_from_slice(&self.flow_id);
        out[16..20].copy_from_slice(&self.flow_epoch.to_le_bytes());
        out[20] = self.role.wire();
        out[21] = self.mode.wire();
        out[22] = self.transport.wire();
        out[23..31].copy_from_slice(&self.mirror_generation.to_le_bytes());
        out[31..47].copy_from_slice(&self.service_id);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != TC_PAIR_LEN {
            return None;
        }
        Some(Self {
            flow_id: tc_id16(b, 0),
            flow_epoch: tc_le_u32(b, 16),
            role: TcRole::from_u8(b[20])?,
            mode: TcMode::from_u8(b[21])?,
            transport: TcTransport::from_u8(b[22])?,
            mirror_generation: tc_le_u64(b, 23),
            service_id: tc_id16(b, 31),
        })
    }
}

/// The STATUS event, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcStatus {
    pub op: u8,
    pub status: u8,
    pub reason: u8,
    pub handle: TcHandle,
    pub value: u64,
    /// The flow the operation named (a PAIR_PREPARE answer arrives before
    /// the anchor holds the handle it issues).
    pub flow_id: [u8; 16],
}

pub const TC_STATUS_LEN: usize = 4 + TC_HANDLE_LEN + 8 + 16;

impl TcStatus {
    pub fn encode(&self, out: &mut [u8; TC_STATUS_LEN]) {
        out[0] = self.op;
        out[1] = self.status;
        out[2] = self.reason;
        out[3] = 0;
        self.handle.put(&mut out[4..12]);
        out[12..20].copy_from_slice(&self.value.to_le_bytes());
        out[20..36].copy_from_slice(&self.flow_id);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != TC_STATUS_LEN || b[3] != 0 {
            return None;
        }
        Some(Self {
            op: b[0],
            status: b[1],
            reason: b[2],
            handle: TcHandle::get(&b[4..12])?,
            value: tc_le_u64(b, 12),
            flow_id: tc_id16(b, 20),
        })
    }
}

/// The planned-migration cut: the final delta, and the
/// digest of the canonical state encoding at that delta, which the standby
/// must reproduce from its shadow byte for byte. Fixed 72 bytes:
/// `flow_id[16] flow_epoch u32 reserved u32 mirror_generation u64
///  last_seq u64 state_digest[32]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcCut {
    pub flow_id: [u8; 16],
    pub flow_epoch: u32,
    pub mirror_generation: u64,
    pub last_seq: u64,
    pub state_digest: [u8; 32],
}

pub const TC_CUT_LEN: usize = 72;

impl TcCut {
    pub fn encode(&self, out: &mut [u8; TC_CUT_LEN]) {
        out[0..16].copy_from_slice(&self.flow_id);
        out[16..20].copy_from_slice(&self.flow_epoch.to_le_bytes());
        out[20..24].copy_from_slice(&0u32.to_le_bytes());
        out[24..32].copy_from_slice(&self.mirror_generation.to_le_bytes());
        out[32..40].copy_from_slice(&self.last_seq.to_le_bytes());
        out[40..72].copy_from_slice(&self.state_digest);
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != TC_CUT_LEN || tc_le_u32(b, 20) != 0 {
            return None;
        }
        let mut state_digest = [0u8; 32];
        state_digest.copy_from_slice(&b[40..72]);
        Some(Self {
            flow_id: tc_id16(b, 0),
            flow_epoch: tc_le_u32(b, 16),
            mirror_generation: tc_le_u64(b, 24),
            last_seq: tc_le_u64(b, 32),
            state_digest,
        })
    }
}

/// The digest a cut names: of the canonical encoding (which is unique for
/// a state), so equal digests mean byte-identical state. `scratch` holds
/// the encoding (`TS_CKPT_MAX` always suffices).
pub fn tc_state_digest(s: &TsState, scratch: &mut [u8]) -> Option<[u8; 32]> {
    let n = ts_encode(s, scratch).ok()?;
    Some(sha256(&scratch[..n]))
}

/// The per-flow emission token ACTIVATE is checked against: minted by the
/// authority that committed the takeover — the ownership directory's flow
/// token, from its committed fenced move — for one flow, the epoch it
/// committed, the anchor it promoted and the fence generation it named.
/// The anchor sends only the 16-byte capability; the provider rebuilds the
/// rest from the command and its OWN anchor id, so a token minted for
/// another anchor, epoch or fence cannot verify here.
///
/// Wire layout, 48 bytes, the minting authority's: `flow_id[16] epoch u32
/// anchor[8] fence_gen u32 capability[16]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcFlowToken {
    pub flow_id: [u8; 16],
    pub epoch: u32,
    pub anchor: [u8; 8],
    pub fence_gen: u32,
    pub capability: [u8; 16],
}

pub const TC_FLOW_TOKEN_LEN: usize = 48;

impl TcFlowToken {
    pub fn encode(&self, out: &mut [u8; TC_FLOW_TOKEN_LEN]) {
        out[0..16].copy_from_slice(&self.flow_id);
        out[16..20].copy_from_slice(&self.epoch.to_le_bytes());
        out[20..28].copy_from_slice(&self.anchor);
        out[28..32].copy_from_slice(&self.fence_gen.to_le_bytes());
        out[32..48].copy_from_slice(&self.capability);
    }
}
