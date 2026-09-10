//! IP Stack Service Module
//!
//! Implements TCP/IP networking as a PIC module. Receives raw ethernet frames
//! from a driver module (e.g. cyw43) via channels, processes ARP/IPv4/ICMP/TCP/UDP,
//! and communicates with consumer modules (HTTP, TLS) via a channel-based net protocol.
//!
//! # Architecture
//!
//! ```text
//! Driver Module (cyw43/enc28j60)           IP Module                    Consumer (HTTP/TLS)
//! ─────────────────────────────           ─────────                    ───────────────────
//! ETH frames → [out_chan] ──────► [in_chan] → ARP/IPv4 parse
//!                                            ├── ICMP echo → reply ──► [out_chan] → driver
//!                                            ├── DHCP reply → config
//!                                            ├── TCP data ────────────► [net_out] MSG_DATA
//!                                            └── UDP datagram ────────► [net_out] MSG_DATA
//! [net_in] CMD_SEND ──────────► TCP/UDP build ──► [out_chan] → driver
//! ```
//!
//! # Channels
//!
//! - `in_chan` (in[0]): Raw ethernet frames from driver module
//! - `out_chan` (out[0]): Raw ethernet frames to driver module
//! - `net_in_chan` (in[1]): Net protocol commands from consumer (CMD_BIND, CMD_SEND, etc.)
//! - `net_out_chan` (out[1]): Net protocol messages to consumer (MSG_DATA, MSG_ACCEPTED, etc.)
//!
//! # Stack profile
//!
//! The supported profile is deliberately narrow, and the narrowing is a
//! constraint on what may reach the transport layers — not a gap to be filled
//! opportunistically:
//!
//! - **No IPv4 reassembly.** Packets carrying MF or a nonzero fragment offset
//!   are dropped before L4 dispatch. Presenting a fragment to TCP/UDP as a
//!   whole packet lets a peer's second fragment decide what the first one
//!   meant, and a bounded reassembler is not implemented.
//! - **One subnet, one default gateway.** An off-subnet destination with no
//!   configured gateway is unreachable; the stack does not ARP directly for
//!   it, which would let any station on the segment answer for an address it
//!   does not own.
//! - **ARP mappings are created only by ARP.** Ordinary IPv4 traffic may
//!   refresh an existing same-MAC entry; it can neither install a new mapping
//!   nor move an existing one.
//! - **One transmit frame per datagram.** There is no transmit-side
//!   fragmentation, so a UDP payload past the frame ceiling is refused with
//!   `EMSGSIZE` rather than truncated.
//!
//! # Config Parameters
//!
//! | Tag | Name     | Type | Default | Description                |
//! |-----|----------|------|---------|----------------------------|
//! | 1   | use_dhcp | u8   | 1       | Enable DHCP (1=yes, 0=no) |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim, zero-copy packet buffers, and MMIO-adjacent operations"
)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
// SHA-256 and the chunked-handoff core, for transport-continuity records.
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/cores/session_handoff.rs");

#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod arp;
/// TCP transport continuity: checkpoint codec, mirror stream, cut-over.
pub mod continuity;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod dhcp;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod eth;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod icmp;
mod index;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod ipv4;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod tcp;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod udp;

// ============================================================================
// Constants
// ============================================================================

/// Maximum ethernet frame size
const MAX_FRAME_SIZE: usize = 1536;

/// Largest transmit frame `send_frame` will accept. It stages
/// `[len:u16 LE][frame…]` inside a single buffer, so two bytes of the
/// ceiling belong to the length prefix.
const MAX_TX_FRAME_PAYLOAD: usize = MAX_FRAME_SIZE - 2;

/// Largest UDP payload that fits one transmit frame. Every frame builder
/// writes into the fixed `tx_frame`, so a datagram past this size cannot be
/// staged at all — it is refused before any copy, never truncated.
const MAX_UDP_TX_PAYLOAD: usize =
    MAX_TX_FRAME_PAYLOAD - eth::ETH_HEADER_LEN - ipv4::IPV4_HEADER_LEN - udp::UDP_HEADER_LEN;

/// Largest TCP payload that fits one transmit frame. The segmenter caps
/// chunks at `tcp::MSS`, which is below this; the bound is the frame
/// builder's own precondition, independent of the caller's arithmetic.
const MAX_TCP_TX_PAYLOAD: usize =
    MAX_TX_FRAME_PAYLOAD - eth::ETH_HEADER_LEN - ipv4::IPV4_HEADER_LEN - tcp::TCP_HEADER_LEN;

/// Largest ICMP message that fits one transmit frame (echo reply is built
/// in place from the request, so the request bounds the reply).
const MAX_ICMP_TX_LEN: usize = MAX_TX_FRAME_PAYLOAD - eth::ETH_HEADER_LEN - ipv4::IPV4_HEADER_LEN;

/// Errno values surfaced to consumers through `MSG_ERROR` / `MSG_DG_ERROR`.
/// Linux numbering, negated on the wire like the rest of the net surface.
const E_MSGSIZE: i8 = -90;
const E_NETUNREACH: i8 = -101;

/// CMD_SEND stash capacity. Must match the largest single-frame
/// payload an upstream consumer can write — `NET_BUF_SIZE` per
/// target. Anything smaller would truncate `ip_net_read_frame`'s
/// body, leaving tail bytes in the ring that the next header parse
/// would mistake for a frame.
#[cfg(target_arch = "aarch64")]
const PENDING_CMD_BUF_SIZE: usize = 8192;
#[cfg(not(target_arch = "aarch64"))]
const PENDING_CMD_BUF_SIZE: usize = 1600;

// NET_FRAME_HDR (3 bytes: msg_type + len u16 LE) defined in pic_runtime.rs

/// Net protocol: downstream messages (IP → consumer)
const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;
/// Request that the consumer retransmit data from `from_seq` onwards on
/// the named connection. Fires on 3 duplicate ACKs or an RTO timeout.
const NET_MSG_RETRANSMIT: u8 = 0x07;
/// Advance the consumer-side "acknowledged bytes" watermark so the
/// consumer may free its retained send buffer up to this offset.
const NET_MSG_ACK: u8 = 0x08;

/// Net protocol: upstream commands (consumer → IP)
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;

// Datagram surface opcodes share the same `net_in` / `net_out` pair as
// net_proto; the disjoint opcode ranges keep the contracts unambiguous.
// See `modules/sdk/contracts/net/datagram.rs`.

// `DG_OWNER_TAG_MARK` / `DG_OWNER_TAG_FIELD` — the marker byte that introduces
// the owner tag on `DG_CMD_SEND_TO` / `DG_CMD_CLOSE`, and the field's width —
// come from `sdk/runtime/net.rs`, which re-exports the contract for every
// module on the datagram surface.

/// Bytes of a `DG_CMD_SEND_TO` payload after the owner-tag field:
/// `[af:1][addr:4][port:2]`.
const DG_V4_DEST_LEN: usize = 1 + 4 + 2;

// ── Multi-homing address table ──────────────────

/// Address-table size. Slot 0 is the primary; slots 1.. are secondaries
/// added via the `addr_ctl` port. Scanned per-frame on the RX path, so the
/// tunable is deliberately small (see the demux comment in `process_ipv4`).
pub use abi::config::ip::MAX_LOCAL_ADDRS;

/// Packets the decision seam may hold at once (`abi::config::ip`). One
/// frame each; exhaustion refuses the next packet rather than displacing a
/// held one.
pub use abi::config::ip::MAX_PACKET_HOLD;

/// Datagram endpoints occupy the first `MAX_DG_ENDPOINTS` connection slots:
/// the wire's `ep_id` is a u8, so the id space binds the endpoint count,
/// not the connection table.
pub use abi::config::ip::MAX_DG_ENDPOINTS;

/// Hash index over the connection table: twice the table, so chains stay
/// short (`index.rs`).
const CONN_INDEX_SIZE: usize = tcp::MAX_TCP_CONNS * 2;
/// Hash index over the local-address table: four times the table, since
/// it is small and every inbound packet demuxes through it.
const ADDR_INDEX_SIZE: usize = MAX_LOCAL_ADDRS * 4;
/// Listening TCP slots tracked by list: a SYN is matched against these,
/// never against the whole table.
const MAX_LISTENERS: usize = if tcp::MAX_TCP_CONNS < 1024 {
    tcp::MAX_TCP_CONNS
} else {
    1024
};
/// Per-port reference counts, so "is this port bound?" is a load. Only
/// worth 128 KiB where the table is large enough for a scan to matter;
/// the small profiles keep the scan.
const PORT_REF_ENTRIES: usize = if tcp::MAX_TCP_CONNS >= 4096 { 65536 } else { 1 };
/// Sources whose half-open count is tracked individually.
///
/// Sized against the half-open ceiling rather than a round number, at the
/// same 2:1 the connection index keeps, because the entries are consumed
/// by DISTINCT sources and a flood is distinct sources by definition. A
/// table smaller than the ceiling fills, and a full table has no free
/// entry to stop a probe at: `source_enter` then walks the whole thing and
/// reports nothing, so the per-source gauge goes blind during exactly the
/// flood it exists to measure. Eight bytes an entry, against a connection
/// table three orders larger.
const HO_SRC_ENTRIES: usize = if tcp::MAX_TCP_CONNS >= 4096 {
    tcp::MAX_TCP_CONNS
} else {
    16
};
const _: () = assert!(HO_SRC_ENTRIES >= tcp::SYN_COOKIE_WATERMARK as usize * 2);
const _: () = assert!(HO_SRC_ENTRIES.is_power_of_two());
/// The TCP timer window: every connection's timers advance once per
/// window, in slices spread across it.
const TCP_SWEEP_WINDOW_MS: u32 = 50;
/// Most connections one step's slice of the timer sweep visits. The
/// proportional slice normally visits a few hundred; this is the ceiling
/// it meets after a stall, when the whole window is owed at once — a
/// full table in one step is a multi-millisecond step on a table whose
/// records are cache misses, and the step guard would end the module for
/// it. The sweep lags a stall by at most `MAX_TCP_CONNS / SWEEP_SLICE_MAX`
/// steps instead.
const SWEEP_SLICE_MAX: usize = 1024;
/// Handshakes held back by neighbour resolution, remembered so an ARP
/// reply retries exactly those rather than walking the table. The timer
/// sweep retries an unsent handshake every tick regardless, so a full
/// list costs latency, never correctness.
const ARP_WAIT_MAX: usize = 64;

/// Wildcard local-address slot — re-exported from `tcp` so the two modules
/// agree on the sentinel used by `TcpConn::local_slot` / `find_conn`.
use tcp::LOCAL_SLOT_ANY;

/// `LocalAddr::flags` bits.
const ADDR_FLAG_PRIMARY: u8 = 0x01;
/// The address emits: frames are sourced from it and ARP for it answered.
/// Clear = fenced. The primary is always armed.
const ADDR_FLAG_ARMED: u8 = 0x02;

/// One configured local address. 16-byte address with IPv4 in the first four
/// bytes (network order), matching the workload CREATE-header convention so
/// IPv6 later is a parser/ND project, not a layout migration. Fields are
/// reordered from the RFC's prose for tight `repr(C)` packing; the wire
/// `addr_ctl` payload is parsed field-by-field, so struct layout is
/// internal-only.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LocalAddr {
    /// 16-byte address, IPv4 in bytes 0..4 (network order).
    pub addr: [u8; 16],
    /// Emission token minted at install; presented by `ADDR_ARM` /
    /// `ADDR_FENCE`. Fresh per install and per boot.
    pub token: [u8; 16],
    /// Install generation, monotonic per module instance.
    pub generation: u32,
    /// Owning workload tag (0 = host/system — a legitimate owner, not a
    /// sentinel). Enforced on bind: an
    /// owner-stamped bind binds only to the address whose `owner_tag` matches,
    /// and an owned secondary (`owner_tag != 0`) is served only by a listener
    /// explicitly bound to it — never by a host wildcard listener. Set via the
    /// `addr_ctl` `IP_ADDR_ADD` payload by the trusted single writer.
    pub owner_tag: u16,
    pub prefix_len: u8,
    pub flags: u8,
}

impl LocalAddr {
    pub const fn empty() -> Self {
        Self {
            addr: [0u8; 16],
            token: [0u8; 16],
            generation: 0,
            owner_tag: 0,
            prefix_len: 0,
            flags: 0,
        }
    }

    /// A slot is in use when its IPv4 word is non-zero (v1 is IPv4-only).
    #[inline(always)]
    fn is_active(&self) -> bool {
        (self.addr[0] | self.addr[1] | self.addr[2] | self.addr[3]) != 0
    }

    /// Decode the IPv4 address as the host-order `u32` the stack compares
    /// against `ip_hdr.dst_ip` and stamps into headers.
    #[inline(always)]
    fn ipv4(&self) -> u32 {
        u32::from_be_bytes([self.addr[0], self.addr[1], self.addr[2], self.addr[3]])
    }

    #[inline(always)]
    fn set_ipv4(&mut self, ip: u32) {
        let b = ip.to_be_bytes();
        self.addr[0] = b[0];
        self.addr[1] = b[1];
        self.addr[2] = b[2];
        self.addr[3] = b[3];
    }
}

/// `addr_ctl` port opcodes — the shared `net::identity` control contract
/// (`modules/sdk/contracts/net/identity.rs`). This module is one *provider* of
/// that contract; the workload backend is its writer. Both sides reference these
/// same constants, so the opcodes/payload layout have a single source of truth
/// (they were previously duplicated here and in the kernel, hand-synced).
///   ADDR_ADD payload: [addr:16][prefix_len:1][owner_tag:2 LE]
///   ADDR_DEL payload: [addr:16]
use abi::contracts::net::identity as netid;
const IP_ADDR_ADD: u8 = netid::ADDR_ADD;
const IP_ADDR_DEL: u8 = netid::ADDR_DEL;
const IP_ADDR_ARM: u8 = netid::ADDR_ARM;
const IP_ADDR_FENCE: u8 = netid::ADDR_FENCE;
/// Emission events to the address-control writer (out[5]).
const ADDR_EVT_PORT: u8 = 5;
/// THIS module's input-port indices, declared to the kernel at init via the
/// `NET_IDENT_PROVIDER` self-registration (module-local facts, matching
/// `manifest.toml` — no longer part of the shared contract).
const NET_IN_PORT: u8 = 1;
const ADDR_CTL_PORT: u8 = 2;
/// Pre-transport decision seam ports (`packet.rs` §decision seam):
/// dispositions in, decision records out, forwarded frames out.
const PACKET_IN_PORT: u8 = 3;
const PACKET_OUT_PORT: u8 = 3;
const PACKET_FWD_PORT: u8 = 4;

/// `packet_decision` values.
const PKT_DECISION_OFF: u8 = 0;
const PKT_DECISION_PRE_TRANSPORT: u8 = 1;

/// Max bytes per queued outbound control frame. Sized for the
/// largest short frame `net_send_*` produces (MSG_RETRANSMIT /
/// MSG_ACK at 8 bytes). MSG_DATA goes through its own per-conn
/// backpressure path.
/// Largest control frame the fallback queue holds: the 3-byte header, a
/// u16 connection id and a u32 sequence number (`MSG_RETRANSMIT`,
/// `MSG_ACK`).
const NET_OUT_FRAME_MAX: usize = 9;
const NET_OUT_QUEUE_SLOTS: usize = 32;

/// `TcpConn::pending_close_notify` codes — non-zero values identify
/// which helper `step_tcp_timers` retries once `net_out_chan` has
/// space.
const NOTIFY_NONE: u8 = 0;
const NOTIFY_CLOSED: u8 = 1;
const NOTIFY_ERROR_REFUSED: u8 = 2;
/// Successful outbound connect whose `MSG_CONNECTED` couldn't be delivered yet
/// — retried so a waiter always learns it connected (conn stays Established).
const NOTIFY_CONNECTED: u8 = 3;
/// Connect timeout (`ETIMEDOUT`) whose `MSG_ERROR` couldn't be delivered yet —
/// retried, then the slot frees (conn is `Closed`).
const NOTIFY_ERROR_TIMEOUT: u8 = 4;
/// TCP timer ticks per second (`step_tcp_timers` advances every 50 ms).
const TCP_TIMER_HZ: u16 = 20;
/// CloseWait bound: the peer has closed and the consumer has not answered
/// with CMD_CLOSE. net_proto's release rule (`CLOSED_ID_GRACE_MS`, 5 s) — the
/// consumer may still close within it and never hits a newcomer; after it
/// this module finishes the close itself so a consumer that never answers
/// cannot leak the slot. Unbounded, this is a slow table leak with a hard
/// end: 254 client-closed connections fill the 256-slot table and every SYN
/// after them is dropped `no_slot`.
const CLOSE_WAIT_TICKS: u16 = (abi::contracts::net::net_proto::CLOSED_ID_GRACE_MS / 50) as u16;

/// A TCP-conn slot is free for re-allocation only when it's `Closed`
/// AND no close-notification latch is still pending — reusing a
/// latched slot would strand the consumer's `MSG_CLOSED` /
/// `MSG_ERROR`.
#[inline(always)]
fn slot_is_free(conn: &tcp::TcpConn) -> bool {
    conn.state == tcp::TcpState::Closed && conn.pending_close_notify == NOTIFY_NONE
}

// ── Table lookup structures (`index.rs`) ────────────────────────────
//
// Every connection that becomes keyed — accepted, cookie-installed,
// connected, bound, or paired for loopback — passes through
// `conn_index_insert` once its fields are set, and every slot release
// passes through `conn_reset`. Those two are the whole maintenance
// surface; lookups validate what they find, so a stale entry can never
// yield a wrong hit, only a longer probe.

/// A connection's index key.
#[inline]
/// The key a connection is indexed under.
///
/// Every field here is immutable for as long as the slot is indexed:
/// `conn_index_insert` runs after they are set and `conn_reset` computes
/// the hash before it clears them, and the removal path rehashes the
/// entries it shifts. A field changed in between would give a different
/// bucket than the one the entry sits in, and the entry would be moved off
/// its own chain rather than found.
fn conn_key_of(c: &tcp::TcpConn) -> index::ConnKey {
    index::ConnKey {
        remote_ip: c.remote_ip,
        remote_port: c.remote_port,
        local_port: c.local_port,
        local_slot: c.local_slot,
    }
}

/// Whether a connection is looked up by 4-tuple: anything with a remote
/// that is neither a listener nor a datagram endpoint.
#[inline]
fn conn_is_keyed(c: &tcp::TcpConn) -> bool {
    !c.is_datagram && c.remote_ip != 0 && c.state != tcp::TcpState::Listen
}

/// Every connection on one listener holds a reference to that listener's
/// port, so a single port's count reaches the whole connection table plus
/// the listener itself. The counter is wider than that sum can be: a
/// saturating add that clamped would lose a reference, and the matching
/// subtractions would then take a port to zero while something was still
/// bound to it — which reads as free.
const _: () = assert!(tcp::MAX_TCP_CONNS < u32::MAX as usize);

#[inline]
unsafe fn port_ref_inc(s: &mut IpState, port: u16) {
    if PORT_REF_ENTRIES > 1 {
        let e = &mut *s.port_ref.as_mut_ptr().add(port as usize);
        *e = e.saturating_add(1);
    }
}

#[inline]
unsafe fn port_ref_dec(s: &mut IpState, port: u16) {
    if PORT_REF_ENTRIES > 1 {
        let e = &mut *s.port_ref.as_mut_ptr().add(port as usize);
        *e = e.saturating_sub(1);
    }
}

unsafe fn listener_add(s: &mut IpState, idx: usize) {
    let mut i = 0;
    while i < MAX_LISTENERS {
        if s.listeners[i] == 0 {
            s.listeners[i] = idx as u32 + 1;
            return;
        }
        i += 1;
    }
}

unsafe fn listener_remove(s: &mut IpState, idx: usize) {
    let want = idx as u32 + 1;
    let mut i = 0;
    while i < MAX_LISTENERS {
        if s.listeners[i] == want {
            s.listeners[i] = 0;
            return;
        }
        i += 1;
    }
}

/// One more half-open connection from `ip`.
unsafe fn half_open_enter(s: &mut IpState, ip: u32) {
    s.tcp_half_open = s.tcp_half_open.saturating_add(1);
    if s.tcp_half_open > s.tcp_half_open_max {
        s.tcp_half_open_max = s.tcp_half_open;
    }
    match index::source_enter(&mut s.ho_src, ip) {
        Some(n) => {
            if n > s.tcp_half_open_src_max {
                s.tcp_half_open_src_max = n;
            }
        }
        None => s.ho_src_untracked = s.ho_src_untracked.wrapping_add(1),
    }
}

/// One fewer half-open connection from `ip`.
unsafe fn half_open_leave(s: &mut IpState, ip: u32) {
    s.tcp_half_open = s.tcp_half_open.saturating_sub(1);
    index::source_leave(&mut s.ho_src, ip);
}

/// Register a connection whose fields are now set: index it by tuple,
/// list it if it listens, count its port, count it if half-open.
unsafe fn conn_index_insert(s: &mut IpState, idx: usize) {
    let (keyed, hash, listens, local_port, half_open, remote_ip) = {
        let c = &*s.tcp_conns.as_ptr().add(idx);
        (
            conn_is_keyed(c),
            conn_key_of(c).hash(s.index_seed),
            c.state == tcp::TcpState::Listen && !c.is_datagram,
            c.local_port,
            c.state == tcp::TcpState::SynReceived && !c.half_open_counted,
            c.remote_ip,
        )
    };
    if keyed {
        let _ = index::insert(&mut s.conn_index, hash, idx);
    }
    if listens {
        listener_add(s, idx);
    }
    if local_port != 0 {
        port_ref_inc(s, local_port);
    }
    if half_open {
        (*s.tcp_conns.as_mut_ptr().add(idx)).half_open_counted = true;
        half_open_enter(s, remote_ip);
    }
}

/// A half-open connection completed or was abandoned: stop counting it.
unsafe fn conn_leave_half_open(s: &mut IpState, idx: usize) {
    let c = &mut *s.tcp_conns.as_mut_ptr().add(idx);
    if c.half_open_counted {
        c.half_open_counted = false;
        let ip = c.remote_ip;
        half_open_leave(s, ip);
    }
}

/// Release a slot: unindex whatever it was, then reset it. Removal is by
/// what the slot holds, not by its state — a slot latched `Closed` for a
/// pending notification is still indexed until here.
unsafe fn conn_reset(s: &mut IpState, idx: usize) {
    let (is_datagram, remote_ip, local_port, hash, half_open) = {
        let c = &*s.tcp_conns.as_ptr().add(idx);
        (
            c.is_datagram,
            c.remote_ip,
            c.local_port,
            conn_key_of(c).hash(s.index_seed),
            c.half_open_counted,
        )
    };
    if !is_datagram && remote_ip != 0 {
        // The shift needs each moved entry's own bucket, and the entries
        // are slots — so the table is read through a raw pointer taken
        // before the index is borrowed. The two do not overlap: the index
        // holds slot numbers, never connections.
        let conns = s.tcp_conns.as_ptr();
        let seed = s.index_seed;
        let _ = index::remove(&mut s.conn_index, hash, idx, |slot| {
            conn_key_of(&*conns.add(slot)).hash(seed)
        });
    }
    if !is_datagram && local_port != 0 {
        listener_remove(s, idx);
    }
    if local_port != 0 {
        port_ref_dec(s, local_port);
    }
    if half_open {
        half_open_leave(s, remote_ip);
    }
    continuity::on_conn_released(s, idx);
    *s.tcp_conns.as_mut_ptr().add(idx) = tcp::TcpConn::new();
    free_push(s, idx);
}

/// Slots examined by one rebuild slice of the free stack. A step of this
/// module must not grow with the table (see `SWEEP_SLICE_MAX`): when the
/// stack is empty — the table is full, or a slot was released by a path
/// that did not push it — one slice per step rebuilds it, and an
/// allocation that finds nothing in the slice is refused for this step.
const ALLOC_SCAN_SLICE: usize = 256;

/// The first slot TCP takes. The first `MAX_DG_ENDPOINTS` slots are the
/// only ones a datagram endpoint can take (its `ep_id` is a u8), so TCP
/// prefers the slots beyond that window and falls back into it only when
/// the rest is full — otherwise a SYN flood, or simply a busy server, would
/// leave no endpoint bindable. On a profile whose table is no larger than
/// the window there is no "beyond".
const fn tcp_slot_lo() -> usize {
    if MAX_DG_ENDPOINTS < tcp::MAX_TCP_CONNS {
        MAX_DG_ENDPOINTS
    } else {
        0
    }
}

/// Return a released TCP slot to the free stack.
unsafe fn free_push(s: &mut IpState, idx: usize) {
    if idx < tcp_slot_lo() || idx >= tcp::MAX_TCP_CONNS {
        return;
    }
    let top = s.free_top as usize;
    if top < tcp::MAX_TCP_CONNS {
        *s.free_slots.as_mut_ptr().add(top) = idx as u16;
        s.free_top = (top + 1) as u32;
    }
}

/// Pop free slots until one is actually free. A stale entry — a slot the
/// stack names that something else has since taken — is skipped.
unsafe fn free_pop(s: &mut IpState) -> Option<usize> {
    while s.free_top > 0 {
        s.free_top -= 1;
        let idx = *s.free_slots.as_ptr().add(s.free_top as usize) as usize;
        if idx < tcp::MAX_TCP_CONNS && slot_is_free(&*s.tcp_conns.as_ptr().add(idx)) {
            return Some(idx);
        }
    }
    None
}

/// A free connection slot for TCP, in constant time: the free stack is
/// popped, and only when it is empty does one bounded slice of the table
/// get scanned — once per step — to rebuild it. A full table refuses
/// every arrival at the cost of that one slice, never a walk of the table
/// per SYN; a walk per SYN at the ceiling is a multi-millisecond step the
/// guard would end the module for.
unsafe fn alloc_free_slot(s: &mut IpState) -> Option<usize> {
    if let Some(i) = free_pop(s) {
        return Some(i);
    }
    if s.alloc_scan_step == s.step_count {
        return None;
    }
    s.alloc_scan_step = s.step_count;
    let lo = tcp_slot_lo();
    let span = tcp::MAX_TCP_CONNS - lo;
    if span > 0 {
        let start = s.alloc_scan_cursor as usize % span;
        let mut n = 0;
        while n < ALLOC_SCAN_SLICE.min(span) {
            let i = lo + (start + n) % span;
            if slot_is_free(&*s.tcp_conns.as_ptr().add(i)) {
                free_push(s, i);
            }
            n += 1;
        }
        s.alloc_scan_cursor = ((start + n) % span) as u32;
        s.alloc_scanned = s.alloc_scanned.wrapping_add(n as u32);
        if let Some(i) = free_pop(s) {
            return Some(i);
        }
    }
    // The datagram window, last.
    let mut i = 0;
    while i < lo {
        if slot_is_free(&*s.tcp_conns.as_ptr().add(i)) {
            s.alloc_scanned = s.alloc_scanned.wrapping_add(i as u32 + 1);
            return Some(i);
        }
        i += 1;
    }
    s.alloc_scanned = s.alloc_scanned.wrapping_add(lo as u32);
    None
}

/// The connection an inbound segment belongs to, by index. A connection
/// on a concrete local slot matches only that slot; one on the wildcard
/// slot matches any, so both keys are tried.
unsafe fn find_conn_indexed(
    s: &IpState,
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    local_slot: u16,
) -> Option<usize> {
    let conns = s.tcp_conns.as_ptr();
    let matches = |slot: usize, want_slot: u16| {
        let c = &*conns.add(slot);
        c.is_active()
            && c.remote_ip == remote_ip
            && c.remote_port == remote_port
            && c.local_port == local_port
            && c.local_slot == want_slot
    };
    let seed = s.index_seed;
    let key = index::ConnKey {
        remote_ip,
        remote_port,
        local_port,
        local_slot,
    };
    if let Some(i) = index::lookup(&s.conn_index, key.hash(seed), |slot| {
        matches(slot, local_slot)
    }) {
        return Some(i);
    }
    if local_slot == LOCAL_SLOT_ANY {
        return None;
    }
    let any = index::ConnKey {
        local_slot: LOCAL_SLOT_ANY,
        ..key
    };
    index::lookup(&s.conn_index, any.hash(seed), |slot| {
        matches(slot, LOCAL_SLOT_ANY)
    })
}

/// The listener for a SYN, by list. Same admission rule as before: a
/// concrete-slot listener serves its slot; a wildcard listener serves slot 0
/// and unowned secondaries, never an owned one.
unsafe fn find_listener_indexed(
    s: &IpState,
    local_port: u16,
    local_slot: u16,
    dst_owned: bool,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_LISTENERS {
        let e = s.listeners[i];
        if e != 0 {
            let idx = (e - 1) as usize;
            let c = &*s.tcp_conns.as_ptr().add(idx);
            if c.state == tcp::TcpState::Listen
                && !c.is_datagram
                && c.local_port == local_port
                && (c.local_slot == local_slot || (c.local_slot == LOCAL_SLOT_ANY && !dst_owned))
            {
                return Some(idx);
            }
        }
        i += 1;
    }
    None
}

/// Inbound RX / command processing pauses when the outbound control
/// queue has fewer than this many free slots. Each accepted segment
/// or command typically synthesises one outbound control event, so
/// pulling more in while the queue is near-full would just risk
/// overflow. The pause propagates backpressure to the upstream
/// producer.
const NET_OUT_QUEUE_HEADROOM: usize = 4;

// ============================================================================
// Module State
// ============================================================================

/// Ingress refusals and security-relevant admission decisions. Every field is
/// a free-running lifetime counter: an operator reads deltas, and a
/// non-advancing counter is itself the signal that a defence never fired.
///
/// These sit apart from `TlmCounters` (bytes / idle / backpressure) because
/// they answer a different question — not "how much moved" but "what was
/// refused, and why".
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpDrops {
    /// Segments refused by the TCP pseudo-header checksum.
    pub cksum_tcp: u32,
    /// Datagrams refused by the UDP pseudo-header checksum. A zero checksum
    /// is "not supplied" for IPv4 UDP and is not counted here.
    pub cksum_udp: u32,
    /// ICMP messages refused by the ICMP checksum.
    pub cksum_icmp: u32,
    /// IPv4 fragments refused before L4 dispatch (no reassembler — see the
    /// module doc comment).
    pub frag: u32,
    /// Datagrams whose UDP length disagreed with the IPv4 payload length.
    pub udp_len: u32,
    /// New or changed ARP mappings refused because they arrived on an
    /// ordinary IPv4 packet rather than on ARP.
    pub arp_from_ipv4: u32,
    /// ARP frames that did not correlate with the outstanding resolution
    /// (wrong sender, wrong target address, or not addressed to us).
    pub arp_uncorrelated: u32,
    /// MAC changes refused because the entry is pinned. Distinguishes a
    /// security refusal from an ordinary cache miss.
    pub arp_pin_reject: u32,
    /// Permanent pins that entered revalidation (a fresh ARP was issued for
    /// an entry that ordinary aging would never expire).
    pub arp_pin_revalidate: u32,
    /// DHCP replies refused for a correlation failure: wrong `chaddr`, wrong
    /// server, or an address that does not match the selected offer.
    pub dhcp_uncorrelated: u32,
    /// Datagrams refused because the payload cannot fit one transmit frame.
    pub udp_oversize: u32,
    /// Sends refused because the destination is off-subnet with no gateway.
    pub route_unreachable: u32,
    /// Passive or active opens refused because no ISN secret could be
    /// established (the CSPRNG was unavailable).
    pub entropy_unavailable: u32,
    /// Ephemeral-port allocations that found no free port.
    pub port_exhausted: u32,
    /// Segments refused by the receive-window acceptability test before the
    /// state machine saw them.
    pub tcp_unacceptable: u32,
    /// Segments whose `SEG.ACK` was outside `[SND.UNA, SND.NXT]`. Counted
    /// whether or not the segment was otherwise admissible: an invalid ACK
    /// never installs a window or advances the send sequence.
    pub tcp_ack_invalid: u32,
    /// In-window RSTs and synchronised-state SYNs answered with a challenge
    /// ACK instead of being acted on.
    pub tcp_challenge_sent: u32,
    /// Challenge ACKs the rate limiter suppressed. A rising count is the
    /// signal that a flood is being absorbed rather than reflected.
    pub tcp_challenge_suppressed: u32,
    /// RSTs dropped for landing outside the receive window.
    pub tcp_rst_out_of_window: u32,
    /// Window advertisements ignored for arriving on a segment no newer than
    /// the one that last set `snd_wnd` (`SND.WL1`/`SND.WL2`).
    pub tcp_stale_window: u32,
    /// Datagram binds refused because the local identity is already held by
    /// another endpoint (`EADDRINUSE`).
    pub dg_bind_conflict: u32,
    /// Datagram commands refused because the named endpoint slot is not a
    /// live endpoint of the requesting consumer.
    pub dg_ep_unowned: u32,
    /// Datagram commands refused because the owner tag presented does not
    /// match the tag recorded when the endpoint was bound (`EPERM`). This is
    /// the cross-consumer axis: a live slot reached by a consumer that does
    /// not own it.
    pub dg_ep_perm: u32,
}

impl IpDrops {
    pub const fn new() -> Self {
        Self {
            cksum_tcp: 0,
            cksum_udp: 0,
            cksum_icmp: 0,
            frag: 0,
            udp_len: 0,
            arp_from_ipv4: 0,
            arp_uncorrelated: 0,
            arp_pin_reject: 0,
            arp_pin_revalidate: 0,
            dhcp_uncorrelated: 0,
            udp_oversize: 0,
            route_unreachable: 0,
            entropy_unavailable: 0,
            port_exhausted: 0,
            tcp_unacceptable: 0,
            tcp_ack_invalid: 0,
            tcp_challenge_sent: 0,
            tcp_challenge_suppressed: 0,
            tcp_rst_out_of_window: 0,
            tcp_stale_window: 0,
            dg_bind_conflict: 0,
            dg_ep_unowned: 0,
            dg_ep_perm: 0,
        }
    }
}

/// One packet held at the decision seam: the whole frame, where the IPv4
/// header starts in it, which local-address slot it was demuxed to, and
/// when it is released if no disposition comes.
#[repr(C)]
pub struct HeldPacket {
    in_use: u8,
    _pad0: u8,
    /// Local-address slot the packet was demuxed to at intake.
    local_slot: u16,
    /// Generation stamped into the `pkt_id`; a disposition naming another
    /// generation is stale.
    gen: u32,
    len: u16,
    l3_off: u16,
    deadline_ms: u32,
    /// A TUNNEL/DSR disposition whose forward write did not fit yet:
    /// `[disposition][args:6]`, `disposition = 0xFF` when none pending.
    pending_fwd: [u8; 7],
    _pad: u8,
    frame: [u8; MAX_FRAME_SIZE],
}

/// Decision-seam counters. Lifetime counters like `IpDrops`; a director
/// reads deltas, and `hold_refused` advancing is the signal that the hold
/// bound is the gate.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PktSeamStats {
    /// Decision records handed to the director.
    pub decided: u32,
    /// Packets refused at intake because every hold slot was taken, or the
    /// decision port had no room for the record.
    pub hold_refused: u32,
    /// Held packets released at their deadline with no disposition.
    pub hold_expired: u32,
    /// Dispositions naming a released or reused `pkt_id`.
    pub stale_disposition: u32,
    pub local: u32,
    pub dropped: u32,
    pub rejected: u32,
    pub forwarded: u32,
    /// TUNNEL/DSR dispositions with no forward port wired; released.
    pub fwd_unwired: u32,
    pub cloned: u32,
    /// Clone requests refused for want of a slot.
    pub clone_refused: u32,
}

#[repr(C)]
struct IpState {
    // Core module fields
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,

    // Config
    use_dhcp: u8,
    /// Opt-in DHCP compatibility profile. Admits two shapes a strict DHCP
    /// client refuses: a BOOTP reply with no message-type option treated as
    /// an implicit ACK, and an ACK arriving in DISCOVERING with no preceding
    /// OFFER to bind it to. Both accept an address assignment the client
    /// cannot correlate to a selection it made.
    dhcp_compat: u8,
    /// Head-sampling rate in per-mille (0–1000); the fraction of ingress roots
    /// that are sampled. Default 1000 (100%). The decision is made once per
    /// connection at accept and stored in `TcpConn::sampled_flags`.
    sample_permille: u16,

    // Network identity
    mac_addr: [u8; 6],
    mac_valid: bool,
    _mac_pad: u8,
    /// Primary (slot-0) address, retained as a hot-path decoded cache of
    /// `local_addrs[0]`'s IPv4 so the RX filter, checksums and source
    /// stamping keep their single-`u32` compares (no per-frame byte-swap).
    /// DHCP-managed when `use_dhcp=1`. `local_addrs[0]` mirrors it.
    local_ip: u32,
    netmask: u32,
    gateway: u32,
    dns_server: u32,
    /// Multi-homing address table. Slot 0 is the primary (mirrors `local_ip`,
    /// `flags.PRIMARY`, `owner_tag=0`); slots 1.. are secondaries added via
    /// `addr_ctl`. One gateway / netmask / segment for all addresses in v1
    /// (§5) — those stay scalar fields above.
    local_addrs: [LocalAddr; MAX_LOCAL_ADDRS],
    ip_configured: bool,
    signaled_ready: bool,
    _ip_pad: [u8; 2],

    // ARP table
    arp_table: [arp::ArpEntry; arp::ARP_TABLE_SIZE],
    arp_pending_ip: u32,
    arp_pending_state: u8,
    arp_pending_timer: u8,
    _arp_pad: [u8; 2],

    // DHCP client
    dhcp: dhcp::DhcpClient,

    // TCP connections
    tcp_conns: [tcp::TcpConn; tcp::MAX_TCP_CONNS],

    // Lookup structures over the tables (`index.rs`); maintained at
    // `conn_index_insert` / `conn_reset` and the address-control paths.
    conn_index: [u32; CONN_INDEX_SIZE],
    addr_index: [u32; ADDR_INDEX_SIZE],
    /// Listening (non-datagram) slots, `slot + 1`; 0 = empty.
    listeners: [u32; MAX_LISTENERS],
    port_ref: [u32; PORT_REF_ENTRIES],
    /// Seeds both index hashes, so which tuples share a cluster is this
    /// instance's secret rather than a published function. Drawn once at
    /// construction and never changed: an index is built under the seed it
    /// is later searched with, so a seed that moved would strand every
    /// entry inserted before it. Zero when the entropy source could not
    /// answer — no worse than an unseeded hash, and still consistent.
    index_seed: u32,
    ho_src: [index::SourceCount; HO_SRC_ENTRIES],
    /// Half-open connections whose source the table had no room to track.
    ho_src_untracked: u32,
    /// Free TCP slots, as a stack: a release pushes, an allocation pops.
    /// Holds only slots at or beyond the datagram window.
    free_slots: [u16; tcp::MAX_TCP_CONNS],
    free_top: u32,
    /// Where the next rebuild slice starts when the stack is empty.
    alloc_scan_cursor: u32,
    /// The step in which the last rebuild slice ran: one slice per step.
    alloc_scan_step: u32,
    /// Slots examined by rebuild and window scans, for the tests.
    alloc_scanned: u32,
    /// Timer sweep position within the current window (0 = at the start).
    sweep_cursor: u32,
    /// When the current sweep window began.
    sweep_window_ms: u32,
    /// Challenge-ACK refill epoch: a connection whose epoch lags is
    /// refilled when the sweep reaches it.
    chal_epoch: u8,
    _idx_pad: [u8; 3],

    // IP identification counter
    ip_id: u16,
    _id_pad: [u8; 2],

    // Net protocol channels (consumer ↔ IP)
    net_in_chan: i32,
    net_out_chan: i32,
    /// Address-control input port (in[2]); -1 when unwired. Single writer =
    /// the platform workload backend. Graphs without it wired get today's
    /// single-address behaviour, byte-identical.
    addr_ctl_chan: i32,
    /// Emission events back to that writer (out[5]); -1 when unwired.
    addr_evt_chan: i32,
    /// Install generation counter for local addresses.
    addr_generation: u32,
    /// Frames refused at the emission gate because their source address is
    /// fenced. A non-zero delta after a fence is the fence doing its job.
    tx_fenced: u32,
    /// A fence whose `MSG_ADDR_FENCED` waits for the driver to report the
    /// wire quiet: the slot, its generation, the address, whether the
    /// staged frame was discarded, and the step-clock deadline after which
    /// the event goes out at the ring hand-off instead. `0xFFFF` = none.
    fence_wait_slot: u16,
    fence_wait_discarded: u8,
    _fw_pad: u8,
    fence_wait_gen: u32,
    fence_wait_deadline_ms: u32,
    fence_wait_addr: [u8; 16],
    /// Fences answered at the ring hand-off because the driver could not
    /// confirm the wire in time.
    fence_ring_handoff: u32,

    // Pre-transport decision seam (in[3], out[3], out[4]); -1 when unwired.
    pkt_in_chan: i32,
    pkt_out_chan: i32,
    pkt_fwd_chan: i32,
    /// `packet_decision` parameter: off, or pre_transport.
    pkt_decision: u8,
    _pkt_pad: u8,
    /// How long a packet is held awaiting disposition before release.
    pkt_hold_ms: u16,
    /// Generation stamped into the next hold; never 0.
    pkt_gen: u32,
    /// Hold slots in use — the seam's live gauge.
    pkt_held: u16,
    pkt_stats: PktSeamStats,
    pkt_hold: [HeldPacket; MAX_PACKET_HOLD],

    // Transport continuity (in[4] / out[6]); ports -1 when unwired.
    cont: continuity::Continuity,

    // Net protocol scratch buffer: NET_FRAME_HDR(3) + conn_id(1) + TCP payload.
    net_scratch: [u8; 1600],

    // Frame buffers
    rx_frame: [u8; MAX_FRAME_SIZE],
    /// Length of the frame in `rx_frame` and where its L3 header starts,
    /// recorded per frame so the decision seam can hold a whole frame.
    rx_frame_len: u16,
    rx_l3_off: u16,
    tx_frame: [u8; MAX_FRAME_SIZE],
    /// Length of a TX frame staged in `pending_tx_buf` awaiting channel space
    /// (0 = no pending). The frame is held in its own buffer so subsequent
    /// `send_frame` calls can reuse `tx_frame` without clobbering it.
    pending_tx_len: u16,
    _ptx_pad: [u8; 2],
    pending_tx_buf: [u8; MAX_FRAME_SIZE + 2],

    /// LOCAL-DELIVERY FASTPATH (loopback). A CMD_CONNECT whose
    /// destination is this host's own address (or 127.0.0.1) never
    /// reaches TCP: it binds a PAIR of conn slots directly — the
    /// connector's and an accepted-side one for the local listener —
    /// and CMD_SEND on either becomes MSG_DATA tagged with the peer's
    /// conn id. No segments, no ARP (a host cannot ARP-resolve
    /// itself through a switch), no handshake; RFC-standard host
    /// behavior (packets to self are delivered locally), which is
    /// what lets one graph compose a client module against its own
    /// listener (e.g. pg_client ↔ pg_edge_anchor on one board).
    /// `-1` = not a loopback conn; otherwise the peer's slot index.
    /// Both slots sit in the ordinary conn table as `Established`
    /// with empty send queues, which the timer scan ignores.
    loopback_peer: [i32; tcp::MAX_TCP_CONNS],

    /// Connections whose SYN or SYN-ACK is waiting on an ARP reply.
    arp_wait: [u32; ARP_WAIT_MAX],
    arp_wait_len: u8,
    _aw_pad: [u8; 3],
    arp_wait_overflow: u32,

    /// Stash for a CMD_SEND tail that couldn't be drained in one tick
    /// (peer window closed mid-frame, or NIC out_chan rejected a
    /// segment). `service_net_channels` resumes from `pending_cmd_off`
    /// on the next tick before touching `net_in_chan`; while the
    /// stash is occupied we never read new frames, so backpressure
    /// propagates back to the consumer through its own
    /// `channel_write` to `net_in_chan`.
    pending_cmd_valid: u8,
    pending_cmd_conn: u16,
    pending_cmd_off: u16,
    pending_cmd_len: u16,
    _pcmd_pad: [u8; 2],
    pending_cmd_buf: [u8; PENDING_CMD_BUF_SIZE],

    /// Deferred CMD_CLOSE slot. Set when CMD_CLOSE arrives while a
    /// `pending_cmd_*` stash is still draining (RFC 793 §3.5 — CLOSE
    /// transmits all queued SENDs first), or when the FIN frame
    /// itself was rejected by the NIC. Cleared once `process_cmd_close`
    /// confirms the FIN is queued.
    pending_close_valid: u8,
    pending_close_conn: u16,
    _pcls_pad: [u8; 2],

    /// Outbound control-frame queue (MSG_BOUND / MSG_ACCEPTED /
    /// MSG_CLOSED / MSG_CONNECTED / MSG_ERROR / MSG_RETRANSMIT).
    /// `net_out_chan` writes are atomic-FIFO and reject when full;
    /// queueing here lets a momentarily-full consumer channel apply
    /// backpressure without losing the control event. Drained at the
    /// top of each `module_step`. MSG_DATA bypasses this and uses its
    /// own per-conn path because it's variable-length and large.
    pending_net_out_frames: [[u8; NET_OUT_FRAME_MAX]; NET_OUT_QUEUE_SLOTS],
    pending_net_out_lens: [u8; NET_OUT_QUEUE_SLOTS],
    pending_net_out_head: u8,
    pending_net_out_tail: u8,
    pending_net_out_count: u8,
    _pno_pad: u8,

    // Step counter for timers
    step_count: u32,

    /// Wallclock millis at which `step_tcp_timers` last advanced.
    /// `retransmit_timer` / `timewait_timer` thresholds are defined
    /// in 50 ms ticks; gating on wallclock keeps them meaningful
    /// regardless of the host scheduler's `tick_us`.
    /// `tcp_idle_s` in 50 ms timer ticks; 0 disables the idle close.
    tcp_idle_ticks: u16,

    // Diagnostic counters
    rx_frame_count: u32,
    tx_frame_count: u32,

    // Ephemeral port counter
    next_ephemeral_port: u16,
    _eph_pad: [u8; 2],

    /// One-shot guard for the "UDP broadcast rejected" log in
    /// `send_udp_data`. Prevents a tick-rate flood from amplifying
    /// itself through the log path.
    bcast_warned: bool,
    _bcast_pad: [u8; 3],

    /// Hot-path counters emitted as `[ip] tlm dt=… rx=… tx=… idle=… bp=…`
    /// every `IP_TLM_PERIOD` steps. `rx`/`tx` are ethernet-frame bytes
    /// (length prefix excluded for rx, included for tx since that's what
    /// hits the channel). `idle` counts steps where no frame moved either
    /// way; `bp` counts steps where `send_frame` couldn't flush because
    /// `out_chan` was full.
    tlm: TlmCounters,
    /// One-line scratch for the tlm emit, sized at `TLM_LINE_BUF_SIZE`.
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],

    /// Lifetime duplicate SYNs received for a slot already in
    /// `SynReceived`. Non-zero means the peer retransmitted SYN —
    /// our SYN-ACK didn't reach the peer (rig→peer loss, not
    /// peer→rig). Emitted on the `[ip] hb` line.
    tcp_dup_syn_rx: u32,

    /// Ingress refusals — see [`IpDrops`].
    drops: IpDrops,

    /// Challenge ACKs still permitted across every connection in the current
    /// refill window (`tcp::CHALLENGE_ACK_GLOBAL_BUDGET`). Paired with the
    /// per-connection bucket in `TcpConn::chal_budget`: the global cap bounds
    /// what the host can be made to emit in total, the per-peer cap stops one
    /// connection consuming all of it.
    chal_ack_budget: u8,
    /// 50 ms timer ticks elapsed in the current challenge-ACK refill window.
    chal_refill_ticks: u8,
    _chal_pad: [u8; 2],

    /// TCP connections currently in `SynReceived` (half-open). Recounted from
    /// the table on each passive open rather than tracked as a delta, so a
    /// teardown path that forgets to decrement cannot strand the gauge.
    tcp_half_open: u32,
    /// High-water mark of `tcp_half_open` since boot.
    tcp_half_open_max: u32,
    /// High-water mark of half-open connections attributable to one source
    /// address. A flood from a single peer shows here, which
    /// `tcp_half_open_max` alone cannot distinguish from legitimate load.
    tcp_half_open_src_max: u32,
    /// Passive opens refused for want of a free slot. Read together with
    /// `tcp_half_open_max` this separates a genuine capacity ceiling from
    /// half-open exhaustion.
    tcp_half_open_refused: u32,
    /// Established connections this module closed for `tcp_idle_s` silence.
    tcp_idle_closed: u32,
    /// CloseWait connections this module finished closing because the
    /// consumer never sent CMD_CLOSE within the grace interval.
    tcp_closewait_expired: u32,
    /// SYN-ACKs answered from cookie mode, spending no connection slot.
    /// `> 0` is the operator's signal that the deployment crossed the
    /// watermark at all — the distinction between "sized correctly" and
    /// "running on cookies" that `tcp_half_open_max` alone cannot make.
    tcp_syn_cookie_sent: u32,
    /// ACKs whose cookie validated and became a connection.
    tcp_syn_cookie_ok: u32,
    /// ACKs that reached cookie validation and failed it. Rising with a flat
    /// `ok` is an off-path injection attempt; rising in step with `sent` is a
    /// clock or secret problem.
    tcp_syn_cookie_bad: u32,
    /// SYNs above the watermark that carried a TCP option area. A cookie
    /// cannot reconstruct a negotiated option from the returning ACK, so
    /// cookie mode refuses to engage and the SYN is dropped.
    tcp_syn_option_refused: u32,

    /// Per-boot secret for the RFC 6528-shaped ISN construction. Drawn once
    /// from the kernel CSPRNG; a connection's ISS is a keyed mix of this
    /// secret with the four-tuple plus a monotonic term, so an off-path peer
    /// cannot derive one connection's sequence space from another's.
    isn_secret: [u8; 16],
    /// Set once `isn_secret` holds CSPRNG output. Until then no TCP
    /// connection is opened in either direction.
    isn_secret_valid: bool,
    /// One-shot guard for the "entropy unavailable" log so a retry loop
    /// cannot amplify itself through the log path.
    entropy_warned: bool,
    /// Gateway ARP resolution outstanding for a permanent pin. The pin is
    /// installed only when a correlated reply arrives, so a cache entry
    /// present before the lease was taken can never be promoted to permanent.
    gw_pin_pending: bool,
    _gwpin_pad: u8,
    /// Address the outstanding gateway pin is for (0 = none).
    gw_pin_ip: u32,
    /// Step count at which the current gateway pin resolution was armed.
    gw_pin_armed_step: u32,

    // ── Pipeline-advancement instrumentation ──────────────────────────
    // See the matching fields in `tls`: byte counters say how much a
    // module did, not whether it had more available and stopped anyway.
    /// Ethernet frames drained from the NIC channel this window.
    adv_rx_frames: u32,
    /// Steps that ended with the RX channel still readable — `ip` stopped
    /// with frames waiting. Sustained non-zero means the 32-frame drain
    /// budget is the binding constraint.
    pend_rx_steps: u32,
    /// Steps that returned early from `service_net_channels` because
    /// outbound headroom was low (`NET_OUT_QUEUE_SLOTS` pressure) — the
    /// module refusing new commands rather than being idle.
    pend_txq_steps: u32,
    /// MSG_DATA frames emitted to `net_out` (wire -> tls direction).
    out_items: u32,
    /// CMD_SEND commands fully consumed from `net_in` (tls -> wire).
    tx_cmd_items: u32,
    /// Steps that left `service_net_channels` early with a PARTIALLY SENT
    /// command stashed in `pending_cmd_*`.
    ///
    /// This is the response-path serialisation counter. While one
    /// connection's response is mid-flight the function `return`s, so NO
    /// other connection's commands are serviced that step — one connection
    /// at a time regardless of how many have responses ready. If this is a
    /// large fraction of steps it is the ceiling, and it would be invisible
    /// to every other counter: no channel backs up (tls sees an empty
    /// queue, so `pend=0`), no drop fires, and CPU stays low, because the
    /// module is deliberately declining work rather than failing to do it.
    pend_cmd_steps: u32,
}

/// Cadence for the `[ip] tlm` line — every 5000 module steps.
/// At `tick_us=1000` that's 5 s; at `tick_us=100` it's 500 ms.
const IP_TLM_PERIOD: u32 = 5000;

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::*;

    define_params! {
        IpState;

        1, use_dhcp, u8, 1, enum { no=0, yes=1 }
            => |s, d, len| { s.use_dhcp = p_u8(d, len, 0, 1); };
        2, expected_dhcp_server, u32, 0
            => |s, d, len| { s.dhcp.expected_server = p_u32(d, len, 0, 0); };
        3, trace_sample_permille, u16, 1000
            => |s, d, len| { s.sample_permille = p_u16(d, len, 0, 1000); };
        4, dhcp_compat, u8, 0, enum { strict=0, bootp_and_direct_ack=1 }
            => |s, d, len| { s.dhcp_compat = p_u8(d, len, 0, 1); };
        // Seconds an Established connection may carry no payload in either
        // direction before this module closes it (FIN, then ETIMEDOUT to the
        // consumer). 0 disables the backstop entirely.
        // A transport-level backstop under the consumer's own lifetime
        // policy: the consumer knows what "idle" means for its protocol, but
        // a consumer without one, or a slot no consumer is tracking, must
        // not hold TCP state for good.
        5, tcp_idle_s, u16, 0
            => |s, d, len| { s.tcp_idle_ticks = p_u16(d, len, 0, 0).saturating_mul(TCP_TIMER_HZ); };
        // Pre-transport decision seam. `pre_transport` hands every validated
        // inbound IPv4 packet to a director on `packet_out` and holds it
        // until a disposition arrives on `packet_in`; `off` (the default)
        // means the code path does not exist at runtime.
        6, packet_decision, u8, 0, enum { off=0, pre_transport=1 }
            => |s, d, len| { s.pkt_decision = p_u8(d, len, 0, 0); };
        // Milliseconds a packet is held awaiting disposition before it is
        // released and reported (`MSG_PKT_EXPIRED`). Clamped to >= 1: a
        // packet released before the director can answer is a seam that
        // does nothing.
        7, packet_hold_ms, u16, 50
            => |s, d, len| {
                let v = p_u16(d, len, 0, 50);
                s.pkt_hold_ms = if v == 0 { 1 } else { v };
            };
    }
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn log_info(s: &IpState, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 3, msg.as_ptr(), msg.len());
}

#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn log_error(s: &IpState, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 1, msg.as_ptr(), msg.len());
}

// Formatting helpers (fmt_u32_raw, fmt_ip_raw) are in pic_runtime.rs

// ── Local-address table helpers ─────────────────

/// CIDR prefix length for a contiguous IPv4 netmask (host order). `0` for a
/// zero mask. Used to seed slot 0's `prefix_len` from `s.netmask`.
#[inline]
fn prefix_len_from_netmask(netmask: u32) -> u8 {
    netmask.count_ones() as u8
}

/// Mirror the primary identity (`local_ip` / `netmask`) into slot 0 of the
/// address table. Called wherever `local_ip` changes (DHCP bind,
/// `force_configured`). Keeps the table the single logical source of truth
/// while `local_ip` remains the hot-path decoded cache.
#[inline]
unsafe fn sync_primary_slot(s: &mut IpState) {
    let a = &mut s.local_addrs[0];
    a.set_ipv4(s.local_ip);
    a.prefix_len = prefix_len_from_netmask(s.netmask);
    a.owner_tag = 0;
    a.flags = ADDR_FLAG_PRIMARY | ADDR_FLAG_ARMED;
}

/// Outbound IPv4 source address for a conn's bound `slot`. Slot 0 (and the
/// `ANY` wildcard used by unbound/host traffic) sources from `local_ip`; a
/// concrete secondary sources from its table entry, falling back to the
/// primary if the slot has since been removed.
#[inline]
fn local_ip_for_slot(s: &IpState, slot: u16) -> u32 {
    if slot == 0 || slot == LOCAL_SLOT_ANY {
        return s.local_ip;
    }
    let i = slot as usize;
    if i < MAX_LOCAL_ADDRS && s.local_addrs[i].is_active() {
        s.local_addrs[i].ipv4()
    } else {
        s.local_ip
    }
}

/// Resolve an inbound destination IP to a local-address slot. `Some(0)` =
/// primary; `Some(i)` = secondary `i`; `None` = not one of ours. The
/// primary is one compare; secondaries go through the address index, so
/// a frame pays for the cluster it lands in rather than for the table.
#[inline]
fn local_slot_for_dst(s: &IpState, dst: u32) -> Option<u16> {
    if s.local_ip != 0 && dst == s.local_ip {
        return Some(0);
    }
    if dst == 0 {
        return None;
    }
    // SAFETY: the index is a power-of-two length by construction.
    unsafe {
        index::lookup(&s.addr_index, index::mix32(dst ^ s.index_seed), |i| {
            i != 0 && i < MAX_LOCAL_ADDRS && {
                let a = &s.local_addrs[i];
                a.is_active() && a.ipv4() == dst
            }
        })
        .map(|i| i as u16)
    }
}

/// True if `ip` is any configured local address (primary or secondary).
#[inline]
fn is_local_addr(s: &IpState, ip: u32) -> bool {
    local_slot_for_dst(s, ip).is_some()
}

/// Owner tag of a local-address slot. Slot 0 (host), the wildcard sentinel,
/// out-of-range, and inactive slots all report 0 (host/system owner). Used by
/// the bind-admission and demux gates.
#[inline]
fn owner_tag_for_slot(s: &IpState, slot: u16) -> u16 {
    let i = slot as usize;
    if slot == LOCAL_SLOT_ANY || i >= MAX_LOCAL_ADDRS {
        return 0;
    }
    let a = &s.local_addrs[i];
    if a.is_active() {
        a.owner_tag
    } else {
        0
    }
}

/// True if `slot` names an OWNED secondary (`owner_tag != 0`). Slot 0 and
/// unowned secondaries return false. With no owned secondary configured
/// this is always false, so every demux/admission gate keyed on it
/// collapses to a plain unowned match.
#[inline]
fn slot_is_owned(s: &IpState, slot: u16) -> bool {
    owner_tag_for_slot(s, slot) != 0
}

/// Resolve a nonzero bind `owner_tag` to the active local-address slot that
/// owner owns. `None` = the owner has no configured address on this host, so a
/// bind stamped with it is refused (the metal analogue of the Linux
/// lease-owner gate). Owner 0 (host) is never
/// resolved here — it binds the wildcard slot.
#[inline]
fn slot_for_owner(s: &IpState, owner_tag: u16) -> Option<u16> {
    if owner_tag == 0 {
        return None;
    }
    let mut i = 0;
    while i < MAX_LOCAL_ADDRS {
        let a = &s.local_addrs[i];
        if a.is_active() && a.owner_tag == owner_tag {
            return Some(i as u16);
        }
        i += 1;
    }
    None
}

// ── Emission control ────────────────────────────────────────────────
//
// An installed address is armed (it emits and answers ARP) or fenced (it
// does neither). The gate is `send_frame`, the one hand-off to the driver
// ring, so a fence holds for every path that builds a frame; ARP answering
// and conflict defence check the same flag. The primary is always armed.

/// Whether `ip` is one of ours AND armed.
#[inline]
fn is_armed_addr(s: &IpState, ip: u32) -> bool {
    match local_slot_for_dst(s, ip) {
        Some(slot) => s.local_addrs[slot as usize].flags & ADDR_FLAG_ARMED != 0,
        None => false,
    }
}

/// Whether a frame may be handed to the driver: its source address is not
/// one of ours, or is one of ours and armed. Source is read from the IPv4
/// header or the ARP sender field; anything else (a DHCP discover from
/// 0.0.0.0, a frame of another type) is not subject to emission control.
///
/// # Safety
/// `frame` must point to `len` readable bytes.
unsafe fn emission_allowed(s: &IpState, frame: *const u8, len: usize) -> bool {
    if len < eth::ETH_HEADER_LEN + 2 {
        return true;
    }
    let ethertype = ((*frame.add(12) as u16) << 8) | *frame.add(13) as u16;
    let src = match ethertype {
        eth::ETHERTYPE_IPV4 if len >= eth::ETH_HEADER_LEN + 20 => {
            let p = frame.add(eth::ETH_HEADER_LEN + 12);
            u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
        }
        eth::ETHERTYPE_ARP if len >= eth::ETH_HEADER_LEN + 28 => {
            let p = frame.add(eth::ETH_HEADER_LEN + 14);
            u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
        }
        _ => return true,
    };
    if src == 0 {
        return true;
    }
    match local_slot_for_dst(s, src) {
        Some(slot) => s.local_addrs[slot as usize].flags & ADDR_FLAG_ARMED != 0,
        None => true,
    }
}

/// Write one emission event to the address-control writer, if it listens.
unsafe fn addr_evt(s: &mut IpState, msg: u8, payload: &[u8]) {
    if s.addr_evt_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut scratch = [0u8; NET_FRAME_HDR + 48];
    let _ = ip_net_write_frame(
        sys,
        s.addr_evt_chan,
        msg,
        payload.as_ptr(),
        payload.len(),
        scratch.as_mut_ptr(),
    );
}

unsafe fn addr_evt_refused(s: &mut IpState, addr16: &[u8; 16], op: u8, reason: u8) {
    let mut p = [0u8; 18];
    p[..16].copy_from_slice(addr16);
    p[16] = op;
    p[17] = reason;
    addr_evt(s, netid::MSG_ADDR_REFUSED, &p);
}

/// Mint an emission token: CSPRNG bytes mixed with the boot incarnation,
/// so it is fresh per install and unmatchable across boots. `None` when
/// either source is unavailable — an install then fails closed.
unsafe fn mint_token(s: &IpState) -> Option<[u8; 16]> {
    let sys = &*s.syscalls;
    let mut t = [0u8; 16];
    if dev_csprng_fill(sys, t.as_mut_ptr(), 16) < 0 {
        log_info(s, b"[ip] token: no entropy");
        return None;
    }
    let Some(inc) = dev_boot_incarnation(sys) else {
        let mut probe = [0u8; 16];
        let rc = (sys.provider_call)(-1, abi::kernel_abi::BOOT_INCARNATION, probe.as_mut_ptr(), 16);
        let mut line = *b"[ip] token: no boot incarnation rc=-000";
        let e = rc.unsigned_abs();
        line[36] = b'0' + ((e / 100) % 10) as u8;
        line[37] = b'0' + ((e / 10) % 10) as u8;
        line[38] = b'0' + (e % 10) as u8;
        log_info(s, &line);
        return None;
    };
    let mut i = 0;
    while i < 16 {
        t[i] ^= inc[i];
        i += 1;
    }
    if t == [0u8; 16] {
        return None;
    }
    Some(t)
}

/// `ADDR_ARM` / `ADDR_FENCE`: the slot the token names, or the refusal.
unsafe fn addr_ctl_resolve(
    s: &mut IpState,
    addr16: &[u8; 16],
    token: &[u8; 16],
    op: u8,
) -> Option<usize> {
    let ipv4 = u32::from_be_bytes([addr16[0], addr16[1], addr16[2], addr16[3]]);
    let Some(slot) = local_slot_for_dst(s, ipv4) else {
        addr_evt_refused(s, addr16, op, netid::refusal::NOT_FOUND);
        return None;
    };
    if slot == 0 {
        addr_evt_refused(s, addr16, op, netid::refusal::PRIMARY);
        return None;
    }
    let a = &s.local_addrs[slot as usize];
    // Constant-time compare: a token is a credential.
    let mut diff = 0u8;
    let mut i = 0;
    while i < 16 {
        diff |= a.token[i] ^ token[i];
        i += 1;
    }
    if diff != 0 {
        addr_evt_refused(s, addr16, op, netid::refusal::TOKEN_MISMATCH);
        return None;
    }
    Some(slot as usize)
}

unsafe fn addr_ctl_arm(s: &mut IpState, addr16: &[u8; 16], token: &[u8; 16]) {
    let Some(slot) = addr_ctl_resolve(s, addr16, token, IP_ADDR_ARM) else {
        return;
    };
    let ipv4 = s.local_addrs[slot].ipv4();
    let generation = s.local_addrs[slot].generation;
    s.local_addrs[slot].flags |= ADDR_FLAG_ARMED;
    log_info(s, b"[ip] addr armed");
    if s.netmask != 0 && s.local_ip != 0 && (ipv4 & s.netmask) == (s.local_ip & s.netmask) {
        send_gratuitous_arp(s, ipv4);
    }
    let mut p = [0u8; 20];
    p[..16].copy_from_slice(addr16);
    p[16..20].copy_from_slice(&generation.to_le_bytes());
    addr_evt(s, netid::MSG_ADDR_ARMED, &p);
}

unsafe fn addr_ctl_fence(s: &mut IpState, addr16: &[u8; 16], token: &[u8; 16]) {
    let Some(slot) = addr_ctl_resolve(s, addr16, token, IP_ADDR_FENCE) else {
        return;
    };
    let ipv4 = s.local_addrs[slot].ipv4();
    let generation = s.local_addrs[slot].generation;
    s.local_addrs[slot].flags &= !ADDR_FLAG_ARMED;
    // A frame from this address staged for the ring is not sent: the
    // cutoff must mean what it says.
    let mut discarded = 0u8;
    if s.pending_tx_len > 0 {
        let f = s.pending_tx_buf.as_ptr().add(2);
        let flen = s.pending_tx_len as usize - 2;
        if !emission_allowed(s, f, flen) {
            s.pending_tx_len = 0;
            s.tx_fenced = s.tx_fenced.wrapping_add(1);
            discarded = 1;
        }
    }
    let _ = ipv4;
    // The gate is closed. Whether the answer can say "wire" depends on
    // the driver: ask it to drain and, while it is still draining, hold
    // the event — bounded, so an unanswered drain still yields a truthful
    // ring hand-off answer.
    match driver_tx_drained(s) {
        DrainAnswer::Drained(index) => {
            emit_fenced(s, addr16, generation, index, netid::cutoff::WIRE, discarded);
        }
        DrainAnswer::Draining if s.fence_wait_slot == 0xFFFF => {
            s.fence_wait_slot = slot as u16;
            s.fence_wait_gen = generation;
            s.fence_wait_discarded = discarded;
            s.fence_wait_addr = *addr16;
            s.fence_wait_deadline_ms = (dev_millis(&*s.syscalls) as u32)
                .wrapping_add(FENCE_WIRE_WAIT_MS)
                .max(1);
        }
        _ => {
            let index = u64::from(s.tx_frame_count);
            s.fence_ring_handoff = s.fence_ring_handoff.wrapping_add(1);
            emit_fenced(
                s,
                addr16,
                generation,
                index,
                netid::cutoff::RING_HANDOFF,
                discarded,
            );
        }
    }
}

/// How long a fence waits for the driver's drain answer before the event
/// goes out at the ring hand-off.
const FENCE_WIRE_WAIT_MS: u32 = 500;

enum DrainAnswer {
    /// The driver reports the wire quiet; the completed transmit count.
    Drained(u64),
    /// Frames are still leaving.
    Draining,
    /// No driver answers the query on this channel.
    Unsupported,
}

/// Ask the frame channel's reader whether everything handed over has left
/// the NIC (`net::identity::tx_drain`).
unsafe fn driver_tx_drained(s: &mut IpState) -> DrainAnswer {
    if s.out_chan < 0 {
        return DrainAnswer::Unsupported;
    }
    let sys = &*s.syscalls;
    let mut arg = [0u8; netid::tx_drain::ARG_LEN];
    let rc = dev_channel_ioctl(
        sys,
        s.out_chan,
        netid::tx_drain::IOCTL,
        arg.as_mut_ptr(),
        arg.len(),
    );
    if rc == 0 {
        DrainAnswer::Drained(u64::from(u32::from_le_bytes(arg)))
    } else if rc == abi::kernel_abi::errno::EAGAIN {
        DrainAnswer::Draining
    } else {
        DrainAnswer::Unsupported
    }
}

unsafe fn emit_fenced(
    s: &mut IpState,
    addr16: &[u8; 16],
    generation: u32,
    index: u64,
    cutoff: u8,
    discarded: u8,
) {
    log_info(s, b"[ip] addr fenced");
    let mut p = [0u8; 30];
    p[..16].copy_from_slice(addr16);
    p[16..20].copy_from_slice(&generation.to_le_bytes());
    p[20..28].copy_from_slice(&index.to_le_bytes());
    p[28] = cutoff;
    p[29] = discarded;
    addr_evt(s, netid::MSG_ADDR_FENCED, &p);
}

/// A fence waiting for the wire: answered when the driver reports it
/// quiet, or at the ring hand-off once the wait is exhausted.
unsafe fn step_fence_wait(s: &mut IpState) {
    if s.fence_wait_slot == 0xFFFF {
        return;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    let expired = now.wrapping_sub(s.fence_wait_deadline_ms) < 0x8000_0000;
    let answer = driver_tx_drained(s);
    let (index, cutoff) = match answer {
        DrainAnswer::Drained(i) => (i, netid::cutoff::WIRE),
        DrainAnswer::Draining if !expired => return,
        _ => {
            s.fence_ring_handoff = s.fence_ring_handoff.wrapping_add(1);
            (u64::from(s.tx_frame_count), netid::cutoff::RING_HANDOFF)
        }
    };
    let addr = s.fence_wait_addr;
    let generation = s.fence_wait_gen;
    let discarded = s.fence_wait_discarded;
    s.fence_wait_slot = 0xFFFF;
    emit_fenced(s, &addr, generation, index, cutoff, discarded);
}

/// Broadcast a gratuitous ARP (L2-broadcast ARP reply) claiming `addr` for our
/// MAC. Sent once when a same-subnet secondary is added and after a DHCP
/// renewal for slot 0.
unsafe fn send_gratuitous_arp(s: &mut IpState, addr: u32) {
    if !s.mac_valid || addr == 0 {
        return;
    }
    let frame_len = arp::build_arp(
        s.tx_frame.as_mut_ptr(),
        arp::ARP_REPLY,
        &s.mac_addr,
        addr,
        &eth::BROADCAST_MAC,
        addr,
    );
    send_frame(s, s.tx_frame.as_ptr(), frame_len);
}

/// Write a net protocol frame to a channel.
/// Frame format: [msg_type: u8] [payload_len: u16 LE] [payload...]
/// Returns 0 on success, -1 on failure.
#[inline(always)]
/// Write a net_proto frame. Module-local variant of pic_runtime::net_write_frame
/// with i32 return (0 or -1) for IP's error handling pattern.
unsafe fn ip_net_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: usize,
    scratch: *mut u8,
) -> i32 {
    // Build frame in scratch: [type][len_lo][len_hi][payload...]
    *scratch = msg_type;
    let pl = (payload_len as u16).to_le_bytes();
    *scratch.add(1) = pl[0];
    *scratch.add(2) = pl[1];
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(payload, scratch.add(NET_FRAME_HDR), payload_len);
    }
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written < total as i32 {
        -1
    } else {
        0
    }
}

/// Read a net_proto frame (header + payload) into the caller's buffer.
/// Returns `(msg_type, payload_len)` on success, or `(0, 0)` if no
/// header is available, the body is short-read, or the body exceeds
/// `buf_cap`. In the oversize case the whole body is drained from
/// the ring so the next read aligns to the next frame.
#[inline(always)]
unsafe fn ip_net_read_frame(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_cap: usize,
) -> (u8, u16) {
    let mut hdr = [0u8; 3];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), 3);
    if n < 3 {
        return (0, 0);
    }
    let msg_type = *hdr.as_ptr();
    let payload_len = (*hdr.as_ptr().add(1) as u16) | ((*hdr.as_ptr().add(2) as u16) << 8);
    if payload_len == 0 || buf_cap == 0 {
        return (msg_type, payload_len);
    }
    if (payload_len as usize) <= buf_cap {
        let body_n = (sys.channel_read)(chan, buf, payload_len as usize);
        if body_n != payload_len as i32 {
            return (0, 0);
        }
        return (msg_type, payload_len);
    }
    // Body too large for the caller's buffer — drain it in chunks so
    // the next header parse doesn't read into the leftover body.
    let mut remaining = payload_len as usize;
    while remaining > 0 {
        let chunk = remaining.min(buf_cap);
        let drained = (sys.channel_read)(chan, buf, chunk);
        if drained <= 0 {
            break;
        }
        remaining -= drained as usize;
    }
    (0, 0)
}

/// Send a MSG_DATA frame to the net consumer channel. Returns
/// `true` when the bytes were accepted (atomic-FIFO, so partial
/// writes are impossible). Callers MUST gate `rcv_nxt` /
/// `delivered_bytes` advancement and the outbound ACK on the return:
/// ACKing data the consumer never received makes the peer think it
/// landed and stop retransmitting, permanently losing payload.
#[inline(always)]
unsafe fn net_send_data(s: &mut IpState, conn_id: u16, data: *const u8, data_len: usize) -> bool {
    if s.net_out_chan < 0 || data_len == 0 {
        return true;
    }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    let payload_len = 2 + data_len; // conn_id (u16 LE) + data
    let max_copy = s.net_scratch.len() - NET_FRAME_HDR - 2;
    if data_len > max_copy {
        return false;
    }
    core::ptr::write_volatile(scratch, NET_MSG_DATA);
    let pl = (payload_len as u16).to_le_bytes();
    core::ptr::write_volatile(scratch.add(1), pl[0]);
    core::ptr::write_volatile(scratch.add(2), pl[1]);
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(scratch.add(3), cb[0]);
    core::ptr::write_volatile(scratch.add(4), cb[1]);
    core::ptr::copy_nonoverlapping(data, scratch.add(5), data_len);
    let total = NET_FRAME_HDR + payload_len;
    let n = (sys.channel_write)(s.net_out_chan, scratch, total);
    if n == total as i32 {
        s.out_items = s.out_items.wrapping_add(1);
        true
    } else {
        false
    }
}

/// Send a short control frame to `net_out_chan`, queueing when the
/// channel is full rather than dropping. Returns `true` when
/// delivered or queued; `false` only when the local queue is itself
/// full. Callers MUST gate any state transition the consumer needs
/// to learn about on this return.
unsafe fn net_send_or_queue(s: &mut IpState, frame: &[u8]) -> bool {
    if s.net_out_chan < 0 {
        return true;
    }
    if frame.is_empty() || frame.len() > NET_OUT_FRAME_MAX {
        return false;
    }
    let sys = &*s.syscalls;
    // Drain anything already queued first so FIFO ordering is
    // preserved across senders and across step boundaries.
    drain_pending_net_out_inner(s, sys);
    if s.pending_net_out_count == 0 {
        let n = (sys.channel_write)(s.net_out_chan, frame.as_ptr(), frame.len());
        if n == frame.len() as i32 {
            return true;
        }
    }
    if s.pending_net_out_count as usize >= NET_OUT_QUEUE_SLOTS {
        log_info(s, b"[ip] net out queue full");
        return false;
    }
    let slot = s.pending_net_out_tail as usize;
    let dst = &mut s.pending_net_out_frames[slot];
    let n = frame.len();
    dst[..n].copy_from_slice(frame);
    s.pending_net_out_lens[slot] = n as u8;
    s.pending_net_out_tail = ((slot + 1) % NET_OUT_QUEUE_SLOTS) as u8;
    s.pending_net_out_count += 1;
    true
}

unsafe fn drain_pending_net_out_inner(s: &mut IpState, sys: &SyscallTable) {
    while s.pending_net_out_count > 0 && s.net_out_chan >= 0 {
        let slot = s.pending_net_out_head as usize;
        let len = s.pending_net_out_lens[slot] as usize;
        let n = (sys.channel_write)(s.net_out_chan, s.pending_net_out_frames[slot].as_ptr(), len);
        if n != len as i32 {
            return;
        }
        s.pending_net_out_head = ((slot + 1) % NET_OUT_QUEUE_SLOTS) as u8;
        s.pending_net_out_count -= 1;
    }
}

unsafe fn drain_pending_net_out(s: &mut IpState) {
    if s.pending_net_out_count == 0 || s.net_out_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    drain_pending_net_out_inner(s, sys);
}

/// Helper: write a short net-proto frame (MSG_ACCEPTED/CLOSED/BOUND/
/// CONNECTED) to `net_out`. All stores use `write_volatile` to keep
/// LLVM from eliding them in PIC on aarch64. Returns whether the
/// frame was delivered or queued; callers MUST hold off on any state
/// transition the consumer needs to learn about when this returns
/// false.
#[inline(always)]
#[must_use]
unsafe fn net_send_short(s: &mut IpState, msg_type: u8, conn_id: u16) -> bool {
    let mut frame = [0u8; 5];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), msg_type);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 2u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    net_send_or_queue(s, &frame)
}

#[inline(always)]
#[must_use]
unsafe fn net_send_accepted(s: &mut IpState, conn_id: u16, local_port: u16) -> bool {
    // MSG_ACCEPTED payload: `[conn_id:2 LE][local_port:2 LE]`, mirroring
    // `net_send_bound`. Consumers that share `net_out` with other anchors
    // (multi-anchor graphs binding distinct ports) filter on `local_port` so
    // they only claim conn_ids whose listener matches their own CMD_BIND;
    // without it every consumer alloc_slot()s the same new conn_id and
    // corrupts each other's subsequent NET_MSG_DATA dispatch.
    let mut frame = [0u8; 7];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_ACCEPTED);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 4u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    let pb = local_port.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), pb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(6), pb[1]);
    let ok = net_send_or_queue(s, &frame);
    // Observability: start a `tcp.connection` span for the accepted (server-
    // side) connection, mint its root trace context, and propagate that context
    // downstream (best-effort `MSG_TRACE_CTX`, right after ACCEPTED) so TLS/HTTP
    // parent their spans under it. One predicate — no clock read, no work — when
    // the telemetry port is unwired, so tracing is zero-cost when disabled.
    if ok && dev_telemetry_enabled(&*s.syscalls) {
        let idx = conn_id as usize;
        if idx < tcp::MAX_TCP_CONNS {
            let sys = &*s.syscalls;
            let now = dev_micros(sys);
            // `0` means "no span"; clamp a (boot-impossible) 0 to 1 so a real
            // accept is never mistaken for an unspanned slot.
            s.tcp_conns[idx].span_start_us = if now == 0 { 1 } else { now };
            dev_csprng_fill(sys, s.tcp_conns[idx].trace_id.as_mut_ptr(), 16);
            dev_csprng_fill(sys, s.tcp_conns[idx].span_id.as_mut_ptr(), 8);
            let trace_id = s.tcp_conns[idx].trace_id;
            let span_id = s.tcp_conns[idx].span_id;
            // Decide head sampling ONCE, here, and latch it on the connection.
            let sampled = ingress_sample_decision(s.sample_permille, &trace_id);
            s.tcp_conns[idx].sampled_flags = sampled;
            let mut scratch = [0u8; NET_FRAME_HDR + abi::contracts::net::net_proto::TRACE_CTX_LEN];
            dev_net_send_trace_ctx(
                sys,
                s.net_out_chan,
                conn_id,
                &trace_id,
                &span_id,
                sampled,
                scratch.as_mut_ptr(),
                scratch.len(),
            );
        }
    }
    ok
}

#[inline(always)]
unsafe fn net_send_closed(s: &mut IpState, conn_id: u16) -> bool {
    // Observability: emit the `tcp.connection` span before the close frame so a
    // full out-queue can't skip it. Only fires for a span that was started
    // (server-accepted, telemetry wired); client connects never set it.
    let idx = conn_id as usize;
    if dev_telemetry_enabled(&*s.syscalls)
        && idx < tcp::MAX_TCP_CONNS
        && s.tcp_conns[idx].span_start_us != 0
    {
        emit_conn_span(s, idx);
        s.tcp_conns[idx].span_start_us = 0;
    }
    net_send_short(s, NET_MSG_CLOSED, conn_id)
}

/// Head-sampling decision for a NEW ingress root, made ONCE at accept. Draws a
/// deterministic per-mille value from the (random) minted `trace_id` and
/// compares it to the configured `sample_permille` rate. Returns the W3C
/// trace-flags to stamp: `TRACE_FLAGS_SAMPLED` when sampled, else 0. The result
/// is stored in `TcpConn::sampled_flags` and BOTH emitted locally and
/// propagated downstream, so the decision is never recomputed (decide once
/// at ingress, carry in flags).
#[inline(always)]
fn ingress_sample_decision(permille: u16, trace_id: &[u8; 16]) -> u8 {
    // permille >= 1000 → always sampled (the common default); 0 → never.
    let draw = u16::from_le_bytes([trace_id[0], trace_id[1]]) % 1000;
    if draw < permille {
        abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    } else {
        0
    }
}

/// Emit the finished `tcp.connection` span using the connection's root trace
/// context (minted at accept, also propagated downstream), so the span and the
/// `MSG_TRACE_CTX` children share one `trace_id` / parent `span_id`. `name_id =
/// 0` is the first `[observability].spans` entry.
#[inline(never)]
unsafe fn emit_conn_span(s: &mut IpState, idx: usize) {
    // Bit test FIRST, before any clock read — the decision was latched at accept
    // (`sampled_flags`), never recomputed. An unsampled root emits nothing (and
    // its children won't either, since the cleared bit was propagated).
    let sampled_flags = s.tcp_conns[idx].sampled_flags;
    if sampled_flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let start = s.tcp_conns[idx].span_start_us;
    let end_raw = dev_micros(sys);
    let end = if end_raw < start { start } else { end_raw };
    let ctx = abi::contracts::telemetry::SpanContext {
        trace_id: s.tcp_conns[idx].trace_id,
        span_id: s.tcp_conns[idx].span_id,
        parent_id: [0u8; 8], // ip is the ingress → root span (no parent)
        flags: sampled_flags,
    };
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = tcp.connection
        abi::contracts::telemetry::SPAN_SERVER,
        abi::contracts::telemetry::STATUS_OK,
        &ctx,
        start,
        end,
    );
}

/// MSG_BOUND payload: `[conn_id:1][local_port:2 LE]`. Consumers that
/// share `net_out` with other bound peers match on `local_port` so they
/// only claim a conn_id for their own CMD_BIND.
#[inline(always)]
unsafe fn net_send_bound(s: &mut IpState, conn_id: u16, local_port: u16) {
    let mut frame = [0u8; 7];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_BOUND);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 4u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    let pb = local_port.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), pb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(6), pb[1]);
    net_send_or_queue(s, &frame);
}

#[inline(always)]
#[must_use]
unsafe fn net_send_connected(s: &mut IpState, conn_id: u16) -> bool {
    // Payload `[conn_id:2 LE][requester_tag]` — the tag echoes the connecting
    // module's CMD_CONNECT tag so a fanned net_out routes the event back to it.
    let tag = if (conn_id as usize) < tcp::MAX_TCP_CONNS {
        s.tcp_conns[conn_id as usize].connect_tag
    } else {
        0
    };
    let mut frame = [0u8; 6];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_CONNECTED);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 3u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), tag);
    net_send_or_queue(s, &frame)
}

/// Send a MSG_ERROR frame. Returns whether the frame was delivered
/// or queued; callers latching `pending_close_notify` on connect /
/// accept failure use the bool to know whether the latch is needed.
#[inline(always)]
unsafe fn net_send_error(s: &mut IpState, conn_id: u16, errno: i8, tag: u8) -> bool {
    // Payload `[conn_id:2 LE][errno][requester_tag]`. The tag echoes the
    // failing CMD_CONNECT's tag so a consumer sharing a fanned net_out
    // attributes a connect failure to the right requester (it has no conn_id
    // yet). Errors not tied to an outbound connect pass tag 0 (untagged).
    let mut frame = [0u8; 7];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_ERROR);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 4u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), errno as u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(6), tag);
    net_send_or_queue(s, &frame)
}

/// Emit a MSG_RETRANSMIT frame. Payload: `[conn_id:2 LE][from_seq:4 LE]`.
#[inline(always)]
unsafe fn net_send_retransmit(s: &mut IpState, conn_id: u16, from_seq: u32) {
    let mut frame = [0u8; 9];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_RETRANSMIT);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 6u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    let b = from_seq.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), b[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(6), b[1]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(7), b[2]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(8), b[3]);
    net_send_or_queue(s, &frame);
}

/// Emit a MSG_ACK frame. Payload: `[conn_id:2 LE][acked_seq:4 LE]`.
#[inline(always)]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
unsafe fn net_send_ack(s: &mut IpState, conn_id: u16, acked_seq: u32) {
    let mut frame = [0u8; 9];
    let cb = conn_id.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr(), NET_MSG_ACK);
    core::ptr::write_volatile(frame.as_mut_ptr().add(1), 6u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(2), 0u8);
    core::ptr::write_volatile(frame.as_mut_ptr().add(3), cb[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(4), cb[1]);
    let b = acked_seq.to_le_bytes();
    core::ptr::write_volatile(frame.as_mut_ptr().add(5), b[0]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(6), b[1]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(7), b[2]);
    core::ptr::write_volatile(frame.as_mut_ptr().add(8), b[3]);
    net_send_or_queue(s, &frame);
}

// ─── datagram emitters ──────────────────────────────────────────
//
// See modules/sdk/contracts/net/datagram.rs for the wire shape. All
// helpers write into `s.net_scratch` and emit on `s.net_out_chan`. IPv4
// addresses are wire-order big-endian; ports are little-endian (matching
// the contract spec).

/// MSG_DG_BOUND payload: `[ep_id:1][local_port:2 LE]`.
#[inline(always)]
unsafe fn dg_send_bound(s: &mut IpState, ep_id: u8, local_port: u16) {
    let mut frame = [0u8; 6];
    use core::ptr::write_volatile as wv;
    wv(frame.as_mut_ptr(), DG_MSG_BOUND);
    wv(frame.as_mut_ptr().add(1), 3u8);
    wv(frame.as_mut_ptr().add(2), 0u8);
    wv(frame.as_mut_ptr().add(3), ep_id);
    let pb = local_port.to_le_bytes();
    wv(frame.as_mut_ptr().add(4), pb[0]);
    wv(frame.as_mut_ptr().add(5), pb[1]);
    net_send_or_queue(s, &frame);
}

/// MSG_DG_RX_FROM (IPv4) payload:
/// `[ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][data...]`.
#[inline(always)]
unsafe fn dg_send_rx_from_v4(
    s: &mut IpState,
    ep_id: u8,
    src_ip: u32,
    src_port: u16,
    data: *const u8,
    data_len: usize,
) {
    if s.net_out_chan < 0 || data_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    let payload_len = 1 + 1 + 4 + 2 + data_len; // ep_id + af + addr + port + data
    let max_copy = s.net_scratch.len() - NET_FRAME_HDR;
    if payload_len > max_copy {
        return;
    }
    use core::ptr::write_volatile as wv;
    wv(scratch, DG_MSG_RX_FROM);
    let pl = (payload_len as u16).to_le_bytes();
    wv(scratch.add(1), pl[0]);
    wv(scratch.add(2), pl[1]);
    wv(scratch.add(3), ep_id);
    wv(scratch.add(4), DG_AF_INET);
    let ip_bytes = src_ip.to_be_bytes();
    wv(scratch.add(5), ip_bytes[0]);
    wv(scratch.add(6), ip_bytes[1]);
    wv(scratch.add(7), ip_bytes[2]);
    wv(scratch.add(8), ip_bytes[3]);
    let port_bytes = src_port.to_le_bytes();
    wv(scratch.add(9), port_bytes[0]);
    wv(scratch.add(10), port_bytes[1]);
    core::ptr::copy_nonoverlapping(data, scratch.add(11), data_len);
    (sys.channel_write)(s.net_out_chan, scratch, NET_FRAME_HDR + payload_len);
}

/// MSG_DG_CLOSED payload: `[ep_id:1]`.
#[inline(always)]
unsafe fn dg_send_closed(s: &mut IpState, ep_id: u8) {
    let mut frame = [0u8; 4];
    use core::ptr::write_volatile as wv;
    wv(frame.as_mut_ptr(), DG_MSG_CLOSED);
    wv(frame.as_mut_ptr().add(1), 1u8);
    wv(frame.as_mut_ptr().add(2), 0u8);
    wv(frame.as_mut_ptr().add(3), ep_id);
    net_send_or_queue(s, &frame);
}

/// MSG_DG_ERROR payload: `[ep_id:1][errno:i8]`.
#[inline(always)]
unsafe fn dg_send_error(s: &mut IpState, ep_id: u8, errno: i8) {
    let mut frame = [0u8; 5];
    use core::ptr::write_volatile as wv;
    wv(frame.as_mut_ptr(), DG_MSG_ERROR);
    wv(frame.as_mut_ptr().add(1), 2u8);
    wv(frame.as_mut_ptr().add(2), 0u8);
    wv(frame.as_mut_ptr().add(3), ep_id);
    wv(frame.as_mut_ptr().add(4), errno as u8);
    net_send_or_queue(s, &frame);
}

/// Recompute the advertised receive window from consumer-channel backpressure.
/// Called after delivering data on a connection.
unsafe fn update_rcv_wnd(s: &mut IpState, conn_idx: usize) {
    let sys = &*s.syscalls;
    // Check whether the consumer channel has drained space.
    let poll_out = (sys.channel_poll)(s.net_out_chan, POLL_OUT);
    let consumer_ready = poll_out > 0 && (poll_out as u32 & POLL_OUT) != 0;
    let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
    // Heuristic: if consumer channel reports writable, treat the
    // downstream buffer as fully drained.
    if consumer_ready {
        conn.consumed_bytes = conn.delivered_bytes;
    }
    let in_flight = conn.delivered_bytes.wrapping_sub(conn.consumed_bytes);
    let avail = (tcp::MAX_RCV_WND as u32).saturating_sub(in_flight) as u16;
    let wnd = core::cmp::min(avail, tcp::MAX_RCV_WND);
    conn.rcv_wnd = continuity::rcv_wnd_exposed(s, conn_idx, wnd);
}

/// Unchecked TCP conn access (avoids bounds check panic in PIC).
#[inline(always)]
unsafe fn tcp_conn(s: &IpState, idx: usize) -> &tcp::TcpConn {
    &*s.tcp_conns.as_ptr().add(idx)
}

#[inline(always)]
unsafe fn tcp_conn_mut(s: &mut IpState, idx: usize) -> &mut tcp::TcpConn {
    &mut *s.tcp_conns.as_mut_ptr().add(idx)
}

/// Ephemeral port range (IANA dynamic range, upper end kept clear of the
/// well-known static assignments some deployments still park above 65000).
const EPHEMERAL_LO: u16 = 49152;
const EPHEMERAL_HI: u16 = 65000;

/// CSPRNG candidates drawn before falling back to a scan.
const EPHEMERAL_TRIES: usize = 8;

/// Upper bound on the fallback scan. At most `MAX_TCP_CONNS` ports can be in
/// use, so a scan this long either finds a free port or proves the table is
/// the binding constraint rather than the range.
const EPHEMERAL_SCAN_MAX: usize = tcp::MAX_TCP_CONNS * 2;

/// Recount half-open (SYN_RECEIVED) connections and update the global and
/// per-source high-water marks. Counting the table rather than tracking a
/// delta keeps the gauge honest across every teardown path.
///
/// `src` is the source address of the SYN that just landed; its own count is
/// tracked separately because a global gauge cannot distinguish a flood from
/// one peer from a genuine burst of distinct clients.
/// Half-open (SYN_RECEIVED) connections currently in the table. The cookie
/// watermark reads this rather than the `tcp_half_open` gauge: the gauge is
/// only refreshed on a passive open, and a stale one would latch cookie mode
/// on after a flood had drained.
///
/// # Safety
/// `s.tcp_conns` must be initialised.
/// Decode the optional owner tag at the head of a `DG_CMD_SEND_TO` /
/// `DG_CMD_CLOSE` payload. Returns `(claimed_tag, offset_of_next_field)`.
///
/// The tag is recognised by `DG_OWNER_TAG_MARK` at offset 1 — the byte that
/// carries `af` in the untagged shape, and a value no address family takes —
/// so the two shapes are distinguished without a length rule over a payload
/// that ends in variable-length data.
///
/// An absent tag decodes as 0. Endpoints bound with `owner_tag == 0` are
/// therefore reachable by any consumer sharing this module's command
/// channel; endpoints bound with a nonzero tag are not.
///
/// # Safety
/// `payload` must point to at least `plen` readable bytes.
#[inline]
unsafe fn dg_decode_owner_tag(payload: *const u8, plen: usize) -> (u16, usize) {
    if plen > DG_OWNER_TAG_FIELD && *payload.add(1) == DG_OWNER_TAG_MARK {
        (
            u16::from_le_bytes([*payload.add(2), *payload.add(3)]),
            1 + DG_OWNER_TAG_FIELD,
        )
    } else {
        (0, 1)
    }
}

/// Outcome of datagram bind admission.
enum DgBind {
    /// No endpoint holds an overlapping identity — allocate a new one.
    Fresh,
    /// The requested identity is already held by this owner; the bind is an
    /// idempotent retry and re-uses the existing endpoint.
    Existing(usize),
    /// The identity is held by someone else, or reachability overlaps an
    /// endpoint bound at a different address slot.
    Conflict,
}

/// Decide whether a datagram bind of `(port, slot, owner_tag)` may proceed.
///
/// Reachability is what makes two binds conflict, not the numeric port. A
/// concrete slot serves one local address; `LOCAL_SLOT_ANY` serves every
/// unowned address, so it overlaps every concrete slot. Two concrete slots
/// never overlap, which is why the same port bound at two local addresses is
/// two sockets. TCP listeners are a different protocol and never conflict
/// here — `find_listener` already excludes datagram slots in the other
/// direction.
unsafe fn dg_bind_admission(s: &IpState, port: u16, slot: u16, owner_tag: u16) -> DgBind {
    let mut i = 0;
    while i < MAX_DG_ENDPOINTS {
        let c = &*s.tcp_conns.as_ptr().add(i);
        if c.is_active() && c.is_datagram && c.local_port == port {
            if c.local_slot == slot {
                if c.owner_tag == owner_tag {
                    return DgBind::Existing(i);
                }
                return DgBind::Conflict;
            }
            if c.local_slot == LOCAL_SLOT_ANY || slot == LOCAL_SLOT_ANY {
                return DgBind::Conflict;
            }
        }
        i += 1;
    }
    DgBind::Fresh
}

/// Pick a free connection slot for a datagram endpoint, starting the scan at
/// a CSPRNG-chosen offset.
///
/// The slot index is the `ep_id` the consumer echoes back on every send and
/// close, and the command channel carries no producer identity, so a
/// consecutively-allocated index is guessable from a consumer's own
/// endpoints. Starting the scan at a random offset removes the ordinal
/// relationship. It is unpredictability, not authority — see the datagram
/// section of `README.md`. Falls back to the first free slot when the CSPRNG
/// is unavailable: a bind carries no sequence-space secret, so refusing it
/// for want of entropy would cost availability and buy nothing.
unsafe fn alloc_dg_slot(s: &mut IpState) -> Option<usize> {
    let sys = &*s.syscalls;
    let mut r = [0u8; 1];
    let start = if dev_csprng_fill(sys, r.as_mut_ptr(), 1) < 0 {
        0usize
    } else {
        (r[0] as usize) % MAX_DG_ENDPOINTS
    };
    // Endpoints live in the first `MAX_DG_ENDPOINTS` slots: the wire's
    // `ep_id` is a u8, and the id space binds the endpoint count.
    let mut n = 0;
    while n < MAX_DG_ENDPOINTS {
        let ci = (start + n) % MAX_DG_ENDPOINTS;
        if slot_is_free(&*s.tcp_conns.as_ptr().add(ci)) {
            return Some(ci);
        }
        n += 1;
    }
    None
}

/// Is `port` already bound by a TCP connection or datagram endpoint?
unsafe fn port_in_use(s: &IpState, port: u16) -> bool {
    if PORT_REF_ENTRIES > 1 {
        return *s.port_ref.as_ptr().add(port as usize) != 0;
    }
    let mut i = 0;
    while i < tcp::MAX_TCP_CONNS {
        let c = &*s.tcp_conns.as_ptr().add(i);
        if c.is_active() && c.local_port == port {
            return true;
        }
        i += 1;
    }
    false
}

/// Allocate an ephemeral port.
///
/// Every allocation draws a fresh CSPRNG candidate rather than incrementing
/// from the last one: an incrementing sequence makes the next allocation
/// predictable from any observed connection, which is half of what an
/// off-path attacker needs to forge into a live conversation. Candidates are
/// probed against the table, and a bounded scan covers the case where the
/// random draws keep landing on live ports.
///
/// `None` means no port could be allocated — either the CSPRNG is
/// unavailable, in which case allocation fails closed rather than falling
/// back to a guessable sequence, or the range is exhausted.
unsafe fn next_port(s: &mut IpState) -> Option<u16> {
    let sys = &*s.syscalls;
    let span = (EPHEMERAL_HI - EPHEMERAL_LO) as u32;
    let mut last = EPHEMERAL_LO;

    let mut tries = 0;
    while tries < EPHEMERAL_TRIES {
        let mut r = [0u8; 2];
        if dev_csprng_fill(sys, r.as_mut_ptr(), 2) < 0 {
            s.drops.entropy_unavailable = s.drops.entropy_unavailable.wrapping_add(1);
            return None;
        }
        let cand = EPHEMERAL_LO + ((u16::from_le_bytes(r) as u32) % span) as u16;
        if !port_in_use(s, cand) {
            s.next_ephemeral_port = cand;
            return Some(cand);
        }
        last = cand;
        tries += 1;
    }

    // Bounded fallback scan from the last candidate.
    let mut scanned = 0;
    let mut cand = last;
    while scanned < EPHEMERAL_SCAN_MAX {
        cand = if cand + 1 >= EPHEMERAL_HI {
            EPHEMERAL_LO
        } else {
            cand + 1
        };
        if !port_in_use(s, cand) {
            s.next_ephemeral_port = cand;
            return Some(cand);
        }
        scanned += 1;
    }
    s.drops.port_exhausted = s.drops.port_exhausted.wrapping_add(1);
    None
}

/// Establish the per-boot ISN secret, once. Returns `false` when the kernel
/// CSPRNG is unavailable; callers must then refuse to open a connection
/// rather than fall back to a derivation an observer can reproduce.
unsafe fn ensure_isn_secret(s: &mut IpState) -> bool {
    if s.isn_secret_valid {
        return true;
    }
    let sys = &*s.syscalls;
    if dev_csprng_fill(sys, s.isn_secret.as_mut_ptr(), 16) < 0 {
        s.drops.entropy_unavailable = s.drops.entropy_unavailable.wrapping_add(1);
        if !s.entropy_warned {
            s.entropy_warned = true;
            log_error(s, b"[ip] no entropy: tcp opens refused");
        }
        return false;
    }
    s.isn_secret_valid = true;
    true
}

/// Avalanche mix (finaliser only — this is a keyed diffusion step, not a MAC).
#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

/// FNV fold of the per-boot ISN secret — the keyed prefix both the ISS
/// construction and the SYN cookie start from. Callers must have established
/// the secret first (`ensure_isn_secret`).
///
/// # Safety
/// `s.isn_secret` must be initialised.
#[inline]
unsafe fn isn_secret_fold(s: &IpState) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < 16 {
        h ^= *s.isn_secret.as_ptr().add(i) as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// Coarse epoch a SYN cookie is minted in: ~65.5 s per tick.
#[inline]
unsafe fn cookie_epoch(s: &IpState) -> u32 {
    (dev_millis(&*s.syscalls) >> 16) as u32
}

/// SYN cookie for one four-tuple in one epoch. The construction is the ISS
/// hash with the epoch mixed in and the epoch's low bits written into the
/// cookie's low bits, so the returning ACK names the epoch its cookie was
/// minted in without a table.
///
/// Nothing about the connection needs to be smuggled through the cookie: no
/// TCP option is negotiated (`tcp::cookie_mode_admissible`), so every field
/// of the connection block is either a compile-time constant or a field of
/// the returning ACK.
///
/// # Safety
/// The ISN secret must be established.
unsafe fn compute_syn_cookie(
    s: &IpState,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    epoch: u32,
) -> u32 {
    let mut h = isn_secret_fold(s);
    h ^= local_ip as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= remote_ip as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= ((local_port as u64) << 16) | (remote_port as u64);
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= epoch as u64;
    let f = mix64(h) as u32;
    (f & !tcp::SYN_COOKIE_EPOCH_MASK) | (epoch & tcp::SYN_COOKIE_EPOCH_MASK)
}

/// Validate a cookie carried back in an ACK. Accepts the current epoch and
/// the one before it — the epoch bits in the cookie select which, so at most
/// one hash is evaluated and there is no scan an attacker can lengthen.
///
/// # Safety
/// The ISN secret must be established.
unsafe fn validate_syn_cookie(
    s: &IpState,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
    cookie: u32,
) -> bool {
    let now = cookie_epoch(s);
    let bits = cookie & tcp::SYN_COOKIE_EPOCH_MASK;
    let mut back: u32 = 0;
    while back < 2 {
        let epoch = now.wrapping_sub(back);
        if (epoch & tcp::SYN_COOKIE_EPOCH_MASK) == bits
            && compute_syn_cookie(s, local_ip, local_port, remote_ip, remote_port, epoch) == cookie
        {
            return true;
        }
        back += 1;
    }
    false
}

/// Initial send sequence number, RFC 6528 §3: `ISN = M + F(tuple, secret)`,
/// where `M` is a 4-microsecond timer and `F` mixes the connection's
/// four-tuple with a per-boot secret.
///
/// The point of the construction is that the offset is per-tuple: the timer
/// alone would let any peer predict every other connection's sequence space,
/// and a per-tuple offset alone would repeat across incarnations of the same
/// tuple. Callers must have established the secret first
/// (`ensure_isn_secret`).
unsafe fn compute_iss(
    s: &IpState,
    local_ip: u32,
    local_port: u16,
    remote_ip: u32,
    remote_port: u16,
) -> u32 {
    let sys = &*s.syscalls;
    // 4 µs tick, the rate RFC 6528 specifies for M.
    let m = (dev_micros(sys) >> 2) as u32;

    let mut h = isn_secret_fold(s);
    h ^= local_ip as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= remote_ip as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= ((local_port as u64) << 16) | (remote_port as u64);
    let f = mix64(h) as u32;

    m.wrapping_add(f)
}

/// Send a raw ethernet frame via `out_chan`. Frames are length-prefixed
/// (`[len:u16 LE][payload]`) so the byte-stream FIFO to the NIC driver
/// preserves frame boundaries; writes are atomic (all 2+N bytes or
/// nothing). If the channel is full the frame is staged in
/// `pending_tx_buf` and retried on the next step.
///
/// Returns `true` iff the frame is safely queued (committed to the
/// ring or stashed for retry). On `false` the caller MUST NOT advance
/// state that assumes the bytes are on the wire (`snd_nxt`, etc.) —
/// TCP retransmit / pending-cmd stash logic relies on this.
unsafe fn send_frame(s: &mut IpState, frame: *const u8, len: usize) -> bool {
    if s.out_chan < 0 || len == 0 || len > MAX_FRAME_SIZE - 2 {
        return false;
    }
    // The emission gate: a frame sourced from a fenced address does not
    // reach the driver ring, whatever path built it. This is the boundary
    // `MSG_ADDR_FENCED` reports, so it is the one place the check lives.
    if !emission_allowed(s, frame, len) {
        s.tx_fenced = s.tx_fenced.wrapping_add(1);
        return false;
    }
    let sys = &*s.syscalls;

    // Flush any frame pending from a previous step before writing a new one.
    if s.pending_tx_len > 0 {
        let p = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if p > 0 && (p as u32 & POLL_OUT) != 0 {
            let plen = s.pending_tx_len as usize;
            let n = (sys.channel_write)(s.out_chan, s.pending_tx_buf.as_ptr(), plen);
            if n != plen as i32 {
                // Ring had room reported by POLL_OUT but not enough
                // for the full frame; atomic-FIFO write rejected.
                // Keep the stash; caller must not advance state.
                s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
                return false;
            }
            s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
            s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(plen as u32);
            s.pending_tx_len = 0;
        } else {
            s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
            return false;
        }
    }

    // Stage "[len_lo][len_hi][frame...]" in pending_tx_buf for atomic write.
    let pbuf = s.pending_tx_buf.as_mut_ptr();
    core::ptr::write_volatile(pbuf, len as u8);
    core::ptr::write_volatile(pbuf.add(1), (len >> 8) as u8);
    core::ptr::copy_nonoverlapping(frame, pbuf.add(2), len);
    let total = 2 + len;

    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
        let n = (sys.channel_write)(s.out_chan, pbuf, total);
        if n == total as i32 {
            s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
            s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(total as u32);
            return true;
        }
        // POLL_OUT reported space but the atomic write didn't fit —
        // bytes are already in `pbuf`, so stash for the next tick.
        s.pending_tx_len = total as u16;
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        true
    } else {
        s.pending_tx_len = total as u16;
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        true
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<IpState>()
}

/// PIC module ABI entry: one-time initialisation. The kernel calls this
/// once during loader bring-up before any `module_new` invocation.
///
/// # Safety
/// `_syscalls` is currently unused. The kernel guarantees ABI binding has
/// completed before this call; no module-side state exists yet so there
/// is nothing to invalidate.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// PIC module ABI entry: construct module state in `state` (kernel-allocated
/// from the manifest-declared `state_size`).
///
/// # Safety
/// `state` / `params` / `syscalls` are kernel-owned buffers passed across the
/// module ABI. The kernel guarantees `state` is at least `state_size` bytes,
/// `params` is at least `params_len` bytes, and `state` is zero-initialised.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: `state` / `syscalls` are kernel-owned buffers passed across the
    // module ABI. We null-check both before deref, bounds-check `state_size`
    // against `sizeof::<IpState>()`, and the kernel guarantees the buffer is
    // zero-initialised by `alloc_state()`.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<IpState>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut IpState);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        s.use_dhcp = 1;
        // Target-tier head-sampling default,
        // overridable by the `trace_sample_permille` param. The bcm2712 (aarch64)
        // module artefact is the pi5-class rig → 50‰; MCU silicon (rp2350/rp2040,
        // thumbv8m/v6m) → 0‰ so tiny targets pay no tracing cost by default.
        #[cfg(target_arch = "aarch64")]
        {
            s.sample_permille = 50;
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            s.sample_permille = 0;
        }
        s.mac_valid = false;

        // No loopback pairs yet (state arrives zeroed; 0 is a valid
        // slot index, so the "none" sentinel must be set explicitly).
        let mut li = 0;
        while li < tcp::MAX_TCP_CONNS {
            s.loopback_peer[li] = -1;
            li += 1;
        }
        s.arp_wait_len = 0;
        s.arp_wait_overflow = 0;

        // Initialize ARP table
        let mut i = 0;
        while i < arp::ARP_TABLE_SIZE {
            *s.arp_table.as_mut_ptr().add(i) = arp::ArpEntry::empty();
            i += 1;
        }
        s.arp_pending_state = arp::ARP_PENDING_NONE;

        // Initialize DHCP
        s.dhcp = dhcp::DhcpClient::new();

        // Initialize TCP connections
        i = 0;
        while i < tcp::MAX_TCP_CONNS {
            *s.tcp_conns.as_mut_ptr().add(i) = tcp::TcpConn::new();
            i += 1;
        }
        index::clear(&mut s.conn_index);
        index::clear(&mut s.addr_index);
        // Taken here and nowhere else: both indexes are searched under the
        // seed they were built with, so a seed established later — after an
        // address is already indexed, say — would strand every entry that
        // came before it.
        //
        // Folded from the boot incarnation rather than drawn from the
        // module's own CSPRNG. The incarnation is already unpredictable to
        // anyone off the host and costs no entropy to read, whereas a draw
        // here would consume from the same stream the ISNs and ephemeral
        // ports come out of — moving every later value and making this
        // module's randomness depend on how many seeds it happened to take.
        // Zero when the incarnation is not up yet: no worse than an
        // unseeded hash, and still one value for the module's whole life.
        s.index_seed = match dev_boot_incarnation(&*s.syscalls) {
            Some(inc) => {
                let mut v = 0u32;
                let mut b = 0;
                while b < 16 {
                    v ^= u32::from(inc[b]) << ((b % 4) * 8);
                    b += 1;
                }
                v
            }
            None => 0,
        };
        i = 0;
        while i < MAX_LISTENERS {
            s.listeners[i] = 0;
            i += 1;
        }
        i = 0;
        while i < PORT_REF_ENTRIES {
            s.port_ref[i] = 0;
            i += 1;
        }
        i = 0;
        while i < HO_SRC_ENTRIES {
            s.ho_src[i] = index::SourceCount::empty();
            i += 1;
        }
        s.ho_src_untracked = 0;
        s.free_top = 0;
        s.alloc_scan_cursor = 0;
        s.alloc_scan_step = u32::MAX;
        s.alloc_scanned = 0;
        {
            // Pushed high to low so allocation hands out the lowest slot
            // first.
            let lo = tcp_slot_lo();
            let mut i = tcp::MAX_TCP_CONNS;
            while i > lo {
                i -= 1;
                free_push(s, i);
            }
        }
        s.sweep_cursor = 0;
        s.sweep_window_ms = dev_millis(&*s.syscalls) as u32;
        s.chal_epoch = 0;

        s.ip_id = 1;
        // Scan cursor only; every allocation draws a fresh CSPRNG candidate.
        s.next_ephemeral_port = 0;
        s.drops = IpDrops::new();
        s.chal_ack_budget = tcp::CHALLENGE_ACK_GLOBAL_BUDGET;
        s.chal_refill_ticks = 0;
        s.isn_secret = [0u8; 16];
        s.isn_secret_valid = false;
        s.entropy_warned = false;
        s.gw_pin_pending = false;
        s.gw_pin_ip = 0;

        // Discover net protocol channels
        let sys = &*s.syscalls;
        s.net_in_chan = dev_channel_port(sys, 0, NET_IN_PORT); // in[1]: net commands from consumer
        s.net_out_chan = dev_channel_port(sys, 1, 1); // out[1]: net messages to consumer
        s.addr_ctl_chan = dev_channel_port(sys, 0, ADDR_CTL_PORT); // in[2]: addr control (optional)
        s.addr_evt_chan = dev_channel_port(sys, 1, ADDR_EVT_PORT); // out[5]: emission events (optional)
        s.addr_generation = 0;
        s.tx_fenced = 0;
        s.fence_wait_slot = 0xFFFF;
        s.fence_wait_discarded = 0;
        s.fence_wait_gen = 0;
        s.fence_wait_deadline_ms = 0;
        s.fence_wait_addr = [0; 16];
        s.fence_ring_handoff = 0;
        s.pkt_in_chan = dev_channel_port(sys, 0, PACKET_IN_PORT); // in[3]: dispositions (optional)
        s.pkt_out_chan = dev_channel_port(sys, 1, PACKET_OUT_PORT); // out[3]: decision records
        s.pkt_fwd_chan = dev_channel_port(sys, 1, PACKET_FWD_PORT); // out[4]: forwarded frames
        continuity::init(s); // in[4] / out[6]: transport continuity (optional)
        let sys = &*s.syscalls;

        // Decision seam starts empty; generation 1 so a zero `pkt_id` never
        // names a live hold.
        s.pkt_decision = PKT_DECISION_OFF;
        s.pkt_hold_ms = 50;
        s.pkt_gen = 1;
        s.pkt_held = 0;
        s.pkt_stats = PktSeamStats::default();
        let mut hi = 0;
        while hi < MAX_PACKET_HOLD {
            let h = &mut *s.pkt_hold.as_mut_ptr().add(hi);
            h.in_use = 0;
            h.pending_fwd[0] = 0xFF;
            hi += 1;
        }

        // Self-register as the node's net-identity provider (the kernel-side
        // workload backend resolves addr_ctl / ingress through this — no name
        // convention). Declares OUR port indices; best-effort: on a
        // single-tenant kernel this is ENOSYS, in a bare harness a stub — the
        // single-address path is byte-identical either way.
        let mut reg = [ADDR_CTL_PORT, NET_IN_PORT];
        let _ = (sys.provider_call)(
            -1,
            abi::kernel_abi::NET_IDENT_PROVIDER,
            reg.as_mut_ptr(),
            reg.len(),
        );

        // Address table starts empty; slot 0 is the primary and is kept in
        // sync with `local_ip` (host-owned, owner_tag 0, flags.PRIMARY). Its
        // IPv4 is populated when DHCP binds or `force_configured` runs.
        let mut ai = 0;
        while ai < MAX_LOCAL_ADDRS {
            *s.local_addrs.as_mut_ptr().add(ai) = LocalAddr::empty();
            ai += 1;
        }
        s.local_addrs[0].flags = ADDR_FLAG_PRIMARY | ADDR_FLAG_ARMED;

        // Parse TLV params
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }

        // The decision seam is either wholly present or wholly absent. A
        // director wired to a module that will never ask it, or a module
        // configured to ask a director that is not there, would run as an
        // ordinary stack with a silent hole where the decision was meant to
        // be — refused here, before network readiness.
        let seam_wired = s.pkt_in_chan >= 0 && s.pkt_out_chan >= 0;
        if s.pkt_decision != PKT_DECISION_OFF && !seam_wired {
            let msg = b"[ip] refusing to construct: packet_decision=pre_transport needs packet_in and packet_out wired";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
            return -1;
        }
        if s.pkt_decision == PKT_DECISION_OFF && (s.pkt_in_chan >= 0 || s.pkt_out_chan >= 0) {
            let msg = b"[ip] refusing to construct: packet ports wired but packet_decision=off";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
            return -1;
        }

        log_info(s, b"[ip] module loaded");

        0
    }
}

/// PIC module ABI entry: per-tick cooperative step. Reads channel events,
/// advances TCP/IP state machines, drains pending output.
///
/// # Safety
/// `state` must point to an initialised `IpState` (laid down by
/// `module_new`). The kernel scheduler guarantees no concurrent step
/// invocation, so the unique `&mut *` re-borrow is sound.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut IpState);
    s.step_count = s.step_count.wrapping_add(1);

    // Snapshot rx/tx/bp counters so we can decide at end-of-step
    // whether *anything* moved (= work happened) or this was an
    // idle tick. Cheaper than threading a `did_work` flag through
    // every helper.
    let rx_pre = s.tlm.bytes_in;
    let tx_pre = s.tlm.bytes_out;
    let bp_pre = s.tlm.bp_steps;

    // 0a. Flush any pending TX frame from previous step. Atomic-FIFO
    // writes are all-or-nothing — only clear `pending_tx_len` when
    // the full frame committed; otherwise leave it stashed for the
    // next tick.
    if s.pending_tx_len > 0 && s.out_chan >= 0 {
        let sys = &*s.syscalls;
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            let len = s.pending_tx_len as usize;
            let n = (sys.channel_write)(s.out_chan, s.pending_tx_buf.as_ptr(), len);
            if n == len as i32 {
                s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
                s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(len as u32);
                s.pending_tx_len = 0;
            } else {
                s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
            }
        }
        // Yield rather than re-step: returning Burst would loop IP up
        // to 16384 times before the NIC driver gets to drain its ring.
        if s.pending_tx_len > 0 {
            // RunnableBacklog: more TX work is ready, but we yield for NIC
            // fairness. Heat the pacer (keep cadence tight for the in-flight
            // traffic) WITHOUT the immediate re-step that would starve the
            // ring (the motivating IP/NIC case).
            dev_report_step_effect(&*s.syscalls, step_effect::RUNNABLE_BACKLOG);
            return 0; // StepOutcome::Continue
        }
    }

    // 0b. Flush any control frames left queued by a congested
    // `net_out_chan` before producing new events; FIFO order matters.
    drain_pending_net_out(s);

    // 0c. Settle the director's dispositions before taking new frames, so
    // the slots they release are available to this step's intake; then
    // release anything held past its deadline.
    service_packet_in(s);

    // 1. Receive and process incoming frames
    let mac_was_valid = s.mac_valid;
    process_rx_frames(s);
    expire_held(s);
    // Did the 32-frame drain budget bind? A still-readable NIC channel
    // after draining means `ip` stopped with frames waiting, which is the
    // discriminator between "ip is the gate" and "ip is starved".
    if s.in_chan >= 0 {
        let p = ((*s.syscalls).channel_poll)(s.in_chan, POLL_IN);
        if p > 0 && (p as u32 & POLL_IN) != 0 {
            s.pend_rx_steps = s.pend_rx_steps.wrapping_add(1);
        }
    }

    // Diagnostic: log when MAC is first learned
    if !mac_was_valid && s.mac_valid {
        let mut buf = [0u8; 40];
        let prefix = b"[ip] mac learned ";
        let mut i = 0;
        while i < prefix.len() {
            buf[i] = prefix[i];
            i += 1;
        }
        // Format MAC as hex
        let hex = b"0123456789abcdef";
        let bp = buf.as_mut_ptr();
        let hp = hex.as_ptr();
        let mut p = prefix.len();
        let mut m = 0usize;
        while m < 6 && p + 2 < 40 {
            let byte = *s.mac_addr.as_ptr().add(m);
            *bp.add(p) = *hp.add((byte >> 4) as usize);
            *bp.add(p + 1) = *hp.add((byte & 0x0F) as usize);
            p += 2;
            if m < 5 && p < 40 {
                *bp.add(p) = b':';
                p += 1;
            }
            m += 1;
        }
        let sl = core::slice::from_raw_parts(bp, p);
        log_info(s, sl);
    }

    // Diagnostic: periodic status (every ~5s at 1ms steps)
    if s.step_count.is_multiple_of(5000) {
        // Module-scope telemetry: emit cumulative counters to the `observe`
        // collector when the telemetry port is wired (no-op otherwise). Metric
        // ids follow `[observability].metrics` order: 0 = bytes_in, 1 = bytes_out.
        if dev_telemetry_enabled(&*s.syscalls) {
            let tsys = &*s.syscalls;
            let me = dev_self_index(tsys);
            if me >= 0 {
                let midx = me as u16;
                let t = dev_micros(tsys);
                let counter = abi::contracts::telemetry::METRIC_COUNTER;
                dev_telemetry_metric(tsys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
                dev_telemetry_metric(tsys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
            }
        }

        if !s.mac_valid {
            log_info(s, b"[ip] waiting for mac");
        } else {
            // Avoid match-returning-slice (broken in PIC) — call log_info directly
            match s.dhcp.state {
                dhcp::DhcpState::Idle => log_info(s, b"[ip] dhcp state=idle"),
                dhcp::DhcpState::Discovering => log_info(s, b"[ip] dhcp state=discover"),
                dhcp::DhcpState::Requesting => log_info(s, b"[ip] dhcp state=request"),
                dhcp::DhcpState::Bound => log_info(s, b"[ip] dhcp state=bound"),
            }
            // Log frame counters using raw pointer writes (no bounds checks)
            {
                let mut buf = [0u8; 40];
                let bp = buf.as_mut_ptr();
                let prefix = b"[ip] rx=";
                let mut p = 0usize;
                while p < prefix.len() {
                    *bp.add(p) = prefix[p];
                    p += 1;
                }
                p += fmt_u32_raw(bp.add(p), s.rx_frame_count);
                let mid = b" tx=";
                let mut m = 0usize;
                while m < mid.len() {
                    *bp.add(p) = mid[m];
                    p += 1;
                    m += 1;
                }
                p += fmt_u32_raw(bp.add(p), s.tx_frame_count);
                let sl = core::slice::from_raw_parts(bp, p);
                log_info(s, sl);
            }
        }
    }

    // 2. Run DHCP state machine (if enabled and not yet configured)
    if s.use_dhcp != 0 && !s.ip_configured {
        step_dhcp(s);
    }

    // 3. Address control (in[2]) then net protocol channels (consumer ↔ IP).
    // addr_ctl is drained first so a workload's address is live before any
    // consumer command that binds/sends on it. No-op when the port is unwired.
    // channel_poll verified working from PIC on aarch64 after u8→u32 widening
    service_addr_ctl(s);
    continuity::service(s);
    service_net_channels(s);

    // 4. Periodic ARP maintenance
    if s.step_count.is_multiple_of(256) {
        step_arp_maintenance(s);
    }

    // 5. TCP timers — wallclock-driven so the 50 ms-tick thresholds
    // hold across schedulers with different `tick_us`.
    step_tcp_timers(s);
    continuity::step(s);
    step_fence_wait(s);

    // Tally idle steps and emit the periodic `[ip] tlm …` line.
    // "Idle" excludes back-pressure steps (so idle + bp + active = dt)
    // and excludes pure-timer steps (DHCP/ARP/TCP timer fired but no
    // data moved), which is what we want for the bottleneck view: the
    // question is whether the data path is starved.
    tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
    // Latch the work signal before `dev_tlm_maybe_emit` zeroes the deltas —
    // read afterwards it compares 0 against a non-zero snapshot and fires
    // WORK_DONE on every cadence step whether or not the step moved data.
    let moved_bytes = s.tlm.bytes_in != rx_pre || s.tlm.bytes_out != tx_pre;
    {
        let sys = &*s.syscalls;
        let scratch_ptr = s.tlm_scratch.as_mut_ptr();
        let scratch_len = s.tlm_scratch.len();
        dev_tlm_maybe_emit(
            sys,
            b"[ip]",
            &mut s.tlm,
            s.step_count,
            IP_TLM_PERIOD,
            scratch_ptr,
            scratch_len,
        );
    }

    // `[ip] hb …` — counters that don't fit dev_tlm_maybe_emit's
    // fixed shape. Same cadence as `[ip] tlm`.
    if s.step_count.is_multiple_of(IP_TLM_PERIOD) {
        let sys = &*s.syscalls;
        let buf = s.tlm_scratch.as_mut_ptr();
        let buf_max = s.tlm_scratch.len();
        let mut pos = 0usize;
        let emit = |bytes: &[u8], pos: &mut usize| {
            let mut k = 0;
            while k < bytes.len() && *pos < buf_max {
                *buf.add(*pos) = bytes[k];
                *pos += 1;
                k += 1;
            }
        };
        emit(b"[ip] hb dupSYN=", &mut pos);
        pos += fmt_u32_dec(s.tcp_dup_syn_rx, buf.add(pos));
        emit(b" adv=", &mut pos);
        pos += fmt_u32_dec(s.adv_rx_frames, buf.add(pos));
        emit(b" pendrx=", &mut pos);
        pos += fmt_u32_dec(s.pend_rx_steps, buf.add(pos));
        emit(b" pendtxq=", &mut pos);
        pos += fmt_u32_dec(s.pend_txq_steps, buf.add(pos));
        emit(b" out=", &mut pos);
        pos += fmt_u32_dec(s.out_items, buf.add(pos));
        emit(b" txcmd=", &mut pos);
        pos += fmt_u32_dec(s.tx_cmd_items, buf.add(pos));
        emit(b" pendcmd=", &mut pos);
        pos += fmt_u32_dec(s.pend_cmd_steps, buf.add(pos));
        dev_log(sys, 3, buf, pos);

        // Ingress refusals and half-open pressure. Separate line: these are
        // lifetime counters, not per-window rates, and are not reset below.
        pos = 0;
        emit(b"[ip] drop cksum=", &mut pos);
        pos += fmt_u32_dec(
            s.drops
                .cksum_tcp
                .wrapping_add(s.drops.cksum_udp)
                .wrapping_add(s.drops.cksum_icmp),
            buf.add(pos),
        );
        emit(b" frag=", &mut pos);
        pos += fmt_u32_dec(s.drops.frag, buf.add(pos));
        emit(b" udplen=", &mut pos);
        pos += fmt_u32_dec(s.drops.udp_len, buf.add(pos));
        emit(b" arp=", &mut pos);
        pos += fmt_u32_dec(
            s.drops.arp_from_ipv4.wrapping_add(s.drops.arp_uncorrelated),
            buf.add(pos),
        );
        emit(b" pinrej=", &mut pos);
        pos += fmt_u32_dec(s.drops.arp_pin_reject, buf.add(pos));
        emit(b" pinreval=", &mut pos);
        pos += fmt_u32_dec(s.drops.arp_pin_revalidate, buf.add(pos));
        emit(b" dhcp=", &mut pos);
        pos += fmt_u32_dec(s.drops.dhcp_uncorrelated, buf.add(pos));
        emit(b" unreach=", &mut pos);
        pos += fmt_u32_dec(s.drops.route_unreachable, buf.add(pos));
        emit(b" fenced=", &mut pos);
        pos += fmt_u32_dec(s.tx_fenced, buf.add(pos));
        emit(b" halfopen=", &mut pos);
        pos += fmt_u32_dec(s.tcp_half_open, buf.add(pos));
        emit(b"/", &mut pos);
        pos += fmt_u32_dec(s.tcp_half_open_max, buf.add(pos));
        emit(b" hosrc=", &mut pos);
        pos += fmt_u32_dec(s.tcp_half_open_src_max, buf.add(pos));
        dev_log(sys, 3, buf, pos);

        // Decision seam, only when it exists.
        if s.pkt_decision != PKT_DECISION_OFF {
            pos = 0;
            emit(b"[ip] pkt held=", &mut pos);
            pos += fmt_u32_dec(s.pkt_held as u32, buf.add(pos));
            emit(b" decided=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.decided, buf.add(pos));
            emit(b" refused=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.hold_refused, buf.add(pos));
            emit(b" expired=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.hold_expired, buf.add(pos));
            emit(b" stale=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.stale_disposition, buf.add(pos));
            emit(b" local=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.local, buf.add(pos));
            emit(b" drop=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.dropped, buf.add(pos));
            emit(b" reject=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.rejected, buf.add(pos));
            emit(b" fwd=", &mut pos);
            pos += fmt_u32_dec(s.pkt_stats.forwarded, buf.add(pos));
            dev_log(sys, 3, buf, pos);
        }

        // SYN-cookie pressure. Its own line: these are lifetime counters and
        // the drop line above has no room left for four more u32 fields.
        // `sent > 0` says the deployment crossed the watermark at all.
        pos = 0;
        emit(b"[ip] cookie sent=", &mut pos);
        pos += fmt_u32_dec(s.tcp_syn_cookie_sent, buf.add(pos));
        emit(b" ok=", &mut pos);
        pos += fmt_u32_dec(s.tcp_syn_cookie_ok, buf.add(pos));
        emit(b" bad=", &mut pos);
        pos += fmt_u32_dec(s.tcp_syn_cookie_bad, buf.add(pos));
        emit(b" optref=", &mut pos);
        pos += fmt_u32_dec(s.tcp_syn_option_refused, buf.add(pos));
        emit(b" horef=", &mut pos);
        pos += fmt_u32_dec(s.tcp_half_open_refused, buf.add(pos));
        emit(b" idlec=", &mut pos);
        pos += fmt_u32_dec(s.tcp_idle_closed, buf.add(pos));
        emit(b" cwexp=", &mut pos);
        pos += fmt_u32_dec(s.tcp_closewait_expired, buf.add(pos));
        dev_log(sys, 3, buf, pos);
        s.adv_rx_frames = 0;
        s.pend_rx_steps = 0;
        s.pend_txq_steps = 0;
        s.out_items = 0;
        s.tx_cmd_items = 0;
        s.pend_cmd_steps = 0;
        s.out_items = 0;
        s.tx_cmd_items = 0;
        s.pend_cmd_steps = 0;
    }

    // §6 work signal: if data moved this step but we didn't take the
    // RunnableBacklog yield above, report WorkDone — keeps the pacer hot for
    // an active data path without an immediate same-module re-step.
    if moved_bytes {
        dev_report_step_effect(&*s.syscalls, step_effect::WORK_DONE);
    }

    // Signal Ready once IP is configured (DHCP bound or static)
    if s.ip_configured && !s.signaled_ready {
        s.signaled_ready = true;
        return 3; // StepOutcome::Ready
    }

    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_in_place_safe"]
pub extern "C" fn module_in_place_safe() -> u32 {
    0
}

// ============================================================================
// Frame Processing
// ============================================================================

/// Read and process all pending RX frames from in_chan.
///
/// The NIC driver writes length-prefixed frames (`[len:u16 LE][frame...]`).
/// We read the 2-byte header first, then exactly `len` bytes so back-to-back
/// frames in the byte-stream channel don't concatenate into one giant "frame".
unsafe fn process_rx_frames(s: &mut IpState) {
    if s.in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    // Drain up to 32 RX frames per IP step. A fast peer can deliver
    // 8-16 ACKs per millisecond on a gigabit link, and the
    // cwnd-growth feedback loop needs each one promptly to keep
    // the segmentation path supplied with credit.
    let mut count = 0;
    while count < 32 {
        // Each iteration may synthesise a control event (SYN →
        // MSG_ACCEPTED, FIN → MSG_CLOSED), so re-check headroom
        // every loop rather than once up-front. The peer's TCP
        // retransmit covers segments dropped while we're paused.
        if NET_OUT_QUEUE_SLOTS - s.pending_net_out_count as usize <= NET_OUT_QUEUE_HEADROOM {
            break;
        }
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }

        let mut hdr = [0u8; 2];
        let hn = (sys.channel_read)(s.in_chan, hdr.as_mut_ptr(), 2);
        if hn < 2 {
            break;
        }
        let frame_len = (hdr[0] as usize) | ((hdr[1] as usize) << 8);
        if frame_len == 0 || frame_len > MAX_FRAME_SIZE {
            break;
        }

        let r = (sys.channel_read)(s.in_chan, s.rx_frame.as_mut_ptr(), frame_len);
        if r <= 0 {
            break;
        }

        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(r as u32);
        process_frame(s, r as usize);
        count += 1;
        s.adv_rx_frames = s.adv_rx_frames.wrapping_add(1);
    }
}

/// Process a single received ethernet frame.
unsafe fn process_frame(s: &mut IpState, len: usize) {
    s.rx_frame_count = s.rx_frame_count.wrapping_add(1);

    let (ethertype, payload_offset) = eth::parse_eth_header(s.rx_frame.as_ptr(), len);

    // EtherType 0x0000 = MAC announcement from cyw43 driver
    if ethertype == 0 {
        if !s.mac_valid && len >= 14 {
            let dst = eth::dst_mac(s.rx_frame.as_ptr());
            // Check that it's a valid unicast MAC (not all zeros)
            if dst[0] & 0x01 == 0 && (dst[0] | dst[1] | dst[2] | dst[3] | dst[4] | dst[5]) != 0 {
                s.mac_addr = dst;
                s.mac_valid = true;
            }
        }
        return;
    }

    // Drivers must announce their MAC explicitly (ethertype=0 frame); we
    // refuse to infer it from inbound traffic, which would let a forged ARP
    // or misconfigured peer drive us to adopt an arbitrary identity.
    if !s.mac_valid {
        return;
    }

    let payload = s.rx_frame.as_ptr().add(payload_offset);
    let payload_len = len - payload_offset;
    s.rx_frame_len = len as u16;
    s.rx_l3_off = payload_offset as u16;

    match ethertype {
        eth::ETHERTYPE_ARP => process_arp(s, payload, payload_len),
        eth::ETHERTYPE_IPV4 => process_ipv4(s, payload, payload_len),
        _ => {}
    }
}

/// Process an ARP packet.
unsafe fn process_arp(s: &mut IpState, data: *const u8, len: usize) {
    let pkt = match arp::parse_arp(data, len) {
        Some(p) => p,
        None => return,
    };
    let arp::ArpPacket {
        opcode,
        sender_ip,
        sender_mac,
        target_ip,
        target_mac,
    } = pkt;

    // Gratuitous-ARP conflict detection: if someone claims ANY of our local
    // addresses from a different MAC, defend by broadcasting a gratuitous
    // reply asserting our MAC for the conflicted address, then notify the
    // consumer via MSG_ERROR. Now checks every configured local address,
    // not just the primary.
    if sender_mac != s.mac_addr && is_armed_addr(s, sender_ip) {
        log_info(s, b"[ip] arp conflict");
        if s.mac_valid {
            send_gratuitous_arp(s, sender_ip);
        }
        net_send_error(s, 0, -1, 0);
        return;
    }

    // A pending resolution is satisfied only by a reply that is genuinely an
    // answer to the question we asked:
    //
    //   * an ARP *Reply* — a request carrying the same sender address is an
    //     unsolicited announcement, not an answer;
    //   * for exactly the address we asked about;
    //   * targeted at one of our local addresses and at our MAC, both in the
    //     ARP payload and in the Ethernet destination.
    //
    // Anything else may still be a legitimate frame on the segment, but it
    // does not get to decide what our outstanding question resolved to.
    let eth_dst = eth::dst_mac(s.rx_frame.as_ptr());
    let correlated_reply = opcode == arp::ARP_REPLY
        && s.arp_pending_state == arp::ARP_PENDING_WAITING
        && s.arp_pending_ip == sender_ip
        && is_local_addr(s, target_ip)
        && target_mac == s.mac_addr
        && eth_dst == s.mac_addr;

    // A MAC change refused by a pin is metered wherever it is observed:
    // an operator reading a cache miss needs to know whether the mapping is
    // simply absent or whether the segment tried to move a pinned one.
    if arp::pin_would_reject(&s.arp_table, sender_ip, sender_mac) {
        s.drops.arp_pin_reject = s.drops.arp_pin_reject.wrapping_add(1);
    }

    if correlated_reply {
        arp::insert(&mut s.arp_table, sender_ip, sender_mac, s.step_count as u16);
        s.arp_pending_state = arp::ARP_PENDING_NONE;
        // A gateway pin is installed only against a mapping this exchange
        // just produced, never against whatever happened to be cached.
        if s.gw_pin_pending && s.gw_pin_ip == sender_ip {
            s.gw_pin_pending = false;
            arp::pin_gateway(&mut s.arp_table, sender_ip);
        }
        // A handshake blocked on this resolution ships now rather than
        // waiting for the next timer tick — the whole stall is the ARP round
        // trip, and the reply has just arrived.
        retry_unsent_handshake(s, sender_ip);
    } else {
        // Uncorrelated ARP may still refresh an unchanged mapping — that is
        // the same authority ordinary IPv4 traffic has, and no more.
        if !arp::refresh_same_mac(&mut s.arp_table, sender_ip, sender_mac) {
            s.drops.arp_uncorrelated = s.drops.arp_uncorrelated.wrapping_add(1);
        }
    }

    // Reply to ARP requests for ANY of our local addresses with the single
    // GEM MAC — ordinary multi-homing on one interface, no per-address MAC.
    // The reply's sender-protocol-address is the requested address, so each
    // secondary answers as itself.
    if opcode == arp::ARP_REQUEST && s.mac_valid && is_armed_addr(s, target_ip) {
        let frame_len = arp::build_arp(
            s.tx_frame.as_mut_ptr(),
            arp::ARP_REPLY,
            &s.mac_addr,
            target_ip,
            &sender_mac,
            sender_ip,
        );
        send_frame(s, s.tx_frame.as_ptr(), frame_len);
    }
}

/// Ship any SYN or SYN-ACK that was held back because the peer's MAC was
/// unresolved and `resolved_ip` is now its next hop. `snd_nxt == iss` is the
/// marker: `send_tcp_control` credits the sequence byte only once the frame
/// is queued, so a connection still sitting at its ISS never reached the wire.
unsafe fn retry_unsent_handshake(s: &mut IpState, resolved_ip: u32) {
    // Walk the waiting list once; an entry that is no longer waiting on
    // a neighbour — sent, or past its handshake — leaves the list, and one
    // waiting on a different neighbour stays.
    let n = s.arp_wait_len as usize;
    let mut kept = 0usize;
    let mut k = 0;
    while k < n {
        let i = s.arp_wait[k] as usize;
        let (state, unsent, remote_ip) = {
            let conn = &*s.tcp_conns.as_ptr().add(i);
            (conn.state, conn.snd_nxt == conn.iss, conn.remote_ip)
        };
        let waiting = unsent
            && matches!(state, tcp::TcpState::SynReceived | tcp::TcpState::SynSent);
        if !waiting {
            k += 1;
            continue;
        }
        if next_hop(s, remote_ip) == Some(resolved_ip) {
            let sent = match state {
                tcp::TcpState::SynReceived => send_tcp_control(s, i, tcp::SYN | tcp::ACK, true),
                _ => send_tcp_control(s, i, tcp::SYN, true),
            };
            if sent {
                k += 1;
                continue;
            }
        }
        s.arp_wait[kept] = i as u32;
        kept += 1;
        k += 1;
    }
    s.arp_wait_len = kept as u8;
}

/// Remember that connection `idx`'s handshake is waiting on a neighbour.
unsafe fn arp_wait_push(s: &mut IpState, idx: usize) {
    let n = s.arp_wait_len as usize;
    let mut k = 0;
    while k < n {
        if s.arp_wait[k] as usize == idx {
            return;
        }
        k += 1;
    }
    if n >= ARP_WAIT_MAX {
        s.arp_wait_overflow = s.arp_wait_overflow.wrapping_add(1);
        return;
    }
    s.arp_wait[n] = idx as u32;
    s.arp_wait_len = (n + 1) as u8;
}

/// Process an IPv4 packet.
unsafe fn process_ipv4(s: &mut IpState, data: *const u8, len: usize) {
    let ip_hdr = match ipv4::parse_ipv4(data, len) {
        Some(h) => h,
        None => return,
    };

    // No reassembler exists, so a fragment is refused rather than handed to
    // L4 as though it were a whole packet. MF set (0x2000) or a nonzero
    // offset (low 13 bits) both qualify; DF and the reserved bit do not.
    if (ip_hdr.flags_frag & 0x2000) != 0 || (ip_hdr.flags_frag & 0x1FFF) != 0 {
        s.drops.frag = s.drops.frag.wrapping_add(1);
        return;
    }

    // Refresh — never create — the sender's ARP mapping from ordinary IPv4
    // traffic. A same-MAC refresh keeps a busy peer's entry alive without
    // letting unauthenticated L3 traffic install or move a mapping; new and
    // changed mappings are learnt only from a correlated ARP reply.
    if ip_hdr.src_ip != 0 && ip_hdr.src_ip != 0xFFFFFFFF {
        let src_mac = eth::src_mac(s.rx_frame.as_ptr());
        if (src_mac[0] | src_mac[1] | src_mac[2] | src_mac[3] | src_mac[4] | src_mac[5]) != 0
            && !arp::refresh_same_mac(&mut s.arp_table, ip_hdr.src_ip, src_mac)
        {
            s.drops.arp_from_ipv4 = s.drops.arp_from_ipv4.wrapping_add(1);
        }
    }

    // Destination demux: which of our local addresses (if any) is this for?
    // Replaces the single `dst == local_ip` compare with a table lookup.
    // `None` = not a unicast local address; still accept the
    // (subnet-)broadcast forms as before.
    let dst_slot = local_slot_for_dst(s, ip_hdr.dst_ip);
    if s.local_ip != 0 && dst_slot.is_none() && ip_hdr.dst_ip != 0xFFFFFFFF {
        // Not for us (also check subnet broadcast — one segment in v1).
        if s.netmask != 0 {
            let subnet_broadcast = (s.local_ip & s.netmask) | (!s.netmask);
            if ip_hdr.dst_ip != subnet_broadcast {
                return;
            }
        } else {
            return;
        }
    }
    // Broadcast / not-yet-configured traffic answers from the primary slot.
    let local_slot = dst_slot.unwrap_or(0);
    // Reply source address: the exact address a unicast was sent to (so a
    // ping/RST to a secondary answers as that secondary); primary otherwise.
    let reply_src = match dst_slot {
        Some(_) => ip_hdr.dst_ip,
        None => s.local_ip,
    };

    let proto_data = data.add(ip_hdr.header_len);
    let proto_len = ip_hdr.total_len as usize - ip_hdr.header_len;

    // The decision seam sits exactly here: after the packet is known to be
    // whole, checksummed at L3 and addressed to us, and before any
    // transport state can be created for it. The stack's own control
    // traffic stays local — ICMP, and the DHCP replies that give the stack
    // its address. Neither is a flow anyone directs, and a director that
    // could hold the lease exchange would decide whether the host exists on
    // the network at all.
    if s.pkt_decision == PKT_DECISION_PRE_TRANSPORT
        && !stack_own_traffic(&ip_hdr, proto_data, proto_len)
    {
        seam_intake(s, &ip_hdr, proto_data, proto_len, local_slot);
        return;
    }

    dispatch_l4(s, &ip_hdr, proto_data, proto_len, local_slot, reply_src);
}

/// Traffic the stack answers for itself, never described to a director:
/// ICMP, and DHCP server-to-client datagrams (the lease exchange).
unsafe fn stack_own_traffic(ip_hdr: &ipv4::Ipv4Header, proto_data: *const u8, proto_len: usize) -> bool {
    match ip_hdr.protocol {
        ipv4::PROTO_ICMP => true,
        ipv4::PROTO_UDP => match udp::parse_udp(proto_data, proto_len) {
            Some(h) => {
                h.src_port == dhcp::DHCP_SERVER_PORT && h.dst_port == dhcp::DHCP_CLIENT_PORT
            }
            None => false,
        },
        _ => false,
    }
}

/// Hand a validated IPv4 packet to its transport.
unsafe fn dispatch_l4(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    proto_data: *const u8,
    proto_len: usize,
    local_slot: u16,
    reply_src: u32,
) {
    match ip_hdr.protocol {
        ipv4::PROTO_ICMP => process_icmp(s, ip_hdr, proto_data, proto_len, reply_src),
        ipv4::PROTO_TCP => process_tcp_segment(s, ip_hdr, proto_data, proto_len, local_slot),
        ipv4::PROTO_UDP => process_udp_packet(s, ip_hdr, proto_data, proto_len, local_slot),
        _ => {}
    }
}

// ============================================================================
// Pre-transport decision seam
// ============================================================================
//
// `packet_decision = pre_transport`: every whole, locally-addressed IPv4
// packet is described to a director and held until the director settles it.
// The buffer has one owner at a time — this module until the disposition,
// then the transport (LOCAL), nobody (DROP/REJECT), or the forward port's
// consumer (TUNNEL/DSR). A hold is bounded twice: `MAX_PACKET_HOLD` slots,
// and `packet_hold_ms` per slot.

/// Transport header verified? What the L4 parse says about a packet at
/// intake.
struct L4Facts {
    src_port: u16,
    dst_port: u16,
    csum_ok: bool,
    /// The packet failed L4 validation and must not reach the seam.
    refused: bool,
}

/// Parse and checksum the transport header once, at the seam. A packet
/// that fails here is dropped and counted exactly as it would be on the
/// ordinary path — the director never sees a corrupt segment.
unsafe fn seam_l4_facts(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    proto_data: *const u8,
    proto_len: usize,
) -> L4Facts {
    let mut f = L4Facts {
        src_port: 0,
        dst_port: 0,
        csum_ok: false,
        refused: false,
    };
    match ip_hdr.protocol {
        ipv4::PROTO_TCP => {
            let Some(h) = tcp::parse_tcp(proto_data, proto_len) else {
                f.refused = true;
                return f;
            };
            if !ipv4::verify_transport_checksum(
                ip_hdr.src_ip,
                ip_hdr.dst_ip,
                ipv4::PROTO_TCP,
                proto_data,
                proto_len,
            ) {
                s.drops.cksum_tcp = s.drops.cksum_tcp.wrapping_add(1);
                f.refused = true;
                return f;
            }
            f.src_port = h.src_port;
            f.dst_port = h.dst_port;
            f.csum_ok = true;
        }
        ipv4::PROTO_UDP => {
            let Some(h) = udp::parse_udp(proto_data, proto_len) else {
                f.refused = true;
                return f;
            };
            if h.length as usize != proto_len {
                s.drops.udp_len = s.drops.udp_len.wrapping_add(1);
                f.refused = true;
                return f;
            }
            if udp::checksum_field(proto_data) != 0 {
                if !ipv4::verify_transport_checksum(
                    ip_hdr.src_ip,
                    ip_hdr.dst_ip,
                    ipv4::PROTO_UDP,
                    proto_data,
                    proto_len,
                ) {
                    s.drops.cksum_udp = s.drops.cksum_udp.wrapping_add(1);
                    f.refused = true;
                    return f;
                }
                f.csum_ok = true;
            }
            f.src_port = h.src_port;
            f.dst_port = h.dst_port;
        }
        _ => {}
    }
    f
}

/// A free hold slot, or `None` when every one is taken.
unsafe fn hold_alloc(s: &mut IpState) -> Option<usize> {
    let mut i = 0;
    while i < MAX_PACKET_HOLD {
        if (*s.pkt_hold.as_ptr().add(i)).in_use == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Release a hold slot.
unsafe fn hold_free(s: &mut IpState, slot: usize) {
    let h = &mut *s.pkt_hold.as_mut_ptr().add(slot);
    if h.in_use != 0 {
        h.in_use = 0;
        h.pending_fwd[0] = 0xFF;
        s.pkt_held = s.pkt_held.saturating_sub(1);
    }
}

/// Every hold slot has to be nameable in the slot field the contract
/// declares.
const _: () = assert!(MAX_PACKET_HOLD <= (1usize << abi::contracts::net::packet::PKT_SLOT_BITS));

/// `pkt_id` for a slot under its current generation.
fn hold_id(slot: usize, gen: u32) -> u32 {
    abi::contracts::net::packet::pkt_id(slot, gen)
}

/// Move to the generation the next hold is stamped with.
///
/// Wraps to one rather than zero: a `pkt_id` of all zeroes is what an
/// uninitialised field looks like, and it names no hold at any slot.
/// Wrapping at all is what a late disposition would have to outlive to
/// match a slot since reused, which is why the generation gets every bit
/// the slot does not need.
fn hold_bump_gen(s: &mut IpState) {
    s.pkt_gen = if s.pkt_gen + 1 >= abi::contracts::net::packet::PKT_GEN_MODULUS {
        1
    } else {
        s.pkt_gen + 1
    };
}

/// The live slot a `pkt_id` names, or `None` when it names a released or
/// reused one.
unsafe fn hold_lookup(s: &IpState, pkt_id: u32) -> Option<usize> {
    let slot = abi::contracts::net::packet::pkt_slot(pkt_id);
    let gen = abi::contracts::net::packet::pkt_generation(pkt_id);
    if slot >= MAX_PACKET_HOLD {
        return None;
    }
    let h = &*s.pkt_hold.as_ptr().add(slot);
    if h.in_use != 0 && h.gen == gen {
        Some(slot)
    } else {
        None
    }
}

/// Describe the packet in `rx_frame` to the director and hold it.
unsafe fn seam_intake(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    proto_data: *const u8,
    proto_len: usize,
    local_slot: u16,
) {
    use abi::contracts::net::packet as pkt;

    let facts = seam_l4_facts(s, ip_hdr, proto_data, proto_len);
    if facts.refused {
        return;
    }

    let Some(slot) = hold_alloc(s) else {
        s.pkt_stats.hold_refused = s.pkt_stats.hold_refused.wrapping_add(1);
        return;
    };

    let sys = &*s.syscalls;
    let gen = s.pkt_gen;
    let id = hold_id(slot, gen);
    let frame_len = s.rx_frame_len as usize;
    let l3_off = s.rx_l3_off as usize;
    let l4_off = l3_off + ip_hdr.header_len;
    let ts_us = dev_micros(sys);

    let mut rec = [0u8; pkt::DECIDE_LEN];
    rec[0..4].copy_from_slice(&id.to_le_bytes());
    rec[4] = pkt::AF_INET;
    rec[5] = ip_hdr.protocol;
    rec[6..10].copy_from_slice(&ip_hdr.src_ip.to_be_bytes());
    rec[10..14].copy_from_slice(&ip_hdr.dst_ip.to_be_bytes());
    rec[14..16].copy_from_slice(&facts.src_port.to_le_bytes());
    rec[16..18].copy_from_slice(&facts.dst_port.to_le_bytes());
    rec[18] = 0; // iface: this module drives one
    rec[19] = 0; // rx_queue: one queue on every current NIC
    rec[20] = pkt::RX_FLAG_HAS_TIMESTAMP
        | if facts.csum_ok {
            pkt::RX_FLAG_CSUM_OK
        } else {
            0
        };
    rec[21] = 0; // frag: fragments never reach the seam
    rec[22..30].copy_from_slice(&ts_us.to_le_bytes());
    rec[30..32].copy_from_slice(&(frame_len as u16).to_le_bytes());
    rec[32..34].copy_from_slice(&(l4_off as u16).to_le_bytes());

    let mut scratch = [0u8; NET_FRAME_HDR + pkt::DECIDE_LEN];
    if ip_net_write_frame(
        sys,
        s.pkt_out_chan,
        pkt::MSG_PKT_DECIDE,
        rec.as_ptr(),
        rec.len(),
        scratch.as_mut_ptr(),
    ) != 0
    {
        // No room for the record: refuse the packet, as a full ring
        // refuses anywhere else. The peer's retransmit covers it.
        s.pkt_stats.hold_refused = s.pkt_stats.hold_refused.wrapping_add(1);
        return;
    }

    let now_ms = dev_millis(sys);
    let hold_ms = s.pkt_hold_ms;
    let h = &mut *s.pkt_hold.as_mut_ptr().add(slot);
    h.in_use = 1;
    h.local_slot = local_slot;
    h.gen = gen;
    h.len = frame_len as u16;
    h.l3_off = l3_off as u16;
    h.deadline_ms = (now_ms as u32).wrapping_add(u32::from(hold_ms));
    h.pending_fwd[0] = 0xFF;
    core::ptr::copy_nonoverlapping(s.rx_frame.as_ptr(), h.frame.as_mut_ptr(), frame_len);
    hold_bump_gen(s);
    s.pkt_held += 1;
    s.pkt_stats.decided = s.pkt_stats.decided.wrapping_add(1);
}

/// Deliver a held packet to its transport — the LOCAL disposition.
///
/// The held frame becomes the current frame first: transport paths that
/// answer the sender read its MAC from `rx_frame`, and the L4 pointers
/// handed on are into `rx_frame` so nothing aliases the hold slot.
unsafe fn deliver_held(s: &mut IpState, slot: usize) {
    let (len, l3_off, local_slot) = {
        let h = &*s.pkt_hold.as_ptr().add(slot);
        core::ptr::copy_nonoverlapping(h.frame.as_ptr(), s.rx_frame.as_mut_ptr(), h.len as usize);
        (h.len as usize, h.l3_off as usize, h.local_slot)
    };
    s.rx_frame_len = len as u16;
    s.rx_l3_off = l3_off as u16;
    let l3 = s.rx_frame.as_ptr().add(l3_off);
    let Some(ip_hdr) = ipv4::parse_ipv4(l3, len - l3_off) else {
        return;
    };
    let proto_data = l3.add(ip_hdr.header_len);
    let proto_len = ip_hdr.total_len as usize - ip_hdr.header_len;
    // Only ICMP consults `reply_src`, and ICMP never reaches the seam.
    dispatch_l4(s, &ip_hdr, proto_data, proto_len, local_slot, ip_hdr.dst_ip);
}

/// Answer a held packet's sender — the REJECT disposition — then release.
unsafe fn reject_held(s: &mut IpState, slot: usize, response: u8) {
    use abi::contracts::net::packet as pkt;
    let (len, l3_off) = {
        let h = &*s.pkt_hold.as_ptr().add(slot);
        // Replies resolve the sender's MAC from the frame they answer.
        core::ptr::copy_nonoverlapping(h.frame.as_ptr(), s.rx_frame.as_mut_ptr(), h.len as usize);
        (h.len as usize, h.l3_off as usize)
    };
    let l3 = s.rx_frame.as_ptr().add(l3_off);
    let l3_len = len - l3_off;
    let Some(ip_hdr) = ipv4::parse_ipv4(l3, l3_len) else {
        return;
    };
    let proto_data = l3.add(ip_hdr.header_len);
    let proto_len = ip_hdr.total_len as usize - ip_hdr.header_len;
    let reply_src = ip_hdr.dst_ip;
    match response {
        pkt::reject::TCP_RST if ip_hdr.protocol == ipv4::PROTO_TCP => {
            let Some(tcp_hdr) = tcp::parse_tcp(proto_data, proto_len) else {
                return;
            };
            // RFC 9293 §3.10.7.1: an RST is never answered with an RST,
            // and without an ACK to mirror the RST acknowledges the whole
            // of the offending segment's sequence space.
            if tcp_hdr.flags & tcp::RST != 0 {
                return;
            }
            let (seq, ack, flags) = if (tcp_hdr.flags & tcp::ACK) != 0 {
                (tcp_hdr.ack_num, 0u32, tcp::RST)
            } else {
                let ack = tcp_hdr
                    .seq_num
                    .wrapping_add(tcp::seg_len(tcp_hdr.flags, tcp_hdr.payload_len));
                (0u32, ack, tcp::RST | tcp::ACK)
            };
            let src_mac = eth::src_mac(s.rx_frame.as_ptr());
            send_tcp_rst_to(
                s,
                ip_hdr.src_ip,
                tcp_hdr.src_port,
                tcp_hdr.dst_port,
                seq,
                ack,
                flags,
                reply_src,
                &src_mac,
            );
        }
        pkt::reject::ICMP_UNREACHABLE => {
            send_icmp_unreachable(s, &ip_hdr, l3, l3_len, reply_src);
        }
        _ => {}
    }
}

/// ICMP destination unreachable, port unreachable (RFC 792): the original
/// IPv4 header plus eight bytes of its payload, back to the sender.
unsafe fn send_icmp_unreachable(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    l3: *const u8,
    l3_len: usize,
    reply_src: u32,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }
    let quoted = (ip_hdr.header_len + 8).min(l3_len);
    let icmp_len = icmp::ICMP_HEADER_LEN + quoted;
    let icmp_start = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    *icmp_start = 3; // destination unreachable
    *icmp_start.add(1) = 3; // port unreachable
    *icmp_start.add(2) = 0;
    *icmp_start.add(3) = 0;
    *icmp_start.add(4) = 0;
    *icmp_start.add(5) = 0;
    *icmp_start.add(6) = 0;
    *icmp_start.add(7) = 0;
    core::ptr::copy_nonoverlapping(l3, icmp_start.add(icmp::ICMP_HEADER_LEN), quoted);
    let csum = ipv4::checksum(icmp_start, icmp_len);
    *icmp_start.add(2) = (csum >> 8) as u8;
    *icmp_start.add(3) = csum as u8;

    let src_mac = eth::src_mac(s.rx_frame.as_ptr());
    let ip_total = (ipv4::IPV4_HEADER_LEN + icmp_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_ICMP,
        reply_src,
        ip_hdr.src_ip,
        s.ip_id,
    );
    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &src_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );
    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// Try to write a held packet's forward record. `true` when it went, and
/// the slot is released; `false` leaves the slot held with the disposition
/// pending for the next step.
unsafe fn forward_held(s: &mut IpState, slot: usize) -> bool {
    use abi::contracts::net::packet as pkt;
    let sys = &*s.syscalls;
    let h = &*s.pkt_hold.as_ptr().add(slot);
    let len = h.len as usize;
    let payload_len = 4 + 1 + pkt::DISP_ARGS_LEN + len;
    let total = NET_FRAME_HDR + payload_len;
    if total > s.net_scratch.len() {
        return true; // cannot ever fit: release rather than hold forever
    }
    let scratch = s.net_scratch.as_mut_ptr();
    *scratch = pkt::MSG_PKT_FORWARD;
    let pl = (payload_len as u16).to_le_bytes();
    *scratch.add(1) = pl[0];
    *scratch.add(2) = pl[1];
    let id = hold_id(slot, h.gen).to_le_bytes();
    core::ptr::copy_nonoverlapping(id.as_ptr(), scratch.add(NET_FRAME_HDR), 4);
    core::ptr::copy_nonoverlapping(
        h.pending_fwd.as_ptr(),
        scratch.add(NET_FRAME_HDR + 4),
        1 + pkt::DISP_ARGS_LEN,
    );
    core::ptr::copy_nonoverlapping(
        h.frame.as_ptr(),
        scratch.add(NET_FRAME_HDR + 4 + 1 + pkt::DISP_ARGS_LEN),
        len,
    );
    let n = (sys.channel_write)(s.pkt_fwd_chan, scratch, total);
    if n == total as i32 {
        s.pkt_stats.forwarded = s.pkt_stats.forwarded.wrapping_add(1);
        true
    } else {
        false
    }
}

/// Act on one disposition.
unsafe fn dispose_held(s: &mut IpState, pkt_id: u32, disp: u8, args: &[u8; 6]) {
    use abi::contracts::net::packet as pkt;
    let Some(slot) = hold_lookup(s, pkt_id) else {
        s.pkt_stats.stale_disposition = s.pkt_stats.stale_disposition.wrapping_add(1);
        return;
    };
    // A slot with a forward pending has been disposed already.
    if (*s.pkt_hold.as_ptr().add(slot)).pending_fwd[0] != 0xFF {
        s.pkt_stats.stale_disposition = s.pkt_stats.stale_disposition.wrapping_add(1);
        return;
    }
    match disp {
        pkt::disposition::LOCAL => {
            s.pkt_stats.local = s.pkt_stats.local.wrapping_add(1);
            deliver_held(s, slot);
            hold_free(s, slot);
        }
        pkt::disposition::DROP => {
            s.pkt_stats.dropped = s.pkt_stats.dropped.wrapping_add(1);
            hold_free(s, slot);
        }
        pkt::disposition::REJECT => {
            s.pkt_stats.rejected = s.pkt_stats.rejected.wrapping_add(1);
            reject_held(s, slot, args[1]);
            hold_free(s, slot);
        }
        pkt::disposition::TUNNEL | pkt::disposition::DSR => {
            if s.pkt_fwd_chan < 0 {
                s.pkt_stats.fwd_unwired = s.pkt_stats.fwd_unwired.wrapping_add(1);
                hold_free(s, slot);
                return;
            }
            {
                let h = &mut *s.pkt_hold.as_mut_ptr().add(slot);
                h.pending_fwd[0] = disp;
                h.pending_fwd[1..7].copy_from_slice(args);
            }
            if forward_held(s, slot) {
                hold_free(s, slot);
            }
        }
        _ => {
            // An unknown disposition is a protocol error; the packet is
            // released as dropped rather than held to its deadline.
            s.pkt_stats.dropped = s.pkt_stats.dropped.wrapping_add(1);
            hold_free(s, slot);
        }
    }
}

/// Hold a second copy of a held packet under a new id.
unsafe fn clone_held(s: &mut IpState, pkt_id: u32) {
    use abi::contracts::net::packet as pkt;
    let sys = &*s.syscalls;
    let clone_id = match hold_lookup(s, pkt_id) {
        None => {
            s.pkt_stats.stale_disposition = s.pkt_stats.stale_disposition.wrapping_add(1);
            pkt::PKT_ID_NONE
        }
        Some(src) => match hold_alloc(s) {
            None => {
                s.pkt_stats.clone_refused = s.pkt_stats.clone_refused.wrapping_add(1);
                pkt::PKT_ID_NONE
            }
            Some(dst) => {
                let gen = s.pkt_gen;
                let from = s.pkt_hold.as_ptr().add(src);
                let to = s.pkt_hold.as_mut_ptr().add(dst);
                core::ptr::copy_nonoverlapping(from, to, 1);
                (*to).gen = gen;
                (*to).pending_fwd[0] = 0xFF;
                hold_bump_gen(s);
                s.pkt_held += 1;
                s.pkt_stats.cloned = s.pkt_stats.cloned.wrapping_add(1);
                hold_id(dst, gen)
            }
        },
    };
    let mut rec = [0u8; 8];
    rec[0..4].copy_from_slice(&pkt_id.to_le_bytes());
    rec[4..8].copy_from_slice(&clone_id.to_le_bytes());
    let mut scratch = [0u8; NET_FRAME_HDR + 8];
    let _ = ip_net_write_frame(
        sys,
        s.pkt_out_chan,
        pkt::MSG_PKT_CLONED,
        rec.as_ptr(),
        rec.len(),
        scratch.as_mut_ptr(),
    );
}

/// Service the director's port: retry pending forwards, then read
/// dispositions and clone requests.
unsafe fn service_packet_in(s: &mut IpState) {
    use abi::contracts::net::packet as pkt;
    if s.pkt_decision == PKT_DECISION_OFF || s.pkt_in_chan < 0 {
        return;
    }
    if s.pkt_held > 0 && s.pkt_fwd_chan >= 0 {
        let mut i = 0;
        while i < MAX_PACKET_HOLD {
            let h = &*s.pkt_hold.as_ptr().add(i);
            if h.in_use != 0 && h.pending_fwd[0] != 0xFF && forward_held(s, i) {
                hold_free(s, i);
            }
            i += 1;
        }
    }
    let sys = &*s.syscalls;
    let mut budget = MAX_PACKET_HOLD * 2;
    while budget > 0 {
        budget -= 1;
        let poll = (sys.channel_poll)(s.pkt_in_chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let mut buf = [0u8; 16];
        let (msg, plen) = ip_net_read_frame(sys, s.pkt_in_chan, buf.as_mut_ptr(), buf.len());
        let plen = plen as usize;
        match msg {
            pkt::CMD_PKT_DISPOSE if plen >= 5 => {
                let id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let mut args = [0u8; 6];
                let n = (plen - 5).min(6);
                args[..n].copy_from_slice(&buf[5..5 + n]);
                dispose_held(s, id, buf[4], &args);
            }
            pkt::CMD_PKT_CLONE if plen >= 4 => {
                let id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                clone_held(s, id);
            }
            0 => break,
            _ => {}
        }
    }
}

/// Release every hold past its deadline and tell the director.
unsafe fn expire_held(s: &mut IpState) {
    use abi::contracts::net::packet as pkt;
    if s.pkt_held == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let now = dev_millis(sys) as u32;
    let mut i = 0;
    while i < MAX_PACKET_HOLD {
        let (live, gen, deadline) = {
            let h = &*s.pkt_hold.as_ptr().add(i);
            (h.in_use != 0, h.gen, h.deadline_ms)
        };
        // At or past the deadline, wrapping: the hold is milliseconds, the
        // counter is days.
        if live && now.wrapping_sub(deadline) < 0x8000_0000 {
            s.pkt_stats.hold_expired = s.pkt_stats.hold_expired.wrapping_add(1);
            let id = hold_id(i, gen).to_le_bytes();
            let mut scratch = [0u8; NET_FRAME_HDR + 4];
            let _ = ip_net_write_frame(
                sys,
                s.pkt_out_chan,
                pkt::MSG_PKT_EXPIRED,
                id.as_ptr(),
                4,
                scratch.as_mut_ptr(),
            );
            hold_free(s, i);
        }
        i += 1;
    }
}

/// Process ICMP packet (echo request → reply).
unsafe fn process_icmp(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
    reply_src: u32,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }

    // The reply is a copy of the request, so the request's length bounds the
    // write into `tx_frame`. Refuse before `handle_icmp` copies.
    if len > MAX_ICMP_TX_LEN {
        return;
    }

    // Verify the ICMP checksum before generating any reply. An echo reply is
    // an amplification surface: a corrupt request must not produce a frame.
    if ipv4::checksum(data, len) != 0 {
        s.drops.cksum_icmp = s.drops.cksum_icmp.wrapping_add(1);
        return;
    }

    // Build reply in tx_frame (after eth + ip headers)
    let icmp_dst = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    let reply_len = icmp::handle_icmp(data, len, icmp_dst);
    if reply_len == 0 {
        return;
    }

    // Resolve destination MAC (use source of incoming frame)
    let src_mac = eth::src_mac(s.rx_frame.as_ptr());

    // Build IPv4 header
    let ip_total = (ipv4::IPV4_HEADER_LEN + reply_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_ICMP,
        reply_src,
        ip_hdr.src_ip,
        s.ip_id,
    );

    // Build ethernet header
    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &src_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    let total_len = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total_len);
}

/// Process incoming UDP packet.
unsafe fn process_udp_packet(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
    local_slot: u16,
) {
    let udp_hdr = match udp::parse_udp(data, len) {
        Some(h) => h,
        None => return,
    };

    // The datagram must fill the (non-fragmented) IPv4 payload exactly. A
    // shorter UDP length would leave trailing bytes whose meaning is decided
    // by whichever layer looks next; no padding profile is supported.
    if udp_hdr.length as usize != len {
        s.drops.udp_len = s.drops.udp_len.wrapping_add(1);
        return;
    }

    // Verify the checksum before demultiplex or any state lookup. For IPv4
    // UDP a zero checksum means "not supplied" (RFC 768) and is accepted;
    // every nonzero value is verified, including the 0xffff a transmitter
    // sends in place of a computed zero.
    if udp::checksum_field(data) != 0
        && !ipv4::verify_transport_checksum(
            ip_hdr.src_ip,
            ip_hdr.dst_ip,
            ipv4::PROTO_UDP,
            data,
            len,
        )
    {
        s.drops.cksum_udp = s.drops.cksum_udp.wrapping_add(1);
        return;
    }

    // Check for DHCP reply
    if udp_hdr.dst_port == dhcp::DHCP_CLIENT_PORT && udp_hdr.src_port == dhcp::DHCP_SERVER_PORT {
        let dhcp_data = data.add(udp_hdr.payload_offset);
        process_dhcp_reply(s, dhcp_data, udp_hdr.payload_len);
        return;
    }

    // Deliver UDP data to the matching datagram endpoint. All UDP consumers
    // now speak datagram (see modules/sdk/contracts/net/datagram.rs) and
    // receive source addressing via MSG_DG_RX_FROM. Bind admission: a
    // wildcard datagram endpoint serves slot 0 and unowned secondaries, but
    // an OWNED secondary is served only by an endpoint bound to it (an
    // owner-stamped DG bind). `dst_owned` is always false with no owned
    // secondary configured, so this collapses to a plain wildcard match.
    let dst_owned = slot_is_owned(s, local_slot);
    let mut i = 0;
    while i < MAX_DG_ENDPOINTS {
        let conn = &*s.tcp_conns.as_ptr().add(i);
        if conn.is_datagram
            && conn.state == tcp::TcpState::Listen
            && conn.local_port == udp_hdr.dst_port
            && (conn.local_slot == local_slot || (conn.local_slot == LOCAL_SLOT_ANY && !dst_owned))
        {
            let payload = data.add(udp_hdr.payload_offset);
            dg_send_rx_from_v4(
                s,
                i as u8,
                ip_hdr.src_ip,
                udp_hdr.src_port,
                payload,
                udp_hdr.payload_len,
            );
            return;
        }
        i += 1;
    }
}

/// Process incoming TCP segment.
unsafe fn process_tcp_segment(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
    local_slot: u16,
) {
    let tcp_hdr = match tcp::parse_tcp(data, len) {
        Some(h) => h,
        None => return,
    };

    // Verify the pseudo-header checksum before demultiplex or state lookup.
    // Every branch below this point can change connection state or emit a
    // frame, so a corrupt segment must not reach any of them.
    if !ipv4::verify_transport_checksum(ip_hdr.src_ip, ip_hdr.dst_ip, ipv4::PROTO_TCP, data, len) {
        s.drops.cksum_tcp = s.drops.cksum_tcp.wrapping_add(1);
        return;
    }

    // Find matching connection. The local-address slot is the fourth axis:
    // the same 4-tuple reached at two local addresses is two distinct
    // conns.
    let conn_idx = find_conn_indexed(
        s,
        ip_hdr.src_ip,
        tcp_hdr.src_port,
        tcp_hdr.dst_port,
        local_slot,
    );

    let conn_idx = match conn_idx {
        Some(i) => i,
        None => {
            // No established connection — accept SYN on a listening socket.
            // Allocate a fresh slot for the accepted connection (BSD-accept
            // semantics): the listener stays in Listen state so it can
            // serve the next SYN. Only accept once the interface is
            // configured; otherwise we'd consume a slot but couldn't send
            // SYN-ACK.
            if (tcp_hdr.flags & tcp::SYN) != 0
                && (tcp_hdr.flags & tcp::ACK) == 0
                && s.mac_valid
                && s.local_ip != 0
            {
                let dst_owned = slot_is_owned(s, local_slot);
                if let Some(li) = find_listener_indexed(s, tcp_hdr.dst_port, local_slot, dst_owned)
                {
                    // A connection cannot be opened without an ISN secret:
                    // a predictable ISS is an off-path injection surface, so
                    // the SYN is dropped and the client retransmits.
                    if !ensure_isn_secret(s) {
                        return;
                    }
                    // Half-open pressure decides whether this SYN costs a
                    // slot. The gauge is maintained at every enter and
                    // leave (`conn_index_insert`, `conn_leave_half_open`,
                    // `conn_reset`), so it is current here.
                    let half_open = s.tcp_half_open;
                    if half_open >= u32::from(tcp::SYN_COOKIE_WATERMARK) {
                        let listener_port = (*s.tcp_conns.as_ptr().add(li)).local_port;
                        let local_src = local_ip_for_slot(s, local_slot);
                        if !tcp::cookie_mode_admissible(&tcp_hdr) {
                            // A cookie carries no option state, so a SYN that
                            // negotiates one cannot be answered from it.
                            // Refuse to engage: drop, and the client
                            // retransmits into whatever capacity frees up.
                            s.tcp_syn_option_refused = s.tcp_syn_option_refused.wrapping_add(1);
                            return;
                        }
                        let epoch = cookie_epoch(s);
                        let cookie = compute_syn_cookie(
                            s,
                            local_src,
                            listener_port,
                            ip_hdr.src_ip,
                            tcp_hdr.src_port,
                            epoch,
                        );
                        send_syn_ack_cookie(
                            s,
                            ip_hdr.src_ip,
                            tcp_hdr.src_port,
                            listener_port,
                            local_src,
                            cookie,
                            tcp_hdr.seq_num.wrapping_add(1),
                        );
                        s.tcp_syn_cookie_sent = s.tcp_syn_cookie_sent.wrapping_add(1);
                        return;
                    }
                    let accept_idx: i32 = match alloc_free_slot(s) {
                        Some(i) => i as i32,
                        None => -1,
                    };
                    if accept_idx < 0 {
                        // No free slot — drop the SYN silently and let
                        // the client retransmit.
                        s.tcp_half_open_refused = s.tcp_half_open_refused.wrapping_add(1);
                        return;
                    }
                    let idx = accept_idx as usize;
                    let listener_port = (*s.tcp_conns.as_ptr().add(li)).local_port;
                    let iss = compute_iss(
                        s,
                        local_ip_for_slot(s, local_slot),
                        listener_port,
                        ip_hdr.src_ip,
                        tcp_hdr.src_port,
                    );
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(idx);
                    *conn = tcp::TcpConn::new();
                    conn.local_port = listener_port;
                    // Latch the local address this SYN arrived at so replies
                    // source from it and the demux axis distinguishes it.
                    conn.local_slot = local_slot;
                    conn.remote_ip = ip_hdr.src_ip;
                    conn.remote_port = tcp_hdr.src_port;
                    conn.iss = iss;
                    conn.snd_nxt = iss;
                    conn.snd_una = iss;
                    conn.rcv_nxt = tcp_hdr.seq_num.wrapping_add(1);
                    conn.snd_wnd = tcp_hdr.window;
                    conn.rcv_wnd = tcp::INITIAL_RCV_WND;
                    conn.cwnd = tcp::INITIAL_CWND;
                    conn.ssthresh = 0xFFFF;
                    conn.rto = tcp::RTO_INITIAL;
                    conn.retransmit_timer = 0;
                    conn.state = tcp::TcpState::SynReceived;
                    conn_index_insert(s, idx);
                    send_tcp_control(s, idx, tcp::SYN | tcp::ACK, false);
                    return;
                }
            }
            // A bare ACK matching no connection may be the third segment of a
            // handshake answered from cookie mode, for which no state was
            // kept. Anything else — and any cookie that fails — falls through
            // to the RST below unchanged.
            match try_cookie_accept(s, ip_hdr, &tcp_hdr, local_slot) {
                CookieAccept::Installed(idx) => idx,
                CookieAccept::Absorbed => return,
                CookieAccept::NotACookie => {
                    // No listener either — send RST if not RST, sourced from
                    // the exact local address the segment targeted.
                    if (tcp_hdr.flags & tcp::RST) == 0 && s.mac_valid && s.local_ip != 0 {
                        let rst_src = local_ip_for_slot(s, local_slot);
                        send_tcp_rst(
                            s,
                            ip_hdr.src_ip,
                            tcp_hdr.src_port,
                            tcp_hdr.dst_port,
                            &tcp_hdr,
                            rst_src,
                        );
                    }
                    return;
                }
            }
        }
    };

    let (state_before, rcv_before) = {
        let c = &*s.tcp_conns.as_ptr().add(conn_idx);
        (c.state, c.rcv_nxt)
    };
    let mut acked_new = false;

    // One admissibility decision, ahead of every state branch.
    let ack_usable = match admit_tcp_segment(s, conn_idx, &tcp_hdr) {
        Admission::Admit { ack_usable } => ack_usable,
        Admission::Refused => return,
    };

    // Window updates are taken here, once, for every admitted segment that
    // carries a usable ACK — never from inside a state branch, so no branch
    // can install a window from a segment the gate would have refused.
    if ack_usable {
        note_window_update(s, conn_idx, &tcp_hdr);
    }

    // Process TCP state machine using deferred actions to avoid borrow conflicts.
    // First update conn state, then perform sends/notifications.
    const ACTION_NONE: u8 = 0;
    const ACTION_SEND_ACK: u8 = 1;
    const ACTION_COMPLETE_CONNECT: u8 = 2;
    const ACTION_COMPLETE_REFUSED: u8 = 3;
    const ACTION_SET_CLOSED: u8 = 4;
    const ACTION_SET_CLOSING: u8 = 5;
    const ACTION_RX_DATA: u8 = 6;
    const ACTION_COMPLETE_ACCEPT: u8 = 7;
    const ACTION_FREE_SLOT: u8 = 8;
    const ACTION_RETRANSMIT_SYNACK: u8 = 9;
    const ACTION_RX_DATA_FIN: u8 = 10;

    let mut action: u8 = ACTION_NONE;
    let mut rx_payload_offset: usize = 0;
    let mut rx_payload_len: usize = 0;
    let mut reorder_pending: bool = false;
    let mut reorder_seq: u32 = 0;
    let mut reorder_offset: usize = 0;
    let mut reorder_len: usize = 0;
    let mut net_send_fast_retransmit: bool = false;
    let mut net_send_fast_retransmit_conn: u16 = 0;
    let mut net_send_fast_retransmit_seq: u32 = 0;

    {
        let conn = &mut (*s.tcp_conns.as_mut_ptr().add(conn_idx));

        match conn.state {
            tcp::TcpState::SynSent => {
                // RFC 9293 §3.10.7.3. `SEG.ACK` must acknowledge exactly our
                // SYN — `ISS < SEG.ACK <= SND.NXT` collapses to `== SND.NXT`
                // here because nothing else has been sent yet. An RST is
                // acceptable ONLY when it carries such an ACK: without that
                // test any host able to guess the four-tuple can refuse the
                // connection, which is the whole point of the check.
                let acks_our_syn =
                    (tcp_hdr.flags & tcp::ACK) != 0 && tcp_hdr.ack_num == conn.snd_nxt;
                if (tcp_hdr.flags & tcp::RST) != 0 {
                    if acks_our_syn {
                        conn.state = tcp::TcpState::Closed;
                        action = ACTION_COMPLETE_REFUSED;
                    } else {
                        s.drops.tcp_ack_invalid = s.drops.tcp_ack_invalid.wrapping_add(1);
                    }
                } else if (tcp_hdr.flags & (tcp::SYN | tcp::ACK)) == (tcp::SYN | tcp::ACK)
                    && acks_our_syn
                {
                    conn.rcv_nxt = tcp_hdr.seq_num.wrapping_add(1);
                    conn.snd_una = tcp_hdr.ack_num;
                    tcp::apply_window_update(
                        conn,
                        tcp_hdr.seq_num,
                        tcp_hdr.ack_num,
                        tcp_hdr.window,
                    );
                    conn.state = tcp::TcpState::Established;
                    conn.retransmit_timer = 0;
                    action = ACTION_COMPLETE_CONNECT;
                }
            }
            tcp::TcpState::Established => {
                if (tcp_hdr.flags & tcp::RST) != 0 {
                    conn.state = tcp::TcpState::Closed;
                    action = ACTION_SET_CLOSED;
                } else {
                    if ack_usable {
                        let prev_una = conn.snd_una;
                        if seq_between(conn.snd_una, tcp_hdr.ack_num, conn.snd_nxt.wrapping_add(1))
                        {
                            conn.snd_una = tcp_hdr.ack_num;
                        }
                        if conn.snd_una != prev_una {
                            // New data acknowledged.
                            acked_new = true;
                            tcp::on_new_ack(conn);
                            tcp::rtt_ack(conn, tcp_hdr.ack_num, s.step_count as u16);
                        } else if tcp_hdr.ack_num == prev_una && tcp_hdr.payload_len == 0 {
                            // Duplicate ACK (no new data, no new ACK).
                            if tcp::on_dup_ack(conn) {
                                // Fast retransmit trigger — consumer notified.
                                net_send_fast_retransmit = true;
                                net_send_fast_retransmit_conn = conn_idx as u16;
                                net_send_fast_retransmit_seq = conn.snd_una;
                            }
                        }
                    }
                    if tcp_hdr.payload_len > 0 && tcp_hdr.seq_num == conn.rcv_nxt {
                        rx_payload_offset = tcp_hdr.payload_offset;
                        rx_payload_len = tcp_hdr.payload_len;
                        action = ACTION_RX_DATA;
                    } else if tcp_hdr.payload_len > 0
                        && seq_between(
                            conn.rcv_nxt,
                            tcp_hdr.seq_num,
                            conn.rcv_nxt.wrapping_add(conn.rcv_wnd as u32),
                        )
                    {
                        // Out-of-order segment within the receive window —
                        // buffer for reassembly and send a duplicate ACK.
                        reorder_pending = true;
                        reorder_seq = tcp_hdr.seq_num;
                        reorder_offset = tcp_hdr.payload_offset;
                        reorder_len = tcp_hdr.payload_len;
                        action = ACTION_SEND_ACK; // duplicate ACK
                    }
                    if (tcp_hdr.flags & tcp::FIN) != 0 {
                        if action == ACTION_RX_DATA {
                            // Data + FIN: defer the FIN bookkeeping
                            // to the handler so it only commits if
                            // the payload was delivered. Advancing
                            // up-front would strand the segment if
                            // delivery is backpressure-rejected —
                            // CloseWait doesn't re-process data.
                            action = ACTION_RX_DATA_FIN;
                        } else if tcp_hdr.seq_num.wrapping_add(tcp_hdr.payload_len as u32)
                            == conn.rcv_nxt
                        {
                            // The FIN sits exactly at our receive
                            // position (a pure FIN at rcv_nxt, or a
                            // retransmitted tail whose payload we have
                            // already delivered): honour it.
                            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                            conn.state = tcp::TcpState::CloseWait;
                            action = ACTION_SET_CLOSING;
                        }
                        // Any other FIN is ahead of undelivered bytes
                        // (out-of-order under loss, or a burst racing
                        // the consumer): IGNORE it — honouring it here
                        // would close the connection and abandon every
                        // byte the consumer has not yet received. The
                        // peer retransmits the gap and the FIN until
                        // the stream completes.
                    }
                }
            }
            tcp::TcpState::FinWait1 => {
                // A FIN is honoured only at the receive position: `SEG.SEQ +
                // payload == RCV.NXT`. Accepting one that merely fell in the
                // window would let a segment sequenced ahead of undelivered
                // bytes close the connection.
                let fin_at_rcv_nxt = (tcp_hdr.flags & tcp::FIN) != 0
                    && tcp_hdr.seq_num.wrapping_add(tcp_hdr.payload_len as u32) == conn.rcv_nxt;
                if ack_usable {
                    if seq_between(conn.snd_una, tcp_hdr.ack_num, conn.snd_nxt.wrapping_add(1)) {
                        conn.snd_una = tcp_hdr.ack_num;
                    }
                    if tcp_hdr.ack_num == conn.snd_nxt {
                        // Our FIN has been acknowledged.
                        if fin_at_rcv_nxt {
                            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                            conn.state = tcp::TcpState::TimeWait;
                            conn.timewait_timer = 0;
                            action = ACTION_SEND_ACK;
                        } else {
                            conn.state = tcp::TcpState::FinWait2;
                        }
                    } else if fin_at_rcv_nxt {
                        // Simultaneous close: the peer's FIN arrived while
                        // ours is still outstanding. Acknowledge it and wait
                        // in CLOSING for the ACK of our own FIN.
                        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                        conn.state = tcp::TcpState::Closing;
                        conn.retransmit_timer = 0;
                        action = ACTION_SEND_ACK;
                    }
                    // Partial ACK (data ACK'd but not FIN) — stay in FinWait1
                }
            }
            tcp::TcpState::Closing => {
                // Both FINs are exchanged; only the acknowledgement of ours
                // is outstanding. Nothing else advances this state.
                if ack_usable && tcp_hdr.ack_num == conn.snd_nxt {
                    conn.state = tcp::TcpState::TimeWait;
                    conn.timewait_timer = 0;
                }
            }
            tcp::TcpState::FinWait2 => {
                if (tcp_hdr.flags & tcp::FIN) != 0
                    && tcp_hdr.seq_num.wrapping_add(tcp_hdr.payload_len as u32) == conn.rcv_nxt
                {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = tcp::TcpState::TimeWait;
                    conn.timewait_timer = 0;
                    action = ACTION_SEND_ACK;
                }
            }
            tcp::TcpState::LastAck => {
                // Only the acknowledgement of our own FIN closes this
                // state: a stale ACK of earlier data must not tear the
                // slot down while the FIN is still in flight.
                if ack_usable && tcp_hdr.ack_num == conn.snd_nxt {
                    conn.state = tcp::TcpState::Closed;
                    action = ACTION_SET_CLOSED;
                }
            }
            tcp::TcpState::TimeWait => {
                // A retransmitted FIN at the receive position is re-ACKed and
                // restarts the quiet period, which is what TIME-WAIT exists
                // to provide. The gate has already established that the
                // segment belongs to this conversation.
                if (tcp_hdr.flags & tcp::FIN) != 0
                    && tcp_hdr.seq_num.wrapping_add(tcp_hdr.payload_len as u32)
                        == conn.rcv_nxt.wrapping_sub(1)
                {
                    conn.timewait_timer = 0;
                    action = ACTION_SEND_ACK;
                }
            }
            tcp::TcpState::SynReceived => {
                if (tcp_hdr.flags & tcp::RST) != 0 {
                    // Connection refused — free the slot. The listener
                    // is on a separate slot and stays put.
                    action = ACTION_FREE_SLOT;
                } else if (tcp_hdr.flags & tcp::SYN) != 0 && (tcp_hdr.flags & tcp::ACK) == 0 {
                    // Duplicate SYN — our prior SYN-ACK didn't reach
                    // the peer. Retransmit; count for the `[ip] hb`
                    // `dupSYN=N` line.
                    s.tcp_dup_syn_rx = s.tcp_dup_syn_rx.wrapping_add(1);
                    conn.retransmit_timer = 0;
                    action = ACTION_RETRANSMIT_SYNACK;
                } else if ack_usable {
                    // Handshake complete
                    if tcp_hdr.ack_num == conn.snd_nxt {
                        conn.snd_una = tcp_hdr.ack_num;
                        conn_leave_half_open(s, conn_idx);
                        conn.state = tcp::TcpState::Established;
                        conn.retransmit_timer = 0;
                        action = ACTION_COMPLETE_ACCEPT;
                        // Handle piggybacked data (ACK + request in same segment)
                        if tcp_hdr.payload_len > 0 && tcp_hdr.seq_num == conn.rcv_nxt {
                            rx_payload_offset = tcp_hdr.payload_offset;
                            rx_payload_len = tcp_hdr.payload_len;
                        }
                    }
                }
            }
            _ => {}
        }
    } // conn borrow dropped here

    // Execute deferred actions
    match action {
        ACTION_SEND_ACK => {
            send_tcp_control(s, conn_idx, tcp::ACK, false);
        }
        ACTION_COMPLETE_CONNECT => {
            send_tcp_control(s, conn_idx, tcp::ACK, false);
            // Latch the connected-notification for retry if it couldn't be
            // delivered now, so a waiter always learns the connect succeeded.
            if !net_send_connected(s, conn_idx as u16) {
                (*s.tcp_conns.as_mut_ptr().add(conn_idx)).pending_close_notify = NOTIFY_CONNECTED;
            }
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            arp::pin(&mut s.arp_table, remote_ip);
        }
        ACTION_COMPLETE_REFUSED => {
            let tag = (*s.tcp_conns.as_ptr().add(conn_idx)).connect_tag;
            let delivered = net_send_error(s, conn_idx as u16, -111i8, tag);
            let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
            if delivered {
                conn_reset(s, conn_idx);
            } else {
                // Latch the slot until `step_tcp_timers` retries so
                // the consumer learns of the refusal — dropping the
                // event would strand any consumer waiting on the
                // connect outcome.
                conn.state = tcp::TcpState::Closed;
                conn.pending_close_notify = NOTIFY_ERROR_REFUSED;
            }
        }
        ACTION_SET_CLOSED => {
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            let delivered = net_send_closed(s, conn_idx as u16);
            let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
            if delivered {
                if remote_ip != 0 {
                    arp::unpin(&mut s.arp_table, remote_ip);
                }
                conn_reset(s, conn_idx);
            } else {
                // ARP unpin is deferred until the slot actually frees
                // so a retry storm doesn't churn the table.
                conn.state = tcp::TcpState::Closed;
                conn.pending_close_notify = NOTIFY_CLOSED;
            }
        }
        ACTION_SET_CLOSING => {
            send_tcp_control(s, conn_idx, tcp::ACK, false);
            if !net_send_closed(s, conn_idx as u16) {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.pending_close_notify = NOTIFY_CLOSED;
            }
        }
        ACTION_RX_DATA | ACTION_RX_DATA_FIN => {
            let payload = data.add(rx_payload_offset);
            // Channel writes are atomic-FIFO: rejected outright when
            // the consumer is full. We MUST NOT advance rcv_nxt /
            // ACK on a rejection — the peer would treat the data as
            // delivered and stop retransmitting. Closing the window
            // (rcv_wnd = 0) and emitting a duplicate ACK lets the
            // peer's retransmit re-deliver once the consumer drains.
            let delivered = net_send_data(s, conn_idx as u16, payload, rx_payload_len);
            if !delivered {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.rcv_wnd = 0;
                send_tcp_control(s, conn_idx, tcp::ACK, false);
                continuity::after_segment(s, conn_idx, state_before, rcv_before, acked_new);
                return;
            }
            {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(rx_payload_len as u32);
                conn.delivered_bytes = conn.delivered_bytes.wrapping_add(rx_payload_len as u32);
                conn.idle_timer = 0;
            }
            // Drain any reorder slots that are now contiguous. Peek
            // first so a mid-loop channel-full leaves the payload in
            // the slot for the next retry — only consume after a
            // successful `net_send_data`.
            loop {
                let conn = &*s.tcp_conns.as_ptr().add(conn_idx);
                let rcv_nxt = conn.rcv_nxt;
                let peeked = tcp::reorder_peek_next(conn, rcv_nxt);
                match peeked {
                    Some((slice, next_seq)) => {
                        let ptr = slice.as_ptr();
                        let len = slice.len();
                        if !net_send_data(s, conn_idx as u16, ptr, len) {
                            break;
                        }
                        let conn2 = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                        tcp::reorder_consume_at(conn2, rcv_nxt);
                        conn2.rcv_nxt = next_seq;
                        conn2.delivered_bytes = conn2.delivered_bytes.wrapping_add(len as u32);
                    }
                    None => break,
                }
            }
            // FIN bookkeeping is deferred to here so it only commits
            // if the payload reached the consumer; the state advance
            // happens before the ACK so the ACK carries the correct
            // ack_num.
            if action == ACTION_RX_DATA_FIN {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                conn.state = tcp::TcpState::CloseWait;
            }
            update_rcv_wnd(s, conn_idx);
            send_tcp_control(s, conn_idx, tcp::ACK, false);
            if action == ACTION_RX_DATA_FIN && !net_send_closed(s, conn_idx as u16) {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.pending_close_notify = NOTIFY_CLOSED;
            }
        }
        ACTION_COMPLETE_ACCEPT => {
            // RX is gated on NET_OUT_QUEUE_HEADROOM, so the queue
            // always has space for MSG_ACCEPTED here. The `_` discard
            // documents the contract: callers MUST have queue
            // headroom before progressing past Established.
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            arp::pin(&mut s.arp_table, remote_ip);
            let local_port = (*s.tcp_conns.as_ptr().add(conn_idx)).local_port;
            let _ = net_send_accepted(s, conn_idx as u16, local_port);
            // Piggybacked data (e.g. HTTP GET on the third handshake
            // ACK). Same gate as the regular RX_DATA path: don't ACK
            // payload the consumer didn't receive.
            if rx_payload_len > 0 {
                let payload = data.add(rx_payload_offset);
                if net_send_data(s, conn_idx as u16, payload, rx_payload_len) {
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(rx_payload_len as u32);
                    conn.delivered_bytes = conn.delivered_bytes.wrapping_add(rx_payload_len as u32);
                    send_tcp_control(s, conn_idx, tcp::ACK, false);
                } else {
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                    conn.rcv_wnd = 0;
                    send_tcp_control(s, conn_idx, tcp::ACK, false);
                }
            }
        }
        ACTION_FREE_SLOT => {
            // Reset this slot back to Closed. Used when an accepted
            // conn never completes the handshake (RST in SynReceived
            // or 15s timeout).
            conn_reset(s, conn_idx);
        }
        ACTION_RETRANSMIT_SYNACK => {
            send_tcp_control(s, conn_idx, tcp::SYN | tcp::ACK, true);
        }
        _ => {}
    }

    // Buffer an out-of-order segment if one was flagged.
    if reorder_pending {
        let payload = data.add(reorder_offset);
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
        tcp::reorder_insert(conn, reorder_seq, payload, reorder_len);
    }

    // A mirrored flow reports what this segment changed.
    if (*s.tcp_conns.as_ptr().add(conn_idx)).is_active() {
        continuity::after_segment(s, conn_idx, state_before, rcv_before, acked_new);
    }

    // Fast retransmit — signal the consumer to resend from `snd_una`.
    if net_send_fast_retransmit {
        net_send_retransmit(
            s,
            net_send_fast_retransmit_conn,
            net_send_fast_retransmit_seq,
        );
    }
}

/// Emit a challenge ACK for `conn_idx` if both the global and the per-peer
/// budget allow it (RFC 5961 §7).
///
/// The challenge ACK is the answer to a segment that is plausibly in the
/// conversation but cannot be acted on. Every such segment is cheap for an
/// off-path attacker to forge, so an unlimited response turns the defence
/// into a reflector: the rate limit, not the check, is what keeps the
/// exchange one-sided. A suppressed challenge is counted rather than logged
/// — under a flood the log itself would be the amplifier.
unsafe fn send_challenge_ack(s: &mut IpState, conn_idx: usize) -> bool {
    let peer_budget = (*s.tcp_conns.as_ptr().add(conn_idx)).chal_budget;
    if peer_budget == 0 || s.chal_ack_budget == 0 {
        s.drops.tcp_challenge_suppressed = s.drops.tcp_challenge_suppressed.wrapping_add(1);
        return false;
    }
    s.chal_ack_budget = s.chal_ack_budget.saturating_sub(1);
    (*s.tcp_conns.as_mut_ptr().add(conn_idx)).chal_budget = peer_budget.saturating_sub(1);
    s.drops.tcp_challenge_sent = s.drops.tcp_challenge_sent.wrapping_add(1);
    send_tcp_control(s, conn_idx, tcp::ACK, false)
}

/// Outcome of the segment-admissibility gate.
enum Admission {
    /// The segment may reach the state machine. `ack_usable` is false when
    /// `SEG.ACK` is below `SND.UNA`: RFC 9293 §3.10.7.4 ignores such an ACK
    /// field but still processes the rest of the segment, so the payload is
    /// not lost to a reordered acknowledgement.
    Admit { ack_usable: bool },
    /// Handled entirely by the gate — challenged, counted, or dropped.
    Refused,
}

/// One admissibility decision for every synchronised state.
///
/// The state machine below is written on the assumption that a segment which
/// reaches it belongs to the conversation. This gate is what makes that
/// assumption true: receive-window acceptability over the segment's full
/// sequence extent (RFC 9293 §3.10.7.4), RST classification (RFC 5961 §3.2),
/// spoofed-SYN handling (RFC 5961 §4), and `SEG.ACK` range validation.
///
/// `SynSent` is excluded — it has no receive sequence space yet and RFC 9293
/// §3.10.7.3 gives it separate rules, applied in its own branch. `Listen` and
/// `Closed` slots are never reached here: `find_conn` matches on a concrete
/// remote tuple.
unsafe fn admit_tcp_segment(s: &mut IpState, conn_idx: usize, hdr: &tcp::TcpHeader) -> Admission {
    let (state, rcv_nxt, rcv_wnd, snd_una, snd_nxt) = {
        let c = &*s.tcp_conns.as_ptr().add(conn_idx);
        (c.state, c.rcv_nxt, c.rcv_wnd, c.snd_una, c.snd_nxt)
    };
    if !state.is_synchronised() {
        // `SynSent` only. Its branch validates `SEG.ACK` against `ISS`/`SND.NXT`
        // itself and installs the window from the accepted SYN-ACK, so the
        // shared ACK/window path stays out of it.
        return Admission::Admit { ack_usable: false };
    }

    // A duplicate SYN in SYN-RECEIVED is the peer retransmitting its passive
    // open. It carries the peer's ISS, exactly one below `RCV.NXT`, so it can
    // never satisfy the window test. Admit that one shape — nothing else with
    // the SYN bit gets past this gate in a synchronised state.
    if state == tcp::TcpState::SynReceived
        && (hdr.flags & tcp::SYN) != 0
        && (hdr.flags & (tcp::ACK | tcp::RST)) == 0
    {
        if hdr.seq_num == rcv_nxt.wrapping_sub(1) {
            return Admission::Admit { ack_usable: false };
        }
        s.drops.tcp_unacceptable = s.drops.tcp_unacceptable.wrapping_add(1);
        return Admission::Refused;
    }

    // RFC 5961 §3.2 — RST is decided on its own sequence rules, before the
    // window test, because a legitimate RST is the one segment whose sequence
    // must match exactly rather than merely fall in the window.
    if (hdr.flags & tcp::RST) != 0 {
        return match tcp::classify_rst(rcv_nxt, rcv_wnd, hdr.seq_num) {
            tcp::RstAction::Reset => Admission::Admit { ack_usable: false },
            tcp::RstAction::Challenge => {
                send_challenge_ack(s, conn_idx);
                Admission::Refused
            }
            tcp::RstAction::Drop => {
                s.drops.tcp_rst_out_of_window = s.drops.tcp_rst_out_of_window.wrapping_add(1);
                Admission::Refused
            }
        };
    }

    // TIME-WAIT exists to absorb a retransmitted peer FIN, which sits one
    // below `RCV.NXT` and so can never satisfy the window test. Admit exactly
    // that shape; the branch re-ACKs it and restarts the quiet period.
    if state == tcp::TcpState::TimeWait
        && (hdr.flags & tcp::FIN) != 0
        && hdr.seq_num.wrapping_add(hdr.payload_len as u32) == rcv_nxt.wrapping_sub(1)
    {
        return Admission::Admit { ack_usable: false };
    }

    let span = tcp::seg_len(hdr.flags, hdr.payload_len);
    let mut acceptable = tcp::segment_acceptable(rcv_nxt, rcv_wnd, hdr.seq_num, span);
    if !acceptable && rcv_wnd == 0 && span > 0 {
        // The window may have been closed by consumer backpressure that has
        // since drained. Re-poll before refusing the peer's retransmit: this
        // is the path by which a backpressured stream resumes.
        update_rcv_wnd(s, conn_idx);
        let reopened = (*s.tcp_conns.as_ptr().add(conn_idx)).rcv_wnd;
        acceptable = tcp::segment_acceptable(rcv_nxt, reopened, hdr.seq_num, span);
    }
    if !acceptable {
        s.drops.tcp_unacceptable = s.drops.tcp_unacceptable.wrapping_add(1);
        send_challenge_ack(s, conn_idx);
        return Admission::Refused;
    }

    // RFC 5961 §4 — a SYN inside the window of an established conversation is
    // spoofed or a stale duplicate. Answering with a challenge ACK lets a
    // genuine peer that really did restart discover the true sequence and
    // send a correctly-sequenced RST; acting on the SYN itself would let one
    // forged segment tear the connection down.
    if (hdr.flags & tcp::SYN) != 0 {
        s.drops.tcp_unacceptable = s.drops.tcp_unacceptable.wrapping_add(1);
        send_challenge_ack(s, conn_idx);
        return Admission::Refused;
    }

    // Synchronised states carry ACK on every segment; one without it is not
    // part of the conversation.
    if (hdr.flags & tcp::ACK) == 0 {
        s.drops.tcp_unacceptable = s.drops.tcp_unacceptable.wrapping_add(1);
        return Admission::Refused;
    }

    if tcp::seq_lt(snd_nxt, hdr.ack_num) {
        // Acknowledges data never sent.
        s.drops.tcp_ack_invalid = s.drops.tcp_ack_invalid.wrapping_add(1);
        send_challenge_ack(s, conn_idx);
        return Admission::Refused;
    }
    let ack_usable = tcp::ack_acceptable(snd_una, snd_nxt, hdr.ack_num);
    if !ack_usable {
        s.drops.tcp_ack_invalid = s.drops.tcp_ack_invalid.wrapping_add(1);
    }
    Admission::Admit { ack_usable }
}

/// Take `SEG.WND` as the peer's window if the segment is newer than the one
/// that last set it, else count the refusal (`SND.WL1`/`SND.WL2`,
/// RFC 9293 §3.10.7.4).
unsafe fn note_window_update(s: &mut IpState, conn_idx: usize, hdr: &tcp::TcpHeader) {
    let allowed = {
        let conn = &*s.tcp_conns.as_ptr().add(conn_idx);
        tcp::window_update_allowed(conn, hdr.seq_num, hdr.ack_num)
    };
    if allowed {
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
        tcp::apply_window_update(conn, hdr.seq_num, hdr.ack_num, hdr.window);
    } else {
        s.drops.tcp_stale_window = s.drops.tcp_stale_window.wrapping_add(1);
    }
}

/// Check if `val` is between `start` (inclusive) and `end` (exclusive) in sequence space.
fn seq_between(start: u32, val: u32, end: u32) -> bool {
    let len = end.wrapping_sub(start);
    let pos = val.wrapping_sub(start);
    pos < len && pos > 0
}

/// Send a TCP RST in response to an unexpected segment.
unsafe fn send_tcp_rst(
    s: &mut IpState,
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    hdr: &tcp::TcpHeader,
    local_src: u32,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }

    // RFC 9293 §3.10.7.1. Without an ACK to mirror, the RST must acknowledge
    // the whole of the offending segment's sequence space — its payload plus
    // one for each of SYN and FIN. A closed-port RST answering a bare SYN
    // with `SEG.SEQ` alone is one short, and the peer discards it as
    // out-of-window, so the connect hangs to its own timeout instead of
    // failing immediately.
    let (seq, ack, flags) = if (hdr.flags & tcp::ACK) != 0 {
        (hdr.ack_num, 0u32, tcp::RST)
    } else {
        let ack = hdr
            .seq_num
            .wrapping_add(tcp::seg_len(hdr.flags, hdr.payload_len));
        (0u32, ack, tcp::RST | tcp::ACK)
    };

    // Resolve MAC
    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return,
    };
    send_tcp_rst_to(
        s,
        remote_ip,
        remote_port,
        local_port,
        seq,
        ack,
        flags,
        local_src,
        &dst_mac,
    );
}

/// Emit an RST to a known MAC. The decision seam answers the frame it
/// holds, whose source MAC is in hand, rather than resolving the sender —
/// a REJECT must not turn into an ARP exchange with the party it refuses.
#[allow(
    clippy::too_many_arguments,
    reason = "one wire frame's fields; a struct would be built and unpacked at the single call site"
)]
unsafe fn send_tcp_rst_to(
    s: &mut IpState,
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    local_src: u32,
    dst_mac: &[u8; 6],
) {
    let dst_mac = *dst_mac;
    let tcp_start = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    tcp::build_tcp_header(tcp_start, local_port, remote_port, seq, ack, flags, 0);

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_TCP,
        local_src,
        remote_ip,
        s.ip_id,
    );

    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &dst_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    tcp::compute_tcp_checksum(tcp_start, tcp::TCP_HEADER_LEN, local_src, remote_ip);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// Outcome of examining a connection-less segment for a returning SYN
/// cookie.
enum CookieAccept {
    /// The cookie validated and the connection was installed on this slot,
    /// still in `SynReceived` so the ordinary state machine performs the
    /// transition, the accept notification and any piggybacked data.
    Installed(usize),
    /// Not a cookie ACK. The caller takes its unchanged path — an RST for
    /// anything that is not itself an RST.
    NotACookie,
    /// A valid cookie with no slot left to install it on. Cookies bound
    /// pre-handshake memory; they cannot manufacture capacity that does not
    /// exist, so the ACK is dropped and the client retries.
    Absorbed,
}

/// Examine a segment that matched no connection for a returning SYN cookie.
///
/// Validation is attempted only when a listener matches the `(port, local
/// address)` the segment targets and the segment is a bare ACK; every other
/// shape reaches the caller's RST path without any hashing, and a cookie
/// that fails validation takes that same path. What a peer sees for a bad
/// cookie is therefore byte-for-byte what it sees for a port nobody listens
/// on.
///
/// # Safety
/// `s` must be an initialised `IpState`; `tcp_hdr` must describe the
/// segment.
unsafe fn try_cookie_accept(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    tcp_hdr: &tcp::TcpHeader,
    local_slot: u16,
) -> CookieAccept {
    if (tcp_hdr.flags & tcp::ACK) == 0
        || (tcp_hdr.flags & (tcp::SYN | tcp::RST | tcp::FIN)) != 0
        || !s.isn_secret_valid
        || !s.mac_valid
        || s.local_ip == 0
        || !tcp::cookie_mode_admissible(tcp_hdr)
    {
        return CookieAccept::NotACookie;
    }
    let dst_owned = slot_is_owned(s, local_slot);
    let li = match find_listener_indexed(s, tcp_hdr.dst_port, local_slot, dst_owned) {
        Some(i) => i,
        None => return CookieAccept::NotACookie,
    };
    let listener_port = (*s.tcp_conns.as_ptr().add(li)).local_port;
    let local_src = local_ip_for_slot(s, local_slot);
    let cookie = tcp_hdr.ack_num.wrapping_sub(1);
    if !validate_syn_cookie(
        s,
        local_src,
        listener_port,
        ip_hdr.src_ip,
        tcp_hdr.src_port,
        cookie,
    ) {
        s.tcp_syn_cookie_bad = s.tcp_syn_cookie_bad.wrapping_add(1);
        return CookieAccept::NotACookie;
    }

    let accept_idx: i32 = match alloc_free_slot(s) {
        Some(i) => i as i32,
        None => -1,
    };
    if accept_idx < 0 {
        s.tcp_half_open_refused = s.tcp_half_open_refused.wrapping_add(1);
        return CookieAccept::Absorbed;
    }

    // Every field is a constant or a field of this ACK — see the cookie
    // construction. The block is installed one step short of `Established`
    // so the shared admissibility gate and state machine complete it.
    let idx = accept_idx as usize;
    let conn = &mut *s.tcp_conns.as_mut_ptr().add(idx);
    *conn = tcp::TcpConn::new();
    conn.local_port = listener_port;
    conn.local_slot = local_slot;
    conn.remote_ip = ip_hdr.src_ip;
    conn.remote_port = tcp_hdr.src_port;
    conn.iss = cookie;
    conn.snd_una = cookie;
    conn.snd_nxt = cookie.wrapping_add(1);
    conn.rcv_nxt = tcp_hdr.seq_num;
    conn.snd_wnd = tcp_hdr.window;
    conn.rcv_wnd = tcp::INITIAL_RCV_WND;
    conn.cwnd = tcp::INITIAL_CWND;
    conn.ssthresh = 0xFFFF;
    conn.rto = tcp::RTO_INITIAL;
    conn.retransmit_timer = 0;
    conn.state = tcp::TcpState::SynReceived;
    conn_index_insert(s, idx);
    s.tcp_syn_cookie_ok = s.tcp_syn_cookie_ok.wrapping_add(1);
    CookieAccept::Installed(idx)
}

/// Send a SYN-ACK for a passive open that holds no connection slot: the
/// sequence number is the cookie and every other field is a constant or a
/// field of the SYN being answered. Nothing is allocated and nothing is
/// swept, which is what makes cookie mode admissible on the MCU profiles.
///
/// # Safety
/// `s` must be an initialised, configured `IpState`.
unsafe fn send_syn_ack_cookie(
    s: &mut IpState,
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    local_src: u32,
    cookie: u32,
    rcv_nxt: u32,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }
    let dst_mac = match resolve_mac(s, remote_ip) {
        Some(m) => m,
        None => return,
    };

    let tcp_start = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    tcp::build_tcp_header(
        tcp_start,
        local_port,
        remote_port,
        cookie,
        rcv_nxt,
        tcp::SYN | tcp::ACK,
        tcp::INITIAL_RCV_WND,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_TCP,
        local_src,
        remote_ip,
        s.ip_id,
    );

    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &dst_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    tcp::compute_tcp_checksum(tcp_start, tcp::TCP_HEADER_LEN, local_src, remote_ip);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// Send a TCP control segment (SYN / ACK / FIN / RST).
///
/// SYN and FIN each consume one sequence number — RFC 793 §3.3.
/// Sequence-space accounting is driven off `snd_una` rather than the
/// `retransmit` flag so the bookkeeping survives a failed initial
/// attempt followed by a successful retry:
///
///   * Fresh send: `seq = snd_nxt` and (since the byte is uncredited)
///     `snd_nxt == seq`, so `snd_nxt` advances by one on success.
///   * Retransmit after a successful original: `seq = snd_una`,
///     `snd_nxt > snd_una`, so `snd_nxt` is unchanged.
///   * Retransmit after a failed original (e.g. ARP miss returned
///     before the first attempt could queue): `seq = snd_una` and
///     `snd_nxt == snd_una`, so the byte is credited the first time
///     it actually reaches the wire.
///
/// ACK-only segments don't consume sequence space, so the flag has
/// no effect on them. Returns `true` iff the frame was queued; the
/// caller defers state transitions on backpressured SYN/FIN.
unsafe fn send_tcp_control(s: &mut IpState, conn_idx: usize, flags: u8, retransmit: bool) -> bool {
    if !s.mac_valid || s.local_ip == 0 {
        return false;
    }

    let conn = &*s.tcp_conns.as_ptr().add(conn_idx);
    let remote_ip = conn.remote_ip;
    let local_port = conn.local_port;
    let remote_port = conn.remote_port;
    // What the peer is shown: under a strict mirror the acknowledgement
    // stops at the confirmed horizon, and a quiescing flow advertises a
    // closed window.
    let rcv_nxt = continuity::ack_exposed(s, conn_idx, conn.rcv_nxt);
    let rcv_wnd = continuity::rcv_wnd_exposed(s, conn_idx, conn.rcv_wnd);
    // Source from the conn's bound local address. Slot 0 / unbound →
    // `local_ip`, so a single-address configuration is unaffected.
    let local_src = local_ip_for_slot(s, conn.local_slot);
    let consumes_seq = (flags & (tcp::SYN | tcp::FIN)) != 0;
    let seq = if retransmit && consumes_seq {
        conn.snd_una
    } else {
        conn.snd_nxt
    };

    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => {
            log_info(s, b"[ip] tcp ctrl: arp pending");
            if (flags & tcp::SYN) != 0 {
                arp_wait_push(s, conn_idx);
            }
            return false;
        }
    };

    let tcp_start = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    tcp::build_tcp_header(
        tcp_start,
        local_port,
        remote_port,
        seq,
        rcv_nxt,
        flags,
        rcv_wnd,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_TCP,
        local_src,
        remote_ip,
        s.ip_id,
    );

    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &dst_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    tcp::compute_tcp_checksum(tcp_start, tcp::TCP_HEADER_LEN, local_src, remote_ip);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    if !send_frame(s, s.tx_frame.as_ptr(), total) {
        return false;
    }
    if consumes_seq {
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
        // Advance only if this byte hasn't already been credited.
        // `snd_nxt == seq` is true for a fresh send and for the first
        // successful retry after a failed initial attempt; it's false
        // once an earlier attempt has already advanced `snd_nxt` past
        // the SYN/FIN byte.
        if conn.snd_nxt == seq {
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        }
    }
    true
}

/// Send a TCP data segment. Returns `true` iff the frame was queued;
/// on `false` `snd_nxt` is unchanged and the bytes remain the caller's
/// responsibility (the upstream stash in `pending_cmd_*`).
#[inline(never)]
unsafe fn send_tcp_data(
    s: &mut IpState,
    conn_idx: usize,
    payload: *const u8,
    payload_len: usize,
) -> bool {
    // The frame builder's own precondition: `payload` is copied into the
    // fixed `tx_frame`, and the caller's stash buffer is larger than that
    // frame on aarch64. Refuse before the copy rather than trusting the
    // segmenter's `MSS` cap to stay below the frame ceiling.
    if payload_len > MAX_TCP_TX_PAYLOAD {
        return false;
    }
    if !s.mac_valid || s.local_ip == 0 || payload_len == 0 {
        return false;
    }

    // Extract conn fields
    let remote_ip = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_ip;
    let local_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).local_port;
    let remote_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_port;
    let snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt;
    let rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt;
    let rcv_nxt = continuity::ack_exposed(s, conn_idx, rcv_nxt);
    let rcv_wnd = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_wnd;
    let rcv_wnd = continuity::rcv_wnd_exposed(s, conn_idx, rcv_wnd);
    let local_slot = (*s.tcp_conns.as_ptr().add(conn_idx)).local_slot;
    let local_src = local_ip_for_slot(s, local_slot);

    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return false,
    };

    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
    let tcp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

    tcp::build_tcp_header(
        tcp_start,
        local_port,
        remote_port,
        snd_nxt,
        rcv_nxt,
        tcp::ACK | tcp::PSH,
        rcv_wnd,
    );

    // Copy payload after TCP header
    let payload_dst = tcp_start.add(tcp::TCP_HEADER_LEN);
    core::ptr::copy_nonoverlapping(payload, payload_dst, payload_len);

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN + payload_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_TCP,
        local_src,
        remote_ip,
        s.ip_id,
    );

    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &dst_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    tcp::compute_tcp_checksum(
        tcp_start,
        tcp::TCP_HEADER_LEN + payload_len,
        local_src,
        remote_ip,
    );

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    if !send_frame(s, s.tx_frame.as_ptr(), total) {
        return false;
    }
    (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx))
        .snd_nxt
        .wrapping_add(payload_len as u32);
    true
}

/// Return true if `dst` is an IPv4 broadcast address we must not emit
/// from `send_udp_data`. Catches both forms:
///   - limited broadcast: 255.255.255.255
///   - directed broadcast for the local subnet: host bits all-ones
///
/// DHCP legitimately sends to 255.255.255.255 but builds its own frame
/// directly via `dhcp::build_discover` / `build_request` — it does not
/// route through `send_udp_data`, so this check doesn't affect it.
#[inline]
fn is_broadcast_dst(dst: u32, local_ip: u32, netmask: u32) -> bool {
    if dst == 0xFFFF_FFFF {
        return true;
    }
    if netmask == 0 {
        return false;
    }
    // Directed broadcast: same subnet, host bits all-ones.
    let host_bits = dst & !netmask;
    let net_bits = dst & netmask;
    host_bits == !netmask && net_bits == (local_ip & netmask)
}

/// Send a UDP datagram. Used for CMD_SEND on Listen-state (bound) conns where
/// the consumer supplies [dst_ip:4 LE][dst_port:2 LE][payload...], and for
/// Established (connected) conns where remote_ip/port come from the conn slot.
///
/// Broadcast destinations are rejected — a misbehaving producer at
/// tick rate would flood the L2 domain. Consumers that legitimately
/// need broadcast (DHCP, future mDNS/NBNS responders) build their
/// own frame and bypass this path.
///
/// Returns `0` when the datagram was staged (or transiently dropped for an
/// unresolved neighbour, which UDP permits), or a negative errno the caller
/// must report to the consumer. The size bound is enforced BEFORE any copy:
/// the command buffer is larger than `tx_frame` on aarch64, so a late check
/// would already have run past the end of the frame buffer.
unsafe fn send_udp_data(
    s: &mut IpState,
    dst_ip: u32,
    dst_port: u16,
    src_port: u16,
    payload: *const u8,
    payload_len: usize,
) -> i8 {
    if payload_len > MAX_UDP_TX_PAYLOAD {
        s.drops.udp_oversize = s.drops.udp_oversize.wrapping_add(1);
        return E_MSGSIZE;
    }

    if !s.mac_valid || s.local_ip == 0 || payload_len == 0 {
        return 0;
    }

    if is_broadcast_dst(dst_ip, s.local_ip, s.netmask) {
        if !s.bcast_warned {
            s.bcast_warned = true;
            let sys = &*s.syscalls;
            let msg = b"[ip] UDP broadcast rejected (build-your-own-frame if legitimate)";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
        }
        return 0;
    }

    if next_hop(s, dst_ip).is_none() {
        s.drops.route_unreachable = s.drops.route_unreachable.wrapping_add(1);
        return E_NETUNREACH;
    }

    let dst_mac = resolve_mac(s, dst_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return 0,
    };

    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
    let udp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

    // Copy payload after UDP header first so build_udp_header can checksum it
    let payload_dst = udp_start.add(udp::UDP_HEADER_LEN);
    let mut i = 0;
    while i < payload_len {
        *payload_dst.add(i) = *payload.add(i);
        i += 1;
    }

    udp::build_udp_header(
        udp_start,
        src_port,
        dst_port,
        payload_len,
        s.local_ip,
        dst_ip,
        payload_dst,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + payload_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_UDP,
        s.local_ip,
        dst_ip,
        s.ip_id,
    );

    eth::build_eth_header(
        s.tx_frame.as_mut_ptr(),
        &dst_mac,
        &s.mac_addr,
        eth::ETHERTYPE_IPV4,
    );

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
    0
}

/// Arm a permanent gateway pin: discard whatever the cache holds for `gw`
/// and resolve it afresh. The pin is installed by `process_arp` when the
/// correlated reply lands, so an entry seeded before this point — including
/// one an attacker raced in ahead of the lease — is never the one promoted.
unsafe fn arm_gateway_pin(s: &mut IpState, gw: u32) {
    arp::invalidate(&mut s.arp_table, gw);
    s.gw_pin_pending = true;
    s.gw_pin_ip = gw;
    s.gw_pin_armed_step = s.step_count;
    // Issues the request when no other resolution is outstanding; the
    // periodic maintenance pass retries otherwise.
    let _ = resolve_mac(s, gw);
}

/// Periodic ARP upkeep: age the table, account permanent-pin revalidations,
/// and drive an outstanding gateway pin to completion.
unsafe fn step_arp_maintenance(s: &mut IpState) {
    let revalidations = arp::age_entries(&mut s.arp_table);
    if revalidations > 0 {
        s.drops.arp_pin_revalidate = s.drops.arp_pin_revalidate.wrapping_add(revalidations);
    }

    // A permanent pin that has gone unconfirmed must be re-earned by a live
    // exchange rather than trusted indefinitely.
    if let Some(ip) = arp::revalidation_due(&s.arp_table) {
        if ip == s.gateway && s.gateway != 0 && !s.gw_pin_pending {
            arm_gateway_pin(s, s.gateway);
            return;
        }
    }

    // Retry an armed pin whose request could not go out because another
    // resolution held the single pending slot.
    if s.gw_pin_pending
        && s.gw_pin_ip != 0
        && s.arp_pending_state == arp::ARP_PENDING_NONE
        && arp::lookup(&s.arp_table, s.gw_pin_ip).is_none()
    {
        let gw = s.gw_pin_ip;
        let _ = resolve_mac(s, gw);
    }
}

/// Next-hop IPv4 for `dst` under the deliberately small route model: one
/// subnet plus one default gateway. `None` means there is no route — an
/// off-subnet destination with no gateway configured. ARPing directly for
/// such a destination would let anything on the local segment answer for an
/// address it does not own, so the send fails with `ENETUNREACH` instead.
fn next_hop(s: &IpState, dst: u32) -> Option<u32> {
    if dst == 0xFFFF_FFFF {
        return Some(dst);
    }
    if s.netmask == 0 || (dst & s.netmask) == (s.local_ip & s.netmask) {
        return Some(dst);
    }
    if s.gateway != 0 {
        Some(s.gateway)
    } else {
        None
    }
}

/// Resolve IP to MAC (returns cached entry or triggers ARP request).
unsafe fn resolve_mac(s: &mut IpState, ip: u32) -> Option<[u8; 6]> {
    // Broadcast
    if ip == 0xFFFFFFFF {
        return Some(eth::BROADCAST_MAC);
    }

    // Off-subnet destinations route through the default gateway; with no
    // gateway there is no route at all (see `next_hop`).
    let target_ip = match next_hop(s, ip) {
        Some(nh) => nh,
        None => {
            s.drops.route_unreachable = s.drops.route_unreachable.wrapping_add(1);
            return None;
        }
    };

    // Check ARP table
    if let Some(mac) = arp::lookup(&s.arp_table, target_ip) {
        return Some(mac);
    }

    // Send ARP request if not already pending
    if s.arp_pending_state == arp::ARP_PENDING_NONE && s.mac_valid && s.local_ip != 0 {
        s.arp_pending_ip = target_ip;
        s.arp_pending_state = arp::ARP_PENDING_WAITING;
        s.arp_pending_timer = 0;

        let frame_len = arp::build_arp(
            s.tx_frame.as_mut_ptr(),
            arp::ARP_REQUEST,
            &s.mac_addr,
            s.local_ip,
            &eth::BROADCAST_MAC,
            target_ip,
        );
        send_frame(s, s.tx_frame.as_ptr(), frame_len);
    }

    None
}

// ============================================================================
// DHCP
// ============================================================================

/// Drive the DHCP state machine.
unsafe fn step_dhcp(s: &mut IpState) {
    if !s.mac_valid {
        return;
    }

    s.dhcp.timer = s.dhcp.timer.wrapping_add(1);

    match s.dhcp.state {
        dhcp::DhcpState::Idle => {
            // Start DHCP discovery — generate an unpredictable XID from the
            // kernel CSPRNG to avoid precomputable race attacks.
            if s.dhcp.xid == 0 {
                let sys = &*s.syscalls;
                let mut xid_bytes = [0u8; 4];
                if dev_csprng_fill(sys, xid_bytes.as_mut_ptr(), 4) < 0 {
                    // Fall back to a step-count derivation if the CSPRNG is
                    // unavailable — better than 0 (which parse_dhcp_reply
                    // rejects) and better than reusing the boot constant.
                    s.dhcp.xid = s.step_count.wrapping_mul(2654435761).wrapping_add(1);
                } else {
                    s.dhcp.xid = u32::from_le_bytes(xid_bytes);
                    if s.dhcp.xid == 0 {
                        s.dhcp.xid = 1;
                    }
                }
            }
            s.dhcp.retries = 0;
            send_dhcp_discover(s);
            s.dhcp.state = dhcp::DhcpState::Discovering;
            s.dhcp.timer = 0;
        }
        dhcp::DhcpState::Discovering => {
            // Retransmit after ~2 seconds (2000 steps at ~1ms)
            if s.dhcp.timer > 2000 {
                s.dhcp.retries += 1;
                if s.dhcp.retries < 10 {
                    send_dhcp_discover(s);
                    s.dhcp.timer = 0;
                } else {
                    // Give up, retry from idle (keep same XID)
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.timer = 0;
                    s.dhcp.retries = 0;
                }
            }
        }
        dhcp::DhcpState::Requesting => {
            // Retransmit after ~2 seconds (2000 steps at ~1ms)
            if s.dhcp.timer > 2000 {
                s.dhcp.retries += 1;
                if s.dhcp.retries < 10 {
                    send_dhcp_request(s);
                    s.dhcp.timer = 0;
                } else {
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.timer = 0;
                    s.dhcp.retries = 0;
                }
            }
        }
        dhcp::DhcpState::Bound => {
            // Track lease expiry (RFC 2131 §4.4.5). T1 = 0.5 * lease, T2 =
            // 0.875 * lease. On T1, send a unicast REQUEST (renewal). At
            // expiry, drop back to Idle and start a fresh discover.
            if s.dhcp.lease_duration > 0 {
                let elapsed = s.step_count.wrapping_sub(s.dhcp.lease_start);
                if elapsed >= s.dhcp.lease_duration {
                    s.ip_configured = false;
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.xid = 0;
                    s.dhcp.timer = 0;
                    s.dhcp.renew_sent = false;
                } else if !s.dhcp.renew_sent && elapsed >= s.dhcp.lease_duration / 2 {
                    s.dhcp.renew_sent = true;
                    send_dhcp_request(s);
                }
            }
        }
    }
}

unsafe fn send_dhcp_discover(s: &mut IpState) {
    log_info(s, b"[ip] dhcp discover tx");
    let frame_len = dhcp::build_dhcp_message(
        s.tx_frame.as_mut_ptr(),
        dhcp::DHCP_DISCOVER,
        &s.mac_addr,
        s.dhcp.xid,
        0,
        0,
    );
    send_frame(s, s.tx_frame.as_ptr(), frame_len);
}

unsafe fn send_dhcp_request(s: &mut IpState) {
    let frame_len = dhcp::build_dhcp_message(
        s.tx_frame.as_mut_ptr(),
        dhcp::DHCP_REQUEST,
        &s.mac_addr,
        s.dhcp.xid,
        s.dhcp.offered_ip,
        s.dhcp.server_ip,
    );
    send_frame(s, s.tx_frame.as_ptr(), frame_len);
}

/// Process a DHCP reply (called from UDP handler).
unsafe fn process_dhcp_reply(s: &mut IpState, data: *const u8, len: usize) {
    let bootp_compat = s.dhcp_compat != 0;
    let client_mac = s.mac_addr;
    let parsed = match dhcp::parse_dhcp_reply(data, len, s.dhcp.xid, &client_mac, bootp_compat) {
        Some(p) => p,
        None => {
            s.drops.dhcp_uncorrelated = s.drops.dhcp_uncorrelated.wrapping_add(1);
            return;
        }
    };
    let dhcp::DhcpReply {
        msg_type,
        offered_ip,
        server_ip,
        subnet_mask,
        gateway,
        dns,
        lease_time,
    } = parsed;

    // Reject replies from servers other than the configured one.
    if s.dhcp.expected_server != 0 && server_ip != s.dhcp.expected_server {
        log_info(s, b"[ip] dhcp reject: unexpected server");
        s.drops.dhcp_uncorrelated = s.drops.dhcp_uncorrelated.wrapping_add(1);
        return;
    }

    // The mask actually adopted is validated, not the one on the wire: an
    // absent option 1 means the /24 default below, and validating the raw
    // zero would check a mask the stack never uses (making every gateway
    // look on-subnet and every host part look valid).
    let effective_mask = if subnet_mask != 0 {
        subnet_mask
    } else {
        0xFFFF_FF00
    };

    // Sanity-check the offered configuration.
    if !dhcp::validate_dhcp_config(offered_ip, effective_mask, gateway, lease_time) {
        log_info(s, b"[ip] dhcp reject: invalid config");
        return;
    }

    match msg_type {
        dhcp::DHCP_OFFER => {
            log_info(s, b"[ip] dhcp offer rx");
            if s.dhcp.state == dhcp::DhcpState::Discovering {
                s.dhcp.offered_ip = offered_ip;
                s.dhcp.server_ip = server_ip;
                s.dhcp.subnet_mask = effective_mask;
                s.dhcp.gateway = gateway;
                s.dhcp.dns_server = dns;
                s.dhcp.lease_time = lease_time;
                s.dhcp.state = dhcp::DhcpState::Requesting;
                s.dhcp.timer = 0;
                s.dhcp.retries = 0;
                send_dhcp_request(s);
            }
        }
        dhcp::DHCP_ACK => {
            log_info(s, b"[ip] dhcp ack rx");
            // An ACK completes the exchange the REQUEST started, so it must
            // come from the server we selected and name the address we asked
            // for. Without both bindings any server on the segment can
            // answer a REQUEST addressed to another, and a changed `yiaddr`
            // silently redirects the client's identity.
            // `server_ip == 0` covers a selection made from an OFFER that
            // carried no server identifier; there is then nothing to bind to
            // and the address match is the whole correlation.
            let matches_selection = (s.dhcp.server_ip == 0 || server_ip == s.dhcp.server_ip)
                && offered_ip == s.dhcp.offered_ip;
            let bound_to_offer = s.dhcp.state == dhcp::DhcpState::Requesting && matches_selection;
            // A renewal REQUEST is sent from BOUND and its ACK arrives there;
            // it must match the same server and address as the lease it
            // renews.
            let renewal =
                s.dhcp.state == dhcp::DhcpState::Bound && s.dhcp.renew_sent && matches_selection;
            // A server that ACKs a DISCOVER without offering first (some
            // embedded servers, QEMU SLIRP) skips the selection step
            // entirely; there is then no offer to bind the ACK to.
            let direct_ack = s.dhcp.state == dhcp::DhcpState::Discovering && s.dhcp_compat != 0;
            if !bound_to_offer && !renewal && !direct_ack {
                log_info(s, b"[ip] dhcp reject: ack does not match offer");
                s.drops.dhcp_uncorrelated = s.drops.dhcp_uncorrelated.wrapping_add(1);
                return;
            }
            {
                // Distinguish first acquisition from a lease renewal: only a
                // renewal announces (gratuitous ARP for slot 0). Initial
                // bind stays byte-identical to pre-multi-address behaviour.
                let renewing = s.dhcp.renew_sent;
                s.local_ip = offered_ip;
                s.netmask = effective_mask;
                s.gateway = gateway;
                s.dns_server = dns;
                // Mirror the primary identity into slot 0 of the address table.
                sync_primary_slot(s);
                if renewing {
                    send_gratuitous_arp(s, s.local_ip);
                }
                s.ip_configured = true;
                s.dhcp.state = dhcp::DhcpState::Bound;
                s.dhcp.lease_start = s.step_count;
                // Convert lease seconds into step ticks (one step = 100 µs or 1 ms
                // depending on config; we approximate by treating step_count as
                // an opaque tick counter and multiplying by 1000 to get ms).
                s.dhcp.lease_duration = lease_time.saturating_mul(1000);
                s.dhcp.renew_sent = false;
                // Resolve the gateway afresh, then pin the mapping that
                // exchange produces (see `arm_gateway_pin`).
                if s.gateway != 0 {
                    let gw = s.gateway;
                    arm_gateway_pin(s, gw);
                }

                // Log the assigned IP address with startup timing
                {
                    let sys = &*s.syscalls;
                    let ms = dev_millis(sys);
                    let mut buf = [0u8; 50];
                    let bp = buf.as_mut_ptr();
                    let prefix = b"[ip] dhcp bound ";
                    let mut i = 0;
                    while i < prefix.len() {
                        *bp.add(i) = prefix[i];
                        i += 1;
                    }
                    i += fmt_ip_raw(bp.add(i), s.local_ip);
                    let mid = b" T+";
                    let mut m = 0;
                    while m < mid.len() {
                        *bp.add(i) = mid[m];
                        i += 1;
                        m += 1;
                    }
                    i += fmt_u32_raw(bp.add(i), ms as u32);
                    *bp.add(i) = b'm';
                    i += 1;
                    *bp.add(i) = b's';
                    i += 1;
                    dev_log(sys, 1, bp, i);
                }
            }
        }
        dhcp::DHCP_NAK => {
            s.dhcp.state = dhcp::DhcpState::Idle;
            s.dhcp.timer = 0;
        }
        _ => {}
    }
}

// ============================================================================
// Net Protocol Channel Service
// ============================================================================

/// True iff the connection state allows queueing new outbound data.
/// Established: normal full-duplex. CloseWait: peer FIN'd but our
/// half is still open per RFC 793 — we can keep sending until our
/// own FIN. Anything else (FinWait1+/Closing/LastAck/TimeWait/Closed)
/// has either already sent FIN or has no socket to deliver to.
#[inline(always)]
fn state_allows_send(state: tcp::TcpState) -> bool {
    matches!(state, tcp::TcpState::Established | tcp::TcpState::CloseWait)
}

/// Apply the CLOSE half-handshake for `conn_id`. Returns `true` iff
/// the action completed (FIN queued AND state advanced, or the
/// listening / already-closed branches that don't need a frame).
/// Returns `false` only when the FIN couldn't be queued — the caller
/// (CMD_CLOSE arm or pending_close retry) must keep the close
/// pending and re-fire next tick.
///
/// Mirrors RFC 793 §3.5: from Established → FIN_WAIT_1 (we initiate
/// close); from CloseWait → LAST_ACK (peer FIN'd first). State only
/// advances on successful FIN queue, so a backpressured FIN doesn't
/// strand the conn in FinWait1 with no frame on the wire.
/// Serve a CMD_CONNECT addressed to this host (see `loopback_peer`):
/// find the local listener, bind a conn-slot PAIR as `Established`,
/// and notify both consumers. Failure surfaces exactly like the TCP
/// path's: ECONNREFUSED when nothing listens, ENOMEM when the table
/// is full — a consumer cannot tell the fastpath from a real connect.
unsafe fn connect_loopback(s: &mut IpState, port: u16, requester_tag: u8) {
    // A listener must exist BEFORE the pair is allocated.
    if find_listener_indexed(s, port, tcp::LOCAL_SLOT_ANY, false).is_none() {
        let _ = net_send_error(s, 0, -111, requester_tag); // ECONNREFUSED
        return;
    }

    // Two free slots: the connector's and the accepted side's.
    let ci: i32 = alloc_free_slot(s).map(|i| i as i32).unwrap_or(-1);
    let mut si: i32 = alloc_free_slot(s).map(|i| i as i32).unwrap_or(-1);
    if si == ci {
        si = alloc_free_slot(s).map(|i| i as i32).unwrap_or(-1);
        if si == ci {
            si = -1;
        }
    }
    if ci < 0 || si < 0 {
        let _ = net_send_error(s, 0, -12, requester_tag); // ENOMEM
        return;
    }
    let (ci, si) = (ci as usize, si as usize);
    let local_port = match next_port(s) {
        Some(p) => p,
        None => {
            let _ = net_send_error(s, 0, -99, requester_tag); // EADDRNOTAVAIL
            return;
        }
    };

    // Established immediately — there is no handshake to perform.
    // `remote_ip` stays 0 so no close path ever touches the ARP table
    // and no incoming segment's 4-tuple can match these slots.
    {
        let c = &mut *s.tcp_conns.as_mut_ptr().add(ci);
        c.state = tcp::TcpState::Established;
        c.remote_ip = 0;
        c.remote_port = port;
        c.local_port = local_port;
        c.local_slot = 0;
        c.connect_tag = requester_tag;
        c.retransmit_timer = 0;
    }
    {
        let v = &mut *s.tcp_conns.as_mut_ptr().add(si);
        v.state = tcp::TcpState::Established;
        v.remote_ip = 0;
        v.remote_port = local_port;
        v.local_port = port;
        v.local_slot = 0;
        v.connect_tag = 0;
        v.retransmit_timer = 0;
    }
    // Both slots go through the same admission `conn_reset` undoes. A
    // loopback pair is not keyed (`remote_ip == 0`), does not listen and is
    // not half-open, so the only thing this does is take the port
    // references teardown gives back — and taking them anywhere else would
    // put the two halves out of step, which reads as a listener's port
    // falling to zero while the listener is still bound.
    // Both slots go through the same admission `conn_reset` undoes. A
    // loopback pair is not keyed (`remote_ip == 0`), does not listen and is
    // not half-open, so the only thing this does is take the port
    // references teardown gives back — and taking them anywhere else would
    // put the two halves out of step, which reads as a listener's port
    // falling to zero while the listener is still bound.
    conn_index_insert(s, ci);
    conn_index_insert(s, si);
    s.loopback_peer[ci] = si as i32;
    s.loopback_peer[si] = ci as i32;

    // Listener first (it filters MSG_ACCEPTED by `local_port`), then
    // the connector. `net_send_or_queue` holds these across full
    // rings; if even the queue is full, tear the pair down — half a
    // notification would strand one side forever.
    if !net_send_accepted(s, si as u16, port) || !net_send_connected(s, ci as u16) {
        s.loopback_peer[ci] = -1;
        s.loopback_peer[si] = -1;
        conn_reset(s, ci);
        conn_reset(s, si);
        let _ = net_send_error(s, 0, -12, requester_tag);
        return;
    }
    log_info(s, b"[ip] loopback pair");
}

/// Tear down a loopback pair from either end: both consumers get
/// MSG_CLOSED, both slots free. Mirrors a FIN'd TCP close as seen
/// from the net-proto surface.
unsafe fn close_loopback(s: &mut IpState, conn_id: usize) {
    let peer = s.loopback_peer[conn_id];
    s.loopback_peer[conn_id] = -1;
    conn_reset(s, conn_id);
    let _ = net_send_closed(s, conn_id as u16);
    if peer >= 0 {
        let pi = peer as usize;
        s.loopback_peer[pi] = -1;
        conn_reset(s, pi);
        let _ = net_send_closed(s, peer as u16);
    }
}

unsafe fn process_cmd_close(s: &mut IpState, conn_id: usize) -> bool {
    if conn_id >= tcp::MAX_TCP_CONNS {
        return true;
    }
    if s.loopback_peer[conn_id] >= 0 {
        close_loopback(s, conn_id);
        return true;
    }
    let conn_state = (*s.tcp_conns.as_ptr().add(conn_id)).state;
    match conn_state {
        tcp::TcpState::Established => {
            let seq = (*s.tcp_conns.as_ptr().add(conn_id)).snd_nxt;
            if !continuity::fin_gate(s, conn_id)
                || !send_tcp_control(s, conn_id, tcp::FIN | tcp::ACK, false)
            {
                return false;
            }
            (*s.tcp_conns.as_mut_ptr().add(conn_id)).state = tcp::TcpState::FinWait1;
            continuity::on_sent(s, conn_id, seq, 0, true);
            continuity::on_state(s, conn_id);
            true
        }
        tcp::TcpState::CloseWait => {
            let seq = (*s.tcp_conns.as_ptr().add(conn_id)).snd_nxt;
            if !continuity::fin_gate(s, conn_id)
                || !send_tcp_control(s, conn_id, tcp::FIN | tcp::ACK, false)
            {
                return false;
            }
            (*s.tcp_conns.as_mut_ptr().add(conn_id)).state = tcp::TcpState::LastAck;
            continuity::on_sent(s, conn_id, seq, 0, true);
            continuity::on_state(s, conn_id);
            true
        }
        tcp::TcpState::Listen => {
            // Close a listening socket
            conn_reset(s, conn_id);
            net_send_closed(s, conn_id as u16);
            true
        }
        _ => {
            // Already closing/closed — reset and notify
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_id)).remote_ip;
            if remote_ip != 0 {
                arp::unpin(&mut s.arp_table, remote_ip);
            }
            conn_reset(s, conn_id);
            net_send_closed(s, conn_id as u16);
            true
        }
    }
}

/// Drain a buffered CMD_SEND payload starting at byte `start_off`
/// (where byte 0 is `conn_id` and bytes 1.. are the data). Emits up
/// to `MSS` bytes per TCP segment, capped by the peer's effective
/// send window. Returns the new data offset.
///
/// Three terminal cases:
///   * `data_off == payload_len`: fully drained. Caller clears stash.
///   * `data_off < payload_len` AND state still allows send: peer
///     window or NIC backpressure stalled the drain. Caller stashes
///     (or leaves stash) for retry.
///   * `data_off < payload_len` AND state no longer allows send:
///     conn went Closed/RST/FinWait* mid-drain. Returns `payload_len`
///     so the caller clears the stash — the remaining bytes are
///     unrecoverable (peer is gone or our FIN already shipped).
unsafe fn try_send_cmd_payload(
    s: &mut IpState,
    conn_id: usize,
    payload: *const u8,
    payload_len: usize,
    start_off: usize,
) -> usize {
    let mut data_off = start_off;
    // Loopback pair: no segmentation, no windows — each chunk becomes
    // one MSG_DATA tagged with the PEER's conn id, sized to the
    // net_out scratch frame. A rejected write returns the offset so
    // the caller's pending-cmd stash resumes next tick, exactly like
    // a closed TCP window.
    if s.loopback_peer[conn_id] >= 0 {
        let peer = s.loopback_peer[conn_id] as u16;
        let max_chunk = s.net_scratch.len() - NET_FRAME_HDR - 2;
        while data_off < payload_len {
            if s.loopback_peer[conn_id] < 0 {
                return payload_len; // peer closed mid-send — drop the tail
            }
            let chunk = (payload_len - data_off).min(max_chunk);
            if !net_send_data(s, peer, payload.add(data_off), chunk) {
                return data_off;
            }
            data_off += chunk;
        }
        return payload_len;
    }
    while data_off < payload_len {
        let conn_state = (*s.tcp_conns.as_ptr().add(conn_id)).state;
        if !state_allows_send(conn_state) {
            return payload_len;
        }
        let conn = &*s.tcp_conns.as_ptr().add(conn_id);
        let eff_wnd = tcp::effective_snd_wnd(conn) as usize;
        let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
        let avail_wnd = eff_wnd.saturating_sub(in_flight);
        if avail_wnd == 0 {
            // Peer's window closed — stash and wait for an ACK to open it.
            return data_off;
        }
        let chunk = (payload_len - data_off)
            .min(tcp::MSS as usize)
            .min(avail_wnd);
        if chunk == 0 {
            return data_off;
        }
        let seq = conn.snd_nxt;
        let tick = s.step_count as u16;
        // A strict mirror sees the allocation before the wire does.
        if !continuity::send_gate(s, conn_id, seq, chunk as u16) {
            return data_off;
        }
        let ok = send_tcp_data(s, conn_id, payload.add(data_off), chunk);
        if !ok {
            // NIC out_chan full or ARP miss. snd_nxt was NOT advanced —
            // stash the unsent tail and retry next tick.
            return data_off;
        }
        continuity::on_sent(s, conn_id, seq, chunk as u16, false);
        let conn2 = &mut *s.tcp_conns.as_mut_ptr().add(conn_id);
        tcp::rtt_arm(conn2, seq, tick);
        data_off += chunk;
    }
    data_off
}

/// Add a secondary local address (`IP_ADDR_ADD`). No-op if the IPv4 word is
/// zero, if the address is already configured (primary or secondary — only
/// owner/prefix are refreshed then), or if the table is full. Sends a single
/// same-subnet gratuitous ARP on first insertion. owner_tag stamps the
/// slot's owner and is enforced on bind (see `slot_for_owner` /
/// `find_listener`).
unsafe fn addr_ctl_add(
    s: &mut IpState,
    addr16: *const u8,
    prefix_len: u8,
    owner_tag: u16,
    flags: u8,
) {
    let ipv4 = u32::from_be_bytes([*addr16, *addr16.add(1), *addr16.add(2), *addr16.add(3)]);
    if ipv4 == 0 {
        return;
    }
    let mut a16 = [0u8; 16];
    core::ptr::copy_nonoverlapping(addr16, a16.as_mut_ptr(), 16);
    if let Some(slot) = local_slot_for_dst(s, ipv4) {
        // Already present. Slot 0 (primary) is off-limits to addr_ctl; a
        // secondary just refreshes owner/prefix without re-announcing and
        // keeps its token, generation and emission state.
        if slot != 0 {
            let a = &mut s.local_addrs[slot as usize];
            a.prefix_len = prefix_len;
            a.owner_tag = owner_tag;
        }
        return;
    }
    let mut i = 1;
    while i < MAX_LOCAL_ADDRS {
        if !s.local_addrs[i].is_active() {
            // A token first: an install with no token would be one nobody
            // could ever fence, so it is refused rather than made.
            let Some(token) = mint_token(s) else {
                log_info(s, b"[ip] addr_ctl add: no entropy for a token");
                addr_evt_refused(s, &a16, IP_ADDR_ADD, netid::refusal::NO_ENTROPY);
                return;
            };
            s.addr_generation = s.addr_generation.wrapping_add(1);
            let generation = s.addr_generation;
            let armed = flags & netid::install::DISARMED == 0;
            let a = &mut s.local_addrs[i];
            a.addr = a16;
            a.token = token;
            a.generation = generation;
            a.prefix_len = prefix_len;
            a.owner_tag = owner_tag;
            a.flags = if armed { ADDR_FLAG_ARMED } else { 0 };
            let _ = index::insert(&mut s.addr_index, index::mix32(ipv4 ^ s.index_seed), i);
            log_info(s, b"[ip] addr_ctl add");
            let mut p = [0u8; 36];
            p[..16].copy_from_slice(&a16);
            p[16..32].copy_from_slice(&token);
            p[32..36].copy_from_slice(&generation.to_le_bytes());
            addr_evt(s, netid::MSG_ADDR_ADDED, &p);
            // GARP only teaches the local segment, so announce same-subnet
            // additions only (§3.3), and only an armed one — a disarmed
            // install says nothing until it is armed.
            if armed
                && s.netmask != 0
                && s.local_ip != 0
                && (ipv4 & s.netmask) == (s.local_ip & s.netmask)
            {
                send_gratuitous_arp(s, ipv4);
            }
            return;
        }
        i += 1;
    }
    log_info(s, b"[ip] addr_ctl add: table full");
    addr_evt_refused(s, &a16, IP_ADDR_ADD, netid::refusal::TABLE_FULL);
}

/// Remove a secondary local address (`IP_ADDR_DEL`). The slot ages out
/// immediately; established conns latched to it keep their concrete slot and
/// fall back to sourcing from the primary (they close naturally). The primary
/// (slot 0) is not removable via addr_ctl.
unsafe fn addr_ctl_del(s: &mut IpState, ipv4: u32) {
    if ipv4 == 0 {
        return;
    }
    match local_slot_for_dst(s, ipv4) {
        Some(slot) if slot != 0 => {
            let addrs = s.local_addrs.as_ptr();
            let seed = s.index_seed;
            let _ = index::remove(
                &mut s.addr_index,
                index::mix32(ipv4 ^ seed),
                slot as usize,
                |i| index::mix32((*addrs.add(i)).ipv4() ^ seed),
            );
            s.local_addrs[slot as usize] = LocalAddr::empty();
            log_info(s, b"[ip] addr_ctl del");
        }
        _ => {}
    }
}

/// Drain the address-control port (in[2]) and apply IP_ADDR_ADD / IP_ADDR_DEL.
/// Single writer = the platform workload backend. No-op — and byte-identical —
/// when the port is unwired.
unsafe fn service_addr_ctl(s: &mut IpState) {
    if s.addr_ctl_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    // Bounded per step: a full table's worth of ops is ample; anything more
    // waits for the next tick (the port is low-rate control, not data).
    let mut count = 0;
    while count <= MAX_LOCAL_ADDRS {
        let mut buf = [0u8; 32];
        let (msg_type, payload_len) =
            ip_net_read_frame(sys, s.addr_ctl_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 {
            break;
        }
        let plen = payload_len as usize;
        match msg_type {
            // [addr:16][prefix_len:1][owner_tag:2 LE][flags:1]?
            IP_ADDR_ADD if plen >= netid::ADDR_ADD_PAYLOAD_LEN => {
                let prefix_len = *buf.as_ptr().add(netid::ADD_PREFIX_LEN_OFF);
                let owner_tag = u16::from_le_bytes([
                    *buf.as_ptr().add(netid::ADD_OWNER_TAG_OFF),
                    *buf.as_ptr().add(netid::ADD_OWNER_TAG_OFF + 1),
                ]);
                let flags = if plen > netid::ADD_FLAGS_OFF {
                    *buf.as_ptr().add(netid::ADD_FLAGS_OFF)
                } else {
                    0
                };
                addr_ctl_add(s, buf.as_ptr(), prefix_len, owner_tag, flags);
            }
            // [addr:16][token:16]
            IP_ADDR_ARM | IP_ADDR_FENCE if plen >= netid::ADDR_TOKEN_PAYLOAD_LEN => {
                let mut a16 = [0u8; 16];
                let mut token = [0u8; 16];
                a16.copy_from_slice(&buf[..16]);
                token.copy_from_slice(&buf[netid::TOKEN_OFF..netid::TOKEN_OFF + 16]);
                if msg_type == IP_ADDR_ARM {
                    addr_ctl_arm(s, &a16, &token);
                } else {
                    addr_ctl_fence(s, &a16, &token);
                }
            }
            // [addr:16]
            IP_ADDR_DEL if plen >= netid::ADDR_DEL_PAYLOAD_LEN => {
                let bp = buf.as_ptr();
                let ipv4 = u32::from_be_bytes([*bp, *bp.add(1), *bp.add(2), *bp.add(3)]);
                addr_ctl_del(s, ipv4);
            }
            _ => {}
        }
        count += 1;
    }
}

/// Read and dispatch net protocol commands from the consumer channel.
unsafe fn service_net_channels(s: &mut IpState) {
    if s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    // Pause command intake when outbound headroom is low: each
    // BIND / CONNECT / CLOSE produces a matching control event, and
    // reading more while we can't queue the responses just risks
    // overflow. The pause propagates backpressure into the
    // consumer's write to `net_in_chan`.
    if NET_OUT_QUEUE_SLOTS - s.pending_net_out_count as usize <= NET_OUT_QUEUE_HEADROOM {
        s.pend_txq_steps = s.pend_txq_steps.wrapping_add(1);
        return;
    }

    // Resume a stashed CMD_SEND tail before touching `net_in_chan`.
    // Holding off on the read propagates backpressure to the consumer
    // (its `channel_write` into `net_in_chan` stalls when the ring
    // fills).
    if s.pending_cmd_valid != 0 {
        let conn_id = s.pending_cmd_conn as usize;
        let total_len = s.pending_cmd_len as usize;
        let off = s.pending_cmd_off as usize;
        let new_off = try_send_cmd_payload(s, conn_id, s.pending_cmd_buf.as_ptr(), total_len, off);
        if new_off >= total_len {
            s.pending_cmd_valid = 0;
            s.pending_cmd_off = 0;
            s.pending_cmd_len = 0;
            s.tx_cmd_items = s.tx_cmd_items.wrapping_add(1);
        } else {
            s.pending_cmd_off = new_off as u16;
            s.pend_cmd_steps = s.pend_cmd_steps.wrapping_add(1);
            return;
        }
    }

    // RFC 793 §3.5: CLOSE transmits all queued SENDs first. With the
    // stash drained, fire any deferred FIN before reading new frames.
    // If `process_cmd_close` couldn't queue the FIN, leave the slot
    // valid and retry next tick — state stays sendable until the FIN
    // is actually on the wire.
    if s.pending_close_valid != 0 {
        let conn_id = s.pending_close_conn as usize;
        if process_cmd_close(s, conn_id) {
            s.pending_close_valid = 0;
        } else {
            return;
        }
    }

    // Process up to 32 commands per step. Producers (http, etc.)
    // stage many MSS-sized CMD_SENDs in a single tick; this batch
    // limit caps single-connection throughput at one MSS per command,
    // sitting well below the burst-iteration limit on aarch64 yet
    // high enough to saturate gigabit.
    //
    // `buf` must be ≥ the largest single CMD_SEND payload — the
    // upstream cap is `NET_BUF_SIZE`, matched here by
    // `PENDING_CMD_BUF_SIZE`. An undersized buffer would truncate
    // the payload and corrupt the next frame's header parse.
    let mut count = 0;
    while count < 32 {
        // Headroom check has to repeat every iteration: each command
        // synthesises a control event, and a once-per-call gate would
        // let a burst run the queue dry mid-loop.
        if NET_OUT_QUEUE_SLOTS - s.pending_net_out_count as usize <= NET_OUT_QUEUE_HEADROOM {
            break;
        }
        let mut buf = [0u8; PENDING_CMD_BUF_SIZE];
        let (msg_type, payload_len) =
            ip_net_read_frame(sys, s.net_in_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 {
            break;
        }

        let plen = payload_len as usize;

        match msg_type {
            NET_CMD_BIND => {
                // Payload: [port: u16 LE]                        host/wildcard
                //     or   [port: u16 LE][owner_tag: u16 LE]     owner-stamped
                // The optional trailing owner_tag is the bind-admission axis.
                // It is stamped by the trusted upstream on behalf of the
                // binding workload; the ip module cannot itself learn the
                // commanding owner (the module syscall ABI exposes no owner
                // query), so the stamp comes from the workload-backend or
                // ingress path. Absent or 0 ⇒ host wildcard.
                if plen >= 2 {
                    let port = u16::from_le_bytes([*buf.as_ptr(), *buf.as_ptr().add(1)]);
                    let owner_tag = if plen >= 4 {
                        u16::from_le_bytes([*buf.as_ptr().add(2), *buf.as_ptr().add(3)])
                    } else {
                        0
                    };
                    // Resolve the target local-address slot for this bind.
                    // owner 0 → wildcard (host). A nonzero owner must own a
                    // configured address here; if it does not, the bind is
                    // refused — the metal analogue of the Linux lease-owner
                    // gate.
                    let target_slot = if owner_tag == 0 {
                        LOCAL_SLOT_ANY
                    } else {
                        match slot_for_owner(s, owner_tag) {
                            Some(si) => si,
                            None => {
                                log_info(s, b"[ip] net bind: refused (owner has no addr)");
                                // EACCES — cross-owner / no-lease bind refusal.
                                // Signalled via the module's MSG_ERROR frame
                                // ([conn_id=0][errno][tag]), the ip module's
                                // established bind-failure channel (matches the
                                // no-free-conn ENOMEM path below).
                                net_send_error(s, 0, -13, 0);
                                count += 1;
                                continue;
                            }
                        }
                    };
                    // Idempotent bind: if a TCP listener for this
                    // `(port, target_slot)` already exists, re-emit MSG_BOUND
                    // for it. The BSD-accept path keeps the listener in
                    // `Listen` across accepted connections, so a defensive
                    // re-bind from a caller would otherwise grow a duplicate
                    // listener every cycle and exhaust MAX_TCP_CONNS. The slot
                    // axis is part of the key so the same port bound at two
                    // owned addresses stays two distinct listeners.
                    // The listener list is the whole search space, and
                    // datagram endpoints are never on it, so a UDP slot on
                    // the same port cannot satisfy a TCP bind.
                    let mut existing: Option<usize> = None;
                    let mut li = 0;
                    while li < MAX_LISTENERS {
                        let e = s.listeners[li];
                        if e != 0 {
                            let idx = (e - 1) as usize;
                            let conn = &*s.tcp_conns.as_ptr().add(idx);
                            if conn.state == tcp::TcpState::Listen
                                && !conn.is_datagram
                                && conn.local_port == port
                                && conn.local_slot == target_slot
                            {
                                existing = Some(idx);
                                break;
                            }
                        }
                        li += 1;
                    }
                    if let Some(idx) = existing {
                        log_info(s, b"[ip] net bind: existing listener");
                        net_send_bound(s, idx as u16, port);
                    } else {
                        let found = alloc_free_slot(s);
                        if let Some(ci) = found {
                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                            conn.state = tcp::TcpState::Listen;
                            conn.local_port = port;
                            conn.remote_ip = 0;
                            conn.remote_port = 0;
                            conn.retransmit_timer = 0;
                            // Wildcard (host) or the owner's own slot.
                            // Reset explicitly — this path reuses a slot
                            // without a full `TcpConn::new()`.
                            conn.local_slot = target_slot;
                            conn_index_insert(s, ci);
                            log_info(s, b"[ip] net bind");
                            net_send_bound(s, ci as u16, port);
                        } else {
                            log_info(s, b"[ip] net bind: no free conn");
                            net_send_error(s, 0, -12, 0); // ENOMEM (bind — untagged)
                        }
                    }
                }
            }
            NET_CMD_CONNECT => {
                // Stream Surface v1: open a TCP outbound connection.
                // Payload: [sock_type: u8 = SOCK_TYPE_STREAM] [ip: u32 LE] [port: u16 LE].
                // Only TCP is accepted here; UDP uses the `datagram`
                // surface (`CMD_DG_BIND` + `CMD_DG_SEND_TO`).
                if plen >= 7 {
                    let bp = buf.as_ptr();
                    let sock_type = *bp;
                    // Optional trailing requester tag (8-byte form); echoed in
                    // MSG_CONNECTED / connect-failure MSG_ERROR so a fanned
                    // net_out routes the event back to the requester.
                    let requester_tag = if plen >= 8 { *bp.add(7) } else { 0 };
                    if sock_type != SOCK_TYPE_STREAM {
                        net_send_error(s, 0, -22, requester_tag); // EINVAL
                    } else {
                        let ip =
                            u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)]);
                        let port = u16::from_le_bytes([*bp.add(5), *bp.add(6)]);

                        // LOCAL-DELIVERY FASTPATH: a connect to this host's
                        // own address (or 127.0.0.1) is served entirely
                        // in-module — see `loopback_peer`. Consumers encode
                        // the address bytes so this LE parse yields the same
                        // numeric form `s.local_ip` holds (pg_client et al.
                        // reverse the endpoint bytes into the payload).
                        if ip == 0x7F00_0001 || (s.local_ip != 0 && ip == s.local_ip) {
                            connect_loopback(s, port, requester_tag);
                            count += 1;
                            continue;
                        }

                        let conn_id: i32 = match alloc_free_slot(s) {
                            Some(i) => i as i32,
                            None => -1,
                        };

                        if conn_id < 0 {
                            net_send_error(s, 0, -12, requester_tag); // ENOMEM
                        } else if !ensure_isn_secret(s) {
                            // EAGAIN — entropy may arrive later; the caller
                            // may retry, but the stack will not substitute a
                            // predictable sequence in the meantime.
                            net_send_error(s, 0, -11, requester_tag);
                        } else if let Some(local_port) = next_port(s) {
                            let ci = conn_id as usize;
                            let iss = compute_iss(s, s.local_ip, local_port, ip, port);

                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                            conn.state = tcp::TcpState::SynSent;
                            conn.remote_ip = ip;
                            conn.remote_port = port;
                            conn.local_port = local_port;
                            // Outbound/host traffic sources from slot 0 in v1;
                            // set it concretely so the peer's replies (dst =
                            // local_ip → slot 0) match on the demux axis. Reset
                            // explicitly — this path reuses a slot in place.
                            conn.local_slot = 0;
                            conn.connect_tag = requester_tag;
                            conn.iss = iss;
                            conn.snd_nxt = iss;
                            conn.snd_una = iss;
                            conn.rcv_wnd = 512;
                            conn.retransmit_timer = 0;
                            conn_index_insert(s, ci);

                            send_tcp_control(s, ci, tcp::SYN, false);
                        } else {
                            // EADDRNOTAVAIL — no ephemeral port available.
                            net_send_error(s, 0, -99, requester_tag);
                        }
                    }
                }
            }
            NET_CMD_SEND => {
                // Stream Surface v1: send TCP payload.
                // Payload: `[conn_id: u16 LE][data...]`. A single CMD_SEND
                // can carry many MSS; `try_send_cmd_payload` segments
                // into MSS-sized writes against the peer window, and
                // any unsent tail goes into `pending_cmd_*` for the
                // next tick.
                if plen >= 3 {
                    let conn_id =
                        u16::from_le_bytes([*buf.as_ptr(), *buf.as_ptr().add(1)]) as usize;
                    let total_len = plen;
                    if conn_id < tcp::MAX_TCP_CONNS && total_len <= PENDING_CMD_BUF_SIZE {
                        let conn_state = (*s.tcp_conns.as_ptr().add(conn_id)).state;
                        if state_allows_send(conn_state) {
                            // A payload the consumer sends is activity for
                            // the idle close, whether or not it ships now.
                            (*s.tcp_conns.as_mut_ptr().add(conn_id)).idle_timer = 0;
                            let new_off =
                                try_send_cmd_payload(s, conn_id, buf.as_ptr(), total_len, 2);
                            if new_off < total_len {
                                // Stash the buffer verbatim (conn_id
                                // at byte 0) so the resume path uses
                                // the same offsets, and stop reading
                                // — backpressure must propagate to
                                // the consumer.
                                core::ptr::copy_nonoverlapping(
                                    buf.as_ptr(),
                                    s.pending_cmd_buf.as_mut_ptr(),
                                    total_len,
                                );
                                s.pending_cmd_conn = conn_id as u16;
                                s.pending_cmd_off = new_off as u16;
                                s.pending_cmd_len = total_len as u16;
                                s.pending_cmd_valid = 1;
                                s.pend_cmd_steps = s.pend_cmd_steps.wrapping_add(1);
                                return;
                            }
                        }
                        // Conn not in a sendable state — drop. Upstream
                        // owns re-delivery (CMD_CLOSE raced CMD_SEND,
                        // or peer RST'd before delivery).
                    }
                }
            }
            NET_CMD_CLOSE => {
                // Payload: `[conn_id: u16 LE]`. Defer the FIN if there's
                // stashed CMD_SEND data still draining (RFC 793 §3.5:
                // CLOSE waits for queued SENDs to be transmitted) or
                // if the FIN frame itself can't be queued; the prelude
                // retry path resumes once the precondition clears.
                if plen >= 2 {
                    let conn_id =
                        u16::from_le_bytes([*buf.as_ptr(), *buf.as_ptr().add(1)]) as usize;
                    if conn_id < tcp::MAX_TCP_CONNS
                        && (s.pending_cmd_valid != 0 || !process_cmd_close(s, conn_id))
                    {
                        s.pending_close_valid = 1;
                        s.pending_close_conn = conn_id as u16;
                        return;
                    }
                }
            }
            DG_CMD_BIND => {
                // datagram bind. Payload: [port: u16 LE] [flags: u8]
                //   or owner-stamped: [port: u16 LE][flags: u8][owner_tag: u16 LE]
                // Port 0 requests ephemeral allocation. Provider responds
                // with MSG_DG_BOUND [ep_id, local_port]. The optional trailing
                // owner_tag is the same bind-admission axis as NET_CMD_BIND;
                // absent or 0 ⇒ host wildcard.
                if plen >= 2 {
                    let req_port = u16::from_le_bytes([*buf.as_ptr(), *buf.as_ptr().add(1)]);
                    let owner_tag = if plen >= 5 {
                        u16::from_le_bytes([*buf.as_ptr().add(3), *buf.as_ptr().add(4)])
                    } else {
                        0
                    };
                    // Resolve the owner's address slot before drawing a port:
                    // a bind that is going to be refused must not consume an
                    // ephemeral allocation.
                    let target_slot = if owner_tag == 0 {
                        Some(LOCAL_SLOT_ANY)
                    } else {
                        slot_for_owner(s, owner_tag)
                    };
                    let target_slot = match target_slot {
                        Some(si) => si,
                        None => {
                            log_info(s, b"[ip] dg bind: refused (owner has no addr)");
                            dg_send_error(s, 0, -13); // EACCES — cross-owner refusal
                            count += 1;
                            continue;
                        }
                    };
                    let port = if req_port == 0 {
                        // Collision-aware: `next_port` probes the live table
                        // for every candidate, so an ephemeral bind cannot
                        // land on a port another endpoint already holds.
                        match next_port(s) {
                            Some(p) => p,
                            None => {
                                log_info(s, b"[ip] dg bind: no ephemeral port");
                                dg_send_error(s, 0, -99); // EADDRNOTAVAIL
                                count += 1;
                                continue;
                            }
                        }
                    } else {
                        req_port
                    };

                    // Bind admission. A datagram endpoint's local identity is
                    // `(protocol, local_port, local_slot)`; the owner stamp
                    // distinguishes a retry by the holder from a second
                    // claimant. Two endpoints on the same port at two distinct
                    // concrete address slots are genuinely distinct sockets and
                    // both stand; anything whose reachability overlaps is a
                    // conflict, because delivery picks one and the other would
                    // silently never receive.
                    match dg_bind_admission(s, port, target_slot, owner_tag) {
                        DgBind::Existing(idx) => {
                            log_info(s, b"[ip] dg bind: existing endpoint");
                            dg_send_bound(s, idx as u8, port);
                            count += 1;
                            continue;
                        }
                        DgBind::Conflict => {
                            log_info(s, b"[ip] dg bind: in use");
                            s.drops.dg_bind_conflict = s.drops.dg_bind_conflict.wrapping_add(1);
                            dg_send_error(s, 0, -98); // EADDRINUSE
                            count += 1;
                            continue;
                        }
                        DgBind::Fresh => {}
                    }

                    match alloc_dg_slot(s) {
                        Some(ci) => {
                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                            *conn = tcp::TcpConn::new();
                            conn.state = tcp::TcpState::Listen;
                            conn.local_port = port;
                            conn.is_datagram = true;
                            // Wildcard (host) or the owner's own slot; the
                            // wildcard endpoint is not served on owned
                            // secondaries (see `process_udp_packet`).
                            conn.local_slot = target_slot;
                            conn.owner_tag = owner_tag;
                            conn_index_insert(s, ci);
                            log_info(s, b"[ip] dg bind");
                            dg_send_bound(s, ci as u8, port);
                        }
                        None => {
                            log_info(s, b"[ip] dg bind: no free conn");
                            dg_send_error(s, 0, -12); // ENOMEM
                        }
                    }
                }
            }
            DG_CMD_SEND_TO => {
                // datagram send. IPv4 payload:
                //   [ep_id:1][af:1=4][dst_addr:4 BE][dst_port:2 LE][data...]
                // Owner-tagged form inserts [MARK][owner_tag:2 LE] between
                // `ep_id` and `af`, so the tag sits at a fixed offset ahead of
                // the variable-length data rather than after it.
                let bp = buf.as_ptr();
                let (claimed_tag, dest_off) = dg_decode_owner_tag(bp, plen);
                if plen >= dest_off + DG_V4_DEST_LEN {
                    let ep_id = *bp as usize;
                    let af = *bp.add(dest_off);
                    if af == DG_AF_INET && ep_id < MAX_DG_ENDPOINTS {
                        let conn = &*s.tcp_conns.as_ptr().add(ep_id);
                        if !(conn.is_datagram && conn.state == tcp::TcpState::Listen) {
                            // The slot exists but holds no live datagram
                            // endpoint: a stale handle whose endpoint was
                            // closed, or a slot that was never bound.
                            s.drops.dg_ep_unowned = s.drops.dg_ep_unowned.wrapping_add(1);
                            dg_send_error(s, ep_id as u8, -88); // ENOTSOCK
                        } else if conn.owner_tag != claimed_tag {
                            // A live endpoint reached by a consumer that does
                            // not hold it. `ep_id` is an index; the tag is the
                            // authority.
                            s.drops.dg_ep_perm = s.drops.dg_ep_perm.wrapping_add(1);
                            dg_send_error(s, ep_id as u8, -1); // EPERM
                        } else {
                            let ap = bp.add(dest_off + 1);
                            let dst_ip =
                                u32::from_be_bytes([*ap, *ap.add(1), *ap.add(2), *ap.add(3)]);
                            let dst_port = u16::from_le_bytes([*ap.add(4), *ap.add(5)]);
                            let udp_data = bp.add(dest_off + DG_V4_DEST_LEN);
                            let udp_len = plen - dest_off - DG_V4_DEST_LEN;
                            let local_port = conn.local_port;
                            let rv =
                                send_udp_data(s, dst_ip, dst_port, local_port, udp_data, udp_len);
                            if rv != 0 {
                                dg_send_error(s, ep_id as u8, rv);
                            }
                        }
                    } else {
                        dg_send_error(s, ep_id as u8, -97); // EAFNOSUPPORT
                    }
                }
            }
            DG_CMD_CLOSE => {
                // datagram close. Payload: [ep_id: u8], or the owner-tagged
                // form [ep_id: u8][MARK][owner_tag: u16 LE].
                if plen >= 1 {
                    let bp = buf.as_ptr();
                    let ep_id = *bp as usize;
                    let (claimed_tag, _) = dg_decode_owner_tag(bp, plen);
                    let live = ep_id < MAX_DG_ENDPOINTS && {
                        let conn = &*s.tcp_conns.as_ptr().add(ep_id);
                        conn.is_datagram && conn.state == tcp::TcpState::Listen
                    };
                    let owned = live && (*s.tcp_conns.as_ptr().add(ep_id)).owner_tag == claimed_tag;
                    if owned {
                        conn_reset(s, ep_id);
                        dg_send_closed(s, ep_id as u8);
                    } else if live {
                        s.drops.dg_ep_perm = s.drops.dg_ep_perm.wrapping_add(1);
                        dg_send_error(s, ep_id as u8, -1); // EPERM
                    } else {
                        // A close naming a slot that is not a live endpoint
                        // is answered rather than silently absorbed: the
                        // counter is what distinguishes a consumer's own
                        // duplicate close from a probe across the shared
                        // command channel.
                        s.drops.dg_ep_unowned = s.drops.dg_ep_unowned.wrapping_add(1);
                        dg_send_error(s, ep_id as u8, -88); // ENOTSOCK
                    }
                }
            }
            _ => {}
        }
        count += 1;
    }
}

// ============================================================================
// TCP Timers
// ============================================================================

/// Process TCP timers (retransmit, time-wait).
/// SYN / SYN-ACK retransmit schedule, in 50 ms timer ticks: fire at 0.5 s,
/// 1.5 s, 3.5 s, 7.5 s (gaps 0.5/1/2/4 s — exponential backoff).
///
/// The previous flat `timer % 60 == 0` retransmitted only every 3 s, so a
/// single dropped SYN-ACK stalled a connection's establishment for a full 3 s.
/// Under a lossy link or a connection burst that throttled *establishment*,
/// which is the dominant achievable-throughput limiter (the server itself has
/// CPU headroom at 10k+ rps; the ceiling is how fast connections come up). A
/// faster first retransmit recovers a dropped SYN-ACK in 0.5 s instead of 3 s.
/// The 15 s connect timeout (`>= 300`) is unchanged.
#[inline]
fn is_syn_retransmit_tick(timer: u16) -> bool {
    matches!(timer, 10 | 30 | 70 | 150)
}

/// Advance every connection's TCP timers once per `TCP_SWEEP_WINDOW_MS`
/// window, in slices spread across the window in proportion to elapsed
/// time — so a full table costs one pass per window whatever the tick,
/// and no single step walks more of it than its share of the window.
/// After a stall the pass catches up in one step, which is the bounded
/// worst case: one pass.
unsafe fn step_tcp_timers(s: &mut IpState) {
    let now = dev_millis(&*s.syscalls) as u32;
    let elapsed = now.wrapping_sub(s.sweep_window_ms);
    let n = tcp::MAX_TCP_CONNS;
    let target = if elapsed >= TCP_SWEEP_WINDOW_MS {
        n
    } else {
        ((n as u64 * u64::from(elapsed)) / u64::from(TCP_SWEEP_WINDOW_MS)) as usize
    };
    let start = s.sweep_cursor as usize;
    if target <= start {
        return;
    }
    let target = target.min(start + SWEEP_SLICE_MAX);
    if start == 0 {
        // Once per window: the challenge-ACK refill clock. Refilling to a
        // fixed ceiling rather than accumulating tokens keeps the burst
        // bound and the long-run rate the same number, which is what
        // makes the defence non-amplifying under a sustained flood. The
        // per-connection buckets refill as the sweep reaches them.
        s.chal_refill_ticks = s.chal_refill_ticks.saturating_add(1);
        if s.chal_refill_ticks >= tcp::CHALLENGE_ACK_REFILL_TICKS {
            s.chal_refill_ticks = 0;
            s.chal_ack_budget = tcp::CHALLENGE_ACK_GLOBAL_BUDGET;
            s.chal_epoch = s.chal_epoch.wrapping_add(1);
        }
    }
    sweep_range(s, start, target);
    if target >= n {
        s.sweep_cursor = 0;
        // The next window starts where this one should have ended; after
        // a stall longer than a window it starts now, so a pass is never
        // owed twice for one stretch of missed time.
        let next = s.sweep_window_ms.wrapping_add(TCP_SWEEP_WINDOW_MS);
        s.sweep_window_ms = if now.wrapping_sub(next) < TCP_SWEEP_WINDOW_MS {
            next
        } else {
            now
        };
    } else {
        s.sweep_cursor = target as u32;
    }
}

/// One slice of the timer sweep: connections `start..end`.
unsafe fn sweep_range(s: &mut IpState, start: usize, end: usize) {
    // Reopen a receive window that consumer backpressure closed. Without
    // this the admissibility gate — which refuses every data segment while
    // `rcv_wnd == 0` — would have no path back once the consumer drained.
    {
        let mut ci = start;
        while ci < end {
            let c = &*s.tcp_conns.as_ptr().add(ci);
            if c.rcv_wnd == 0
                && matches!(
                    c.state,
                    tcp::TcpState::Established | tcp::TcpState::SynReceived
                )
            {
                update_rcv_wnd(s, ci);
            }
            ci += 1;
        }
    }

    // Retry pending close-notifications first. Terminal slots
    // (`state == Closed`) are freed on successful retry; non-terminal
    // slots (`CloseWait`, `LastAck`) carried peer-FIN news to the
    // consumer but the local side may still send data, so the latch
    // is dropped without disturbing TCP state — the slot frees
    // naturally when the local side closes.
    {
        let mut i = start;
        while i < end {
            let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
            let kind = conn.pending_close_notify;
            let tag = conn.connect_tag;
            if kind != NOTIFY_NONE && kind != continuity::NOTIFY_SHADOW_RESERVED {
                let delivered = match kind {
                    NOTIFY_CLOSED => net_send_closed(s, i as u16),
                    NOTIFY_ERROR_REFUSED => net_send_error(s, i as u16, -111i8, tag),
                    NOTIFY_ERROR_TIMEOUT => net_send_error(s, i as u16, -110i8, tag),
                    NOTIFY_CONNECTED => net_send_connected(s, i as u16),
                    _ => true, // unknown code → drop the latch
                };
                if delivered {
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
                    if conn.state == tcp::TcpState::Closed {
                        let remote_ip = conn.remote_ip;
                        if remote_ip != 0 {
                            arp::unpin(&mut s.arp_table, remote_ip);
                        }
                        conn_reset(s, i);
                    } else {
                        conn.pending_close_notify = NOTIFY_NONE;
                    }
                }
            }
            i += 1;
        }
    }

    let mut i = start;
    while i < end {
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
        // Challenge-ACK refill lands on a connection when the sweep
        // reaches it, once per refill epoch.
        if conn.chal_epoch != s.chal_epoch {
            conn.chal_epoch = s.chal_epoch;
            conn.chal_budget = tcp::CHALLENGE_ACK_PEER_BUDGET;
        }
        match conn.state {
            tcp::TcpState::SynSent => {
                conn.retransmit_timer += 1;
                // A SYN that never reached the wire (`snd_nxt` still at
                // `iss`) is not a loss to back off from — it was blocked on
                // neighbour resolution or NIC backpressure. Retry it every
                // tick until it ships; the backoff schedule then governs
                // genuine retransmits.
                let unsent = conn.snd_nxt == conn.iss;
                // Retransmit SYN on the exponential-backoff schedule
                // (0.5/1.5/3.5/7.5 s) so a dropped SYN recovers fast.
                if unsent || is_syn_retransmit_tick(conn.retransmit_timer) {
                    send_tcp_control(s, i, tcp::SYN, true);
                }
                // Connect timeout after ~15 s: emit exactly one TAGGED terminal
                // result (ETIMEDOUT) so the requester completes its connect and
                // can drop the orphan, then free the slot. Without this the
                // consumer (HTTP/MQTT/OTLP) would wait forever with no conn_id.
                if conn.retransmit_timer >= 300 {
                    let tag = conn.connect_tag;
                    // Free on delivery; else latch (Closed + retry) so the
                    // requester always gets exactly one tagged terminal result.
                    if net_send_error(s, i as u16, -110, tag) {
                        conn_reset(s, i);
                    } else {
                        let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
                        conn.state = tcp::TcpState::Closed;
                        conn.pending_close_notify = NOTIFY_ERROR_TIMEOUT;
                    }
                }
            }
            tcp::TcpState::SynReceived => {
                conn.retransmit_timer += 1;
                // As for SYN-SENT: an unsent SYN-ACK is waiting on neighbour
                // resolution, not on the peer.
                let unsent = conn.snd_nxt == conn.iss;
                // Retransmit SYN-ACK on the exponential-backoff schedule
                // (0.5/1.5/3.5/7.5 s) instead of the old flat 3 s — a dropped
                // SYN-ACK was the main cause of slow connection establishment.
                if unsent || is_syn_retransmit_tick(conn.retransmit_timer) {
                    send_tcp_control(s, i, tcp::SYN | tcp::ACK, true);
                }
                // Timeout after ~15 seconds — free the slot.
                if conn.retransmit_timer >= 300 {
                    conn_reset(s, i);
                }
            }
            tcp::TcpState::CloseWait => {
                // The peer closed; the consumer owes CMD_CLOSE and has the
                // contract's grace interval to send it. Past that, finish the
                // close here exactly as its CMD_CLOSE would have: FIN, then
                // LastAck. Without the bound a CloseWait slot lives until
                // the consumer closes — forever, for a consumer that never
                // does.
                conn.closewait_timer = conn.closewait_timer.saturating_add(1);
                if conn.closewait_timer >= CLOSE_WAIT_TICKS
                    && send_tcp_control(s, i, tcp::FIN | tcp::ACK, false)
                {
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
                    conn.state = tcp::TcpState::LastAck;
                    conn.retransmit_timer = 0;
                    s.tcp_closewait_expired = s.tcp_closewait_expired.wrapping_add(1);
                }
            }
            tcp::TcpState::Closing | tcp::TcpState::LastAck => {
                // Waiting only for the ACK of our own FIN. Bound the wait so a
                // peer that vanishes mid-close cannot hold the slot: same
                // ~15 s ceiling the half-open states use. LastAck joins
                // Closing here — it is the same wait, reached from CloseWait.
                conn.retransmit_timer = conn.retransmit_timer.saturating_add(1);
                if conn.retransmit_timer >= 300 {
                    let remote_ip = conn.remote_ip;
                    if net_send_closed(s, i as u16) {
                        if remote_ip != 0 {
                            arp::unpin(&mut s.arp_table, remote_ip);
                        }
                        conn_reset(s, i);
                    }
                }
            }
            tcp::TcpState::TimeWait => {
                conn.timewait_timer += 1;
                // Exit after ~2 s (40 × 50 ms). Long enough to cover
                // stray retransmits, short enough to avoid slot
                // exhaustion from a single peer at >8 hps. Held until
                // MSG_CLOSED can be delivered so consumers don't strand.
                if conn.timewait_timer > 40 {
                    let remote_ip = conn.remote_ip;
                    if net_send_closed(s, i as u16) {
                        if remote_ip != 0 {
                            arp::unpin(&mut s.arp_table, remote_ip);
                        }
                        conn_reset(s, i);
                    }
                }
            }
            tcp::TcpState::Established => {
                // Idle close. `idle_timer` is reset wherever a payload byte
                // moves (RX commit, CMD_SEND); pure ACKs and window updates do
                // not count as activity. Closing goes the same way a
                // CMD_CLOSE from Established does — FIN, FinWait1 — and the
                // consumer learns through an untagged ETIMEDOUT, which routes
                // by connection id like a close does.
                if s.tcp_idle_ticks != 0 {
                    conn.idle_timer = conn.idle_timer.saturating_add(1);
                    if conn.idle_timer >= s.tcp_idle_ticks {
                        conn.idle_timer = 0;
                        if send_tcp_control(s, i, tcp::FIN | tcp::ACK, false) {
                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
                            conn.state = tcp::TcpState::FinWait1;
                            s.tcp_idle_closed = s.tcp_idle_closed.wrapping_add(1);
                            let _ = net_send_error(s, i as u16, -110, 0);
                        }
                        i += 1;
                        continue;
                    }
                }
                // RTO: if there is unacknowledged data and the timer expires,
                // collapse cwnd, signal the consumer to retransmit, and arm
                // backoff. Karn: don't use the retransmit sample for RTT.
                if conn.snd_nxt != conn.snd_una {
                    conn.retransmit_timer = conn.retransmit_timer.saturating_add(1);
                    if conn.retransmit_timer >= conn.rto {
                        tcp::on_rto(conn);
                        let seq = conn.snd_una;
                        conn.retransmit_timer = 0;
                        // Exponential backoff — double RTO for next timeout.
                        conn.rto = core::cmp::min(conn.rto.saturating_mul(2), tcp::RTO_MAX);
                        conn.rtt_active = false; // Karn's algorithm
                        net_send_retransmit(s, i as u16, seq);
                    }
                } else {
                    conn.retransmit_timer = 0;
                }
            }
            _ => {}
        }
        i += 1;
    }
}

// ============================================================================
// Test helpers (host-test feature only)
// ============================================================================

#[cfg(feature = "host-test")]
pub mod test_helpers {
    //! Helpers for host-side test harnesses. Not compiled into PIC
    //! firmware.
    //!
    //! These give tests a way to bypass the DHCP / ARP bootstrap
    //! sequence so the TCP / UDP behavioural surfaces can be
    //! exercised directly. Using them outside of `cfg(test)` is a
    //! contract violation — the kernel should never need them.

    use super::{arp, tcp, IpDrops, IpState};

    /// How many entries of the connection index are occupied.
    ///
    /// A removal that closes its hole leaves this equal to the number of
    /// indexed connections; one that only marks its entry leaves it
    /// higher, and the difference is the count that never comes back.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    #[must_use]
    pub unsafe fn conn_index_occupancy(state: *const u8) -> usize {
        let s = &*(state as *const IpState);
        s.conn_index
            .iter()
            .filter(|e| **e != super::index::EMPTY)
            .count()
    }

    /// How many connection slots are currently indexed — keyed, and so
    /// expected to hold exactly one index entry each.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    #[must_use]
    pub unsafe fn keyed_conn_count(state: *const u8) -> usize {
        let s = &*(state as *const IpState);
        (0..tcp::MAX_TCP_CONNS)
            .filter(|i| {
                let c = &*s.tcp_conns.as_ptr().add(*i);
                c.is_active() && super::conn_is_keyed(c)
            })
            .count()
    }

    /// The reference count held on `port`. Setup and teardown must move it
    /// by the same amount: a port whose count reaches zero while something
    /// is still bound to it reads as free, and `next_port` will hand it out
    /// as an ephemeral source.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    #[must_use]
    pub unsafe fn port_ref(state: *const u8, port: u16) -> u32 {
        let s = &*(state as *const IpState);
        if super::PORT_REF_ENTRIES > 1 {
            *s.port_ref.as_ptr().add(port as usize)
        } else {
            0
        }
    }

    /// Install a fixed ISN secret so a test can assert an exact sequence
    /// number without depending on the harness CSPRNG. Production seeds this
    /// from the kernel CSPRNG and refuses to open connections without it.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_isn_secret(state: *mut u8, secret: [u8; 16]) {
        let s = &mut *(state as *mut IpState);
        s.isn_secret = secret;
        s.isn_secret_valid = true;
    }

    /// Set the MAC without forcing a configured identity, so a test can
    /// exercise the real DHCP bring-up.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_mac(state: *mut u8, mac: [u8; 6]) {
        let s = &mut *(state as *mut IpState);
        s.mac_addr = mac;
        s.mac_valid = true;
    }

    /// Snapshot of the module state immediately following `tx_frame`. A
    /// transmit that runs past the frame buffer lands here, so a test can
    /// assert the boundary held without reasoning about field layout.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn tx_frame_canary(state: *const u8) -> [u8; 64] {
        let s = &*(state as *const IpState);
        let past = s.tx_frame.as_ptr().add(super::MAX_FRAME_SIZE);
        let mut out = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            out[i] = *past.add(i);
            i += 1;
        }
        out
    }

    /// Promote an ARP entry to a permanent pin, standing in for a completed
    /// gateway resolution.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn pin_gateway(state: *mut u8, ip: u32) -> bool {
        let s = &mut *(state as *mut IpState);
        arp::pin_gateway(&mut s.arp_table, ip)
    }

    /// Read the ingress refusal counters.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn drops(state: *const u8) -> IpDrops {
        (*(state as *const IpState)).drops
    }

    /// The first slot a TCP connection is allocated from: TCP prefers the
    /// slots beyond the datagram window (`alloc_free_slot`), so on a profile
    /// whose table is larger than the window the first connect lands here.
    pub const TCP_SLOT_BASE: usize = if super::MAX_DG_ENDPOINTS < tcp::MAX_TCP_CONNS {
        super::MAX_DG_ENDPOINTS
    } else {
        0
    };

    /// Probes a destination-address demux costs: `(slot, probes)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn addr_lookup_probes(state: *const u8, dst: u32) -> (Option<usize>, usize) {
        let s = &*(state as *const IpState);
        super::index::lookup_counted(
            &s.addr_index,
            super::index::mix32(dst ^ s.index_seed),
            |i| {
                i != 0 && i < super::MAX_LOCAL_ADDRS && {
                    let a = &s.local_addrs[i];
                    a.is_active() && a.ipv4() == dst
                }
            },
        )
    }

    /// Probes a connection lookup costs for `(remote_ip, remote_port,
    /// local_port, local_slot)`: `(slot, probes)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_lookup_probes(
        state: *const u8,
        remote_ip: u32,
        remote_port: u16,
        local_port: u16,
        local_slot: u16,
    ) -> (Option<usize>, usize) {
        let s = &*(state as *const IpState);
        let key = super::index::ConnKey {
            remote_ip,
            remote_port,
            local_port,
            local_slot,
        };
        let conns = s.tcp_conns.as_ptr();
        super::index::lookup_counted(&s.conn_index, key.hash(s.index_seed), |slot| {
            let c = &*conns.add(slot);
            c.is_active()
                && c.remote_ip == remote_ip
                && c.remote_port == remote_port
                && c.local_port == local_port
                && c.local_slot == local_slot
        })
    }

    /// Where the timer sweep stands in its window: `(cursor, table)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn sweep_position(state: *const u8) -> (usize, usize) {
        let s = &*(state as *const IpState);
        (s.sweep_cursor as usize, tcp::MAX_TCP_CONNS)
    }

    /// Half-open sources the table could not track.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn half_open_untracked(state: *const u8) -> u32 {
        (*(state as *const IpState)).ho_src_untracked
    }

    /// Frames refused at the emission gate.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn tx_fenced(state: *const u8) -> u32 {
        (*(state as *const IpState)).tx_fenced
    }

    /// Whether a local address is armed (`None` when not ours).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn addr_armed(state: *const u8, ip: u32) -> Option<bool> {
        let s = &*(state as *const IpState);
        super::local_slot_for_dst(s, ip)
            .map(|slot| s.local_addrs[slot as usize].flags & super::ADDR_FLAG_ARMED != 0)
    }

    /// Decision-seam counters.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn pkt_stats(state: *const u8) -> super::PktSeamStats {
        (*(state as *const IpState)).pkt_stats
    }

    /// Packets currently held at the decision seam.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn pkt_held(state: *const u8) -> usize {
        (*(state as *const IpState)).pkt_held as usize
    }

    /// Half-open gauges: `(current, max, per_source_max, refused)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn half_open(state: *const u8) -> (u32, u32, u32, u32) {
        let s = &*(state as *const IpState);
        (
            s.tcp_half_open,
            s.tcp_half_open_max,
            s.tcp_half_open_src_max,
            s.tcp_half_open_refused,
        )
    }

    /// SYN-cookie counters: `(sent, ok, bad, option_refused)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn syn_cookies(state: *const u8) -> (u32, u32, u32, u32) {
        let s = &*(state as *const IpState);
        (
            s.tcp_syn_cookie_sent,
            s.tcp_syn_cookie_ok,
            s.tcp_syn_cookie_bad,
            s.tcp_syn_option_refused,
        )
    }

    /// Half-open occupancy at which cookie mode engages, for a test that must
    /// cross it without restating the derivation.
    pub const SYN_COOKIE_WATERMARK: u16 = tcp::SYN_COOKIE_WATERMARK;

    /// Local port latched on a connection slot.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_local_port(state: *const u8, idx: usize) -> u16 {
        (*(state as *const IpState)).tcp_conns[idx].local_port
    }

    /// Global challenge-ACK bucket: `(remaining, ticks_into_refill_window)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn challenge_bucket(state: *const u8) -> (u8, u8) {
        let s = &*(state as *const IpState);
        (s.chal_ack_budget, s.chal_refill_ticks)
    }

    /// Sequence and window variables of one connection slot, so a test can
    /// assert what a segment did to the state machine rather than inferring
    /// it from emitted frames.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct ConnView {
        /// `TcpState` discriminant.
        pub state: u8,
        pub local_port: u16,
        pub remote_port: u16,
        pub snd_una: u32,
        pub snd_nxt: u32,
        pub snd_wnd: u16,
        pub snd_wl1: u32,
        pub snd_wl2: u32,
        pub rcv_nxt: u32,
        pub rcv_wnd: u16,
        pub dup_ack_count: u8,
        pub chal_budget: u8,
        pub is_datagram: bool,
        pub local_slot: u16,
        pub owner_tag: u16,
    }

    /// Handshakes waiting on a neighbour: (listed, overflowed).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn arp_wait(state: *const u8) -> (usize, u32) {
        let s = &*(state as *const IpState);
        (s.arp_wait_len as usize, s.arp_wait_overflow)
    }

    /// Continuity counters.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn cont_stats(state: *const u8) -> super::continuity::ContStats {
        (*(state as *const IpState)).cont.stats
    }

    /// The flow identity of connection `idx`, as a coordinator names it.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn flow_id(state: *const u8, idx: usize) -> [u8; 16] {
        super::continuity::flow_id_of(&*(state as *const IpState), idx)
    }

    /// The checkpoint layout digest `PAIR_PREPARE` must carry.
    pub fn codec_digest() -> [u8; 32] {
        super::continuity::codec_digest()
    }

    /// Phase of shadow `i` (0 = empty).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn shadow_phase(state: *const u8, i: usize) -> u8 {
        let s = &*(state as *const IpState);
        if s.cont.shadows[i].in_use == 0 {
            0
        } else {
            s.cont.shadows[i].phase
        }
    }

    /// Mirror `i`: (in_use, live, profile, delta_no, recv_horizon).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn mirror_view(state: *const u8, i: usize) -> (bool, bool, u8, u32, u32) {
        let m = &(*(state as *const IpState)).cont.mirrors[i];
        (
            m.in_use != 0,
            m.live != 0,
            m.profile,
            m.delta_no,
            m.recv_horizon,
        )
    }

    /// `TcpState` discriminants a test compares `ConnView::state` against.
    pub const STATE_ESTABLISHED: u8 = tcp::TcpState::Established as u8;
    pub const STATE_FIN_WAIT1: u8 = tcp::TcpState::FinWait1 as u8;

    /// The congestion window a takeover restarts at.
    pub fn initial_cwnd() -> u16 {
        tcp::INITIAL_CWND
    }

    /// Force congestion state on `idx`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_congestion(
        state: *mut u8,
        idx: usize,
        cwnd: u16,
        ssthresh: u16,
        in_recovery: bool,
    ) {
        let c = &mut (*(state as *mut IpState)).tcp_conns[idx];
        c.cwnd = cwnd;
        c.ssthresh = ssthresh;
        c.in_recovery = in_recovery;
    }

    /// Force the retransmit timer of `idx`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_retransmit_timer(state: *mut u8, idx: usize, ticks: u16) {
        (*(state as *mut IpState)).tcp_conns[idx].retransmit_timer = ticks;
    }

    /// The decoded connection held by shadow `i`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn shadow_conn_view(state: *const u8, i: usize) -> ConnView {
        let c = &(*(state as *const IpState)).cont.shadows[i].conn;
        ConnView {
            state: c.state as u8,
            local_port: c.local_port,
            remote_port: c.remote_port,
            snd_una: c.snd_una,
            snd_nxt: c.snd_nxt,
            snd_wnd: c.snd_wnd,
            snd_wl1: c.snd_wl1,
            snd_wl2: c.snd_wl2,
            rcv_nxt: c.rcv_nxt,
            rcv_wnd: c.rcv_wnd,
            dup_ack_count: c.dup_ack_count,
            chal_budget: c.chal_budget,
            is_datagram: c.is_datagram,
            local_slot: c.local_slot,
            owner_tag: c.owner_tag,
        }
    }

    /// Connection slots reserved for shadows.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn reserved_slots(state: *const u8) -> usize {
        let s = &*(state as *const IpState);
        s.tcp_conns
            .iter()
            .filter(|c| {
                c.state == tcp::TcpState::Closed
                    && c.pending_close_notify == super::continuity::NOTIFY_SHADOW_RESERVED
            })
            .count()
    }

    /// Congestion and timer fields of connection `idx`:
    /// (cwnd, ssthresh, in_recovery, retransmit_timer, rto).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_timers(state: *const u8, idx: usize) -> (u16, u16, bool, u16, u16) {
        let c = &(*(state as *const IpState)).tcp_conns[idx];
        (c.cwnd, c.ssthresh, c.in_recovery, c.retransmit_timer, c.rto)
    }

    /// Read one connection slot.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_view(state: *const u8, idx: usize) -> ConnView {
        let c = &(*(state as *const IpState)).tcp_conns[idx];
        ConnView {
            state: c.state as u8,
            local_port: c.local_port,
            remote_port: c.remote_port,
            snd_una: c.snd_una,
            snd_nxt: c.snd_nxt,
            snd_wnd: c.snd_wnd,
            snd_wl1: c.snd_wl1,
            snd_wl2: c.snd_wl2,
            rcv_nxt: c.rcv_nxt,
            rcv_wnd: c.rcv_wnd,
            dup_ack_count: c.dup_ack_count,
            chal_budget: c.chal_budget,
            is_datagram: c.is_datagram,
            local_slot: c.local_slot,
            owner_tag: c.owner_tag,
        }
    }

    /// Force a connection's advertised receive window, standing in for the
    /// consumer backpressure that closes it in production.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_rcv_wnd(state: *mut u8, idx: usize, wnd: u16) {
        (*(state as *mut IpState)).tcp_conns[idx].rcv_wnd = wnd;
    }

    /// Initial send sequence number latched on a connection slot.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_iss(state: *const u8, idx: usize) -> u32 {
        (*(state as *const IpState)).tcp_conns[idx].iss
    }

    /// ARP cache view for one address: `(mac, pinned, pin_count, revalidate)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn arp_entry(state: *const u8, ip: u32) -> Option<([u8; 6], bool, u8, bool)> {
        let s = &*(state as *const IpState);
        let mut i = 0;
        while i < arp::ARP_TABLE_SIZE {
            let e = &s.arp_table[i];
            if e.valid && e.ip == ip {
                return Some((e.mac, e.pinned, e.pin_count, e.revalidate));
            }
            i += 1;
        }
        None
    }

    /// Seed an ARP cache entry directly, standing in for whatever traffic
    /// would have installed it.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn seed_arp(state: *mut u8, ip: u32, mac: [u8; 6]) {
        let s = &mut *(state as *mut IpState);
        arp::insert(&mut s.arp_table, ip, mac, 0);
    }

    /// Force ARP aging forward by `passes` maintenance ticks.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn age_arp(state: *mut u8, passes: u32) -> u32 {
        let s = &mut *(state as *mut IpState);
        let mut revalidations = 0;
        let mut i = 0;
        while i < passes {
            revalidations += arp::age_entries(&mut s.arp_table);
            i += 1;
        }
        s.drops.arp_pin_revalidate = s.drops.arp_pin_revalidate.wrapping_add(revalidations);
        revalidations
    }

    /// Drive one periodic ARP maintenance pass.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn arp_maintenance(state: *mut u8) {
        super::step_arp_maintenance(&mut *(state as *mut IpState));
    }

    /// DHCP client state as its discriminant, plus the bound identity:
    /// `(state, local_ip, netmask, gateway)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn dhcp_view(state: *const u8) -> (u8, u32, u32, u32) {
        let s = &*(state as *const IpState);
        (s.dhcp.state as u8, s.local_ip, s.netmask, s.gateway)
    }

    /// Overwrite the DHCP client's exchange state so a test can drive a
    /// reply against a known transaction.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_dhcp_exchange(
        state: *mut u8,
        dhcp_state: u8,
        xid: u32,
        offered_ip: u32,
        server_ip: u32,
    ) {
        let s = &mut *(state as *mut IpState);
        s.dhcp.state = match dhcp_state {
            1 => super::dhcp::DhcpState::Discovering,
            2 => super::dhcp::DhcpState::Requesting,
            3 => super::dhcp::DhcpState::Bound,
            _ => super::dhcp::DhcpState::Idle,
        };
        s.dhcp.xid = xid;
        s.dhcp.offered_ip = offered_ip;
        s.dhcp.server_ip = server_ip;
    }

    /// Mark a renewal REQUEST as outstanding.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn set_dhcp_renew_sent(state: *mut u8, sent: bool) {
        (*(state as *mut IpState)).dhcp.renew_sent = sent;
    }

    /// Force the IP stack into a "configured" state with the given
    /// MAC and IP. Skips DHCP entirely. Tests that exercise DHCP
    /// itself should not call this.
    ///
    /// # Safety
    /// `state` must point to a fully-initialised `IpState` (i.e.
    /// `module_new` has already returned).
    pub unsafe fn force_configured(
        state: *mut u8,
        mac: [u8; 6],
        local_ip: u32,
        netmask: u32,
        gateway: u32,
    ) {
        let s = &mut *(state as *mut IpState);
        s.mac_addr = mac;
        s.mac_valid = true;
        s.local_ip = local_ip;
        s.netmask = netmask;
        s.gateway = gateway;
        s.ip_configured = true;
        s.use_dhcp = 0;
        // Mirror the primary identity into slot 0 of the address table.
        super::sync_primary_slot(s);
    }

    /// Number of active local-address slots (primary + secondaries).
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn local_addr_count(state: *const u8) -> usize {
        let s = &*(state as *const IpState);
        let mut n = 0;
        if s.local_ip != 0 {
            n += 1;
        }
        let mut i = 1;
        while i < super::MAX_LOCAL_ADDRS {
            if s.local_addrs[i].is_active() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Resolve a dst IPv4 to its local-address slot, or `None` if not ours.
    /// Mirrors the RX-path demux used by the module.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn local_slot_for_dst(state: *const u8, dst: u32) -> Option<u16> {
        super::local_slot_for_dst(&*(state as *const IpState), dst)
    }

    /// Read the `local_slot` axis latched on a TCP conn slot.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn conn_local_slot(state: *const u8, idx: usize) -> u16 {
        (*(state as *const IpState)).tcp_conns[idx].local_slot
    }

    /// Inspect the local IP currently held by the IP stack.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`.
    pub unsafe fn local_ip(state: *const u8) -> u32 {
        (*(state as *const IpState)).local_ip
    }

    /// Borrow the connection table for assertion. Returns the slot
    /// count `(used, total)`.
    ///
    /// # Safety
    /// `state` must point to an initialised `IpState`. The borrow lives
    /// only for the call; tests run single-threaded so no aliasing.
    /// Free slots the allocator's stack currently names.
    pub unsafe fn free_stack_len(state: *const u8) -> usize {
        (*(state as *const IpState)).free_top as usize
    }

    /// Slots examined by the allocator's rebuild and window scans so far.
    pub unsafe fn alloc_scanned(state: *const u8) -> u32 {
        (*(state as *const IpState)).alloc_scanned
    }

    pub unsafe fn conn_count(state: *const u8) -> (usize, usize) {
        let s = &*(state as *const IpState);
        let mut used = 0;
        for c in s.tcp_conns.iter() {
            if c.state != tcp::TcpState::Closed {
                used += 1;
            }
        }
        (used, tcp::MAX_TCP_CONNS)
    }

    /// Snapshot of the per-tick telemetry counters. Tests use this to
    /// gate on "the data path is starved" (`idle_steps` ≈ ticks) vs
    /// "back-pressure caused stalls" (`bp_steps` > 0) without parsing
    /// the periodic `[ip] tlm …` log line.
    pub struct TlmSnapshot {
        pub bytes_in: u32,
        pub bytes_out: u32,
        pub idle_steps: u32,
        pub bp_steps: u32,
        pub step_count: u32,
    }

    /// # Safety
    /// `state` must point to an initialised `IpState`. Single-threaded
    /// borrow as for `conn_count`.
    pub unsafe fn tlm_snapshot(state: *const u8) -> TlmSnapshot {
        let s = &*(state as *const IpState);
        TlmSnapshot {
            bytes_in: s.tlm.bytes_in,
            bytes_out: s.tlm.bytes_out,
            idle_steps: s.tlm.idle_steps,
            bp_steps: s.tlm.bp_steps,
            step_count: s.step_count,
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
