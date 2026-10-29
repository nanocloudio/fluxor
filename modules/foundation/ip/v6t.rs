//! IPv6 TCP and UDP: the stack's one TCP machine and datagram path,
//! reached over IPv6.
//!
//! An IPv6 address this module terminates (`ip6`, a `seam_v6` address a
//! director delivers `LOCAL`, or an `ADDR_ADD` of family 6) is held as a
//! local-address slot whose IPv4 word is a *stand-in* from 240.0.0.0/8 —
//! reserved space (RFC 1112 §4) that never appears on a wire this module
//! accepts — and every IPv6 peer it talks to as a peer entry whose stand-in
//! is from 241.0.0.0/8. Between the wire and the transports the network
//! header is translated statelessly in both directions (the RFC 7915
//! header map: addresses replaced by their stand-ins, hop limit and TTL
//! carried, the transport checksum verified over the arriving family's
//! pseudo-header and recomputed over the other's), so a connection over
//! IPv6 is the same `TcpConn` with the same sequence space, timers,
//! retransmission, emission fence and continuity export as one over IPv4.
//! What differs is kept here and made true at the edge:
//!
//! - **Addresses.** Stand-ins never leave the module: an inbound IPv4
//!   packet whose source or destination is in 240.0.0.0/7 is dropped before
//!   anything parses it, the stack's peer report (`MSG_PEER`), the datagram
//!   surface (`af = 6`) and the continuity record (FXTC's IPv6
//!   layout, `flow_id_v6`) name the IPv6 addresses, and an outbound frame to a
//!   stand-in is only ever sent as IPv6.
//! - **Policy.** `net.policy` tables name IPv4 addresses; while any table
//!   judges packets, a flow they would judge whose address is a stand-in
//!   is dropped (`policy.rs`), never judged as the stand-in.
//! - **Segment size.** The IPv6 header is twenty bytes longer, so a
//!   connection to a stand-in segments at `V6T_MSS`, a SYN's MSS option is
//!   clamped to it on the way out, and a datagram whose IPv6 packet would
//!   pass the link MTU is refused (`EMSGSIZE`).
//! - **Neighbours.** A peer's link-layer address is learnt from the frame
//!   that introduced it, or from a neighbour advertisement answering our
//!   solicitation (an outbound connect, or a standby that imported the
//!   connection); a later frame from another MAC does not move it — only an
//!   override advertisement does, and never the router's (`gateway6`, the
//!   pin ARP gives the IPv4 gateway). With `gateway6` set every peer is
//!   reached through that router.
//! - **Source.** Traffic to an IPv6 peer leaves from an IPv6 address of
//!   its sender's own: a workload's from its own (none is `ENETUNREACH`),
//!   the node's from an address no workload owns (`owner_slot`,
//!   `node_slot`). A frame whose source is not a local stand-in is never
//!   given another address's.
//! - **Emission.** The stand-in slot is the address's emission gate: a
//!   fenced IPv6 address sources nothing, answers no solicitation, and an
//!   armed one announces itself with an unsolicited override advertisement
//!   (RFC 4861 §7.2.6) when armed.
//!
//! The datagram surface reports an IPv6 peer as itself (`af = 6`) and sends
//! to one by `af = 6`, so a QUIC endpoint or any datagram service over `ip`
//! serves IPv6 as it serves IPv4. ICMPv6 other than neighbour discovery and
//! echo is not delivered.

use super::*;

/// Whether this build carries IPv6 TCP (the 64-bit targets; the small
/// profiles keep their state arena).
pub const V6T: bool = cfg!(target_arch = "aarch64");

/// IPv6 peers held at once.
pub const V6T_PEERS: usize = if V6T { 64 } else { 1 };
/// Local IPv6 addresses held at once (each also a local-address slot).
pub const V6T_LOCALS: usize = if V6T { 16 } else { 1 };
/// The translated frame `send_frame` hands the driver.
pub const V6T_OUT: usize = if V6T { MAX_FRAME_SIZE } else { 1 };

/// MSS over IPv6: the IPv4 MSS less the twenty extra header bytes.
pub const V6T_MSS: u16 = tcp::MSS - 20;
/// Largest UDP payload to an IPv6 peer: what fills the link MTU under the
/// IPv6 and UDP headers.
pub const V6T_UDP_MAX: usize = LINK_MTU - ipv6::IPV6_HEADER_LEN - udp::UDP_HEADER_LEN;

/// Stand-in blocks (first octet).
pub const V6T_LOCAL_NET: u32 = 0xF000_0000;
pub const V6T_PEER_NET: u32 = 0xF100_0000;

/// `LocalAddr::flags`: the slot stands in for an IPv6 address.
pub const ADDR_FLAG_V6: u8 = 0x08;

/// A peer's neighbour state.
pub const PEER_FREE: u8 = 0;
pub const PEER_RESOLVING: u8 = 1;
pub const PEER_VALID: u8 = 2;

/// How long a solicitation is waited on before it is sent again (ms).
const NS_RETRY_MS: u32 = 1000;

#[derive(Clone, Copy)]
pub struct V6Peer {
    pub addr: [u8; 16],
    pub mac: [u8; 6],
    pub state: u8,
    pub _pad: u8,
    /// The local slot this peer last reached (0 none): what a datagram to
    /// it from a wildcard endpoint is sourced from.
    pub via_slot: u16,
    /// `dev_millis` (low 32 bits) of the last use; a solicitation's send
    /// time while resolving.
    pub last_ms: u32,
}

impl V6Peer {
    pub const fn empty() -> Self {
        Self {
            addr: [0; 16],
            mac: [0; 6],
            state: PEER_FREE,
            _pad: 0,
            via_slot: 0,
            last_ms: 0,
        }
    }
}

/// Counters, kept for a debugger's reading of the state.
#[derive(Clone, Copy, Default)]
pub struct V6tStats {
    pub rx: u32,
    pub tx: u32,
    /// Frames for a stand-in with no neighbour yet (a solicitation sent).
    pub unresolved: u32,
    /// A new peer with the table full of live ones.
    pub peers_full: u32,
    /// A spoofed stand-in on IPv4.
    pub martian: u32,
    /// Frames to a stand-in that are neither TCP nor UDP, malformed, or with
    /// no IPv6 address of their own to leave from.
    pub untranslatable: u32,
    /// Datagrams to a stand-in whose IPv6 packet would pass the link MTU.
    pub oversize: u32,
    pub ns_sent: u32,
    pub na_learnt: u32,
    pub unsolicited_na: u32,
    pub mss_clamped: u32,
}

/// Whether `ip` is a peer stand-in.
#[inline]
pub fn is_peer(ip: u32) -> bool {
    V6T && ip & 0xFF00_0000 == V6T_PEER_NET
}

/// Whether `ip` is in the blocks stand-ins come from (240.0.0.0/7, inside
/// the reserved 240/4 — the limited broadcast is not in it).
#[inline]
pub fn is_reserved(ip: u32) -> bool {
    ip & 0xFE00_0000 == 0xF000_0000
}

/// The peer index of a stand-in.
#[inline]
pub fn peer_index(ip: u32) -> Option<usize> {
    if !is_peer(ip) {
        return None;
    }
    let i = (ip & 0x00FF_FFFF) as usize;
    if i == 0 || i > V6T_PEERS {
        None
    } else {
        Some(i - 1)
    }
}

#[inline]
pub fn peer_standin(i: usize) -> u32 {
    V6T_PEER_NET | (i as u32 + 1)
}

/// The stand-in a local slot `i` holds.
#[inline]
pub fn local_standin(slot: usize) -> u32 {
    V6T_LOCAL_NET | slot as u32
}

/// The IPv6 address of local slot `slot`, when it stands in for one.
pub fn local_v6(s: &IpState, slot: u16) -> Option<[u8; 16]> {
    if !V6T || slot == 0 || slot as usize >= MAX_LOCAL_ADDRS {
        return None;
    }
    let a = &s.local_addrs[slot as usize];
    if !a.is_active() || a.flags & ADDR_FLAG_V6 == 0 {
        return None;
    }
    let mut k = 0;
    while k < V6T_LOCALS {
        if s.v6_local_slot[k] == slot {
            return Some(s.v6_local[k]);
        }
        k += 1;
    }
    None
}

/// The local slot standing in for IPv6 address `a`.
pub fn slot_of_v6(s: &IpState, a: &[u8; 16]) -> Option<u16> {
    if !V6T {
        return None;
    }
    let mut k = 0;
    while k < V6T_LOCALS {
        let slot = s.v6_local_slot[k];
        if slot != 0 && s.v6_local[k] == *a {
            let l = &s.local_addrs[slot as usize];
            if l.is_active() && l.flags & ADDR_FLAG_V6 != 0 {
                return Some(slot);
            }
        }
        k += 1;
    }
    None
}

/// Forget local slot `slot`'s IPv6 address (the slot is being freed).
pub fn forget_local(s: &mut IpState, slot: u16) {
    let mut k = 0;
    while k < V6T_LOCALS {
        if s.v6_local_slot[k] == slot {
            s.v6_local_slot[k] = 0;
            s.v6_local[k] = [0; 16];
        }
        k += 1;
    }
}

/// The IPv6 address of a local stand-in.
fn local_standin_v6(s: &IpState, ip: u32) -> Option<[u8; 16]> {
    if V6T && ip & 0xFF00_0000 == V6T_LOCAL_NET {
        let slot = ip & 0x00FF_FFFF;
        if (slot as usize) < MAX_LOCAL_ADDRS {
            return local_v6(s, slot as u16);
        }
    }
    None
}

/// The IPv6 address of a stand-in (local or peer).
pub fn v6_of_standin(s: &IpState, ip: u32) -> Option<[u8; 16]> {
    if let Some(i) = peer_index(ip) {
        let p = &s.v6_peers[i];
        return (p.state != PEER_FREE).then_some(p.addr);
    }
    local_standin_v6(s, ip)
}

/// Install a local IPv6 address in a free slot under its stand-in, with the
/// flags given (`ADDR_FLAG_ARMED` or not). The slot, or `None` with the
/// table full. An address already held returns its slot unchanged.
pub unsafe fn install_local(
    s: &mut IpState,
    a: &[u8; 16],
    prefix_len: u8,
    owner_tag: u16,
    flags: u8,
) -> Option<u16> {
    if !V6T {
        return None;
    }
    if let Some(slot) = slot_of_v6(s, a) {
        return Some(slot);
    }
    let mut k = 0;
    while k < V6T_LOCALS && s.v6_local_slot[k] != 0 {
        k += 1;
    }
    if k == V6T_LOCALS {
        return None;
    }
    let mut i = 1;
    while i < MAX_LOCAL_ADDRS {
        if !s.local_addrs[i].is_active() {
            let ip = local_standin(i);
            let l = &mut s.local_addrs[i];
            *l = LocalAddr::empty();
            l.set_ipv4(ip);
            l.prefix_len = prefix_len;
            l.owner_tag = owner_tag;
            l.flags = flags | ADDR_FLAG_V6;
            s.v6_local[k] = *a;
            s.v6_local_slot[k] = i as u16;
            let _ = index::insert(&mut s.addr_index, index::mix32(ip ^ s.index_seed), i);
            s.addr_epoch = s.addr_epoch.wrapping_add(1).max(1);
            return Some(i as u16);
        }
        i += 1;
    }
    None
}

/// Whether some connection, listener or staged import still names peer `i`.
unsafe fn peer_in_use(s: &IpState, i: usize) -> bool {
    let ip = peer_standin(i);
    let mut k = 0;
    while k < s.tcp_conns.len() {
        let c = &*s.tcp_conns.ptr(k);
        if c.remote_ip == ip && !slot_is_free(c) {
            return true;
        }
        k += 1;
    }
    false
}

/// The peer entry for `a`: found, or made (its MAC `mac` when one is in
/// hand, else to be solicited). `None` with every entry live.
pub unsafe fn peer_for(s: &mut IpState, a: &[u8; 16], mac: Option<[u8; 6]>) -> Option<usize> {
    if !V6T {
        return None;
    }
    let now = dev_millis(&*s.syscalls) as u32;
    let mut free = None;
    let mut oldest: Option<(usize, u32)> = None;
    let mut i = 0;
    while i < V6T_PEERS {
        let p = &s.v6_peers[i];
        if p.state != PEER_FREE && p.addr == *a {
            s.v6_peers[i].last_ms = now;
            if let Some(m) = mac {
                if s.v6_peers[i].state == PEER_RESOLVING {
                    s.v6_peers[i].mac = m;
                    s.v6_peers[i].state = PEER_VALID;
                }
            }
            return Some(i);
        }
        if p.state == PEER_FREE && free.is_none() {
            free = Some(i);
        }
        let age = now.wrapping_sub(p.last_ms);
        if p.state != PEER_FREE && oldest.is_none_or(|(_, a)| age > a) {
            oldest = Some((i, age));
        }
        i += 1;
    }
    let slot = match free {
        Some(f) => f,
        None => {
            // Reuse the least recently used entry nothing names any more.
            let (cand, _) = oldest?;
            if peer_in_use(s, cand) {
                // Look for any idle entry before refusing.
                let mut k = 0;
                let mut found = None;
                while k < V6T_PEERS {
                    if !peer_in_use(s, k) {
                        found = Some(k);
                        break;
                    }
                    k += 1;
                }
                match found {
                    Some(k) => k,
                    None => {
                        s.v6t_stats.peers_full = s.v6t_stats.peers_full.wrapping_add(1);
                        return None;
                    }
                }
            } else {
                cand
            }
        }
    };
    let p = &mut s.v6_peers[slot];
    p.addr = *a;
    p.via_slot = 0;
    p.last_ms = now;
    match mac {
        Some(m) => {
            p.mac = m;
            p.state = PEER_VALID;
        }
        None => {
            p.mac = [0; 6];
            p.state = PEER_RESOLVING;
            // Send the first solicitation on the next resolve.
            p.last_ms = now.wrapping_sub(NS_RETRY_MS);
        }
    }
    Some(slot)
}

/// The MAC frames to stand-in `ip` go to, or `None` with a solicitation
/// sent (rate-limited) for the neighbour that is not known yet, from the
/// address the frame leaves from (`src`, `solicit_source`).
pub unsafe fn resolve(s: &mut IpState, ip: u32, src: u32) -> Option<[u8; 6]> {
    let i = peer_index(ip)?;
    // Through the router when one is set.
    let target = if s.v6_gateway_set {
        let gw = s.v6_gateway;
        peer_for(s, &gw, None)?
    } else {
        i
    };
    let p = s.v6_peers[target];
    if p.state == PEER_VALID {
        return Some(p.mac);
    }
    s.v6t_stats.unresolved = s.v6t_stats.unresolved.wrapping_add(1);
    let now = dev_millis(&*s.syscalls) as u32;
    if now.wrapping_sub(p.last_ms) >= NS_RETRY_MS {
        let addr = p.addr;
        if let Some(from) = solicit_source(s, src) {
            s.v6_peers[target].last_ms = now;
            send_solicitation(s, &from, &addr);
        }
    }
    None
}

/// The address a solicitation for a frame from `src` is sent from: `src`
/// itself when it is a local IPv6 address that is armed (a workload's flow
/// solicits from the workload's own address), else — for a frame from no
/// IPv6 address of ours — the node's own (`node_slot`). Never another
/// owner's address, and never the unspecified address, which only
/// duplicate address detection solicits from (RFC 4862 §5.4.2): with no
/// such address there is no solicitation.
fn solicit_source(s: &IpState, src: u32) -> Option<[u8; 16]> {
    if V6T && src & 0xFF00_0000 == V6T_LOCAL_NET {
        let slot = (src & 0x00FF_FFFF) as u16;
        let i = slot as usize;
        let armed = i < MAX_LOCAL_ADDRS && s.local_addrs[i].flags & ADDR_FLAG_ARMED != 0;
        return if armed { local_v6(s, slot) } else { None };
    }
    node_slot(s, 0).and_then(|k| local_v6(s, k))
}

/// Whether any local IPv6 address is held (IPv6 frames are then read).
pub fn any_local(s: &IpState) -> bool {
    let mut k = 0;
    while k < V6T_LOCALS {
        if s.v6_local_slot[k] != 0 {
            return true;
        }
        k += 1;
    }
    false
}

/// A neighbour solicitation for `target` from `src` (RFC 4861 §4.3), to its
/// solicited-node group, with our link-layer address.
unsafe fn send_solicitation(s: &mut IpState, src: &[u8; 16], target: &[u8; 16]) {
    let src = *src;
    let dst = ipv6::solicited_node(target);
    let l4 = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN);
    let mut b = [0u8; 32];
    b[0] = ipv6::ICMPV6_NS;
    b[8..24].copy_from_slice(target);
    b[24] = 1; // source link-layer address option
    b[25] = 1;
    b[26..32].copy_from_slice(&s.mac_addr);
    core::ptr::copy_nonoverlapping(b.as_ptr(), l4, b.len());
    let c = ipv6::transport_checksum(&src, &dst, ipv6::NH_ICMPV6, l4, b.len());
    *l4.add(2) = (c >> 8) as u8;
    *l4.add(3) = c as u8;
    ipv6::build_ipv6_header(
        s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN),
        b.len() as u16,
        ipv6::NH_ICMPV6,
        255,
        &src,
        &dst,
    );
    let mac = s.mac_addr;
    let dmac = ipv6::multicast_mac(&dst);
    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dmac, &mac, eth::ETHERTYPE_IPV6);
    s.v6t_stats.ns_sent = s.v6t_stats.ns_sent.wrapping_add(1);
    let total = eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN + b.len();
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// An unsolicited override advertisement for an armed address, to all
/// nodes (RFC 4861 §7.2.6): what a moving VIP's new owner says, as an IPv4
/// one sends a gratuitous ARP.
pub unsafe fn announce(s: &mut IpState, a: &[u8; 16]) {
    let dst: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let l4 = s
        .tx_frame
        .as_mut_ptr()
        .add(eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN);
    let mut b = [0u8; 32];
    b[0] = ipv6::ICMPV6_NA;
    b[4] = 0x20; // override, not solicited
    b[8..24].copy_from_slice(a);
    b[24] = 2; // target link-layer address option
    b[25] = 1;
    b[26..32].copy_from_slice(&s.mac_addr);
    core::ptr::copy_nonoverlapping(b.as_ptr(), l4, b.len());
    let c = ipv6::transport_checksum(a, &dst, ipv6::NH_ICMPV6, l4, b.len());
    *l4.add(2) = (c >> 8) as u8;
    *l4.add(3) = c as u8;
    ipv6::build_ipv6_header(
        s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN),
        b.len() as u16,
        ipv6::NH_ICMPV6,
        255,
        a,
        &dst,
    );
    let mac = s.mac_addr;
    let dmac = ipv6::multicast_mac(&dst);
    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dmac, &mac, eth::ETHERTYPE_IPV6);
    s.v6t_stats.unsolicited_na = s.v6t_stats.unsolicited_na.wrapping_add(1);
    let total = eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN + b.len();
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// A neighbour advertisement arrived (its hop limit, code, checksum and
/// addressing validated by the caller, RFC 4861 §7.1.2): a peer we are
/// resolving learns its MAC, and an override advertisement moves a known
/// one — except the router's, which only a solicitation it answers while
/// unresolved sets, as the IPv4 gateway's ARP mapping is pinned.
pub unsafe fn on_advert(s: &mut IpState, l4: *const u8, l4_len: usize) {
    if !V6T || l4_len < 24 {
        return;
    }
    let mut target = [0u8; 16];
    core::ptr::copy_nonoverlapping(l4.add(8), target.as_mut_ptr(), 16);
    if ipv6::is_multicast(&target) {
        return;
    }
    let flags = *l4.add(4);
    // The target link-layer address option, else the frame's source.
    let mut mac = eth::src_mac(s.rx_frame.as_ptr());
    let mut off = 24;
    while off + 8 <= l4_len {
        let kind = *l4.add(off);
        let units = *l4.add(off + 1) as usize;
        if units == 0 {
            // RFC 4861 §7.1.2: an option of length zero voids the message.
            return;
        }
        if kind == 2 && units == 1 {
            core::ptr::copy_nonoverlapping(l4.add(off + 2), mac.as_mut_ptr(), 6);
        }
        off += units * 8;
    }
    let pinned = s.v6_gateway_set && s.v6_gateway == target;
    let mut i = 0;
    while i < V6T_PEERS {
        let p = &mut s.v6_peers[i];
        if p.state != PEER_FREE && p.addr == target {
            if p.state == PEER_RESOLVING || (flags & 0x20 != 0 && !pinned) {
                p.mac = mac;
                p.state = PEER_VALID;
                s.v6t_stats.na_learnt = s.v6t_stats.na_learnt.wrapping_add(1);
            }
            return;
        }
        i += 1;
    }
}

/// Recompute a TCP checksum in place over the IPv4 pseudo-header.
unsafe fn csum4(l4: *mut u8, len: usize, src: u32, dst: u32) {
    tcp::compute_tcp_checksum(l4, len, src, dst);
}

/// An IPv6 TCP segment for local slot `slot` (its stand-in the
/// destination): translated in `rx_frame` and handed to the TCP machine.
/// `l4` points into `rx_frame`.
pub unsafe fn rx_tcp(s: &mut IpState, h: &ipv6::Ipv6Header, l4: *mut u8, l4_len: usize, slot: u16) {
    if !V6T || l4_len < tcp::TCP_HEADER_LEN {
        return;
    }
    if !ipv6::verify_transport(&h.src, &h.dst, ipv6::NH_TCP, l4, l4_len) {
        s.drops.cksum_tcp = s.drops.cksum_tcp.wrapping_add(1);
        return;
    }
    let src_mac = eth::src_mac(s.rx_frame.as_ptr());
    let Some(pi) = peer_for(s, &h.src, Some(src_mac)) else {
        return;
    };
    s.v6_peers[pi].via_slot = slot;
    let src = peer_standin(pi);
    let dst = local_slot_ip(s, slot);
    csum4(l4, l4_len, src, dst);
    s.v6t_stats.rx = s.v6t_stats.rx.wrapping_add(1);
    let hdr = ipv4::Ipv4Header {
        ihl: 5,
        total_len: (ipv4::IPV4_HEADER_LEN + l4_len) as u16,
        identification: 0,
        flags_frag: 0x4000,
        ttl: h.hop_limit,
        protocol: ipv4::PROTO_TCP,
        src_ip: src,
        dst_ip: dst,
        header_len: ipv4::IPV4_HEADER_LEN,
    };
    process_tcp_segment(s, &hdr, l4, l4_len, slot);
}

/// An IPv6 UDP datagram for local slot `slot`: translated in `rx_frame`
/// and handed to the datagram path (its checksum verified here, over the
/// IPv6 pseudo-header, and zeroed for the IPv4 one it then travels under).
pub unsafe fn rx_udp(s: &mut IpState, h: &ipv6::Ipv6Header, l4: *mut u8, l4_len: usize, slot: u16) {
    if !V6T || l4_len < 8 {
        return;
    }
    let ulen = u16::from_be_bytes([*l4.add(4), *l4.add(5)]) as usize;
    let csum = u16::from_be_bytes([*l4.add(6), *l4.add(7)]);
    // RFC 8200 §8.1: a zero UDP checksum is not permitted over IPv6.
    if ulen != l4_len
        || csum == 0
        || !ipv6::verify_transport(&h.src, &h.dst, ipv6::NH_UDP, l4, l4_len)
    {
        s.drops.cksum_udp = s.drops.cksum_udp.wrapping_add(1);
        return;
    }
    let src_mac = eth::src_mac(s.rx_frame.as_ptr());
    let Some(pi) = peer_for(s, &h.src, Some(src_mac)) else {
        return;
    };
    s.v6_peers[pi].via_slot = slot;
    let src = peer_standin(pi);
    let dst = local_slot_ip(s, slot);
    *l4.add(6) = 0;
    *l4.add(7) = 0;
    s.v6t_stats.rx = s.v6t_stats.rx.wrapping_add(1);
    let hdr = ipv4::Ipv4Header {
        ihl: 5,
        total_len: (ipv4::IPV4_HEADER_LEN + l4_len) as u16,
        identification: 0,
        flags_frag: 0x4000,
        ttl: h.hop_limit,
        protocol: ipv4::PROTO_UDP,
        src_ip: src,
        dst_ip: dst,
        header_len: ipv4::IPV4_HEADER_LEN,
    };
    process_udp_packet(s, &hdr, l4, l4_len, slot);
}

/// The IPv4 word of a local slot.
fn local_slot_ip(s: &IpState, slot: u16) -> u32 {
    s.local_addrs[slot as usize].ipv4()
}

/// Clamp a SYN's MSS option to `V6T_MSS`; `true` when one was changed.
unsafe fn clamp_mss(l4: *mut u8, l4_len: usize) -> bool {
    let doff = ((*l4.add(12) >> 4) as usize) * 4;
    if *l4.add(13) & tcp::SYN == 0 || doff <= tcp::TCP_HEADER_LEN || doff > l4_len {
        return false;
    }
    let mut off = tcp::TCP_HEADER_LEN;
    while off < doff {
        let kind = *l4.add(off);
        if kind == 0 {
            break;
        }
        if kind == 1 {
            off += 1;
            continue;
        }
        if off + 1 >= doff {
            break;
        }
        let len = *l4.add(off + 1) as usize;
        if len < 2 || off + len > doff {
            break;
        }
        if kind == 2 && len == 4 {
            let v = u16::from_be_bytes([*l4.add(off + 2), *l4.add(off + 3)]);
            if v > V6T_MSS {
                let b = V6T_MSS.to_be_bytes();
                *l4.add(off + 2) = b[0];
                *l4.add(off + 3) = b[1];
                return true;
            }
            return false;
        }
        off += len;
    }
    false
}

/// What `send_frame` does with an IPv4 frame: `None` to send it as it is,
/// `Some(len)` when it was a frame to a peer stand-in, translated into
/// `v6t_out` (`0` when it cannot go: not TCP, or no neighbour yet).
pub unsafe fn tx_translate(s: &mut IpState, frame: *const u8, len: usize) -> Option<usize> {
    if !V6T || len < eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN {
        return None;
    }
    let et = ((*frame.add(12) as u16) << 8) | *frame.add(13) as u16;
    if et != eth::ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame.add(eth::ETH_HEADER_LEN);
    let dst = u32::from_be_bytes([*ip.add(16), *ip.add(17), *ip.add(18), *ip.add(19)]);
    if !is_peer(dst) {
        return None;
    }
    let src = u32::from_be_bytes([*ip.add(12), *ip.add(13), *ip.add(14), *ip.add(15)]);
    let ihl = ((*ip & 0x0F) as usize) * 4;
    let total = u16::from_be_bytes([*ip.add(2), *ip.add(3)]) as usize;
    let proto = *ip.add(9);
    let ttl = *ip.add(8);
    if !matches!(proto, ipv4::PROTO_TCP | ipv4::PROTO_UDP)
        || ihl < ipv4::IPV4_HEADER_LEN
        || total < ihl
        || eth::ETH_HEADER_LEN + total > len
    {
        s.v6t_stats.untranslatable = s.v6t_stats.untranslatable.wrapping_add(1);
        return Some(0);
    }
    let l4_len = total - ihl;
    // The datagram path refuses what would not fit (`V6T_UDP_MAX`) and TCP
    // segments at `V6T_MSS`, so this holds for every frame the stack builds.
    if ipv6::IPV6_HEADER_LEN + l4_len > LINK_MTU {
        s.v6t_stats.oversize = s.v6t_stats.oversize.wrapping_add(1);
        return Some(0);
    }
    let out_len = eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN + l4_len;
    // The source is the local IPv6 address the sender chose, by its
    // stand-in (`lane_source`, `endpoint_source`). A frame to an IPv6 peer
    // from anything else — an address since removed — has no IPv6 source of
    // its own and is not sent from another one.
    let (Some(sa), Some(da)) = (local_standin_v6(s, src), v6_of_standin(s, dst)) else {
        s.v6t_stats.untranslatable = s.v6t_stats.untranslatable.wrapping_add(1);
        return Some(0);
    };
    let Some(mac) = resolve(s, dst, src) else {
        return Some(0);
    };
    let out = s.v6t_out.as_mut_ptr();
    let l4 = out.add(eth::ETH_HEADER_LEN + ipv6::IPV6_HEADER_LEN);
    core::ptr::copy_nonoverlapping(ip.add(ihl), l4, l4_len);
    let (nh, at) = if proto == ipv4::PROTO_TCP {
        if clamp_mss(l4, l4_len) {
            s.v6t_stats.mss_clamped = s.v6t_stats.mss_clamped.wrapping_add(1);
        }
        (ipv6::NH_TCP, 16)
    } else {
        (ipv6::NH_UDP, 6)
    };
    *l4.add(at) = 0;
    *l4.add(at + 1) = 0;
    let mut c = ipv6::transport_checksum(&sa, &da, nh, l4, l4_len);
    if nh == ipv6::NH_UDP && c == 0 {
        c = 0xFFFF;
    }
    *l4.add(at) = (c >> 8) as u8;
    *l4.add(at + 1) = c as u8;
    ipv6::build_ipv6_header(
        out.add(eth::ETH_HEADER_LEN),
        l4_len as u16,
        nh,
        ttl.max(1),
        &sa,
        &da,
    );
    let me = s.mac_addr;
    eth::build_eth_header(out, &mac, &me, eth::ETHERTYPE_IPV6);
    if let Some(i) = peer_index(dst) {
        s.v6_peers[i].last_ms = dev_millis(&*s.syscalls) as u32;
    }
    s.v6t_stats.tx = s.v6t_stats.tx.wrapping_add(1);
    Some(out_len)
}

/// The flow identity of an IPv6 connection: the tuple does not fit sixteen
/// bytes, so it is named by a digest of it, the same on every host that
/// holds the connection (its first byte 0xF6, which no IPv4 identity —
/// whose first byte is a local address's first octet — can be).
pub fn flow_id_v6(local: &[u8; 16], remote: &[u8; 16], lport: u16, rport: u16) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"fxtc.v6.flow");
    h.update(local);
    h.update(remote);
    h.update(&lport.to_be_bytes());
    h.update(&rport.to_be_bytes());
    let d = h.finalize();
    let mut f = [0u8; 16];
    f[0] = 0xF6;
    f[1..16].copy_from_slice(&d[..15]);
    f
}

/// Segment size for connection `idx`.
pub unsafe fn conn_mss(s: &IpState, idx: usize) -> usize {
    if is_peer((*s.tcp_conns.ptr(idx)).remote_ip) {
        V6T_MSS as usize
    } else {
        tcp::MSS as usize
    }
}

/// The IPv6 address slot owner `owner` (nonzero) holds: its first armed
/// one, else its first (a fenced address emits nothing, so traffic from it
/// waits on the fence rather than leaving from any other address). `None`
/// when the owner holds no IPv6 address.
pub fn owner_slot(s: &IpState, owner: u16) -> Option<u16> {
    if owner == 0 {
        return None;
    }
    let mut first = None;
    let mut k = 0;
    while k < V6T_LOCALS {
        let slot = s.v6_local_slot[k];
        if slot != 0 {
            let l = &s.local_addrs[slot as usize];
            if l.is_active() && l.flags & ADDR_FLAG_V6 != 0 && l.owner_tag == owner {
                if l.flags & ADDR_FLAG_ARMED != 0 {
                    return Some(slot);
                }
                first = first.or(Some(slot));
            }
        }
        k += 1;
    }
    first
}

/// The node's own IPv6 source slot: `via` (the address a peer last reached)
/// when that is an armed IPv6 address no workload owns, else the node's
/// first armed IPv6 address. A workload's address is never the node's
/// source. `None` when the node holds no armed IPv6 address.
pub fn node_slot(s: &IpState, via: u16) -> Option<u16> {
    let node_armed = |slot: u16| {
        let i = slot as usize;
        i != 0 && i < MAX_LOCAL_ADDRS && {
            let l = &s.local_addrs[i];
            l.is_active()
                && l.flags & ADDR_FLAG_V6 != 0
                && l.flags & ADDR_FLAG_ARMED != 0
                && l.owner_tag == 0
        }
    };
    if node_armed(via) {
        return Some(via);
    }
    let mut k = 0;
    while k < V6T_LOCALS {
        let slot = s.v6_local_slot[k];
        if node_armed(slot) {
            return Some(slot);
        }
        k += 1;
    }
    None
}

/// The stand-in an outbound connection or datagram to `a` is made to: a
/// peer entry (its neighbour to be solicited). `None` for an address no
/// connection can be made to, or with no room for the peer. The caller has
/// already chosen the local IPv6 address it leaves from (`lane_source`,
/// `endpoint_source`).
pub unsafe fn dial(s: &mut IpState, a: &[u8; 16]) -> Option<u32> {
    if !V6T || ipv6::is_multicast(a) || ipv6::is_unspecified(a) {
        return None;
    }
    let i = peer_for(s, a, None)?;
    Some(peer_standin(i))
}
