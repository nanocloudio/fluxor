// nat — checksum-, ICMP- and PMTU-correct NAT44 and NAT64 packet primitives.
//
// What a translator writes, as functions of the packet and the mapping a
// tuple table (`cores/tuple_arena.rs`) chose. Nothing here holds state: the
// mapping, the address pool and the policy are the caller's.
//
// NAT44 (RFC 3022 / RFC 4787 / RFC 5508) rewrites in place. Addresses and
// ports change with RFC 1624 incremental checksum arithmetic (eqn. 3), so a
// rewrite never needs the whole payload: the IPv4 header checksum, the TCP
// or UDP checksum (a UDP checksum of zero — none — stays zero, a computed
// zero is sent as 0xFFFF, RFC 768), the ICMP query identifier, and for an
// ICMP error the embedded packet's header and port, the embedded checksums
// and the outer ICMP checksum, all agree with a from-scratch computation —
// and a packet that arrived with a bad checksum still has one. An ICMP
// error, whose outer checksum covers the rewritten quote, is rewritten only
// when that checksum verifies (`NatWhy::Checksum`).
//
// NAT64 (RFC 7915, RFC 6052, RFC 6146's header half) translates between
// families into a caller buffer: the IP header is rebuilt, the TCP/UDP
// checksum is carried across by the pseudo-header difference (only the
// addresses differ; length and protocol contribute the same to both sums),
// a UDP datagram without a checksum is given one or refused by policy, ICMP
// and ICMPv6 informational and error messages are mapped by RFC 7915's
// tables — the arriving checksum verified, the translated one recomputed
// (ICMPv6's over its pseudo header) — an error's embedded packet is
// translated too and the whole error kept within the IPv6 minimum MTU or
// RFC 1812's 576 bytes, a Packet Too Big / Fragmentation Needed MTU is
// mapped with RFC 1191's plateaus, and the hop limit / TTL is decremented as
// a router does. RFC 6052 embeds and extracts IPv4 addresses
// at every defined prefix length (32, 40, 48, 56, 64, 96), skipping the `u`
// octet, and the well-known prefix refuses non-global IPv4 (§3.1).
//
// Not translated, refused by name: fragments (`NatWhy::Fragment` — a
// translator that reassembles is a different module), IPv4 options and
// IPv6 extension headers (`NatWhy::Options`), and protocols other than TCP,
// UDP and ICMP (`NatWhy::Protocol`, which a caller answers with protocol
// unreachable / parameter problem when its profile says so).
//
// `no_std`, allocation-free, no I/O.

/// Why a packet is not rewritten or translated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatWhy {
    /// Shorter than its headers say, or than its headers.
    Short,
    /// Not the IP version the function takes.
    Version,
    /// IPv4 options or an IPv6 extension header.
    Options,
    /// A fragment (or a packet with an IPv6 Fragment Header).
    Fragment,
    /// Not TCP, UDP or ICMP.
    Protocol,
    /// An ICMP type/code RFC 7915 drops, or an error whose embedded packet
    /// is not translatable.
    Icmp,
    /// A UDP datagram with no checksum under a drop policy.
    UdpZeroChecksum,
    /// The TTL / hop limit would reach zero (the caller answers Time
    /// Exceeded).
    Ttl,
    /// The output buffer is too short.
    Capacity,
    /// An ICMP message whose checksum does not verify: rewriting it would
    /// make a corrupt message whole.
    Checksum,
    /// An address outside the profile's prefix, a set `u` octet, or a
    /// non-global IPv4 address under the well-known prefix.
    NotTranslatable,
    /// A profile prefix of an undefined length or with stray bits.
    Prefix,
}

pub const NAT_PROTO_ICMP: u8 = 1;
pub const NAT_PROTO_TCP: u8 = 6;
pub const NAT_PROTO_UDP: u8 = 17;
pub const NAT_PROTO_ICMPV6: u8 = 58;

/// IPv4 header length the translator writes (no options).
pub const NAT_V4_HDR: usize = 20;
/// IPv6 fixed header length.
pub const NAT_V6_HDR: usize = 40;
/// The IPv6 minimum MTU: an ICMPv6 error is never longer (RFC 4443 §2.4).
pub const NAT_V6_MIN_MTU: usize = 1280;
/// RFC 1812 §4.3.2.3: an ICMPv4 error quotes at most this much.
pub const NAT_V4_ICMP_ERR_MAX: usize = 576;

// ── checksum arithmetic ─────────────────────────────────────────────────

/// The Internet checksum (RFC 1071) of `data`, folded, not complemented.
pub fn nat_ones_sum(data: &[u8]) -> u16 {
    nat_fold(nat_sum_acc(0, data))
}

fn nat_sum_acc(mut s: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        s += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        s += u32::from(data[i]) << 8;
    }
    s
}

fn nat_fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s as u16
}

/// RFC 1624 eqn. 3: the new checksum field `HC'` when 16-bit words `old`
/// become `new`: `HC' = ~(~HC + ~m + m')`.
pub fn nat_csum_adjust(checksum: u16, old: &[u16], new: &[u16]) -> u16 {
    let mut s: u32 = u32::from(!checksum);
    for w in old {
        s += u32::from(!*w);
    }
    for w in new {
        s += u32::from(*w);
    }
    !nat_fold(s)
}

fn nat_words4(a: [u8; 4]) -> [u16; 2] {
    [
        u16::from_be_bytes([a[0], a[1]]),
        u16::from_be_bytes([a[2], a[3]]),
    ]
}

fn nat_words16(a: &[u8; 16]) -> [u16; 8] {
    let mut w = [0u16; 8];
    for (i, x) in w.iter_mut().enumerate() {
        *x = u16::from_be_bytes([a[2 * i], a[2 * i + 1]]);
    }
    w
}

/// The IPv4 header and TCP/UDP checksum fields after a source rewrite from
/// `(old_addr, old_port)` to `(new_addr, new_port)`.
pub fn nat44_source_rewrite(
    ip_checksum: u16,
    l4_checksum: u16,
    udp: bool,
    old_addr: [u8; 4],
    old_port: u16,
    new_addr: [u8; 4],
    new_port: u16,
) -> (u16, u16) {
    let oa = nat_words4(old_addr);
    let na = nat_words4(new_addr);
    let ip = nat_csum_adjust(ip_checksum, &oa, &na);
    if udp && l4_checksum == 0 {
        return (ip, 0);
    }
    let l4 = nat_csum_adjust(
        l4_checksum,
        &[oa[0], oa[1], old_port],
        &[na[0], na[1], new_port],
    );
    (ip, if udp && l4 == 0 { 0xFFFF } else { l4 })
}

fn rd16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn wr16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn addr4(b: &[u8], at: usize) -> [u8; 4] {
    [b[at], b[at + 1], b[at + 2], b[at + 3]]
}

fn addr16(b: &[u8], at: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    a
}

/// The IPv4 header checksum of `hdr` (its checksum field taken as zero).
pub fn nat_v4_header_checksum(hdr: &[u8]) -> u16 {
    let s = nat_sum_acc(nat_sum_acc(0, &hdr[..10]), &hdr[12..]);
    !nat_fold(s)
}

// ── IPv4 tuples and NAT44 ───────────────────────────────────────────────

/// A packet's translation identity. For ICMP queries the identifier is
/// both ports; for an ICMP error it is the embedded packet's, reversed to
/// the direction the error travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct NatV4Tuple {
    pub proto: u8,
    pub src: [u8; 4],
    pub src_port: u16,
    pub dst: [u8; 4],
    pub dst_port: u16,
    /// The packet is an ICMP error about a packet of this tuple's flow.
    pub icmp_error: bool,
}

struct V4View {
    ihl: usize,
    total: usize,
    proto: u8,
}

fn v4_view(p: &[u8]) -> Result<V4View, NatWhy> {
    if p.len() < NAT_V4_HDR {
        return Err(NatWhy::Short);
    }
    if p[0] >> 4 != 4 {
        return Err(NatWhy::Version);
    }
    let ihl = usize::from(p[0] & 0x0F) * 4;
    if ihl < NAT_V4_HDR {
        return Err(NatWhy::Short);
    }
    if ihl != NAT_V4_HDR {
        return Err(NatWhy::Options);
    }
    let total = usize::from(rd16(p, 2));
    if total < ihl || total > p.len() {
        return Err(NatWhy::Short);
    }
    Ok(V4View {
        ihl,
        total,
        proto: p[9],
    })
}

fn v4_is_fragment(p: &[u8]) -> bool {
    rd16(p, 6) & 0x3FFF != 0
}

fn icmp4_is_query(t: u8) -> bool {
    matches!(t, 0 | 8 | 13 | 14)
}

fn icmp4_is_error(t: u8) -> bool {
    matches!(t, 3 | 4 | 5 | 11 | 12)
}

/// The tuple a packet translates under.
pub fn nat_v4_tuple(p: &[u8]) -> Result<NatV4Tuple, NatWhy> {
    let v = v4_view(p)?;
    if v4_is_fragment(p) {
        return Err(NatWhy::Fragment);
    }
    let l4 = &p[v.ihl..v.total];
    let mut t = NatV4Tuple {
        proto: v.proto,
        src: addr4(p, 12),
        dst: addr4(p, 16),
        ..Default::default()
    };
    match v.proto {
        NAT_PROTO_TCP | NAT_PROTO_UDP => {
            if l4.len() < if v.proto == NAT_PROTO_TCP { 20 } else { 8 } {
                return Err(NatWhy::Short);
            }
            t.src_port = rd16(l4, 0);
            t.dst_port = rd16(l4, 2);
        }
        NAT_PROTO_ICMP => {
            if l4.len() < 8 {
                return Err(NatWhy::Short);
            }
            if icmp4_is_query(l4[0]) {
                t.src_port = rd16(l4, 4);
                t.dst_port = t.src_port;
            } else if icmp4_is_error(l4[0]) {
                let inner = nat_v4_tuple_quoted(&l4[8..])?;
                t = NatV4Tuple {
                    proto: inner.proto,
                    src: inner.dst,
                    src_port: inner.dst_port,
                    dst: inner.src,
                    dst_port: inner.src_port,
                    icmp_error: true,
                };
            } else {
                return Err(NatWhy::Icmp);
            }
        }
        _ => return Err(NatWhy::Protocol),
    }
    Ok(t)
}

/// The tuple of a quoted (possibly truncated) packet: its header and the
/// first eight bytes of its transport header.
fn nat_v4_tuple_quoted(q: &[u8]) -> Result<NatV4Tuple, NatWhy> {
    v4_view_quoted(q)?;
    let proto = q[9];
    let l4 = &q[NAT_V4_HDR..];
    let (sp, dp) = match proto {
        NAT_PROTO_TCP | NAT_PROTO_UDP => (rd16(l4, 0), rd16(l4, 2)),
        NAT_PROTO_ICMP if icmp4_is_query(l4[0]) => (rd16(l4, 4), rd16(l4, 4)),
        _ => return Err(NatWhy::Icmp),
    };
    Ok(NatV4Tuple {
        proto,
        src: addr4(q, 12),
        src_port: sp,
        dst: addr4(q, 16),
        dst_port: dp,
        icmp_error: false,
    })
}

/// Which end of a packet a NAT44 rewrite changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatSide {
    /// The source address and port (SNAT, the outbound direction).
    Source,
    /// The destination address and port (DNAT, the return direction).
    Destination,
}

/// Rewrite one end of an IPv4 packet in place to `(addr, port)`, every
/// checksum kept correct. For an ICMP query the port is the identifier
/// (both ends share it). For an ICMP error the outer header's `side` is
/// rewritten and the embedded packet's opposite end with it — the embedded
/// packet travelled the other way — so a returning error names the inside
/// flow. `ttl` decrements the TTL (a router's rewrite), refusing at one.
pub fn nat44_rewrite(
    p: &mut [u8],
    side: NatSide,
    addr: [u8; 4],
    port: u16,
    ttl: bool,
) -> Result<(), NatWhy> {
    let v = v4_view(p)?;
    if v4_is_fragment(p) {
        return Err(NatWhy::Fragment);
    }
    if ttl && p[8] <= 1 {
        return Err(NatWhy::Ttl);
    }
    let a_off = if side == NatSide::Source { 12 } else { 16 };
    let old_addr = addr4(p, a_off);
    let ihl = v.ihl;
    let total = v.total;
    match v.proto {
        NAT_PROTO_TCP | NAT_PROTO_UDP => {
            let udp = v.proto == NAT_PROTO_UDP;
            let need = if udp { 8 } else { 20 };
            if total - ihl < need {
                return Err(NatWhy::Short);
            }
            let p_off = ihl + if side == NatSide::Source { 0 } else { 2 };
            let c_off = ihl + if udp { 6 } else { 16 };
            let old_port = rd16(p, p_off);
            let l4c = rd16(p, c_off);
            let (_, nl4) = nat44_source_rewrite(0, l4c, udp, old_addr, old_port, addr, port);
            wr16(p, p_off, port);
            wr16(p, c_off, nl4);
        }
        NAT_PROTO_ICMP => {
            if total - ihl < 8 {
                return Err(NatWhy::Short);
            }
            let t = p[ihl];
            if icmp4_is_query(t) {
                let old_id = rd16(p, ihl + 4);
                let c = rd16(p, ihl + 2);
                wr16(p, ihl + 2, nat_csum_adjust(c, &[old_id], &[port]));
                wr16(p, ihl + 4, port);
            } else if icmp4_is_error(t) {
                nat44_rewrite_quoted(&mut p[ihl..total], side, addr, port)?;
            } else {
                return Err(NatWhy::Icmp);
            }
        }
        _ => return Err(NatWhy::Protocol),
    }
    // The header checksum moves with what changed (RFC 1624), so a header
    // that arrived corrupt stays corrupt.
    let mut hc = nat_csum_adjust(rd16(p, 10), &nat_words4(old_addr), &nat_words4(addr));
    p[a_off..a_off + 4].copy_from_slice(&addr);
    if ttl {
        let old = rd16(p, 8);
        p[8] -= 1;
        hc = nat_csum_adjust(hc, &[old], &[rd16(p, 8)]);
    }
    wr16(p, 10, hc);
    Ok(())
}

/// The embedded packet of an ICMP error (`icmp` is the whole ICMP message),
/// its opposite end rewritten; the ICMP checksum recomputed.
fn nat44_rewrite_quoted(
    icmp: &mut [u8],
    side: NatSide,
    addr: [u8; 4],
    port: u16,
) -> Result<(), NatWhy> {
    if nat_ones_sum(icmp) != 0xFFFF {
        return Err(NatWhy::Checksum);
    }
    let q = &mut icmp[8..];
    nat_v4_tuple_quoted(q)?;
    // The quoted packet went the other way.
    let (qa, qp) = if side == NatSide::Source {
        (16, 2)
    } else {
        (12, 0)
    };
    let old_addr = addr4(q, qa);
    let qproto = q[9];
    let l4 = NAT_V4_HDR;
    match qproto {
        NAT_PROTO_TCP | NAT_PROTO_UDP => {
            let udp = qproto == NAT_PROTO_UDP;
            let old_port = rd16(q, l4 + qp);
            wr16(q, l4 + qp, port);
            // The quoted transport checksum is adjusted only when quoted.
            let c_off = l4 + if udp { 6 } else { 16 };
            if q.len() >= c_off + 2 {
                let c = rd16(q, c_off);
                let (_, n) = nat44_source_rewrite(0, c, udp, old_addr, old_port, addr, port);
                wr16(q, c_off, n);
            }
        }
        _ => {
            let old_id = rd16(q, l4 + 4);
            let c = rd16(q, l4 + 2);
            wr16(q, l4 + 2, nat_csum_adjust(c, &[old_id], &[port]));
            wr16(q, l4 + 4, port);
        }
    }
    let qc = nat_csum_adjust(rd16(q, 10), &nat_words4(old_addr), &nat_words4(addr));
    q[qa..qa + 4].copy_from_slice(&addr);
    wr16(q, 10, qc);
    // Verified whole above, so a recomputation is the adjustment.
    wr16(icmp, 2, 0);
    let c = !nat_ones_sum(icmp);
    wr16(icmp, 2, c);
    Ok(())
}

// ── RFC 6052 address embedding ──────────────────────────────────────────

/// The RFC 6052 well-known prefix, 64:ff9b::/96.
pub const NAT64_WKP: [u8; 16] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// A NAT64 prefix: RFC 6052 §2.2's lengths only, no bits past the length,
/// the `u` octet (bits 64..71) zero.
pub fn nat64_prefix_valid(prefix: &[u8; 16], len: u8) -> bool {
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return false;
    }
    let n = usize::from(len / 8);
    prefix[n..].iter().all(|b| *b == 0) && prefix[8] == 0
}

fn v4_slots(len: u8) -> [usize; 4] {
    match len {
        32 => [4, 5, 6, 7],
        40 => [5, 6, 7, 9],
        48 => [6, 7, 9, 10],
        56 => [7, 9, 10, 11],
        64 => [9, 10, 11, 12],
        _ => [12, 13, 14, 15],
    }
}

/// Whether an IPv4 address is global for the well-known prefix's purposes
/// (RFC 6052 §3.1): not this-network, RFC 1918, shared address space
/// (RFC 6598), loopback, link-local, the IETF protocol assignments
/// (192.0.0.0/24), benchmarking (198.18.0.0/15), multicast or reserved. The
/// documentation ranges stay translatable — RFC 6052's own examples embed
/// 192.0.2.33 under 64:ff9b::/96. DNS64 synthesis excludes by this same
/// test, so a resolver never hands out an address the translator refuses.
pub fn nat_v4_is_global(a: [u8; 4]) -> bool {
    !(a[0] == 0
        || a[0] == 10
        || a[0] == 127
        || (a[0] == 100 && (a[1] & 0xC0) == 64)
        || (a[0] == 169 && a[1] == 254)
        || (a[0] == 172 && (a[1] & 0xF0) == 16)
        || (a[0] == 192 && a[1] == 0 && a[2] == 0)
        || (a[0] == 192 && a[1] == 168)
        || (a[0] == 198 && (a[1] & 0xFE) == 18)
        || a[0] >= 224)
}

/// `v4` embedded under `prefix`/`len`.
pub fn nat64_embed(prefix: &[u8; 16], len: u8, v4: [u8; 4]) -> Result<[u8; 16], NatWhy> {
    if !nat64_prefix_valid(prefix, len) {
        return Err(NatWhy::Prefix);
    }
    if len == 96 && *prefix == NAT64_WKP && !nat_v4_is_global(v4) {
        return Err(NatWhy::NotTranslatable);
    }
    let mut out = *prefix;
    for (i, s) in v4_slots(len).iter().enumerate() {
        out[*s] = v4[i];
    }
    Ok(out)
}

/// The IPv4 address embedded in `v6` under `prefix`/`len`.
pub fn nat64_extract(prefix: &[u8; 16], len: u8, v6: &[u8; 16]) -> Result<[u8; 4], NatWhy> {
    if !nat64_prefix_valid(prefix, len) {
        return Err(NatWhy::Prefix);
    }
    let n = usize::from(len / 8);
    if v6[..n] != prefix[..n] || v6[8] != 0 {
        return Err(NatWhy::NotTranslatable);
    }
    let mut out = [0u8; 4];
    for (i, s) in v4_slots(len).iter().enumerate() {
        out[i] = v6[*s];
    }
    if len == 96 && *prefix == NAT64_WKP && !nat_v4_is_global(out) {
        return Err(NatWhy::NotTranslatable);
    }
    Ok(out)
}

// ── RFC 7915 ICMP and PMTU mappings ─────────────────────────────────────

/// RFC 7915 §4.2: an ICMPv4 type/code as ICMPv6, `None` to drop.
pub fn nat_icmp4_to_icmp6(t: u8, c: u8) -> Option<(u8, u8)> {
    match (t, c) {
        (8, 0) => Some((128, 0)),
        (0, 0) => Some((129, 0)),
        (3, 0) | (3, 1) | (3, 5) | (3, 6) | (3, 7) | (3, 8) | (3, 11) | (3, 12) => Some((1, 0)),
        (3, 2) => Some((4, 1)),
        (3, 3) => Some((1, 4)),
        (3, 4) => Some((2, 0)),
        (3, 9) | (3, 10) | (3, 13) | (3, 15) => Some((1, 1)),
        (11, c) if c <= 1 => Some((3, c)),
        (12, 0) | (12, 2) => Some((4, 0)),
        _ => None,
    }
}

/// RFC 7915 §5.2: an ICMPv6 type/code as ICMPv4, `None` to drop.
pub fn nat_icmp6_to_icmp4(t: u8, c: u8) -> Option<(u8, u8)> {
    match (t, c) {
        (128, 0) => Some((8, 0)),
        (129, 0) => Some((0, 0)),
        (1, 0) | (1, 2) | (1, 3) => Some((3, 1)),
        (1, 1) => Some((3, 10)),
        (1, 4) => Some((3, 3)),
        (2, 0) => Some((3, 4)),
        (3, c) if c <= 1 => Some((11, c)),
        (4, 0) => Some((12, 0)),
        (4, 1) => Some((3, 2)),
        _ => None,
    }
}

/// RFC 1191 §7 plateaus, greatest first.
const NAT_PLATEAUS: [u16; 11] = [
    65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68,
];

/// The next-hop MTUs a translator declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatMtu {
    pub v6_nexthop: u16,
    pub v4_nexthop: u16,
}

/// RFC 7915 §4.2: the ICMPv6 Packet Too Big MTU for an ICMPv4
/// Fragmentation Needed that advertised `mtu` (zero: a pre-RFC 1191 router,
/// whose returned packet had `total_length`, answered with the greatest
/// plateau below it that is at least 1280, or 1280).
pub fn nat_pmtu_v4_to_v6(m: &NatMtu, mtu: u16, total_length: u16) -> u32 {
    let floor = NAT_V6_MIN_MTU as u16;
    let adv = if mtu == 0 {
        NAT_PLATEAUS
            .iter()
            .copied()
            .find(|v| *v < total_length && *v >= floor)
            .unwrap_or(floor)
    } else {
        mtu
    };
    (u32::from(adv) + 20)
        .min(u32::from(m.v6_nexthop))
        .min(u32::from(m.v4_nexthop) + 20)
}

/// RFC 7915 §5.2: the ICMPv4 Fragmentation Needed MTU for an ICMPv6 Packet
/// Too Big that advertised `mtu`.
pub fn nat_pmtu_v6_to_v4(m: &NatMtu, mtu: u32) -> u32 {
    mtu.saturating_sub(20)
        .min(u32::from(m.v4_nexthop))
        .min(u32::from(m.v6_nexthop).saturating_sub(20))
}

/// RFC 7915 §4.2 figure 3: an ICMPv4 Parameter Problem pointer as ICMPv6's.
fn ptr4_to_6(p: u8) -> Option<u32> {
    match p {
        0 | 1 => Some(u32::from(p)),
        2 | 3 => Some(4),
        8 => Some(7),
        9 => Some(6),
        12..=15 => Some(8),
        16..=19 => Some(24),
        _ => None,
    }
}

/// RFC 7915 §5.2 figure 6: an ICMPv6 Parameter Problem pointer as ICMPv4's.
fn ptr6_to_4(p: u32) -> Option<u8> {
    match p {
        0 | 1 => Some(p as u8),
        4 | 5 => Some(2),
        6 => Some(9),
        7 => Some(8),
        8..=23 => Some(12),
        24..=39 => Some(16),
        _ => None,
    }
}

// ── NAT64 translation ───────────────────────────────────────────────────

/// What to do with a UDP datagram that carries no checksum (IPv4 allows
/// it; IPv6 does not).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatUdpZero {
    /// Compute one (RFC 7915 §4.5).
    Compute,
    /// Refuse it (`NatWhy::UdpZeroChecksum`), for the caller to count.
    Drop,
}

/// The addresses a translation writes: outer, and for an ICMP error the
/// embedded packet's (which a stateful translator looks up in reverse).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nat64Addrs<A> {
    pub src: A,
    pub dst: A,
    pub inner_src: A,
    pub inner_dst: A,
}

/// IPv6 pseudo-header words of a transport checksum, minus length and
/// next header (which match the IPv4 pseudo header's contribution).
fn v6_addr_words(src: &[u8; 16], dst: &[u8; 16]) -> [u16; 16] {
    let mut w = [0u16; 16];
    w[..8].copy_from_slice(&nat_words16(src));
    w[8..].copy_from_slice(&nat_words16(dst));
    w
}

fn v4_addr_words(src: [u8; 4], dst: [u8; 4]) -> [u16; 4] {
    let s = nat_words4(src);
    let d = nat_words4(dst);
    [s[0], s[1], d[0], d[1]]
}

fn icmp6_checksum(src: &[u8; 16], dst: &[u8; 16], msg: &[u8]) -> u16 {
    let mut s = nat_sum_acc(0, src);
    s = nat_sum_acc(s, dst);
    let len = msg.len() as u32;
    s += len >> 16;
    s += len & 0xFFFF;
    s += u32::from(NAT_PROTO_ICMPV6);
    s = nat_sum_acc(s, msg);
    !nat_fold(s)
}

fn udp4_checksum(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> u16 {
    let mut s = nat_sum_acc(0, &src);
    s = nat_sum_acc(s, &dst);
    s += u32::from(NAT_PROTO_UDP);
    s += seg.len() as u32;
    let c = !nat_fold(nat_sum_acc(s, seg));
    if c == 0 {
        0xFFFF
    } else {
        c
    }
}

/// Translate an IPv4 packet `p` to IPv6 into `out`; the IPv6 packet's
/// length. `addrs` are the IPv6 addresses to write (outer, and inner for an
/// ICMP error); `mtu` maps a Fragmentation Needed.
pub fn nat64_v4_to_v6(
    p: &[u8],
    out: &mut [u8],
    addrs: &Nat64Addrs<[u8; 16]>,
    udp_zero: NatUdpZero,
    mtu: &NatMtu,
) -> Result<usize, NatWhy> {
    let v = v4_view(p)?;
    if v4_is_fragment(p) {
        return Err(NatWhy::Fragment);
    }
    if p[8] <= 1 {
        return Err(NatWhy::Ttl);
    }
    let l4 = &p[v.ihl..v.total];
    let n = v4_to_v6_inner(
        p,
        l4,
        out,
        &addrs.src,
        &addrs.dst,
        p[8] - 1,
        Some(addrs),
        udp_zero,
        mtu,
    )?;
    Ok(n)
}

/// One level of v4→v6: the outer packet (`inner_addrs` set) or a quoted one
/// (`None`, its transport possibly truncated and its checksums adjusted
/// only, never recomputed).
#[allow(
    clippy::too_many_arguments,
    reason = "one level of a translation takes the packet, its output and the addresses and policy that level writes"
)]
fn v4_to_v6_inner(
    hdr: &[u8],
    l4: &[u8],
    out: &mut [u8],
    src: &[u8; 16],
    dst: &[u8; 16],
    hop: u8,
    outer: Option<&Nat64Addrs<[u8; 16]>>,
    udp_zero: NatUdpZero,
    mtu: &NatMtu,
) -> Result<usize, NatWhy> {
    let proto = hdr[9];
    let next = if proto == NAT_PROTO_ICMP {
        NAT_PROTO_ICMPV6
    } else {
        proto
    };
    if !matches!(proto, NAT_PROTO_TCP | NAT_PROTO_UDP | NAT_PROTO_ICMP) {
        return Err(NatWhy::Protocol);
    }
    // The outer packet's payload length is what we write; a quoted one
    // keeps its original's.
    let max_out = if outer.is_some() {
        out.len()
    } else {
        out.len().min(NAT_V6_MIN_MTU)
    };
    if max_out < NAT_V6_HDR + l4.len().min(8) {
        return Err(NatWhy::Capacity);
    }
    // A quote is truncated to what the error may carry.
    let l4 = if outer.is_none() {
        &l4[..l4.len().min(max_out - NAT_V6_HDR)]
    } else {
        l4
    };
    // Header.
    let tc = hdr[1];
    out[0] = 0x60 | (tc >> 4);
    out[1] = tc << 4;
    out[2] = 0;
    out[3] = 0;
    out[6] = next;
    out[7] = hop;
    out[8..24].copy_from_slice(src);
    out[24..40].copy_from_slice(dst);
    let payload_len_orig = usize::from(rd16(hdr, 2)).saturating_sub(NAT_V4_HDR);
    let body = &mut out[NAT_V6_HDR..];
    let (src4, dst4) = (addr4(hdr, 12), addr4(hdr, 16));
    let written = match proto {
        NAT_PROTO_TCP | NAT_PROTO_UDP => {
            let udp = proto == NAT_PROTO_UDP;
            if body.len() < l4.len() {
                return Err(NatWhy::Capacity);
            }
            body[..l4.len()].copy_from_slice(l4);
            let c_off = if udp { 6 } else { 16 };
            if l4.len() >= c_off + 2 {
                let c = rd16(l4, c_off);
                let nc = if udp && c == 0 {
                    if outer.is_none() {
                        0
                    } else if udp_zero == NatUdpZero::Drop {
                        return Err(NatWhy::UdpZeroChecksum);
                    } else {
                        let full = udp4_checksum(src4, dst4, l4);
                        nat_csum_adjust(full, &v4_addr_words(src4, dst4), &v6_addr_words(src, dst))
                    }
                } else {
                    nat_csum_adjust(c, &v4_addr_words(src4, dst4), &v6_addr_words(src, dst))
                };
                // A computed zero is sent as all ones; only a quote keeps
                // the zero (none) it carried.
                let keep_none = udp && c == 0 && outer.is_none();
                let nc = if udp && nc == 0 && !keep_none {
                    0xFFFF
                } else {
                    nc
                };
                wr16(body, c_off, nc);
            } else if outer.is_some() {
                return Err(NatWhy::Short);
            }
            l4.len()
        }
        _ => {
            if l4.len() < 8 {
                return Err(NatWhy::Short);
            }
            if outer.is_some() && nat_ones_sum(l4) != 0xFFFF {
                return Err(NatWhy::Checksum);
            }
            let (t, c) = (l4[0], l4[1]);
            let (nt, nc) = nat_icmp4_to_icmp6(t, c).ok_or(NatWhy::Icmp)?;
            if icmp4_is_error(t) {
                let Some(o) = outer else {
                    // An error quoting an error is not translated.
                    return Err(NatWhy::Icmp);
                };
                body[0] = nt;
                body[1] = nc;
                body[4..8].fill(0);
                if t == 3 && c == 4 {
                    let adv = rd16(l4, 6);
                    let qlen = if l4.len() >= 8 + 4 {
                        rd16(l4, 8 + 2)
                    } else {
                        0
                    };
                    let m = nat_pmtu_v4_to_v6(mtu, adv, qlen);
                    body[4..8].copy_from_slice(&m.to_be_bytes());
                } else if t == 12 {
                    let ptr = ptr4_to_6(l4[4]).ok_or(NatWhy::Icmp)?;
                    body[4..8].copy_from_slice(&ptr.to_be_bytes());
                } else if t == 3 && c == 2 {
                    // Protocol unreachable: pointer to the next header field.
                    body[4..8].copy_from_slice(&6u32.to_be_bytes());
                }
                let q = &l4[8..];
                let qv = v4_view_quoted(q)?;
                let qhop = q[8];
                // The whole error stays within the IPv6 minimum MTU.
                let room = (max_out - NAT_V6_HDR - 8).min(NAT_V6_MIN_MTU - NAT_V6_HDR - 8);
                let mut qbuf = [0u8; NAT_V6_MIN_MTU];
                let qn = v4_to_v6_inner(
                    q,
                    &q[NAT_V4_HDR..qv],
                    &mut qbuf[..room],
                    &o.inner_src,
                    &o.inner_dst,
                    qhop,
                    None,
                    udp_zero,
                    mtu,
                )?;
                body[8..8 + qn].copy_from_slice(&qbuf[..qn]);
                8 + qn
            } else {
                if body.len() < l4.len() {
                    return Err(NatWhy::Capacity);
                }
                body[..l4.len()].copy_from_slice(l4);
                body[0] = nt;
                body[1] = nc;
                l4.len()
            }
        }
    };
    // The payload length: ours for the outer packet; the original's for a
    // quoted one, which may be truncated.
    let plen = if outer.is_some() {
        written
    } else {
        payload_len_orig
    };
    wr16(out, 4, plen as u16);
    if proto == NAT_PROTO_ICMP {
        let body = &mut out[NAT_V6_HDR..NAT_V6_HDR + written];
        wr16(body, 2, 0);
        if outer.is_some() {
            let c = icmp6_checksum(src, dst, body);
            wr16(body, 2, c);
        } else {
            // A quoted ICMP query: its checksum moves by the type change
            // and the pseudo header, which a truncated quote cannot
            // recompute; carry the original's adjusted.
            let old = rd16(l4, 2);
            let tw_old = u16::from_be_bytes([l4[0], l4[1]]);
            let tw_new = u16::from_be_bytes([body[0], body[1]]);
            let len = payload_len_orig as u32;
            let mut nw = [0u16; 16 + 3];
            nw[..16].copy_from_slice(&v6_addr_words(src, dst));
            nw[16] = (len >> 16) as u16;
            nw[17] = (len & 0xFFFF) as u16;
            nw[18] = u16::from(NAT_PROTO_ICMPV6);
            let c = nat_csum_adjust(old, &[tw_old], &[tw_new]);
            let c = nat_csum_adjust(c, &[], &nw);
            wr16(body, 2, c);
        }
    }
    Ok(NAT_V6_HDR + written)
}

/// A quoted IPv4 packet's header end offset into its transport bytes
/// (the quote's whole length, since it may be truncated).
fn v4_view_quoted(q: &[u8]) -> Result<usize, NatWhy> {
    if q.len() < NAT_V4_HDR + 8 || q[0] >> 4 != 4 {
        return Err(NatWhy::Icmp);
    }
    if usize::from(q[0] & 0x0F) * 4 != NAT_V4_HDR {
        return Err(NatWhy::Options);
    }
    if v4_is_fragment(q) {
        return Err(NatWhy::Fragment);
    }
    Ok(q.len())
}

/// Translate an IPv6 packet `p` to IPv4 into `out`; the IPv4 packet's
/// length. `ident` is the Identification to write; DF is set past 1260
/// bytes (RFC 7915 §5.1).
pub fn nat64_v6_to_v4(
    p: &[u8],
    out: &mut [u8],
    addrs: &Nat64Addrs<[u8; 4]>,
    ident: u16,
    mtu: &NatMtu,
) -> Result<usize, NatWhy> {
    if p.len() < NAT_V6_HDR {
        return Err(NatWhy::Short);
    }
    if p[0] >> 4 != 6 {
        return Err(NatWhy::Version);
    }
    let plen = usize::from(rd16(p, 4));
    if NAT_V6_HDR + plen > p.len() {
        return Err(NatWhy::Short);
    }
    if p[7] <= 1 {
        return Err(NatWhy::Ttl);
    }
    v6_to_v4_inner(
        p,
        &p[NAT_V6_HDR..NAT_V6_HDR + plen],
        out,
        addrs.src,
        addrs.dst,
        p[7] - 1,
        ident,
        Some(addrs),
        mtu,
    )
}

fn v6_next_ok(next: u8) -> Result<u8, NatWhy> {
    match next {
        NAT_PROTO_TCP | NAT_PROTO_UDP => Ok(next),
        NAT_PROTO_ICMPV6 => Ok(NAT_PROTO_ICMP),
        44 => Err(NatWhy::Fragment),
        0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 => Err(NatWhy::Options),
        _ => Err(NatWhy::Protocol),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one level of a translation takes the packet, its output and the addresses and policy that level writes"
)]
fn v6_to_v4_inner(
    hdr: &[u8],
    l4: &[u8],
    out: &mut [u8],
    src: [u8; 4],
    dst: [u8; 4],
    ttl: u8,
    ident: u16,
    outer: Option<&Nat64Addrs<[u8; 4]>>,
    mtu: &NatMtu,
) -> Result<usize, NatWhy> {
    let proto = v6_next_ok(hdr[6])?;
    let max_out = if outer.is_some() {
        out.len()
    } else {
        out.len().min(NAT_V4_ICMP_ERR_MAX)
    };
    if max_out < NAT_V4_HDR + l4.len().min(8) {
        return Err(NatWhy::Capacity);
    }
    let l4 = if outer.is_none() {
        &l4[..l4.len().min(max_out - NAT_V4_HDR)]
    } else {
        l4
    };
    let (src6, dst6) = (addr16(hdr, 8), addr16(hdr, 24));
    let payload_len_orig = usize::from(rd16(hdr, 4));
    let body_cap = max_out - NAT_V4_HDR;
    let written = {
        let body = &mut out[NAT_V4_HDR..NAT_V4_HDR + body_cap];
        match proto {
            NAT_PROTO_TCP | NAT_PROTO_UDP => {
                let udp = proto == NAT_PROTO_UDP;
                if body.len() < l4.len() {
                    return Err(NatWhy::Capacity);
                }
                body[..l4.len()].copy_from_slice(l4);
                let c_off = if udp { 6 } else { 16 };
                if l4.len() >= c_off + 2 {
                    let c = rd16(l4, c_off);
                    let nc =
                        nat_csum_adjust(c, &v6_addr_words(&src6, &dst6), &v4_addr_words(src, dst));
                    wr16(body, c_off, if udp && nc == 0 { 0xFFFF } else { nc });
                } else if outer.is_some() {
                    return Err(NatWhy::Short);
                }
                l4.len()
            }
            _ => {
                if l4.len() < 8 {
                    return Err(NatWhy::Short);
                }
                if outer.is_some() && icmp6_checksum(&src6, &dst6, l4) != 0 {
                    return Err(NatWhy::Checksum);
                }
                let (t, c) = (l4[0], l4[1]);
                let (nt, nc) = nat_icmp6_to_icmp4(t, c).ok_or(NatWhy::Icmp)?;
                if t < 128 {
                    let Some(o) = outer else {
                        return Err(NatWhy::Icmp);
                    };
                    body[0] = nt;
                    body[1] = nc;
                    body[4..8].fill(0);
                    if t == 2 {
                        let adv = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                        let m = nat_pmtu_v6_to_v4(mtu, adv).min(0xFFFF) as u16;
                        body[6..8].copy_from_slice(&m.to_be_bytes());
                    } else if t == 4 && c == 0 {
                        let ptr = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
                        body[4] = ptr6_to_4(ptr).ok_or(NatWhy::Icmp)?;
                    }
                    let q = &l4[8..];
                    if q.len() < NAT_V6_HDR + 8 || q[0] >> 4 != 6 {
                        return Err(NatWhy::Icmp);
                    }
                    // The whole error stays within RFC 1812's 576 bytes.
                    let room = (body_cap - 8).min(NAT_V4_ICMP_ERR_MAX - NAT_V4_HDR - 8);
                    let mut qbuf = [0u8; NAT_V4_ICMP_ERR_MAX];
                    let qn = v6_to_v4_inner(
                        q,
                        &q[NAT_V6_HDR..],
                        &mut qbuf[..room],
                        o.inner_src,
                        o.inner_dst,
                        q[7],
                        0,
                        None,
                        mtu,
                    )?;
                    body[8..8 + qn].copy_from_slice(&qbuf[..qn]);
                    8 + qn
                } else {
                    if body.len() < l4.len() {
                        return Err(NatWhy::Capacity);
                    }
                    body[..l4.len()].copy_from_slice(l4);
                    body[0] = nt;
                    body[1] = nc;
                    l4.len()
                }
            }
        }
    };
    let total = if outer.is_some() {
        NAT_V4_HDR + written
    } else {
        NAT_V4_HDR + payload_len_orig
    };
    let tc = (hdr[0] << 4) | (hdr[1] >> 4);
    out[0] = 0x45;
    out[1] = tc;
    wr16(out, 2, total as u16);
    wr16(out, 4, ident);
    wr16(out, 6, if total > 1260 { 0x4000 } else { 0 });
    out[8] = ttl;
    out[9] = proto;
    out[12..16].copy_from_slice(&src);
    out[16..20].copy_from_slice(&dst);
    wr16(out, 10, 0);
    let c = nat_v4_header_checksum(&out[..NAT_V4_HDR]);
    wr16(out, 10, c);
    if proto == NAT_PROTO_ICMP {
        let body = &mut out[NAT_V4_HDR..NAT_V4_HDR + written];
        if outer.is_some() {
            wr16(body, 2, 0);
            let c = !nat_ones_sum(body);
            wr16(body, 2, c);
        } else {
            let old = rd16(l4, 2);
            let tw_old = u16::from_be_bytes([l4[0], l4[1]]);
            let tw_new = u16::from_be_bytes([body[0], body[1]]);
            let len = payload_len_orig as u32;
            let mut ow = [0u16; 16 + 3];
            ow[..16].copy_from_slice(&v6_addr_words(&src6, &dst6));
            ow[16] = (len >> 16) as u16;
            ow[17] = (len & 0xFFFF) as u16;
            ow[18] = u16::from(NAT_PROTO_ICMPV6);
            let c = nat_csum_adjust(old, &ow, &[]);
            let c = nat_csum_adjust(c, &[tw_old], &[tw_new]);
            wr16(body, 2, c);
        }
    }
    Ok(NAT_V4_HDR + written)
}
