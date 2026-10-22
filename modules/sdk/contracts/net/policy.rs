// Contract: net.policy — the platform enforces packet policy and service NAT.
//
// Layer: contracts (public, stable).
//
// A consumer states WHAT traffic is allowed and where a virtual address leads;
// the platform decides HOW: the host's packet filter on Linux, the native packet
// filter on bare metal, nothing (and says so) where there is nothing to enforce
// with.
// The consumer never names a platform and never renders a platform's syntax,
// so the same compiled policy runs everywhere and the difference between
// targets is a capability bit, not a code path.
//
// ## Tables
//
// Policy lives in named TABLES, each replaced atomically and whole. A
// controller owns a table (`netpolicy`, `proxy`) and republishes it when its
// inputs change; there is no rule-by-rule edit, because an edit sequence that
// is interrupted leaves a policy nobody wrote. Every REPLACE advances the
// table's GENERATION, which is how an in-graph enforcer (the bare-metal packet
// filter) learns it must re-read.
//
// ## Honesty
//
// `CAPS` states what the provider will ENFORCE, not what it will accept. A
// provider that records tables but cannot act on them (wasm; bare metal with
// no filter in the packet path) accepts REPLACE and leaves [`caps::ENFORCED`]
// clear. A consumer that must not run unenforced — a workload has a policy —
// reads the bit and reports the gap; it never assumes. A rule kind the
// provider cannot realize at all fails REPLACE with `ENOSYS` rather than being
// dropped: a table that silently lost its DNAT is a service that silently
// stopped working.
//
// ## Authority
//
// The tables are the node's: REPLACE, CLEAR and ATTACH answer `EACCES` to a
// module not acting with the node's authority, whatever it holds. REPLACE
// and CLEAR also need `platform_raw`; PROBE, CAPS and READ need neither.
//
// Little-endian lengths, big-endian addresses and ports (network order, as
// they appear on the wire the rules describe).

/// Provider class id (opcode class 0x1Exx). Mirrors
/// `kernel::module::provider::contract::NET_POLICY`.
pub const CLASS: u16 = 0x001E;

/// Returns 1 when a net.policy provider is present. handle=-1, arg=null.
pub const PROBE: u32 = 0x1E00;

/// Capability bitmap. handle=-1, arg = `[caps_out:u32 LE]` (4 bytes, written).
/// Returns 0.
pub const CAPS: u32 = 0x1E01;

/// Replace a table atomically. handle=-1, arg:
/// ```text
/// [name_len:u8][name bytes]        table name, 1..=MAX_TABLE_NAME
/// [rules_ptr:u64 LE][rules_len:u32 LE]
/// [gen_out_ptr:u64 LE]             receives the new generation (u64 LE), or 0
/// ```
/// `rules` is a sequence of rule records (see [`rule`]). An empty sequence is
/// a table with no rules — not a deletion; [`CLEAR`] deletes. Returns 0, or
/// `EINVAL` (malformed), `ENOSPC` (too many tables/rules), `ENOSYS` (a rule
/// kind this provider cannot realize), `EACCES` (not the node's authority),
/// `EAGAIN` (another REPLACE or CLEAR is being applied), or the platform's
/// error applying it — in which case the stored table is as it was.
pub const REPLACE: u32 = 0x1E02;

/// Delete a table. handle=-1, arg = `[name_len:u8][name bytes]`. Idempotent;
/// returns 0, or `EACCES` (not the node's authority), `EAGAIN` (another
/// change is being applied) or the platform's error removing it. Deleting a
/// table that exists consumes a generation (the
/// store-wide one [`READ`] reports for a zero-length name), so one poll of
/// that value notices a deletion as it notices a replace.
pub const CLEAR: u32 = 0x1E03;

/// Read a table back: its state and rules. handle=-1, arg:
/// ```text
/// [name_len:u8][name bytes]
/// [out_ptr:u64 LE][out_cap:u32 LE]  receives the rule records
/// [state_out_ptr:u64 LE]            receives the table's state, or 0
/// ```
/// The state is [`state::BYTES`] bytes (see [`state`]): the table's
/// generation, the generation its enforcer last applied, and the per-table
/// flags — [`state::ENFORCED`] among them. Returns the byte count written,
/// `ENOENT` for no such table, `ERANGE` when `out_cap` is too small (the
/// state is still written), or `EAGAIN` when a concurrent writer kept the
/// store moving for every bounded retry (the caller keeps its previous copy).
///
/// A zero-length name (`name_len = 0`, no name bytes, the rest as above)
/// reads the STORE: the state's generation is the last generation issued by
/// any REPLACE or CLEAR, nothing is copied to `out`, and the call returns 0.
/// An enforcer polls that one value, and re-reads its tables only when it
/// moved.
pub const READ: u32 = 0x1E04;

/// An in-graph enforcer (the bare-metal packet filter, `ip`) declares the
/// tables it applies, and reports what it applied. handle=-1, arg: one or
/// more entries, back to back,
/// ```text
/// [name_len:u8][name bytes][applied_gen:u64 LE]
/// ```
/// `applied_gen` is the generation of that table the enforcer has applied in
/// full, or 0 for none yet. The first ATTACH naming a table binds it to the
/// calling module, by its slot and that slot's generation; re-issuing ATTACH
/// with a new `applied_gen` reports progress. A table has at most one
/// enforcer: naming a table bound to another live enforcer is `EBUSY`, and
/// the call changes nothing (all entries or none). A binding ends when its
/// module's slot is released or re-occupied. Returns 0, `EINVAL` (malformed),
/// `ENOSPC` (more bound tables than the store holds), `EBUSY`, or `EACCES` to
/// a caller not acting with the node's authority (attaching is a claim about
/// the node's packet policy; it needs no `platform_raw`).
///
/// A table is ENFORCED ([`state::ENFORCED`] in its READ state) only while an
/// enforcer is bound for it and the generation it applied equals the stored
/// one: an enforcer that could not hold a table (oversized), kept a stale
/// copy, or faulted leaves the flag clear, so a consumer never believes a
/// policy is in force on a node with no filter in the path. A platform whose
/// provider realizes tables itself (Linux) is that table's enforcer the
/// moment a REPLACE it applied lands.
pub const ATTACH: u32 = 0x1E05;

/// Bytes after an ATTACH entry's name: its `applied_gen`.
pub const ATTACH_TAIL: usize = 8;

/// The table state [`READ`] writes to `state_out_ptr`.
/// ```text
/// [generation:u64 LE][applied_gen:u64 LE][flags:u32 LE][reserved:u32]
/// ```
pub mod state {
    /// Size of the state record.
    pub const BYTES: usize = 24;
    /// Offset of the table's generation (for a zero-length name: the
    /// store-wide last generation issued).
    pub const GENERATION: usize = 0;
    /// Offset of the generation the bound enforcer last applied (0: none).
    pub const APPLIED: usize = 8;
    /// Offset of the flags word.
    pub const FLAGS: usize = 16;
    /// Flag: an enforcer is bound and has applied this exact generation —
    /// the table is in force.
    pub const ENFORCED: u32 = 1 << 0;
    /// Flag: an enforcer is bound for the table (whatever it applied).
    pub const BOUND: u32 = 1 << 1;
}

/// Longest table name.
pub const MAX_TABLE_NAME: usize = 32;

/// Capability bits.
pub mod caps {
    /// ALLOW / DROP / ISOLATE rules are understood.
    pub const FILTER: u32 = 1 << 0;
    /// DNAT rules are understood.
    pub const DNAT: u32 = 1 << 1;
    /// A DNAT with more than one backend is balanced across them.
    pub const BALANCE: u32 = 1 << 2;
    /// EGRESS-direction filter rules are understood.
    pub const EGRESS: u32 = 1 << 3;
    /// Accepted tables CAN take effect on traffic: the provider realizes them
    /// itself, or an in-graph enforcer is attached. Clear on a provider that
    /// only records them. Whether one table IS in force is that table's
    /// [`super::state::ENFORCED`] flag.
    pub const ENFORCED: u32 = 1 << 4;
    /// DNAT `translate_source` other than never is realized.
    pub const SOURCE_TRANSLATE: u32 = 1 << 5;
    /// DNAT records with `scope = local` (traffic originated on this node)
    /// are realized. A provider with this bit and without [`DNAT`] refuses a
    /// `scope = any` record with `ENOSYS`.
    pub const DNAT_LOCAL: u32 = 1 << 6;
}

/// Rule records. Each is `[kind:u8][body_len:u8][body]`; a reader skips a kind
/// it does not know by `body_len` only when the kind is ADVISORY (bit 7 set) —
/// an unknown mandatory kind fails the REPLACE (`ENOSYS`).
pub mod rule {
    /// Let matching traffic through. Body:
    /// ```text
    /// [dir:u8][proto:u8]
    /// [subject_addr:u32 BE][subject_prefix:u8]  the workloads the rule is about
    /// [peer_addr:u32 BE][peer_prefix:u8]        the other end (0/0 = any)
    /// [port_lo:u16 BE][port_hi:u16 BE]          DESTINATION port range (0/0 = any)
    /// ```
    /// The port is always the destination's: the subject's own port for
    /// ingress, the peer's for egress, in both directions alike, as
    /// orchestrator network policies define a rule's ports.
    pub const ALLOW: u8 = 1;
    /// Drop matching traffic. Same body as [`ALLOW`].
    pub const DROP: u8 = 2;
    /// Default-deny for a subject in one direction: traffic to (ingress) or
    /// from (egress) it passes only if an ALLOW in the same table matches.
    /// Body: `[dir:u8][subject_addr:u32 BE][subject_prefix:u8]`.
    pub const ISOLATE: u8 = 3;
    /// Destination NAT: traffic to `vip:vport` goes to one of the backends.
    /// Body:
    /// ```text
    /// [proto:u8][vip:u32 BE][vport:u16 BE][n:u8][flags:u8]
    /// n × ([addr:u32 BE][port:u16 BE])
    /// ```
    /// `flags`: bits 0–1 `translate_source` ([`XLATE_NEVER`],
    /// [`XLATE_HAIRPIN`], [`XLATE_ALWAYS`]), bit 2 [`DNAT_SCOPE_LOCAL`]; the
    /// other bits are zero.
    ///
    /// A backend port of 0 is the service's own port (`vport`).
    ///
    /// `n == 0` is a VIP with no backends: traffic to it is rejected, not
    /// passed through to an address nothing serves. A VIP with more backends
    /// than one record holds ([`DNAT_MAX_BACKENDS`]) is several DNAT records
    /// for the same `proto`/`vip`/`vport` in one table; the provider merges
    /// them into one balanced set, and the records must agree on `flags`.
    /// IPv4 only.
    pub const DNAT: u8 = 4;
    /// `translate_source` (flags bits 0–1): preserve the caller's source.
    pub const XLATE_NEVER: u8 = 0;
    /// Translate the source to the segment gateway, only when after
    /// translation source and destination are the same workload.
    pub const XLATE_HAIRPIN: u8 = 1;
    /// Translate the source to the egress interface's address, every
    /// translated flow.
    pub const XLATE_ALWAYS: u8 = 2;
    /// Mask of `translate_source` in the flags byte.
    pub const DNAT_XLATE_MASK: u8 = 0x03;
    /// Flags bit 2: translate only traffic originated on this node (its
    /// workloads and its own dials); clear = any traffic reaching the node.
    pub const DNAT_SCOPE_LOCAL: u8 = 1 << 2;
    /// Every flags bit with a meaning.
    pub const DNAT_FLAGS_KNOWN: u8 = DNAT_XLATE_MASK | DNAT_SCOPE_LOCAL;
    /// Bit 7 of `kind`: the record may be skipped by a provider that does not
    /// know it.
    pub const ADVISORY: u8 = 0x80;

    /// `dir` values.
    pub const DIR_INGRESS: u8 = 0;
    pub const DIR_EGRESS: u8 = 1;
    /// `proto` values (IP protocol numbers); 0 matches any.
    pub const PROTO_ANY: u8 = 0;
    pub const PROTO_ICMP: u8 = 1;
    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;

    /// Body sizes of the fixed-shape kinds.
    pub const FILTER_BODY: usize = 1 + 1 + 4 + 1 + 4 + 1 + 2 + 2;
    pub const ISOLATE_BODY: usize = 1 + 4 + 1;
    /// DNAT body before its backends, and per backend.
    pub const DNAT_HEAD: usize = 1 + 4 + 2 + 1 + 1;
    pub const DNAT_BACKEND: usize = 4 + 2;
    /// The most backends one DNAT can carry: `body_len` is a u8.
    pub const DNAT_MAX_BACKENDS: usize = (255 - DNAT_HEAD) / DNAT_BACKEND;
}

/// A filter rule's fields (ALLOW / DROP), decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    pub dir: u8,
    pub proto: u8,
    pub subject: u32,
    pub subject_prefix: u8,
    pub peer: u32,
    pub peer_prefix: u8,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// A DNAT rule's head, decoded; its backends are read with [`dnat_backend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dnat {
    pub proto: u8,
    pub vip: u32,
    pub vport: u16,
    pub backends: u8,
    /// The raw flags byte; read it with [`Dnat::translate_source`] and
    /// [`Dnat::local`].
    pub flags: u8,
}

impl Dnat {
    /// `translate_source`: [`rule::XLATE_NEVER`], [`rule::XLATE_HAIRPIN`]
    /// or [`rule::XLATE_ALWAYS`].
    pub fn translate_source(&self) -> u8 {
        self.flags & rule::DNAT_XLATE_MASK
    }
    /// `scope = local`.
    pub fn local(&self) -> bool {
        self.flags & rule::DNAT_SCOPE_LOCAL != 0
    }
}

// Every reader below is panic-free — `.get()` and raw reads, no indexing
// that could fail, no slice `.contains`, no iterator adapters — because the
// in-graph enforcers (`ip`, `pkt_filter`) link it under the strict PIC rules,
// where a panic path is a link error.

fn byte(b: &[u8], at: usize) -> u8 {
    match b.get(at) {
        Some(v) => *v,
        None => 0,
    }
}
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([
        byte(b, at),
        byte(b, at + 1),
        byte(b, at + 2),
        byte(b, at + 3),
    ])
}
fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([byte(b, at), byte(b, at + 1)])
}

/// The rule record at `at`: `(kind, body, next)`, or None past the end or on a
/// record that runs past it. One implementation, so every provider and the
/// in-graph enforcer agree on what a table says.
pub fn next_rule(rules: &[u8], at: usize) -> Option<(u8, &[u8], usize)> {
    let kind = *rules.get(at)?;
    let len = *rules.get(at + 1)? as usize;
    let end = at + 2 + len;
    let body = rules.get(at + 2..end)?;
    Some((kind, body, end))
}

/// Decode an ALLOW/DROP body.
pub fn filter(body: &[u8]) -> Option<Filter> {
    if body.len() != rule::FILTER_BODY || byte(body, 0) > rule::DIR_EGRESS {
        return None;
    }
    let f = Filter {
        dir: byte(body, 0),
        proto: byte(body, 1),
        subject: be32(body, 2),
        subject_prefix: byte(body, 6),
        peer: be32(body, 7),
        peer_prefix: byte(body, 11),
        port_lo: be16(body, 12),
        port_hi: be16(body, 14),
    };
    if f.subject_prefix > 32 || f.peer_prefix > 32 {
        return None;
    }
    Some(f)
}

/// Decode an ISOLATE body: `(dir, subject, prefix)`.
pub fn isolate(body: &[u8]) -> Option<(u8, u32, u8)> {
    if body.len() != rule::ISOLATE_BODY || byte(body, 0) > rule::DIR_EGRESS || byte(body, 5) > 32 {
        return None;
    }
    Some((byte(body, 0), be32(body, 1), byte(body, 5)))
}

/// Decode a DNAT head, checking the body holds exactly its backends and its
/// flags are ones this contract defines.
pub fn dnat(body: &[u8]) -> Option<Dnat> {
    if body.len() < rule::DNAT_HEAD {
        return None;
    }
    let d = Dnat {
        proto: byte(body, 0),
        vip: be32(body, 1),
        vport: be16(body, 5),
        backends: byte(body, 7),
        flags: byte(body, 8),
    };
    if body.len() != rule::DNAT_HEAD + d.backends as usize * rule::DNAT_BACKEND {
        return None;
    }
    if d.flags & !rule::DNAT_FLAGS_KNOWN != 0
        || d.flags & rule::DNAT_XLATE_MASK > rule::XLATE_ALWAYS
    {
        return None;
    }
    Some(d)
}

/// Whether an earlier DNAT record in `rules[..until]` for the same
/// `(proto, vip, vport)` as `d` carries different flags.
fn dnat_conflicts(rules: &[u8], until: usize, d: &Dnat) -> bool {
    let mut at = 0;
    while at < until {
        let Some((kind, body, next)) = next_rule(rules, at) else {
            return false;
        };
        if kind == rule::DNAT {
            if let Some(e) = dnat(body) {
                if e.proto == d.proto && e.vip == d.vip && e.vport == d.vport && e.flags != d.flags
                {
                    return true;
                }
            }
        }
        at = next;
    }
    false
}

/// Backend `i` of a DNAT body: `(addr, port)`.
pub fn dnat_backend(body: &[u8], i: usize) -> Option<(u32, u16)> {
    let at = rule::DNAT_HEAD + i * rule::DNAT_BACKEND;
    if at + rule::DNAT_BACKEND > body.len() {
        return None;
    }
    Some((be32(body, at), be16(body, at + 4)))
}

// ── The evaluator ───────────────────────────────────────────────────────
//
// What a table does to one packet, for an in-graph enforcer (`ip`,
// `pkt_filter`) — the same decision the Linux provider's rendering makes in
// the host's packet filter, rule for rule, so a policy means the same on
// every node (checked by a differential test against the rendered rules):
//
// 1. ALLOW and DROP records in table order; the first that matches decides.
// 2. Otherwise an ISOLATE drops a packet to (ingress) or from (egress) its
//    subject.
// 3. Otherwise a packet to a service address with no backends is rejected.
// 4. Otherwise it passes.
//
// A packet passes the node only if every table passes it. The judgement is
// for a flow's first packet: an established flow keeps the verdict its
// first packet had (connection tracking on Linux, the flow's own record on
// bare metal), so the evaluator never sees one.

/// A packet as policy judges it: addresses host order, `dport` the
/// destination port (0 for ICMP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub dport: u16,
}

/// A table's verdict on a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
}

/// `addr` lies in `net/prefix` (prefix 0 matches everything).
#[inline]
pub fn in_net(addr: u32, net: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        !(u32::MAX >> prefix)
    };
    (addr & mask) == (net & mask)
}

/// The layer-4 part of a rule — `(proto, lo, hi)`, ports the destination's,
/// `0/0` none — matches the packet, as the Linux rendering spells it: TCP or
/// UDP with ports match that protocol and port range; TCP or UDP alone, that
/// protocol; ICMP matches ICMP whatever the ports; any other protocol with
/// ports matches TCP or UDP to those ports, and with none, every packet.
#[inline]
pub fn l4_matches(proto: u8, lo: u16, hi: u16, p: &Packet) -> bool {
    let ports = lo != 0 || hi != 0;
    let port_ok = if hi == 0 || hi == lo {
        p.dport == lo
    } else {
        p.dport >= lo && p.dport <= hi
    };
    let tcp_udp = p.proto == rule::PROTO_TCP || p.proto == rule::PROTO_UDP;
    match proto {
        rule::PROTO_TCP | rule::PROTO_UDP => p.proto == proto && (!ports || port_ok),
        rule::PROTO_ICMP => p.proto == rule::PROTO_ICMP,
        _ if ports => tcp_udp && port_ok,
        _ => true,
    }
}

/// One table's verdict on `p` (see the section comment).
pub fn evaluate(rules: &[u8], p: &Packet) -> Verdict {
    // 1. ALLOW / DROP, first match.
    let mut at = 0;
    while let Some((kind, body, next)) = next_rule(rules, at) {
        at = next;
        if kind != rule::ALLOW && kind != rule::DROP {
            continue;
        }
        let Some(f) = filter(body) else { continue };
        let (subject, peer) = if f.dir == rule::DIR_INGRESS {
            (p.dst, p.src)
        } else {
            (p.src, p.dst)
        };
        if in_net(subject, f.subject, f.subject_prefix)
            && in_net(peer, f.peer, f.peer_prefix)
            && l4_matches(f.proto, f.port_lo, f.port_hi, p)
        {
            return if kind == rule::ALLOW {
                Verdict::Accept
            } else {
                Verdict::Drop
            };
        }
    }
    // 2. ISOLATE.
    if isolates(rules, rule::DIR_INGRESS, p.dst) || isolates(rules, rule::DIR_EGRESS, p.src) {
        return Verdict::Drop;
    }
    // 3. A service address with no backends.
    let mut at = 0;
    while let Some((kind, body, next)) = next_rule(rules, at) {
        at = next;
        if kind != rule::DNAT {
            continue;
        }
        let Some(d) = dnat(body) else { continue };
        if d.backends == 0
            && !dnat_has_backends(rules, &d)
            && p.dst == d.vip
            && l4_matches(d.proto, d.vport, d.vport, p)
        {
            return Verdict::Reject;
        }
    }
    Verdict::Accept
}

/// Whether some DNAT record of `rules` for `d`'s `(proto, vip, vport)`
/// carries backends: records for one service merge, so a backend-less record
/// beside one with backends is not a service with none.
fn dnat_has_backends(rules: &[u8], d: &Dnat) -> bool {
    let mut at = 0;
    while let Some((kind, body, next)) = next_rule(rules, at) {
        at = next;
        if kind != rule::DNAT {
            continue;
        }
        if let Some(e) = dnat(body) {
            if e.proto == d.proto && e.vip == d.vip && e.vport == d.vport && e.backends > 0 {
                return true;
            }
        }
    }
    false
}

/// Whether `rules` isolate `addr` in direction `dir`.
pub fn isolates(rules: &[u8], dir: u8, addr: u32) -> bool {
    let mut at = 0;
    while let Some((kind, body, next)) = next_rule(rules, at) {
        at = next;
        if kind != rule::ISOLATE {
            continue;
        }
        if let Some((d, subject, prefix)) = isolate(body) {
            if d == dir && in_net(addr, subject, prefix) {
                return true;
            }
        }
    }
    false
}

/// Whether `rules` hold any filter record (ALLOW, DROP, ISOLATE, or a
/// service with no backends): a table without one never judges a packet.
pub fn filters(rules: &[u8]) -> bool {
    let mut at = 0;
    while let Some((kind, body, next)) = next_rule(rules, at) {
        at = next;
        match kind {
            rule::ALLOW | rule::DROP | rule::ISOLATE => return true,
            rule::DNAT => {
                if let Some(d) = dnat(body) {
                    if d.backends == 0 {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Check a whole table against what a provider can realize. `Err(errno)`:
/// `EINVAL` for a malformed record (or DNAT records for one
/// `(proto, vip, vport)` disagreeing on `translate_source` or scope),
/// `ENOSYS` for a mandatory kind, a direction, a scope or a source
/// translation the provider's `caps` does not cover. An advisory kind the
/// provider does not know is skipped.
pub fn validate(rules: &[u8], caps: u32) -> Result<(), i32> {
    const EINVAL: i32 = -22;
    const ENOSYS: i32 = -38;
    let mut at = 0;
    while at < rules.len() {
        let Some((kind, body, next)) = next_rule(rules, at) else {
            return Err(EINVAL);
        };
        match kind {
            rule::ALLOW | rule::DROP => {
                let Some(f) = filter(body) else {
                    return Err(EINVAL);
                };
                if caps & caps::FILTER == 0 {
                    return Err(ENOSYS);
                }
                if f.dir == rule::DIR_EGRESS && caps & caps::EGRESS == 0 {
                    return Err(ENOSYS);
                }
            }
            rule::ISOLATE => {
                let Some((dir, _, _)) = isolate(body) else {
                    return Err(EINVAL);
                };
                if caps & caps::FILTER == 0 || (dir == rule::DIR_EGRESS && caps & caps::EGRESS == 0)
                {
                    return Err(ENOSYS);
                }
            }
            rule::DNAT => {
                let Some(d) = dnat(body) else {
                    return Err(EINVAL);
                };
                if dnat_conflicts(rules, at, &d) {
                    return Err(EINVAL);
                }
                // `scope = any` needs DNAT; `scope = local` is met by either.
                let scoped = if d.local() {
                    caps & (caps::DNAT | caps::DNAT_LOCAL) != 0
                } else {
                    caps & caps::DNAT != 0
                };
                if !scoped {
                    return Err(ENOSYS);
                }
                if d.translate_source() != rule::XLATE_NEVER && caps & caps::SOURCE_TRANSLATE == 0 {
                    return Err(ENOSYS);
                }
            }
            k if k & rule::ADVISORY != 0 => {}
            _ => return Err(ENOSYS),
        }
        at = next;
    }
    Ok(())
}
