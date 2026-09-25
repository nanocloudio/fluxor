// Contract: net.policy — the platform enforces packet policy and service NAT.
//
// Layer: contracts (public, stable).
//
// A consumer states WHAT traffic is allowed and where a virtual address leads;
// the platform decides HOW: nftables on Linux, the native packet filter on
// bare metal, nothing (and says so) where there is nothing to enforce with.
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
// clear. A consumer that must not run unenforced — a NetworkPolicy exists for
// a pod — reads the bit and reports the gap; it never assumes. A rule kind the
// provider cannot realize at all fails REPLACE with `ENOSYS` rather than being
// dropped: a table that silently lost its DNAT is a Service that silently
// stopped working.
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
/// kind this provider cannot realize), or the platform's error applying it.
pub const REPLACE: u32 = 0x1E02;

/// Delete a table. handle=-1, arg = `[name_len:u8][name bytes]`. Idempotent;
/// returns 0.
pub const CLEAR: u32 = 0x1E03;

/// Read a table back: its generation and rules. handle=-1, arg:
/// ```text
/// [name_len:u8][name bytes]
/// [out_ptr:u64 LE][out_cap:u32 LE]  receives the rule records
/// [gen_out_ptr:u64 LE]              receives the generation (u64 LE), or 0
/// ```
/// Returns the byte count written, `ENOENT` for no such table, or `ERANGE`
/// when `out_cap` is too small (the generation is still written). An
/// in-graph enforcer polls the generation and re-reads on change.
pub const READ: u32 = 0x1E04;

/// An in-graph enforcer (the bare-metal packet filter) declares it applies
/// tables read with [`READ`]. handle=-1, arg=null. Returns 0. A provider whose
/// tables take effect only through such an enforcer reports
/// [`caps::ENFORCED`] once one has attached — and not before, so a consumer
/// never believes a policy is in force on a node with no filter in the path.
pub const ATTACH: u32 = 0x1E05;

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
    /// Accepted tables TAKE EFFECT on traffic. Clear on a provider that only
    /// records them.
    pub const ENFORCED: u32 = 1 << 4;
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
    /// ingress, the peer's for egress — which is what a Kubernetes
    /// NetworkPolicy's `ports` means in both directions.
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
    /// [proto:u8][vip:u32 BE][vport:u16 BE][n:u8]
    /// n × ([addr:u32 BE][port:u16 BE])
    /// ```
    /// `n == 0` is a VIP with no backends: traffic to it is rejected, not
    /// passed through to an address nothing serves. A VIP with more backends
    /// than one record holds ([`DNAT_MAX_BACKENDS`]) is several DNAT records
    /// for the same `proto`/`vip`/`vport` in one table; the provider merges
    /// them into one balanced set.
    pub const DNAT: u8 = 4;
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
    pub const DNAT_HEAD: usize = 1 + 4 + 2 + 1;
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
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The rule record at `at`: `(kind, body, next)`, or None past the end or on a
/// record that runs past it. One implementation, so every provider and the
/// in-graph enforcer agree on what a table says.
pub fn next_rule(rules: &[u8], at: usize) -> Option<(u8, &[u8], usize)> {
    if at + 2 > rules.len() {
        return None;
    }
    let kind = rules[at];
    let len = rules[at + 1] as usize;
    let end = at + 2 + len;
    if end > rules.len() {
        return None;
    }
    Some((kind, &rules[at + 2..end], end))
}

/// Decode an ALLOW/DROP body.
pub fn filter(body: &[u8]) -> Option<Filter> {
    if body.len() != rule::FILTER_BODY || body[0] > rule::DIR_EGRESS {
        return None;
    }
    let f = Filter {
        dir: body[0],
        proto: body[1],
        subject: be32(body, 2),
        subject_prefix: body[6],
        peer: be32(body, 7),
        peer_prefix: body[11],
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
    if body.len() != rule::ISOLATE_BODY || body[0] > rule::DIR_EGRESS || body[5] > 32 {
        return None;
    }
    Some((body[0], be32(body, 1), body[5]))
}

/// Decode a DNAT head, checking the body holds exactly its backends.
pub fn dnat(body: &[u8]) -> Option<Dnat> {
    if body.len() < rule::DNAT_HEAD {
        return None;
    }
    let d = Dnat {
        proto: body[0],
        vip: be32(body, 1),
        vport: be16(body, 5),
        backends: body[7],
    };
    if body.len() != rule::DNAT_HEAD + d.backends as usize * rule::DNAT_BACKEND {
        return None;
    }
    Some(d)
}

/// Backend `i` of a DNAT body: `(addr, port)`.
pub fn dnat_backend(body: &[u8], i: usize) -> Option<(u32, u16)> {
    let at = rule::DNAT_HEAD + i * rule::DNAT_BACKEND;
    if at + rule::DNAT_BACKEND > body.len() {
        return None;
    }
    Some((be32(body, at), be16(body, at + 4)))
}

/// Check a whole table against what a provider can realize. `Err(errno)`:
/// `EINVAL` for a malformed record, `ENOSYS` for a mandatory kind (or a
/// direction) the provider's `caps` does not cover. An advisory kind the
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
                if dnat(body).is_none() {
                    return Err(EINVAL);
                }
                if caps & caps::DNAT == 0 {
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
