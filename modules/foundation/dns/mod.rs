//! DNS Server PIC Module
//!
//! Resolves configured hostnames locally, forwards everything else to an
//! upstream DNS server (default 8.8.8.8). Two admitted extensions, each off
//! unless its manifest parameter is set: DNS64 synthesis on the forwarding
//! path (`dns64_prefix`) and an authenticated single-zone dynamic-update
//! authority (`update_zone`).
//!
//! # DNS64 (RFC 6147, non-validating /96 profile)
//!
//! A native AAAA answer is always preserved. A locally configured A is
//! synthesized into an AAAA at the configured TTL. A forwarded AAAA whose
//! answer is a complete, correlated NOERROR/NODATA — not NXDOMAIN, not an
//! error, not truncated, not a referral, not malformed — starts ONE follow-up
//! A query for the terminal owner in the SAME pending slot, in a second phase
//! with the same absolute deadline. CNAME chains are followed under
//! `MAX_CNAME_HOPS` / `MAX_CHAIN_BYTES` with loop detection; the chain is
//! preserved and only the terminal owner's A RRset is synthesized. A
//! DNAME-derived answer is refused with SERVFAIL. Queries with DO or CD set
//! are forwarded unchanged and never synthesized; a synthesized answer clears
//! AD. The TTL is `min(remaining A TTL, negative-AAAA SOA minimum)`, or the
//! remaining A TTL capped at `DNS64_TTL_CAP_S` without a SOA, with the time
//! spent resolving deducted. Addresses in `dns64_exclude` (default: every
//! non-global IPv4 range) are never translated, and the well-known prefix
//! `64:ff9b::/96` never translates a non-global address whatever the
//! exclusion list says. Each prefix or exclusion publication carries a
//! generation; a pending query keeps the generation it started under and is
//! answered without synthesis if the generation moved beneath it.
//!
//! # Dynamic update (RFC 2136) with TSIG (RFC 8945)
//!
//! One zone (`update_zone`), held as an immutable generation of at most
//! `MAX_ZONE_RRS` records and served authoritatively. Every UPDATE must carry
//! a valid `hmac-sha256` TSIG under a key named in `update_allow`; the key
//! lives in the kernel vault under the label `dns/tsig/<keyname>` and is
//! opened — never generated — at construct. Unsigned requests are REFUSED;
//! a bad key, signature or time answers NOTAUTH with the RFC 8945 TSIG error
//! (BADKEY / BADSIG / BADTIME). The time check uses the kernel's trusted
//! calendar time and fails closed when the clock is untrusted. Prerequisites
//! (all five RFC 2136 §2.4 forms) are evaluated against the current
//! generation; the update section is applied to a candidate copy, and only a
//! candidate that passed every check is published, so any failure leaves the
//! current generation untouched. `update_durability = durable` commits the
//! candidate through the `fs` contract (temp → write → fsync → rename)
//! before acknowledging and recovers the last complete committed generation
//! at construct; `volatile` acknowledges immediately and loses the zone on
//! restart. A repeated authenticated transaction (same key and MAC) inside
//! `TXN_RETAIN_MS` is answered from the cached response.
//!
//! # Supported profile
//!
//! Exactly one question per query (`QDCOUNT == 1`), opcode 0. A local answer is
//! constructed from the query header plus that question; nothing trailing the
//! question is echoed back.
//!
//! # Forwarding correlation
//!
//! A forwarded query carries a CSPRNG-drawn upstream transaction id, never the
//! client's own — two clients that pick the same id stay distinct
//! conversations, and an off-path guess must also match the rest of the tuple.
//! The pending slot retains the client id and endpoint, the upstream endpoint,
//! the question (QNAME hash, QTYPE, QCLASS), the opcode, and a deadline; an
//! answer is relayed only after reproducing all of them, and the slot is
//! consumed as it is relayed so a duplicate cannot re-fire. Only free or
//! expired slots are taken: with every slot live the NEW query is answered
//! SERVFAIL rather than displacing work already accepted.
//!
//! # Architecture
//!
//! Uses the datagram surface
//! (see `modules/sdk/contracts/net/datagram.rs` and
//! `docs/architecture/protocol_surfaces.md`) over the shared `net_in`/
//! `net_out` channel pair on the IP module:
//!
//! - **Server endpoint** — `CMD_DG_BIND` on port 53 allocates `server_ep`;
//!   inbound client queries arrive as `MSG_DG_RX_FROM` carrying the client
//!   address; replies go out as `CMD_DG_SEND_TO` to the captured client
//!   address.
//! - **Upstream endpoint** — `CMD_DG_BIND` on port 0 (ephemeral) allocates
//!   `upstream_ep`; forwarded queries go out as `CMD_DG_SEND_TO` to the
//!   upstream DNS server; upstream responses arrive as `MSG_DG_RX_FROM`.
//!
//! Frames share the 3-byte TLV header with net_proto, but datagram
//! opcodes (`0x20..0x43`) are disjoint from net_proto's (`0x01..0x14`) so
//! a shared `net_out` channel can carry both contracts unambiguously.
//!
//! # Parameters
//!
//! | Tag | Name     | Type | Default    | Description                    |
//! |-----|----------|------|------------|--------------------------------|
//! | 1   | upstream | u32  | 0x08080808 | Upstream DNS IP (LE)           |
//! | 2   | host     | str  | (none)     | "hostname=ip" (repeatable)     |
//! | 3   | ttl      | u32  | 300        | TTL for local responses (sec)  |
//! | 4   | port     | u16  | 53         | Listen port                    |
//! | 5   | trace_sample_permille | u16 | tier | `dns.query` head-sampling rate |
//! | 6   | upstream_port | u16 | 53    | Upstream destination port      |
//! | 7   | dns64_prefix | str | (none) | DNS64 prefix, `"<ipv6>/96"` text or 16 prefix bytes + length byte; only /96 is admitted, anything else refuses construction |
//! | 8   | dns64_exclude | str | non-global | IPv4 range never translated, `"a.b.c.d/n"` (repeatable, `MAX_DNS64_EXCLUDES`); when absent every non-global range is excluded |
//! | 9   | update_zone | str | (none)   | Zone apex served authoritatively and open to TSIG-signed UPDATE |
//! | 10  | update_durability | u8 enum | (unset) | `volatile` or `durable`; required with `update_zone` |
//! | 11  | update_allow | str | (none)  | `"keyname=name-suffix,TYPE,TYPE"` (repeatable, `MAX_UPDATE_KEYS`); `*` admits every type. The key is vault label `dns/tsig/<keyname>` |
//! | 12  | update_path | str | dns_zone.fxz | File the durable generation is committed to through the `fs` contract |

#![cfg_attr(not(feature = "host-test"), no_std)]
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
// Bound-endpoint bind lifecycle + addressed send, shared with log_net /
// transport_buffer / quic / dtls. dns composes two: server (port 53) + upstream
// (ephemeral), demuxed by ep_id on one channel.
include!("../../sdk/cores/datagram_endpoint.rs");
// The DNS message codec — header, names, question, resource records —
// shared with the `ip` stub resolver.
#[path = "../../sdk/contracts/net/dns_wire.rs"]
mod dns_wire;
use dns_wire::*;

// ============================================================================
// Constants
// ============================================================================

// datagram opcodes / DG_V4_PREFIX / DG_AF_INET come from
// modules/sdk/runtime.rs (shared across consumers).

/// Net buffer size (frame header + ep_id + addressing + DNS packet)
const NET_BUF_SIZE: usize = 600;

/// Maximum local host entries
const MAX_HOSTS: usize = 16;

/// Maximum pending upstream queries
const MAX_PENDING: usize = 8;

/// Pending query timeout (milliseconds)
const PENDING_TIMEOUT_MS: u32 = 5000;

/// Draws taken from the CSPRNG when allocating an upstream transaction id
/// before the forward is refused. Each draw is rejected only on collision with
/// a live pending slot, so the bound is reached with negligible probability.
const UPSTREAM_ID_DRAWS: usize = 8;

// ── DNS64 ────────────────────────────────────────────────────────────────

/// Only /96 prefixes are admitted (RFC 6052 §2.2 with the IPv4 address in
/// the low 32 bits); the prefix occupies the first `DNS64_PREFIX_BYTES`.
const DNS64_PREFIX_BITS: u8 = 96;
const DNS64_PREFIX_BYTES: usize = 12;

/// Configured address exclusions (`dns64_exclude`).
const MAX_DNS64_EXCLUDES: usize = 16;

/// Cap on the synthesized TTL when the negative AAAA answer carried no SOA
/// (RFC 6147 §5.1.7).
const DNS64_TTL_CAP_S: u32 = 600;

/// CNAME hops followed from the question to the terminal owner.
const MAX_CNAME_HOPS: usize = 4;

/// Bytes of re-encoded alias records retained per pending slot for the
/// synthesized answer; a chain past it is refused with SERVFAIL.
const MAX_CHAIN_BYTES: usize = 384;

/// A records of the terminal owner synthesized into one answer.
const MAX_SYNTH_ADDRS: usize = 8;

/// The well-known prefix (RFC 6052 §2.1), which must never translate a
/// non-global IPv4 address.
const DNS64_WELL_KNOWN_PREFIX: [u8; DNS64_PREFIX_BYTES] =
    [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// The non-global IPv4 ranges excluded by default and always excluded under
/// the well-known prefix: `(network, mask)` in host order.
const DNS64_NON_GLOBAL: [(u32, u32); 9] = [
    (0x0000_0000, 0xFF00_0000), // 0.0.0.0/8
    (0x0A00_0000, 0xFF00_0000), // 10.0.0.0/8
    (0x6440_0000, 0xFFC0_0000), // 100.64.0.0/10
    (0x7F00_0000, 0xFF00_0000), // 127.0.0.0/8
    (0xA9FE_0000, 0xFFFF_0000), // 169.254.0.0/16
    (0xAC10_0000, 0xFFF0_0000), // 172.16.0.0/12
    (0xC0A8_0000, 0xFFFF_0000), // 192.168.0.0/16
    (0xE000_0000, 0xF000_0000), // 224.0.0.0/4
    (0xF000_0000, 0xF000_0000), // 240.0.0.0/4
];

/// Pending-slot phases.
const PHASE_RELAY: u8 = 0;
/// A DNS64-eligible AAAA question awaiting its upstream AAAA answer.
const PHASE_AAAA: u8 = 1;
/// The follow-up A question for the terminal owner, in the same slot.
const PHASE_A: u8 = 2;

// ── Dynamic update ───────────────────────────────────────────────────────

/// Records one zone generation holds. Per profile: the host and pi5-class
/// profile serve allocated address space, an MCU serves a handful of hosts.
#[cfg(target_arch = "aarch64")]
const MAX_ZONE_RRS: usize = 64;
#[cfg(not(target_arch = "aarch64"))]
const MAX_ZONE_RRS: usize = 16;

/// Records admitted in the prerequisite section and in the update section
/// of one UPDATE message, each.
const MAX_UPDATE_RRS: usize = 32;

/// Longest owner name a zone record may carry (dotted form) and longest
/// RDATA, uncompressed.
const MAX_ZONE_NAME: usize = 128;
const MAX_ZONE_RDATA: usize = 128;

/// TSIG keys admitted through `update_allow`.
const MAX_UPDATE_KEYS: usize = 4;

/// Record types one `update_allow` entry may list.
const MAX_ALLOW_TYPES: usize = 8;

/// Widest signing window honoured, whatever fudge the request asks for
/// (RFC 8945 §5.2.3 recommends 300 s).
const MAX_TSIG_FUDGE_S: u64 = 300;

/// The only TSIG algorithm admitted, and its MAC length.
const TSIG_ALG_HMAC_SHA256: &[u8] = b"hmac-sha256";
const TSIG_MAC_LEN: usize = 32;

/// TSIG error codes (RFC 8945 §5.2).
const TSIG_ERR_BADSIG: u16 = 16;
const TSIG_ERR_BADKEY: u16 = 17;
const TSIG_ERR_BADTIME: u16 = 18;

/// Authenticated transactions whose response is retained, and for how long.
const MAX_TXN_CACHE: usize = 4;
const TXN_RETAIN_MS: u32 = 30000;

/// Longest committed-generation file path.
const MAX_ZONE_PATH: usize = 96;

/// The committed-generation file: magic, generation, count, records, digest.
const ZONE_FILE_MAGIC: [u8; 4] = *b"FXDZ";
const ZONE_RECORD_MAX: usize = 1 + MAX_ZONE_NAME + 2 + 2 + 4 + 2 + MAX_ZONE_RDATA;
const MAX_ZONE_FILE: usize = 4 + 4 + 2 + MAX_ZONE_RRS * ZONE_RECORD_MAX + 4;

/// Writes issued for one commit before it is refused as stalled.
const MAX_COMMIT_WRITES: usize = 64;

/// Vault label prefix for TSIG keys: `dns/tsig/<keyname>`.
const TSIG_LABEL_PREFIX: &[u8] = b"dns/tsig/";
/// Longest vault label (`key_vault::MAX_LABEL`).
const MAX_VAULT_LABEL: usize = 64;

/// Durability modes (`update_durability`).
const DURABILITY_UNSET: u8 = 0;
const DURABILITY_VOLATILE: u8 = 1;
const DURABILITY_DURABLE: u8 = 2;

/// Scratch for TSIG MAC input: the message plus the TSIG variables.
const MAC_INPUT_MAX: usize = 2 + TSIG_MAC_LEN + DNS_MAX_PACKET + 2 * (MAX_ZONE_NAME + 2) + 32;

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u32;
    use super::p_u8;
    use super::DnsState;
    use super::SCHEMA_MAX;

    define_params! {
        DnsState;

        1, upstream, u32, 0x08080808
            => |s, d, len| { s.upstream_ip = p_u32(d, len, 0, 0x08080808); };

        2, host, str, 0
            => |s, d, len| { super::parse_host_entry(s, d, len); };

        3, ttl, u32, 300
            => |s, d, len| { s.ttl = p_u32(d, len, 0, 300); };

        4, port, u16, 53
            => |s, d, len| { s.listen_port = p_u16(d, len, 0, 53); };

        // Head-sampling rate (per-mille, 0..=1000) for `dns.query` spans. The
        // default is the sentinel `0xFFFF` ("unset") so `module_new` can apply
        // the target-tier default (aarch64 50‰ / MCU 0‰) only when no explicit
        // value was supplied — set_defaults would otherwise clobber it.
        5, trace_sample_permille, u16, 0xFFFF
            => |s, d, len| { s.sample_permille = p_u16(d, len, 0, 0xFFFF); };

        // Destination port for forwarded (upstream) queries. Lets the
        // upstream be a delegation listener on a non-standard port;
        // default remains standard DNS.
        6, upstream_port, u16, 53
            => |s, d, len| { s.upstream_port = p_u16(d, len, 0, 53); };

        // DNS64 prefix; absent means no synthesis at all.
        7, dns64_prefix, str, 0
            => |s, d, len| { super::parse_dns64_prefix(s, d, len); };

        // IPv4 ranges never translated (repeatable).
        8, dns64_exclude, str, 0
            => |s, d, len| { super::parse_dns64_exclude(s, d, len); };

        // The one zone served authoritatively and open to UPDATE.
        9, update_zone, str, 0
            => |s, d, len| { super::parse_update_zone(s, d, len); };

        // Whether a published generation survives a restart. Required with
        // `update_zone`; there is no default because the choice is the
        // operator's to record.
        10, update_durability, u8, 0, enum { volatile=1, durable=2 }
            => |s, d, len| { s.update_durability = p_u8(d, len, 0, 0); };

        // TSIG key admission: "keyname=name-suffix,TYPE,..." (repeatable).
        11, update_allow, str, 0
            => |s, d, len| { super::parse_update_allow(s, d, len); };

        // Committed-generation file for durable mode.
        12, update_path, str, 0
            => |s, d, len| { super::parse_update_path(s, d, len); };
    }
}

// ============================================================================
// Data structures
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
struct HostEntry {
    name_hash: u32,
    ip: u32,
    name_len: u8,
    _pad: [u8; 3],
    name: [u8; MAX_NAME_LEN + 1],
}

impl HostEntry {
    const fn empty() -> Self {
        Self {
            name_hash: 0,
            ip: 0,
            name_len: 0,
            _pad: [0; 3],
            name: [0; MAX_NAME_LEN + 1],
        }
    }
}

/// One forwarded query awaiting its upstream answer.
///
/// The correlation key on the wire is `upstream_id` — drawn from the CSPRNG,
/// never the client's own id — so two clients that pick the same id remain
/// distinct conversations. Everything an answer must reproduce before it is
/// relayed is retained here: the upstream endpoint it must come from, the
/// question it must repeat, and the client endpoint plus original id it is
/// rewritten for.
#[derive(Clone, Copy)]
#[repr(C)]
struct PendingQuery {
    /// Transaction id used towards the upstream resolver.
    upstream_id: u16,
    /// Transaction id the client chose, restored into the relayed answer.
    client_id: u16,
    client_port: u16,
    qtype: u16,
    qclass: u16,
    upstream_port: u16,
    client_ip: u32,
    upstream_ip: u32,
    /// `fnv1a_lower` over the dotted lowercase QNAME of the forwarded question.
    qname_hash: u32,
    /// Wall-clock millisecond deadline; the slot is dead once it passes.
    /// Fixed when the query is accepted: the DNS64 second phase runs against
    /// the same deadline.
    deadline_ms: u32,
    /// When the query was accepted, for the DNS64 TTL accounting.
    start_ms: u32,
    /// DNS64 generation the query was accepted under.
    dns64_gen: u32,
    /// Negative-AAAA SOA minimum from the first phase, when `has_soa`.
    neg_ttl: u32,
    opcode: u8,
    active: u8,
    /// `PHASE_RELAY`, `PHASE_AAAA` or `PHASE_A`.
    phase: u8,
    has_soa: u8,
    /// The client's original flags word (its RD bit is echoed).
    client_flags: u16,
    /// Bytes of `chain` in use and the alias records they encode.
    chain_len: u16,
    chain_rrs: u8,
    qname_len: u8,
    term_len: u8,
    _pad: u8,
    /// The client's QNAME, dotted lowercase.
    qname: [u8; MAX_NAME_LEN + 1],
    /// The terminal owner after alias resolution (equals `qname` without a
    /// chain).
    term: [u8; MAX_NAME_LEN + 1],
    /// Alias records re-encoded uncompressed for the synthesized answer.
    chain: [u8; MAX_CHAIN_BYTES],
}

impl PendingQuery {
    const fn empty() -> Self {
        Self {
            upstream_id: 0,
            client_id: 0,
            client_port: 0,
            qtype: 0,
            qclass: 0,
            upstream_port: 0,
            client_ip: 0,
            upstream_ip: 0,
            qname_hash: 0,
            deadline_ms: 0,
            start_ms: 0,
            dns64_gen: 0,
            neg_ttl: 0,
            opcode: 0,
            active: 0,
            phase: PHASE_RELAY,
            has_soa: 0,
            client_flags: 0,
            chain_len: 0,
            chain_rrs: 0,
            qname_len: 0,
            term_len: 0,
            _pad: 0,
            qname: [0; MAX_NAME_LEN + 1],
            term: [0; MAX_NAME_LEN + 1],
            chain: [0; MAX_CHAIN_BYTES],
        }
    }
}

/// One record of a zone generation. Names are dotted lowercase; RDATA is
/// uncompressed wire format.
#[derive(Clone, Copy)]
#[repr(C)]
struct ZoneRr {
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlen: u8,
    name_len: u8,
    _pad: [u8; 2],
    name: [u8; MAX_ZONE_NAME],
    rdata: [u8; MAX_ZONE_RDATA],
}

impl ZoneRr {
    const fn empty() -> Self {
        Self {
            rtype: 0,
            rclass: 0,
            ttl: 0,
            rdlen: 0,
            name_len: 0,
            _pad: [0; 2],
            name: [0; MAX_ZONE_NAME],
            rdata: [0; MAX_ZONE_RDATA],
        }
    }
}

/// An immutable zone generation. A candidate is built as a copy, checked
/// whole, and published by replacing the current one.
#[derive(Clone, Copy)]
#[repr(C)]
struct Zone {
    generation: u32,
    count: u16,
    _pad: [u8; 2],
    rrs: [ZoneRr; MAX_ZONE_RRS],
}

impl Zone {
    const fn empty() -> Self {
        Self {
            generation: 0,
            count: 0,
            _pad: [0; 2],
            rrs: [ZoneRr::empty(); MAX_ZONE_RRS],
        }
    }
}

/// One `update_allow` entry: a TSIG key name, the vault handle it opened
/// to (or -1 when the vault holds no such key), and what it may change.
#[derive(Clone, Copy)]
#[repr(C)]
struct TsigKey {
    handle: i32,
    name_len: u8,
    suffix_len: u8,
    type_count: u8,
    /// `1` when the entry admits every record type (`*`).
    any_type: u8,
    types: [u16; MAX_ALLOW_TYPES],
    /// Key name, dotted lowercase, no trailing dot.
    name: [u8; MAX_ZONE_NAME],
    /// Owner-name suffix the key may change, dotted lowercase.
    suffix: [u8; MAX_ZONE_NAME],
}

impl TsigKey {
    const fn empty() -> Self {
        Self {
            handle: -1,
            name_len: 0,
            suffix_len: 0,
            type_count: 0,
            any_type: 0,
            types: [0; MAX_ALLOW_TYPES],
            name: [0; MAX_ZONE_NAME],
            suffix: [0; MAX_ZONE_NAME],
        }
    }
}

/// A retained authenticated transaction: the request MAC that identifies a
/// retry, and the response it was answered with.
#[derive(Clone, Copy)]
#[repr(C)]
struct TxnEntry {
    stored_ms: u32,
    reply_len: u16,
    key_idx: u8,
    live: u8,
    mac: [u8; TSIG_MAC_LEN],
    reply: [u8; DNS_MAX_PACKET],
}

impl TxnEntry {
    const fn empty() -> Self {
        Self {
            stored_ms: 0,
            reply_len: 0,
            key_idx: 0,
            live: 0,
            mac: [0; TSIG_MAC_LEN],
            reply: [0; DNS_MAX_PACKET],
        }
    }
}

/// A verified TSIG record on an UPDATE request.
#[derive(Clone, Copy)]
struct TsigInfo {
    /// Offset where the TSIG RR starts: the signed message ends here.
    tsig_off: usize,
    key_idx: usize,
    time_signed: u64,
    fudge: u16,
    orig_id: u16,
    mac: [u8; TSIG_MAC_LEN],
}

/// Outcome of checking an UPDATE request's TSIG (RFC 8945 §5.2).
#[derive(Clone, Copy, PartialEq)]
enum TsigVerdict {
    /// No TSIG record: the request is unauthenticated.
    Absent,
    /// A TSIG record that does not parse.
    Malformed,
    BadKey,
    BadSig,
    /// Outside the signing window, or no trusted clock to check it with.
    BadTime,
    Ok,
}

/// The question a response must repeat exactly to be accepted.
#[derive(Clone, Copy)]
struct Question {
    qname_hash: u32,
    qtype: u16,
    qclass: u16,
    /// Offset of the first byte after the question section.
    end: usize,
}

/// True once `deadline_ms` has passed, wrap-safe over the 32-bit millisecond
/// clock.
#[inline(always)]
fn deadline_passed(now_ms: u32, deadline_ms: u32) -> bool {
    (now_ms.wrapping_sub(deadline_ms) as i32) >= 0
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct DnsState {
    syscalls: *const SyscallTable,
    net_in_chan: i32,
    net_out_chan: i32,

    upstream_ip: u32,
    /// Destination port for forwarded queries. Default 53; configurable so a
    /// host authority resolver on a non-standard port can be the upstream.
    upstream_port: u16,
    ttl: u32,
    listen_port: u16,
    host_count: u8,

    /// Datagram endpoints (shared `datagram_endpoint` core). `server_ep` binds
    /// `listen_port` for client queries; `upstream_ep` binds an ephemeral port
    /// to forward to / receive from the upstream DNS server. They share one
    /// channel and are demuxed by the provider-assigned ep_id; bound
    /// sequentially (server, then upstream).
    server_ep: DatagramEndpoint,
    upstream_ep: DatagramEndpoint,

    // ── DNS64 ──
    /// `1` when `dns64_prefix` is configured and valid.
    dns64_enabled: u8,
    /// `1` when the configured prefix failed validation; construction is
    /// refused.
    dns64_bad: u8,
    /// `1` under the well-known prefix, which always excludes non-global IPv4.
    dns64_wkp: u8,
    dns64_exclude_count: u8,
    dns64_prefix: [u8; DNS64_PREFIX_BYTES],
    /// Published generation of the prefix/exclusion configuration.
    dns64_generation: u32,
    /// `(network, mask)` in host order.
    dns64_exclude: [(u32, u32); MAX_DNS64_EXCLUDES],

    // ── Dynamic update ──
    update_enabled: u8,
    update_durability: u8,
    /// `1` once the storage provider answered `CAPS` with the write tier and
    /// the committed generation was loaded; durable updates before that are
    /// refused SERVFAIL.
    durable_ready: u8,
    update_zone_len: u8,
    update_path_len: u8,
    key_count: u8,
    _pad_u: [u8; 2],
    update_zone: [u8; MAX_ZONE_NAME],
    update_path: [u8; MAX_ZONE_PATH],
    keys: [TsigKey; MAX_UPDATE_KEYS],
    zone: Zone,
    candidate: Zone,
    txn_cache: [TxnEntry; MAX_TXN_CACHE],
    /// Serialization scratch for the committed-generation file.
    zone_file: [u8; MAX_ZONE_FILE],
    /// TSIG MAC-input scratch.
    mac_buf: [u8; MAC_INPUT_MAX],

    // Statistics
    queries_local: u32,
    queries_forwarded: u32,
    /// Upstream datagrams refused by correlation: wrong source endpoint, no
    /// QR bit, unexpected opcode, unparsable or mismatched question, unknown /
    /// expired transaction id, or a duplicate arriving after the first answer
    /// was consumed.
    upstream_drops: u32,
    /// Client queries refused with SERVFAIL because every pending slot was
    /// live, or because no upstream transaction id could be drawn.
    forward_refusals: u32,

    // Module-scope telemetry: cumulative byte counters + last emit timestamp
    // (cadence gated on the wallclock since dns has no per-step counter).
    tlm: TlmCounters,
    tlm_last_ms: u64,
    /// Head-sampling rate (per-mille) for `dns.query` spans. Target-tier
    /// default: 50‰ on aarch64 (pi5-class), 0‰ on MCUs. Decided per query
    /// from its minted trace id.
    sample_permille: u16,

    // Host table
    hosts: [HostEntry; MAX_HOSTS],

    // Pending upstream queries
    pending: [PendingQuery; MAX_PENDING],

    // Net protocol frame buffer (shared for TX)
    net_buf: [u8; NET_BUF_SIZE],

    // DNS packet work buffer
    tx_buf: [u8; DNS_MAX_PACKET],
}

impl DnsState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.upstream_ip = 0x08080808; // 8.8.8.8
        self.upstream_port = 53;
        self.ttl = 300;
        self.listen_port = 53;
        self.host_count = 0;
        self.server_ep = DatagramEndpoint::new();
        self.upstream_ep = DatagramEndpoint::new();
        self.queries_local = 0;
        self.queries_forwarded = 0;
        self.upstream_drops = 0;
        self.forward_refusals = 0;
        let mut i = 0;
        while i < MAX_PENDING {
            self.pending[i] = PendingQuery::empty();
            i += 1;
        }
        self.dns64_enabled = 0;
        self.dns64_bad = 0;
        self.dns64_wkp = 0;
        self.dns64_exclude_count = 0;
        self.dns64_prefix = [0; DNS64_PREFIX_BYTES];
        self.dns64_generation = 1;
        self.dns64_exclude = [(0, 0); MAX_DNS64_EXCLUDES];
        self.update_enabled = 0;
        self.update_durability = DURABILITY_UNSET;
        self.durable_ready = 0;
        self.update_zone_len = 0;
        self.update_path_len = 0;
        self.key_count = 0;
        i = 0;
        while i < MAX_UPDATE_KEYS {
            self.keys[i] = TsigKey::empty();
            i += 1;
        }
        self.zone = Zone::empty();
        self.candidate = Zone::empty();
        i = 0;
        while i < MAX_TXN_CACHE {
            self.txn_cache[i] = TxnEntry::empty();
            i += 1;
        }
        self.tlm = TlmCounters::new();
        self.tlm_last_ms = 0;
        // `sample_permille` is resolved in `module_new` after param parsing
        // (set_defaults would clobber any value set here), via the
        // `trace_sample_permille` param's `0xFFFF` "unset" sentinel.
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// FNV-1a hash (32-bit, lowercase variant)
// ============================================================================

/// FNV-1a hash over raw pointer data, lowercasing ASCII.
unsafe fn fnv1a_lower(data: *const u8, len: usize) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < len {
        let mut b = *data.add(i);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
unsafe fn log_info(s: &DnsState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Parse a "hostname=ip" string and add to host table.
unsafe fn parse_host_entry(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 || s.host_count as usize >= MAX_HOSTS {
        return;
    }

    // Find '=' separator
    let mut eq_pos = 0usize;
    let mut found = false;
    while eq_pos < len {
        if *data.add(eq_pos) == b'=' {
            found = true;
            break;
        }
        eq_pos += 1;
    }
    if !found || eq_pos == 0 || eq_pos + 1 >= len {
        return;
    }

    let name_len = eq_pos.min(MAX_NAME_LEN);
    let ip = parse_ipv4(data.add(eq_pos + 1), len - eq_pos - 1);
    if ip == 0 {
        return;
    }

    let idx = s.host_count as usize;
    let entry = &mut *s.hosts.as_mut_ptr().add(idx);

    // Copy name, lowercased
    let mut i = 0;
    while i < name_len {
        let mut b = *data.add(i);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        *entry.name.as_mut_ptr().add(i) = b;
        i += 1;
    }
    entry.name_len = name_len as u8;
    entry.ip = ip;
    entry.name_hash = fnv1a_lower(data, name_len);

    s.host_count += 1;
}

/// Parse "a.b.c.d" IPv4 address from raw bytes. Returns IP in network byte order.
unsafe fn parse_ipv4(data: *const u8, len: usize) -> u32 {
    let mut octets = [0u8; 4];
    let op = octets.as_mut_ptr();
    let mut octet_idx = 0usize;
    let mut val: u16 = 0;
    let mut i = 0;

    while i < len {
        let b = *data.add(i);
        if b == b'.' {
            if octet_idx >= 3 {
                return 0;
            }
            if val > 255 {
                return 0;
            }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as u16;
        } else {
            break; // stop at non-digit/non-dot
        }
        i += 1;
    }

    if octet_idx != 3 || val > 255 {
        return 0;
    }
    *op.add(3) = val as u8;

    // Return as network byte order u32 (big endian)
    ((*op as u32) << 24)
        | ((*op.add(1) as u32) << 16)
        | ((*op.add(2) as u32) << 8)
        | (*op.add(3) as u32)
}

/// Look up a hostname in the local host table. Insertion and lookup share the
/// one `fnv1a_lower` invariant, so a caller that has not already lowercased its
/// name still matches.
unsafe fn lookup_host(s: &DnsState, name_ptr: *const u8, name_len: usize) -> Option<u32> {
    let hash = fnv1a_lower(name_ptr, name_len);
    let mut i = 0;
    while i < s.host_count as usize {
        let entry = &*s.hosts.as_ptr().add(i);
        if entry.name_hash == hash && entry.name_len as usize == name_len {
            // Byte comparison
            let mut match_ok = true;
            let mut j = 0;
            while j < name_len {
                let mut b = *name_ptr.add(j);
                if b.is_ascii_uppercase() {
                    b += 32;
                }
                if *entry.name.as_ptr().add(j) != b {
                    match_ok = false;
                    break;
                }
                j += 1;
            }
            if match_ok {
                return Some(entry.ip);
            }
        }
        i += 1;
    }
    None
}

/// Check if a name matches a reverse PTR lookup for any local host.
/// PTR queries for 1.2.3.4 come as "4.3.2.1.in-addr.arpa".
unsafe fn lookup_ptr(s: &DnsState, name_ptr: *const u8, name_len: usize) -> Option<(u32, usize)> {
    // Must end with ".in-addr.arpa"
    let suffix = b".in-addr.arpa";
    if name_len <= suffix.len() {
        return None;
    }
    let suffix_start = name_len - suffix.len();
    let mut i = 0;
    while i < suffix.len() {
        if *name_ptr.add(suffix_start + i) != *suffix.as_ptr().add(i) {
            return None;
        }
        i += 1;
    }

    // Parse reversed octets: "4.3.2.1"
    let addr_len = suffix_start;
    let mut octets = [0u8; 4];
    let op = octets.as_mut_ptr();
    let mut octet_idx: usize = 0;
    let mut val: u16 = 0;
    i = 0;
    while i < addr_len {
        let b = *name_ptr.add(i);
        if b == b'.' {
            if octet_idx >= 4 || val > 255 {
                return None;
            }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as u16;
        } else {
            return None;
        }
        i += 1;
    }
    if octet_idx != 3 || val > 255 {
        return None;
    }
    *op.add(3) = val as u8;

    // Reconstruct IP in network order (reversing the reversed octets)
    let ip = ((*op.add(3) as u32) << 24)
        | ((*op.add(2) as u32) << 16)
        | ((*op.add(1) as u32) << 8)
        | (*op as u32);

    // Find matching host
    let mut h = 0;
    while h < s.host_count as usize {
        if (*s.hosts.as_ptr().add(h)).ip == ip {
            return Some((ip, h));
        }
        h += 1;
    }
    None
}

/// Start a locally generated response: copy the query header and its FIRST
/// question, stamp the response flags, and set the record counts. Bytes after
/// the first question (further questions, additional records) are deliberately
/// not copied — a local answer is constructed, never echoed. Returns the write
/// position (the end of the question section), or 0 if the reply cannot fit.
unsafe fn begin_local_response(
    query_pkt: *const u8,
    question_end: usize,
    extra_flags: u16,
    ancount: u16,
    answer_reserve: usize,
    tx: *mut u8,
) -> usize {
    // Smallest legal question is the root label plus QTYPE/QCLASS.
    if question_end < DNS_HEADER_LEN + 5 || question_end + answer_reserve > DNS_MAX_PACKET {
        return 0;
    }

    let mut i = 0;
    while i < question_end {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // QR=1, AA=1, RA=1, preserving the client's RD bit and opcode.
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags =
        FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD) | (flags & FLAG_OPCODE_MASK) | extra_flags;
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // QDCOUNT = 1 (the one question copied above)
    *tx.add(4) = 0;
    *tx.add(5) = 1;
    let ab = ancount.to_be_bytes();
    *tx.add(6) = ab[0];
    *tx.add(7) = ab[1];
    // NSCOUNT = 0, ARCOUNT = 0
    *tx.add(8) = 0;
    *tx.add(9) = 0;
    *tx.add(10) = 0;
    *tx.add(11) = 0;

    question_end
}

/// Bytes an A record occupies: name pointer, type, class, TTL, RDLENGTH, RDATA.
const A_RECORD_LEN: usize = 16;

/// Build a DNS A record response. Returns total packet length.
unsafe fn build_a_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    ip: u32,
    tx: *mut u8,
) -> usize {
    let mut pos = begin_local_response(query_pkt, question_end, 0, 1, A_RECORD_LEN, tx);
    if pos == 0 {
        return 0;
    }

    // Name pointer to question QNAME (offset 12)
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE A = 1
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // CLASS IN = 1
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0];
    *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2];
    *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH = 4
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 4;
    pos += 2;

    // RDATA = IPv4 address (network byte order)
    let ip_bytes = ip.to_be_bytes();
    *tx.add(pos) = ip_bytes[0];
    *tx.add(pos + 1) = ip_bytes[1];
    *tx.add(pos + 2) = ip_bytes[2];
    *tx.add(pos + 3) = ip_bytes[3];
    pos += 4;

    pos
}

/// Build a DNS PTR record response. Returns total packet length.
unsafe fn build_ptr_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    host_idx: usize,
    tx: *mut u8,
) -> usize {
    let entry = &*s.hosts.as_ptr().add(host_idx);

    // Fixed record fields plus the worst-case encoded name (one length byte per
    // label plus the root terminator).
    let reserve = 12 + entry.name_len as usize + 2;
    let mut pos = begin_local_response(query_pkt, question_end, 0, 1, reserve, tx);
    if pos == 0 {
        return 0;
    }

    // Name pointer
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE PTR = 12
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 12;
    pos += 2;

    // CLASS IN
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0];
    *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2];
    *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH placeholder
    let rdlen_pos = pos;
    pos += 2;

    // Encode hostname as DNS wire format
    let name_written = encode_name(entry.name.as_ptr(), entry.name_len as usize, tx.add(pos));
    pos += name_written;

    // Fill in RDLENGTH
    let rdlen = name_written as u16;
    let rdb = rdlen.to_be_bytes();
    *tx.add(rdlen_pos) = rdb[0];
    *tx.add(rdlen_pos + 1) = rdb[1];

    pos
}

/// Build an NXDOMAIN response. Returns total packet length.
unsafe fn build_nxdomain(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, RCODE_NXDOMAIN, 0, 0, tx)
}

/// Build a SERVFAIL response — the answer to a query the resolver accepted but
/// cannot forward, so the client learns to retry instead of waiting out its own
/// timeout.
unsafe fn build_servfail(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, RCODE_SERVFAIL, 0, 0, tx)
}

/// Send `dns_data[..dns_len]` from `ep` to an IPv4 dst via the shared
/// `datagram_endpoint` core, bumping the module's `bytes_out` counter on a
/// successful (whole-datagram) write. Uses the raw state pointer so `net_buf`
/// (the framing scratch) is reachable independently of any live borrow.
/// Returns true when the whole datagram was accepted; false is backpressure.
unsafe fn dg_send_from(
    state: *mut DnsState,
    ep: &DatagramEndpoint,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) -> bool {
    let sys = &*(*state).syscalls;
    let net_out = (*state).net_out_chan;
    let buf = (*state).net_buf.as_mut_ptr();
    let n = ep.send_to(
        sys,
        net_out,
        dst_ip,
        dst_port,
        dns_data,
        dns_len,
        buf,
        NET_BUF_SIZE,
    );
    if n > 0 {
        (*state).tlm.bytes_out = (*state).tlm.bytes_out.wrapping_add(dns_len as u32);
    }
    n > 0
}

/// Module-scope telemetry: emit cumulative `bytes_in` / `bytes_out` counters to
/// the `observe` collector when the telemetry port is wired (no-op otherwise),
/// at a ~5s wallclock cadence. Metric ids follow `[observability].metrics`
/// order: 0 = bytes_in, 1 = bytes_out. Counter semantics are monotonic, so the
/// deltas are NOT reset here. Bytes counted are DNS payload (excluding the
/// datagram framing) on both directions. Metric ids 2/3 carry the correlation
/// refusal counters (`upstream_drops`, `forward_refusals`).
#[inline(never)]
unsafe fn maybe_emit_telemetry(s: &mut DnsState) {
    let sys = &*s.syscalls;
    // Ring-based emission (§5.2): zero-cost when no consumer is subscribed.
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.tlm_last_ms) < 5000 {
        return;
    }
    s.tlm_last_ms = now;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let midx = me as u16;
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    dev_telemetry_metric(sys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 2, s.upstream_drops as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 3, s.forward_refusals as u64);
}

/// Head-sampling decision for a new `dns.query` root, drawn deterministically
/// from the (random) minted trace id and compared to `permille`. Returns the
/// W3C trace-flags to stamp (`TRACE_FLAGS_SAMPLED` or 0). Mirrors the ip
/// module's `ingress_sample_decision` so the two stay aligned.
#[inline(always)]
fn ingress_sample_decision(permille: u16, trace_id: &[u8; 16]) -> u8 {
    let draw = u16::from_le_bytes([trace_id[0], trace_id[1]]) % 1000;
    if draw < permille {
        abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    } else {
        0
    }
}

/// Minted-per-query trace context for a `dns.query` span. Zero-sized cost when
/// the telemetry port is unwired or the query isn't head-sampled.
struct QuerySpan {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    flags: u8,
    start_us: u64,
}

/// Mint a root trace context for an incoming query when telemetry is wired.
/// Returns `None` (no work) when the telemetry port is unwired; otherwise draws
/// random ids, makes the head-sampling decision, and captures the start time
/// only for sampled queries (the clock read is gated behind the sample bit).
#[inline(never)]
unsafe fn begin_query_span(s: &DnsState) -> Option<QuerySpan> {
    let sys = &*s.syscalls;
    // No consumer subscribed → skip the id draw + span mint entirely (§5.2).
    if !dev_telemetry_enabled(sys) {
        return None;
    }
    let mut trace_id = [0u8; 16];
    let mut span_id = [0u8; 8];
    dev_csprng_fill(sys, trace_id.as_mut_ptr(), 16);
    dev_csprng_fill(sys, span_id.as_mut_ptr(), 8);
    let flags = ingress_sample_decision(s.sample_permille, &trace_id);
    let start_us = if flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED != 0 {
        dev_micros(sys)
    } else {
        0
    };
    Some(QuerySpan {
        trace_id,
        span_id,
        flags,
        start_us,
    })
}

/// Emit the finished `dns.query` span (name_id 0, SERVER kind) for a locally
/// resolved query. No-op unless the query was head-sampled. Called at each
/// local-reply site; the bit test runs before the clock read so an unsampled
/// query does no work.
#[inline(never)]
unsafe fn emit_query_span(s: &DnsState, span: &QuerySpan) {
    if span.flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let end_raw = dev_micros(sys);
    let end = if end_raw < span.start_us {
        span.start_us
    } else {
        end_raw
    };
    let ctx = abi::contracts::telemetry::SpanContext {
        trace_id: span.trace_id,
        span_id: span.span_id,
        parent_id: [0u8; 8], // dns is the ingress for this query → root span
        flags: span.flags,
    };
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = dns.query
        abi::contracts::telemetry::SPAN_SERVER,
        abi::contracts::telemetry::STATUS_OK,
        &ctx,
        span.start_us,
        end,
    );
}

/// Send a DNS reply from the server endpoint back to the original client.
unsafe fn send_server_reply(
    state: *mut DnsState,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) -> bool {
    dg_send_from(
        state,
        &(*state).server_ep,
        dst_ip,
        dst_port,
        dns_data,
        dns_len,
    )
}

/// Send a DNS query from the upstream endpoint to the configured upstream
/// DNS server.
unsafe fn send_upstream_query(state: *mut DnsState, dns_data: *const u8, dns_len: usize) -> bool {
    let upstream_ip = (*state).upstream_ip;
    let upstream_port = (*state).upstream_port;
    dg_send_from(
        state,
        &(*state).upstream_ep,
        upstream_ip,
        upstream_port,
        dns_data,
        dns_len,
    )
}

/// Index of a slot that is free or whose deadline has passed. A LIVE slot is
/// never recycled: accepted work is only ever displaced by its own timeout.
unsafe fn free_pending_slot(s: &DnsState, now_ms: u32) -> Option<usize> {
    let p = s.pending.as_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &*p.add(i);
        if slot.active == 0 || deadline_passed(now_ms, slot.deadline_ms) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// True if any live slot already holds `id` as its upstream transaction id.
unsafe fn upstream_id_in_use(s: &DnsState, now_ms: u32, id: u16) -> bool {
    let p = s.pending.as_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &*p.add(i);
        if slot.active != 0 && !deadline_passed(now_ms, slot.deadline_ms) && slot.upstream_id == id
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Draw an unpredictable upstream transaction id that no live slot is using.
/// Returns `None` when the CSPRNG is unavailable (the caller then refuses the
/// query rather than forwarding a guessable id) or when every draw collided.
unsafe fn alloc_upstream_id(s: &DnsState, now_ms: u32) -> Option<u16> {
    let sys = s.sys();
    let mut draw = 0usize;
    while draw < UPSTREAM_ID_DRAWS {
        let mut raw = [0u8; 2];
        // Platform CSPRNGs report success as either 0 or the byte count; any
        // negative value is a failure and must not be treated as entropy.
        if dev_csprng_fill(sys, raw.as_mut_ptr(), 2) < 0 {
            return None;
        }
        let id = u16::from_le_bytes(raw);
        if !upstream_id_in_use(s, now_ms, id) {
            return Some(id);
        }
        draw += 1;
    }
    None
}

/// Record a forwarded query in `slot`.
#[allow(
    clippy::too_many_arguments,
    reason = "the pending record is the correlation tuple; grouping it into a struct would move the argument list, not shorten it"
)]
unsafe fn store_pending(
    s: &mut DnsState,
    slot: usize,
    upstream_id: u16,
    client_id: u16,
    client_ip: u32,
    client_port: u16,
    q: &Question,
    opcode: u8,
    now_ms: u32,
) {
    let e = &mut *s.pending.as_mut_ptr().add(slot);
    e.upstream_id = upstream_id;
    e.client_id = client_id;
    e.client_ip = client_ip;
    e.client_port = client_port;
    e.qname_hash = q.qname_hash;
    e.qtype = q.qtype;
    e.qclass = q.qclass;
    e.upstream_ip = s.upstream_ip;
    e.upstream_port = s.upstream_port;
    e.opcode = opcode;
    e.deadline_ms = now_ms.wrapping_add(PENDING_TIMEOUT_MS);
    e.start_ms = now_ms;
    e.phase = PHASE_RELAY;
    e.dns64_gen = s.dns64_generation;
    e.chain_len = 0;
    e.chain_rrs = 0;
    e.has_soa = 0;
    e.neg_ttl = 0;
    e.qname_len = 0;
    e.term_len = 0;
    e.active = 1;
}

/// Consume the live pending slot an upstream answer correlates to. Every field
/// the answer must reproduce is checked here, and the slot is cleared before
/// returning, so a duplicate or late copy finds nothing and cannot re-fire.
unsafe fn take_pending(
    s: &mut DnsState,
    now_ms: u32,
    upstream_id: u16,
    src_ip: u32,
    src_port: u16,
    opcode: u8,
    q: &Question,
) -> Option<(u16, u32, u16, usize)> {
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &mut *p.add(i);
        if slot.active != 0
            && !deadline_passed(now_ms, slot.deadline_ms)
            && slot.upstream_id == upstream_id
            && slot.upstream_ip == src_ip
            && slot.upstream_port == src_port
            && slot.opcode == opcode
            && slot.qname_hash == q.qname_hash
            && slot.qtype == q.qtype
            && slot.qclass == q.qclass
        {
            slot.active = 0;
            return Some((slot.client_id, slot.client_ip, slot.client_port, i));
        }
        i += 1;
    }
    None
}

/// Release pending slots whose deadline has passed.
unsafe fn expire_pending(s: &mut DnsState) {
    let now = dev_millis(s.sys()) as u32;
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &mut *p.add(i);
        if slot.active != 0 && deadline_passed(now, slot.deadline_ms) {
            slot.active = 0;
        }
        i += 1;
    }
}

/// Parse the single question section of `pkt`, writing the dotted lowercase
/// QNAME into `name_buf` (at least `MAX_NAME_LEN + 1` bytes). Returns the
/// question and the QNAME length.
unsafe fn parse_question(
    pkt: *const u8,
    pkt_len: usize,
    name_buf: *mut u8,
) -> Option<(Question, usize)> {
    let mut offset = DNS_HEADER_LEN;
    let name_len = extract_qname(pkt, pkt_len, &mut offset, name_buf);
    if name_len == 0 || offset + 4 > pkt_len {
        return None;
    }
    let qtype = u16::from_be_bytes([*pkt.add(offset), *pkt.add(offset + 1)]);
    let qclass = u16::from_be_bytes([*pkt.add(offset + 2), *pkt.add(offset + 3)]);
    Some((
        Question {
            qname_hash: fnv1a_lower(name_buf, name_len),
            qtype,
            qclass,
            end: offset + 4,
        },
        name_len,
    ))
}

/// Process a DNS query received on the server socket.
unsafe fn handle_query(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if pkt_len < DNS_HEADER_LEN {
        return;
    }

    // Parse DNS header
    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let qdcount = u16::from_be_bytes([*pkt.add(4), *pkt.add(5)]);

    // Standard queries (QR=0, opcode 0) are served or forwarded; UPDATE
    // (opcode 5) is served by the zone authority. Everything else is
    // dropped.
    let opcode = ((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8;
    if (flags & FLAG_QR) != 0 || (opcode != OPCODE_QUERY && opcode != OPCODE_UPDATE) {
        return;
    }
    // The supported profile is exactly one question per query: local answers
    // are constructed from that question, and an upstream answer is correlated
    // against it.
    if qdcount != 1 {
        return;
    }

    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let (question, name_len) = match parse_question(pkt, pkt_len, name_buf.as_mut_ptr()) {
        Some(v) => v,
        None => return,
    };
    let qtype = question.qtype;
    let question_end = question.end;

    if opcode == OPCODE_UPDATE {
        handle_update(
            s,
            client_ip,
            client_port,
            pkt,
            pkt_len,
            question_end,
            name_buf.as_ptr(),
            name_len,
            qtype,
            question.qclass,
        );
        return;
    }

    // Only handle IN class
    if question.qclass != QCLASS_IN {
        // Forward unknown classes
        forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
        return;
    }

    // Use raw pointer to tx_buf to avoid borrow checker issues
    let tx_ptr = s.tx_buf.as_mut_ptr();

    // A name inside the configured zone is answered from the current
    // generation and never forwarded.
    if s.update_enabled != 0
        && name_within(
            name_buf.as_ptr(),
            name_len,
            s.update_zone.as_ptr(),
            s.update_zone_len as usize,
        )
    {
        let resp_len = build_zone_response(
            s,
            pkt,
            question_end,
            name_buf.as_ptr(),
            name_len,
            qtype,
            tx_ptr,
        );
        if resp_len > 0 {
            send_server_reply(
                s as *mut DnsState,
                client_ip,
                client_port,
                tx_ptr as *const u8,
                resp_len,
            );
            s.queries_local += 1;
        }
        return;
    }

    // DNS64 applies to IN AAAA questions without DO or CD; anything else
    // takes the plain path and is never synthesized.
    let dns64_query = s.dns64_enabled != 0
        && qtype == QTYPE_AAAA
        && flags & FLAG_CD == 0
        && !query_has_do(pkt, pkt_len, question_end);

    // Mint a `dns.query` trace context now (past the parse-fail returns, before
    // resolution). Emitted only at the local-reply sites below; forwarded
    // queries leave `qspan` unused. `None` when telemetry is unwired.
    let qspan = begin_query_span(s);

    match qtype {
        QTYPE_A => {
            // Look up in local host table
            match lookup_host(s, name_buf.as_ptr(), name_len) {
                Some(ip) => {
                    // Build and send local A response
                    let resp_len = build_a_response(s, pkt, question_end, ip, tx_ptr);
                    if resp_len > 0 {
                        send_server_reply(
                            s as *mut DnsState,
                            client_ip,
                            client_port,
                            tx_ptr as *const u8,
                            resp_len,
                        );
                        s.queries_local += 1;
                        if let Some(ref sp) = qspan {
                            emit_query_span(s, sp);
                        }
                    }
                }
                None => {
                    // Forward to upstream
                    forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
                }
            }
        }
        QTYPE_AAAA => {
            // A local host has no native AAAA: with DNS64 its configured A is
            // synthesized unless excluded; otherwise the answer is NODATA.
            if let Some(ip) = lookup_host(s, name_buf.as_ptr(), name_len) {
                let resp_len = if dns64_query && !dns64_excluded(s, ip) {
                    build_aaaa_local_response(s, pkt, question_end, ip, tx_ptr)
                } else {
                    build_empty_response(pkt, question_end, tx_ptr)
                };
                if resp_len > 0 {
                    send_server_reply(
                        s as *mut DnsState,
                        client_ip,
                        client_port,
                        tx_ptr as *const u8,
                        resp_len,
                    );
                    if let Some(ref sp) = qspan {
                        emit_query_span(s, sp);
                    }
                }
            } else if dns64_query {
                forward_dns64(
                    s,
                    id,
                    flags,
                    client_ip,
                    client_port,
                    &question,
                    name_buf.as_ptr(),
                    name_len,
                    pkt,
                    pkt_len,
                );
            } else {
                forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
            }
        }
        QTYPE_PTR => {
            // Reverse lookup
            match lookup_ptr(s, name_buf.as_ptr(), name_len) {
                Some((_ip, host_idx)) => {
                    let resp_len = build_ptr_response(s, pkt, question_end, host_idx, tx_ptr);
                    if resp_len > 0 {
                        send_server_reply(
                            s as *mut DnsState,
                            client_ip,
                            client_port,
                            tx_ptr as *const u8,
                            resp_len,
                        );
                        s.queries_local += 1;
                        if let Some(ref sp) = qspan {
                            emit_query_span(s, sp);
                        }
                    }
                }
                None => {
                    forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
                }
            }
        }
        _ => {
            // Forward all other types to upstream
            forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
        }
    }
}

/// Build an empty response (NOERROR, 0 answers) for local hosts with no matching record type.
unsafe fn build_empty_response(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, 0, 0, 0, tx)
}

/// Answer a query the resolver accepted but cannot forward with SERVFAIL, so
/// the client can retry immediately instead of waiting out its own timeout.
unsafe fn refuse_with_servfail(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    question_end: usize,
) {
    s.forward_refusals = s.forward_refusals.wrapping_add(1);
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let len = build_servfail(pkt, question_end, tx_ptr);
    if len > 0 {
        send_server_reply(
            s as *mut DnsState,
            client_ip,
            client_port,
            tx_ptr as *const u8,
            len,
        );
    }
}

/// Forward a query to the upstream DNS server under a fresh, unpredictable
/// transaction id. The client's own id never reaches the wire: it is retained
/// in the pending slot and restored when the matching answer is relayed back.
///
/// A pending slot is taken before the send, and only free or expired slots are
/// taken — accepted work is never displaced. With no slot, no id, or no bound
/// upstream endpoint the query is refused with SERVFAIL. Returns the slot
/// the query occupies.
unsafe fn forward_to_upstream(
    s: &mut DnsState,
    client_id: u16,
    client_ip: u32,
    client_port: u16,
    question: &Question,
    pkt: *const u8,
    pkt_len: usize,
) -> Option<usize> {
    if !s.upstream_ep.is_ready() || pkt_len > DNS_MAX_PACKET {
        refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
        return None;
    }

    let now = dev_millis(s.sys()) as u32;
    let slot = match free_pending_slot(s, now) {
        Some(i) => i,
        None => {
            refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
            return None;
        }
    };
    let upstream_id = match alloc_upstream_id(s, now) {
        Some(id) => id,
        None => {
            refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
            return None;
        }
    };

    // Copy the query into the work buffer and stamp the upstream id over the
    // client's. The rest of the query — including any EDNS additional records —
    // is forwarded unchanged.
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let mut i = 0;
    while i < pkt_len {
        *tx_ptr.add(i) = *pkt.add(i);
        i += 1;
    }
    let idb = upstream_id.to_be_bytes();
    *tx_ptr = idb[0];
    *tx_ptr.add(1) = idb[1];

    let opcode = ((u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]) & FLAG_OPCODE_MASK)
        >> FLAG_OPCODE_SHIFT) as u8;
    store_pending(
        s,
        slot,
        upstream_id,
        client_id,
        client_ip,
        client_port,
        question,
        opcode,
        now,
    );

    // Send query to upstream via CMD_DG_SEND_TO on the upstream endpoint. A
    // rejected write means the query was never forwarded, so the slot is
    // released again and the client is refused rather than left to time out.
    if !send_upstream_query(s as *mut DnsState, tx_ptr as *const u8, pkt_len) {
        (*s.pending.as_mut_ptr().add(slot)).active = 0;
        refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
        return None;
    }
    s.queries_forwarded += 1;
    Some(slot)
}

/// Forward a DNS64-eligible AAAA question: the plain forward, with the slot
/// marked for the AAAA phase and carrying what the second phase needs — the
/// question name, the client's flags and the generation.
#[allow(
    clippy::too_many_arguments,
    reason = "the pending record is the correlation tuple plus the question name"
)]
unsafe fn forward_dns64(
    s: &mut DnsState,
    client_id: u16,
    client_flags: u16,
    client_ip: u32,
    client_port: u16,
    question: &Question,
    name: *const u8,
    name_len: usize,
    pkt: *const u8,
    pkt_len: usize,
) {
    let slot =
        match forward_to_upstream(s, client_id, client_ip, client_port, question, pkt, pkt_len) {
            Some(i) => i,
            None => return,
        };
    let e = &mut *s.pending.as_mut_ptr().add(slot);
    e.phase = PHASE_AAAA;
    e.client_flags = client_flags;
    copy_bytes(e.qname.as_mut_ptr(), name, name_len);
    e.qname_len = name_len as u8;
    copy_bytes(e.term.as_mut_ptr(), name, name_len);
    e.term_len = name_len as u8;
}

/// Process a datagram received on the upstream endpoint.
///
/// It is relayed to a client only if it is a response (QR set) from the exact
/// configured upstream endpoint, carries the expected opcode and exactly the
/// question that was forwarded, and matches a live upstream transaction id.
/// Everything else — including a query arriving on the response port, a spoofed
/// source, and a duplicate arriving after the first answer was consumed — is
/// dropped and metered.
unsafe fn handle_upstream_response(
    s: &mut DnsState,
    src_ip: u32,
    src_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if !(DNS_HEADER_LEN..=DNS_MAX_PACKET).contains(&pkt_len) {
        s.upstream_drops = s.upstream_drops.wrapping_add(1);
        return;
    }

    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let qdcount = u16::from_be_bytes([*pkt.add(4), *pkt.add(5)]);
    let opcode = ((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8;

    if (flags & FLAG_QR) == 0 || qdcount != 1 {
        s.upstream_drops = s.upstream_drops.wrapping_add(1);
        return;
    }

    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let question = match parse_question(pkt, pkt_len, name_buf.as_mut_ptr()) {
        Some((q, _)) => q,
        None => {
            s.upstream_drops = s.upstream_drops.wrapping_add(1);
            return;
        }
    };

    let now_ms = dev_millis(s.sys()) as u32;
    let (client_id, client_ip, client_port, slot_idx) =
        match take_pending(s, now_ms, id, src_ip, src_port, opcode, &question) {
            Some(v) => v,
            None => {
                s.upstream_drops = s.upstream_drops.wrapping_add(1);
                return;
            }
        };

    let phase = (*s.pending.as_ptr().add(slot_idx)).phase;
    if phase == PHASE_A {
        // The slot is consumed; the answer is built from its copy.
        let slot = *s.pending.as_ptr().add(slot_idx);
        finish_dns64(s as *mut DnsState, slot, pkt, pkt_len, question.end, now_ms);
        return;
    }
    if phase == PHASE_AAAA {
        let e = &mut *s.pending.as_mut_ptr().add(slot_idx);
        match classify_aaaa_answer(e, pkt, pkt_len, question.end) {
            AaaaOutcome::Relay => {}
            AaaaOutcome::ServFail => {
                let slot = *s.pending.as_ptr().add(slot_idx);
                servfail_slot(s as *mut DnsState, &slot);
                return;
            }
            AaaaOutcome::Nodata => {
                // A generation published beneath the query answers the
                // question as it stands: NODATA, without synthesis.
                let gen_moved = e.dns64_gen != s.dns64_generation;
                if gen_moved || !start_a_phase(s as *mut DnsState, slot_idx, now_ms) {
                    let slot = *s.pending.as_ptr().add(slot_idx);
                    if gen_moved {
                        let tx_ptr = s.tx_buf.as_mut_ptr();
                        let addrs = [0u32; MAX_SYNTH_ADDRS];
                        let len = build_dns64_answer(s, &slot, &addrs, 0, 0, tx_ptr);
                        if len > 0 {
                            send_server_reply(
                                s as *mut DnsState,
                                client_ip,
                                client_port,
                                tx_ptr as *const u8,
                                len,
                            );
                        }
                    } else {
                        servfail_slot(s as *mut DnsState, &slot);
                    }
                }
                return;
            }
        }
    }

    // Restore the client's own transaction id, then relay to the endpoint the
    // query was accepted from.
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let mut i = 0;
    while i < pkt_len {
        *tx_ptr.add(i) = *pkt.add(i);
        i += 1;
    }
    let idb = client_id.to_be_bytes();
    *tx_ptr = idb[0];
    *tx_ptr.add(1) = idb[1];

    send_server_reply(
        s as *mut DnsState,
        client_ip,
        client_port,
        tx_ptr as *const u8,
        pkt_len,
    );
}

// ============================================================================
// Wire helpers shared by DNS64 and UPDATE
// ============================================================================

/// True when `name` equals `zone` or ends with `.zone`.
unsafe fn name_within(name: *const u8, name_len: usize, zone: *const u8, zone_len: usize) -> bool {
    if zone_len == 0 {
        return false;
    }
    if names_equal(name, name_len, zone, zone_len) {
        return true;
    }
    if name_len <= zone_len || *name.add(name_len - zone_len - 1) != b'.' {
        return false;
    }
    names_equal(name.add(name_len - zone_len), zone_len, zone, zone_len)
}

/// Position of `needle` in `data[..len]`, or `len` when absent.
unsafe fn find_byte(data: *const u8, len: usize, needle: u8) -> usize {
    let mut i = 0;
    while i < len {
        if *data.add(i) == needle {
            return i;
        }
        i += 1;
    }
    len
}

// ============================================================================
// DNS64: configuration
// ============================================================================

/// Parse `dns64_prefix`: either `"<ipv6>/96"` text or 16 prefix bytes
/// followed by one length byte. Anything but a /96 marks the configuration
/// bad and construction is refused.
unsafe fn parse_dns64_prefix(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let mut prefix = [0u8; 16];
    let ok = if len == 17 && !(*data).is_ascii_graphic() {
        copy_bytes(prefix.as_mut_ptr(), data, 16);
        *data.add(16) == DNS64_PREFIX_BITS
    } else {
        parse_ipv6_prefix_text(data, len, &mut prefix)
    };
    // The low 32 bits of a /96 prefix are the address; a configured prefix
    // carrying bits there is not a /96.
    if !ok || prefix[12] != 0 || prefix[13] != 0 || prefix[14] != 0 || prefix[15] != 0 {
        s.dns64_bad = 1;
        return;
    }
    copy_bytes(
        s.dns64_prefix.as_mut_ptr(),
        prefix.as_ptr(),
        DNS64_PREFIX_BYTES,
    );
    s.dns64_enabled = 1;
    s.dns64_wkp = u8::from(s.dns64_prefix == DNS64_WELL_KNOWN_PREFIX);
}

/// Parse `"<ipv6>/96"` into `out`. RFC 4291 text form with one optional
/// `::`, no embedded IPv4 form; the length suffix must be exactly 96.
unsafe fn parse_ipv6_prefix_text(data: *const u8, len: usize, out: &mut [u8; 16]) -> bool {
    let slash = find_byte(data, len, b'/');
    if slash == len {
        return false;
    }
    // Length suffix.
    let mut bits: u32 = 0;
    let mut i = slash + 1;
    if i >= len {
        return false;
    }
    while i < len {
        let c = *data.add(i);
        if !c.is_ascii_digit() {
            return false;
        }
        bits = bits * 10 + (c - b'0') as u32;
        if bits > 128 {
            return false;
        }
        i += 1;
    }
    if bits != DNS64_PREFIX_BITS as u32 {
        return false;
    }
    // Address groups, with at most one `::` gap.
    let mut groups = [0u16; 8];
    let mut count = 0usize;
    let mut gap: Option<usize> = None;
    let mut pos = 0usize;
    if slash >= 2 && *data == b':' && *data.add(1) == b':' {
        gap = Some(0);
        pos = 2;
    }
    while pos < slash {
        let mut val: u32 = 0;
        let mut digits = 0usize;
        while pos < slash && *data.add(pos) != b':' {
            let c = *data.add(pos);
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return false,
            };
            val = (val << 4) | d as u32;
            digits += 1;
            if digits > 4 {
                return false;
            }
            pos += 1;
        }
        if digits == 0 || count >= 8 {
            return false;
        }
        groups[count] = val as u16;
        count += 1;
        if pos < slash {
            // A separator: `:` or `::`.
            pos += 1;
            if pos < slash && *data.add(pos) == b':' {
                if gap.is_some() {
                    return false;
                }
                gap = Some(count);
                pos += 1;
            } else if pos >= slash {
                return false;
            }
        }
    }
    let mut full = [0u16; 8];
    match gap {
        Some(g) => {
            if count >= 8 {
                return false;
            }
            let mut k = 0;
            while k < g {
                full[k] = groups[k];
                k += 1;
            }
            let tail = count - g;
            let mut t = 0;
            while t < tail {
                full[8 - tail + t] = groups[g + t];
                t += 1;
            }
        }
        None => {
            if count != 8 {
                return false;
            }
            full = groups;
        }
    }
    let mut k = 0;
    while k < 8 {
        let b = full[k].to_be_bytes();
        out[2 * k] = b[0];
        out[2 * k + 1] = b[1];
        k += 1;
    }
    true
}

/// Parse one `dns64_exclude` entry `"a.b.c.d/n"` (or `"a.b.c.d"` for /32).
unsafe fn parse_dns64_exclude(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 || s.dns64_exclude_count as usize >= MAX_DNS64_EXCLUDES {
        return;
    }
    let slash = find_byte(data, len, b'/');
    let ip = parse_ipv4(data, slash);
    let mut bits: u32 = 32;
    if slash < len {
        bits = 0;
        let mut i = slash + 1;
        if i >= len {
            return;
        }
        while i < len {
            let c = *data.add(i);
            if !c.is_ascii_digit() {
                return;
            }
            bits = bits * 10 + (c - b'0') as u32;
            if bits > 32 {
                return;
            }
            i += 1;
        }
    }
    if ip == 0 && bits != 0 && slash == len {
        return;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    let idx = s.dns64_exclude_count as usize;
    s.dns64_exclude[idx] = (ip & mask, mask);
    s.dns64_exclude_count += 1;
}

/// True when `ip` (host order) must not be translated: it matches a
/// configured exclusion, or a non-global range while the default policy
/// applies — no exclusions configured, or the well-known prefix in use.
fn dns64_excluded(s: &DnsState, ip: u32) -> bool {
    let mut i = 0;
    while i < s.dns64_exclude_count as usize {
        let (net, mask) = s.dns64_exclude[i];
        if ip & mask == net {
            return true;
        }
        i += 1;
    }
    if s.dns64_exclude_count == 0 || s.dns64_wkp != 0 {
        let mut k = 0;
        while k < DNS64_NON_GLOBAL.len() {
            let (net, mask) = DNS64_NON_GLOBAL[k];
            if ip & mask == net {
                return true;
            }
            k += 1;
        }
    }
    false
}

/// Publish a new prefix generation. Pending work keeps the generation it
/// was accepted under and completes without synthesis.
unsafe fn dns64_set_prefix(s: &mut DnsState, prefix: &[u8; DNS64_PREFIX_BYTES]) {
    copy_bytes(
        s.dns64_prefix.as_mut_ptr(),
        prefix.as_ptr(),
        DNS64_PREFIX_BYTES,
    );
    s.dns64_wkp = u8::from(s.dns64_prefix == DNS64_WELL_KNOWN_PREFIX);
    s.dns64_enabled = 1;
    s.dns64_generation = s.dns64_generation.wrapping_add(1);
}

/// Host-test entry to the prefix publication path, so a gate can move the
/// generation beneath a query in flight.
#[cfg(feature = "host-test")]
pub fn dns64_publish_prefix(state: *mut u8, prefix: &[u8; DNS64_PREFIX_BYTES]) {
    unsafe {
        let s = &mut *(state as *mut DnsState);
        dns64_set_prefix(s, prefix);
    }
}

/// True when the query carries an OPT record with DO set. A query whose
/// additional section does not parse is treated as DO: it is forwarded
/// unchanged, which is the safe direction.
unsafe fn query_has_do(pkt: *const u8, pkt_len: usize, question_end: usize) -> bool {
    let ancount = u16::from_be_bytes([*pkt.add(6), *pkt.add(7)]) as usize;
    let nscount = u16::from_be_bytes([*pkt.add(8), *pkt.add(9)]) as usize;
    let arcount = u16::from_be_bytes([*pkt.add(10), *pkt.add(11)]) as usize;
    if arcount == 0 {
        return false;
    }
    let pos = match skip_rrs(pkt, pkt_len, question_end, ancount + nscount) {
        Some(p) => p,
        None => return true,
    };
    if arcount > MAX_SECTION_RRS {
        return true;
    }
    let mut scratch = [0u8; MAX_NAME_LEN + 1];
    let mut p = pos;
    let mut i = 0;
    while i < arcount {
        let rr = match parse_rr(pkt, pkt_len, p, scratch.as_mut_ptr()) {
            Some(r) => r,
            None => return true,
        };
        // The OPT TTL field is extended RCODE, version, then the 16 flag
        // bits; DO is the top flag bit.
        if rr.rtype == QTYPE_OPT && (rr.ttl & 0xFFFF) as u16 & EDNS_DO != 0 {
            return true;
        }
        p = rr.next;
        i += 1;
    }
    false
}

// ============================================================================
// DNS64: answers
// ============================================================================

/// Bytes an AAAA record with a name pointer occupies.
const AAAA_RECORD_LEN: usize = 28;

/// Synthesized AAAA for a locally configured host, at the local TTL.
unsafe fn build_aaaa_local_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    ip: u32,
    tx: *mut u8,
) -> usize {
    let mut pos = begin_local_response(query_pkt, question_end, 0, 1, AAAA_RECORD_LEN, tx);
    if pos == 0 {
        return 0;
    }
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;
    put_u16(tx.add(pos), QTYPE_AAAA);
    put_u16(tx.add(pos + 2), QCLASS_IN);
    put_u32(tx.add(pos + 4), s.ttl);
    put_u16(tx.add(pos + 8), 16);
    pos += 10;
    copy_bytes(tx.add(pos), s.dns64_prefix.as_ptr(), DNS64_PREFIX_BYTES);
    put_u32(tx.add(pos + DNS64_PREFIX_BYTES), ip);
    pos += 16;
    pos
}

/// What the first-phase AAAA answer turned out to be.
enum AaaaOutcome {
    /// Relay the upstream bytes unchanged: a native answer, a referral, an
    /// error, or a truncated one.
    Relay,
    /// Refuse with SERVFAIL: DNAME, an alias loop, a chain past its bound,
    /// or a section that does not parse.
    ServFail,
    /// A complete NODATA at the terminal owner: start the A phase.
    Nodata,
}

/// Classify the first-phase answer for `slot`, recording the terminal owner,
/// the alias chain and the negative TTL into the slot.
unsafe fn classify_aaaa_answer(
    slot: &mut PendingQuery,
    pkt: *const u8,
    pkt_len: usize,
    question_end: usize,
) -> AaaaOutcome {
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    if flags & RCODE_MASK != 0 || flags & FLAG_TC != 0 {
        return AaaaOutcome::Relay;
    }
    let ancount = u16::from_be_bytes([*pkt.add(6), *pkt.add(7)]) as usize;
    let nscount = u16::from_be_bytes([*pkt.add(8), *pkt.add(9)]) as usize;
    if ancount > MAX_SECTION_RRS || nscount > MAX_SECTION_RRS {
        return AaaaOutcome::ServFail;
    }

    let mut owner = [0u8; MAX_NAME_LEN + 1];
    let mut target = [0u8; MAX_NAME_LEN + 1];
    // Every owner visited so far, for loop detection: the question plus one
    // per hop.
    let mut visited = [[0u8; MAX_NAME_LEN + 1]; MAX_CNAME_HOPS + 1];
    let mut visited_len = [0usize; MAX_CNAME_HOPS + 1];
    copy_bytes(
        visited[0].as_mut_ptr(),
        slot.qname.as_ptr(),
        slot.qname_len as usize,
    );
    visited_len[0] = slot.qname_len as usize;
    let mut hops = 0usize;
    slot.chain_len = 0;
    slot.chain_rrs = 0;

    loop {
        let cur = visited[hops].as_ptr();
        let cur_len = visited_len[hops];
        let mut found_aaaa = false;
        let mut cname: Option<(usize, u32)> = None;
        let mut pos = question_end;
        let mut i = 0;
        while i < ancount {
            let rr = match parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()) {
                Some(r) => r,
                None => return AaaaOutcome::ServFail,
            };
            if rr.rtype == QTYPE_DNAME {
                return AaaaOutcome::ServFail;
            }
            if names_equal(owner.as_ptr(), rr.owner_len, cur, cur_len) {
                if rr.rtype == QTYPE_AAAA {
                    found_aaaa = true;
                } else if rr.rtype == QTYPE_CNAME && cname.is_none() {
                    let (t_len, end) =
                        match read_name(pkt, pkt_len, rr.rdata_off, target.as_mut_ptr()) {
                            Some(v) => v,
                            None => return AaaaOutcome::ServFail,
                        };
                    if end != rr.next {
                        return AaaaOutcome::ServFail;
                    }
                    cname = Some((t_len, rr.ttl));
                }
            }
            pos = rr.next;
            i += 1;
        }
        if found_aaaa {
            return AaaaOutcome::Relay;
        }
        let (t_len, ttl) = match cname {
            Some(c) => c,
            None => break,
        };
        hops += 1;
        if hops > MAX_CNAME_HOPS {
            return AaaaOutcome::ServFail;
        }
        let mut v = 0;
        while v < hops {
            if names_equal(visited[v].as_ptr(), visited_len[v], target.as_ptr(), t_len) {
                return AaaaOutcome::ServFail;
            }
            v += 1;
        }
        // Re-encode the alias uncompressed: owner, CNAME, IN, its own TTL,
        // target.
        let need = cur_len + 2 + 10 + t_len + 2;
        let base = slot.chain_len as usize;
        if base + need > MAX_CHAIN_BYTES {
            return AaaaOutcome::ServFail;
        }
        let ch = slot.chain.as_mut_ptr().add(base);
        let owner_wire = encode_name(cur, cur_len, ch);
        if owner_wire == 0 {
            return AaaaOutcome::ServFail;
        }
        let mut p = owner_wire;
        put_u16(ch.add(p), QTYPE_CNAME);
        put_u16(ch.add(p + 2), QCLASS_IN);
        put_u32(ch.add(p + 4), ttl);
        p += 8;
        let rdlen_pos = p;
        p += 2;
        let target_wire = encode_name(target.as_ptr(), t_len, ch.add(p));
        if target_wire == 0 {
            return AaaaOutcome::ServFail;
        }
        put_u16(ch.add(rdlen_pos), target_wire as u16);
        p += target_wire;
        slot.chain_len = (base + p) as u16;
        slot.chain_rrs += 1;
        copy_bytes(visited[hops].as_mut_ptr(), target.as_ptr(), t_len);
        visited_len[hops] = t_len;
    }

    // No AAAA at the terminal owner. Distinguish a referral (NS without SOA
    // and nothing answered) from NODATA, and capture the negative TTL.
    let term_len = visited_len[hops];
    copy_bytes(slot.term.as_mut_ptr(), visited[hops].as_ptr(), term_len);
    slot.term_len = term_len as u8;
    slot.has_soa = 0;
    let auth = match skip_rrs(pkt, pkt_len, question_end, ancount) {
        Some(p) => p,
        None => return AaaaOutcome::ServFail,
    };
    let mut pos = auth;
    let mut saw_ns = false;
    let mut i = 0;
    while i < nscount {
        let rr = match parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()) {
            Some(r) => r,
            None => return AaaaOutcome::ServFail,
        };
        if rr.rtype == QTYPE_SOA {
            // MNAME, RNAME, then five u32s of which MINIMUM is the last.
            let (_, p1) = match read_name(pkt, pkt_len, rr.rdata_off, target.as_mut_ptr()) {
                Some(v) => v,
                None => return AaaaOutcome::ServFail,
            };
            let (_, p2) = match read_name(pkt, pkt_len, p1, target.as_mut_ptr()) {
                Some(v) => v,
                None => return AaaaOutcome::ServFail,
            };
            if p2 + 20 > rr.next {
                return AaaaOutcome::ServFail;
            }
            let minimum = u32::from_be_bytes([
                *pkt.add(p2 + 16),
                *pkt.add(p2 + 17),
                *pkt.add(p2 + 18),
                *pkt.add(p2 + 19),
            ]);
            slot.neg_ttl = if rr.ttl < minimum { rr.ttl } else { minimum };
            slot.has_soa = 1;
        } else if rr.rtype == QTYPE_NS {
            saw_ns = true;
        }
        pos = rr.next;
        i += 1;
    }
    if saw_ns && slot.has_soa == 0 && ancount == 0 {
        return AaaaOutcome::Relay;
    }
    AaaaOutcome::Nodata
}

/// Header and question for an answer to the slot's original AAAA question.
/// Returns the write position, or 0 when it cannot fit.
unsafe fn begin_dns64_answer(slot: &PendingQuery, ancount: u16, tx: *mut u8) -> usize {
    put_u16(tx, slot.client_id);
    // AD is never claimed for a fabricated RRset; AA is never claimed for a
    // forwarded one.
    let flags = FLAG_QR | FLAG_RA | (slot.client_flags & FLAG_RD);
    put_u16(tx.add(2), flags);
    put_u16(tx.add(4), 1);
    put_u16(tx.add(6), ancount);
    put_u16(tx.add(8), 0);
    put_u16(tx.add(10), 0);
    let qlen = slot.qname_len as usize;
    if DNS_HEADER_LEN + qlen + 2 + 4 > DNS_MAX_PACKET {
        return 0;
    }
    let n = encode_name(slot.qname.as_ptr(), qlen, tx.add(DNS_HEADER_LEN));
    if n == 0 {
        return 0;
    }
    let mut pos = DNS_HEADER_LEN + n;
    put_u16(tx.add(pos), QTYPE_AAAA);
    put_u16(tx.add(pos + 2), QCLASS_IN);
    pos += 4;
    // The preserved alias chain, whole or not at all.
    let chain_len = slot.chain_len as usize;
    if pos + chain_len > DNS_MAX_PACKET {
        return 0;
    }
    copy_bytes(tx.add(pos), slot.chain.as_ptr(), chain_len);
    pos + chain_len
}

/// The answer to the original AAAA question with `count` synthesized
/// addresses at `ttl`, or the chain alone when `count` is 0 (NODATA).
/// Records that do not fit are dropped whole and TC is set.
unsafe fn build_dns64_answer(
    s: &DnsState,
    slot: &PendingQuery,
    addrs: &[u32; MAX_SYNTH_ADDRS],
    count: usize,
    ttl: u32,
    tx: *mut u8,
) -> usize {
    let chain_rrs = slot.chain_rrs as u16;
    let mut pos = begin_dns64_answer(slot, chain_rrs, tx);
    if pos == 0 {
        return 0;
    }
    let term_len = slot.term_len as usize;
    let mut written: u16 = 0;
    let mut i = 0;
    while i < count {
        // Owner: the terminal name, as a pointer to the question when it is
        // the question.
        let owner_len = if term_len == slot.qname_len as usize {
            2
        } else {
            term_len + 2
        };
        let need = owner_len + 10 + 16;
        if pos + need > DNS_MAX_PACKET {
            let flags = u16::from_be_bytes([*tx.add(2), *tx.add(3)]) | FLAG_TC;
            put_u16(tx.add(2), flags);
            break;
        }
        if owner_len == 2 {
            *tx.add(pos) = 0xC0;
            *tx.add(pos + 1) = 0x0C;
            pos += 2;
        } else {
            let n = encode_name(slot.term.as_ptr(), term_len, tx.add(pos));
            if n == 0 {
                return 0;
            }
            pos += n;
        }
        put_u16(tx.add(pos), QTYPE_AAAA);
        put_u16(tx.add(pos + 2), QCLASS_IN);
        put_u32(tx.add(pos + 4), ttl);
        put_u16(tx.add(pos + 8), 16);
        pos += 10;
        copy_bytes(tx.add(pos), s.dns64_prefix.as_ptr(), DNS64_PREFIX_BYTES);
        put_u32(tx.add(pos + DNS64_PREFIX_BYTES), addrs[i]);
        pos += 16;
        written += 1;
        i += 1;
    }
    put_u16(tx.add(6), chain_rrs + written);
    pos
}

/// Finish the second phase for `slot` from the upstream A answer: collect
/// the terminal owner's translatable addresses, compute the TTL, and answer
/// the client. Anything but a NOERROR answer with such addresses answers
/// the original question as NODATA with the preserved chain.
unsafe fn finish_dns64(
    state: *mut DnsState,
    slot: PendingQuery,
    pkt: *const u8,
    pkt_len: usize,
    question_end: usize,
    now_ms: u32,
) {
    let s = &mut *state;
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let mut addrs = [0u32; MAX_SYNTH_ADDRS];
    let mut count = 0usize;
    let mut min_ttl = u32::MAX;
    if flags & RCODE_MASK == 0
        && flags & FLAG_TC == 0
        && slot.dns64_gen == s.dns64_generation
        && s.dns64_enabled != 0
    {
        let ancount = u16::from_be_bytes([*pkt.add(6), *pkt.add(7)]) as usize;
        let mut owner = [0u8; MAX_NAME_LEN + 1];
        let mut pos = question_end;
        let mut i = 0;
        while i < ancount && i < MAX_SECTION_RRS {
            let rr = match parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()) {
                Some(r) => r,
                None => break,
            };
            if rr.rtype == QTYPE_A
                && rr.rclass == QCLASS_IN
                && rr.rdlen == 4
                && names_equal(
                    owner.as_ptr(),
                    rr.owner_len,
                    slot.term.as_ptr(),
                    slot.term_len as usize,
                )
            {
                let ip = u32::from_be_bytes([
                    *pkt.add(rr.rdata_off),
                    *pkt.add(rr.rdata_off + 1),
                    *pkt.add(rr.rdata_off + 2),
                    *pkt.add(rr.rdata_off + 3),
                ]);
                if !dns64_excluded(s, ip) && count < MAX_SYNTH_ADDRS {
                    addrs[count] = ip;
                    count += 1;
                    if rr.ttl < min_ttl {
                        min_ttl = rr.ttl;
                    }
                }
            }
            pos = rr.next;
            i += 1;
        }
    }
    // RFC 6147 §5.1.7: min(remaining A TTL, negative SOA TTL), or the A TTL
    // capped without a SOA; the time already spent resolving is deducted.
    let elapsed_s = now_ms.wrapping_sub(slot.start_ms) / 1000;
    let remaining = if min_ttl == u32::MAX {
        0
    } else {
        min_ttl.saturating_sub(elapsed_s)
    };
    let bound = if slot.has_soa != 0 {
        slot.neg_ttl
    } else {
        DNS64_TTL_CAP_S
    };
    let ttl = if remaining < bound { remaining } else { bound };
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let len = build_dns64_answer(s, &slot, &addrs, count, ttl, tx_ptr);
    if len > 0 {
        send_server_reply(
            state,
            slot.client_ip,
            slot.client_port,
            tx_ptr as *const u8,
            len,
        );
    }
}

/// Send the follow-up A question for the slot's terminal owner under a
/// fresh upstream id, in the same slot and against the same deadline.
/// Returns false when no id could be drawn or the send was refused; the
/// slot is released and the caller answers SERVFAIL.
unsafe fn start_a_phase(state: *mut DnsState, slot_idx: usize, now_ms: u32) -> bool {
    let s = &mut *state;
    let upstream_id = match alloc_upstream_id(s, now_ms) {
        Some(id) => id,
        None => return false,
    };
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let e = &mut *s.pending.as_mut_ptr().add(slot_idx);
    put_u16(tx_ptr, upstream_id);
    put_u16(tx_ptr.add(2), FLAG_RD);
    put_u16(tx_ptr.add(4), 1);
    put_u16(tx_ptr.add(6), 0);
    put_u16(tx_ptr.add(8), 0);
    put_u16(tx_ptr.add(10), 0);
    let term_len = e.term_len as usize;
    let n = encode_name(e.term.as_ptr(), term_len, tx_ptr.add(DNS_HEADER_LEN));
    if n == 0 {
        return false;
    }
    let mut pos = DNS_HEADER_LEN + n;
    put_u16(tx_ptr.add(pos), QTYPE_A);
    put_u16(tx_ptr.add(pos + 2), QCLASS_IN);
    pos += 4;
    e.upstream_id = upstream_id;
    e.phase = PHASE_A;
    e.qtype = QTYPE_A;
    e.qname_hash = fnv1a_lower(e.term.as_ptr(), term_len);
    e.active = 1;
    if !send_upstream_query(state, tx_ptr as *const u8, pos) {
        e.active = 0;
        return false;
    }
    true
}

/// Answer `slot`'s client with SERVFAIL from the slot's own question.
unsafe fn servfail_slot(state: *mut DnsState, slot: &PendingQuery) {
    let s = &mut *state;
    s.forward_refusals = s.forward_refusals.wrapping_add(1);
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let mut pos = begin_dns64_answer(slot, 0, tx_ptr);
    if pos == 0 {
        return;
    }
    // The chain is not part of a refusal.
    pos -= slot.chain_len as usize;
    let flags = u16::from_be_bytes([*tx_ptr.add(2), *tx_ptr.add(3)]) | RCODE_SERVFAIL;
    put_u16(tx_ptr.add(2), flags);
    send_server_reply(
        state,
        slot.client_ip,
        slot.client_port,
        tx_ptr as *const u8,
        pos,
    );
}

// ============================================================================
// Dynamic update: configuration
// ============================================================================

/// `update_zone`: the apex, dotted lowercase without a trailing dot.
unsafe fn parse_update_zone(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    let n = copy_name_lower(s.update_zone.as_mut_ptr(), MAX_ZONE_NAME, data, len);
    if n == 0 {
        return;
    }
    s.update_zone_len = n as u8;
    s.update_enabled = 1;
}

/// `update_path`: the committed-generation file.
unsafe fn parse_update_path(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 || len > MAX_ZONE_PATH {
        return;
    }
    copy_bytes(s.update_path.as_mut_ptr(), data, len);
    s.update_path_len = len as u8;
}

/// Record type by mnemonic, for `update_allow`.
unsafe fn parse_rtype(data: *const u8, len: usize) -> Option<u16> {
    let mut up = [0u8; 8];
    if len == 0 || len > 8 {
        return None;
    }
    let mut i = 0;
    while i < len {
        up[i] = (*data.add(i)).to_ascii_uppercase();
        i += 1;
    }
    let t = &up[..len];
    Some(match t {
        b"A" => QTYPE_A,
        b"NS" => QTYPE_NS,
        b"CNAME" => QTYPE_CNAME,
        b"PTR" => QTYPE_PTR,
        b"MX" => QTYPE_MX,
        b"TXT" => QTYPE_TXT,
        b"AAAA" => QTYPE_AAAA,
        _ => return None,
    })
}

/// One `update_allow` entry: `"keyname=name-suffix,TYPE,TYPE"`, `*` for
/// every type. A malformed entry is ignored, so the key it would have
/// admitted stays unadmitted.
unsafe fn parse_update_allow(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 || s.key_count as usize >= MAX_UPDATE_KEYS {
        return;
    }
    let eq = find_byte(data, len, b'=');
    if eq == 0 || eq >= len {
        return;
    }
    let rest = data.add(eq + 1);
    let rest_len = len - eq - 1;
    let comma = find_byte(rest, rest_len, b',');
    if comma == 0 {
        return;
    }
    let idx = s.key_count as usize;
    let key = &mut *s.keys.as_mut_ptr().add(idx);
    *key = TsigKey::empty();
    let n = copy_name_lower(key.name.as_mut_ptr(), MAX_ZONE_NAME, data, eq);
    if n == 0 {
        return;
    }
    key.name_len = n as u8;
    let n = copy_name_lower(key.suffix.as_mut_ptr(), MAX_ZONE_NAME, rest, comma);
    if n == 0 {
        return;
    }
    key.suffix_len = n as u8;
    let mut pos = comma + 1;
    if pos >= rest_len {
        return;
    }
    while pos < rest_len {
        let seg = rest.add(pos);
        let seg_len = find_byte(seg, rest_len - pos, b',');
        if seg_len == 1 && *seg == b'*' {
            key.any_type = 1;
        } else {
            let t = match parse_rtype(seg, seg_len) {
                Some(t) => t,
                None => return,
            };
            if key.type_count as usize >= MAX_ALLOW_TYPES {
                return;
            }
            key.types[key.type_count as usize] = t;
            key.type_count += 1;
        }
        pos += seg_len + 1;
    }
    if key.any_type == 0 && key.type_count == 0 {
        return;
    }
    s.key_count += 1;
}

/// Open every admitted key by label (`dns/tsig/<keyname>`) — never
/// generating one. A key the vault does not hold leaves its entry with
/// handle -1, and every request under it is refused BADKEY.
unsafe fn open_tsig_keys(s: &mut DnsState) {
    use abi::contracts::key_vault as kv;
    let sys = &*s.syscalls;
    let mut i = 0;
    while i < s.key_count as usize {
        let key = &mut *s.keys.as_mut_ptr().add(i);
        let name_len = key.name_len as usize;
        let label_len = TSIG_LABEL_PREFIX.len() + name_len;
        if label_len > MAX_VAULT_LABEL {
            key.handle = -1;
            i += 1;
            continue;
        }
        let mut arg = [0u8; 8 + MAX_VAULT_LABEL + 12];
        arg[0..2].copy_from_slice(&kv::suite::HMAC_SHA256.to_le_bytes());
        arg[2..6].copy_from_slice(&(kv::usage::SIGN | kv::usage::VERIFY).to_le_bytes());
        arg[6] = 0;
        arg[7] = label_len as u8;
        arg[8..8 + TSIG_LABEL_PREFIX.len()].copy_from_slice(TSIG_LABEL_PREFIX);
        copy_bytes(
            arg.as_mut_ptr().add(8 + TSIG_LABEL_PREFIX.len()),
            key.name.as_ptr(),
            name_len,
        );
        let n = 8 + label_len + 12;
        let rc = (sys.provider_call)(-1, kv::OPEN, arg.as_mut_ptr(), n);
        if rc < 0 {
            key.handle = -1;
            log_info(
                s,
                b"[dns] update key absent from vault: requests under it are refused",
            );
        } else {
            key.handle = rc;
        }
        i += 1;
    }
}

/// Index of the admitted key named `name`.
unsafe fn find_key(s: &DnsState, name: *const u8, name_len: usize) -> Option<usize> {
    let mut i = 0;
    while i < s.key_count as usize {
        let k = &*s.keys.as_ptr().add(i);
        if names_equal(k.name.as_ptr(), k.name_len as usize, name, name_len) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether `key` may change records of `rtype` at `name`. A delete-all
/// (`type ANY`) needs an entry admitting every type.
unsafe fn key_permits(key: &TsigKey, name: *const u8, name_len: usize, rtype: u16) -> bool {
    if !name_within(name, name_len, key.suffix.as_ptr(), key.suffix_len as usize) {
        return false;
    }
    if key.any_type != 0 {
        return true;
    }
    if rtype == QTYPE_ANY {
        return false;
    }
    let mut i = 0;
    while i < key.type_count as usize {
        if key.types[i] == rtype {
            return true;
        }
        i += 1;
    }
    false
}

// ============================================================================
// TSIG (RFC 8945)
// ============================================================================

/// Calendar seconds the platform vouches for, or 0 when there is no
/// trusted clock — in which case no signing window can be checked and the
/// request is BADTIME.
unsafe fn trusted_now_secs(sys: &SyscallTable) -> u64 {
    use abi::kernel_abi::trusted_time as tt;
    let rec = dev_trusted_unix(sys);
    if rec[tt::OFF_FLAGS] & tt::flags::TRUSTED == 0 {
        return 0;
    }
    let mut secs = [0u8; 8];
    secs.copy_from_slice(&rec[tt::OFF_UNIX_SECONDS..tt::OFF_UNIX_SECONDS + 8]);
    u64::from_le_bytes(secs)
}

/// Append the TSIG variables (RFC 8945 §4.3.3) for `key` to `buf[pos..]`.
/// Returns the new position, or 0 when they do not fit.
#[allow(
    clippy::too_many_arguments,
    reason = "the TSIG variables are the record's fields; a struct would move the list, not shorten it"
)]
unsafe fn put_tsig_vars(
    buf: *mut u8,
    cap: usize,
    pos: usize,
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> usize {
    let name_len = key.name_len as usize;
    let need = name_len + 2 + 6 + TSIG_ALG_HMAC_SHA256.len() + 2 + 6 + 2 + 2 + 2 + other.len();
    if pos + need > cap {
        return 0;
    }
    let mut p = pos;
    let n = encode_name(key.name.as_ptr(), name_len, buf.add(p));
    if n == 0 {
        return 0;
    }
    p += n;
    put_u16(buf.add(p), QCLASS_ANY);
    put_u32(buf.add(p + 2), 0);
    p += 6;
    let n = encode_name(
        TSIG_ALG_HMAC_SHA256.as_ptr(),
        TSIG_ALG_HMAC_SHA256.len(),
        buf.add(p),
    );
    p += n;
    let t = time_signed.to_be_bytes();
    copy_bytes(buf.add(p), t.as_ptr().add(2), 6);
    p += 6;
    put_u16(buf.add(p), fudge);
    put_u16(buf.add(p + 2), error);
    put_u16(buf.add(p + 4), other.len() as u16);
    p += 6;
    copy_bytes(buf.add(p), other.as_ptr(), other.len());
    p + other.len()
}

/// Locate and parse the TSIG record, which must be the last record of the
/// additional section (RFC 8945 §5.1). `sections` is the offset just past
/// the question.
unsafe fn parse_tsig(
    s: &DnsState,
    pkt: *const u8,
    pkt_len: usize,
    question_end: usize,
    info: &mut TsigInfo,
) -> TsigVerdict {
    let ancount = u16::from_be_bytes([*pkt.add(6), *pkt.add(7)]) as usize;
    let nscount = u16::from_be_bytes([*pkt.add(8), *pkt.add(9)]) as usize;
    let arcount = u16::from_be_bytes([*pkt.add(10), *pkt.add(11)]) as usize;
    if arcount == 0 {
        return TsigVerdict::Absent;
    }
    let pos = match skip_rrs(pkt, pkt_len, question_end, ancount + nscount) {
        Some(p) => p,
        None => return TsigVerdict::Malformed,
    };
    let pos = match skip_rrs(pkt, pkt_len, pos, arcount - 1) {
        Some(p) => p,
        None => return TsigVerdict::Malformed,
    };
    let mut owner = [0u8; MAX_NAME_LEN + 1];
    let rr = match parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()) {
        Some(r) => r,
        None => return TsigVerdict::Malformed,
    };
    if rr.rtype != QTYPE_TSIG {
        return TsigVerdict::Absent;
    }
    if rr.rclass != QCLASS_ANY || rr.ttl != 0 || rr.next != pkt_len {
        return TsigVerdict::Malformed;
    }
    // RDATA: algorithm, time (48), fudge, mac size, mac, original id,
    // error, other len, other data.
    let mut alg = [0u8; MAX_NAME_LEN + 1];
    let (alg_len, p) = match read_name(pkt, pkt_len, rr.rdata_off, alg.as_mut_ptr()) {
        Some(v) => v,
        None => return TsigVerdict::Malformed,
    };
    if p + 6 + 2 + 2 > rr.next {
        return TsigVerdict::Malformed;
    }
    let mut t = [0u8; 8];
    copy_bytes(t.as_mut_ptr().add(2), pkt.add(p), 6);
    let time_signed = u64::from_be_bytes(t);
    let fudge = u16::from_be_bytes([*pkt.add(p + 6), *pkt.add(p + 7)]);
    let mac_size = u16::from_be_bytes([*pkt.add(p + 8), *pkt.add(p + 9)]) as usize;
    let mac_off = p + 10;
    if mac_off + mac_size + 6 > rr.next {
        return TsigVerdict::Malformed;
    }
    let after_mac = mac_off + mac_size;
    let orig_id = u16::from_be_bytes([*pkt.add(after_mac), *pkt.add(after_mac + 1)]);
    let other_len = u16::from_be_bytes([*pkt.add(after_mac + 4), *pkt.add(after_mac + 5)]) as usize;
    if after_mac + 6 + other_len != rr.next {
        return TsigVerdict::Malformed;
    }
    info.tsig_off = rr.start;
    info.time_signed = time_signed;
    info.fudge = fudge;
    info.orig_id = orig_id;
    let key_idx = match find_key(s, owner.as_ptr(), rr.owner_len) {
        Some(k) => k,
        None => return TsigVerdict::BadKey,
    };
    if (*s.keys.as_ptr().add(key_idx)).handle < 0 {
        return TsigVerdict::BadKey;
    }
    info.key_idx = key_idx;
    if !names_equal(
        alg.as_ptr(),
        alg_len,
        TSIG_ALG_HMAC_SHA256.as_ptr(),
        TSIG_ALG_HMAC_SHA256.len(),
    ) {
        return TsigVerdict::BadKey;
    }
    if mac_size != TSIG_MAC_LEN {
        return TsigVerdict::BadSig;
    }
    copy_bytes(info.mac.as_mut_ptr(), pkt.add(mac_off), TSIG_MAC_LEN);
    TsigVerdict::Ok
}

/// Verify the request MAC in the vault (constant time there) and the
/// signing window against trusted time. Key, then MAC, then time, as RFC
/// 8945 §5.2 orders them.
unsafe fn verify_tsig(
    s: &mut DnsState,
    pkt: *const u8,
    pkt_len: usize,
    question_end: usize,
    info: &mut TsigInfo,
    now_secs: u64,
) -> TsigVerdict {
    use abi::contracts::key_vault as kv;
    let v = parse_tsig(s, pkt, pkt_len, question_end, info);
    if v != TsigVerdict::Ok {
        return v;
    }
    let key = *s.keys.as_ptr().add(info.key_idx);
    // MAC input: the message without the TSIG record, ARCOUNT decremented
    // and the id as originally sent, then the TSIG variables.
    let buf = s.mac_buf.as_mut_ptr();
    let msg_len = info.tsig_off;
    copy_bytes(buf, pkt, msg_len);
    put_u16(buf, info.orig_id);
    let arcount = u16::from_be_bytes([*pkt.add(10), *pkt.add(11)]);
    put_u16(buf.add(10), arcount - 1);
    let end = put_tsig_vars(
        buf,
        MAC_INPUT_MAX,
        msg_len,
        &key,
        info.time_signed,
        info.fudge,
        0,
        &[],
    );
    if end == 0 {
        return TsigVerdict::Malformed;
    }
    // VERIFY against the slot: [msg_len][mac_len][pub_len=0][pad][msg][mac].
    let mut arg = [0u8; 8 + MAC_INPUT_MAX + TSIG_MAC_LEN];
    arg[0..2].copy_from_slice(&(end as u16).to_le_bytes());
    arg[2..4].copy_from_slice(&(TSIG_MAC_LEN as u16).to_le_bytes());
    copy_bytes(arg.as_mut_ptr().add(8), buf, end);
    copy_bytes(
        arg.as_mut_ptr().add(8 + end),
        info.mac.as_ptr(),
        TSIG_MAC_LEN,
    );
    let rc = (s.sys().provider_call)(
        key.handle,
        kv::VERIFY,
        arg.as_mut_ptr(),
        8 + end + TSIG_MAC_LEN,
    );
    if rc != 1 {
        return TsigVerdict::BadSig;
    }
    if now_secs == 0 {
        return TsigVerdict::BadTime;
    }
    let fudge = if (info.fudge as u64) < MAX_TSIG_FUDGE_S {
        info.fudge as u64
    } else {
        MAX_TSIG_FUDGE_S
    };
    let skew = now_secs.abs_diff(info.time_signed);
    if skew > fudge {
        return TsigVerdict::BadTime;
    }
    TsigVerdict::Ok
}

/// Append a TSIG record to the response in `tx[..len]`. With `signed`
/// the MAC is computed over the request MAC, the response and the TSIG
/// variables; without it (BADKEY / BADSIG) the record carries an empty MAC.
/// Returns the new length, or 0 when the record does not fit or the vault
/// refused.
#[allow(
    clippy::too_many_arguments,
    reason = "the TSIG record is its fields; a struct would move the list, not shorten it"
)]
unsafe fn append_tsig(
    s: &mut DnsState,
    key_idx: usize,
    signed: bool,
    request_mac: &[u8; TSIG_MAC_LEN],
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
    tx: *mut u8,
    len: usize,
) -> usize {
    use abi::contracts::key_vault as kv;
    let key = *s.keys.as_ptr().add(key_idx);
    let mut mac = [0u8; TSIG_MAC_LEN];
    if signed {
        let buf = s.mac_buf.as_mut_ptr();
        put_u16(buf, TSIG_MAC_LEN as u16);
        copy_bytes(buf.add(2), request_mac.as_ptr(), TSIG_MAC_LEN);
        let mut p = 2 + TSIG_MAC_LEN;
        if p + len > MAC_INPUT_MAX {
            return 0;
        }
        copy_bytes(buf.add(p), tx, len);
        p += len;
        let end = put_tsig_vars(
            buf,
            MAC_INPUT_MAX,
            p,
            &key,
            time_signed,
            fudge,
            error,
            other,
        );
        if end == 0 {
            return 0;
        }
        // SIGN: [mode][pad][input_len:u32][input][out_ptr:u64][cap:u16][len_out:u16]
        let mut arg = [0u8; 6 + MAC_INPUT_MAX + 12];
        arg[0] = kv::sign_mode::RAW;
        arg[2..6].copy_from_slice(&(end as u32).to_le_bytes());
        copy_bytes(arg.as_mut_ptr().add(6), buf, end);
        let tail = 6 + end;
        arg[tail..tail + 8].copy_from_slice(&(mac.as_mut_ptr() as u64).to_le_bytes());
        arg[tail + 8..tail + 10].copy_from_slice(&(TSIG_MAC_LEN as u16).to_le_bytes());
        let rc = (s.sys().provider_call)(key.handle, kv::SIGN, arg.as_mut_ptr(), tail + 12);
        if rc < 0 {
            return 0;
        }
    }
    let mac_len = if signed { TSIG_MAC_LEN } else { 0 };
    let name_len = key.name_len as usize;
    let rdlen = TSIG_ALG_HMAC_SHA256.len() + 2 + 6 + 2 + 2 + mac_len + 2 + 2 + 2 + other.len();
    let need = name_len + 2 + 10 + rdlen;
    if len + need > DNS_MAX_PACKET {
        return 0;
    }
    let mut p = len;
    let n = encode_name(key.name.as_ptr(), name_len, tx.add(p));
    if n == 0 {
        return 0;
    }
    p += n;
    put_u16(tx.add(p), QTYPE_TSIG);
    put_u16(tx.add(p + 2), QCLASS_ANY);
    put_u32(tx.add(p + 4), 0);
    put_u16(tx.add(p + 8), rdlen as u16);
    p += 10;
    let n = encode_name(
        TSIG_ALG_HMAC_SHA256.as_ptr(),
        TSIG_ALG_HMAC_SHA256.len(),
        tx.add(p),
    );
    p += n;
    let t = time_signed.to_be_bytes();
    copy_bytes(tx.add(p), t.as_ptr().add(2), 6);
    p += 6;
    put_u16(tx.add(p), fudge);
    put_u16(tx.add(p + 2), mac_len as u16);
    p += 4;
    copy_bytes(tx.add(p), mac.as_ptr(), mac_len);
    p += mac_len;
    put_u16(tx.add(p), u16::from_be_bytes([*tx, *tx.add(1)]));
    put_u16(tx.add(p + 2), error);
    put_u16(tx.add(p + 4), other.len() as u16);
    p += 6;
    copy_bytes(tx.add(p), other.as_ptr(), other.len());
    p += other.len();
    let arcount = u16::from_be_bytes([*tx.add(10), *tx.add(11)]);
    put_u16(tx.add(10), arcount + 1);
    p
}

// ============================================================================
// Dynamic update: the zone
// ============================================================================

/// Index of the first record at `name` with `rtype` (`QTYPE_ANY` for any
/// type) and, when `rdata` is given, that RDATA.
unsafe fn zone_find(
    z: &Zone,
    name: *const u8,
    name_len: usize,
    rtype: u16,
    rdata: Option<(*const u8, usize)>,
) -> Option<usize> {
    let mut i = 0;
    while i < z.count as usize {
        let rr = &*z.rrs.as_ptr().add(i);
        if names_equal(rr.name.as_ptr(), rr.name_len as usize, name, name_len)
            && (rtype == QTYPE_ANY || rr.rtype == rtype)
        {
            match rdata {
                None => return Some(i),
                Some((d, dl)) => {
                    if rr.rdlen as usize == dl && names_equal(rr.rdata.as_ptr(), dl, d, dl) {
                        return Some(i);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Number of records at `name` with `rtype`.
unsafe fn zone_count(z: &Zone, name: *const u8, name_len: usize, rtype: u16) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < z.count as usize {
        let rr = &*z.rrs.as_ptr().add(i);
        if names_equal(rr.name.as_ptr(), rr.name_len as usize, name, name_len) && rr.rtype == rtype
        {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Remove record `idx`, keeping order.
unsafe fn zone_remove(z: &mut Zone, idx: usize) {
    let count = z.count as usize;
    let mut i = idx;
    while i + 1 < count {
        *z.rrs.as_mut_ptr().add(i) = *z.rrs.as_ptr().add(i + 1);
        i += 1;
    }
    z.count -= 1;
}

/// Remove every record at `name` matching `rtype` (`QTYPE_ANY` for all).
unsafe fn zone_remove_all(z: &mut Zone, name: *const u8, name_len: usize, rtype: u16) {
    let mut guard = 0;
    while guard < MAX_ZONE_RRS {
        match zone_find(z, name, name_len, rtype, None) {
            Some(i) => zone_remove(z, i),
            None => break,
        }
        guard += 1;
    }
}

/// Copy an RDATA into uncompressed form: single-name types are re-encoded
/// from the decoded name, everything else is copied as is. Returns the
/// length written, or 0 when it does not fit.
unsafe fn rdata_uncompressed(pkt: *const u8, pkt_len: usize, rr: &RrView, out: *mut u8) -> usize {
    match rr.rtype {
        QTYPE_CNAME | QTYPE_PTR | QTYPE_NS => {
            let mut name = [0u8; MAX_NAME_LEN + 1];
            let (n, end) = match read_name(pkt, pkt_len, rr.rdata_off, name.as_mut_ptr()) {
                Some(v) => v,
                None => return 0,
            };
            if end != rr.next || n + 2 > MAX_ZONE_RDATA {
                return 0;
            }
            if n == 0 {
                *out = 0;
                return 1;
            }
            encode_name(name.as_ptr(), n, out)
        }
        _ => {
            if rr.rdlen > MAX_ZONE_RDATA {
                return 0;
            }
            copy_bytes(out, pkt.add(rr.rdata_off), rr.rdlen);
            rr.rdlen
        }
    }
}

/// Serve a query for a name inside the configured zone from the current
/// generation. Returns the response length.
unsafe fn build_zone_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    name: *const u8,
    name_len: usize,
    qtype: u16,
    tx: *mut u8,
) -> usize {
    if qtype == QTYPE_ANY {
        return begin_local_response(query_pkt, question_end, RCODE_NOTIMP, 0, 0, tx);
    }
    let z = &s.zone;
    if zone_find(z, name, name_len, QTYPE_ANY, None).is_none() {
        return build_nxdomain(query_pkt, question_end, tx);
    }
    // A CNAME at the name answers every other type.
    let want = if zone_find(z, name, name_len, QTYPE_CNAME, None).is_some() && qtype != QTYPE_CNAME
    {
        QTYPE_CNAME
    } else {
        qtype
    };
    let mut pos = begin_local_response(query_pkt, question_end, 0, 0, 0, tx);
    if pos == 0 {
        return 0;
    }
    let mut written: u16 = 0;
    let mut i = 0;
    while i < z.count as usize {
        let rr = &*z.rrs.as_ptr().add(i);
        if rr.rtype == want && names_equal(rr.name.as_ptr(), rr.name_len as usize, name, name_len) {
            let need = 2 + 10 + rr.rdlen as usize;
            if pos + need > DNS_MAX_PACKET {
                let flags = u16::from_be_bytes([*tx.add(2), *tx.add(3)]) | FLAG_TC;
                put_u16(tx.add(2), flags);
                break;
            }
            *tx.add(pos) = 0xC0;
            *tx.add(pos + 1) = 0x0C;
            put_u16(tx.add(pos + 2), rr.rtype);
            put_u16(tx.add(pos + 4), rr.rclass);
            put_u32(tx.add(pos + 6), rr.ttl);
            put_u16(tx.add(pos + 10), rr.rdlen as u16);
            pos += 12;
            copy_bytes(tx.add(pos), rr.rdata.as_ptr(), rr.rdlen as usize);
            pos += rr.rdlen as usize;
            written += 1;
        }
        i += 1;
    }
    put_u16(tx.add(6), written);
    pos
}

/// Evaluate the prerequisite section (RFC 2136 §3.2) against the current
/// generation. `pos` is the section start. Returns the offset past the
/// section, or the rcode to answer with.
unsafe fn check_prerequisites(
    s: &DnsState,
    pkt: *const u8,
    pkt_len: usize,
    section_start: usize,
    prcount: usize,
) -> Result<usize, u16> {
    let zone_name = s.update_zone.as_ptr();
    let zone_len = s.update_zone_len as usize;
    let z = &s.zone;
    let mut owner = [0u8; MAX_NAME_LEN + 1];
    let mut scratch = [0u8; MAX_NAME_LEN + 1];
    let mut rdata = [0u8; MAX_ZONE_RDATA];
    let mut pos = section_start;
    let mut i = 0;
    while i < prcount {
        let rr = parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()).ok_or(RCODE_FORMERR)?;
        if rr.ttl != 0 {
            return Err(RCODE_FORMERR);
        }
        if !name_within(owner.as_ptr(), rr.owner_len, zone_name, zone_len) {
            return Err(RCODE_NOTZONE);
        }
        match rr.rclass {
            QCLASS_ANY => {
                if rr.rdlen != 0 {
                    return Err(RCODE_FORMERR);
                }
                if rr.rtype == QTYPE_ANY {
                    if zone_find(z, owner.as_ptr(), rr.owner_len, QTYPE_ANY, None).is_none() {
                        return Err(RCODE_NXDOMAIN);
                    }
                } else if zone_find(z, owner.as_ptr(), rr.owner_len, rr.rtype, None).is_none() {
                    return Err(RCODE_NXRRSET);
                }
            }
            QCLASS_NONE => {
                if rr.rdlen != 0 {
                    return Err(RCODE_FORMERR);
                }
                if rr.rtype == QTYPE_ANY {
                    if zone_find(z, owner.as_ptr(), rr.owner_len, QTYPE_ANY, None).is_some() {
                        return Err(RCODE_YXDOMAIN);
                    }
                } else if zone_find(z, owner.as_ptr(), rr.owner_len, rr.rtype, None).is_some() {
                    return Err(RCODE_YXRRSET);
                }
            }
            QCLASS_IN => {
                // Value-dependent: the zone's RRset must be exactly the set
                // named. Every named record must be present, and the set
                // sizes must agree; the section is bounded, so the count is
                // taken over it whole.
                if rr.rtype == QTYPE_ANY {
                    return Err(RCODE_FORMERR);
                }
                let dl = rdata_uncompressed(pkt, pkt_len, &rr, rdata.as_mut_ptr());
                if dl == 0 && rr.rdlen != 0 {
                    return Err(RCODE_FORMERR);
                }
                if zone_find(
                    z,
                    owner.as_ptr(),
                    rr.owner_len,
                    rr.rtype,
                    Some((rdata.as_ptr(), dl)),
                )
                .is_none()
                {
                    return Err(RCODE_NXRRSET);
                }
                let mut named = 0usize;
                let mut q = section_start;
                let mut k = 0;
                while k < prcount {
                    let other =
                        parse_rr(pkt, pkt_len, q, scratch.as_mut_ptr()).ok_or(RCODE_FORMERR)?;
                    if other.rclass == QCLASS_IN
                        && other.rtype == rr.rtype
                        && names_equal(
                            scratch.as_ptr(),
                            other.owner_len,
                            owner.as_ptr(),
                            rr.owner_len,
                        )
                    {
                        named += 1;
                    }
                    q = other.next;
                    k += 1;
                }
                if zone_count(z, owner.as_ptr(), rr.owner_len, rr.rtype) != named {
                    return Err(RCODE_NXRRSET);
                }
            }
            _ => return Err(RCODE_FORMERR),
        }
        pos = rr.next;
        i += 1;
    }
    Ok(pos)
}

/// Prescan (RFC 2136 §3.4.1) and apply (§3.4.2) the update section into
/// the candidate, which must already be a copy of the current generation.
/// Returns the offset past the section, or the rcode to answer with; the
/// candidate is meaningless after an error.
unsafe fn apply_update_section(
    s: &mut DnsState,
    key_idx: usize,
    pkt: *const u8,
    pkt_len: usize,
    section_start: usize,
    upcount: usize,
) -> Result<usize, u16> {
    let zone_name = s.update_zone.as_ptr();
    let zone_len = s.update_zone_len as usize;
    let key = *s.keys.as_ptr().add(key_idx);
    let mut owner = [0u8; MAX_NAME_LEN + 1];
    let mut rdata = [0u8; MAX_ZONE_RDATA];

    // Prescan: every record is checked before any is applied, so a
    // malformed or unpermitted record late in the section refuses the
    // whole message with the candidate untouched.
    let mut pos = section_start;
    let mut i = 0;
    while i < upcount {
        let rr = parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()).ok_or(RCODE_FORMERR)?;
        if !name_within(owner.as_ptr(), rr.owner_len, zone_name, zone_len) {
            return Err(RCODE_NOTZONE);
        }
        match rr.rclass {
            QCLASS_IN => {
                if rr.rtype == QTYPE_ANY || rr.rtype == QTYPE_TSIG || rr.rtype == QTYPE_OPT {
                    return Err(RCODE_FORMERR);
                }
            }
            QCLASS_ANY => {
                if rr.ttl != 0 || rr.rdlen != 0 || rr.rtype == QTYPE_TSIG || rr.rtype == QTYPE_OPT {
                    return Err(RCODE_FORMERR);
                }
            }
            QCLASS_NONE => {
                if rr.ttl != 0 || rr.rtype == QTYPE_ANY || rr.rtype == QTYPE_TSIG {
                    return Err(RCODE_FORMERR);
                }
            }
            _ => return Err(RCODE_FORMERR),
        }
        if !key_permits(&key, owner.as_ptr(), rr.owner_len, rr.rtype) {
            return Err(RCODE_REFUSED);
        }
        pos = rr.next;
        i += 1;
    }

    let cand = &mut s.candidate;
    pos = section_start;
    i = 0;
    while i < upcount {
        let rr = parse_rr(pkt, pkt_len, pos, owner.as_mut_ptr()).ok_or(RCODE_FORMERR)?;
        if rr.owner_len > MAX_ZONE_NAME {
            return Err(RCODE_SERVFAIL);
        }
        match rr.rclass {
            QCLASS_IN => {
                let dl = rdata_uncompressed(pkt, pkt_len, &rr, rdata.as_mut_ptr());
                if dl == 0 && rr.rdlen != 0 {
                    return Err(RCODE_SERVFAIL);
                }
                let has_cname =
                    zone_find(cand, owner.as_ptr(), rr.owner_len, QTYPE_CNAME, None).is_some();
                let has_any =
                    zone_find(cand, owner.as_ptr(), rr.owner_len, QTYPE_ANY, None).is_some();
                // §3.4.2.2: a CNAME never coexists with other data at a
                // name; the conflicting addition is ignored.
                if (rr.rtype == QTYPE_CNAME && has_any && !has_cname)
                    || (rr.rtype != QTYPE_CNAME && has_cname)
                {
                    pos = rr.next;
                    i += 1;
                    continue;
                }
                match zone_find(
                    cand,
                    owner.as_ptr(),
                    rr.owner_len,
                    rr.rtype,
                    Some((rdata.as_ptr(), dl)),
                ) {
                    Some(idx) => {
                        (*cand.rrs.as_mut_ptr().add(idx)).ttl = rr.ttl;
                    }
                    None => {
                        // A CNAME replaces an existing CNAME (§3.4.2.2).
                        if rr.rtype == QTYPE_CNAME {
                            zone_remove_all(cand, owner.as_ptr(), rr.owner_len, QTYPE_CNAME);
                        }
                        if cand.count as usize >= MAX_ZONE_RRS {
                            return Err(RCODE_SERVFAIL);
                        }
                        let e = &mut *cand.rrs.as_mut_ptr().add(cand.count as usize);
                        *e = ZoneRr::empty();
                        copy_bytes(e.name.as_mut_ptr(), owner.as_ptr(), rr.owner_len);
                        e.name_len = rr.owner_len as u8;
                        e.rtype = rr.rtype;
                        e.rclass = QCLASS_IN;
                        e.ttl = rr.ttl;
                        copy_bytes(e.rdata.as_mut_ptr(), rdata.as_ptr(), dl);
                        e.rdlen = dl as u8;
                        cand.count += 1;
                    }
                }
            }
            QCLASS_ANY => {
                zone_remove_all(cand, owner.as_ptr(), rr.owner_len, rr.rtype);
            }
            QCLASS_NONE => {
                let dl = rdata_uncompressed(pkt, pkt_len, &rr, rdata.as_mut_ptr());
                if dl == 0 && rr.rdlen != 0 {
                    return Err(RCODE_SERVFAIL);
                }
                if let Some(idx) = zone_find(
                    cand,
                    owner.as_ptr(),
                    rr.owner_len,
                    rr.rtype,
                    Some((rdata.as_ptr(), dl)),
                ) {
                    zone_remove(cand, idx);
                }
            }
            _ => return Err(RCODE_FORMERR),
        }
        pos = rr.next;
        i += 1;
    }
    Ok(pos)
}

// ============================================================================
// Dynamic update: durable commit and recovery (`fs` contract)
// ============================================================================

/// Serialize `z` into the zone-file scratch. Returns the length.
unsafe fn zone_serialize(s: &mut DnsState, from_candidate: bool) -> usize {
    let z: *const Zone = if from_candidate {
        &s.candidate
    } else {
        &s.zone
    };
    let buf = s.zone_file.as_mut_ptr();
    copy_bytes(buf, ZONE_FILE_MAGIC.as_ptr(), 4);
    put_u32(buf.add(4), (*z).generation);
    put_u16(buf.add(8), (*z).count);
    let mut p = 10;
    let mut i = 0;
    while i < (*z).count as usize {
        let rr = &*(*z).rrs.as_ptr().add(i);
        *buf.add(p) = rr.name_len;
        p += 1;
        copy_bytes(buf.add(p), rr.name.as_ptr(), rr.name_len as usize);
        p += rr.name_len as usize;
        put_u16(buf.add(p), rr.rtype);
        put_u16(buf.add(p + 2), rr.rclass);
        put_u32(buf.add(p + 4), rr.ttl);
        put_u16(buf.add(p + 8), rr.rdlen as u16);
        p += 10;
        copy_bytes(buf.add(p), rr.rdata.as_ptr(), rr.rdlen as usize);
        p += rr.rdlen as usize;
        i += 1;
    }
    let digest = fnv1a_lower(buf, p);
    put_u32(buf.add(p), digest);
    p + 4
}

/// Load the zone-file scratch (`len` bytes) into the current generation.
/// A file that is short, undigested or over its bounds is refused whole:
/// a recovered generation is complete or it is nothing.
unsafe fn zone_deserialize(s: &mut DnsState, len: usize) -> bool {
    let buf = s.zone_file.as_ptr();
    if !(14..=MAX_ZONE_FILE).contains(&len) {
        return false;
    }
    let mut magic = [0u8; 4];
    copy_bytes(magic.as_mut_ptr(), buf, 4);
    if magic != ZONE_FILE_MAGIC {
        return false;
    }
    let body = len - 4;
    let stored = u32::from_be_bytes([
        *buf.add(body),
        *buf.add(body + 1),
        *buf.add(body + 2),
        *buf.add(body + 3),
    ]);
    if fnv1a_lower(buf, body) != stored {
        return false;
    }
    let generation = u32::from_be_bytes([*buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7)]);
    let count = u16::from_be_bytes([*buf.add(8), *buf.add(9)]) as usize;
    if count > MAX_ZONE_RRS {
        return false;
    }
    let mut loaded = Zone::empty();
    let mut p = 10;
    let mut i = 0;
    while i < count {
        if p + 1 > body {
            return false;
        }
        let name_len = *buf.add(p) as usize;
        p += 1;
        if name_len == 0 || name_len > MAX_ZONE_NAME || p + name_len + 10 > body {
            return false;
        }
        let e = &mut *loaded.rrs.as_mut_ptr().add(i);
        copy_bytes(e.name.as_mut_ptr(), buf.add(p), name_len);
        e.name_len = name_len as u8;
        p += name_len;
        e.rtype = u16::from_be_bytes([*buf.add(p), *buf.add(p + 1)]);
        e.rclass = u16::from_be_bytes([*buf.add(p + 2), *buf.add(p + 3)]);
        e.ttl = u32::from_be_bytes([
            *buf.add(p + 4),
            *buf.add(p + 5),
            *buf.add(p + 6),
            *buf.add(p + 7),
        ]);
        let rdlen = u16::from_be_bytes([*buf.add(p + 8), *buf.add(p + 9)]) as usize;
        p += 10;
        if rdlen > MAX_ZONE_RDATA || p + rdlen > body {
            return false;
        }
        copy_bytes(e.rdata.as_mut_ptr(), buf.add(p), rdlen);
        e.rdlen = rdlen as u8;
        p += rdlen;
        i += 1;
    }
    if p != body {
        return false;
    }
    loaded.count = count as u16;
    loaded.generation = generation;
    s.zone = loaded;
    true
}

/// The committed-generation path and its temporary sibling (`.tmp`).
unsafe fn zone_paths(s: &DnsState, tmp: *mut u8) -> (usize, usize) {
    let n = s.update_path_len as usize;
    copy_bytes(tmp, s.update_path.as_ptr(), n);
    copy_bytes(tmp.add(n), b".tmp".as_ptr(), 4);
    (n, n + 4)
}

/// Commit the candidate through the `fs` contract: temp → write → fsync →
/// close → rename. Returns false, with the final name untouched, on any
/// refusal along the way.
unsafe fn zone_commit_durable(s: &mut DnsState) -> bool {
    use abi::contracts::storage::fs;
    let len = zone_serialize(s, true);
    let sys = &*s.syscalls;
    let mut tmp = [0u8; MAX_ZONE_PATH + 4];
    let (path_len, tmp_len) = zone_paths(s, tmp.as_mut_ptr());
    // A previous interrupted commit may have left the temporary behind.
    let _ = (sys.provider_call)(-1, fs::UNLINK, tmp.as_mut_ptr(), tmp_len);
    let fd = (sys.provider_call)(-1, fs::OPEN_CREATE, tmp.as_mut_ptr(), tmp_len);
    if fd < 0 {
        return false;
    }
    let buf = s.zone_file.as_mut_ptr();
    let mut done = 0usize;
    let mut writes = 0usize;
    while done < len {
        if writes >= MAX_COMMIT_WRITES {
            (sys.provider_call)(fd, fs::CLOSE, core::ptr::null_mut(), 0);
            return false;
        }
        let n = (sys.provider_call)(fd, fs::WRITE, buf.add(done), len - done);
        if n <= 0 {
            (sys.provider_call)(fd, fs::CLOSE, core::ptr::null_mut(), 0);
            return false;
        }
        done += n as usize;
        writes += 1;
    }
    if (sys.provider_call)(fd, fs::FSYNC, core::ptr::null_mut(), 0) < 0 {
        (sys.provider_call)(fd, fs::CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    if (sys.provider_call)(fd, fs::CLOSE, core::ptr::null_mut(), 0) < 0 {
        return false;
    }
    // RENAME: [src_len:u16][src][dst_len:u16][dst], little-endian lengths.
    let mut arg = [0u8; 2 * (MAX_ZONE_PATH + 4) + 4];
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(tmp_len as u16).to_le_bytes());
    p += 2;
    copy_bytes(arg.as_mut_ptr().add(p), tmp.as_ptr(), tmp_len);
    p += tmp_len;
    arg[p..p + 2].copy_from_slice(&(path_len as u16).to_le_bytes());
    p += 2;
    copy_bytes(arg.as_mut_ptr().add(p), s.update_path.as_ptr(), path_len);
    p += path_len;
    (sys.provider_call)(-1, fs::RENAME, arg.as_mut_ptr(), p) >= 0
}

/// Probe the storage provider's write tier. `None` while it has no answer
/// yet (`EAGAIN`), `Some(false)` when it lacks a capability the commit
/// needs.
unsafe fn zone_storage_ready(s: &DnsState) -> Option<bool> {
    use abi::contracts::storage::fs;
    let mut caps = [0u8; 4];
    let rc = (s.sys().provider_call)(-1, fs::CAPS, caps.as_mut_ptr(), 4);
    if rc == abi::errno::EAGAIN {
        return None;
    }
    if rc < 0 {
        return Some(false);
    }
    let bits = u32::from_le_bytes(caps);
    let need = fs::caps::OPEN_CREATE | fs::caps::WRITE | fs::caps::FSYNC | fs::caps::RENAME;
    Some(bits & need == need)
}

/// Recover the last committed generation. An absent file is an empty zone;
/// a file that does not verify is refused and logged, and the zone starts
/// empty rather than from a partial read.
unsafe fn zone_recover(s: &mut DnsState) {
    use abi::contracts::storage::fs;
    let sys = &*s.syscalls;
    let mut path = [0u8; MAX_ZONE_PATH];
    let n = s.update_path_len as usize;
    copy_bytes(path.as_mut_ptr(), s.update_path.as_ptr(), n);
    let fd = (sys.provider_call)(-1, fs::OPEN, path.as_mut_ptr(), n);
    if fd < 0 {
        log_info(s, b"[dns] zone: no committed generation, starting empty");
        return;
    }
    let buf = s.zone_file.as_mut_ptr();
    let mut got = 0usize;
    let mut reads = 0usize;
    let mut overflow = false;
    while reads < MAX_COMMIT_WRITES {
        if got >= MAX_ZONE_FILE {
            // Anything past the ceiling is not a generation this profile
            // wrote.
            let mut probe = [0u8; 1];
            if (sys.provider_call)(fd, fs::READ, probe.as_mut_ptr(), 1) > 0 {
                overflow = true;
            }
            break;
        }
        let r = (sys.provider_call)(fd, fs::READ, buf.add(got), MAX_ZONE_FILE - got);
        if r <= 0 {
            break;
        }
        got += r as usize;
        reads += 1;
    }
    (sys.provider_call)(fd, fs::CLOSE, core::ptr::null_mut(), 0);
    if overflow || !zone_deserialize(s, got) {
        log_info(
            s,
            b"[dns] zone: committed generation rejected, starting empty",
        );
        return;
    }
    log_info(s, b"[dns] zone: recovered committed generation");
}

// ============================================================================
// Dynamic update: transaction cache and the request handler
// ============================================================================

/// A retained response for the same key and request MAC.
unsafe fn txn_lookup(
    s: &DnsState,
    key_idx: usize,
    mac: &[u8; TSIG_MAC_LEN],
    now_ms: u32,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TXN_CACHE {
        let e = &*s.txn_cache.as_ptr().add(i);
        if e.live != 0
            && e.key_idx as usize == key_idx
            && now_ms.wrapping_sub(e.stored_ms) < TXN_RETAIN_MS
            && e.mac == *mac
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Retain a response, displacing the oldest entry.
unsafe fn txn_store(
    s: &mut DnsState,
    key_idx: usize,
    mac: &[u8; TSIG_MAC_LEN],
    reply: *const u8,
    reply_len: usize,
    now_ms: u32,
) {
    let mut victim = 0usize;
    let mut oldest_age = 0u32;
    let mut i = 0;
    while i < MAX_TXN_CACHE {
        let e = &*s.txn_cache.as_ptr().add(i);
        if e.live == 0 {
            victim = i;
            break;
        }
        let age = now_ms.wrapping_sub(e.stored_ms);
        if age >= oldest_age {
            oldest_age = age;
            victim = i;
        }
        i += 1;
    }
    let e = &mut *s.txn_cache.as_mut_ptr().add(victim);
    e.live = 1;
    e.key_idx = key_idx as u8;
    e.stored_ms = now_ms;
    e.mac = *mac;
    copy_bytes(e.reply.as_mut_ptr(), reply, reply_len);
    e.reply_len = reply_len as u16;
}

/// Header plus the echoed zone section for an UPDATE response.
unsafe fn begin_update_response(
    pkt: *const u8,
    question_end: usize,
    rcode: u16,
    tx: *mut u8,
) -> usize {
    if !(DNS_HEADER_LEN + 5..=DNS_MAX_PACKET).contains(&question_end) {
        return 0;
    }
    copy_bytes(tx, pkt, question_end);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    put_u16(tx.add(2), FLAG_QR | (flags & FLAG_OPCODE_MASK) | rcode);
    put_u16(tx.add(4), 1);
    put_u16(tx.add(6), 0);
    put_u16(tx.add(8), 0);
    put_u16(tx.add(10), 0);
    question_end
}

/// Process an UPDATE (opcode 5). The order is RFC 2136 §3 with RFC 8945
/// authentication first: TSIG, zone section, prerequisites, permissions and
/// prescan, apply into the candidate, commit, publish, sign the response.
#[allow(
    clippy::too_many_arguments,
    reason = "the client endpoint and the parsed zone section are passed as their fields"
)]
unsafe fn handle_update(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    pkt_len: usize,
    question_end: usize,
    zone_name: *const u8,
    zone_len: usize,
    zone_qtype: u16,
    zone_qclass: u16,
) {
    let state = s as *mut DnsState;
    let tx = s.tx_buf.as_mut_ptr();
    if s.update_enabled == 0 || pkt_len > DNS_MAX_PACKET {
        let n = begin_update_response(pkt, question_end, RCODE_REFUSED, tx);
        if n > 0 {
            send_server_reply(state, client_ip, client_port, tx as *const u8, n);
        }
        return;
    }
    let now_ms = dev_millis(s.sys()) as u32;
    let now_secs = trusted_now_secs(s.sys());
    let mut info = TsigInfo {
        tsig_off: 0,
        key_idx: 0,
        time_signed: 0,
        fudge: 0,
        orig_id: 0,
        mac: [0; TSIG_MAC_LEN],
    };
    let verdict = verify_tsig(s, pkt, pkt_len, question_end, &mut info, now_secs);
    match verdict {
        TsigVerdict::Absent | TsigVerdict::Malformed => {
            let rcode = if verdict == TsigVerdict::Absent {
                RCODE_REFUSED
            } else {
                RCODE_FORMERR
            };
            let n = begin_update_response(pkt, question_end, rcode, tx);
            if n > 0 {
                send_server_reply(state, client_ip, client_port, tx as *const u8, n);
            }
            return;
        }
        TsigVerdict::BadKey | TsigVerdict::BadSig => {
            // Unsigned NOTAUTH with the TSIG error (RFC 8945 §5.3.2). The
            // key name comes from the request when the key is unknown, so
            // the record is appended only when an admitted key was named.
            let n = begin_update_response(pkt, question_end, RCODE_NOTAUTH, tx);
            if n == 0 {
                return;
            }
            let err = if verdict == TsigVerdict::BadKey {
                TSIG_ERR_BADKEY
            } else {
                TSIG_ERR_BADSIG
            };
            let mut len = n;
            if find_key_named_in_request(s, pkt, pkt_len, &info).is_some() {
                let m = append_tsig(
                    s,
                    info.key_idx,
                    false,
                    &info.mac,
                    info.time_signed,
                    info.fudge,
                    err,
                    &[],
                    tx,
                    n,
                );
                if m > 0 {
                    len = m;
                }
            }
            send_server_reply(state, client_ip, client_port, tx as *const u8, len);
            return;
        }
        TsigVerdict::BadTime => {
            // Signed NOTAUTH carrying the server's time (RFC 8945 §5.2.3).
            let n = begin_update_response(pkt, question_end, RCODE_NOTAUTH, tx);
            if n == 0 {
                return;
            }
            let t = now_secs.to_be_bytes();
            let mut other = [0u8; 6];
            copy_bytes(other.as_mut_ptr(), t.as_ptr().add(2), 6);
            let len = append_tsig(
                s,
                info.key_idx,
                true,
                &info.mac,
                info.time_signed,
                info.fudge,
                TSIG_ERR_BADTIME,
                &other,
                tx,
                n,
            );
            if len > 0 {
                send_server_reply(state, client_ip, client_port, tx as *const u8, len);
            }
            return;
        }
        TsigVerdict::Ok => {}
    }

    // A retried transaction is answered as it was, without re-evaluating
    // anything.
    if let Some(i) = txn_lookup(s, info.key_idx, &info.mac, now_ms) {
        let e = &*s.txn_cache.as_ptr().add(i);
        let len = e.reply_len as usize;
        copy_bytes(tx, e.reply.as_ptr(), len);
        send_server_reply(state, client_ip, client_port, tx as *const u8, len);
        return;
    }

    let rcode = evaluate_update(
        s,
        &info,
        pkt,
        question_end,
        zone_name,
        zone_len,
        zone_qtype,
        zone_qclass,
    );
    let n = begin_update_response(pkt, question_end, rcode, tx);
    if n == 0 {
        return;
    }
    let len = append_tsig(
        s,
        info.key_idx,
        true,
        &info.mac,
        info.time_signed,
        info.fudge,
        0,
        &[],
        tx,
        n,
    );
    if len == 0 {
        return;
    }
    txn_store(s, info.key_idx, &info.mac, tx as *const u8, len, now_ms);
    send_server_reply(state, client_ip, client_port, tx as *const u8, len);
}

/// Whether the request's TSIG names an admitted key (with or without a
/// vault handle), so an error response can be addressed to it.
unsafe fn find_key_named_in_request(
    s: &DnsState,
    pkt: *const u8,
    pkt_len: usize,
    info: &TsigInfo,
) -> Option<usize> {
    if info.tsig_off == 0 {
        return None;
    }
    let mut owner = [0u8; MAX_NAME_LEN + 1];
    let rr = parse_rr(pkt, pkt_len, info.tsig_off, owner.as_mut_ptr())?;
    find_key(s, owner.as_ptr(), rr.owner_len)
}

/// Zone section, prerequisites, update section, commit, publish. Returns
/// the rcode; the current generation changes only on NOERROR.
#[allow(
    clippy::too_many_arguments,
    reason = "the parsed zone section is passed as its fields"
)]
unsafe fn evaluate_update(
    s: &mut DnsState,
    info: &TsigInfo,
    pkt: *const u8,
    question_end: usize,
    zone_name: *const u8,
    zone_len: usize,
    zone_qtype: u16,
    zone_qclass: u16,
) -> u16 {
    // The signed message ends where the TSIG record starts.
    let msg_len = info.tsig_off;
    if zone_qtype != QTYPE_SOA || zone_qclass != QCLASS_IN {
        return RCODE_FORMERR;
    }
    if !names_equal(
        zone_name,
        zone_len,
        s.update_zone.as_ptr(),
        s.update_zone_len as usize,
    ) {
        return RCODE_NOTAUTH;
    }
    let prcount = u16::from_be_bytes([*pkt.add(6), *pkt.add(7)]) as usize;
    let upcount = u16::from_be_bytes([*pkt.add(8), *pkt.add(9)]) as usize;
    if prcount > MAX_UPDATE_RRS || upcount > MAX_UPDATE_RRS {
        return RCODE_REFUSED;
    }
    if s.update_durability == DURABILITY_DURABLE && s.durable_ready != 1 {
        return RCODE_SERVFAIL;
    }
    let after_pr = match check_prerequisites(s, pkt, msg_len, question_end, prcount) {
        Ok(p) => p,
        Err(rc) => return rc,
    };
    s.candidate = s.zone;
    if let Err(rc) = apply_update_section(s, info.key_idx, pkt, msg_len, after_pr, upcount) {
        return rc;
    }
    s.candidate.generation = s.zone.generation.wrapping_add(1);
    if s.update_durability == DURABILITY_DURABLE && !zone_commit_durable(s) {
        log_info(s, b"[dns] zone: commit refused, generation unchanged");
        return RCODE_SERVFAIL;
    }
    s.zone = s.candidate;
    RCODE_NOERROR
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DnsState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<DnsState>() {
            return -6;
        }

        let s = &mut *(state as *mut DnsState);
        s.init(syscalls as *const SyscallTable);

        // Net channels: in[0] = net_in (from IP), out[0] = net_out (to IP)
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        // Parse TLV params
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Resolve the target-tier head-sampling default only when the
        // `trace_sample_permille` param was not explicitly supplied (still the
        // `0xFFFF` sentinel): aarch64 (pi5-class) 50‰, MCUs 0‰. An explicit
        // value (including 0) is honoured as-is.
        if s.sample_permille == 0xFFFF {
            #[cfg(target_arch = "aarch64")]
            {
                s.sample_permille = 50;
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                s.sample_permille = 0;
            }
        }

        if s.dns64_bad != 0 {
            log_info(
                s,
                b"[dns] refusing to construct: dns64_prefix is not a /96 prefix",
            );
            return -1;
        }
        if s.dns64_enabled != 0 {
            log_info(s, b"[dns] dns64: /96 synthesis on, non-validating profile (DO/CD forwarded unchanged)");
        }
        if s.update_enabled != 0 {
            match s.update_durability {
                DURABILITY_VOLATILE => {
                    log_info(
                        s,
                        b"[dns] update zone: volatile, the zone is lost on restart",
                    );
                }
                DURABILITY_DURABLE => {
                    if s.update_path_len == 0 {
                        let path = b"dns_zone.fxz";
                        parse_update_path(s, path.as_ptr(), path.len());
                    }
                    log_info(
                        s,
                        b"[dns] update zone: durable, generations committed through fs",
                    );
                }
                _ => {
                    log_info(s, b"[dns] refusing to construct: update_zone needs update_durability = volatile | durable");
                    return -1;
                }
            }
            if s.key_count == 0 {
                log_info(
                    s,
                    b"[dns] update zone: no update_allow key, every UPDATE is refused",
                );
            }
            open_tsig_keys(s);
        } else if s.update_durability != DURABILITY_UNSET || s.key_count != 0 {
            log_info(
                s,
                b"[dns] refusing to construct: update_durability / update_allow need update_zone",
            );
            return -1;
        }

        log_info(s, b"[dns] init");

        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut DnsState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Module-scope metrics: cumulative byte counters, ~5s cadence, no-op
        // when the telemetry port is unwired.
        maybe_emit_telemetry(s);

        // Durable mode serves updates only once the storage provider has
        // answered for its write tier and the committed generation is loaded.
        if s.update_enabled != 0
            && s.update_durability == DURABILITY_DURABLE
            && s.durable_ready == 0
        {
            match zone_storage_ready(s) {
                Some(true) => {
                    zone_recover(s);
                    s.durable_ready = 1;
                }
                Some(false) => {
                    log_info(
                        s,
                        b"[dns] zone: storage lacks the write tier, durable updates refused",
                    );
                    // Asked again each step; the answer is per provider and
                    // does not change, so the log line is the once-only cost.
                    s.durable_ready = 2;
                }
                None => {}
            }
        }

        // Drive the two binds sequentially — server on `listen_port`, then the
        // ephemeral upstream once the server is up — so each MSG_DG_BOUND routes
        // to the single endpoint in WaitBound. The shared `datagram_endpoint`
        // core owns the bind handshake (with backoff) and the addressed send;
        // `dg_recv` classifies one inbound frame per step.
        let sys = &*s.syscalls;
        let net_out = s.net_out_chan;
        let net_in = s.net_in_chan;
        let buf = s.net_buf.as_mut_ptr();

        s.server_ep
            .poll_bind(sys, net_out, s.listen_port, buf, NET_BUF_SIZE);
        if s.server_ep.is_ready() {
            s.upstream_ep.poll_bind(sys, net_out, 0, buf, NET_BUF_SIZE);
        }

        let mut did_work = false;
        if let Some(ev) = dg_recv(sys, net_in, buf, NET_BUF_SIZE) {
            match ev {
                DgEvent::Bound { ep_id, .. } => {
                    // Sequential binds: exactly one endpoint is in WaitBound, so
                    // the completion routes unambiguously.
                    s.server_ep.on_bound(ep_id);
                    s.upstream_ep.on_bound(ep_id);
                    if s.server_ep.owns(ep_id) {
                        log_info(s, b"[dns] server bound");
                    } else if s.upstream_ep.owns(ep_id) {
                        log_info(s, b"[dns] serving");
                    }
                    did_work = true;
                }
                DgEvent::Rx {
                    ep_id,
                    src_ip,
                    src_port,
                    data,
                    len,
                } => {
                    if len >= DNS_HEADER_LEN {
                        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(len as u32);
                        if s.server_ep.owns(ep_id) {
                            handle_query(s, src_ip, src_port, data, len);
                        } else if s.upstream_ep.owns(ep_id) {
                            handle_upstream_response(s, src_ip, src_port, data, len);
                        }
                        did_work = true;
                    }
                }
                DgEvent::Err { .. } => {
                    // Bind failure — the endpoint in WaitBound backs off + retries.
                    s.server_ep.on_error(sys);
                    s.upstream_ep.on_error(sys);
                }
                DgEvent::Closed { .. } => {}
            }
        }

        // Expire old pending queries periodically.
        expire_pending(s);

        if did_work {
            2
        } else {
            0
        } // burst when work happened, else continue
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
