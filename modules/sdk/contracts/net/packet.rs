// Contract: packet — packet protocol surface.
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Packet Surface.
//
// The packet surface is a channel contract for flows that need
// packet-preserving behaviour and richer ingress metadata than the
// datagram surface exposes. Intended consumers: QUIC engines, DTLS /
// SRTP packet processors, packet policy modules, packet classifiers,
// direct NIC fast paths, market-data and control-plane packet flows.
//
// Two verb families share the surface. The endpoint verbs (bind, tx, rx,
// close) are an envelope no module in this tree provides or consumes. The
// decision-seam verbs below them are provided by `modules/foundation/ip`: a
// director settles every inbound packet before transport state exists for
// it.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto and datagram so the shared SDK helpers
// (net_read_frame, net_write_frame) work unchanged. Opcode ranges are
// disjoint from net_proto (0x01..0x1F) and datagram (0x20..0x4F) so
// misconfigured channels fail loudly.
//
// Relationship to datagram: the packet surface subsumes the datagram
// envelope and adds ingress/egress metadata (timestamp, lane, ECN/DSCP,
// offload status, flow hint). A module that only cares about payload
// bytes and src/dst should use datagram instead; the packet surface is
// for modules that want to see ingress side-information.
//
// Address families and byte order match datagram exactly.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Address family: IPv4 (4-byte address, big-endian).
pub const AF_INET: u8 = 4;
/// Address family: IPv6 (16-byte address, big-endian).
pub const AF_INET6: u8 = 6;

// ─── RX flags (provider → consumer, MSG_PKT_RX) ────────────────────

/// The ingress packet had ECN codepoint CE (congestion experienced).
pub const RX_FLAG_ECN_CE: u8 = 1 << 0;
/// Hardware or driver verified the L4 checksum as correct.
pub const RX_FLAG_CSUM_OK: u8 = 1 << 1;
/// The `flow_hint` field is meaningful (non-zero is not sufficient by itself
/// — some providers may supply `flow_hint = 0` legitimately).
pub const RX_FLAG_HAS_FLOW_HINT: u8 = 1 << 2;
/// The `ts_us` field is meaningful. If clear, `ts_us` is provider-synthesised
/// and may be approximate.
pub const RX_FLAG_HAS_TIMESTAMP: u8 = 1 << 3;
/// Packet arrived via a fast path (e.g. mailbox edge, zero-copy NIC ring).
pub const RX_FLAG_FAST_PATH: u8 = 1 << 4;

// ─── TX flags (consumer → provider, CMD_PKT_TX) ────────────────────

/// Request ECN-capable transmit (set ECT(0) or ECT(1) per policy).
pub const TX_FLAG_ECN_CAPABLE: u8 = 1 << 0;
/// Skip L4 checksum offload hint (checksum is already in the payload).
pub const TX_FLAG_NO_CSUM: u8 = 1 << 1;
/// Urgent: bypass egress pacing queues if supported.
pub const TX_FLAG_URGENT: u8 = 1 << 2;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Bind a new packet endpoint to a local port.
/// Payload: [port: u16 LE] [flags: u8].
/// Port 0 requests ephemeral allocation. Provider responds with
/// MSG_PKT_BOUND carrying the allocated ep_id and local_port.
pub const CMD_PKT_BIND: u8 = 0x50;

/// Send a packet from `ep_id` to the given destination.
///
/// IPv4 payload:
///   [ep_id: u8] [af: u8 = 4] [dst_addr: 4 bytes BE] [dst_port: u16 LE]
///   [lane_hint: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// IPv6 payload:
///   [ep_id: u8] [af: u8 = 6] [dst_addr: 16 bytes BE] [dst_port: u16 LE]
///   [lane_hint: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// On TX, `ts_us` is a caller-supplied desired transmit timestamp (0 = send
/// now). `lane_hint = 0` means the provider chooses.
pub const CMD_PKT_TX: u8 = 0x51;

/// Close an endpoint and release its resources.
/// Payload: [ep_id: u8].
pub const CMD_PKT_CLOSE: u8 = 0x52;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Bind completed. Payload: [ep_id: u8] [local_port: u16 LE].
pub const MSG_PKT_BOUND: u8 = 0x60;

/// Received packet with full ingress metadata.
///
/// IPv4 payload:
///   [ep_id: u8] [af: u8 = 4] [src_addr: 4 bytes BE] [src_port: u16 LE]
///   [lane: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// IPv6 payload:
///   [ep_id: u8] [af: u8 = 6] [src_addr: 16 bytes BE] [src_port: u16 LE]
///   [lane: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// `ts_us` is monotonic microseconds at ingress (from `TIMER_MICROS`) when
/// `RX_FLAG_HAS_TIMESTAMP` is set; approximate otherwise.
pub const MSG_PKT_RX: u8 = 0x61;

/// Endpoint closed. Payload: [ep_id: u8].
pub const MSG_PKT_CLOSED: u8 = 0x62;

/// Endpoint error. Payload: [ep_id: u8] [errno: i8].
pub const MSG_PKT_ERROR: u8 = 0x63;

// ─── Pre-transport decision seam ───────────────────────────────────
//
// A second use of this surface, alongside the endpoint verbs above: the
// `ip` module, with `packet_decision = "pre_transport"`, parses and
// validates every inbound IPv4 packet (and, with `seam_v6`, every IPv6
// packet to the addresses it names) ONCE and — before any connection
// state is created — hands a director the headers and holds the buffer
// until exactly one disposition comes back. Ownership follows the
// disposition: LOCAL resumes the ordinary transport path, DROP and REJECT
// release the buffer here, TUNNEL and DSR hand the whole frame to the
// director's forward port. A packet held past the configured deadline is
// released and reported. Nothing about tables, affinity or policy crosses
// this seam; those are the director's.
//
// Three ports carry it: decision records out, dispositions in, forwarded
// frames out. `pkt_id` is `[slot][generation]`, split by [`PKT_SLOT_BITS`]
// — a slot index needs only as many bits as there are slots, and the rest
// go to the generation, which is what makes a disposition naming a reused
// slot fail to match. A disposition for a packet already released — or for
// a reused slot — is refused as stale rather than acted on.
//
// A director never has to take a `pkt_id` apart: it echoes the value back.
// The split is declared here anyway, once, with accessors, because the
// provider and its tests do take it apart, and a reader that counts bits
// out of somebody else's field is invisible to both review and the
// compiler — a split that moves breaks it silently, and the failure
// surfaces as a wrong answer rather than a parse error.

/// Consumer → provider: settle one held packet. Payload:
/// `[pkt_id: u32 LE] [disposition: u8] [args...]` — see `DISP_*` for the
/// argument bytes each disposition carries. A second disposition for the
/// same `pkt_id` is a stale reference and is ignored.
pub const CMD_PKT_DISPOSE: u8 = 0x53;

/// Consumer → provider: hold a second copy of a held packet under a new
/// `pkt_id`, so one copy can be forwarded and the other delivered or
/// mirrored. Payload: `[pkt_id: u32 LE]`. Answered by `MSG_PKT_CLONED`.
pub const CMD_PKT_CLONE: u8 = 0x54;

/// Provider → consumer: a packet awaits disposition. Payload
/// (`DECIDE_LEN` bytes):
///
/// ```text
/// [pkt_id: u32 LE] [af: u8] [proto: u8]
/// [src_addr: 4 BE] [dst_addr: 4 BE] [src_port: u16 LE] [dst_port: u16 LE]
/// [iface: u8] [rx_queue: u8] [flags: u8] [frag: u8]
/// [ts_us: u64 LE] [frame_len: u16 LE] [l4_off: u16 LE]
/// ```
///
/// `flags` are the `RX_FLAG_*` bits; `RX_FLAG_CSUM_OK` is set only after
/// the provider verified the L4 checksum, so a director never re-parses.
/// Ports are 0 for a protocol that has none. `frag` is 0: the provider
/// refuses fragments before the seam and counts them. `l4_off` is the
/// transport header's offset from the frame start.
pub const MSG_PKT_DECIDE: u8 = 0x64;

/// Provider → consumer, on the forward port: a packet disposed TUNNEL,
/// DSR or CHAIN, or a MIRROR's copy, whole. Payload: `[pkt_id: u32 LE]
/// [disposition: u8] [args: 6] [frame...]` — the disposition and its
/// argument bytes exactly as the consumer wrote them (for a `COPY`
/// disposition, one record of the base and one of `MIRROR`, each with its
/// own block), then the Ethernet frame. The buffer is the consumer's from
/// here on.
pub const MSG_PKT_FORWARD: u8 = 0x65;

/// Provider → consumer: answer to `CMD_PKT_CLONE`. Payload:
/// `[pkt_id: u32 LE] [clone_id: u32 LE]`, `clone_id = PKT_ID_NONE` when
/// no hold slot was free.
pub const MSG_PKT_CLONED: u8 = 0x66;

/// Provider → consumer: a held packet reached its hold deadline with no
/// disposition and was released. Payload: `[pkt_id: u32 LE]`.
pub const MSG_PKT_EXPIRED: u8 = 0x67;

/// Provider → consumer: the copy a `MIRROR` disposition asked for was not
/// made — the mirror budget was spent, or the forward port was unwired or
/// full — and the original went its way alone. Payload:
/// `[pkt_id: u32 LE] [lost_total: u32 LE]`, the second the provider's
/// running count of copies lost, so a consumer that misses a report still
/// sees how many it missed. A mirror never holds or delays the original.
pub const MSG_PKT_MIRROR_LOST: u8 = 0x68;

/// `MSG_PKT_MIRROR_LOST` payload length.
pub const MIRROR_LOST_LEN: usize = 8;

/// Provider → consumer: an IPv6 packet awaits disposition. Payload
/// (`DECIDE6_LEN` bytes), `MSG_PKT_DECIDE`'s fields with the addresses
/// sixteen bytes wide:
///
/// ```text
/// [pkt_id: u32 LE] [af: u8 = 6] [proto: u8]
/// [src_addr: 16 BE] [dst_addr: 16 BE] [src_port: u16 LE] [dst_port: u16 LE]
/// [iface: u8] [rx_queue: u8] [flags: u8] [frag: u8]
/// [ts_us: u64 LE] [frame_len: u16 LE] [l4_off: u16 LE]
/// ```
///
/// A separate message rather than a longer `MSG_PKT_DECIDE`, so a director
/// that reads only IPv4 records is unaffected: a provider sends it only
/// when IPv6 is on at its seam (`ip`'s `seam_v6`). `proto` is the IPv6 next
/// header, which is the transport — a packet with extension headers is
/// refused before the seam, as a fragment is. The IPv6 header starts at
/// `l4_off - 40`. `LOCAL` and `MIRROR` deliver to the provider's local
/// transport: `ip` delivers TCP and UDP to an IPv6 address it terminates
/// (`seam_v6`'s are) on a build with its IPv6 transport (the aarch64
/// profile), and releases any other such packet counted (`v6_no_local`).
pub const MSG_PKT_DECIDE6: u8 = 0x69;

/// Length of a `MSG_PKT_DECIDE6` payload.
pub const DECIDE6_LEN: usize = 4 + 1 + 1 + 16 + 16 + 2 + 2 + 1 + 1 + 1 + 1 + 8 + 2 + 2;

/// Length of a `MSG_PKT_DECIDE` payload.
pub const DECIDE_LEN: usize = 4 + 1 + 1 + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 8 + 2 + 2;

/// Length of the argument block following a disposition byte. Every
/// disposition carries exactly this many bytes, unused ones zero, so the
/// forward record has one shape.
pub const DISP_ARGS_LEN: usize = 6;

/// The `pkt_id` that names no packet.
pub const PKT_ID_NONE: u32 = u32::MAX;

/// Low bits of a `pkt_id` holding the hold-slot index; the rest are the
/// generation. Eight is comfortably above any profile's hold depth, and
/// every bit not spent on the slot buys time before the generation wraps
/// — wrap being the one way a `pkt_id` held long enough could name a slot
/// that has since been reused.
pub const PKT_SLOT_BITS: u32 = 8;

/// Generation values before the counter repeats one for a given slot.
pub const PKT_GEN_MODULUS: u32 = 1 << (32 - PKT_SLOT_BITS);

/// The hold slot a `pkt_id` names.
#[inline]
#[must_use]
pub fn pkt_slot(id: u32) -> usize {
    (id & ((1 << PKT_SLOT_BITS) - 1)) as usize
}

/// The generation a `pkt_id` names.
#[inline]
#[must_use]
pub fn pkt_generation(id: u32) -> u32 {
    id >> PKT_SLOT_BITS
}

/// The `pkt_id` naming `slot` under `generation`.
#[inline]
#[must_use]
pub fn pkt_id(slot: usize, generation: u32) -> u32 {
    (slot as u32) | (generation << PKT_SLOT_BITS)
}

/// Dispositions, and the argument bytes each carries.
pub mod disposition {
    /// Deliver to the local transport. No arguments.
    pub const LOCAL: u8 = 0;
    /// Release silently. `[reason: u8]`.
    pub const DROP: u8 = 1;
    /// Release and answer the sender. `[reason: u8] [response: u8]` — see
    /// `reject`.
    pub const REJECT: u8 = 2;
    /// Hand the frame to the forward port for an attachment.
    /// `[attach_id: u16 LE] [flow_epoch: u32 LE]`.
    pub const TUNNEL: u8 = 3;
    /// Hand the frame to the forward port for direct return.
    /// `[endpoint_id: u16 LE] [rewrite_id: u16 LE]`.
    pub const DSR: u8 = 4;
    /// Deliver to the local transport AND hand a copy to the forward port,
    /// within the provider's mirror budget (copies per second, its
    /// `packet_mirror_budget`). `[mirror_id: u16 LE] [flow_epoch: u32 LE]`,
    /// echoed in the copy's forward record. A copy the budget or the
    /// forward port cannot take is lost, counted and reported
    /// (`MSG_PKT_MIRROR_LOST`); the original is delivered either way.
    pub const MIRROR: u8 = 5;
    /// Hand the frame to the forward port for the next stage of a service
    /// chain. `[chain_id: u16 LE] [stage: u8] [flags: u8] [instance: u16
    /// LE]` — the chain encapsulation (`cores/chain_encap.rs`) is the
    /// consumer's to write; the seam only settles the packet's owner.
    pub const CHAIN: u8 = 6;

    /// Forward-and-copy: OR'd into `TUNNEL`, `DSR` or `CHAIN`, the
    /// disposition carries a second argument block, a `MIRROR`'s
    /// `[mirror_id: u16 LE] [flow_epoch: u32 LE]` —
    /// `[pkt_id][disposition | COPY][args: 6][mirror args: 6]`. The frame
    /// goes to the forward port as the base disposition says (its record
    /// names the base disposition, the flag clear), and one copy goes there
    /// too as a record naming `MIRROR` and the mirror arguments, within the
    /// same `packet_mirror_budget` a `MIRROR` spends. As with a `MIRROR`, a
    /// copy the budget or the port cannot take is lost, counted and reported
    /// (`MSG_PKT_MIRROR_LOST`), never held for and never holding the
    /// original back — so a copy can precede an original the port could not
    /// yet take. This is how a director mirrors a tunnelled, direct-return
    /// or chained flow, where `MIRROR` would deliver it locally.
    pub const COPY: u8 = 0x80;

    /// The base dispositions `COPY` may be OR'd into.
    pub const fn copy_allowed(base: u8) -> bool {
        matches!(base, TUNNEL | DSR | CHAIN)
    }
}

/// Length of a `CMD_PKT_DISPOSE` payload carrying `disposition::COPY`.
pub const DISPOSE_COPY_LEN: usize = 4 + 1 + DISP_ARGS_LEN + DISP_ARGS_LEN;

/// `REJECT` response kinds.
pub mod reject {
    /// No response on the wire.
    pub const SILENT: u8 = 0;
    /// A TCP RST acknowledging the offending segment (TCP only; a segment
    /// that is itself an RST gets no answer).
    pub const TCP_RST: u8 = 1;
    /// ICMP destination unreachable, port unreachable.
    pub const ICMP_UNREACHABLE: u8 = 2;
}

// ─── Payload layout helpers ────────────────────────────────────────

/// Size of the metadata block that follows the address fields in both
/// CMD_PKT_TX and MSG_PKT_RX: `[lane:1][flags:1][dscp:1][ts_us:8 LE][flow_hint:4 LE]`.
pub const META_BLOCK: usize = 1 + 1 + 1 + 8 + 4;

/// Byte offset of the first packet byte in a CMD_PKT_TX / MSG_PKT_RX payload
/// when the address family is IPv4. Layout:
/// `[ep_id:1][af:1][addr:4][port:2][lane:1][flags:1][dscp:1][ts_us:8][flow_hint:4]`.
pub const V4_META_PREFIX: usize = 1 + 1 + 4 + 2 + META_BLOCK;

/// Byte offset of the first packet byte in a CMD_PKT_TX / MSG_PKT_RX payload
/// when the address family is IPv6.
pub const V6_META_PREFIX: usize = 1 + 1 + 16 + 2 + META_BLOCK;
