// Contract: identity — Net-Identity Address-Control.
//
// Layer: contracts/net (public, stable).
//
// The control-plane contract by which a workload's network identity (a
// secondary local address) and its name-service context are installed on the
// node's **net-identity provider** — the module that owns the node's IP stack
// (`ip` on bare metal, the host net provider on Linux). The provider exposes a
// single-writer control input port (`addr_ctl`) and an event output
// (`addr_evt`); both are ordinary wired edges. On a node that admits
// workloads the writer is the **workload creator** (the node agent): after
// `CREATE` it writes the workload's `ADDR_ADD` (and `OWNER_RESOLVER`), waits
// for `MSG_ADDR_ADDED` before `START`, and writes `ADDR_DEL` when it destroys
// the workload. A coordinator that moves service addresses (a VIP
// controller) is the writer on a node with no workload creator.
//
// A workload's address is its owner's, by owner slot AND generation, and no
// longer than the owner lives: when the kernel frees the owner (its lanes
// detach, or its host process ends) the provider releases every address it
// holds, `ADDR_DEL` or not, and an install naming a generation the slot no
// longer holds is refused (`refusal::OWNER`). A later owner of the slot
// never inherits an address of an earlier one.
//
// An `ADDR_ADD` of an address the same owner already holds is answered
// `MSG_ADDR_ADDED` again (a writer re-issuing after its own restart); one that
// would move an address another owner holds is refused, unless the writer
// names the node (owner tag 0).
//
// ─── Framing ────────────────────────────────────────────────────────
//
// Frames use the same `[msg_type: u8] [len: u16 LE] [payload...]` TLV header as
// net_proto / datagram / packet / session_ctrl, so the shared SDK framing
// helpers (`net_read_frame` / `net_write_frame`) work unchanged.
//
// These opcodes ride a single-writer control port (`addr_ctl`), and
// the ABI registry's `net_tlv` msgset (`abi/registry.toml`) gives every
// message type of every surface sharing this header a distinct value,
// so a mis-wire cannot misparse.

/// Frame header size (`msg_type` + `len`), identical to the other net contracts.
pub const FRAME_HDR: usize = 3;

// ─── Opcodes (writer → provider, over `addr_ctl`) ───────────────────

/// Install a workload's secondary local address.
/// Payload: `[addr: 16][prefix_len: 1][owner_tag: 2 LE]`, then optionally
/// `[flags: u8]` ([`install`]), after the flags `[segment: u16 LE]`, and
/// after the segment `[owner_gen: u32 LE]` (`addr` is a 16-byte address slot,
/// IPv4 in bytes 0..4 in network order — the provider's `LocalAddr` layout, so
/// it copies in with no re-order; `owner_tag` is the workload's owner slot
/// and `owner_gen` that owner's generation, which an install naming a
/// workload owner (`owner_tag != 0`) must carry, or it is refused
/// `refusal::OWNER`; `segment` ≥ 1 names the `net.route` segment the address
/// joins, which must exist and hold it — otherwise the install is refused
/// `refusal::SEGMENT` — and 0 or absent joins none).
pub use super::super::super::registry::msg::identity::ADDR_ADD;

/// A workload owner's name-service context: the resolver its lanes' name
/// queries go to, and its search list. Payload:
/// `[owner_slot: u16 LE][owner_gen: u32 LE][family: u8][server: 16]
/// [n_search: u8]([len: u8][name])×n_search`. `family` 0 clears the
/// owner's context (its queries go to the node's own upstream). Not
/// answered; the provider keeps it until the owner's lanes detach. A writer
/// sends it before `START`, with the `ADDR_ADD`, and again after its own
/// restart (the same context again changes nothing).
pub use super::super::super::registry::msg::identity::OWNER_RESOLVER;

/// Remove a workload's secondary local address.
/// Payload: `[addr: 16]`.
pub use super::super::super::registry::msg::identity::ADDR_DEL;

// ─── Emission control ───────────────────────────────────────────────
//
// An installed address has an EMISSION state: armed, and the provider
// sources frames from it and answers ARP for it; or fenced, and it does
// neither. Every install mints an emission token — 16 bytes from the
// kernel CSPRNG mixed with the boot incarnation, so a token from a
// previous install or a previous boot cannot match — and returns it on the
// provider's `addr_evt` port. Arming and fencing present that token, which
// is what stops a coordinator from a previous life of the address, or of
// the host, from re-enabling emission it no longer owns.
//
// `ADDR_ADD` installs ARMED unless `INSTALL_DISARMED` is set in the
// optional trailing flags byte; a writer that does not send the byte gets
// the behaviour it always had. A standby that must not speak until told
// installs disarmed and is armed by the coordinator.

/// Arm emission from an installed address.
/// Payload: `[addr: 16][token: 16]`. Answered by `MSG_ADDR_ARMED` or
/// `MSG_ADDR_REFUSED`; a gratuitous ARP announces the address on arming.
pub use super::super::super::registry::msg::identity::ADDR_ARM;

/// Fence an installed address: no frame sourced from it enters the driver
/// ring after the answer, and ARP for it is not answered. Payload:
/// `[addr: 16][token: 16]`. Answered by `MSG_ADDR_FENCED`, which carries
/// the cutoff boundary, or `MSG_ADDR_REFUSED`. The primary address cannot
/// be fenced.
pub use super::super::super::registry::msg::identity::ADDR_FENCE;

// ─── Two providers, one surface ─────────────────────────────────────
//
// `fence.enforceable` is answered on this port pair by two kinds of
// provider, and a continuity declaration needs both
// (`protocol_surfaces.md` §transport_migratable):
//
//   * the **net-identity provider** (`ip`), whose fence closes its own
//     emission gate — a cutoff at the ring hand-off, or at the wire where
//     the NIC driver drains on request. It proves what this host has
//     stopped sending. It cannot prove anything about a host that has
//     failed, because it is that host.
//
//   * an **out-of-band fence agent**, a member of the graph composed from
//     another node (`modules[].node`), whose fence cuts the whole failure
//     domain from outside — power, or the fabric port. It answers the same
//     verbs with these meanings:
//
//       `ADDR_ADD`     take custody of the host that owns `addr`, which
//                      is the only field of the payload an agent reads —
//                      it binds an actuator to a host, not a route, so
//                      `prefix_len` and `owner_tag` carry nothing here.
//                      The token minted on `MSG_ADDR_ADDED` is fresh per
//                      custody and per boot of the agent, as it is for an
//                      install, and re-taking custody of a held host mints
//                      a new one: a coordinator that has taken over cannot
//                      be fenced by its predecessor's token.
//       `ADDR_FENCE`   cut. The agent drives its actuator and answers
//                      `MSG_ADDR_FENCED` only after the actuator confirmed
//                      the cut AND the domain's hold-up time has passed —
//                      never on dispatch, and never on the actuator's
//                      word alone: a host runs on for what its supply
//                      holds after the relay opens, and a coordinator
//                      that activated on the relay's word would be
//                      activating against a host still on the wire.
//                      `cutoff_kind` is
//                      `cutoff::WIRE`: a host with no power puts nothing on
//                      the wire. `cutoff` is the agent's own fence count,
//                      monotonic for the agent's life, and `generation` is
//                      the custody generation — the `fence_gen` a failover
//                      coordinator carries on `CMD_SC_ACTIVATE`. An
//                      actuator that does not confirm is refused
//                      `refusal::ACTUATOR`, and the coordinator must not
//                      activate.
//       `ADDR_ARM`     restore (power the host back on), or
//                      `refusal::ACTUATOR` when the actuator cannot.
//       `ADDR_DEL`     release custody.
//
//     An agent's actuator names the host it acts on, so one agent holds
//     one host and a deployment that fences several composes one per host;
//     a second address is refused `TABLE_FULL`.
//
//     A fence agent declares `cutoff = "wire"` in its manifest's
//     `[capability_facts."fence.enforceable"]`; the composer admits that
//     fact only from a member placed on another node, because a cutoff
//     claimed from inside the failure domain is not evidence about it.
//
// A failover coordinator therefore holds one `addr_ctl` / `addr_evt` pair
// to each provider: it fences the primary's address on the agent, takes
// the confirmed generation, and only then activates the standby.

/// `ADDR_ADD` flags byte (optional, at `ADD_FLAGS_OFF`).
pub mod install {
    /// Install fenced; `ADDR_ARM` is required before the address emits.
    pub const DISARMED: u8 = 0x01;
    /// The address is IPv6 (all sixteen bytes); without it the first four
    /// bytes are an IPv4 address and the rest zero. An IPv6 address is
    /// armed, fenced and removed by the same verbs; arming announces it with
    /// an unsolicited neighbour advertisement, and only an armed one
    /// answers neighbour solicitation or sources a packet.
    pub const FAMILY6: u8 = 0x02;
}

// ─── Events (provider → writer, over `addr_evt`) ───────────────────

/// An address was installed and its token minted.
/// Payload: `[addr: 16][token: 16][generation: u32 LE]`.
pub use super::super::super::registry::msg::identity::MSG_ADDR_ADDED;

/// Emission is armed. Payload: `[addr: 16][generation: u32 LE]`.
pub use super::super::super::registry::msg::identity::MSG_ADDR_ARMED;

/// Emission is fenced. Payload: `[addr: 16][generation: u32 LE]
/// [cutoff: u64 LE][cutoff_kind: u8][pending_discarded: u8]`. `cutoff` is
/// the provider's own monotonic index for this fence, so two fences of an
/// address are distinguishable and ordered: the ip module counts the
/// frames it has handed over, and nothing sourced from the address is
/// handed over after the index the fence reports; an out-of-band agent
/// counts the cuts it has made. `cutoff_kind` says what the boundary is
/// worth (see `cutoff`); `pending_discarded` is 1 when a frame from the
/// address staged for the ring was discarded rather than sent, and 0 from
/// a provider with no ring to stage into.
pub use super::super::super::registry::msg::identity::MSG_ADDR_FENCED;

/// The longest event payload: `MSG_ADDR_ADDED`'s address, token and
/// generation.
pub const EVENT_PAYLOAD_MAX: usize = 16 + 16 + 4;
/// The largest record on `addr_evt`, header included: what every provider of
/// the events declares as its `max_record` and every consumer accepts.
pub const EVENT_RECORD_MAX: usize = FRAME_HDR + EVENT_PAYLOAD_MAX;

/// An install, arm or fence was refused.
/// Payload: `[addr: 16][op: u8][reason: u8]` — `op` the refused opcode,
/// `reason` per `refusal`.
pub use super::super::super::registry::msg::identity::MSG_ADDR_REFUSED;

/// The transmit-drain query a NIC driver answers on the frame edge the ip
/// module writes: the edge contract `net_tx_drain`, reached by binding the
/// frames output port (`BIND` with `bind::PORT`) and served by the driver at
/// the other end, handed its own frames input port. This is how a fence
/// reaches the wire: after closing its gate the ip module asks the driver
/// whether every frame handed over before the fence has left the NIC.
///
/// `DRAINED` (`registry::net_tx_drain::DRAINED`): `arg` out `[completed u32
/// LE]`. Answer: `0` when the driver holds no unread frame on that edge and
/// every submitted transmit descriptor is reported complete by the hardware,
/// with the driver's completed transmit count in `arg`; `EAGAIN` while either
/// is still pending. A driver that serves no such contract makes the bind
/// fail: it cannot prove the wire, so the fence reports
/// `cutoff::RING_HANDOFF`.
pub mod tx_drain {
    /// Bytes `arg` carries: the completed transmit count.
    pub const ARG_LEN: usize = 4;
}

/// What a fence's cutoff boundary is worth — the `fence.enforceable`
/// capability's `cutoff` fact, carried on every `MSG_ADDR_FENCED`.
pub mod cutoff {
    /// The boundary is the hand-off to the driver's ring: nothing from the
    /// address is handed over after it, but frames already in the ring may
    /// still leave. What the ip module alone can prove.
    pub const RING_HANDOFF: u8 = 0;
    /// The boundary is the wire. A driver that drains on request and
    /// reports its completed transmit index proves no later frame left the
    /// NIC; an out-of-band agent proves it by cutting the host, which puts
    /// nothing on the wire at all.
    pub const WIRE: u8 = 1;
}

/// `MSG_ADDR_REFUSED` reasons.
pub mod refusal {
    /// No such address installed.
    pub const NOT_FOUND: u8 = 1;
    /// The token does not match the address's current install.
    pub const TOKEN_MISMATCH: u8 = 2;
    /// The primary address is not subject to emission control.
    pub const PRIMARY: u8 = 3;
    /// No entropy to mint a token; the install was refused rather than
    /// made with a predictable token.
    pub const NO_ENTROPY: u8 = 4;
    /// The address table is full.
    pub const TABLE_FULL: u8 = 5;
    /// An out-of-band fence agent's actuator did not confirm the cut (or
    /// the restore): the host's state is unknown, and a coordinator must
    /// not activate a standby on it.
    pub const ACTUATOR: u8 = 6;
    /// The authority refused the arm's emission token, or gave no verdict
    /// within `ARM_AUTH_WAIT_MS` (a refusal with the authority's own code
    /// is `0x80 | code`).
    pub const AUTHORITY: u8 = 7;
    /// An arm under `arm_authority` carried no authority token.
    pub const NO_AUTHORITY: u8 = 8;
    /// Not an address the provider can install: multicast, unspecified or
    /// loopback, or IPv6 on a provider built without IPv6.
    pub const NOT_UNICAST: u8 = 9;
    /// The segment the install names does not exist, does not hold the
    /// address, or the address is its gateway.
    pub const SEGMENT: u8 = 10;
    /// The address is held by another owner, or the install names a
    /// workload owner without its generation or with one its slot no
    /// longer holds.
    pub const OWNER: u8 = 11;
}

// ─── The VIP authority's token ──────────────────────────────────────
//
// A provider run with `arm_authority` sources an address only once the
// authority that commits ownership has accepted the emission token it
// issued for this host: installs are disarmed whatever they ask, and an
// `ADDR_ARM` carries the token after its install token —
// `[addr:16][token:16][auth_len:u16 LE][auth:auth_len]`. The provider does
// not parse the token (it is the authority's opaque, generation-checked
// capability); it asks the authority it wires, naming its own boot
// incarnation so a token issued for another boot of this host, or for
// another host, cannot verify, and arms only on an accepting verdict.
// Unwired, or silent past `ARM_AUTH_WAIT_MS`, nothing arms. The token is
// held nowhere, so a restart loses it and the host must be issued another.

/// Largest authority token an `ADDR_ARM` carries.
pub const ARM_AUTH_MAX: usize = 160;
/// How long an arm waits for the authority's verdict (ms).
pub const ARM_AUTH_WAIT_MS: u32 = 2000;
/// Authority → provider (`auth_rsp`): `[addr:16][generation:u32 LE]
/// [sha256(auth):32][verdict:u8]`, verdict 0 accepting, anything else the
/// authority's refusal code.
pub use super::super::super::registry::msg::identity::ARM_AUTH_VERDICT;
/// Provider → authority (`auth_req`): `[addr:16][generation:u32 LE]
/// [boot_incarnation:16][auth_len:u16 LE][auth]`.
pub use super::super::super::registry::msg::identity::MSG_ARM_AUTH_CHECK;
pub const ARM_AUTH_VERDICT_LEN: usize = 16 + 4 + 32 + 1;

// ─── Payload layout ─────────────────────────────────────────────────

/// Byte length of an `ADDR_ADD` payload: `[addr:16][prefix_len:1][owner_tag:2]`.
pub const ADDR_ADD_PAYLOAD_LEN: usize = 19;

/// The longest `ADDR_ADD` payload: the flags byte, the segment and the
/// owner's generation after it ([`ADDR_ADD_OWNED_LEN`]).
pub const ADDR_ADD_PAYLOAD_MAX: usize = ADDR_ADD_OWNED_LEN;

/// Byte length of an `ADDR_ADD` naming a workload owner: through
/// `owner_gen`.
pub const ADDR_ADD_OWNED_LEN: usize = ADD_OWNER_GEN_OFF + 4;

/// Byte length of an `ADDR_DEL` payload: `[addr:16]`.
pub const ADDR_DEL_PAYLOAD_LEN: usize = 16;

/// Byte length of an `ADDR_ARM` / `ADDR_FENCE` payload: `[addr:16][token:16]`.
pub const ADDR_TOKEN_PAYLOAD_LEN: usize = 32;

/// Largest `addr_ctl` payload across the opcodes (an `ADDR_ADD` with its
/// flags byte, or a token-bearing op).
pub const MAX_PAYLOAD: usize = ADDR_TOKEN_PAYLOAD_LEN;

/// Offset of `prefix_len` within an `ADDR_ADD` payload.
pub const ADD_PREFIX_LEN_OFF: usize = 16;
/// Offset of `owner_tag` (u16 LE) within an `ADDR_ADD` payload.
pub const ADD_OWNER_TAG_OFF: usize = 17;
/// Offset of the optional flags byte within an `ADDR_ADD` payload.
pub const ADD_FLAGS_OFF: usize = 19;
/// Offset of the optional segment (u16 LE) within an `ADDR_ADD` payload.
pub const ADD_SEGMENT_OFF: usize = 20;
/// Offset of the owner's generation (u32 LE) within an `ADDR_ADD` payload:
/// required when `owner_tag` names a workload owner.
pub const ADD_OWNER_GEN_OFF: usize = 22;

/// `OWNER_RESOLVER` payload layout.
pub mod owner_resolver {
    /// Bytes before the context: `[owner_slot u16][owner_gen u32]`.
    pub const OWNER: usize = 6;
    /// Bytes of the context before its search list: family, server, count.
    pub const HEAD: usize = 1 + 16 + 1;
    /// The longest context: the server and a search list of names.
    pub const CONTEXT_MAX: usize = 256;
    /// The longest payload.
    pub const PAYLOAD_MAX: usize = OWNER + CONTEXT_MAX;
}
/// Offset of the token within an `ADDR_ARM` / `ADDR_FENCE` payload.
pub const TOKEN_OFF: usize = 16;
