// Contract: identity — Net-Identity Address-Control v1.
//
// Layer: contracts/net (public, stable).
//
// The control-plane contract by which a **workload backend** installs and
// removes a workload's network identity (a secondary local address) on the
// node's shared **net-identity provider** — the foundation module that owns the
// node's IP stack. The provider exposes a dedicated single-writer control input
// port (`addr_ctl`); the backend is its sole writer. On a `net=own` workload
// CREATE the backend writes one `ADDR_ADD`; on DESTROY / KILL it writes the
// matching `ADDR_DEL`.
//
// This contract is the shared source of truth for that exchange. Before it
// existed, the opcodes and payload layout were duplicated — defined privately in
// the provider module (`ip`) and again in the kernel workload backend, kept in
// sync only by a comment. Both sides now reference the constants here, so the
// kernel moves contract-defined bytes to a provider it resolves by role, and
// never embeds any one provider module's private protocol.
//
// ─── Provider discovery (self-registration) ─────────────────────────
//
// The provider SELF-REGISTERS at init via the `NET_IDENT_PROVIDER` syscall
// (`kernel_abi::NET_IDENT_PROVIDER`), declaring its own `addr_ctl` and
// net-ingress input-port indices. The kernel therefore never knows the
// provider's name or fixes its topology — any base-graph (system-owned)
// module implementing this contract's `addr_ctl` receiver may register;
// first-wins, workload modules are refused. A node where nothing registers
// simply has no net-identity provider, and a `net=own` CREATE there fails
// cleanly (`ENODEV`) rather than silently. This file carries only the
// PROTOCOL: framing, opcodes, payload layout.
//
// ─── Framing ────────────────────────────────────────────────────────
//
// Frames use the same `[msg_type: u8] [len: u16 LE] [payload...]` TLV header as
// net_proto / datagram / packet / session_ctrl, so the shared SDK framing
// helpers (`net_read_frame` / `net_write_frame`) work unchanged.
//
// Unlike the multiplexed stream/datagram/packet surfaces, these opcodes ride a
// **dedicated single-writer control port** (`addr_ctl`) that never carries other
// contracts. Their opcode space is therefore port-local: `ADDR_ADD` (0x60) /
// `ADDR_DEL` (0x61) overlap the `packet` range (0x50..0x63) by number, but a
// shared channel never carries both, so there is no ambiguity.

/// Frame header size (`msg_type` + `len`), identical to the other net contracts.
pub const FRAME_HDR: usize = 3;

// ─── Opcodes (backend → provider, over `addr_ctl`) ──────────────────

/// Install a workload's secondary local address.
/// Payload: `[addr: 16][prefix_len: 1][owner_tag: 2 LE]`
/// (`addr` is a 16-byte address slot, IPv4 in bytes 0..4 in network order — the
/// provider's `LocalAddr` layout, so it copies in with no re-order; `owner_tag`
/// is the workload's owner slot). The address is live before the workload runs.
pub const ADDR_ADD: u8 = 0x60;

/// Remove a workload's secondary local address.
/// Payload: `[addr: 16]`.
pub const ADDR_DEL: u8 = 0x61;

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
pub const ADDR_ARM: u8 = 0x62;

/// Fence an installed address: no frame sourced from it enters the driver
/// ring after the answer, and ARP for it is not answered. Payload:
/// `[addr: 16][token: 16]`. Answered by `MSG_ADDR_FENCED`, which carries
/// the cutoff boundary, or `MSG_ADDR_REFUSED`. The primary address cannot
/// be fenced.
pub const ADDR_FENCE: u8 = 0x63;

/// `ADDR_ADD` flags byte (optional, at `ADD_FLAGS_OFF`).
pub mod install {
    /// Install fenced; `ADDR_ARM` is required before the address emits.
    pub const DISARMED: u8 = 0x01;
}

// ─── Events (provider → backend, over `addr_evt`) ───────────────────

/// An address was installed and its token minted.
/// Payload: `[addr: 16][token: 16][generation: u32 LE]`.
pub const MSG_ADDR_ADDED: u8 = 0x70;

/// Emission is armed. Payload: `[addr: 16][generation: u32 LE]`.
pub const MSG_ADDR_ARMED: u8 = 0x71;

/// Emission is fenced. Payload: `[addr: 16][generation: u32 LE]
/// [cutoff: u64 LE][cutoff_kind: u8][pending_discarded: u8]`. `cutoff` is
/// the provider's frame counter at the fence: frames numbered below it
/// were handed to the driver before the fence, none sourced from the
/// address is handed after. `cutoff_kind` says what the boundary is worth
/// (see `cutoff`); `pending_discarded` is 1 when a frame from the address
/// staged for the ring was discarded rather than sent.
pub const MSG_ADDR_FENCED: u8 = 0x72;

/// An install, arm or fence was refused.
/// Payload: `[addr: 16][op: u8][reason: u8]` — `op` the refused opcode,
/// `reason` per `refusal`.
pub const MSG_ADDR_REFUSED: u8 = 0x73;

/// What a fence's cutoff boundary is worth — the `fence.enforceable`
/// capability's `cutoff` fact, carried on every `MSG_ADDR_FENCED`.
pub mod cutoff {
    /// The boundary is the hand-off to the driver's ring: nothing from the
    /// address is handed over after it, but frames already in the ring may
    /// still leave. What the ip module alone can prove.
    pub const RING_HANDOFF: u8 = 0;
    /// The boundary is the wire: a driver that drains and reports its
    /// completed transmit index proves no later frame left the NIC.
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
}

// ─── Payload layout ─────────────────────────────────────────────────

/// Byte length of an `ADDR_ADD` payload: `[addr:16][prefix_len:1][owner_tag:2]`.
pub const ADDR_ADD_PAYLOAD_LEN: usize = 19;

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
/// Offset of the token within an `ADDR_ARM` / `ADDR_FENCE` payload.
pub const TOKEN_OFF: usize = 16;
