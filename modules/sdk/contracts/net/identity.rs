// Contract: identity — Net-Identity Address-Control v1.
//
// Layer: contracts/net (public, stable).
//
// See rfc_net_identity_metal.md §3 and rfc_workload_backend_metal.md §3.3.
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

// ─── Payload layout ─────────────────────────────────────────────────

/// Byte length of an `ADDR_ADD` payload: `[addr:16][prefix_len:1][owner_tag:2]`.
pub const ADDR_ADD_PAYLOAD_LEN: usize = 19;

/// Byte length of an `ADDR_DEL` payload: `[addr:16]`.
pub const ADDR_DEL_PAYLOAD_LEN: usize = 16;

/// Largest `addr_ctl` payload across the opcodes (an `ADDR_ADD`).
pub const MAX_PAYLOAD: usize = ADDR_ADD_PAYLOAD_LEN;

/// Offset of `prefix_len` within an `ADDR_ADD` payload.
pub const ADD_PREFIX_LEN_OFF: usize = 16;
/// Offset of `owner_tag` (u16 LE) within an `ADDR_ADD` payload.
pub const ADD_OWNER_TAG_OFF: usize = 17;
