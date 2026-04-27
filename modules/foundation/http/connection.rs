//! Connection framing constants.
//!
//! Wraps the `IP module`'s on-channel framing protocol. HTTP versions
//! and WebSocket all share the same connection-level transport (TCP or
//! TLS), so the byte-shape of `NET_MSG_*` / `NET_CMD_*` frames lives
//! here, version-blind.
//!
//! The actual frame I/O helpers (`net_write_frame`, `net_read_frame`,
//! `NET_FRAME_HDR`) live in `modules/sdk/runtime.rs` and are pulled into
//! the top-level module's scope by `include!`. Submodules reach them
//! via `super::net_write_frame` etc.

// ── Inbound messages from the IP module ──
pub(crate) const NET_MSG_ACCEPTED: u8 = 0x01;
pub(crate) const NET_MSG_DATA: u8 = 0x02;
pub(crate) const NET_MSG_CLOSED: u8 = 0x03;
pub(crate) const NET_MSG_BOUND: u8 = 0x04;
pub(crate) const NET_MSG_CONNECTED: u8 = 0x05;
pub(crate) const NET_MSG_ERROR: u8 = 0x06;

// ── Outbound commands to the IP module ──
pub(crate) const NET_CMD_BIND: u8 = 0x10;
pub(crate) const NET_CMD_SEND: u8 = 0x11;
pub(crate) const NET_CMD_CLOSE: u8 = 0x12;
pub(crate) const NET_CMD_CONNECT: u8 = 0x13;

/// Scratch buffer size for assembling outbound and reading inbound
/// frames. Must be ≥ the IP module's largest single MSG_DATA payload
/// (linux_net writes up to 1500 + framing) — otherwise channel reads
/// truncate mid-MSG and h2 frame parsing breaks. 1600 = 1500 TCP read
/// budget + 4 MSG header + slack.
pub(crate) const NET_BUF_SIZE: usize = 1600;
