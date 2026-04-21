// Contract: net_proto — channel-based networking protocol.
//
// Layer: contracts/net (public, stable).
//
// Frame format: [msg_type: u8] [len: u16 LE] [payload: len bytes]
// Carried over channels between IP / TLS / HTTP / DNS / MQTT / VoIP /
// RTP modules. The kernel does not interpret these bytes — protocol
// state lives entirely in the modules.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

// Downstream: IP/net → consumer
/// New connection accepted. Payload: [conn_id: u8]
pub const MSG_ACCEPTED: u8 = 0x01;
/// Received data. Payload: [conn_id: u8] [data...]
pub const MSG_DATA: u8 = 0x02;
/// Remote closed connection. Payload: [conn_id: u8]
pub const MSG_CLOSED: u8 = 0x03;
/// Bind/listen completed. No payload.
pub const MSG_BOUND: u8 = 0x04;
/// Outbound connect completed. Payload: [conn_id: u8]
pub const MSG_CONNECTED: u8 = 0x05;
/// Error. Payload: [conn_id: u8] [errno: i8]
pub const MSG_ERROR: u8 = 0x06;

// Upstream: consumer → IP/net
/// Bind to port and listen. Payload: [port: u16 LE]
pub const CMD_BIND: u8 = 0x10;
/// Send data on connection. Payload: [conn_id: u8] [data...]
pub const CMD_SEND: u8 = 0x11;
/// Close connection. Payload: [conn_id: u8]
pub const CMD_CLOSE: u8 = 0x12;
/// Initiate outbound connection. Payload: [sock_type: u8] [ip: u32 LE] [port: u16 LE]
pub const CMD_CONNECT: u8 = 0x13;

pub const SOCK_TYPE_STREAM: u8 = 1;
pub const SOCK_TYPE_DGRAM: u8 = 2;

// Netif state propagation: drivers emit state transitions as
// `MSG_NETIF_STATE` frames on a dedicated `netif_state` output port;
// consumers read from a wired input port of the same name. All
// inter-module networking uses channel-based net_proto (this file) or
// direct FMP messaging — there is no separate netif dispatch surface.
