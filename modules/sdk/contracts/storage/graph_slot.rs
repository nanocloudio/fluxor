// Contract: graph_slot — A/B graph slots for OTA reconfigure.
//
// Layer: contracts/storage (public, stable).
//
// The graph slot is the storage-medium-neutral channel protocol spoken
// between `ota_ingest` / `reconfigure` and the `graph_slot` PIC module.
// Storage layout (flash offsets, magic bytes, slot sizes) is NOT part
// of this contract — it lives in `platform/<chip>/flash_layout.rs`
// because it's platform-specific (RP 4 MB XIP flash vs. ESP32 NVS vs.
// BCM2712 SD/NVMe).
//
// Current RP layout: see `platform::rp::flash_layout::GRAPH_SLOT_*`.
// On-flash slot header (256 bytes, at the start of each slot) is
// documented alongside those constants.
//
// The graph_slot PIC module owns the on-flash format. It is served
// over channels — consumers write FMP-framed requests and read
// FMP-framed responses. There is no kernel-side dispatch opcode.

/// Channel protocol for the graph_slot service.
///
/// Wiring:
/// - Consumer writes FMP-framed requests to its output port; the edge
///   lands on graph_slot's `in` channel.
/// - graph_slot writes FMP-framed responses to its `out` channel; the
///   edge lands on the consumer's input port.
/// - Frame format: `[type: u32 LE][len: u16 LE][payload: len bytes]`
///   (matches `contracts::net::net_proto` framing).
///
/// Request types are FNV-1a hashes of the string names below; consumers
/// import the `REQ_*` constants to avoid redefining them inline. The
/// response type `RESP_RESULT` carries `[echoed_req_type: u32 LE][value: i32 LE]`
/// — 8 bytes. `value` semantics:
///
/// | Request | `value` meaning                                         |
/// |---------|---------------------------------------------------------|
/// | ERASE   | 0 on success, negative errno on failure                 |
/// | WRITE   | 0 on success, negative errno on failure                 |
/// | ACTIVATE| 0 on success, negative errno on failure                 |
/// | ACTIVE  | 0 or 1 (slot index), -1 if neither slot is live         |
/// | CFG     | XIP absolute address of live config blob, -1 if no live |
pub mod channel {
    /// Erase the inactive slot's 128 sectors in one pass. Payload: empty.
    pub const REQ_ERASE: u32    = super::fnv1a_const(b"gs.erase");
    /// Program one 256-byte page into the inactive slot.
    /// Payload: `[offset_in_slot: u32 LE][page: 256 bytes]` (260 bytes).
    pub const REQ_WRITE: u32    = super::fnv1a_const(b"gs.write");
    /// Validate the candidate slot's SHA-256 and (if valid) promote it.
    /// Payload: empty.
    pub const REQ_ACTIVATE: u32 = super::fnv1a_const(b"gs.activate");
    /// Query which slot is currently live. Payload: empty.
    pub const REQ_ACTIVE: u32   = super::fnv1a_const(b"gs.query_active");
    /// Query the XIP address of the live slot's config blob. Payload: empty.
    pub const REQ_CFG: u32      = super::fnv1a_const(b"gs.query_cfg");
    /// Response frame type. Payload: `[req_type: u32 LE][value: i32 LE]`.
    pub const RESP_RESULT: u32  = super::fnv1a_const(b"gs.result");

    /// Frame header size (type + len fields).
    pub const FRAME_HDR: usize = 6;
    /// Largest request payload (WRITE: 4 offset + 256 page).
    pub const REQ_MAX_PAYLOAD: usize = 4 + 256;
    /// Response payload is always 8 bytes.
    pub const RESP_PAYLOAD: usize = 8;
    /// Response frame total size.
    pub const RESP_FRAME_LEN: usize = FRAME_HDR + RESP_PAYLOAD;
}

/// Compile-time FNV-1a 32-bit hash (matches `fluxor::fnv1a32`).
/// Lives here so contract consts can be `pub const` without a proc
/// macro. Don't call at runtime — the SDK runtime already provides
/// `fnv1a` for that.
const fn fnv1a_const(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    let mut i = 0usize;
    while i < data.len() {
        hash ^= data[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}
