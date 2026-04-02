// Mesh Wire Format Types
//
// Shared between mqtt/mod.rs and mesh/mod.rs via include!().
// Defines the mesh Event header, Command payload, content types,
// and action codes from docs/architecture/mesh.md.
//
// All types are #[repr(C, packed)] for exact wire layout. All multi-byte
// fields are little-endian on wire.

// ============================================================================
// Object Identity
// ============================================================================

/// 128-bit UUID for mesh objects
pub type ObjectId = [u8; 16];

/// Null ObjectId (all zeros)
pub const NULL_OBJECT_ID: ObjectId = [0u8; 16];

// ============================================================================
// Event Header (32 bytes, wire format)
// ============================================================================

/// Mesh Event header — 32 bytes exactly.
///
/// Layout:
///   [0-15]  source: ObjectId (16 bytes, UUID)
///   [16-19] sequence: u32 (LE)
///   [20-27] timestamp_us: u64 (LE)
///   [28]    content_type: u8
///   [29]    flags: u8
///   [30-31] length: u16 (LE) — payload bytes following header
#[repr(C, packed)]
pub struct EventHeader {
    pub source: ObjectId,
    pub sequence: u32,
    pub timestamp_us: u64,
    pub content_type: u8,
    pub flags: u8,
    pub length: u16,
}

pub const EVENT_HEADER_SIZE: usize = 32;

// ============================================================================
// Content Type IDs (u8)
// ============================================================================

pub const CT_OCTET_STREAM: u8 = 0;
pub const CT_CBOR: u8 = 1;
pub const CT_JSON: u8 = 2;
pub const CT_AUDIO_PCM: u8 = 3;
pub const CT_MESH_COMMAND: u8 = 13;
pub const CT_MESH_STATE: u8 = 14;

// ============================================================================
// Event Flags
// ============================================================================

pub const FLAG_RESPONSE_REQUIRED: u8 = 0x01;
pub const FLAG_HIGH_PRIORITY: u8 = 0x02;
pub const FLAG_IDEMPOTENT: u8 = 0x04;

// ============================================================================
// Command Payload (12 bytes header + variable args)
// ============================================================================

/// Command payload — inner content of Event with content_type == CT_MESH_COMMAND.
///
/// Layout:
///   [0-3]   request_id: u32 (LE)
///   [4-5]   action: u16 (LE)
///   [6]     flags: u8
///   [7]     reserved: u8
///   [8-11]  args_length: u32 (LE)
///   [12..]  args (CBOR, variable)
#[repr(C)]
pub struct CommandPayload {
    pub request_id: u32,
    pub action: u16,
    pub flags: u8,
    pub reserved: u8,
    pub args_length: u32,
}

pub const COMMAND_HEADER_SIZE: usize = 12;

// ============================================================================
// Audio Action Codes (0x0100-0x01FF)
// ============================================================================

pub const ACTION_PLAY: u16 = 0x0100;
pub const ACTION_PAUSE: u16 = 0x0101;
pub const ACTION_NEXT: u16 = 0x0102;
pub const ACTION_PREVIOUS: u16 = 0x0103;
pub const ACTION_SET_VOLUME: u16 = 0x0104;
pub const ACTION_SELECT: u16 = 0x0105;

// ============================================================================
// Response Payload (8 bytes header + variable data)
// ============================================================================

/// Response payload — sent in reply to commands.
///
/// Layout:
///   [0-3]   request_id: u32 (LE)
///   [4]     result: u8
///   [5]     flags: u8
///   [6-7]   data_length: u16 (LE)
///   [8..]   data (CBOR, variable)
#[repr(C)]
pub struct ResponsePayload {
    pub request_id: u32,
    pub result: u8,
    pub flags: u8,
    pub data_length: u16,
}

pub const RESPONSE_HEADER_SIZE: usize = 8;

pub const RESULT_OK: u8 = 0;
pub const RESULT_ACCEPTED: u8 = 1;
pub const RESULT_ERROR: u8 = 2;
pub const RESULT_NOT_FOUND: u8 = 3;
pub const RESULT_NOT_SUPPORTED: u8 = 4;

// ============================================================================
// Pack/Unpack Helpers
// ============================================================================

/// Pack EventHeader into buffer. Caller ensures buf has >= 32 bytes.
/// Returns EVENT_HEADER_SIZE (32).
#[inline(always)]
pub unsafe fn pack_event_header(buf: *mut u8, hdr: &EventHeader) -> usize {
    // source (16 bytes)
    let mut i = 0;
    while i < 16 {
        *buf.add(i) = hdr.source[i];
        i += 1;
    }
    // sequence (LE)
    let seq = hdr.sequence.to_le_bytes();
    *buf.add(16) = seq[0];
    *buf.add(17) = seq[1];
    *buf.add(18) = seq[2];
    *buf.add(19) = seq[3];
    // timestamp_us (LE)
    let ts = hdr.timestamp_us.to_le_bytes();
    i = 0;
    while i < 8 {
        *buf.add(20 + i) = ts[i];
        i += 1;
    }
    // content_type, flags, length
    *buf.add(28) = hdr.content_type;
    *buf.add(29) = hdr.flags;
    let len = hdr.length.to_le_bytes();
    *buf.add(30) = len[0];
    *buf.add(31) = len[1];
    EVENT_HEADER_SIZE
}

/// Unpack EventHeader from buffer. Caller ensures buf has >= 32 bytes.
#[inline(always)]
pub unsafe fn unpack_event_header(buf: *const u8) -> EventHeader {
    let mut source = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        source[i] = *buf.add(i);
        i += 1;
    }
    EventHeader {
        source,
        sequence: u32::from_le_bytes([
            *buf.add(16), *buf.add(17), *buf.add(18), *buf.add(19),
        ]),
        timestamp_us: u64::from_le_bytes([
            *buf.add(20), *buf.add(21), *buf.add(22), *buf.add(23),
            *buf.add(24), *buf.add(25), *buf.add(26), *buf.add(27),
        ]),
        content_type: *buf.add(28),
        flags: *buf.add(29),
        length: u16::from_le_bytes([*buf.add(30), *buf.add(31)]),
    }
}

/// Pack CommandPayload header (12 bytes). Caller ensures buf has >= 12 bytes.
/// Returns COMMAND_HEADER_SIZE (12).
#[inline(always)]
pub unsafe fn pack_command_header(buf: *mut u8, cmd: &CommandPayload) -> usize {
    let rid = cmd.request_id.to_le_bytes();
    *buf.add(0) = rid[0];
    *buf.add(1) = rid[1];
    *buf.add(2) = rid[2];
    *buf.add(3) = rid[3];
    let act = cmd.action.to_le_bytes();
    *buf.add(4) = act[0];
    *buf.add(5) = act[1];
    *buf.add(6) = cmd.flags;
    *buf.add(7) = cmd.reserved;
    let al = cmd.args_length.to_le_bytes();
    *buf.add(8) = al[0];
    *buf.add(9) = al[1];
    *buf.add(10) = al[2];
    *buf.add(11) = al[3];
    COMMAND_HEADER_SIZE
}

/// Unpack CommandPayload header from buffer. Caller ensures buf has >= 12 bytes.
#[inline(always)]
pub unsafe fn unpack_command_header(buf: *const u8) -> CommandPayload {
    CommandPayload {
        request_id: u32::from_le_bytes([
            *buf.add(0), *buf.add(1), *buf.add(2), *buf.add(3),
        ]),
        action: u16::from_le_bytes([*buf.add(4), *buf.add(5)]),
        flags: *buf.add(6),
        reserved: *buf.add(7),
        args_length: u32::from_le_bytes([
            *buf.add(8), *buf.add(9), *buf.add(10), *buf.add(11),
        ]),
    }
}

// ============================================================================
// UUID Hex Encoding
// ============================================================================

const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

/// Encode 16-byte UUID as 32-byte lowercase hex string (no dashes).
#[inline(always)]
pub unsafe fn encode_uuid_hex(uuid: &[u8; 16], out: &mut [u8; 32]) {
    let mut i = 0;
    while i < 16 {
        out[i * 2] = HEX_TABLE[(uuid[i] >> 4) as usize];
        out[i * 2 + 1] = HEX_TABLE[(uuid[i] & 0x0F) as usize];
        i += 1;
    }
}

/// Compare 32-byte hex string against another. Returns true if equal.
#[inline(always)]
pub unsafe fn hex_eq(a: &[u8; 32], b: *const u8, len: usize) -> bool {
    if len != 32 {
        return false;
    }
    let mut i = 0;
    while i < 32 {
        if a[i] != *b.add(i) {
            return false;
        }
        i += 1;
    }
    true
}
