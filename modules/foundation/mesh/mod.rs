// MeshBridge PIC Module
//
// Translates between mesh Events and internal FMP messages.
//
// # Channel Wiring (multi-port ABI v2)
//
// | Port     | Direction | Connects to                              |
// |----------|-----------|------------------------------------------|
// | in[0]    | from MQTT | Received MQTT messages (commands)         |
// | out[0]   | to MQTT   | Outgoing MQTT messages (events)           |
// | in[1]    | from bank | FMP `status` messages (out[1] of bank)    |
// | ctrl[0]  | to bank   | FMP control messages (ctrl_chan in new)    |
//
// # Inbound (MQTT command → FMP message)
//
// 1. Read framed message from in[0]: [topic_len][topic][EventHeader][payload]
// 2. Verify content_type == CT_MESH_COMMAND
// 3. Parse CommandPayload (12 bytes) from Event payload
// 4. Map action code → FMP message type (next/prev/toggle/select)
// 5. Write FMP message to ctrl_chan
//
// # Outbound (FMP status → MQTT event)
//
// 1. Read FMP `status` message from in[1]
// 2. Build EventHeader: source=object_uuid, sequence++, content_type=CT_MESH_STATE
// 3. Build topic: fluxor/{device_hex}/objects/{object_hex}/events
// 4. Write framed message to out[0]: [topic_len][topic][EventHeader][status payload]

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");
include!("mesh_types.rs");

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::MeshBridgeState;
    use super::SCHEMA_MAX;

    define_params! {
        MeshBridgeState;

        // Mesh uses structured binary params (device_uuid + object array).
        // TLV v2 envelope is detected but params are parsed manually.
        // Tag 1: device_uuid (16 bytes raw)
        // Tag 2: object entries (24 bytes each: uuid[16] + control_id[1] + ctrl_port_index[1] + reserved[6])
    }
}

// ============================================================================
// Constants
// ============================================================================

const MAX_OBJECTS: usize = 4;
const MAX_TOPIC_LEN: usize = 96;
const CHAN_BUF_SIZE: usize = 192;
const STATUS_BUF_SIZE: usize = 16;

// Topic prefix: "fluxor/" = 7 bytes
// Device hex: 32 bytes
// "/objects/" = 9 bytes
// Object hex: 32 bytes
// "/events" or "/commands" = 7 or 9 bytes
// Max topic: 7 + 32 + 9 + 32 + 9 = 89 bytes

// ============================================================================
// Object Mapping
// ============================================================================

#[repr(C)]
struct ObjectMapping {
    uuid: [u8; 16],
    uuid_hex: [u8; 32],  // pre-computed at init
    control_id: u8,
    ctrl_port_index: u8,
    _pad: [u8; 2],
    sequence: u32,
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct MeshBridgeState {
    syscalls: *const SyscallTable,

    // Channels
    in_chan: i32,      // in[0]: from MQTT (commands)
    out_chan: i32,     // out[0]: to MQTT (events)
    notif_chan: i32,   // in[1]: FMP status from bank
    ctrl_chan: i32,    // ctrl[0]: FMP commands to bank

    // Device identity
    device_uuid: [u8; 16],
    device_hex: [u8; 32],

    // Objects
    object_count: u8,
    _pad: [u8; 3],
    objects: [ObjectMapping; MAX_OBJECTS],

    // Pre-built topic prefixes per object
    // "fluxor/{device_hex}/objects/{object_hex}/" = 7+32+9+32+1 = 81 bytes
    topic_prefix: [[u8; 84]; MAX_OBJECTS],
    topic_prefix_len: [u8; MAX_OBJECTS],

    // Buffers
    chan_buf: [u8; CHAN_BUF_SIZE],
    status_buf: [u8; STATUS_BUF_SIZE],
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
unsafe fn millis(s: &MeshBridgeState) -> u64 {
    dev_millis(&*s.syscalls)
}

#[inline(always)]
unsafe fn log_msg(s: &MeshBridgeState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

#[inline(always)]
unsafe fn log_err(s: &MeshBridgeState, msg: &[u8]) {
    dev_log(&*s.syscalls, 1, msg.as_ptr(), msg.len());
}

#[inline(always)]
unsafe fn ptr_copy(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

/// Map mesh action code → FMP message type.
/// Returns (msg_type, valid).
#[inline(always)]
fn map_action(action: u16) -> (u32, bool) {
    match action {
        ACTION_PLAY    => (MSG_TOGGLE, true),
        ACTION_PAUSE   => (MSG_TOGGLE, true),
        ACTION_NEXT    => (MSG_NEXT, true),
        ACTION_PREVIOUS => (MSG_PREV, true),
        ACTION_SELECT  => (MSG_SELECT, true),
        _ => (0, false),
    }
}

/// Build topic prefix for an object: "fluxor/{device_hex}/objects/{object_hex}/"
/// Returns length written.
unsafe fn build_topic_prefix(
    buf: *mut u8,
    device_hex: &[u8; 32],
    object_hex: &[u8; 32],
) -> usize {
    let mut offset = 0;

    // "fluxor/"
    let prefix = b"fluxor/";
    ptr_copy(buf, prefix.as_ptr(), 7);
    offset += 7;

    // device hex (32 bytes)
    ptr_copy(buf.add(offset), device_hex.as_ptr(), 32);
    offset += 32;

    // "/objects/"
    let seg = b"/objects/";
    ptr_copy(buf.add(offset), seg.as_ptr(), 9);
    offset += 9;

    // object hex (32 bytes)
    ptr_copy(buf.add(offset), object_hex.as_ptr(), 32);
    offset += 32;

    // trailing "/"
    *buf.add(offset) = b'/';
    offset += 1;

    offset // should be 81
}

/// Find object index by matching UUID hex in topic.
/// The topic format is: fluxor/{device}/objects/{object_hex}/commands
/// We extract the object_hex portion (bytes 48..80 in a well-formed topic)
/// and compare against known objects.
unsafe fn find_object_by_topic(s: &MeshBridgeState, topic: *const u8, topic_len: usize) -> i32 {
    // Minimum topic: "fluxor/" + 32 + "/objects/" + 32 + "/commands" = 89
    if topic_len < 81 {
        return -1;
    }

    // Object hex starts at offset 48 (7 + 32 + 9 = 48)
    let obj_hex_ptr = topic.add(48);
    let obj_hex_len = if topic_len >= 80 { 32 } else { return -1 };

    let mut i: usize = 0;
    let objs = s.objects.as_ptr();
    while i < s.object_count as usize {
        if hex_eq(&(*objs.add(i)).uuid_hex, obj_hex_ptr, obj_hex_len) {
            return i as i32;
        }
        i += 1;
    }
    -1
}

// ============================================================================
// Inbound: MQTT command → FMP message
// ============================================================================

unsafe fn handle_inbound_command(s: &mut MeshBridgeState) {
    let sys_ptr = s.syscalls;
    let sys = &*sys_ptr;

    if s.in_chan < 0 { return; }

    let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    // Read framed message: [topic_len:u8][topic][EventHeader(32)][payload]
    let rc = (sys.channel_read)(
        s.in_chan,
        s.chan_buf.as_mut_ptr(),
        CHAN_BUF_SIZE,
    );
    if rc <= 0 { return; }
    let msg_len = rc as usize;

    let buf = s.chan_buf.as_ptr();
    let topic_len = *buf as usize;
    if topic_len == 0 { return; }

    let header_start = 1 + topic_len;
    // Need at least: 1 + topic + EventHeader(32) + CommandPayload(12)
    if msg_len < header_start + EVENT_HEADER_SIZE + COMMAND_HEADER_SIZE {
        return;
    }

    // Parse EventHeader
    let hdr = unpack_event_header(buf.add(header_start));

    // Must be a mesh command
    if hdr.content_type != CT_MESH_COMMAND {
        return;
    }

    // Parse CommandPayload
    let cmd_start = header_start + EVENT_HEADER_SIZE;
    let cmd = unpack_command_header(buf.add(cmd_start));

    // Map action → FMP message type
    let (msg_type, valid) = map_action(cmd.action);
    if !valid {
        return;
    }

    // Write FMP message to ctrl_chan
    if s.ctrl_chan >= 0 {
        let ctrl_poll = (sys.channel_poll)(s.ctrl_chan, POLL_OUT);
        if ctrl_poll > 0 && ((ctrl_poll as u32) & POLL_OUT) != 0 {
            // For SELECT, pass u16 index from CBOR args as payload
            if msg_type == MSG_SELECT && cmd.args_length >= 2 {
                let args_start = cmd_start + COMMAND_HEADER_SIZE;
                if msg_len >= args_start + 2 {
                    let param = [*buf.add(args_start), *buf.add(args_start + 1)];
                    msg_write(sys, s.ctrl_chan, msg_type, param.as_ptr(), 2);
                } else {
                    msg_write(sys, s.ctrl_chan, msg_type, core::ptr::null(), 0);
                }
            } else {
                msg_write(sys, s.ctrl_chan, msg_type, core::ptr::null(), 0);
            }
        }
    }
}

// ============================================================================
// Outbound: FMP status → MQTT event
// ============================================================================

unsafe fn handle_outbound_notification(s: &mut MeshBridgeState) {
    let sys_ptr = s.syscalls;
    let sys = &*sys_ptr;

    if s.notif_chan < 0 { return; }
    if s.out_chan < 0 { return; }
    if s.object_count == 0 { return; }

    let poll = (sys.channel_poll)(s.notif_chan, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    // Read FMP status message from bank
    let (ty, payload_len) = msg_read(sys, s.notif_chan, s.status_buf.as_mut_ptr(), STATUS_BUF_SIZE);
    if ty != MSG_STATUS || payload_len == 0 {
        return;
    }
    let payload_len = payload_len as usize;

    // Use first object for notifications (primary speaker object)
    let obj0 = s.objects.as_mut_ptr().add(0);
    (*obj0).sequence = (*obj0).sequence.wrapping_add(1);
    let source = (*obj0).uuid;
    let sequence = (*obj0).sequence;

    // Build topic: prefix + "events"
    let prefix_len = *s.topic_prefix_len.as_ptr() as usize;
    let suffix = b"events";
    let topic_len = prefix_len + suffix.len();

    if topic_len > MAX_TOPIC_LEN { return; }

    // Build EventHeader
    let now_us = millis(s) * 1000;
    let hdr = EventHeader {
        source,
        sequence,
        timestamp_us: now_us,
        content_type: CT_MESH_STATE,
        flags: 0,
        length: payload_len as u16,
    };

    // Build framed message: [topic_len:u8][topic][EventHeader(32)][status payload]
    let total = 1 + topic_len + EVENT_HEADER_SIZE + payload_len;
    if total > CHAN_BUF_SIZE { return; }

    let cb = s.chan_buf.as_mut_ptr();
    let mut offset = 0;

    // topic_len
    *cb = topic_len as u8;
    offset += 1;

    // topic = prefix + "events"
    ptr_copy(cb.add(offset), (*s.topic_prefix.as_ptr()).as_ptr(), prefix_len);
    offset += prefix_len;
    ptr_copy(cb.add(offset), suffix.as_ptr(), suffix.len());
    offset += suffix.len();

    // EventHeader (32 bytes)
    pack_event_header(cb.add(offset), &hdr);
    offset += EVENT_HEADER_SIZE;

    // Status payload
    ptr_copy(cb.add(offset), s.status_buf.as_ptr(), payload_len);
    offset += payload_len;

    // Write to out_chan (to MQTT)
    let out_poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if out_poll > 0 && ((out_poll as u32) & POLL_OUT) != 0 {
        (sys.channel_write)(s.out_chan, cb, offset);
    }
    // If channel not ready, drop (QoS 0 — best effort)
}

// ============================================================================
// Exported PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<MeshBridgeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<MeshBridgeState>() { return -6; }

        let s = &mut *(state as *mut MeshBridgeState);
        let state_bytes = state_size.min(core::mem::size_of::<MeshBridgeState>());
        __aeabi_memclr(state, state_bytes);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Discover additional ports via ABI v2
        let sys = &*(syscalls as *const SyscallTable);
        // in[1] = bank notification channel
        s.notif_chan = dev_channel_port(sys, 0, 1); // port_type=in(0), index=1

        log_msg(s, b"[mesh] init");

        // Detect TLV v2 envelope — mesh uses structured binary params
        // within the TLV v2 envelope (tags parsed manually).
        let (p, plen) = if !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01
        {
            // TLV v2: skip 4-byte header, payload follows
            let payload_len = u16::from_le_bytes([*params.add(2), *params.add(3)]) as usize;
            let effective_len = if 4 + payload_len < params_len { payload_len } else { params_len - 4 };
            (params.add(4), effective_len)
        } else if !params.is_null() {
            (params, params_len)
        } else {
            log_err(s, b"[mesh] no params");
            return -3;
        };

        if plen < 20 {
            log_err(s, b"[mesh] params too short");
            return -10;
        }

        // Device UUID
        ptr_copy(s.device_uuid.as_mut_ptr(), p, 16);
        encode_uuid_hex(&s.device_uuid, &mut s.device_hex);

        // Objects
        let obj_count = (*p.add(16) as usize).min(MAX_OBJECTS);
        s.object_count = obj_count as u8;

        let mut i: usize = 0;
        while i < obj_count {
            let obj_offset = 20 + i * 24;
            if obj_offset + 18 > plen {
                break;
            }

            let obj = &mut *s.objects.as_mut_ptr().add(i);
            ptr_copy(obj.uuid.as_mut_ptr(), p.add(obj_offset), 16);
            obj.control_id = *p.add(obj_offset + 16);
            obj.ctrl_port_index = *p.add(obj_offset + 17);
            obj.sequence = 0;

            // Pre-compute hex
            encode_uuid_hex(&obj.uuid, &mut obj.uuid_hex);

            // Pre-build topic prefix
            let prefix_len = build_topic_prefix(
                (*s.topic_prefix.as_mut_ptr().add(i)).as_mut_ptr(),
                &s.device_hex,
                &obj.uuid_hex,
            );
            *s.topic_prefix_len.as_mut_ptr().add(i) = prefix_len as u8;

            i += 1;
        }

        log_msg(s, b"[mesh] ready");
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut MeshBridgeState);
        if s.syscalls.is_null() { return -1; }

        // 1. Process inbound commands (MQTT → bank control)
        handle_inbound_command(s);

        // 2. Process outbound notifications (bank → MQTT)
        handle_outbound_notification(s);

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 256 }, // in[0]: from MQTT
        ChannelHint { port_type: 0, port_index: 1, buffer_size: 256 }, // in[1]: FMP status from bank
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 256 }, // out[0]: to MQTT
        ChannelHint { port_type: 2, port_index: 0, buffer_size: 256 }, // ctrl[0]: FMP commands to bank
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
