//! Rules Engine PIC Module
//!
//! Evaluates a configurable rule table against incoming i32 LE values.
//! Rules have cross-inhibition for hysteresis debounce.
//! Outputs MQTT-framed messages when rules fire.
//!
//! **Params:**
//! - `high_threshold`: High temperature threshold in milli-C (default 30000)
//! - `low_threshold`: Low temperature threshold in milli-C (default 20000)
//! - `topic`: MQTT topic base string (default "fluxor/temp")
//!
//! **Input:** 4 bytes i32 LE — value in millidegrees Celsius
//! **Output:** MQTT-framed: [topic_len:u8][topic:bytes][payload:bytes]

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

const MAX_RULES: usize = 4;
const MAX_TOPIC_LEN: usize = 48;
const MAX_TAG_LEN: usize = 16;
const MSG_BUF_SIZE: usize = 128;

// Comparison operators
const OP_GT: u8 = 0;
const OP_LT: u8 = 1;

// ============================================================================
// Rule Table
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct Rule {
    op: u8,
    active: bool,
    fired: bool,
    clear_mask: u8,
    threshold: i32,
    topic: [u8; MAX_TOPIC_LEN],
    topic_len: u8,
    tag: [u8; MAX_TAG_LEN],
    tag_len: u8,
}

impl Rule {
    const fn empty() -> Self {
        Self {
            op: 0,
            active: false,
            fired: false,
            clear_mask: 0,
            threshold: 0,
            topic: [0; MAX_TOPIC_LEN],
            topic_len: 0,
            tag: [0; MAX_TAG_LEN],
            tag_len: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct RulesState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    rules: [Rule; MAX_RULES],
    // Params (used to build rules in init)
    high_threshold: i32,
    low_threshold: i32,
    topic_prefix: [u8; MAX_TOPIC_LEN],
    topic_prefix_len: u8,
    initialized: bool,
    msg_buf: [u8; MSG_BUF_SIZE],
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::RulesState;
    use super::{p_u16, MAX_TOPIC_LEN};
    use super::SCHEMA_MAX;

    define_params! {
        RulesState;

        1, high_threshold, u16, 30000
            => |s, d, len| { s.high_threshold = p_u16(d, len, 0, 30000) as i32; };

        2, low_threshold, u16, 20000
            => |s, d, len| { s.low_threshold = p_u16(d, len, 0, 20000) as i32; };

        3, topic, str, 0
            => |s, d, len| {
                let n = if len > MAX_TOPIC_LEN { MAX_TOPIC_LEN } else { len };
                s.topic_prefix_len = n as u8;
                if n > 0 {
                    let mut i = 0;
                    while i < n {
                        s.topic_prefix[i] = *d.add(i);
                        i += 1;
                    }
                }
            };
    }
}

// ============================================================================
// Integer-to-string helper (raw pointer, no bounds checks)
// ============================================================================

/// Write i32 as decimal string into buf (raw pointer). Returns bytes written.
/// Caller must ensure buf has at least 12 bytes of space.
unsafe fn i32_to_buf(val: i32, buf: *mut u8) -> usize {
    let mut pos = 0usize;
    let mut v = val;

    if v < 0 {
        *buf.add(pos) = b'-';
        pos += 1;
        v = -v;
    }

    if v == 0 {
        *buf.add(pos) = b'0';
        return pos + 1;
    }

    // Extract digits in reverse
    let mut digits = [0u8; 11];
    let mut dlen = 0usize;
    while v > 0 {
        *digits.as_mut_ptr().add(dlen) = b'0' + (v % 10) as u8;
        v /= 10;
        dlen += 1;
    }

    // Reverse into output
    let mut i = dlen;
    while i > 0 {
        i -= 1;
        *buf.add(pos) = *digits.as_ptr().add(i);
        pos += 1;
    }

    pos
}

// ============================================================================
// Rule initialization
// ============================================================================

/// Build the default 2-rule hysteresis pair from params.
unsafe fn build_rules(s: &mut RulesState) {
    // Set default topic if none configured
    if s.topic_prefix_len == 0 {
        let default_topic = b"fluxor/temp";
        let len = default_topic.len();
        let dst = s.topic_prefix.as_mut_ptr();
        let src = default_topic.as_ptr();
        let mut i = 0;
        while i < len {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        s.topic_prefix_len = len as u8;
    }

    // Build alert topic: prefix + "/alert"
    let prefix_len = s.topic_prefix_len as usize;
    let suffix = b"/alert";
    let mut topic_len = prefix_len + suffix.len();
    if topic_len > MAX_TOPIC_LEN { topic_len = MAX_TOPIC_LEN; }

    let mut topic = [0u8; MAX_TOPIC_LEN];
    let tp = topic.as_mut_ptr();
    let pp = s.topic_prefix.as_ptr();
    let mut i = 0;
    while i < prefix_len && i < MAX_TOPIC_LEN {
        *tp.add(i) = *pp.add(i);
        i += 1;
    }
    let sp = suffix.as_ptr();
    let mut j = 0;
    while j < suffix.len() && i < MAX_TOPIC_LEN {
        *tp.add(i) = *sp.add(j);
        i += 1;
        j += 1;
    }

    // Rule 0: value > high_threshold -> fire, clear rule 1
    s.rules[0] = Rule {
        op: OP_GT,
        active: true,
        fired: false,
        clear_mask: 0x02,
        threshold: s.high_threshold,
        topic,
        topic_len: topic_len as u8,
        tag: [0; MAX_TAG_LEN],
        tag_len: 4,
    };
    s.rules[0].tag[0] = b'h';
    s.rules[0].tag[1] = b'i';
    s.rules[0].tag[2] = b'g';
    s.rules[0].tag[3] = b'h';

    // Rule 1: value < low_threshold -> fire, clear rule 0
    s.rules[1] = Rule {
        op: OP_LT,
        active: true,
        fired: false,
        clear_mask: 0x01,
        threshold: s.low_threshold,
        topic,
        topic_len: topic_len as u8,
        tag: [0; MAX_TAG_LEN],
        tag_len: 3,
    };
    s.rules[1].tag[0] = b'l';
    s.rules[1].tag[1] = b'o';
    s.rules[1].tag[2] = b'w';
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<RulesState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<RulesState>() {
            return -2;
        }

        let s = &mut *(state as *mut RulesState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.initialized = false;

        // Zero out rules
        s.rules = [Rule::empty(); MAX_RULES];

        // Zero topic
        s.topic_prefix_len = 0;
        __aeabi_memclr(s.topic_prefix.as_mut_ptr(), MAX_TOPIC_LEN);

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Build rule table from params
        build_rules(s);
        s.initialized = true;

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut RulesState);
        if s.syscalls.is_null() || s.in_chan < 0 {
            return -1;
        }

        let sys = &*s.syscalls;

        // Poll input channel
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || ((poll as u8) & POLL_IN) == 0 {
            return 0;
        }

        // Read 4 bytes (i32 LE)
        let mut raw = [0u8; 4];
        let n = (sys.channel_read)(s.in_chan, raw.as_mut_ptr(), 4);
        if n < 4 {
            return 0;
        }

        let value = i32::from_le_bytes(raw);

        // Evaluate each active rule (raw pointer access to avoid bounds checks)
        let rules_ptr = s.rules.as_mut_ptr();
        let mut i = 0usize;
        while i < MAX_RULES {
            let r = &mut *rules_ptr.add(i);
            if !r.active || r.fired {
                i += 1;
                continue;
            }

            let triggered = match r.op {
                OP_GT => value > r.threshold,
                OP_LT => value < r.threshold,
                _ => false,
            };

            if triggered {
                // Mark this rule as fired (inhibited)
                r.fired = true;

                // Clear rules in clear_mask (un-inhibit them)
                let mask = r.clear_mask;
                let mut j = 0usize;
                while j < MAX_RULES {
                    if (mask & (1 << j)) != 0 {
                        (*rules_ptr.add(j)).fired = false;
                    }
                    j += 1;
                }

                // Format and send MQTT message
                emit_alert(s, sys, i, value);
            }

            i += 1;
        }

        0
    }
}

/// Format and emit an MQTT-framed alert message.
///
/// Output format: [topic_len:u8][topic][payload]
/// Payload: "tag:value" e.g. "high:31500"
unsafe fn emit_alert(s: &mut RulesState, sys: &SyscallTable, rule_idx: usize, value: i32) {
    let r = &*s.rules.as_ptr().add(rule_idx);
    let topic_len = r.topic_len as usize;
    let tag_len = r.tag_len as usize;
    let buf = s.msg_buf.as_mut_ptr();

    // Framing: [topic_len:u8]
    *buf = topic_len as u8;

    // Copy topic
    let topic_src = r.topic.as_ptr();
    let mut i = 0usize;
    while i < topic_len {
        *buf.add(1 + i) = *topic_src.add(i);
        i += 1;
    }

    // Payload starts after header + topic
    let payload_start = 1 + topic_len;
    let mut pos = 0usize;

    // Copy tag
    let tag_src = r.tag.as_ptr();
    i = 0;
    while i < tag_len && payload_start + pos < MSG_BUF_SIZE {
        *buf.add(payload_start + pos) = *tag_src.add(i);
        pos += 1;
        i += 1;
    }

    // Separator ':'
    if payload_start + pos < MSG_BUF_SIZE {
        *buf.add(payload_start + pos) = b':';
        pos += 1;
    }

    // Value as decimal string (i32_to_buf needs max 12 bytes)
    if payload_start + pos + 12 <= MSG_BUF_SIZE {
        let val_len = i32_to_buf(value, buf.add(payload_start + pos));
        pos += val_len;
    }

    let total = payload_start + pos;

    // Write to output channel
    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if poll > 0 && ((poll as u8) & POLL_OUT) != 0 {
        (sys.channel_write)(s.out_chan, buf, total);
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
