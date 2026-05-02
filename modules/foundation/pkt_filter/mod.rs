//! Stateless Packet Filter PIC Module
//!
//! Reads parsed packet metadata (from eth_parser), evaluates match rules
//! from config params, and forwards or drops packets.
//!
//! # Channels
//!
//! - `in[0]`: Parsed packets (20-byte metadata + payload from eth_parser)
//! - `out[0]`: Accepted packets (same format, passed through)
//!
//! # Config Params
//!
//! Rules are configured via params:
//! - tag 1: rule_count (u8, max 8)
//! - tags 10-17: rule_N (8 bytes each):
//!   ```text
//!   [0]     action: 0=drop, 1=accept
//!   [1]     proto_match: 0=any, 6=TCP, 17=UDP, 1=ICMP
//!   [2..3]  dst_port_lo (u16 LE, 0=any)
//!   [4..5]  dst_port_hi (u16 LE, 0=same as lo)
//!   [6..7]  reserved
//!   ```
//!
//! Default policy: accept all (no rules = pass-through).

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const MAX_FRAME: usize = 1514;
const META_SIZE: usize = 20;
const MAX_RULES: usize = 8;
const STATE_SIZE: usize = 128;

const ACTION_DROP: u8 = 0;
const ACTION_ACCEPT: u8 = 1;

// ============================================================================
// Rule
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct FilterRule {
    action: u8,
    proto_match: u8,
    dst_port_lo: u16,
    dst_port_hi: u16,
    _reserved: u16,
}

impl FilterRule {
    const fn empty() -> Self {
        Self {
            action: ACTION_ACCEPT,
            proto_match: 0,
            dst_port_lo: 0,
            dst_port_hi: 0,
            _reserved: 0,
        }
    }
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct FilterState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    rule_count: u8,
    default_action: u8,
    _pad: [u8; 2],
    rules: [FilterRule; MAX_RULES],
    accepted: u32,
    dropped: u32,
}

// ============================================================================
// Param parsing
// ============================================================================

unsafe fn parse_params(s: &mut FilterState, params: *const u8, params_len: usize) {
    if params.is_null() || params_len == 0 { return; }

    let mut off = 0usize;
    while off + 2 <= params_len {
        let tag = *params.add(off);
        let len = *params.add(off + 1) as usize;
        off += 2;
        if off + len > params_len { break; }
        let val = params.add(off);

        match tag {
            1 => {
                // rule_count
                if len >= 1 {
                    s.rule_count = (*val).min(MAX_RULES as u8);
                }
            }
            2 => {
                // default_action
                if len >= 1 {
                    s.default_action = *val;
                }
            }
            10..=17 => {
                // rule N
                let idx = (tag - 10) as usize;
                if idx < MAX_RULES && len >= 6 {
                    let rp = s.rules.as_mut_ptr().add(idx);
                    (*rp).action = *val;
                    (*rp).proto_match = *val.add(1);
                    (*rp).dst_port_lo = u16::from_le_bytes([*val.add(2), *val.add(3)]);
                    (*rp).dst_port_hi = u16::from_le_bytes([*val.add(4), *val.add(5)]);
                    (*rp)._reserved = 0;
                    if (*rp).dst_port_hi == 0 {
                        (*rp).dst_port_hi = (*rp).dst_port_lo;
                    }
                }
            }
            _ => {}
        }
        off += len;
    }
}

// ============================================================================
// Filter logic
// ============================================================================

unsafe fn evaluate(s: &FilterState, meta: &[u8; META_SIZE]) -> bool {
    if s.rule_count == 0 {
        return s.default_action != ACTION_DROP;
    }

    let mp = meta.as_ptr();
    let ip_proto = *mp.add(10);
    let dst_port = ((*mp.add(13) as u16) << 8) | *mp.add(14) as u16; // big-endian in meta

    let mut i = 0usize;
    while i < s.rule_count as usize {
        let rule = &*s.rules.as_ptr().add(i);

        // Protocol match
        let proto_ok = rule.proto_match == 0 || rule.proto_match == ip_proto;

        // Port match
        let port_ok = rule.dst_port_lo == 0
            || (dst_port >= rule.dst_port_lo && dst_port <= rule.dst_port_hi);

        if proto_ok && port_ok {
            return rule.action == ACTION_ACCEPT;
        }
        i += 1;
    }

    // No rule matched: use default
    s.default_action != ACTION_DROP
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { STATE_SIZE }

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut FilterState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s._ctrl_chan = ctrl_chan;
    s.rule_count = 0;
    s.default_action = ACTION_ACCEPT;
    s.accepted = 0;
    s.dropped = 0;

    // Init rules to empty
    let mut i = 0;
    while i < MAX_RULES {
        let rp = unsafe { s.rules.as_mut_ptr().add(i) };
        unsafe { *rp = FilterRule::empty(); }
        i += 1;
    }

    unsafe { parse_params(s, params, params_len); }
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut FilterState);
    let sys = &*s.syscalls;

    // Read parsed packet (metadata + payload)
    let mut buf = [0u8; META_SIZE + MAX_FRAME];
    let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
    if n < META_SIZE as i32 {
        return 0; // Nothing to process
    }

    // Extract metadata
    let mut meta = [0u8; META_SIZE];
    let mp = meta.as_mut_ptr();
    let bp = buf.as_ptr();
    let mut i = 0;
    while i < META_SIZE {
        core::ptr::write_volatile(mp.add(i), core::ptr::read_volatile(bp.add(i)));
        i += 1;
    }

    if evaluate(s, &meta) {
        // Forward entire message (metadata + payload)
        (sys.channel_write)(s.out_chan, buf.as_ptr(), n as usize);
        s.accepted = s.accepted.wrapping_add(1);
    } else {
        s.dropped = s.dropped.wrapping_add(1);
    }

    2 // Burst (may have more)
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
