//! Wake-latency probe SOURCE (wake-on-write silicon AC, RFC
//! idle_skip_wake).
//!
//! Every `emit_every` (default 997) of its own steps, writes a 12-byte
//! probe on `out`: `[magic u32 LE][dev_millis u64 LE]`. The paired
//! `wake_snk` consumer computes delivery latency from the embedded
//! timestamp. With `wake: true` on the edge, the write latches the
//! consumer's event-wake bit, so its 200-tick step period is bypassed
//! and the probe is consumed on the next scheduler pass.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts the complete SDK; this probe uses a small subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

const MAGIC: u32 = 0x574b_5031; // "WKP1"

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    out_chan: i32,
    tick: u32,
    /// Steps between probe emits. Default 997 — CO-PRIME with wake_snk's
    /// 200-tick period so emits drift across the period window (a
    /// divisible interval phase-locks onto the due slots and fakes
    /// dt=0). `1` = storm mode (pi5_wake_storm): emit on every step.
    emit_every: u32,
    /// Busy-spin per step in µs (storm mode): inflates the domain's
    /// consumed budget so the woken-path budget bound (RFC
    /// idle_skip_wake §5) is actually exercised.
    burn_us: u32,
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::p_u32;

    define_params! {
        State;

        1, emit_every, u32, 997
            => |s, d, len| { let v = p_u32(d, len, 0, 997); s.emit_every = if v == 0 { 997 } else { v }; };

        2, burn_us, u32, 0
            => |s, d, len| { s.burn_us = p_u32(d, len, 0, 0); };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.tick = 0;
        s.emit_every = 997;
        s.burn_us = 0;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return 0;
        }
        let sys = &*s.syscalls;
        s.tick = s.tick.wrapping_add(1);
        // Storm mode: burn budget before the emit so the domain's
        // consumed time genuinely exceeds its limit and the woken-path
        // bound (RFC idle_skip_wake §5) has something to defer.
        if s.burn_us > 0 {
            let start = dev_micros(sys);
            while dev_micros(sys).saturating_sub(start) < s.burn_us as u64 {
                core::hint::spin_loop();
            }
        }
        // checked_rem: a runtime divisor would otherwise emit a
        // panic_const_rem_by_zero path no_std PIC can't link.
        if s.tick.checked_rem(s.emit_every) != Some(0) {
            return 0;
        }
        let now = dev_millis(sys);
        let mut probe = [0u8; 12];
        probe[..4].copy_from_slice(&MAGIC.to_le_bytes());
        probe[4..12].copy_from_slice(&now.to_le_bytes());
        let rc = (sys.channel_write)(s.out_chan, probe.as_ptr(), probe.len());
        if rc == probe.len() as i32 {
            dev_log(sys, 3, b"[wksrc] emit".as_ptr(), 12);
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
