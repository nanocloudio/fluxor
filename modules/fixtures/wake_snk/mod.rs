//! Wake-latency probe SINK (wake-on-write silicon AC, RFC
//! idle_skip_wake).
//!
//! Period-gated (manifest `step_period_ticks = 200`). Each step reads
//! one probe from `in` (writes wake it once per probe, so one read per
//! step keeps pace); on a valid probe (`[magic u32][dev_millis u64]`
//! from wake_src) it logs `[wksnk] dt_ms=<n> fast=<0|1>` where
//! `fast = dt < 50 ms`. With `wake: true` on the edge, every delivery
//! is `fast=1` (the wake bypasses the period gate and the probe is
//! consumed on the next pass); without it, delivery waits for the next
//! 200-tick period slot (`fast=0`, dt up to ~800 ms at tick_us=4000).

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

const MAGIC: u32 = 0x574b_5031; // "WKP1"
const FAST_MS: u64 = 50;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    steps: u32,
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
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
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
        s.in_chan = in_chan;
        s.steps = 0;
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
        if s.syscalls.is_null() || s.in_chan < 0 {
            return 0;
        }
        let sys = &*s.syscalls;
        // Step-rate diagnostic: if the 200-tick period gate binds, this
        // fires roughly every 250×200 ticks; if the module is being
        // stepped every pass, it fires every 250 passes (~1 s at
        // tick_us=4000) — separates "gated but woken" from "never
        // gated" without kernel instrumentation.
        s.steps = s.steps.wrapping_add(1);
        if s.steps % 250 == 0 {
            dev_log(sys, 3, b"[wksnk] hb250".as_ptr(), 13);
        }
        let mut buf = [0u8; 12];
        let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
        if n < 12 {
            return 0;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return 0;
        }
        let sent = u64::from_le_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        let now = dev_millis(sys);
        // A zeroed clock (e.g. the timer contract call failing ENOSYS
        // because `[[resources]]` didn't declare it) would fake dt=0
        // and make every delivery look instant — fail loudly instead.
        if now == 0 || sent == 0 {
            dev_log(sys, 1, b"[wksnk] clock_dead".as_ptr(), 18);
            return 0;
        }
        let dt = now.saturating_sub(sent);

        // "[wksnk] dt_ms=<n> fast=<0|1>" — hand-rolled digits (no fmt in
        // no_std PIC). 20 digit slots cover the full u64 range.
        let mut msg = [0u8; 48];
        let prefix = b"[wksnk] dt_ms=";
        msg[..prefix.len()].copy_from_slice(prefix);
        let mut len = prefix.len();
        let mut digits = [0u8; 20];
        let mut d = 0usize;
        let mut v = dt;
        loop {
            digits[d] = b'0' + (v % 10) as u8;
            d += 1;
            v /= 10;
            if v == 0 || d >= digits.len() {
                break;
            }
        }
        while d > 0 {
            d -= 1;
            msg[len] = digits[d];
            len += 1;
        }
        let tail: &[u8] = if dt < FAST_MS {
            b" fast=1"
        } else {
            b" fast=0"
        };
        msg[len..len + tail.len()].copy_from_slice(tail);
        len += tail.len();
        dev_log(sys, 3, msg.as_ptr(), len);
        0
    }
}

include!("../../sdk/wasm_entry.rs");
