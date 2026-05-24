//! USB-MIDI class host — SCAFFOLD.
//!
//! Enumerates a class-compliant USB-MIDI device on a host-mode USB
//! controller, claims its MIDI Streaming interface, and bridges its
//! virtual cables to the `input::midi` 4-byte frame surface (see
//! `modules/sdk/contracts/input/midi.rs`).
//!
//! `mode: in` emits frames on `events_out`; `mode: out` consumes
//! frames on `events_in`; `mode: duplex` does both. The stack
//! `stacks/midi.toml` selects this module on pico2w / picow / cm5
//! targets via `platform.midi: {direction: ...}`.
//!
//! Status: **scaffold only**. The module compiles, packs to `.fmod`,
//! loads cleanly, and validates against the `usb_host` contract — but
//! the runtime is a no-op. Real implementation requires:
//!
//!   1. A USB host controller driver on the target silicon (the
//!      RP2350 has an OTG controller exposed via embassy-rp's device
//!      side; the host side does not exist yet. BCM2712 / CM5 uses
//!      DesignWare DWC2 — also absent.).
//!   2. Kernel-side `provider::contract::USB_HOST` vtable wiring
//!      `BIND` / `OPEN_ENDPOINT` / `BULK_READ` / `BULK_WRITE` /
//!      `INTERRUPT_POLL` / `RELEASE` (constant is allocated; no
//!      handlers registered).
//!   3. The actual MIDI Streaming class enumerator + USB-MIDI event-
//!      packet (`[cable<<4 | CIN] [status] [d1] [d2]`) → input::midi
//!      4-byte frame translator. Lucky alignment: the USB-MIDI wire
//!      shape is one byte different from `input::midi`'s — see
//!      `frame_from_usb_midi_packet` (TODO).
//!
//! **Params** (declared via `define_params!` below — PIC modules
//! embed schema in Rust, not TOML `[[params]]`):
//!
//!   1. `mode` (enum, default `in`) — `in` | `out` | `duplex`
//!   2. `usb_bus` (u8, default 0) — selects host controller index
//!   3. `device_filter` (str, default empty) — substring match on
//!      device descriptor's iProduct string; empty selects the
//!      first device claiming the MIDI Streaming class.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]


use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// State
// ============================================================================

const MAX_DEVICE_FILTER: usize = 32;

#[repr(C)]
struct UsbMidiHostState {
    syscalls: *const SyscallTable,

    /// Output port (mode in/duplex). -1 when unbound.
    events_out: i32,
    /// Input port (mode out/duplex). -1 when unbound.
    events_in: i32,

    // Params
    mode: u8,
    usb_bus: u8,
    device_filter_len: u8,
    _pad0: u8,
    device_filter: [u8; MAX_DEVICE_FILTER],

    // Runtime
    step_count: u32,
    /// 0 = STUB warning not yet emitted; 1 = emitted. The host
    /// runtime logs a one-shot warning the first time `module_step`
    /// runs so the unimplemented state is visible at boot.
    warned: u8,
    _pad1: [u8; 3],
}

// ============================================================================
// Param schema
// ============================================================================

mod params_def {
    use super::UsbMidiHostState;
    use super::MAX_DEVICE_FILTER;
    use super::SCHEMA_MAX;
    use super::p_u8;

    define_params! {
        UsbMidiHostState;

        1, mode, u8, 0, enum { in=0, out=1, duplex=2 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        2, usb_bus, u8, 0
            => |s, d, len| { s.usb_bus = p_u8(d, len, 0, 0); };

        3, device_filter, str, 0
            => |s, d, len| {
                let n = if len > MAX_DEVICE_FILTER { MAX_DEVICE_FILTER } else { len };
                let mut i = 0usize;
                while i < n { s.device_filter[i] = *d.add(i); i += 1; }
                s.device_filter_len = n as u8;
            };
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<UsbMidiHostState>() as u32
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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<UsbMidiHostState>() {
            return -3;
        }

        let s = &mut *(state as *mut UsbMidiHostState);
        s.syscalls = syscalls as *const SyscallTable;
        s.events_in = in_chan;
        s.events_out = out_chan;
        s.mode = 0;
        s.usb_bus = 0;
        s.device_filter_len = 0;
        s.device_filter = [0u8; MAX_DEVICE_FILTER];
        s.step_count = 0;
        s.warned = 0;

        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }

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
        let s = &mut *(state as *mut UsbMidiHostState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;

        // One-shot STUB warning on first step. Visible at runtime so
        // a user running `examples/midi_echo/pico2w.yaml` (or any
        // graph wiring `usb_midi_host`) sees the unimplemented state.
        if s.warned == 0 {
            let msg = b"[usb_midi_host] STUB - USB host stack not yet implemented; module is a no-op";
            dev_log(sys, 3, msg.as_ptr(), msg.len());
            s.warned = 1;
        }

        // Drain `events_in` so a producer wired to `mode = out` or
        // `duplex` doesn't backpressure into a black hole while the
        // implementation is pending. Reads are discarded. Capped at
        // 256 bytes (64 MIDI frames) per step to bound the CPU a
        // runaway producer can steal from other modules in the same
        // domain. `mode == 0` is input-only — events_in is unbound
        // (-1) in that case and the guard skips the read.
        if s.events_in >= 0 {
            let mut scratch = [0u8; 256];
            let _ = (sys.channel_read)(s.events_in, scratch.as_mut_ptr(), scratch.len());
        }

        s.step_count = s.step_count.wrapping_add(1);
        0
    }
}
