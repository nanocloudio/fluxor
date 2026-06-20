//! Panel Surface Traits PIC module — bare-metal Surface Traits authority.
//!
//! The bare-metal implementation of the runtime environment plane
//! (`.context/rfc_surface_traits.md`). A fixed-function panel (a speaker LCD, an
//! instrument display) has a statically-known viewport and a statically-known
//! set of input modalities (e.g. a few physical buttons, maybe a touchscreen),
//! declared in the board graph. This module emits one
//! `input::surface_traits::MSG_TRAITS` record describing that surface, so an
//! application reacts to a buttoned panel the same way it reacts to a browser
//! window — the whole point of the environment plane.
//!
//! It derives orientation + size class from the configured geometry using the
//! contract's own helpers (`abi::contracts::input::surface_traits`), so the
//! thresholds are never duplicated. Modalities + gamepad count are taken
//! verbatim from params (no `/proc`, no DOM on bare metal — the board declares
//! what is wired). A USB-gamepad hot-plug path would later bump the epoch; v1
//! is a static declaration and emits the baseline once the output channel is
//! ready.
//!
//! It also covers the **screenless** case (an rp2350 + I2S speaker, like an
//! iPod Shuffle): set `display_count = 0` and the geometry is irrelevant — the
//! record describes an audio-only device with physical buttons, and a consumer
//! drives it by transport buttons + audio cues, never a screen.
//!
//! Params (PIC schema via define_params!, NOT manifest [[params]]):
//!   1 width          (u32) — viewport width px  (ignored when display_count=0)
//!   2 height         (u32) — viewport height px (ignored when display_count=0)
//!   3 modalities     (u32) — input::surface_traits MODALITY_* bitmask
//!   4 gamepad_count  (u32) — attached controllers
//!   5 display_count  (u32) — attached displays; 0 = headless (audio-only)
//!   6 audio_channels (u32) — 0 none, 1 mono, 2 stereo, …
//!   7 audio_rate     (u32) — output sample rate (Hz)
//!
//! Output: 24-byte MSG_TRAITS record (content type `SurfaceTraits`).

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

use abi::contracts::input::surface_traits as st;

const EVENT_RECORD: usize = 24;

// Default modality set for a typical fixed panel: a key path plus physical
// buttons. Boards override via the `modalities` param.
const DEFAULT_MODALITIES: u32 = (st::MODALITY_KEY | st::MODALITY_PHYSICAL_BUTTONS) as u32;

#[repr(C)]
struct PanelState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    width: u16,
    height: u16,
    modalities: u16,
    gamepad_count: u8,
    display_count: u8,
    audio_channels: u8,
    audio_rate: u32,
    prev_w_class: u8,
    prev_h_class: u8,
    epoch: u32,
    emitted: bool,
}

mod params_def {
    use super::p_u32;
    use super::PanelState;
    use super::{DEFAULT_MODALITIES, SCHEMA_MAX};

    define_params! {
        PanelState;

        1, width, u32, 800
            => |s, d, len| { s.width = p_u32(d, len, 0, 800) as u16; };
        2, height, u32, 480
            => |s, d, len| { s.height = p_u32(d, len, 0, 480) as u16; };
        3, modalities, u32, DEFAULT_MODALITIES
            => |s, d, len| { s.modalities = p_u32(d, len, 0, DEFAULT_MODALITIES) as u16; };
        4, gamepad_count, u32, 0
            => |s, d, len| { s.gamepad_count = p_u32(d, len, 0, 0) as u8; };
        5, display_count, u32, 1
            => |s, d, len| { s.display_count = p_u32(d, len, 0, 1) as u8; };
        6, audio_channels, u32, 0
            => |s, d, len| { s.audio_channels = p_u32(d, len, 0, 0) as u8; };
        7, audio_rate, u32, 0
            => |s, d, len| { s.audio_rate = p_u32(d, len, 0, 0); };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<PanelState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
#[allow(clippy::too_many_arguments, reason = "fixed module_new ABI signature")]
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
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<PanelState>() {
            return -2;
        }
        let s = &mut *(state as *mut PanelState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.prev_w_class = st::SIZE_REGULAR;
        s.prev_h_class = st::SIZE_REGULAR;
        s.epoch = 0;
        s.emitted = false;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
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
        let s = &mut *(state as *mut PanelState);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return -1;
        }
        if s.emitted {
            return 0;
        }
        let sys = &*s.syscalls;

        // Wait until the output channel can accept the record.
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll <= 0 || ((poll as u32) & POLL_OUT) == 0 {
            return 0;
        }

        s.prev_w_class = st::size_class_for(s.width, s.prev_w_class);
        s.prev_h_class = st::size_class_for(s.height, s.prev_h_class);
        let orient = st::orientation_for(s.width, s.height);
        s.epoch = s.epoch.wrapping_add(1);

        let mut buf = [0u8; EVENT_RECORD];
        buf[0] = st::MSG_TRAITS;
        buf[1] = orient;
        buf[2] = s.prev_w_class;
        buf[3] = s.prev_h_class;
        buf[4..6].copy_from_slice(&s.width.to_le_bytes());
        buf[6..8].copy_from_slice(&s.height.to_le_bytes());
        buf[8..10].copy_from_slice(&s.modalities.to_le_bytes());
        buf[10] = s.gamepad_count;
        buf[11] = s.audio_channels;
        buf[12..16].copy_from_slice(&s.audio_rate.to_le_bytes());
        buf[16..20].copy_from_slice(&s.epoch.to_le_bytes());
        buf[20] = st::AUTHORITY_PANEL;
        buf[21] = s.display_count;
        buf[22] = 0;
        buf[23] = 0;

        let n = (sys.channel_write)(s.out_chan, buf.as_ptr(), EVENT_RECORD);
        if n == EVENT_RECORD as i32 {
            s.emitted = true;
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [ChannelHint {
        port_type: 1,
        port_index: 0,
        buffer_size: 64,
    }];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

include!("../../sdk/wasm_entry.rs");
