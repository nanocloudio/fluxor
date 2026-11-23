//! Panel Surface Traits PIC module — bare-metal Surface Traits authority.
//!
//! The bare-metal implementation of the runtime environment plane. A
//! fixed-function panel (a speaker LCD, an instrument display) has a
//! statically-known viewport and a statically-known set of input modalities
//! (e.g. a few physical buttons, maybe a touchscreen), declared in the board
//! graph. This module emits one `input::surface_traits::MSG_TRAITS` record
//! describing that surface, so an application reacts to a buttoned panel the
//! same way it reacts to a browser window — the whole point of the environment
//! plane.
//!
//! It derives orientation + size class from the configured geometry using the
//! contract's own helpers (`abi::contracts::input::surface_traits`), so the
//! thresholds are never duplicated. Modalities + gamepad count are taken
//! verbatim from params (no `/proc`, no DOM on bare metal — the board declares
//! what is wired). The declaration is static: the module emits the one record
//! once the output channel is ready.
//!
//! It also covers the **screenless** case (an rp2350 + I2S speaker, like an
//! iPod Shuffle): set `display_count = 0` and the geometry is irrelevant — the
//! record describes an audio-only device with physical buttons, and a consumer
//! drives it by transport buttons + audio cues, never a screen.
//!
//! Params (PIC schema via fluxor_rt::define_params!, NOT manifest [[params]]):
//!   1 width          (u32) — viewport width px  (ignored when display_count=0)
//!   2 height         (u32) — viewport height px (ignored when display_count=0)
//!   3 modalities     (u32) — input::surface_traits MODALITY_* bitmask
//!   4 gamepad_count  (u32) — attached controllers
//!   5 display_count  (u32) — attached displays; 0 = headless (audio-only)
//!   6 audio_channels (u32) — 0 none, 1 mono, 2 stereo, …
//!   7 audio_rate     (u32) — output sample rate (Hz)
//!   8 dpr_eighths    (u32) — surface pixels per logical pixel, in eighths
//!                            (8 = 1x, 12 = 1.5x, 16 = 2x)
//!
//! `width` and `height` are the viewport in logical pixels; the panel's own
//! pixels are `viewport x dpr_eighths / 8`, the raster a producer renders to
//! be shown 1:1. A board with a dense panel declares the two together. A
//! panel with no display (`display_count = 0`) reports no ratio.
//!
//! Output: 24-byte MSG_TRAITS record (content type `SurfaceTraits`).

#![no_std]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::input::surface_traits as st;

// Default modality set for a typical fixed panel: a key path plus physical
// buttons. Boards override via the `modalities` param.
const DEFAULT_MODALITIES: u32 = (st::MODALITY_KEY | st::MODALITY_PHYSICAL_BUTTONS) as u32;

// One surface pixel per logical pixel unless the board declares a denser
// panel.
const DEFAULT_DPR_EIGHTHS: u32 = st::DPR_1X as u32;

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
    dpr_eighths: u8,
    prev_w_class: u8,
    prev_h_class: u8,
    epoch: u32,
    emitted: bool,
}

mod params_def {
    use super::p_u32;
    use super::PanelState;
    use super::DEFAULT_DPR_EIGHTHS;
    use super::DEFAULT_MODALITIES;

    fluxor_rt::define_params! {
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
        8, dpr_eighths, u32, DEFAULT_DPR_EIGHTHS
            => |s, d, len| {
                // A ratio is 1..=255 eighths; the build refuses any other.
                let v = p_u32(d, len, 0, DEFAULT_DPR_EIGHTHS);
                s.dpr_eighths = if v == 0 || v > 255 { super::st::DPR_1X } else { v as u8 };
            };
    }
}

fluxor_rt::module_facts! { state: PanelState }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
#[allow(clippy::too_many_arguments, reason = "fixed module_new ABI signature")]
pub unsafe extern "C" fn module_new(
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
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    unsafe {
        if state.is_null() {
            return StepReturn::error(-1);
        }
        let s = &mut *(state as *mut PanelState);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return StepReturn::error(-1);
        }
        if s.emitted {
            return StepReturn::Continue;
        }
        let sys = &*s.syscalls;

        // Wait until the output channel can accept the record.
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll <= 0 || ((poll as u32) & POLL_OUT) == 0 {
            return StepReturn::Continue;
        }

        s.prev_w_class = st::size_class_for(s.width, s.prev_w_class);
        s.prev_h_class = st::size_class_for(s.height, s.prev_h_class);
        let orient = st::orientation_for(s.width, s.height);
        s.epoch = s.epoch.wrapping_add(1);

        let buf = st::encode(&st::Traits {
            orientation: orient,
            size_class_w: s.prev_w_class,
            size_class_h: s.prev_h_class,
            viewport_w_px: s.width,
            viewport_h_px: s.height,
            modalities: s.modalities,
            gamepad_count: s.gamepad_count,
            audio_channels: s.audio_channels,
            audio_rate_hz: s.audio_rate,
            epoch: s.epoch,
            authority: st::AUTHORITY_PANEL,
            display_count: s.display_count,
            // A panel with no display has no pixels to state a ratio for.
            dpr_eighths: if s.display_count == st::DISPLAY_HEADLESS {
                st::DPR_UNREPORTED
            } else {
                s.dpr_eighths
            },
        });

        let n = (sys.channel_write)(s.out_chan, buf.as_ptr(), buf.len());
        if n == buf.len() as i32 {
            s.emitted = true;
        }
        StepReturn::Continue
    }
}

fluxor_rt::wasm_entry!();
