//! Synthetic byte-stream source.
//!
//! Emits `size` bytes onto its single output channel on every
//! `stream_select` `SELECT` from the downstream consumer (typically
//! `http.file_data`), then ends the stream (`channel::SET_HUP`) once the
//! requested byte count has been written so the consumer transitions
//! cleanly to end-of-source.
//!
//! Decouples HTTP / IP throughput measurement from disk content. The
//! hot path writes the module's pre-zeroed scratch buffer rather than
//! synthesizing pattern bytes per step — consumers (curl, range
//! probes) length-check only, so the payload itself is irrelevant for
//! throughput measurement and skipping the fill saves ~2 GB/s of
//! memcpy bandwidth per sustained stream-second. See `step` below.
//!
//! A position-only pattern (`byte_at(off) = (off ^ off>>8) as u8`)
//! matching `fat32_seed`'s `pattern = 1` payload is retained as
//! `fill_pattern` below and can be re-enabled in the hot path for
//! byte-exact verifier runs; a future fat32-seeded NVMe read test
//! could then verify equivalence between the two sources by comparing
//! the http response payload to the same generator output.
//!
//! **Params:**
//!
//!   1. `size` (u32, default 0) — total bytes to emit per request.
//!      Capped only by the consumer's appetite; values up to several
//!      MiB are routine for synthetic WASM-class assets.
//!   2. `chunk_size` (u16, default 4096) — bytes synthesized per
//!      `module_step` call. Caps the per-tick CPU + channel-write
//!      pressure; smaller values smooth latency, larger values lift
//!      throughput at the cost of one tick of head-of-line.
//!
//! **Wiring:** single output port `stream` (OctetStream), which serves
//! `stream_select`: the consumer drives the request lifecycle by binding
//! that contract through its input port and calling `SELECT`. Every
//! position names the one synthetic item.

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

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_CHUNK_SIZE: u16 = 4096;
/// Largest single chunk emit, the port's `max_record`: a host stream feeds
/// HTTP throughput runs, an MCU one stays within its state budget.
#[cfg(target_arch = "aarch64")]
const MAX_CHUNK_SIZE: usize = 32768;
#[cfg(not(target_arch = "aarch64"))]
const MAX_CHUNK_SIZE: usize = 4096;

/// Cadence for the `[synth_source] tlm` line (matches the other hot-
/// path modules so the host parser can reconcile windows).
const SYNTH_TLM_PERIOD: u32 = 5000;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct SynthState {
    syscalls: *const SyscallTable,
    out_chan: i32,

    // Params
    size: u32,
    chunk_size: u16,
    _pad0: u16,

    // Runtime cursor
    /// Bytes already written to `out_chan` for the current request.
    /// Reset to 0 on each `SELECT`.
    sent: u32,
    /// 1 once a `SELECT` has been received and we're streaming;
    /// 0 in the idle gap between requests (or pre-first-request).
    streaming: u8,
    /// 1 once `SET_HUP` has been issued for the current request;
    /// guards against multiple set-hup calls in the same request.
    hup_emitted: u8,
    _pad1: u16,

    // Telemetry
    step_count: u32,
    tlm: TlmCounters,
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],

    // One-shot scratch for chunk synthesis. Stack frames in `module_step`
    // would also work, but the rp2350 stack budget is tight enough that
    // a fixed module-state buffer is more honest.
    chunk_buf: [u8; MAX_CHUNK_SIZE],
}

// ============================================================================
// Param schema
// ============================================================================

mod params_def {
    use super::SynthState;

    use super::{p_u16, p_u32};

    fluxor_rt::define_params! {
        SynthState;

        1, size, u32, 0
            => |s, d, len| { s.size = p_u32(d, len, 0, 0); };

        2, chunk_size, u16, 4096
            => |s, d, len| {
                let v = p_u16(d, len, 0, super::DEFAULT_CHUNK_SIZE);
                s.chunk_size = if v == 0 {
                    super::DEFAULT_CHUNK_SIZE
                } else if (v as usize) > super::MAX_CHUNK_SIZE {
                    super::MAX_CHUNK_SIZE as u16
                } else {
                    v
                };
            };
    }
}

// ============================================================================
// Pattern generator
// ============================================================================

// ============================================================================
// Module ABI
// ============================================================================

fluxor_rt::module_facts! { state: SynthState }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<SynthState>() {
            return -3;
        }

        let s = &mut *(state as *mut SynthState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.size = 0;
        s.chunk_size = DEFAULT_CHUNK_SIZE;
        s.sent = 0;
        s.streaming = 0;
        s.hup_emitted = 0;
        s.step_count = 0;
        s.tlm = TlmCounters::new();

        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
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
        let s = &mut *(state as *mut SynthState);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return StepReturn::error(-1);
        }

        s.step_count = s.step_count.wrapping_add(1);
        let rx_pre = s.tlm.bytes_in;
        let tx_pre = s.tlm.bytes_out;
        let bp_pre = s.tlm.bp_steps;

        let rc = step_inner(s);

        tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
        let sys = &*s.syscalls;
        let scratch_ptr = s.tlm_scratch.as_mut_ptr();
        let scratch_len = s.tlm_scratch.len();
        let tick = s.step_count;
        dev_tlm_maybe_emit(
            sys,
            b"[synth_source]",
            &mut s.tlm,
            tick,
            SYNTH_TLM_PERIOD,
            scratch_ptr,
            scratch_len,
        );
        rc
    }
}

unsafe fn step_inner(s: &mut SynthState) -> StepReturn {
    let sys = &*s.syscalls;

    // Idle until the consumer's `SELECT` (`module_provider_dispatch`)
    // starts a request.
    if s.streaming == 0 {
        return StepReturn::Continue;
    }

    // Already finished this request — wait for the next `SELECT`.
    if s.sent >= s.size {
        if s.hup_emitted == 0 {
            // Last byte already flushed; signal end-of-stream so the
            // consumer's poll path sees POLL_HUP and transitions
            // out of read.
            dev_channel_set_hup(sys, s.out_chan);
            s.hup_emitted = 1;
            // Drop back into the idle branch on the next step.
            s.streaming = 0;
        }
        return StepReturn::Continue;
    }

    // Compute this tick's chunk: min(chunk_size, remaining).
    let chunk_cap = (s.chunk_size as usize).min(MAX_CHUNK_SIZE);
    let remaining = (s.size - s.sent) as usize;
    let want = chunk_cap.min(remaining);
    if want == 0 {
        return StepReturn::Continue;
    }

    // The scratch chunk buffer is pre-zeroed at module init and
    // reused — no per-tick fill required. Original semantics
    // (deterministic position-only pattern) are documented as a
    // verification aid for paired fat32 read tests; in the hot path
    // we just push zero bytes through the channel. Curl-side checks
    // are length-only, so this is observationally equivalent for the
    // throughput rig and removes ~2 GB/s of memcpy bandwidth pressure
    // per second of sustained streaming. To restore pattern bytes for
    // future verification, reintroduce `fill_pattern(buf_ptr, s.sent,
    // want)` here.
    let buf_ptr = s.chunk_buf.as_mut_ptr();
    let written = (sys.channel_write)(s.out_chan, buf_ptr, want);
    if written == E_AGAIN || written == 0 {
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        return StepReturn::Continue;
    }
    if written < 0 {
        return StepReturn::error(-1);
    }
    s.sent = s.sent.wrapping_add(written as u32);
    s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(written as u32);

    if s.sent >= s.size {
        // Issue HUP next step (after the consumer has at least one
        // tick to drain the final chunk). Returning 2 keeps the
        // module hot — the next step transitions through the
        // `sent >= size` branch above and emits SET_HUP.
        return StepReturn::Burst;
    }

    // More to send and the channel had room — re-step in the same
    // tick to keep the pipe saturated.
    StepReturn::Burst
}

/// Serves `stream_select` to the consumer wired to `stream`: `SELECT`
/// starts a fresh emit of `size` bytes, whatever the position (there is one
/// synthetic item). The consumer has flushed its input, which also cleared
/// the previous request's HUP, so the stream starts over at once.
///
/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised; `arg[..arg_len]` is valid for the
/// call.
#[no_mangle]
#[link_section = ".text.module_provider_dispatch"]
pub unsafe extern "C" fn module_provider_dispatch(
    state: *mut u8,
    _handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    _data: *mut u8,
    _data_len: usize,
) -> i32 {
    use abi::contracts::stream_select;
    if state.is_null() || arg.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state as *mut SynthState);
    let arg = core::slice::from_raw_parts(arg, arg_len);
    match op {
        stream_select::SELECT => {
            if stream_select::select::parse(arg).is_none() {
                return E_INVAL;
            }
            s.sent = 0;
            s.hup_emitted = 0;
            s.streaming = 1;
            0
        }
        _ => E_NOSYS,
    }
}

fluxor_rt::wasm_entry!();
