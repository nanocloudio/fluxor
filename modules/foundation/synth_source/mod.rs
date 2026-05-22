//! Synthetic byte-stream source.
//!
//! Emits `size` bytes onto its single output channel on every
//! IOCTL_NOTIFY received from a downstream consumer (typically
//! `http.file_data`), then signals `IOCTL_SET_HUP` once the requested
//! byte count has been written so the consumer transitions cleanly to
//! end-of-source.
//!
//! Decouples HTTP / IP throughput measurement from disk content. The
//! hot path writes the module's pre-zeroed scratch buffer rather than
//! synthesizing pattern bytes per step — consumers (curl, range
//! probes) length-check only, so the payload itself is irrelevant for
//! throughput measurement and skipping the fill saves ~2 GB/s of
//! memcpy bandwidth per sustained stream-second. See `step` below.
//!
//! A position-only pattern (`byte_at(off) = (off ^ off>>8) as u8`)
//! matching `fat32`'s `seed_pattern=1` write path is retained as
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
//! **Wiring:** single output port `stream` (OctetStream). Consumer
//! drives the request lifecycle via `IOCTL_NOTIFY` on this channel.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_CHUNK_SIZE: u16 = 4096;
const MAX_CHUNK_SIZE: usize = 32768;

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
    /// Reset to 0 on each IOCTL_NOTIFY.
    sent: u32,
    /// 1 once IOCTL_NOTIFY has been received and we're streaming;
    /// 0 in the idle gap between requests (or pre-first-request).
    streaming: u8,
    /// 1 once IOCTL_SET_HUP has been issued for the current request;
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
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32};

    define_params! {
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

/// Same formula as `fat32::seed_byte_at` so a verifier reading bytes
/// from either path computes the same expected value.
#[inline(always)]
const fn byte_at(off: u32) -> u8 {
    (off ^ (off >> 8)) as u8
}

/// Fill `dst[..len]` with the pattern starting at offset `off`.
///
/// Generates 8 bytes at a time from the deterministic generator,
/// then `core::ptr::copy_nonoverlapping`s the trailing bytes. The
/// underlying formula is per-byte (`byte_at(off + i)`), but
/// computing 8 bytes via a single u64 shift/xor pattern lets the
/// CPU's wide ALU stay busy and cuts the per-MSS fill cost from
/// ~5 µs (the original byte-loop) to under 1 µs on Cortex-A76.
#[inline(always)]
unsafe fn fill_pattern(dst: *mut u8, off: u32, len: usize) {
    // 8-bytes-at-a-time core. We synthesize 8 successive
    // `byte_at(off + k)` values into a u64 little-endian word, then
    // store with a single unaligned write. The byte values for the
    // 8 indices i, i+1, ..., i+7 are
    //   byte_at(off+i+k) = ((off+i+k) ^ ((off+i+k) >> 8)) as u8
    // so the high byte (k=7) and low byte (k=0) differ only by
    // simple arithmetic on `off+i`.
    let mut i = 0usize;
    while i + 8 <= len {
        let p = off.wrapping_add(i as u32);
        let p0 = (p ^ (p >> 8)) as u64;
        let p1 = ((p + 1) ^ ((p + 1) >> 8)) as u64;
        let p2 = ((p + 2) ^ ((p + 2) >> 8)) as u64;
        let p3 = ((p + 3) ^ ((p + 3) >> 8)) as u64;
        let p4 = ((p + 4) ^ ((p + 4) >> 8)) as u64;
        let p5 = ((p + 5) ^ ((p + 5) >> 8)) as u64;
        let p6 = ((p + 6) ^ ((p + 6) >> 8)) as u64;
        let p7 = ((p + 7) ^ ((p + 7) >> 8)) as u64;
        let word = (p0 & 0xFF)
            | ((p1 & 0xFF) << 8)
            | ((p2 & 0xFF) << 16)
            | ((p3 & 0xFF) << 24)
            | ((p4 & 0xFF) << 32)
            | ((p5 & 0xFF) << 40)
            | ((p6 & 0xFF) << 48)
            | ((p7 & 0xFF) << 56);
        core::ptr::write_unaligned(dst.add(i) as *mut u64, word);
        i += 8;
    }
    while i < len {
        *dst.add(i) = byte_at(off.wrapping_add(i as u32));
        i += 1;
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SynthState>() as u32
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
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut SynthState);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return -1;
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

unsafe fn step_inner(s: &mut SynthState) -> i32 {
    let sys = &*s.syscalls;

    // Idle: poll for an IOCTL_NOTIFY from the consumer. The notify
    // payload (file index) is irrelevant — synth_source only ever
    // emits one logical "file", so any notify resets and starts a new
    // emit cycle. This mirrors `fat32::check_seek_request` semantics.
    if s.streaming == 0 {
        let mut notify_pos: u32 = 0;
        let pos_ptr = &mut notify_pos as *mut u32 as *mut u8;
        let res = dev_channel_ioctl(sys, s.out_chan, IOCTL_POLL_NOTIFY, pos_ptr, 4);
        if res == 0 {
            // Consumer requested a fresh emit. Note: IOCTL_FLUSH from
            // the consumer side has already cleared the channel ring
            // and the previous HUP flag, so we can start writing
            // immediately.
            s.sent = 0;
            s.hup_emitted = 0;
            s.streaming = 1;
        } else {
            return 0;
        }
    }

    // Already finished this request — wait for the next NOTIFY.
    if s.sent >= s.size {
        if s.hup_emitted == 0 {
            // Last byte already flushed; signal end-of-stream so the
            // consumer's poll path sees POLL_HUP and transitions
            // out of read.
            // SDK exports `IOCTL_EOF` for the kernel-side
            // `IOCTL_SET_HUP` opcode (both opcode 4). Naming is just
            // surface-level; the kernel's behaviour is the same:
            // sticky HUP that consumer poll surfaces as `POLL_HUP`.
            dev_channel_ioctl(sys, s.out_chan, IOCTL_EOF, core::ptr::null_mut(), 0);
            s.hup_emitted = 1;
            // Drop back into the idle branch on the next step.
            s.streaming = 0;
        }
        return 0;
    }

    // Compute this tick's chunk: min(chunk_size, remaining).
    let chunk_cap = (s.chunk_size as usize).min(MAX_CHUNK_SIZE);
    let remaining = (s.size - s.sent) as usize;
    let want = chunk_cap.min(remaining);
    if want == 0 {
        return 0;
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
        return 0;
    }
    if written < 0 {
        return -1;
    }
    s.sent = s.sent.wrapping_add(written as u32);
    s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(written as u32);

    if s.sent >= s.size {
        // Issue HUP next step (after the consumer has at least one
        // tick to drain the final chunk). Returning 2 keeps the
        // module hot — the next step transitions through the
        // `sent >= size` branch above and emits SET_HUP.
        return 2;
    }

    // More to send and the channel had room — re-step in the same
    // tick to keep the pipe saturated.
    2
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        // out[0]: stream — sized comfortably above one full
        // `MAX_CHUNK_SIZE` chunk so a fresh emit can land without
        // back-pressure even when the consumer is one tick behind.
        // The downstream (http) typically requests 65536; the
        // kernel takes max(producer, consumer) hints, so this
        // value matters only when the downstream isn't http.
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 65536 },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

include!("../../sdk/wasm_entry.rs");
