//! Unified Audio Decoder PIC Module
//!
//! Detects audio format from stream header and decodes accordingly.
//! Supports WAV (PCM), MP3 (MPEG-1 Layer III), and AAC (ADTS-framed).
//!
//! # Format Detection
//!
//! First bytes of input determine codec:
//! - `RIFF` (4 bytes) → WAV
//! - `0xFF 0xFB/FA/F3/F2` (MPEG sync) → MP3
//! - `ID3` (3 bytes) → MP3 (ID3 tag, then MPEG sync)
//! - `0xFF 0xF0/F1/F8/F9` (ADTS sync) → AAC
//!
//! # Stream Reset
//!
//! When bank switches files, it flushes the data channel. The decoder
//! detects stream end (codec returns done or sync loss) and resets to
//! format detection for the next file.
//!
//! # State Layout
//!
//! DecoderState wraps a codec union (byte array sized to largest codec).
//! Only one codec is active at a time.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

mod wav_codec;

mod mp3_codec;

mod aac_codec;

// ============================================================================
// Constants
// ============================================================================

/// Format tags
const FMT_DETECTING: u8 = 0;
const FMT_WAV: u8 = 1;
const FMT_MP3: u8 = 2;
const FMT_AAC: u8 = 3;
const FMT_IMAGE: u8 = 4;


/// Detection buffer size — enough to identify any format
const DETECT_BUF_SIZE: usize = 16;

/// IO buffer for detection phase reads
const DETECT_IO_SIZE: usize = 256;

/// Number of consecutive scheduler ticks with `POLL_IN` clear and
/// `POLL_HUP` set that the decoder waits before resetting to format-
/// detection mode. Sized to cover the codec emitting at most one
/// full AAC frame's PCM out of its internal output buffer
/// (1024 stereo i16 = 4096 B, emitted in one channel_write per tick
/// in the current AAC IO_BUF_SIZE) plus a small safety margin.
const HUP_QUIESCE_TICKS: u8 = 64;

/// Codec state buffer size — must be >= largest codec state
const CODEC_STATE_SIZE: usize = {
    let wav_size = core::mem::size_of::<wav_codec::WavState>();
    let mp3_size = core::mem::size_of::<mp3_codec::Mp3State>();
    let aac_size = core::mem::size_of::<aac_codec::AacState>();
    // Manual max of three values (const context)
    let mut max = wav_size;
    if mp3_size > max { max = mp3_size; }
    if aac_size > max { max = aac_size; }
    // Align up to 4 bytes
    (max + 3) & !3
};

// ============================================================================
// State
// ============================================================================

/// Wrapper guaranteeing 8-byte alignment of the codec state buffer.
///
/// AacState/Mp3State/WavState all start with `*const SyscallTable`,
/// which on aarch64 / wasm32 / x86_64 needs 8-byte alignment for the
/// load. A bare `[u8; N]` field has alignment 1, so reinterpreting it
/// as one of those structs at an arbitrary `[u8]` offset SIGBUSes on
/// strict-alignment targets (aarch64). The `align(8)` newtype forces
/// the buffer to land on an 8-byte boundary inside `DecoderState`.
#[repr(C, align(8))]
struct CodecBuf([u8; CODEC_STATE_SIZE]);

#[repr(C)]
struct DecoderState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// Active format: 0=detecting, 1=wav, 2=mp3, 3=aac
    format: u8,
    /// Number of bytes in detect_buf
    detect_len: u8,
    /// Consecutive empty reads (for stream-end detection)
    empty_reads: u8,
    /// Consecutive ticks observed with `HUP set & POLL_IN clear` since
    /// the upstream signalled EOF. Reset is deferred until this counter
    /// reaches `HUP_QUIESCE_TICKS` so the codec gets a chance to finish
    /// emitting any PCM that was already decoded but hadn't been
    /// channel_write'd to its consumer yet. Without this delay, the
    /// browser harness lost ~250 ms of audio (last 2 notes of the
    /// 8-note scale) because `host_browser_fetch` HUPs as soon as the
    /// response body is fully drained — even though the channel ring
    /// still had ~10 AAC frames buffered for the codec to decode.
    hup_quiet_ticks: u8,
    /// Header accumulation buffer for format detection
    detect_buf: [u8; DETECT_BUF_SIZE],
    /// IO buffer used during detection phase
    detect_io: [u8; DETECT_IO_SIZE],
    /// Codec state — overlay for WavState/Mp3State/AacState
    codec: CodecBuf,
}

impl DecoderState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }

    #[inline(always)]
    unsafe fn wav(&mut self) -> &mut wav_codec::WavState {
        &mut *(self.codec.0.as_mut_ptr() as *mut wav_codec::WavState)
    }

    #[inline(always)]
    unsafe fn mp3(&mut self) -> &mut mp3_codec::Mp3State {
        &mut *(self.codec.0.as_mut_ptr() as *mut mp3_codec::Mp3State)
    }

    #[inline(always)]
    unsafe fn aac(&mut self) -> &mut aac_codec::AacState {
        &mut *(self.codec.0.as_mut_ptr() as *mut aac_codec::AacState)
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::DecoderState;
    use super::SCHEMA_MAX;

    define_params! {
        DecoderState;
    }
}

// ============================================================================
// Format Detection
// ============================================================================

/// Attempt to identify the audio format from accumulated bytes.
/// Returns FMT_* constant, or FMT_DETECTING if more bytes needed.
fn detect_format(buf: &[u8; DETECT_BUF_SIZE], len: u8) -> u8 {
    let n = len as usize;
    if n < 2 {
        return FMT_DETECTING;
    }

    // Check for RIFF/WAV (4 bytes)
    if n >= 4 && buf[0] == b'R' && buf[1] == b'I' && buf[2] == b'F' && buf[3] == b'F' {
        return FMT_WAV;
    }

    // Check for ID3 tag (MP3 with ID3v2 header)
    if n >= 3 && buf[0] == b'I' && buf[1] == b'D' && buf[2] == b'3' {
        return FMT_MP3;
    }

    // Check MPEG/ADTS sync word (0xFF followed by frame info)
    if buf[0] == 0xFF {
        let b1 = buf[1];

        // MPEG sync: 0xFF followed by 0xE0+ (11 sync bits set)
        // Layer III: bits 1-2 of second byte = 01
        // MPEG-1: bit 3 = 1
        // Common MP3 second bytes: 0xFB (MPEG1 Layer3 no CRC),
        // 0xFA (MPEG1 Layer3 CRC), 0xF3 (MPEG2 Layer3 no CRC),
        // 0xF2 (MPEG2 Layer3 CRC)
        if (b1 & 0xE0) == 0xE0 {
            let layer = (b1 >> 1) & 0x03;
            if layer == 0x01 {
                // Layer III = MP3
                return FMT_MP3;
            }
        }

        // ADTS sync: 0xFFF followed by 0 or 1 (ID bit)
        // Second byte: 0xF0, 0xF1, 0xF8, 0xF9
        if (b1 & 0xF0) == 0xF0 && (b1 & 0x06) == 0x00 {
            // This is ADTS (AAC)
            return FMT_AAC;
        }
    }

    // If we have enough bytes and still can't identify, give up
    if n >= 8 {
        // Unknown format — default to treating as raw PCM (WAV passthrough)
        // This is a fallback; in practice, bank only sends known formats
        return FMT_WAV;
    }

    FMT_DETECTING
}

/// Reset decoder to format detection state.
unsafe fn reset_to_detect(s: &mut DecoderState) {
    s.format = FMT_DETECTING;
    s.detect_len = 0;
    s.empty_reads = 0;
    s.hup_quiet_ticks = 0;
    // Zero the codec state
    __aeabi_memclr(s.codec.0.as_mut_ptr(), CODEC_STATE_SIZE);
}

/// Initialize the detected codec and feed it the detection bytes.
unsafe fn init_codec(s: &mut DecoderState) {
    let syscalls = s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;
    let detect_len = s.detect_len as usize;
    // Take raw pointer to detect_buf before borrowing codec via &mut
    let detect_ptr = s.detect_buf.as_ptr();
    let codec_ptr = s.codec.0.as_mut_ptr();

    match s.format {
        FMT_WAV => {
            let ws = &mut *(codec_ptr as *mut wav_codec::WavState);
            wav_codec::wav_init(ws, syscalls, in_chan, out_chan);
            wav_codec::wav_feed_detect(ws, detect_ptr, detect_len);
            dev_log(&*syscalls, 3, b"[dec] wav".as_ptr(), 9);
        }
        FMT_MP3 => {
            let ms = &mut *(codec_ptr as *mut mp3_codec::Mp3State);
            mp3_codec::mp3_init(ms, syscalls, in_chan, out_chan);
            mp3_codec::mp3_feed_detect(ms, detect_ptr, detect_len);
            dev_log(&*syscalls, 3, b"[dec] mp3".as_ptr(), 9);
        }
        FMT_AAC => {
            let a = &mut *(codec_ptr as *mut aac_codec::AacState);
            aac_codec::aac_init(a, syscalls, in_chan, out_chan);
            aac_codec::aac_feed_detect(a, detect_ptr, detect_len);
            dev_log(&*syscalls, 3, b"[dec] aac".as_ptr(), 9);
        }
        _ => {}
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DecoderState>() as u32
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
        if state_size < core::mem::size_of::<DecoderState>() {
            return -2;
        }

        // Zero-init entire state
        __aeabi_memclr(state, core::mem::size_of::<DecoderState>());

        let s = &mut *(state as *mut DecoderState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.format = FMT_DETECTING;
        s.detect_len = 0;
        s.empty_reads = 0;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

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
        let s = &mut *(state as *mut DecoderState);
        if s.syscalls.is_null() {
            return -1;
        }

        // ----------------------------------------------------------------
        // Format detection phase
        // ----------------------------------------------------------------
        if s.format == FMT_DETECTING {
            let sys = s.sys();
            let in_poll = (sys.channel_poll)(s.in_chan, POLL_IN);
            if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 {
                return 0;
            }

            // Read bytes into detect_buf
            let space = DETECT_BUF_SIZE - (s.detect_len as usize);
            if space == 0 {
                // Shouldn't happen — detect_format returns at 8 bytes
                // Fallback to WAV
                s.format = FMT_WAV;
                init_codec(s);
                return 0;
            }

            let to_read = if space > DETECT_IO_SIZE { DETECT_IO_SIZE } else { space };
            let read = (sys.channel_read)(
                s.in_chan,
                s.detect_io.as_mut_ptr(),
                to_read,
            );

            if read <= 0 {
                return 0;
            }

            // Copy read bytes into detect_buf
            let n = read as usize;
            let offset = s.detect_len as usize;
            let mut i: usize = 0;
            while i < n && (offset + i) < DETECT_BUF_SIZE {
                s.detect_buf[offset + i] = *s.detect_io.as_ptr().add(i);
                i += 1;
            }
            s.detect_len += i as u8;

            // Try format detection
            let fmt = detect_format(&s.detect_buf, s.detect_len);
            if fmt != FMT_DETECTING {
                s.format = fmt;
                init_codec(s);
                return 2; // Burst — start decoding immediately
            }

            return 0;
        }

        // ----------------------------------------------------------------
        // Active codec phase
        // ----------------------------------------------------------------

        // Check for stream reset signal (EOF from bank on file switch
        // OR end-of-asset from host_browser_fetch). Reset must be
        // deferred until BOTH:
        //   1. The input channel has actually drained (POLL_IN clear).
        //      `host_browser_fetch` sets HUP as soon as the response
        //      body has been fully read from the JS side, but the
        //      kernel's channel ring may still hold ~10 AAC frames
        //      that the codec hasn't decoded yet. Flushing those
        //      bytes via IOCTL_FLUSH was costing the wasm browser
        //      harness ~250 ms of trailing audio (last 2 notes of
        //      the 8-note cmajor scale).
        //   2. The codec has been quiescent for HUP_QUIESCE_TICKS
        //      consecutive ticks after (1). Each codec keeps a
        //      bounded internal buffer of decoded PCM that it
        //      drip-feeds to its consumer one chunk per tick; the
        //      quiesce window lets it finish that drain before we
        //      wipe its state.
        {
            let sys_ptr = s.syscalls;
            let in_chan = s.in_chan;
            let in_poll = ((*sys_ptr).channel_poll)(in_chan, POLL_IN | POLL_HUP);
            let has_hup = (in_poll as u32) & POLL_HUP != 0;
            let has_in  = (in_poll as u32) & POLL_IN  != 0;
            if has_hup && !has_in {
                s.hup_quiet_ticks = s.hup_quiet_ticks.saturating_add(1);
                if s.hup_quiet_ticks >= HUP_QUIESCE_TICKS {
                    // Codec genuinely idle on a closed input — safe to
                    // flush + reset for the next stream.
                    dev_channel_ioctl(&*sys_ptr, in_chan, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                    dev_log(&*sys_ptr, 3, b"[dec] rst".as_ptr(), 9);
                    reset_to_detect(s);
                    return 0;
                }
            } else {
                // Either fresh input arrived or HUP cleared (bank
                // started a new file); restart the quiesce window.
                s.hup_quiet_ticks = 0;
            }
        }

        // Dispatch to detected codec's step function
        match s.format {
            FMT_WAV => wav_codec::wav_step(s.wav()),
            FMT_MP3 => mp3_codec::mp3_step(s.mp3()),
            FMT_AAC => aac_codec::aac_step(s.aac()),
            _ => 0,
        }
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

/// Request a generous output buffer so a 4-second test asset's worth of
/// PCM (≈720 KB) can buffer through to a slow consumer (e.g. a WS client
/// that connects ~2 s after the source pipeline starts). With the default
/// 8 KB buffer the codec backpressures within ~2 frames; downstream
/// (`ws_stream` → `http`) would then either drop pre-connect bytes at the
/// no-fan-out gate or stall. 1 MiB fits any single-asset test plus several
/// seconds of live decode at typical bitrates.
#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(hints: *mut ChannelHint, max_hints: usize) -> usize {
    if hints.is_null() || max_hints == 0 { return 0; }
    unsafe {
        *hints = ChannelHint { port_type: 1, port_index: 0, buffer_size: 1048576 };
    }
    1
}

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
