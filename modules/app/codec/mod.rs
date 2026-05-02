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
    _pad: u8,
    /// Header accumulation buffer for format detection
    detect_buf: [u8; DETECT_BUF_SIZE],
    /// IO buffer used during detection phase
    detect_io: [u8; DETECT_IO_SIZE],
    /// Codec state — overlay for WavState/Mp3State/AacState
    codec: [u8; CODEC_STATE_SIZE],
}

impl DecoderState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }

    #[inline(always)]
    unsafe fn wav(&mut self) -> &mut wav_codec::WavState {
        &mut *(self.codec.as_mut_ptr() as *mut wav_codec::WavState)
    }

    #[inline(always)]
    unsafe fn mp3(&mut self) -> &mut mp3_codec::Mp3State {
        &mut *(self.codec.as_mut_ptr() as *mut mp3_codec::Mp3State)
    }

    #[inline(always)]
    unsafe fn aac(&mut self) -> &mut aac_codec::AacState {
        &mut *(self.codec.as_mut_ptr() as *mut aac_codec::AacState)
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
    // Zero the codec state
    __aeabi_memclr(s.codec.as_mut_ptr(), CODEC_STATE_SIZE);
}

/// Initialize the detected codec and feed it the detection bytes.
unsafe fn init_codec(s: &mut DecoderState) {
    let syscalls = s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;
    let detect_len = s.detect_len as usize;
    // Take raw pointer to detect_buf before borrowing codec via &mut
    let detect_ptr = s.detect_buf.as_ptr();
    let codec_ptr = s.codec.as_mut_ptr();

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

        // Check for stream reset signal (EOF from bank on file switch)
        {
            let sys = s.sys();
            let in_poll = (sys.channel_poll)(s.in_chan, POLL_IN | POLL_HUP);
            if (in_poll as u32) & POLL_HUP != 0 {
                // Flush our input: clears old encoded data and the eof_flag
                dev_channel_ioctl(sys, s.in_chan, IOCTL_FLUSH, core::ptr::null_mut());
                dev_log(sys, 3, b"[dec] rst".as_ptr(), 9);
                reset_to_detect(s);
                return 0;
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

/// Request larger output buffer for MP3 decode expansion.
/// One MP3 frame (576 bytes) → 2304 stereo i16 samples (4608 bytes).
/// Request 8192 bytes (≈2 frames) so downstream always has data during decode.
#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(hints: *mut ChannelHint, max_hints: usize) -> usize {
    if hints.is_null() || max_hints == 0 { return 0; }
    unsafe {
        *hints = ChannelHint { port_type: 1, port_index: 0, buffer_size: 8192 };
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
