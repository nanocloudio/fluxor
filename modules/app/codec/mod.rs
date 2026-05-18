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

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

// Host-test builds skip the SDK's PIC EABI intrinsic stubs (which
// are gated to `target_os = "none"` / `wasm32`); provide a host
// fallback for the one intrinsic the audio sub-codecs reach for.
#[cfg(feature = "host-test")]
#[allow(non_snake_case)]
pub unsafe fn __aeabi_memclr(dest: *mut u8, n: usize) {
    core::ptr::write_bytes(dest, 0, n);
}

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// Sub-codecs. PIC builds keep these private; host-test builds expose
// them so the harness can drive each sub-codec directly.
#[cfg(feature = "host-test")] pub mod wav_codec;
#[cfg(not(feature = "host-test"))] mod wav_codec;

#[cfg(feature = "host-test")] pub mod mp3_codec;
#[cfg(not(feature = "host-test"))] mod mp3_codec;

#[cfg(feature = "host-test")] pub mod aac_codec;
#[cfg(not(feature = "host-test"))] mod aac_codec;

mod image_codec;
mod image_deflate;
mod image_gif;
mod image_jpeg;
mod image_png;

// ============================================================================
// Constants
// ============================================================================

/// Format tags
const FMT_DETECTING: u8 = 0;
const FMT_WAV: u8 = 1;
const FMT_MP3: u8 = 2;
const FMT_AAC: u8 = 3;
const FMT_BMP: u8 = 4;
const FMT_GIF: u8 = 5;
const FMT_PNG: u8 = 6;
const FMT_JPEG: u8 = 7;

#[inline(always)]
fn is_image_format(fmt: u8) -> bool {
    matches!(fmt, FMT_BMP | FMT_GIF | FMT_PNG | FMT_JPEG)
}


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
    let img_size = core::mem::size_of::<image_codec::ImageState>();
    // Manual max of four values (const context)
    let mut max = wav_size;
    if mp3_size > max { max = mp3_size; }
    if aac_size > max { max = aac_size; }
    if img_size > max { max = img_size; }
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
    /// `out_chan` is the FIRST output port from `module_new` — the
    /// audio sink for audio formats. `pixels_chan` is looked up
    /// separately at module_new via `dev_channel_port(.., 1, 1)`
    /// because the BMP/image path emits VideoRaster on the second
    /// output port. Unwired ports return `-1`; the dispatch checks
    /// before writing.
    out_chan: i32,
    pixels_chan: i32,
    /// Active format: 0=detecting, 1=wav, 2=mp3, 3=aac, 4=bmp
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
    _pad_tc: [u8; 1],
    /// Tick counter for the per-codec heartbeat (every 5000 ticks).
    /// Drives the `[img] decoded (heartbeat)` re-emit + the sticky
    /// `last_err` replay, both of which exist because a one-shot
    /// dev_log from inside `decode_buffer` can be lost in the
    /// early-boot log ring before log_net's UDP stream is fully
    /// draining.
    tick_count: u32,
    /// Header accumulation buffer for format detection
    detect_buf: [u8; DETECT_BUF_SIZE],
    /// IO buffer used during detection phase
    detect_io: [u8; DETECT_IO_SIZE],
    /// Codec state — overlay for WavState/Mp3State/AacState/ImageState
    codec: CodecBuf,

    // ── Image-format staging ──
    //
    // BMP format isn't detected until the first two bytes arrive, by
    // which time the ImageState lives inside the `codec` union. We
    // stage the YAML-driven params here at module_new time and copy
    // them into `ImageState` from `init_codec` once the format is
    // known. Default-zero fields use `image_codec`'s own defaults
    // (480×480 stretch, 8 MiB max).
    image_dst_w: u16,
    image_dst_h: u16,
    image_scale_mode: u8,
    _image_pad: u8,
    image_max_bytes: u32,
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

    #[inline(always)]
    unsafe fn img(&mut self) -> &mut image_codec::ImageState {
        &mut *(self.codec.0.as_mut_ptr() as *mut image_codec::ImageState)
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::DecoderState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    // Image params (1-4). Audio formats have no per-format params
    // today (everything is auto-detected from the bitstream); when
    // they do, append at tag 10+.
    define_params! {
        DecoderState;

        1, width, u16, 480
            => |s, d, len| { s.image_dst_w = p_u16(d, len, 0, 480); };

        2, height, u16, 480
            => |s, d, len| { s.image_dst_h = p_u16(d, len, 0, 480); };

        3, scale_mode, u8, 0, enum { stretch=0, fit=1, fill=2 }
            => |s, d, len| { s.image_scale_mode = p_u8(d, len, 0, 0); };

        4, max_bytes, u32, 8388608
            => |s, d, len| { s.image_max_bytes = p_u32(d, len, 0, 8388608); };
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

    // BMP — `BM` magic at offset 0. Two bytes is enough to commit.
    if buf[0] == image_codec::BMP_MAGIC[0] && buf[1] == image_codec::BMP_MAGIC[1] {
        return FMT_BMP;
    }

    // GIF — `GIF8` is shared by both GIF87a and GIF89a.
    if n >= 4 && buf[..4] == *image_codec::GIF_MAGIC {
        return FMT_GIF;
    }

    // PNG — 8-byte signature `89 50 4E 47 0D 0A 1A 0A`.
    if n >= 8 && buf[..8] == *image_codec::PNG_MAGIC {
        return FMT_PNG;
    }

    // JPEG — SOI (FF D8) followed by another marker byte (FF xx);
    // the first segment is always FF E0 (APP0/JFIF) or similar, so
    // three bytes are enough to commit.
    if n >= 3 && buf[..3] == *image_codec::JPEG_MAGIC {
        return FMT_JPEG;
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
        FMT_BMP | FMT_GIF | FMT_PNG | FMT_JPEG => {
            // Image path emits on `pixels` (output port 1), not the
            // audio `out_chan` (output port 0). The parent looks
            // `pixels_chan` up via `dev_channel_port(.., 1, 1)` in
            // module_new and stashes it on `DecoderState`.
            let pix_chan = s.pixels_chan;
            let (dw, dh, sm, mb) = (
                s.image_dst_w,
                s.image_dst_h,
                s.image_scale_mode,
                s.image_max_bytes,
            );
            let img = &mut *(codec_ptr as *mut image_codec::ImageState);
            // Stage params + format discriminant before image_init.
            img.dst_w = if dw == 0 { 480 } else { dw };
            img.dst_h = if dh == 0 { 480 } else { dh };
            img.scale_mode = sm;
            img.max_bytes = if mb == 0 { 8 * 1024 * 1024 } else { mb };
            img.image_format = match s.format {
                FMT_GIF => image_codec::ImageFormat::Gif,
                FMT_PNG => image_codec::ImageFormat::Png,
                FMT_JPEG => image_codec::ImageFormat::Jpeg,
                _ => image_codec::ImageFormat::Bmp,
            };
            image_codec::image_init(img, syscalls, in_chan, pix_chan);
            image_codec::image_feed_detect(img, detect_ptr, detect_len);
            let tag: &[u8] = match s.format {
                FMT_GIF => b"[dec] gif",
                FMT_PNG => b"[dec] png",
                FMT_JPEG => b"[dec] jpeg",
                _ => b"[dec] bmp",
            };
            dev_log(&*syscalls, 3, tag.as_ptr(), tag.len());
        }
        _ => {}
    }
}

// ============================================================================
// Module API
// ============================================================================

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DecoderState>() as u32
}

/// Per-module heap budget. Sized for the image path's worst case
/// (8 MiB encoded BMP accumulator + 2 MiB decoded RGB565 slack); the
/// audio paths use ~32 KB at most. Same budget covers any format
/// since only one is active at a time per module instance.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    10 * 1024 * 1024
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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
        // pixels port: output index 1 in the manifest (audio is
        // output index 0 = `out_chan` above). Unwired = -1; the
        // image path checks before writing.
        s.pixels_chan = dev_channel_port(&*s.syscalls, 1, 1);
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

#[cfg_attr(not(feature = "host-test"), no_mangle)]
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

        // Once-per-heartbeat re-emit of `[img] decoded` while the
        // image path holds a successfully-decoded frame
        // (Phase::Decoded or Phase::Draining — NOT Phase::Error
        // which would be a false positive). The one-shot log fired
        // inside `decode_buffer` can be lost in the early-boot log
        // ring if it lands before log_net's UDP stream is fully
        // draining — same pattern fat32/nvme use for their `init=`
        // / `st=` heartbeats so a viewer connecting mid-run still
        // sees the proof line.
        s.tick_count = s.tick_count.wrapping_add(1);
        if s.tick_count % 5000 == 0 && is_image_format(s.format) {
            let img = &*(s.codec.0.as_ptr() as *const image_codec::ImageState);
            let ph = img.phase as u32;
            if ph == image_codec::Phase::Decoded as u32
                || ph == image_codec::Phase::Draining as u32
            {
                let msg = b"[img] decoded (heartbeat)";
                dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
            }
            // Sticky error replay: format decoders write the reason
            // into `last_err` on every failure path. Surface it once
            // per heartbeat so the rig telemetry sees the diagnosis
            // even when the one-shot dev_log from inside
            // `decode_buffer` was dropped by log_net at boot.
            if img.last_err_len > 0 {
                dev_log(
                    s.sys(),
                    3,
                    img.last_err.as_ptr(),
                    img.last_err_len as usize,
                );
            }
        }

        // ----------------------------------------------------------------
        // Format detection phase
        // ----------------------------------------------------------------
        if s.format == FMT_DETECTING {
            let sys = s.sys();
            // Ack a pending stream-boundary HUP iff the ring is
            // empty. Bank waits on HUP-clear before writing the next
            // file, so the consumer side must release it here.
            // Flushing while bytes are queued would drop the start
            // of the new stream — those bytes are what we need to
            // run detection against.
            let poll = (sys.channel_poll)(s.in_chan, POLL_IN | POLL_HUP);
            let has_hup = (poll as u32) & POLL_HUP != 0;
            let has_in = (poll as u32) & POLL_IN != 0;
            if has_hup && !has_in {
                dev_channel_ioctl(sys, s.in_chan, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                return 0;
            }
            if !has_in {
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

        // Audio sub-codecs: reset on upstream HUP. Image formats
        // own their own EOF / drain / reset cycle inside
        // `image_codec.rs`'s phase machine — wiping their state here
        // would tear down a 1 MiB RGB565 frame mid-drain (≈ 1000
        // ticks at WRITE_CHUNK = 1024 B/tick).
        if !is_image_format(s.format) {
            let sys_ptr = s.syscalls;
            let in_chan = s.in_chan;
            let in_poll = ((*sys_ptr).channel_poll)(in_chan, POLL_IN | POLL_HUP);
            let has_hup = (in_poll as u32) & POLL_HUP != 0;
            let has_in  = (in_poll as u32) & POLL_IN  != 0;

            // Fast path: WAV has reached the header-declared
            // `data_size` and upstream signalled HUP. The stream is
            // over — reset and FLUSH. The FLUSH both drops any
            // trailing junk (some WAV files carry metadata after
            // the data chunk) and clears HUP so a HUP-gated producer
            // can resume. MP3 / AAC don't expose a `sub_done`
            // predicate and fall through to the quiesce path.
            let sub_done = match s.format {
                FMT_WAV => wav_codec::wav_is_done(s.wav()),
                _ => false,
            };
            if has_hup && sub_done {
                dev_log(&*sys_ptr, 3, b"[dec] rst-adv".as_ptr(), 13);
                dev_channel_ioctl(&*sys_ptr, in_chan, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                reset_to_detect(s);
                return 0;
            }

            // Quiesce path: HUP is set and the ring has drained.
            // Wait `HUP_QUIESCE_TICKS` consecutive ticks to give the
            // sub-codec a chance to flush its internal output (the
            // wasm fetch consumer drops the last 250 ms of audio
            // without it), then FLUSH + reset.
            if has_hup && !has_in {
                s.hup_quiet_ticks = s.hup_quiet_ticks.saturating_add(1);
                if s.hup_quiet_ticks >= HUP_QUIESCE_TICKS {
                    dev_channel_ioctl(&*sys_ptr, in_chan, IOCTL_FLUSH, core::ptr::null_mut(), 0);
                    dev_log(&*sys_ptr, 3, b"[dec] rst".as_ptr(), 9);
                    reset_to_detect(s);
                    return 0;
                }
            } else {
                // Fresh input or HUP-cleared — restart the window.
                s.hup_quiet_ticks = 0;
            }
        }

        // Dispatch to detected codec's step function
        match s.format {
            FMT_WAV => wav_codec::wav_step(s.wav()),
            FMT_MP3 => mp3_codec::mp3_step(s.mp3()),
            FMT_AAC => aac_codec::aac_step(s.aac()),
            FMT_BMP | FMT_GIF | FMT_PNG | FMT_JPEG => image_codec::image_step(s.img()),
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
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(hints: *mut ChannelHint, max_hints: usize) -> usize {
    if hints.is_null() || max_hints == 0 { return 0; }
    unsafe {
        *hints = ChannelHint { port_type: 1, port_index: 0, buffer_size: 1048576 };
        if max_hints > 1 {
            // Input encoded stream — bank writes 1024 bytes per tick;
            // size for a healthy lead so writes don't stall when the
            // BMP path is in Phase::Draining (not reading from in_chan
            // for ~1000 ticks while emitting the decoded frame).
            *hints.add(1) = ChannelHint { port_type: 0, port_index: 0, buffer_size: 65536 };
            return 2;
        }
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
