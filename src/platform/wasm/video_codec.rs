//! `wasm_browser_video_codec` built-in: MKV container → browser
//! WebCodecs `VideoDecoder` → canvas. Direct playback of H.264/H.265
//! video without transcoding — the browser's own (usually hardware)
//! decoder does the work; the kernel side owns the container.
//!
//! Division of labour:
//!   * kernel (this module): incremental Matroska demux (the same
//!     `mkv_demux.rs` the PIC codec uses), whole-sample staging,
//!     shim-queue backpressure, EOF flush.
//!   * shim (`host_shims.js` videoShim): codec-string derivation from
//!     avcC/hvcC, `VideoDecoder` lifecycle, PTS-paced presentation of
//!     decoded `VideoFrame`s onto the page canvas (the browser also
//!     handles HDR→SDR when compositing), decode-queue depth
//!     reporting for backpressure.
//!
//! WebCodecs consumes length-prefixed samples as stored in Matroska
//! blocks ("avc"/"hevc" bitstream format with `description` set), so
//! no Annex B re-framing happens anywhere on this path.
//!
//! Software fallback: this module does NOT fall back internally. A
//! graph that must run without WebCodecs uses the PIC `codec` module
//! (pure-Rust H.264 baseline) instead; `host_video_config` returning
//! an error simply marks this module failed.

use crate::kernel::{channel, scheduler, syscalls};

#[path = "../../../modules/app/codec/mkv_demux.rs"]
mod mkv_demux;

use mkv_demux::{MkvDemux, MkvError, MkvSink, VideoCodec, VideoTrackInfo};

extern "C" {
    /// Configure (or reconfigure) the page's video decoder.
    /// `kind`: 1 = H.264/avcC, 2 = H.265/hvcC. `desc` is the raw
    /// Matroska CodecPrivate (avcC / hvcC record) the shim passes to
    /// `VideoDecoder.configure` as `description` and derives the
    /// RFC 6381 codec string from. Returns 0 when a decoder was
    /// (optimistically) configured, negative when WebCodecs or the
    /// codec kind is unavailable. Async config errors surface later
    /// through `host_video_status`.
    fn host_video_config(
        kind: u32,
        desc_ptr: *const u8,
        desc_len: usize,
        width: u32,
        height: u32,
    ) -> i32;

    /// Queue one complete coded sample (one Matroska block payload,
    /// length-prefixed NALs as stored). `ts_ms` is the block's
    /// presentation time in milliseconds. Returns negative on fatal
    /// decoder error, else 0.
    fn host_video_chunk(ts_ms: u32, keyframe: u32, ptr: *const u8, len: usize) -> i32;

    /// Combined depth of the decoder input queue and the undisplayed
    /// decoded-frame queue. `>= 0` depth; `-2` fatal decoder error.
    fn host_video_status() -> i32;

    /// End of stream: flush the decoder so trailing frames present.
    fn host_video_flush() -> i32;
}

/// Per-tick input budget. A UHD remux runs ~10 MB/s; 64 KiB/tick at
/// a few thousand ticks/s leaves a comfortable margin without letting
/// one tick monopolise the scheduler.
const READ_CHUNK: usize = 2048;
const READS_PER_TICK: usize = 32;

/// Stop feeding the shim when (decoder queue + presentation queue)
/// exceeds this. Keeps a second-ish of lead at 24 fps without letting
/// the browser buffer unboundedly.
const QUEUE_HIGH_WATER: i32 = 24;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Streaming = 0,
    Flushed = 1,
    Error = 2,
}

#[repr(C)]
pub(crate) struct VideoCodecState {
    in_chan: i32,
    width: u16,
    height: u16,
    phase: u8, // Phase
    /// host_video_config accepted a track.
    configured: u8,
    _pad: [u8; 2],

    demux: MkvDemux,

    // Current-sample staging (one whole Matroska block payload —
    // WebCodecs takes complete samples only).
    frame_ptr: *mut u8,
    frame_cap: u32,
    frame_len: u32,
    frame_ts_ms: u32,
    frame_key: u32,
    /// ns per Matroska tick, from the track info.
    ts_scale_ns: u64,
}

/// Heap need: State + the sample staging buffer.
pub(crate) fn heap_size_for(max_frame_bytes: u32) -> usize {
    core::mem::size_of::<VideoCodecState>() + max_frame_bytes as usize + 256
}

unsafe fn alloc_state(
    in_chan: i32,
    width: u16,
    height: u16,
    max_frame_bytes: u32,
) -> *mut VideoCodecState {
    let table = syscalls::get_syscall_table();
    let raw =
        (table.heap_alloc)(core::mem::size_of::<VideoCodecState>() as u32) as *mut VideoCodecState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let frame = (table.heap_alloc)(max_frame_bytes);
    if frame.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        VideoCodecState {
            in_chan,
            width,
            height,
            phase: Phase::Streaming as u8,
            configured: 0,
            _pad: [0; 2],
            demux: MkvDemux::new(),
            frame_ptr: frame,
            frame_cap: max_frame_bytes,
            frame_len: 0,
            frame_ts_ms: 0,
            frame_key: 0,
            ts_scale_ns: 1_000_000,
        },
    );
    raw
}

// ── Demux sink ────────────────────────────────────────────────────────────
//
// Raw state pointer for the same reason as the PIC codec's EsSink:
// `feed()` mutably borrows the demuxer inside the same struct the
// sink mutates. Single-threaded module step; the sink never touches
// `demux` itself.

struct ChunkSink {
    s: *mut VideoCodecState,
}

impl MkvSink for ChunkSink {
    fn on_video_track(&mut self, info: &VideoTrackInfo<'_>) {
        let s = unsafe { &mut *self.s };
        let kind = match info.codec {
            VideoCodec::H264 => 1u32,
            VideoCodec::H265 => 2u32,
            VideoCodec::Unknown => {
                s.phase = Phase::Error as u8;
                return;
            }
        };
        s.ts_scale_ns = info.timestamp_scale;
        let rv = unsafe {
            host_video_config(
                kind,
                info.codec_private.as_ptr(),
                info.codec_private.len(),
                info.pixel_width,
                info.pixel_height,
            )
        };
        if rv < 0 {
            s.phase = Phase::Error as u8;
        } else {
            s.configured = 1;
        }
    }

    fn on_frame_begin(&mut self, timestamp_ticks: i64, keyframe: bool) {
        let s = unsafe { &mut *self.s };
        s.frame_len = 0;
        s.frame_key = keyframe as u32;
        // Standard TimestampScale is 1 ms; general case in u32 math
        // (PIC-portable habit, and wasm32 u64 div is just slow).
        let ticks = if timestamp_ticks < 0 {
            0
        } else {
            timestamp_ticks as u64
        };
        s.frame_ts_ms = if s.ts_scale_ns == 1_000_000 {
            ticks as u32
        } else {
            let per_tick_us = ((s.ts_scale_ns as u32) / 1000).max(1);
            (ticks as u32).wrapping_mul(per_tick_us) / 1000
        };
    }

    fn on_frame_data(&mut self, data: &[u8]) {
        let s = unsafe { &mut *self.s };
        if s.phase != Phase::Streaming as u8 {
            return;
        }
        if s.frame_len + data.len() as u32 > s.frame_cap {
            // Sample larger than the staging buffer (raise
            // `max_frame_bytes` in the graph) — fatal for the stream.
            s.phase = Phase::Error as u8;
            return;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                s.frame_ptr.add(s.frame_len as usize),
                data.len(),
            );
        }
        s.frame_len += data.len() as u32;
    }

    fn on_frame_end(&mut self) {
        let s = unsafe { &mut *self.s };
        if s.phase != Phase::Streaming as u8 || s.configured == 0 || s.frame_len == 0 {
            return;
        }
        let rv = unsafe {
            host_video_chunk(
                s.frame_ts_ms,
                s.frame_key,
                s.frame_ptr,
                s.frame_len as usize,
            )
        };
        if rv < 0 {
            s.phase = Phase::Error as u8;
        }
        s.frame_len = 0;
    }

    fn on_error(&mut self, _err: MkvError) {
        let s = unsafe { &mut *self.s };
        s.phase = Phase::Error as u8;
    }
}

fn step(state: *mut u8) -> i32 {
    // SAFETY: kernel-provided opaque state pointer, written by build().
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut VideoCodecState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        if st.phase != Phase::Streaming as u8 {
            return 0;
        }
        if st.in_chan < 0 {
            return 0;
        }

        // Decoder health / backpressure gate.
        if st.configured != 0 {
            let depth = host_video_status();
            if depth == -2 {
                st.phase = Phase::Error as u8;
                return 0;
            }
            if depth > QUEUE_HIGH_WATER {
                return 0;
            }
        }

        // Pull container bytes through the demuxer.
        let mut buf = [0u8; READ_CHUNK];
        let mut got_any = false;
        for _ in 0..READS_PER_TICK {
            let n = channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len());
            if n <= 0 {
                break;
            }
            got_any = true;
            let mut sink = ChunkSink {
                s: st as *mut VideoCodecState,
            };
            // Split borrow: the sink never touches `demux`.
            let demux = &mut *(&mut st.demux as *mut MkvDemux);
            demux.feed(&buf[..n as usize], &mut sink);
            if st.phase != Phase::Streaming as u8 {
                return 0;
            }
        }

        // EOF: upstream HUP with nothing left to read.
        if !got_any {
            let poll = channel::channel_poll(st.in_chan, channel::POLL_HUP | channel::POLL_IN);
            let hup = poll > 0 && (poll as u32 & channel::POLL_HUP) != 0;
            let has_in = poll > 0 && (poll as u32 & channel::POLL_IN) != 0;
            if hup && !has_in && st.configured != 0 {
                let _ = host_video_flush();
                st.phase = Phase::Flushed as u8;
            }
        }
        0
    }
}

pub(crate) unsafe fn build(
    in_chan: i32,
    width: u16,
    height: u16,
    max_frame_bytes: u32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_video_codec", step);
    let raw = alloc_state(in_chan, width, height, max_frame_bytes);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut VideoCodecState, raw);
    m
}
