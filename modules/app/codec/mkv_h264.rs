// MKV/H.264 video codec kernel — unified-decoder sub-codec gluing the
// clean-room Matroska demuxer (`mkv_demux.rs`) to the h264bsd Rust
// port (`h264/`). Same init / feed_detect / step shape as the audio
// and image kernels; the parent `mod.rs` owns the PIC entry points.
//
// Pipeline (all streaming, O(1) module state + arena buffers):
//   in_chan bytes → MkvDemux → avcC re-framing (length-prefixed NALs
//   → Annex B start codes, SPS/PPS injected once from CodecPrivate)
//   → `es[]` elementary-stream accumulator → h264bsdDecode (one call
//   per step: bounded per-tick work) → DPB output picture (YUV420)
//   → crop + nearest-neighbour scale + BT.601 → RGB565 LE `pending[]`
//   → WRITE_CHUNK'd onto the pixels port, exactly like the image path.
//
// Memory (heap, via syscalls.heap_alloc through the port's Allocator):
//   * es[]       — Annex B accumulator (cap `max_bytes`, 2 MiB default)
//   * pending[]  — RGB565 frame (dst_w × dst_h × 2)
//   * decoder    — mbLayer / mb array / sliceGroupMap / DPB frames,
//                  allocated inside the port when SPS activates
// The Allocator's free maps to heap_free, so nothing leaks on the
// Linux host; on wasm the bump allocator makes free a no-op, which
// only matters for re-sent parameter sets (avcC feeds each set once).
//
// Current limits:
//   * first supported (H.264) video track only; audio tracks ignored
//   * no block lacing (ffmpeg never laces video)
//   * scale_mode is stretch regardless of param (fit/fill TODO)
//   * VUI fullRange is ignored — BT.601 limited-range conversion

use super::abi::SyscallTable;
use super::{dev_flow_budget, dev_log, dev_millis};
use super::h264::{self, h264_decoder, storage_t, Allocator};
use super::mkv_demux::{parse_avcc, MkvDemux, MkvError, MkvSink, VideoCodec, VideoTrackInfo};

const IN_CHUNK: usize = 1024;
/// Larger than the image path's 1024: a 768×432 RGB565 frame is
/// ~663 KB — at 1 KB/step the channel copy alone caps playback well
/// below 25 fps. 16 KB keeps per-step work bounded while sustaining
/// SD-movie frame rates.
const WRITE_CHUNK: usize = 16384;

/// Stop feeding the demuxer when fewer than this many free bytes are
/// left in `es[]` — one IN_CHUNK of block payload can expand by at
/// most a few start codes.
const ES_HEADROOM: u32 = 8 * 1024;

/// Ticks of upstream quiet with HUP before flushing the decoder.
const EOF_TICKS: u32 = 200;

/// Caps for the retained parameter sets (x264 SPS ≈ 25 B, PPS ≈ 10 B).
const PS_MAX: usize = 128;

/// PTS queue depth — bounded by DPB lag (≤ dpbSize+1, ~3 for
/// baseline) plus demux lead over the decoder within one step.
const PTS_RING: usize = 32;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum VPhase {
    /// Demux + decode as input arrives.
    Run = 0,
    /// A decoded picture is streaming out of `pending[]`.
    Drain = 1,
    /// Terminal for this stream (bad container / decode error).
    Error = 2,
    /// Upstream HUP seen, decoder flushed, all frames drained.
    Done = 3,
}

#[repr(C)]
pub struct MkvH264State {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32, // pixels port

    // params (parent stages these before mkv_init, same as image path)
    pub dst_w: u16,
    pub dst_h: u16,
    pub scale_mode: u8,
    _pad0: u8,
    pub max_bytes: u32,

    pub phase: VPhase,
    /// After Drain completes, more DPB output pictures may be queued;
    /// pull the next one before decoding further.
    more_pics: u8,
    /// SPS/PPS from avcC already injected into `es`.
    ps_injected: u8,
    /// avcC NAL length-prefix size (1/2/4).
    nal_length_size: u8,

    // Matroska demuxer + block re-framing state
    demux: MkvDemux,
    /// Bytes of the current NAL length prefix accumulated (< nal_length_size).
    prefix_have: u8,
    _pad1: [u8; 3],
    prefix: [u8; 4],
    /// Payload bytes remaining in the current NAL.
    nal_remaining: u32,

    // retained parameter sets (from CodecPrivate)
    sps_len: u8,
    pps_len: u8,
    sps: [u8; PS_MAX],
    pps: [u8; PS_MAX],

    // Annex B elementary-stream accumulator
    es: *mut u8,
    es_cap: u32,
    es_len: u32,
    es_pos: u32,
    /// High-water mark of COMPLETE NALs in `es[]`. h264bsdDecode
    /// treats end-of-buffer as end-of-NAL, so it must never see a
    /// partially-appended NAL; the demux re-framer knows the exact
    /// boundaries and advances this after each whole NAL (and after
    /// the injected SPS/PPS).
    es_complete: u32,

    // decoder (embedded; zeroed by the parent's state memclr, the
    // Allocator hooks are installed by h264bsdInit before first use)
    storage: storage_t,
    dec_ready: u8,
    _pad2: [u8; 3],

    // picture geometry (known at HDRS_RDY)
    pic_w: u32,
    pic_h: u32,
    crop_x: u32,
    crop_y: u32,
    crop_w: u32,
    crop_h: u32,

    // RGB565 output staging
    pending: *mut u8,
    pending_size: u32,
    pending_pos: u32,

    pub frames_out: u32,
    quiet_ticks: u32,

    // ── PTS pacing ──
    // Block timestamps queue up here at demux time (decode order ==
    // presentation order for baseline: no B-frames); one entry pops
    // per output picture. A frame is staged for emit no earlier than
    // its PTS relative to the first frame's wall-clock. If the host
    // has no timer primitive (dev_millis == 0) pacing disables itself.
    /// ns per Matroska timestamp tick (from TrackInfo).
    ts_scale_ns: u64,
    pts_ring: [u64; PTS_RING],
    pts_head: u8,
    pts_count: u8,
    pace_base_set: u8,
    /// End-of-stream: h264bsdFlushBuffer already issued.
    flushed: u8,
    /// Wall-clock ms at first emitted frame.
    pace_base_ms: u64,
    /// PTS ms of first emitted frame.
    pace_base_pts: u64,
    pub last_err_len: u8,
    _pad3: [u8; 3],
    pub last_err: [u8; 48],
}

// ── Allocator adapters (module arena) ─────────────────────────────────────

unsafe fn arena_alloc(ctx: *mut u8, bytes: usize) -> *mut u8 {
    let sys = ctx as *const SyscallTable;
    ((*sys).heap_alloc)(bytes as u32)
}

unsafe fn arena_free(ctx: *mut u8, ptr: *mut u8) {
    let sys = ctx as *const SyscallTable;
    ((*sys).heap_free)(ptr)
}

// ── Lifecycle ─────────────────────────────────────────────────────────────

pub unsafe fn mkv_init(
    s: &mut MkvH264State,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.phase = VPhase::Run;
    s.demux.reset();
    // dst_w/dst_h/max_bytes staged by the parent before this call.
    if s.max_bytes == 0 {
        s.max_bytes = 2 * 1024 * 1024;
    }
    let alloc = Allocator {
        ctx: syscalls as *mut u8,
        alloc: arena_alloc,
        free: arena_free,
    };
    if h264_decoder::h264bsdInit(&mut s.storage, 0, alloc) != h264::HANTRO_OK {
        set_err(s, b"[mkv] decoder init failed");
        s.phase = VPhase::Error;
        return;
    }
    s.dec_ready = 1;
    dev_log(&*syscalls, 3, b"[dec] mkv/h264".as_ptr(), 14);
}

/// Replay the parent's detect bytes (the EBML magic + following
/// bytes) into the demuxer.
pub unsafe fn mkv_feed_detect(s: &mut MkvH264State, buf: *const u8, len: usize) {
    let slice = core::slice::from_raw_parts(buf, len);
    feed_demux(s, slice);
}

/// The parent uses this on upstream HUP to decide when to reset back
/// to format detection.
pub unsafe fn mkv_is_done(s: &MkvH264State) -> bool {
    matches!(s.phase, VPhase::Done | VPhase::Error)
}

// ── Demux sink ────────────────────────────────────────────────────────────
//
// The sink re-frames avcC length-prefixed NALs into Annex B in `es[]`
// as payload bytes stream through — no per-frame buffering. It holds
// a raw state pointer because `feed()` already mutably borrows the
// demuxer inside the same struct; single-threaded module step, no
// aliasing of the demux fields from the sink.

struct EsSink {
    s: *mut MkvH264State,
}

const START_CODE: [u8; 4] = [0, 0, 0, 1];

impl MkvSink for EsSink {
    fn on_video_track(&mut self, info: &VideoTrackInfo<'_>) {
        let s = unsafe { &mut *self.s };
        if info.codec != VideoCodec::H264 {
            unsafe { set_err(s, b"[mkv] video track is not H.264") };
            s.phase = VPhase::Error;
            return;
        }
        match parse_avcc(info.codec_private) {
            Some(avcc) if avcc.sps.len() <= PS_MAX && avcc.pps.len() <= PS_MAX => {
                s.ts_scale_ns = info.timestamp_scale;
                s.nal_length_size = avcc.nal_length_size;
                s.sps[..avcc.sps.len()].copy_from_slice(avcc.sps);
                s.sps_len = avcc.sps.len() as u8;
                s.pps[..avcc.pps.len()].copy_from_slice(avcc.pps);
                s.pps_len = avcc.pps.len() as u8;
            }
            _ => {
                unsafe { set_err(s, b"[mkv] bad avcC codec private") };
                s.phase = VPhase::Error;
            }
        }
    }

    fn on_frame_begin(&mut self, timestamp_ticks: i64, _keyframe: bool) {
        let s = unsafe { &mut *self.s };
        s.prefix_have = 0;
        s.nal_remaining = 0;
        // Queue this block's PTS in ms (drop-oldest on overflow —
        // pacing degrades gracefully, decode is unaffected).
        let ticks = if timestamp_ticks < 0 { 0 } else { timestamp_ticks as u64 };
        let scale = if s.ts_scale_ns == 0 { 1_000_000 } else { s.ts_scale_ns };
        // TimestampScale is 1 ms (1_000_000 ns) in practice — ticks ARE
        // milliseconds. The general case stays in u32 arithmetic: a
        // u64 division would pull in __aeabi_uldivmod, which the
        // 32-bit PIC targets can't link.
        let pts_ms: u64 = if scale == 1_000_000 {
            ticks
        } else {
            let per_tick_us = ((scale as u32) / 1000).max(1);
            ((ticks as u32).wrapping_mul(per_tick_us) / 1000) as u64
        };
        if (s.pts_count as usize) == PTS_RING {
            s.pts_head = (s.pts_head + 1) % PTS_RING as u8;
            s.pts_count -= 1;
        }
        let tail = (s.pts_head as usize + s.pts_count as usize) % PTS_RING;
        s.pts_ring[tail] = pts_ms;
        s.pts_count += 1;
        // Parameter sets go in front of the first frame.
        if s.ps_injected == 0 && s.sps_len > 0 {
            s.ps_injected = 1;
            unsafe {
                let sps_len = s.sps_len as usize;
                let pps_len = s.pps_len as usize;
                let sps = s.sps;
                let pps = s.pps;
                es_append(s, &START_CODE);
                es_append(s, &sps[..sps_len]);
                es_append(s, &START_CODE);
                es_append(s, &pps[..pps_len]);
                s.es_complete = s.es_len;
            }
        }
    }

    fn on_frame_data(&mut self, mut data: &[u8]) {
        let s = unsafe { &mut *self.s };
        if s.phase == VPhase::Error {
            return;
        }
        let nls = s.nal_length_size as usize;
        while !data.is_empty() {
            if s.nal_remaining == 0 {
                // Accumulate the next length prefix.
                while (s.prefix_have as usize) < nls && !data.is_empty() {
                    s.prefix[s.prefix_have as usize] = data[0];
                    s.prefix_have += 1;
                    data = &data[1..];
                }
                if (s.prefix_have as usize) < nls {
                    return;
                }
                let mut len = 0u32;
                for i in 0..nls {
                    len = (len << 8) | s.prefix[i] as u32;
                }
                s.prefix_have = 0;
                if len == 0 {
                    continue;
                }
                // Can-never-fit check (fail loud, not wedged): the
                // decoder consumes only COMPLETE NALs (`es_complete`),
                // and the feed gate stops ES_HEADROOM short of full —
                // so a NAL that cannot fit in the accumulator even
                // after full compaction would stall the pipeline
                // forever without ever reaching es_append's overflow
                // backstop. We know the declared length right here;
                // refuse it deterministically. (`max_bytes` is the
                // graph-tunable cap — raise it for exotic streams.)
                if len.saturating_add(START_CODE.len() as u32) > s.es_cap.max(s.max_bytes) {
                    unsafe { set_err(s, b"[mkv] NAL exceeds es buffer cap") };
                    s.phase = VPhase::Error;
                    return;
                }
                s.nal_remaining = len;
                unsafe { es_append(s, &START_CODE) };
                continue;
            }
            let take = (s.nal_remaining as usize).min(data.len());
            unsafe { es_append(s, &data[..take]) };
            s.nal_remaining -= take as u32;
            if s.nal_remaining == 0 {
                s.es_complete = s.es_len;
            }
            data = &data[take..];
        }
    }

    fn on_frame_end(&mut self) {}

    fn on_error(&mut self, _err: MkvError) {
        let s = unsafe { &mut *self.s };
        unsafe { set_err(s, b"[mkv] demux error") };
        s.phase = VPhase::Error;
    }
}

unsafe fn feed_demux(s: &mut MkvH264State, data: &[u8]) {
    let mut sink = EsSink { s: s as *mut MkvH264State };
    // Split the borrow: demux is only touched through this pointer
    // while the sink mutates the rest of the state.
    let demux = &mut *(&mut s.demux as *mut MkvDemux);
    demux.feed(data, &mut sink);
}

// ── ES accumulator ────────────────────────────────────────────────────────

unsafe fn es_append(s: &mut MkvH264State, bytes: &[u8]) {
    if s.phase == VPhase::Error {
        return;
    }
    if s.es.is_null() {
        let cap = s.max_bytes;
        let p = ((*s.syscalls).heap_alloc)(cap);
        if p.is_null() {
            set_err(s, b"[mkv] es alloc failed");
            s.phase = VPhase::Error;
            return;
        }
        s.es = p;
        s.es_cap = cap;
        s.es_len = 0;
        s.es_pos = 0;
    }
    if s.es_len + bytes.len() as u32 > s.es_cap {
        set_err(s, b"[mkv] es overflow");
        s.phase = VPhase::Error;
        return;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), s.es.add(s.es_len as usize), bytes.len());
    s.es_len += bytes.len() as u32;
}

/// Reclaim consumed bytes once the decoder has caught up, so `es[]`
/// never grows past one in-flight burst.
unsafe fn es_compact(s: &mut MkvH264State) {
    if s.es_pos == 0 {
        return;
    }
    if s.es_pos == s.es_len {
        s.es_pos = 0;
        s.es_len = 0;
        s.es_complete = 0;
        return;
    }
    // Only compact from a safe point: h264bsdDecode never needs the
    // consumed prefix again.
    let remain = (s.es_len - s.es_pos) as usize;
    core::ptr::copy(s.es.add(s.es_pos as usize), s.es, remain);
    s.es_len = remain as u32;
    s.es_complete -= s.es_pos;
    s.es_pos = 0;
}

// ── Step ──────────────────────────────────────────────────────────────────

pub unsafe fn mkv_step(s: &mut MkvH264State) -> i32 {
    match s.phase {
        VPhase::Error | VPhase::Done => 0,

        VPhase::Drain => {
            if s.pending_pos < s.pending_size {
                // Chunk size from the pixels edge's rate class when
                // declared (`rate: video` → cadence-derived grant),
                // else the fixed WRITE_CHUNK.
                let grant = dev_flow_budget(&*s.syscalls, 1);
                let chunk = if grant == 0 { WRITE_CHUNK as u32 } else { grant.max(1024) };
                let take = (s.pending_size - s.pending_pos).min(chunk);
                let mut w = ((*s.syscalls).channel_write)(
                    s.out_chan,
                    s.pending.add(s.pending_pos as usize),
                    take as usize,
                );
                if w <= 0 && take > 1024 {
                    // channel_write is all-or-nothing on rings smaller
                    // than the chunk (the wasm host doesn't honour the
                    // 1 MiB pixels hint) — trickle at ring pace instead
                    // of wedging the frame.
                    w = ((*s.syscalls).channel_write)(
                        s.out_chan,
                        s.pending.add(s.pending_pos as usize),
                        1024,
                    );
                }
                if w > 0 {
                    s.pending_pos += w as u32;
                }
                return 0;
            }
            s.pending_pos = 0;
            s.pending_size = 0;
            // More output pictures queued in the DPB?
            if s.more_pics != 0 {
                if !pace_ok(s) {
                    return 0; // hold in Drain until the next frame is due
                }
                if next_picture(s) {
                    return 2; // keep draining
                }
            }
            s.more_pics = 0;
            s.phase = VPhase::Run;
            2
        }

        VPhase::Run => {
            // 0) A decoded picture is waiting in the DPB (PIC_RDY seen
            // but not yet due). Emit it when its PTS arrives; don't
            // decode further until the output queue drains.
            if s.more_pics != 0 {
                if !pace_ok(s) {
                    return 0;
                }
                if next_picture(s) {
                    s.phase = VPhase::Drain;
                    return 2;
                }
                // DPB output queue empty — resume decoding.
            }

            // 1) Pull input into the demuxer while there's ES headroom.
            let free = s.es_cap.saturating_sub(s.es_len);
            if s.es.is_null() || free > ES_HEADROOM {
                let mut chunk = [0u8; IN_CHUNK];
                let n = ((*s.syscalls).channel_read)(s.in_chan, chunk.as_mut_ptr(), chunk.len());
                if n > 0 {
                    s.quiet_ticks = 0;
                    feed_demux(s, &chunk[..n as usize]);
                    if s.phase == VPhase::Error {
                        return 0;
                    }
                }
            }

            // 2) One decode call per step over the accumulated ES.
            if s.dec_ready != 0 && s.es_pos < s.es_complete {
                let mut read_bytes = 0u32;
                let ret = h264_decoder::h264bsdDecode(
                    &mut s.storage,
                    s.es.add(s.es_pos as usize),
                    s.es_complete - s.es_pos,
                    s.frames_out,
                    &mut read_bytes,
                );
                s.es_pos += read_bytes;
                match ret {
                    h264::H264BSD_HDRS_RDY => {
                        on_headers(s);
                        return 2;
                    }
                    h264::H264BSD_PIC_RDY => {
                        // Emit via the paced path at the top of Run.
                        s.more_pics = 1;
                        return 2;
                    }
                    h264::H264BSD_RDY => {
                        if read_bytes == 0 {
                            // Decoder wants more data than buffered
                            // (mid-NAL). Compact and wait for input.
                            es_compact(s);
                            return 0;
                        }
                        return 2;
                    }
                    h264::H264BSD_MEMALLOC_ERROR => {
                        set_err(s, b"[mkv] decode memalloc error");
                        s.phase = VPhase::Error;
                        return 0;
                    }
                    _ => {
                        // Stream errors: h264bsd conceals and carries
                        // on; hard param-set errors end the stream.
                        set_err(s, b"[mkv] decode error");
                        s.phase = VPhase::Error;
                        return 0;
                    }
                }
            }
            es_compact(s);

            // 3) End of stream: upstream HUP + everything consumed.
            let poll = ((*s.syscalls).channel_poll)(s.in_chan, super::POLL_IN | super::POLL_HUP);
            let has_hup = (poll as u32) & super::POLL_HUP != 0;
            let has_in = (poll as u32) & super::POLL_IN != 0;
            if has_hup && !has_in && s.es_pos >= s.es_complete {
                s.quiet_ticks = s.quiet_ticks.saturating_add(1);
                if s.quiet_ticks >= EOF_TICKS {
                    if s.dec_ready != 0 && s.flushed == 0 {
                        // Release the DPB's buffered tail; the paced
                        // emit at the top of Run drains it over the
                        // following steps.
                        h264_decoder::h264bsdFlushBuffer(&mut s.storage);
                        s.flushed = 1;
                        s.more_pics = 1;
                        return 0;
                    }
                    if s.more_pics != 0 {
                        // Tail frames still owed (pacing) — hold.
                        return 0;
                    }
                    dev_log(s.syscalls.as_ref().unwrap_unchecked(), 3, b"[mkv] done".as_ptr(), 10);
                    s.phase = VPhase::Done;
                }
            } else {
                s.quiet_ticks = 0;
            }
            0
        }
    }
}

// ── Decoder events ────────────────────────────────────────────────────────

unsafe fn on_headers(s: &mut MkvH264State) {
    s.pic_w = h264_decoder::h264bsdPicWidth(&mut s.storage) * 16;
    s.pic_h = h264_decoder::h264bsdPicHeight(&mut s.storage) * 16;
    let mut flag = 0u32;
    let (mut cx, mut cy, mut cw, mut ch) = (0u32, 0u32, 0u32, 0u32);
    h264_decoder::h264bsdCroppingParams(
        &mut s.storage, &mut flag, &mut cx, &mut cw, &mut cy, &mut ch,
    );
    if flag == 0 {
        cx = 0;
        cy = 0;
        cw = s.pic_w;
        ch = s.pic_h;
    }
    s.crop_x = cx;
    s.crop_y = cy;
    s.crop_w = cw;
    s.crop_h = ch;
    // Default output size: native cropped dimensions.
    if s.dst_w == 0 {
        s.dst_w = cw as u16;
    }
    if s.dst_h == 0 {
        s.dst_h = ch as u16;
    }
    dev_log(s.syscalls.as_ref().unwrap_unchecked(), 3, b"[mkv] hdrs".as_ptr(), 10);
}

/// True when the next queued frame is due for emit (or pacing is
/// unavailable: empty queue / no timer primitive).
unsafe fn pace_ok(s: &mut MkvH264State) -> bool {
    if s.pts_count == 0 {
        return true;
    }
    let pts = s.pts_ring[s.pts_head as usize];
    let now = dev_millis(&*s.syscalls);
    if now == 0 {
        // No timer primitive on this host — emit unpaced.
        return true;
    }
    if s.pace_base_set == 0 || pts < s.pace_base_pts {
        // First frame, or PTS restarted (clip looped without a codec
        // reset) — (re)base the clock mapping.
        s.pace_base_set = 1;
        s.pace_base_ms = now;
        s.pace_base_pts = pts;
        return true;
    }
    now >= s.pace_base_ms + (pts - s.pace_base_pts)
}

/// Drop the head PTS entry (its picture is being emitted).
fn pts_pop(s: &mut MkvH264State) {
    if s.pts_count > 0 {
        s.pts_head = (s.pts_head + 1) % PTS_RING as u8;
        s.pts_count -= 1;
    }
}

/// Pull the next output picture from the DPB into `pending[]` as
/// scaled RGB565. Returns true if a picture was staged.
unsafe fn next_picture(s: &mut MkvH264State) -> bool {
    let mut pic_id = 0u32;
    let mut is_idr = 0u32;
    let mut num_err = 0u32;
    let data = h264_decoder::h264bsdNextOutputPicture(
        &mut s.storage,
        &mut pic_id,
        &mut is_idr,
        &mut num_err,
    );
    if data.is_null() {
        s.more_pics = 0;
        return false;
    }
    let dst_bytes = s.dst_w as u32 * s.dst_h as u32 * 2;
    if s.pending.is_null() {
        let p = ((*s.syscalls).heap_alloc)(dst_bytes);
        if p.is_null() {
            set_err(s, b"[mkv] pending alloc failed");
            s.phase = VPhase::Error;
            return false;
        }
        s.pending = p;
    }
    yuv420_to_rgb565(s, data);
    pts_pop(s);
    s.pending_size = dst_bytes;
    s.pending_pos = 0;
    s.frames_out = s.frames_out.wrapping_add(1);
    true
}

/// Crop + nearest-neighbour stretch + BT.601 limited-range YUV420 →
/// RGB565 LE into `pending[]`.
unsafe fn yuv420_to_rgb565(s: &mut MkvH264State, yuv: *const u8) {
    let w = s.pic_w as usize;
    let h = s.pic_h as usize;
    let (cx, cy, cw, ch) = (
        s.crop_x as usize,
        s.crop_y as usize,
        s.crop_w as usize,
        s.crop_h as usize,
    );
    let dw = s.dst_w as usize;
    let dh = s.dst_h as usize;
    let y_plane = yuv;
    let cb_plane = yuv.add(w * h);
    let cr_plane = yuv.add(w * h + w * h / 4);
    let dst = s.pending;

    for dy in 0..dh {
        let sy = cy + h264::udiv((dy * ch) as u32, dh as u32) as usize;
        let yrow = y_plane.add(sy * w);
        let crow = (sy / 2) * (w / 2);
        for dx in 0..dw {
            let sx = cx + h264::udiv((dx * cw) as u32, dw as u32) as usize;
            let yv = *yrow.add(sx) as i32;
            let u = *cb_plane.add(crow + sx / 2) as i32;
            let v = *cr_plane.add(crow + sx / 2) as i32;
            let c = 298 * (yv - 16);
            let r = (c + 409 * (v - 128) + 128) >> 8;
            let g = (c - 100 * (u - 128) - 208 * (v - 128) + 128) >> 8;
            let b = (c + 516 * (u - 128) + 128) >> 8;
            let r = if r < 0 { 0 } else if r > 255 { 255 } else { r } as u16;
            let g = if g < 0 { 0 } else if g > 255 { 255 } else { g } as u16;
            let b = if b < 0 { 0 } else if b > 255 { 255 } else { b } as u16;
            let px = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
            let off = (dy * dw + dx) * 2;
            *dst.add(off) = px as u8;
            *dst.add(off + 1) = (px >> 8) as u8;
        }
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────

/// Flow-observability heartbeat: one line with output progress +
/// ES fill + phase, emitted on the parent's heartbeat cadence.
/// `out=` frozen across heartbeats while `es=` holds bytes is the
/// wedged-drain signature.
pub unsafe fn mkv_heartbeat(s: &MkvH264State, sys: &SyscallTable) {
    let mut buf = [0u8; 96];
    let p = buf.as_mut_ptr();
    let mut q = 0usize;
    let pfx = b"[mkv] hb out=";
    let mut t = 0;
    while t < pfx.len() { *p.add(q) = pfx[t]; q += 1; t += 1; }
    q += super::fmt_u32_raw(p.add(q), s.frames_out);
    let es = b" es=";
    let mut t = 0;
    while t < es.len() { *p.add(q) = es[t]; q += 1; t += 1; }
    q += super::fmt_u32_raw(p.add(q), s.es_len.saturating_sub(s.es_pos));
    let ph = b" phase=";
    let mut t = 0;
    while t < ph.len() { *p.add(q) = ph[t]; q += 1; t += 1; }
    q += super::fmt_u32_raw(p.add(q), s.phase as u32);
    dev_log(sys, 3, p, q);
}

unsafe fn set_err(s: &mut MkvH264State, msg: &[u8]) {
    let n = msg.len().min(s.last_err.len());
    s.last_err[..n].copy_from_slice(&msg[..n]);
    s.last_err_len = n as u8;
    if !s.syscalls.is_null() {
        dev_log(&*s.syscalls, 2, msg.as_ptr(), msg.len());
    }
}
