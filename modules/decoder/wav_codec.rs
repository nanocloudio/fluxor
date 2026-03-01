// WAV codec kernel for unified decoder.
//
// Extracted from wav.rs — contains state struct, header parsing, and
// init/step functions. No module boilerplate (#[no_mangle], panic handler).
//
// Used by: modules/decoder/mod.rs (unified decoder)
// Standalone: modules/wav.rs (unchanged, still builds independently)

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, drain_pending, track_pending, p_u32, dev_log};

// ============================================================================
// Constants
// ============================================================================

const WAV_IO_BUF_SIZE: usize = 256;

/// Header buffer size (enough for any reasonable WAV header)
const HEADER_BUF_SIZE: usize = 512;

/// WAV codec parsing phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum WavPhase {
    ParsingHeader = 0,
    SkippingToData = 1,
    StreamingData = 2,
    Done = 3,
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
unsafe fn read_u16_le(ptr: *const u8) -> u16 {
    (*ptr as u16) | ((*ptr.add(1) as u16) << 8)
}

#[inline(always)]
unsafe fn read_u32_le(ptr: *const u8) -> u32 {
    (*ptr as u32) | ((*ptr.add(1) as u32) << 8) | ((*ptr.add(2) as u32) << 16) | ((*ptr.add(3) as u32) << 24)
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
pub struct WavState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    /// Parsing phase
    phase: WavPhase,
    _pad0: u8,
    /// Number of audio channels in WAV file
    channels: u16,
    /// Bits per sample
    bits_per_sample: u16,
    /// Block alignment (bytes per frame)
    block_align: u16,
    /// Sample rate from WAV header
    sample_rate: u32,
    /// Byte offset where audio data begins (from start of file)
    data_offset: u32,
    /// Total audio data size in bytes
    data_size: u32,
    /// Bytes of audio data forwarded so far
    data_read: u32,
    /// Total bytes consumed from input (for tracking position during skip)
    bytes_consumed: u32,
    /// How many header bytes we've collected
    header_len: u16,
    /// Pending output tracking
    pending_out: u16,
    pending_offset: u16,
    _pad1: u16,
    /// Header buffer for accumulating initial bytes
    header_buf: [u8; HEADER_BUF_SIZE],
    /// I/O buffer for pass-through streaming
    io_buf: [u8; WAV_IO_BUF_SIZE],
}

// ============================================================================
// WAV Header Parsing
// ============================================================================

/// Parse WAV header from buffered data.
/// Returns true if header was successfully parsed, false if more data needed or error.
unsafe fn parse_wav_header(s: &mut WavState) -> bool {
    let buf = s.header_buf.as_ptr();
    let len = s.header_len as usize;

    // Need at least 44 bytes for a minimal WAV header
    if len < 44 {
        return false;
    }

    // Check RIFF magic (bytes 0-3): 'R','I','F','F'
    if *buf != b'R' || *buf.add(1) != b'I' || *buf.add(2) != b'F' || *buf.add(3) != b'F' {
        return false;
    }

    // Check WAVE magic (bytes 8-11): 'W','A','V','E'
    if *buf.add(8) != b'W' || *buf.add(9) != b'A' || *buf.add(10) != b'V' || *buf.add(11) != b'E' {
        return false;
    }

    // Walk chunks starting at offset 12
    let mut offset: usize = 12;
    let mut found_fmt = false;
    let mut found_data = false;

    while offset + 8 <= len {
        let chunk_id_ptr = buf.add(offset);
        let chunk_size = read_u32_le(buf.add(offset + 4)) as usize;

        let is_fmt = *chunk_id_ptr == b'f'
            && *chunk_id_ptr.add(1) == b'm'
            && *chunk_id_ptr.add(2) == b't'
            && *chunk_id_ptr.add(3) == b' ';

        let is_data = *chunk_id_ptr == b'd'
            && *chunk_id_ptr.add(1) == b'a'
            && *chunk_id_ptr.add(2) == b't'
            && *chunk_id_ptr.add(3) == b'a';

        if is_fmt {
            if offset + 8 + 16 > len {
                return false;
            }
            let fmt_ptr = buf.add(offset + 8);
            let audio_format = read_u16_le(fmt_ptr);
            if audio_format != 1 {
                return false; // Not PCM
            }
            s.channels = read_u16_le(fmt_ptr.add(2));
            s.sample_rate = read_u32_le(fmt_ptr.add(4));
            s.block_align = read_u16_le(fmt_ptr.add(12));
            s.bits_per_sample = read_u16_le(fmt_ptr.add(14));
            found_fmt = true;
        }

        if is_data {
            s.data_offset = (offset + 8) as u32;
            s.data_size = chunk_size as u32;
            found_data = true;
        }

        if found_fmt && found_data {
            return true;
        }

        let padded_size = if chunk_size & 1 != 0 { chunk_size + 1 } else { chunk_size };
        offset += 8 + padded_size;
    }

    if found_fmt && found_data {
        return true;
    }

    if len >= HEADER_BUF_SIZE {
        return false;
    }

    false
}

// ============================================================================
// Codec API (called by decoder.rs)
// ============================================================================

/// Initialize WAV codec state.
pub unsafe fn wav_init(
    s: &mut WavState,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.phase = WavPhase::ParsingHeader;
    s.channels = 0;
    s.bits_per_sample = 0;
    s.block_align = 0;
    s.sample_rate = 0;
    s.data_offset = 0;
    s.data_size = 0;
    s.data_read = 0;
    s.bytes_consumed = 0;
    s.header_len = 0;
    s.pending_out = 0;
    s.pending_offset = 0;
}

/// Feed initial detection bytes into WAV header buffer.
/// Call after wav_init, before first wav_step, to provide bytes
/// already consumed during format detection.
pub unsafe fn wav_feed_detect(s: &mut WavState, buf: *const u8, len: usize) {
    let to_copy = if len > HEADER_BUF_SIZE { HEADER_BUF_SIZE } else { len };
    let mut i: usize = 0;
    while i < to_copy {
        *s.header_buf.as_mut_ptr().add(i) = *buf.add(i);
        i += 1;
    }
    s.header_len = to_copy as u16;
    s.bytes_consumed = to_copy as u32;
}

/// Returns true if the WAV codec has finished (DONE state).
pub unsafe fn wav_is_done(s: &WavState) -> bool {
    s.phase == WavPhase::Done
}

/// Step the WAV codec. Returns 0 on success.
pub unsafe fn wav_step(s: &mut WavState) -> i32 {
    if s.syscalls.is_null() {
        return -1;
    }

    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    if s.phase == WavPhase::Done {
        return 0;
    }

    // Drain pending output
    if s.phase == WavPhase::StreamingData {
        if !drain_pending(sys, out_chan, s.io_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
            return 0;
        }
    }

    // State: PARSING_HEADER
    if s.phase == WavPhase::ParsingHeader {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 {
            return 0;
        }

        let space = HEADER_BUF_SIZE - (s.header_len as usize);
        if space == 0 {
            dev_log(sys, 1, b"[wav] hdr too big".as_ptr(), 16);
            s.phase = WavPhase::Done;
            return 0;
        }

        let read = (sys.channel_read)(
            in_chan,
            s.header_buf.as_mut_ptr().add(s.header_len as usize),
            space,
        );
        if read <= 0 {
            return 0;
        }

        s.header_len += read as u16;
        s.bytes_consumed += read as u32;

        if parse_wav_header(s) {
            dev_log(sys, 3, b"[wav] hdr ok".as_ptr(), 12);

            if s.bytes_consumed >= s.data_offset {
                let excess_start = s.data_offset as usize;
                let excess_end = s.bytes_consumed as usize;
                if excess_end > excess_start {
                    let excess_len = excess_end - excess_start;
                    let to_write = if excess_len as u32 > s.data_size {
                        s.data_size as usize
                    } else {
                        excess_len
                    };

                    if to_write > 0 {
                        let mut written_total: usize = 0;
                        while written_total < to_write {
                            let chunk = to_write - written_total;
                            let chunk = if chunk > WAV_IO_BUF_SIZE { WAV_IO_BUF_SIZE } else { chunk };

                            let src = s.header_buf.as_ptr().add(excess_start + written_total);
                            let dst = s.io_buf.as_mut_ptr();
                            let mut i: usize = 0;
                            while i < chunk {
                                *dst.add(i) = *src.add(i);
                                i += 1;
                            }

                            let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
                            if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
                                s.pending_offset = 0;
                                s.pending_out = chunk as u16;
                                s.data_read += written_total as u32;
                                s.phase = WavPhase::StreamingData;
                                return 0;
                            }

                            let written = (sys.channel_write)(out_chan, s.io_buf.as_ptr(), chunk);
                            if written > 0 {
                                track_pending(written, chunk, &mut s.pending_out, &mut s.pending_offset);
                                written_total += written as usize;
                                if s.pending_out > 0 {
                                    s.data_read += written_total as u32;
                                    s.phase = WavPhase::StreamingData;
                                    return 0;
                                }
                            } else {
                                s.pending_offset = 0;
                                s.pending_out = chunk as u16;
                                s.data_read += written_total as u32;
                                s.phase = WavPhase::StreamingData;
                                return 0;
                            }
                        }
                        s.data_read += written_total as u32;
                    }
                }
                s.phase = WavPhase::StreamingData;
            } else {
                s.phase = WavPhase::SkippingToData;
            }
        }
        return 0;
    }

    // State: SKIPPING_TO_DATA
    if s.phase == WavPhase::SkippingToData {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 {
            return 0;
        }

        let remaining = s.data_offset - s.bytes_consumed;
        if remaining == 0 {
            s.phase = WavPhase::StreamingData;
            return 0;
        }

        let to_read = if remaining as usize > WAV_IO_BUF_SIZE {
            WAV_IO_BUF_SIZE
        } else {
            remaining as usize
        };

        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), to_read);
        if read <= 0 {
            return 0;
        }

        s.bytes_consumed += read as u32;
        if s.bytes_consumed >= s.data_offset {
            s.phase = WavPhase::StreamingData;
        }

        return 0;
    }

    // State: STREAMING_DATA
    if s.phase == WavPhase::StreamingData {
        if s.data_size > 0 && s.data_read >= s.data_size {
            s.phase = WavPhase::Done;
            dev_log(sys, 3, b"[wav] done".as_ptr(), 10);
            return 0;
        }

        let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
            return 0;
        }

        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 {
            return 0;
        }

        let data_remaining = if s.data_size > 0 {
            s.data_size - s.data_read
        } else {
            WAV_IO_BUF_SIZE as u32
        };
        let to_read = if data_remaining as usize > WAV_IO_BUF_SIZE {
            WAV_IO_BUF_SIZE
        } else {
            data_remaining as usize
        };

        if to_read == 0 {
            s.phase = WavPhase::Done;
            dev_log(sys, 3, b"[wav] done".as_ptr(), 10);
            return 0;
        }

        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), to_read);
        if read <= 0 {
            return 0;
        }

        let byte_count = read as usize;
        let written = (sys.channel_write)(out_chan, s.io_buf.as_ptr(), byte_count);
        track_pending(written, byte_count, &mut s.pending_out, &mut s.pending_offset);

        if written > 0 {
            s.data_read += written as u32;
        }

        return 0;
    }

    0
}
