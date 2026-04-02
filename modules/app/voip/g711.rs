// G.711 u-law codec: decode table, encode function, step_decode, step_encode.

// ============================================================================
// Constants
// ============================================================================

/// Max u-law bytes per decode step (64 → 256 PCM bytes in dec_out_buf)
const DEC_IN_MAX: usize = 64;

/// u-law bias (ITU-T G.711)
const ULAW_BIAS: i16 = 0x84;
/// u-law clip level
const ULAW_CLIP: i16 = 0x7F7B;

// ============================================================================
// u-law to Linear PCM Decode Table
// ============================================================================

static ULAW_TO_LINEAR: [i16; 256] = [
    -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
    -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
    -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
    -11900, -11388, -10876, -10364,  -9852,  -9340,  -8828,  -8316,
     -7932,  -7676,  -7420,  -7164,  -6908,  -6652,  -6396,  -6140,
     -5884,  -5628,  -5372,  -5116,  -4860,  -4604,  -4348,  -4092,
     -3900,  -3772,  -3644,  -3516,  -3388,  -3260,  -3132,  -3004,
     -2876,  -2748,  -2620,  -2492,  -2364,  -2236,  -2108,  -1980,
     -1884,  -1820,  -1756,  -1692,  -1628,  -1564,  -1500,  -1436,
     -1372,  -1308,  -1244,  -1180,  -1116,  -1052,   -988,   -924,
      -876,   -844,   -812,   -780,   -748,   -716,   -684,   -652,
      -620,   -588,   -556,   -524,   -492,   -460,   -428,   -396,
      -372,   -356,   -340,   -324,   -308,   -292,   -276,   -260,
      -244,   -228,   -212,   -196,   -180,   -164,   -148,   -132,
      -120,   -112,   -104,    -96,    -88,    -80,    -72,    -64,
       -56,    -48,    -40,    -32,    -24,    -16,     -8,      0,
     32124,  31100,  30076,  29052,  28028,  27004,  25980,  24956,
     23932,  22908,  21884,  20860,  19836,  18812,  17788,  16764,
     15996,  15484,  14972,  14460,  13948,  13436,  12924,  12412,
     11900,  11388,  10876,  10364,   9852,   9340,   8828,   8316,
      7932,   7676,   7420,   7164,   6908,   6652,   6396,   6140,
      5884,   5628,   5372,   5116,   4860,   4604,   4348,   4092,
      3900,   3772,   3644,   3516,   3388,   3260,   3132,   3004,
      2876,   2748,   2620,   2492,   2364,   2236,   2108,   1980,
      1884,   1820,   1756,   1692,   1628,   1564,   1500,   1436,
      1372,   1308,   1244,   1180,   1116,   1052,    988,    924,
       876,    844,    812,    780,    748,    716,    684,    652,
       620,    588,    556,    524,    492,    460,    428,    396,
       372,    356,    340,    324,    308,    292,    276,    260,
       244,    228,    212,    196,    180,    164,    148,    132,
       120,    112,    104,     96,     88,     80,     72,     64,
        56,     48,     40,     32,     24,     16,      8,      0,
];

// ============================================================================
// u-law Encode (algorithmic, ITU-T G.711)
// ============================================================================

#[inline(always)]
fn linear_to_ulaw(sample: i16) -> u8 {
    let sign: u8;
    let mut mag: i16;
    if sample < 0 {
        mag = if sample <= -32767 { 32767 } else { -sample };
        sign = 0x80;
    } else {
        mag = sample;
        sign = 0;
    }

    if mag > ULAW_CLIP {
        mag = ULAW_CLIP;
    }

    mag += ULAW_BIAS;

    let mut segment: u8 = 0;
    let mut shifted = mag >> 7;
    while shifted > 0 {
        segment += 1;
        shifted >>= 1;
    }

    let quant = if segment >= 1 {
        ((mag >> (segment + 3)) & 0x0F) as u8
    } else {
        ((mag >> 4) & 0x0F) as u8
    };

    !(sign | (segment << 4) | quant)
}

// ============================================================================
// Decode: jitter_out_buf → PCM stereo → out[0]
// ============================================================================

unsafe fn step_decode(s: &mut VoipState) {
    let sys = &*s.syscalls;
    let out_chan = s.decode_out;

    // Drain pending output from previous step
    if !drain_pending(sys, out_chan, s.dec_out_buf.as_ptr(),
                      &mut s.dec_pending_out, &mut s.dec_pending_offset) {
        return;
    }

    // Check if jitter has data
    if s.jitter_out_len == 0 || s.jitter_out_offset >= s.jitter_out_len {
        return;
    }

    // Check output ready
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
        return;
    }

    // Read from jitter output buffer (max 64 u-law bytes → 256 PCM bytes)
    let remaining = (s.jitter_out_len - s.jitter_out_offset) as usize;
    let in_count = if remaining > DEC_IN_MAX { DEC_IN_MAX } else { remaining };

    // Decode u-law to i16 stereo
    let in_ptr = s.jitter_out_buf.as_ptr().add(s.jitter_out_offset as usize);
    let out_ptr = s.dec_out_buf.as_mut_ptr();
    let mut i: usize = 0;
    while i < in_count {
        let sample = ULAW_TO_LINEAR[*in_ptr.add(i) as usize];
        let sample_bytes = sample.to_le_bytes();
        let out_off = i * 4;
        *out_ptr.add(out_off) = sample_bytes[0];
        *out_ptr.add(out_off + 1) = sample_bytes[1];
        *out_ptr.add(out_off + 2) = sample_bytes[0];
        *out_ptr.add(out_off + 3) = sample_bytes[1];
        i += 1;
    }

    let out_bytes = in_count * 4;

    let written = (sys.channel_write)(out_chan, s.dec_out_buf.as_ptr(), out_bytes);
    if written < 0 && written != E_AGAIN {
        return;
    }

    track_pending(written, out_bytes, &mut s.dec_pending_out, &mut s.dec_pending_offset);

    // Advance jitter output offset
    s.jitter_out_offset += in_count as u16;
    if s.jitter_out_offset >= s.jitter_out_len {
        s.jitter_out_len = 0;
        s.jitter_out_offset = 0;
    }
}

// ============================================================================
// Encode: in[0] → PCM stereo to G.711 u-law → out[1]
// ============================================================================

unsafe fn step_encode(s: &mut VoipState) {
    let sys = &*s.syscalls;
    let in_chan = s.encode_in;
    let out_chan = s.encode_out;

    // Drain pending output
    if !drain_pending(sys, out_chan, s.enc_out_buf.as_ptr(),
                      &mut s.enc_pending_out, &mut s.enc_pending_offset) {
        return;
    }

    // Check output ready
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
        return;
    }

    // Check input available
    let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
    if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 {
        return;
    }

    // Read stereo PCM
    let read = (sys.channel_read)(in_chan, s.enc_in_buf.as_mut_ptr(), ENC_IN_BUF_SIZE);
    if read <= 0 {
        return;
    }

    let in_bytes = read as usize;
    let sample_count = in_bytes / 4;
    if sample_count == 0 {
        return;
    }

    // Encode stereo PCM to mono u-law
    let in_ptr = s.enc_in_buf.as_ptr();
    let out_ptr = s.enc_out_buf.as_mut_ptr();
    let mut i: usize = 0;
    while i < sample_count {
        let off = i * 4;
        let left = i16::from_le_bytes([*in_ptr.add(off), *in_ptr.add(off + 1)]);
        let right = i16::from_le_bytes([*in_ptr.add(off + 2), *in_ptr.add(off + 3)]);
        let mono = ((left as i32 + right as i32) / 2) as i16;
        *out_ptr.add(i) = linear_to_ulaw(mono);
        i += 1;
    }

    let written = (sys.channel_write)(out_chan, s.enc_out_buf.as_ptr(), sample_count);
    if written < 0 && written != E_AGAIN {
        return;
    }

    track_pending(written, sample_count, &mut s.enc_pending_out, &mut s.enc_pending_offset);
}
