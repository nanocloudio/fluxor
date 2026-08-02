// Base64 (RFC 4648, standard alphabet, `=` padding) — portable, no_std,
// no heap, no unsafe. Encode/decode into caller buffers, `None` on overflow
// or malformed input. Used by protocol handshakes that carry binary values in
// text fields (SCRAM messages, WebSocket `Sec-WebSocket-Accept`). Include!-able
// like the other `sdk/crypto` sources (no inner attributes, no test module).
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 encode (with `=` padding). Returns the length or `None`.
pub fn b64_encode(data: &[u8], out: &mut [u8]) -> Option<usize> {
    let outlen = data.len().div_ceil(3) * 4;
    if out.len() < outlen {
        return None;
    }
    let mut o = 0;
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out[o] = B64[((n >> 18) & 63) as usize];
        out[o + 1] = B64[((n >> 12) & 63) as usize];
        out[o + 2] = B64[((n >> 6) & 63) as usize];
        out[o + 3] = B64[(n & 63) as usize];
        o += 4;
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out[o] = B64[((n >> 18) & 63) as usize];
            out[o + 1] = B64[((n >> 12) & 63) as usize];
            out[o + 2] = b'=';
            out[o + 3] = b'=';
            o += 4;
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out[o] = B64[((n >> 18) & 63) as usize];
            out[o + 1] = B64[((n >> 12) & 63) as usize];
            out[o + 2] = B64[((n >> 6) & 63) as usize];
            out[o + 3] = b'=';
            o += 4;
        }
        _ => {}
    }
    Some(o)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard Base64 decode (ignores `=`/CR/LF). Returns the length or `None` on a
/// bad character or insufficient output space.
pub fn b64_decode(data: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut o = 0;
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in data {
        if c == b'=' || c == b'\r' || c == b'\n' {
            continue;
        }
        let v = b64_val(c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if o >= out.len() {
                return None;
            }
            out[o] = (buf >> bits) as u8;
            o += 1;
        }
    }
    Some(o)
}
