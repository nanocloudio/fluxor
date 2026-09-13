// SHA-1 (RFC 3174) — one-shot, portable, no_std, no heap, no unsafe.
//
// SHA-1 is broken for collision resistance and MUST NOT be used for new
// designs; it exists here only because deployed protocols still require it:
// MySQL `mysql_native_password` (SHA-1 challenge-response) and the WebSocket
// upgrade handshake's `Sec-WebSocket-Accept` (RFC 6455). Include!-able like the
// other `sdk/crypto` sources (no inner attributes, no test module).
fn sha1_block(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    let mut t = 0;
    while t < 16 {
        w[t] = u32::from_be_bytes([
            block[t * 4],
            block[t * 4 + 1],
            block[t * 4 + 2],
            block[t * 4 + 3],
        ]);
        t += 1;
    }
    while t < 80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        t += 1;
    }
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    let mut i = 0;
    while i < 80 {
        let (f, k) = if i < 20 {
            ((b & c) | ((!b) & d), 0x5A827999u32)
        } else if i < 40 {
            (b ^ c ^ d, 0x6ED9EBA1)
        } else if i < 60 {
            ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
        } else {
            (b ^ c ^ d, 0xCA62C1D6)
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
        i += 1;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// One-shot SHA-1. Inputs here are small (≤40 bytes), so a two-block scratch
/// suffices for the padded final block.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = [
        0x67452301u32,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ];
    let mut i = 0;
    while i + 64 <= data.len() {
        sha1_block(&mut h, &data[i..i + 64]);
        i += 64;
    }
    let rem = &data[i..];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut block = [0u8; 128];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    let total = if rem.len() + 1 + 8 <= 64 { 64 } else { 128 };
    block[total - 8..total].copy_from_slice(&bitlen.to_be_bytes());
    sha1_block(&mut h, &block[..64]);
    if total == 128 {
        sha1_block(&mut h, &block[64..128]);
    }
    let mut out = [0u8; 20];
    let mut j = 0;
    while j < 5 {
        out[j * 4..j * 4 + 4].copy_from_slice(&h[j].to_be_bytes());
        j += 1;
    }
    out
}
