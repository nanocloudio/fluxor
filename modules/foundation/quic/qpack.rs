// QPACK header compression — RFC 9204 — vendored for the QUIC module.
//
// Mirrors `modules/foundation/http/qpack.rs` byte-for-byte minus the
// redundant `mod varint;` declaration (the QUIC module already pulls
// in the varint codec at the top of `mod.rs`). When the http module
// gains live HTTP/3 wiring it will share this same source via
// `include!`.

/// QPACK static-table size (RFC 9204 Appendix A).
pub const QPACK_STATIC_COUNT: u32 = 99;

/// Lookup a static-table entry by 0-based index (RFC 9204 Appendix A).
pub fn qpack_static_lookup(idx: u32) -> Option<(&'static [u8], &'static [u8])> {
    Some(match idx {
        0 => (b":authority", b""),
        1 => (b":path", b"/"),
        2 => (b"age", b"0"),
        3 => (b"content-disposition", b""),
        4 => (b"content-length", b"0"),
        5 => (b"cookie", b""),
        6 => (b"date", b""),
        7 => (b"etag", b""),
        8 => (b"if-modified-since", b""),
        9 => (b"if-none-match", b""),
        10 => (b"last-modified", b""),
        11 => (b"link", b""),
        12 => (b"location", b""),
        13 => (b"referer", b""),
        14 => (b"set-cookie", b""),
        15 => (b":method", b"CONNECT"),
        16 => (b":method", b"DELETE"),
        17 => (b":method", b"GET"),
        18 => (b":method", b"HEAD"),
        19 => (b":method", b"OPTIONS"),
        20 => (b":method", b"POST"),
        21 => (b":method", b"PUT"),
        22 => (b":scheme", b"http"),
        23 => (b":scheme", b"https"),
        24 => (b":status", b"103"),
        25 => (b":status", b"200"),
        26 => (b":status", b"304"),
        27 => (b":status", b"404"),
        28 => (b":status", b"503"),
        29 => (b"accept", b"*/*"),
        30 => (b"accept", b"application/dns-message"),
        31 => (b"accept-encoding", b"gzip, deflate, br"),
        32 => (b"accept-ranges", b"bytes"),
        33 => (b"access-control-allow-headers", b"cache-control"),
        34 => (b"access-control-allow-headers", b"content-type"),
        35 => (b"access-control-allow-origin", b"*"),
        36 => (b"cache-control", b"max-age=0"),
        37 => (b"cache-control", b"max-age=2592000"),
        38 => (b"cache-control", b"max-age=604800"),
        39 => (b"cache-control", b"no-cache"),
        40 => (b"cache-control", b"no-store"),
        41 => (b"cache-control", b"public, max-age=31536000"),
        42 => (b"content-encoding", b"br"),
        43 => (b"content-encoding", b"gzip"),
        44 => (b"content-type", b"application/dns-message"),
        45 => (b"content-type", b"application/javascript"),
        46 => (b"content-type", b"application/json"),
        47 => (b"content-type", b"application/x-www-form-urlencoded"),
        48 => (b"content-type", b"image/gif"),
        49 => (b"content-type", b"image/jpeg"),
        50 => (b"content-type", b"image/png"),
        51 => (b"content-type", b"text/css"),
        52 => (b"content-type", b"text/html; charset=utf-8"),
        53 => (b"content-type", b"text/plain"),
        54 => (b"content-type", b"text/plain;charset=utf-8"),
        55 => (b"range", b"bytes=0-"),
        56 => (b"strict-transport-security", b"max-age=31536000"),
        57 => (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
        58 => (b"strict-transport-security", b"max-age=31536000; includesubdomains; preload"),
        59 => (b"vary", b"accept-encoding"),
        60 => (b"vary", b"origin"),
        61 => (b"x-content-type-options", b"nosniff"),
        62 => (b"x-xss-protection", b"1; mode=block"),
        63 => (b":status", b"100"),
        64 => (b":status", b"204"),
        65 => (b":status", b"206"),
        66 => (b":status", b"302"),
        67 => (b":status", b"400"),
        68 => (b":status", b"403"),
        69 => (b":status", b"421"),
        70 => (b":status", b"425"),
        71 => (b":status", b"500"),
        72 => (b"accept-language", b""),
        73 => (b"access-control-allow-credentials", b"FALSE"),
        74 => (b"access-control-allow-credentials", b"TRUE"),
        75 => (b"access-control-allow-headers", b"*"),
        76 => (b"access-control-allow-methods", b"get"),
        77 => (b"access-control-allow-methods", b"get, post, options"),
        78 => (b"access-control-allow-methods", b"options"),
        79 => (b"access-control-expose-headers", b"content-length"),
        80 => (b"access-control-request-headers", b"content-type"),
        81 => (b"access-control-request-method", b"get"),
        82 => (b"access-control-request-method", b"post"),
        83 => (b"alt-svc", b"clear"),
        84 => (b"authorization", b""),
        85 => (b"content-security-policy", b"script-src 'none'; object-src 'none'; base-uri 'none'"),
        86 => (b"early-data", b"1"),
        87 => (b"expect-ct", b""),
        88 => (b"forwarded", b""),
        89 => (b"if-range", b""),
        90 => (b"origin", b""),
        91 => (b"purpose", b"prefetch"),
        92 => (b"server", b""),
        93 => (b"timing-allow-origin", b"*"),
        94 => (b"upgrade-insecure-requests", b"1"),
        95 => (b"user-agent", b""),
        96 => (b"x-forwarded-for", b""),
        97 => (b"x-frame-options", b"deny"),
        98 => (b"x-frame-options", b"sameorigin"),
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// QPACK integer codec (RFC 9204 §4.1.1)
// ---------------------------------------------------------------------

pub fn qpack_encode_int(value: u64, prefix_bits: u8, flags: u8, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out[0] = (flags & !mask_low(prefix_bits)) | (value as u8);
        return 1;
    }
    out[0] = (flags & !mask_low(prefix_bits)) | (max as u8);
    let mut remainder = value - max;
    let mut cursor = 1;
    while remainder >= 128 {
        if cursor >= out.len() {
            return 0;
        }
        out[cursor] = ((remainder & 0x7F) as u8) | 0x80;
        cursor += 1;
        remainder >>= 7;
    }
    if cursor >= out.len() {
        return 0;
    }
    out[cursor] = remainder as u8;
    cursor + 1
}

pub fn qpack_decode_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let mask = mask_low(prefix_bits) as u64;
    let mut value = (buf[0] as u64) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    let mut cursor = 1;
    loop {
        if cursor >= buf.len() {
            return None;
        }
        let b = buf[cursor];
        cursor += 1;
        // RFC 7541 §5.1: reject encodings that don't fit in u64 instead
        // of wrapping. `shift >= 64` would shift the contribution off
        // the end; at shift == 63 only the low bit of (b & 0x7F) is
        // representable, the other 6 bits would silently truncate.
        if shift >= 64 {
            return None;
        }
        let chunk = (b as u64) & 0x7F;
        let max_chunk = (u64::MAX >> shift) & 0x7F;
        if chunk > max_chunk {
            return None;
        }
        value = match value.checked_add(chunk << shift) {
            Some(v) => v,
            None => return None,
        };
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((value, cursor))
}

fn mask_low(bits: u8) -> u8 {
    if bits >= 8 {
        0xFF
    } else {
        ((1u16 << bits) - 1) as u8
    }
}

// ----------------------------------------------------------------------
// QPACK Huffman decode (RFC 7541 Appendix B).
// ----------------------------------------------------------------------

/// Decode `input` as a Huffman-coded byte stream into `out`. Returns
/// `Some(written)` on success, `None` on truncation, an embedded EOS
/// symbol (RFC 7541 §5.2 forbids), or a code longer than 30 bits.
/// Failure maps to QPACK_DECOMPRESSION_FAILED at the caller.
pub fn qpack_huffman_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    // 64-bit accumulator. The longest legal code is 30 bits; the
    // refill loop keeps at most 56 buffered bits so a fresh byte can
    // always shift in without overflow.
    let mut acc: u64 = 0;
    let mut bits: u8 = 0;
    let mut written = 0usize;
    let mut i = 0usize;
    loop {
        while bits <= 56 && i < input.len() {
            acc = (acc << 8) | (input[i] as u64);
            bits += 8;
            i += 1;
        }
        if bits == 0 {
            return Some(written);
        }
        // Codes are prefix-free, so the first matching length wins.
        let mut matched = false;
        let mut try_len: u8 = 5;
        while try_len <= 30 {
            if bits < try_len {
                break;
            }
            let shift = bits - try_len;
            let code = ((acc >> shift) as u32) & ((1u32 << try_len) - 1);
            if let Some(sym) = huffman_lookup(code, try_len) {
                if written < out.len() {
                    out[written] = sym;
                    written += 1;
                    bits -= try_len;
                    if bits == 0 {
                        acc = 0;
                    } else {
                        acc &= (1u64 << bits).wrapping_sub(1);
                    }
                    matched = true;
                    break;
                } else {
                    return None;
                }
            }
            try_len += 1;
        }
        if !matched {
            // ≤ 7 trailing bits all set is valid EOS padding
            // (RFC 7541 §5.2).
            if i >= input.len() && bits < 8 {
                let pad = (1u64 << bits) - 1;
                if acc == pad {
                    return Some(written);
                }
            }
            return None;
        }
    }
}

/// Lookup a Huffman code prefix in the RFC 7541 Appendix B table.
/// EOS (symbol 256, code `0x3fffffff` length 30) is intentionally
/// absent so an embedded EOS surfaces as None.
fn huffman_lookup(code: u32, len: u8) -> Option<u8> {
    match (len, code) {
        // 5-bit codes (10 entries)
        (5, 0x0) => Some(48),  // '0'
        (5, 0x1) => Some(49),  // '1'
        (5, 0x2) => Some(50),  // '2'
        (5, 0x3) => Some(97),  // 'a'
        (5, 0x4) => Some(99),  // 'c'
        (5, 0x5) => Some(101),  // 'e'
        (5, 0x6) => Some(105),  // 'i'
        (5, 0x7) => Some(111),  // 'o'
        (5, 0x8) => Some(115),  // 's'
        (5, 0x9) => Some(116),  // 't'
        // 6-bit codes (26 entries)
        (6, 0x14) => Some(32),  // ' '
        (6, 0x15) => Some(37),  // '%'
        (6, 0x16) => Some(45),  // '-'
        (6, 0x17) => Some(46),  // '.'
        (6, 0x18) => Some(47),  // '/'
        (6, 0x19) => Some(51),  // '3'
        (6, 0x1a) => Some(52),  // '4'
        (6, 0x1b) => Some(53),  // '5'
        (6, 0x1c) => Some(54),  // '6'
        (6, 0x1d) => Some(55),  // '7'
        (6, 0x1e) => Some(56),  // '8'
        (6, 0x1f) => Some(57),  // '9'
        (6, 0x20) => Some(61),  // '='
        (6, 0x21) => Some(65),  // 'A'
        (6, 0x22) => Some(95),  // '_'
        (6, 0x23) => Some(98),  // 'b'
        (6, 0x24) => Some(100),  // 'd'
        (6, 0x25) => Some(102),  // 'f'
        (6, 0x26) => Some(103),  // 'g'
        (6, 0x27) => Some(104),  // 'h'
        (6, 0x28) => Some(108),  // 'l'
        (6, 0x29) => Some(109),  // 'm'
        (6, 0x2a) => Some(110),  // 'n'
        (6, 0x2b) => Some(112),  // 'p'
        (6, 0x2c) => Some(114),  // 'r'
        (6, 0x2d) => Some(117),  // 'u'
        // 7-bit codes (32 entries)
        (7, 0x5c) => Some(58),  // ':'
        (7, 0x5d) => Some(66),  // 'B'
        (7, 0x5e) => Some(67),  // 'C'
        (7, 0x5f) => Some(68),  // 'D'
        (7, 0x60) => Some(69),  // 'E'
        (7, 0x61) => Some(70),  // 'F'
        (7, 0x62) => Some(71),  // 'G'
        (7, 0x63) => Some(72),  // 'H'
        (7, 0x64) => Some(73),  // 'I'
        (7, 0x65) => Some(74),  // 'J'
        (7, 0x66) => Some(75),  // 'K'
        (7, 0x67) => Some(76),  // 'L'
        (7, 0x68) => Some(77),  // 'M'
        (7, 0x69) => Some(78),  // 'N'
        (7, 0x6a) => Some(79),  // 'O'
        (7, 0x6b) => Some(80),  // 'P'
        (7, 0x6c) => Some(81),  // 'Q'
        (7, 0x6d) => Some(82),  // 'R'
        (7, 0x6e) => Some(83),  // 'S'
        (7, 0x6f) => Some(84),  // 'T'
        (7, 0x70) => Some(85),  // 'U'
        (7, 0x71) => Some(86),  // 'V'
        (7, 0x72) => Some(87),  // 'W'
        (7, 0x73) => Some(89),  // 'Y'
        (7, 0x74) => Some(106),  // 'j'
        (7, 0x75) => Some(107),  // 'k'
        (7, 0x76) => Some(113),  // 'q'
        (7, 0x77) => Some(118),  // 'v'
        (7, 0x78) => Some(119),  // 'w'
        (7, 0x79) => Some(120),  // 'x'
        (7, 0x7a) => Some(121),  // 'y'
        (7, 0x7b) => Some(122),  // 'z'
        // 8-bit codes (6 entries)
        (8, 0xf8) => Some(38),  // '&'
        (8, 0xf9) => Some(42),  // '*'
        (8, 0xfa) => Some(44),  // ','
        (8, 0xfb) => Some(59),  // ';'
        (8, 0xfc) => Some(88),  // 'X'
        (8, 0xfd) => Some(90),  // 'Z'
        // 10-bit codes (5 entries)
        (10, 0x3f8) => Some(33),  // '!'
        (10, 0x3f9) => Some(34),  // 0x22
        (10, 0x3fa) => Some(40),  // '('
        (10, 0x3fb) => Some(41),  // ')'
        (10, 0x3fc) => Some(63),  // '?'
        // 11-bit codes (3 entries)
        (11, 0x7fa) => Some(39),  // 0x27
        (11, 0x7fb) => Some(43),  // '+'
        (11, 0x7fc) => Some(124),  // '|'
        // 12-bit codes (2 entries)
        (12, 0xffa) => Some(35),  // '#'
        (12, 0xffb) => Some(62),  // '>'
        // 13-bit codes (6 entries)
        (13, 0x1ff8) => Some(0),  // 0x00
        (13, 0x1ff9) => Some(36),  // '$'
        (13, 0x1ffa) => Some(64),  // '@'
        (13, 0x1ffb) => Some(91),  // '['
        (13, 0x1ffc) => Some(93),  // ']'
        (13, 0x1ffd) => Some(126),  // '~'
        // 14-bit codes (2 entries)
        (14, 0x3ffc) => Some(94),  // '^'
        (14, 0x3ffd) => Some(125),  // '}'
        // 15-bit codes (3 entries)
        (15, 0x7ffc) => Some(60),  // '<'
        (15, 0x7ffd) => Some(96),  // '`'
        (15, 0x7ffe) => Some(123),  // '{'
        // 19-bit codes (3 entries)
        (19, 0x7fff0) => Some(92),  // 0x5c
        (19, 0x7fff1) => Some(195),  // 0xc3
        (19, 0x7fff2) => Some(208),  // 0xd0
        // 20-bit codes (8 entries)
        (20, 0xfffe6) => Some(128),  // 0x80
        (20, 0xfffe7) => Some(130),  // 0x82
        (20, 0xfffe8) => Some(131),  // 0x83
        (20, 0xfffe9) => Some(162),  // 0xa2
        (20, 0xfffea) => Some(184),  // 0xb8
        (20, 0xfffeb) => Some(194),  // 0xc2
        (20, 0xfffec) => Some(224),  // 0xe0
        (20, 0xfffed) => Some(226),  // 0xe2
        // 21-bit codes (13 entries)
        (21, 0x1fffdc) => Some(153),  // 0x99
        (21, 0x1fffdd) => Some(161),  // 0xa1
        (21, 0x1fffde) => Some(167),  // 0xa7
        (21, 0x1fffdf) => Some(172),  // 0xac
        (21, 0x1fffe0) => Some(176),  // 0xb0
        (21, 0x1fffe1) => Some(177),  // 0xb1
        (21, 0x1fffe2) => Some(179),  // 0xb3
        (21, 0x1fffe3) => Some(209),  // 0xd1
        (21, 0x1fffe4) => Some(216),  // 0xd8
        (21, 0x1fffe5) => Some(217),  // 0xd9
        (21, 0x1fffe6) => Some(227),  // 0xe3
        (21, 0x1fffe7) => Some(229),  // 0xe5
        (21, 0x1fffe8) => Some(230),  // 0xe6
        // 22-bit codes (26 entries)
        (22, 0x3fffd2) => Some(129),  // 0x81
        (22, 0x3fffd3) => Some(132),  // 0x84
        (22, 0x3fffd4) => Some(133),  // 0x85
        (22, 0x3fffd5) => Some(134),  // 0x86
        (22, 0x3fffd6) => Some(136),  // 0x88
        (22, 0x3fffd7) => Some(146),  // 0x92
        (22, 0x3fffd8) => Some(154),  // 0x9a
        (22, 0x3fffd9) => Some(156),  // 0x9c
        (22, 0x3fffda) => Some(160),  // 0xa0
        (22, 0x3fffdb) => Some(163),  // 0xa3
        (22, 0x3fffdc) => Some(164),  // 0xa4
        (22, 0x3fffdd) => Some(169),  // 0xa9
        (22, 0x3fffde) => Some(170),  // 0xaa
        (22, 0x3fffdf) => Some(173),  // 0xad
        (22, 0x3fffe0) => Some(178),  // 0xb2
        (22, 0x3fffe1) => Some(181),  // 0xb5
        (22, 0x3fffe2) => Some(185),  // 0xb9
        (22, 0x3fffe3) => Some(186),  // 0xba
        (22, 0x3fffe4) => Some(187),  // 0xbb
        (22, 0x3fffe5) => Some(189),  // 0xbd
        (22, 0x3fffe6) => Some(190),  // 0xbe
        (22, 0x3fffe7) => Some(196),  // 0xc4
        (22, 0x3fffe8) => Some(198),  // 0xc6
        (22, 0x3fffe9) => Some(228),  // 0xe4
        (22, 0x3fffea) => Some(232),  // 0xe8
        (22, 0x3fffeb) => Some(233),  // 0xe9
        // 23-bit codes (29 entries)
        (23, 0x7fffd8) => Some(1),  // 0x01
        (23, 0x7fffd9) => Some(135),  // 0x87
        (23, 0x7fffda) => Some(137),  // 0x89
        (23, 0x7fffdb) => Some(138),  // 0x8a
        (23, 0x7fffdc) => Some(139),  // 0x8b
        (23, 0x7fffdd) => Some(140),  // 0x8c
        (23, 0x7fffde) => Some(141),  // 0x8d
        (23, 0x7fffdf) => Some(143),  // 0x8f
        (23, 0x7fffe0) => Some(147),  // 0x93
        (23, 0x7fffe1) => Some(149),  // 0x95
        (23, 0x7fffe2) => Some(150),  // 0x96
        (23, 0x7fffe3) => Some(151),  // 0x97
        (23, 0x7fffe4) => Some(152),  // 0x98
        (23, 0x7fffe5) => Some(155),  // 0x9b
        (23, 0x7fffe6) => Some(157),  // 0x9d
        (23, 0x7fffe7) => Some(158),  // 0x9e
        (23, 0x7fffe8) => Some(165),  // 0xa5
        (23, 0x7fffe9) => Some(166),  // 0xa6
        (23, 0x7fffea) => Some(168),  // 0xa8
        (23, 0x7fffeb) => Some(174),  // 0xae
        (23, 0x7fffec) => Some(175),  // 0xaf
        (23, 0x7fffed) => Some(180),  // 0xb4
        (23, 0x7fffee) => Some(182),  // 0xb6
        (23, 0x7fffef) => Some(183),  // 0xb7
        (23, 0x7ffff0) => Some(188),  // 0xbc
        (23, 0x7ffff1) => Some(191),  // 0xbf
        (23, 0x7ffff2) => Some(197),  // 0xc5
        (23, 0x7ffff3) => Some(231),  // 0xe7
        (23, 0x7ffff4) => Some(239),  // 0xef
        // 24-bit codes (12 entries)
        (24, 0xffffea) => Some(9),  // 0x09
        (24, 0xffffeb) => Some(142),  // 0x8e
        (24, 0xffffec) => Some(144),  // 0x90
        (24, 0xffffed) => Some(145),  // 0x91
        (24, 0xffffee) => Some(148),  // 0x94
        (24, 0xffffef) => Some(159),  // 0x9f
        (24, 0xfffff0) => Some(171),  // 0xab
        (24, 0xfffff1) => Some(206),  // 0xce
        (24, 0xfffff2) => Some(215),  // 0xd7
        (24, 0xfffff3) => Some(225),  // 0xe1
        (24, 0xfffff4) => Some(236),  // 0xec
        (24, 0xfffff5) => Some(237),  // 0xed
        // 25-bit codes (4 entries)
        (25, 0x1ffffec) => Some(199),  // 0xc7
        (25, 0x1ffffed) => Some(207),  // 0xcf
        (25, 0x1ffffee) => Some(234),  // 0xea
        (25, 0x1ffffef) => Some(235),  // 0xeb
        // 26-bit codes (15 entries)
        (26, 0x3ffffe0) => Some(192),  // 0xc0
        (26, 0x3ffffe1) => Some(193),  // 0xc1
        (26, 0x3ffffe2) => Some(200),  // 0xc8
        (26, 0x3ffffe3) => Some(201),  // 0xc9
        (26, 0x3ffffe4) => Some(202),  // 0xca
        (26, 0x3ffffe5) => Some(205),  // 0xcd
        (26, 0x3ffffe6) => Some(210),  // 0xd2
        (26, 0x3ffffe7) => Some(213),  // 0xd5
        (26, 0x3ffffe8) => Some(218),  // 0xda
        (26, 0x3ffffe9) => Some(219),  // 0xdb
        (26, 0x3ffffea) => Some(238),  // 0xee
        (26, 0x3ffffeb) => Some(240),  // 0xf0
        (26, 0x3ffffec) => Some(242),  // 0xf2
        (26, 0x3ffffed) => Some(243),  // 0xf3
        (26, 0x3ffffee) => Some(255),  // 0xff
        // 27-bit codes (19 entries)
        (27, 0x7ffffde) => Some(203),  // 0xcb
        (27, 0x7ffffdf) => Some(204),  // 0xcc
        (27, 0x7ffffe0) => Some(211),  // 0xd3
        (27, 0x7ffffe1) => Some(212),  // 0xd4
        (27, 0x7ffffe2) => Some(214),  // 0xd6
        (27, 0x7ffffe3) => Some(221),  // 0xdd
        (27, 0x7ffffe4) => Some(222),  // 0xde
        (27, 0x7ffffe5) => Some(223),  // 0xdf
        (27, 0x7ffffe6) => Some(241),  // 0xf1
        (27, 0x7ffffe7) => Some(244),  // 0xf4
        (27, 0x7ffffe8) => Some(245),  // 0xf5
        (27, 0x7ffffe9) => Some(246),  // 0xf6
        (27, 0x7ffffea) => Some(247),  // 0xf7
        (27, 0x7ffffeb) => Some(248),  // 0xf8
        (27, 0x7ffffec) => Some(250),  // 0xfa
        (27, 0x7ffffed) => Some(251),  // 0xfb
        (27, 0x7ffffee) => Some(252),  // 0xfc
        (27, 0x7ffffef) => Some(253),  // 0xfd
        (27, 0x7fffff0) => Some(254),  // 0xfe
        // 28-bit codes (29 entries)
        (28, 0xfffffe2) => Some(2),  // 0x02
        (28, 0xfffffe3) => Some(3),  // 0x03
        (28, 0xfffffe4) => Some(4),  // 0x04
        (28, 0xfffffe5) => Some(5),  // 0x05
        (28, 0xfffffe6) => Some(6),  // 0x06
        (28, 0xfffffe7) => Some(7),  // 0x07
        (28, 0xfffffe8) => Some(8),  // 0x08
        (28, 0xfffffe9) => Some(11),  // 0x0b
        (28, 0xfffffea) => Some(12),  // 0x0c
        (28, 0xfffffeb) => Some(14),  // 0x0e
        (28, 0xfffffec) => Some(15),  // 0x0f
        (28, 0xfffffed) => Some(16),  // 0x10
        (28, 0xfffffee) => Some(17),  // 0x11
        (28, 0xfffffef) => Some(18),  // 0x12
        (28, 0xffffff0) => Some(19),  // 0x13
        (28, 0xffffff1) => Some(20),  // 0x14
        (28, 0xffffff2) => Some(21),  // 0x15
        (28, 0xffffff3) => Some(23),  // 0x17
        (28, 0xffffff4) => Some(24),  // 0x18
        (28, 0xffffff5) => Some(25),  // 0x19
        (28, 0xffffff6) => Some(26),  // 0x1a
        (28, 0xffffff7) => Some(27),  // 0x1b
        (28, 0xffffff8) => Some(28),  // 0x1c
        (28, 0xffffff9) => Some(29),  // 0x1d
        (28, 0xffffffa) => Some(30),  // 0x1e
        (28, 0xffffffb) => Some(31),  // 0x1f
        (28, 0xffffffc) => Some(127),  // 0x7f
        (28, 0xffffffd) => Some(220),  // 0xdc
        (28, 0xffffffe) => Some(249),  // 0xf9
        // 30-bit codes (3 entries; code 0x3fffffff is EOS).
        (30, 0x3ffffffc) => Some(10),  // 0x0a
        (30, 0x3ffffffd) => Some(13),  // 0x0d
        (30, 0x3ffffffe) => Some(22),  // 0x16
        _ => None,
    }
}

// ---------------------------------------------------------------------
// QPACK literal-only encoder (RFC 9204 §4.5)
// ---------------------------------------------------------------------

fn qpack_static_index_for_pair(name: &[u8], value: &[u8]) -> Option<u32> {
    let mut i = 0u32;
    while i < QPACK_STATIC_COUNT {
        if let Some((n, v)) = qpack_static_lookup(i) {
            if qpack_bytes_eq(n, name) && qpack_bytes_eq(v, value) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn qpack_static_index_for_name(name: &[u8]) -> Option<u32> {
    let mut i = 0u32;
    while i < QPACK_STATIC_COUNT {
        if let Some((n, _)) = qpack_static_lookup(i) {
            if qpack_bytes_eq(n, name) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn qpack_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Emit the QPACK header-block prefix (Required Insert Count + Sign +
/// Delta Base — both zero since we don't use the dynamic table).
pub fn qpack_emit_block_prefix(out: &mut [u8]) -> usize {
    if out.len() < 2 {
        return 0;
    }
    out[0] = 0x00;
    out[1] = 0x00;
    2
}

/// Encode one (name, value) pair. Returns bytes written.
pub fn qpack_encode_field(name: &[u8], value: &[u8], out: &mut [u8]) -> usize {
    if let Some(idx) = qpack_static_index_for_pair(name, value) {
        // Indexed Field Line — pattern 1 T iiiiii (6-bit prefix, T=1).
        return qpack_encode_int(idx as u64, 6, 0xC0, out);
    }
    if let Some(idx) = qpack_static_index_for_name(name) {
        // Literal With Name Reference §4.5.4 — pattern 0 1 N T iiii.
        let mut pos = qpack_encode_int(idx as u64, 4, 0x50, out);
        if pos == 0 {
            return 0;
        }
        let n = qpack_encode_int(value.len() as u64, 7, 0x00, &mut out[pos..]);
        if n == 0 {
            return 0;
        }
        pos += n;
        if pos + value.len() > out.len() {
            return 0;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                value.as_ptr(),
                out.as_mut_ptr().add(pos),
                value.len(),
            );
        }
        return pos + value.len();
    }
    // Literal Without Name Reference §4.5.6 — pattern 0 0 1 N H.
    let mut pos = qpack_encode_int(name.len() as u64, 3, 0x20, out);
    if pos == 0 {
        return 0;
    }
    if pos + name.len() > out.len() {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            name.as_ptr(),
            out.as_mut_ptr().add(pos),
            name.len(),
        );
    }
    pos += name.len();
    let n = qpack_encode_int(value.len() as u64, 7, 0x00, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    if pos + value.len() > out.len() {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            value.as_ptr(),
            out.as_mut_ptr().add(pos),
            value.len(),
        );
    }
    pos + value.len()
}

// ---------------------------------------------------------------------
// QPACK decoder — static + literal forms only (no dynamic table).
// ---------------------------------------------------------------------

/// Scratch size sufficient for typical header names and values when
/// resolving Huffman-coded literals.
pub const QPACK_HUFFMAN_SCRATCH: usize = 256;

pub enum QpackName<'a> {
    Static(&'static [u8]),
    Literal(&'a [u8]),
    /// Raw Huffman-coded bytes (RFC 7541 Appendix B); decoded on
    /// demand via `qpack_name_resolve`.
    Huffman(&'a [u8]),
}

pub enum QpackValue<'a> {
    Static(&'static [u8]),
    Literal(&'a [u8]),
    Huffman(&'a [u8]),
}

/// Resolve a `QpackName` to a usable byte slice. Static and Literal
/// variants are zero-copy; Huffman decodes into `scratch` and
/// returns a borrow of the decoded bytes. None on invalid Huffman or
/// scratch overflow.
pub fn qpack_name_resolve<'a, 'b>(
    name: &QpackName<'a>,
    scratch: &'b mut [u8],
) -> Option<&'b [u8]>
where
    'a: 'b,
{
    match name {
        QpackName::Static(s) => Some(*s),
        QpackName::Literal(b) => Some(*b),
        QpackName::Huffman(b) => {
            let n = qpack_huffman_decode(b, scratch)?;
            Some(&scratch[..n])
        }
    }
}

/// Resolve a `QpackValue` into a usable byte slice. See
/// `qpack_name_resolve` for semantics.
pub fn qpack_value_resolve<'a, 'b>(
    value: &QpackValue<'a>,
    scratch: &'b mut [u8],
) -> Option<&'b [u8]>
where
    'a: 'b,
{
    match value {
        QpackValue::Static(s) => Some(*s),
        QpackValue::Literal(b) => Some(*b),
        QpackValue::Huffman(b) => {
            let n = qpack_huffman_decode(b, scratch)?;
            Some(&scratch[..n])
        }
    }
}

/// Read the block prefix (Required Insert Count + Delta Base — both
/// MUST be zero in our scheme). Returns bytes consumed.
pub fn qpack_decode_block_prefix(block: &[u8]) -> Option<usize> {
    let (ric, n1) = qpack_decode_int(block, 8)?;
    if ric != 0 {
        return None;
    }
    let after = &block[n1..];
    if after.is_empty() {
        return None;
    }
    let (db, n2) = qpack_decode_int(after, 7)?;
    if db != 0 {
        return None;
    }
    Some(n1 + n2)
}

pub fn qpack_decode_field<'a>(
    block: &'a [u8],
) -> Option<(QpackName<'a>, QpackValue<'a>, usize)> {
    if block.is_empty() {
        return None;
    }
    let first = block[0];
    if first & 0x80 != 0 {
        // Indexed Field Line — pattern 1 T iiiiii.
        if first & 0x40 == 0 {
            return None; // Dynamic table.
        }
        let (idx, n) = qpack_decode_int(block, 6)?;
        let (name, value) = qpack_static_lookup(idx as u32)?;
        return Some((QpackName::Static(name), QpackValue::Static(value), n));
    }
    if first & 0x40 != 0 {
        // Literal Field Line With Name Reference — 0 1 N T iiii.
        if first & 0x10 == 0 {
            return None; // Dynamic table name ref.
        }
        let (idx, n_name) = qpack_decode_int(block, 4)?;
        let (name, _) = qpack_static_lookup(idx as u32)?;
        let after = &block[n_name..];
        if after.is_empty() {
            return None;
        }
        let value_huff = (after[0] & 0x80) != 0;
        let (vlen, n_vlen) = qpack_decode_int(after, 7)?;
        let after2 = &after[n_vlen..];
        let vlen = vlen as usize;
        if after2.len() < vlen {
            return None;
        }
        let value_bytes = &after2[..vlen];
        let value = if value_huff {
            QpackValue::Huffman(value_bytes)
        } else {
            QpackValue::Literal(value_bytes)
        };
        return Some((
            QpackName::Static(name),
            value,
            n_name + n_vlen + vlen,
        ));
    }
    if first & 0x20 != 0 {
        // Literal Field Line Without Name Reference — 0 0 1 N H.
        let name_huff = (first & 0x08) != 0;
        let (nlen, n_nlen) = qpack_decode_int(block, 3)?;
        let after = &block[n_nlen..];
        let nlen = nlen as usize;
        if after.len() < nlen {
            return None;
        }
        let name_bytes = &after[..nlen];
        let after2 = &after[nlen..];
        if after2.is_empty() {
            return None;
        }
        let value_huff = (after2[0] & 0x80) != 0;
        let (vlen, n_vlen) = qpack_decode_int(after2, 7)?;
        let after3 = &after2[n_vlen..];
        let vlen = vlen as usize;
        if after3.len() < vlen {
            return None;
        }
        let value_bytes = &after3[..vlen];
        let name = if name_huff {
            QpackName::Huffman(name_bytes)
        } else {
            QpackName::Literal(name_bytes)
        };
        let value = if value_huff {
            QpackValue::Huffman(value_bytes)
        } else {
            QpackValue::Literal(value_bytes)
        };
        return Some((
            name,
            value,
            n_nlen + nlen + n_vlen + vlen,
        ));
    }
    None
}
