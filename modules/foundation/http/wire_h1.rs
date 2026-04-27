//! HTTP/1 wire codec — text framing.
//!
//! Pure byte-level read and write helpers. No syscalls, no channel I/O,
//! no module state: each function takes raw byte slices so the same
//! routines serve both the server and client state machines.

/// Locate the end-of-headers sentinel `\r\n\r\n` in a partial HTTP/1
/// message. Returns the byte offset *after* the sentinel — i.e. where
/// the body begins — or `None` if the sentinel is not yet present.
///
/// `len` may be smaller than `buf.len()` to scan only the populated
/// prefix of a fixed-size receive buffer.
pub unsafe fn find_header_end(buf: &[u8], len: usize) -> Option<usize> {
    if len < 4 {
        return None;
    }
    let ptr = buf.as_ptr();
    let mut i = 0;
    while i + 3 < len {
        if *ptr.add(i) == b'\r'
            && *ptr.add(i + 1) == b'\n'
            && *ptr.add(i + 2) == b'\r'
            && *ptr.add(i + 3) == b'\n'
        {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

/// Parse an HTTP/1 request line (`GET /path HTTP/1.x\r\n`) out of `src`
/// and copy the path bytes into `dst`. Returns the path length on
/// success or `None` if the line is malformed, truncated, or too short
/// to contain the minimum viable request.
///
/// GET is the only method this server accepts; non-GET requests fall
/// through to a 400 reply.
pub unsafe fn parse_request_line(src: *const u8, src_len: usize, dst: *mut u8, dst_cap: usize) -> Option<usize> {
    if src_len < 14 {
        return None;
    }
    if *src != b'G' || *src.add(1) != b'E' || *src.add(2) != b'T' || *src.add(3) != b' ' {
        return None;
    }

    let mut path_end = 4usize;
    while path_end < src_len && *src.add(path_end) != b' ' {
        path_end += 1;
    }
    if path_end <= 4 || *src.add(4) != b'/' {
        return None;
    }

    let plen = (path_end - 4).min(dst_cap);
    let mut i = 0;
    while i < plen {
        *dst.add(i) = *src.add(4 + i);
        i += 1;
    }
    Some(plen)
}

/// Write a minimal HTTP/1.0 response status line plus `Connection:
/// close` and a `Content-Type` header into `dst`, terminated by the
/// blank line that ends the head. Returns the number of bytes written
/// (capped at `dst_cap`).
pub unsafe fn write_status_line(
    dst: *mut u8,
    dst_cap: usize,
    status: &[u8],
    content_type: &[u8],
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.0 ");
    put!(status);
    put!(b"\r\nConnection: close\r\nContent-Type: ");
    put!(content_type);
    put!(b"\r\n\r\n");

    off
}

/// Write a minimal HTTP/1.0 error response (status line + Connection:
/// close + blank line + body) into `dst`. Returns total bytes written.
pub unsafe fn write_error_response(
    dst: *mut u8,
    dst_cap: usize,
    code: &[u8],
    body: &[u8],
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.0 ");
    put!(code);
    put!(b"\r\nConnection: close\r\n\r\n");
    put!(body);

    off
}

/// Write an HTTP/1.0 GET request line plus `Host:` header (using the
/// peer's dotted-quad IP) and the `Connection: close` terminator into
/// `dst`. Returns the total request length.
///
/// Capped at 256 bytes total — `dst_cap` must reflect the caller's
/// scratch capacity. The host IP is written in big-endian dotted-quad.
pub unsafe fn write_request_line(
    dst: *mut u8,
    dst_cap: usize,
    path: *const u8,
    path_len: usize,
    host_ip_be: u32,
) -> usize {
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < dst_cap {
                *dst.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"GET ");

    let mut i = 0;
    while i < path_len && off < dst_cap {
        *dst.add(off) = *path.add(i);
        off += 1;
        i += 1;
    }

    put!(b" HTTP/1.0\r\nHost: ");

    // host IP, big-endian dotted-quad
    let ip = host_ip_be.to_be_bytes();
    let octets = [ip[0], ip[1], ip[2], ip[3]];
    let mut o = 0;
    while o < 4 {
        let b = octets[o];
        if b >= 100 && off < dst_cap {
            *dst.add(off) = b'0' + (b / 100);
            off += 1;
        }
        if b >= 10 && off < dst_cap {
            *dst.add(off) = b'0' + ((b / 10) % 10);
            off += 1;
        }
        if off < dst_cap {
            *dst.add(off) = b'0' + (b % 10);
            off += 1;
        }
        if o < 3 && off < dst_cap {
            *dst.add(off) = b'.';
            off += 1;
        }
        o += 1;
    }

    put!(b"\r\nConnection: close\r\n\r\n");

    off
}
