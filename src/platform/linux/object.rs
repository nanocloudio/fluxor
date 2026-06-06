// ============================================================================
// Linux storage.object provider — HTTP `Range:` reads over std::net
// ============================================================================
//
// The host-linux peer of the wasm `storage.object` provider
// (`src/platform/wasm/object.rs`). It backs the STORAGE_OBJECT
// contract's `HEAD` / `GET` / `RANGE_GET` / `CLOSE` opcodes with
// blocking HTTP/1.1 requests so a Linux-hosted graph can demand-page
// immutable assets by byte range — the Playload RFC §12.3 surface.
//
// All windowing math (clamp-to-tail, HEAD-record encoding, `Range`
// header formatting) is shared with the wasm provider through the
// host-neutral `abi::contracts::storage::object::range` module, which
// is unit-tested off-target. This file is the transport wrapper.
//
// "Through linux_net": production routing should hand these requests to
// the async `linux_net` module's connection table. This skeleton uses a
// blocking `std::net::TcpStream` directly (same pragmatic shape as the
// libc-backed FS provider above) so the surface is exercisable before
// that integration lands; the request bytes — including the `Range`
// header — are identical either way.

// This file is textually `include!`d into the `linux` platform module,
// which already imports `std::io::{Read, Write}` and others elsewhere.
// To avoid duplicate-import collisions everything here is fully
// qualified; the two `io` traits are pulled in anonymously
// (`as _`) inside `http_request` so their methods resolve without
// binding a colliding name.
use fluxor::abi::contracts::fence as obj_dev_fence;
use fluxor::abi::contracts::storage::object as obj_dev;
use fluxor::kernel::errno as obj_errno;
use fluxor::kernel::fd::{tag_fd, FD_TAG_STORAGE_OBJECT};

const OBJ_MAX_OPEN: usize = 16;
const OBJ_MAX_KEY: usize = 256;
const OBJ_HTTP_TIMEOUT_SECS: u64 = 10;

struct LinuxObjectSlot {
    in_use: bool,
    key: [u8; OBJ_MAX_KEY],
    key_len: usize,
}

const OBJ_EMPTY_SLOT: LinuxObjectSlot = LinuxObjectSlot {
    in_use: false,
    key: [0u8; OBJ_MAX_KEY],
    key_len: 0,
};

static mut LINUX_OBJECTS: [LinuxObjectSlot; OBJ_MAX_OPEN] =
    [OBJ_EMPTY_SLOT; OBJ_MAX_OPEN];

/// Outcome of one blocking HTTP request.
struct HttpResult {
    /// Response body bytes (already the requested range when the server
    /// honoured `Range:` with `206`; the whole object on a `200`).
    body: Vec<u8>,
    /// `Content-Length` of the body, or the object size for a HEAD.
    content_length: u64,
    /// Whether the response was `206 Partial Content` (server honoured
    /// the range) vs `200 OK` (server ignored it → caller slices).
    partial: bool,
}

/// Dispatch entry registered for the STORAGE_OBJECT contract from
/// `linux_init_providers`.
unsafe fn linux_object_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // Per-handle fence: HTTP fetches are volatile (no durability tier).
    if opcode == obj_dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < obj_dev_fence::WIRE_MAX_LEN {
            return obj_errno::EINVAL;
        }
        let slot_idx = handle as usize;
        let objs = &*core::ptr::addr_of!(LINUX_OBJECTS);
        if slot_idx >= OBJ_MAX_OPEN || !objs[slot_idx].in_use {
            return obj_errno::ENOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match obj_dev_fence::Fence::Volatile.encode(buf) {
            Some(n) => n as i32,
            None => obj_errno::EINVAL,
        };
    }
    match opcode {
        obj_dev::GET => linux_obj_get(arg, arg_len),
        obj_dev::HEAD => linux_obj_head(arg, arg_len),
        obj_dev::RANGE_GET => linux_obj_range_get(handle, arg, arg_len),
        obj_dev::CLOSE => linux_obj_close(handle),
        _ => obj_errno::ENOSYS,
    }
}

unsafe fn obj_read_u64(ptr: *const u8, off: usize) -> u64 {
    let mut b = [0u8; 8];
    core::ptr::copy_nonoverlapping(ptr.add(off), b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

unsafe fn linux_obj_alloc(key: &[u8]) -> i32 {
    if key.is_empty() || key.len() > OBJ_MAX_KEY {
        return obj_errno::EINVAL;
    }
    let objs = &mut *core::ptr::addr_of_mut!(LINUX_OBJECTS);
    let slot_idx = match objs.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return obj_errno::ENOMEM,
    };
    let slot = &mut objs[slot_idx];
    slot.key[..key.len()].copy_from_slice(key);
    slot.key_len = key.len();
    slot.in_use = true;
    tag_fd(FD_TAG_STORAGE_OBJECT, slot_idx as i32)
}

/// `GET` — reserve a handle bound to the UTF-8 key.
unsafe fn linux_obj_get(key_ptr: *mut u8, key_len: usize) -> i32 {
    if key_ptr.is_null() || key_len == 0 {
        return obj_errno::EINVAL;
    }
    let key = core::slice::from_raw_parts(key_ptr, key_len);
    linux_obj_alloc(key)
}

/// `RANGE_GET` — `[offset:u64][length:u32][out_ptr:u64]`. Issues a
/// ranged HTTP GET and copies up to `length` bytes into `out_ptr`.
unsafe fn linux_obj_range_get(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 + 4 + 8 {
        return obj_errno::EINVAL;
    }
    let slot_idx = handle as usize;
    let objs = &*core::ptr::addr_of!(LINUX_OBJECTS);
    if slot_idx >= OBJ_MAX_OPEN || !objs[slot_idx].in_use {
        return obj_errno::EINVAL;
    }
    let offset = obj_read_u64(arg, 0);
    let length = {
        let mut b = [0u8; 4];
        core::ptr::copy_nonoverlapping(arg.add(8), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as u64
    };
    let out_ptr = obj_read_u64(arg, 12) as *mut u8;
    if length == 0 || out_ptr.is_null() {
        return obj_errno::OK;
    }
    let key = &objs[slot_idx].key[..objs[slot_idx].key_len];

    match http_request(key, Some((offset, length)), false) {
        Ok(res) => {
            // If the server honoured the range, `body` is already the
            // window; otherwise slice locally against the full object.
            let (start, avail) = if res.partial {
                (0usize, res.body.len() as u64)
            } else {
                let r = obj_dev::range::resolve(offset, length, res.body.len() as u64);
                (r.start as usize, r.count)
            };
            let n = core::cmp::min(length, avail) as usize;
            let end = core::cmp::min(start + n, res.body.len());
            let n = end.saturating_sub(start);
            if n > 0 {
                core::ptr::copy_nonoverlapping(res.body.as_ptr().add(start), out_ptr, n);
            }
            n as i32
        }
        Err(code) => code,
    }
}

/// `HEAD` — fill the caller's out buffer with a `range::encode_head`
/// record and write a Volatile fence.
unsafe fn linux_obj_head(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return obj_errno::EINVAL;
    }
    let key_len = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };
    let fixed = 2 + key_len + 8 + 4 + 8 + 2;
    if arg_len < fixed || key_len == 0 || key_len > OBJ_MAX_KEY {
        return obj_errno::EINVAL;
    }
    let key = core::slice::from_raw_parts(arg.add(2), key_len);
    let mut p = 2 + key_len;
    let out_ptr = obj_read_u64(arg, p) as *mut u8;
    p += 8;
    let out_cap = {
        let mut b = [0u8; 4];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as usize
    };
    p += 4;
    let fence_out_ptr = obj_read_u64(arg, p) as *mut u8;
    p += 8;
    let fence_out_cap = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };

    let size = match http_request(key, None, true) {
        Ok(res) => res.content_length,
        Err(code) => return code,
    };
    if out_ptr.is_null() {
        return obj_errno::EINVAL;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    // mtime is left 0: parsing the HTTP-date `Last-Modified` header
    // without a date dependency is deferred to the linux_net integration.
    let written = match obj_dev::range::encode_head(out, size, 0, &[], &[]) {
        Some(n) => n,
        None => return obj_errno::EINVAL,
    };
    if !fence_out_ptr.is_null() && fence_out_cap >= obj_dev_fence::WIRE_MAX_LEN {
        let fbuf = core::slice::from_raw_parts_mut(fence_out_ptr, fence_out_cap);
        let _ = obj_dev_fence::Fence::Volatile.encode(fbuf);
    }
    written as i32
}

/// `CLOSE` — free the slot.
unsafe fn linux_obj_close(handle: i32) -> i32 {
    let slot_idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(LINUX_OBJECTS);
    if slot_idx >= OBJ_MAX_OPEN || !objs[slot_idx].in_use {
        return obj_errno::EINVAL;
    }
    objs[slot_idx].in_use = false;
    objs[slot_idx].key_len = 0;
    obj_errno::OK
}

/// Parse an `http://host[:port]/path` key into `(host, port, path)`.
fn parse_http_key(key: &[u8]) -> Option<(String, u16, String)> {
    let s = core::str::from_utf8(key).ok()?;
    let rest = s.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (
            authority[..i].to_string(),
            authority[i + 1..].parse::<u16>().ok()?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// Issue one blocking HTTP/1.1 request. `range` set issues a ranged
/// `GET` with a shared-core `Range:` header; `head` issues a `HEAD`.
/// Maps transport/protocol failures to errnos.
fn http_request(key: &[u8], range: Option<(u64, u64)>, head: bool) -> Result<HttpResult, i32> {
    use std::io::Read as _;
    use std::io::Write as _;
    let timeout = std::time::Duration::from_secs(OBJ_HTTP_TIMEOUT_SECS);
    let (host, port, path) = parse_http_key(key).ok_or(obj_errno::EINVAL)?;

    let mut req = String::new();
    let method = if head { "HEAD" } else { "GET" };
    req.push_str(method);
    req.push(' ');
    req.push_str(&path);
    req.push_str(" HTTP/1.1\r\nHost: ");
    req.push_str(&host);
    req.push_str("\r\n");
    if let Some((offset, length)) = range {
        let r = obj_dev::range::resolve(offset, length, u64::MAX);
        let mut hdr = [0u8; 64];
        if let Some(n) = obj_dev::range::write_range_header_value(&mut hdr, r.start, r.count) {
            req.push_str("Range: ");
            req.push_str(core::str::from_utf8(&hdr[..n]).unwrap_or(""));
            req.push_str("\r\n");
        }
    }
    req.push_str("Connection: close\r\n\r\n");

    let mut stream =
        std::net::TcpStream::connect((host.as_str(), port)).map_err(|_| obj_errno::ENODEV)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| obj_errno::ENODEV)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| obj_errno::ENODEV)?;
    stream
        .write_all(req.as_bytes())
        .map_err(|_| obj_errno::ENODEV)?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|_| obj_errno::ENODEV)?;

    // Split headers / body at the first CRLFCRLF.
    let split = find_subslice(&raw, b"\r\n\r\n").ok_or(obj_errno::ERROR)?;
    let header_bytes = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let headers = core::str::from_utf8(header_bytes).map_err(|_| obj_errno::ERROR)?;

    let mut lines = headers.split("\r\n");
    let status_line = lines.next().ok_or(obj_errno::ERROR)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or(obj_errno::ERROR)?;
    if !(200..300).contains(&status) {
        return Err(obj_errno::ENODEV);
    }

    let mut content_length: u64 = body.len() as u64;
    for line in lines {
        if let Some(v) = line.strip_prefix("Content-Length:") {
            if let Ok(n) = v.trim().parse::<u64>() {
                content_length = n;
            }
        }
    }

    Ok(HttpResult {
        body,
        content_length,
        partial: status == 206,
    })
}

/// First index where `needle` occurs in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}
