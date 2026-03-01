//! HTTP Server PIC Module — Routing, Templating, and Proxy
//!
//! Serves content over HTTP with path-based routing, template rendering
//! with live variable injection, file serving, and forward proxy support.
//!
//! # Content Sources
//!
//! Each route maps a URL path prefix to one of four handler types:
//!
//! | Handler  | Description                                    |
//! |----------|------------------------------------------------|
//! | static   | Serve inline body as-is (text/html)            |
//! | template | Serve inline body with `{{ var }}` substitution |
//! | file     | Stream files from fat32 via channel             |
//! | proxy    | Forward request to upstream HTTP server         |
//!
//! # Variable Injection
//!
//! Template variables are populated from FMP messages on `in[0]`.
//! Any module (temp_sensor, mqtt, etc.) can emit FMP messages whose
//! type hash becomes the variable key. Latest value wins.
//!
//! Example: temp_sensor emits `FMP(type="temperature", payload="23.5")`
//! → `{{temperature}}` renders as `23.5`.
//!
//! # Connection Model
//!
//! One connection at a time. After close, re-opens/binds/listens.
//!
//! # Parameters
//!
//! | Tag | Name | Type | Default | Description |
//! |-----|------|------|---------|-------------|
//! | 1   | port | u16  | 80      | TCP listen port |
//! | 2   | body | str  | (none)  | Legacy inline body (backward compat) |
//! | 10  | route_0_path | str | — | Route 0 URL prefix |
//! | 11  | route_0_body | str | — | Route 0 body content |
//! | 12  | route_0_handler | u8 | 0 | Handler type (0-3) |
//! | 13  | route_0_proxy_ip | u32 | 0 | Proxy upstream IP |
//! | 14  | route_0_proxy_port | u16 | 0 | Proxy upstream port |
//! | 15  | route_0_source | u16 | 0xFFFF | Source blob index (-1=inline) |
//! | 20-25 | route_1_* | — | — | Route 1 params |
//! | 30-35 | route_2_* | — | — | Route 2 params |
//! | 40-45 | route_3_* | — | — | Route 3 params |

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

const RECV_BUF_SIZE: usize = 256;
const SEND_BUF_SIZE: usize = 512;
const MAX_ROUTES: usize = 4;
const MAX_PATH: usize = 32;
const BODY_POOL_SIZE: usize = 3072;
const MAX_VARS: usize = 16;
const MAX_VAR_VALUE: usize = 16;

const HANDLER_STATIC: u8 = 0;
const HANDLER_TEMPLATE: u8 = 1;
const HANDLER_FILE: u8 = 2;
const HANDLER_PROXY: u8 = 3;

const MAX_CACHE: usize = 4;

// ============================================================================
// Phase Enum
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum HttpPhase {
    Init = 0,
    SocketOpen = 1,
    WaitBind = 2,
    WaitListen = 3,
    WaitAccept = 4,
    RecvRequest = 5,
    DispatchRoute = 6,
    SendHeaders = 7,
    SendBody = 8,
    DrainSend = 9,
    CloseConn = 10,
    FetchContent = 11,
    CacheStream = 12,
    ProxyConnect = 13,
    ProxyWaitConnect = 14,
    ProxySendRequest = 15,
    ProxyRelayHeaders = 16,
    ProxyRelayBody = 17,
    Error = 255,
}

// ============================================================================
// Route + Variable Structs
// ============================================================================

#[repr(C)]
struct Route {
    proxy_ip: u32,
    body_offset: u16,
    body_len: u16,
    proxy_port: u16,
    path_len: u8,
    handler: u8,
    source_index: i16,   // -1=inline body, >=0=channel blob index
    _route_pad: [u8; 2],
    path: [u8; MAX_PATH],
}

impl Route {
    const fn new() -> Self {
        Self {
            proxy_ip: 0,
            body_offset: 0,
            body_len: 0,
            proxy_port: 0,
            path_len: 0,
            handler: 0,
            source_index: -1,
            _route_pad: [0; 2],
            path: [0; MAX_PATH],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CacheEntry {
    route_index: u8,     // which route this caches
    flags: u8,           // bit 0=valid, bit 1=complete
    lru_tick: u8,
    _pad: u8,
    arena_offset: u16,   // offset into body_pool
    length: u16,         // cached bytes so far
}

impl CacheEntry {
    const fn new() -> Self {
        Self {
            route_index: 0,
            flags: 0,
            lru_tick: 0,
            _pad: 0,
            arena_offset: 0,
            length: 0,
        }
    }
}

const CACHE_VALID: u8 = 0x01;
const CACHE_COMPLETE: u8 = 0x02;

#[repr(C)]
struct VarEntry {
    name_hash: u32,
    value_len: u8,
    _pad: [u8; 3],
    value: [u8; MAX_VAR_VALUE],
}

impl VarEntry {
    const fn new() -> Self {
        Self {
            name_hash: 0,
            value_len: 0,
            _pad: [0; 3],
            value: [0; MAX_VAR_VALUE],
        }
    }
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct HttpServerState {
    syscalls: *const SyscallTable,
    var_chan: i32,
    file_chan: i32,
    out_chan: i32,
    socket_handle: i32,
    upstream_handle: i32,

    port: u16,
    body_pool_used: u16,
    recv_len: u16,
    send_offset: u16,
    send_len: u16,
    tmpl_pos: u16,
    file_index: i16,
    file_count: u16,
    index_pos: u16,

    phase: HttpPhase,
    route_count: u8,
    matched_route: i8,
    recv_parsed: u8,
    req_path_len: u8,
    var_count: u8,
    legacy_mode: u8,
    cache_count: u8,
    cache_tick: u8,
    req_path: [u8; MAX_PATH],

    routes: [Route; MAX_ROUTES],
    vars: [VarEntry; MAX_VARS],
    cache_entries: [CacheEntry; MAX_CACHE],
    recv_buf: [u8; RECV_BUF_SIZE],
    send_buf: [u8; SEND_BUF_SIZE],
    body_pool: [u8; BODY_POOL_SIZE],
}

impl HttpServerState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::HttpServerState;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        HttpServerState;

        1, port, u16, 80
            => |s, d, len| { s.port = p_u16(d, len, 0, 80); };

        2, body, str, 0
            => |s, d, len| { super::parse_route_body(s, 0, d, len); };

        10, route_0_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 0, d, len); };
        11, route_0_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 0, d, len); };
        12, route_0_handler, u8, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(0)).handler = p_u8(d, len, 0, 0); };
        13, route_0_proxy_ip, u32, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(0)).proxy_ip = p_u32(d, len, 0, 0); };
        14, route_0_proxy_port, u16, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(0)).proxy_port = p_u16(d, len, 0, 0); };
        15, route_0_source, u16, 0xFFFF
            => |s, d, len| { (*s.routes.as_mut_ptr().add(0)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        20, route_1_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 1, d, len); };
        21, route_1_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 1, d, len); };
        22, route_1_handler, u8, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(1)).handler = p_u8(d, len, 0, 0); };
        23, route_1_proxy_ip, u32, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(1)).proxy_ip = p_u32(d, len, 0, 0); };
        24, route_1_proxy_port, u16, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(1)).proxy_port = p_u16(d, len, 0, 0); };
        25, route_1_source, u16, 0xFFFF
            => |s, d, len| { (*s.routes.as_mut_ptr().add(1)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        30, route_2_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 2, d, len); };
        31, route_2_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 2, d, len); };
        32, route_2_handler, u8, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(2)).handler = p_u8(d, len, 0, 0); };
        33, route_2_proxy_ip, u32, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(2)).proxy_ip = p_u32(d, len, 0, 0); };
        34, route_2_proxy_port, u16, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(2)).proxy_port = p_u16(d, len, 0, 0); };
        35, route_2_source, u16, 0xFFFF
            => |s, d, len| { (*s.routes.as_mut_ptr().add(2)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        40, route_3_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 3, d, len); };
        41, route_3_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 3, d, len); };
        42, route_3_handler, u8, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(3)).handler = p_u8(d, len, 0, 0); };
        43, route_3_proxy_ip, u32, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(3)).proxy_ip = p_u32(d, len, 0, 0); };
        44, route_3_proxy_port, u16, 0
            => |s, d, len| { (*s.routes.as_mut_ptr().add(3)).proxy_port = p_u16(d, len, 0, 0); };
        45, route_3_source, u16, 0xFFFF
            => |s, d, len| { (*s.routes.as_mut_ptr().add(3)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };
    }
}

// ============================================================================
// Parameter Parsing Helpers
// ============================================================================

unsafe fn parse_route_path(s: &mut HttpServerState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 { return; }
    let route = &mut *s.routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_PATH);
    let mut i = 0;
    while i < n {
        route.path[i] = *d.add(i);
        i += 1;
    }
    route.path_len = n as u8;
    if (idx + 1) as u8 > s.route_count {
        s.route_count = (idx + 1) as u8;
    }
}

unsafe fn parse_route_body(s: &mut HttpServerState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 { return; }
    let offset = s.body_pool_used as usize;
    let remaining = BODY_POOL_SIZE - offset;
    if remaining == 0 { return; }
    let n = len.min(remaining);
    let mut i = 0;
    while i < n {
        *s.body_pool.as_mut_ptr().add(offset + i) = *d.add(i);
        i += 1;
    }
    let route = &mut *s.routes.as_mut_ptr().add(idx);
    if route.body_len == 0 {
        route.body_offset = offset as u16;
    }
    route.body_len += n as u16;
    s.body_pool_used = (offset + n) as u16;
    // Auto-count routes for legacy body (tag 2 → route 0)
    if idx == 0 && s.route_count == 0 {
        // Will be finalized in module_new
    }
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
unsafe fn log_info(s: &HttpServerState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

unsafe fn reset_socket(s: &mut HttpServerState) {
    if s.socket_handle >= 0 {
        dev_socket_close(s.sys(), s.socket_handle);
        s.socket_handle = -1;
    }
    if s.upstream_handle >= 0 {
        dev_socket_close(s.sys(), s.upstream_handle);
        s.upstream_handle = -1;
    }
    s.phase = HttpPhase::SocketOpen;
}

/// Parse "GET /path HTTP/..." — copy path into req_path buffer.
/// Returns 0 on success, -1 on error.
unsafe fn parse_request_line(s: &mut HttpServerState) -> i32 {
    let buf = s.recv_buf.as_ptr();
    let len = s.recv_len as usize;

    if len < 14 { return -1; }
    if *buf != b'G' || *buf.add(1) != b'E' || *buf.add(2) != b'T' || *buf.add(3) != b' ' {
        return -1;
    }

    let mut path_end = 4usize;
    while path_end < len && *buf.add(path_end) != b' ' {
        path_end += 1;
    }
    if path_end <= 4 || *buf.add(4) != b'/' { return -1; }

    // Copy path into stable buffer (recv_buf may be compacted later)
    let plen = (path_end - 4).min(MAX_PATH);
    let mut i = 0;
    while i < plen {
        *s.req_path.as_mut_ptr().add(i) = *buf.add(4 + i);
        i += 1;
    }
    s.req_path_len = plen as u8;
    0
}

/// Match request path against route table. Returns route index or -1.
unsafe fn match_route(s: &HttpServerState) -> i8 {
    let req = s.req_path.as_ptr();
    let plen = s.req_path_len as usize;

    let mut i = 0u8;
    while (i as usize) < s.route_count as usize {
        let route = &*s.routes.as_ptr().add(i as usize);
        let rlen = route.path_len as usize;
        if rlen > 0 && plen >= rlen {
            let mut j = 0;
            let mut ok = true;
            let path_ptr = route.path.as_ptr();
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok { return i as i8; }
        }
        i += 1;
    }
    -1
}

/// Build HTTP response header (no Content-Length, relies on Connection: close).
unsafe fn build_header(s: &mut HttpServerState, status: &[u8], content_type: &[u8]) {
    let buf = s.send_buf.as_mut_ptr();
    let cap = SEND_BUF_SIZE;
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < cap {
                *buf.add(off) = *src.as_ptr().add(i);
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

    s.send_offset = 0;
    s.send_len = off as u16;
}

unsafe fn build_error(s: &mut HttpServerState, code: &[u8], body: &[u8]) {
    let buf = s.send_buf.as_mut_ptr();
    let cap = SEND_BUF_SIZE;
    let mut off = 0usize;

    macro_rules! put {
        ($data:expr) => {
            let src = $data;
            let mut i = 0;
            while i < src.len() && off < cap {
                *buf.add(off) = *src.as_ptr().add(i);
                off += 1;
                i += 1;
            }
        };
    }

    put!(b"HTTP/1.0 ");
    put!(code);
    put!(b"\r\nConnection: close\r\n\r\n");
    put!(body);

    s.send_offset = 0;
    s.send_len = off as u16;
}

// ============================================================================
// Variable Cache
// ============================================================================

/// Drain FMP messages from var_chan and update variable cache.
unsafe fn drain_variables(s: &mut HttpServerState) {
    if s.var_chan < 0 { return; }

    let var_chan = s.var_chan;
    let syscalls = s.syscalls;
    let mut buf = [0u8; MSG_HDR_SIZE + MAX_VAR_VALUE];

    loop {
        let poll = ((*syscalls).channel_poll)(var_chan, POLL_IN);
        if poll <= 0 || (poll as u8 & POLL_IN) == 0 { break; }

        let (msg_type, payload_len) = msg_read(&*syscalls, var_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 && payload_len == 0 { break; }

        let vlen = (payload_len as usize).min(MAX_VAR_VALUE);

        // Find existing entry or allocate new slot
        let var_count = s.var_count as usize;
        let mut slot: usize = var_count; // default: new slot
        let mut j = 0usize;
        while j < var_count {
            if (*s.vars.as_ptr().add(j)).name_hash == msg_type {
                slot = j;
                break;
            }
            j += 1;
        }

        if slot >= MAX_VARS { continue; } // cache full

        let var = &mut *s.vars.as_mut_ptr().add(slot);
        var.name_hash = msg_type;
        var.value_len = vlen as u8;
        let mut k = 0;
        let buf_ptr = buf.as_ptr();
        while k < vlen {
            *var.value.as_mut_ptr().add(k) = *buf_ptr.add(k);
            k += 1;
        }

        if slot == var_count {
            s.var_count += 1;
        }
    }
}

/// Look up a variable by FNV-1a hash. Returns (ptr, len).
unsafe fn lookup_var(s: &HttpServerState, hash: u32) -> (*const u8, usize) {
    let mut i = 0usize;
    while i < s.var_count as usize {
        let var = &*s.vars.as_ptr().add(i);
        if var.name_hash == hash {
            return (var.value.as_ptr(), var.value_len as usize);
        }
        i += 1;
    }
    (core::ptr::null(), 0)
}

// ============================================================================
// LRU Content Cache
// ============================================================================

/// Look up a cache entry by route index. Returns entry index or -1.
unsafe fn cache_lookup(s: &HttpServerState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.cache_count as usize {
        let e = &*s.cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Evict all cache entries, resetting the cache arena.
/// Returns the arena start offset (= body_pool_used from inline params).
unsafe fn cache_evict_all(s: &mut HttpServerState) -> u16 {
    s.cache_count = 0;
    // The inline params occupy body_pool[0..body_pool_used].
    // Cache arena starts right after.
    // body_pool_used tracks the inline portion and never changes after init,
    // but we need to track the "inline high water mark" separately.
    // Since cache entries are stored after inline data, we search routes
    // for the maximum inline body end to find the boundary.
    let mut inline_end: u16 = 0;
    let mut i = 0usize;
    while i < s.route_count as usize {
        let r = &*s.routes.as_ptr().add(i);
        if r.source_index < 0 && r.body_len > 0 {
            let end = r.body_offset + r.body_len;
            if end > inline_end { inline_end = end; }
        }
        i += 1;
    }
    inline_end
}

/// Allocate a cache entry for a route. Evicts all if no arena space.
/// Sets up the entry and returns it. Caller fills it during CacheStream.
unsafe fn cache_alloc(s: &mut HttpServerState, route_idx: u8) -> usize {
    // Compute arena end for existing cache entries
    let mut arena_end: u16 = cache_evict_all(s);

    // Use the first slot
    let idx = 0usize;
    let e = &mut *s.cache_entries.as_mut_ptr().add(idx);
    e.route_index = route_idx;
    e.flags = CACHE_VALID;
    s.cache_tick = s.cache_tick.wrapping_add(1);
    e.lru_tick = s.cache_tick;
    e.arena_offset = arena_end;
    e.length = 0;
    s.cache_count = 1;
    idx
}

// ============================================================================
// Template Rendering
// ============================================================================

/// Render next chunk of template body into send_buf.
/// Returns true if more data remains.
unsafe fn render_template_chunk(s: &mut HttpServerState) -> bool {
    let route = &*s.routes.as_ptr().add(s.matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pool = s.body_pool.as_ptr();
    let buf = s.send_buf.as_mut_ptr();
    let mut out = 0usize;
    let mut pos = body_start + s.tmpl_pos as usize;

    while pos < body_end && out < SEND_BUF_SIZE {
        // Check for {{ — need room for at least a variable value
        if pos + 1 < body_end
            && *pool.add(pos) == b'{'
            && *pool.add(pos + 1) == b'{'
        {
            // Ensure room for a variable value
            if out + MAX_VAR_VALUE > SEND_BUF_SIZE { break; }

            pos += 2; // skip {{

            // Hash variable name (skip whitespace)
            let mut hash: u32 = 0x811c9dc5;
            while pos + 1 < body_end
                && !(*pool.add(pos) == b'}' && *pool.add(pos + 1) == b'}')
            {
                let c = *pool.add(pos);
                if c != b' ' {
                    hash ^= c as u32;
                    hash = hash.wrapping_mul(0x01000193);
                }
                pos += 1;
            }
            // Skip closing }}
            if pos + 1 < body_end { pos += 2; }

            // Substitute variable value
            let (val_ptr, val_len) = lookup_var(s, hash);
            if !val_ptr.is_null() {
                let mut vi = 0;
                while vi < val_len && out < SEND_BUF_SIZE {
                    *buf.add(out) = *val_ptr.add(vi);
                    out += 1;
                    vi += 1;
                }
            }
        } else {
            *buf.add(out) = *pool.add(pos);
            out += 1;
            pos += 1;
        }
    }

    s.tmpl_pos = (pos - body_start) as u16;
    s.send_offset = 0;
    s.send_len = out as u16;
    pos < body_end
}

// ============================================================================
// Legacy File Mode Helpers
// ============================================================================

/// Parse file index from path suffix after route prefix.
/// "/files/3" with route prefix "/files" → 3
unsafe fn parse_file_index(s: &HttpServerState) -> i16 {
    let buf = s.req_path.as_ptr();
    let route = &*s.routes.as_ptr().add(s.matched_route as usize);
    let suffix_start = route.path_len as usize;
    let path_end = s.req_path_len as usize;

    // No suffix or just "/" → index page
    if suffix_start >= path_end { return -1; }
    let mut pos = suffix_start;
    // Skip leading /
    if *buf.add(pos) == b'/' { pos += 1; }
    if pos >= path_end { return -1; }

    // Parse decimal number
    let mut idx: i32 = 0;
    while pos < path_end {
        let c = *buf.add(pos);
        if c < b'0' || c > b'9' { return -2; }
        idx = idx * 10 + (c - b'0') as i32;
        if idx > 0x7FFF { return -2; }
        pos += 1;
    }
    idx as i16
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpServerState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
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
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<HttpServerState>() { return -6; }

        let s = &mut *(state as *mut HttpServerState);
        let sys = syscalls as *const SyscallTable;
        s.syscalls = sys;
        s.var_chan = in_chan;
        s.file_chan = -1;
        s.out_chan = out_chan;
        s.socket_handle = -1;
        s.upstream_handle = -1;
        s.port = 80;
        s.body_pool_used = 0;
        s.recv_len = 0;
        s.send_offset = 0;
        s.send_len = 0;
        s.tmpl_pos = 0;
        s.file_index = -1;
        s.file_count = 0;
        s.index_pos = 0;
        s.phase = HttpPhase::Init;
        s.route_count = 0;
        s.matched_route = -1;
        s.recv_parsed = 0;
        s.req_path_len = 0;
        s.var_count = 0;
        s.legacy_mode = 0;
        s.cache_count = 0;
        s.cache_tick = 0;

        // Parse TLV params
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;
        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Discover additional ports
        s.file_chan = dev_channel_port(&*sys, 0, 1); // in[1] = file data

        if s.route_count == 0 {
            let r0 = &mut *s.routes.as_mut_ptr().add(0);
            if r0.body_len > 0 {
                // Legacy body mode: tag 2 wrote body into route[0]
                *r0.path.as_mut_ptr() = b'/';
                r0.path_len = 1;
                r0.handler = HANDLER_STATIC;
                s.route_count = 1;
                s.legacy_mode = 1;
            } else if in_chan >= 0 {
                // Legacy file mode: in[0] is file data
                s.file_chan = in_chan;
                s.var_chan = -1;
                s.legacy_mode = 2;
            }
        }

        // Query fat32 file count if file channel is connected
        if s.file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(&*sys, s.file_chan, IOCTL_GET_SEEK, count_ptr);
            if r >= 0 {
                s.file_count = count as u16;
            }
        }

        log_info(s, b"[http_server] ready");
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut HttpServerState);
        if s.syscalls.is_null() { return -1; }

        // Drain variable updates from input channel
        drain_variables(s);

        match s.phase {
            // ── Socket Setup ─────────────────────────────────────────
            HttpPhase::Init | HttpPhase::SocketOpen => {
                let handle = dev_socket_open(s.sys(), SOCK_TYPE_STREAM);
                if handle < 0 { return 0; }
                s.socket_handle = handle;
                let rc = dev_socket_bind(s.sys(), handle, s.port);
                if rc < 0 && rc != E_INPROGRESS {
                    reset_socket(s);
                    return 0;
                }
                s.phase = HttpPhase::WaitBind;
                return 2;
            }

            HttpPhase::WaitBind => {
                let rc = dev_socket_listen(s.sys(), s.socket_handle);
                if rc == E_BUSY { return 0; }
                if rc < 0 && rc != E_INPROGRESS {
                    reset_socket(s);
                    return 0;
                }
                s.phase = HttpPhase::WaitListen;
                return 2;
            }

            HttpPhase::WaitListen => {
                let rc = dev_socket_accept(s.sys(), s.socket_handle);
                if rc == E_BUSY { return 0; }
                if rc < 0 && rc != E_INPROGRESS {
                    s.phase = HttpPhase::Error;
                    return -1;
                }
                s.phase = HttpPhase::WaitAccept;
            }

            HttpPhase::WaitAccept => {
                let poll = dev_socket_poll(s.sys(), s.socket_handle, POLL_CONN | POLL_HUP);
                if poll <= 0 { return 0; }
                if (poll as u8 & POLL_CONN) != 0 {
                    s.recv_len = 0;
                    s.recv_parsed = 0;
                    s.phase = HttpPhase::RecvRequest;
                } else if (poll as u8 & POLL_HUP) != 0 {
                    s.phase = HttpPhase::CloseConn;
                }
            }

            // ── Request Parsing ──────────────────────────────────────
            HttpPhase::RecvRequest => {
                let space = RECV_BUF_SIZE - s.recv_len as usize;
                if space > 0 {
                    let buf_ptr = s.recv_buf.as_mut_ptr().add(s.recv_len as usize);
                    let n = dev_socket_recv(s.sys(), s.socket_handle, buf_ptr, space);
                    if n > 0 { s.recv_len += n as u16; }
                }

                let len = s.recv_len as usize;

                // Stage 0: parse request line at first \r\n
                if s.recv_parsed == 0 {
                    let ptr = s.recv_buf.as_ptr();
                    let mut has_line = false;
                    let mut i = 0;
                    while i + 1 < len {
                        if *ptr.add(i) == b'\r' && *ptr.add(i + 1) == b'\n' {
                            has_line = true;
                            break;
                        }
                        i += 1;
                    }
                    if has_line {
                        if parse_request_line(s) < 0 {
                            build_error(s, b"400 Bad Request", b"Bad Request\n");
                            s.phase = HttpPhase::DrainSend;
                            return 0;
                        }
                        s.recv_parsed = 1;
                    } else if space == 0 {
                        build_error(s, b"400 Bad Request", b"Bad Request\n");
                        s.phase = HttpPhase::DrainSend;
                        return 0;
                    }
                }

                // Stage 1: drain headers until \r\n\r\n
                if s.recv_parsed == 1 {
                    let ptr = s.recv_buf.as_ptr();
                    let scan_len = s.recv_len as usize;
                    let mut found = false;
                    if scan_len >= 4 {
                        let mut i = 0;
                        while i + 3 < scan_len {
                            if *ptr.add(i) == b'\r' && *ptr.add(i + 1) == b'\n'
                                && *ptr.add(i + 2) == b'\r' && *ptr.add(i + 3) == b'\n'
                            {
                                found = true;
                                break;
                            }
                            i += 1;
                        }
                    }

                    if found {
                        s.phase = HttpPhase::DispatchRoute;
                        return 2;
                    } else if space == 0 {
                        // Compact buffer for continued header drain
                        let l = s.recv_len as usize;
                        if l >= 3 {
                            let p = s.recv_buf.as_mut_ptr();
                            *p = *p.add(l - 3);
                            *p.add(1) = *p.add(l - 2);
                            *p.add(2) = *p.add(l - 1);
                            s.recv_len = 3;
                        }
                    }
                }

                // Check HUP
                let poll = dev_socket_poll(s.sys(), s.socket_handle, POLL_HUP);
                if poll > 0 && (poll as u8 & POLL_HUP) != 0 {
                    s.phase = HttpPhase::CloseConn;
                }
            }

            // ── Route Dispatch ───────────────────────────────────────
            HttpPhase::DispatchRoute => {
                if s.legacy_mode == 2 {
                    // Legacy file mode: use old numeric path parsing
                    step_legacy_file_dispatch(s);
                    return 0;
                }

                let ri = match_route(s);
                if ri < 0 {
                    build_error(s, b"404 Not Found", b"Not Found\n");
                    s.phase = HttpPhase::DrainSend;
                    return 0;
                }
                s.matched_route = ri;
                let route = &*s.routes.as_ptr().add(ri as usize);
                let handler = route.handler;
                let src_idx = route.source_index;

                match handler {
                    HANDLER_STATIC | HANDLER_TEMPLATE => {
                        if src_idx >= 0 && s.file_chan >= 0 {
                            // Channel-sourced content — check LRU cache
                            let ci = cache_lookup(s, ri as u8);
                            if ci >= 0 {
                                // Cache hit — update LRU tick, point body at cache
                                let ce = &mut *s.cache_entries.as_mut_ptr().add(ci as usize);
                                s.cache_tick = s.cache_tick.wrapping_add(1);
                                ce.lru_tick = s.cache_tick;
                                let r = &mut *s.routes.as_mut_ptr().add(ri as usize);
                                r.body_offset = ce.arena_offset;
                                r.body_len = ce.length;
                                build_header(s, b"200 OK", b"text/html");
                                s.tmpl_pos = 0;
                                s.phase = HttpPhase::SendHeaders;
                            } else {
                                // Cache miss — fetch from channel
                                let _slot = cache_alloc(s, ri as u8);
                                dev_channel_ioctl(
                                    s.sys(), s.file_chan, IOCTL_FLUSH, core::ptr::null_mut(),
                                );
                                let mut pos = src_idx as u32;
                                let pos_ptr = &mut pos as *mut u32 as *mut u8;
                                dev_channel_ioctl(
                                    s.sys(), s.file_chan, IOCTL_SEEK, pos_ptr,
                                );
                                s.phase = HttpPhase::FetchContent;
                            }
                        } else {
                            // Inline body from params
                            build_header(s, b"200 OK", b"text/html");
                            s.tmpl_pos = 0;
                            s.phase = HttpPhase::SendHeaders;
                        }
                    }
                    HANDLER_FILE => {
                        let fi = parse_file_index(s);
                        s.file_index = fi;
                        if fi == -1 {
                            // Index page
                            if s.file_chan >= 0 {
                                let mut count: u32 = 0;
                                let count_ptr = &mut count as *mut u32 as *mut u8;
                                let r = dev_channel_ioctl(
                                    s.sys(), s.file_chan, IOCTL_GET_SEEK, count_ptr,
                                );
                                if r >= 0 { s.file_count = count as u16; }
                            }
                            build_header(s, b"200 OK", b"text/plain");
                            s.index_pos = 0;
                            s.phase = HttpPhase::SendHeaders;
                        } else if fi >= 0 {
                            // Seek to file
                            if s.file_chan >= 0 {
                                dev_channel_ioctl(
                                    s.sys(), s.file_chan, IOCTL_FLUSH, core::ptr::null_mut(),
                                );
                                let mut pos = fi as u32;
                                let pos_ptr = &mut pos as *mut u32 as *mut u8;
                                let r = dev_channel_ioctl(
                                    s.sys(), s.file_chan, IOCTL_SEEK, pos_ptr,
                                );
                                if r < 0 {
                                    build_error(s, b"404 Not Found", b"Not Found\n");
                                    s.phase = HttpPhase::DrainSend;
                                    return 0;
                                }
                                build_header(s, b"200 OK", b"application/octet-stream");
                            } else {
                                build_error(s, b"404 Not Found", b"Not Found\n");
                                s.phase = HttpPhase::DrainSend;
                                return 0;
                            }
                            s.phase = HttpPhase::SendHeaders;
                        } else {
                            build_error(s, b"400 Bad Request", b"Bad Request\n");
                            s.phase = HttpPhase::DrainSend;
                            return 0;
                        }
                    }
                    HANDLER_PROXY => {
                        // Phase 3 stub: return 502
                        build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
                        s.phase = HttpPhase::DrainSend;
                    }
                    _ => {
                        build_error(s, b"500 Internal Server Error", b"Unknown handler\n");
                        s.phase = HttpPhase::DrainSend;
                    }
                }
            }

            // ── Send Headers ─────────────────────────────────────────
            HttpPhase::SendHeaders => {
                let remaining = (s.send_len - s.send_offset) as usize;
                if remaining == 0 {
                    let handler = if s.matched_route >= 0 {
                        (*s.routes.as_ptr().add(s.matched_route as usize)).handler
                    } else {
                        HANDLER_FILE // legacy file mode
                    };

                    match handler {
                        HANDLER_STATIC => {
                            // Send body directly
                            s.phase = HttpPhase::SendBody;
                        }
                        HANDLER_TEMPLATE => {
                            s.phase = HttpPhase::SendBody;
                        }
                        HANDLER_FILE => {
                            if s.file_index < 0 {
                                // Index page
                                s.phase = HttpPhase::SendBody;
                            } else {
                                // File data relay
                                s.phase = HttpPhase::SendBody;
                            }
                        }
                        _ => {
                            s.phase = HttpPhase::CloseConn;
                        }
                    }
                    return 2;
                }
                let ptr = s.send_buf.as_ptr().add(s.send_offset as usize);
                let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, remaining);
                if sent > 0 { s.send_offset += sent as u16; }
            }

            // ── Send Body ────────────────────────────────────────────
            HttpPhase::SendBody => {
                let handler = if s.matched_route >= 0 {
                    (*s.routes.as_ptr().add(s.matched_route as usize)).handler
                } else {
                    HANDLER_FILE
                };

                match handler {
                    HANDLER_STATIC => {
                        return step_send_static(s);
                    }
                    HANDLER_TEMPLATE => {
                        return step_send_template(s);
                    }
                    HANDLER_FILE => {
                        if s.file_index < 0 {
                            return step_send_index(s);
                        } else {
                            return step_send_file(s);
                        }
                    }
                    _ => {
                        s.phase = HttpPhase::CloseConn;
                    }
                }
            }

            // ── Drain Error/Redirect Response ────────────────────────
            HttpPhase::DrainSend => {
                let remaining = (s.send_len - s.send_offset) as usize;
                if remaining == 0 {
                    s.phase = HttpPhase::CloseConn;
                    return 0;
                }
                let ptr = s.send_buf.as_ptr().add(s.send_offset as usize);
                let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, remaining);
                if sent > 0 { s.send_offset += sent as u16; }
            }

            // ── Fetch Content from Channel ────────────────────────────
            HttpPhase::FetchContent => {
                // Wait for upstream to start sending data
                if s.file_chan < 0 {
                    build_error(s, b"500 Internal Server Error", b"No content source\n");
                    s.phase = HttpPhase::DrainSend;
                    return 0;
                }
                let poll = (s.sys().channel_poll)(s.file_chan, POLL_IN | POLL_HUP);
                if poll > 0 && ((poll as u8 & POLL_IN) != 0 || (poll as u8 & POLL_HUP) != 0) {
                    s.phase = HttpPhase::CacheStream;
                    return 2;
                }
                // Still waiting for upstream to respond to seek
            }

            // ── Stream Content into Cache ────────────────────────────
            HttpPhase::CacheStream => {
                if s.cache_count == 0 || s.file_chan < 0 {
                    s.phase = HttpPhase::CloseConn;
                    return 0;
                }
                let ce_idx = 0usize; // We always use slot 0 for active fetch
                let ce = &mut *s.cache_entries.as_mut_ptr().add(ce_idx);
                let arena_off = ce.arena_offset as usize;
                let cur_len = ce.length as usize;
                let pool_cap = BODY_POOL_SIZE;

                // Read from channel into body_pool cache arena
                let space = pool_cap - (arena_off + cur_len);
                if space > 0 {
                    let dst = s.body_pool.as_mut_ptr().add(arena_off + cur_len);
                    let to_read = space.min(SEND_BUF_SIZE);
                    let n = (s.sys().channel_read)(s.file_chan, dst, to_read);
                    if n > 0 {
                        ce.length += n as u16;
                    }
                }

                // Check for EOF
                let poll = (s.sys().channel_poll)(s.file_chan, POLL_IN | POLL_HUP);
                let eof = poll > 0 && (poll as u8 & POLL_HUP) != 0
                    && (poll <= 0 || (poll as u8 & POLL_IN) == 0);
                let full = (arena_off + ce.length as usize) >= pool_cap;

                if eof || full {
                    // Mark cache entry complete
                    ce.flags |= CACHE_COMPLETE;
                    // Point route body at cached data
                    let ri = s.matched_route as usize;
                    let r = &mut *s.routes.as_mut_ptr().add(ri);
                    r.body_offset = ce.arena_offset;
                    r.body_len = ce.length;
                    // Now serve the response
                    build_header(s, b"200 OK", b"text/html");
                    s.tmpl_pos = 0;
                    s.phase = HttpPhase::SendHeaders;
                    return 2;
                }

                return 2; // Keep streaming
            }

            // ── Connection Close + Re-listen ─────────────────────────
            HttpPhase::CloseConn => {
                reset_socket(s);
            }

            // ── Proxy Phases (Phase 3 stubs) ─────────────────────────
            HttpPhase::ProxyConnect
            | HttpPhase::ProxyWaitConnect
            | HttpPhase::ProxySendRequest
            | HttpPhase::ProxyRelayHeaders
            | HttpPhase::ProxyRelayBody => {
                build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
                s.phase = HttpPhase::DrainSend;
            }

            HttpPhase::Error => {
                return 1; // Done
            }

            _ => {
                s.phase = HttpPhase::Error;
                return -1;
            }
        }

        0
    }
}

// ============================================================================
// Body Send Helpers
// ============================================================================

/// Send static body from body_pool (no template rendering).
unsafe fn step_send_static(s: &mut HttpServerState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.phase = HttpPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    let route = &*s.routes.as_ptr().add(s.matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + s.tmpl_pos as usize;

    if pos >= body_end {
        s.phase = HttpPhase::CloseConn;
        return 0;
    }

    let remaining = body_end - pos;
    let to_send = remaining.min(SEND_BUF_SIZE);
    let ptr = s.body_pool.as_ptr().add(pos);
    let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, to_send);
    if sent > 0 {
        s.tmpl_pos += sent as u16;
        return 2;
    }
    0
}

/// Send template body with {{ }} variable substitution.
unsafe fn step_send_template(s: &mut HttpServerState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.phase = HttpPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    // If send_buf has unsent data, send it first
    if s.send_offset < s.send_len {
        let remaining = (s.send_len - s.send_offset) as usize;
        let ptr = s.send_buf.as_ptr().add(s.send_offset as usize);
        let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, remaining);
        if sent > 0 { s.send_offset += sent as u16; }
        return 0;
    }

    // Render next chunk
    let has_more = render_template_chunk(s);
    if s.send_len > 0 {
        let ptr = s.send_buf.as_ptr();
        let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, s.send_len as usize);
        if sent > 0 { s.send_offset = sent as u16; }
        return if has_more { 2 } else { 0 };
    }

    if !has_more {
        s.phase = HttpPhase::CloseConn;
    }
    0
}

/// Send file index listing: "0\n1\n2\n..."
unsafe fn step_send_index(s: &mut HttpServerState) -> i32 {
    if s.index_pos >= s.file_count {
        s.phase = HttpPhase::CloseConn;
        return 0;
    }

    if s.send_offset >= s.send_len {
        let buf = s.send_buf.as_mut_ptr();
        let mut off = 0usize;
        let mut idx = s.index_pos;
        while idx < s.file_count && off + 6 < SEND_BUF_SIZE {
            off += fmt_u32_raw(buf.add(off), idx as u32);
            *buf.add(off) = b'\n';
            off += 1;
            idx += 1;
        }
        s.send_offset = 0;
        s.send_len = off as u16;
        s.index_pos = idx;
    }

    let remaining = (s.send_len - s.send_offset) as usize;
    let ptr = s.send_buf.as_ptr().add(s.send_offset as usize);
    let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, remaining);
    if sent > 0 {
        s.send_offset += sent as u16;
        return 2;
    }
    0
}

/// Relay file data from fat32 channel to socket.
unsafe fn step_send_file(s: &mut HttpServerState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.phase = HttpPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    if s.send_offset >= s.send_len {
        let n = (s.sys().channel_read)(s.file_chan, s.send_buf.as_mut_ptr(), SEND_BUF_SIZE);
        if n > 0 {
            s.send_offset = 0;
            s.send_len = n as u16;
        } else {
            let chan_poll = (s.sys().channel_poll)(s.file_chan, POLL_IN | POLL_HUP);
            if chan_poll > 0 && (chan_poll as u8 & POLL_HUP) != 0 {
                s.phase = HttpPhase::CloseConn;
            }
            return 0;
        }
    }

    let remaining = (s.send_len - s.send_offset) as usize;
    let ptr = s.send_buf.as_ptr().add(s.send_offset as usize);
    let sent = dev_socket_send(s.sys(), s.socket_handle, ptr, remaining);
    if sent > 0 {
        s.send_offset += sent as u16;
        return 2;
    }
    0
}

// ============================================================================
// Legacy File Mode (backward compat with no routes)
// ============================================================================

/// Dispatch for legacy file mode (numeric path: / = index, /N = file).
unsafe fn step_legacy_file_dispatch(s: &mut HttpServerState) {
    let buf = s.req_path.as_ptr();
    let plen = s.req_path_len as usize;

    if plen == 1 && *buf == b'/' {
        // Index page
        if s.file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(s.sys(), s.file_chan, IOCTL_GET_SEEK, count_ptr);
            if r >= 0 { s.file_count = count as u16; }
        }
        build_header(s, b"200 OK", b"text/plain");
        s.index_pos = 0;
        s.file_index = -1;
        s.matched_route = -1;
        s.phase = HttpPhase::SendHeaders;
    } else if plen >= 2 && *buf == b'/' {
        // Parse numeric index
        let mut idx: i32 = 0;
        let mut i = 1usize;
        let mut valid = true;
        while i < plen {
            let c = *buf.add(i);
            if c < b'0' || c > b'9' { valid = false; break; }
            idx = idx * 10 + (c - b'0') as i32;
            if idx > 0x7FFF { valid = false; break; }
            i += 1;
        }
        if !valid {
            build_error(s, b"400 Bad Request", b"Bad Request\n");
            s.phase = HttpPhase::DrainSend;
            return;
        }

        s.file_index = idx as i16;
        s.matched_route = -1;
        if s.file_chan >= 0 {
            dev_channel_ioctl(s.sys(), s.file_chan, IOCTL_FLUSH, core::ptr::null_mut());
            let mut pos = idx as u32;
            let pos_ptr = &mut pos as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(s.sys(), s.file_chan, IOCTL_SEEK, pos_ptr);
            if r < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                s.phase = HttpPhase::DrainSend;
                return;
            }
            build_header(s, b"200 OK", b"application/octet-stream");
        } else {
            build_error(s, b"404 Not Found", b"Not Found\n");
            s.phase = HttpPhase::DrainSend;
            return;
        }
        s.phase = HttpPhase::SendHeaders;
    } else {
        build_error(s, b"400 Bad Request", b"Bad Request\n");
        s.phase = HttpPhase::DrainSend;
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 256 },  // in[0]: var updates
        ChannelHint { port_type: 0, port_index: 1, buffer_size: 2048 }, // in[1]: file data
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 256 },  // out[0]: fat32 ctrl
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
