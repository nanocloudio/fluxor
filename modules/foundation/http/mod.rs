//! HTTP Module — Unified Client + Server
//!
//! A single PIC module that operates in one of two modes:
//!
//! - **Server** (mode 0, default): Routing, templating, file serving, proxy
//! - **Client** (mode 1): Fetches data from an HTTP URL, outputs to channel
//!
//! # Server Mode
//!
//! Serves content over HTTP with path-based routing, template rendering
//! with live variable injection, file serving, and forward proxy support.
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
//! # Client Mode
//!
//! Fetches data from an HTTP URL and outputs it to a channel.
//! From the consumer's perspective, this looks identical to the SD module —
//! just bytes flowing through a channel.
//!
//! # Parameters
//!
//! | Tag | Name | Type | Default | Description |
//! |-----|------|------|---------|-------------|
//! | 0   | mode | u8   | 0       | 0=server, 1=client |
//! | 1   | port | u16  | 80      | TCP listen port (server) or target port (client) |
//! | 2   | body | str  | (none)  | Legacy inline body (server, backward compat) |
//! | 3   | path | str  | "/"     | URL path (client mode) |
//! | 4   | host_ip | u32 | 0     | Target IP (client mode) |
//! | 10-45 | route_N_* | — | — | Route params (server mode) |

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, ChannelAddr};

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// Constants — Server
// ============================================================================

const SRV_RECV_BUF_SIZE: usize = 256;
const SRV_SEND_BUF_SIZE: usize = 512;
const MAX_ROUTES: usize = 4;
const MAX_PATH: usize = 32;
const DEFAULT_BODY_POOL_SIZE: usize = 3072;
const MAX_VARS: usize = 16;
const MAX_VAR_VALUE: usize = 16;

const HANDLER_STATIC: u8 = 0;
const HANDLER_TEMPLATE: u8 = 1;
const HANDLER_FILE: u8 = 2;
const HANDLER_PROXY: u8 = 3;

const MAX_CACHE: usize = 4;

// ============================================================================
// Constants — Client
// ============================================================================

const CLI_RECV_BUF_SIZE: usize = 512;
const CLI_MAX_PATH_LEN: usize = 128;
const CONNECT_TIMEOUT_MS: u64 = 10000;

const DEV_SOCKET_OPEN: u32 = 0x0800;
const DEV_SOCKET_CONNECT: u32 = 0x0801;
const DEV_SOCKET_SEND: u32 = 0x0802;
const DEV_SOCKET_RECV: u32 = 0x0803;
const DEV_SOCKET_POLL: u32 = 0x0804;
const DEV_SOCKET_CLOSE: u32 = 0x0805;

const E_SOCKET_FAILED: i32 = -30;
const E_CONNECT_FAILED: i32 = -31;
const E_SEND_FAILED: i32 = -32;
const E_RECV_FAILED: i32 = -33;
const E_WRITE_FAILED: i32 = -34;

// ============================================================================
// Mode Constants
// ============================================================================

const MODE_SERVER: u8 = 0;
const MODE_CLIENT: u8 = 1;

// ============================================================================
// Phase Enums
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum ServerPhase {
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

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum ClientPhase {
    Init = 0,
    SocketOpen = 1,
    Connecting = 2,
    WaitConnect = 3,
    SendRequest = 4,
    WaitSend = 5,
    RecvHeaders = 6,
    RecvBody = 7,
    Writing = 8,
    Done = 9,
    Error = 255,
}

// ============================================================================
// Route + Variable Structs (Server)
// ============================================================================

#[repr(C)]
struct Route {
    proxy_ip: u32,
    body_offset: u16,
    body_len: u16,
    proxy_port: u16,
    path_len: u8,
    handler: u8,
    source_index: i16,
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
    route_index: u8,
    flags: u8,
    lru_tick: u8,
    _pad: u8,
    arena_offset: u16,
    length: u16,
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
// Unified State
// ============================================================================

#[repr(C)]
struct HttpState {
    syscalls: *const SyscallTable,
    mode: u8,
    _mode_pad: [u8; 3],

    // ── Server fields ──
    srv_var_chan: i32,
    srv_file_chan: i32,
    srv_out_chan: i32,
    srv_socket_handle: i32,
    srv_upstream_handle: i32,

    srv_port: u16,
    srv_body_pool_used: u16,
    srv_recv_len: u16,
    srv_send_offset: u16,
    srv_send_len: u16,
    srv_tmpl_pos: u16,
    srv_file_index: i16,
    srv_file_count: u16,
    srv_index_pos: u16,

    srv_phase: ServerPhase,
    srv_route_count: u8,
    srv_matched_route: i8,
    srv_recv_parsed: u8,
    srv_req_path_len: u8,
    srv_var_count: u8,
    srv_legacy_mode: u8,
    srv_cache_count: u8,
    srv_cache_tick: u8,
    srv_req_path: [u8; MAX_PATH],

    srv_routes: [Route; MAX_ROUTES],
    srv_vars: [VarEntry; MAX_VARS],
    srv_cache_entries: [CacheEntry; MAX_CACHE],
    srv_recv_buf: [u8; SRV_RECV_BUF_SIZE],
    srv_send_buf: [u8; SRV_SEND_BUF_SIZE],
    srv_body_pool: *mut u8,
    srv_body_pool_cap: u16,
    srv_draining: u8,
    _srv_pad: [u8; 1],

    // ── Client fields ──
    cli_socket_handle: i32,
    cli_out_chan: i32,

    cli_host_ip: u32,
    cli_port: u16,
    cli_path_len: u16,

    cli_phase: ClientPhase,
    cli_headers_done: u8,
    _cli_pad: [u8; 2],

    cli_connect_start_ms: u64,

    cli_pending_offset: u16,
    cli_recv_len: u16,

    cli_content_length: u32,
    cli_bytes_received: u32,

    cli_request_len: u16,
    cli_request_sent: u16,

    cli_path: [u8; CLI_MAX_PATH_LEN],
    cli_recv_buf: [u8; CLI_RECV_BUF_SIZE],
    cli_request_buf: [u8; 256],
}

impl HttpState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::HttpState;
    use super::{p_u8, p_u16, p_u32};
    use super::CLI_MAX_PATH_LEN;
    use super::SCHEMA_MAX;

    define_params! {
        HttpState;

        0, mode, u8, 0
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        1, port, u16, 80
            => |s, d, len| {
                let v = p_u16(d, len, 0, 80);
                s.srv_port = v;
                s.cli_port = v;
            };

        2, body, str, 0
            => |s, d, len| { super::parse_route_body(s, 0, d, len); };

        3, path, str, 0
            => |s, d, len| {
                let n = if len > CLI_MAX_PATH_LEN { CLI_MAX_PATH_LEN } else { len };
                s.cli_path_len = n as u16;
                let mut i = 0;
                while i < n {
                    s.cli_path[i] = *d.add(i);
                    i += 1;
                }
            };

        4, host_ip, u32, 0
            => |s, d, len| { s.cli_host_ip = p_u32(d, len, 0, 0); };

        10, route_0_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 0, d, len); };
        11, route_0_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 0, d, len); };
        12, route_0_handler, u8, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(0)).handler = p_u8(d, len, 0, 0); };
        13, route_0_proxy_ip, u32, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(0)).proxy_ip = p_u32(d, len, 0, 0); };
        14, route_0_proxy_port, u16, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(0)).proxy_port = p_u16(d, len, 0, 0); };
        15, route_0_source, u16, 0xFFFF
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(0)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        20, route_1_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 1, d, len); };
        21, route_1_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 1, d, len); };
        22, route_1_handler, u8, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(1)).handler = p_u8(d, len, 0, 0); };
        23, route_1_proxy_ip, u32, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(1)).proxy_ip = p_u32(d, len, 0, 0); };
        24, route_1_proxy_port, u16, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(1)).proxy_port = p_u16(d, len, 0, 0); };
        25, route_1_source, u16, 0xFFFF
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(1)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        30, route_2_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 2, d, len); };
        31, route_2_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 2, d, len); };
        32, route_2_handler, u8, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(2)).handler = p_u8(d, len, 0, 0); };
        33, route_2_proxy_ip, u32, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(2)).proxy_ip = p_u32(d, len, 0, 0); };
        34, route_2_proxy_port, u16, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(2)).proxy_port = p_u16(d, len, 0, 0); };
        35, route_2_source, u16, 0xFFFF
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(2)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };

        40, route_3_path, str, 0
            => |s, d, len| { super::parse_route_path(s, 3, d, len); };
        41, route_3_body, str, 0
            => |s, d, len| { super::parse_route_body(s, 3, d, len); };
        42, route_3_handler, u8, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(3)).handler = p_u8(d, len, 0, 0); };
        43, route_3_proxy_ip, u32, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(3)).proxy_ip = p_u32(d, len, 0, 0); };
        44, route_3_proxy_port, u16, 0
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(3)).proxy_port = p_u16(d, len, 0, 0); };
        45, route_3_source, u16, 0xFFFF
            => |s, d, len| { (*s.srv_routes.as_mut_ptr().add(3)).source_index = p_u16(d, len, 0, 0xFFFF) as i16; };
    }
}

// ============================================================================
// Parameter Parsing Helpers (Server)
// ============================================================================

unsafe fn parse_route_path(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 { return; }
    let route = &mut *s.srv_routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_PATH);
    let mut i = 0;
    while i < n {
        route.path[i] = *d.add(i);
        i += 1;
    }
    route.path_len = n as u8;
    if (idx + 1) as u8 > s.srv_route_count {
        s.srv_route_count = (idx + 1) as u8;
    }
}

unsafe fn parse_route_body(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 { return; }
    if s.srv_body_pool.is_null() { return; }
    let offset = s.srv_body_pool_used as usize;
    let cap = s.srv_body_pool_cap as usize;
    let remaining = cap - offset;
    if remaining == 0 { return; }
    let n = len.min(remaining);
    let mut i = 0;
    while i < n {
        *s.srv_body_pool.add(offset + i) = *d.add(i);
        i += 1;
    }
    let route = &mut *s.srv_routes.as_mut_ptr().add(idx);
    if route.body_len == 0 {
        route.body_offset = offset as u16;
    }
    route.body_len += n as u16;
    s.srv_body_pool_used = (offset + n) as u16;
}

// ============================================================================
// Helpers — Server
// ============================================================================

#[inline(always)]
unsafe fn srv_log(s: &HttpState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

unsafe fn reset_socket(s: &mut HttpState) {
    if s.srv_socket_handle >= 0 {
        dev_socket_close(s.sys(), s.srv_socket_handle);
        s.srv_socket_handle = -1;
    }
    if s.srv_upstream_handle >= 0 {
        dev_socket_close(s.sys(), s.srv_upstream_handle);
        s.srv_upstream_handle = -1;
    }
    s.srv_phase = ServerPhase::SocketOpen;
}

unsafe fn parse_request_line(s: &mut HttpState) -> i32 {
    let buf = s.srv_recv_buf.as_ptr();
    let len = s.srv_recv_len as usize;

    if len < 14 { return -1; }
    if *buf != b'G' || *buf.add(1) != b'E' || *buf.add(2) != b'T' || *buf.add(3) != b' ' {
        return -1;
    }

    let mut path_end = 4usize;
    while path_end < len && *buf.add(path_end) != b' ' {
        path_end += 1;
    }
    if path_end <= 4 || *buf.add(4) != b'/' { return -1; }

    let plen = (path_end - 4).min(MAX_PATH);
    let mut i = 0;
    while i < plen {
        *s.srv_req_path.as_mut_ptr().add(i) = *buf.add(4 + i);
        i += 1;
    }
    s.srv_req_path_len = plen as u8;
    0
}

unsafe fn match_route(s: &HttpState) -> i8 {
    let req = s.srv_req_path.as_ptr();
    let plen = s.srv_req_path_len as usize;

    let mut i = 0u8;
    while (i as usize) < s.srv_route_count as usize {
        let route = &*s.srv_routes.as_ptr().add(i as usize);
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

unsafe fn build_header(s: &mut HttpState, status: &[u8], content_type: &[u8]) {
    let buf = s.srv_send_buf.as_mut_ptr();
    let cap = SRV_SEND_BUF_SIZE;
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

    s.srv_send_offset = 0;
    s.srv_send_len = off as u16;
}

unsafe fn build_error(s: &mut HttpState, code: &[u8], body: &[u8]) {
    let buf = s.srv_send_buf.as_mut_ptr();
    let cap = SRV_SEND_BUF_SIZE;
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

    s.srv_send_offset = 0;
    s.srv_send_len = off as u16;
}

// ============================================================================
// Variable Cache (Server)
// ============================================================================

unsafe fn drain_variables(s: &mut HttpState) {
    if s.srv_var_chan < 0 { return; }

    let var_chan = s.srv_var_chan;
    let syscalls = s.syscalls;
    let mut buf = [0u8; MSG_HDR_SIZE + MAX_VAR_VALUE];

    loop {
        let poll = ((*syscalls).channel_poll)(var_chan, POLL_IN);
        if poll <= 0 || (poll as u8 & POLL_IN) == 0 { break; }

        let (msg_type, payload_len) = msg_read(&*syscalls, var_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 && payload_len == 0 { break; }

        let vlen = (payload_len as usize).min(MAX_VAR_VALUE);

        let var_count = s.srv_var_count as usize;
        let mut slot: usize = var_count;
        let mut j = 0usize;
        while j < var_count {
            if (*s.srv_vars.as_ptr().add(j)).name_hash == msg_type {
                slot = j;
                break;
            }
            j += 1;
        }

        if slot >= MAX_VARS { continue; }

        let var = &mut *s.srv_vars.as_mut_ptr().add(slot);
        var.name_hash = msg_type;
        var.value_len = vlen as u8;
        let mut k = 0;
        let buf_ptr = buf.as_ptr();
        while k < vlen {
            *var.value.as_mut_ptr().add(k) = *buf_ptr.add(k);
            k += 1;
        }

        if slot == var_count {
            s.srv_var_count += 1;
        }
    }
}

unsafe fn lookup_var(s: &HttpState, hash: u32) -> (*const u8, usize) {
    let mut i = 0usize;
    while i < s.srv_var_count as usize {
        let var = &*s.srv_vars.as_ptr().add(i);
        if var.name_hash == hash {
            return (var.value.as_ptr(), var.value_len as usize);
        }
        i += 1;
    }
    (core::ptr::null(), 0)
}

// ============================================================================
// LRU Content Cache (Server)
// ============================================================================

unsafe fn cache_lookup(s: &HttpState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.srv_cache_count as usize {
        let e = &*s.srv_cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

unsafe fn cache_evict_all(s: &mut HttpState) -> u16 {
    s.srv_cache_count = 0;
    let mut inline_end: u16 = 0;
    let mut i = 0usize;
    while i < s.srv_route_count as usize {
        let r = &*s.srv_routes.as_ptr().add(i);
        if r.source_index < 0 && r.body_len > 0 {
            let end = r.body_offset + r.body_len;
            if end > inline_end { inline_end = end; }
        }
        i += 1;
    }
    inline_end
}

unsafe fn cache_alloc(s: &mut HttpState, route_idx: u8) -> usize {
    let arena_end: u16 = cache_evict_all(s);

    let idx = 0usize;
    let e = &mut *s.srv_cache_entries.as_mut_ptr().add(idx);
    e.route_index = route_idx;
    e.flags = CACHE_VALID;
    s.srv_cache_tick = s.srv_cache_tick.wrapping_add(1);
    e.lru_tick = s.srv_cache_tick;
    e.arena_offset = arena_end;
    e.length = 0;
    s.srv_cache_count = 1;
    idx
}

// ============================================================================
// Template Rendering (Server)
// ============================================================================

unsafe fn render_template_chunk(s: &mut HttpState) -> bool {
    let route = &*s.srv_routes.as_ptr().add(s.srv_matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pool = s.srv_body_pool as *const u8;
    let buf = s.srv_send_buf.as_mut_ptr();
    let mut out = 0usize;
    let mut pos = body_start + s.srv_tmpl_pos as usize;

    while pos < body_end && out < SRV_SEND_BUF_SIZE {
        if pos + 1 < body_end
            && *pool.add(pos) == b'{'
            && *pool.add(pos + 1) == b'{'
        {
            if out + MAX_VAR_VALUE > SRV_SEND_BUF_SIZE { break; }

            pos += 2;

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
            if pos + 1 < body_end { pos += 2; }

            let (val_ptr, val_len) = lookup_var(s, hash);
            if !val_ptr.is_null() {
                let mut vi = 0;
                while vi < val_len && out < SRV_SEND_BUF_SIZE {
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

    s.srv_tmpl_pos = (pos - body_start) as u16;
    s.srv_send_offset = 0;
    s.srv_send_len = out as u16;
    pos < body_end
}

// ============================================================================
// Legacy File Mode Helpers (Server)
// ============================================================================

unsafe fn parse_file_index(s: &HttpState) -> i16 {
    let buf = s.srv_req_path.as_ptr();
    let route = &*s.srv_routes.as_ptr().add(s.srv_matched_route as usize);
    let suffix_start = route.path_len as usize;
    let path_end = s.srv_req_path_len as usize;

    if suffix_start >= path_end { return -1; }
    let mut pos = suffix_start;
    if *buf.add(pos) == b'/' { pos += 1; }
    if pos >= path_end { return -1; }

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
// Helpers — Client
// ============================================================================

unsafe fn build_client_request(s: &mut HttpState) {
    let buf_ptr = s.cli_request_buf.as_mut_ptr();
    let mut offset = 0usize;

    let get = b"GET ";
    let mut i = 0;
    while i < get.len() && offset < 255 {
        *buf_ptr.add(offset) = *get.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    let path_ptr = s.cli_path.as_ptr();
    i = 0;
    while i < s.cli_path_len as usize && offset < 255 {
        *buf_ptr.add(offset) = *path_ptr.add(i);
        offset += 1;
        i += 1;
    }

    let http = b" HTTP/1.0\r\nHost: ";
    i = 0;
    while i < http.len() && offset < 255 {
        *buf_ptr.add(offset) = *http.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    let ip = s.cli_host_ip.to_be_bytes();
    let b0 = ip[0]; let b1 = ip[1]; let b2 = ip[2]; let b3 = ip[3];

    macro_rules! write_octet {
        ($b:expr) => {
            if $b >= 100 && offset < 255 {
                *buf_ptr.add(offset) = b'0' + ($b / 100);
                offset += 1;
            }
            if $b >= 10 && offset < 255 {
                *buf_ptr.add(offset) = b'0' + (($b / 10) % 10);
                offset += 1;
            }
            if offset < 255 {
                *buf_ptr.add(offset) = b'0' + ($b % 10);
                offset += 1;
            }
        };
    }

    write_octet!(b0);
    if offset < 255 { *buf_ptr.add(offset) = b'.'; offset += 1; }
    write_octet!(b1);
    if offset < 255 { *buf_ptr.add(offset) = b'.'; offset += 1; }
    write_octet!(b2);
    if offset < 255 { *buf_ptr.add(offset) = b'.'; offset += 1; }
    write_octet!(b3);

    let close = b"\r\nConnection: close\r\n\r\n";
    i = 0;
    while i < close.len() && offset < 256 {
        *buf_ptr.add(offset) = *close.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    s.cli_request_len = offset as u16;
    s.cli_request_sent = 0;
}

unsafe fn find_header_end(buf: &[u8], len: usize) -> Option<usize> {
    if len < 4 {
        return None;
    }
    let ptr = buf.as_ptr();
    let mut i = 0;
    while i + 3 < len {
        if *ptr.add(i) == b'\r' && *ptr.add(i + 1) == b'\n' &&
           *ptr.add(i + 2) == b'\r' && *ptr.add(i + 3) == b'\n' {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

// ============================================================================
// Server Init
// ============================================================================

unsafe fn server_init(s: &mut HttpState, in_chan: i32, out_chan: i32) {
    let sys = s.syscalls;
    s.srv_var_chan = in_chan;
    s.srv_file_chan = -1;
    s.srv_out_chan = out_chan;
    s.srv_socket_handle = -1;
    s.srv_upstream_handle = -1;
    s.srv_port = 80;
    s.srv_body_pool_used = 0;
    s.srv_recv_len = 0;
    s.srv_send_offset = 0;
    s.srv_send_len = 0;
    s.srv_tmpl_pos = 0;
    s.srv_file_index = -1;
    s.srv_file_count = 0;
    s.srv_index_pos = 0;
    s.srv_phase = ServerPhase::Init;
    s.srv_route_count = 0;
    s.srv_matched_route = -1;
    s.srv_recv_parsed = 0;
    s.srv_req_path_len = 0;
    s.srv_var_count = 0;
    s.srv_legacy_mode = 0;
    s.srv_cache_count = 0;
    s.srv_cache_tick = 0;

    // Allocate body pool from heap
    let pool = heap_alloc(&*sys, DEFAULT_BODY_POOL_SIZE as u32);
    if pool.is_null() {
        s.srv_body_pool = core::ptr::null_mut();
        s.srv_body_pool_cap = 0;
    } else {
        s.srv_body_pool = pool;
        s.srv_body_pool_cap = DEFAULT_BODY_POOL_SIZE as u16;
    }
}

unsafe fn server_post_params(s: &mut HttpState, in_chan: i32) {
    let sys = &*s.syscalls;

    // Discover additional ports
    s.srv_file_chan = dev_channel_port(sys, 0, 1); // in[1] = file data

    if s.srv_route_count == 0 {
        let r0 = &mut *s.srv_routes.as_mut_ptr().add(0);
        if r0.body_len > 0 {
            *r0.path.as_mut_ptr() = b'/';
            r0.path_len = 1;
            r0.handler = HANDLER_STATIC;
            s.srv_route_count = 1;
            s.srv_legacy_mode = 1;
        } else if in_chan >= 0 {
            s.srv_file_chan = in_chan;
            s.srv_var_chan = -1;
            s.srv_legacy_mode = 2;
        }
    }

    // Query fat32 file count if file channel is connected
    if s.srv_file_chan >= 0 {
        let mut count: u32 = 0;
        let count_ptr = &mut count as *mut u32 as *mut u8;
        let r = dev_channel_ioctl(sys, s.srv_file_chan, IOCTL_POLL_NOTIFY, count_ptr);
        if r >= 0 {
            s.srv_file_count = count as u16;
        }
    }

    srv_log(s, b"[http] server ready");
}

// ============================================================================
// Client Init
// ============================================================================

unsafe fn client_init(s: &mut HttpState, out_chan: i32) {
    s.cli_socket_handle = -1;
    s.cli_out_chan = out_chan;
    s.cli_host_ip = 0;
    s.cli_port = 80;
    s.cli_path_len = 0;
    s.cli_phase = ClientPhase::Init;
    s.cli_headers_done = 0;
    s.cli_connect_start_ms = 0;
    s.cli_pending_offset = 0;
    s.cli_recv_len = 0;
    s.cli_content_length = 0;
    s.cli_bytes_received = 0;
    s.cli_request_len = 0;
    s.cli_request_sent = 0;
}

unsafe fn client_post_params(s: &mut HttpState) {
    // Default to "/" if no path given
    if s.cli_path_len == 0 {
        s.cli_path[0] = b'/';
        s.cli_path_len = 1;
    }

    srv_log(s, b"[http] client configured");
}

// ============================================================================
// Server Step
// ============================================================================

unsafe fn server_step(s: &mut HttpState) -> i32 {
    // Drain variable updates from input channel
    drain_variables(s);

    match s.srv_phase {
        // ── Socket Setup ─────────────────────────────────────────
        ServerPhase::Init | ServerPhase::SocketOpen => {
            let handle = dev_socket_open(s.sys(), SOCK_TYPE_STREAM);
            if handle < 0 { return 0; }
            s.srv_socket_handle = handle;
            let rc = dev_socket_bind(s.sys(), handle, s.srv_port);
            if rc < 0 && rc != E_INPROGRESS {
                reset_socket(s);
                return 0;
            }
            s.srv_phase = ServerPhase::WaitBind;
            return 2;
        }

        ServerPhase::WaitBind => {
            let rc = dev_socket_listen(s.sys(), s.srv_socket_handle);
            if rc == E_BUSY { return 0; }
            if rc < 0 && rc != E_INPROGRESS {
                reset_socket(s);
                return 0;
            }
            s.srv_phase = ServerPhase::WaitListen;
            return 2;
        }

        ServerPhase::WaitListen => {
            if s.srv_draining != 0 {
                return 1;
            }
            let rc = dev_socket_accept(s.sys(), s.srv_socket_handle);
            if rc == E_BUSY { return 0; }
            if rc < 0 && rc != E_INPROGRESS {
                s.srv_phase = ServerPhase::Error;
                return -1;
            }
            s.srv_phase = ServerPhase::WaitAccept;
        }

        ServerPhase::WaitAccept => {
            if s.srv_draining != 0 {
                return 1;
            }
            let poll = dev_socket_poll(s.sys(), s.srv_socket_handle, POLL_CONN | POLL_HUP);
            if poll <= 0 { return 0; }
            if (poll as u8 & POLL_CONN) != 0 {
                s.srv_recv_len = 0;
                s.srv_recv_parsed = 0;
                s.srv_phase = ServerPhase::RecvRequest;
            } else if (poll as u8 & POLL_HUP) != 0 {
                s.srv_phase = ServerPhase::CloseConn;
            }
        }

        // ── Request Parsing ──────────────────────────────────────
        ServerPhase::RecvRequest => {
            let space = SRV_RECV_BUF_SIZE - s.srv_recv_len as usize;
            if space > 0 {
                let buf_ptr = s.srv_recv_buf.as_mut_ptr().add(s.srv_recv_len as usize);
                let n = dev_socket_recv(s.sys(), s.srv_socket_handle, buf_ptr, space);
                if n > 0 { s.srv_recv_len += n as u16; }
            }

            let len = s.srv_recv_len as usize;

            if s.srv_recv_parsed == 0 {
                let ptr = s.srv_recv_buf.as_ptr();
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
                        s.srv_phase = ServerPhase::DrainSend;
                        return 0;
                    }
                    s.srv_recv_parsed = 1;
                } else if space == 0 {
                    build_error(s, b"400 Bad Request", b"Bad Request\n");
                    s.srv_phase = ServerPhase::DrainSend;
                    return 0;
                }
            }

            if s.srv_recv_parsed == 1 {
                let ptr = s.srv_recv_buf.as_ptr();
                let scan_len = s.srv_recv_len as usize;
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
                    s.srv_phase = ServerPhase::DispatchRoute;
                    return 2;
                } else if space == 0 {
                    let l = s.srv_recv_len as usize;
                    if l >= 3 {
                        let p = s.srv_recv_buf.as_mut_ptr();
                        *p = *p.add(l - 3);
                        *p.add(1) = *p.add(l - 2);
                        *p.add(2) = *p.add(l - 1);
                        s.srv_recv_len = 3;
                    }
                }
            }

            let poll = dev_socket_poll(s.sys(), s.srv_socket_handle, POLL_HUP);
            if poll > 0 && (poll as u8 & POLL_HUP) != 0 {
                s.srv_phase = ServerPhase::CloseConn;
            }
        }

        // ── Route Dispatch ───────────────────────────────────────
        ServerPhase::DispatchRoute => {
            if s.srv_legacy_mode == 2 {
                step_legacy_file_dispatch(s);
                return 0;
            }

            let ri = match_route(s);
            if ri < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                s.srv_phase = ServerPhase::DrainSend;
                return 0;
            }
            s.srv_matched_route = ri;
            let route = &*s.srv_routes.as_ptr().add(ri as usize);
            let handler = route.handler;
            let src_idx = route.source_index;

            match handler {
                HANDLER_STATIC | HANDLER_TEMPLATE => {
                    if src_idx >= 0 && s.srv_file_chan >= 0 {
                        let ci = cache_lookup(s, ri as u8);
                        if ci >= 0 {
                            let ce = &mut *s.srv_cache_entries.as_mut_ptr().add(ci as usize);
                            s.srv_cache_tick = s.srv_cache_tick.wrapping_add(1);
                            ce.lru_tick = s.srv_cache_tick;
                            let r = &mut *s.srv_routes.as_mut_ptr().add(ri as usize);
                            r.body_offset = ce.arena_offset;
                            r.body_len = ce.length;
                            build_header(s, b"200 OK", b"text/html");
                            s.srv_tmpl_pos = 0;
                            s.srv_phase = ServerPhase::SendHeaders;
                        } else {
                            let _slot = cache_alloc(s, ri as u8);
                            dev_channel_ioctl(
                                s.sys(), s.srv_file_chan, IOCTL_FLUSH, core::ptr::null_mut(),
                            );
                            let mut pos = src_idx as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            dev_channel_ioctl(
                                s.sys(), s.srv_file_chan, IOCTL_NOTIFY, pos_ptr,
                            );
                            s.srv_phase = ServerPhase::FetchContent;
                        }
                    } else {
                        build_header(s, b"200 OK", b"text/html");
                        s.srv_tmpl_pos = 0;
                        s.srv_phase = ServerPhase::SendHeaders;
                    }
                }
                HANDLER_FILE => {
                    let fi = parse_file_index(s);
                    s.srv_file_index = fi;
                    if fi == -1 {
                        if s.srv_file_chan >= 0 {
                            let mut count: u32 = 0;
                            let count_ptr = &mut count as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                s.sys(), s.srv_file_chan, IOCTL_POLL_NOTIFY, count_ptr,
                            );
                            if r >= 0 { s.srv_file_count = count as u16; }
                        }
                        build_header(s, b"200 OK", b"text/plain");
                        s.srv_index_pos = 0;
                        s.srv_phase = ServerPhase::SendHeaders;
                    } else if fi >= 0 {
                        if s.srv_file_chan >= 0 {
                            dev_channel_ioctl(
                                s.sys(), s.srv_file_chan, IOCTL_FLUSH, core::ptr::null_mut(),
                            );
                            let mut pos = fi as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                s.sys(), s.srv_file_chan, IOCTL_NOTIFY, pos_ptr,
                            );
                            if r < 0 {
                                build_error(s, b"404 Not Found", b"Not Found\n");
                                s.srv_phase = ServerPhase::DrainSend;
                                return 0;
                            }
                            build_header(s, b"200 OK", b"application/octet-stream");
                        } else {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            s.srv_phase = ServerPhase::DrainSend;
                            return 0;
                        }
                        s.srv_phase = ServerPhase::SendHeaders;
                    } else {
                        build_error(s, b"400 Bad Request", b"Bad Request\n");
                        s.srv_phase = ServerPhase::DrainSend;
                        return 0;
                    }
                }
                HANDLER_PROXY => {
                    build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
                    s.srv_phase = ServerPhase::DrainSend;
                }
                _ => {
                    build_error(s, b"500 Internal Server Error", b"Unknown handler\n");
                    s.srv_phase = ServerPhase::DrainSend;
                }
            }
        }

        // ── Send Headers ─────────────────────────────────────────
        ServerPhase::SendHeaders => {
            let remaining = (s.srv_send_len - s.srv_send_offset) as usize;
            if remaining == 0 {
                let handler = if s.srv_matched_route >= 0 {
                    (*s.srv_routes.as_ptr().add(s.srv_matched_route as usize)).handler
                } else {
                    HANDLER_FILE
                };

                match handler {
                    HANDLER_STATIC => {
                        s.srv_phase = ServerPhase::SendBody;
                    }
                    HANDLER_TEMPLATE => {
                        s.srv_phase = ServerPhase::SendBody;
                    }
                    HANDLER_FILE => {
                        if s.srv_file_index < 0 {
                            s.srv_phase = ServerPhase::SendBody;
                        } else {
                            s.srv_phase = ServerPhase::SendBody;
                        }
                    }
                    _ => {
                        s.srv_phase = ServerPhase::CloseConn;
                    }
                }
                return 2;
            }
            let ptr = s.srv_send_buf.as_ptr().add(s.srv_send_offset as usize);
            let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, remaining);
            if sent > 0 { s.srv_send_offset += sent as u16; }
        }

        // ── Send Body ────────────────────────────────────────────
        ServerPhase::SendBody => {
            let handler = if s.srv_matched_route >= 0 {
                (*s.srv_routes.as_ptr().add(s.srv_matched_route as usize)).handler
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
                    if s.srv_file_index < 0 {
                        return step_send_index(s);
                    } else {
                        return step_send_file(s);
                    }
                }
                _ => {
                    s.srv_phase = ServerPhase::CloseConn;
                }
            }
        }

        // ── Drain Error/Redirect Response ────────────────────────
        ServerPhase::DrainSend => {
            let remaining = (s.srv_send_len - s.srv_send_offset) as usize;
            if remaining == 0 {
                s.srv_phase = ServerPhase::CloseConn;
                return 0;
            }
            let ptr = s.srv_send_buf.as_ptr().add(s.srv_send_offset as usize);
            let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, remaining);
            if sent > 0 { s.srv_send_offset += sent as u16; }
        }

        // ── Fetch Content from Channel ────────────────────────────
        ServerPhase::FetchContent => {
            if s.srv_file_chan < 0 {
                build_error(s, b"500 Internal Server Error", b"No content source\n");
                s.srv_phase = ServerPhase::DrainSend;
                return 0;
            }
            let poll = (s.sys().channel_poll)(s.srv_file_chan, POLL_IN | POLL_HUP);
            if poll > 0 && ((poll as u8 & POLL_IN) != 0 || (poll as u8 & POLL_HUP) != 0) {
                s.srv_phase = ServerPhase::CacheStream;
                return 2;
            }
        }

        // ── Stream Content into Cache ────────────────────────────
        ServerPhase::CacheStream => {
            if s.srv_cache_count == 0 || s.srv_file_chan < 0 {
                s.srv_phase = ServerPhase::CloseConn;
                return 0;
            }
            let ce_idx = 0usize;
            let ce = &mut *s.srv_cache_entries.as_mut_ptr().add(ce_idx);
            let arena_off = ce.arena_offset as usize;
            let cur_len = ce.length as usize;
            let pool_cap = s.srv_body_pool_cap as usize;

            let space = pool_cap - (arena_off + cur_len);
            if space > 0 && !s.srv_body_pool.is_null() {
                let dst = s.srv_body_pool.add(arena_off + cur_len);
                let to_read = space.min(SRV_SEND_BUF_SIZE);
                let n = (s.sys().channel_read)(s.srv_file_chan, dst, to_read);
                if n > 0 {
                    ce.length += n as u16;
                }
            }

            let poll = (s.sys().channel_poll)(s.srv_file_chan, POLL_IN | POLL_HUP);
            let eof = poll > 0 && (poll as u8 & POLL_HUP) != 0
                && (poll <= 0 || (poll as u8 & POLL_IN) == 0);
            let full = (arena_off + ce.length as usize) >= pool_cap;

            if eof || full {
                ce.flags |= CACHE_COMPLETE;
                let ri = s.srv_matched_route as usize;
                let r = &mut *s.srv_routes.as_mut_ptr().add(ri);
                r.body_offset = ce.arena_offset;
                r.body_len = ce.length;
                build_header(s, b"200 OK", b"text/html");
                s.srv_tmpl_pos = 0;
                s.srv_phase = ServerPhase::SendHeaders;
                return 2;
            }

            return 2;
        }

        // ── Connection Close + Re-listen ─────────────────────────
        ServerPhase::CloseConn => {
            reset_socket(s);
            if s.srv_draining != 0 {
                return 1;
            }
        }

        // ── Proxy Phases (stubs) ─────────────────────────────────
        ServerPhase::ProxyConnect
        | ServerPhase::ProxyWaitConnect
        | ServerPhase::ProxySendRequest
        | ServerPhase::ProxyRelayHeaders
        | ServerPhase::ProxyRelayBody => {
            build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
            s.srv_phase = ServerPhase::DrainSend;
        }

        ServerPhase::Error => {
            return 1;
        }

        _ => {
            s.srv_phase = ServerPhase::Error;
            return -1;
        }
    }

    0
}

// ============================================================================
// Body Send Helpers (Server)
// ============================================================================

unsafe fn step_send_static(s: &mut HttpState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.srv_socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.srv_phase = ServerPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    let route = &*s.srv_routes.as_ptr().add(s.srv_matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + s.srv_tmpl_pos as usize;

    if pos >= body_end {
        s.srv_phase = ServerPhase::CloseConn;
        return 0;
    }

    let remaining = body_end - pos;
    let to_send = remaining.min(SRV_SEND_BUF_SIZE);
    let ptr = (s.srv_body_pool as *const u8).add(pos);
    let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, to_send);
    if sent > 0 {
        s.srv_tmpl_pos += sent as u16;
        return 2;
    }
    0
}

unsafe fn step_send_template(s: &mut HttpState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.srv_socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.srv_phase = ServerPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    if s.srv_send_offset < s.srv_send_len {
        let remaining = (s.srv_send_len - s.srv_send_offset) as usize;
        let ptr = s.srv_send_buf.as_ptr().add(s.srv_send_offset as usize);
        let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, remaining);
        if sent > 0 { s.srv_send_offset += sent as u16; }
        return 0;
    }

    let has_more = render_template_chunk(s);
    if s.srv_send_len > 0 {
        let ptr = s.srv_send_buf.as_ptr();
        let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, s.srv_send_len as usize);
        if sent > 0 { s.srv_send_offset = sent as u16; }
        return if has_more { 2 } else { 0 };
    }

    if !has_more {
        s.srv_phase = ServerPhase::CloseConn;
    }
    0
}

unsafe fn step_send_index(s: &mut HttpState) -> i32 {
    if s.srv_index_pos >= s.srv_file_count {
        s.srv_phase = ServerPhase::CloseConn;
        return 0;
    }

    if s.srv_send_offset >= s.srv_send_len {
        let buf = s.srv_send_buf.as_mut_ptr();
        let mut off = 0usize;
        let mut idx = s.srv_index_pos;
        while idx < s.srv_file_count && off + 6 < SRV_SEND_BUF_SIZE {
            off += fmt_u32_raw(buf.add(off), idx as u32);
            *buf.add(off) = b'\n';
            off += 1;
            idx += 1;
        }
        s.srv_send_offset = 0;
        s.srv_send_len = off as u16;
        s.srv_index_pos = idx;
    }

    let remaining = (s.srv_send_len - s.srv_send_offset) as usize;
    let ptr = s.srv_send_buf.as_ptr().add(s.srv_send_offset as usize);
    let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, remaining);
    if sent > 0 {
        s.srv_send_offset += sent as u16;
        return 2;
    }
    0
}

unsafe fn step_send_file(s: &mut HttpState) -> i32 {
    let poll = dev_socket_poll(s.sys(), s.srv_socket_handle, POLL_OUT | POLL_HUP);
    if poll <= 0 { return 0; }
    if (poll as u8 & POLL_HUP) != 0 { s.srv_phase = ServerPhase::CloseConn; return 0; }
    if (poll as u8 & POLL_OUT) == 0 { return 0; }

    if s.srv_send_offset >= s.srv_send_len {
        let n = (s.sys().channel_read)(s.srv_file_chan, s.srv_send_buf.as_mut_ptr(), SRV_SEND_BUF_SIZE);
        if n > 0 {
            s.srv_send_offset = 0;
            s.srv_send_len = n as u16;
        } else {
            let chan_poll = (s.sys().channel_poll)(s.srv_file_chan, POLL_IN | POLL_HUP);
            if chan_poll > 0 && (chan_poll as u8 & POLL_HUP) != 0 {
                s.srv_phase = ServerPhase::CloseConn;
            }
            return 0;
        }
    }

    let remaining = (s.srv_send_len - s.srv_send_offset) as usize;
    let ptr = s.srv_send_buf.as_ptr().add(s.srv_send_offset as usize);
    let sent = dev_socket_send(s.sys(), s.srv_socket_handle, ptr, remaining);
    if sent > 0 {
        s.srv_send_offset += sent as u16;
        return 2;
    }
    0
}

// ============================================================================
// Legacy File Mode (Server)
// ============================================================================

unsafe fn step_legacy_file_dispatch(s: &mut HttpState) {
    let buf = s.srv_req_path.as_ptr();
    let plen = s.srv_req_path_len as usize;

    if plen == 1 && *buf == b'/' {
        if s.srv_file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(s.sys(), s.srv_file_chan, IOCTL_POLL_NOTIFY, count_ptr);
            if r >= 0 { s.srv_file_count = count as u16; }
        }
        build_header(s, b"200 OK", b"text/plain");
        s.srv_index_pos = 0;
        s.srv_file_index = -1;
        s.srv_matched_route = -1;
        s.srv_phase = ServerPhase::SendHeaders;
    } else if plen >= 2 && *buf == b'/' {
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
            s.srv_phase = ServerPhase::DrainSend;
            return;
        }

        s.srv_file_index = idx as i16;
        s.srv_matched_route = -1;
        if s.srv_file_chan >= 0 {
            dev_channel_ioctl(s.sys(), s.srv_file_chan, IOCTL_FLUSH, core::ptr::null_mut());
            let mut pos = idx as u32;
            let pos_ptr = &mut pos as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(s.sys(), s.srv_file_chan, IOCTL_NOTIFY, pos_ptr);
            if r < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                s.srv_phase = ServerPhase::DrainSend;
                return;
            }
            build_header(s, b"200 OK", b"application/octet-stream");
        } else {
            build_error(s, b"404 Not Found", b"Not Found\n");
            s.srv_phase = ServerPhase::DrainSend;
            return;
        }
        s.srv_phase = ServerPhase::SendHeaders;
    } else {
        build_error(s, b"400 Bad Request", b"Bad Request\n");
        s.srv_phase = ServerPhase::DrainSend;
    }
}

// ============================================================================
// Client Step
// ============================================================================

unsafe fn client_step(s: &mut HttpState) -> i32 {
    loop {
        match s.cli_phase {
            ClientPhase::Init => {
                srv_log(s, b"[http] opening socket");
                s.cli_phase = ClientPhase::SocketOpen;
                continue;
            }

            ClientPhase::SocketOpen => {
                let mut sock_arg = [SOCK_TYPE_STREAM];
                let handle = (s.sys().dev_call)(-1, DEV_SOCKET_OPEN, sock_arg.as_mut_ptr(), 1);
                if handle < 0 {
                    srv_log(s, b"[http] socket_open failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_SOCKET_FAILED;
                }
                s.cli_socket_handle = handle;
                s.cli_phase = ClientPhase::Connecting;
                continue;
            }

            ClientPhase::Connecting => {
                let addr = ChannelAddr::new(s.cli_host_ip, s.cli_port);
                let rc = (s.sys().dev_call)(s.cli_socket_handle, DEV_SOCKET_CONNECT, &addr as *const _ as *mut u8, core::mem::size_of::<ChannelAddr>());
                if rc < 0 && rc != E_INPROGRESS {
                    srv_log(s, b"[http] connect failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_CONNECT_FAILED;
                }
                s.cli_connect_start_ms = dev_millis(s.sys());
                s.cli_phase = ClientPhase::WaitConnect;
                return 0;
            }

            ClientPhase::WaitConnect => {
                let mut poll_arg = [POLL_CONN];
                let poll = (s.sys().dev_call)(s.cli_socket_handle, DEV_SOCKET_POLL, poll_arg.as_mut_ptr(), 1);
                if poll < 0 {
                    s.cli_phase = ClientPhase::Error;
                    return E_CONNECT_FAILED;
                }
                if (poll as u8 & POLL_CONN) != 0 {
                    srv_log(s, b"[http] connected");
                    build_client_request(s);
                    s.cli_phase = ClientPhase::SendRequest;
                    continue;
                }
                if dev_millis(s.sys()).wrapping_sub(s.cli_connect_start_ms) >= CONNECT_TIMEOUT_MS {
                    srv_log(s, b"[http] connect timeout");
                    s.cli_phase = ClientPhase::Error;
                    return E_CONNECT_FAILED;
                }
                return 0;
            }

            ClientPhase::SendRequest => {
                let remaining = (s.cli_request_len - s.cli_request_sent) as usize;
                let buf_ptr = s.cli_request_buf.as_mut_ptr().add(s.cli_request_sent as usize);

                let sent = (s.sys().dev_call)(
                    s.cli_socket_handle,
                    DEV_SOCKET_SEND,
                    buf_ptr,
                    remaining,
                );

                if sent < 0 {
                    if sent == E_AGAIN {
                        return 0;
                    }
                    srv_log(s, b"[http] send failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_SEND_FAILED;
                }

                s.cli_request_sent += sent as u16;
                if s.cli_request_sent >= s.cli_request_len {
                    srv_log(s, b"[http] request sent");
                    s.cli_headers_done = 0;
                    s.cli_phase = ClientPhase::RecvHeaders;
                }
                return 0;
            }

            ClientPhase::RecvHeaders => {
                let read = (s.sys().dev_call)(
                    s.cli_socket_handle,
                    DEV_SOCKET_RECV,
                    s.cli_recv_buf.as_mut_ptr(),
                    CLI_RECV_BUF_SIZE,
                );

                if read < 0 {
                    if read == E_AGAIN {
                        return 0;
                    }
                    srv_log(s, b"[http] recv failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_RECV_FAILED;
                }

                if read == 0 {
                    srv_log(s, b"[http] premature close");
                    s.cli_phase = ClientPhase::Done;
                    return 1;
                }

                if let Some(body_start) = find_header_end(&s.cli_recv_buf, read as usize) {
                    let body_len = (read as usize) - body_start;
                    if body_len > 0 {
                        let buf_ptr = s.cli_recv_buf.as_mut_ptr();
                        let mut i = 0;
                        while i < body_len {
                            *buf_ptr.add(i) = *buf_ptr.add(body_start + i);
                            i += 1;
                        }
                        s.cli_recv_len = body_len as u16;
                        s.cli_pending_offset = 0;
                        s.cli_phase = ClientPhase::Writing;
                    } else {
                        s.cli_phase = ClientPhase::RecvBody;
                    }
                    srv_log(s, b"[http] headers done");
                    continue;
                }

                return 0;
            }

            ClientPhase::RecvBody => {
                if s.cli_out_chan >= 0 {
                    let poll = (s.sys().channel_poll)(s.cli_out_chan, POLL_OUT);
                    if poll <= 0 || (poll as u8 & POLL_OUT) == 0 {
                        return 0;
                    }
                }

                let read = (s.sys().dev_call)(
                    s.cli_socket_handle,
                    DEV_SOCKET_RECV,
                    s.cli_recv_buf.as_mut_ptr(),
                    CLI_RECV_BUF_SIZE,
                );

                if read < 0 {
                    if read == E_AGAIN {
                        return 0;
                    }
                    srv_log(s, b"[http] recv body failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_RECV_FAILED;
                }

                if read == 0 {
                    srv_log(s, b"[http] transfer done");
                    s.cli_phase = ClientPhase::Done;
                    return 1;
                }

                s.cli_recv_len = read as u16;
                s.cli_pending_offset = 0;
                s.cli_bytes_received += read as u32;
                s.cli_phase = ClientPhase::Writing;
                continue;
            }

            ClientPhase::Writing => {
                if s.cli_out_chan < 0 {
                    s.cli_phase = ClientPhase::RecvBody;
                    continue;
                }

                let offset = s.cli_pending_offset as usize;
                let remaining = (s.cli_recv_len as usize) - offset;

                let written = (s.sys().channel_write)(
                    s.cli_out_chan,
                    s.cli_recv_buf.as_ptr().add(offset),
                    remaining,
                );

                if written < 0 {
                    if written == E_AGAIN {
                        return 0;
                    }
                    srv_log(s, b"[http] write failed");
                    s.cli_phase = ClientPhase::Error;
                    return E_WRITE_FAILED;
                }

                s.cli_pending_offset += written as u16;
                if s.cli_pending_offset >= s.cli_recv_len {
                    s.cli_phase = ClientPhase::RecvBody;
                }
                return 0;
            }

            ClientPhase::Done => {
                if s.cli_socket_handle >= 0 {
                    (s.sys().dev_call)(s.cli_socket_handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
                    s.cli_socket_handle = -1;
                }
                return 1;
            }

            ClientPhase::Error => {
                if s.cli_socket_handle >= 0 {
                    (s.sys().dev_call)(s.cli_socket_handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
                    s.cli_socket_handle = -1;
                }
                return -1;
            }

            _ => return -1,
        }
    }
}

// ============================================================================
// Exported PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpState>() as u32
}

/// Declare heap arena size. The body pool is allocated from this arena (server mode).
#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    (DEFAULT_BODY_POOL_SIZE + 64) as u32
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
        if state_size < core::mem::size_of::<HttpState>() { return -6; }

        let s = &mut *(state as *mut HttpState);
        s.syscalls = syscalls as *const SyscallTable;
        s.mode = MODE_SERVER; // default

        // Pre-init both modes so body pool is ready for param parsing
        server_init(s, in_chan, out_chan);
        client_init(s, out_chan);

        // Parse TLV params (sets mode, server params, client params)
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Post-param setup based on mode
        if s.mode == MODE_CLIENT {
            client_post_params(s);
        } else {
            server_post_params(s, in_chan);
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut HttpState);
        if s.syscalls.is_null() { return -1; }

        if s.mode == MODE_CLIENT {
            client_step(s)
        } else {
            server_step(s)
        }
    }
}

// ============================================================================
// Drain Support (Server mode only)
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    if state.is_null() { return -1; }
    unsafe {
        let s = &mut *(state as *mut HttpState);
        if s.mode == MODE_SERVER {
            s.srv_draining = 1;
        }
    }
    0
}

// ============================================================================
// Channel Hints (Server mode)
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
