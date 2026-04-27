//! HTTP server — accepts connections, routes requests, serves static
//! content / templates / files / proxy responses.
//!
//! State, route definitions, content cache, and the per-tick step
//! machine all live here. Pure-byte parse and build helpers come from
//! `super::wire::h1`; framing constants come from `super::connection`;
//! shared utilities come from `super::core`.

use super::abi::SyscallTable;
use super::connection::{
    NET_BUF_SIZE, NET_CMD_BIND, NET_CMD_CLOSE, NET_CMD_SEND, NET_MSG_ACCEPTED, NET_MSG_BOUND,
    NET_MSG_CLOSED, NET_MSG_DATA, NET_MSG_ERROR,
};
use super::h2;
use super::wire_h1 as h1;
use super::wire_h2;
use super::wire_ws as ws;
use super::HttpState;
use super::{
    dev_channel_ioctl, dev_channel_port, dev_log, dev_millis as _, fmt_u32_raw, heap_alloc,
    msg_read, net_read_frame, net_write_frame, p_u16, p_u32, p_u8, IOCTL_FLUSH, IOCTL_NOTIFY,
    IOCTL_POLL_NOTIFY, MSG_HDR_SIZE, NET_FRAME_HDR, POLL_HUP, POLL_IN, POLL_OUT,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────

pub(crate) const RECV_BUF_SIZE: usize = 2048;
pub(crate) const SEND_BUF_SIZE: usize = 1024;
pub(crate) const MAX_ROUTES: usize = 4;
pub(crate) const MAX_PATH: usize = 32;
pub(crate) const DEFAULT_BODY_POOL_SIZE: usize = 3072;
pub(crate) const MAX_VARS: usize = 16;
pub(crate) const MAX_VAR_VALUE: usize = 16;
pub(crate) const MAX_CACHE: usize = 4;

// ── Route handler kinds (stored in Route.handler) ─────────────────────────

pub(crate) const HANDLER_STATIC: u8 = 0;
pub(crate) const HANDLER_TEMPLATE: u8 = 1;
pub(crate) const HANDLER_FILE: u8 = 2;
pub(crate) const HANDLER_PROXY: u8 = 3;
pub(crate) const HANDLER_WEBSOCKET: u8 = 4;

const CACHE_VALID: u8 = 0x01;
const CACHE_COMPLETE: u8 = 0x02;

// ── Phase machine ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Init = 0,
    Binding = 1,
    WaitBound = 2,
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

    /// 101 Switching Protocols composed; flush it then enter `WsActive`.
    WsHandshake = 18,
    /// WebSocket frame loop. Reads masked client frames from net_in,
    /// echoes data frames, replies to ping with pong, processes close.
    WsActive = 19,
    /// A close frame is queued in `send_buf`; flush it then close the
    /// connection.
    WsClose = 20,

    /// HTTP/2 connection mode (h2c). Reached when the first 24 bytes
    /// of a connection match the h2 preface; all further state lives
    /// in `ServerState.h2`.
    H2Active = 21,

    Error = 255,
}

// ── Route + cache + variable types ────────────────────────────────────────

#[repr(C)]
pub(crate) struct Route {
    pub(crate) proxy_ip: u32,
    pub(crate) body_offset: u16,
    pub(crate) body_len: u16,
    pub(crate) proxy_port: u16,
    pub(crate) path_len: u8,
    pub(crate) handler: u8,
    pub(crate) source_index: i16,
    _route_pad: [u8; 2],
    pub(crate) path: [u8; MAX_PATH],
}

impl Route {
    pub(crate) const fn new() -> Self {
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

// ── Server state ──────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct ServerState {
    pub(crate) var_chan: i32,
    pub(crate) file_chan: i32,
    pub(crate) out_chan: i32,
    pub(crate) conn_id: u8,
    _conn_pad: [u8; 3],

    pub(crate) port: u16,
    pub(crate) body_pool_used: u16,
    pub(crate) recv_len: u16,
    pub(crate) send_offset: u16,
    pub(crate) send_len: u16,
    pub(crate) tmpl_pos: u16,
    pub(crate) file_index: i16,
    pub(crate) file_count: u16,
    pub(crate) index_pos: u16,

    pub(crate) phase: Phase,
    pub(crate) route_count: u8,
    pub(crate) matched_route: i8,
    pub(crate) recv_parsed: u8,
    pub(crate) req_path_len: u8,
    pub(crate) var_count: u8,
    pub(crate) legacy_mode: u8,
    pub(crate) cache_count: u8,
    pub(crate) cache_tick: u8,
    pub(crate) req_path: [u8; MAX_PATH],

    pub(crate) routes: [Route; MAX_ROUTES],
    vars: [VarEntry; MAX_VARS],
    cache_entries: [CacheEntry; MAX_CACHE],
    pub(crate) recv_buf: [u8; RECV_BUF_SIZE],
    pub(crate) send_buf: [u8; SEND_BUF_SIZE],
    pub(crate) body_pool: *mut u8,
    pub(crate) body_pool_cap: u16,
    pub(crate) draining: u8,
    _pad: [u8; 1],

    /// HTTP/2 connection state. Only meaningful while `phase ==
    /// Phase::H2Active`; zero-valued otherwise.
    pub(crate) h2: super::h2::H2State,
}

// ServerState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Param parsing helpers (called from mod.rs::params_def) ────────────────

pub(crate) unsafe fn parse_route_path(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 {
        return;
    }
    let route = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_PATH);
    let mut i = 0;
    while i < n {
        route.path[i] = *d.add(i);
        i += 1;
    }
    route.path_len = n as u8;
    if (idx + 1) as u8 > s.server.route_count {
        s.server.route_count = (idx + 1) as u8;
    }
}

pub(crate) unsafe fn parse_route_body(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES || len == 0 {
        return;
    }
    if s.server.body_pool.is_null() {
        return;
    }
    let offset = s.server.body_pool_used as usize;
    let cap = s.server.body_pool_cap as usize;
    let remaining = cap - offset;
    if remaining == 0 {
        return;
    }
    let n = len.min(remaining);
    let mut i = 0;
    while i < n {
        *s.server.body_pool.add(offset + i) = *d.add(i);
        i += 1;
    }
    let route = &mut *s.server.routes.as_mut_ptr().add(idx);
    if route.body_len == 0 {
        route.body_offset = offset as u16;
    }
    route.body_len += n as u16;
    s.server.body_pool_used = (offset + n) as u16;
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    let sys = s.syscalls;
    s.server.var_chan = -1;
    s.server.file_chan = -1;
    s.server.out_chan = -1;
    s.server.port = 80;
    s.server.file_index = -1;
    s.server.matched_route = -1;
    s.server.phase = Phase::Init;

    let pool = heap_alloc(&*sys, DEFAULT_BODY_POOL_SIZE as u32);
    if !pool.is_null() {
        s.server.body_pool = pool;
        s.server.body_pool_cap = DEFAULT_BODY_POOL_SIZE as u16;
    }
}

pub(crate) unsafe fn post_params(s: &mut HttpState) {
    let sys = &*s.syscalls;

    // Discover additional ports:
    //   in[1]  = variable updates  (FmpMessage)
    //   in[2]  = file data         (OctetStream)
    //   out[1] = file ctrl         (OctetStream)
    s.server.var_chan = dev_channel_port(sys, 0, 1);
    s.server.file_chan = dev_channel_port(sys, 0, 2);
    s.server.out_chan = dev_channel_port(sys, 1, 1);

    if s.server.route_count == 0 {
        let r0 = &mut *s.server.routes.as_mut_ptr().add(0);
        if r0.body_len > 0 {
            *r0.path.as_mut_ptr() = b'/';
            r0.path_len = 1;
            r0.handler = HANDLER_STATIC;
            s.server.route_count = 1;
            s.server.legacy_mode = 1;
        } else if s.server.file_chan >= 0 {
            s.server.legacy_mode = 2;
        }
    }

    if s.server.file_chan >= 0 {
        let mut count: u32 = 0;
        let count_ptr = &mut count as *mut u32 as *mut u8;
        let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr);
        if r >= 0 {
            s.server.file_count = count as u16;
        }
    }

    log(s, b"[http] server ready");
}

// ── Internal helpers ──────────────────────────────────────────────────────

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

unsafe fn reset_connection(s: &mut HttpState) {
    if s.server.phase as u8 > Phase::WaitAccept as u8 && s.net_out_chan >= 0 {
        let sys = &*s.syscalls;
        let chan = s.net_out_chan;
        let buf = s.net_buf.as_mut_ptr();
        let mut payload = [0u8; 1];
        payload[0] = s.server.conn_id;
        net_write_frame(sys, chan, NET_CMD_CLOSE, payload.as_ptr(), 1, buf, NET_BUF_SIZE);
    }
    // The IP module resets the listener slot to Closed when a connection
    // completes, so we must send a fresh CMD_BIND to re-listen.
    s.server.phase = Phase::Binding;
}

pub(crate) unsafe fn match_route(s: &HttpState) -> i8 {
    let req = s.server.req_path.as_ptr();
    let plen = s.server.req_path_len as usize;

    let mut i = 0u8;
    while (i as usize) < s.server.route_count as usize {
        let route = &*s.server.routes.as_ptr().add(i as usize);
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
            if ok {
                return i as i8;
            }
        }
        i += 1;
    }
    -1
}

unsafe fn build_header(s: &mut HttpState, status: &[u8], content_type: &[u8]) {
    let len = h1::write_status_line(
        s.server.send_buf.as_mut_ptr(),
        SEND_BUF_SIZE,
        status,
        content_type,
    );
    s.server.send_offset = 0;
    s.server.send_len = len as u16;
}

unsafe fn build_error(s: &mut HttpState, code: &[u8], body: &[u8]) {
    let len = h1::write_error_response(
        s.server.send_buf.as_mut_ptr(),
        SEND_BUF_SIZE,
        code,
        body,
    );
    s.server.send_offset = 0;
    s.server.send_len = len as u16;
}

// ── Variable cache (drained from in[1] each tick) ──────────────────────────

unsafe fn drain_variables(s: &mut HttpState) {
    if s.server.var_chan < 0 {
        return;
    }

    let var_chan = s.server.var_chan;
    let syscalls = s.syscalls;
    let mut buf = [0u8; MSG_HDR_SIZE + MAX_VAR_VALUE];

    loop {
        let poll = ((*syscalls).channel_poll)(var_chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }

        let (msg_type, payload_len) = msg_read(&*syscalls, var_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 && payload_len == 0 {
            break;
        }

        let vlen = (payload_len as usize).min(MAX_VAR_VALUE);

        let var_count = s.server.var_count as usize;
        let mut slot: usize = var_count;
        let mut j = 0usize;
        while j < var_count {
            if (*s.server.vars.as_ptr().add(j)).name_hash == msg_type {
                slot = j;
                break;
            }
            j += 1;
        }

        if slot >= MAX_VARS {
            continue;
        }

        let var = &mut *s.server.vars.as_mut_ptr().add(slot);
        var.name_hash = msg_type;
        var.value_len = vlen as u8;
        let mut k = 0;
        let buf_ptr = buf.as_ptr();
        while k < vlen {
            *var.value.as_mut_ptr().add(k) = *buf_ptr.add(k);
            k += 1;
        }

        if slot == var_count {
            s.server.var_count += 1;
        }
    }
}

unsafe fn lookup_var(s: &HttpState, hash: u32) -> (*const u8, usize) {
    let mut i = 0usize;
    while i < s.server.var_count as usize {
        let var = &*s.server.vars.as_ptr().add(i);
        if var.name_hash == hash {
            return (var.value.as_ptr(), var.value_len as usize);
        }
        i += 1;
    }
    (core::ptr::null(), 0)
}

// ── LRU content cache ──────────────────────────────────────────────────────

unsafe fn cache_lookup(s: &HttpState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

unsafe fn cache_evict_all(s: &mut HttpState) -> u16 {
    s.server.cache_count = 0;
    let mut inline_end: u16 = 0;
    let mut i = 0usize;
    while i < s.server.route_count as usize {
        let r = &*s.server.routes.as_ptr().add(i);
        if r.source_index < 0 && r.body_len > 0 {
            let end = r.body_offset + r.body_len;
            if end > inline_end {
                inline_end = end;
            }
        }
        i += 1;
    }
    inline_end
}

unsafe fn cache_alloc(s: &mut HttpState, route_idx: u8) -> usize {
    let arena_end: u16 = cache_evict_all(s);

    let idx = 0usize;
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(idx);
    e.route_index = route_idx;
    e.flags = CACHE_VALID;
    s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
    e.lru_tick = s.server.cache_tick;
    e.arena_offset = arena_end;
    e.length = 0;
    s.server.cache_count = 1;
    idx
}

// ── Phase-agnostic cache fetch (used by h2 dispatch) ──────────────────────

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum CacheLookup {
    /// Cache hit; `route.body_offset` / `route.body_len` now point at
    /// the cached arena region. Caller can render immediately.
    Hit,
    /// Cache miss; an `IOCTL_NOTIFY` has been queued on `file_chan`.
    /// Caller must run `cache_fetch_step` until it returns `Ready`.
    Pending,
    /// `file_chan` isn't wired or `source_index < 0` — caller should
    /// fall back to inline body if any.
    NoSource,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum CacheStepResult {
    Pending,
    Ready,
    Error,
}

/// h2-friendly entry point: try cache first, otherwise kick off a fetch.
/// Mirrors the h1 path in `step()::DispatchRoute` for HANDLER_STATIC /
/// HANDLER_TEMPLATE with `source_index >= 0`.
pub(crate) unsafe fn cache_try_or_fetch(s: &mut HttpState, route_idx: i8) -> CacheLookup {
    let r = &*s.server.routes.as_ptr().add(route_idx as usize);
    let src_idx = r.source_index;
    if src_idx < 0 || s.server.file_chan < 0 {
        return CacheLookup::NoSource;
    }
    let ci = cache_lookup(s, route_idx as u8);
    if ci >= 0 {
        let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
        s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
        ce.lru_tick = s.server.cache_tick;
        let r = &mut *s.server.routes.as_mut_ptr().add(route_idx as usize);
        r.body_offset = ce.arena_offset;
        r.body_len = ce.length;
        return CacheLookup::Hit;
    }
    let _slot = cache_alloc(s, route_idx as u8);
    dev_channel_ioctl(
        &*s.syscalls,
        s.server.file_chan,
        IOCTL_FLUSH,
        core::ptr::null_mut(),
    );
    let mut pos = src_idx as u32;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr);
    CacheLookup::Pending
}

/// Drive one tick of the cache fetch loop. Mirrors `Phase::CacheStream`
/// without touching `s.server.phase`. On `Ready`, the matched route's
/// `body_offset` / `body_len` are updated to point at the cached arena.
pub(crate) unsafe fn cache_fetch_step(s: &mut HttpState) -> CacheStepResult {
    if s.server.file_chan < 0 || s.server.cache_count == 0 {
        return CacheStepResult::Error;
    }
    let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let in_ready = poll > 0 && (poll as u32 & POLL_IN) != 0;
    let hup = poll > 0 && (poll as u32 & POLL_HUP) != 0;
    if !in_ready && !hup {
        return CacheStepResult::Pending;
    }

    let ce_idx = 0usize;
    let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ce_idx);
    let arena_off = ce.arena_offset as usize;
    let cur_len = ce.length as usize;
    let pool_cap = s.server.body_pool_cap as usize;
    let used = arena_off.saturating_add(cur_len);
    let space = pool_cap.saturating_sub(used);
    if space > 0 && !s.server.body_pool.is_null() && in_ready {
        let dst = s.server.body_pool.add(arena_off + cur_len);
        let to_read = space.min(SEND_BUF_SIZE);
        let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, to_read);
        if n > 0 {
            ce.length += n as u16;
        }
    }

    let new_len = ce.length as usize;
    let full = (arena_off + new_len) >= pool_cap;
    if hup || full {
        ce.flags |= CACHE_COMPLETE;
        let ri = s.server.matched_route as usize;
        let r = &mut *s.server.routes.as_mut_ptr().add(ri);
        r.body_offset = ce.arena_offset;
        r.body_len = ce.length;
        return CacheStepResult::Ready;
    }
    CacheStepResult::Pending
}

// ── Body renderers ────────────────────────────────────────────────────────
//
// Each renderer writes the next chunk of body bytes for the matched route
// into a caller-provided `[dst, dst+cap)` buffer and returns
// `(bytes_written, more_pending)`. They keep their position state in
// `ServerState` (`tmpl_pos` / `index_pos` / `file_chan`) so that successive
// calls advance through the body. h1's `step_send_*` helpers and h2's
// `Sub::SendingBody` substate share these renderers — h1 writes to
// `send_buf` at offset 0; h2 writes at offset `FRAME_HEADER_LEN` so it can
// backfill an h2 DATA frame header.

/// Walk inline static body bytes from `body_pool`. `tmpl_pos` is the
/// offset within the route body (0 = start).
pub(crate) unsafe fn render_static_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let route = &*s.server.routes.as_ptr().add(s.server.matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + s.server.tmpl_pos as usize;
    if pos >= body_end || cap == 0 {
        return (0, pos < body_end);
    }
    let n = (body_end - pos).min(cap);
    let src = (s.server.body_pool as *const u8).add(pos);
    core::ptr::copy_nonoverlapping(src, dst, n);
    s.server.tmpl_pos += n as u16;
    let more = (pos + n) < body_end;
    (n, more)
}

/// Render a template body chunk with `{{var}}` substitution into `dst`.
pub(crate) unsafe fn render_template_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let route = &*s.server.routes.as_ptr().add(s.server.matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pool = s.server.body_pool as *const u8;
    let mut out = 0usize;
    let mut pos = body_start + s.server.tmpl_pos as usize;

    while pos < body_end && out < cap {
        if pos + 1 < body_end && *pool.add(pos) == b'{' && *pool.add(pos + 1) == b'{' {
            // Look the variable up first so the headroom check uses
            // its actual width rather than the worst-case bound — a
            // tight `cap` (e.g. send_window-capped) can still emit a
            // small value that wouldn't have cleared `MAX_VAR_VALUE`.
            let saved_pos = pos;
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
            if pos + 1 < body_end {
                pos += 2;
            }

            let (val_ptr, val_len) = lookup_var(s, hash);
            let emit_len = if val_ptr.is_null() { 0 } else { val_len };
            if out + emit_len > cap {
                // Defer the whole substitution to the next call —
                // rewinding to `{{` keeps us atomic so the caller
                // never sees a half-expanded value.
                pos = saved_pos;
                break;
            }
            if !val_ptr.is_null() {
                let mut vi = 0;
                while vi < val_len {
                    *dst.add(out) = *val_ptr.add(vi);
                    out += 1;
                    vi += 1;
                }
            }
        } else {
            *dst.add(out) = *pool.add(pos);
            out += 1;
            pos += 1;
        }
    }

    s.server.tmpl_pos = (pos - body_start) as u16;
    (out, pos < body_end)
}

/// Pull the next chunk of file bytes from `file_chan`. Returns
/// `(0, true)` when no data is available yet but the channel hasn't
/// hung up — callers should yield and retry. Returns `(0, false)` once
/// HUP is observed with no payload.
pub(crate) unsafe fn render_file_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    if s.server.file_chan < 0 {
        return (0, false);
    }
    let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, cap);
    if n > 0 {
        return (n as usize, true);
    }
    let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let hup = poll > 0 && (poll as u32 & POLL_HUP) != 0;
    (0, !hup)
}

/// Render the directory-index listing (decimal indices, one per line)
/// from `index_pos` up to `file_count`.
pub(crate) unsafe fn render_index_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let mut off = 0usize;
    let mut idx = s.server.index_pos;
    while idx < s.server.file_count && off + 7 < cap {
        off += fmt_u32_raw(dst.add(off), idx as u32);
        *dst.add(off) = b'\n';
        off += 1;
        idx += 1;
    }
    s.server.index_pos = idx;
    (off, idx < s.server.file_count)
}

/// h1 template wrapper — writes a chunk into `send_buf` and updates
/// `send_offset`/`send_len` so the existing `step_send_template` flow
/// can flush it.
unsafe fn render_template_chunk(s: &mut HttpState) -> bool {
    let buf = s.server.send_buf.as_mut_ptr();
    let (n, more) = render_template_into(s, buf, SEND_BUF_SIZE);
    s.server.send_offset = 0;
    s.server.send_len = n as u16;
    more
}

// ── Legacy file mode helpers ──────────────────────────────────────────────

pub(crate) unsafe fn parse_file_index(s: &HttpState) -> i16 {
    let buf = s.server.req_path.as_ptr();
    let route = &*s.server.routes.as_ptr().add(s.server.matched_route as usize);
    let suffix_start = route.path_len as usize;
    let path_end = s.server.req_path_len as usize;

    if suffix_start >= path_end {
        return -1;
    }
    let mut pos = suffix_start;
    if *buf.add(pos) == b'/' {
        pos += 1;
    }
    if pos >= path_end {
        return -1;
    }

    let mut idx: i32 = 0;
    while pos < path_end {
        let c = *buf.add(pos);
        if c < b'0' || c > b'9' {
            return -2;
        }
        idx = idx * 10 + (c - b'0') as i32;
        if idx > 0x7FFF {
            return -2;
        }
        pos += 1;
    }
    idx as i16
}

unsafe fn step_legacy_file_dispatch(s: &mut HttpState) {
    let buf = s.server.req_path.as_ptr();
    let plen = s.server.req_path_len as usize;

    if plen == 1 && *buf == b'/' {
        if s.server.file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr);
            if r >= 0 {
                s.server.file_count = count as u16;
            }
        }
        build_header(s, b"200 OK", b"text/plain");
        s.server.index_pos = 0;
        s.server.file_index = -1;
        s.server.matched_route = -1;
        s.server.phase = Phase::SendHeaders;
    } else if plen >= 2 && *buf == b'/' {
        let mut idx: i32 = 0;
        let mut i = 1usize;
        let mut valid = true;
        while i < plen {
            let c = *buf.add(i);
            if c < b'0' || c > b'9' {
                valid = false;
                break;
            }
            idx = idx * 10 + (c - b'0') as i32;
            if idx > 0x7FFF {
                valid = false;
                break;
            }
            i += 1;
        }
        if !valid {
            build_error(s, b"400 Bad Request", b"Bad Request\n");
            s.server.phase = Phase::DrainSend;
            return;
        }

        s.server.file_index = idx as i16;
        s.server.matched_route = -1;
        if s.server.file_chan >= 0 {
            dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_FLUSH, core::ptr::null_mut());
            let mut pos = idx as u32;
            let pos_ptr = &mut pos as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr);
            if r < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                s.server.phase = Phase::DrainSend;
                return;
            }
            build_header(s, b"200 OK", b"application/octet-stream");
        } else {
            build_error(s, b"404 Not Found", b"Not Found\n");
            s.server.phase = Phase::DrainSend;
            return;
        }
        s.server.phase = Phase::SendHeaders;
    } else {
        build_error(s, b"400 Bad Request", b"Bad Request\n");
        s.server.phase = Phase::DrainSend;
    }
}

// ── WebSocket dispatch ────────────────────────────────────────────────────

/// Try to upgrade the just-parsed HTTP request into a WebSocket
/// connection. Validates the required headers, computes the accept
/// value, and queues the 101 response into `send_buf`. Returns `true`
/// if the upgrade is in progress (caller should transition to
/// `WsHandshake`); `false` if the request is malformed (caller has
/// already populated `send_buf` with the appropriate error response and
/// transitioned to `DrainSend`).
unsafe fn begin_ws_upgrade(s: &mut HttpState) -> bool {
    let buf = s.server.recv_buf.as_ptr();
    let len = s.server.recv_len as usize;

    let upgrade = ws::find_header_value(buf, len, b"Upgrade");
    let connection = ws::find_header_value(buf, len, b"Connection");
    let key = ws::find_header_value(buf, len, b"Sec-WebSocket-Key");
    let version = ws::find_header_value(buf, len, b"Sec-WebSocket-Version");

    let upgrade_ok = match upgrade {
        Some((off, n)) => ws::header_value_contains_token(buf, off, n, b"websocket"),
        None => false,
    };
    let connection_ok = match connection {
        Some((off, n)) => ws::header_value_contains_token(buf, off, n, b"upgrade"),
        None => false,
    };
    let version_ok = match version {
        Some((off, n)) => n == 2 && *buf.add(off) == b'1' && *buf.add(off + 1) == b'3',
        None => false,
    };

    let (key_off, key_len) = match key {
        Some(v) if upgrade_ok && connection_ok && version_ok => v,
        _ => {
            build_error(s, b"400 Bad Request", b"Bad Request\n");
            s.server.phase = Phase::DrainSend;
            return false;
        }
    };

    let mut accept = [0u8; 28];
    ws::compute_accept(buf.add(key_off), key_len, accept.as_mut_ptr());

    let written = ws::write_handshake_response(
        s.server.send_buf.as_mut_ptr(),
        SEND_BUF_SIZE,
        accept.as_ptr(),
    );
    s.server.send_offset = 0;
    s.server.send_len = written as u16;
    s.server.recv_len = 0;
    s.server.recv_parsed = 0;
    true
}

/// Build an unmasked server-to-client WebSocket frame in `send_buf`.
unsafe fn ws_queue_frame(s: &mut HttpState, opcode: u8, payload: *const u8, payload_len: usize) {
    let written = ws::write_frame(
        s.server.send_buf.as_mut_ptr(),
        SEND_BUF_SIZE,
        true,
        opcode,
        payload,
        payload_len,
    );
    s.server.send_offset = 0;
    s.server.send_len = written as u16;
}

/// Build a CLOSE frame carrying `code` (network-byte-order u16) and
/// transition to the close-flush phase.
unsafe fn ws_begin_close(s: &mut HttpState, code: u16) {
    let payload = [(code >> 8) as u8, (code & 0xFF) as u8];
    ws_queue_frame(s, ws::OP_CLOSE, payload.as_ptr(), 2);
    s.server.phase = Phase::WsClose;
}

/// Process WebSocket frames buffered in `recv_buf`. Returns `true` if a
/// frame was processed (caller should re-enter the step loop), `false`
/// if more data is needed.
unsafe fn ws_process_inbound(s: &mut HttpState) -> bool {
    let buf_ptr = s.server.recv_buf.as_mut_ptr();
    let len = s.server.recv_len as usize;

    let frame = match ws::parse_frame(buf_ptr, len) {
        Ok(Some(f)) => f,
        Ok(None) => return false,
        Err(()) => {
            ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return true;
        }
    };

    let total = frame.header_len as usize + frame.payload_len as usize;
    if total > RECV_BUF_SIZE {
        // Frame won't fit in our receive buffer; close cleanly with
        // 1009 (Message Too Big) rather than reading partial data we
        // can't act on.
        ws_begin_close(s, ws::CLOSE_MESSAGE_TOO_BIG);
        return true;
    }
    if len < total {
        return false;
    }

    // Per RFC 6455 §5.3, every client→server frame must be masked.
    if !frame.masked {
        ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
        return true;
    }

    let payload_ptr = buf_ptr.add(frame.header_len as usize);
    ws::unmask(payload_ptr, frame.payload_len, &frame.mask_key);

    match frame.opcode {
        ws::OP_CLOSE => {
            // Echo the peer's close payload (or send a bare close if
            // they sent an empty body).
            let pl = frame.payload_len as usize;
            ws_queue_frame(s, ws::OP_CLOSE, payload_ptr, pl);
            s.server.phase = Phase::WsClose;
        }
        ws::OP_PING => {
            ws_queue_frame(s, ws::OP_PONG, payload_ptr, frame.payload_len as usize);
        }
        ws::OP_PONG => {
            // Unsolicited pongs are valid keep-alives — drop silently.
        }
        ws::OP_TEXT | ws::OP_BINARY | ws::OP_CONTINUATION => {
            // Echo: send back as the same data opcode. Continuation
            // frames keep the original opcode the peer chose; the echo
            // pattern doesn't need to track fragmented messages because
            // we mirror them frame-for-frame.
            let echo_op = if frame.opcode == ws::OP_CONTINUATION {
                ws::OP_CONTINUATION
            } else {
                frame.opcode
            };
            ws_queue_frame(s, echo_op, payload_ptr, frame.payload_len as usize);
        }
        _ => {
            ws_begin_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return true;
        }
    }

    // Shift any bytes after this frame to the start of the buffer.
    let consumed = total;
    let leftover = len - consumed;
    if leftover > 0 {
        let mut i = 0;
        while i < leftover {
            *buf_ptr.add(i) = *buf_ptr.add(consumed + i);
            i += 1;
        }
    }
    s.server.recv_len = leftover as u16;
    true
}

// ── Outbound data send (CMD_SEND envelope) ────────────────────────────────

/// Send up to `len` bytes of HTTP payload to the IP module wrapped in a
/// CMD_SEND frame. Returns the number of payload bytes actually
/// accepted (0 if the channel is full).
unsafe fn net_send(s: &mut HttpState, data: *const u8, len: usize) -> i32 {
    if s.net_out_chan < 0 {
        return 0;
    }
    let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    let to_send = len.min(max_data);
    if to_send == 0 {
        return 0;
    }

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let conn_id = s.server.conn_id;
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 1 + to_send;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(3) = conn_id;
    core::ptr::copy_nonoverlapping(data, scratch.add(4), to_send);
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written >= total as i32 {
        to_send as i32
    } else {
        0
    }
}

// ── Body-send phase helpers ───────────────────────────────────────────────

unsafe fn step_send_static(s: &mut HttpState) -> i32 {
    let route = &*s.server.routes.as_ptr().add(s.server.matched_route as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + s.server.tmpl_pos as usize;

    if pos >= body_end {
        s.server.phase = Phase::CloseConn;
        return 0;
    }

    let remaining = body_end - pos;
    let to_send = remaining.min(SEND_BUF_SIZE);
    let ptr = (s.server.body_pool as *const u8).add(pos);
    let sent = net_send(s, ptr, to_send);
    if sent > 0 {
        s.server.tmpl_pos += sent as u16;
        return 2;
    }
    0
}

unsafe fn step_send_template(s: &mut HttpState) -> i32 {
    if s.server.send_offset < s.server.send_len {
        let remaining = (s.server.send_len - s.server.send_offset) as usize;
        let ptr = s.server.send_buf.as_ptr().add(s.server.send_offset as usize);
        let sent = net_send(s, ptr, remaining);
        if sent > 0 {
            s.server.send_offset += sent as u16;
        }
        return 0;
    }

    let has_more = render_template_chunk(s);
    if s.server.send_len > 0 {
        let ptr = s.server.send_buf.as_ptr();
        let sent = net_send(s, ptr, s.server.send_len as usize);
        if sent > 0 {
            s.server.send_offset = sent as u16;
        }
        return if has_more { 2 } else { 0 };
    }

    if !has_more {
        s.server.phase = Phase::CloseConn;
    }
    0
}

unsafe fn step_send_index(s: &mut HttpState) -> i32 {
    if s.server.index_pos >= s.server.file_count {
        s.server.phase = Phase::CloseConn;
        return 0;
    }

    if s.server.send_offset >= s.server.send_len {
        let buf = s.server.send_buf.as_mut_ptr();
        let mut off = 0usize;
        let mut idx = s.server.index_pos;
        while idx < s.server.file_count && off + 6 < SEND_BUF_SIZE {
            off += fmt_u32_raw(buf.add(off), idx as u32);
            *buf.add(off) = b'\n';
            off += 1;
            idx += 1;
        }
        s.server.send_offset = 0;
        s.server.send_len = off as u16;
        s.server.index_pos = idx;
    }

    let remaining = (s.server.send_len - s.server.send_offset) as usize;
    let ptr = s.server.send_buf.as_ptr().add(s.server.send_offset as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        s.server.send_offset += sent as u16;
        return 2;
    }
    0
}

unsafe fn step_send_file(s: &mut HttpState) -> i32 {
    if s.server.send_offset >= s.server.send_len {
        let n = ((*s.syscalls).channel_read)(
            s.server.file_chan,
            s.server.send_buf.as_mut_ptr(),
            SEND_BUF_SIZE,
        );
        if n > 0 {
            s.server.send_offset = 0;
            s.server.send_len = n as u16;
        } else {
            let chan_poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if chan_poll > 0 && (chan_poll as u32 & POLL_HUP) != 0 {
                s.server.phase = Phase::CloseConn;
            }
            return 0;
        }
    }

    let remaining = (s.server.send_len - s.server.send_offset) as usize;
    let ptr = s.server.send_buf.as_ptr().add(s.server.send_offset as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        s.server.send_offset += sent as u16;
        return 2;
    }
    0
}

// ── Per-tick step machine ──────────────────────────────────────────────────

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    drain_variables(s);

    match s.server.phase {
        Phase::Init | Phase::Binding => {
            if s.net_out_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_out_chan;
            let buf = s.net_buf.as_mut_ptr();
            let mut payload = [0u8; 2];
            payload[0] = (s.server.port & 0xFF) as u8;
            payload[1] = (s.server.port >> 8) as u8;
            let wrote = net_write_frame(sys, chan, NET_CMD_BIND, payload.as_ptr(), 2, buf, NET_BUF_SIZE);
            if wrote == 0 {
                return 0;
            }
            s.server.phase = Phase::WaitBound;
            return 2;
        }

        Phase::WaitBound => {
            if s.net_in_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_in_chan;
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return 0;
            }

            let buf = s.net_buf.as_mut_ptr();
            let (msg_type, _payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
            if msg_type == NET_MSG_BOUND {
                log(s, b"[http] bound, waiting for connections");
                s.server.phase = Phase::WaitAccept;
                return 2;
            } else if msg_type == NET_MSG_ERROR {
                s.server.phase = Phase::Error;
                return -1;
            }
        }

        Phase::WaitAccept => {
            if s.server.draining != 0 {
                return 1;
            }
            if s.net_in_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_in_chan;
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return 0;
            }

            let buf = s.net_buf.as_mut_ptr();
            let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
            if msg_type == NET_MSG_ACCEPTED && payload_len >= 1 {
                s.server.conn_id = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                s.server.recv_len = 0;
                s.server.recv_parsed = 0;
                s.server.phase = Phase::RecvRequest;
            }
        }

        Phase::RecvRequest => {
            if s.net_in_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_in_chan;
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return 0;
            }

            let buf = s.net_buf.as_mut_ptr();
            let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);

            if msg_type == NET_MSG_CLOSED {
                s.server.phase = Phase::CloseConn;
                return 0;
            }

            if msg_type == NET_MSG_DATA && payload_len > 1 {
                let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let data_len = payload_len - 1;

                let space = RECV_BUF_SIZE - s.server.recv_len as usize;
                let to_copy = data_len.min(space);
                if to_copy > 0 {
                    let dst = s.server.recv_buf.as_mut_ptr().add(s.server.recv_len as usize);
                    core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                    s.server.recv_len += to_copy as u16;
                }
            } else {
                return 0;
            }

            let len = s.server.recv_len as usize;

            // Detect the HTTP/2 cleartext (h2c) preface — 24 bytes
            // beginning with `PRI`. We check before the h1 request
            // parse so a misdirected h1 client doesn't accidentally
            // hit the same path. The preface is a fixed string; first
            // few bytes are sufficient to disambiguate.
            if s.server.recv_parsed == 0 && len >= 1 && *s.server.recv_buf.as_ptr() == b'P' {
                if len < wire_h2::PREFACE.len() {
                    return 0; // wait for the rest of the preface
                }
                let mut prefix_match = true;
                let mut i = 0;
                while i < wire_h2::PREFACE.len() {
                    if s.server.recv_buf[i] != wire_h2::PREFACE[i] {
                        prefix_match = false;
                        break;
                    }
                    i += 1;
                }
                if prefix_match {
                    // Drop the preface from recv_buf and hand off to
                    // the h2 state machine. Any frames that arrived in
                    // the same MSG_DATA stay queued for it to consume.
                    let pre = wire_h2::PREFACE.len();
                    let leftover = len - pre;
                    let p = s.server.recv_buf.as_mut_ptr();
                    let mut j = 0;
                    while j < leftover {
                        *p.add(j) = *p.add(pre + j);
                        j += 1;
                    }
                    s.server.recv_len = leftover as u16;
                    s.server.recv_parsed = 0;
                    s.server.phase = Phase::H2Active;
                    h2::enter(s);
                    return 2;
                }
                // Not the preface; fall through to h1 parsing.
            }

            if s.server.recv_parsed == 0 {
                let ptr = s.server.recv_buf.as_ptr();
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
                    let plen = h1::parse_request_line(
                        s.server.recv_buf.as_ptr(),
                        s.server.recv_len as usize,
                        s.server.req_path.as_mut_ptr(),
                        MAX_PATH,
                    );
                    match plen {
                        Some(n) => {
                            s.server.req_path_len = n as u8;
                            s.server.recv_parsed = 1;
                        }
                        None => {
                            build_error(s, b"400 Bad Request", b"Bad Request\n");
                            s.server.phase = Phase::DrainSend;
                            return 0;
                        }
                    }
                } else if s.server.recv_len as usize >= RECV_BUF_SIZE {
                    build_error(s, b"400 Bad Request", b"Bad Request\n");
                    s.server.phase = Phase::DrainSend;
                    return 0;
                }
            }

            if s.server.recv_parsed == 1 {
                let ptr = s.server.recv_buf.as_ptr();
                let scan_len = s.server.recv_len as usize;
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
                    s.server.phase = Phase::DispatchRoute;
                    return 2;
                } else if s.server.recv_len as usize >= RECV_BUF_SIZE {
                    let l = s.server.recv_len as usize;
                    if l >= 3 {
                        let p = s.server.recv_buf.as_mut_ptr();
                        *p = *p.add(l - 3);
                        *p.add(1) = *p.add(l - 2);
                        *p.add(2) = *p.add(l - 1);
                        s.server.recv_len = 3;
                    }
                }
            }
        }

        Phase::DispatchRoute => {
            if s.server.legacy_mode == 2 {
                step_legacy_file_dispatch(s);
                return 0;
            }

            // Diagnostic endpoint `/_fan` — calls the kernel
            // `FAN_DIAG_SNAPSHOT` opcode and serves the resulting ASCII
            // line (fan-out / fan-in pump counters + log_ring state).
            // Available on every http instance without route configuration.
            let req = s.server.req_path.as_ptr();
            let plen = s.server.req_path_len as usize;
            if plen >= 5
                && *req == b'/' && *req.add(1) == b'_'
                && *req.add(2) == b'f' && *req.add(3) == b'a' && *req.add(4) == b'n'
            {
                let buf = s.server.send_buf.as_mut_ptr();
                let cap = SEND_BUF_SIZE;
                let mut off = 0usize;
                let header = b"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n";
                let mut k = 0;
                while k < header.len() && off < cap {
                    *buf.add(off) = header[k];
                    off += 1;
                    k += 1;
                }
                let room = cap.saturating_sub(off);
                let n = ((*s.syscalls).provider_call)(-1, 0x0C65, buf.add(off), room);
                if n > 0 {
                    off += n as usize;
                }
                s.server.send_offset = 0;
                s.server.send_len = off as u16;
                s.server.phase = Phase::DrainSend;
                return 0;
            }

            let ri = match_route(s);
            if ri < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                s.server.phase = Phase::DrainSend;
                return 0;
            }
            s.server.matched_route = ri;
            let route = &*s.server.routes.as_ptr().add(ri as usize);
            let handler = route.handler;
            let src_idx = route.source_index;

            match handler {
                HANDLER_STATIC | HANDLER_TEMPLATE => {
                    if src_idx >= 0 && s.server.file_chan >= 0 {
                        let ci = cache_lookup(s, ri as u8);
                        if ci >= 0 {
                            let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
                            s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
                            ce.lru_tick = s.server.cache_tick;
                            let r = &mut *s.server.routes.as_mut_ptr().add(ri as usize);
                            r.body_offset = ce.arena_offset;
                            r.body_len = ce.length;
                            build_header(s, b"200 OK", b"text/html");
                            s.server.tmpl_pos = 0;
                            s.server.phase = Phase::SendHeaders;
                        } else {
                            let _slot = cache_alloc(s, ri as u8);
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                            );
                            let mut pos = src_idx as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr);
                            s.server.phase = Phase::FetchContent;
                        }
                    } else {
                        build_header(s, b"200 OK", b"text/html");
                        s.server.tmpl_pos = 0;
                        s.server.phase = Phase::SendHeaders;
                    }
                }
                HANDLER_FILE => {
                    let fi = parse_file_index(s);
                    s.server.file_index = fi;
                    if fi == -1 {
                        if s.server.file_chan >= 0 {
                            let mut count: u32 = 0;
                            let count_ptr = &mut count as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_POLL_NOTIFY,
                                count_ptr,
                            );
                            if r >= 0 {
                                s.server.file_count = count as u16;
                            }
                        }
                        build_header(s, b"200 OK", b"text/plain");
                        s.server.index_pos = 0;
                        s.server.phase = Phase::SendHeaders;
                    } else if fi >= 0 {
                        if s.server.file_chan >= 0 {
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                            );
                            let mut pos = fi as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_NOTIFY,
                                pos_ptr,
                            );
                            if r < 0 {
                                build_error(s, b"404 Not Found", b"Not Found\n");
                                s.server.phase = Phase::DrainSend;
                                return 0;
                            }
                            build_header(s, b"200 OK", b"application/octet-stream");
                        } else {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            s.server.phase = Phase::DrainSend;
                            return 0;
                        }
                        s.server.phase = Phase::SendHeaders;
                    } else {
                        build_error(s, b"400 Bad Request", b"Bad Request\n");
                        s.server.phase = Phase::DrainSend;
                        return 0;
                    }
                }
                HANDLER_PROXY => {
                    build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
                    s.server.phase = Phase::DrainSend;
                }
                HANDLER_WEBSOCKET => {
                    if begin_ws_upgrade(s) {
                        s.server.phase = Phase::WsHandshake;
                    }
                    // begin_ws_upgrade has already populated send_buf
                    // and switched phase on the failure path.
                }
                _ => {
                    build_error(s, b"500 Internal Server Error", b"Unknown handler\n");
                    s.server.phase = Phase::DrainSend;
                }
            }
        }

        Phase::SendHeaders => {
            let remaining = (s.server.send_len - s.server.send_offset) as usize;
            if remaining == 0 {
                let handler = if s.server.matched_route >= 0 {
                    (*s.server.routes.as_ptr().add(s.server.matched_route as usize)).handler
                } else {
                    HANDLER_FILE
                };

                match handler {
                    HANDLER_STATIC | HANDLER_TEMPLATE | HANDLER_FILE => {
                        s.server.phase = Phase::SendBody;
                    }
                    _ => {
                        s.server.phase = Phase::CloseConn;
                    }
                }
                return 2;
            }
            let sent = net_send(
                s,
                s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
                remaining,
            );
            if sent > 0 {
                s.server.send_offset += sent as u16;
            }
        }

        Phase::SendBody => {
            let handler = if s.server.matched_route >= 0 {
                (*s.server.routes.as_ptr().add(s.server.matched_route as usize)).handler
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
                    if s.server.file_index < 0 {
                        return step_send_index(s);
                    } else {
                        return step_send_file(s);
                    }
                }
                _ => {
                    s.server.phase = Phase::CloseConn;
                }
            }
        }

        Phase::DrainSend => {
            let remaining = (s.server.send_len - s.server.send_offset) as usize;
            if remaining == 0 {
                s.server.phase = Phase::CloseConn;
                return 0;
            }
            let sent = net_send(
                s,
                s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
                remaining,
            );
            if sent > 0 {
                s.server.send_offset += sent as u16;
            }
        }

        Phase::FetchContent => {
            if s.server.file_chan < 0 {
                build_error(s, b"500 Internal Server Error", b"No content source\n");
                s.server.phase = Phase::DrainSend;
                return 0;
            }
            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if poll > 0 && ((poll as u32 & POLL_IN) != 0 || (poll as u32 & POLL_HUP) != 0) {
                s.server.phase = Phase::CacheStream;
                return 2;
            }
        }

        Phase::CacheStream => {
            if s.server.cache_count == 0 || s.server.file_chan < 0 {
                s.server.phase = Phase::CloseConn;
                return 0;
            }
            let ce_idx = 0usize;
            let ce = &mut *s.server.cache_entries.as_mut_ptr().add(ce_idx);
            let arena_off = ce.arena_offset as usize;
            let cur_len = ce.length as usize;
            let pool_cap = s.server.body_pool_cap as usize;

            let space = pool_cap - (arena_off + cur_len);
            if space > 0 && !s.server.body_pool.is_null() {
                let dst = s.server.body_pool.add(arena_off + cur_len);
                let to_read = space.min(SEND_BUF_SIZE);
                let n = ((*s.syscalls).channel_read)(s.server.file_chan, dst, to_read);
                if n > 0 {
                    ce.length += n as u16;
                }
            }

            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            let eof = poll > 0
                && (poll as u32 & POLL_HUP) != 0
                && (poll <= 0 || (poll as u32 & POLL_IN) == 0);
            let full = (arena_off + ce.length as usize) >= pool_cap;

            if eof || full {
                ce.flags |= CACHE_COMPLETE;
                let ri = s.server.matched_route as usize;
                let r = &mut *s.server.routes.as_mut_ptr().add(ri);
                r.body_offset = ce.arena_offset;
                r.body_len = ce.length;
                build_header(s, b"200 OK", b"text/html");
                s.server.tmpl_pos = 0;
                s.server.phase = Phase::SendHeaders;
                return 2;
            }

            return 2;
        }

        Phase::CloseConn => {
            reset_connection(s);
            if s.server.draining != 0 {
                return 1;
            }
        }

        Phase::ProxyConnect
        | Phase::ProxyWaitConnect
        | Phase::ProxySendRequest
        | Phase::ProxyRelayHeaders
        | Phase::ProxyRelayBody => {
            build_error(s, b"502 Bad Gateway", b"Proxy not implemented\n");
            s.server.phase = Phase::DrainSend;
        }

        Phase::WsHandshake => {
            let remaining = (s.server.send_len - s.server.send_offset) as usize;
            if remaining == 0 {
                log(s, b"[http] websocket upgraded");
                s.server.send_offset = 0;
                s.server.send_len = 0;
                s.server.phase = Phase::WsActive;
                return 2;
            }
            let sent = net_send(
                s,
                s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
                remaining,
            );
            if sent > 0 {
                s.server.send_offset += sent as u16;
            }
        }

        Phase::WsActive => {
            // Flush any pending outbound frame first; readers may emit
            // data faster than the network can drain.
            if s.server.send_len > 0 && s.server.send_offset < s.server.send_len {
                let remaining = (s.server.send_len - s.server.send_offset) as usize;
                let sent = net_send(
                    s,
                    s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
                    remaining,
                );
                if sent > 0 {
                    s.server.send_offset += sent as u16;
                }
                if s.server.send_offset >= s.server.send_len {
                    s.server.send_offset = 0;
                    s.server.send_len = 0;
                }
                return 2;
            }

            // No pending output — try to drive a frame out of recv_buf.
            if ws_process_inbound(s) {
                return 2;
            }

            // No complete frame buffered yet. Pull more bytes from the
            // network if available.
            if s.net_in_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_in_chan;
            let poll = (sys.channel_poll)(chan, POLL_IN);
            if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                return 0;
            }
            let buf = s.net_buf.as_mut_ptr();
            let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
            if msg_type == NET_MSG_CLOSED {
                s.server.phase = Phase::CloseConn;
                return 0;
            }
            if msg_type == NET_MSG_DATA && payload_len > 1 {
                let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let data_len = payload_len - 1;
                let space = RECV_BUF_SIZE - s.server.recv_len as usize;
                let to_copy = data_len.min(space);
                if to_copy > 0 {
                    let dst = s.server.recv_buf.as_mut_ptr().add(s.server.recv_len as usize);
                    core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                    s.server.recv_len += to_copy as u16;
                }
                if data_len > to_copy {
                    // The frame won't fit even after this read — close.
                    ws_begin_close(s, ws::CLOSE_MESSAGE_TOO_BIG);
                }
            }
        }

        Phase::WsClose => {
            let remaining = (s.server.send_len - s.server.send_offset) as usize;
            if remaining == 0 {
                s.server.phase = Phase::CloseConn;
                return 0;
            }
            let sent = net_send(
                s,
                s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
                remaining,
            );
            if sent > 0 {
                s.server.send_offset += sent as u16;
            }
        }

        Phase::H2Active => {
            let r = h2::step(s);
            if r == 1 {
                s.server.phase = Phase::CloseConn;
                return 0;
            }
            return r;
        }

        Phase::Error => {
            return 1;
        }
    }

    0
}

// ── Param-time setter helpers (called from mod.rs::params_def) ────────────

#[inline]
pub(crate) unsafe fn set_route_handler(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).handler = p_u8(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn set_route_proxy_ip(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).proxy_ip = p_u32(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn set_route_proxy_port(
    s: &mut HttpState,
    idx: usize,
    d: *const u8,
    len: usize,
) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).proxy_port = p_u16(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn set_route_source(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).source_index =
            p_u16(d, len, 0, 0xFFFF) as i16;
    }
}
