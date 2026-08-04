//! HTTP server — accepts connections, routes requests, serves static
//! content / templates / files / proxy responses.
//!
//! State, route definitions, content cache, and the per-tick step
//! machine all live here. Pure-byte parse and build helpers come from
//! `super::wire::h1`; framing constants come from `super::connection`;
//! shared utilities come from `super::core`.

use super::abi::SyscallTable;
use super::connection::{
    NET_BUF_SIZE, NET_CMD_BIND, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND, NET_MSG_ACCEPTED,
    NET_MSG_BOUND, NET_MSG_CLOSED, NET_MSG_CONNECTED, NET_MSG_DATA, NET_MSG_ERROR,
    NET_MSG_TRACE_CTX,
};
#[cfg(feature = "h2")]
use super::h2;
use super::wire_h1 as h1;
#[cfg(feature = "h2")]
use super::wire_h2;
use super::wire_ws as ws;
use super::HttpState;
use super::{
    dev_channel_ioctl, dev_channel_port, dev_csprng_fill, dev_log, dev_micros, dev_millis,
    dev_owner_tag, dev_requester_tag, dev_self_index, dev_telemetry_enabled, dev_telemetry_span,
    fmt_u32_raw, heap_alloc, heap_free, heap_realloc, msg_read, net_read_frame, net_write_frame,
    p_u16, p_u32, p_u8, IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY, MSG_HDR_SIZE, NET_FRAME_HDR,
    POLL_HUP, POLL_IN, POLL_OUT, SOCK_TYPE_STREAM,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────
//
// All cross-cutting capacity tunables live in `abi::config::http`,
// `abi::config::kernel`, etc. Per-board profiles. See
// `modules/sdk/config.rs` for the full envelope.

pub(crate) use super::abi::config::http::{
    ARENA_WORKING_SET_CONNS, DEFAULT_BODY_POOL_SIZE, MAX_CACHE, MAX_CONCURRENT_CONNS,
    MAX_CONTENT_TYPE, MAX_DYN_ROUTES, MAX_FS_PATH, MAX_PATH, MAX_ROUTES, MAX_ROUTE_BACKENDS,
    MAX_VARS, MAX_VAR_VALUE, RECV_BUF_SIZE, SEND_BUF_SIZE,
};

// Dynamic-route table consumer (rfc_dynamic_routes §2/§3.2). The
// `DynRoute` arena is populated at runtime from the `/dataplane/edge/`
// prefix via the shared table_consumer state machine — the reusable
// `cores/table_consumer` core, `include!`d here (it is an implementation,
// not a wire contract; see the file header). `SyscallTable` is brought
// into scope for the include per the core's includer contract.
mod table_consumer {
    use super::super::abi::SyscallTable;
    include!("../../sdk/cores/table_consumer.rs");
}
use table_consumer::{TableConsumer, TableSink};

/// Decode one hex digit (`0-9a-fA-F`) for percent-unescaping request
/// paths. Returns `None` for non-hex bytes.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ── Retention buffer sizing ───────────────────────────────────────────────

/// Server-wide retention buffer capacity. Sized for one decoded
/// 800×480 RGB565 frame (~750 KiB) plus headroom for envelope
/// headers and a small margin; multi-MiB images won't fit and will
/// reset capture mid-stream — that's fine for the demo (single
/// fan-out producer + browser size cap), and the value can grow on
/// large-host profiles when a richer use case lands.
const RETAINED_BUF_CAP: usize = 2 * 1024 * 1024;
/// Per-envelope header in `retained_buf`:
/// `[opcode:u8][fin:u8][payload_len:u16 LE]`.
const RETAINED_ENVELOPE_HDR: usize = 4;
/// Ticks of `module_step` quiescence on `ws_in` before the next
/// captured envelope wipes the buffer and starts fresh. At a typical
/// 100µs tick the threshold is ~50 ms — much longer than the gap
/// between chunks of one decoded frame, much shorter than any
/// reasonable producer-side state change.
const RETAIN_RESET_TICKS: u16 = 500;

// ── Route handler kinds (stored in Route.handler) ─────────────────────────

pub(crate) const HANDLER_STATIC: u8 = 0;
pub(crate) const HANDLER_TEMPLATE: u8 = 1;
pub(crate) const HANDLER_FILE: u8 = 2;
pub(crate) const HANDLER_PROXY: u8 = 3;
pub(crate) const HANDLER_WEBSOCKET: u8 = 4;
/// Like `HANDLER_WEBSOCKET` (101 upgrade and full RFC 6455 framing), but
/// instead of echoing data frames internally, route them to the module's
/// `ws_out` port as `WsFrame` records and queue outbound frames from the
/// `ws_in` port. Lets a downstream module own application-level WS
/// semantics (chat, command stream, raster bridge, …) while this module
/// keeps owning HTTP and the WS protocol envelope.
pub(crate) const HANDLER_WEBSOCKET_FANOUT: u8 = 5;
/// Like `HANDLER_FILE` but with a config-time fixed `source_index`
/// instead of one parsed from the URL. Streams the asset's bytes
/// straight through `send_buf` without staging them in `body_pool`,
/// so multi-MiB payloads (WASM bundles, large media) aren't capped
/// by the body-pool size. Used for routes declared with
/// `source: <port>` + `source_index: N` + `stream: true` in YAML.
pub(crate) const HANDLER_STREAM: u8 = 6;
/// Serve a file by path through the FS_CONTRACT provider (fat32 on
/// bare-metal, linux_fs_dispatch on the host). The route declares an
/// absolute `fs_path:` and the http module opens it via
/// `provider_call(-1, FS_OPEN, …)`, queries `FS_STAT` for the
/// Content-Length, then streams the body via `FS_READ` chunks
/// directly into `send_buf`.
pub(crate) const HANDLER_FS_FILE: u8 = 7;
/// Directory listing as JSON, served via the FS provider's
/// `FS_OPENDIR` / `FS_READDIR` ops. The route's `fs_path` holds the
/// directory path; `fs_filter` (optional) holds a comma-separated
/// case-insensitive extension list (`.mp3,.wav,.aac`) — empty means
/// every regular file is listed. The response is a one-shot JSON
/// payload (`{"items":["song1.mp3","song2.wav",…]}`) built into
/// `send_buf` at request time so new files dropped into the directory
/// appear on the next GET. Subdirectories are skipped. Used by the
/// browser-side image_viewer / audio_player launchers to enumerate
/// the asset bank without bespoke handler code.
pub(crate) const HANDLER_FS_LIST: u8 = 8;

/// WebSocket fan-out for SESSION protocols: identical wiring to
/// `HANDLER_WEBSOCKET_FANOUT` (Upgrade accepted, inbound → `ws_out`,
/// outbound ← `ws_in`) but retention replay is suppressed — a new
/// connection must NEVER receive envelopes produced for a previous
/// session. Fan-out retention exists for idempotent presentation
/// state (rasters, telemetry snapshots); replaying a session
/// protocol's frames (e.g. an auth gate's AUTH_OK) to a fresh,
/// unauthenticated subscriber is wrong and surfaced live as one
/// session's replies delivered into the next.
pub(crate) const HANDLER_WEBSOCKET_SESSION: u8 = 9;

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

    /// HANDLER_FS_FILE: file is open but the FS provider hasn't yet
    /// resolved length / final status (wasm browser-fetch with
    /// response headers in flight). Polls `FS_STAT` each step until
    /// it returns OK (length known → `SendHeaders` with
    /// Content-Length), ENOSYS (no Content-Length → streaming
    /// `SendHeaders`), ENODEV (`DrainSend` 502), or stays EAGAIN
    /// past the poll-timeout (`DrainSend` 504). No response bytes
    /// hit the wire until the outcome is known.
    AwaitFsStat = 22,

    Error = 255,
}

// ── Route + cache + variable types ────────────────────────────────────────

#[repr(C)]
pub(crate) struct Route {
    pub(crate) proxy_ip: u32,
    /// Byte offset of this route's body within `body_pool`. Widened
    /// to u32 so the pool can grow past 64 KB on aarch64 hosts that
    /// configure many or large templates.
    pub(crate) body_offset: u32,
    pub(crate) body_len: u32,
    pub(crate) proxy_port: u16,
    pub(crate) path_len: u8,
    pub(crate) handler: u8,
    pub(crate) source_index: i16,
    pub(crate) content_type_len: u8,
    pub(crate) fs_path_len: u8,
    /// Length of `fs_filter`; 0 means accept every entry returned by
    /// `FS_READDIR`. Comma-separated, case-insensitive extension list.
    pub(crate) fs_filter_len: u8,
    pub(crate) path: [u8; MAX_PATH],
    pub(crate) content_type: [u8; MAX_CONTENT_TYPE],
    /// Absolute filesystem path served by `HANDLER_FS_FILE` (a single
    /// file) or `HANDLER_FS_LIST` (a directory to enumerate as JSON).
    /// Populated by `set_route_fs_path` / `set_route_fs_list`.
    pub(crate) fs_path: [u8; MAX_FS_PATH],
    /// Extension filter for `HANDLER_FS_LIST` (e.g. `.mp3,.wav,.aac`).
    /// Compared case-insensitively against each filename's tail.
    pub(crate) fs_filter: [u8; 64],
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
            content_type_len: 0,
            fs_path_len: 0,
            fs_filter_len: 0,
            path: [0; MAX_PATH],
            content_type: [0; MAX_CONTENT_TYPE],
            fs_path: [0; MAX_FS_PATH],
            fs_filter: [0; 64],
        }
    }

    /// Per-route Content-Type bytes if the route declared one,
    /// otherwise the supplied default. Static-body routes typically
    /// pass `b"text/html"` as the default to preserve the historical
    /// behavior.
    pub(crate) fn content_type_or<'a>(&'a self, default: &'a [u8]) -> &'a [u8] {
        let n = self.content_type_len as usize;
        if n == 0 || n > MAX_CONTENT_TYPE {
            default
        } else {
            &self.content_type[..n]
        }
    }
}

// ── Dynamic routes (rfc_dynamic_routes §3.2) ───────────────────────────────
//
// A DEDICATED arena, separate from the TLV-locked static `routes`
// above. Rows are programmed at runtime by the table_consumer helper
// from the compiled `/dataplane/edge/<ns>/<name>` prefix, one key per
// route carrying the full backend set:
//
//   host=<h>;path=<prefix>;be=<ip>:<port>:<w>:<r>,<ip>:<port>:<w>:<r>,…
//
// Host matching, weights, and readiness are net-new capabilities; the
// static path matcher is path-only. The relay (HANDLER_PROXY) dials the
// selected backend and streams both ways (rfc_workload_ingress P1); this
// table is its runtime backend source.

/// Host header buffer per dynamic route.
pub(crate) const MAX_DYN_HOST: usize = 64;
/// `/dataplane/edge/<ns>/<name>` key buffer — the row's stable identity
/// for upsert/remove.
pub(crate) const MAX_DYN_KEY: usize = 64;

/// One backend of a dynamic route.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Backend {
    pub(crate) ip: u32,
    pub(crate) port: u16,
    pub(crate) weight: u8,
    pub(crate) ready: bool,
}

impl Backend {
    const fn new() -> Self {
        Self {
            ip: 0,
            port: 0,
            weight: 0,
            ready: false,
        }
    }
}

/// A runtime-programmed proxy route: host + path prefix + a weighted,
/// readiness-gated backend set, plus a round-robin cursor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DynRoute {
    pub(crate) key: [u8; MAX_DYN_KEY],
    pub(crate) host: [u8; MAX_DYN_HOST],
    pub(crate) path: [u8; MAX_PATH],
    pub(crate) backends: [Backend; MAX_ROUTE_BACKENDS],
    pub(crate) key_len: u8,
    pub(crate) host_len: u8,
    pub(crate) path_len: u8,
    pub(crate) backend_count: u8,
    /// Weighted-round-robin cursor. u16 to keep modulo bias small; the
    /// distribution is best-effort under churn (§3.2) and converges.
    pub(crate) rr_cursor: u16,
    /// 1 when this slot holds a live route.
    pub(crate) used: u8,
}

impl DynRoute {
    pub(crate) const fn new() -> Self {
        Self {
            key: [0; MAX_DYN_KEY],
            host: [0; MAX_DYN_HOST],
            path: [0; MAX_PATH],
            backends: [Backend::new(); MAX_ROUTE_BACKENDS],
            key_len: 0,
            host_len: 0,
            path_len: 0,
            backend_count: 0,
            rr_cursor: 0,
            used: 0,
        }
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len as usize]
    }
    pub(crate) fn host(&self) -> &[u8] {
        &self.host[..self.host_len as usize]
    }
    pub(crate) fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Weighted round-robin over `ready` backends with `weight > 0`.
    /// Advances `rr_cursor` by one each call; over `total_weight` calls
    /// the distribution matches the weights. Returns `(ip, port)` or
    /// `None` when no backend is ready.
    pub fn select_backend(&mut self) -> Option<(u32, u16)> {
        let mut total: u32 = 0;
        for b in &self.backends[..self.backend_count as usize] {
            if b.ready && b.weight > 0 {
                total += b.weight as u32;
            }
        }
        if total == 0 {
            return None;
        }
        let mut target = self.rr_cursor as u32 % total;
        self.rr_cursor = self.rr_cursor.wrapping_add(1);
        for b in &self.backends[..self.backend_count as usize] {
            if b.ready && b.weight > 0 {
                let w = b.weight as u32;
                if target < w {
                    return Some((b.ip, b.port));
                }
                target -= w;
            }
        }
        None
    }
}

/// The dynamic-route arena plus its rebuild shadow (§2 rule 4). The
/// table_consumer helper fills `shadow` during a relist and
/// `swap_shadow` promotes it atomically; live requests only ever see a
/// whole, consistent `live` table.
#[repr(C)]
pub struct DynRoutes {
    pub(crate) live: [DynRoute; MAX_DYN_ROUTES],
    pub(crate) shadow: [DynRoute; MAX_DYN_ROUTES],
    /// Cumulative rows/backends dropped on overflow — mirrored to the
    /// `http.routes.dropped` telemetry counter (§2.5, §6: a reader
    /// surfaces degradation through telemetry, never a store key).
    pub(crate) dropped: u32,
}

impl DynRoutes {
    pub(crate) const fn new() -> Self {
        Self {
            live: [DynRoute::new(); MAX_DYN_ROUTES],
            shadow: [DynRoute::new(); MAX_DYN_ROUTES],
            dropped: 0,
        }
    }

    fn arena(&mut self, shadow: bool) -> &mut [DynRoute; MAX_DYN_ROUTES] {
        if shadow {
            &mut self.shadow
        } else {
            &mut self.live
        }
    }
}

/// Find the `;`-separated `tag=` field's value in a compact record.
fn dyn_field<'a>(value: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let mut start = 0;
    while start <= value.len() {
        let end = value[start..]
            .iter()
            .position(|&b| b == b';')
            .map(|i| start + i)
            .unwrap_or(value.len());
        let seg = &value[start..end];
        if seg.len() >= tag.len() && &seg[..tag.len()] == tag {
            return Some(&seg[tag.len()..]);
        }
        if end >= value.len() {
            break;
        }
        start = end + 1;
    }
    None
}

/// Parse a leading run of ASCII digits as u32.
fn dyn_u32(b: &[u8]) -> u32 {
    let mut n: u32 = 0;
    for &c in b {
        if c.is_ascii_digit() {
            n = n.wrapping_mul(10).wrapping_add((c - b'0') as u32);
        } else {
            break;
        }
    }
    n
}

/// Parse a dotted-quad IPv4 (`a.b.c.d`) into a big-endian-packed u32
/// (`a<<24 | b<<16 | c<<8 | d`).
fn dyn_ipv4(b: &[u8]) -> u32 {
    let mut octets = [0u32; 4];
    let mut oi = 0usize;
    let mut cur = 0u32;
    let mut seen = false;
    for &c in b {
        if c == b'.' {
            if oi < 4 {
                octets[oi] = cur & 0xFF;
            }
            oi += 1;
            cur = 0;
            seen = false;
        } else if c.is_ascii_digit() {
            cur = cur.wrapping_mul(10).wrapping_add((c - b'0') as u32);
            seen = true;
        } else {
            break;
        }
    }
    if seen && oi < 4 {
        octets[oi] = cur & 0xFF;
    }
    (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
}

/// Fill a `DynRoute` slot from `key` + compact `value`
/// (`host=…;path=…;be=<ip>:<port>:<w>:<r>,…`). Returns the number of
/// backends dropped because the set exceeded `MAX_ROUTE_BACKENDS`.
fn dyn_fill(dst: &mut DynRoute, key: &[u8], value: &[u8]) -> u32 {
    *dst = DynRoute::new();
    let kn = key.len().min(MAX_DYN_KEY);
    dst.key[..kn].copy_from_slice(&key[..kn]);
    dst.key_len = kn as u8;

    if let Some(h) = dyn_field(value, b"host=") {
        let n = h.len().min(MAX_DYN_HOST);
        dst.host[..n].copy_from_slice(&h[..n]);
        dst.host_len = n as u8;
    }
    if let Some(p) = dyn_field(value, b"path=") {
        let n = p.len().min(MAX_PATH);
        dst.path[..n].copy_from_slice(&p[..n]);
        dst.path_len = n as u8;
    }

    let mut dropped = 0u32;
    if let Some(be) = dyn_field(value, b"be=") {
        let mut start = 0usize;
        while start <= be.len() {
            let end = be[start..]
                .iter()
                .position(|&b| b == b',')
                .map(|i| start + i)
                .unwrap_or(be.len());
            let seg = &be[start..end];
            if !seg.is_empty() {
                // `<ip>:<port>:<w>:<r>`
                let mut it = seg.split(|&b| b == b':');
                let ip = it.next().map(dyn_ipv4).unwrap_or(0);
                let port = it.next().map(dyn_u32).unwrap_or(0) as u16;
                let weight = it.next().map(dyn_u32).unwrap_or(1);
                let ready = it.next().map(dyn_u32).unwrap_or(1);
                if (dst.backend_count as usize) < MAX_ROUTE_BACKENDS {
                    let i = dst.backend_count as usize;
                    dst.backends[i] = Backend {
                        ip,
                        port,
                        weight: weight.min(255) as u8,
                        ready: ready != 0,
                    };
                    dst.backend_count += 1;
                } else {
                    dropped += 1;
                }
            }
            if end >= be.len() {
                break;
            }
            start = end + 1;
        }
    }
    dropped
}

impl TableSink for DynRoutes {
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool) {
        // Reuse an existing slot with this key, else the first free one.
        let arena = self.arena(shadow);
        let mut free: Option<usize> = None;
        let mut found: Option<usize> = None;
        for (i, r) in arena.iter().enumerate() {
            if r.used == 1 && r.key() == key {
                found = Some(i);
                break;
            }
            if r.used == 0 && free.is_none() {
                free = Some(i);
            }
        }
        let slot = match found.or(free) {
            Some(i) => i,
            None => {
                // Arena full — serve what fits, count the drop (§2.5).
                self.dropped = self.dropped.wrapping_add(1);
                return;
            }
        };
        let dropped = dyn_fill(&mut arena[slot], key, value);
        arena[slot].used = 1;
        if dropped > 0 {
            self.dropped = self.dropped.wrapping_add(dropped);
        }
    }

    fn remove(&mut self, key: &[u8], shadow: bool) {
        let arena = self.arena(shadow);
        for r in arena.iter_mut() {
            if r.used == 1 && r.key() == key {
                r.used = 0;
                return;
            }
        }
    }

    fn clear_shadow(&mut self) {
        for r in self.shadow.iter_mut() {
            r.used = 0;
        }
    }

    fn swap_shadow(&mut self) {
        // Atomic promotion: one whole-arena copy. Requests are only
        // served in separate step invocations, never mid-swap.
        self.live = self.shadow;
    }
}

// Host-test surface: the harness constructs and drives the DynRoute
// arena directly to exercise matching / selection / overflow without a
// full HttpState. No firmware symbol surface (the module is private
// off `host-test`).
#[cfg(feature = "host-test")]
impl DynRoutes {
    pub fn test_new() -> Self {
        Self::new()
    }
    /// Program one live route from a compiled key + value.
    pub fn test_program(&mut self, key: &[u8], value: &[u8]) {
        self.upsert(key, value, false);
    }
    /// Remove one live route by key.
    pub fn test_remove(&mut self, key: &[u8]) {
        self.remove(key, false);
    }
    pub fn test_dropped(&self) -> u32 {
        self.dropped
    }
    /// Mutable access to a live slot (for selection tests).
    pub fn test_live_mut(&mut self, i: usize) -> &mut DynRoute {
        &mut self.live[i]
    }
    /// Backend count on a live slot.
    pub fn test_backend_count(&self, i: usize) -> usize {
        self.live[i].backend_count as usize
    }
}

// ── Dynamic listeners (rfc_workload_ingress §4.2) ─────────────────────
//
// A second table-consumer subscription: the anchor consumes
// `/dataplane/edge-listeners/<port> = proto=tcp;tls=<0|1>` and binds each
// listed port MID-LIFE (outside the Init→Binding→WaitBound bind path that
// serves the single static `port`). The kernel's endpoint-lease gate
// (rfc_endpoint_lease.md §5.3, already shipped) enforces "bind ∈ lease
// set": a port the edge owner was not granted is refused with
// `MSG_BIND_REFUSED`, so the listener never comes up. The grant model is a
// pre-leased port POOL — the edge owner's plan carries one lease per pool
// port (an `export` per port, tools/compose.rs) and mid-life bind draws
// from it at runtime; no runtime lease-grant is needed.
//
// P3 scope: tcp / `tls=0` (cleartext) listeners, where http drives
// linux_net directly. A `tls=1` dynamic listener would need the fronting
// tls module to bind/accept a new port mid-life too (the static 443 bind
// is forwarded through tls today); that per-listener tls state is a
// follow-on — a `tls=1` row is recorded and reported but NOT bound in P3.

/// linux_net's bind-refusal opcode (`src/platform/linux/providers.rs`
/// `MSG_BIND_REFUSED`): `[port:u16 LE][errno:u8]`. Distinct from the
/// metal `ip` module's 0x07 (RETRANSMIT) — acted on ONLY when the
/// dynamic-listener feature is configured (linux edge), so the metal path
/// stays byte-identical.
pub(crate) const NET_MSG_BIND_REFUSED: u8 = 0x07;

/// Additional listeners beyond the static `port`, bound from the
/// pre-leased pool. Small: listener churn is operator-rate (§4.2).
pub(crate) const MAX_DYN_LISTENERS: usize = 8;
/// Input port index carrying the self-edged listener change sink (in[5]).
pub(crate) const DYN_LISTENERS_PORT_INDEX: u8 = 5;

// Reconciler bind states for one pooled listener.
/// Desired, CMD_BIND not yet issued.
const LISTENER_IDLE: u8 = 0;
/// CMD_BIND issued; awaiting MSG_BOUND / MSG_BIND_REFUSED.
const LISTENER_BINDING: u8 = 1;
/// MSG_BOUND seen — accepts on this port are claimed.
const LISTENER_BOUND: u8 = 2;
/// MSG_BIND_REFUSED seen (port not leased) — not retried, never accepts.
const LISTENER_REFUSED: u8 = 3;

/// One desired listener row (table-consumer half). `tls=1` is recorded
/// but not bound in P3 (see the module comment).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ListenerRow {
    pub(crate) key: [u8; MAX_DYN_KEY],
    pub(crate) key_len: u8,
    pub(crate) port: u16,
    pub(crate) tls: u8,
    pub(crate) used: u8,
}

impl ListenerRow {
    const fn new() -> Self {
        Self {
            key: [0; MAX_DYN_KEY],
            key_len: 0,
            port: 0,
            tls: 0,
            used: 0,
        }
    }
    fn key(&self) -> &[u8] {
        &self.key[..self.key_len as usize]
    }
}

/// One runtime bind record (reconciler half). NOT part of the table, so
/// it survives a LOST shadow-swap of the desired set.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BoundListener {
    pub(crate) port: u16,
    pub(crate) state: u8,
    pub(crate) used: u8,
    /// linux_net listener conn_id from MSG_BOUND (teardown CMD_CLOSE).
    pub(crate) conn_id: i16,
}

impl BoundListener {
    const fn new() -> Self {
        Self {
            port: 0,
            state: LISTENER_IDLE,
            used: 0,
            conn_id: -1,
        }
    }
}

/// The desired-listener table (live + rebuild shadow, table-consumer
/// driven) plus the reconciler's runtime bind records. Default-off: an
/// unconfigured `listeners_prefix` leaves every field zero-init and the
/// pump a no-op, so the server is byte-identical.
#[repr(C)]
pub struct DynListeners {
    pub(crate) live: [ListenerRow; MAX_DYN_LISTENERS],
    pub(crate) shadow: [ListenerRow; MAX_DYN_LISTENERS],
    /// Runtime bind state — owned by `reconcile_listeners`, never by the
    /// TableSink swap.
    pub(crate) bound: [BoundListener; MAX_DYN_LISTENERS],
    /// Rows dropped on overflow (mirrors §2.5 degradation-to-telemetry).
    pub(crate) dropped: u32,
}

impl DynListeners {
    pub(crate) const fn new() -> Self {
        Self {
            live: [ListenerRow::new(); MAX_DYN_LISTENERS],
            shadow: [ListenerRow::new(); MAX_DYN_LISTENERS],
            bound: [BoundListener::new(); MAX_DYN_LISTENERS],
            dropped: 0,
        }
    }
    fn arena(&mut self, shadow: bool) -> &mut [ListenerRow; MAX_DYN_LISTENERS] {
        if shadow {
            &mut self.shadow
        } else {
            &mut self.live
        }
    }
}

/// The `<port>` tail of a `/dataplane/edge-listeners/<port>` key: the last
/// '/'-delimited segment parsed as a u16. 0 (unparseable) is ignored.
fn listener_port_of_key(key: &[u8]) -> u16 {
    let seg = match key.iter().rposition(|&b| b == b'/') {
        Some(i) => &key[i + 1..],
        None => key,
    };
    (dyn_u32(seg) & 0xFFFF) as u16
}

impl TableSink for DynListeners {
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool) {
        let port = listener_port_of_key(key);
        // `tls=1` recorded; only `tls=0` is bound in P3.
        let tls = dyn_field(value, b"tls=")
            .map(|v| dyn_u32(v) != 0)
            .unwrap_or(false);
        let arena = self.arena(shadow);
        let mut free: Option<usize> = None;
        let mut found: Option<usize> = None;
        for (i, r) in arena.iter().enumerate() {
            if r.used == 1 && r.key() == key {
                found = Some(i);
                break;
            }
            if r.used == 0 && free.is_none() {
                free = Some(i);
            }
        }
        let slot = match found.or(free) {
            Some(i) => i,
            None => {
                self.dropped = self.dropped.wrapping_add(1);
                return;
            }
        };
        let r = &mut arena[slot];
        *r = ListenerRow::new();
        let kn = key.len().min(MAX_DYN_KEY);
        r.key[..kn].copy_from_slice(&key[..kn]);
        r.key_len = kn as u8;
        r.port = port;
        r.tls = tls as u8;
        r.used = 1;
    }

    fn remove(&mut self, key: &[u8], shadow: bool) {
        let arena = self.arena(shadow);
        for r in arena.iter_mut() {
            if r.used == 1 && r.key() == key {
                r.used = 0;
                return;
            }
        }
    }

    fn clear_shadow(&mut self) {
        for r in self.shadow.iter_mut() {
            r.used = 0;
        }
    }

    fn swap_shadow(&mut self) {
        // Promote only the DESIRED set; the reconciler's `bound` records
        // are untouched, so a relist never drops a live listener.
        self.live = self.shadow;
    }
}

impl DynListeners {
    /// A bound (accepting) dynamic listener owns `port`?
    fn port_is_bound(&self, port: u16) -> bool {
        self.bound
            .iter()
            .any(|b| b.used == 1 && b.state == LISTENER_BOUND && b.port == port)
    }
    /// A pending (BINDING) dynamic listener for `port`, if any.
    fn bound_slot_for(&mut self, port: u16) -> Option<usize> {
        self.bound
            .iter()
            .position(|b| b.used == 1 && b.port == port)
    }
}

#[cfg(feature = "host-test")]
impl DynListeners {
    pub fn test_new() -> Self {
        Self::new()
    }
    pub fn test_program(&mut self, key: &[u8], value: &[u8]) {
        self.upsert(key, value, false);
    }
    pub fn test_remove(&mut self, key: &[u8]) {
        self.remove(key, false);
    }
    /// `(state, conn_id)` of the runtime bind record for `port`, if any.
    pub fn test_bound_state(&self, port: u16) -> Option<(u8, i16)> {
        self.bound
            .iter()
            .find(|b| b.used == 1 && b.port == port)
            .map(|b| (b.state, b.conn_id))
    }
    pub const LISTENER_BINDING: u8 = LISTENER_BINDING;
    pub const LISTENER_BOUND: u8 = LISTENER_BOUND;
    pub const LISTENER_REFUSED: u8 = LISTENER_REFUSED;
}

// Host-test hooks for the proxy relay (rfc_workload_ingress §3). They
// reach into a booted module's opaque `module_state` buffer so the
// harness can program a dynamic route without a live store, seed the
// client source address for the `X-Forwarded-For` assertion, and read
// the `http.proxy.*` counters. No firmware symbol surface.
#[cfg(feature = "host-test")]
/// Program one live dynamic route (`key` + compact `value`) directly
/// into a booted http module's arena, as if the table-consumer applied
/// it. `state` is the harness `module_state` pointer.
///
/// # Safety
/// `state` must point at a live `HttpState` (a booted http module's
/// state buffer).
pub unsafe fn test_inject_dyn_route(state: *mut u8, key: &[u8], value: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.dyn_routes.upsert(key, value, false);
}

#[cfg(feature = "host-test")]
/// Enable the dynamic-listener subsystem on a booted module (as if
/// `listeners_prefix` were configured), so `pump_listeners` reconciles
/// injected desired rows. `sink` is left resolved so the table_consumer
/// never touches the store in a harness.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_enable_listeners(state: *mut u8) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners_prefix[0] = b'/';
    s.server.listeners_prefix_len = 1;
    s.server.listeners_sink = i32::MAX; // non-negative: skip re-resolve
    s.server.ltc.subscribed = 1; // skip SUBSCRIBE/relist in the harness
}

#[cfg(feature = "host-test")]
/// Program one desired listener row (`/dataplane/edge-listeners/<port>` +
/// `proto=tcp;tls=<0|1>`) directly, as if the listener table_consumer
/// applied it.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_inject_listener(state: *mut u8, key: &[u8], value: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners.upsert(key, value, false);
}

#[cfg(feature = "host-test")]
/// Withdraw a desired listener row by key.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_remove_listener(state: *mut u8, key: &[u8]) {
    let s = &mut *(state as *mut HttpState);
    s.server.listeners.remove(key, false);
}

#[cfg(feature = "host-test")]
/// `(state, conn_id)` of the runtime bind record for `port`, if tracked.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_listener_state(state: *mut u8, port: u16) -> Option<(u8, i16)> {
    let s = &*(state as *mut HttpState);
    s.server.listeners.test_bound_state(port)
}

/// Listener bind-state discriminants for harness assertions.
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_BINDING: u8 = LISTENER_BINDING;
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_BOUND: u8 = LISTENER_BOUND;
#[cfg(feature = "host-test")]
pub const LISTENER_STATE_REFUSED: u8 = LISTENER_REFUSED;

#[cfg(feature = "host-test")]
/// Seed the client source address (`X-Forwarded-For`) for the slot
/// currently owning `conn_id`. No-op if no slot owns it yet.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_set_client_ip(state: *mut u8, conn_id: u8, ip: u32) {
    let s = &mut *(state as *mut HttpState);
    if let Some(idx) = find_slot_by_conn_id(s, conn_id) {
        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
        slot.client_ip = ip;
    }
}

#[cfg(feature = "host-test")]
/// `(http.proxy.retries, http.proxy.5xx)` cumulative counters.
///
/// # Safety
/// See [`test_inject_dyn_route`].
pub unsafe fn test_proxy_metrics(state: *mut u8) -> (u32, u32) {
    let s = &*(state as *mut HttpState);
    (s.server.proxy_retries, s.server.proxy_5xx)
}

/// Param setter for `routes_prefix` (TLV tag 90). An empty value
/// leaves the feature off. Copies up to `MAX_DYN_PREFIX` bytes.
///
/// # Safety
/// `d` points at `len` readable bytes (the TLV value).
pub(crate) unsafe fn set_routes_prefix(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(MAX_DYN_PREFIX);
    let dst = s.server.routes_prefix.as_mut_ptr();
    let mut i = 0;
    while i < n {
        *dst.add(i) = *d.add(i);
        i += 1;
    }
    s.server.routes_prefix_len = n as u16;
}

/// Param setter for `listeners_prefix` (TLV tag 91). Empty leaves the
/// dynamic-listener feature off (byte-identical server). Copies up to
/// `MAX_DYN_PREFIX` bytes (rfc_workload_ingress §4.2).
///
/// # Safety
/// `d` points at `len` readable bytes (the TLV value).
pub(crate) unsafe fn set_listeners_prefix(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(MAX_DYN_PREFIX);
    let dst = s.server.listeners_prefix.as_mut_ptr();
    let mut i = 0;
    while i < n {
        *dst.add(i) = *d.add(i);
        i += 1;
    }
    s.server.listeners_prefix_len = n as u16;
}

/// Match a request `host`/`path` against the dynamic-route table: host
/// must match exactly (byte-wise), then the longest path prefix wins
/// (an empty route path matches any path). Returns the live index, or
/// `-1` when none match. Consulted after the static arena (§3.2).
pub fn match_dyn_route(dyn_routes: &DynRoutes, host: &[u8], path: &[u8]) -> i32 {
    let mut best: i32 = -1;
    let mut best_len: usize = 0;
    for (i, r) in dyn_routes.live.iter().enumerate() {
        if r.used != 1 || r.host() != host {
            continue;
        }
        let rp = r.path();
        let matches = rp.is_empty() || (path.len() >= rp.len() && &path[..rp.len()] == rp);
        if matches && (best < 0 || rp.len() > best_len) {
            best = i as i32;
            best_len = rp.len();
        }
    }
    best
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CacheEntry {
    route_index: u8,
    flags: u8,
    lru_tick: u8,
    /// Reader refcount. Bumped on cache hit / fill-complete, dropped
    /// on emission end. `cache_alloc` refuses to evict an entry with
    /// `retain > 0`, so a long-lived reader (h2 stream rendering
    /// chunks across many ticks; h1 SendBody crossing into
    /// DrainSend) can't have its `body_pool` region overwritten by
    /// a sibling cache miss.
    retain: u8,
    arena_offset: u32,
    length: u32,
}

impl CacheEntry {
    const fn new() -> Self {
        Self {
            route_index: 0,
            flags: 0,
            lru_tick: 0,
            retain: 0,
            arena_offset: 0,
            length: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct VarEntry {
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

/// Per-connection state. `ServerState` holds an array of these and
/// the step machine ticks each active slot every step so multiple
/// HTTP transactions progress in parallel.
///
/// A slot is **free** when `phase == Phase::Init` AND `conn_id < 0`.
/// The accept path allocates the first free slot it finds; the close
/// path resets the slot back to that state.
#[repr(C)]
pub(crate) struct ConnSlot {
    /// Conn id from `MSG_ACCEPTED`. `-1` when the slot is free.
    pub(crate) conn_id: i16,
    /// Per-slot phase machine state.
    pub(crate) phase: Phase,
    pub(crate) matched_route: i8,
    pub(crate) recv_parsed: u8,
    pub(crate) req_path_len: u8,
    pub(crate) peer_closed: u8,
    /// Keep-alive for the current request. Derived in
    /// `Phase::RecvRequest` from the version + `Connection:` header,
    /// consumed by `finish_response`. Cleared in `free_slot`.
    pub(crate) keepalive: u8,
    /// Set to 1 when the matched route uses
    /// `HANDLER_WEBSOCKET_FANOUT` and the upgrade succeeded.
    pub(crate) ws_fan_out: u8,
    /// Set to 1 if a WsFrame envelope read from `ws_in` had fin=1
    /// and was split into multiple wire fragments. The final wire
    /// fragment will carry `fin=1`; intermediate ones carry `fin=0`.
    pub(crate) ws_frag_orig_fin: u8,
    /// 1 while this slot is rendering bytes from a body-cache
    /// entry (incremented on `cache_try_or_fetch::Hit` or
    /// `cache_fetch_step::Ready`; decremented on transition out
    /// of body emission via `cache_release_for_route`). Pair-flag
    /// so over- or under-release can't happen if the slot enters
    /// DrainSend more than once.
    pub(crate) cache_retained: u8,

    pub(crate) recv_len: u16,
    /// Offset in `recv_buf` of the first byte after `\r\n\r\n` (or
    /// the start of the next pipelined request). 0 before parse.
    pub(crate) header_end_off: u16,
    pub(crate) send_offset: u16,
    pub(crate) send_len: u16,
    pub(crate) file_index: i16,
    pub(crate) file_count: u16,
    pub(crate) index_pos: u16,
    pub(crate) fs_stat_ticks: u16,
    /// Render position into the route's `body_offset..body_offset+body_len`
    /// region of the body_pool arena. Widened to u32 to match the
    /// route's `body_offset` / `body_len` widths — large inline /
    /// template / cached bodies (e.g. >64 KiB single-page apps,
    /// jpeg/png assets) would wrap a u16 cursor and cause the
    /// renderer to resend or corrupt mid-body.
    pub(crate) tmpl_pos: u32,

    pub(crate) fs_fd: i32,
    pub(crate) fs_total: u32,
    pub(crate) fs_sent: u32,

    pub(crate) req_path: [u8; MAX_PATH],
    /// Heap-allocated request buffer. Allocated by
    /// `alloc_free_slot` on accept, freed by `free_slot` on close.
    /// `null` while the slot is free — keeping idle slots small so
    /// the slot table can scale to thousands of connections without
    /// reserving 8 KB × N permanent memory.
    pub(crate) recv_buf: *mut u8,
    pub(crate) recv_cap: u16,

    /// Heap-allocated response buffer; lifecycle parallels `recv_buf`.
    pub(crate) send_buf: *mut u8,
    pub(crate) send_cap: u16,

    /// HTTP/2 connection state. Heap-allocated lazily on the h2c
    /// preface (or h2-via-ALPN entry); null while the slot is in
    /// h1 mode or idle. Sized at ~3 KB on aarch64 (4 streams + WS
    /// reassembly buffer), so making it lazy saves ~3 MB on a
    /// 1024-slot table for h1-only workloads.
    #[cfg(feature = "h2")]
    pub(crate) h2: *mut super::h2::H2State,

    // ── WebSocket fan-out fragmentation state ──────────────────────
    //
    // When a WsFrame envelope read from `ws_in` carries a payload
    // larger than `SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, it can't
    // fit as a single wire frame. The first fragment is queued
    // immediately with the original opcode and `fin=0`; subsequent
    // chunks ride out as `CONTINUATION` frames over later step()
    // iterations. `ws_frag_buf` holds the source payload until the
    // final fragment is queued, then is freed.
    /// Heap-allocated copy of the source payload during fragmentation.
    /// `null` outside fragmentation. Size = `ws_frag_total` bytes.
    pub(crate) ws_frag_buf: *mut u8,
    /// Total source payload length (bytes still belonging to the
    /// in-flight logical message). 0 when no fragmentation in flight.
    pub(crate) ws_frag_total: u16,
    /// Bytes already queued in earlier fragments. Next fragment
    /// starts at `ws_frag_buf + ws_frag_offset`.
    pub(crate) ws_frag_offset: u16,
    /// Original opcode (BINARY/TEXT) the source frame carried, used
    /// only on the first fragment; subsequent fragments carry
    /// `OP_CONT (0x0)`.
    pub(crate) ws_frag_opcode: u8,
    _slot_pad1: [u8; 3],

    // ── Retention replay state ─────────────────────────────────────
    //
    // When a slot enters `WsActive` (fresh client connect on a
    // fan-out route), it first drains any envelopes captured in the
    // server-wide `retained_buf` so that reloads see the producer's
    // most recent snapshot without the producer having to re-emit.
    // `retained_replay_offset` walks the retain buffer one envelope
    // at a time, bounded by `retained_replay_target` (snapshot of
    // `retained_used` taken on the slot's first WsActive tick). New
    // live envelopes captured during replay grow `retained_used` past
    // the target — replay must NOT cross that boundary or the new
    // subscriber would receive them twice (once via live queue, once
    // via replay walk). `retained_replay_done` flips to 1 when offset
    // hits the target (caught up; normal live flow resumes).
    pub(crate) retained_replay_offset: u32,
    pub(crate) retained_replay_target: u32,
    pub(crate) retained_replay_done: u8,
    /// 1 once the replay-start snapshot has been captured for this
    /// slot. Zero on slot reset → first WsActive tick stamps
    /// `retained_replay_target = retained_used` and flips this bit.
    pub(crate) retained_replay_started: u8,
    _slot_pad2: [u8; 2],

    /// Observability: monotonic-micros start of this request's
    /// `http.server.request` span, latched when the request head is parsed and
    /// the telemetry port is wired (`0` = no span). Keepalive reuses the slot,
    /// so it's re-latched per request. See `standards/observability.md`.
    pub(crate) span_start_us: u64,
    /// W3C trace context the span actually adopts (per request): the client's
    /// `traceparent` header when present, else the connection context below.
    /// All-zero trace id → root span.
    pub(crate) span_trace_id: [u8; 16],
    pub(crate) span_parent_id: [u8; 8],
    /// W3C trace-flags the span adopts (per request): the `traceparent` flags
    /// when present, else `conn_flags`. Low bit = `sampled`.
    pub(crate) span_flags: u8,
    /// Connection-scoped trace context from IP→TLS `MSG_TRACE_CTX` (TLS's span
    /// id as parent). Set once at accept, applied to every request on the
    /// connection that doesn't carry its own `traceparent`. All-zero = none.
    pub(crate) conn_trace_id: [u8; 16],
    pub(crate) conn_parent_id: [u8; 8],
    /// W3C trace-flags from the connection's `MSG_TRACE_CTX`. Low bit = `sampled`.
    pub(crate) conn_flags: u8,

    // ── Proxy relay state (rfc_workload_ingress §3) ────────────────
    //
    // A HANDLER_PROXY route (static `proxy_ip/port`) or a dynamic-route
    // match dials an upstream backend and relays bytes both ways
    // within this slot's existing `recv_buf` (client→backend) and
    // `send_buf` (backend→client) windows — no extra arenas.
    /// Upstream backend conn id latched from `MSG_CONNECTED`; `-1`
    /// when no backend conn is dialed / open.
    pub(crate) backend_conn_id: i16,
    /// Dyn-route index driving this relay (`-1` = static proxy route
    /// or none). Used to advance `rr_cursor` + reselect on failover.
    pub(crate) proxy_dyn_idx: i16,
    /// Selected backend address for the (re)dial.
    pub(crate) proxy_be_ip: u32,
    pub(crate) proxy_be_port: u16,
    /// Client's source address for `X-Forwarded-For`. 0 (`0.0.0.0`)
    /// when unknown — the net layer's `MSG_ACCEPTED` carries only
    /// `[conn_id][local_port]`, not the peer address (P1 correction),
    /// so this stays 0 in production until a peer-address surface
    /// lands. The XFF injection path itself is real and exercised.
    pub(crate) client_ip: u32,
    /// Wall-clock ms the current dial started (connect timeout).
    pub(crate) proxy_connect_start_ms: u32,
    /// Connect attempts made so far (0 = first). Retry budget is 1.
    pub(crate) proxy_attempt: u8,
    /// 1 once demux latched `MSG_CONNECTED` for our pending dial.
    pub(crate) proxy_connected: u8,
    /// 1 once demux saw a connect `MSG_ERROR` for our pending dial.
    pub(crate) proxy_connect_failed: u8,
    /// 1 once the backend peer closed (`MSG_CLOSED` on `backend_conn_id`).
    pub(crate) backend_closed: u8,
    /// Read cursor into `recv_buf` for the client→backend body relay.
    pub(crate) proxy_creq_off: u16,
    _proxy_pad: [u8; 2],
}

impl ConnSlot {
    /// True when the slot is available for `alloc_free_slot`. Free
    /// slots have null buffers — their heap allocations have been
    /// returned to the arena.
    pub(crate) fn is_free(&self) -> bool {
        self.conn_id < 0 && matches!(self.phase, Phase::Init | Phase::WaitAccept)
    }
}

/// Slot lifecycle helpers. Operate on the slot table indirectly so
/// they can call `heap_alloc` / `heap_free` via the syscall table.
///
/// `slot_init_zero` is called once per slot at module init (the
/// kernel zero-fills `module_state` so we just need to set the
/// `-1` sentinels — no heap activity yet).
unsafe fn slot_init_zero(slot: &mut ConnSlot) {
    slot.conn_id = -1;
    slot.matched_route = -1;
    slot.file_index = -1;
    slot.fs_fd = -1;
    // Proxy relay sentinels — a zero-fill leaves these at 0, which is
    // a *valid* conn id / route index, so they must be re-set to -1.
    slot.backend_conn_id = -1;
    slot.proxy_dyn_idx = -1;
}

/// Free a slot's heap allocations (recv_buf, send_buf, h2),
/// zero its metadata, and clear its bit in the ready bitmap.
/// Called from `free_slot` (close path) and as the cleanup half
/// of `alloc_free_slot` when a buffer's allocation fails.
unsafe fn slot_release_buffers(s: &mut HttpState, idx: usize) {
    // If this slot owned `file_chan`, release the lock so a sibling
    // slot blocked in DispatchRoute can proceed. Done before the
    // slot's `cur_slot` index is touched so `release_file_chan`
    // matches the right owner check.
    if s.server.file_chan_owner == idx as i16 {
        s.server.file_chan_owner = -1;
    }
    // Same for a serialised proxy connect owned by this slot — a slot
    // freed mid-dial must not wedge the connect serialisation.
    if s.server.proxy_connect_owner == idx as i16 {
        s.server.proxy_connect_owner = -1;
    }
    // If this slot was the current fan-out winner, clear the
    // pointer so the next subscriber doesn't immediately self-close
    // against a stale index.
    if s.server.latest_fanout_slot == idx as i32 {
        s.server.latest_fanout_slot = -1;
    }
    // If this slot was retaining a body-cache entry (mid-emission
    // close), release the retain so the entry can be evicted.
    {
        let slot = &*s.server.slots.as_ptr().add(idx);
        if slot.cache_retained != 0 && slot.matched_route >= 0 {
            let route_idx = slot.matched_route;
            cache_release_for_route(s, route_idx as u8);
            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
            slot.cache_retained = 0;
        }
    }
    let sys = s.syscalls;
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    if !slot.recv_buf.is_null() {
        heap_free(&*sys, slot.recv_buf);
        slot.recv_buf = core::ptr::null_mut();
        slot.recv_cap = 0;
    }
    if !slot.send_buf.is_null() {
        heap_free(&*sys, slot.send_buf);
        slot.send_buf = core::ptr::null_mut();
        slot.send_cap = 0;
    }
    #[cfg(feature = "h2")]
    if !slot.h2.is_null() {
        heap_free(&*sys, slot.h2 as *mut u8);
        slot.h2 = core::ptr::null_mut();
    }
    // WS fan-out fragmentation may have a heap-allocated source
    // payload buffer in flight when the conn closes mid-message.
    // Free it explicitly — the slot zero-fill below clears the
    // pointer, which would otherwise leak the allocation.
    if !slot.ws_frag_buf.is_null() {
        heap_free(&*sys, slot.ws_frag_buf);
        slot.ws_frag_buf = core::ptr::null_mut();
        slot.ws_frag_total = 0;
        slot.ws_frag_offset = 0;
    }
    // Zero the rest of the slot then re-set sentinels.
    let p = slot as *mut ConnSlot as *mut u8;
    core::ptr::write_bytes(p, 0, core::mem::size_of::<ConnSlot>());
    slot_init_zero(slot);
    ready_clear(s, idx);
}

/// Allocate the per-slot heap buffers. Returns `false` on
/// allocation failure — caller is expected to release any partial
/// allocation via `slot_release_buffers` and close the conn.
unsafe fn slot_acquire_buffers(s: &mut HttpState, idx: usize) -> bool {
    let sys = s.syscalls;
    let recv = heap_alloc(&*sys, RECV_BUF_SIZE as u32);
    if recv.is_null() {
        return false;
    }
    let send = heap_alloc(&*sys, SEND_BUF_SIZE as u32);
    if send.is_null() {
        heap_free(&*sys, recv);
        return false;
    }
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.recv_buf = recv;
    slot.recv_cap = RECV_BUF_SIZE as u16;
    slot.send_buf = send;
    slot.send_cap = SEND_BUF_SIZE as u16;
    true
}

/// Server-wide state shared across all connections. Holds channel
/// handles, route configuration, the body cache + arena, telemetry
/// variables, the per-connection slot table, and the step
/// iterator's bookkeeping. Per-connection state lives in
/// [`ConnSlot`] inside `slots`.
#[repr(C)]
pub(crate) struct ServerState {
    /// `var_chan` carries `FmpMessage` updates that drive
    /// `{{var:name}}` substitutions in template responses.
    pub(crate) var_chan: i32,
    /// File-backed content channel used by `HANDLER_FILE`,
    /// `HANDLER_STREAM`, and `HANDLER_TEMPLATE`'s cache-fill path.
    /// One channel shared across all slots; serialised via
    /// `file_chan_owner` so concurrent fetches don't race on
    /// `IOCTL_FLUSH`/`IOCTL_NOTIFY`. `HANDLER_FS_FILE` (handler 7)
    /// bypasses this entirely via per-slot `fs_fd` through the
    /// FS_CONTRACT and is the recommended path for new deployments.
    pub(crate) file_chan: i32,
    /// Slot index that currently owns `file_chan` (-1 = free). A
    /// handler that needs the channel calls `try_acquire_file_chan`
    /// to claim it; if another slot is mid-fetch, the caller stalls
    /// in `DispatchRoute` and retries on the next tick. Released on
    /// transition to `DrainSend` (fetch / body-send complete) and
    /// in `slot_release_buffers` (any close path).
    pub(crate) file_chan_owner: i16,
    _file_chan_pad: [u8; 2],
    pub(crate) out_chan: i32,
    /// Output channel for `ws_out` (manifest port out[2]). Carries
    /// `WsFrame` records when a route uses `HANDLER_WEBSOCKET_FANOUT`.
    /// `-1` if the port is unwired.
    pub(crate) ws_out_chan: i32,
    /// Input channel for `ws_in` (manifest port in[3]). Carries
    /// `WsFrame` records to be queued back as outbound WS frames.
    /// `-1` if the port is unwired.
    pub(crate) ws_in_chan: i32,

    pub(crate) port: u16,
    /// Bytes currently consumed in `body_pool`. u32 so the pool
    /// can grow past 64 KiB for hosts that configure many or
    /// large templates.
    pub(crate) body_pool_used: u32,

    pub(crate) route_count: u8,
    /// Configured at boot in `post_params` based on the wired routes.
    /// Server-wide (not per-conn) — every connection's dispatch path
    /// keys off the same configured mode.
    pub(crate) legacy_mode: u8,
    pub(crate) cache_count: u8,
    pub(crate) cache_tick: u8,
    /// Telemetry-variable count. Updates arrive on `var_chan` and
    /// apply to every connection's template render — vars are
    /// shared so two concurrent renders see the same snapshot.
    pub(crate) var_count: u8,

    pub(crate) routes: [Route; MAX_ROUTES],
    /// Variable table keyed by `name_hash`; updated by
    /// `drain_variables` from `var_chan`, read by `lookup_var`
    /// during template render. Shared across all connections.
    pub(crate) vars: [VarEntry; MAX_VARS],
    cache_entries: [CacheEntry; MAX_CACHE],
    pub(crate) body_pool: *mut u8,
    pub(crate) body_pool_cap: u32,
    pub(crate) draining: u8,
    /// Set to `1` after the IP module's `MSG_BOUND` arrives. Gates
    /// `demux_inbound` so it stays dormant during the bind sequence
    /// (Init → Binding → WaitBound) but stays active once binding
    /// has succeeded — even if slot 0 cycles Init → assigned →
    /// Init → assigned through subsequent connections.
    pub(crate) bound: u8,

    /// Per-connection slot table. Each slot can independently be in
    /// any phase, including `Init` (free). The accept path allocates
    /// the first free slot, the close path resets the slot back to
    /// free.
    pub(crate) slots: [ConnSlot; MAX_CONCURRENT_CONNS],
    /// Index of the currently-active slot. `-1` when no connection
    /// is being ticked.
    pub(crate) cur_slot: i32,
    /// Round-robin cursor for the step iterator. Tracks which slot
    /// got the most recent phase tick so the next tick picks a
    /// different one — fairness across concurrent transactions.
    pub(crate) step_cursor: u32,
    /// Bitmap of slots that need ticking. Bit `i` set ⇔ the
    /// iterator should call `step_active_slot` for slot `i` this
    /// tick. Allocating a slot via `alloc_free_slot` sets the bit;
    /// freeing it via `slot_release_buffers` clears it. Slot 0
    /// stays set during the boot bind sequence
    /// (Init → Binding → WaitBound) and the WaitBound→WaitAccept
    /// transition clears it. This makes per-tick cost O(active)
    /// instead of O(MAX_CONCURRENT_CONNS).
    pub(crate) ready_bits: [u64; READY_BITS_WORDS],

    // ── Retention buffer ──────────────────────────────────────────
    //
    // Server-wide capture of the most recent burst of WsFrame
    // envelopes seen on `ws_in`. Each envelope is encoded as
    // `[opcode:u8][fin:u8][payload_len:u16 LE][payload:N]` and
    // appended to `retained_buf`. When a NEW connection enters
    // `WsActive` with `ws_fan_out=1`, its first `retained_used`
    // bytes' worth of replay drains this buffer envelope-by-envelope
    // into `send_buf` before live envelopes resume.
    //
    // Single subscriber by design: the producer emits once per state
    // change; the server retains the latest "complete" snapshot
    // (defined by an idle gap > `RETAIN_RESET_TICKS`). New connects
    // see the snapshot immediately; live envelopes mid-capture also
    // see the live stream via the normal `ws_drain_fanout_input`
    // path.
    pub(crate) retained_buf: *mut u8,
    pub(crate) retained_cap: u32,
    pub(crate) retained_used: u32,
    pub(crate) retained_envelope_count: u16,
    /// Ticks since the last `ws_in` envelope was captured. Reset to
    /// 0 on capture; saturating-incremented every step. When it
    /// exceeds `RETAIN_RESET_TICKS` the next captured envelope
    /// triggers a wipe of `retained_used` so the buffer holds the
    /// fresh post-idle snapshot instead of growing without bound.
    pub(crate) retained_idle_ticks: u16,
    _retained_pad: [u8; 2],

    /// Last-connection-wins: index of the slot that most recently
    /// completed a fan-out WS upgrade, or `-1` when no fan-out
    /// subscriber is active. Every other slot whose `ws_fan_out=1`
    /// self-closes (CLOSE 1001) on its next `WsActive` tick. The
    /// fan-out routes are inherently single-subscriber — image
    /// viewers, raster bridges, telemetry feeds — so a second tab
    /// connecting must displace the first cleanly, and a displaced
    /// tab must NOT auto-reconnect (the WS source built-in and the
    /// canonical runtime shell both have no reconnect logic).
    pub(crate) latest_fanout_slot: i32,

    // ── Dynamic routes (rfc_dynamic_routes §3.2) ──────────────────
    //
    // Default-off: `routes_prefix_len == 0` means the whole subsystem
    // is dormant and the server behaves byte-for-byte as before.
    /// Store prefix the table_consumer subscribes to (e.g.
    /// `/dataplane/edge/`). Empty (`routes_prefix_len == 0`) = feature
    /// off.
    pub(crate) routes_prefix: [u8; MAX_DYN_PREFIX],
    pub(crate) routes_prefix_len: u16,
    /// Change-sink channel (store SUBSCRIBE pushes here; self-edge
    /// alloc, in[DYN_ROUTES_PORT_INDEX]). `-1` until resolved.
    pub(crate) routes_sink: i32,
    /// Subscription bookkeeping.
    pub(crate) tc: TableConsumer,
    /// The dynamic-route arena + rebuild shadow.
    pub(crate) dyn_routes: DynRoutes,
    /// Scratch for the `CHANGES` relist response.
    pub(crate) routes_scratch: [u8; DYN_SCRATCH],

    // ── Proxy relay bookkeeping (rfc_workload_ingress §3) ──────────
    /// Slot index owning the in-flight proxy `CONNECT` handshake, or
    /// `-1`. `MSG_CONNECTED`/`MSG_ERROR` carry only `[conn_id][tag]`
    /// and the tag is the module index (identical across slots), so
    /// the CONNECT→CONNECTED window is serialised — demux correlates
    /// the reply to this owner. Mirrors `file_chan_owner`; the relay
    /// itself (the long part) runs concurrently across slots.
    pub(crate) proxy_connect_owner: i16,
    _proxy_owner_pad: [u8; 2],
    /// Cumulative failover retries (`http.proxy.retries`, §3). A reader
    /// surfaces this via telemetry, never a store key (dynamic_routes §6).
    pub(crate) proxy_retries: u32,
    /// Cumulative relay 5xx responses (`http.proxy.5xx`, §3).
    pub(crate) proxy_5xx: u32,

    // ── Dynamic listeners (rfc_workload_ingress §4.2) ──────────────
    //
    // Default-off: `listeners_prefix_len == 0` leaves the whole
    // mid-life-bind subsystem dormant and the server byte-identical.
    /// Store prefix the listener table_consumer subscribes to (e.g.
    /// `/dataplane/edge-listeners/`). Empty = feature off.
    pub(crate) listeners_prefix: [u8; MAX_DYN_PREFIX],
    pub(crate) listeners_prefix_len: u16,
    /// Change-sink channel (self-edge alloc, in[DYN_LISTENERS_PORT_INDEX]).
    /// `-1` until resolved.
    pub(crate) listeners_sink: i32,
    /// Listener-subscription bookkeeping (second table consumer).
    pub(crate) ltc: TableConsumer,
    /// Desired-listener table + reconciler bind records.
    pub(crate) listeners: DynListeners,
}

/// Store-prefix buffer for `routes_prefix`.
pub(crate) const MAX_DYN_PREFIX: usize = 64;
/// `CHANGES` relist scratch. Holds the full snapshot for a cold-start /
/// LOST rebuild; a snapshot larger than this fails closed (keeps the
/// prior table) — sized to comfortably cover the arena's worst case.
pub(crate) const DYN_SCRATCH: usize = 8192;
/// Input port index carrying the self-edged change sink (in[4]).
pub(crate) const DYN_ROUTES_PORT_INDEX: u8 = 4;

/// Number of `u64` words needed to cover `MAX_CONCURRENT_CONNS`
/// bits (rounded up). At MAX=1024 this is 16 words = 128 bytes.
pub(crate) const READY_BITS_WORDS: usize = MAX_CONCURRENT_CONNS.div_ceil(64);

#[inline(always)]
unsafe fn ready_set(s: &mut HttpState, idx: usize) {
    if idx < MAX_CONCURRENT_CONNS {
        s.server.ready_bits[idx / 64] |= 1u64 << (idx % 64);
    }
}

#[inline(always)]
unsafe fn ready_clear(s: &mut HttpState, idx: usize) {
    if idx < MAX_CONCURRENT_CONNS {
        s.server.ready_bits[idx / 64] &= !(1u64 << (idx % 64));
    }
}

// ServerState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Multi-conn slot helpers ───────────────────────────────────────────────
//
// These helpers locate / allocate / free slots in the
// `ServerState::slots` array. They underpin the iterator-based step
// machine — `cur_slot` is the slot index the per-tick handler is
// currently running against; convenience accessors below
// (`cur_recv_len`, `cur_send_buf_mut_ptr`, …) read or mutate that
// slot's per-conn state.

/// Find the slot whose `conn_id` matches `conn_id`. Returns `None`
/// when no slot owns that conn id (e.g. an MSG_DATA arrived for a
/// peer that already closed and got pruned).
pub(crate) unsafe fn find_slot_by_conn_id(s: &HttpState, conn_id: u8) -> Option<usize> {
    let needle = conn_id as i16;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.conn_id == needle {
            return Some(i);
        }
    }
    None
}

/// Return the lowest-indexed slot that has `ws_fan_out = 1` and a
/// live conn. Used by `ws_drain_fanout_input` when the envelope's
/// `conn_id` is the `u32::MAX` "unclaimed" sentinel from
/// `ws_stream` — i.e. the producer hasn't latched a real id yet
/// because no inbound WS frame has arrived.
///
/// Single-active-WS workloads (the common case) get correct
/// delivery without ws_stream needing a real id; multi-WS
/// workloads naturally provide the real id once any inbound
/// arrives. Returns `None` if no fan-out slot is currently active.
pub(crate) unsafe fn find_first_ws_fanout_slot(s: &HttpState) -> Option<usize> {
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.conn_id >= 0 && slot.ws_fan_out != 0 {
            return Some(i);
        }
    }
    None
}

/// Allocate the first free slot and acquire its heap buffers.
/// Returns `None` when the slot table is full or the heap is
/// exhausted — caller closes the incoming connection in either
/// case (the IP module would otherwise leave the slot in
/// `Established` until the per-conn timeout, exhausting
/// `MAX_TCP_CONNS` under any non-trivial load).
///
/// Free slots are guaranteed clean (zeroed metadata, null buffer
/// pointers) by `slot_release_buffers` on the close path — this
/// function therefore only needs to acquire fresh buffers and set
/// the conn id.
pub(crate) unsafe fn alloc_free_slot(s: &mut HttpState, conn_id: u8) -> Option<usize> {
    let mut chosen: Option<usize> = None;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.is_free() {
            chosen = Some(i);
            break;
        }
    }
    let idx = chosen?;
    if !slot_acquire_buffers(s, idx) {
        // Heap exhausted — leave the slot free and tell the caller.
        return None;
    }
    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot.conn_id = conn_id as i16;
    // Clear any trace context inherited from a prior connection on this slot;
    // the new connection's `MSG_TRACE_CTX` (if any) repopulates it.
    slot.conn_trace_id = [0u8; 16];
    slot.conn_parent_id = [0u8; 8];
    slot.conn_flags = 0;
    slot.span_trace_id = [0u8; 16];
    slot.span_parent_id = [0u8; 8];
    slot.span_flags = 0;
    ready_set(s, idx);
    Some(idx)
}

/// Free the slot at `idx`: returns its heap buffers to the arena
/// and zeroes its metadata so the next `alloc_free_slot` call can
/// pick it up cleanly.
pub(crate) unsafe fn free_slot(s: &mut HttpState, idx: usize) {
    if idx >= MAX_CONCURRENT_CONNS {
        return;
    }
    slot_release_buffers(s, idx);
}

/// Borrow the currently-active slot — the one whose state the
/// per-tick handler is reading/writing. Returns `None` when
/// `cur_slot < 0`, i.e. the server is idle / between connections.
pub(crate) unsafe fn cur_slot(s: &HttpState) -> Option<&ConnSlot> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        return None;
    }
    Some(&*s.server.slots.as_ptr().add(idx as usize))
}

/// Mutable variant of [`cur_slot`].
pub(crate) unsafe fn cur_slot_mut(s: &mut HttpState) -> Option<&mut ConnSlot> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        return None;
    }
    Some(&mut *s.server.slots.as_mut_ptr().add(idx as usize))
}

/// Convenience read of the active slot's `matched_route`. Returns
/// `-1` (the "no match" sentinel) when no slot is active.
#[inline(always)]
pub(crate) unsafe fn cur_matched_route(s: &HttpState) -> i8 {
    cur_slot(s).map(|c| c.matched_route).unwrap_or(-1)
}

/// Convenience read of the active slot's `ws_fan_out`. Returns 0
/// when no slot is active.
#[inline(always)]
pub(crate) unsafe fn cur_ws_fan_out(s: &HttpState) -> u8 {
    cur_slot(s).map(|c| c.ws_fan_out).unwrap_or(0)
}

/// Convenience read of the active slot's `recv_len`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_recv_len(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.recv_len).unwrap_or(0)
}

/// Convenience read of the active slot's `send_offset`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_offset(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.send_offset).unwrap_or(0)
}

/// Convenience read of the active slot's `send_len`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_len(s: &HttpState) -> u16 {
    cur_slot(s).map(|c| c.send_len).unwrap_or(0)
}

/// Convenience read of the active slot's `fs_fd`. -1 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_fd(s: &HttpState) -> i32 {
    cur_slot(s).map(|c| c.fs_fd).unwrap_or(-1)
}

/// Convenience read of the active slot's `fs_total`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_total(s: &HttpState) -> u32 {
    cur_slot(s).map(|c| c.fs_total).unwrap_or(0)
}

/// Convenience read of the active slot's `fs_sent`. 0 when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_fs_sent(s: &HttpState) -> u32 {
    cur_slot(s).map(|c| c.fs_sent).unwrap_or(0)
}

/// Convenience read of the active slot's `phase`. `Phase::Init` when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_phase(s: &HttpState) -> Phase {
    cur_slot(s).map(|c| c.phase).unwrap_or(Phase::Init)
}

/// Set the active slot's `phase`. No-op if no slot.
#[inline(always)]
pub(crate) unsafe fn set_cur_phase(s: &mut HttpState, p: Phase) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = p;
    }
}

/// Active slot's `H2State` shared ref. Caller must already know
/// the slot is in h2 mode (i.e. h2 has been allocated via
/// `ensure_h2_state`).
///
/// # Safety
/// `cur_slot` must point at a non-free slot whose `h2` pointer is
/// non-null. The h2 phase machine maintains both invariants — it
/// only reads h2 state after `enter()` (which calls
/// `ensure_h2_state`) and before the slot transitions to
/// `CloseConn` (which clears the pointer).
#[cfg(feature = "h2")]
#[inline(always)]
pub(crate) unsafe fn cur_h2(s: &HttpState) -> &super::h2::H2State {
    &*cur_slot(s).unwrap_unchecked().h2
}

/// Active slot's `H2State` mut ref. Same precondition as
/// [`cur_h2`].
#[cfg(feature = "h2")]
#[inline(always)]
pub(crate) unsafe fn cur_h2_mut(s: &mut HttpState) -> &mut super::h2::H2State {
    &mut *cur_slot_mut(s).unwrap_unchecked().h2
}

/// Allocate the active slot's `H2State` if not already allocated.
/// Called from `h2::enter()` before the slot runs its first h2
/// tick. Returns `false` on heap exhaustion — the caller must
/// transition to `CloseConn` rather than enter `H2Active`.
#[cfg(feature = "h2")]
pub(crate) unsafe fn ensure_h2_state(s: &mut HttpState) -> bool {
    let idx = match current_slot_index(s) {
        Some(i) => i,
        None => return false,
    };
    let slot = &*s.server.slots.as_ptr().add(idx);
    if !slot.h2.is_null() {
        return true;
    }
    let sys = s.syscalls;
    let raw = heap_alloc(&*sys, core::mem::size_of::<super::h2::H2State>() as u32);
    if raw.is_null() {
        return false;
    }
    // Initialise via H2State::zeroed() — `write_bytes(0)` would
    // leave `emit_cursor`, `file_owner`, `recv_window`,
    // `send_window`, and `peer_initial_window_size` at zero, which
    // makes every new stream's send_window 0 (RFC 7540 §6.9.2:
    // streams inherit peer_initial_window_size). h2 DATA emission
    // would then stall waiting for a WINDOW_UPDATE the peer has no
    // reason to send.
    core::ptr::write(raw as *mut super::h2::H2State, super::h2::H2State::zeroed());
    let slot_mut = &mut *s.server.slots.as_mut_ptr().add(idx);
    slot_mut.h2 = raw as *mut super::h2::H2State;
    true
}

/// Active slot's `recv_buf` const pointer; null when no slot or
/// the slot's heap allocation is missing (between close and the
/// next `alloc_free_slot`).
#[inline(always)]
pub(crate) unsafe fn cur_recv_buf_ptr(s: &HttpState) -> *const u8 {
    cur_slot(s)
        .map(|c| c.recv_buf as *const u8)
        .unwrap_or(core::ptr::null())
}

/// Active slot's `recv_buf` mut pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_recv_buf_mut_ptr(s: &mut HttpState) -> *mut u8 {
    cur_slot(s)
        .map(|c| c.recv_buf)
        .unwrap_or(core::ptr::null_mut())
}

/// Active slot's `send_buf` const pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_buf_ptr(s: &HttpState) -> *const u8 {
    cur_slot(s)
        .map(|c| c.send_buf as *const u8)
        .unwrap_or(core::ptr::null())
}

/// Active slot's `send_buf` mut pointer; null when no slot.
#[inline(always)]
pub(crate) unsafe fn cur_send_buf_mut_ptr(s: &mut HttpState) -> *mut u8 {
    cur_slot(s)
        .map(|c| c.send_buf)
        .unwrap_or(core::ptr::null_mut())
}

/// Active slot's `conn_id` as u8. The slot stores conn_id as i16
/// with `-1` meaning free; callers reaching this are only in-flight
/// phases where the slot is live (conn_id ≥ 0). The cast to u8
/// matches the wire format in MSG_ACCEPTED / CMD_SEND etc.
#[inline(always)]
pub(crate) unsafe fn cur_conn_id(s: &HttpState) -> u8 {
    cur_slot(s).map(|c| c.conn_id as u8).unwrap_or(0)
}

/// Number of slots currently in use (any phase other than `Init`
/// with a non-negative `conn_id`). Used by the step iterator to
/// know when to round-robin and by tests to assert occupancy.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub(crate) unsafe fn active_slot_count(s: &HttpState) -> usize {
    let mut count = 0;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if !slot.is_free() {
            count += 1;
        }
    }
    count
}

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
        log(s, b"[http] parse_route_body: body_pool NULL");
        return;
    }
    let offset = s.server.body_pool_used as usize;
    let cap = s.server.body_pool_cap as usize;
    let needed = offset + len;
    if needed > cap {
        // Grow the pool exponentially (doubling) until it fits, so
        // many small `parse_route_body` calls converge to amortised
        // O(1) regardless of total body size. Heap exhaustion drops
        // the bytes quietly — caller has no error path.
        let mut new_cap = cap.max(1);
        while new_cap < needed {
            new_cap = new_cap.saturating_mul(2);
        }
        let sys = s.syscalls;
        let new_pool = heap_realloc(&*sys, s.server.body_pool, new_cap as u32);
        if new_pool.is_null() {
            // Fall back to the truncate-at-cap behaviour so the
            // server still boots; the un-stored body bytes are
            // dropped.
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
                route.body_offset = offset as u32;
            }
            route.body_len += n as u32;
            s.server.body_pool_used = (offset + n) as u32;
            return;
        }
        s.server.body_pool = new_pool;
        s.server.body_pool_cap = new_cap as u32;
    }
    let mut i = 0;
    while i < len {
        *s.server.body_pool.add(offset + i) = *d.add(i);
        i += 1;
    }
    let route = &mut *s.server.routes.as_mut_ptr().add(idx);
    if route.body_len == 0 {
        route.body_offset = offset as u32;
    }
    route.body_len += len as u32;
    s.server.body_pool_used = (offset + len) as u32;
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    let sys = s.syscalls;
    s.server.var_chan = -1;
    s.server.file_chan = -1;
    s.server.file_chan_owner = -1;
    s.server.out_chan = -1;
    s.server.ws_out_chan = -1;
    s.server.ws_in_chan = -1;
    s.server.latest_fanout_slot = -1;
    // Dynamic-route subscription: sink resolved lazily on first pump.
    // The arena, shadow, and TableConsumer are zero-init (kernel
    // zero-fills state) — equivalent to `DynRoutes::new()` /
    // `TableConsumer::new()`.
    s.server.routes_sink = -1;
    // Dynamic-listener subscription: sink resolved lazily on first pump;
    // the table, shadow, bind records, and TableConsumer are zero-init.
    s.server.listeners_sink = -1;
    s.server.proxy_connect_owner = -1;
    s.server.port = 80;
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_fd = -1;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_total = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.fs_sent = 0;
    }
    // `matched_route`, `file_index`, `peer_closed`, `ws_fan_out`, and
    // `ws_pending_stuck_ticks` live in `ConnSlot`; the slot reset
    // below (`ConnSlot::reset`) zero-initializes them for every slot.

    // Multi-conn slots all start free (`conn_id = -1`,
    // `phase = Phase::Init`). The kernel zero-fills `module_state`
    // so we just need to set the `-1` sentinels — no heap activity
    // happens here; buffers are allocated on `alloc_free_slot` when
    // an MSG_ACCEPTED arrives.
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &mut *s.server.slots.as_mut_ptr().add(i);
        slot_init_zero(slot);
    }
    // Slot 0 owns the bind sequence (Init → Binding → WaitBound →
    // WaitAccept). Mark it ready so the iterator drives it; the
    // WaitBound→WaitAccept transition clears the bit, making the
    // slot truly idle until the demux re-allocates it.
    s.server.cur_slot = 0;
    s.server.step_cursor = 0;
    s.server.ready_bits = [0u64; READY_BITS_WORDS];
    ready_set(s, 0);
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::Init;
    }

    let pool = heap_alloc(&*sys, DEFAULT_BODY_POOL_SIZE as u32);
    if !pool.is_null() {
        s.server.body_pool = pool;
        s.server.body_pool_cap = DEFAULT_BODY_POOL_SIZE as u32;
    }

    // Retention buffer: server-wide snapshot of the most recent
    // burst on `ws_in`. Best-effort — if STATE_ARENA can't satisfy
    // a 2 MiB request we leave `retained_buf` null and the capture /
    // replay paths short-circuit (retention silently degrades to off,
    // producers must re-emit on every connect just like before).
    let retained = heap_alloc(&*sys, RETAINED_BUF_CAP as u32);
    if !retained.is_null() {
        s.server.retained_buf = retained;
        s.server.retained_cap = RETAINED_BUF_CAP as u32;
    } else {
        log(s, b"[http] retention disabled (no heap)");
    }
}

pub(crate) unsafe fn post_params(s: &mut HttpState) {
    let sys = &*s.syscalls;

    // Discover additional ports:
    //   in[1]  = variable updates  (FmpMessage)
    //   in[2]  = file data         (OctetStream)
    //   in[3]  = ws_in             (WsFrame, fan-out only)
    //   out[1] = file ctrl         (OctetStream)
    //   out[2] = ws_out            (WsFrame, fan-out only)
    s.server.var_chan = dev_channel_port(sys, 0, 1);
    s.server.file_chan = dev_channel_port(sys, 0, 2);
    s.server.ws_in_chan = dev_channel_port(sys, 0, 3);
    s.server.out_chan = dev_channel_port(sys, 1, 1);
    s.server.ws_out_chan = dev_channel_port(sys, 1, 2);

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
        let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr, 4);
        if r >= 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.file_count = count as u16;
            }
        }
    }

    // Diagnostic: dump each route's final body_len + offset so we
    // can pinpoint where body packing truncates without needing
    // browser dev tools.
    let mut i = 0u8;
    while i < s.server.route_count {
        let r = &*s.server.routes.as_ptr().add(i as usize);
        let mut buf = [0u8; 96];
        let p = buf.as_mut_ptr();
        let pfx = b"[http] route ";
        let mut q = 0usize;
        let mut t = 0;
        while t < pfx.len() {
            *p.add(q) = pfx[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), i as u32);
        let bl = b" body_len=";
        let mut t = 0;
        while t < bl.len() {
            *p.add(q) = bl[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), r.body_len);
        let bo = b" body_off=";
        let mut t = 0;
        while t < bo.len() {
            *p.add(q) = bo[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), r.body_offset);
        dev_log(&*s.syscalls, 2, p, q);
        i += 1;
    }
    {
        let mut buf = [0u8; 64];
        let p = buf.as_mut_ptr();
        let pfx = b"[http] body_pool used=";
        let mut q = 0usize;
        let mut t = 0;
        while t < pfx.len() {
            *p.add(q) = pfx[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), s.server.body_pool_used);
        let cp = b" cap=";
        let mut t = 0;
        while t < cp.len() {
            *p.add(q) = cp[t];
            q += 1;
            t += 1;
        }
        q += fmt_u32_raw(p.add(q), s.server.body_pool_cap);
        dev_log(&*s.syscalls, 2, p, q);
    }
    log(s, b"[http] server ready");
}

// ── Internal helpers ──────────────────────────────────────────────────────

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Try to claim exclusive use of `file_chan` for the active slot.
/// Returns `true` if the channel is now ours (either freshly claimed
/// or already held by us). Returns `false` if another slot owns it —
/// caller must stall in its current phase and retry on the next
/// tick.
///
/// Multi-conn safety: HANDLER_FILE / HANDLER_STREAM / HANDLER_TEMPLATE's
/// cache-fill path issue `IOCTL_FLUSH` + `IOCTL_NOTIFY` and then read
/// the response body across multiple step()s. Without serialisation
/// a second slot's FLUSH wipes the first's pending notify mid-fetch,
/// shredding the body. This guard linearises the channel.
#[inline]
unsafe fn try_acquire_file_chan(s: &mut HttpState) -> bool {
    let me = s.server.cur_slot;
    if me < 0 {
        return false;
    }
    let me = me as i16;
    let owner = s.server.file_chan_owner;
    if owner == me {
        return true;
    }
    if owner < 0 {
        s.server.file_chan_owner = me;
        return true;
    }
    false
}

/// Release `file_chan` ownership held by the active slot. No-op if
/// the channel was held by another slot (defensive — a misordered
/// release shouldn't free another slot's lock).
#[inline]
unsafe fn release_file_chan(s: &mut HttpState) {
    let me = s.server.cur_slot;
    if me < 0 {
        return;
    }
    if s.server.file_chan_owner == me as i16 {
        s.server.file_chan_owner = -1;
    }
}

/// Public wrapper for `try_acquire_file_chan` so h2 paths
/// (`begin_file_response`) can claim cross-slot ownership without
/// duplicating the helper.
#[cfg(feature = "h2")]
#[inline]
pub(crate) unsafe fn try_acquire_file_chan_external(s: &mut HttpState) -> bool {
    try_acquire_file_chan(s)
}

/// Public wrapper for `release_file_chan` so h2 error paths can
/// release on aborted fetch.
#[cfg(feature = "h2")]
#[inline]
pub(crate) unsafe fn release_file_chan_external(s: &mut HttpState) {
    release_file_chan(s);
}

unsafe fn reset_connection(s: &mut HttpState) {
    // Skip CMD_CLOSE if the peer already closed (`peer_closed` flag).
    // Otherwise the IP module would either no-op (empty slot) OR —
    // worse, under fast slot reuse — close the next browser connection
    // that just landed on the same slot index.
    let peer_closed = cur_slot(s).map(|c| c.peer_closed).unwrap_or(0);
    if peer_closed == 0 && cur_phase(s) as u8 > Phase::WaitAccept as u8 && s.net_out_chan >= 0 {
        close_net_conn(s, cur_conn_id(s));
    }
    // Close any FS_CONTRACT FD left open by a previous response. The
    // FS dispatch handles CLOSE on a mid-stream slot, so this is safe
    // even if the connection dropped before we reached EOF.
    if cur_fs_fd(s) >= 0 {
        ((*s.syscalls).provider_call)(
            cur_fs_fd(s),
            0x0903, // FS_CLOSE
            core::ptr::null_mut(),
            0,
        );
    }
    // Proxy relay teardown: close the upstream backend conn (if any,
    // and not already closed by the peer) and drop any serialised
    // connect ownership this slot held.
    let (backend, backend_closed) = match cur_slot(s) {
        Some(c) => (c.backend_conn_id, c.backend_closed),
        None => (-1, 0),
    };
    if backend >= 0 && backend_closed == 0 && s.net_out_chan >= 0 {
        close_net_conn(s, backend as u8);
    }
    if let Some(idx) = current_slot_index(s) {
        if s.server.proxy_connect_owner == idx as i16 {
            s.server.proxy_connect_owner = -1;
        }
    }
    // Release the slot's heap buffers (recv_buf, send_buf) and zero
    // every per-conn field so the next `alloc_free_slot` call can
    // reuse the slot cleanly. The `is_free()` predicate now reads
    // `phase=Init && conn_id<0` — both set by `slot_init_zero`
    // inside `slot_release_buffers`. Idle slots cost only their
    // ~250 B inline metadata; the heap buffers are returned to the
    // arena for the next accept (or any other allocator caller).
    if let Some(idx) = current_slot_index(s) {
        slot_release_buffers(s, idx);
    }
}

/// Returns `Some(idx)` when `cur_slot >= 0`, otherwise `None`.
/// Useful when you need the slot index (not just the slot itself)
/// to call slot-lifecycle helpers.
#[inline(always)]
unsafe fn current_slot_index(s: &HttpState) -> Option<usize> {
    let idx = s.server.cur_slot;
    if idx < 0 || (idx as usize) >= MAX_CONCURRENT_CONNS {
        None
    } else {
        Some(idx as usize)
    }
}

unsafe fn close_net_conn(s: &mut HttpState, conn_id: u8) {
    if s.net_out_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 1];
    payload[0] = conn_id;
    net_write_frame(
        sys,
        chan,
        NET_CMD_CLOSE,
        payload.as_ptr(),
        1,
        buf,
        NET_BUF_SIZE,
    );
}

// ── Proxy relay (rfc_workload_ingress §3) ─────────────────────────────
//
// A `HANDLER_PROXY` static route (`proxy_ip/port`) or a dynamic-route
// match dials an upstream backend and relays bytes both ways within the
// slot's existing arenas: `recv_buf` is the client→backend window,
// `send_buf` the backend→client window. No transformation, no extra
// buffering; content-length and chunked bodies pass through as bytes.

/// Wall-clock budget for a backend connect before failover / 502.
const PROXY_CONNECT_TIMEOUT_MS: u32 = 10_000;

/// Find the slot whose upstream `backend_conn_id` matches `conn`.
unsafe fn find_slot_by_backend_conn(s: &HttpState, conn: u8) -> Option<usize> {
    let needle = conn as i16;
    for i in 0..MAX_CONCURRENT_CONNS {
        let slot = &*s.server.slots.as_ptr().add(i);
        if slot.backend_conn_id == needle {
            return Some(i);
        }
    }
    None
}

/// True while a slot is in a byte-relay phase (request already
/// forwarded). Demux stages backend→client bytes into `send_buf` only
/// in these phases.
#[inline(always)]
fn is_proxy_relay_phase(p: Phase) -> bool {
    matches!(p, Phase::ProxyRelayHeaders | Phase::ProxyRelayBody)
}

/// Append a dotted-quad IPv4 (`a.b.c.d`) for a big-endian-packed u32.
unsafe fn put_ipv4_decimal(dst: *mut u8, cap: usize, mut off: usize, ip: u32) -> usize {
    let o = ip.to_be_bytes();
    off = put_u32_decimal(dst, cap, off, o[0] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[1] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[2] as u32);
    off = put_bytes(dst, cap, off, b".");
    off = put_u32_decimal(dst, cap, off, o[3] as u32);
    off
}

/// Dial the active slot's selected backend via the runtime
/// `NET_CMD_CONNECT` primitive — the exact payload the client side
/// uses (`[sock_type][ip:4][port:2][requester_tag]`), reused
/// server-side. Returns `true` when the CONNECT frame was written.
unsafe fn proxy_dial(s: &mut HttpState) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    let (ip, port) = match cur_slot(s) {
        Some(c) => (c.proxy_be_ip, c.proxy_be_port),
        None => return false,
    };
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let ip_bytes = ip.to_le_bytes();
    let mut payload = [0u8; 8];
    payload[0] = SOCK_TYPE_STREAM;
    payload[1] = ip_bytes[0];
    payload[2] = ip_bytes[1];
    payload[3] = ip_bytes[2];
    payload[4] = ip_bytes[3];
    payload[5] = (port & 0xFF) as u8;
    payload[6] = (port >> 8) as u8;
    payload[7] = dev_requester_tag(sys);
    let wrote = net_write_frame(
        sys,
        chan,
        NET_CMD_CONNECT,
        payload.as_ptr(),
        8,
        buf,
        NET_BUF_SIZE,
    );
    wrote != 0
}

/// Enter the proxy relay for the active slot against a chosen backend.
/// `dyn_idx` is the dynamic-route index (for failover reselection) or
/// `-1` for a static `HANDLER_PROXY` route. Proxy responses are
/// close-delimited in v1 (no response parsing / keep-alive).
unsafe fn begin_proxy(s: &mut HttpState, ip: u32, port: u16, dyn_idx: i16) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.proxy_be_ip = ip;
        cur.proxy_be_port = port;
        cur.proxy_dyn_idx = dyn_idx;
        cur.proxy_attempt = 0;
        cur.backend_conn_id = -1;
        cur.proxy_connected = 0;
        cur.proxy_connect_failed = 0;
        cur.backend_closed = 0;
        cur.proxy_creq_off = 0;
        cur.keepalive = 0; // v1 relay is close-delimited
        cur.phase = Phase::ProxyConnect;
    }
}

/// A backend connect failed (error or timeout): one retry against the
/// next `ready=1` dynamic backend (advancing `rr_cursor`), else a
/// terminal 502. Counts `http.proxy.retries` / `http.proxy.5xx`.
unsafe fn proxy_connect_failed(s: &mut HttpState) {
    if let Some(idx) = current_slot_index(s) {
        if s.server.proxy_connect_owner == idx as i16 {
            s.server.proxy_connect_owner = -1;
        }
    }
    let (attempt, dyn_idx) = match cur_slot(s) {
        Some(c) => (c.proxy_attempt, c.proxy_dyn_idx),
        None => (2, -1),
    };
    if attempt == 0 && dyn_idx >= 0 && (dyn_idx as usize) < MAX_DYN_ROUTES {
        let next = s.server.dyn_routes.live[dyn_idx as usize].select_backend();
        if let Some((ip, port)) = next {
            s.server.proxy_retries = s.server.proxy_retries.wrapping_add(1);
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_be_ip = ip;
                cur.proxy_be_port = port;
                cur.proxy_attempt = 1;
                cur.backend_conn_id = -1;
                cur.proxy_connected = 0;
                cur.proxy_connect_failed = 0;
                cur.phase = Phase::ProxyConnect;
            }
            return;
        }
    }
    s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
    build_error(s, b"502 Bad Gateway", b"Backend unavailable\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::DrainSend;
    }
}

/// Build the request head to forward to the backend into `send_buf`:
/// the parsed request line + headers with an appended
/// `X-Forwarded-For: <client-ip>` (net-new serialization — the relay
/// owns it). The Host header passes through unchanged (v1). Any client
/// body bytes already buffered after the head are compacted to the
/// front of `recv_buf` for the client→backend relay.
unsafe fn proxy_build_forward_head(s: &mut HttpState) {
    let (heo, recv_len, client_ip) = match cur_slot(s) {
        Some(c) => (c.header_end_off as usize, c.recv_len as usize, c.client_ip),
        None => return,
    };
    let recv = cur_recv_buf_ptr(s);
    let send = cur_send_buf_mut_ptr(s);
    if recv.is_null() || send.is_null() || heo < 4 {
        return;
    }
    // Keep everything up to (but not including) the terminating blank
    // line, so XFF splices in as the final header.
    let head_body = heo - 2;
    let mut off = 0usize;
    off = put_bytes(
        send,
        SEND_BUF_SIZE,
        off,
        core::slice::from_raw_parts(recv, head_body),
    );
    off = put_bytes(send, SEND_BUF_SIZE, off, b"X-Forwarded-For: ");
    off = put_ipv4_decimal(send, SEND_BUF_SIZE, off, client_ip);
    off = put_bytes(send, SEND_BUF_SIZE, off, b"\r\n\r\n");
    let leftover = recv_len.saturating_sub(heo);
    if leftover > 0 {
        let rbuf = cur_recv_buf_mut_ptr(s);
        core::ptr::copy(rbuf.add(heo), rbuf, leftover);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
        cur.proxy_creq_off = 0;
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// One bidirectional relay tick: drain buffered client bytes to the
/// backend (`recv_buf`) and buffered backend bytes to the client
/// (`send_buf`). Tears the slot down once the backend has closed and
/// its last bytes have flushed to the client.
unsafe fn proxy_relay_step(s: &mut HttpState) {
    let (backend, client, recv_len, creq_off, send_len, send_off) = match cur_slot(s) {
        Some(c) => (
            c.backend_conn_id,
            c.conn_id,
            c.recv_len,
            c.proxy_creq_off,
            c.send_len,
            c.send_offset,
        ),
        None => return,
    };
    // client → backend
    if backend >= 0 && recv_len > creq_off {
        let remaining = (recv_len - creq_off) as usize;
        let sent = net_send_conn(
            s,
            backend as u8,
            cur_recv_buf_ptr(s).add(creq_off as usize),
            remaining,
        );
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_creq_off += sent as u16;
                if cur.proxy_creq_off >= cur.recv_len {
                    cur.recv_len = 0;
                    cur.proxy_creq_off = 0;
                }
            }
        }
    }
    // backend → client
    if send_len > send_off {
        let remaining = (send_len - send_off) as usize;
        let sent = net_send_conn(
            s,
            client as u8,
            cur_send_buf_ptr(s).add(send_off as usize),
            remaining,
        );
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
                if cur.send_offset >= cur.send_len {
                    cur.send_len = 0;
                    cur.send_offset = 0;
                }
            }
        }
    }
    // Teardown: backend closed + its bytes fully flushed → close the
    // client (`edge_anchored`: no session migration, §5).
    let (backend_closed, send_len2, send_off2) = match cur_slot(s) {
        Some(c) => (c.backend_closed, c.send_len, c.send_offset),
        None => return,
    };
    if backend_closed != 0 && send_len2 == send_off2 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
    }
}

/// Consult the dynamic-route table for a proxy match on the active
/// slot's Host + path (§5: host exact, then longest path-prefix, then
/// readiness-gated backend selection). Returns `true` when it took
/// over dispatch (started a relay or emitted a 502); `false` when no
/// dynamic route matched (caller falls back to its fixed surface).
unsafe fn try_begin_dyn_proxy(s: &mut HttpState) -> bool {
    let (heo, rp_ptr, rp_len, recv_ptr) = match cur_slot(s) {
        Some(c) => (
            c.header_end_off as usize,
            c.req_path.as_ptr(),
            c.req_path_len as usize,
            c.recv_buf as *const u8,
        ),
        None => return false,
    };
    if recv_ptr.is_null() || heo == 0 {
        return false;
    }
    let host = match ws::find_header_value(recv_ptr, heo, b"Host") {
        Some((o, n)) => core::slice::from_raw_parts(recv_ptr.add(o), n),
        None => &[],
    };
    let path = core::slice::from_raw_parts(rp_ptr, rp_len);
    let di = match_dyn_route(&s.server.dyn_routes, host, path);
    if di < 0 {
        return false;
    }
    match s.server.dyn_routes.live[di as usize].select_backend() {
        Some((ip, port)) => {
            begin_proxy(s, ip, port, di as i16);
            true
        }
        None => {
            // Matched a route but no `ready=1` backend (§5 readiness gate).
            s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
            build_error(s, b"502 Bad Gateway", b"No ready backend\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            true
        }
    }
}

pub(crate) unsafe fn match_route(s: &HttpState) -> i8 {
    let cur = match cur_slot(s) {
        Some(c) => c,
        None => return -1,
    };
    match_route_path(s, cur.req_path.as_ptr(), cur.req_path_len as usize)
}

/// Path-based variant of `match_route` for callers that need to
/// resolve a route without mutating `cur_slot.req_path` first
/// (notably H2's `needs_exclusive_for_request`, which must check
/// the same matching rules dispatch will apply but is called
/// before the active slot is committed to a particular stream's
/// path). Returns the route index, or -1 if no route matches.
pub(crate) unsafe fn match_route_path(s: &HttpState, req: *const u8, plen: usize) -> i8 {
    // Routes are exact-match by default. A route that ends in '/' is
    // treated as a prefix match (so `/api/` matches `/api/foo`), but a
    // bare `/` is exact-only — otherwise it would swallow every
    // unmatched path including `/favicon.ico`, returning the wrong
    // body on requests that should have 404'd. Among prefix-eligible
    // candidates the longest-matching wins; ties resolve to the lower
    // index. Returns -1 when no route matches → caller returns 404.
    let mut best: i8 = -1;
    let mut best_len: usize = 0;
    let mut i = 0u8;
    while (i as usize) < s.server.route_count as usize {
        let route = &*s.server.routes.as_ptr().add(i as usize);
        let rlen = route.path_len as usize;
        if rlen == 0 {
            i += 1;
            continue;
        }
        let path_ptr = route.path.as_ptr();
        // Exact match wins outright.
        if rlen == plen {
            let mut j = 0;
            let mut ok = true;
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
        // Prefix match: requires the route path to end with '/' AND
        // the request to be strictly longer. Skips short root '/'.
        let route_is_prefix = rlen >= 2 && *path_ptr.add(rlen - 1) == b'/';
        if route_is_prefix && plen > rlen && rlen > best_len {
            let mut j = 0;
            let mut ok = true;
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                best = i as i8;
                best_len = rlen;
            }
        }
        // HANDLER_FS_LIST routes implicitly serve individual files at
        // `<route_path>/<filename>` (in addition to the JSON listing
        // they serve at the exact route path). The implicit-prefix
        // matcher fires only when the route path does NOT already
        // end in '/' (otherwise the explicit-prefix branch above
        // covers it) and the next byte after the prefix is '/'
        // (the listing-vs-file separator). The handler decides the
        // listing-vs-file split based on whether req == route_path.
        if !route_is_prefix
            && route.handler == HANDLER_FS_LIST
            && plen > rlen + 1
            && rlen > best_len
            && *req.add(rlen) == b'/'
        {
            let mut j = 0;
            let mut ok = true;
            while j < rlen {
                if *req.add(j) != *path_ptr.add(j) {
                    ok = false;
                    break;
                }
                j += 1;
            }
            if ok {
                best = i as i8;
                best_len = rlen;
            }
        }
        i += 1;
    }
    best
}

/// Map a request path's file-extension suffix to a MIME type.
/// Returns an empty slice when no extension is recognised — caller
/// falls back to `application/octet-stream`.
///
/// Used by the AwaitFsStat content-type resolver when the matched
/// route has no explicit `content_type:` (HANDLER_FS_LIST file-serve
/// path — see the dual-mode dispatch). Recognises the common image
/// / audio / web mime types the scenario host pages serve plus a
/// few generic text formats. Anything outside this small whitelist
/// falls through to octet-stream — sniffing arbitrary bytes is a
/// bigger ABI question we don't take a position on here.
unsafe fn content_type_from_path(path: *const u8, plen: usize) -> &'static [u8] {
    // Find the last '.' in the path (after the last '/').
    let mut dot: Option<usize> = None;
    let mut last_slash: usize = 0;
    let mut i = 0;
    while i < plen {
        let b = *path.add(i);
        if b == b'/' {
            last_slash = i + 1;
            dot = None;
        } else if b == b'.' {
            dot = Some(i);
        }
        i += 1;
    }
    let start = match dot {
        Some(d) if d + 1 > last_slash => d + 1,
        _ => return &[],
    };
    let ext_len = plen - start;
    if ext_len == 0 || ext_len > 8 {
        return &[];
    }
    // ASCII-lowercase scratch.
    let mut buf = [0u8; 8];
    for (k, slot) in buf.iter_mut().enumerate().take(ext_len) {
        let mut b = *path.add(start + k);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        *slot = b;
    }
    let ext = &buf[..ext_len];
    match ext {
        b"html" | b"htm" => b"text/html",
        b"css" => b"text/css",
        b"js" | b"mjs" => b"application/javascript",
        b"json" => b"application/json",
        b"wasm" => b"application/wasm",
        b"png" => b"image/png",
        b"jpg" | b"jpeg" => b"image/jpeg",
        b"gif" => b"image/gif",
        b"bmp" => b"image/bmp",
        b"webp" => b"image/webp",
        b"svg" => b"image/svg+xml",
        b"ico" => b"image/x-icon",
        b"wav" => b"audio/wav",
        b"mp3" => b"audio/mpeg",
        b"aac" => b"audio/aac",
        b"ogg" => b"audio/ogg",
        b"mp4" => b"video/mp4",
        b"txt" => b"text/plain",
        b"xml" => b"application/xml",
        _ => &[],
    }
}

/// Close-delimited response header (no Content-Length). Forces
/// `Connection: close` and clears the slot's keepalive flag. For
/// self-delimited responses use `build_header_with_len` /
/// `build_header_fs_full` / `build_header_fs_partial` so keep-alive
/// is preserved.
unsafe fn build_header(s: &mut HttpState, status: &[u8], content_type: &[u8]) {
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let len = h1::write_status_line(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        status,
        content_type,
        false,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = len as u16;
    }
}

/// Like `build_header` but also emits a `Content-Length: <n>` header.
/// Used for responses whose body length is known up-front (e.g. the
/// FS_CONTRACT path queries `FS_STAT` for the file size before
/// streaming).
unsafe fn build_header_with_len(
    s: &mut HttpState,
    status: &[u8],
    content_type: &[u8],
    content_length: u32,
) {
    // Write the standard status line (which terminates with \r\n\r\n)
    // then strip the trailing blank line, append the Content-Length
    // header, and re-terminate.
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let mut off = h1::write_status_line(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        status,
        content_type,
        keepalive,
    );
    if off >= 4 {
        off -= 4;
    }
    let dst = cur_send_buf_mut_ptr(s);
    let prefix: &[u8] = b"\r\nContent-Length: ";
    let mut k = 0usize;
    while k < prefix.len() && off < SEND_BUF_SIZE {
        *dst.add(off) = prefix[k];
        off += 1;
        k += 1;
    }
    // Decimal Content-Length value (max 10 digits for u32).
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    let mut v = content_length;
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    while n > 0 {
        n -= 1;
        if off < SEND_BUF_SIZE {
            *dst.add(off) = digits[n];
            off += 1;
        }
    }
    let suffix: &[u8] = b"\r\n\r\n";
    let mut k = 0usize;
    while k < suffix.len() && off < SEND_BUF_SIZE {
        *dst.add(off) = suffix[k];
        off += 1;
        k += 1;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = off as u16;
    }
}

unsafe fn build_error(s: &mut HttpState, code: &[u8], body: &[u8]) {
    // Error responses are close-delimited — keep wire + slot in sync.
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let len = h1::write_error_response(cur_send_buf_mut_ptr(s), SEND_BUF_SIZE, code, body);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = len as u16;
    }
}

/// Append a decimal u32 at `off` in `dst`, returning the new offset.
/// Helper for the Content-Range / Content-Length writers below.
unsafe fn put_u32_decimal(dst: *mut u8, dst_cap: usize, mut off: usize, mut v: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    if v == 0 {
        digits[0] = b'0';
        n = 1;
    } else {
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    while n > 0 {
        n -= 1;
        if off < dst_cap {
            *dst.add(off) = digits[n];
            off += 1;
        }
    }
    off
}

unsafe fn put_bytes(dst: *mut u8, dst_cap: usize, mut off: usize, src: &[u8]) -> usize {
    let mut k = 0usize;
    while k < src.len() && off < dst_cap {
        *dst.add(off) = src[k];
        off += 1;
        k += 1;
    }
    off
}

/// Like `build_header_with_len` but also emits `Accept-Ranges: bytes`
/// so clients (browser media elements, iOS players, curl) know they
/// can seek. Used by `HANDLER_FS_FILE` on the no-Range happy path.
unsafe fn build_header_fs_full(
    s: &mut HttpState,
    status: &[u8],
    content_type: &[u8],
    content_length: u32,
) {
    let cap = SEND_BUF_SIZE;
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = h1::write_status_line(dst, cap, status, content_type, keepalive);
    if off >= 4 {
        off -= 4; // strip the trailing \r\n\r\n; we'll re-add it.
    }
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nAccept-Ranges: bytes\r\nContent-Length: ",
    );
    off = put_u32_decimal(dst, cap, off, content_length);
    off = put_bytes(dst, cap, off, b"\r\n\r\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// Compose a 206 Partial Content head: status line + Content-Type +
/// Accept-Ranges + Content-Range + Content-Length, terminated by the
/// blank line. `start`/`end` are inclusive byte offsets into the file;
/// `total` is the full file size.
unsafe fn build_header_fs_partial(
    s: &mut HttpState,
    content_type: &[u8],
    start: u32,
    end: u32,
    total: u32,
) {
    let cap = SEND_BUF_SIZE;
    let keepalive = cur_slot(s).map(|c| c.keepalive != 0).unwrap_or(false);
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = h1::write_status_line(dst, cap, b"206 Partial Content", content_type, keepalive);
    if off >= 4 {
        off -= 4;
    }
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nAccept-Ranges: bytes\r\nContent-Range: bytes ",
    );
    off = put_u32_decimal(dst, cap, off, start);
    off = put_bytes(dst, cap, off, b"-");
    off = put_u32_decimal(dst, cap, off, end);
    off = put_bytes(dst, cap, off, b"/");
    off = put_u32_decimal(dst, cap, off, total);
    off = put_bytes(dst, cap, off, b"\r\nContent-Length: ");
    off = put_u32_decimal(dst, cap, off, end - start + 1);
    off = put_bytes(dst, cap, off, b"\r\n\r\n");
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
}

/// 416 Range Not Satisfiable response: status line + `Content-Range:
/// bytes */<total>` so the client learns the resource length.
unsafe fn build_error_416(s: &mut HttpState, total: u32) {
    // Close-delimited error — keep wire + slot in sync.
    if let Some(cur) = cur_slot_mut(s) {
        cur.keepalive = 0;
    }
    let cap = SEND_BUF_SIZE;
    let dst = cur_send_buf_mut_ptr(s);
    let mut off = put_bytes(
        dst,
        cap,
        0,
        b"HTTP/1.1 416 Range Not Satisfiable\r\nConnection: close\r\nContent-Range: bytes */",
    );
    off = put_u32_decimal(dst, cap, off, total);
    off = put_bytes(
        dst,
        cap,
        off,
        b"\r\nContent-Length: 22\r\n\r\nRange Not Satisfiable\n",
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
        cur.send_len = off as u16;
    }
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
    let count = s.server.var_count as usize;
    let mut i = 0usize;
    while i < count {
        let var = &*s.server.vars.as_ptr().add(i);
        if var.name_hash == hash {
            return (var.value.as_ptr(), var.value_len as usize);
        }
        i += 1;
    }
    (core::ptr::null(), 0)
}

// ── LRU content cache ──────────────────────────────────────────────────────

/// Find a fully-filled cache entry for `route_idx`. Used by the hit
/// paths (`cache_try_or_fetch`, h1 inline `HANDLER_STATIC`/`TEMPLATE`)
/// — returns -1 for entries that are still mid-fill so a sibling
/// request doesn't render zero/partial bytes from `body_pool` while
/// the original fetch is in flight.
unsafe fn cache_lookup(s: &HttpState, route_idx: u8) -> i8 {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        let usable = e.flags & (CACHE_VALID | CACHE_COMPLETE);
        if usable == (CACHE_VALID | CACHE_COMPLETE) && e.route_index == route_idx {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Find any cache entry for `route_idx`, regardless of fill state.
/// Used by `cache_retain_for_route` / `cache_release_for_route` so
/// the refcount on an in-flight entry stays balanced even before
/// the fill completes (e.g. a stream is closed mid-fetch).
unsafe fn cache_lookup_any(s: &HttpState, route_idx: u8) -> i8 {
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

/// True when no cache entry is currently held by an in-flight
/// reader. Callers that want to evict (or recycle the body_pool
/// arena offsets) must check this first; an evict-while-reading
/// would corrupt the reader's view of the body_pool region.
unsafe fn cache_evictable(s: &HttpState) -> bool {
    let mut i = 0usize;
    while i < s.server.cache_count as usize {
        let e = &*s.server.cache_entries.as_ptr().add(i);
        if (e.flags & CACHE_VALID) != 0 && e.retain > 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Increment the reader refcount on the cache entry currently
/// caching `route_idx`. Uses `cache_lookup_any` so retain works
/// even before `CACHE_COMPLETE` is set (matters for the
/// fetch-in-progress path: the fetch's eventual completion
/// retains, and concurrent retain/release on the same entry must
/// find it). No-op if no such entry exists.
pub(crate) unsafe fn cache_retain_for_route(s: &mut HttpState, route_idx: u8) {
    let ci = cache_lookup_any(s, route_idx);
    if ci < 0 {
        return;
    }
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
    e.retain = e.retain.saturating_add(1);
}

/// Decrement the reader refcount on the cache entry currently
/// caching `route_idx`. No-op if no such entry exists or the
/// counter is already zero (defensive — a misordered release
/// shouldn't underflow).
pub(crate) unsafe fn cache_release_for_route(s: &mut HttpState, route_idx: u8) {
    let ci = cache_lookup_any(s, route_idx);
    if ci < 0 {
        return;
    }
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(ci as usize);
    if e.retain > 0 {
        e.retain -= 1;
    }
}

unsafe fn cache_evict_all(s: &mut HttpState) -> u32 {
    s.server.cache_count = 0;
    let mut inline_end: u32 = 0;
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

/// Returns -1 if any existing cache entry has `retain > 0` —
/// caller must defer (treat as Busy) and retry on a later tick.
/// Otherwise evicts all entries, allocates a fresh entry at idx 0
/// for `route_idx`, and returns 0.
unsafe fn cache_alloc(s: &mut HttpState, route_idx: u8) -> i32 {
    if !cache_evictable(s) {
        return -1;
    }
    let arena_end: u32 = cache_evict_all(s);

    let idx = 0usize;
    let e = &mut *s.server.cache_entries.as_mut_ptr().add(idx);
    e.route_index = route_idx;
    e.flags = CACHE_VALID;
    e.retain = 0;
    s.server.cache_tick = s.server.cache_tick.wrapping_add(1);
    e.lru_tick = s.server.cache_tick;
    e.arena_offset = arena_end;
    e.length = 0;
    s.server.cache_count = 1;
    idx as i32
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
    /// `file_chan` is currently held by another slot. Caller should
    /// mark the stream Fetching anyway and retry on subsequent ticks
    /// — `drive_cache_fetch` re-attempts `cache_try_or_fetch` until
    /// the lock frees, at which point it transitions to `Pending`
    /// and the normal fetch flow resumes.
    Busy,
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
        // Retain the entry while emission is in flight — without
        // this, a sibling cache miss could evict and reuse the
        // body_pool region we're about to render from. Caller
        // releases via `cache_release_for_route` at end-of-emission.
        ce.retain = ce.retain.saturating_add(1);
        let r = &mut *s.server.routes.as_mut_ptr().add(route_idx as usize);
        r.body_offset = ce.arena_offset;
        r.body_len = ce.length;
        return CacheLookup::Hit;
    }
    // Cross-slot serialisation: only one slot may hold `file_chan`
    // at a time. If another slot is mid-fetch, return Busy without
    // issuing IOCTL or claiming a cache slot — caller marks the
    // stream Fetching and `drive_cache_fetch` will retry on the
    // next tick. Without this gate, two concurrent h2 streams or
    // an h1 + h2 race would both call FLUSH/NOTIFY and shred each
    // other's pending fetch.
    if !try_acquire_file_chan(s) {
        return CacheLookup::Busy;
    }
    // Cache_alloc returns -1 if the existing entry is retained by
    // an in-flight reader — in that case we can't repurpose the
    // body_pool region without corrupting the reader's view.
    // Defer (Busy) and release the file_chan lock so progress can
    // still happen elsewhere; we'll retry next tick.
    if cache_alloc(s, route_idx as u8) < 0 {
        release_file_chan(s);
        return CacheLookup::Busy;
    }
    dev_channel_ioctl(
        &*s.syscalls,
        s.server.file_chan,
        IOCTL_FLUSH,
        core::ptr::null_mut(),
        0,
    );
    let mut pos = src_idx as u32;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr, 4);
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
    let hup_pre = poll > 0 && (poll as u32 & POLL_HUP) != 0;
    if !in_ready && !hup_pre {
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
            ce.length += n as u32;
            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(n as u32);
        }
    }

    // Re-poll AFTER the read so HUP only counts as EOF when no
    // more bytes are pending. The pre-read poll can show POLL_IN +
    // POLL_HUP simultaneously when there's still data to drain
    // — taking that as EOF prematurely truncates files larger than
    // SEND_BUF_SIZE (one read per tick is the plumbing limit).
    // Mirrors the h1 `Phase::CacheStream` path, which has always
    // got this right.
    let poll_after = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
    let in_after = poll_after > 0 && (poll_after as u32 & POLL_IN) != 0;
    let hup_after = poll_after > 0 && (poll_after as u32 & POLL_HUP) != 0;
    let eof = hup_after && !in_after;

    let new_len = ce.length as usize;
    let full = (arena_off + new_len) >= pool_cap;
    if eof || full {
        ce.flags |= CACHE_COMPLETE;
        // Retain on behalf of the imminent reader (the stream that
        // requested this fetch). Without this, a sibling cache
        // miss arriving in the same tick before the reader runs
        // could evict and overwrite the body_pool region.
        ce.retain = ce.retain.saturating_add(1);
        // Resolve the route from the CACHE ENTRY, not from
        // `cur_matched_route` on the active slot. h2's
        // `dispatch_request` mutates the slot's matched_route every
        // time it picks up a new pending stream; if the slot has
        // moved on to dispatching another stream while this fetch
        // was completing, `cur_matched_route` would point at the
        // wrong route and we'd publish the cache body's offset/len
        // there. The cache entry remembers which route it was
        // allocated for — that's the canonical answer.
        let ri = ce.route_index as usize;
        if ri < MAX_ROUTES {
            let r = &mut *s.server.routes.as_mut_ptr().add(ri);
            r.body_offset = ce.arena_offset;
            r.body_len = ce.length;
        }
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
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + (*cur_ptr).tmpl_pos as usize;
    if pos >= body_end || cap == 0 {
        return (0, pos < body_end);
    }
    let n = (body_end - pos).min(cap);
    let src = (s.server.body_pool as *const u8).add(pos);
    core::ptr::copy_nonoverlapping(src, dst, n);
    (*cur_ptr).tmpl_pos += n as u32;
    let more = (pos + n) < body_end;
    (n, more)
}

/// Render a template body chunk with `{{var}}` substitution into `dst`.
pub(crate) unsafe fn render_template_into(
    s: &mut HttpState,
    dst: *mut u8,
    cap: usize,
) -> (usize, bool) {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pool = s.server.body_pool as *const u8;
    let mut out = 0usize;
    let mut pos = body_start + (*cur_ptr).tmpl_pos as usize;

    while pos < body_end && out < cap {
        if pos + 1 < body_end && *pool.add(pos) == b'{' && *pool.add(pos + 1) == b'{' {
            // Look the variable up first so the headroom check uses
            // its actual width rather than the worst-case bound — a
            // tight `cap` (e.g. send_window-capped) can still emit a
            // small value that wouldn't have cleared `MAX_VAR_VALUE`.
            let saved_pos = pos;
            pos += 2;
            let mut hash: u32 = 0x811c9dc5;
            while pos + 1 < body_end && !(*pool.add(pos) == b'}' && *pool.add(pos + 1) == b'}') {
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

    (*cur_ptr).tmpl_pos = (pos - body_start) as u32;
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
        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(n as u32);
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
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return (0, false),
    };
    let mut off = 0usize;
    let mut idx = (*cur_ptr).index_pos;
    let file_count = (*cur_ptr).file_count;
    while idx < file_count && off + 7 < cap {
        off += fmt_u32_raw(dst.add(off), idx as u32);
        *dst.add(off) = b'\n';
        off += 1;
        idx += 1;
    }
    (*cur_ptr).index_pos = idx;
    (off, idx < file_count)
}

/// h1 template wrapper — writes a chunk into `send_buf` and updates
/// `send_offset`/`send_len` so the existing `step_send_template` flow
/// can flush it.
unsafe fn render_template_chunk(s: &mut HttpState) -> bool {
    let buf = cur_send_buf_mut_ptr(s);
    let (n, more) = render_template_into(s, buf, SEND_BUF_SIZE);
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = n as u16;
    }
    more
}

// ── Legacy file mode helpers ──────────────────────────────────────────────

pub(crate) unsafe fn parse_file_index(s: &HttpState) -> i16 {
    let cur = match cur_slot(s) {
        Some(c) => c,
        None => return -1,
    };
    let buf = cur.req_path.as_ptr();
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let suffix_start = route.path_len as usize;
    let path_end = cur.req_path_len as usize;

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

/// Returns `true` if the dispatch handled the request (advanced the
/// phase to SendHeaders / DrainSend). Returns `false` if `file_chan`
/// is currently held by another slot — caller should stay in
/// DispatchRoute and retry on the next tick.
unsafe fn step_legacy_file_dispatch(s: &mut HttpState) -> bool {
    let (buf, plen) = match cur_slot(s) {
        Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
        None => return true,
    };

    if plen == 1 && *buf == b'/' {
        if s.server.file_chan >= 0 {
            // POLL_NOTIFY is read-only and doesn't trample pending
            // FLUSH/NOTIFY state, but we still gate behind the
            // cross-slot lock so a concurrent slot can't observe
            // a half-modified channel state.
            if !try_acquire_file_chan(s) {
                return false;
            }
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(
                &*s.syscalls,
                s.server.file_chan,
                IOCTL_POLL_NOTIFY,
                count_ptr,
                4,
            );
            if r >= 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.file_count = count as u16;
                }
            }
        }
        build_header(s, b"200 OK", b"text/plain");
        if let Some(cur) = cur_slot_mut(s) {
            cur.index_pos = 0;
            cur.file_index = -1;
            cur.matched_route = -1;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::SendHeaders;
        }
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
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return true;
        }

        if let Some(cur) = cur_slot_mut(s) {
            cur.file_index = idx as i16;
            cur.matched_route = -1;
        }
        if s.server.file_chan >= 0 {
            // Cross-slot serialisation for the FLUSH/NOTIFY pair.
            // If another slot owns the channel, leave the slot in
            // DispatchRoute and retry next tick.
            if !try_acquire_file_chan(s) {
                return false;
            }
            dev_channel_ioctl(
                &*s.syscalls,
                s.server.file_chan,
                IOCTL_FLUSH,
                core::ptr::null_mut(),
                0,
            );
            let mut pos = idx as u32;
            let pos_ptr = &mut pos as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(&*s.syscalls, s.server.file_chan, IOCTL_NOTIFY, pos_ptr, 4);
            if r < 0 {
                build_error(s, b"404 Not Found", b"Not Found\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return true;
            }
            build_header(s, b"200 OK", b"application/octet-stream");
        } else {
            build_error(s, b"404 Not Found", b"Not Found\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return true;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::SendHeaders;
        }
    } else {
        build_error(s, b"400 Bad Request", b"Bad Request\n");
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::DrainSend;
        }
    }
    true
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
    let buf = cur_recv_buf_ptr(s);
    let len = cur_recv_len(s) as usize;

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
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return false;
        }
    };

    let mut accept = [0u8; 28];
    ws::compute_accept(buf.add(key_off), key_len, accept.as_mut_ptr());

    let written =
        ws::write_handshake_response(cur_send_buf_mut_ptr(s), SEND_BUF_SIZE, accept.as_ptr());
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = written as u16;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_parsed = 0;
    }
    true
}

/// Build an unmasked server-to-client WebSocket frame in `send_buf`.
unsafe fn ws_queue_frame(s: &mut HttpState, opcode: u8, payload: *const u8, payload_len: usize) {
    ws_queue_frame_fin(s, opcode, true, payload, payload_len);
}

/// Variant that lets the caller control the FIN bit. Used by the fan-out
/// outbound path where a single application-level message may span multiple
/// WS frames (BINARY/fin=0, CONTINUATION/fin=0, ..., CONTINUATION/fin=1).
unsafe fn ws_queue_frame_fin(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) {
    let written = ws::write_frame(
        cur_send_buf_mut_ptr(s),
        SEND_BUF_SIZE,
        fin,
        opcode,
        payload,
        payload_len,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_offset = 0;
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.send_len = written as u16;
    }
}

/// Build a CLOSE frame carrying `code` (network-byte-order u16) and
/// transition to the close-flush phase.
unsafe fn ws_begin_close(s: &mut HttpState, code: u16) {
    let payload = [(code >> 8) as u8, (code & 0xFF) as u8];
    ws_queue_frame(s, ws::OP_CLOSE, payload.as_ptr(), 2);
    if let Some(cur) = cur_slot_mut(s) {
        cur.phase = Phase::WsClose;
    }
}

// ── WebSocket fan-out helpers ─────────────────────────────────────────────
//
// Wire format on the `ws_out` / `ws_in` ports (content type `WsFrame`):
//   [conn_id : u32 LE]   bytes 0..4
//   [opcode  : u8]       byte  4   (RFC 6455 opcode: text/binary/cont)
//   [fin     : u8]       byte  5   (1 = final frame in WS message)
//   [payload_len : u16 LE] bytes 6..8
//   [payload : payload_len bytes]
//
// One mailbox-style write per frame, capped at CHANNEL_BUFFER_SIZE.

const WS_FRAME_HDR: usize = 8;

/// Header bytes to reserve at the front of `send_buf` when sizing a
/// WS wire fragment. RFC 6455 §5.2 server-to-client frame headers
/// are 2 bytes for ≤125-byte payloads, 4 bytes for ≤65535-byte
/// payloads. We size each fragment so its header fits in 4 bytes
/// (i.e. payload ≤ 65535) and the total wire frame fits in
/// `SEND_BUF_SIZE`. Anything larger gets split into multiple
/// fragments via the continuation path.
const WS_FRAG_HDR_RESERVE: usize = 4;

/// Emit a single inbound WS data frame on the `ws_out` port. Drops the
/// frame silently if the port isn't wired or the payload exceeds the
/// channel buffer — both are misconfiguration cases the downstream
/// consumer can't recover the lost data from anyway.
unsafe fn ws_emit_fanout_frame(
    s: &mut HttpState,
    opcode: u8,
    fin: u8,
    payload: *const u8,
    payload_len: usize,
) {
    if s.server.ws_out_chan < 0 {
        return;
    }
    if WS_FRAME_HDR + payload_len > super::abi::CHANNEL_BUFFER_SIZE {
        return;
    }
    let mut frame_buf = [0u8; super::abi::CHANNEL_BUFFER_SIZE];
    let conn_id = cur_conn_id(s) as u32;
    frame_buf[0..4].copy_from_slice(&conn_id.to_le_bytes());
    frame_buf[4] = opcode;
    frame_buf[5] = fin;
    let plen = payload_len as u16;
    frame_buf[6..8].copy_from_slice(&plen.to_le_bytes());
    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(
            payload,
            frame_buf.as_mut_ptr().add(WS_FRAME_HDR),
            payload_len,
        );
    }
    let total = WS_FRAME_HDR + payload_len;
    let sys = &*s.syscalls;
    let _ = (sys.channel_write)(s.server.ws_out_chan, frame_buf.as_ptr(), total);
}

/// Try to read one outbound WsFrame from `ws_in` and queue it as a WS
/// wire frame in `send_buf`. Returns true if a wire frame was queued,
/// false if no data was available or the frame couldn't fit.
///
/// Caller must guarantee `send_buf` is empty before calling — this
/// function unconditionally overwrites it.
///
/// **Fragmentation**: when the source envelope's payload exceeds
/// `SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, the message is split across
/// multiple wire frames per RFC 6455 §5.4. The first fragment carries
/// the original opcode (BINARY/TEXT) with `fin=0`; subsequent
/// fragments carry `OP_CONTINUATION` with `fin=0`; the last carries
/// `fin=1` if the source envelope had `fin=1`. While a fragmentation
/// is in flight on the active slot (`ws_frag_buf` non-null) the
/// function emits the next continuation chunk instead of reading
/// from `ws_in` — preserving the message ordering guarantee that no
/// other frame interleaves with the fragmented one on the wire.
unsafe fn ws_drain_fanout_input(s: &mut HttpState) -> bool {
    if s.server.ws_in_chan < 0 {
        return false;
    }

    // If a fragmentation is in flight on the active slot, emit the
    // next continuation chunk — do not read a new frame from ws_in.
    let frag_in_flight = cur_slot(s)
        .map(|c| !c.ws_frag_buf.is_null())
        .unwrap_or(false);
    if frag_in_flight {
        return ws_emit_next_fragment(s);
    }

    let sys = &*s.syscalls;
    let chan = s.server.ws_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return false;
    }

    let mut frame_buf = [0u8; super::abi::CHANNEL_BUFFER_SIZE];
    // mailbox-mode read pulls a complete WsFrame in one shot.
    let n = (sys.channel_read)(
        chan,
        frame_buf.as_mut_ptr(),
        super::abi::CHANNEL_BUFFER_SIZE,
    );
    if n < WS_FRAME_HDR as i32 {
        return false;
    }
    let payload_len = u16::from_le_bytes([frame_buf[6], frame_buf[7]]) as usize;
    let total = WS_FRAME_HDR + payload_len;
    if (n as usize) < total {
        return false;
    }
    let opcode = frame_buf[4];
    let fin = frame_buf[5] != 0;

    // Route by envelope conn_id. ws_stream stamps the recipient
    // conn_id at bytes 0-3 of every envelope; the active slot
    // calling ws_drain may not be the target, so without explicit
    // routing one client's bytes could be delivered to another.
    //
    // Special case: until ws_stream observes an inbound frame
    // from the browser it stamps the `u32::MAX` "unclaimed"
    // sentinel — producer-first bundles (server pushes
    // immediately on connect) ride this path. Sentinel envelopes
    // go to the first ws-fan-out slot found; routing them by a
    // default id of 0 would alias slot 0, which is typically the
    // IP listener and never a fan-out target.
    //
    // Real conn_ids are u8 and originate from the IP module's TCP
    // slot index (`MAX_TCP_CONNS`, independent of HTTP's
    // `MAX_CONCURRENT_CONNS`). On the wire bytes 1..4 are
    // zero-padding for real ids; they're all `0xFF` for the
    // sentinel, which is how we distinguish "no real id yet" from
    // a valid id 255. `find_slot_by_conn_id` returns `None` when
    // no slot owns the requested id (the conn may have closed
    // between the producer's write and our read), so it doubles
    // as the validity check.
    let conn_u32 = u32::from_le_bytes([frame_buf[0], frame_buf[1], frame_buf[2], frame_buf[3]]);
    let target_idx = if conn_u32 == u32::MAX {
        match find_first_ws_fanout_slot(s) {
            Some(i) => i,
            None => return false, // no fan-out slot active; drop
        }
    } else {
        match find_slot_by_conn_id(s, frame_buf[0]) {
            Some(i) => i,
            None => {
                // Unknown conn — the conn closed between the
                // producer's write and our read. Drop the envelope;
                // unavoidable loss for a closed recipient.
                return false;
            }
        }
    };

    // The target slot's send_buf must be empty before we overwrite
    // it. The active caller's own send_buf is empty by contract,
    // but the target's may not be. We've already consumed the
    // envelope from the mailbox (so ws_stream's tx_pending retry
    // can't replay it for us), so on contention we write it back:
    //
    //   * After `channel_read` the mailbox is STREAMING.
    //   * `channel_write` of the same envelope returns it to READY.
    //   * The cross-domain pump's POLL_OUT check observes
    //     non-STREAMING and holds — ws_stream stays in tx_pending
    //     until the mailbox is free again.
    //   * The next ws_drain on any slot reads the same envelope
    //     and re-attempts routing.
    //
    // The hold is bounded by the target's send_buf drain time —
    // typically a handful of ticks.
    let target_send_busy = {
        let slot = &*s.server.slots.as_ptr().add(target_idx);
        slot.send_len > slot.send_offset || !slot.ws_frag_buf.is_null()
    };
    if target_send_busy {
        let _ = (sys.channel_write)(chan, frame_buf.as_ptr(), total);
        return false;
    }

    // Switch cur_slot to target for the queue operation; the helpers
    // (ws_queue_frame_fin, cur_slot_mut, cur_send_buf_mut_ptr) all
    // key off cur_slot. Restore on the way out so the caller's
    // WsActive loop continues on its own slot.
    let saved_cur = s.server.cur_slot;
    s.server.cur_slot = target_idx as i32;

    let queued = ws_queue_envelope_on_active(
        s,
        opcode,
        fin,
        frame_buf.as_ptr().add(WS_FRAME_HDR),
        payload_len,
    );
    s.server.cur_slot = saved_cur;
    if !queued {
        return false;
    }

    // Capture: append this envelope to the retention buffer so a
    // future fan-out connect can replay the producer's snapshot
    // without the producer re-emitting. Idle-gap reset wipes the
    // buffer on the first envelope after a long quiet period so we
    // hold the *latest* state, not an unbounded history.
    retain_capture_envelope(
        s,
        opcode,
        fin,
        frame_buf.as_ptr().add(WS_FRAME_HDR),
        payload_len,
    );

    true
}

/// Queue one logical envelope on the currently-active slot. Single-
/// frame fast path if the payload fits within `SEND_BUF_SIZE -
/// WS_FRAG_HDR_RESERVE`; otherwise stamps the slot's `ws_frag_*`
/// fields and emits the first fragment, with subsequent
/// continuations driven by `ws_emit_next_fragment` on later ticks.
///
/// Caller guarantees:
///   * the active slot's `send_buf` is empty
///   * no fragmentation is currently in flight on the active slot
///
/// Returns `false` on heap-alloc failure (only possible for the
/// fragmentation path); the caller must treat that as "this envelope
/// is dropped and the producer must retry."
unsafe fn ws_queue_envelope_on_active(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) -> bool {
    let max_chunk = SEND_BUF_SIZE.saturating_sub(WS_FRAG_HDR_RESERVE);
    if payload_len <= max_chunk {
        ws_queue_frame_fin(s, opcode, fin, payload, payload_len);
        return true;
    }
    let sys = &*s.syscalls;
    let frag_buf = heap_alloc(sys, payload_len as u32);
    if frag_buf.is_null() {
        return false;
    }
    core::ptr::copy_nonoverlapping(payload, frag_buf, payload_len);
    if let Some(cur) = cur_slot_mut(s) {
        cur.ws_frag_buf = frag_buf;
        cur.ws_frag_total = payload_len as u16;
        cur.ws_frag_offset = max_chunk as u16;
        cur.ws_frag_opcode = opcode;
        cur.ws_frag_orig_fin = if fin { 1 } else { 0 };
    }
    ws_queue_frame_fin(s, opcode, false, frag_buf, max_chunk);
    true
}

/// Append a captured envelope to the server-wide retention buffer.
/// Idle-gap reset: if `retained_idle_ticks > RETAIN_RESET_TICKS`,
/// wipe the buffer first so the captured snapshot reflects only the
/// *new* burst (avoids unbounded growth across producer state
/// changes). Envelopes that won't fit even after a reset are
/// dropped silently — retention is best-effort.
unsafe fn retain_capture_envelope(
    s: &mut HttpState,
    opcode: u8,
    fin: bool,
    payload: *const u8,
    payload_len: usize,
) {
    if s.server.retained_buf.is_null() || s.server.retained_cap == 0 {
        return;
    }
    if payload_len > u16::MAX as usize {
        return;
    }
    // Retention feeds ONLY `HANDLER_WEBSOCKET_FANOUT` replay. If no
    // configured route replays (session-mode fan-out or none at all),
    // capturing would retain one session's frames for no consumer —
    // and stale session data must not outlive its connection.
    let mut any_replay_route = false;
    for i in 0..s.server.route_count as usize {
        if s.server.routes[i].handler == HANDLER_WEBSOCKET_FANOUT {
            any_replay_route = true;
            break;
        }
    }
    if !any_replay_route {
        return;
    }
    let needed = RETAINED_ENVELOPE_HDR + payload_len;
    if s.server.retained_idle_ticks > RETAIN_RESET_TICKS {
        s.server.retained_used = 0;
        s.server.retained_envelope_count = 0;
    }
    if s.server.retained_used as usize + needed > s.server.retained_cap as usize {
        // No room — wipe and try once. If a single envelope still
        // can't fit, retention is misconfigured (cap too small for
        // this workload); drop and let the live path serve it.
        s.server.retained_used = 0;
        s.server.retained_envelope_count = 0;
        if needed > s.server.retained_cap as usize {
            return;
        }
    }
    let dst = s.server.retained_buf.add(s.server.retained_used as usize);
    *dst = opcode;
    *dst.add(1) = if fin { 1 } else { 0 };
    let len_bytes = (payload_len as u16).to_le_bytes();
    *dst.add(2) = len_bytes[0];
    *dst.add(3) = len_bytes[1];
    if payload_len > 0 {
        core::ptr::copy_nonoverlapping(payload, dst.add(RETAINED_ENVELOPE_HDR), payload_len);
    }
    s.server.retained_used += needed as u32;
    s.server.retained_envelope_count = s.server.retained_envelope_count.saturating_add(1);
    s.server.retained_idle_ticks = 0;
}

/// Emit the next continuation fragment from the active slot's
/// in-flight fragmentation. Frees `ws_frag_buf` and clears state on
/// the final fragment (which carries the original `fin` bit).
unsafe fn ws_emit_next_fragment(s: &mut HttpState) -> bool {
    let max_chunk = SEND_BUF_SIZE.saturating_sub(WS_FRAG_HDR_RESERVE);
    let (buf, total, offset, orig_fin) = {
        let Some(cur) = cur_slot(s) else {
            return false;
        };
        (
            cur.ws_frag_buf,
            cur.ws_frag_total as usize,
            cur.ws_frag_offset as usize,
            cur.ws_frag_orig_fin,
        )
    };
    if buf.is_null() || offset >= total {
        return false;
    }

    let remaining = total - offset;
    let chunk = remaining.min(max_chunk);
    let is_last = chunk == remaining;
    let final_fin = is_last && orig_fin != 0;

    ws_queue_frame_fin(s, ws::OP_CONTINUATION, final_fin, buf.add(offset), chunk);

    if is_last {
        let sys = &*s.syscalls;
        heap_free(sys, buf);
        if let Some(cur) = cur_slot_mut(s) {
            cur.ws_frag_buf = core::ptr::null_mut();
            cur.ws_frag_total = 0;
            cur.ws_frag_offset = 0;
            cur.ws_frag_opcode = 0;
            cur.ws_frag_orig_fin = 0;
        }
    } else if let Some(cur) = cur_slot_mut(s) {
        cur.ws_frag_offset = (offset + chunk) as u16;
    }
    true
}

/// Process WebSocket frames buffered in `recv_buf`. Returns `true` if a
/// frame was processed (caller should re-enter the step loop), `false`
/// if more data is needed.
unsafe fn ws_process_inbound(s: &mut HttpState) -> bool {
    let buf_ptr = cur_recv_buf_mut_ptr(s);
    let len = cur_recv_len(s) as usize;

    let frame = match ws::parse_frame(buf_ptr, len) {
        Ok(Some(f)) => f,
        Ok(None) => return false,
        Err(()) => {
            // Drop everything buffered so the bad bytes don't get re-
            // parsed on every future tick — that would re-enter
            // `ws_begin_close` until the loop's progress signal flipped.
            if let Some(cur) = cur_slot_mut(s) {
                cur.recv_len = 0;
            }
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
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::WsClose;
            }
        }
        ws::OP_PING => {
            ws_queue_frame(s, ws::OP_PONG, payload_ptr, frame.payload_len as usize);
        }
        ws::OP_PONG => {
            // Unsolicited pongs are valid keep-alives — drop silently.
        }
        ws::OP_TEXT | ws::OP_BINARY | ws::OP_CONTINUATION => {
            if cur_ws_fan_out(s) != 0 {
                // Fan out: emit a WsFrame record on `ws_out` and let the
                // downstream module decide what to do with the payload.
                ws_emit_fanout_frame(
                    s,
                    frame.opcode,
                    if frame.fin { 1 } else { 0 },
                    payload_ptr,
                    frame.payload_len as usize,
                );
            } else {
                // Echo: send back as the same data opcode. Continuation
                // frames keep the original opcode the peer chose; the
                // echo pattern doesn't need to track fragmented messages
                // because we mirror them frame-for-frame.
                let echo_op = if frame.opcode == ws::OP_CONTINUATION {
                    ws::OP_CONTINUATION
                } else {
                    frame.opcode
                };
                ws_queue_frame(s, echo_op, payload_ptr, frame.payload_len as usize);
            }
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
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
    }
    true
}

// ── Outbound data send (CMD_SEND envelope) ────────────────────────────────

/// Send up to `len` bytes of HTTP payload to the IP module wrapped in a
/// CMD_SEND frame. Returns the number of payload bytes actually
/// accepted (0 if the channel is full).
unsafe fn net_send(s: &mut HttpState, data: *const u8, len: usize) -> i32 {
    let conn_id = cur_conn_id(s);
    net_send_conn(s, conn_id, data, len)
}

/// Like [`net_send`] but targets an explicit `conn_id` rather than the
/// active slot's client conn. The proxy relay uses it to write to the
/// backend conn (`backend_conn_id`) while the same slot's client conn
/// stays the `cur_conn_id` target. Byte-identical framing / sizing to
/// `net_send`; the only difference is which conn the bytes address.
unsafe fn net_send_conn(s: &mut HttpState, conn_id: u8, data: *const u8, len: usize) -> i32 {
    if s.net_out_chan < 0 {
        return 0;
    }
    // Per-call payload sizing depends on the downstream:
    //
    //  * `linux_net` (Linux host) → `libc::send()` into the kernel TCP
    //    stack. The kernel handles segmentation (TSO, etc.), so a
    //    large CMD_SEND amortises channel-write + syscall cost across
    //    many MSSes.
    //
    //  * fluxor's `ip` module (bcm2712 bare metal, …) → emits one TCP
    //    segment per CMD_SEND and drops anything in the chunk that
    //    overflows the effective send window. Capping at one MSS
    //    keeps the module from losing data when the IP send queue
    //    is tight.
    //
    // Both paths build for aarch64-unknown-none in PIC, so the cap is
    // a module-local runtime field set from the `host_tcp` param.
    let frame_cap = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    let per_call_cap = if s.host_tcp != 0 {
        frame_cap
    } else {
        1460usize // single MSS — safe with fluxor IP segmenter
    };
    let to_send = len.min(per_call_cap).min(frame_cap);
    if to_send == 0 {
        return 0;
    }

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 1 + to_send;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(3) = conn_id;
    core::ptr::copy_nonoverlapping(data, scratch.add(4), to_send);
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written == total as i32 {
        s.tlm.bytes_out = s.tlm.bytes_out.wrapping_add(to_send as u32);
        to_send as i32
    } else {
        // Atomic FIFO write rejected — treat as backpressure.
        s.tlm.bp_steps = s.tlm.bp_steps.wrapping_add(1);
        0
    }
}

// ── Body-send phase helpers ───────────────────────────────────────────────

/// Emit the `http.server.request` span for the just-completed response. Joins
/// the caller's distributed trace when the request carried a `traceparent`
/// (parsed into the slot at request start); otherwise mints a fresh root.
/// `name_id = 0` is the first `[observability].spans` entry. No-op when the
/// telemetry port is unwired or no span was started for this request.
unsafe fn emit_request_span(s: &mut HttpState) {
    if !dev_telemetry_enabled(&*s.syscalls) {
        return;
    }
    let (start, tp_trace, tp_parent, tp_flags) = match cur_slot(s) {
        Some(c) if c.span_start_us != 0 => (
            c.span_start_us,
            c.span_trace_id,
            c.span_parent_id,
            c.span_flags,
        ),
        _ => return,
    };
    // Head-sampling gate FIRST — before any clock read or RNG. A propagated
    // `traceparent` carries the caller's decision; a minted root is sampled. An
    // unsampled flow emits nothing (RFC observability bit test); the client
    // controls this, so the early gate matters.
    let propagated = tp_trace != [0u8; 16];
    let eff_flags = if propagated {
        tp_flags
    } else {
        super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    };
    if eff_flags & super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.span_start_us = 0;
        }
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let end_raw = dev_micros(sys);
    let end = if end_raw < start { start } else { end_raw };
    let mut ctx = super::abi::contracts::telemetry::SpanContext {
        trace_id: [0u8; 16],
        span_id: [0u8; 8],
        parent_id: [0u8; 8],
        flags: eff_flags,
    };
    // A non-zero trace id means the caller propagated context — join its trace
    // and parent under it; otherwise this is a minted root.
    if propagated {
        ctx.trace_id = tp_trace;
        ctx.parent_id = tp_parent;
    } else {
        dev_csprng_fill(sys, ctx.trace_id.as_mut_ptr(), 16);
    }
    dev_csprng_fill(sys, ctx.span_id.as_mut_ptr(), 8);
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = http.server.request
        super::abi::contracts::telemetry::SPAN_SERVER,
        super::abi::contracts::telemetry::STATUS_OK,
        &ctx,
        start,
        end,
    );
    if let Some(cur) = cur_slot_mut(s) {
        cur.span_start_us = 0;
    }
}

/// Transition out of a fully-drained response. Honours the slot's
/// `keepalive` flag: reuse the slot for the next request (compacting
/// any pipelined bytes already in `recv_buf`) or close the
/// connection.
unsafe fn finish_response(s: &mut HttpState) {
    // Observability: a response is fully drained here (keepalive reuse or
    // close), so this is the single span-end chokepoint for the request.
    emit_request_span(s);
    let (keepalive, header_end_off, recv_len) = match cur_slot(s) {
        Some(c) => (
            c.keepalive != 0,
            c.header_end_off as usize,
            c.recv_len as usize,
        ),
        None => {
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return;
        }
    };
    if !keepalive {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
        return;
    }
    // Compact any pipelined-request bytes to recv_buf[0..] so the
    // next RecvRequest pass parses them without needing a fresh
    // channel read.
    let leftover = recv_len.saturating_sub(header_end_off);
    if leftover > 0 {
        let buf = cur_recv_buf_mut_ptr(s);
        core::ptr::copy(buf.add(header_end_off), buf, leftover);
    }
    if let Some(cur) = cur_slot_mut(s) {
        cur.recv_len = leftover as u16;
        cur.recv_parsed = 0;
        cur.req_path_len = 0;
        cur.matched_route = -1;
        cur.header_end_off = 0;
        cur.tmpl_pos = 0;
        cur.send_offset = 0;
        cur.send_len = 0;
        // `keepalive` left untouched — re-derived from the next
        // request's headers (clients may switch mid-session).
        cur.phase = Phase::RecvRequest;
    }
}

unsafe fn step_send_static(s: &mut HttpState) -> i32 {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return 0,
    };
    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
    let body_start = route.body_offset as usize;
    let body_end = body_start + route.body_len as usize;
    let pos = body_start + (*cur_ptr).tmpl_pos as usize;

    if pos >= body_end {
        finish_response(s);
        return 0;
    }

    let remaining = body_end - pos;
    let to_send = remaining.min(SEND_BUF_SIZE);
    let ptr = (s.server.body_pool as *const u8).add(pos);
    let sent = net_send(s, ptr, to_send);
    if sent > 0 {
        (*cur_ptr).tmpl_pos += sent as u32;
        return 2;
    }
    0
}

unsafe fn step_send_template(s: &mut HttpState) -> i32 {
    if cur_send_offset(s) < cur_send_len(s) {
        let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
        let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
        let sent = net_send(s, ptr, remaining);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
            }
        }
        return 0;
    }

    let has_more = render_template_chunk(s);
    if cur_send_len(s) > 0 {
        let ptr = cur_send_buf_ptr(s);
        let sent = net_send(s, ptr, cur_send_len(s) as usize);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = sent as u16;
            }
        }
        return if has_more { 2 } else { 0 };
    }

    if !has_more {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
    }
    0
}

unsafe fn step_send_index(s: &mut HttpState) -> i32 {
    let cur_ptr = match cur_slot_mut(s) {
        Some(c) => c as *mut ConnSlot,
        None => return 0,
    };
    if (*cur_ptr).index_pos >= (*cur_ptr).file_count {
        if let Some(cur) = cur_slot_mut(s) {
            cur.phase = Phase::CloseConn;
        }
        return 0;
    }

    if cur_send_offset(s) >= cur_send_len(s) {
        let buf = cur_send_buf_mut_ptr(s);
        let mut off = 0usize;
        let mut idx = (*cur_ptr).index_pos;
        let file_count = (*cur_ptr).file_count;
        while idx < file_count && off + 6 < SEND_BUF_SIZE {
            off += fmt_u32_raw(buf.add(off), idx as u32);
            *buf.add(off) = b'\n';
            off += 1;
            idx += 1;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset = 0;
        }
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_len = off as u16;
        }
        (*cur_ptr).index_pos = idx;
    }

    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
    let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset += sent as u16;
        }
        return 2;
    }
    0
}

unsafe fn step_send_file(s: &mut HttpState) -> i32 {
    if cur_send_offset(s) >= cur_send_len(s) {
        let n = ((*s.syscalls).channel_read)(
            s.server.file_chan,
            cur_send_buf_mut_ptr(s),
            SEND_BUF_SIZE,
        );
        if n > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
        } else {
            let chan_poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if chan_poll > 0 && (chan_poll as u32 & POLL_HUP) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
            }
            return 0;
        }
    }

    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
    let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
    let sent = net_send(s, ptr, remaining);
    if sent > 0 {
        if let Some(cur) = cur_slot_mut(s) {
            cur.send_offset += sent as u16;
        }
        return 2;
    }
    0
}

/// HANDLER_FS_FILE body streamer. Drains `send_buf` to net_out;
/// when empty, calls `FS_READ` for the next chunk. Closes the FD and
/// transitions to `CloseConn` when `fs_sent == fs_total` (or FS_READ
/// returns ≤ 0).
///
/// Runs up to `FS_SEND_ROUNDS` fill+send cycles per step — a single
/// 4 KiB round per step caps serving around 2 MB/s under the
/// scheduler's burst budget, an order of magnitude short of media
/// streaming. Backpressure exits immediately (net_send returning 0
/// ends the loop), so slow consumers see one-round pacing.
unsafe fn step_send_fs_file(s: &mut HttpState) -> i32 {
    const FS_SEND_ROUNDS: usize = 16;
    let mut progressed = false;
    for _ in 0..FS_SEND_ROUNDS {
        if cur_fs_fd(s) < 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return 0;
        }
        if cur_send_offset(s) >= cur_send_len(s) {
            // `fs_total == u32::MAX` is the streaming sentinel — read
            // until FS_READ signals EOF below. Otherwise close out once
            // the declared content length is reached.
            let length_known = cur_fs_total(s) != u32::MAX;
            if length_known && cur_fs_sent(s) >= cur_fs_total(s) {
                let sys = &*s.syscalls;
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                // Self-delimited (Content-Length already emitted) — honour
                // the client's keep-alive intent.
                finish_response(s);
                return 0;
            }
            // Refill: streaming reads a full SEND_BUF; length-known caps
            // at the remaining bytes so we never over-read.
            let sys = &*s.syscalls;
            let want = SEND_BUF_SIZE as u32;
            let cap = if length_known {
                let remaining = cur_fs_total(s).saturating_sub(cur_fs_sent(s));
                (if remaining < want { remaining } else { want }) as usize
            } else {
                want as usize
            };
            let n = (sys.provider_call)(
                cur_fs_fd(s),
                0x0901, // FS_READ
                cur_send_buf_mut_ptr(s),
                cap,
            );
            // EAGAIN: provider has no bytes ready but the stream isn't
            // done. Yield; the next step re-polls. Distinguishing this
            // from EOF matters — closing on a not-yet-ready read would
            // truncate every async-backed file.
            if n == -11 {
                return if progressed { 2 } else { 0 };
            }
            if n <= 0 {
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset = 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_len = n as u16;
            }
        }

        let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
        let ptr = cur_send_buf_ptr(s).add(cur_send_offset(s) as usize);
        let sent = net_send(s, ptr, remaining);
        if sent > 0 {
            if let Some(cur) = cur_slot_mut(s) {
                cur.send_offset += sent as u16;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.fs_sent = cur.fs_sent.wrapping_add(sent as u32);
            }
            progressed = true;
            if (sent as usize) < remaining {
                // Net ring filled mid-buffer — no point retrying now.
                return 2;
            }
            continue;
        }
        // Net backpressure with nothing accepted this round.
        return if progressed { 2 } else { 0 };
    }
    2
}

// ── Per-tick step machine ──────────────────────────────────────────────────

/// Drain `net_in_chan` once per step and route each frame to the
/// owning slot. Replaces the per-phase channel polls in `WaitAccept`
/// / `RecvRequest` / `drain_background_messages` so that an idle
/// peer on one slot can never starve another slot's data, and so
/// that messages for any slot get routed regardless of which slot
/// happens to be `cur_slot` this tick.
///
/// Gated on slot 0 being past the bind sequence — the binding
/// state machine itself still consumes `MSG_BOUND` directly via
/// the `WaitBound` handler.
unsafe fn demux_inbound(s: &mut HttpState) {
    if s.net_in_chan < 0 {
        return;
    }
    // Don't demux until the listener is bound. Slot 0's binding
    // flow (Init → Binding → WaitBound → WaitAccept) consumes
    // CMD_BIND / MSG_BOUND directly. Once `bound=1` the demux runs
    // every step, regardless of slot 0's current phase (slot 0
    // cycles Init → assigned → Init → ... as later connections
    // recycle it).
    if s.server.bound == 0 {
        return;
    }

    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    // Bound the loop so a stuck channel can't monopolise a tick;
    // anything left over rolls into the next demux call.
    for _ in 0..16 {
        let poll = (sys.channel_poll)(chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            return;
        }

        // Peek the frame header (and the conn_id byte for MSG_DATA)
        // before consuming. If the target slot's recv_buf can't
        // hold the payload, leave the frame on `net_in_chan` and
        // return: the channel fills, the IP module's next
        // `channel_write` for that conn fails (atomic-FIFO
        // whole-frame reject), IP closes that conn's `rcv_wnd`,
        // and the peer retransmits once we drain. Consuming
        // unconditionally would let IP advance ACK and the peer
        // would never retransmit the bytes we couldn't hold.
        let mut hdr = [0u8; NET_FRAME_HDR + 1];
        let peeked = (sys.channel_peek)(chan, hdr.as_mut_ptr(), hdr.len());
        if peeked < NET_FRAME_HDR as i32 {
            return;
        }
        let peeked_msg = hdr[0];
        let peeked_payload_len = u16::from_le_bytes([hdr[1], hdr[2]]) as usize;
        if peeked_msg == NET_MSG_DATA && peeked_payload_len > 1 {
            // Need at least the conn_id byte to find the target.
            if peeked < NET_FRAME_HDR as i32 + 1 {
                return;
            }
            let conn = hdr[NET_FRAME_HDR];
            let data_len = peeked_payload_len - 1;
            if let Some(idx) = find_slot_by_conn_id(s, conn) {
                let slot = &*s.server.slots.as_ptr().add(idx);
                if !slot.recv_buf.is_null() {
                    let space = slot.recv_cap as usize - slot.recv_len as usize;
                    if data_len > space {
                        // Target full. Leave the frame on the
                        // channel and stop the demux loop — we
                        // can't safely skip past one frame to
                        // process later ones without peeking the
                        // next header, so a slow consumer briefly
                        // stalls siblings until it drains. IP's
                        // TCP backpressure handles the producer
                        // side correctly.
                        return;
                    }
                }
                // recv_buf null (slot freed mid-stream): the data
                // has nowhere to go, but we still have to consume
                // to make room on the channel. Falls through to
                // the consume-and-discard path below.
            } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                // Backend→client bytes for a proxy relay. Stage them
                // into the slot's `send_buf`, but only once the request
                // has been forwarded (relay phase). Before that, or
                // when `send_buf` is full, leave the frame on the
                // channel so TCP backpressure applies to the backend.
                let slot = &*s.server.slots.as_ptr().add(idx);
                if !is_proxy_relay_phase(slot.phase) {
                    return;
                }
                if !slot.send_buf.is_null() {
                    let space = slot.send_cap as usize - slot.send_len as usize;
                    if data_len > space {
                        return;
                    }
                }
            }
            // Unknown conn (no matching slot): same consume-and-
            // discard fallthrough — the IP module shouldn't send
            // data for an unmapped conn, and we won't let it
            // wedge the demux loop if it does.
        }

        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
        match msg_type {
            NET_MSG_ACCEPTED if payload_len >= 1 => {
                let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                // Multi-anchor demux: when the accept carries a listener
                // port (payload_len >= 3), claim it only if it matches our
                // bound port — a fanned net_out delivers every consumer's
                // accepts to all of them. A port-less frame (legacy
                // single-anchor producer) is always ours. A non-matching
                // accept is ignored (the owning anchor closes/claims it).
                let ours = payload_len < 3 || {
                    let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                    let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                    is_listen_port(s, (lo as u16) | ((hi as u16) << 8))
                };
                if ours {
                    if let Some(idx) = alloc_free_slot(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        slot.phase = Phase::RecvRequest;
                    } else {
                        // Slot table full — actively close the new conn
                        // (never drop silently: the IP module would
                        // otherwise leave the slot in `Established`
                        // until per-conn timeout, exhausting MAX_TCP_CONNS).
                        close_net_conn(s, conn);
                    }
                }
            }
            // A dynamic listener's mid-life bind completed (§4.2). Post-
            // `bound`, a MSG_BOUND is only ever a pooled-listener bind (the
            // static bind is consumed pre-`bound` by slot 0's WaitBound).
            // Payload `[conn_id:1][port:2 LE]`.
            NET_MSG_BOUND if payload_len >= 3 => {
                let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR) as i16;
                let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                let port = (lo as u16) | ((hi as u16) << 8);
                if let Some(bi) = s.server.listeners.bound_slot_for(port) {
                    let b = &mut s.server.listeners.bound[bi];
                    b.state = LISTENER_BOUND;
                    b.conn_id = conn;
                }
            }
            // A mid-life bind was refused — the port is outside the edge
            // owner's lease pool (rfc_endpoint_lease.md §5.3). linux_net
            // frames it `[port:2 LE][errno:1]`. Acted on ONLY with the
            // feature configured, so the metal `ip` module's 0x07
            // (RETRANSMIT) is never misread on the byte-identical path.
            NET_MSG_BIND_REFUSED if s.server.listeners_prefix_len != 0 && payload_len >= 2 => {
                let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let port = (lo as u16) | ((hi as u16) << 8);
                if let Some(bi) = s.server.listeners.bound_slot_for(port) {
                    s.server.listeners.bound[bi].state = LISTENER_REFUSED;
                }
            }
            NET_MSG_DATA if payload_len > 1 => {
                let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                let data_len = payload_len - 1;
                if let Some(idx) = find_slot_by_conn_id(s, conn) {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    if slot.recv_buf.is_null() {
                        // Slot freed mid-stream; drop the data.
                        continue;
                    }
                    let space = slot.recv_cap as usize - slot.recv_len as usize;
                    // Peek above guarantees `data_len <= space` for
                    // a valid slot — this is just a defence-in-depth
                    // bound, not a truncation point.
                    let to_copy = data_len.min(space);
                    if to_copy > 0 {
                        let dst = slot.recv_buf.add(slot.recv_len as usize);
                        core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                        slot.recv_len += to_copy as u16;
                        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(to_copy as u32);
                    }
                } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                    // Proxy backend→client: stage into `send_buf` for
                    // the relay step to flush. Gated on the relay phase
                    // (the peek above already backpressured otherwise).
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    if !slot.send_buf.is_null() && is_proxy_relay_phase(slot.phase) {
                        let space = slot.send_cap as usize - slot.send_len as usize;
                        let to_copy = data_len.min(space);
                        if to_copy > 0 {
                            let dst = slot.send_buf.add(slot.send_len as usize);
                            core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                            slot.send_len += to_copy as u16;
                            s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(to_copy as u32);
                        }
                    }
                }
                // Else: orphan — slot already closed; drop the data.
            }
            NET_MSG_CONNECTED if payload_len >= 1 => {
                // Reply to a serialised proxy dial. `MSG_CONNECTED`
                // carries `[conn_id][tag]` and the tag is our module
                // index (identical across slots), so the pending
                // `proxy_connect_owner` is the correlator. The owner's
                // `ProxyWaitConnect` handler releases the ownership
                // once it forwards the request.
                let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                let owner = s.server.proxy_connect_owner;
                if owner >= 0 && (owner as usize) < MAX_CONCURRENT_CONNS {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(owner as usize);
                    slot.backend_conn_id = conn as i16;
                    slot.proxy_connected = 1;
                }
            }
            NET_MSG_ERROR if payload_len >= 1 => {
                // Post-bind, an ERROR is a backend connect failure for
                // the serialised proxy dial (pre-bind errors are
                // consumed by slot 0's `WaitBound` handler, before the
                // demux runs).
                let owner = s.server.proxy_connect_owner;
                if owner >= 0 && (owner as usize) < MAX_CONCURRENT_CONNS {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(owner as usize);
                    slot.proxy_connect_failed = 1;
                }
            }
            NET_MSG_CLOSED if payload_len >= 1 => {
                let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                if let Some(idx) = find_slot_by_conn_id(s, conn) {
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.peer_closed = 1;
                } else if let Some(idx) = find_slot_by_backend_conn(s, conn) {
                    // Upstream backend closed — the relay flushes any
                    // staged bytes to the client, then tears down.
                    let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                    slot.backend_closed = 1;
                }
                // Else: nothing to clean up.
            }
            _ => {}
        }
    }
}

/// Outer step loop. Drains inbound messages once via the demux,
/// then walks the ready-slot bitmap so per-tick cost is O(active)
/// rather than O(MAX_CONCURRENT_CONNS).
///
/// The bitmap holds one bit per slot. `alloc_free_slot` sets it on
/// accept; `slot_release_buffers` clears it on close. Slot 0
/// during the bind sequence is the one exception: bit 0 is set by
/// `init()` and cleared when the WaitBound→WaitAccept transition
/// completes (slot 0 then behaves like any other slot).
///
/// Iteration starts at `step_cursor` and walks the bitmap forward
/// (wrapping at the end). Each tick advances the cursor by one
/// slot so no single conn can starve others on consecutive ticks.
/// Pump the dynamic-route table consumer one step: resolve the sink on
/// first use, then run the subscribe / apply / shadow-relist state
/// machine against `routes_prefix`. No-op when the feature is off
/// (`routes_prefix_len == 0`), keeping the server byte-identical.
pub(crate) unsafe fn pump_dyn_routes(s: &mut HttpState) {
    let prefix_len = s.server.routes_prefix_len as usize;
    if prefix_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.server.routes_sink < 0 {
        s.server.routes_sink = dev_channel_port(sys, 0, DYN_ROUTES_PORT_INDEX);
        if s.server.routes_sink < 0 {
            return; // port unwired — nothing to subscribe against
        }
    }
    let sink = s.server.routes_sink;
    // Disjoint field borrows of `s.server`.
    let prefix = &s.server.routes_prefix[..prefix_len];
    let scratch = &mut s.server.routes_scratch;
    let tc = &mut s.server.tc;
    let dyn_routes = &mut s.server.dyn_routes;
    tc.step(sys, sink, prefix, scratch, dyn_routes);
}

/// Pump the dynamic-listener table consumer one step, then reconcile the
/// desired listener set against the runtime bind records: bind newly
/// desired ports mid-life (`CMD_BIND`), tear down withdrawn ones
/// (`CMD_CLOSE`). No-op when the feature is off (`listeners_prefix_len ==
/// 0`), keeping the server byte-identical (rfc_workload_ingress §4.2).
///
/// The mid-life bind is issued only once the static listener is bound
/// (`bound == 1`): the shared `net_out` / `net_in` pair carries the init
/// bind first, and its `MSG_BOUND`/`MSG_BIND_REFUSED` for a dynamic port
/// then arrives through `demux_inbound` (which runs post-`bound`).
pub(crate) unsafe fn pump_listeners(s: &mut HttpState) {
    let prefix_len = s.server.listeners_prefix_len as usize;
    if prefix_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.server.listeners_sink < 0 {
        s.server.listeners_sink = dev_channel_port(sys, 0, DYN_LISTENERS_PORT_INDEX);
        if s.server.listeners_sink < 0 {
            return; // port unwired — nothing to subscribe against
        }
    }
    let sink = s.server.listeners_sink;
    // Disjoint field borrows of `s.server`. The listener CHANGES relist
    // reuses `routes_scratch` — the two pumps run sequentially, never
    // mid-relist of the other, so the transient buffer is free to share.
    let prefix = &s.server.listeners_prefix[..prefix_len];
    let scratch = &mut s.server.routes_scratch;
    let ltc = &mut s.server.ltc;
    let listeners = &mut s.server.listeners;
    ltc.step(sys, sink, prefix, scratch, listeners);

    // Reconcile only after the static bind: the mid-life CMD_BIND rides
    // the same net_out, and its reply comes back through the demux.
    if s.server.bound != 0 {
        reconcile_listeners(s);
    }
}

/// Diff the desired listener set against the runtime bind records and act:
/// issue `CMD_BIND` for a newly desired `tls=0` port, `CMD_CLOSE` the
/// linux_net listener conn for a withdrawn one. Idempotent — a port
/// already tracked (any bind state) is left alone; the lease gate refuses
/// an unleased port and the refusal surfaces as `MSG_BIND_REFUSED` in the
/// demux (which flips the record to `LISTENER_REFUSED`, never retried).
unsafe fn reconcile_listeners(s: &mut HttpState) {
    // 1. Bind newly-desired ports. Skip `tls=1` (P3 scope: cleartext).
    for li in 0..MAX_DYN_LISTENERS {
        let (port, tls, used) = {
            let r = &s.server.listeners.live[li];
            (r.port, r.tls, r.used)
        };
        if used != 1 || port == 0 || tls != 0 {
            continue;
        }
        if port == s.server.port {
            continue; // the static listener already owns this port
        }
        if s.server.listeners.bound_slot_for(port).is_some() {
            continue; // already tracked (binding / bound / refused)
        }
        // Claim a free bind record.
        let Some(bi) = s.server.listeners.bound.iter().position(|b| b.used == 0) else {
            s.server.listeners.dropped = s.server.listeners.dropped.wrapping_add(1);
            continue;
        };
        s.server.listeners.bound[bi] = BoundListener {
            port,
            state: LISTENER_BINDING,
            used: 1,
            conn_id: -1,
        };
        if !listener_send_bind(s, port) {
            // net_out full — roll back so a later tick retries.
            s.server.listeners.bound[bi] = BoundListener::new();
        }
    }

    // 2. Tear down withdrawn ports: a bind record with no live desired row.
    for bi in 0..MAX_DYN_LISTENERS {
        let (port, state, conn_id, used) = {
            let b = &s.server.listeners.bound[bi];
            (b.port, b.state, b.conn_id, b.used)
        };
        if used != 1 {
            continue;
        }
        let still_desired = s
            .server
            .listeners
            .live
            .iter()
            .any(|r| r.used == 1 && r.port == port && r.tls == 0);
        if still_desired {
            continue;
        }
        if state == LISTENER_BOUND && conn_id >= 0 {
            close_net_conn(s, conn_id as u8);
        }
        s.server.listeners.bound[bi] = BoundListener::new();
    }
}

/// Fill a `NET_CMD_BIND` payload for `port`, optionally owner-stamped for a
/// metal `net=own` workload (`rfc_workload_backend_metal.md` §3.4 / P3a). The
/// base payload is `[port:u16 LE]` (host/wildcard, byte-identical to pre-P3a);
/// when this http instance belongs to a workload owner (`dev_owner_tag != 0`,
/// stamped by `apply_add`'s `set_module_owner` post-alloc) it appends
/// `[owner_tag:u16 LE]`, which the ip module's P2 admission resolves to the
/// workload's owned address (a wrong/unowned tag is refused EACCES). A
/// host-owned (base-graph) http reads owner slot 0 and appends nothing.
/// Returns the payload length (2 or 4).
#[inline]
unsafe fn fill_bind_payload(sys: &SyscallTable, port: u16, out: &mut [u8; 4]) -> usize {
    out[0] = (port & 0xFF) as u8;
    out[1] = (port >> 8) as u8;
    let owner_tag = dev_owner_tag(sys);
    if owner_tag != 0 {
        out[2] = (owner_tag & 0xFF) as u8;
        out[3] = (owner_tag >> 8) as u8;
        4
    } else {
        2
    }
}

/// Issue a mid-life `CMD_BIND [port:u16 LE]` on `net_out` for a pooled
/// listener. Returns false when the channel is unwired or full.
unsafe fn listener_send_bind(s: &mut HttpState, port: u16) -> bool {
    if s.net_out_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 4];
    let plen = fill_bind_payload(sys, port, &mut payload);
    net_write_frame(
        sys,
        chan,
        NET_CMD_BIND,
        payload.as_ptr(),
        plen,
        buf,
        NET_BUF_SIZE,
    ) != 0
}

/// True when `port` is one of the anchor's live listen ports: the single
/// static listener, or a bound dynamic listener. Used by the accept demux
/// to claim only accepts on a port this anchor owns.
#[inline]
unsafe fn is_listen_port(s: &HttpState, port: u16) -> bool {
    port == s.server.port || s.server.listeners.port_is_bound(port)
}

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    demux_inbound(s);
    pump_dyn_routes(s);
    pump_listeners(s);

    // Graceful-drain check, run before any per-slot work. Drain is
    // complete once `module_drain` has set the flag, the listener
    // has bound, and no in-flight conns remain. This is
    // slot-agnostic on purpose — slot 0 is reused for connections
    // after bind, so it's not always the listener slot when drain
    // is requested.
    if s.server.draining != 0 && s.server.bound != 0 && active_slot_count(s) == 0 {
        return 1;
    }

    let mut aggregated = 0i32;
    // Snapshot the bitmap. The body of step_active_slot may set
    // or clear other slots' bits (e.g. demux runs implicitly via
    // any phase that re-enters the channel poll), but we only
    // walk the slots that were ready at the start of the tick.
    let ready_snapshot = s.server.ready_bits;
    let cursor_start = (s.server.step_cursor as usize) % MAX_CONCURRENT_CONNS;
    // First half: cursor_start..MAX. Second half: 0..cursor_start.
    // Walking in two halves keeps round-robin fairness across ticks.
    for half in 0..2 {
        let (lo, hi) = if half == 0 {
            (cursor_start, MAX_CONCURRENT_CONNS)
        } else {
            (0, cursor_start)
        };
        let mut word_idx = lo / 64;
        let word_end = hi.div_ceil(64);
        while word_idx < word_end {
            let mut word = ready_snapshot[word_idx];
            // Mask off bits before `lo` and at-or-after `hi` to
            // respect the half boundaries.
            let bit_base = word_idx * 64;
            if bit_base < lo {
                word &= !((1u64 << (lo - bit_base)) - 1);
            }
            if bit_base + 64 > hi {
                let drop = bit_base + 64 - hi;
                word &= u64::MAX >> drop;
            }
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let idx = bit_base + bit;
                word &= word - 1;
                s.server.cur_slot = idx as i32;
                let r = step_active_slot(s);
                if r > aggregated {
                    aggregated = r;
                }
            }
            word_idx += 1;
        }
    }
    s.server.cur_slot = 0;
    s.server.step_cursor = ((cursor_start + 1) % MAX_CONCURRENT_CONNS) as u32;
    aggregated
}

unsafe fn step_active_slot(s: &mut HttpState) -> i32 {
    drain_variables(s);

    // Background-drain inbound network messages during phases that
    // don't already poll `net_in_chan` themselves. Without this the
    // channel buffer fills up while the server is mid-response and
    // the upstream network module stops `accept()`ing new TCP
    // connections — TCP wedges from the outside even though the
    // scheduler keeps ticking. WaitBound / WaitAccept / RecvRequest /
    // WsActive are excluded because their per-phase handlers consume
    // the same channel directly with phase-specific semantics.
    // Inbound channel drain happens once per `step()` call via
    // `demux_inbound` (sibling of this function), which routes
    // every frame to the right slot. Per-slot ticks no longer poll
    // the channel themselves.

    // If MSG_CLOSED has fired for the current conn, any outbound-write
    // phase will spin against a closed slot — IP accepts CMD_SEND on
    // CloseWait but the bytes never reach the wire, so `send_offset`
    // never advances. Short-circuit to CloseConn so WaitAccept gets
    // ticks again.
    //
    // RecvRequest / H2Active included so a connect-then-close client
    // (peer_closed=1 with recv_len=0) doesn't leak the slot:
    //   - RecvRequest at the bottom of this match returns 0 when
    //     `recv_len == 0`, with no peer_closed check; without this
    //     preemption the slot stays in RecvRequest forever.
    //   - H2Active hands off to `h2::step`, which doesn't see the
    //     close (demux consumed it) so it can stall on stream-init
    //     waits the peer will never satisfy.
    if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
        match cur_phase(s) {
            Phase::RecvRequest
            | Phase::H2Active
            | Phase::SendHeaders
            | Phase::SendBody
            | Phase::DrainSend
            | Phase::FetchContent
            | Phase::CacheStream
            | Phase::WsHandshake
            | Phase::WsClose
            | Phase::AwaitFsStat
            | Phase::ProxyConnect
            | Phase::ProxyWaitConnect
            | Phase::ProxySendRequest
            | Phase::ProxyRelayHeaders
            | Phase::ProxyRelayBody => {
                if cur_fs_fd(s) >= 0 {
                    ((*s.syscalls).provider_call)(
                        cur_fs_fd(s),
                        0x0903, // FS_CLOSE
                        core::ptr::null_mut(),
                        0,
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = -1;
                    }
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
            }
            _ => {}
        }
    }

    match cur_phase(s) {
        Phase::Init | Phase::Binding => {
            if s.net_out_chan < 0 {
                return 0;
            }
            let sys = &*s.syscalls;
            let chan = s.net_out_chan;
            let buf = s.net_buf.as_mut_ptr();
            let mut payload = [0u8; 4];
            let plen = fill_bind_payload(sys, s.server.port, &mut payload);
            let wrote = net_write_frame(
                sys,
                chan,
                NET_CMD_BIND,
                payload.as_ptr(),
                plen,
                buf,
                NET_BUF_SIZE,
            );
            if wrote == 0 {
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::WaitBound;
            }
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
            let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
            match msg_type {
                // Multi-anchor demux: on a shared `net_in` fan IP emits one
                // MSG_BOUND per anchor's CMD_BIND. Treat only the bound for
                // OUR listener port as ours (a port-less legacy frame is
                // accepted). Ignoring a neighbour's bound here prevents this
                // server from flipping to WaitAccept / `bound` on someone
                // else's listen completing first.
                NET_MSG_BOUND
                    if payload_len < 3 || {
                        let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                        let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                        ((lo as u16) | ((hi as u16) << 8)) == s.server.port
                    } =>
                {
                    log(s, b"[http] bound, waiting for connections");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::WaitAccept;
                    }
                    // Slot 0's bind-sequence work is done; demux now
                    // owns its lifecycle like any other slot. Drop
                    // it from the ready bitmap so idle ticks are
                    // free, and flip the global bound flag so the
                    // demux can run from now on.
                    if let Some(idx) = current_slot_index(s) {
                        ready_clear(s, idx);
                    }
                    s.server.bound = 1;
                    return 2;
                }
                NET_MSG_ERROR => {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::Error;
                    }
                    return -1;
                }
                NET_MSG_ACCEPTED if payload_len >= 1 => {
                    // A connection accepted by linux_net while we were
                    // still binding. Allocate a slot directly — the
                    // slot table is the queue. Multi-anchor demux: claim
                    // only accepts on our bound port (see the demux path).
                    let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                    let ours = payload_len < 3 || {
                        let lo = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                        let hi = *s.net_buf.as_ptr().add(NET_FRAME_HDR + 2);
                        ((lo as u16) | ((hi as u16) << 8)) == s.server.port
                    };
                    if ours {
                        if let Some(idx) = alloc_free_slot(s, conn) {
                            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                            slot.phase = Phase::RecvRequest;
                        } else {
                            close_net_conn(s, conn);
                        }
                    }
                    return 2;
                }
                NET_MSG_DATA if payload_len > 1 => {
                    // Append directly to the owning slot's `recv_buf`.
                    let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                    let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
                    let data_len = payload_len - 1;
                    if let Some(idx) = find_slot_by_conn_id(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        if slot.recv_buf.is_null() {
                            // Slot freed mid-stream; drop the data.
                            return 2;
                        }
                        let space = slot.recv_cap as usize - slot.recv_len as usize;
                        let to_copy = data_len.min(space);
                        if to_copy > 0 {
                            let dst = slot.recv_buf.add(slot.recv_len as usize);
                            core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
                            slot.recv_len += to_copy as u16;
                        }
                    }
                    // Else: orphan — drop.
                    return 2;
                }
                NET_MSG_CLOSED if payload_len >= 1 => {
                    let conn = *s.net_buf.as_ptr().add(NET_FRAME_HDR);
                    if let Some(idx) = find_slot_by_conn_id(s, conn) {
                        let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                        slot.peer_closed = 1;
                    }
                    return 2;
                }
                NET_MSG_TRACE_CTX
                    if payload_len >= super::abi::contracts::net::net_proto::TRACE_CTX_LEN =>
                {
                    // Observability: the upstream (IP via TLS) trace context for
                    // this connection — `[conn_id][trace_id 16][tls_span_id 8]`.
                    // Store as the connection default; each request without its
                    // own `traceparent` parents `http.server.request` under it.
                    if dev_telemetry_enabled(&*s.syscalls) {
                        let p = s.net_buf.as_ptr().add(NET_FRAME_HDR);
                        let conn = *p;
                        if let Some(idx) = find_slot_by_conn_id(s, conn) {
                            let slot = &mut *s.server.slots.as_mut_ptr().add(idx);
                            core::ptr::copy_nonoverlapping(
                                p.add(1),
                                slot.conn_trace_id.as_mut_ptr(),
                                16,
                            );
                            core::ptr::copy_nonoverlapping(
                                p.add(17),
                                slot.conn_parent_id.as_mut_ptr(),
                                8,
                            );
                            slot.conn_flags = *p.add(25);
                        }
                    }
                    return 2;
                }
                _ => return 2,
            }
        }

        Phase::WaitAccept => {
            // No-op — `demux_inbound` allocates this slot directly
            // when MSG_ACCEPTED arrives, transitioning it to
            // RecvRequest without any per-slot channel poll here.
        }

        Phase::RecvRequest => {
            // Inbound bytes are routed to this slot's `recv_buf` by
            // `demux_inbound` at the top of `step()`. If nothing's
            // buffered, the slot is genuinely idle — yield this tick.
            if cur_recv_len(s) == 0 {
                return 0;
            }

            let len = cur_recv_len(s) as usize;

            // Detect the HTTP/2 cleartext (h2c) preface — 24 bytes
            // beginning with `PRI`. We check before the h1 request
            // parse so a misdirected h1 client doesn't accidentally
            // hit the same path. The preface is a fixed string; first
            // few bytes are sufficient to disambiguate. Without the
            // h2 feature the whole detect is compiled out and a `PRI`
            // request falls through to h1 parsing (which 400s it) —
            // fail-visible rather than silently half-speaking h2.
            let recv_parsed = cur_slot(s).map(|c| c.recv_parsed).unwrap_or(0);
            #[cfg(feature = "h2")]
            if recv_parsed == 0 && len >= 1 && *cur_recv_buf_ptr(s) == b'P' {
                if len < wire_h2::PREFACE.len() {
                    return 0; // wait for the rest of the preface
                }
                let mut prefix_match = true;
                let mut i = 0;
                let recv_buf = cur_recv_buf_ptr(s);
                while i < wire_h2::PREFACE.len() {
                    if *recv_buf.add(i) != wire_h2::PREFACE[i] {
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
                    let p = cur_recv_buf_mut_ptr(s);
                    let mut j = 0;
                    while j < leftover {
                        *p.add(j) = *p.add(pre + j);
                        j += 1;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.recv_len = leftover as u16;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.recv_parsed = 0;
                    }
                    if !h2::enter(s) {
                        // Heap exhausted: close the conn cleanly.
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                        return 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::H2Active;
                    }
                    return 2;
                }
                // Not the preface; fall through to h1 parsing.
            }

            if recv_parsed == 0 {
                let ptr = cur_recv_buf_ptr(s);
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
                    let recv_buf_ptr = cur_recv_buf_ptr(s);
                    let plen = if let Some(cur) = cur_slot_mut(s) {
                        let recv_len = cur.recv_len as usize;
                        h1::parse_request_line(
                            recv_buf_ptr,
                            recv_len,
                            cur.req_path.as_mut_ptr(),
                            MAX_PATH,
                        )
                    } else {
                        None
                    };
                    match plen {
                        Some(n) => {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.req_path_len = n as u8;
                                cur.recv_parsed = 1;
                            }
                        }
                        None => {
                            build_error(s, b"400 Bad Request", b"Bad Request\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                    }
                } else if cur_recv_len(s) as usize >= RECV_BUF_SIZE {
                    build_error(s, b"400 Bad Request", b"Bad Request\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 0;
                }
            }

            let recv_parsed = cur_slot(s).map(|c| c.recv_parsed).unwrap_or(0);
            if recv_parsed == 1 {
                let ptr = cur_recv_buf_ptr(s);
                let scan_len = cur_recv_len(s) as usize;
                let mut found_at: Option<usize> = None;
                if scan_len >= 4 {
                    let mut i = 0;
                    while i + 3 < scan_len {
                        if *ptr.add(i) == b'\r'
                            && *ptr.add(i + 1) == b'\n'
                            && *ptr.add(i + 2) == b'\r'
                            && *ptr.add(i + 3) == b'\n'
                        {
                            found_at = Some(i);
                            break;
                        }
                        i += 1;
                    }
                }

                if let Some(crlf_pos) = found_at {
                    // Pin keep-alive disposition before DispatchRoute
                    // so every write_status_line sees the right flag.
                    let head_len = crlf_pos + 4;
                    let head = core::slice::from_raw_parts(ptr, head_len);
                    let keepalive = h1::request_keeps_alive(head);
                    // Observability: stamp the `http.server.request` span start
                    // as the head is parsed. Computed before the slot borrow;
                    // one predicate, no clock read, when the port is unwired.
                    let span_now: u64 = if dev_telemetry_enabled(&*s.syscalls) {
                        let n = dev_micros(&*s.syscalls);
                        if n == 0 {
                            1
                        } else {
                            n
                        }
                    } else {
                        0
                    };
                    // W3C trace-context ingress: when tracing, a `traceparent`
                    // header (the caller's distributed trace) takes precedence;
                    // otherwise fall back to the connection context propagated
                    // in-band by IP/TLS. Resolved per request so a keepalive slot
                    // never inherits a previous request's header.
                    let header_ctx: Option<([u8; 16], [u8; 8], u8)> = if span_now != 0 {
                        h1::find_header(head, b"traceparent")
                            .and_then(super::abi::contracts::telemetry::parse_traceparent)
                    } else {
                        None
                    };
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.keepalive = if keepalive { 1 } else { 0 };
                        cur.header_end_off = head_len as u16;
                        cur.phase = Phase::DispatchRoute;
                        let flags = match header_ctx {
                            Some((tid, pid, flags)) => {
                                cur.span_trace_id = tid;
                                cur.span_parent_id = pid;
                                flags
                            }
                            None => {
                                // In-band connection context (all-zero = root).
                                cur.span_trace_id = cur.conn_trace_id;
                                cur.span_parent_id = cur.conn_parent_id;
                                cur.conn_flags
                            }
                        };
                        cur.span_flags = flags;
                        // Head-sampling: a propagated context carries the caller's
                        // bit; a root (all-zero trace) is sampled. Latch the span
                        // start ONLY when sampled, so an unsampled request does NO
                        // end-of-request clock/RNG work (emit returns on start==0).
                        let propagated = cur.span_trace_id != [0u8; 16];
                        let sampled = !propagated
                            || flags & super::abi::contracts::telemetry::TRACE_FLAGS_SAMPLED != 0;
                        cur.span_start_us = if sampled { span_now } else { 0 };
                    }
                    return 2;
                } else if cur_recv_len(s) as usize >= RECV_BUF_SIZE {
                    let l = cur_recv_len(s) as usize;
                    if l >= 3 {
                        let p = cur_recv_buf_mut_ptr(s);
                        *p = *p.add(l - 3);
                        *p.add(1) = *p.add(l - 2);
                        *p.add(2) = *p.add(l - 1);
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.recv_len = 3;
                        }
                    }
                }
            }
        }

        Phase::DispatchRoute => {
            if s.server.legacy_mode == 2 {
                // Returns false if file_chan was busy; caller stays
                // in DispatchRoute and retries next tick.
                let _ = step_legacy_file_dispatch(s);
                return 0;
            }

            // Diagnostic endpoint `/_fan` — calls the kernel
            // `FAN_DIAG_SNAPSHOT` opcode and serves the resulting ASCII
            // line (fan-out / fan-in pump counters + log_ring state).
            // Available on every http instance without route configuration.
            let (req, plen) = match cur_slot(s) {
                Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                None => return 0,
            };
            if plen >= 5
                && *req == b'/'
                && *req.add(1) == b'_'
                && *req.add(2) == b'f'
                && *req.add(3) == b'a'
                && *req.add(4) == b'n'
            {
                // Close-delimited (provider body ends at EOF) —
                // keep wire + slot in sync.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.keepalive = 0;
                }
                let buf = cur_send_buf_mut_ptr(s);
                let cap = SEND_BUF_SIZE;
                let mut off = 0usize;
                let header =
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n";
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
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                    cur.send_len = off as u16;
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }

            let ri = match_route(s);
            if ri < 0 {
                // No static route — consult the dynamic-route proxy
                // table (§3.2: after the static arena). An empty table
                // falls through to the fixed 404 surface (§7).
                if try_begin_dyn_proxy(s) {
                    return 2;
                }
                build_error(s, b"404 Not Found", b"Not Found\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }
            if let Some(cur) = cur_slot_mut(s) {
                cur.matched_route = ri;
            }
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
                            // Retain the entry while emission is in
                            // flight. Released at SendBody → DrainSend.
                            ce.retain = ce.retain.saturating_add(1);
                            let r = &mut *s.server.routes.as_mut_ptr().add(ri as usize);
                            r.body_offset = ce.arena_offset;
                            r.body_len = ce.length;
                            // Borrow the route's content_type before
                            // calling build_header (which takes &mut s).
                            let mut ct = [0u8; MAX_CONTENT_TYPE];
                            let ct_len = r.content_type_len as usize;
                            if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                                ct[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                            }
                            let ct_slice: &[u8] = if ct_len == 0 {
                                b"text/html"
                            } else {
                                &ct[..ct_len]
                            };
                            // Static → Content-Length + keep-alive.
                            // Template → close-delimited.
                            let body_len = r.body_len;
                            if handler == HANDLER_STATIC {
                                build_header_with_len(s, b"200 OK", ct_slice, body_len);
                            } else {
                                build_header(s, b"200 OK", ct_slice);
                            }
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.tmpl_pos = 0;
                                cur.cache_retained = 1;
                            }
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::SendHeaders;
                            }
                        } else {
                            // Cache miss → file_chan fetch. Serialise
                            // across slots so concurrent template
                            // misses don't trample each other's
                            // FLUSH/NOTIFY.
                            if !try_acquire_file_chan(s) {
                                // Another slot owns the channel —
                                // stay in DispatchRoute, retry next
                                // tick. The active route is already
                                // matched on this slot.
                                return 0;
                            }
                            // cache_alloc refuses if another reader
                            // is retaining the existing entry —
                            // defer (release lock, retry next tick).
                            if cache_alloc(s, ri as u8) < 0 {
                                release_file_chan(s);
                                return 0;
                            }
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                                0,
                            );
                            let mut pos = src_idx as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_NOTIFY,
                                pos_ptr,
                                4,
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::FetchContent;
                            }
                        }
                    } else {
                        let mut ct = [0u8; MAX_CONTENT_TYPE];
                        let ct_len = route.content_type_len as usize;
                        if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                            ct[..ct_len].copy_from_slice(&route.content_type[..ct_len]);
                        }
                        let ct_slice: &[u8] = if ct_len == 0 {
                            b"text/html"
                        } else {
                            &ct[..ct_len]
                        };
                        // Static → fixed body_len, emit Content-Length
                        // (enables keep-alive). Template → unknown
                        // total, close-delimited.
                        let body_len = route.body_len;
                        if handler == HANDLER_STATIC {
                            build_header_with_len(s, b"200 OK", ct_slice, body_len);
                        } else {
                            build_header(s, b"200 OK", ct_slice);
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.tmpl_pos = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    }
                }
                HANDLER_FILE => {
                    let fi = parse_file_index(s);
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.file_index = fi;
                    }
                    if fi == -1 {
                        if s.server.file_chan >= 0 {
                            let mut count: u32 = 0;
                            let count_ptr = &mut count as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_POLL_NOTIFY,
                                count_ptr,
                                4,
                            );
                            if r >= 0 {
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.file_count = count as u16;
                                }
                            }
                        }
                        build_header(s, b"200 OK", b"text/plain");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.index_pos = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    } else if fi >= 0 {
                        if s.server.file_chan >= 0 {
                            // Serialise: concurrent HANDLER_FILE
                            // requests across slots must not race on
                            // FLUSH/NOTIFY. Stall in DispatchRoute
                            // until the channel is free.
                            if !try_acquire_file_chan(s) {
                                return 0;
                            }
                            dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_FLUSH,
                                core::ptr::null_mut(),
                                0,
                            );
                            let mut pos = fi as u32;
                            let pos_ptr = &mut pos as *mut u32 as *mut u8;
                            let r = dev_channel_ioctl(
                                &*s.syscalls,
                                s.server.file_chan,
                                IOCTL_NOTIFY,
                                pos_ptr,
                                4,
                            );
                            if r < 0 {
                                build_error(s, b"404 Not Found", b"Not Found\n");
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.phase = Phase::DrainSend;
                                }
                                return 0;
                            }
                            build_header(s, b"200 OK", b"application/octet-stream");
                        } else {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                    } else {
                        build_error(s, b"400 Bad Request", b"Bad Request\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                }
                HANDLER_STREAM => {
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let src_idx = route.source_index;
                    if src_idx < 0 || s.server.file_chan < 0 {
                        build_error(
                            s,
                            b"500 Internal Server Error",
                            b"Stream handler missing source\n",
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot the per-route content_type before we
                    // pass `&mut s` to build_header.
                    let mut ct = [0u8; MAX_CONTENT_TYPE];
                    let ct_len = route.content_type_len as usize;
                    if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                        ct[..ct_len].copy_from_slice(&route.content_type[..ct_len]);
                    }
                    let ct_slice: &[u8] = if ct_len == 0 {
                        b"application/octet-stream"
                    } else {
                        &ct[..ct_len]
                    };
                    // Serialise: HANDLER_STREAM body-send reads from
                    // file_chan across multiple step()s. Without this
                    // gate a sibling slot's IOCTL_FLUSH would wipe
                    // our pending notify mid-stream.
                    if !try_acquire_file_chan(s) {
                        return 0;
                    }
                    dev_channel_ioctl(
                        &*s.syscalls,
                        s.server.file_chan,
                        IOCTL_FLUSH,
                        core::ptr::null_mut(),
                        0,
                    );
                    let mut pos = src_idx as u32;
                    let pos_ptr = &mut pos as *mut u32 as *mut u8;
                    let r = dev_channel_ioctl(
                        &*s.syscalls,
                        s.server.file_chan,
                        IOCTL_NOTIFY,
                        pos_ptr,
                        4,
                    );
                    if r < 0 {
                        build_error(s, b"500 Internal Server Error", b"Stream NOTIFY failed\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    build_header(s, b"200 OK", ct_slice);
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::SendHeaders;
                    }
                }
                HANDLER_FS_FILE => {
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let n = route.fs_path_len as usize;
                    if n == 0 || n > MAX_FS_PATH {
                        build_error(s, b"500 Internal Server Error", b"FS route missing path\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot the path before borrowing &mut s for
                    // header construction. Content-type is re-derived
                    // from `matched_route` in `Phase::AwaitFsStat`
                    // once the response code is decided.
                    let mut fs_path = [0u8; MAX_FS_PATH];
                    fs_path[..n].copy_from_slice(&route.fs_path[..n]);

                    let sys = &*s.syscalls;
                    // FS_OPEN(-1, path, len) → fd or negative errno.
                    // Dispatched through the kernel's FS_VTABLE to
                    // whichever module registered as the FS provider
                    // (fat32 on bare-metal, linux_fs_dispatch on host,
                    // browser-fetch on wasm).
                    let fd = (sys.provider_call)(
                        -1,
                        0x0900, // FS_OPEN
                        fs_path.as_mut_ptr(),
                        n,
                    );
                    if fd < 0 {
                        build_error(s, b"404 Not Found", b"Not Found\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // FS_STAT may pend for async providers, so the
                    // response-line decision happens in
                    // `Phase::AwaitFsStat` once the outcome is known.
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = fd;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_sent = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_total = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_stat_ticks = 0;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::AwaitFsStat;
                    }
                }
                HANDLER_FS_LIST => {
                    // Dual-mode: when the request path exactly matches
                    // the route path → emit the JSON directory listing
                    // (the original FS_LIST behaviour). When the
                    // request path is `<route>/<filename>` (matched
                    // via the implicit-prefix rule in
                    // `match_route_path`) → open `<fs_path>/<filename>`
                    // and stream it like HANDLER_FS_FILE.  This dual
                    // mode lets one route serve both the listing AND
                    // every file in the dir, which is what the
                    // scenario synthesiser's `list:` binding emits
                    // (the canonical case is `/api/list` + the gallery
                    // files the host page navigates between).
                    //
                    // The dispatch into the file-serve path falls
                    // through to the HANDLER_FS_FILE Phase::AwaitFsStat
                    // machinery below by setting `cur.fs_fd` after
                    // FS_OPEN-ing the composed path and transitioning
                    // straight to AwaitFsStat — no code duplication.
                    let route = &*s.server.routes.as_ptr().add(cur_matched_route(s) as usize);
                    let route_path_len = route.path_len as usize;
                    let (req_path_ptr_local, req_path_len) = match cur_slot(s) {
                        Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                        None => (core::ptr::null(), 0usize),
                    };
                    let is_file_request = req_path_len > route_path_len + 1;

                    if is_file_request {
                        // Compose `<fs_path>/<suffix>`. The suffix
                        // already includes its leading '/' (the
                        // separator between route path and filename),
                        // which lets us concat without inserting one.
                        let mut composed = [0u8; MAX_FS_PATH];
                        let dir_len = route.fs_path_len as usize;
                        let suffix_len = req_path_len - route_path_len;
                        if dir_len == 0 || dir_len + suffix_len > MAX_FS_PATH {
                            build_error(
                                s,
                                b"500 Internal Server Error",
                                b"FS_LIST file path too long\n",
                            );
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        composed[..dir_len].copy_from_slice(&route.fs_path[..dir_len]);
                        let req_path_ptr = req_path_ptr_local;
                        // Percent-decode the request suffix so spaces and
                        // other `%XX`-escaped bytes in filenames resolve to
                        // the real on-disk path (browsers encode them).
                        // Decoding only shrinks the length, so the bound
                        // check above stays valid.
                        let mut out = dir_len;
                        let mut k = 0usize;
                        while k < suffix_len {
                            let mut b = *req_path_ptr.add(route_path_len + k);
                            if b == b'%' && k + 3 <= suffix_len {
                                match (
                                    hex_val(*req_path_ptr.add(route_path_len + k + 1)),
                                    hex_val(*req_path_ptr.add(route_path_len + k + 2)),
                                ) {
                                    (Some(h), Some(l)) => {
                                        b = (h << 4) | l;
                                        k += 3;
                                    }
                                    _ => k += 1,
                                }
                            } else {
                                k += 1;
                            }
                            // Reject embedded null / backslash control bytes.
                            if b == 0 || b == b'\\' {
                                build_error(s, b"400 Bad Request", b"bad path\n");
                                if let Some(cur) = cur_slot_mut(s) {
                                    cur.phase = Phase::DrainSend;
                                }
                                return 0;
                            }
                            composed[out] = b;
                            out += 1;
                        }
                        let total = out;
                        // Reject `..` traversal: scan for `/../`,
                        // trailing `/..`, leading `../`, or bare `..`.
                        // Cheap byte-window check rather than a full
                        // canonicaliser — we're guarding the suffix
                        // (already validated for nulls/backslashes
                        // above), and the suffix is provided by the
                        // request URL which we don't trust.
                        let suffix_start = dir_len;
                        let suffix_end = total;
                        let mut k = suffix_start;
                        while k + 1 < suffix_end {
                            if composed[k] == b'.' && composed[k + 1] == b'.' {
                                let before_ok = k == suffix_start || composed[k - 1] == b'/';
                                let after_ok = (k + 2) == suffix_end || composed[k + 2] == b'/';
                                if before_ok && after_ok {
                                    build_error(
                                        s,
                                        b"400 Bad Request",
                                        b"path traversal rejected\n",
                                    );
                                    if let Some(cur) = cur_slot_mut(s) {
                                        cur.phase = Phase::DrainSend;
                                    }
                                    return 0;
                                }
                            }
                            k += 1;
                        }

                        let sys = &*s.syscalls;
                        let fd = (sys.provider_call)(
                            -1,
                            0x0900, // FS_OPEN
                            composed.as_mut_ptr(),
                            total,
                        );
                        if fd < 0 {
                            build_error(s, b"404 Not Found", b"Not Found\n");
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.phase = Phase::DrainSend;
                            }
                            return 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_fd = fd;
                            cur.fs_sent = 0;
                            cur.fs_total = 0;
                            cur.fs_stat_ticks = 0;
                            cur.phase = Phase::AwaitFsStat;
                        }
                        return 0;
                    }

                    // Fall through: exact-match listing path.
                    let n = route.fs_path_len as usize;
                    if n == 0 || n > MAX_FS_PATH {
                        build_error(
                            s,
                            b"500 Internal Server Error",
                            b"FS_LIST route missing path\n",
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }
                    // Snapshot path + filter so the FS calls + body
                    // build don't borrow `s` immutably while we later
                    // need it mutable to write send_buf.
                    let mut fs_path = [0u8; MAX_FS_PATH];
                    fs_path[..n].copy_from_slice(&route.fs_path[..n]);
                    let filter_len = route.fs_filter_len as usize;
                    let mut filter = [0u8; 64];
                    filter[..filter_len].copy_from_slice(&route.fs_filter[..filter_len]);

                    let sys = &*s.syscalls;
                    let dir_fd = (sys.provider_call)(
                        -1,
                        0x0907, /* FS_OPENDIR */
                        fs_path.as_mut_ptr(),
                        n,
                    );
                    if dir_fd < 0 {
                        build_error(s, b"404 Not Found", b"Directory not found\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                        return 0;
                    }

                    // Build JSON body into a local scratch then write
                    // headers + body into send_buf together (we need
                    // body_len for Content-Length before writing).
                    let mut body = [0u8; 2048];
                    let mut bp = 0usize;
                    // Opening `{"items":[`.
                    let prefix: &[u8] = b"{\"items\":[";
                    while bp < prefix.len() && bp < body.len() {
                        body[bp] = prefix[bp];
                        bp += 1;
                    }
                    let mut first = true;
                    let mut readdir_buf = [0u8; 1024];
                    loop {
                        let nb = (sys.provider_call)(
                            dir_fd,
                            0x0908, /* FS_READDIR */
                            readdir_buf.as_mut_ptr(),
                            readdir_buf.len(),
                        );
                        if nb <= 0 {
                            break;
                        }
                        let nb = nb as usize;
                        if nb < 2 {
                            break;
                        }
                        let count = u16::from_le_bytes([readdir_buf[0], readdir_buf[1]]) as usize;
                        // Belt-and-braces: some providers may return
                        // `nb=2 count=0` at end-of-dir; honour either.
                        if count == 0 {
                            break;
                        }
                        let mut pos = 2usize;
                        let mut emitted = 0usize;
                        while emitted < count && pos + 2 <= nb {
                            let name_len = readdir_buf[pos] as usize;
                            let entry_type = readdir_buf[pos + 1];
                            pos += 2;
                            if pos + name_len > nb {
                                break;
                            }
                            let name = &readdir_buf[pos..pos + name_len];
                            pos += name_len;
                            emitted += 1;
                            // Skip subdirectories.
                            if entry_type == 1 {
                                continue;
                            }
                            // Extension filter (case-insensitive).
                            if filter_len > 0 {
                                let mut ok = false;
                                let mut fi = 0usize;
                                while fi < filter_len {
                                    let start = fi;
                                    while fi < filter_len && filter[fi] != b',' {
                                        fi += 1;
                                    }
                                    let elen = fi - start;
                                    if elen > 0 && elen <= name.len() {
                                        let tail = &name[name.len() - elen..];
                                        let mut m = true;
                                        let mut k = 0usize;
                                        while k < elen {
                                            let a = tail[k];
                                            let b = filter[start + k];
                                            let al = a.to_ascii_lowercase();
                                            let bl = b.to_ascii_lowercase();
                                            if al != bl {
                                                m = false;
                                                break;
                                            }
                                            k += 1;
                                        }
                                        if m {
                                            ok = true;
                                            break;
                                        }
                                    }
                                    if fi < filter_len && filter[fi] == b',' {
                                        fi += 1;
                                    }
                                }
                                if !ok {
                                    continue;
                                }
                            }
                            // Comma separator between items.
                            if !first && bp < body.len() {
                                body[bp] = b',';
                                bp += 1;
                            }
                            first = false;
                            // Opening quote.
                            if bp < body.len() {
                                body[bp] = b'"';
                                bp += 1;
                            }
                            // Name bytes (escape `"` and `\`; everything else
                            // pass-through — filenames are ASCII-ish in practice).
                            let mut k = 0usize;
                            while k < name.len() && bp + 2 < body.len() {
                                let c = name[k];
                                if c == b'"' || c == b'\\' {
                                    body[bp] = b'\\';
                                    bp += 1;
                                }
                                body[bp] = c;
                                bp += 1;
                                k += 1;
                            }
                            // Closing quote.
                            if bp < body.len() {
                                body[bp] = b'"';
                                bp += 1;
                            }
                        }
                    }
                    (sys.provider_call)(
                        dir_fd,
                        0x0903, /* FS_CLOSE */
                        core::ptr::null_mut(),
                        0,
                    );
                    // Closing `]}`.
                    let suffix: &[u8] = b"]}";
                    let mut si = 0usize;
                    while si < suffix.len() && bp < body.len() {
                        body[bp] = suffix[si];
                        bp += 1;
                        si += 1;
                    }
                    let body_len = bp as u32;

                    // Write status line + Content-Length headers, then
                    // the body bytes, all into send_buf.
                    build_header_with_len(s, b"200 OK", b"application/json", body_len);
                    // After build_header_with_len, send_len is the
                    // header length. Append the body bytes.
                    let header_end = cur_send_len(s) as usize;
                    let dst = cur_send_buf_mut_ptr(s);
                    let body_ptr = body.as_ptr();
                    let max_total = SEND_BUF_SIZE.min(header_end + bp);
                    let mut k = 0usize;
                    while header_end + k < max_total {
                        *dst.add(header_end + k) = *body_ptr.add(k);
                        k += 1;
                    }
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.send_len = (header_end + k) as u16;
                        cur.send_offset = 0;
                        cur.phase = Phase::SendHeaders;
                    }
                }
                HANDLER_PROXY => {
                    // Build-time static proxy backend (`proxy_ip/port`).
                    // The dynamic-route path is handled before dispatch
                    // (no static route matched → `try_begin_dyn_proxy`).
                    let (ip, port) = {
                        let r = &*s.server.routes.as_ptr().add(ri as usize);
                        (r.proxy_ip, r.proxy_port)
                    };
                    if ip == 0 || port == 0 {
                        s.server.proxy_5xx = s.server.proxy_5xx.wrapping_add(1);
                        build_error(s, b"502 Bad Gateway", b"No proxy backend\n");
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::DrainSend;
                        }
                    } else {
                        begin_proxy(s, ip, port, -1);
                    }
                }
                HANDLER_WEBSOCKET | HANDLER_WEBSOCKET_FANOUT | HANDLER_WEBSOCKET_SESSION => {
                    if begin_ws_upgrade(s) {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::WsHandshake;
                        }
                        let fan = if handler == HANDLER_WEBSOCKET_FANOUT
                            || handler == HANDLER_WEBSOCKET_SESSION
                        {
                            1
                        } else {
                            0
                        };
                        let session = handler == HANDLER_WEBSOCKET_SESSION;
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.ws_fan_out = fan;
                            if session {
                                // Session-mode: skip retention replay for this
                                // slot entirely — mark the replay already done
                                // so the WsActive path falls straight through
                                // to the live stream.
                                cur.retained_replay_started = 1;
                                cur.retained_replay_done = 1;
                            }
                        }
                    }
                    // begin_ws_upgrade has already populated send_buf
                    // and switched phase on the failure path.
                }
                _ => {
                    build_error(s, b"500 Internal Server Error", b"Unknown handler\n");
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                }
            }
        }

        Phase::AwaitFsStat => {
            // Poll FS_STAT until the four-state code resolves:
            //   OK     → known length; commit Content-Length.
            //   ENOSYS → no Content-Length; commit streaming 200 OK.
            //            `fs_total = u32::MAX` is the streaming
            //            sentinel that `step_send_fs_file` reads to
            //            avoid gating on `fs_sent >= fs_total`.
            //   ENODEV → fetch failed; commit 502.
            //   EAGAIN → headers pending; keep polling up to
            //            `FS_STAT_PROBE_TIMEOUT_TICKS`, then 504.
            const E_NODEV: i32 = -19;
            const E_NOSYS: i32 = -38;
            const E_AGAIN: i32 = -11;
            const FS_STAT_PROBE_TIMEOUT_TICKS: u16 = 1500; // ~30 s on pi5 4 kHz
            let sys = &*s.syscalls;
            let mut stat = [0u8; 8];
            let st = (sys.provider_call)(
                cur_fs_fd(s),
                0x0904, // FS_STAT
                stat.as_mut_ptr(),
                stat.len(),
            );

            let ct_owner: Option<&Route> = if cur_matched_route(s) >= 0 {
                Some(&*s.server.routes.as_ptr().add(cur_matched_route(s) as usize))
            } else {
                None
            };
            let ct_len = ct_owner.map(|r| r.content_type_len as usize).unwrap_or(0);
            let mut ct_buf = [0u8; MAX_CONTENT_TYPE];
            if let Some(r) = ct_owner {
                if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                    ct_buf[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                }
            }
            // Content-Type resolution order:
            //   1. Route's explicit `content_type:` (e.g. HANDLER_FS_FILE
            //      with `content_type: "text/html"`).
            //   2. Sniffed from the request path's extension. Covers
            //      the HANDLER_FS_LIST file-serve path where the route
            //      has no fixed content_type — the request URL is the
            //      only source of mime info we have without a content
            //      sniff.
            //   3. Fallback `application/octet-stream`.
            let sniffed = if ct_len == 0 {
                let (req_p, req_l) = match cur_slot(s) {
                    Some(c) => (c.req_path.as_ptr(), c.req_path_len as usize),
                    None => (core::ptr::null(), 0usize),
                };
                content_type_from_path(req_p, req_l)
            } else {
                &[][..]
            };
            let ct_slice: &[u8] = if ct_len > 0 {
                &ct_buf[..ct_len]
            } else if !sniffed.is_empty() {
                sniffed
            } else {
                b"application/octet-stream"
            };

            if st == E_NODEV {
                (sys.provider_call)(
                    cur_fs_fd(s),
                    0x0903, // FS_CLOSE
                    core::ptr::null_mut(),
                    0,
                );
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_fd = -1;
                }
                build_error(s, b"502 Bad Gateway", b"Upstream fetch failed\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 2;
            }
            if st >= 0 {
                let size = u32::from_le_bytes([stat[0], stat[1], stat[2], stat[3]]);
                // In keep-alive mode recv_buf may also hold pipelined
                // bytes from the next request; cap the Range scan at
                // the current request's head so a follow-up `Range:`
                // can't bleed into this request's framing decision.
                let (recv_ptr, scan_len) = match cur_slot(s) {
                    Some(c) => (
                        c.recv_buf as *const u8,
                        if c.header_end_off > 0 {
                            (c.header_end_off as usize).min(c.recv_len as usize)
                        } else {
                            c.recv_len as usize
                        },
                    ),
                    None => (core::ptr::null::<u8>(), 0usize),
                };
                let range = if recv_ptr.is_null() || scan_len == 0 {
                    h1::RangeParse::None
                } else {
                    match ws::find_header_value(recv_ptr, scan_len, b"Range") {
                        Some((off, n)) => h1::parse_range_header(
                            core::slice::from_raw_parts(recv_ptr.add(off), n),
                            size,
                        ),
                        None => h1::RangeParse::None,
                    }
                };

                match range {
                    h1::RangeParse::Satisfiable { start, end } => {
                        // Pre-seek so the streamer's first FS_READ hits
                        // the right offset; if the provider can't seek
                        // (wasm browser-fetch returns ENOSYS), degrade
                        // to 200 OK on the full body rather than 5xx —
                        // the client falls back to a non-range fetch.
                        let mut seek_arg = (start as i32).to_le_bytes();
                        let seek_rc = (sys.provider_call)(
                            cur_fs_fd(s),
                            0x0902, // FS_SEEK
                            seek_arg.as_mut_ptr(),
                            seek_arg.len(),
                        );
                        if seek_rc < 0 {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.fs_total = size;
                            }
                            build_header_fs_full(s, b"200 OK", ct_slice, size);
                        } else {
                            // Re-target the streamer at the range:
                            // `fs_total` becomes the range length, the
                            // FD's position is at `start`, and the
                            // existing `fs_sent < fs_total` window stops
                            // at the right byte.
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.fs_total = end - start + 1;
                            }
                            build_header_fs_partial(s, ct_slice, start, end, size);
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendHeaders;
                        }
                        return 2;
                    }
                    h1::RangeParse::Unsatisfiable => {
                        (sys.provider_call)(
                            cur_fs_fd(s),
                            0x0903, // FS_CLOSE
                            core::ptr::null_mut(),
                            0,
                        );
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_fd = -1;
                            cur.phase = Phase::DrainSend;
                        }
                        build_error_416(s, size);
                        return 2;
                    }
                    h1::RangeParse::None => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.fs_total = size;
                            cur.phase = Phase::SendHeaders;
                        }
                        build_header_fs_full(s, b"200 OK", ct_slice, size);
                        return 2;
                    }
                }
            }
            if st == E_NOSYS {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_total = u32::MAX;
                }
                build_header(s, b"200 OK", ct_slice);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::SendHeaders;
                }
                return 2;
            }
            if st == E_AGAIN {
                // The active slot is guaranteed by the AwaitFsStat
                // entry path (`HANDLER_FS_FILE` sets cur_slot before
                // transitioning here); the `if let` is just a
                // panic-free borrow that PIC builds tolerate (no
                // `core::option::expect_failed` symbol).
                let timed_out = if let Some(cur) = cur_slot_mut(s) {
                    cur.fs_stat_ticks = cur.fs_stat_ticks.saturating_add(1);
                    cur.fs_stat_ticks >= FS_STAT_PROBE_TIMEOUT_TICKS
                } else {
                    false
                };
                if timed_out {
                    (sys.provider_call)(
                        cur_fs_fd(s),
                        0x0903, // FS_CLOSE
                        core::ptr::null_mut(),
                        0,
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.fs_fd = -1;
                    }
                    build_error(
                        s,
                        b"504 Gateway Timeout",
                        b"Upstream fetch did not respond\n",
                    );
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::DrainSend;
                    }
                    return 2;
                }
                return 0;
            }
            // Unknown FS_STAT error — treat as a fetch failure.
            (sys.provider_call)(
                cur_fs_fd(s),
                0x0903, // FS_CLOSE
                core::ptr::null_mut(),
                0,
            );
            if let Some(cur) = cur_slot_mut(s) {
                cur.fs_fd = -1;
            }
            build_error(s, b"502 Bad Gateway", b"Upstream fetch failed\n");
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::DrainSend;
            }
            return 2;
        }

        Phase::SendHeaders => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                let handler = if cur_matched_route(s) >= 0 {
                    (*s.server.routes.as_ptr().add(cur_matched_route(s) as usize)).handler
                } else {
                    HANDLER_FILE
                };

                match handler {
                    HANDLER_STATIC | HANDLER_TEMPLATE | HANDLER_FILE | HANDLER_STREAM
                    | HANDLER_FS_FILE => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::SendBody;
                        }
                    }
                    HANDLER_FS_LIST => {
                        // FS_LIST is dual-mode:
                        //   - exact-match listing: the JSON body is
                        //     already in `send_buf` and has drained;
                        //     close.
                        //   - file-serve (prefix `<route>/<file>`):
                        //     AwaitFsStat opened a real fd and only
                        //     emitted the status line + headers into
                        //     `send_buf`; the body still needs to be
                        //     streamed via FS_READ → SendBody. The fd
                        //     state (`fs_fd >= 0` after AwaitFsStat
                        //     committed) is the discriminator.
                        let has_open_fd = cur_fs_fd(s) >= 0;
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = if has_open_fd {
                                Phase::SendBody
                            } else {
                                Phase::DrainSend
                            };
                        }
                    }
                    _ => {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.phase = Phase::CloseConn;
                        }
                    }
                }
                return 2;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::SendBody => {
            let handler = if cur_matched_route(s) >= 0 {
                (*s.server.routes.as_ptr().add(cur_matched_route(s) as usize)).handler
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
                    let fi = cur_slot(s).map(|c| c.file_index).unwrap_or(-1);
                    if fi < 0 {
                        return step_send_index(s);
                    } else {
                        return step_send_file(s);
                    }
                }
                HANDLER_STREAM => {
                    return step_send_file(s);
                }
                HANDLER_FS_FILE => {
                    return step_send_fs_file(s);
                }
                HANDLER_FS_LIST => {
                    // Dual-mode FS_LIST in file-serve mode reuses the
                    // FS_FILE streamer wholesale — same fs_fd / fs_sent
                    // / fs_total state machine, same FS_READ chunked
                    // drain. SendHeaders only forwards us here when
                    // `cur_fs_fd >= 0` (i.e. AwaitFsStat opened a real
                    // file handle), so the FS_LIST listing path
                    // (single-shot send_buf) never reaches SendBody.
                    return step_send_fs_file(s);
                }
                _ => {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::CloseConn;
                    }
                }
            }
        }

        Phase::DrainSend => {
            // The body / fetch is done with file_chan; release
            // ownership so any sibling slot blocked in DispatchRoute
            // can claim it. `release_file_chan` is idempotent (only
            // frees if we're still the owner), so calling it on
            // every DrainSend tick during the chunked drain is
            // safe.
            release_file_chan(s);
            // Release the body-cache retain count if this slot was
            // rendering from a cache entry. `cache_retained` is the
            // gate that keeps this exactly-once across the chunked
            // drain.
            let (was_cached, route_idx) = match cur_slot(s) {
                Some(c) => (c.cache_retained != 0, c.matched_route),
                None => (false, -1),
            };
            if was_cached && route_idx >= 0 {
                cache_release_for_route(s, route_idx as u8);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.cache_retained = 0;
                }
            }
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                finish_response(s);
                return 0;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::FetchContent => {
            if s.server.file_chan < 0 {
                build_error(s, b"500 Internal Server Error", b"No content source\n");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::DrainSend;
                }
                return 0;
            }
            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            if poll > 0 && ((poll as u32 & POLL_IN) != 0 || (poll as u32 & POLL_HUP) != 0) {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CacheStream;
                }
                return 2;
            }
        }

        Phase::CacheStream => {
            if s.server.cache_count == 0 || s.server.file_chan < 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
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
                    ce.length += n as u32;
                }
            }

            let poll = ((*s.syscalls).channel_poll)(s.server.file_chan, POLL_IN | POLL_HUP);
            let eof = poll > 0 && (poll as u32 & POLL_HUP) != 0 && (poll as u32 & POLL_IN) == 0;
            let full = (arena_off + ce.length as usize) >= pool_cap;

            if eof || full {
                ce.flags |= CACHE_COMPLETE;
                // Retain the entry on behalf of the imminent reader
                // (this slot, transitioning to SendHeaders →
                // SendBody → DrainSend). DrainSend's release path
                // calls cache_release_for_route to balance.
                ce.retain = ce.retain.saturating_add(1);
                let ri = cur_matched_route(s) as usize;
                let r = &mut *s.server.routes.as_mut_ptr().add(ri);
                r.body_offset = ce.arena_offset;
                r.body_len = ce.length;
                let handler = r.handler;
                let body_len = r.body_len;
                let mut ct = [0u8; MAX_CONTENT_TYPE];
                let ct_len = r.content_type_len as usize;
                if ct_len > 0 && ct_len <= MAX_CONTENT_TYPE {
                    ct[..ct_len].copy_from_slice(&r.content_type[..ct_len]);
                }
                let ct_slice: &[u8] = if ct_len == 0 {
                    b"text/html"
                } else {
                    &ct[..ct_len]
                };
                // Static bodies: Content-Length is known, so emit it
                // and keep-alive is preserved. Templates render
                // chunk-by-chunk with unknown total → close-delimited.
                if handler == HANDLER_STATIC {
                    build_header_with_len(s, b"200 OK", ct_slice, body_len);
                } else {
                    build_header(s, b"200 OK", ct_slice);
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.tmpl_pos = 0;
                    cur.cache_retained = 1;
                    cur.phase = Phase::SendHeaders;
                }
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

        Phase::ProxyConnect => {
            // Serialise the CONNECT→CONNECTED handshake so demux can
            // correlate the reply (it carries only conn + module tag).
            let me = match current_slot_index(s) {
                Some(i) => i as i16,
                None => return 0,
            };
            if s.server.proxy_connect_owner >= 0 && s.server.proxy_connect_owner != me {
                return 0; // another slot mid-connect — retry next tick
            }
            s.server.proxy_connect_owner = me;
            if !proxy_dial(s) {
                return 0; // net_out full — retry next tick, keep ownership
            }
            let now = dev_millis(&*s.syscalls) as u32;
            if let Some(cur) = cur_slot_mut(s) {
                cur.proxy_connect_start_ms = now;
                cur.phase = Phase::ProxyWaitConnect;
            }
            return 2;
        }

        Phase::ProxyWaitConnect => {
            let (connected, failed, start) = match cur_slot(s) {
                Some(c) => (
                    c.proxy_connected != 0,
                    c.proxy_connect_failed != 0,
                    c.proxy_connect_start_ms,
                ),
                None => return 0,
            };
            if failed {
                proxy_connect_failed(s);
                return 2;
            }
            if connected {
                if let Some(idx) = current_slot_index(s) {
                    if s.server.proxy_connect_owner == idx as i16 {
                        s.server.proxy_connect_owner = -1;
                    }
                }
                proxy_build_forward_head(s);
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::ProxySendRequest;
                }
                return 2;
            }
            let now = dev_millis(&*s.syscalls) as u32;
            if now.wrapping_sub(start) >= PROXY_CONNECT_TIMEOUT_MS {
                proxy_connect_failed(s);
                return 2;
            }
            return 0;
        }

        Phase::ProxySendRequest => {
            let backend = match cur_slot(s) {
                Some(c) => c.backend_conn_id,
                None => return 0,
            };
            if backend < 0 {
                proxy_connect_failed(s);
                return 2;
            }
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                // Head fully forwarded — enter the byte relay and free
                // `send_buf` so demux can stage backend→client bytes.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                    cur.send_len = 0;
                    cur.phase = Phase::ProxyRelayBody;
                }
                return 2;
            }
            let sent = net_send_conn(
                s,
                backend as u8,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::ProxyRelayHeaders | Phase::ProxyRelayBody => {
            proxy_relay_step(s);
        }

        Phase::WsHandshake => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                log(s, b"[http] websocket upgraded");
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset = 0;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_len = 0;
                }
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::WsActive;
                }
                // Last-connection-wins: stamp this slot as the
                // current fan-out subscriber. Every other slot whose
                // `ws_fan_out=1` will self-close (CLOSE 1001) on its
                // next `WsActive` tick — see the displacement check
                // at the top of the WsActive arm. Doing it that way
                // (rather than walking the table here and queuing
                // CLOSE on busy slots) avoids the race where the
                // displaced slot is mid-flush of a big payload and
                // skipped because its `send_buf` is non-empty:
                // the per-slot check re-fires every tick until the
                // flush drains, at which point the close cleanly
                // takes over.
                if cur_ws_fan_out(s) != 0 {
                    s.server.latest_fanout_slot = s.server.cur_slot;
                }
                return 2;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
            }
        }

        Phase::WsActive => {
            // `demux_inbound` (called once per `step()` before the
            // slot loop) routes MSG_ACCEPTED / MSG_CLOSED / MSG_DATA
            // to the right slot, so the per-tick handler here only
            // has to drain ws_in / recv_buf.
            //
            // Peer-closed fast path: if `linux_net` has signalled
            // MSG_CLOSED for this conn, the slot's TCP socket is
            // gone — sending any more bytes is wasted work, and
            // leaving `ws_fan_out=1` on the slot makes
            // `find_first_ws_fanout_slot` hand new producers a dead
            // delivery target. Transition straight to CloseConn so
            // `slot_release_buffers` clears the fanout flag and
            // frees the slot for a new live client. Without this
            // gate, a reloaded browser tab leaves its old slot
            // hogging the fanout target indefinitely (lower slot
            // index always wins find_first), and the reloaded tab's
            // new slot never gets a single envelope.
            if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.ws_fan_out = 0;
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }

            // Last-connection-wins self-check: if a newer fan-out
            // upgrade has stamped `latest_fanout_slot` to a different
            // slot, this slot has been displaced. Queue a graceful
            // CLOSE 1001 the moment `send_buf` is clear and no
            // fragmentation is in flight; otherwise let the in-flight
            // flush complete and re-check on the next tick. Skipping
            // retention replay + ws_in drain here is intentional —
            // we don't want a being-displaced slot to consume more
            // envelopes that the new slot should be receiving.
            let me_idx = s.server.cur_slot;
            let displaced = cur_ws_fan_out(s) != 0
                && s.server.latest_fanout_slot >= 0
                && s.server.latest_fanout_slot != me_idx;
            if displaced {
                let send_empty = cur_send_len(s) == 0;
                let no_frag = cur_slot(s).map(|c| c.ws_frag_buf.is_null()).unwrap_or(true);
                if send_empty && no_frag {
                    ws_begin_close(s, ws::CLOSE_GOING_AWAY);
                    return 2;
                }
                // Mid-flush: drain remaining bytes then re-check.
                if cur_send_len(s) > 0 && cur_send_offset(s) < cur_send_len(s) {
                    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
                    let sent = net_send(
                        s,
                        cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                        remaining,
                    );
                    if sent > 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset += sent as u16;
                        }
                        if cur_send_offset(s) >= cur_send_len(s) {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.send_offset = 0;
                                cur.send_len = 0;
                            }
                        }
                    }
                }
                return 0;
            }

            // Retention replay: a freshly upgraded fan-out slot drains
            // any envelopes still held in `retained_buf` (the producer's
            // most recent snapshot) before joining the live fan-out
            // path. Single envelope per loop iteration so the existing
            // flush + fragmentation machinery handles each one
            // identically to a live ws_in arrival. Once `retained_used`
            // is exhausted (or the buffer has been reset mid-replay by
            // a fresh producer burst), `retained_replay_done` flips and
            // subsequent ticks fall through to the normal flow.
            let needs_replay = cur_slot(s)
                .map(|c| {
                    c.ws_fan_out != 0 && c.retained_replay_done == 0 && c.ws_frag_buf.is_null()
                })
                .unwrap_or(false);
            if needs_replay && cur_send_len(s) == 0 && !s.server.retained_buf.is_null() {
                // First tick in this slot: stamp the replay target
                // to the current `retained_used`. The replay walks
                // only up to that boundary, so envelopes captured
                // *after* the slot enters WsActive (which are also
                // queued live) don't get re-delivered through replay.
                let started = cur_slot(s).map(|c| c.retained_replay_started).unwrap_or(0);
                if started == 0 {
                    let snapshot = s.server.retained_used;
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.retained_replay_target = snapshot;
                        cur.retained_replay_started = 1;
                    }
                }
                let (offset, target) = (
                    cur_slot(s).map(|c| c.retained_replay_offset).unwrap_or(0),
                    cur_slot(s).map(|c| c.retained_replay_target).unwrap_or(0),
                );
                // If the buffer was reset since replay started
                // (retained_used dropped below the snapshot target),
                // the bytes the slot was about to read are
                // partially overwritten — abort cleanly.
                let buf_reset = s.server.retained_used < target;
                if offset >= target || buf_reset {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.retained_replay_done = 1;
                    }
                } else if (offset as usize) + RETAINED_ENVELOPE_HDR <= target as usize {
                    let buf = s.server.retained_buf.add(offset as usize);
                    let r_op = *buf;
                    let r_fin = *buf.add(1) != 0;
                    let r_len = u16::from_le_bytes([*buf.add(2), *buf.add(3)]) as usize;
                    let envelope_total = RETAINED_ENVELOPE_HDR + r_len;
                    if (offset as usize) + envelope_total > target as usize {
                        // Truncated tail (retained_buf reset mid-walk
                        // by a fresh burst). Bail out of replay; live
                        // path resumes next iteration.
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.retained_replay_done = 1;
                        }
                    } else {
                        let payload_ptr = buf.add(RETAINED_ENVELOPE_HDR);
                        if ws_queue_envelope_on_active(s, r_op, r_fin, payload_ptr, r_len) {
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.retained_replay_offset = cur
                                    .retained_replay_offset
                                    .saturating_add(envelope_total as u32);
                            }
                        } else {
                            // Heap-alloc failure on fragmentation —
                            // give up on replay, let live producer
                            // re-emit if/when it can.
                            if let Some(cur) = cur_slot_mut(s) {
                                cur.retained_replay_done = 1;
                            }
                        }
                    }
                }
            }

            // Loop within this tick alternating between flushing send_buf
            // to net_out and draining the next outbound frame from
            // ws_in / recv_buf. This keeps the pipeline saturated under
            // heavy producer load (spectrum_video chunking ~50 WsFrames
            // per video frame would otherwise take ~50 ticks to emit).
            // Exits as soon as no work can be done on either side.
            let mut did_any = false;
            loop {
                let mut progress = false;

                // Flush as much of send_buf as net_out will accept.
                if cur_send_len(s) > 0 && cur_send_offset(s) < cur_send_len(s) {
                    let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
                    let sent = net_send(
                        s,
                        cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                        remaining,
                    );
                    if sent > 0 {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset += sent as u16;
                        }
                        progress = true;
                    }
                    if cur_send_offset(s) >= cur_send_len(s) {
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_offset = 0;
                        }
                        if let Some(cur) = cur_slot_mut(s) {
                            cur.send_len = 0;
                        }
                    }
                }

                // Drain a WsFrame from ws_in if send_buf is now empty.
                // ws_drain_fanout_input writes one WsFrame's worth into
                // send_buf and returns true on success.
                if cur_send_len(s) == 0 && cur_ws_fan_out(s) != 0 && ws_drain_fanout_input(s) {
                    progress = true;
                }

                // Process any pre-buffered inbound frame. In echo mode
                // this writes to send_buf (skip if non-empty); in
                // fan-out mode it writes to ws_out and is always safe.
                // A peer CLOSE frame is parsed even with send_buf
                // occupied: we're transitioning to WsClose anyway, and
                // a saturated ws_in feed (e.g. 50 fps fan-out) would
                // otherwise keep send_buf permanently refilled and
                // the CLOSE would never get parsed.
                let peer_close_pending = cur_recv_len(s) > 0 && *cur_recv_buf_ptr(s) == 0x88;
                let can_process = cur_send_len(s) == 0 || peer_close_pending;
                if can_process && ws_process_inbound(s) {
                    progress = true;
                }

                if !progress {
                    break;
                }
                did_any = true;
                // ws_process_inbound may have transitioned to WsClose
                // (peer sent CLOSE, or we initiated CLOSE on protocol
                // error). Exit the loop so the next tick handles the
                // outgoing CLOSE frame from the WsClose arm rather than
                // continuing to drain ws_in / parse stale recv_buf.
                if !matches!(cur_phase(s), Phase::WsActive) {
                    break;
                }
            }

            // The slot table is the parallelism bound: idle WSes
            // don't starve other conns on hosts with multiple
            // slots; embedded targets with `MAX_CONCURRENT_CONNS = 1`
            // simply reject new conns at the demux until the WS
            // closes.
            if did_any {
                return 2;
            }

            // Nothing more to process this tick. Inbound bytes are
            // routed to this slot's `recv_buf` by `demux_inbound`,
            // and `peer_closed` is set there too — no per-slot
            // channel poll needed.
            if cur_slot(s).map(|c| c.peer_closed).unwrap_or(0) != 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
        }

        Phase::WsClose => {
            let remaining = (cur_send_len(s) - cur_send_offset(s)) as usize;
            if remaining == 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
            let sent = net_send(
                s,
                cur_send_buf_ptr(s).add(cur_send_offset(s) as usize),
                remaining,
            );
            if sent > 0 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.send_offset += sent as u16;
                }
                if cur_send_offset(s) >= cur_send_len(s) {
                    if let Some(cur) = cur_slot_mut(s) {
                        cur.phase = Phase::CloseConn;
                    }
                    return 0;
                }
            } else {
                // CLOSE-echo is best-effort: the peer initiated the
                // close, so they aren't waiting on our reply. If
                // `net_send` rejects (TCP send buffer full, slot gone,
                // zero peer window) free the slot rather than spin.
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
                return 0;
            }
        }

        #[cfg(not(feature = "h2"))]
        Phase::H2Active => {
            // Unreachable without h2 (nothing constructs H2Active —
            // the preface detect is compiled out), but the enum
            // variant is kept so phase numbering and the phase-walk
            // arms stay identical across variants. Fail closed.
            if let Some(cur) = cur_slot_mut(s) {
                cur.phase = Phase::CloseConn;
            }
            return 0;
        }
        #[cfg(feature = "h2")]
        Phase::H2Active => {
            let r = h2::step(s);
            if r == 1 {
                if let Some(cur) = cur_slot_mut(s) {
                    cur.phase = Phase::CloseConn;
                }
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
pub(crate) unsafe fn parse_route_content_type(
    s: &mut HttpState,
    idx: usize,
    d: *const u8,
    len: usize,
) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = len.min(MAX_CONTENT_TYPE);
    let mut i = 0;
    while i < n {
        r.content_type[i] = *d.add(i);
        i += 1;
    }
    r.content_type_len = n as u8;
}

#[inline]
pub(crate) unsafe fn set_route_proxy_port(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).proxy_port = p_u16(d, len, 0, 0);
    }
}

#[inline]
pub(crate) unsafe fn set_route_source(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx < MAX_ROUTES {
        (*s.server.routes.as_mut_ptr().add(idx)).source_index = p_u16(d, len, 0, 0xFFFF) as i16;
    }
}

/// Set a route's `fs_path` (filesystem path served via FS_CONTRACT).
/// Also flips the handler to `HANDLER_FS_FILE` so a route with
/// `fs_path:` configured serves through the FS provider without any
/// other YAML setup.
pub(crate) unsafe fn set_route_fs_path(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > MAX_FS_PATH { MAX_FS_PATH } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_path[i] = *d.add(i);
        i += 1;
    }
    r.fs_path_len = n as u8;
    if n > 0 {
        r.handler = HANDLER_FS_FILE;
    }
}

/// Set a route's `fs_list` directory path. Storage shares the `fs_path`
/// field with `set_route_fs_path` (they're mutually exclusive at the
/// route level — `fs_list:` lists a directory as JSON, `fs_path:`
/// streams a single file). Flips the handler to `HANDLER_FS_LIST` so
/// a GET against the route returns a fresh `FS_READDIR`-built JSON
/// payload.
pub(crate) unsafe fn set_route_fs_list(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > MAX_FS_PATH { MAX_FS_PATH } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_path[i] = *d.add(i);
        i += 1;
    }
    r.fs_path_len = n as u8;
    if n > 0 {
        r.handler = HANDLER_FS_LIST;
    }
}

/// Set the per-route extension filter consumed by `HANDLER_FS_LIST`.
/// Comma-separated, case-insensitive. Empty = list every regular
/// file the FS provider returns. No-op when the route isn't an
/// `fs_list:` route.
pub(crate) unsafe fn set_route_fs_filter(s: &mut HttpState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_ROUTES {
        return;
    }
    let r = &mut *s.server.routes.as_mut_ptr().add(idx);
    let n = if len > 64 { 64 } else { len };
    let mut i = 0usize;
    while i < n {
        r.fs_filter[i] = *d.add(i);
        i += 1;
    }
    r.fs_filter_len = n as u8;
}
