//! HTTP module — unified client + server.
//!
//! A single PIC module that operates in one of two modes:
//!
//! - **Server** (mode 0, default): routing, templating, file serving,
//!   forward-proxy stub.
//! - **Client** (mode 1): fetches a URL, streams the response body to
//!   the data output channel.
//!
//! # Layout
//!
//! - `wire_h1.rs` / `wire_h2.rs` / `wire_ws.rs` — pure byte-level
//!   parse and build helpers per protocol family
//! - `hpack.rs` — RFC 7541 header compression for HTTP/2
//! - `connection.rs` — IP-module framing constants
//! - `server.rs` — h1 server state machine, WebSocket upgrade, and
//!   the dispatch into h2 once an h2c preface is observed
//! - `h2.rs` — h2 connection state machine
//! - `client.rs` — h1 client state machine
//!
//! Future wire codecs land alongside `wire_h1.rs` (`wire_h2.rs`,
//! `wire_h3.rs`, `wire_ws.rs`) and stay flat — the PIC build system
//! expects each PIC module to be a single directory, with submodule
//! files at one level.
//!
//! # Server mode
//!
//! Each route maps a URL path prefix to one of five handler types:
//!
//! | id | Handler   | Description                                      |
//! |----|-----------|--------------------------------------------------|
//! | 0  | static    | Serve inline body as-is (text/html)              |
//! | 1  | template  | Serve inline body with `{{ var }}` substitution  |
//! | 2  | file      | Stream files from fat32 via channel              |
//! | 3  | proxy     | Forward request to upstream HTTP server (stub)   |
//! | 4  | websocket | Accept the WebSocket upgrade and echo frames     |
//!
//! WebSocket and HTTP routes share the same TCP/TLS listen socket: the
//! connection arrives, the request is parsed as HTTP/1, and routes
//! marked `handler=4` switch the connection into RFC 6455 frame mode
//! when the client sends an `Upgrade: websocket` request.
//!
//! # Client mode
//!
//! Fetches data from an HTTP URL and outputs the body to a channel.
//! From the consumer's perspective, this looks identical to the SD
//! module — just bytes flowing through a channel.
//!
//! # Parameters
//!
//! | Tag   | Name        | Type | Default | Description                                         |
//! |-------|-------------|------|---------|-----------------------------------------------------|
//! | 0     | mode        | u8   | 0       | 0=server, 1=client                                  |
//! | 1     | port        | u16  | 80      | TCP listen port (server) or target port (client)    |
//! | 2     | body        | str  | (none)  | Legacy inline body (server, backward compat)        |
//! | 3     | path        | str  | "/"     | URL path (client mode)                              |
//! | 4     | host_ip     | u32  | 0       | Target IP (client mode)                             |
//! | 10-45 | route_N_*   | —    | —       | Route params (server mode)                          |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unsafe_code,
    reason = "PIC module: ABI shim and zero-copy buffer plumbing"
)]
// PIC library code must not panic; surface errors through the ABI.
#![deny(clippy::unwrap_used)]
#![allow(
    clippy::duplicate_mod,
    reason = "PIC build path-mounts sdk/* into each `.rs` file via `#[path = \"...\"] mod`; in the host workspace build the same file appears in multiple parents. Splitting into a shared `use` import would break the bare-metal compilation pattern where each .rs is its own rustc invocation."
)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

mod client;
mod client_h2;
mod connection;
mod h2;
mod h3;
mod server;

// Wire codecs are pure-byte and useful for host tests of the
// h1 / h2 / h3 / ws / hpack / qpack layers. Stay private outside
// the host-test feature so the firmware's symbol surface is
// unchanged.
#[cfg(not(feature = "host-test"))]
mod hpack;
#[cfg(feature = "host-test")]
pub mod hpack;
#[cfg(not(feature = "host-test"))]
mod qpack;
#[cfg(feature = "host-test")]
pub mod qpack;
#[cfg(not(feature = "host-test"))]
mod wire_h1;
#[cfg(feature = "host-test")]
pub mod wire_h1;
#[cfg(not(feature = "host-test"))]
mod wire_h2;
#[cfg(feature = "host-test")]
pub mod wire_h2;
#[cfg(not(feature = "host-test"))]
mod wire_h3;
#[cfg(feature = "host-test")]
pub mod wire_h3;
#[cfg(not(feature = "host-test"))]
mod wire_ws;
#[cfg(feature = "host-test")]
pub mod wire_ws;

use client::ClientState;
use connection::NET_BUF_SIZE;
use server::ServerState;

// ── Mode constants ─────────────────────────────────────────────────────────

const MODE_SERVER: u8 = 0;
const MODE_CLIENT: u8 = 1;

// ── Top-level module state ─────────────────────────────────────────────────

#[repr(C)]
struct HttpState {
    syscalls: *const SyscallTable,
    mode: u8,
    /// 0 (default) — downstream is fluxor's `ip` module. `net_send`
    /// caps each `CMD_SEND` at one MSS so the IP segmenter never
    /// has to drop data past the effective send window.
    /// 1 — downstream is `linux_net` (Linux host). Kernel TCP
    /// handles segmentation, so we ship up to `NET_BUF_SIZE` per
    /// `CMD_SEND` and amortise the channel-write + syscall cost.
    host_tcp: u8,
    _mode_pad: [u8; 2],

    // Network channels are shared by both modes (in[0] = net_in,
    // out[0] = net_out). The IP module sees one client per http
    // instance regardless of role.
    net_in_chan: i32,
    net_out_chan: i32,
    /// Optional telemetry output (out[3]) to the `observe` collector; -1 when
    /// unwired. Cumulative counters emitted on the tlm cadence.
    telemetry_chan: i32,
    net_buf: [u8; NET_BUF_SIZE],

    /// Monotonic step counter feeding the tlm cadence.
    step_count: u32,
    /// Hot-path counters emitted as `[http] tlm dt=… rx=… tx=… idle=… bp=…`
    /// every `HTTP_TLM_PERIOD` steps. `rx` counts MSG_DATA payload
    /// bytes drained off `net_in_chan`; `tx` counts response bytes
    /// pushed onto `net_out_chan` from the send-file / send-response
    /// paths. `bp` increments when `step_send_file` short-writes.
    tlm: TlmCounters,
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],

    server: ServerState,
    client: ClientState,
}

/// Cadence for the `[http] tlm` line.
const HTTP_TLM_PERIOD: u32 = 5000;

// ── Parameter schema ───────────────────────────────────────────────────────
//
// Tags must be stable: external configs reference these by ID. Adding
// a new param appends a new tag; the macro emits PARAM_SCHEMA bytes
// embedded in the .fmod, which the host config tool reads to validate
// YAML against the runtime schema.

mod params_def {
    use super::client;
    use super::client::MAX_PATH_LEN;
    use super::server;
    use super::HttpState;
    use super::SCHEMA_MAX;
    use super::{p_u16, p_u32, p_u8};

    define_params! {
        HttpState;

        0, mode, u8, 0
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        1, port, u16, 80
            => |s, d, len| {
                let v = p_u16(d, len, 0, 80);
                s.server.port = v;
                s.client.port = v;
            };

        2, body, str, 0
            => |s, d, len| { server::parse_route_body(s, 0, d, len); };

        3, path, str, 0
            => |s, d, len| {
                let n = if len > MAX_PATH_LEN { MAX_PATH_LEN } else { len };
                s.client.path_len = n as u16;
                let mut i = 0;
                while i < n {
                    s.client.path[i] = *d.add(i);
                    i += 1;
                }
            };

        4, host_ip, u32, 0
            => |s, d, len| { s.client.host_ip = p_u32(d, len, 0, 0); };

        5, protocol, u8, 0
            => |s, d, len| { s.client.protocol = p_u8(d, len, 0, 0); };

        6, request_body, str, 0
            => |s, d, len| { client::parse_request_body(s, d, len); };

        7, websocket, u8, 0
            => |s, d, len| { s.client.websocket = p_u8(d, len, 0, 0); };

        // 0 (default) = downstream is fluxor's `ip` module — cap each
        // CMD_SEND at one MSS so the IP segmenter never drops past
        // cwnd. 1 = downstream is `linux_net` — kernel TCP handles
        // segmentation, so push the full per-call buffer to amortise
        // overhead across many MSSes.
        8, host_tcp, u8, 0
            => |s, d, len| { s.host_tcp = p_u8(d, len, 0, 0); };

        10, route_0_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 0, d, len); };
        11, route_0_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 0, d, len); };
        12, route_0_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 0, d, len); };
        13, route_0_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 0, d, len); };
        14, route_0_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 0, d, len); };
        15, route_0_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 0, d, len); };
        16, route_0_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 0, d, len); };
        17, route_0_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 0, d, len); };
        18, route_0_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 0, d, len); };
        19, route_0_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 0, d, len); };

        20, route_1_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 1, d, len); };
        21, route_1_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 1, d, len); };
        22, route_1_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 1, d, len); };
        23, route_1_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 1, d, len); };
        24, route_1_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 1, d, len); };
        25, route_1_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 1, d, len); };
        26, route_1_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 1, d, len); };
        27, route_1_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 1, d, len); };
        28, route_1_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 1, d, len); };
        29, route_1_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 1, d, len); };

        30, route_2_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 2, d, len); };
        31, route_2_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 2, d, len); };
        32, route_2_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 2, d, len); };
        33, route_2_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 2, d, len); };
        34, route_2_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 2, d, len); };
        35, route_2_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 2, d, len); };
        36, route_2_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 2, d, len); };
        37, route_2_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 2, d, len); };
        38, route_2_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 2, d, len); };
        39, route_2_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 2, d, len); };

        40, route_3_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 3, d, len); };
        41, route_3_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 3, d, len); };
        42, route_3_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 3, d, len); };
        43, route_3_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 3, d, len); };
        44, route_3_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 3, d, len); };
        45, route_3_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 3, d, len); };
        46, route_3_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 3, d, len); };
        47, route_3_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 3, d, len); };
        48, route_3_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 3, d, len); };
        49, route_3_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 3, d, len); };

        50, route_4_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 4, d, len); };
        51, route_4_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 4, d, len); };
        52, route_4_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 4, d, len); };
        53, route_4_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 4, d, len); };
        54, route_4_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 4, d, len); };
        55, route_4_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 4, d, len); };
        56, route_4_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 4, d, len); };
        57, route_4_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 4, d, len); };
        58, route_4_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 4, d, len); };
        59, route_4_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 4, d, len); };

        60, route_5_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 5, d, len); };
        61, route_5_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 5, d, len); };
        62, route_5_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 5, d, len); };
        63, route_5_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 5, d, len); };
        64, route_5_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 5, d, len); };
        65, route_5_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 5, d, len); };
        66, route_5_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 5, d, len); };
        67, route_5_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 5, d, len); };
        68, route_5_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 5, d, len); };
        69, route_5_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 5, d, len); };

        70, route_6_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 6, d, len); };
        71, route_6_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 6, d, len); };
        72, route_6_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 6, d, len); };
        73, route_6_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 6, d, len); };
        74, route_6_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 6, d, len); };
        75, route_6_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 6, d, len); };
        76, route_6_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 6, d, len); };
        77, route_6_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 6, d, len); };
        78, route_6_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 6, d, len); };
        79, route_6_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 6, d, len); };

        80, route_7_path, str, 0
            => |s, d, len| { server::parse_route_path(s, 7, d, len); };
        81, route_7_body, str, 0
            => |s, d, len| { server::parse_route_body(s, 7, d, len); };
        82, route_7_handler, u8, 0
            => |s, d, len| { server::set_route_handler(s, 7, d, len); };
        83, route_7_proxy_ip, u32, 0
            => |s, d, len| { server::set_route_proxy_ip(s, 7, d, len); };
        84, route_7_proxy_port, u16, 0
            => |s, d, len| { server::set_route_proxy_port(s, 7, d, len); };
        85, route_7_source, u16, 0xFFFF
            => |s, d, len| { server::set_route_source(s, 7, d, len); };
        86, route_7_content_type, str, 0
            => |s, d, len| { server::parse_route_content_type(s, 7, d, len); };
        87, route_7_fs_path, str, 0
            => |s, d, len| { server::set_route_fs_path(s, 7, d, len); };
        88, route_7_fs_list, str, 0
            => |s, d, len| { server::set_route_fs_list(s, 7, d, len); };
        89, route_7_fs_filter, str, 0
            => |s, d, len| { server::set_route_fs_filter(s, 7, d, len); };
    }
}

// ── Exported PIC interface ────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpState>() as u32
}

/// Heap arena size — sized for the **working set**, not the slot
/// table ceiling. The slot table (`MAX_CONCURRENT_CONNS`) is the
/// architectural cap on simultaneous in-flight connections; the
/// arena (`ARENA_WORKING_SET_CONNS`) is the realistic peak number
/// of *active* connections the system serves at once. When the
/// arena fills, `alloc_free_slot` returns `None` and the demux
/// closes the new conn cleanly — graceful overload behaviour, no
/// silent drops.
///
/// Decoupling these means a 1024-slot table on aarch64 doesn't
/// require 16+ MiB of pre-reserved arena that's idle 99% of the
/// time. The arena holds:
///   - the server's body pool (initial `DEFAULT_BODY_POOL_SIZE`,
///     grown via `heap_realloc` doubling — accounted for by
///     doubling the body budget here),
///   - per-active-conn `recv_buf` + `send_buf` allocated on accept,
///   - per-active-conn `H2State` (~3 KB) allocated lazily on the
///     h2c preface,
///   - allocator overhead.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    // Reserve room for the body pool plus headroom for `heap_realloc`
    // doubling under big inline-template configurations.
    let body_budget = (server::DEFAULT_BODY_POOL_SIZE as u32).saturating_mul(2);
    let per_slot_buffers = (server::RECV_BUF_SIZE + server::SEND_BUF_SIZE) as u32;
    let working_set = server::ARENA_WORKING_SET_CONNS as u32;
    let conns_buffers = per_slot_buffers.saturating_mul(working_set);
    let h2_state_size = core::mem::size_of::<h2::H2State>() as u32;
    let h2_buffers = h2_state_size.saturating_mul(working_set);
    // 16 bytes of allocator overhead per heap_alloc call (8-byte
    // header + alignment padding). Up to 3 allocs per active conn
    // (recv_buf, send_buf, h2).
    let alloc_overhead = (16u32 * 3).saturating_mul(working_set);
    body_budget
        .saturating_add(conns_buffers)
        .saturating_add(h2_buffers)
        .saturating_add(alloc_overhead)
        .saturating_add(2048) // slack for body_pool resize + headers
}

/// PIC module ABI entry: one-time initialisation. No state to bind yet.
///
/// # Safety
/// `_syscalls` is currently unused; the kernel guarantees ABI binding has
/// completed before this call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// PIC module ABI entry: construct module state in `state`.
///
/// # Safety
/// `state` / `params` / `syscalls` are kernel-owned buffers; the loader
/// passes `state_size` ≥ `module_state_size()` and `params_len` ≥ the
/// declared TLV size, both zero-init.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: kernel-owned buffers; null-checked + size-checked before use,
    // and the kernel guarantees `state` is zero-initialised at `state_size`.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<HttpState>() {
            return -6;
        }

        let s = &mut *(state as *mut HttpState);
        s.syscalls = syscalls as *const SyscallTable;
        s.mode = MODE_SERVER;
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;
        s.telemetry_chan = dev_channel_port(&*s.syscalls, 1, 3); // out[3]: telemetry (optional)

        // Pre-init both modes so the body pool is ready before TLV
        // params (which may call parse_route_body) are dispatched.
        server::init(s);
        client::init(s);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        if s.mode == MODE_CLIENT {
            client::post_params(s);
        } else {
            server::post_params(s);
        }

        0
    }
}

/// PIC module ABI entry: per-tick cooperative step.
///
/// # Safety
/// `state` must point to an initialised `HttpState`; the scheduler
/// guarantees no concurrent step invocation.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: `state` was initialised by `module_new`; the scheduler
    // serialises module_step calls so the `&mut *` re-borrow is unique.
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut HttpState);
        if s.syscalls.is_null() {
            return -1;
        }

        s.step_count = s.step_count.wrapping_add(1);
        let rx_pre = s.tlm.bytes_in;
        let tx_pre = s.tlm.bytes_out;
        let bp_pre = s.tlm.bp_steps;

        // Retention idle-tick: bumped every step; reset to 0 in
        // `ws_drain_fanout_input` on a fresh capture. Lets the next
        // captured envelope decide whether to wipe the buffer (idle
        // gap exceeded → new producer state) or append (still
        // streaming the same burst). Server-mode only — client mode
        // never enters the retention path.
        if s.mode == MODE_SERVER {
            s.server.retained_idle_ticks = s.server.retained_idle_ticks.saturating_add(1);
        }

        let rc = if s.mode == MODE_CLIENT {
            if s.client.protocol == 1 {
                client_h2::step(s)
            } else {
                client::step(s)
            }
        } else {
            server::step(s)
        };

        tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
        let sys = &*s.syscalls;
        let scratch_ptr = s.tlm_scratch.as_mut_ptr();
        let scratch_len = s.tlm_scratch.len();
        dev_tlm_maybe_emit(
            sys,
            b"[http]",
            &mut s.tlm,
            s.step_count,
            HTTP_TLM_PERIOD,
            scratch_ptr,
            scratch_len,
        );

        // Module-scope telemetry: emit cumulative counters to the `observe`
        // collector on the tlm cadence (no-op when the telemetry port is
        // unwired). ids follow `[observability].metrics`: 0=bytes_in, 1=bytes_out.
        if s.telemetry_chan >= 0 && s.step_count.is_multiple_of(HTTP_TLM_PERIOD) {
            let me = dev_self_index(sys);
            if me >= 0 {
                let midx = me as u16;
                let t = s.step_count as u64;
                let counter = abi::contracts::telemetry::METRIC_COUNTER;
                dev_telemetry_metric(
                    sys,
                    s.telemetry_chan,
                    midx,
                    t,
                    counter,
                    0,
                    s.tlm.bytes_in as u64,
                );
                dev_telemetry_metric(
                    sys,
                    s.telemetry_chan,
                    midx,
                    t,
                    counter,
                    1,
                    s.tlm.bytes_out as u64,
                );
            }
        }

        // Phase-machine snapshot — fires every tlm period so when the
        // server appears unresponsive we can see exactly which Phase
        // it sat in (e.g. ph=19 = WsActive, pca>0 = stale WS holding
        // queued accepts). The structured tlm line shows bytes/idle
        // but doesn't surface the FSM state, and the wedge surface
        // recurs often enough that having this on by default is the
        // only cheap way to characterise the next regression without
        // round-tripping a redeploy.
        if s.mode == MODE_SERVER && s.step_count.is_multiple_of(HTTP_TLM_PERIOD) {
            let mut buf = [0u8; 128];
            let p = buf.as_mut_ptr();
            let prefix = b"[http] state ph=";
            let mut q = 0usize;
            while q < prefix.len() {
                *p.add(q) = prefix[q];
                q += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_phase(s) as u32);
            let mc = b" conn=";
            let mut t = 0usize;
            while t < mc.len() {
                *p.add(q) = mc[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_conn_id(s) as u32);
            let mpc = b" pc=";
            let mut t = 0usize;
            while t < mpc.len() {
                *p.add(q) = mpc[t];
                q += 1;
                t += 1;
            }
            let peer_closed = server::cur_slot(s).map(|c| c.peer_closed).unwrap_or(0);
            q += fmt_u32_raw(p.add(q), peer_closed as u32);
            let mrl = b" rl=";
            let mut t = 0usize;
            while t < mrl.len() {
                *p.add(q) = mrl[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_recv_len(s) as u32);
            let mso = b" so=";
            let mut t = 0usize;
            while t < mso.len() {
                *p.add(q) = mso[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_send_offset(s) as u32);
            let msl = b" sl=";
            let mut t = 0usize;
            while t < msl.len() {
                *p.add(q) = msl[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::cur_send_len(s) as u32);
            let mac = b" act=";
            let mut t = 0usize;
            while t < mac.len() {
                *p.add(q) = mac[t];
                q += 1;
                t += 1;
            }
            q += fmt_u32_raw(p.add(q), server::active_slot_count(s) as u32);
            dev_log(sys, 3, p, q);
        }
        rc
    }
}

/// Drain marks the server for graceful shutdown — the next time it
/// returns to `WaitAccept` it reports done instead of looping. Client
/// mode is one-shot and ignores drain.
///
/// # Safety
/// `state` must point to an initialised `HttpState`.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_drain"]
pub unsafe extern "C" fn module_drain(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: state non-null per the check above; module_new initialised
    // it as `HttpState` so the cast is sound.
    unsafe {
        let s = &mut *(state as *mut HttpState);
        if s.mode == MODE_SERVER {
            // `server::step` checks the drain flag at the top of
            // every tick and returns 1 once no in-flight conns
            // remain, so no specific slot needs to be poked.
            s.server.draining = 1;
        }
    }
    0
}

/// PIC module ABI entry: report per-port channel ring sizes.
///
/// # Safety
/// `out` must be valid for writes of at least `max_len` bytes; the
/// loader passes a buffer it owns.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[link_section = ".text.module_channel_hints"]
pub unsafe extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    // net_in / net_out / file_data sized to absorb 8 KiB CMD_SEND
    // payloads (the staging cap on aarch64) plus a couple of frames
    // worth of in-flight headroom. Channel writes are all-or-nothing
    // on the kernel ring, so the buffer must be ≥ the largest single
    // write the producer ever attempts.
    //
    // **aarch64**: 16 KiB net rings + 16 KiB file_data — tracks
    // `NET_BUF_SIZE = 8192` and gives ~2× pipelined frames.
    //
    // **rp2350 / wasm32 / rp2040**: 2 KiB legacy budget; embedded
    // workloads stage 1600-byte payloads.
    #[cfg(target_arch = "aarch64")]
    let net_ring: u32 = 16384;
    #[cfg(target_arch = "aarch64")]
    let file_ring: u32 = 16384;
    #[cfg(not(target_arch = "aarch64"))]
    let net_ring: u32 = 2048;
    #[cfg(not(target_arch = "aarch64"))]
    let file_ring: u32 = 2048;

    // ws_in carries `WsFrame` envelopes from `ws_stream`:
    //   [conn_id u32 LE][opcode u8][fin u8][payload_len u16 LE][payload]
    // payload_len is u16 = up to 65535 bytes; full envelope ~65 KiB.
    // Channel writes are all-or-nothing — a 2 KiB default buffer
    // silently rejects every envelope and ws_drain_fanout_input sits
    // on an empty channel forever. Size to one full envelope plus
    // header slack; mailbox mode would be ideal but a sufficiently
    // large FIFO works for single-producer single-consumer.
    #[cfg(target_arch = "aarch64")]
    let ws_in_ring: u32 = 131072; // 128 KiB — 2 full envelopes pipelined
    #[cfg(not(target_arch = "aarch64"))]
    let ws_in_ring: u32 = 65600; // exactly one envelope + header
    let hints = [
        ChannelHint {
            port_type: 0,
            port_index: 0,
            buffer_size: net_ring,
        }, // in[0]: net_in (from IP)
        ChannelHint {
            port_type: 0,
            port_index: 1,
            buffer_size: 256,
        }, // in[1]: var updates
        ChannelHint {
            port_type: 0,
            port_index: 2,
            buffer_size: file_ring,
        }, // in[2]: file data
        ChannelHint {
            port_type: 0,
            port_index: 3,
            buffer_size: ws_in_ring,
        }, // in[3]: ws_in (WsFrame envelopes from ws_stream)
        ChannelHint {
            port_type: 1,
            port_index: 0,
            buffer_size: net_ring,
        }, // out[0]: net_out (to IP)
        ChannelHint {
            port_type: 1,
            port_index: 1,
            buffer_size: 256,
        }, // out[1]: file ctrl
    ];
    // SAFETY: `write_channel_hints` validates `max_len` against the hint
    // table size before writing through `out`.
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
