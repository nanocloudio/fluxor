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

#![no_std]

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
mod hpack;
mod qpack;
mod server;
mod wire_h1;
mod wire_h2;
mod wire_h3;
mod wire_ws;

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
    use super::{p_u16, p_u32, p_u8};
    use super::SCHEMA_MAX;

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
    }
}

// ── Exported PIC interface ────────────────────────────────────────────────

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpState>() as u32
}

/// Heap arena size. The server's body pool is allocated from this
/// arena.
#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    (server::DEFAULT_BODY_POOL_SIZE + 64) as u32
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

        // Pre-init both modes so the body pool is ready before TLV
        // params (which may call parse_route_body) are dispatched.
        server::init(s);
        client::init(s);

        let is_tlv = !params.is_null()
            && params_len >= 4
            && *params == 0xFE
            && *params.add(1) == 0x01;
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

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
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
        rc
    }
}

/// Drain marks the server for graceful shutdown — the next time it
/// returns to `WaitAccept` it reports done instead of looping. Client
/// mode is one-shot and ignores drain.
#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    unsafe {
        let s = &mut *(state as *mut HttpState);
        if s.mode == MODE_SERVER {
            s.server.draining = 1;
        }
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
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

    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: net_ring }, // in[0]: net_in (from IP)
        ChannelHint { port_type: 0, port_index: 1, buffer_size: 256 },      // in[1]: var updates
        ChannelHint { port_type: 0, port_index: 2, buffer_size: file_ring }, // in[2]: file data
        ChannelHint { port_type: 1, port_index: 0, buffer_size: net_ring }, // out[0]: net_out (to IP)
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 256 },      // out[1]: file ctrl
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
