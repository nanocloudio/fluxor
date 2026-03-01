//! HTTP Source PIC Module
//!
//! A PIC module that fetches data from an HTTP URL and outputs it to a channel.
//! From the consumer's perspective, this looks identical to the SD module -
//! just bytes flowing through a channel.
//!
//! # Unified I/O Model
//!
//! This module demonstrates fluxor's unified I/O design:
//! - SD module: reads blocks from disk -> writes bytes to channel
//! - HTTP module: reads from network -> writes bytes to channel
//! - Consumer modules (e.g., MP3 decoder) don't care about the source
//!
//! # Parameters
//!
//! The module takes these config parameters:
//! - host_ip: IPv4 address as u32 (network byte order)
//! - port: TCP port (default 80)
//! - path_offset: offset into path string buffer
//! - path_len: length of path string
//!
//! # State Machine
//!
//! ```text
//! INIT → SOCKET_OPEN → CONNECTING → WAIT_CONNECT →
//!        SEND_REQUEST → WAIT_SEND → RECV_HEADERS →
//!        RECV_BODY → WRITING → DONE
//! ```

#![no_std]

use core::ffi::c_void;
use core::ptr;

#[path = "../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, ChannelAddr};

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Module Parameters
// ============================================================================

/// Parameters for HTTP source module.
/// Layout:
///   [0-3]   host_ip: u32 (IPv4 in network byte order)
///   [4-5]   port: u16
///   [6-7]   path_len: u16
///   [8..]   path: [u8; path_len] (URL path, e.g., "/audio/song.mp3")
#[repr(C)]
struct HttpParams {
    host_ip: u32,
    port: u16,
    path_len: u16,
    // path bytes follow immediately after
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::HttpState;
    use super::p_u32;
    use super::p_u16;
    use super::MAX_PATH_LEN;
    use super::SCHEMA_MAX;

    define_params! {
        HttpState;

        1, host_ip, u32, 0
            => |s, d, len| { s.host_ip = p_u32(d, len, 0, 0); };

        2, port, u16, 80
            => |s, d, len| { s.port = p_u16(d, len, 0, 80); };

        3, path, str, 0
            => |s, d, len| {
                let n = if len > MAX_PATH_LEN { MAX_PATH_LEN } else { len };
                s.path_len = n as u16;
                let mut i = 0;
                while i < n {
                    s.path[i] = *d.add(i);
                    i += 1;
                }
            };
    }
}

// ============================================================================
// Constants
// ============================================================================

// dev_call socket opcodes
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

/// Receive buffer size
const RECV_BUF_SIZE: usize = 512;

/// Maximum path length
const MAX_PATH_LEN: usize = 128;

/// Connect timeout in milliseconds
const CONNECT_TIMEOUT_MS: u64 = 10000;

// ============================================================================
// State Machine Constants
// ============================================================================

/// HTTP client request lifecycle phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum HttpClientPhase {
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
// State Struct
// ============================================================================

#[repr(C)]
struct HttpState {
    syscalls: *const SyscallTable,
    socket_handle: i32,
    out_chan: i32,

    // Connection parameters
    host_ip: u32,
    port: u16,
    path_len: u16,

    // State machine
    phase: HttpClientPhase,
    headers_done: u8,
    _pad: [u8; 2],

    // Timing
    connect_start_ms: u64,

    // Write tracking
    pending_offset: u16,
    recv_len: u16,

    // Content tracking
    content_length: u32,
    bytes_received: u32,

    // Request buffer (built dynamically)
    request_len: u16,
    request_sent: u16,

    // Buffers
    path: [u8; MAX_PATH_LEN],
    recv_buf: [u8; RECV_BUF_SIZE],
    request_buf: [u8; 256],
}

impl HttpState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.socket_handle = -1;
        self.out_chan = -1;
        self.host_ip = 0;
        self.port = 80;
        self.path_len = 0;
        self.phase = HttpClientPhase::Init;
        self.headers_done = 0;
        self._pad = [0; 2];
        self.connect_start_ms = 0;
        self.pending_offset = 0;
        self.recv_len = 0;
        self.content_length = 0;
        self.bytes_received = 0;
        self.request_len = 0;
        self.request_sent = 0;
        self.path = [0; MAX_PATH_LEN];
        self.recv_buf = [0; RECV_BUF_SIZE];
        self.request_buf = [0; 256];
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
unsafe fn millis(s: &HttpState) -> u64 {
    dev_millis(s.sys())
}

#[inline(always)]
unsafe fn log_info(s: &HttpState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Build HTTP GET request into request_buf
/// Uses pointer arithmetic to avoid bounds-check panics in no_std
unsafe fn build_request(s: &mut HttpState) {
    // Simple HTTP/1.0 GET request
    // Format: "GET <path> HTTP/1.0\r\nHost: <ip>\r\nConnection: close\r\n\r\n"

    let buf_ptr = s.request_buf.as_mut_ptr();
    let mut offset = 0usize;

    // "GET "
    let get = b"GET ";
    let mut i = 0;
    while i < get.len() && offset < 255 {
        *buf_ptr.add(offset) = *get.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    // Path
    let path_ptr = s.path.as_ptr();
    i = 0;
    while i < s.path_len as usize && offset < 255 {
        *buf_ptr.add(offset) = *path_ptr.add(i);
        offset += 1;
        i += 1;
    }

    // " HTTP/1.0\r\nHost: "
    let http = b" HTTP/1.0\r\nHost: ";
    i = 0;
    while i < http.len() && offset < 255 {
        *buf_ptr.add(offset) = *http.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    // IP address as dotted decimal (unroll to avoid array indexing)
    let ip = s.host_ip.to_be_bytes();
    let b0 = ip[0]; let b1 = ip[1]; let b2 = ip[2]; let b3 = ip[3];

    // Helper to write one IP octet
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

    // "\r\nConnection: close\r\n\r\n"
    let close = b"\r\nConnection: close\r\n\r\n";
    i = 0;
    while i < close.len() && offset < 256 {
        *buf_ptr.add(offset) = *close.as_ptr().add(i);
        offset += 1;
        i += 1;
    }

    s.request_len = offset as u16;
    s.request_sent = 0;
}

/// Check if we've found the end of HTTP headers (\r\n\r\n)
/// Uses pointer arithmetic to avoid bounds-check panics in no_std
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
// Exported PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<HttpState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
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
        s.init(syscalls as *const SyscallTable);

        s.out_chan = out_chan;

        // Parse params
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else if !params.is_null() && params_len >= core::mem::size_of::<HttpParams>() {
            // Legacy binary params
            let cfg = &*(params as *const HttpParams);
            s.host_ip = cfg.host_ip;
            s.port = if cfg.port == 0 { 80 } else { cfg.port };

            let path_len = (cfg.path_len as usize).min(MAX_PATH_LEN);
            s.path_len = path_len as u16;
            let path_src = (params as *const u8).add(core::mem::size_of::<HttpParams>());
            let mut i = 0;
            while i < path_len {
                s.path[i] = *path_src.add(i);
                i += 1;
            }
        } else {
            params_def::set_defaults(s);
        }

        // Default to "/" if no path given
        if s.path_len == 0 {
            s.path[0] = b'/';
            s.path_len = 1;
        }

        log_info(s, b"[http] configured");
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

        loop {
            match s.phase {
                HttpClientPhase::Init => {
                    log_info(s, b"[http] opening socket");
                    s.phase = HttpClientPhase::SocketOpen;
                    continue;
                }

                HttpClientPhase::SocketOpen => {
                    // Open stream socket
                    let mut sock_arg = [SOCK_TYPE_STREAM];
                    let handle = (s.sys().dev_call)(-1, DEV_SOCKET_OPEN, sock_arg.as_mut_ptr(), 1);
                    if handle < 0 {
                        log_info(s, b"[http] socket_open failed");
                        s.phase = HttpClientPhase::Error;
                        return E_SOCKET_FAILED;
                    }
                    s.socket_handle = handle;
                    s.phase = HttpClientPhase::Connecting;
                    continue;
                }

                HttpClientPhase::Connecting => {
                    // Start connection
                    let addr = ChannelAddr::new(s.host_ip, s.port);
                    let rc = (s.sys().dev_call)(s.socket_handle, DEV_SOCKET_CONNECT, &addr as *const _ as *mut u8, core::mem::size_of::<ChannelAddr>());
                    if rc < 0 && rc != E_INPROGRESS {
                        log_info(s, b"[http] connect failed");
                        s.phase = HttpClientPhase::Error;
                        return E_CONNECT_FAILED;
                    }
                    s.connect_start_ms = millis(s);
                    s.phase = HttpClientPhase::WaitConnect;
                    return 0;
                }

                HttpClientPhase::WaitConnect => {
                    // Poll for connection complete
                    let mut poll_arg = [POLL_CONN];
                    let poll = (s.sys().dev_call)(s.socket_handle, DEV_SOCKET_POLL, poll_arg.as_mut_ptr(), 1);
                    if poll < 0 {
                        s.phase = HttpClientPhase::Error;
                        return E_CONNECT_FAILED;
                    }
                    if (poll as u8 & POLL_CONN) != 0 {
                        log_info(s, b"[http] connected");
                        build_request(s);
                        s.phase = HttpClientPhase::SendRequest;
                        continue;
                    }
                    // Check timeout
                    if millis(s).wrapping_sub(s.connect_start_ms) >= CONNECT_TIMEOUT_MS {
                        log_info(s, b"[http] connect timeout");
                        s.phase = HttpClientPhase::Error;
                        return E_CONNECT_FAILED;
                    }
                    return 0;
                }

                HttpClientPhase::SendRequest => {
                    // Send HTTP request
                    let remaining = (s.request_len - s.request_sent) as usize;
                    let buf_ptr = s.request_buf.as_mut_ptr().add(s.request_sent as usize);

                    let sent = (s.sys().dev_call)(
                        s.socket_handle,
                        DEV_SOCKET_SEND,
                        buf_ptr,
                        remaining,
                    );

                    if sent < 0 {
                        if sent == E_AGAIN {
                            return 0;
                        }
                        log_info(s, b"[http] send failed");
                        s.phase = HttpClientPhase::Error;
                        return E_SEND_FAILED;
                    }

                    s.request_sent += sent as u16;
                    if s.request_sent >= s.request_len {
                        log_info(s, b"[http] request sent");
                        s.headers_done = 0;
                        s.phase = HttpClientPhase::RecvHeaders;
                    }
                    return 0;
                }

                HttpClientPhase::RecvHeaders => {
                    // Receive and skip HTTP headers
                    let read = (s.sys().dev_call)(
                        s.socket_handle,
                        DEV_SOCKET_RECV,
                        s.recv_buf.as_mut_ptr(),
                        RECV_BUF_SIZE,
                    );

                    if read < 0 {
                        if read == E_AGAIN {
                            return 0;
                        }
                        log_info(s, b"[http] recv failed");
                        s.phase = HttpClientPhase::Error;
                        return E_RECV_FAILED;
                    }

                    if read == 0 {
                        // Connection closed before headers complete
                        log_info(s, b"[http] premature close");
                        s.phase = HttpClientPhase::Done;
                        return 1;
                    }

                    // Look for end of headers
                    if let Some(body_start) = find_header_end(&s.recv_buf, read as usize) {
                        // Headers done, save any body data received
                        let body_len = (read as usize) - body_start;
                        if body_len > 0 {
                            // Move body data to start of buffer (using pointer arithmetic)
                            let buf_ptr = s.recv_buf.as_mut_ptr();
                            let mut i = 0;
                            while i < body_len {
                                *buf_ptr.add(i) = *buf_ptr.add(body_start + i);
                                i += 1;
                            }
                            s.recv_len = body_len as u16;
                            s.pending_offset = 0;
                            s.phase = HttpClientPhase::Writing;
                        } else {
                            s.phase = HttpClientPhase::RecvBody;
                        }
                        log_info(s, b"[http] headers done");
                        continue;
                    }

                    // Still reading headers
                    return 0;
                }

                HttpClientPhase::RecvBody => {
                    // Check if output channel (pipe) is ready
                    if s.out_chan >= 0 {
                        let poll = (s.sys().channel_poll)(s.out_chan, POLL_OUT);
                        if poll <= 0 || (poll as u8 & POLL_OUT) == 0 {
                            return 0; // Channel not ready
                        }
                    }

                    // Receive more data from socket
                    let read = (s.sys().dev_call)(
                        s.socket_handle,
                        DEV_SOCKET_RECV,
                        s.recv_buf.as_mut_ptr(),
                        RECV_BUF_SIZE,
                    );

                    if read < 0 {
                        if read == E_AGAIN {
                            return 0;
                        }
                        log_info(s, b"[http] recv body failed");
                        s.phase = HttpClientPhase::Error;
                        return E_RECV_FAILED;
                    }

                    if read == 0 {
                        // Connection closed - transfer complete
                        log_info(s, b"[http] transfer done");
                        s.phase = HttpClientPhase::Done;
                        return 1;
                    }

                    s.recv_len = read as u16;
                    s.pending_offset = 0;
                    s.bytes_received += read as u32;
                    s.phase = HttpClientPhase::Writing;
                    continue;
                }

                HttpClientPhase::Writing => {
                    if s.out_chan < 0 {
                        // No output channel, just discard
                        s.phase = HttpClientPhase::RecvBody;
                        continue;
                    }

                    let offset = s.pending_offset as usize;
                    let remaining = (s.recv_len as usize) - offset;

                    let written = (s.sys().channel_write)(
                        s.out_chan,
                        s.recv_buf.as_ptr().add(offset),
                        remaining,
                    );

                    if written < 0 {
                        if written == E_AGAIN {
                            return 0;
                        }
                        log_info(s, b"[http] write failed");
                        s.phase = HttpClientPhase::Error;
                        return E_WRITE_FAILED;
                    }

                    s.pending_offset += written as u16;
                    if s.pending_offset >= s.recv_len {
                        // All data written, receive more
                        s.phase = HttpClientPhase::RecvBody;
                    }
                    return 0;
                }

                HttpClientPhase::Done => {
                    // Close socket
                    if s.socket_handle >= 0 {
                        (s.sys().dev_call)(s.socket_handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
                        s.socket_handle = -1;
                    }
                    return 1;
                }

                HttpClientPhase::Error => {
                    if s.socket_handle >= 0 {
                        (s.sys().dev_call)(s.socket_handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
                        s.socket_handle = -1;
                    }
                    return -1;
                }

                _ => return -1,
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
