//! WiFi Connect PIC Module
//!
//! Sequences WiFi association using the cyw43 driver module.
//! Uses FMP (Fluxor Message Protocol) for all inter-module communication.
//!
//! # Channels
//!
//! - `out[0]` → `cyw43.ctrl`: FMP commands (connect, scan)
//! - `in[0]`  ← `cyw43.out[3]`: FMP status events (optional, falls back to netif poll)
//! - `in[1]`  ← `cyw43.out[2]`: FMP scan results (optional, for scan-then-select)
//!
//! # Modes
//!
//! - **Credentials provided** (ssid + password in config): Send CONNECT, wait for link.
//! - **No credentials**: Send SCAN, collect results on `in[1]`, display via log.
//!   If a preferred SSID is configured, auto-select and connect to the best match.
//!
//! # State Machine
//!
//! ```text
//! Init → NetifOpen → WaitReady → [has credentials?]
//!   ├─ yes → Associate → WaitConnected → Connected → Monitor
//!   └─ no  → Scan → CollectScan → SelectNetwork → Associate → ...
//!                            ^                                    |
//!                            +<--- Disconnected <-----------------+
//! ```

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

mod constants;
use constants::*;

/// Netif dev_call opcodes (mirror abi::dev_netif)
const DEV_NETIF_OPEN: u32 = 0x0700;
const DEV_NETIF_STATE: u32 = 0x0704;


mod params_def {
    use super::*;

    define_params! {
        WifiConnectState;

        1, ssid, str, 0
            => |s, d, len| {
                let n = if len > MAX_SSID_LEN { MAX_SSID_LEN } else { len };
                s.assoc_buf[0] = n as u8;
                let mut i = 0;
                while i < n {
                    s.assoc_buf[2 + i] = *d.add(i);
                    i += 1;
                }
            };

        2, password, str, 0
            => |s, d, len| {
                let n = if len > MAX_PASS_LEN { MAX_PASS_LEN } else { len };
                s.assoc_buf[1] = n as u8;
                let mut i = 0;
                while i < n {
                    s.assoc_buf[2 + MAX_SSID_LEN + i] = *d.add(i);
                    i += 1;
                }
            };

        3, security, u8, 4, enum { open=0, wpa=2, wpa2=3, wpa3=4 }
            => |s, d, _len| {
                let v = *d;
                // Map schema enum to wire: 0=WPA2, 1=WPA3, 2=Open
                s.security = if v == 4 { 1 } else if v == 0 { 2 } else { 0 };
            };
    }
}

// ============================================================================
// State
// ============================================================================

/// Compact scan result for tracking best candidate
#[repr(C)]
struct ScanEntry {
    ssid: [u8; 32],
    ssid_len: u8,
    channel: u8,
    rssi: i8,
    _pad: u8,
}

#[repr(C)]
struct WifiConnectState {
    syscalls: *const SyscallTable,
    in_chan: i32,        // in[0]: status events from cyw43
    out_chan: i32,       // out[0]: commands to cyw43.ctrl
    scan_chan: i32,      // in[1]: binary scan results from cyw43
    netif_handle: i32,
    phase: WifiPhase,
    retry_count: u8,
    radio_ready: bool,
    security: u8,   // 0=WPA2, 1=WPA3, 2=Open
    last_time_ms: u64,
    assoc_buf: [u8; ASSOC_BUF_SIZE],

    // Scan result tracking
    scan_results: [ScanEntry; MAX_SCAN_RESULTS],
    scan_count: u8,
    _pad2: [u8; 3],

    // Scratch buffer for FMP message payloads
    msg_buf: [u8; 64],
}

impl WifiConnectState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn log_msg(s: &WifiConnectState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

unsafe fn log_err(s: &WifiConnectState, msg: &[u8]) {
    dev_log(s.sys(), 1, msg.as_ptr(), msg.len());
}

/// Drain all pending FMP status events from in_chan.
unsafe fn drain_status_events(s: &mut WifiConnectState) {
    if s.in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    loop {
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
            break;
        }
        let (ty, _len) = msg_read(sys, s.in_chan, s.msg_buf.as_mut_ptr(), s.msg_buf.len());
        if ty == 0 {
            break;
        }

        match ty {
            MSG_RADIO_READY => {
                s.radio_ready = true;
            }
            MSG_CONNECTED => {
                if s.phase == WifiPhase::WaitConnected {
                    s.phase = WifiPhase::Connected;
                    s.retry_count = 0;
                    dev_log(sys, 3, b"[wifi] evt connected".as_ptr(), 20);
                }
            }
            MSG_DISCONNECTED => {
                if s.phase == WifiPhase::Monitor || s.phase == WifiPhase::Connected {
                    dev_log(sys, 1, b"[wifi] evt lost".as_ptr(), 15);
                    s.phase = WifiPhase::Disconnected;
                    s.last_time_ms = dev_millis(sys);
                }
            }
            MSG_SCAN_DONE => {
                if s.phase == WifiPhase::CollectScan {
                    s.phase = WifiPhase::SelectNetwork;
                }
            }
            _ => {}
        }
    }
}

/// Read one FMP-wrapped binary scan result from scan_chan (in[1]).
/// Returns true if a result was read and stored.
unsafe fn read_scan_result(s: &mut WifiConnectState) -> bool {
    if s.scan_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.scan_chan, POLL_IN);
    if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
        return false;
    }

    let mut rec = [0u8; SCAN_RESULT_SIZE];
    let (ty, len) = msg_read(sys, s.scan_chan, rec.as_mut_ptr(), SCAN_RESULT_SIZE);
    if ty != MSG_SCAN_RESULT || (len as usize) < SCAN_RESULT_SIZE {
        return false;
    }

    let idx = s.scan_count as usize;
    if idx >= MAX_SCAN_RESULTS {
        return false; // Full, skip
    }

    // Use pointer access to avoid bounds-check panic in no_std
    let entry = &mut *s.scan_results.as_mut_ptr().add(idx);
    let ssid_len = (rec[0] as usize).min(32);
    entry.ssid_len = ssid_len as u8;

    let mut i = 0;
    while i < 32 {
        *entry.ssid.as_mut_ptr().add(i) = *rec.as_ptr().add(1 + i);
        i += 1;
    }
    entry.channel = *rec.as_ptr().add(33);
    entry.rssi = *rec.as_ptr().add(34) as i8;
    entry._pad = 0;

    s.scan_count += 1;
    true
}

/// Send a CONNECT command as FMP message on out_chan.
/// Payload: [ssid_len, pass_len, security, ssid..., password...]
unsafe fn send_connect(s: &mut WifiConnectState) -> bool {
    if s.out_chan < 0 {
        dev_log(&*s.syscalls, 1, b"[wifi] no ctrl ch".as_ptr(), 17);
        return false;
    }
    let sys = &*s.syscalls;

    let ssid_len = s.assoc_buf[0] as usize;
    let pass_len = s.assoc_buf[1] as usize;

    // Payload: [ssid_len, pass_len, security, ssid..., password...]
    let payload_len = 3 + ssid_len + pass_len;
    let mut cmd = [0u8; 3 + MAX_SSID_LEN + MAX_PASS_LEN];
    let cp = cmd.as_mut_ptr();
    let ap = s.assoc_buf.as_ptr();
    *cp = ssid_len as u8;
    *cp.add(1) = pass_len as u8;
    *cp.add(2) = s.security;

    let mut i = 0;
    while i < ssid_len {
        *cp.add(3 + i) = *ap.add(2 + i);
        i += 1;
    }
    i = 0;
    while i < pass_len {
        *cp.add(3 + ssid_len + i) = *ap.add(2 + MAX_SSID_LEN + i);
        i += 1;
    }

    let r = msg_write(sys, s.out_chan, MSG_CONNECT, cmd.as_ptr(), payload_len as u16);
    r >= 0
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<WifiConnectState>() as u32
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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<WifiConnectState>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut WifiConnectState);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;          // in[0]: status events
        s.out_chan = out_chan;        // out[0]: commands → cyw43.ctrl
        s.netif_handle = -1;
        s.phase = WifiPhase::Init;

        // Require in[0] (status from cyw43) and out[0] (commands to cyw43)
        if in_chan < 0 || out_chan < 0 {
            log_err(s, b"[wifi] in[0]+out[0] required");
            return -3;
        }

        // Discover secondary input: binary scan results (in[1])
        s.scan_chan = dev_channel_port(&*s.syscalls, 0, 1); // port_type=in, index=1

        // Parse credentials from TLV params
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
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
        let s = &mut *(state as *mut WifiConnectState);
        let sys_ptr = s.syscalls;
        let sys = &*sys_ptr;
        let now = dev_millis(sys);

        // Always drain status events first (non-blocking)
        drain_status_events(s);

        // ════════════════════════════════════════════════════════════════
        // WiFi Phase Transitions (IEEE 802.11 association, simplified)
        // ════════════════════════════════════════════════════════════════
        //
        // Phase           | Trigger                 | Next             | Timeout / Retry
        // ────────────────|─────────────────────────|──────────────────|──────────────────
        // Init            | always                  | NetifOpen        |
        // NetifOpen       | netif handle acquired   | WaitReady        | retry @ 3s
        // WaitReady       | RADIO_READY event       | Associate        |
        // WaitReady       | netif NO_ADDR/READY     | Connected        | (fallback poll)
        // WaitReady       | netif ERROR             | Disconnected     |
        // Associate       | has credentials         | WaitConnected    | send CONNECT
        // Associate       | no creds + scan_chan    | CollectScan      | send SCAN
        // Associate       | no creds, no scan_chan  | Scan             | send SCAN
        // CollectScan     | SCAN_DONE event         | SelectNetwork    | 10s timeout
        // SelectNetwork   | always                  | ScanDone         |
        // WaitConnected   | CONNECTED event         | Connected        |
        // WaitConnected   | netif NO_ADDR/READY     | Connected        | (fallback poll)
        // WaitConnected   | timeout                 | Disconnected     | 15s
        // Connected       | always                  | Monitor          |
        // Monitor         | DISCONNECTED event      | Disconnected     | (drain_status)
        // Monitor         | netif poll != connected | Disconnected     | poll @ 5s
        // Disconnected    | backoff elapsed         | WaitReady        | 3s (×4 after 5)
        // Scan            | timeout                 | ScanDone         | 10s
        // ScanDone        | (terminal)              | —                |
        //
        match s.phase {
            WifiPhase::Init => {
                log_msg(s, b"[wifi] init");
                s.phase = WifiPhase::NetifOpen;
            }

            WifiPhase::NetifOpen => {
                let mut ntype = [NETIF_TYPE_WIFI];
                let handle = (sys.dev_call)(-1, DEV_NETIF_OPEN, ntype.as_mut_ptr(), 1);
                if handle >= 0 {
                    s.netif_handle = handle;
                    s.phase = WifiPhase::WaitReady;
                    log_msg(s, b"[wifi] opened");
                } else {
                    if now - s.last_time_ms > RECONNECT_DELAY_MS {
                        s.last_time_ms = now;
                        log_err(s, b"[wifi] open fail");
                    }
                }
            }

            WifiPhase::WaitReady => {
                // Event-driven: check if we got RADIO_READY event
                if s.radio_ready {
                    s.phase = WifiPhase::Associate;
                    return 0;
                }
                // Fallback: poll netif state directly
                let st = (sys.dev_call)(s.netif_handle, DEV_NETIF_STATE, core::ptr::null_mut(), 0);
                if st as u8 == NETIF_STATE_NO_LINK || st as u8 == NETIF_STATE_NO_ADDRESS || st as u8 == NETIF_STATE_READY {
                    if st as u8 == NETIF_STATE_NO_ADDRESS || st as u8 == NETIF_STATE_READY {
                        s.phase = WifiPhase::Connected;
                        log_msg(s, b"[wifi] already up");
                    } else {
                        s.phase = WifiPhase::Associate;
                    }
                } else if st as u8 == NETIF_STATE_ERROR {
                    log_err(s, b"[wifi] radio err");
                    s.phase = WifiPhase::Disconnected;
                    s.last_time_ms = now;
                }
            }

            WifiPhase::Associate => {
                if s.out_chan < 0 {
                    log_err(s, b"[wifi] no ctrl ch");
                    s.phase = WifiPhase::Disconnected;
                    s.last_time_ms = now;
                } else {
                    let ssid_len = s.assoc_buf[0] as usize;

                    if ssid_len == 0 {
                        // No credentials — initiate scan via FMP
                        let r = msg_write_empty(sys, s.out_chan, MSG_SCAN);
                        if r < 0 {
                            log_err(s, b"[wifi] write fail");
                            s.phase = WifiPhase::Disconnected;
                            s.last_time_ms = now;
                        } else {
                            log_msg(s, b"[wifi] scanning");
                            s.scan_count = 0;
                            // If we have scan_chan, collect results; otherwise just wait
                            if s.scan_chan >= 0 {
                                s.phase = WifiPhase::CollectScan;
                            } else {
                                s.phase = WifiPhase::Scan;
                            }
                            s.last_time_ms = now;
                        }
                    } else {
                        // Has credentials — send connect
                        log_msg(s, b"[wifi] connecting");
                        if send_connect(s) {
                            s.phase = WifiPhase::WaitConnected;
                            s.last_time_ms = now;
                        } else {
                            s.phase = WifiPhase::Disconnected;
                            s.last_time_ms = now;
                        }
                    }
                }
            }

            WifiPhase::CollectScan => {
                // Read all available scan results from scan_chan (in[1])
                while read_scan_result(s) {}

                // Timeout: if no SCAN_DONE event arrives within 10s, move on
                if now - s.last_time_ms > 10000 {
                    log_msg(s, b"[wifi] scan timeout");
                    s.phase = WifiPhase::SelectNetwork;
                }
                // Note: drain_status_events() sets WifiPhase::SelectNetwork on SCAN_DONE
            }

            WifiPhase::SelectNetwork => {
                // Drain any remaining scan results
                while read_scan_result(s) {}

                if s.scan_count == 0 {
                    log_msg(s, b"[wifi] no networks");
                }
                // Scan-only mode: results already forwarded to debug via cyw43.out[1]
                s.phase = WifiPhase::ScanDone;
            }

            WifiPhase::WaitConnected => {
                // Event-driven path handled by drain_status_events() above
                // Fallback: poll netif state
                let st = (sys.dev_call)(s.netif_handle, DEV_NETIF_STATE, core::ptr::null_mut(), 0);
                if st as u8 == NETIF_STATE_NO_ADDRESS || st as u8 == NETIF_STATE_READY {
                    s.phase = WifiPhase::Connected;
                    s.retry_count = 0;
                    log_msg(s, b"[wifi] connected");
                } else if now - s.last_time_ms > ASSOCIATE_TIMEOUT_MS {
                    log_err(s, b"[wifi] timeout");
                    s.phase = WifiPhase::Disconnected;
                    s.last_time_ms = now;
                }
            }

            WifiPhase::Connected => {
                s.phase = WifiPhase::Monitor;
                s.last_time_ms = now;
            }

            WifiPhase::Monitor => {
                // Event-driven path: DISCONNECTED event handled by drain_status_events()
                // Fallback: poll netif periodically
                if now - s.last_time_ms >= MONITOR_INTERVAL_MS {
                    s.last_time_ms = now;
                    let st = (sys.dev_call)(s.netif_handle, DEV_NETIF_STATE, core::ptr::null_mut(), 0);
                    if st as u8 != NETIF_STATE_NO_ADDRESS && st as u8 != NETIF_STATE_READY {
                        log_err(s, b"[wifi] lost");
                        s.phase = WifiPhase::Disconnected;
                        s.last_time_ms = now;
                    }
                }
            }

            WifiPhase::Disconnected => {
                let delay = if s.retry_count < MAX_QUICK_RETRIES {
                    RECONNECT_DELAY_MS
                } else {
                    RECONNECT_DELAY_MS * 4
                };
                if now - s.last_time_ms >= delay {
                    s.retry_count = s.retry_count.saturating_add(1);
                    s.phase = WifiPhase::WaitReady;
                    log_msg(s, b"[wifi] retry");
                }
            }

            WifiPhase::Scan => {
                // Scan mode (no scan_chan): wait for timeout
                if now - s.last_time_ms > 10000 {
                    log_msg(s, b"[wifi] scan done");
                    s.phase = WifiPhase::ScanDone;
                }
            }

            WifiPhase::ScanDone => {
                // Terminal state — module idle after scan
            }

            _ => {
                s.phase = WifiPhase::Init;
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
