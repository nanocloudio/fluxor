//! CH9120 UART-to-Ethernet Driver PIC Module
//!
//! Transparent serial-to-network bridge using the WCH CH9120 TCP/IP offload
//! chip. The CH9120 has its own internal TCP/IP stack and operates as a
//! transparent bridge: UART TX data goes out on the network, network data
//! arrives on UART RX.
//!
//! Configuration is done via serial commands while the CFG0 pin is held low
//! (fixed 9600 baud). After configuration, CFG0 goes high and the chip
//! operates in transparent data mode at the configured baud rate.
//!
//! **Params (TLV v2):**
//!   tag 1: reset_pin (u8, default 14)
//!   tag 2: cfg0_pin (u8, default 15)
//!   tag 3: uart_bus (u8, default 0)
//!   tag 4: net_mode (u8, default 1 = TCP client)
//!   tag 5: local_port (u16, default 8080)
//!   tag 6: dest_port (u16, default 8080)
//!   tag 7: data_baud (u32, default 115200)
//!   tag 8: use_dhcp (u8, default 1 = on)
//!   tag 9: local_ip (u32, default 192.168.1.200)
//!   tag 10: subnet (u32, default 255.255.255.0)
//!   tag 11: gateway (u32, default 192.168.1.1)
//!   tag 12: dest_ip (u32, default 192.168.1.100)
//!
//! Channels:
//!   - in_chan: Data to send to the network (channel → UART TX → CH9120 → net)
//!   - out_chan: Data received from the network (net → CH9120 → UART RX → channel)

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

mod constants;
use constants::*;

// ============================================================================
// State Machine Enums
// ============================================================================

// ════════════════════════════════════════════════════════════════
// CH9120 Phase Transitions
// ════════════════════════════════════════════════════════════════
//
// Phase           | Trigger                | Next             | Notes
// ────────────────|────────────────────────|──────────────────|──────────────────
// Init            | GPIO claimed ok        | Reset            | claim reset + cfg0 pins
// Init            | GPIO claim failed      | Error            |
// Reset           | reset pulse done       | EnterConfig      | 50ms low → high, 200ms settle
// EnterConfig     | UART opened at 9600    | Configure        | CFG0 pin pulled low
// EnterConfig     | UART open failed       | Error            |
// Configure       | cmd written + acked    | Configure        | config_step++ (8 commands)
// Configure       | all cmds done          | SaveExit         | config_step >= NUM_CONFIG_CMDS
// Configure       | UART error             | Error            |
// SaveExit        | save+exec acked        | ReopenUart       | CMD_SAVE then CMD_EXEC
// ReopenUart      | UART reopened          | OpenNetif        | close 9600, open at data_baud
// OpenNetif       | netif handle acquired  | Running          |
// Running         | (continuous)           | Running          | bridge data, poll link
// Error           | always                 | (terminal)       | return -1

/// CH9120 driver lifecycle phases.
///
/// Ref: CH9120 datasheet §3 (configuration mode) + §4 (data mode)
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Ch9120Phase {
    Init = 0,
    Reset = 1,
    EnterConfig = 2,
    Configure = 3,
    SaveExit = 4,
    ReopenUart = 5,
    OpenNetif = 6,
    Running = 7,
    Error = 255,
}

/// UART command substep within Configure and SaveExit phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum CmdSubstep {
    WriteCmd = 0,
    WaitWrite = 1,
    ReadResp = 2,
    WaitRead = 3,
    Next = 4,
}

/// Reset pin substep.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum ResetSubstep {
    PulseLow = 0,
    WaitPulse = 1,
    PulseHigh = 2,
    WaitSettle = 3,
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct Ch9120State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    // Hardware handles
    uart_handle: i32,
    reset_handle: i32,
    cfg0_handle: i32,
    netif_handle: i32,
    // State machine
    phase: Ch9120Phase,
    config_step: u8,
    cmd_substep: CmdSubstep,
    reset_substep: ResetSubstep,
    save_step: u8,
    _pad0: u8,
    // Timing
    deadline_ms: u64,
    // Config command buffer
    cmd_buf: [u8; CMD_BUF_SIZE],
    cmd_len: u8,
    resp_buf: [u8; RESP_BUF_SIZE],
    _pad1: u8,
    // Data bridge buffers
    rx_buf: [u8; DATA_BUF_SIZE],
    tx_buf: [u8; DATA_BUF_SIZE],
    tx_pending: u16,
    tx_offset: u16,
    // Params (from config)
    reset_pin: u8,
    cfg0_pin: u8,
    uart_bus: u8,
    net_mode: u8,
    local_ip: [u8; 4],
    subnet: [u8; 4],
    gateway: [u8; 4],
    dest_ip: [u8; 4],
    local_port: u16,
    dest_port: u16,
    data_baud: u32,
    use_dhcp: u8,
}

impl Ch9120State {
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::Ch9120State;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        Ch9120State;

        1, reset_pin, u8, 14
            => |s, d, len| { s.reset_pin = p_u8(d, len, 0, 14); };

        2, cfg0_pin, u8, 15
            => |s, d, len| { s.cfg0_pin = p_u8(d, len, 0, 15); };

        3, uart_bus, u8, 0
            => |s, d, len| { s.uart_bus = p_u8(d, len, 0, 0); };

        4, net_mode, u8, 1, enum { tcp_server=0, tcp_client=1, udp_server=2, udp_client=3 }
            => |s, d, len| { s.net_mode = p_u8(d, len, 0, 1); };

        5, local_port, u16, 8080
            => |s, d, len| { s.local_port = p_u16(d, len, 0, 8080); };

        6, dest_port, u16, 8080
            => |s, d, len| { s.dest_port = p_u16(d, len, 0, 8080); };

        7, data_baud, u32, 115200
            => |s, d, len| { s.data_baud = p_u32(d, len, 0, 115200); };

        8, use_dhcp, u8, 1, enum { off=0, on=1 }
            => |s, d, len| { s.use_dhcp = p_u8(d, len, 0, 1); };

        9, local_ip, u32, 0xC8A80100
            => |s, d, len| {
                let v = p_u32(d, len, 0, 0xC8A80100);
                s.local_ip = v.to_le_bytes();
            };

        10, subnet, u32, 0x00FFFFFF
            => |s, d, len| {
                let v = p_u32(d, len, 0, 0x00FFFFFF);
                s.subnet = v.to_le_bytes();
            };

        11, gateway, u32, 0x01A8C0
            => |s, d, len| {
                let v = p_u32(d, len, 0, 0x01A8C0);
                s.gateway = v.to_le_bytes();
            };

        12, dest_ip, u32, 0x64A8C0
            => |s, d, len| {
                let v = p_u32(d, len, 0, 0x64A8C0);
                s.dest_ip = v.to_le_bytes();
            };
    }
}

// ============================================================================
// dev_call Helpers
// ============================================================================

unsafe fn dev_gpio_claim(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.dev_call)(-1, DEV_GPIO_CLAIM, arg.as_mut_ptr(), 1)
}

unsafe fn dev_gpio_set_mode(sys: &SyscallTable, handle: i32, mode: u8, initial: u8) -> i32 {
    let mut arg = [mode, initial];
    (sys.dev_call)(handle, DEV_GPIO_SET_MODE, arg.as_mut_ptr(), 2)
}

unsafe fn dev_gpio_set_level(sys: &SyscallTable, handle: i32, level: u8) -> i32 {
    let mut arg = [level];
    (sys.dev_call)(handle, DEV_GPIO_SET_LEVEL, arg.as_mut_ptr(), 1)
}

unsafe fn dev_uart_open(sys: &SyscallTable, bus: u8) -> i32 {
    let mut arg = [bus];
    (sys.dev_call)(-1, DEV_UART_OPEN, arg.as_mut_ptr(), 1)
}

unsafe fn dev_uart_close(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, DEV_UART_CLOSE, core::ptr::null_mut(), 0)
}

unsafe fn dev_uart_write(sys: &SyscallTable, handle: i32, data: *const u8, len: usize) -> i32 {
    (sys.dev_call)(handle, DEV_UART_WRITE, data as *mut u8, len)
}

unsafe fn dev_uart_read(sys: &SyscallTable, handle: i32, buf: *mut u8, len: usize) -> i32 {
    (sys.dev_call)(handle, DEV_UART_READ, buf, len)
}

unsafe fn dev_uart_poll(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, DEV_UART_POLL, core::ptr::null_mut(), 0)
}

unsafe fn dev_netif_open(sys: &SyscallTable, if_type: u8) -> i32 {
    let mut arg = [if_type];
    (sys.dev_call)(-1, DEV_NETIF_OPEN, arg.as_mut_ptr(), 1)
}

// ============================================================================
// CH9120 Config Command Builders
// ============================================================================

/// Build a config command in cmd_buf. Returns the total command length.
fn build_config_cmd(buf: &mut [u8; CMD_BUF_SIZE], cmd: u8, args: &[u8]) -> u8 {
    buf[0] = CMD_PREFIX[0];
    buf[1] = CMD_PREFIX[1];
    buf[2] = cmd;
    let arg_len = args.len().min(CMD_BUF_SIZE - 3);
    let mut i = 0;
    while i < arg_len {
        buf[3 + i] = args[i];
        i += 1;
    }
    (3 + arg_len) as u8
}

/// Build the config command for the given config_step index.
unsafe fn build_step_cmd(s: &mut Ch9120State) {
    let len = match s.config_step {
        0 => build_config_cmd(&mut s.cmd_buf, CMD_SET_MODE, &[s.net_mode]),
        1 => {
            if s.use_dhcp != 0 {
                build_config_cmd(&mut s.cmd_buf, CMD_SET_DHCP, &[1])
            } else {
                build_config_cmd(&mut s.cmd_buf, CMD_SET_LOCAL_IP, &s.local_ip)
            }
        }
        2 => build_config_cmd(&mut s.cmd_buf, CMD_SET_SUBNET, &s.subnet),
        3 => build_config_cmd(&mut s.cmd_buf, CMD_SET_GATEWAY, &s.gateway),
        4 => {
            let port_le = s.local_port.to_le_bytes();
            build_config_cmd(&mut s.cmd_buf, CMD_SET_LOCAL_PORT, &port_le)
        }
        5 => {
            // Destination IP (skip for server modes)
            if s.net_mode == MODE_TCP_SERVER || s.net_mode == MODE_UDP_SERVER {
                // No-op: build a version query as a harmless placeholder
                build_config_cmd(&mut s.cmd_buf, CMD_GET_VERSION, &[])
            } else {
                build_config_cmd(&mut s.cmd_buf, CMD_SET_DEST_IP, &s.dest_ip)
            }
        }
        6 => {
            // Destination port (skip for server modes)
            if s.net_mode == MODE_TCP_SERVER || s.net_mode == MODE_UDP_SERVER {
                build_config_cmd(&mut s.cmd_buf, CMD_GET_VERSION, &[])
            } else {
                let port_le = s.dest_port.to_le_bytes();
                build_config_cmd(&mut s.cmd_buf, CMD_SET_DEST_PORT, &port_le)
            }
        }
        7 => {
            let baud_le = s.data_baud.to_le_bytes();
            build_config_cmd(&mut s.cmd_buf, CMD_SET_BAUD, &baud_le)
        }
        _ => build_config_cmd(&mut s.cmd_buf, CMD_GET_VERSION, &[]),
    };
    s.cmd_len = len;
}

// ============================================================================
// Phase Step Functions
// ============================================================================

unsafe fn step_init(s: &mut Ch9120State) -> i32 {
    let sys = &*s.syscalls;

    // Claim reset pin as output, initially high (not in reset)
    let rh = dev_gpio_claim(sys, s.reset_pin);
    if rh < 0 {
        dev_log(sys, 1, b"[ch9120] reset pin claim failed".as_ptr(), 31);
        s.phase = Ch9120Phase::Error;
        return -1;
    }
    dev_gpio_set_mode(sys, rh, 1, 1);
    s.reset_handle = rh;

    // Claim CFG0 pin as output, initially high (normal mode)
    let ch = dev_gpio_claim(sys, s.cfg0_pin);
    if ch < 0 {
        dev_log(sys, 1, b"[ch9120] cfg0 pin claim failed".as_ptr(), 30);
        s.phase = Ch9120Phase::Error;
        return -1;
    }
    dev_gpio_set_mode(sys, ch, 1, 1);
    s.cfg0_handle = ch;

    s.phase = Ch9120Phase::Reset;
    s.reset_substep = ResetSubstep::PulseLow;
    0
}

unsafe fn step_reset(s: &mut Ch9120State) -> i32 {
    let sys = &*s.syscalls;
    let now = dev_millis(sys);

    match s.reset_substep {
        ResetSubstep::PulseLow => {
            // Pull reset low
            dev_gpio_set_level(sys, s.reset_handle, 0);
            s.deadline_ms = now.wrapping_add(RESET_PULSE_MS);
            s.reset_substep = ResetSubstep::WaitPulse;
        }
        ResetSubstep::WaitPulse => {
            if now >= s.deadline_ms {
                s.reset_substep = ResetSubstep::PulseHigh;
            }
        }
        ResetSubstep::PulseHigh => {
            // Release reset (high)
            dev_gpio_set_level(sys, s.reset_handle, 1);
            s.deadline_ms = now.wrapping_add(RESET_SETTLE_MS);
            s.reset_substep = ResetSubstep::WaitSettle;
        }
        ResetSubstep::WaitSettle => {
            if now >= s.deadline_ms {
                s.phase = Ch9120Phase::EnterConfig;
            }
        }
        _ => {
            s.phase = Ch9120Phase::Error;
            return -1;
        }
    }
    0
}

unsafe fn step_enter_config(s: &mut Ch9120State) -> i32 {
    let sys = &*s.syscalls;

    // Pull CFG0 low to enter configuration mode
    dev_gpio_set_level(sys, s.cfg0_handle, 0);

    // Open UART at config baud rate (9600)
    let handle = dev_uart_open(sys, s.uart_bus);
    if handle < 0 {
        dev_log(sys, 1, b"[ch9120] uart open failed".as_ptr(), 25);
        s.phase = Ch9120Phase::Error;
        return -1;
    }
    s.uart_handle = handle;

    // Start configuration sequence
    s.config_step = 0;
    s.cmd_substep = CmdSubstep::WriteCmd;
    s.phase = Ch9120Phase::Configure;

    dev_log(sys, 3, b"[ch9120] config mode".as_ptr(), 20);
    0
}

unsafe fn step_configure(s: &mut Ch9120State) -> i32 {
    // All config commands done?
    if s.config_step >= NUM_CONFIG_CMDS {
        s.phase = Ch9120Phase::SaveExit;
        s.save_step = 0;
        s.cmd_substep = CmdSubstep::WriteCmd;
        return 0;
    }

    match s.cmd_substep {
        CmdSubstep::WriteCmd => {
            build_step_cmd(s);
            let len = s.cmd_len as usize;
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            dev_uart_write(sys, handle, s.cmd_buf.as_ptr(), len);
            s.cmd_substep = CmdSubstep::WaitWrite;
        }
        CmdSubstep::WaitWrite => {
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            let result = dev_uart_poll(sys, handle);
            if result > 0 {
                s.cmd_substep = CmdSubstep::ReadResp;
            } else if result < 0 {
                s.phase = Ch9120Phase::Error;
                return -1;
            }
        }
        CmdSubstep::ReadResp => {
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            dev_uart_read(sys, handle, s.resp_buf.as_mut_ptr(), RESP_BUF_SIZE);
            s.cmd_substep = CmdSubstep::WaitRead;
        }
        CmdSubstep::WaitRead => {
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            let result = dev_uart_poll(sys, handle);
            if result > 0 || result == 0 {
                // CH9120 may not echo all commands — advance regardless.
                s.cmd_substep = CmdSubstep::Next;
            } else {
                s.phase = Ch9120Phase::Error;
                return -1;
            }
        }
        CmdSubstep::Next => {
            s.config_step += 1;
            s.cmd_substep = CmdSubstep::WriteCmd;
        }
        _ => {
            s.phase = Ch9120Phase::Error;
            return -1;
        }
    }
    0
}

unsafe fn step_save_exit(s: &mut Ch9120State) -> i32 {
    // save_step: 0=write_save, 1=wait_save, 2=write_exec, 3=wait_exec
    match s.save_step {
        0 => {
            s.cmd_len = build_config_cmd(&mut s.cmd_buf, CMD_SAVE, &[]);
            let handle = s.uart_handle;
            let len = s.cmd_len as usize;
            let sys = &*s.syscalls;
            dev_uart_write(sys, handle, s.cmd_buf.as_ptr(), len);
            s.save_step = 1;
        }
        1 => {
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            let result = dev_uart_poll(sys, handle);
            if result > 0 {
                s.save_step = 2;
            } else if result < 0 {
                s.phase = Ch9120Phase::Error;
                return -1;
            }
        }
        2 => {
            s.cmd_len = build_config_cmd(&mut s.cmd_buf, CMD_EXEC, &[]);
            let handle = s.uart_handle;
            let len = s.cmd_len as usize;
            let sys = &*s.syscalls;
            dev_uart_write(sys, handle, s.cmd_buf.as_ptr(), len);
            s.save_step = 3;
        }
        3 => {
            let handle = s.uart_handle;
            let sys = &*s.syscalls;
            let result = dev_uart_poll(sys, handle);
            if result > 0 || result == 0 {
                // CMD_EXEC triggers chip reset; may not get response
                s.phase = Ch9120Phase::ReopenUart;
            } else {
                s.phase = Ch9120Phase::Error;
                return -1;
            }
        }
        _ => {
            s.phase = Ch9120Phase::Error;
            return -1;
        }
    }
    0
}

unsafe fn step_reopen_uart(s: &mut Ch9120State) -> i32 {
    let sys = &*s.syscalls;

    // Close config-mode UART
    dev_uart_close(sys, s.uart_handle);
    s.uart_handle = -1;

    // Pull CFG0 high (exit config mode, enter data mode)
    dev_gpio_set_level(sys, s.cfg0_handle, 1);

    // Reopen UART (kernel will use default baud; we configured CH9120 to match data_baud)
    let handle = dev_uart_open(sys, s.uart_bus);
    if handle < 0 {
        dev_log(sys, 1, b"[ch9120] uart reopen failed".as_ptr(), 27);
        s.phase = Ch9120Phase::Error;
        return -1;
    }
    s.uart_handle = handle;

    dev_log(sys, 3, b"[ch9120] data mode".as_ptr(), 18);
    s.phase = Ch9120Phase::OpenNetif;
    0
}

unsafe fn step_open_netif(s: &mut Ch9120State) -> i32 {
    let sys = &*s.syscalls;

    let handle = dev_netif_open(sys, NETIF_TYPE_ETHERNET);
    if handle >= 0 {
        s.netif_handle = handle;
        dev_netif_set_state(sys, handle, NETIF_STATE_READY);
    }
    // Netif registration is optional — don't fail if unavailable

    dev_log(sys, 3, b"[ch9120] running".as_ptr(), 16);
    s.phase = Ch9120Phase::Running;
    0
}

unsafe fn step_running(s: &mut Ch9120State) -> i32 {
    let uart = s.uart_handle;
    let in_ch = s.in_chan;
    let out_ch = s.out_chan;
    let sysp = s.syscalls;
    let sys = &*sysp;
    let mut did_work = false;

    // 1. Drain any pending UART TX from previous step
    if s.tx_pending > 0 {
        let result = dev_uart_poll(sys, uart);
        if result > 0 || result < 0 {
            s.tx_pending = 0;
            s.tx_offset = 0;
        }
    }

    // 2. Check UART RX → output channel
    if out_ch >= 0 {
        dev_uart_read(sys, uart, s.rx_buf.as_mut_ptr(), DATA_BUF_SIZE);
        let result = dev_uart_poll(sys, uart);
        if result > 0 {
            let bytes = result as usize;
            let poll = (sys.channel_poll)(out_ch, POLL_OUT);
            if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
                (sys.channel_write)(out_ch, s.rx_buf.as_ptr(), bytes);
                did_work = true;
            }
        }
    }

    // 3. Check input channel → UART TX
    if in_ch >= 0 && s.tx_pending == 0 {
        let poll = (sys.channel_poll)(in_ch, POLL_IN);
        if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            let bytes = (sys.channel_read)(in_ch, s.tx_buf.as_mut_ptr(), DATA_BUF_SIZE);
            if bytes > 0 {
                dev_uart_write(sys, uart, s.tx_buf.as_ptr(), bytes as usize);
                s.tx_pending = bytes as u16;
                s.tx_offset = 0;
                did_work = true;
            }
        }
    }

    if did_work { 2 } else { 0 }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Ch9120State>() as u32
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
        if state_size < core::mem::size_of::<Ch9120State>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut Ch9120State);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.uart_handle = -1;
        s.reset_handle = -1;
        s.cfg0_handle = -1;
        s.netif_handle = -1;
        s.phase = Ch9120Phase::Init;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
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
        let s = &mut *(state as *mut Ch9120State);
        if s.syscalls.is_null() {
            return -1;
        }

        match s.phase {
            Ch9120Phase::Init => step_init(s),
            Ch9120Phase::Reset => step_reset(s),
            Ch9120Phase::EnterConfig => step_enter_config(s),
            Ch9120Phase::Configure => step_configure(s),
            Ch9120Phase::SaveExit => step_save_exit(s),
            Ch9120Phase::ReopenUart => step_reopen_uart(s),
            Ch9120Phase::OpenNetif => step_open_netif(s),
            Ch9120Phase::Running => step_running(s),
            Ch9120Phase::Error => -1,
            _ => {
                s.phase = Ch9120Phase::Error;
                -1
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn module_drop(
    state: *mut u8,
    _state_size: usize,
    _syscalls: *const c_void,
) {
    // Kernel's release_module_handles() cleans up UART and GPIO handles
    // automatically on module finish. Nothing extra needed here.
    if state.is_null() {
        return;
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
