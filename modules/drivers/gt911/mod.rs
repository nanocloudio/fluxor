//! GT911 Capacitive Touch Controller PIC Module
//!
//! Board-agnostic driver for GT911 5-point capacitive touch controllers.
//! Communicates via I2C; all pin assignments configurable via params.
//!
//! # Initialization
//!
//! 1. Address selection: INT low + RST pulse → addr 0x5D
//! 2. Wait for boot (55ms + 50ms)
//! 3. Open I2C handle, verify product ID (reg 0x8140)
//! 4. Create event, bind to INT falling edge
//!
//! # Runtime
//!
//! On INT falling edge: read status register (0x814E), read touch points
//! (0x8150+), clear status, write TouchEvent to output channel.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

const GT911_ADDR_LOW: u8 = 0x5D;  // INT low during reset → 0x5D

// GT911 registers
const REG_PRODUCT_ID: u16 = 0x8140;
const REG_STATUS: u16 = 0x814E;
const REG_POINT1: u16 = 0x8150;

// Touch point data size: 8 bytes per point (x2, y2, size2, reserved2)
const POINT_SIZE: usize = 8;

/// GT911 touch controller init + polling phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Gt911Phase {
    ResetLow = 0,
    AddrSelect = 1,
    WaitBoot = 2,
    OpenI2c = 3,
    ReadIdStart = 4,
    ReadIdPoll = 5,
    Running = 6,
    ReadStatusStart = 7,
    ReadStatusPoll = 8,
    ReadPointsStart = 9,
    ReadPointsPoll = 10,
    ClearStatusStart = 11,
    ClearStatusPoll = 12,
    Error = 255,
}

// ============================================================================
// Touch event output format
// ============================================================================

/// Touch event written to output channel (8 bytes).
#[repr(C)]
struct TouchEvent {
    x: u16,
    y: u16,
    event_type: u8,   // 1=press, 2=release, 3=move
    touch_count: u8,
    pressure: u16,
}

const TOUCH_PRESS: u8 = 1;
const TOUCH_RELEASE: u8 = 2;
const TOUCH_MOVE: u8 = 3;

// ============================================================================
// Module state
// ============================================================================

#[repr(C)]
struct Gt911State {
    syscalls: *const SyscallTable,
    out_chan: i32,
    timer_fd: i32,
    i2c_handle: i32,
    event_fd: i32,

    // GPIO handles
    int_handle: i32,
    rst_handle: i32,

    // State machine
    phase: Gt911Phase,
    was_touching: u8,

    // Config (from params)
    i2c_bus: u8,
    addr: u8,
    int_pin: u8,
    rst_pin: u8,

    // I2C transfer buffer: 2 bytes tx_len + 2 bytes reg addr + space for rx
    // Max rx: 4 bytes product ID, or 1 byte status, or 5*8=40 bytes point data
    xfer_buf: [u8; 48],
    touch_count: u8,
}

impl Gt911State {
    #[inline(always)]
    fn sys(&self) -> &SyscallTable {
        unsafe { &*self.syscalls }
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::Gt911State;
    use super::p_u8;
    use super::SCHEMA_MAX;

    define_params! {
        Gt911State;

        1, i2c_bus, u8, 1
            => |s, d, len| { s.i2c_bus = p_u8(d, len, 0, 1); };
        2, addr, u8, 93
            => |s, d, len| { s.addr = p_u8(d, len, 0, 93); };
        3, int_pin, u8, 17
            => |s, d, len| { s.int_pin = p_u8(d, len, 0, 17); };
        4, rst_pin, u8, 16
            => |s, d, len| { s.rst_pin = p_u8(d, len, 0, 16); };
    }
}

// ============================================================================
// I2C helpers
// ============================================================================

/// Set up xfer_buf for I2C write-read: 2-byte tx_len header + register address bytes + rx space.
/// Format: [tx_len_lo, tx_len_hi, reg_hi, reg_lo, ...rx_space...]
/// Returns total arg_len to pass to provider_call.
unsafe fn setup_write_read(s: &mut Gt911State, reg: u16, rx_len: usize) -> usize {
    let tx_len: u16 = 2; // 2 bytes register address
    s.xfer_buf[0] = (tx_len & 0xFF) as u8;
    s.xfer_buf[1] = (tx_len >> 8) as u8;
    s.xfer_buf[2] = (reg >> 8) as u8;   // Register address MSB first
    s.xfer_buf[3] = (reg & 0xFF) as u8;
    2 + 2 + rx_len // tx_len header + tx data + rx space
}

/// Set up xfer_buf for I2C write: register address + data.
/// Returns total arg_len to pass to provider_call.
unsafe fn setup_write(s: &mut Gt911State, reg: u16, data: &[u8]) -> usize {
    s.xfer_buf[0] = (reg >> 8) as u8;
    s.xfer_buf[1] = (reg & 0xFF) as u8;
    let mut i = 0;
    while i < data.len() {
        s.xfer_buf[2 + i] = data[i];
        i += 1;
    }
    2 + data.len()
}

// ============================================================================
// GPIO helpers
// ============================================================================

// Provider contract ids (mirror kernel::provider::contract::*).
const HAL_GPIO_CONTRACT: u32 = 0x0001;
const HAL_I2C_CONTRACT:  u32 = 0x0003;
const TIMER_CONTRACT:    u32 = 0x0006;
const EVENT_CONTRACT:    u32 = 0x000B;

unsafe fn claim_gpio_output(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_open)(HAL_GPIO_CONTRACT, 0x0106, arg.as_mut_ptr(), 1) // GPIO_SET_OUTPUT
}

unsafe fn claim_gpio_input(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_open)(HAL_GPIO_CONTRACT, 0x0107, arg.as_mut_ptr(), 1) // GPIO_SET_INPUT
}

unsafe fn gpio_set(sys: &SyscallTable, handle: i32, level: u8) {
    let mut lvl = [level];
    (sys.provider_call)(handle, 0x0104, lvl.as_mut_ptr(), 1); // GPIO_SET_LEVEL
}

unsafe fn gpio_set_mode_output(sys: &SyscallTable, handle: i32) {
    let mut mode = [1u8]; // 1 = output
    (sys.provider_call)(handle, 0x0102, mode.as_mut_ptr(), 1); // GPIO_SET_MODE
}

unsafe fn gpio_set_mode_input(sys: &SyscallTable, handle: i32) {
    let mut mode = [0u8]; // 0 = input
    (sys.provider_call)(handle, 0x0102, mode.as_mut_ptr(), 1); // GPIO_SET_MODE
}

unsafe fn timer_set(sys: &SyscallTable, timer_fd: i32, delay_ms: u32) -> i32 {
    let mut ms_buf = delay_ms.to_le_bytes();
    (sys.provider_call)(timer_fd, 0x0605, ms_buf.as_mut_ptr(), 4) // TIMER_SET
}

unsafe fn timer_expired(sys: &SyscallTable, timer_fd: i32) -> bool {
    dev_fd_poll(sys, timer_fd, POLL_IN) & (POLL_IN as i32) != 0
}

// ============================================================================
// Module exports
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Gt911State>() as u32
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
    if state.is_null() || syscalls.is_null() {
        return -22; // EINVAL
    }
    if state_size < core::mem::size_of::<Gt911State>() {
        return -12; // ENOMEM
    }

    let s = unsafe { &mut *(state as *mut Gt911State) };
    s.syscalls = syscalls as *const SyscallTable;

    // Parse params
    unsafe {
        params_def::set_defaults(s);
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }
    }

    s.out_chan = out_chan;
    s.timer_fd = -1;
    s.i2c_handle = -1;
    s.event_fd = -1;
    s.int_handle = -1;
    s.rst_handle = -1;
    s.phase = Gt911Phase::ResetLow;
    s.was_touching = 0;
    s.touch_count = 0;

    unsafe {
        let sys = &*s.syscalls;

        // Create timer — tracked against TIMER contract.
        s.timer_fd = (sys.provider_open)(TIMER_CONTRACT, 0x0604, core::ptr::null_mut(), 0);
        if s.timer_fd < 0 {
            return -12;
        }

        // GT911 address selection protocol:
        // 1. INT pin as output, drive low (selects 0x5D)
        // 2. RST pin as output, drive low (assert reset)
        // 3. Wait 10ms

        s.int_handle = claim_gpio_output(sys, s.int_pin);
        if s.int_handle < 0 { return s.int_handle; }

        s.rst_handle = claim_gpio_output(sys, s.rst_pin);
        if s.rst_handle < 0 { return s.rst_handle; }

        // INT low → selects addr 0x5D
        gpio_set(sys, s.int_handle, 0);
        // RST low → assert reset
        gpio_set(sys, s.rst_handle, 0);

        timer_set(sys, s.timer_fd, 10);
    }

    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut Gt911State) };
    let sys = unsafe { &*s.syscalls };

    match s.phase {
        Gt911Phase::ResetLow => {
            // Wait 10ms with RST+INT low
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return 0;
            }
            // Release RST (high), keep INT low for addr selection
            unsafe {
                gpio_set(sys, s.rst_handle, 1);
                timer_set(sys, s.timer_fd, 55);
            }
            s.phase = Gt911Phase::AddrSelect;
            0
        }

        Gt911Phase::AddrSelect => {
            // Wait 55ms for RST rise
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return 0;
            }
            // Change INT to input (release bus)
            unsafe {
                gpio_set_mode_input(sys, s.int_handle);
                timer_set(sys, s.timer_fd, 50);
            }
            s.phase = Gt911Phase::WaitBoot;
            0
        }

        Gt911Phase::WaitBoot => {
            // Wait 50ms for GT911 boot
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return 0;
            }
            s.phase = Gt911Phase::OpenI2c;
            2 // Burst
        }

        Gt911Phase::OpenI2c => {
            // Open I2C handle
            let mut arg = [0u8; 7];
            arg[0] = s.i2c_bus;
            arg[1] = s.addr;
            // arg[2] = padding
            // arg[3..7] = freq_hz (400kHz default if < 7 bytes, but let's be explicit)
            let freq: u32 = 400_000;
            let fb = freq.to_le_bytes();
            arg[3] = fb[0];
            arg[4] = fb[1];
            arg[5] = fb[2];
            arg[6] = fb[3];

            let handle = unsafe {
                (sys.provider_open)(HAL_I2C_CONTRACT, 0x0300, arg.as_mut_ptr(), 7) // I2C_OPEN
            };
            if handle < 0 {
                s.phase = Gt911Phase::Error;
                return handle;
            }
            s.i2c_handle = handle;
            s.phase = Gt911Phase::ReadIdStart;
            2 // Burst
        }

        Gt911Phase::ReadIdStart => {
            // Read product ID: reg 0x8140, 4 bytes
            let arg_len = unsafe { setup_write_read(s, REG_PRODUCT_ID, 4) };
            let rc = unsafe {
                (sys.provider_call)(
                    s.i2c_handle,
                    0x0304, // I2C_WRITE_READ
                    s.xfer_buf.as_mut_ptr(),
                    arg_len,
                )
            };
            if rc < 0 && rc != E_INPROGRESS { // EINPROGRESS is expected
                s.phase = Gt911Phase::Error;
                return rc;
            }
            s.phase = Gt911Phase::ReadIdPoll;
            0
        }

        Gt911Phase::ReadIdPoll => {
            // Poll for I2C completion
            let arg_len = unsafe { setup_write_read(s, REG_PRODUCT_ID, 4) };
            let rc = unsafe {
                (sys.provider_call)(
                    s.i2c_handle,
                    0x0304, // I2C_WRITE_READ
                    s.xfer_buf.as_mut_ptr(),
                    arg_len,
                )
            };
            if rc == 0 {
                return 0; // Still pending
            }
            if rc < 0 {
                s.phase = Gt911Phase::Error;
                return rc;
            }
            // Product ID is at xfer_buf[4..8] (after tx_len header + tx data)
            // Expected: "911\0" or similar. Just verify non-zero.
            // GT911 returns ASCII: '9','1','1','\0'
            let id_offset = 4; // 2 bytes tx_len + 2 bytes tx data
            if s.xfer_buf[id_offset] == 0 {
                s.phase = Gt911Phase::Error;
                return -19; // ENODEV
            }

            // Create event for INT pin edge detection
            unsafe {
                s.event_fd = (sys.provider_open)(EVENT_CONTRACT, 0x0B00, core::ptr::null_mut(), 0); // EVENT_CREATE
                if s.event_fd < 0 {
                    s.phase = Gt911Phase::Error;
                    return s.event_fd;
                }

                // Bind event to INT pin falling edge
                // WATCH_EDGE: handle=gpio, arg[0]=edge(2=falling), arg[1..5]=event_fd(i32 LE)
                let mut watch_arg = [0u8; 5];
                watch_arg[0] = 2; // FALLING
                let efd_bytes = s.event_fd.to_le_bytes();
                watch_arg[1] = efd_bytes[0];
                watch_arg[2] = efd_bytes[1];
                watch_arg[3] = efd_bytes[2];
                watch_arg[4] = efd_bytes[3];
                let wrc = (sys.provider_call)(s.int_handle, 0x010A, watch_arg.as_mut_ptr(), 5); // WATCH_EDGE
                if wrc < 0 {
                    s.phase = Gt911Phase::Error;
                    return wrc;
                }
            }

            s.phase = Gt911Phase::Running;
            0
        }

        Gt911Phase::Running => {
            // Check if INT event fired (touch data available)
            let poll = unsafe { dev_fd_poll(sys, s.event_fd, POLL_IN) };
            if poll & (POLL_IN as i32) == 0 {
                return 0; // No touch event pending
            }
            // Consume the event signal
            unsafe {
                (sys.provider_call)(s.event_fd, 0x0B02, core::ptr::null_mut(), 0); // EVENT_POLL (clears)
            }
            // Read status register
            s.phase = Gt911Phase::ReadStatusStart;
            2 // Burst
        }

        Gt911Phase::ReadStatusStart => {
            // Read status: reg 0x814E, 1 byte
            let arg_len = unsafe { setup_write_read(s, REG_STATUS, 1) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0304, s.xfer_buf.as_mut_ptr(), arg_len)
            };
            if rc < 0 && rc != E_INPROGRESS { return rc; }
            s.phase = Gt911Phase::ReadStatusPoll;
            0
        }

        Gt911Phase::ReadStatusPoll => {
            let arg_len = unsafe { setup_write_read(s, REG_STATUS, 1) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0304, s.xfer_buf.as_mut_ptr(), arg_len)
            };
            if rc == 0 { return 0; }
            if rc < 0 {
                // I2C error — go back to waiting
                s.phase = Gt911Phase::Running;
                return 0;
            }

            let status = s.xfer_buf[4]; // After 2-byte header + 2-byte tx
            let buffer_ready = (status & 0x80) != 0;
            let num_points = status & 0x0F;

            if !buffer_ready || num_points == 0 {
                // No valid data, or release event
                if s.was_touching != 0 {
                    // Send release event
                    s.was_touching = 0;
                    let evt = TouchEvent {
                        x: 0,
                        y: 0,
                        event_type: TOUCH_RELEASE,
                        touch_count: 0,
                        pressure: 0,
                    };
                    if s.out_chan >= 0 {
                        unsafe {
                            (sys.channel_write)(
                                s.out_chan,
                                &evt as *const TouchEvent as *const u8,
                                core::mem::size_of::<TouchEvent>(),
                            );
                        }
                    }
                }
                // Clear status register
                s.phase = Gt911Phase::ClearStatusStart;
                return 2; // Burst
            }

            // Cap to 5 points
            s.touch_count = if num_points > 5 { 5 } else { num_points };
            s.phase = Gt911Phase::ReadPointsStart;
            2 // Burst
        }

        Gt911Phase::ReadPointsStart => {
            // Read touch point data: each point is 8 bytes
            let rx_len = (s.touch_count as usize) * POINT_SIZE;
            let arg_len = unsafe { setup_write_read(s, REG_POINT1, rx_len) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0304, s.xfer_buf.as_mut_ptr(), arg_len)
            };
            if rc < 0 && rc != E_INPROGRESS { return rc; }
            s.phase = Gt911Phase::ReadPointsPoll;
            0
        }

        Gt911Phase::ReadPointsPoll => {
            let rx_len = (s.touch_count as usize) * POINT_SIZE;
            let arg_len = unsafe { setup_write_read(s, REG_POINT1, rx_len) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0304, s.xfer_buf.as_mut_ptr(), arg_len)
            };
            if rc == 0 { return 0; }
            if rc < 0 {
                s.phase = Gt911Phase::ClearStatusStart;
                return 2;
            }

            // Parse first touch point (offset 4 after tx_len header + tx data)
            let base = 4; // 2 tx_len + 2 reg addr
            // GT911 point format: tracking_id(1), x_lo(1), x_hi(1), y_lo(1), y_hi(1), size_lo(1), size_hi(1), reserved(1)
            let x = (s.xfer_buf[base + 1] as u16) | ((s.xfer_buf[base + 2] as u16) << 8);
            let y = (s.xfer_buf[base + 3] as u16) | ((s.xfer_buf[base + 4] as u16) << 8);
            let size = (s.xfer_buf[base + 5] as u16) | ((s.xfer_buf[base + 6] as u16) << 8);

            let event_type = if s.was_touching != 0 { TOUCH_MOVE } else { TOUCH_PRESS };
            s.was_touching = 1;

            let evt = TouchEvent {
                x,
                y,
                event_type,
                touch_count: s.touch_count,
                pressure: size,
            };

            if s.out_chan >= 0 {
                unsafe {
                    (sys.channel_write)(
                        s.out_chan,
                        &evt as *const TouchEvent as *const u8,
                        core::mem::size_of::<TouchEvent>(),
                    );
                }
            }

            s.phase = Gt911Phase::ClearStatusStart;
            2 // Burst
        }

        Gt911Phase::ClearStatusStart => {
            // Write 0 to status register (0x814E) to acknowledge
            let arg_len = unsafe { setup_write(s, REG_STATUS, &[0x00]) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0302, s.xfer_buf.as_mut_ptr(), arg_len) // I2C_WRITE
            };
            if rc < 0 && rc != E_INPROGRESS { return rc; }
            s.phase = Gt911Phase::ClearStatusPoll;
            0
        }

        Gt911Phase::ClearStatusPoll => {
            let arg_len = unsafe { setup_write(s, REG_STATUS, &[0x00]) };
            let rc = unsafe {
                (sys.provider_call)(s.i2c_handle, 0x0302, s.xfer_buf.as_mut_ptr(), arg_len)
            };
            if rc == 0 { return 0; }
            // Done or error — return to waiting
            s.phase = Gt911Phase::Running;
            0
        }

        _ => -1,
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 256 },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// ============================================================================
// Panic handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
