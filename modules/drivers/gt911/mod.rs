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
//! 4. Watch the INT pin's falling edge
//!
//! # Runtime
//!
//! On INT falling edge: read status register (0x814E), read touch points
//! (0x8150+), clear status, write TouchEvent to output channel.

#![no_std]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

// ============================================================================
// Constants
// ============================================================================

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
    event_type: u8, // 1=press, 2=release, 3=move
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
    /// The INT pin's edge watch.
    watch_fd: i32,

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

    // Bytes an I2C read returns: 4 bytes product ID, 1 byte status, or
    // 5*8=40 bytes point data.
    xfer_buf: [u8; 48],
    touch_count: u8,
}

impl Gt911State {}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::p_u8;
    use super::Gt911State;

    fluxor_rt::define_params! {
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

/// Start a write of register address `reg` followed by a read of `rx_len`
/// bytes; [`i2c_poll`] collects them into `xfer_buf`.
unsafe fn i2c_read_reg_start(s: &mut Gt911State, reg: u16, rx_len: usize) -> i32 {
    let sys = &*s.syscalls;
    let mut tx = reg.to_be_bytes();
    let mut arg = abi::contracts::hal::i2c::read::encode(rx_len as u16);
    (sys.provider_call)(
        s.i2c_handle,
        abi::registry::i2c::WRITE_READ,
        arg.as_mut_ptr(),
        arg.len(),
        tx.as_mut_ptr(),
        tx.len(),
    )
}

/// Start a write of register address `reg` followed by `bytes`.
unsafe fn i2c_write_reg_start(s: &mut Gt911State, reg: u16, bytes: &[u8]) -> i32 {
    let sys = &*s.syscalls;
    let mut tx = [0u8; 8];
    let r = reg.to_be_bytes();
    tx[0] = r[0];
    tx[1] = r[1];
    let mut i = 0;
    while i < bytes.len() && 2 + i < tx.len() {
        tx[2 + i] = bytes[i];
        i += 1;
    }
    (sys.provider_call)(
        s.i2c_handle,
        abi::registry::i2c::WRITE,
        core::ptr::null_mut(),
        0,
        tx.as_mut_ptr(),
        2 + i,
    )
}

/// The started transfer: `E_AGAIN` while it runs, then its byte count (the
/// bytes read land at `xfer_buf[0..]`) or its error.
unsafe fn i2c_poll(s: &mut Gt911State) -> i32 {
    let sys = &*s.syscalls;
    (sys.provider_call)(
        s.i2c_handle,
        abi::registry::i2c::POLL,
        core::ptr::null_mut(),
        0,
        s.xfer_buf.as_mut_ptr(),
        s.xfer_buf.len(),
    )
}

// ============================================================================
// GPIO helpers
// ============================================================================

// Provider contract ids (mirror kernel::module::provider::contract::*).
const HAL_GPIO_CONTRACT: u32 = abi::registry::gpio::ID as u32;
const HAL_I2C_CONTRACT: u32 = abi::registry::i2c::ID as u32;
const TIMER_CONTRACT: u32 = abi::registry::timer::ID as u32;

unsafe fn claim_gpio_output(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_open)(
        HAL_GPIO_CONTRACT,
        abi::registry::gpio::SET_OUTPUT,
        arg.as_mut_ptr(),
        1,
    ) // GPIO_SET_OUTPUT
}

unsafe fn gpio_set(sys: &SyscallTable, handle: i32, level: u8) {
    let mut lvl = [level];
    (sys.provider_call)(
        handle,
        abi::registry::gpio::SET_LEVEL,
        lvl.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
    // GPIO_SET_LEVEL
}

unsafe fn gpio_set_mode_input(sys: &SyscallTable, handle: i32) {
    let mut mode = [0u8]; // 0 = input
    (sys.provider_call)(
        handle,
        abi::registry::gpio::SET_MODE,
        mode.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
    // GPIO_SET_MODE
}

unsafe fn timer_set(sys: &SyscallTable, timer_fd: i32, delay_ms: u32) -> i32 {
    let mut ms_buf = delay_ms.to_le_bytes();
    (sys.provider_call)(
        timer_fd,
        abi::registry::timer::SET,
        ms_buf.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    )
    // TIMER_SET
}

unsafe fn timer_expired(sys: &SyscallTable, timer_fd: i32) -> bool {
    dev_fd_poll(sys, timer_fd, POLL_IN) & (POLL_IN as i32) != 0
}

// ============================================================================
// Module exports
// ============================================================================

fluxor_rt::module_facts! { state: Gt911State }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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
    s.watch_fd = -1;
    s.int_handle = -1;
    s.rst_handle = -1;
    s.phase = Gt911Phase::ResetLow;
    s.was_touching = 0;
    s.touch_count = 0;

    unsafe {
        let sys = &*s.syscalls;

        // Create timer — tracked against TIMER contract.
        s.timer_fd = (sys.provider_open)(
            TIMER_CONTRACT,
            abi::registry::timer::CREATE,
            core::ptr::null_mut(),
            0,
        );
        if s.timer_fd < 0 {
            return -12;
        }

        // GT911 address selection protocol:
        // 1. INT pin as output, drive low (selects 0x5D)
        // 2. RST pin as output, drive low (assert reset)
        // 3. Wait 10ms

        s.int_handle = claim_gpio_output(sys, s.int_pin);
        if s.int_handle < 0 {
            return s.int_handle;
        }

        s.rst_handle = claim_gpio_output(sys, s.rst_pin);
        if s.rst_handle < 0 {
            return s.rst_handle;
        }

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
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    let s = unsafe { &mut *(state as *mut Gt911State) };
    let sys = unsafe { &*s.syscalls };

    match s.phase {
        Gt911Phase::ResetLow => {
            // Wait 10ms with RST+INT low
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return StepReturn::Continue;
            }
            // Release RST (high), keep INT low for addr selection
            unsafe {
                gpio_set(sys, s.rst_handle, 1);
                timer_set(sys, s.timer_fd, 55);
            }
            s.phase = Gt911Phase::AddrSelect;
            StepReturn::Continue
        }

        Gt911Phase::AddrSelect => {
            // Wait 55ms for RST rise
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return StepReturn::Continue;
            }
            // Change INT to input (release bus)
            unsafe {
                gpio_set_mode_input(sys, s.int_handle);
                timer_set(sys, s.timer_fd, 50);
            }
            s.phase = Gt911Phase::WaitBoot;
            StepReturn::Continue
        }

        Gt911Phase::WaitBoot => {
            // Wait 50ms for GT911 boot
            if !unsafe { timer_expired(sys, s.timer_fd) } {
                return StepReturn::Continue;
            }
            s.phase = Gt911Phase::OpenI2c;
            StepReturn::Burst
        }

        Gt911Phase::OpenI2c => {
            // Open I2C handle
            let mut arg = abi::contracts::hal::i2c::open::encode(s.i2c_bus, s.addr as u16);

            let handle = unsafe {
                (sys.provider_open)(
                    HAL_I2C_CONTRACT,
                    abi::registry::i2c::OPEN,
                    arg.as_mut_ptr(),
                    arg.len(),
                )
            };
            if handle < 0 {
                s.phase = Gt911Phase::Error;
                return StepReturn::error(handle);
            }
            s.i2c_handle = handle;
            s.phase = Gt911Phase::ReadIdStart;
            StepReturn::Burst
        }

        Gt911Phase::ReadIdStart => {
            // Read product ID: reg 0x8140, 4 bytes
            let rc = unsafe { i2c_read_reg_start(s, REG_PRODUCT_ID, 4) };
            if rc < 0 {
                s.phase = Gt911Phase::Error;
                return StepReturn::error(rc);
            }
            s.phase = Gt911Phase::ReadIdPoll;
            StepReturn::Continue
        }

        Gt911Phase::ReadIdPoll => {
            // Poll for I2C completion
            let rc = unsafe { i2c_poll(s) };
            if rc == E_AGAIN {
                return StepReturn::Continue; // Still pending
            }
            if rc <= 0 {
                s.phase = Gt911Phase::Error;
                return StepReturn::error(if rc == 0 { E_IO } else { rc });
            }
            // Product ID is at xfer_buf[0..4].
            // Expected: "911\0" or similar. Just verify non-zero.
            // GT911 returns ASCII: '9','1','1','\0'
            if s.xfer_buf[0] == 0 {
                s.phase = Gt911Phase::Error;
                return StepReturn::error(-19); // ENODEV
            }

            // Watch the INT pin's falling edge: the watch handle polls
            // ready once per edge.
            unsafe {
                let mut edge = [2u8]; // FALLING
                s.watch_fd = (sys.provider_call)(
                    s.int_handle,
                    abi::registry::gpio::WATCH_EDGE,
                    edge.as_mut_ptr(),
                    1,
                    core::ptr::null_mut(),
                    0,
                );
                if s.watch_fd < 0 {
                    s.phase = Gt911Phase::Error;
                    return StepReturn::error(s.watch_fd);
                }
            }

            s.phase = Gt911Phase::Running;
            StepReturn::Continue
        }

        Gt911Phase::Running => {
            // An INT edge since the last poll (touch data available); the
            // poll takes it.
            let poll = unsafe { dev_fd_poll(sys, s.watch_fd, POLL_IN) };
            if poll < 0 || poll & (POLL_IN as i32) == 0 {
                return StepReturn::Continue; // No touch event pending
            }
            // Read status register
            s.phase = Gt911Phase::ReadStatusStart;
            StepReturn::Burst
        }

        Gt911Phase::ReadStatusStart => {
            // Read status: reg 0x814E, 1 byte
            let rc = unsafe { i2c_read_reg_start(s, REG_STATUS, 1) };
            if rc < 0 {
                return StepReturn::error(rc);
            }
            s.phase = Gt911Phase::ReadStatusPoll;
            StepReturn::Continue
        }

        Gt911Phase::ReadStatusPoll => {
            let rc = unsafe { i2c_poll(s) };
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            if rc <= 0 {
                // I2C error — go back to waiting
                s.phase = Gt911Phase::Running;
                return StepReturn::Continue;
            }

            let status = s.xfer_buf[0];
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
                return StepReturn::Burst;
            }

            // Cap to 5 points
            s.touch_count = if num_points > 5 { 5 } else { num_points };
            s.phase = Gt911Phase::ReadPointsStart;
            StepReturn::Burst
        }

        Gt911Phase::ReadPointsStart => {
            // Read touch point data: each point is 8 bytes
            let rx_len = (s.touch_count as usize) * POINT_SIZE;
            let rc = unsafe { i2c_read_reg_start(s, REG_POINT1, rx_len) };
            if rc < 0 {
                return StepReturn::error(rc);
            }
            s.phase = Gt911Phase::ReadPointsPoll;
            StepReturn::Continue
        }

        Gt911Phase::ReadPointsPoll => {
            let rx_len = (s.touch_count as usize) * POINT_SIZE;
            let rc = unsafe { i2c_poll(s) };
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            // The read answers the bytes it moved: anything short of the
            // points asked for is a failed read.
            if rc <= 0 || (rc as usize) < rx_len.min(POINT_SIZE) {
                s.phase = Gt911Phase::ClearStatusStart;
                return StepReturn::Burst;
            }

            // Parse the first touch point.
            let base = 0;
            // GT911 point format: tracking_id(1), x_lo(1), x_hi(1), y_lo(1), y_hi(1), size_lo(1), size_hi(1), reserved(1)
            let x = (s.xfer_buf[base + 1] as u16) | ((s.xfer_buf[base + 2] as u16) << 8);
            let y = (s.xfer_buf[base + 3] as u16) | ((s.xfer_buf[base + 4] as u16) << 8);
            let size = (s.xfer_buf[base + 5] as u16) | ((s.xfer_buf[base + 6] as u16) << 8);

            let event_type = if s.was_touching != 0 {
                TOUCH_MOVE
            } else {
                TOUCH_PRESS
            };
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
            StepReturn::Burst
        }

        Gt911Phase::ClearStatusStart => {
            // Write 0 to status register (0x814E) to acknowledge
            let rc = unsafe { i2c_write_reg_start(s, REG_STATUS, &[0x00]) };
            if rc < 0 {
                return StepReturn::error(rc);
            }
            s.phase = Gt911Phase::ClearStatusPoll;
            StepReturn::Continue
        }

        Gt911Phase::ClearStatusPoll => {
            let rc = unsafe { i2c_poll(s) };
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            // Done or error — return to waiting
            s.phase = Gt911Phase::Running;
            StepReturn::Continue
        }

        _ => StepReturn::error(-1),
    }
}

// ============================================================================
// Panic handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `crates/fluxor-rt/src/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
fluxor_rt::wasm_entry!();
