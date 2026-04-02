//! ENC28J60 Ethernet Frame Provider PIC Module
//!
//! Example frame provider that reads/writes raw Ethernet frames via SPI.
//! The kernel runs TCP/UDP (smoltcp) on top of this interface.
//!
//! This is a skeleton/template - actual ENC28J60 register access needs
//! to be implemented based on the datasheet.
//!
//! **Params (TLV v2):**
//!   tag 1: spi_bus (u8, default 0)
//!   tag 2: cs_pin (u8, default 1)
//!   tag 3: int_pin (u8, default 0 = none)
//!
//! Channels:
//!   - out_chan: Sends received frames to kernel
//!   - in_chan: Receives frames to transmit from kernel
//!
//! Frame format (both directions):
//!   Raw Ethernet frame (14-byte header + payload, no FCS)

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, SpiOpenArgs, SpiTransferStartArgs};

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

mod constants;
use constants::*;

// ============================================================================
// Module State
// ============================================================================

/// Module state machine
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Init = 0,
    Reset = 1,
    Configure = 2,
    Running = 3,
    Error = 255,
}

#[repr(C)]
struct Enc28State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// SPI handle
    spi_handle: i32,
    /// CS GPIO handle
    cs_handle: i32,
    /// Current state
    phase: Phase,
    /// Configuration step (during init)
    config_step: u8,
    /// SPI bus number
    spi_bus: u8,
    /// CS pin number
    cs_pin: u8,
    /// Interrupt pin (0 = none)
    int_pin: u8,
    /// Current bank selected
    current_bank: u8,
    /// MAC address
    mac_addr: [u8; 6],
    /// Receive buffer
    rx_buf: [u8; MTU],
    /// Transmit buffer
    tx_buf: [u8; MTU],
}

impl Enc28State {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.spi_handle = -1;
        self.cs_handle = -1;
        self.phase = Phase::Init;
        self.config_step = 0;
        self.spi_bus = 0;
        self.cs_pin = 1;
        self.int_pin = 0;
        self.current_bank = 0;
        self.mac_addr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    }

    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::Enc28State;
    use super::p_u8;
    use super::SCHEMA_MAX;

    define_params! {
        Enc28State;

        1, spi_bus, u8, 0
            => |s, d, len| { s.spi_bus = p_u8(d, len, 0, 0); };

        2, cs_pin, u8, 1
            => |s, d, len| { s.cs_pin = p_u8(d, len, 0, 1); };

        3, int_pin, u8, 0
            => |s, d, len| { s.int_pin = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// dev_call helpers
// ============================================================================

/// Claim a GPIO pin via dev_call
unsafe fn dev_gpio_claim(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.dev_call)(-1, DEV_GPIO_CLAIM, arg.as_mut_ptr(), 1)
}

/// Set GPIO mode via dev_call (mode: 1=output, initial_level: 0/1)
unsafe fn dev_gpio_set_mode(sys: &SyscallTable, handle: i32, mode: u8, initial: u8) -> i32 {
    let mut arg = [mode, initial];
    (sys.dev_call)(handle, DEV_GPIO_SET_MODE, arg.as_mut_ptr(), 2)
}

/// Set GPIO level via dev_call
unsafe fn dev_gpio_set_level(sys: &SyscallTable, handle: i32, level: u8) -> i32 {
    let mut arg = [level];
    (sys.dev_call)(handle, DEV_GPIO_SET_LEVEL, arg.as_mut_ptr(), 1)
}

/// Open SPI via dev_call
unsafe fn dev_spi_open(sys: &SyscallTable, bus: u8, cs_handle: i32, freq_hz: u32, mode: u8) -> i32 {
    let mut args = SpiOpenArgs {
        cs_handle,
        freq_hz,
        bus,
        mode,
        _pad: [0; 2],
    };
    (sys.dev_call)(-1, DEV_SPI_OPEN, &mut args as *mut _ as *mut u8,
        core::mem::size_of::<SpiOpenArgs>())
}

/// Start SPI transfer via dev_call
unsafe fn dev_spi_transfer_start(
    sys: &SyscallTable,
    handle: i32,
    tx: *const u8,
    rx: *mut u8,
    len: usize,
    fill: u8,
) -> i32 {
    let mut args = SpiTransferStartArgs {
        tx,
        rx,
        len: len as u32,
        fill,
        _pad: [0; 3],
    };
    (sys.dev_call)(handle, DEV_SPI_TRANSFER_START, &mut args as *mut _ as *mut u8,
        core::mem::size_of::<SpiTransferStartArgs>())
}

/// Poll SPI transfer via dev_call
unsafe fn dev_spi_transfer_poll(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, DEV_SPI_TRANSFER_POLL, core::ptr::null_mut(), 0)
}

/// Poll SPI byte via dev_call
unsafe fn dev_spi_poll_byte(sys: &SyscallTable, handle: i32) -> i32 {
    (sys.dev_call)(handle, DEV_SPI_POLL_BYTE, core::ptr::null_mut(), 0)
}

// ============================================================================
// ENC28J60 SPI helpers
// ============================================================================

/// Select SPI chip (CS low)
unsafe fn cs_low(s: &Enc28State) {
    dev_gpio_set_level(s.sys(), s.cs_handle, 0);
}

/// Deselect SPI chip (CS high)
unsafe fn cs_high(s: &Enc28State) {
    dev_gpio_set_level(s.sys(), s.cs_handle, 1);
}

/// Write a single byte via SPI (blocking)
unsafe fn spi_write_byte(s: &Enc28State, byte: u8) -> i32 {
    let tx = [byte];
    let result = dev_spi_transfer_start(s.sys(), s.spi_handle, tx.as_ptr(), core::ptr::null_mut(), 1, 0xFF);
    if result < 0 {
        return result;
    }
    loop {
        let poll = dev_spi_transfer_poll(s.sys(), s.spi_handle);
        if poll > 0 { return 0; }
        if poll < 0 { return poll; }
    }
}

/// Read a single byte via SPI (blocking)
unsafe fn spi_read_byte(s: &Enc28State) -> i32 {
    let sys = s.sys();
    let result = dev_spi_poll_byte(sys, s.spi_handle);
    if result >= 0x100 {
        return (result - 0x100) as i32;
    }
    if result == 0 {
        let r = dev_spi_transfer_start(sys, s.spi_handle, core::ptr::null(), core::ptr::null_mut(), 1, 0xFF);
        if r < 0 { return r; }
        loop {
            let poll = dev_spi_poll_byte(sys, s.spi_handle);
            if poll >= 0x100 { return (poll - 0x100) as i32; }
            if poll < 0 { return poll; }
        }
    }
    result
}

/// Write control register
unsafe fn write_reg(s: &mut Enc28State, addr: u8, value: u8) {
    cs_low(s);
    spi_write_byte(s, ENC_WRITE_CTRL_REG | (addr & 0x1F));
    spi_write_byte(s, value);
    cs_high(s);
}

/// Read control register
unsafe fn read_reg(s: &Enc28State, addr: u8) -> u8 {
    cs_low(s);
    spi_write_byte(s, ENC_READ_CTRL_REG | (addr & 0x1F));
    let val = spi_read_byte(s);
    cs_high(s);
    val as u8
}

/// Soft reset the chip
unsafe fn soft_reset(s: &Enc28State) {
    cs_low(s);
    spi_write_byte(s, ENC_SOFT_RESET);
    cs_high(s);
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Enc28State>() as u32
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
        if state_size < core::mem::size_of::<Enc28State>() {
            return -2;
        }

        let s = &mut *(state as *mut Enc28State);
        s.init(syscalls as *const SyscallTable);
        s.in_chan = in_chan;
        s.out_chan = out_chan;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 2 {
            // Legacy: spi_bus at [0], cs_pin at [1]
            s.spi_bus = *params;
            s.cs_pin = *params.add(1);
            if params_len >= 3 {
                s.int_pin = *params.add(2);
            }
        } else {
            params_def::set_defaults(s);
        }

        let sys = &*s.syscalls;

        // Claim CS pin as output via dev_call
        let cs_pin = s.cs_pin;
        let cs_handle = dev_gpio_claim(sys, cs_pin);
        if cs_handle < 0 {
            return -4;
        }
        dev_gpio_set_mode(sys, cs_handle, 1, 1); // Output, initially high
        s.cs_handle = cs_handle;

        // Open SPI via dev_call (10MHz, mode 0)
        let bus = s.spi_bus;
        let spi_handle = dev_spi_open(sys, bus, cs_handle, 10_000_000, 0);
        if spi_handle < 0 {
            return -5;
        }
        s.spi_handle = spi_handle;

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
        let s = &mut *(state as *mut Enc28State);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;

        match s.phase {
            Phase::Init => {
                cs_high(s);
                s.phase = Phase::Reset;
            }

            Phase::Reset => {
                soft_reset(s);
                s.phase = Phase::Configure;
                s.config_step = 0;
            }

            Phase::Configure => {
                s.config_step += 1;
                if s.config_step >= 10 {
                    s.phase = Phase::Running;
                    dev_log(sys, 3, b"[enc28j60] ready".as_ptr(), b"[enc28j60] ready".len());
                }
            }

            Phase::Running => {
                // Check for received packets
                let has_packet = false; // TODO: check ENC28J60

                if has_packet {
                    let len = 0usize; // TODO: read actual packet

                    if len > 0 && s.out_chan >= 0 {
                        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
                        if poll > 0 && (poll as u8 & POLL_OUT) != 0 {
                            (sys.channel_write)(s.out_chan, s.rx_buf.as_ptr(), len);
                        }
                    }
                }

                // Check for frames to transmit
                if s.in_chan >= 0 {
                    let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
                    if poll > 0 && (poll as u8 & POLL_IN) != 0 {
                        let len = (sys.channel_read)(s.in_chan, s.tx_buf.as_mut_ptr(), MTU);
                        if len > 0 {
                            let _frame_len = len as usize;
                            // TODO: Write frame to ENC28J60 TX buffer
                        }
                    }
                }
            }

            Phase::Error => {
                return -1;
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
