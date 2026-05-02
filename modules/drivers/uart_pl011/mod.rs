//! UART Driver — PIC module provider
//!
//! Manages UART peripheral access using kernel register bridge.
//! Registers as the HAL_UART provider (contract id 0x0D).
//! FIFO-based polling for TX/RX.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const MAX_HANDLES: usize = 4;
const MAX_BUSES: usize = 2;

// PL011 register offsets
const UARTDR: u8 = 0x00;
const UARTFR: u8 = 0x18;
const UARTIBRD: u8 = 0x24;
const UARTFBRD: u8 = 0x28;
const UARTLCR_H: u8 = 0x2C;
const UARTCR: u8 = 0x30;
const UARTIMSC: u8 = 0x38;
const UARTDMACR: u8 = 0x48;

// UARTFR bits
const FR_TXFF: u32 = 1 << 5; // TX FIFO full
const FR_RXFE: u32 = 1 << 4; // RX FIFO empty
const FR_BUSY: u32 = 1 << 3;

#[repr(C)]
struct UartHandle {
    in_use: u8,
    bus_id: u8,
    owner: u8,
    _pad: u8,
}

#[repr(C)]
struct UartTransfer {
    buf_ptr: u32,
    buf_len: u16,
    pos: u16,
    pending: u8,
    active: u8,
    is_read: u8,
    _pad: u8,
    result: i32,
}

#[repr(C)]
struct UartState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    handles: [UartHandle; MAX_HANDLES],
    transfers: [UartTransfer; MAX_HANDLES],
    step_count: u32,
    next_handle: u8,
    _pad: [u8; 3],
}

use abi::platform::rp::uart_raw::{REG_WRITE as UART_REG_WRITE, REG_READ as UART_REG_READ};

unsafe fn uart_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0]; *bp.add(2) = v[1]; *bp.add(3) = v[2]; *bp.add(4) = v[3];
    (sys.provider_call)(bus as i32, UART_REG_WRITE, bp, 5);
}

unsafe fn uart_reg_read(sys: &SyscallTable, bus: u8, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.provider_call)(bus as i32, UART_REG_READ, bp, 5);
    u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)])
}

unsafe fn configure_uart(sys: &SyscallTable, bus: u8, baud: u32) {
    // Disable UART
    uart_reg_write(sys, bus, UARTCR, 0);

    // Baud rate: IBRD = Fsys / (16 * baud), FBRD = fractional * 64
    // Use shift-based division to avoid panic_const_div_by_zero in PIC
    let fsys = 150_000_000u32;
    let divisor = baud << 4; // baud * 16
    // Integer division via repeated subtraction (baud rates are small)
    let mut ibrd = 0u32;
    let mut rem = fsys;
    while rem >= divisor { rem -= divisor; ibrd += 1; }
    // Fractional: (rem * 64) / divisor
    let mut fbrd = 0u32;
    let mut frac_rem = rem << 6; // rem * 64
    while frac_rem >= divisor { frac_rem -= divisor; fbrd += 1; }
    uart_reg_write(sys, bus, UARTIBRD, ibrd);
    uart_reg_write(sys, bus, UARTFBRD, fbrd);

    // 8N1 + FIFO enable
    uart_reg_write(sys, bus, UARTLCR_H, (0x3 << 5) | (1 << 4)); // WLEN=8, FEN=1

    // Disable interrupts and DMA
    uart_reg_write(sys, bus, UARTIMSC, 0);
    uart_reg_write(sys, bus, UARTDMACR, 0);

    // Enable UART + TX + RX
    uart_reg_write(sys, bus, UARTCR, 0x301); // UARTEN + TXE + RXE
}

unsafe fn poll_uart_transfer(s: &mut UartState, idx: usize) {
    let sys = &*s.syscalls;
    let tp = s.transfers.as_mut_ptr().add(idx);
    if (*tp).active == 0 { return; }

    let bus = (*s.handles.as_ptr().add(idx)).bus_id;
    let fr = uart_reg_read(sys, bus, UARTFR);
    let pos = (*tp).pos as usize;
    let len = (*tp).buf_len as usize;

    if (*tp).is_read != 0 {
        // RX: read available bytes
        if (fr & FR_RXFE) == 0 && pos < len {
            let byte = uart_reg_read(sys, bus, UARTDR) as u8;
            if (*tp).buf_ptr != 0 {
                *(((*tp).buf_ptr as usize + pos) as *mut u8) = byte;
            }
            (*tp).pos = (pos + 1) as u16;
        }
        if (*tp).pos as usize >= len {
            (*tp).result = len as i32;
            (*tp).active = 0;
        }
    } else {
        // TX: write available space
        if (fr & FR_TXFF) == 0 && pos < len {
            let byte = if (*tp).buf_ptr != 0 {
                *(((*tp).buf_ptr as usize + pos) as *const u8)
            } else { 0 };
            uart_reg_write(sys, bus, UARTDR, byte as u32);
            (*tp).pos = (pos + 1) as u16;
        }
        if (*tp).pos as usize >= len && (fr & FR_BUSY) == 0 {
            (*tp).result = len as i32;
            (*tp).active = 0;
        }
    }
}

const UART_OPEN: u32 = 0x0D00;
const UART_CLOSE: u32 = 0x0D01;
const UART_WRITE: u32 = 0x0D02;
const UART_READ: u32 = 0x0D03;
const UART_POLL: u32 = 0x0D04;
const UART_CONFIGURE: u32 = 0x0D05;

#[unsafe(no_mangle)]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn uart_dispatch(
    state: *mut u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut UartState);

    match opcode {
        UART_OPEN => {
            if arg.is_null() || arg_len < 1 { return -22; }
            let bus = *arg;
            if bus as usize >= MAX_BUSES { return -22; }
            let mut i = 0usize;
            while i < MAX_HANDLES {
                let idx = (s.next_handle as usize + i) % MAX_HANDLES;
                let hp = s.handles.as_mut_ptr().add(idx);
                if (*hp).in_use == 0 {
                    (*hp).in_use = 1;
                    (*hp).bus_id = bus;
                    s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                    return idx as i32;
                }
                i += 1;
            }
            -16
        }
        UART_CLOSE => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            (*s.handles.as_mut_ptr().add(idx)).in_use = 0;
            0
        }
        UART_WRITE | UART_READ => {
            // arg=[buf_ptr:u32, len:u16] (6 bytes)
            if arg.is_null() || arg_len < 6 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).active != 0 { return -16; }
            (*tp).buf_ptr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*tp).buf_len = u16::from_le_bytes([*arg.add(4), *arg.add(5)]);
            (*tp).pos = 0;
            (*tp).is_read = if opcode == UART_READ { 1 } else { 0 };
            (*tp).result = 0;
            (*tp).pending = 0;
            (*tp).active = 1;
            0
        }
        UART_POLL => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_ptr().add(idx);
            if (*tp).active != 0 { return 0; }
            (*tp).result
        }
        UART_CONFIGURE => {
            // arg=[baud:u32 LE] (4 bytes)
            if arg.is_null() || arg_len < 4 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let bus = (*s.handles.as_ptr().add(idx)).bus_id;
            let baud = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let sys = &*s.syscalls;
            configure_uart(sys, bus, baud);
            0
        }
        _ => -38,
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { core::mem::size_of::<UartState>() }

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<UartState>() { return -2; }
        let s = &mut *(state as *mut UartState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan; s.out_chan = out_chan; s.ctrl_chan = ctrl_chan;

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[uart] ready".as_ptr(), 11);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    0x000D // HAL_UART
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut UartState);
    let mut i = 0usize;
    while i < MAX_HANDLES {
        let tp = s.transfers.as_ptr().add(i);
        if (*tp).active != 0 { poll_uart_transfer(s, i); }
        i += 1;
    }
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
