//! UART Driver — PIC module provider
//!
//! Manages UART peripheral access using kernel register bridge.
//! Registers as the HAL_UART provider (contract id 0x0D).
//! FIFO-based polling for TX/RX through a transmit and a receive ring per
//! bus; every op copies between a ring and the caller's `data`.

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

/// Bytes each ring of a bus holds.
const RING: usize = 256;
/// Bytes moved each way per bus per step.
const BURST: usize = 32;

#[repr(C)]
struct UartHandle {
    in_use: u8,
    bus_id: u8,
    owner: u8,
    _pad: u8,
}

/// A bus's transmit and receive rings, shared by every handle open on it.
#[repr(C)]
struct BusRings {
    tx: [u8; RING],
    rx: [u8; RING],
    tx_head: u16,
    tx_len: u16,
    rx_head: u16,
    rx_len: u16,
}

#[repr(C)]
struct UartState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    handles: [UartHandle; MAX_HANDLES],
    buses: [BusRings; MAX_BUSES],
    step_count: u32,
    next_handle: u8,
    ready_reported: u8,
    _pad: [u8; 2],
}

use abi::platform::rp::uart_raw::{REG_READ as UART_REG_READ, REG_WRITE as UART_REG_WRITE};

unsafe fn uart_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0];
    *bp.add(2) = v[1];
    *bp.add(3) = v[2];
    *bp.add(4) = v[3];
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::UART, bus),
        UART_REG_WRITE,
        bp,
        5,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn uart_reg_read(sys: &SyscallTable, bus: u8, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::UART, bus),
        UART_REG_READ,
        bp,
        5,
        core::ptr::null_mut(),
        0,
    );
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
    while rem >= divisor {
        rem -= divisor;
        ibrd += 1;
    }
    // Fractional: (rem * 64) / divisor
    let mut fbrd = 0u32;
    let mut frac_rem = rem << 6; // rem * 64
    while frac_rem >= divisor {
        frac_rem -= divisor;
        fbrd += 1;
    }
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

/// Whether any open handle names `bus`.
fn bus_open(s: &UartState, bus: u8) -> bool {
    s.handles.iter().any(|h| h.in_use != 0 && h.bus_id == bus)
}

/// Move up to [`BURST`] bytes each way between `bus`'s rings and its FIFOs.
unsafe fn pump_bus(s: &mut UartState, bus: u8) {
    let sys = &*s.syscalls;
    let r = &mut s.buses[bus as usize];
    let mut n = 0usize;
    while n < BURST && r.tx_len > 0 {
        if uart_reg_read(sys, bus, UARTFR) & FR_TXFF != 0 {
            break;
        }
        uart_reg_write(sys, bus, UARTDR, r.tx[r.tx_head as usize] as u32);
        r.tx_head = ((r.tx_head as usize + 1) % RING) as u16;
        r.tx_len -= 1;
        n += 1;
    }
    n = 0;
    while n < BURST && (r.rx_len as usize) < RING {
        if uart_reg_read(sys, bus, UARTFR) & FR_RXFE != 0 {
            break;
        }
        let byte = uart_reg_read(sys, bus, UARTDR) as u8;
        let at = (r.rx_head as usize + r.rx_len as usize) % RING;
        r.rx[at] = byte;
        r.rx_len += 1;
        n += 1;
    }
}

/// Queue `src` on the transmit ring; the bytes it took.
fn ring_put(r: &mut BusRings, src: &[u8]) -> usize {
    let room = RING - r.tx_len as usize;
    let n = if src.len() < room { src.len() } else { room };
    let mut i = 0usize;
    while i < n {
        let at = (r.tx_head as usize + r.tx_len as usize + i) % RING;
        r.tx[at] = src[i];
        i += 1;
    }
    r.tx_len += n as u16;
    n
}

/// Take received bytes into `dst`; the bytes taken.
fn ring_take(r: &mut BusRings, dst: &mut [u8]) -> usize {
    let n = if dst.len() < r.rx_len as usize {
        dst.len()
    } else {
        r.rx_len as usize
    };
    let mut i = 0usize;
    while i < n {
        dst[i] = r.rx[(r.rx_head as usize + i) % RING];
        i += 1;
    }
    r.rx_head = ((r.rx_head as usize + n) % RING) as u16;
    r.rx_len -= n as u16;
    n
}

const UART_OPEN: u32 = abi::registry::uart::OPEN;
const UART_CLOSE: u32 = abi::registry::uart::CLOSE;
const UART_WRITE: u32 = abi::registry::uart::WRITE;
const UART_READ: u32 = abi::registry::uart::READ;
const UART_POLL: u32 = abi::registry::uart::POLL;
const UART_CONFIGURE: u32 = abi::registry::uart::CONFIGURE;

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// both valid for the call.
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn uart_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    let s = &mut *(state as *mut UartState);
    let arg: &[u8] = if arg.is_null() {
        &[]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    if opcode == UART_OPEN {
        let Some(&bus) = arg.first() else {
            return E_INVAL;
        };
        if bus as usize >= MAX_BUSES {
            return E_INVAL;
        }
        let mut i = 0usize;
        while i < MAX_HANDLES {
            let idx = (s.next_handle as usize + i) % MAX_HANDLES;
            let hp = &mut s.handles[idx];
            if hp.in_use == 0 {
                hp.in_use = 1;
                hp.bus_id = bus;
                s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                return idx as i32;
            }
            i += 1;
        }
        return E_BUSY;
    }

    if handle < 0 {
        return E_INVAL;
    }
    let idx = handle as usize;
    if idx >= MAX_HANDLES || s.handles[idx].in_use == 0 {
        return E_INVAL;
    }
    let bus = s.handles[idx].bus_id;

    match opcode {
        UART_CLOSE => {
            s.handles[idx].in_use = 0;
            0
        }
        UART_WRITE => {
            if data.is_null() || data_len == 0 {
                return 0;
            }
            let src = core::slice::from_raw_parts(data, data_len);
            ring_put(&mut s.buses[bus as usize], src) as i32
        }
        UART_READ => {
            if data.is_null() || data_len == 0 {
                return 0;
            }
            let dst = core::slice::from_raw_parts_mut(data, data_len);
            ring_take(&mut s.buses[bus as usize], dst) as i32
        }
        UART_POLL => s.buses[bus as usize].tx_len as i32,
        UART_CONFIGURE => {
            // arg=[baud:u32 LE] (4 bytes)
            let Some(b) = arg.get(..4) else {
                return E_INVAL;
            };
            let baud = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let sys = &*s.syscalls;
            configure_uart(sys, bus, baud);
            0
        }
        _ => E_NOSYS,
    }
}

fluxor_rt::module_facts! { state: UartState }

// Same figure as data, so `pack` records it in the manifest and a graph's
// state-arena demand is summable host-side.

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<UartState>() {
            return -2;
        }
        let s = &mut *(state as *mut UartState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[uart] ready".as_ptr(), 11);
        0
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut UartState);
    let mut bus = 0u8;
    while (bus as usize) < MAX_BUSES {
        if bus_open(s, bus) {
            pump_bus(s, bus);
        }
        bus += 1;
    }
    // Ready on the first step: nothing is brought up before a consumer's
    // first open, and the scheduler holds this provider's consumers until
    // it reports Ready.
    if s.ready_reported == 0 {
        s.ready_reported = 1;
        return StepReturn::Ready;
    }
    StepReturn::Continue
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `crates/fluxor-rt/src/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
fluxor_rt::wasm_entry!();
