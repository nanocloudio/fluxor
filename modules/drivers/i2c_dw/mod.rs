//! I2C Bus Driver — PIC module provider
//!
//! Manages I2C bus access using kernel register bridge (I2C_REG_WRITE/READ).
//! Registers as the HAL_I2C provider (contract id 0x03).
//!
//! Uses FIFO-based polling (not DMA) — I2C transactions are typically <32 bytes
//! and run at 100-400 KHz, so polling is efficient and simpler.

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

const MAX_HANDLES: usize = 8;
const MAX_BUSES: usize = 2;
const XFER_MAX: usize = abi::contracts::hal::i2c::XFER_MAX;

// DW I2C register offsets
const IC_CON: u8 = 0x00;
const IC_TAR: u8 = 0x04;
const IC_DATA_CMD: u8 = 0x10;
const IC_SS_SCL_HCNT: u8 = 0x14;
const IC_SS_SCL_LCNT: u8 = 0x18;
const IC_FS_SCL_HCNT: u8 = 0x1C;
const IC_FS_SCL_LCNT: u8 = 0x20;
const IC_INTR_MASK: u8 = 0x30;
const IC_CLR_TX_ABRT: u8 = 0x54;
const IC_STATUS: u8 = 0x70;
const IC_TXFLR: u8 = 0x74;
const IC_TX_ABRT_SRC: u8 = 0x80;

// IC_STATUS bits
const STAT_RFNE: u32 = 1 << 3; // RX FIFO not empty
const STAT_TFNF: u32 = 1 << 1; // TX FIFO not full
const STAT_ACTIVITY: u32 = 1 << 0;

// IC_DATA_CMD bits
const CMD_READ: u32 = 1 << 8;
const CMD_STOP: u32 = 1 << 9;
const CMD_RESTART: u32 = 1 << 10;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct I2cHandle {
    in_use: u8,
    bus_id: u8,
    owner: u8,
    _pad: u8,
    addr: u16, // 7-bit target address
    _pad2: u16,
}

/// One handle's transfer. `buf` holds the bytes to write, copied in when the
/// transfer starts, and then the bytes read, from 0: every write byte is in
/// the TX FIFO before the first read command, so a received byte never
/// lands on one still to be sent.
#[repr(C)]
struct I2cTransfer {
    buf: [u8; XFER_MAX],
    tx_len: u16,
    rx_len: u16,
    tx_pos: u16, // bytes written to TX FIFO so far
    rx_pos: u16, // bytes read from RX FIFO so far
    pending: u8, // 1 = waiting to start
    active: u8,  // 1 = FIFO transfer in progress
    op_type: u8, // 0=write, 1=read, 2=write_read
    done: u8,    // 1 = finished, `result` not yet polled
    result: i32,
}

#[repr(C)]
struct BusInfo {
    initialized: u8,
    bus_owner: i8,
    _pad: [u8; 2],
    current_freq: u32,
}

#[repr(C)]
struct I2cState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    handles: [I2cHandle; MAX_HANDLES],
    transfers: [I2cTransfer; MAX_HANDLES],
    buses: [BusInfo; MAX_BUSES],
    step_count: u32,
    next_handle: u8,
    ready_reported: u8,
    _pad: [u8; 2],
}

// ============================================================================
// Register bridge helpers
// ============================================================================

unsafe fn i2c_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0];
    *bp.add(2) = v[1];
    *bp.add(3) = v[2];
    *bp.add(4) = v[3];
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::I2C, bus),
        abi::registry::rp_raw::I2C_REG_WRITE,
        bp,
        5,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn i2c_reg_read(sys: &SyscallTable, bus: u8, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::I2C, bus),
        abi::registry::rp_raw::I2C_REG_READ,
        bp,
        5,
        core::ptr::null_mut(),
        0,
    );
    u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)])
}

unsafe fn i2c_set_enable(sys: &SyscallTable, bus: u8, enable: bool) {
    let mut buf = [if enable { 1u8 } else { 0u8 }];
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::I2C, bus),
        abi::registry::rp_raw::I2C_SET_ENABLE,
        buf.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
}

// ============================================================================
// I2C configuration
// ============================================================================

unsafe fn configure_bus(sys: &SyscallTable, bus: u8, freq_hz: u32) {
    i2c_set_enable(sys, bus, false);

    // IC_CON: master mode, 7-bit addr, restart enable, speed
    let speed_bits = if freq_hz > 100_000 { 0x04 } else { 0x02 }; // FS or SS
    let con = (1 << 6) | (1 << 5) | speed_bits | (1 << 0); // SLAVE_DISABLE | RESTART_EN | SPEED | MASTER
    i2c_reg_write(sys, bus, IC_CON, con);

    // Clock counts: assume Fsys=150MHz
    let fsys = 150_000_000u32;
    let period = fsys / freq_hz;
    let hcnt = period * 4 / 10; // ~40% high
    let lcnt = period - hcnt; // ~60% low

    if freq_hz <= 100_000 {
        i2c_reg_write(sys, bus, IC_SS_SCL_HCNT, hcnt);
        i2c_reg_write(sys, bus, IC_SS_SCL_LCNT, lcnt);
    } else {
        i2c_reg_write(sys, bus, IC_FS_SCL_HCNT, hcnt);
        i2c_reg_write(sys, bus, IC_FS_SCL_LCNT, lcnt);
    }

    // Disable interrupts
    i2c_reg_write(sys, bus, IC_INTR_MASK, 0);

    i2c_set_enable(sys, bus, true);
}

// ============================================================================
// Transfer execution (FIFO-based polling)
// ============================================================================

unsafe fn start_i2c_transfer(s: &mut I2cState, idx: usize) {
    let sys = &*s.syscalls;
    let hp = s.handles.as_ptr().add(idx);
    let tp = s.transfers.as_mut_ptr().add(idx);
    let bus = (*hp).bus_id;
    let bi = s.buses.as_mut_ptr().add(bus as usize);

    // Configure bus speed if needed
    if (*bi).current_freq == 0 {
        configure_bus(sys, bus, 100_000); // default 100KHz
        (*bi).current_freq = 100_000;
    }

    // Set target address
    i2c_set_enable(sys, bus, false);
    i2c_reg_write(sys, bus, IC_TAR, (*hp).addr as u32);
    // Clear any abort
    let _ = i2c_reg_read(sys, bus, IC_CLR_TX_ABRT);
    i2c_set_enable(sys, bus, true);

    (*tp).tx_pos = 0;
    (*tp).rx_pos = 0;
    (*tp).pending = 0;
    (*tp).active = 1;
}

unsafe fn poll_i2c_transfer(s: &mut I2cState, idx: usize) {
    let sys = &*s.syscalls;
    let hp = s.handles.as_ptr().add(idx);
    let tp = s.transfers.as_mut_ptr().add(idx);
    if (*tp).active == 0 {
        return;
    }

    let bus = (*hp).bus_id;

    // Check for abort
    let abrt = i2c_reg_read(sys, bus, IC_TX_ABRT_SRC);
    if abrt != 0 {
        let _ = i2c_reg_read(sys, bus, IC_CLR_TX_ABRT);
        (*tp).result = -5; // EIO
        (*tp).active = 0;
        (*tp).done = 1;
        return;
    }

    let status = i2c_reg_read(sys, bus, IC_STATUS);

    // Push TX data or read commands into TX FIFO
    let total_tx = (*tp).tx_len as usize;
    let total_rx = (*tp).rx_len as usize;
    let tx_pos = (*tp).tx_pos as usize;

    match (*tp).op_type {
        0 => {
            // Write: push data bytes
            if tx_pos < total_tx && (status & STAT_TFNF) != 0 {
                let byte = (*tp).buf[tx_pos];
                let last = tx_pos + 1 == total_tx;
                let cmd = (byte as u32) | if last { CMD_STOP } else { 0 };
                i2c_reg_write(sys, bus, IC_DATA_CMD, cmd);
                (*tp).tx_pos = (tx_pos + 1) as u16;
            }
            // Check completion
            if (*tp).tx_pos as usize >= total_tx {
                // Wait for TX FIFO to drain
                let txflr = i2c_reg_read(sys, bus, IC_TXFLR);
                if txflr == 0 && (status & STAT_ACTIVITY) == 0 {
                    (*tp).result = total_tx as i32;
                    (*tp).active = 0;
                    (*tp).done = 1;
                }
            }
        }
        1 => {
            // Read: push read commands, then collect RX data
            if tx_pos < total_rx && (status & STAT_TFNF) != 0 {
                let last = tx_pos + 1 == total_rx;
                let cmd = CMD_READ | if last { CMD_STOP } else { 0 };
                i2c_reg_write(sys, bus, IC_DATA_CMD, cmd);
                (*tp).tx_pos = (tx_pos + 1) as u16;
            }
            // Read RX FIFO
            let rx_pos = (*tp).rx_pos as usize;
            if rx_pos < total_rx && (status & STAT_RFNE) != 0 {
                let byte = i2c_reg_read(sys, bus, IC_DATA_CMD) as u8;
                (*tp).buf[rx_pos] = byte;
                (*tp).rx_pos = (rx_pos + 1) as u16;
            }
            if (*tp).rx_pos as usize >= total_rx {
                (*tp).result = total_rx as i32;
                (*tp).active = 0;
                (*tp).done = 1;
            }
        }
        2 => {
            // Write+Read: write phase, then restart + read phase
            if tx_pos < total_tx && (status & STAT_TFNF) != 0 {
                let byte = (*tp).buf[tx_pos];
                // No STOP after write — restart before read
                i2c_reg_write(sys, bus, IC_DATA_CMD, byte as u32);
                (*tp).tx_pos = (tx_pos + 1) as u16;
            } else if tx_pos >= total_tx && tx_pos < total_tx + total_rx {
                // Read phase: push read commands
                if (status & STAT_TFNF) != 0 {
                    let read_idx = tx_pos - total_tx;
                    let last = read_idx + 1 == total_rx;
                    let restart = if read_idx == 0 { CMD_RESTART } else { 0 };
                    let cmd = CMD_READ | restart | if last { CMD_STOP } else { 0 };
                    i2c_reg_write(sys, bus, IC_DATA_CMD, cmd);
                    (*tp).tx_pos = (tx_pos + 1) as u16;
                }
            }
            // Collect RX
            let rx_pos = (*tp).rx_pos as usize;
            if rx_pos < total_rx && (status & STAT_RFNE) != 0 {
                let byte = i2c_reg_read(sys, bus, IC_DATA_CMD) as u8;
                (*tp).buf[rx_pos] = byte;
                (*tp).rx_pos = (rx_pos + 1) as u16;
            }
            if (*tp).rx_pos as usize >= total_rx && (*tp).tx_pos as usize >= total_tx + total_rx {
                (*tp).result = total_rx as i32;
                (*tp).active = 0;
                (*tp).done = 1;
            }
        }
        _ => {
            (*tp).result = -38;
            (*tp).active = 0;
            (*tp).done = 1;
        }
    }
}

// ============================================================================
// Provider dispatch
// ============================================================================

const I2C_OPEN: u32 = abi::registry::i2c::OPEN;
const I2C_CLOSE: u32 = abi::registry::i2c::CLOSE;
const I2C_WRITE: u32 = abi::registry::i2c::WRITE;
const I2C_READ: u32 = abi::registry::i2c::READ;
const I2C_WRITE_READ: u32 = abi::registry::i2c::WRITE_READ;
const I2C_POLL: u32 = abi::registry::i2c::POLL;
const I2C_CLAIM: u32 = abi::registry::i2c::CLAIM;
const I2C_RELEASE: u32 = abi::registry::i2c::RELEASE;

/// The slot an open handle names, if it is open.
unsafe fn live_idx(s: &I2cState, handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let idx = handle as usize;
    if idx >= MAX_HANDLES || (*s.handles.as_ptr().add(idx)).in_use == 0 {
        return None;
    }
    Some(idx)
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// both valid for the call.
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn i2c_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    let s = &mut *(state as *mut I2cState);
    let arg: &[u8] = if arg.is_null() {
        &[]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };

    if opcode == I2C_OPEN {
        let Some((bus, addr)) = abi::contracts::hal::i2c::open::decode(arg) else {
            return E_INVAL;
        };
        if bus as usize >= MAX_BUSES {
            return E_INVAL;
        }
        let mut i = 0usize;
        while i < MAX_HANDLES {
            let idx = (s.next_handle as usize + i) % MAX_HANDLES;
            let hp = s.handles.as_mut_ptr().add(idx);
            if (*hp).in_use == 0 {
                (*hp).in_use = 1;
                (*hp).bus_id = bus;
                (*hp).addr = addr;
                (*hp).owner = 0;
                s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                let tp = s.transfers.as_mut_ptr().add(idx);
                (*tp).pending = 0;
                (*tp).active = 0;
                (*tp).done = 0;
                (*tp).result = 0;
                return idx as i32;
            }
            i += 1;
        }
        return E_BUSY;
    }

    let Some(idx) = live_idx(s, handle) else {
        return E_INVAL;
    };
    let tp = s.transfers.as_mut_ptr().add(idx);

    match opcode {
        I2C_CLOSE => {
            (*s.handles.as_mut_ptr().add(idx)).in_use = 0;
            (*tp).pending = 0;
            (*tp).active = 0;
            (*tp).done = 0;
            0
        }
        I2C_WRITE | I2C_READ | I2C_WRITE_READ => {
            if (*tp).pending != 0 || (*tp).active != 0 {
                return E_BUSY;
            }
            let tx_len = if opcode == I2C_READ { 0 } else { data_len };
            let rx_len = if opcode == I2C_WRITE {
                0
            } else {
                match abi::contracts::hal::i2c::read::decode(arg) {
                    Some(n) => n as usize,
                    None => return E_INVAL,
                }
            };
            if tx_len > XFER_MAX || rx_len > XFER_MAX {
                return E_INVAL;
            }
            if (opcode != I2C_READ && (tx_len == 0 || data.is_null()))
                || (opcode != I2C_WRITE && rx_len == 0)
            {
                return E_INVAL;
            }
            if tx_len > 0 {
                core::ptr::copy_nonoverlapping(data, (*tp).buf.as_mut_ptr(), tx_len);
            }
            (*tp).tx_len = tx_len as u16;
            (*tp).rx_len = rx_len as u16;
            (*tp).op_type = if opcode == I2C_WRITE {
                0
            } else if opcode == I2C_READ {
                1
            } else {
                2
            };
            (*tp).done = 0;
            (*tp).result = 0;
            (*tp).pending = 1;
            0
        }
        I2C_POLL => {
            if (*tp).pending != 0 || (*tp).active != 0 {
                return E_AGAIN;
            }
            if (*tp).done == 0 {
                return 0;
            }
            (*tp).done = 0;
            let rx_len = (*tp).rx_len as usize;
            if (*tp).result > 0 && rx_len > 0 && !data.is_null() {
                let n = if rx_len < data_len { rx_len } else { data_len };
                core::ptr::copy_nonoverlapping((*tp).buf.as_ptr(), data, n);
            }
            (*tp).result
        }
        I2C_CLAIM => {
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != idx as i8 {
                return E_BUSY;
            }
            (*bi).bus_owner = idx as i8;
            0
        }
        I2C_RELEASE => {
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner == idx as i8 {
                (*bi).bus_owner = -1;
            }
            0
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// Module ABI
// ============================================================================

fluxor_rt::module_facts! { state: I2cState }

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
        if state_size < core::mem::size_of::<I2cState>() {
            return -2;
        }
        let s = &mut *(state as *mut I2cState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Initialize bus info
        let mut bus = 0u8;
        while (bus as usize) < MAX_BUSES {
            let bi = s.buses.as_mut_ptr().add(bus as usize);
            (*bi).bus_owner = -1;
            bus += 1;
        }

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[i2c] ready".as_ptr(), 10);
        0
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut I2cState);
    s.step_count = s.step_count.wrapping_add(1);

    let mut i = 0usize;
    while i < MAX_HANDLES {
        let tp = s.transfers.as_mut_ptr().add(i);
        if (*tp).pending != 0 {
            start_i2c_transfer(s, i);
        } else if (*tp).active != 0 {
            poll_i2c_transfer(s, i);
        }
        i += 1;
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
