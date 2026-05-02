//! SPI Bus Driver — PIC module provider
//!
//! Manages SPI bus access for consumer modules (sd, enc28j60, cyw43, st7701s).
//! Uses the kernel's thin register bridge (`spi_raw::REG_WRITE/READ/BUS_INFO`)
//! and the PLATFORM_DMA contract's channel family for transfers.
//!
//! Registers as the HAL_SPI provider (contract id 0x02); handles OPEN/CLOSE/
//! CONFIGURE/TRANSFER_START/TRANSFER_POLL for all consumer modules.
//!
//! # Architecture
//!
//! ```text
//! Consumer module (sd, enc28j60, ...)
//!   → provider_call(spi_handle, SPI_OPEN/TRANSFER/...)
//!     → kernel provider dispatch (HAL_SPI vtable)
//!       → spi_pl022 provider_dispatch
//!         → spi_raw::REG_WRITE (kernel bridge, ~5 lines MMIO)
//!         → channel::START (kernel bridge, ~10 lines MMIO)
//! ```
//!
//! # Transfer Flow
//!
//! 1. Consumer calls SPI_TRANSFER_START (stages tx/rx pointers + length)
//! 2. SPI module's provider dispatch stores the operation as pending
//! 3. On next module_step: configures SPI registers, starts TX+RX DMA
//! 4. Subsequent module_step: polls DMA busy flag
//! 5. DMA done: sets result, consumer sees it via SPI_TRANSFER_POLL

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

const MAX_HANDLES: usize = 8;
const MAX_BUSES: usize = 2;
const OWNER_KERNEL: u8 = 0xFF;

// SPI register offsets (PL022 / RP2350)
const SSPCR0: u8 = 0x00;   // Control register 0 (format, clock rate)
const SSPCR1: u8 = 0x04;   // Control register 1 (enable, mode)
const SSPDR: u8 = 0x08;    // Data register
const SSPSR: u8 = 0x0C;    // Status register
const SSPCPSR: u8 = 0x10;  // Clock prescaler
const SSPDMACR: u8 = 0x24; // DMA control

// SSPSR bits
const SSPSR_BSY: u32 = 1 << 4;
const SSPSR_TFE: u32 = 1 << 0; // TX FIFO empty

// DMA flags for SPI: data_size=8bit (0), incr_read=1, incr_write=1
const DMA_FLAG_INCR_READ: u8 = 0x01;
const DMA_FLAG_INCR_WRITE: u8 = 0x02;
const DMA_FLAG_SIZE_8: u8 = 0x00;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct SpiHandle {
    in_use: u8,
    bus_id: u8,
    mode: u8,         // SPI mode (CPOL/CPHA)
    owner: u8,        // module index that opened this handle
    cs_handle: i32,   // GPIO handle for CS, or -1
    freq_hz: u32,
}

#[repr(C)]
struct SpiTransfer {
    tx_ptr: *const u8, // TX buffer (null = drive fill byte)
    rx_ptr: *mut u8,   // RX buffer (null = discard)
    len: u32,          // shared length for tx + rx (full-duplex)
    fill: u8,          // fill byte when tx is null
    pending: u8,       // 1 = waiting to start
    active: u8,        // 1 = DMA in progress
    _pad: u8,
    result: i32,       // >0 = bytes transferred, <0 = error, 0 = not done
    tx_dma_ch: i8,     // allocated TX DMA channel (-1 = none)
    rx_dma_ch: i8,     // allocated RX DMA channel (-1 = none)
    _pad2: [u8; 2],
}

#[repr(C)]
struct BusInfo {
    dr_addr: u32,     // SPI data register physical address
    tx_dreq: u8,
    rx_dreq: u8,
    initialized: u8,
    _pad: u8,
    max_freq: u32,
    current_freq: u32,
    current_mode: u8,
    bus_owner: i8,    // handle index that claimed the bus (-1 = free)
    _pad2: [u8; 2],
}

#[repr(C)]
struct SpiState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    handles: [SpiHandle; MAX_HANDLES],
    transfers: [SpiTransfer; MAX_HANDLES],
    buses: [BusInfo; MAX_BUSES],
    step_count: u32,
    next_handle: u8,
    _pad: [u8; 3],
}

// ============================================================================
// Contract structs + register bridge helpers (opcodes from layered ABI).
// ============================================================================

use abi::contracts::hal::spi::{OpenArgs as SpiOpenArgs, TransferStartArgs as SpiTransferStartArgs};
use abi::contracts::hal::gpio as hal_gpio;

use abi::platform::rp::spi_raw::{
    REG_WRITE as SPI_REG_WRITE,
    REG_READ as SPI_REG_READ,
    BUS_INFO as SPI_BUS_INFO,
    PIN_INIT as SPI_PIN_INIT,
    SET_ENABLE as SPI_SET_ENABLE,
};

unsafe fn spi_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0]; *bp.add(2) = v[1]; *bp.add(3) = v[2]; *bp.add(4) = v[3];
    (sys.provider_call)(bus as i32, SPI_REG_WRITE, bp, 5);
}

unsafe fn spi_reg_read(sys: &SyscallTable, bus: u8, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.provider_call)(bus as i32, SPI_REG_READ, bp, 5);
    u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)])
}

unsafe fn spi_bus_info(sys: &SyscallTable, bus: u8, info: &mut BusInfo) {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    (sys.provider_call)(bus as i32, SPI_BUS_INFO, bp, 12);
    info.dr_addr = u32::from_le_bytes([*bp, *bp.add(1), *bp.add(2), *bp.add(3)]);
    info.tx_dreq = *bp.add(4);
    info.rx_dreq = *bp.add(5);
    info.max_freq = u32::from_le_bytes([*bp.add(6), *bp.add(7), *bp.add(8), *bp.add(9)]);
}

unsafe fn spi_set_enable(sys: &SyscallTable, bus: u8, enable: bool) {
    let mut buf = [if enable { 1u8 } else { 0u8 }];
    (sys.provider_call)(bus as i32, SPI_SET_ENABLE, buf.as_mut_ptr(), 1);
}

unsafe fn spi_pin_init(sys: &SyscallTable, bus: u8, clk: u8, mosi: u8, miso: u8) {
    let mut buf = [clk, mosi, miso];
    (sys.provider_call)(bus as i32, SPI_PIN_INIT, buf.as_mut_ptr(), 3);
}

// DMA: channel family only. spi_pl022 allocates a raw DMA channel per
// direction (tx / rx), manually drives each transfer via channel::START,
// polls with channel::BUSY. All ops are handle-scoped — the handle is
// the channel number returned by provider_open(PLATFORM_DMA,
// channel::ALLOC). See `provider::contract::PLATFORM_DMA` for the
// channel-vs-fd family distinction.
use abi::platform::rp::dma_raw::channel as dma_channel;

const PLATFORM_DMA: u32 = 0x0008;

unsafe fn dma_alloc(sys: &SyscallTable) -> i32 {
    (sys.provider_open)(PLATFORM_DMA, dma_channel::ALLOC, core::ptr::null(), 0)
}

unsafe fn dma_free(sys: &SyscallTable, ch: u8) {
    (sys.provider_call)(ch as i32, dma_channel::FREE, core::ptr::null_mut(), 0);
}

unsafe fn dma_start(sys: &SyscallTable, ch: u8, read: u32, write: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let mut buf = [0u8; 14];
    let bp = buf.as_mut_ptr();
    let r = read.to_le_bytes();
    *bp = r[0]; *bp.add(1) = r[1]; *bp.add(2) = r[2]; *bp.add(3) = r[3];
    let w = write.to_le_bytes();
    *bp.add(4) = w[0]; *bp.add(5) = w[1]; *bp.add(6) = w[2]; *bp.add(7) = w[3];
    let c = count.to_le_bytes();
    *bp.add(8) = c[0]; *bp.add(9) = c[1]; *bp.add(10) = c[2]; *bp.add(11) = c[3];
    *bp.add(12) = dreq;
    *bp.add(13) = flags;
    (sys.provider_call)(ch as i32, dma_channel::START, bp, 14)
}

unsafe fn dma_busy(sys: &SyscallTable, ch: u8) -> bool {
    (sys.provider_call)(ch as i32, dma_channel::BUSY, core::ptr::null_mut(), 0) != 0
}

// ============================================================================
// SPI configuration
// ============================================================================

unsafe fn configure_bus(sys: &SyscallTable, bus: u8, freq_hz: u32, mode: u8) {
    // Disable SPI while configuring
    spi_set_enable(sys, bus, false);

    // Clock: prescaler * (1 + SCR) = Fsys / freq
    // Prescaler must be even, 2..254. SCR is 0..255.
    let fsys = 150_000_000u32; // TODO: query from kernel
    let mut prescaler = 2u32;
    let mut scr = 0u32;
    if freq_hz > 0 {
        let div = fsys / freq_hz;
        // Find best prescaler/SCR combo
        prescaler = 2;
        while prescaler <= 254 {
            scr = (div / prescaler).saturating_sub(1);
            if scr <= 255 { break; }
            prescaler += 2;
        }
        if scr > 255 { scr = 255; }
    }

    // SSPCPSR = prescaler (even, 2..254)
    spi_reg_write(sys, bus, SSPCPSR, prescaler);

    // SSPCR0: SCR[15:8] | SPH[7] | SPO[6] | FRF=Motorola[5:4] | DSS=8bit[3:0]
    let cpol = ((mode >> 1) & 1) as u32;
    let cpha = (mode & 1) as u32;
    let cr0 = (scr << 8) | (cpha << 7) | (cpol << 6) | 0x07; // 8-bit, Motorola
    spi_reg_write(sys, bus, SSPCR0, cr0);

    // Enable DMA (TX + RX)
    spi_reg_write(sys, bus, SSPDMACR, 0x03);

    // SSPCR1: SSE=1 (enable), MS=0 (master)
    spi_set_enable(sys, bus, true);
}

// ============================================================================
// Transfer execution
// ============================================================================

unsafe fn start_transfer(s: &mut SpiState, handle_idx: usize) {
    let sys = &*s.syscalls;
    let hp = s.handles.as_ptr().add(handle_idx);
    let tp = s.transfers.as_mut_ptr().add(handle_idx);
    let bus_id = (*hp).bus_id;
    let bi = s.buses.as_ptr().add(bus_id as usize);

    // Configure bus for this handle's settings if changed
    if (*hp).freq_hz != (*bi).current_freq || (*hp).mode != (*bi).current_mode {
        configure_bus(sys, bus_id, (*hp).freq_hz, (*hp).mode);
        let bm = s.buses.as_mut_ptr().add(bus_id as usize);
        (*bm).current_freq = (*hp).freq_hz;
        (*bm).current_mode = (*hp).mode;
    }

    let len = (*tp).len;
    if len == 0 {
        (*tp).result = 1; // zero-length = immediate success
        (*tp).pending = 0;
        return;
    }

    // Allocate DMA channels
    let tx_ch = dma_alloc(sys);
    if tx_ch < 0 { (*tp).result = tx_ch; (*tp).pending = 0; return; }
    let rx_ch = dma_alloc(sys);
    if rx_ch < 0 {
        dma_free(sys, tx_ch as u8);
        (*tp).result = rx_ch; (*tp).pending = 0; return;
    }
    (*tp).tx_dma_ch = tx_ch as i8;
    (*tp).rx_dma_ch = rx_ch as i8;

    let dr = (*bi).dr_addr;

    // Start RX DMA first (so it's ready when TX pushes data)
    if !(*tp).rx_ptr.is_null() {
        dma_start(sys, rx_ch as u8, dr, (*tp).rx_ptr as u32, len,
            (*bi).rx_dreq, DMA_FLAG_INCR_WRITE | DMA_FLAG_SIZE_8);
    } else {
        // No RX buffer — still drain RX FIFO to dev/null via a non-incrementing write
        dma_start(sys, rx_ch as u8, dr, dr, len,
            (*bi).rx_dreq, DMA_FLAG_SIZE_8);
    }

    // Start TX DMA
    if !(*tp).tx_ptr.is_null() {
        dma_start(sys, tx_ch as u8, (*tp).tx_ptr as u32, dr, len,
            (*bi).tx_dreq, DMA_FLAG_INCR_READ | DMA_FLAG_SIZE_8);
    } else {
        // TX fill: write same byte repeatedly from fill field address
        let fill_addr = &(*tp).fill as *const u8 as u32;
        dma_start(sys, tx_ch as u8, fill_addr, dr, len,
            (*bi).tx_dreq, DMA_FLAG_SIZE_8);
    }

    (*tp).pending = 0;
    (*tp).active = 1;
}

unsafe fn poll_transfer(s: &mut SpiState, handle_idx: usize) {
    let sys = &*s.syscalls;
    let tp = s.transfers.as_mut_ptr().add(handle_idx);
    if (*tp).active == 0 { return; }

    let rx_ch = (*tp).rx_dma_ch;
    if rx_ch >= 0 && dma_busy(sys, rx_ch as u8) {
        return; // still running
    }

    // Transfer complete
    (*tp).result = (*tp).len as i32;
    (*tp).active = 0;

    // Free DMA channels
    if (*tp).tx_dma_ch >= 0 { dma_free(sys, (*tp).tx_dma_ch as u8); (*tp).tx_dma_ch = -1; }
    if (*tp).rx_dma_ch >= 0 { dma_free(sys, (*tp).rx_dma_ch as u8); (*tp).rx_dma_ch = -1; }
}

// ============================================================================
// Provider dispatch (called by kernel when a consumer does provider_call
// on a HAL_SPI handle).
// ============================================================================

// Must match the HAL_SPI contract opcodes in abi::contracts::hal::spi.
const SPI_OPEN: u32 = 0x0200;
const SPI_CLOSE: u32 = 0x0201;
const SPI_BEGIN: u32 = 0x0202;
const SPI_END: u32 = 0x0203;
const SPI_SET_CS: u32 = 0x0204;
const SPI_CLAIM: u32 = 0x0205;
const SPI_CONFIGURE: u32 = 0x0206;
const SPI_TRANSFER_START: u32 = 0x0207;
const SPI_TRANSFER_POLL: u32 = 0x0208;
const SPI_POLL_BYTE: u32 = 0x0209;
const SPI_GET_CAPS: u32 = 0x020A;

/// Resolve an incoming handle to a live slot index. Returns `Some(idx)`
/// only if the handle is in range AND the slot is currently in use.
/// Used by every per-handle opcode so stale handles (closed, or never
/// issued by SPI_OPEN but routed here via class-byte fallback) cannot
/// mutate bus state.
#[inline]
unsafe fn live_handle_idx(s: &SpiState, handle: i32) -> Option<usize> {
    if handle < 0 { return None; }
    let idx = handle as usize;
    if idx >= MAX_HANDLES { return None; }
    if (*s.handles.as_ptr().add(idx)).in_use == 0 { return None; }
    Some(idx)
}

// Provider dispatch — called from kernel via registered function pointer.
// SAFETY: state is our SpiState, validated at registration time.
#[unsafe(no_mangle)]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn spi_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut SpiState);
    let sys = &*s.syscalls;

    match opcode {
        SPI_OPEN => {
            if arg.is_null() || arg_len < core::mem::size_of::<SpiOpenArgs>() { return -22; }
            let args = &*(arg as *const SpiOpenArgs);
            if args.bus as usize >= MAX_BUSES { return -22; }

            // Find free handle
            let mut i = 0usize;
            while i < MAX_HANDLES {
                let idx = (s.next_handle as usize + i) % MAX_HANDLES;
                let hp = s.handles.as_mut_ptr().add(idx);
                if (*hp).in_use == 0 {
                    (*hp).in_use = 1;
                    (*hp).bus_id = args.bus;
                    (*hp).cs_handle = args.cs_handle;
                    (*hp).freq_hz = args.freq_hz;
                    (*hp).mode = args.mode;
                    (*hp).owner = 0; // TODO: get caller module index
                    s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                    // Clear transfer state so nothing from a previous owner leaks.
                    let tp = s.transfers.as_mut_ptr().add(idx);
                    (*tp).tx_ptr = core::ptr::null();
                    (*tp).rx_ptr = core::ptr::null_mut();
                    (*tp).len = 0;
                    (*tp).fill = 0;
                    (*tp).pending = 0;
                    (*tp).active = 0;
                    (*tp).result = 0;
                    (*tp).tx_dma_ch = -1;
                    (*tp).rx_dma_ch = -1;
                    return idx as i32;
                }
                i += 1;
            }
            -16 // EBUSY
        }
        SPI_CLOSE => {
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let hp = s.handles.as_mut_ptr().add(idx);
            // Abort any active transfer
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).tx_dma_ch >= 0 { dma_free(sys, (*tp).tx_dma_ch as u8); }
            if (*tp).rx_dma_ch >= 0 { dma_free(sys, (*tp).rx_dma_ch as u8); }
            (*tp).pending = 0;
            (*tp).active = 0;
            // Release the bus if this handle owned it.
            let bus = (*hp).bus_id as usize;
            if bus < MAX_BUSES {
                let bi = s.buses.as_mut_ptr().add(bus);
                if (*bi).bus_owner == idx as i8 { (*bi).bus_owner = -1; }
            }
            (*hp).in_use = 0;
            0
        }
        SPI_CLAIM => {
            // Non-blocking try-claim. arg is a u32 timeout in ms that
            // callers use to pace their own retry loops; this dispatch
            // itself just attempts the claim once and returns.
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES { return -22; }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != idx as i8 {
                return -16; // EBUSY
            }
            (*bi).bus_owner = idx as i8;
            0
        }
        SPI_BEGIN => {
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES { return -22; }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != idx as i8 {
                return -16; // EBUSY
            }
            (*bi).bus_owner = idx as i8;
            0
        }
        SPI_END => {
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES { return -22; }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner == idx as i8 {
                (*bi).bus_owner = -1;
            }
            0
        }
        SPI_SET_CS => {
            // arg=[level:u8]
            if arg.is_null() || arg_len < 1 { return -22; }
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let cs = (*s.handles.as_ptr().add(idx)).cs_handle;
            if cs >= 0 {
                let mut buf = [*arg];
                (sys.provider_call)(cs, hal_gpio::SET_LEVEL, buf.as_mut_ptr(), 1);
            }
            0
        }
        SPI_CONFIGURE => {
            // arg=[freq:u32 LE, mode:u8] (5 bytes)
            if arg.is_null() || arg_len < 5 { return -22; }
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let hp = s.handles.as_mut_ptr().add(idx);
            (*hp).freq_hz = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*hp).mode = *arg.add(4);
            0
        }
        SPI_TRANSFER_START => {
            if arg.is_null() || arg_len < core::mem::size_of::<SpiTransferStartArgs>() { return -22; }
            let args = &*(arg as *const SpiTransferStartArgs);
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).pending != 0 || (*tp).active != 0 { return -16; }
            (*tp).tx_ptr = args.tx;
            (*tp).rx_ptr = args.rx;
            (*tp).len = args.len;
            (*tp).fill = args.fill;
            (*tp).result = 0;
            (*tp).pending = 1;
            0
        }
        SPI_TRANSFER_POLL => {
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let tp = s.transfers.as_ptr().add(idx);
            if (*tp).pending != 0 { return 0; }  // not started yet
            if (*tp).active != 0 { return 0; }   // DMA in progress
            (*tp).result  // >0 = done (byte count), <0 = error
        }
        SPI_POLL_BYTE => {
            // Byte-sized poll for single-byte transfers: returns
            //   0         = no byte available yet (still pending / active)
            //   0x100|b   = complete, b is the received byte
            //   < 0       = error
            let idx = match live_handle_idx(s, handle) { Some(i) => i, None => return -22 };
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).result < 0 {
                let r = (*tp).result;
                (*tp).result = 0;
                return r;
            }
            if (*tp).pending != 0 || (*tp).active != 0 { return 0; }
            if (*tp).result > 0 {
                let byte = if !(*tp).rx_ptr.is_null() {
                    *(*tp).rx_ptr
                } else {
                    0xFF
                };
                (*tp).result = 0; // consume
                return 0x100 | byte as i32;
            }
            0
        }
        SPI_GET_CAPS => {
            if arg.is_null() || arg_len < 8 { return -22; }
            // Return [max_freq:u32, mode_mask:u8, pad:3]
            let max_freq = 75_000_000u32; // conservative: Fsys/2
            let mf = max_freq.to_le_bytes();
            *arg = mf[0]; *arg.add(1) = mf[1]; *arg.add(2) = mf[2]; *arg.add(3) = mf[3];
            *arg.add(4) = 0x0F; // all 4 SPI modes
            0
        }
        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<SpiState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<SpiState>() { return -2; }

        let s = &mut *(state as *mut SpiState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Initialize bus info from kernel bridge
        let sys = &*s.syscalls;
        let mut bus = 0u8;
        while (bus as usize) < MAX_BUSES {
            let bi = s.buses.as_mut_ptr().add(bus as usize);
            spi_bus_info(sys, bus, &mut *bi);
            (*bi).bus_owner = -1;
            if (*bi).dr_addr != 0 {
                (*bi).initialized = 1;
            }
            bus += 1;
        }

        // Initialize handles
        let mut i = 0usize;
        while i < MAX_HANDLES {
            let tp = s.transfers.as_mut_ptr().add(i);
            (*tp).tx_dma_ch = -1;
            (*tp).rx_dma_ch = -1;
            i += 1;
        }

        dev_log(sys, 3, b"[spi] ready".as_ptr(), 10);
        0
    }
}

/// Loader-driven provider registration: kernel calls this after
/// module_new() succeeds, reads the contract id, looks up
/// `module_provider_dispatch` in the export table, and registers us.
#[unsafe(no_mangle)]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    0x0002 // HAL_SPI
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SpiState);
    s.step_count = s.step_count.wrapping_add(1);

    // Process pending transfers and poll active ones
    let mut i = 0usize;
    while i < MAX_HANDLES {
        let tp = s.transfers.as_mut_ptr().add(i);
        if (*tp).pending != 0 {
            start_transfer(s, i);
        } else if (*tp).active != 0 {
            poll_transfer(s, i);
        }
        i += 1;
    }

    0 // Continue
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
