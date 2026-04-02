//! SPI Bus Driver — PIC module provider
//!
//! Manages SPI bus access for consumer modules (sd, enc28j60, cyw43, st7701s).
//! Uses the kernel's thin register bridge (SPI_REG_WRITE/READ, SPI_BUS_INFO)
//! and raw DMA bridge (DMA_ALLOC/START/BUSY/FREE) for transfers.
//!
//! Same role as the kernel SPI driver in rp_providers.rs, but as a PIC module:
//! registers as the SPI provider (device class 0x02), handles OPEN/CLOSE/
//! CONFIGURE/TRANSFER_START/TRANSFER_POLL for all consumer modules.
//!
//! # Architecture
//!
//! ```text
//! Consumer module (sd, enc28j60, ...)
//!   → dev_call(SPI_OPEN/TRANSFER/...)
//!     → kernel provider dispatch
//!       → spi PIC module dispatch function
//!         → SPI_REG_WRITE (kernel bridge, ~5 lines MMIO)
//!         → DMA_START (kernel bridge, ~10 lines MMIO)
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

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

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
    cs_handle: i16,   // GPIO handle for CS, or -1
    owner: u8,        // module index that opened this handle
    mode: u8,         // SPI mode (CPOL/CPHA)
    _pad: [u8; 2],
    freq_hz: u32,
}

#[repr(C)]
struct SpiTransfer {
    tx_ptr: u32,      // TX buffer address (0 = no TX)
    rx_ptr: u32,      // RX buffer address (0 = no RX)
    tx_len: u16,
    rx_len: u16,
    fill: u8,         // fill byte for RX-only transfers
    pending: u8,      // 1 = waiting to start
    active: u8,       // 1 = DMA in progress
    _pad: u8,
    result: i32,      // >0 = bytes transferred, <0 = error, 0 = not done
    tx_dma_ch: i8,    // allocated TX DMA channel (-1 = none)
    rx_dma_ch: i8,    // allocated RX DMA channel (-1 = none)
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
// Register bridge helpers
// ============================================================================

unsafe fn spi_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0]; *bp.add(2) = v[1]; *bp.add(3) = v[2]; *bp.add(4) = v[3];
    (sys.dev_call)(bus as i32, 0x0CA0, bp, 5);
}

unsafe fn spi_reg_read(sys: &SyscallTable, bus: u8, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.dev_call)(bus as i32, 0x0CA1, bp, 5);
    u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)])
}

unsafe fn spi_bus_info(sys: &SyscallTable, bus: u8, info: &mut BusInfo) {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    (sys.dev_call)(bus as i32, 0x0CA2, bp, 12);
    info.dr_addr = u32::from_le_bytes([*bp, *bp.add(1), *bp.add(2), *bp.add(3)]);
    info.tx_dreq = *bp.add(4);
    info.rx_dreq = *bp.add(5);
    info.max_freq = u32::from_le_bytes([*bp.add(6), *bp.add(7), *bp.add(8), *bp.add(9)]);
}

unsafe fn spi_set_enable(sys: &SyscallTable, bus: u8, enable: bool) {
    let mut buf = [if enable { 1u8 } else { 0u8 }];
    (sys.dev_call)(bus as i32, 0x0CA4, buf.as_mut_ptr(), 1);
}

unsafe fn spi_pin_init(sys: &SyscallTable, bus: u8, clk: u8, mosi: u8, miso: u8) {
    let mut buf = [clk, mosi, miso];
    (sys.dev_call)(bus as i32, 0x0CA3, buf.as_mut_ptr(), 3);
}

// Raw DMA helpers
unsafe fn dma_alloc(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, 0x0C80, core::ptr::null_mut(), 0)
}

unsafe fn dma_free(sys: &SyscallTable, ch: u8) {
    let mut buf = [ch];
    (sys.dev_call)(-1, 0x0C81, buf.as_mut_ptr(), 1);
}

unsafe fn dma_start(sys: &SyscallTable, ch: u8, read: u32, write: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let mut buf = [0u8; 15];
    let bp = buf.as_mut_ptr();
    *bp = ch;
    let r = read.to_le_bytes();
    *bp.add(1) = r[0]; *bp.add(2) = r[1]; *bp.add(3) = r[2]; *bp.add(4) = r[3];
    let w = write.to_le_bytes();
    *bp.add(5) = w[0]; *bp.add(6) = w[1]; *bp.add(7) = w[2]; *bp.add(8) = w[3];
    let c = count.to_le_bytes();
    *bp.add(9) = c[0]; *bp.add(10) = c[1]; *bp.add(11) = c[2]; *bp.add(12) = c[3];
    *bp.add(13) = dreq;
    *bp.add(14) = flags;
    (sys.dev_call)(-1, 0x0C82, bp, 15)
}

unsafe fn dma_busy(sys: &SyscallTable, ch: u8) -> bool {
    let mut buf = [ch];
    (sys.dev_call)(-1, 0x0C83, buf.as_mut_ptr(), 1) != 0
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

    let tx_len = (*tp).tx_len as u32;
    let rx_len = (*tp).rx_len as u32;
    let len = if tx_len > rx_len { tx_len } else { rx_len };
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
    if (*tp).rx_ptr != 0 {
        dma_start(sys, rx_ch as u8, dr, (*tp).rx_ptr, len,
            (*bi).rx_dreq, DMA_FLAG_INCR_WRITE | DMA_FLAG_SIZE_8);
    } else {
        // No RX buffer — still drain RX FIFO to dev/null
        // Use a dummy address that doesn't increment
        dma_start(sys, rx_ch as u8, dr, dr, len,
            (*bi).rx_dreq, DMA_FLAG_SIZE_8); // no incr_write
    }

    // Start TX DMA
    if (*tp).tx_ptr != 0 {
        dma_start(sys, tx_ch as u8, (*tp).tx_ptr, dr, len,
            (*bi).tx_dreq, DMA_FLAG_INCR_READ | DMA_FLAG_SIZE_8);
    } else {
        // TX fill: write same byte repeatedly from fill field address
        let fill_addr = &(*tp).fill as *const u8 as u32;
        dma_start(sys, tx_ch as u8, fill_addr, dr, len,
            (*bi).tx_dreq, DMA_FLAG_SIZE_8); // no incr_read
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
    let tx_len = (*tp).tx_len as i32;
    let rx_len = (*tp).rx_len as i32;
    (*tp).result = if tx_len > rx_len { tx_len } else { rx_len };
    (*tp).active = 0;

    // Free DMA channels
    if (*tp).tx_dma_ch >= 0 { dma_free(sys, (*tp).tx_dma_ch as u8); (*tp).tx_dma_ch = -1; }
    if (*tp).rx_dma_ch >= 0 { dma_free(sys, (*tp).rx_dma_ch as u8); (*tp).rx_dma_ch = -1; }
}

// ============================================================================
// Provider dispatch (called by kernel when consumer does dev_call SPI class)
// ============================================================================

// These constants match the SPI dev_call opcodes in abi.rs
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

// Provider dispatch — called from kernel via registered function pointer.
// SAFETY: state is our SpiState, validated at registration time.
#[unsafe(no_mangle)]
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
            // arg=[bus:u8, cs_handle:i16 LE, freq:u32 LE, mode:u8] (8 bytes)
            if arg.is_null() || arg_len < 8 { return -22; }
            let bus = *arg;
            if bus as usize >= MAX_BUSES { return -22; }
            let cs = i16::from_le_bytes([*arg.add(1), *arg.add(2)]);
            let freq = u32::from_le_bytes([*arg.add(3), *arg.add(4), *arg.add(5), *arg.add(6)]);
            let mode = *arg.add(7);

            // Find free handle
            let mut i = 0usize;
            while i < MAX_HANDLES {
                let idx = (s.next_handle as usize + i) % MAX_HANDLES;
                let hp = s.handles.as_mut_ptr().add(idx);
                if (*hp).in_use == 0 {
                    (*hp).in_use = 1;
                    (*hp).bus_id = bus;
                    (*hp).cs_handle = cs;
                    (*hp).freq_hz = freq;
                    (*hp).mode = mode;
                    (*hp).owner = 0; // TODO: get caller module index
                    s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                    // Clear transfer state
                    let tp = s.transfers.as_mut_ptr().add(idx);
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
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let hp = s.handles.as_mut_ptr().add(idx);
            if (*hp).in_use == 0 { return -22; }
            // Abort any active transfer
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).tx_dma_ch >= 0 { dma_free(sys, (*tp).tx_dma_ch as u8); }
            if (*tp).rx_dma_ch >= 0 { dma_free(sys, (*tp).rx_dma_ch as u8); }
            (*tp).pending = 0;
            (*tp).active = 0;
            (*hp).in_use = 0;
            0
        }
        SPI_BEGIN => {
            // Claim bus for exclusive access
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let hp = s.handles.as_ptr().add(idx);
            let bus = (*hp).bus_id as usize;
            if bus >= MAX_BUSES { return -22; }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != handle as i8 {
                return -16; // EBUSY
            }
            (*bi).bus_owner = handle as i8;
            0
        }
        SPI_END => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let hp = s.handles.as_ptr().add(idx);
            let bus = (*hp).bus_id as usize;
            if bus >= MAX_BUSES { return -22; }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner == handle as i8 {
                (*bi).bus_owner = -1;
            }
            0
        }
        SPI_SET_CS => {
            // arg=[level:u8]
            if arg.is_null() || arg_len < 1 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let hp = s.handles.as_ptr().add(idx);
            let cs = (*hp).cs_handle;
            if cs >= 0 {
                // Toggle CS via GPIO SET_LEVEL
                let mut buf = [*arg]; // level
                (sys.dev_call)(cs as i32, 0x0107, buf.as_mut_ptr(), 1); // GPIO_SET_LEVEL
            }
            0
        }
        SPI_CONFIGURE => {
            // arg=[freq:u32 LE, mode:u8] (5 bytes)
            if arg.is_null() || arg_len < 5 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let hp = s.handles.as_mut_ptr().add(idx);
            (*hp).freq_hz = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*hp).mode = *arg.add(4);
            0
        }
        SPI_TRANSFER_START => {
            // arg=[tx_ptr:u32, rx_ptr:u32, tx_len:u16, rx_len:u16, fill:u8] (13 bytes)
            if arg.is_null() || arg_len < 13 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).pending != 0 || (*tp).active != 0 { return -16; }
            (*tp).tx_ptr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*tp).rx_ptr = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            (*tp).tx_len = u16::from_le_bytes([*arg.add(8), *arg.add(9)]);
            (*tp).rx_len = u16::from_le_bytes([*arg.add(10), *arg.add(11)]);
            (*tp).fill = *arg.add(12);
            (*tp).result = 0;
            (*tp).pending = 1;
            0
        }
        SPI_TRANSFER_POLL => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_ptr().add(idx);
            if (*tp).pending != 0 { return 0; }  // not started yet
            if (*tp).active != 0 { return 0; }   // DMA in progress
            (*tp).result  // >0 = done (byte count), <0 = error
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

        // Register as SPI provider (device class 0x02)
        let dispatch_addr = spi_dispatch as *const () as u32;
        let mut reg_args = [0u8; 8];
        let rp = reg_args.as_mut_ptr();
        *rp = 0x02; // device_class = SPI
        *rp.add(1) = 0; *rp.add(2) = 0; *rp.add(3) = 0;
        let da = dispatch_addr.to_le_bytes();
        *rp.add(4) = da[0]; *rp.add(5) = da[1]; *rp.add(6) = da[2]; *rp.add(7) = da[3];
        (sys.dev_call)(-1, 0x0C20, rp, 8); // REGISTER_PROVIDER

        dev_log(sys, 3, b"[spi] provider registered".as_ptr(), 24);
        0
    }
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
