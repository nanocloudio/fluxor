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
//! 1. Consumer lends a span on its SPI handle and calls SPI_TRANSFER_START
//!    naming `[lend][offset][len][fill]`; the lend's direction is the
//!    transfer's (`contracts::hal::spi::transfer_start`)
//! 2. SPI module's provider dispatch borrows the span and stores the
//!    operation as pending
//! 3. On next module_step: configures SPI registers, stages a chunk in the
//!    bus's bounce buffer, starts TX+RX DMA over it (the bounce is this
//!    module's own memory, lent once to each of the bus's DMA channels)
//! 4. Subsequent module_step: polls DMA busy flag; each finished chunk's
//!    received bytes are copied back, and the next chunk started
//! 5. Done: the borrow is given back, the result set, and the consumer sees
//!    it via SPI_TRANSFER_POLL

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

// SPI register offsets (PL022 / RP2350)
const SSPCR0: u8 = 0x00; // Control register 0 (format, clock rate)
const SSPCPSR: u8 = 0x10; // Clock prescaler
const SSPDMACR: u8 = 0x24; // DMA control

/// DMA flags for SPI: byte units, the memory side advancing.
const DMA_FLAGS: u8 =
    abi::platform::rp::dma_raw::flags::INCR | abi::platform::rp::dma_raw::flags::SIZE_BYTE;

/// Bytes one DMA chunk moves: the bus's bounce buffer.
const BOUNCE: usize = 1024;

/// Cookie of the bounce buffer's lend on each of a bus's DMA channels.
const BOUNCE_LEND: u32 = 1;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct SpiHandle {
    in_use: u8,
    bus_id: u8,
    mode: u8,       // SPI mode (CPOL/CPHA)
    owner: u8,      // module index that opened this handle
    cs_handle: i32, // the CS pin's GPIO claim, held by this provider, or -1
    freq_hz: u32,
}

#[repr(C)]
struct SpiTransfer {
    /// The consumer's span, borrowed from TRANSFER_START until the transfer
    /// ends; null when nothing is borrowed.
    span: *mut u8,
    /// The session (the handle as the kernel delivered it) and cookie the
    /// borrow is given back under.
    session: i32,
    lend: u32,
    len: u32,   // bytes to clock (full-duplex)
    done: u32,  // bytes clocked so far
    chunk: u32, // bytes of the chunk in flight
    fill: u8,   // byte transmitted when the span is not read
    /// The lend's direction: `LEND_IN` transmit, `LEND_OUT` receive,
    /// `LEND_INOUT` both.
    dir: u8,
    pending: u8, // 1 = waiting to start
    active: u8,  // 1 = DMA in progress
    result: i32, // >0 = bytes transferred, <0 = error, 0 = not done
    /// The received byte of a finished transfer, for POLL_BYTE.
    last_rx: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct BusInfo {
    tx_dreq: u8,
    rx_dreq: u8,
    initialized: u8,
    _pad: u8,
    max_freq: u32,
    current_freq: u32,
    current_mode: u8,
    bus_owner: i8, // handle index that claimed the bus (-1 = free)
    /// Handle whose transfer holds the bounce buffer (-1 = none).
    busy: i8,
    _pad2: u8,
    /// The bus's DMA channels (handles; -1 until first use), each
    /// with the bounce buffer lent on it.
    tx_ch: i32,
    rx_ch: i32,
    bounce: [u8; BOUNCE],
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
    ready_reported: u8,
    _pad: [u8; 2],
}

// ============================================================================
// Contract structs + register bridge helpers (opcodes from layered ABI).
// ============================================================================

use abi::contracts::hal::gpio as hal_gpio;
use abi::contracts::hal::spi::{open as spi_open, transfer_start};

use abi::platform::rp::spi_raw::{
    BUS_INFO as SPI_BUS_INFO, REG_WRITE as SPI_REG_WRITE, SET_ENABLE as SPI_SET_ENABLE,
};

unsafe fn spi_reg_write(sys: &SyscallTable, bus: u8, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0];
    *bp.add(2) = v[1];
    *bp.add(3) = v[2];
    *bp.add(4) = v[3];
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::SPI, bus),
        SPI_REG_WRITE,
        bp,
        5,
        core::ptr::null_mut(),
        0,
    );
}

/// The bus's DMA pacing; false when the bus cannot be claimed or the die
/// lacks it.
unsafe fn spi_bus_info(sys: &SyscallTable, bus: u8, info: &mut BusInfo) -> bool {
    let mut buf = [0u8; 8];
    let rc = (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::SPI, bus),
        SPI_BUS_INFO,
        buf.as_mut_ptr(),
        buf.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return false;
    }
    info.tx_dreq = buf[0];
    info.rx_dreq = buf[1];
    info.max_freq = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    true
}

unsafe fn spi_set_enable(sys: &SyscallTable, bus: u8, enable: bool) {
    let mut buf = [if enable { 1u8 } else { 0u8 }];
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::SPI, bus),
        SPI_SET_ENABLE,
        buf.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
}

// DMA: channel family only. spi_pl022 allocates a raw DMA channel per
// direction (tx / rx), manually drives each transfer via channel::START,
// polls with channel::BUSY. All ops are handle-scoped — the handle is
// the channel number returned by provider_open(PLATFORM_DMA,
// channel::ALLOC). See `provider::contract::PLATFORM_DMA` for the
// channel-vs-fd family distinction.
use abi::platform::rp::dma_raw::channel as dma_channel;

const PLATFORM_DMA: u32 = abi::registry::platform_dma::ID as u32;

unsafe fn dma_alloc(sys: &SyscallTable) -> i32 {
    (sys.provider_open)(PLATFORM_DMA, dma_channel::ALLOC, core::ptr::null(), 0)
}

/// Start `ch` over `count` bytes of the bounce buffer lent on it, paced by
/// `dreq`.
unsafe fn dma_start(sys: &SyscallTable, ch: i32, count: u32, dreq: u8) -> i32 {
    let mut arg = abi::platform::rp::dma_raw::start::encode(BOUNCE_LEND, 0, count, dreq, DMA_FLAGS);
    (sys.provider_call)(
        ch,
        dma_channel::START,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

unsafe fn dma_abort(sys: &SyscallTable, ch: i32) {
    (sys.provider_call)(
        ch,
        dma_channel::ABORT,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn dma_busy(sys: &SyscallTable, ch: i32) -> bool {
    (sys.provider_call)(
        ch,
        dma_channel::BUSY,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    ) != 0
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
            if scr <= 255 {
                break;
            }
            prescaler += 2;
        }
        if scr > 255 {
            scr = 255;
        }
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

/// The bus's two DMA channels, allocated and given the bounce buffer as a
/// lend on first use. False while either cannot be had.
unsafe fn bus_channels(sys: &SyscallTable, bi: &mut BusInfo) -> bool {
    let bounce = bi.bounce.as_mut_ptr();
    for (ch, dir) in [(&mut bi.tx_ch, LEND_IN), (&mut bi.rx_ch, LEND_OUT)] {
        if *ch >= 0 {
            continue;
        }
        let h = dma_alloc(sys);
        if h < 0 {
            return false;
        }
        if dev_lend_open(sys, h, dir, BOUNCE_LEND, bounce, BOUNCE) < 0 {
            (sys.provider_call)(
                h,
                dma_channel::FREE,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            );
            return false;
        }
        *ch = h;
    }
    true
}

/// End handle `idx`'s transfer with `result`: the borrow goes back first,
/// and the bus's bounce buffer is free again.
unsafe fn end_transfer(s: &mut SpiState, idx: usize, result: i32) {
    let sys = &*s.syscalls;
    let tp = s.transfers.as_mut_ptr().add(idx);
    if !(*tp).span.is_null() {
        dev_lend_return(sys, (*tp).session, (*tp).lend);
        (*tp).span = core::ptr::null_mut();
    }
    (*tp).pending = 0;
    (*tp).active = 0;
    (*tp).result = result;
    let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
    if bus < MAX_BUSES {
        let bi = s.buses.as_mut_ptr().add(bus);
        if (*bi).busy == idx as i8 {
            (*bi).busy = -1;
        }
    }
}

/// Stage and start the next chunk of handle `idx`'s transfer.
unsafe fn start_chunk(s: &mut SpiState, idx: usize) {
    let sys = &*s.syscalls;
    let tp = s.transfers.as_mut_ptr().add(idx);
    let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
    let bi = &mut *s.buses.as_mut_ptr().add(bus);
    let n = ((*tp).len - (*tp).done).min(BOUNCE as u32);
    let at = (*tp).span.add((*tp).done as usize);
    if (*tp).dir & LEND_IN != 0 {
        core::ptr::copy_nonoverlapping(at, bi.bounce.as_mut_ptr(), n as usize);
    } else {
        core::ptr::write_bytes(bi.bounce.as_mut_ptr(), (*tp).fill, n as usize);
    }
    (*tp).chunk = n;
    // RX first, so it is ready when TX pushes data. In place: byte i is
    // received only after it has been sent.
    let rc = dma_start(sys, bi.rx_ch, n, bi.rx_dreq);
    let rc = if rc < 0 {
        rc
    } else {
        dma_start(sys, bi.tx_ch, n, bi.tx_dreq)
    };
    if rc < 0 {
        dma_abort(sys, bi.rx_ch);
        end_transfer(s, idx, rc);
        return;
    }
    (*tp).active = 1;
}

unsafe fn start_transfer(s: &mut SpiState, handle_idx: usize) {
    let sys = &*s.syscalls;
    let hp = s.handles.as_ptr().add(handle_idx);
    let tp = s.transfers.as_mut_ptr().add(handle_idx);
    let bus_id = (*hp).bus_id;
    let bi = &mut *s.buses.as_mut_ptr().add(bus_id as usize);
    if bi.busy >= 0 && bi.busy != handle_idx as i8 {
        return; // another handle's transfer holds the bus
    }

    // Configure bus for this handle's settings if changed
    if (*hp).freq_hz != bi.current_freq || (*hp).mode != bi.current_mode {
        configure_bus(sys, bus_id, (*hp).freq_hz, (*hp).mode);
        bi.current_freq = (*hp).freq_hz;
        bi.current_mode = (*hp).mode;
    }

    if (*tp).len == 0 {
        end_transfer(s, handle_idx, 1); // zero-length = immediate success
        return;
    }
    if !bus_channels(sys, bi) {
        end_transfer(s, handle_idx, -12); // ENOMEM
        return;
    }
    bi.busy = handle_idx as i8;
    (*tp).pending = 0;
    (*tp).done = 0;
    start_chunk(s, handle_idx);
}

unsafe fn poll_transfer(s: &mut SpiState, handle_idx: usize) {
    let sys = &*s.syscalls;
    let tp = s.transfers.as_mut_ptr().add(handle_idx);
    if (*tp).active == 0 {
        return;
    }
    let bus = (*s.handles.as_ptr().add(handle_idx)).bus_id as usize;
    let bi = &*s.buses.as_ptr().add(bus);
    if dma_busy(sys, bi.rx_ch) {
        return; // still running
    }
    // The chunk is in: what came back goes where the lend lets it.
    let n = (*tp).chunk as usize;
    if n > 0 {
        (*tp).last_rx = bi.bounce[n - 1];
    }
    if (*tp).dir & LEND_OUT != 0 {
        let at = (*tp).span.add((*tp).done as usize);
        core::ptr::copy_nonoverlapping(bi.bounce.as_ptr(), at, n);
    }
    (*tp).done += (*tp).chunk;
    (*tp).active = 0;
    if (*tp).done < (*tp).len {
        start_chunk(s, handle_idx);
        return;
    }
    let len = (*tp).len as i32;
    end_transfer(s, handle_idx, len);
}

// ============================================================================
// Provider dispatch (called by kernel when a consumer does provider_call
// on a HAL_SPI handle).
// ============================================================================

// Must match the HAL_SPI contract opcodes in abi::contracts::hal::spi.
const SPI_OPEN: u32 = abi::registry::spi::OPEN;
const SPI_CLOSE: u32 = abi::registry::spi::CLOSE;
const SPI_BEGIN: u32 = abi::registry::spi::BEGIN;
const SPI_END: u32 = abi::registry::spi::END;
const SPI_SET_CS: u32 = abi::registry::spi::SET_CS;
const SPI_CLAIM: u32 = abi::registry::spi::CLAIM;
const SPI_CONFIGURE: u32 = abi::registry::spi::CONFIGURE;
const SPI_TRANSFER_START: u32 = abi::registry::spi::TRANSFER_START;
const SPI_TRANSFER_POLL: u32 = abi::registry::spi::TRANSFER_POLL;
const SPI_POLL_BYTE: u32 = abi::registry::spi::POLL_BYTE;
const SPI_CAPS: u32 = abi::registry::spi::CAPS;
const SPI_DESCRIBE: u32 = abi::registry::spi::DESCRIBE;
/// Highest SCK the PL022 drives here: Fsys / 2, conservatively.
const MAX_FREQ_HZ: u32 = 75_000_000;

/// Resolve an incoming handle to a live slot index. Returns `Some(idx)`
/// only if the handle is in range AND the slot is currently in use.
/// Used by every per-handle opcode so stale handles (closed, or never
/// issued by SPI_OPEN but routed here via class-byte fallback) cannot
/// mutate bus state.
#[inline]
unsafe fn live_handle_idx(s: &SpiState, handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let idx = handle as usize;
    if idx >= MAX_HANDLES {
        return None;
    }
    if (*s.handles.as_ptr().add(idx)).in_use == 0 {
        return None;
    }
    Some(idx)
}

// Provider dispatch — called from kernel via registered function pointer.
// SAFETY: state is our SpiState, validated at registration time.
/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, and `arg` points to `arg_len` bytes
/// (may be null when `arg_len` is 0) valid for the call.
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn spi_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    _data: *mut u8,
    _data_len: usize,
) -> i32 {
    let s = &mut *(state as *mut SpiState);
    let sys = &*s.syscalls;

    match opcode {
        SPI_OPEN => {
            if arg.is_null() {
                return -22;
            }
            let Some(args) = spi_open::parse(core::slice::from_raw_parts(arg, arg_len)) else {
                return -22;
            };
            if args.bus as usize >= MAX_BUSES {
                return -22;
            }
            // The chip select is part of the claim: its pin is claimed here,
            // as an output held high (deasserted), and released on CLOSE.
            let cs = if args.cs_pin == spi_open::NO_CS {
                -1
            } else {
                let mut pin = [args.cs_pin];
                let h = (sys.provider_open)(
                    u32::from(abi::registry::gpio::ID),
                    hal_gpio::SET_OUTPUT,
                    pin.as_mut_ptr(),
                    1,
                );
                if h < 0 {
                    return h;
                }
                let mut high = [1u8];
                (sys.provider_call)(
                    h,
                    hal_gpio::SET_LEVEL,
                    high.as_mut_ptr(),
                    1,
                    core::ptr::null_mut(),
                    0,
                );
                h
            };

            // Find free handle
            let mut i = 0usize;
            while i < MAX_HANDLES {
                let idx = (s.next_handle as usize + i) % MAX_HANDLES;
                let hp = s.handles.as_mut_ptr().add(idx);
                if (*hp).in_use == 0 {
                    (*hp).in_use = 1;
                    (*hp).bus_id = args.bus;
                    (*hp).cs_handle = cs;
                    (*hp).freq_hz = args.freq_hz;
                    (*hp).mode = args.mode;
                    (*hp).owner = 0; // TODO: get caller module index
                    s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                    // Clear transfer state so nothing from a previous owner leaks.
                    let tp = s.transfers.as_mut_ptr().add(idx);
                    (*tp).span = core::ptr::null_mut();
                    (*tp).len = 0;
                    (*tp).fill = 0;
                    (*tp).pending = 0;
                    (*tp).active = 0;
                    (*tp).result = 0;
                    return idx as i32;
                }
                i += 1;
            }
            if cs >= 0 {
                (sys.provider_close)(cs);
            }
            -16 // EBUSY
        }
        SPI_CLOSE => {
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let hp = s.handles.as_mut_ptr().add(idx);
            // Abort any active transfer before its borrow goes back.
            let tp = s.transfers.as_ptr().add(idx);
            let bus = (*hp).bus_id as usize;
            if (*tp).active != 0 && bus < MAX_BUSES {
                let bi = &*s.buses.as_ptr().add(bus);
                dma_abort(sys, bi.tx_ch);
                dma_abort(sys, bi.rx_ch);
            }
            end_transfer(s, idx, 0);
            // Release the bus if this handle owned it.
            let bus = (*hp).bus_id as usize;
            if bus < MAX_BUSES {
                let bi = s.buses.as_mut_ptr().add(bus);
                if (*bi).bus_owner == idx as i8 {
                    (*bi).bus_owner = -1;
                }
            }
            if (*hp).cs_handle >= 0 {
                (sys.provider_close)((*hp).cs_handle);
                (*hp).cs_handle = -1;
            }
            (*hp).in_use = 0;
            0
        }
        SPI_CLAIM => {
            // Non-blocking try-claim. arg is a u32 timeout in ms that
            // callers use to pace their own retry loops; this dispatch
            // itself just attempts the claim once and returns.
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES {
                return -22;
            }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != idx as i8 {
                return -16; // EBUSY
            }
            (*bi).bus_owner = idx as i8;
            0
        }
        SPI_BEGIN => {
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES {
                return -22;
            }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner >= 0 && (*bi).bus_owner != idx as i8 {
                return -16; // EBUSY
            }
            (*bi).bus_owner = idx as i8;
            0
        }
        SPI_END => {
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let bus = (*s.handles.as_ptr().add(idx)).bus_id as usize;
            if bus >= MAX_BUSES {
                return -22;
            }
            let bi = s.buses.as_mut_ptr().add(bus);
            if (*bi).bus_owner == idx as i8 {
                (*bi).bus_owner = -1;
            }
            0
        }
        SPI_SET_CS => {
            // arg=[level:u8]
            if arg.is_null() || arg_len < 1 {
                return -22;
            }
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let cs = (*s.handles.as_ptr().add(idx)).cs_handle;
            if cs >= 0 {
                let mut buf = [*arg];
                (sys.provider_call)(
                    cs,
                    hal_gpio::SET_LEVEL,
                    buf.as_mut_ptr(),
                    1,
                    core::ptr::null_mut(),
                    0,
                );
            }
            0
        }
        SPI_CONFIGURE => {
            // arg=[freq:u32 LE, mode:u8] (5 bytes)
            if arg.is_null() || arg_len < 5 {
                return -22;
            }
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let hp = s.handles.as_mut_ptr().add(idx);
            (*hp).freq_hz = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*hp).mode = *arg.add(4);
            0
        }
        SPI_TRANSFER_START => {
            if arg.is_null() {
                return -22;
            }
            let Some((lend, offset, len, fill)) =
                transfer_start::decode(core::slice::from_raw_parts(arg, arg_len))
            else {
                return -22;
            };
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).pending != 0 || (*tp).active != 0 {
                return -16;
            }
            // The span is borrowed until the transfer ends.
            let Some((base, lent, dir)) = dev_lend_resolve(sys, handle, lend) else {
                return -2; // ENOENT
            };
            let end = (offset as usize).checked_add(len as usize);
            if end.is_none_or(|e| e > lent) {
                dev_lend_return(sys, handle, lend);
                return -22;
            }
            (*tp).span = base.add(offset as usize);
            (*tp).session = handle;
            (*tp).lend = lend;
            (*tp).dir = dir;
            (*tp).len = len;
            (*tp).fill = fill;
            (*tp).result = 0;
            (*tp).pending = 1;
            0
        }
        SPI_TRANSFER_POLL => {
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let tp = s.transfers.as_ptr().add(idx);
            if (*tp).pending != 0 {
                return 0;
            } // not started yet
            if (*tp).active != 0 {
                return 0;
            } // DMA in progress
            (*tp).result // >0 = done (byte count), <0 = error
        }
        SPI_POLL_BYTE => {
            // Byte-sized poll for single-byte transfers: returns
            //   0         = no byte available yet (still pending / active)
            //   0x100|b   = complete, b is the received byte
            //   < 0       = error
            let idx = match live_handle_idx(s, handle) {
                Some(i) => i,
                None => return -22,
            };
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).result < 0 {
                let r = (*tp).result;
                (*tp).result = 0;
                return r;
            }
            if (*tp).pending != 0 || (*tp).active != 0 {
                return 0;
            }
            if (*tp).result > 0 {
                let byte = (*tp).last_rx;
                (*tp).result = 0; // consume
                return 0x100 | byte as i32;
            }
            0
        }
        SPI_CAPS | SPI_DESCRIBE => {
            if arg.is_null() || arg_len != 4 {
                return -22;
            }
            // Every PL022 drives all four modes.
            use abi::contracts::hal::spi::caps;
            let word = if opcode == SPI_CAPS {
                caps::MODE0 | caps::MODE1 | caps::MODE2 | caps::MODE3
            } else {
                MAX_FREQ_HZ
            };
            let w = word.to_le_bytes();
            *arg = w[0];
            *arg.add(1) = w[1];
            *arg.add(2) = w[2];
            *arg.add(3) = w[3];
            0
        }
        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Module ABI
// ============================================================================

fluxor_rt::module_facts! { state: SpiState }

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
        if state_size < core::mem::size_of::<SpiState>() {
            return -2;
        }

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
            (*bi).bus_owner = -1;
            (*bi).busy = -1;
            (*bi).tx_ch = -1;
            (*bi).rx_ch = -1;
            if spi_bus_info(sys, bus, &mut *bi) {
                (*bi).initialized = 1;
            }
            bus += 1;
        }

        dev_log(sys, 3, b"[spi] ready".as_ptr(), 10);
        0
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
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
