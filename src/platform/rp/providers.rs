//! RP provider assembly for the kernel namespace.
//!
//! This module is only compiled for RP targets (via cfg in mod.rs).
//! It groups DMA ownership and provider dispatch concerns in
//! `platform/rp/providers.rs`.

use portable_atomic::{compiler_fence, AtomicU16, Ordering};

use crate::kernel::ipc::fd;
use crate::kernel::module::syscalls::{register_dev_query_extension, register_system_extension};
use crate::kernel::sys::errno;
use crate::platform::chip::PWM_BASE;
use crate::platform::rp_dma as dma;
use crate::platform::rp_gpio_regs as gpio_regs;
use crate::platform::rp_io::gpio;
use crate::platform::rp_pio_regs as pio_regs;
use crate::platform::rp_pio_regs::addr::SmReg;
use crate::platform::rp_regs::{read32, write32};

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;
const E_NOMEM: i32 = errno::ENOMEM;

// ============================================================================
// DMA channel allocation
// ============================================================================

/// Bitmap of allocated DMA channels. CH0-CH7 pre-marked at boot.
static DMA_CHANNELS_USED: AtomicU16 = AtomicU16::new(0x00FF); // CH0-CH7 reserved

/// Channels this silicon actually implements, as a mask.
///
/// RP2350 has 16 DMA channels and RP2040 has 12, so the allocatable set is
/// not the same on both. The previous literal `0xFF00` offered channels 8-15
/// unconditionally, which on RP2040 hands out 12-15 — registers that die does
/// not implement. Deriving the mask from the generated count makes the
/// difference a declared fact rather than something the allocator assumes.
const fn implemented_channel_mask() -> u16 {
    let n = crate::platform::chip::DMA_CHANNELS as u32;
    if n >= 16 {
        u16::MAX
    } else {
        ((1u32 << n) - 1) as u16
    }
}

pub(crate) fn dma_alloc_channel() -> i32 {
    loop {
        let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
        // `!used` alone would offer the reserved low channels back; masking
        // to implemented channels keeps the 0-7 reservation and drops any
        // channel this die lacks.
        let free_mask = !used & implemented_channel_mask() & 0xFF00;
        if free_mask == 0 {
            return E_NOMEM;
        }
        let ch = free_mask.trailing_zeros() as u16;
        let bit = 1u16 << ch;
        if DMA_CHANNELS_USED
            .compare_exchange(
                used,
                used | bit,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
        {
            return ch as i32;
        }
    }
}

pub(crate) fn dma_free_channel(ch: u8) -> i32 {
    if !(8..=15).contains(&ch) {
        return E_INVAL;
    }
    let bit = 1u16 << ch;
    DMA_CHANNELS_USED.fetch_and(!bit, core::sync::atomic::Ordering::Release);
    0
}

pub(crate) unsafe fn dma_start_raw(
    ch: u8,
    read_addr: u32,
    write_addr: u32,
    count: u32,
    dreq: u8,
    flags: u8,
) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
    if used & (1u16 << ch) == 0 {
        return E_INVAL;
    }

    let c = ch as usize;
    // SAFETY: `ch` is an implemented, allocated channel, so every address
    // below is inside this silicon's DMA block.
    unsafe {
        write32(chan(c, dma::addr::READ_ADDR), read_addr);
        write32(chan(c, dma::addr::WRITE_ADDR), write_addr);
        write32(chan(c, dma::addr::TRANS_COUNT), dma::trans_count(count));
        compiler_fence(Ordering::SeqCst);
        // CTRL_TRIG last: writing it starts the transfer.
        write32(chan(c, dma::addr::CTRL_TRIG), ctrl_for(ch, dreq, flags).0);
    }
    compiler_fence(Ordering::SeqCst);
    0
}

/// The shared `CTRL_TRIG` value for a channel configured from the syscall's
/// `flags` byte. One definition for the three call sites that build it.
fn ctrl_for(ch: u8, dreq: u8, flags: u8) -> dma::CtrlTrig {
    let data_size = if flags & 0x04 != 0 {
        dma::DataSize::Word
    } else {
        dma::DataSize::HalfWord
    };
    dma::CtrlTrig::default()
        .enable(true)
        .incr_read(flags & 0x01 != 0)
        .incr_write(flags & 0x02 != 0)
        .data_size(data_size)
        .treq_sel(dreq)
        .chain_to(ch)
}

/// Address of channel `ch`'s register at `reg`.
#[inline]
fn chan(ch: usize, reg: usize) -> usize {
    dma::addr::channel_reg(crate::platform::chip::DMA_BASE as usize, ch, reg)
}

fn dma_busy(ch: u8) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    // SAFETY: `ch` is implemented on this silicon.
    if channel_is_busy(ch) {
        1
    } else {
        0
    }
}

/// Whether a channel is mid-transfer.
fn channel_is_busy(ch: u8) -> bool {
    // SAFETY: callers check `is_implemented` first.
    dma::CtrlTrig(unsafe { read32(chan(ch as usize, dma::addr::CTRL_TRIG)) }).busy()
}

pub(crate) fn dma_abort(ch: u8) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    // Bounded: the previous spin on BUSY never gave up, so a channel that did
    // not acknowledge the abort hung whoever asked.
    if dma::abort(ch, DMA_ABORT_LIMIT) {
        0
    } else {
        crate::kernel::sys::errno::ERROR
    }
}

/// Spin budget for a channel to acknowledge an abort, in poll iterations.
const DMA_ABORT_LIMIT: u32 = 100_000;

pub(crate) unsafe fn dma_restart_raw(ch: u8, read_addr: u32, count: u32) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    let c = ch as usize;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `ch` is implemented. AL3_READ_ADDR_TRIG is written last because
    // writing it re-triggers the channel.
    unsafe {
        write32(chan(c, dma::addr::AL3_TRANS_COUNT), dma::trans_count(count));
        write32(chan(c, dma::addr::AL3_READ_ADDR_TRIG), read_addr);
    }
    compiler_fence(Ordering::SeqCst);
    0
}

// ============================================================================
// DMA FD operations (ping-pong DMA channels as fd)
// ============================================================================

use portable_atomic::AtomicBool;
use portable_atomic::AtomicU8;

const MAX_DMA_FDS: usize = 8;

struct DmaFdSlot {
    allocated: AtomicBool,
    owner: AtomicU8,
    channel_a: AtomicU8,
    channel_b: AtomicU8,
    active_is_b: AtomicBool,
    pending: AtomicBool,
}

impl DmaFdSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            owner: AtomicU8::new(0xFF),
            channel_a: AtomicU8::new(0xFF),
            channel_b: AtomicU8::new(0xFF),
            active_is_b: AtomicBool::new(false),
            pending: AtomicBool::new(false),
        }
    }

    fn active_ch(&self) -> u8 {
        if self.active_is_b.load(Ordering::Acquire) {
            self.channel_b.load(Ordering::Acquire)
        } else {
            self.channel_a.load(Ordering::Acquire)
        }
    }

    fn inactive_ch(&self) -> u8 {
        if self.active_is_b.load(Ordering::Acquire) {
            self.channel_a.load(Ordering::Acquire)
        } else {
            self.channel_b.load(Ordering::Acquire)
        }
    }
}

static DMA_FD_SLOTS: [DmaFdSlot; MAX_DMA_FDS] = [const { DmaFdSlot::new() }; MAX_DMA_FDS];

pub fn dma_fd_create() -> i32 {
    let ch_a = dma_alloc_channel();
    if ch_a < 0 {
        return ch_a;
    }
    let ch_b = dma_alloc_channel();
    if ch_b < 0 {
        dma_free_channel(ch_a as u8);
        return ch_b;
    }
    let owner = crate::kernel::exec::scheduler::current_module_index() as u8;
    for (i, dma) in DMA_FD_SLOTS.iter().enumerate() {
        if dma
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            dma.owner.store(owner, Ordering::Release);
            dma.channel_a.store(ch_a as u8, Ordering::Release);
            dma.channel_b.store(ch_b as u8, Ordering::Release);
            dma.active_is_b.store(false, Ordering::Release);
            dma.pending.store(false, Ordering::Release);
            return fd::tag_fd(fd::FD_TAG_DMA, i as i32);
        }
    }
    dma_free_channel(ch_a as u8);
    dma_free_channel(ch_b as u8);
    errno::ENOMEM
}

pub fn dma_fd_start(
    fd_handle: i32,
    read_addr: u32,
    write_addr: u32,
    count: u32,
    dreq: u8,
    flags: u8,
) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return E_INVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return E_INVAL;
    }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    // SAFETY: ch_a is allocated to this fd_handle; dma_start_raw programs the
    // DMA registers for an allocated channel only.
    let rc = unsafe { dma_start_raw(ch_a, read_addr, write_addr, count, dreq, flags) };
    if rc < 0 {
        return rc;
    }
    // SAFETY: ch_b is allocated to the same fd_handle (ping-pong pair); it is
    // not currently running until dma_fd_queue chains to it.
    unsafe {
        dma_preconfigure_inactive(ch_b, write_addr, dreq, flags);
    }
    dma.active_is_b.store(false, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    rc
}

unsafe fn dma_preconfigure_inactive(ch: u8, write_addr: u32, dreq: u8, flags: u8) {
    let c = ch as usize;
    // AL1_CTRL, not CTRL_TRIG: this channel must be configured without being
    // started, since the point is for the active channel to chain into it.
    //
    // SAFETY: the caller's contract is that `ch` is an allocated channel of
    // this fd's ping-pong pair, so both addresses are inside this silicon's
    // DMA block and no other owner is writing them.
    unsafe {
        write32(chan(c, dma::addr::WRITE_ADDR), write_addr);
        write32(chan(c, dma::addr::AL1_CTRL), ctrl_for(ch, dreq, flags).0);
    }
}

pub fn dma_fd_queue(fd_handle: i32, read_addr: u32, count: u32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return E_INVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return E_INVAL;
    }
    let active = dma.active_ch();
    let inactive = dma.inactive_ch();
    {
        let (a, i) = (active as usize, inactive as usize);
        // SAFETY: both channels belong to this fd's allocated ping-pong pair,
        // so both are implemented and owned here.
        unsafe {
            write32(chan(i, dma::addr::READ_ADDR), read_addr);
            write32(chan(i, dma::addr::TRANS_COUNT), dma::trans_count(count));
            compiler_fence(Ordering::SeqCst);
            // Point the running channel at the one just loaded, editing
            // through AL1_CTRL so the edit does not itself re-trigger it.
            let ctrl = dma::CtrlTrig(read32(chan(a, dma::addr::AL1_CTRL)));
            write32(chan(a, dma::addr::AL1_CTRL), ctrl.chain_to(inactive).0);
            compiler_fence(Ordering::SeqCst);
            if !channel_is_busy(active) {
                // The active channel finished before the chain was armed, so
                // nothing will follow it; start the loaded channel directly.
                write32(chan(i, dma::addr::AL3_TRANS_COUNT), dma::trans_count(count));
                write32(chan(i, dma::addr::AL3_READ_ADDR_TRIG), read_addr);
                write32(chan(a, dma::addr::AL1_CTRL), ctrl.chain_to(active).0);
                dma.active_is_b
                    .store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
            }
        }
    }
    dma.pending.store(true, Ordering::Release);
    0
}

pub fn dma_fd_restart(fd_handle: i32, read_addr: u32, count: u32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return E_INVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return E_INVAL;
    }
    let ch = dma.active_ch();
    // SAFETY: `ch` is the dma_fd's allocated active channel.
    unsafe { dma_restart_raw(ch, read_addr, count) }
}

pub fn dma_fd_free(fd_handle: i32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return E_INVAL;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return E_INVAL;
    }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    dma_abort(ch_a);
    dma_abort(ch_b);
    dma_free_channel(ch_a);
    dma_free_channel(ch_b);
    dma.channel_a.store(0xFF, Ordering::Release);
    dma.channel_b.store(0xFF, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    dma.active_is_b.store(false, Ordering::Release);
    dma.owner.store(0xFF, Ordering::Release);
    dma.allocated.store(false, Ordering::Release);
    0
}

fn dma_fd_poll_ready(slot: i32) -> bool {
    if slot < 0 || slot as usize >= MAX_DMA_FDS {
        return false;
    }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) {
        return false;
    }
    let active = dma.active_ch();
    if channel_is_busy(active) {
        return false;
    }
    if dma.pending.load(Ordering::Acquire) {
        let a = active as usize;
        // SAFETY: `active` is this fd's allocated channel.
        unsafe {
            let ctrl = dma::CtrlTrig(read32(chan(a, dma::addr::AL1_CTRL)));
            write32(chan(a, dma::addr::AL1_CTRL), ctrl.chain_to(active).0);
        }
        dma.active_is_b
            .store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        dma.pending.store(false, Ordering::Release);
    }
    true
}

pub fn release_dma_fds_owned_by(module_idx: u8) {
    for dma in DMA_FD_SLOTS.iter() {
        if !dma.allocated.load(Ordering::Acquire) {
            continue;
        }
        if dma.owner.load(Ordering::Acquire) != module_idx {
            continue;
        }
        let ch_a = dma.channel_a.load(Ordering::Acquire);
        let ch_b = dma.channel_b.load(Ordering::Acquire);
        if ch_a != 0xFF {
            dma_abort(ch_a);
            dma_free_channel(ch_a);
        }
        if ch_b != 0xFF {
            dma_abort(ch_b);
            dma_free_channel(ch_b);
        }
        dma.channel_a.store(0xFF, Ordering::Release);
        dma.channel_b.store(0xFF, Ordering::Release);
        dma.pending.store(false, Ordering::Release);
        dma.active_is_b.store(false, Ordering::Release);
        dma.owner.store(0xFF, Ordering::Release);
        dma.allocated.store(false, Ordering::Release);
    }
}

// ============================================================================
// RP provider dispatch and registration
// ============================================================================

// ============================================================================
// Public API
// ============================================================================

pub fn init() {
    init_rp_providers();
    // Register DMA FD poll function with the fd subsystem
    fd::register_dma_fd_poll(dma_fd_poll_ready);
    // Register provider_query extension for GPIO and SYS_CLOCK_HZ
    register_dev_query_extension(rp_dev_query_extension);
}

pub fn release_handles(module_idx: u8) {
    release_rp_handles(module_idx);
    release_dma_fds_owned_by(module_idx);
}

// RP-family hardware providers for the syscall system.
//
// This file is compiled as `src/platform/rp/providers.rs`
// under `#[cfg(feature = "rp")]`.
// All symbols share the `syscalls` module namespace — they can reference E_NOSYS,
// channel::*, gpio::*, etc. directly.
//
// SPI, I2C, UART, and ADC providers live in PIC modules; the loader
// auto-registers them after module_new() via the
// `module_provides_contract` export. The raw register bridges they
// call into remain in `rp_system_extension_dispatch` below.

use crate::platform::rp_io::pio as pio_util;

/// Check if a GPIO pin has been claimed
pub fn is_gpio_registered(pin_num: u8) -> bool {
    gpio::gpio_is_claimed(pin_num)
}

/// Convenience syscall: claim + configure as output
/// Returns handle on success, <0 on error
///
/// # Safety
/// `extern "C"` syscall ABI shim invoked by PIC modules. Takes no
/// pointers; marked `unsafe` only to match the syscall-table signature.
/// All side effects route through the GPIO submodule's own checked
/// claim/release/set_mode paths.
pub unsafe extern "C" fn syscall_gpio_request_output(pin_num: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        log::error!("[gpio] request_output pin {pin_num} claim failed rc={handle}");
        return handle;
    }
    gpio::gpio_set_owner(
        pin_num,
        crate::kernel::exec::scheduler::current_module_index() as u8,
    );
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Output, true);
    if result < 0 {
        log::error!("[gpio] request_output pin {pin_num} set_mode failed rc={result}");
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// Convenience syscall: claim + configure as input with pull
/// pull: 0=none, 1=up, 2=down
/// Returns handle on success, <0 on error
///
/// BOOTSEL is a separate capability — use the `flash_rp` driver,
/// not a synthetic GPIO pin. This entry point handles real GPIO
/// pins only.
///
/// # Safety
/// `extern "C"` syscall ABI shim invoked by PIC modules. Takes no
/// pointers; marked `unsafe` only to match the syscall-table signature.
pub unsafe extern "C" fn syscall_gpio_request_input(pin_num: u8, pull: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        return handle;
    }
    gpio::gpio_set_owner(
        pin_num,
        crate::kernel::exec::scheduler::current_module_index() as u8,
    );
    // Set pull configuration
    let pin_pull = match pull {
        1 => gpio::PinPull::Up,
        2 => gpio::PinPull::Down,
        _ => gpio::PinPull::None,
    };
    gpio::gpio_set_pull(handle, pin_pull);
    // Configure as input
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Input, false);
    if result < 0 {
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// GPIO get level wrapper.
unsafe extern "C" fn syscall_gpio_get_level(handle: i32) -> i32 {
    if !gpio::gpio_check_owner(handle) {
        return E_INVAL;
    }
    gpio::gpio_get_level(handle)
}

// ============================================================================
// Per-class provider dispatchers (RP-specific)
// ============================================================================

unsafe fn gpio_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::contracts::hal::gpio as dev_gpio;
    // Strip FD_TAG_HAL_GPIO so the inner ops see a raw pin number.
    // No-op on the -1 sentinel for open-style opcodes.
    let handle = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    match opcode {
        dev_gpio::CLAIM => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let result = gpio::syscall_gpio_claim(*arg);
            if result >= 0 {
                gpio::gpio_set_owner(
                    *arg,
                    crate::kernel::exec::scheduler::current_module_index() as u8,
                );
            }
            result
        }
        dev_gpio::SET_OUTPUT => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            syscall_gpio_request_output(*arg)
        }
        dev_gpio::SET_INPUT => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            syscall_gpio_request_input(*arg, *arg.add(1))
        }
        dev_gpio::RELEASE => {
            if !gpio::gpio_check_owner(handle) {
                return E_INVAL;
            }
            gpio::syscall_gpio_release(handle)
        }
        dev_gpio::SET_MODE => {
            if !gpio::gpio_check_owner(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            gpio::syscall_gpio_set_mode(handle, *arg, *arg.add(1))
        }
        dev_gpio::SET_PULL => {
            if !gpio::gpio_check_owner(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            gpio::syscall_gpio_set_pull(handle, *arg)
        }
        dev_gpio::SET_LEVEL => {
            if !gpio::gpio_check_owner(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            gpio::syscall_gpio_set_level(handle, *arg)
        }
        dev_gpio::GET_LEVEL => syscall_gpio_get_level(handle),
        dev_gpio::WATCH_EDGE => {
            if !gpio::gpio_check_owner(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let edge = *arg;
            let evt = i32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            gpio::gpio_watch_edge(handle as u8, edge, evt)
        }
        _ => E_NOSYS,
    }
}

// PIO provider dispatch removed — PIC pio_stream module handles PIO via register bridges.

// ============================================================================
// Raw PAC GPIO 9-bit SPI bit-bang (for display register init)
// ============================================================================

/// Set a pin as SIO output with initial level.
unsafe fn spi9_gpio_init(pin: u8, high: bool) {
    use crate::platform::rp_gpio_regs as gpio_regs;

    // SAFETY: the caller owns `pin` for the duration of the bit-banged
    // transfer. Level before output-enable, so the pin never briefly drives
    // the wrong value at the display.
    unsafe {
        gpio_regs::set_function(pin, SPI9_FUNCSEL_SIO);
        gpio_regs::set_pad_output(pin, gpio_regs::Drive::Ma4);
        gpio_regs::set_level(pin, high);
        gpio_regs::set_output_enable(pin, true);
    }
}

/// IO_BANK0 `FUNCSEL` for software control of a pin (SIO).
const SPI9_FUNCSEL_SIO: u32 = 5;

/// `FUNCSEL` for the PWM peripheral.
const PWM_FUNCSEL: u32 = 4;

/// `FUNCSEL` 31 is "no peripheral", which releases the pin.
const FUNCSEL_NONE: u32 = 31;

/// `OUT X, 32` — consume a FIFO word into the X scratch register.
const PIO_OUT_X_32: u32 = 0x6020;
/// `OUT Y, 32`.
const PIO_OUT_Y_32: u32 = 0x6040;
/// `SET PINDIRS, 1` — drive the pin.
const PIO_SET_PINDIRS_1: u32 = 0xE081;

/// Longest a single gSPI transfer may run before `CMD_POLL` gives up on it.
///
/// A full frame at the slowest configured clock is well under a
/// millisecond; this is two orders of magnitude clear of that, so it only
/// fires for a transfer that has genuinely stopped.
const XFER_LIMIT_US: u64 = 50_000;

/// When each channel's current transfer started, for the timeout.
static mut XFER_STARTED_US: [u64; 16] = [0; 16];

fn xfer_note_started(ch: u8) {
    if (ch as usize) < 16 {
        // SAFETY: single writer, the syscall path, on a single core.
        unsafe { XFER_STARTED_US[ch as usize] = crate::platform::rp_timer::now_us() };
    }
}

fn xfer_elapsed_us(ch: u8) -> u64 {
    if (ch as usize) >= 16 {
        return 0;
    }
    // SAFETY: as `xfer_note_started`.
    let t0 = unsafe { XFER_STARTED_US[ch as usize] };
    crate::platform::rp_timer::now_us().wrapping_sub(t0)
}

/// Set bits in a register that has no atomic alias.
///
/// # Safety
/// As [`crate::platform::rp_regs::modify32`]: the register must not be
/// write-one-to-clear.
#[inline]
unsafe fn set_bits_rmw(addr: usize, bits: u32) {
    // SAFETY: the caller's contract — a plain read/write register it owns.
    unsafe { crate::platform::rp_regs::modify32(addr, |v| v | bits) };
}

/// Set a SIO output pin level.
#[inline(always)]
unsafe fn spi9_pin_set(pin: u8, high: bool) {
    // SAFETY: as `spi9_gpio_init`; the pin is already configured as an output.
    unsafe { crate::platform::rp_gpio_regs::set_level(pin, high) };
}

/// Busy-wait for `us` microseconds using the RP hardware TIMER.
#[inline(always)]
unsafe fn spi9_timer_us(us: u32) {
    // The monotonic clock, not a private read of the timer block: one source
    // for every timestamp in the kernel, so this cannot drift from what the
    // scheduler believes the time is.
    let t0 = crate::platform::rp_timer::now_us();
    while crate::platform::rp_timer::now_us().wrapping_sub(t0) < us as u64 {}
}

/// Busy-wait ~100 us using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay() {
    spi9_timer_us(100);
}

/// Busy-wait ~N ms using hardware TIMER.
#[inline(always)]
unsafe fn spi9_pac_delay_ms(ms: u32) {
    spi9_timer_us(ms * 1000);
}

/// Send one 9-bit SPI word. Clock idle low, data on rising edge, MSB first.
unsafe fn spi9_pac_write_word(sck: u8, sda: u8, word: u16) {
    for i in (0..=8i32).rev() {
        spi9_pin_set(sda, (word & (1u16 << i as u32)) != 0);
        spi9_timer_us(10); // Data setup time before rising edge
        spi9_pin_set(sck, true);
        spi9_pac_delay(); // 100 us SCK high time
        spi9_pin_set(sck, false);
        spi9_pac_delay(); // 100 us SCK low time
    }
}

/// Send 9-bit SPI command + data bytes, CS-framed.
unsafe fn spi9_pac_send(
    cs: u8,
    sck: u8,
    sda: u8,
    cmd: u8,
    data: *const u8,
    data_len: usize,
    hold_cs: bool,
) {
    spi9_pin_set(cs, false);
    spi9_timer_us(5); // CS setup time before first clock
    spi9_pac_write_word(sck, sda, cmd as u16); // DC=0 for command
    for i in 0..data_len {
        spi9_pac_write_word(sck, sda, 0x0100 | *data.add(i) as u16); // DC=1 for data
    }
    if !hold_cs {
        spi9_timer_us(5); // CS hold time after last clock
        spi9_pin_set(cs, true);
    }
}

/// Reset sequence + SIO pin init for 9-bit SPI.
unsafe fn spi9_pac_reset(rst: u8, cs: u8, sck: u8, sda: u8) {
    spi9_gpio_init(cs, true);
    spi9_gpio_init(sck, false);
    spi9_gpio_init(sda, false);
    spi9_gpio_init(rst, true);

    spi9_pin_set(rst, true);
    spi9_pac_delay_ms(20);
    spi9_pin_set(rst, false);
    spi9_pac_delay_ms(20);
    spi9_pin_set(rst, true);
    spi9_pac_delay_ms(200);
}

// ============================================================================
// RP System Extension Dispatch
// ============================================================================
//
// Handles hardware-specific system opcodes (PWM, PIO registers, DMA, SPI9)
// delegated from system_provider_dispatch's catch-all arm.

/// Handle-family discriminators for `PLATFORM_DMA` (channel number
/// tagged with FD_TAG_DMA_CHANNEL, from `channel::ALLOC`) and
/// `PLATFORM_DMA_FD` (FD_TAG_DMA-tagged fd, from `fd::CREATE`).
/// The two families have disjoint tag values; handlers reject a
/// wrong-family handle with EINVAL. A raw untagged slot (tag 0) is
/// accepted from callers that bypass `provider_open`.
#[inline]
fn is_dma_channel_handle(h: i32) -> bool {
    if h < 0 {
        return false;
    }
    let (tag, _slot) = crate::kernel::ipc::fd::untag_fd(h);
    tag == crate::kernel::ipc::fd::FD_TAG_DMA_CHANNEL || tag == 0
}

#[inline]
fn is_dma_fd_handle(h: i32) -> bool {
    if h < 0 {
        return false;
    }
    let (tag, _slot) = crate::kernel::ipc::fd::untag_fd(h);
    tag == crate::kernel::ipc::fd::FD_TAG_DMA
}

unsafe fn rp_system_extension_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use crate::abi::contracts::storage::runtime_params;
    use crate::abi::internal::flash;
    use crate::abi::internal::provider_registry::FLASH_STORE_ENABLE;
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::abi::platform::rp::{
        adc_raw, dma_raw, i2c_raw, pio_raw, pwm_raw, spi9_raw, spi_raw, uart_raw,
    };
    match opcode {
        // ── Raw PWM register bridge ─────────────────────────────────
        pwm_raw::PIN_ENABLE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize {
                return E_INVAL;
            }
            // SAFETY: `pin` is bounded by the runtime GPIO count above.
            unsafe {
                gpio_regs::set_function(pin as u8, PWM_FUNCSEL);
                gpio_regs::set_pad_output(pin as u8, gpio_regs::Drive::Ma4);
            }
            0
        }
        pwm_raw::PIN_DISABLE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let pin = *arg as usize;
            if pin >= gpio::runtime_max_gpio() as usize {
                return E_INVAL;
            }
            // SAFETY: as PIN_ENABLE.
            unsafe { gpio_regs::set_function(pin as u8, FUNCSEL_NONE) };
            0
        }
        pwm_raw::SLICE_WRITE => {
            if arg.is_null() || arg_len < 6 {
                return E_INVAL;
            }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            if slice >= crate::platform::chip::PWM_SLICES as usize {
                return E_INVAL;
            }
            let Some(addr) = gpio_regs::pwm::reg(PWM_BASE as usize, slice, reg) else {
                return E_INVAL;
            };
            // SAFETY: `slice` is below this silicon's slice count and `reg` is
            // one of the five the block defines, so the address is inside it.
            unsafe { write32(addr, value) };
            0
        }
        pwm_raw::SLICE_READ => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let slice = *arg as usize;
            let reg = *arg.add(1);
            if slice >= crate::platform::chip::PWM_SLICES as usize {
                return E_INVAL;
            }
            let Some(addr) = gpio_regs::pwm::reg(PWM_BASE as usize, slice, reg) else {
                return E_INVAL;
            };
            // SAFETY: as SLICE_WRITE.
            unsafe { read32(addr) as i32 }
        }
        // ── Raw PIO register bridge ───────────────────────────────────
        pio_raw::SM_EXEC => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let sm = *arg.add(1);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            if !pio_regs::is_state_machine(sm) {
                return E_INVAL;
            }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            // SAFETY: `base` is an implemented instance and `sm` a real
            // state machine, both checked above.
            unsafe { pio_regs::write_sm_reg(base, sm, SmReg::Instr, instr as u32) };
            0
        }
        pio_raw::SM_WRITE_REG => {
            if arg.is_null() || arg_len < 7 {
                return E_INVAL;
            }
            let sm_idx = *arg.add(1);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            if !pio_regs::is_state_machine(sm_idx) {
                return E_INVAL;
            }
            // ADDR is read-only, so it is not writable even though
            // SM_READ_REG names it.
            let reg = match SmReg::from_syscall(*arg.add(2)) {
                Some(SmReg::Addr) | None => return E_INVAL,
                Some(r) => r,
            };
            let value = u32::from_le_bytes([*arg.add(3), *arg.add(4), *arg.add(5), *arg.add(6)]);
            // SAFETY: checked instance and state machine, as SM_EXEC.
            unsafe { pio_regs::write_sm_reg(base, sm_idx, reg, value) };
            0
        }
        pio_raw::SM_READ_REG => {
            if arg.is_null() || arg_len < 3 {
                return E_INVAL;
            }
            let sm_idx = *arg.add(1);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            if !pio_regs::is_state_machine(sm_idx) {
                return E_INVAL;
            }
            let Some(reg) = SmReg::from_syscall(*arg.add(2)) else {
                return E_INVAL;
            };
            // SAFETY: checked instance and state machine, as SM_EXEC.
            unsafe { pio_regs::read_sm_reg(base, sm_idx, reg) as i32 }
        }
        pio_raw::SM_ENABLE => {
            if arg.is_null() || arg_len < 3 {
                return E_INVAL;
            }
            let mask = *arg.add(1) & 0x0F;
            let enable = *arg.add(2);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { pio_regs::set_enabled(base, mask, enable != 0) };
            0
        }
        pio_raw::INSTR_ALLOC => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let pio_num = *arg;
            let count = *arg.add(1);
            if pio_regs::instance(pio_num).is_none() || count == 0 || count > 32 {
                return E_INVAL;
            }
            match pio_util::alloc_instruction_slots(pio_num, count as usize) {
                Some((origin, mask)) => {
                    // Write mask back to arg[2..6] so caller can free later
                    if arg_len >= 6 {
                        let mask_bytes = mask.to_le_bytes();
                        *arg.add(2) = mask_bytes[0];
                        *arg.add(3) = mask_bytes[1];
                        *arg.add(4) = mask_bytes[2];
                        *arg.add(5) = mask_bytes[3];
                    }
                    origin as i32
                }
                None => E_NOMEM,
            }
        }
        pio_raw::INSTR_WRITE => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let slot = *arg.add(1);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            if !pio_regs::is_instr_slot(slot) {
                return E_INVAL;
            }
            let instr = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
            // SAFETY: checked instance and instruction slot.
            unsafe { write32(pio_regs::addr::instr_mem(base, slot as usize), instr as u32) };
            0
        }
        pio_raw::INSTR_FREE => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let pio_num = *arg;
            if pio_regs::instance(pio_num).is_none() {
                return E_INVAL;
            }
            let mask = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            pio_util::free_instruction_slots(pio_num, mask);
            0
        }
        pio_raw::PIN_SETUP => {
            if arg.is_null() || arg_len < 3 {
                return E_INVAL;
            }
            let pin = *arg;
            let pio_num = *arg.add(1);
            let pull = *arg.add(2);
            if pio_regs::instance(pio_num).is_none()
                || pin as usize >= gpio::runtime_max_gpio() as usize
            {
                return E_INVAL;
            }
            let pio_pull = match pull {
                0 => pio_util::PioPull::None,
                1 => pio_util::PioPull::PullDown,
                2 => pio_util::PioPull::PullUp,
                _ => return E_INVAL,
            };
            pio_util::setup_pio_pin(pin, pio_num, pio_pull);
            0
        }
        pio_raw::PIN_LEVEL => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let pin = *arg;
            if pin as usize >= gpio::runtime_max_gpio() as usize {
                return E_INVAL;
            }
            // SAFETY: a pin the caller set up for PIO; the pad's input
            // buffer is enabled by that setup, so the level is real.
            i32::from(unsafe { gpio_regs::read_level(pin) })
        }
        pio_raw::GPIOBASE => {
            // PIO GPIOBASE: RP2350 only (register absent on RP2040 PAC)
            #[cfg(not(feature = "chip-rp2040"))]
            {
                if arg.is_null() || arg_len < 2 {
                    return E_INVAL;
                }
                let base16 = *arg.add(1);
                let Some(base) = pio_regs::instance(*arg) else {
                    return E_INVAL;
                };
                // SAFETY: `base` is an implemented instance, and GPIOBASE
                // exists on this silicon (the cfg around this arm).
                unsafe { write32(base + pio_regs::addr::GPIOBASE, u32::from(base16 != 0)) };
                0
            }
            #[cfg(feature = "chip-rp2040")]
            {
                E_NOSYS
            }
        }
        pio_raw::TXF_WRITE => {
            if arg.is_null() || arg_len < 6 {
                return E_INVAL;
            }
            let sm = *arg.add(1);
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            if !pio_regs::is_state_machine(sm) {
                return E_INVAL;
            }
            let value = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            // SAFETY: checked instance and state machine.
            unsafe { write32(pio_regs::addr::txf(base, sm as usize), value) };
            0
        }
        pio_raw::FSTAT_READ => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { read32(base + pio_regs::addr::FSTAT) as i32 }
        }
        pio_raw::SM_RESTART => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let mask = *arg.add(1) & 0x0F;
            let Some(base) = pio_regs::instance(*arg) else {
                return E_INVAL;
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { pio_regs::restart(base, mask) };
            0
        }
        pio_raw::INPUT_SYNC_BYPASS => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let pio_num = *arg;
            if pio_regs::instance(pio_num).is_none() {
                return E_INVAL;
            }
            let mask = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            let Some(base) = pio_regs::instance(pio_num) else {
                return E_INVAL;
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { set_bits_rmw(base + pio_regs::addr::INPUT_SYNC_BYPASS, mask) };
            0
        }
        pio_raw::CMD_TRANSFER => {
            // Atomic PIO cmd transfer: setup SM + DMA in one call (no syscall latency between steps)
            // arg layout (28 bytes):
            //   [0] pio_num, [1] sm_num, [2] origin, [3] reserved
            //   [4..8] write_bits (u32 LE), [8..12] read_bits (u32 LE)
            //   [12..16] tx_addr (u32 LE), [16..20] tx_words (u32 LE)
            //   [20..24] rx_addr (u32 LE), [24] dma_ch_tx, [25] dma_ch_rx, [26..28] reserved
            if arg.is_null() || arg_len < 28 {
                return E_INVAL;
            }
            let pio_num = *arg;
            let sm_num = *arg.add(1) as usize;
            let origin = *arg.add(2);
            if pio_regs::instance(pio_num).is_none() || sm_num >= pio_regs::STATE_MACHINES {
                return E_INVAL;
            }

            let write_bits =
                u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let read_bits =
                u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let tx_addr =
                u32::from_le_bytes([*arg.add(12), *arg.add(13), *arg.add(14), *arg.add(15)]);
            let tx_words =
                u32::from_le_bytes([*arg.add(16), *arg.add(17), *arg.add(18), *arg.add(19)]);
            let rx_addr =
                u32::from_le_bytes([*arg.add(20), *arg.add(21), *arg.add(22), *arg.add(23)]);
            let ch_tx = *arg.add(24);
            let _ch_rx = *arg.add(25);

            // Checked above; `sm_num` is a real state machine.
            let Some(base) = pio_regs::instance(pio_num) else {
                return E_INVAL;
            };
            let sm = sm_num as u8;
            let sm_mask = 1u8 << sm_num;

            // SAFETY: checked instance and state machine throughout this
            // block; `origin` is an instruction-memory address the caller
            // obtained from INSTR_ALLOC.
            let (txf_addr, rxf_addr) = unsafe {
                pio_regs::set_enabled(base, sm_mask, false);

                // Seed X with write_bits, then Y with read_bits, by pushing
                // each through the TX FIFO and forcing an OUT that consumes
                // it. The delays let the forced instruction retire before
                // the next is written.
                write32(pio_regs::addr::txf(base, sm_num), write_bits);
                pio_regs::write_sm_reg(base, sm, SmReg::Instr, PIO_OUT_X_32);
                crate::arch::cortex_m::delay(10);

                write32(pio_regs::addr::txf(base, sm_num), read_bits);
                pio_regs::write_sm_reg(base, sm, SmReg::Instr, PIO_OUT_Y_32);
                crate::arch::cortex_m::delay(10);

                // Drive the pin for the TX phase, then jump to the program.
                pio_regs::write_sm_reg(base, sm, SmReg::Instr, PIO_SET_PINDIRS_1);
                crate::arch::cortex_m::delay(10);

                pio_regs::write_sm_reg(base, sm, SmReg::Instr, origin as u32);
                crate::arch::cortex_m::delay(10);

                compiler_fence(Ordering::SeqCst);

                let txf = pio_regs::addr::txf(base, sm_num) as u32;
                let rxf = pio_regs::addr::rxf(base, sm_num) as u32;

                // Enable the state machine before DMA so the PIO FIFOs drain
                // as transfers land.
                pio_regs::set_enabled(base, sm_mask, true);
                (txf, rxf)
            };

            let tx_dreq = (pio_num << 3) + sm_num as u8;
            let rx_dreq = tx_dreq + 4;

            compiler_fence(Ordering::SeqCst);

            // Sequential TX then RX on a single DMA channel. RX must run
            // even for write-only transactions — the PIO program expects
            // the full TX→RX cycle to complete.
            let rx_words = if read_bits > 0 {
                (read_bits + 1).div_ceil(32)
            } else {
                1
            };

            // Both directions at once, on their own channels, and return.
            //
            // The transfer used to run to completion inside this call: TX,
            // spin, RX, spin. At 25 MHz a full gSPI frame is half a
            // millisecond of the core doing nothing, and the module calling
            // this does several per step during association — steps of
            // 1-1.6 ms, over the scheduler's budget at the default tick.
            // The caller already has the shape for waiting (its
            // `TxnStep::WaitPio`); this makes the wait real. RX is armed
            // first so its DREQ is watching the FIFO before TX fills it.
            let ch_rx = _ch_rx;
            crate::platform::rp_providers::dma_start_raw(
                ch_rx, rxf_addr, rx_addr, rx_words, rx_dreq, 0x06,
            );
            compiler_fence(Ordering::SeqCst);
            if tx_words > 0 {
                crate::platform::rp_providers::dma_start_raw(
                    ch_tx, tx_addr, txf_addr, tx_words, tx_dreq, 0x05,
                );
                compiler_fence(Ordering::SeqCst);
            }
            xfer_note_started(ch_tx);
            0
        }
        pio_raw::CMD_POLL => {
            // Completion of a transfer started above: `arg` is the two
            // channel numbers. 1 while either is still moving, 0 when both
            // have stopped. A transfer that has run longer than any frame
            // can take is aborted and reported, rather than polled for ever
            // by a caller that has no other way to know.
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let ch_tx = *arg;
            let ch_rx = *arg.add(1);
            let busy = dma_busy(ch_tx) == 1 || dma_busy(ch_rx) == 1;
            if !busy {
                compiler_fence(Ordering::SeqCst);
                return 0;
            }
            if xfer_elapsed_us(ch_tx) > XFER_LIMIT_US {
                log::warn!(
                    "[pio] transfer timed out: tx ch{} busy={} rx ch{} busy={}",
                    ch_tx,
                    dma_busy(ch_tx),
                    ch_rx,
                    dma_busy(ch_rx)
                );
                let _ = dma_abort(ch_tx);
                let _ = dma_abort(ch_rx);
                return crate::kernel::sys::errno::ERROR;
            }
            1
        }
        // ── PLATFORM_DMA: channel family ──────────────────────────────
        //
        // Handle-type rule: `channel::ALLOC` is the only opener in this
        // family; its returned handle is a raw DMA channel number
        // (0..15). Every follow-up op requires that handle and rejects
        // tagged fds from the `fd::*` family.
        //
        // Cross-family rejection: a tagged DMA fd has bits >= 15 set
        // (FD_TAG_DMA=7 shifted by TAG_SHIFT=27). `is_dma_channel_handle`
        // refuses any such handle outright — so passing `fd::CREATE`'s
        // return value to `channel::FREE` fails fast with EINVAL.
        dma_raw::channel::ALLOC => dma_alloc_channel(),
        dma_raw::channel::FREE => {
            if !is_dma_channel_handle(handle) {
                return E_INVAL;
            }
            dma_free_channel(crate::kernel::ipc::fd::slot_of(handle) as u8)
        }
        dma_raw::channel::START => {
            if !is_dma_channel_handle(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 14 {
                return E_INVAL;
            }
            let ch = crate::kernel::ipc::fd::slot_of(handle) as u8;
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let write_addr =
                u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let count = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let dreq = *arg.add(12);
            let flags = *arg.add(13);
            dma_start_raw(ch, read_addr, write_addr, count, dreq, flags)
        }
        dma_raw::channel::BUSY => {
            if !is_dma_channel_handle(handle) {
                return E_INVAL;
            }
            dma_busy(crate::kernel::ipc::fd::slot_of(handle) as u8)
        }
        dma_raw::channel::ABORT => {
            if !is_dma_channel_handle(handle) {
                return E_INVAL;
            }
            dma_abort(crate::kernel::ipc::fd::slot_of(handle) as u8)
        }
        spi9_raw::SEND => {
            // 9-bit SPI bit-bang: send command + data using raw PAC GPIO.
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let cs = *arg;
            let sck = *arg.add(1);
            let sda = *arg.add(2);
            let cmd = *arg.add(3);
            let data_len = *arg.add(4) as usize;
            if arg_len < 5 + data_len {
                return E_INVAL;
            }
            let hold_cs = if arg_len > 5 + data_len {
                *arg.add(5 + data_len) != 0
            } else {
                false
            };
            spi9_pac_send(cs, sck, sda, cmd, arg.add(5), data_len, hold_cs);
            0
        }
        spi9_raw::RESET => {
            // 9-bit SPI reset: RST high->low->high + init SIO pins
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let rst = *arg;
            let cs = *arg.add(1);
            let sck = *arg.add(2);
            let sda = *arg.add(3);
            spi9_pac_reset(rst, cs, sck, sda);
            0
        }
        spi9_raw::CS_SET => {
            // Set CS pin level: arg=[cs_pin:u8, level:u8]
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let cs = *arg;
            let level = *arg.add(1) != 0;
            spi9_pin_set(cs, level);
            0
        }
        // ── Raw SPI peripheral bridge ─────────────────────────────────
        spi_raw::REG_WRITE => {
            // handle=bus_id, arg=[offset:u8, value:u32 LE]
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4008_0000usize
            } else {
                0x4009_0000usize
            };
            let offset = (*arg as usize) & 0xFC; // 4-byte aligned
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        spi_raw::REG_READ => {
            // handle=bus_id, arg=[offset:u8], returns value in arg[1..5]
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4008_0000usize
            } else {
                0x4009_0000usize
            };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0];
            *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2];
            *arg.add(4) = bytes[3];
            0
        }
        spi_raw::BUS_INFO => {
            // handle=bus_id, returns [dr_addr:u32, tx_dreq:u8, rx_dreq:u8, max_freq:u32, pad:u16]
            if arg.is_null() || arg_len < 12 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let dr_addr: u32 = if bus == 0 { 0x4008_0008 } else { 0x4009_0008 };
            let tx_dreq: u8 = if bus == 0 { 16 } else { 18 };
            let rx_dreq: u8 = if bus == 0 { 17 } else { 19 };
            // SPI's ceiling is Fsys/2, so it moves with the system clock
            // rather than with a literal that happens to match today's.
            let max_freq: u32 = crate::platform::chip::SYS_CLK_HZ / 2;
            let dr = dr_addr.to_le_bytes();
            *arg = dr[0];
            *arg.add(1) = dr[1];
            *arg.add(2) = dr[2];
            *arg.add(3) = dr[3];
            *arg.add(4) = tx_dreq;
            *arg.add(5) = rx_dreq;
            let mf = max_freq.to_le_bytes();
            *arg.add(6) = mf[0];
            *arg.add(7) = mf[1];
            *arg.add(8) = mf[2];
            *arg.add(9) = mf[3];
            *arg.add(10) = 0;
            *arg.add(11) = 0;
            0
        }
        spi_raw::PIN_INIT => {
            // handle=bus_id, arg=[clk:u8, mosi:u8, miso:u8]
            if arg.is_null() || arg_len < 3 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let funcsel: u32 = 1; // SPI function on RP2350
            let pins = [*arg, *arg.add(1), *arg.add(2)];
            let mut i = 0usize;
            while i < 3 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    // Enable pad (IE + drive)
                    core::ptr::write_volatile(pad_base as *mut u32, 0x56);
                    // Set funcsel
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        // ── Raw I2C peripheral bridge ──────────────────────────────────
        i2c_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4009_0000usize
            } else {
                0x4009_8000usize
            };
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        i2c_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4009_0000usize
            } else {
                0x4009_8000usize
            };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0];
            *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2];
            *arg.add(4) = bytes[3];
            0
        }
        i2c_raw::BUS_INFO => {
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let data_cmd: u32 = if bus == 0 { 0x4009_0010 } else { 0x4009_8010 }; // IC_DATA_CMD
            let tx_dreq: u8 = if bus == 0 { 20 } else { 22 }; // I2C0_TX=20, I2C1_TX=22
            let rx_dreq: u8 = if bus == 0 { 21 } else { 23 };
            let dc = data_cmd.to_le_bytes();
            *arg = dc[0];
            *arg.add(1) = dc[1];
            *arg.add(2) = dc[2];
            *arg.add(3) = dc[3];
            *arg.add(4) = tx_dreq;
            *arg.add(5) = rx_dreq;
            *arg.add(6) = 0;
            *arg.add(7) = 0;
            0
        }
        i2c_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let funcsel: u32 = 3; // I2C function on RP2350
            let pins = [*arg, *arg.add(1)];
            let mut i = 0usize;
            while i < 2 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    // I2C needs pullup + input enable
                    core::ptr::write_volatile(pad_base as *mut u32, 0x4E); // IE + PUE + drive=4mA
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        i2c_raw::SET_ENABLE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4009_0000usize
            } else {
                0x4009_8000usize
            };
            // IC_ENABLE at offset 0x6C
            core::ptr::write_volatile((base + 0x6C) as *mut u32, if *arg != 0 { 1 } else { 0 });
            0
        }
        // ── Raw UART peripheral bridge ─────────────────────────────────
        uart_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4007_0000usize
            } else {
                0x4007_8000usize
            };
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        uart_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4007_0000usize
            } else {
                0x4007_8000usize
            };
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0];
            *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2];
            *arg.add(4) = bytes[3];
            0
        }
        uart_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let funcsel: u32 = 2; // UART function on RP2350
            let pins = [*arg, *arg.add(1)];
            let mut i = 0usize;
            while i < 2 {
                let pin = pins[i];
                if pin != 0xFF && pin < 30 {
                    let pad_base = 0x4003_8004usize + (pin as usize) * 4;
                    let io_base = 0x4002_8004usize + (pin as usize) * 8;
                    core::ptr::write_volatile(pad_base as *mut u32, 0x56);
                    core::ptr::write_volatile(io_base as *mut u32, funcsel);
                }
                i += 1;
            }
            0
        }
        uart_raw::SET_ENABLE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4007_0000usize
            } else {
                0x4007_8000usize
            };
            // UARTCR at offset 0x30
            let cr = core::ptr::read_volatile((base + 0x30) as *const u32);
            if *arg != 0 {
                core::ptr::write_volatile((base + 0x30) as *mut u32, cr | 0x301);
            // UARTEN + TXE + RXE
            } else {
                core::ptr::write_volatile((base + 0x30) as *mut u32, cr & !1); // clear UARTEN
            }
            0
        }
        // ── Raw ADC peripheral bridge ──────────────────────────────────
        adc_raw::REG_WRITE => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let base = 0x400A_0000usize;
            let offset = (*arg as usize) & 0xFC;
            let val = u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            core::ptr::write_volatile((base + offset) as *mut u32, val);
            0
        }
        adc_raw::REG_READ => {
            if arg.is_null() || arg_len < 5 {
                return E_INVAL;
            }
            let base = 0x400A_0000usize;
            let offset = (*arg as usize) & 0xFC;
            let val = core::ptr::read_volatile((base + offset) as *const u32);
            let bytes = val.to_le_bytes();
            *arg.add(1) = bytes[0];
            *arg.add(2) = bytes[1];
            *arg.add(3) = bytes[2];
            *arg.add(4) = bytes[3];
            0
        }
        adc_raw::PIN_INIT => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let pin = *arg;
            if !(26..=29).contains(&pin) {
                return E_INVAL;
            }
            let pad_base = 0x4003_8004usize + (pin as usize) * 4;
            // ADC: disable digital input (IE=0), no pulls
            core::ptr::write_volatile(pad_base as *mut u32, 0x80); // ISO=1 (analog mode)
            0
        }
        // ── SPI bridge (continued) ─────────────────────────────────────
        spi_raw::SET_ENABLE => {
            // handle=bus_id, arg=[enable:u8]
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let bus = handle as u8;
            if bus > 1 {
                return E_INVAL;
            }
            let base = if bus == 0 {
                0x4008_0000usize
            } else {
                0x4009_0000usize
            };
            let cr1 = core::ptr::read_volatile((base + 0x04) as *const u32);
            if *arg != 0 {
                core::ptr::write_volatile((base + 0x04) as *mut u32, cr1 | (1 << 1));
            // SSE=1
            } else {
                core::ptr::write_volatile((base + 0x04) as *mut u32, cr1 & !(1 << 1));
                // SSE=0
            }
            0
        }
        flash::SIDEBAND => {
            use crate::abi::internal::flash::sideband_op as flash_sideband_op;
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            match *arg {
                flash_sideband_op::READ_CS => {
                    crate::platform::rp_flash::xip_lock::flash_sideband_read_cs()
                }
                flash_sideband_op::XIP_READ => {
                    if arg_len < 6 {
                        return E_INVAL;
                    }
                    let offset =
                        u32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
                    const FLASH_SIZE: u32 = 0x0040_0000;
                    let data_len = arg_len - 5;
                    if offset >= FLASH_SIZE {
                        return E_INVAL;
                    }
                    let avail = (FLASH_SIZE - offset) as usize;
                    let copy_len = if data_len < avail { data_len } else { avail };
                    let xip_src = (0x1000_0000u32 + offset) as *const u8;
                    core::ptr::copy_nonoverlapping(xip_src, arg.add(5), copy_len);
                    copy_len as i32
                }
                _ => E_NOSYS,
            }
        }
        // ── Runtime parameter store ──
        runtime_params::STORE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let module_id = crate::kernel::exec::scheduler::current_module_index() as u8;
            let mut fwd = [0u8; 252];
            fwd[0] = module_id;
            let n = if arg_len > 251 { 251 } else { arg_len };
            core::ptr::copy_nonoverlapping(arg, fwd.as_mut_ptr().add(1), n);
            crate::platform::rp_flash::store::dispatch_param_op(
                runtime_params::STORE,
                fwd.as_mut_ptr(),
                1 + n,
            )
        }
        runtime_params::DELETE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let module_id = crate::kernel::exec::scheduler::current_module_index() as u8;
            let mut fwd = [module_id, *arg];
            crate::platform::rp_flash::store::dispatch_param_op(
                runtime_params::DELETE,
                fwd.as_mut_ptr(),
                2,
            )
        }
        runtime_params::CLEAR_ALL => {
            if arg_len >= 1 && !arg.is_null() && *arg == 0xFF {
                let mut fwd = [0xFFu8];
                crate::platform::rp_flash::store::dispatch_param_op(
                    runtime_params::CLEAR_ALL,
                    fwd.as_mut_ptr(),
                    1,
                )
            } else {
                let module_id = crate::kernel::exec::scheduler::current_module_index() as u8;
                let mut fwd = [module_id];
                crate::platform::rp_flash::store::dispatch_param_op(
                    runtime_params::CLEAR_ALL,
                    fwd.as_mut_ptr(),
                    1,
                )
            }
        }
        // ── Flash store bridge ──
        FLASH_STORE_ENABLE => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let fn_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let module_idx = crate::kernel::exec::scheduler::current_module_index();
            // Resolve export hash to absolute address (PIC-safe)
            let resolved_addr =
                crate::kernel::module::loader::resolve_export_for_module(module_idx, fn_addr)
                    .unwrap_or(fn_addr as usize);
            let dispatch: crate::platform::rp_flash::store::FlashStoreDispatchFn =
                core::mem::transmute(resolved_addr);
            let state = crate::kernel::exec::scheduler::get_module_state(module_idx);
            crate::platform::rp_flash::store::register_dispatch(dispatch, state)
        }
        flash::RAW_ERASE => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::platform::rp_flash::store::raw_erase(offset)
        }
        flash::RAW_PROGRAM => {
            if arg.is_null() || arg_len < 4 + 256 {
                return E_INVAL;
            }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::platform::rp_flash::store::raw_program(offset, arg.add(4))
        }
        // ── PLATFORM_DMA: fd family ──────────────────────────────────
        //
        // Handle-type rule: `fd::CREATE` is the only opener in this
        // family; its returned handle is a tagged DMA fd (FD_TAG_DMA).
        // Every follow-up op rejects raw channel numbers via
        // `is_dma_fd_handle` so passing `channel::ALLOC`'s return value
        // to `fd::START` fails fast with EINVAL.
        dma_raw::fd::CREATE => dma_fd_create(),
        dma_raw::fd::START => {
            if !is_dma_fd_handle(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 14 {
                return E_INVAL;
            }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let write_addr =
                u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let count = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let dreq = *arg.add(12);
            let flags = *arg.add(13);
            dma_fd_start(handle, read_addr, write_addr, count, dreq, flags)
        }
        dma_raw::fd::RESTART => {
            if !is_dma_fd_handle(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            dma_fd_restart(handle, read_addr, count)
        }
        dma_raw::fd::FREE => {
            if !is_dma_fd_handle(handle) {
                return E_INVAL;
            }
            dma_fd_free(handle)
        }
        dma_raw::fd::QUEUE => {
            if !is_dma_fd_handle(handle) {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            dma_fd_queue(handle, read_addr, count)
        }
        // ── SYS_CLOCK_HZ ──
        SYS_CLOCK_HZ => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            *(arg as *mut u32) = crate::platform::rp_clocks::measured_sys_hz();
            0
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP provider_query extension (GPIO + SYS_CLOCK_HZ)
// ============================================================================

unsafe fn rp_dev_query_extension(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32 {
    use crate::abi::contracts::hal::gpio as dev_gpio;
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::kernel::module::provider::contract as dev_class;
    let class = ((key >> 8) & 0xFF) as u16;
    match class {
        dev_class::GPIO => match key {
            dev_gpio::GET_LEVEL => {
                if !gpio::gpio_check_owner(handle) {
                    return E_INVAL;
                }
                gpio::gpio_get_level(handle)
            }
            _ => E_NOSYS,
        },
        dev_class::INTERNAL_DISPATCH_BUCKET => match key {
            SYS_CLOCK_HZ => {
                if out.is_null() || out_len < 4 {
                    return E_INVAL;
                }
                *(out as *mut u32) = crate::platform::rp_clocks::measured_sys_hz();
                0
            }
            _ => E_NOSYS,
        },
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP Provider Registration + Cleanup
// ============================================================================

/// Register RP-specific contract providers. Called from init_providers().
fn init_rp_providers() {
    use crate::kernel::module::provider::{self, contract as dev_class};
    provider::register(dev_class::HAL_GPIO, gpio_provider_dispatch);
    // Handle-scoped vtable routes tracked GPIO handles by contract id;
    // the class-byte registration above is the fallback for handle=-1
    // global ops.
    provider::register_vtable(&GPIO_VTABLE);
    // PIO, SPI, I2C, UART, ADC, PWM providers are registered by the
    // loader when their PIC module exports `module_provides_contract`.
    // Register system extension for hardware opcodes (raw register bridges)
    register_system_extension(rp_system_extension_dispatch);
}

// Handle-scoped vtable for HAL GPIO. `call` delegates to
// `gpio_provider_dispatch`; open-style opcodes (CLAIM, SET_INPUT,
// SET_OUTPUT) return a pin handle that `provider_open` tracks. Close
// invokes RELEASE.
static GPIO_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_GPIO,
        call: gpio_provider_dispatch,
        query: None,
        default_close_op: crate::abi::contracts::hal::gpio::RELEASE,
    };

/// Release all RP-specific hardware handles owned by a module.
fn release_rp_handles(module_idx: u8) {
    // PIO handles released by PIC pio_stream module provider
    // Release GPIO pins
    gpio::release_owned_by(module_idx);
}
