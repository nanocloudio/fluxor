//! RP provider assembly for the kernel namespace.
//!
//! This module is only compiled for RP targets (via cfg in mod.rs).
//! It groups DMA ownership and provider dispatch concerns in
//! `platform/rp/providers.rs`.

use portable_atomic::{compiler_fence, AtomicU16, Ordering};

use crate::kernel::module::syscalls::{register_dev_query_extension, register_system_extension};
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;
use crate::platform::chip::PWM_BASE;
use crate::platform::rp_dma as dma;
use crate::platform::rp_gpio_regs as gpio_regs;
use crate::platform::rp_io::gpio;
use crate::platform::rp_pio_regs as pio_regs;
use crate::platform::rp_pio_regs::addr::SmReg;
use crate::platform::rp_regs::{read32, write32};

use crate::abi::platform::rp::raw_claim::family;
use crate::platform::chip;

const E_INVAL: i32 = errno::EINVAL;

/// IO_BANK0 function selects of the bus peripherals, the same on both dies.
const FUNCSEL_SPI: u32 = 1;
const FUNCSEL_UART: u32 = 2;
const FUNCSEL_I2C: u32 = 3;
/// `FUNCSEL` 31 detaches a pin from every peripheral (an analog input).
const FUNCSEL_NULL: u32 = 31;

/// PL022 (SPI) register offsets.
const PL022_CR1: usize = 0x04;
const PL022_DR: usize = 0x08;
const PL022_CR1_SSE: u32 = 1 << 1;
/// PL011 (UART) data and control registers, and the control enables.
const PL011_DR: usize = 0x00;
const PL011_CR: usize = 0x30;
const PL011_CR_UARTEN: u32 = 1 << 0;
const PL011_CR_TXE: u32 = 1 << 8;
const PL011_CR_RXE: u32 = 1 << 9;
/// DW_apb_i2c data/command and enable registers.
const DW_I2C_DATA_CMD: usize = 0x10;
const DW_I2C_ENABLE: usize = 0x6C;
const E_NOSYS: i32 = errno::ENOSYS;
const E_NOMEM: i32 = errno::ENOMEM;

// ============================================================================
// DMA channel allocation
// ============================================================================

/// Bitmap of allocated DMA channels. CH0-CH7 pre-marked at boot.
static DMA_CHANNELS_USED: AtomicU16 = AtomicU16::new(0x00FF); // CH0-CH7 reserved

/// The module each allocated channel belongs to (`NO_MODULE` for the
/// kernel's own and for free ones). A raw channel number is a handle the
/// allocator gave one module; no other may start, poll or free it.
static DMA_CHANNEL_OWNER: [AtomicU16; 16] = [const { AtomicU16::new(NO_MODULE) }; 16];

/// Whether channel `ch` is one the module being stepped allocated.
fn owns_channel(ch: u8) -> bool {
    (ch as usize) < DMA_CHANNEL_OWNER.len()
        && DMA_CHANNEL_OWNER[ch as usize].load(Ordering::Acquire)
            == crate::kernel::exec::scheduler::current_module_id()
}

/// Free every channel `module` allocated and still holds.
fn release_channels_owned_by(module: ModuleId) {
    for (ch, owner) in DMA_CHANNEL_OWNER.iter().enumerate() {
        if owner.load(Ordering::Acquire) == module {
            let _ = dma_abort(ch as u8);
            let _ = dma_free_channel(ch as u8);
        }
    }
}

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
            DMA_CHANNEL_OWNER[ch as usize].store(
                crate::kernel::exec::scheduler::current_module_id(),
                Ordering::Release,
            );
            return ch as i32;
        }
    }
}

pub(crate) fn dma_free_channel(ch: u8) -> i32 {
    if !(8..=15).contains(&ch) {
        return E_INVAL;
    }
    DMA_CHANNEL_OWNER[ch as usize].store(NO_MODULE, Ordering::Release);
    let bit = 1u16 << ch;
    DMA_CHANNELS_USED.fetch_and(!bit, core::sync::atomic::Ordering::Release);
    0
}

// ============================================================================
// DMA transfers over lends
// ============================================================================
//
// A transfer moves memory to or from one peripheral FIFO. The peripheral side
// is the FIFO its DREQ paces, on an instance the caller holds a raw claim on
// (`fifo_of`); the memory side is a span the caller lent on the handle the
// transfer runs on (`lend::OPEN`), named `[cookie][offset]` (`lent_at`).
// Nobody names an address.

/// `flags` bit: the memory side advances each unit.
const FLAG_INCR: u8 = crate::abi::platform::rp::dma_raw::flags::INCR;

/// A transfer's peripheral side: the FIFO register `dreq` paces, and whether
/// the transfer moves memory into it.
#[derive(Clone, Copy)]
struct Fifo {
    addr: u32,
    to_peripheral: bool,
}

/// The FIFO `dreq` paces, on a PIO block, SPI, UART or I2C instance the
/// caller holds a raw claim on. `EBADF` for an instance it does not hold,
/// `EINVAL` for a DREQ no FIFO of this die answers to.
fn fifo_of(dreq: u8) -> Result<Fifo, i32> {
    let held = |f: u8, instance: u8| -> Result<(), i32> {
        let me = crate::kernel::exec::scheduler::current_module_id();
        match raw_slot(f, instance).map(|s| RAW_OWNER[s].load(Ordering::Acquire)) {
            Some(owner) if owner == me => Ok(()),
            _ => Err(errno::EBADF),
        }
    };
    // PIO block n paces TX of state machine sm at 8n + sm, RX at 8n + 4 + sm.
    let pio_num = dreq >> 3;
    if (pio_num as usize) < chip::PIO_COUNT as usize {
        held(family::PIO, pio_num)?;
        let base = pio_regs::instance(pio_num).ok_or(E_INVAL)?;
        let sm = (dreq & 3) as usize;
        let rx = dreq & 4 != 0;
        let addr = if rx {
            pio_regs::addr::rxf(base, sm)
        } else {
            pio_regs::addr::txf(base, sm)
        };
        return Ok(Fifo {
            addr: addr as u32,
            to_peripheral: !rx,
        });
    }
    type Bus = (
        u8,
        fn(u8) -> Option<usize>,
        fn(u8) -> Option<(u8, u8)>,
        usize,
        u8,
    );
    let buses: [Bus; 3] = [
        (
            family::SPI,
            chip::spi_base,
            chip::spi_dreq,
            PL022_DR,
            chip::SPI_COUNT,
        ),
        (
            family::UART,
            chip::uart_base,
            chip::uart_dreq,
            PL011_DR,
            chip::UART_COUNT,
        ),
        (
            family::I2C,
            chip::i2c_base,
            chip::i2c_dreq,
            DW_I2C_DATA_CMD,
            chip::I2C_COUNT,
        ),
    ];
    for (f, base_of, dreq_of, fifo, count) in buses {
        for instance in 0..count {
            let Some((tx, rx)) = dreq_of(instance) else {
                continue;
            };
            if dreq != tx && dreq != rx {
                continue;
            }
            held(f, instance)?;
            let base = base_of(instance).ok_or(E_INVAL)?;
            return Ok(Fifo {
                addr: (base + fifo) as u32,
                to_peripheral: dreq == tx,
            });
        }
    }
    Err(E_INVAL)
}

/// The transfer unit `flags` names and its width in bytes.
fn unit_of(flags: u8) -> Option<(dma::DataSize, usize)> {
    use crate::abi::platform::rp::dma_raw::flags as f;
    match flags & f::SIZE_MASK {
        f::SIZE_BYTE => Some((dma::DataSize::Byte, 1)),
        f::SIZE_HALF => Some((dma::DataSize::HalfWord, 2)),
        f::SIZE_WORD => Some((dma::DataSize::Word, 4)),
        _ => None,
    }
}

/// The address `offset` bytes into the span the caller lent on `handle`
/// under `cookie`, when `bytes` from there lie inside it and the lend lets
/// the transfer read it (`to_peripheral`) or write it.
fn lent_at(
    handle: i32,
    cookie: u32,
    offset: u32,
    bytes: usize,
    to_peripheral: bool,
) -> Result<u32, i32> {
    use crate::kernel::ipc::lend;
    let me = crate::kernel::exec::scheduler::current_module_id();
    let (addr, len, dir) = lend::resolve_kernel(handle, cookie, me).ok_or(errno::ENOENT)?;
    let need = if to_peripheral {
        lend::dir::IN
    } else {
        lend::dir::OUT
    };
    if dir & need == 0 {
        return Err(errno::EACCES);
    }
    let end = (offset as usize).checked_add(bytes).ok_or(E_INVAL)?;
    if end > len {
        return Err(E_INVAL);
    }
    u32::try_from(addr + offset as usize).map_err(|_| E_INVAL)
}

/// A decoded transfer: `[cookie u32][offset u32][count u32][dreq u8]
/// [flags u8]` against the lends on `handle`.
struct Transfer {
    read: u32,
    write: u32,
    count: u32,
    fifo: Fifo,
    ctrl: dma::CtrlTrig,
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn transfer_of(handle: i32, ch: u8, arg: &[u8]) -> Result<Transfer, i32> {
    let (Some(cookie), Some(offset), Some(count), Some(&dreq), Some(&flags)) = (
        le32(arg, 0),
        le32(arg, 4),
        le32(arg, 8),
        arg.get(12),
        arg.get(13),
    ) else {
        return Err(E_INVAL);
    };
    let (size, width) = unit_of(flags).ok_or(E_INVAL)?;
    let fifo = fifo_of(dreq)?;
    let incr = flags & FLAG_INCR != 0;
    let bytes = if incr {
        (count as usize).checked_mul(width).ok_or(E_INVAL)?
    } else {
        width
    };
    let mem = lent_at(handle, cookie, offset, bytes, fifo.to_peripheral)?;
    let (read, write) = if fifo.to_peripheral {
        (mem, fifo.addr)
    } else {
        (fifo.addr, mem)
    };
    let ctrl = dma::CtrlTrig::default()
        .enable(true)
        .incr_read(incr && fifo.to_peripheral)
        .incr_write(incr && !fifo.to_peripheral)
        .data_size(size)
        .treq_sel(dreq)
        .chain_to(ch);
    Ok(Transfer {
        read,
        write,
        count,
        fifo,
        ctrl,
    })
}

/// Program and start channel `ch`.
///
/// # Safety
/// `ch` is an implemented, allocated channel, and `t`'s memory side lies
/// inside a span lent for this transfer.
unsafe fn dma_start_raw(ch: u8, t: &Transfer) -> i32 {
    if !dma::is_implemented(ch) || DMA_CHANNELS_USED.load(Ordering::Acquire) & (1u16 << ch) == 0 {
        return E_INVAL;
    }
    let c = ch as usize;
    // SAFETY: `ch` is an implemented, allocated channel, so every address
    // below is inside this silicon's DMA block; the caller's contract covers
    // the memory the channel will touch.
    unsafe {
        write32(chan(c, dma::addr::READ_ADDR), t.read);
        write32(chan(c, dma::addr::WRITE_ADDR), t.write);
        write32(chan(c, dma::addr::TRANS_COUNT), dma::trans_count(t.count));
        compiler_fence(Ordering::SeqCst);
        // CTRL_TRIG last: writing it starts the transfer.
        write32(chan(c, dma::addr::CTRL_TRIG), t.ctrl.0);
    }
    compiler_fence(Ordering::SeqCst);
    0
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
    i32::from(channel_is_busy(ch))
}

/// Whether a channel is mid-transfer.
fn channel_is_busy(ch: u8) -> bool {
    // SAFETY: callers check `is_implemented` first; CTRL_TRIG is a read-only
    // status read here.
    dma::CtrlTrig(unsafe { read32(chan(ch as usize, dma::addr::CTRL_TRIG)) }).busy()
}

pub(crate) fn dma_abort(ch: u8) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    // Bounded: a channel that does not acknowledge the abort fails the call
    // rather than hanging whoever asked.
    if dma::abort(ch, DMA_ABORT_LIMIT) {
        0
    } else {
        crate::kernel::sys::errno::ERROR
    }
}

/// Spin budget for a channel to acknowledge an abort, in poll iterations.
const DMA_ABORT_LIMIT: u32 = 100_000;

/// Re-trigger `ch` from `read` for `count` units, keeping the rest of its
/// configuration.
///
/// # Safety
/// `ch` is an implemented channel the caller owns, configured to move memory
/// to a FIFO, and `read` starts a span lent for `count` units.
unsafe fn dma_restart_raw(ch: u8, read: u32, count: u32) -> i32 {
    if !dma::is_implemented(ch) {
        return E_INVAL;
    }
    let c = ch as usize;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the caller's contract. AL3_READ_ADDR_TRIG is written last
    // because writing it re-triggers the channel.
    unsafe {
        write32(chan(c, dma::addr::AL3_TRANS_COUNT), dma::trans_count(count));
        write32(chan(c, dma::addr::AL3_READ_ADDR_TRIG), read);
    }
    compiler_fence(Ordering::SeqCst);
    0
}

// ============================================================================
// DMA fds: a ping-pong channel pair
// ============================================================================

use portable_atomic::AtomicBool;
use portable_atomic::AtomicU8;

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};

const MAX_DMA_FDS: usize = 8;

struct DmaFdSlot {
    allocated: AtomicBool,
    owner: AtomicU16,
    channel_a: AtomicU8,
    channel_b: AtomicU8,
    active_is_b: AtomicBool,
    pending: AtomicBool,
    /// The last `START` moved memory to a FIFO, so `QUEUE` and `RESTART`
    /// (which reload the read side) apply.
    to_peripheral: AtomicBool,
    /// Bytes per unit of the last `START`, and whether its memory side
    /// advances.
    width: AtomicU8,
    incr: AtomicBool,
}

impl DmaFdSlot {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            owner: AtomicU16::new(NO_MODULE),
            channel_a: AtomicU8::new(0xFF),
            channel_b: AtomicU8::new(0xFF),
            active_is_b: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            to_peripheral: AtomicBool::new(false),
            width: AtomicU8::new(0),
            incr: AtomicBool::new(false),
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

    fn clear(&self) {
        self.channel_a.store(0xFF, Ordering::Release);
        self.channel_b.store(0xFF, Ordering::Release);
        self.pending.store(false, Ordering::Release);
        self.active_is_b.store(false, Ordering::Release);
        self.to_peripheral.store(false, Ordering::Release);
        self.owner.store(NO_MODULE, Ordering::Release);
        self.allocated.store(false, Ordering::Release);
    }
}

static DMA_FD_SLOTS: [DmaFdSlot; MAX_DMA_FDS] = [const { DmaFdSlot::new() }; MAX_DMA_FDS];

/// The index a DMA fd answers: [`DMA_FD_BASE`] plus its slot, a band no DMA
/// channel number shares, so a lend opened on one never resolves through the
/// other.
const DMA_FD_BASE: i32 = 0x100;

/// The fd slot a DMA fd index names, if it is one.
fn fd_slot(index: i32) -> Option<&'static DmaFdSlot> {
    usize::try_from(index.checked_sub(DMA_FD_BASE)?)
        .ok()
        .and_then(|i| DMA_FD_SLOTS.get(i))
}

fn dma_fd_create() -> i32 {
    let ch_a = dma_alloc_channel();
    if ch_a < 0 {
        return ch_a;
    }
    let ch_b = dma_alloc_channel();
    if ch_b < 0 {
        dma_free_channel(ch_a as u8);
        return ch_b;
    }
    let owner = crate::kernel::exec::scheduler::current_module_id();
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
            return DMA_FD_BASE + i as i32;
        }
    }
    dma_free_channel(ch_a as u8);
    dma_free_channel(ch_b as u8);
    errno::ENOMEM
}

/// The fd slot `fd_handle` names, when the module being stepped created it.
fn owned_fd(fd_handle: i32) -> Result<&'static DmaFdSlot, i32> {
    let dma = fd_slot(fd_handle).ok_or(errno::EBADF)?;
    if !dma.allocated.load(Ordering::Acquire)
        || dma.owner.load(Ordering::Acquire) != crate::kernel::exec::scheduler::current_module_id()
    {
        return Err(errno::EBADF);
    }
    Ok(dma)
}

fn dma_fd_start(fd_handle: i32, arg: &[u8]) -> Result<i32, i32> {
    let dma = owned_fd(fd_handle)?;
    if list_running(fd_index(fd_handle)) {
        return Err(errno::EBUSY);
    }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    let t = transfer_of(fd_handle, ch_a, arg)?;
    let width = unit_of(arg[13]).map_or(0, |(_, w)| w as u8);
    // SAFETY: `ch_a` is allocated to this fd, and `t`'s memory side was
    // checked against the caller's lend.
    let rc = unsafe { dma_start_raw(ch_a, &t) };
    if rc < 0 {
        return Err(rc);
    }
    // The pair's other channel takes the same FIFO and configuration, armed
    // but not started: `QUEUE` chains into it. AL1_CTRL, not CTRL_TRIG, so
    // configuring it does not start it.
    let b = ch_b as usize;
    // SAFETY: `ch_b` is allocated to this fd and idle until chained to.
    unsafe {
        write32(chan(b, dma::addr::WRITE_ADDR), t.write);
        write32(chan(b, dma::addr::READ_ADDR), t.read);
        write32(chan(b, dma::addr::AL1_CTRL), t.ctrl.chain_to(ch_b).0);
    }
    dma.active_is_b.store(false, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    dma.to_peripheral
        .store(t.fifo.to_peripheral, Ordering::Release);
    dma.width.store(width, Ordering::Release);
    dma.incr.store(arg[13] & FLAG_INCR != 0, Ordering::Release);
    Ok(rc)
}

/// `[cookie u32][offset u32][count u32]` of a `QUEUE` or `RESTART`: the read
/// side and count, for an fd whose `START` moved memory to a FIFO.
fn reload_of(fd_handle: i32, dma: &DmaFdSlot, arg: &[u8]) -> Result<(u32, u32), i32> {
    let (Some(cookie), Some(offset), Some(count)) = (le32(arg, 0), le32(arg, 4), le32(arg, 8))
    else {
        return Err(E_INVAL);
    };
    if !dma.to_peripheral.load(Ordering::Acquire) {
        return Err(E_INVAL);
    }
    let width = usize::from(dma.width.load(Ordering::Acquire));
    let bytes = if dma.incr.load(Ordering::Acquire) {
        (count as usize).checked_mul(width).ok_or(E_INVAL)?
    } else {
        width
    };
    Ok((lent_at(fd_handle, cookie, offset, bytes, true)?, count))
}

fn dma_fd_queue(fd_handle: i32, arg: &[u8]) -> Result<i32, i32> {
    let dma = owned_fd(fd_handle)?;
    if list_running(fd_index(fd_handle)) {
        return Err(errno::EBUSY);
    }
    let (read, count) = reload_of(fd_handle, dma, arg)?;
    let active = dma.active_ch();
    let inactive = dma.inactive_ch();
    let (a, i) = (active as usize, inactive as usize);
    // SAFETY: both channels belong to this fd's allocated ping-pong pair, so
    // both are implemented and owned here; `read` lies in the caller's lend.
    unsafe {
        write32(chan(i, dma::addr::READ_ADDR), read);
        write32(chan(i, dma::addr::TRANS_COUNT), dma::trans_count(count));
        compiler_fence(Ordering::SeqCst);
        // Point the running channel at the one just loaded, editing through
        // AL1_CTRL so the edit does not itself re-trigger it.
        let ctrl = dma::CtrlTrig(read32(chan(a, dma::addr::AL1_CTRL)));
        write32(chan(a, dma::addr::AL1_CTRL), ctrl.chain_to(inactive).0);
        compiler_fence(Ordering::SeqCst);
        if !channel_is_busy(active) {
            // The active channel finished before the chain was armed, so
            // nothing will follow it; start the loaded channel directly.
            write32(chan(i, dma::addr::AL3_TRANS_COUNT), dma::trans_count(count));
            write32(chan(i, dma::addr::AL3_READ_ADDR_TRIG), read);
            write32(chan(a, dma::addr::AL1_CTRL), ctrl.chain_to(active).0);
            dma.active_is_b
                .store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        }
    }
    dma.pending.store(true, Ordering::Release);
    Ok(0)
}

fn dma_fd_restart(fd_handle: i32, arg: &[u8]) -> Result<i32, i32> {
    let dma = owned_fd(fd_handle)?;
    if list_running(fd_index(fd_handle)) {
        return Err(errno::EBUSY);
    }
    let (read, count) = reload_of(fd_handle, dma, arg)?;
    // SAFETY: the fd's active channel, moving memory to a FIFO; `read` lies
    // in the caller's lend.
    Ok(unsafe { dma_restart_raw(dma.active_ch(), read, count) })
}

fn dma_fd_free(fd_handle: i32) -> i32 {
    let dma = match owned_fd(fd_handle) {
        Ok(d) => d,
        Err(e) => return e,
    };
    dma_list_stop(fd_index(fd_handle));
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    dma_abort(ch_a);
    dma_abort(ch_b);
    dma_free_channel(ch_a);
    dma_free_channel(ch_b);
    dma.clear();
    0
}

fn dma_fd_poll_ready(index: i32) -> bool {
    let Some(dma) = fd_slot(index) else {
        return false;
    };
    if !dma.allocated.load(Ordering::Acquire) {
        return false;
    }
    // An fd running a list is readable when entries have been sent since
    // its owner last read the status.
    let listed = crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked on the owner's core.
        unsafe { lists() }
            .running
            .get(fd_index(index))
            .and_then(|r| r.as_ref().map(|r| r.list.ready()))
    });
    if let Some(ready) = listed {
        return ready;
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

fn release_dma_fds_owned_by(module_idx: ModuleId) {
    for (index, dma) in DMA_FD_SLOTS.iter().enumerate() {
        if !dma.allocated.load(Ordering::Acquire) || dma.owner.load(Ordering::Acquire) != module_idx
        {
            continue;
        }
        dma_list_stop(index);
        for ch in [
            dma.channel_a.load(Ordering::Acquire),
            dma.channel_b.load(Ordering::Acquire),
        ] {
            if ch != 0xFF {
                dma_abort(ch);
                dma_free_channel(ch);
            }
        }
        dma.clear();
    }
}

// ============================================================================
// DMA scan lists
// ============================================================================
//
// A list runs on a DMA fd's two channels and a third claimed for it: the
// fd's first channel moves the data, its second loads the first from the
// list's control blocks, the third rewinds the list (`platform::rp_dma_list`
// holds the rules; this is the registers). The data channel's completion
// raises `DMA_IRQ_0` on core 0 or `DMA_IRQ_1` on a second core, whichever
// runs the owning module's domain, and the handler accounts for the entries
// the scan has passed.
//
// A list's state is touched by its owner's syscalls and by that interrupt,
// both on the owner's core, the syscalls with that core's interrupts masked;
// and by core 0 for a flash write or a module's release, with any other core
// parked.

use crate::platform::rp_dma_list::{self as dma_list, List, Pool, Shape};

/// The kernel's one table of control blocks, 16-byte aligned so a block is
/// one ring of the control channel's write address.
#[repr(C, align(16))]
struct BlockTable(core::cell::UnsafeCell<[[u32; 4]; dma_list::POOL_BLOCKS]>);
// SAFETY: written a word at a time through volatile stores, under the rules
// above; read by the DMA.
unsafe impl Sync for BlockTable {}

static LIST_BLOCKS: BlockTable =
    BlockTable(core::cell::UnsafeCell::new([[0; 4]; dma_list::POOL_BLOCKS]));

/// Each fd's fill word, which a fill entry sends over and over, and the
/// word its rewind channel writes: the address of its first block.
static LIST_FILL: [portable_atomic::AtomicU32; MAX_DMA_FDS] =
    [const { portable_atomic::AtomicU32::new(0) }; MAX_DMA_FDS];
static LIST_REWIND: [portable_atomic::AtomicU32; MAX_DMA_FDS] =
    [const { portable_atomic::AtomicU32::new(0) }; MAX_DMA_FDS];

/// A list running on an fd.
#[derive(Clone, Copy)]
struct RunningList {
    list: List,
    data: u8,
    control: u8,
    rewind: u8,
    /// The core that runs the owner's domain, and so takes the interrupt.
    core: u8,
    /// The owner's lend the entries send from, and the bytes one entry
    /// moves.
    lend: u32,
    span_bytes: u32,
}

struct ListState {
    running: [Option<RunningList>; MAX_DMA_FDS],
    pool: Pool,
}

struct ListCell(core::cell::UnsafeCell<ListState>);
// SAFETY: accessed under the rules at the head of this section.
unsafe impl Sync for ListCell {}

static LISTS: ListCell = ListCell(core::cell::UnsafeCell::new(ListState {
    running: [None; MAX_DMA_FDS],
    pool: Pool::new(),
}));

/// The lists' state.
///
/// # Safety
/// The caller is the owner's syscall with its core's interrupts masked, the
/// owner's core's DMA interrupt, or core 0 with any other core parked.
unsafe fn lists() -> &'static mut ListState {
    // SAFETY: the caller's contract.
    unsafe { &mut *LISTS.0.get() }
}

/// The block table as the DMA and the list rules see it.
struct ListBus {
    control: u8,
}

impl dma_list::Bus for ListBus {
    fn write(&mut self, block: usize, word: usize, value: u32) {
        if block < dma_list::POOL_BLOCKS && word < 4 {
            // SAFETY: a word of the table, in bounds.
            unsafe {
                core::ptr::write_volatile(
                    (LIST_BLOCKS.0.get() as *mut u32).add(block * 4 + word),
                    value,
                );
            }
        }
    }

    fn control_offset(&mut self) -> u32 {
        // SAFETY: the list's control channel, allocated to its fd.
        unsafe { read32(chan(self.control as usize, dma::addr::READ_ADDR)) }
            .wrapping_sub(LIST_BLOCKS.0.get() as u32)
    }
}

/// The fd slot index of `fd_handle`.
fn fd_index(fd_handle: i32) -> usize {
    (fd_handle - DMA_FD_BASE) as usize
}

/// Whether a list runs on fd slot `index`.
fn list_running(index: usize) -> bool {
    crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked on the calling core.
        unsafe { lists() }
            .running
            .get(index)
            .is_some_and(Option::is_some)
    })
}

fn dma_list_start(fd_handle: i32, arg: &[u8]) -> Result<i32, i32> {
    use crate::abi::platform::rp::dma_raw::list_start;
    let dma = owned_fd(fd_handle)?;
    let index = fd_index(fd_handle);
    let args = list_start::decode(arg).ok_or(E_INVAL)?;
    let data = dma.channel_a.load(Ordering::Acquire);
    let control = dma.channel_b.load(Ordering::Acquire);
    if list_running(index) || channel_is_busy(data) || channel_is_busy(control) {
        return Err(errno::EBUSY);
    }
    let (size, width) = unit_of(args.flags).ok_or(E_INVAL)?;
    let fifo = fifo_of(args.dreq)?;
    if !fifo.to_peripheral {
        return Err(E_INVAL);
    }
    let span_bytes = (args.count as usize)
        .checked_mul(width)
        .and_then(|b| u32::try_from(b).ok())
        .ok_or(E_INVAL)?;
    // One entry's span must lie inside the lend at all.
    lent_at(fd_handle, args.lend, 0, span_bytes as usize, true)?;
    if !List::fits(args.entries) {
        return Err(E_NOMEM);
    }
    let rewind = dma_alloc_channel();
    if rewind < 0 {
        return Err(E_NOMEM);
    }
    let rewind = rewind as u8;
    let table = LIST_BLOCKS.0.get() as u32;
    let core = chip::core_id().min(1) as u8;

    let block = |incr: bool, chain: u8| {
        dma::CtrlTrig::default()
            .enable(true)
            .data_size(size)
            .incr_read(incr)
            .treq_sel(args.dreq)
            .chain_to(chain)
            .0
    };
    crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked; no list runs on this fd yet.
        let state = unsafe { lists() };
        let Some(first) = state.pool.take(args.entries) else {
            dma_free_channel(rewind);
            return Err(E_NOMEM);
        };
        LIST_FILL[index].store(args.fill, Ordering::Release);
        LIST_REWIND[index].store(
            table + u32::from(first) * dma_list::BLOCK_BYTES,
            Ordering::Release,
        );
        let shape = Shape {
            first,
            entries: args.entries,
            write_addr: fifo.addr,
            trans_count: dma::trans_count(args.count),
            fill_addr: LIST_FILL[index].as_ptr() as u32,
            ctrl_fill: block(false, control),
            ctrl_armed: block(true, control),
            ctrl_fill_last: block(false, rewind),
            ctrl_armed_last: block(true, rewind),
        };
        let list = List::start(shape, &mut ListBus { control });
        state.running[index] = Some(RunningList {
            list,
            data,
            control,
            rewind,
            core,
            lend: args.lend,
            span_bytes,
        });
        let quiet_word = dma::CtrlTrig::default()
            .enable(true)
            .data_size(dma::DataSize::Word)
            .treq_sel(dma::TREQ_PERMANENT)
            .irq_quiet(true);
        let (d, c, r) = (data as usize, control as usize, rewind as usize);
        let base = chip::DMA_BASE as usize;
        // SAFETY: the fd's two channels and the one just allocated, all
        // idle; the interrupt registers of this silicon's DMA block.
        unsafe {
            // The data channel's completion reaches this core's line.
            write32(base + dma::addr::INTR, 1 << data);
            crate::platform::rp_regs::set_bits(base + dma::addr::INTE[core as usize], 1 << data);
            // The rewind channel: one word, the list's first block, into the
            // control channel's read pointer, which restarts it.
            write32(
                chan(r, dma::addr::READ_ADDR),
                LIST_REWIND[index].as_ptr() as u32,
            );
            write32(
                chan(r, dma::addr::WRITE_ADDR),
                chan(c, dma::addr::AL3_READ_ADDR_TRIG) as u32,
            );
            write32(chan(r, dma::addr::TRANS_COUNT), dma::trans_count(1));
            write32(chan(r, dma::addr::AL1_CTRL), quiet_word.chain_to(rewind).0);
            // The control channel: four words a block into the data
            // channel's registers, wrapping back to the first of them.
            write32(
                chan(c, dma::addr::WRITE_ADDR),
                chan(d, dma::addr::AL1_CTRL) as u32,
            );
            write32(chan(c, dma::addr::TRANS_COUNT), dma::trans_count(4));
            write32(
                chan(c, dma::addr::READ_ADDR),
                table + u32::from(first) * dma_list::BLOCK_BYTES,
            );
            compiler_fence(Ordering::SeqCst);
            // Its control word last: writing it loads block 0, which starts
            // the data channel.
            write32(
                chan(c, dma::addr::CTRL_TRIG),
                quiet_word
                    .incr_read(true)
                    .incr_write(true)
                    .ring_write(4)
                    .chain_to(control)
                    .0,
            );
        }
        crate::arch::cortex_m::nvic_unmask(dma::IRQ_LINES[core as usize]);
        Ok(0)
    })
}

fn dma_list_arm(fd_handle: i32, arg: &[u8]) -> Result<i32, i32> {
    use crate::abi::platform::rp::dma_raw::list_arm;
    owned_fd(fd_handle)?;
    let index = fd_index(fd_handle);
    let (entry, offset) = list_arm::decode(arg).ok_or(E_INVAL)?;
    crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked on the owner's core.
        let Some(running) = unsafe { lists() }.running[index].as_mut() else {
            return Err(E_INVAL);
        };
        if entry >= running.list.shape().entries {
            return Err(E_INVAL);
        }
        let read = lent_at(
            fd_handle,
            running.lend,
            offset,
            running.span_bytes as usize,
            true,
        )?;
        let mut bus = ListBus {
            control: running.control,
        };
        match running.list.arm(&mut bus, entry, read) {
            Ok(()) => Ok(0),
            Err(dma_list::ArmError::NoEntry) => Err(E_INVAL),
            Err(dma_list::ArmError::Busy) => Err(errno::EBUSY),
        }
    })
}

fn dma_list_status(fd_handle: i32, arg: &mut [u8]) -> Result<i32, i32> {
    use crate::abi::platform::rp::dma_raw::list_status;
    owned_fd(fd_handle)?;
    let index = fd_index(fd_handle);
    let out = arg.get_mut(..list_status::LEN).ok_or(E_INVAL)?;
    let (position, underruns) = crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked on the owner's core.
        let running = unsafe { lists() }.running[index].as_mut().ok_or(E_INVAL)?;
        let mut bus = ListBus {
            control: running.control,
        };
        Ok::<_, i32>(running.list.status(&mut bus))
    })?;
    out.copy_from_slice(&list_status::encode(position, underruns));
    Ok(0)
}

/// Stop the list on fd slot `index`, if one runs: its three channels idle
/// and disabled, its interrupt off, its blocks and its third channel free.
fn dma_list_stop(index: usize) {
    crate::arch::cortex_m::interrupt_free(|| {
        // SAFETY: interrupts masked; the caller is the owner or releases
        // for it with any other core parked.
        let state = unsafe { lists() };
        let Some(running) = state.running.get_mut(index).and_then(Option::take) else {
            return;
        };
        let base = chip::DMA_BASE as usize;
        // The loaders first, disabled so the data channel's last completion
        // starts nothing; then the data channel.
        for ch in [running.control, running.rewind, running.data] {
            // SAFETY: the list's own channels.
            unsafe { write32(chan(ch as usize, dma::addr::AL1_CTRL), 0) };
            let _ = dma_abort(ch);
            // SAFETY: as above; a load in flight when the first write
            // landed may have enabled the data channel again.
            unsafe { write32(chan(ch as usize, dma::addr::AL1_CTRL), 0) };
        }
        // SAFETY: the interrupt registers of this silicon's DMA block.
        unsafe {
            crate::platform::rp_regs::clear_bits(
                base + dma::addr::INTE[running.core as usize],
                1 << running.data,
            );
            write32(base + dma::addr::INTR, 1 << running.data);
        }
        let shape = *running.list.shape();
        state.pool.give(shape.first, shape.entries);
        dma_free_channel(running.rewind);
    });
}

/// Return every armed entry of every list to fill. Core 0, with its
/// interrupts masked and any other core parked, before it holds them for a
/// flash erase or program: no interrupt returns a sent entry to fill
/// meanwhile, and one left armed would be sent again a lap later from a
/// span its owner has since reused. The entries go out as fill and count as
/// underruns.
pub fn dma_lists_disarm_all() {
    // SAFETY: the caller's contract is this function's.
    for running in unsafe { lists() }.running.iter_mut().flatten() {
        let mut bus = ListBus {
            control: running.control,
        };
        running.list.disarm_all(&mut bus);
    }
}

/// The data-channel completion interrupt of the lists `core` owns.
fn dma_list_interrupt(core: usize) {
    let base = chip::DMA_BASE as usize;
    // SAFETY: this core's interrupt status of the DMA block.
    let pending = unsafe { read32(base + dma::addr::INTS[core]) };
    let mut ours = 0u32;
    // SAFETY: this core's interrupt; its lists are touched nowhere else
    // with this core's interrupts enabled.
    for running in unsafe { lists() }.running.iter_mut().flatten() {
        let bit = 1u32 << running.data;
        if usize::from(running.core) != core || pending & bit == 0 {
            continue;
        }
        ours |= bit;
        // SAFETY: the raw flag, cleared before the pointer is read so a
        // completion after the read raises the interrupt again.
        unsafe { write32(base + dma::addr::INTR, bit) };
        let mut bus = ListBus {
            control: running.control,
        };
        running.list.advance(&mut bus);
    }
    // A flag that is no list's would raise the line for ever.
    let stray = pending & !ours;
    if stray != 0 {
        // SAFETY: as above.
        unsafe { crate::platform::rp_regs::clear_bits(base + dma::addr::INTE[core], stray) };
    }
    if ours != 0 {
        crate::kernel::sys::hal::wake_scheduler();
    }
}

/// # Safety
/// ISR vector entry, invoked by the NVIC on core 0, never directly.
#[no_mangle]
pub unsafe extern "C" fn DMA_IRQ_0() {
    dma_list_interrupt(0);
}

/// # Safety
/// ISR vector entry, invoked by the NVIC on the second core, never directly.
#[no_mangle]
pub unsafe extern "C" fn DMA_IRQ_1() {
    #[cfg(feature = "smp")]
    crate::platform::rp_core1::count_interrupt();
    dma_list_interrupt(1);
}

// ============================================================================
// RP provider dispatch and registration
// ============================================================================

// ============================================================================
// Public API
// ============================================================================

pub fn init() {
    init_rp_providers();
    // Register provider_query extension for GPIO and SYS_CLOCK_HZ
    register_dev_query_extension(rp_dev_query_extension);
}

pub fn release_handles(module_idx: ModuleId) {
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
// manifest's `provider_contracts`. The raw register bridges they
// call into remain in `rp_system_extension_dispatch` below.

use crate::platform::rp_io::pio as pio_util;

/// Check if a GPIO pin has been claimed
pub fn is_gpio_registered(pin_num: u8) -> bool {
    gpio::gpio_is_claimed(pin_num)
}

/// Claim `pin_num` for the module being stepped and drive it as an output.
/// Returns its handle, or a negative errno.
fn gpio_request_output(pin_num: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        log::error!("[gpio] request_output pin {pin_num} claim failed rc={handle}");
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::exec::scheduler::current_module_id());
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Output, true);
    if result < 0 {
        log::error!("[gpio] request_output pin {pin_num} set_mode failed rc={result}");
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

/// Claim `pin_num` for the module being stepped as an input with pull
/// `pull` (0 none, 1 up, 2 down). Returns its handle, or a negative errno.
///
/// BOOTSEL is a separate capability — the `flash_rp` driver — not a
/// synthetic GPIO pin.
fn gpio_request_input(pin_num: u8, pull: u8) -> i32 {
    let handle = gpio::gpio_claim(pin_num);
    if handle < 0 {
        return handle;
    }
    gpio::gpio_set_owner(pin_num, crate::kernel::exec::scheduler::current_module_id());
    let pin_pull = match pull {
        1 => gpio::PinPull::Up,
        2 => gpio::PinPull::Down,
        _ => gpio::PinPull::None,
    };
    gpio::gpio_set_pull(handle, pin_pull);
    let result = gpio::gpio_set_mode(handle, gpio::PinMode::Input, false);
    if result < 0 {
        gpio::gpio_release(handle);
        return result;
    }
    handle
}

// ============================================================================
// Per-class provider dispatchers (RP-specific)
// ============================================================================

/// Run `f` with the other core kept out, when another core runs a domain:
/// the platform providers' state is one copy that either core's modules
/// reach, and a provider call is short. With core 1 running no domain there
/// is no other core to keep out.
#[inline]
pub fn exclusive<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "smp")]
    if crate::platform::rp_core1::running() {
        return critical_section::with(|_| f());
    }
    f()
}

fn gpio_provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    exclusive(|| gpio_ops(handle, opcode, arg, data))
}

fn gpio_ops(handle: i32, opcode: u32, arg: &mut [u8], _data: UserSpan<'_>) -> i32 {
    use crate::abi::contracts::hal::gpio as dev_gpio;
    // `handle` is the pin a claim names, or `WATCH_BASE` plus the pin for an
    // edge watch.
    if let Some(pin) = watched_pin(handle) {
        return watch_dispatch(pin, opcode, arg);
    }
    let owned = || gpio::gpio_check_owner(handle);
    match opcode {
        dev_gpio::CLAIM => {
            let Some(&pin) = arg.first() else {
                return E_INVAL;
            };
            // SAFETY: a pointer-free syscall entry point.
            let result = unsafe { gpio::syscall_gpio_claim(pin) };
            if result >= 0 {
                gpio::gpio_set_owner(pin, crate::kernel::exec::scheduler::current_module_id());
            }
            result
        }
        dev_gpio::SET_OUTPUT => match arg.first() {
            Some(&pin) => gpio_request_output(pin),
            None => E_INVAL,
        },
        dev_gpio::SET_INPUT => match arg {
            [pin, pull, ..] => gpio_request_input(*pin, *pull),
            _ => E_INVAL,
        },
        dev_gpio::RELEASE => {
            if !owned() {
                return E_INVAL;
            }
            // SAFETY: a pointer-free syscall entry point.
            unsafe { gpio::syscall_gpio_release(handle) }
        }
        dev_gpio::SET_MODE => match arg {
            [mode, level, ..] if owned() => {
                // SAFETY: a pointer-free syscall entry point.
                unsafe { gpio::syscall_gpio_set_mode(handle, *mode, *level) }
            }
            _ => E_INVAL,
        },
        dev_gpio::SET_PULL => match arg {
            [pull, ..] if owned() => {
                // SAFETY: a pointer-free syscall entry point.
                unsafe { gpio::syscall_gpio_set_pull(handle, *pull) }
            }
            _ => E_INVAL,
        },
        dev_gpio::SET_LEVEL => match arg {
            [level, ..] if owned() => {
                // SAFETY: a pointer-free syscall entry point.
                unsafe { gpio::syscall_gpio_set_level(handle, *level) }
            }
            _ => E_INVAL,
        },
        dev_gpio::GET_LEVEL => {
            if !owned() {
                return E_INVAL;
            }
            gpio::gpio_get_level(handle)
        }
        // `[edge u8]`: the watch's index, which the kernel wraps in a
        // signalling handle and hands the doorbell its edges ring.
        dev_gpio::WATCH_EDGE => match arg {
            [edge, ..] if owned() => match gpio::gpio_watch_edge(handle as u8, *edge) {
                0 => WATCH_BASE + handle,
                e => e,
            },
            _ => E_INVAL,
        },
        _ => E_NOSYS,
    }
}

/// The index an edge watch answers: [`WATCH_BASE`] plus the pin, a band no
/// pin claim shares.
const WATCH_BASE: i32 = 0x100;

/// The pin a watch index names, if it is one.
fn watched_pin(index: i32) -> Option<u8> {
    u8::try_from(index.checked_sub(WATCH_BASE)?)
        .ok()
        .filter(|&p| p < gpio::runtime_max_gpio())
}

/// An op on an edge watch: the kernel's doorbell for it, or its release.
fn watch_dispatch(pin: u8, opcode: u32, arg: &[u8]) -> i32 {
    use crate::abi::kernel_abi::doorbell;
    if !gpio::gpio_check_owner(i32::from(pin)) {
        return errno::EBADF;
    }
    match opcode {
        doorbell::BIND_DOORBELL => match doorbell::parse_bind(arg) {
            Some((d, _)) => gpio::gpio_bind_doorbell(pin, d as i32),
            None => E_INVAL,
        },
        crate::abi::contracts::hal::gpio::RELEASE => gpio::gpio_unwatch(pin),
        _ => errno::EBADF,
    }
}

// PIO provider dispatch removed — PIC pio_stream module handles PIO via register bridges.

// ============================================================================
// Raw PAC GPIO 9-bit SPI bit-bang (for display register init)
// ============================================================================

/// Set a pin as SIO output with initial level.
fn spi9_gpio_init(pin: u8, high: bool) {
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
fn spi9_pin_set(pin: u8, high: bool) {
    // SAFETY: as `spi9_gpio_init`; the pin is already configured as an output.
    unsafe { crate::platform::rp_gpio_regs::set_level(pin, high) };
}

/// Busy-wait for `us` microseconds using the RP hardware TIMER.
#[inline(always)]
fn spi9_timer_us(us: u32) {
    // The monotonic clock, not a private read of the timer block: one source
    // for every timestamp in the kernel, so this cannot drift from what the
    // scheduler believes the time is.
    let t0 = crate::platform::rp_timer::now_us();
    while crate::platform::rp_timer::now_us().wrapping_sub(t0) < us as u64 {}
}

/// Busy-wait ~100 us using hardware TIMER.
#[inline(always)]
fn spi9_pac_delay() {
    spi9_timer_us(100);
}

/// Busy-wait ~N ms using hardware TIMER.
#[inline(always)]
fn spi9_pac_delay_ms(ms: u32) {
    spi9_timer_us(ms * 1000);
}

/// Send one 9-bit SPI word. Clock idle low, data on rising edge, MSB first.
fn spi9_pac_write_word(sck: u8, sda: u8, word: u16) {
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
fn spi9_pac_send(cs: u8, sck: u8, sda: u8, cmd: u8, data: &[u8], hold_cs: bool) {
    spi9_pin_set(cs, false);
    spi9_timer_us(5); // CS setup time before first clock
    spi9_pac_write_word(sck, sda, cmd as u16); // DC=0 for command
    for &b in data {
        spi9_pac_write_word(sck, sda, 0x0100 | b as u16); // DC=1 for data
    }
    if !hold_cs {
        spi9_timer_us(5); // CS hold time after last clock
        spi9_pin_set(cs, true);
    }
}

/// Reset sequence + SIO pin init for 9-bit SPI.
fn spi9_pac_reset(rst: u8, cs: u8, sck: u8, sda: u8) {
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

/// The channel a `PLATFORM_DMA` index names, when the module being stepped
/// allocated it.
fn owned_channel(handle: i32) -> Result<u8, i32> {
    let ch = u8::try_from(handle).map_err(|_| errno::EBADF)?;
    if !owns_channel(ch) {
        return Err(errno::EBADF);
    }
    Ok(ch)
}

/// The `i32` result of a call that answers either a value or an errno.
fn rc(r: Result<i32, i32>) -> i32 {
    r.unwrap_or_else(|e| e)
}

fn rp_system_extension_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    use crate::abi::internal::flash;
    // The flash ops detach execute-in-place, which parks the other core
    // between two of its steps: they run outside the cores' lock, which a
    // core waiting to park could otherwise be spinning on. Core 0 runs them
    // (core 1's are handed to it) and keeps the other core out by parking
    // it.
    if matches!(
        opcode,
        flash::SIDEBAND | flash::RAW_ERASE | flash::RAW_PROGRAM
    ) {
        return system_extension_ops(handle, opcode, arg, data);
    }
    exclusive(|| system_extension_ops(handle, opcode, arg, data))
}

fn system_extension_ops(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    use crate::abi::internal::flash;
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::abi::platform::rp::{
        adc_raw, dma_raw, i2c_raw, pio_raw, pwm_raw, raw_claim, spi9_raw, spi_raw, uart_raw,
    };
    match opcode {
        // ── Raw instance claims ─────────────────────────────────────
        raw_claim::CLAIM => {
            if arg.len() < 2 {
                return E_INVAL;
            }
            raw_claim_instance(arg[0], arg[1])
        }
        raw_claim::RELEASE => raw_release(handle),
        // ── Raw PWM register bridge ─────────────────────────────────
        pwm_raw::PIN_ENABLE => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let pin = arg[0] as usize;
            if let Err(e) = own_pins(&[arg[0]]) {
                return e;
            }
            // SAFETY: a pin of this die the caller owns.
            unsafe {
                gpio_regs::set_function(pin as u8, PWM_FUNCSEL);
                gpio_regs::set_pad_output(pin as u8, gpio_regs::Drive::Ma4);
            }
            0
        }
        pwm_raw::PIN_DISABLE => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let pin = arg[0] as usize;
            if let Err(e) = own_pins(&[arg[0]]) {
                return e;
            }
            // SAFETY: as PIN_ENABLE.
            unsafe { gpio_regs::set_function(pin as u8, FUNCSEL_NONE) };
            0
        }
        pwm_raw::SLICE_WRITE => {
            if arg.len() < 6 {
                return E_INVAL;
            }
            let slice = match owned_named(handle, family::PWM, arg[0]) {
                Ok(i) => i as usize,
                Err(e) => return e,
            };
            let reg = arg[1];
            let value = u32::from_le_bytes([arg[2], arg[3], arg[4], arg[5]]);
            let Some(addr) = gpio_regs::pwm::reg(PWM_BASE as usize, slice, reg) else {
                return E_INVAL;
            };
            // SAFETY: `slice` is a slice of this die the caller has claimed,
            // and `reg` one of the five the block defines.
            unsafe { write32(addr, value) };
            0
        }
        pwm_raw::SLICE_READ => {
            if arg.len() < 2 {
                return E_INVAL;
            }
            let slice = match owned_named(handle, family::PWM, arg[0]) {
                Ok(i) => i as usize,
                Err(e) => return e,
            };
            let reg = arg[1];
            let Some(addr) = gpio_regs::pwm::reg(PWM_BASE as usize, slice, reg) else {
                return E_INVAL;
            };
            // SAFETY: as SLICE_WRITE.
            unsafe { read32(addr) as i32 }
        }
        // ── Raw PIO register bridge ───────────────────────────────────
        pio_raw::SM_EXEC => {
            if arg.len() < 4 {
                return E_INVAL;
            }
            let sm = arg[1];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if !pio_regs::is_state_machine(sm) {
                return E_INVAL;
            }
            let instr = u16::from_le_bytes([arg[2], arg[3]]);
            // SAFETY: `base` is an implemented instance and `sm` a real
            // state machine, both checked above.
            unsafe { pio_regs::write_sm_reg(base, sm, SmReg::Instr, instr as u32) };
            0
        }
        pio_raw::SM_WRITE_REG => {
            if arg.len() < 7 {
                return E_INVAL;
            }
            let sm_idx = arg[1];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if !pio_regs::is_state_machine(sm_idx) {
                return E_INVAL;
            }
            // ADDR is read-only, so it is not writable even though
            // SM_READ_REG names it.
            let reg = match SmReg::from_syscall(arg[2]) {
                Some(SmReg::Addr) | None => return E_INVAL,
                Some(r) => r,
            };
            let value = u32::from_le_bytes([arg[3], arg[4], arg[5], arg[6]]);
            // SAFETY: checked instance and state machine, as SM_EXEC.
            unsafe { pio_regs::write_sm_reg(base, sm_idx, reg, value) };
            0
        }
        pio_raw::SM_READ_REG => {
            if arg.len() < 3 {
                return E_INVAL;
            }
            let sm_idx = arg[1];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if !pio_regs::is_state_machine(sm_idx) {
                return E_INVAL;
            }
            let Some(reg) = SmReg::from_syscall(arg[2]) else {
                return E_INVAL;
            };
            // SAFETY: checked instance and state machine, as SM_EXEC.
            unsafe { pio_regs::read_sm_reg(base, sm_idx, reg) as i32 }
        }
        pio_raw::SM_ENABLE => {
            if arg.len() < 3 {
                return E_INVAL;
            }
            let mask = arg[1] & 0x0F;
            let enable = arg[2];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { pio_regs::set_enabled(base, mask, enable != 0) };
            0
        }
        pio_raw::INSTR_ALLOC => {
            if arg.len() < 2 {
                return E_INVAL;
            }
            let pio_num = arg[0];
            let count = arg[1];
            if let Err(e) = owned_pio(handle, pio_num) {
                return e;
            }
            if count == 0 || count > 32 {
                return E_INVAL;
            }
            match pio_util::alloc_instruction_slots(pio_num, count as usize) {
                Some((origin, mask)) => {
                    // The mask goes back in arg[2..6] so the caller can free
                    // the slots later.
                    if let Some(out) = arg.get_mut(2..6) {
                        out.copy_from_slice(&mask.to_le_bytes());
                    }
                    origin as i32
                }
                None => E_NOMEM,
            }
        }
        pio_raw::INSTR_WRITE => {
            if arg.len() < 4 {
                return E_INVAL;
            }
            let slot = arg[1];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if !pio_regs::is_instr_slot(slot) {
                return E_INVAL;
            }
            let instr = u16::from_le_bytes([arg[2], arg[3]]);
            // SAFETY: checked instance and instruction slot.
            unsafe { write32(pio_regs::addr::instr_mem(base, slot as usize), instr as u32) };
            0
        }
        pio_raw::INSTR_FREE => {
            if arg.len() < 5 {
                return E_INVAL;
            }
            let pio_num = arg[0];
            if let Err(e) = owned_pio(handle, pio_num) {
                return e;
            }
            let mask = u32::from_le_bytes([arg[1], arg[2], arg[3], arg[4]]);
            pio_util::free_instruction_slots(pio_num, mask);
            0
        }
        pio_raw::PIN_SETUP => {
            if arg.len() < 3 {
                return E_INVAL;
            }
            let pin = arg[0];
            let pio_num = arg[1];
            let pull = arg[2];
            if let Err(e) = owned_pio(handle, pio_num) {
                return e;
            }
            if let Err(e) = own_pins(&[pin]) {
                return e;
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
            if arg.is_empty() {
                return E_INVAL;
            }
            let pin = arg[0];
            if let Err(e) = own_pins(&[pin]) {
                return e;
            }
            // SAFETY: a pin the caller set up for PIO; the pad's input
            // buffer is enabled by that setup, so the level is real.
            i32::from(unsafe { gpio_regs::read_level(pin) })
        }
        pio_raw::GPIOBASE => {
            // PIO GPIOBASE: RP2350 only (register absent on RP2040 PAC)
            #[cfg(not(feature = "chip-rp2040"))]
            {
                if arg.len() < 2 {
                    return E_INVAL;
                }
                let base16 = arg[1];
                let base = match owned_pio(handle, arg[0]) {
                    Ok(b) => b,
                    Err(e) => return e,
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
            if arg.len() < 6 {
                return E_INVAL;
            }
            let sm = arg[1];
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if !pio_regs::is_state_machine(sm) {
                return E_INVAL;
            }
            let value = u32::from_le_bytes([arg[2], arg[3], arg[4], arg[5]]);
            // SAFETY: checked instance and state machine.
            unsafe { write32(pio_regs::addr::txf(base, sm as usize), value) };
            0
        }
        pio_raw::FSTAT_READ => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { read32(base + pio_regs::addr::FSTAT) as i32 }
        }
        pio_raw::SM_RESTART => {
            if arg.len() < 2 {
                return E_INVAL;
            }
            let mask = arg[1] & 0x0F;
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: `base` is an implemented instance.
            unsafe { pio_regs::restart(base, mask) };
            0
        }
        pio_raw::INPUT_SYNC_BYPASS => {
            if arg.len() < 5 {
                return E_INVAL;
            }
            let base = match owned_pio(handle, arg[0]) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let mask = u32::from_le_bytes([arg[1], arg[2], arg[3], arg[4]]);
            // SAFETY: `base` is an implemented instance.
            unsafe { set_bits_rmw(base + pio_regs::addr::INPUT_SYNC_BYPASS, mask) };
            0
        }
        pio_raw::CMD_TRANSFER => {
            // One gSPI command frame: set the state machine up and start both
            // DMA directions in one call, with no syscall latency between the
            // steps. `arg` is [`pio_raw::cmd_transfer`]: the TX words and the
            // RX words lie in one span the caller lent on `handle` (its claim
            // of the PIO block).
            use pio_raw::cmd_transfer as ct;
            if arg.len() < ct::LEN {
                return E_INVAL;
            }
            let pio_num = arg[ct::PIO];
            let sm_num = arg[ct::SM] as usize;
            let origin = arg[ct::ORIGIN];
            let base = match owned_pio(handle, pio_num) {
                Ok(b) => b,
                Err(e) => return e,
            };
            if sm_num >= pio_regs::STATE_MACHINES {
                return E_INVAL;
            }
            let field = |at: usize| le32(arg, at).unwrap_or(0);
            let write_bits = field(ct::WRITE_BITS);
            let read_bits = field(ct::READ_BITS);
            let cookie = field(ct::LEND);
            let tx_words = field(ct::TX_WORDS);
            let ch_tx = arg[ct::CH_TX];
            let ch_rx = arg[ct::CH_RX];
            // The transfer runs on two channels the caller allocated; it
            // starts no channel another module holds.
            if !owns_channel(ch_tx) || !owns_channel(ch_rx) {
                return errno::EBADF;
            }
            // RX runs even for a write-only transaction: the PIO program
            // expects the full TX→RX cycle to complete.
            let rx_words = if read_bits > 0 {
                (read_bits + 1).div_ceil(32)
            } else {
                1
            };
            let tx = match lent_at(
                handle,
                cookie,
                field(ct::TX_OFFSET),
                tx_words as usize * 4,
                true,
            ) {
                Ok(a) => a,
                Err(e) => return e,
            };
            let rx = match lent_at(
                handle,
                cookie,
                field(ct::RX_OFFSET),
                rx_words as usize * 4,
                false,
            ) {
                Ok(a) => a,
                Err(e) => return e,
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

            let tx_dreq = (pio_num << 3) + sm;
            let rx_dreq = tx_dreq + 4;
            let word = |ch: u8, dreq: u8, to_peripheral: bool| {
                dma::CtrlTrig::default()
                    .enable(true)
                    .incr_read(to_peripheral)
                    .incr_write(!to_peripheral)
                    .data_size(dma::DataSize::Word)
                    .treq_sel(dreq)
                    .chain_to(ch)
            };

            compiler_fence(Ordering::SeqCst);

            // Both directions at once, on their own channels, and return
            // without waiting. At 25 MHz a full gSPI frame is half a
            // millisecond, and the module calling this does several per step
            // during association: spinning on each would put a step at
            // 1-1.6 ms, over the scheduler's budget at the default tick.
            // RX is armed first so its DREQ is watching the FIFO before TX
            // fills it.
            let rx_t = Transfer {
                read: rxf_addr,
                write: rx,
                count: rx_words,
                fifo: Fifo {
                    addr: rxf_addr,
                    to_peripheral: false,
                },
                ctrl: word(ch_rx, rx_dreq, false),
            };
            // SAFETY: `ch_rx` is the caller's channel; `rx` lies in its lend.
            unsafe { dma_start_raw(ch_rx, &rx_t) };
            compiler_fence(Ordering::SeqCst);
            if tx_words > 0 {
                let tx_t = Transfer {
                    read: tx,
                    write: txf_addr,
                    count: tx_words,
                    fifo: Fifo {
                        addr: txf_addr,
                        to_peripheral: true,
                    },
                    ctrl: word(ch_tx, tx_dreq, true),
                };
                // SAFETY: `ch_tx` is the caller's channel; `tx` lies in its
                // lend.
                unsafe { dma_start_raw(ch_tx, &tx_t) };
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
            let [ch_tx, ch_rx, ..] = *arg else {
                return E_INVAL;
            };
            if !owns_channel(ch_tx) || !owns_channel(ch_rx) {
                return errno::EBADF;
            }
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
        // `channel::ALLOC` answers the channel number (8..15), which the
        // kernel wraps in a handle; every follow-up op is handed it back.
        dma_raw::channel::ALLOC => dma_alloc_channel(),
        // The channel number a handle holds, for a platform op that names
        // the channels it owns (a PIO command transfer).
        dma_raw::channel::CHANNEL => match (owned_channel(handle), arg.first_mut()) {
            (Ok(ch), Some(out)) => {
                *out = ch;
                0
            }
            (Ok(_), None) => E_INVAL,
            (Err(e), _) => e,
        },
        dma_raw::channel::FREE => match owned_channel(handle) {
            Ok(ch) => dma_free_channel(ch),
            Err(e) => e,
        },
        dma_raw::channel::START => rc(owned_channel(handle).and_then(|ch| {
            let t = transfer_of(handle, ch, arg)?;
            // SAFETY: `ch` is the caller's channel; `t`'s memory side was
            // checked against the caller's lend on it.
            Ok(unsafe { dma_start_raw(ch, &t) })
        })),
        dma_raw::channel::BUSY => match owned_channel(handle) {
            Ok(ch) => dma_busy(ch),
            Err(e) => e,
        },
        dma_raw::channel::ABORT => match owned_channel(handle) {
            Ok(ch) => dma_abort(ch),
            Err(e) => e,
        },
        spi9_raw::SEND => {
            // 9-bit SPI bit-bang: send command + data on three pins the
            // caller owns.
            if arg.len() < 5 {
                return E_INVAL;
            }
            let cs = arg[0];
            let sck = arg[1];
            let sda = arg[2];
            if let Err(e) = own_pins(&[cs, sck, sda]) {
                return e;
            }
            let cmd = arg[3];
            let data_len = arg[4] as usize;
            let Some(data) = arg.get(5..5 + data_len) else {
                return E_INVAL;
            };
            let hold_cs = arg.get(5 + data_len).is_some_and(|&h| h != 0);
            spi9_pac_send(cs, sck, sda, cmd, data, hold_cs);
            0
        }
        spi9_raw::RESET => {
            // 9-bit SPI reset: RST high->low->high + init SIO pins
            if arg.len() < 4 {
                return E_INVAL;
            }
            let rst = arg[0];
            let cs = arg[1];
            let sck = arg[2];
            let sda = arg[3];
            if let Err(e) = own_pins(&[rst, cs, sck, sda]) {
                return e;
            }
            spi9_pac_reset(rst, cs, sck, sda);
            0
        }
        spi9_raw::CS_SET => {
            // Set CS pin level: arg=[cs_pin:u8, level:u8]
            if arg.len() < 2 {
                return E_INVAL;
            }
            let cs = arg[0];
            if let Err(e) = own_pins(&[cs]) {
                return e;
            }
            let level = arg[1] != 0;
            spi9_pin_set(cs, level);
            0
        }
        // ── Raw bus bridges: SPI, I2C, UART, ADC ──────────────────────
        //
        // `handle` is the caller's claim of the bus (`raw_claim::CLAIM`);
        // its block and DREQs come from the silicon's generated tables. A
        // register offset is word-aligned and stays inside the block.
        spi_raw::REG_WRITE | i2c_raw::REG_WRITE | uart_raw::REG_WRITE | adc_raw::REG_WRITE => {
            if arg.len() < 5 {
                return E_INVAL;
            }
            let base = match bus_block(handle, opcode) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let offset = (arg[0] as usize) & 0xFC;
            let val = u32::from_le_bytes([arg[1], arg[2], arg[3], arg[4]]);
            // SAFETY: `base` is a block of this die the caller has claimed,
            // and the offset stays inside it.
            unsafe { write32(base + offset, val) };
            0
        }
        spi_raw::REG_READ | i2c_raw::REG_READ | uart_raw::REG_READ | adc_raw::REG_READ => {
            if arg.len() < 5 {
                return E_INVAL;
            }
            let base = match bus_block(handle, opcode) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let offset = (arg[0] as usize) & 0xFC;
            // SAFETY: as REG_WRITE.
            let bytes = unsafe { read32(base + offset) }.to_le_bytes();
            arg[1] = bytes[0];
            arg[2] = bytes[1];
            arg[3] = bytes[2];
            arg[4] = bytes[3];
            0
        }
        spi_raw::BUS_INFO => {
            // returns [tx_dreq u8][rx_dreq u8][0 u16][max_freq u32]
            if arg.len() < 8 {
                return E_INVAL;
            }
            let bus = match owned_instance(handle, family::SPI) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let (Some(base), Some((tx_dreq, rx_dreq))) = (chip::spi_base(bus), chip::spi_dreq(bus))
            else {
                return E_INVAL;
            };
            let _ = base;
            // SPI's ceiling is Fsys/2, so it moves with the system clock.
            let mf = (chip::SYS_CLK_HZ / 2).to_le_bytes();
            arg[..8].copy_from_slice(&[tx_dreq, rx_dreq, 0, 0, mf[0], mf[1], mf[2], mf[3]]);
            0
        }
        i2c_raw::BUS_INFO => {
            // returns [tx_dreq u8][rx_dreq u8][0 u16]
            if arg.len() < 4 {
                return E_INVAL;
            }
            let bus = match owned_instance(handle, family::I2C) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let (Some(base), Some((tx_dreq, rx_dreq))) = (chip::i2c_base(bus), chip::i2c_dreq(bus))
            else {
                return E_INVAL;
            };
            let _ = base;
            arg[..4].copy_from_slice(&[tx_dreq, rx_dreq, 0, 0]);
            0
        }
        spi_raw::PIN_INIT => {
            // arg=[clk:u8, mosi:u8, miso:u8]; 0xFF leaves a line unused.
            if arg.len() < 3 {
                return E_INVAL;
            }
            if let Err(e) = owned_instance(handle, family::SPI) {
                return e;
            }
            let pad = gpio_regs::PadConfig::default()
                .input_enable(true)
                .drive(gpio_regs::Drive::Ma4);
            bus_pins(&[arg[0], arg[1], arg[2]], FUNCSEL_SPI, pad)
        }
        i2c_raw::PIN_INIT => {
            // arg=[sda:u8, scl:u8]: open-drain lines, pulled up.
            if arg.len() < 2 {
                return E_INVAL;
            }
            if let Err(e) = owned_instance(handle, family::I2C) {
                return e;
            }
            let pad = gpio_regs::PadConfig::default()
                .input_enable(true)
                .schmitt(true)
                .pull_up(true)
                .drive(gpio_regs::Drive::Ma4);
            bus_pins(&[arg[0], arg[1]], FUNCSEL_I2C, pad)
        }
        uart_raw::PIN_INIT => {
            // arg=[tx:u8, rx:u8]
            if arg.len() < 2 {
                return E_INVAL;
            }
            if let Err(e) = owned_instance(handle, family::UART) {
                return e;
            }
            let pad = gpio_regs::PadConfig::default()
                .input_enable(true)
                .drive(gpio_regs::Drive::Ma4);
            bus_pins(&[arg[0], arg[1]], FUNCSEL_UART, pad)
        }
        adc_raw::PIN_INIT => {
            // arg=[pin:u8]: one of this die's ADC inputs, made analog.
            if arg.is_empty() {
                return E_INVAL;
            }
            if let Err(e) = owned_instance(handle, family::ADC) {
                return e;
            }
            let pin = arg[0];
            if !adc_pins().contains(&pin) {
                return E_INVAL;
            }
            // Analog: no digital input, never driven, no pulls.
            let pad = gpio_regs::PadConfig::default().output_disable(true);
            bus_pins(&[pin], FUNCSEL_NULL, pad)
        }
        i2c_raw::SET_ENABLE => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let base = match bus_block(handle, opcode) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: a claimed block of this die; IC_ENABLE is inside it.
            unsafe { write32(base + DW_I2C_ENABLE, u32::from(arg[0] != 0)) };
            0
        }
        uart_raw::SET_ENABLE => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let base = match bus_block(handle, opcode) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: a claimed block of this die; UARTCR is inside it.
            unsafe {
                let cr = read32(base + PL011_CR);
                let cr = if arg[0] != 0 {
                    cr | PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE
                } else {
                    cr & !PL011_CR_UARTEN
                };
                write32(base + PL011_CR, cr);
            }
            0
        }
        spi_raw::SET_ENABLE => {
            if arg.is_empty() {
                return E_INVAL;
            }
            let base = match bus_block(handle, opcode) {
                Ok(b) => b,
                Err(e) => return e,
            };
            // SAFETY: a claimed block of this die; SSPCR1 is inside it.
            unsafe {
                let cr1 = read32(base + PL022_CR1);
                let cr1 = if arg[0] != 0 {
                    cr1 | PL022_CR1_SSE
                } else {
                    cr1 & !PL022_CR1_SSE
                };
                write32(base + PL022_CR1, cr1);
            }
            0
        }
        flash::SIDEBAND => {
            use crate::abi::internal::flash::sideband_op as flash_sideband_op;
            if arg.is_empty() {
                return E_INVAL;
            }
            match arg[0] {
                flash_sideband_op::READ_CS => {
                    crate::platform::rp_flash::xip_lock::flash_sideband_read_cs()
                }
                flash_sideband_op::XIP_READ => {
                    // [op u8][offset u32] in; the bytes read go to `data`.
                    const FLASH_SIZE: u32 = crate::platform::chip::FLASH_SIZE;
                    let Some(offset) = le32(arg, 1) else {
                        return E_INVAL;
                    };
                    let out = data.as_mut();
                    if out.is_empty() || offset >= FLASH_SIZE {
                        return E_INVAL;
                    }
                    let n = out.len().min((FLASH_SIZE - offset) as usize);
                    // SAFETY: XIP maps the whole flash read-only at
                    // 0x1000_0000; `offset + n` stays inside it.
                    let src = unsafe {
                        core::slice::from_raw_parts((0x1000_0000u32 + offset) as *const u8, n)
                    };
                    out[..n].copy_from_slice(src);
                    n as i32
                }
                _ => E_NOSYS,
            }
        }
        flash::RAW_ERASE => {
            if arg.len() < 4 {
                return E_INVAL;
            }
            let offset = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]);
            crate::platform::rp_flash::store::raw_erase(offset)
        }
        flash::RAW_PROGRAM => {
            // [offset u32][page; 256]
            let (Some(offset), Some(page)) = (le32(arg, 0), arg.get(4..4 + 256)) else {
                return E_INVAL;
            };
            crate::platform::rp_flash::store::raw_program(offset, page)
        }
        // ── PLATFORM_DMA: fd family ──────────────────────────────────
        //
        // `fd::CREATE` answers the fd's index (`DMA_FD_BASE` plus its slot),
        // which the kernel wraps in a handle; every follow-up op is handed
        // it back.
        dma_raw::fd::CREATE => dma_fd_create(),
        dma_raw::fd::START => rc(dma_fd_start(handle, arg)),
        dma_raw::fd::RESTART => rc(dma_fd_restart(handle, arg)),
        dma_raw::fd::QUEUE => rc(dma_fd_queue(handle, arg)),
        dma_raw::fd::LIST_START => rc(dma_list_start(handle, arg)),
        dma_raw::fd::LIST_ARM => rc(dma_list_arm(handle, arg)),
        dma_raw::fd::LIST_STATUS => rc(dma_list_status(handle, arg)),
        dma_raw::fd::FREE => dma_fd_free(handle),
        // ── SYS_CLOCK_HZ ──
        SYS_CLOCK_HZ => match arg.get_mut(..4) {
            Some(out) => {
                out.copy_from_slice(&crate::platform::rp_clocks::measured_sys_hz().to_le_bytes());
                0
            }
            None => E_INVAL,
        },
        _ => E_NOSYS,
    }
}

// ============================================================================
// RP provider_query: GPIO levels, SYS_CLOCK_HZ
// ============================================================================

/// `provider_query` on a GPIO handle: `handle` is the pin its claim names.
fn gpio_query(handle: i32, key: u32, _out: &mut [u8]) -> i32 {
    match key {
        crate::abi::contracts::hal::gpio::GET_LEVEL if gpio::gpio_check_owner(handle) => {
            gpio::gpio_get_level(handle)
        }
        crate::abi::contracts::hal::gpio::GET_LEVEL => E_INVAL,
        _ => E_NOSYS,
    }
}

fn rp_dev_query_extension(_handle: i32, key: u32, out: &mut [u8]) -> i32 {
    use crate::abi::kernel_abi::SYS_CLOCK_HZ;
    use crate::kernel::module::provider::contract as dev_class;
    let class = ((key >> 8) & 0xFF) as u16;
    match class {
        dev_class::INTERNAL_DISPATCH_BUCKET => match key {
            SYS_CLOCK_HZ => match out.get_mut(..4) {
                Some(o) => {
                    o.copy_from_slice(&crate::platform::rp_clocks::measured_sys_hz().to_le_bytes());
                    0
                }
                None => E_INVAL,
            },
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
    // The vtables give each platform handle its close (and a DMA fd its
    // poll); the dispatch is the class registration's.
    provider::register_vtable(&GPIO_VTABLE);
    provider::register_vtable(&DMA_VTABLE);
    provider::register_vtable(&DMA_FD_VTABLE);
    provider::register_vtable(&RAW_VTABLE);
    provider::register_platform_handle_slots(platform_handle_slots);
    // PIO, SPI, I2C, UART, ADC, PWM providers are registered by the
    // loader when their PIC module's manifest names it in `provider_contracts`.
    // Register system extension for hardware opcodes (raw register bridges)
    register_system_extension(rp_system_extension_dispatch);
}

// HAL GPIO: open-style opcodes (CLAIM, SET_INPUT, SET_OUTPUT) answer the
// pin, WATCH_EDGE a watch index; close is RELEASE on either.
static GPIO_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_GPIO,
        call: gpio_provider_dispatch,
        query: Some(gpio_query),
        default_close_op: crate::abi::contracts::hal::gpio::RELEASE,
        poll: None,
    };

/// The class-routed platform contracts reach the kernel bucket; their vtables
/// give their handles a close and, for a DMA fd, a poll.
fn class_routed_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    crate::kernel::module::provider::dispatch(
        crate::kernel::module::provider::contract::INTERNAL_DISPATCH_BUCKET,
        handle,
        op,
        arg,
        data,
    )
}

static DMA_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::abi::registry::platform_dma::ID,
        call: class_routed_call,
        query: None,
        default_close_op: crate::abi::platform::rp::dma_raw::channel::FREE,
        poll: None,
    };

/// `HANDLE_POLL` on a DMA fd: readable when its active channel is idle.
fn dma_fd_poll(index: i32, events: u32) -> i32 {
    if events & crate::abi::kernel_abi::poll::IN != 0 && dma_fd_poll_ready(index) {
        crate::abi::kernel_abi::poll::IN as i32
    } else {
        0
    }
}

static DMA_FD_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::abi::registry::platform_dma_fd::ID,
        call: class_routed_call,
        query: None,
        default_close_op: crate::abi::platform::rp::dma_raw::fd::FREE,
        poll: Some(dma_fd_poll),
    };

static RAW_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::abi::registry::rp_raw::ID,
        call: class_routed_call,
        query: None,
        default_close_op: crate::abi::platform::rp::raw_claim::RELEASE,
        poll: None,
    };

/// Handles the RP platform's own provider tables can hand out at once: a
/// claim and a watch per pin, an allocatable DMA channel each, the DMA fds, a
/// claim per raw peripheral instance, and the kernel vault's key slots.
fn platform_handle_slots() -> usize {
    let pins = gpio::runtime_max_gpio() as usize;
    let channels = (implemented_channel_mask() & 0xFF00).count_ones() as usize;
    2 * pins + channels + MAX_DMA_FDS + RAW_SLOTS + crate::kernel::security::key_vault::MAX_SLOTS
}

/// Release all RP-specific hardware handles owned by a module.
fn release_rp_handles(module_idx: ModuleId) {
    release_raw_claims_owned_by(module_idx);
    release_channels_owned_by(module_idx);
    gpio::release_owned_by(module_idx);
}

// ============================================================================
// Raw peripheral claims
// ============================================================================
//
// A raw register bridge acts on one peripheral instance — a PIO block, a PWM
// slice, an SPI, I2C or UART bus, the ADC — and only on one the caller has
// claimed. `raw_claim::CLAIM` gives the instance to the first module that
// asks and returns a handle the kernel checks on every op; a second claimant
// is refused. Pins are owned the same way through the GPIO table: a raw op
// configures only a pin the caller holds, taking a free one for it.

/// Instances of `f` this die has.
const fn family_count(f: u8) -> usize {
    match f {
        family::PIO => chip::PIO_COUNT as usize,
        family::PWM => chip::PWM_SLICES as usize,
        family::SPI => chip::SPI_COUNT as usize,
        family::I2C => chip::I2C_COUNT as usize,
        family::UART => chip::UART_COUNT as usize,
        family::ADC => 1,
        _ => 0,
    }
}

/// Where family `f`'s instances start in [`RAW_OWNER`].
const fn family_first(f: u8) -> usize {
    let mut i = 0u8;
    let mut at = 0usize;
    while i < f {
        at += family_count(i);
        i += 1;
    }
    at
}

/// Every instance of every family.
const RAW_SLOTS: usize = family_first(family::ADC + 1);

/// The module holding each instance; `NO_MODULE` when none does.
static RAW_OWNER: [AtomicU16; RAW_SLOTS] = [const { AtomicU16::new(NO_MODULE) }; RAW_SLOTS];

/// Instance `instance` of `f`'s place in [`RAW_OWNER`], if the die has it.
fn raw_slot(f: u8, instance: u8) -> Option<usize> {
    ((instance as usize) < family_count(f)).then(|| family_first(f) + instance as usize)
}

/// Claim instance `instance` of `f` for the module being stepped: its index
/// (`[family u8][instance u8]`, which the kernel wraps in a handle),
/// `EBUSY` when another module holds it, `EINVAL` for one the die lacks.
fn raw_claim_instance(f: u8, instance: u8) -> i32 {
    let Some(slot) = raw_slot(f, instance) else {
        return E_INVAL;
    };
    let me = crate::kernel::exec::scheduler::current_module_id();
    match RAW_OWNER[slot].compare_exchange(NO_MODULE, me, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(owner) if owner == me => {}
        Err(_) => return errno::EBUSY,
    }
    (i32::from(f) << 8) | i32::from(instance)
}

/// The instance of `f` that `handle` claims for the module being stepped;
/// `EBADF` for any handle that is not that.
fn owned_instance(handle: i32, f: u8) -> Result<u8, i32> {
    if handle < 0 {
        return Err(errno::EBADF);
    }
    let (hf, instance) = ((handle >> 8) as u8, (handle & 0xFF) as u8);
    if handle >> 16 != 0 || hf != f {
        return Err(errno::EBADF);
    }
    let owner = raw_slot(f, instance).map(|s| RAW_OWNER[s].load(Ordering::Acquire));
    if owner != Some(crate::kernel::exec::scheduler::current_module_id()) {
        return Err(errno::EBADF);
    }
    Ok(instance)
}

/// As [`owned_instance`], for an op whose argument also names the instance:
/// the two must agree.
fn owned_named(handle: i32, f: u8, named: u8) -> Result<u8, i32> {
    let instance = owned_instance(handle, f)?;
    if instance != named {
        return Err(E_INVAL);
    }
    Ok(instance)
}

/// The register block of the PIO instance `pio_num` the caller has claimed.
fn owned_pio(handle: i32, pio_num: u8) -> Result<usize, i32> {
    owned_named(handle, family::PIO, pio_num)?;
    pio_regs::instance(pio_num).ok_or(E_INVAL)
}

/// Release the claim `handle` names.
fn raw_release(handle: i32) -> i32 {
    let f = (handle >> 8) as u8;
    match owned_instance(handle, f) {
        Ok(instance) => {
            if let Some(s) = raw_slot(f, instance) {
                RAW_OWNER[s].store(NO_MODULE, Ordering::Release);
            }
            0
        }
        Err(e) => e,
    }
}

/// Release every instance `module` claimed.
fn release_raw_claims_owned_by(module: ModuleId) {
    for owner in RAW_OWNER.iter() {
        let _ = owner.compare_exchange(module, NO_MODULE, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Make each pin the caller's: one it holds, or a free one it now takes.
/// `EBUSY` when another module holds one, `EINVAL` past the die's pins.
fn own_pins(pins: &[u8]) -> Result<(), i32> {
    let me = crate::kernel::exec::scheduler::current_module_id();
    for &pin in pins {
        if pin >= gpio::runtime_max_gpio() {
            return Err(E_INVAL);
        }
        if gpio::gpio_is_claimed(pin) {
            if gpio::gpio_owner(pin) != me {
                return Err(errno::EBUSY);
            }
            continue;
        }
        if gpio::gpio_claim(pin) < 0 {
            return Err(errno::EBUSY);
        }
        gpio::gpio_set_owner(pin, me);
    }
    Ok(())
}

/// The register block of the bus a bus op's `handle` claims.
fn bus_block(handle: i32, opcode: u32) -> Result<usize, i32> {
    use crate::abi::platform::rp::{adc_raw, i2c_raw, spi_raw, uart_raw};
    let f = match opcode {
        spi_raw::REG_WRITE | spi_raw::REG_READ | spi_raw::SET_ENABLE => family::SPI,
        i2c_raw::REG_WRITE | i2c_raw::REG_READ | i2c_raw::SET_ENABLE => family::I2C,
        uart_raw::REG_WRITE | uart_raw::REG_READ | uart_raw::SET_ENABLE => family::UART,
        adc_raw::REG_WRITE | adc_raw::REG_READ => family::ADC,
        _ => return Err(E_INVAL),
    };
    let instance = owned_instance(handle, f)?;
    let base = match f {
        family::SPI => chip::spi_base(instance),
        family::I2C => chip::i2c_base(instance),
        family::UART => chip::uart_base(instance),
        _ => Some(chip::ADC_BASE as usize),
    };
    base.ok_or(E_INVAL)
}

/// Route `pins` (0xFF: an unused line) to function `funcsel` with pad
/// `pad`, once the caller owns every one.
fn bus_pins(pins: &[u8], funcsel: u32, pad: gpio_regs::PadConfig) -> i32 {
    let mut used = [0u8; 4];
    let mut n = 0;
    for &pin in pins.iter().filter(|&&p| p != 0xFF) {
        used[n] = pin;
        n += 1;
    }
    if let Err(e) = own_pins(&used[..n]) {
        return e;
    }
    for &pin in &used[..n] {
        // SAFETY: a pin of this die the caller owns.
        unsafe {
            gpio_regs::write_pad(pin, pad);
            gpio_regs::set_function(pin, funcsel);
        }
    }
    0
}

/// The pins this die's ADC samples: 26–29 on the 30-pin parts, 40–47 on
/// RP2350B.
fn adc_pins() -> core::ops::RangeInclusive<u8> {
    if gpio::runtime_max_gpio() > 30 {
        40..=47
    } else {
        26..=29
    }
}
