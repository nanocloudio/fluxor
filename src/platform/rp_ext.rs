//! RP platform extension — wraps rp_providers.rs in the kernel namespace.
//!
//! This module is only compiled for RP targets (via cfg in mod.rs).
//! It provides init_rp_providers() and release_rp_handles() called
//! through the HAL dispatch table.
//!
//! Also contains DMA channel allocation and DMA FD operations that
//! were previously cfg-gated in syscalls.rs and fd.rs.

use portable_atomic::{AtomicU16, Ordering, compiler_fence};

use crate::kernel::errno;
use crate::kernel::gpio;
use crate::kernel::syscalls::{register_system_extension, register_dev_query_extension};
use crate::kernel::fd;

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;
const E_NOMEM: i32 = errno::ENOMEM;

// ============================================================================
// DMA channel allocation
// ============================================================================

/// Bitmap of allocated DMA channels. CH0-CH7 pre-marked at boot.
static DMA_CHANNELS_USED: AtomicU16 = AtomicU16::new(0x00FF); // CH0-CH7 reserved

pub(crate) fn dma_alloc_channel() -> i32 {
    loop {
        let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
        let free_mask = !used & 0xFF00;
        if free_mask == 0 {
            return E_NOMEM;
        }
        let ch = free_mask.trailing_zeros() as u16;
        let bit = 1u16 << ch;
        if DMA_CHANNELS_USED.compare_exchange(
            used, used | bit,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        ).is_ok() {
            return ch as i32;
        }
    }
}

pub(crate) fn dma_free_channel(ch: u8) -> i32 {
    if ch < 8 || ch > 15 { return E_INVAL; }
    let bit = 1u16 << ch;
    DMA_CHANNELS_USED.fetch_and(!bit, core::sync::atomic::Ordering::Release);
    0
}

pub(crate) unsafe fn dma_start_raw(ch: u8, read_addr: u32, write_addr: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
    if used & (1u16 << ch) == 0 { return E_INVAL; }

    use embassy_rp::pac;
    let dma_ch = pac::DMA.ch(ch as usize);
    dma_ch.read_addr().write_value(read_addr);
    dma_ch.write_addr().write_value(write_addr);
    super::chip::dma_write_trans_count(&dma_ch, count);
    compiler_fence(Ordering::SeqCst);

    let incr_read = flags & 0x01 != 0;
    let incr_write = flags & 0x02 != 0;
    let data_size = if flags & 0x04 != 0 {
        pac::dma::vals::DataSize::SIZE_WORD
    } else {
        pac::dma::vals::DataSize::SIZE_HALFWORD
    };

    dma_ch.ctrl_trig().write(|w| {
        w.set_treq_sel(pac::dma::vals::TreqSel::from(dreq));
        w.set_data_size(data_size);
        w.set_incr_read(incr_read);
        w.set_incr_write(incr_write);
        w.set_chain_to(ch);
        w.set_en(true);
    });
    compiler_fence(Ordering::SeqCst);
    0
}

fn dma_busy(ch: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    if pac::DMA.ch(ch as usize).ctrl_trig().read().busy() { 1 } else { 0 }
}

pub(crate) fn dma_abort(ch: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    pac::DMA.chan_abort().write(|w| w.0 = 1u32 << ch);
    while pac::DMA.ch(ch as usize).ctrl_trig().read().busy() {}
    0
}

pub(crate) unsafe fn dma_restart_raw(ch: u8, read_addr: u32, count: u32) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    let dma_ch = pac::DMA.ch(ch as usize);
    compiler_fence(Ordering::SeqCst);
    dma_ch.al3_trans_count().write_value(count);
    dma_ch.al3_read_addr_trig().write_value(read_addr);
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
    if ch_a < 0 { return ch_a; }
    let ch_b = dma_alloc_channel();
    if ch_b < 0 {
        dma_free_channel(ch_a as u8);
        return ch_b;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    for i in 0..MAX_DMA_FDS {
        if DMA_FD_SLOTS[i]
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            DMA_FD_SLOTS[i].owner.store(owner, Ordering::Release);
            DMA_FD_SLOTS[i].channel_a.store(ch_a as u8, Ordering::Release);
            DMA_FD_SLOTS[i].channel_b.store(ch_b as u8, Ordering::Release);
            DMA_FD_SLOTS[i].active_is_b.store(false, Ordering::Release);
            DMA_FD_SLOTS[i].pending.store(false, Ordering::Release);
            return fd::tag_fd(fd::FD_TAG_DMA, i as i32);
        }
    }
    dma_free_channel(ch_a as u8);
    dma_free_channel(ch_b as u8);
    errno::ENOMEM
}

pub fn dma_fd_start(fd_handle: i32, read_addr: u32, write_addr: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS { return E_INVAL; }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) { return E_INVAL; }
    let ch_a = dma.channel_a.load(Ordering::Acquire);
    let ch_b = dma.channel_b.load(Ordering::Acquire);
    let rc = unsafe { dma_start_raw(ch_a, read_addr, write_addr, count, dreq, flags) };
    if rc < 0 { return rc; }
    unsafe { dma_preconfigure_inactive(ch_b, write_addr, dreq, flags); }
    dma.active_is_b.store(false, Ordering::Release);
    dma.pending.store(false, Ordering::Release);
    rc
}

unsafe fn dma_preconfigure_inactive(ch: u8, write_addr: u32, dreq: u8, flags: u8) {
    use embassy_rp::pac;
    let dma_ch = pac::DMA.ch(ch as usize);
    dma_ch.write_addr().write_value(write_addr);
    let incr_read = flags & 0x01 != 0;
    let incr_write = flags & 0x02 != 0;
    let data_size = if flags & 0x04 != 0 {
        pac::dma::vals::DataSize::SIZE_WORD
    } else {
        pac::dma::vals::DataSize::SIZE_HALFWORD
    };
    let mut ctrl = pac::dma::regs::CtrlTrig(0);
    ctrl.set_en(true);
    ctrl.set_incr_read(incr_read);
    ctrl.set_incr_write(incr_write);
    ctrl.set_data_size(data_size);
    ctrl.set_treq_sel(pac::dma::vals::TreqSel::from(dreq));
    ctrl.set_chain_to(ch);
    dma_ch.al1_ctrl().write_value(ctrl.0);
}

pub fn dma_fd_queue(fd_handle: i32, read_addr: u32, count: u32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS { return E_INVAL; }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) { return E_INVAL; }
    let active = dma.active_ch();
    let inactive = dma.inactive_ch();
    {
        use embassy_rp::pac;
        let inactive_ch = pac::DMA.ch(inactive as usize);
        let active_ch = pac::DMA.ch(active as usize);
        inactive_ch.read_addr().write_value(read_addr);
        super::chip::dma_write_trans_count(&inactive_ch, count);
        compiler_fence(Ordering::SeqCst);
        let mut ctrl = pac::dma::regs::CtrlTrig(active_ch.al1_ctrl().read());
        ctrl.set_chain_to(inactive);
        active_ch.al1_ctrl().write_value(ctrl.0);
        compiler_fence(Ordering::SeqCst);
        if !active_ch.ctrl_trig().read().busy() {
            inactive_ch.al3_trans_count().write_value(count);
            inactive_ch.al3_read_addr_trig().write_value(read_addr);
            ctrl.set_chain_to(active);
            active_ch.al1_ctrl().write_value(ctrl.0);
            dma.active_is_b.store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        }
    }
    dma.pending.store(true, Ordering::Release);
    0
}

pub fn dma_fd_restart(fd_handle: i32, read_addr: u32, count: u32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS { return E_INVAL; }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) { return E_INVAL; }
    let ch = dma.active_ch();
    unsafe { dma_restart_raw(ch, read_addr, count) }
}

pub fn dma_fd_free(fd_handle: i32) -> i32 {
    let slot = fd::slot_of(fd_handle);
    if slot < 0 || slot as usize >= MAX_DMA_FDS { return E_INVAL; }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) { return E_INVAL; }
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
    if slot < 0 || slot as usize >= MAX_DMA_FDS { return false; }
    let dma = &DMA_FD_SLOTS[slot as usize];
    if !dma.allocated.load(Ordering::Acquire) { return false; }
    let active = dma.active_ch();
    use embassy_rp::pac;
    if pac::DMA.ch(active as usize).ctrl_trig().read().busy() { return false; }
    if dma.pending.load(Ordering::Acquire) {
        let dma_ch = pac::DMA.ch(active as usize);
        let mut ctrl = pac::dma::regs::CtrlTrig(dma_ch.al1_ctrl().read());
        ctrl.set_chain_to(active);
        dma_ch.al1_ctrl().write_value(ctrl.0);
        dma.active_is_b.store(!dma.active_is_b.load(Ordering::Acquire), Ordering::Release);
        dma.pending.store(false, Ordering::Release);
    }
    true
}

pub fn release_dma_fds_owned_by(module_idx: u8) {
    for i in 0..MAX_DMA_FDS {
        let dma = &DMA_FD_SLOTS[i];
        if !dma.allocated.load(Ordering::Acquire) { continue; }
        if dma.owner.load(Ordering::Acquire) != module_idx { continue; }
        let ch_a = dma.channel_a.load(Ordering::Acquire);
        let ch_b = dma.channel_b.load(Ordering::Acquire);
        if ch_a != 0xFF { dma_abort(ch_a); dma_free_channel(ch_a); }
        if ch_b != 0xFF { dma_abort(ch_b); dma_free_channel(ch_b); }
        dma.channel_a.store(0xFF, Ordering::Release);
        dma.channel_b.store(0xFF, Ordering::Release);
        dma.pending.store(false, Ordering::Release);
        dma.active_is_b.store(false, Ordering::Release);
        dma.owner.store(0xFF, Ordering::Release);
        dma.allocated.store(false, Ordering::Release);
    }
}

// ============================================================================
// RP Platform Providers (included from rp_providers.rs)
// ============================================================================

include!("../platform/rp_providers.rs");

// ============================================================================
// Public API
// ============================================================================

pub fn init() {
    init_rp_providers();
    // Register DMA FD poll function with the fd subsystem
    fd::register_dma_fd_poll(dma_fd_poll_ready);
    // Register dev_query extension for GPIO and SYS_CLOCK_HZ
    register_dev_query_extension(rp_dev_query_extension);
}

pub fn release_handles(module_idx: u8) {
    release_rp_handles(module_idx);
    release_dma_fds_owned_by(module_idx);
}
