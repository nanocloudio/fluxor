//! Kernel resource locking and flash sideband operations.
//!
//! Provides exclusive access to named critical resources (e.g., FLASH_XIP)
//! and sideband operations that require exclusive resource access.
//!
//! The resource lock is a lightweight CAS-based mechanism. On the single-core
//! cooperative scheduler, contention only arises when a module holds a lock
//! across step() boundaries (which is discouraged for FLASH_XIP).
//!
//! Flash sideband operations (e.g., BOOTSEL button read) use an atomic
//! lock-read-unlock pattern: acquire FLASH_XIP, perform the operation with
//! interrupts disabled, release. The QSPI CS read technique follows the
//! same approach as embassy-rp's bootsel module.

use portable_atomic::{AtomicU8, AtomicU32, Ordering};
use crate::kernel::errno;

/// Maximum number of lockable resources.
const MAX_RESOURCES: usize = 4;

/// Free / no owner marker.
const OWNER_FREE: u8 = 0xFF;

/// Resource IDs (must match abi::resource_id).
const RESOURCE_FLASH_XIP: usize = 0;

/// Resource lock slot.
struct ResourceSlot {
    /// Owner module index, or OWNER_FREE if unlocked.
    owner: AtomicU8,
}

impl ResourceSlot {
    const fn new() -> Self {
        Self {
            owner: AtomicU8::new(OWNER_FREE),
        }
    }
}

static RESOURCE_SLOTS: [ResourceSlot; MAX_RESOURCES] =
    [const { ResourceSlot::new() }; MAX_RESOURCES];

// ============================================================================
// Public API
// ============================================================================

/// Attempt to lock a resource. Returns lock handle (= resource_id) or EBUSY.
pub fn try_lock(resource_id: u8) -> i32 {
    let idx = resource_id as usize;
    if idx >= MAX_RESOURCES {
        return errno::EINVAL;
    }
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    match RESOURCE_SLOTS[idx].owner.compare_exchange(
        OWNER_FREE,
        owner,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => idx as i32,
        Err(_) => errno::EBUSY,
    }
}

/// Unlock a resource. handle = resource_id returned from try_lock.
pub fn unlock(handle: i32) -> i32 {
    if handle < 0 || handle as usize >= MAX_RESOURCES {
        return errno::EINVAL;
    }
    let slot = &RESOURCE_SLOTS[handle as usize];
    let owner = crate::kernel::scheduler::current_module_index() as u8;
    match slot.owner.compare_exchange(
        owner,
        OWNER_FREE,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => 0,
        Err(_) => errno::EINVAL, // Not the owner
    }
}

/// Reset all resource locks. Called on graph teardown / reload.
pub fn reset_all() {
    for slot in &RESOURCE_SLOTS {
        slot.owner.store(OWNER_FREE, Ordering::Release);
    }
}

/// Flash sideband: read QSPI CS pin (BOOTSEL button).
///
/// This operation internally acquires FLASH_XIP for the duration of the
/// register manipulation (~4000 cycles with interrupts disabled).
///
/// Rate-limited: the actual QMI direct-mode read happens at most every
/// BOOTSEL_POLL_INTERVAL_MS milliseconds. Intermediate calls return the
/// cached result. This prevents rapid QMI direct-mode cycling from
/// disrupting XIP cache coherence during CYW43 firmware loading.
///
/// Returns 0 (not pressed) or 1 (pressed), or EAGAIN if resource busy.
pub fn flash_sideband_read_cs() -> i32 {
    // Rate-limit: only do the expensive QMI read every N calls.
    // At 1ms tick rate, 20 calls ≈ 20ms — plenty fast for button debounce.
    const BOOTSEL_POLL_DIVISOR: u32 = 20;
    static CALL_COUNT: AtomicU32 = AtomicU32::new(0);
    static CACHED_RESULT: AtomicU8 = AtomicU8::new(0);

    let count = CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    if count % BOOTSEL_POLL_DIVISOR != 0 {
        return CACHED_RESULT.load(Ordering::Relaxed) as i32;
    }

    let owner = crate::kernel::scheduler::current_module_index() as u8;
    let slot = &RESOURCE_SLOTS[RESOURCE_FLASH_XIP];

    // Atomic short-term lock: try-lock, do the read, then unlock.
    // If already locked by someone else, return EAGAIN.
    let prev = slot.owner.compare_exchange(
        OWNER_FREE,
        owner,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    let was_free = prev.is_ok();
    let already_ours = prev == Err(owner);

    if !was_free && !already_ours {
        return errno::EAGAIN;
    }

    let result = read_bootsel();

    // Only unlock if we acquired it in this call
    if was_free {
        slot.owner.store(OWNER_FREE, Ordering::Release);
    }

    // Cache for rate-limited intermediate reads
    if result >= 0 {
        CACHED_RESULT.store(result as u8, Ordering::Relaxed);
    }

    result
}

// ============================================================================
// Low-level BOOTSEL read
// ============================================================================

/// Read the BOOTSEL button state.
///
/// Temporarily disconnects flash and samples the QSPI SS pad as a GPIO input.
/// Must run entirely from RAM with interrupts disabled.
///
/// Returns 0 (not pressed) or 1 (pressed).
fn read_bootsel() -> i32 {
    use embassy_rp::pac;
    use super::chip;

    let mut sio_hi_sample: u32 = 0;

    cortex_m::interrupt::free(|_| {
        // Wait for all DMA channels reading from flash to finish.
        const SRAM_LOWER: u32 = 0x2000_0000;
        for n in 0..chip::BOOTSEL_DMA_CH_COUNT {
            let ch = pac::DMA.ch(n);
            if ch.read_addr().read() < SRAM_LOWER && ch.ctrl_trig().read().busy() {
                while ch.read_addr().read() < SRAM_LOWER && ch.ctrl_trig().read().busy() {}
            }
        }
        // Wait for any XIP streaming to complete
        while pac::XIP_CTRL.stream_ctr().read().0 > 0 {}

        let (_status, sio) = unsafe { read_bootsel_io_qspi() };
        sio_hi_sample = sio;
    });

    // BOOTSEL is active-low: pressed when the QSPI SS bit is LOW.
    if (sio_hi_sample >> chip::BOOTSEL_QSPI_SS_BIT) & 1 == 0 { 1 } else { 0 }
}

// ============================================================================
// RAM-resident BOOTSEL IO read
// ============================================================================

/// Temporarily release flash CS and sample QSPI SS as GPIO input.
///
/// All register addresses and values come from the silicon TOML via
/// chip_generated.rs. The algorithm is identical for RP2040 (XIP_SSI disable)
/// and RP2350 (QMI direct mode) — only the addresses/values differ.
///
/// # Safety
/// Must be called within a critical section with flash DMA idle.
#[inline(never)]
#[link_section = ".data.ram_func"]
unsafe fn read_bootsel_io_qspi() -> (u32, u32) {
    use super::chip;

    // Save originals
    let orig_ctrl = core::ptr::read_volatile(chip::BOOTSEL_CTRL_ADDR as *const u32);
    let orig_release = core::ptr::read_volatile(chip::BOOTSEL_FLASH_RELEASE_ADDR as *const u32);
    let orig_pad = core::ptr::read_volatile(chip::BOOTSEL_PAD_ADDR as *const u32);

    // Release flash CS (disable XIP_SSI on RP2040, enter QMI direct mode on RP2350)
    core::ptr::write_volatile(chip::BOOTSEL_FLASH_RELEASE_ADDR as *mut u32, chip::BOOTSEL_FLASH_RELEASE_VALUE);
    // Configure pad: OD=1, IE=1, PUE=1, SCHMITT=1
    core::ptr::write_volatile(chip::BOOTSEL_PAD_ADDR as *mut u32, chip::BOOTSEL_PAD_VALUE);
    // IO control: output disable + SIO funcsel
    core::ptr::write_volatile(chip::BOOTSEL_CTRL_ADDR as *mut u32, chip::BOOTSEL_CTRL_VALUE);

    // Settle delay (~4000 cycles)
    core::arch::asm!("dsb", options(nomem, nostack, preserves_flags));
    for _ in 0..1000u32 {
        core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    }

    // Sample
    let status = core::ptr::read_volatile(chip::BOOTSEL_STATUS_ADDR as *const u32);
    let sio_hi = core::ptr::read_volatile(chip::BOOTSEL_GPIO_HI_ADDR as *const u32);

    // Restore (ctrl first, pad, flash release last)
    core::ptr::write_volatile(chip::BOOTSEL_CTRL_ADDR as *mut u32, orig_ctrl);
    core::ptr::write_volatile(chip::BOOTSEL_PAD_ADDR as *mut u32, orig_pad);
    core::ptr::write_volatile(chip::BOOTSEL_FLASH_RELEASE_ADDR as *mut u32, orig_release);

    core::arch::asm!("dsb", options(nomem, nostack, preserves_flags));
    core::arch::asm!("isb", options(nomem, nostack, preserves_flags));

    (status, sio_hi)
}
