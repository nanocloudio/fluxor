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
// Low-level BOOTSEL read (RP2350 QMI direct mode approach)
// ============================================================================

/// Read the BOOTSEL button state on RP2350.
///
/// On RP2350, QMI has a dedicated pad driver on the flash CS path.
/// This routine places QMI in direct mode and temporarily configures
/// the QSPI SS pad for input so the pad level can be sampled reliably.
///
/// Current implementation derives the pressed state from
/// SIO GPIO_HI_IN bit 27 (QSPI SS) sampled while QMI direct mode is active.
/// IO_QSPI GPIO_STATUS.INFROMPAD is logged for diagnostics.
///
/// Sequence:
///  1. Put QMI in direct mode (DIRECT_CSR.EN=1) with CS not asserted
///  2. This stops QMI from driving the CS pad
///  3. Read SIO GPIO_HI_IN (bit 27 = QSPI SS) and IO_QSPI STATUS for diagnostics
///  4. Restore QMI to normal XIP operation
///
/// Returns 0 (not pressed) or 1 (pressed).
fn read_bootsel() -> i32 {
    use embassy_rp::pac;

    let mut sio_hi_sample: u32 = 0;

    cortex_m::interrupt::free(|_| {
        // Wait for all DMA channels reading from flash to finish.
        const SRAM_LOWER: u32 = 0x2000_0000;
        for n in 0..16 {
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

    // QSPI SS is bit 27 of SIO GPIO_HI_IN.
    // BOOTSEL is active-low: pressed when this bit is LOW.
    if (sio_hi_sample >> 27) & 1 == 0 { 1 } else { 0 }
}

/// RAM-resident BOOTSEL read for RP2350.
///
/// 1. Save QMI_CSR, PADS_QSPI_SS, IO_QSPI_SS_CTRL
/// 2. QMI direct mode (releases dedicated pad driver)
/// 3. PADS OD=1, IE=1, PUE=1 (disable pad output, enable input + pull-up)
/// 4. OEOVER=DISABLE + FUNCSEL=SIO (0x8005)
/// 5. Delay, read IO_QSPI_SS_STATUS + SIO_GPIO_HI_IN, restore all
///
/// # Safety
/// Must be called within a critical section with flash DMA idle.
#[inline(never)]
#[link_section = ".data.ram_func"]
unsafe fn read_bootsel_io_qspi() -> (u32, u32) {
    const IO_QSPI_SS_STATUS: *const u32 = 0x4003_0008 as *const u32;
    const IO_QSPI_SS_CTRL: *mut u32 = 0x4003_000C as *mut u32;
    const QMI_DIRECT_CSR: *mut u32 = 0x400D_0000 as *mut u32;
    // PADS_QSPI GPIO_QSPI_SS register.
    const PADS_QSPI_SS: *mut u32 = 0x4004_0018 as *mut u32;
    const SIO_GPIO_HI_IN: *const u32 = 0xD000_0008 as *const u32;

    // Save original register values
    let orig_ctrl = core::ptr::read_volatile(IO_QSPI_SS_CTRL);
    let orig_qmi = core::ptr::read_volatile(QMI_DIRECT_CSR);
    let orig_pad = core::ptr::read_volatile(PADS_QSPI_SS);

    // QMI direct mode: EN=1, CS not asserted
    core::ptr::write_volatile(QMI_DIRECT_CSR, 0x01);

    // PADS: OD=1(7), IE=1(6), PUE=1(3), SCHMITT=1(1) = 0xCA
    core::ptr::write_volatile(PADS_QSPI_SS, 0xCA);

    // IO_QSPI CTRL: OEOVER=DISABLE + FUNCSEL=SIO (5) = 0x8005
    core::ptr::write_volatile(IO_QSPI_SS_CTRL, 0x8005);

    // Settle delay (~4000 cycles)
    // CRITICAL: Use inline asm directly — cortex_m::asm functions live in
    // flash and get called via linker thunks. Since QMI is in direct mode
    // here (flash inaccessible), calling into flash would hard fault.
    // The XIP cache may mask this bug for some binary layouts but not others.
    core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags));
    for _ in 0..1000u32 {
        core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    }

    // Sample while direct mode is active
    let status = core::ptr::read_volatile(IO_QSPI_SS_STATUS);
    let sio_hi = core::ptr::read_volatile(SIO_GPIO_HI_IN);

    // Restore (CTRL first, then PADS, then QMI last)
    core::ptr::write_volatile(IO_QSPI_SS_CTRL, orig_ctrl);
    core::ptr::write_volatile(PADS_QSPI_SS, orig_pad);
    core::ptr::write_volatile(QMI_DIRECT_CSR, orig_qmi);

    // Ensure QMI has fully exited direct mode before returning.
    // Without this barrier, the first instruction fetch from flash after
    // return may race the QMI register write and hit a bus fault or stale
    // data. The DSB ensures the peripheral write completes; the ISB flushes
    // the instruction pipeline so subsequent fetches use the restored QMI.
    core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags));
    core::arch::asm!("isb sy", options(nomem, nostack, preserves_flags));

    (status, sio_hi)
}
