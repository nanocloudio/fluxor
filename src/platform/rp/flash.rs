//! RP flash support.

use crate::kernel::chip;

pub mod store {
    //! Runtime parameter store — boot scan, merge, and flash hardware bridge.
    //!
    //! The store occupies the last 4KB sector of flash. At boot, `boot_scan()`
    //! reads the sector and `merge_runtime_overrides()` appends matching entries
    //! into PARAM_BUFFER before each module's `module_new()`.
    //!
    //! Domain logic (store, delete, clear, compact) lives in the flash PIC module.
    //! The kernel provides raw flash erase/program bridge syscalls and a dispatch
    //! shim that forwards PARAM_STORE/DELETE/CLEAR_ALL to the flash module's
    //! registered dispatch function.

    use crate::abi::platform::rp::flash_layout;

    // ============================================================================
    // Constants
    // ============================================================================

    const STORE_XIP: *const u8 =
        (flash_layout::XIP_BASE + flash_layout::PARAM_STORE_OFFSET) as *const u8;
    const SECTOR_SIZE: usize = flash_layout::PARAM_STORE_SIZE; // 4096
    const HEADER_SIZE: usize = 8;
    const ENTRY_HEADER_SIZE: usize = 4; // module_id + tag + flags + value_len
    const PAGE_SIZE: usize = 256;

    /// Maximum number of active override entries tracked at boot.
    /// 16 modules x 2 params each = 32 entries max in practice.
    const MAX_OVERRIDES: usize = 32;

    /// Arena for copying override values from XIP into RAM.
    /// Used at boot so values survive any later flash writes.
    const OVERRIDE_ARENA_SIZE: usize = 368;

    // Entry flags
    const FLAG_TOMBSTONE: u8 = 0x01;
    const FLAG_CLEAR_ALL: u8 = 0x02;

    // ============================================================================
    // Static storage
    // ============================================================================

    /// Boot-time override table: populated by boot_scan(), consumed during merge.
    static mut BOOT_OVERRIDES: OverrideTable = OverrideTable::empty();

    /// Arena for override value copies (so they survive any later flash writes).
    static mut OVERRIDE_ARENA: [u8; OVERRIDE_ARENA_SIZE] = [0u8; OVERRIDE_ARENA_SIZE];
    static mut OVERRIDE_ARENA_OFFSET: usize = 0;

    /// Cached free offset within the sector (set by boot_scan).
    static mut FREE_OFFSET: usize = 0;

    // ============================================================================
    // Flash store dispatch — registered by flash module at runtime
    // ============================================================================

    /// Dispatch function signature: (state, opcode, arg, arg_len) -> i32.
    /// Matches the flash module's `flash_store_dispatch` export.
    pub type FlashStoreDispatchFn =
        unsafe extern "C" fn(state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

    /// Registered dispatch function (None = flash module not wired).
    static mut STORE_DISPATCH: Option<FlashStoreDispatchFn> = None;
    /// State pointer for the registered dispatch function.
    static mut STORE_STATE: *mut u8 = core::ptr::null_mut();

    /// Register the flash module's dispatch function. Called via FLASH_STORE_ENABLE.
    pub fn register_dispatch(dispatch: FlashStoreDispatchFn, state: *mut u8) -> i32 {
        unsafe {
            let p = &raw const STORE_DISPATCH;
            if (*p).is_some() {
                return crate::kernel::errno::EBUSY;
            }
            STORE_DISPATCH = Some(dispatch);
            STORE_STATE = state;
        }
        0
    }

    /// Forward a param operation to the flash module's dispatch function.
    /// Returns ENOSYS if no flash module is registered.
    pub fn dispatch_param_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
        unsafe {
            match STORE_DISPATCH {
                Some(dispatch) => dispatch(STORE_STATE, opcode, arg, arg_len),
                None => crate::kernel::errno::ENOSYS,
            }
        }
    }

    // ============================================================================
    // Override table (boot-time data)
    // ============================================================================

    #[derive(Clone, Copy)]
    struct OverrideEntry {
        module_id: u8,
        tag: u8,
        value_ptr: *const u8, // points into OVERRIDE_ARENA
        value_len: u8,
    }

    struct OverrideTable {
        entries: [OverrideEntry; MAX_OVERRIDES],
        count: usize,
        valid: bool,
    }

    impl OverrideTable {
        const fn empty() -> Self {
            Self {
                entries: [OverrideEntry {
                    module_id: 0,
                    tag: 0,
                    value_ptr: core::ptr::null(),
                    value_len: 0,
                }; MAX_OVERRIDES],
                count: 0,
                valid: false,
            }
        }
    }

    // ============================================================================
    // Boot scan — called once at startup
    // ============================================================================

    /// Scan the runtime store sector and populate BOOT_OVERRIDES.
    ///
    /// Reads via XIP (no flash write needed). Copies active override values
    /// into OVERRIDE_ARENA so they remain valid if flash is later modified.
    pub fn boot_scan() {
        unsafe {
            OVERRIDE_ARENA_OFFSET = 0;
            BOOT_OVERRIDES = OverrideTable::empty();
            FREE_OFFSET = HEADER_SIZE;

            // Validate header magic
            let magic = read_u32(STORE_XIP);
            if magic != flash_layout::PARAM_STORE_MAGIC {
                // Virgin or corrupt sector — no overrides
                if magic == 0xFFFF_FFFF {
                    // Virgin sector, free_offset stays at start (no header yet)
                    FREE_OFFSET = 0;
                }
                return;
            }

            let version = *STORE_XIP.add(4);
            if version != flash_layout::PARAM_STORE_VERSION {
                log::warn!("[flash_store] unknown version {}", version);
                return;
            }

            // Walk entries, building last-writer-wins map
            // We process all entries to find the latest per (module_id, tag),
            // respecting tombstones and clear-all markers.
            let sector = STORE_XIP;
            let mut off = HEADER_SIZE;

            while off + ENTRY_HEADER_SIZE <= SECTOR_SIZE {
                let module_id = *sector.add(off);
                if module_id == 0xFF {
                    break; // free space
                }

                let tag = *sector.add(off + 1);
                let flags = *sector.add(off + 2);
                let value_len = *sector.add(off + 3) as usize;

                if off + ENTRY_HEADER_SIZE + value_len > SECTOR_SIZE {
                    log::warn!("[flash_store] truncated entry at offset {}", off);
                    break;
                }

                if flags & FLAG_CLEAR_ALL != 0 {
                    // Remove all entries for this module
                    remove_module_entries(module_id);
                } else if flags & FLAG_TOMBSTONE != 0 {
                    // Remove specific tag
                    remove_entry(module_id, tag);
                } else {
                    // Upsert: replace if exists, append if not
                    upsert_override(
                        module_id,
                        tag,
                        sector.add(off + ENTRY_HEADER_SIZE),
                        value_len as u8,
                    );
                }

                off += ENTRY_HEADER_SIZE + value_len;
            }

            FREE_OFFSET = off;
            {
                let p = &raw mut BOOT_OVERRIDES;
                (*p).valid = true;
            }

            let count = {
                let p = &raw const BOOT_OVERRIDES;
                (*p).count
            };
            if count > 0 {
                log::info!(
                    "[flash_store] {} active overrides, free={}",
                    count,
                    SECTOR_SIZE - FREE_OFFSET
                );
            }
        }
    }

    unsafe fn remove_module_entries(module_id: u8) {
        let table = &raw mut BOOT_OVERRIDES;
        let mut i = 0;
        while i < (*table).count {
            if (*table).entries[i].module_id == module_id {
                // Swap-remove
                (*table).count -= 1;
                if i < (*table).count {
                    (*table).entries[i] = (*table).entries[(*table).count];
                }
            } else {
                i += 1;
            }
        }
    }

    unsafe fn remove_entry(module_id: u8, tag: u8) {
        let table = &raw mut BOOT_OVERRIDES;
        let mut i = 0;
        while i < (*table).count {
            if (*table).entries[i].module_id == module_id && (*table).entries[i].tag == tag {
                (*table).count -= 1;
                if i < (*table).count {
                    (*table).entries[i] = (*table).entries[(*table).count];
                }
                return;
            }
            i += 1;
        }
    }

    /// Copy value from XIP flash into OVERRIDE_ARENA and record in table.
    unsafe fn upsert_override(module_id: u8, tag: u8, src: *const u8, value_len: u8) {
        let len = value_len as usize;

        // Allocate from arena
        if OVERRIDE_ARENA_OFFSET + len > OVERRIDE_ARENA_SIZE {
            log::warn!("[flash_store] override arena full, dropping override");
            return;
        }
        let dest = (&raw mut OVERRIDE_ARENA)
            .cast::<u8>()
            .add(OVERRIDE_ARENA_OFFSET);
        core::ptr::copy_nonoverlapping(src, dest, len);
        let value_ptr = dest as *const u8;
        OVERRIDE_ARENA_OFFSET += len;

        // Check if entry already exists (update in place)
        let table = &raw mut BOOT_OVERRIDES;
        let mut i = 0;
        while i < (*table).count {
            if (*table).entries[i].module_id == module_id && (*table).entries[i].tag == tag {
                // Note: old arena bytes become dead — acceptable waste, arena is large enough
                (*table).entries[i].value_ptr = value_ptr;
                (*table).entries[i].value_len = value_len;
                return;
            }
            i += 1;
        }

        // Append new entry
        if (*table).count < MAX_OVERRIDES {
            (*table).entries[(*table).count] = OverrideEntry {
                module_id,
                tag,
                value_ptr,
                value_len,
            };
            (*table).count += 1;
        }
    }

    // ============================================================================
    // Boot merge — called per module during instantiation
    // ============================================================================

    /// Merge runtime overrides for `module_id` into `param_buf`.
    ///
    /// Appends override TLV entries after the compiled params. Since
    /// `parse_tlv()` processes entries sequentially (last writer wins),
    /// overrides naturally take precedence.
    ///
    /// `param_buf` points to PARAM_BUFFER data, `param_len` is current length.
    /// Returns the new length.
    ///
    /// # Safety
    /// `param_buf` must point to a valid buffer of at least `max_len` bytes.
    pub unsafe fn merge_runtime_overrides(
        module_id: u8,
        param_buf: *mut u8,
        param_len: usize,
        max_len: usize,
    ) -> usize {
        // Need at least 4 bytes for a TLV v2 header; bail if buffer is undersized.
        if max_len < 4 {
            return param_len.min(max_len);
        }
        {
            let table = &raw const BOOT_OVERRIDES;
            if !(*table).valid || (*table).count == 0 {
                return param_len;
            }

            // Count how many overrides match this module
            let mut match_count = 0usize;
            let mut i = 0;
            while i < (*table).count {
                if (*table).entries[i].module_id == module_id {
                    match_count += 1;
                }
                i += 1;
            }
            if match_count == 0 {
                return param_len;
            }

            // If no compiled params, create a TLV v2 header
            let mut pos = param_len;
            if pos < 4 {
                // Empty params — write TLV v2 header: magic(0xFE), version(0x02), len(0x0000)
                *param_buf.add(0) = 0xFE;
                *param_buf.add(1) = 0x02;
                *param_buf.add(2) = 0;
                *param_buf.add(3) = 0;
                pos = 4;
            }

            // Find the end of existing TLV entries.
            // TLV v2: bytes 2-3 = payload_length. Entries start at byte 4.
            // Scan for 0xFF end marker or use payload_length.
            let payload_len = u16::from_le_bytes([*param_buf.add(2), *param_buf.add(3)]) as usize;
            let payload_end = if payload_len > 0 && 4 + payload_len < pos {
                4 + payload_len
            } else {
                // Scan for 0xFF end marker
                let mut p = 4usize;
                while p + 2 <= pos {
                    let tag = *param_buf.add(p);
                    if tag == 0xFF {
                        break;
                    }
                    let elen = *param_buf.add(p + 1) as usize;
                    p += 2 + elen;
                }
                p
            };

            // Append overrides at payload_end
            let mut write_pos = payload_end;
            i = 0;
            while i < (*table).count {
                let e = &(*table).entries[i];
                if e.module_id == module_id {
                    let needed = 2 + e.value_len as usize; // tag + len + value
                    if write_pos + needed + 1 > max_len {
                        break; // no room
                    }
                    *param_buf.add(write_pos) = e.tag;
                    *param_buf.add(write_pos + 1) = e.value_len;
                    if e.value_len > 0 {
                        core::ptr::copy_nonoverlapping(
                            e.value_ptr,
                            param_buf.add(write_pos + 2),
                            e.value_len as usize,
                        );
                    }
                    write_pos += needed;
                }
                i += 1;
            }

            // Write 0xFF end marker
            if write_pos < max_len {
                *param_buf.add(write_pos) = 0xFF;
            }

            // Update TLV v2 payload length (bytes 2-3)
            let new_payload_len = (write_pos - 4) as u16;
            let len_bytes = new_payload_len.to_le_bytes();
            *param_buf.add(2) = len_bytes[0];
            *param_buf.add(3) = len_bytes[1];

            // Return new total length (including end marker)
            write_pos + 1
        }
    }

    // ============================================================================
    // Raw flash bridge — thin kernel-side operations called by flash module
    // ============================================================================

    /// Bounds-check a flash offset against all regions writable via the raw
    /// bridge. Returns true when `offset` lies within the `size`-byte
    /// region starting at a known-writable sector.
    fn is_writable_sector(offset: u32, size: u32) -> bool {
        let end = offset.saturating_add(size);

        // Runtime parameter store — one sector.
        if offset >= flash_layout::PARAM_STORE_OFFSET
            && end <= flash_layout::PARAM_STORE_OFFSET + SECTOR_SIZE as u32
        {
            return true;
        }

        // Graph slots A and B — OTA-writable bundles.
        if offset >= flash_layout::GRAPH_SLOT_A_OFFSET
            && end <= flash_layout::GRAPH_SLOT_A_OFFSET + flash_layout::GRAPH_SLOT_SIZE
        {
            return true;
        }
        if offset >= flash_layout::GRAPH_SLOT_B_OFFSET
            && end <= flash_layout::GRAPH_SLOT_B_OFFSET + flash_layout::GRAPH_SLOT_SIZE
        {
            return true;
        }

        false
    }

    /// Erase a 4KB sector. Validates the offset is sector-aligned and falls
    /// within a known writable region (`is_writable_sector`).
    pub fn raw_erase(offset: u32) -> i32 {
        if offset & (SECTOR_SIZE as u32 - 1) != 0 {
            return crate::kernel::errno::EINVAL;
        }
        if !is_writable_sector(offset, SECTOR_SIZE as u32) {
            return crate::kernel::errno::EINVAL;
        }
        unsafe {
            match with_flash_op(|| flash_erase_sector(offset)) {
                Ok(()) => 0,
                Err(()) => crate::kernel::errno::ERROR,
            }
        }
    }

    /// Program a 256-byte page. Validates the offset falls within a known
    /// writable region (`is_writable_sector`).
    pub fn raw_program(offset: u32, data: *const u8) -> i32 {
        if !is_writable_sector(offset, PAGE_SIZE as u32) {
            return crate::kernel::errno::EINVAL;
        }
        unsafe {
            match with_flash_op(|| flash_program_page(offset, data)) {
                Ok(()) => 0,
                Err(()) => crate::kernel::errno::ERROR,
            }
        }
    }

    // ============================================================================
    // Flash hardware operations (ROM bootloader calls)
    // ============================================================================

    /// Execute a flash operation within a critical section with DMA safety.
    ///
    /// Acquires exclusive flash access, disables interrupts, waits for all
    /// DMA channels reading from flash to complete, then runs the operation.
    unsafe fn with_flash_op<F: FnOnce()>(op: F) -> Result<(), ()> {
        use embassy_rp::pac;

        cortex_m::interrupt::free(|_| {
            // Wait for all DMA channels reading from flash to finish
            const SRAM_LOWER: u32 = 0x2000_0000;
            for n in 0..16 {
                let ch = pac::DMA.ch(n);
                if ch.read_addr().read() < SRAM_LOWER && ch.ctrl_trig().read().busy() {
                    while ch.read_addr().read() < SRAM_LOWER && ch.ctrl_trig().read().busy() {}
                }
            }
            // Wait for XIP stream completion
            while pac::XIP_CTRL.stream_ctr().read().0 > 0 {}

            op();
        });

        Ok(())
    }

    /// Copy boot2 into a RAM buffer and return a callable function pointer.
    ///
    /// RP2040: boot2 lives at flash offset 0 (XIP 0x10000000). Must be copied
    ///         before flash_exit_xip() since flash is inaccessible after that.
    /// RP2350: boot2 is shadowed in BOOTRAM (0x400e_0000), always readable.
    #[inline(always)]
    unsafe fn copy_boot2(buf: &mut [u32; 256 / 4]) -> unsafe extern "C" fn() {
        core::ptr::copy_nonoverlapping(
            super::chip::BOOT2_SRC as *const u8,
            buf.as_mut_ptr() as *mut u8,
            256,
        );
        let fn_ptr = (buf.as_ptr() as *const u8).offset(1);
        core::mem::transmute(fn_ptr)
    }

    /// Erase one 4KB sector at the given flash offset.
    ///
    /// # Safety
    /// Must be called within `with_flash_op` (interrupts disabled, DMA idle).
    #[inline(never)]
    #[link_section = ".data.ram_func"]
    unsafe fn flash_erase_sector(offset: u32) {
        use embassy_rp::rom_data;

        let mut boot2 = [0u32; 256 / 4];
        let boot2_fn = copy_boot2(&mut boot2);

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        (rom_data::connect_internal_flash::ptr())();
        (rom_data::flash_exit_xip::ptr())();
        (rom_data::flash_range_erase::ptr())(
            offset,
            SECTOR_SIZE,
            super::chip::FLASH_ERASE_BLOCK_SIZE,
            super::chip::FLASH_ERASE_CMD,
        );
        (rom_data::flash_flush_cache::ptr())();
        boot2_fn();
    }

    /// Program one 256-byte page at the given flash offset.
    ///
    /// `data` must point to exactly 256 bytes in SRAM.
    ///
    /// # Safety
    /// Must be called within `with_flash_op` (interrupts disabled, DMA idle).
    #[inline(never)]
    #[link_section = ".data.ram_func"]
    unsafe fn flash_program_page(offset: u32, data: *const u8) {
        use embassy_rp::rom_data;

        let mut boot2 = [0u32; 256 / 4];
        let boot2_fn = copy_boot2(&mut boot2);

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        (rom_data::connect_internal_flash::ptr())();
        (rom_data::flash_exit_xip::ptr())();
        (rom_data::flash_range_program::ptr())(offset, data, PAGE_SIZE);
        (rom_data::flash_flush_cache::ptr())();
        boot2_fn();
    }

    // ============================================================================
    // Helpers
    // ============================================================================

    /// Read a u32 from an unaligned pointer (little-endian).
    unsafe fn read_u32(ptr: *const u8) -> u32 {
        u32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
    }
}

pub mod xip_lock {
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

    use crate::kernel::errno;
    use portable_atomic::{AtomicU32, AtomicU8, Ordering};

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
        match slot
            .owner
            .compare_exchange(owner, OWNER_FREE, Ordering::AcqRel, Ordering::Acquire)
        {
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
        if !count.is_multiple_of(BOOTSEL_POLL_DIVISOR) {
            return CACHED_RESULT.load(Ordering::Relaxed) as i32;
        }

        let owner = crate::kernel::scheduler::current_module_index() as u8;
        let slot = &RESOURCE_SLOTS[RESOURCE_FLASH_XIP];

        // Atomic short-term lock: try-lock, do the read, then unlock.
        // If already locked by someone else, return EAGAIN.
        let prev =
            slot.owner
                .compare_exchange(OWNER_FREE, owner, Ordering::AcqRel, Ordering::Acquire);
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
        use super::chip;
        use embassy_rp::pac;

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
        if (sio_hi_sample >> chip::BOOTSEL_QSPI_SS_BIT) & 1 == 0 {
            1
        } else {
            0
        }
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
        core::ptr::write_volatile(
            chip::BOOTSEL_FLASH_RELEASE_ADDR as *mut u32,
            chip::BOOTSEL_FLASH_RELEASE_VALUE,
        );
        // Configure pad: OD=1, IE=1, PUE=1, SCHMITT=1
        core::ptr::write_volatile(chip::BOOTSEL_PAD_ADDR as *mut u32, chip::BOOTSEL_PAD_VALUE);
        // IO control: output disable + SIO funcsel
        core::ptr::write_volatile(
            chip::BOOTSEL_CTRL_ADDR as *mut u32,
            chip::BOOTSEL_CTRL_VALUE,
        );

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
}
