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

use crate::abi::runtime_store;

// ============================================================================
// Constants
// ============================================================================

const XIP_BASE: u32 = 0x1000_0000;
const STORE_XIP: *const u8 = (XIP_BASE + runtime_store::OFFSET) as *const u8;
const SECTOR_SIZE: usize = runtime_store::SIZE; // 4096
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
        if (*&raw const STORE_DISPATCH).is_some() {
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
        if magic != runtime_store::MAGIC {
            // Virgin or corrupt sector — no overrides
            if magic == 0xFFFF_FFFF {
                // Virgin sector, free_offset stays at start (no header yet)
                FREE_OFFSET = 0;
            }
            return;
        }

        let version = *STORE_XIP.add(4);
        if version != runtime_store::VERSION {
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
                upsert_override(module_id, tag, sector.add(off + ENTRY_HEADER_SIZE), value_len as u8);
            }

            off += ENTRY_HEADER_SIZE + value_len;
        }

        FREE_OFFSET = off;
        BOOT_OVERRIDES.valid = true;

        if (*&raw const BOOT_OVERRIDES).count > 0 {
            log::info!(
                "[flash_store] {} active overrides, free={}",
                (*&raw const BOOT_OVERRIDES).count,
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
    let dest = (&raw mut OVERRIDE_ARENA).cast::<u8>().add(OVERRIDE_ARENA_OFFSET);
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
/// `parse_tlv_v2()` processes entries sequentially (last writer wins),
/// overrides naturally take precedence.
///
/// `param_buf` points to PARAM_BUFFER data, `param_len` is current length.
/// Returns the new length.
///
/// # Safety
/// `param_buf` must point to a valid buffer of at least `max_len` bytes.
pub unsafe fn merge_runtime_overrides(module_id: u8, param_buf: *mut u8, param_len: usize, max_len: usize) -> usize {
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

/// Erase the runtime store sector. Validates offset == runtime_store::OFFSET.
pub fn raw_erase(offset: u32) -> i32 {
    if offset != runtime_store::OFFSET {
        return crate::kernel::errno::EINVAL;
    }
    unsafe {
        match with_flash_op(|| flash_erase_sector(offset)) {
            Ok(()) => 0,
            Err(()) => crate::kernel::errno::ERROR,
        }
    }
}

/// Program a 256-byte page within the runtime store sector.
/// Validates offset is within sector bounds.
pub fn raw_program(offset: u32, data: *const u8) -> i32 {
    if offset < runtime_store::OFFSET
        || offset >= runtime_store::OFFSET + SECTOR_SIZE as u32
    {
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

/// Erase one 4KB sector at the given flash offset.
///
/// # Safety
/// Must be called within `with_flash_op` (interrupts disabled, DMA idle).
#[inline(never)]
#[link_section = ".data.ram_func"]
unsafe fn flash_erase_sector(offset: u32) {
    use embassy_rp::rom_data;

    // Copy boot2 from BOOTRAM (required for XIP re-entry on RP2350)
    let mut boot2 = [0u32; 256 / 4];
    let bootram_base = 0x400e_0000u32 as *const u8;
    core::ptr::copy_nonoverlapping(bootram_base, boot2.as_mut_ptr() as *mut u8, 256);

    let boot2_fn_ptr = (boot2.as_ptr() as *const u8).offset(1);
    let boot2_fn: unsafe extern "C" fn() = core::mem::transmute(boot2_fn_ptr);

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    (rom_data::connect_internal_flash::ptr())();
    (rom_data::flash_exit_xip::ptr())();
    (rom_data::flash_range_erase::ptr())(offset, SECTOR_SIZE, 1 << 31, 0);
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
    let bootram_base = 0x400e_0000u32 as *const u8;
    core::ptr::copy_nonoverlapping(bootram_base, boot2.as_mut_ptr() as *mut u8, 256);

    let boot2_fn_ptr = (boot2.as_ptr() as *const u8).offset(1);
    let boot2_fn: unsafe extern "C" fn() = core::mem::transmute(boot2_fn_ptr);

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
