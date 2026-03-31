//! PIC Module Loader
//!
//! Loads and resolves modules from the flash-resident module table.
//! Modules are position-independent code that execute directly from flash (XIP).

use crate::abi::SyscallTable;
use crate::fnv1a32;
use crate::kernel::config::read_layout;
use crate::modules::{Module, StepOutcome};

// ============================================================================
// Constants
// ============================================================================

/// Pre-computed export hashes for standard module interface
pub mod export_hashes {
    pub const MODULE_STATE_SIZE: u32 = 0x74f40805; // "module_state_size"
    pub const MODULE_INIT: u32 = 0xfb8dc9bc;       // "module_init"
    pub const MODULE_NEW: u32 = 0xe6d4ac90;        // "module_new"
    pub const MODULE_STEP: u32 = 0xc7ea2db4;       // "module_step"
    pub const MODULE_CHANNEL_HINTS: u32 = 0xfcc07eec; // "module_channel_hints"
    pub const MODULE_ARENA_SIZE: u32 = 0x1b6f4183; // "module_arena_size"
}

/// Module table magic: "FXMT"
pub const MODULE_TABLE_MAGIC: u32 = 0x544D5846;

/// Module magic: "FXMD"
pub const MODULE_MAGIC: u32 = 0x444D5846;

/// Total arena size for module state buffers.
/// Bump-allocated per module at runtime — each module gets exactly what
/// module_state_size() reports. Reset on graph reconfigure.
///
/// Channel buffers are allocated from a separate arena in buffer_pool.rs,
/// so this entire budget is available for module state.
///
/// Module state arena size — from silicon TOML [kernel] section.
/// RP2350: 256 KB, RP2040: 64 KB.
const STATE_ARENA_SIZE: usize = super::chip::STATE_ARENA_SIZE;

// MAX_PARAMS_SIZE removed — pending modules now store a pointer to the
// static PARAM_BUFFER instead of copying, eliminating truncation.

// Flash memory bounds (RP2350 XIP range)
#[cfg(feature = "rp")]
const FLASH_BASE: u32 = 0x10000000;
#[cfg(feature = "rp")]
const FLASH_END: u32 = 0x11000000;

// ============================================================================
// Error types
// ============================================================================

/// Expected module ABI version (must match tools/src/modules.rs ABI_VERSION).
pub const MODULE_ABI_VERSION: u8 = 1;

/// Errors that can occur during module loading and instantiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderError {
    /// No valid layout trailer found
    NoLayout,
    /// No modules embedded in flash
    NoModules,
    /// Invalid module table magic
    InvalidTableMagic,
    /// Invalid module magic at offset
    InvalidModuleMagic,
    /// Module not found by hash
    ModuleNotFound,
    /// Export not found by hash
    ExportNotFound,
    /// Function pointer validation failed
    InvalidFnPtr,
    /// Module base address outside flash
    InvalidModuleBase,
    /// Code extends past flash end
    CodeOutOfBounds,
    /// Code size too large
    CodeSizeTooLarge,
    /// State arena exhausted (not enough contiguous space)
    StatePoolExhausted,
    /// module_init returned error
    InitFailed(i32),
    /// module_new returned error
    NewFailed(i32),
    /// Module ABI version mismatch
    AbiVersionMismatch { expected: u8, found: u8 },
    /// Integrity hash mismatch (manifest SHA-256 doesn't match code+data)
    IntegrityMismatch,
}

impl LoaderError {
    /// Log the error with appropriate level.
    pub fn log(&self, context: &str) {
        match self {
            Self::NoLayout => log::warn!("[loader] {}: no layout trailer", context),
            Self::NoModules => log::info!("[loader] {}: no modules", context),
            Self::InvalidTableMagic => log::warn!("[loader] {}: bad table magic", context),
            Self::InvalidModuleMagic => log::warn!("[loader] {}: bad module magic", context),
            Self::ModuleNotFound => log::warn!("[loader] {}: not found", context),
            Self::ExportNotFound => log::warn!("[loader] {}: export missing", context),
            Self::InvalidFnPtr => log::error!("[loader] {}: invalid fn ptr", context),
            Self::InvalidModuleBase => log::error!("[loader] {}: base outside flash", context),
            Self::CodeOutOfBounds => log::error!("[loader] {}: code past flash", context),
            Self::CodeSizeTooLarge => log::error!("[loader] {}: code too large", context),
            Self::StatePoolExhausted => log::error!("[loader] {}: state arena full", context),
            Self::InitFailed(code) => log::error!("[loader] {}: init failed rc={}", context, code),
            Self::NewFailed(code) => log::warn!("[loader] {}: new failed rc={}", context, code),
            Self::AbiVersionMismatch { expected, found } =>
                log::error!("[loader] {}: abi mismatch expected={} found={}", context, expected, found),
            Self::IntegrityMismatch =>
                log::error!("[loader] {}: integrity hash mismatch", context),
        }
    }
}

// ============================================================================
// Flash memory primitives
// ============================================================================

/// Read a ModuleTableHeader from flash.
///
/// # Safety
/// - `ptr` must point to valid, aligned flash memory
/// - The memory must contain a valid ModuleTableHeader struct
#[inline]
unsafe fn read_table_header(ptr: *const u8) -> ModuleTableHeader {
    core::ptr::read_volatile(ptr as *const ModuleTableHeader)
}

/// Read a ModuleTableEntry from flash at the given index.
///
/// # Safety
/// - `base` must point to the start of the entries array in flash
/// - `index` must be within bounds of the table
#[inline]
unsafe fn read_table_entry(base: *const u8, index: usize) -> ModuleTableEntry {
    let entry_ptr = base.add(index * 16) as *const ModuleTableEntry;
    core::ptr::read_volatile(entry_ptr)
}

/// Read a ModuleHeader from flash.
///
/// # Safety
/// - `ptr` must point to valid, aligned flash memory containing a module
#[inline]
unsafe fn read_module_header(ptr: *const u8) -> ModuleHeader {
    core::ptr::read_volatile(ptr as *const ModuleHeader)
}

/// Read an ExportEntry from the export table.
///
/// # Safety
/// - `table` must point to a valid export table in flash
/// - `index` must be within bounds of the export table
#[inline]
unsafe fn read_export_entry(table: *const u8, index: usize) -> ExportEntry {
    let entry_ptr = table.add(index * 8) as *const ExportEntry;
    *entry_ptr
}

/// Compute pointer offset within flash.
///
/// # Safety
/// - `base` must be a valid flash pointer
/// - `offset` must not cause the pointer to go out of bounds
#[inline]
unsafe fn offset_ptr(base: *const u8, offset: usize) -> *const u8 {
    base.add(offset)
}

// ============================================================================
// FFI types and wrappers
// ============================================================================

/// Function pointer type for module_state_size export
pub type ModuleStateSizeFn = unsafe extern "C" fn() -> usize;

/// Function pointer type for module_init export
pub type ModuleInitFn = unsafe extern "C" fn(*const SyscallTable);

/// Function pointer type for module_new export
/// Signature: module_new(in_chan, out_chan, ctrl_chan, params, params_len, state, state_size, syscalls) -> i32
pub type ModuleNewFn = unsafe extern "C" fn(i32, i32, i32, *const u8, usize, *mut u8, usize, *const SyscallTable) -> i32;

/// Function pointer type for module_step export
pub type ModuleStepFn = unsafe extern "C" fn(*mut u8) -> i32;

/// Function pointer type for module_channel_hints export
pub type ModuleChannelHintsFn = unsafe extern "C" fn(*mut u8, usize) -> i32;

/// Convert a raw address (with Thumb bit set) directly to a typed function pointer.
///
/// This uses transmute_copy to go directly from u32 -> fn ptr without an
/// intermediate *const () which can lose Thumb state information.
///
/// # Safety
/// - `addr` must be a valid function address (Thumb bit set on Cortex-M)
/// - The function at that address must match the signature of `F`
#[inline]
unsafe fn fn_ptr_from_addr<F: Copy>(addr: usize) -> F {
    core::mem::transmute_copy(&addr)
}

/// Count of PIC calls that returned with interrupts disabled.
static mut PIC_IRQ_DISABLED_COUNT: u32 = 0;

/// Flush pipeline, synchronize, and restore interrupts after PIC call.
#[inline(always)]
fn pic_barrier() {
    #[cfg(feature = "rp")]
    {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Check if PIC code accidentally disabled interrupts
        let primask = cortex_m::register::primask::read();
        if !primask.is_active() {
            unsafe {
                PIC_IRQ_DISABLED_COUNT += 1;
                cortex_m::interrupt::enable();
            }
        }
    }
    #[cfg(feature = "chip-bcm2712")]
    {
        // aarch64: DSB + ISB for pipeline sync after PIC call
        unsafe { core::arch::asm!("dsb sy", "isb") };
    }
}

/// Call module_state_size export.
#[inline]
unsafe fn call_state_size(f: ModuleStateSizeFn) -> usize {
    let r = f();
    pic_barrier();
    r
}

/// Call module_init export.
#[inline]
unsafe fn call_init(f: ModuleInitFn, syscalls: *const SyscallTable) {
    f(syscalls);
    pic_barrier();
}

/// Call module_new export.
#[inline]
unsafe fn call_new(
    f: ModuleNewFn,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    let r = f(in_chan, out_chan, ctrl_chan, params, params_len, state, state_size, syscalls);
    pic_barrier();
    r
}

/// Call module_step export.
#[inline]
unsafe fn call_step(f: ModuleStepFn, state: *mut u8) -> i32 {
    let r = f(state);
    pic_barrier();
    r
}

/// Return count of PIC calls that left interrupts disabled.
pub fn pic_irq_disabled_count() -> u32 {
    unsafe { PIC_IRQ_DISABLED_COUNT }
}

// ============================================================================
// State pool
// ============================================================================

/// Bump-allocated arena for module state buffers.
/// Each module gets exactly what module_state_size() reports.
/// Reset on graph reconfigure via reset_state_arena().
///
/// Must be 4-byte aligned so that allocations at aligned offsets
/// produce 4-byte-aligned pointers (ARM requires aligned access for
/// struct fields like pointers and u32).
#[repr(C, align(4))]
struct AlignedArena([u8; STATE_ARENA_SIZE]);
static mut STATE_ARENA: AlignedArena = AlignedArena([0; STATE_ARENA_SIZE]);

/// Current bump offset into STATE_ARENA.
static mut STATE_ARENA_OFFSET: usize = 0;

/// Allocate a state buffer of `size` bytes from the arena.
///
/// Returns pointer to zeroed buffer, aligned to 4 bytes.
pub fn alloc_state(size: usize) -> Result<*mut u8, LoaderError> {
    // SAFETY: Single-threaded embedded context, no concurrent access
    unsafe {
        // Align offset up to 4 bytes (ARM word alignment)
        let aligned = (STATE_ARENA_OFFSET + 3) & !3;
        if aligned + size > STATE_ARENA_SIZE {
            log::error!("[loader] state arena full need={} used={} cap={}",
                size, aligned, STATE_ARENA_SIZE);
            return Err(LoaderError::StatePoolExhausted);
        }
        let ptr = core::ptr::addr_of_mut!(STATE_ARENA.0).cast::<u8>().add(aligned);
        core::ptr::write_bytes(ptr, 0, size);
        STATE_ARENA_OFFSET = aligned + size;
        Ok(ptr)
    }
}

/// Return current arena usage: (used_bytes, total_bytes).
pub fn arena_usage() -> (usize, usize) {
    unsafe { (STATE_ARENA_OFFSET, STATE_ARENA_SIZE) }
}

/// Free a state buffer — no-op for arena allocator.
/// Full reset happens via reset_state_arena() on graph reconfigure.
fn free_state(_ptr: *mut u8) {
    // Arena: individual free is a no-op
}

/// Reset the arena for a new graph configuration.
/// Called from scheduler before instantiating modules.
pub fn reset_state_arena() {
    // SAFETY: Single-threaded embedded context
    unsafe {
        STATE_ARENA_OFFSET = 0;
        // Don't zero the whole arena — alloc_state zeros each allocation
    }
}

// ============================================================================
// Table types
// ============================================================================

/// Module table header (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleTableHeader {
    pub magic: u32,
    pub version: u8,
    pub module_count: u8,
    pub total_size: u16,
    pub reserved: [u8; 8],
}

/// Module table entry (16 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleTableEntry {
    pub name_hash: u32,
    pub offset: u32,
    pub size: u32,
    pub module_type: u8,
    pub flags: u8,
    pub reserved: [u8; 2],
}

/// Module header (68 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleHeader {
    pub magic: u32,
    pub version: u8,
    pub abi_version: u8,
    pub module_type: u8,
    pub flags: u8,
    pub code_size: u32,
    pub data_size: u32,
    pub bss_size: u32,
    pub init_offset: u32,
    pub export_count: u16,
    pub export_offset: u16,
    pub name: [u8; 32],
    pub reserved: [u8; 8],
}

impl ModuleHeader {
    pub const SIZE: usize = 68;

    /// ABI v2 reserved layout:
    ///   byte 0: flags
    ///     bit 0: mailbox_safe — module can safely consume from mailbox channels.
    ///            Required for buffer_group aliasing: the scheduler checks this
    ///            flag in `open_channels` and skips the alias (falls back to a
    ///            separate FIFO channel) if the downstream module is not safe.
    ///            Set for any module that handles mailbox input correctly
    ///            (via buffer_acquire_read, buffer_acquire_inplace, or
    ///            transparent channel_read).
    ///     bit 1: in_place_writer — module uses buffer_acquire_inplace to modify
    ///            the buffer in place. Used for setup-time validation: at most
    ///            one in_place_writer per buffer_group is allowed.
    ///     bits 2-7: reserved (0)
    ///   byte 1: step_period_ms
    ///   bytes 2-3: schema_size (u16 LE)
    ///   bytes 4-5: manifest_size (u16 LE)
    ///   bytes 6-7: required_caps (u16 LE)

    /// Step period hint from reserved[1]: 0 = every tick, N = every N ms.
    pub fn step_period_ms(&self) -> u8 {
        self.reserved[1]
    }

    /// Schema section size from reserved[2..4].
    pub fn schema_size(&self) -> u16 {
        u16::from_le_bytes([self.reserved[2], self.reserved[3]])
    }

    /// Manifest section size from reserved[4..6].
    pub fn manifest_size(&self) -> u16 {
        u16::from_le_bytes([self.reserved[4], self.reserved[5]])
    }

    /// Required device class bitmask from reserved[6..8].
    /// Bit N set = module requires device class N through dev_call.
    pub fn required_caps(&self) -> u16 {
        u16::from_le_bytes([self.reserved[6], self.reserved[7]])
    }
}

/// Export table entry (8 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExportEntry {
    pub hash: u32,
    pub offset: u32,
}

/// Module types (matches config)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModuleType {
    Source = 1,
    Transformer = 2,
    Sink = 3,
    EventHandler = 4,
    Protocol = 5,
}

// ============================================================================
// Loaded module handle
// ============================================================================

/// Loaded module handle
#[derive(Debug, Clone, Copy)]
pub struct LoadedModule {
    /// Base address of module in flash
    pub base: *const u8,
    /// Parsed header
    pub header: ModuleHeader,
}

impl LoadedModule {
    /// Get the code section base address
    pub fn code_base(&self) -> *const u8 {
        // SAFETY: base is valid flash pointer, SIZE is constant offset
        unsafe { offset_ptr(self.base, ModuleHeader::SIZE) }
    }

    /// Get module name as string slice
    pub fn name_str(&self) -> &str {
        let end = self.header.name.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.header.name[..end]).unwrap_or("")
    }

    /// Get export table pointer
    fn export_table(&self) -> *const u8 {
        // Compute from code_size + data_size (both u32) to avoid u16 overflow
        // in the header's export_offset field for modules > 64KB.
        let offset = self.header.code_size as usize + self.header.data_size as usize;
        unsafe { offset_ptr(self.code_base(), offset) }
    }

    /// Get a function address by hash.
    /// On Cortex-M: returns u32 with Thumb bit set.
    /// On aarch64: returns usize (64-bit address, no Thumb bit).
    pub fn get_export_addr(&self, hash: u32) -> Result<usize, LoaderError> {
        let export_count = self.header.export_count as usize;
        if export_count == 0 {
            return Err(LoaderError::ExportNotFound);
        }

        let code_base = self.code_base();
        let export_table = self.export_table();

        for i in 0..export_count {
            // SAFETY: i < export_count from validated header
            let entry = unsafe { read_export_entry(export_table, i) };

            if entry.hash == hash {
                let offset = entry.offset & !1;
                let fn_addr = (code_base as usize).wrapping_add(offset as usize);
                #[cfg(feature = "rp")]
                let fn_addr = fn_addr | 1; // Set Thumb bit for Cortex-M
                return Ok(fn_addr);
            }
        }

        Err(LoaderError::ExportNotFound)
    }

    /// Log header info for debugging (minimal to avoid buffer overflow)
    pub fn log_header_info(&self) {
    }
}

// ============================================================================
// Module loader
// ============================================================================

/// Module loader - reads from flash module table
pub struct ModuleLoader {
    table_base: *const u8,
    header: Option<ModuleTableHeader>,
    /// Skip integrity checks (for embedded blob modules)
    pub skip_integrity: bool,
}

impl ModuleLoader {
    /// Create a new loader (uninitialized)
    pub const fn new() -> Self {
        Self {
            table_base: core::ptr::null(),
            header: None,
            skip_integrity: false,
        }
    }

    /// Initialize the loader by reading the layout trailer and module table header
    pub fn init(&mut self) -> Result<(), LoaderError> {
        let layout = read_layout().ok_or(LoaderError::NoLayout)?;

        if layout.modules_addr == 0 {
            log::info!("[loader] no modules in flash");
            return Err(LoaderError::NoModules);
        }

        self.table_base = layout.modules_addr as *const u8;

        // SAFETY: table_base points to flash memory at modules_addr
        let header = unsafe { read_table_header(self.table_base) };

        if header.magic != MODULE_TABLE_MAGIC {
            log::warn!("[loader] bad table magic=0x{:08x}", header.magic);
            return Err(LoaderError::InvalidTableMagic);
        }

        log::debug!(
            "[loader] {} modules at 0x{:08x}",
            header.module_count,
            layout.modules_addr
        );
        self.header = Some(header);
        Ok(())
    }

    /// Get number of modules in table
    pub fn module_count(&self) -> usize {
        self.header.map(|h| h.module_count as usize).unwrap_or(0)
    }

    /// Find module by name
    pub fn find_by_name(&self, name: &str) -> Result<LoadedModule, LoaderError> {
        let hash = fnv1a32(name.as_bytes());
        self.find_by_name_hash(hash)
    }

    /// Find module by name hash
    pub fn find_by_name_hash(&self, name_hash: u32) -> Result<LoadedModule, LoaderError> {
        let header = self.header.ok_or(LoaderError::NoModules)?;
        // SAFETY: table_base is valid, offset 16 is after the header
        let entries_base = unsafe { offset_ptr(self.table_base, 16) };

        for i in 0..header.module_count as usize {
            // SAFETY: i < module_count from validated header
            let entry = unsafe { read_table_entry(entries_base, i) };

            if entry.name_hash == name_hash {
                return self.load_module_at(entry.offset);
            }
        }

        Err(LoaderError::ModuleNotFound)
    }

    /// Find module by type (returns first match)
    pub fn find_by_type(&self, module_type: ModuleType) -> Result<LoadedModule, LoaderError> {
        let header = self.header.ok_or(LoaderError::NoModules)?;
        // SAFETY: table_base is valid, offset 16 is after the header
        let entries_base = unsafe { offset_ptr(self.table_base, 16) };

        for i in 0..header.module_count as usize {
            // SAFETY: i < module_count from validated header
            let entry = unsafe { read_table_entry(entries_base, i) };

            if entry.module_type == module_type as u8 {
                return self.load_module_at(entry.offset);
            }
        }

        Err(LoaderError::ModuleNotFound)
    }

    /// Find all modules of a given type
    pub fn find_all_by_type(&self, module_type: ModuleType) -> ModuleIter<'_> {
        ModuleIter {
            loader: self,
            index: 0,
            filter_type: Some(module_type),
        }
    }

    /// Load module at given offset within table
    fn load_module_at(&self, offset: u32) -> Result<LoadedModule, LoaderError> {
        // SAFETY: table_base is valid, offset comes from validated table entry
        let module_base = unsafe { offset_ptr(self.table_base, offset as usize) };
        // SAFETY: module_base points to module header in flash
        let header = unsafe { read_module_header(module_base) };

        if header.magic != MODULE_MAGIC {
            log::warn!("[loader] bad module magic offset={}", offset);
            return Err(LoaderError::InvalidModuleMagic);
        }

        Ok(LoadedModule {
            base: module_base,
            header,
        })
    }

    /// Initialize from an in-memory module table blob (no flash layout needed).
    /// Skips integrity checks since the blob was embedded at compile time.
    pub fn init_from_blob(&mut self, blob: *const u8) -> Result<(), LoaderError> {
        let header = unsafe { read_table_header(blob) };
        if header.magic != MODULE_TABLE_MAGIC {
            return Err(LoaderError::InvalidTableMagic);
        }
        self.table_base = blob;
        self.header = Some(header);
        self.skip_integrity = true;
        log::info!("[loader] {} modules from blob", header.module_count);
        Ok(())
    }

    /// Get module table entry by index
    pub fn get_entry(&self, index: usize) -> Option<ModuleTableEntry> {
        let header = self.header?;
        if index >= header.module_count as usize {
            return None;
        }

        // SAFETY: table_base is valid, index < module_count
        let entries_base = unsafe { offset_ptr(self.table_base, 16) };
        // SAFETY: index bounds checked above
        Some(unsafe { read_table_entry(entries_base, index) })
    }
}

/// Iterator over modules
pub struct ModuleIter<'a> {
    loader: &'a ModuleLoader,
    index: usize,
    filter_type: Option<ModuleType>,
}

impl<'a> Iterator for ModuleIter<'a> {
    type Item = LoadedModule;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.loader.header?;

        while self.index < header.module_count as usize {
            let entry = self.loader.get_entry(self.index)?;
            self.index += 1;

            if let Some(filter_type) = self.filter_type {
                if entry.module_type != filter_type as u8 {
                    continue;
                }
            }

            if let Ok(module) = self.loader.load_module_at(entry.offset) {
                return Some(module);
            }
        }

        None
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate a function address before converting to a function pointer.
///
/// Checks:
/// - Thumb bit is set (bit 0)
/// - 2-byte aligned for Thumb-2
/// - Within flash memory range
fn validate_fn_addr(addr: usize, name: &str) -> Result<(), LoaderError> {
    #[cfg(feature = "rp")]
    {
        // Check Thumb bit (bit 0 must be set for Thumb code)
        if addr & 1 == 0 {
            log::error!("[loader] {}: missing thumb bit addr=0x{:08x}", name, addr);
            return Err(LoaderError::InvalidFnPtr);
        }
        // Check if within flash range
        let instr_addr = addr & !1;
        if instr_addr < FLASH_BASE as usize || instr_addr >= FLASH_END as usize {
            log::error!("[loader] {}: outside flash addr=0x{:08x}", name, addr);
            return Err(LoaderError::InvalidFnPtr);
        }
    }
    #[cfg(feature = "chip-bcm2712")]
    {
        // aarch64: non-null check only (PIC code may not be 4-byte aligned)
        if addr == 0 {
            log::error!("[loader] {}: null addr", name);
            return Err(LoaderError::InvalidFnPtr);
        }
    }
    let _ = name; // suppress unused warning
    Ok(())
}

/// Validate a loaded module's base address and header.
pub fn validate_module(module: &LoadedModule, name: &str) -> Result<(), LoaderError> {
    // Check base is in valid memory range
    #[cfg(feature = "rp")]
    {
        let base = module.base as u32;
        if base < FLASH_BASE || base >= FLASH_END {
            log::error!("[loader] {}: base outside flash addr=0x{:08x}", name, base);
            return Err(LoaderError::InvalidModuleBase);
        }
    }
    #[cfg(feature = "chip-bcm2712")]
    {
        if module.base.is_null() {
            log::error!("[loader] {}: null base", name);
            return Err(LoaderError::InvalidModuleBase);
        }
    }

    // Check ABI version
    if module.header.abi_version != MODULE_ABI_VERSION {
        log::error!(
            "[loader] {}: abi version={} expected={}",
            name, module.header.abi_version, MODULE_ABI_VERSION
        );
        return Err(LoaderError::AbiVersionMismatch {
            expected: MODULE_ABI_VERSION,
            found: module.header.abi_version,
        });
    }

    // Check code_size is reasonable (< 384KB — protocol modules may bundle firmware+NVRAM)
    if module.header.code_size > 393216 {
        log::error!("[loader] {}: code too large size={}", name, module.header.code_size);
        return Err(LoaderError::CodeSizeTooLarge);
    }

    // Check code base is still in valid memory
    #[cfg(feature = "rp")]
    {
        let code_base = module.code_base() as u32;
        let code_end = code_base + module.header.code_size;
        if code_end > FLASH_END {
            log::error!("[loader] {}: code past flash end=0x{:08x}", name, code_end);
            return Err(LoaderError::CodeOutOfBounds);
        }
    }

    // Verify integrity hash from manifest section (ABI v2)
    let manifest_size = module.header.manifest_size() as usize;
    if manifest_size >= 48 {
        // Verify manifest integrity (SHA-256) — RP only (too slow in QEMU)
        #[cfg(feature = "rp")]
        {
        let code_size = module.header.code_size as usize;
        let data_size = module.header.data_size as usize;
        let export_size = module.header.export_count as usize * 8;
        let schema_size = module.header.schema_size() as usize;
        let manifest_offset = ModuleHeader::SIZE + code_size + data_size + export_size + schema_size;
        let manifest_ptr = unsafe { offset_ptr(module.base, manifest_offset) };
        let manifest_data = unsafe {
            core::slice::from_raw_parts(manifest_ptr, manifest_size)
        };
        if manifest_size >= 16 {
            let magic = u32::from_le_bytes([manifest_data[0], manifest_data[1], manifest_data[2], manifest_data[3]]);
            if magic == 0x464D5846 {
                let has_integrity = manifest_data[14] != 0;
                if has_integrity {
                    // Extract stored hash (last 32 bytes of manifest)
                    let hash_offset = manifest_size - 32;
                    let stored_hash = &manifest_data[hash_offset..hash_offset + 32];

                    // Compute SHA-256 over code + data sections from flash
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    let code_ptr = module.code_base();
                    let code_data = unsafe { core::slice::from_raw_parts(code_ptr, code_size) };
                    hasher.update(code_data);
                    if data_size > 0 {
                        let data_ptr = unsafe { offset_ptr(code_ptr, code_size) };
                        let data_section = unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
                        hasher.update(data_section);
                    }
                    let computed = hasher.finalize();

                    if computed.as_slice() != stored_hash {
                        // Skip integrity failure for embedded blob modules
                        #[cfg(feature = "chip-bcm2712")]
                        { log::warn!("[loader] {}: integrity skip (blob)", name); }
                        #[cfg(feature = "rp")]
                        {
                            log::error!("[loader] {}: integrity mismatch", name);
                            return Err(LoaderError::IntegrityMismatch);
                        }
                    }
                }
            }
        }
        } // #[cfg(feature = "rp")]
    } // if manifest_size >= 48

    Ok(())
}

/// Check if function address is within module's code section.
fn validate_fn_in_code(
    addr: usize,
    code_base: usize,
    code_size: u32,
    _name: &str,
) -> Result<(), LoaderError> {
    #[cfg(feature = "rp")]
    {
        let fn_addr = addr & !1;
        let code_end = code_base.wrapping_add(code_size as usize);
        if fn_addr < code_base || fn_addr >= code_end {
            log::error!("[loader] {}: outside code", _name);
            return Err(LoaderError::InvalidFnPtr);
        }
    }
    // On aarch64, skip code range check — PIC code is in embedded blob
    let _ = (addr, code_base, code_size);
    Ok(())
}

// ============================================================================
// Dynamic module
// ============================================================================

/// Validated typed function pointers for a module.
pub struct ModuleExports {
    pub state_size_fn: ModuleStateSizeFn,
    pub new_fn: ModuleNewFn,
    pub step_fn: ModuleStepFn,
}

/// Lookup and validate all required exports from a module (safe - no FFI calls)
pub fn lookup_exports(module: &LoadedModule, _name: &str) -> Result<ModuleExports, LoaderError> {
    let state_size_addr = module.get_export_addr(export_hashes::MODULE_STATE_SIZE)?;
    validate_fn_addr(state_size_addr, "module_state_size")?;

    let new_addr = module.get_export_addr(export_hashes::MODULE_NEW)?;
    validate_fn_addr(new_addr, "module_new")?;

    let step_addr = module.get_export_addr(export_hashes::MODULE_STEP)?;
    validate_fn_addr(step_addr, "module_step")?;

    // Convert addresses to typed function pointers
    // SAFETY: addresses validated above, types match module ABI
    Ok(ModuleExports {
        state_size_fn: unsafe { fn_ptr_from_addr(state_size_addr) },
        new_fn: unsafe { fn_ptr_from_addr(new_addr) },
        step_fn: unsafe { fn_ptr_from_addr(step_addr) },
    })
}

/// Call module_state_size - returns required state buffer size
pub fn invoke_state_size(exports: &ModuleExports) -> usize {
    // SAFETY: state_size_fn was validated in lookup_exports
    unsafe { call_state_size(exports.state_size_fn) }
}

/// Prepare and call module_init - validates then invokes
pub fn invoke_init(
    module: &LoadedModule,
    syscalls: &SyscallTable,
    _name: &str,
) -> Result<(), LoaderError> {
    // Lookup init export (may not exist)
    let init_addr = match module.get_export_addr(export_hashes::MODULE_INIT) {
        Ok(addr) => addr,
        Err(_) => return Err(LoaderError::ExportNotFound),
    };

    // Validate address before use
    validate_fn_addr(init_addr, "module_init")?;
    let code_base = module.code_base() as usize;
    validate_fn_in_code(init_addr, code_base, module.header.code_size, "module_init")?;

    // Convert to typed function pointer and call
    // SAFETY: init_addr validated above, syscalls is valid reference
    let init_fn: ModuleInitFn = unsafe { fn_ptr_from_addr(init_addr) };
    unsafe { call_init(init_fn, syscalls) };

    Ok(())
}

/// Status returned by module_new
pub enum NewStatus {
    /// Initialization complete (returned 0)
    Ready,
    /// Async operation pending, need to retry (returned >0)
    Pending,
}

/// Call module_new to create instance
///
/// # Safety
/// `new_fn` must be a valid, validated module entrypoint.
/// `params` must point to `params_len` readable bytes (or be null if `params_len == 0`).
/// `state_ptr` must point to `state_size` writable bytes, zeroed and exclusively owned.
pub unsafe fn invoke_new(
    new_fn: ModuleNewFn,
    syscalls: &SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state_ptr: *mut u8,
    state_size: usize,
) -> Result<NewStatus, LoaderError> {
    // SAFETY: new_fn validated in lookup_exports, params/state from caller
    let result = unsafe {
        call_new(new_fn, in_chan, out_chan, ctrl_chan, params, params_len, state_ptr, state_size, syscalls)
    };

    if result < 0 {
        Err(LoaderError::NewFailed(result))
    } else if result > 0 {
        Ok(NewStatus::Pending)
    } else {
        Ok(NewStatus::Ready)
    }
}

/// Unified dynamic module wrapper for PIC modules using standard exports.
///
/// This wrapper works with modules that export:
/// - `module_state_size()` - Returns required state buffer size
/// - `module_init(syscalls)` - Called once after loading
/// - `module_new(in_chan, out_chan, ctrl_chan, params, len, state, state_size, syscalls)` - Creates instance
/// - `module_step(state)` - Advances module state
pub struct DynamicModule {
    step_fn: ModuleStepFn,
    state_ptr: *mut u8,
}

/// Partially initialized module waiting for async operations to complete.
///
/// When `module_new()` returns >0 (pending), this holds the state needed
/// to retry the call after yielding to the executor.
///
/// # Safety
///
/// `params_ptr` must remain valid for the lifetime of the pending state.
/// In practice this is guaranteed because:
/// - Params point to the static `PARAM_BUFFER` in scheduler.rs
/// - The scheduler's instantiation loop blocks on the pending retry loop
///   before overwriting `PARAM_BUFFER` for the next module
pub struct DynamicModulePending {
    step_fn: ModuleStepFn,
    new_fn: ModuleNewFn,
    state_ptr: *mut u8,
    state_size: usize,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params_ptr: *const u8,
    params_len: usize,
    name: &'static str,
}

impl DynamicModulePending {
    /// Get step function pointer (for force-completing a pending module).
    pub fn step_fn_ptr(&self) -> ModuleStepFn { self.step_fn }
    /// Get state pointer (for force-completing a pending module).
    pub fn state_ptr(&self) -> *mut u8 { self.state_ptr }

    /// Create from pre-validated parts (for debug stepping through instantiation).
    ///
    /// # Safety
    /// `params` must remain valid for the lifetime of the returned pending state.
    pub fn new(
        step_fn: ModuleStepFn,
        new_fn: ModuleNewFn,
        state_ptr: *mut u8,
        state_size: usize,
        syscalls: &SyscallTable,
        in_chan: i32,
        out_chan: i32,
        ctrl_chan: i32,
        params: *const u8,
        params_len: usize,
        name: &'static str,
    ) -> Self {
        Self {
            step_fn,
            new_fn,
            state_ptr,
            state_size,
            syscalls: syscalls as *const _,
            in_chan,
            out_chan,
            ctrl_chan,
            params_ptr: params,
            params_len,
            name,
        }
    }

    /// Try to complete initialization by calling module_new again.
    ///
    /// Returns:
    /// - `Ok(Some(module))` - initialization complete
    /// - `Ok(None)` - still pending, call again after yielding
    /// - `Err(e)` - initialization failed
    pub unsafe fn try_complete(&mut self) -> Result<Option<DynamicModule>, LoaderError> {
        match invoke_new(
            self.new_fn,
            &*self.syscalls,
            self.in_chan,
            self.out_chan,
            self.ctrl_chan,
            self.params_ptr,
            self.params_len,
            self.state_ptr,
            self.state_size,
        )? {
            NewStatus::Ready => {
                log::info!("[inst] loaded {}", self.name);
                Ok(Some(DynamicModule {
                    step_fn: self.step_fn,
                    state_ptr: self.state_ptr,
                }))
            }
            NewStatus::Pending => Ok(None),
        }
    }

    /// Free state if we're dropping without completing
    pub unsafe fn abort(self) {
        free_state(self.state_ptr);
    }
}

/// Result of starting module creation
pub enum StartNewResult {
    /// Module is ready immediately
    Ready(DynamicModule),
    /// Module initialization is pending - call try_complete() after yielding
    Pending(DynamicModulePending),
}

impl DynamicModule {
    /// Get the module's state pointer (for provider dispatch).
    pub fn state_ptr(&self) -> *mut u8 {
        self.state_ptr
    }

    /// Create from pre-validated parts (for debug stepping through instantiation).
    pub fn from_parts(step_fn: ModuleStepFn, state_ptr: *mut u8) -> Self {
        Self { step_fn, state_ptr }
    }

    /// Create from loaded module with configuration parameters.
    ///
    /// This is the synchronous version - it will fail if the module
    /// Start creating a module, supporting async initialization.
    ///
    /// Sequence:
    /// 1. Validate module header
    /// 2. Lookup and validate all exports
    /// 3. Call module_state_size() to get required buffer size
    /// 4. Allocate state from kernel pool
    /// 5. Call module_init() with syscall table
    /// 6. Call module_new() - may return pending
    ///
    /// If module_new returns pending (>0), returns `StartNewResult::Pending`.
    /// Caller should yield to executor and call `try_complete()` on the
    /// pending state until it returns Ready.
    ///
    /// # Safety
    /// - `params` must be valid for `params_len` bytes
    /// - `module` must remain valid for the module's lifetime
    #[inline(never)]
    pub unsafe fn start_new(
        module: &LoadedModule,
        syscalls: &SyscallTable,
        in_chan: i32,
        out_chan: i32,
        ctrl_chan: i32,
        params: *const u8,
        params_len: usize,
        name: &'static str,
    ) -> Result<StartNewResult, LoaderError> {
        // 1. Validate module header (safe)
        validate_module(module, name)?;

        // 2. Lookup and validate exports (safe)
        module.log_header_info();
        let exports = lookup_exports(module, name)?;

        // 3. Get required state size (FFI call, but validated)
        let required_size = invoke_state_size(&exports);

        // 4. Allocate state from arena (safe)
        let state_ptr = alloc_state(required_size)?;

        // 4b. If module exports module_arena_size, allocate and init heap
        if let Ok(arena_addr) = module.get_export_addr(export_hashes::MODULE_ARENA_SIZE) {
            let arena_fn: ModuleStateSizeFn = fn_ptr_from_addr(arena_addr);
            let arena_size = call_state_size(arena_fn);
            if arena_size > 0 {
                if let Ok(arena_ptr) = alloc_state(arena_size) {
                    let module_idx = super::scheduler::current_module_index();
                    super::heap::init_module_heap(module_idx as usize, arena_ptr, arena_size);
                }
            }
        }

        // 5. Initialize module (FFI call, but validated)
        if let Err(e) = invoke_init(module, syscalls, name) {
            free_state(state_ptr);
            return Err(e);
        }

        // 6. Try to create instance (may return pending)
        match invoke_new(exports.new_fn, syscalls, in_chan, out_chan, ctrl_chan, params, params_len, state_ptr, required_size)? {
            NewStatus::Ready => {
                log::info!("[inst] loaded {}", name);
                Ok(StartNewResult::Ready(DynamicModule {
                    step_fn: exports.step_fn,
                    state_ptr,
                }))
            }
            NewStatus::Pending => {
                // Store state for retry — params_ptr points to static
                // PARAM_BUFFER which remains valid through the pending loop
                let pending = DynamicModulePending {
                    step_fn: exports.step_fn,
                    new_fn: exports.new_fn,
                    state_ptr,
                    state_size: required_size,
                    syscalls: syscalls as *const _,
                    in_chan,
                    out_chan,
                    ctrl_chan,
                    params_ptr: params,
                    params_len,
                    name,
                };
                log::info!("[inst] pending {}", name);
                Ok(StartNewResult::Pending(pending))
            }
        }
    }
}

impl Module for DynamicModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        // SAFETY: step_fn and state_ptr were validated during construction
        let result = unsafe { call_step(self.step_fn, self.state_ptr) };
        match result {
            0 => Ok(StepOutcome::Continue),
            1 => Ok(StepOutcome::Done),
            2 => Ok(StepOutcome::Burst),
            3 => Ok(StepOutcome::Ready),
            _ => Err(result),
        }
    }

    fn name(&self) -> &'static str {
        "dynamic"
    }
}

// ============================================================================
// Channel Hints Query
// ============================================================================

/// Per-port buffer size hint from a module.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChannelHint {
    /// Port direction: 0=in, 1=out, 2=ctrl
    pub port_type: u8,
    /// Port index within that direction
    pub port_index: u8,
    /// Requested buffer size in bytes (0 = use default)
    pub buffer_size: u16,
}

/// Maximum number of hints we can collect per module
const MAX_HINTS_PER_MODULE: usize = 8;

/// Query channel hints from a loaded module.
///
/// Returns a slice of hints, or an empty slice if the module doesn't export
/// `module_channel_hints`. This is optional — modules without the export
/// get default 2048-byte buffers on all ports.
pub fn query_channel_hints(module: &LoadedModule) -> ([ChannelHint; MAX_HINTS_PER_MODULE], usize) {
    let mut hints = [ChannelHint { port_type: 0, port_index: 0, buffer_size: 0 }; MAX_HINTS_PER_MODULE];

    // Look up the optional export
    let addr = match module.get_export_addr(export_hashes::MODULE_CHANNEL_HINTS) {
        Ok(a) => a,
        Err(_) => return (hints, 0), // No hints export — use defaults
    };

    // Validate function address
    if validate_fn_addr(addr, "module_channel_hints").is_err() {
        return (hints, 0);
    }

    // Call the export: module_channel_hints(out: *mut u8, max_len: usize) -> i32
    let hints_fn: ModuleChannelHintsFn = unsafe { fn_ptr_from_addr(addr) };
    let buf_size = MAX_HINTS_PER_MODULE * 4; // 4 bytes per ChannelHint
    let mut buf = [0u8; MAX_HINTS_PER_MODULE * 4];
    let count = unsafe { hints_fn(buf.as_mut_ptr(), buf_size) };

    if count <= 0 {
        return (hints, 0);
    }

    let count = (count as usize).min(MAX_HINTS_PER_MODULE);
    for i in 0..count {
        let offset = i * 4;
        hints[i] = ChannelHint {
            port_type: buf[offset],
            port_index: buf[offset + 1],
            buffer_size: u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]),
        };
    }

    (hints, count)
}

/// Look up buffer size hint for a specific port.
///
/// Returns the requested buffer size, or 0 if no hint exists (use default).
pub fn find_hint_for_port(
    hints: &[ChannelHint],
    port_type: u8,
    port_index: u8,
) -> u16 {
    for hint in hints {
        if hint.port_type == port_type && hint.port_index == port_index {
            return hint.buffer_size;
        }
    }
    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fnv1a32;

    #[test]
    fn test_export_hashes() {
        assert_eq!(fnv1a32(b"module_state_size"), export_hashes::MODULE_STATE_SIZE);
        assert_eq!(fnv1a32(b"module_init"), export_hashes::MODULE_INIT);
        assert_eq!(fnv1a32(b"module_new"), export_hashes::MODULE_NEW);
        assert_eq!(fnv1a32(b"module_step"), export_hashes::MODULE_STEP);
        assert_eq!(fnv1a32(b"module_channel_hints"), export_hashes::MODULE_CHANNEL_HINTS);
    }
}
