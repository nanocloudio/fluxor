//! PIC Module Loader
//!
//! Loads and resolves modules from the flash-resident module table.
//! Modules are position-independent code that execute directly from flash (XIP).

use crate::abi::SyscallTable;
use crate::fnv1a32;
use crate::kernel::config::read_layout;
use crate::kernel::hal;
use crate::modules::{Module, StepOutcome};

// ============================================================================
// Constants
// ============================================================================

/// Pre-computed export hashes for standard module interface
pub mod export_hashes {
    pub const MODULE_STATE_SIZE: u32 = 0x74f40805; // "module_state_size"
    pub const MODULE_INIT: u32 = 0xfb8dc9bc; // "module_init"
    pub const MODULE_NEW: u32 = 0xe6d4ac90; // "module_new"
    pub const MODULE_STEP: u32 = 0xc7ea2db4; // "module_step"
    pub const MODULE_CHANNEL_HINTS: u32 = 0xfcc07eec; // "module_channel_hints"
    pub const MODULE_ARENA_SIZE: u32 = 0x1b6f4183; // "module_arena_size"
    pub const MODULE_DRAIN: u32 = 0xc4c5636c; // "module_drain"
    pub const MODULE_ISR_INIT: u32 = 0x9cfb0a03; // "module_isr_init"
    pub const MODULE_ISR_ENTRY: u32 = 0x56c6a743; // "module_isr_entry"
    pub const MODULE_PROVIDER_DISPATCH: u32 = 0xc7832e76; // "module_provider_dispatch"
    pub const MODULE_PROVIDES_CONTRACT: u32 = 0x671c57bb; // "module_provides_contract"
    pub const MODULE_FLASH_STORE_DISPATCH: u32 = 0x2f7172b5; // "module_flash_store_dispatch"
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
    /// Ed25519 signature invalid or missing when enforce_signatures is set.
    SignatureInvalid,
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
            Self::AbiVersionMismatch { expected, found } => log::error!(
                "[loader] {}: abi mismatch expected={} found={}",
                context,
                expected,
                found
            ),
            Self::IntegrityMismatch => log::error!("[loader] {}: integrity hash mismatch", context),
            Self::SignatureInvalid => log::error!("[loader] {}: signature invalid", context),
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
pub type ModuleNewFn = unsafe extern "C" fn(
    i32,
    i32,
    i32,
    *const u8,
    usize,
    *mut u8,
    usize,
    *const SyscallTable,
) -> i32;

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

/// Resolved provider-auto-registration hooks for a module.
///
/// A PIC module is a provider for a contract when it exports both
/// `module_provides_contract() -> u32` (returns the contract id) and
/// `module_provider_dispatch(state, handle, op, arg, len) -> i32` (the
/// dispatch fn). We resolve both addresses at load time and call
/// `register_module_provider` after `module_new()` returns Ready.
/// Modules that aren't providers leave both exports absent and this
/// whole path is a no-op.
struct ProviderAutoRegister {
    contract_fn: unsafe extern "C" fn() -> u32,
    dispatch_fn: crate::kernel::provider::ModuleProviderDispatchFn,
}

impl ProviderAutoRegister {
    /// Look for the `module_provides_contract` + `module_provider_dispatch`
    /// export pair. Returns None if the module isn't a provider.
    unsafe fn resolve(module: &LoadedModule) -> Option<Self> {
        let contract_addr = module
            .get_export_addr(export_hashes::MODULE_PROVIDES_CONTRACT)
            .ok()?;
        let dispatch_addr = module
            .get_export_addr(export_hashes::MODULE_PROVIDER_DISPATCH)
            .ok()?;
        Some(Self {
            contract_fn: fn_ptr_from_addr(contract_addr),
            dispatch_fn: fn_ptr_from_addr(dispatch_addr),
        })
    }

    /// Register this module as a provider. Called after module_new() Ready.
    unsafe fn register(&self, module_idx: u8, state_ptr: *mut u8, name: &'static str) {
        let contract = (self.contract_fn)() as u16;
        let rc = crate::kernel::provider::register_module_provider(
            contract,
            module_idx,
            self.dispatch_fn,
            state_ptr,
        );
        if rc != 0 {
            log::warn!(
                "[inst] {} provider auto-register failed contract=0x{:04x} rc={}",
                name,
                contract,
                rc
            );
        }
    }
}

/// Count of PIC calls that returned with interrupts disabled.
static mut PIC_IRQ_DISABLED_COUNT: u32 = 0;

/// Increment the IRQ-disabled counter (called by HAL pic_barrier).
pub fn increment_irq_disabled_count() {
    unsafe {
        PIC_IRQ_DISABLED_COUNT += 1;
    }
}

/// Flush pipeline, synchronize, and restore interrupts after PIC call.
/// Delegates to the platform HAL for architecture-specific barrier sequences.
#[inline(always)]
fn pic_barrier() {
    hal::pic_barrier();
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

/// Channel handles wired to a module instance: data input, data output,
/// and the optional control input.
#[derive(Copy, Clone)]
pub struct ChannelHandles {
    pub in_chan: i32,
    pub out_chan: i32,
    pub ctrl_chan: i32,
}

/// Pointer + length pair for a packed `module_new` parameter blob.
#[derive(Copy, Clone)]
pub struct ParamSlice {
    pub ptr: *const u8,
    pub len: usize,
}

/// Inputs to a `module_new` call. Bundled to keep the kernel call sites
/// readable when the wire-level signature would otherwise need 7+ args.
pub struct ModuleInitArgs {
    pub in_chan: i32,
    pub out_chan: i32,
    pub ctrl_chan: i32,
    pub params: *const u8,
    pub params_len: usize,
    pub state_ptr: *mut u8,
    pub state_size: usize,
}

/// Call module_new export.
#[inline]
unsafe fn call_new(f: ModuleNewFn, args: &ModuleInitArgs, syscalls: *const SyscallTable) -> i32 {
    let r = f(
        args.in_chan,
        args.out_chan,
        args.ctrl_chan,
        args.params,
        args.params_len,
        args.state_ptr,
        args.state_size,
        syscalls,
    );
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

/// Function pointer type for module_drain export
pub type ModuleDrainFn = unsafe extern "C" fn(*mut u8) -> i32;

/// Function pointer type for module_isr_init export (Tier 2 ISR modules).
/// Called once during setup (non-ISR context) to initialize ISR-tier state.
pub type ModuleIsrInitFn = unsafe extern "C" fn(*mut u8, *const SyscallTable) -> i32;

/// Function pointer type for module_isr_entry export (Tier 2 ISR modules).
/// Called from the IRQ handler. Returns i32 status (0 = ok, <0 = error).
pub type ModuleIsrEntryFn = unsafe extern "C" fn(*mut u8) -> i32;

/// Call module_drain export.
#[inline]
unsafe fn call_drain(f: ModuleDrainFn, state: *mut u8) -> i32 {
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

/// Pool of state buffers for PIC modules.
///
/// The pool is a bump allocator with a bounded free list for granular
/// reuse. Allocations served from the free list (first-fit over freed
/// regions); when no free region is large enough, the pool bumps
/// `STATE_ARENA_OFFSET` upward. `free_state_range` returns a region to
/// the free list, coalescing with adjacent free regions. When the region
/// being freed ends at the high-water mark, the bump offset is lowered.
///
/// `reset_state_arena` clears the free list and resets the bump offset,
/// returning the entire pool to empty. This is the path taken by the
/// atomic graph reconfigure in `prepare_graph`.
///
/// Must be 4-byte aligned so aligned offsets produce 4-byte-aligned
/// pointers (ARM requires aligned access for struct fields like pointers
/// and u32).
#[repr(C, align(4))]
struct AlignedArena([u8; STATE_ARENA_SIZE]);
static mut STATE_ARENA: AlignedArena = AlignedArena([0; STATE_ARENA_SIZE]);

/// Bump offset — high-water mark. Memory at `[0, STATE_ARENA_OFFSET)`
/// has been handed out at some point; free holes in that range are
/// recorded in `FREE_LIST`.
static mut STATE_ARENA_OFFSET: usize = 0;

/// Free-list entry describing a reusable hole.
#[derive(Copy, Clone)]
struct FreeRegion {
    offset: u32,
    size: u32,
}

/// Bounded free list. Coalescing keeps fragmentation manageable in
/// practice. When the free list is full, a freed region is leaked until
/// the next full `reset_state_arena`.
const MAX_FREE_REGIONS: usize = 32;
static mut FREE_LIST: [FreeRegion; MAX_FREE_REGIONS] =
    [FreeRegion { offset: 0, size: 0 }; MAX_FREE_REGIONS];
static mut FREE_COUNT: usize = 0;

const STATE_ALIGN: usize = 8;

#[inline]
fn align_up(n: usize) -> usize {
    (n + STATE_ALIGN - 1) & !(STATE_ALIGN - 1)
}

/// Allocate a state buffer of `size` bytes from the pool.
///
/// Returns a pointer to a zeroed, 8-byte-aligned buffer. Served from
/// the free list if a region fits; otherwise bumps the high-water mark.
pub fn alloc_state(size: usize) -> Result<*mut u8, LoaderError> {
    // SAFETY: Single-threaded embedded context, no concurrent access
    unsafe {
        let need = align_up(size);

        // 1. Scan free list for first-fit.
        let free_list = &raw mut FREE_LIST;
        let count = FREE_COUNT;
        let mut i = 0;
        while i < count {
            let region = (*free_list)[i];
            if (region.size as usize) >= need {
                let offset = region.offset as usize;
                let remainder = region.size as usize - need;
                if remainder == 0 {
                    // Consume the whole region: compact the list.
                    for j in i..count - 1 {
                        (*free_list)[j] = (*free_list)[j + 1];
                    }
                    FREE_COUNT = count - 1;
                } else {
                    // Shrink: advance the region past the allocation.
                    (*free_list)[i] = FreeRegion {
                        offset: (offset + need) as u32,
                        size: remainder as u32,
                    };
                }
                let ptr = core::ptr::addr_of_mut!(STATE_ARENA.0)
                    .cast::<u8>()
                    .add(offset);
                core::ptr::write_bytes(ptr, 0, size);
                return Ok(ptr);
            }
            i += 1;
        }

        // 2. Bump from the high-water mark.
        let aligned = align_up(STATE_ARENA_OFFSET);
        if aligned + need > STATE_ARENA_SIZE {
            log::error!(
                "[loader] state arena full need={} used={} cap={}",
                need,
                aligned,
                STATE_ARENA_SIZE
            );
            return Err(LoaderError::StatePoolExhausted);
        }
        let ptr = core::ptr::addr_of_mut!(STATE_ARENA.0)
            .cast::<u8>()
            .add(aligned);
        core::ptr::write_bytes(ptr, 0, size);
        STATE_ARENA_OFFSET = aligned + need;
        Ok(ptr)
    }
}

/// Return high-water mark: (used_bytes, total_bytes). Does not reflect
/// free-list holes — live memory is (used − Σ holes).
pub fn arena_usage() -> (usize, usize) {
    unsafe { (STATE_ARENA_OFFSET, STATE_ARENA_SIZE) }
}

/// Return a previously allocated region to the pool. `size` must match
/// the original allocation size; it is re-aligned internally. Adjacent
/// free regions are coalesced. If the region ends at the high-water
/// mark, the mark is lowered.
///
/// # Safety
/// `ptr` must have been returned by `alloc_state` and not already freed.
pub unsafe fn free_state_range(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let base = core::ptr::addr_of_mut!(STATE_ARENA.0).cast::<u8>();
    let offset = ptr as usize - base as usize;
    let need = align_up(size);

    let free_list = &raw mut FREE_LIST;
    let mut new_offset = offset as u32;
    let mut new_size = need as u32;

    // Coalesce with adjacent regions (walk + merge + remove merged entries).
    let mut i = 0;
    while i < FREE_COUNT {
        let r = (*free_list)[i];
        if r.offset + r.size == new_offset {
            // Previous neighbour: absorb.
            new_offset = r.offset;
            new_size += r.size;
            for j in i..FREE_COUNT - 1 {
                (*free_list)[j] = (*free_list)[j + 1];
            }
            FREE_COUNT -= 1;
            continue;
        }
        if new_offset + new_size == r.offset {
            // Next neighbour: absorb.
            new_size += r.size;
            for j in i..FREE_COUNT - 1 {
                (*free_list)[j] = (*free_list)[j + 1];
            }
            FREE_COUNT -= 1;
            continue;
        }
        i += 1;
    }

    // If the region ends at the high-water mark, retract instead of storing.
    if (new_offset + new_size) as usize == STATE_ARENA_OFFSET {
        STATE_ARENA_OFFSET = new_offset as usize;
        return;
    }

    // Otherwise record in the free list; if full, the region is leaked
    // until the next full reset.
    if FREE_COUNT < MAX_FREE_REGIONS {
        (*free_list)[FREE_COUNT] = FreeRegion {
            offset: new_offset,
            size: new_size,
        };
        FREE_COUNT += 1;
    } else {
        log::warn!(
            "[loader] free list full; leaking {} bytes until reset",
            new_size
        );
    }
}

/// Reset the pool: clear the free list and drop the high-water mark to 0.
/// Called from scheduler at the start of `prepare_graph`.
pub fn reset_state_arena() {
    // SAFETY: Single-threaded embedded context
    unsafe {
        STATE_ARENA_OFFSET = 0;
        FREE_COUNT = 0;
        // Content is not zeroed; alloc_state zeros each allocation.
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
    pub total_size_lo: u16, // low 16 bits (backward compat)
    pub total_size_hi: u16, // high 16 bits (uses first 2 reserved bytes)
    pub reserved: [u8; 6],
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

/// Module header (72 bytes, ABI v3). ABI v2 was 68 bytes with a u16
/// `required_caps`; v3 widens `required_caps` to u32 at bytes 6..10 so
/// every contract id in `MAX_CONTRACTS` (0..31) is expressible in the
/// manifest bitmask.
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
    pub reserved: [u8; 12],
}

impl ModuleHeader {
    pub const SIZE: usize = 72;

    /// Reserved layout (ABI v3):
    ///   byte 0: flags
    ///     bit 0: mailbox_safe — module can safely consume from mailbox channels.
    ///     bit 1: in_place_writer — module uses buffer_acquire_inplace.
    ///     bit 2: deferred_ready — module needs init time before downstream runs.
    ///     bit 3: drain_capable — module exports module_drain for live reconfigure.
    ///     bit 4: isr_module — module exports module_isr_init / module_isr_entry.
    ///     bits 5-7: reserved (0). Fine-grained permissions
    ///     (reconfigure / flash_raw / platform_raw / backing_provider /
    ///     monitor / bridge) live in the manifest binary at byte 15,
    ///     read by `LoadedModule::manifest_permissions()`.
    ///   byte 1: step_period_ms (0 = every tick, N = every N ms).
    ///   bytes 2-3: schema_size (u16 LE).
    ///   bytes 4-5: manifest_size (u16 LE).
    ///   bytes 6-9: required_caps (u32 LE) — public contract bitmask,
    ///     bit N = contract id N required in `[[resources]]`. Covers
    ///     the full 0..31 range of contract ids defined in
    ///     `provider::contract`.
    ///   bytes 10-11: reserved (0), available for future ABI extensions.
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

    /// Required public-contract bitmask from reserved[6..10].
    /// Bit N set = module declared `requires_contract = "..."` for
    /// contract id N in its manifest. Full 0..31 range since v3.
    pub fn required_caps(&self) -> u32 {
        u32::from_le_bytes([
            self.reserved[6],
            self.reserved[7],
            self.reserved[8],
            self.reserved[9],
        ])
    }

    /// Whether this module is an ISR module (Tier 2). Flags bit 4.
    pub fn is_isr_module(&self) -> bool {
        self.reserved[0] & 0x10 != 0
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

    /// Get export table pointer (used internally and by scheduler for export resolution)
    pub fn export_table_ptr(&self) -> *const u8 {
        // Compute from code_size + data_size (both u32) to avoid u16 overflow
        // in the header's export_offset field for modules > 64KB.
        let offset = self.header.code_size as usize + self.header.data_size as usize;
        unsafe { offset_ptr(self.code_base(), offset) }
    }

    /// Read the fine-grained permissions bitmap from the manifest section.
    /// The manifest binary stores this at byte offset 15 (manifest magic
    /// `FXMF` occupies bytes 0-3). Returns 0 if the manifest is missing
    /// or too small to contain the permissions byte. See
    /// `docs/architecture/abi_layers.md` and the `permission` module in
    /// `src/kernel/syscalls.rs` for the bit layout.
    pub fn manifest_permissions(&self) -> u8 {
        let manifest_size = self.header.manifest_size() as usize;
        if manifest_size < 16 {
            return 0;
        }
        let code_size = self.header.code_size as usize;
        let data_size = self.header.data_size as usize;
        let export_size = self.header.export_count as usize * 8;
        let schema_size = self.header.schema_size() as usize;
        let manifest_offset =
            ModuleHeader::SIZE + code_size + data_size + export_size + schema_size;
        unsafe {
            let p = offset_ptr(self.base, manifest_offset);
            // Verify magic before trusting byte 15.
            let magic = u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
            if magic != 0x464D5846 {
                return 0;
            } // "FXMF"
            *p.add(15)
        }
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
        let export_table = self.export_table_ptr();

        for i in 0..export_count {
            // SAFETY: i < export_count from validated header
            let entry = unsafe { read_export_entry(export_table, i) };

            if entry.hash == hash {
                let offset = entry.offset & !1;
                let fn_addr = (code_base as usize).wrapping_add(offset as usize);
                let fn_addr = hal::apply_code_bit(fn_addr);
                return Ok(fn_addr);
            }
        }

        Err(LoaderError::ExportNotFound)
    }

    /// Log header info for debugging (minimal to avoid buffer overflow)
    pub fn log_header_info(&self) {}
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

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
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
    if !hal::validate_fn_addr(addr) {
        log::error!("[loader] {}: invalid fn addr=0x{:08x}", name, addr);
        return Err(LoaderError::InvalidFnPtr);
    }
    let _ = name;
    Ok(())
}

/// Validate a loaded module's base address and header.
pub fn validate_module(module: &LoadedModule, name: &str) -> Result<(), LoaderError> {
    // Check base is in valid memory range
    if !hal::validate_module_base(module.base as usize) {
        log::error!(
            "[loader] {}: invalid base addr=0x{:08x}",
            name,
            module.base as usize
        );
        return Err(LoaderError::InvalidModuleBase);
    }

    // Check ABI version
    if module.header.abi_version != MODULE_ABI_VERSION {
        log::error!(
            "[loader] {}: abi version={} expected={}",
            name,
            module.header.abi_version,
            MODULE_ABI_VERSION
        );
        return Err(LoaderError::AbiVersionMismatch {
            expected: MODULE_ABI_VERSION,
            found: module.header.abi_version,
        });
    }

    // Check code_size is reasonable (< 384KB — protocol modules may bundle firmware+NVRAM)
    if module.header.code_size > 393216 {
        log::error!(
            "[loader] {}: code too large size={}",
            name,
            module.header.code_size
        );
        return Err(LoaderError::CodeSizeTooLarge);
    }

    // Check code base is still in valid memory
    {
        let code_base = module.code_base() as usize;
        let code_end = code_base + module.header.code_size as usize;
        let flash_end = hal::flash_end();
        if flash_end > 0 && code_end > flash_end {
            log::error!("[loader] {}: code past flash end=0x{:08x}", name, code_end);
            return Err(LoaderError::CodeOutOfBounds);
        }
    }

    // Verify integrity hash from manifest section (ABI v2)
    let manifest_size = module.header.manifest_size() as usize;
    if manifest_size >= 48 {
        let code_size = module.header.code_size as usize;
        let data_size = module.header.data_size as usize;
        let export_size = module.header.export_count as usize * 8;
        let schema_size = module.header.schema_size() as usize;
        let manifest_offset =
            ModuleHeader::SIZE + code_size + data_size + export_size + schema_size;
        let manifest_ptr = unsafe { offset_ptr(module.base, manifest_offset) };
        let manifest_data = unsafe { core::slice::from_raw_parts(manifest_ptr, manifest_size) };
        if manifest_size >= 16 {
            let magic = u32::from_le_bytes([
                manifest_data[0],
                manifest_data[1],
                manifest_data[2],
                manifest_data[3],
            ]);
            if magic == 0x464D5846 {
                let version = manifest_data[4];
                let flags = manifest_data[14];
                let has_integrity = (flags & 0x01) != 0;
                let has_signature = version >= 2 && (flags & 0x02) != 0;
                let mut computed_hash: Option<[u8; 32]> = None;
                if has_integrity {
                    // Stored hash sits after ports/resources/dependencies; its
                    // offset depends on those counts. If signature follows,
                    // the hash is still first (signature is appended after).
                    let var_size = (manifest_data[5] as usize) * 4
                        + (manifest_data[6] as usize) * 4
                        + (manifest_data[7] as usize) * 8;
                    let hash_offset = 16 + var_size;
                    if hash_offset + 32 > manifest_size {
                        log::error!("[loader] {}: manifest hash out of range", name);
                        return Err(LoaderError::IntegrityMismatch);
                    }
                    let stored_hash = &manifest_data[hash_offset..hash_offset + 32];

                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    let code_ptr = module.code_base();
                    let code_data = unsafe { core::slice::from_raw_parts(code_ptr, code_size) };
                    hasher.update(code_data);
                    if data_size > 0 {
                        let data_ptr = unsafe { offset_ptr(code_ptr, code_size) };
                        let data_section =
                            unsafe { core::slice::from_raw_parts(data_ptr, data_size) };
                        hasher.update(data_section);
                    }
                    let computed = hasher.finalize();
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&computed);

                    if !hal::verify_integrity(&h, stored_hash) {
                        log::error!("[loader] {}: integrity mismatch", name);
                        return Err(LoaderError::IntegrityMismatch);
                    }
                    computed_hash = Some(h);
                }

                // Signature verification. The feature flag gates enforcement;
                // when off, we still verify if a signature is present (to
                // surface mismatches in test builds) but do not reject on
                // missing signatures.
                if has_signature {
                    let var_size = (manifest_data[5] as usize) * 4
                        + (manifest_data[6] as usize) * 4
                        + (manifest_data[7] as usize) * 8;
                    let sig_offset = 16 + var_size + 32;
                    if sig_offset + 96 > manifest_size {
                        return Err(LoaderError::SignatureInvalid);
                    }
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&manifest_data[sig_offset..sig_offset + 64]);
                    let mut _signer_fp = [0u8; 32];
                    _signer_fp.copy_from_slice(&manifest_data[sig_offset + 64..sig_offset + 96]);

                    let hash = match computed_hash {
                        Some(h) => h,
                        None => return Err(LoaderError::SignatureInvalid),
                    };

                    let mut pubkey = [0u8; 32];
                    if hal::otp_read_signing_key(&mut pubkey) {
                        if !crate::kernel::crypto::ed25519::verify(&pubkey, &hash, &sig) {
                            log::error!("[loader] {}: signature invalid", name);
                            return Err(LoaderError::SignatureInvalid);
                        }
                    } else if cfg!(feature = "enforce_signatures") {
                        // No pubkey provisioned but enforcement demanded — reject.
                        return Err(LoaderError::SignatureInvalid);
                    }
                } else if cfg!(feature = "enforce_signatures") {
                    // Unsigned module under enforcement — reject.
                    log::error!("[loader] {}: unsigned module rejected", name);
                    return Err(LoaderError::SignatureInvalid);
                }
            }
        }
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
    if !hal::validate_fn_in_code(addr, code_base, code_size) {
        log::error!("[loader] {}: outside code", _name);
        return Err(LoaderError::InvalidFnPtr);
    }
    let _ = (_name,);
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
/// `args.params` must point to `args.params_len` readable bytes (or be null if zero-length).
/// `args.state_ptr` must point to `args.state_size` writable bytes, zeroed and exclusively owned.
pub unsafe fn invoke_new(
    new_fn: ModuleNewFn,
    syscalls: &SyscallTable,
    args: &ModuleInitArgs,
) -> Result<NewStatus, LoaderError> {
    // SAFETY: new_fn validated in lookup_exports, params/state from caller
    let result = unsafe { call_new(new_fn, args, syscalls) };

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
    /// Size of the state buffer `state_ptr` points into. Needed so the
    /// pool can reclaim the region on module teardown.
    state_size: u32,
    /// Optional drain function pointer (resolved from module_drain export).
    /// None if the module does not export module_drain.
    drain_fn: Option<ModuleDrainFn>,
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
    drain_fn: Option<ModuleDrainFn>,
    auto_register: Option<ProviderAutoRegister>,
    module_idx: u8,
}

impl DynamicModulePending {
    /// Get step function pointer (for force-completing a pending module).
    pub fn step_fn_ptr(&self) -> ModuleStepFn {
        self.step_fn
    }
    /// Get state pointer (for force-completing a pending module).
    pub fn state_ptr(&self) -> *mut u8 {
        self.state_ptr
    }

    /// Create from pre-validated parts (for debug stepping through instantiation).
    ///
    /// # Safety
    /// `args.params` must remain valid for the lifetime of the returned
    /// pending state; `args.state_ptr` must point to `args.state_size`
    /// writable bytes.
    pub fn new(
        step_fn: ModuleStepFn,
        new_fn: ModuleNewFn,
        syscalls: &SyscallTable,
        args: &ModuleInitArgs,
        name: &'static str,
    ) -> Self {
        Self {
            step_fn,
            new_fn,
            state_ptr: args.state_ptr,
            state_size: args.state_size,
            syscalls: syscalls as *const _,
            in_chan: args.in_chan,
            out_chan: args.out_chan,
            ctrl_chan: args.ctrl_chan,
            params_ptr: args.params,
            params_len: args.params_len,
            name,
            drain_fn: None,
            auto_register: None,
            module_idx: 0,
        }
    }

    /// Try to complete initialization by calling module_new again.
    ///
    /// Returns:
    /// - `Ok(Some(module))` - initialization complete
    /// - `Ok(None)` - still pending, call again after yielding
    /// - `Err(e)` - initialization failed
    ///
    /// # Safety
    /// The pending state's `state_ptr`, `params_ptr`, `syscalls`, and
    /// channel handles must still be valid (the underlying allocations
    /// must not have been freed since `start_new` returned `Pending`).
    /// Re-entrancy on the same `DynamicModulePending` is unsound.
    pub unsafe fn try_complete(&mut self) -> Result<Option<DynamicModule>, LoaderError> {
        let args = ModuleInitArgs {
            in_chan: self.in_chan,
            out_chan: self.out_chan,
            ctrl_chan: self.ctrl_chan,
            params: self.params_ptr,
            params_len: self.params_len,
            state_ptr: self.state_ptr,
            state_size: self.state_size,
        };
        match invoke_new(self.new_fn, &*self.syscalls, &args)? {
            NewStatus::Ready => {
                log::info!("[inst] loaded {}", self.name);
                if let Some(ar) = self.auto_register.as_ref() {
                    ar.register(self.module_idx, self.state_ptr, self.name);
                }
                Ok(Some(DynamicModule {
                    step_fn: self.step_fn,
                    state_ptr: self.state_ptr,
                    state_size: self.state_size as u32,
                    drain_fn: self.drain_fn,
                }))
            }
            NewStatus::Pending => Ok(None),
        }
    }

    /// Release this pending module's state buffer back to the pool.
    /// Consumes the pending state. Use when dropping without completing.
    ///
    /// # Safety
    /// The state buffer must not be referenced anywhere after this call
    /// — `module_new` must not have stashed `state_ptr` into a global
    /// (e.g. via a successful provider registration). Aborting only
    /// makes sense for a `Pending` that has not transitioned to Ready.
    pub unsafe fn abort(self) {
        free_state_range(self.state_ptr, self.state_size);
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
    pub fn from_parts(step_fn: ModuleStepFn, state_ptr: *mut u8, state_size: u32) -> Self {
        Self {
            step_fn,
            state_ptr,
            state_size,
            drain_fn: None,
        }
    }

    /// Release this module's state buffer back to the pool. Consumes the
    /// module. Call this only when the module is being torn down.
    ///
    /// # Safety
    /// The module must not be stepped after this call. The caller is
    /// responsible for also freeing any heap arena recorded separately
    /// (see `free_state_range`).
    pub unsafe fn free(self) {
        if !self.state_ptr.is_null() && self.state_size > 0 {
            free_state_range(self.state_ptr, self.state_size as usize);
        }
    }

    /// Call module_drain if the module exports it.
    /// Returns the drain function's return code, or -1 if not drain-capable.
    ///
    /// # Safety
    /// `self.state_ptr` must still point at the module's live state and
    /// the module's code must remain mapped — i.e. the `DynamicModule`
    /// has not been `free()`d and the underlying `LoadedModule` has not
    /// been unloaded. Drain may invoke arbitrary syscalls on the
    /// module's behalf and must run on the module's owning core.
    pub unsafe fn call_drain(&self) -> i32 {
        match self.drain_fn {
            Some(f) => call_drain(f, self.state_ptr),
            None => -1,
        }
    }

    /// Returns true if this module exports module_drain.
    pub fn has_drain(&self) -> bool {
        self.drain_fn.is_some()
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
    /// - `params.ptr` must be valid for `params.len` bytes
    /// - `module` must remain valid for the module's lifetime
    #[inline(never)]
    pub unsafe fn start_new(
        module: &LoadedModule,
        syscalls: &SyscallTable,
        channels: ChannelHandles,
        params: ParamSlice,
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

        // Set instantiation state so syscalls made from module_new can
        // locate the module by index → state pointer.
        let inst_idx = super::scheduler::current_module_index();
        super::scheduler::set_instantiation_state(inst_idx, state_ptr);

        // Resolve optional provider-auto-registration exports. If the
        // module declares itself a provider, the loader calls
        // `register_module_provider` as soon as module_new() returns
        // Ready — module code never touches registration directly.
        let auto_register = ProviderAutoRegister::resolve(module);

        // 4b. If module exports module_arena_size, allocate and init heap
        if let Ok(arena_addr) = module.get_export_addr(export_hashes::MODULE_ARENA_SIZE) {
            let arena_fn: ModuleStateSizeFn = fn_ptr_from_addr(arena_addr);
            let arena_size = call_state_size(arena_fn);
            if arena_size > 0 {
                if let Ok(arena_ptr) = alloc_state(arena_size) {
                    let module_idx = super::scheduler::current_module_index();
                    super::heap::init_module_heap(module_idx, arena_ptr, arena_size);
                }
            }
        }

        // 5. Initialize module (FFI call, but validated)
        if let Err(e) = invoke_init(module, syscalls, name) {
            free_state_range(state_ptr, required_size);
            return Err(e);
        }

        // 5b. Resolve optional module_drain export
        let drain_fn: Option<ModuleDrainFn> = module
            .get_export_addr(export_hashes::MODULE_DRAIN)
            .ok()
            .map(|addr| fn_ptr_from_addr(addr));

        // 6. Try to create instance (may return pending)
        let init_args = ModuleInitArgs {
            in_chan: channels.in_chan,
            out_chan: channels.out_chan,
            ctrl_chan: channels.ctrl_chan,
            params: params.ptr,
            params_len: params.len,
            state_ptr,
            state_size: required_size,
        };
        match invoke_new(exports.new_fn, syscalls, &init_args)? {
            NewStatus::Ready => {
                log::info!("[inst] loaded {}", name);
                if let Some(ar) = auto_register.as_ref() {
                    ar.register(inst_idx as u8, state_ptr, name);
                }
                Ok(StartNewResult::Ready(DynamicModule {
                    step_fn: exports.step_fn,
                    state_ptr,
                    state_size: required_size as u32,
                    drain_fn,
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
                    in_chan: channels.in_chan,
                    out_chan: channels.out_chan,
                    ctrl_chan: channels.ctrl_chan,
                    params_ptr: params.ptr,
                    params_len: params.len,
                    name,
                    drain_fn,
                    auto_register,
                    module_idx: inst_idx as u8,
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
    let mut hints = [ChannelHint {
        port_type: 0,
        port_index: 0,
        buffer_size: 0,
    }; MAX_HINTS_PER_MODULE];

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
    for (i, hint) in hints.iter_mut().take(count).enumerate() {
        let offset = i * 4;
        *hint = ChannelHint {
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
pub fn find_hint_for_port(hints: &[ChannelHint], port_type: u8, port_index: u8) -> u16 {
    for hint in hints {
        if hint.port_type == port_type && hint.port_index == port_index {
            return hint.buffer_size;
        }
    }
    0
}

// ============================================================================
// Export resolution for provider dispatch
// ============================================================================

/// Resolve an export hash to an absolute address for a given module.
///
/// Used by loader-side lookups that bind module exports to kernel-side
/// function pointers — e.g. the flash-store and NVMe-backing
/// registration paths pass an FNV-1a hash of an exported symbol name,
/// and this helper walks the module's export table to get the real
/// function address (code_base + offset, with the Thumb bit applied
/// for ARMv7-M/ARMv8-M).
///
/// Returns `Some(absolute_address)` on success, `None` if the hash is
/// not found (caller may then fall back to treating the value as a
/// raw address).
pub fn resolve_export_for_module(module_idx: usize, export_hash: u32) -> Option<usize> {
    let (code_base, export_table, export_count) = super::scheduler::get_module_exports(module_idx);

    if export_table.is_null() || export_count == 0 || code_base == 0 {
        return None;
    }

    for i in 0..export_count as usize {
        let entry = unsafe { read_export_entry(export_table, i) };
        if entry.hash == export_hash {
            let offset = entry.offset & !1;
            let fn_addr = code_base.wrapping_add(offset as usize);
            let fn_addr = hal::apply_code_bit(fn_addr);
            return Some(fn_addr);
        }
    }

    None
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
        assert_eq!(
            fnv1a32(b"module_state_size"),
            export_hashes::MODULE_STATE_SIZE
        );
        assert_eq!(fnv1a32(b"module_init"), export_hashes::MODULE_INIT);
        assert_eq!(fnv1a32(b"module_new"), export_hashes::MODULE_NEW);
        assert_eq!(fnv1a32(b"module_step"), export_hashes::MODULE_STEP);
        assert_eq!(
            fnv1a32(b"module_channel_hints"),
            export_hashes::MODULE_CHANNEL_HINTS
        );
        assert_eq!(
            fnv1a32(b"module_provider_dispatch"),
            export_hashes::MODULE_PROVIDER_DISPATCH
        );
        assert_eq!(
            fnv1a32(b"module_provides_contract"),
            export_hashes::MODULE_PROVIDES_CONTRACT
        );
        assert_eq!(
            fnv1a32(b"module_flash_store_dispatch"),
            export_hashes::MODULE_FLASH_STORE_DISPATCH
        );
    }
}
