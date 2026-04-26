//! Provider dispatch — registered handlers for contract operations.
//!
//! ## Routing
//!
//! A contract is the portable surface a module asks for (HAL GPIO, HAL
//! SPI, channel, timer, FS, …). Each contract has a `ProviderVTable`
//! with `call`, optional `query`, and a `default_close_op`. Consumers
//! call `provider_open(contract, open_op, config, len)` to get a
//! handle; the kernel records which contract the handle belongs to in
//! `HANDLE_BINDINGS`, and subsequent `provider_call` / `provider_query`
//! / `provider_close` route through that contract's vtable.
//!
//! Handle resolution order (see `lookup_contract`):
//!   1. Tagged fds (event / timer / DMA-fd) self-identify via their
//!      high-bit tag — no tracking entry required.
//!   2. Handles returned by `provider_open` are looked up in
//!      `HANDLE_BINDINGS`.
//!   3. Anything else — `handle = -1` globals and scheduler-assigned
//!      channel fds — falls through to class-byte routing, where the
//!      opcode's high byte identifies the contract and
//!      `dispatch(contract, …)` invokes the registered provider chain.
//!
//! ## Registration
//!
//! Each contract's call path can come from:
//! - A kernel-internal function (registered at startup via `register()`).
//! - A PIC module export (registered by the loader via
//!   `register_module_provider()` after the module publishes a
//!   `module_provides_contract` export). Module providers form a chain
//!   (stack) per contract. The top-of-chain provider receives dispatch
//!   first. Middleware modules (TLS, compression) intercept calls and
//!   forward to the layer below via `CHAIN_NEXT`.

use crate::kernel::errno;
use crate::kernel::fd;

/// Stable contract identifier. The vtable registry is indexed by this id;
/// the same value appears in the opcode's high byte so class-byte routing
/// (used for `handle = -1` globals) can reach the same vtable.
pub type ContractId = u16;

pub mod contract {
    //! Contract ids — the public, stable dispatch surface. Each id
    //! below maps 1:1 to a contract file under `modules/sdk/contracts/`
    //! and to a row in the inventory tables in
    //! `docs/architecture/abi_layers.md`.
    //!
    //! The value `0x000C` is intentionally NOT a public contract.
    //! It is the kernel-internal dispatch bucket for the 0x0Cxx opcode
    //! range (kernel_abi primitives plus permission-gated orchestration
    //! ops). Modules must not `provider_open` against it; the kernel
    //! uses it only for routing. See `INTERNAL_DISPATCH_BUCKET` below.
    pub const COMMON: u16 = 0x0000;
    pub const HAL_GPIO: u16 = 0x0001;
    pub const HAL_SPI: u16 = 0x0002;
    pub const HAL_I2C: u16 = 0x0003;
    pub const HAL_PIO: u16 = 0x0004;
    pub const CHANNEL: u16 = 0x0005;
    pub const TIMER: u16 = 0x0006;
    pub const FS: u16 = 0x0009;
    pub const BUFFER: u16 = 0x000A;
    pub const EVENT: u16 = 0x000B;
    /// NIC ring management (create/destroy/info). Drivers declare
    /// `requires_contract = "platform_nic_ring"` in their manifest;
    /// the `platform_raw` permission gates the specific opcodes in
    /// addition to the contract claim.
    pub const PLATFORM_NIC_RING: u16 = 0x0007;
    /// Raw DMA channel allocation. Handle returned by `channel::ALLOC`
    /// is a raw DMA channel number. Used by drivers that manage their
    /// own transfer lifecycle (e.g. `spi_pl022`, `pio_rp` CMD
    /// transfers). The `platform_raw` permission gates the opcodes in
    /// addition to the contract claim. Kernel-side handle-type
    /// enforcement is in `is_dma_channel_handle` in
    /// `src/platform/rp/providers.rs`.
    pub const PLATFORM_DMA: u16 = 0x0008;
    /// Async DMA fd with ping-pong queuing. Handle returned by
    /// `fd::CREATE` is an FD_TAG_DMA-tagged fd. Used by drivers that
    /// want kernel-managed async DMA (e.g. `pio_rp` streams,
    /// `st7701s`). Distinct contract from `PLATFORM_DMA` — drivers
    /// that use both families declare both in `[[resources]]`. The
    /// `platform_raw` permission gates the opcodes in addition to the
    /// contract claim. Kernel-side handle-type enforcement is in
    /// `is_dma_fd_handle` in `src/platform/rp/providers.rs`.
    pub const PLATFORM_DMA_FD: u16 = 0x0011;
    /// Handle-scoped PCIe device binding. `provider_open` takes a
    /// selector string (board alias like `"m2_primary"` or
    /// `"@class=nvme"`) and returns a handle that carries all
    /// subsequent config-space, BAR-map, and MSI-X ops. Drivers
    /// declare `requires_contract = "pcie_device"`; the
    /// `platform_raw` permission gates the underlying opcodes.
    pub const PCIE_DEVICE: u16 = 0x0012;
    pub const HAL_UART: u16 = 0x000D;
    pub const HAL_ADC: u16 = 0x000E;
    pub const HAL_PWM: u16 = 0x000F;
    pub const KEY_VAULT: u16 = 0x0010;

    /// Kernel-internal dispatch bucket for 0x0Cxx opcodes. NOT a
    /// public contract. `syscall_provider_open` rejects this id from
    /// module code; it is only reachable from intra-kernel paths
    /// (vtable registration, primitive routing).
    pub const INTERNAL_DISPATCH_BUCKET: u16 = 0x000C;

    // Short-name aliases used by kernel-side dispatchers (`GPIO`, `SPI`,
    // `PIO`, `UART`, `ADC`, `PWM`). Same numeric values as the `HAL_*`
    // constants — the alias just drops the prefix for callsite brevity.
    pub const GPIO: u16 = HAL_GPIO;
    pub const SPI: u16 = HAL_SPI;
    pub const I2C: u16 = HAL_I2C;
    pub const PIO: u16 = HAL_PIO;
    pub const UART: u16 = HAL_UART;
    pub const ADC: u16 = HAL_ADC;
    pub const PWM: u16 = HAL_PWM;
}

/// Function signatures for a contract vtable.
///
/// `call` handles every operation on a handle or global (handle=-1)
/// op — including open-style ops that return a handle (CLAIM,
/// SET_INPUT, OPEN, CREATE, …). The caller picks the open-style
/// opcode; `provider_open` tracks the returned handle against the
/// contract.
///
/// `query` reads introspection state. `default_close_op` is the opcode
/// `provider_close` invokes to release a handle (e.g. `gpio::RELEASE`,
/// `channel::CLOSE`). Contracts whose handles don't need a close hook
/// (BUFFER, some net paths) leave it as 0, in which case
/// `provider_close` just releases the tracking entry.
pub type VTableCallFn = unsafe fn(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32;
pub type VTableQueryFn = unsafe fn(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32;

/// A contract's dispatch vtable. Registered once at kernel init via
/// `register_vtable`.
pub struct ProviderVTable {
    pub contract: ContractId,
    pub call: VTableCallFn,
    pub query: Option<VTableQueryFn>,
    /// Opcode used by `provider_close` to release a handle. 0 = none.
    pub default_close_op: u32,
}

/// Maximum number of contracts. Contract ids fit in 5 bits today.
pub const MAX_CONTRACTS: usize = 32;

/// Registered vtables, indexed by contract id.
static mut VTABLES: [Option<&'static ProviderVTable>; MAX_CONTRACTS] =
    [const { None }; MAX_CONTRACTS];

/// Register a contract vtable at kernel init. Overwrites any previous
/// registration for the same contract id. Panics if the contract id is
/// out of range.
pub fn register_vtable(vt: &'static ProviderVTable) {
    let idx = vt.contract as usize;
    assert!(idx < MAX_CONTRACTS, "contract id out of range");
    unsafe {
        VTABLES[idx] = Some(vt);
    }
}

/// Look up a contract's vtable by id.
fn vtable_for(contract: ContractId) -> Option<&'static ProviderVTable> {
    let idx = contract as usize;
    if idx >= MAX_CONTRACTS {
        return None;
    }
    unsafe { VTABLES[idx] }
}

// ── Handle → contract tracking ───────────────────────────────────────
//
// Untagged handles returned by `provider_open` (GPIO pin numbers, DMA
// channel numbers, HAL handles) are recorded here so `provider_call` /
// `provider_query` / `provider_close` can route by the bound contract
// instead of inferring from the opcode's class byte. Tagged fds
// (event / timer / DMA-fd) identify their contract via tag bits and
// don't consume a slot.

const MAX_TRACKED: usize = 128;

struct HandleBinding {
    handle: i32,
    contract: ContractId,
}

static mut HANDLE_BINDINGS: [HandleBinding; MAX_TRACKED] = [const {
    HandleBinding {
        handle: -1,
        contract: 0,
    }
}; MAX_TRACKED];

fn track_handle(handle: i32, contract: ContractId) {
    if handle < 0 {
        return;
    }
    // Tagged fds (event / timer / dma) are self-identifying — the FD
    // tag carries the contract id, so `lookup_contract` resolves them
    // without a tracking table entry. Skip tracking to keep the table
    // available for untagged handles (GPIO pins, DMA channel numbers,
    // HAL handles) that genuinely need an entry.
    if fd_tag_contract(handle).is_some() {
        return;
    }
    unsafe {
        let p = &raw mut HANDLE_BINDINGS;
        for slot in (*p).iter_mut() {
            if slot.handle == -1 {
                slot.handle = handle;
                slot.contract = contract;
                return;
            }
        }
        log::warn!("[provider] handle tracking full, {} untracked", handle);
    }
}

/// Public lookup — returns the contract bound to `handle`. Resolution
/// order: tagged FD (self-identifying via high-bit tag) → tracked
/// binding from `provider_open` → None.
pub fn contract_of(handle: i32) -> Option<ContractId> {
    lookup_contract(handle)
}

/// Derive a contract from an FD tag, if the handle carries one. This
/// is the fast path for scheduler-assigned fds (channel / event /
/// timer) and for tagged-fd opens (DMA fd). Returns `None` for raw
/// integer handles (GPIO pin numbers, DMA channel numbers, etc.) —
/// those rely on the `HANDLE_BINDINGS` tracking table populated by
/// `provider_open`.
fn fd_tag_contract(handle: i32) -> Option<ContractId> {
    if handle < 0 {
        return None;
    }
    use crate::kernel::fd;
    // Tag 0 (FD_TAG_CHANNEL) produces handles indistinguishable from
    // raw integers because tag 0 doesn't set any high bits. Resolving
    // channels via tag would clash with e.g. DMA channel numbers
    // (0..15) that share the same bit pattern. Keep channel handles
    // on the opcode-class-byte dispatch path — CHANNEL ops all carry
    // 0x05 in the opcode's high byte so routing is unambiguous. The
    // explicit tags below (2, 3, 7) have high bits set, so no
    // collision with raw small integers.
    let (tag, _slot) = fd::untag_fd(handle);
    match tag {
        _t if _t == fd::FD_TAG_EVENT => Some(contract::EVENT),
        _t if _t == fd::FD_TAG_TIMER => Some(contract::TIMER),
        _t if _t == fd::FD_TAG_DMA => Some(contract::PLATFORM_DMA_FD),
        _t if _t == fd::FD_TAG_KEY_VAULT => Some(contract::KEY_VAULT),
        _t if _t == fd::FD_TAG_PCIE_DEVICE => Some(contract::PCIE_DEVICE),
        _t if _t == fd::FD_TAG_NIC_RING => Some(contract::PLATFORM_NIC_RING),
        _t if _t == fd::FD_TAG_DMA_CHANNEL => Some(contract::PLATFORM_DMA),
        _t if _t == fd::FD_TAG_FS => Some(contract::FS),
        _t if _t == fd::FD_TAG_BUFFER => Some(contract::BUFFER),
        _t if _t == fd::FD_TAG_HAL_GPIO => Some(contract::HAL_GPIO),
        _t if _t == fd::FD_TAG_HAL_SPI => Some(contract::HAL_SPI),
        _t if _t == fd::FD_TAG_HAL_I2C => Some(contract::HAL_I2C),
        _t if _t == fd::FD_TAG_HAL_UART => Some(contract::HAL_UART),
        _t if _t == fd::FD_TAG_HAL_ADC => Some(contract::HAL_ADC),
        _t if _t == fd::FD_TAG_HAL_PWM => Some(contract::HAL_PWM),
        _t if _t == fd::FD_TAG_HAL_PIO => Some(contract::HAL_PIO),
        _ => None,
    }
}

fn lookup_contract(handle: i32) -> Option<ContractId> {
    if handle < 0 {
        return None;
    }
    if let Some(c) = fd_tag_contract(handle) {
        return Some(c);
    }
    unsafe {
        let p = &raw const HANDLE_BINDINGS;
        for slot in (*p).iter() {
            if slot.handle == handle {
                return Some(slot.contract);
            }
        }
    }
    None
}

fn release_handle(handle: i32) {
    if handle < 0 {
        return;
    }
    unsafe {
        let p = &raw mut HANDLE_BINDINGS;
        for slot in (*p).iter_mut() {
            if slot.handle == handle {
                slot.handle = -1;
                slot.contract = 0;
                return;
            }
        }
    }
}

// ── Handle-scoped dispatch (new API) ─────────────────────────────────

/// Contract → FD-tag mapping. Every contract that returns a handle
/// to a module appears here so `provider_open` can apply the tag
/// that matches `fd_tag_contract`'s inverse lookup. Contracts
/// returning `None` don't use tagged fds (CHANNEL is the only one).
fn contract_to_tag(contract: ContractId) -> Option<i32> {
    match contract {
        c if c == contract::EVENT => Some(fd::FD_TAG_EVENT),
        c if c == contract::TIMER => Some(fd::FD_TAG_TIMER),
        c if c == contract::PLATFORM_DMA_FD => Some(fd::FD_TAG_DMA),
        c if c == contract::KEY_VAULT => Some(fd::FD_TAG_KEY_VAULT),
        c if c == contract::PCIE_DEVICE => Some(fd::FD_TAG_PCIE_DEVICE),
        c if c == contract::PLATFORM_NIC_RING => Some(fd::FD_TAG_NIC_RING),
        c if c == contract::PLATFORM_DMA => Some(fd::FD_TAG_DMA_CHANNEL),
        c if c == contract::FS => Some(fd::FD_TAG_FS),
        c if c == contract::BUFFER => Some(fd::FD_TAG_BUFFER),
        c if c == contract::HAL_GPIO => Some(fd::FD_TAG_HAL_GPIO),
        c if c == contract::HAL_SPI => Some(fd::FD_TAG_HAL_SPI),
        c if c == contract::HAL_I2C => Some(fd::FD_TAG_HAL_I2C),
        c if c == contract::HAL_UART => Some(fd::FD_TAG_HAL_UART),
        c if c == contract::HAL_ADC => Some(fd::FD_TAG_HAL_ADC),
        c if c == contract::HAL_PWM => Some(fd::FD_TAG_HAL_PWM),
        c if c == contract::HAL_PIO => Some(fd::FD_TAG_HAL_PIO),
        _ => None,
    }
}

/// Open a handle on the named contract. The caller chooses the
/// open-style opcode (e.g. `gpio::CLAIM`, `gpio::SET_INPUT`,
/// `spi::OPEN`, `timer::CREATE`) — `config` / `config_len` are the
/// operation's arg payload. Returns a handle (>= 0) on success,
/// negative errno on failure.
///
/// The returned handle carries the contract's FD tag per
/// `contract_to_tag`. Handlers that self-tag (event, timer, DMA-fd,
/// key_vault, PCIE_DEVICE) pass through if the tag matches; handlers
/// that return a raw slot get tagged here. Handlers that return a
/// mismatched tag are refused with ENOSYS — better to fail loudly
/// than silently misroute.
pub fn provider_open(
    contract: ContractId,
    open_op: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    let handle = match vtable_for(contract) {
        Some(vt) => unsafe { (vt.call)(-1, open_op, config as *mut u8, config_len) },
        None => {
            // No vtable — fall back to the contract's registered
            // chain dispatcher directly.
            unsafe { dispatch(contract, -1, open_op, config as *mut u8, config_len) }
        }
    };
    if handle < 0 {
        return handle;
    }
    match contract_to_tag(contract) {
        Some(expected) => {
            let (actual, slot) = fd::untag_fd(handle);
            if actual == expected {
                handle
            } else if actual == 0 {
                fd::tag_fd(expected, slot)
            } else {
                log::error!(
                    "[provider] contract {:#x} open returned handle with tag={} (expected {}); refusing",
                    contract, actual, expected,
                );
                errno::ENOSYS
            }
        }
        None => {
            // Untagged contract (CHANNEL): class-byte dispatch looks
            // the handle up via HANDLE_BINDINGS.
            track_handle(handle, contract);
            handle
        }
    }
}

/// Invoke an operation on an open handle.
///
/// Routing resolution order:
///   1. `handle >= 0` with an FD tag: the tag self-identifies the
///      contract via `fd_tag_contract`.
///   2. Channel fds (tag 0) + `handle == -1` globals: HANDLE_BINDINGS
///      lookup, then class-byte dispatch on the opcode's high byte.
///
/// Tagged handles pass through unchanged. Handlers strip with
/// `slot_of(handle)` at entry when they need the raw slot, or inspect
/// the tag when they need to reject a wrong-family handle (e.g. a
/// channel-op handler rejecting a DMA-fd tag).
pub fn provider_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            return unsafe { (vt.call)(handle, op, arg, arg_len) };
        }
        return unsafe { dispatch(contract, handle, op, arg, arg_len) };
    }
    let contract = ((op >> 8) & 0xFF) as u16;
    unsafe { dispatch(contract, handle, op, arg, arg_len) }
}

/// Query handle state by key.
pub fn provider_query(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32 {
    if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            return match vt.query {
                Some(f) => unsafe { f(handle, key, out, out_len) },
                None => errno::ENOSYS,
            };
        }
    }
    errno::ENOSYS
}

/// Close an open handle using the contract's default close opcode.
/// For contracts whose vtable declares `default_close_op = 0`,
/// `provider_close` only releases the tracking entry and returns 0.
pub fn provider_close(handle: i32) -> i32 {
    let result = if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            if vt.default_close_op != 0 {
                unsafe { (vt.call)(handle, vt.default_close_op, core::ptr::null_mut(), 0) }
            } else {
                0
            }
        } else {
            errno::ENOSYS
        }
    } else {
        errno::ENOSYS
    };
    release_handle(handle);
    result
}

/// Clear all handle tracking. Called on `scheduler::reset` so new
/// graphs don't inherit stale handle→contract bindings.
pub fn reset_handle_tracking() {
    unsafe {
        let p = &raw mut HANDLE_BINDINGS;
        for slot in (*p).iter_mut() {
            slot.handle = -1;
            slot.contract = 0;
        }
    }
}

/// Function signature for a kernel-internal contract provider.
/// Arguments: handle, opcode, arg pointer, arg length.
/// Returns: result code (0 = success, >0 = bytes/count, <0 = errno).
pub type ProviderDispatch =
    unsafe fn(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

/// Function signature for a PIC module contract provider. Shape matches
/// `ProviderDispatch` with the module's state pointer prepended. Called
/// synchronously from kernel context — must not block or perform async I/O.
pub type ModuleProviderDispatchFn = unsafe extern "C" fn(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32;

/// Maximum registered contracts (indexed by `ContractId`).
const MAX_PROVIDERS: usize = 32;

/// Maximum chain depth per contract (kernel + up to 3 middleware modules).
pub const MAX_CHAIN_DEPTH: usize = 3;

/// Flag ORed onto opcode to dispatch to the next provider below the caller.
pub const CHAIN_NEXT: u32 = 0x0001_0000;

/// A single layer in a provider chain.
struct ProviderLayer {
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
}

/// Provider entry — combines kernel and module providers for a single contract.
struct ProviderEntry {
    /// Kernel-internal dispatch (None if no kernel provider).
    kernel_dispatch: Option<ProviderDispatch>,
    /// Module provider chain (stack). chain[depth-1] is the top.
    chain: [Option<ProviderLayer>; MAX_CHAIN_DEPTH],
    /// Number of active layers in the chain.
    depth: u8,
}

impl ProviderEntry {
    const fn empty() -> Self {
        Self {
            kernel_dispatch: None,
            chain: [const { None }; MAX_CHAIN_DEPTH],
            depth: 0,
        }
    }
}

/// Provider table — indexed by contract id (0x00..0x1F).
static mut PROVIDERS: [ProviderEntry; MAX_PROVIDERS] =
    [const { ProviderEntry::empty() }; MAX_PROVIDERS];

/// Register a kernel-internal provider for a contract. Called at
/// kernel startup.
///
/// Panics if `contract as usize >= MAX_PROVIDERS`.
pub fn register(contract: ContractId, dispatch: ProviderDispatch) {
    let idx = contract as usize;
    assert!(idx < MAX_PROVIDERS, "contract id out of range");
    unsafe {
        PROVIDERS[idx].kernel_dispatch = Some(dispatch);
    }
}

/// Contracts a PIC module is allowed to provide. The loader calls
/// `register_module_provider` after resolving a module's
/// `module_provides_contract` export — a compromised or mis-built
/// module could in principle name any contract. We whitelist only
/// the contracts where it's architecturally legitimate for a module
/// to be the provider: the HAL peripherals and FS (bare-metal
/// filesystems). CHANNEL / TIMER / BUFFER / EVENT / KEY_VAULT and
/// the internal dispatch bucket are kernel-only and must not be
/// replaceable by a module.
#[inline]
fn is_module_providable(contract: ContractId) -> bool {
    matches!(
        contract,
        contract::HAL_GPIO
            | contract::HAL_SPI
            | contract::HAL_I2C
            | contract::HAL_PIO
            | contract::HAL_UART
            | contract::HAL_ADC
            | contract::HAL_PWM
            | contract::FS
    )
}

/// Register a PIC module as provider for a contract.
///
/// Pushes the module onto the top of the chain. Returns 0 on success,
/// EINVAL if `contract` is out of range or not in the module-providable
/// whitelist, or if the dispatch pointer is outside the module's code
/// region; EBUSY if chain is full.
pub fn register_module_provider(
    contract: ContractId,
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::EINVAL;
    }
    if !is_module_providable(contract) {
        log::error!(
            "[provider] module {} tried to register for non-providable contract 0x{:04x}",
            module_idx,
            contract,
        );
        return errno::EACCES;
    }

    // Validate dispatch function pointer is within the registering module's
    // code region. Prevents a corrupted module from registering a pointer
    // into kernel memory or another module's code.
    let fn_addr = dispatch as usize;
    let (code_base, code_size) = crate::kernel::scheduler::module_code_region(module_idx as usize);
    if code_base != 0 && code_size != 0 {
        let code_end = code_base + code_size as usize;
        if fn_addr < code_base || fn_addr >= code_end {
            log::error!(
                "[provider] module {} fn_ptr 0x{:08x} outside code region 0x{:08x}..0x{:08x}",
                module_idx,
                fn_addr,
                code_base,
                code_end
            );
            return errno::EINVAL;
        }
        // On Cortex-M (Thumb mode): verify LSB is set
        #[cfg(target_arch = "arm")]
        if fn_addr & 1 == 0 {
            log::error!(
                "[provider] module {} fn_ptr 0x{:08x} missing Thumb bit",
                module_idx,
                fn_addr
            );
            return errno::EINVAL;
        }
    }

    unsafe {
        let entry = &mut PROVIDERS[idx];

        // Check same module isn't already registered for this class
        for i in 0..entry.depth as usize {
            if let Some(ref layer) = entry.chain[i] {
                if layer.module_idx == module_idx {
                    return errno::EBUSY;
                }
            }
        }

        // Check chain capacity
        if entry.depth as usize >= MAX_CHAIN_DEPTH {
            return errno::EBUSY;
        }

        // Push onto top of chain
        let d = entry.depth as usize;
        entry.chain[d] = Some(ProviderLayer {
            module_idx,
            dispatch,
            state,
        });
        entry.depth += 1;
        log::info!(
            "[provider] module {} registered for contract 0x{:04x} at depth {}",
            module_idx,
            contract,
            entry.depth
        );
    }
    0
}

/// Release all module providers owned by a given module index.
/// Called on module finish (Done/Error) for cleanup.
/// Compacts chains to maintain stack ordering.
pub fn release_module_providers(module_idx: u8) {
    unsafe {
        let p = &raw mut PROVIDERS;
        let providers = &mut *p;
        for entry in providers.iter_mut() {
            // Compact: remove layers belonging to this module
            let mut write = 0usize;
            for read in 0..entry.depth as usize {
                let keep = match &entry.chain[read] {
                    Some(layer) => layer.module_idx != module_idx,
                    None => false,
                };
                if keep {
                    if write != read {
                        // Move layer down
                        let layer = entry.chain[read].take();
                        entry.chain[write] = layer;
                    }
                    write += 1;
                }
            }
            // Clear remaining slots
            for i in write..entry.depth as usize {
                entry.chain[i] = None;
            }
            entry.depth = write as u8;
        }
    }
}

/// Dispatch an operation to the registered provider for `contract`.
///
/// Module provider chain top takes priority. Falls back to kernel provider.
/// Returns E_NOSYS if no provider is registered for this contract.
///
/// # Safety
/// `arg` must satisfy the aliasing and validity requirements expected by the
/// registered dispatch handler for the given `contract` and `opcode`.
pub unsafe fn dispatch(
    contract: ContractId,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    unsafe {
        let entry = &PROVIDERS[idx];

        // Dispatch to top of chain if any module providers registered
        if entry.depth > 0 {
            let top = (entry.depth - 1) as usize;
            if let Some(ref layer) = entry.chain[top] {
                let saved = crate::kernel::scheduler::current_module_index();
                crate::kernel::scheduler::set_current_module(layer.module_idx as usize);
                let result = (layer.dispatch)(layer.state, handle, opcode, arg, arg_len);
                crate::kernel::scheduler::set_current_module(saved);
                return result;
            }
        }

        // Fall back to kernel provider
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => {
                log::warn!(
                    "[provider] contract 0x{:04x} op 0x{:04x}: no provider",
                    contract,
                    opcode
                );
                errno::ENOSYS
            }
        }
    }
}

/// Dispatch to the next provider below the caller in the chain.
///
/// Called when a module sets the CHAIN_NEXT flag on an opcode.
/// Finds the caller's position in the chain and dispatches to the layer below.
/// If the caller is at the bottom (position 0), dispatches to the kernel provider.
///
/// # Safety
/// Same requirements as `dispatch`.
pub unsafe fn dispatch_next(
    caller_module: u8,
    contract: ContractId,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    unsafe {
        let entry = &PROVIDERS[idx];

        // Find caller's position in the chain (search top-down)
        let mut caller_pos: Option<usize> = None;
        for i in (0..entry.depth as usize).rev() {
            if let Some(ref layer) = entry.chain[i] {
                if layer.module_idx == caller_module {
                    caller_pos = Some(i);
                    break;
                }
            }
        }

        let pos = match caller_pos {
            Some(p) => p,
            None => {
                // Caller not in chain — fall back to kernel provider
                return match entry.kernel_dispatch {
                    Some(handler) => handler(handle, opcode, arg, arg_len),
                    None => errno::ENOSYS,
                };
            }
        };

        // If caller is at bottom (position 0), dispatch to kernel provider
        if pos == 0 {
            return match entry.kernel_dispatch {
                Some(handler) => handler(handle, opcode, arg, arg_len),
                None => errno::ENOSYS,
            };
        }

        // Dispatch to layer below
        let below = pos - 1;
        if let Some(ref layer) = entry.chain[below] {
            let saved = crate::kernel::scheduler::current_module_index();
            crate::kernel::scheduler::set_current_module(layer.module_idx as usize);
            let result = (layer.dispatch)(layer.state, handle, opcode, arg, arg_len);
            crate::kernel::scheduler::set_current_module(saved);
            return result;
        }

        // Gap in chain — shouldn't happen but fall back to kernel
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => errno::ENOSYS,
        }
    }
}
