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
//!   (stack) per contract. Middleware modules (TLS, compression)
//!   intercept calls and forward to the layer below via `CHAIN_NEXT`.
//!
//! Each layer carries an **instance selector**: `0` for the default
//! provider, or the hash of a short name (a volume, say) for a keyed one.
//! Class-byte dispatch (`handle == -1`) reaches the top-most *unkeyed*
//! layer; keyed layers are reachable only by name via `provider_call_sel`.
//! That is what lets several providers of one contract coexist — two
//! `fat32` volumes behind a `mount` router — without any of them shadowing
//! another. Selectors are unique per contract: a duplicate is refused at
//! registration, because a shadowed provider is silently unreachable.
//!
//! The name `platform` is reserved: `provider_call_sel("platform", …)`
//! reaches the platform's own (kernel-registered) provider of the contract
//! beneath any module layers — the host filesystem under a graph-local
//! `fat32`, say. A handle minted through any selector is returned as a
//! routed handle that names its minting provider, so its handle-bound ops
//! reach that provider however the default layer changes (see `Route`).

use crate::kernel::ipc::fd;
use crate::kernel::sys::errno;

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

    /// Directory-like name-keyed storage surface — opcode class 0x13xx.
    /// See `modules/sdk/contracts/storage/namespace.rs` and
    /// `docs/architecture/storage_capability_surface.md`.
    pub const STORAGE_NAMESPACE: u16 = 0x0013;
    /// Whole-blob byte-addressed storage surface — opcode class 0x14xx.
    /// See `modules/sdk/contracts/storage/object.rs` and
    /// `docs/architecture/storage_capability_surface.md`.
    pub const STORAGE_OBJECT: u16 = 0x0014;

    /// USB host controller binding — opcode class 0x15xx.
    ///
    /// **Status: allocated, unserved.** The id and the per-side drift
    /// guards exist so a USB-host foundation module can declare
    /// `requires_contract = "usb_host"` and be admitted. No platform
    /// registers a vtable for it, so `provider_open(USB_HOST, …)`
    /// answers `-ENOSYS` on every target: a module may hold the
    /// declaration, and gets nothing back until a host-controller
    /// driver serves it.
    pub const USB_HOST: u16 = 0x0015;

    // 0x0016 reserved (host process executor — host-scoped class; semantic
    // constant lives at `abi::platform::linux::host_process::PROC_CLASS`, its
    // fd tag routes via `register_fd_tag_route`).

    // 0x0017 unused (reserved — do not reassign): a versioned watchable KV is
    // distributed-state logic, not a fluxor primitive; it lives in lattice, and
    // nanocloud consumes it there.

    // 0x0018 and 0x0019 unused (reserved — do not reassign): host isolation is
    // expressed through WORKLOAD (0x1A). The host-process namespace/cgroup mechanism is
    // WORKLOAD's Linux host-process backend (`hp_spawn` in
    // `src/platform/linux/host_backend.rs`).

    /// Generic stream-clock capability — opcode class 0x1Cxx. Answers the
    /// `STREAM_TIME` (0x0C30) syscall's audio-clock query independently of any
    /// PIO hardware: hosts (linux/wasm) register a dedicated clock provider
    /// here instead of impersonating a PIO provider. On bare-metal RP the clock
    /// is a property of the active PIO stream, so no STREAM_CLOCK provider is
    /// registered and the syscall falls back to HAL_PIO's per-stream time.
    pub const STREAM_CLOCK: u16 = 0x001C;

    /// The platform's verdict on a certificate chain — opcode class 0x1Dxx.
    /// A VERIFY contract rather than an anchor-reading one: the provider
    /// applies the platform's policy and answers yes-or-no plus what it
    /// actually checked, so no anchor DER crosses a syscall and a consumer's
    /// claim about provenance is one it was told. Registered by the linux
    /// host platform; `bcm2712`, `rp` and `wasm` register nothing here, and a
    /// graph asking for `trust = "system"` on those refuses at build.
    /// Semantic constants live at `abi::contracts::trust`.
    pub const TRUST: u16 = 0x001D;

    /// Packet policy and service NAT enforced by the platform — opcode class
    /// 0x1Exx. Named tables of neutral rules (allow/drop/isolate/dnat) that
    /// the linux platform realizes as nftables, bare metal as the in-graph
    /// packet filter's table, and wasm records without enforcing — the
    /// provider's CAPS say which. Semantic constants live at
    /// `abi::contracts::net::policy`.
    pub const NET_POLICY: u16 = 0x001E;

    /// Platform-neutral isolated-workload surface — opcode class 0x1Axx. One
    /// contract for "run an isolated workload with a declared capability
    /// envelope," realized by two placement-resolved backends: an fmod-graph
    /// backend (MPU/EL0 + owner/lease, bare metal) and a host-process backend
    /// (namespaces/cgroups/veth, Linux). The consumer never names a platform.
    /// Gated by `requires_contract = "workload"` AND `platform_raw`; handles are
    /// `FD_TAG_WORKLOAD`-tagged.
    pub const WORKLOAD: u16 = 0x001A;
    /// Linux host-process mechanics (exec/PTY/read/bundles) — the host-scoped
    /// class beside the stable 0x1A workload surface. Registered
    /// only by the linux host platform; semantic constants live at
    /// `abi::platform::linux::host_process`.
    pub const HOST_PROCESS: u16 = 0x001B;
    /// Linux host mounts of block devices under the operator's mount root —
    /// a host-scoped class, registered only by the linux host platform;
    /// semantic constants live at `abi::platform::linux::host_mount`.
    pub const HOST_MOUNT: u16 = 0x001F;

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

/// Maximum number of contracts. A contract id is simultaneously the
/// vtable index here, the opcode's class byte, and a bit position in the
/// fmod header's `required_caps` (`ModuleHeader::required_caps`, u64), so
/// this ceiling and that field's width are one number and must move
/// together.
pub const MAX_CONTRACTS: usize = 64;

/// Registered vtables, indexed by contract id.
static mut VTABLES: [Option<&'static ProviderVTable>; MAX_CONTRACTS] =
    [const { None }; MAX_CONTRACTS];

/// Register a contract vtable at kernel init. Overwrites any previous
/// registration for the same contract id. Panics if the contract id is
/// out of range.
pub fn register_vtable(vt: &'static ProviderVTable) {
    let idx = vt.contract as usize;
    assert!(idx < MAX_CONTRACTS, "contract id out of range");
    // SAFETY: vtable registration is single-threaded boot-time work; no
    // concurrent reader observes VTABLES at this point. `idx` bounded
    // by the assert.
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
    // SAFETY: VTABLES is set during boot; read-only after that. `idx`
    // bounded above.
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
    /// Owner that opened the handle. Present only on multi-tenant builds —
    /// bare metal carries no per-handle ownership state.
    #[cfg(feature = "multitenant")]
    owner: crate::kernel::workload::owner::OwnerHandle,
}

static mut HANDLE_BINDINGS: [HandleBinding; MAX_TRACKED] = [const {
    HandleBinding {
        handle: -1,
        contract: 0,
        #[cfg(feature = "multitenant")]
        owner: crate::kernel::workload::owner::OWNER_SYSTEM,
    }
}; MAX_TRACKED];

/// Result of `track_handle`. `Ok(())` = a tracking slot was claimed (or none
/// was needed because the handle is self-identifying via FD tag).
/// `Err(())` = the tracking table was full; the caller must release the
/// underlying handle and propagate an error to the module.
fn track_handle(handle: i32, contract: ContractId) -> Result<(), ()> {
    if handle < 0 {
        return Ok(());
    }
    // Tagged fds (event / timer / dma) are self-identifying — the FD
    // tag carries the contract id, so `lookup_contract` resolves them
    // without a tracking table entry. Skip tracking to keep the table
    // available for untagged handles (GPIO pins, DMA channel numbers,
    // HAL handles) that genuinely need an entry.
    if fd_tag_contract(handle).is_some() {
        return Ok(());
    }
    // SAFETY: HANDLE_BINDINGS is scheduler-thread-owned; track_handle
    // is called from provider_open which serialises on the kernel side.
    unsafe {
        let p = &raw mut HANDLE_BINDINGS;
        for slot in (*p).iter_mut() {
            if slot.handle == -1 {
                slot.handle = handle;
                slot.contract = contract;
                // Stamp the opening module's owner so later use is owner-scoped.
                #[cfg(feature = "multitenant")]
                {
                    slot.owner = crate::kernel::exec::scheduler::caller_owner();
                }
                return Ok(());
            }
        }
        log::error!(
            "[provider] HANDLE_BINDINGS exhausted (MAX_TRACKED={MAX_TRACKED}); refusing to leak \
             untracked handle {handle} for contract {contract:#x}",
        );
        Err(())
    }
}

/// Owner-scoping guard for tracked provider handles. Returns `true` — deny —
/// when the calling module's owner may not use `handle` because it was opened
/// by a different, non-system owner. Self-identifying FDs (event/timer/dma)
/// are skipped: they carry no tracking entry and the event/timer subsystems
/// enforce their own per-module ownership. Compile-time `false` (allow) on
/// single-tenant builds, and inert on multi-tenant builds until the node agent
/// stamps per-workload owners (every module is the system owner until then).
#[cfg(feature = "multitenant")]
fn deny_cross_owner_handle(handle: i32, syscall: &str) -> bool {
    if handle < 0 || fd_tag_contract(handle).is_some() {
        return false;
    }
    // SAFETY: HANDLE_BINDINGS is scheduler-thread-owned (see `track_handle`).
    let bound_owner = unsafe {
        let p = &raw const HANDLE_BINDINGS;
        (*p).iter().find(|s| s.handle == handle).map(|s| s.owner)
    };
    // Untracked handle → no entry to scope (raw HAL handle, etc.); allow.
    let Some(bound_owner) = bound_owner else {
        return false;
    };
    let caller = crate::kernel::exec::scheduler::caller_owner();
    if crate::kernel::workload::owner::same_or_system(caller, bound_owner) {
        false
    } else {
        log::warn!(
            "[provider] {syscall}: owner slot {} denied cross-owner handle {handle} \
             (opened by owner slot {})",
            caller.slot,
            bound_owner.slot,
        );
        true
    }
}

/// Single-tenant: no ownership to enforce.
#[cfg(not(feature = "multitenant"))]
#[inline(always)]
fn deny_cross_owner_handle(_handle: i32, _syscall: &str) -> bool {
    false
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
    use crate::kernel::ipc::fd;
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
        _t if _t == fd::FD_TAG_STORAGE_NAMESPACE => Some(contract::STORAGE_NAMESPACE),
        _t if _t == fd::FD_TAG_STORAGE_OBJECT => Some(contract::STORAGE_OBJECT),
        _t if _t == fd::FD_TAG_HAL_PIO => Some(contract::HAL_PIO),
        _t if _t == fd::FD_TAG_WORKLOAD => Some(contract::WORKLOAD),
        // USB host: allocated but unserved (see `contract::USB_HOST`), so
        // `provider_open(USB_HOST, ...)` returns no tagged handle; the tag
        // resolves here so a registered vtable would be reachable unchanged.
        _t if _t == fd::FD_TAG_USB_HOST => Some(contract::USB_HOST),
        // Platform-registered routes (host-scoped tags the generic kernel
        // does not know by name — see `register_fd_tag_route`).
        t => dyn_tag_route(t),
    }
}

fn lookup_contract(handle: i32) -> Option<ContractId> {
    if handle < 0 {
        return None;
    }
    if let Some(c) = fd_tag_contract(handle) {
        return Some(c);
    }
    // SAFETY: HANDLE_BINDINGS read-only path; the producer side is
    // serialised on the scheduler thread.
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
    // SAFETY: scheduler-thread-only mutation.
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

// ── Handle-scoped dispatch ───────────────────────────────────────────

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
        c if c == contract::WORKLOAD => Some(fd::FD_TAG_WORKLOAD),
        c if c == contract::STORAGE_NAMESPACE => Some(fd::FD_TAG_STORAGE_NAMESPACE),
        c if c == contract::STORAGE_OBJECT => Some(fd::FD_TAG_STORAGE_OBJECT),
        c if c == contract::USB_HOST => Some(fd::FD_TAG_USB_HOST),
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
    // ISR-tier modules must not touch the provider table.
    // Bridge channels are the only legal cross-tier conduit.
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_open") {
        return errno::EACCES;
    }
    // Admission gate: opening a provider handle admits new work, which is
    // refused for a Draining owner. Handles it already holds keep working (`authorize_use`
    // semantics) so in-flight work can run dry. System-owned modules are
    // unaffected.
    #[cfg(feature = "multitenant")]
    {
        let owner = crate::kernel::exec::scheduler::caller_owner();
        if !owner.is_system()
            && !crate::kernel::exec::scheduler::owners_mut().authorize_admit(owner)
        {
            log::warn!(
                "[provider] open refused: owner slot {} draining/revoked",
                owner.slot
            );
            return errno::EACCES;
        }
    }
    let handle = match vtable_for(contract) {
        // SAFETY: vt.call is the contract's registered fn-pointer; passing
        // -1 (no handle yet) with the open opcode and caller's config buf.
        Some(vt) => unsafe { (vt.call)(-1, open_op, config as *mut u8, config_len) },
        None => {
            // No vtable — fall back to the contract's registered
            // chain dispatcher directly.
            // SAFETY: as above; `dispatch` enforces its own bounds checks.
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
                    "[provider] contract {contract:#x} open returned handle with tag={actual} (expected {expected}); refusing",
                );
                errno::ENOSYS
            }
        }
        None => {
            // Untagged contract (CHANNEL): class-byte dispatch looks
            // the handle up via HANDLE_BINDINGS. If tracking fails
            // (table full), close the resource we just opened and
            // refuse the open — fail-closed; never return an
            // untracked handle.
            match track_handle(handle, contract) {
                Ok(()) => handle,
                Err(()) => {
                    // Release the underlying resource. Use the same
                    // dispatch path provider_close uses so contracts
                    // without a vtable still get the default-close op
                    // delivered.
                    if let Some(vt) = vtable_for(contract) {
                        if vt.default_close_op != 0 {
                            // SAFETY: vt.call is the registered fn-pointer;
                            // null arg, zero len is the close convention.
                            unsafe {
                                (vt.call)(handle, vt.default_close_op, core::ptr::null_mut(), 0);
                            }
                        }
                    }
                    // Use ENOMEM: tracking table is a finite kernel
                    // resource and the caller exhausted it. Same class
                    // as STATE_ARENA exhaustion in the loader.
                    errno::ENOMEM
                }
            }
        }
    }
}

/// Invoke an operation on an open handle.
///
/// Routing resolution order:
///   0. Kernel primitives (opcode class `INTERNAL_DISPATCH_BUCKET`): a
///      question about a handle rather than a request to its provider, so
///      the opcode decides ahead of the handle.
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
    // Defense in depth: ISR-tier (Tier 1b/2) modules must not reach
    // `provider_call` — the contract is "bridge-only I/O, no syscalls".
    // The build-time validator already gates admission; this catches
    // hand-rolled binaries that bypass the tools pipeline. EXCEPTION: the
    // bridge ops and `SELF_BRIDGES` enumeration ARE the sanctioned
    // ISR-tier I/O path (lock-free, allocation-free rings), so they are
    // exempt from the deny here too — matching the exemption in
    // `syscall_provider_call`.
    if !crate::abi::internal::bridge::is_isr_safe(op)
        && crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_call")
    {
        return errno::EACCES;
    }
    if deny_cross_owner_handle(handle, "provider_call") {
        return errno::EACCES;
    }
    let class = ((op >> 8) & 0xFF) as u16;
    // A kernel primitive (the 0x0Cxx class — HANDLE_POLL above all) is a
    // question about a handle, not a request to its provider: `fd_poll` on a
    // timer or event fd asks the KERNEL whether the fd is ready, and the
    // handle's own provider has no opinion to offer. So the primitive is
    // routed by its opcode class ahead of the handle's contract; a contract's
    // vtable sees only the opcodes it defines.
    if class == contract::INTERNAL_DISPATCH_BUCKET {
        // SAFETY: dispatch routes to the kernel-internal bucket handler.
        return unsafe { dispatch(class, handle, op, arg, arg_len) };
    }
    // A handle minted through a selector belongs to the provider that minted
    // it, not to whichever layer is the default now.
    match route_lookup(handle) {
        // SAFETY: caller owns `arg`/`arg_len` for the call.
        RouteLookup::Live(idx) => return unsafe { call_route(idx, op, arg, arg_len) },
        RouteLookup::Stale => return EBADF,
        RouteLookup::NotRouted => {}
    }
    if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            // SAFETY: vt.call is the contract's registered ABI entry;
            // caller owns `arg`/`arg_len` for the call.
            return unsafe { (vt.call)(handle, op, arg, arg_len) };
        }
        // SAFETY: dispatch routes to the chain-registered handler.
        return unsafe { dispatch(contract, handle, op, arg, arg_len) };
    }
    // SAFETY: as above; class-byte dispatch fallback.
    unsafe { dispatch(class, handle, op, arg, arg_len) }
}

/// Query handle state by key.
pub fn provider_query(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_query") {
        return errno::EACCES;
    }
    if deny_cross_owner_handle(handle, "provider_query") {
        return errno::EACCES;
    }
    if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            return match vt.query {
                // SAFETY: vt.query is the registered fn-pointer.
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
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_close") {
        return errno::EACCES;
    }
    if deny_cross_owner_handle(handle, "provider_close") {
        return errno::EACCES;
    }
    match route_lookup(handle) {
        RouteLookup::Live(idx) => {
            let r = route_at(idx);
            let close = vtable_for(r.contract).map_or(0, |v| v.default_close_op);
            if close == 0 {
                retire_route(idx, r.generation);
                return 0;
            }
            // SAFETY: close convention: null arg, zero length.
            return unsafe { call_route(idx, close, core::ptr::null_mut(), 0) };
        }
        RouteLookup::Stale => return EBADF,
        RouteLookup::NotRouted => {}
    }
    let result = if let Some(contract) = lookup_contract(handle) {
        if let Some(vt) = vtable_for(contract) {
            if vt.default_close_op != 0 {
                // SAFETY: vt.call is the registered fn-pointer.
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
    // SAFETY: called from scheduler::reset between graph rebuilds; no
    // module observes HANDLE_BINDINGS at this point.
    unsafe {
        let p = &raw mut HANDLE_BINDINGS;
        for slot in (*p).iter_mut() {
            slot.handle = -1;
            slot.contract = 0;
        }
        let p = &raw mut ROUTES;
        let routes = &mut *p;
        for r in routes.iter_mut() {
            r.in_use = false;
            r.inner = -1;
        }
    }
}

/// Snapshot of provider tracking-table usage. Used by diagnostics and
/// harness tests that need to assert tracking-table state without
/// reading the private `HANDLE_BINDINGS` static directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleTrackingStats {
    /// Slots currently bound to an open handle.
    pub in_use: usize,
    /// Total slots in the tracking table.
    pub capacity: usize,
}

/// Return current usage of the provider handle tracking table.
/// Cheap: walks `MAX_TRACKED` entries once with relaxed ordering.
pub fn handle_tracking_stats() -> HandleTrackingStats {
    let mut in_use = 0usize;
    // SAFETY: read-only walk of HANDLE_BINDINGS; producer side runs on
    // the scheduler thread.
    unsafe {
        let p = &raw const HANDLE_BINDINGS;
        for slot in (*p).iter() {
            if slot.handle != -1 {
                in_use += 1;
            }
        }
    }
    HandleTrackingStats {
        in_use,
        capacity: MAX_TRACKED,
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

/// Maximum registered contracts (indexed by `ContractId`). The provider
/// chain table and the vtable registry index the same id space, so this is
/// `MAX_CONTRACTS`, not an independent ceiling: a contract registerable in
/// one and not the other would panic at boot on the narrower table.
const MAX_PROVIDERS: usize = MAX_CONTRACTS;

/// Layers registerable per contract: one default (unkeyed) provider plus the
/// instance-keyed backends beneath it. A multi-volume storage graph spends one
/// layer on the `mount` policy module and one per distinct volume, so
/// `MAX_CHAIN_DEPTH - 1` is the hard ceiling on volumes a single graph can
/// carry. `mount`'s `MAX_MOUNTS` bounds mount *prefixes*, which may share a
/// volume, so it is allowed to exceed that.
///
/// Sized per target: a chain entry is 24 bytes and the table is
/// `MAX_PROVIDERS × MAX_CHAIN_DEPTH`, so depth 8 costs ~12 KiB where depth 3
/// costs ~4.6 KiB. An application processor can host a multi-drive carrier and
/// has the RAM for it; the MCUs cannot and don't (rp2040 shares ~264 KiB with
/// the USB and network stacks), so they keep the smaller table.
#[cfg(feature = "chip-rp2040")]
pub const MAX_CHAIN_DEPTH: usize = 3;
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
pub const MAX_CHAIN_DEPTH: usize = 4; // rp2350
#[cfg(not(feature = "rp"))]
pub const MAX_CHAIN_DEPTH: usize = 8; // bcm2712 / host

/// Flag ORed onto opcode to dispatch to the next provider below the caller.
pub const CHAIN_NEXT: u32 = 0x0001_0000;

/// A single layer in a provider chain.
struct ProviderLayer {
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
    /// Instance selector (FNV-1a hash of a short volume/instance string,
    /// shared with modules via `abi::provider_selector::hash`). `0` =
    /// unkeyed / default provider — the target of the class-byte
    /// (`handle == -1`) dispatch path. A non-zero selector is reachable only
    /// via `provider_call_sel`, letting multiple volumes of one contract (two
    /// `fat32`, NVMe + SD) coexist without shadowing.
    selector: u32,
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

/// Provider table — indexed by contract id (0x00..MAX_CONTRACTS).
static mut PROVIDERS: [ProviderEntry; MAX_PROVIDERS] =
    [const { ProviderEntry::empty() }; MAX_PROVIDERS];

/// Register a kernel-internal provider for a contract. Called at
/// kernel startup.
///
/// Panics if `contract as usize >= MAX_PROVIDERS`.
pub fn register(contract: ContractId, dispatch: ProviderDispatch) {
    let idx = contract as usize;
    assert!(idx < MAX_PROVIDERS, "contract id out of range");
    // SAFETY: register runs once per contract during boot; no concurrent
    // reader observes PROVIDERS[idx].kernel_dispatch.
    unsafe {
        PROVIDERS[idx].kernel_dispatch = Some(dispatch);
    }
}

/// Contracts a PIC module is allowed to provide. The loader calls
/// `register_module_provider` after resolving a module's
/// `module_provides_contract` (or `module_provides_contracts`) export — a
/// compromised or mis-built module could in principle name any contract.
/// Only the contracts where it is architecturally legitimate for a module to
/// be the provider are admitted: the HAL peripherals, FS, and the
/// `storage.namespace` / `storage.object` surfaces. CHANNEL / TIMER / BUFFER /
/// EVENT / KEY_VAULT and the internal dispatch bucket are kernel-only and
/// must not be replaceable by a module.
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
            | contract::STORAGE_NAMESPACE
            | contract::STORAGE_OBJECT
    )
}

/// Register a PIC module as provider for a contract.
///
/// Pushes the module onto the top of the chain. Returns 0 on success;
/// EINVAL if `contract` is out of range or the dispatch pointer is outside
/// the module's code region; EACCES if `contract` is not module-providable or
/// `selector` is the reserved `platform` name; EBUSY if the module already
/// holds a layer of this contract, the selector is already taken, or the
/// chain is full.
pub fn register_module_provider(
    contract: ContractId,
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
    selector: u32,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::EINVAL;
    }
    if !is_module_providable(contract) {
        log::error!(
            "[provider] module {module_idx} tried to register for non-providable contract 0x{contract:04x}",
        );
        return errno::EACCES;
    }
    // The platform's name is not a module's to take: a layer carrying it
    // would make `provider_call_sel("platform", …)` reach the module, and the
    // one path that names the platform beneath a graph would stop doing so.
    if selector == PLATFORM_SELECTOR {
        log::error!(
            "[provider] module {module_idx} registers the reserved selector `platform` for \
             contract 0x{contract:04x}; that name reaches the platform's own provider"
        );
        return errno::EACCES;
    }

    // Validate dispatch function pointer is within the registering module's
    // code region. Prevents a corrupted module from registering a pointer
    // into kernel memory or another module's code.
    let fn_addr = dispatch as usize;
    let (code_base, code_size) =
        crate::kernel::exec::scheduler::module_code_region(module_idx as usize);
    if code_base != 0 && code_size != 0 {
        let code_end = code_base + code_size as usize;
        if fn_addr < code_base || fn_addr >= code_end {
            log::error!(
                "[provider] module {module_idx} fn_ptr 0x{fn_addr:08x} outside code region 0x{code_base:08x}..0x{code_end:08x}"
            );
            return errno::EINVAL;
        }
        // On Cortex-M (Thumb mode): verify LSB is set
        #[cfg(target_arch = "arm")]
        if fn_addr & 1 == 0 {
            log::error!("[provider] module {module_idx} fn_ptr 0x{fn_addr:08x} missing Thumb bit");
            return errno::EINVAL;
        }
    }

    // SAFETY: `idx < MAX_PROVIDERS` (bounds-checked above); registration
    // runs on the scheduler thread.
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
            log::error!(
                "[provider] module {module_idx}: contract 0x{contract:04x} already has {MAX_CHAIN_DEPTH} layers (the per-target `MAX_CHAIN_DEPTH`); one is the default provider and the rest are instance-keyed backends, so this graph names more volumes than this target can register"
            );
            return errno::EBUSY;
        }

        // Reject a duplicate selector, keyed or not — either shadows silently.
        // A second unkeyed (selector 0) provider is unreachable because
        // `default_layer_index` takes the top-most selector-0 layer; a
        // duplicate keyed one is unreachable because `provider_call_sel`
        // returns the first match. Selectors are a hash of a short name, so
        // this also catches a genuine hash collision between two distinct
        // volume names, which no amount of config validation could see. The
        // config validator (`validate_single_provider`) blocks the graph
        // earlier; this is the kernel-side backstop.
        for i in 0..entry.depth as usize {
            if let Some(ref layer) = entry.chain[i] {
                if layer.selector == selector {
                    let which = if selector == 0 {
                        "a second unkeyed provider"
                    } else {
                        "a duplicate instance selector"
                    };
                    log::error!(
                        "[provider] module {module_idx} registers {which} (0x{selector:08x}) for contract 0x{contract:04x}; it would shadow module {} — give each backend a distinct `volume:`",
                        layer.module_idx
                    );
                    return errno::EBUSY;
                }
            }
        }

        // Push onto top of chain
        let d = entry.depth as usize;
        entry.chain[d] = Some(ProviderLayer {
            module_idx,
            dispatch,
            state,
            selector,
        });
        entry.depth += 1;
        log::info!(
            "[provider] module {} registered for contract 0x{:04x} at depth {} (selector 0x{:08x})",
            module_idx,
            contract,
            entry.depth,
            selector
        );
    }
    0
}

/// Release all module providers owned by a given module index.
/// Called on module finish (Done/Error) for cleanup.
/// Compacts chains to maintain stack ordering.
pub fn release_module_providers(module_idx: u8) {
    // A freed slot must not stay subscribed: the slot is reused, and the next
    // module to land in it would inherit a subscription it never asked for.
    clear_owner_release_observer(module_idx);
    // Before the chain is compacted, so the departing module's own routed
    // handles are closed at owners that are still registered.
    release_routes_of(module_idx);
    // SAFETY: called from scheduler module-finish path; scheduler thread.
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

// ============================================================================
// Owner-release notification
// ============================================================================
//
// A provider that holds resources on a consumer's behalf — scratch objects,
// open files, staged writes — needs to know when that consumer's owner goes
// away, or it holds them until the next reset. The kernel is the only party
// that knows, so it has to say so.
//
// Two platform calls (`linux_net_close_owner_conns`,
// `linux_workload_close_owner`) cover the kernel's OWN per-owner state on the
// drain path. This is the module-provider counterpart, delivered from
// `free_owner` itself rather than from the drain driver, so the paths that
// never reach the drain driver — the workload verbs (KILL, DESTROY) and
// admission rollback — are covered too.
//
// Ordering is the whole point: the notification runs BEFORE any teardown, so
// the owner handle still resolves, the provider module's state is still live,
// and a handler may make syscalls exactly as it would in a normal frame. A
// notification after `free_owner` would reach a provider that cannot validate
// the owner it was handed (the generation has moved) and that may itself have
// been torn down.

/// Providers that asked to hear about owner teardown, by module index.
/// Opt-in: set by the loader when a provider module exports
/// `module_observes_owner_release`. Never notified otherwise, because
/// calling every registered provider with an opcode it does not know would
/// reach modules whose dispatch does not bounds-check its input.
static mut OWNER_RELEASE_OBSERVERS: crate::kernel::workload::bitmask::ModuleMask =
    crate::kernel::workload::bitmask::ModuleMask::EMPTY;

/// Mark `module_idx` as an owner-release observer. Called by the loader after
/// the module's provider registration succeeds; a module that is not a
/// registered provider has no dispatch to notify, so it is refused.
pub fn register_owner_release_observer(module_idx: u8) -> i32 {
    let idx = module_idx as usize;
    if idx >= crate::kernel::boot::config::MAX_MODULES {
        return errno::EINVAL;
    }
    if !module_has_provider_layer(module_idx) {
        log::warn!(
            "[provider] module {module_idx} exports module_observes_owner_release but \
             provides no contract; nothing to notify"
        );
        return errno::EINVAL;
    }
    // SAFETY: scheduler-thread-only, same access class as the provider table.
    unsafe {
        let p = &raw mut OWNER_RELEASE_OBSERVERS;
        (*p).set(idx);
    }
    0
}

/// Drop `module_idx` from the observer set. Called alongside
/// `release_module_providers` so a freed slot cannot be notified, and a later
/// module reusing the slot does not inherit the subscription.
pub fn clear_owner_release_observer(module_idx: u8) {
    let idx = module_idx as usize;
    if idx >= crate::kernel::boot::config::MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only.
    unsafe {
        let p = &raw mut OWNER_RELEASE_OBSERVERS;
        (*p).clear(idx);
    }
}

/// Whether `module_idx` holds at least one registered provider layer.
fn module_has_provider_layer(module_idx: u8) -> bool {
    module_dispatch_entry(module_idx).is_some()
}

/// Encode an owner handle as the 8-byte record `OWNER_RELEASED` carries.
///
/// The same encoder answers `query_key::CALLER_OWNER`, so a provider compares
/// the owner it stamped against the one released to it without reformatting
/// either. One function rather than two matching layouts: the two are only
/// useful while they agree, and nothing but this would keep them agreeing.
pub(crate) fn encode_owner_record(owner: crate::kernel::workload::owner::OwnerHandle) -> [u8; 8] {
    let slot = owner.slot.to_le_bytes();
    let generation = owner.generation.to_le_bytes();
    [
        slot[0],
        slot[1],
        0,
        0,
        generation[0],
        generation[1],
        generation[2],
        generation[3],
    ]
}

/// Tell every subscribed provider that `owner` is about to be freed.
///
/// Called from `free_owner` before it touches anything, and from the
/// admission-rollback path. Each observer is notified once even when it
/// provides several contracts. Return values are ignored: a provider with
/// nothing to release answers `-ENOSYS`, which is not an error here.
///
/// The handler runs inline on the scheduler thread inside teardown, in a
/// provider frame, so `caller_module_index` reports whoever is tearing down
/// rather than leaving a stale frame behind.
pub fn notify_owner_released(owner: crate::kernel::workload::owner::OwnerHandle) {
    // SAFETY: scheduler-thread read of the observer set.
    let observers = unsafe {
        let p = &raw const OWNER_RELEASE_OBSERVERS;
        *p
    };
    if observers.is_empty() {
        return;
    }

    // Resolve which modules to call BEFORE calling any of them. A handler runs
    // arbitrary module code and may reach `provider_open`/`provider_close`, or
    // finish a module and compact the chain through
    // `release_module_providers` — so no borrow of `PROVIDERS` may span a
    // dispatch. Collecting into a mask also makes the dedup free: a module
    // serving several contracts is one subscriber, not one per contract.
    let mut targets = crate::kernel::workload::bitmask::ModuleMask::EMPTY;
    // SAFETY: scheduler-thread read; no module code runs inside this loop.
    unsafe {
        let p = &raw const PROVIDERS;
        for entry in (*p).iter() {
            for i in 0..entry.depth as usize {
                if let Some(ref layer) = entry.chain[i] {
                    let midx = layer.module_idx as usize;
                    if midx < crate::kernel::boot::config::MAX_MODULES && observers.test(midx) {
                        targets.set(midx);
                    }
                }
            }
        }
    }

    for midx in 0..crate::kernel::boot::config::MAX_MODULES {
        if !targets.test(midx) {
            continue;
        }
        // Re-resolve per module, in a borrow that ends before the call. If an
        // earlier handler tore this one's layer out, it is simply skipped —
        // there is nothing left to notify.
        let Some((dispatch, state)) = module_dispatch_entry(midx as u8) else {
            continue;
        };
        // A fresh record per handler: one provider scribbling on the buffer
        // must not change what the next one is told.
        let mut record = encode_owner_record(owner);
        in_provider_frame(midx, || {
            // SAFETY: `dispatch` and `state` are the pair the module
            // registered; `record` is a live 8-byte buffer owned by this frame.
            unsafe {
                dispatch(
                    state,
                    -1,
                    crate::abi::internal::reconfigure::OWNER_RELEASED,
                    record.as_mut_ptr(),
                    crate::abi::internal::reconfigure::OWNER_RELEASED_ARG_LEN,
                )
            }
        });
    }
}

/// The first registered `(dispatch, state)` pair for `module_idx`, or `None`
/// when it holds no provider layer. The borrow of `PROVIDERS` ends with the
/// call, so the caller may safely run module code with the result.
fn module_dispatch_entry(module_idx: u8) -> Option<(ModuleProviderDispatchFn, *mut u8)> {
    // SAFETY: scheduler-thread read; nothing here calls into module code.
    unsafe {
        let p = &raw const PROVIDERS;
        for entry in (*p).iter() {
            for i in 0..entry.depth as usize {
                if let Some(ref layer) = entry.chain[i] {
                    if layer.module_idx == module_idx {
                        return Some((layer.dispatch, layer.state));
                    }
                }
            }
        }
    }
    None
}

/// Run a provider's dispatch with `module_idx` as the current module and the
/// previous one published as the caller.
///
/// Both halves are restored on the way out, so nesting is exact: a provider
/// that calls another provider is that one's caller, and the original
/// requester is restored when the inner frame returns. This is the whole of
/// the caller-identity mechanism — `provider_call` deliberately carries no
/// owner argument, because widening it is a positional-ABI flag day across
/// every module in the fleet for a fact the kernel already holds.
#[inline]
pub(crate) fn in_provider_frame<R>(module_idx: usize, f: impl FnOnce() -> R) -> R {
    use crate::kernel::exec::scheduler;
    let saved_current = scheduler::current_module_index();
    let saved_caller = scheduler::caller_module_index();
    scheduler::set_caller_module(saved_current);
    scheduler::set_current_module(module_idx);
    let result = f();
    scheduler::set_current_module(saved_current);
    scheduler::set_caller_module(saved_caller);
    result
}

/// Dispatch an operation to the registered provider for `contract`.
///
/// The top-most unkeyed module layer takes priority; the kernel provider
/// answers when none is registered. Returns ENOSYS if no provider is
/// registered for this contract.
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
    // SAFETY: `idx < MAX_PROVIDERS` bounded; the registered dispatch chain
    // is set up on the scheduler thread before any module observes it.
    unsafe {
        let entry = &PROVIDERS[idx];

        // Dispatch to the default (unkeyed) module provider if one is
        // registered: the top-most selector-0 layer — identical to
        // `chain[depth-1]` when every provider is unkeyed, and the `mount`
        // policy module when keyed volume backends coexist with it. Keyed
        // backends are reached only via `dispatch_to`.
        if let Some(top) = default_layer_index(entry) {
            if let Some(ref layer) = entry.chain[top] {
                let result = in_provider_frame(layer.module_idx as usize, || {
                    (layer.dispatch)(layer.state, handle, opcode, arg, arg_len)
                });
                return result;
            }
        }

        // Keyed backends exist but nothing serves the class-byte path. Name the
        // shape explicitly: the generic "no provider" line below would send the
        // reader looking for a missing module when the real fault is a missing
        // router.
        if entry.depth > 0 && entry.kernel_dispatch.is_none() {
            log::error!(
                "[provider] contract 0x{contract:04x} op 0x{opcode:04x}: {} instance-keyed provider(s) registered but no default (unkeyed) one — a `handle == -1` op has no router. Add a policy module (e.g. `mount`) that registers unkeyed and routes to the keyed backends.",
                entry.depth
            );
            return errno::ENOSYS;
        }

        // Fall back to kernel provider
        match entry.kernel_dispatch {
            Some(handler) => {
                let rc = handler(handle, opcode, arg, arg_len);
                if rc == errno::ENOSYS {
                    log::debug!(
                        "[provider] contract 0x{contract:04x} op 0x{opcode:04x}: kernel handler returned ENOSYS"
                    );
                }
                rc
            }
            None => {
                log::warn!("[provider] contract 0x{contract:04x} op 0x{opcode:04x}: no provider");
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
    // SAFETY: `idx < MAX_PROVIDERS` bounded; PROVIDERS chain is mutated
    // only on the scheduler thread, callers run cooperatively.
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
            let result = in_provider_frame(layer.module_idx as usize, || {
                (layer.dispatch)(layer.state, handle, opcode, arg, arg_len)
            });
            return result;
        }

        // Gap in chain — shouldn't happen but fall back to kernel
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => errno::ENOSYS,
        }
    }
}

/// Index of the layer that serves the class-byte (`handle == -1`) dispatch
/// path for a contract: the top-most (highest-index) unkeyed (selector 0)
/// layer. Identical to `chain[depth-1]` when every provider is unkeyed.
///
/// `None` when the chain is empty OR when every layer is instance-keyed.
/// Falling back to some keyed layer would reinstate exactly the shadowing
/// this keying exists to remove: a consumer calling `provider_call(-1, …)`
/// against a multi-volume graph with no `mount` would silently reach an
/// arbitrary volume. Returning `None` sends it to the kernel provider, or to
/// `ENOSYS` — a caller that reaches an unrouted class-byte op here has a
/// wiring bug, and the diagnostic is worth more than reaching a volume that
/// is right only by luck.
fn default_layer_index(entry: &ProviderEntry) -> Option<usize> {
    for i in (0..entry.depth as usize).rev() {
        if let Some(ref layer) = entry.chain[i] {
            if layer.selector == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Call the provider of the opcode's contract selected by `sel`: an
/// instance-keyed module layer (a volume name), or — for the reserved name
/// [`PLATFORM_SELECTOR_NAME`] — the platform's own provider of that contract
/// (the host filesystem on Linux), whatever module layers sit above it. The
/// contract is the opcode's class byte, the same rule the `handle == -1` path
/// uses.
///
/// `op_handle` is `-1` for an open-style op. A handle such an op mints is
/// returned as a *routed* handle (see [`Route`]): it names the provider that
/// minted it, so every later op on it — through this call or through plain
/// `provider_call` — reaches that provider with the provider's own slot, no
/// matter which layer is the default. A non-negative `op_handle` must be such
/// a routed handle minted through the same selector for the opcode's own
/// contract; anything else is
/// `EBADF`, because a handle another provider minted means nothing here.
///
/// Resolving by selector (rather than by a cached module-index token) is what
/// keeps this sound under live graph mutation: a freed-then-reused module
/// index cannot alias a stale binding. Returns `EINVAL` on bad args, `ENODEV`
/// if nothing carries `sel`.
///
/// # Safety
/// `sel` must point to `sel_len` readable bytes; `arg` must satisfy the
/// registered dispatch handler's requirements for `opcode`.
pub unsafe fn provider_call_sel(
    sel: *const u8,
    sel_len: usize,
    op_handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if sel.is_null() || sel_len == 0 {
        return errno::EINVAL;
    }
    let contract = ((opcode >> 8) & 0xFF) as u16;
    if contract as usize >= MAX_PROVIDERS {
        return errno::EINVAL;
    }
    // SAFETY: caller guarantees `sel[..sel_len]` is readable.
    let bytes = unsafe { core::slice::from_raw_parts(sel, sel_len) };
    // Never 0: `hash` nudges a zero result to 1 precisely so a real name can
    // never alias the "unkeyed default" sentinel.
    let want = crate::abi::kernel_abi::provider_selector::hash(bytes);

    if op_handle >= 0 {
        return match route_lookup(op_handle) {
            RouteLookup::Live(idx) => {
                let r = route_at(idx);
                if r.selector != want || r.contract != contract {
                    log::warn!(
                        "[provider] call_sel: handle {op_handle:#x} belongs to contract \
                         0x{:04x} selector 0x{:08x}, not contract 0x{contract:04x} selector \
                         0x{want:08x}",
                        r.contract,
                        r.selector
                    );
                    return EBADF;
                }
                // SAFETY: forwarded caller contract.
                unsafe { call_route(idx, opcode, arg, arg_len) }
            }
            RouteLookup::Stale => EBADF,
            RouteLookup::NotRouted if is_module_providable(contract) => EBADF,
            // Kernel-only contracts are never routed: no module can stand in
            // front of them, so their handles already belong to the platform.
            RouteLookup::NotRouted => match target_of(contract, want) {
                // SAFETY: forwarded caller contract.
                Some(t) => unsafe { call_target(contract, t, op_handle, opcode, arg, arg_len) },
                None => errno::ENODEV,
            },
        };
    }

    let Some(target) = target_of(contract, want) else {
        return errno::ENODEV;
    };
    // SAFETY: forwarded caller contract.
    let rc = unsafe { call_target(contract, target, -1, opcode, arg, arg_len) };
    mint_route(contract, want, target, rc)
}

// ── Routed handles ───────────────────────────────────────────────────────────
//
// A handle a provider mints is a slot in THAT provider's table. Two providers
// of one contract hand out colliding slots (every fs provider starts at slot 0),
// and handle-bound ops carry no contract beyond the handle's tag, so a
// provider-local handle names its owner only as long as that owner is the one
// layer the tag resolves to — the default. A handle minted through a selector
// (a keyed volume, or the platform beneath a graph-local default) does not
// satisfy that, so the kernel mints a routed handle in its place: same contract
// tag, a slot in this table, and the table records which provider owns it and
// what the provider called it. Every later op on the routed handle, through
// either `provider_call` or `provider_call_sel`, is delivered to that owner
// with its own slot. `mount` needs exactly this for its backends and uses the
// same mechanism, so there is one owner rule for every non-default handle.

/// `EBADF`: a handle this call cannot use — minted by another provider, or
/// closed. Module-local here as in `mount`: the stable errno table has no
/// entry for it.
const EBADF: i32 = -9;

/// Selector name reserved for the platform's own provider of a contract. A
/// module may not register it (refused in `register_module_provider`, and by
/// the config validator before that).
pub const PLATFORM_SELECTOR_NAME: &[u8] = b"platform";
/// The selector [`PLATFORM_SELECTOR_NAME`] hashes to.
pub const PLATFORM_SELECTOR: u32 =
    crate::abi::kernel_abi::provider_selector::hash(PLATFORM_SELECTOR_NAME);

/// Slot bit marking a routed handle. Providers mint small slots (their table
/// indices); the kernel owns this bit of the 26-bit slot field.
const ROUTED_SLOT_BIT: i32 = 1 << 25;
/// Slot bits carrying the route index; the bits above it (below
/// [`ROUTED_SLOT_BIT`]) carry the entry's generation, so a handle kept past
/// its close does not resolve onto whatever reused the entry.
const ROUTE_IDX_BITS: u32 = 8;
const ROUTE_IDX_MASK: i32 = (1 << ROUTE_IDX_BITS) - 1;
const ROUTE_GEN_MASK: u16 = 0xFFFF;

/// Routed handles live at once. Sized per target like the chain depth: one
/// per file a sel-minted consumer holds open (`mount` holds one per open
/// file on a keyed volume).
#[cfg(feature = "chip-rp2040")]
const MAX_ROUTES: usize = 16;
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
const MAX_ROUTES: usize = 32;
#[cfg(not(feature = "rp"))]
const MAX_ROUTES: usize = 128;
const _: () = assert!(MAX_ROUTES <= 1 << ROUTE_IDX_BITS);

/// `module_idx` of a route whose owner is the platform provider.
const ROUTE_PLATFORM: u8 = u8::MAX;

/// Which provider serves a selector.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Platform,
    Module(u8),
}

/// One routed handle.
#[derive(Clone, Copy)]
struct Route {
    in_use: bool,
    contract: ContractId,
    /// Selector the handle was minted through ([`PLATFORM_SELECTOR`] for the
    /// platform).
    selector: u32,
    /// Owning layer's module index, or [`ROUTE_PLATFORM`].
    module_idx: u8,
    /// Module that was running when the handle was minted: its handles are
    /// closed when it is released.
    minter: u8,
    generation: u16,
    /// The handle as the owning provider minted it.
    inner: i32,
}

impl Route {
    const EMPTY: Self = Self {
        in_use: false,
        contract: 0,
        selector: 0,
        module_idx: 0,
        minter: 0,
        generation: 0,
        inner: -1,
    };

    fn target(&self) -> Target {
        if self.module_idx == ROUTE_PLATFORM {
            Target::Platform
        } else {
            Target::Module(self.module_idx)
        }
    }
}

static mut ROUTES: [Route; MAX_ROUTES] = [Route::EMPTY; MAX_ROUTES];

/// A copy of route `idx`, so no borrow of the table spans a call into a
/// provider.
fn route_at(idx: usize) -> Route {
    // SAFETY: scheduler-thread read; `idx < MAX_ROUTES` at every caller.
    unsafe {
        let p = &raw const ROUTES;
        (*p)[idx]
    }
}

enum RouteLookup {
    /// Not a routed handle.
    NotRouted,
    /// Carries the routed bit but names no live route: closed, or its owner
    /// is gone.
    Stale,
    Live(usize),
}

fn route_lookup(handle: i32) -> RouteLookup {
    // Only handles of contracts a module can provide are ever routed; every
    // other tag keeps its own slot space.
    let Some(contract) = fd_tag_contract(handle) else {
        return RouteLookup::NotRouted;
    };
    if !is_module_providable(contract) {
        return RouteLookup::NotRouted;
    }
    let slot = fd::slot_of(handle);
    if slot & ROUTED_SLOT_BIT == 0 {
        return RouteLookup::NotRouted;
    }
    let idx = (slot & ROUTE_IDX_MASK) as usize;
    let field = (slot & !ROUTED_SLOT_BIT) >> ROUTE_IDX_BITS;
    // Bits above the generation are never minted: a handle carrying them
    // names no route, not the route its low bits would alias.
    if idx >= MAX_ROUTES || field > i32::from(ROUTE_GEN_MASK) {
        return RouteLookup::Stale;
    }
    let generation = field as u16;
    let r = route_at(idx);
    if r.in_use && r.generation == generation && r.contract == contract {
        RouteLookup::Live(idx)
    } else {
        RouteLookup::Stale
    }
}

/// The provider `selector` names for `contract`, if any.
fn target_of(contract: ContractId, selector: u32) -> Option<Target> {
    // SAFETY: scheduler-thread read; `contract < MAX_PROVIDERS` checked by
    // every caller.
    let entry = unsafe {
        let p = &raw const PROVIDERS;
        &(*p)[contract as usize]
    };
    if selector == PLATFORM_SELECTOR {
        return entry.kernel_dispatch.map(|_| Target::Platform);
    }
    for i in 0..entry.depth as usize {
        if let Some(ref layer) = entry.chain[i] {
            if layer.selector == selector {
                return Some(Target::Module(layer.module_idx));
            }
        }
    }
    None
}

/// Deliver one op to `target`. `ENODEV` when the target has gone.
///
/// # Safety
/// `arg` must satisfy the target's requirements for `opcode`.
unsafe fn call_target(
    contract: ContractId,
    target: Target,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // SAFETY: as `target_of`.
    let entry = unsafe {
        let p = &raw const PROVIDERS;
        &(*p)[contract as usize]
    };
    match target {
        Target::Platform => match entry.kernel_dispatch {
            // SAFETY: the registered kernel handler; caller's `arg` contract.
            Some(handler) => unsafe { handler(handle, opcode, arg, arg_len) },
            None => errno::ENODEV,
        },
        Target::Module(midx) => {
            for i in 0..entry.depth as usize {
                if let Some(ref layer) = entry.chain[i] {
                    if layer.module_idx == midx {
                        return in_provider_frame(midx as usize, || {
                            // SAFETY: the pair the module registered.
                            unsafe { (layer.dispatch)(layer.state, handle, opcode, arg, arg_len) }
                        });
                    }
                }
            }
            errno::ENODEV
        }
    }
}

/// Turn the result of an open-style op sent through a selector into what the
/// caller gets back: a routed handle when `rc` is a handle of `contract`,
/// `rc` unchanged otherwise.
///
/// A result is a handle when it carries the contract's own fd tag — the
/// convention every provider follows for the handles its open-style ops
/// return (`provider_open` additionally tags a bare slot, and refuses another
/// contract's tag). Byte counts and capability words from a `handle == -1` op
/// never reach the tag bits.
fn mint_route(contract: ContractId, selector: u32, target: Target, rc: i32) -> i32 {
    if rc < 0 || !is_module_providable(contract) {
        return rc;
    }
    let Some(tag) = contract_to_tag(contract) else {
        return rc;
    };
    let (rc_tag, rc_slot) = fd::untag_fd(rc);
    if rc_tag != tag || tag == 0 {
        return rc;
    }
    // A provider handing back a routed handle it holds (it opened through a
    // selector itself) passes an owner that is already recorded.
    if rc_slot & ROUTED_SLOT_BIT != 0 {
        return rc;
    }
    let minter = {
        let m = crate::kernel::exec::scheduler::current_module_index();
        if m < ROUTE_PLATFORM as usize {
            m as u8
        } else {
            ROUTE_PLATFORM
        }
    };
    // SAFETY: scheduler-thread mutation; no module code runs in this block.
    let claimed = unsafe {
        let p = &raw mut ROUTES;
        let routes = &mut *p;
        let mut claimed = None;
        for (i, r) in routes.iter_mut().enumerate() {
            if !r.in_use {
                r.in_use = true;
                r.contract = contract;
                r.selector = selector;
                r.module_idx = match target {
                    Target::Platform => ROUTE_PLATFORM,
                    Target::Module(m) => m,
                };
                r.minter = minter;
                r.generation = r.generation.wrapping_add(1) & ROUTE_GEN_MASK;
                r.inner = rc;
                claimed = Some((i, r.generation));
                break;
            }
        }
        claimed
    };
    match claimed {
        Some((idx, generation)) => {
            let slot = ROUTED_SLOT_BIT | (i32::from(generation) << ROUTE_IDX_BITS) | idx as i32;
            fd::tag_fd(tag, slot)
        }
        None => {
            log::error!(
                "[provider] routed-handle table exhausted (MAX_ROUTES={MAX_ROUTES}); closing \
                 handle {rc:#x} of contract {contract:#x} rather than returning one no op \
                 could reach"
            );
            if let Some(close) = vtable_for(contract).map(|v| v.default_close_op) {
                if close != 0 {
                    // SAFETY: close convention: null arg, zero length.
                    unsafe {
                        call_target(
                            contract,
                            target,
                            fd::slot_of(rc),
                            close,
                            core::ptr::null_mut(),
                            0,
                        );
                    }
                }
            }
            errno::ENOMEM
        }
    }
}

/// Deliver `opcode` on live route `idx` to its owner with the owner's own
/// slot, and retire the route when the op is the contract's close.
///
/// The slot is passed untagged, as the class-byte vtables pass every handle
/// inward: providers index their tables with it.
///
/// # Safety
/// `arg` must satisfy the owner's requirements for `opcode`.
unsafe fn call_route(idx: usize, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let r = route_at(idx);
    let close = vtable_for(r.contract).map_or(0, |v| v.default_close_op);
    // SAFETY: forwarded caller contract.
    let rc = unsafe {
        call_target(
            r.contract,
            r.target(),
            fd::slot_of(r.inner),
            opcode,
            arg,
            arg_len,
        )
    };
    if close != 0 && opcode == close {
        retire_route(idx, r.generation);
    }
    rc
}

/// Free route `idx` if it still holds `generation` (the op may have run
/// module code that already retired it).
fn retire_route(idx: usize, generation: u16) {
    // SAFETY: scheduler-thread mutation.
    unsafe {
        let p = &raw mut ROUTES;
        let r = &mut (*p)[idx];
        if r.in_use && r.generation == generation {
            r.in_use = false;
            r.inner = -1;
        }
    }
}

/// Retire every route owned by, or minted by, `module_idx`. A route whose
/// owner is gone names nothing and is dropped. A route the departing module
/// minted on a provider that stays is closed there, so the provider does not
/// hold the file open for a consumer that no longer exists.
fn release_routes_of(module_idx: u8) {
    // The platform's sentinel is not a module: nothing releases it.
    if module_idx == ROUTE_PLATFORM {
        return;
    }
    let mut to_close = [(0usize, 0u16); MAX_ROUTES];
    let mut n = 0usize;
    // SAFETY: scheduler-thread mutation; no module code runs in this block.
    unsafe {
        let p = &raw mut ROUTES;
        let routes = &mut *p;
        for (i, r) in routes.iter_mut().enumerate() {
            if !r.in_use {
                continue;
            }
            if r.module_idx == module_idx {
                r.in_use = false;
                r.inner = -1;
            } else if r.minter == module_idx {
                to_close[n] = (i, r.generation);
                n += 1;
            }
        }
    }
    for &(idx, generation) in &to_close[..n] {
        let r = route_at(idx);
        if !r.in_use || r.generation != generation {
            continue;
        }
        let close = vtable_for(r.contract).map_or(0, |v| v.default_close_op);
        if close != 0 {
            // SAFETY: close convention: null arg, zero length.
            unsafe {
                call_route(idx, close, core::ptr::null_mut(), 0);
            }
        }
        retire_route(idx, generation);
    }
}

/// Routed handles currently live. Diagnostics and tests.
pub fn routed_handles_in_use() -> usize {
    // SAFETY: scheduler-thread read.
    unsafe {
        let p = &raw const ROUTES;
        (*p).iter().filter(|r| r.in_use).count()
    }
}

// ── Platform-registered fd-tag routes ────────────────────────────────────────
// Host-scoped handle tags (e.g. the linux process-executor tag) route to their
// class via registration at platform init, so the generic kernel carries no
// platform vocabulary in its routing table.

const MAX_DYN_TAG_ROUTES: usize = 4;
static mut DYN_TAG_ROUTES: [(i32, u16); MAX_DYN_TAG_ROUTES] = [(0, 0); MAX_DYN_TAG_ROUTES];

/// Register a handle-tag → contract-class route. Boot-time (single mutator on
/// core 0, before any module runs). Silently ignores overflow past
/// `MAX_DYN_TAG_ROUTES` (a platform registering that many tags is a bug caught
/// by its own tests).
pub fn register_fd_tag_route(tag: i32, class: u16) {
    // SAFETY: boot-time single-threaded registration; read-only afterwards.
    unsafe {
        let t = &mut *core::ptr::addr_of_mut!(DYN_TAG_ROUTES);
        for slot in t.iter_mut() {
            if slot.1 == 0 {
                *slot = (tag, class);
                return;
            }
        }
    }
}

fn dyn_tag_route(tag: i32) -> Option<u16> {
    // SAFETY: read-only after boot registration.
    let t = unsafe { &*core::ptr::addr_of!(DYN_TAG_ROUTES) };
    t.iter()
        .find(|(g, c)| *c != 0 && *g == tag)
        .map(|(_, c)| *c)
}
