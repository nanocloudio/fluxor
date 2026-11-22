//! Provider dispatch — registered handlers for contract operations.
//!
//! ## Routing
//!
//! A contract is the portable surface a module asks for (HAL GPIO, HAL
//! SPI, channel, timer, FS, …). Each contract has a `ProviderVTable`
//! with `call`, optional `query`, and a `default_close_op`. Consumers
//! call `provider_open(contract, open_op, arg)` to get a handle; the kernel
//! records which contract the handle belongs to, and later `provider_call` /
//! `provider_query` / `provider_close` route through that contract's vtable.
//!
//! Every call carries one handle slot, one flat `arg` record (a slice) and
//! one bulk `data` span ([`UserSpan`]), and nothing else: no provider follows
//! an address it was handed in bytes, and the kernel rewrites no argument.
//!
//! Every handle a module holds is a word the kernel minted
//! (`abi::kernel_abi::handle`): `(contract, generation, index)`. A native
//! handle (channel, event, timer, lend) names its slot in the kernel's own
//! table, and the native op resolves it. Any other handle names a route
//! ([`Route`]): which provider serves it and what that provider called it
//! (its own index, `inner`). A provider — kernel, platform or module — answers
//! an op that mints (the registry's handle use `mints`, `scoped_mints`,
//! `minted_mints`) with its own index, and the kernel wraps it in a route. A
//! handle whose generation is not its slot's names nothing (`EBADF`).
//!
//! A `handle = -1` op goes by its opcode's class byte to the contract's
//! default provider: the top-most unkeyed module layer, else the platform's.
//!
//! ## Registration
//!
//! Each contract's call path can come from:
//! - A kernel-internal function (registered at startup via `register()`).
//! - A PIC module export (registered by the loader via
//!   `register_module_provider()` after the module publishes a
//!   manifest's `provider_contracts`). Module providers form a chain
//!   (stack) per contract. Middleware modules (TLS, compression)
//!   intercept calls and forward to the layer below via `CHAIN_NEXT`.
//!
//! Each layer carries an **instance selector**: `0` for the default
//! provider, or the hash of a short name (a volume, say) for a keyed one.
//! Class-byte dispatch (`handle == -1`) reaches the top-most *unkeyed*
//! layer; a keyed layer is reached through a handle bound to it by name
//! (`kernel::BIND`). That is what lets several providers of one contract
//! coexist — two `fat32` volumes behind a `mount` router — without any of
//! them shadowing another. Selectors are unique per contract: a duplicate is
//! refused at registration, because a shadowed provider is silently
//! unreachable.
//!
//! The name `platform` is reserved: a bind to it reaches the platform's own
//! (kernel-registered) provider of the contract beneath any module layers —
//! the host filesystem under a graph-local `fat32`, say.
//!
//! An **edge contract** (`storage.block`, `net_tx_drain`) has no default and
//! no chain: it is served by the module at the other end of one of the
//! caller's ports, through a handle bound to that port. The provider is
//! handed its own port on the edge as the handle of every such op.
//!
//! A bound handle, and every handle an op through it mints, is a routed
//! handle that names its provider (see `Route`), so its ops reach that
//! provider however the default layer changes.

use crate::abi::kernel_abi::handle;
use crate::abi::registry::gate::HandleUse;
use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::mem::handles::{HandleTable, Slot};
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;

/// Stable contract identifier. The vtable registry is indexed by this id;
/// the same value appears in the opcode's high byte so class-byte routing
/// (used for `handle = -1` globals) can reach the same vtable.
pub type ContractId = u16;

pub mod contract {
    //! Contract ids, as the kernel's dispatchers name them. Every value is
    //! the ABI registry's (`abi::registry`, from `abi/registry.toml`); see
    //! the contract files under `crates/fluxor-abi/src/contracts/` for what each serves.

    /// The kernel's own contract: primitives routed by opcode class ahead of
    /// any handle. Not a provider contract: `syscall_provider_open` refuses
    /// it from module code.
    pub const INTERNAL_DISPATCH_BUCKET: u16 = crate::abi::registry::kernel::ID;
    pub const HAL_GPIO: u16 = crate::abi::registry::gpio::ID;
    pub const HAL_SPI: u16 = crate::abi::registry::spi::ID;
    pub const HAL_I2C: u16 = crate::abi::registry::i2c::ID;
    pub const HAL_PIO: u16 = crate::abi::registry::pio::ID;
    pub const HAL_UART: u16 = crate::abi::registry::uart::ID;
    pub const HAL_ADC: u16 = crate::abi::registry::adc::ID;
    pub const HAL_PWM: u16 = crate::abi::registry::pwm::ID;
    pub const CHANNEL: u16 = crate::abi::registry::channel::ID;
    pub const TIMER: u16 = crate::abi::registry::timer::ID;
    pub const EVENT: u16 = crate::abi::registry::event::ID;
    pub const FS: u16 = crate::abi::registry::fs::ID;
    pub const STORAGE_NAMESPACE: u16 = crate::abi::registry::storage_namespace::ID;
    pub const STORAGE_OBJECT: u16 = crate::abi::registry::storage_object::ID;
    pub const KEY_VAULT: u16 = crate::abi::registry::key_vault::ID;
    pub const PLATFORM_NIC_RING: u16 = crate::abi::registry::platform_nic_ring::ID;
    pub const PLATFORM_DMA: u16 = crate::abi::registry::platform_dma::ID;
    pub const PLATFORM_DMA_FD: u16 = crate::abi::registry::platform_dma_fd::ID;
    pub const PCIE_DEVICE: u16 = crate::abi::registry::pcie_device::ID;
    pub const STREAM_CLOCK: u16 = crate::abi::registry::stream_clock::ID;
    pub const TRUST: u16 = crate::abi::registry::trust::ID;
    pub const NET_POLICY: u16 = crate::abi::registry::net_policy::ID;
    pub const NET_ROUTE: u16 = crate::abi::registry::net_route::ID;
    pub const WORKLOAD: u16 = crate::abi::registry::workload::ID;
    pub const HOST_PROCESS: u16 = crate::abi::registry::host_process::ID;
    pub const HOST_MOUNT: u16 = crate::abi::registry::host_mount::ID;

    // Short names the kernel-side dispatchers use.
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
/// SET_INPUT, OPEN, CREATE, …). `arg` is the op's flat record: read in
/// place, and written in place where the op answers into it. `data` is the
/// op's bulk span, valid for this call.
///
/// `query` reads introspection state into `out`. `default_close_op` is the
/// opcode `provider_close` invokes to release a handle (e.g. `gpio::RELEASE`,
/// `channel::CLOSE`). Contracts whose handles don't need a close hook leave
/// it as 0, in which case `provider_close` just releases the route.
pub type VTableCallFn = fn(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32;
pub type VTableQueryFn = fn(handle: i32, key: u32, out: &mut [u8]) -> i32;
/// Readiness of one of a contract's handles (`HANDLE_POLL`): the ready bits of
/// `events`, or a negative errno. `inner` is the provider's own index; for a
/// native contract, the handle itself.
pub type VTablePollFn = fn(inner: i32, events: u32) -> i32;

/// A contract's dispatch vtable. Registered once at kernel init via
/// `register_vtable`.
pub struct ProviderVTable {
    pub contract: ContractId,
    pub call: VTableCallFn,
    pub query: Option<VTableQueryFn>,
    /// Opcode used by `provider_close` to release a handle. 0 = none.
    pub default_close_op: u32,
    /// `HANDLE_POLL` on the contract's handles; `None`: they do not poll
    /// (`EINVAL`). A signalling handle polls its doorbell instead.
    pub poll: Option<VTablePollFn>,
}

/// Maximum number of contracts. A contract id is simultaneously the
/// vtable index here, the opcode's class byte, and a bit position in a
/// module's first grant word (u64), so this ceiling and that word's width
/// are one number and must move together.
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

// ── Handles ──────────────────────────────────────────────────────────

/// Whether `contract`'s handles are native: slots in a kernel table the
/// contract's own ops resolve (`ipc::handle::resolve_owned`, the channel's
/// resolver), never routes.
pub fn is_native(contract: ContractId) -> bool {
    matches!(
        contract,
        contract::CHANNEL | contract::TIMER | contract::EVENT
    ) || contract == crate::abi::registry::lend::ID
}

/// The contract a handle names: `None` for a negative value (an errno, or
/// `-1`) and for a contract field past [`MAX_CONTRACTS`].
pub fn contract_of(h: i32) -> Option<ContractId> {
    handle::contract_of(h).filter(|&c| (c as usize) < MAX_CONTRACTS)
}

/// The rule the registry declares for `op` (`gate::op_rule`).
fn rule_of(op: u32) -> Option<crate::abi::registry::gate::OpRule> {
    crate::abi::registry::gate::op_rule(op & !CHAIN_NEXT)
}

/// Whether `op` answers a handle the kernel wraps in a route: its rule mints
/// and its contract's handles are not native.
fn op_mints(op: u32) -> bool {
    let class = ((op >> 8) & 0xFF) as ContractId;
    !is_native(class)
        && class != contract::INTERNAL_DISPATCH_BUCKET
        && rule_of(op).is_some_and(|r| {
            matches!(
                r.handle,
                HandleUse::Mints | HandleUse::ScopedMints | HandleUse::MintedMints
            )
        })
}

/// Whether the handle `op` mints signals its minter.
fn op_signals(op: u32) -> bool {
    rule_of(op).is_some_and(|r| r.signals)
}

/// Whether the calling module's owner may use route `r`: a routed handle is
/// its minting module's, so its owner's alone. Logs a refusal.
fn route_owner_ok(r: &Route, h: i32, syscall: &str) -> bool {
    // An owner table of the node owner's slot alone stamps every handle and every
    // caller `OWNER_NODE`: nothing can be another owner's. This is every
    // call on a node whose plan seats no workload, so it costs one load.
    if crate::kernel::exec::scheduler::owners().slot_count() <= 1 || r.minter == NO_MODULE {
        return true;
    }
    let caller = crate::kernel::exec::scheduler::caller_owner();
    let minted_by = crate::kernel::exec::scheduler::module_owner(r.minter as usize);
    if caller == minted_by {
        return true;
    }
    log::warn!(
        "[provider] {syscall}: owner slot {} denied handle {h:#x} (minted by owner slot {})",
        caller.slot,
        minted_by.slot,
    );
    false
}

/// Open a handle on the named contract. The caller chooses the
/// open-style opcode (e.g. `gpio::CLAIM`, `spi::OPEN`, `timer::CREATE`) —
/// `arg` is the operation's record, which the kernel holds its own copy of for
/// the call. Returns a handle (>= 0) on success, negative errno on failure.
///
/// `kernel::BIND` is answered here: it opens a handle bound to one provider
/// of `contract` (see [`bind`]).
pub fn provider_open(contract: ContractId, open_op: u32, config: &[u8]) -> i32 {
    // interrupt-mode modules must not touch the provider table.
    // Bridge channels are the only legal conduit between execution modes.
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_open") {
        return errno::EACCES;
    }
    // Admission gate: opening a provider handle admits new work, which is
    // refused for a Draining owner. Handles it already holds keep working (`authorize_use`
    // semantics) so in-flight work can run dry, and an owner being added
    // opens for its modules' `module_new` (`authorize_own_admit`).
    // Node-owned modules are unaffected.
    let owner = crate::kernel::exec::scheduler::caller_owner();
    if !owner.is_node() && !crate::kernel::exec::scheduler::owners_mut().authorize_own_admit(owner)
    {
        log::warn!(
            "[provider] open refused: owner slot {} draining/revoked",
            owner.slot
        );
        return errno::EACCES;
    }
    if open_op == crate::abi::registry::kernel::BIND {
        return bind(contract, config);
    }
    if ((open_op >> 8) & 0xFF) as ContractId != contract {
        return errno::EINVAL;
    }
    // The provider writes into an open's record as into any other: it is
    // the kernel's copy, so a caller's read-only config stays untouched.
    let mut copy = [0u8; crate::abi::registry::gate::ARG_MAX];
    let Some(arg) = copy.get_mut(..config.len()) else {
        return errno::EINVAL;
    };
    arg.copy_from_slice(config);
    call_by_class(-1, open_op, arg, UserSpan::empty())
}

/// Invoke an operation on a handle (or `handle == -1`).
///
/// Routing:
///   0. A class-routed opcode (the kernel's own class, and every contract the
///      registry routes by class) goes to the kernel ahead of the handle; a
///      handle of the op's own contract is first resolved to its route's
///      inner index.
///   1. A native contract's op goes to its vtable with the handle as is.
///   2. A handle: its route's provider, with the provider's own index.
///   3. `handle == -1`: the contract's default provider.
pub fn provider_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    // Defense in depth: interrupt-mode (`timer`/`irq`) modules must not reach
    // `provider_call` — the contract is "bridge-only I/O, no syscalls".
    // EXCEPTION: the bridge ops and `SELF_BRIDGE` are the sanctioned interrupt-mode
    // I/O path (lock-free, allocation-free rings), so they are exempt here
    // too — matching the exemption in `syscall_provider_call`.
    if !crate::abi::internal::bridge::is_isr_safe(op)
        && crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_call")
    {
        return errno::EACCES;
    }
    // The doorbell a provider is handed is the kernel's to hand: a module
    // naming one would bind its own provider to another module's wake.
    if op & !CHAIN_NEXT == crate::abi::kernel_abi::doorbell::BIND_DOORBELL {
        return errno::EACCES;
    }
    if handle >= 0 && rule_of(op).is_none_or(|r| r.handle != HandleUse::Value) {
        call_by_handle(handle, op, arg, data)
    } else {
        call_by_class(handle, op, arg, data)
    }
}

/// An op through `h`, a handle.
fn call_by_handle(h: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    let class = ((op >> 8) & 0xFF) as ContractId;
    let Some(c) = contract_of(h) else {
        return EBADF;
    };
    if crate::abi::registry::op_routes_to_kernel(op) {
        // The kernel's own ops and the native contracts' resolve the handle
        // themselves (a lend is opened on any session), and so does an op
        // naming a native handle of another contract (the event a monitor
        // subscription signals). Any other handle is translated to what its
        // provider calls it, and must be of the op's own contract.
        if is_native(class)
            || class == contract::INTERNAL_DISPATCH_BUCKET
            || (c != class && is_native(c))
        {
            return call_by_class(h, op, arg, data);
        }
        if c != class {
            return EBADF;
        }
        let (idx, generation, r) = match route_of(h) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if !route_owner_ok(&r, h, "provider_call") {
            return errno::EACCES;
        }
        return call_route(idx, generation, r, op, arg, data);
    }
    if is_native(class) {
        return match vtable_for(class) {
            Some(vt) => (vt.call)(h, op, arg, data),
            None => errno::ENOSYS,
        };
    }
    // A handle names one contract: an op of another through it names
    // nothing, before any provider sees it. The fence query is every
    // storage contract's own (`fence::QUERY_OP`), forwarded by the kernel.
    if c != class && op != crate::abi::fence::QUERY_OP {
        log::warn!("[provider] op {op:#06x} through a handle of contract {c:#06x}; refusing");
        return EBADF;
    }
    let (idx, generation, r) = match route_of(h) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !route_owner_ok(&r, h, "provider_call") {
        return errno::EACCES;
    }
    call_route(idx, generation, r, op, arg, data)
}

/// An op by its opcode's class: `handle` is `-1`, a value the op takes in
/// the handle slot, or a handle of another contract the kernel op resolves.
fn call_by_class(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    let class = ((op >> 8) & 0xFF) as ContractId;
    if crate::abi::registry::op_routes_to_kernel(op) {
        let rc = dispatch(contract::INTERNAL_DISPATCH_BUCKET, handle, op, arg, data);
        if rc >= 0 && op_mints(op) {
            return mint(Mint {
                contract: class,
                selector: 0,
                target: Target::Platform,
                inner: rc,
                bound: false,
                class_routed: true,
                signals: op_signals(op),
            });
        }
        return rc;
    }
    if is_native(class) {
        return match vtable_for(class) {
            Some(vt) => (vt.call)(handle, op, arg, data),
            None => dispatch(class, handle, op, arg, data),
        };
    }
    // An edge contract is reached through a bound handle alone: a
    // `handle == -1` op has no edge to travel.
    if crate::abi::registry::contract_is_edge(class) {
        return EBADF;
    }
    let Some(target) = default_target(class) else {
        return dispatch(class, handle, op, arg, data);
    };
    let rc = call_target(class, target, handle, op, arg, data);
    if rc >= 0 && op_mints(op) {
        let selector = match target {
            Target::Platform => PLATFORM_SELECTOR,
            Target::Module(_) => 0,
        };
        return mint(Mint {
            contract: class,
            selector,
            target,
            inner: rc,
            bound: false,
            class_routed: false,
            signals: op_signals(op),
        });
    }
    rc
}

/// Query handle state by key into `out`.
pub fn provider_query(handle: i32, key: u32, out: &mut [u8]) -> i32 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_query") {
        return errno::EACCES;
    }
    let Some(c) = contract_of(handle) else {
        return errno::ENOSYS;
    };
    let (vt_contract, inner) = if is_native(c) {
        (c, handle)
    } else {
        match route_of(handle) {
            Ok((_, _, r)) => {
                if !route_owner_ok(&r, handle, "provider_query") {
                    return errno::EACCES;
                }
                (r.contract, r.inner)
            }
            Err(_) => return errno::ENOSYS,
        }
    };
    match vtable_for(vt_contract).and_then(|v| v.query) {
        Some(f) => f(inner, key, out),
        None => errno::ENOSYS,
    }
}

/// `HANDLE_POLL`: the ready bits of `events` on `h`, or a negative errno.
/// A native handle polls through its contract's vtable; a routed one polls
/// its doorbell when it signals (taking the ring, so it reads ready once per
/// ring), else its contract's vtable with the provider's own index.
pub fn poll(h: i32, events: u32) -> i32 {
    if h < 0 {
        return errno::EINVAL;
    }
    let Some(c) = contract_of(h) else {
        return EBADF;
    };
    if is_native(c) {
        return match vtable_for(c).and_then(|v| v.poll) {
            Some(f) => f(h, events),
            None => errno::EINVAL,
        };
    }
    let (_, _, r) = match route_of(h) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !route_owner_ok(&r, h, "handle_poll") {
        return errno::EACCES;
    }
    if r.event >= 0 {
        let rang = events & crate::abi::kernel_abi::poll::IN != 0
            && crate::kernel::ipc::event::doorbell_take(r.event);
        return if rang {
            crate::abi::kernel_abi::poll::IN as i32
        } else {
            0
        };
    }
    match vtable_for(r.contract).and_then(|v| v.poll) {
        Some(f) => f(r.inner, events),
        None => errno::EINVAL,
    }
}

/// Close a handle: a native one through its contract's close op, a routed
/// one by asking its provider to close its index (the contract's default
/// close op) and dropping the route.
///
/// The route is dropped whatever the provider answers: a close never waits
/// and always releases (the `fs` contract's `CLOSE`), and a provider with
/// write-back left to do finishes it in its own step. The answer is passed
/// through for the caller to see, never as a reason to keep the handle.
pub fn provider_close(handle: i32) -> i32 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_close") {
        return errno::EACCES;
    }
    let Some(c) = contract_of(handle) else {
        return EBADF;
    };
    if is_native(c) {
        return match vtable_for(c) {
            Some(vt) if vt.default_close_op != 0 => {
                (vt.call)(handle, vt.default_close_op, &mut [], UserSpan::empty())
            }
            Some(_) => 0,
            None => errno::ENOSYS,
        };
    }
    let (idx, generation, r) = match route_of(handle) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !route_owner_ok(&r, handle, "provider_close") {
        return errno::EACCES;
    }
    close_route(idx, generation, &r)
}

/// What the platform does when an owner is released: close what the owner
/// holds open on the platform and drop its storage. Registered by the
/// platform at init; called from `notify_owner_released` after the module
/// observers, while the owner's entry still resolves.
static mut OWNER_RELEASE_HOOK: Option<fn(crate::kernel::workload::owner::OwnerHandle)> = None;

/// Register the platform's owner-release hook. One hook; the last wins.
pub fn register_owner_release_hook(hook: fn(crate::kernel::workload::owner::OwnerHandle)) {
    // SAFETY: platform init, before any owner is released.
    unsafe { *core::ptr::addr_of_mut!(OWNER_RELEASE_HOOK) = Some(hook) };
}

/// Drop every route. Called on `scheduler::reset` so a new graph inherits no
/// handle of the old one; the generations stay, so none of them names a
/// route of the new graph.
pub fn reset_handle_tracking() {
    // SAFETY: called from scheduler::reset between graph rebuilds; no
    // module observes ROUTES at this point.
    unsafe { (*core::ptr::addr_of_mut!(ROUTES)).clear() };
}

/// Snapshot of the route table. Used by diagnostics and harness tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleTrackingStats {
    /// Routes live now.
    pub in_use: usize,
    /// Routes the table holds (the `handles` pool's ceiling).
    pub capacity: usize,
}

/// Return the route table's usage.
pub fn handle_tracking_stats() -> HandleTrackingStats {
    let routes = routes();
    HandleTrackingStats {
        in_use: routes.in_use(),
        capacity: routes.capacity(),
    }
}

/// Function signature for a kernel-internal contract provider: the vtable
/// call's shape.
pub type ProviderDispatch = VTableCallFn;

/// Function signature for a PIC module contract provider: the six call words
/// with the module's state pointer prepended. Called synchronously from
/// kernel context, in the caller's frame — must not block or perform async
/// I/O.
pub type ModuleProviderDispatchFn = unsafe extern "C" fn(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32;

/// Call a module's provider dispatch with one call's words.
fn call_module(
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    mut data: UserSpan<'_>,
) -> i32 {
    let (dp, dl) = data.as_raw();
    let ap = if arg.is_empty() {
        core::ptr::null_mut()
    } else {
        arg.as_mut_ptr()
    };
    // SAFETY: `dispatch` and `state` are the pair the module registered
    // (its entry point inside its own code, its own state); `arg` and `data`
    // are live, disjoint spans for the call, as its C ABI expects.
    unsafe { dispatch(state, handle, opcode, ap, arg.len(), dp, dl) }
}

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
pub use crate::abi::registry::CHAIN_NEXT;

/// A single layer in a provider chain.
struct ProviderLayer {
    module_idx: ModuleId,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
    /// The owner of the module that registered the layer: the one owner
    /// whose modules the layer serves (see `layer_visible`).
    owner: crate::kernel::workload::owner::OwnerHandle,
    /// Instance selector (FNV-1a hash of a short volume/instance string,
    /// shared with modules via `abi::provider_selector::hash`). `0` =
    /// unkeyed / default provider — the target of the class-byte
    /// (`handle == -1`) dispatch path. A non-zero selector is reachable only
    /// through a handle bound to it by name, letting multiple volumes of one contract (two
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
/// manifest naming the contract in `provider_contracts` — a
/// compromised or mis-built module could in principle name any contract.
/// Only the contracts where it is architecturally legitimate for a module to
/// be the provider are admitted — those the registry marks `module_provided`
/// (the HAL peripherals, FS, the `storage.namespace` / `storage.object`
/// surfaces, the runtime parameter store). CHANNEL / TIMER / BUFFER / EVENT /
/// KEY_VAULT and the internal dispatch bucket are kernel-only and must not be
/// replaceable by a module.
#[inline]
fn is_module_providable(contract: ContractId) -> bool {
    crate::abi::registry::module_providable(contract)
}

/// Whether `dispatch` lies inside `module_idx`'s code region (and, on a
/// Cortex-M, is a Thumb address): a corrupted module may not register a
/// pointer into kernel memory or another module's code.
fn dispatch_in_code(module_idx: ModuleId, dispatch: ModuleProviderDispatchFn) -> bool {
    let fn_addr = dispatch as usize;
    let (code_base, code_size) =
        crate::kernel::exec::scheduler::module_code_region(module_idx as usize);
    if code_base == 0 || code_size == 0 {
        return true;
    }
    let code_end = code_base + code_size as usize;
    if fn_addr < code_base || fn_addr >= code_end {
        log::error!(
            "[provider] module {module_idx} fn_ptr 0x{fn_addr:08x} outside code region 0x{code_base:08x}..0x{code_end:08x}"
        );
        return false;
    }
    #[cfg(target_arch = "arm")]
    if fn_addr & 1 == 0 {
        log::error!("[provider] module {module_idx} fn_ptr 0x{fn_addr:08x} missing Thumb bit");
        return false;
    }
    true
}

// ── Edge servers ─────────────────────────────────────────────────────────────
//
// A module serving an edge contract is reached by module index through a
// handle bound to one of the caller's ports (`bind`), never by class byte.

/// Modules serving edge contracts at once. Sized per target like the chain.
#[cfg(feature = "chip-rp2040")]
const MAX_EDGE_SERVERS: usize = 8;
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
const MAX_EDGE_SERVERS: usize = 16;
#[cfg(not(feature = "rp"))]
const MAX_EDGE_SERVERS: usize = 64;

#[derive(Clone, Copy)]
struct EdgeServer {
    module_idx: ModuleId,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
    /// Edge contracts it serves, one bit per contract id.
    contracts: u64,
}

static mut EDGE_SERVERS: [Option<EdgeServer>; MAX_EDGE_SERVERS] = [None; MAX_EDGE_SERVERS];

fn register_edge_server(
    contract: ContractId,
    module_idx: ModuleId,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
) -> i32 {
    // SAFETY: registration runs on the scheduler thread.
    let servers = unsafe { &mut *core::ptr::addr_of_mut!(EDGE_SERVERS) };
    let bit = 1u64 << contract;
    if let Some(e) = servers
        .iter_mut()
        .flatten()
        .find(|e| e.module_idx == module_idx)
    {
        if e.contracts & bit != 0 {
            return errno::EBUSY;
        }
        e.contracts |= bit;
        return 0;
    }
    match servers.iter_mut().find(|e| e.is_none()) {
        Some(slot) => {
            *slot = Some(EdgeServer {
                module_idx,
                dispatch,
                state,
                contracts: bit,
            });
            log::info!("[provider] module {module_idx} serves edge contract 0x{contract:04x}");
            0
        }
        None => {
            log::error!(
                "[provider] module {module_idx}: {MAX_EDGE_SERVERS} modules already serve edge \
                 contracts (the per-target `MAX_EDGE_SERVERS`)"
            );
            errno::EBUSY
        }
    }
}

/// Record a module the platform runs built in as `contract`'s server on its
/// edges: an edge contract only, its dispatch the platform's own code and
/// `state` the module's instance state. `EINVAL` for a contract that is not
/// an edge contract; otherwise as a PIC module's registration.
pub fn register_native_edge_server(
    contract: ContractId,
    module_idx: ModuleId,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
) -> i32 {
    if contract as usize >= MAX_PROVIDERS || !crate::abi::registry::contract_is_edge(contract) {
        return errno::EINVAL;
    }
    register_edge_server(contract, module_idx, dispatch, state)
}

/// `module_idx`'s dispatch, if it serves edge contract `contract`.
fn edge_server(
    module_idx: ModuleId,
    contract: ContractId,
) -> Option<(ModuleProviderDispatchFn, *mut u8)> {
    // SAFETY: scheduler-thread read; the copy ends the borrow.
    let servers = unsafe { &*core::ptr::addr_of!(EDGE_SERVERS) };
    servers
        .iter()
        .flatten()
        .find(|e| e.module_idx == module_idx && e.contracts & (1u64 << contract) != 0)
        .map(|e| (e.dispatch, e.state))
}

fn release_edge_server(module_idx: ModuleId) {
    // SAFETY: scheduler-thread mutation.
    let servers = unsafe { &mut *core::ptr::addr_of_mut!(EDGE_SERVERS) };
    for e in servers.iter_mut() {
        if e.is_some_and(|e| e.module_idx == module_idx) {
            *e = None;
        }
    }
}

/// Register a PIC module as provider for a contract.
///
/// Pushes the module onto the top of the chain, or for an edge contract
/// records it as that contract's server on its edges. Returns 0 on success;
/// EINVAL if `contract` is out of range or the dispatch pointer is outside
/// the module's code region; EACCES if `contract` is not module-providable or
/// `selector` is the reserved `platform` name; EBUSY if the module already
/// holds a layer of this contract, the selector is already taken, or the
/// chain is full.
pub fn register_module_provider(
    contract: ContractId,
    module_idx: ModuleId,
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
    if !dispatch_in_code(module_idx, dispatch) {
        return errno::EINVAL;
    }
    // An edge contract is served per edge, addressed by module: it has no
    // chain, no default and no selector.
    if crate::abi::registry::contract_is_edge(contract) {
        return register_edge_server(contract, module_idx, dispatch, state);
    }
    // The platform's name is not a module's to take: a layer carrying it
    // would make a bind to `platform` reach the module, and the
    // one path that names the platform beneath a graph would stop doing so.
    if selector == PLATFORM_SELECTOR {
        log::error!(
            "[provider] module {module_idx} registers the reserved selector `platform` for \
             contract 0x{contract:04x}; that name reaches the platform's own provider"
        );
        return errno::EACCES;
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
        // duplicate keyed one is unreachable because a bind by name
        // takes the first match. Selectors are a hash of a short name, so
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
            owner: crate::kernel::exec::scheduler::module_owner(module_idx as usize),
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

/// Drop every module-registered provider layer, owner-release subscription
/// and pool-sampler mark, keeping the kernel's own dispatchers. A full graph rebuild
/// (`prepare_graph`) calls this: the modules that registered those layers
/// are gone, their state arena is reset and reused, and the rebuild never
/// runs their finish path. A layer left in place would stay the default
/// provider — old code called against reused state — and the new instance
/// landing in the same slot would be refused `EBUSY` when it registers.
/// Routed handles minted through those layers are dropped by
/// `reset_handle_tracking`, which the rebuild runs first.
pub fn reset_module_layers() {
    // SAFETY: rebuild path, scheduler thread, peers parked.
    unsafe {
        let p = &raw mut PROVIDERS;
        for entry in (*p).iter_mut() {
            for layer in entry.chain.iter_mut() {
                *layer = None;
            }
            entry.depth = 0;
        }
        *core::ptr::addr_of_mut!(EDGE_SERVERS) = [None; MAX_EDGE_SERVERS];
        let o = &raw mut OWNER_RELEASE_OBSERVERS;
        *o = crate::kernel::workload::bitmask::ModuleMask::new();
        let s = &raw mut POOL_SAMPLERS;
        *s = crate::kernel::workload::bitmask::ModuleMask::new();
    }
}

/// Release all module providers owned by a given module index.
/// Called on module finish (Done/Error) for cleanup.
/// Compacts chains to maintain stack ordering.
pub fn release_module_providers(module_idx: ModuleId) {
    // A freed slot must not stay subscribed: the slot is reused, and the next
    // module to land in it would inherit a subscription it never asked for.
    clear_owner_release_observer(module_idx);
    clear_pool_sampler(module_idx);
    // A net.route writer that goes releases its tables' bindings; the tables
    // and what they realized stay.
    crate::kernel::net_route::release_module(module_idx as usize);
    // Before the chain is compacted, so the departing module's own routed
    // handles are closed at owners that are still registered.
    release_routes_of(module_idx);
    release_edge_server(module_idx);
    // A departing net.policy enforcer stops vouching for its tables.
    crate::kernel::net_policy::release_enforcer(module_idx);
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
// The platform's owner-release hook covers what the platform's own providers
// hold for an owner. This is the module-provider counterpart. Both are
// delivered from `free_owner` itself rather than from the drain driver, so
// the paths that never reach the drain driver — the workload verbs (KILL,
// DESTROY), `FREE_OWNER` and admission rollback — are covered too.
//
// Ordering is the whole point: the notification runs BEFORE any teardown, so
// the owner handle still resolves, the provider module's state is still live,
// and a handler may make syscalls exactly as it would in a normal frame. A
// notification after `free_owner` would reach a provider that cannot validate
// the owner it was handed (the generation has moved) and that may itself have
// been torn down.

/// Providers that asked to hear about owner teardown, by module index.
/// Opt-in: set by the loader when a provider module exports
/// `observes_owner_release = true`. Never notified otherwise, because
/// calling every registered provider with an opcode it does not know would
/// reach modules whose dispatch does not bounds-check its input.
static mut OWNER_RELEASE_OBSERVERS: crate::kernel::workload::bitmask::ModuleMask =
    crate::kernel::workload::bitmask::ModuleMask::EMPTY;

/// Mark `module_idx` as an owner-release observer. Called by the loader after
/// the module's provider registration succeeds; a module that is not a
/// registered provider has no dispatch to notify, so it is refused.
pub fn register_owner_release_observer(module_idx: ModuleId) -> i32 {
    let idx = module_idx as usize;
    if idx >= crate::kernel::exec::scheduler::module_slots() {
        return errno::EINVAL;
    }
    if !module_has_provider_layer(module_idx) {
        log::warn!(
            "[provider] module {module_idx} observes owner release but \
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
pub fn clear_owner_release_observer(module_idx: ModuleId) {
    let idx = module_idx as usize;
    if idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only.
    unsafe {
        let p = &raw mut OWNER_RELEASE_OBSERVERS;
        (*p).clear(idx);
    }
}

// ============================================================================
// Pool sampling: module-provided pools
// ============================================================================
//
// A pool can be served by a module provider instead of a kernel table (the
// store's subscriptions, under a module `storage.namespace` provider). The
// ledger keeps no counters, so it pulls the pool's in-use figure from that
// provider (`resource::POOL_SAMPLE`), and the provider tells it of each
// refusal (`resource::LEDGER_DENY`). Both go to one module: the system
// owner's top-most unkeyed layer of the pool's contract — the layer the
// node's class-byte calls reach.

/// Providers that answer `POOL_SAMPLE`, by module index. Opt-in, set by the
/// loader when a provider's manifest says `samples_pool = true`, for the reason
/// `OWNER_RELEASE_OBSERVERS` is: a dispatch that never asked for the opcode
/// is never handed it.
static mut POOL_SAMPLERS: crate::kernel::workload::bitmask::ModuleMask =
    crate::kernel::workload::bitmask::ModuleMask::EMPTY;

/// Mark `module_idx` as a pool sampler. Called by the loader after the
/// module's provider registration succeeds; a module holding no provider
/// layer has no dispatch to ask, so it is refused.
pub fn register_pool_sampler(module_idx: ModuleId) -> i32 {
    let idx = module_idx as usize;
    if idx >= crate::kernel::exec::scheduler::module_slots() {
        return errno::EINVAL;
    }
    if !module_has_provider_layer(module_idx) {
        log::warn!(
            "[provider] module {module_idx} samples a pool but provides no \
             contract; nothing to ask"
        );
        return errno::EINVAL;
    }
    // SAFETY: scheduler-thread-only, same access class as the provider table.
    unsafe {
        let p = &raw mut POOL_SAMPLERS;
        (*p).set(idx);
    }
    0
}

/// Drop `module_idx` from the sampler set — with its provider layers, so a
/// module reusing the slot does not inherit it.
pub fn clear_pool_sampler(module_idx: ModuleId) {
    let idx = module_idx as usize;
    if idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only.
    unsafe {
        let p = &raw mut POOL_SAMPLERS;
        (*p).clear(idx);
    }
}

/// The module serving `pool` for the node: the node owner's top-most
/// unkeyed layer of the pool's contract (`resource::
/// module_provided_pool_contract`), with its dispatch. `None` for a pool no
/// module provides, or none registered. The borrow of `PROVIDERS` ends with
/// the call.
fn pool_provider_layer(pool: u16) -> Option<(ModuleId, ModuleProviderDispatchFn, *mut u8)> {
    let contract = crate::abi::contracts::resource::module_provided_pool_contract(pool)?;
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return None;
    }
    // SAFETY: scheduler-thread read; nothing here calls into module code.
    unsafe {
        let p = &raw const PROVIDERS;
        let entry = &(*p)[idx];
        for i in (0..entry.depth as usize).rev() {
            if let Some(ref layer) = entry.chain[i] {
                if layer.selector == 0 && layer.owner.is_node() {
                    return Some((layer.module_idx, layer.dispatch, layer.state));
                }
            }
        }
    }
    None
}

/// Whether `module_idx` is the module serving `pool` ([`pool_provider_layer`])
/// — the one module `LEDGER_DENY` admits for it.
pub fn is_pool_provider(pool: u16, module_idx: usize) -> bool {
    pool_provider_layer(pool).is_some_and(|(m, ..)| m as usize == module_idx)
}

/// Ask the module serving `pool` how much of it is in use (`POOL_SAMPLE`):
/// `Some(n)` from a marked provider that answered, `None` when no module
/// serves the pool, the one that does never asked to be sampled, or it could
/// not say. Runs the provider's dispatch in a provider frame on the calling
/// thread; the caller must not itself be inside that provider's call (the
/// ledger asks from its PSTATUS round alone).
pub fn sample_module_pool(pool: u16) -> Option<u64> {
    let (module_idx, dispatch, state) = pool_provider_layer(pool)?;
    let midx = module_idx as usize;
    // SAFETY: scheduler-thread read of the sampler set.
    let marked = unsafe {
        let p = &raw const POOL_SAMPLERS;
        midx < crate::kernel::exec::scheduler::module_slots() && (*p).test(midx)
    };
    if !marked {
        return None;
    }
    let mut arg = pool.to_le_bytes();
    let rc = in_provider_frame(midx, || {
        call_module(
            dispatch,
            state,
            -1,
            crate::abi::contracts::resource::POOL_SAMPLE,
            &mut arg[..crate::abi::contracts::resource::POOL_SAMPLE_ARG_LEN],
            UserSpan::empty(),
        )
    });
    (rc >= 0).then_some(rc as u64)
}

/// Whether `module_idx` holds at least one registered provider layer.
fn module_has_provider_layer(module_idx: ModuleId) -> bool {
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
    notify_module_observers(owner);
    // SAFETY: scheduler-thread read of a hook set at platform init.
    if let Some(hook) = unsafe { *core::ptr::addr_of!(OWNER_RELEASE_HOOK) } {
        hook(owner);
    }
}

/// The module half of [`notify_owner_released`]: every provider module that
/// subscribed is told once.
fn notify_module_observers(owner: crate::kernel::workload::owner::OwnerHandle) {
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
                    if midx < crate::kernel::exec::scheduler::module_slots() && observers.test(midx)
                    {
                        targets.set(midx);
                    }
                }
            }
        }
    }

    for midx in 0..crate::kernel::exec::scheduler::module_slots() {
        if !targets.test(midx) {
            continue;
        }
        // Re-resolve per module, in a borrow that ends before the call. If an
        // earlier handler tore this one's layer out, it is simply skipped —
        // there is nothing left to notify.
        let Some((dispatch, state)) = module_dispatch_entry(midx as ModuleId) else {
            continue;
        };
        // A fresh record per handler: one provider scribbling on the buffer
        // must not change what the next one is told.
        let mut record = encode_owner_record(owner);
        in_provider_frame(midx, || {
            call_module(
                dispatch,
                state,
                -1,
                crate::abi::internal::reconfigure::OWNER_RELEASED,
                &mut record[..crate::abi::internal::reconfigure::OWNER_RELEASED_ARG_LEN],
                UserSpan::empty(),
            )
        });
    }
}

/// The first registered `(dispatch, state)` pair for `module_idx`, or `None`
/// when it holds no provider layer. The borrow of `PROVIDERS` ends with the
/// call, so the caller may safely run module code with the result.
fn module_dispatch_entry(module_idx: ModuleId) -> Option<(ModuleProviderDispatchFn, *mut u8)> {
    // SAFETY: scheduler-thread read; nothing here calls into module code.
    let edge = unsafe {
        (*core::ptr::addr_of!(EDGE_SERVERS))
            .iter()
            .flatten()
            .find(|e| e.module_idx == module_idx)
            .map(|e| (e.dispatch, e.state))
    };
    if edge.is_some() {
        return edge;
    }
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
pub fn dispatch(
    contract: ContractId,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    // Dispatch to the default (unkeyed) module provider if one is
    // registered: the top-most selector-0 layer — identical to
    // `chain[depth-1]` when every provider is unkeyed, and the `mount`
    // policy module when keyed volume backends coexist with it. Keyed
    // backends are reached only through a handle bound to them.
    let target = {
        // SAFETY: `idx < MAX_PROVIDERS`; the chain is set up on the scheduler
        // thread before any module observes it, and the borrow ends here,
        // before any module code runs.
        let entry = unsafe { &(*core::ptr::addr_of!(PROVIDERS))[idx] };
        match default_layer_index(entry).and_then(|top| entry.chain[top].as_ref()) {
            Some(layer) => Ok((layer.module_idx, layer.dispatch, layer.state)),
            None => Err((entry.depth, entry.kernel_dispatch)),
        }
    };
    match target {
        Ok((midx, f, state)) => in_provider_frame(midx as usize, || {
            call_module(f, state, handle, opcode, arg, data)
        }),
        // Keyed backends exist but nothing serves the class-byte path. Name the
        // shape explicitly: the generic "no provider" line below would send the
        // reader looking for a missing module when the real fault is a missing
        // router.
        Err((depth, None)) if depth > 0 => {
            log::error!(
                "[provider] contract 0x{contract:04x} op 0x{opcode:04x}: {depth} instance-keyed provider(s) registered but no default (unkeyed) one — a `handle == -1` op has no router. Add a policy module (e.g. `mount`) that registers unkeyed and routes to the keyed backends.",
            );
            errno::ENOSYS
        }
        Err((_, Some(handler))) => {
            let rc = handler(handle, opcode, arg, data);
            if rc == errno::ENOSYS {
                log::debug!(
                    "[provider] contract 0x{contract:04x} op 0x{opcode:04x}: kernel handler returned ENOSYS"
                );
            }
            rc
        }
        Err((_, None)) => {
            log::warn!("[provider] contract 0x{contract:04x} op 0x{opcode:04x}: no provider");
            errno::ENOSYS
        }
    }
}

/// Dispatch to the next provider below the caller in the chain.
///
/// Called when a module sets the CHAIN_NEXT flag on an opcode.
/// Finds the caller's position in the chain and dispatches to the layer below.
/// If the caller is at the bottom (position 0), dispatches to the kernel provider.
pub fn dispatch_next(
    caller_module: ModuleId,
    contract: ContractId,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    // The layer below the caller it may reach, else the kernel provider.
    let target = {
        // SAFETY: `idx < MAX_PROVIDERS`; the chain is mutated only on the
        // scheduler thread, and the borrow ends before module code runs.
        let entry = unsafe { &(*core::ptr::addr_of!(PROVIDERS))[idx] };
        let caller_pos = (0..entry.depth as usize).rev().find(|&i| {
            entry.chain[i]
                .as_ref()
                .is_some_and(|l| l.module_idx == caller_module)
        });
        let below = caller_pos.and_then(|pos| {
            (0..pos)
                .rev()
                .find_map(|b| entry.chain[b].as_ref().filter(|l| layer_visible(l)))
        });
        match below {
            Some(layer) => Ok((layer.module_idx, layer.dispatch, layer.state)),
            None => Err(entry.kernel_dispatch),
        }
    };
    match target {
        Ok((midx, f, state)) => in_provider_frame(midx as usize, || {
            call_module(f, state, handle, opcode, arg, data)
        }),
        Err(Some(handler)) => handler(handle, opcode, arg, data),
        Err(None) => errno::ENOSYS,
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
            if layer.selector == 0 && layer_visible(layer) {
                return Some(i);
            }
        }
    }
    None
}

/// Whether the calling module may reach `layer`: a module of the layer's own
/// owner may, and so may one that acts with the authority of the layer's
/// owner. A workload's filesystem serves that workload alone, and the node's
/// providers serve the node alone: a node provider serving a workload would
/// act with the node's authority on the workload's behalf, so a workload
/// reaches storage through providers of its own or through the platform,
/// which roots it. An owner admitted to act with the node's authority
/// reaches the node's providers as the node does; its own layers stay its
/// own, unseen by the node and by its siblings.
#[inline]
fn layer_visible(layer: &ProviderLayer) -> bool {
    use crate::kernel::exec::scheduler;
    layer.owner == scheduler::caller_owner() || layer.owner == scheduler::caller_authority()
}

/// The node's own default layer of `contract`: the top-most unkeyed layer a
/// node-owned module registered, whoever is calling. `None` when the node
/// has none.
fn node_default_layer(entry: &ProviderEntry) -> Option<&ProviderLayer> {
    (0..entry.depth as usize).rev().find_map(|i| {
        entry.chain[i]
            .as_ref()
            .filter(|l| l.selector == 0 && l.owner.is_node())
    })
}

/// Deliver an op to the node's own default provider of `contract` (the
/// node's `fat32` for `fs`), in that provider's frame, whoever the caller
/// is. `ENOSYS` when the node has none.
///
/// This is the one way past [`layer_visible`], and it is the platform's: a
/// platform rooting layer (the bare-metal owner roots) answers a workload's
/// call by rewriting it beneath the workload's own root and handing it to
/// the node's provider here. No syscall, contract op or module export
/// reaches it, and the only caller is a kernel-registered provider handing
/// down a request it has already confined: a path to it from anywhere else
/// would hand a workload the node's whole namespace.
/// `tests/harness/tests/node_default_reach_lint.rs` holds every caller to
/// the platform rooting layers.
pub fn dispatch_node_default(
    contract: ContractId,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    // SAFETY: scheduler-thread read; the layer's pair is copied out before
    // module code runs.
    let target = unsafe {
        let entry = &(*core::ptr::addr_of!(PROVIDERS))[idx];
        node_default_layer(entry).map(|l| (l.module_idx, l.dispatch, l.state))
    };
    match target {
        Some((midx, f, state)) => in_provider_frame(midx as usize, || {
            call_module(f, state, handle, opcode, arg, data)
        }),
        None => errno::ENOSYS,
    }
}

/// The module serving the node's own default layer of `contract`, if any.
pub fn node_default_module(contract: usize) -> Option<usize> {
    if contract >= MAX_PROVIDERS {
        return None;
    }
    // SAFETY: scheduler-thread read.
    unsafe {
        let entry = &(*core::ptr::addr_of!(PROVIDERS))[contract];
        node_default_layer(entry).map(|l| l.module_idx as usize)
    }
}

/// The module serving `contract` by default — its top-most unkeyed layer —
/// or `None` when no module does (no provider, or only the kernel's own).
/// The contract-readiness gate asks this once the graph is instantiated.
pub fn default_module_provider(contract: usize) -> Option<usize> {
    if contract >= MAX_PROVIDERS {
        return None;
    }
    // SAFETY: scheduler thread, after instantiation; read-only.
    unsafe {
        let entry = &(*core::ptr::addr_of!(PROVIDERS))[contract];
        let top = default_layer_index(entry)?;
        entry.chain[top].as_ref().map(|l| l.module_idx as usize)
    }
}

/// `kernel::BIND`: a handle bound to one provider of `contract`.
///
/// `[NAME][len u8][name]` binds the instance-keyed layer registered under
/// `name`, or for [`PLATFORM_SELECTOR_NAME`] the platform's own provider
/// beneath every module layer. `[PORT][port_type u8][index u8]` binds the
/// module at the other end of one of the caller's ports, which must serve
/// `contract` there (an edge contract); it is handed its own port on the edge
/// as the handle of every op that reaches it.
///
/// Every op on the bound handle reaches that provider; a handle such an op
/// mints comes back routed to the same one. Returns the bound handle, or
/// `EINVAL` (a malformed bind), `ENODEV` (nothing carries the name, or no
/// module is at the other end of the port), `ENOSYS` (the provider there
/// does not serve `contract`).
pub fn bind(contract: ContractId, arg: &[u8]) -> i32 {
    use crate::abi::kernel_abi::bind as b;
    // Only a contract a module may serve has providers to choose between.
    if contract as usize >= MAX_PROVIDERS || !is_module_providable(contract) {
        return errno::EINVAL;
    }
    match arg.first() {
        Some(&b::NAME) => {
            let Some(&len) = arg.get(1) else {
                return errno::EINVAL;
            };
            let len = usize::from(len);
            let Some(name) = arg.get(2..2 + len) else {
                return errno::EINVAL;
            };
            if name.is_empty() || name.len() > b::NAME_MAX || arg.len() != 2 + len {
                return errno::EINVAL;
            }
            if crate::abi::registry::contract_is_edge(contract) {
                return errno::EINVAL;
            }
            // Never 0: `hash` nudges a zero result to 1 precisely so a real
            // name can never alias the "unkeyed default" sentinel.
            let selector = crate::abi::kernel_abi::provider_selector::hash(name);
            match target_of(contract, selector) {
                Some(target) => mint_binding(contract, selector, target, -1),
                None => errno::ENODEV,
            }
        }
        Some(&b::PORT) => {
            let (Some(&port_type), Some(&index), 3) = (arg.get(1), arg.get(2), arg.len()) else {
                return errno::EINVAL;
            };
            if !crate::abi::registry::contract_is_edge(contract) {
                return errno::EINVAL;
            }
            let me = crate::kernel::exec::scheduler::current_module_index();
            let Some((peer, peer_type, peer_index)) =
                crate::kernel::exec::scheduler::edge_peer(me, port_type, index)
            else {
                return errno::ENODEV;
            };
            if edge_server(peer as ModuleId, contract).is_none() {
                return errno::ENOSYS;
            }
            mint_binding(
                contract,
                0,
                Target::Module(peer as ModuleId),
                b::port_ref(peer_type, peer_index),
            )
        }
        _ => errno::EINVAL,
    }
}

/// The provider serving the session `handle` names, and that provider's own
/// index for it: the borrower a span lent on the session is bound to
/// (`ipc::lend`). A routed handle's provider module ([`NO_MODULE`] for the
/// platform) and inner index; a native handle is the kernel's own, under the
/// handle itself. `None` when `handle` names nothing.
pub fn session_server(handle: i32) -> Option<(ModuleId, i32)> {
    let c = contract_of(handle)?;
    if is_native(c) {
        return Some((NO_MODULE, handle));
    }
    let (_, _, r) = route_of(handle).ok()?;
    Some((r.module_idx, r.inner))
}

// ── Routed handles ───────────────────────────────────────────────────────────
//
// A handle a provider mints is an index in THAT provider's table: two
// providers of one contract hand out colliding indices (every fs provider
// starts at 0), and the default layer can change under a handle. So the
// kernel keeps a route per handle — which provider serves it and what that
// provider called it — and the handle names the route: `(contract, route
// generation, route index)`. Every later op on it is delivered to that
// provider with its own index. A bound handle (`BIND`) is a route that names a
// provider and no resource of it.

/// `EBADF`: a handle this call cannot use — of another contract, closed, or
/// never minted.
const EBADF: i32 = errno::EBADF;

/// Selector name reserved for the platform's own provider of a contract. A
/// module may not register it (refused in `register_module_provider`, and by
/// the config validator before that).
pub const PLATFORM_SELECTOR_NAME: &[u8] = b"platform";
/// The selector [`PLATFORM_SELECTOR_NAME`] hashes to.
pub const PLATFORM_SELECTOR: u32 =
    crate::abi::kernel_abi::provider_selector::hash(PLATFORM_SELECTOR_NAME);

/// `module_idx` of a route whose provider is the platform.
const ROUTE_PLATFORM: ModuleId = NO_MODULE;

/// Which provider serves a selector.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Platform,
    Module(ModuleId),
}

/// One routed handle.
#[derive(Clone, Copy)]
struct Route {
    contract: ContractId,
    /// Selector the handle was minted through ([`PLATFORM_SELECTOR`] for the
    /// platform).
    selector: u32,
    /// Serving provider's module index, or [`ROUTE_PLATFORM`].
    module_idx: ModuleId,
    /// Module that was running when the handle was minted: its owner is the
    /// handle's, and its handles are closed when it is released.
    minter: ModuleId,
    /// What the provider calls the handle: its own index; for a bound
    /// handle, what the provider is handed as the handle of an op through it
    /// (`-1`, or its own port on the edge).
    inner: i32,
    /// A `BIND` handle: it names the provider, not a resource of it, so a
    /// handle an op through it mints is routed to the same provider.
    bound: bool,
    /// The contract is routed by class: its ops reach the kernel bucket.
    class_routed: bool,
    /// For a signalling handle, the doorbell its provider rings; `-1`.
    event: i32,
}

impl Route {
    const EMPTY: Self = Self {
        contract: 0,
        selector: 0,
        module_idx: 0,
        minter: 0,
        inner: -1,
        bound: false,
        class_routed: false,
        event: -1,
    };

    fn target(&self) -> Target {
        if self.module_idx == ROUTE_PLATFORM {
            Target::Platform
        } else {
            Target::Module(self.module_idx)
        }
    }
}

/// The route table's compiled size on a static profile; elsewhere it is
/// sized from the `handles` pool.
const MAX_ROUTES: usize =
    crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_HANDLES);

static mut ROUTES: HandleTable<Route, MAX_ROUTES> = HandleTable::new(crate::boot_table!(
    MAX_ROUTES,
    Slot::free(Route::EMPTY),
    crate::abi::contracts::resource::POOL_HANDLES
));

/// The route table, sized from the plan's defaults when no plan has sized it.
fn routes() -> &'static HandleTable<Route, MAX_ROUTES> {
    // SAFETY: scheduler-thread access; a shared borrow that ends before any
    // provider code runs at every caller.
    let t = unsafe { &*core::ptr::addr_of!(ROUTES) };
    t.size_unplanned(|| {
        crate::kernel::sys::resource_ledger::ceiling(crate::abi::contracts::resource::POOL_HANDLES)
            as usize
    });
    t
}

/// The route table, for a mutation.
fn routes_mut() -> &'static mut HandleTable<Route, MAX_ROUTES> {
    let _ = routes();
    // SAFETY: scheduler-thread mutation; no borrow of the table spans a call
    // into a provider.
    unsafe { &mut *core::ptr::addr_of_mut!(ROUTES) }
}

/// Size the route table to the `handles` pool's ceiling.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size_routes(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    // SAFETY: the caller's contract.
    unsafe { (*core::ptr::addr_of!(ROUTES)).size(n) }
}

/// How many handles the platform's own provider tables can hand out at once:
/// the part of the `handles` pool the boot plan derives before the reserve.
static mut PLATFORM_HANDLE_SLOTS: Option<fn() -> usize> = None;

/// Register the platform's count of provider-table slots (its file table,
/// object and namespace tables, DMA descriptors, claimable pins, ...). One
/// counter; the last wins.
pub fn register_platform_handle_slots(f: fn() -> usize) {
    // SAFETY: platform init, before any graph is planned.
    unsafe { *core::ptr::addr_of_mut!(PLATFORM_HANDLE_SLOTS) = Some(f) };
}

/// The platform's provider-table slots, 0 when it registered no count.
pub fn platform_handle_slots() -> usize {
    // SAFETY: written once at platform init; a word-sized copy.
    unsafe { *core::ptr::addr_of!(PLATFORM_HANDLE_SLOTS) }.map_or(0, |f| f())
}

/// The live route `h` names: `(index, generation, route)`, or `EBADF`.
fn route_of(h: i32) -> Result<(u32, u16, Route), i32> {
    let Some((c, generation, idx)) = handle::decode(h) else {
        return Err(EBADF);
    };
    match routes().get(idx, generation) {
        Some(r) if r.contract == c => Ok((idx, generation, *r)),
        _ => Err(EBADF),
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
            if layer.selector == selector && layer_visible(layer) {
                return Some(Target::Module(layer.module_idx));
            }
        }
    }
    None
}

/// The provider a `handle == -1` op of `contract` reaches: the top-most
/// unkeyed module layer the caller may see, else the platform's own. `None`
/// when neither serves it.
fn default_target(contract: ContractId) -> Option<Target> {
    let idx = contract as usize;
    if idx >= MAX_PROVIDERS {
        return None;
    }
    // SAFETY: scheduler-thread read; the borrow ends before any module code
    // runs.
    let entry = unsafe { &(*core::ptr::addr_of!(PROVIDERS))[idx] };
    match default_layer_index(entry).and_then(|top| entry.chain[top].as_ref()) {
        Some(layer) => Some(Target::Module(layer.module_idx)),
        None => entry.kernel_dispatch.map(|_| Target::Platform),
    }
}

/// Deliver one op to `target`. `ENODEV` when the target has gone.
fn call_target(
    contract: ContractId,
    target: Target,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let found = match target {
        Target::Platform => {
            // SAFETY: scheduler-thread read; the copy ends the borrow.
            let k = unsafe { (*core::ptr::addr_of!(PROVIDERS))[contract as usize].kernel_dispatch };
            return match k {
                Some(handler) => handler(handle, opcode, arg, data),
                None => errno::ENODEV,
            };
        }
        Target::Module(midx) if crate::abi::registry::contract_is_edge(contract) => {
            edge_server(midx, contract).map(|(f, st)| (midx, f, st))
        }
        Target::Module(midx) => {
            // SAFETY: scheduler-thread read; the pair is copied out before
            // module code runs.
            let entry = unsafe { &(*core::ptr::addr_of!(PROVIDERS))[contract as usize] };
            entry.chain[..entry.depth as usize]
                .iter()
                .flatten()
                .find(|l| l.module_idx == midx)
                .map(|l| (midx, l.dispatch, l.state))
        }
    };
    match found {
        Some((midx, f, state)) => in_provider_frame(midx as usize, || {
            call_module(f, state, handle, opcode, arg, data)
        }),
        None => errno::ENODEV,
    }
}

/// Deliver `op` to route `r`'s provider with `handle` (its inner index, or
/// a binding's word).
fn deliver(r: &Route, handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    if r.class_routed {
        dispatch(contract::INTERNAL_DISPATCH_BUCKET, handle, op, arg, data)
    } else {
        call_target(r.contract, r.target(), handle, op, arg, data)
    }
}

/// What a new route is.
struct Mint {
    contract: ContractId,
    selector: u32,
    target: Target,
    inner: i32,
    bound: bool,
    class_routed: bool,
    signals: bool,
}

/// Wrap a provider's index in a route and return the handle naming it. A
/// signalling handle gets a doorbell, handed to its provider
/// (`BIND_DOORBELL`). On any refusal the index is closed at its provider and
/// the error returned: `ENOSPC` when the route table (the `handles` pool) or,
/// for a doorbell, the event pool is spent.
fn mint(m: Mint) -> i32 {
    use crate::abi::contracts::resource::POOL_HANDLES;
    // A handle minted in kernel context has no module minter: the
    // platform's sentinel, which nothing releases.
    let minter = crate::kernel::exec::scheduler::current_module_id();
    let mut route = Route {
        contract: m.contract,
        selector: m.selector,
        module_idx: match m.target {
            Target::Platform => ROUTE_PLATFORM,
            Target::Module(midx) => midx,
        },
        minter,
        inner: m.inner,
        bound: m.bound,
        class_routed: m.class_routed,
        event: -1,
    };
    if m.signals {
        let ringer = match m.target {
            Target::Platform => NO_MODULE,
            Target::Module(midx) => midx,
        };
        let doorbell = crate::kernel::ipc::event::doorbell_claim(minter, ringer);
        if doorbell < 0 {
            close_inner(&route);
            return doorbell;
        }
        route.event = doorbell;
    }
    let Some((idx, generation)) = routes_mut().claim(route) else {
        log::error!(
            "[provider] pool 'handles' at its ceiling of {} routes; handle of contract \
             {:#x} refused",
            routes().capacity(),
            m.contract
        );
        crate::kernel::sys::resource_ledger::deny(POOL_HANDLES);
        if route.event >= 0 {
            crate::kernel::ipc::event::doorbell_release(route.event);
        }
        if !m.bound {
            close_inner(&route);
        }
        return errno::ENOSPC;
    };
    if route.event >= 0 {
        let mut arg =
            crate::abi::kernel_abi::doorbell::bind_arg(route.event as u32, route.contract);
        let rc = deliver(
            &route,
            route.inner,
            crate::abi::kernel_abi::doorbell::BIND_DOORBELL,
            &mut arg,
            UserSpan::empty(),
        );
        if rc < 0 {
            close_route(idx, generation, &route);
            return rc;
        }
    }
    handle::encode(route.contract, generation, idx)
}

/// Ask route `r`'s provider to close its index (the contract's default close
/// op), when it has one and the route names a resource.
fn close_inner(r: &Route) -> i32 {
    if r.bound {
        return 0;
    }
    match vtable_for(r.contract).map_or(0, |v| v.default_close_op) {
        0 => 0,
        close => deliver(r, r.inner, close, &mut [], UserSpan::empty()),
    }
}

/// Close route `idx` at its provider and drop it.
fn close_route(idx: u32, generation: u16, r: &Route) -> i32 {
    let rc = close_inner(r);
    retire_route(idx, generation);
    rc
}

/// The handle a `BIND` returns: a route to `target` that names no resource.
fn mint_binding(contract: ContractId, selector: u32, target: Target, inner: i32) -> i32 {
    mint(Mint {
        contract,
        selector,
        target,
        inner,
        bound: true,
        class_routed: false,
        signals: false,
    })
}

/// Deliver `op` on live route `idx` to its provider with the provider's own
/// index (a binding's word for a bound handle), wrap a handle the op mints in
/// a route to the same provider, and drop the route when the op closes it.
fn call_route(
    idx: u32,
    generation: u16,
    r: Route,
    op: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let rc = deliver(&r, r.inner, op, arg, data);
    if rc >= 0 && op_mints(op) {
        return mint(Mint {
            contract: r.contract,
            selector: r.selector,
            target: r.target(),
            inner: rc,
            bound: false,
            class_routed: r.class_routed,
            signals: op_signals(op),
        });
    }
    if !r.bound && rule_of(op).is_some_and(|rule| rule.closes) {
        retire_route(idx, generation);
    }
    rc
}

/// Drop route `idx` if it still holds `generation` (the op may have run
/// module code that already dropped it), freeing its doorbell.
fn retire_route(idx: u32, generation: u16) {
    if let Some(r) = routes_mut().release(idx, generation) {
        if r.event >= 0 {
            crate::kernel::ipc::event::doorbell_release(r.event);
        }
    }
}

/// Retire every route to the platform's provider of `contract` that names its
/// index `inner`. A platform provider that frees an index other than by the
/// handle's close (a workload's `DESTROY`, through any handle naming it or by
/// identity) calls this as it frees it: no handle outlives what it named, and
/// none names whatever the index is handed to next.
pub fn retire_routes_naming(contract: ContractId, inner: i32) {
    let mut i = 0usize;
    loop {
        let next = routes()
            .live()
            .find(|(idx, _, r)| {
                *idx as usize >= i
                    && r.contract == contract
                    && r.module_idx == ROUTE_PLATFORM
                    && !r.bound
                    && r.inner == inner
            })
            .map(|(idx, generation, _)| (idx, generation));
        let Some((idx, generation)) = next else {
            break;
        };
        retire_route(idx, generation);
        i = idx as usize + 1;
    }
}

/// Retire every route served by, or minted by, `module_idx`. A route whose
/// provider is gone names nothing and is dropped. A route the departing module
/// minted on a provider that stays is closed there, so the provider does not
/// hold the resource for a consumer that no longer exists.
fn release_routes_of(module_idx: ModuleId) {
    // The platform's sentinel is not a module: nothing releases it.
    if module_idx == ROUTE_PLATFORM {
        return;
    }
    let mut i = 0usize;
    loop {
        // One route at a time, by index, with no borrow of the table held
        // across a close: the close runs provider code.
        let next = routes()
            .live()
            .find(|(idx, _, r)| {
                *idx as usize >= i && (r.module_idx == module_idx || r.minter == module_idx)
            })
            .map(|(idx, generation, r)| (idx, generation, *r));
        let Some((idx, generation, r)) = next else {
            break;
        };
        if r.module_idx == module_idx {
            retire_route(idx, generation);
        } else {
            close_route(idx, generation, &r);
        }
        i = idx as usize + 1;
    }
}

/// Routed handles currently live. Diagnostics and tests.
pub fn routed_handles_in_use() -> usize {
    routes().in_use()
}
