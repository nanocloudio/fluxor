//! Syscall implementations for PIC modules.
//!
//! This module provides the kernel-side implementation of the syscall table.
//! PIC modules call these functions through function pointers to access
//! hardware resources (SPI, GPIO, timers, etc.).
//!
//! ## Concurrency
//!
//! `SYSCALL_TABLE`, `HARDWARE_CONTEXT`, `SYSTEM_EXTENSION`, and
//! `DEV_QUERY_EXTENSION` are written once by `init_syscall_table` /
//! `init_providers` on core 0, then read from every core during
//! steady-state syscall traffic. The function-local `LOGGED` /
//! `LOGGED_NULL_STATE` debounce flags can race across cores; the
//! worst case is a duplicate log line per process lifetime. See
//! `docs/architecture/concurrency.md`.
//!
//! # Architecture
//!
//! Portable kernel code lives in this file. Platform-specific hardware drivers
//! (SPI, I2C, UART, ADC, DMA, PIO, PWM, GPIO hardware ops) are registered
//! via the HAL `init_providers()` callback at boot time.
//!
//! # Return Value Convention
//!
//! All syscalls follow a consistent return value pattern:
//! - `< 0`: Error (negative errno values)
//! - `= 0`: Success or pending (context-dependent)
//! - `> 0`: Success with data (bytes transferred, handle, etc.)
//!
//! # Error Codes
//!
//! Uses Linux errno values for compatibility:
//! - `E_INVAL` (-22): Invalid argument
//! - `E_AGAIN` (-11): Resource temporarily unavailable / try again
//! - `E_NODEV` (-19): No such device
//! - `E_BUSY` (-16): Device or resource busy
//! - `E_NOSYS` (-38): Function not implemented

use core::ptr::null_mut;

use crate::abi::{SyscallTable, ABI_VERSION};
use crate::kernel::exec::scheduler::ModuleId;
use crate::kernel::ipc::channel;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;
use crate::kernel::sys::hal;
// ============================================================================
// Error Codes (Linux errno values)
// ============================================================================

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;

// ============================================================================
// Syscall Table
// ============================================================================

static mut SYSCALL_TABLE: SyscallTable = empty_syscall_table();

pub fn set_syscall_table(table: SyscallTable) {
    // SAFETY: called once during boot (kernel::boot -> init_syscall_table)
    // before any module runs; no concurrent reader.
    unsafe {
        SYSCALL_TABLE = table;
    }
}

pub fn init_syscall_table() {
    set_syscall_table(SyscallTable {
        version: ABI_VERSION,
        telemetry_enabled: crate::kernel::sys::telemetry_ring::enabled_ptr(),
        channel_read: channel::syscall_channel_read,
        channel_write: channel::syscall_channel_write,
        channel_poll: channel::syscall_channel_poll,
        heap_alloc: syscall_heap_alloc,
        heap_free: syscall_heap_free,
        heap_realloc: syscall_heap_realloc,
        provider_open: syscall_provider_open,
        provider_call: syscall_provider_call,
        provider_query: syscall_provider_query,
        provider_close: syscall_provider_close,
        channel_peek: channel::syscall_channel_peek,
        channel_discard: channel::syscall_channel_discard,
    });
}

// ── Handle-scoped provider dispatch ─────────────────────────────────
//
// Every `syscall_provider_*` wrapper fires the interrupt-mode gate as its
// FIRST check, before the grant check and the dispatch, so an interrupt-mode
// module calling an op it holds no grant for is told `EACCES` by the
// interrupt-mode gate, not by the grant check. The inner `provider::*`
// functions also gate as defense in depth.

/// The caller's `[ptr, ptr + len)` as a slice: empty for a zero length,
/// `None` for a null pointer with a non-zero one.
///
/// # Safety
/// The ungated syscall-table contract: the span is the calling module's own
/// memory, live and unaliased for the call.
unsafe fn caller_slice<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

/// # Safety
/// `config[..config_len]` is the calling module's own readable memory.
unsafe extern "C" fn syscall_provider_open(
    contract: u32,
    open_op: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_open") {
        return crate::kernel::sys::errno::EACCES;
    }
    // INTERNAL_DISPATCH_BUCKET (the `kernel` contract) is kernel-internal only — module
    // code must use the public platform contracts (PLATFORM_NIC_RING,
    // PLATFORM_DMA, PLATFORM_DMA_FD) for handle-returning platform ops.
    if contract as u16 == crate::kernel::module::provider::contract::INTERNAL_DISPATCH_BUCKET {
        log::warn!(
            "[grant] module called provider_open on the kernel contract; \
             use PLATFORM_NIC_RING / PLATFORM_DMA / PLATFORM_DMA_FD instead"
        );
        return E_NOSYS;
    }
    let Ok(contract) = u16::try_from(contract) else {
        return errno::EINVAL;
    };
    if open_op == crate::abi::registry::kernel::BIND {
        // A bind names which provider of `contract` answers, never what the
        // caller may ask of it: the caller holds the contract itself.
        let Some(need) = crate::abi::registry::contract_grant(contract) else {
            return E_NOSYS;
        };
        if let Some(rc) = refuse(u32::from(contract), need) {
            return rc;
        }
    } else {
        // An open names the contract it opens and an op of that contract; the
        // provider is chosen by the first, so the second must agree with it.
        if (open_op >> 8) & 0xFF != u32::from(contract) {
            return errno::EINVAL;
        }
        if let Some(rc) = check_grant(open_op) {
            return rc;
        }
    }
    // Every provider_open mints a new held resource, so it is admission-gated.
    if admission_closed("provider_open") {
        return crate::kernel::sys::errno::EACCES;
    }
    // SAFETY: the caller's contract; an open only reads its config.
    let Some(config) = (unsafe { caller_slice(config as *mut u8, config_len) }) else {
        return errno::EINVAL;
    };
    crate::kernel::module::provider::provider_open(contract, open_op, config)
}

/// # Safety
/// `arg[..arg_len]` and `data[..data_len]` are the calling module's own
/// memory, live for the call.
unsafe extern "C" fn syscall_provider_call(
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    // interrupt-mode (`timer`/`irq`) modules are denied `provider_call` in general,
    // but the bridge ops and `SELF_BRIDGE` are exempt:
    // their underlying ring operations are lock-free and allocation-free, so
    // they are the *sanctioned* I/O path for an interrupt-mode step body.
    if !crate::abi::internal::bridge::is_isr_safe(op)
        && crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_call")
    {
        return crate::kernel::sys::errno::EACCES;
    }
    // A kernel primitive (a class-routed contract) is routed by its opcode
    // ahead of any handle, so its handle argument names no contract: a
    // LOG_WRITE carries a log level there. Any other op is answered by the
    // handle's provider, so the caller must hold that contract as well.
    if let Some(rc) = check_grant(op) {
        return rc;
    }
    if !crate::abi::registry::op_routes_to_kernel(op) {
        if let Some(rc) = check_handle_grant(handle) {
            return rc;
        }
    }
    // Admission gate on the open/create/accept/arm-class opcodes —
    // use-style ops on established handles stay state-blind so a
    // draining owner can flush in-flight work.
    if admission_class_op(op) && admission_closed("provider_call") {
        return crate::kernel::sys::errno::EACCES;
    }
    // The provider holds `arg` and `data` at once.
    if crate::kernel::module::user_span::overlaps(arg, arg_len, data, data_len) {
        return errno::EINVAL;
    }
    // SAFETY: the caller's contract, and the two spans are disjoint.
    let (Some(arg), Some(data)) = (unsafe { caller_slice(arg, arg_len) }, unsafe {
        crate::kernel::module::user_span::UserSpan::from_checked(data, data_len)
    }) else {
        return errno::EINVAL;
    };
    crate::kernel::module::provider::provider_call(handle, op, arg, data)
}

/// # Safety
/// `out[..out_len]` is the calling module's own writable memory.
unsafe extern "C" fn syscall_provider_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_query") {
        return crate::kernel::sys::errno::EACCES;
    }
    if let Some(rc) = check_grant(key) {
        return rc;
    }
    if let Some(rc) = check_handle_grant(handle) {
        return rc;
    }
    // SAFETY: the caller's contract.
    let Some(out) = (unsafe { caller_slice(out, out_len) }) else {
        return errno::EINVAL;
    };
    // Try the handle's vtable first; if no contract query is registered,
    // fall back to the built-in cross-class query dispatcher.
    let vt_rc = crate::kernel::module::provider::provider_query(handle, key, out);
    if vt_rc != E_NOSYS {
        return vt_rc;
    }
    kernel_query_dispatch(handle, key, out)
}

unsafe extern "C" fn syscall_provider_close(handle: i32) -> i32 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("provider_close") {
        return crate::kernel::sys::errno::EACCES;
    }
    if let Some(rc) = check_handle_grant(handle) {
        return rc;
    }
    crate::kernel::module::provider::provider_close(handle)
}

fn syscall_table() -> &'static SyscallTable {
    // SAFETY: `SYSCALL_TABLE` is set once during boot before any module
    // observes it; `&raw const` avoids materialising a long-lived shared
    // reference to a mutable static.
    unsafe {
        let p = &raw const SYSCALL_TABLE;
        &*p
    }
}

/// Get a reference to the full (unfiltered) syscall table for passing to PIC modules
pub fn get_syscall_table() -> &'static SyscallTable {
    syscall_table()
}

// ============================================================================
// Channel Wrappers
// ============================================================================

/// Admission gate: true when the calling module's owner may NOT admit new
/// work. Admission closes the moment a drain begins; existing-handle use
/// stays state-blind (`authorize_use` semantics), which is what lets
/// in-flight work run dry. It is open while the owner is being added, for
/// its modules' `module_new` (`authorize_own_admit`). Node-owned modules
/// always pass. Every module-facing create/open/accept/allocate/arm path
/// consults this: provider open/bind, `channel_open`, open-style
/// `provider_call` ops (`admission_class_op`), event create, heap
/// allocation, timer arm.
fn admission_closed(surface: &'static str) -> bool {
    let owner = crate::kernel::exec::scheduler::module_owner(
        crate::kernel::exec::scheduler::current_module_index(),
    );
    if owner.is_node() {
        return false;
    }
    if crate::kernel::exec::scheduler::owners_mut().authorize_own_admit(owner) {
        return false;
    }
    log::warn!("[owner] {surface} refused: admission closed (owner draining/revoked)");
    true
}

/// Open-style / arm-style `provider_call` opcodes that CREATE new work or
/// resources and therefore fall under the admission gate. Use-style ops
/// on established handles (read/write/poll/fsync/close/cancel/destroy/
/// buffer-acquire on open channels) are deliberately absent: a draining
/// owner must still flush in-flight work to completion.
fn admission_class_op(op: u32) -> bool {
    crate::abi::registry::op_admits(op)
}

/// A module's `channel::OPEN`: a ring of the capacity `config` asks for,
/// the caller both its ends.
pub fn channel_open(config: &[u8]) -> i32 {
    if admission_closed("channel_open") {
        return -1;
    }
    channel::channel_open_for_module(config, crate::kernel::exec::scheduler::current_module_id())
}

pub fn channel_close(handle: i32) {
    channel::channel_close(handle)
}

// ============================================================================
// SPI/I2C Initialization Status
// ============================================================================

use crate::kernel::boot::config::HardwareContext;

// Hardware context - tracks which resources have been initialized
static mut HARDWARE_CONTEXT: HardwareContext = HardwareContext::new();

pub fn mark_spi_initialized(bus: u8) {
    // SAFETY: HARDWARE_CONTEXT lives on the boot-time / scheduler thread;
    // mark/is calls do not race because scheduler-init runs sequentially.
    unsafe {
        let p = &raw mut HARDWARE_CONTEXT;
        (*p).mark_spi_initialized(bus)
    }
}

/// Check if an SPI bus has been initialized
pub fn is_spi_initialized(bus: u8) -> bool {
    // SAFETY: as above; read-only path.
    unsafe {
        let p = &raw const HARDWARE_CONTEXT;
        (*p).is_spi_initialized(bus)
    }
}

pub fn mark_i2c_initialized(bus: u8) {
    // SAFETY: as above.
    unsafe {
        let p = &raw mut HARDWARE_CONTEXT;
        (*p).mark_i2c_initialized(bus)
    }
}

/// Check if an I2C bus has been initialized
pub fn is_i2c_initialized(bus: u8) -> bool {
    // SAFETY: as above; read-only path.
    unsafe {
        let p = &raw const HARDWARE_CONTEXT;
        (*p).is_i2c_initialized(bus)
    }
}

// ============================================================================
// Provider Registration
// ============================================================================

/// Register all built-in device class providers.
/// Called once at startup after init_syscall_table().
pub fn init_providers() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::CHANNEL, channel_provider_dispatch);
    provider::register(dev_class::TIMER, timer_provider_dispatch);
    provider::register(dev_class::EVENT, event_provider_dispatch);
    provider::register(
        dev_class::INTERNAL_DISPATCH_BUCKET,
        system_provider_dispatch,
    );
    // PLATFORM_NIC_RING / PLATFORM_DMA / PLATFORM_DMA_FD expose disjoint
    // handle types to drivers (NIC ring, raw DMA channel number, tagged
    // DMA fd). They share `system_provider_dispatch` because dispatch is
    // by opcode, but each contract id gets its own vtable slot so
    // declaration and gating stay independent.
    provider::register(dev_class::PLATFORM_NIC_RING, system_provider_dispatch);
    provider::register(dev_class::PLATFORM_DMA, system_provider_dispatch);
    provider::register(dev_class::PLATFORM_DMA_FD, system_provider_dispatch);
    provider::register(dev_class::PCIE_DEVICE, system_provider_dispatch);
    // FS has no kernel-side provider — a PIC filesystem module (fat32,
    // …) or a host platform dispatcher (linux_fs_dispatch) registers
    // itself. If nothing is registered, `provider::dispatch(FS, …)`
    // returns ENOSYS naturally; no stub needed.
    // KEY_VAULT: the router, on BOTH paths — this class-byte dispatch and
    // the KEY_VAULT_VTABLE below. It serves the kernel software backend
    // and, when a platform registers one behind it (the Linux PKCS#11
    // backend), a hardware backend; each handle names the backend that
    // holds its key. Consumers never name a platform — they read
    // PROBE/CUSTODY/DESCRIBE.
    provider::register(dev_class::KEY_VAULT, primary_stack_key_vault);
    provider::register(
        crate::abi::registry::metal_device::ID,
        crate::kernel::module::metal_device::dispatch,
    );
    // The vault's durable store is the same router's other surface; its ops
    // need the `seal_key` grant.
    provider::register(
        crate::abi::registry::vault_store::ID,
        primary_stack_key_vault,
    );

    // Handle-scoped vtables for the kernel-owned contracts. Tracked
    // handles route through the vtable; handle=-1 globals fall through
    // to the class-byte dispatch registered above. Both paths converge
    // on the same dispatch functions.
    provider::register_vtable(&CHANNEL_VTABLE);
    provider::register_vtable(&TIMER_VTABLE);
    provider::register_vtable(&EVENT_VTABLE);
    provider::register_vtable(&KEY_VAULT_VTABLE);
    provider::register_vtable(&FS_VTABLE);
    provider::register_vtable(&STORAGE_NAMESPACE_VTABLE);
    provider::register_vtable(&STORAGE_OBJECT_VTABLE);
    provider::register_vtable(&PCIE_DEVICE_VTABLE);
    // Lends are class-routed to the kernel bucket; the vtable gives a lend
    // handle its close.
    provider::register(crate::abi::registry::lend::ID, system_provider_dispatch);
    provider::register_vtable(&LEND_VTABLE);
    provider::register_vtable(&BRIDGE_VTABLE);

    // HAL vtables for contracts whose `call` dispatch is supplied by a
    // PIC module (registered by the loader from its manifest's `provider_contracts`).
    // The vtable's `call` routes through the kernel's class-byte dispatch
    // chain so it picks up whatever provider is registered at call time.
    // Consumer modules with tracked handles dispatch through the vtable;
    // handle=-1 global opens fall through the same chain.
    provider::register_vtable(&HAL_GPIO_VTABLE);
    provider::register_vtable(&HAL_SPI_VTABLE);
    provider::register_vtable(&HAL_I2C_VTABLE);
    provider::register_vtable(&HAL_PIO_VTABLE);
    provider::register_vtable(&HAL_UART_VTABLE);
    provider::register_vtable(&HAL_ADC_VTABLE);
    provider::register_vtable(&HAL_PWM_VTABLE);

    // Platform-specific providers (GPIO, PIO, etc.) registered via HAL
    hal::init_providers();
}

// ── Handle-scoped vtables ───────────────────────────────────────────
//
// Each vtable's `call` is the existing class dispatch function (or a
// thin wrapper around `provider::dispatch` with the right class byte
// for PIC-module-provided contracts). `default_close_op` is the
// opcode `provider_close` invokes to release a handle. Contracts that
// don't need a close hook leave it as 0.

use crate::abi::contracts;
use crate::abi::kernel_abi;

static CHANNEL_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::CHANNEL,
        call: channel_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::channel::CLOSE,
        poll: Some(channel_handle_poll),
    };

static TIMER_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::TIMER,
        call: timer_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::timer::DESTROY,
        poll: Some(crate::kernel::ipc::timer::timer_poll),
    };

static EVENT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::EVENT,
        call: event_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::event::DESTROY,
        poll: Some(crate::kernel::ipc::event::event_poll_ready),
    };

/// `HANDLE_POLL` on a channel handle.
fn channel_handle_poll(handle: i32, events: u32) -> i32 {
    channel::channel_poll(handle, events)
}

/// `HANDLE_POLL` on a bridge: readable when its ring holds a record.
fn bridge_handle_poll(slot: i32, events: u32) -> i32 {
    use crate::abi::internal::bridge;
    if slot < 0 || events & crate::abi::kernel_abi::poll::IN == 0 {
        return 0;
    }
    let ready = crate::kernel::ipc::isr_ring::dispatch(
        slot as usize,
        bridge::POLL,
        &mut [],
        UserSpan::empty(),
    );
    if ready > 0 {
        crate::abi::kernel_abi::poll::IN as i32
    } else {
        0
    }
}

/// Bridges are class-routed to the kernel bucket; the vtable gives a bridge
/// handle its poll.
static BRIDGE_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::abi::registry::bridge::ID,
        call: system_provider_dispatch,
        query: None,
        default_close_op: 0,
        poll: Some(bridge_handle_poll),
    };

// KEY_VAULT vtable: the router, over every backend.
static KEY_VAULT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::KEY_VAULT,
        call: primary_stack_key_vault,
        query: None,
        default_close_op: contracts::key_vault::DESTROY,
        poll: None,
    };

// PCIE_DEVICE shares `system_provider_dispatch` (same call path as
// PLATFORM_NIC_RING / PLATFORM_DMA / PLATFORM_DMA_FD) but needs its
// own vtable so `provider_close(handle)` dispatches the CLOSE opcode
// to release per-handle bookkeeping.
static PCIE_DEVICE_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::PCIE_DEVICE,
        call: system_provider_dispatch,
        query: None,
        default_close_op: crate::abi::contracts::hal::pcie_device::CLOSE,
        poll: None,
    };

static LEND_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::abi::registry::lend::ID,
        call: system_provider_dispatch,
        query: None,
        default_close_op: crate::abi::registry::lend::CLOSE,
        poll: None,
    };

// FS contract has no built-in kernel implementation — a PIC filesystem
// module (fat32, …) or a host-side platform dispatcher (linux_fs_dispatch)
// registers as the provider. The vtable's `call` routes through the
// class-byte dispatch chain so it picks up whichever provider is
// registered, same shape as the HAL vtables.
fn fs_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::FS, handle, op, arg, data)
}

static FS_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::FS,
        call: fs_call,
        query: None,
        default_close_op: contracts::storage::fs::CLOSE,
        poll: None,
    };

// STORAGE_NAMESPACE / STORAGE_OBJECT vtables. Same shape as FS: the
// kernel ships no built-in provider; a PIC module (a local store, a
// cluster store, an object-store adapter) registers via
// `provider_contracts` and is
// routed through the class-byte dispatch chain. The vtable carries
// `default_close_op` so `provider_close` releases tracked handles
// uniformly.

fn storage_namespace_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::STORAGE_NAMESPACE, handle, op, arg, data)
}

static STORAGE_NAMESPACE_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::STORAGE_NAMESPACE,
        call: storage_namespace_call,
        query: None,
        default_close_op: contracts::storage::namespace::CLOSE,
        poll: None,
    };

fn storage_object_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::STORAGE_OBJECT, handle, op, arg, data)
}

static STORAGE_OBJECT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::STORAGE_OBJECT,
        call: storage_object_call,
        query: None,
        default_close_op: contracts::storage::object::CLOSE,
        poll: None,
    };

// HAL contracts whose `call` dispatch is a PIC module provider. The
// vtable's `call` forwards to `provider::dispatch` with the right
// class byte so the existing module-chain routing applies.

fn hal_gpio_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::GPIO, handle, op, arg, data)
}

/// A gpio claim or watch is closed with `RELEASE`, whoever serves it; a
/// platform with its own gpio provider registers its own vtable over this.
static HAL_GPIO_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_GPIO,
        call: hal_gpio_call,
        query: None,
        default_close_op: contracts::hal::gpio::RELEASE,
        poll: None,
    };

fn hal_spi_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::SPI, handle, op, arg, data)
}

static HAL_SPI_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_SPI,
        call: hal_spi_call,
        query: None,
        default_close_op: contracts::hal::spi::CLOSE,
        poll: None,
    };

fn hal_i2c_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::I2C, handle, op, arg, data)
}

static HAL_I2C_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_I2C,
        call: hal_i2c_call,
        query: None,
        default_close_op: contracts::hal::i2c::CLOSE,
        poll: None,
    };

fn hal_pio_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::PIO, handle, op, arg, data)
}

// PIO contracts open handles via multiple alloc variants (STREAM_ALLOC,
// CMD_ALLOC, RX_STREAM_ALLOC) and release them via STREAM_FREE or
// CMD_FREE. The default close op is STREAM_FREE; callers that opened
// a command or RX handle should invoke the matching FREE opcode via
// `provider_call` before `provider_close`.
static HAL_PIO_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_PIO,
        call: hal_pio_call,
        query: None,
        default_close_op: crate::abi::platform::rp::pio::STREAM_FREE,
        poll: None,
    };

fn hal_uart_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::UART, handle, op, arg, data)
}

static HAL_UART_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_UART,
        call: hal_uart_call,
        query: None,
        default_close_op: contracts::hal::uart::CLOSE,
        poll: None,
    };

fn hal_adc_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::ADC, handle, op, arg, data)
}

static HAL_ADC_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_ADC,
        call: hal_adc_call,
        query: None,
        default_close_op: contracts::hal::adc::CLOSE,
        poll: None,
    };

fn hal_pwm_call(handle: i32, op: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::module::provider::contract as class;
    crate::kernel::module::provider::dispatch(class::PWM, handle, op, arg, data)
}

static HAL_PWM_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_PWM,
        call: hal_pwm_call,
        query: None,
        default_close_op: contracts::hal::pwm::CLOSE,
        poll: None,
    };

/// The key vault's provider: the router, on a stack that holds a signature
/// (see [`primary_stack_dispatch`]); `ENOTSUP` on a small one.
#[inline(never)]
fn primary_stack_key_vault(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    if on_small_stack() {
        return errno::ENOTSUP;
    }
    crate::kernel::security::key_vault_router::dispatch(handle, opcode, arg, data)
}

// ============================================================================
// Generic Device Call / Query
// ============================================================================

/// Whether the module being stepped holds what `need` asks for.
fn holds(need: crate::abi::registry::OpGrant) -> bool {
    use crate::abi::registry::OpGrant;
    let held = crate::kernel::exec::scheduler::current_module_grants();
    match need {
        OpGrant::Free => true,
        OpGrant::Contract(c) => held[0] & (1u64 << c) != 0,
        OpGrant::Grant(g) => held[1] & (1u64 << g) != 0,
    }
}

/// The manifest name of what `need` asks for, for the refusal's log line.
fn grant_name(need: crate::abi::registry::OpGrant) -> &'static str {
    use crate::abi::registry::{contract_name, grant, OpGrant};
    match need {
        OpGrant::Free => "",
        OpGrant::Contract(c) => contract_name(c).unwrap_or("?"),
        OpGrant::Grant(g) => grant::name(g).unwrap_or("?"),
    }
}

/// Refuse a call the module being stepped does not hold the grant for.
fn refuse(what: u32, need: crate::abi::registry::OpGrant) -> Option<i32> {
    if holds(need) {
        return None;
    }
    log::warn!(
        "[grant] module {} refused 0x{:04x}: it does not hold `{}`",
        crate::kernel::exec::scheduler::current_module_index(),
        what,
        grant_name(need),
    );
    Some(errno::EACCES)
}

/// The one authority check: whether the module being stepped may call `op`.
///
/// `None` when it may. An op the registry does not list does not exist
/// (`ENOSYS`); one it lists but the module does not hold the grant for is
/// refused (`EACCES`). Every way into a provider applies it — by handle, by
/// opcode class, by selector and by query key — and the gateway funnels a
/// gated module's calls into the same table, so a gated and an ungated
/// module meet the same rule.
fn check_grant(op: u32) -> Option<i32> {
    let op = op & !crate::abi::registry::CHAIN_NEXT;
    let Some(need) = crate::abi::registry::op_grant(op) else {
        return Some(E_NOSYS);
    };
    refuse(op, need)
}

/// The grant a handle's own contract asks of whoever uses the handle, so an
/// op answered by the handle's provider is held to that contract too.
fn check_handle_grant(handle: i32) -> Option<i32> {
    let contract = crate::kernel::module::provider::contract_of(handle)?;
    let Some(need) = crate::abi::registry::contract_grant(contract) else {
        return Some(E_NOSYS);
    };
    refuse(contract as u32, need)
}

// ============================================================================
// Per-class provider dispatch functions (portable)
// ============================================================================

/// A little-endian `u32` at the head of `arg`, when it holds one.
fn arg_u32(arg: &[u8]) -> Option<u32> {
    let b: [u8; 4] = arg.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// A little-endian `u64` at `arg[at..at + 8]`, when it holds one.
fn arg_u64(arg: &[u8], at: usize) -> Option<u64> {
    let b: [u8; 8] = arg.get(at..at + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(b))
}

/// Write `answer` at the head of `arg`; `EINVAL` when it does not fit.
fn answer(arg: &mut [u8], answer: &[u8]) -> Result<(), i32> {
    match arg.get_mut(..answer.len()) {
        Some(out) => {
            out.copy_from_slice(answer);
            Ok(())
        }
        None => Err(E_INVAL),
    }
}

fn channel_provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], _data: UserSpan<'_>) -> i32 {
    use crate::abi::kernel_abi::channel as dev_channel;
    use crate::kernel::ipc::channel;
    let me = crate::kernel::exec::scheduler::current_module_id();
    match opcode {
        dev_channel::OPEN => channel_open(arg),
        dev_channel::CLOSE => channel::close_as(handle, me),
        dev_channel::PORT => match *arg {
            [port_type, index, ..] => {
                crate::kernel::exec::scheduler::channel_port_lookup(port_type, index)
            }
            _ => E_INVAL,
        },
        // `arg` out `[producer_owner u16][flags u8][0]` about a channel the
        // caller is an end of.
        dev_channel::FACTS => {
            use crate::abi::kernel_abi::channel::facts;
            let Some(out) = arg.get_mut(..facts::LEN) else {
                return E_INVAL;
            };
            let me = crate::kernel::exec::scheduler::current_module_index();
            match crate::kernel::exec::scheduler::channel_facts(handle, me) {
                Some((owner, flags)) => {
                    out[facts::PRODUCER_OWNER..facts::PRODUCER_OWNER + 2]
                        .copy_from_slice(&owner.to_le_bytes());
                    out[facts::FLAGS] = flags;
                    out[facts::FLAGS + 1] = 0;
                    0
                }
                None => errno::EBADF,
            }
        }
        dev_channel::FLUSH => channel::flush_as(handle, me),
        dev_channel::SET_HUP => channel::set_hup_as(handle, me),
        dev_channel::WRITABLE => {
            let Some(out) = arg.get_mut(..4) else {
                return E_INVAL;
            };
            match channel::writable_as(handle, me) {
                Ok(n) => {
                    out.copy_from_slice(&(n.min(u32::MAX as usize) as u32).to_le_bytes());
                    0
                }
                Err(e) => e,
            }
        }
        dev_channel::RECORD_LEN => channel::record_len_as(handle, me),
        dev_channel::ACQUIRE_WRITE => {
            acquire_reply(arg, || channel::buffer_acquire_write(handle, me))
        }
        // The length is the record: without it nothing is published.
        dev_channel::RELEASE_WRITE => match arg_u32(arg) {
            Some(len) => channel::buffer_release_write(handle, me, len),
            None => E_INVAL,
        },
        dev_channel::ACQUIRE_READ => {
            acquire_reply(arg, || channel::buffer_acquire_read(handle, me))
        }
        dev_channel::RELEASE_READ => channel::buffer_release_read(handle, me),
        dev_channel::ACQUIRE_INPLACE => {
            acquire_reply(arg, || channel::buffer_acquire_inplace(handle, me))
        }
        _ => E_NOSYS,
    }
}

/// Run a mailbox acquire and answer it: the buffer's address and length go
/// into the caller's `acquired` record and the status is the call's result, so
/// an address is never squeezed into the `i32` a call returns. The record is
/// checked before anything is acquired: a caller that cannot be told where its
/// buffer is must not be left holding one.
fn acquire_reply(arg: &mut [u8], acquire: impl FnOnce() -> channel::Acquired) -> i32 {
    use crate::abi::kernel_abi::channel::acquired as rec;
    let Some(out) = arg.get_mut(..rec::SIZE) else {
        return E_INVAL;
    };
    let acquired = acquire();
    out.fill(0);
    out[rec::PTR..rec::PTR + 8].copy_from_slice(&(acquired.ptr as usize as u64).to_le_bytes());
    out[rec::LEN..rec::LEN + 4].copy_from_slice(&acquired.len.to_le_bytes());
    acquired.status
}

/// `TIMER::DISCIPLINE`: anchor the network-disciplined wall clock. Only a
/// platform whose HAL reads `time_sync` (bcm2712, uefi, rp2350) takes an anchor;
/// anywhere else the call is `ENOSYS` rather than a second clock nobody reads.
fn discipline_wall_clock(unix_us: u64, mono_us: u64, err_us: u64) -> i32 {
    #[cfg(any(
        feature = "aarch64-metal",
        all(feature = "rp", not(feature = "chip-rp2040"))
    ))]
    {
        let now = hal::now_micros();
        let rc = crate::kernel::sys::time_sync::discipline(unix_us, mono_us, err_us, now);
        if rc == 0 {
            log::info!(
                "[time] anchored unix_ms={} err_us={}",
                unix_us / 1_000,
                err_us
            );
        }
        rc
    }
    #[cfg(not(any(
        feature = "aarch64-metal",
        all(feature = "rp", not(feature = "chip-rp2040"))
    )))]
    {
        let _ = (unix_us, mono_us, err_us);
        E_NOSYS
    }
}

/// The `TIMER::TRUSTED_UNIX` observation: what time it is, and what this
/// platform can honestly claim about it. One function for the syscall and
/// for kernel-resident providers that decide against time (a store admitting
/// a capability grant), so both judge by the same reading.
pub(crate) fn trusted_unix_record() -> [u8; crate::abi::kernel_abi::trusted_time::LEN] {
    use crate::abi::kernel_abi::trusted_time as tt;
    let unix_ms = hal::now_unix_millis();
    let monotonic_us = hal::now_micros();

    // What this platform can honestly claim.
    //
    // `now_unix_millis` alone cannot answer this and never could: a
    // nonzero reading from a clock nobody synchronised looks exactly
    // like a good one, so a reading on its own can never be more
    // than `RTC`.
    //
    // `hal::clock_sync_status` is what says more. An operating system
    // running a time protocol tracks whether its clock has been
    // disciplined and by how much it may be off, and asking it is
    // evidence rather than assumption. Three distinguishable answers,
    // and the distinctions are the point:
    //
    //   - the platform cannot tell           → `RTC`, untrusted
    //   - it can tell, and says NOT synced   → `RTC`, untrusted
    //   - it can tell, and says synced       → `NETWORK_SYNC`,
    //                                          `SYNCHRONIZED | TRUSTED`
    //
    // The middle case is deliberately not weaker than the first. A
    // clock the platform knows is unsynchronised is no worse than one
    // it knows nothing about — it is the same reading with better
    // reporting, and demoting it would punish the platform for being
    // honest.
    //
    // `TRUSTED` is set only in the third case. It is the flag a
    // consumer reads to decide whether a validity window means
    // anything, so setting it without evidence would issue
    // credentials against a clock that lies — and the fail-closed
    // direction is that a missing flag denies.
    let sync = hal::clock_sync_status();
    let (source_class, flags, uncertainty_ms) = if unix_ms == 0 {
        (tt::source::UNAVAILABLE, 0u8, u32::MAX)
    } else {
        match sync {
            Some((true, max_error_us)) => {
                // The kernel's own estimate of how far off it may be,
                // rounded UP to milliseconds: a consumer sizing a
                // window from this must not be handed a bound
                // narrower than the truth.
                let ms = max_error_us.div_ceil(1_000);
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "saturated to u32::MAX immediately below"
                )]
                let ms = if ms > u64::from(u32::MAX) {
                    u32::MAX
                } else {
                    ms as u32
                };
                (
                    tt::source::NETWORK_SYNC,
                    tt::flags::SYNCHRONIZED | tt::flags::TRUSTED,
                    // Never narrower than the one-millisecond tick
                    // this clock is read at.
                    ms.max(1),
                )
            }
            // Either the platform cannot tell, or it can and the
            // answer is no. Same claim: a local clock, untrusted.
            _ => (tt::source::RTC, 0u8, 1u32),
        }
    };

    // Which clock this reading belongs to. The ledger compares it
    // against the previous reading through the monotonic counter
    // read at the same instant, so a step or a resynchronisation
    // moves the epoch and a backward step raises the flag — the
    // two things a consumer holding a cached decision needs and
    // that the reading alone can never carry.
    let synced = sync.map(|(s, _)| s);
    let obs =
        crate::kernel::sys::wall_clock::observe(unix_ms, monotonic_us, synced, uncertainty_ms);
    let flags = if obs.rollback_suspect {
        flags | tt::flags::ROLLBACK_SUSPECT
    } else {
        flags
    };

    let mut rec = [0u8; tt::LEN];
    rec[tt::OFF_UNIX_SECONDS..tt::OFF_UNIX_SECONDS + 8]
        .copy_from_slice(&(unix_ms / 1000).to_le_bytes());
    #[allow(
        clippy::cast_possible_truncation,
        reason = "sub-second remainder, always < 1e9"
    )]
    rec[tt::OFF_UNIX_NANOS..tt::OFF_UNIX_NANOS + 4]
        .copy_from_slice(&(((unix_ms % 1000) * 1_000_000) as u32).to_le_bytes());
    // The interval this reading is honest within: the kernel's own
    // `maxerror` when it has one, the read granularity otherwise.
    rec[tt::OFF_UNCERTAINTY_MS..tt::OFF_UNCERTAINTY_MS + 4]
        .copy_from_slice(&uncertainty_ms.to_le_bytes());
    rec[tt::OFF_MONOTONIC_US..tt::OFF_MONOTONIC_US + 8]
        .copy_from_slice(&monotonic_us.to_le_bytes());
    rec[tt::OFF_SOURCE_EPOCH..tt::OFF_SOURCE_EPOCH + 8].copy_from_slice(&obs.epoch.to_le_bytes());
    rec[tt::OFF_SOURCE_CLASS] = source_class;
    rec[tt::OFF_FLAGS] = flags;
    rec
}

fn timer_provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], _data: UserSpan<'_>) -> i32 {
    use crate::abi::kernel_abi::timer as dev_timer;
    use crate::kernel::ipc::timer as fd;
    let reply = |arg: &mut [u8], v: &[u8]| match answer(arg, v) {
        Ok(()) => 0,
        Err(e) => e,
    };
    match opcode {
        dev_timer::MILLIS => reply(arg, &hal::now_millis().to_le_bytes()),
        dev_timer::MICROS => reply(arg, &hal::now_micros().to_le_bytes()),
        dev_timer::UNIX_MILLIS => reply(arg, &hal::now_unix_millis().to_le_bytes()),
        dev_timer::TRUSTED_UNIX => {
            use crate::abi::kernel_abi::trusted_time as tt;
            if arg.len() < tt::LEN {
                return E_INVAL;
            }
            reply(arg, &trusted_unix_record())
        }
        dev_timer::DISCIPLINE => {
            let (Some(unix_us), Some(mono_us), Some(err_us)) = (
                arg_u64(arg, 0),
                arg_u64(arg, 8),
                arg.get(16..).and_then(arg_u32),
            ) else {
                return E_INVAL;
            };
            discipline_wall_clock(unix_us, mono_us, u64::from(err_us))
        }
        dev_timer::CREATE => fd::timer_create(),
        dev_timer::SET => match arg_u32(arg) {
            Some(ms) => fd::timer_set(handle, ms),
            None => E_INVAL,
        },
        dev_timer::CANCEL => fd::timer_cancel(handle),
        dev_timer::DESTROY => fd::timer_destroy(handle),
        _ => E_NOSYS,
    }
}

/// A module occupancy as `CALLER_MODULE` and `MODULE_LIVE` carry it: `[module idx u16][0 u16][slot generation u32]`, laid out like
/// the owner record so a provider stamps and compares both alike.
fn module_record(idx: u16, gen: u32) -> [u8; 8] {
    let mut r = [0u8; 8];
    r[..2].copy_from_slice(&idx.to_le_bytes());
    r[4..].copy_from_slice(&gen.to_le_bytes());
    r
}

fn event_provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], _data: UserSpan<'_>) -> i32 {
    use crate::abi::kernel_abi::event as dev_event;
    use crate::kernel::ipc::event;
    match opcode {
        dev_event::CREATE => event::event_create(),
        dev_event::SIGNAL => event::event_signal(handle),
        dev_event::POLL => event::event_poll(handle),
        dev_event::DESTROY => event::event_destroy(handle),
        dev_event::BIND_IRQ => bind_irq(handle, arg),
        _ => E_NOSYS,
    }
}

/// `event::BIND_IRQ`: `handle` = an event the caller owns; `arg = [irq u32]
/// [ack u8]`, `ack` naming how the kernel quiets the device behind the line
/// (`event::ack`). The interrupt signals the event's handle, so an event
/// destroyed since is never signalled.
fn bind_irq(handle: i32, arg: &[u8]) -> i32 {
    use crate::abi::kernel_abi::event::ack;
    let (Some(irq), Some(&how)) = (arg_u32(arg), arg.get(4)) else {
        return E_INVAL;
    };
    let how = match how {
        ack::NONE => hal::IrqAck::None,
        ack::VIRTIO_MMIO => hal::IrqAck::VirtioMmio,
        _ => return E_INVAL,
    };
    if !crate::kernel::ipc::event::owned_by_caller(handle) {
        return errno::EBADF;
    }
    // Event-bound IRQs (e.g. virtio-mmio) are serviced on core 0.
    hal::irq_bind(irq, handle, how, 0)
}

// ============================================================================
// System Provider Dispatch (portable opcodes + extension point)
// ============================================================================

/// Platform-extension dispatch entry: the same call every kernel provider
/// takes.
pub type ExtensionFn = crate::kernel::module::provider::VTableCallFn;

/// Platform-extension query entry: the same as a contract's query.
pub type QueryExtensionFn = crate::kernel::module::provider::VTableQueryFn;

/// Extension point for platform-specific system opcodes (PWM, PIO, DMA, SPI9, etc.)
static mut SYSTEM_EXTENSION: Option<ExtensionFn> = None;

pub fn register_system_extension(f: ExtensionFn) {
    // SAFETY: called once during platform init before any module runs.
    unsafe {
        SYSTEM_EXTENSION = Some(f);
    }
}

/// Extension point for platform-specific provider-query entries.
/// Called by the kernel-side query fallback when a handle's contract
/// vtable doesn't claim the key. Used by platform code (RP, BCM2712)
/// to expose chip-specific introspection (SYS_CLOCK_HZ, GPIO::GET_LEVEL
/// for untracked handles, …).
static mut DEV_QUERY_EXTENSION: Option<QueryExtensionFn> = None;

pub fn register_dev_query_extension(f: QueryExtensionFn) {
    // SAFETY: as `register_system_extension` — boot-time installation.
    unsafe {
        DEV_QUERY_EXTENSION = Some(f);
    }
}

/// The platform's answer to whether the calling core steps on a stack too
/// small for the kernel's deepest calls: a secondary core with a small stack
/// of its own. None registered: every core's stack holds them.
static mut SMALL_STACK: Option<fn() -> bool> = None;

/// Name the platform's small-stack test. Boot-time, or `None` to clear it.
pub fn register_small_stack(f: Option<fn() -> bool>) {
    // SAFETY: as `register_system_extension` — boot-time installation.
    unsafe {
        SMALL_STACK = f;
    }
}

/// Whether the calling core steps on a small stack ([`register_small_stack`]).
fn on_small_stack() -> bool {
    // SAFETY: written once at boot before any module runs; a word-sized copy.
    let test = unsafe { *core::ptr::addr_of!(SMALL_STACK) };
    test.is_some_and(|f| f())
}

fn system_extension() -> Option<ExtensionFn> {
    // SAFETY: written once at boot before any module runs; a word-sized copy.
    unsafe { *core::ptr::addr_of!(SYSTEM_EXTENSION) }
}

fn dev_query_extension() -> Option<QueryExtensionFn> {
    // SAFETY: as `system_extension`.
    unsafe { *core::ptr::addr_of!(DEV_QUERY_EXTENSION) }
}

/// `PROGRAM_INFO`, `PROGRAM_READ`, `SIGNING_ROOT` and `SLOT_ADMITTED`:
/// the calling module's own programs, the node graph slots are signed
/// against, and the slots this boot admitted. A module names a program only
/// by its slot among its own; whose programs they are comes from which module
/// is running, never from the request.
fn handle_program_op(opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    use crate::abi::kernel_abi::{
        program as pg, FLASH_LAYOUT, PROGRAM_INFO, PROGRAM_READ, SLOT_ADMITTED,
    };
    use crate::kernel::exec::scheduler;
    match opcode {
        SLOT_ADMITTED => {
            #[cfg(feature = "rp")]
            return i32::from(crate::platform::planner::admitted_slots());
            #[cfg(not(feature = "rp"))]
            return errno::ENOSYS;
        }
        FLASH_LAYOUT => {
            #[cfg(feature = "rp")]
            {
                use crate::abi::platform::rp::flash_layout::GRAPH_FLASH_LEN;
                match answer(arg, &crate::platform::chip::GRAPH_FLASH.encode()) {
                    Ok(()) => GRAPH_FLASH_LEN as i32,
                    Err(e) => e,
                }
            }
            #[cfg(not(feature = "rp"))]
            {
                let _ = arg;
                errno::ENOSYS
            }
        }
        PROGRAM_INFO => {
            let Some(out) = arg.get_mut(..pg::INFO_LEN) else {
                return E_INVAL;
            };
            let Some(p) = scheduler::module_program(scheduler::current_module_index(), out[0])
            else {
                return errno::ENOENT;
            };
            // An address answer: where the module may read the bytes in
            // place, and how many; `0, 0` where it cannot dereference kernel
            // memory and reads through PROGRAM_READ instead.
            let (addr, len, region_end) = if cfg!(target_arch = "wasm32") {
                (0u64, 0u32, 0u32)
            } else {
                let addr = p.addr as usize;
                let end = (p.region as usize + p.region_len).saturating_sub(addr);
                (addr as u64, p.size as u32, end as u32)
            };
            let put =
                |out: &mut [u8], at: usize, v: &[u8]| out[at..at + v.len()].copy_from_slice(v);
            out.fill(0);
            put(out, pg::info::ADDR, &addr.to_le_bytes());
            put(out, pg::info::LEN, &len.to_le_bytes());
            put(out, pg::info::KIND, &p.kind.to_le_bytes());
            put(out, pg::info::SIZE, &(p.size as u32).to_le_bytes());
            put(out, pg::info::REGION_END, &region_end.to_le_bytes());
            put(out, pg::info::FORMAT, &p.format);
            pg::INFO_LEN as i32
        }
        PROGRAM_READ => {
            // `[slot u8][0; 3][offset u32 LE]`; the bytes go to `data`.
            let (Some(&slot), Some(offset)) = (arg.first(), arg.get(4..).and_then(arg_u32)) else {
                return E_INVAL;
            };
            let Some(p) = scheduler::module_program(scheduler::current_module_index(), slot) else {
                return errno::ENOENT;
            };
            let offset = offset as usize;
            if offset >= p.size {
                return 0;
            }
            let out = data.as_mut();
            let n = (p.size - offset).min(out.len()).min(i32::MAX as usize);
            // SAFETY: the loader bounded the program to `[addr, addr + size)`
            // inside memory the kernel keeps for the module's life, and
            // `offset + n <= size`.
            let src = unsafe { core::slice::from_raw_parts(p.addr.add(offset), n) };
            out[..n].copy_from_slice(src);
            n as i32
        }
        _ => errno::ENOSYS,
    }
}

/// `kernel_abi::SIGNAL_CORE`: raise an SGI on one core. `arg = [core u8][sgi u8]`.
fn signal_core(arg: &[u8]) -> i32 {
    let (core, sgi) = match *arg {
        [core, sgi, ..] => (core, sgi),
        _ => return E_INVAL,
    };
    #[cfg(feature = "aarch64-metal")]
    {
        if usize::from(core) >= crate::arch::aarch64::exception::MAX_CORES || sgi > 15 {
            return E_INVAL;
        }
        // SAFETY: the GIC is configured and initialised on every core before
        // any module runs; `core` and `sgi` are in range.
        unsafe { crate::arch::aarch64::gic::send_sgi(u32::from(core), u32::from(sgi)) };
        0
    }
    #[cfg(not(feature = "aarch64-metal"))]
    {
        let _ = (core, sgi);
        E_NOSYS
    }
}

/// Whether `opcode` is one the kernel answers on the primary stack alone:
/// the `reconfigure` contract (a change of the graph, a staged update) and
/// the signing root, which reads and checks the image's layout.
fn primary_stack_op(opcode: u32) -> bool {
    opcode >> 8 == u32::from(crate::abi::registry::reconfigure::ID)
        || opcode == crate::abi::kernel_abi::SIGNING_ROOT
}

/// The ops of [`primary_stack_op`]. They run the kernel's deepest frames (a
/// signature check, the loader), so a core that steps on a small stack of its
/// own is refused `ENOTSUP` before any of them runs
/// ([`register_small_stack`]). The firmware build's stack bound counts a
/// `primary_stack_*` function for its own frame and no deeper on such a
/// core, which holds because the refusal is the function's first act.
#[inline(never)]
fn primary_stack_dispatch(opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::abi::internal::reconfigure;
    use crate::kernel::exec::scheduler;
    if on_small_stack() {
        return errno::ENOTSUP;
    }
    match opcode {
        crate::abi::kernel_abi::SIGNING_ROOT => {
            match crate::kernel::security::root::signing_root() {
                Some(root) => match answer(arg, &root) {
                    Ok(()) => 32,
                    Err(e) => e,
                },
                None => errno::ENOENT,
            }
        }
        // ── Live reconfigure primitives ──
        reconfigure::SET_PHASE
        | reconfigure::CALL_DRAIN
        | reconfigure::MARK_FINISHED
        | reconfigure::MODULE_COUNT
        | reconfigure::MODULE_INFO
        | reconfigure::MODULE_UPSTREAM
        | reconfigure::MODULE_DONE
        | reconfigure::SLOT_CAPACITY => handle_reconfigure_op(opcode, arg),
        // `data` = the configuration to rebuild from; empty = the one this
        // graph booted from. A rebuild reloads the boot configuration on
        // every platform, so a supplied one has nowhere to go.
        reconfigure::TRIGGER_REBUILD => {
            if !data.is_empty() {
                return E_NOSYS;
            }
            scheduler::request_rebuild();
            0
        }

        // ── Live graph mutation ──
        // `data` = the encoded subgraph, read in place for this call; the
        // new owner's `[slot u16][generation u32]` is answered into `arg`.
        reconfigure::APPLY_ADD => {
            // A node whose plan seats no workload owner stages no add.
            if scheduler::splice::add_capacity() == 0 {
                return crate::kernel::sys::errno::ENOSPC;
            }
            if arg.len() < 6 {
                return E_INVAL;
            }
            // SAFETY: `data` is the caller's span for this call and the add
            // completes within it. The calling module is the add's creator.
            match unsafe {
                scheduler::splice::apply_encoded_by(
                    data.as_slice(),
                    scheduler::current_module_index(),
                )
            } {
                Ok(owner) => {
                    scheduler::splice::write_handle(&mut arg[..6], owner);
                    0
                }
                Err(e) => e,
            }
        }
        reconfigure::FREE_OWNER => scheduler::live::free_owner_encoded(arg),
        reconfigure::OWNER_PAUSE => scheduler::live::owner_pause_encoded(arg),
        reconfigure::OWNER_RESUME => scheduler::live::owner_resume_encoded(arg),

        // ── OTA RAM staging (Pi 5 / hosted Linux; ENOSYS elsewhere) ──
        // `arg = [offset u32]`, `data` = the bytes to stage there.
        #[cfg(any(feature = "chip-bcm2712", feature = "host-linux"))]
        reconfigure::OTA_STAGE_WRITE => match arg_u32(arg) {
            Some(offset) => {
                crate::kernel::module::ota_stage::stage_write(offset as usize, data.as_slice())
            }
            None => E_INVAL,
        },
        #[cfg(any(feature = "chip-bcm2712", feature = "host-linux"))]
        reconfigure::OTA_STAGE_CTRL => match arg.first() {
            Some(&cmd) => crate::kernel::module::ota_stage::stage_ctrl(cmd),
            None => E_INVAL,
        },
        _ => E_NOSYS,
    }
}

/// The kernel bucket's provider: every class-routed op (the kernel's own and
/// every contract the registry routes by class) and the platform contracts
/// that share it.
fn system_provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::abi::contracts::resource;
    use crate::abi::contracts::telemetry;
    use crate::abi::internal::diag;
    use crate::abi::internal::{bridge, monitor};
    use crate::abi::kernel_abi::doorbell::DOORBELL_RING;
    use crate::abi::kernel_abi::{
        ARENA_GET, BOOT_INCARNATION, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE,
        MODULE_FLOW_BUDGET, MODULE_INSTANCE_PARAMS, NET_IDENT_PROVIDER, RANDOM_FILL,
        REPORT_LATENCY, REPORT_STEP_EFFECT, SELF_INDEX, SERIAL_WRITE, SIGNAL_CORE,
    };
    use crate::abi::registry::lend;
    use crate::kernel::exec::scheduler;
    match opcode {
        SIGNAL_CORE => signal_core(arg),
        // ── Core primitives ──
        SELF_INDEX
        | NET_IDENT_PROVIDER
        | BOOT_INCARNATION
        | ARENA_GET
        | REPORT_LATENCY
        | REPORT_STEP_EFFECT
        | LOG_WRITE
        | SERIAL_WRITE
        | GET_HW_ETHERNET_MAC
        | HANDLE_POLL
        | RANDOM_FILL
        | MODULE_INSTANCE_PARAMS
        | MODULE_FLOW_BUDGET
        | bridge::SELF_BRIDGE
        | monitor::INTERRUPT_METRICS => handle_core_primitive(handle, opcode, arg, data),
        // A module provider rings a doorbell it was handed: `[doorbell u32]`.
        DOORBELL_RING => match arg_u32(arg) {
            Some(d) => crate::kernel::ipc::event::doorbell_ring_by(
                d as i32,
                scheduler::current_module_id(),
            ),
            None => E_INVAL,
        },
        crate::abi::kernel_abi::PROGRAM_INFO
        | crate::abi::kernel_abi::PROGRAM_READ
        | crate::abi::kernel_abi::SLOT_ADMITTED
        | crate::abi::kernel_abi::FLASH_LAYOUT => handle_program_op(opcode, arg, data),
        // ── Lends ──
        lend::OPEN => {
            let mut span = data;
            crate::kernel::ipc::lend::open(handle, arg, &mut span)
        }
        lend::RESOLVE => crate::kernel::ipc::lend::resolve(arg),
        lend::RETURN => crate::kernel::ipc::lend::give_back(arg),
        lend::CLOSE => crate::kernel::ipc::lend::close(handle),
        resource::ELASTIC_ALLOC => handle_elastic_alloc(arg),
        // A module provider's refusal of a pool it serves, counted by the
        // ledger; `module_deny` admits the pool's server alone.
        resource::LEDGER_DENY => match *arg {
            [a, b, ..] => crate::kernel::sys::resource_ledger::module_deny(
                u16::from_le_bytes([a, b]),
                scheduler::current_module_index(),
            ),
            _ => E_INVAL,
        },
        telemetry::TLM_EMIT
        | telemetry::TLM_SUBSCRIBE
        | telemetry::TLM_DRAIN
        | telemetry::TLM_STATS => handle_telemetry_op(handle, opcode, arg, data),
        // ── Cycle and instruction-cache counters ──
        crate::abi::contracts::counters::DESCRIBE | crate::abi::contracts::counters::READ => {
            crate::kernel::sys::counters::dispatch(opcode, arg)
        }
        // ── Diagnostics / log transport ──
        diag::LOG_RING_DRAIN => handle_diag_op(opcode, data),
        // ── Bridge channel operations ──
        bridge::WRITE | bridge::READ | bridge::POLL | bridge::INFO => {
            // `handle` = the bridge's slot (its route's inner index).
            if handle < 0 {
                return E_INVAL;
            }
            crate::kernel::ipc::isr_ring::dispatch(handle as usize, opcode, arg, data)
        }
        // ── Fault monitor ──
        monitor::FAULT_MONITOR_SUBSCRIBE
        | monitor::FAULT_MONITOR_POP
        | monitor::FAULT_STATS_QUERY
        | monitor::FAULT_RAISE
        | monitor::STEP_HISTOGRAM_QUERY
        | monitor::MODULE_STATE_QUERY => handle_fault_monitor_op(handle, opcode, arg),

        // ── Live reconfigure, graph mutation, staging; the signing root ──
        op if primary_stack_op(op) => primary_stack_dispatch(op, arg, data),

        _ => match system_extension() {
            // Platform extension for hardware-specific opcodes.
            Some(ext) => ext(handle, opcode, arg, data),
            None => E_NOSYS,
        },
    }
}

// ============================================================================
// system_provider_dispatch category handlers
// ============================================================================
//
// The class-routed opcodes are split across small category handlers below
// so the top-level match stays readable and each concern is local.

/// `ELASTIC_ALLOC` (`resource` contract): grant an elastic-region chunk from the
/// kernel elastic region to the calling module. `arg` in `[bytes u32 LE]`,
/// out `[addr u64 LE][len u32 LE]` (an address answer); returns 0 or an
/// accounted `ENOSPC`.
fn handle_elastic_alloc(arg: &mut [u8]) -> i32 {
    let Some(bytes) = arg_u32(arg) else {
        return E_INVAL;
    };
    if arg.len() < 12 {
        return E_INVAL;
    }
    let bytes = bytes as usize;
    let idx = crate::kernel::exec::scheduler::current_module_index();
    if idx >= crate::kernel::exec::scheduler::module_slots() {
        return E_INVAL;
    }
    // The deployment envelope may size the region down (static reservation over the
    // elastic region reserve): check the enforced ceiling before granting.
    {
        use crate::kernel::config::ELASTIC_QUANTUM;
        let (used, _) = crate::kernel::mem::elastic::region_usage();
        let would = used + bytes.div_ceil(ELASTIC_QUANTUM.max(1)) * ELASTIC_QUANTUM.max(1);
        if !crate::kernel::sys::resource_ledger::enforced_allows(
            crate::abi::contracts::resource::POOL_ELASTIC_REGION,
            would as u32,
        ) {
            crate::kernel::sys::resource_ledger::deny(
                crate::abi::contracts::resource::POOL_ELASTIC_REGION,
            );
            return crate::kernel::sys::errno::ENOSPC;
        }
    }
    match crate::kernel::mem::elastic::alloc(idx as ModuleId, bytes) {
        Some((ptr, len)) => {
            arg[0..8].copy_from_slice(&(ptr as usize as u64).to_le_bytes());
            arg[8..12].copy_from_slice(&(len as u32).to_le_bytes());
            0
        }
        None => {
            crate::kernel::sys::resource_ledger::deny(
                crate::abi::contracts::resource::POOL_ELASTIC_REGION,
            );
            crate::kernel::sys::errno::ENOSPC
        }
    }
}

fn handle_telemetry_op(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    use crate::abi::contracts::telemetry as tlm;
    use crate::kernel::exec::scheduler;
    use crate::kernel::sys::telemetry_ring;
    // Kernel-stamped identity: the current stepping module, or the UNATTRIBUTED
    // sentinel when called outside a step bracket (a real module index never
    // reaches the reserved high values). Stamps emits and owns drain slots, so a
    // module can neither forge another's records nor drain another's slot.
    let idx = scheduler::current_module_index();
    let caller = if idx <= 0xFFFD {
        idx as u16
    } else {
        tlm::MODULE_UNATTRIBUTED
    };
    match opcode {
        // `arg` = one whole record, header first.
        tlm::TLM_EMIT => {
            if arg.len() < tlm::HEADER_SIZE || arg.len() > tlm::MAX_RECORD_SIZE {
                return E_INVAL;
            }
            telemetry_ring::emit(caller, arg);
            0
        }
        // `arg = [filter u32]` and, optionally, `[pstatus_interval_ms u64]`.
        tlm::TLM_SUBSCRIBE => {
            let filter = arg_u32(arg).unwrap_or(tlm::FILTER_ALL);
            // The trailing PSTATUS cadence: how often the collector wants the
            // kernel to push its step-histogram / arena round. Absent → keep
            // the kernel default.
            if let Some(ms) = arg_u64(arg, tlm::SUBSCRIBE_INTERVAL_OFFSET) {
                scheduler::set_pstatus_interval_ms(ms);
            }
            telemetry_ring::subscribe(caller, filter)
        }
        tlm::TLM_DRAIN => {
            // `handle` carries the slot id from TLM_SUBSCRIBE; whole records
            // go to `data`.
            if handle < 0 {
                return E_INVAL;
            }
            // A drain advances the tail, so draining a slot you do not own
            // destroys its owner's records. `observe` grants the surface, not
            // another consumer's stream.
            if !telemetry_ring::owns(handle as usize, caller) {
                return E_INVAL;
            }
            telemetry_ring::drain(handle as usize, data.as_mut()) as i32
        }
        tlm::TLM_STATS => {
            // Layout: `[head u32][dropped u32 × CONSUMERS]`.
            let need = 4 + telemetry_ring::CONSUMERS * 4;
            let Some(out) = arg.get_mut(..need) else {
                return E_INVAL;
            };
            let (head, slots) = telemetry_ring::stats();
            out[0..4].copy_from_slice(&head.to_le_bytes());
            for (chunk, (_active, _lag, dropped)) in out[4..].chunks_exact_mut(4).zip(slots.iter())
            {
                chunk.copy_from_slice(&dropped.to_le_bytes());
            }
            need as i32
        }
        _ => E_NOSYS,
    }
}

/// `LOG_WRITE`: one message at a log level. Bytes that are not UTF-8 are
/// dropped whole.
fn log_write(level: u8, msg: &[u8]) {
    if let Ok(s) = core::str::from_utf8(msg) {
        match level {
            1 => log::error!("{s}"),
            2 => log::warn!("{s}"),
            3 => log::info!("{s}"),
            4 => log::debug!("{s}"),
            _ => log::trace!("{s}"),
        }
    }
}

fn handle_core_primitive(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    use crate::abi::internal::bridge;
    use crate::abi::internal::monitor::INTERRUPT_METRICS;
    use crate::abi::kernel_abi::{
        ARENA_GET, BOOT_INCARNATION, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE,
        MODULE_FLOW_BUDGET, MODULE_INSTANCE_PARAMS, NET_IDENT_PROVIDER, RANDOM_FILL,
        REPORT_LATENCY, REPORT_STEP_EFFECT, SELF_INDEX, SERIAL_WRITE,
    };
    use crate::kernel::exec::scheduler;
    match opcode {
        SELF_INDEX => scheduler::current_module_index() as i32,
        BOOT_INCARNATION => {
            let v = crate::kernel::sys::incarnation::get();
            if let Err(e) = answer(arg, &v) {
                return e;
            }
            if v == [0u8; 16] {
                // The entropy source has not answered: no incarnation yet,
                // and a consumer must not mint against zeros.
                return errno::EAGAIN;
            }
            0
        }
        // Net-identity provider self-registration: the calling BASE-GRAPH
        // module declares itself the node's shared network stack, carrying its
        // own `addr_ctl` input-port index in `arg` (see
        // `kernel_abi::NET_IDENT_PROVIDER`). Workload modules are refused —
        // a owner must not hijack identity installs.
        NET_IDENT_PROVIDER => {
            let addr_ctl = match *arg {
                [a, ..] => a,
                _ => return E_INVAL,
            };
            let idx = scheduler::current_module_index();
            if !scheduler::module_owner(idx).is_node() {
                return crate::kernel::sys::errno::EACCES;
            }
            crate::kernel::workload::workload_graph::register_net_identity_provider(
                idx as u16, addr_ctl,
            )
        }
        // One of the calling module's own ISR bridges: `arg = [dir u8][index
        // u8]`. Answers the bridge's slot, which the kernel wraps in a handle.
        bridge::SELF_BRIDGE => {
            let (Some(&dir), Some(&index)) = (arg.first(), arg.get(1)) else {
                return crate::kernel::sys::errno::EINVAL;
            };
            let idx = scheduler::current_module_index();
            if idx >= scheduler::MAX_MODULES {
                return crate::kernel::sys::errno::ENODEV;
            }
            let Some((in_b, out_b)) =
                crate::kernel::exec::interrupt::module_bridge_slots(idx as ModuleId)
            else {
                return crate::kernel::sys::errno::ENODEV;
            };
            let side = match dir {
                bridge::DIR_IN => in_b,
                bridge::DIR_OUT => out_b,
                _ => return crate::kernel::sys::errno::EINVAL,
            };
            match side.iter().filter(|s| **s >= 0).nth(usize::from(index)) {
                Some(&s) => i32::from(s),
                None => crate::kernel::sys::errno::ENOENT,
            }
        }
        // `arg = [port u8][dir u8]` (`0` output, `1` input). An input port's
        // budget is resolved through the channel the calling module reads it
        // by, which the kernel looks up itself.
        MODULE_FLOW_BUDGET => match *arg {
            [port, 1, ..] => scheduler::syscall_input_flow_budget(port),
            [port, 0, ..] => scheduler::syscall_flow_budget(port),
            _ => E_INVAL,
        },
        // The instance's params into `data`; an empty `data` asks only their
        // length. Answers the bytes written (or the length).
        MODULE_INSTANCE_PARAMS => {
            let out = data.as_mut();
            let total = scheduler::copy_module_params(scheduler::current_module_index(), out);
            if out.is_empty() {
                total as i32
            } else {
                total.min(out.len()) as i32
            }
        }
        // `arg` out `[addr u64][size u32]`: the calling module's arena.
        ARENA_GET => {
            let (ptr, size) = scheduler::arena_get();
            let Some(out) = arg.get_mut(..12) else {
                return E_INVAL;
            };
            out[0..8].copy_from_slice(&(ptr as usize as u64).to_le_bytes());
            out[8..12].copy_from_slice(&size.to_le_bytes());
            0
        }
        REPORT_LATENCY => match arg_u32(arg) {
            Some(frames) => {
                scheduler::report_module_latency(scheduler::current_module_index(), frames);
                0
            }
            None => E_INVAL,
        },
        // Work signal: one byte of StepEffect. Heats the adaptive pacer
        // for WorkDone/RunnableBacklog/Burst; never authorises re-step.
        REPORT_STEP_EFFECT => match arg.first() {
            Some(&effect) => {
                scheduler::report_step_effect(scheduler::current_module_index(), effect);
                0
            }
            None => E_INVAL,
        },
        // `handle` = the level, `data` = the message.
        LOG_WRITE => {
            log_write(handle as u8, data.as_slice());
            0
        }
        // Binary-safe raw write of `data` to the debug serial sink (the
        // transport_buffer telemetry path). Returns bytes accepted.
        SERIAL_WRITE => {
            if data.is_empty() {
                return 0;
            }
            crate::kernel::sys::hal::serial_write(data.as_slice()) as i32
        }
        GET_HW_ETHERNET_MAC => {
            #[cfg(feature = "dtb")]
            {
                match crate::kernel::boot::dtb::read_ethernet_mac() {
                    Some(mac) => match answer(arg, &mac) {
                        Ok(()) => 6,
                        Err(e) => e,
                    },
                    None => errno::ENODEV,
                }
            }
            #[cfg(not(feature = "dtb"))]
            {
                let _ = arg;
                errno::ENODEV
            }
        }
        HANDLE_POLL => {
            let events = arg.first().copied().unwrap_or(0xFF);
            crate::kernel::ipc::handle::fd_poll(handle, events)
        }
        // `data` = the bytes to fill, all of them or none.
        RANDOM_FILL => {
            let out = data.as_mut();
            if out.is_empty() {
                return E_INVAL;
            }
            hal::csprng_fill(out)
        }
        INTERRUPT_METRICS => crate::kernel::exec::interrupt::interrupt_metrics_dispatch(arg),
        _ => E_NOSYS,
    }
}

/// The `[module_idx:u16 LE]` that leads a reconfigure or monitor argument.
/// `None` when the argument is too short to hold one.
fn module_arg(arg: &[u8]) -> Option<usize> {
    match *arg {
        [a, b, ..] => Some(usize::from(u16::from_le_bytes([a, b]))),
        _ => None,
    }
}

fn handle_reconfigure_op(opcode: u32, arg: &mut [u8]) -> i32 {
    use crate::abi::internal::reconfigure;
    use crate::kernel::exec::scheduler;
    match opcode {
        reconfigure::SET_PHASE => {
            let phase = match arg.first() {
                Some(0) => scheduler::ReconfigurePhase::Running,
                Some(1) => scheduler::ReconfigurePhase::Draining,
                _ => return E_INVAL,
            };
            scheduler::set_reconfigure_phase(phase);
            0
        }
        reconfigure::CALL_DRAIN => match module_arg(arg) {
            Some(idx) => scheduler::call_module_drain(idx),
            None => E_INVAL,
        },
        reconfigure::MARK_FINISHED => match module_arg(arg) {
            Some(idx) => {
                scheduler::mark_module_finished(idx);
                0
            }
            None => E_INVAL,
        },
        reconfigure::MODULE_COUNT => scheduler::active_module_count() as i32,
        reconfigure::MODULE_INFO => match module_arg(arg) {
            Some(idx) => scheduler::module_info_flags(idx) as i32,
            None => E_INVAL,
        },
        reconfigure::MODULE_UPSTREAM => {
            // Arg layout: in `[module_idx:u16 LE][first_word:u16 LE]`, out
            // `[mask word u64 LE × W]` from offset 4, starting at mask word
            // `first_word`. The kernel writes
            // `W = min(total - first_word, (arg_len - 4) / 8)` words and
            // returns `total` (`MODULE_MASK_WORDS`), so a caller reads the
            // mask in windows sized to its own buffer and never needs the
            // kernel's slot count compiled in. `arg_len >= 12` (index, first
            // word, one word).
            if arg.len() < 12 {
                return E_INVAL;
            }
            let Some(idx) = module_arg(arg) else {
                return E_INVAL;
            };
            let first = usize::from(u16::from_le_bytes([arg[2], arg[3]]));
            let mut words = [0u64; crate::kernel::workload::bitmask::MODULE_MASK_WORDS];
            let total = scheduler::module_upstream_words(idx, &mut words);
            let window = words.iter().skip(first).take(total.saturating_sub(first));
            for (chunk, word) in arg[4..].chunks_exact_mut(8).zip(window) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            total as i32
        }
        reconfigure::MODULE_DONE => match module_arg(arg) {
            Some(idx) => i32::from(scheduler::module_is_finished(idx)),
            None => E_INVAL,
        },
        // The boot plan's module-slot ceiling (derived + live-add reserve): a
        // fixed figure for the graph's life, where the committed slot count
        // grows under live adds.
        reconfigure::SLOT_CAPACITY => (crate::kernel::sys::resource_ledger::ceiling(
            crate::abi::contracts::resource::POOL_MODULE_SLOTS,
        ) as usize)
            .min(crate::kernel::exec::scheduler::MAX_MODULES)
            as i32,
        _ => E_NOSYS,
    }
}

fn handle_fault_monitor_op(handle: i32, opcode: u32, arg: &mut [u8]) -> i32 {
    use crate::abi::internal::monitor;
    use crate::kernel::exec::scheduler;
    match opcode {
        monitor::FAULT_MONITOR_SUBSCRIBE => {
            // `handle` = an event the caller owns, signalled on each fault,
            // or -1 to poll.
            if handle >= 0 && !crate::kernel::ipc::event::owned_by_caller(handle) {
                return errno::EBADF;
            }
            crate::kernel::exec::step_guard::subscribe(handle)
        }
        monitor::FAULT_MONITOR_POP => {
            use crate::kernel::exec::step_guard::FaultRecord;
            let Some(out) = arg.get_mut(..FaultRecord::SIZE) else {
                return E_INVAL;
            };
            let mut rec = FaultRecord::default();
            let got = crate::kernel::exec::step_guard::pop_fault(&mut rec);
            if got == 1 {
                out.copy_from_slice(&rec.to_bytes());
            }
            got
        }
        // `handle` = the module index.
        monitor::FAULT_STATS_QUERY => {
            use crate::kernel::exec::step_guard::FaultStats;
            if handle < 0 || handle as usize >= scheduler::module_slots() {
                return E_INVAL;
            }
            let stats: [u8; FaultStats::SIZE] =
                scheduler::get_fault_stats(handle as usize).to_bytes();
            match answer(arg, &stats) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        monitor::FAULT_RAISE => {
            let (Some(idx), Some(&kind)) = (module_arg(arg), arg.get(2)) else {
                return E_INVAL;
            };
            scheduler::raise_module_fault(idx, kind);
            0
        }
        // `handle` = the module index, or -1 for the whole graph.
        monitor::STEP_HISTOGRAM_QUERY => {
            let idx = if handle < 0 {
                usize::MAX
            } else {
                handle as usize
            };
            scheduler::query_step_histogram(idx, arg)
        }
        monitor::MODULE_STATE_QUERY => {
            if handle < 0 {
                return E_INVAL;
            }
            scheduler::query_module_state(handle as usize, arg)
        }
        _ => E_NOSYS,
    }
}

fn handle_diag_op(opcode: u32, mut data: UserSpan<'_>) -> i32 {
    use crate::abi::internal::diag;
    match opcode {
        diag::LOG_RING_DRAIN => {
            let out = data.as_mut();
            if out.is_empty() {
                return E_INVAL;
            }
            // Low 16 bits = payload length, next 15 bits = dropped count
            // (saturating). Top bit is kept clear so the return is always
            // a non-negative `i32`.
            let n = crate::kernel::sys::log_ring::drain_net(out);
            let dropped = crate::kernel::sys::log_ring::take_dropped_net();
            let dropped_sat = if dropped > 0x7FFF { 0x7FFF } else { dropped };
            ((dropped_sat << 16) | (n as u32 & 0xFFFF)) as i32
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// Device Query
// ============================================================================

/// Answer `query_key::LAST_FENCE` for any handle whose contract
/// implements `contracts::fence::QUERY_OP` in its dispatch.
///
/// Routes through `provider::provider_call` so the contract's
/// vtable resolves from the handle's FD tag and strips the tag
/// before the provider sees the slot. Handle=-1 and untracked
/// handles return `E_NOSYS`; one-shot ops without a handle (object
/// `PUT`, namespace `RENAME`, …) carry their fence in the `arg`
/// trailer instead — see the storage contract files.
fn last_fence_query(handle: i32, out: &mut [u8]) -> i32 {
    use crate::abi::fence::{QUERY_OP, WIRE_MAX_LEN};

    if out.len() < WIRE_MAX_LEN {
        return E_INVAL;
    }
    if crate::kernel::module::provider::contract_of(handle).is_none() {
        return E_NOSYS;
    }
    crate::kernel::module::provider::provider_call(handle, QUERY_OP, out, UserSpan::empty())
}

/// Write a 4-byte LE answer at the head of `out`.
fn query_u32(out: &mut [u8], v: u32) -> i32 {
    match answer(out, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Write a record at the head of `out` and answer its length.
fn query_record(out: &mut [u8], record: &[u8]) -> i32 {
    match answer(out, record) {
        Ok(()) => record.len() as i32,
        Err(e) => e,
    }
}

/// Kernel-side cross-class query dispatcher.
///
/// Fallback path invoked by `syscall_provider_query` when the handle's
/// contract vtable doesn't claim the key. Handles:
///  - cross-class common keys (`query_key::*`) applicable to any handle
///  - SYSTEM-contract introspection (ARENA_USAGE, GRAPH_SAMPLE_RATE, …)
fn kernel_query_dispatch(handle: i32, key: u32, out: &mut [u8]) -> i32 {
    use crate::abi::kernel_abi::query_key as dev_query_key;
    use crate::kernel::exec::scheduler;
    match key {
        dev_query_key::CLASS => {
            let Some(class) = crate::kernel::module::provider::contract_of(handle) else {
                return E_INVAL;
            };
            match answer(out, &[class as u8]) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        dev_query_key::HEAP_STATS => {
            // The record is one length (`abi::heap_stats::LEN`); a
            // buffer of any other is a caller reading another layout.
            use crate::abi::heap_stats::LEN;
            if out.len() != LEN {
                return E_INVAL;
            }
            let idx = scheduler::current_module_index();
            query_record(out, &crate::kernel::mem::heap::heap_stats(idx).encode())
        }
        dev_query_key::LAST_FENCE => last_fence_query(handle, out),
        dev_query_key::CALLER_OWNER => {
            // A buffer that cannot hold the record is a malformed call,
            // whatever the provider stack holds.
            if out.len() < 8 {
                return E_INVAL;
            }
            let caller = scheduler::caller_module_index();
            // Nothing on the provider stack means this module is stepping
            // its own work, not serving a request. Answering with an
            // owner here would let a provider charge background work to
            // whoever called it last, which is worse than no answer.
            if caller >= scheduler::module_slots() {
                return errno::ESRCH;
            }
            // The same encoder the `OWNER_RELEASED` notification uses, so
            // a provider can compare the two records directly.
            let owner = scheduler::module_owner(caller);
            query_record(
                out,
                &crate::kernel::module::provider::encode_owner_record(owner),
            )
        }
        dev_query_key::CALLER_MODULE => {
            // A buffer that cannot hold the record is a malformed call,
            // whatever the provider stack holds.
            if out.len() < 8 {
                return E_INVAL;
            }
            let caller = scheduler::caller_module_index();
            // As CALLER_OWNER: nobody is calling when nothing is on the
            // provider stack.
            if caller >= scheduler::module_slots() {
                return errno::ESRCH;
            }
            let gen = scheduler::module_slot_generation(caller);
            query_record(out, &module_record(caller as u16, gen))
        }
        // `out` holds the occupancy to test on entry.
        dev_query_key::MODULE_LIVE => {
            let Some(rec) = out.get(..8) else {
                return E_INVAL;
            };
            let idx = u16::from_le_bytes([rec[0], rec[1]]) as usize;
            let gen = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
            let live = idx < scheduler::module_slots()
                && scheduler::module_slot_generation(idx) == gen
                && !scheduler::module_is_finished(idx);
            i32::from(live)
        }
        crate::abi::kernel_abi::STREAM_TIME => {
            // STREAM_TIME: prefer a dedicated STREAM_CLOCK provider
            // (hosts register one — the audio sink's clock — without
            // any PIO hardware). If none is registered (bare-metal RP),
            // fall back to the active PIO stream's own time: on RP the
            // clock genuinely is a property of the PIO stream. handle=-1
            // resolves to the first active stream (see
            // `kernel_abi::STREAM_TIME`).
            use crate::abi::registry::pio::STREAM_TIME as PIO_STREAM_TIME;
            use crate::abi::registry::stream_clock::QUERY as STREAM_CLOCK_QUERY;
            use crate::kernel::module::provider;
            let rc = provider::dispatch(
                provider::contract::STREAM_CLOCK,
                handle,
                STREAM_CLOCK_QUERY,
                out,
                UserSpan::empty(),
            );
            if rc == E_NOSYS {
                provider::dispatch(
                    provider::contract::HAL_PIO,
                    handle,
                    PIO_STREAM_TIME,
                    out,
                    UserSpan::empty(),
                )
            } else {
                rc
            }
        }
        crate::abi::internal::monitor::ARENA_USAGE => {
            let (used, total) = crate::kernel::module::loader::arena_usage();
            query_u32(out, ((used as u32) << 16) | (total as u32 & 0xFFFF))
        }
        crate::abi::kernel_abi::GRAPH_SAMPLE_RATE => query_u32(out, scheduler::graph_sample_rate()),
        crate::abi::kernel_abi::DOWNSTREAM_LATENCY => {
            let idx = scheduler::current_module_index();
            query_u32(out, scheduler::downstream_latency(idx))
        }
        _ => match dev_query_extension() {
            Some(ext) => ext(handle, key, out),
            None => E_NOSYS,
        },
    }
}

// ============================================================================
// Syscall Table Stubs (for `empty_syscall_table`)
// ============================================================================

/// The table before boot installs the real one: every entry refuses.
pub const fn empty_syscall_table() -> SyscallTable {
    SyscallTable {
        version: ABI_VERSION,
        telemetry_enabled: core::ptr::null(),
        channel_read: stub_channel_read,
        channel_write: stub_channel_write,
        channel_poll: stub_channel_poll,
        heap_alloc: stub_heap_alloc,
        heap_free: stub_heap_free,
        heap_realloc: stub_heap_realloc,
        provider_open: stub_provider_open,
        provider_call: stub_provider_call,
        provider_query: stub_provider_query,
        provider_close: stub_provider_close,
        channel_peek: stub_channel_peek,
        channel_discard: stub_channel_discard,
    }
}

unsafe extern "C" fn stub_channel_peek(_handle: i32, _buf: *mut u8, _len: usize) -> i32 {
    -1
}

unsafe extern "C" fn stub_channel_discard(_handle: i32, _len: usize) -> i32 {
    -1
}

// ============================================================================
// Handle Ownership Cleanup
// ============================================================================

/// Release all hardware handles owned by a module.
/// Called when a module finishes (done or error) to prevent resource leaks.
pub fn release_module_handles(module_idx: ModuleId) {
    // Release platform-specific handles (GPIO, DMA FDs, etc.)
    hal::release_platform_handles(module_idx);
    // Release events
    crate::kernel::ipc::event::release_owned_by(module_idx);
    // Release fd-based timers
    crate::kernel::ipc::timer::release_timers_owned_by(module_idx);
    // Release module provider registrations
    crate::kernel::module::provider::release_module_providers(module_idx);
    // End what it borrowed (its DMA went with its platform handles above),
    // and close what it lent: a span still borrowed waits for its return,
    // and `free_module_state` quarantines the memory under it.
    crate::kernel::ipc::lend::release_module(usize::from(module_idx));
    // A mailbox record it held for writing is cancelled, one it held for
    // reading goes back unconsumed: nothing else would ever end those lends.
    crate::kernel::ipc::buffer_pool::release_lends_of(module_idx);
}

unsafe extern "C" fn stub_channel_read(_handle: i32, _buf: *mut u8, _len: usize) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_channel_write(_handle: i32, _data: *const u8, _len: usize) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_channel_poll(_handle: i32, _events: u32) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_heap_alloc(_size: u32) -> *mut u8 {
    null_mut()
}
unsafe extern "C" fn stub_heap_free(_ptr: *mut u8) {}
unsafe extern "C" fn stub_heap_realloc(_ptr: *mut u8, _new_size: u32) -> *mut u8 {
    null_mut()
}
unsafe extern "C" fn stub_provider_open(
    _contract: u32,
    _op: u32,
    _config: *const u8,
    _config_len: usize,
) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_provider_call(
    _handle: i32,
    _op: u32,
    _arg: *mut u8,
    _arg_len: usize,
    _data: *mut u8,
    _data_len: usize,
) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_provider_query(
    _handle: i32,
    _key: u32,
    _out: *mut u8,
    _out_len: usize,
) -> i32 {
    E_NOSYS
}
unsafe extern "C" fn stub_provider_close(_handle: i32) -> i32 {
    E_NOSYS
}

// ============================================================================
// Heap Syscall Implementations
// ============================================================================

/// Allocate from the calling module's heap.
///
/// interrupt-mode modules are forbidden from heap operations.
/// The gate fires here (at the syscall boundary) rather than in
/// `heap::heap_alloc` itself because kernel-internal heap callers
/// must keep working — only the module-facing path is gated.
unsafe extern "C" fn syscall_heap_alloc(size: u32) -> *mut u8 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("heap_alloc") {
        return core::ptr::null_mut();
    }
    // Admission gate: heap growth is new allocation. Frees (and
    // in-place use of existing allocations) stay state-blind.
    if admission_closed("heap_alloc") {
        return core::ptr::null_mut();
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_alloc(idx, size as usize)
}

/// Free a previous allocation from the calling module's heap.
unsafe extern "C" fn syscall_heap_free(ptr: *mut u8) {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("heap_free") {
        return;
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_free(idx, ptr)
}

/// Reallocate from the calling module's heap.
unsafe extern "C" fn syscall_heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    if crate::kernel::exec::scheduler::deny_interrupt_mode_syscall("heap_realloc") {
        return core::ptr::null_mut();
    }
    // Admission gate: realloc can grow — new allocation.
    if admission_closed("heap_realloc") {
        return core::ptr::null_mut();
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_realloc(idx, ptr, new_size as usize)
}

// RP platform providers are registered via HAL (init_providers / release_module_handles);
// rp/providers.rs is included from the RP platform entrypoint.
//
// The cap-class grant policy (`CAP_CONTRACT_MASK`) is pinned by an out-of-tree
// test — `service_contracts_admit_storage_family_like_fs` in
// `tests/harness/tests/kernel_permissions.rs` — so production `src/` stays
// inline-test-free.
