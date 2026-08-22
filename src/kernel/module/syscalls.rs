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
use crate::kernel::ipc::channel;
use crate::kernel::sys::errno;
use crate::kernel::sys::hal;
// ============================================================================
// Error Codes (Linux errno values)
// ============================================================================

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
const E_NOMEM: i32 = errno::ENOMEM;

// ============================================================================
// Syscall Table
// ============================================================================

static mut SYSCALL_TABLE: SyscallTable = SyscallTable::empty();

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
        channel_peek: syscall_channel_peek,
        provider_call_sel: syscall_provider_call_sel,
    });
}

unsafe extern "C" fn syscall_channel_peek(handle: i32, buf: *mut u8, len: usize) -> i32 {
    // ISR-tier gate at the syscall-wrapper boundary (matches the
    // pattern below for provider_*). The inner `channel::channel_peek`
    // also gates as defense in depth, but firing here means the
    // module sees `EACCES` rather than any later validation error.
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("channel_peek") {
        return crate::kernel::sys::errno::EACCES;
    }
    channel::channel_peek(handle, buf, len)
}

// ── Handle-scoped provider dispatch ─────────────────────────────────
//
// Every `syscall_provider_*` wrapper fires the ISR-tier gate as its
// FIRST check — BEFORE the contract-grant lookup, the
// privileged-op gate, or the contract dispatch. Without this
// ordering, an ISR-tier module calling `provider_open` on a
// contract it has no permission for would receive `ENOSYS` (the
// permission gate's reject) rather than `EACCES` (the §D7 ISR
// gate's reject), and a future loader bug could ride that path
// silently. The inner `provider::*` functions also gate as
// defense in depth.

unsafe extern "C" fn syscall_provider_open(
    contract: u32,
    open_op: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_open") {
        return crate::kernel::sys::errno::EACCES;
    }
    // INTERNAL_DISPATCH_BUCKET (0x000C) is kernel-internal only — module
    // code must use the public platform contracts (PLATFORM_NIC_RING,
    // PLATFORM_DMA, PLATFORM_DMA_FD) for handle-returning platform ops.
    if contract as u16 == crate::kernel::module::provider::contract::INTERNAL_DISPATCH_BUCKET {
        log::warn!(
            "[cap] module called provider_open on INTERNAL_DISPATCH_BUCKET; \
             use PLATFORM_NIC_RING / PLATFORM_DMA / PLATFORM_DMA_FD instead"
        );
        return E_NOSYS;
    }
    if let Some(rc) = check_contract_grant(contract as u16) {
        return rc;
    }
    // Open-style ops can also touch privileged orchestration surface
    // (NIC_RING_CREATE, DMA_FD_CREATE, etc.), so the permission gate
    // applies here as well as in `provider_call`.
    if let Some(rc) = check_privileged_internal_op(open_op) {
        return rc;
    }
    // Every provider_open mints a new held resource — §3.5 admission.
    if admission_closed("provider_open") {
        return crate::kernel::sys::errno::EACCES;
    }
    crate::kernel::module::provider::provider_open(contract as u16, open_op, config, config_len)
}

unsafe extern "C" fn syscall_provider_call(
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // ISR-tier (Tier 1b/2) modules are denied `provider_call` in general
    // (RFC §D6/§D7), but the bridge ops and the `SELF_BRIDGES` enumeration are
    // exempt: their underlying ring operations are lock-free and
    // allocation-free, so they are the *sanctioned* I/O path for an ISR-tier
    // step body (RFC rfc_isr_tier_surface "ISR-tier I/O contract").
    if !crate::abi::internal::bridge::is_isr_safe(op)
        && crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_call")
    {
        return crate::kernel::sys::errno::EACCES;
    }
    // Contract comes from the handle's FD tag (tagged fds resolve
    // directly via `fd_tag_contract`), falling back to the opcode's
    // class byte for handle=-1 globals and scheduler-assigned channel
    // fds. Non-channel contracts hand out tagged fds so `contract_of`
    // produces an unambiguous result per handle.
    let contract =
        crate::kernel::module::provider::contract_of(handle).unwrap_or(((op >> 8) & 0xFF) as u16);
    if let Some(rc) = check_contract_grant(contract) {
        return rc;
    }
    // Privileged 0x0Cxx opcodes also require the matching permission bit.
    if let Some(rc) = check_privileged_internal_op(op) {
        return rc;
    }
    // §3.5 admission gate on the open/create/accept/arm-class opcodes —
    // use-style ops on established handles stay state-blind so a
    // draining owner can flush in-flight work.
    if admission_class_op(op) && admission_closed("provider_call") {
        return crate::kernel::sys::errno::EACCES;
    }
    crate::kernel::module::provider::provider_call(handle, op, arg, arg_len)
}

unsafe extern "C" fn syscall_provider_call_sel(
    sel: *const u8,
    sel_len: usize,
    op_handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if !crate::abi::internal::bridge::is_isr_safe(op)
        && crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_call_sel")
    {
        return crate::kernel::sys::errno::EACCES;
    }
    // The contract is the opcode's class byte (same rule as the handle=-1
    // path); grant-check the caller against it, then apply the same
    // open-class admission gate `provider_call` uses.
    let c = ((op >> 8) & 0xFF) as u16;
    if let Some(rc) = check_contract_grant(c) {
        return rc;
    }
    if admission_class_op(op) && admission_closed("provider_call_sel") {
        return crate::kernel::sys::errno::EACCES;
    }
    // SAFETY: same arg-validity contract as `provider_call`; `sel[..sel_len]`
    // validity is the module's responsibility.
    unsafe {
        crate::kernel::module::provider::provider_call_sel(
            sel, sel_len, op_handle, op, arg, arg_len,
        )
    }
}

unsafe extern "C" fn syscall_provider_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_query") {
        return crate::kernel::sys::errno::EACCES;
    }
    let contract =
        crate::kernel::module::provider::contract_of(handle).unwrap_or(((key >> 8) & 0xFF) as u16);
    if let Some(rc) = check_contract_grant(contract) {
        return rc;
    }
    // Queries against privileged 0x0Cxx keys require the same permission
    // bit as `provider_call` for those opcodes.
    if let Some(rc) = check_privileged_internal_op(key) {
        return rc;
    }
    // Try the handle's vtable first; if no contract query is registered,
    // fall back to the built-in cross-class query dispatcher.
    let vt_rc = crate::kernel::module::provider::provider_query(handle, key, out, out_len);
    if vt_rc != E_NOSYS {
        return vt_rc;
    }
    kernel_query_dispatch(handle, key, out, out_len)
}

unsafe extern "C" fn syscall_provider_close(handle: i32) -> i32 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("provider_close") {
        return crate::kernel::sys::errno::EACCES;
    }
    if let Some(contract) = crate::kernel::module::provider::contract_of(handle) {
        if let Some(rc) = check_contract_grant(contract) {
            return rc;
        }
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
// Capability-Filtered Syscall Tables
// ============================================================================

/// Get the syscall table for a given module type.
///
/// All modules get the same table; per-contract capability enforcement
/// happens at `provider_*` dispatch time (see `check_contract_grant`).
pub fn get_table_for_module_type(_module_type: u8) -> &'static SyscallTable {
    syscall_table()
}

// ============================================================================
// Logging
// ============================================================================

unsafe extern "C" fn syscall_log(level: u8, msg: *const u8, len: usize) {
    if msg.is_null() || len == 0 {
        return;
    }
    let slice = core::slice::from_raw_parts(msg, len);
    if let Ok(s) = core::str::from_utf8(slice) {
        match level {
            1 => log::error!("{s}"),
            2 => log::warn!("{s}"),
            3 => log::info!("{s}"),
            4 => log::debug!("{s}"),
            _ => log::trace!("{s}"),
        }
    }
}

/// Channel port discovery syscall - returns channel handle for a given port.
/// Delegates to the scheduler which tracks per-module port assignments.
unsafe extern "C" fn syscall_channel_port(port_type: u8, index: u8) -> i32 {
    crate::kernel::exec::scheduler::channel_port_lookup(port_type, index)
}

// ============================================================================
// Channel Wrappers
// ============================================================================

/// Admission gate (rfc_owner_drain_and_logs.md §3.5): true when the calling
/// module's owner may NOT admit new work. Admission closes the moment a drain
/// begins; existing-handle use stays state-blind (`authorize_use` semantics),
/// which is what lets in-flight work run dry. System-owned modules always
/// pass. Every module-facing create/open/accept/allocate/arm path consults
/// this — the §3.5 checklist: provider open/bind, `channel_open`, open-style
/// `provider_call` ops (`admission_class_op`), event create, heap
/// allocation, timer arm.
fn admission_closed(surface: &'static str) -> bool {
    let owner = crate::kernel::exec::scheduler::module_owner(
        crate::kernel::exec::scheduler::current_module_index(),
    );
    if owner.is_system() {
        return false;
    }
    if crate::kernel::exec::scheduler::owners_mut().authorize_admit(owner) {
        return false;
    }
    log::warn!("[owner] {surface} refused: admission closed (owner draining/revoked)");
    true
}

/// Open-style / arm-style `provider_call` opcodes that CREATE new work or
/// resources and therefore fall under the §3.5 admission gate. Use-style ops
/// on established handles (read/write/poll/fsync/close/cancel/destroy/
/// buffer-acquire on open channels) are deliberately absent: a draining
/// owner must still flush in-flight work to completion.
fn admission_class_op(op: u32) -> bool {
    use crate::abi::contracts::storage::fs;
    use crate::abi::kernel_abi::{channel, event, timer};
    matches!(
        op,
        // New channels / endpoints (accept = new connection admission).
        channel::OPEN | channel::CONNECT | channel::BIND | channel::LISTEN | channel::ACCEPT
        // Timer create + arm: cancelling timers plus this gate is the
        // operational definition of "autonomous producers stop" (§3.5).
        | timer::CREATE | timer::SET
        // New wake sources.
        | event::CREATE | event::BIND_IRQ
        // Filesystem opens (read tier and write tier — both admit a new
        // held resource; established fds keep working).
        | fs::OPEN | fs::OPENDIR | fs::OPEN_CREATE
    )
}

pub fn channel_open(chan_type: u8, config: *const u8, config_len: usize) -> i32 {
    if admission_closed("channel_open") {
        return -1;
    }
    channel::syscall_channel_open(chan_type, config, config_len)
}

pub fn channel_close(handle: i32) {
    channel::syscall_channel_close(handle)
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
    provider::register(dev_class::BUFFER, buffer_provider_dispatch);
    // KEY_VAULT: the kernel software backend is the *default* a platform
    // may override (rfc_crypto_extensions §4.1). Unlike FS, KEY_VAULT is
    // registered here in kernel core on BOTH paths — this class-byte
    // dispatch and the KEY_VAULT_VTABLE below — so a hardware platform
    // (e.g. the Linux PKCS#11 backend) must re-register BOTH at platform
    // boot: `register` and `register_vtable` overwrite, and
    // `hal::init_providers()` runs after these defaults, so a platform
    // override wins. Overriding only one path would split custody
    // between two backends. When no hardware is present the software
    // backend stays live; consumers never name a platform — they read
    // PROBE/CAPS/TIER.
    provider::register(dev_class::KEY_VAULT, key_vault_provider_dispatch);

    // Handle-scoped vtables for the kernel-owned contracts. Tracked
    // handles route through the vtable; handle=-1 globals fall through
    // to the class-byte dispatch registered above. Both paths converge
    // on the same dispatch functions.
    provider::register_vtable(&CHANNEL_VTABLE);
    provider::register_vtable(&TIMER_VTABLE);
    provider::register_vtable(&EVENT_VTABLE);
    provider::register_vtable(&BUFFER_VTABLE);
    provider::register_vtable(&KEY_VAULT_VTABLE);
    provider::register_vtable(&FS_VTABLE);
    provider::register_vtable(&STORAGE_NAMESPACE_VTABLE);
    provider::register_vtable(&STORAGE_OBJECT_VTABLE);
    provider::register_vtable(&PCIE_DEVICE_VTABLE);

    // HAL vtables for contracts whose `call` dispatch is supplied by a
    // PIC module (registered by the loader via `module_provides_contract`).
    // The vtable's `call` routes through the kernel's class-byte dispatch
    // chain so it picks up whatever provider is registered at call time.
    // Consumer modules with tracked handles dispatch through the vtable;
    // handle=-1 global opens fall through the same chain.
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
    };

static TIMER_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::TIMER,
        call: timer_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::timer::DESTROY,
    };

static EVENT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::EVENT,
        call: event_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::event::DESTROY,
    };

static BUFFER_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::BUFFER,
        call: buffer_provider_dispatch,
        query: None,
        default_close_op: 0, // buffers released by explicit RELEASE opcodes
    };

// Default (software-backend) KEY_VAULT vtable. A hardware platform
// overriding KEY_VAULT registers its own vtable with the same
// `default_close_op` alongside its class dispatch — see the note at
// the class registration in `init_providers`.
static KEY_VAULT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::KEY_VAULT,
        call: key_vault_provider_dispatch,
        query: None,
        default_close_op: contracts::key_vault::DESTROY,
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
    };

// FS contract has no built-in kernel implementation — a PIC filesystem
// module (fat32, …) or a host-side platform dispatcher (linux_fs_dispatch)
// registers as the provider. The vtable's `call` routes through the
// class-byte dispatch chain so it picks up whichever provider is
// registered, same shape as the HAL vtables.
unsafe fn fs_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    // PIC module providers register on a class byte and operate on
    // raw slots; strip any FD tag before dispatching inward.
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::FS, h, op, arg, arg_len)
}

static FS_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::FS,
        call: fs_call,
        query: None,
        default_close_op: contracts::storage::fs::CLOSE,
    };

// STORAGE_NAMESPACE / STORAGE_OBJECT vtables. Same shape as FS: the
// kernel ships no built-in provider; a PIC module (loam, clustor,
// the s3-adapter) registers via `module_provides_contract` and is
// routed through the class-byte dispatch chain. The vtable carries
// `default_close_op` so `provider_close` releases tracked handles
// uniformly.

unsafe fn storage_namespace_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::STORAGE_NAMESPACE, h, op, arg, arg_len)
}

static STORAGE_NAMESPACE_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::STORAGE_NAMESPACE,
        call: storage_namespace_call,
        query: None,
        default_close_op: contracts::storage::namespace::CLOSE,
    };

unsafe fn storage_object_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::STORAGE_OBJECT, h, op, arg, arg_len)
}

static STORAGE_OBJECT_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::STORAGE_OBJECT,
        call: storage_object_call,
        query: None,
        default_close_op: contracts::storage::object::CLOSE,
    };

// HAL contracts whose `call` dispatch is a PIC module provider. The
// vtable's `call` forwards to `provider::dispatch` with the right
// class byte so the existing module-chain routing applies.

unsafe fn hal_spi_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::SPI, h, op, arg, arg_len)
}

static HAL_SPI_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_SPI,
        call: hal_spi_call,
        query: None,
        default_close_op: contracts::hal::spi::CLOSE,
    };

unsafe fn hal_i2c_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::I2C, h, op, arg, arg_len)
}

static HAL_I2C_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_I2C,
        call: hal_i2c_call,
        query: None,
        default_close_op: contracts::hal::i2c::CLOSE,
    };

unsafe fn hal_pio_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::PIO, h, op, arg, arg_len)
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
    };

unsafe fn hal_uart_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::UART, h, op, arg, arg_len)
}

static HAL_UART_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_UART,
        call: hal_uart_call,
        query: None,
        default_close_op: contracts::hal::uart::CLOSE,
    };

unsafe fn hal_adc_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::ADC, h, op, arg, arg_len)
}

static HAL_ADC_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_ADC,
        call: hal_adc_call,
        query: None,
        default_close_op: contracts::hal::adc::CLOSE,
    };

unsafe fn hal_pwm_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::module::provider::contract as class;
    let h = if handle >= 0 {
        crate::kernel::ipc::fd::slot_of(handle)
    } else {
        handle
    };
    crate::kernel::module::provider::dispatch(class::PWM, h, op, arg, arg_len)
}

static HAL_PWM_VTABLE: crate::kernel::module::provider::ProviderVTable =
    crate::kernel::module::provider::ProviderVTable {
        contract: crate::kernel::module::provider::contract::HAL_PWM,
        call: hal_pwm_call,
        query: None,
        default_close_op: contracts::hal::pwm::CLOSE,
    };

/// KEY_VAULT provider adapter — forwards to the kernel key_vault module.
unsafe fn key_vault_provider_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    crate::kernel::security::key_vault::provider_dispatch(handle, opcode, arg, arg_len)
}

// ============================================================================
// Generic Device Call / Query
// ============================================================================

/// Generic device call — dispatches to per-class implementations via opcode.
///
/// The opcode's upper byte identifies the device class, the lower byte
/// Per-contract capability enforcement.
///
/// Returns `Some(E_NOSYS)` when the calling module is not permitted to
/// touch `contract`, or `None` when the call may proceed. Applies to
/// both routing paths: the handle-scoped `provider_*` path (contract
/// id carried by the handle or passed to `provider_open`), and the
/// class-byte path for handle=-1 global ops (contract id from the
/// opcode's high byte).
///
/// Two layers:
///
/// 1. **Tier mask**: every module is assigned a capability tier
///    (`current_module_cap_class`). Each tier's bitmask declares which
///    contracts that tier may reach. Service tiers (0..=2) expose
///    infra contracts + key vault; the GPIO / PIO variants add one
///    HAL contract each; `CAP_FULL` opens everything.
///
/// 2. **Manifest mask**: the contract must be either on the infra
///    allow-list (below) or in the module's declared `required_caps`
///    set. Modules that declare nothing get nothing beyond infra +
///    whatever the tier mask opens.
// Storage family: a service-tier module may reach the storage contracts
// on the same footing as FS (already in the masks below) when — and only
// when — it declares them in `[[resources]]` (the manifest gate in
// `check_contract_grant` remains authoritative). This lets a service-tier
// backend (e.g. an emulator asset bank, RFC 0009) resolve an object
// handle via `storage.object`/`storage.namespace` without being
// mis-typed as a CAP_FULL `Protocol` module just to get the grant.
// STORAGE_NAMESPACE = 0x13, STORAGE_OBJECT = 0x14 — both read-only.
const STORAGE_FAMILY: u64 = (1u64
    << crate::kernel::module::provider::contract::STORAGE_NAMESPACE as u64)
    | (1u64 << crate::kernel::module::provider::contract::STORAGE_OBJECT as u64);

/// Per-cap-class contract ceiling. Indexed by
/// `scheduler::current_module_cap_class()`. Bits 7 / 8 / 17 / 18 / 21
/// (PLATFORM_NIC_RING, PLATFORM_DMA, PLATFORM_DMA_FD, PCIE_DEVICE,
/// USB_HOST) are permitted at every service tier so a driver's
/// `[[resources]]` declaration is what actually grants access; the
/// `platform_raw` permission then gates the individual opcodes on top.
/// USB_HOST is a scaffold — the bit is reserved so a future driver
/// landing only needs to register handlers, not amend this mask. This is
/// a ceiling, NOT a grant: `check_contract_grant`'s manifest gate still
/// requires each non-infra contract to be declared.
///
/// `pub` so the cap-class policy can be pinned by an out-of-tree harness
/// test (`tests/harness/tests/kernel_permissions.rs`) — production `src/`
/// keeps no inline tests (enforced by `tools/tests/src_shape_no_inline_tests`).
/// PROC (0x16, bit 22) — the host process-executor contract. Added to the service-tier
/// ceilings so an app/Source/Transformer module (e.g. sector's `do`) CAN declare it; this
/// is a ceiling only, the manifest `[[resources]]` gate still grants per-module.
const PROC_CONTRACT: u64 = 1u64 << 0x16;
/// WORKLOAD (0x1A, bit 26) — the platform-neutral isolated-workload surface,
/// the sole host-isolation contract. Service-tier ceiling so a node module (the workload manager) CAN declare
/// it; the manifest `[[resources]]` gate still grants per-module, AND every
/// 0x1Axx op additionally requires the `platform_raw` permission (spawning
/// isolated workloads is privileged). Ceiling only.
const WORKLOAD_CONTRACT: u64 = 1u64 << 0x1A;
pub const CAP_CONTRACT_MASK: [u64; 4] = [
    0x0027_1FE1 | STORAGE_FAMILY | PROC_CONTRACT | WORKLOAD_CONTRACT, // CAP_SERVICE: infra + FS + storage family + KEY_VAULT + PLATFORM_NIC_RING + PLATFORM_DMA + PLATFORM_DMA_FD + PCIE_DEVICE + USB_HOST + PROC + WORKLOAD
    0x0027_1FF1 | STORAGE_FAMILY | PROC_CONTRACT | WORKLOAD_CONTRACT, // CAP_SERVICE_PIO: service + HAL_PIO
    0x0027_1FE3 | STORAGE_FAMILY | PROC_CONTRACT | WORKLOAD_CONTRACT, // CAP_SERVICE_GPIO: service + HAL_GPIO
    u64::MAX,                                                         // CAP_FULL: any contract
];

unsafe fn check_contract_grant(contract: u16) -> Option<i32> {
    use crate::kernel::module::provider::contract as ct;

    // host_process (0x1B) is the workload contract's Linux host-class companion
    // (D-WORKLOAD-ABI eviction from the 0x1A surface): the READ/EXEC/TTY ops act
    // on a workload the module already created, so they carry the SAME
    // `requires_contract = "workload"` grant (see provider::contract::HOST_PROCESS).
    // Without this the opcode-class-byte gate would demand a separate 0x1B bit
    // that no manifest can declare — `tools/src/manifest.rs` has no name mapping
    // to 0x1B — so every host-process op fails ENOSYS.
    //
    // The remap covers the CONTRACT grant only. `platform_raw` is required for
    // this class by its own arm in `privileged_op_permission` (0x1B00..=0x1BFF),
    // which must stay in step with the 0x1A arm: executing a process and opening
    // a PTY on the host is not a lesser privilege than creating the workload.
    let contract = if contract == ct::HOST_PROCESS {
        ct::WORKLOAD
    } else {
        contract
    };

    // A contract id outside the representable range has no bit in either
    // ceiling below, so neither gate could test it. Refuse it here: the
    // alternative — skipping a gate whose bit does not exist — turns both
    // ceilings off for exactly the ids no policy has ever admitted. The
    // range is `MAX_CONTRACTS`, which is also the width of the header's
    // `required_caps` and of `CAP_CONTRACT_MASK`; the three are one number.
    if contract as usize >= crate::kernel::module::provider::MAX_CONTRACTS {
        return Some(E_NOSYS);
    }
    let contract_bit = 1u64 << contract;

    let cap = crate::kernel::exec::scheduler::current_module_cap_class() as usize;
    if cap < CAP_CONTRACT_MASK.len() {
        let mask = CAP_CONTRACT_MASK[cap];
        if (mask & contract_bit) == 0 {
            return Some(E_NOSYS);
        }
    }

    // Infra contracts are implicit grants — kernel services (channel,
    // timer, buffer, event, key_vault) plus the kernel-primitive 0x0Cxx
    // transport bucket (LOG_WRITE, HANDLE_POLL, RANDOM_FILL, ARENA_GET,
    // BIND_IRQ, …) are available to any module regardless of manifest.
    // Privileged 0x0Cxx opcodes (bridge, monitor, reconfigure, flash
    // raw, backing-provider registration, platform MMIO/DMA/PCIe, …)
    // are gated separately by `check_privileged_internal_op` against
    // the manifest's `permissions = [...]` bitmap. Bit 12 below is the
    // dispatch bucket for 0x0Cxx routing, not a public contract id.
    //
    // PLATFORM_NIC_RING, PLATFORM_DMA, PLATFORM_DMA_FD, and PCIE_DEVICE
    // are public contracts subject to the same declare-to-use rule as
    // HAL_* — they are NOT in this list.
    const INFRA_CONTRACTS: u64 = (1u64 << 0)              |  // COMMON / cross-class
        (1u64 << ct::CHANNEL)    |
        (1u64 << ct::TIMER)      |
        (1u64 << ct::BUFFER)     |
        (1u64 << ct::EVENT)      |
        (1u64 << 0x0C)           |  // 0x0Cxx transport bucket (implicit routing)
        (1u64 << ct::KEY_VAULT);

    // Manifest gate: every non-infra contract must be declared in the
    // module's `[[resources]]` list. Channel-only consumers and app
    // modules are unaffected because channels/timers/etc. live in
    // INFRA_CONTRACTS.
    let req = crate::kernel::exec::scheduler::current_module_required_caps();
    if (INFRA_CONTRACTS & contract_bit) == 0 && (req & contract_bit) == 0 {
        log::warn!(
            "[syscalls] module {} contract 0x{contract:04x}: manifest gate denied — staged required_caps=0x{req:016x} (returns ENOSYS; declare `[[resources]]` requires_contract for this contract, and confirm the packed .fmod header carries the bit — `fluxor inspect` shows the manifest-derived mask, not the header field)",
            crate::kernel::exec::scheduler::current_module_index(),
        );
        return Some(E_NOSYS);
    }
    None
}

/// Fine-grained permission categories. Each privileged 0x0Cxx opcode
/// maps to exactly one category; a module must carry the corresponding
/// bit in its manifest `permissions = [...]` list to reach that opcode.
///
/// Bit layout is shared with `tools/src/manifest.rs` — keep in sync.
pub mod permission {
    // 16-bit bitmap, bits 9.. free. Bit layout is shared with
    // `tools/src/manifest.rs` — keep the two in sync.
    pub const RECONFIGURE: u16 = 1 << 0;
    pub const FLASH_RAW: u16 = 1 << 1;
    pub const BACKING_PROVIDER: u16 = 1 << 2;
    pub const PLATFORM_RAW: u16 = 1 << 3;
    pub const MONITOR: u16 = 1 << 4;
    pub const BRIDGE: u16 = 1 << 5;
    /// Kernel-mediated PCIe device binding (bind/config/BAR/MSI/info on a
    /// validated device handle) — distinct from raw MMIO/DMA (`platform_raw`).
    pub const PCIE_DEVICE: u16 = 1 << 6;
    /// DMA-buffer allocation from the kernel's bounded DMA arena + the cache
    /// maintenance on those buffers — narrower than raw register poke
    /// (`platform_raw` still gates `MMIO_READ32`/`MMIO_WRITE32`).
    pub const DMA: u16 = 1 << 7;
    /// Read-only telemetry-ring drain (`TLM_SUBSCRIBE`/`DRAIN`/`STATS`). Strictly
    /// read-only — deliberately NOT `monitor`, which also grants `FAULT_RAISE`.
    pub const OBSERVE: u16 = 1 << 8;

    pub fn name(bit: u16) -> &'static str {
        match bit {
            RECONFIGURE => "reconfigure",
            FLASH_RAW => "flash_raw",
            BACKING_PROVIDER => "backing_provider",
            PLATFORM_RAW => "platform_raw",
            MONITOR => "monitor",
            BRIDGE => "bridge",
            PCIE_DEVICE => "pcie_device",
            DMA => "dma",
            OBSERVE => "observe",
            _ => "<unknown>",
        }
    }
}

/// Classify a 0x0Cxx opcode into its required permission category.
/// Returns `None` for implicit primitives (every module may call them).
/// Opcode → category is authoritative: when a new opcode is added in
/// `modules/sdk/internal/*` or `modules/sdk/platform/*`, it must be
/// classified here or it falls through to `PLATFORM_RAW` (most
/// restrictive, avoiding accidental privilege leakage).
fn privileged_op_permission(op: u32) -> Option<u16> {
    use permission::*;
    // USB host (0x15xx) — scaffold contract. The kernel-side vtable
    // is unimplemented; once it lands, every USB host op (BIND,
    // OPEN_ENDPOINT, BULK_READ/WRITE, INTERRUPT_POLL, RELEASE) is
    // expected to live in this opcode class and require `platform_raw`
    // like the other kernel-mediated controller bindings. Gating here
    // — rather than at the contract level — keeps the model consistent
    // with how PCIE_DEVICE / PLATFORM_DMA / NIC_RING enforce their
    // privileged ops (all of which live in the 0x0Cxx bucket but the
    // pattern is identical). A future driver that picks a 0x15xx
    // opcode for a non-privileged op (none planned) would need to add
    // a fine-grained match arm here.
    // USB host ops are kernel-mediated (a bound controller handle), so when the
    // stack lands they should gate on a dedicated `usb_host` grant like
    // PCIE_DEVICE — not this `platform_raw` fallback. The permission bitmap is a
    // u16 with bits 9.. free, so that grant costs nothing but the arm.
    if (0x1500..=0x15FF).contains(&op) {
        return Some(PLATFORM_RAW);
    }
    // Isolated-workload surface (workload, 0x1Axx) — spawning owner-bound
    // isolated workloads is privileged; gated by the same
    // platform_raw bit as raw DMA/MMIO/PCIe.
    if (0x1A00..=0x1AFF).contains(&op) {
        return Some(PLATFORM_RAW);
    }
    // Host-process mechanics (host_process, 0x1Bxx) — EXEC / TTY_* / READ run
    // and drive a real process on the Linux host, so they carry the same
    // platform_raw bar as the 0x1A ops that created the workload. The contract
    // grant for this class is the workload one (see `check_contract_grant`);
    // this is the permission half, and dropping it would leave process
    // execution reachable with a strictly weaker declaration than workload
    // creation.
    if (0x1B00..=0x1BFF).contains(&op) {
        return Some(PLATFORM_RAW);
    }
    if !(0x0C00..=0x0CFF).contains(&op) {
        return None;
    }
    match op {
        // ── Implicit primitives (no permission needed) ──────────────────
        // kernel_abi primitives: STREAM_TIME, GRAPH queries, ISR metrics,
        // runtime-params store/delete/clear (per-module-scoped),
        // ARENA_GET / BIND_IRQ / REPORT_LATENCY family, LOG_WRITE,
        // HANDLE_POLL, RANDOM_FILL, SYS_CLOCK_HZ, paged-arena GET/PREFAULT.
        0x0C30
        | 0x0C31
        | 0x0C33
        | 0x0C34
        | 0x0C35
        | 0x0C36
        | 0x0C3A..=0x0C3D
        | 0x0C3E // TLM_EMIT — implicit primitive like LOG_WRITE (any module emits)
        | 0x0C3F // ELASTIC_ALLOC — Tier B chunk grant (denial is the gate)
        | 0x0C40
        | 0x0C41
        | 0x0C42
        | 0x0C43
        | 0x0C44
        | 0x0C45
        | 0x0C46
        | 0x0C4B
        | 0x0C4C
        | 0x0C50
        | 0x0C51
        | 0x0C65
        | 0x0CE8
        | 0x0CF8
        | 0x0CFA => None,

        // ── flash_raw: flash ERASE / PROGRAM / sideband / store enable ──
        0x0C10 | 0x0C37 | 0x0C38 | 0x0C39 => Some(FLASH_RAW),

        // ── observe: read-only telemetry-ring drain (TLM_SUBSCRIBE/DRAIN/STATS).
        //    TLM_EMIT is above in the implicit-primitives arm. Strictly
        //    read-only — NOT `monitor` (which also grants FAULT_RAISE). ──
        0x0C4D..=0x0C4F => Some(OBSERVE),

        // ── monitor: FAULT_MONITOR_*, STEP_HISTOGRAM, PAGED_ARENA_STATS ─
        0x0C52..=0x0C5F | 0x0CF9 => Some(MONITOR),

        // ── reconfigure: graph slot commit, boot counter, FMP routing ──
        0x0C67..=0x0C6F => Some(RECONFIGURE),

        // ── live-mutation block (WS-D APPLY_ADD/FREE_OWNER + owner PAUSE/
        //    RESUME, 0x0C47..=0x0C4A): dispatched by the reconfigure kernel
        //    arms in system_provider_dispatch. Classified PLATFORM_RAW via the
        //    catch-all below — no dedicated arm needed. Deliberately OUTSIDE
        //    the peripheral range (0x0C70..) so they never shadow rp PIO. ──

        // ── bridge: cross-domain WRITE/READ/POLL/INFO ──────────────────
        0x0CE0..=0x0CE3 => Some(BRIDGE),

        // ── dma: DMA-buffer alloc (contig/streaming) + cache maintenance on
        //    those buffers (0x0CE6/0x0CE7/0x0CEA/0x0CEB/0x0CEC). MMIO_READ32/
        //    WRITE32 (0x0CE4/0x0CE5) stay platform_raw — arbitrary register
        //    access, not a bounded arena. ──
        0x0CE6 | 0x0CE7 | 0x0CEA | 0x0CEB | 0x0CEC => Some(DMA),

        // ── pcie_device: kernel-mediated device binding. BIND/CLOSE/
        //    CFG_READ32/CFG_WRITE32/BAR_MAP/MSI_ALLOC/INFO on a validated
        //    handle (0x0CA0..0x0CA6) — the kernel mediates every access, so
        //    this is a narrower grant than raw MMIO/DMA (`platform_raw`). ──
        0x0CA0..=0x0CA6 => Some(PCIE_DEVICE),

        // ── backing_provider: BACKING_PROVIDER_ENABLE, ARENA_REGISTER, ─
        //     ARENA_READ, SMMU map/unmap/fault-check, ARENA_BULK. ───────
        0x0CE9 | 0x0CED | 0x0CEE | 0x0CEF | 0x0CFB..=0x0CFF => Some(BACKING_PROVIDER),

        // ── platform_raw: everything else in 0x0Cxx ────────────────────
        // Explicit coverage for clarity:
        //   0x0C60..0x0C63  PWM raw pin/slice bridges
        //   0x0C64..0x0C66  log ring drain / raw UART / raw USB writes
        //   0x0C70..0x0CCF  raw peripheral register bridges (I2C, SPI, ADC, UART, PIO)
        //   0x0CD0..0x0CDF  PCIe MSI controller
        //   0x0CE4..0x0CE5  MMIO_READ32/WRITE32 (raw register access)
        //   0x0CF0..0x0CF7  NIC bar/ring/cfg, PCIE_RESCAN
        _ => Some(PLATFORM_RAW),
    }
}

/// Enforce privileged-opcode gating by fine-grained permission category.
/// Called from `provider_open` / `provider_call` / `provider_query` for
/// 0x0Cxx ops. Returns `Some(E_NOSYS)` when the caller lacks the
/// matching permission.
///
/// Every module that reaches a privileged op must carry the permission
/// bit in its manifest's `permissions = [...]` list. The only bypass is
/// `CAP_FULL` tier (module_type = Protocol, kernel-trusted).
unsafe fn check_privileged_internal_op(op: u32) -> Option<i32> {
    let required = privileged_op_permission(op)?;
    let cap = crate::kernel::exec::scheduler::current_module_cap_class();
    if cap == 3 {
        return None;
    } // CAP_FULL (kernel-trusted, module_type=Protocol)
    let held = crate::kernel::exec::scheduler::current_module_permissions();
    if held & required == 0 {
        log::warn!(
            "[cap] module called 0x{:04x} without permissions = [\"{}\"]",
            op,
            permission::name(required),
        );
        return Some(E_NOSYS);
    }
    None
}

// ============================================================================
// Per-class provider dispatch functions (portable)
// ============================================================================

unsafe fn channel_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::channel as dev_channel;
    use crate::kernel::ipc::channel;
    match opcode {
        dev_channel::OPEN => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            channel::syscall_channel_open(*arg, arg.add(1), arg_len - 1)
        }
        dev_channel::CLOSE => {
            channel::syscall_channel_close(handle);
            0
        }
        dev_channel::READ => {
            if arg.is_null() {
                return E_INVAL;
            }
            channel::syscall_channel_read(handle, arg, arg_len)
        }
        dev_channel::WRITE => {
            if arg.is_null() {
                return E_INVAL;
            }
            channel::syscall_channel_write(handle, arg as *const u8, arg_len)
        }
        dev_channel::POLL => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            channel::syscall_channel_poll(handle, *arg as u32)
        }
        dev_channel::PORT => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            syscall_channel_port(*arg, *arg.add(1))
        }
        dev_channel::IOCTL => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let cmd = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let payload_len = arg_len - 4;
            // Built-in cmds have fixed-size args. The kernel handlers
            // deref the arg pointer at a fixed width, so reject any
            // mismatched length here rather than letting them read
            // out-of-bounds bytes from the caller's buffer.
            match cmd {
                channel::IOCTL_NOTIFY | channel::IOCTL_POLL_NOTIFY => {
                    if payload_len != 4 {
                        return E_INVAL;
                    }
                }
                channel::IOCTL_FLUSH | channel::IOCTL_SET_HUP => {
                    if payload_len != 0 {
                        return E_INVAL;
                    }
                }
                _ => {
                    // Module-registered handler — length is part of
                    // the per-cmd contract, validated by the handler.
                }
            }
            let data_ptr = if payload_len > 0 {
                arg.add(4)
            } else {
                core::ptr::null_mut()
            };
            channel::syscall_channel_ioctl(handle, cmd, data_ptr)
        }
        dev_channel::REGISTER_IOCTL => {
            if arg.is_null() || arg_len < 16 {
                return E_INVAL;
            }
            let state = u64::from_le_bytes([
                *arg,
                *arg.add(1),
                *arg.add(2),
                *arg.add(3),
                *arg.add(4),
                *arg.add(5),
                *arg.add(6),
                *arg.add(7),
            ]) as *mut core::ffi::c_void;
            let handler = u64::from_le_bytes([
                *arg.add(8),
                *arg.add(9),
                *arg.add(10),
                *arg.add(11),
                *arg.add(12),
                *arg.add(13),
                *arg.add(14),
                *arg.add(15),
            ]) as *mut ();
            channel::syscall_channel_register_ioctl_handler(handle, state, handler)
        }
        _ => E_NOSYS,
    }
}

unsafe fn buffer_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::buffer as dev_buffer;
    use crate::kernel::ipc::channel;
    match opcode {
        dev_buffer::ACQUIRE_WRITE => {
            let cap_out = if !arg.is_null() && arg_len >= 4 {
                arg as *mut u32
            } else {
                core::ptr::null_mut()
            };
            channel::syscall_buffer_acquire_write(handle, cap_out) as i32
        }
        dev_buffer::RELEASE_WRITE => {
            let len = if !arg.is_null() && arg_len >= 4 {
                u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)])
            } else {
                0
            };
            channel::syscall_buffer_release_write(handle, len)
        }
        dev_buffer::ACQUIRE_READ => {
            let len_out = if !arg.is_null() && arg_len >= 4 {
                arg as *mut u32
            } else {
                core::ptr::null_mut()
            };
            channel::syscall_buffer_acquire_read(handle, len_out) as i32
        }
        dev_buffer::RELEASE_READ => channel::syscall_buffer_release_read(handle),
        dev_buffer::ACQUIRE_INPLACE => {
            let len_out = if !arg.is_null() && arg_len >= 4 {
                arg as *mut u32
            } else {
                core::ptr::null_mut()
            };
            channel::syscall_buffer_acquire_inplace(handle, len_out) as i32
        }
        _ => E_NOSYS,
    }
}

unsafe fn timer_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::timer as dev_timer;
    use crate::kernel::ipc::fd;
    match opcode {
        dev_timer::MILLIS => {
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let ms = syscall_millis();
            core::ptr::write_unaligned(arg as *mut u64, ms);
            0
        }
        dev_timer::MICROS => {
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let us = syscall_micros();
            core::ptr::write_unaligned(arg as *mut u64, us);
            0
        }
        dev_timer::UNIX_MILLIS => {
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            core::ptr::write_unaligned(arg as *mut u64, hal::now_unix_millis());
            0
        }
        dev_timer::CREATE => fd::timer_create(),
        dev_timer::SET => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let ms = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            fd::timer_set(handle, ms)
        }
        dev_timer::CANCEL => fd::timer_cancel(handle),
        dev_timer::DESTROY => fd::timer_destroy(handle),
        _ => E_NOSYS,
    }
}

unsafe fn event_provider_dispatch(handle: i32, opcode: u32, _arg: *mut u8, _arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::event as dev_event;
    use crate::kernel::ipc::event;
    use crate::kernel::ipc::fd;
    let slot = fd::slot_of(handle);
    match opcode {
        dev_event::CREATE => fd::tag_fd(fd::FD_TAG_EVENT, event::event_create()),
        dev_event::SIGNAL => event::event_signal(slot),
        dev_event::POLL => event::event_poll(slot),
        dev_event::DESTROY => event::event_destroy(slot),
        _ => E_NOSYS,
    }
}

// ============================================================================
// System Provider Dispatch (portable opcodes + extension point)
// ============================================================================

/// Platform-extension dispatch entry: `(handle, opcode, arg_ptr, arg_len) -> i32`.
pub type ExtensionFn = unsafe fn(i32, u32, *mut u8, usize) -> i32;

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
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
static mut DEV_QUERY_EXTENSION: Option<ExtensionFn> = None;

pub fn register_dev_query_extension(f: ExtensionFn) {
    // SAFETY: as `register_system_extension` — boot-time installation.
    unsafe {
        DEV_QUERY_EXTENSION = Some(f);
    }
}

/// Shared helper for *_ENABLE registration syscalls. Validates that
/// `arg` carries a 4-byte export hash, resolves the hash to a function
/// address in the calling module, and returns `(fn_addr, state_ptr)`.
/// Returns `None` on any validation failure.
unsafe fn resolve_register_target(arg: *mut u8, arg_len: usize) -> Option<(usize, *mut u8)> {
    use crate::kernel::exec::scheduler;
    if arg.is_null() || arg_len < 4 {
        return None;
    }
    let hash = core::ptr::read_unaligned(arg as *const u32);
    let module_idx = scheduler::current_module_index();
    let resolved =
        crate::kernel::module::loader::resolve_export_for_module(module_idx, hash).unwrap_or(0);
    if resolved == 0 {
        // Diagnostic: log details once-per-hash so provider/store
        // registration failures aren't silent. Gated by a static
        // bit so the log ring doesn't flood on retry loops.
        static mut LOGGED: u64 = 0;
        let bit = (hash as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58;
        let mask = 1u64 << (bit & 63);
        if (LOGGED & mask) == 0 {
            LOGGED |= mask;
            let (_code, tbl, cnt) = scheduler::get_module_exports(module_idx);
            log::warn!(
                "[reg] resolve_export failed: hash={hash:#x} mod={module_idx} exp_tbl={tbl:?} exp_cnt={cnt}",
            );
        }
        return None;
    }
    let state = scheduler::get_module_state(module_idx);
    if state.is_null() {
        static mut LOGGED_NULL_STATE: bool = false;
        if !LOGGED_NULL_STATE {
            LOGGED_NULL_STATE = true;
            log::warn!("[reg] state-null: hash={hash:#x} mod={module_idx} resolved={resolved:#x}",);
        }
        return None;
    }
    Some((resolved, state))
}

unsafe fn system_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::contracts::resource;
    use crate::abi::contracts::telemetry;
    use crate::abi::internal::diag;
    use crate::abi::internal::{bridge, monitor, provider_registry, reconfigure};
    use crate::abi::kernel_abi::event::BIND_IRQ;
    use crate::abi::kernel_abi::{
        ARENA_GET, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE, MODULE_FLOW_BUDGET,
        MODULE_INSTANCE_PARAMS, NET_IDENT_PROVIDER, OWNER_TAG, PAGED_ARENA_GET,
        PAGED_ARENA_PREFAULT, RANDOM_FILL, REPORT_LATENCY, REPORT_STEP_EFFECT, SELF_INDEX,
        SERIAL_WRITE,
    };
    use crate::kernel::exec::scheduler;
    match opcode {
        // ── Core primitives ──
        SELF_INDEX
        | OWNER_TAG
        | NET_IDENT_PROVIDER
        | ARENA_GET
        | REPORT_LATENCY
        | REPORT_STEP_EFFECT
        | LOG_WRITE
        | SERIAL_WRITE
        | GET_HW_ETHERNET_MAC
        | BIND_IRQ
        | HANDLE_POLL
        | RANDOM_FILL
        | MODULE_INSTANCE_PARAMS
        | MODULE_FLOW_BUDGET
        | bridge::SELF_BRIDGES
        | monitor::ISR_METRICS => handle_core_primitive(handle, opcode, arg, arg_len),
        // ── Telemetry ring (rfc_observability_surface.md §5.2). The
        //    OBSERVE gate for the consumer ops is applied upstream by
        //    `check_privileged_internal_op`; TLM_EMIT is ungated. ──
        resource::ELASTIC_ALLOC => handle_elastic_alloc(arg, arg_len),
        telemetry::TLM_EMIT
        | telemetry::TLM_SUBSCRIBE
        | telemetry::TLM_DRAIN
        | telemetry::TLM_STATS => handle_telemetry_op(handle, opcode, arg, arg_len),
        // ── Diagnostics / log transport ──
        diag::LOG_RING_DRAIN | diag::FAN_DIAG_SNAPSHOT => handle_diag_op(opcode, arg, arg_len),
        // ── Bridge channel operations ──
        bridge::WRITE | bridge::READ | bridge::POLL | bridge::INFO => {
            let bridge_op = opcode - bridge::WRITE; // 0=write, 1=read, 2=poll, 3=info
            let slot = crate::kernel::ipc::fd::slot_of(handle);
            if slot < 0 {
                return E_INVAL;
            }
            crate::kernel::bridge::bridge_dispatch(slot as usize, bridge_op, arg, arg_len)
        }
        // ── Paged arena ──
        PAGED_ARENA_GET | monitor::PAGED_ARENA_STATS | PAGED_ARENA_PREFAULT => {
            handle_paged_arena_op(opcode, arg, arg_len)
        }
        // ── Fault monitor ──
        monitor::FAULT_MONITOR_SUBSCRIBE
        | monitor::FAULT_MONITOR_POP
        | monitor::FAULT_STATS_QUERY
        | monitor::FAULT_RAISE
        | monitor::STEP_HISTOGRAM_QUERY => handle_fault_monitor_op(handle, opcode, arg, arg_len),

        // ── Live Reconfigure primitives (consumed by modules/reconfigure) ──
        reconfigure::SELF_INDEX
        | reconfigure::SET_PHASE
        | reconfigure::CALL_DRAIN
        | reconfigure::MARK_FINISHED
        | reconfigure::MODULE_COUNT
        | reconfigure::MODULE_INFO
        | reconfigure::MODULE_UPSTREAM
        | reconfigure::MODULE_DONE => handle_reconfigure_op(opcode, arg, arg_len),
        // ── NVMe paged-arena backing registration (kernel-private
        //    dispatch registry for a private backing interface) ──
        provider_registry::BACKING_PROVIDER_ENABLE => handle_service_register(opcode, arg, arg_len),

        reconfigure::TRIGGER_REBUILD => {
            // arg = [config_ptr:usize, config_len:usize] (platform pointer size)
            let ptr_size = core::mem::size_of::<usize>();
            if arg.is_null() || arg_len < 2 * ptr_size {
                return E_INVAL;
            }
            // SAFETY: `arg_len >= 2 * sizeof::<usize>()` checked above;
            // `read_unaligned` handles any alignment of `arg`.
            let config_ptr = unsafe { core::ptr::read_unaligned(arg as *const usize) } as *const u8;
            // SAFETY: as above; second usize at arg + sizeof::<usize>().
            let config_len =
                unsafe { core::ptr::read_unaligned(arg.add(ptr_size) as *const usize) };
            // SAFETY: `request_rebuild` is a kernel-internal scheduler API
            // that takes ownership of the config pointer for the reconfigure
            // ABI; the caller (this opcode handler) holds the only reference.
            unsafe {
                scheduler::request_rebuild(config_ptr, config_len);
            }
            0
        }

        // ── WS-D-min: live graph mutation (multi-tenant only) ──
        reconfigure::APPLY_ADD => {
            #[cfg(feature = "multitenant")]
            {
                // SAFETY: `arg`/`arg_len` describe the caller's request buffer,
                // valid for this call; the decoder borrows module params from it
                // in place and writes the owner handle back into it.
                unsafe { scheduler::live::apply_add_encoded(arg, arg_len) }
            }
            #[cfg(not(feature = "multitenant"))]
            {
                let _ = (arg, arg_len);
                E_NOSYS
            }
        }
        reconfigure::FREE_OWNER => {
            #[cfg(feature = "multitenant")]
            {
                // SAFETY: `arg`/`arg_len` describe a readable handle record.
                unsafe { scheduler::live::free_owner_encoded(arg, arg_len) }
            }
            #[cfg(not(feature = "multitenant"))]
            {
                let _ = (arg, arg_len);
                E_NOSYS
            }
        }
        // Owner pause/resume (rfc_workload_lifecycle.md §3.2 P4). Arms are
        // cfg-gated OUT (not ENOSYS-stubbed) on non-multitenant builds so the
        // opcodes fall through to the platform extension. They live in the
        // 0x0C47..=0x0C4A live-mutation block (well clear of the peripheral
        // register-bridge range), so on an rp build 0x0C49/0x0C4A reach the
        // platform extension and are simply unknown there — no longer
        // shadowing the rp PIO SM_READ_REG/SM_ENABLE bridges at 0x0C72/0x0C73.
        #[cfg(feature = "multitenant")]
        reconfigure::OWNER_PAUSE => {
            // SAFETY: `arg`/`arg_len` describe a readable handle record.
            unsafe { scheduler::live::owner_pause_encoded(arg, arg_len) }
        }
        #[cfg(feature = "multitenant")]
        reconfigure::OWNER_RESUME => {
            // SAFETY: `arg`/`arg_len` describe a readable handle record.
            unsafe { scheduler::live::owner_resume_encoded(arg, arg_len) }
        }

        // ── OTA RAM staging (Pi 5 / hosted Linux; ENOSYS elsewhere) ──
        #[cfg(any(feature = "chip-bcm2712", feature = "host-linux"))]
        reconfigure::OTA_STAGE_WRITE => {
            // arg = [offset: u32 LE][payload bytes]
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            // SAFETY: 4-byte offset prefix bounds-checked above; the
            // payload slice covers the caller's buffer for this call.
            let (offset, data) = unsafe {
                let off =
                    u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
                (off, core::slice::from_raw_parts(arg.add(4), arg_len - 4))
            };
            crate::kernel::module::ota_stage::stage_write(offset, data)
        }
        #[cfg(any(feature = "chip-bcm2712", feature = "host-linux"))]
        reconfigure::OTA_STAGE_CTRL => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            // SAFETY: 1-byte command bounds-checked above.
            let cmd = unsafe { *arg };
            crate::kernel::module::ota_stage::stage_ctrl(cmd)
        }

        _ => {
            // Delegate to platform extension for hardware-specific opcodes
            if let Some(ext) = SYSTEM_EXTENSION {
                ext(handle, opcode, arg, arg_len)
            } else {
                E_NOSYS
            }
        }
    }
}

// ============================================================================
// system_provider_dispatch category handlers
// ============================================================================
//
// The 0x0Cxx opcode range is split across small category handlers below
// so the top-level match stays readable and each concern is local.

/// Telemetry ring ops (`rfc_observability_surface.md` §5.2). `TLM_EMIT` is an
/// implicit primitive (any module); `TLM_SUBSCRIBE`/`DRAIN`/`STATS` are gated by
/// the read-only `observe` permission upstream in `check_privileged_internal_op`.
/// `ELASTIC_ALLOC` (`resource` contract): grant a Tier B chunk from the
/// kernel elastic region to the calling module. arg in `[bytes u32 LE]`,
/// out `[ptr u64 LE]`; returns granted bytes or an accounted `ENOSPC`.
/// EL0-isolated modules cannot reach this op at all — their SVC surface
/// carries no `provider_call` — so grants are structurally EL1-only.
unsafe fn handle_elastic_alloc(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return E_INVAL;
    }
    let bytes = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
    let idx = crate::kernel::exec::scheduler::current_module_index();
    if idx >= crate::kernel::exec::scheduler::MAX_MODULES {
        return E_INVAL;
    }
    // The deployment envelope may size the region down (Tier A over the
    // Tier B reserve): check the enforced ceiling before granting.
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
    match crate::kernel::mem::elastic::alloc(idx as u8, bytes) {
        Some((ptr, len)) => {
            let addr = (ptr as usize as u64).to_le_bytes();
            for (i, b) in addr.iter().enumerate() {
                *arg.add(i) = *b;
            }
            len as i32
        }
        None => {
            crate::kernel::sys::resource_ledger::deny(
                crate::abi::contracts::resource::POOL_ELASTIC_REGION,
            );
            crate::kernel::sys::errno::ENOSPC
        }
    }
}

unsafe fn handle_telemetry_op(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
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
        tlm::TLM_EMIT => {
            if arg.is_null() || arg_len < 12 {
                return E_INVAL;
            }
            let module_idx = caller;
            let rec = core::slice::from_raw_parts(arg, arg_len);
            telemetry_ring::emit(module_idx, rec);
            0
        }
        tlm::TLM_SUBSCRIBE => {
            let filter = if !arg.is_null() && arg_len >= 4 {
                u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)])
            } else {
                tlm::FILTER_ALL
            };
            // Optional trailing 8-byte LE PSTATUS cadence (§5.3): the collector
            // declares how often it wants the kernel to push its step-histogram
            // / arena round. Absent (4-byte arg) → keep the kernel default.
            let off = tlm::SUBSCRIBE_INTERVAL_OFFSET;
            if !arg.is_null() && arg_len >= off + 8 {
                let mut b = [0u8; 8];
                for (i, v) in b.iter_mut().enumerate() {
                    *v = *arg.add(off + i);
                }
                scheduler::set_pstatus_interval_ms(u64::from_le_bytes(b));
            }
            telemetry_ring::subscribe(caller, filter)
        }
        tlm::TLM_DRAIN => {
            // `handle` carries the slot id from TLM_SUBSCRIBE; `arg` is the
            // caller's output buffer, filled with whole records only.
            if arg.is_null() || handle < 0 {
                return E_INVAL;
            }
            // A drain advances the tail, so draining a slot you do not own
            // destroys its owner's records. `observe` grants the surface, not
            // another consumer's stream.
            if !telemetry_ring::owns(handle as usize, caller) {
                return E_INVAL;
            }
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            telemetry_ring::drain(handle as usize, out) as i32
        }
        tlm::TLM_STATS => {
            // Layout: `[head u32][dropped u32 × CONSUMERS]`.
            let need = 4 + telemetry_ring::CONSUMERS * 4;
            if arg.is_null() || arg_len < need {
                return E_INVAL;
            }
            let (head, slots) = telemetry_ring::stats();
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            out[0..4].copy_from_slice(&head.to_le_bytes());
            for (i, (_active, _lag, dropped)) in slots.iter().enumerate() {
                let off = 4 + i * 4;
                out[off..off + 4].copy_from_slice(&dropped.to_le_bytes());
            }
            need as i32
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_core_primitive(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::bridge;
    use crate::abi::internal::monitor::ISR_METRICS;
    use crate::abi::kernel_abi::event::BIND_IRQ;
    use crate::abi::kernel_abi::{
        ARENA_GET, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE, MODULE_FLOW_BUDGET,
        MODULE_INSTANCE_PARAMS, NET_IDENT_PROVIDER, OWNER_TAG, RANDOM_FILL, REPORT_LATENCY,
        REPORT_STEP_EFFECT, SELF_INDEX, SERIAL_WRITE,
    };
    use crate::kernel::exec::scheduler;
    match opcode {
        SELF_INDEX => scheduler::current_module_index() as i32,
        // The calling module's owner slot (`owner_tag`). `apply_add` stamps
        // every module of a `net=own` workload with its owner post-alloc
        // (`set_module_owner`), so a bind-emitting module reads its owner here
        // and appends it to `NET_CMD_BIND` / `DG_CMD_BIND` (metal owner-scoped
        // binds, `rfc_workload_backend_metal.md` §3.4 / P3a). Slot 0
        // (`OWNER_SYSTEM`, a base-graph module) is the host/wildcard tag — a
        // legitimate value, not an error. A module can only read its OWN owner.
        OWNER_TAG => scheduler::module_owner(scheduler::current_module_index()).slot as i32,
        // Net-identity provider self-registration: the calling BASE-GRAPH
        // module declares itself the node's shared network stack, carrying its
        // own `addr_ctl` / ingress input-port indices in `arg` (see
        // `kernel_abi::NET_IDENT_PROVIDER`). Workload modules are refused —
        // a tenant must not hijack identity installs. Single-tenant builds
        // have no workload backend to serve: ENOSYS.
        NET_IDENT_PROVIDER => {
            #[cfg(feature = "multitenant")]
            {
                if arg.is_null() || arg_len < 2 {
                    return crate::kernel::sys::errno::EINVAL;
                }
                let idx = scheduler::current_module_index();
                if !scheduler::module_owner(idx).is_system() {
                    return crate::kernel::sys::errno::EACCES;
                }
                let a = core::slice::from_raw_parts(arg, 2);
                crate::kernel::workload::workload_graph::register_net_identity_provider(
                    idx as u16, a[0], a[1],
                )
            }
            #[cfg(not(feature = "multitenant"))]
            {
                crate::kernel::sys::errno::ENOSYS
            }
        }
        // Module-facing ISR-bridge enumeration (RFC rfc_isr_tier_surface
        // "ISR-tier I/O contract"). Returns the calling module's own input /
        // output bridge fds (tagged), so an ISR-tier step body can then move
        // data with the ISR-exempt bridge WRITE/READ/POLL/INFO ops.
        bridge::SELF_BRIDGES => {
            use crate::kernel::ipc::fd::{tag_fd, FD_TAG_BRIDGE};
            let idx = scheduler::current_module_index();
            if idx >= scheduler::MAX_MODULES {
                return crate::kernel::sys::errno::ENODEV;
            }
            let (in_b, out_b) = match crate::kernel::exec::isr_tier::module_bridge_slots(idx as u8)
            {
                Some(b) => b,
                None => return crate::kernel::sys::errno::ENODEV,
            };
            let in_n = in_b.iter().filter(|s| **s >= 0).count();
            let out_n = out_b.iter().filter(|s| **s >= 0).count();
            let need = 4 + (in_n + out_n) * 4;
            if arg.is_null() || arg_len < need {
                return crate::kernel::sys::errno::EINVAL;
            }
            // SAFETY: `arg` is the caller's output buffer; `arg_len >= need`
            // checked above, so the `need`-byte slice is in bounds.
            let out = unsafe { core::slice::from_raw_parts_mut(arg, need) };
            out[0] = in_n as u8;
            out[1] = out_n as u8;
            out[2] = 0;
            out[3] = 0;
            let mut pos = 4;
            for s in in_b.iter().chain(out_b.iter()).filter(|s| **s >= 0) {
                let fd = tag_fd(FD_TAG_BRIDGE, *s as i32);
                out[pos..pos + 4].copy_from_slice(&fd.to_le_bytes());
                pos += 4;
            }
            need as i32
        }
        MODULE_FLOW_BUDGET => {
            // arg[0] = graph port index. Optional arg[1]: 0=output,
            // 1=input. Input requests may carry the raw channel
            // descriptor in arg[2..6] for bridge/repacking resolution. The
            // provider handle stays global (-1): raw channel handles are
            // intentionally untagged and can collide with tracked provider
            // handles during generic provider dispatch.
            if arg.is_null() || arg_len < 1 {
                return crate::kernel::sys::errno::EINVAL;
            }
            // SAFETY: non-null, len >= 1 checked above.
            let port_index = unsafe { *arg };
            let input = arg_len >= 2
                // SAFETY: arg non-null (checked above); arg_len >= 2 gates this read.
                && unsafe { *arg.add(1) } == 1;
            if input {
                let channel = if arg_len >= 6 {
                    // SAFETY: non-null and arg_len >= 6 checked above.
                    i32::from_le_bytes(unsafe {
                        [*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]
                    })
                } else {
                    -1
                };
                scheduler::syscall_input_flow_budget(port_index, channel)
            } else {
                scheduler::syscall_flow_budget(port_index)
            }
        }
        MODULE_INSTANCE_PARAMS => {
            let idx = scheduler::current_module_index();
            let (src, len) = scheduler::module_params(idx);
            if src.is_null() || len == 0 {
                return 0;
            }
            // Size query: `arg=null` or `arg_len=0` returns the full
            // param length without copying, so callers can size the
            // buffer before allocating. A real buffer gets
            // `min(len, arg_len)` bytes.
            if arg.is_null() || arg_len == 0 {
                return len as i32;
            }
            let copy_len = len.min(arg_len);
            // SAFETY: `copy_len <= min(len, arg_len)` so `src[..copy_len]`
            // and `arg[..copy_len]` are both in-bounds; `src` is `&[u8]`,
            // `arg` is the caller's `*mut u8` (non-null checked above).
            unsafe {
                core::ptr::copy_nonoverlapping(src, arg, copy_len);
            }
            copy_len as i32
        }
        ARENA_GET => {
            let mut size_out: u32 = 0;
            let ptr = scheduler::syscall_arena_get(&mut size_out);
            // The wire field is 4 bytes, so a resident arena pointer must fit
            // in u32 or it would be silently truncated into a wrong base. On
            // pi5 `STATE_ARENA` (.bss) is linked sub-4GiB so this never trips;
            // a hosted (PIE) Linux process can place .bss above 4GiB, where
            // truncation would corrupt the module's arena base. Fail closed
            // with a hard check. (PAGED_ARENA_GET carries a u64 base for
            // callers that genuinely need >4GiB.)
            if (ptr as usize) > u32::MAX as usize {
                log::error!(
                    "[syscall] ARENA_GET: arena ptr {ptr:p} exceeds u32; use PAGED_ARENA_GET"
                );
                return E_INVAL;
            }
            if !arg.is_null() && arg_len >= 4 {
                let addr = ptr as u32;
                *arg = addr as u8;
                *arg.add(1) = (addr >> 8) as u8;
                *arg.add(2) = (addr >> 16) as u8;
                *arg.add(3) = (addr >> 24) as u8;
            }
            size_out as i32
        }
        REPORT_LATENCY => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let frames = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let idx = scheduler::current_module_index();
            scheduler::report_module_latency(idx, frames);
            0
        }
        REPORT_STEP_EFFECT => {
            // §6.1 work signal: one byte of StepEffect. Heats the adaptive pacer
            // for WorkDone/RunnableBacklog/Burst; never authorises re-step.
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let idx = scheduler::current_module_index();
            scheduler::report_step_effect(idx, *arg);
            0
        }
        LOG_WRITE => {
            syscall_log(handle as u8, arg, arg_len);
            0
        }
        SERIAL_WRITE => {
            // Binary-safe raw write to the debug serial sink (the transport_buffer
            // telemetry path). Returns bytes accepted.
            if arg.is_null() || arg_len == 0 {
                return 0;
            }
            let bytes = core::slice::from_raw_parts(arg, arg_len);
            crate::kernel::sys::hal::serial_write(bytes) as i32
        }
        GET_HW_ETHERNET_MAC => {
            if arg.is_null() || arg_len < 6 {
                return E_INVAL;
            }
            #[cfg(feature = "dtb")]
            {
                match crate::kernel::boot::dtb::read_ethernet_mac() {
                    Some(mac) => {
                        for (i, byte) in mac.iter().enumerate() {
                            *arg.add(i) = *byte;
                        }
                        6
                    }
                    None => errno::ENODEV,
                }
            }
            #[cfg(not(feature = "dtb"))]
            {
                let _ = arg;
                errno::ENODEV
            }
        }
        BIND_IRQ => {
            if arg.is_null() || arg_len < 4 {
                return E_INVAL;
            }
            let irq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let mmio_base = if arg_len >= 12 {
                u64::from_le_bytes([
                    *arg.add(4),
                    *arg.add(5),
                    *arg.add(6),
                    *arg.add(7),
                    *arg.add(8),
                    *arg.add(9),
                    *arg.add(10),
                    *arg.add(11),
                ]) as usize
            } else {
                0
            };
            let event_slot = crate::kernel::ipc::fd::slot_of(handle);
            if event_slot < 0 {
                return E_INVAL;
            }
            // Event-bound IRQs (e.g. virtio-mmio) are serviced on core 0.
            hal::irq_bind(irq, event_slot, mmio_base, 0)
        }
        HANDLE_POLL => {
            let events = if !arg.is_null() && arg_len >= 1 {
                *arg
            } else {
                0xFF
            };
            crate::kernel::ipc::fd::fd_poll(handle, events)
        }
        RANDOM_FILL => {
            if arg.is_null() || arg_len == 0 {
                return E_INVAL;
            }
            hal::csprng_fill(arg, arg_len)
        }
        ISR_METRICS => crate::kernel::exec::isr_tier::isr_metrics_dispatch(arg, arg_len),
        _ => E_NOSYS,
    }
}

unsafe fn handle_reconfigure_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::reconfigure;
    use crate::kernel::exec::scheduler;
    match opcode {
        reconfigure::SELF_INDEX => scheduler::current_module_index() as i32,
        reconfigure::SET_PHASE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let phase_byte = core::ptr::read(arg);
            let phase = match phase_byte {
                0 => scheduler::ReconfigurePhase::Running,
                1 => scheduler::ReconfigurePhase::Draining,
                2 => scheduler::ReconfigurePhase::Migrating,
                _ => return E_INVAL,
            };
            scheduler::set_reconfigure_phase(phase);
            0
        }
        reconfigure::CALL_DRAIN => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            scheduler::call_module_drain(idx)
        }
        reconfigure::MARK_FINISHED => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            scheduler::mark_module_finished(idx);
            0
        }
        reconfigure::MODULE_COUNT => scheduler::active_module_count() as i32,
        reconfigure::MODULE_INFO => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            scheduler::module_info_flags(idx) as i32
        }
        reconfigure::MODULE_UPSTREAM => {
            // Arg layout: in `[module_idx:u8]`, out `[mask word u64 LE × W]`
            // (low word first), where the kernel writes
            // `W = min(MODULE_MASK_WORDS, (arg_len - 1) / 8)` words and
            // returns `MODULE_MASK_WORDS` — so a caller whose buffer is
            // narrower than the full mask can detect the truncation from
            // the return value. `arg_len >= 9` (index byte + one word).
            if arg.is_null() || arg_len < 9 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            let mut words = [0u64; crate::kernel::workload::bitmask::MODULE_MASK_WORDS];
            let total = scheduler::module_upstream_words(idx, &mut words);
            let fit = ((arg_len - 1) / 8).min(total);
            for (w, word) in words.iter().enumerate().take(fit) {
                let bytes = word.to_le_bytes();
                for (i, b) in bytes.iter().enumerate() {
                    *arg.add(1 + w * 8 + i) = *b;
                }
            }
            total as i32
        }
        reconfigure::MODULE_DONE => {
            if arg.is_null() || arg_len < 1 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            if scheduler::module_is_finished(idx) {
                1
            } else {
                0
            }
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_fault_monitor_op(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::monitor;
    use crate::kernel::exec::scheduler;
    match opcode {
        monitor::FAULT_MONITOR_SUBSCRIBE => {
            if handle < 0 {
                crate::kernel::exec::step_guard::subscribe(-1)
            } else {
                let slot = crate::kernel::ipc::fd::slot_of(handle);
                if slot < 0 {
                    return E_INVAL;
                }
                crate::kernel::exec::step_guard::subscribe(slot)
            }
        }
        monitor::FAULT_MONITOR_POP => {
            use crate::kernel::exec::step_guard::FaultRecord;
            if arg.is_null() || arg_len < FaultRecord::SIZE {
                return E_INVAL;
            }
            let mut rec = FaultRecord::default();
            let got = crate::kernel::exec::step_guard::pop_fault(&mut rec);
            if got == 1 {
                let bytes = rec.to_bytes();
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, FaultRecord::SIZE);
            }
            got
        }
        monitor::FAULT_STATS_QUERY => {
            use crate::kernel::exec::step_guard::FaultStats;
            if handle < 0 || handle as usize >= crate::kernel::boot::config::MAX_MODULES {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < core::mem::size_of::<FaultStats>() {
                return E_INVAL;
            }
            let stats = scheduler::get_fault_stats(handle as usize);
            core::ptr::copy_nonoverlapping(
                &stats as *const FaultStats as *const u8,
                arg,
                core::mem::size_of::<FaultStats>(),
            );
            0
        }
        monitor::FAULT_RAISE => {
            if arg.is_null() || arg_len < 2 {
                return E_INVAL;
            }
            let idx = core::ptr::read(arg) as usize;
            let kind = core::ptr::read(arg.add(1));
            scheduler::raise_module_fault(idx, kind);
            0
        }
        monitor::STEP_HISTOGRAM_QUERY => {
            if arg.is_null() || arg_len < 32 {
                return E_INVAL;
            }
            let idx = if handle < 0 {
                usize::MAX
            } else {
                handle as usize
            };
            scheduler::query_step_histogram(idx, arg)
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_paged_arena_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::monitor::PAGED_ARENA_STATS;
    use crate::abi::kernel_abi::{PAGED_ARENA_GET, PAGED_ARENA_PREFAULT};
    use crate::kernel::exec::scheduler;
    match opcode {
        PAGED_ARENA_GET => {
            let idx = scheduler::current_module_index();
            let config = crate::kernel::pager::get_config(idx);
            if !arg.is_null() && arg_len >= 20 {
                let base = if config.active {
                    config.base_vaddr as u64
                } else {
                    0
                };
                let size = if config.active {
                    config.virtual_size as u64
                } else {
                    0
                };
                let status: u32 = if config.active { 1 } else { 0 };
                let p = arg;
                let base_bytes = base.to_le_bytes();
                let size_bytes = size.to_le_bytes();
                let status_bytes = status.to_le_bytes();
                core::ptr::copy_nonoverlapping(base_bytes.as_ptr(), p, 8);
                core::ptr::copy_nonoverlapping(size_bytes.as_ptr(), p.add(8), 8);
                core::ptr::copy_nonoverlapping(status_bytes.as_ptr(), p.add(16), 4);
            }
            if config.active {
                0
            } else {
                E_NOSYS
            }
        }
        PAGED_ARENA_STATS => {
            let idx = scheduler::current_module_index();
            let stats = crate::kernel::pager::build_stats(idx);
            let stats_size = core::mem::size_of::<crate::kernel::pager::PagedArenaStats>();
            if !arg.is_null() && arg_len >= stats_size {
                let src = &stats as *const _ as *const u8;
                core::ptr::copy_nonoverlapping(src, arg, stats_size);
                0
            } else {
                E_INVAL
            }
        }
        PAGED_ARENA_PREFAULT => {
            if arg.is_null() || arg_len < 8 {
                return E_INVAL;
            }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let idx = scheduler::current_module_index();
            crate::kernel::pager::prefault(idx, offset, count) as i32
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_diag_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::diag;
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    match opcode {
        diag::LOG_RING_DRAIN => {
            // Low 16 bits = payload length, next 15 bits = dropped count
            // (saturating). Top bit is kept clear so the return is always
            // a non-negative `i32`.
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            let n = crate::kernel::sys::log_ring::drain_net(out);
            let dropped = crate::kernel::sys::log_ring::take_dropped_net();
            let dropped_sat = if dropped > 0x7FFF { 0x7FFF } else { dropped };
            ((dropped_sat << 16) | (n as u32 & 0xFFFF)) as i32
        }
        diag::FAN_DIAG_SNAPSHOT => {
            let f = FAN_DIAG_HANDLER.load(core::sync::atomic::Ordering::Acquire);
            if f.is_null() {
                return E_NOSYS;
            }
            let handler: unsafe fn(*mut u8, usize) -> i32 = core::mem::transmute(f);
            handler(arg, arg_len)
        }
        _ => E_NOSYS,
    }
}

/// Platform-injected handler for `FAN_DIAG_SNAPSHOT`. A null handler
/// causes the syscall to return ENOSYS, which is the expected behaviour
/// on platforms that don't expose fan-out / fan-in diagnostics.
pub static FAN_DIAG_HANDLER: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn register_fan_diag_handler(f: unsafe fn(*mut u8, usize) -> i32) {
    FAN_DIAG_HANDLER.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

unsafe fn handle_service_register(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::provider_registry;
    let (f, state) = match resolve_register_target(arg, arg_len) {
        Some(v) => v,
        None => return E_INVAL,
    };
    match opcode {
        provider_registry::BACKING_PROVIDER_ENABLE => {
            let dispatch: crate::kernel::backing_provider::BackingProviderDispatchFn =
                core::mem::transmute(f);
            crate::kernel::backing_provider::register(dispatch, state);
            0
        }
        _ => E_NOSYS,
    }
}

// ============================================================================
// Timer (millis / micros) — delegates to platform
// ============================================================================

/// # Safety
/// `extern "C"` syscall ABI shim: takes no pointers and is safe to call
/// from any context that has the kernel timer initialised. Marked
/// `unsafe` only to match the `SyscallTable` signature.
pub unsafe extern "C" fn syscall_millis() -> u64 {
    hal::now_millis()
}

/// # Safety
/// `extern "C"` syscall ABI shim: takes no pointers and is safe to call
/// from any context that has the kernel timer initialised. Marked
/// `unsafe` only to match the `SyscallTable` signature.
pub unsafe extern "C" fn syscall_micros() -> u64 {
    hal::now_micros()
}

// DMA channel allocation and bridge — platform-specific, moved to rp/providers.rs

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
/// `PUT`, namespace `RENAME`, …) carry an explicit `fence_out_ptr`
/// in their arg layout instead — see the storage contract files.
unsafe fn last_fence_query(handle: i32, out: *mut u8, out_len: usize) -> i32 {
    use crate::abi::fence::{QUERY_OP, WIRE_MAX_LEN};

    if out.is_null() || out_len < WIRE_MAX_LEN {
        return E_INVAL;
    }
    if crate::kernel::module::provider::contract_of(handle).is_none() {
        return E_NOSYS;
    }
    crate::kernel::module::provider::provider_call(handle, QUERY_OP, out, out_len)
}

/// Kernel-side cross-class query dispatcher.
///
/// Fallback path invoked by `syscall_provider_query` when the handle's
/// contract vtable doesn't claim the key. Handles:
///  - cross-class common keys (`query_key::*`) applicable to any handle
///  - per-contract defaults (SPI GET_CAPS, I2C GET_CAPS, …)
///  - SYSTEM-contract introspection (ARENA_USAGE, GRAPH_SAMPLE_RATE, …)
unsafe fn kernel_query_dispatch(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32 {
    use crate::abi::kernel_abi::query_key as dev_query_key;
    use crate::kernel::ipc::fd;
    use crate::kernel::module::provider::contract as dev_class;

    // Handle cross-class common queries (0x0000-0x00FF)
    if key < 0x0100 {
        return match key {
            dev_query_key::CLASS => {
                if out.is_null() || out_len < 1 {
                    return E_INVAL;
                }
                let (tag, _) = fd::untag_fd(handle);
                let class = match tag {
                    fd::FD_TAG_CHANNEL => dev_class::CHANNEL,
                    fd::FD_TAG_EVENT => dev_class::EVENT,
                    fd::FD_TAG_TIMER => dev_class::TIMER,
                    _ => return E_INVAL,
                };
                *out = class as u8;
                0
            }
            dev_query_key::STATE => E_NOSYS,
            dev_query_key::HEAP_STATS => {
                // Accept any `out_len >= HEAP_STATS_MIN` and copy up
                // to `out_len` bytes from the struct, returning the
                // actual bytes written. This lets the SDK grow the
                // `HeapStats` struct forward without breaking
                // pre-existing PIC modules whose SDK helper passes
                // only a 16-byte prefix buffer.
                const HEAP_STATS_MIN: usize = 16;
                let stats_size = core::mem::size_of::<crate::kernel::mem::heap::HeapStats>();
                if out.is_null() || out_len < HEAP_STATS_MIN {
                    return E_INVAL;
                }
                let idx = crate::kernel::exec::scheduler::current_module_index();
                let stats = crate::kernel::mem::heap::heap_stats(idx);
                let copy_len = stats_size.min(out_len);
                core::ptr::copy_nonoverlapping(
                    &stats as *const crate::kernel::mem::heap::HeapStats as *const u8,
                    out,
                    copy_len,
                );
                copy_len as i32
            }
            dev_query_key::FAULT_STATS => {
                use crate::kernel::exec::step_guard::FaultStats;
                let stats_size = core::mem::size_of::<FaultStats>();
                if out.is_null() || out_len < stats_size {
                    return E_INVAL;
                }
                let module_idx = if handle == -1 {
                    crate::kernel::exec::scheduler::current_module_index()
                } else {
                    handle as usize
                };
                let stats = crate::kernel::exec::scheduler::get_fault_stats(module_idx);
                core::ptr::copy_nonoverlapping(
                    &stats as *const FaultStats as *const u8,
                    out,
                    stats_size,
                );
                stats_size as i32
            }
            dev_query_key::LAST_FENCE => last_fence_query(handle, out, out_len),
            dev_query_key::CALLER_OWNER => {
                if out.is_null() || out_len < 8 {
                    return E_INVAL;
                }
                let caller = crate::kernel::exec::scheduler::caller_module_index();
                // Nothing on the provider stack means this module is stepping
                // its own work, not serving a request. Answering with an
                // owner here would let a provider charge background work to
                // whoever called it last, which is worse than no answer.
                if caller >= crate::kernel::exec::scheduler::MAX_MODULES {
                    return errno::ESRCH;
                }
                let owner = crate::kernel::exec::scheduler::module_owner(caller);
                let slot = owner.slot.to_le_bytes();
                let generation = owner.generation.to_le_bytes();
                *out = slot[0];
                *out.add(1) = slot[1];
                *out.add(2) = 0;
                *out.add(3) = 0;
                *out.add(4) = generation[0];
                *out.add(5) = generation[1];
                *out.add(6) = generation[2];
                *out.add(7) = generation[3];
                8
            }
            _ => E_NOSYS,
        };
    }

    let class = ((key >> 8) & 0xFF) as u16;
    match class {
        dev_class::SPI => {
            use crate::abi::contracts::hal::spi as dev_spi;
            match key {
                dev_spi::GET_CAPS => {
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    // Return SPI capabilities: bit 0 = DMA, bit 1 = async
                    *(out as *mut u32) = 0x03;
                    0
                }
                _ => E_NOSYS,
            }
        }
        dev_class::I2C => {
            use crate::abi::contracts::hal::i2c as dev_i2c;
            match key {
                dev_i2c::GET_CAPS => {
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    // I2C capabilities: bit 0 = async bridge, bit 1 = multi-handle
                    *(out as *mut u32) = 0x03;
                    0
                }
                _ => E_NOSYS,
            }
        }
        // PIO queries route through the PIC pio_stream module directly.
        dev_class::INTERNAL_DISPATCH_BUCKET => {
            use crate::abi::internal::monitor::ARENA_USAGE;
            use crate::abi::kernel_abi::{DOWNSTREAM_LATENCY, GRAPH_SAMPLE_RATE};
            use crate::kernel::exec::scheduler;
            match key {
                0x0C00 => {
                    // Get kernel ABI version
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    *(out as *mut u32) = ABI_VERSION;
                    0
                }
                0x0C30 => {
                    // STREAM_TIME: prefer a dedicated STREAM_CLOCK provider
                    // (hosts register one — the audio sink's clock — without
                    // any PIO hardware). If none is registered (bare-metal RP),
                    // fall back to the active PIO stream's own time: on RP the
                    // clock genuinely is a property of the PIO stream. handle=-1
                    // resolves to the first active stream (see
                    // `kernel_abi::STREAM_TIME`).
                    use crate::kernel::module::provider;
                    const STREAM_CLOCK_QUERY: u32 = 0x1C00;
                    const PIO_STREAM_TIME: u32 = 0x0407;
                    let rc = provider::dispatch(
                        provider::contract::STREAM_CLOCK,
                        handle,
                        STREAM_CLOCK_QUERY,
                        out,
                        out_len,
                    );
                    if rc == E_NOSYS {
                        provider::dispatch(
                            provider::contract::HAL_PIO,
                            handle,
                            PIO_STREAM_TIME,
                            out,
                            out_len,
                        )
                    } else {
                        rc
                    }
                }
                ARENA_USAGE => {
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    let (used, total) = crate::kernel::module::loader::arena_usage();
                    *(out as *mut u32) = ((used as u32) << 16) | (total as u32 & 0xFFFF);
                    0
                }
                GRAPH_SAMPLE_RATE => {
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    *(out as *mut u32) = scheduler::graph_sample_rate();
                    0
                }
                DOWNSTREAM_LATENCY => {
                    if out.is_null() || out_len < 4 {
                        return E_INVAL;
                    }
                    let idx = scheduler::current_module_index();
                    *(out as *mut u32) = scheduler::downstream_latency(idx);
                    0
                }
                _ => {
                    if let Some(ext) = DEV_QUERY_EXTENSION {
                        ext(handle, key, out, out_len)
                    } else {
                        E_NOSYS
                    }
                }
            }
        }
        _ => {
            // SAFETY: `DEV_QUERY_EXTENSION` is a `Option<fn>` set once at
            // boot; the copy out is a word-sized load.
            if let Some(ext) = unsafe { DEV_QUERY_EXTENSION } {
                // SAFETY: `ext` is the registered platform extension fn;
                // arguments are passed straight through from the caller.
                unsafe { ext(handle, key, out, out_len) }
            } else {
                E_NOSYS
            }
        }
    }
}

// ============================================================================
// Syscall Table Stubs (for SyscallTable::empty())
// ============================================================================

impl SyscallTable {
    pub const fn empty() -> Self {
        Self {
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
            provider_call_sel: stub_provider_call_sel,
        }
    }
}

unsafe extern "C" fn stub_channel_peek(_handle: i32, _buf: *mut u8, _len: usize) -> i32 {
    -1
}

// ============================================================================
// Handle Ownership Cleanup
// ============================================================================

/// Release all hardware handles owned by a module.
/// Called when a module finishes (done or error) to prevent resource leaks.
pub fn release_module_handles(module_idx: u8) {
    // Release platform-specific handles (GPIO, DMA FDs, etc.)
    hal::release_platform_handles(module_idx);
    // Release events
    crate::kernel::ipc::event::release_owned_by(module_idx);
    // Release fd-based timers
    crate::kernel::ipc::fd::release_timers_owned_by(module_idx);
    // Release module provider registrations
    crate::kernel::module::provider::release_module_providers(module_idx);
    // Clear channel ioctl handlers registered by this module so a
    // finalised module's function pointer cannot survive in the
    // channel table — the next `channel_ioctl` cmd on a bound
    // channel would otherwise call into freed code.
    crate::kernel::ipc::channel::release_module_handlers(module_idx);
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
unsafe extern "C" fn stub_provider_call_sel(
    _sel: *const u8,
    _sel_len: usize,
    _op_handle: i32,
    _op: u32,
    _arg: *mut u8,
    _arg_len: usize,
) -> i32 {
    E_NOSYS
}

// ============================================================================
// Heap Syscall Implementations
// ============================================================================

/// Allocate from the calling module's heap.
///
/// RFC §D7: ISR-tier modules are forbidden from heap operations.
/// The gate fires here (at the syscall boundary) rather than in
/// `heap::heap_alloc` itself because kernel-internal heap callers
/// must keep working — only the module-facing path is gated.
unsafe extern "C" fn syscall_heap_alloc(size: u32) -> *mut u8 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("heap_alloc") {
        return core::ptr::null_mut();
    }
    // §3.5 admission gate: heap growth is new allocation. Frees (and
    // in-place use of existing allocations) stay state-blind.
    if admission_closed("heap_alloc") {
        return core::ptr::null_mut();
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_alloc(idx, size as usize)
}

/// Free a previous allocation from the calling module's heap.
unsafe extern "C" fn syscall_heap_free(ptr: *mut u8) {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("heap_free") {
        return;
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_free(idx, ptr)
}

/// Reallocate from the calling module's heap.
unsafe extern "C" fn syscall_heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    if crate::kernel::exec::scheduler::deny_isr_tier_syscall("heap_realloc") {
        return core::ptr::null_mut();
    }
    // §3.5 admission gate: realloc can grow — new allocation.
    if admission_closed("heap_realloc") {
        return core::ptr::null_mut();
    }
    let idx = crate::kernel::exec::scheduler::current_module_index();
    crate::kernel::mem::heap::heap_realloc(idx, ptr, new_size as usize)
}

// RP platform providers are now registered via HAL (init_providers / release_module_handles).
// The rp/providers.rs file is included from the RP platform entrypoint instead.
//
// The cap-class grant policy (`CAP_CONTRACT_MASK`) is pinned by an out-of-tree
// test — `service_tiers_admit_storage_family_like_fs` in
// `tests/harness/tests/kernel_permissions.rs` — so production `src/` stays
// inline-test-free.
