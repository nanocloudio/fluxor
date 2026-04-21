//! Syscall implementations for PIC modules.
//!
//! This module provides the kernel-side implementation of the syscall table.
//! PIC modules call these functions through function pointers to access
//! hardware resources (SPI, GPIO, timers, etc.).
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

use crate::kernel::channel;
use crate::kernel::errno;
use crate::kernel::hal;
use crate::abi::{SyscallTable, ABI_VERSION};
// ============================================================================
// Error Codes (Linux errno values)
// ============================================================================

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;
#[allow(dead_code)]
const E_NOMEM: i32 = errno::ENOMEM;

// ============================================================================
// Syscall Table
// ============================================================================

static mut SYSCALL_TABLE: SyscallTable = SyscallTable::empty();

pub fn set_syscall_table(table: SyscallTable) {
    unsafe { SYSCALL_TABLE = table; }
}

pub fn init_syscall_table() {
    set_syscall_table(SyscallTable {
        version: ABI_VERSION,
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
    });
}

// ── v2 syscalls: handle-scoped provider dispatch ────────────────────

unsafe extern "C" fn syscall_provider_open(
    contract: u32,
    open_op: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    // INTERNAL_DISPATCH_BUCKET (0x000C) is kernel-internal only — module
    // code must use the public platform contracts (PLATFORM_NIC_RING,
    // PLATFORM_DMA, PLATFORM_DMA_FD) for handle-returning platform ops.
    if contract as u16 == crate::kernel::provider::contract::INTERNAL_DISPATCH_BUCKET {
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
    crate::kernel::provider::provider_open(contract as u16, open_op, config, config_len)
}

unsafe extern "C" fn syscall_provider_call(
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // Contract for capability check: prefer the handle's tracked
    // contract; fall back to the opcode's class byte for handle=-1
    // globals and untagged channel fds.
    let contract = crate::kernel::provider::contract_of(handle)
        .unwrap_or_else(|| ((op >> 8) & 0xFF) as u16);
    if let Some(rc) = check_contract_grant(contract) {
        return rc;
    }
    // Privileged 0x0Cxx opcodes also require the matching permission bit.
    if let Some(rc) = check_privileged_internal_op(op) {
        return rc;
    }
    crate::kernel::provider::provider_call(handle, op, arg, arg_len)
}

unsafe extern "C" fn syscall_provider_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let contract = crate::kernel::provider::contract_of(handle)
        .unwrap_or_else(|| ((key >> 8) & 0xFF) as u16);
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
    let vt_rc = crate::kernel::provider::provider_query(handle, key, out, out_len);
    if vt_rc != E_NOSYS {
        return vt_rc;
    }
    kernel_query_dispatch(handle, key, out, out_len)
}

unsafe extern "C" fn syscall_provider_close(handle: i32) -> i32 {
    if let Some(contract) = crate::kernel::provider::contract_of(handle) {
        if let Some(rc) = check_contract_grant(contract) {
            return rc;
        }
    }
    crate::kernel::provider::provider_close(handle)
}

fn syscall_table() -> &'static SyscallTable {
    unsafe { &*(&raw const SYSCALL_TABLE) }
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
            1 => log::error!("{}", s),
            2 => log::warn!("{}", s),
            3 => log::info!("{}", s),
            4 => log::debug!("{}", s),
            _ => log::trace!("{}", s),
        }
    }
}

/// Channel port discovery syscall - returns channel handle for a given port.
/// Delegates to the scheduler which tracks per-module port assignments.
unsafe extern "C" fn syscall_channel_port(port_type: u8, index: u8) -> i32 {
    crate::kernel::scheduler::channel_port_lookup(port_type, index)
}

// ============================================================================
// Channel Wrappers
// ============================================================================

pub fn channel_open(chan_type: u8, config: *const u8, config_len: usize) -> i32 {
    channel::syscall_channel_open(chan_type, config, config_len)
}

pub fn channel_close(handle: i32) {
    channel::syscall_channel_close(handle)
}

// ============================================================================
// SPI/I2C Initialization Status
// ============================================================================

use crate::kernel::config::HardwareContext;

// Hardware context - tracks which resources have been initialized
static mut HARDWARE_CONTEXT: HardwareContext = HardwareContext::new();

pub fn mark_spi_initialized(bus: u8) {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_spi_initialized(bus) }
}

/// Check if an SPI bus has been initialized
pub fn is_spi_initialized(bus: u8) -> bool {
    unsafe { (*(&raw const HARDWARE_CONTEXT)).is_spi_initialized(bus) }
}

pub fn mark_i2c_initialized(bus: u8) {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_i2c_initialized(bus) }
}

/// Check if an I2C bus has been initialized
pub fn is_i2c_initialized(bus: u8) -> bool {
    unsafe { (*(&raw const HARDWARE_CONTEXT)).is_i2c_initialized(bus) }
}

// ============================================================================
// Provider Registration
// ============================================================================

/// Register all built-in device class providers.
/// Called once at startup after init_syscall_table().
pub fn init_providers() {
    use crate::kernel::provider::contract as dev_class;
    use crate::kernel::provider;
    provider::register(dev_class::CHANNEL, channel_provider_dispatch);
    provider::register(dev_class::TIMER, timer_provider_dispatch);
    provider::register(dev_class::EVENT, event_provider_dispatch);
    provider::register(dev_class::INTERNAL_DISPATCH_BUCKET, system_provider_dispatch);
    // PLATFORM_NIC_RING / PLATFORM_DMA / PLATFORM_DMA_FD expose disjoint
    // handle types to drivers (NIC ring, raw DMA channel number, tagged
    // DMA fd). They share `system_provider_dispatch` because dispatch is
    // by opcode, but each contract id gets its own vtable slot so
    // declaration and gating stay independent.
    provider::register(dev_class::PLATFORM_NIC_RING, system_provider_dispatch);
    provider::register(dev_class::PLATFORM_DMA, system_provider_dispatch);
    provider::register(dev_class::PLATFORM_DMA_FD, system_provider_dispatch);
    // FS has no kernel-side provider — a PIC filesystem module (fat32,
    // …) or a host platform dispatcher (linux_fs_dispatch) registers
    // itself. If nothing is registered, `provider::dispatch(FS, …)`
    // returns ENOSYS naturally; no stub needed.
    provider::register(dev_class::BUFFER, buffer_provider_dispatch);
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

use crate::abi::kernel_abi;
use crate::abi::contracts;

static CHANNEL_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::CHANNEL,
        call:  channel_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::channel::CLOSE,
    };

static TIMER_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::TIMER,
        call:  timer_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::timer::DESTROY,
    };

static EVENT_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::EVENT,
        call:  event_provider_dispatch,
        query: None,
        default_close_op: kernel_abi::event::DESTROY,
    };

static BUFFER_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::BUFFER,
        call:  buffer_provider_dispatch,
        query: None,
        default_close_op: 0, // buffers released by explicit RELEASE opcodes
    };

static KEY_VAULT_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::KEY_VAULT,
        call:  key_vault_provider_dispatch,
        query: None,
        default_close_op: contracts::key_vault::DESTROY,
    };

// FS contract has no built-in kernel implementation — a PIC filesystem
// module (fat32, …) or a host-side platform dispatcher (linux_fs_dispatch)
// registers as the provider. The vtable's `call` routes through the
// class-byte dispatch chain so it picks up whichever provider is
// registered, same shape as the HAL vtables.
unsafe fn fs_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::FS, handle, op, arg, arg_len)
}

static FS_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::FS,
        call:  fs_call,
        query: None,
        default_close_op: contracts::storage::fs::CLOSE,
    };

// HAL contracts whose `call` dispatch is a PIC module provider. The
// vtable's `call` forwards to `provider::dispatch` with the right
// class byte so the existing module-chain routing applies.

unsafe fn hal_spi_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::SPI, handle, op, arg, arg_len)
}

static HAL_SPI_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_SPI,
        call:  hal_spi_call,
        query: None,
        default_close_op: contracts::hal::spi::CLOSE,
    };

unsafe fn hal_i2c_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::I2C, handle, op, arg, arg_len)
}

static HAL_I2C_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_I2C,
        call:  hal_i2c_call,
        query: None,
        default_close_op: contracts::hal::i2c::CLOSE,
    };

unsafe fn hal_pio_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::PIO, handle, op, arg, arg_len)
}

// PIO contracts open handles via multiple alloc variants (STREAM_ALLOC,
// CMD_ALLOC, RX_STREAM_ALLOC) and release them via STREAM_FREE or
// CMD_FREE. The default close op is STREAM_FREE; callers that opened
// a command or RX handle should invoke the matching FREE opcode via
// `provider_call` before `provider_close`.
static HAL_PIO_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_PIO,
        call:  hal_pio_call,
        query: None,
        default_close_op: contracts::hal::pio::STREAM_FREE,
    };

unsafe fn hal_uart_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::UART, handle, op, arg, arg_len)
}

static HAL_UART_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_UART,
        call:  hal_uart_call,
        query: None,
        default_close_op: contracts::hal::uart::CLOSE,
    };

unsafe fn hal_adc_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::ADC, handle, op, arg, arg_len)
}

static HAL_ADC_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_ADC,
        call:  hal_adc_call,
        query: None,
        default_close_op: contracts::hal::adc::CLOSE,
    };

unsafe fn hal_pwm_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::provider::contract as class;
    crate::kernel::provider::dispatch(class::PWM, handle, op, arg, arg_len)
}

static HAL_PWM_VTABLE: crate::kernel::provider::ProviderVTable =
    crate::kernel::provider::ProviderVTable {
        contract: crate::kernel::provider::contract::HAL_PWM,
        call:  hal_pwm_call,
        query: None,
        default_close_op: contracts::hal::pwm::CLOSE,
    };

/// KEY_VAULT provider adapter — forwards to the kernel key_vault module.
unsafe fn key_vault_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    crate::kernel::key_vault::provider_dispatch(handle, opcode, arg, arg_len)
}

// ============================================================================
// Generic Device Call / Query (ABI v3)
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
unsafe fn check_contract_grant(contract: u16) -> Option<i32> {
    use crate::kernel::provider::contract as ct;

    // Tiers mirror `scheduler::current_module_cap_class()` return values.
    // Bits 7 / 8 / 17 (PLATFORM_NIC_RING, PLATFORM_DMA, PLATFORM_DMA_FD)
    // are permitted at every service tier so a driver's `[[resources]]`
    // declaration is what actually grants access. The `platform_raw`
    // permission then gates the individual opcodes on top.
    const CAP_CONTRACT_MASK: [u32; 4] = [
        0x0003_1FE1, // CAP_SERVICE: infra + FS + KEY_VAULT + PLATFORM_NIC_RING + PLATFORM_DMA + PLATFORM_DMA_FD
        0x0003_1FF1, // CAP_SERVICE_PIO: service + HAL_PIO
        0x0003_1FE3, // CAP_SERVICE_GPIO: service + HAL_GPIO
        0xFFFF_FFFF, // CAP_FULL: any contract
    ];

    let cap = crate::kernel::scheduler::current_module_cap_class() as usize;
    if cap < CAP_CONTRACT_MASK.len() {
        let mask = CAP_CONTRACT_MASK[cap];
        if (contract as u32) < 32 && (mask & (1u32 << contract)) == 0 {
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
    // PLATFORM_NIC_RING, PLATFORM_DMA, and PLATFORM_DMA_FD are public
    // contracts subject to the same declare-to-use rule as HAL_* —
    // they are NOT in this list.
    const INFRA_CONTRACTS: u32 =
        (1u32 << 0)              |  // COMMON / cross-class
        (1u32 << ct::CHANNEL)    |
        (1u32 << ct::TIMER)      |
        (1u32 << ct::BUFFER)     |
        (1u32 << ct::EVENT)      |
        (1u32 << 0x0C)           |  // 0x0Cxx transport bucket (implicit routing)
        (1u32 << ct::KEY_VAULT);

    // Manifest gate: every non-infra contract must be declared in the
    // module's `[[resources]]` list. Channel-only consumers and app
    // modules are unaffected because channels/timers/etc. live in
    // INFRA_CONTRACTS.
    let req = crate::kernel::scheduler::current_module_required_caps();
    if (contract as u32) < 32
        && (INFRA_CONTRACTS & (1u32 << contract)) == 0
        && (req & (1u32 << contract)) == 0
    {
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
    pub const RECONFIGURE:       u8 = 1 << 0;
    pub const FLASH_RAW:         u8 = 1 << 1;
    pub const BACKING_PROVIDER:  u8 = 1 << 2;
    pub const PLATFORM_RAW:      u8 = 1 << 3;
    pub const MONITOR:           u8 = 1 << 4;
    pub const BRIDGE:            u8 = 1 << 5;

    pub fn name(bit: u8) -> &'static str {
        match bit {
            RECONFIGURE      => "reconfigure",
            FLASH_RAW        => "flash_raw",
            BACKING_PROVIDER => "backing_provider",
            PLATFORM_RAW     => "platform_raw",
            MONITOR          => "monitor",
            BRIDGE           => "bridge",
            _                => "<unknown>",
        }
    }
}

/// Classify a 0x0Cxx opcode into its required permission category.
/// Returns `None` for implicit primitives (every module may call them).
/// Opcode → category is authoritative: when a new opcode is added in
/// `modules/sdk/internal/*` or `modules/sdk/platform/*`, it must be
/// classified here or it falls through to `PLATFORM_RAW` (most
/// restrictive, avoiding accidental privilege leakage).
fn privileged_op_permission(op: u32) -> Option<u8> {
    use permission::*;
    if op < 0x0C00 || op > 0x0CFF { return None; }
    match op {
        // ── Implicit primitives (no permission needed) ──────────────────
        // kernel_abi primitives: STREAM_TIME, GRAPH queries, ISR metrics,
        // runtime-params store/delete/clear (per-module-scoped),
        // ARENA_GET / BIND_IRQ / REPORT_LATENCY family, LOG_WRITE,
        // HANDLE_POLL, RANDOM_FILL, SYS_CLOCK_HZ, paged-arena GET/PREFAULT.
        0x0C30 | 0x0C31 | 0x0C33 |
        0x0C34 | 0x0C35 | 0x0C36 |
        0x0C3A ..= 0x0C3D |
        0x0C40 | 0x0C41 |
        0x0C50 | 0x0C51 |
        0x0CE8 |
        0x0CF8 | 0x0CFA => None,

        // ── flash_raw: flash ERASE / PROGRAM / sideband / store enable ──
        0x0C10 | 0x0C37 | 0x0C38 | 0x0C39 => Some(FLASH_RAW),

        // ── monitor: FAULT_MONITOR_*, STEP_HISTOGRAM, PAGED_ARENA_STATS ─
        0x0C52 ..= 0x0C5F | 0x0CF9 => Some(MONITOR),

        // ── reconfigure: graph slot commit, boot counter, FMP routing ──
        0x0C67 ..= 0x0C6F => Some(RECONFIGURE),

        // ── bridge: cross-domain WRITE/READ/POLL/INFO ──────────────────
        0x0CE0 ..= 0x0CE3 => Some(BRIDGE),

        // ── backing_provider: BACKING_PROVIDER_ENABLE, ARENA_REGISTER, ─
        //     ARENA_READ, SMMU map/unmap/fault-check. ────────────────────
        0x0CED | 0x0CEE | 0x0CEF |
        0x0CFB ..= 0x0CFF => Some(BACKING_PROVIDER),

        // ── platform_raw: everything else in 0x0Cxx ────────────────────
        // Explicit coverage for clarity:
        //   0x0C60..0x0C63  PWM raw pin/slice bridges
        //   0x0C64..0x0C66  log ring drain / raw UART / raw USB writes
        //   0x0C70..0x0CCF  raw peripheral register bridges (I2C, SPI, ADC, UART, PIO)
        //   0x0CD0..0x0CDF  PCIe MSI controller
        //   0x0CE4..0x0CE7  MMIO_READ/WRITE, DMA_ALLOC_CONTIG, CACHE_FLUSH
        //   0x0CEA..0x0CEC  DMA_FLUSH / DMA_INVALIDATE / DMA_ALLOC_STREAMING
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
    let required = match privileged_op_permission(op) {
        Some(bit) => bit,
        None => return None, // implicit primitive
    };
    let cap = crate::kernel::scheduler::current_module_cap_class();
    if cap == 3 { return None; } // CAP_FULL (kernel-trusted, module_type=Protocol)
    let held = crate::kernel::scheduler::current_module_permissions();
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
    use crate::kernel::channel;
    match opcode {
        dev_channel::OPEN => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            channel::syscall_channel_open(*arg, arg.add(1), arg_len - 1)
        }
        dev_channel::CLOSE => { channel::syscall_channel_close(handle); 0 }
        dev_channel::READ => {
            if arg.is_null() { return E_INVAL; }
            channel::syscall_channel_read(handle, arg, arg_len)
        }
        dev_channel::WRITE => {
            if arg.is_null() { return E_INVAL; }
            channel::syscall_channel_write(handle, arg as *const u8, arg_len)
        }
        dev_channel::POLL => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            channel::syscall_channel_poll(handle, *arg as u32)
        }
        dev_channel::PORT => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            syscall_channel_port(*arg, *arg.add(1))
        }
        dev_channel::IOCTL => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let cmd = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let data_ptr = if arg_len >= 8 { arg.add(4) } else { core::ptr::null_mut() };
            channel::syscall_channel_ioctl(handle, cmd, data_ptr)
        }
        dev_channel::REGISTER_IOCTL => {
            if arg.is_null() || arg_len < 16 { return E_INVAL; }
            let state = u64::from_le_bytes([
                *arg,        *arg.add(1), *arg.add(2), *arg.add(3),
                *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
            ]) as *mut core::ffi::c_void;
            let handler = u64::from_le_bytes([
                *arg.add(8),  *arg.add(9),  *arg.add(10), *arg.add(11),
                *arg.add(12), *arg.add(13), *arg.add(14), *arg.add(15),
            ]) as *mut ();
            channel::syscall_channel_register_ioctl_handler(handle, state, handler)
        }
        _ => E_NOSYS,
    }
}

unsafe fn buffer_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::buffer as dev_buffer;
    use crate::kernel::channel;
    match opcode {
        dev_buffer::ACQUIRE_WRITE => {
            let cap_out = if !arg.is_null() && arg_len >= 4 { arg as *mut u32 } else { core::ptr::null_mut() };
            channel::syscall_buffer_acquire_write(handle, cap_out) as i32
        }
        dev_buffer::RELEASE_WRITE => {
            let len = if !arg.is_null() && arg_len >= 4 {
                u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)])
            } else { 0 };
            channel::syscall_buffer_release_write(handle, len)
        }
        dev_buffer::ACQUIRE_READ => {
            let len_out = if !arg.is_null() && arg_len >= 4 { arg as *mut u32 } else { core::ptr::null_mut() };
            channel::syscall_buffer_acquire_read(handle, len_out) as i32
        }
        dev_buffer::RELEASE_READ => channel::syscall_buffer_release_read(handle),
        dev_buffer::ACQUIRE_INPLACE => {
            let len_out = if !arg.is_null() && arg_len >= 4 { arg as *mut u32 } else { core::ptr::null_mut() };
            channel::syscall_buffer_acquire_inplace(handle, len_out) as i32
        }
        _ => E_NOSYS,
    }
}

unsafe fn timer_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::timer as dev_timer;
    use crate::kernel::fd;
    match opcode {
        dev_timer::MILLIS => {
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let ms = syscall_millis();
            core::ptr::write_unaligned(arg as *mut u64, ms);
            0
        }
        dev_timer::MICROS => {
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let us = syscall_micros();
            core::ptr::write_unaligned(arg as *mut u64, us);
            0
        }
        dev_timer::CREATE => fd::timer_create(),
        dev_timer::SET => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
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
    use crate::kernel::event;
    use crate::kernel::fd;
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

/// Extension point for platform-specific system opcodes (PWM, PIO, DMA, SPI9, etc.)
static mut SYSTEM_EXTENSION: Option<unsafe fn(i32, u32, *mut u8, usize) -> i32> = None;

pub fn register_system_extension(f: unsafe fn(i32, u32, *mut u8, usize) -> i32) {
    unsafe { SYSTEM_EXTENSION = Some(f); }
}

/// Extension point for platform-specific provider-query entries.
/// Called by the kernel-side query fallback when a handle's contract
/// vtable doesn't claim the key. Used by platform code (RP, BCM2712)
/// to expose chip-specific introspection (SYS_CLOCK_HZ, GPIO::GET_LEVEL
/// for untracked handles, …).
#[allow(dead_code)]
static mut DEV_QUERY_EXTENSION: Option<unsafe fn(i32, u32, *mut u8, usize) -> i32> = None;

pub fn register_dev_query_extension(f: unsafe fn(i32, u32, *mut u8, usize) -> i32) {
    unsafe { DEV_QUERY_EXTENSION = Some(f); }
}

/// Shared helper for *_ENABLE registration syscalls. Validates that
/// `arg` carries a 4-byte export hash, resolves the hash to a function
/// address in the calling module, and returns `(fn_addr, state_ptr)`.
/// Returns `None` on any validation failure.
unsafe fn resolve_register_target(arg: *mut u8, arg_len: usize) -> Option<(usize, *mut u8)> {
    use crate::kernel::scheduler;
    if arg.is_null() || arg_len < 4 { return None; }
    let hash = core::ptr::read_unaligned(arg as *const u32);
    let module_idx = scheduler::current_module_index();
    let resolved = crate::kernel::loader::resolve_export_for_module(module_idx, hash)
        .unwrap_or(0);
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
                "[reg] resolve_export failed: hash={:#x} mod={} exp_tbl={:?} exp_cnt={}",
                hash, module_idx, tbl, cnt,
            );
        }
        return None;
    }
    let state = scheduler::get_module_state(module_idx);
    if state.is_null() {
        static mut LOGGED_NULL_STATE: bool = false;
        if !LOGGED_NULL_STATE {
            LOGGED_NULL_STATE = true;
            log::warn!(
                "[reg] state-null: hash={:#x} mod={} resolved={:#x}",
                hash, module_idx, resolved,
            );
        }
        return None;
    }
    Some((resolved, state))
}

unsafe fn system_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::{bridge, monitor, provider_registry, reconfigure};
    use crate::abi::internal::diag;
    use crate::abi::kernel_abi::{
        ARENA_GET, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE,
        PAGED_ARENA_GET, PAGED_ARENA_PREFAULT, RANDOM_FILL, REPORT_LATENCY,
    };
    use crate::abi::kernel_abi::event::BIND_IRQ;
    use crate::kernel::scheduler;
    match opcode {
        // ── Core primitives ──
        ARENA_GET
        | REPORT_LATENCY
        | LOG_WRITE
        | GET_HW_ETHERNET_MAC
        | BIND_IRQ
        | HANDLE_POLL
        | RANDOM_FILL
        | monitor::ISR_METRICS => {
            handle_core_primitive(handle, opcode, arg, arg_len)
        }
        // ── Diagnostics / log transport ──
        diag::LOG_RING_DRAIN
        | diag::UART_WRITE_RAW
        | diag::USB_WRITE_RAW => {
            handle_diag_op(opcode, arg, arg_len)
        }
        // ── Bridge channel operations ──
        bridge::WRITE | bridge::READ |
        bridge::POLL | bridge::INFO => {
            let bridge_op = opcode - bridge::WRITE; // 0=write, 1=read, 2=poll, 3=info
            let slot = crate::kernel::fd::slot_of(handle);
            if slot < 0 { return E_INVAL; }
            crate::kernel::bridge::bridge_dispatch(slot as usize, bridge_op, arg, arg_len)
        }
        // ── Paged arena ──
        PAGED_ARENA_GET
        | monitor::PAGED_ARENA_STATS
        | PAGED_ARENA_PREFAULT => {
            handle_paged_arena_op(opcode, arg, arg_len)
        }
        // ── Fault monitor ──
        monitor::FAULT_MONITOR_SUBSCRIBE
        | monitor::FAULT_MONITOR_POP
        | monitor::FAULT_STATS_QUERY
        | monitor::FAULT_RAISE
        | monitor::STEP_HISTOGRAM_QUERY => {
            handle_fault_monitor_op(handle, opcode, arg, arg_len)
        }

        // ── Live Reconfigure primitives (consumed by modules/reconfigure) ──
        reconfigure::SELF_INDEX
        | reconfigure::SET_PHASE
        | reconfigure::CALL_DRAIN
        | reconfigure::MARK_FINISHED
        | reconfigure::MODULE_COUNT
        | reconfigure::MODULE_INFO
        | reconfigure::MODULE_UPSTREAM
        | reconfigure::MODULE_DONE => {
            handle_reconfigure_op(opcode, arg, arg_len)
        }
        // ── NVMe paged-arena backing registration (kernel-private
        //    dispatch registry for a private backing interface) ──
        provider_registry::BACKING_PROVIDER_ENABLE => {
            handle_service_register(opcode, arg, arg_len)
        }

        reconfigure::TRIGGER_REBUILD => {
            // arg = [config_ptr:usize, config_len:usize] (platform pointer size)
            let ptr_size = core::mem::size_of::<usize>();
            if arg.is_null() || arg_len < 2 * ptr_size { return E_INVAL; }
            let config_ptr = unsafe { core::ptr::read_unaligned(arg as *const usize) } as *const u8;
            let config_len = unsafe { core::ptr::read_unaligned(arg.add(ptr_size) as *const usize) };
            unsafe { scheduler::request_rebuild(config_ptr, config_len); }
            0
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

unsafe fn handle_core_primitive(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::{
        ARENA_GET, GET_HW_ETHERNET_MAC, HANDLE_POLL, LOG_WRITE,
        RANDOM_FILL, REPORT_LATENCY,
    };
    use crate::abi::kernel_abi::event::BIND_IRQ;
    use crate::abi::internal::monitor::ISR_METRICS;
    use crate::kernel::scheduler;
    match opcode {
        ARENA_GET => {
            let mut size_out: u32 = 0;
            let ptr = scheduler::syscall_arena_get(&mut size_out);
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
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let frames = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let idx = scheduler::current_module_index();
            scheduler::report_module_latency(idx, frames);
            0
        }
        LOG_WRITE => {
            syscall_log(handle as u8, arg, arg_len);
            0
        }
        GET_HW_ETHERNET_MAC => {
            if arg.is_null() || arg_len < 6 { return E_INVAL; }
            #[cfg(feature = "chip-bcm2712")]
            {
                match crate::kernel::dtb::read_ethernet_mac() {
                    Some(mac) => {
                        for i in 0..6 { *arg.add(i) = mac[i]; }
                        6
                    }
                    None => errno::ENODEV,
                }
            }
            #[cfg(not(feature = "chip-bcm2712"))]
            { let _ = arg; errno::ENODEV }
        }
        BIND_IRQ => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let irq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let mmio_base = if arg_len >= 12 {
                u64::from_le_bytes([
                    *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
                    *arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11),
                ]) as usize
            } else { 0 };
            let event_slot = crate::kernel::fd::slot_of(handle);
            if event_slot < 0 { return E_INVAL; }
            hal::irq_bind(irq, event_slot, mmio_base)
        }
        HANDLE_POLL => {
            let events = if !arg.is_null() && arg_len >= 1 { *arg } else { 0xFF };
            crate::kernel::fd::fd_poll(handle, events)
        }
        RANDOM_FILL => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            hal::csprng_fill(arg, arg_len)
        }
        ISR_METRICS => {
            crate::kernel::isr_tier::isr_metrics_dispatch(arg, arg_len)
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_reconfigure_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::reconfigure;
    use crate::kernel::scheduler;
    match opcode {
        reconfigure::SELF_INDEX => {
            scheduler::current_module_index() as i32
        }
        reconfigure::SET_PHASE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
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
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            scheduler::call_module_drain(idx)
        }
        reconfigure::MARK_FINISHED => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            scheduler::mark_module_finished(idx);
            0
        }
        reconfigure::MODULE_COUNT => {
            scheduler::active_module_count() as i32
        }
        reconfigure::MODULE_INFO => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            scheduler::module_info_flags(idx) as i32
        }
        reconfigure::MODULE_UPSTREAM => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            scheduler::module_upstream_mask(idx) as i32
        }
        reconfigure::MODULE_DONE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            if scheduler::module_is_finished(idx) { 1 } else { 0 }
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_fault_monitor_op(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::internal::monitor;
    use crate::kernel::scheduler;
    match opcode {
        monitor::FAULT_MONITOR_SUBSCRIBE => {
            if handle < 0 {
                crate::kernel::step_guard::subscribe(-1)
            } else {
                let slot = crate::kernel::fd::slot_of(handle);
                if slot < 0 { return E_INVAL; }
                crate::kernel::step_guard::subscribe(slot)
            }
        }
        monitor::FAULT_MONITOR_POP => {
            use crate::kernel::step_guard::FaultRecord;
            if arg.is_null() || arg_len < FaultRecord::SIZE { return E_INVAL; }
            let mut rec = FaultRecord::default();
            let got = crate::kernel::step_guard::pop_fault(&mut rec);
            if got == 1 {
                let bytes = rec.to_bytes();
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, FaultRecord::SIZE);
            }
            got
        }
        monitor::FAULT_STATS_QUERY => {
            use crate::kernel::step_guard::FaultStats;
            if handle < 0 || handle as usize >= crate::kernel::config::MAX_MODULES {
                return E_INVAL;
            }
            if arg.is_null() || arg_len < core::mem::size_of::<FaultStats>() { return E_INVAL; }
            let stats = scheduler::get_fault_stats(handle as usize);
            core::ptr::copy_nonoverlapping(
                &stats as *const FaultStats as *const u8,
                arg,
                core::mem::size_of::<FaultStats>(),
            );
            0
        }
        monitor::FAULT_RAISE => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let idx = core::ptr::read(arg) as usize;
            let kind = core::ptr::read(arg.add(1));
            scheduler::raise_module_fault(idx, kind);
            0
        }
        monitor::STEP_HISTOGRAM_QUERY => {
            if arg.is_null() || arg_len < 32 { return E_INVAL; }
            let idx = if handle < 0 { usize::MAX } else { handle as usize };
            scheduler::query_step_histogram(idx, arg)
        }
        _ => E_NOSYS,
    }
}

unsafe fn handle_paged_arena_op(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::kernel_abi::{PAGED_ARENA_GET, PAGED_ARENA_PREFAULT};
    use crate::abi::internal::monitor::PAGED_ARENA_STATS;
    use crate::kernel::scheduler;
    match opcode {
        PAGED_ARENA_GET => {
            let idx = scheduler::current_module_index();
            let config = crate::kernel::pager::get_config(idx);
            if !arg.is_null() && arg_len >= 20 {
                let base = if config.active { config.base_vaddr as u64 } else { 0 };
                let size = if config.active { config.virtual_size as u64 } else { 0 };
                let status: u32 = if config.active { 1 } else { 0 };
                let p = arg;
                let base_bytes = base.to_le_bytes();
                let size_bytes = size.to_le_bytes();
                let status_bytes = status.to_le_bytes();
                core::ptr::copy_nonoverlapping(base_bytes.as_ptr(), p, 8);
                core::ptr::copy_nonoverlapping(size_bytes.as_ptr(), p.add(8), 8);
                core::ptr::copy_nonoverlapping(status_bytes.as_ptr(), p.add(16), 4);
            }
            if config.active { 0 } else { E_NOSYS }
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
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
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
    if arg.is_null() || arg_len == 0 { return E_INVAL; }
    match opcode {
        diag::LOG_RING_DRAIN => {
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            let n = crate::kernel::log_ring::drain(out);
            let dropped = crate::kernel::log_ring::take_dropped();
            let dropped_sat = if dropped > 0xFFFF { 0xFFFF } else { dropped };
            ((dropped_sat << 16) | (n as u32 & 0xFFFF)) as i32
        }
        diag::UART_WRITE_RAW => {
            // Platform hook — a platform registers its UART writer via
            // `uart_write::install`. If nothing is installed, the platform
            // has no UART available to user-space, so we report ENOSYS
            // rather than silently dropping bytes.
            let bytes = core::slice::from_raw_parts(arg, arg_len);
            match crate::kernel::uart_write::write(bytes) {
                Some(n) => n as i32,
                None => errno::ENOSYS,
            }
        }
        diag::USB_WRITE_RAW => {
            // May return short counts when the USB TX pipe is
            // backpressured — the caller (log_usb) holds the unsent
            // tail in its staging buffer.
            let bytes = core::slice::from_raw_parts(arg, arg_len);
            match crate::kernel::usb_write::write(bytes) {
                Some(n) => n as i32,
                None => errno::ENOSYS,
            }
        }
        _ => E_NOSYS,
    }
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

pub unsafe extern "C" fn syscall_millis() -> u64 {
    hal::now_millis()
}

pub unsafe extern "C" fn syscall_micros() -> u64 {
    hal::now_micros()
}

// DMA channel allocation and bridge — platform-specific, moved to rp/providers.rs

// ============================================================================
// Device Query
// ============================================================================

/// Kernel-side cross-class query dispatcher.
///
/// Fallback path invoked by `syscall_provider_query` when the handle's
/// contract vtable doesn't claim the key. Handles:
///  - cross-class common keys (`query_key::*`) applicable to any handle
///  - per-contract defaults (SPI GET_CAPS, I2C GET_CAPS, …)
///  - SYSTEM-contract introspection (ARENA_USAGE, GRAPH_SAMPLE_RATE, …)
unsafe fn kernel_query_dispatch(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::kernel::provider::contract as dev_class;
    use crate::abi::kernel_abi::query_key as dev_query_key;
    use crate::kernel::fd;

    // Handle cross-class common queries (0x0000-0x00FF)
    if key < 0x0100 {
        return match key {
            dev_query_key::CLASS => {
                if out.is_null() || out_len < 1 { return E_INVAL; }
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
            dev_query_key::STATE => {
                E_NOSYS
            }
            dev_query_key::HEAP_STATS => {
                // Return heap stats for the calling module
                let stats_size = core::mem::size_of::<crate::kernel::heap::HeapStats>();
                if out.is_null() || out_len < stats_size { return E_INVAL; }
                let idx = crate::kernel::scheduler::current_module_index();
                let stats = crate::kernel::heap::heap_stats(idx);
                *(out as *mut crate::kernel::heap::HeapStats) = stats;
                stats_size as i32
            }
            dev_query_key::FAULT_STATS => {
                use crate::kernel::step_guard::FaultStats;
                let stats_size = core::mem::size_of::<FaultStats>();
                if out.is_null() || out_len < stats_size { return E_INVAL; }
                let module_idx = if handle == -1 {
                    crate::kernel::scheduler::current_module_index()
                } else {
                    handle as usize
                };
                let stats = crate::kernel::scheduler::get_fault_stats(module_idx);
                core::ptr::copy_nonoverlapping(
                    &stats as *const FaultStats as *const u8, out, stats_size,
                );
                stats_size as i32
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
                    if out.is_null() || out_len < 4 { return E_INVAL; }
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
                    if out.is_null() || out_len < 4 { return E_INVAL; }
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
            use crate::kernel::scheduler;
            match key {
                0x0C00 => {
                    // Get kernel ABI version
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = ABI_VERSION;
                    0
                }
                0x0C30 => {
                    // STREAM_TIME: delegate to the HAL_PIO provider chain
                    // via the PIO-side STREAM_TIME opcode (0x0407). The
                    // PIO PIC module owns per-stream state; when called
                    // with handle=-1 it resolves to the first active
                    // stream (documented behavior in `kernel_abi::STREAM_TIME`).
                    use crate::kernel::provider;
                    const PIO_STREAM_TIME: u32 = 0x0407;
                    provider::dispatch(
                        provider::contract::HAL_PIO, handle, PIO_STREAM_TIME, out, out_len,
                    )
                }
                ARENA_USAGE => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    let (used, total) = crate::kernel::loader::arena_usage();
                    *(out as *mut u32) = ((used as u32) << 16) | (total as u32 & 0xFFFF);
                    0
                }
                GRAPH_SAMPLE_RATE => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = scheduler::graph_sample_rate();
                    0
                }
                DOWNSTREAM_LATENCY => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
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
            if let Some(ext) = unsafe { DEV_QUERY_EXTENSION } {
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
        }
    }
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
    crate::kernel::event::release_owned_by(module_idx);
    // Release fd-based timers
    crate::kernel::fd::release_timers_owned_by(module_idx);
    // Release module provider registrations
    crate::kernel::provider::release_module_providers(module_idx);
}

unsafe extern "C" fn stub_channel_read(_handle: i32, _buf: *mut u8, _len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_channel_write(_handle: i32, _data: *const u8, _len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_channel_poll(_handle: i32, _events: u32) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_heap_alloc(_size: u32) -> *mut u8 { null_mut() }
unsafe extern "C" fn stub_heap_free(_ptr: *mut u8) {}
unsafe extern "C" fn stub_heap_realloc(_ptr: *mut u8, _new_size: u32) -> *mut u8 { null_mut() }
unsafe extern "C" fn stub_provider_open(_contract: u32, _op: u32, _config: *const u8, _config_len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_provider_call(_handle: i32, _op: u32, _arg: *mut u8, _arg_len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_provider_query(_handle: i32, _key: u32, _out: *mut u8, _out_len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_provider_close(_handle: i32) -> i32 { E_NOSYS }

// ============================================================================
// Heap Syscall Implementations
// ============================================================================

/// Allocate from the calling module's heap.
unsafe extern "C" fn syscall_heap_alloc(size: u32) -> *mut u8 {
    let idx = crate::kernel::scheduler::current_module_index();
    crate::kernel::heap::heap_alloc(idx, size as usize)
}

/// Free a previous allocation from the calling module's heap.
unsafe extern "C" fn syscall_heap_free(ptr: *mut u8) {
    let idx = crate::kernel::scheduler::current_module_index();
    crate::kernel::heap::heap_free(idx, ptr)
}

/// Reallocate from the calling module's heap.
unsafe extern "C" fn syscall_heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    let idx = crate::kernel::scheduler::current_module_index();
    crate::kernel::heap::heap_realloc(idx, ptr, new_size as usize)
}

// RP platform providers are now registered via HAL (init_providers / release_module_handles).
// The rp/providers.rs file is included from the RP platform entrypoint instead.
