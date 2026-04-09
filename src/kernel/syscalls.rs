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
use crate::kernel::net;
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
        dev_call: syscall_dev_call,
        dev_query: syscall_dev_query,
        heap_alloc: syscall_heap_alloc,
        heap_free: syscall_heap_free,
        heap_realloc: syscall_heap_realloc,
    });
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
/// With ABI v7, all non-hot-path operations go through dev_call (capability-checked
/// at the provider dispatch level), so all module types get the same table.
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
    use crate::abi::dev_class;
    use crate::kernel::provider;
    provider::register(dev_class::CHANNEL, channel_provider_dispatch);
    provider::register(dev_class::TIMER, timer_provider_dispatch);
    provider::register(dev_class::NETIF, netif_provider_dispatch);
    provider::register(dev_class::EVENT, event_provider_dispatch);
    provider::register(dev_class::SYSTEM, system_provider_dispatch);
    provider::register(dev_class::FS, fs_provider_dispatch);
    provider::register(dev_class::BUFFER, buffer_provider_dispatch);
    // Platform-specific providers (GPIO, PIO, etc.) registered via HAL
    hal::init_providers();
}

// ============================================================================
// Generic Device Call / Query (ABI v3)
// ============================================================================

/// Generic device call — dispatches to per-class implementations via opcode.
///
/// The opcode's upper byte identifies the device class, the lower byte
/// identifies the operation within that class. This allows a single entry
/// point for all device operations while preserving the typed syscall API
/// as the primary interface.
///
/// Cross-class opcodes (0x00xx) are handled uniformly for all device types.
unsafe extern "C" fn syscall_dev_call(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use crate::abi::dev_class;
    use crate::kernel::provider;

    // Check for CHAIN_NEXT flag and strip it
    let chain_next = (opcode & provider::CHAIN_NEXT) != 0;
    let clean_opcode = opcode & 0xFFFF;
    let class = ((clean_opcode >> 8) & 0xFF) as u8;

    // Capability enforcement: check if the calling module's tier allows this class.
    // Bit N in the mask = device class N is allowed through dev_call.
    //   COMMON(0) GPIO(1) SPI(2) I2C(3) PIO(4) Chan(5) Timer(6)
    //   NetIF(7) Socket(8) FS(9) Buffer(A) Event(B) System(C) UART(D) ADC(E)
    const CAP_CLASS_MASK: [u32; 4] = [
        0x0000_1FE1, // CAP_SERVICE: infra + contract (no GPIO/SPI/I2C/PIO/UART/ADC)
        0x0000_1FF1, // CAP_SERVICE_PIO: service + PIO
        0x0000_1FE3, // CAP_SERVICE_GPIO: service + GPIO
        0xFFFF_FFFF, // CAP_FULL: all classes (0-31)
    ];
    {
        let cap = crate::kernel::scheduler::current_module_cap_class() as usize;
        if cap < CAP_CLASS_MASK.len() {
            let mask = CAP_CLASS_MASK[cap];
            if (class as u32) < 32 && (mask & (1 << class)) == 0 {
                return E_NOSYS;
            }
        }

        // Manifest enforcement: if the module declared required_caps, restrict
        // to only those device classes. Modules with required_caps=0 (no manifest
        // or empty resources) fall through to type-based enforcement above.
        //
        // Infrastructure classes are exempt — they're kernel services (logging,
        // timing, IPC, buffers, events) that any module may use, not hardware
        // resources that need explicit declaration.
        const INFRA_CLASSES: u32 =
            (1 << dev_class::COMMON)  |
            (1 << dev_class::CHANNEL) |
            (1 << dev_class::TIMER)   |
            (1 << dev_class::BUFFER)  |
            (1 << dev_class::EVENT)   |
            (1 << dev_class::SYSTEM);
        let req = crate::kernel::scheduler::current_module_required_caps();
        if req != 0 && (class as u32) < 32
            && (INFRA_CLASSES & (1 << class)) == 0
            && (req & (1 << class)) == 0
        {
            return E_NOSYS;
        }
    }

    if class == dev_class::COMMON {
        return E_NOSYS;
    }

    // Dispatch to registered provider (or next in chain if CHAIN_NEXT set)
    let result = if chain_next {
        let caller = crate::kernel::scheduler::current_module_index() as u8;
        provider::dispatch_next(caller, class, handle, clean_opcode, arg, arg_len)
    } else {
        provider::dispatch(class, handle, clean_opcode, arg, arg_len)
    };
    result
}

// ============================================================================
// Per-class provider dispatch functions (portable)
// ============================================================================

unsafe fn channel_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_channel;
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
        _ => E_NOSYS,
    }
}

unsafe fn buffer_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_buffer;
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
    use crate::abi::dev_timer;
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

unsafe fn netif_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::dev_netif;
    match opcode {
        dev_netif::OPEN => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            net::NetIfService::open(*arg)
        }
        dev_netif::REGISTER_FRAME => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let if_type = *arg;
            let channel = i32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            net::NetIfService::register_frame_provider(if_type, channel)
        }
        dev_netif::IOCTL => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let cmd = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let ioctl_arg = if arg_len > 4 { arg.add(4) } else { core::ptr::null_mut() };
            net::NetIfService::ioctl(handle, cmd, ioctl_arg)
        }
        dev_netif::STATE => net::NetIfService::state(handle),
        dev_netif::CLOSE => net::NetIfService::close(handle),
        _ => E_NOSYS,
    }
}

unsafe fn fs_provider_dispatch(_handle: i32, _opcode: u32, _arg: *mut u8, _arg_len: usize) -> i32 {
    // FS is a contract class — a PIC module registers as provider when available.
    // Built-in kernel provider returns E_NOSYS for all operations.
    E_NOSYS
}

unsafe fn event_provider_dispatch(handle: i32, opcode: u32, _arg: *mut u8, _arg_len: usize) -> i32 {
    use crate::abi::dev_event;
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

/// Extension point for platform-specific dev_query entries
#[allow(dead_code)]
static mut DEV_QUERY_EXTENSION: Option<unsafe fn(i32, u32, *mut u8, usize) -> i32> = None;

pub fn register_dev_query_extension(f: unsafe fn(i32, u32, *mut u8, usize) -> i32) {
    unsafe { DEV_QUERY_EXTENSION = Some(f); }
}

unsafe fn system_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::{dev_system, RegisterProviderArgs};
    use crate::kernel::{provider, scheduler};
    match opcode {
        dev_system::REGISTER_PROVIDER => {
            if arg.is_null() || arg_len < core::mem::size_of::<RegisterProviderArgs>() {
                return E_INVAL;
            }
            let args = &*(arg as *const RegisterProviderArgs);
            let class = args.device_class;
            let fn_addr = args.dispatch_fn;
            // Validate: module must declare the class in required_caps
            let module_idx = scheduler::current_module_index();
            let required_caps = scheduler::current_module_required_caps();
            if required_caps != 0 && (required_caps & (1u32 << class)) == 0 {
                return errno::EACCES;
            }

            // Get module state pointer
            let state = scheduler::get_module_state(module_idx);
            if state.is_null() {
                log::error!("[provider] register class=0x{:02x}: state null for module {}", class, module_idx);
                return E_INVAL;
            }

            // fn_addr is either a raw function address (legacy) or FNV-1a hash
            // of an exported symbol name. Try to resolve from module exports first.
            let resolved_addr = crate::kernel::loader::resolve_export_for_module(
                module_idx, fn_addr
            ).unwrap_or(fn_addr as usize);

            // Transmute resolved address to function pointer
            let dispatch_fn: provider::ModuleProviderDispatchFn =
                core::mem::transmute(resolved_addr);

            let reg_result = provider::register_module_provider(
                class,
                module_idx as u8,
                dispatch_fn,
                state,
            );
            if reg_result != 0 {
                log::error!("[provider] register failed class=0x{:02x} rc={}", class, reg_result);
            }
            reg_result
        }
        dev_system::ARENA_GET => {
            // Return module's arena pointer via arg buffer, size as return value
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
        dev_system::REPORT_LATENCY => {
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let frames = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let idx = scheduler::current_module_index();
            scheduler::report_module_latency(idx, frames);
            0
        }
        dev_system::LOG => {
            syscall_log(handle as u8, arg, arg_len);
            0
        }
        dev_system::IRQ_BIND => {
            // Bind an event handle to a hardware IRQ. handle=event, arg=[irq:u32, mmio_base:u64]
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let irq = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let mmio_base = if arg_len >= 12 {
                u64::from_le_bytes([
                    *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
                    *arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11),
                ]) as usize
            } else { 0 };
            // Pass raw event slot (not tagged FD) to the ISR binding
            let event_slot = crate::kernel::fd::slot_of(handle);
            if event_slot < 0 { return E_INVAL; }
            hal::irq_bind(irq, event_slot, mmio_base)
        }
        dev_system::FD_POLL => {
            let events = if !arg.is_null() && arg_len >= 1 { *arg } else { 0xFF };
            crate::kernel::fd::fd_poll(handle, events)
        }
        // ── Bridge channel operations ──
        dev_system::BRIDGE_WRITE | dev_system::BRIDGE_READ |
        dev_system::BRIDGE_POLL | dev_system::BRIDGE_INFO => {
            let bridge_op = opcode - dev_system::BRIDGE_WRITE; // 0=write, 1=read, 2=poll, 3=info
            let slot = crate::kernel::fd::slot_of(handle);
            if slot < 0 { return E_INVAL; }
            crate::kernel::bridge::bridge_dispatch(slot as usize, bridge_op, arg, arg_len)
        }
        // ── Paged arena ──
        dev_system::PAGED_ARENA_GET => {
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
        dev_system::PAGED_ARENA_STATS => {
            let idx = scheduler::current_module_index();
            let stats = crate::kernel::pager::build_stats(idx);
            if !arg.is_null() && arg_len >= core::mem::size_of::<crate::kernel::pager::PagedArenaStats>() {
                let src = &stats as *const _ as *const u8;
                core::ptr::copy_nonoverlapping(src, arg, core::mem::size_of::<crate::kernel::pager::PagedArenaStats>());
                0
            } else {
                E_INVAL
            }
        }
        dev_system::PAGED_ARENA_PREFAULT => {
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let idx = scheduler::current_module_index();
            crate::kernel::pager::prefault(idx, offset, count) as i32
        }
        // ── ISR tier metrics ──
        dev_system::ISR_METRICS => {
            crate::kernel::isr_tier::isr_metrics_dispatch(arg, arg_len)
        }
        // ── CSPRNG fill ──
        dev_system::CSPRNG_FILL => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            hal::csprng_fill(arg, arg_len)
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
// Timer (millis / micros) — delegates to platform
// ============================================================================

pub unsafe extern "C" fn syscall_millis() -> u64 {
    hal::now_millis()
}

pub unsafe extern "C" fn syscall_micros() -> u64 {
    hal::now_micros()
}

// DMA channel allocation and bridge — platform-specific, moved to rp_providers.rs

// ============================================================================
// Device Query
// ============================================================================

/// Query device information by key.
///
/// Provides uniform introspection across all device classes.
unsafe extern "C" fn syscall_dev_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::abi::{dev_class, dev_query_key};
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
                *out = class;
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

    let class = ((key >> 8) & 0xFF) as u8;
    match class {
        dev_class::SPI => {
            use crate::abi::dev_spi;
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
            use crate::abi::dev_i2c;
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
        // PIO dev_query removed — PIC pio_stream module handles PIO directly
        dev_class::NETIF => {
            use crate::abi::dev_netif;
            match key {
                dev_netif::STATE => {
                    net::NetIfService::state(handle)
                }
                _ => E_NOSYS,
            }
        }
        dev_class::SYSTEM => {
            use crate::abi::dev_system;
            use crate::kernel::scheduler;
            match key {
                0x0C00 => {
                    // Get kernel ABI version
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = ABI_VERSION;
                    0
                }
                // STREAM_TIME removed — PIC pio_stream module handles stream time
                dev_system::ARENA_USAGE => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    let (used, total) = crate::kernel::loader::arena_usage();
                    *(out as *mut u32) = ((used as u32) << 16) | (total as u32 & 0xFFFF);
                    0
                }
                dev_system::GRAPH_SAMPLE_RATE => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = scheduler::graph_sample_rate();
                    0
                }
                dev_system::DOWNSTREAM_LATENCY => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    let idx = scheduler::current_module_index();
                    *(out as *mut u32) = scheduler::downstream_latency(idx);
                    0
                }
                _ => {
                    // Delegate to platform extension for dev_query
                    if let Some(ext) = DEV_QUERY_EXTENSION {
                        ext(handle, key, out, out_len)
                    } else {
                        E_NOSYS
                    }
                }
            }
        }
        _ => {
            // Delegate to platform extension for dev_query
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
            dev_call: stub_dev_call,
            dev_query: stub_dev_query,
            heap_alloc: stub_heap_alloc,
            heap_free: stub_heap_free,
            heap_realloc: stub_heap_realloc,
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
unsafe extern "C" fn stub_dev_call(_handle: i32, _opcode: u32, _arg: *mut u8, _arg_len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_dev_query(_handle: i32, _key: u32, _out: *mut u8, _out_len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_heap_alloc(_size: u32) -> *mut u8 { null_mut() }
unsafe extern "C" fn stub_heap_free(_ptr: *mut u8) {}
unsafe extern "C" fn stub_heap_realloc(_ptr: *mut u8, _new_size: u32) -> *mut u8 { null_mut() }

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
// The rp_providers.rs file is included from the rp_hal module instead.
