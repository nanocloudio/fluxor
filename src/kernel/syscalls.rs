//! Syscall implementations for PIC modules.
//!
//! This module provides the kernel-side implementation of the syscall table.
//! PIC modules call these functions through function pointers to access
//! hardware resources (SPI, GPIO, timers, etc.).
//!
//! # Architecture
//!
//! Portable kernel code lives in this file. Platform-specific hardware drivers
//! (SPI, I2C, UART, ADC, DMA, PIO, PWM, GPIO hardware ops) are in
//! `src/platform/rp_providers.rs`, included at the bottom under `#[cfg(feature = "rp")]`.
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
#[cfg(feature = "rp")]
use portable_atomic::{AtomicBool, AtomicI32, AtomicU16, Ordering, compiler_fence};

use crate::kernel::channel;
use crate::kernel::errno;
use crate::kernel::net;
use crate::kernel::socket;
#[cfg(feature = "rp")]
use crate::io::gpio;
use crate::abi::{DeviceInfo, SyscallTable, ABI_VERSION};
#[cfg(feature = "rp")]
use crate::abi::SpiCaps;

// ============================================================================
// Error Codes (Linux errno values)
// ============================================================================

const E_INVAL: i32 = errno::EINVAL;
const E_NOSYS: i32 = errno::ENOSYS;
#[cfg(feature = "rp")]
const E_AGAIN: i32 = errno::EAGAIN;
#[cfg(feature = "rp")]
const E_BUSY: i32 = errno::EBUSY;
#[cfg(feature = "rp")]
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

#[cfg(feature = "rp")]
use crate::kernel::config::HardwareContext;

// Hardware context - tracks which resources have been initialized
#[cfg(feature = "rp")]
static mut HARDWARE_CONTEXT: HardwareContext = HardwareContext::new();

#[cfg(feature = "rp")]
pub fn mark_spi_initialized(bus: u8) {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_spi_initialized(bus) }
}

/// Check if an SPI bus has been initialized
#[cfg(feature = "rp")]
pub fn is_spi_initialized(bus: u8) -> bool {
    unsafe { (*(&raw const HARDWARE_CONTEXT)).is_spi_initialized(bus) }
}

#[cfg(not(feature = "rp"))]
pub fn is_spi_initialized(_bus: u8) -> bool { false }

#[cfg(feature = "rp")]
pub fn mark_i2c_initialized(bus: u8) {
    unsafe { (*(&raw mut HARDWARE_CONTEXT)).mark_i2c_initialized(bus) }
}

/// Check if an I2C bus has been initialized
#[cfg(feature = "rp")]
pub fn is_i2c_initialized(bus: u8) -> bool {
    unsafe { (*(&raw const HARDWARE_CONTEXT)).is_i2c_initialized(bus) }
}

#[cfg(not(feature = "rp"))]
pub fn is_i2c_initialized(_bus: u8) -> bool { false }

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
    provider::register(dev_class::SOCKET, socket_provider_dispatch);
    provider::register(dev_class::EVENT, event_provider_dispatch);
    provider::register(dev_class::SYSTEM, system_provider_dispatch);
    provider::register(dev_class::FS, fs_provider_dispatch);
    provider::register(dev_class::BUFFER, buffer_provider_dispatch);
    // RP-specific providers (SPI, I2C, GPIO, PIO, UART, ADC) registered in rp_providers
    #[cfg(feature = "rp")]
    init_rp_providers();
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
    use crate::abi::{dev_class, dev_common};

    let class = ((opcode >> 8) & 0xFF) as u8;

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

    // Handle cross-class operations first
    if class == dev_class::COMMON {
        return match opcode {
            dev_common::GET_STATS => E_NOSYS,        // Future: per-class stats
            dev_common::SET_POWER_STATE => E_NOSYS,   // Future: power management
            dev_common::GET_POWER_STATE => E_NOSYS,
            dev_common::RESET => E_NOSYS,             // Future: device reset
            dev_common::GET_INFO => {
                if arg.is_null() || arg_len < core::mem::size_of::<DeviceInfo>() {
                    return E_INVAL;
                }
                // Without a handle-to-class registry, GET_INFO requires
                // the caller to know the class. Return ENOSYS for now.
                E_NOSYS
            }
            _ => E_NOSYS,
        };
    }

    // Dispatch to registered provider
    crate::kernel::provider::dispatch(class, handle, opcode, arg, arg_len)
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
            channel::syscall_channel_poll(handle, *arg)
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
        dev_netif::REGISTER_SOCKET => {
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            let if_type = *arg;
            let channel = i32::from_le_bytes([*arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4)]);
            net::NetIfService::register_socket_provider(if_type, channel)
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

unsafe fn socket_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::{dev_socket, SocketServiceInfo, ChannelAddr};
    use crate::kernel::fd;
    let slot_handle = fd::slot_of(handle);
    match opcode {
        // --- User-facing socket ops ---
        dev_socket::OPEN => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            fd::tag_fd(fd::FD_TAG_SOCKET, socket::SocketService::open(*arg))
        }
        dev_socket::CONNECT => {
            if arg.is_null() || arg_len < core::mem::size_of::<ChannelAddr>() { return E_INVAL; }
            socket::SocketService::connect(slot_handle, &*(arg as *const ChannelAddr))
        }
        dev_socket::SEND => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot(slot_handle) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let input = core::slice::from_raw_parts(arg as *const u8, arg_len);
            let written = slot.tx_write(input);
            if written == 0 { socket::SOCK_EAGAIN } else { written as i32 }
        }
        dev_socket::RECV => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot(slot_handle) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let output = core::slice::from_raw_parts_mut(arg, arg_len);
            let read = slot.rx_read(output);
            if read == 0 { socket::SOCK_EAGAIN } else { read as i32 }
        }
        dev_socket::POLL => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            socket::SocketService::poll(slot_handle, *arg)
        }
        dev_socket::CLOSE => socket::SocketService::close(slot_handle),
        dev_socket::BIND => {
            if arg.is_null() || arg_len < 2 { return E_INVAL; }
            let port = u16::from_le_bytes([*arg, *arg.add(1)]);
            socket::SocketService::bind(slot_handle, port)
        }
        dev_socket::LISTEN => {
            let backlog = if arg.is_null() || arg_len < 4 { 1 } else {
                i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)])
            };
            socket::SocketService::listen(slot_handle, backlog)
        }
        dev_socket::ACCEPT => socket::SocketService::accept(slot_handle),
        // --- Service ops (used by IP module) ---
        dev_socket::SERVICE_COUNT => socket::MAX_SOCKETS as i32,
        dev_socket::SERVICE_INFO => {
            if arg.is_null() || arg_len < core::mem::size_of::<SocketServiceInfo>() { return E_INVAL; }
            if handle < 0 || handle >= socket::MAX_SOCKETS as i32 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot_by_index(handle as usize) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let info = &mut *(arg as *mut SocketServiceInfo);
            if slot.is_free() {
                info.socket_type = 0;
                info.state = 0;
                info.pending_op = 0;
            } else {
                info.socket_type = slot.socket_type();
                info.state = slot.state() as u8;
                info.pending_op = slot.pending_op() as u8;
                info.local_id = slot.local_id();
                info.remote_id = slot.remote_id();
                info.remote_endpoint = slot.remote_endpoint();
                info.tx_pending = slot.tx_pending() as u16;
                info.rx_available = slot.rx_available() as u16;
                info.rx_space = slot.rx_space() as u16;
            }
            info._pad = 0;
            0
        }
        dev_socket::SERVICE_TX_READ => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            if handle < 0 || handle >= socket::MAX_SOCKETS as i32 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot_by_index(handle as usize) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let buf = core::slice::from_raw_parts_mut(arg, arg_len);
            slot.tx_read(buf) as i32
        }
        dev_socket::SERVICE_RX_WRITE => {
            if arg.is_null() || arg_len == 0 { return E_INVAL; }
            if handle < 0 || handle >= socket::MAX_SOCKETS as i32 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot_by_index(handle as usize) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let data = core::slice::from_raw_parts(arg as *const u8, arg_len);
            slot.rx_write(data) as i32
        }
        dev_socket::SERVICE_COMPLETE_OP => {
            // arg[0..4]=result(i32 LE), arg[4]=state, arg[5]=poll_flags (optional)
            if arg.is_null() || arg_len < 5 { return E_INVAL; }
            if handle < 0 || handle >= socket::MAX_SOCKETS as i32 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot_by_index(handle as usize) {
                Some(s) => s,
                None => return E_INVAL,
            };
            let result = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            slot.complete_op(result);
            slot.set_state(*arg.add(4));
            if arg_len >= 6 {
                slot.set_poll_flags(*arg.add(5));
            }
            0
        }
        dev_socket::SERVICE_SET_STATE => {
            // arg[0]=state, arg[1]=poll_flags (optional)
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            if handle < 0 || handle >= socket::MAX_SOCKETS as i32 { return E_INVAL; }
            let slot = match socket::SocketService::get_slot_by_index(handle as usize) {
                Some(s) => s,
                None => return E_INVAL,
            };
            slot.set_state(*arg);
            if arg_len >= 2 {
                slot.set_poll_flags(*arg.add(1));
            }
            0
        }
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

#[cfg(feature = "rp")]
fn register_system_extension(f: unsafe fn(i32, u32, *mut u8, usize) -> i32) {
    unsafe { SYSTEM_EXTENSION = Some(f); }
}

/// Extension point for platform-specific dev_query entries
#[allow(dead_code)]
static mut DEV_QUERY_EXTENSION: Option<unsafe fn(i32, u32, *mut u8, usize) -> i32> = None;

#[allow(dead_code)]
fn register_dev_query_extension(f: unsafe fn(i32, u32, *mut u8, usize) -> i32) {
    unsafe { DEV_QUERY_EXTENSION = Some(f); }
}

unsafe fn system_provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::{dev_system, RegisterProviderArgs};
    use crate::kernel::{provider, scheduler};
    match opcode {
        #[cfg(feature = "rp")]
        dev_system::RESOURCE_TRY_LOCK => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            crate::kernel::resource::try_lock(*arg)
        }
        #[cfg(feature = "rp")]
        dev_system::RESOURCE_UNLOCK => crate::kernel::resource::unlock(handle),
        #[cfg(feature = "rp")]
        dev_system::FLASH_SIDEBAND => {
            use crate::abi::flash_sideband_op;
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            match *arg {
                flash_sideband_op::READ_CS => crate::kernel::resource::flash_sideband_read_cs(),
                flash_sideband_op::XIP_READ => {
                    if arg_len < 6 { return E_INVAL; }
                    let offset = u32::from_le_bytes([
                        *arg.add(1), *arg.add(2), *arg.add(3), *arg.add(4),
                    ]);
                    const FLASH_SIZE: u32 = 0x0040_0000;
                    let data_len = arg_len - 5;
                    if offset >= FLASH_SIZE { return E_INVAL; }
                    let avail = (FLASH_SIZE - offset) as usize;
                    let copy_len = if data_len < avail { data_len } else { avail };
                    let xip_src = (0x1000_0000u32 + offset) as *const u8;
                    core::ptr::copy_nonoverlapping(xip_src, arg.add(5), copy_len);
                    copy_len as i32
                }
                _ => E_NOSYS,
            }
        }
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
                return E_INVAL;
            }

            // Transmute u32 address to function pointer
            let dispatch_fn: provider::ModuleProviderDispatchFn =
                core::mem::transmute(fn_addr as usize);

            provider::register_module_provider(
                class,
                module_idx as u8,
                dispatch_fn,
                state,
            )
        }
        dev_system::UNREGISTER_PROVIDER => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let class = *arg;
            provider::unregister_module_provider(class)
        }
        // ── Runtime parameter store (shims → flash module dispatch, RP-only) ─
        #[cfg(feature = "rp")]
        dev_system::PARAM_STORE => {
            // Shim: prepend caller module_id, forward to flash module
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let module_id = scheduler::current_module_index() as u8;
            let mut fwd = [0u8; 252]; // module_id + tag + 250 max value
            fwd[0] = module_id;
            let n = if arg_len > 251 { 251 } else { arg_len };
            core::ptr::copy_nonoverlapping(arg, fwd.as_mut_ptr().add(1), n);
            crate::kernel::flash_store::dispatch_param_op(
                dev_system::PARAM_STORE, fwd.as_mut_ptr(), 1 + n)
        }
        #[cfg(feature = "rp")]
        dev_system::PARAM_DELETE => {
            if arg.is_null() || arg_len < 1 { return E_INVAL; }
            let module_id = scheduler::current_module_index() as u8;
            let mut fwd = [module_id, *arg];
            crate::kernel::flash_store::dispatch_param_op(
                dev_system::PARAM_DELETE, fwd.as_mut_ptr(), 2)
        }
        #[cfg(feature = "rp")]
        dev_system::PARAM_CLEAR_ALL => {
            if arg_len >= 1 && !arg.is_null() && *arg == 0xFF {
                let mut fwd = [0xFFu8];
                crate::kernel::flash_store::dispatch_param_op(
                    dev_system::PARAM_CLEAR_ALL, fwd.as_mut_ptr(), 1)
            } else {
                let module_id = scheduler::current_module_index() as u8;
                let mut fwd = [module_id];
                crate::kernel::flash_store::dispatch_param_op(
                    dev_system::PARAM_CLEAR_ALL, fwd.as_mut_ptr(), 1)
            }
        }
        // ── Flash store bridge (RP-only) ─────────────────────────────
        #[cfg(feature = "rp")]
        dev_system::FLASH_STORE_ENABLE => {
            // Register flash module dispatch: arg = [fn_addr:u32 LE]
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let fn_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let dispatch: crate::kernel::flash_store::FlashStoreDispatchFn =
                core::mem::transmute(fn_addr as usize);
            let module_idx = scheduler::current_module_index();
            let state = scheduler::get_module_state(module_idx);
            crate::kernel::flash_store::register_dispatch(dispatch, state)
        }
        #[cfg(feature = "rp")]
        dev_system::FLASH_RAW_ERASE => {
            // Erase runtime store sector: arg = [offset:u32 LE]
            if arg.is_null() || arg_len < 4 { return E_INVAL; }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::kernel::flash_store::raw_erase(offset)
        }
        #[cfg(feature = "rp")]
        dev_system::FLASH_RAW_PROGRAM => {
            // Program page: arg = [offset:u32 LE, data:256 bytes]
            if arg.is_null() || arg_len < 4 + 256 { return E_INVAL; }
            let offset = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            crate::kernel::flash_store::raw_program(offset, arg.add(4))
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
        dev_system::FD_POLL => {
            let events = if !arg.is_null() && arg_len >= 1 { *arg } else { 0xFF };
            crate::kernel::fd::fd_poll(handle, events)
        }
        // ── DMA FD (RP-only: fd-wrapped DMA channels) ──
        #[cfg(feature = "rp")]
        dev_system::DMA_FD_CREATE => {
            crate::kernel::fd::dma_fd_create()
        }
        #[cfg(feature = "rp")]
        dev_system::DMA_FD_START => {
            // handle=dma_fd, arg=[read_addr:u32, write_addr:u32, count:u32, dreq:u8, flags:u8] (14 bytes)
            if arg.is_null() || arg_len < 14 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let write_addr = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            let count = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let dreq = *arg.add(12);
            let flags = *arg.add(13);
            crate::kernel::fd::dma_fd_start(handle, read_addr, write_addr, count, dreq, flags)
        }
        #[cfg(feature = "rp")]
        dev_system::DMA_FD_RESTART => {
            // handle=dma_fd, arg=[read_addr:u32, count:u32] (8 bytes)
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            crate::kernel::fd::dma_fd_restart(handle, read_addr, count)
        }
        #[cfg(feature = "rp")]
        dev_system::DMA_FD_FREE => {
            crate::kernel::fd::dma_fd_free(handle)
        }
        #[cfg(feature = "rp")]
        dev_system::DMA_FD_QUEUE => {
            // handle=dma_fd, arg=[read_addr:u32, count:u32] (8 bytes)
            if arg.is_null() || arg_len < 8 { return E_INVAL; }
            let read_addr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let count = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            crate::kernel::fd::dma_fd_queue(handle, read_addr, count)
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

#[cfg(feature = "rp")]
pub unsafe extern "C" fn syscall_millis() -> u64 {
    embassy_time::Instant::now().as_millis()
}

#[cfg(feature = "rp")]
pub unsafe extern "C" fn syscall_micros() -> u64 {
    embassy_time::Instant::now().as_micros()
}

#[cfg(not(feature = "rp"))]
pub unsafe extern "C" fn syscall_millis() -> u64 { 0 }

#[cfg(not(feature = "rp"))]
pub unsafe extern "C" fn syscall_micros() -> u64 { 0 }

// ============================================================================
// DMA channel allocation and bridge
// ============================================================================

/// Bitmap of allocated DMA channels. CH0-CH7 pre-marked at boot.
#[cfg(feature = "rp")]
static DMA_CHANNELS_USED: AtomicU16 = AtomicU16::new(0x00FF); // CH0-CH7 reserved

#[cfg(feature = "rp")]
pub(crate) fn dma_alloc_channel() -> i32 {
    loop {
        let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
        let free_mask = !used & 0xFF00;
        if free_mask == 0 {
            return E_NOMEM;
        }
        let ch = free_mask.trailing_zeros() as u16;
        let bit = 1u16 << ch;
        if DMA_CHANNELS_USED.compare_exchange(
            used, used | bit,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        ).is_ok() {
            return ch as i32;
        }
    }
}

#[cfg(feature = "rp")]
pub(crate) fn dma_free_channel(ch: u8) -> i32 {
    if ch < 8 || ch > 15 { return E_INVAL; }
    let bit = 1u16 << ch;
    DMA_CHANNELS_USED.fetch_and(!bit, core::sync::atomic::Ordering::Release);
    0
}

#[cfg(feature = "rp")]
pub(crate) unsafe fn dma_start_raw(ch: u8, read_addr: u32, write_addr: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    // Verify channel is allocated
    let used = DMA_CHANNELS_USED.load(Ordering::Acquire);
    if used & (1u16 << ch) == 0 { return E_INVAL; }

    use embassy_rp::pac;

    let dma_ch = pac::DMA.ch(ch as usize);
    dma_ch.read_addr().write_value(read_addr);
    dma_ch.write_addr().write_value(write_addr);
    super::chip::dma_write_trans_count(&dma_ch, count);
    compiler_fence(Ordering::SeqCst);

    let incr_read = flags & 0x01 != 0;
    let incr_write = flags & 0x02 != 0;
    let data_size = if flags & 0x04 != 0 {
        pac::dma::vals::DataSize::SIZE_WORD  // 32-bit
    } else {
        pac::dma::vals::DataSize::SIZE_HALFWORD  // 16-bit
    };

    dma_ch.ctrl_trig().write(|w| {
        w.set_treq_sel(pac::dma::vals::TreqSel::from(dreq));
        w.set_data_size(data_size);
        w.set_incr_read(incr_read);
        w.set_incr_write(incr_write);
        w.set_chain_to(ch); // self-chain = no chain
        w.set_en(true);
    });
    compiler_fence(Ordering::SeqCst);
    0
}


#[cfg(feature = "rp")]
fn dma_busy(ch: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    if pac::DMA.ch(ch as usize).ctrl_trig().read().busy() { 1 } else { 0 }
}


#[cfg(feature = "rp")]
pub(crate) fn dma_abort(ch: u8) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    // Write 1 to CHAN_ABORT bit to abort the channel
    pac::DMA.chan_abort().write(|w| w.0 = 1u32 << ch);
    // Wait for abort to complete
    while pac::DMA.ch(ch as usize).ctrl_trig().read().busy() {}
    0
}


/// Fast DMA re-trigger via Alias 3 registers.
/// Writes AL3_TRANS_COUNT (no trigger) then AL3_READ_ADDR_TRIG (triggers start).
/// Preserves CTRL, WRITE_ADDR from the initial dma_start_raw configuration.
#[cfg(feature = "rp")]
pub(crate) unsafe fn dma_restart_raw(ch: u8, read_addr: u32, count: u32) -> i32 {
    if ch > 15 { return E_INVAL; }
    use embassy_rp::pac;
    let dma_ch = pac::DMA.ch(ch as usize);
    compiler_fence(Ordering::SeqCst);
    dma_ch.al3_trans_count().write_value(count);
    dma_ch.al3_read_addr_trig().write_value(read_addr);
    compiler_fence(Ordering::SeqCst);
    0
}

// ============================================================================
// Device Query
// ============================================================================

#[cfg(feature = "rp")]
use crate::abi::StreamTime;

/// Query device information by key.
///
/// Provides uniform introspection across all device classes.
unsafe extern "C" fn syscall_dev_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::abi::{dev_class, dev_common, dev_query_key, DeviceInfo};
    use crate::kernel::fd;

    // Handle cross-class common queries (0x0000-0x00FF)
    if key < 0x0100 {
        return match key {
            dev_common::GET_INFO => {
                if out.is_null() || out_len < core::mem::size_of::<DeviceInfo>() {
                    return E_INVAL;
                }
                // System-wide info when handle == -1
                if handle == -1 {
                    let info = DeviceInfo {
                        class: dev_class::SYSTEM,
                        version: ABI_VERSION as u8,
                        _reserved: 0,
                        capabilities: 0x001F, // GPIO | SPI | I2C | PIO | Timer
                    };
                    *(out as *mut DeviceInfo) = info;
                    return 0;
                }
                E_NOSYS
            }
            dev_query_key::CLASS => {
                if out.is_null() || out_len < 1 { return E_INVAL; }
                let (tag, _) = fd::untag_fd(handle);
                let class = match tag {
                    fd::FD_TAG_CHANNEL => dev_class::CHANNEL,
                    fd::FD_TAG_SOCKET => dev_class::SOCKET,
                    fd::FD_TAG_EVENT => dev_class::EVENT,
                    fd::FD_TAG_TIMER => dev_class::TIMER,
                    fd::FD_TAG_PIO_STREAM | fd::FD_TAG_PIO_CMD => dev_class::PIO,
                    _ => return E_INVAL,
                };
                *out = class;
                0
            }
            dev_query_key::STATE => {
                if out.is_null() || out_len < 1 { return E_INVAL; }
                let (tag, slot) = fd::untag_fd(handle);
                match tag {
                    fd::FD_TAG_SOCKET => {
                        match socket::SocketService::get_slot(slot) {
                            Some(s) => { *out = s.state(); 0 }
                            None => E_INVAL,
                        }
                    }
                    _ => E_NOSYS,
                }
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
        #[cfg(feature = "rp")]
        dev_class::GPIO => {
            use crate::abi::dev_gpio;
            match key {
                dev_gpio::GET_LEVEL => {
                    if !gpio::gpio_check_owner(handle) {
                        return E_INVAL;
                    }
                    gpio::gpio_get_level(handle)
                }
                _ => E_NOSYS,
            }
        }
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
        #[cfg(feature = "rp")]
        dev_class::PIO => {
            use crate::abi::dev_pio;
            use crate::io::pio;
            match key {
                dev_pio::STREAM_GET_BUFFER => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    let ptr = pio::syscall_pio_stream_get_buffer(handle);
                    *(out as *mut *mut u32) = ptr;
                    0
                }
                dev_pio::STREAM_TIME => {
                    if out.is_null() || out_len < core::mem::size_of::<StreamTime>() { return E_INVAL; }
                    pio::syscall_stream_time(handle, out as *mut StreamTime)
                }
                dev_pio::PROGRAM_STATUS => {
                    // Check FD tag to determine stream vs cmd
                    let (tag, slot) = crate::kernel::fd::untag_fd(handle);
                    match tag {
                        crate::kernel::fd::FD_TAG_PIO_STREAM =>
                            pio::PioStreamService::program_status_for(slot),
                        crate::kernel::fd::FD_TAG_PIO_CMD =>
                            pio::PioCmdService::program_status_for(slot),
                        _ => E_INVAL,
                    }
                }
                _ => E_NOSYS,
            }
        }
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
                #[cfg(feature = "rp")]
                dev_system::STREAM_TIME => {
                    use crate::io::pio;
                    // Stream time from first active PIO stream (no handle needed)
                    if out.is_null() || out_len < core::mem::size_of::<StreamTime>() { return E_INVAL; }
                    match pio::PioStreamService::stream_time_any() {
                        Some(time) => {
                            *(out as *mut StreamTime) = time;
                            0
                        }
                        None => E_NOSYS, // no active stream
                    }
                }
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
                #[cfg(feature = "rp")]
                dev_system::SYS_CLOCK_HZ => {
                    if out.is_null() || out_len < 4 { return E_INVAL; }
                    *(out as *mut u32) = embassy_rp::clocks::clk_sys_freq();
                    0
                }
                _ => E_NOSYS,
            }
        }
        _ => E_NOSYS,
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
    // Release RP-specific handles (SPI, I2C, UART, ADC, PIO, GPIO)
    #[cfg(feature = "rp")]
    release_rp_handles(module_idx);
    // Release events
    crate::kernel::event::release_owned_by(module_idx);
    // Release fd-based timers
    crate::kernel::fd::release_timers_owned_by(module_idx);
    // Release DMA FDs (RP-only)
    #[cfg(feature = "rp")]
    crate::kernel::fd::release_dma_fds_owned_by(module_idx);
    // Release module provider registrations
    crate::kernel::provider::release_module_providers(module_idx);
}

unsafe extern "C" fn stub_channel_read(_handle: i32, _buf: *mut u8, _len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_channel_write(_handle: i32, _data: *const u8, _len: usize) -> i32 { E_NOSYS }
unsafe extern "C" fn stub_channel_poll(_handle: i32, _events: u8) -> i32 { E_NOSYS }
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

// ============================================================================
// RP Platform Providers (hardware drivers)
// ============================================================================

#[cfg(feature = "rp")]
include!("../platform/rp_providers.rs");
