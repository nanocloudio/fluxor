//! Shared ABI definitions for core and PIC modules.
#![allow(dead_code)]

pub const ABI_VERSION: u32 = 1;

/// Default channel buffer size in bytes.
/// Referenced by kernel (buffer_pool, scheduler fan buffer) and modules
/// (I2S input buffer, mixer sample buffer) to stay in sync.
pub const CHANNEL_BUFFER_SIZE: usize = 2048;

/// Generic stream timing information (domain-neutral).
///
/// Used to synchronize producers with real-time sinks (audio, LED strips, DACs, etc).
/// The kernel doesn't know what a "unit" is — that's defined by the sink.
/// For I2S audio, a unit is one PIO word (= one stereo frame).
///
/// Accessible via `dev_query(STREAM_TIME)` (key 0x0407) or the `stream_time`
/// syscall. `t0_micros` is captured on first push, not at alloc/init.
/// See `docs/architecture/timing.md` for usage patterns.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamTime {
    /// Units that have definitely left the system (consumed by hardware)
    pub consumed_units: u64,
    /// Units currently buffered ahead of consumption
    pub queued_units: u32,
    /// Consumption rate in units/second (Q16.16 fixed point, or 0 if unknown)
    pub units_per_sec_q16: u32,
    /// Monotonic microsecond timestamp when the stream first started
    /// (first push accepted). Zero if stream has not started.
    pub t0_micros: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ChannelAddr {
    pub addr: u32,
    pub endpoint: u16,
    pub _reserved: u16,
}

impl ChannelAddr {
    pub const fn new(addr: u32, endpoint: u16) -> Self {
        Self {
            addr,
            endpoint,
            _reserved: 0,
        }
    }
}

#[repr(C)]
pub struct SpiCaps {
    pub max_freq_hz: u32,
    pub mode_mask: u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallTable {
    pub version: u32,
    /// Read from a channel. Returns bytes read, 0 on empty, <0 on error.
    pub channel_read: unsafe extern "C" fn(handle: i32, buf: *mut u8, len: usize) -> i32,
    /// Write to a channel. Returns bytes written, 0 on full, <0 on error.
    pub channel_write: unsafe extern "C" fn(handle: i32, data: *const u8, len: usize) -> i32,
    /// Poll a channel for readiness. Returns bitmask of ready events.
    pub channel_poll: unsafe extern "C" fn(handle: i32, events: u8) -> i32,
    /// Invoke a device operation by opcode. Dispatches to the appropriate
    /// per-class handler via the provider registry.
    ///
    /// - handle: device handle (from class-specific open), or -1 for open operations
    /// - opcode: namespaced operation code (class << 8 | operation), see dev_* modules
    /// - arg: opcode-specific argument buffer (input, output, or both)
    /// - arg_len: length of argument buffer in bytes
    ///
    /// Returns: class/opcode-specific result, or ENOSYS (-38) if not implemented
    pub dev_call: unsafe extern "C" fn(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32,
    /// Query device information by key.
    ///
    /// Provides uniform introspection across all device classes. Useful for
    /// diagnostics, debug shells, and cross-cutting services that need to
    /// inspect device state without class-specific knowledge.
    ///
    /// - handle: device handle
    /// - key: query key (see dev_query_key module)
    /// - out: output buffer
    /// - out_len: output buffer length in bytes
    ///
    /// Returns: bytes written to out on success, or ENOSYS (-38) if not supported
    pub dev_query: unsafe extern "C" fn(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32,
}

// ============================================================================
// Poll Flags
// ============================================================================

/// Poll event flags (used with fd_poll / channel_poll).
/// These values are part of the stable ABI — modules hardcode them.
pub mod poll {
    /// Data available for reading.
    pub const IN: u8 = 0x01;
    /// Space available for writing.
    pub const OUT: u8 = 0x02;
    /// Error condition.
    pub const ERR: u8 = 0x04;
    /// Hang-up (peer closed / end-of-stream).
    pub const HUP: u8 = 0x08;
    /// Connection established.
    pub const CONN: u8 = 0x10;
}

// ============================================================================
// Error Codes
// ============================================================================

/// Standard error codes (negative errno values).
/// These values are part of the stable ABI — modules hardcode them.
pub mod errno {
    /// Operation completed successfully.
    pub const OK: i32 = 0;
    /// Generic / unspecified error.
    pub const ERROR: i32 = -1;
    /// Permission denied (capability check failed).
    pub const EACCES: i32 = -13;
    /// No such device or address (e.g. I2C NACK).
    pub const ENXIO: i32 = -6;
    /// Resource temporarily unavailable — try again.
    pub const EAGAIN: i32 = -11;
    /// Cannot allocate memory / no free slots.
    pub const ENOMEM: i32 = -12;
    /// Resource busy.
    pub const EBUSY: i32 = -16;
    /// No such device.
    pub const ENODEV: i32 = -19;
    /// Invalid argument.
    pub const EINVAL: i32 = -22;
    /// Operation in progress (async not yet complete).
    pub const EINPROGRESS: i32 = -36;
    /// Function / syscall not implemented.
    pub const ENOSYS: i32 = -38;
    /// Operation not supported (e.g. wrong pin mode).
    pub const ENOTSUP: i32 = -95;
    /// Transport endpoint is not connected.
    pub const ENOTCONN: i32 = -107;
    /// Connection timed out.
    pub const ETIMEDOUT: i32 = -110;
    /// Connection refused.
    pub const ECONNREFUSED: i32 = -111;
}

// ============================================================================
// GPIO Edge Detection Modes
// ============================================================================

/// GPIO edge detection modes (used with dev_gpio::SET_IRQ).
/// These values are part of the stable ABI — modules hardcode them.
pub mod gpio_edge {
    /// No edge detection.
    pub const NONE: u8 = 0;
    /// Rising edge (low → high).
    pub const RISING: u8 = 1;
    /// Falling edge (high → low).
    pub const FALLING: u8 = 2;
    /// Both edges.
    pub const BOTH: u8 = 3;
}

// ============================================================================
// Channel Ioctl Commands (stable ABI values)
// ============================================================================
//
// Channel ioctl commands. Values are stable ABI (modules hardcode them).
// The kernel provides the mechanism; modules define protocol meaning.
//
//   1 = SET_U32:  store auxiliary u32 value (arg: *const u32)
//                 Use case: seek position, file index, or any producer signal
//   2 = GET_U32:  atomic read-and-clear of auxiliary u32 (arg: *mut u32)
//                 Returns OK if value was pending (written to arg), EAGAIN if not
//   3 = FLUSH:    clear ring buffer and reset flags
//   4 = SET_HUP:  set HUP flag (detected via fd_poll with poll::HUP)

// ============================================================================
// Device Classes and Opcode Namespace
// ============================================================================
//
// Syscalls are organized into device classes. Each class owns a 256-opcode
// range (class << 8 | operation). This numbering is used by `dev_call` for
// generic dispatch and establishes the ABI contract for the future marketplace.
//
// Classes fall into three categories:
//   - Bus classes (GPIO, SPI, I2C, PIO): hardware transport primitives
//   - Infrastructure classes (Channel, Timer, Buffer): kernel services
//   - Contract classes (NetIF, Socket, FS): driver-to-service boundaries
//
// Contract classes define interfaces that driver modules *provide* and service
// modules *consume*. The kernel dispatches between them but does not implement
// networking, filesystems, or any domain-specific logic.
//
// Current typed syscalls (spi_open, gpio_get_level, etc.) remain the primary
// API. dev_call dispatches to the same implementations via opcode lookup.

/// Device class identifiers.
/// Upper byte of opcode = class. Lower byte = operation within class.
pub mod dev_class {
    /// Cross-class operations (common to all devices)
    pub const COMMON: u8 = 0x00;
    /// GPIO pins
    pub const GPIO: u8 = 0x01;
    /// SPI bus
    pub const SPI: u8 = 0x02;
    /// I2C bus
    pub const I2C: u8 = 0x03;
    /// PIO (Programmable I/O)
    pub const PIO: u8 = 0x04;
    /// Inter-module channels
    pub const CHANNEL: u8 = 0x05;
    /// Timers
    pub const TIMER: u8 = 0x06;
    /// Network interfaces (contract: drivers provide, services consume)
    pub const NETIF: u8 = 0x07;
    /// Network sockets (contract: IP stack provides, services consume)
    pub const SOCKET: u8 = 0x08;
    /// Filesystem (contract: FS module provides, services consume)
    pub const FS: u8 = 0x09;
    /// Zero-copy buffers
    pub const BUFFER: u8 = 0x0A;
    /// Event objects (signalable/pollable flags for ISR-to-module notification)
    pub const EVENT: u8 = 0x0B;
    /// System resources (locks, flash sideband)
    pub const SYSTEM: u8 = 0x0C;
    /// UART serial bus
    pub const UART: u8 = 0x0D;
    /// ADC (analog-to-digital converter)
    pub const ADC: u8 = 0x0E;
    /// PWM (pulse-width modulation)
    pub const PWM: u8 = 0x0F;
}

/// Standard cross-class opcodes (0x0000-0x00FF).
/// Every device class should respond to these (or return ENOSYS).
pub mod dev_common {
    /// Get device statistics. Returns class-specific stats struct.
    /// arg: pointer to output buffer, arg_len: buffer size
    pub const GET_STATS: u32 = 0x0001;
    /// Set power state. arg: pointer to u8 (0=off, 1=low, 2=normal, 3=high)
    pub const SET_POWER_STATE: u32 = 0x0002;
    /// Get power state. arg: pointer to u8 output
    pub const GET_POWER_STATE: u32 = 0x0003;
    /// Reset device to initial state.
    pub const RESET: u32 = 0x0004;
    /// Get device info (class, version, capabilities bitfield).
    /// arg: pointer to DeviceInfo struct
    pub const GET_INFO: u32 = 0x0005;
}

/// Power states for SET_POWER_STATE / GET_POWER_STATE
pub mod power_state {
    pub const OFF: u8 = 0;
    pub const LOW: u8 = 1;
    pub const NORMAL: u8 = 2;
    pub const HIGH: u8 = 3;
}

/// Device info returned by GET_INFO
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceInfo {
    /// Device class (dev_class::*)
    pub class: u8,
    /// Class-specific version
    pub version: u8,
    /// Reserved
    pub _reserved: u16,
    /// Capability bitfield (class-specific)
    pub capabilities: u32,
}

/// GPIO opcodes (0x0100-0x01FF)
pub mod dev_gpio {
    pub const CLAIM: u32 = 0x0100;
    pub const RELEASE: u32 = 0x0101;
    pub const SET_MODE: u32 = 0x0102;
    pub const SET_PULL: u32 = 0x0103;
    pub const SET_LEVEL: u32 = 0x0104;
    pub const GET_LEVEL: u32 = 0x0105;
    pub const REQUEST_OUTPUT: u32 = 0x0106;
    pub const REQUEST_INPUT: u32 = 0x0107;
    /// Set edge detection interest. handle=gpio, arg[0]=edge (0=none, 1=rising, 2=falling, 3=both).
    pub const SET_IRQ: u32 = 0x0108;
    /// Poll and clear pending edges. handle=gpio. Returns edge bits (bit0=rising, bit1=falling).
    pub const POLL_IRQ: u32 = 0x0109;
    /// Bind event to GPIO edge. handle=gpio (pin).
    /// arg[0]=edge (1=rising, 2=falling, 3=both), arg[1..5]=event_handle (i32 LE).
    /// Sets up edge detection and auto-signals the event on each detected edge.
    pub const WATCH_EDGE: u32 = 0x010A;
    /// Unbind event from GPIO edge. handle=gpio (pin). Clears edge detection and event binding.
    pub const UNWATCH_EDGE: u32 = 0x010B;
}

/// SPI opcodes (0x0200-0x02FF)
pub mod dev_spi {
    pub const OPEN: u32 = 0x0200;
    pub const CLOSE: u32 = 0x0201;
    pub const BEGIN: u32 = 0x0202;
    pub const END: u32 = 0x0203;
    pub const SET_CS: u32 = 0x0204;
    pub const CLAIM: u32 = 0x0205;
    pub const CONFIGURE: u32 = 0x0206;
    pub const TRANSFER_START: u32 = 0x0207;
    pub const TRANSFER_POLL: u32 = 0x0208;
    pub const POLL_BYTE: u32 = 0x0209;
    pub const GET_CAPS: u32 = 0x020A;
}

/// I2C opcodes (0x0300-0x03FF)
pub mod dev_i2c {
    pub const OPEN: u32 = 0x0300;
    pub const CLOSE: u32 = 0x0301;
    pub const WRITE: u32 = 0x0302;
    pub const READ: u32 = 0x0303;
    pub const WRITE_READ: u32 = 0x0304;
    pub const CLAIM: u32 = 0x0305;
    pub const RELEASE: u32 = 0x0306;
    pub const GET_CAPS: u32 = 0x0307;
}

/// PIO opcodes (0x0400-0x04FF)
pub mod dev_pio {
    // Streaming (unidirectional, continuous DMA — I2S, LED strips, etc.)
    pub const STREAM_ALLOC: u32 = 0x0400;
    pub const STREAM_LOAD_PROGRAM: u32 = 0x0401;
    pub const STREAM_GET_BUFFER: u32 = 0x0402;
    pub const STREAM_CONFIGURE: u32 = 0x0403;
    pub const STREAM_CAN_PUSH: u32 = 0x0404;
    pub const STREAM_PUSH: u32 = 0x0405;
    pub const STREAM_FREE: u32 = 0x0406;
    pub const STREAM_TIME: u32 = 0x0407;
    pub const DIRECT_BUFFER: u32 = 0x0408;
    pub const DIRECT_PUSH: u32 = 0x0409;
    /// Program load status: 0=none, 1=pending, 2=loaded, 3=error.
    pub const PROGRAM_STATUS: u32 = 0x040A;
    /// Set consumption rate (units/sec, Q16.16 fixed point). arg = &u32.
    pub const STREAM_SET_RATE: u32 = 0x040B;
    // Command/response (bidirectional, discrete transfers — gSPI, etc.)
    pub const CMD_ALLOC: u32 = 0x0410;
    pub const CMD_LOAD_PROGRAM: u32 = 0x0411;
    pub const CMD_CONFIGURE: u32 = 0x0412;
    /// Synchronous transfer: executes PIO DMA inline (PAC-level busy-wait).
    /// Returns total bytes on success, negative errno on error.
    pub const CMD_TRANSFER: u32 = 0x0413;
    pub const CMD_POLL: u32 = 0x0414;
    pub const CMD_FREE: u32 = 0x0415;
    // RX Stream (unidirectional input, continuous DMA capture — mic, ADC streams, etc.)
    pub const RX_STREAM_ALLOC: u32 = 0x0420;
    pub const RX_STREAM_LOAD_PROGRAM: u32 = 0x0421;
    pub const RX_STREAM_CONFIGURE: u32 = 0x0422;
    pub const RX_STREAM_CAN_PULL: u32 = 0x0423;
    pub const RX_STREAM_PULL: u32 = 0x0424;
    pub const RX_STREAM_FREE: u32 = 0x0425;
    pub const RX_STREAM_GET_BUFFER: u32 = 0x0426;
    pub const RX_STREAM_SET_RATE: u32 = 0x0427;
    // RGB opcodes 0x0430-0x0437 removed — display logic moved to PIC module
    // using generic PIO + DMA bridges (dev_system 0x0C70-0x0C84)
}

/// Arguments for `dev_pio::STREAM_LOAD_PROGRAM` via `dev_call`
#[repr(C)]
pub struct PioLoadProgramArgs {
    pub program: *const u16,
    pub program_len: u32,
    pub wrap_target: u8,
    pub wrap: u8,
    pub sideset_bits: u8,
    pub options: u8,
}

/// Arguments for `dev_pio::STREAM_CONFIGURE` via `dev_call`
#[repr(C)]
pub struct PioConfigureArgs {
    pub clock_div: u32,
    pub data_pin: u8,
    pub clock_base: u8,
    pub shift_bits: u8,
    pub _pad: u8,
}

/// Arguments for `dev_pio::RX_STREAM_CONFIGURE` via `dev_call`
#[repr(C)]
pub struct PioRxConfigureArgs {
    pub clock_div: u32,
    pub in_pin: u8,
    pub sideset_base: u8,
    pub shift_bits: u8,
    pub _pad: u8,
}

/// Arguments for `dev_pio::CMD_CONFIGURE` via `dev_call`
#[repr(C)]
pub struct PioCmdConfigureArgs {
    pub data_pin: u8,
    pub clk_pin: u8,
    pub _pad: [u8; 2],
    pub clock_div: u32,
}

/// Arguments for `dev_pio::CMD_TRANSFER` via `dev_call`
#[repr(C)]
pub struct PioCmdTransferArgs {
    pub tx_ptr: *const u8,
    pub tx_len: u32,
    pub rx_ptr: *mut u8,
    pub rx_len: u32,
}

// PioRgbConfigureArgs removed — display config is module-internal

/// Arguments for `dev_system::REGISTER_PROVIDER` via `dev_call`.
///
/// Modules that want to act as providers for a device class pass this struct.
/// The dispatch function is called synchronously from kernel context during
/// dev_call dispatch for the registered class. It MUST NOT block or perform
/// async I/O. For hardware operations, start the operation and return
/// E_INPROGRESS; caller polls for completion.
#[repr(C)]
pub struct RegisterProviderArgs {
    /// Device class to provide (0x00..0x1F).
    pub device_class: u8,
    pub _pad: [u8; 3],
    /// Module's dispatch function pointer (with Thumb bit set).
    /// Signature: `fn(state: *mut u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32`
    pub dispatch_fn: u32,
}

/// Arguments for `dev_spi::OPEN` via `dev_call`
#[repr(C)]
pub struct SpiOpenArgs {
    pub cs_handle: i32,
    pub freq_hz: u32,
    pub bus: u8,
    pub mode: u8,
    pub _pad: [u8; 2],
}

/// Arguments for `dev_spi::TRANSFER_START` via `dev_call`
#[repr(C)]
pub struct SpiTransferStartArgs {
    pub tx: *const u8,
    pub rx: *mut u8,
    pub len: u32,
    pub fill: u8,
    pub _pad: [u8; 3],
}

/// Arguments for `dev_gpio::SET_MODE` via `dev_call`
#[repr(C)]
pub struct GpioSetModeArgs {
    pub mode: u8,
    pub initial_level: u8,
}

/// Channel opcodes (0x0500-0x05FF)
pub mod dev_channel {
    pub const OPEN: u32 = 0x0500;
    pub const CLOSE: u32 = 0x0501;
    pub const CONNECT: u32 = 0x0502;
    pub const READ: u32 = 0x0503;
    pub const WRITE: u32 = 0x0504;
    pub const POLL: u32 = 0x0505;
    pub const IOCTL: u32 = 0x0506;
    pub const SENDTO: u32 = 0x0507;
    pub const RECVFROM: u32 = 0x0508;
    pub const BIND: u32 = 0x0509;
    pub const LISTEN: u32 = 0x050A;
    pub const ACCEPT: u32 = 0x050B;
    pub const PORT: u32 = 0x050C;
}

/// Timer opcodes (0x0600-0x06FF)
pub mod dev_timer {
    pub const MILLIS: u32 = 0x0602;
    pub const MICROS: u32 = 0x0603;
    /// Create a timer fd. handle=-1. Returns tagged timer fd.
    pub const CREATE: u32 = 0x0604;
    /// Start/restart timer. handle=timer_fd, arg[0..4]=delay_ms (LE).
    pub const SET: u32 = 0x0605;
    /// Cancel timer. handle=timer_fd.
    pub const CANCEL: u32 = 0x0606;
    /// Destroy timer. handle=timer_fd.
    pub const DESTROY: u32 = 0x0607;
}

/// NetIF opcodes (0x0700-0x07FF)
pub mod dev_netif {
    pub const OPEN: u32 = 0x0700;
    pub const REGISTER_FRAME: u32 = 0x0701;
    pub const REGISTER_SOCKET: u32 = 0x0702;
    pub const CLOSE: u32 = 0x0703;
    pub const STATE: u32 = 0x0704;
    pub const IOCTL: u32 = 0x0705;
}

/// Socket opcodes (0x0800-0x08FF)
pub mod dev_socket {
    pub const OPEN: u32 = 0x0800;
    pub const CONNECT: u32 = 0x0801;
    pub const SEND: u32 = 0x0802;
    pub const RECV: u32 = 0x0803;
    pub const POLL: u32 = 0x0804;
    pub const CLOSE: u32 = 0x0805;
    /// Bind socket to local port. handle=socket, arg[0..2]=port (u16 LE).
    pub const BIND: u32 = 0x0806;
    /// Listen for incoming connections. handle=socket, arg[0..4]=backlog (i32 LE, optional).
    pub const LISTEN: u32 = 0x0807;
    /// Accept incoming connection. handle=socket (must be listening).
    /// Transforms the listening socket into the connected socket.
    pub const ACCEPT: u32 = 0x0808;

    // Socket service opcodes (0x0810-0x081F) — for IP stack module
    // These allow the IP stack module to service socket slots directly.
    /// Get socket slot info. handle=slot_idx, arg=*mut SocketServiceInfo.
    pub const SERVICE_INFO: u32 = 0x0810;
    /// Read from socket TX buffer. handle=slot_idx, arg=*mut u8, arg_len=buf_size.
    /// Returns bytes read.
    pub const SERVICE_TX_READ: u32 = 0x0811;
    /// Write to socket RX buffer. handle=slot_idx, arg=*const u8, arg_len=data_len.
    /// Returns bytes written.
    pub const SERVICE_RX_WRITE: u32 = 0x0812;
    /// Complete pending socket operation. handle=slot_idx.
    /// arg[0..4] = result (i32 LE), arg[4] = new_state (u8), arg[5] = poll_flags (u8, optional).
    pub const SERVICE_COMPLETE_OP: u32 = 0x0813;
    /// Set socket state. handle=slot_idx, arg[0] = state (u8), arg[1] = poll_flags (u8, optional).
    pub const SERVICE_SET_STATE: u32 = 0x0814;
    /// Get number of socket slots. handle=-1. Returns count.
    pub const SERVICE_COUNT: u32 = 0x0815;
}

/// Socket service info structure (returned by SERVICE_INFO).
/// Field values (type codes, states, operations) are defined by the
/// socket provider module — the kernel fills them from opaque slot data.
#[repr(C)]
pub struct SocketServiceInfo {
    /// Provider-defined type code (0=free)
    pub socket_type: u8,
    /// Provider-defined state value
    pub state: u8,
    /// Provider-defined pending operation code
    pub pending_op: u8,
    /// Padding
    pub _pad: u8,
    /// Local identifier (provider-defined)
    pub local_id: u16,
    /// Remote identifier (provider-defined)
    pub remote_id: u16,
    /// Remote endpoint identifier (provider-defined)
    pub remote_endpoint: u32,
    /// TX buffer bytes pending
    pub tx_pending: u16,
    /// RX buffer bytes available
    pub rx_available: u16,
    /// RX buffer free space
    pub rx_space: u16,
}

/// Filesystem opcodes (0x0900-0x09FF)
pub mod dev_fs {
    pub const OPEN: u32 = 0x0900;
    pub const READ: u32 = 0x0901;
    pub const SEEK: u32 = 0x0902;
    pub const CLOSE: u32 = 0x0903;
    pub const STAT: u32 = 0x0904;
}

/// Buffer opcodes (0x0A00-0x0AFF)
pub mod dev_buffer {
    pub const ACQUIRE_WRITE: u32 = 0x0A00;
    pub const RELEASE_WRITE: u32 = 0x0A01;
    pub const ACQUIRE_READ: u32 = 0x0A02;
    pub const RELEASE_READ: u32 = 0x0A03;
    pub const ACQUIRE_INPLACE: u32 = 0x0A04;
}

/// Event opcodes (0x0B00-0x0BFF)
pub mod dev_event {
    /// Create event. handle=-1, arg=unused. Returns event handle (>=0) or <0 on error.
    pub const CREATE: u32 = 0x0B00;
    /// Signal event. handle=event. Returns 0 or <0.
    pub const SIGNAL: u32 = 0x0B01;
    /// Poll event (non-blocking, clears signaled flag). handle=event.
    /// Returns 1 if was signaled (now cleared), 0 if not signaled, <0 on error.
    pub const POLL: u32 = 0x0B02;
    /// Destroy event and free slot. handle=event. Returns 0 or <0.
    pub const DESTROY: u32 = 0x0B03;
}

/// System opcodes (0x0C00-0x0CFF)
pub mod dev_system {
    /// Log message. handle=log_level, arg=message, arg_len=message length.
    pub const LOG: u32 = 0x0C40;
    /// Poll any fd. handle=fd, arg[0]=events mask. Returns poll result bitmask.
    pub const FD_POLL: u32 = 0x0C41;
    /// Non-blocking resource lock attempt.
    /// handle=-1, arg[0]=resource_id. Returns lock handle (>=0) or EBUSY.
    pub const RESOURCE_TRY_LOCK: u32 = 0x0C00;
    /// Release resource lock. handle=lock handle. Returns 0 or error.
    pub const RESOURCE_UNLOCK: u32 = 0x0C01;
    /// Flash sideband operation (internally acquires FLASH_XIP).
    /// handle=-1, arg[0]=operation kind. Returns result or EAGAIN.
    pub const FLASH_SIDEBAND: u32 = 0x0C10;
    /// Register a PIC module as provider for a device class.
    /// handle=-1, arg = RegisterProviderArgs. Returns 0 or error.
    pub const REGISTER_PROVIDER: u32 = 0x0C20;
    /// Unregister a module provider. handle=-1, arg[0]=device_class. Returns 0 or error.
    pub const UNREGISTER_PROVIDER: u32 = 0x0C21;
    /// Query stream time from first active PIO stream (handle=-1).
    /// Returns StreamTime struct. No PIO handle or ownership required.
    pub const STREAM_TIME: u32 = 0x0C30;
    /// Query graph-level sample rate. handle=-1. Returns u32 (0 = not set).
    pub const GRAPH_SAMPLE_RATE: u32 = 0x0C31;
    /// Query arena memory usage. handle=-1.
    /// Returns (used_bytes: u16, total_bytes: u16) packed as u32: (used << 16) | total.
    pub const ARENA_USAGE: u32 = 0x0C32;
    /// Query downstream latency for current module. handle=-1. Returns u32 frames.
    pub const DOWNSTREAM_LATENCY: u32 = 0x0C33;
    /// Report module's own processing latency in frames. handle=-1, arg[0..4]=frames (u32 LE).
    pub const REPORT_LATENCY: u32 = 0x0C50;
    /// Raw PWM pin enable: set pin funcsel to PWM (4), configure pad.
    /// handle=-1, arg[0]=pin. Returns 0 or error.
    pub const PWM_PIN_ENABLE: u32 = 0x0C60;
    /// Raw PWM pin disable: reset pin funcsel to NULL (31).
    /// handle=-1, arg[0]=pin. Returns 0 or error.
    pub const PWM_PIN_DISABLE: u32 = 0x0C61;
    /// Raw PWM slice register write.
    /// handle=-1, arg=[slice:u8, reg:u8, value:u32 LE] (6 bytes).
    /// Registers: 0=CSR, 1=DIV, 2=CTR, 3=CC, 4=TOP.
    pub const PWM_SLICE_WRITE: u32 = 0x0C62;
    /// Raw PWM slice register read.
    /// handle=-1, arg=[slice:u8, reg:u8] (2 bytes). Returns register value as i32.
    pub const PWM_SLICE_READ: u32 = 0x0C63;

    // --- Raw PIO register bridge (0x0C70-0x0C7F) ---
    // Generic PIO SM access. Module specifies pio_num (0/1/2) in every call.

    /// Force-execute an instruction on a PIO SM.
    /// handle=-1, arg=[pio:u8, sm:u8, instr:u16 LE] (4 bytes).
    pub const PIO_SM_EXEC: u32 = 0x0C70;
    /// Write a PIO SM register.
    /// handle=-1, arg=[pio:u8, sm:u8, reg:u8, value:u32 LE] (7 bytes).
    /// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL.
    pub const PIO_SM_WRITE_REG: u32 = 0x0C71;
    /// Read a PIO SM register.
    /// handle=-1, arg=[pio:u8, sm:u8, reg:u8] (3 bytes). Returns register value as i32.
    /// Registers: 0=CLKDIV, 1=EXECCTRL, 2=SHIFTCTRL, 3=PINCTRL, 4=ADDR.
    pub const PIO_SM_READ_REG: u32 = 0x0C72;
    /// Atomic multi-SM enable/disable.
    /// handle=-1, arg=[pio:u8, mask:u8, enable:u8] (3 bytes).
    pub const PIO_SM_ENABLE: u32 = 0x0C73;
    /// Allocate contiguous instruction slots.
    /// handle=-1, arg=[pio:u8, count:u8] (2 bytes). Returns origin as i32, or <0 error.
    pub const PIO_INSTR_ALLOC: u32 = 0x0C74;
    /// Write a single instruction to PIO instruction memory.
    /// handle=-1, arg=[pio:u8, addr:u8, instr:u16 LE] (4 bytes).
    pub const PIO_INSTR_WRITE: u32 = 0x0C75;
    /// Free instruction slots by mask.
    /// handle=-1, arg=[pio:u8, mask:u32 LE] (5 bytes).
    pub const PIO_INSTR_FREE: u32 = 0x0C76;
    /// Setup a GPIO pin for PIO use (funcsel + pad config).
    /// handle=-1, arg=[pin:u8, pio_num:u8, pull:u8] (3 bytes).
    /// pull: 0=none, 1=pull-down, 2=pull-up.
    pub const PIO_PIN_SETUP: u32 = 0x0C77;
    /// Set PIO GPIOBASE register.
    /// handle=-1, arg=[pio:u8, base16:u8] (2 bytes). base16: 0=GPIO 0-31, 1=GPIO 16-47.
    pub const PIO_GPIOBASE: u32 = 0x0C78;
    /// Write a 32-bit value to a PIO SM TX FIFO.
    /// handle=-1, arg=[pio:u8, sm:u8, value:u32 LE] (6 bytes).
    pub const PIO_TXF_WRITE: u32 = 0x0C79;
    /// Read PIO FSTAT register.
    /// handle=-1, arg=[pio:u8] (1 byte). Returns fstat as i32.
    pub const PIO_FSTAT_READ: u32 = 0x0C7A;
    /// SM restart + clock divider restart.
    /// handle=-1, arg=[pio:u8, mask:u8] (2 bytes).
    pub const PIO_SM_RESTART: u32 = 0x0C7B;

    // --- Raw DMA bridge (0x0C80-0x0C84) ---
    // Generic DMA channel access for PIC modules.

    /// Allocate a DMA channel. handle=-1, arg=[]. Returns channel number (i32) or <0.
    pub const DMA_ALLOC: u32 = 0x0C80;
    /// Free a DMA channel. handle=-1, arg=[ch:u8] (1 byte).
    pub const DMA_FREE: u32 = 0x0C81;
    /// Start a DMA transfer (non-blocking).
    /// handle=-1, arg=[ch:u8, read_addr:u32 LE, write_addr:u32 LE, count:u32 LE, dreq:u8, flags:u8] (15 bytes).
    /// flags: bit0=incr_read, bit1=incr_write, bit2=data_size (0=16-bit, 1=32-bit).
    pub const DMA_START: u32 = 0x0C82;
    /// Poll DMA channel busy status.
    /// handle=-1, arg=[ch:u8] (1 byte). Returns 1 if busy, 0 if done.
    pub const DMA_BUSY: u32 = 0x0C83;
    /// Abort a DMA transfer.
    /// handle=-1, arg=[ch:u8] (1 byte).
    pub const DMA_ABORT: u32 = 0x0C84;

    // --- DMA FD (0x0C85-0x0C88) ---
    // FD-wrapped DMA channels with fd_poll(POLL_IN) for non-blocking completion.

    /// Create a DMA FD: allocates CH8-15 channel, returns tagged fd.
    /// handle=-1, arg=[]. Returns tagged DMA fd or <0.
    pub const DMA_FD_CREATE: u32 = 0x0C85;
    /// Start a DMA transfer on a DMA FD (full configuration).
    /// handle=dma_fd, arg=[read_addr:u32 LE, write_addr:u32 LE, count:u32 LE, dreq:u8, flags:u8] (14 bytes).
    /// flags: bit0=incr_read, bit1=incr_write, bit2=data_size (0=16-bit, 1=32-bit).
    pub const DMA_FD_START: u32 = 0x0C86;
    /// Fast DMA re-trigger via AL3 registers (preserves write_addr/dreq/flags from start).
    /// handle=dma_fd, arg=[read_addr:u32 LE, count:u32 LE] (8 bytes).
    pub const DMA_FD_RESTART: u32 = 0x0C87;
    /// Free a DMA FD: frees both DMA channels, releases slot.
    /// handle=dma_fd, arg=[].
    pub const DMA_FD_FREE: u32 = 0x0C88;
    /// Queue next DMA transfer (ping-pong). Configures the inactive channel and
    /// sets CHAIN_TO on the active channel for zero-gap hardware handoff.
    /// handle=dma_fd, arg=[read_addr:u32 LE, count:u32 LE] (8 bytes).
    pub const DMA_FD_QUEUE: u32 = 0x0C89;

    // --- 9-bit SPI bit-bang (0x0C90) ---
    // Raw PAC GPIO bit-bang for display register init.

    /// Send a 9-bit SPI command + data block.
    /// handle=-1, arg=[cs:u8, sck:u8, sda:u8, cmd:u8, data_len:u8, data[0..data_len]].
    /// Total arg_len = 5 + data_len. Drives SIO pins directly via PAC.
    pub const SPI9_SEND: u32 = 0x0C90;

    /// Execute 9-bit SPI reset sequence.
    /// handle=-1, arg=[rst:u8, cs:u8, sck:u8, sda:u8] (4 bytes).
    /// RST high 20ms → low 20ms → high 200ms, then inits SIO pins.
    pub const SPI9_RESET: u32 = 0x0C91;

    /// Set 9-bit SPI CS pin level explicitly.
    /// handle=-1, arg=[cs_pin:u8, level:u8] (2 bytes). level: 0=low, 1=high.
    /// Used to hold CS low across delays (e.g. SLEEP_OUT 120ms).
    pub const SPI9_CS_SET: u32 = 0x0C92;

    // --- Runtime parameter store (0x0C34-0x0C36) ---

    /// Store a runtime parameter override (persists across reboots).
    /// handle=-1, arg=[tag:u8, value_bytes...], arg_len=1+value_len.
    /// Scoped to current module instance. Returns 0 or negative errno.
    pub const PARAM_STORE: u32 = 0x0C34;
    /// Delete a runtime parameter override (reverts to compiled default).
    /// handle=-1, arg=[tag:u8], arg_len=1.
    /// Scoped to current module instance. Returns 0 or negative errno.
    pub const PARAM_DELETE: u32 = 0x0C35;
    /// Clear all runtime overrides for current module (arg_len=0) or
    /// global factory reset (arg[0]=0xFF). handle=-1.
    pub const PARAM_CLEAR_ALL: u32 = 0x0C36;

    // --- Flash store bridge (0x0C37-0x0C39) ---

    /// Register flash store dispatch function. Called by flash module on init.
    /// handle=-1, arg=[fn_addr:u32 LE] (4 bytes). Kernel stores fn ptr + module state.
    /// Returns 0 or negative errno.
    pub const FLASH_STORE_ENABLE: u32 = 0x0C37;
    /// Raw flash erase: erase 4KB sector (restricted to runtime store bounds).
    /// handle=-1, arg=[offset:u32 LE] (4 bytes). Returns 0 or negative errno.
    pub const FLASH_RAW_ERASE: u32 = 0x0C38;
    /// Raw flash program: program 256B page (restricted to runtime store bounds).
    /// handle=-1, arg=[offset:u32 LE, data:256 bytes] (260 bytes). Returns 0 or negative errno.
    pub const FLASH_RAW_PROGRAM: u32 = 0x0C39;

    // --- Module arena (0x0C3A) ---

    /// Get module's arena allocation. handle=-1, arg=[out_ptr:*mut *mut u8] (4 bytes).
    /// Returns arena size in bytes (0 if no arena allocated).
    pub const ARENA_GET: u32 = 0x0C3A;
}

/// Flash sideband operation kinds
pub mod flash_sideband_op {
    /// Read QSPI CS pin level (BOOTSEL button). Returns 0 or 1.
    pub const READ_CS: u8 = 0;
    /// Read flash via XIP. arg=[offset:u32 LE], kernel writes data at arg[4..].
    /// Returns bytes copied or negative error.
    pub const XIP_READ: u8 = 1;
}

/// Runtime parameter store constants.
///
/// The store occupies the last 4KB sector of 4MB flash. Log-structured
/// append with TLV v2-compatible entries scoped per (module_id, tag).
/// At boot, overrides are merged into compiled params before module_new().
pub mod runtime_store {
    /// Flash offset (from 0x10000000) of the runtime store sector.
    pub const OFFSET: u32 = 0x003F_F000;
    /// Size of the runtime store sector in bytes.
    pub const SIZE: usize = 4096;
    /// Sector header magic ("FXPS" little-endian).
    pub const MAGIC: u32 = 0x4650_5846;
    /// Sector format version.
    pub const VERSION: u8 = 1;
}

/// UART opcodes (0x0D00-0x0DFF)
pub mod dev_uart {
    pub const OPEN: u32 = 0x0D00;
    pub const CLOSE: u32 = 0x0D01;
    pub const WRITE: u32 = 0x0D02;
    pub const READ: u32 = 0x0D03;
    pub const POLL: u32 = 0x0D04;
    pub const CONFIGURE: u32 = 0x0D05;
}

/// ADC opcodes (0x0E00-0x0EFF)
pub mod dev_adc {
    pub const OPEN: u32 = 0x0E00;
    pub const CLOSE: u32 = 0x0E01;
    pub const READ: u32 = 0x0E02;
    pub const POLL: u32 = 0x0E03;
    pub const CONFIGURE: u32 = 0x0E04;
}

/// PWM opcodes (0x0F00-0x0FFF)
///
/// Hardware PWM output on GPIO pins. Each pin maps to a PWM slice and channel:
/// slice = pin / 2, channel = A (even pins) or B (odd pins).
///
/// OPEN: arg[0] = pin number → returns handle (slot index)
/// CONFIGURE: arg = [top:u16 LE, div_int:u8, div_frac:u8] (4 bytes)
/// SET_DUTY: arg = [duty:u16 LE] (2 bytes), duty range 0..=top
/// GET_DUTY: returns current duty cycle value
/// CLOSE: release PWM handle and reset pin
pub mod dev_pwm {
    pub const OPEN: u32 = 0x0F00;
    pub const CLOSE: u32 = 0x0F01;
    pub const CONFIGURE: u32 = 0x0F02;
    pub const SET_DUTY: u32 = 0x0F03;
    pub const GET_DUTY: u32 = 0x0F04;
}

/// Query keys for dev_query
pub mod dev_query_key {
    /// Device class (returns u8)
    pub const CLASS: u32 = 1;
    /// Human-readable name (returns null-terminated string)
    pub const NAME: u32 = 2;
    /// Capability bitfield (returns u32, class-specific)
    pub const CAPABILITIES: u32 = 3;
    /// Current state (returns u8, class-specific)
    pub const STATE: u32 = 4;
    /// Error count since last reset (returns u32)
    pub const ERROR_COUNT: u32 = 5;
}

// ============================================================================
// Module ABI
// ============================================================================

// Module ABI (v3):
//
// module_new(in_chan, out_chan, ctrl_chan, params, params_len, state, state_size, syscalls) -> i32
//
// Channels:
//   in_chan   - Data input channel (from upstream module)
//   out_chan  - Data output channel (to downstream module)
//   ctrl_chan - Control input channel (for gesture/command events)
//
// All channels are -1 if not connected.
// params is purely module-specific config (from YAML).
// Each module defines its own #[repr(C)] struct to interpret params bytes.
//
// Control events use the standard format:
//   { target_frame: u32, command: u8, control_id: u8, param: u16 } (8 bytes)
//   Commands: 0x01=Toggle, 0x10=Next, 0x11=Prev, 0x12=Select
//
// Multi-port (ABI v2):
//   Modules with multiple inputs/outputs discover extra ports via channel_port() syscall.
//   port_type: 0=in, 1=out, 2=ctrl. index 0 = primary (same as in_chan/out_chan/ctrl_chan).
