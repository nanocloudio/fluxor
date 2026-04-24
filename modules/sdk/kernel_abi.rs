// Kernel ABI — core primitives every module can rely on.
//
// Layer: kernel_abi (public, stable).
//
// Contents: syscall table, poll flags, error codes, and the explicit
// typed namespaces for channel / timer / buffer / event / core-system
// primitives. Hardware contracts live in `contracts/hal/*`; domain
// protocols live in `contracts/{net,storage}/*`; kernel-private
// orchestration lives in `internal/*`; chip-specific raw registers
// live in `platform/*`.
//
// This file is `include!`'d by `abi.rs` into `pub mod kernel_abi`.

/// ABI version number. Single version — there is no backwards
/// compatibility layer. Every module is built against the current
/// `SyscallTable` shape, which is `channel_*` + `heap_*` +
/// `provider_open`/`call`/`query`/`close`.
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
/// Accessible via `provider_query(handle, STREAM_TIME, ...)`. `t0_micros`
/// is captured on first push, not at alloc/init. See
/// `docs/architecture/timing.md` for usage patterns.
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

/// Syscall function-pointer table handed to every PIC module at init.
///
/// All provider dispatch goes through the handle-scoped
/// `provider_open` / `provider_call` / `provider_query` / `provider_close`
/// quartet. Channel I/O and heap are direct typed syscalls. Handles
/// returned by `provider_open` are tracked against their contract;
/// subsequent calls route via the bound contract's vtable. Tagged fds
/// (event / timer / DMA-fd) self-identify via their high-bit tag. Global
/// `handle = -1` ops and scheduler-assigned channel fds route by the
/// opcode's contract bits.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallTable {
    pub version: u32,
    /// Read from a channel. Returns bytes read, 0 on empty, <0 on error.
    pub channel_read: unsafe extern "C" fn(handle: i32, buf: *mut u8, len: usize) -> i32,
    /// Write to a channel. Returns bytes written, 0 on full, <0 on error.
    pub channel_write: unsafe extern "C" fn(handle: i32, data: *const u8, len: usize) -> i32,
    /// Poll a channel for readiness. Returns bitmask of ready events.
    pub channel_poll: unsafe extern "C" fn(handle: i32, events: u32) -> i32,

    /// Allocate memory from this module's heap arena.
    /// Returns pointer to allocated memory, or null on failure.
    /// Size is rounded up to 16-byte alignment internally.
    pub heap_alloc: unsafe extern "C" fn(size: u32) -> *mut u8,

    /// Free memory returned by heap_alloc. Passing null is a no-op;
    /// invalid pointers are detected and logged by the kernel.
    pub heap_free: unsafe extern "C" fn(ptr: *mut u8),

    /// Reallocate memory. Returns new pointer or null on failure.
    /// If null is returned, the original allocation is unchanged.
    pub heap_realloc: unsafe extern "C" fn(ptr: *mut u8, new_size: u32) -> *mut u8,

    /// Open a handle on the named contract with a specific open-style
    /// operation. Returns handle (>= 0) on success, negative errno on
    /// failure. `open_op` is the contract opcode that produces a
    /// handle (e.g. `gpio::CLAIM`, `gpio::SET_INPUT`, `spi::OPEN`,
    /// `timer::CREATE`); `config` / `config_len` are its arg payload.
    pub provider_open: unsafe extern "C" fn(
        contract: u32, open_op: u32, config: *const u8, config_len: usize,
    ) -> i32,

    /// Invoke an operation on a handle from `provider_open`, or a global
    /// op with `handle = -1`. The kernel looks up the handle's bound
    /// contract (when tracked) and routes to its vtable; for untracked
    /// handles and globals the opcode's high byte identifies the contract.
    pub provider_call: unsafe extern "C" fn(
        handle: i32, op: u32, arg: *mut u8, arg_len: usize,
    ) -> i32,

    /// Query introspection state on a handle. See `kernel_abi::query_key`
    /// for well-known keys.
    pub provider_query: unsafe extern "C" fn(
        handle: i32, key: u32, out: *mut u8, out_len: usize,
    ) -> i32,

    /// Release a handle, invoking the contract's close hook if any.
    pub provider_close: unsafe extern "C" fn(handle: i32) -> i32,
}

/// Poll event flags (used with `handle_poll` / `channel_poll`).
/// These values are part of the stable ABI — modules hardcode them.
pub mod poll {
    /// Data available for reading.
    pub const IN: u32 = 0x01;
    /// Space available for writing.
    pub const OUT: u32 = 0x02;
    /// Error condition.
    pub const ERR: u32 = 0x04;
    /// Hang-up (peer closed / end-of-stream).
    pub const HUP: u32 = 0x08;
    /// Connection established.
    pub const CONN: u32 = 0x10;
}

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

// ─────────────────────────────────────────────────────────────────────
// Channel primitive
// ─────────────────────────────────────────────────────────────────────
//
// The channel ring-buffer contract. `channel_read` / `channel_write` /
// `channel_poll` are direct syscalls on the SyscallTable; the opcodes
// below are reserved for the control plane (open/close/bind/listen/
// accept) and for ioctl sideband.
//
// Channel ioctl commands (stable ABI values, passed in the ioctl `cmd`
// parameter rather than as opcodes):
//   1 = SET_U32:  store auxiliary u32 value (arg: *const u32)
//                 Use case: seek position, file index, producer signal
//   2 = GET_U32:  atomic read-and-clear of auxiliary u32 (arg: *mut u32)
//                 Returns OK if value was pending, EAGAIN if not
//   3 = FLUSH:    clear ring buffer and reset flags
//   4 = SET_HUP:  set HUP flag (detected via handle_poll with poll::HUP)
pub mod channel {
    pub const OPEN: u32 = 0x0500;
    pub const CLOSE: u32 = 0x0501;
    pub const CONNECT: u32 = 0x0502;
    pub const READ: u32 = 0x0503;
    pub const WRITE: u32 = 0x0504;
    pub const POLL: u32 = 0x0505;
    pub const IOCTL: u32 = 0x0506;
    /// Bind a module-provided ioctl handler to this channel.
    /// Arg layout: `{ state_ptr: u64 LE, handler_fn: u64 LE }` (16 B).
    /// Any `channel_ioctl` cmd not handled by the kernel's built-in set
    /// (NOTIFY / POLL_NOTIFY / FLUSH / SET_HUP) is forwarded to
    /// `handler_fn(state_ptr, cmd, arg)`. `handler_fn = 0` clears.
    pub const REGISTER_IOCTL: u32 = 0x0507;
    pub const BIND: u32 = 0x0509;
    pub const LISTEN: u32 = 0x050A;
    pub const ACCEPT: u32 = 0x050B;
    pub const PORT: u32 = 0x050C;
}

// ─────────────────────────────────────────────────────────────────────
// Timer primitive
// ─────────────────────────────────────────────────────────────────────
pub mod timer {
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

// ─────────────────────────────────────────────────────────────────────
// Buffer primitive (zero-copy slot acquisition)
// ─────────────────────────────────────────────────────────────────────
pub mod buffer {
    pub const ACQUIRE_WRITE: u32 = 0x0A00;
    pub const RELEASE_WRITE: u32 = 0x0A01;
    pub const ACQUIRE_READ: u32 = 0x0A02;
    pub const RELEASE_READ: u32 = 0x0A03;
    pub const ACQUIRE_INPLACE: u32 = 0x0A04;
}

// ─────────────────────────────────────────────────────────────────────
// Event primitive (single-bit ISR→module wake signal)
// ─────────────────────────────────────────────────────────────────────
pub mod event {
    /// Create event. handle=-1, arg=unused. Returns event handle (>=0) or <0 on error.
    pub const CREATE: u32 = 0x0B00;
    /// Signal event. handle=event. Returns 0 or <0.
    pub const SIGNAL: u32 = 0x0B01;
    /// Poll event (non-blocking, clears signaled flag). handle=event.
    /// Returns 1 if was signaled (now cleared), 0 if not signaled, <0 on error.
    pub const POLL: u32 = 0x0B02;
    /// Destroy event and free slot. handle=event. Returns 0 or <0.
    pub const DESTROY: u32 = 0x0B03;
    /// Bind an event handle to a hardware IRQ number.
    /// handle=event_handle, arg=[irq_number:u32 LE], arg_len=4.
    /// The kernel signals the event when the IRQ fires (ISR-safe).
    pub const BIND_IRQ: u32 = 0x0C51;
}

// ─────────────────────────────────────────────────────────────────────
// Core system primitives
// ─────────────────────────────────────────────────────────────────────
//
// Opcodes that every module may invoke — logging, random, handle poll,
// own-arena queries, timing queries. These are the "syscalls" of the
// ABI. Anything that only infrastructure modules touch (fault monitor,
// reconfigure, bridge) lives in `internal/*` instead.

/// Log message. handle=log_level, arg=message, arg_len=message length.
pub const LOG_WRITE: u32 = 0x0C40;
/// Poll any handle. handle=fd, arg[0]=events mask. Returns poll result bitmask.
pub const HANDLE_POLL: u32 = 0x0C41;

/// Query stream time via `provider_query`. `handle=-1` returns the
/// first active PIO stream's StreamTime (delegated to HAL_PIO
/// internally — no PIO handle or ownership required by the caller).
/// `handle=<stream>` returns that specific stream's time. Returns a
/// 24-byte StreamTime struct.
pub const STREAM_TIME: u32 = 0x0C30;
/// Query graph-level sample rate. handle=-1. Returns u32 (0 = not set).
pub const GRAPH_SAMPLE_RATE: u32 = 0x0C31;
/// Query downstream latency for current module. handle=-1. Returns u32 frames.
pub const DOWNSTREAM_LATENCY: u32 = 0x0C33;
/// Report module's own processing latency in frames. handle=-1, arg[0..4]=frames (u32 LE).
pub const REPORT_LATENCY: u32 = 0x0C50;

/// Get module's arena allocation. handle=-1, arg=[out_ptr:*mut *mut u8] (4 bytes).
/// Returns arena size in bytes (0 if no arena allocated).
pub const ARENA_GET: u32 = 0x0C3A;

/// Fill buffer with cryptographically secure random bytes.
/// handle=-1, arg=output buffer, arg_len=requested byte count.
/// Returns bytes written (== arg_len) on success, or negative errno.
/// Source: TRNG/ROSC on RP, timer hash on BCM2712, getrandom on Linux.
pub const RANDOM_FILL: u32 = 0x0C3C;

/// Query system clock frequency in Hz. handle=-1. Returns u32 (e.g. 125_000_000).
pub const SYS_CLOCK_HZ: u32 = 0x0C3B;

/// Query the calling module's own scheduler index. handle=-1, no arg.
/// Returns u8 (0..MAX_MODULES-1) on success, negative errno on failure.
/// Used by anchors / workers to render `mod=<idx>` in MON_SESSION
/// telemetry lines. Distinct from `internal::reconfigure::SELF_INDEX`
/// (0x0C67), which is gated by the `reconfigure` permission and is
/// only meant for orchestration modules.
pub const SELF_INDEX: u32 = 0x0C42;

/// Read the hardware-provisioned ethernet MAC address from platform
/// sources (on bcm2712, the DTB passed by Pi 5 firmware). handle=-1,
/// arg=output buffer of exactly 6 bytes. Returns 6 on success, or
/// negative errno (ENODEV) if no MAC is available.
pub const GET_HW_ETHERNET_MAC: u32 = 0x0C3D;

/// Get paged arena info. handle=-1, arg=20-byte output buffer.
/// Returns: [base_vaddr:u64 LE, virtual_size:u64 LE, status:u32 LE].
/// status: 0=no arena, 1=active.
pub const PAGED_ARENA_GET: u32 = 0x0CF8;
/// Prefault pages into paged arena. handle=-1, arg=[offset_pages:u32 LE, count:u32 LE] (8 bytes).
/// Returns number of pages prefaulted.
pub const PAGED_ARENA_PREFAULT: u32 = 0x0CFA;

// ─────────────────────────────────────────────────────────────────────
// Provider query keys
// ─────────────────────────────────────────────────────────────────────
//
// Uniform introspection surface for `provider_query`. Contracts may
// define additional keys in a contract-specific numeric range.
pub mod query_key {
    /// Contract id (returns u8)
    pub const CLASS: u32 = 1;
    /// Human-readable name (returns null-terminated string)
    pub const NAME: u32 = 2;
    /// Capability bitfield (returns u32, contract-specific)
    pub const CAPABILITIES: u32 = 3;
    /// Current state (returns u8, contract-specific)
    pub const STATE: u32 = 4;
    /// Error count since last reset (returns u32)
    pub const ERROR_COUNT: u32 = 5;
    /// Heap statistics (returns HeapStats struct, 16 bytes).
    /// handle=-1 queries the calling module's heap.
    pub const HEAP_STATS: u32 = 6;
    /// Fault statistics (returns FaultStats struct, 12 bytes).
    /// handle=-1 queries the calling module, handle=N queries module N.
    pub const FAULT_STATS: u32 = 7;
}

// ─────────────────────────────────────────────────────────────────────
// Module ABI
// ─────────────────────────────────────────────────────────────────────
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
// Multi-port:
//   Modules with multiple inputs/outputs discover extra ports via the
//   channel::PORT opcode. port_type: 0=in, 1=out, 2=ctrl.
//   index 0 = primary (same as in_chan/out_chan/ctrl_chan).
