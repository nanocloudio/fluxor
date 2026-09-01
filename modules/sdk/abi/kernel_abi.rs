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
// Vocabulary note (F11): the POSIX-derived low-level
// terms here — `fd` (tagged handle), `errno` (negative error code), poll
// flags — are RETAINED deliberately. They are universally-understood OS
// primitives at the kernel/module boundary, not orchestrator (K8s/OCI)
// vocabulary; nativizing them would churn the whole ABI for no architectural
// gain. Higher-level orchestration vocabulary is native Fluxor (`owner`,
// `workload`, `lease`, `posture`, `endpoint`); K8s terms stay in nanocloud.
//
// This file is `include!`'d by `abi.rs` into `pub mod kernel_abi`.

/// ABI version exposed via `SyscallTable.version` (u32 for layout
/// reasons). Widened from the on-disk `wire::ABI_VERSION` byte so
/// every consumer sees the same value.
pub const ABI_VERSION: u32 = super::wire::ABI_VERSION as u32;

/// Default channel buffer size in bytes.
/// Referenced by kernel (buffer_pool, scheduler fan buffer) and modules
/// (I2S input buffer, mixer sample buffer) to stay in sync. Sized to
/// hold one ZX Spectrum ZVFF packet (6924 B) plus framing in a single
/// channel write — byte-stream parsers see message boundaries at fixed
/// offsets rather than scrambling across fragments. Embedded targets
/// (rp2040 16 KiB arena, rp2350 32 KiB) constrain the upper bound;
/// channels needing more should request it via `module_channel_hints`
/// rather than raising this default.
pub const CHANNEL_BUFFER_SIZE: usize = 8192;

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
        contract: u32,
        open_op: u32,
        config: *const u8,
        config_len: usize,
    ) -> i32,

    /// Invoke an operation on a handle from `provider_open`, or a global
    /// op with `handle = -1`. The kernel looks up the handle's bound
    /// contract (when tracked) and routes to its vtable; for untracked
    /// handles and globals the opcode's high byte identifies the contract.
    pub provider_call:
        unsafe extern "C" fn(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32,

    /// Query introspection state on a handle. See `kernel_abi::query_key`
    /// for well-known keys.
    pub provider_query:
        unsafe extern "C" fn(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32,

    /// Release a handle, invoking the contract's close hook if any.
    pub provider_close: unsafe extern "C" fn(handle: i32) -> i32,

    /// Copy up to `len` bytes from the head of a FIFO channel into
    /// `buf` WITHOUT advancing the read pointer. Returns the number
    /// of bytes copied (0 if empty), or a negative errno (`EINVAL`
    /// for null buf, mailbox channels, or invalid handles).
    ///
    /// Used by frame-aware consumers that need to inspect a header
    /// (e.g. message type + payload length + conn_id) before
    /// committing to consume the frame. Lets the consumer leave a
    /// non-deliverable frame on the channel so the producer's
    /// flow-control kicks in instead of the consumer silently
    /// dropping bytes.
    ///
    /// Mailbox channels are not peekable (the payload is delivered
    /// as an opaque buffer reference, not a byte stream); peek
    /// returns `EINVAL` on those.
    pub channel_peek: unsafe extern "C" fn(handle: i32, buf: *mut u8, len: usize) -> i32,
    /// Producer-side telemetry enabled gate (`rfc_observability_surface.md`
    /// §5.1). Points at a kernel-published `u32` that is non-zero when at least
    /// one telemetry consumer is subscribed. The `dev_telemetry_*` helpers read
    /// it (a plain single-word load, no trap) before building a record, so
    /// instrumentation is zero-cost when nothing is collecting.
    ///
    /// Null means "cannot check", NOT "disabled": a table without the word
    /// (the wasm host, an isolated module whose protection domain does not map
    /// kernel memory) emits unconditionally and lets the ring drop when no
    /// consumer is subscribed. Losing the optimisation is the safe failure;
    /// losing the records is not.
    pub telemetry_enabled: *const u32,

    /// Call an instance-keyed provider selected by name (`sel`, a short
    /// volume string). The contract is the opcode's class byte, as on the
    /// `handle = -1` path — so the `mount` policy module names the target
    /// volume inline on every op, resolved by the shared
    /// `provider_selector::hash`. `op_handle` carries the op's OWN handle
    /// (`-1` for open-style ops, or a provider-local slot for handle-bound
    /// ops); `sel` is purely routing. Returns the provider's result, or
    /// `EINVAL` / `ENODEV` (no registered layer carries that selector).
    pub provider_call_sel: unsafe extern "C" fn(
        sel: *const u8,
        sel_len: usize,
        op_handle: i32,
        op: u32,
        arg: *mut u8,
        arg_len: usize,
    ) -> i32,
}

// SAFETY: `SyscallTable` was auto-`Sync` before the `telemetry_enabled` raw
// pointer was added (it is otherwise `fn` pointers + a `u32`). The table is
// immutable after construction and shared by `&`-reference — the wasm runtime
// holds it in a `static` (`WASM_SYSCALLS`), and the kernel hands out a shared
// pointer to every module across cores. `telemetry_enabled` points at a
// kernel-owned word that is only ever READ through this pointer (a benign
// single-word load; the kernel writes it atomically), never written here — so
// sharing the table across threads/cores is sound.
unsafe impl Sync for SyscallTable {}

// Positional `repr(C)` ABI ratchet. `SyscallTable` is the load-bearing
// kernel<->module boundary: modules call through it by field *offset*, not
// by name. Reordering, inserting, or removing a field silently breaks any
// module built against a different layout (it jumps through the wrong
// function pointer). These asserts pin the layout so any such change fails
// the build. New fields are only ever APPENDED at the end (never inserted or
// reordered), so a module built against an older, shorter layout keeps every
// offset it knows and simply never reaches the new tail slots — a
// backward-compatible extension, not a version break. Layout is one `u32` slot
// (version, padded to pointer width), 11 function pointers, a telemetry gate
// pointer, and 1 provider-instance routing pointer = 14 pointer-sized slots,
// which holds on both 64-bit (native) and 32-bit wasm builds.
const _: () = {
    // Every positional field is pinned, not just the first/last + size — a
    // size-preserving reorder (e.g. swapping channel_read and channel_write)
    // would otherwise compile while breaking every module.
    let p = core::mem::size_of::<usize>();
    assert!(core::mem::offset_of!(SyscallTable, version) == 0);
    assert!(core::mem::offset_of!(SyscallTable, channel_read) == p);
    assert!(core::mem::offset_of!(SyscallTable, channel_write) == p * 2);
    assert!(core::mem::offset_of!(SyscallTable, channel_poll) == p * 3);
    assert!(core::mem::offset_of!(SyscallTable, heap_alloc) == p * 4);
    assert!(core::mem::offset_of!(SyscallTable, heap_free) == p * 5);
    assert!(core::mem::offset_of!(SyscallTable, heap_realloc) == p * 6);
    assert!(core::mem::offset_of!(SyscallTable, provider_open) == p * 7);
    assert!(core::mem::offset_of!(SyscallTable, provider_call) == p * 8);
    assert!(core::mem::offset_of!(SyscallTable, provider_query) == p * 9);
    assert!(core::mem::offset_of!(SyscallTable, provider_close) == p * 10);
    assert!(core::mem::offset_of!(SyscallTable, channel_peek) == p * 11);
    assert!(core::mem::offset_of!(SyscallTable, telemetry_enabled) == p * 12);
    assert!(core::mem::offset_of!(SyscallTable, provider_call_sel) == p * 13);
    assert!(core::mem::size_of::<SyscallTable>() == p * 14);
};

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
    /// Capacity denial — a resource-ledger pool or budget is exhausted.
    /// Distinct from `ENOMEM` (allocator failure): the request was
    /// well-formed and the denial is accounted (pool `denials` counter,
    /// PSTATUS `POOL` records).
    pub const ENOSPC: i32 = -28;
    /// Argument list / output buffer too long — caller should retry
    /// with a larger buffer. Used by FS_READDIR when one entry
    /// doesn't fit and no progress could be made.
    pub const E2BIG: i32 = -7;
    /// Entry already exists. `LINK` against a name that is taken.
    pub const EEXIST: i32 = -17;
    /// Target is a directory. `LINK` against one, and `UNLINK` against one
    /// on a provider that separates directory removal into `RMDIR`.
    pub const EISDIR: i32 = -21;
    /// Cross-device link: the two paths are not on the same volume, so no
    /// second name can reference the same file.
    pub const EXDEV: i32 = -18;
    /// Directory not empty. `RMDIR` against a directory that still holds
    /// entries; the check is the provider's, because a caller's enumeration
    /// only describes the moment it looked.
    pub const ENOTEMPTY: i32 = -39;
    /// No such process / no such context. Answered by
    /// [`query_key::CALLER_OWNER`] when nothing is on the provider stack —
    /// there is no requester to name, which is a different statement from
    /// "the requester is the system owner".
    pub const ESRCH: i32 = -3;
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

    /// No such entry. A lookup that found nothing, as distinct from one
    /// that could not be performed.
    pub const ENOENT: i32 = -2;

    /// The caller's buffer is too small, and the call has written the
    /// exact requirement into the layout's `*_len_out` field.
    ///
    /// Distinct from `ENOSPC` (the STORE is full) and from `EINVAL` (the
    /// request was wrong). This one says the request was right and the
    /// caller should resize — a caller that cannot tell those apart either
    /// gives up on a recoverable call or retries an unrecoverable one
    /// forever.
    pub const ERANGE: i32 = -34;
    /// A value is too large for the width the caller asked it in. Used by
    /// FS_STAT when a file's size does not fit the 32-bit output form, so
    /// the caller learns to ask again with a wider buffer rather than
    /// receiving a clamped number it cannot distinguish from a real one.
    pub const EOVERFLOW: i32 = -75;
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
/// The `timer::TRUSTED_UNIX` observation record.
pub mod trusted_time {
    /// Encoded length of the record.
    pub const LEN: usize = 8 + 4 + 4 + 8 + 8 + 1 + 1 + 2;

    /// Field offsets within the record.
    pub const OFF_UNIX_SECONDS: usize = 0;
    pub const OFF_UNIX_NANOS: usize = 8;
    pub const OFF_UNCERTAINTY_MS: usize = 12;
    pub const OFF_MONOTONIC_US: usize = 16;
    pub const OFF_SOURCE_EPOCH: usize = 24;
    pub const OFF_SOURCE_CLASS: usize = 32;
    pub const OFF_FLAGS: usize = 33;

    /// Where the observation came from. Ordered by how much it is worth, so
    /// a policy can say "at least this" rather than enumerate.
    pub mod source {
        /// No time source at all. `unix_seconds` is meaningless.
        pub const UNAVAILABLE: u8 = 0;
        /// A counter running since boot with no absolute reference.
        pub const FREE_RUNNING: u8 = 1;
        /// A local real-time clock, never externally checked.
        pub const RTC: u8 = 2;
        /// Synchronised against a network time source.
        pub const NETWORK_SYNC: u8 = 3;
        /// Signed by an authority whose signature was verified.
        pub const SIGNED_AUTHORITY: u8 = 4;
    }

    /// What is known about the observation.
    pub mod flags {
        /// The source has been synchronised at least once.
        pub const SYNCHRONIZED: u8 = 0x01;
        /// The deployment's policy accepts this source for security
        /// decisions. A provider sets it; a consumer does not infer it.
        pub const TRUSTED: u8 = 0x02;
        /// The source moved backwards, or its epoch advanced unexpectedly.
        /// A consumer holding decisions cached under an earlier epoch must
        /// discard them.
        pub const ROLLBACK_SUSPECT: u8 = 0x04;
    }
}

pub mod timer {
    pub const MILLIS: u32 = 0x0602;
    pub const MICROS: u32 = 0x0603;
    /// Wall-clock milliseconds since the Unix epoch (0 if the platform has no RTC).
    /// Distinct from MILLIS (monotonic uptime).
    ///
    /// A bare number, and it cannot say whether it is trustworthy: zero means
    /// "no RTC" but every other value is indistinguishable from a good one,
    /// including one from a clock that was never synchronised or has just
    /// been stepped backwards. Suitable for timestamps a human reads and for
    /// cache ages; NOT suitable for deciding whether a credential is still
    /// valid. Use `TRUSTED_UNIX` for that. handle=-1, arg=[u64 LE].
    pub const UNIX_MILLIS: u32 = 0x0608;

    /// A security-grade time observation: what time it is, and what is known
    /// about how much that is worth.
    ///
    /// Not a second version of `UNIX_MILLIS` — a different question.
    /// `UNIX_MILLIS` answers "what time is it"; this answers "what may I
    /// conclude from it", which is what a credential decision actually needs
    /// and what a bare `u64` structurally cannot carry. Every expiry, replay
    /// window, certificate lifetime and key-retirement decision is a
    /// statement about time, and on a board with no RTC each of them is
    /// currently being made against a number that may be zero or may be
    /// wrong with no way to tell the two apart.
    ///
    /// `handle=-1`, `arg` receives `trusted_time::LEN` bytes:
    ///
    /// ```text
    /// [unix_seconds: u64 LE]
    /// [unix_nanos:   u32 LE]
    /// [uncertainty_ms: u32 LE]   — half-width of the confidence interval
    /// [monotonic_us: u64 LE]     — read at the SAME instant, so a caller
    ///                              can measure elapsed time without
    ///                              re-reading a wall clock that may step
    /// [source_epoch: u64 LE]     — increments on every step or resync
    /// [source_class: u8]         — see `trusted_time::source`
    /// [flags: u8]                — see `trusted_time::flags`
    /// [_reserved: u16]
    /// ```
    ///
    /// `source_epoch` is what makes rollback detectable: a consumer stamps a
    /// cached decision with the epoch it was made under and invalidates the
    /// decision when the epoch moves. Without it a clock that goes backwards
    /// and comes forward again is invisible.
    pub const TRUSTED_UNIX: u32 = 0x0609;
    /// Create a timer fd. handle=-1. Returns tagged timer fd.
    ///
    /// A timer is an fd in every sense that matters: `SET` arms it, the
    /// generic fd `POLL` reports `POLL_IN` once it has fired, and the KERNEL
    /// steps the owning module when it fires — the owner's wake bit latches
    /// exactly as an event's does, once per arming, and the earliest armed
    /// timer bounds the pacer's sleep, relaxed idle backstop included. So a
    /// module that arms 5 ms is stepped at ~5 ms on an idle domain whose
    /// backstop is 50 ms, not at 50: a module waits on its timer rather than
    /// polling the clock on a tick it does not control.
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
/// Write raw bytes to the platform debug serial sink (binary-safe, unlike
/// LOG_WRITE which UTF-8-filters). arg=bytes, arg_len=count. Returns bytes
/// accepted. The telemetry `transport_buffer` sink; `platform_raw`-gated. 0x0C66 is
/// the slot the dispatch comment reserves for "raw UART / USB writes", beside
/// LOG_RING_DRAIN (0x0C64) / FAN_DIAG_SNAPSHOT (0x0C65).
pub const SERIAL_WRITE: u32 = 0x0C66;
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

/// Report this module's `StepEffect` for the current scheduler pass (RFC
/// adaptive_tick_extra §6.1). handle=-1, arg[0]=effect code (u8):
///   0=Idle, 1=Waiting, 2=WorkDone, 3=RunnableBacklog, 4=Burst.
/// WorkDone/RunnableBacklog/Burst keep the adaptive pacer hot WITHOUT
/// authorising an immediate same-module re-step (that stays `StepOutcome::Burst`
/// only). Idle/Waiting do not heat the pacer. A no-permission core primitive;
/// a module that never calls it is treated as `Idle`.
pub const REPORT_STEP_EFFECT: u32 = 0x0C45;

/// `StepEffect` codes for `REPORT_STEP_EFFECT` (wire-stable; mirrors the
/// kernel's `scheduler::step_effect`).
pub mod step_effect {
    pub const IDLE: u8 = 0;
    pub const WAITING: u8 = 1;
    pub const WORK_DONE: u8 = 2;
    pub const RUNNABLE_BACKLOG: u8 = 3;
    pub const BURST: u8 = 4;
}

/// Get module's arena allocation. handle=-1, arg=[out_ptr:*mut *mut u8] (4 bytes).
/// Returns arena size in bytes (0 if no arena allocated).
pub const ARENA_GET: u32 = 0x0C3A;

/// Fill buffer with cryptographically secure random bytes.
/// handle=-1, arg=output buffer, arg_len=requested byte count.
/// Returns 0 on success, or a negative errno. A fill is all-or-nothing:
/// there is no partial success to report a byte count for, and a caller
/// that gets 0 has every one of `arg_len` bytes.
/// Entropy comes from whatever the platform calls a CSPRNG — a hardware
/// TRNG where one exists, the host CSPRNG where the kernel is hosted.
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

/// Copy the calling module's per-instance params blob into `out`.
/// handle=-1; arg=output buffer of size `out_len`. Returns the number
/// of bytes written (≤ out_len) on success, or negative errno. Calling
/// with `arg=null` or `out_len=0` returns the natural size without
/// copying — used to size a buffer before the read. The blob shape
/// is the manifest TLV: `[0xFE 0x01 len_lo len_hi {tag len value}*
/// 0xFF]`.
///
/// Native PIC modules receive params as direct call arguments to
/// `module_new` (the loader copies from the .fmod params section).
/// Wasm modules pull params through this query, since the kernel /
/// module memory split rules out the direct path. The opcode is
/// honoured on every target.
pub const MODULE_INSTANCE_PARAMS: u32 = 0x0C43;

/// Query the calling module's owner slot (`owner_tag`).
/// handle=-1, arg=NULL. Returns the module's owner slot (0..MAX_OWNERS-1)
/// on success, negative errno on failure. Slot 0 is `OWNER_SYSTEM` — a
/// base-graph / host-owned module — which is the legitimate "host / wildcard"
/// owner_tag, not an error.
///
/// This is the self-identity read behind metal owner-scoped binds
/// (`rfc_workload_backend_metal.md` §3.4 / P3a, `rfc_net_identity_metal`
/// §3.4). `apply_add` stamps every module of a `net=own` workload with its
/// owner (`set_module_owner`, post-`owners.alloc`), so a bind-emitting module
/// (http, a DG binder) reads its owner slot here and appends it as the
/// trailing `owner_tag` on `NET_CMD_BIND` / `DG_CMD_BIND` — the field the ip
/// module's P2 admission resolves to the workload's owned address. Ungated
/// self-query (same permission class as `SELF_INDEX` / `MODULE_INSTANCE_PARAMS`);
/// a module can only ever read its OWN owner, never another's. Resolves the
/// gap the ip module flagged ("the module syscall ABI exposes no owner query").
pub const OWNER_TAG: u32 = 0x0C4B;

/// Register the CALLING module as the node's net-identity provider (the
/// module owning the shared network stack that realizes `net::identity`
/// ADDR_ADD/ADDR_DEL installs and net-ingress spare-lane attach).
/// `arg = [addr_ctl_port: u8][net_in_port: u8]` — the provider declares its
/// own control and ingress input-port indices, so the kernel learns the
/// topology from the provider itself rather than from a name convention.
/// Gated to base-graph (system-owned) modules — a workload module cannot
/// hijack identity installs — and first-wins (`EBUSY` on a second claim).
/// `ENOSYS` on single-tenant builds (no workload backend to serve).
pub const NET_IDENT_PROVIDER: u32 = 0x0C4C;

/// Per-step flow-budget grant for one of the calling module's ports.
/// `arg[0] = port index`; optional `arg[1] = direction` (`0` output,
/// `1` input). Input requests may carry the raw channel descriptor in
/// `arg[2..6]` to resolve a runtime bridge/repacking alias. The provider handle
/// is always global (`-1`) because raw channel descriptors are untagged. A
/// one-byte request (`arg_len == 1`) is an output-port query.
pub const MODULE_FLOW_BUDGET: u32 = 0x0C46;

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

    /// Most recent `contracts::fence::Fence` advertised on this
    /// handle. Cross-class: any storage / file / namespace / object
    /// provider answers this for handles it owns. The output buffer
    /// must be at least `abi::fence::WIRE_MAX_LEN` bytes;
    /// the provider writes the prefix-tagged encoding documented in
    /// `contracts/fence.rs` and returns the byte count, or `ENOSYS`
    /// for handles whose contract has no fence concept (HAL
    /// peripherals, channels, timers). Consumers decode via
    /// `Fence::decode` — an unknown tag is not promoted to
    /// `Volatile`; it means the provider did not advertise a
    /// recognised fence and the consumer refuses to proceed.
    pub const LAST_FENCE: u32 = 8;

    /// Owner of the module that invoked the provider frame currently
    /// running. `handle = -1`; writes `[slot: u16 LE][_pad: u16][generation:
    /// u32 LE]` (8 bytes) and returns 8.
    ///
    /// This is the identity a provider needs to attribute a request, and it
    /// is a query rather than an argument on `provider_call` on purpose:
    /// widening that signature is a positional-ABI flag day across every
    /// module in the fleet, for a fact the kernel already holds. A provider
    /// that never asks is unaffected.
    ///
    /// Returns `ESRCH` when nothing is on the provider stack — a module
    /// stepping normally is not serving anybody's request, and answering
    /// with the system owner there would let a provider charge its own
    /// background work to whoever last called it.
    pub const CALLER_OWNER: u32 = 9;
}

// ─────────────────────────────────────────────────────────────────────
// File-descriptor tagging
// ─────────────────────────────────────────────────────────────────────
//
// Every handle Fluxor hands back to a module is encoded as a tagged
// i32: bits [30..26] = 5-bit type tag, bits [25..0] = 26-bit slot.
// Bit 31 is always 0 so tagged fds stay positive and unambiguous
// against negative errno values.
//
// The kernel resolves `(handle) -> contract_id` from the tag rather
// than from a shared lookup table — contract handle-spaces are
// disjoint by bit pattern. PIC module providers (fat32, loam, …)
// self-tag the handles they return from open-style ops; the
// kernel-side `fd.rs` re-exports from this module so the bit layout
// has a single source of truth.
pub mod fd {
    pub const FD_TAG_CHANNEL: i32 = 0;
    pub const FD_TAG_EVENT: i32 = 2;
    pub const FD_TAG_TIMER: i32 = 3;
    pub const FD_TAG_DMA: i32 = 7;
    pub const FD_TAG_BRIDGE: i32 = 8;
    pub const FD_TAG_KEY_VAULT: i32 = 9;
    pub const FD_TAG_PCIE_DEVICE: i32 = 10;
    pub const FD_TAG_NIC_RING: i32 = 11;
    pub const FD_TAG_DMA_CHANNEL: i32 = 12;
    pub const FD_TAG_FS: i32 = 13;
    pub const FD_TAG_BUFFER: i32 = 14;
    pub const FD_TAG_HAL_GPIO: i32 = 15;
    pub const FD_TAG_HAL_SPI: i32 = 16;
    pub const FD_TAG_HAL_I2C: i32 = 17;
    pub const FD_TAG_HAL_UART: i32 = 18;
    pub const FD_TAG_HAL_ADC: i32 = 19;
    pub const FD_TAG_HAL_PWM: i32 = 20;
    pub const FD_TAG_HAL_PIO: i32 = 21;
    pub const FD_TAG_STORAGE_NAMESPACE: i32 = 22;
    pub const FD_TAG_STORAGE_OBJECT: i32 = 23;
    /// USB host controller handle. Allocated as part of the scaffold
    /// for `provider::contract::USB_HOST` (0x0015) — `provider_open`
    /// will tag its returned handles with this once the host stack
    /// lands. No live producer yet.
    pub const FD_TAG_USB_HOST: i32 = 24;
    // 25: host process-executor tag — registry value reserved here; the
    // semantic constant lives at `abi::platform::linux::host_process::FD_TAG_PROC`.
    // 26 unused (reserved; do not reuse).
    /// Isolated-workload handle (`provider::contract::WORKLOAD`, 0x001A):
    /// `workload::CREATE` tags the returned slot with this; the lifecycle ops
    /// (START/WAIT/SIGNAL/DESTROY/READ) carry it back, stripped via `slot_of`.
    pub const FD_TAG_WORKLOAD: i32 = 27;

    pub const TAG_SHIFT: u32 = 26;
    pub const SLOT_MASK: i32 = 0x03FF_FFFF;

    /// Encode a type tag and slot index into a tagged fd. A negative
    /// `slot` passes through unchanged so PIC provider open-ops can
    /// pipe an errno through `tag_fd(TAG, errno)` without altering
    /// the error code.
    #[inline]
    pub const fn tag_fd(tag: i32, slot: i32) -> i32 {
        if slot < 0 {
            return slot;
        }
        // Fail closed on an out-of-range tag rather than masking it into a
        // valid one. The tag field is 5 bits [30..26] with bit 31 reserved,
        // so only tags 0..32 are encodable. Masking a tag of 32+ to 5 bits
        // would ALIAS a real contract (32 -> tag 0 = channels) and silently
        // mis-route a handle; returning EINVAL makes callers treat it as the
        // error it is (they already check for negative returns). Valid tags
        // are pinned < 32 by `fd_tag_wire_surface.rs`, so this never fires in
        // practice — it is the construction-time backstop.
        if tag < 0 || tag >= 32 {
            return -22; // EINVAL
        }
        (tag << TAG_SHIFT) | (slot & SLOT_MASK)
    }

    /// Decode a tagged fd into `(tag, slot)`.
    #[inline]
    pub const fn untag_fd(fd: i32) -> (i32, i32) {
        let tag = (fd >> TAG_SHIFT) & 0x1F;
        let slot = fd & SLOT_MASK;
        (tag, slot)
    }

    /// Strip the tag and return only the slot index. Used at typed
    /// inbound entry points that receive a tagged handle from a
    /// chained caller.
    #[inline]
    pub const fn slot_of(fd: i32) -> i32 {
        fd & SLOT_MASK
    }
}

/// Provider instance selectors — the shared hash the kernel and modules
/// both compute so a module's declared selector string and a
/// `provider_bind(contract, "name")` query resolve to the same u32 key.
pub mod provider_selector {
    /// FNV-1a hash of a short selector string (a volume / instance name
    /// such as `"nvme0"` or `"boot"`). Single source of truth for both
    /// sides of `provider_bind`; keep it a `const fn` so a module can fold
    /// its selector at compile time. Hash `0` is reserved to mean "unkeyed
    /// / default provider" — an input that happens to hash to `0` is
    /// nudged to `1` so it never aliases the default.
    #[inline]
    pub const fn hash(bytes: &[u8]) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        let mut i = 0;
        while i < bytes.len() {
            h ^= bytes[i] as u32;
            h = h.wrapping_mul(0x0100_0193);
            i += 1;
        }
        if h == 0 {
            1
        } else {
            h
        }
    }
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
