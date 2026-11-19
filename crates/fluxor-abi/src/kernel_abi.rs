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
// Vocabulary: the POSIX-derived low-level terms here — `fd` (a handle),
// `errno` (negative error code), poll flags — are universally understood
// primitives at the kernel/module boundary, not an orchestrator's
// vocabulary. Tenancy is Fluxor's own: `owner`, `workload`, `lease`,
// `posture`, `endpoint`, `grant`. No user, group or mode bit crosses this
// boundary; those belong to the host-process platform contract alone.
//
// This file is `include!`'d by `abi.rs` into `pub mod kernel_abi`.

/// ABI version exposed via `SyscallTable.version` (u32 for layout
/// reasons). Widened from the on-disk `wire::ABI_VERSION` byte so
/// every consumer sees the same value.
pub const ABI_VERSION: u32 = super::wire::ABI_VERSION as u32;

/// Default channel buffer size in bytes.
/// The ring an edge gets when neither its ports nor its wiring size it
/// (the kernel's ring rule, `fluxor_contracts::ring_size`); modules that
/// size their own buffers to one ring's worth (the I2S input buffer)
/// read it too. Sized to hold one ZX Spectrum ZVFF packet (6924 B) plus
/// framing in a single channel write — byte-stream parsers see message
/// boundaries at fixed offsets rather than scrambling across fragments.
/// The RP buffer arenas (16 KiB on rp2040, 64 KiB on rp2350) bound the
/// upper end; ports needing more declare `buffer_size` in the module
/// manifest rather than raising this default.
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
/// quartet. Channel I/O and heap are direct typed syscalls. Every handle is
/// a kernel-minted word naming its contract ([`handle`]), so a call on one
/// reaches that contract's vtable; `handle = -1` ops route by the opcode's
/// contract bits.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallTable {
    pub version: u32,
    /// Read from a channel. Returns bytes read, `EAGAIN` when nothing is
    /// buffered or `len == 0`, <0 on error.
    pub channel_read: unsafe extern "C" fn(handle: i32, buf: *mut u8, len: usize) -> i32,
    /// Write one record to a channel, whole or not at all. Returns `len`,
    /// `EAGAIN` when it does not fit now, 0 for `len == 0` (nothing is
    /// published), <0 on error.
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
    /// op with `handle = -1`. Every op takes the same six words: one handle
    /// slot, one flat `arg` record (its direction and maximum are the
    /// registry's; a small answer is written back into it) and one bulk
    /// `data` span, valid for this call only. Neither carries an address
    /// or a handle: a second object is named by a cookie, and memory that
    /// must outlive the call is a `lend`.
    pub provider_call: unsafe extern "C" fn(
        handle: i32,
        op: u32,
        arg: *mut u8,
        arg_len: usize,
        data: *mut u8,
        data_len: usize,
    ) -> i32,

    /// Query introspection state on a handle. See `kernel_abi::query_key`
    /// for well-known keys.
    pub provider_query:
        unsafe extern "C" fn(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32,

    /// Release a handle, invoking the contract's close hook if any.
    pub provider_close: unsafe extern "C" fn(handle: i32) -> i32,

    /// Copy up to `len` bytes from the head of a channel into `buf`
    /// without consuming them: from a FIFO, the head of its stream; from a
    /// mailbox, the head of its pending record, which stays pending.
    /// Returns the number of bytes copied (0 when nothing is buffered), or
    /// `EINVAL` for a null buffer, `EBADF` for a handle that is not the
    /// caller's input.
    ///
    /// Used by frame-aware consumers that inspect a header (message type,
    /// payload length, connection id) before committing to consume the
    /// frame, so a frame that cannot be delivered yet stays on the channel
    /// and the producer's flow control holds.
    pub channel_peek: unsafe extern "C" fn(handle: i32, buf: *mut u8, len: usize) -> i32,
    /// Producer-side telemetry enabled gate. Points at a kernel-published
    /// `u32` that is non-zero when at least one telemetry consumer is
    /// subscribed. The `dev_telemetry_*` helpers read it (a plain single-word
    /// load, no trap) before building a record, so instrumentation is
    /// zero-cost when nothing is collecting.
    ///
    /// Null means "cannot check", NOT "disabled": a table without the word
    /// (the wasm host, an isolated module whose protection domain does not map
    /// kernel memory) emits unconditionally and lets the ring drop when no
    /// consumer is subscribed. Losing the optimisation is the safe failure;
    /// losing the records is not.
    pub telemetry_enabled: *const u32,

    /// Drop the next `len` bytes of a channel's stream without copying
    /// them. On a FIFO, what is buffered goes at once and the rest is
    /// dropped from the front of each later write as it arrives; returns
    /// `len`, or `EINVAL` for a `len` past `i32::MAX`. On a mailbox the unit
    /// is the record: `len` at least the pending record's releases it whole
    /// and returns its length, a shorter non-zero `len` is `EINVAL` (no
    /// partial record is left), and `EAGAIN` when none is pending. `len == 0`
    /// returns 0.
    ///
    /// The consuming half of a whole-frame read: a frame-aware consumer
    /// peeks the header, peeks the frame once it is all buffered, and
    /// discards what it copied; a frame it cannot hold, or that is larger
    /// than the ring, it discards whole. Nothing it does can leave part of a
    /// frame on the channel.
    pub channel_discard: unsafe extern "C" fn(handle: i32, len: usize) -> i32,
}

// SAFETY: apart from the `telemetry_enabled` raw pointer, `SyscallTable` is
// `fn` pointers and a `u32`, all `Sync`. The table is
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
// the build; the table is part of the ABI surface the digest covers. Layout
// is one `u32` slot (version, padded to pointer width), 11 function
// pointers, a telemetry gate pointer and the channel discard pointer = 14
// pointer-sized slots, which holds on both 64-bit (native) and 32-bit wasm
// builds.
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
    assert!(core::mem::offset_of!(SyscallTable, channel_discard) == p * 13);
    assert!(core::mem::size_of::<SyscallTable>() == p * 14);
};

/// Poll event flags (used with `handle_poll` / `channel_poll`).
/// These values are part of the stable ABI — modules hardcode them.
pub mod poll {
    /// Error condition.
    pub use super::super::registry::poll::ERR;
    /// Hang-up (peer closed / end-of-stream).
    ///
    /// On its own this does NOT mean the stream carried anything. A
    /// channel can report `HUP` before its producer has ever written —
    /// a producer that is terminated, faulted, or retired before its
    /// first write hangs up its outputs — and a consumer reading `HUP`
    /// as "the stream is complete" then treats a stream that never
    /// started as one that ended empty. Pair it with [`WROTE`].
    pub use super::super::registry::poll::HUP;
    /// Data available for reading.
    pub use super::super::registry::poll::IN;
    /// Space available for writing.
    pub use super::super::registry::poll::OUT;
    /// The channel has carried at least one byte since it was last
    /// flushed. Sticky: once set it stays set until `channel::FLUSH`
    /// begins a new stream.
    ///
    /// This is what makes [`HUP`] answerable. `HUP | WROTE` is a stream
    /// that ended; `HUP` without `WROTE` is a stream that never started,
    /// and a consumer staging one should treat it as an empty source or
    /// keep waiting, not as a complete one.
    ///
    /// The distinction carries across a whole graph, because a module
    /// that retires hangs up its own outputs: a consumer that reads a
    /// never-written hang-up as a complete stream stages nothing, fails,
    /// and retires, which presents the next consumer downstream with the
    /// same reading. One misread at the head of a chain retires all of
    /// it, within a few steps of boot and with no error anywhere.
    pub use super::super::registry::poll::WROTE;
}

/// Standard error codes (negative errno values).
/// These values are part of the stable ABI — modules hardcode them.
pub mod errno {
    /// Argument list / output buffer too long — caller should retry
    /// with a larger buffer. Used by FS_READDIR when one entry
    /// doesn't fit and no progress could be made.
    pub use super::super::registry::errno::E2BIG;
    /// Refused: the caller does not hold the op's grant.
    pub use super::super::registry::errno::EACCES;
    /// Resource temporarily unavailable — try again.
    pub use super::super::registry::errno::EAGAIN;
    /// The handle is not the caller's: free, or another module's.
    pub use super::super::registry::errno::EBADF;
    /// Resource busy.
    pub use super::super::registry::errno::EBUSY;
    /// Entry already exists. `LINK` against a name that is taken.
    pub use super::super::registry::errno::EEXIST;
    /// A pointer the caller passed is not the caller's memory.
    pub use super::super::registry::errno::EFAULT;
    /// Operation in progress (async not yet complete).
    pub use super::super::registry::errno::EINPROGRESS;
    /// Invalid argument.
    pub use super::super::registry::errno::EINVAL;
    /// I/O error: the medium refused or lost what it was given.
    pub use super::super::registry::errno::EIO;
    /// Target is a directory. `LINK` against one, and `UNLINK` against one
    /// on a provider that separates directory removal into `RMDIR`.
    pub use super::super::registry::errno::EISDIR;
    /// No such device.
    pub use super::super::registry::errno::ENODEV;
    /// A module that cannot be brought up: no module of that name, or one
    /// whose constructor refused.
    pub use super::super::registry::errno::ENOEXEC;
    /// Cannot allocate memory / no free slots.
    pub use super::super::registry::errno::ENOMEM;
    /// Capacity denial — a resource-ledger pool or budget is exhausted.
    /// Distinct from `ENOMEM` (allocator failure): the request was
    /// well-formed and the denial is accounted (pool `denials` counter,
    /// PSTATUS `POOL` records).
    pub use super::super::registry::errno::ENOSPC;
    /// Function / syscall not implemented.
    pub use super::super::registry::errno::ENOSYS;
    /// Directory not empty. `RMDIR` against a directory that still holds
    /// entries; the check is the provider's, because a caller's enumeration
    /// only describes the moment it looked.
    pub use super::super::registry::errno::ENOTEMPTY;
    /// No such device or address (e.g. I2C NACK).
    pub use super::super::registry::errno::ENXIO;
    /// Generic / unspecified error.
    pub use super::super::registry::errno::ERROR;
    /// No such process / no such context. Answered by
    /// [`query_key::CALLER_OWNER`] when nothing is on the provider stack —
    /// there is no requester to name, which is a different statement from
    /// "the requester is the system owner".
    pub use super::super::registry::errno::ESRCH;
    /// Cross-device link: the two paths are not on the same volume, so no
    /// second name can reference the same file.
    pub use super::super::registry::errno::EXDEV;
    /// Operation completed successfully.
    pub use super::super::registry::errno::OK;

    /// No such entry. A lookup that found nothing, as distinct from one
    /// that could not be performed.
    pub use super::super::registry::errno::ENOENT;

    /// Connection refused.
    pub use super::super::registry::errno::ECONNREFUSED;
    /// Transport endpoint is not connected.
    pub use super::super::registry::errno::ENOTCONN;
    /// Operation not supported (e.g. wrong pin mode).
    pub use super::super::registry::errno::ENOTSUP;
    /// A value is too large for the field that must carry it (a name past
    /// `STORAGE_KEY_MAX` in a listing), refused rather than clamped.
    pub use super::super::registry::errno::EOVERFLOW;
    /// The caller's buffer is too small, and the call has written the
    /// exact requirement into the layout's `*_len_out` field.
    ///
    /// Distinct from `ENOSPC` (the STORE is full) and from `EINVAL` (the
    /// request was wrong). This one says the request was right and the
    /// caller should resize — a caller that cannot tell those apart either
    /// gives up on a recoverable call or retries an unrecoverable one
    /// forever.
    pub use super::super::registry::errno::ERANGE;
    /// A `storage.object` object's retention or legal hold refuses the
    /// change. No host errno has this value, so a provider relaying a host
    /// call's answer can never produce it by accident.
    pub use super::super::registry::errno::ERETAINED;
    /// Connection timed out.
    pub use super::super::registry::errno::ETIMEDOUT;
}

// ─────────────────────────────────────────────────────────────────────
// Channel primitive
// ─────────────────────────────────────────────────────────────────────
//
// A channel joins one producer to one consumer: a ring (FIFO) or, for an
// aliased edge, a mailbox holding one record. `channel_read` /
// `channel_write` / `channel_peek` / `channel_discard` / `channel_poll` are
// direct syscalls on the SyscallTable; the opcodes below are the rest of the
// object. Every op is checked against the caller's end: reads, peeks,
// discards, `RECORD_LEN` and the read and in-place lends are the consumer's;
// writes, `SET_HUP`, `WRITABLE` and the write lend the producer's; `POLL` and
// `FLUSH` either end's. `EBADF` for anyone else.
//
// Records. Every write is one record (a write over 65535 bytes is several),
// and a ring keeps each record's boundary: `RECORD_LEN` answers the unread
// bytes of the record at the head. Reads, peeks and discards stay a byte
// stream over the records' payload. A record costs its length plus two bytes
// of ring, so a ring of N bytes takes a write of at most N - 2.
//
// Zero lengths. A write of 0 bytes publishes nothing and returns 0; a read
// that fits no byte (`len == 0`, or nothing buffered) returns `EAGAIN`; a
// peek or discard of 0 returns 0. On a mailbox a read needs room for the whole record (a shorter
// buffer is `EINVAL`, the record left in place), and a discard drops the
// record whole: `n >= record` returns the record's length, `0 < n < record`
// is `EINVAL`.
//
// The mailbox's record is IDLE, WRITING, READY or READING. A lend (WRITING or
// READING) is its acquirer's until it releases or cancels it, it retires, or
// the channel closes: `FLUSH` answers `EBUSY` while one is out.
pub mod channel {
    /// The consumer's lend of the READY record for modification, when no
    /// in-place writer has processed it yet (READY → WRITING);
    /// `RELEASE_WRITE` then hands it on, marked processed. Argument: an
    /// [`acquired`] record.
    pub use super::super::registry::channel::ACQUIRE_INPLACE;
    /// The consumer's lend of the READY record for reading (READY →
    /// READING). Argument: an [`acquired`] record.
    pub use super::super::registry::channel::ACQUIRE_READ;
    /// The producer's lend of the mailbox record for writing (IDLE →
    /// WRITING). Argument: an [`acquired`] record, written by the kernel.
    pub use super::super::registry::channel::ACQUIRE_WRITE;
    pub use super::super::registry::channel::CLOSE;
    pub use super::super::registry::channel::FACTS;
    /// Either end: drop what is buffered and start the stream over — the
    /// ring's bytes or the mailbox's READY record, the owed discard and
    /// `WROTE`, and `HUP` unless the producer is gone (`ERR` stays). `EBUSY`
    /// while the mailbox record is lent.
    pub use super::super::registry::channel::FLUSH;
    /// `arg` = the ring's capacity in bytes, `u32` LE, a power of two within
    /// the ring bounds; empty for the default ring. The opener is both ends.
    pub use super::super::registry::channel::OPEN;
    pub use super::super::registry::channel::PORT;
    /// The consumer: the unread bytes of the record at the head, as the
    /// call's result (on a mailbox, the READY record's length); `EAGAIN`
    /// when nothing is buffered.
    pub use super::super::registry::channel::RECORD_LEN;
    /// The lend's holder ends a read lend, consuming the record (READING →
    /// IDLE). No argument.
    pub use super::super::registry::channel::RELEASE_READ;
    /// The lend's holder publishes the record (WRITING → READY) and the call
    /// returns its length. Argument: `u32` LE, the record's length, at most
    /// the capacity `ACQUIRE_WRITE` reported (`EINVAL` past it, the lend
    /// kept). A length of `0` cancels the lend (WRITING → IDLE), publishes
    /// nothing and returns 0. `EBUSY` from anyone but the lend's holder.
    pub use super::super::registry::channel::RELEASE_WRITE;
    /// The producer: end of stream, seen as `poll::HUP` (a tap of the
    /// channel sees it too). No argument.
    pub use super::super::registry::channel::SET_HUP;
    /// The producer: `arg` out `u32` LE, the largest write the ring takes
    /// now; 0 for a full ring and for a mailbox, which has no ring to
    /// measure.
    pub use super::super::registry::channel::WRITABLE;

    /// The record the three acquires fill in. The call's result is the
    /// status and never the address: a pointer does not fit the `i32` a call
    /// returns on a 64-bit target.
    ///
    /// Result `0`: acquired. `EAGAIN`: the mailbox is not available now
    /// (write: its record is not IDLE and `LEN` is the capacity; read and
    /// in-place: no record is ready). `ENOTSUP`: the channel is not a
    /// mailbox. `EINVAL`: an argument shorter than [`SIZE`] (nothing is
    /// acquired then). `EBADF`: no such channel, or not the caller's end.
    pub mod acquired {
        /// Total length, in bytes.
        pub const SIZE: usize = 16;
        /// `u64` LE — the buffer's address; `0` unless the result was `0`.
        pub const PTR: usize = 0;
        /// `u32` LE — write: the buffer's capacity (also for a busy
        /// mailbox); read and in-place: the record's length; `0` otherwise.
        pub const LEN: usize = 8;
    }

    /// `FACTS`' answer, written into `arg`: `[producer_owner u16 LE]
    /// [flags u8][0 u8]`, about a channel the caller is an end of (handle =
    /// the channel; `EBADF` for one it is not).
    ///
    /// `producer_owner` is the owner slot of the module that writes the
    /// channel (0 = the host), as the kernel knows it: a provider reading
    /// commands off the channel admits them as that owner, never as one a
    /// record names. A channel fed by a fan-in is written by the merge the
    /// graph inserted, which belongs to the graph's owner.
    pub mod facts {
        /// Answer length.
        pub const LEN: usize = 4;
        pub const PRODUCER_OWNER: usize = 0;
        pub const FLAGS: usize = 2;
        /// Every consumer reading this channel (through a fan, every one
        /// it fans to) declares `retains_send` on its port: it keeps its
        /// own copy of what it sends until the provider reports it
        /// acknowledged. Set by the composer on the graph's edges.
        pub const RETAINS_SEND: u8 = 0x01;
    }
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
    pub use super::super::registry::timer::MICROS;
    pub use super::super::registry::timer::MILLIS;
    /// Wall-clock milliseconds since the Unix epoch (0 if the platform has no RTC).
    /// Distinct from MILLIS (monotonic uptime).
    ///
    /// A bare number, and it cannot say whether it is trustworthy: zero means
    /// "no RTC" but every other value is indistinguishable from a good one,
    /// including one from a clock that was never synchronised or has just
    /// been stepped backwards. Suitable for timestamps a human reads and for
    /// cache ages; NOT suitable for deciding whether a credential is still
    /// valid. Use `TRUSTED_UNIX` for that. handle=-1, arg=[u64 LE].
    pub use super::super::registry::timer::UNIX_MILLIS;

    /// Cancel timer. handle=timer_fd.
    pub use super::super::registry::timer::CANCEL;
    /// Create a timer. handle=-1. Returns the timer's handle.
    ///
    /// A timer is an fd in every sense that matters: `SET` arms it, the
    /// generic fd `POLL` reports `POLL_IN` once it has fired, and the KERNEL
    /// steps the owning module when it fires — the owner's wake bit latches
    /// exactly as an event's does, once per arming, and the earliest armed
    /// timer bounds the pacer's sleep, relaxed idle backstop included. So a
    /// module that arms 5 ms is stepped at ~5 ms on an idle domain whose
    /// backstop is 50 ms, not at 50: a module waits on its timer rather than
    /// polling the clock on a tick it does not control.
    pub use super::super::registry::timer::CREATE;
    /// Destroy timer. handle=timer_fd.
    pub use super::super::registry::timer::DESTROY;
    /// Anchor the platform's wall clock to a network time measurement — for a
    /// board with no RTC and no OS time service (the `sntp` foundation module
    /// calls it). `handle=-1`, `arg` = `[unix_us: u64 LE][monotonic_us: u64
    /// LE][error_us: u32 LE]` (20 bytes): at monotonic instant `monotonic_us`
    /// (a `MICROS` reading, not in the future) it was `unix_us`, within
    /// `error_us`. The platform then reports `NETWORK_SYNC` through
    /// `TRUSTED_UNIX`, its uncertainty growing with the anchor's age, until
    /// the anchor goes stale (one hour without a fresh one). `EINVAL` for an anchor that cannot be true (a
    /// Unix time before 2024, or a monotonic instant in the future).
    /// Privileged (`timer.discipline`): whoever anchors the clock decides every
    /// credential's validity window. `ENOSYS` on a platform whose wall clock
    /// does not come from this anchor (bcm2712 is the one that does).
    pub use super::super::registry::timer::DISCIPLINE;
    /// Start/restart timer. handle=timer_fd, arg[0..4]=delay_ms (LE).
    pub use super::super::registry::timer::SET;
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
    pub use super::super::registry::timer::TRUSTED_UNIX;
}

// ─────────────────────────────────────────────────────────────────────
// Event primitive (single-bit ISR→module wake signal)
// ─────────────────────────────────────────────────────────────────────
pub mod event {
    /// Bind an event handle to a hardware IRQ number.
    /// handle=event_handle, arg=[irq_number:u32 LE][ack:u8] (5 bytes). The
    /// kernel signals the event
    /// when the IRQ fires (ISR-safe), first acknowledging the device behind
    /// the line when `ack` says how. `EINVAL` for an `ack` the machine has no
    /// such device behind `irq` for.
    pub use super::super::registry::event::BIND_IRQ;
    /// How the kernel quiets the device behind a [`BIND_IRQ`] line before it
    /// signals the event.
    pub mod ack {
        /// The driver acknowledges the device itself.
        pub const NONE: u8 = 0;
        /// The line is a virtio-mmio transport's: the kernel writes its
        /// `InterruptStatus` back to `InterruptACK`. Which transport raises
        /// the line is the machine's fact, not the caller's.
        pub const VIRTIO_MMIO: u8 = 1;
    }
    /// Create event. handle=-1, arg=unused. Returns event handle (>=0) or <0 on error.
    pub use super::super::registry::event::CREATE;
    /// Destroy event and free slot. handle=event. Returns 0 or <0.
    pub use super::super::registry::event::DESTROY;
    /// Poll event (non-blocking, clears signaled flag). handle=event.
    /// Returns 1 if was signaled (now cleared), 0 if not signaled, <0 on error.
    pub use super::super::registry::event::POLL;
    /// Signal event. handle=event. Returns 0 or <0.
    pub use super::super::registry::event::SIGNAL;
}

// ─────────────────────────────────────────────────────────────────────
// Core system primitives
// ─────────────────────────────────────────────────────────────────────
//
// Opcodes that every module may invoke — logging, random, handle poll,
// own-arena queries, timing queries. These are the "syscalls" of the
// ABI. Anything that only infrastructure modules touch (fault monitor,
// reconfigure, bridge) lives in `internal/*` instead.

/// Poll any handle. handle=fd, arg[0]=events mask. Returns poll result bitmask.
pub use super::registry::kernel::HANDLE_POLL;
/// Log message. handle=log_level, no `arg`, `data` in = the message.
pub use super::registry::kernel::LOG_WRITE;
/// Write raw bytes to the platform debug serial sink (binary-safe, unlike
/// LOG_WRITE which UTF-8-filters). No `arg`, `data` in = the bytes. Returns bytes
/// accepted. The telemetry `transport_buffer` sink; needs `kernel.serial`. `kernel::SERIAL_WRITE` is
/// the slot the dispatch comment reserves for "raw UART / USB writes", beside
/// LOG_RING_DRAIN (`diag::LOG_RING_DRAIN`).
pub use super::registry::kernel::SERIAL_WRITE;

/// Query downstream latency for current module. handle=-1. Returns u32 frames.
pub use super::registry::kernel::DOWNSTREAM_LATENCY;
/// Query graph-level sample rate. handle=-1. Returns u32 (0 = not set).
pub use super::registry::kernel::GRAPH_SAMPLE_RATE;
/// Report module's own processing latency in frames. handle=-1, arg[0..4]=frames (u32 LE).
pub use super::registry::kernel::REPORT_LATENCY;
/// Query stream time via `provider_query`. `handle=-1` returns the
/// first active PIO stream's StreamTime (delegated to HAL_PIO
/// internally — no PIO handle or ownership required by the caller).
/// `handle=<stream>` returns that specific stream's time. Returns a
/// 24-byte StreamTime struct.
pub use super::registry::kernel::STREAM_TIME;

/// Report this module's `StepEffect` for the current scheduler pass.
/// handle=-1, arg[0]=effect code (u8):
///   0=Idle, 1=Waiting, 2=WorkDone, 3=RunnableBacklog, 4=Burst.
/// WorkDone/RunnableBacklog/Burst keep the adaptive pacer hot WITHOUT
/// authorising an immediate same-module re-step (that stays `StepOutcome::Burst`
/// only). Idle/Waiting do not heat the pacer. A no-permission core primitive;
/// a module that never calls it is treated as `Idle`.
pub use super::registry::kernel::REPORT_STEP_EFFECT;

/// `StepEffect` codes for `REPORT_STEP_EFFECT` (wire-stable; mirrors the
/// kernel's `scheduler::step_effect`).
pub mod step_effect {
    pub const IDLE: u8 = 0;
    pub const WAITING: u8 = 1;
    pub const WORK_DONE: u8 = 2;
    pub const RUNNABLE_BACKLOG: u8 = 3;
    pub const BURST: u8 = 4;
}

/// What `module_step` returns (wire-stable). Any other value is an error the
/// module reports, and faults it.
pub mod step_return {
    /// More work is possible on later ticks.
    pub const CONTINUE: i32 = 0;
    /// Finished: the module is never stepped again.
    pub const DONE: i32 = 1;
    /// More work now: step again this tick, up to the scheduler's burst limit.
    pub const BURST: i32 = 2;
    /// Initialisation complete, outputs now meaningful: downstream may start.
    /// Returned once; later steps answer `CONTINUE` or `BURST`.
    pub const READY: i32 = 3;
}

/// Get module's arena allocation. handle=-1; `arg` out = `[addr:u64 LE]
/// [size:u32 LE]` (an address answer; both 0 when the module has no arena).
/// Returns 0.
pub use super::registry::kernel::ARENA_GET;

/// Fill buffer with cryptographically secure random bytes.
/// handle=-1, no `arg`, `data` out = the bytes to fill.
/// Returns 0 on success, or a negative errno. A fill is all-or-nothing:
/// there is no partial success to report a byte count for, and a caller
/// that gets 0 has every byte of `data`.
/// Entropy comes from whatever the platform calls a CSPRNG — a hardware
/// TRNG where one exists, the host CSPRNG where the kernel is hosted.
pub use super::registry::kernel::RANDOM_FILL;

/// Query system clock frequency in Hz. handle=-1. Returns u32 (e.g. 125_000_000).
pub use super::registry::kernel::SYS_CLOCK_HZ;

/// Query the calling module's own scheduler index. handle=-1, no arg.
/// Returns the index — a u16 value below the kernel's module-slot count
/// (`internal::reconfigure::SLOT_CAPACITY`) — on success, negative errno on
/// failure.
/// Used by anchors / workers to render `mod=<idx>` in MON_SESSION
/// telemetry lines, and by orchestration modules to name themselves.
pub use super::registry::kernel::SELF_INDEX;

/// Copy the calling module's per-instance params blob into `data`.
/// handle=-1, no `arg`. Returns the number of bytes written (≤ the length
/// of `data`) on success, or negative errno. An empty `data` returns the
/// natural size without copying — used to size a buffer before the read. The blob shape
/// is the manifest TLV: `[0xFE 0x01 len_lo len_hi {tag len value}*
/// 0xFF]`.
///
/// Native PIC modules receive params as direct call arguments to
/// `module_new` (the loader copies from the .fmod params section).
/// Wasm modules pull params through this query, since the kernel /
/// module memory split rules out the direct path. The opcode is
/// honoured on every target.
pub use super::registry::kernel::MODULE_INSTANCE_PARAMS;

/// Register the CALLING module as the node's net-identity provider (the
/// module owning the shared network stack that realizes `net::identity`
/// ADDR_ADD/ADDR_DEL installs and net-ingress spare-lane attach).
/// `arg = [addr_ctl_port: u8][net_in_port: u8]` — the provider declares its
/// own control and ingress input-port indices, so the kernel learns the
/// topology from the provider itself rather than from a name convention.
/// Gated to base-graph (system-owned) modules — a workload module cannot
/// hijack identity installs — and first-wins (`EBUSY` on a second claim).
/// `ENOSYS` on single-tenant builds (no workload backend to serve).
pub use super::registry::kernel::NET_IDENT_PROVIDER;

/// This boot's incarnation: 16 bytes drawn from the kernel CSPRNG once per
/// boot, the same for every module that asks. What it is for: anything
/// minted during a boot — an emission token, a fence epoch, a directory
/// entry — mixes it in, so a value from a previous life of this host is
/// structurally unmatchable rather than merely unlikely. Ungated self-query.
/// `handle = -1`, `arg` receives 16 bytes.
///
/// Ungated: a self-query every module may make, whatever capability it
/// holds.
pub use super::registry::kernel::BOOT_INCARNATION;

/// Describe one of the calling module's programs: an opaque blob the
/// graph bundled for this module instance (a compiled script, a model, a
/// table), carried in the bundle's program section beside the module table
/// and covered by the same digest and signature as the modules.
/// `handle = -1`; `arg` is a buffer of at least [`program::INFO_LEN`] bytes
/// whose first byte names the program's slot (0 for the first) on entry. On
/// success it receives the description [`program::INFO_LEN`] lays out and
/// the call answers the bytes written; `ENOENT` when this instance has no
/// program in that slot. Ungated self-query: the kernel finds the programs by the calling
/// module, so a module can only ever name its own.
///
/// The record opens with an address answer `[addr u64][len u32]`: where the
/// bytes can be read in place (flash on an XIP board, the loaded bundle
/// elsewhere), or `0, 0` where the module cannot dereference kernel memory
/// (wasm), which reads through [`PROGRAM_READ`] instead; the size is
/// stated either way. An isolated module is granted read-only,
/// never-executable access to the region over its programs: an MPU region
/// of exactly that span on RP, its pages EL0 read-only on the Pi 5; the
/// record says where it ends, as bytes from `addr`.
pub use super::registry::kernel::PROGRAM_INFO;

/// Copy bytes of one of the calling module's programs into `data`.
/// `handle = -1`; `arg` holds `[slot: u8][0; 3][offset: u32 LE]` and `data`
/// is as many bytes as are wanted; the call fills it with program bytes from
/// `offset` and answers how many (0 at the end). `ENOENT` for no program in
/// that slot.
pub use super::registry::kernel::PROGRAM_READ;

/// The signing root this kernel verifies modules and graph-slot signatures
/// against: the 32-byte Ed25519 public key written into the kernel image.
/// `handle = -1`, `arg` receives 32 bytes; `ENOENT` on a rootless image,
/// which checks no signature. Ungated: the key is public, and a slot writer
/// (`graph_slot`) checks a signature before it activates a slot rather than
/// leaving a bad image for the next boot to discover.
pub use super::registry::kernel::SIGNING_ROOT;

/// Which graph slots this boot's slot selector admitted: `handle = -1`, the
/// answer is a mask (bit 0 = slot A, bit 1 = slot B), on an RP board only
/// (`ENOSYS` elsewhere). A slot is admitted when its header decodes, its ABI
/// pin matches, and -- on an image with a signing root -- its signature verifies
/// and its payload matches its digest. A slot writer that cannot afford to
/// verify a signature every time it asks which slot is live (`graph_slot`)
/// starts from this, and tracks the slots it erases and activates itself.
pub use super::registry::kernel::SLOT_ADMITTED;

/// How this board's flash is partitioned: `handle = -1`, `arg` receives
/// `flash_layout::GRAPH_FLASH_LEN` bytes, `flash_layout::GraphFlash::encode`
/// of the kernel's own partition (where the firmware region ends, the two
/// graph slots and their size, the parameter store). On an RP board only;
/// `ENOSYS` elsewhere. The kernel is built for one board and computes it from
/// that board's flash size (`flash_layout::graph_flash`), so a module asks
/// rather than compiling a geometry in, and one module build serves every
/// board of its silicon. Ungated: it is the shape of the flash, not its
/// contents.
pub use super::registry::kernel::FLASH_LAYOUT;

/// The program section: per-module-instance program blobs carried after
/// the module table. Its offset from the table's start, a multiple of
/// 4 KiB, is the table header's first reserved word (bytes 10..14); 0
/// means none.
///
/// ```text
///   header (16): [magic "FXPG": u32][version: u8][count: u8][0: u16]
///                [total_size: u32][0: u32]
///   entries (count x 64):
///     [type_hash: u32]   FNV-1a of the owning module's type name
///     [ordinal: u8]      which instance of that type, in graph order
///     [slot: u8]         which of its programs
///     [0: u16]
///     [kind: u32]        FNV-1a of a kind name, or 0
///     [offset: u32]      from the section's start
///     [size: u32]        the program's bytes
///     [region_off: u32]  the owner's run of programs, from the section's
///     [region_len: u32]  start: what an isolated reader is granted
///     [0: u32]
///     [format: 32]       a digest the producer names its format by, or 0
///   data: each owner's programs together in one region that starts on a
///         4 KiB boundary and is a whole number of 32-byte granules (so an
///         MPU region, or the pages a page table maps, covers exactly one
///         owner's), each program on a 32-byte boundary.
/// ```
///
/// Entries run in (type_hash, ordinal, slot) order, every entry of an
/// owner names the same region, regions follow the entries and each other
/// without overlap, and `total_size` is a whole number of 4 KiB. The kernel
/// reads no program from a section that breaks any of this.
pub mod program {
    pub const SECTION_MAGIC: u32 = 0x4750_5846; // "FXPG"
    pub const SECTION_VERSION: u8 = 1;
    pub const HEADER_LEN: usize = 16;
    pub const ENTRY_LEN: usize = 64;
    pub const OWNER_ALIGN: usize = 4096;
    pub const PROGRAM_ALIGN: usize = 32;
    /// Bytes `PROGRAM_INFO` writes: `[addr: u64][len: u32][kind: u32]
    /// [size: u32][region_end: u32][0: 8][format: 32]`.
    pub const INFO_LEN: usize = 64;
    /// `PROGRAM_INFO` field offsets.
    pub mod info {
        /// `u64` LE — where the program can be read in place, or 0.
        pub const ADDR: usize = 0;
        /// `u32` LE — the bytes readable at `ADDR`: the program's size, or 0
        /// with `ADDR` 0.
        pub const LEN: usize = 8;
        /// `u32` LE — the program's kind.
        pub const KIND: usize = 12;
        /// `u32` LE — the program's size, whether or not it is readable in
        /// place.
        pub const SIZE: usize = 16;
        /// `u32` LE — bytes from `ADDR` to the end of the region an isolated
        /// reader is granted over its programs; 0 with `ADDR` 0.
        pub const REGION_END: usize = 20;
        /// `[u8; 32]` — the producer's format digest.
        pub const FORMAT: usize = 32;
    }
}

/// Per-step flow-budget grant for one of the calling module's ports.
/// `handle = -1`; `arg = [port index: u8][direction: u8]` (`0` output, `1`
/// input). An input port's budget is resolved through the channel the
/// calling module reads that port by, which the kernel looks up itself, so
/// a bridge or a repacking stage in front of it changes nothing.
pub use super::registry::kernel::MODULE_FLOW_BUDGET;

/// Raise software-generated interrupt `sgi` (0..=15) on core `core`: the
/// stimulus a Tier-2 module that owns an SGI is tested with. handle=-1,
/// arg=[core:u8, sgi:u8] (2 bytes). Needs `kernel.signal_core`. Returns 0,
/// `EINVAL` for a core the machine does not have or an `sgi` above 15, or
/// `ENOSYS` where the machine has no generic interrupt controller.
pub use super::registry::kernel::SIGNAL_CORE;

/// Read the hardware-provisioned ethernet MAC address from platform
/// sources (on bcm2712, the DTB passed by Pi 5 firmware). handle=-1,
/// arg=output buffer of exactly 6 bytes. Returns 6 on success, or
/// negative errno (ENODEV) if no MAC is available.
pub use super::registry::kernel::GET_HW_ETHERNET_MAC;

// ─────────────────────────────────────────────────────────────────────
// Provider query keys
// ─────────────────────────────────────────────────────────────────────
//
// Uniform introspection surface for `provider_query`. Contracts may
// define additional keys in a contract-specific numeric range.
pub mod query_key {
    /// Contract id (returns u8)
    pub use super::super::registry::kernel::QUERY_CLASS as CLASS;
    /// Heap statistics: the `heap_stats` record, exactly `heap_stats::LEN`
    /// bytes. handle=-1 queries the calling module's heap.
    pub use super::super::registry::kernel::QUERY_HEAP_STATS as HEAP_STATS;

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
    pub use super::super::registry::kernel::QUERY_LAST_FENCE as LAST_FENCE;

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
    pub use super::super::registry::kernel::QUERY_CALLER_OWNER as CALLER_OWNER;

    /// The module occupancy that invoked the provider frame currently
    /// running: `handle = -1`; writes `[module idx: u16 LE][_pad: u16]
    /// [slot generation: u32 LE]` (8 bytes) and returns 8. The generation
    /// moves whenever the slot is reset, restarted or given another module,
    /// so the pair names one occupancy: a provider stamps what it holds for
    /// a module with it and asks [`MODULE_LIVE`] later whether that
    /// occupancy still stands. `ESRCH` when nothing is on the provider stack.
    pub use super::super::registry::kernel::QUERY_CALLER_MODULE as CALLER_MODULE;

    /// Whether a module occupancy still stands: the out buffer carries an
    /// 8-byte record as [`CALLER_MODULE`] writes it, `handle = -1`. Returns 1
    /// when that slot still holds that generation and its module has not
    /// finished, 0 otherwise. A provider holding work for a module checks it
    /// lazily — before acting on the module's behalf — instead of relying on
    /// a release notification's timing.
    pub use super::super::registry::kernel::QUERY_MODULE_LIVE as MODULE_LIVE;
}

// ─────────────────────────────────────────────────────────────────────
// Handles
// ─────────────────────────────────────────────────────────────────────
//
// Every handle a module holds is a word the kernel minted:
// `0 | contract | generation | index` (`handle::encode`). A native object
// (a channel, event, timer or lend) is named by its slot in the kernel's own
// table; any other handle by a route the kernel keeps to the provider that
// serves it. A provider — kernel, platform or module — returns and receives
// only its own index, a non-negative `i32` it chooses. A handle whose
// generation is not its slot's current one names nothing (`EBADF`).
pub mod handle {
    pub use super::super::registry::handle::*;
}

/// A doorbell: how a provider signals the module that minted a signalling
/// handle (an op the registry marks `signals`). The kernel hands the provider
/// one per handle through `kernel::BIND_DOORBELL`; the provider rings it with
/// `kernel::DOORBELL_RING`. The minter's handle then polls ready once and the
/// minter is woken. A doorbell of a closed handle rings nothing.
pub mod doorbell {
    pub use super::super::registry::kernel::{BIND_DOORBELL, DOORBELL_RING};

    /// `BIND_DOORBELL`'s argument: `[doorbell u32][contract u16][0 u16]`.
    pub const BIND_ARG_LEN: usize = 8;
    /// `DOORBELL_RING`'s argument: `[doorbell u32]`.
    pub const RING_ARG_LEN: usize = 4;

    /// The `BIND_DOORBELL` argument handing `doorbell` for a handle of
    /// `contract`.
    pub const fn bind_arg(doorbell: u32, contract: u16) -> [u8; BIND_ARG_LEN] {
        let d = doorbell.to_le_bytes();
        let c = contract.to_le_bytes();
        [d[0], d[1], d[2], d[3], c[0], c[1], 0, 0]
    }

    /// `(doorbell, contract)` of a `BIND_DOORBELL` argument.
    pub fn parse_bind(arg: &[u8]) -> Option<(u32, u16)> {
        let b: &[u8; BIND_ARG_LEN] = arg.get(..BIND_ARG_LEN)?.try_into().ok()?;
        Some((
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
        ))
    }

    /// The `DOORBELL_RING` argument for `doorbell`.
    pub const fn ring_arg(doorbell: u32) -> [u8; RING_ARG_LEN] {
        doorbell.to_le_bytes()
    }
}

/// Provider instance selectors — the shared hash the kernel and modules
/// both compute so a provider's declared selector string and the name a
/// `BIND` by name carries resolve to the same u32 key.
pub mod provider_selector {
    /// FNV-1a hash of a short selector string (a volume / instance name
    /// such as `"nvme0"` or `"boot"`). Single source of truth for both
    /// sides of a `BIND` by name; keep it a `const fn` so a module can fold
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

/// `kernel::BIND`: open a handle bound to one provider of a contract
/// (`provider_open(contract, BIND, arg)`). Every op on the handle reaches
/// that provider; a handle an op on it mints is bound to the same one. The
/// handle names a provider, never a resource, so closing it closes nothing
/// the provider holds.
/// The one capability-discovery shape. Every contract with capability bits
/// has a `CAPS` op at low byte `0xFF`: `handle = -1` or a bound handle, no
/// `data`, `arg` out exactly [`caps_word::LEN`] bytes holding the `u32` LE
/// word, returning 0. Every provider of such a contract implements it, so
/// `ENOSYS` from `CAPS` means no provider.
pub mod caps_word {
    /// The `CAPS` argument's exact length.
    pub const LEN: usize = 4;
    /// Every `CAPS` op's low byte.
    pub const OP_LOW: u8 = 0xFF;

    /// Write `word` into a `CAPS` argument: 0, or `EINVAL` when `arg` is not
    /// exactly [`LEN`] bytes.
    pub fn answer(arg: &mut [u8], word: u32) -> i32 {
        if arg.len() != LEN {
            return super::errno::EINVAL;
        }
        arg.copy_from_slice(&word.to_le_bytes());
        0
    }

    /// The word a `CAPS` call answered into `arg`.
    pub fn parse(arg: &[u8]) -> Option<u32> {
        let b: [u8; LEN] = arg.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    }
}

pub mod bind {
    pub use super::super::registry::kernel::BIND;

    /// `[NAME][len u8][name]`: the instance-keyed layer registered under
    /// `name` (its `provider_selector::hash`), or for `platform` the
    /// platform's own provider beneath every module layer.
    pub const NAME: u8 = 1;
    /// `[PORT][port_type u8][index u8]`: the module at the other end of one
    /// of the caller's ports, which serves an edge contract on it.
    pub const PORT: u8 = 2;
    /// Longest name a `NAME` bind carries.
    pub const NAME_MAX: usize = 32;
    /// Longest `BIND` argument.
    pub const ARG_MAX: usize = 2 + NAME_MAX;

    /// Port types a `PORT` bind names, as `channel::PORT` numbers them.
    pub const PORT_IN: u8 = 0;
    pub const PORT_OUT: u8 = 1;
    pub const PORT_CTRL: u8 = 2;

    /// The `NAME` argument for `name` in `out`; its length, or `None` for a
    /// name that is empty or longer than [`NAME_MAX`].
    pub fn name(name: &[u8], out: &mut [u8; ARG_MAX]) -> Option<usize> {
        if name.is_empty() || name.len() > NAME_MAX {
            return None;
        }
        out[0] = NAME;
        out[1] = name.len() as u8;
        out[2..2 + name.len()].copy_from_slice(name);
        Some(2 + name.len())
    }

    /// The `PORT` argument for the caller's port `index` of `port_type`.
    pub const fn port(port_type: u8, index: u8) -> [u8; 3] {
        [PORT, port_type, index]
    }

    /// What a provider is handed as the handle of an op that reached it
    /// through a `PORT` bind: its own port on that edge.
    pub const fn port_ref(port_type: u8, index: u8) -> i32 {
        ((port_type as i32) << 8) | index as i32
    }

    /// The `(port_type, index)` a provider's port reference names.
    pub const fn split_port_ref(r: i32) -> (u8, u8) {
        (((r >> 8) & 0xFF) as u8, (r & 0xFF) as u8)
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
