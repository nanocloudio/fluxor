//! Module flavors and the slot enum the scheduler stores them in.
//!
//! Five concrete `Module` impls live behind `ModuleSlot::*`:
//!
//! - `Empty`                   — slot not in use.
//! - `Dynamic(DynamicModule)`  — a PIC `.fmod` loaded by `kernel::loader`;
//!   the struct itself lives in the loader, the slot just carries it.
//! - `Dummy(DummyModule)`      — a placeholder that always returns
//!   `Continue`; useful as a no-op while bringing up a graph.
//! - `Tee(TeeModule)`          — kernel-side fan-out (1-in / N-out byte
//!   forwarder). Inserted by the graph compiler when one producer
//!   feeds multiple consumers.
//! - `Merge(MergeModule)`      — kernel-side fan-in (N-in / 1-out byte
//!   forwarder, round-robin between inputs).
//! - `BuiltIn(BuiltInModule)`  — a statically-linked `(name, step_fn)`
//!   pair, used by platforms without PIC loading (linux/wasm builtins,
//!   plus the wasm proxy that dispatches into a host-loaded wasm
//!   module instance).
//!
//! ## Concurrency
//!
//! `FAN_BUFS[d]` is per-domain scratch shared by `TeeModule` and
//! `MergeModule`. Every tee/merge inherits its fan group's `domain_id`
//! at construction (see `instantiate_one_module`); a domain runs on
//! exactly one core, so indexing by `domain` keeps each core on its
//! own buffer. See `docs/architecture/concurrency.md`.

use super::{MAX_CHANNELS, MAX_DOMAINS, MAX_PORTS};
use crate::kernel::channel;
use crate::kernel::loader::DynamicModule;
use crate::modules::{Module, StepOutcome};

// ============================================================================
// FAN_BUFS — per-domain scratch for Tee / Merge
// ============================================================================

/// Per-domain scratch buffer for tee/merge fan modules. Caps the
/// per-step bytes a fan can shuttle from one input ring to its
/// output(s); a throughput knob, not a correctness invariant —
/// raw-byte fan-out splits at this cap, frame-aware fan-out (see
/// `step_framed`) defers a frame whose total exceeds it.
///
/// One entry per domain because tee/merge inherit their fan group's
/// `domain_id` (see `push_internal_module`); on multicore platforms a
/// domain runs on exactly one core, so indexing by `domain_id` keeps
/// each core on its own buffer.
///
///   * **aarch64** — 32 KiB. ETH rings can hit 32 KiB on Pi-class
///     targets; one step drains a full ring.
///   * **chip-rp2040 / chip-rp2350b** — 2 KiB. RP chips have tight
///     `.bss` budgets; audio fan-out (~1 KiB chunks) and the log_net
///     merge stay well below this.
///   * **wasm32 / linux host** — 8 KiB, matching the default
///     `CHANNEL_BUFFER_SIZE`.
#[cfg(target_arch = "aarch64")]
const FAN_BUF_SIZE: usize = 32768;
#[cfg(any(feature = "chip-rp2040", feature = "chip-rp2350b"))]
const FAN_BUF_SIZE: usize = 2048;
#[cfg(all(
    not(target_arch = "aarch64"),
    not(feature = "chip-rp2040"),
    not(feature = "chip-rp2350b"),
))]
const FAN_BUF_SIZE: usize = 8192;
static mut FAN_BUFS: [[u8; FAN_BUF_SIZE]; MAX_DOMAINS] = [[0u8; FAN_BUF_SIZE]; MAX_DOMAINS];

// ============================================================================
// ModuleSlot
// ============================================================================

/// Module slot - holds an instantiated module
pub enum ModuleSlot {
    Empty,
    /// Dynamically loaded PIC module
    Dynamic(DynamicModule),
    Dummy(DummyModule),
    Tee(TeeModule),
    Merge(MergeModule),
    /// Statically linked built-in module (function pointers + state buffer).
    /// Used on platforms without PIC loading (e.g. aarch64 QEMU).
    BuiltIn(BuiltInModule),
}

impl ModuleSlot {
    /// Returns true if this slot contains a dynamically loaded PIC module
    pub fn is_dynamic(&self) -> bool {
        matches!(self, ModuleSlot::Dynamic(_))
    }

    /// Returns the module type as a string for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            ModuleSlot::Empty => "empty",
            ModuleSlot::Dynamic(_) => "dynamic",
            ModuleSlot::Dummy(_) => "dummy",
            ModuleSlot::Tee(_) => "tee",
            ModuleSlot::Merge(_) => "merge",
            ModuleSlot::BuiltIn(m) => m.name,
        }
    }

    pub(super) fn as_module_mut(&mut self) -> Option<&mut dyn Module> {
        match self {
            ModuleSlot::Empty => None,
            ModuleSlot::Dynamic(m) => Some(m),
            ModuleSlot::Dummy(m) => Some(m),
            ModuleSlot::Tee(m) => Some(m),
            ModuleSlot::Merge(m) => Some(m),
            ModuleSlot::BuiltIn(m) => Some(m),
        }
    }
}

// ============================================================================
// DummyModule
// ============================================================================

pub struct DummyModule;

impl Module for DummyModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "dummy"
    }
}

// ============================================================================
// BuiltInModule
// ============================================================================

/// Built-in module: step function pointer + opaque state.
/// Used for statically-linked modules on platforms without PIC loading.
pub struct BuiltInModule {
    pub name: &'static str,
    step_fn: fn(*mut u8) -> i32,
    pub state: [u8; 64], // Fixed-size state (enough for channel handles + counters)
}

impl BuiltInModule {
    pub fn new(name: &'static str, step_fn: fn(*mut u8) -> i32) -> Self {
        Self {
            name,
            step_fn,
            state: [0u8; 64],
        }
    }
}

impl Module for BuiltInModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        let rc = (self.step_fn)(self.state.as_mut_ptr());
        match rc {
            0 => Ok(StepOutcome::Continue),
            1 => Ok(StepOutcome::Done),
            2 => Ok(StepOutcome::Burst),
            3 => Ok(StepOutcome::Ready),
            _ => Err(rc),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ============================================================================
// TeeModule
// ============================================================================

/// Wire format of frames flowing through a fan module's input port.
/// `port_frame_kind_from_content_type` (in `scheduler::mod`) maps a
/// fanned port's manifest `content_type` byte to one of these
/// values; the fan reads the per-frame length prefix accordingly so
/// a transfer covers one whole frame and preserves producer
/// atomic-write boundaries.
pub const FRAME_KIND_NONE: u8 = 0;
/// `[len:u16 LE][payload:len]` — content_type `EthernetFrame`
/// (NIC ↔ IP).
pub const FRAME_KIND_ETH: u8 = 1;
/// `[msg_type:u8][len:u16 LE][payload:len]` — content_type
/// `NetProto` (IP / TLS / QUIC ↔ consumer ports). msg_type at
/// byte 0, little-endian length at bytes 1..3.
pub const FRAME_KIND_NET: u8 = 2;

/// Manifest `content_type` byte values that map to a non-NONE
/// `FRAME_KIND_*`. Position must match `tools::manifest::CONTENT_TYPES`.
pub const CONTENT_TYPE_ETHERNET_FRAME: u8 = 19;
pub const CONTENT_TYPE_NET_PROTO: u8 = 30;

pub struct TeeModule {
    in_chan: i32,
    /// Channel handles for each tee output. Sized to `MAX_PORTS` so the
    /// enum slot stays compact: `populate_ports` already caps any
    /// module's port count at `MAX_PORTS`, and the `ModuleSlot` enum
    /// reserves space for its largest variant in every slot regardless
    /// of which variant is in use.
    out_chans: [i32; MAX_PORTS],
    out_count: usize,
    /// Domain this tee runs in. Selects which `FAN_BUFS` entry the
    /// `step` body uses so concurrent fan modules on different cores
    /// don't share a scratch buffer.
    domain: u8,
    /// Wire format of the input frames. `FRAME_KIND_NONE` keeps the
    /// best-effort byte-stream forwarder (audio fan-out, log_net
    /// merge); `FRAME_KIND_ETH` / `FRAME_KIND_NET` switch to
    /// frame-aware transfer.
    frame_kind: u8,
}

impl TeeModule {
    pub(super) fn new(
        in_chan: i32,
        out_chans: &[i32; MAX_CHANNELS],
        out_count: usize,
        domain: u8,
        frame_kind: u8,
    ) -> Self {
        let mut chans = [-1i32; MAX_PORTS];
        let n = out_count.min(MAX_PORTS);
        let mut i = 0;
        while i < n {
            chans[i] = out_chans[i];
            i += 1;
        }
        Self {
            in_chan,
            out_chans: chans,
            out_count: n,
            domain,
            frame_kind,
        }
    }
}

impl Module for TeeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.in_chan < 0 || self.out_count == 0 {
            return Err(-1);
        }

        if self.frame_kind != FRAME_KIND_NONE {
            return unsafe { self.step_framed() };
        }

        // Raw byte-stream fan-out: shift up to `min(in_len,
        // FAN_BUF_SIZE, min_out_space)` bytes from the input to every
        // output, then return. Producer atomic-write boundaries can
        // split here; ports that need frame preservation route through
        // `step_framed` via `port_frame_kind`.
        let in_len = channel::channel_readable_bytes(self.in_chan);
        if in_len == 0 {
            return Ok(StepOutcome::Continue);
        }

        let buf = unsafe {
            let p = &raw mut FAN_BUFS[self.domain as usize];
            &mut *p
        };

        let mut read_amount = in_len.min(buf.len());
        for idx in 0..self.out_count {
            let out_space = channel::channel_writable_bytes(self.out_chans[idx]);
            if out_space < read_amount {
                read_amount = out_space;
            }
        }
        if read_amount == 0 {
            return Ok(StepOutcome::Continue);
        }

        let read =
            unsafe { channel::syscall_channel_read(self.in_chan, buf.as_mut_ptr(), read_amount) };
        if read <= 0 {
            return Ok(StepOutcome::Continue);
        }

        let len = read as usize;
        for idx in 0..self.out_count {
            let wrote =
                unsafe { channel::syscall_channel_write(self.out_chans[idx], buf.as_ptr(), len) };
            if wrote != read {
                // Output space was pre-checked; a short write would
                // mean the kernel's atomic-FIFO contract was broken.
                return Err(-2);
            }
        }

        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "tee"
    }
}

impl TeeModule {
    /// Frame-aware step body. Inspects the input ring's length-prefixed
    /// header via `channel_peek` (no consume), validates that every
    /// output ring has space for the full frame, then commits the
    /// read and writes atomically. Because nothing is consumed from
    /// the input until all outputs can absorb the frame, the per-
    /// domain `FAN_BUFS` scratch is only ever used within a single
    /// step — no stash race between fans in the same domain.
    unsafe fn step_framed(&mut self) -> Result<StepOutcome, i32> {
        let avail = channel::channel_readable_bytes(self.in_chan);
        let hdr_len = frame_kind_hdr_len(self.frame_kind);
        if avail < hdr_len {
            return Ok(StepOutcome::Continue);
        }

        // Peek just enough bytes to read the length field — no
        // consume yet, so a backpressured output doesn't strand the
        // header in our scratch.
        let mut hdr = [0u8; 3];
        let peeked = unsafe { channel::channel_peek(self.in_chan, hdr.as_mut_ptr(), hdr_len) };
        if peeked != hdr_len as i32 {
            return Err(-3);
        }
        let frame_len = decode_frame_len(self.frame_kind, &hdr);
        let total = hdr_len + frame_len;

        let buf = unsafe {
            let p = &raw mut FAN_BUFS[self.domain as usize];
            &mut *p
        };
        // Zero-length payload is fatal for ETH (eth frames always carry
        // ≥ 1 byte) but valid for NET — net_proto control frames carry
        // a header alone (e.g. CMD_BIND with no payload). Reject only
        // the truly anomalous cases.
        if total > buf.len() {
            // Frame doesn't fit FAN_BUFS scratch — a config-time
            // topology error.
            return Err(-4);
        }
        if frame_len == 0 && self.frame_kind == FRAME_KIND_ETH {
            return Err(-4);
        }

        // Full frame must already be present (atomic FIFO write
        // commits header + body together) and every output ring must
        // have room for it. If any precondition fails, defer without
        // consuming — the input bytes stay in the ring for the next
        // tick to retry.
        if avail < total {
            return Ok(StepOutcome::Continue);
        }
        for idx in 0..self.out_count {
            if channel::channel_writable_bytes(self.out_chans[idx]) < total {
                return Ok(StepOutcome::Continue);
            }
        }

        let read = unsafe { channel::syscall_channel_read(self.in_chan, buf.as_mut_ptr(), total) };
        if read != total as i32 {
            return Err(-5);
        }
        for idx in 0..self.out_count {
            let wrote =
                unsafe { channel::syscall_channel_write(self.out_chans[idx], buf.as_ptr(), total) };
            if wrote != total as i32 {
                return Err(-2);
            }
        }
        Ok(StepOutcome::Continue)
    }
}

/// Bytes in the wire-format header for each frame kind. Returned
/// length determines how many bytes `channel_peek` reads to inspect
/// the length field before the fan commits to a full frame transfer.
#[inline(always)]
pub(super) fn frame_kind_hdr_len(kind: u8) -> usize {
    match kind {
        FRAME_KIND_ETH => 2,
        FRAME_KIND_NET => 3,
        _ => 0,
    }
}

/// Decode the payload length out of a peeked header.
#[inline(always)]
pub(super) fn decode_frame_len(kind: u8, hdr: &[u8; 3]) -> usize {
    match kind {
        FRAME_KIND_ETH => (hdr[0] as usize) | ((hdr[1] as usize) << 8),
        // net_proto: msg_type at hdr[0], len at hdr[1..3].
        FRAME_KIND_NET => (hdr[1] as usize) | ((hdr[2] as usize) << 8),
        _ => 0,
    }
}

// ============================================================================
// MergeModule
// ============================================================================

pub struct MergeModule {
    /// Channel handles for each merge input; see `TeeModule::out_chans`
    /// for the sizing rationale.
    in_chans: [i32; MAX_PORTS],
    in_count: usize,
    out_chan: i32,
    next_idx: usize,
    /// Domain this merge runs in. Selects which `FAN_BUFS` entry the
    /// `step` body uses; see `TeeModule::domain`.
    domain: u8,
    /// Wire format of the input frames. See `TeeModule::frame_kind`.
    frame_kind: u8,
}

impl MergeModule {
    pub(super) fn new(
        in_chans: &[i32; MAX_CHANNELS],
        in_count: usize,
        out_chan: i32,
        domain: u8,
        frame_kind: u8,
    ) -> Self {
        let mut chans = [-1i32; MAX_PORTS];
        let n = in_count.min(MAX_PORTS);
        let mut i = 0;
        while i < n {
            chans[i] = in_chans[i];
            i += 1;
        }
        Self {
            in_chans: chans,
            in_count: n,
            out_chan,
            next_idx: 0,
            domain,
            frame_kind,
        }
    }
}

impl Module for MergeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.out_chan < 0 || self.in_count == 0 {
            return Err(-1);
        }

        if self.frame_kind != FRAME_KIND_NONE {
            return unsafe { self.step_framed() };
        }

        // Raw byte-stream fan-in (mirror of `TeeModule::step` raw
        // path): round-robin across inputs, copy `min(in_len,
        // FAN_BUF_SIZE, out_space)` bytes from the first non-empty
        // source into the output. Producer atomic-write boundaries
        // can split; framed ports route through `step_framed`.
        for _ in 0..self.in_count {
            let idx = self.next_idx % self.in_count;
            self.next_idx = (self.next_idx + 1) % self.in_count;
            let chan = self.in_chans[idx];

            let in_len = channel::channel_readable_bytes(chan);
            if in_len == 0 {
                continue;
            }

            let buf = unsafe {
                let p = &raw mut FAN_BUFS[self.domain as usize];
                &mut *p
            };
            let out_space = channel::channel_writable_bytes(self.out_chan);
            let read_amount = in_len.min(buf.len()).min(out_space);
            if read_amount == 0 {
                continue;
            }

            let read =
                unsafe { channel::syscall_channel_read(chan, buf.as_mut_ptr(), read_amount) };
            if read <= 0 {
                continue;
            }

            let wrote = unsafe {
                channel::syscall_channel_write(self.out_chan, buf.as_ptr(), read as usize)
            };
            if wrote != read {
                // Output space was pre-checked; a short write would
                // mean the kernel's atomic-FIFO contract was broken.
                return Err(-2);
            }

            return Ok(StepOutcome::Continue);
        }

        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "merge"
    }
}

impl MergeModule {
    /// Frame-aware step body. Round-robins across inputs; the first
    /// one with a complete frame whose entire size fits in the output
    /// ring gets transferred atomically. Like `TeeModule::step_framed`
    /// the input is only consumed after every precondition passes,
    /// so the per-domain `FAN_BUFS` scratch is never held across
    /// step calls.
    unsafe fn step_framed(&mut self) -> Result<StepOutcome, i32> {
        let buf = unsafe {
            let p = &raw mut FAN_BUFS[self.domain as usize];
            &mut *p
        };
        let hdr_len = frame_kind_hdr_len(self.frame_kind);

        for _ in 0..self.in_count {
            let idx = self.next_idx % self.in_count;
            self.next_idx = (self.next_idx + 1) % self.in_count;
            let chan = self.in_chans[idx];

            let avail = channel::channel_readable_bytes(chan);
            if avail < hdr_len {
                continue;
            }

            let mut hdr = [0u8; 3];
            let peeked = unsafe { channel::channel_peek(chan, hdr.as_mut_ptr(), hdr_len) };
            if peeked != hdr_len as i32 {
                return Err(-3);
            }
            let frame_len = decode_frame_len(self.frame_kind, &hdr);
            let total = hdr_len + frame_len;
            if total > buf.len() {
                return Err(-4);
            }
            if frame_len == 0 && self.frame_kind == FRAME_KIND_ETH {
                return Err(-4);
            }
            if avail < total {
                continue;
            }
            if channel::channel_writable_bytes(self.out_chan) < total {
                continue;
            }

            let read = unsafe { channel::syscall_channel_read(chan, buf.as_mut_ptr(), total) };
            if read != total as i32 {
                return Err(-5);
            }
            let wrote =
                unsafe { channel::syscall_channel_write(self.out_chan, buf.as_ptr(), total) };
            if wrote != total as i32 {
                return Err(-2);
            }
            return Ok(StepOutcome::Continue);
        }

        Ok(StepOutcome::Continue)
    }
}
