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
use crate::kernel::channel::{self, POLL_IN, POLL_OUT};
use crate::kernel::loader::DynamicModule;
use crate::modules::{Module, StepOutcome};

// ============================================================================
// FAN_BUFS — per-domain scratch for Tee / Merge
// ============================================================================

/// Per-domain scratch buffer for tee/merge fan modules.
///
/// Sized independently of `CHANNEL_BUFFER_SIZE`: fan-out is a byte-stream
/// forwarder (channels don't preserve write boundaries), so this is a
/// per-step throughput knob, not a message-atomicity guarantee.
/// Producers that need larger atomic transfers should connect peers
/// directly rather than routing through tee/merge. 2 KiB matches
/// typical streaming chunks and keeps `.bss` small on Cortex-M targets.
///
/// One entry per domain because tee/merge inherit their fan group's
/// `domain_id` (see `push_internal_module`); on multicore platforms a
/// domain runs on exactly one core, so indexing by `domain_id` keeps
/// each core on its own buffer. RP and wasm pin everything to domain 0
/// — total footprint is 4 entries × 2 KiB = 8 KiB on every target,
/// acceptable even on rp2040.
const FAN_BUF_SIZE: usize = 2048;
static mut FAN_BUFS: [[u8; FAN_BUF_SIZE]; MAX_DOMAINS] =
    [[0u8; FAN_BUF_SIZE]; MAX_DOMAINS];

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
}

impl TeeModule {
    pub(super) fn new(
        in_chan: i32,
        out_chans: &[i32; MAX_CHANNELS],
        out_count: usize,
        domain: u8,
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
        }
    }
}

impl Module for TeeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.in_chan < 0 || self.out_count == 0 {
            return Err(-1);
        }

        if channel::syscall_channel_poll(self.in_chan, POLL_IN) & (POLL_IN as i32) == 0 {
            return Ok(StepOutcome::Continue);
        }

        for idx in 0..self.out_count {
            if channel::syscall_channel_poll(self.out_chans[idx], POLL_OUT) & (POLL_OUT as i32) == 0
            {
                return Ok(StepOutcome::Continue);
            }
        }

        let buf = unsafe {
            let p = &raw mut FAN_BUFS[self.domain as usize];
            &mut *p
        };
        let read =
            unsafe { channel::syscall_channel_read(self.in_chan, buf.as_mut_ptr(), buf.len()) };
        if read <= 0 {
            return Ok(StepOutcome::Continue);
        }

        let len = read as usize;
        for idx in 0..self.out_count {
            let wrote =
                unsafe { channel::syscall_channel_write(self.out_chans[idx], buf.as_ptr(), len) };
            if wrote != read {
                return Err(-2);
            }
        }

        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "tee"
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
}

impl MergeModule {
    pub(super) fn new(
        in_chans: &[i32; MAX_CHANNELS],
        in_count: usize,
        out_chan: i32,
        domain: u8,
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
        }
    }
}

impl Module for MergeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.out_chan < 0 || self.in_count == 0 {
            return Err(-1);
        }

        if channel::syscall_channel_poll(self.out_chan, POLL_OUT) & (POLL_OUT as i32) == 0 {
            return Ok(StepOutcome::Continue);
        }

        for _ in 0..self.in_count {
            let idx = self.next_idx % self.in_count;
            self.next_idx = (self.next_idx + 1) % self.in_count;
            let chan = self.in_chans[idx];

            if channel::syscall_channel_poll(chan, POLL_IN) & (POLL_IN as i32) == 0 {
                continue;
            }

            let buf = unsafe {
                let p = &raw mut FAN_BUFS[self.domain as usize];
                &mut *p
            };
            let read = unsafe { channel::syscall_channel_read(chan, buf.as_mut_ptr(), buf.len()) };
            if read <= 0 {
                return Ok(StepOutcome::Continue);
            }

            let wrote = unsafe {
                channel::syscall_channel_write(self.out_chan, buf.as_ptr(), read as usize)
            };
            if wrote != read {
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
