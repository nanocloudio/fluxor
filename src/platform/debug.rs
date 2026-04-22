//! Platform-runtime debug drain.
//!
//! Owns the local-transport debug path: drains `kernel::log_ring` into a
//! board-provided `DebugTx` sink. Does **not** live in kernel — the
//! kernel owns `log_ring` and nothing transport-specific. This module is
//! a platform-runtime sibling, imported by platform entry points.
//!
//! The drain reads from the ring's local tail via `log_ring::drain_local`.
//! The net-side `LOG_RING_DRAIN` syscall uses an independent tail, so
//! both consumers see the same byte stream without contending for it.
//!
//! # Relationship to the emergency crash path
//!
//! This is the **normal-runtime** path. Panic / exception handlers do not
//! use it: they dump a snapshot of `log_ring` via
//! [`kernel::log_ring::read_tail`] over a platform-owned blocking
//! transport (raw UART on bcm2712, RTT / RAM breadcrumbs on rp, etc.)
//! that bypasses the scheduler entirely.
//!
//! # Backpressure policy
//!
//! The drain owns one staging buffer plus `(pending_len, pending_off)`.
//! Each call to [`DebugDrain::poll`] performs at most two writes to the
//! sink:
//!
//! 1. If a pending tail exists, call `write()` once on its remaining
//!    bytes. If the sink short-writes, the offset advances and the poll
//!    returns without draining fresh bytes from the ring.
//! 2. If there is no pending tail (either none existed, or step 1
//!    cleared it), drain at most one fresh chunk from `log_ring` and
//!    call `write()` once on it. Any short-write is staged as the new
//!    pending tail.
//!
//! There is no inner retry loop, no wall-time spin budget, and the
//! producer is never blocked. If the sink stays stalled, the drain's
//! staging buffer fills first, after which new bytes are lost only
//! through the existing `log_ring` drop-new overflow behavior.
//!
//! # Staging buffer sizing
//!
//! The staging size is supplied as a const generic so each platform can
//! pick a size matched to its transport's natural chunk:
//!
//! - **bcm2712**: `DebugDrain<1024>` — UART FIFO + tight tick cadence.
//! - **rp2350**: `DebugDrain<256>`  — USB CDC 64-byte MTU, tighter SRAM.
//!
//! The staging buffer sits entirely inside the drain struct; place the
//! static in `.bss` via `static mut` or a suitable lock pattern on the
//! board side.

use crate::kernel::log_ring;

/// Write raw bytes to a local debug transport.
///
/// # Semantics
///
/// - Non-allocating, non-blocking (normal-runtime paths only).
/// - May short-write: returns the number of bytes actually accepted.
///   Blocking sinks simply return `bytes.len()`; async/enqueue sinks
///   return whatever their underlying queue accepted.
/// - Not usable from panic / exception context: emergency crash output
///   goes through a platform-owned blocking path, not through this
///   trait.
pub trait DebugTx {
    fn write(&mut self, bytes: &[u8]) -> usize;
}

/// A sink that discards everything. Use on boards with no local debug
/// transport; paired with a running drain, the local tail still advances
/// and the ring does not fill on the local side.
pub struct NullTx;

impl DebugTx for NullTx {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> usize {
        bytes.len()
    }
}

/// Drains `kernel::log_ring` into a [`DebugTx`] sink with single-tail
/// staging. See module docs for the backpressure policy.
pub struct DebugDrain<const N: usize> {
    staging: [u8; N],
    pending_len: u16,
    pending_off: u16,
}

impl<const N: usize> DebugDrain<N> {
    pub const fn new() -> Self {
        const {
            assert!(N > 0 && N <= u16::MAX as usize, "staging size out of range");
        }
        Self {
            staging: [0; N],
            pending_len: 0,
            pending_off: 0,
        }
    }

    /// Perform one drain poll. Idempotent when there is nothing to do.
    ///
    /// Caller supplies the sink so the drain state can be static and
    /// distinct from the sink's own state (which often needs a different
    /// lifetime, e.g. a board-held UART handle or an Embassy pipe ref).
    pub fn poll<T: DebugTx + ?Sized>(&mut self, sink: &mut T) {
        if self.pending_len > 0 {
            let start = self.pending_off as usize;
            let end = self.pending_len as usize;
            let written = sink.write(&self.staging[start..end]);
            let new_off = start + written;
            if new_off < end {
                self.pending_off = new_off as u16;
                return;
            }
            self.pending_len = 0;
            self.pending_off = 0;
        }

        let n = log_ring::drain_local(&mut self.staging);
        if n == 0 {
            return;
        }
        let written = sink.write(&self.staging[..n]);
        if written < n {
            self.pending_len = n as u16;
            self.pending_off = written as u16;
        }
    }

    /// Bytes currently staged but not yet accepted by the sink. Useful
    /// for telemetry / heartbeat.
    #[inline]
    pub fn pending(&self) -> usize {
        (self.pending_len - self.pending_off) as usize
    }

    /// Discard any bytes staged but not yet accepted by the sink. Called
    /// by the platform runtime when the sink goes offline (e.g. USB CDC
    /// host detaches) so the next attach does not replay pre-detach
    /// bytes as if they were current.
    #[inline]
    pub fn reset(&mut self) {
        self.pending_len = 0;
        self.pending_off = 0;
    }
}

impl<const N: usize> Default for DebugDrain<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sink that accepts the first `accept` bytes of every write and
    /// rejects the rest, so the drain is forced to stage a pending tail.
    struct Partial {
        accept: usize,
    }
    impl DebugTx for Partial {
        fn write(&mut self, bytes: &[u8]) -> usize {
            core::cmp::min(bytes.len(), self.accept)
        }
    }

    /// After `reset`, a drain that had a non-empty pending tail must
    /// behave like a fresh drain: its next `poll` does not replay the
    /// pre-reset bytes, and `pending()` reports zero.
    #[test]
    fn reset_discards_pending_tail() {
        // Normalise ring state: disable + re-activate seeds the local
        // tail to the current HEAD, so the bytes pushed below are the
        // only ones this drain can see.
        crate::kernel::log_ring::disable_local();
        crate::kernel::log_ring::activate_local();

        // Push more bytes than the sink will accept in one call so the
        // drain is forced to stage a pending tail.
        for _ in 0..10 {
            crate::kernel::log_ring::push_byte(b'P');
        }

        let mut drain: DebugDrain<16> = DebugDrain::new();
        let mut sink = Partial { accept: 4 };
        drain.poll(&mut sink);
        assert!(
            drain.pending() > 0,
            "expected pending tail after short sink write (pending={})",
            drain.pending()
        );

        drain.reset();
        assert_eq!(drain.pending(), 0);

        // With nothing staged and no fresh ring bytes, a subsequent
        // poll against a fully-accepting sink is a no-op — the pre-reset
        // bytes must not be replayed.
        let mut accepting = Partial { accept: usize::MAX };
        drain.poll(&mut accepting);
        assert_eq!(drain.pending(), 0);
    }
}
