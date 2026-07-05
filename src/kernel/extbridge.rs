//! Bounded external-node bridge (rfc_k8s.md §6.8, Q13).
//!
//! The data path between a graph-resident proxy module and an external-hosted
//! process (Linux OCI/`linux.oci` executor). The §6.8 contract this enforces:
//! every bridge is a **bounded queue with a declared overload policy** — it may
//! reject or throttle the external producer, drop per policy, or mark the
//! workload NotReady, but it may **never block `module_step` or grow without
//! bound**.
//!
//! Frame-oriented: each push is one frame (a length header + payload in the
//! ring), so overload drops whole frames and framing survives every policy.
//! Raw byte-stream passthrough (TCP-style) uses frames as arbitrary chunks —
//! byte-stream semantics are preserved because chunk boundaries carry no
//! meaning there. This is the Q13 framing decision: length-prefixed frames for
//! typed unix/stdio content, chunked passthrough for raw streams.
//!
//! Concurrency: SPSC. One producer (the platform worker thread pumping the
//! external process) and one consumer (`module_step` polling). For `Block` /
//! `DropNewest` / `NotReady` the producer never touches the tail, so the
//! consumer is wait-free and owns the tail exclusively. `DropOldest` is the
//! exception: the producer must free from the front, so producer-eviction and
//! consumer-pop both advance the tail — and would otherwise race (the producer
//! frees, then its head-write overwrites, bytes the consumer is mid-copy on, a
//! data race on the non-atomic ring). Under `DropOldest` both sides therefore
//! guard the tail-advance + byte copy with `xlock`: the producer *blocks* on it
//! (it is the pump thread, never `module_step`), while the consumer *try-locks*
//! and, if the producer holds it mid-eviction, returns "no frame this tick"
//! rather than spinning — so `module_step` is never blocked. `no_std`,
//! allocation-free.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

/// What the bridge does when a push does not fit (rfc_k8s.md §6.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverloadPolicy {
    /// Reject the push; the producer throttles/backpressures the external
    /// process. (Never blocks the consumer — "Block" is the producer's stance.)
    Block,
    /// Evict oldest frames until the new one fits.
    DropOldest,
    /// Discard the incoming frame.
    DropNewest,
    /// Reject the push and latch the NotReady flag for workload health
    /// aggregation; clears when the consumer drains below the high-water mark.
    NotReady,
}

/// Outcome of a push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Frame enqueued.
    Ok,
    /// Frame enqueued after evicting `n` older frames (`DropOldest`).
    OkDroppedOldest(u16),
    /// Frame rejected (`Block` / `NotReady`); producer should throttle.
    Rejected,
    /// Frame discarded (`DropNewest`).
    DroppedNewest,
    /// Frame larger than the ring can ever hold — configuration error.
    TooLarge,
}

/// Frame length header width in the ring.
const HDR: usize = 4;

/// A bounded SPSC frame bridge over a caller-supplied backing ring.
///
/// `CAP` must be a power of two. Total in-ring footprint of a frame is
/// `HDR + len`, so the largest pushable frame is `CAP - HDR`.
pub struct ExtBridge<const CAP: usize> {
    buf: core::cell::UnsafeCell<[u8; CAP]>,
    /// Producer cursor (monotonic; wraps modulo CAP on access).
    head: AtomicU32,
    /// Consumer cursor (monotonic). CAS-mutated: pop (consumer) and
    /// drop-oldest eviction (producer) both claim via compare_exchange.
    tail: AtomicU32,
    policy: OverloadPolicy,
    not_ready: AtomicBool,
    dropped_frames: AtomicU32,
    rejected_pushes: AtomicU32,
    /// Exclusive lock held (only under `DropOldest`) while a side advances the
    /// tail + copies frame bytes, so producer-eviction and consumer-pop never
    /// race the non-atomic ring bytes. Uncontended for the other policies.
    xlock: AtomicBool,
}

// SAFETY: SPSC contract — interior buffer bytes are only written by the single
// producer in the region [head, head+frame) which the consumer never reads
// until head is published with Release; cursor coordination is atomic.
unsafe impl<const CAP: usize> Sync for ExtBridge<CAP> {}

impl<const CAP: usize> ExtBridge<CAP> {
    pub const fn new(policy: OverloadPolicy) -> Self {
        assert!(
            CAP.is_power_of_two(),
            "ExtBridge CAP must be a power of two"
        );
        assert!(CAP > HDR, "ExtBridge CAP must exceed the frame header");
        ExtBridge {
            buf: core::cell::UnsafeCell::new([0u8; CAP]),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            policy,
            not_ready: AtomicBool::new(false),
            dropped_frames: AtomicU32::new(0),
            rejected_pushes: AtomicU32::new(0),
            xlock: AtomicBool::new(false),
        }
    }

    /// Producer-side blocking acquire (the producer is the external-process
    /// pump thread, never `module_step`, so it may wait out a consumer copy).
    #[inline]
    fn lock(&self) {
        while self
            .xlock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    /// Consumer-side non-blocking acquire. Returns false if the producer holds
    /// the lock (briefly, for a single eviction) — the consumer then treats this
    /// tick as "no frame yet" rather than spinning, honouring the never-block-
    /// `module_step` contract.
    #[inline]
    fn try_lock(&self) -> bool {
        self.xlock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    fn unlock(&self) {
        self.xlock.store(false, Ordering::Release);
    }

    #[inline]
    fn used(&self, head: u32, tail: u32) -> usize {
        head.wrapping_sub(tail) as usize
    }

    /// Bytes currently enqueued (headers included).
    pub fn len_bytes(&self) -> usize {
        self.used(
            self.head.load(Ordering::Acquire),
            self.tail.load(Ordering::Acquire),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.len_bytes() == 0
    }

    /// NotReady latch state (workload health aggregation reads this).
    pub fn not_ready(&self) -> bool {
        self.not_ready.load(Ordering::Acquire)
    }

    /// Total frames evicted/discarded by overload policy.
    pub fn dropped_frames(&self) -> u32 {
        self.dropped_frames.load(Ordering::Relaxed)
    }

    /// Total pushes rejected (`Block`/`NotReady`).
    pub fn rejected_pushes(&self) -> u32 {
        self.rejected_pushes.load(Ordering::Relaxed)
    }

    #[inline]
    fn write_bytes(&self, at: u32, src: &[u8]) {
        // SAFETY: producer-exclusive region [head, head+frame); see Sync note.
        let buf = unsafe { &mut *self.buf.get() };
        let mut pos = at as usize;
        for &b in src {
            buf[pos & (CAP - 1)] = b;
            pos += 1;
        }
    }

    #[inline]
    fn read_bytes(&self, at: u32, dst: &mut [u8]) {
        // SAFETY: consumer reads only below the Acquire-loaded head.
        let buf = unsafe { &*self.buf.get() };
        let mut pos = at as usize;
        for b in dst.iter_mut() {
            *b = buf[pos & (CAP - 1)];
            pos += 1;
        }
    }

    #[inline]
    fn frame_len_at(&self, at: u32) -> usize {
        let mut hdr = [0u8; HDR];
        self.read_bytes(at, &mut hdr);
        u32::from_le_bytes(hdr) as usize
    }

    /// Producer: enqueue one frame. Wait-free except the bounded `DropOldest`
    /// eviction loop. Never blocks; never grows past `CAP`.
    pub fn push_frame(&self, frame: &[u8]) -> PushOutcome {
        let need = HDR + frame.len();
        if need > CAP {
            return PushOutcome::TooLarge;
        }
        let head = self.head.load(Ordering::Relaxed);
        let mut evicted: u16 = 0;
        loop {
            let tail = self.tail.load(Ordering::Acquire);
            if CAP - self.used(head, tail) >= need {
                // Space available: write payload after header, publish head.
                self.write_bytes(head, &(frame.len() as u32).to_le_bytes());
                self.write_bytes(head.wrapping_add(HDR as u32), frame);
                self.head
                    .store(head.wrapping_add(need as u32), Ordering::Release);
                // Drained below full → clear NotReady latch opportunistically.
                if self.policy == OverloadPolicy::NotReady {
                    self.not_ready.store(false, Ordering::Release);
                }
                return if evicted > 0 {
                    self.dropped_frames
                        .fetch_add(evicted as u32, Ordering::Relaxed);
                    PushOutcome::OkDroppedOldest(evicted)
                } else {
                    PushOutcome::Ok
                };
            }
            match self.policy {
                OverloadPolicy::Block => {
                    self.rejected_pushes.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::Rejected;
                }
                OverloadPolicy::NotReady => {
                    self.not_ready.store(true, Ordering::Release);
                    self.rejected_pushes.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::Rejected;
                }
                OverloadPolicy::DropNewest => {
                    self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::DroppedNewest;
                }
                OverloadPolicy::DropOldest => {
                    // Evict the oldest frame under `xlock` so it cannot race a
                    // concurrent pop's byte copy (the freed region is reused by a
                    // later head-write). Re-read the tail under the lock; if the
                    // consumer already drained it, the outer loop re-checks space.
                    self.lock();
                    let t = self.tail.load(Ordering::Acquire);
                    let h = self.head.load(Ordering::Acquire);
                    if self.used(h, t) != 0 {
                        let flen = self.frame_len_at(t);
                        self.tail
                            .store(t.wrapping_add((HDR + flen) as u32), Ordering::Release);
                        evicted = evicted.saturating_add(1);
                    }
                    self.unlock();
                }
            }
        }
    }

    /// Consumer: dequeue one frame into `out`. Returns the frame length, or
    /// `None` when empty. NEVER blocks `module_step`. For non-`DropOldest`
    /// policies the tail is consumer-exclusive and this is wait-free; under
    /// `DropOldest` it *try-locks* `xlock` around the copy + tail-advance so the
    /// producer's eviction cannot free-and-overwrite the bytes being copied — if
    /// the producer holds the lock (mid-eviction), this returns `None` and the
    /// frame is delivered on a later tick rather than spinning. A frame longer
    /// than `out` is truncated to `out.len()` (the remainder of that frame is
    /// discarded — size `out` for the bridge's max frame).
    pub fn pop_frame(&self, out: &mut [u8]) -> Option<usize> {
        // Only DropOldest lets the producer touch the tail; guard only then, and
        // never block — a failed try-lock means "no frame this tick".
        let guarded = self.policy == OverloadPolicy::DropOldest;
        if guarded && !self.try_lock() {
            return None;
        }
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if self.used(head, tail) == 0 {
            if guarded {
                self.unlock();
            }
            return None;
        }
        let flen = self.frame_len_at(tail);
        let copy = flen.min(out.len());
        self.read_bytes(tail.wrapping_add(HDR as u32), &mut out[..copy]);
        self.tail
            .store(tail.wrapping_add((HDR + flen) as u32), Ordering::Release);
        if guarded {
            self.unlock();
        }
        Some(copy)
    }
}
