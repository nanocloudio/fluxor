//! Interrupt-mode rings: the lock-free SPSC ring each edge with an
//! interrupt-mode end moves its records through.
//!
//! A module stepped from a timer or an IRQ cannot use a channel, so the edge
//! keeps its channel on the cooperative side and a ring on the other, and
//! `scheduler::pump_isr_bridges` moves records between the two every pass.
//! A ring is fixed-element, power-of-two deep and drops on full (an ISR
//! never blocks); every operation is allocation-free and safe from interrupt
//! context.
//!
//! The table is sized when a graph is prepared to the edges of its plan with
//! an interrupt-mode end ([`size`]), so a graph without one holds none. An
//! interrupt-context reader reads only what is committed and never sizes it.

use core::cell::UnsafeCell;

use portable_atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use crate::kernel::exec::scheduler::ModuleId;
use crate::kernel::mem::table::{Table, TableError};

/// Most rings one graph holds, from the profile.
pub const MAX_RINGS: usize = crate::kernel::config::MAX_BRIDGES;

/// Bytes of one ring element.
pub const MAX_ELEM: usize = 56;

/// Elements in one ring. A power of two.
const RING_CAPACITY: usize = 32;

/// Cache line size for alignment (Cortex-A76 / RP2350).
const CACHE_LINE: usize = 64;

/// One edge's ring.
#[repr(C, align(64))]
pub struct IsrRing {
    /// Producer write index (only written by the producer).
    head: AtomicU32,
    _pad_head: [u8; CACHE_LINE - 4],
    /// Consumer read index (only written by the consumer).
    tail: AtomicU32,
    _pad_tail: [u8; CACHE_LINE - 4],
    /// Element size in bytes, set when the ring is wired.
    elem_size: AtomicU32,
    /// Elements dropped on a full ring.
    drop_count: AtomicU32,
    /// The edge's producer and consumer, for `INFO`.
    from: AtomicU16,
    to: AtomicU16,
    /// Wired to an edge of the current graph.
    in_use: AtomicBool,
    _pad_meta: [u8; CACHE_LINE - 13],
    /// Element `i` at `data[i * elem_size]`.
    data: UnsafeCell<[u8; RING_CAPACITY * MAX_ELEM]>,
}

// SAFETY: one producer and one consumer per ring, each publishing through
// `head`/`tail` with release stores read by acquire loads; an element's
// bytes are written before the index that exposes them and read before the
// index that frees them.
unsafe impl Sync for IsrRing {}

impl IsrRing {
    pub const fn new() -> Self {
        Self {
            head: AtomicU32::new(0),
            _pad_head: [0; CACHE_LINE - 4],
            tail: AtomicU32::new(0),
            _pad_tail: [0; CACHE_LINE - 4],
            elem_size: AtomicU32::new(0),
            drop_count: AtomicU32::new(0),
            from: AtomicU16::new(0),
            to: AtomicU16::new(0),
            in_use: AtomicBool::new(false),
            _pad_meta: [0; CACHE_LINE - 13],
            data: UnsafeCell::new([0; RING_CAPACITY * MAX_ELEM]),
        }
    }

    /// Wire the ring to the edge `from → to`, empty, with `elem_size`-byte
    /// elements.
    fn wire(&self, elem_size: usize, from: ModuleId, to: ModuleId) {
        self.elem_size
            .store(elem_size.min(MAX_ELEM) as u32, Ordering::Relaxed);
        self.from.store(from, Ordering::Relaxed);
        self.to.store(to, Ordering::Relaxed);
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        self.drop_count.store(0, Ordering::Release);
    }

    /// The edge's producer.
    pub fn from_module(&self) -> ModuleId {
        self.from.load(Ordering::Relaxed)
    }

    /// The edge's consumer.
    pub fn to_module(&self) -> ModuleId {
        self.to.load(Ordering::Relaxed)
    }

    fn base(&self) -> *mut u8 {
        self.data.get().cast()
    }

    /// Push one element (producer side, ISR-safe). `false` when the ring is
    /// full and the element was dropped.
    pub fn push(&self, src: &[u8]) -> bool {
        let sz = self.elem_size.load(Ordering::Relaxed) as usize;
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= RING_CAPACITY as u32 {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let offset = ((head as usize) & (RING_CAPACITY - 1)) * sz;
        let len = src.len().min(sz);
        let dst = self.base();
        // SAFETY: `offset + sz <= RING_CAPACITY * MAX_ELEM` (`idx <
        // RING_CAPACITY`, `sz <= MAX_ELEM`); the element at `head` is the
        // producer's alone until `head` is published below.
        unsafe {
            for (i, &b) in src.iter().take(len).enumerate() {
                core::ptr::write_volatile(dst.add(offset + i), b);
            }
            for i in len..sz {
                core::ptr::write_volatile(dst.add(offset + i), 0);
            }
        }
        self.head.store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Copy the oldest element into `dst` without taking it: the byte count,
    /// 0 when the ring is empty. [`IsrRing::pop`] takes it.
    pub fn peek_one(&self, dst: &mut [u8]) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return 0;
        }
        let sz = self.elem_size.load(Ordering::Relaxed) as usize;
        let offset = ((tail as usize) & (RING_CAPACITY - 1)) * sz;
        let len = dst.len().min(sz);
        let src = self.base();
        // SAFETY: as `push`; the element at `tail` is the consumer's until
        // `tail` advances.
        unsafe {
            for (i, slot) in dst.iter_mut().take(len).enumerate() {
                *slot = core::ptr::read_volatile(src.add(offset + i));
            }
        }
        len
    }

    /// Take the oldest element into `dst` (consumer side, ISR-safe): the
    /// byte count, 0 when the ring is empty.
    pub fn pop(&self, dst: &mut [u8]) -> usize {
        let n = self.peek_one(dst);
        if n > 0 {
            let tail = self.tail.load(Ordering::Acquire);
            self.tail.store(tail.wrapping_add(1), Ordering::Release);
        }
        n
    }

    /// Elements queued.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) as usize
    }

    /// No element queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// No free element: a producer that must not lose what it would push
    /// checks before taking it from its source.
    pub fn is_full(&self) -> bool {
        self.len() >= RING_CAPACITY
    }

    /// Elements dropped on a full ring.
    pub fn drops(&self) -> u32 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

impl Default for IsrRing {
    fn default() -> Self {
        Self::new()
    }
}

static RINGS: Table<IsrRing, MAX_RINGS> = crate::boot_table!(MAX_RINGS, IsrRing::new());

/// Size the table to `n` rings, all free: the edges of the graph being
/// prepared with an interrupt-mode end.
///
/// # Safety
/// Graph preparation: no reference into the table is live and no
/// interrupt-mode module runs.
pub unsafe fn size(n: usize) -> Result<(), TableError> {
    // SAFETY: the caller's contract.
    unsafe { RINGS.reserve(n)? };
    RINGS.grow(n)?;
    reset_all();
    Ok(())
}

/// Free every ring: a graph's rings go with it.
pub fn reset_all() {
    for ring in RINGS.committed() {
        ring.in_use.store(false, Ordering::Release);
    }
}

/// Wire a free ring to the edge `from → to`: its index, or `None` when
/// every ring the plan sized is taken.
pub fn alloc(elem_size: usize, from: ModuleId, to: ModuleId) -> Option<usize> {
    let rings = RINGS.committed();
    let i = rings
        .iter()
        .position(|r| !r.in_use.load(Ordering::Acquire))?;
    rings[i].wire(elem_size, from, to);
    rings[i].in_use.store(true, Ordering::Release);
    Some(i)
}

/// The ring at `idx`, when it is wired. Safe from interrupt context.
pub fn get(idx: usize) -> Option<&'static IsrRing> {
    let ring = RINGS.committed().get(idx)?;
    ring.in_use.load(Ordering::Acquire).then_some(ring)
}

/// A module's call on the ring at `slot` (`abi::internal::bridge`): `WRITE`
/// pushes `data`, `READ` pops into it, `POLL` answers 1 while an element is
/// queued, `INFO` writes the ring's description into `arg`.
pub fn dispatch(
    slot: usize,
    opcode: u32,
    arg: &mut [u8],
    mut data: crate::kernel::module::user_span::UserSpan<'_>,
) -> i32 {
    use crate::abi::internal::bridge;
    use crate::kernel::sys::errno;
    let Some(ring) = get(slot) else {
        return errno::EINVAL;
    };
    match opcode {
        bridge::WRITE => {
            if data.is_empty() {
                return errno::EINVAL;
            }
            if ring.push(data.as_slice()) {
                0
            } else {
                errno::EAGAIN
            }
        }
        bridge::READ => {
            if data.is_empty() {
                return errno::EINVAL;
            }
            match ring.pop(data.as_mut()) {
                0 => errno::EAGAIN,
                n => n as i32,
            }
        }
        bridge::POLL => i32::from(!ring.is_empty()),
        bridge::INFO => {
            let Some(out) = arg.get_mut(..bridge::INFO_LEN) else {
                return errno::EINVAL;
            };
            out.fill(0);
            out[2..4].copy_from_slice(&ring.from_module().to_le_bytes());
            out[4..6].copy_from_slice(&ring.to_module().to_le_bytes());
            out[8..12].copy_from_slice(&ring.drops().to_le_bytes());
            bridge::INFO_LEN as i32
        }
        _ => errno::ENOSYS,
    }
}
