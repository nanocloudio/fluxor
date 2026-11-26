//! One direction of one lane channel: a single-producer single-consumer ring
//! in a sealed `memfd` both processes map.
//!
//! ```text
//! [0..4)   "FXLN"
//! [4..8)   capacity: u32 LE   — bytes of data area, a multiple of 4
//! [8..12)  max_record: u32 LE — the channel's largest record
//! [16..24) producer index: u64, atomic (bytes ever committed)
//! [24..32) consumer index: u64, atomic (bytes ever released)
//! [32..36) waiting: u32, atomic — the consumer is asleep on the doorbell
//! [64..)   data area
//! ```
//!
//! A record is `[len:u32 LE][bytes]` padded to 4 and never split: when it
//! would straddle the end of the data area, a pad marker (`len =
//! u32::MAX`) fills the rest and the record starts at 0. A record that
//! does not fit whole is refused whole; the overload policy above the ring
//! decides whether to drop it or hold it. The capacity is at least
//! `2 · (max_record + 4)`, so a record always fits once the ring drains.
//!
//! Commit is the `Release` store of the producer index alone: a producer
//! that dies mid-write leaves nothing visible. Each side keeps private
//! copies of the capacity, the maximum and its own index, and treats the
//! mapping as hostile: the peer's index must be monotonic and within
//! capacity, a record's length is read once, and its bytes are copied out
//! before anything parses them.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

/// The header's leading bytes.
pub const MAGIC: [u8; 4] = *b"FXLN";
/// Bytes before the data area.
pub const HEADER: usize = 64;
/// The length of a pad marker.
pub const PAD: u32 = u32::MAX;

/// Where each header field sits.
pub const OFF_CAP: usize = 4;
pub const OFF_MAX: usize = 8;
pub const OFF_PROD: usize = 16;
pub const OFF_CONS: usize = 24;
pub const OFF_WAIT: usize = 32;

/// The seals a ring's `memfd` carries before the peer sees it: its size is
/// fixed and the seals themselves are.
const SEALS: libc::c_int = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;

/// What a record of `len` bytes takes of the ring: its length word and its
/// bytes, padded to 4.
pub const fn footprint(len: usize) -> usize {
    4 + ((len + 3) & !3)
}

/// The data area a channel of `max_record` gets: room for two records at
/// the maximum, so one always fits once the ring has drained.
pub const fn capacity_for(max_record: u32) -> usize {
    let two = 2 * footprint(max_record as usize);
    if two < 256 {
        256
    } else {
        two
    }
}

/// Why a ring could not be made or attached, or what the peer did to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    /// The system refused the `memfd`, its seals or the mapping (errno).
    Os(i32),
    /// The descriptor is not a ring this side can trust: unsealed, the
    /// wrong size, the wrong magic, or a header that disagrees with the
    /// channel it was offered for.
    Shape,
    /// The peer moved an index backwards, past capacity, or wrote a record
    /// the header does not admit.
    Hostile,
}

/// A shared mapping of one ring, unmapped on drop.
struct Mapping {
    base: *mut u8,
    len: usize,
}

// SAFETY: the mapping is plain shared memory; every access through it is
// either an atomic or a copy, and each side holds its half on one thread at
// a time.
unsafe impl Send for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are the mapping `mmap` returned, unmapped once.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

impl Mapping {
    fn map(fd: &OwnedFd, len: usize) -> Result<Mapping, RingError> {
        // SAFETY: a fresh shared mapping of an fd we hold, of the length its
        // size was checked or set to; MAP_FAILED is checked below.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(RingError::Os(errno()));
        }
        Ok(Mapping {
            base: p.cast(),
            len,
        })
    }

    fn u64_at(&self, off: usize) -> &AtomicU64 {
        // SAFETY: `off` is 8-aligned inside the page-aligned header, which
        // lives as long as `self`.
        unsafe { &*self.base.add(off).cast::<AtomicU64>() }
    }

    fn u32_at(&self, off: usize) -> &AtomicU32 {
        // SAFETY: as `u64_at`, 4-aligned.
        unsafe { &*self.base.add(off).cast::<AtomicU32>() }
    }

    fn data(&self) -> *mut u8 {
        // SAFETY: the data area starts at HEADER inside the mapping.
        unsafe { self.base.add(HEADER) }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Make a ring for a channel of `max_record`: a sealed `memfd` holding the
/// header and the data area, and its mapping. Returns the descriptor to
/// hand the peer and the producer or consumer half this side keeps.
fn create(max_record: u32) -> Result<(OwnedFd, Mapping, u64), RingError> {
    let cap = capacity_for(max_record);
    let len = HEADER + cap;
    // SAFETY: a static NUL-terminated name and flags; the result is checked.
    let raw = unsafe {
        libc::memfd_create(
            c"fluxor-lane".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(RingError::Os(errno()));
    }
    // SAFETY: `raw` is a descriptor memfd_create just returned to us.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: integer arguments on a descriptor we own.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
        return Err(RingError::Os(errno()));
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0 {
        return Err(RingError::Os(errno()));
    }
    let map = Mapping::map(&fd, len)?;
    // SAFETY: the header's first bytes, inside the fresh mapping.
    unsafe {
        core::ptr::copy_nonoverlapping(MAGIC.as_ptr(), map.base, 4);
    }
    map.u32_at(OFF_CAP).store(cap as u32, Ordering::Relaxed);
    map.u32_at(OFF_MAX).store(max_record, Ordering::Relaxed);
    map.u64_at(OFF_PROD).store(0, Ordering::Relaxed);
    map.u64_at(OFF_CONS).store(0, Ordering::Relaxed);
    map.u32_at(OFF_WAIT).store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    Ok((fd, map, cap as u64))
}

/// Map a ring the peer made for a channel of `max_record`, refusing one
/// that is not sealed, not the size its header states, or whose header
/// disagrees with the channel.
fn attach(fd: &OwnedFd, max_record: u32) -> Result<(Mapping, u64), RingError> {
    // SAFETY: integer arguments on a descriptor we hold.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & SEALS != SEALS {
        return Err(RingError::Shape);
    }
    // SAFETY: `st` is a writable stat for the call.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(RingError::Os(errno()));
    }
    let size = st.st_size as usize;
    let cap = capacity_for(max_record);
    if size != HEADER + cap {
        return Err(RingError::Shape);
    }
    let map = Mapping::map(fd, size)?;
    let mut magic = [0u8; 4];
    // SAFETY: the header's first bytes, inside the mapping.
    unsafe { core::ptr::copy_nonoverlapping(map.base, magic.as_mut_ptr(), 4) };
    let hdr_cap = map.u32_at(OFF_CAP).load(Ordering::Acquire) as usize;
    let hdr_max = map.u32_at(OFF_MAX).load(Ordering::Acquire);
    if magic != MAGIC || hdr_cap != cap || hdr_max != max_record {
        return Err(RingError::Shape);
    }
    Ok((map, cap as u64))
}

/// The producing half of a ring.
pub struct Producer {
    map: Mapping,
    cap: u64,
    max: u32,
    head: u64,
    seen_tail: u64,
}

/// Why a record was not committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// No room for it whole now.
    Full,
    /// Longer than the channel's maximum: it never fits.
    TooBig,
    /// The consumer's index is not one a consumer could have written.
    Hostile,
}

impl Producer {
    /// Make a ring for a channel of `max_record` this side produces into;
    /// the descriptor goes to the consumer.
    pub fn create(max_record: u32) -> Result<(Producer, OwnedFd), RingError> {
        let (fd, map, cap) = create(max_record)?;
        Ok((Producer::over(map, cap, max_record), fd))
    }

    /// Produce into a ring the consumer made.
    pub fn attach(fd: &OwnedFd, max_record: u32) -> Result<Producer, RingError> {
        let (map, cap) = attach(fd, max_record)?;
        let p = Producer::over(map, cap, max_record);
        let tail = p.map.u64_at(OFF_CONS).load(Ordering::Acquire);
        let head = p.map.u64_at(OFF_PROD).load(Ordering::Acquire);
        if head != 0 || tail != 0 {
            return Err(RingError::Shape);
        }
        Ok(p)
    }

    fn over(map: Mapping, cap: u64, max: u32) -> Producer {
        Producer {
            map,
            cap,
            max,
            head: 0,
            seen_tail: 0,
        }
    }

    /// The channel's largest record.
    pub fn max_record(&self) -> u32 {
        self.max
    }

    /// Commit `rec` whole, or refuse it whole.
    pub fn push(&mut self, rec: &[u8]) -> Result<(), Push> {
        if rec.len() > self.max as usize {
            return Err(Push::TooBig);
        }
        let tail = self.map.u64_at(OFF_CONS).load(Ordering::Acquire);
        if tail < self.seen_tail || tail > self.head {
            return Err(Push::Hostile);
        }
        self.seen_tail = tail;
        let need = footprint(rec.len()) as u64;
        let pos = self.head % self.cap;
        let to_end = self.cap - pos;
        let pad = if to_end < need { to_end } else { 0 };
        if self.head - tail + pad + need > self.cap {
            return Err(Push::Full);
        }
        let data = self.map.data();
        let mut at = pos as usize;
        if pad > 0 {
            // SAFETY: `at + 4 <= cap`: positions and the capacity are
            // multiples of 4 and `to_end > 0`.
            unsafe { core::ptr::write_volatile(data.add(at).cast::<u32>(), PAD.to_le()) };
            at = 0;
        }
        // SAFETY: `at + need <= cap`, checked above; the bytes between the
        // consumer's index and ours are this side's to write.
        unsafe {
            core::ptr::write_volatile(data.add(at).cast::<u32>(), (rec.len() as u32).to_le());
            core::ptr::copy_nonoverlapping(rec.as_ptr(), data.add(at + 4), rec.len());
        }
        self.head += pad + need;
        self.map
            .u64_at(OFF_PROD)
            .store(self.head, Ordering::Release);
        Ok(())
    }

    /// Whether the consumer is asleep on the doorbell, clearing the flag:
    /// the producer rings once per sleep, however many records it commits.
    pub fn take_waiting(&self) -> bool {
        fence(Ordering::SeqCst);
        self.map.u32_at(OFF_WAIT).swap(0, Ordering::SeqCst) != 0
    }

    /// Whether everything committed has been released by the consumer.
    pub fn drained(&self) -> bool {
        self.map.u64_at(OFF_CONS).load(Ordering::Acquire) == self.head
    }

    /// What this ring can take now, to plan commits against before making
    /// them. The consumer only frees room, so every record the view says
    /// fits, committed in the same order, is taken. A hostile consumer
    /// index reads as a full ring (the commit then says why).
    pub fn view(&self) -> View {
        let tail = self.map.u64_at(OFF_CONS).load(Ordering::Acquire);
        let tail = if tail < self.seen_tail || tail > self.head {
            self.head.saturating_sub(self.cap)
        } else {
            tail
        };
        View {
            cap: self.cap,
            max: self.max,
            head: self.head,
            tail,
        }
    }
}

/// A producer's plan of commits ([`Producer::view`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    cap: u64,
    max: u32,
    head: u64,
    tail: u64,
}

impl View {
    /// A view of a ring that takes nothing.
    pub const NONE: View = View {
        cap: 0,
        max: 0,
        head: 0,
        tail: 0,
    };

    /// Whether a record of `len` bytes fits after what was planned; when it
    /// does it is planned, as [`Producer::push`] would place it.
    pub fn fits(&mut self, len: usize) -> bool {
        if self.cap == 0 || len > self.max as usize {
            return false;
        }
        let need = footprint(len) as u64;
        let pos = self.head % self.cap;
        let to_end = self.cap - pos;
        let pad = if to_end < need { to_end } else { 0 };
        if self.head - self.tail + pad + need > self.cap {
            return false;
        }
        self.head += pad + need;
        true
    }

    /// Bytes of records of up to `frame` bytes each that fit after what was
    /// planned, counting each record's length word and padding and one
    /// wrap: a lower bound, never more than [`View::fits`] takes.
    pub fn room(&self, frame: usize) -> usize {
        if self.cap == 0 {
            return 0;
        }
        let free = self.cap - (self.head - self.tail);
        free.saturating_sub(footprint(frame) as u64) as usize
    }
}

/// The consuming half of a ring.
pub struct Consumer {
    map: Mapping,
    cap: u64,
    max: u32,
    tail: u64,
    seen_head: u64,
}

/// Why a record was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop {
    /// The caller's buffer is shorter than the channel's maximum.
    Short,
    /// The producer's index or a record's length is not one a producer
    /// could have written.
    Hostile,
}

impl Consumer {
    /// Make a ring for a channel of `max_record` this side consumes from;
    /// the descriptor goes to the producer.
    pub fn create(max_record: u32) -> Result<(Consumer, OwnedFd), RingError> {
        let (fd, map, cap) = create(max_record)?;
        Ok((Consumer::over(map, cap, max_record), fd))
    }

    /// Consume from a ring the producer made.
    pub fn attach(fd: &OwnedFd, max_record: u32) -> Result<Consumer, RingError> {
        let (map, cap) = attach(fd, max_record)?;
        let c = Consumer::over(map, cap, max_record);
        // The producer may already have committed records (it made the
        // ring and may write as soon as it is handed over); nothing can
        // have released any.
        if c.map.u64_at(OFF_CONS).load(Ordering::Acquire) != 0 {
            return Err(RingError::Shape);
        }
        Ok(c)
    }

    fn over(map: Mapping, cap: u64, max: u32) -> Consumer {
        Consumer {
            map,
            cap,
            max,
            tail: 0,
            seen_head: 0,
        }
    }

    /// The channel's largest record.
    pub fn max_record(&self) -> u32 {
        self.max
    }

    fn head(&mut self) -> Result<u64, Pop> {
        let head = self.map.u64_at(OFF_PROD).load(Ordering::Acquire);
        if head < self.seen_head || head < self.tail || head - self.tail > self.cap {
            return Err(Pop::Hostile);
        }
        self.seen_head = head;
        Ok(head)
    }

    /// Whether a record is waiting.
    pub fn ready(&mut self) -> Result<bool, Pop> {
        Ok(self.head()? != self.tail)
    }

    /// Take the next record into `out` (at least the channel's maximum
    /// long): its length, or `None` when the ring is empty.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<Option<usize>, Pop> {
        if out.len() < self.max as usize {
            return Err(Pop::Short);
        }
        let head = self.head()?;
        let data = self.map.data();
        loop {
            if self.tail == head {
                return Ok(None);
            }
            let pos = self.tail % self.cap;
            let to_end = self.cap - pos;
            let avail = head - self.tail;
            if avail < 4 {
                return Err(Pop::Hostile);
            }
            // SAFETY: `pos + 4 <= cap` (positions are multiples of 4 below
            // the capacity); read once, as a value.
            let len = u32::from_le(unsafe {
                core::ptr::read_volatile(data.add(pos as usize).cast::<u32>())
            });
            if len == PAD {
                if to_end > avail {
                    return Err(Pop::Hostile);
                }
                self.tail += to_end;
                continue;
            }
            if len > self.max {
                return Err(Pop::Hostile);
            }
            let need = footprint(len as usize) as u64;
            if need > to_end || need > avail {
                return Err(Pop::Hostile);
            }
            let n = len as usize;
            // SAFETY: `pos + 4 + n <= cap` (checked: `need <= to_end`) and
            // `n <= max <= out.len()`.
            unsafe {
                core::ptr::copy_nonoverlapping(data.add(pos as usize + 4), out.as_mut_ptr(), n);
            }
            self.tail += need;
            self.map
                .u64_at(OFF_CONS)
                .store(self.tail, Ordering::Release);
            return Ok(Some(n));
        }
    }

    /// Mark this side asleep on the doorbell. The caller looks at the ring
    /// once more after this and before it sleeps.
    pub fn set_waiting(&self) {
        self.map.u32_at(OFF_WAIT).store(1, Ordering::SeqCst);
        fence(Ordering::SeqCst);
    }

    /// Mark this side awake.
    pub fn clear_waiting(&self) {
        self.map.u32_at(OFF_WAIT).store(0, Ordering::SeqCst);
    }
}
