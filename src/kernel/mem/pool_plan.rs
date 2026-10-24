//! The arithmetic of a carve zone's split: pure, so a host test can plan
//! graphs against an RP profile's pool with the very functions the kernel
//! runs.
//!
//! A zone is `[lo, hi)`. Kernel tables are carved off its top, one way and
//! downwards ([`carve_down`]); what they leave below the carve floor is the
//! arenas'. On RP the zone is the one static pool in `.bss`, and once the
//! graph's tables are carved [`place_arenas`] takes the channel buffer arena
//! off the top of what is left and gives the module state arena the rest. On
//! bcm2712 the zone is the device tree's DRAM and only the tables are carved
//! (the state arena is the remainder, its buffer arena a fixed `.bss` one).
//! A table that moves to a larger block there hands its old one back, and
//! [`FreeExtents`] keeps those blocks, coalesced, for the carves that follow.
//!
//! No statics, no `crate` paths: the kernel's carve allocator
//! (`kernel::mem::carve`) holds the zone's state under its lock and calls in
//! here for the numbers.

/// The new carve floor for `bytes` at `align` below `floor`, in a zone whose
/// bottom is `lo`. `None` when the zone cannot hold it. `align` is a power of
/// two; the floor is rounded down to it.
pub const fn carve_down(floor: usize, lo: usize, bytes: usize, align: usize) -> Option<usize> {
    let align = if align < 16 { 16 } else { align };
    let Some(top) = floor.checked_sub(bytes) else {
        return None;
    };
    let new = top & !(align - 1);
    if new < lo {
        None
    } else {
        Some(new)
    }
}

/// Which arena a split could not place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
    /// The channel buffer arena's size is past what the tables left.
    BufferArena,
    /// The state arena the envelope asks for is past what the tables and the
    /// buffer arena left.
    StateArena,
}

/// Why a split was refused: the arena, what it asked and the room it had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub over: Over,
    pub asked: usize,
    pub room: usize,
}

/// Where the arenas landed: the buffer arena at `[buffer_at, buffer_at +
/// buffer)`, the state arena at `[state_at, state_at + state)`, and the new
/// carve floor (the buffer arena's base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaSplit {
    pub buffer_at: usize,
    pub buffer: usize,
    pub state_at: usize,
    pub state: usize,
    pub floor: usize,
}

/// Place the arenas in what the tables left of `[lo, floor)`: `buffer` bytes
/// of channel buffer arena carved at `buffer_align` off the top, and the rest
/// the module state arena. `state_asked` is the deployment's state-arena
/// entry, when its envelope carries one: a remainder short of it is refused,
/// naming the state arena, rather than booting a graph whose modules the
/// arena cannot seat. Without an entry the state arena is whatever is left,
/// which may be none.
pub const fn place_arenas(
    lo: usize,
    floor: usize,
    buffer: usize,
    buffer_align: usize,
    state_asked: Option<usize>,
) -> Result<ArenaSplit, Refusal> {
    let room = floor.saturating_sub(lo);
    let Some(buffer_at) = carve_down(floor, lo, buffer, buffer_align) else {
        return Err(Refusal {
            over: Over::BufferArena,
            asked: buffer,
            room,
        });
    };
    let state = buffer_at - lo;
    if let Some(asked) = state_asked {
        if asked > state {
            return Err(Refusal {
                over: Over::StateArena,
                asked,
                room: state,
            });
        }
    }
    Ok(ArenaSplit {
        buffer_at,
        buffer,
        state_at: lo,
        state,
        floor: buffer_at,
    })
}

/// Carved blocks handed back for reuse: up to `N` disjoint extents `[lo, hi)`
/// of the zone, sorted by address and coalesced as they arrive. The tables
/// one plan sized were carved one below another, so the blocks a larger plan
/// leaves behind merge back into a few extents, and a later carve takes from
/// them before it lowers the floor.
///
/// Bytes the list cannot hold — a block that coalesces with nothing while
/// every extent is in use and is smaller than all of them, or the sliver an
/// aligned take leaves above itself with no extent free for it — are counted
/// in [`dropped`](Self::dropped) and not reused.
pub struct FreeExtents<const N: usize> {
    lo: [usize; N],
    hi: [usize; N],
    len: usize,
    dropped: usize,
}

impl<const N: usize> FreeExtents<N> {
    /// An empty list.
    pub const fn new() -> Self {
        Self {
            lo: [0; N],
            hi: [0; N],
            len: 0,
            dropped: 0,
        }
    }

    /// Extents held.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no extent is held.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Extent `i` as `(lo, hi)`, in address order.
    pub const fn get(&self, i: usize) -> Option<(usize, usize)> {
        if i < self.len {
            Some((self.lo[i], self.hi[i]))
        } else {
            None
        }
    }

    /// Bytes held for reuse.
    pub fn bytes(&self) -> usize {
        (0..self.len).map(|i| self.hi[i] - self.lo[i]).sum()
    }

    /// Bytes given back that the list could not hold.
    pub const fn dropped(&self) -> usize {
        self.dropped
    }

    /// Forget every extent: the zone they lay in is planned afresh.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    fn remove(&mut self, i: usize) {
        let mut k = i;
        while k + 1 < self.len {
            self.lo[k] = self.lo[k + 1];
            self.hi[k] = self.hi[k + 1];
            k += 1;
        }
        self.len -= 1;
    }

    fn insert(&mut self, i: usize, lo: usize, hi: usize) {
        let mut k = self.len;
        while k > i {
            self.lo[k] = self.lo[k - 1];
            self.hi[k] = self.hi[k - 1];
            k -= 1;
        }
        self.lo[i] = lo;
        self.hi[i] = hi;
        self.len += 1;
    }

    /// Hand back `[at, at + bytes)`, a block no extent overlaps. It joins the
    /// extent that ends where it starts and the one that starts where it
    /// ends. One that joins neither while the list is full replaces the
    /// smallest extent when it is larger, and is dropped otherwise.
    pub fn give(&mut self, at: usize, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let end = at.saturating_add(bytes);
        let mut i = 0;
        while i < self.len && self.lo[i] < at {
            i += 1;
        }
        let joins_prev = i > 0 && self.hi[i - 1] == at;
        let joins_next = i < self.len && self.lo[i] == end;
        match (joins_prev, joins_next) {
            (true, true) => {
                self.hi[i - 1] = self.hi[i];
                self.remove(i);
            }
            (true, false) => self.hi[i - 1] = end,
            (false, true) => self.lo[i] = at,
            (false, false) => {
                if self.len < N {
                    self.insert(i, at, end);
                    return;
                }
                if self.len == 0 {
                    self.dropped += bytes;
                    return;
                }
                let mut smallest = 0;
                for k in 1..self.len {
                    if self.hi[k] - self.lo[k] < self.hi[smallest] - self.lo[smallest] {
                        smallest = k;
                    }
                }
                let small = self.hi[smallest] - self.lo[smallest];
                if small >= bytes {
                    self.dropped += bytes;
                    return;
                }
                self.dropped += small;
                self.remove(smallest);
                let mut i = 0;
                while i < self.len && self.lo[i] < at {
                    i += 1;
                }
                self.insert(i, at, end);
            }
        }
    }

    /// Take `bytes` at `align` (a power of two, at least 16, as
    /// [`carve_down`] rounds it) off the top of the smallest extent that
    /// holds them, so a large extent is kept whole for a large ask. `None`
    /// when no extent does.
    pub fn take(&mut self, bytes: usize, align: usize) -> Option<usize> {
        if bytes == 0 {
            return None;
        }
        let mut best: Option<(usize, usize)> = None;
        for i in 0..self.len {
            if let Some(at) = carve_down(self.hi[i], self.lo[i], bytes, align) {
                let size = self.hi[i] - self.lo[i];
                if best.is_none_or(|(b, _)| size < self.hi[b] - self.lo[b]) {
                    best = Some((i, at));
                }
            }
        }
        let (i, at) = best?;
        let (lo, hi) = (self.lo[i], self.hi[i]);
        let end = at + bytes;
        // What stays: the part below the block, and the sliver alignment
        // left above it.
        match (lo < at, end < hi) {
            (true, true) => {
                self.hi[i] = at;
                if self.len < N {
                    self.insert(i + 1, end, hi);
                } else {
                    self.dropped += hi - end;
                }
            }
            (true, false) => self.hi[i] = at,
            (false, true) => self.lo[i] = end,
            (false, false) => self.remove(i),
        }
        Some(at)
    }
}

impl<const N: usize> Default for FreeExtents<N> {
    fn default() -> Self {
        Self::new()
    }
}
