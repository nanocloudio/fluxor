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
