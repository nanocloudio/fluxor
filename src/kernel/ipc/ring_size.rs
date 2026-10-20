//! The channel ring sizing rule: what one edge asks for, the ring it is
//! granted, what that ring takes from the buffer arena, and the mailbox
//! groups that let edges share one ring.
//!
//! The scheduler opens every ring by these definitions (`open_channels`),
//! `channel_open` bounds every ring by them, and the composer sums a graph's
//! rings by them before the graph is built (`tools/src/ring_plan.rs`, which
//! mounts this file by `#[path]`): one definition, compiled into both.
//! Self-contained, so it mounts anywhere: it names nothing outside itself.
//! Kernel and tool code only — no module compiles against it, so it is not
//! part of the module ABI.

/// The smallest ring a channel is granted.
pub const MIN_RING_BYTES: u32 = 64;

/// The largest ring one channel may ask for. A request above it is refused,
/// never clamped: a producer told it has headroom it does not would find out
/// as a wedge under load.
pub const MAX_RING_BYTES: u32 = 4 * 1024 * 1024;

/// The ring an edge gets when neither port nor the graph sizes it: the
/// module ABI's `CHANNEL_BUFFER_SIZE`, which `buffer_pool` asserts equal.
pub const DEFAULT_RING_BYTES: u32 = 8192;

/// Alignment of every ring in the buffer arena: one cache line. The arena
/// allocator rounds each allocation up to it.
pub const RING_ALIGN: u32 = 64;

/// The first `buffer_group` fan insertion gives an edge of its own. Groups
/// below it are the config's: in-place chains numbered up from 1 and framed
/// edges numbered down from 31, all inside the edge record's 5-bit field. A
/// group minted for an edge around a record fan is above every one of them,
/// so it never aliases an edge the graph grouped.
pub const RECORD_FAN_GROUP_FIRST: u8 = 32;

/// The `buffer_group` values a kernel with `max_edges` graph edges spans:
/// the whole byte on a profile whose graph holds more than 128 edges, half
/// of it elsewhere. Groups at or above [`RECORD_FAN_GROUP_FIRST`] are the
/// ones record fans take, one per edge around the fan, so this bounds how
/// many such edges a graph holds.
pub const fn buffer_groups(max_edges: usize) -> usize {
    if max_edges > 128 {
        256
    } else {
        128
    }
}

/// What an edge asks for: the largest of the producer port's capacity, the
/// consumer port's and the graph's `buffer_bytes`. A port capacity is a
/// per-type minimum, `buffer_bytes` a per-edge one, so the larger wins. 0
/// means nothing sized the edge.
pub const fn edge_request(producer_port: u32, consumer_port: u32, buffer_bytes: u32) -> u32 {
    let a = if producer_port > consumer_port {
        producer_port
    } else {
        consumer_port
    };
    if a > buffer_bytes {
        a
    } else {
        buffer_bytes
    }
}

/// The ring a sized request is granted: raised to [`MIN_RING_BYTES`] and
/// rounded up to a power of two. `None` above [`MAX_RING_BYTES`]. A request
/// of 0 is unsized; [`ring_for`] gives it the default.
pub const fn sized_ring(request: u32) -> Option<u32> {
    if request > MAX_RING_BYTES {
        return None;
    }
    let r = if request < MIN_RING_BYTES {
        MIN_RING_BYTES
    } else {
        request
    };
    Some(r.next_power_of_two())
}

/// The ring an edge's request is granted, unsized included. `None` above
/// [`MAX_RING_BYTES`].
pub const fn ring_for(request: u32) -> Option<u32> {
    if request == 0 {
        Some(DEFAULT_RING_BYTES)
    } else {
        sized_ring(request)
    }
}

/// Bytes a ring of `ring` bytes takes from the buffer arena.
pub const fn arena_bytes(ring: u32) -> u64 {
    (ring as u64 + RING_ALIGN as u64 - 1) & !(RING_ALIGN as u64 - 1)
}
