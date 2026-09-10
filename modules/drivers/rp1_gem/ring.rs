//! Descriptor-ring index arithmetic.
//!
//! The RX and TX rings are walked with free-running `u16` positions and a
//! `position % count` index. A free-running counter wraps at 65,536, and
//! 65,536 is a multiple of the ring size only when the size is a power of
//! two: for any other size the index jumps at the wrap, the driver and the
//! MAC part company on which descriptor is next, and reception halts with
//! every descriptor handed back and the MAC still reporting no buffer
//! available. The positions therefore wrap at the largest multiple of the
//! ring size a `u16` holds, so the index is continuous for every size.

/// The modulus a free-running position wraps at for a ring of `count`.
#[inline(always)]
pub const fn span(count: u16) -> u32 {
    if count == 0 {
        return 1;
    }
    (65_536 / count as u32) * count as u32
}

/// The position after `pos` on a ring of `count`.
#[inline(always)]
pub const fn next(pos: u16, count: u16) -> u16 {
    ((pos as u32 + 1) % span(count)) as u16
}

/// The descriptor index a position names.
#[inline(always)]
pub const fn index(pos: u16, count: u16) -> usize {
    if count == 0 {
        return 0;
    }
    (pos % count) as usize
}

/// Positions between `tail` and `head` (the entries in use), both
/// free-running on the same ring.
#[inline(always)]
pub const fn used(head: u16, tail: u16, count: u16) -> u16 {
    let m = span(count);
    ((head as u32 + m - tail as u32) % m) as u16
}
