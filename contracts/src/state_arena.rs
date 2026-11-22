//! The state arena's carve rule: what one allocation takes from the arena.
//!
//! Every allocation the kernel makes from the module state arena — a module's
//! state, a native module's state, a heap committed at instantiation, the
//! state of a gated module's private region — is the asked size, a trailing
//! canary word, rounded up to the arena's alignment. The loader carves by
//! [`carve_bytes`] (`alloc_state`), and the composer charges a graph by it
//! before the graph is built (`fluxor build`'s state-arena table): one
//! definition, linked by both.
//!
//! Three more figures the build charges by are stated here for the same
//! reason: the first segment an elastic heap commits when its module is
//! instantiated ([`first_heap_segment`]), the heap a native module seats for
//! its instance ([`heap_seat_bytes`]), and what an isolated module's
//! allocations take from the isolated-module arena ([`iso_carve_bytes`]).

/// Alignment of every carve, and of the arena's high-water mark.
pub const STATE_ALIGN: usize = 8;

/// The canary word written after every allocation's last byte: a module that
/// overruns its state clobbers it, and the free path reports it.
pub const STATE_CANARY_BYTES: usize = 4;

/// Bytes of arena one allocation of `n` bytes takes: `n` and its canary,
/// rounded up to [`STATE_ALIGN`]. `None` when that overflows, which no arena
/// can seat.
pub const fn carve_bytes(n: usize) -> Option<usize> {
    match n.checked_add(STATE_CANARY_BYTES + STATE_ALIGN - 1) {
        Some(m) => Some(m & !(STATE_ALIGN - 1)),
        None => None,
    }
}

/// Bytes of a heap block's header.
pub const HEAP_BLOCK_HEADER: usize = 8;

/// The smallest block a heap hands out, its header aside.
pub const HEAP_MIN_BLOCK: usize = 16;

/// The segment an elastic heap of `cap` bytes commits when its module is
/// instantiated, on a kernel whose heaps grow in up to `segments` segments of
/// at least `quantum` bytes: `cap >> (segments - 1)`, at least the quantum,
/// never past the cap, in whole 8-byte units; the whole cap where a heap has
/// one segment. 0 for a cap too small to hold one block (or past `u32`), which
/// gets no heap. The kernel commits exactly this (`heap::commit_first`), and
/// the build charges its carve; growth past it is the module's own
/// allocation, which no budget predicts.
pub const fn first_heap_segment(cap: usize, segments: usize, quantum: usize) -> usize {
    let cap = cap & !(HEAP_BLOCK_HEADER - 1);
    if cap < HEAP_BLOCK_HEADER + HEAP_MIN_BLOCK || cap > u32::MAX as usize {
        return 0;
    }
    if segments <= 1 {
        return cap;
    }
    let mut first = cap >> (segments - 1);
    if first < quantum {
        first = quantum;
    }
    if first > cap {
        first = cap;
    }
    first & !(HEAP_BLOCK_HEADER - 1)
}

/// Page granule of the isolated-module arena: every allocation there is its
/// size and canary rounded up to whole pages, so the page table maps it alone.
pub const ISO_PAGE: usize = 4096;

/// Bytes of the isolated-module arena one allocation of `n` bytes takes: `n`
/// and its canary, rounded up to [`ISO_PAGE`]. `None` when that overflows.
pub const fn iso_carve_bytes(n: usize) -> Option<usize> {
    match n.checked_add(STATE_CANARY_BYTES + ISO_PAGE - 1) {
        Some(m) => Some(m & !(ISO_PAGE - 1)),
        None => None,
    }
}

/// The bytes of module heap a heap native seats for an instance with
/// `params`, by its seat rule `seat` (its `HEAP_SEAT`, generated from its
/// manifest's `[capacities]`): `[base, per_pixel, width tag, height tag,
/// param tag, param default]`. The base, plus `per_pixel` × the `width` ×
/// `height` params (each read as a u16, 0 when absent), plus the value of the
/// param tag (a u32, its default when absent; no param when the tag is 0).
/// `None` when that overflows.
pub fn heap_seat_bytes(seat: &[u32; 6], params: &[u8]) -> Option<usize> {
    let [base, per_pixel, width_tag, height_tag, param_tag, param_default] = *seat;
    let (mut width, mut height, mut param) = (0u32, 0u32, param_default);
    crate::params_tlv::walk_declared(params, |tag, value| {
        let mut b = [0u8; 4];
        let n = value.len().min(4);
        b[..n].copy_from_slice(&value[..n]);
        let v = u32::from_le_bytes(b);
        let tag = u32::from(tag);
        if per_pixel != 0 && tag == width_tag {
            width = v & 0xFFFF;
        } else if per_pixel != 0 && tag == height_tag {
            height = v & 0xFFFF;
        } else if param_tag != 0 && tag == param_tag {
            param = v;
        }
    });
    let param = if param_tag != 0 { param as usize } else { 0 };
    (per_pixel as usize)
        .checked_mul(width as usize)?
        .checked_mul(height as usize)?
        .checked_add(base as usize)?
        .checked_add(param)
}
