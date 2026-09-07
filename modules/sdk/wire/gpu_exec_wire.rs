// GPU backend hand-off encoding — validated work, in table slots.
//
// The contract (`gpu_wire.rs`) is what a producer speaks. This is what a
// provider hands its backend once admission has already proved every handle,
// range, alignment, usage and right: the same work with the handles resolved
// to slot numbers and nothing left to check.
//
// It exists because one backend lives behind a foreign-function boundary. The
// native provider passes an owned Rust enum across a thread; the browser
// backend is JavaScript, which cannot hold a Rust value, so its work has to be
// bytes. Rather than inventing a second private layout inside the wasm
// built-in, the layout lives here — path-mounted by the Rust side and pinned
// against the JS literals by `tests/harness/tests/gpu_backend_wire.rs`, which
// is the only way a number can move on one side and not the other.
//
// Deliberately NOT part of the producer contract. Nothing outside a provider
// and its own backend ever encodes or decodes these bytes, and a consumer that
// tried would be naming table slots it has no business knowing.
//
// Little-endian throughout. `no_std`, zero-alloc.

/// `[0x01][pipeline u16][bind_count u16][bindings…][gx u32][gy u32][gz u32]`,
/// where each binding is
/// `[binding u32][buffer u16][pad u16][offset u64][size u64]`.
pub const EXEC_DISPATCH: u8 = 0x01;
/// `[0x02][src u16][dst u16][src_offset u64][dst_offset u64][len u64]`.
pub const EXEC_COPY: u8 = 0x02;

/// Bytes of one dispatch binding entry.
pub const EXEC_BIND_LEN: usize = 24;
/// Bytes of a dispatch header, before its bindings.
pub const EXEC_DISPATCH_HEADER: usize = 5;
/// Bytes of a dispatch's trailing workgroup counts.
pub const EXEC_DISPATCH_GROUPS: usize = 12;
/// Bytes of a whole copy item.
pub const EXEC_COPY_LEN: usize = 29;

/// Bytes a dispatch item occupies with `n` bindings.
#[must_use]
pub const fn exec_dispatch_len(n: usize) -> usize {
    EXEC_DISPATCH_HEADER + n * EXEC_BIND_LEN + EXEC_DISPATCH_GROUPS
}

/// Write a dispatch header, answering the offset the first binding goes at.
/// `None` when `out` cannot hold the whole item.
#[must_use]
pub fn exec_put_dispatch(out: &mut [u8], pipeline: u16, bind_count: usize) -> Option<usize> {
    if out.len() < exec_dispatch_len(bind_count) || bind_count > u16::MAX as usize {
        return None;
    }
    out[0] = EXEC_DISPATCH;
    out[1..3].copy_from_slice(&pipeline.to_le_bytes());
    out[3..5].copy_from_slice(&(bind_count as u16).to_le_bytes());
    Some(EXEC_DISPATCH_HEADER)
}

/// Write one binding entry at `off`.
pub fn exec_put_bind(
    out: &mut [u8],
    off: usize,
    binding: u32,
    buffer: u16,
    offset: u64,
    size: u64,
) {
    out[off..off + 4].copy_from_slice(&binding.to_le_bytes());
    out[off + 4..off + 6].copy_from_slice(&buffer.to_le_bytes());
    out[off + 6..off + 8].copy_from_slice(&0u16.to_le_bytes());
    out[off + 8..off + 16].copy_from_slice(&offset.to_le_bytes());
    out[off + 16..off + 24].copy_from_slice(&size.to_le_bytes());
}

/// Write the workgroup counts that close a dispatch item at `off`.
pub fn exec_put_groups(out: &mut [u8], off: usize, groups: [u32; 3]) {
    out[off..off + 4].copy_from_slice(&groups[0].to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&groups[1].to_le_bytes());
    out[off + 8..off + 12].copy_from_slice(&groups[2].to_le_bytes());
}

/// Write a whole copy item. `None` when `out` is too small.
#[must_use]
pub fn exec_put_copy(
    out: &mut [u8],
    src: u16,
    dst: u16,
    src_offset: u64,
    dst_offset: u64,
    len: u64,
) -> Option<usize> {
    if out.len() < EXEC_COPY_LEN {
        return None;
    }
    out[0] = EXEC_COPY;
    out[1..3].copy_from_slice(&src.to_le_bytes());
    out[3..5].copy_from_slice(&dst.to_le_bytes());
    out[5..13].copy_from_slice(&src_offset.to_le_bytes());
    out[13..21].copy_from_slice(&dst_offset.to_le_bytes());
    out[21..29].copy_from_slice(&len.to_le_bytes());
    Some(EXEC_COPY_LEN)
}

// ── Adapter facts ───────────────────────────────────────────────────────
//
// What a backend reports about the device it opened, in a flat record the
// provider reads into its `DeviceLimits`. Fixed offsets rather than a
// self-describing form: the fields are the contract between one provider and
// one backend, and a reader that cannot find one has a build mismatch.

pub const FACT_MIN_ALIGN: usize = 0; // u32
pub const FACT_MAX_BINDINGS: usize = 4; // u32
pub const FACT_MAX_WORKGROUP_X: usize = 8; // u32
pub const FACT_MAX_WORKGROUP_Y: usize = 12; // u32
pub const FACT_MAX_WORKGROUP_Z: usize = 16; // u32
pub const FACT_MAX_INVOCATIONS: usize = 20; // u32
pub const FACT_MAX_GRID: usize = 24; // u32
/// Backend capability bits — [`FACT_HAS_F16`] and friends below.
pub const FACT_FLAGS: usize = 28; // u32
pub const FACT_MAX_BUFFER_BYTES: usize = 32; // u64
pub const FACT_LEN: usize = 40;

/// The adapter reports native f16 arithmetic. Absent, the provider declares
/// f16 unsupported rather than emulated — there is no emulation path here.
pub const FACT_HAS_F16: u32 = 1 << 0;
/// The adapter can time GPU work.
pub const FACT_HAS_TIMESTAMP: u32 = 1 << 1;
