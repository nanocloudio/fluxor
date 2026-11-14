// A module's heap statistics: the record `provider_query(HEAP_STATS)`
// answers, defined here by offset and exact length so the kernel that
// writes it and the module that reads it cannot disagree. Every field is a
// little-endian u32; the kernel refuses a buffer of any other length.

/// Bytes of the record.
pub const LEN: usize = 36;

/// Field offsets.
pub mod at {
    /// The heap's size in bytes: its cap, which an elastic heap commits only
    /// as it is used.
    pub const ARENA_SIZE: usize = 0;
    /// Bytes allocated now (excluding headers).
    pub const ALLOCATED: usize = 4;
    /// Allocations live now.
    pub const ALLOC_COUNT: usize = 8;
    /// Allocations made since the heap was created.
    pub const TOTAL_ALLOCS: usize = 12;
    /// The most bytes ever allocated at once.
    pub const HIGH_WATER: usize = 16;
    /// Free blocks: how fragmented the heap is.
    pub const FREE_BLOCKS: usize = 20;
    /// The largest single allocation the heap can serve next.
    pub const LARGEST_FREE: usize = 24;
    /// Allocations that failed.
    pub const FAIL_COUNT: usize = 28;
    /// Allocations refused because the heap could not grow.
    pub const GROW_DENIED: usize = 32;
}

/// The record's fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapStats {
    pub arena_size: u32,
    pub allocated: u32,
    pub alloc_count: u32,
    pub total_allocs: u32,
    pub high_water: u32,
    pub free_blocks: u32,
    pub largest_free: u32,
    pub fail_count: u32,
    pub grow_denied: u32,
}

impl HeapStats {
    /// The record's bytes.
    pub fn encode(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        for (offset, v) in [
            (at::ARENA_SIZE, self.arena_size),
            (at::ALLOCATED, self.allocated),
            (at::ALLOC_COUNT, self.alloc_count),
            (at::TOTAL_ALLOCS, self.total_allocs),
            (at::HIGH_WATER, self.high_water),
            (at::FREE_BLOCKS, self.free_blocks),
            (at::LARGEST_FREE, self.largest_free),
            (at::FAIL_COUNT, self.fail_count),
            (at::GROW_DENIED, self.grow_denied),
        ] {
            b[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    /// The fields of a record's bytes.
    pub fn decode(b: &[u8; LEN]) -> Self {
        let u = |offset: usize| {
            u32::from_le_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        };
        Self {
            arena_size: u(at::ARENA_SIZE),
            allocated: u(at::ALLOCATED),
            alloc_count: u(at::ALLOC_COUNT),
            total_allocs: u(at::TOTAL_ALLOCS),
            high_water: u(at::HIGH_WATER),
            free_blocks: u(at::FREE_BLOCKS),
            largest_free: u(at::LARGEST_FREE),
            fail_count: u(at::FAIL_COUNT),
            grow_denied: u(at::GROW_DENIED),
        }
    }
}
