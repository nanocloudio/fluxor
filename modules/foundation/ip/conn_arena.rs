//! Connection-table storage: an inline first block plus chunks granted on
//! demand from the kernel elastic region.
//!
//! The table's CEILING is `tcp::MAX_TCP_CONNS` — slot numbers, the side
//! tables sized by it (`conn_index`, `free_slots`, `loopback_peer`, …) and
//! every published bound keep that meaning. Only the BACKING is lazy: the
//! first `CONN_FIRST` connections live inline in module state (always
//! available — the table's `min`), and further `CONN_CHUNK`-slot chunks are
//! granted by `resource::ELASTIC_ALLOC` as the allocator runs out (the
//! `max`). Committing the whole table would cost `MAX_TCP_CONNS × ~2.2 KiB`
//! — ~137 MiB on aarch64 — of the kernel state arena for a table a typical
//! graph uses a few dozen slots of; inline it costs ~1.1 MiB.
//!
//! Slots at or past [`ConnArena::len`] are unbacked memory: every access
//! driven by a slot number that did not come from this module's own
//! allocator (a consumer's `conn_id`, a sweep or scan bound) is checked
//! against `len()`, never against `MAX_TCP_CONNS`. Grants are
//! monotonic-to-teardown (the kernel reclaims them with the module's owner),
//! so `len()` never shrinks and a slot once valid stays valid.
//!
//! What can actually be granted is bounded by the elastic region, not by
//! `MAX_TCP_CONNS`: at 16 MiB on aarch64 (`abi::config::kernel::
//! ELASTIC_REGION_SIZE`, shared with every other Tier B pool, TLS sessions
//! among them) a 256-slot chunk rounds to ~576 KiB, so roughly 28 chunks —
//! ~7k slots on top of the inline block — until that profile constant is
//! raised. A denial is counted and the arrival refused, never a fault.
//!
//! On embedded targets the inline block IS the whole table (`CONN_FIRST ==
//! MAX_TCP_CONNS`, no elastic chunks): identical behaviour to a static
//! array, with no elastic dependency.

use super::{abi, tcp, SyscallTable, MAX_DG_ENDPOINTS};

/// Connections held inline in module state.
#[cfg(target_arch = "aarch64")]
pub const CONN_FIRST: usize = 512;
#[cfg(not(target_arch = "aarch64"))]
pub const CONN_FIRST: usize = tcp::MAX_TCP_CONNS;

/// Connections per elastic grant (~563 KiB, which the kernel rounds up to
/// nine 64 KiB quanta).
#[cfg(target_arch = "aarch64")]
const CONN_CHUNK: usize = 256;
#[cfg(not(target_arch = "aarch64"))]
const CONN_CHUNK: usize = 1;

/// Elastic chunks past the inline block, at most.
const EXTRA_CHUNKS: usize = (tcp::MAX_TCP_CONNS - CONN_FIRST) / CONN_CHUNK;

const _: () = assert!(CONN_FIRST <= tcp::MAX_TCP_CONNS);
const _: () = assert!(CONN_FIRST + EXTRA_CHUNKS * CONN_CHUNK == tcp::MAX_TCP_CONNS);
// Datagram endpoints occupy the first `MAX_DG_ENDPOINTS` slots and are
// scanned without a length check: the window must always be backed.
const _: () = assert!(CONN_FIRST >= MAX_DG_ENDPOINTS);

/// The connection table. `Index`/`IndexMut` and [`Self::ptr`] /
/// [`Self::ptr_mut`] keep every call site reading like a plain inline array;
/// the chunk indirection is invisible to the state machine.
pub struct ConnArena {
    first: [tcp::TcpConn; CONN_FIRST],
    extra: [*mut tcp::TcpConn; EXTRA_CHUNKS],
    extra_allocated: u32,
    /// Elastic chunks granted, lifetime.
    pub grants: u32,
    /// Elastic requests the kernel refused, lifetime. Asking at the
    /// ceiling is not a request and is not counted.
    pub denials: u32,
}

impl ConnArena {
    /// Backed slots (inline + granted chunks). Every bound that drives or
    /// guards an access into the table is this, not `MAX_TCP_CONNS`.
    #[inline(always)]
    pub fn len(&self) -> usize {
        CONN_FIRST + self.extra_allocated as usize * CONN_CHUNK
    }

    /// Slot-initialise the inline block. Called once from `module_new`.
    pub fn init(&mut self) {
        let mut i = 0;
        while i < CONN_FIRST {
            // SAFETY: `i < CONN_FIRST`, inside the inline block.
            unsafe { *self.first.as_mut_ptr().add(i) = tcp::TcpConn::new() };
            i += 1;
        }
        self.extra_allocated = 0;
        self.grants = 0;
        self.denials = 0;
    }

    /// Pointer to slot `i`.
    ///
    /// # Safety
    /// `i < self.len()`.
    #[inline(always)]
    pub unsafe fn ptr(&self, i: usize) -> *const tcp::TcpConn {
        if i < CONN_FIRST {
            self.first.as_ptr().add(i)
        } else {
            let k = i - CONN_FIRST;
            (*self.extra.as_ptr().add(k / CONN_CHUNK)).add(k % CONN_CHUNK)
        }
    }

    /// Mutable pointer to slot `i`.
    ///
    /// # Safety
    /// `i < self.len()`.
    #[inline(always)]
    pub unsafe fn ptr_mut(&mut self, i: usize) -> *mut tcp::TcpConn {
        if i < CONN_FIRST {
            self.first.as_mut_ptr().add(i)
        } else {
            let k = i - CONN_FIRST;
            (*self.extra.as_ptr().add(k / CONN_CHUNK)).add(k % CONN_CHUNK)
        }
    }

    /// Iterate the backed slots.
    pub fn iter(&self) -> impl Iterator<Item = &tcp::TcpConn> {
        // SAFETY: `i < len()`.
        (0..self.len()).map(move |i| unsafe { &*self.ptr(i) })
    }

    /// Grant one more chunk from the kernel elastic region; its slots are
    /// the `CONN_CHUNK` below the new `len()`. `false` at the ceiling or
    /// when the region denies (the caller treats both as table-full). Control-plane only — called from
    /// the allocator once the free stack and its rebuild slice are empty,
    /// never per packet.
    pub fn grow(&mut self, sys: &SyscallTable) -> bool {
        let next = self.extra_allocated as usize;
        if next >= EXTRA_CHUNKS {
            return false;
        }
        let bytes = (CONN_CHUNK * core::mem::size_of::<tcp::TcpConn>()) as u32;
        let b = bytes.to_le_bytes();
        let mut arg = [b[0], b[1], b[2], b[3], 0, 0, 0, 0];
        // SAFETY: kernel-owned syscall table; arg is an 8-byte local.
        let rc = unsafe {
            (sys.provider_call)(
                -1,
                abi::contracts::resource::ELASTIC_ALLOC,
                arg.as_mut_ptr(),
                arg.len(),
            )
        };
        if rc < 0 || (rc as u32) < bytes {
            self.denials = self.denials.wrapping_add(1);
            return false;
        }
        let chunk = u64::from_le_bytes(arg) as usize as *mut tcp::TcpConn;
        if chunk.is_null() {
            self.denials = self.denials.wrapping_add(1);
            return false;
        }
        // Slot-initialise the grant, as `init` does the inline block: the
        // kernel zeroes the chunk, but `TcpConn::new()` is authoritative
        // (its wildcard `local_slot` is not zero). `write` never reads or
        // drops the old bytes.
        let mut k = 0;
        while k < CONN_CHUNK {
            // SAFETY: the kernel granted `CONN_CHUNK` connections at `chunk`.
            unsafe { core::ptr::write(chunk.add(k), tcp::TcpConn::new()) };
            k += 1;
        }
        // SAFETY: `next < EXTRA_CHUNKS`.
        unsafe { *self.extra.as_mut_ptr().add(next) = chunk };
        self.extra_allocated += 1;
        self.grants = self.grants.wrapping_add(1);
        true
    }
}

impl core::ops::Index<usize> for ConnArena {
    type Output = tcp::TcpConn;
    #[inline(always)]
    fn index(&self, i: usize) -> &tcp::TcpConn {
        debug_assert!(i < self.len());
        // SAFETY: every index the module forms is a slot it allocated, or
        // one checked against `len()` at the boundary it arrived through.
        unsafe { &*self.ptr(i) }
    }
}

impl core::ops::IndexMut<usize> for ConnArena {
    #[inline(always)]
    fn index_mut(&mut self, i: usize) -> &mut tcp::TcpConn {
        debug_assert!(i < self.len());
        // SAFETY: as in `Index`.
        unsafe { &mut *self.ptr_mut(i) }
    }
}
