//! The send buffers: one pool of equal blocks, each the bytes one
//! connection has sent and the peer has not yet acknowledged.
//!
//! A connection whose consumer keeps no copy of what it sends (one not
//! granted `RETX`) takes a block when a burst starts and gives it back when
//! the peer has acknowledged everything in it, so the pool is sized for the
//! connections sending at once, not for the table. A block is
//! `tcp_send_buf` bytes; what a connection keeps in flight is the least of
//! its block, its congestion window and the peer's window. With no block to
//! be had, a send waits in its lane's stash exactly as it waits for a closed
//! window — the lane stops reading commands until a block frees.
//!
//! The pool is `tcp_send_pool` bytes, as many blocks as that holds. The
//! composer derives it from the graph: none at all where no consumer of
//! `net_out` leaves retention to this module (every one retains its own, or
//! opens no stream) and no workload lane is served, so such a graph pays
//! nothing for it. On aarch64 the blocks are granted on demand from the
//! kernel elastic region (`resource::ELASTIC_ALLOC`); a grant is kept for
//! reuse once given back. On an MCU-class target they are taken from the
//! module heap at construction — the composer grows the heap by the pool —
//! and a heap that cannot hold them refuses the instance.

use super::{abi, heap_alloc, tcp, SyscallTable};

/// Blocks a pool may hold: the table of them is compiled in, the blocks
/// are not. Two on an MCU-class target, where a block is held only while a
/// burst is unacknowledged, so two connections sending at once — or one
/// sending while another waits a round trip — fit it.
#[cfg(target_arch = "aarch64")]
pub const POOL_BLOCKS: usize = 128;
#[cfg(not(target_arch = "aarch64"))]
pub const POOL_BLOCKS: usize = 2;

/// A block's bytes when the graph declares none (`tcp_send_buf`): one MSS
/// on RP2040, two on RP2350, 64 KiB where the region is elastic.
#[cfg(target_arch = "aarch64")]
pub const BLOCK_DEFAULT: u32 = 64 * 1024;
#[cfg(all(not(target_arch = "aarch64"), fluxor_abi = "thumbv6m"))]
pub const BLOCK_DEFAULT: u32 = tcp::MSS as u32;
#[cfg(all(not(target_arch = "aarch64"), not(fluxor_abi = "thumbv6m")))]
pub const BLOCK_DEFAULT: u32 = 2 * tcp::MSS as u32;

/// The pool when the graph declares none (`tcp_send_pool`): every block
/// the table holds, of the default size.
pub const POOL_DEFAULT: u32 = POOL_BLOCKS as u32 * BLOCK_DEFAULT;

/// The heap a block costs beyond its bytes on an MCU-class target, where
/// blocks come from the heap: its allocation header.
#[cfg(not(target_arch = "aarch64"))]
pub const BLOCK_OVERHEAD: u32 = 16;

/// Blocks are granted on demand (elastic) rather than taken at
/// construction.
const ON_DEMAND: bool = cfg!(target_arch = "aarch64");

/// Why a pool cannot be sized.
pub enum PoolRefusal {
    /// `tcp_send_pool` is less than one `tcp_send_buf` block, or more
    /// blocks than the table holds (`POOL_BLOCKS`).
    Blocks,
    /// The heap cannot hold the blocks.
    Heap,
}

pub struct SendPool {
    /// Bytes per block; 0 retains nothing (every consumer retains its own,
    /// or opens no stream).
    grant: u32,
    /// Blocks the pool holds at most: `tcp_send_pool / tcp_send_buf`.
    blocks: u16,
    /// Blocks backed so far, `block[..made]`.
    made: u16,
    /// Blocks given back and free for reuse, `free[..free_n]`.
    free_n: u16,
    block: [*mut u8; POOL_BLOCKS],
    free: [u16; POOL_BLOCKS],
    /// Blocks handed out, lifetime.
    pub takes: u32,
    /// Takes that found no block, lifetime.
    pub misses: u32,
}

impl SendPool {
    pub const EMPTY: SendPool = SendPool {
        grant: 0,
        blocks: 0,
        made: 0,
        free_n: 0,
        block: [core::ptr::null_mut(); POOL_BLOCKS],
        free: [0; POOL_BLOCKS],
        takes: 0,
        misses: 0,
    };

    /// Bytes per block.
    #[inline(always)]
    pub fn grant(&self) -> u32 {
        self.grant
    }

    /// Size the pool: `pool` bytes in blocks of `grant`, and on an
    /// MCU-class target every block taken from the heap now. Either 0
    /// retains nothing.
    ///
    /// # Safety
    /// `sys` is the module's live syscall table.
    pub unsafe fn init(
        &mut self,
        sys: &SyscallTable,
        grant: u32,
        pool: u32,
    ) -> Result<(), PoolRefusal> {
        *self = SendPool::EMPTY;
        if grant == 0 || pool == 0 {
            return Ok(());
        }
        let blocks = pool / grant;
        if blocks == 0 || blocks as usize > POOL_BLOCKS {
            return Err(PoolRefusal::Blocks);
        }
        self.grant = grant;
        self.blocks = blocks as u16;
        if ON_DEMAND {
            return Ok(());
        }
        while self.made < self.blocks {
            let p = heap_alloc(sys, grant);
            if p.is_null() {
                return Err(PoolRefusal::Heap);
            }
            self.block[self.made as usize] = p;
            self.free[self.free_n as usize] = self.made;
            self.made += 1;
            self.free_n += 1;
        }
        Ok(())
    }

    /// A free block, granting a new one when the region allows;
    /// `tcp::SBUF_NONE` when none can be had.
    ///
    /// # Safety
    /// `sys` is the module's live syscall table.
    pub unsafe fn take(&mut self, sys: &SyscallTable) -> u16 {
        if self.grant == 0 {
            return tcp::SBUF_NONE;
        }
        if self.free_n == 0 && !(ON_DEMAND && self.grow(sys)) {
            self.misses = self.misses.wrapping_add(1);
            return tcp::SBUF_NONE;
        }
        self.free_n -= 1;
        self.takes = self.takes.wrapping_add(1);
        self.free[self.free_n as usize]
    }

    /// Give block `b` back.
    pub fn give(&mut self, b: u16) {
        if (b as usize) < self.made as usize && (self.free_n as usize) < POOL_BLOCKS {
            self.free[self.free_n as usize] = b;
            self.free_n += 1;
        }
    }

    /// Block `b`'s bytes.
    ///
    /// # Safety
    /// `b` was handed out by [`Self::take`] and not given back.
    #[inline(always)]
    pub unsafe fn bytes(&mut self, b: u16) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.block[b as usize], self.grant as usize)
    }

    /// Block `b`'s bytes, to read.
    ///
    /// # Safety
    /// As [`Self::bytes`].
    #[inline(always)]
    pub unsafe fn view(&self, b: u16) -> &[u8] {
        core::slice::from_raw_parts(self.block[b as usize], self.grant as usize)
    }

    /// Blocks backed and blocks free: `(made, free)`.
    #[cfg(feature = "host-test")]
    pub fn counts(&self) -> (u16, u16) {
        (self.made, self.free_n)
    }

    /// Back one more block from the elastic region.
    unsafe fn grow(&mut self, sys: &SyscallTable) -> bool {
        if self.made >= self.blocks {
            return false;
        }
        let b = self.grant.to_le_bytes();
        // In: [bytes u32]; out: [addr u64][len u32].
        let mut arg = [b[0], b[1], b[2], b[3], 0, 0, 0, 0, 0, 0, 0, 0];
        let rc = (sys.provider_call)(
            -1,
            abi::contracts::resource::ELASTIC_ALLOC,
            arg.as_mut_ptr(),
            arg.len(),
            core::ptr::null_mut(),
            0,
        );
        let granted = u32::from_le_bytes([arg[8], arg[9], arg[10], arg[11]]);
        let at = u64::from_le_bytes([
            arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7],
        ]) as usize as *mut u8;
        if rc < 0 || granted < self.grant || at.is_null() {
            return false;
        }
        self.block[self.made as usize] = at;
        self.free[self.free_n as usize] = self.made;
        self.made += 1;
        self.free_n += 1;
        true
    }
}

/// Ring arithmetic over one block: the `n` bytes from offset `at` as up to
/// two contiguous runs `(first, second)` of a block of `cap` bytes.
#[inline(always)]
pub fn runs(at: u32, n: u32, cap: u32) -> ((usize, usize), (usize, usize)) {
    if cap == 0 {
        return ((0, 0), (0, 0));
    }
    let at = at % cap;
    let first = n.min(cap - at);
    ((at as usize, first as usize), (0, (n - first) as usize))
}
