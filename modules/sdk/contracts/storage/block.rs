// Contract: block — raw logical-block I/O (`storage.block`).
//
// Layer: contracts/storage (public, stable).
//
// One of four canonical storage surfaces (`storage.block`, `file.data`,
// `storage.namespace`, `storage.object`) — see
// `docs/architecture/storage_capability_surface.md`.
//
// ## Addressing
//
// A block source is not provider-dispatched. It is the channel wired to a
// consumer's `blocks` input, and every request below is a channel ioctl on
// that channel. The graph edge is the binding: there is no default source,
// so inserting a transform (a source on one side, a consumer on the other)
// never changes which device another consumer reaches.
//
// ## Units
//
// Every count and address is in **logical blocks** of the size `CAPS`
// reports. A consumer that has not asked has no licence to assume 512.
// Addresses are 64-bit; a source whose hardware addresses less refuses an
// out-of-range request rather than truncating it.
//
// ## Requests and completions
//
// A request is a fixed [`req`] record; a completion is a fixed [`cpl`]
// record. The same records serve both execution styles:
//
// - `EXEC` runs one request to completion inside the call and writes its
//   completion. For a consumer that must answer within its own dispatch.
// - `SUBMIT` queues one request and returns; `REAP` hands back one finished
//   completion. For a consumer that keeps several requests in flight.
//
// A source that cannot queue reports no [`caps::F_ASYNC`] and answers
// `SUBMIT` with `ENOSYS`.
//
// `tag` is the consumer's request identity. The source echoes it in the
// completion and never interprets it. Tags need only be unique among a
// consumer's requests in flight.
//
// ## Ordering
//
// Requests in flight are unordered. A consumer that needs A durable, or
// even visible, before B waits for A's completion before submitting B.
//
// - `FLUSH` makes durable every write whose completion was reaped before
//   the `FLUSH` was submitted.
// - [`F_PREFLUSH`] on any request performs that flush before the request
//   itself. It is the contract's barrier: this contract has no ordering
//   barrier beyond it.
// - [`F_FUA`] on a write makes that write durable before it completes.
//
// ## Buffers
//
// `buf_ptr` / `buf_len` name the caller's memory. `buf_len` must equal
// `nblocks * logical_block_size` for `READ` and `WRITE` and be zero for
// every other op. A read buffer is lent to the source until the request's
// completion is reaped (or `EXEC` returns). A write buffer is lent for the
// same span, unless the source reports [`caps::F_WRITE_COPIES`], in which
// case it is released when `SUBMIT` returns.
//
// ## Fences
//
// A successful completion carries the strongest `Fence` the source
// achieved, encoded with `Fence::encode`:
//
// - a write, discard or flush that reached non-volatile media:
//   `LocalDurable { device_id }`, or the lower fence a transform passes
//   through;
// - a write that may still sit in a volatile cache: `Volatile`;
// - a read or a failure: no fence (`fence_len = 0`).
//
// A source whose device has no volatile write cache reports no
// [`caps::F_FLUSH`], and every completed write is `LocalDurable`.
//
// ## Retries
//
// A consumer that resubmits a write whose outcome it does not know resubmits
// byte-identical data at the same address. A source may execute a block
// write more than once; it never merges or reorders the bytes of one.

/// Channel ioctl commands on a block source's `blocks` channel.
pub mod ioctl {
    /// Stream `nblocks` blocks back on the channel itself instead of into a
    /// buffer. Argument: one [`super::req`] record with `op = READ`;
    /// `buf_ptr`/`buf_len` are ignored. For a consumer that participates in
    /// the channel state machine rather than one that needs bytes inside its
    /// own dispatch. Returns 0 when queued.
    pub const READ_STREAM: u32 = 0x4E56_0002;
    /// Describe the source. Argument: one [`super::caps`] record, written by
    /// the source. Returns `caps::LEN`, or `EAGAIN` while the device has
    /// not attached.
    pub const CAPS: u32 = 0x4E56_0009;
    /// Queue one request. Argument: one [`super::req`] record. Returns 0 when
    /// queued, `EAGAIN` when the queue is full, or a negative errno when the
    /// request is refused before it is queued.
    pub const SUBMIT: u32 = 0x4E56_000A;
    /// Hand back one finished completion. Argument: one [`super::cpl`]
    /// record, written by the source. Returns 1 when a completion was
    /// written and 0 when none is ready.
    pub const REAP: u32 = 0x4E56_000B;
    /// Run one request to completion. Argument: one [`super::req`] record
    /// followed by one [`super::cpl`] record, which the source writes.
    /// Returns the completion's status.
    pub const EXEC: u32 = 0x4E56_000C;
}

/// Request operations.
pub mod op {
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 2;
    pub const FLUSH: u8 = 3;
    pub const DISCARD: u8 = 4;
}

/// Write-through: the write is durable before it completes. `WRITE` only.
pub const F_FUA: u8 = 0x01;
/// Flush every write reaped before this request was submitted, then execute
/// it. Valid on every op.
pub const F_PREFLUSH: u8 = 0x02;
/// Every flag this contract defines.
pub const F_ALL: u8 = F_FUA | F_PREFLUSH;

/// Request record.
pub mod req {
    /// Total length, in bytes.
    pub const LEN: usize = 40;
    /// `u8` — one of [`super::op`].
    pub const OP: usize = 0;
    /// `u8` — [`super::F_FUA`] / [`super::F_PREFLUSH`].
    pub const FLAGS: usize = 1;
    /// `u32` LE — logical blocks. Zero for `FLUSH`.
    pub const NBLOCKS: usize = 4;
    /// `u64` LE — first logical block.
    pub const LBA: usize = 8;
    /// `u64` LE — caller's buffer.
    pub const BUF_PTR: usize = 16;
    /// `u32` LE — buffer length in bytes.
    pub const BUF_LEN: usize = 24;
    /// `u64` LE — consumer's request identity, echoed in the completion.
    pub const TAG: usize = 32;
}

/// Completion record.
pub mod cpl {
    /// Total length, in bytes.
    pub const LEN: usize = 80;
    /// `u64` LE — the request's tag.
    pub const TAG: usize = 0;
    /// `i32` LE — 0 or a negative errno.
    pub const STATUS: usize = 8;
    /// `u16` LE — encoded fence length; 0 for none.
    pub const FENCE_LEN: usize = 12;
    /// `Fence::encode` bytes, up to `fence::WIRE_MAX_LEN`.
    pub const FENCE: usize = 16;
    /// Room for the longest encoded fence.
    pub const FENCE_CAP: usize = LEN - FENCE;
}

/// Capability record.
pub mod caps {
    /// Total length, in bytes.
    pub const LEN: usize = 40;
    /// `u32` LE — logical block size in bytes.
    pub const LOGICAL_BLOCK_SIZE: usize = 0;
    /// `u64` LE — logical blocks the source addresses.
    pub const BLOCK_COUNT: usize = 8;
    /// `u32` LE — most blocks one request may carry.
    pub const MAX_BLOCKS: usize = 16;
    /// `u32` LE — blocks the device writes atomically across power loss.
    pub const ATOMIC_BLOCKS: usize = 20;
    /// `u16` LE — requests the source holds in flight; 1 without `F_ASYNC`.
    pub const QUEUE_DEPTH: usize = 24;
    /// `u32` LE — `F_*` below.
    pub const FLAGS: usize = 28;
    /// `u64` LE — the device identity its `LocalDurable` fences name.
    pub const DEVICE_ID: usize = 32;

    /// Accepts `WRITE`. Clear on a read-only source.
    pub const F_WRITE: u32 = 1 << 0;
    /// Has a volatile write cache, so `FLUSH` does work and an un-FUA write
    /// completes `Volatile`.
    pub const F_FLUSH: u32 = 1 << 1;
    /// Honours `F_FUA` natively rather than as write-then-flush.
    pub const F_FUA: u32 = 1 << 2;
    /// Accepts `DISCARD`.
    pub const F_DISCARD: u32 = 1 << 3;
    /// Discarded blocks read back as zeros.
    pub const F_DISCARD_ZEROES: u32 = 1 << 4;
    /// Accepts `SUBMIT` / `REAP`.
    pub const F_ASYNC: u32 = 1 << 5;
    /// Accepts `READ_STREAM`.
    pub const F_READ_STREAM: u32 = 1 << 6;
    /// Releases a write buffer when `SUBMIT` returns.
    pub const F_WRITE_COPIES: u32 = 1 << 7;
}

/// A decoded request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Req {
    pub op: u8,
    pub flags: u8,
    pub nblocks: u32,
    pub lba: u64,
    pub buf_ptr: u64,
    pub buf_len: u32,
    pub tag: u64,
}

impl Req {
    /// Write this request at `out[..req::LEN]`. Reserved bytes are zeroed.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < req::LEN {
            return false;
        }
        let o = &mut out[..req::LEN];
        o.fill(0);
        o[req::OP] = self.op;
        o[req::FLAGS] = self.flags;
        o[req::NBLOCKS..req::NBLOCKS + 4].copy_from_slice(&self.nblocks.to_le_bytes());
        o[req::LBA..req::LBA + 8].copy_from_slice(&self.lba.to_le_bytes());
        o[req::BUF_PTR..req::BUF_PTR + 8].copy_from_slice(&self.buf_ptr.to_le_bytes());
        o[req::BUF_LEN..req::BUF_LEN + 4].copy_from_slice(&self.buf_len.to_le_bytes());
        o[req::TAG..req::TAG + 8].copy_from_slice(&self.tag.to_le_bytes());
        true
    }

    /// Read a request from `buf[..req::LEN]`, refusing any record this
    /// contract does not define: an unknown op or flag, `F_FUA` off a write,
    /// a data op without blocks or buffer, a non-data op with a buffer, or a
    /// `FLUSH` that names blocks.
    ///
    /// Whether `buf_len` matches `nblocks` is the source's check: only it
    /// knows its block size.
    pub fn decode(buf: &[u8]) -> Option<Req> {
        if buf.len() < req::LEN {
            return None;
        }
        let r = Req {
            op: buf[req::OP],
            flags: buf[req::FLAGS],
            nblocks: u32::from_le_bytes(buf[req::NBLOCKS..req::NBLOCKS + 4].try_into().ok()?),
            lba: u64::from_le_bytes(buf[req::LBA..req::LBA + 8].try_into().ok()?),
            buf_ptr: u64::from_le_bytes(buf[req::BUF_PTR..req::BUF_PTR + 8].try_into().ok()?),
            buf_len: u32::from_le_bytes(buf[req::BUF_LEN..req::BUF_LEN + 4].try_into().ok()?),
            tag: u64::from_le_bytes(buf[req::TAG..req::TAG + 8].try_into().ok()?),
        };
        if r.flags & !F_ALL != 0 {
            return None;
        }
        if r.flags & F_FUA != 0 && r.op != op::WRITE {
            return None;
        }
        let ok = match r.op {
            op::READ | op::WRITE => r.nblocks != 0 && r.buf_len != 0 && r.buf_ptr != 0,
            op::DISCARD => r.nblocks != 0 && r.buf_len == 0,
            op::FLUSH => r.nblocks == 0 && r.lba == 0 && r.buf_len == 0,
            _ => false,
        };
        if ok {
            Some(r)
        } else {
            None
        }
    }

    /// Whether the source writes into the caller's buffer.
    pub fn writes_buffer(&self) -> bool {
        self.op == op::READ
    }
}

/// A completion. `fence` holds `fence_len` bytes of `Fence::encode` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpl {
    pub tag: u64,
    pub status: i32,
    pub fence_len: u16,
    pub fence: [u8; cpl::FENCE_CAP],
}

impl Cpl {
    /// A completion with no fence.
    pub const fn bare(tag: u64, status: i32) -> Cpl {
        Cpl {
            tag,
            status,
            fence_len: 0,
            fence: [0; cpl::FENCE_CAP],
        }
    }

    /// Write this completion at `out[..cpl::LEN]`.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < cpl::LEN || self.fence_len as usize > cpl::FENCE_CAP {
            return false;
        }
        let o = &mut out[..cpl::LEN];
        o.fill(0);
        o[cpl::TAG..cpl::TAG + 8].copy_from_slice(&self.tag.to_le_bytes());
        o[cpl::STATUS..cpl::STATUS + 4].copy_from_slice(&self.status.to_le_bytes());
        o[cpl::FENCE_LEN..cpl::FENCE_LEN + 2].copy_from_slice(&self.fence_len.to_le_bytes());
        let n = self.fence_len as usize;
        o[cpl::FENCE..cpl::FENCE + n].copy_from_slice(&self.fence[..n]);
        true
    }

    /// Read a completion from `buf[..cpl::LEN]`.
    pub fn decode(buf: &[u8]) -> Option<Cpl> {
        if buf.len() < cpl::LEN {
            return None;
        }
        let fence_len =
            u16::from_le_bytes(buf[cpl::FENCE_LEN..cpl::FENCE_LEN + 2].try_into().ok()?);
        if fence_len as usize > cpl::FENCE_CAP {
            return None;
        }
        let mut fence = [0u8; cpl::FENCE_CAP];
        fence.copy_from_slice(&buf[cpl::FENCE..cpl::LEN]);
        Some(Cpl {
            tag: u64::from_le_bytes(buf[cpl::TAG..cpl::TAG + 8].try_into().ok()?),
            status: i32::from_le_bytes(buf[cpl::STATUS..cpl::STATUS + 4].try_into().ok()?),
            fence_len,
            fence,
        })
    }

    /// The encoded fence bytes.
    pub fn fence_bytes(&self) -> &[u8] {
        &self.fence[..self.fence_len as usize]
    }
}

/// A decoded capability record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub logical_block_size: u32,
    pub block_count: u64,
    pub max_blocks: u32,
    pub atomic_blocks: u32,
    pub queue_depth: u16,
    pub flags: u32,
    pub device_id: u64,
}

impl Caps {
    /// Write this record at `out[..caps::LEN]`.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < caps::LEN {
            return false;
        }
        let o = &mut out[..caps::LEN];
        o.fill(0);
        o[caps::LOGICAL_BLOCK_SIZE..caps::LOGICAL_BLOCK_SIZE + 4]
            .copy_from_slice(&self.logical_block_size.to_le_bytes());
        o[caps::BLOCK_COUNT..caps::BLOCK_COUNT + 8]
            .copy_from_slice(&self.block_count.to_le_bytes());
        o[caps::MAX_BLOCKS..caps::MAX_BLOCKS + 4].copy_from_slice(&self.max_blocks.to_le_bytes());
        o[caps::ATOMIC_BLOCKS..caps::ATOMIC_BLOCKS + 4]
            .copy_from_slice(&self.atomic_blocks.to_le_bytes());
        o[caps::QUEUE_DEPTH..caps::QUEUE_DEPTH + 2]
            .copy_from_slice(&self.queue_depth.to_le_bytes());
        o[caps::FLAGS..caps::FLAGS + 4].copy_from_slice(&self.flags.to_le_bytes());
        o[caps::DEVICE_ID..caps::DEVICE_ID + 8].copy_from_slice(&self.device_id.to_le_bytes());
        true
    }

    /// Read a capability record, refusing one no source may report: a block
    /// size that is not a power of two of at least 512, or a zero
    /// per-request, atomic or queue limit.
    pub fn decode(buf: &[u8]) -> Option<Caps> {
        if buf.len() < caps::LEN {
            return None;
        }
        let c = Caps {
            logical_block_size: u32::from_le_bytes(
                buf[caps::LOGICAL_BLOCK_SIZE..caps::LOGICAL_BLOCK_SIZE + 4]
                    .try_into()
                    .ok()?,
            ),
            block_count: u64::from_le_bytes(
                buf[caps::BLOCK_COUNT..caps::BLOCK_COUNT + 8]
                    .try_into()
                    .ok()?,
            ),
            max_blocks: u32::from_le_bytes(
                buf[caps::MAX_BLOCKS..caps::MAX_BLOCKS + 4]
                    .try_into()
                    .ok()?,
            ),
            atomic_blocks: u32::from_le_bytes(
                buf[caps::ATOMIC_BLOCKS..caps::ATOMIC_BLOCKS + 4]
                    .try_into()
                    .ok()?,
            ),
            queue_depth: u16::from_le_bytes(
                buf[caps::QUEUE_DEPTH..caps::QUEUE_DEPTH + 2]
                    .try_into()
                    .ok()?,
            ),
            flags: u32::from_le_bytes(buf[caps::FLAGS..caps::FLAGS + 4].try_into().ok()?),
            device_id: u64::from_le_bytes(
                buf[caps::DEVICE_ID..caps::DEVICE_ID + 8].try_into().ok()?,
            ),
        };
        let lbs = c.logical_block_size;
        if lbs < 512 || !lbs.is_power_of_two() {
            return None;
        }
        if c.max_blocks == 0 || c.atomic_blocks == 0 || c.queue_depth == 0 {
            return None;
        }
        Some(c)
    }

    /// Whether `r` fits this source: its op is supported, its range is inside
    /// the device, its size within one request, and its buffer exactly
    /// covers its blocks.
    pub fn admits(&self, r: &Req) -> bool {
        let has = |f: u32| self.flags & f != 0;
        match r.op {
            op::READ => {}
            op::WRITE => {
                if !has(caps::F_WRITE) {
                    return false;
                }
            }
            op::DISCARD => {
                if !has(caps::F_DISCARD) {
                    return false;
                }
            }
            op::FLUSH => return true,
            _ => return false,
        }
        if r.nblocks > self.max_blocks {
            return false;
        }
        let Some(end) = r.lba.checked_add(u64::from(r.nblocks)) else {
            return false;
        };
        if end > self.block_count {
            return false;
        }
        if r.op == op::DISCARD {
            return true;
        }
        u64::from(r.buf_len) == u64::from(r.nblocks) * u64::from(self.logical_block_size)
    }
}
