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
// `storage.block` is an edge contract: it is served by the module at the
// other end of a consumer's `blocks` port, and reached only through that
// edge. The consumer binds it once (`kernel::BIND` with `bind::PORT` naming
// its own port) and keeps the bound handle; every op below is a
// `provider_call` on that handle. The source is handed its own port
// reference on the edge (`bind::port_ref`) as the op's handle. The graph
// edge is the binding: there is no default source, so inserting a transform
// (a source on one side, a consumer on the other) never changes which device
// another consumer reaches.
//
// ## Units
//
// Every count and address is in **logical blocks** of the size `DESCRIBE`
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
//   completion. It MAY WAIT on the device — for the request, and for the
//   flush an `F_PREFLUSH` asks for — so it is for a consumer outside any
//   caller's step deadline (a vault, a fixture's own step).
// - `SUBMIT` queues one request and returns; `REAP` hands back one finished
//   completion. For a consumer that keeps several requests in flight.
//   `SUBMIT` never waits, `F_PREFLUSH` included: the source queues the
//   flush and starts the request once it completes.
//
// A provider answering inside a caller's step — an fs provider serving the
// `fs` contract — uses only `SUBMIT`/`REAP` and non-blocking flush fences
// (a `FLUSH` submitted and reaped), never `EXEC`: the `fs` contract does not
// let a call wait on the device. Such a provider therefore requires a source
// that reports `F_ASYNC` and refuses one that does not; every source that
// can sit under one does report it.
//
// A source that cannot queue reports no [`describe::F_ASYNC`] and answers
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
// A queued request's memory is a lend. The consumer lends its buffer or
// block cache once, on the bound handle (`lend::OPEN`, direction in/out as
// it reads and writes), under a cookie it chooses, and every `SUBMIT` names
// `[lend][offset][buf_len]` inside it. `buf_len` must equal
// `nblocks * logical_block_size` for `READ` and `WRITE` and be zero for
// every other op, which names no lend.
//
// The source resolves the cookie under the port reference it was handed
// (`lend::RESOLVE`), refuses a range outside the lend or a direction the
// lend does not allow, moves the bytes, and returns the borrow
// (`lend::RETURN`) before the request's completion becomes reapable. A read
// buffer is therefore the source's until its completion is reaped. A write
// buffer is lent for the same span, unless the source reports
// [`describe::F_WRITE_COPIES`]: it copies the bytes and returns the borrow before
// `SUBMIT` returns.
//
// `EXEC` names no lend: its buffer is the call's `data` span
// (`data_len == buf_len` for `READ` and `WRITE`, zero for every other op),
// and its `lend` and `offset` fields are zero.
//
// `READ_STREAM` names no buffer either: its blocks arrive on the edge's
// channel.
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
// [`describe::F_FLUSH`], and every completed write is `LocalDurable`.
//
// ## Retries
//
// A consumer that resubmits a write whose outcome it does not know resubmits
// byte-identical data at the same address. A source may execute a block
// write more than once; it never merges or reorders the bytes of one.

// ## Ops
//
// Op numbers are `registry::storage_block`:
//
// - `DESCRIBE`: `arg` out one [`describe`] record. Returns 0, or `EAGAIN`
//   while the device has not attached. The record's `F_*` flags are this
//   contract's capability bits: they qualify the geometry beside them (the
//   queue depth is meaningful with `F_ASYNC`, the device id with
//   `F_FLUSH`) and exist only once the device has attached, so they travel
//   in the one record a consumer reads after binding, and the contract has
//   no separate `CAPS`.
// - `SUBMIT`: `arg` in one [`req`] record. Returns 0 when queued, `EAGAIN`
//   when the queue is full, or a negative errno when the request is refused
//   before it is queued.
// - `REAP`: `arg` out one [`cpl`] record. Returns 1 when a completion was
//   written and 0 when none is ready.
// - `EXEC`: `arg` inout one [`req`] record followed by one [`cpl`] record,
//   which the source writes ([`exec`]); `data` the buffer. Returns the
//   completion's status.
// - `READ_STREAM`: `arg` in one [`req`] record with `op = READ`, naming no
//   buffer; the blocks are streamed onto the edge's channel. For a consumer
//   that participates in the channel state machine rather than one that
//   needs bytes inside its own dispatch. Returns 0 when queued.

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

/// Request record:
/// `[op u8][flags u8][0 u16][nblocks u32][lba u64][lend u32][offset u32]
/// [buf_len u32][0 u32][tag u64]`.
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
    /// `u32` LE — the cookie of the consumer's lend the buffer lies in.
    pub const LEND: usize = 16;
    /// `u32` LE — the buffer's offset inside that lend.
    pub const OFFSET: usize = 20;
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

/// `EXEC` argument: one [`req`] record, then one [`cpl`] record.
pub mod exec {
    /// The completion's offset in the argument.
    pub const CPL: usize = super::req::LEN;
    /// Total length, in bytes.
    pub const ARG_LEN: usize = super::req::LEN + super::cpl::LEN;
}

/// The device description record `DESCRIBE` answers.
pub mod describe {
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
    /// Cookie of the lend the buffer lies in (`SUBMIT`); 0 for `EXEC` and
    /// for an op without a buffer.
    pub lend: u32,
    /// Offset of the buffer inside that lend.
    pub offset: u32,
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
        o[req::LEND..req::LEND + 4].copy_from_slice(&self.lend.to_le_bytes());
        o[req::OFFSET..req::OFFSET + 4].copy_from_slice(&self.offset.to_le_bytes());
        o[req::BUF_LEN..req::BUF_LEN + 4].copy_from_slice(&self.buf_len.to_le_bytes());
        o[req::TAG..req::TAG + 8].copy_from_slice(&self.tag.to_le_bytes());
        true
    }

    /// Read a `READ_STREAM` request from `buf[..req::LEN]`: a `READ` of at
    /// least one block that names no buffer (no lend, offset or length) and
    /// carries no flag, since its blocks arrive on the edge's channel.
    pub fn decode_stream(buf: &[u8]) -> Option<Req> {
        if buf.len() < req::LEN {
            return None;
        }
        let r = Req {
            op: buf[req::OP],
            flags: buf[req::FLAGS],
            nblocks: u32::from_le_bytes(buf[req::NBLOCKS..req::NBLOCKS + 4].try_into().ok()?),
            lba: u64::from_le_bytes(buf[req::LBA..req::LBA + 8].try_into().ok()?),
            lend: u32::from_le_bytes(buf[req::LEND..req::LEND + 4].try_into().ok()?),
            offset: u32::from_le_bytes(buf[req::OFFSET..req::OFFSET + 4].try_into().ok()?),
            buf_len: u32::from_le_bytes(buf[req::BUF_LEN..req::BUF_LEN + 4].try_into().ok()?),
            tag: u64::from_le_bytes(buf[req::TAG..req::TAG + 8].try_into().ok()?),
        };
        let ok = r.op == op::READ
            && r.flags == 0
            && r.nblocks != 0
            && r.buf_len == 0
            && r.lend == 0
            && r.offset == 0;
        ok.then_some(r)
    }

    /// Read a request from `buf[..req::LEN]`, refusing any record this
    /// contract does not define: an unknown op or flag, `F_FUA` off a write,
    /// a data op without blocks or buffer, a non-data op with a buffer or a
    /// lend, or a `FLUSH` that names blocks.
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
            lend: u32::from_le_bytes(buf[req::LEND..req::LEND + 4].try_into().ok()?),
            offset: u32::from_le_bytes(buf[req::OFFSET..req::OFFSET + 4].try_into().ok()?),
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
            op::READ | op::WRITE => r.nblocks != 0 && r.buf_len != 0,
            op::DISCARD => r.nblocks != 0 && r.buf_len == 0 && r.lend == 0 && r.offset == 0,
            op::FLUSH => {
                r.nblocks == 0 && r.lba == 0 && r.buf_len == 0 && r.lend == 0 && r.offset == 0
            }
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

    /// Whether the op moves bytes through a buffer.
    pub fn has_buffer(&self) -> bool {
        matches!(self.op, op::READ | op::WRITE)
    }

    /// The buffer's byte range inside a lend of `lend_len` bytes, or `None`
    /// when it does not lie wholly inside it.
    pub fn range_in(&self, lend_len: usize) -> Option<core::ops::Range<usize>> {
        let start = self.offset as usize;
        let end = start.checked_add(self.buf_len as usize)?;
        (end <= lend_len).then_some(start..end)
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

/// A decoded [`describe`] record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub logical_block_size: u32,
    pub block_count: u64,
    pub max_blocks: u32,
    pub atomic_blocks: u32,
    pub queue_depth: u16,
    pub flags: u32,
    pub device_id: u64,
}

impl Description {
    /// Write this record at `out[..describe::LEN]`.
    pub fn encode(&self, out: &mut [u8]) -> bool {
        if out.len() < describe::LEN {
            return false;
        }
        let o = &mut out[..describe::LEN];
        o.fill(0);
        o[describe::LOGICAL_BLOCK_SIZE..describe::LOGICAL_BLOCK_SIZE + 4]
            .copy_from_slice(&self.logical_block_size.to_le_bytes());
        o[describe::BLOCK_COUNT..describe::BLOCK_COUNT + 8]
            .copy_from_slice(&self.block_count.to_le_bytes());
        o[describe::MAX_BLOCKS..describe::MAX_BLOCKS + 4]
            .copy_from_slice(&self.max_blocks.to_le_bytes());
        o[describe::ATOMIC_BLOCKS..describe::ATOMIC_BLOCKS + 4]
            .copy_from_slice(&self.atomic_blocks.to_le_bytes());
        o[describe::QUEUE_DEPTH..describe::QUEUE_DEPTH + 2]
            .copy_from_slice(&self.queue_depth.to_le_bytes());
        o[describe::FLAGS..describe::FLAGS + 4].copy_from_slice(&self.flags.to_le_bytes());
        o[describe::DEVICE_ID..describe::DEVICE_ID + 8]
            .copy_from_slice(&self.device_id.to_le_bytes());
        true
    }

    /// Read a [`describe`] record, refusing one no source may report: a block
    /// size that is not a power of two of at least 512, or a zero
    /// per-request, atomic or queue limit.
    pub fn decode(buf: &[u8]) -> Option<Description> {
        if buf.len() < describe::LEN {
            return None;
        }
        let c = Description {
            logical_block_size: u32::from_le_bytes(
                buf[describe::LOGICAL_BLOCK_SIZE..describe::LOGICAL_BLOCK_SIZE + 4]
                    .try_into()
                    .ok()?,
            ),
            block_count: u64::from_le_bytes(
                buf[describe::BLOCK_COUNT..describe::BLOCK_COUNT + 8]
                    .try_into()
                    .ok()?,
            ),
            max_blocks: u32::from_le_bytes(
                buf[describe::MAX_BLOCKS..describe::MAX_BLOCKS + 4]
                    .try_into()
                    .ok()?,
            ),
            atomic_blocks: u32::from_le_bytes(
                buf[describe::ATOMIC_BLOCKS..describe::ATOMIC_BLOCKS + 4]
                    .try_into()
                    .ok()?,
            ),
            queue_depth: u16::from_le_bytes(
                buf[describe::QUEUE_DEPTH..describe::QUEUE_DEPTH + 2]
                    .try_into()
                    .ok()?,
            ),
            flags: u32::from_le_bytes(buf[describe::FLAGS..describe::FLAGS + 4].try_into().ok()?),
            device_id: u64::from_le_bytes(
                buf[describe::DEVICE_ID..describe::DEVICE_ID + 8]
                    .try_into()
                    .ok()?,
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
                if !has(describe::F_WRITE) {
                    return false;
                }
            }
            op::DISCARD => {
                if !has(describe::F_DISCARD) {
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
