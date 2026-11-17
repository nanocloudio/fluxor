// ============================================================================
// storage.block client
// ============================================================================
//
// The consumer half of `abi::contracts::storage::block`. The client binds
// the contract once through the consumer's `blocks` input port (the source is
// the module at the other end of that edge) and keeps the bound handle. A
// queued request's buffer lies in the one region the consumer named at
// `bind` — its block cache, or its state — which the client lends to the
// source once, on first use; requests name offsets into that lend. `EXEC`
// lends nothing: its buffer is the call's data span.
//
// Two families:
//
// - Non-blocking, for anything that runs inside a step: tagged reads
//   (`submit_read` / `take_read`), tracked writes and discards
//   (`submit_write` / `submit_discard` / `write_state`), and durability
//   fences (`flush_submit` / `flush_poll`). None of them waits on the
//   device: a call submits, reaps what has finished, and returns.
// - Blocking `EXEC` helpers (`read`, `write`, `exec`, `flush`), for a
//   consumer that runs outside any step's deadline. `EXEC` may wait on the
//   device (see the contract), so a provider answering inside a caller's
//   step never uses them.
//
// A consumer that keeps requests of every op in flight under its own tags (a
// device frontend) uses `submit` / `reap_one` instead; the two styles do not
// share one client.
//
// A fence names every write submitted before it opened. It is durable once
// each of those writes has completed without error and, on a source with a
// volatile write cache, a `FLUSH` submitted after they were all reaped has
// completed. Completions arrive in any order, so the client tracks the
// individual writes in flight rather than a count: a later write finishing
// first proves nothing about an earlier one.
//
// The non-blocking family needs a source that queues (`F_ASYNC`); against
// one that does not, every call of it answers `ENOSYS`. It never falls back
// to `EXEC`, which may wait. Every source in this tree that can sit under a
// provider answering inside a step reports `F_ASYNC`: nvme, `file_block`,
// `crypt_block` and `sd`.

use crate::*;

/// Writes one client keeps in flight at most, and reads likewise.
pub const BLK_CLIENT_SLOTS: usize = 32;

/// Tag bit marking a completion as the client's own `FLUSH`. The rest of
/// the tag is the write sequence the flush covers.
pub const BLK_FLUSH_TAG: u64 = 1 << 63;

/// Tag bit marking a completion as a caller-tagged read.
pub const BLK_READ_TAG: u64 = 1 << 62;

/// Largest tag a caller may give `submit_read`.
pub const BLK_READ_TAG_MAX: u64 = BLK_READ_TAG - 1;

/// The cookie of the client's one lend to its source.
pub const BLK_LEND_COOKIE: u32 = 1;

/// Failed write sequences remembered exactly. Past this many, every write
/// at or after the first failure reads as failed.
pub const BLK_FAILED_SLOTS: usize = 4;

/// State for one block source, zero-initialisable in a module's state.
#[repr(C)]
pub struct BlockClient {
    /// The handle bound to the source through `port`, or -1 until the
    /// first call binds it.
    pub handle: core::cell::Cell<i32>,
    /// The lend of `region` to the source, or -1 until a queued request
    /// first needs it.
    pub lend: core::cell::Cell<i32>,
    /// Start and length of the memory every queued request's buffer lies
    /// in; length 0 lends nothing (an `EXEC`-only consumer).
    pub region: usize,
    pub region_len: usize,
    /// The consumer's input port the source is wired to.
    pub port: u8,
    pub _pad0: [u8; 7],
    /// Logical block size from `DESCRIBE`; 0 until asked. The description
    /// fields are learned on first use, from paths that only read the
    /// client.
    pub lbs: core::cell::Cell<u32>,
    pub max_blocks: core::cell::Cell<u32>,
    pub block_count: core::cell::Cell<u64>,
    pub flags: core::cell::Cell<u32>,
    pub queue_depth: core::cell::Cell<u16>,
    pub _pad: [u8; 6],
    pub device_id: core::cell::Cell<u64>,
    /// Sequence of the last write submitted; the first is 1.
    pub next_seq: u64,
    /// Sequence of each write in flight; 0 = free.
    pub outstanding: [u64; BLK_CLIENT_SLOTS],
    /// Lowest sequence that completed with an error; 0 = none.
    pub first_fail: u64,
    /// Failed sequences, exactly, while they fit.
    pub failed: [u64; BLK_FAILED_SLOTS],
    /// More writes failed than `failed` holds.
    pub failed_overflow: u8,
    pub _pad1: [u8; 1],
    /// Caller-tagged reads submitted and not yet reaped.
    pub reads_inflight: u16,
    /// Reaped read completions not yet taken: `done_len` entries from
    /// `done_head`, ring of `BLK_CLIENT_SLOTS`.
    pub done_head: u16,
    pub done_len: u16,
    /// Sequence a `FLUSH` in flight covers; 0 = none in flight.
    pub flush_inflight: u64,
    /// Highest sequence a completed `FLUSH` proved durable.
    pub flush_done: u64,
    /// A `FLUSH` failed: no fence may report durable again.
    pub flush_err: i32,
    pub _pad2: [u8; 4],
    pub done_tag: [u64; BLK_CLIENT_SLOTS],
    pub done_status: [i32; BLK_CLIENT_SLOTS],
}

impl BlockClient {
    /// Point the client at the source wired to input port `port`, with
    /// every queued request's buffer inside `region[..region_len]`, and
    /// forget everything it knew. Nothing is called until first use.
    ///
    /// # Safety
    /// `region[..region_len]` is this module's own memory and stays so,
    /// unmoved, for the module's life: the source may write it whenever a
    /// request naming it is in flight.
    pub unsafe fn bind(&mut self, port: u8, region: *mut u8, region_len: usize) {
        // SAFETY: every field is an integer, a cell of one, or an array of
        // them; all-zero is the empty client.
        unsafe { core::ptr::write_bytes(self as *mut BlockClient, 0, 1) };
        self.handle.set(-1);
        self.lend.set(-1);
        self.port = port;
        self.region = region as usize;
        self.region_len = region_len;
    }

    /// Close the lend and the bound handle and forget everything the client
    /// knew, keeping its port and region: the next call binds afresh and
    /// asks the source's description again.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with; no
    /// request of this client may be in flight.
    pub unsafe fn reset(&mut self, sys: &SyscallTable) {
        if self.lend.get() >= 0 {
            dev_lend_close(sys, self.lend.get());
        }
        if self.handle.get() >= 0 {
            (sys.provider_close)(self.handle.get());
        }
        let (port, region, len) = (self.port, self.region as *mut u8, self.region_len);
        self.bind(port, region, len);
    }

    /// The bound handle, binding it on first use. `ENODEV` while the port is
    /// not wired, `ENOSYS` when the module there serves no `storage.block`.
    unsafe fn session(&self, sys: &SyscallTable) -> Result<i32, i32> {
        let h = self.handle.get();
        if h >= 0 {
            return Ok(h);
        }
        let h = dev_bind_port(
            sys,
            abi::registry::storage_block::ID,
            abi::kernel_abi::bind::PORT_IN,
            self.port,
        );
        if h < 0 {
            return Err(h);
        }
        self.handle.set(h);
        Ok(h)
    }

    /// The bound handle with the region lent on it, lending it on first use.
    unsafe fn lent(&self, sys: &SyscallTable) -> Result<i32, i32> {
        let h = self.session(sys)?;
        if self.lend.get() >= 0 {
            return Ok(h);
        }
        if self.region_len == 0 {
            return Err(E_INVAL);
        }
        let l = dev_lend_open(
            sys,
            h,
            LEND_INOUT,
            BLK_LEND_COOKIE,
            self.region as *mut u8,
            self.region_len,
        );
        if l < 0 {
            return Err(l);
        }
        self.lend.set(l);
        Ok(h)
    }

    /// The offset of `buf[..len]` inside the lent region, when it lies
    /// wholly inside it.
    pub fn offset_of(&self, buf: *const u8, len: u32) -> Option<u32> {
        let off = (buf as usize).checked_sub(self.region)?;
        let end = off.checked_add(len as usize)?;
        if end > self.region_len {
            return None;
        }
        u32::try_from(off).ok()
    }

    /// Queue one encoded request through the bound handle with the region
    /// lent.
    unsafe fn submit_raw(
        &self,
        sys: &SyscallTable,
        r: &abi::contracts::storage::block::Req,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let h = match self.lent(sys) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let mut rb = [0u8; blk::req::LEN];
        r.encode(&mut rb);
        dev_call(
            sys,
            h,
            abi::registry::storage_block::SUBMIT,
            rb.as_mut_ptr(),
            rb.len(),
        )
    }

    /// One `REAP` through the bound handle into `cb`.
    unsafe fn reap_raw(
        &self,
        sys: &SyscallTable,
        cb: &mut [u8; abi::contracts::storage::block::cpl::LEN],
    ) -> i32 {
        let h = match self.session(sys) {
            Ok(h) => h,
            Err(e) => return e,
        };
        dev_call(
            sys,
            h,
            abi::registry::storage_block::REAP,
            cb.as_mut_ptr(),
            cb.len(),
        )
    }

    pub fn has(&self, f: u32) -> bool {
        self.flags.get() & f != 0
    }

    /// The source's logical block size, once `describe` has answered.
    pub fn block_size(&self) -> u32 {
        self.lbs.get()
    }

    /// Most blocks one request may carry, once `describe` has answered.
    pub fn max_blocks(&self) -> u32 {
        self.max_blocks.get()
    }

    /// Blocks the source addresses, once `describe` has answered.
    pub fn block_count(&self) -> u64 {
        self.block_count.get()
    }

    /// The device the source's `LocalDurable` fences name.
    pub fn device_id(&self) -> u64 {
        self.device_id.get()
    }

    /// The source's capability flags, once `describe` has answered.
    pub fn flags(&self) -> u32 {
        self.flags.get()
    }

    /// Whether the source queues requests (`F_ASYNC`), once `describe` has
    /// answered. Without it the non-blocking calls answer `ENOSYS`.
    pub fn is_async(&self) -> bool {
        self.has(abi::contracts::storage::block::describe::F_ASYNC)
    }

    /// Ask the source for its description once. Returns 0, `EAGAIN` while
    /// the device attaches, or the source's error (`ENOSYS` from a source
    /// that does not speak this contract).
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn describe(&self, sys: &SyscallTable) -> i32 {
        use abi::contracts::storage::block as blk;
        if self.lbs.get() != 0 {
            return 0;
        }
        let h = match self.session(sys) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let mut buf = [0u8; blk::describe::LEN];
        let rc = dev_call(
            sys,
            h,
            abi::registry::storage_block::DESCRIBE,
            buf.as_mut_ptr(),
            blk::describe::LEN,
        );
        if rc < 0 {
            return rc;
        }
        let Some(c) = blk::Description::decode(&buf) else {
            return E_INVAL;
        };
        self.max_blocks.set(c.max_blocks);
        self.block_count.set(c.block_count);
        self.device_id.set(c.device_id);
        self.flags.set(c.flags);
        self.queue_depth.set(c.queue_depth);
        self.lbs.set(c.logical_block_size);
        0
    }

    /// Requests the source holds in flight, once `describe` has answered.
    pub fn queue_depth(&self) -> u16 {
        self.queue_depth.get()
    }

    /// Queue one request the caller built and tagged. Returns 0 when queued,
    /// `EAGAIN` when the source's queue is full, or the source's refusal.
    ///
    /// The client does not track caller-tagged requests: a consumer that
    /// submits them collects its completions with [`BlockClient::reap_one`].
    /// [`BlockClient::reap`] would take them and drop every tag it does not
    /// know, so the two styles do not share one client.
    ///
    /// A data request's buffer is `[r.offset..][..r.buf_len]` of the region
    /// given at [`BlockClient::bind`] ([`BlockClient::offset_of`]), and
    /// `r.lend` is [`BLK_LEND_COOKIE`].
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// The buffer `r` names is the source's until its completion is reaped.
    pub unsafe fn submit(
        &self,
        sys: &SyscallTable,
        r: &abi::contracts::storage::block::Req,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        if !self.has(blk::describe::F_ASYNC) {
            return E_NOSYS;
        }
        self.submit_raw(sys, r)
    }

    /// Hand back one finished completion of a caller-tagged request into
    /// `out`. Returns 1 when one was written, 0 when none is ready, or a
    /// negative errno.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn reap_one(
        &self,
        sys: &SyscallTable,
        out: &mut abi::contracts::storage::block::Cpl,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let mut cb = [0u8; blk::cpl::LEN];
        let rc = self.reap_raw(sys, &mut cb);
        if rc != 1 {
            return rc;
        }
        match blk::Cpl::decode(&cb) {
            Some(c) => {
                *out = c;
                1
            }
            None => E_INVAL,
        }
    }

    /// Run one request to completion over `data[..r.buf_len]` (null for an
    /// op without a buffer). Returns its status. May wait on the device: not
    /// for a provider answering inside a caller's step.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// `data` must be valid for `r.buf_len` bytes for the call.
    pub unsafe fn exec(
        &self,
        sys: &SyscallTable,
        r: &abi::contracts::storage::block::Req,
        data: *mut u8,
    ) -> i32 {
        let mut c = abi::contracts::storage::block::Cpl::bare(r.tag, 0);
        self.exec_cpl(sys, r, data, &mut c)
    }

    /// As [`BlockClient::exec`], with the completion written to `out` when
    /// the source answered one.
    ///
    /// # Safety
    /// As [`BlockClient::exec`].
    pub unsafe fn exec_cpl(
        &self,
        sys: &SyscallTable,
        r: &abi::contracts::storage::block::Req,
        data: *mut u8,
        out: &mut abi::contracts::storage::block::Cpl,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        let h = match self.session(sys) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let mut buf = [0u8; blk::exec::ARG_LEN];
        let mut req = *r;
        req.lend = 0;
        req.offset = 0;
        req.encode(&mut buf);
        let len = if data.is_null() {
            0
        } else {
            r.buf_len as usize
        };
        let rc = dev_call_data(
            sys,
            h,
            abi::registry::storage_block::EXEC,
            buf.as_mut_ptr(),
            buf.len(),
            data,
            len,
        );
        if rc < 0 {
            return rc;
        }
        match blk::Cpl::decode(&buf[blk::exec::CPL..]) {
            Some(c) => {
                *out = c;
                c.status
            }
            None => E_INVAL,
        }
    }

    /// A request over `len` bytes at `offset` in the client's lend (none
    /// when `len` is 0).
    pub fn data_req(
        op: u8,
        flags: u8,
        lba: u64,
        nblocks: u32,
        offset: u32,
        len: u32,
        tag: u64,
    ) -> abi::contracts::storage::block::Req {
        abi::contracts::storage::block::Req {
            op,
            flags,
            nblocks,
            lba,
            lend: if len == 0 { 0 } else { BLK_LEND_COOKIE },
            offset: if len == 0 { 0 } else { offset },
            buf_len: len,
            tag,
        }
    }

    /// A request for `EXEC`, whose buffer is the call's data span.
    pub fn exec_req(
        op: u8,
        flags: u8,
        lba: u64,
        nblocks: u32,
        len: u32,
    ) -> abi::contracts::storage::block::Req {
        abi::contracts::storage::block::Req {
            op,
            flags,
            nblocks,
            lba,
            lend: 0,
            offset: 0,
            buf_len: len,
            tag: 0,
        }
    }

    /// Read `nblocks` blocks at `lba` into `buf` through `EXEC`, which may
    /// wait on the device.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// `buf` must be writable for `nblocks` logical blocks.
    pub unsafe fn read(&self, sys: &SyscallTable, lba: u64, nblocks: u32, buf: *mut u8) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        let len = nblocks.saturating_mul(self.lbs.get());
        self.exec(
            sys,
            &Self::exec_req(blk::op::READ, 0, lba, nblocks, len),
            buf,
        )
    }

    /// Ask the source to stream `nblocks` blocks from `lba` onto the edge's
    /// channel (`READ_STREAM`): the next bytes it writes there are those
    /// blocks, in order. No buffer is named and nothing is lent.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn read_stream(&self, sys: &SyscallTable, lba: u64, nblocks: u32) -> i32 {
        use abi::contracts::storage::block as blk;
        let h = match self.session(sys) {
            Ok(h) => h,
            Err(e) => return e,
        };
        let mut rb = [0u8; blk::req::LEN];
        Self::data_req(blk::op::READ, 0, lba, nblocks, 0, 0, 0).encode(&mut rb);
        dev_call(
            sys,
            h,
            abi::registry::storage_block::READ_STREAM,
            rb.as_mut_ptr(),
            rb.len(),
        )
    }

    /// Write `nblocks` blocks at `lba` from `buf` through `EXEC`, which may
    /// wait on the device. `fua` makes the write durable before it
    /// completes.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// `buf` must be readable for `nblocks` logical blocks.
    pub unsafe fn write(
        &self,
        sys: &SyscallTable,
        lba: u64,
        nblocks: u32,
        buf: *const u8,
        fua: bool,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        let len = nblocks.saturating_mul(self.lbs.get());
        let flags = if fua { blk::F_FUA } else { 0 };
        self.exec(
            sys,
            &Self::exec_req(blk::op::WRITE, flags, lba, nblocks, len),
            buf as *mut u8,
        )
    }

    /// Flush the volatile cache through `EXEC`, which may wait on the
    /// device. Returns `EAGAIN` without flushing while a tracked write is
    /// still in flight: this reaps once and never spins on the device. For
    /// a consumer outside any step's deadline; inside one, use
    /// [`BlockClient::flush_submit`] / [`BlockClient::flush_poll`].
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn flush(&mut self, sys: &SyscallTable) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        self.reap(sys);
        if self.writes_in_flight() != 0 {
            return E_AGAIN;
        }
        if self.first_fail != 0 {
            return E_IO;
        }
        if !self.has(blk::describe::F_FLUSH) {
            return 0;
        }
        let rc = self.exec(
            sys,
            &Self::exec_req(blk::op::FLUSH, 0, 0, 0, 0),
            core::ptr::null_mut(),
        );
        if rc == 0 && self.next_seq > self.flush_done {
            self.flush_done = self.next_seq;
        }
        rc
    }

    pub fn writes_in_flight(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0usize;
        while i < BLK_CLIENT_SLOTS {
            if self.outstanding[i] != 0 {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Requests of this client the source holds right now.
    pub fn in_flight(&self) -> usize {
        self.writes_in_flight()
            + usize::from(self.reads_inflight)
            + usize::from(self.flush_inflight != 0)
    }

    /// Whether another request fits the source's queue now.
    pub fn queue_room(&self) -> bool {
        let depth = usize::from(self.queue_depth.get().max(1));
        self.in_flight() < depth
    }

    pub fn free_write_slot(&self) -> Option<usize> {
        let mut i = 0usize;
        while i < BLK_CLIENT_SLOTS {
            if self.outstanding[i] == 0 {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    pub fn note_write_failure(&mut self, seq: u64) {
        if self.first_fail == 0 || seq < self.first_fail {
            self.first_fail = seq;
        }
        let mut i = 0usize;
        while i < BLK_FAILED_SLOTS {
            if self.failed[i] == 0 {
                self.failed[i] = seq;
                return;
            }
            i += 1;
        }
        self.failed_overflow = 1;
    }

    /// Queue a tracked write (`op::WRITE`) or discard (`op::DISCARD`).
    pub unsafe fn submit_tracked(
        &mut self,
        sys: &SyscallTable,
        op: u8,
        lba: u64,
        nblocks: u32,
        buf: *const u8,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        let len = if op == blk::op::WRITE {
            nblocks.saturating_mul(self.lbs.get())
        } else {
            0
        };
        let offset = if op == blk::op::WRITE {
            match self.offset_of(buf, len) {
                Some(o) => o,
                None => return E_INVAL,
            }
        } else {
            0
        };
        if !self.has(blk::describe::F_ASYNC) {
            return E_NOSYS;
        }
        self.reap(sys);
        if !self.queue_room() {
            return E_AGAIN;
        }
        let Some(slot) = self.free_write_slot() else {
            return E_AGAIN;
        };
        let seq = self.next_seq + 1;
        let r = Self::data_req(op, 0, lba, nblocks, offset, len, seq);
        let rc = self.submit_raw(sys, &r);
        if rc == 0 {
            self.next_seq = seq;
            self.outstanding[slot] = seq;
        }
        rc
    }

    /// Queue a write of `nblocks` blocks at `lba` without waiting. Returns
    /// 0, or `EAGAIN` when nothing more can be in flight; its sequence is
    /// [`BlockClient::last_seq`] once it returns 0.
    ///
    /// `buf` lies in the region given at [`BlockClient::bind`]; `EINVAL`
    /// otherwise.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with. `buf`
    /// must stay unchanged until [`BlockClient::write_state`] stops
    /// reporting the write in flight — unless the source reports
    /// `F_WRITE_COPIES`, in which case it is free when this returns.
    pub unsafe fn submit_write(
        &mut self,
        sys: &SyscallTable,
        lba: u64,
        nblocks: u32,
        buf: *const u8,
    ) -> i32 {
        self.submit_tracked(
            sys,
            abi::contracts::storage::block::op::WRITE,
            lba,
            nblocks,
            buf,
        )
    }

    /// Queue a discard of `nblocks` blocks at `lba`, tracked and fenced like
    /// a write.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn submit_discard(&mut self, sys: &SyscallTable, lba: u64, nblocks: u32) -> i32 {
        self.submit_tracked(
            sys,
            abi::contracts::storage::block::op::DISCARD,
            lba,
            nblocks,
            core::ptr::null(),
        )
    }

    /// Sequence of the most recent tracked write or discard.
    pub fn last_seq(&self) -> u64 {
        self.next_seq
    }

    /// Where tracked write `seq` stands: 1 while in flight, 0 once it
    /// completed, `EIO` when it failed. Reflects completions reaped so far.
    pub fn write_state(&self, seq: u64) -> i32 {
        if seq == 0 {
            return 0;
        }
        let mut i = 0usize;
        while i < BLK_CLIENT_SLOTS {
            if self.outstanding[i] == seq {
                return 1;
            }
            i += 1;
        }
        let mut k = 0usize;
        while k < BLK_FAILED_SLOTS {
            if self.failed[k] == seq {
                return E_IO;
            }
            k += 1;
        }
        if self.failed_overflow != 0 && self.first_fail != 0 && seq >= self.first_fail {
            return E_IO;
        }
        0
    }

    /// Queue a read of `nblocks` blocks at `lba` into `buf` under `tag`
    /// (at most [`BLK_READ_TAG_MAX`]). Returns 0 when queued, `EAGAIN` when
    /// nothing more can be in flight, or the source's refusal. Its
    /// completion comes back through [`BlockClient::take_read`].
    ///
    /// `buf` lies in the region given at [`BlockClient::bind`]; `EINVAL`
    /// otherwise.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with. `buf`
    /// must stay unread by anyone else until `take_read` hands back this
    /// tag: the source writes it until then.
    pub unsafe fn submit_read(
        &mut self,
        sys: &SyscallTable,
        lba: u64,
        nblocks: u32,
        buf: *mut u8,
        tag: u64,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.describe(sys);
        if rc != 0 {
            return rc;
        }
        if tag > BLK_READ_TAG_MAX {
            return E_INVAL;
        }
        // Every read submitted ends up in the ring, so admitting it only
        // while the ring has room for it means the ring never overflows.
        if usize::from(self.reads_inflight) + usize::from(self.done_len) >= BLK_CLIENT_SLOTS {
            return E_AGAIN;
        }
        let len = nblocks.saturating_mul(self.lbs.get());
        let Some(offset) = self.offset_of(buf, len) else {
            return E_INVAL;
        };
        if !self.has(blk::describe::F_ASYNC) {
            return E_NOSYS;
        }
        self.reap(sys);
        if !self.queue_room() {
            return E_AGAIN;
        }
        let r = Self::data_req(
            blk::op::READ,
            0,
            lba,
            nblocks,
            offset,
            len,
            tag | BLK_READ_TAG,
        );
        let rc = self.submit_raw(sys, &r);
        if rc == 0 {
            self.reads_inflight += 1;
        }
        rc
    }

    pub fn push_done(&mut self, tag: u64, status: i32) {
        if usize::from(self.done_len) >= BLK_CLIENT_SLOTS {
            return;
        }
        let at = (usize::from(self.done_head) + usize::from(self.done_len)) % BLK_CLIENT_SLOTS;
        self.done_tag[at] = tag;
        self.done_status[at] = status;
        self.done_len += 1;
    }

    /// Take one finished read: `(tag, status)`. Call [`BlockClient::reap`]
    /// first to collect what the source has finished.
    pub fn take_read(&mut self) -> Option<(u64, i32)> {
        if self.done_len == 0 {
            return None;
        }
        let at = usize::from(self.done_head) % BLK_CLIENT_SLOTS;
        let out = (self.done_tag[at], self.done_status[at]);
        self.done_head = ((at + 1) % BLK_CLIENT_SLOTS) as u16;
        self.done_len -= 1;
        Some(out)
    }

    /// Reads submitted whose completion has not been taken yet.
    pub fn reads_pending(&self) -> usize {
        usize::from(self.reads_inflight) + usize::from(self.done_len)
    }

    /// Open a fence over every write submitted so far. Never touches the
    /// device.
    pub fn fence_open(&self) -> u64 {
        self.next_seq
    }

    /// Non-blocking flush: open a fence over every tracked write submitted
    /// so far. Its ticket is polled with [`BlockClient::flush_poll`].
    pub fn flush_submit(&self) -> u64 {
        self.fence_open()
    }

    /// Poll a fence from [`BlockClient::flush_submit`]. Never waits.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn flush_poll(&mut self, sys: &SyscallTable, ticket: u64) -> i32 {
        self.fence_poll(sys, ticket)
    }

    /// Poll a fence. Returns 0 when durable, 1 while pending, or a negative
    /// errno when it never can be. Never waits on the device: it reaps,
    /// and submits a `FLUSH` once every covered write has been reaped.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn fence_poll(&mut self, sys: &SyscallTable, ticket: u64) -> i32 {
        use abi::contracts::storage::block as blk;
        self.reap(sys);
        if self.first_fail != 0 && self.first_fail <= ticket {
            return E_IO;
        }
        let mut i = 0usize;
        while i < BLK_CLIENT_SLOTS {
            let s = self.outstanding[i];
            if s != 0 && s <= ticket {
                return 1;
            }
            i += 1;
        }
        if !self.has(blk::describe::F_FLUSH) {
            return 0;
        }
        if self.flush_err != 0 {
            return self.flush_err;
        }
        if self.flush_done >= ticket {
            return 0;
        }
        if self.flush_inflight != 0 {
            return 1;
        }
        // Every write up to the lowest one still in flight has been reaped,
        // so a flush submitted now covers them.
        let mut low = 0u64;
        let mut k = 0usize;
        while k < BLK_CLIENT_SLOTS {
            let s = self.outstanding[k];
            if s != 0 && (low == 0 || s < low) {
                low = s;
            }
            k += 1;
        }
        let covers = if low == 0 { self.next_seq } else { low - 1 };
        let r = Self::data_req(blk::op::FLUSH, 0, 0, 0, 0, 0, BLK_FLUSH_TAG | covers);
        if !self.has(blk::describe::F_ASYNC) {
            return E_NOSYS;
        }
        if !self.queue_room() {
            return 1;
        }
        let rc = self.submit_raw(sys, &r);
        if rc == 0 {
            self.flush_inflight = covers.max(1);
        } else if rc != E_AGAIN {
            self.flush_err = rc;
            return rc;
        }
        1
    }

    /// Collect every finished completion: tracked writes and the client's
    /// flushes are settled here, and caller-tagged reads are kept for
    /// [`BlockClient::take_read`].
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn reap(&mut self, sys: &SyscallTable) {
        use abi::contracts::storage::block as blk;
        if self.lbs.get() == 0 || !self.has(blk::describe::F_ASYNC) {
            return;
        }
        loop {
            let mut cb = [0u8; blk::cpl::LEN];
            let rc = self.reap_raw(sys, &mut cb);
            if rc != 1 {
                return;
            }
            let Some(c) = blk::Cpl::decode(&cb) else {
                return;
            };
            if c.tag & BLK_FLUSH_TAG != 0 {
                let covers = c.tag & !BLK_FLUSH_TAG;
                if c.status == 0 {
                    if covers > self.flush_done {
                        self.flush_done = covers;
                    }
                } else if self.flush_err == 0 {
                    self.flush_err = c.status;
                }
                self.flush_inflight = 0;
                continue;
            }
            if c.tag & BLK_READ_TAG != 0 {
                if self.reads_inflight > 0 {
                    self.reads_inflight -= 1;
                    self.push_done(c.tag & BLK_READ_TAG_MAX, c.status);
                }
                continue;
            }
            let mut i = 0usize;
            while i < BLK_CLIENT_SLOTS {
                if self.outstanding[i] == c.tag && c.tag != 0 {
                    self.outstanding[i] = 0;
                    if c.status != 0 {
                        self.note_write_failure(c.tag);
                    }
                    break;
                }
                i += 1;
            }
        }
    }
}

/// A source borrows a queued request's buffer: the bytes `r` names in the
/// lend its consumer opened on the session `handle` (the port reference the
/// source was handed), one borrow out. `EINVAL` for a range outside the
/// lend, `EACCES` for a lend whose direction does not let the op move its
/// bytes (a read writes the buffer, a write reads it), `ENOENT` for no such
/// lend. Every borrow is given back with [`blk_give_back`] before the
/// request's completion becomes reapable.
///
/// # Safety
/// `sys` must be the syscall table this module was started with.
pub unsafe fn blk_borrow(
    sys: &SyscallTable,
    handle: i32,
    r: &abi::contracts::storage::block::Req,
) -> Result<*mut u8, i32> {
    let Some((base, len, dir)) = dev_lend_resolve(sys, handle, r.lend) else {
        return Err(-2);
    };
    let need = if r.writes_buffer() { LEND_OUT } else { LEND_IN };
    let Some(range) = r.range_in(len) else {
        dev_lend_return(sys, handle, r.lend);
        return Err(E_INVAL);
    };
    if dir & need == 0 {
        dev_lend_return(sys, handle, r.lend);
        return Err(-13);
    }
    Ok(base.add(range.start))
}

/// Give back the borrow [`blk_borrow`] took for `r`.
///
/// # Safety
/// `sys` must be the syscall table this module was started with.
pub unsafe fn blk_give_back(
    sys: &SyscallTable,
    handle: i32,
    r: &abi::contracts::storage::block::Req,
) {
    dev_lend_return(sys, handle, r.lend);
}
