// ============================================================================
// storage.block client
// ============================================================================
//
// The consumer half of `abi::contracts::storage::block`: synchronous
// requests through `EXEC`, pipelined writes through `SUBMIT`/`REAP`, and
// durability fences built from them. A consumer that keeps requests of every
// op in flight under its own tags (a device frontend) uses `submit` /
// `reap_one` instead of the write pipeline.
//
// A fence names every write submitted before it opened. It is durable once
// each of those writes has completed without error and, on a source with a
// volatile write cache, a `FLUSH` submitted after they were all reaped has
// completed. Completions arrive in any order, so the client tracks the
// individual writes in flight rather than a count: a later write finishing
// first proves nothing about an earlier one.

/// Writes one client keeps in flight at most.
pub const BLK_CLIENT_SLOTS: usize = 32;

/// Tag bit marking a completion as the client's own `FLUSH`. The rest of
/// the tag is the write sequence the flush covers.
const BLK_FLUSH_TAG: u64 = 1 << 63;

/// Rounds `flush_sync` spends reaping before reporting `EAGAIN`.
const BLK_DRAIN_ROUNDS: u32 = 1 << 20;

/// State for one block source, zero-initialisable in a module's state.
#[repr(C)]
pub struct BlockClient {
    /// The `blocks` channel, or -1.
    pub chan: i32,
    /// Logical block size from `CAPS`; 0 until asked. The capability
    /// fields are learned on first use, from paths that only read the
    /// client.
    lbs: core::cell::Cell<u32>,
    max_blocks: core::cell::Cell<u32>,
    block_count: core::cell::Cell<u64>,
    flags: core::cell::Cell<u32>,
    queue_depth: core::cell::Cell<u16>,
    _pad: [u8; 6],
    device_id: core::cell::Cell<u64>,
    /// Sequence of the last write submitted; the first is 1.
    next_seq: u64,
    /// Sequence of each write in flight; 0 = free.
    outstanding: [u64; BLK_CLIENT_SLOTS],
    /// Lowest sequence that completed with an error; 0 = none.
    first_fail: u64,
    /// Sequence a `FLUSH` in flight covers; 0 = none in flight.
    flush_inflight: u64,
    /// Highest sequence a completed `FLUSH` proved durable.
    flush_done: u64,
    /// A `FLUSH` failed: no fence may report durable again.
    flush_err: i32,
    _pad2: [u8; 4],
}

impl BlockClient {
    /// Point the client at `chan` and forget everything it knew.
    pub fn bind(&mut self, chan: i32) {
        // SAFETY: every field is an integer or an array of them; all-zero
        // is the empty client.
        unsafe { core::ptr::write_bytes(self as *mut BlockClient, 0, 1) };
        self.chan = chan;
    }

    fn has(&self, f: u32) -> bool {
        self.flags.get() & f != 0
    }

    /// The source's logical block size, once `caps` has answered.
    pub fn block_size(&self) -> u32 {
        self.lbs.get()
    }

    /// Most blocks one request may carry, once `caps` has answered.
    pub fn max_blocks(&self) -> u32 {
        self.max_blocks.get()
    }

    /// Blocks the source addresses, once `caps` has answered.
    pub fn block_count(&self) -> u64 {
        self.block_count.get()
    }

    /// The device the source's `LocalDurable` fences name.
    pub fn device_id(&self) -> u64 {
        self.device_id.get()
    }

    /// The source's capability flags, once `caps` has answered.
    pub fn flags(&self) -> u32 {
        self.flags.get()
    }

    /// Ask the source for its capabilities once. Returns 0, `EAGAIN` while
    /// the device attaches, or the source's error (`ENOSYS` from a source
    /// that does not speak this contract).
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn caps(&self, sys: &SyscallTable) -> i32 {
        use abi::contracts::storage::block as blk;
        if self.lbs.get() != 0 {
            return 0;
        }
        let mut buf = [0u8; blk::caps::LEN];
        let rc = dev_channel_ioctl(
            sys,
            self.chan,
            blk::ioctl::CAPS,
            buf.as_mut_ptr(),
            blk::caps::LEN,
        );
        if rc < 0 {
            return rc;
        }
        let Some(c) = blk::Caps::decode(&buf) else {
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

    /// Requests the source holds in flight, once `caps` has answered.
    pub fn queue_depth(&self) -> u16 {
        self.queue_depth.get()
    }

    /// Queue one request the caller built and tagged. Returns 0 when queued,
    /// `EAGAIN` when the source's queue is full, or the source's refusal.
    ///
    /// The client does not track caller-tagged requests: a consumer that
    /// submits them collects its completions with [`BlockClient::reap_one`].
    /// [`BlockClient::reap`] would take them and discard every tag it does
    /// not know, so the two styles do not share one client.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// The buffer `r` names must stay valid, and unmoved, until its
    /// completion is reaped: the source may use it until then.
    pub unsafe fn submit(
        &self,
        sys: &SyscallTable,
        r: &abi::contracts::storage::block::Req,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        if !self.has(blk::caps::F_ASYNC) {
            return E_NOSYS;
        }
        let mut rb = [0u8; blk::req::LEN];
        r.encode(&mut rb);
        dev_channel_ioctl(
            sys,
            self.chan,
            blk::ioctl::SUBMIT,
            rb.as_mut_ptr(),
            rb.len(),
        )
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
        let rc = dev_channel_ioctl(sys, self.chan, blk::ioctl::REAP, cb.as_mut_ptr(), cb.len());
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

    /// Run one request to completion. Returns its status.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// The buffer `r` names must be valid for its length for the call.
    pub unsafe fn exec(&self, sys: &SyscallTable, r: &abi::contracts::storage::block::Req) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        let mut buf = [0u8; blk::req::LEN + blk::cpl::LEN];
        r.encode(&mut buf);
        let rc = dev_channel_ioctl(
            sys,
            self.chan,
            blk::ioctl::EXEC,
            buf.as_mut_ptr(),
            buf.len(),
        );
        if rc < 0 {
            return rc;
        }
        match blk::Cpl::decode(&buf[blk::req::LEN..]) {
            Some(c) => c.status,
            None => E_INVAL,
        }
    }

    fn data_req(
        op: u8,
        flags: u8,
        lba: u64,
        nblocks: u32,
        buf: u64,
        len: u32,
        tag: u64,
    ) -> abi::contracts::storage::block::Req {
        abi::contracts::storage::block::Req {
            op,
            flags,
            nblocks,
            lba,
            buf_ptr: buf,
            buf_len: len,
            tag,
        }
    }

    /// Read `nblocks` blocks at `lba` into `buf`, which holds exactly
    /// `nblocks * lbs` bytes.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// `buf` must be writable for `nblocks` logical blocks.
    pub unsafe fn read(&self, sys: &SyscallTable, lba: u64, nblocks: u32, buf: *mut u8) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        let len = nblocks.saturating_mul(self.lbs.get());
        self.exec(
            sys,
            &Self::data_req(blk::op::READ, 0, lba, nblocks, buf as u64, len, 0),
        )
    }

    /// Write `nblocks` blocks at `lba` from `buf` and wait for completion.
    /// `fua` makes the write durable before it completes.
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
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        let len = nblocks.saturating_mul(self.lbs.get());
        let flags = if fua { blk::F_FUA } else { 0 };
        self.exec(
            sys,
            &Self::data_req(blk::op::WRITE, flags, lba, nblocks, buf as u64, len, 0),
        )
    }

    /// Make every write submitted so far durable: wait for the pipelined
    /// ones, then flush the volatile cache if the source has one.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn flush(&mut self, sys: &SyscallTable) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        let mut rounds = 0u32;
        while self.in_flight() != 0 {
            self.reap(sys);
            rounds += 1;
            if rounds >= BLK_DRAIN_ROUNDS {
                return E_AGAIN;
            }
        }
        if self.first_fail != 0 {
            return E_IO;
        }
        if !self.has(blk::caps::F_FLUSH) {
            return 0;
        }
        let rc = self.exec(sys, &Self::data_req(blk::op::FLUSH, 0, 0, 0, 0, 0, 0));
        if rc == 0 && self.next_seq > self.flush_done {
            self.flush_done = self.next_seq;
        }
        rc
    }

    fn in_flight(&self) -> usize {
        self.outstanding.iter().filter(|&&s| s != 0).count()
    }

    /// Queue a write of `nblocks` blocks at `lba` without waiting. The
    /// source copies `buf` before returning. Returns 0, or `EAGAIN` when
    /// nothing more can be in flight.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    /// `buf` must be readable for `nblocks` logical blocks for the call; the
    /// source copies it before returning.
    pub unsafe fn submit_write(
        &mut self,
        sys: &SyscallTable,
        lba: u64,
        nblocks: u32,
        buf: *const u8,
    ) -> i32 {
        use abi::contracts::storage::block as blk;
        let rc = self.caps(sys);
        if rc != 0 {
            return rc;
        }
        if !self.has(blk::caps::F_ASYNC) || !self.has(blk::caps::F_WRITE_COPIES) {
            return E_NOSYS;
        }
        self.reap(sys);
        let limit = (self.queue_depth.get() as usize).min(BLK_CLIENT_SLOTS);
        if self.in_flight() >= limit {
            return E_AGAIN;
        }
        let Some(slot) = self.outstanding.iter().position(|&s| s == 0) else {
            return E_AGAIN;
        };
        let seq = self.next_seq + 1;
        let len = nblocks.saturating_mul(self.lbs.get());
        let r = Self::data_req(blk::op::WRITE, 0, lba, nblocks, buf as u64, len, seq);
        let mut rb = [0u8; blk::req::LEN];
        r.encode(&mut rb);
        let rc = dev_channel_ioctl(
            sys,
            self.chan,
            blk::ioctl::SUBMIT,
            rb.as_mut_ptr(),
            rb.len(),
        );
        if rc == 0 {
            self.next_seq = seq;
            self.outstanding[slot] = seq;
        }
        rc
    }

    /// Open a fence over every write submitted so far.
    pub fn fence_open(&self) -> u64 {
        self.next_seq
    }

    /// Poll a fence. Returns 0 when durable, 1 while pending, or a negative
    /// errno when it never can be.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn fence_poll(&mut self, sys: &SyscallTable, ticket: u64) -> i32 {
        use abi::contracts::storage::block as blk;
        self.reap(sys);
        if self.first_fail != 0 && self.first_fail <= ticket {
            return E_IO;
        }
        if self.outstanding.iter().any(|&s| s != 0 && s <= ticket) {
            return 1;
        }
        if !self.has(blk::caps::F_FLUSH) {
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
        let covers = match self.outstanding.iter().filter(|&&s| s != 0).min() {
            Some(&low) => low - 1,
            None => self.next_seq,
        };
        let r = Self::data_req(blk::op::FLUSH, 0, 0, 0, 0, 0, BLK_FLUSH_TAG | covers);
        let mut rb = [0u8; blk::req::LEN];
        r.encode(&mut rb);
        let rc = dev_channel_ioctl(
            sys,
            self.chan,
            blk::ioctl::SUBMIT,
            rb.as_mut_ptr(),
            rb.len(),
        );
        if rc == 0 {
            self.flush_inflight = covers.max(1);
        } else if rc != E_AGAIN {
            self.flush_err = rc;
            return rc;
        }
        1
    }

    /// Collect every finished completion.
    ///
    /// # Safety
    /// `sys` must be the syscall table this module was started with.
    pub unsafe fn reap(&mut self, sys: &SyscallTable) {
        use abi::contracts::storage::block as blk;
        loop {
            let mut cb = [0u8; blk::cpl::LEN];
            let rc = dev_channel_ioctl(sys, self.chan, blk::ioctl::REAP, cb.as_mut_ptr(), cb.len());
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
            if let Some(slot) = self.outstanding.iter().position(|&s| s == c.tag) {
                self.outstanding[slot] = 0;
                if c.status != 0 && (self.first_fail == 0 || c.tag < self.first_fail) {
                    self.first_fail = c.tag;
                }
            }
        }
    }
}
