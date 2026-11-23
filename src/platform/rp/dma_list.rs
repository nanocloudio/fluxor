//! The RP DMA scan list: a cyclic sequence of transfers to one FIFO that the
//! DMA walks with no software in its timing.
//!
//! Three channels. The **data** channel moves each entry's units to the
//! FIFO. The **control** channel copies one four-word block per entry into
//! the data channel's `AL1` registers (`CTRL`, `READ_ADDR`, `WRITE_ADDR`,
//! `TRANS_COUNT_TRIG`), the last write starting the data channel; the data
//! channel chains back to the control channel for the next block. The last
//! entry's block chains instead to the **rewind** channel, which writes the
//! list's first block address into the control channel's
//! `AL3_READ_ADDR_TRIG` and so starts the list again.
//!
//! Every block of a list has the same `WRITE_ADDR` (the FIFO) and
//! `TRANS_COUNT`. An entry is **fill** (`READ_ADDR` the list's fill word,
//! `CTRL` without `INCR_READ`: the same unit sent `count` times) or
//! **armed** (`READ_ADDR` a span of the caller's lend, `CTRL` with
//! `INCR_READ`). The control channel reads a block's `CTRL` and then its
//! `READ_ADDR`, and the kernel changes a block while the scan runs, so the
//! one pair that must never be loaded is `INCR_READ` with the fill word's
//! address: `count` units read from past the fill word.
//!
//! - **Arming** writes `READ_ADDR`, then `CTRL`. A load that reads between
//!   the two sees the old `CTRL` (no increment) with the span's address: the
//!   span's first unit, `count` times. Never the forbidden pair, whatever
//!   the interleaving, because `CTRL` is read first and written last.
//! - **Disarming** writes `CTRL`, then waits while the control channel sits
//!   between this block's `CTRL` and its `READ_ADDR`, then writes
//!   `READ_ADDR`. A load that read the old `CTRL` has read the old
//!   `READ_ADDR` too by the time the second write lands; a load that starts
//!   after the first write reads the new `CTRL`, with which either address
//!   is sound.
//!
//! The scan's position is the control channel's read pointer, never a count
//! of interrupts: a late or coalesced interrupt accounts for every entry
//! passed since the last one, as long as the scan has gone less than once
//! round the list in between. The pointer says where in the list the scan
//! is, not how many laps it has made, so across a span with the owner's
//! interrupts masked for a lap or longer (a flash erase longer than a
//! refresh) whole laps are not counted: the position and the underruns
//! move on by the entries passed modulo the list's length.
//!
//! This file is the list's state and rules over a [`Bus`], with no register
//! in it, so a host test runs it against a model of the three channels.

/// Control blocks in the kernel's one table, shared by every list.
pub const POOL_BLOCKS: usize = 64;
/// Bytes in a block: the four `AL1` registers.
pub const BLOCK_BYTES: u32 = 16;

/// A block's words, in the order the control channel reads them.
pub mod word {
    pub const CTRL: usize = 0;
    pub const READ_ADDR: usize = 1;
    pub const WRITE_ADDR: usize = 2;
    pub const TRANS_COUNT: usize = 3;
}

/// The longest a disarm waits for the control channel to leave a block it
/// is in the middle of, in reads of its pointer. A block load is four
/// transfers at the bus's own pace; the bound is there so that nothing in
/// the kernel waits on hardware without an end.
pub const LOAD_SPINS: u32 = 4096;

/// What a list touches: the block table and the control channel's pointer.
pub trait Bus {
    /// Store `value` into word `word` of table block `block`.
    fn write(&mut self, block: usize, word: usize, value: u32);
    /// The control channel's read pointer, in bytes from the start of the
    /// table.
    fn control_offset(&mut self) -> u32;
}

/// What is the same for every block of a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The list's first block in the table, and its entries.
    pub first: u16,
    pub entries: u16,
    /// Every block's `WRITE_ADDR` (the FIFO) and `TRANS_COUNT` word.
    pub write_addr: u32,
    pub trans_count: u32,
    /// The address of the list's fill word.
    pub fill_addr: u32,
    /// `CTRL` of a fill block and of an armed one, chaining to the control
    /// channel.
    pub ctrl_fill: u32,
    pub ctrl_armed: u32,
    /// The same for the last entry, chaining to the rewind channel.
    pub ctrl_fill_last: u32,
    pub ctrl_armed_last: u32,
}

/// Why an entry was not armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmError {
    /// No such entry.
    NoEntry,
    /// The entry is armed already, is being sent, or is the next to be
    /// loaded.
    Busy,
}

/// One running list.
#[derive(Clone, Copy, Debug)]
pub struct List {
    shape: Shape,
    /// A bit per armed entry.
    armed: u64,
    /// The entry the scan was at when it was last accounted for.
    at: u16,
    /// Entries sent since the list started, and those sent as fill.
    position: u32,
    underruns: u32,
    /// `position` as the owner last read it.
    reported: u32,
}

impl List {
    /// Whether a list of `entries` can run: at least the contract's minimum,
    /// below which no entry could ever be armed (see [`List::arm`]), and no
    /// more than the table holds.
    pub const fn fits(entries: u16) -> bool {
        entries >= crate::abi::platform::rp::dma_raw::list_start::MIN_ENTRIES
            && entries as usize <= POOL_BLOCKS
    }

    /// Write every block of a list as fill and return the list, its scan at
    /// entry 0. The channels are not running yet.
    pub fn start(shape: Shape, bus: &mut impl Bus) -> Self {
        let list = Self {
            shape,
            armed: 0,
            at: 0,
            position: 0,
            underruns: 0,
            reported: 0,
        };
        for entry in 0..shape.entries {
            let block = list.block(entry);
            bus.write(block, word::WRITE_ADDR, shape.write_addr);
            bus.write(block, word::TRANS_COUNT, shape.trans_count);
            bus.write(block, word::READ_ADDR, shape.fill_addr);
            bus.write(block, word::CTRL, list.ctrl(entry, false));
        }
        list
    }

    /// The list's shape.
    pub const fn shape(&self) -> &Shape {
        &self.shape
    }

    /// The table block of `entry`.
    const fn block(&self, entry: u16) -> usize {
        (self.shape.first + entry) as usize
    }

    /// The `CTRL` word of `entry`, armed or fill.
    const fn ctrl(&self, entry: u16, armed: bool) -> u32 {
        let last = entry + 1 == self.shape.entries;
        match (armed, last) {
            (false, false) => self.shape.ctrl_fill,
            (true, false) => self.shape.ctrl_armed,
            (false, true) => self.shape.ctrl_fill_last,
            (true, true) => self.shape.ctrl_armed_last,
        }
    }

    const fn next(&self, entry: u16) -> u16 {
        if entry + 1 == self.shape.entries {
            0
        } else {
            entry + 1
        }
    }

    /// The entry the scan is at, from the control channel's pointer: the
    /// one being loaded if the pointer is inside a block, else the one last
    /// loaded, which the data channel is sending. With the pointer at the
    /// list's first block nothing of this lap is loaded yet and entry 0 is
    /// the one about to be.
    pub const fn scan_at(&self, control_offset: u32) -> u16 {
        let rel = control_offset.wrapping_sub(self.shape.first as u32 * BLOCK_BYTES);
        let block = rel / BLOCK_BYTES;
        let inside = !rel.is_multiple_of(BLOCK_BYTES);
        let entries = self.shape.entries as u32;
        let entry = if inside {
            block % entries
        } else if block == 0 {
            0
        } else {
            (block - 1) % entries
        };
        entry as u16
    }

    /// Account for the entries the scan has passed since this last ran,
    /// modulo the list's length (whole laps gone by unseen are not counted):
    /// each armed one returns to fill, each fill one is an underrun, and
    /// the position moves on by their number. Called with the owner's
    /// interrupts masked, from the data channel's interrupt and before any
    /// rule that depends on where the scan is.
    pub fn advance(&mut self, bus: &mut impl Bus) {
        let now = self.scan_at(bus.control_offset());
        let entries = self.shape.entries;
        let passed = (now + entries - self.at) % entries;
        let mut entry = self.at;
        for _ in 0..passed {
            if self.armed & (1 << entry) != 0 {
                self.disarm(bus, entry);
            } else {
                self.underruns = self.underruns.wrapping_add(1);
            }
            entry = self.next(entry);
        }
        self.position = self.position.wrapping_add(u32::from(passed));
        self.at = now;
    }

    /// Arm `entry` to send from `read_addr` the next time the scan reaches
    /// it. The caller has checked the span lies inside the owner's lend,
    /// and holds the owner's interrupts masked.
    pub fn arm(&mut self, bus: &mut impl Bus, entry: u16, read_addr: u32) -> Result<(), ArmError> {
        if entry >= self.shape.entries {
            return Err(ArmError::NoEntry);
        }
        self.advance(bus);
        if self.armed & (1 << entry) != 0 || entry == self.at || entry == self.next(self.at) {
            return Err(ArmError::Busy);
        }
        let block = self.block(entry);
        // The address first, the control word last: a load between the two
        // sends the span's first unit `count` times.
        bus.write(block, word::READ_ADDR, read_addr);
        bus.write(block, word::CTRL, self.ctrl(entry, true));
        self.armed |= 1 << entry;
        Ok(())
    }

    /// Return `entry` to fill.
    fn disarm(&mut self, bus: &mut impl Bus, entry: u16) {
        let block = self.block(entry);
        bus.write(block, word::CTRL, self.ctrl(entry, false));
        // A load that read the armed control word reads the span's address
        // with it: the fill address is not written while the control
        // channel is between the two.
        let between = block as u32 * BLOCK_BYTES + BLOCK_BYTES / 4;
        let mut spins = 0;
        while bus.control_offset() == between && spins < LOAD_SPINS {
            spins += 1;
        }
        bus.write(block, word::READ_ADDR, self.shape.fill_addr);
        self.armed &= !(1 << entry);
    }

    /// Return every armed entry to fill: before the owner's core holds its
    /// interrupts for longer than the scan takes to come round, when no
    /// interrupt would return a sent entry to fill and it would be sent
    /// again a lap later.
    pub fn disarm_all(&mut self, bus: &mut impl Bus) {
        for entry in 0..self.shape.entries {
            if self.armed & (1 << entry) != 0 {
                self.disarm(bus, entry);
            }
        }
    }

    /// `(position, underruns)`, brought up to the scan, and remembered as
    /// what the owner has seen.
    pub fn status(&mut self, bus: &mut impl Bus) -> (u32, u32) {
        self.advance(bus);
        self.reported = self.position;
        (self.position, self.underruns)
    }

    /// Whether entries have been sent since the owner last read the status.
    pub const fn ready(&self) -> bool {
        self.position != self.reported
    }

    /// Whether `entry` is armed.
    pub const fn is_armed(&self, entry: u16) -> bool {
        entry < self.shape.entries && self.armed & (1 << entry) != 0
    }
}

/// The table's free blocks, a bit per block; a list takes a run of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pool {
    used: u64,
}

impl Pool {
    pub const fn new() -> Self {
        Self { used: 0 }
    }

    /// A run of `entries` consecutive free blocks, taken; `None` when the
    /// table has none that long.
    pub fn take(&mut self, entries: u16) -> Option<u16> {
        let n = entries as usize;
        if n == 0 || n > POOL_BLOCKS {
            return None;
        }
        let run = if n == POOL_BLOCKS {
            u64::MAX
        } else {
            (1u64 << n) - 1
        };
        let mut first = 0;
        while first + n <= POOL_BLOCKS {
            if self.used & (run << first) == 0 {
                self.used |= run << first;
                return Some(first as u16);
            }
            first += 1;
        }
        None
    }

    /// Give back the run `take` returned.
    pub fn give(&mut self, first: u16, entries: u16) {
        let n = entries as usize;
        let run = if n >= POOL_BLOCKS {
            u64::MAX
        } else {
            (1u64 << n) - 1
        };
        self.used &= !(run << first);
    }
}
