// Placing exchange records on a port without losing one.
//
// A response cannot be un-built, and `channel_write` on an edge with no room
// places nothing and says so. Letting that drop the record answers a request
// with silence: the caller waits out its own timeout and the only evidence is a
// connection that went quiet, indistinguishable from a hung provider. Every
// refusal to write is therefore a reason to HOLD, and the step loop retries
// before it reads anything else — which is what makes the listener's
// back-pressure reach the place that governs the exchange instead of being
// absorbed as a lost answer.

/// One outbound record staged and not yet placed on its port.
///
/// The bytes live in the caller's own buffer; this holds only how many of them
/// are owed. A second record offered while one is held would overwrite it, so
/// [`ExchangeOutbox::send`] refuses instead — and says so by returning false,
/// the same answer as "held", because in both cases the record has not left.
#[derive(Clone, Copy, Default)]
pub struct ExchangeOutbox {
    len: usize,
}

impl ExchangeOutbox {
    pub const fn new() -> Self {
        Self { len: 0 }
    }

    /// Whether a record is held.
    pub const fn holding(&self) -> bool {
        self.len != 0
    }

    /// Place `len` bytes of `buf` now, or hold them for the step loop to retry.
    /// True when the record is away, false when it is owed.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI, and `buf` must
    /// keep holding the record until [`ExchangeOutbox::flush`] reports clear.
    pub unsafe fn send(&mut self, sys: &SyscallTable, chan: i32, buf: &[u8], len: usize) -> bool {
        if self.len != 0 || len == 0 || len > buf.len() {
            return false;
        }
        if (sys.channel_write)(chan, buf.as_ptr(), len) > 0 {
            return true;
        }
        self.len = len;
        false
    }

    /// Hold `len` bytes of the caller's buffer without trying to place them —
    /// for a record that must wait behind another on the same port. The next
    /// [`ExchangeOutbox::flush`] places it. False when a record is already
    /// held, or `len` is zero.
    pub fn hold(&mut self, len: usize) -> bool {
        if self.len != 0 || len == 0 {
            return false;
        }
        self.len = len;
        true
    }

    /// Try to place what is held, and report whether the slot is now clear.
    ///
    /// # Safety
    ///
    /// `sys` must be a valid syscall table per the module ABI, and `buf` must
    /// still hold the record that was staged.
    pub unsafe fn flush(&mut self, sys: &SyscallTable, chan: i32, buf: &[u8]) -> bool {
        if self.len == 0 {
            return true;
        }
        if self.len <= buf.len() && (sys.channel_write)(chan, buf.as_ptr(), self.len) > 0 {
            self.len = 0;
        }
        self.len == 0
    }
}
