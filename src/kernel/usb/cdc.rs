//! CDC ACM class logic.
//!
//! The serial-over-USB class: line coding, control line state, and the
//! bounded buffers between a log producer and a host that may or may not be
//! listening.
//!
//! # The rule this module exists to enforce
//!
//! **Draining logs to USB must never block.** A CDC endpoint with no host
//! reading it fills and stays full. A producer that waits for space then
//! waits forever, inside a module step, and the scheduler's step guard
//! converts that into a terminated module — which is how a board stops doing
//! anything at all because nobody opened the serial port.
//!
//! So every write here is offer-and-account: it takes what fits, reports what
//! it took, and counts what it dropped. A caller cannot accidentally write a
//! blocking loop against this API because there is nothing to block on.
//!
//! # DTR is a policy, not a gate
//!
//! DTR ("data terminal ready") is the host saying a program has the port
//! open. Gating transmission on it is tempting and wrong in one direction:
//! logs written before anyone connects are exactly the boot logs worth
//! having. The policy here is to buffer regardless and let the ring's own
//! bound discard the oldest, so a late-connecting host sees recent history
//! rather than nothing.

/// CDC class-specific requests (USB CDC 1.2 Table 19).
pub mod request {
    /// `SET_LINE_CODING` — baud, stop bits, parity, data bits.
    pub const SET_LINE_CODING: u8 = 0x20;
    /// `GET_LINE_CODING`.
    pub const GET_LINE_CODING: u8 = 0x21;
    /// `SET_CONTROL_LINE_STATE` — DTR and RTS.
    pub const SET_CONTROL_LINE_STATE: u8 = 0x22;
    /// `SEND_BREAK`.
    pub const SEND_BREAK: u8 = 0x23;
}

/// `SET_CONTROL_LINE_STATE` wValue bits.
pub mod control_line {
    /// Data terminal ready: a host program has the port open.
    pub const DTR: u16 = 1 << 0;
    /// Request to send.
    pub const RTS: u16 = 1 << 1;
}

/// Line coding, as the host sets it.
///
/// Meaningless to a USB link — there is no UART on the other side — but the
/// host expects the device to remember what it was told and hand the same
/// values back. A device that returns something else confuses terminal
/// programs into reconfiguring in a loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineCoding {
    /// Bits per second.
    pub baud: u32,
    /// Stop bits: 0 = one, 1 = 1.5, 2 = two.
    pub stop_bits: u8,
    /// Parity: 0 none, 1 odd, 2 even, 3 mark, 4 space.
    pub parity: u8,
    /// Data bits: 5, 6, 7, 8 or 16.
    pub data_bits: u8,
}

impl Default for LineCoding {
    fn default() -> Self {
        // The conventional default a host sees before it sets anything.
        Self {
            baud: 115_200,
            stop_bits: 0,
            parity: 0,
            data_bits: 8,
        }
    }
}

impl LineCoding {
    /// Wire size of the line-coding structure.
    pub const WIRE_LEN: usize = 7;

    /// Decode from the seven wire bytes.
    ///
    /// Returns `None` for anything but exactly seven bytes: a short buffer
    /// would leave fields reading whatever preceded them.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            baud: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            stop_bits: bytes[4],
            parity: bytes[5],
            data_bits: bytes[6],
        })
    }

    /// Encode to the seven wire bytes.
    pub fn to_bytes(self) -> [u8; Self::WIRE_LEN] {
        let b = self.baud.to_le_bytes();
        [
            b[0],
            b[1],
            b[2],
            b[3],
            self.stop_bits,
            self.parity,
            self.data_bits,
        ]
    }
}

/// Bytes the transmit ring holds.
///
/// Sized for a boot's worth of log lines rather than for throughput: the
/// point is that a host connecting late sees recent history, not that the
/// link is fast.
pub const TX_CAPACITY: usize = 2048;

/// What happened to an offered write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Bytes accepted into the ring.
    pub accepted: usize,
    /// Bytes discarded to make room, from the oldest end.
    pub discarded: usize,
}

/// A CDC ACM endpoint's state and its bounded transmit ring.
pub struct CdcState {
    line_coding: LineCoding,
    dtr: bool,
    rts: bool,
    tx: [u8; TX_CAPACITY],
    head: usize,
    len: usize,
    /// Bytes discarded since boot, so loss is accounted rather than silent.
    /// Saturating: a counter that wraps reports healthy after enough loss,
    /// which is the opposite of what it is for.
    dropped_total: u32,
}

impl Default for CdcState {
    fn default() -> Self {
        Self::new()
    }
}

impl CdcState {
    /// A closed, empty endpoint.
    pub const fn new() -> Self {
        Self {
            line_coding: LineCoding {
                baud: 115_200,
                stop_bits: 0,
                parity: 0,
                data_bits: 8,
            },
            dtr: false,
            rts: false,
            tx: [0; TX_CAPACITY],
            head: 0,
            len: 0,
            dropped_total: 0,
        }
    }

    /// The line coding the host last set.
    pub const fn line_coding(&self) -> LineCoding {
        self.line_coding
    }

    /// Record a `SET_LINE_CODING`.
    pub fn set_line_coding(&mut self, coding: LineCoding) {
        self.line_coding = coding;
    }

    /// Whether a host program has the port open.
    pub const fn dtr(&self) -> bool {
        self.dtr
    }

    /// Whether the host asserted RTS.
    pub const fn rts(&self) -> bool {
        self.rts
    }

    /// Record a `SET_CONTROL_LINE_STATE`.
    ///
    /// Dropping DTR does **not** clear the buffer: what is queued was worth
    /// sending when it was written, and a host that closes and reopens the
    /// port should see it. Clearing here would discard exactly the log lines
    /// someone reconnecting is trying to read.
    pub fn set_control_line_state(&mut self, value: u16) {
        self.dtr = value & control_line::DTR != 0;
        self.rts = value & control_line::RTS != 0;
    }

    /// A USB bus reset: the host is starting over.
    ///
    /// Control line state is void — the host has not asserted DTR on the new
    /// connection — but buffered output is kept, for the same reason.
    pub fn bus_reset(&mut self) {
        self.dtr = false;
        self.rts = false;
        self.line_coding = LineCoding::default();
    }

    /// Bytes waiting to be sent.
    pub const fn queued(&self) -> usize {
        self.len
    }

    /// Bytes the ring can take without discarding anything.
    ///
    /// For a producer that would rather wait than lose data: `write` never
    /// blocks and never refuses, so a producer with something better to do
    /// than drop the oldest line — a drain that can hold bytes back until
    /// there is room — asks first.
    pub const fn free(&self) -> usize {
        TX_CAPACITY - self.len
    }

    /// Bytes discarded since boot.
    pub const fn dropped_total(&self) -> u32 {
        self.dropped_total
    }

    /// Offer `data` to the transmit ring. **Never blocks.**
    ///
    /// Takes what fits, discarding the oldest bytes when it must, and reports
    /// both numbers. There is deliberately no "wait for space" variant: a
    /// producer waiting on a ring nothing is draining waits forever inside a
    /// module step, and the step guard turns that into a terminated module.
    /// That is how a board stops working because nobody opened the port.
    pub fn write(&mut self, data: &[u8]) -> WriteOutcome {
        // Longer than the ring: only the tail can survive, so the caller is
        // told the whole overflow was discarded rather than silently keeping
        // a middle slice.
        let (data, pre_discarded) = if data.len() > TX_CAPACITY {
            let cut = data.len() - TX_CAPACITY;
            (&data[cut..], cut)
        } else {
            (data, 0)
        };

        let free = TX_CAPACITY - self.len;
        let discarded = data.len().saturating_sub(free);
        if discarded > 0 {
            // Drop from the oldest end: recent output is what a reader wants.
            self.head = (self.head + discarded) % TX_CAPACITY;
            self.len -= discarded;
        }

        for &b in data {
            let at = (self.head + self.len) % TX_CAPACITY;
            self.tx[at] = b;
            self.len += 1;
        }

        let total_discarded = discarded + pre_discarded;
        self.dropped_total = self
            .dropped_total
            .saturating_add(total_discarded.min(u32::MAX as usize) as u32);

        WriteOutcome {
            accepted: data.len(),
            discarded: total_discarded,
        }
    }

    /// Take up to `out.len()` bytes for transmission, returning how many.
    ///
    /// A **partial** take is normal and correct: an endpoint sends one packet
    /// at a time, so the drain is called repeatedly and must not assume it
    /// empties the ring.
    pub fn read_tx(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            *slot = self.tx[(self.head + i) % TX_CAPACITY];
        }
        self.head = (self.head + n) % TX_CAPACITY;
        self.len -= n;
        n
    }
}
