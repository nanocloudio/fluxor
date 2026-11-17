// HAL contract: I2C.
//
// Layer: contracts/hal (public, stable).
//
// A transfer is started by one op and finished by `POLL`: the provider
// copies the bytes to send when the transfer starts and hands the bytes
// received back when it is polled, so no caller memory is held between
// calls. One transfer per handle is in flight at a time; a start while one
// runs is refused with `EBUSY`.

pub use super::super::super::registry::i2c::CLAIM;
pub use super::super::super::registry::i2c::CLOSE;
/// Open a device on a bus. arg in = [`open`].
pub use super::super::super::registry::i2c::OPEN;
/// The transfer in flight on the handle. No `arg`; `data` out receives the
/// bytes read (up to its length). Returns `EAGAIN` while the transfer runs;
/// once it is done, the bytes it moved (read for `READ` and `WRITE_READ`,
/// written for `WRITE`) or its error, once; 0 when nothing is in flight.
pub use super::super::super::registry::i2c::POLL;
/// Start a read of `len` bytes. arg in = [`read`], no `data`. Returns 0
/// once started.
pub use super::super::super::registry::i2c::READ;
pub use super::super::super::registry::i2c::RELEASE;
/// Start a write. No `arg`; `data` in = the bytes, 1..=[`XFER_MAX`],
/// copied during the call. Returns 0 once started.
pub use super::super::super::registry::i2c::WRITE;
/// Start a write followed, after a repeated start, by a read. arg in =
/// [`read`] (the read length); `data` in = the bytes to write,
/// 1..=[`XFER_MAX`], copied during the call. Returns 0 once started; the
/// bytes read come back from `POLL`.
pub use super::super::super::registry::i2c::WRITE_READ;

/// The most bytes one transfer writes, and the most it reads.
pub const XFER_MAX: usize = 64;

/// `OPEN` argument: `[bus u8][target u16 LE]` — the bus and the device's
/// 7-bit target number on it.
pub mod open {
    /// Total length, in bytes.
    pub const ARG_LEN: usize = 3;

    pub const fn encode(bus: u8, target: u16) -> [u8; ARG_LEN] {
        let a = target.to_le_bytes();
        [bus, a[0], a[1]]
    }

    /// `(bus, target)` from an argument.
    pub fn decode(arg: &[u8]) -> Option<(u8, u16)> {
        match arg {
            [bus, a0, a1, ..] => Some((*bus, u16::from_le_bytes([*a0, *a1]))),
            _ => None,
        }
    }
}

/// `READ` / `WRITE_READ` argument: `[len u16 LE]` — bytes to read,
/// 1..=[`super::XFER_MAX`].
pub mod read {
    /// Total length, in bytes.
    pub const ARG_LEN: usize = 2;

    pub const fn encode(len: u16) -> [u8; ARG_LEN] {
        len.to_le_bytes()
    }

    /// The read length from an argument.
    pub fn decode(arg: &[u8]) -> Option<u16> {
        match arg {
            [l0, l1, ..] => Some(u16::from_le_bytes([*l0, *l1])),
            _ => None,
        }
    }
}
