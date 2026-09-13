//! USB Mass Storage Bulk-Only Transport.
//!
//! Every command is a 31-byte Command Block Wrapper out, optional data, then
//! a 13-byte Command Status Wrapper in. Both are fixed-format and both arrive
//! from the far end of a cable.
//!
//! # What goes wrong, and why none of it errors on its own
//!
//! - **The tag is the only thing tying a status to its command.** A device
//!   that returns the wrong one is answering a different question, and a host
//!   that does not check has just accepted a status for a transfer it did not
//!   make. With queued commands that is a write reported as a successful
//!   read.
//! - **Residue is how much of the promised data did *not* move.** Ignoring it
//!   means treating a short read as a full one — the buffer keeps whatever was
//!   in it beyond the bytes that arrived, and that data is returned to the
//!   caller as if the device had sent it.
//! - **The signatures are the only framing.** Bulk endpoints carry a byte
//!   stream with no packet boundaries a class can rely on, so a desynchronised
//!   stream reads the middle of a data block as a wrapper. Checking the
//!   signature is what resynchronises rather than proceeding into nonsense.
//! - **`bCBWCBLength` is 1..=16.** Zero is a command with no command, and
//!   above 16 runs off the end of the wrapper.

/// Bytes in a Command Block Wrapper.
pub const CBW_LEN: usize = 31;
/// Bytes in a Command Status Wrapper.
pub const CSW_LEN: usize = 13;

/// `dCBWSignature`, "USBC" little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// `dCSWSignature`, "USBS" little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// Largest command block a wrapper can carry.
pub const MAX_CB_LENGTH: u8 = 16;

/// Direction bit in `bmCBWFlags`.
pub const FLAG_DIRECTION_IN: u8 = 0x80;

/// Why a wrapper was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotError {
    /// Not the right number of bytes for this wrapper.
    WrongLength,
    /// The signature does not match: the stream is out of step.
    BadSignature,
    /// A status whose tag does not match the command it answers.
    TagMismatch,
    /// `bCBWCBLength` is zero or above sixteen.
    InvalidCommandLength,
    /// The device reported moving more than it was asked to.
    ResidueExceedsTransfer,
    /// The status byte is not one the specification defines.
    InvalidStatus,
}

/// A parsed Command Block Wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandBlockWrapper {
    /// `dCBWTag` — echoed in the status, and the only thing tying the two
    /// together.
    pub tag: u32,
    /// `dCBWDataTransferLength` — bytes the host expects to move.
    pub data_length: u32,
    /// Whether data flows device-to-host.
    pub direction_in: bool,
    /// Logical unit.
    pub lun: u8,
    /// Bytes of `CBWCB` that are meaningful.
    pub command_length: u8,
}

impl CommandBlockWrapper {
    /// Decode a wrapper from the wire.
    pub fn parse(bytes: &[u8]) -> Result<Self, BotError> {
        if bytes.len() != CBW_LEN {
            return Err(BotError::WrongLength);
        }
        let signature = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if signature != CBW_SIGNATURE {
            return Err(BotError::BadSignature);
        }
        let command_length = bytes[14] & 0x1f;
        if command_length == 0 || command_length > MAX_CB_LENGTH {
            return Err(BotError::InvalidCommandLength);
        }
        Ok(Self {
            tag: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            data_length: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            direction_in: bytes[12] & FLAG_DIRECTION_IN != 0,
            lun: bytes[13] & 0x0f,
            command_length,
        })
    }
}

/// What a device reported about a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// The command succeeded.
    Passed,
    /// The command failed; the host should request sense data.
    Failed,
    /// The device is confused and needs a reset recovery.
    PhaseError,
}

/// A parsed Command Status Wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandStatusWrapper {
    /// `dCSWTag`, which must equal the command's.
    pub tag: u32,
    /// `dCSWDataResidue` — how much of the promised data did **not** move.
    pub residue: u32,
    /// Outcome.
    pub status: CommandStatus,
}

impl CommandStatusWrapper {
    /// Decode a status, checking it against the command it claims to answer.
    ///
    /// `expected` is not optional. A status parsed without the command it
    /// belongs to cannot have its tag checked, and the tag is the only thing
    /// tying the two together — so the API does not offer a way to skip it.
    pub fn parse(bytes: &[u8], expected: &CommandBlockWrapper) -> Result<Self, BotError> {
        if bytes.len() != CSW_LEN {
            return Err(BotError::WrongLength);
        }
        let signature = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if signature != CSW_SIGNATURE {
            return Err(BotError::BadSignature);
        }
        let tag = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if tag != expected.tag {
            // Answering a different question. With queued commands this is a
            // write reported as a successful read.
            return Err(BotError::TagMismatch);
        }
        let residue = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if residue > expected.data_length {
            // More was left over than was ever promised, so the device and
            // the host disagree about what the transfer was.
            return Err(BotError::ResidueExceedsTransfer);
        }
        let status = match bytes[12] {
            0x00 => CommandStatus::Passed,
            0x01 => CommandStatus::Failed,
            0x02 => CommandStatus::PhaseError,
            _ => return Err(BotError::InvalidStatus),
        };
        Ok(Self {
            tag,
            residue,
            status,
        })
    }

    /// Bytes that actually moved, given the command that was issued.
    ///
    /// Separate from `residue` because that is the quantity the wire carries
    /// and this is the one every caller wants. Computing it at each call site
    /// is how a short read gets treated as a full one.
    pub const fn transferred(&self, command: &CommandBlockWrapper) -> u32 {
        command.data_length - self.residue
    }
}
