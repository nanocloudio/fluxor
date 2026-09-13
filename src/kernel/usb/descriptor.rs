//! Defensive parsing of USB descriptors.
//!
//! Descriptors arrive from the other end of a cable. They are attacker-
//! controlled in the plainest sense — a device chooses what to say about
//! itself — so every field here is treated as hostile until it has been
//! bounds-checked against the buffer it came in.
//!
//! The failure this module exists to prevent is not a crash. It is the
//! descriptor walk that never terminates: a descriptor declaring
//! `bLength = 0` advances the cursor by zero, and the obvious loop spins
//! forever holding whatever lock enumeration runs under. That one is not
//! hypothetical — it is the classic USB parser bug, and it is reachable by
//! plugging in a device.

/// Descriptor types this core understands (USB 2.0 Table 9-5).
pub mod desc_type {
    /// Device descriptor.
    pub const DEVICE: u8 = 0x01;
    /// Configuration descriptor.
    pub const CONFIGURATION: u8 = 0x02;
    /// String descriptor.
    pub const STRING: u8 = 0x03;
    /// Interface descriptor.
    pub const INTERFACE: u8 = 0x04;
    /// Endpoint descriptor.
    pub const ENDPOINT: u8 = 0x05;
    /// Binary Object Store.
    pub const BOS: u8 = 0x0f;
    /// SuperSpeed endpoint companion.
    pub const SS_ENDPOINT_COMPANION: u8 = 0x30;
}

/// The smallest legal `bLength` for each type we parse fields out of.
///
/// A descriptor shorter than this declares a type whose fields do not fit in
/// the bytes it claims — reading them would read the *next* descriptor, or
/// past the buffer.
pub mod min_length {
    /// `bLength`, `bDescriptorType`.
    pub const HEADER: usize = 2;
    /// USB 2.0 §9.6.1.
    pub const DEVICE: usize = 18;
    /// USB 2.0 §9.6.3.
    pub const CONFIGURATION: usize = 9;
    /// USB 2.0 §9.6.5.
    pub const INTERFACE: usize = 9;
    /// USB 2.0 §9.6.6.
    pub const ENDPOINT: usize = 7;
    /// USB 3.2 §9.6.7.
    pub const SS_ENDPOINT_COMPANION: usize = 6;
}

/// Why a descriptor was rejected.
///
/// Distinct variants rather than one `Invalid`: which check failed is the
/// difference between "this device is buggy" and "this device is hostile",
/// and the telemetry is worth having when a board stops enumerating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// Fewer than two bytes remain: not even a header.
    Truncated,
    /// `bLength` is zero. Advancing by it would not terminate.
    ZeroLength,
    /// `bLength` exceeds the bytes remaining in the buffer.
    OverrunsBuffer,
    /// `bLength` is too small for the fields its type defines.
    TooShortForType,
    /// The descriptor count or total length exceeds what this core will hold.
    CapacityExceeded,
    /// A field holds a value the specification does not permit.
    InvalidField,
}

/// One descriptor located within a buffer, borrowed rather than copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor<'a> {
    /// `bDescriptorType`.
    pub kind: u8,
    /// The whole descriptor, `bLength` bytes including the two header bytes.
    pub bytes: &'a [u8],
}

impl Descriptor<'_> {
    /// A byte at `offset` within the descriptor, or `None` if it lies beyond
    /// `bLength`.
    ///
    /// Every field accessor goes through this. Indexing directly would read
    /// the next descriptor's bytes for a short-but-legal descriptor, which
    /// is a disclosure rather than a panic and so would not be noticed.
    #[inline]
    pub fn byte(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// A little-endian `u16` at `offset`, or `None` if either byte lies
    /// beyond `bLength`.
    #[inline]
    pub fn word(&self, offset: usize) -> Option<u16> {
        let lo = self.byte(offset)? as u16;
        let hi = self.byte(offset + 1)? as u16;
        Some(lo | (hi << 8))
    }
}

/// The most descriptors this core will walk in one configuration.
///
/// A bound, not a guess: a device can declare an arbitrarily long
/// configuration, and enumeration must be able to give up rather than spend
/// unbounded time on one attachment.
pub const MAX_DESCRIPTORS: usize = 64;

/// Walk a descriptor buffer, calling `visit` for each well-formed descriptor.
///
/// Stops at the first malformed descriptor and reports it: a configuration
/// that is partly garbage is not one to half-accept, because the interfaces
/// already visited may reference endpoints in the part that did not parse.
///
/// Terminates. The cursor advances by `bLength`, which is checked non-zero
/// before use, and the descriptor count is capped — so neither a zero length
/// nor a very long buffer can hold the caller indefinitely.
pub fn walk<'a>(
    buf: &'a [u8],
    mut visit: impl FnMut(Descriptor<'a>) -> Result<(), DescriptorError>,
) -> Result<usize, DescriptorError> {
    let mut cursor = 0usize;
    let mut seen = 0usize;

    while cursor < buf.len() {
        let remaining = buf.len() - cursor;
        if remaining < min_length::HEADER {
            // Trailing bytes that cannot be a descriptor. A device that pads
            // its configuration is not malformed up to this point, but the
            // padding is not a descriptor and must not be read as one.
            return Err(DescriptorError::Truncated);
        }

        let length = buf[cursor] as usize;
        // The termination guarantee. Checked before the cursor moves.
        if length == 0 {
            return Err(DescriptorError::ZeroLength);
        }
        if length < min_length::HEADER {
            return Err(DescriptorError::TooShortForType);
        }
        if length > remaining {
            return Err(DescriptorError::OverrunsBuffer);
        }
        if seen == MAX_DESCRIPTORS {
            return Err(DescriptorError::CapacityExceeded);
        }

        let bytes = &buf[cursor..cursor + length];
        visit(Descriptor {
            kind: bytes[1],
            bytes,
        })?;

        seen += 1;
        cursor += length;
    }

    Ok(seen)
}

/// Endpoint direction, from bit 7 of `bEndpointAddress`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Host to device.
    Out,
    /// Device to host.
    In,
}

/// Endpoint transfer type, from the low two bits of `bmAttributes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferType {
    /// Control.
    Control,
    /// Isochronous.
    Isochronous,
    /// Bulk.
    Bulk,
    /// Interrupt.
    Interrupt,
}

/// A validated endpoint descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Endpoint number, 1..=15. Zero is the control endpoint and is never
    /// described by an endpoint descriptor.
    pub number: u8,
    /// Direction.
    pub direction: Direction,
    /// Transfer type.
    pub transfer_type: TransferType,
    /// Maximum packet size, in bytes.
    pub max_packet_size: u16,
    /// Polling interval, in frames or microframes by type and speed.
    pub interval: u8,
}

/// Largest `wMaxPacketSize` USB 2.0 permits, for any type.
///
/// The field is 11 bits of size plus 2 bits of additional-transaction count,
/// so a device can encode a larger number than any endpoint may legally use.
/// The cap matters because this value sizes buffers.
pub const MAX_PACKET_SIZE_LIMIT: u16 = 1024;

/// Parse and validate an endpoint descriptor.
///
/// The checks are not stylistic. `max_packet_size` sizes a buffer, so a zero
/// there yields an endpoint that can never transfer and a huge one asks the
/// allocator for memory the controller does not have. An endpoint number of
/// zero would alias the control endpoint's state.
pub fn parse_endpoint(d: &Descriptor<'_>) -> Result<Endpoint, DescriptorError> {
    if d.kind != desc_type::ENDPOINT {
        return Err(DescriptorError::InvalidField);
    }
    if d.bytes.len() < min_length::ENDPOINT {
        return Err(DescriptorError::TooShortForType);
    }

    let address = d.byte(2).ok_or(DescriptorError::TooShortForType)?;
    let attributes = d.byte(3).ok_or(DescriptorError::TooShortForType)?;
    let max_packet = d.word(4).ok_or(DescriptorError::TooShortForType)?;
    let interval = d.byte(6).ok_or(DescriptorError::TooShortForType)?;

    let number = address & 0x0f;
    if number == 0 {
        // Endpoint 0 is the control endpoint and is implicit; a descriptor
        // claiming it would give a second owner to EP0's state.
        return Err(DescriptorError::InvalidField);
    }

    let direction = if address & 0x80 != 0 {
        Direction::In
    } else {
        Direction::Out
    };

    let transfer_type = match attributes & 0x03 {
        0 => TransferType::Control,
        1 => TransferType::Isochronous,
        2 => TransferType::Bulk,
        _ => TransferType::Interrupt,
    };

    // Only the low 11 bits are the size; the other bits are the
    // additional-transaction count for high-speed periodic endpoints.
    let max_packet_size = max_packet & 0x07ff;
    if max_packet_size == 0 || max_packet_size > MAX_PACKET_SIZE_LIMIT {
        return Err(DescriptorError::InvalidField);
    }

    // A periodic endpoint that never polls is not a valid schedule entry:
    // bandwidth admission would divide by it.
    if matches!(
        transfer_type,
        TransferType::Interrupt | TransferType::Isochronous
    ) && interval == 0
    {
        return Err(DescriptorError::InvalidField);
    }

    Ok(Endpoint {
        number,
        direction,
        transfer_type,
        max_packet_size,
        interval,
    })
}

/// Validate a configuration descriptor's own fields and report `wTotalLength`.
///
/// `wTotalLength` is how many bytes the host will request in the second
/// fetch, so a value larger than the caller's buffer must be refused here
/// rather than discovered as a short read later.
pub fn configuration_total_length(
    d: &Descriptor<'_>,
    buffer_capacity: usize,
) -> Result<u16, DescriptorError> {
    if d.kind != desc_type::CONFIGURATION {
        return Err(DescriptorError::InvalidField);
    }
    if d.bytes.len() < min_length::CONFIGURATION {
        return Err(DescriptorError::TooShortForType);
    }
    let total = d.word(2).ok_or(DescriptorError::TooShortForType)?;
    if (total as usize) < min_length::CONFIGURATION {
        return Err(DescriptorError::InvalidField);
    }
    if total as usize > buffer_capacity {
        return Err(DescriptorError::CapacityExceeded);
    }
    Ok(total)
}
