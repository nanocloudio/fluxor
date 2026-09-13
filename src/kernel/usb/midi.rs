//! USB-MIDI event packets, and their translation to `input::midi` frames.
//!
//! A class-compliant USB-MIDI device sends fixed 4-byte event packets:
//!
//! ```text
//! [cable << 4 | CIN] [status] [data1] [data2]
//! ```
//!
//! and `input::midi` carries fixed 4-byte frames:
//!
//! ```text
//! [event_kind] [channel] [data1] [data2]
//! ```
//!
//! The two shapes look one byte apart, and they are not. Treating them that
//! way is how a translator ends up plausibly wrong:
//!
//! - **Channel is 1-based in `input::midi` and 0-based on the wire.** A
//!   straight copy puts every event one channel low, which a musician
//!   notices and a test does not unless it is looking.
//! - **`event_kind` is deliberately not the status nibble.** The contract
//!   says so: the values are chosen to be distinct so a fused byte stream
//!   cannot be misread as pre-decoded frames.
//! - **NoteOn with velocity zero means NoteOff**, and the contract puts that
//!   normalisation on the producer — here. A consumer that trusts the
//!   contract will hold notes on forever if this is skipped.
//! - **The CIN, not the status byte, gives the packet's length.** They agree
//!   for channel-voice messages and diverge for System Common and SysEx.
//!
//! This lives in the kernel's shared USB core rather than in a controller
//! driver so that one translator serves every controller. A translator per
//! controller is two translators that will eventually disagree.

use super::super::super::kernel;

/// Code Index Numbers (USB Device Class Definition for MIDI Devices, Table
/// 4-1). The low nibble of a packet's first byte.
pub mod cin {
    /// Two-byte System Common.
    pub const SYS_COMMON_2: u8 = 0x2;
    /// Three-byte System Common.
    pub const SYS_COMMON_3: u8 = 0x3;
    /// SysEx starts or continues.
    pub const SYSEX_START: u8 = 0x4;
    /// Single-byte System Common, or SysEx ending with one byte.
    pub const SYSEX_END_1: u8 = 0x5;
    /// SysEx ending with two bytes.
    pub const SYSEX_END_2: u8 = 0x6;
    /// SysEx ending with three bytes.
    pub const SYSEX_END_3: u8 = 0x7;
    /// Note-off.
    pub const NOTE_OFF: u8 = 0x8;
    /// Note-on.
    pub const NOTE_ON: u8 = 0x9;
    /// Polyphonic key pressure.
    pub const POLY_PRESSURE: u8 = 0xA;
    /// Control change.
    pub const CONTROL_CHANGE: u8 = 0xB;
    /// Program change.
    pub const PROGRAM_CHANGE: u8 = 0xC;
    /// Channel pressure.
    pub const CHANNEL_PRESSURE: u8 = 0xD;
    /// Pitch bend.
    pub const PITCH_BEND: u8 = 0xE;
    /// A single unparsed byte.
    pub const SINGLE_BYTE: u8 = 0xF;
}

/// `input::midi` event kinds, mirrored from the contract.
///
/// Mirrored rather than imported because the contract lives in the SDK tree,
/// which the kernel does not depend on. A test asserts the two agree, so the
/// duplication cannot drift silently.
pub mod kind {
    /// Note off.
    pub const NOTE_OFF: u8 = 0x01;
    /// Note on.
    pub const NOTE_ON: u8 = 0x02;
    /// Polyphonic key pressure.
    pub const POLY_PRESSURE: u8 = 0x03;
    /// Control change.
    pub const CONTROL_CHANGE: u8 = 0x04;
    /// Program change.
    pub const PROGRAM_CHANGE: u8 = 0x05;
    /// Channel pressure.
    pub const CHANNEL_PRESSURE: u8 = 0x06;
    /// Pitch bend.
    pub const PITCH_BEND: u8 = 0x07;
}

/// Bytes in a USB-MIDI event packet, and in an `input::midi` frame. They
/// happen to match, which is convenient and not a reason to conflate them.
pub const PACKET_LEN: usize = 4;

/// How many of a packet's three payload bytes the CIN says are meaningful.
///
/// The CIN is authoritative, not the status byte. They agree for
/// channel-voice messages and diverge for System Common and SysEx, which is
/// exactly where a translator that trusts the status byte goes wrong.
pub const fn payload_len(cin: u8) -> usize {
    match cin {
        cin::SYSEX_END_1 | cin::SINGLE_BYTE => 1,
        cin::SYS_COMMON_2 | cin::PROGRAM_CHANGE | cin::CHANNEL_PRESSURE | cin::SYSEX_END_2 => 2,
        cin::SYS_COMMON_3
        | cin::SYSEX_START
        | cin::SYSEX_END_3
        | cin::NOTE_OFF
        | cin::NOTE_ON
        | cin::POLY_PRESSURE
        | cin::CONTROL_CHANGE
        | cin::PITCH_BEND => 3,
        // 0x0 and 0x1 are reserved. Reporting zero keeps a reserved CIN from
        // being read as a message.
        _ => 0,
    }
}

/// An `input::midi` frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// `event_kind`.
    pub kind: u8,
    /// 1-based MIDI channel, 1..=16.
    pub channel: u8,
    /// First payload byte.
    pub data1: u8,
    /// Second payload byte; zero where the message has none.
    pub data2: u8,
}

impl Frame {
    /// The four wire bytes, in contract order.
    pub const fn to_bytes(self) -> [u8; PACKET_LEN] {
        [self.kind, self.channel, self.data1, self.data2]
    }
}

/// Translate one USB-MIDI event packet.
///
/// `None` for anything that is not a channel-voice message: System Common
/// and SysEx belong to a separate streaming contract, and `input::midi` says
/// so. Returning a frame for them would put SysEx bytes where a note number
/// is expected.
pub fn frame_from_usb_midi_packet(packet: &[u8]) -> Option<Frame> {
    if packet.len() < PACKET_LEN {
        return None;
    }
    let cin = packet[0] & 0x0f;
    let status = packet[1];
    let data1 = packet[2];
    let data2 = packet[3];

    // The channel nibble is 0-based on the wire; the contract is 1-based.
    let channel = (status & 0x0f) + 1;

    let (kind, d1, d2) = match cin {
        cin::NOTE_OFF => (kind::NOTE_OFF, data1, data2),
        cin::NOTE_ON => {
            // A NoteOn at velocity zero is a NoteOff. The contract puts this
            // normalisation on the producer, and a consumer that trusts it
            // holds the note on forever if it is skipped here.
            if data2 == 0 {
                (kind::NOTE_OFF, data1, 0)
            } else {
                (kind::NOTE_ON, data1, data2)
            }
        }
        cin::POLY_PRESSURE => (kind::POLY_PRESSURE, data1, data2),
        cin::CONTROL_CHANGE => (kind::CONTROL_CHANGE, data1, data2),
        // Two-byte messages: the contract says the unused byte is zero, not
        // whatever the device happened to send.
        cin::PROGRAM_CHANGE => (kind::PROGRAM_CHANGE, data1, 0),
        cin::CHANNEL_PRESSURE => (kind::CHANNEL_PRESSURE, data1, 0),
        cin::PITCH_BEND => (kind::PITCH_BEND, data1, data2),
        _ => return None,
    };

    Some(Frame {
        kind,
        channel,
        data1: d1,
        data2: d2,
    })
}

/// The cable number a packet arrived on, 0..=15.
///
/// A device may expose several virtual cables on one endpoint, so this is
/// what separates two keyboards behind one connector.
pub const fn cable(packet_first_byte: u8) -> u8 {
    packet_first_byte >> 4
}

/// USB-MIDI class descriptor identifiers (USB Device Class Definition for
/// MIDI Devices §B).
pub mod class {
    /// `bInterfaceClass` for audio.
    pub const AUDIO: u8 = 0x01;
    /// `bInterfaceSubClass` for MIDI Streaming.
    pub const MIDI_STREAMING: u8 = 0x03;
    /// `bInterfaceSubClass` for Audio Control, which a compliant device
    /// presents alongside the streaming interface.
    pub const AUDIO_CONTROL: u8 = 0x01;
}

/// Whether an interface descriptor is a MIDI Streaming interface.
///
/// Both fields are checked. A device exposing Audio Control on the same
/// audio class would otherwise be claimed as a MIDI interface, and its
/// endpoints opened as if they carried event packets.
pub fn is_midi_streaming_interface(descriptor: &[u8]) -> bool {
    use kernel::usb::descriptor::{desc_type, min_length};
    if descriptor.len() < min_length::INTERFACE || descriptor[1] != desc_type::INTERFACE {
        return false;
    }
    // bInterfaceClass is byte 5, bInterfaceSubClass byte 6.
    descriptor[5] == class::AUDIO && descriptor[6] == class::MIDI_STREAMING
}
