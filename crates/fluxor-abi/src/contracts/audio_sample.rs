// Contract: the `AudioSample` stream's records.
//
// Layer: contracts (portable capability vocabulary).
//
// An `AudioSample` edge carries interleaved signed 16-bit stereo PCM: every
// sample record is a whole number of 4-byte frames. Beside them the stream
// carries one kind of control record, in band: a [`format`] record, which
// states the sample rate of the frames after it. Its length is not a multiple
// of a frame, so no sample record is ever one.
//
// A consumer reads the stream record by record — `channel::RECORD_LEN` names
// the next record's length on a ring, and a mailbox holds one record at a
// time — and takes a record of [`format::LEN`] bytes that [`format::parse`]
// accepts as a rate change. A stage between producer and sink (a mixer, an
// effect) forwards a format record as it arrives.

/// Bytes in one stereo 16-bit frame: a sample record's length is a multiple
/// of it.
pub const FRAME_BYTES: usize = 4;

/// The format record: `[MAGIC u16 LE][sample_rate u32 LE]`.
pub mod format {
    /// Encoded length: 6, never a whole number of frames.
    pub const LEN: usize = 6;
    /// The record's first two bytes.
    pub const MAGIC: u16 = 0xA5F0;

    /// The record stating `sample_rate` (Hz).
    pub const fn encode(sample_rate: u32) -> [u8; LEN] {
        let m = MAGIC.to_le_bytes();
        let r = sample_rate.to_le_bytes();
        [m[0], m[1], r[0], r[1], r[2], r[3]]
    }

    /// The sample rate `record` states, when it is a format record.
    pub fn parse(record: &[u8]) -> Option<u32> {
        if record.len() != LEN || u16::from_le_bytes([record[0], record[1]]) != MAGIC {
            return None;
        }
        Some(u32::from_le_bytes([
            record[2], record[3], record[4], record[5],
        ]))
    }
}

const _: () = assert!(!format::LEN.is_multiple_of(FRAME_BYTES));
