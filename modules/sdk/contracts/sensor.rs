// Contract: sensor — measured-quantity surface (the `SensorSample` content type).
//
// Layer: contracts (public, stable).
//
// One reading per record, fixed 24 bytes, little-endian:
//
//   [sensor_id: u16] [flags: u8] [scale: i8]
//   [seq: u32] [t_micros: u64] [value: i64]
//
// The reading is `value × 10^scale`. FIXED POINT, not float: the RP2040 has no
// FPU, and chronicle's deterministic expression VM evaluates `int` as `i64` — a
// float here would be converted at every consumer and would make the same
// reading evaluate differently on different silicon, which a deterministic
// engine cannot allow.
//
// WHAT the quantity is, and its unit, are CAPABILITY FACTS on the producing
// port (`sensor.sample`, facts `quantity` / `period_ms` / `max_payload`), not
// bytes in this record. The registry states the general rule — quantities are
// facts, not name segments — and the practical reason is that the check then
// happens where it can act: the composer refuses a Celsius producer wired to a
// lux consumer at build time, which no per-record byte can do. An enumeration in
// the wire table would also be unbounded, and the first sensor outside it would
// re-create the `OctetStream` escape hatch this surface exists to close.
//
// Framed, not streamed: 24 fixed bytes with no length prefix means a consumer
// handed half a record cannot tell it was truncated — it would read a plausible
// value from the wrong offsets and a rule would fire on it.
//
// Timestamp IS in the payload here, unlike `input::key` and `input::midi` where
// timing lives on the edge. A reading's time is part of the measurement — an
// event-time window folds on it, and a late reading is corrected against it —
// so it cannot be the time the record happened to be delivered.

/// Total record size in bytes.
pub const SAMPLE_SIZE: usize = 24;

/// Byte offsets, so a producer and a consumer cannot disagree about layout.
pub const OFF_SENSOR_ID: usize = 0;
pub const OFF_FLAGS: usize = 2;
pub const OFF_SCALE: usize = 3;
pub const OFF_SEQ: usize = 4;
pub const OFF_T_MICROS: usize = 8;
pub const OFF_VALUE: usize = 16;

/// `flags` bit 0 — the reading is a SUBSTITUTE, not a measurement: a held last
/// value, an interpolation, or a default after a read failure. A rule that must
/// not act on stale data tests this rather than inferring staleness from
/// timestamps, which cannot distinguish "not measured" from "measured slowly".
pub const FLAG_SUBSTITUTE: u8 = 1 << 0;
/// `flags` bit 1 — the sensor reported the value at or beyond its range limit,
/// so the true quantity may be larger. Clamping without saying so is how a
/// saturated sensor reads as a plausible measurement.
pub const FLAG_SATURATED: u8 = 1 << 1;

/// Encode one reading. Returns the bytes written, or `None` if `out` is short —
/// never a partial record, because a partial fixed-layout record is
/// indistinguishable from a whole one.
pub fn encode(
    out: &mut [u8],
    sensor_id: u16,
    flags: u8,
    scale: i8,
    seq: u32,
    t_micros: u64,
    value: i64,
) -> Option<usize> {
    if out.len() < SAMPLE_SIZE {
        return None;
    }
    out[OFF_SENSOR_ID..OFF_SENSOR_ID + 2].copy_from_slice(&sensor_id.to_le_bytes());
    out[OFF_FLAGS] = flags;
    out[OFF_SCALE] = scale as u8;
    out[OFF_SEQ..OFF_SEQ + 4].copy_from_slice(&seq.to_le_bytes());
    out[OFF_T_MICROS..OFF_T_MICROS + 8].copy_from_slice(&t_micros.to_le_bytes());
    out[OFF_VALUE..OFF_VALUE + 8].copy_from_slice(&value.to_le_bytes());
    Some(SAMPLE_SIZE)
}

/// One decoded reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub sensor_id: u16,
    pub flags: u8,
    pub scale: i8,
    pub seq: u32,
    pub t_micros: u64,
    pub value: i64,
}

impl Sample {
    /// True when the reading is a substitute rather than a measurement.
    pub fn is_substitute(&self) -> bool {
        self.flags & FLAG_SUBSTITUTE != 0
    }
    /// True when the sensor was at or beyond its range limit.
    pub fn is_saturated(&self) -> bool {
        self.flags & FLAG_SATURATED != 0
    }
}

/// Decode one reading. `None` on a short buffer — a truncated fixed-layout
/// record is refused whole rather than read from the wrong offsets.
pub fn decode(b: &[u8]) -> Option<Sample> {
    if b.len() < SAMPLE_SIZE {
        return None;
    }
    Some(Sample {
        sensor_id: u16::from_le_bytes([b[OFF_SENSOR_ID], b[OFF_SENSOR_ID + 1]]),
        flags: b[OFF_FLAGS],
        scale: b[OFF_SCALE] as i8,
        seq: u32::from_le_bytes([b[OFF_SEQ], b[OFF_SEQ + 1], b[OFF_SEQ + 2], b[OFF_SEQ + 3]]),
        t_micros: u64::from_le_bytes([
            b[OFF_T_MICROS],
            b[OFF_T_MICROS + 1],
            b[OFF_T_MICROS + 2],
            b[OFF_T_MICROS + 3],
            b[OFF_T_MICROS + 4],
            b[OFF_T_MICROS + 5],
            b[OFF_T_MICROS + 6],
            b[OFF_T_MICROS + 7],
        ]),
        value: i64::from_le_bytes([
            b[OFF_VALUE],
            b[OFF_VALUE + 1],
            b[OFF_VALUE + 2],
            b[OFF_VALUE + 3],
            b[OFF_VALUE + 4],
            b[OFF_VALUE + 5],
            b[OFF_VALUE + 6],
            b[OFF_VALUE + 7],
        ]),
    })
}

// The offsets are a layout commitment, so their arithmetic is asserted rather
// than trusted: a field inserted without moving the ones after it would encode
// over its neighbour and decode plausible garbage. Every adjacency is covered,
// in field order — a gap in this list is a pair of fields free to overlap.
const _: () = assert!(OFF_SENSOR_ID == 0);
const _: () = assert!(OFF_SENSOR_ID + 2 == OFF_FLAGS);
const _: () = assert!(OFF_FLAGS + 1 == OFF_SCALE);
const _: () = assert!(OFF_SCALE + 1 == OFF_SEQ);
const _: () = assert!(OFF_SEQ + 4 == OFF_T_MICROS);
const _: () = assert!(OFF_T_MICROS + 8 == OFF_VALUE);
const _: () = assert!(OFF_VALUE + 8 == SAMPLE_SIZE);
