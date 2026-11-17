// Contract: stream select (an edge contract).
//
// Layer: contracts (portable capability vocabulary).
//
// A consumer asks the producer at the other end of one of its input ports to
// restart the stream it writes on that edge at a position the consumer names:
// the index of an item an indexed source holds (a blob, a file of a bank).
// The consumer binds once — `BIND(stream_select, PORT in <index>)` — and calls
// `SELECT` through the bound handle; the producer is handed its own output
// port ref as the handle. What a position means is the producer port's own
// documented fact; a position it does not hold is `EINVAL`.
//
// The usual sequence on the consumer: `FLUSH` its input (what is buffered
// belongs to the stream being abandoned), then `SELECT`. The producer drops
// what it had pending, writes the selected item, and ends it with `SET_HUP`.

/// The contract id (its opcode class byte).
pub const CLASS: u16 = super::super::registry::stream_select::ID;

/// Restart the stream at a position. `arg` in: [`select`].
pub use super::super::registry::stream_select::SELECT;

/// `SELECT`'s argument: `[position u64 LE]`.
pub mod select {
    /// Encoded length.
    pub const LEN: usize = 8;

    /// The record for `position`.
    pub const fn encode(position: u64) -> [u8; LEN] {
        position.to_le_bytes()
    }

    /// The position `arg` names; `None` unless it is exactly [`LEN`] bytes.
    pub fn parse(arg: &[u8]) -> Option<u64> {
        let b: [u8; LEN] = arg.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    }
}
