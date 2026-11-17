// HAL contract: UART.
//
// Layer: contracts/hal (public, stable).
//
// The provider keeps a transmit and a receive ring per bus and moves bytes
// between them and the wire on its own; every op copies, so no caller memory
// is held between calls.

pub use super::super::super::registry::uart::CLOSE;
/// arg in = `[baud u32 LE]`.
pub use super::super::super::registry::uart::CONFIGURE;
/// arg in = `[bus u8]`. Returns the handle.
pub use super::super::super::registry::uart::OPEN;
/// Bytes in the handle's bus's transmit ring not yet handed to the UART;
/// 0 once all have been. No `arg`.
pub use super::super::super::registry::uart::POLL;
/// Take received bytes. No `arg`; `data` out receives up to its length.
/// Returns the bytes taken, 0 when none have arrived.
pub use super::super::super::registry::uart::READ;
/// Queue bytes to send. No `arg`; `data` in = the bytes. Returns how many
/// the transmit ring took (from the front of `data`), 0 when it is full.
pub use super::super::super::registry::uart::WRITE;
