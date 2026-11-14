// Platform: RP raw peripheral claims.
//
// Layer: platform/rp (chip-specific, unstable).
//
// A raw register bridge acts only on a peripheral instance its caller has
// claimed. A driver claims each instance once, at bring-up, and passes the
// handle as the `handle` of every raw op on that instance; the kernel refuses
// a second claimant and any handle not the caller's (`EBADF`). Pins the raw
// ops configure are owned the same way, through the GPIO table.

/// Claim one instance of a family for the caller.
/// handle=-1, arg=[family:u8, instance:u8]. Returns the claim's handle,
/// `EBUSY` when another module holds the instance, `EINVAL` for an instance
/// the die does not have.
pub use super::super::super::registry::rp_raw::CLAIM;
/// Release a claim. handle = the claim. Returns 0 or `EBADF`.
pub use super::super::super::registry::rp_raw::RELEASE;

/// The families a claim names, with the instance each counts.
pub mod family {
    /// A PIO block, by number.
    pub const PIO: u8 = 0;
    /// A PWM slice.
    pub const PWM: u8 = 1;
    /// An SPI bus.
    pub const SPI: u8 = 2;
    /// An I2C bus.
    pub const I2C: u8 = 3;
    /// A UART.
    pub const UART: u8 = 4;
    /// The ADC (instance 0).
    pub const ADC: u8 = 5;
}
