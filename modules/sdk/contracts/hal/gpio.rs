// HAL contract: GPIO.
//
// Layer: contracts/hal (public, stable).
//
// Portable GPIO operations. Chip backings live in `platform/<chip>/*`.
//
// This file is `include!`'d by `abi.rs` into
// `pub mod contracts::hal::gpio`.

/// GPIO edge detection modes (used with WATCH_EDGE).
/// These values are part of the stable ABI — modules hardcode them.
pub mod edge {
    /// No edge detection.
    pub const NONE: u8 = 0;
    /// Rising edge (low → high).
    pub const RISING: u8 = 1;
    /// Falling edge (high → low).
    pub const FALLING: u8 = 2;
    /// Both edges.
    pub const BOTH: u8 = 3;
}

pub use super::super::super::registry::gpio::CLAIM;
pub use super::super::super::registry::gpio::GET_LEVEL;
pub use super::super::super::registry::gpio::RELEASE;
pub use super::super::super::registry::gpio::SET_INPUT;
pub use super::super::super::registry::gpio::SET_LEVEL;
pub use super::super::super::registry::gpio::SET_MODE;
pub use super::super::super::registry::gpio::SET_OUTPUT;
pub use super::super::super::registry::gpio::SET_PULL;
/// Bind event to GPIO edge. handle=gpio (pin).
/// arg[0]=edge (1=rising, 2=falling, 3=both), arg[1..5]=event_handle (i32 LE).
/// Sets up edge detection and auto-signals the event on each detected edge.
pub use super::super::super::registry::gpio::WATCH_EDGE;
