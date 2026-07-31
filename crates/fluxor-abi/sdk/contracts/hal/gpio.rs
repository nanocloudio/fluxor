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

pub const CLAIM: u32 = 0x0100;
pub const RELEASE: u32 = 0x0101;
pub const SET_MODE: u32 = 0x0102;
pub const SET_PULL: u32 = 0x0103;
pub const SET_LEVEL: u32 = 0x0104;
pub const GET_LEVEL: u32 = 0x0105;
pub const SET_OUTPUT: u32 = 0x0106;
pub const SET_INPUT: u32 = 0x0107;
/// Bind event to GPIO edge. handle=gpio (pin).
/// arg[0]=edge (1=rising, 2=falling, 3=both), arg[1..5]=event_handle (i32 LE).
/// Sets up edge detection and auto-signals the event on each detected edge.
pub const WATCH_EDGE: u32 = 0x010A;
