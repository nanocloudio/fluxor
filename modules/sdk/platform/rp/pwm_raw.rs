// Platform: RP PWM raw register bridge.
//
// Layer: platform/rp (chip-specific, unstable).
//
// Used by the pwm PIC provider module to drive RP2040/RP2350 PWM
// slices directly. Portable consumers should call the HAL PWM contract
// (`contracts/hal/pwm.rs`) instead.

/// Raw PWM pin enable: set pin funcsel to PWM (4), configure pad.
/// handle=-1, arg[0]=pin. Returns 0 or error.
pub const PIN_ENABLE: u32 = 0x0C60;
/// Raw PWM pin disable: reset pin funcsel to NULL (31).
/// handle=-1, arg[0]=pin. Returns 0 or error.
pub const PIN_DISABLE: u32 = 0x0C61;
/// Raw PWM slice register write.
/// handle=-1, arg=[slice:u8, reg:u8, value:u32 LE] (6 bytes).
/// Registers: 0=CSR, 1=DIV, 2=CTR, 3=CC, 4=TOP.
pub const SLICE_WRITE: u32 = 0x0C62;
/// Raw PWM slice register read.
/// handle=-1, arg=[slice:u8, reg:u8] (2 bytes). Returns register value as i32.
pub const SLICE_READ: u32 = 0x0C63;
