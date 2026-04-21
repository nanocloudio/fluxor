// HAL contract: PWM (pulse-width modulation).
//
// Layer: contracts/hal (public, stable).
//
// Hardware PWM output on GPIO pins. The generic portable contract is
// below; chip-specific raw slice register access lives in
// `platform/<chip>/pwm_raw.rs`.
//
// OPEN: arg[0] = pin number → returns handle (slot index)
// CONFIGURE: arg = [top:u16 LE, div_int:u8, div_frac:u8] (4 bytes)
// SET_DUTY: arg = [duty:u16 LE] (2 bytes), duty range 0..=top
// GET_DUTY: returns current duty cycle value
// CLOSE: release PWM handle and reset pin

pub const OPEN: u32 = 0x0F00;
pub const CLOSE: u32 = 0x0F01;
pub const CONFIGURE: u32 = 0x0F02;
pub const SET_DUTY: u32 = 0x0F03;
pub const GET_DUTY: u32 = 0x0F04;
