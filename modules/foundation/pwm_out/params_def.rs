use super::PwmOutState;
use super::p_u8;
use super::SCHEMA_MAX;

define_params! {
    PwmOutState;

    1, pin, u8, 25
        => |s, d, len| { s.pin = p_u8(d, len, 0, 25); };
}
