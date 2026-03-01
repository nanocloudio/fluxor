// I2S parameter definitions (single source of truth).

use super::I2sState;
use super::{p_u8, p_u32};
use super::SCHEMA_MAX;

define_params! {
    I2sState;

    1, data_pin, u8, 28
        => |s, d, len| {
            let v = p_u8(d, len, 0, 28);
            s.data_pin = if v == 0 { 28 } else { v };
        };

    2, clock_base, u8, 26
        => |s, d, len| {
            let v = p_u8(d, len, 0, 26);
            s.clock_base = if v == 0 { 26 } else { v };
        };

    3, sample_rate, u32, 44100
        => |s, d, len| {
            let v = p_u32(d, len, 0, 44100);
            s.sample_rate = if v == 0 { 44100 } else { v };
        };
}
