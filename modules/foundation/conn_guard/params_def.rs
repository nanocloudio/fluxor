use super::{p_u8, p_u16, GuardState, MAX_TABLE};
use super::SCHEMA_MAX;

define_params! {
    GuardState;

    1, rate_table_size, u8, MAX_TABLE as u32
        => |s, d, len| {
            let v = p_u8(d, len, 0, MAX_TABLE as u8);
            s.rate_table_size = if v == 0 { 1 } else if v as usize > MAX_TABLE { MAX_TABLE as u8 } else { v };
        };

    2, rate_limit_per_ip, u8, 16
        => |s, d, len| { s.rate_limit_per_ip = p_u8(d, len, 0, 16); };

    3, rate_window_ms, u16, 1000
        => |s, d, len| {
            let v = p_u16(d, len, 0, 1000);
            s.rate_window_ms = if v == 0 { 1 } else { v };
        };
}
