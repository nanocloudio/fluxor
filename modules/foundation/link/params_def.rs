use super::LinkState;
use super::{p_u8, p_u16, p_u32};
use super::SCHEMA_MAX;

define_params! {
    LinkState;

    1, uart_bus, u8, 0
        => |s, d, len| { s.uart_bus = p_u8(d, len, 0, 0); };

    2, baud, u32, 3000000
        => |s, d, len| { s.baud = p_u32(d, len, 0, 3000000); };

    3, block_size, u16, 512
        => |s, d, len| { s.block_size = p_u16(d, len, 0, 512); };

    4, jitter_depth, u8, 3
        => |s, d, len| {
            let v = p_u8(d, len, 0, 3);
            s.jitter_depth = if v > 6 { 6 } else if v < 2 { 2 } else { v };
        };

    5, pipeline_latency, u16, 1024
        => |s, d, len| { s.pipeline_latency = p_u16(d, len, 0, 1024); };

    6, mode, u8, 0
        => |s, d, len| {
            let v = p_u8(d, len, 0, 0);
            s.mode = if v > 2 { 0 } else { v };
        };
}
