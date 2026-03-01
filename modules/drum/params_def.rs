// Drum parameter definitions (single source of truth).
//
// Generates: dispatch_param(), set_defaults(), parse_tlv_v2(), PARAM_SCHEMA.

use super::DrumState;
use super::{p_u8, p_u32};
use super::SCHEMA_MAX;

define_params! {
    DrumState;

    1, sample_rate, u32, 8000
        => |s, d, len| {
            let sr = p_u32(d, len, 0, 8000);
            s.sample_rate = if sr > 0 { sr } else { 8000 };
        };

    2, level, u8, 200
        => |s, d, len| { s.level = p_u8(d, len, 0, 200); };

    3, kick_decay, u8, 180
        => |s, d, len| { s.kick_decay = p_u8(d, len, 0, 180); };

    4, kick_pitch, u8, 60
        => |s, d, len| { s.kick_pitch = p_u8(d, len, 0, 60); };

    5, snare_decay, u8, 120
        => |s, d, len| { s.snare_decay = p_u8(d, len, 0, 120); };

    6, snare_tone, u8, 128
        => |s, d, len| { s.snare_tone = p_u8(d, len, 0, 128); };

    7, hat_decay, u8, 60
        => |s, d, len| { s.hat_decay = p_u8(d, len, 0, 60); };
}
