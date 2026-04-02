use super::BrightnessState;
use super::{p_u8, p_u16};
use super::SCHEMA_MAX;

define_params! {
    BrightnessState;

    1, mode, u8, 0, enum { sequencer=0, audio=1 }
        => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

    2, curve, u8, 1, enum { linear=0, gamma22=1, gamma28=2, inv_gamma=3 }
        => |s, d, len| { s.curve = p_u8(d, len, 0, 1); };

    3, attack, u16, 2000
        => |s, d, len| { s.attack_coeff = p_u16(d, len, 0, 2000); };

    4, release, u16, 200
        => |s, d, len| { s.release_coeff = p_u16(d, len, 0, 200); };

    5, output_divider, u8, 1
        => |s, d, len| { s.output_divider = p_u8(d, len, 0, 1).max(1); };
}
