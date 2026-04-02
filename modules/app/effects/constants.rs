// Effects constants, buffer sizes, and lookup tables.

pub const PARAMS_SIZE: usize = 256;
pub const MAX_VOICES: usize = 16;
pub const OUT_BUF_SIZE: usize = 512; // 128 stereo frames * 4 bytes
pub const SAMPLES_PER_CHUNK: usize = 64;

// Ctrl message types
pub const CTRL_PATCH: u8 = 0x00;
pub const CTRL_RELOAD: u8 = 0x01;

// FX LFO target bits
pub const FX_LFO_TGT_DELAY_MIX: u8 = 0x01;
pub const FX_LFO_TGT_REVERB_MIX: u8 = 0x02;
pub const FX_LFO_TGT_CHORUS_MIX: u8 = 0x04;
pub const FX_LFO_TGT_FLANGER_MIX: u8 = 0x08;
pub const FX_LFO_TGT_PHASER_MIX: u8 = 0x10;
pub const FX_LFO_TGT_GRANULAR_MIX: u8 = 0x20;

// Effect enable flags (u32 bitmask)
pub const FX_CHORUS: u32 = 0x0001;
pub const FX_DELAY: u32 = 0x0002;
pub const FX_OVERDRIVE: u32 = 0x0004;
pub const FX_BITCRUSH: u32 = 0x0008;
pub const FX_TREMOLO: u32 = 0x0010;
pub const FX_RING_MOD: u32 = 0x0020;
pub const FX_WAVESHAPER: u32 = 0x0040;
pub const FX_LIMITER: u32 = 0x0080;
pub const FX_GATE: u32 = 0x0100;
pub const FX_COMPRESSOR: u32 = 0x0200;
pub const FX_PHASER: u32 = 0x0400;
pub const FX_EQ: u32 = 0x0800;
pub const FX_FLANGER: u32 = 0x1000;
pub const FX_COMB: u32 = 0x2000;
pub const FX_REVERB: u32 = 0x4000;
pub const FX_PITCH_SHIFT: u32 = 0x8000;
pub const FX_HARMONIZER: u32 = 0x10000;
pub const FX_GRANULAR: u32 = 0x20000;

// Gate states
pub const GATE_CLOSED: u8 = 0;
pub const GATE_ATTACK: u8 = 1;
pub const GATE_OPEN: u8 = 2;
pub const GATE_HOLD: u8 = 3;
pub const GATE_RELEASE: u8 = 4;

// Phaser
pub const MAX_PHASER_STAGES: usize = 6;

// EQ
pub const NUM_EQ_BANDS: usize = 3;

// Buffer sizes
pub const CHORUS_BUF_FRAMES: usize = 160;  // ~20ms at 8kHz
pub const DELAY_BUF_FRAMES: usize = 2048;  // ~93ms at 22kHz, ~256ms at 8kHz
pub const FLANGER_BUF_SIZE: usize = 128;   // ~10ms at 8kHz per channel
pub const COMB_BUF_SIZE: usize = 400;      // 50ms at 8kHz, 8-bit mono

// Reverb buffer component sizes (at 8kHz)
pub const REVERB_COMB_LEN_1: usize = 307;  // ~38ms
pub const REVERB_COMB_LEN_2: usize = 353;  // ~44ms
pub const REVERB_COMB_LEN_3: usize = 389;  // ~49ms
pub const REVERB_COMB_LEN_4: usize = 433;  // ~54ms
pub const REVERB_ALLPASS_LEN_1: usize = 89;  // ~11ms
pub const REVERB_ALLPASS_LEN_2: usize = 127; // ~16ms
pub const REVERB_PREDELAY_MAX: usize = 400;  // 50ms at 8kHz
pub const REVERB_TOTAL_BUF: usize = REVERB_COMB_LEN_1 + REVERB_COMB_LEN_2
    + REVERB_COMB_LEN_3 + REVERB_COMB_LEN_4
    + REVERB_ALLPASS_LEN_1 + REVERB_ALLPASS_LEN_2
    + REVERB_PREDELAY_MAX; // 2098

// Pitch shift / harmonizer
pub const PITCH_BUF_SIZE: usize = 800;     // 100ms at 8kHz per channel
pub const HARM_WINDOW_SIZE: u16 = 200;     // Crossfade window for harmonizer

// Granular
pub const GRAIN_BUF_SIZE: usize = 1600;    // 200ms at 8kHz, mono
pub const MAX_GRAINS: usize = 4;

// Semitone to ratio lookup table (12 entries for one octave, Q16 format)
pub const SEMITONE_RATIOS: [u32; 13] = [
    65536,  // 0: 1.0
    69433,  // 1: 1.059
    73562,  // 2: 1.122
    77936,  // 3: 1.189
    82570,  // 4: 1.260
    87480,  // 5: 1.335
    92682,  // 6: 1.414
    98193,  // 7: 1.498
    104032, // 8: 1.587
    110218, // 9: 1.682
    116772, // 10: 1.782
    123715, // 11: 1.888
    131072, // 12: 2.0
];

// Sine table for LFO
pub const SINE_TABLE: [i8; 64] = [
    0, 3, 6, 9, 12, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46,
    49, 51, 54, 57, 60, 62, 65, 67, 70, 72, 75, 77, 79, 81, 83, 85,
    87, 89, 91, 93, 94, 96, 97, 99, 100, 101, 102, 104, 105, 105, 106, 107,
    108, 108, 109, 109, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
];
