// Synth constants, buffer sizes, and lookup tables.

pub const PARAMS_SIZE: usize = 256; // TLV format needs room for extensible tags
pub const OUT_BUF_SIZE: usize = 256;
pub const NOTE_EVENT_SIZE: usize = 8;
pub const SAMPLES_PER_CHUNK: usize = 64;
pub const EVENT_QUEUE_SIZE: usize = 4;
pub const MAX_VOICES: usize = 16;
pub const MAX_POLY: usize = 4;
// Ctrl message types
pub const CTRL_PATCH: u8 = 0x00;
pub const CTRL_RELOAD: u8 = 0x01;

// Waveforms
pub const WAVE_SAW: u8 = 0;
pub const WAVE_SQUARE: u8 = 1;
pub const WAVE_TRIANGLE: u8 = 2;
pub const WAVE_PULSE: u8 = 3;
pub const WAVE_NOISE: u8 = 4;
pub const WAVE_SINE: u8 = 5;

// Glide modes
pub const GLIDE_OFF: u8 = 0;
pub const GLIDE_ALWAYS: u8 = 1;
pub const GLIDE_LEGATO: u8 = 2;

/// ADSR envelope phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum EnvPhase {
    Idle = 0,
    Attack = 1,
    Decay = 2,
    Sustain = 3,
    Release = 4,
}

// Pluck oscillator
pub const WAVE_PLUCK: u8 = 6;
pub const PLUCK_BUF_SIZE: usize = 128; // Supports ~60Hz at 8kHz

// Sample & hold (LFO only — random value latched once per cycle)
pub const WAVE_SAMPLE_HOLD: u8 = 7;

// LFO target bitmask
pub const LFO_TGT_CUTOFF: u8 = 0x01;
pub const LFO_TGT_PITCH: u8 = 0x02;
pub const LFO_TGT_LEVEL: u8 = 0x04;
pub const LFO_TGT_RESONANCE: u8 = 0x08;
pub const LFO_TGT_PULSE_WIDTH: u8 = 0x10;
pub const LFO_TGT_PAN: u8 = 0x20;

// Quarter-wave sine table for audio oscillator (256 entries, i16, 0..32767)
// sin(i * pi/512) * 32767 for i = 0..255
pub const SINE_QUARTER: [i16; 256] = [
    0, 201, 402, 603, 804, 1005, 1206, 1407, 1608, 1809, 2009, 2210, 2410, 2611, 2811, 3012, 3212,
    3412, 3612, 3811, 4011, 4210, 4410, 4609, 4808, 5007, 5205, 5404, 5602, 5800, 5998, 6195, 6393,
    6590, 6786, 6983, 7179, 7375, 7571, 7767, 7962, 8157, 8351, 8545, 8739, 8933, 9126, 9319, 9512,
    9704, 9896, 10087, 10278, 10469, 10659, 10849, 11039, 11228, 11417, 11605, 11793, 11980, 12167,
    12353, 12539, 12725, 12910, 13094, 13279, 13462, 13645, 13828, 14010, 14191, 14372, 14553,
    14732, 14912, 15090, 15269, 15446, 15623, 15800, 15976, 16151, 16325, 16499, 16673, 16846,
    17018, 17189, 17360, 17530, 17700, 17869, 18037, 18204, 18371, 18537, 18703, 18868, 19032,
    19195, 19357, 19519, 19680, 19841, 20000, 20159, 20317, 20475, 20631, 20787, 20942, 21096,
    21250, 21403, 21554, 21705, 21856, 22005, 22154, 22301, 22448, 22594, 22739, 22884, 23027,
    23170, 23311, 23452, 23592, 23731, 23870, 24007, 24143, 24279, 24413, 24547, 24680, 24811,
    24942, 25072, 25201, 25329, 25456, 25582, 25708, 25832, 25955, 26077, 26198, 26319, 26438,
    26556, 26674, 26790, 26905, 27019, 27133, 27245, 27356, 27466, 27575, 27683, 27790, 27896,
    28001, 28105, 28208, 28310, 28411, 28510, 28609, 28706, 28803, 28898, 28992, 29085, 29177,
    29268, 29358, 29447, 29534, 29621, 29706, 29791, 29874, 29956, 30037, 30117, 30195, 30273,
    30349, 30424, 30498, 30571, 30643, 30714, 30783, 30852, 30919, 30985, 31050, 31113, 31176,
    31237, 31297, 31356, 31414, 31470, 31526, 31580, 31633, 31685, 31736, 31785, 31833, 31880,
    31926, 31971, 32014, 32057, 32098, 32137, 32176, 32213, 32250, 32285, 32318, 32351, 32382,
    32412, 32441, 32469, 32495, 32521, 32545, 32567, 32589, 32609, 32628, 32646, 32663, 32678,
    32692, 32705, 32717, 32728, 32737, 32745, 32752, 32757, 32761, 32765, 32766,
];

// Sine table for LFO
pub const SINE_TABLE: [i8; 64] = [
    0, 3, 6, 9, 12, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 51, 54, 57, 60, 62, 65, 67, 70,
    72, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93, 94, 96, 97, 99, 100, 101, 102, 104, 105, 105, 106,
    107, 108, 108, 109, 109, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110, 110,
];
