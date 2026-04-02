# Audio Effects Module Reference

This document provides a comprehensive taxonomy of audio effects modules available and planned for Fluxor.

## Overview

Effects are organized into categories based on their primary function. Each module is designed for minimal RAM usage while providing quality audio processing suitable for embedded applications.

## Module Status Legend

| Symbol | Meaning |
|--------|---------|
| ✓ | Implemented and tested |
| 🔨 | Recently added, needs testing |
| □ | Planned / Not yet implemented |

---

## SYNTHESIS (Sound Generation)

Sound sources that generate audio from scratch.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| **Oscillator** | `oscillator` | ~1KB | ✓ | Multi-waveform with vibrato |
| **Noise** | `noise` | ~512B | ✓ | White/pink noise generator |
| **Pluck** | `pluck` | ~512B | ✓ | Karplus-Strong string synthesis |
| **Monosynth** | `monosynth` | ~2KB | 🔨 | Complete mono voice (osc+filter+env) |
| Wavetable | `wavetable` | ~4KB | □ | Wavetable oscillator |
| Drum Synth | `drum` | ~1KB | □ | Analog-style drum synthesis |
| FM Synth | `fmsynth` | ~2KB | □ | 2-4 operator FM |

### Oscillator Waveforms
- **Sawtooth**: Rich harmonics, classic for bass/lead
- **Square**: Hollow, woody character
- **Triangle**: Soft, flute-like
- **Pulse**: Variable width for PWM
- **Noise**: White noise for FX/percussion

### Monosynth Features
- Multi-waveform oscillator with sub-oscillator
- Resonant filter with envelope modulation
- Separate filter and amp ADSR envelopes
- Glide/portamento (off, always, legato)
- Soft saturation drive
- Runtime parameter control via ctrl channel

---

## FILTER (Frequency Shaping)

Modules that shape the frequency content of audio.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| **Filter** | `filter` | ~1KB | ✓ | Resonant LP/HP/BP |
| **Comb** | `comb` | ~400B | ✓ | Short delay + feedback (metallic) |
| Allpass | `allpass` | ~256B | □ | Phase shift (reverb building block) |
| Parametric EQ | `eq` | ~2KB | □ | Multi-band equalization |
| Formant | `formant` | ~1KB | □ | Vowel/vocal filtering |
| Wah | `wah` | ~1KB | □ | Swept bandpass (auto-wah) |

### Filter Types
- **Lowpass (LP)**: Removes high frequencies
- **Highpass (HP)**: Removes low frequencies
- **Bandpass (BP)**: Passes frequencies around cutoff

### Comb Filter Applications
- **Short delay (10-30 samples)**: Metallic, robotic
- **Medium delay (50-100 samples)**: Flanger-like
- **High feedback**: Resonant, ringing tones

---

## TIME (Delay-Based Effects)

Effects based on delayed copies of the signal.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| **Delay** | `delay` | ~16KB | ✓ | Multi-tap with modulation |
| **Chorus** | `chorus` | ~640B | ✓ | Modulated short delay |
| Flanger | `flanger` | ~400B | □ | Very short modulated delay |
| Phaser | `phaser` | ~512B | □ | Cascaded allpass filters |
| Reverb | `reverb` | ~8-32KB | □ | Room simulation |

### Delay Features (Enhanced)
- **Multi-tap**: Up to 4 independent delay taps
- **Modulation**: LFO wobble for tape-echo character
- **Filtered feedback**: Darkening repeats
- **Ping-pong**: Stereo alternating effect

### Chorus Settings Guide
| Rate | Depth | Character |
|------|-------|-----------|
| 0.5Hz | 2ms | Subtle thickening |
| 1-2Hz | 4-6ms | Classic chorus |
| 3-5Hz | 8-10ms | Vibrato/Leslie |

---

## DYNAMICS (Amplitude Control)

Modules that control signal level and dynamics.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| **Gain** | `gain` | ~1KB | ✓ | Level control |
| **Limiter** | `limiter` | ~1KB | ✓ | Hard/soft clip |
| **Envelope** | `envelope` | ~1KB | ✓ | ADSR amplitude shaping |
| Compressor | `compressor` | ~1KB | □ | Dynamic range control |
| Gate | `gate` | ~1KB | □ | Noise gate/expander |
| Tremolo | `tremolo` | ~512B | □ | LFO amplitude modulation |

### Limiter Modes
- **Hard clip**: Instant limiting at threshold
- **Soft clip**: Smooth tanh-like saturation curve

---

## DISTORTION (Waveshaping)

Effects that add harmonic content through nonlinear processing.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| Soft Clip | (in limiter) | - | ✓ | Gentle saturation |
| Overdrive | `overdrive` | ~512B | □ | Asymmetric soft clip |
| Fuzz | `fuzz` | ~512B | □ | Hard clip + filter |
| Bitcrush | `bitcrush` | ~256B | □ | Sample rate + bit reduction |
| Wavefold | `wavefold` | ~512B | □ | Folding distortion |

---

## PITCH (Frequency Manipulation)

Effects that alter pitch or create harmonics.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| Vibrato | (in oscillator) | - | ✓ | Pitch modulation |
| Octaver | `octaver` | ~1KB | □ | Sub/super octave |
| Pitch Shift | `pitchshift` | ~4KB | □ | Granular pitch change |
| Harmonizer | `harmonizer` | ~8KB | □ | Intelligent pitch shift |

---

## MODULATION (Parameter Animation)

LFO and modulation utilities.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| Internal LFO | (in modules) | - | ✓ | Built into delay/chorus/etc |
| Ring Mod | `ringmod` | ~256B | □ | Multiply two signals |
| Sample & Hold | `samplehold` | ~256B | □ | Random stepped modulation |
| Env Follower | `envfollow` | ~512B | □ | Extract envelope from audio |

---

## UTILITY (Routing/Mixing)

Helper modules for signal routing.

| Module | Code | RAM | Status | Description |
|--------|------|-----|--------|-------------|
| **Mixer** | `mixer` | ~1KB | ✓ | Multi-input mixing |
| **Resampler** | `resampler` | ~2KB | ✓ | Sample rate conversion |
| Pan | `pan` | ~512B | □ | Stereo positioning |
| Crossfade | `crossfade` | ~512B | □ | Blend two sources |

---

## Effect Dependencies

Some effects are building blocks for others:

```
         ┌─────────┐
         │ allpass │ ←── building block
         └────┬────┘
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌────────┐
│phaser │ │reverb │ │diffuser│
└───────┘ └───────┘ └────────┘

         ┌─────────┐
         │  delay  │ ←── building block
         └────┬────┘
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐
│chorus │ │flanger│ │ echo  │
└───────┘ └───────┘ └───────┘

         ┌─────────┐
         │   LFO   │ ←── built into modules
         └────┬────┘
              │
    ┌────┬────┼────┬────┐
    ▼    ▼    ▼    ▼    ▼
tremolo vibrato chorus phaser wah
```

---

## Preset Examples

### Acid Bass (TB-303 Style)
```yaml
synth:
  type: monosynth
  waveform: saw
  cutoff: 60
  resonance: 230
  env_amount: 200
  filter_decay_ms: 120
  amp_decay_ms: 150
  amp_sustain: 0
  drive: 80
```

### Sub Bass
```yaml
synth:
  type: monosynth
  waveform: triangle
  sub_level: 220
  cutoff: 50
  resonance: 60
  filter_decay_ms: 400
  amp_sustain: 180
```

### Synth Lead
```yaml
synth:
  type: monosynth
  waveform: square
  cutoff: 120
  resonance: 140
  glide_ms: 60
  glide_mode: legato
  amp_sustain: 200
```

### Plucked String
```yaml
pluck:
  type: pluck
  decay: 252
  brightness: 220
  amplitude: 28000
```

---

## Implementation Priority

### Phase 1 - Core Synth (Current)
- ✓ oscillator, filter, envelope, gain, delay
- 🔨 monosynth

### Phase 2 - Essential Effects
- □ compressor
- □ reverb
- □ phaser
- □ bitcrush
- □ overdrive

### Phase 3 - Extended Palette
- □ flanger, tremolo, ring mod
- □ octaver, pitch shift
- □ parametric EQ
- □ drum synth, FM synth

### Phase 4 - Advanced
- □ vocoder, harmonizer
- □ granular, wavetable
- □ convolution reverb

---

## RAM Budget Guidelines

| Category | Typical RAM | Notes |
|----------|-------------|-------|
| Simple FX | 256-512B | Gate, pan, gain |
| Standard FX | 1-2KB | Filter, envelope, limiter |
| Delay-based | 4-16KB | Depends on max delay time |
| Synth voice | 2-4KB | Complete voice with state |
| Reverb | 8-32KB | Quality vs RAM tradeoff |

Total available: ~260KB (with current kernel)
Recommended per-pipeline: Keep under 32KB for flexibility
