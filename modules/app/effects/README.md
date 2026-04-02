# effects Module

Effects Chain PIC Module

Detailed design notes are in [DESIGN.md](./DESIGN.md).

## Files

- `manifest.toml`
- `mod.rs`
- `comb.rs`
- `compressor.rs`
- `constants.rs`
- `effects.rs`
- `eq.rs`
- `flanger.rs`
- `gate.rs`
- `granular.rs`
- `harmonizer.rs`
- `limiter.rs`
- `phaser.rs`
- `pitch_shift.rs`
- `reverb.rs`
- `ring_mod.rs`
- `state.rs`
- `tlv.rs`
- `tremolo.rs`
- `waveshaper.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio"
direction = "input"
content_type = "AudioPcm"
required = true

[[ports]]
name = "processed"
direction = "output"
content_type = "AudioPcm"
required = true

[[ports]]
name = "preset"
direction = "ctrl_input"
content_type = "FmpMessage"

[commands]
accepts = ["next", "prev"]
```

## Parameters

- `bitcrush_bits`
- `bitcrush_rate_div`
- `buffer_mode`
- `chorus_depth_ms`
- `chorus_mix`
- `chorus_rate`
- `comb_delay_ms`
- `comb_feedback`
- `comb_mix`
- `compressor_attack_ms`
- `compressor_makeup`
- `compressor_mix`
- `compressor_ratio`
- `compressor_release_ms`
- `compressor_threshold`
- `delay_feedback`
- `delay_filter`
- `delay_mix`
- `delay_ms`
- `duck_amount`
- `duck_release_ms`
- `duck_target`
- `eq_high_freq`
- `eq_high_gain`
- `eq_low_freq`
- `eq_low_gain`
- `eq_mid_freq`
- `eq_mid_gain`
- `eq_mid_q`
- `flanger_depth`
- `flanger_feedback`
- `flanger_manual`
- `flanger_mix`
- `flanger_rate`
- `fx_lfo_depth`
- `fx_lfo_rate`
- `fx_lfo_shape`
- `fx_lfo_target`
- `gate_attack_ms`
- `gate_release_ms`
- `gate_threshold`
- `granular_density`
- `granular_grain_size_ms`
- `granular_mix`
- `granular_pitch`
- `granular_spread`
- `harmonizer_dry_level`
- `harmonizer_voice1_level`
- `harmonizer_voice1_semitones`
- `harmonizer_voice2_level`
- `harmonizer_voice2_semitones`
- `limiter_mode`
- `limiter_threshold`
- `macro1_depth`
- `macro2_depth`
- `overdrive_gain`
- `overdrive_tone`
- `phaser_depth`
- `phaser_feedback`
- `phaser_mix`
- `phaser_rate`
- `phaser_stages`
- `pitch_shift_mix`
- `pitch_shift_semitones`
- `pitch_shift_window_ms`
- `reverb_damping`
- `reverb_decay`
- `reverb_mix`
- `reverb_predelay_ms`
- `ring_mod_freq`
- `ring_mod_mix`
- `sample_rate`
- `tremolo_depth`
- `tremolo_rate`
- `tremolo_shape`
- `waveshaper_amount`
- `waveshaper_curve`
- `waveshaper_mix`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
