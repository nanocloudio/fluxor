# synth Module

Synth PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`
- `envelope.rs`
- `filter.rs`
- `oscillator.rs`
- `params.rs`
- `params_def.rs`
- `state.rs`
- `tlv.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "notes"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioSample"
required = true

[[ports]]
name = "preset"
direction = "ctrl_input"
content_type = "FmpMessage"

[commands]
accepts = ["next", "prev"]
```

## Parameters

- `accent`
- `amp_attack_ms`
- `amp_decay_ms`
- `amp_release_ms`
- `amp_sustain`
- `cutoff`
- `detune_curve`
- `drive`
- `env_amount`
- `env_loop`
- `filter_attack_ms`
- `filter_decay_ms`
- `filter_release_ms`
- `filter_sustain`
- `glide_mode`
- `glide_ms`
- `key_track`
- `level`
- `lfo_depth`
- `lfo_rate`
- `lfo_target`
- `lfo_waveform`
- `loop_rate_scale`
- `pan`
- `pluck_brightness`
- `pluck_decay`
- `polyphony`
- `pulse_width`
- `resonance`
- `sample_rate`
- `sub_level`
- `vel_to_cutoff`
- `vel_to_drive`
- `vel_to_env_amt`
- `vel_to_lfo_depth`
- `voice_count`
- `voice_detune_cents`
- `waveform`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
