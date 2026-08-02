# sequencer Module

Sequencer PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`
- `presets.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "control"
direction = "input"
content_type = "FmpMessage"

[[ports]]
name = "notes"
direction = "output"
content_type = "OctetStream"
required = true

[commands]
accepts = ["status", "toggle", "select"]
```

## Parameters

- `auto_advance_preset`
- `fill_on_loop_end`
- `humanize_prob`
- `mode`
- `octave_range`
- `play_every_n_loops`
- `preset`
- `probability`
- `random_pitch`
- `ratchet_count`
- `ratchet_spacing`
- `ratchet_velocity_falloff`
- `retrigger`
- `sample_rate`
- `skip_probability`
- `step_ms`
- `timing_jitter_ms`
- `velocity_jitter_pct`
- `velocity_max`
- `velocity_min`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
