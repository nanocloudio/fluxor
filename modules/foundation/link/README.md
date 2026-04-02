# link Module

Link — bidirectional audio/control transport over UART.

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio_in"
direction = "input"
content_type = "AudioPcm"

[[ports]]
name = "audio_out"
direction = "output"
content_type = "AudioPcm"

[[ports]]
name = "ctrl_fwd"
direction = "output"
content_type = "FmpMessage"

[[ports]]
name = "control"
direction = "ctrl_input"
content_type = "FmpMessage"

[[resources]]
device_class = "uart"
access = "exclusive"
```

## Parameters

- `baud`
- `block_size`
- `jitter_depth`
- `mode`
- `pipeline_latency`
- `uart_bus`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
