# voip Module

VoIP Module — G.711 codec + jitter buffer + SIP user agent

## Files

- `manifest.toml`
- `mod.rs`
- `g711.rs`
- `jitter.rs`
- `sip.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "mic"
direction = "input"
content_type = "AudioSample"

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioSample"
required = true

[[ports]]
name = "rtp"
index = 1
direction = "output"
content_type = "OctetStream"

[[ports]]
name = "sip_ctrl"
index = 2
direction = "output"
content_type = "OctetStream"

[[ports]]
name = "call"
direction = "ctrl_input"
content_type = "FmpMessage"

[[resources]]
requires_contract = "socket"
access = "write"
```

## Parameters

- `auto_answer`
- `jitter_ms`
- `local_ip`
- `local_sip_port`
- `peer_ip`
- `peer_sip_port`
- `ptime`
- `rtp_port`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
