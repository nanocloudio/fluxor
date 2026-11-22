# link Module

Link — bidirectional audio/control transport over UART.

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `audio_in` | input | `AudioSample` |  |
| `audio_out` | output | `AudioSample` |  |
| `ctrl_fwd` | output | `FmpMessage` |  |
| `control` | ctrl_input | `FmpMessage` |  |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `uart_bus` (u8, default 0): UART bus.
- `baud` (u32, default 3000000).
- `block_size` (u16, default 512): samples per audio block.
- `jitter_depth` (u8, default 3, clamped to 2–6): blocks of jitter buffer.
- `pipeline_latency` (u16, default 1024): samples TX runs ahead of the master.
- `mode` (u8, default 0): 0 = TX (audio from `audio_in` to the UART), 1 = RX
  (audio from the UART to `audio_out`), 2 = both. A value above 2 reads as 0.

The module declares `deferred_ready`: TX reports Ready once its UART is
configured, RX and bidirectional mode once the jitter buffer has filled.
