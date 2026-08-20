# Music Player

The music player is a composition of foundation and driver modules:
storage feeds an asset bank, the bank streams the selected track to an
audio sink, and a button-driven gesture module supplies navigation
commands. This guide describes the graph shape and its control model.

Source: `modules/foundation/fs_bank/`, `modules/foundation/gesture/`,
`modules/foundation/fat32/`, `modules/foundation/sd/`,
`modules/drivers/button/`, `modules/drivers/i2s_pio/`.

## Reference graph

```text
button --raw--> gesture --commands--> bank --stream--> i2s_pio
                                        |
                                        +--notify--> display (optional)

sd --blocks--> fat32        (bank opens files through the fs contract)
```

- `sd` provides block-level storage.
- `fat32` consumes those blocks and provides the `fs` contract.
- `bank` (`type: fs_bank`) opens its configured `path_N` files through
  that contract; there is no wired data edge from `fat32` to the bank.
- `i2s_pio` consumes the audio stream and drives the I2S output on
  RP2350. On other targets the sink differs: `linux_audio` on the
  Linux host, `wasm_browser_audio` in the browser.
- `button` emits raw press events; `gesture` turns clicks, double
  clicks, and long presses into FMP commands.

The wired stream carries whatever bytes the files hold. Raw PCM can
feed `i2s_pio` directly; encoded formats splice a codec module
(spectra) between `bank.stream` and the sink, and the `format` module
converts sample rate, width, and channel count where the source and
sink disagree.

## Control model

Navigation and playback are control-plane concerns; audio bytes are
data-plane flow.

- Control plane: `gesture -> bank` (`next`, `prev`, `toggle`,
  `select`)
- Data plane: `bank -> [codec ->] i2s_pio`
- Status plane: `bank.notify -> display`, a `status` message per
  selection change carrying `{ index, count, file_type, flags }`

This separation keeps user interaction responsive when storage or
decode latency varies between files.

## Track switching

The bank walks files one at a time: the next path opens only after the
current file reaches end of stream or a navigation command arrives. On
navigation the bank drops the current stream and opens the selected
path, so downstream stages see a clean stream boundary. At natural
file end, `auto_advance` moves to the next index and `mode` decides
what happens past the last entry (`loop` wraps, `once` and `hold`
stop).

## Configuration

`fs_bank` parameters ([asset_banks.md](asset_banks.md) has the full
set):

- `path_0` … : one file path per index
- `item_count` (alias `file_count`): navigation positions, derived
  from the paths when unset
- `mode`: `once`, `loop`, or `hold`
- `initial_index`: startup selection
- `auto_advance`: advance on end of stream

Runtime control is message-based, so the same graph can be driven by
buttons, touch, or remote-control sources; only the module feeding
`gesture` (or `bank.commands` directly) changes.

## Related documentation

- [asset_banks.md](asset_banks.md) — bank ports, commands, parameters
- [audio.md](audio.md) — audio formats and pipeline stages
- [../architecture/pipeline.md](../architecture/pipeline.md) — channel
  behaviour
- [../architecture/timing.md](../architecture/timing.md) — scheduler
  timing
