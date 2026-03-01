# Music Player

This guide describes the standard music-player pipeline and the control model
used for track navigation, playback continuity, and status reporting.

## Reference Graph

```
button* -> merge -> gesture --ctrl--> bank --audio--> decoder -> i2s
                                      |
                                      +--status--> display (optional)

sd -> fat32 --files--> bank
```

## Architectural Roles

- `sd` provides block-level storage access.
- `fat32` maps file indices to filesystem data streams.
- `bank` owns track selection, navigation commands, and auto-advance policy.
- `decoder` converts encoded audio into PCM.
- `i2s` streams PCM to hardware output.
- `gesture` maps raw input actions into semantic control messages.

## Control Model

The music player treats navigation and playback as control-plane concerns and
audio bytes as data-plane flow.

- Control plane: `gesture -> bank` (`next`, `prev`, `toggle`, `select`)
- Data plane: `fat32 -> bank -> decoder -> i2s`
- Status plane: `bank -> display` (current index, count, file type, paused flag)

This separation keeps user interaction deterministic even when storage or decode
latency varies between files.

## Track Switching Semantics

On track changes, the pipeline performs a clean cutover to avoid mixed-stream
decode state:

1. Signal end-of-stream toward `decoder`.
2. Flush buffered audio bytes in transit.
3. Seek upstream to the selected file.
4. Resume flow; `decoder` re-enters format detection for the new stream.

At natural file end, `fat32` signals stream completion and `bank` applies the
configured policy (`once` or `loop`) to determine the next action.

## Configuration Surface

`bank` parameters define playlist behavior:

- `file_count`: total indexed files
- `mode`: play once or loop
- `initial_index`: startup selection

Runtime control uses message-based commands (`next`, `prev`, `toggle`,
`select(index)`), allowing the same pipeline to be driven by buttons, touch, or
remote control sources.

## Integration Notes

- For pipeline and channel behavior, see `docs/architecture/pipeline.md`.
- For scheduler timing assumptions, see `docs/architecture/timing.md`.
- For audio-format and decoder details, see `docs/guides/audio.md`.

This guide defines the intended architecture for the music-player path, while
module READMEs remain the source of module-local implementation details.
