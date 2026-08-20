# Asset Banks

An asset bank packages a set of assets behind an index and streams the
selected one to the rest of the graph. Selection changes through
commands, not rewiring, so playback, sequencing, and UI flows keep a
stable topology while the content varies at runtime.

Source: `modules/sdk/cores/bank_stream.rs` (shared navigation and
streaming core), `modules/foundation/fs_bank/`,
`modules/foundation/object_bank/`.

## Model

```text
storage backend -> bank -> consumer
                    ^
                    |
                 control
```

- The bank owns index selection and progression policy.
- Consumers (codecs, synthesis modules, displays) see only the
  selected asset's byte stream.
- Control modules (typically `gesture`) drive selection through
  FMP commands.

## Implementations

Both banks share the `bank_stream` core, so navigation, commands, and
status behave identically; only the storage backend differs.

- `fs_bank` reads files through the `fs` contract (`fat32` on bare
  metal, the host filesystem dispatch on Linux). Entries come either
  from explicit `path_N` parameters or from a directory scan.
- `object_bank` enumerates a key prefix via `storage.namespace` LIST
  and streams entries via `storage.object` GET/RANGE_GET. It works
  against any provider pair that offers those surfaces, including the
  browser's OPFS-backed object store on the wasm host.

## Ports

- `stream` (output, `OctetStream`): the selected asset's bytes.
  Entries are walked one at a time; the next opens only after the
  current one reaches end of stream or a navigation command arrives.
- `notify` (output, `FmpMessage`): a `status` notification on each
  selection change, carrying `{ index, count, file_type, flags }` for
  UI and telemetry consumers.
- `commands` (ctrl input, `FmpMessage`): accepts `next`, `prev`,
  `toggle` (pause/resume), and `select` with a `u16` index payload.

Keeping the data plane (`stream`) and status plane (`notify`) on
separate ports lets display updates and media transport back-pressure
independently.

## Parameters

- `item_count` (alias `file_count`): navigation positions; derived
  from the populated `path_N` slots when unset.
- `mode`: `once`, `loop`, or `hold`. `loop` wraps navigation past
  either end of the index; the other two stop at the ends.
- `initial_index`: startup selection.
- `auto_advance`: advance to the next entry on end of stream.
- `path_0` … (`fs_bank`): one path per index. With no paths set the
  bank runs as a preset selector: navigation and status work, but no
  bytes flow downstream.

## Composition patterns

- music player: `fat32`-backed `fs_bank` streaming to a codec and an
  audio sink ([music_player.md](music_player.md))
- instrument or tone sets: bank selecting presets for a synthesis
  module
- image galleries: bank streaming to an image codec and a display

## Related documentation

- [music_player.md](music_player.md)
- [audio.md](audio.md)
- [../architecture/pipeline.md](../architecture/pipeline.md)
