# sequencer

Plays a stored sequence of values as timestamped note events, on the
stream clock rather than the wall clock.

## What it is for

A sequence is only musical if its steps land where they were meant to
land. Timing it from `millis()` means every step inherits whatever jitter
the scheduler had that tick, and the error accumulates over a bar. So each
event carries the frame it is *for*, computed from the sample rate, and a
consumer places it at that frame regardless of when the message arrived.

That is the whole reason this is a module rather than a loop in a consumer:
the frame arithmetic has to be done once, against the clock the audio path
actually uses.

## Ports

| Port | Direction | Purpose |
|---|---|---|
| `control` | input | FMP messages that select and steer playback. |
| `notes` | output | 8-byte events: `target_frame` u32, `freq` u16, `velocity` u8, `flags` u8. |

## Control

| Command | Effect |
|---|---|
| `status` | Report position and the live preset. |
| `toggle` | Pause or resume. |
| `select` | Jump to a preset by index. |
| `next` / `prev` | Step through presets, wrapping at each end. |

## Presets

Up to four sequences of up to 128 `u16` values each, supplied as repeated
`preset` parameters — one entry per preset, filling the slots in order.
`mode` decides how a sequence is traversed: `one_shot`, `loop`, or
`ping_pong`.

Holding presets in the module, rather than restating the sequence on every
change, is what lets `next`/`prev`/`select` be a single control message.

## Generative parameters

Beyond the stored sequence, the schema in `params_def.rs` declares
parameters that perturb playback: `probability` and `skip_probability` thin
the steps, `random_pitch` and `octave_range` move them, `velocity_min` /
`velocity_max` and `velocity_jitter_pct` shape dynamics,
`timing_jitter_ms` and `humanize_prob` loosen placement, `ratchet_count` /
`ratchet_spacing` / `ratchet_velocity_falloff` subdivide a step, and
`play_every_n_loops`, `fill_on_loop_end` and `auto_advance_preset` act
across whole passes.

Every one of them defaults to neutral rather than to zero — `probability`
to always, `ratchet_count` to a single hit, the velocities to a fixed
value, the jitters to none — so a graph that sets none of them plays the
stored sequence exactly as given. That matters because the same module has
to serve a deterministic test fixture and a generative instrument, and the
deterministic case is the one that must not need configuring.

## Parameters

Defaults and accepted spellings are declared in `params_def.rs`, the
single source of truth for the schema. `sample_rate` is declared first and
must stay first: `step_ms` derives `step_frames` from it, so it has to be
applied before that closure runs.
