# Codec Porting and Validation

This guide describes the workflow for bringing an audio decoder under
`modules/app/codec/` to parity with an external reference decoder. It is
based on the MP3 porting work, but the process is codec-independent.

The purpose is to avoid debugging the live Fluxor pipeline before the
decoder DSP is correct. First prove the decoder in isolation, then wire
it into the runtime, then chase transport or scheduling issues.

## Short Version

1. Build a reference decoder first. It should produce PCM and optional
   per-stage probe dumps.
2. Port in `f32` when the target set supports it. It is shorter, easier
   to audit, and closer to common reference implementations.
3. Build a standalone Rust replica of the codec DSP outside the Fluxor
   runtime. It should share the same decode logic as the module.
4. Diff per-stage probes to find the first divergent layer.
5. Only after the standalone replica matches the reference should you
   test the WebSocket or browser harness.

## Reference Decoder

Use a known decoder as the authority for both PCM and intermediate state.
Keep reference sources and scratch probes outside the repository unless
they are small, licensed appropriately, and intended to become test
fixtures.

For MP3, the port used `minimp3` as the reference. For AAC-LC, use a
reference such as FAAD2 or another decoder whose behavior you can inspect
and reproduce.

The reference should be able to write records like:

```text
u32 magic       codec probe tag, for example MP3P or AACP
u32 frame       frame index
u32 unit        granule, window, or block index
u32 channel     channel index
u32 stage       decoder stage id
u32 count       number of f32 values
f32[count]      spectral or time-domain values
```

The exact stage list is codec-specific. Pick boundaries that match the
reference implementation's named phases, such as Huffman decode,
requantization, stereo processing, windowing, IMDCT, overlap, or final
PCM conversion.

## Standalone Rust Replica

The standalone replica is the highest-value debugging artifact. It is a
normal `std` Rust binary that copies or shares the codec DSP from
`modules/app/codec/<name>_codec.rs`, reads an encoded file, writes PCM,
and optionally writes the same probe records as the C reference.

It should not depend on the Fluxor scheduler, channels, loader, or host
runtime. The point is to answer one question cleanly: does the decoder
math match the reference?

The replica usually needs small substitutions:

- replace `SyscallTable` fields with inert placeholders
- remove or stub runtime logging calls
- replace channel writes with file writes
- expose probe hooks around the same decode stages

When the replica matches the reference, any remaining mismatch in a live
Fluxor run is likely in stream framing, channel scheduling, parameters,
initialisation order, or browser/host transport.

## Float Port Pattern

Prefer `f32` for codecs whose supported targets have hardware or efficient
native floating point. It keeps the code close to the reference decoder
and avoids Q-format bookkeeping.

Target filtering still matters. If a codec depends on floating point, its
manifest should list only the verified `hardware_targets`. Do not let an
RP2040 build try to link a decoder that requires hardware floating point.

After adding a target to a codec manifest:

- build the module for that target
- run the standalone replica against the same fixture
- run the Fluxor harness for that target or host
- update the supported-format table only after the harness passes

## Bug Patterns

These are the failure modes that tend to survive code review because the
decoder still produces plausible audio:

- **Exponent offsets.** Re-derive scalefactor and gain exponents from the
  standard or the reference code. A one-step exponent error can sound
  merely "too quiet" while destroying numeric parity.
- **Band tables keyed by block type.** Long, short, start, and stop
  windows often use different scale-factor-band offsets. The wrong table
  can keep reads in bounds while corrupting the spectrum.
- **Window-shape dispatch.** Wrong window selection usually appears as
  clicks, transient fuzz, or peak/RMS drift while average energy still
  looks reasonable.
- **Stereo normalization.** Some references fold the normalization into a
  band gain rather than the stereo transform itself. Do not add an extra
  divide just because the formula looks familiar.
- **Rounding sign.** Final PCM conversion often has exact reference
  behavior around negative values. LSB drift is small per sample but
  obvious in long fixture diffs.
- **Frame alignment and priming.** Encoder delay, pre-trim, and final
  padding must be explicit in the diff harness.

## Fluxor Harness Checks

Once the standalone decoder matches the reference, test the module in the
Fluxor graph. The common harness path is:

```text
encoded asset
  -> codec module
  -> PCM channel
  -> ws_stream or audio sink
  -> capture client
  -> diff_<codec>.py
```

Check these before blaming the DSP:

- The codec output channel has enough buffer space for the fixture and
  client startup latency.
- Each `channel_write` maps cleanly to the downstream framing model.
  Tiny writes can expose bugs in fan-out or envelope parsing even when
  the decoder is correct.
- Browser and WASM bundles were rebuilt after the codec `.fmod` changed.
- The capture client trims priming and padding the same way as the
  reference comparison.
- Host and browser caches are not serving a stale bundle.

## Definition of Done

Use one fixture that exercises steady-state decode and one that exercises
transitions. A codec port is done when the standalone replica and the
Fluxor harness both satisfy the same thresholds:

| Metric | Target |
| --- | --- |
| Full-duration correlation with reference | >= 0.995 |
| Per-section RMS | within +/- 2% of reference |
| Sample-wise mean absolute delta | <= 50 |
| Sample-wise max absolute delta | <= 500, unless a documented priming edge explains it |
| Saturated samples | 0 |
| Peak/RMS ratio | within +/- 10% of reference |
| Verified target builds | every declared `hardware_target` |
| Harness coverage | all affected Fluxor example or test-harness graphs pass |

If a codec cannot meet one of these thresholds because the reference
decoder differs intentionally from the target behavior, document that in
the module or harness next to the fixture and make the exception specific.

## What To Commit

Commit only stable artifacts:

- codec source under `modules/app/codec/`
- manifest target updates
- small fixtures that are license-compatible and useful long term
- diff scripts and harness configs under `examples/test_harness/`
- module README notes for codec-specific alignment, tables, or known
  deviations

Do not commit large scratch probes, dated porting diaries, or temporary
reference source checkouts. They are useful while porting, but public
docs should describe the current workflow and current support status.
