# Codec Porting & Validation

This guide captures the workflow we developed bringing the unified codec's
MP3 decode to sample-accurate parity with `ffmpeg`'s `libmpg123` reference.
The same recipe applies to the AAC port (and any future essence decoder
sitting under `modules/app/codec/`).

The point of the document is not "MP3 is fixed" — it's "next time we wire a
new audio codec, here's the order to do the work in so we don't waste
days debugging the wrong layer."

## TL;DR

1. **Get a byte-exact reference decoder running first** — before you write or
   port any code. For MP3 we used `lieff/minimp3` (CC0, single-header C);
   for AAC use `FAAD2` or `fdk-aac` similarly.
2. **Float (`f32`) port, not fixed-point** — every Fluxor target except
   rp2040 has hardware single-precision FP. Stay in `f32` for clarity
   and so the math literally mirrors the reference.
3. **Build a standalone Rust replica of the codec's DSP** — same source
   files, no Fluxor runtime, no streaming, just file in → PCM file out.
   This is the diff target for "is my DSP correct?". Without it you'll
   spend hours chasing streaming bugs that aren't there.
4. **Layer-boundary probes** — both the C reference and the standalone
   replica should be able to dump `[frame, granule, channel, stage,
   n × f32]` records at each pipeline stage. Diff per-stage to localise
   the first diverging layer.
5. **Only then** turn on the WS-streaming harness and chase end-to-end
   variance. By that point the DSP is byte-exact and any remaining
   variance is in transport.

## Why this order matters

The MP3 port at peak was correlating 0.70 against the reference with a
mean sample-wise delta of 2785. It would have been very tempting to start
adding probes inside the live `fluxor-linux` process and instrumenting
the WS pipeline, but the actual bugs were two off-by-one constants and
one missing block-type dispatch in pure DSP. Steps 1–3 above isolate
those before the streaming pipeline can hide them; step 4 says where to
focus once you know the DSP is right.

## Reference decoder setup

Drop the reference under `/tmp` so it doesn't enter the tree, and make
it dump intermediate state, not just PCM.

**MP3 (recipe we used):**
```bash
mkdir -p /tmp/minimp3 && cd /tmp/minimp3
wget -q https://raw.githubusercontent.com/lieff/minimp3/master/minimp3.h
# probe_driver.c: see modules/app/codec/README.md for full source
cc -O2 -DMINIMP3_IMPLEMENTATION -DMINIMP3_NO_SIMD -o driver driver.c -lm
./driver assets/test_harness/cmajor.mp3 /tmp/minimp3_pcm.s16le
```

**AAC (next):**
```bash
# faad2: https://github.com/knik0/faad2 — vanilla AAC-LC, CC0-friendly
# Build the binary with -DDEBUG_OUTPUT to dump intermediate spectra.
# Equivalent of MP3's "freq lines per granule" for AAC is "post-MDCT
# spectral coefficients per long/short block".
```

The reference dumps both PCM and a binary log of layer values; we'll
diff our codec's output against the same shape. Stage IDs used in the
MP3 port:

| stage | what's in it |
| ---: | --- |
| 0 | after huffman + requantize (`grbuf` per granule/channel) |
| 1 | after MS / intensity stereo |
| 2 | after antialias + reorder (input to IMDCT) |
| 3 | after IMDCT + change-sign (input to synthesis) |
| 4 | overlap buffer state after IMDCT (for next-granule carry) |

AAC will have a different list (no antialias, different windowing, TNS
filter step, PNS noise substitution); pick stages that mirror the
reference's natural boundaries — typically wherever the reference
splits into named functions.

The record format is trivial:

```
u32 magic     'MP3P' (or 'AACP', etc.) — sanity tag
u32 frame     frame index in the stream
u32 gr        granule index (MP3) / window index (AAC short)
u32 ch        channel (0 or 1)
u32 stage     stage id from the table above
u32 n         count of f32 values to follow
n × f32       the layer's spectral / time-domain data
```

Both producers — the C reference and our standalone replica — write the
same struct, byte-for-byte, in stream order. A 5-line Python loader is
enough to ingest both and compare.

## The standalone Rust replica

This is the single highest-value debugging artefact. It is the same
DSP code from `modules/app/codec/<name>_codec.rs`, but:

- compiled as a normal `std` Rust binary (so it has `println!`, `File`,
  full diagnostics — no `no_std` overhead);
- driven by a `main()` that opens the encoded file, finds frame syncs,
  and feeds them to the same `decode_frame()` your module uses;
- emits PCM to a `.s16le` file and probes to a `.bin` file;
- is byte-bit-exact with the in-tree codec at the DSP level.

Layout used in the MP3 port:

```
/tmp/mp3_probe/
├── Cargo.toml
└── src/
    └── main.rs          # ~2500 lines:
                         #   - exact copy of mp3_codec.rs DSP section
                         #   - struct Mp3StateProbe { ...same fields, no syscalls }
                         #   - decode_frame_with_probes() that dumps stage 0..4
                         #   - fn main() — opens the .mp3, walks frame syncs
```

The trick: the in-tree codec is `#![no_std]` and pulls a `SyscallTable`
into its state struct, so a verbatim copy won't compile under `std`.
The minimal surgery is replacing `pub syscalls: *const SyscallTable`
with a `pub _unused: u32` placeholder and zero-stubbing `dev_log` /
`dev_channel_ioctl`. Everything else — bitstream readers, tables,
DSP — copies verbatim and gives us a reference-quality test bed.

When the replica matches the C reference byte-for-byte, you know the
DSP is correct. Any remaining mismatch in the live pipeline is in
streaming, channel scheduling, or initialisation order — not in the
codec.

## Float port pattern

The in-tree MP3 codec was originally Q15/Q30 fixed-point. Three things
made the port-to-float worth doing:

1. **Targets all have hardware f32.** rp2350 has FPv5-SP, bcm2712 has
   NEON+vfp, wasm32 has the engine's f32 ops. Only rp2040 (cortex-m0+,
   no FPU) doesn't, and the codec manifest already declared
   `hardware_targets = ["rp2350"]`.
2. **Reference code is in floats.** `minimp3` and `faad2` are both
   float-domain; a float port can be a line-by-line transcription with
   no Q-format reasoning. Q-format reasoning is where bugs hide.
3. **Float code is shorter.** The Q15 IMDCT was ~250 lines including
   saturation handling; the f32 version is ~80 lines and easier to
   audit against the spec.

### Build-system follow-through

Float code means you _must_ filter the codec out of any cortex-m0+
build. Two pieces support this:

- The module's `manifest.toml` declares `hardware_targets = ["rp2350"]`
  (plus any other targets you've verified). Add `"bcm2712"` and `"wasm"`
  as you verify each.
- `Makefile`'s `modules:` build loop reads the manifest's
  `hardware_targets` line and skips the module if `$(TARGET)` isn't
  listed. Without this, `make modules-all` will try to build the f32
  codec for rp2040 and fail at link time on `__aeabi_fmul`.

This filter is already in place — see `Makefile` after the `for src in
$$(find ...)` line, where it `grep`s `hardware_targets` from the
manifest and `continue`s if the current target isn't in the list.

## Bug sites we already paid for once

These are MP3-specific but the _pattern_ generalises to AAC. Watch for
the same family of mistakes:

1. **Exponent quantization rounding-up.** MP3's `MAX_SCFI` is
   `(MAX_SCF + 3) & ~3 = 44`, not `MAX_SCF = 41`. A naïve port reads the
   spec, sees 41, and produces output 2^(1/4) too soft. AAC has its own
   per-sfb scalefactor exponent — re-derive the quantization rule
   from the standard, don't trust your eyeballing of the reference.
2. **Region / band boundary lookup keyed on block type.** MP3 huffman
   region boundaries come from a _block-type-specific_ sfb table.
   Using the long-block table for short-block region 0 puts the
   boundary at line 44 (long) vs 36 (short) and silently corrupts
   ~6 huffman pairs per granule. AAC's equivalent is the
   long/short window's sfb_offset; same mistake possible.
3. **Window shape dispatch.** MP3 has 4 block types
   (long/start/short/stop) and the wrong window for any of them
   produces audible note-onset clicks. AAC has 4 window sequences
   (only_long / long_start / 8_short / long_stop) — same kind of
   dispatch table, same kind of mis-route.
4. **Stereo gain adjustment.** MS-stereo in MP3 isn't `L = M+S/√2,
   R = M-S/√2`; the `√2` is folded into the per-band gain exponent
   (gain_exp -= 2). Doing both gives 1/2 amplitude, doing neither
   gives ×√2. AAC's intensity-stereo and PNS have analogous
   "the multiplier is in the exponent, not the math" gotchas.
5. **Rounding sign check.** `mp3d_scale_pcm` rounds the converted
   `i32`, not the float sign: `s -= (s < 0)`, not
   `if sample < 0.0`. Trivial but produces ±1 LSB drift that adds
   up over a 4-second sweep.

## Test harness wiring (what the codec output flows through)

The unified harness — `examples/test_harness/linux/ws_capture.yaml` plus
`ws_capture_client.py` plus `diff_<codec>.py` — is built around
WebSocket fan-out so it scales to image rasters (4 MiB/frame) and
video as well as audio. The codec doesn't see any of this; it writes
PCM to its output channel and the rest of the graph delivers it. But
the harness has three tunings that the codec implicitly relies on, and
the next codec author should know them:

1. **`SEND_BUF_SIZE` in `modules/sdk/config.rs`** is 8 200 bytes (was
   4 100). Anything smaller than `8 (WsFrame header) + ws_stream's
   max_payload` makes http fragment the frame across step boundaries,
   and the fragment buffer is per-slot — a second fan-out write
   arriving mid-fragmentation drops bytes.
2. **`ws_stream` per-step read cap is 4 096 bytes** (in
   `modules/foundation/ws_stream/mod.rs`). This pairs with
   `SEND_BUF_SIZE = 8 200` so every WS BINARY envelope hits http's
   single-frame fast path. Lift the cap if you increase
   `SEND_BUF_SIZE` to match.
3. **Codec output `buffer_size` hint is 1 MiB** (in `mod.rs`'s
   `module_channel_hints`). Smaller buffers (≤ 64 KiB) make the
   codec back-pressure before a WS client can finish its handshake,
   and the http server's fan-out path drops envelopes that arrive
   before any client has connected. The 1 MiB hint lets the codec
   buffer roughly a 4-second test asset's PCM into the channel and
   let the client drain at its own pace.
4. **Per-`channel_write` chunk size must match at most one WS
   envelope's worth.** AAC sized its `IO_BUF_SIZE` to 256 bytes
   first — wrote 16 sub-chunks per AAC frame. The `ws.tx_out → http.ws_in`
   channel is FIFO; `http::server::ws_drain_fanout_input` reads up to
   `CHANNEL_BUFFER_SIZE = 8 192 B` per call but parses only the
   **first** envelope and discards the rest of the read. Sixteen
   256-B envelopes piling up faster than http drains == 15 dropped
   per AAC frame, end-to-end correlation collapses to ~0.04 even
   though the codec is bit-perfect. Bump the codec's `IO_BUF_SIZE`
   to a value where one `channel_write` carries a full
   application-level message (e.g. one AAC frame = 4 096 B i16
   stereo) and the queue never accumulates. WAV writes large enough
   chunks to hide this; AAC's tighter framing exposes it. The
   structural fix lives in `ws_drain_fanout_input` (process every
   envelope in the read buffer or make `ws_in` an explicit
   mailbox), but a producer-side workaround unblocks codecs today.

If the next codec produces output at a much higher byte rate (say,
1080p video at 60 fps = 240 MiB/s), revisit point 3 — at that rate
1 MiB is a quarter-frame.

## Definition-of-done metrics

The bar for the MP3 port was:

| metric | target |
| --- | --- |
| Cross-correlation with reference (full duration) | ≥ 0.995 |
| Per-step RMS within ±2 % of reference for each note of an 8-note sweep | yes |
| Sample-wise mean \|Δ\| | ≤ 50 |
| Sample-wise max \|Δ\| | ≤ 500 |
| Saturated samples | 0 |
| Peak / RMS ratio within ±10 % of reference | yes |
| Builds clean for every declared `hardware_target` | yes |
| All sibling bundles in `examples/test_harness/linux/` still pass | yes |

Re-use the same bar for AAC. The standalone replica routinely lands at
correlation 1.0000 / max |Δ| ≤ 400 once the DSP is right — anything
worse than that means there's still a layer bug, not a precision
ceiling.

## The iteration loop

Once the standalone replica matches the C reference, the inner loop
that lands changes is:

```
edit modules/app/codec/<name>_codec.rs
cp -p modules/app/codec/<name>_codec.rs /tmp/<probe-dir>/src/main.rs   # keep replica in sync
(cd /tmp/<probe-dir> && cargo build --release)                          # ~1 s
/tmp/<probe-dir>/target/release/<probe-bin>  asset.<ext>  /tmp/probe.bin
python3 diff_probes.py /tmp/ref_probe.bin /tmp/probe.bin                # ~1 s
```

That's 2–3 seconds per iteration with no Fluxor restart, no module
build, no WS harness. The end-to-end test (`make modules
TARGET=bcm2712 && make linux-bin && bash /tmp/run_<codec>.sh && python3
diff_<codec>.py`) only runs once you're sure the DSP is correct.

## Browser / WASM bundle gotcha

WASM bundles (`target/wasm/test_harness_audio_*.wasm`, served by
`examples/test_harness/wasm/serve.sh`) are self-contained artefacts:
they embed both the wasm-target kernel _and_ a packed copy of each
module's `.fmod`. Rebuilding the codec module is necessary but not
sufficient — the bundle YAML at `examples/test_harness/wasm/audio_<kind>.yaml`
also has to be re-baked:

```bash
make modules TARGET=wasm       # refresh target/wasm/modules/codec.fmod
target/aarch64-unknown-linux-gnu/release/fluxor build \
  examples/test_harness/wasm/audio_mp3.yaml \
  -o target/wasm/test_harness_audio_mp3.wasm
```

The bundle's mtime should be newer than the codec's `.fmod` mtime,
or the browser is serving a stale decoder. Browsers also cache `.wasm`
aggressively across page reloads — a hard refresh (Cmd+Shift+R /
Ctrl+F5) bypasses that.

This caught us once: the browser kept playing the pre-fix MP3 bundle
("clipped and underwater") long after every other test path showed
correlation 1.0000 against the reference. The decode runs in the
browser tab — not on the server — so the path under test really is
the bundle's embedded codec, and it has to be rebuilt independently
of `make modules-all` / `make linux-bin`.

## What to write down when porting AAC

Concretely, the AAC port should produce:

1. `modules/app/codec/aac_codec.rs` (already exists as a stub) — full
   AAC-LC decoder in f32, mirroring `faad2`/`fdk-aac`.
2. `/tmp/aac_probe/` — standalone Rust replica.
3. `/tmp/faad_probe/` — C driver around `faad2`, instrumented to dump
   per-frame post-huffman / post-stereo / post-IMDCT spectra.
4. `examples/test_harness/diff_aac.py` — same shape as `diff_mp3.py`,
   handles ADTS framing and AAC-LC's two window sizes.
5. `/tmp/run_aac.sh` — same shape as `/tmp/run_mp3.sh`.
6. A short follow-up to this guide capturing AAC-specific bug sites
   (intensity stereo direction, TNS filter ordering, PNS seeding).

Then update the codec module's `manifest.toml` `hardware_targets`
list and the README's supported-formats table.

## AAC-specific bug sites

This section captures the porting work for the AAC-LC f32 port,
including the bug sites we've already identified (and ones we expect
to hit, mirroring the pattern from the MP3 port).

### State as of 2026-05-12 — **byte-exact match with faad2 / ffmpeg**

| metric | cmajor.aac (44k) | cmajor_192k.aac | DoD target |
| --- | --- | --- | --- |
| in-tree codec SIGBUS at init | **fixed** ✓ | **fixed** ✓ | — |
| in-tree codec PIC-loader SIGSEGV (jump-table reloc) | **fixed** ✓ | **fixed** ✓ | — |
| linux harness runs end-to-end | **yes** ✓ | **yes** ✓ | — |
| WASM bundle builds + serves | **yes** ✓ | n/a | — |
| `run_ws_capture.sh` all 7 codecs | **pass=7 fail=0** ✓ | n/a | — |
| in-tree codec vs ffmpeg correlation | **1.0000** ✓ | **1.0000** ✓ | ≥ 0.995 |
| in-tree codec vs ffmpeg RMS | 6495 vs 6495 (exact) | 6487 vs 6487 (exact) | within ±2% |
| in-tree per-step RMS (each scale-note 350 ms) | **1.000 every step** ✓ | **1.000 every step** ✓ | within ±2% |
| saturated samples | **0** ✓ | **0** ✓ | 0 |
| peak/RMS deviation | 3.6 % | 0.0 % | ≤ ±10 % |
| mean \|Δ\| | 1.6 | 0.6 | ≤ 50 |
| max \|Δ\| | 1230 | 7 | ≤ 500 |
| priming alignment | matches faad (lag=-1024, pre-trim=1024) | matches faad (lag=-2048, pre-trim=2048) | matches faad |

The port reached byte-exact match with `faad → ffmpeg` after four
fixes; all four lived in different layers (linker, transport, lifecycle,
DSP) and only the last is AAC-specific.

**The four fixes that took the port from "broken" to byte-exact:**

- **(1) PIC module loader was SIGSEGVing on LLVM switch-table
  relocations.** LLVM emits jump tables for `match cb { 1 => …, 2
  => …, … 11 => … }` over the AAC huffman codebooks into a
  `.data.rel.ro` output section, holding absolute pointers into
  `.rodata`. The PIC loader doesn't relocate those at load time,
  so the first dispatched call SIGSEGVs. Fix lives in
  `modules/module.ld` — funnel `*(.data.rel.ro*)` into `.rodata`
  so the section is loaded as ordinary read-only data with the
  pointers intact. Defence-in-depth: AAC huffman cb-dispatch was
  also refactored to an `if/else` chain calling inner helpers, so
  the heuristic that produces the switch table is dodged
  unconditionally.
- **(2) Codec → ws → http envelope-drop on small chunks.** Initial
  AAC port wrote PCM in 256-byte chunks (`IO_BUF_SIZE = 256`).
  `http::server::ws_drain_fanout_input` reads up to
  `CHANNEL_BUFFER_SIZE = 8 192 B` per call and parses the **first**
  envelope from that read; the rest is discarded. With 16
  256-byte writes per AAC frame piling up faster than http drains,
  ~15 of every 16 envelopes were lost end-to-end, manifesting as
  correlation 0.04 vs ffmpeg even though the codec was bit-perfect
  (`s.output` matched the replica at every audio sample). Fix:
  bump `IO_BUF_SIZE` to 4 096 so each `channel_write` emits one
  full AAC frame in one envelope. See harness-wiring point 4
  above. The structural fix lives in the http server; this
  producer-side workaround unblocks codecs today.
- **(3) Premature HUP-reset truncated the trailing PCM in the
  wasm browser harness.** `modules/app/codec/mod.rs` reset codec
  state on `POLL_HUP` alone, but `host_browser_fetch` raises HUP
  as soon as the JS-side response body is drained — while the
  channel ring still held ~10 AAC frames the codec hadn't decoded
  yet. Symptom: "playback stops at the 6th note" — the last
  ~250 ms of audio was getting flushed mid-stream by the reset's
  `IOCTL_FLUSH`. Fix: reset only when HUP set AND `POLL_IN` clear
  AND the codec has been idle in that state for
  `HUP_QUIESCE_TICKS = 64` consecutive ticks. The counter clears
  when fresh input arrives or HUP clears, so the bank-driven
  multi-file scenario the reset was originally written for still
  works.
- **(4) Sine window table generator used the spec's
  doubled-frequency formula.** The auto-generated table at
  `modules/app/codec/aac_sine_tables.rs` used `W(n) =
  sin((π/N)·(n+0.5))` where `N` is the block size, but the AAC
  spec (ISO/IEC 14496-3 §4.6.11) defines the sine window as
  `W_SINE(n) = sin((π/(2N))·(n+0.5))` — half the angular
  frequency. With the wrong formula, the stored "rising half"
  window of length N went `0 → 1 → 0` over the table instead of
  the spec-required monotonic `0 → 1`. The filterbank then hit
  both halves of every IMDCT output with the same bell curve
  instead of complementary `0→1` / `1→0` ramps. The Princen-
  Bradley overlap-add accidentally still preserved the average
  energy (steady-state RMS ratio = 1.000), but at transient
  onsets (LONG_START → EIGHT_SHORT → LONG_STOP transitions) the
  miscoupled windowing produced precisely √2-equivalent peak
  overshoot — audible as "compressed fuzz at the start of each
  note". After fix: correlation 0.9911 → **1.0000**, mean \|Δ\|
  147 → 1.6, peak/RMS dev 31 % → 3.6 %. faad2 reference for
  verification: `libfaad/sine_win.h` `sine_long_1024[0] =
  0.00076699031874270449` — ours was `0.001534` (= 2× off in the
  small-angle region). The KBD tables were already correct
  (extracted verbatim from faad2). Regenerator script at
  `tools/gen_sine_tables.py`.

**Lesson learned**: auto-generated math tables need a one-line
golden-value check against the upstream reference. A formula
typo (`/N` vs `/(2N)`) can sit hidden for the entire port if the
overlap-add geometry happens to preserve energy averaged — the
error only surfaces at transients where local peak-vs-RMS
behaviour changes. The diff_aac validator's "peak/RMS ratio"
column was the earliest signal of this (stuck at 31 % deviation
through the whole port until this was found).

Where the correlation came from: the standalone replica's first-cut
f32 DSP gets every layer hooked up — ADTS sync, ICS info parse,
section data, HCB_SF scalefactor differential decode, HCB 1–11
spectral huffman (auto-extracted from `/tmp/faad2-src/libfaad/codebook/*.h`
via `/tmp/extract_hcb.py`, ~103 KB of tables), iquant via x^(4/3)
lookup and `2^(0.25·sf − 25)` gain, MS-stereo, direct-DFT IMDCT
(N=2048 for ONLY_LONG, validated formula =
`(2/N) · Σ X_k cos((π/(2N))·(2n+1+N/2)·(2k+1))`), and sine-window
50% overlap-add. **What it doesn't yet do**: LONG_START / LONG_STOP /
EIGHT_SHORT windowing (these frames currently emit silence and zero
the overlap, which contaminates the *following* ONLY_LONG frame's
first half), PNS, TNS, intensity stereo, pulse coding, KBD window
shape. The 0.018 correlation is therefore expected from a
"first-pass" port that handles roughly a third of the bitstream tools.

The prior 2 200-line Q15/Q31 implementation has been removed because
it SIGBUSed at init on aarch64. What's in the tree now:

- `modules/app/codec/aac_codec.rs` — clean f32 skeleton (~340 LOC)
  that walks ADTS frames correctly and emits silence per frame. Builds
  byte-clean for rp2350, bcm2712, wasm. The unified codec's harness
  (`audio_aac.yaml`, `ws_capture_aac.yaml`, the wasm bundle) is wired
  end-to-end and produces a clean (but silent) WAV.
- `/tmp/faad_probe/` — `probe_pcm.c` linked against `-lfaad` produces
  byte-exact reference PCM at `/tmp/faad_pcm.s16le`. Cross-correlation
  with `ffmpeg -i cmajor.aac -f s16le …` is **0.999998** — two
  independent decoders agree, so the reference is sound.
- `/tmp/aac_probe/` — standalone Rust replica with the first-cut
  f32 DSP wired up. Build: `cd /tmp/aac_probe && cargo build --release`.
  Run: `/tmp/aac_probe/target/release/aac_probe in.aac out.s16le`.
  `src/hcb_tables.rs` is auto-generated by `/tmp/extract_hcb.py` from
  faad2's codebook headers — re-run the extractor if you pull a newer
  faad2 source. **The replica's DSP is currently a divergent first-cut**
  (correlation 0.018 vs faad). To iterate: edit `/tmp/aac_probe/src/main.rs`,
  `cargo build --release`, re-run, re-diff. See "Remaining work"
  below for the bug-hunting order.
- `examples/test_harness/diff_aac.py`, `/tmp/run_aac.sh`,
  `examples/test_harness/wasm/audio_aac.yaml` — same shape as the MP3
  variants; AAC-specific tweaks: 1024-sample frames (vs MP3's 1152),
  pretrim ∈ {0, 1024, 2048} for the encoder-delay sweep.

`run_ws_capture.sh` runs the AAC harness by default as of
2026-05-12; AAC is part of the `kinds=(wav mp3 aac jpeg png bmp gif)`
default list.

### Decoder structure (faad2 LC subset)

Decode flow inside `decode_aac_frame()`, mirroring faad2's
`raw_data_block` → `reconstruct_channel_pair` / `…_single_channel`:

```
raw_data_block(br)
├─ loop: id_syn_ele ∈ {SCE, CPE, LFE, DSE, PCE, FIL, END}
│  SCE → single_channel_element:
│    ├─ ics_info()              # window_sequence, max_sfb, …
│    ├─ section_data()          # huffman codebook per band
│    ├─ scale_factor_data()     # HCB_SF differential scalefactors
│    ├─ pulse_data()            # 0..4 pulses on LONG windows
│    ├─ tns_data()              # LPC inverse-filter coeffs per band
│    ├─ spectral_data()         # HCB 1..11 per band
│  CPE → channel_pair_element:
│    ├─ ics_info() [common or twice]
│    ├─ ms_mask_present / ms_used[g][sfb]
│    ├─ individual_channel_stream × 2
└─ post-bitstream DSP per element:
   ├─ pns_decode()              # NOISE_HCB-keyed pseudo-random noise
   ├─ ms_decode()               # mid/side per ms_used[g][sfb]
   ├─ is_decode()               # intensity stereo (HCB 14/15)
   ├─ quant_to_spec()           # x^(4/3) + 2^(0.25·(sf-100)) gain
   ├─ tns_decode_frame()        # IIR inverse on flagged SFBs
   └─ ifilter_bank()            # IMDCT + sine/KBD window + overlap
```

### Bug sites we expect (pattern from MP3 port, plus AAC-specific)

1. **Scalefactor exponent base.** AAC's per-band gain is
   `2^(0.25 · (scalefac - 100))` (a faad2 idiom is multiplying by
   `pow2sf_tab[scalefac - 100 + offset]` with `offset = 100`). Getting
   the `100` offset wrong skews everything by a constant factor — the
   audible analogue of MP3's `MAX_SCFI` rounding bug. Pre-compute the
   table at codec init from `f32::exp2(0.25 * (i - 100))`.

2. **SFB tables keyed on window sequence.** Long/start/stop windows
   use `swb_offset_1024_*`; EIGHT_SHORT uses `swb_offset_128_*` (8×).
   Using the long-window offsets for a short-window section keeps the
   huffman decode within bounds but corrupts the per-sfb scalefactor
   assignment — same family as MP3's "block-type-specific sfb table"
   bug. faad2 dispatches via `swb_offset_1024_window[sf_index]` and
   `swb_offset_128_window[sf_index]` (see `specrec.c:221`).

3. **Window-shape dispatch.** AAC ICS has a `window_shape` bit:
   `0 = sine`, `1 = KBD` (Kaiser-Bessel-Derived). Both have to ship as
   static tables (the KBD coefficients are too expensive to compute on
   the fly cleanly; the sine window can be runtime-computed). Pairing
   rule: the **left half** of frame *N*'s overlap uses frame *N*'s
   `window_shape`; the **right half** of frame *N*'s overlap uses
   frame *N-1*'s `window_shape` (faad2 ships `window_shape_prev` for
   exactly this). Get this wrong and short→long transitions click
   audibly.

4. **MS-stereo gain folded into the inverse transform.** AAC's
   `ms_decode` is literally `L' = L + R; R' = L - R` (no `/2` and no
   `/√2`). The 1/√2 normalisation is *already* in faad2's iquant
   step — the SFB gain it applies absorbs the factor. Mirroring MP3's
   bug: if you add a `/2` to ms_decode "to be safe", you'll be
   1/4 amplitude on every MS-coded band. Don't.

5. **Intensity-stereo direction signalled by codebook.** When
   `sfb_cb` is `INTENSITY_HCB` (15) or `INTENSITY_HCB2` (14), the
   right channel's spectrum is replaced by `L * sign · gain` where
   `gain = 2^(-0.25 · scalefac)`. The codebook number distinguishes
   sign: HCB 15 = `+1`, HCB 14 = `-1`. There's no separate flag —
   getting this wrong silently flips the stereo image on every IS
   band.

6. **PNS RNG seeding.** Perceptual Noise Substitution generates
   deterministic-but-noise spectra for `NOISE_HCB` (cb 13) bands. The
   seed is a per-stream pair of u32 LCG states (faad2 keeps them on
   the decoder struct as `__r1`, `__r2`). Re-seeding per frame breaks
   cross-frame coherence; never re-seeding *also* breaks the first
   frame's repeatability (depending on how you initialise). Initialise
   the pair to `(1, 1)` at `aac_init()` and let `pns_decode` advance
   them as in `pns.c::ne_rng()`.

7. **TNS filter direction.** The LPC inverse filter in `tns_decode_frame`
   runs *upward* for short windows but *downward* for long windows on
   some SFBs — faad2's `tns.c` reads `direction` per filter and picks
   the iteration order. The TNS coefficient table itself depends on
   the filter `coef_res` bit (3-bit or 4-bit quantisation). Off-by-one
   on the coefficient sign-extension is the most common bug.

8. **Pulse coding only on LONG windows.** `pulse_data_present == 1`
   in an EIGHT_SHORT ICS is a stream error per spec, but some
   encoders emit it. faad2 logs and skips; we should do the same
   rather than reject the frame.

9. **IMDCT 1/N normalisation.** AAC's spec defines IMDCT with no
   gain term, but the reference encoders bake `1/N` into the bitstream
   gain assumption. Real-world: faad2's `faad_imdct` divides by N
   inside the transform; the iquant gain absorbs that. If you do
   *both* you'll be 1/2048 amplitude on long windows.

10. **Encoder delay = one frame.** AAC-LC encoders insert 1024 samples
    of silence at the start to prime the IMDCT overlap. ffmpeg
    strips it; faad doesn't (our reference is faad → we keep the
    delay frame). `diff_aac.py` sweeps `pretrim ∈ {0, 1024, 2048}`
    against the ffmpeg reference; **use the pretrim=2048 alignment**
    (1024 encoder delay + 1024 first-frame warmup) once the DSP is
    in.

### Remaining work — bug-hunting order

The standalone replica is the testbed; do not touch the in-tree codec
until the replica matches faad to byte-exact PCM. Suggested order
(ordered by likely impact on correlation):

1. **LONG_START / LONG_STOP / EIGHT_SHORT window dispatch**.
   Currently these frames emit silence + zero overlap, which corrupts
   the following ONLY_LONG frame's first half. Port the full window
   dispatch from `filtbank.c::ifilter_bank` (the four switch cases).
   For EIGHT_SHORT specifically, the spectral data layout is
   group-interleaved — `spectral_data()` in `syntax.c` walks per-group
   sections and the `p` index advances by section-width inside each
   group (see `groups*nshort` in faad). This is documented in
   `syntax.c` lines ~1670 onward.
2. **Per-group scalefactor / spectral-data storage**. For
   `EIGHT_SHORT_SEQUENCE` with multiple groups, the replica's flat
   `[i16; MAX_SFB]` scalefactor array overwrites between groups.
   Bump to `[[i16; MAX_SFB]; MAX_WIN_GROUPS]` and key reads per group
   index.
3. **KBD window**. Ship `kbd_long_1024[]` and `kbd_short_128[]`
   verbatim from `/tmp/faad2-src/libfaad/kbd_win.h` (just a sed-rename
   of `static const real_t kbd_long_1024[] = { ... }` to
   `pub static KBD_LONG_1024: [f32; 1024] = [ ... ];`). Then dispatch
   window_long[shape] in the filtbank like faad does.
4. **First-noise 9-bit PCM flag**. In `read_scalefactors`, the FIRST
   `NOISE_HCB` band reads 9 explicit bits (then subtract 256), not a
   huffman code. Subsequent noise bands read huffman as normal. Find
   the `noise_pcm_flag` in `decode_scale_factors()` in
   `syntax.c:1894`.
5. **TNS inverse filter**. faad's `tns.c::tns_decode_frame()` — per-band
   LPC inverse. Currently `skip_tns_data()` reads & discards. The
   coefficient bits are correct (verified by frame_count progress)
   but the filter is never applied.
6. **PNS noise injection**. faad's `pns.c::pns_decode()`. Cmajor.aac
   is music (not noise-coded heavily) so probably small impact, but
   needed for general AAC.
7. **Intensity stereo**. `is.c::is_decode()` — apply when
   `sfb_cb ∈ {INTENSITY_HCB, INTENSITY_HCB2}` after iquant. Sign from
   codebook: HCB 15 = +1, HCB 14 = -1.
8. **Pulse coding**. `pulse.c::pulse_decode()` — up to 4 pulses added
   to LONG-window spectra. Currently `decode_ics` skips the pulse
   payload via raw `read_bits` but doesn't apply pulses.
9. **Verify HCB_SF leaf-value sign**. Faad returns `int8_t` from
   `huffman_scale_factor()` which is then `t - 60` to get the
   differential. My code does `decode_hcb_sf() as i8 - 60` — verify
   the table leaf values map to the right range and that diffs match
   faad for a known scalefactor sequence.

A useful first step before tackling (1) is to instrument faad2 itself
(`/tmp/faad2-src` is already cloned) with `fprintf` of the per-frame
scalefactors and quant_data into a binary file, then diff the
replica's same arrays. That'll tell you exactly which layer is
diverging.

### Original work checklist (kept for reference)

Tracked roughly by faad2 source file. Each step should be validated
via the standalone replica producing identical PCM (or, when wired,
identical per-stage probes) to the faad reference before moving on.

| step | faad2 source | what goes into `aac_codec.rs` | LOC est. |
| ---: | --- | --- | ---: |
| 1 | `bits.c` | BitReader already present; keep f32-clean | done |
| 2 | `syntax.c::raw_data_block` etc. | element loop + side_info + section_data + scale_factor_data + spectral_data; previous tree had most of this — restore from `git log -p modules/app/codec/aac_codec.rs` | ~600 |
| 3 | `huffman.c` + `codebook/*.h` | HCB_SF + HCB 1..11 — extract verbatim into a separate `aac_codebooks.rs` (huge integer tables) | ~3 000 |
| 4 | `specrec.c::quant_to_spec` | x^(4/3) lookup + scalefactor gain + per-section dispatch | ~150 |
| 5 | `pns.c::pns_decode` | LCG, per-band noise injection | ~80 |
| 6 | `ms.c::ms_decode` | per-sfb in-place L/R combine | ~30 |
| 7 | `is.c::is_decode` | intensity-stereo replication w/ HCB-keyed sign | ~50 |
| 8 | `pulse.c::pulse_decode` | up to 4 pulses, LONG windows only | ~40 |
| 9 | `tns.c::tns_decode_frame` | per-band LPC inverse | ~200 |
| 10 | `mdct.c::faad_imdct` | length-2048 / length-256 IMDCT via CFFT | ~250 |
| 11 | `filtbank.c::ifilter_bank` | window dispatch + 50% overlap-add + window-shape continuity | ~250 |
| 12 | `sine_win.h` / `kbd_win.h` | sine_long_1024 (computed at init); kbd_long_1024 + kbd_short_128 (shipped verbatim) | ~10 KB |
| 13 | `iq_table.h` | 8 192-entry f32 x^(4/3) table — compute at init | ~10 |
| 14 | `mdct_tab.h` / `cfft_tab.h` | trigonometric LUTs — compute at init from `f32::sin` / `cos` | ~30 |

Estimated **~4 500 lines of Rust** when complete, ~half of which is
mechanical table data. The unified codec's `CODEC_STATE_SIZE` already
reserves enough room in `mod.rs::CodecBuf` for the largest member, so
no boilerplate plumbing changes are needed when filling each step in.

When the standalone replica matches faad at sample level, copy the DSP
verbatim into `modules/app/codec/aac_codec.rs` and re-run
`bash examples/test_harness/run_ws_capture.sh aac` to confirm the
WS-streaming path also passes. Then:

- Remove `aac` from `run_ws_capture.sh`'s skip-explanation comment and
  add it to the default `kinds=(…)` list.
- Update `examples/test_harness/wasm/index.html`'s AAC matrix row to
  `<div class="pass">expected ✓</div>` and re-bake
  `target/wasm/test_harness_audio_aac.wasm` per the §"Browser / WASM
  bundle gotcha" recipe above.
- Run `bash examples/test_harness/run_ws_capture.sh` (no args) and
  confirm `pass=6`.
- Also verify against `assets/test_harness/cmajor_192k.aac` (generated
  with `ffmpeg -i cmajor.wav -c:a aac -b:a 192k cmajor_192k.aac`) so
  you've fixed the codec, not memorised one input.

### Per-stage probe wiring (when ready)

The C reference's stage probes require modifying faad2's source — the
shipped `-lfaad` is a black-box. The minimum useful instrumentation is
to add `fwrite()` calls in:

- `specrec.c::quant_to_spec` (stage 0: post-iquant)
- `pns.c::pns_decode` (stage 1: post-PNS)
- `ms.c::ms_decode` (stage 2: post-MS)
- `is.c::is_decode` (stage 3: post-IS)
- `tns.c::tns_decode_frame` (stage 4: post-TNS-inverse)
- `filtbank.c::ifilter_bank` (stage 5: post-IMDCT, pre-overlap; stage 6:
  post-overlap-add, in time domain)

Build the modified faad2 in-tree under `/tmp/faad2-src/` (already
cloned from `https://github.com/knik0/faad2`):

```bash
cd /tmp/faad2-src && ./bootstrap && ./configure --disable-shared
make -j
# then re-build /tmp/faad_probe/probe_pcm.c against the in-tree libfaad:
cc -O2 -I/tmp/faad2-src/include -L/tmp/faad2-src/libfaad/.libs \
   /tmp/faad_probe/probe_pcm.c -o /tmp/faad_probe/probe_pcm \
   -lfaad -static
```

Once that produces both PCM and `/tmp/aac_probe_ref.bin`, the
standalone replica's `emit_probe()` calls (currently stubbed) can be
wired at the same stages and diffed with a 5-line Python loader.

