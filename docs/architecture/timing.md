# Timing Model

Fluxor distinguishes wall-clock time (when work is scheduled) from
stream-clock time (what time the data corresponds to). Modules that
keep the two clocks separate get predictable A/V sync; modules that
conflate them drift.

Source: `crates/fluxor-abi/src/kernel_abi.rs` (`StreamTime`),
`crates/fluxor-abi/src/contracts/stream_clock.rs`,
`src/kernel/module/syscalls.rs` (the `STREAM_TIME` query).

## 1) Define what "time" means in your system

Use two distinct clocks:
- Wall clock (host time): `dev_micros` / `dev_millis` (`fluxor-rt`), used only for when to schedule work.
- Stream clock (media time): a monotonically increasing count of frames (audio frames, LED frames, etc.) that represents what time the data corresponds to.

Do not try to achieve precise A/V sync using wall clock alone.

---

## 2) Make one clock the authority per stream

For audio pipelines, the authority is the sink's consumption rate — the
I2S DMA on RP, the audio device on a host.

Any module reads it with `provider_query(-1, kernel_abi::STREAM_TIME, out)`
(key `0x0030`, no grant needed), which writes a 24-byte `StreamTime`:

```c
struct StreamTime {
    u64 consumed_units;      // units consumed by hardware (monotonic)
    u32 queued_units;        // units buffered ahead of consumption
    u32 units_per_sec_q16;   // consumption rate (Q16.16 fixed point, 0 = unknown)
    u64 t0_micros;           // monotonic µs timestamp of first push (0 = not started)
};
```

The kernel answers from the registered `stream_clock` provider (the
Linux and wasm hosts register one backed by their audio sink); where none
is registered (bare-metal RP) it answers from the first active PIO
stream, whose rate is set with the PIO `STREAM_SET_RATE` op. A
non-negative handle names one stream instead of the first.

Units are defined by the stream — for I2S they are PIO words (= stereo frames).
`t0_micros` is captured on the first push, not at init or alloc.

Derive played/committed counts from `StreamTime`:
- `committed = consumed_units + queued_units`
- `played ≈ consumed_units`

If you need a wall-clock estimate of the current play position:
- `played_time_us ≈ t0_micros + consumed_units * 1_000_000 / sample_rate`

---

## 3) Treat every buffer as a time interval

Every push of N frames defines:
- `start_frame = audio_frames_committed`
- `end_frame = start_frame + N`

This is the core primitive for scheduling anything "in sync".

If you want an LED to change "at the same time as note X", you schedule the LED change for a target audio frame.

---

## 4) Add timestamps to messages (or define implicit ones)

Any message that affects output (frequency, gain, LED value, etc.) should be associated with a stream time:
- `value + target_frame` (preferred), or
- `value applies at next buffer boundary` (acceptable but introduces quantisation)

If you do not carry `target_frame`, you will get jitter equal to your processing chunk size.

---

## 5) Quantisation rules you must accept (and minimise)

Your system is inherently quantised by:
- Audio chunk size: jitter up to one chunk if control applies at chunk boundaries.
- Scheduler tick: jitter up to one tick if producers are wall-clock paced.
- Split reads: a channel write is whole or nothing, but a read is a byte
  stream ([record boundaries](pipeline.md#record-boundaries)); a consumer
  that reads one message across two steps applies it a step late.

To reduce jitter:
- Prefer smaller chunks for control-sensitive generators.
- Prefer `dev_micros` over `dev_millis` for scheduling.
- Keep control messages small (`u32`) and read each one whole.

---

## 6) Start-time alignment across a chain

For any source -> processors -> sink chain, define a "start of stream" moment:
1. The sink's `StreamTime` records `t0_micros` when the first committed frame is pushed.
2. Upstream modules treat that moment as frame 0.

Practical approach:
- The kernel captures `t0_micros` automatically on first push (see `StreamTime`).
- Any module can read `StreamTime` (section 2) and convert
  `target_frame` <-> `target_time`:

```
target_time_us = t0_micros + target_frame * 1_000_000 / sample_rate
```

This is your bridge between wall clock and stream clock.

---

## 7) Scheduling a producer correctly

For a timed producer (sequencer, LFO, animation), do not "sleep 500 ms then emit".
Instead:
- Maintain `next_event_frame` in stream frames.
- Each step:
  - Read `consumed_units` from `StreamTime` (= played frames).
  - While `consumed_units + lead_frames >= next_event_frame`: emit event(s).

Where:
- `lead_frames` compensates for buffering latency (at least one DMA buffer, often two).

This prevents "first event long" and ensures steady timing regardless of backpressure.

---

## 8) Backpressure contract (critical)

A producer must never advance its notion of stream time based on "attempted output".
Advance only when:
- the message is committed to the next stage, or
- you have intentionally dropped/overwritten it (latest-wins mailbox)

For audio control, "latest-wins" is usually better than queueing.

---

## 9) LED synchronisation with audio (practical recipe)

Goal: LED change aligned to sound.
1. Decide LED update granularity (e.g. every 10 ms or every note).
2. Convert desired LED event time to `target_frame`.
3. Ensure the LED module updates ahead of time by at least `lead_frames`.
4. Apply LED change when `played_frame >= target_frame` (or when approaching, if hardware latency requires).

If LEDs are not tied to the audio sample clock, they will still have their own output latency; treat that as a fixed offset and calibrate once.

---

## 10) Measuring a region: cycle and cache counters

Stream time says when something should happen. To learn what a piece of a
module's own code costs, read the target's counters around it through the
`counters` contract (`fluxor_rt::counters`). A module that reads them
declares `grants = ["counters"]`: an instruction-cache count that covers the
whole node moves with every other owner's code, so the read is granted, not
free.

```rust
let what = counters::describe(sys)?;      // once: which counters, which clock
let cost = counters::calibrate(sys)?;     // once: cycles one read costs this module
let before = counters::read(sys)?;
hot_loop();
let after = counters::read(sys)?;
let ran = counters::elapsed(&before, &after);
let cycles = ran.cycles.saturating_sub(cost);
```

What the numbers mean is the target's, and `describe` says it:

| Target | Cycle count | Instruction-cache counts |
|---|---|---|
| rp2350 | the calling core's own cycle counter, at the system clock | the execute-in-place cache's hits and accesses, one pair for both cores and every flash-reading transfer (`node`) |
| rp2040 | the 1 MHz timer (`system`): microseconds, not core cycles | the execute-in-place cache's, for the node |
| bcm2712 | the calling core's cycle counter | the calling core's L1 instruction-cache accesses and hits (`core`); on a machine that enters the kernel below EL2, the system clock and no cache count |
| uefi, linux, wasm | a system clock (`system`), at the rate `describe` reports | none |

A target states the same in its `[counters]` table, as the facts of the
target capabilities `counter.cycles` (`clock = "core" | "system"`) and
`counter.icache` (`scope = "core" | "node"`). A module that cannot work
without one requires it and is refused at build for a target that lacks it;
a module that only reports takes what `describe` answers. A counter the
target lacks reads zero with its `present` bit clear.

Rules for a measurement that means something:

- **Every count wraps at 32 bits.** Subtract two readings with `elapsed`,
  and keep a region shorter than one wrap: 28 s of cycles at 150 MHz.
- **Subtract the read.** A read is a kernel call and costs cycles of its
  own, more through the gateway when the module is gated. `calibrate`
  measures it the way this module pays it.
- **Warm the region first.** Run the loop once before the first reading, so
  the figure is the loop's steady cost and not the cache filling.
- **Measure many iterations between two readings**, a thousand or more, not
  one iteration a thousand times: the cost of the readings then disappears
  into the total.
- **The counts are the core's, not the module's.** Everything that ran on
  the core between the readings is in them: interrupts, and kernel work.
  With scope `node` the cache counts also include the other core and
  flash-reading transfers. No attribution to a module is claimed; measure in
  the graph the module will run in, since the other modules' code competes
  for the cache there as it will in use.
- **A hit rate is hits over accesses of the same region.** On an
  execute-in-place target a hot loop that outgrows the cache shows here
  first: the loop runs several times slower than the same code running
  from cache.

A module that publishes what it measured emits it as measurement records
(content type `MeasurementStream`, capability `measurement.stream` with the
block's shape in its facts), so any measurement consumer takes it unchanged.

---

## Checklist for new modules

- Does the module operate in stream frames, not wall-clock ms?
- Are outputs timestamped (`target_frame`) or explicitly "next boundary"?
- Is control messaging small (`u32`) and read whole?
- Does the control consumer drain all pending messages each step and apply only
  the most recent value?
- Does it advance time only on commit, not on attempt?
- Does it account for lead time equal to buffering latency?
- Is its unavoidable jitter bounded by a documented quantum (chunk size)?
