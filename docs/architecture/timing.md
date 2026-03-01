# Concise Timing Guide for This Architecture

## 1) Define what "time" means in your system

Use two distinct clocks:
- Wall clock (host time): `micros()`/`millis()` used only for when to schedule work.
- Stream clock (media time): a monotonically increasing count of frames (audio frames, LED frames, etc.) that represents what time the data corresponds to.

Do not try to achieve precise A/V sync using wall clock alone.

---

## 2) Make one clock the authority per stream

For audio pipelines, the authority is the I2S DMA consumption rate.

The kernel exposes timing via `StreamTime` (available through `dev_query` key
`STREAM_TIME` = 0x0407, or the `stream_time` syscall):

```c
struct StreamTime {
    u64 consumed_units;      // units consumed by hardware (monotonic)
    u32 queued_units;        // units buffered ahead of consumption
    u32 units_per_sec_q16;   // consumption rate (Q16.16 fixed point)
    u64 t0_micros;           // monotonic µs timestamp of first push (0 = not started)
};
```

Units are domain-defined — for I2S they are PIO words (= stereo frames).
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
- Audio chunk size (`SAMPLES_PER_CHUNK`): jitter up to one chunk if control applies at chunk boundaries.
- Scheduler tick (`Timer::after`): jitter up to one tick if producers are wall-clock paced.
- Channel partial reads/writes: jitter when messages are split across steps.

To reduce jitter:
- Prefer smaller chunks for control-sensitive generators.
- Prefer `micros()` over `millis()` for scheduling.
- Use atomic-sized control messages (`u32`) so the channel can be implemented without partial delivery.

---

## 6) Start-time alignment across a chain

For any source -> processors -> sink chain, define a "start of stream" moment:
1. Sink (I2S) exposes `t0_frame` when it begins playing the first committed frame.
2. Upstream modules treat that as frame 0.

Practical approach:
- The kernel captures `t0_micros` automatically on first push (see `StreamTime`).
- Any module can query `StreamTime` via `dev_query(STREAM_TIME)` and convert
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

## 10) Minimal instrumentation you should implement

The PIO stream service already exposes `StreamTime` via `dev_query(STREAM_TIME)`
(key 0x0407). It provides everything needed for sync:

| Field | Meaning |
|-------|---------|
| `consumed_units` | Frames consumed by DMA (monotonic) |
| `queued_units` | Frames buffered ahead of DMA |
| `units_per_sec_q16` | Consumption rate, Q16.16 (set via `SET_RATE`) |
| `t0_micros` | Monotonic µs of first push (0 = not started) |

Derived: `committed = consumed_units + queued_units`.

With just `consumed_units + queued_units`, you can produce stable sync.

---

## Checklist for new modules

- Does the module operate in stream frames, not wall-clock ms?
- Are outputs timestamped (`target_frame`) or explicitly "next boundary"?
- Is control messaging atomic-sized (`u32`) to avoid partials?
- Does the control consumer drain all pending messages each step and apply only
  the most recent value?
- Does it advance time only on commit, not on attempt?
- Does it account for lead time equal to buffering latency?
- Is its unavoidable jitter bounded by a documented quantum (chunk size)?
