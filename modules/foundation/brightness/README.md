# brightness

Turns a signal into an LED brightness byte, with the perceptual curve
applied on the way.

## What it is for

An LED driven straight from a linear amplitude looks wrong: perceived
brightness is roughly the 2.2 power of emitted light, so a value that is
numerically half reads as considerably more than half as bright. Every
consumer that lights an LED from a signal needs the same correction, and
writing it at each one gets it subtly different at each one.

So the correction lives here, once, and the module takes whichever of the
two signals a graph actually has: sequencer note events, or audio samples.

## Ports

| Port | Direction | Purpose |
|---|---|---|
| `source` | input | Note events or audio samples, per `mode`. |
| `level` | output | One brightness byte, 0–255. |

## Modes

`mode = sequencer` reads 8-byte note events and takes the note's frequency
field as the brightness, clamped at 255. `mode = audio` reads interleaved
stereo `i16` samples and runs an envelope follower over them, so the LED
tracks loudness rather than individual samples.

Either way a byte goes out only when it differs from the last one sent. An
LED that is already at the right level needs no write, and a stream of
identical bytes would be indistinguishable from a stream of changes to
anything watching the channel.

The envelope has separate `attack` and `release` coefficients because the
two directions want different speeds: brightness should chase a transient
quickly and fall away slowly, or the LED flickers on ordinary programme
material. The defaults (`attack` 2000, `release` 200) are that asymmetry.

## Curves

| `curve` | Transform | When |
|---|---|---|
| `linear` | none | The source is already perceptual, or a meter is wanted rather than a light. |
| `gamma22` | gamma 2.2 | The default. Matches how brightness is perceived. |
| `gamma28` | gamma 2.8 | Cheap LEDs, whose low end is crushed and needs more of the range spent there. |
| `inv_gamma` | inverse gamma | The source has already been gamma-corrected upstream and must be undone. |

## Parameters

`mode`, `curve`, `attack`, `release`, `output_divider` — defaults and
accepted spellings are declared in `params_def.rs`, which is the single
source of truth for the schema.

`output_divider` thins the output: one byte is emitted every *n*
computations. An LED does not need a new value per audio sample, and a
consumer that cannot keep up is the reason to divide here rather than
downstream.
