# `drums/` — TR-808-style drum machine

Classic 4/4 drum pattern driving the `drum` PIC module — a multi-voice
percussion synthesizer with kick / snare / closed hat / open hat /
clap voices. Adds reverb via the `effects` module for room ambience.

Pipeline:

```
sequencer → drum → effects → i2s
```

Note encoding (frequency field carries the drum index):
`1=kick, 2=snare, 3=closed hat, 4=open hat, 5=clap, 0=rest`.

Pattern (16th notes at 120 BPM): K H H H S H H H K H K H S H H H

## Targets

- `pico2w.yaml`

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/drums/pico2w.yaml
# I²S DAC output: data=28, bclk=26, lrclk=27
```

## Related

- [`synth/`](../synth/) — tonal multi-voice synthesizer (different module).
- The drum module source: [`modules/app/drum/`](../../modules/app/drum/).
