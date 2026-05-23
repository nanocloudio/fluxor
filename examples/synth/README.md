# `synth/` — multi-voice tonal synthesizer

31 voice presets, 5 melody presets, BOOTSEL cycles voices, sequencer
auto-advances through melodies on loop end. The kitchen-sink synth
demo — exercises the full synth + effects + sequencer + i2s chain.

Voices include analog-style (acid_bass, sub_bass, analog_bass),
classic synth shapes (square_lead, pure_sine, vibrato_lead),
character voices (lofi_crunch, retro_8bit, distorted_lead,
ring_mod, robot_voice), and ambient textures (glass_pad, ambient,
granular_atmo, gated_pad, tape_echo).

Pipeline:

```
flash_rp → gesture → fan out to synth.preset + effects.preset
sequencer → synth → effects → i2s_pio
```

Melody presets in the `data:` section: `c_major`, `c_minor`,
`pentatonic`, `blues`, `fur_elise`. (Absorbed the former
`scale_player/`, `fur_elise/` examples.)

## Targets

- `pico2w.yaml` — Pi Pico 2 W (RP2350)
- `picow.yaml` — Pi Pico W (RP2040)

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/synth/pico2w.yaml
# tap BOOTSEL to cycle voices; sequencer auto-advances melodies
```

## Related

- [`drums/`](../drums/) — TR-808-style synthesized percussion (drum module).
- [`audio_player/`](../audio_player/) — codec-driven playback from files.
