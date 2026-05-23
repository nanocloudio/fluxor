# `button_control/` — button-driven scale player

A GPIO button drives a full audio chain: single-click toggles
play/pause, double-click advances to the next preset, triple-click
steps back. Shows the canonical three-layer input architecture
end-to-end on real audio output rather than a logging stub.

Pipeline:

```
button → gesture → bank → sequencer        (control chain)
sequencer → synth → i2s                    (audio chain)
```

The `button` module debounces a GPIO pin into raw 0/1 transitions;
`gesture` counts clicks and emits FMP verbs; `bank` cycles preset
selection; `sequencer` plays the current scale through `synth` to
the I²S DAC.

The BOOTSEL-button equivalent of the same chain uses `flash_rp` in
place of `button` — both emit the byte-identical `input::button`
raw contract. See [`led_patterns/`](../led_patterns/) for the
BOOTSEL variant driving an LED instead of audio.

## Targets

- `pico2w.yaml` — button on GPIO21 (active low), I²S DAC outputs

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/button_control/pico2w.yaml
# wire a button to GPIO21 → GND; tap to play
```

## Related

- [`synth/`](../synth/) — same synthesizer chain with 31 voice
  presets cyclable via BOOTSEL.
- [`led_patterns/`](../led_patterns/) — same three-layer input
  chain driving an LED.
- The contract: [`modules/sdk/contracts/input/button.rs`](../../modules/sdk/contracts/input/button.rs)
