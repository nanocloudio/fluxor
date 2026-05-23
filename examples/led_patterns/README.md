# `led_patterns/` — button-cycled LED demo

The canonical "fluxor + LED" demo for RP boards. BOOTSEL single-click
advances to the next pattern, double-click steps back. Four patterns
share one sequencer thanks to per-preset cadence in the `data:` block:

1. `blink` — 1 Hz square wave (500 ms on / 500 ms off)
2. `breathe` — gamma-corrected sine ramp, 32 steps × 50 ms (~1.6 s)
3. `solid_on` — LED held on
4. `off` — LED held off

Pipeline:

```
flash_rp.raw → gesture.commands → sequencer.control
sequencer.notes → brightness.source → cyw43.led
```

The `brightness` module with gamma22 maps 0 ↔ 0 and 255 ↔ 255 exactly,
so the blink pattern still produces a clean square wave through it —
no separate fast path needed.

## Targets

- `pico2w.yaml` — Pi Pico 2 W (RP2350)
- `picow.yaml` — Pi Pico W (RP2040)

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/led_patterns/pico2w.yaml
# tap BOOTSEL to cycle patterns
```

Replaces the older `blinky`, `breathe`, and `led_switch` examples —
each was a one-pattern slice of the same graph shape.

## Related

- [`button_control/`](../button_control/) — same three-layer input
  chain (button → gesture → bank) driving audio instead of an LED.
- [`synth/`](../synth/) — same BOOTSEL-cycles-presets pattern with
  a tonal synthesiser instead of brightness levels.
