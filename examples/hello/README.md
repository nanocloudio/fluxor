# `hello/` — minimal bare-metal smoke test

Literally the smallest valid fluxor config: `modules: []`, `wiring: []`.
Validates that the kernel boots on the target, drives its scheduler
tick, and reaches the platform-runtime debug drain (which lights up
UART output without needing any modules to be wired). Survives in
every environment that lets the kernel run at all.

## Targets

- `cm5.yaml` — bare-metal Pi 5; kernel log reaches the RP1 PL011
  on GPIO14/15 via the built-in debug drain, no overlay module
  required.

## Run

```sh
make firmware TARGET=cm5 && make modules TARGET=bcm2712
fluxor combine -o kernel8.img target/cm5/firmware.bin examples/hello/cm5.yaml
# netboot or copy kernel8.img to /boot/firmware/
tio /dev/ttyUSB0 -b 115200
```

The rig regression that drives this end-to-end:
[`tests/hardware/cm5_boot_banner.toml`](../../tests/hardware/cm5_boot_banner.toml).

## Related

- For network-aware demos see [`web_server/`](../web_server/) or
  [`log_net/`](../log_net/) (netconsole when UART is unavailable).
- Platform-bringup probes (DMA, GEM, NVMe identify) live under
  [`../test_harness/cm5/bringup/`](../test_harness/cm5/bringup/).
