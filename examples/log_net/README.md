# `log_net/` — netconsole for bare-metal

Enables the `debug` stack with `to: net`: the kernel log ring is
drained each tick and forwarded as UDP datagrams via the ethernet+ip
path. Use when the UART is unavailable (a HAT blocks GPIO14/15) or
when you want to capture logs from multiple boards at once.

Optionally enables the monitor overlay — the monitor PIC module
periodically emits `MON_HIST` lines via `log::info!`, which flow
through the same netconsole stream. `fluxor monitor --net :6666`
consumes that stream and renders a live dashboard.
(Absorbed the former `log_net_monitor/pi5.yaml`.)

## Targets

- `pi5.yaml`

## Run

```sh
make firmware TARGET=pi5 && fluxor modules build --target bcm2712
fluxor combine -o kernel8.img target/pi5/firmware.bin examples/log_net/pi5.yaml

# Capture (any host on the same L2 segment)
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 6666))
while True:
    d, a = s.recvfrom(4096); print(a, d.decode(errors="replace"), end="")
PY

# Or, for the dashboard, uncomment `monitor: true` in the YAML and:
fluxor monitor --net :6666
```

## Related

- [`hello/`](../hello/) — the UART-only smoke test for pi5; use
  that when even the network is suspect.
- [`web_server/`](../web_server/) — the other canonical pi5
  network demo.
