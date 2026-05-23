# `mqtt_publisher/` — canonical MQTT publish demo

The fluxor MQTT example. Connects to a broker over WiFi, publishes
events as they occur. The payload here is **temperature alerts**
from the RP2350's onboard thermal diode, but the lesson is the
publish pipeline: any sensor → rules → MQTT graph follows this
shape.

Pipeline (data side):

```
temp_sensor.reading  →  rules.sensor          (every 5 s)
rules.alarm          →  mqtt.mesh_rx          (only on threshold cross)
```

Plus the standard MQTT control plane: `mqtt ⇄ ip ⇄ cyw43` (WiFi).

## Why `rules` is load-bearing (not decoration)

`rules` implements **hysteresis with cross-inhibition** — once the
high alarm fires, no more high alarms publish until temperature
drops below the *low* threshold, and vice versa. Without it the
sensor would publish on every reading near the boundary and the
broker would see flapping. This is the canonical "don't flap"
pattern for any threshold-based publisher; the `rules` module is
the right place to learn it.

## Threshold units

`high_threshold` and `low_threshold` are in **millidegrees Celsius**.
`30000` = 30 °C, `20000` = 20 °C. The example flags warm/cold
crossings; touch the pico to trigger one.

## Targets

- `pico2w.yaml` — broker hardcoded at `192.168.1.100:1883`,
  client_id `fluxor-temp-01`, topic `fluxor/temp`. Adjust those
  three values before flashing.

## Run

```sh
# Configure broker IP + WiFi credentials in the YAML
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/mqtt_publisher/pico2w.yaml

# Watch from any host on the same broker
mosquitto_sub -h <broker> -t 'fluxor/temp/+'
# warm or cool the chip — you'll see one alarm per threshold cross
```

## Related

- [`dns_server/`](../dns_server/) — another networked-app demo on
  the same pico2w + WiFi platform.
- For canonical HTTP/HTTPS publish patterns see
  [`web_server/`](../web_server/) — different transport, same idea
  of "configure routes, serve a payload."
