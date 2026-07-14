// =============================================================================
// Example Configs
// =============================================================================

use std::collections::HashMap;
use std::sync::LazyLock;

pub static EXAMPLES: LazyLock<HashMap<&'static str, Value>> = LazyLock::new(|| {
    let mut m = HashMap::new();

    m.insert(
        "blinky",
        json!({
            "modules": {
                "timer": {"type": "timer", "interval_us": 1000000, "periodic": true},
                "led": {"type": "led", "initial": 0}
            },
            "wiring": [
                {"from": "timer.out", "to": "led.in"}
            ]
        }),
    );

    m.insert("sd-audio", json!({
        "modules": {
            "sd": {"type": "sd", "start_block": 0, "block_count": 131072},
            "format": {"type": "format", "input_rate": 11025, "output_rate": 44100, "input_bits": 8, "input_channels": 1},
            "i2s": {"type": "i2s_output", "data_pin": 28, "clock_pin_base": 26, "bits": 16, "sample_rate": 44100}
        },
        "wiring": [
            {"from": "sd.out", "to": "format.in"},
            {"from": "format.out", "to": "i2s.in"}
        ]
    }));

    m.insert("playlist", json!({
        "modules": {
            "playlist": {"type": "playlist", "directory": "/music", "mode": "loop", "auto_start": true},
            "i2s": {"type": "i2s_output", "data_pin": 28, "clock_pin_base": 26, "bits": 16, "sample_rate": 44100}
        },
        "wiring": [
            {"from": "playlist.out", "to": "i2s.in"}
        ]
    }));

    m.insert("test-tone", json!({
        "modules": {
            "tone": {"type": "test_tone", "frequency": 440, "sample_rate": 44100},
            "i2s": {"type": "i2s_output", "data_pin": 28, "clock_pin_base": 26, "bits": 16, "sample_rate": 44100}
        },
        "wiring": [
            {"from": "tone.out", "to": "i2s.in"}
        ]
    }));

    m.insert(
        "button-led",
        json!({
            "modules": {
                "button": {"type": "button", "pin": 15, "pull": "up", "active_low": 1},
                "led": {"type": "led", "initial": 0}
            },
            "wiring": [
                {"from": "button.out", "to": "led.in"}
            ]
        }),
    );

    m.insert(
        "button-bootsel",
        json!({
            "modules": {
                "button": {"type": "button"},
                "led": {"type": "led", "initial": 0}
            },
            "wiring": [
                {"from": "button.out", "to": "led.in"}
            ]
        }),
    );

    // HTTP/Icecast streaming - URL configured at runtime via MQTT
    m.insert("http-stream", json!({
        "sources": [
            {"type": "TcpSocket", "id": 0, "content_type": "AudioMp3"}
        ],
        "sinks": [
            {"type": "I2sOutput", "id": 0, "data_pin": 28, "clock_pin_base": 26, "bits": 16, "sample_rate": 44100}
        ],
        "pipelines": [
            {"source_id": 0, "sink_id": 0, "transformers": [], "enabled": true}
        ]
    }));

    m
});

