//! Wiring configuration format encoding and decoding
//!
//! Supports both the current pointer-based format (FXCF) and legacy format (FXWR).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde_json::{json, Map, Value};

use fluxor_contracts::vocabulary::capability_and_parents;

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;
use crate::manifest::{self, Manifest, TimerClass};
use crate::schema;
use crate::uf2::extract_region;

/// Magic numbers
pub const MAGIC_CONFIG: u32 = 0x46435846; // "FXCF" (current format)
pub const MAGIC_LEGACY: u32 = crate::trust_anchors::FXWR_MAGIC; // "FXWR" (legacy format)

/// Maximum counts
const MAX_SOURCES: usize = 8;
const MAX_SINKS: usize = 8;
const MAX_TRANSFORMERS: usize = 8;

/// Entry sizes (legacy format)
const SOURCE_SIZE: usize = 76;
const SINK_SIZE: usize = 76;
const TRANSFORMER_SIZE: usize = 72;
const PIPELINE_SIZE: usize = 8;

const MAX_HW_SPI: usize = 2;
const MAX_HW_I2C: usize = 2;
const MAX_HW_UART: usize = 2;
const MAX_HW_GPIO: usize = 8;
const MAX_HW_PIO: usize = 3;

/// Type mappings
const SOURCE_TYPES: &[&str] = &[
    "None",
    "MqttTopic",
    "SdCard",
    "SdCardFile",
    "GpioInput",
    "Timer",
    "UartRx",
    "I2cRead",
    "SpiRead",
    "SpiFrame",
    "AdcChannel",
    "TcpSocket",
    "Playlist",
    "TestTone",
];

const SINK_TYPES: &[&str] = &[
    "None",
    "I2sOutput",
    "MqttPublish",
    "GpioOutput",
    "UartTx",
    "I2cWrite",
    "SpiWrite",
    "PwmOutput",
    "SdCardWrite",
    "TcpSocket",
    "Log",
    "Led",
];

const TRANSFORMER_TYPES: &[&str] = &[
    "None",
    "AudioFormat",
    "Resampler",
    "GpioToMqtt",
    "MqttToGpio",
    "RawToAudio",
    "Aggregate",
    "Split",
    "Passthrough",
    "Digest",
];

// `CONTENT_TYPES` lives in `crate::manifest`; we re-use the same
// table here so manifest parsing and compiled-config decoding can
// never drift apart. Originally `config.rs` carried a positional
// mirror of the manifest table — appending out of sync silently
// re-numbered every wire byte downstream of the divergence point.
use crate::manifest::CONTENT_TYPES;

const INPUT_CONTROL_TYPES: &[&str] = &["Button", "Range"];

const INPUT_SOURCE_TYPES: &[&str] = &["GpioInput", "AdcChannel", "Touch", "System"];

const GESTURE_PATTERNS: &[&str] = &[
    "Click",
    "Long",
    "Double",
    "Triple",
    "Hold",
    "Release",
    "Change",
    "CrossUp",
    "CrossDown",
];

/// Read null-terminated string from memory map
fn read_string_at(memory: &BTreeMap<u32, u8>, addr: u32) -> String {
    if addr == 0 {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut a = addr;
    while let Some(&b) = memory.get(&a) {
        if b == 0 {
            break;
        }
        chars.push(b as char);
        a += 1;
    }
    chars.into_iter().collect()
}

/// Read UUID from memory and format as string
fn read_uuid_at(memory: &BTreeMap<u32, u8>, addr: u32) -> String {
    if addr == 0 {
        return String::new();
    }
    if let Some(bytes) = extract_region(memory, addr, 16) {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        )
    } else {
        String::new()
    }
}

/// Format UUID bytes as string
fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn get_type_name(types: &[&str], id: u8) -> String {
    types
        .get(id as usize)
        .map_or_else(|| format!("Unknown({id})"), |s| s.to_string())
}

/// Decode source entry from binary (pointer-based format, 16 bytes)
fn decode_source(entry: &[u8], memory: &BTreeMap<u32, u8>) -> Value {
    let type_id = entry[0];
    let id = entry[1];
    let content_type = entry[2];

    let mut result = Map::new();
    result.insert("type".into(), json!(get_type_name(SOURCE_TYPES, type_id)));
    result.insert("id".into(), json!(id));

    if content_type != 0 {
        result.insert(
            "content_type".into(),
            json!(get_type_name(CONTENT_TYPES, content_type)),
        );
    }

    let union_data = &entry[4..16];

    match type_id {
        1 => {
            // MqttTopic
            let topic_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert("topic".into(), json!(read_string_at(memory, topic_ptr)));
            result.insert("qos".into(), json!(union_data[8]));
        }
        2 => {
            // SdCard
            let start =
                u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let count =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("start_block".into(), json!(start));
            result.insert("block_count".into(), json!(count));
        }
        3 => {
            // SdCardFile
            let path_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert("path".into(), json!(read_string_at(memory, path_ptr)));
        }
        4 => {
            // GpioInput
            result.insert("pin".into(), json!(union_data[0]));
            let edge = match union_data[1] {
                0 => "falling",
                1 => "rising",
                _ => "both",
            };
            result.insert("edge".into(), json!(edge));
            let pull = match union_data[2] {
                1 => "up",
                2 => "down",
                _ => "none",
            };
            result.insert("pull".into(), json!(pull));
        }
        5 => {
            // Timer
            let interval =
                u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            result.insert("interval_us".into(), json!(interval));
            result.insert("periodic".into(), json!(union_data[4] != 0));
        }
        6 => {
            // UartRx
            result.insert("uart_id".into(), json!(union_data[0]));
            let baudrate =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("baudrate".into(), json!(baudrate));
        }
        7 => {
            // I2cRead
            result.insert("i2c_id".into(), json!(union_data[0]));
            result.insert("address".into(), json!(format!("0x{:02x}", union_data[1])));
            result.insert("register".into(), json!(format!("0x{:02x}", union_data[2])));
            result.insert("length".into(), json!(union_data[3]));
        }
        8 => {
            // SpiRead
            result.insert("spi_id".into(), json!(union_data[0]));
            result.insert("cs_pin".into(), json!(union_data[1]));
        }
        9 => {
            // SpiFrame - not decoded here (requires more union data)
        }
        10 => {
            // AdcChannel
            result.insert("channel".into(), json!(union_data[0]));
            let rate =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("sample_rate".into(), json!(rate));
        }
        11 => {
            // TcpSocket
            let host_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            let port = u16::from_le_bytes([union_data[8], union_data[9]]);
            result.insert("host".into(), json!(read_string_at(memory, host_ptr)));
            result.insert("port".into(), json!(port));
            result.insert(
                "mode".into(),
                json!(if union_data[10] != 0 {
                    "server"
                } else {
                    "client"
                }),
            );
        }
        12 => {
            // Playlist
            let dir_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert("directory".into(), json!(read_string_at(memory, dir_ptr)));
            let mode = match union_data[8] {
                0 => "sequential",
                1 => "loop",
                2 => "loop_one",
                _ => "shuffle",
            };
            result.insert("mode".into(), json!(mode));
            result.insert("auto_start".into(), json!(union_data[9] != 0));
        }
        13 => {
            // TestTone
            let freq =
                u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let rate =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("frequency".into(), json!(freq));
            result.insert("sample_rate".into(), json!(rate));
        }
        _ => {}
    }

    Value::Object(result)
}

/// Decode sink entry from binary (pointer-based format, 16 bytes)
fn decode_sink(entry: &[u8], memory: &BTreeMap<u32, u8>) -> Value {
    let type_id = entry[0];
    let id = entry[1];
    let content_type = entry[2];

    let mut result = Map::new();
    result.insert("type".into(), json!(get_type_name(SINK_TYPES, type_id)));
    result.insert("id".into(), json!(id));

    if content_type != 0 {
        result.insert(
            "content_type".into(),
            json!(get_type_name(CONTENT_TYPES, content_type)),
        );
    }

    let union_data = &entry[4..16];

    match type_id {
        1 => {
            // I2sOutput
            result.insert("data_pin".into(), json!(union_data[0]));
            result.insert("clock_pin_base".into(), json!(union_data[1]));
            result.insert("bits".into(), json!(union_data[2]));
            let rate =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("sample_rate".into(), json!(rate));
        }
        2 => {
            // MqttPublish
            let topic_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert("topic".into(), json!(read_string_at(memory, topic_ptr)));
            result.insert("qos".into(), json!(union_data[8]));
            result.insert("retain".into(), json!(union_data[9] != 0));
        }
        3 => {
            // GpioOutput
            result.insert("pin".into(), json!(union_data[0]));
            result.insert("initial".into(), json!(union_data[1]));
        }
        4 => {
            // UartTx
            result.insert("uart_id".into(), json!(union_data[0]));
        }
        5 => {
            // I2cWrite
            result.insert("i2c_id".into(), json!(union_data[0]));
            result.insert("address".into(), json!(format!("0x{:02x}", union_data[1])));
        }
        6 => {
            // SpiWrite
            result.insert("spi_id".into(), json!(union_data[0]));
            result.insert("cs_pin".into(), json!(union_data[1]));
        }
        7 => {
            // PwmOutput
            result.insert("slice".into(), json!(union_data[0]));
            result.insert("channel".into(), json!(union_data[1]));
            let wrap = u16::from_le_bytes([union_data[2], union_data[3]]);
            let initial = u16::from_le_bytes([union_data[4], union_data[5]]);
            result.insert("wrap".into(), json!(wrap));
            result.insert("initial".into(), json!(initial));
        }
        9 => {
            // TcpSocket
            let host_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            let port = u16::from_le_bytes([union_data[8], union_data[9]]);
            result.insert("host".into(), json!(read_string_at(memory, host_ptr)));
            result.insert("port".into(), json!(port));
        }
        10 => {
            // Log
            result.insert("level".into(), json!(union_data[0]));
        }
        11 => {
            // Led
            result.insert("initial".into(), json!(union_data[0]));
        }
        _ => {}
    }

    Value::Object(result)
}

/// Decode transformer entry from binary (pointer-based format, 16 bytes)
fn decode_transformer(entry: &[u8], memory: &BTreeMap<u32, u8>) -> Value {
    let type_id = entry[0];
    let id = entry[1];

    let mut result = Map::new();
    result.insert(
        "type".into(),
        json!(get_type_name(TRANSFORMER_TYPES, type_id)),
    );
    result.insert("id".into(), json!(id));

    let union_data = &entry[4..16];

    match type_id {
        1 => {
            // AudioFormat
            result.insert("input_format".into(), json!(union_data[0]));
            result.insert("output_format".into(), json!(union_data[1]));
            let gain = u16::from_le_bytes([union_data[2], union_data[3]]);
            result.insert("gain".into(), json!(gain as f64 / 256.0));
        }
        2 => {
            // Resampler
            let in_rate =
                u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let out_rate =
                u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("input_rate".into(), json!(in_rate));
            result.insert("output_rate".into(), json!(out_rate));
        }
        3 => {
            // GpioToMqtt
            let prefix_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert(
                "topic_prefix".into(),
                json!(read_string_at(memory, prefix_ptr)),
            );
            result.insert("json_format".into(), json!(union_data[8] != 0));
            result.insert("include_timestamp".into(), json!(union_data[9] != 0));
        }
        4 => {
            // MqttToGpio
            let filter_ptr = u64::from_le_bytes([
                union_data[0],
                union_data[1],
                union_data[2],
                union_data[3],
                union_data[4],
                union_data[5],
                union_data[6],
                union_data[7],
            ]) as u32;
            result.insert(
                "topic_filter".into(),
                json!(read_string_at(memory, filter_ptr)),
            );
            result.insert("json_format".into(), json!(union_data[8] != 0));
        }
        5 => {
            // RawToAudio
            result.insert("format".into(), json!(union_data[0]));
        }
        6 => {
            // Aggregate
            let target = u16::from_le_bytes([union_data[0], union_data[1]]);
            result.insert("target_size".into(), json!(target));
        }
        7 => {
            // Split
            let max_size = u16::from_le_bytes([union_data[0], union_data[1]]);
            result.insert("max_size".into(), json!(max_size));
        }
        _ => {}
    }

    Value::Object(result)
}

/// Decode pipeline entry
fn decode_pipeline(entry: &[u8]) -> Value {
    let source_id = entry[0];
    let sink_id = entry[1];
    let transformer_ids: Vec<u8> = entry[2..6].to_vec();
    let transformer_count = entry[6];
    let enabled = entry[7] != 0;

    json!({
        "source_id": source_id,
        "sink_id": sink_id,
        "transformers": transformer_ids[..transformer_count as usize].to_vec(),
        "enabled": enabled,
    })
}

/// Decode graph edge entry (4 bytes)
fn decode_graph_edge(entry: &[u8]) -> Value {
    let from_id = entry[0];
    let to_id = entry[1];
    let byte2 = entry[2];
    let to_port = (byte2 >> 7) & 1;
    let edge_class = (byte2 >> 5) & 0x03;
    let buffer_group = byte2 & 0x1F;
    let port_byte = entry[3];
    let from_port_index = (port_byte >> 4) & 0x0F;
    let to_port_index = port_byte & 0x0F;
    // bytes 4-7: buffer_bytes u32 LE.
    let buffer_bytes = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
    // byte 8: rate_class (absent in truncated slices → control).
    let rate_class = entry.get(8).copied().unwrap_or(0);
    let mut edge = serde_json::Map::new();
    edge.insert("from_id".into(), json!(from_id));
    edge.insert("to_id".into(), json!(to_id));
    edge.insert(
        "to_port".into(),
        json!(if to_port == 1 { "ctrl" } else { "in" }),
    );
    if buffer_group > 0 {
        edge.insert("buffer_group".into(), json!(buffer_group));
    }
    if from_port_index != 0 || to_port_index != 0 {
        edge.insert("from_port_index".into(), json!(from_port_index));
        edge.insert("to_port_index".into(), json!(to_port_index));
    }
    if edge_class != 0 {
        let ec_name = match edge_class {
            1 => "dma_owned",
            2 => "cross_core",
            3 => "nic_ring",
            _ => "local",
        };
        edge.insert("edge_class".into(), json!(ec_name));
    }
    if buffer_bytes != 0 {
        edge.insert("buffer_bytes".into(), json!(buffer_bytes));
    }
    if rate_class != 0 {
        let rc = fluxor_contracts::RateClass::from_str_opt(match rate_class {
            1 => "audio",
            2 => "video",
            3 => "bulk",
            _ => "control",
        });
        if let Some(rc) = rc {
            edge.insert("rate".into(), json!(rc.as_str()));
        }
    }
    Value::Object(edge)
}

/// Decode input control entry (8 bytes)
fn decode_control(entry: &[u8]) -> Value {
    let id = entry[0];
    let type_id = entry[1];
    let source_type = entry[2];
    let params = &entry[4..8];

    let mut result = Map::new();
    result.insert("id".into(), json!(id));
    result.insert(
        "type".into(),
        json!(get_type_name(INPUT_CONTROL_TYPES, type_id)),
    );
    result.insert(
        "source".into(),
        json!(get_type_name(INPUT_SOURCE_TYPES, source_type)),
    );

    match source_type {
        0 => {
            // GpioInput
            result.insert("pin".into(), json!(params[0]));
            let pull = match params[1] {
                1 => "up",
                2 => "down",
                _ => "none",
            };
            result.insert("pull".into(), json!(pull));
            if params[2] != 0 {
                result.insert("active_low".into(), json!(true));
            }
        }
        1 => {
            // AdcChannel
            result.insert("channel".into(), json!(params[0]));
        }
        2 => {
            // Touch
            result.insert("region".into(), json!(params[0]));
        }
        3 => {
            // System
            let event = match params[0] {
                0 => "bootsel",
                _ => "unknown",
            };
            result.insert("event".into(), json!(event));
        }
        _ => {}
    }

    Value::Object(result)
}

/// Decode gesture pattern entry (8 bytes)
fn decode_gesture(entry: &[u8]) -> Value {
    let control_id = entry[0];
    let pattern = entry[1];
    let param = u16::from_le_bytes([entry[2], entry[3]]);
    let action = u16::from_le_bytes([entry[4], entry[5]]);
    let target_id = entry[6];
    let flags = entry[7];

    let mut result = Map::new();
    result.insert("control".into(), json!(control_id));
    result.insert(
        "pattern".into(),
        json!(get_type_name(GESTURE_PATTERNS, pattern)),
    );

    if param != 0 {
        match pattern {
            0 | 1 => result.insert("threshold_ms".into(), json!(param)),
            2 | 3 => result.insert("window_ms".into(), json!(param)),
            6 => result.insert("deadband".into(), json!(param)),
            7 | 8 => result.insert("threshold".into(), json!(param)),
            _ => None,
        };
    }

    // Action names
    let action_name = match action {
        0x0001 => "Ping",
        0x0002 => "GetState",
        0x0006 => "Start",
        0x0007 => "Stop",
        0x0008 => "Reset",
        0x0100 => "Play",
        0x0101 => "Pause",
        0x0102 => "Next",
        0x0103 => "Previous",
        0x0104 => "SetVolume",
        0x0105 => "PlayPause",
        0x0200 => "SetPin",
        0x0201 => "GetPin",
        0x0202 => "Toggle",
        0xF001 => "Reboot",
        0xF002 => "BootselMode",
        _ => "",
    };

    if action_name.is_empty() {
        result.insert("action".into(), json!(format!("0x{:04x}", action)));
    } else {
        result.insert("action".into(), json!(action_name));
    }

    if target_id != 0xFF {
        result.insert("target".into(), json!(target_id));
    }
    if flags & 0x01 != 0 {
        result.insert("value_from_range".into(), json!(true));
    }

    Value::Object(result)
}

/// Decode object entry (32 bytes in pointer format)
fn decode_object(entry: &[u8], memory: &BTreeMap<u32, u8>) -> Value {
    let uuid_bytes = &entry[0..16];
    let name_ptr = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
    let emits_ptr = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
    let accepts_ptr = u32::from_le_bytes([entry[24], entry[25], entry[26], entry[27]]);
    let emit_count = entry[28];
    let accept_count = entry[29];
    let enabled = entry[30] != 0;

    let mut result = Map::new();
    result.insert("uuid".into(), json!(format_uuid(uuid_bytes)));
    result.insert("name".into(), json!(read_string_at(memory, name_ptr)));
    result.insert("enabled".into(), json!(enabled));

    // Decode emit bindings
    let mut emits = Vec::new();
    for i in 0..emit_count {
        if let Some(binding) = extract_region(memory, emits_ptr + (i as u32) * 2, 2) {
            emits.push(json!({
                "content_type": get_type_name(CONTENT_TYPES, binding[0]),
                "pipeline_id": binding[1],
            }));
        }
    }
    result.insert("emits".into(), json!(emits));

    // Decode accept bindings
    let mut accepts = Vec::new();
    for i in 0..accept_count {
        if let Some(binding) = extract_region(memory, accepts_ptr + (i as u32) * 2, 2) {
            accepts.push(json!({
                "content_type": get_type_name(CONTENT_TYPES, binding[0]),
                "pipeline_id": binding[1],
            }));
        }
    }
    result.insert("accepts".into(), json!(accepts));

    Value::Object(result)
}

/// Decode current format (FXCF, pointer-based)
fn decode_current_format(header_data: &[u8], memory: &BTreeMap<u32, u8>) -> Result<Value> {
    // Parse header (64 bytes)
    let _magic = u32::from_le_bytes([
        header_data[0],
        header_data[1],
        header_data[2],
        header_data[3],
    ]);
    let _total_size = u16::from_le_bytes([header_data[4], header_data[5]]);
    let source_count = header_data[6];
    let sink_count = header_data[7];
    let transformer_count = header_data[8];
    let pipeline_count = header_data[9];
    let object_count = header_data[10];
    let control_count = header_data[11];
    let gesture_count = header_data[12];

    // Pointers (at offset 16)
    let sources_ptr = u32::from_le_bytes([
        header_data[16],
        header_data[17],
        header_data[18],
        header_data[19],
    ]);
    let sinks_ptr = u32::from_le_bytes([
        header_data[20],
        header_data[21],
        header_data[22],
        header_data[23],
    ]);
    let transformers_ptr = u32::from_le_bytes([
        header_data[24],
        header_data[25],
        header_data[26],
        header_data[27],
    ]);
    let pipelines_ptr = u32::from_le_bytes([
        header_data[28],
        header_data[29],
        header_data[30],
        header_data[31],
    ]);
    let objects_ptr = u32::from_le_bytes([
        header_data[32],
        header_data[33],
        header_data[34],
        header_data[35],
    ]);
    let _strings_ptr = u32::from_le_bytes([
        header_data[36],
        header_data[37],
        header_data[38],
        header_data[39],
    ]);

    // Device identity (at offset 48)
    let device_uuid_ptr = u32::from_le_bytes([
        header_data[48],
        header_data[49],
        header_data[50],
        header_data[51],
    ]);
    let device_name_ptr = u32::from_le_bytes([
        header_data[52],
        header_data[53],
        header_data[54],
        header_data[55],
    ]);

    // Controls and gestures (at offset 56)
    let controls_ptr = u32::from_le_bytes([
        header_data[56],
        header_data[57],
        header_data[58],
        header_data[59],
    ]);
    let gestures_ptr = u32::from_le_bytes([
        header_data[60],
        header_data[61],
        header_data[62],
        header_data[63],
    ]);

    let mut result = Map::new();

    // Device identity
    if device_uuid_ptr != 0 {
        result.insert(
            "device_uuid".into(),
            json!(read_uuid_at(memory, device_uuid_ptr)),
        );
    }
    if device_name_ptr != 0 {
        result.insert(
            "device_name".into(),
            json!(read_string_at(memory, device_name_ptr)),
        );
    }

    // Decode sources
    let mut sources = Vec::new();
    for i in 0..source_count {
        if let Some(entry) = extract_region(memory, sources_ptr + (i as u32) * 16, 16) {
            sources.push(decode_source(&entry, memory));
        }
    }
    result.insert("sources".into(), json!(sources));

    // Decode sinks
    let mut sinks = Vec::new();
    for i in 0..sink_count {
        if let Some(entry) = extract_region(memory, sinks_ptr + (i as u32) * 16, 16) {
            sinks.push(decode_sink(&entry, memory));
        }
    }
    result.insert("sinks".into(), json!(sinks));

    // Decode transformers
    let mut transformers = Vec::new();
    for i in 0..transformer_count {
        if let Some(entry) = extract_region(memory, transformers_ptr + (i as u32) * 16, 16) {
            transformers.push(decode_transformer(&entry, memory));
        }
    }
    result.insert("transformers".into(), json!(transformers));

    // Decode pipelines
    let mut pipelines = Vec::new();
    for i in 0..pipeline_count {
        if let Some(entry) = extract_region(memory, pipelines_ptr + (i as u32) * 8, 8) {
            pipelines.push(decode_pipeline(&entry));
        }
    }
    result.insert("pipelines".into(), json!(pipelines));

    // Decode objects
    let mut objects = Vec::new();
    for i in 0..object_count {
        if let Some(entry) = extract_region(memory, objects_ptr + (i as u32) * 32, 32) {
            objects.push(decode_object(&entry, memory));
        }
    }
    result.insert("objects".into(), json!(objects));

    // Decode controls
    let mut controls = Vec::new();
    for i in 0..control_count {
        if let Some(entry) = extract_region(memory, controls_ptr + (i as u32) * 8, 8) {
            controls.push(decode_control(&entry));
        }
    }
    result.insert("controls".into(), json!(controls));

    // Decode gestures
    let mut gestures = Vec::new();
    for i in 0..gesture_count {
        if let Some(entry) = extract_region(memory, gestures_ptr + (i as u32) * 8, 8) {
            gestures.push(decode_gesture(&entry));
        }
    }
    result.insert("gestures".into(), json!(gestures));

    Ok(Value::Object(result))
}

/// Decode legacy format (FXWR, fixed-width)
fn decode_legacy_format(data: &[u8]) -> Result<Value> {
    // Header: magic(4) + version(2) + checksum(2) + counts(4) = 12 bytes
    let version = u16::from_le_bytes([data[4], data[5]]);
    let source_count = data[8];
    let sink_count = data[9];
    let transformer_count = data[10];
    // In version 3+, byte 11 is edge_count; in versions 1-2, it's pipeline_count
    let count_byte_11 = data[11];

    let mut result = Map::new();
    result.insert(
        "format".into(),
        json!(if version >= 3 { "graph" } else { "legacy" }),
    );
    result.insert("version".into(), json!(version));
    result.insert("source_count".into(), json!(source_count));
    result.insert("sink_count".into(), json!(sink_count));
    result.insert("transformer_count".into(), json!(transformer_count));
    if version >= 3 {
        result.insert("edge_count".into(), json!(count_byte_11));
    } else {
        result.insert("pipeline_count".into(), json!(count_byte_11));
    }
    result.insert(
        "note".into(),
        json!("FXWR format - detailed decoding available for basic types"),
    );

    // Parse sources from legacy format
    let sources_offset = 16; // After header + counts
    let mut sources = Vec::new();
    for i in 0..source_count as usize {
        let offset = sources_offset + i * SOURCE_SIZE;
        if offset + 8 <= data.len() {
            let type_id = data[offset];
            let id = data[offset + 1];
            let mut src = Map::new();
            src.insert("type".into(), json!(get_type_name(SOURCE_TYPES, type_id)));
            src.insert("id".into(), json!(id));

            // Decode basic params based on type
            match type_id {
                2 => {
                    // SdCard
                    let start = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let count = u32::from_le_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);
                    src.insert("start_block".into(), json!(start));
                    src.insert("block_count".into(), json!(count));
                }
                5 => {
                    // Timer
                    let interval = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    src.insert("interval_us".into(), json!(interval));
                    src.insert("periodic".into(), json!(data[offset + 8] != 0));
                }
                _ => {}
            }
            sources.push(Value::Object(src));
        }
    }
    result.insert("sources".into(), json!(sources));

    // Parse sinks
    let sinks_offset = sources_offset + MAX_SOURCES * SOURCE_SIZE;
    let mut sinks = Vec::new();
    for i in 0..sink_count as usize {
        let offset = sinks_offset + i * SINK_SIZE;
        if offset + 8 <= data.len() {
            let type_id = data[offset];
            let id = data[offset + 1];
            let mut snk = Map::new();
            snk.insert("type".into(), json!(get_type_name(SINK_TYPES, type_id)));
            snk.insert("id".into(), json!(id));

            match type_id {
                1 => {
                    // I2sOutput
                    snk.insert("data_pin".into(), json!(data[offset + 4]));
                    snk.insert("clock_pin_base".into(), json!(data[offset + 5]));
                    snk.insert("bits".into(), json!(data[offset + 6]));
                    let rate = u32::from_le_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);
                    snk.insert("sample_rate".into(), json!(rate));
                }
                11 => {
                    // Led
                    snk.insert("initial".into(), json!(data[offset + 4]));
                }
                _ => {}
            }
            sinks.push(Value::Object(snk));
        }
    }
    result.insert("sinks".into(), json!(sinks));

    // Parse transformers
    let transformers_offset = sinks_offset + MAX_SINKS * SINK_SIZE;
    let mut transformers = Vec::new();
    for i in 0..transformer_count as usize {
        let offset = transformers_offset + i * TRANSFORMER_SIZE;
        if offset + 16 <= data.len() {
            let type_id = data[offset];
            let id = data[offset + 1];
            let mut xform = Map::new();
            xform.insert(
                "type".into(),
                json!(get_type_name(TRANSFORMER_TYPES, type_id)),
            );
            xform.insert("id".into(), json!(id));

            match type_id {
                1 => {
                    // AudioFormat: input_rate(4), output_rate(4), input_format(1), output_format(1), gain(2)
                    let in_rate = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let out_rate = u32::from_le_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);
                    let in_fmt = data[offset + 12];
                    let out_fmt = data[offset + 13];
                    let gain = u16::from_le_bytes([data[offset + 14], data[offset + 15]]);
                    xform.insert("input_rate".into(), json!(in_rate));
                    xform.insert("output_rate".into(), json!(out_rate));
                    xform.insert(
                        "input_format".into(),
                        json!(if in_fmt == 0 { "u8_mono" } else { "i16_mono" }),
                    );
                    xform.insert(
                        "output_format".into(),
                        json!(if out_fmt == 0 {
                            "i16_mono"
                        } else {
                            "i16_stereo"
                        }),
                    );
                    xform.insert("gain".into(), json!(gain));
                }
                2 => {
                    // Resampler: input_rate(4), output_rate(4)
                    let in_rate = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let out_rate = u32::from_le_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);
                    xform.insert("input_rate".into(), json!(in_rate));
                    xform.insert("output_rate".into(), json!(out_rate));
                }
                9 => {
                    // Digest - no additional params
                }
                _ => {}
            }
            transformers.push(Value::Object(xform));
        }
    }
    result.insert("transformers".into(), json!(transformers));

    // Parse pipelines or graph edges depending on version
    let pipelines_offset = transformers_offset + MAX_TRANSFORMERS * TRANSFORMER_SIZE;

    if version >= 3 {
        // Version 3: Graph section (64 bytes)
        // Format: edge_count(1), flags(1), reserved(2), edges(4 bytes each)
        let graph_offset = pipelines_offset;
        let edge_count = count_byte_11 as usize;

        let mut edges = Vec::new();
        // Skip header (4 bytes), edges start at offset 4
        for i in 0..edge_count.min(MAX_GRAPH_EDGES) {
            let offset = graph_offset + 4 + i * GRAPH_EDGE_SIZE;
            if offset + GRAPH_EDGE_SIZE <= data.len() {
                edges.push(decode_graph_edge(&data[offset..offset + GRAPH_EDGE_SIZE]));
            }
        }
        result.insert("graph".into(), json!(edges));
    } else {
        // Version 1-2: Pipelines (8 bytes each)
        let pipeline_count = count_byte_11 as usize;
        let mut pipelines = Vec::new();
        for i in 0..pipeline_count {
            let offset = pipelines_offset + i * PIPELINE_SIZE;
            if offset + 8 <= data.len() {
                pipelines.push(decode_pipeline(&data[offset..offset + 8]));
            }
        }
        result.insert("pipelines".into(), json!(pipelines));
    }

    Ok(Value::Object(result))
}

/// Decode config from binary data
pub fn decode_config(data: &[u8], memory: &BTreeMap<u32, u8>) -> Result<Value> {
    if data.len() < 4 {
        return Err(Error::Config("Config data too short".into()));
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match magic {
        MAGIC_CONFIG => {
            if data.len() < 64 {
                return Err(Error::Config("Current format config too short".into()));
            }
            decode_current_format(data, memory)
        }
        MAGIC_LEGACY => decode_legacy_format(data),
        _ => Err(Error::Config(format!(
            "Unknown config magic: 0x{magic:08x}"
        ))),
    }
}

// =============================================================================
// Config Generation
// =============================================================================

/// Config builder for generating binary configs
#[derive(Default)]
pub struct ConfigBuilder;

impl ConfigBuilder {
    pub fn new() -> Self {
        Self
    }
}

// ── Split for navigability ──────────────────────────────────────────────────
// The wiring-config module was one 9.3k-line file. It is split into sibling
// files pulled in via `include!` (the repo's SDK-file convention), which keeps
// a single flat scope — every cross-reference, const, and private item resolves
// exactly as before, with no visibility changes. Each file is one cohesive area.
include!("builder.rs"); // ConfigBuilder + graph-config generation
include!("manifest.rs"); // module search paths + manifest loading
include!("validate.rs"); // presentation-group + continuity validators
include!("placement.rs"); // members composed from another node
include!("generate.rs"); // FXWR encode, ModuleCaps, generate_config_ext
include!("tests.rs"); // #[cfg(test)] suites
