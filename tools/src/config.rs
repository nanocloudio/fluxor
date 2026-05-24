//! Wiring configuration format encoding and decoding
//!
//! Supports both the current pointer-based format (FXCF) and legacy format (FXWR).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;
use crate::manifest::{self, Manifest};
use crate::schema;
use crate::uf2::extract_region;

/// Magic numbers
pub const MAGIC_CONFIG: u32 = 0x46435846; // "FXCF" (current format)
pub const MAGIC_LEGACY: u32 = 0x52575846; // "FXWR" (legacy format)

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

// =============================================================================
// Graph Config (Version 3+)
// =============================================================================

/// Graph edge size in bytes (8 = 4-byte fixed header + 4-byte
/// `buffer_bytes` u32 LE override). Mirrors
/// `kernel::config::GRAPH_EDGE_SIZE`; the layout is documented there.
const GRAPH_EDGE_SIZE: usize = 8;
/// Maximum number of graph edges. Raised from 64 to 128 to fit the
/// Quantum graph (114 edges).
const MAX_GRAPH_EDGES: usize = 128;
/// Per-domain metadata: 4 domains × (tick_us:u16 + exec_mode:u8 + reserved:u8) = 16 bytes
const DOMAIN_META_SIZE: usize = 16;
/// Graph section size (header + edges + domain metadata)
const GRAPH_SECTION_SIZE: usize = 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE + DOMAIN_META_SIZE;

/// Maximum number of modules.
///
/// Raised from 24 to 64 to accommodate graphs like Quantum's multi-protocol
/// broker (42 modules: 23 Clustor substrate + 19 application). The wake
/// bitmap in `kernel/event.rs` also bumped to u64 to match.
const MAX_MODULES: usize = 64;

/// Module entry header size (entry_length:u32 + name_hash:u32 + id:u8 + reserved:u8).
/// entry_length widened to u32 so a single module's params can exceed
/// 64 KiB — needed by synth host's http module when both halves of a
/// split scenario inline the canonical wasm shell as body routes
/// (~95 KiB combined). Coordinated with `src/kernel/config.rs`'s
/// `parse_module_entry`, which reads matching field widths.
const MODULE_ENTRY_HEADER_SIZE: usize = 10;

/// Maximum module params size. 128 KiB accommodates the
/// wasm-scenario synth host's http module, which inlines the
/// canonical browser shell (runtime.html + host_shims.js, ~60 KiB
/// combined) as `body:` routes per the shared-infra-in-orchestrator
/// partition principle. Wavetables and large sequences fit
/// comfortably within the same bound.
const MAX_MODULE_PARAMS_SIZE: usize = 128 * 1024;

/// Param base offset within a module entry (= header size = 8)
const P: usize = MODULE_ENTRY_HEADER_SIZE;

/// Parse a waveform string into its numeric ID.
/// Used by synth, monosynth, and other oscillator-based modules.
/// Parse UUID string (with or without dashes) to 16 bytes. Returns [0; 16] on error.
fn parse_uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = [0u8; 16];
    if hex.len() != 32 {
        return out;
    }
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

/// Parse IPv4 address string to u32 (network byte order).
fn parse_ipv4(s: &str) -> u32 {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return 0;
    }
    let a = parts[0].parse::<u8>().unwrap_or(0);
    let b = parts[1].parse::<u8>().unwrap_or(0);
    let c = parts[2].parse::<u8>().unwrap_or(0);
    let d = parts[3].parse::<u8>().unwrap_or(0);
    u32::from_be_bytes([a, b, c, d])
}

/// Parse "host:port" string. Returns (ip_u32, port).
fn parse_broker_addr(s: &str) -> (u32, u16) {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let ip = parse_ipv4(parts.first().unwrap_or(&""));
    let port = parts
        .get(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(1883);
    (ip, port)
}

/// Default step deadline in microseconds — mirrors
/// `kernel::step_guard::DEFAULT_STEP_DEADLINE_US`. Kept duplicated
/// rather than imported so this tool stays independent of the kernel
/// crate's `no_std` feature set; the silicon-config drift guard in
/// `tools/tests/silicon_toml_shape.rs` pattern can be extended to
/// pin this if it ever needs to change.
const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// Maximum number of scheduling domains the kernel supports.
/// Mirrors `src/platform/bcm2712/multicore.rs::MAX_DOMAINS = 4` and
/// the scheduler's `MAX_DOMAINS` constant. The config writer
/// serialises exactly 4 domain-metadata entries; the wire format
/// has no slot for a 5th. Locked at the wire layer by
/// `tests/harness/tests/abi_wire_surface.rs` (the kernel-side
/// constant is exercised there); the tools side hardcodes the same
/// value here with a comment so a future bump touches both
/// together.
const MAX_DOMAINS: usize = 4;

/// Burst-mode deadline multiplier — mirrors
/// `kernel::step_guard::BURST_MULTIPLIER`.
const BURST_DEADLINE_MULTIPLIER: u32 = 8;

/// Effective tick_us when the config doesn't set one anywhere. Mirrors
/// the platform main-loop fallback (`tick_period_us = 1000` when
/// `cfg_header_tick_us == 0`).
const DEFAULT_TICK_US: u32 = 1000;

/// Hard absolute cap on a single module's burst deadline. The burst
/// path uses `step_deadline_us * BURST_MULTIPLIER` as its extended
/// timeout; capping the product at 100 ms keeps Tier 1a loops
/// responsive even when a misconfigured module runs through its full
/// burst budget. 100 ms is the conservative side of "no human-
/// perceivable jitter" for audio/video pipelines; raise this only
/// alongside a measured rationale.
const HARD_BURST_CAP_US: u32 = 100_000;

/// Soft warning threshold for the **declared** deadline sum on a
/// single domain, expressed as a multiple of the domain's tick_us.
/// Crossing this means the domain's modules collectively claim more
/// budget than the tick allots — if any sustained run hits its
/// declared deadline the loop slips. The threshold is a multiple
/// because per-module deadlines are *fault thresholds*, not expected
/// runtimes; most modules complete well inside their declared budget.
const DECLARED_DEADLINE_BUDGET_FACTOR: u32 = 4;

/// Cross-check that **explicitly declared** `step_deadline_us` values
/// fit inside the domain budgets. Modules that don't declare a
/// deadline silently use the kernel default
/// (`DEFAULT_STEP_DEADLINE_US = 2000`); that default is a fault
/// threshold, not a steady-state budget, and is intentionally bigger
/// than typical tick_us values — so it's excluded from the sum-vs-tick
/// invariant. Only opt-in deadlines are scored, because declaring a
/// deadline is the config author saying "I expect this module to
/// occasionally take this long, treat it as a real budget."
///
/// Rules enforced:
///   1. Per-module hard cap: declared `step_deadline_us *
///      BURST_MULTIPLIER` must not exceed `HARD_BURST_CAP_US` —
///      otherwise the burst path silently authorises a multi-tick
///      stall that starves every sibling module in the domain.
///   2. Per-module hard cap: `step_deadline_us * BURST_MULTIPLIER`
///      must not exceed `domain_tick_us * 16`. The burst guardrail
///      is meant to absorb spike workloads, not authorise unbounded
///      runaway loops.
///   3. Per-domain warning: when the **sum of declared deadlines**
///      exceeds `domain_tick_us * DECLARED_DEADLINE_BUDGET_FACTOR`,
///      emit a warning. Each module is making a deadline claim and
///      the domain can't keep all promises simultaneously.
///
/// `tick_us == 0` (graph-level) means "use platform default";
/// `domain_tick_us[i] == 0` means "use the graph-level tick".
fn validate_scheduler_budgets(
    config: &Value,
    module_list: &[Value],
    tick_us: u16,
    domain_names: &[String],
    domain_tick_us: &[u16],
) -> Result<()> {
    let effective_tick = |dtick: u16| -> u32 {
        if dtick > 0 {
            dtick as u32
        } else if tick_us > 0 {
            tick_us as u32
        } else {
            DEFAULT_TICK_US
        }
    };

    // Sum of **declared** deadlines per domain; modules that don't
    // declare are not scored.
    let mut per_domain_sum: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();

    for module in module_list {
        let name = module
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let domain = resolve_domain_id(module, config)?;
        let dtick = domain_tick_us.get(domain as usize).copied().unwrap_or(0);
        let domain_budget = effective_tick(dtick);

        let declared_deadline = module
            .get("step_deadline_us")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        // An explicit `step_deadline_burst_us` overrides the implicit
        // `step_deadline_us * BURST_MULTIPLIER` ceiling at runtime.
        // The validator must check the EFFECTIVE burst deadline —
        // otherwise a config with
        // `step_deadline_us: 1000, step_deadline_burst_us: 1_000_000`
        // would pass (because 1000 × 16 = 16ms is under the 100ms
        // cap) while authorising a 1-second runtime burst. Read the
        // override here and prefer it; fall back to the multiplier
        // math when no override is declared.
        //
        // The raw YAML value is type- and range-checked explicitly.
        // A u64 silently cast to u32 would wrap at 0x_0000_0001_0000_0000
        // → 0; non-numeric values (e.g. a typo like
        // `step_deadline_burst_us: "very_long"`) would otherwise become
        // `None` via `as_u64` and silently disable the override.
        let declared_burst_raw = module.get("step_deadline_burst_us");
        let declared_burst: Option<u32> = match declared_burst_raw {
            None => None,
            Some(v) if v.is_null() => None,
            Some(v) => match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => Some(n as u32),
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us = {n} exceeds u32::MAX \
                         ({})",
                        u32::MAX
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            },
        };

        // Suppress the unused-binding lint on the kernel default —
        // surfacing it keeps the const linked to its kernel mirror;
        // future readers will see they need to update both sides if
        // it changes.
        let _ = DEFAULT_STEP_DEADLINE_US;

        // A module with no declared `step_deadline_us` but an
        // explicit `step_deadline_burst_us` still has to honour the
        // per-domain burst ceiling — the burst budget must fit even
        // when the typical deadline isn't declared.
        let deadline = match declared_deadline {
            Some(0) | None => {
                if declared_burst.is_some() {
                    // Use the kernel's default step deadline for the
                    // "typical" budget when validating burst alone;
                    // the runtime treats `step_deadline_us == 0` as
                    // "use default", so this matches behaviour.
                    DEFAULT_STEP_DEADLINE_US
                } else {
                    continue;
                }
            }
            Some(d) => d,
        };

        // Effective runtime burst = explicit override if set, else
        // the multiplier math. The same per-module / per-domain caps
        // apply to either path.
        let burst = declared_burst
            .filter(|b| *b > 0)
            .unwrap_or_else(|| deadline.saturating_mul(BURST_DEADLINE_MULTIPLIER));

        // Rule 1 — absolute burst cap.
        if burst > HARD_BURST_CAP_US {
            return Err(Error::Config(format!(
                "module '{name}': step_deadline_us={deadline} → burst deadline {burst} us \
                 (× BURST_MULTIPLIER={BURST_DEADLINE_MULTIPLIER}) exceeds the {HARD_BURST_CAP_US} us absolute cap. \
                 A single module cannot authorise stalling the scheduler \
                 this long."
            )));
        }

        // Rule 2 — burst budget relative to the domain tick. Bursts
        // can span multiple ticks but capping at 16 × tick keeps the
        // guardrail meaningful.
        let burst_cap_for_domain = domain_budget.saturating_mul(16);
        if burst > burst_cap_for_domain {
            let domain_label = domain_names
                .get(domain as usize)
                .map(String::as_str)
                .unwrap_or("default");
            return Err(Error::Config(format!(
                "module '{name}' in domain '{domain_label}': burst deadline {burst} us \
                 (step_deadline_us={deadline} × {BURST_DEADLINE_MULTIPLIER}) exceeds 16 × domain tick_us \
                 ({burst_cap_for_domain} us). Bursts are guardrails, not licences to monopolise \
                 the domain."
            )));
        }

        *per_domain_sum.entry(domain).or_insert(0) += deadline;
    }

    // Rule 3 — per-domain warning for the declared-deadline sum.
    for (domain, sum) in per_domain_sum {
        let dtick = domain_tick_us.get(domain as usize).copied().unwrap_or(0);
        let domain_budget = effective_tick(dtick);
        let budget_ceiling = domain_budget.saturating_mul(DECLARED_DEADLINE_BUDGET_FACTOR);
        if sum > budget_ceiling {
            let domain_label = domain_names
                .get(domain as usize)
                .map(String::as_str)
                .unwrap_or("default");
            eprintln!(
                "warning: domain '{domain_label}' declared step_deadline_us sum = {sum} exceeds \
                 {DECLARED_DEADLINE_BUDGET_FACTOR}× tick_us ({budget_ceiling} us). If every module hits its declared deadline \
                 the loop slips. Lower a declared deadline, raise tick_us, or \
                 split modules across additional domains."
            );
        }
    }

    Ok(())
}

/// Build-time admission gate for Tier 1b/Tier 2 (ISR) domains.
///
/// Two rules enforced:
///
/// 1. **`isr_safe` attestation is mandatory.** Every module assigned
///    to a domain with `tier: 1b` (`exec_mode == 2`) or `tier: 2`
///    (`exec_mode == 4`) must declare `isr_safe = true` in its
///    manifest. Modules without the flag are rejected at build time
///    with a message naming the module, the domain, and the manifest
///    path so the author knows exactly where to add the attestation.
///    Bridge routing has no fall-back: if the kernel admitted a
///    non-ISR-safe module into an ISR domain it would deadlock on
///    `provider_call` from interrupt context.
///
/// 2. **Edge class compatibility.** Bridge routing is derived from
///    the consumer's tier — see `.context/rfc_isr_tier_surface.md`
///    §D6. The validator rejects wiring that pre-emptively tags an
///    edge with a class incompatible with bridge routing
///    (`dma_owned`, `cross_core`, `nic_ring`) when either endpoint
///    is in an ISR-tier domain. Untagged or `local`-tagged edges are
///    accepted and silently promoted to bridge channels at
///    instantiation time.
///
/// Modules whose manifests can't be located are skipped with a
/// warning — the wiring/manifest validation in `validate_wiring_types`
/// raises a separate, more descriptive error for missing manifests,
/// and double-erroring here would obscure that diagnostic.
fn validate_isr_tier_admission(
    config: &Value,
    module_list: &[Value],
    modules_dir: &std::path::Path,
    extra_module_dirs: &[&std::path::Path],
) -> Result<()> {
    // Per-domain exec_mode for the four supported domains.
    let mut domain_exec_mode: [u8; 4] = [0; 4];
    let mut domain_names_local: [Option<String>; 4] = [None, None, None, None];
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
        for (i, dom) in domains.iter().take(4).enumerate() {
            if let Some(name) = dom.get("name").and_then(|n| n.as_str()) {
                domain_names_local[i] = Some(name.to_string());
            }
            match parse_domain_tier_to_exec_mode(dom) {
                Some(m) => domain_exec_mode[i] = m,
                None => {
                    // Unknown tier specifier — surface it. Silent
                    // fall-through to Tier 0 cooperative would let a
                    // typo (`tier: 1c`) silently downgrade the
                    // execution discipline.
                    if dom.get("tier").is_some() || dom.get("exec_mode").is_some() {
                        let label = domain_names_local[i]
                            .clone()
                            .unwrap_or_else(|| format!("domains[{i}]"));
                        return Err(Error::Config(format!(
                            "execution.domains entry '{label}' has an unknown tier/exec_mode \
                             value. Valid: 0/cooperative, 1a/high_rate, 1b/isr_timer, \
                             3/poll, 2/isr_owned."
                        )));
                    }
                }
            }
        }
    }

    // Hard-reject Tier 1b / Tier 2 admission until the runtime
    // path is wired up. The pieces in place today:
    //   * YAML surface: parsed by `parse_domain_tier_to_exec_mode`.
    //   * Build-time admission: this validator (the `isr_safe`
    //     manifest gate + the edge-class check below).
    //   * Kernel cooperative skip: `step_one_module` returns
    //     early for ISR-tier modules so they don't double-step.
    //   * Runtime gate: `channel_open` returns EACCES from a
    //     Tier 1b/2 caller.
    //
    // What's missing:
    //   * `register_tier1b_module` / `register_tier2_module` have
    //     no call sites — prepare_graph doesn't hand modules to
    //     the ISR machinery.
    //   * `bcm2712::run_domain_loop` only special-cases exec
    //     modes 1 and 3; modes 2 and 4 fall through to the
    //     default (cooperative) loop, which then skips the
    //     module → it never runs.
    //   * Bridge channel allocation from YAML edges is not done.
    //
    // Net effect of letting a Tier 1b/2 graph through today: the
    // build succeeds, the module loads, and nothing ever runs it
    // — the worst flavour of "config silently passes." Reject at
    // build time with a precise message until the runtime piece
    // lands; see `.context/rfc_isr_tier_surface.md` for the
    // sequencing.
    for d in 0..4 {
        let m = domain_exec_mode[d];
        if m == 2 || m == 4 {
            let label = domain_names_local[d]
                .clone()
                .unwrap_or_else(|| format!("domains[{d}]"));
            let tier_name = if m == 2 {
                "1b (isr_timer)"
            } else {
                "2 (isr_owned)"
            };
            return Err(Error::Config(format!(
                "execution.domains entry '{label}': tier {tier_name} is declared but not yet \
                 runtime-supported on any target. The YAML schema, manifest gate, and \
                 cooperative scheduler skip are in place, but the platform's \
                 `register_tier1b_module` / `register_tier2_module` glue + bridge channel \
                 allocation are not wired up — a build with this tier would load the \
                 module and never run it. Use tier 0/1a/3 for now; track \
                 .context/rfc_isr_tier_surface.md for the lift."
            )));
        }
    }

    // Helper: does this exec_mode require ISR-safe modules?
    // (Reachable now only via the build-time-only branches below
    // since the hard-reject above blocks any config from ever
    // setting `domain_exec_mode[d]` to 2 or 4 — but kept for
    // when the runtime path lands and the reject is lifted.)
    let is_isr_tier = |m: u8| -> bool { m == 2 || m == 4 };

    // Helper: friendly tier label for error messages.
    let tier_label = |m: u8| -> &'static str {
        match m {
            2 => "1b (isr_timer)",
            4 => "2 (isr_owned)",
            _ => "unknown",
        }
    };

    let manifests =
        load_module_manifests_with_extra(&Value::Array(module_list.to_vec()), extra_module_dirs);

    // ── Rule 1: isr_safe attestation ────────────────────────────
    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let domain = resolve_domain_id(module, config)?;
        let exec_mode = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
        if !is_isr_tier(exec_mode) {
            continue;
        }
        let domain_label = domain_names_local
            .get(domain as usize)
            .and_then(|n| n.clone())
            .unwrap_or_else(|| format!("domain {domain}"));

        // Look up the manifest. Missing-manifest is reported elsewhere
        // (`validate_wiring_types`); skip silently here so this gate
        // gives a single, focused diagnostic.
        let manifest = match manifests.get(name) {
            Some(m) => m,
            None => continue,
        };
        if !manifest.isr_safe {
            let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') is assigned to domain '{domain_label}' \
                 (tier {tier}) but its manifest does not declare `isr_safe = true`. \
                 Add `isr_safe = true` to the module's manifest.toml, or move the module \
                 to a cooperative domain. See .context/rfc_isr_tier_surface.md §D7.",
                tier = tier_label(exec_mode)
            )));
        }
        // ISR-tier modules are scalar-only by contract.
        // NEON registers are not preserved across a Tier 1b/Tier 2
        // ISR — a module that pulls in `core::arch::aarch64` SIMD
        // intrinsics from inside its ISR entry would corrupt the
        // preempted cooperative thread's NEON file. Run the
        // source-static lint on the module's `src/` tree; if it
        // finds NEON markers, reject the placement.
        let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
        let mut src_root: Option<std::path::PathBuf> = None;
        for dir in std::iter::once(modules_dir).chain(extra_module_dirs.iter().copied()) {
            let candidate = dir.join(module_type);
            if candidate.exists() {
                src_root = Some(candidate);
                break;
            }
        }
        if let Some(root) = src_root {
            if let Err(e) = crate::manifest::check_isr_safe_no_neon(&root) {
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') admitted to domain \
                     '{domain_label}' (tier {tier}) but its source declares NEON: {e}",
                    tier = tier_label(exec_mode)
                )));
            }
        }
    }

    // ── Rule 2: incompatible edge classes on ISR-tier edges ─────
    // Build module name → exec_mode lookup.
    let mut module_exec_mode: std::collections::HashMap<String, u8> =
        std::collections::HashMap::new();
    for module in module_list {
        if let Some(name) = module.get("name").and_then(|n| n.as_str()) {
            let domain = resolve_domain_id(module, config)?;
            let m = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
            module_exec_mode.insert(name.to_string(), m);
        }
    }

    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Ok(()),
    };
    for (i, edge) in wiring.iter().enumerate() {
        let ec_str = match edge.get("edge_class").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue, // untagged = local = OK with bridge
        };
        if ec_str == "local" {
            continue;
        }
        let from_mod = edge
            .get("from")
            .and_then(|v| v.as_str())
            .and_then(|s| s.split('.').next())
            .unwrap_or("");
        let to_mod = edge
            .get("to")
            .and_then(|v| v.as_str())
            .and_then(|s| s.split('.').next())
            .unwrap_or("");
        let from_isr = module_exec_mode
            .get(from_mod)
            .copied()
            .map(is_isr_tier)
            .unwrap_or(false);
        let to_isr = module_exec_mode
            .get(to_mod)
            .copied()
            .map(is_isr_tier)
            .unwrap_or(false);
        if from_isr || to_isr {
            return Err(Error::Config(format!(
                "wiring[{i}] (from '{from_mod}' to '{to_mod}'): edge_class '{ec_str}' is \
                 incompatible with ISR-tier endpoints. Tier 1b/2 modules consume their \
                 inputs through bridge channels; the kernel routes the edge \
                 automatically. Remove the `edge_class:` field or set it to `local`.",
            )));
        }
    }

    // Bonus diagnostic: warn if an ISR-tier domain has no modules
    // assigned. A misnamed `domain:` field on a module is a common
    // typo (the hard-error `resolve_domain_id` already catches
    // it), but a correctly-named domain with no members is also a
    // bug. Check by **domain id**, not by exec_mode: two domains
    // at the same tier would otherwise mask each other (every
    // module's exec_mode would be 2, satisfying the check for
    // BOTH Tier 1b domains regardless of which they actually
    // belong to).
    //
    // Currently unreachable in practice because the hard-reject
    // above blocks any Tier 1b/2 admission — but kept honest so
    // lifting the reject doesn't reintroduce the bug.
    let mut per_domain_member_count: [usize; 4] = [0; 4];
    for module in module_list {
        let d = resolve_domain_id(module, config)?;
        if (d as usize) < per_domain_member_count.len() {
            per_domain_member_count[d as usize] += 1;
        }
    }
    for d in 0..4 {
        if !is_isr_tier(domain_exec_mode[d]) {
            continue;
        }
        if per_domain_member_count[d] > 0 {
            continue;
        }
        let label = domain_names_local[d]
            .clone()
            .unwrap_or_else(|| format!("domains[{d}]"));
        eprintln!(
            "warning: execution.domains entry '{label}' is tier {tier} but has no \
             modules assigned to it. Did you forget a `domain: {label}` on a module?",
            tier = tier_label(domain_exec_mode[d])
        );
    }

    let _ = modules_dir; // reserved for future use (per-domain budget files)
    Ok(())
}

/// Translate a domain's YAML tier specifier into the kernel's
/// `domain_exec_mode` wire byte. Accepts the preferred friendly form
/// (`tier: 1a`) and the legacy `exec_mode:` synonym for backward
/// compatibility. Returns `None` when both fields are absent so the
/// caller can default to Tier 0 (cooperative) without confusing
/// "tier omitted" with "tier explicitly set to 0".
///
/// Wire encoding (kept stable — adding a tier here MUST keep the
/// existing values intact so older `.cfg.bin` blobs continue to
/// parse correctly):
///
/// | Tier (friendly)       | exec_mode byte |
/// |-----------------------|----------------|
/// | `0` / `cooperative`   | 0              |
/// | `1a` / `high_rate`    | 1              |
/// | `1b` / `isr_timer`    | 2 (Tier 1b)    |
/// | `3` / `poll`          | 3              |
/// | `2` / `isr_owned`     | 4 (Tier 2)     |
///
/// The Tier 1b → 2 / Tier 2 → 4 mapping is asymmetric because
/// `domain_exec_mode` values {0, 1, 3} were allocated before Tier 1b
/// and Tier 2 were introduced. Reshuffling would break already-built
/// `.cfg.bin` blobs.
///
/// **Returned `Err` only on explicit unknown values** — silently
/// dropping a typo'd tier (e.g. `tier: 1c`) would route the domain
/// to Tier 0 cooperative without warning. See
/// `.context/rfc_isr_tier_surface.md` §D5 for the design rationale.
pub(crate) fn parse_domain_tier_to_exec_mode(domain: &Value) -> Option<u8> {
    // `tier:` is the preferred friendly form per the RFC.
    if let Some(raw) = domain.get("tier") {
        if let Some(s) = raw.as_str() {
            return match s {
                "0" | "cooperative" => Some(0),
                "1a" | "high_rate" | "tier1a" => Some(1),
                "1b" | "isr_timer" | "tier1b" => Some(2),
                "3" | "poll" | "tier3" => Some(3),
                "2" | "isr_owned" | "tier2" => Some(4),
                _ => None,
            };
        }
        if let Some(n) = raw.as_u64() {
            // Bare numeric `tier: 0` only resolves to cooperative;
            // numeric form is intentionally narrow because it's
            // ambiguous for Tier 1a/1b/Tier 2.
            return match n {
                0 => Some(0),
                _ => None,
            };
        }
    }
    // Legacy `exec_mode:` synonym — kept so existing configs (e.g.
    // `examples/cm5/*` exercising Tier 1a) build unchanged.
    if let Some(m) = domain.get("exec_mode").and_then(|m| m.as_str()) {
        return match m {
            "cooperative" => Some(0),
            "high_rate" | "tier1a" => Some(1),
            "isr_timer" | "tier1b" => Some(2),
            "poll" | "tier3" => Some(3),
            "isr_owned" | "tier2" => Some(4),
            _ => None,
        };
    }
    None
}

/// Resolve a module's domain assignment to a numeric domain ID.
///
/// Looks up the module's `domain` field (string) in the
/// `execution.domains` list. Returns 0 (default domain) when no domain
/// is specified. **Hard error** when a domain is named but not present
/// in `execution.domains` — silently falling back to domain 0 lets a
/// typo'd domain name (or a stale config referencing a removed domain)
/// silently route modules to the default partition, hiding capacity
/// and budget mismatches the rest of the validator counts on.
fn resolve_domain_id(module: &Value, config: &Value) -> Result<u8> {
    let domain_name = match module.get("domain").and_then(|d| d.as_str()) {
        Some(name) => name,
        None => return Ok(0),
    };

    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            for (i, domain) in domains.iter().enumerate() {
                if let Some(name) = domain.get("name").and_then(|n| n.as_str()) {
                    if name == domain_name {
                        // Defense in depth: even though
                        // `generate_config_impl` hard-rejects
                        // `execution.domains.len() > MAX_DOMAINS`
                        // at the top of validation, this lookup is
                        // also reached directly by unit tests +
                        // callers that bypass that gate. Reject
                        // here too so a module that *resolves* to
                        // an out-of-range domain id can never slip
                        // into the rest of the pipeline.
                        if i >= MAX_DOMAINS {
                            return Err(Error::Config(format!(
                                "module references domain '{domain_name}' at index {i}, but \
                                 the kernel supports at most {MAX_DOMAINS} domains. The 5th+ \
                                 entry in `execution.domains` is invalid — drop it or merge \
                                 the modules into an existing domain."
                            )));
                        }
                        return Ok(i as u8);
                    }
                }
            }
            // Build a name list for the error message so the user can
            // spot the typo without grepping the YAML.
            let known: Vec<String> = domains
                .iter()
                .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect();
            return Err(Error::Config(format!(
                "module references unknown domain '{}'; execution.domains declares [{}]",
                domain_name,
                known.join(", ")
            )));
        }
    }

    Err(Error::Config(format!(
        "module references domain '{domain_name}' but execution.domains is missing or empty"
    )))
}

/// Load a built-in module's manifest from the source tree and
/// synthesize a `ParamSchema` from its `[[params]]` declarations.
/// Returns `None` when the manifest doesn't exist, isn't marked
/// built-in, or declares no params. Repeated lookups share a
/// per-process cache via `Manifest::from_source_tree`.
fn load_builtin_param_schema(
    module_type: &str,
) -> Option<(crate::manifest::Manifest, schema::ParamSchema)> {
    let m = crate::manifest::Manifest::from_source_tree(module_type).ok()??;
    if !m.builtin {
        return None;
    }
    let s = schema::ParamSchema::from_manifest(&m)?;
    Some((m, s))
}

/// Reject any YAML key on a built-in module entry that the schema doesn't
/// know about. PIC modules currently silently ignore unknown keys; here we
/// hard-fail because the manifest is the contract and a typo will otherwise
/// silently use the default. Skips structural metadata (name, type, …).
/// Top-level YAML keys that are structural metadata, not module params.
/// Mirrors `schema.rs::SKIP_KEYS` plus the protection/policy/trust tier
/// fields that `build_module_entry` writes as reserved TLV tags
/// (0xF0..0xF5) and a few other cross-cutting fields that the config
/// generator injects.
const NON_PARAM_KEYS: &[&str] = &[
    "name",
    "type",
    "wiring",
    "preset",
    "presets",
    "voices",
    "routes",
    "step_deadline_us",
    "fault_policy",
    "max_restarts",
    "restart_backoff_ms",
    "trust_tier",
    "protection",
    "cert_file",
    "key_file",
    "trust_cert_file",
    "verify_hostname",
    "domain",
    "sample_rate", // injected by graph_sample_rate
    // Protection-control keys emitted as TLV tags by
    // `build_module_entry`. These are top-level module entries, not
    // schema params, so the allow-list lets `validate_yaml_params`
    // pass them through to the dedicated emitter.
    "step_deadline_burst_us",
    "quarantine_partner",     // name form, resolved at wiring pass
    "quarantine_partner_idx", // numeric form passed straight through
    "heap",                   // nested object: { zero_on_free,
                              //   alloc_failure_policy, canary_enabled }
];

/// Reject any YAML key on a module entry that the schema doesn't know
/// about. Hard-fails for both `.fmod` modules (schema embedded in the
/// .fmod) and built-ins (schema in `manifest.toml [[params]]`).
///
/// The candidate-name check mirrors `build_params_from_schema`'s
/// flattening: nested objects expand to dotted/underscored variants,
/// and outer keys ending in a `GROUPING_SUFFIXES` entry can also resolve
/// to suffix-stripped names. Anything the packer would actually consume
/// passes; only keys that have no path to any schema param fail here.
/// Structural validator for the optional `heap:` subtree. Runs on every
/// module entry regardless of whether the module has a schema source —
/// schema-gated validation would otherwise let a `heap.alloc_failure_policy:
/// "fualt"` typo on a no-schema driver pass silently and disable fault
/// recovery without diagnostic. The emitter at `build_module_entry`
/// reads each subkey through `.as_bool()` / `.as_str()` and drops
/// unrecognised entries with no error; this validator catches the typo
/// at the YAML boundary instead.
fn validate_heap_subtree(module: &Value, module_name: &str) -> Result<()> {
    let Some(value) = module.get("heap") else {
        return Ok(());
    };
    let heap_obj = value.as_object().ok_or_else(|| {
        Error::Config(format!(
            "module '{module_name}': `heap` must be an object \
             (with `zero_on_free` / `alloc_failure_policy` / `canary_enabled`)"
        ))
    })?;
    const HEAP_KEYS: &[&str] = &["zero_on_free", "alloc_failure_policy", "canary_enabled"];
    for (subkey, subval) in heap_obj {
        if !HEAP_KEYS.contains(&subkey.as_str()) {
            return Err(Error::Config(format!(
                "module '{module_name}': unknown heap key 'heap.{subkey}' (valid: {})",
                HEAP_KEYS.join(", "),
            )));
        }
        // `alloc_failure_policy` is the only string-valued key; the
        // others are bool. A type mismatch on either would otherwise
        // leave the tag at its default — the canonical typo case is
        // `true`/`false` misspelled as `"yes"`/`"flase"`.
        match subkey.as_str() {
            "alloc_failure_policy" => {
                let s = subval.as_str().ok_or_else(|| {
                    Error::Config(format!(
                        "module '{module_name}': heap.alloc_failure_policy must be a \
                         string (\"return_null\" or \"fault\")"
                    ))
                })?;
                if s != "return_null" && s != "fault" {
                    return Err(Error::Config(format!(
                        "module '{module_name}': heap.alloc_failure_policy = '{s}' is \
                         invalid (use \"return_null\" or \"fault\")"
                    )));
                }
            }
            _ => {
                if subval.as_bool().is_none() {
                    return Err(Error::Config(format!(
                        "module '{module_name}': heap.{subkey} must be a boolean (true/false)"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_yaml_params(
    module: &Value,
    schema: &schema::ParamSchema,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    for (key, value) in obj {
        if NON_PARAM_KEYS.contains(&key.as_str()) {
            if key == "heap" {
                validate_heap_subtree(module, module_name)?;
                let _ = value;
            }
            continue;
        }
        if schema::SKIP_KEYS.contains(&key.as_str()) {
            continue;
        }

        if let Some(inner_obj) = value.as_object() {
            // `params: { ... }` is a transparent wrapper (see
            // `schema::build_params_from_schema`): inner keys map to
            // schema params with no prefix.
            let transparent = key == "params";
            for (inner_key, _) in inner_obj {
                let candidates: Vec<String> = if transparent {
                    let mut c = vec![inner_key.clone()];
                    if inner_key.contains('.') {
                        c.push(inner_key.replace('.', "_"));
                    }
                    c
                } else {
                    nested_key_candidates(key, inner_key)
                };
                if !candidates.iter().any(|c| schema.find(c).is_some()) {
                    let display = if transparent {
                        format!("params.{inner_key}")
                    } else {
                        format!("{key}.{inner_key}")
                    };
                    let suggestion = candidates
                        .iter()
                        .filter_map(|c| closest_param_name(c, schema))
                        .next();
                    return Err(Error::Config(format!(
                        "module '{}': unknown param '{}'{}",
                        module_name,
                        display,
                        format_hint(suggestion, schema),
                    )));
                }
            }
            continue;
        }

        // Scalar: same-name lookup, with dotted-to-underscored fallback.
        let mut candidates = vec![key.clone()];
        if key.contains('.') {
            candidates.push(key.replace('.', "_"));
        }
        if !candidates.iter().any(|c| schema.find(c).is_some()) {
            let suggestion = candidates
                .iter()
                .filter_map(|c| closest_param_name(c, schema))
                .next();
            return Err(Error::Config(format!(
                "module '{}': unknown param '{}'{}",
                module_name,
                key,
                format_hint(suggestion, schema),
            )));
        }
    }
    Ok(())
}

/// Produce the candidate schema-key names a nested YAML pair would
/// resolve to. Mirrors the flattening logic in
/// `schema::build_params_from_schema`: dotted, fully underscored, and
/// (when the outer key ends with a grouping suffix) suffix-stripped.
fn nested_key_candidates(outer: &str, inner: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    let dotted = format!("{outer}.{inner}");
    out.push(dotted.replace('.', "_"));
    out.push(dotted);
    for suffix in schema::GROUPING_SUFFIXES {
        if let Some(prefix) = outer.strip_suffix(suffix) {
            out.push(format!("{prefix}_{inner}"));
        }
    }
    out
}

fn format_hint(suggestion: Option<&str>, schema: &schema::ParamSchema) -> String {
    if let Some(s) = suggestion {
        format!(" — did you mean '{s}'?")
    } else {
        let valid: Vec<&str> = schema.params.iter().map(|p| p.name.as_str()).collect();
        format!(" — valid params: {}", valid.join(", "))
    }
}

/// Fail the build if any param flagged `required = true` is missing or
/// empty in the YAML entry. Counts both the top-level form
/// (`path: ...`) and the transparent `params: { path: ... }` wrapper.
/// "Empty" means the YAML supplied a string that's `""` — for required
/// string params there is no useful fallback, and silently passing the
/// empty value through to the runtime would defeat the point of the
/// flag (e.g. `host_asset_source.path = ""` would land at
/// `File::open("")`). Defaults aren't a fallback for required params
/// — by definition there isn't one.
fn validate_required_params(
    module: &Value,
    manifest: &crate::manifest::Manifest,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    let inner = obj.get("params").and_then(|v| v.as_object());
    for p in &manifest.params {
        if !p.required {
            continue;
        }
        let value = obj
            .get(&p.name)
            .or_else(|| inner.and_then(|i| i.get(&p.name)));
        let Some(v) = value else {
            return Err(Error::Config(format!(
                "module '{}': required param '{}' is missing from YAML",
                module_name, p.name,
            )));
        };
        // Strings (including the enum default representation) must
        // be non-empty — an empty string here is the same failure
        // shape as omission, just spelled differently.
        if let Some(s) = v.as_str() {
            if s.is_empty() {
                return Err(Error::Config(format!(
                    "module '{}': required param '{}' is empty",
                    module_name, p.name,
                )));
            }
        }
    }
    Ok(())
}

/// Range-check numeric params against the manifest's `range = [min, max]`.
/// Honors both top-level placement and the transparent `params: {...}`
/// wrapper so the check stays in lock-step with the packer's view.
fn validate_param_ranges(
    module: &Value,
    manifest: &crate::manifest::Manifest,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    let inner = obj.get("params").and_then(|v| v.as_object());
    for p in &manifest.params {
        let Some((min, max)) = p.range else {
            continue;
        };
        let Some(v) = obj
            .get(&p.name)
            .or_else(|| inner.and_then(|i| i.get(&p.name)))
            .and_then(|v| v.as_u64())
        else {
            continue;
        };
        if (v as u32) < min || (v as u32) > max {
            return Err(Error::Config(format!(
                "module '{}': param '{}'={} is outside [{}, {}]",
                module_name, p.name, v, min, max,
            )));
        }
    }
    Ok(())
}

/// Clone the YAML module entry and fill in any manifest-declared
/// default that the YAML didn't supply. Honours the transparent
/// `params: { ... }` wrapper — values inside it are picked up first.
/// Result: every declared param has a value (YAML override or default),
/// so the packer emits a TLV entry for each one and built-ins don't
/// need to re-encode defaults in code.
fn inject_manifest_defaults(module: &Value, manifest: &crate::manifest::Manifest) -> Value {
    let mut clone = module.clone();
    let Some(obj) = clone.as_object_mut() else {
        return clone;
    };
    let inner_present: std::collections::HashSet<String> = obj
        .get("params")
        .and_then(|p| p.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for p in &manifest.params {
        // Already supplied — top-level form or in the params: wrapper.
        if obj.contains_key(&p.name) || inner_present.contains(&p.name) {
            continue;
        }
        if p.required {
            // Required params have no default to inject;
            // `validate_required_params` raises the user-facing error.
            continue;
        }
        let val = match p.ptype {
            crate::manifest::ManifestParamType::U8
            | crate::manifest::ManifestParamType::U16
            | crate::manifest::ManifestParamType::U32 => json!(p.default_num),
            crate::manifest::ManifestParamType::Str => json!(p.default_str),
            crate::manifest::ManifestParamType::Enum => {
                // Enums pack from string→u8 via the schema, so put the
                // default name on the YAML side and let the packer
                // resolve it.
                json!(p.default_str)
            }
        };
        obj.insert(p.name.clone(), val);
    }
    clone
}

/// Levenshtein-light: pick the schema param name with the smallest edit
/// distance to `key`, returning it only if the distance is plausibly a typo
/// (≤ 2 edits, or up to half the key length for short names).
/// "Did you mean…?" lookup for param names. Threshold is dynamic —
/// `(key.len() / 2).clamp(2, 4)` — because param names vary widely
/// in length and a fixed cap would be too strict for long names
/// (`encryption_passphrase` deserves more typo tolerance than `iv`).
///
/// Delegates the actual Levenshtein walk to the shared
/// `crate::text_distance::closest_match` helper used across every
/// other "did you mean" surface. Single source of truth — a future
/// improvement to the Levenshtein implementation (or a switch to
/// Damerau-Levenshtein etc.) takes effect uniformly.
fn closest_param_name<'a>(key: &str, schema: &'a schema::ParamSchema) -> Option<&'a str> {
    let threshold = (key.len() / 2).clamp(2, 4);
    let candidates: Vec<String> = schema.params.iter().map(|p| p.name.clone()).collect();
    crate::text_distance::closest_match(key, &candidates, threshold).and_then(|name| {
        // closest_match returns an owned String; map back to the
        // borrowed `&'a str` the caller expects by looking up
        // the schema entry that matched.
        schema
            .params
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.name.as_str())
    })
}

/// Expand compound YAML fields that don't map 1:1 to schema params,
/// returning a clone with the flat fields in place. Pure YAML-level
/// rewrite — schema lookup runs unchanged afterwards.
///
/// Currently handles:
///   - mqtt `broker: "host:port"` → `broker_ip: u32` + `broker_port: u16`
///   - mqtt derived `subscribe_topic` from top-level `device_uuid` if
///     the YAML didn't set one explicitly
///
/// Modules whose params can already be expressed as schema entries
/// (or where `params: { ... }` covers the grouping) don't need an
/// entry here.
fn expand_compound_yaml_fields(type_name: &str, module: &Value, config: &Value) -> Value {
    let mut clone = module.clone();
    if type_name == "mqtt" {
        if let Some(obj) = clone.as_object_mut() {
            // Pull `broker:` out (singular form) and expand into
            // `broker_ip` / `broker_port` if neither is already set.
            if let Some(broker) = obj.get("broker").and_then(|v| v.as_str()) {
                let (ip, port) = parse_broker_addr(broker);
                if !obj.contains_key("broker_ip") {
                    obj.insert("broker_ip".into(), json!(ip));
                }
                if !obj.contains_key("broker_port") {
                    obj.insert("broker_port".into(), json!(port));
                }
                obj.remove("broker");
            }
            // Derive subscribe_topic from top-level device_uuid if the
            // YAML didn't set one explicitly. mesh-aware mqtt brokers
            // listen on `fluxor/{device_hex}/objects/+/commands`.
            if !obj.contains_key("subscribe_topic") {
                if let Some(uuid_str) = config.get("device_uuid").and_then(|v| v.as_str()) {
                    let uuid = parse_uuid_bytes(uuid_str);
                    if uuid != [0u8; 16] {
                        let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
                        obj.insert(
                            "subscribe_topic".into(),
                            json!(format!("fluxor/{}/objects/+/commands", hex)),
                        );
                    }
                }
            }
        }
    }
    clone
}

fn build_module_entry(
    name: &str,
    module: &Value,
    id: u8,
    data_section: Option<&Value>,
    config: &Value,
    modules_dir: &Path,
) -> Result<Vec<u8>> {
    // Start with max possible size, will truncate to actual used size
    let mut entry = vec![0u8; MODULE_ENTRY_HEADER_SIZE + MAX_MODULE_PARAMS_SIZE];

    // Leave bytes 0-1 for entry_length (filled at end)

    // Module type: explicit "type" field or falls back to "name"
    let type_name = module["type"].as_str().unwrap_or(name);

    // Name hash (bytes 2-5) — hash the type name so the kernel can find the .fmod.
    // This allows multiple instances: name: seq_kick, type: sequencer
    let name_hash = fnv1a_hash(type_name.as_bytes());
    // Header layout (10 bytes total):
    //   bytes 0-3: entry_length (u32, patched in below at line ~1953)
    //   bytes 4-7: name_hash (u32)
    //   byte 8:    module id
    //   byte 9:    domain id
    entry[4..8].copy_from_slice(&name_hash.to_le_bytes());
    entry[8] = id;
    let domain_id = resolve_domain_id(module, config)?;
    entry[9] = domain_id;

    // Track actual params length used
    let params_len: usize;

    // Some modules accept compound YAML fields that don't map 1:1 to
    // schema params (e.g. `broker: "host:port"` in mqtt). Expand them
    // into the flat fields the schema knows about before packing.
    let normalized_module = expand_compound_yaml_fields(type_name, module, config);
    let module = &normalized_module;

    // The `heap:` subtree is structurally orthogonal to the schema
    // (it's emitted as protection TLV tags, not schema params), so
    // its validator runs unconditionally — modules with no schema
    // source must still surface a `heap.alloc_failure_policy` typo
    // at build time rather than letting it silently drop at runtime.
    validate_heap_subtree(module, type_name)?;

    // PIC modules embed their schema in the `.fmod`; built-ins declare
    // it in `modules/builtin/<platform>/<name>/manifest.toml`. Both
    // paths produce a `ParamSchema` and feed the same TLV packer, so
    // the wire format is identical at the kernel boundary.
    if let Some(param_schema) = schema::load_schema_for_module(type_name, modules_dir) {
        validate_yaml_params(module, &param_schema, type_name)?;
        params_len = schema::build_params_from_schema(
            module,
            &param_schema,
            &mut entry,
            P,
            data_section,
            type_name,
        )
        .map_err(Error::Config)?;
    } else if let Some((manifest, param_schema)) = load_builtin_param_schema(type_name) {
        validate_yaml_params(module, &param_schema, type_name)?;
        validate_param_ranges(module, &manifest, type_name)?;
        validate_required_params(module, &manifest, type_name)?;
        // Inject manifest defaults into a YAML clone so every declared
        // param produces a TLV entry. The built-in's step function
        // reads values straight off the wire, with no defaults
        // duplicated in Rust.
        let module_with_defaults = inject_manifest_defaults(module, &manifest);
        params_len = schema::build_params_from_schema(
            &module_with_defaults,
            &param_schema,
            &mut entry,
            P,
            data_section,
            type_name,
        )
        .map_err(Error::Config)?;
    } else {
        // Module type with no schema source — typically a misnamed
        // YAML entry. Emit an empty params section; downstream
        // resource and capability checks raise the user-facing error.
        params_len = 0;
    }

    // Append protection / fault-policy params as reserved TLV tags
    // (0xF0..0xFA). Parsed by the kernel scheduler during
    // instantiation via `parse_protection_config`.
    //
    // The schema packer writes a `0xFF 0x00` TLV end-marker at the
    // tail of `params_len`, and the kernel parser stops on
    // `tag == 0xFF`. Protection tags therefore have to land BEFORE
    // that marker — strip it by rewinding `params_len` by 2 when the
    // trailing bytes are `0xFF 0x00`, append the protection tags,
    // then re-write the end marker at the new tail. Modules with no
    // schema source (`params_len == 0`) don't have an end marker to
    // strip; one is added here only if at least one protection tag
    // fires, so a module declaring no policy stays at `params_len == 0`.
    let mut extra_len = 0usize;
    let had_end_marker = params_len >= 2
        && entry
            .get(MODULE_ENTRY_HEADER_SIZE + params_len - 2)
            .copied()
            == Some(0xFF)
        && entry
            .get(MODULE_ENTRY_HEADER_SIZE + params_len - 1)
            .copied()
            == Some(0x00);
    let base = if had_end_marker {
        MODULE_ENTRY_HEADER_SIZE + params_len - 2
    } else {
        MODULE_ENTRY_HEADER_SIZE + params_len
    };

    // Every numeric protection field below is range-checked. Typos
    // and overflows produce explicit `Error::Config` at build time
    // rather than silent `as u32` / `as u16` truncation; the
    // non-numeric case (string typos like `"forever"`) also rejects
    // explicitly so a malformed YAML value can't disable the field.

    // Tag 0xF0: step_deadline_us (u32, 4 bytes)
    if let Some(v) = module.get("step_deadline_us") {
        if !v.is_null() {
            let deadline = match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => n as u32,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_us = {n} exceeds u32::MAX"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 6 < entry.len() {
                entry[base + extra_len] = 0xF0;
                entry[base + extra_len + 1] = 4;
                let bytes = deadline.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&bytes);
                extra_len += 6;
            }
        }
    }

    // Tag 0xF1: fault_policy (u8: 0=skip, 1=restart, 2=restart_graph).
    // Unknown policy strings error explicitly; the accepted set
    // mirrors the kernel-side `FaultPolicy` enum.
    if let Some(v) = module.get("fault_policy") {
        if !v.is_null() {
            let policy_str = v.as_str().ok_or_else(|| {
                Error::Config(format!(
                    "module '{name}': fault_policy must be a string \
                     (\"skip\" | \"restart\" | \"restart_graph\"); got {v}"
                ))
            })?;
            let policy_val: u8 = match policy_str {
                "skip" => 0,
                "restart" => 1,
                "restart_graph" => 2,
                _ => {
                    return Err(Error::Config(format!(
                        "module '{name}': fault_policy = '{policy_str}' is invalid \
                         (use \"skip\", \"restart\", or \"restart_graph\")"
                    )));
                }
            };
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF1;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = policy_val;
                extra_len += 3;
            }
        }
    }

    // Tag 0xF2: max_restarts (u16, 2 bytes)
    if let Some(v) = module.get("max_restarts") {
        if !v.is_null() {
            let max_r = match v.as_u64() {
                Some(n) if n <= u16::MAX as u64 => n as u16,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': max_restarts = {n} exceeds u16::MAX (65535)"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': max_restarts must be a non-negative integer \
                         (got {v})"
                    )));
                }
            };
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xF2;
                entry[base + extra_len + 1] = 2;
                let bytes = max_r.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
                extra_len += 4;
            }
        }
    }

    // Tag 0xF3: restart_backoff_ms (u16, 2 bytes)
    if let Some(v) = module.get("restart_backoff_ms") {
        if !v.is_null() {
            let backoff = match v.as_u64() {
                Some(n) if n <= u16::MAX as u64 => n as u16,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': restart_backoff_ms = {n} exceeds u16::MAX (65535)"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': restart_backoff_ms must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xF3;
                entry[base + extra_len + 1] = 2;
                let bytes = backoff.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
                extra_len += 4;
            }
        }
    }

    // Tag 0xF4: trust_tier (u8: 0=platform, 1=verified, 2=community, 3=unsigned).
    // Per-module field wins; `default_trust_tier` at the top level or under
    // `graph:` applies to any module that omits it. Defaults to `platform`
    // (most permissive) for first-party builds.
    let tier_str = module
        .get("trust_tier")
        .and_then(|v| v.as_str())
        .or_else(|| {
            config
                .get("default_trust_tier")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    config
                        .get("graph")
                        .and_then(|g| g.get("default_trust_tier"))
                        .and_then(|v| v.as_str())
                })
        })
        .unwrap_or("platform");
    let tier_val: u8 = match tier_str {
        "platform" => 0,
        "verified" => 1,
        "community" => 2,
        "unsigned" => 3,
        _ => 0,
    };
    if base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xF4;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = tier_val;
        extra_len += 3;
    }

    // Tag 0xF5: protection level (u8: 0=none, 1=guarded, 2=isolated).
    // An explicit `protection:` on the module (or the graph) wins; otherwise
    // derive from the trust tier:
    //   platform  -> none
    //   verified  -> guarded
    //   community -> isolated
    //   unsigned  -> isolated (signature enforcement refuses the load elsewhere)
    let explicit_prot = module
        .get("protection")
        .and_then(|v| v.as_str())
        .or_else(|| {
            config
                .get("protection")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    config
                        .get("graph")
                        .and_then(|g| g.get("protection"))
                        .and_then(|v| v.as_str())
                })
        });
    let prot_val: u8 = match explicit_prot {
        Some("none") => 0,
        Some("guarded") => 1,
        Some("isolated") => 2,
        _ => match tier_val {
            0 => 0, // platform -> none
            1 => 1, // verified -> guarded
            _ => 2, // community/unsigned -> isolated
        },
    };
    if base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xF5;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = prot_val;
        extra_len += 3;
    }

    // Extended-protection tags — emit when the module YAML declares
    // them. The kernel-side parser at `parse_protection_config`
    // reads each tag and routes to the appropriate setter. All tags
    // are optional; omit when the field isn't declared so module
    // graphs that opt out see no change.

    // Tag 0xF6: step_deadline_burst_us (u32 LE, 4 bytes). Range-
    // check the YAML value as u32 explicitly and reject non-numeric
    // values. `validate_scheduler_budgets` also rejects out-of-range
    // values, but `build_module_entry` runs in paths that bypass the
    // validator (e.g. built-in packing tests); enforcing here too
    // keeps the wire tag from ever being silently wrapped.
    if let Some(v) = module.get("step_deadline_burst_us") {
        if !v.is_null() {
            let burst_us = match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => n as u32,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us = {n} exceeds u32::MAX"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            let burst = burst_us.to_le_bytes();
            if base + extra_len + 6 < entry.len() {
                entry[base + extra_len] = 0xF6;
                entry[base + extra_len + 1] = 4;
                entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&burst);
                extra_len += 6;
            }
        }
    }

    // Tag 0xF7: quarantine_partner (u8 module index, 0xFF = none).
    // Accepts either the partner's index directly (`quarantine_partner:
    // 3`) or its name (`quarantine_partner: "tls_handshake"`). Name
    // resolution happens in the wiring pass once the module-name →
    // index map is built; what reaches `build_module_entry` is always
    // the numeric form.
    if let Some(v) = module.get("quarantine_partner_idx") {
        if !v.is_null() {
            // Reject non-numeric values explicitly: a string like
            // `quarantine_partner_idx: "3"` would otherwise return
            // `None` from `as_u64()` and silently omit the tag.
            let partner = match v.as_u64() {
                Some(n) => n,
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': quarantine_partner_idx must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if partner >= MAX_MODULES as u64 {
                return Err(Error::Config(format!(
                    "module '{name}': quarantine_partner_idx {partner} out of range \
                     (max {})",
                    MAX_MODULES - 1
                )));
            }
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF7;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = partner as u8;
                extra_len += 3;
            }
        }
    }

    // Tag 0xF8: heap.zero_on_free (u8 bool)
    if let Some(heap) = module.get("heap") {
        if let Some(v) = heap.get("zero_on_free").and_then(|v| v.as_bool()) {
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF8;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = if v { 1 } else { 0 };
                extra_len += 3;
            }
        }

        // Tag 0xF9: heap.alloc_failure_policy
        //   "return_null" (default) → tag NOT emitted
        //   "fault" → tag emitted with value 1
        // The value space is validated by `validate_heap_subtree`; only
        // `"fault"` produces a tag here.
        if let Some(s) = heap.get("alloc_failure_policy").and_then(|v| v.as_str()) {
            if s == "fault" && base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF9;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = 1;
                extra_len += 3;
            }
        }

        // Tag 0xFA: heap.canary_enabled
        if let Some(v) = heap.get("canary_enabled").and_then(|v| v.as_bool()) {
            if v && base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xFA;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = 1;
                extra_len += 3;
            }
        }
    }

    // Emit the schema-section end marker `0xFF 0x00` here, after the
    // protection tags (0xF0-0xFA) but BEFORE any extended cert/key
    // blobs. The schema SDK parser walks until it hits 0xFF and
    // ignores everything after; cert/key extended tags reuse low
    // tag numbers (10/11/12/13) that collide with real schema tags
    // — notably QUIC's `enable_concurrent_bidi` at tag 10 — so they
    // must live AFTER this marker. The TLS-module extended-TLV
    // scanner independently walks the full params region looking
    // for the `[tag, 0x00, hi, lo, payload]` extended pattern and
    // picks them up there. Without this split, a cert-bearing QUIC
    // config would silently reset `enable_concurrent_bidi` to 0.
    if base + extra_len + 1 < entry.len() {
        entry[base + extra_len] = 0xFF;
        entry[base + extra_len + 1] = 0x00;
        extra_len += 2;
        // Also update the schema TLV header's payload_len (u16 LE at
        // bytes 2-3 of the schema TLV) so it reflects the new end-marker
        // position. Without this update, the TLS extended scanner
        // (which uses the header's payload_len to find `basic_end`)
        // would start mid-protection-tag and either false-match or skip
        // legitimate cert/key tags.
        //
        // payload_len is measured from byte 4 (past the TLV header) to
        // the byte AFTER the end marker. With the schema's original
        // end marker overwritten, the new end-marker position relative
        // to byte 4 is `base + extra_len - (MODULE_ENTRY_HEADER_SIZE + 4)`.
        let header_pos = MODULE_ENTRY_HEADER_SIZE;
        if entry.len() >= header_pos + 4 && entry[header_pos] == 0xFE {
            let new_payload_len = (base + extra_len) - (header_pos + 4);
            if new_payload_len <= u16::MAX as usize {
                let bytes = (new_payload_len as u16).to_le_bytes();
                entry[header_pos + 2] = bytes[0];
                entry[header_pos + 3] = bytes[1];
            }
        }
    }

    // Tag 10: cert_file (DER blob, extended TLV for > 255 bytes)
    if let Some(cert_path) = module.get("cert_file").and_then(|v| v.as_str()) {
        match std::fs::read(cert_path) {
            Ok(cert_data) => {
                let n = cert_data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 10; // tag
                    entry[base + extra_len + 1] = 0x00; // extended length marker
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n]
                        .copy_from_slice(&cert_data);
                    extra_len += 4 + n;
                    eprintln!("  cert_file: {cert_path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: cert_file: could not read '{cert_path}': {e}"),
        }
    }

    // Tag 11: key_file (DER blob, extended TLV for > 255 bytes)
    if let Some(key_path) = module.get("key_file").and_then(|v| v.as_str()) {
        match std::fs::read(key_path) {
            Ok(key_data) => {
                let n = key_data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 11; // tag
                    entry[base + extra_len + 1] = 0x00; // extended length marker
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n]
                        .copy_from_slice(&key_data);
                    extra_len += 4 + n;
                    eprintln!("  key_file: {key_path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: key_file: could not read '{key_path}': {e}"),
        }
    }

    // Tag 12: trust_cert_file (DER blob, extended TLV).
    if let Some(path) = module.get("trust_cert_file").and_then(|v| v.as_str()) {
        match std::fs::read(path) {
            Ok(data) => {
                let n = data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 12;
                    entry[base + extra_len + 1] = 0x00;
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(&data);
                    extra_len += 4 + n;
                    eprintln!("  trust_cert_file: {path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: trust_cert_file: could not read '{path}': {e}"),
        }
    }

    // Tag 13: verify_hostname (ASCII string, extended TLV).
    if let Some(name) = module.get("verify_hostname").and_then(|v| v.as_str()) {
        let bytes = name.as_bytes();
        let n = bytes.len();
        if n > 0 && n < 256 && base + extra_len + 4 + n < entry.len() {
            entry[base + extra_len] = 13;
            entry[base + extra_len + 1] = 0x00;
            entry[base + extra_len + 2] = (n >> 8) as u8;
            entry[base + extra_len + 3] = n as u8;
            entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(bytes);
            extra_len += 4 + n;
            eprintln!("  verify_hostname: {name}");
        }
    }

    // Calculate total entry length and write to header. The
    // extended cert/key bytes were written past the end marker and
    // are accounted for in `extra_len`. The 2-byte original schema
    // end marker, if any, was overwritten and re-emitted by the
    // inserted-end-marker block above:
    //   * had_end_marker == true:  base = orig_params_len - 2; the
    //     original `0xFF 0x00` was overwritten and re-emitted
    //     (counted in `extra_len`). Total = MODULE_ENTRY_HEADER_SIZE
    //     + (params_len - 2) + extra_len.
    //   * had_end_marker == false: base = orig_params_len; the end
    //     marker was appended (counted in extra_len). Total =
    //     MODULE_ENTRY_HEADER_SIZE + params_len + extra_len.
    let payload_total = if had_end_marker {
        params_len.saturating_sub(2) + extra_len
    } else {
        params_len + extra_len
    };
    let entry_len = MODULE_ENTRY_HEADER_SIZE + payload_total;
    entry[0..4].copy_from_slice(&(entry_len as u32).to_le_bytes());

    // Truncate to actual size
    entry.truncate(entry_len);

    Ok(entry)
}

fn parse_modules_map(
    modules: &Value,
    data_section: Option<&Value>,
    config: &Value,
    modules_dir: &Path,
) -> Result<(Vec<Vec<u8>>, Vec<String>)> {
    let mut entries = Vec::new();
    let mut names = Vec::new();

    let list = modules.as_array().ok_or_else(|| {
        Error::Config("modules must be a list of module configs (each with a 'name' field)".into())
    })?;

    // Pre-pass: collect module names so a `quarantine_partner:
    // "name"` (string form) resolves to an index regardless of
    // declaration order. Forward and backward partner references both
    // resolve here. Modules using `quarantine_partner_idx: N`
    // (numeric form) bypass this entirely.
    let mut name_to_idx: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    for (idx, m) in list.iter().enumerate() {
        if idx >= MAX_MODULES {
            break;
        }
        if let Some(n) = m.get("name").and_then(|v| v.as_str()) {
            name_to_idx.entry(n.to_string()).or_insert(idx as u8);
        }
    }

    for (idx, module) in list.iter().enumerate() {
        if idx >= MAX_MODULES {
            return Err(Error::Config(format!(
                "Too many modules: {} > {}",
                idx + 1,
                MAX_MODULES
            )));
        }
        let name = module["name"]
            .as_str()
            .ok_or_else(|| Error::Config(format!("Module at index {idx} missing 'name' field")))?;
        // Duplicate-name detector. Names are used as keys in
        // manifests / wiring lookup / scheduler module table, so
        // two modules sharing a name silently makes every name
        // reference ambiguous (the later one wins in some places,
        // the earlier in others — neither is right). Catch at
        // parse time and name the conflicting index pair so the
        // user can find both occurrences in the YAML.
        if let Some(prev_idx) = names.iter().position(|n| n == name) {
            return Err(Error::Config(format!(
                "Duplicate module name '{name}' at index {idx}; first declared at index \
                 {prev_idx}. Every module needs a unique `name:` — rename one (the wiring \
                 still uses the rename, the manifest's `type:` stays the same)."
            )));
        }

        // Resolve `quarantine_partner` (string or numeric form) →
        // `quarantine_partner_idx: N` so `build_module_entry` reads
        // only the numeric form. Both spellings route to the same
        // `_idx` field. The module Value is cloned to avoid mutating
        // the borrowed input; the clone is cheap relative to the
        // rest of the build.
        let mut module_owned = module.clone();
        let partner_val = module.get("quarantine_partner");
        let resolved_idx: Option<u8> = match partner_val {
            Some(v) if v.is_string() => {
                let partner_name = v.as_str().unwrap();
                let idx = name_to_idx.get(partner_name).copied().ok_or_else(|| {
                    Error::Config(format!(
                        "module '{name}': quarantine_partner '{partner_name}' is not a declared module"
                    ))
                })?;
                Some(idx)
            }
            Some(v) if v.is_u64() => {
                let n = v.as_u64().unwrap();
                if n >= MAX_MODULES as u64 {
                    return Err(Error::Config(format!(
                        "module '{name}': quarantine_partner index {n} out of range (max {})",
                        MAX_MODULES - 1
                    )));
                }
                Some(n as u8)
            }
            Some(_) => {
                return Err(Error::Config(format!(
                    "module '{name}': quarantine_partner must be a module name (string) \
                     or index (number)"
                )));
            }
            None => None,
        };
        if let Some(idx) = resolved_idx {
            if let Some(obj) = module_owned.as_object_mut() {
                obj.insert(
                    "quarantine_partner_idx".to_string(),
                    serde_json::Value::Number((idx as u64).into()),
                );
            }
        }

        let id = idx as u8;
        let entry = build_module_entry(name, &module_owned, id, data_section, config, modules_dir)?;
        entries.push(entry);
        names.push(name.to_string());
    }

    Ok((entries, names))
}

/// Parse a port spec like "module.out[1]" or "module.ctrl" into (name, port_type, port_index).
/// port_type: 0=in, 1=out, 2=ctrl. port_index: 0-based.
/// Simple forms: "module" → (module, in, 0), "module.out" → (module, out, 0),
/// Indexed: "module.in[1]" → (module, in, 1), "module.out[1]" → (module, out, 1)
/// Load manifests for all modules referenced in the config.
///
/// Resolves module type aliases (e.g., `name: btn_melody, type: button` loads
/// `modules/button/manifest.toml` and stores it under key `btn_melody`).
/// Manifests live in the source `modules/` directory, not `target/modules/`.
/// Load manifests from both the standard fluxor module directories and
/// Extract the manifest-source search paths a config wants the build tool
/// to consult, in priority order. The returned list is the union of:
///
/// 1. Any explicit `module_search_paths: [..]` entries declared at the
///    top level of the YAML config. Each entry is resolved relative to
///    the config file's directory (so `module_search_paths:
///    [../../clustor/modules]` in `quantum/configs/*.yaml` points at
///    `clustor/modules` regardless of where the tool is invoked from).
///
/// 2. The implicit `<config-parent>/../modules` default (e.g.
///    `quantum/modules` for a config in `quantum/configs/*.yaml`).
///    Kept for backward compatibility; new graphs should prefer the
///    explicit `module_search_paths:` key so the substrate / app split
///    is visible at the config layer.
///
/// Both manifest discovery (`load_module_manifests_with_extra`) and
/// graph parsing should consult this list. Non-existent entries are
/// kept (the consumer skips them) so an env-specific path that's
/// missing doesn't silently shadow other entries.
pub fn extract_module_search_paths(
    config: &Value,
    config_path: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let config_dir = config_path.parent().unwrap_or(std::path::Path::new("."));

    if let Some(arr) = config.get("module_search_paths").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                let joined = config_dir.join(s);
                let canon = joined.canonicalize().unwrap_or(joined);
                paths.push(canon);
            }
        }
    }

    if let Some(default) = config_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("modules"))
    {
        // Avoid duplicating the default if the YAML already pointed at
        // the same place.
        let canon = default.canonicalize().unwrap_or(default);
        if !paths.iter().any(|p| p == &canon) {
            paths.push(canon);
        }
    }

    // Append the project root's `modules/` and the install root's
    // `modules/` so external user projects see the bundled
    // modules in their search-path view. The manifest loader
    // (`load_module_manifests_with_extra`) already walks these
    // independently via `STANDARD_MODULE_SUBDIRS`; surfacing them
    // here keeps `inspect`'s module-search-paths listing and the
    // actual loader behaviour aligned.
    let project = crate::project::root();
    let project_modules = project.join("modules");
    let canon = project_modules.canonicalize().unwrap_or(project_modules);
    if !paths.iter().any(|p| p == &canon) {
        paths.push(canon);
    }
    if let Some(install) = crate::project::install_root() {
        if install.path != project {
            let install_modules = install.path.join("modules");
            let canon = install_modules.canonicalize().unwrap_or(install_modules);
            if !paths.iter().any(|p| p == &canon) {
                paths.push(canon);
            }
        }
    }

    paths
}

/// any additional search paths (e.g., relative to the config file).
/// Standard fluxor module subdirectories, relative to a root. Mirrors
/// `Manifest::from_source_tree` in `tools/src/manifest.rs`. Built-ins
/// live under `modules/builtin/<platform>/<name>/`.
const STANDARD_MODULE_SUBDIRS: &[&str] = &[
    "modules/drivers",
    "modules/foundation",
    "modules/app",
    "modules/builtin/linux",
    "modules/builtin/host",
    "modules/builtin/wasm",
    "modules/builtin/qemu",
    "modules",
];

/// Build the prioritized list of module search roots. Order:
///   1. `<project_root>/<standard subdirs>` — user's overrides
///      first so a local module shadows the bundled one.
///   2. `<install_root>/<standard subdirs>` — bundled fallback
///      when the install root differs from the project root.
///
/// Returns absolute paths in priority order. Non-existent entries
/// are kept (the manifest loader skips them) so a missing
/// per-platform directory doesn't silently shadow other entries.
fn standard_module_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let project = crate::project::root();
    for sub in STANDARD_MODULE_SUBDIRS {
        dirs.push(project.join(sub));
    }
    if let Some(install) = crate::project::install_root() {
        if install.path != project {
            for sub in STANDARD_MODULE_SUBDIRS {
                let p = install.path.join(sub);
                if !dirs.contains(&p) {
                    dirs.push(p);
                }
            }
        }
    }
    dirs
}

/// Process-global "already warned" cache for malformed manifest
/// paths. `load_module_manifests_with_extra` runs multiple times
/// in a single `fluxor validate` / `fluxor build` invocation
/// (presentation groups + the main pipeline + each scenario
/// component); without deduplication the same warning fires 3-4
/// times for a single broken manifest. The cache survives for the
/// process lifetime, which is the natural scope — a fresh
/// invocation re-emits the warnings.
fn warn_manifest_parse_error_once(path: &std::path::Path, err: &Error) {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::BTreeSet<std::path::PathBuf>>> = OnceLock::new();
    let lock = SEEN.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()));
    let mut seen = match lock.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if seen.insert(path.to_path_buf()) {
        eprintln!(
            "warning: manifest at {} failed to parse: {}",
            path.display(),
            err
        );
    }
}

pub fn load_module_manifests_with_extra(
    modules_config: &Value,
    extra_dirs: &[&std::path::Path],
) -> HashMap<String, Manifest> {
    let mut manifests = HashMap::new();
    let standard = standard_module_dirs();
    let list = match modules_config.as_array() {
        Some(l) => l,
        None => return manifests,
    };
    for module in list {
        let name = match module["name"].as_str() {
            Some(n) => n,
            None => continue,
        };
        let type_name = module["type"].as_str().unwrap_or(name);
        let mut found = false;

        // Search standard dirs first (project root, then install
        // root). User overrides win because the project root is
        // walked first.
        for dir in &standard {
            let manifest_path = dir.join(type_name).join("manifest.toml");
            if manifest_path.exists() {
                match Manifest::from_toml(&manifest_path) {
                    Ok(m) => {
                        manifests.insert(name.to_string(), m);
                        found = true;
                    }
                    Err(e) => {
                        // Don't silently swallow the parse error —
                        // a malformed manifest looks identical to
                        // a missing one downstream ("no manifest
                        // found"), and the user has no idea why.
                        // Surface the path + error so they can fix
                        // it; the downstream gate still errors out
                        // because the module didn't make it into
                        // the map. Dedup'd across the process so
                        // re-entry from multiple validators doesn't
                        // spam the same path 3-4 times.
                        warn_manifest_parse_error_once(&manifest_path, &e);
                    }
                }
                break;
            }
        }

        // Then search extra dirs (config-relative module paths)
        if !found {
            for extra in extra_dirs {
                let manifest_path = extra.join(type_name).join("manifest.toml");
                if manifest_path.exists() {
                    match Manifest::from_toml(&manifest_path) {
                        Ok(m) => {
                            manifests.insert(name.to_string(), m);
                        }
                        Err(e) => {
                            warn_manifest_parse_error_once(&manifest_path, &e);
                        }
                    }
                    break;
                }
            }
        }
    }
    manifests
}

/// Resolve a port spec using named ports from the module manifest.
///
/// Supported forms:
/// - `module` (bare name) — default to out[0] for "from:", in[0] for "to:"
/// - `module.portname` — look up named port in manifest
///
/// `context_is_from`: true if this is a `from:` spec (must resolve to output),
///                     false if this is a `to:` spec (must resolve to input or ctrl).
fn resolve_port_spec<'a>(
    spec: &'a str,
    context_is_from: bool,
    manifests: &HashMap<String, Manifest>,
    declared_names: &[String],
) -> std::result::Result<(&'a str, u8, u8), String> {
    let parts: Vec<&str> = spec.split('.').collect();
    let module_name = parts.first().unwrap_or(&spec).trim();

    if parts.len() < 2 {
        // Bare module name — default to out[0] for "from:", in[0] for "to:"
        let port_type = if context_is_from { 1 } else { 0 };
        return Ok((module_name, port_type, 0));
    }

    let port_part = parts[1].trim();

    // Named port — look up in manifest. A missing manifest at this
    // point is almost always one of: a typo in the module's name
    // (e.g. `sequencr.notes` when the module is declared as
    // `sequencer`), a typo in the `type:` field, a `.fmod` whose
    // source tree fluxor can't see (the project root is wrong, or
    // the install root needs to be set), or a built-in module
    // whose feature isn't compiled into the running fluxor binary.
    // Run a Levenshtein lookup against the declared module-name
    // list first — typo'd name is the single most common cause.
    let manifest = manifests.get(module_name).ok_or_else(|| {
        let typo_hint = crate::target::closest_match(module_name, declared_names, 3)
            .map(|s| format!("Did you mean '{s}'? "))
            .unwrap_or_default();
        format!(
            "no manifest found for module '{module_name}' (needed to resolve port name \
             '{port_part}'). {typo_hint}Common causes:\n\
             \x20\x20- the module name is misspelled or doesn't match a `name:` declared \
             under `modules:`;\n\
             \x20\x20- the module's `type:` field is misspelled or refers to a module that \
             doesn't exist;\n\
             \x20\x20- the project / install roots don't include the module's source tree \
             (run `fluxor inspect` to see the search paths in use);\n\
             \x20\x20- the module is a built-in whose feature isn't compiled into this \
             `fluxor` binary."
        )
    })?;

    let (direction, index, _content_type) =
        manifest.find_port_by_name(port_part).ok_or_else(|| {
            // Build helpful error with available port names + a
            // Levenshtein "did you mean" suggestion. `notess` →
            // 'notes' is the most common shape — the same pattern
            // every other typo-prone surface in this tool uses.
            let available: Vec<String> = manifest
                .ports
                .iter()
                .filter_map(|p| p.name.clone())
                .collect();
            if available.is_empty() {
                format!("module '{module_name}' has no named ports in its manifest")
            } else {
                let did_you_mean = crate::text_distance::closest_match(port_part, &available, 3)
                    .map(|h| format!(" Did you mean '{h}'?"))
                    .unwrap_or_default();
                format!(
                    "module '{module_name}' has no port named '{port_part}'.{did_you_mean} \
                     Available: {}",
                    available.join(", ")
                )
            }
        })?;

    // Validate direction matches context
    if context_is_from && direction != 1 && direction != 3 {
        return Err(format!(
            "port '{}.{}' is {} but used in 'from:' (must be output or ctrl_output)",
            module_name,
            port_part,
            manifest::direction_to_str(direction)
        ));
    }
    if !context_is_from && direction == 1 {
        return Err(format!(
            "port '{module_name}.{port_part}' is output but used in 'to:' (must be input or ctrl)"
        ));
    }

    Ok((module_name, direction, index))
}

/// Reject configs where a module declares an input port as
/// `required: true` in its manifest but no wiring edge connects to
/// that port. Without this check, the build silently succeeds and
/// the runtime instance blocks forever on an empty input ring (or
/// produces uninitialised output) — exactly the kind of "config
/// passes but graph runs wrong" failure that's most painful to
/// debug because nothing is logged.
///
/// Edges are checked against the resolved `to_port_index` field
/// (the per-direction index `parse_wiring_edges` computed from
/// either the bare-name shorthand or the explicit
/// `module.portname` form). A module with multiple required inputs
/// must have one edge per required input.
///
/// **Scope:** data inputs (direction == 0) only. Control inputs
/// (direction == 2) are usually rare-event signaling channels that
/// are typically optional; the manifest can still mark them
/// `required: true` if a module genuinely can't initialise without
/// the control wire, but the common case is "left unconnected".
/// If a need surfaces to enforce required ctrl inputs too, this
/// validator extends easily.
fn validate_required_inputs_wired(
    edges: &[(u8, u8, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    use std::collections::BTreeSet;

    // Index every (to_module_id, to_port_index) pair an edge
    // delivers into. `to_port` (the wire format's 0=in/1=ctrl
    // distinction) is also tracked so we can match against the
    // manifest's direction byte.
    //   wire_to_port 0 + manifest direction 0 → data input.
    //   wire_to_port 1 + manifest direction 2 → ctrl input.
    let mut covered_data: BTreeSet<(u8, u8)> = BTreeSet::new();
    for &(_, to_id, to_port, _, to_port_index) in edges {
        if to_port == 0 {
            covered_data.insert((to_id, to_port_index));
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for (module_id, name) in module_names.iter().enumerate() {
        let manifest = match manifests.get(name) {
            Some(m) => m,
            // No manifest → already an error class handled by the
            // wiring/manifest validator. Skip silently here to
            // avoid double-reporting.
            None => continue,
        };
        for port in &manifest.ports {
            // direction == 0 = data input. Skip output (1) and
            // ctrl input/output (2/3) — see scope comment above.
            if port.direction != 0 {
                continue;
            }
            // flags bit 0 = required (per `Manifest::from_toml` at
            // tools/src/manifest.rs line ~760). A non-required
            // input left unconnected is fine — module handles
            // empty input by design.
            if port.flags & 0x01 == 0 {
                continue;
            }
            if covered_data.contains(&(module_id as u8, port.index)) {
                continue;
            }
            // Build the most actionable label: prefer the port's
            // human name if the manifest declares one, else fall
            // back to `in[N]` so the user can spot which slot
            // needs wiring.
            let port_label = port
                .name
                .as_deref()
                .map(|n| format!("'{n}' (in[{}])", port.index))
                .unwrap_or_else(|| format!("in[{}]", port.index));
            violations.push(format!(
                "module '{name}' declares input port {port_label} as required, but no \
                 wiring edge connects to it. Add a `wiring:` entry of the form \
                 `to: {name}{port_specifier}`.",
                port_specifier = match &port.name {
                    Some(n) => format!(".{n}"),
                    None if port.index == 0 => String::new(),
                    None => format!(" (port index {})", port.index),
                }
            ));
        }
    }

    if !violations.is_empty() {
        return Err(Error::Config(format!(
            "Required input(s) left unwired — these modules will block at runtime:\n  - {}",
            violations.join("\n  - ")
        )));
    }
    Ok(())
}

/// Validate content-type compatibility for all wiring edges.
fn validate_wiring_types(
    edges: &[(u8, u8, u8, u8, u8)],
    force_flags: &[bool],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    from_specs: &[String],
    to_specs: &[String],
) -> Result<()> {
    // OctetStream content type ID = 0 (first in CONTENT_TYPES list)
    const OCTET_STREAM: u8 = 0;

    for (i, &(from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate()
    {
        if force_flags.get(i).copied().unwrap_or(false) {
            continue;
        }

        let from_name = &module_names[from_id as usize];
        let to_name = &module_names[to_id as usize];

        // Look up content types from manifests
        let from_ct = manifests
            .get(from_name)
            .and_then(|m| m.find_port(1, from_port_index)); // direction=1 (output)
        let to_direction = if to_port == 1 { 2u8 } else { 0u8 }; // ctrl=2, in=0
        let to_ct = manifests
            .get(to_name)
            .and_then(|m| m.find_port(to_direction, to_port_index));

        // Both must be known to validate
        if let (Some(from_ct), Some(to_ct)) = (from_ct, to_ct) {
            // OctetStream is universal — matches anything
            if from_ct == OCTET_STREAM || to_ct == OCTET_STREAM {
                continue;
            }
            if from_ct != to_ct {
                return Err(Error::Config(format!(
                    "content type mismatch: {} produces {} but {} expects {}\n  \
                     Add 'force: true' to the edge to override.",
                    from_specs[i],
                    manifest::content_type_to_str(from_ct),
                    to_specs[i],
                    manifest::content_type_to_str(to_ct),
                )));
            }
        }
    }
    Ok(())
}

const CUTOVER_POLICIES: &[&str] = &["boundary_cut", "resumable", "anchor_preserved"];
const CONTINUITY_POLICIES: &[&str] = &["drain", "anchor_preserved"];
const MIRROR_POLICIES: &[&str] = &["independent", "strict_mirror", "partition"];
const AUDIO_SINK_CAPS: &[&str] = &["audio.sample", "audio.encoded"];
const VIDEO_SINK_CAPS: &[&str] = &["video.raster", "video.scanout", "video.encoded"];
const VIDEO_PROTECTED_CAPS: &[&str] = &["display.protected_scanout", "video.protected_decode"];

/// Maximum value (in ms) accepted for `latency_budget_ms` /
/// `skew_budget_ms`. Beyond this the value almost certainly indicates a
/// unit confusion (microseconds, frames) rather than an honest budget.
const MAX_PRESENTATION_BUDGET_MS: u64 = 10_000;

fn json_kind(v: &Value) -> &'static str {
    if v.is_string() {
        "string"
    } else if v.is_number() {
        "number"
    } else if v.is_boolean() {
        "boolean"
    } else if v.is_null() {
        "null"
    } else if v.is_array() {
        "array"
    } else {
        "object"
    }
}

fn check_enum(field: &str, value: &str, allowed: &[&str], group_id: &str) -> Result<()> {
    if !allowed.contains(&value) {
        return Err(Error::Config(format!(
            "presentation_group `{}`: {} `{}` is invalid (expected {})",
            group_id,
            field,
            value,
            allowed.join(" | ")
        )));
    }
    Ok(())
}

/// Validate the optional top-level `presentation_groups` block. Members,
/// clock authority, and policy fields are checked against the manifest
/// capabilities of each named module. Presentation groups are
/// compile-time only — there is no binary representation in the
/// compiled config.
///
/// Schema and capability semantics live in
/// `docs/architecture/av_capability_surface.md`. In short:
///
/// ```yaml
/// presentation_groups:
///   - id: living_room
///     clock_authority: hdmi_audio
///     members: [hdmi_audio, lcd_panel]
///     latency_budget_ms: 40
///     skew_budget_ms: 8
///     cutover_policy: boundary_cut
///     continuity_policy: drain
///     mirror_policy: independent
///     protected: false
///     multihead: false
/// ```
pub fn validate_presentation_groups(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    let groups = match config.get("presentation_groups") {
        Some(v) => v,
        None => return Ok(()),
    };
    let list = groups
        .as_array()
        .ok_or_else(|| Error::Config("presentation_groups must be a list".into()))?;

    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (gi, g) in list.iter().enumerate() {
        let id = g
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_groups[{gi}]: required field `id` missing"
                ))
            })?
            .to_string();
        if !seen_ids.insert(id.clone()) {
            return Err(Error::Config(format!(
                "presentation_groups: duplicate id `{id}`"
            )));
        }

        let clock_authority = g
            .get("clock_authority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{id}`: required field `clock_authority` missing"
                ))
            })?
            .to_string();

        let members_raw = g.get("members").and_then(|v| v.as_array()).ok_or_else(|| {
            Error::Config(format!(
                "presentation_group `{id}`: required field `members` missing"
            ))
        })?;
        let mut members: Vec<String> = Vec::with_capacity(members_raw.len());
        for (mi, raw) in members_raw.iter().enumerate() {
            let s = raw.as_str().ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{}`: members[{}] must be a string (got {})",
                    id,
                    mi,
                    json_kind(raw)
                ))
            })?;
            members.push(s.to_string());
        }
        if members.is_empty() {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: `members` is empty"
            )));
        }
        for m in &members {
            if !module_names.iter().any(|n| n == m) {
                return Err(Error::Config(format!(
                    "presentation_group `{id}`: unknown member `{m}`"
                )));
            }
        }
        if !members.iter().any(|m| m == &clock_authority) {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: clock_authority `{clock_authority}` is not in members {members:?}"
            )));
        }

        let manifest_caps = |name: &str| -> &[String] {
            manifests
                .get(name)
                .map(|m| m.capabilities.as_slice())
                .unwrap_or(&[])
        };
        let has_cap = |caps: &[String], wanted: &str| -> bool { caps.iter().any(|c| c == wanted) };
        let has_any_cap = |caps: &[String], wanted: &[&str]| -> bool {
            caps.iter().any(|c| wanted.contains(&c.as_str()))
        };

        if !has_cap(manifest_caps(&clock_authority), "presentation.clock") {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: clock_authority `{clock_authority}` does not declare \
                 capability `presentation.clock` (add it to the module's manifest, \
                 or pick an authority that does)"
            )));
        }

        if let Some(cp) = g.get("cutover_policy").and_then(|v| v.as_str()) {
            check_enum("cutover_policy", cp, CUTOVER_POLICIES, &id)?;
        }
        if let Some(cp) = g.get("continuity_policy").and_then(|v| v.as_str()) {
            check_enum("continuity_policy", cp, CONTINUITY_POLICIES, &id)?;
        }
        if let Some(mp) = g.get("mirror_policy").and_then(|v| v.as_str()) {
            check_enum("mirror_policy", mp, MIRROR_POLICIES, &id)?;
        }

        // Protected playback: every audio sink must declare
        // `audio.protected_out`; every video sink must declare either
        // `display.protected_scanout` or `video.protected_decode`. A
        // protected path is end-to-end or it isn't a protected path.
        if g.get("protected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            for m in &members {
                let caps = manifest_caps(m);
                if has_any_cap(caps, AUDIO_SINK_CAPS) && !has_cap(caps, "audio.protected_out") {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: protected=true but audio member \
                         `{m}` does not declare `audio.protected_out`"
                    )));
                }
                if has_any_cap(caps, VIDEO_SINK_CAPS) && !has_any_cap(caps, VIDEO_PROTECTED_CAPS) {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: protected=true but video member \
                         `{m}` does not declare `display.protected_scanout` or \
                         `video.protected_decode`"
                    )));
                }
            }
        }

        // Multihead: at least two members must be independently bindable
        // paced display outputs.
        if g.get("multihead")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let scanout_count = members
                .iter()
                .filter(|m| has_cap(manifest_caps(m), "display.scanout"))
                .count();
            if scanout_count < 2 {
                return Err(Error::Config(format!(
                    "presentation_group `{id}`: multihead=true but only {scanout_count} member(s) \
                     declare `display.scanout` (need ≥2)"
                )));
            }
        }

        for k in &["latency_budget_ms", "skew_budget_ms"] {
            if let Some(v) = g.get(*k) {
                let n = v.as_u64().ok_or_else(|| {
                    Error::Config(format!(
                        "presentation_group `{id}`: `{k}` must be an unsigned integer (ms)"
                    ))
                })?;
                if n > MAX_PRESENTATION_BUDGET_MS {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: `{k}` = {n} ms exceeds the {MAX_PRESENTATION_BUDGET_MS} ms \
                         sanity bound (typical lip-sync budgets are ≤ 100 ms)"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Compose a clear "unknown module in wiring" error. For logical sink
/// names that the platform stack would normally provide, hint at the
/// missing `platform.<stack>:` block instead of leaving the developer
/// to guess. For everything else, run a Levenshtein lookup against
/// the declared module list — the most common cause is a typo (e.g.
/// `wiring: [from: my_modul.out]` against `name: my_module`).
fn unknown_module_in_wiring(name: &str, declared_names: &[String]) -> String {
    let stack_hint = match name {
        "display" => Some("did you forget `platform.display:` in your config?".to_string()),
        "audio_out" => Some("did you forget `platform.audio:` in your config?".to_string()),
        _ => None,
    };
    let typo_hint = crate::target::closest_match(name, declared_names, 3)
        .map(|s| format!("did you mean '{s}'?"));
    let hints: Vec<String> = stack_hint.into_iter().chain(typo_hint).collect();
    if hints.is_empty() {
        format!("Unknown module in wiring: {name}")
    } else {
        format!("Unknown module in wiring: {name} ({})", hints.join("; "))
    }
}

/// One entry per wire: `(from_id, to_id, to_port, from_port_index, to_port_index)`.
/// `to_port`: 0 = data input, 1 = control input.
type WireTuple = (u8, u8, u8, u8, u8);

/// Result bundle from `parse_wiring_edges`: tuples, force flags,
/// and the original source/destination spec strings (parallel arrays).
type WiringEdges = (Vec<WireTuple>, Vec<bool>, Vec<String>, Vec<String>);

/// Parse wiring edges from YAML config.
/// Supports indexed port syntax: "bank.out[1]" → from_port_index=1
/// Supports named port syntax: "voip.rtp" → resolves via manifest
fn parse_wiring_edges(
    wiring: &Value,
    names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<WiringEdges> {
    let list = wiring
        .as_array()
        .ok_or_else(|| Error::Config("wiring must be a list".into()))?;

    let mut edges = Vec::new();
    let mut force_flags = Vec::new();
    let mut from_specs = Vec::new();
    let mut to_specs = Vec::new();

    for w in list {
        let from = w["from"].as_str().unwrap_or("");
        let to = w["to"].as_str().unwrap_or("");
        let force = w["force"].as_bool().unwrap_or(false);

        let (from_name, _from_port_type, from_port_index) =
            resolve_port_spec(from, true, manifests, names)
                .map_err(|e| Error::Config(format!("wiring from '{from}': {e}")))?;
        let (to_name, to_port_type, to_port_index) = resolve_port_spec(to, false, manifests, names)
            .map_err(|e| Error::Config(format!("wiring to '{to}': {e}")))?;

        // Map destination port type to wire format: in(0)→0, ctrl(2)→1
        let to_port = if to_port_type == 2 { 1u8 } else { 0u8 };

        let from_id = names
            .iter()
            .position(|n| n == from_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(from_name, names)))?
            as u8;
        let to_id = names
            .iter()
            .position(|n| n == to_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(to_name, names)))?
            as u8;

        edges.push((from_id, to_id, to_port, from_port_index, to_port_index));
        force_flags.push(force);
        from_specs.push(from.to_string());
        to_specs.push(to.to_string());
    }
    Ok((edges, force_flags, from_specs, to_specs))
}

/// Validate GPIO pin number against target's max_gpio.
fn validate_gpio_pin(pin: u64, context: &str, max_gpio: u8) -> Result<u8> {
    if pin >= max_gpio as u64 {
        return Err(Error::Config(format!(
            "{}: GPIO pin {} out of range (0-{})",
            context,
            pin,
            max_gpio - 1
        )));
    }
    Ok(pin as u8)
}

/// Build hardware section binary
///
/// Format (must match firmware config.rs parse_hardware_section):
/// - spi_count (u8)
/// - i2c_count (u8)
/// - gpio_count (u8)
/// - pio_count (u8)
/// - spi_configs[spi_count] (8 bytes each): bus, miso, mosi, sck, freq_hz(u32)
/// - i2c_configs[i2c_count] (8 bytes each): bus, sda, scl, reserved, freq_hz(u32)
/// - gpio_configs[gpio_count] (5 bytes each): pin, flags, initial, owner_module_id, reserved
/// - pio_configs[pio_count] (4 bytes each): pio_idx, data_pin, clk_pin, extra_pin
fn build_hardware_section(
    hardware: &Value,
    module_names: &[String],
    max_gpio: u8,
    pio_count: u8,
) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    let spi_configs = hardware["spi"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let i2c_configs = hardware["i2c"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let uart_configs = hardware["uart"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let gpio_configs = hardware["gpio"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let pio_configs = hardware["pio"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();

    if spi_configs.len() > MAX_HW_SPI {
        return Err(Error::Config(format!(
            "Too many SPI configs: {} > {}",
            spi_configs.len(),
            MAX_HW_SPI
        )));
    }
    if i2c_configs.len() > MAX_HW_I2C {
        return Err(Error::Config(format!(
            "Too many I2C configs: {} > {}",
            i2c_configs.len(),
            MAX_HW_I2C
        )));
    }
    if uart_configs.len() > MAX_HW_UART {
        return Err(Error::Config(format!(
            "Too many UART configs: {} > {}",
            uart_configs.len(),
            MAX_HW_UART
        )));
    }
    if gpio_configs.len() > MAX_HW_GPIO {
        return Err(Error::Config(format!(
            "Too many GPIO configs: {} > {}",
            gpio_configs.len(),
            MAX_HW_GPIO
        )));
    }
    if pio_configs.len() > MAX_HW_PIO {
        return Err(Error::Config(format!(
            "Too many PIO configs: {} > {}",
            pio_configs.len(),
            MAX_HW_PIO
        )));
    }

    // Header: counts + max_gpio + uart_count (6 bytes)
    result.push(spi_configs.len() as u8);
    result.push(i2c_configs.len() as u8);
    result.push(gpio_configs.len() as u8);
    result.push(pio_configs.len() as u8);
    result.push(max_gpio);
    result.push(uart_configs.len() as u8);

    // SPI configs (8 bytes each)
    for (i, spi) in spi_configs.iter().enumerate() {
        let bus = spi["bus"].as_u64().unwrap_or(0) as u8;
        let miso = validate_gpio_pin(
            spi["miso"].as_u64().unwrap_or(16),
            &format!("hardware.spi[{i}].miso"),
            max_gpio,
        )?;
        let mosi = validate_gpio_pin(
            spi["mosi"].as_u64().unwrap_or(19),
            &format!("hardware.spi[{i}].mosi"),
            max_gpio,
        )?;
        let sck = validate_gpio_pin(
            spi["sck"].as_u64().unwrap_or(18),
            &format!("hardware.spi[{i}].sck"),
            max_gpio,
        )?;
        let freq_hz = spi["freq_hz"].as_u64().unwrap_or(400_000) as u32;

        result.push(bus);
        result.push(miso);
        result.push(mosi);
        result.push(sck);
        result.extend_from_slice(&freq_hz.to_le_bytes());
    }

    // I2C configs (8 bytes each)
    for (i, i2c) in i2c_configs.iter().enumerate() {
        let bus = i2c["bus"].as_u64().unwrap_or(0) as u8;
        let sda = validate_gpio_pin(
            i2c["sda"].as_u64().unwrap_or(4),
            &format!("hardware.i2c[{i}].sda"),
            max_gpio,
        )?;
        let scl = validate_gpio_pin(
            i2c["scl"].as_u64().unwrap_or(5),
            &format!("hardware.i2c[{i}].scl"),
            max_gpio,
        )?;
        let freq_hz = i2c["freq_hz"].as_u64().unwrap_or(100_000) as u32;

        result.push(bus);
        result.push(sda);
        result.push(scl);
        result.push(0); // reserved
        result.extend_from_slice(&freq_hz.to_le_bytes());
    }

    // UART configs (8 bytes each): bus, tx_pin, rx_pin, reserved, baudrate(u32)
    for (i, uart) in uart_configs.iter().enumerate() {
        let bus = uart["bus"].as_u64().unwrap_or(0) as u8;
        let tx_pin = validate_gpio_pin(
            uart["tx_pin"].as_u64().unwrap_or(0),
            &format!("hardware.uart[{i}].tx_pin"),
            max_gpio,
        )?;
        let rx_pin = validate_gpio_pin(
            uart["rx_pin"].as_u64().unwrap_or(1),
            &format!("hardware.uart[{i}].rx_pin"),
            max_gpio,
        )?;
        let baudrate = uart["baudrate"].as_u64().unwrap_or(115200) as u32;

        result.push(bus);
        result.push(tx_pin);
        result.push(rx_pin);
        result.push(0); // reserved
        result.extend_from_slice(&baudrate.to_le_bytes());
    }

    // GPIO configs (5 bytes each): pin, flags, initial, owner_module_id, reserved
    for (i, gpio) in gpio_configs.iter().enumerate() {
        let pin = validate_gpio_pin(
            gpio["pin"].as_u64().unwrap_or(0),
            &format!("hardware.gpio[{i}].pin"),
            max_gpio,
        )?;

        // Direction: "output" or "input" (default: output)
        let direction = match gpio["direction"].as_str().unwrap_or("output") {
            "input" | "in" => 0u8,
            _ => 1u8, // output
        };

        // Pull: "none", "up", "down" (default: none)
        let pull = match gpio["pull"].as_str().unwrap_or("none") {
            "up" => 1u8,
            "down" => 2u8,
            _ => 0u8, // none
        };

        // Initial level: "high" or "low" (default: high for outputs)
        let initial = match gpio["initial"].as_str() {
            Some("low") | Some("0") => 0u8,
            Some("high") | Some("1") => 1u8,
            None => {
                // Default based on numeric value or true/false
                if let Some(n) = gpio["initial"].as_u64() {
                    if n == 0 {
                        0u8
                    } else {
                        1u8
                    }
                } else if let Some(b) = gpio["initial"].as_bool() {
                    if b {
                        1u8
                    } else {
                        0u8
                    }
                } else {
                    1u8 // default high
                }
            }
            _ => 1u8,
        };

        // Owner module: resolve name to index, 0xFF = kernel-owned
        let owner_module_id: u8 = if let Some(owner_name) = gpio["owner"].as_str() {
            match module_names.iter().position(|n| n == owner_name) {
                Some(idx) => idx as u8,
                None => {
                    return Err(Error::Config(format!(
                        "hardware.gpio[{i}].owner: unknown module '{owner_name}'"
                    )));
                }
            }
        } else {
            0xFF // kernel-owned (default)
        };

        // flags: bit0 = direction (0=in, 1=out), bit1-2 = pull (0=none, 1=up, 2=down)
        let flags = direction | (pull << 1);

        result.push(pin);
        result.push(flags);
        result.push(initial);
        result.push(owner_module_id);
        result.push(0); // reserved
    }

    // PIO configs (4 bytes each): pio_idx, data_pin, clk_pin, extra_pin
    for (i, pio) in pio_configs.iter().enumerate() {
        let pio_idx = pio["pio_idx"].as_u64().unwrap_or(0) as u8;
        if pio_idx >= pio_count {
            return Err(Error::Config(format!(
                "hardware.pio[{i}].pio_idx {pio_idx} >= target pio_count {pio_count}"
            )));
        }
        let data_pin = validate_gpio_pin(
            pio["data_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{i}].data_pin"),
            max_gpio,
        )?;
        let clk_pin = validate_gpio_pin(
            pio["clk_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{i}].clk_pin"),
            max_gpio,
        )?;
        let extra_pin = pio["extra_pin"].as_u64().unwrap_or(0xFF) as u8;

        result.push(pio_idx);
        result.push(data_pin);
        result.push(clk_pin);
        result.push(extra_pin);
    }

    Ok(result)
}

/// Resolve edge_class for each wiring entry.
///
/// Reads `edge_class` field from each wiring entry:
/// - "local" (default) → 0
/// - "dma_owned" → 1
/// - "cross_core" → 2
///
/// Also validates: cross_core edges must connect modules in different domains.
fn resolve_edge_classes(
    config: &Value,
    _module_names: &[String],
    domain_names: &[String],
) -> Result<Vec<u8>> {
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Ok(Vec::new()),
    };

    let mut classes = Vec::with_capacity(wiring.len());

    // Build module_name → domain_id lookup. Surfaces an unknown-domain
    // typo here too so cross_core edge-class validation can't fall back
    // to a phantom domain 0.
    let modules_list = config.get("modules").and_then(|m| m.as_array());
    let mut module_domain: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    if let Some(mods) = modules_list {
        for m in mods {
            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                let domain = resolve_domain_id(m, config)?;
                module_domain.insert(name.to_string(), domain);
            }
        }
    }

    for (i, entry) in wiring.iter().enumerate() {
        let ec_str = entry
            .get("edge_class")
            .and_then(|v| v.as_str())
            .unwrap_or("local");
        let ec = match ec_str {
            "dma_owned" => 1u8,
            "cross_core" => {
                // Validate: from and to must be in different domains
                if let (Some(from_spec), Some(to_spec)) = (
                    entry.get("from").and_then(|v| v.as_str()),
                    entry.get("to").and_then(|v| v.as_str()),
                ) {
                    let from_mod = from_spec.split('.').next().unwrap_or("");
                    let to_mod = to_spec.split('.').next().unwrap_or("");
                    let from_d = module_domain.get(from_mod).copied().unwrap_or(0);
                    let to_d = module_domain.get(to_mod).copied().unwrap_or(0);
                    if from_d == to_d && !domain_names.is_empty() {
                        eprintln!("warning: wiring[{i}] edge_class=cross_core but '{from_mod}' and '{to_mod}' are in same domain {from_d}");
                    }
                }
                2u8
            }
            "nic_ring" => 3u8,
            _ => 0u8, // "local" or unknown
        };
        classes.push(ec);
    }

    Ok(classes)
}

/// Resolve `buffer_bytes` for each wiring entry.
///
/// Reads the optional `buffer_bytes` field on each `wiring[]` entry.
/// `0` (or missing) means "use module hints / default". Non-zero
/// values are clamped to `[64, MAX_CHAN_BYTES = 256 KiB]`; the kernel
/// rounds up to the next power of two at channel-open time, so the
/// encoded value is the lower bound the producer needs.
///
/// Per-edge sizing matters when edge bandwidth depends on graph
/// composition rather than module type — e.g. a `spectrum_video →
/// wasm_browser_canvas` raster edge that must carry 98 KiB per
/// frame at 50 fps doesn't share a default with a low-rate
/// telemetry edge from the same producer.
fn resolve_edge_buffer_bytes(config: &Value) -> Vec<u32> {
    const MAX_CHAN_BYTES: u32 = 256 * 1024;
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(wiring.len());
    for (i, entry) in wiring.iter().enumerate() {
        let raw = entry
            .get("buffer_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let clamped = if raw == 0 {
            0
        } else if raw < 64 {
            eprintln!("warning: wiring[{i}] buffer_bytes={raw} below minimum 64; rounding up");
            64
        } else if raw > MAX_CHAN_BYTES as u64 {
            eprintln!(
                "warning: wiring[{i}] buffer_bytes={raw} exceeds MAX_CHAN_BYTES={MAX_CHAN_BYTES}; clamping"
            );
            MAX_CHAN_BYTES
        } else {
            raw as u32
        };
        out.push(clamped);
    }
    out
}

/// Generate binary config in FXWR format (version 1)
///
/// Layout:
/// - Header (8 bytes): magic (u32), version (u16), checksum (u16)
/// - Counts (8 bytes): module_count, edge_count, reserved[6]
/// - Module section header (6 bytes): module_count, reserved, section_size (u32)
/// - Module entries (variable length each)
/// - Graph section (64 bytes): edge_count, flags, reserved[2], edges[15]
/// - Hardware section: spi_count, i2c_count, gpio_count, reserved, configs...
///
/// Module capability info for buffer aliasing and manifest validation.
pub struct ModuleCaps {
    pub name: String,
    /// Can safely consume from mailbox channels (header flags bit 0)
    pub mailbox_safe: bool,
    /// Uses buffer_acquire_inplace to modify buffer (header flags bit 1)
    pub in_place_writer: bool,
    pub manifest: crate::manifest::Manifest,
}

/// Generate config with extra module search directories (for external projects).
///
/// `resolved_target` is the silicon-or-board id chosen by the CLI's
/// `--target` flag (or the default), already resolved by the caller via
/// `target::load_target`. When `Some`, it overrides any literal
/// `target:` field in the YAML config — that's what makes the
/// `[requires]` hardware-capability check honour the actual build
/// target rather than a stale YAML default. `None` means fall back to
/// the YAML's literal value, which is the documented opt-in behaviour
/// for legacy configs / fixtures with no declared target.
#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
pub fn generate_config_ext(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
    resolved_target: Option<&str>,
) -> Result<Vec<u8>> {
    generate_config_impl(
        config,
        _template,
        module_caps,
        modules_dir,
        extra_module_dirs,
        max_gpio,
        pio_count,
        resolved_target,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
fn generate_config_impl(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
    resolved_target: Option<&str>,
) -> Result<Vec<u8>> {
    let modules = config
        .get("modules")
        .ok_or_else(|| Error::Config("modules section required".into()))?;

    // Parse graph-level sample_rate (top-level or under graph: key)
    let graph_sample_rate: u32 = config
        .get("sample_rate")
        .or_else(|| config.get("graph").and_then(|g| g.get("sample_rate")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // Parse tick_us (top-level or under execution:)
    let tick_us: u16 = config
        .get("tick_us")
        .or_else(|| config.get("execution").and_then(|e| e.get("tick_us")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    // Validate tick_us range
    if tick_us > 0 && !(100..=50000).contains(&tick_us) {
        return Err(Error::Config(format!(
            "tick_us {tick_us} out of range (valid: 100-50000, or 0 for default 1000)"
        )));
    }

    // Parse execution.domains. Hard-reject if the list exceeds
    // the kernel's `MAX_DOMAINS = 4` ceiling. The config writer
    // serialises exactly 4 domain-metadata entries
    // (`domain metadata: 4 entries × …` in the graph section), so
    // a 5th declared domain would either be silently dropped on
    // the wire OR (worse) a module assigned to it would resolve
    // to a domain id the kernel can't address (`domain_count`
    // clamps to 4 in `prepare_graph`). Reject at source so the
    // user sees a single clear error rather than odd runtime
    // behaviour.
    let mut domain_names: Vec<String> = Vec::new();
    let mut domain_tick_us: Vec<u16> = Vec::new();
    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            if domains.len() > MAX_DOMAINS {
                return Err(Error::Config(format!(
                    "execution.domains has {} entries; the kernel supports at most {} \
                     (MAX_DOMAINS — one per physical or logical scheduling partition). \
                     Drop the extras or merge their modules into existing domains.",
                    domains.len(),
                    MAX_DOMAINS
                )));
            }
            for domain in domains {
                let name = domain
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default");
                domain_names.push(name.to_string());
                let dtick = domain.get("tick_us").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                domain_tick_us.push(dtick);
            }
        }
    }
    // Domain count is inferred by the kernel from module domain_id assignments.
    // domain_names is still used for edge_class validation below.

    // Warn if tick_us < 500 with many modules
    let module_list = modules
        .as_array()
        .ok_or_else(|| Error::Config("modules must be a list".into()))?;
    if tick_us > 0 && tick_us < 500 && module_list.len() > 8 {
        eprintln!(
            "warning: tick_us={} with {} modules may exceed tick budget",
            tick_us,
            module_list.len()
        );
    }

    // Budget validation: prove step_deadlines, burst budgets, and
    // per-domain tick budgets fit together before the kernel ever
    // boots the graph. Until this lands, a config could declare
    // `step_deadline_us: 5000` on a module in a domain with
    // `tick_us: 1000` and the deadline would silently force every
    // step over budget — observable only as missed-deadline timeouts
    // at runtime.
    validate_scheduler_budgets(config, module_list, tick_us, &domain_names, &domain_tick_us)?;

    // ISR-tier admission: every module routed to a Tier 1b/2 domain
    // must declare `isr_safe = true` in its manifest, and the wiring
    // touching it cannot use an edge class incompatible with bridge
    // routing. The build-time gate is half of D6 — the runtime
    // routing in `channel_open` is the other half. See
    // `.context/rfc_isr_tier_surface.md` for the full contract.
    validate_isr_tier_admission(config, module_list, modules_dir, extra_module_dirs)?;

    // Inject graph sample_rate into modules that don't declare their own
    let modules_with_rate;
    let modules_ref = if graph_sample_rate > 0 {
        let mut list = module_list.clone();
        for m in &mut list {
            if m.get("sample_rate").is_none() {
                if let Some(obj) = m.as_object_mut() {
                    obj.insert("sample_rate".to_string(), json!(graph_sample_rate));
                }
            }
        }
        modules_with_rate = Value::Array(list);
        &modules_with_rate
    } else {
        modules
    };

    // Get data section for preset resolution
    let data_section = config.get("data");

    let (module_entries, module_names) =
        parse_modules_map(modules_ref, data_section, config, modules_dir)?;

    // Load manifests for named port resolution and type validation
    let manifests = load_module_manifests_with_extra(modules_ref, extra_module_dirs);

    // Hardware-capability validation. Each module's `[requires]`
    // block declares what the silicon must provide (FPU / NEON /
    // MMU). Reject placement on a silicon that doesn't satisfy the
    // request BEFORE generating a binary that would silently
    // soft-float on RP2040 or fail to link NEON on Cortex-M.
    //
    // The CLI-resolved target wins over any literal `target:` in the
    // YAML — that's the contract that lets `--target` override a
    // checked-in default. Legacy fixtures without either omit the
    // check entirely; that's by design, since the default `requires`
    // is all-false and satisfies every silicon.
    let silicon_opt = resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str()));
    if let Some(silicon) = silicon_opt {
        for (i, m) in module_list.iter().enumerate() {
            let name = m
                .get("name")
                .and_then(|n| n.as_str())
                .or_else(|| m.get("type").and_then(|n| n.as_str()))
                .unwrap_or("?");
            if let Some(manifest) = manifests.get(name) {
                if let Err(e) =
                    crate::manifest::check_target_capabilities(manifest.requires, silicon)
                {
                    return Err(Error::Config(format!("modules[{i}] ({name}): {e}")));
                }
            }
        }
    }

    let (edges, force_flags, from_specs, to_specs) = if config.get("wiring").is_some() {
        parse_wiring_edges(&config["wiring"], &module_names, &manifests)?
    } else {
        return Err(Error::Config("wiring section required".into()));
    };

    // Validate content-type compatibility
    validate_wiring_types(
        &edges,
        &force_flags,
        &module_names,
        &manifests,
        &from_specs,
        &to_specs,
    )?;

    // Required-input-unwired detector. Manifests mark some input
    // ports `required: true` — those MUST have a wiring edge
    // connecting to them or the module will block on an empty
    // input ring at runtime with no diagnostic. Catching this at
    // build time turns a silent runtime stall into a loud
    // validate-time failure.
    validate_required_inputs_wired(&edges, &module_names, &manifests)?;

    // (Considered: warn on declared-but-never-wired modules. Real
    // bug class — refactor leftovers, typo'd wire references —
    // but the false-positive rate on legitimate standalone modules
    // (`debug`, monitor, alive heartbeat) is too high to justify
    // a default warning. Filed for revisit if a manifest-side
    // `standalone: true` opt-in lands so the check can be precise.)

    validate_presentation_groups(config, &module_names, &manifests)?;

    if edges.len() > MAX_GRAPH_EDGES {
        return Err(Error::Config(format!(
            "Too many graph edges: {} > {}",
            edges.len(),
            MAX_GRAPH_EDGES
        )));
    }

    // Validate per-module port indices against `MAX_PORTS`. The
    // kernel's `populate_ports()` enforces the same bound at module
    // instantiation; catching it at build time gives a clear error
    // instead of a cryptic boot failure. Must equal
    // `src/kernel/scheduler.rs::MAX_PORTS`. The wire encoding
    // (`port_byte` is two 4-bit fields, indices 0..=15) is the
    // ultimate ceiling.
    const MAX_PORTS: u8 = 16;
    for &(from_id, to_id, _to_port, from_port_index, to_port_index) in &edges {
        if from_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' output port index {} exceeds limit (max {})",
                module_names[from_id as usize],
                from_port_index,
                MAX_PORTS - 1
            )));
        }
        if to_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' input port index {} exceeds limit (max {})",
                module_names[to_id as usize],
                to_port_index,
                MAX_PORTS - 1
            )));
        }
    }

    // Mirrors `kernel::config`'s version check; bumped only when the
    // kernel parser breaks compatibility, not for additive wire-
    // format extensions like the per-edge `buffer_bytes` override.
    let version: u16 = 1;

    let mut result = Vec::new();

    // Header (8 bytes): magic, version, checksum
    result.extend_from_slice(&MAGIC_LEGACY.to_le_bytes()); // "FXWR"
    result.extend_from_slice(&version.to_le_bytes());
    result.extend_from_slice(&0u16.to_le_bytes()); // checksum (computed later)

    // Counts (8 bytes): module_count(1), edge_count(1), tick_us(2), graph_sample_rate(4)
    result.push(module_entries.len() as u8); // module_count
    result.push(edges.len() as u8); // edge_count
    result.extend_from_slice(&tick_us.to_le_bytes()); // tick_us (u16, bytes 10-11)
    result.extend_from_slice(&graph_sample_rate.to_le_bytes()); // graph_sample_rate (u32, bytes 12-15)

    // Calculate total module section size
    let module_section_size: usize = module_entries.iter().map(|e| e.len()).sum();

    // Module section header (6 bytes). `section_size` is u32 so the
    // synth host can carry per-component embedded shells (~60 KiB
    // each) without overflowing — split scenarios that mount a
    // viewer/player alongside a producer easily sum to >64 KiB of
    // module data when both halves' http modules inline their
    // shells. Embedded targets (rp/bcm) still fit in u16 worth of
    // bytes in practice; the wider field costs 2 bytes per config.
    result.push(module_entries.len() as u8); // module_count
    result.push(0); // reserved
    result.extend_from_slice(&(module_section_size as u32).to_le_bytes()); // section_size

    // Module entries (variable length)
    for entry in &module_entries {
        result.extend_from_slice(entry);
    }

    // Validate manifests: check dependencies and resource conflicts
    if !module_caps.is_empty() {
        validate_manifests(&module_names, module_caps)?;
    }

    // Validate service dependencies from YAML `services:` section
    validate_services(config, &module_names, &manifests)?;

    // Assign buffer groups for aliasable edge chains, then apply
    // per-edge YAML overrides. The auto-assign pass only groups
    // edges where the destination is an in-place-safe chain interior
    // — it can't see "this edge needs mailbox semantics for transport
    // atomicity" (e.g. WsFrame envelopes between ws_stream and http).
    // A non-zero `buffer_group:` field on a wiring entry enables
    // mailbox mode on that channel (see
    // `src/kernel/scheduler/mod.rs::open_channels` — mailbox flag is
    // set when buffer_group != 0). Without this, the channel is a
    // byte-streaming FIFO and structured envelopes get fragmented.
    let mut buffer_groups = assign_buffer_groups(&edges, &module_names, module_caps)?;
    if let Some(wiring) = config.get("wiring").and_then(|w| w.as_array()) {
        for (i, entry) in wiring.iter().enumerate() {
            if let Some(g) = entry.get("buffer_group").and_then(|v| v.as_u64()) {
                if g > 0 && g <= 31 && i < buffer_groups.len() {
                    buffer_groups[i] = g as u8;
                }
            }
        }
    }

    // Resolve per-edge edge_class from wiring entries
    let edge_classes = resolve_edge_classes(config, &module_names, &domain_names)?;
    // Resolve per-edge `buffer_bytes` overrides from wiring entries.
    // Parallel array; entries default to 0 ("use module hints").
    let edge_buffer_bytes = resolve_edge_buffer_bytes(config);

    // Graph section.
    //   header (4 bytes): edge_count, flags, reserved[2]
    //   edges  (MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE bytes)
    //   domain metadata (DOMAIN_META_SIZE bytes)
    //
    // Edge format (8 bytes; mirrors `kernel::config::parse_graph_edge`):
    //   byte 0:    from_id
    //   byte 1:    to_id
    //   byte 2:    bit 7    = to_port
    //              bits 6:5 = edge_class (2 bits)
    //              bits 4:0 = buffer_group (5 bits, 0..31)
    //   byte 3:    bits 7:4 = from_port_index (4 bits, 0..15)
    //              bits 3:0 = to_port_index   (4 bits, 0..15)
    //   bytes 4-7: buffer_bytes (u32 LE; 0 = use module hints)
    //
    // Both ports get 4 bits; the runtime cap is `MAX_PORTS=16`. The
    // 5-bit `buffer_group` ceiling (31) is enforced by
    // `assign_buffer_groups`.
    // Graph section header layout — must agree with the parser at
    // `src/kernel/config.rs::read_config_at_into` (graph_flags read).
    //   byte 0: edge_count
    //   byte 1: graph_flags (bit 0 = ACCEPT_CYCLES; bits 1-7 reserved)
    //   bytes 2-3: reserved (must be 0)
    let accept_cycles = config
        .get("scheduler")
        .and_then(|s| s.get("accept_cycles"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let graph_flags: u8 = if accept_cycles { 0x01 } else { 0x00 };

    let mut graph_section = Vec::with_capacity(GRAPH_SECTION_SIZE);
    graph_section.push(edges.len() as u8);
    graph_section.push(graph_flags);
    graph_section.extend_from_slice(&[0u8; 2]);
    for (i, (from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let group = buffer_groups.get(i).copied().unwrap_or(0);
        let ec = edge_classes.get(i).copied().unwrap_or(0);
        let buffer_bytes = edge_buffer_bytes.get(i).copied().unwrap_or(0);
        graph_section.push(*from_id);
        graph_section.push(*to_id);
        graph_section.push((to_port << 7) | ((ec & 0x03) << 5) | (group & 0x1F));
        graph_section.push(((from_port_index & 0x0F) << 4) | (to_port_index & 0x0F));
        graph_section.extend_from_slice(&buffer_bytes.to_le_bytes());
    }
    // Pad edge entries to fixed offset, then write domain metadata
    while graph_section.len() < 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE {
        graph_section.push(0);
    }
    // Domain metadata: 4 entries × (tick_us:u16 LE + exec_mode:u8 + reserved:u8) = 16 bytes
    for d in 0..4usize {
        let dtick = domain_tick_us.get(d).copied().unwrap_or(0);
        graph_section.extend_from_slice(&dtick.to_le_bytes());
        let mode = if let Some(domains) = config
            .get("execution")
            .and_then(|e| e.get("domains"))
            .and_then(|d| d.as_array())
        {
            domains
                .get(d)
                .map(|dom| parse_domain_tier_to_exec_mode(dom).unwrap_or(0))
                .unwrap_or(0)
        } else {
            0u8
        };
        graph_section.push(mode);
        graph_section.push(0); // reserved
    }
    while graph_section.len() < GRAPH_SECTION_SIZE {
        graph_section.push(0);
    }
    result.extend_from_slice(&graph_section);

    // Hardware section
    let hw_section =
        build_hardware_section(&config["hardware"], &module_names, max_gpio, pio_count)?;
    result.extend_from_slice(&hw_section);

    // Compute CRC16-CCITT checksum of body (bytes 8 onwards)
    let checksum = crc16_ccitt(&result[8..]);
    result[6..8].copy_from_slice(&checksum.to_le_bytes());

    Ok(result)
}

/// Assign buffer group IDs for aliasable edge chains.
///
/// Identifies linear chains of edges where intermediate modules are in-place-safe
/// (single data input, single data output, marked in_place_safe in .fmod header).
/// Edges in the same chain get the same non-zero group ID, enabling the scheduler
/// to alias them to the same channel buffer at runtime.
///
/// Returns a Vec of group IDs parallel to the edges slice. Group 0 = no aliasing.
fn assign_buffer_groups(
    edges: &[(u8, u8, u8, u8, u8)],
    module_names: &[String],
    module_caps: &[ModuleCaps],
) -> Result<Vec<u8>> {
    let n = edges.len();
    let mut groups = vec![0u8; n];

    // If no module caps provided, no aliasing possible
    if module_caps.is_empty() {
        return Ok(groups);
    }

    // Build lookups: module_name -> capability flags
    let is_chain_interior_capable = |module_id: u8| -> bool {
        let id = module_id as usize;
        if id >= module_names.len() {
            return false;
        }
        let name = &module_names[id];
        // Chain interior requires BOTH: can consume mailbox AND modifies in-place
        module_caps
            .iter()
            .any(|c| &c.name == name && c.mailbox_safe && c.in_place_writer)
    };

    // Count data edges per module (only data edges, to_port == 0)
    let num_modules = module_names.len();
    let mut data_in_count = vec![0u8; num_modules];
    let mut data_out_count = vec![0u8; num_modules];
    for (_, to_id, to_port, _, _) in edges {
        if *to_port == 0 {
            let idx = *to_id as usize;
            if idx < num_modules {
                data_in_count[idx] += 1;
            }
        }
        // All edges have an implicit "from out" so count from_id outputs
    }
    for (from_id, _, _, _, _) in edges {
        let idx = *from_id as usize;
        if idx < num_modules {
            data_out_count[idx] += 1;
        }
    }

    // Chain interior: 1-in, 1-out, mailbox_safe AND in_place_writer.
    // These modules read+write the same aliased buffer via acquire_inplace.
    let is_chain_interior = |module_id: u8| -> bool {
        let idx = module_id as usize;
        idx < num_modules
            && data_in_count[idx] == 1
            && data_out_count[idx] == 1
            && is_chain_interior_capable(module_id)
    };

    // Find the single data-out edge index for a module
    let find_out_edge = |module_id: u8| -> Option<usize> {
        edges
            .iter()
            .position(|(from_id, _, _, _, _)| *from_id == module_id)
    };

    let mut next_group: u8 = 1;

    // For each edge, if destination is a chain-interior module, try to form/extend a chain
    for i in 0..n {
        let (_, to_id, to_port, _, _) = edges[i];
        // Only consider data edges
        if to_port != 0 {
            continue;
        }
        // Destination must be in-place-safe with 1-in/1-out
        if !is_chain_interior(to_id) {
            continue;
        }

        // This edge feeds an in-place module. Find the output edge from that module.
        if let Some(out_idx) = find_out_edge(to_id) {
            // Both edges share a group so the in-place writer aliases
            // its input/output buffers. Group 0 means "no aliasing", so
            // 31 distinct chain ids are available before the 5-bit
            // `buffer_group` field is exhausted.
            let existing_group = if groups[i] != 0 {
                groups[i]
            } else if groups[out_idx] != 0 {
                groups[out_idx]
            } else {
                if next_group > 31 {
                    return Err(Error::Config(
                        "graph has more than 31 in-place chains; buffer_group field is 5 bits"
                            .into(),
                    ));
                }
                let g = next_group;
                next_group += 1;
                g
            };
            groups[i] = existing_group;
            groups[out_idx] = existing_group;
        }
    }

    // Propagate: if an edge has a group, and its destination is in-place-safe,
    // extend the group to the output edge (handles chains of 3+)
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if groups[i] == 0 {
                continue;
            }
            let (_, to_id, to_port, _, _) = edges[i];
            if to_port != 0 {
                continue;
            }
            if !is_chain_interior(to_id) {
                continue;
            }
            if let Some(out_idx) = find_out_edge(to_id) {
                if groups[out_idx] != groups[i] {
                    groups[out_idx] = groups[i];
                    changed = true;
                }
            }
        }
    }

    Ok(groups)
}

/// Validate module manifests: check dependencies and resource conflicts.
fn validate_manifests(module_names: &[String], module_caps: &[ModuleCaps]) -> Result<()> {
    use crate::hash::fnv1a_hash;

    // Build hash map and detect collisions
    let mut hash_to_name: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
    for name in module_names {
        let h = fnv1a_hash(name.as_bytes());
        if let Some(existing) = hash_to_name.get(&h) {
            return Err(Error::Config(format!(
                "FNV-1a hash collision: '{existing}' and '{name}' both hash to 0x{h:08x}",
            )));
        }
        hash_to_name.insert(h, name);
    }
    let available_hashes: std::collections::HashSet<u32> = hash_to_name.keys().copied().collect();

    // Check dependencies
    for cap in module_caps {
        for dep in &cap.manifest.dependencies {
            if !available_hashes.contains(&dep.name_hash) {
                return Err(Error::Config(format!(
                    "module '{}' requires dependency (hash 0x{:08x}) not present in config",
                    cap.name, dep.name_hash,
                )));
            }
        }
    }

    // Check exclusive resource conflicts (instance-aware).
    // Chain providers (access_mode 3) sit on top of exclusive providers via the
    // provider chain pattern (CHAIN_NEXT dispatch). They coexist with exclusive
    // providers and with each other on the same device class.
    // (device_class, instance, module_name)
    let mut exclusive_claims: Vec<(u8, u8, &str)> = Vec::new();
    for cap in module_caps {
        for res in &cap.manifest.resources {
            if res.access_mode == 2 {
                // exclusive — conflict when same class AND instances overlap
                // instances overlap when either is 0xFF (any) or they are equal
                if let Some((_, _, other)) = exclusive_claims.iter().find(|(c, inst, _)| {
                    *c == res.device_class
                        && (*inst == 0xFF || res.instance == 0xFF || *inst == res.instance)
                }) {
                    let inst_msg = if res.instance != 0xFF {
                        format!(" instance {}", res.instance)
                    } else {
                        String::new()
                    };
                    return Err(Error::Config(format!(
                        "resource conflict: both '{}' and '{}' claim exclusive access to device class 0x{:02x}{}",
                        other, cap.name, res.device_class, inst_msg,
                    )));
                }
                exclusive_claims.push((res.device_class, res.instance, &cap.name));
            }
            // access_mode 3 (chain) — no conflict check, chains stack on top
        }
    }

    Ok(())
}

/// Validate service dependencies declared in the YAML `services:` section.
///
/// Each entry maps a service name to a provider module name. Validation checks:
/// 1. The provider module exists in the config
/// 2. The provider module's manifest declares `provides` for that service
fn validate_services(
    config: &serde_json::Value,
    module_names: &[String],
    manifests: &std::collections::HashMap<String, crate::manifest::Manifest>,
) -> Result<()> {
    let services = match config.get("services") {
        Some(s) => s,
        None => return Ok(()), // no services section — skip validation
    };

    let services_map = match services.as_object() {
        Some(m) => m,
        None => {
            return Err(Error::Config(
                "services must be a mapping of service_name: provider_module".into(),
            ))
        }
    };

    for (service_name, provider_val) in services_map {
        let provider = provider_val.as_str().ok_or_else(|| {
            Error::Config(format!(
                "services.{service_name}: provider must be a string"
            ))
        })?;

        // Check provider module exists in config
        // Module names come from either name or type field — check by type too
        let provider_found = module_names.iter().any(|n| n == provider);
        if !provider_found {
            return Err(Error::Config(format!(
                "services.{service_name}: provider module '{provider}' not found in config modules",
            )));
        }

        // Check provider's manifest declares this service
        if let Some(manifest) = manifests.get(provider) {
            if !manifest.provides.iter().any(|p| p == service_name) {
                return Err(Error::Config(format!(
                    "services.{service_name}: module '{provider}' does not declare 'provides = [\"{service_name}\"]' in its manifest",
                )));
            }
        }
        // If no manifest found, skip the provides check (backward compat)
    }

    Ok(())
}

/// CRC16-CCITT calculation (matching C++ implementation)
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

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

#[cfg(test)]
mod scheduler_validation_tests {
    use super::*;

    // ---- resolve_domain_id: hard-fail on unknown domain ----

    #[test]
    fn unknown_domain_name_is_a_hard_error() {
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "audio", "tick_us": 1000},
                    {"name": "control", "tick_us": 10000}
                ]
            }
        });
        let module = json!({"name": "synth", "type": "x", "domain": "audoi"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("audoi") && msg.contains("audio") && msg.contains("control"),
            "expected error to name typo and known domains, got: {msg}"
        );
    }

    #[test]
    fn module_without_domain_resolves_to_default_zero() {
        let cfg = json!({
            "execution": {
                "domains": [{"name": "audio", "tick_us": 1000}]
            }
        });
        let module = json!({"name": "m", "type": "x"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 0);
    }

    #[test]
    fn known_domain_resolves_to_its_index() {
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "audio", "tick_us": 1000},
                    {"name": "control", "tick_us": 10000}
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "control"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 1);
    }

    #[test]
    fn resolve_rejects_module_targeting_fifth_or_later_domain() {
        // Defense-in-depth: even if a caller bypasses the
        // `generate_config_impl` top-level rejection of >4
        // domains, `resolve_domain_id` must refuse to return an
        // out-of-range domain id. A `domain_id >= MAX_DOMAINS`
        // can't be encoded in the 4-slot domain metadata + the
        // kernel's `domain_count` clamp would make the runtime
        // behaviour undefined.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "d0"},
                    {"name": "d1"},
                    {"name": "d2"},
                    {"name": "d3"},
                    {"name": "d4"}   // 5th domain — index 4
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "d4"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("at most 4") || msg.contains("index 4"),
            "expected out-of-range domain diagnostic, got: {msg}"
        );
    }

    #[test]
    fn resolve_accepts_module_targeting_fourth_domain() {
        // Boundary: index 3 (the 4th domain) IS valid — the cap
        // is `MAX_DOMAINS = 4` total, so indices 0..=3 are legal.
        // Catches an off-by-one regression where the bound
        // accidentally goes `> MAX_DOMAINS` instead of `>=`.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "d0"},
                    {"name": "d1"},
                    {"name": "d2"},
                    {"name": "d3"}
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "d3"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 3);
    }

    #[test]
    fn domain_named_without_any_execution_domains_section_errors() {
        // Catches the case where a module asks for a domain but the
        // YAML forgot to declare `execution.domains` at all.
        let cfg = json!({});
        let module = json!({"name": "m", "type": "x", "domain": "audio"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("execution.domains is missing"),
            "expected missing-section error, got: {msg}"
        );
    }

    // ---- validate_scheduler_budgets ----

    #[test]
    fn declared_burst_over_100ms_hard_caps() {
        // step_deadline_us=20_000 × BURST_MULTIPLIER(8) = 160 ms > 100 ms hard cap.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![json!({
            "name": "heavy",
            "type": "x",
            "step_deadline_us": 20_000
        })];
        let err = validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("absolute cap") && msg.contains("heavy"),
            "expected absolute-cap error naming the module, got: {msg}"
        );
    }

    #[test]
    fn declared_burst_over_16x_tick_hard_caps() {
        // step_deadline_us=3000 × 8 = 24_000 us. With tick_us=1000,
        // domain budget × 16 = 16_000 us < 24_000 us → hard fail.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![json!({
            "name": "spikey",
            "type": "x",
            "step_deadline_us": 3000
        })];
        let err = validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("16 \u{00d7} domain tick_us") || msg.contains("16 × domain tick_us"),
            "expected 16×-tick error, got: {msg}"
        );
    }

    #[test]
    fn undeclared_deadlines_skip_budget_validation() {
        // Three modules all using the kernel default deadline should
        // not trip the validator — the default is a fault threshold,
        // not a budget claim.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![
            json!({"name": "a", "type": "x"}),
            json!({"name": "b", "type": "x"}),
            json!({"name": "c", "type": "x"}),
        ];
        validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap();
    }

    // ---- parse_domain_tier_to_exec_mode ----

    #[test]
    fn tier_friendly_strings_map_to_exec_mode_bytes() {
        // The byte mapping is wire-stable — adding tiers must preserve
        // existing values. This test pins the {0,1,2,3,4} table from
        // .context/rfc_isr_tier_surface.md §D5.
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "cooperative"})),
            Some(0)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "1a"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "1b"})),
            Some(2),
            "Tier 1b → exec_mode 2 (the new admission target)"
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "3"})),
            Some(3)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "2"})),
            Some(4),
            "Tier 2 → exec_mode 4 (asymmetric because the byte was \
             allocated after 1a/3)"
        );
    }

    #[test]
    fn legacy_exec_mode_field_still_parses() {
        // Pre-RFC configs use `exec_mode: tier1a`. The parser must
        // keep accepting these so `examples/cm5/*` and other live
        // configs build unchanged.
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "tier1a"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "high_rate"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "poll"})),
            Some(3)
        );
    }

    #[test]
    fn unknown_tier_string_returns_none() {
        // Caller is responsible for hard-failing on a None when the
        // YAML actually had a `tier` / `exec_mode` field — silent
        // fall-through to Tier 0 would mask typos.
        assert!(parse_domain_tier_to_exec_mode(&json!({"tier": "1c"})).is_none());
        assert!(parse_domain_tier_to_exec_mode(&json!({"exec_mode": "real-time"})).is_none());
    }

    #[test]
    fn no_tier_field_returns_none_for_default() {
        assert!(parse_domain_tier_to_exec_mode(&json!({"name": "d"})).is_none());
    }

    // ---- validate_isr_tier_admission ----
    //
    // These tests exercise the validator directly with synthetic
    // manifests. Going through the full `fluxor build` path would
    // require a populated modules tree; the validator's contract is
    // narrow enough to test in isolation.

    fn run_admission(config: serde_json::Value, modules: Vec<serde_json::Value>) -> Result<()> {
        // Use a path that surely doesn't exist so `load_module_
        // manifests_with_extra` finds nothing. The validator handles
        // the missing-manifest case by skipping the isr_safe check
        // (the wiring/manifest validator surfaces missing-manifest
        // errors separately), so for the unknown-tier-and-typed-edge
        // tests we don't need a real manifest. The cases that DO
        // need a manifest plant fake ones via an `extra_module_dirs`
        // tempdir — see the dedicated tests below.
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = Vec::new();
        validate_isr_tier_admission(&config, &modules, modules_dir, &extras)
    }

    #[test]
    fn admission_passes_when_no_isr_tier_domains_present() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1a"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        run_admission(cfg, modules).expect("cooperative graph admits");
    }

    #[test]
    fn admission_rejects_unknown_tier_string() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1c"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown tier") && msg.contains("1a/high_rate"),
            "expected unknown-tier diagnostic naming valid values, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_tier_1b_as_not_yet_runtime_supported() {
        // Tier 1b is build-time-rejected today: the YAML schema +
        // build-time manifest gate + cooperative scheduler skip
        // are in place, but the runtime registration / bridge
        // wiring isn't. Better to fail loudly at build than ship
        // a config whose modules silently never run. Lift this
        // test (and the gate) when the runtime path lands.
        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "audio_isr"})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("tier 1b") && msg.contains("not yet runtime-supported"),
            "expected tier-1b-not-supported diagnostic, got: {msg}"
        );
        assert!(
            msg.contains("rfc_isr_tier_surface"),
            "diagnostic should point at the lift-tracking RFC, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_tier_2_as_not_yet_runtime_supported() {
        // Symmetric: Tier 2 (`tier: 2` / `isr_owned`) hits the
        // same hard-reject — same missing runtime piece, same
        // explanation.
        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "tier": "2"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "irq_owner"})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("tier 2") && msg.contains("not yet runtime-supported"),
            "expected tier-2-not-supported diagnostic, got: {msg}"
        );
    }

    #[test]
    fn admission_accepts_tier_1a_cooperative_with_isr_safe_field_present() {
        // Cooperative tiers (0/1a/3) are unaffected by the
        // Tier 1b/2 hard-reject — the `isr_safe` manifest flag is
        // simply ignored for non-ISR-tier domains. Catches a
        // regression where the gate goes too broad.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("plain_mod");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\nisr_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1a"}]}
        });
        let modules = vec![json!({"name": "plain_mod", "type": "plain_mod", "domain": "main"})];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras)
            .expect("cooperative tier with isr_safe=false on its modules is fine");
    }

    #[test]
    fn declared_deadlines_within_budget_pass() {
        // Two modules in domain 0 with declared deadlines summing to
        // 1500 us, tick_us 1000 → declared sum < 4×tick = 4000 → ok.
        let cfg = json!({"execution": {"domains": [{"name": "d0", "tick_us": 1000}]}});
        let modules = vec![
            json!({"name": "a", "type": "x", "step_deadline_us": 800}),
            json!({"name": "b", "type": "x", "step_deadline_us": 700}),
        ];
        validate_scheduler_budgets(&cfg, &modules, 1000, &["d0".to_string()], &[1000]).unwrap();
    }
}

#[cfg(test)]
#[allow(
    clippy::undocumented_unsafe_blocks,
    reason = "test scaffolding wraps std::env::{set_var, remove_var} which became `unsafe fn` in Rust 2024; safety is identical at every call site — the tests serialise on the module-level mutex"
)]
mod module_discovery_tests {
    //! Tests for the dual-root module manifest discovery added on
    //! top of the project/install root resolver. Verifies that
    //! `load_module_manifests_with_extra` finds modules under the
    //! install root when the project root lacks them (the
    //! "external user project pulls bundled modules" path), and
    //! that the project root wins on duplicate names (the "user
    //! overrides bundled" path).

    use super::*;

    /// Shared env-var lock — the project resolver reads
    /// `$FLUXOR_PROJECT_ROOT` / `$FLUXOR_INSTALL_ROOT` and these
    /// tests mutate both. Serialise so parallel test execution
    /// doesn't see each other's settings.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Set up a tree under `root` with a manifest at
    /// `root/modules/foundation/<name>/manifest.toml`. Used to
    /// synthesise both project and install roots for these tests
    /// without depending on the real source tree.
    fn plant_manifest(root: &std::path::Path, name: &str, isr_safe: bool) {
        let dir = root.join("modules/foundation").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let body = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\nisr_safe = {isr_safe}\n",
        );
        std::fs::write(dir.join("manifest.toml"), body).unwrap();
    }

    /// Install the `.fluxor` marker + a stub `targets/` + `stacks/`
    /// so `discover()` and `install_root()` accept the path.
    fn mark_project(root: &std::path::Path) {
        std::fs::write(root.join(".fluxor"), b"").unwrap();
    }

    fn mark_install(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("stacks")).unwrap();
        std::fs::create_dir_all(root.join("targets")).unwrap();
    }

    #[test]
    fn finds_module_in_install_root_when_project_lacks_it() {
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        // Only the install root has the manifest.
        plant_manifest(install.path(), "bundled_mod", true);

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        let modules = json!([{"name": "bundled_mod", "type": "bundled_mod"}]);
        let manifests = load_module_manifests_with_extra(&modules, &[]);
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }
        let m = manifests
            .get("bundled_mod")
            .expect("install-root manifest must be discoverable");
        assert!(m.isr_safe, "manifest content round-trips");
    }

    #[test]
    fn project_root_module_shadows_install_root_module() {
        // Both roots carry the manifest under the same name. The
        // project root's version must win — `isr_safe = true` in
        // project, `false` in install. After loading, the result
        // must reflect the project version.
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        plant_manifest(project.path(), "shared_mod", true);
        plant_manifest(install.path(), "shared_mod", false);

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        let modules = json!([{"name": "shared_mod", "type": "shared_mod"}]);
        let manifests = load_module_manifests_with_extra(&modules, &[]);
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }
        let m = manifests.get("shared_mod").expect("must find shared_mod");
        assert!(
            m.isr_safe,
            "expected project-root manifest (isr_safe=true) to shadow install-root manifest, got isr_safe=false"
        );
    }

    #[test]
    fn extract_module_search_paths_includes_install_root_modules() {
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        // Create a `modules/` dir in install so the returned path
        // canonicalises to an existing location.
        std::fs::create_dir_all(install.path().join("modules")).unwrap();

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        // Place the config inside the project tree so the
        // <config-parent>/../modules default doesn't accidentally
        // land at a path that masks the install/modules entry.
        let cfg_path = project.path().join("cfg/dummy.yaml");
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        let cfg = json!({});
        let paths = extract_module_search_paths(&cfg, &cfg_path);
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }

        let install_modules = install.path().join("modules").canonicalize().unwrap();
        assert!(
            paths.contains(&install_modules),
            "install-root modules dir must appear in the search-paths surface; got {paths:?}"
        );
    }
}
