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
    "None", "MqttTopic", "SdCard", "SdCardFile", "GpioInput", "Timer",
    "UartRx", "I2cRead", "SpiRead", "SpiFrame", "AdcChannel", "TcpSocket", "Playlist", "TestTone",
];

const SINK_TYPES: &[&str] = &[
    "None", "I2sOutput", "MqttPublish", "GpioOutput", "UartTx", "I2cWrite",
    "SpiWrite", "PwmOutput", "SdCardWrite", "TcpSocket", "Log", "Led",
];

const TRANSFORMER_TYPES: &[&str] = &[
    "None", "AudioFormat", "Resampler", "GpioToMqtt", "MqttToGpio",
    "RawToAudio", "Aggregate", "Split", "Passthrough", "Digest",
];

const CONTENT_TYPES: &[&str] = &[
    "OctetStream", "Cbor", "Json", "AudioPcm", "AudioOpus", "AudioMp3", "AudioAac",
    "TextPlain", "TextHtml", "ImageRaw", "ImageJpeg", "ImagePng",
    "MeshEvent", "MeshCommand", "MeshState", "MeshHandle", "InputEvent", "GestureMatch",
];

const INPUT_CONTROL_TYPES: &[&str] = &["Button", "Range"];

const INPUT_SOURCE_TYPES: &[&str] = &["GpioInput", "AdcChannel", "Touch", "System"];

const GESTURE_PATTERNS: &[&str] = &[
    "Click", "Long", "Double", "Triple", "Hold", "Release", "Change", "CrossUp", "CrossDown",
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
    types.get(id as usize).map_or_else(
        || format!("Unknown({})", id),
        |s| s.to_string(),
    )
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
        result.insert("content_type".into(), json!(get_type_name(CONTENT_TYPES, content_type)));
    }

    let union_data = &entry[4..16];

    match type_id {
        1 => {
            // MqttTopic
            let topic_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
            ]) as u32;
            result.insert("topic".into(), json!(read_string_at(memory, topic_ptr)));
            result.insert("qos".into(), json!(union_data[8]));
        }
        2 => {
            // SdCard
            let start = u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let count = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("start_block".into(), json!(start));
            result.insert("block_count".into(), json!(count));
        }
        3 => {
            // SdCardFile
            let path_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
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
            let interval = u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            result.insert("interval_us".into(), json!(interval));
            result.insert("periodic".into(), json!(union_data[4] != 0));
        }
        6 => {
            // UartRx
            result.insert("uart_id".into(), json!(union_data[0]));
            let baudrate = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
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
            let rate = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("sample_rate".into(), json!(rate));
        }
        11 => {
            // TcpSocket
            let host_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
            ]) as u32;
            let port = u16::from_le_bytes([union_data[8], union_data[9]]);
            result.insert("host".into(), json!(read_string_at(memory, host_ptr)));
            result.insert("port".into(), json!(port));
            result.insert("mode".into(), json!(if union_data[10] != 0 { "server" } else { "client" }));
        }
        12 => {
            // Playlist
            let dir_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
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
            let freq = u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let rate = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
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
        result.insert("content_type".into(), json!(get_type_name(CONTENT_TYPES, content_type)));
    }

    let union_data = &entry[4..16];

    match type_id {
        1 => {
            // I2sOutput
            result.insert("data_pin".into(), json!(union_data[0]));
            result.insert("clock_pin_base".into(), json!(union_data[1]));
            result.insert("bits".into(), json!(union_data[2]));
            let rate = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("sample_rate".into(), json!(rate));
        }
        2 => {
            // MqttPublish
            let topic_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
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
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
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
    result.insert("type".into(), json!(get_type_name(TRANSFORMER_TYPES, type_id)));
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
            let in_rate = u32::from_le_bytes([union_data[0], union_data[1], union_data[2], union_data[3]]);
            let out_rate = u32::from_le_bytes([union_data[4], union_data[5], union_data[6], union_data[7]]);
            result.insert("input_rate".into(), json!(in_rate));
            result.insert("output_rate".into(), json!(out_rate));
        }
        3 => {
            // GpioToMqtt
            let prefix_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
            ]) as u32;
            result.insert("topic_prefix".into(), json!(read_string_at(memory, prefix_ptr)));
            result.insert("json_format".into(), json!(union_data[8] != 0));
            result.insert("include_timestamp".into(), json!(union_data[9] != 0));
        }
        4 => {
            // MqttToGpio
            let filter_ptr = u64::from_le_bytes([
                union_data[0], union_data[1], union_data[2], union_data[3],
                union_data[4], union_data[5], union_data[6], union_data[7],
            ]) as u32;
            result.insert("topic_filter".into(), json!(read_string_at(memory, filter_ptr)));
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
    let buffer_group = byte2 & 0x7F;
    let port_byte = entry[3];
    let from_port_index = (port_byte >> 6) & 0x03;
    let edge_class = (port_byte >> 4) & 0x03;
    let to_port_index = port_byte & 0x0F;
    let mut edge = serde_json::Map::new();
    edge.insert("from_id".into(), json!(from_id));
    edge.insert("to_id".into(), json!(to_id));
    edge.insert("to_port".into(), json!(if to_port == 1 { "ctrl" } else { "in" }));
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
    result.insert("type".into(), json!(get_type_name(INPUT_CONTROL_TYPES, type_id)));
    result.insert("source".into(), json!(get_type_name(INPUT_SOURCE_TYPES, source_type)));

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
    result.insert("pattern".into(), json!(get_type_name(GESTURE_PATTERNS, pattern)));

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
    let _magic = u32::from_le_bytes([header_data[0], header_data[1], header_data[2], header_data[3]]);
    let _total_size = u16::from_le_bytes([header_data[4], header_data[5]]);
    let source_count = header_data[6];
    let sink_count = header_data[7];
    let transformer_count = header_data[8];
    let pipeline_count = header_data[9];
    let object_count = header_data[10];
    let control_count = header_data[11];
    let gesture_count = header_data[12];

    // Pointers (at offset 16)
    let sources_ptr = u32::from_le_bytes([header_data[16], header_data[17], header_data[18], header_data[19]]);
    let sinks_ptr = u32::from_le_bytes([header_data[20], header_data[21], header_data[22], header_data[23]]);
    let transformers_ptr = u32::from_le_bytes([header_data[24], header_data[25], header_data[26], header_data[27]]);
    let pipelines_ptr = u32::from_le_bytes([header_data[28], header_data[29], header_data[30], header_data[31]]);
    let objects_ptr = u32::from_le_bytes([header_data[32], header_data[33], header_data[34], header_data[35]]);
    let _strings_ptr = u32::from_le_bytes([header_data[36], header_data[37], header_data[38], header_data[39]]);

    // Device identity (at offset 48)
    let device_uuid_ptr = u32::from_le_bytes([header_data[48], header_data[49], header_data[50], header_data[51]]);
    let device_name_ptr = u32::from_le_bytes([header_data[52], header_data[53], header_data[54], header_data[55]]);

    // Controls and gestures (at offset 56)
    let controls_ptr = u32::from_le_bytes([header_data[56], header_data[57], header_data[58], header_data[59]]);
    let gestures_ptr = u32::from_le_bytes([header_data[60], header_data[61], header_data[62], header_data[63]]);

    let mut result = Map::new();

    // Device identity
    if device_uuid_ptr != 0 {
        result.insert("device_uuid".into(), json!(read_uuid_at(memory, device_uuid_ptr)));
    }
    if device_name_ptr != 0 {
        result.insert("device_name".into(), json!(read_string_at(memory, device_name_ptr)));
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
    result.insert("format".into(), json!(if version >= 3 { "graph" } else { "legacy" }));
    result.insert("version".into(), json!(version));
    result.insert("source_count".into(), json!(source_count));
    result.insert("sink_count".into(), json!(sink_count));
    result.insert("transformer_count".into(), json!(transformer_count));
    if version >= 3 {
        result.insert("edge_count".into(), json!(count_byte_11));
    } else {
        result.insert("pipeline_count".into(), json!(count_byte_11));
    }
    result.insert("note".into(), json!("FXWR format - detailed decoding available for basic types"));

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
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    let count = u32::from_le_bytes([
                        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                    ]);
                    src.insert("start_block".into(), json!(start));
                    src.insert("block_count".into(), json!(count));
                }
                5 => {
                    // Timer
                    let interval = u32::from_le_bytes([
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
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
                        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
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
            xform.insert("type".into(), json!(get_type_name(TRANSFORMER_TYPES, type_id)));
            xform.insert("id".into(), json!(id));

            match type_id {
                1 => {
                    // AudioFormat: input_rate(4), output_rate(4), input_format(1), output_format(1), gain(2)
                    let in_rate = u32::from_le_bytes([
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    let out_rate = u32::from_le_bytes([
                        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                    ]);
                    let in_fmt = data[offset + 12];
                    let out_fmt = data[offset + 13];
                    let gain = u16::from_le_bytes([data[offset + 14], data[offset + 15]]);
                    xform.insert("input_rate".into(), json!(in_rate));
                    xform.insert("output_rate".into(), json!(out_rate));
                    xform.insert("input_format".into(), json!(if in_fmt == 0 { "u8_mono" } else { "i16_mono" }));
                    xform.insert("output_format".into(), json!(if out_fmt == 0 { "i16_mono" } else { "i16_stereo" }));
                    xform.insert("gain".into(), json!(gain));
                }
                2 => {
                    // Resampler: input_rate(4), output_rate(4)
                    let in_rate = u32::from_le_bytes([
                        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                    ]);
                    let out_rate = u32::from_le_bytes([
                        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
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
        MAGIC_LEGACY => {
            decode_legacy_format(data)
        }
        _ => Err(Error::Config(format!("Unknown config magic: 0x{:08x}", magic))),
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

/// Graph edge size in bytes
const GRAPH_EDGE_SIZE: usize = 4;
/// Maximum number of graph edges
const MAX_GRAPH_EDGES: usize = 15;
/// Per-domain metadata: 4 domains × (tick_us:u16 + exec_mode:u8 + reserved:u8) = 16 bytes
const DOMAIN_META_SIZE: usize = 16;
/// Graph section size (header + edges + domain metadata)
const GRAPH_SECTION_SIZE: usize = 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE + DOMAIN_META_SIZE; // 80 bytes

/// Maximum number of modules
const MAX_MODULES: usize = 16;

/// Module entry header size (entry_length + name_hash + id + reserved)
const MODULE_ENTRY_HEADER_SIZE: usize = 8;

/// Maximum module params size (allows for wavetables, large sequences, etc.)
const MAX_MODULE_PARAMS_SIZE: usize = 16384;

/// Param base offset within a module entry (= header size = 8)
const P: usize = MODULE_ENTRY_HEADER_SIZE;

/// Parse a waveform string into its numeric ID.
/// Used by synth, monosynth, and other oscillator-based modules.
/// Parse UUID string (with or without dashes) to 16 bytes. Returns [0; 16] on error.
fn parse_uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = [0u8; 16];
    if hex.len() != 32 { return out; }
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap_or(0);
    }
    out
}

/// Parse IPv4 address string to u32 (network byte order).
fn parse_ipv4(s: &str) -> u32 {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return 0; }
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
    let port = parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(1883);
    (ip, port)
}

fn build_mqtt_params(module: &Value, entry: &mut [u8], config: &Value) -> usize {
    // mqtt params layout:
    // [0-3]     broker_ip: u32
    // [4-5]     broker_port: u16 (default 1883)
    // [6]       keepalive_s: u8 (default 60)
    // [7]       client_id_len: u8
    // [8-39]    client_id: [u8; 32]
    // [40]      subscribe_topic_len: u8
    // [41]      publish_topic_len: u8
    // [42-43]   reserved
    // [44-139]  subscribe_topic: [u8; 96]
    // [140-235] publish_topic_prefix: [u8; 96]

    // Broker address
    let (broker_ip, broker_port) = if let Some(s) = module["broker"].as_str() {
        parse_broker_addr(s)
    } else {
        let ip = module["broker_ip"].as_str().map(parse_ipv4).unwrap_or(0);
        let port = module["broker_port"].as_u64().unwrap_or(1883) as u16;
        (ip, port)
    };

    let keepalive = module["keepalive"].as_u64().unwrap_or(60) as u8;
    let client_id = module["client_id"].as_str().unwrap_or("");
    let cid_bytes = client_id.as_bytes();
    let cid_len = cid_bytes.len().min(32);

    entry[P..P+4].copy_from_slice(&broker_ip.to_le_bytes());
    entry[P+4..P+6].copy_from_slice(&broker_port.to_le_bytes());
    entry[P+6] = keepalive;
    entry[P+7] = cid_len as u8;

    for (i, &b) in cid_bytes.iter().take(cid_len).enumerate() {
        entry[P+8+i] = b;
    }

    // Build subscribe and publish topics from device_uuid + object UUIDs
    // Subscribe: "fluxor/{device_hex}/objects/+/commands"
    // Publish prefix is not stored — mesh_bridge provides full topic per message
    let device_uuid_str = config.get("device_uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let device_uuid = parse_uuid_bytes(device_uuid_str);
    let device_hex: String = device_uuid.iter().map(|b| format!("{:02x}", b)).collect();

    // Subscribe topic: "fluxor/{device_hex}/objects/+/commands"
    let sub_topic = if !device_hex.is_empty() && device_uuid != [0u8; 16] {
        format!("fluxor/{}/objects/+/commands", device_hex)
    } else if let Some(t) = module["subscribe_topic"].as_str() {
        t.to_string()
    } else {
        String::new()
    };

    let sub_bytes = sub_topic.as_bytes();
    let sub_len = sub_bytes.len().min(96);
    entry[P+40] = sub_len as u8;
    entry[P+41] = 0; // publish_topic_len (unused — mesh_bridge provides topics)

    for (i, &b) in sub_bytes.iter().take(sub_len).enumerate() {
        entry[P+44+i] = b;
    }

    236 // fixed param size
}

fn build_mesh_bridge_params(module: &Value, entry: &mut [u8], config: &Value) -> usize {
    // mesh_bridge params layout:
    // [0-15]  device_uuid: [u8; 16]
    // [16]    object_count: u8
    // [17-19] reserved
    // Per object (24 bytes each, starting at offset 20):
    //   [0-15]  object_uuid: [u8; 16]
    //   [16]    control_id: u8
    //   [17]    ctrl_port_index: u8
    //   [18-23] reserved

    let device_uuid_str = config.get("device_uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let device_uuid = parse_uuid_bytes(device_uuid_str);
    entry[P..P+16].copy_from_slice(&device_uuid);

    let objects = module["objects"].as_array();
    let obj_count = objects.map(|a| a.len().min(4)).unwrap_or(0);
    entry[P+16] = obj_count as u8;

    if let Some(objs) = objects {
        for (i, obj) in objs.iter().take(4).enumerate() {
            let offset = P + 20 + i * 24;
            let uuid_str = obj["uuid"].as_str().unwrap_or("");
            let uuid_bytes = parse_uuid_bytes(uuid_str);
            entry[offset..offset+16].copy_from_slice(&uuid_bytes);
            entry[offset+16] = obj["control_id"].as_u64().unwrap_or(0) as u8;
            entry[offset+17] = obj["ctrl_port_index"].as_u64().unwrap_or(0) as u8;
        }
    }

    20 + obj_count * 24 // variable size
}

/// Build a variable-length module entry from config.
///
/// Binary format (variable length):
/// Resolve a module's domain assignment to a numeric domain ID.
///
/// Looks up the module's `domain` field (string) in the `execution.domains` list.
/// Returns 0 (default domain) if no domain is specified or the name is not found.
fn resolve_domain_id(module: &Value, config: &Value) -> u8 {
    let domain_name = match module.get("domain").and_then(|d| d.as_str()) {
        Some(name) => name,
        None => return 0,
    };

    // Look up in execution.domains list
    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            for (i, domain) in domains.iter().enumerate() {
                if let Some(name) = domain.get("name").and_then(|n| n.as_str()) {
                    if name == domain_name {
                        return i as u8;
                    }
                }
            }
        }
    }

    // Domain name not found in config — treat as domain 0 with a warning
    eprintln!("warning: module domain '{}' not found in execution.domains, using default", domain_name);
    0
}

/// - Bytes 0-1: entry_length (u16) - total size including header
/// - Bytes 2-5: name_hash (fnv1a32)
/// - Byte 6: id
/// - Byte 7: domain_id
/// - Bytes 8+: params (variable, module-specific)
fn build_module_entry(name: &str, module: &Value, id: u8, data_section: Option<&Value>, config: &Value, modules_dir: &Path) -> Result<Vec<u8>> {
    // Start with max possible size, will truncate to actual used size
    let mut entry = vec![0u8; MODULE_ENTRY_HEADER_SIZE + MAX_MODULE_PARAMS_SIZE];

    // Leave bytes 0-1 for entry_length (filled at end)

    // Module type: explicit "type" field or falls back to "name"
    let type_name = module["type"].as_str().unwrap_or(name);

    // Name hash (bytes 2-5) — hash the type name so the kernel can find the .fmod.
    // This allows multiple instances: name: seq_kick, type: sequencer
    let name_hash = fnv1a_hash(type_name.as_bytes());
    entry[2..6].copy_from_slice(&name_hash.to_le_bytes());

    // Module ID (byte 6)
    entry[6] = id;
    // Domain ID (byte 7) — resolved from module's "domain" field against domain_names
    let domain_id = resolve_domain_id(module, config);
    entry[7] = domain_id;

    // Track actual params length used
    let params_len: usize;

    // Try schema-first: load .fmod schema and use generic packer
    if let Some(param_schema) = schema::load_schema_for_module(type_name, modules_dir) {
        params_len = schema::build_params_from_schema(module, &param_schema, &mut entry, P, data_section, type_name)
            .map_err(|e| Error::Config(e))?;
    } else {
        // Legacy fallback — module-specific builders (removed once all modules have schemas)
        params_len = build_legacy_params(type_name, module, &mut entry, data_section, config);
    }

    // Append protection/fault policy params as reserved TLV tags (0xF0-0xF3).
    // These are parsed by the kernel scheduler during instantiation.
    let mut extra_len = 0usize;
    let base = MODULE_ENTRY_HEADER_SIZE + params_len;

    // Tag 0xF0: step_deadline_us (u32, 4 bytes)
    if let Some(deadline) = module.get("step_deadline_us").and_then(|v| v.as_u64()) {
        if base + extra_len + 6 < entry.len() {
            entry[base + extra_len] = 0xF0;
            entry[base + extra_len + 1] = 4;
            let bytes = (deadline as u32).to_le_bytes();
            entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&bytes);
            extra_len += 6;
        }
    }

    // Tag 0xF1: fault_policy (u8: 0=skip, 1=restart, 2=restart_graph)
    if let Some(policy_str) = module.get("fault_policy").and_then(|v| v.as_str()) {
        let policy_val: u8 = match policy_str {
            "skip" => 0,
            "restart" => 1,
            "restart_graph" => 2,
            _ => 0,
        };
        if base + extra_len + 3 < entry.len() {
            entry[base + extra_len] = 0xF1;
            entry[base + extra_len + 1] = 1;
            entry[base + extra_len + 2] = policy_val;
            extra_len += 3;
        }
    }

    // Tag 0xF2: max_restarts (u16, 2 bytes)
    if let Some(max_r) = module.get("max_restarts").and_then(|v| v.as_u64()) {
        if base + extra_len + 4 < entry.len() {
            entry[base + extra_len] = 0xF2;
            entry[base + extra_len + 1] = 2;
            let bytes = (max_r as u16).to_le_bytes();
            entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
            extra_len += 4;
        }
    }

    // Tag 0xF3: restart_backoff_ms (u16, 2 bytes)
    if let Some(backoff) = module.get("restart_backoff_ms").and_then(|v| v.as_u64()) {
        if base + extra_len + 4 < entry.len() {
            entry[base + extra_len] = 0xF3;
            entry[base + extra_len + 1] = 2;
            let bytes = (backoff as u16).to_le_bytes();
            entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
            extra_len += 4;
        }
    }

    // Calculate total entry length and write to header
    let entry_len = MODULE_ENTRY_HEADER_SIZE + params_len + extra_len;
    entry[0..2].copy_from_slice(&(entry_len as u16).to_le_bytes());

    // Truncate to actual size
    entry.truncate(entry_len);

    Ok(entry)
}

/// Legacy module-specific param builders. Used as fallback when no schema is available.
fn build_legacy_params(type_name: &str, module: &Value, entry: &mut Vec<u8>, _data_section: Option<&Value>, config: &Value) -> usize {
    match type_name.to_lowercase().as_str() {
        // Most modules use embedded .fmod schemas (build_params_from_schema).
        // Only modules with complex param formats that can't be expressed as
        // simple TLV schemas need legacy builders here.
        "mqtt" => build_mqtt_params(module, entry, config),
        "mesh_bridge" => build_mesh_bridge_params(module, entry, config),
        _ => 0,
    }
}

fn parse_modules_map(modules: &Value, data_section: Option<&Value>, config: &Value, modules_dir: &Path) -> Result<(Vec<Vec<u8>>, Vec<String>)> {
    let mut entries = Vec::new();
    let mut names = Vec::new();

    let list = modules.as_array().ok_or_else(|| {
        Error::Config("modules must be a list of module configs (each with a 'name' field)".into())
    })?;

    for (idx, module) in list.iter().enumerate() {
        if idx >= MAX_MODULES {
            return Err(Error::Config(format!("Too many modules: {} > {}", idx + 1, MAX_MODULES)));
        }
        let name = module["name"].as_str().ok_or_else(|| {
            Error::Config(format!("Module at index {} missing 'name' field", idx))
        })?;
        let id = idx as u8;
        let entry = build_module_entry(name, module, id, data_section, config, modules_dir)?;
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
fn load_module_manifests(modules_config: &Value) -> HashMap<String, Manifest> {
    let mut manifests = HashMap::new();
    let source_dir = std::path::Path::new("modules");
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
        let manifest_path = source_dir.join(type_name).join("manifest.toml");
        if manifest_path.exists() {
            if let Ok(m) = Manifest::from_toml(&manifest_path) {
                manifests.insert(name.to_string(), m);
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
) -> std::result::Result<(&'a str, u8, u8), String> {
    let parts: Vec<&str> = spec.split('.').collect();
    let module_name = parts.first().unwrap_or(&spec).trim();

    if parts.len() < 2 {
        // Bare module name — default to out[0] for "from:", in[0] for "to:"
        let port_type = if context_is_from { 1 } else { 0 };
        return Ok((module_name, port_type, 0));
    }

    let port_part = parts[1].trim();

    // Named port — look up in manifest
    let manifest = manifests.get(module_name).ok_or_else(|| {
        format!("no manifest found for module '{}' (needed to resolve port name '{}')", module_name, port_part)
    })?;

    let (direction, index, _content_type) = manifest.find_port_by_name(port_part).ok_or_else(|| {
        // Build helpful error with available port names
        let available: Vec<&str> = manifest.ports.iter()
            .filter_map(|p| p.name.as_deref())
            .collect();
        if available.is_empty() {
            format!("module '{}' has no named ports in its manifest", module_name)
        } else {
            format!("module '{}' has no port named '{}'; available: {}", module_name, port_part, available.join(", "))
        }
    })?;

    // Validate direction matches context
    if context_is_from && direction != 1 && direction != 3 {
        return Err(format!(
            "port '{}.{}' is {} but used in 'from:' (must be output or ctrl_output)",
            module_name, port_part, manifest::direction_to_str(direction)
        ));
    }
    if !context_is_from && direction == 1 {
        return Err(format!(
            "port '{}.{}' is output but used in 'to:' (must be input or ctrl)",
            module_name, port_part
        ));
    }

    Ok((module_name, direction, index))
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

    for (i, &(from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        if force_flags.get(i).copied().unwrap_or(false) {
            continue;
        }

        let from_name = &module_names[from_id as usize];
        let to_name = &module_names[to_id as usize];

        // Look up content types from manifests
        let from_ct = manifests.get(from_name)
            .and_then(|m| m.find_port(1, from_port_index)); // direction=1 (output)
        let to_direction = if to_port == 1 { 2u8 } else { 0u8 }; // ctrl=2, in=0
        let to_ct = manifests.get(to_name)
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

/// Parse wiring edges from YAML config.
/// Returns Vec of (from_id, to_id, to_port, from_port_index, to_port_index).
/// to_port: 0 = data input, 1 = control input.
/// Supports indexed port syntax: "bank.out[1]" → from_port_index=1
/// Supports named port syntax: "voip.rtp" → resolves via manifest
fn parse_wiring_edges(wiring: &Value, names: &[String], manifests: &HashMap<String, Manifest>) -> Result<(Vec<(u8, u8, u8, u8, u8)>, Vec<bool>, Vec<String>, Vec<String>)> {
    let list = wiring.as_array().ok_or_else(|| {
        Error::Config("wiring must be a list".into())
    })?;

    let mut edges = Vec::new();
    let mut force_flags = Vec::new();
    let mut from_specs = Vec::new();
    let mut to_specs = Vec::new();

    for w in list {
        let from = w["from"].as_str().unwrap_or("");
        let to = w["to"].as_str().unwrap_or("");
        let force = w["force"].as_bool().unwrap_or(false);

        let (from_name, _from_port_type, from_port_index) = resolve_port_spec(from, true, manifests)
            .map_err(|e| Error::Config(format!("wiring from '{}': {}", from, e)))?;
        let (to_name, to_port_type, to_port_index) = resolve_port_spec(to, false, manifests)
            .map_err(|e| Error::Config(format!("wiring to '{}': {}", to, e)))?;

        // Map destination port type to wire format: in(0)→0, ctrl(2)→1
        let to_port = if to_port_type == 2 { 1u8 } else { 0u8 };

        let from_id = names.iter().position(|n| n == from_name)
            .ok_or_else(|| Error::Config(format!("Unknown module in wiring: {}", from_name)))? as u8;
        let to_id = names.iter().position(|n| n == to_name)
            .ok_or_else(|| Error::Config(format!("Unknown module in wiring: {}", to_name)))? as u8;

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
            "{}: GPIO pin {} out of range (0-{})", context, pin, max_gpio - 1
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
fn build_hardware_section(hardware: &Value, module_names: &[String], max_gpio: u8, pio_count: u8) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    let spi_configs = hardware["spi"].as_array().map(|a| a.to_vec()).unwrap_or_default();
    let i2c_configs = hardware["i2c"].as_array().map(|a| a.to_vec()).unwrap_or_default();
    let uart_configs = hardware["uart"].as_array().map(|a| a.to_vec()).unwrap_or_default();
    let gpio_configs = hardware["gpio"].as_array().map(|a| a.to_vec()).unwrap_or_default();
    let pio_configs = hardware["pio"].as_array().map(|a| a.to_vec()).unwrap_or_default();

    if spi_configs.len() > MAX_HW_SPI {
        return Err(Error::Config(format!("Too many SPI configs: {} > {}", spi_configs.len(), MAX_HW_SPI)));
    }
    if i2c_configs.len() > MAX_HW_I2C {
        return Err(Error::Config(format!("Too many I2C configs: {} > {}", i2c_configs.len(), MAX_HW_I2C)));
    }
    if uart_configs.len() > MAX_HW_UART {
        return Err(Error::Config(format!("Too many UART configs: {} > {}", uart_configs.len(), MAX_HW_UART)));
    }
    if gpio_configs.len() > MAX_HW_GPIO {
        return Err(Error::Config(format!("Too many GPIO configs: {} > {}", gpio_configs.len(), MAX_HW_GPIO)));
    }
    if pio_configs.len() > MAX_HW_PIO {
        return Err(Error::Config(format!("Too many PIO configs: {} > {}", pio_configs.len(), MAX_HW_PIO)));
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
        let miso = validate_gpio_pin(spi["miso"].as_u64().unwrap_or(16), &format!("hardware.spi[{}].miso", i), max_gpio)?;
        let mosi = validate_gpio_pin(spi["mosi"].as_u64().unwrap_or(19), &format!("hardware.spi[{}].mosi", i), max_gpio)?;
        let sck = validate_gpio_pin(spi["sck"].as_u64().unwrap_or(18), &format!("hardware.spi[{}].sck", i), max_gpio)?;
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
        let sda = validate_gpio_pin(i2c["sda"].as_u64().unwrap_or(4), &format!("hardware.i2c[{}].sda", i), max_gpio)?;
        let scl = validate_gpio_pin(i2c["scl"].as_u64().unwrap_or(5), &format!("hardware.i2c[{}].scl", i), max_gpio)?;
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
        let tx_pin = validate_gpio_pin(uart["tx_pin"].as_u64().unwrap_or(0), &format!("hardware.uart[{}].tx_pin", i), max_gpio)?;
        let rx_pin = validate_gpio_pin(uart["rx_pin"].as_u64().unwrap_or(1), &format!("hardware.uart[{}].rx_pin", i), max_gpio)?;
        let baudrate = uart["baudrate"].as_u64().unwrap_or(115200) as u32;

        result.push(bus);
        result.push(tx_pin);
        result.push(rx_pin);
        result.push(0); // reserved
        result.extend_from_slice(&baudrate.to_le_bytes());
    }

    // GPIO configs (5 bytes each): pin, flags, initial, owner_module_id, reserved
    for (i, gpio) in gpio_configs.iter().enumerate() {
        let pin = validate_gpio_pin(gpio["pin"].as_u64().unwrap_or(0), &format!("hardware.gpio[{}].pin", i), max_gpio)?;

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
                    if n == 0 { 0u8 } else { 1u8 }
                } else if let Some(b) = gpio["initial"].as_bool() {
                    if b { 1u8 } else { 0u8 }
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
                        "hardware.gpio[{}].owner: unknown module '{}'",
                        i, owner_name
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
                "hardware.pio[{}].pio_idx {} >= target pio_count {}", i, pio_idx, pio_count
            )));
        }
        let data_pin = validate_gpio_pin(pio["data_pin"].as_u64().unwrap_or(0), &format!("hardware.pio[{}].data_pin", i), max_gpio)?;
        let clk_pin = validate_gpio_pin(pio["clk_pin"].as_u64().unwrap_or(0), &format!("hardware.pio[{}].clk_pin", i), max_gpio)?;
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
fn resolve_edge_classes(config: &Value, _module_names: &[String], domain_names: &[String]) -> Vec<u8> {
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Vec::new(),
    };

    let mut classes = Vec::with_capacity(wiring.len());

    // Build module_name → domain_id lookup
    let modules_list = config.get("modules").and_then(|m| m.as_array());
    let mut module_domain: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    if let Some(mods) = modules_list {
        for m in mods {
            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                let domain = resolve_domain_id(m, config);
                module_domain.insert(name.to_string(), domain);
            }
        }
    }

    for (i, entry) in wiring.iter().enumerate() {
        let ec_str = entry.get("edge_class").and_then(|v| v.as_str()).unwrap_or("local");
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
                        eprintln!("warning: wiring[{}] edge_class=cross_core but '{}' and '{}' are in same domain {}",
                            i, from_mod, to_mod, from_d);
                    }
                }
                2u8
            }
            "nic_ring" => 3u8,
            _ => 0u8, // "local" or unknown
        };
        classes.push(ec);
    }

    classes
}

/// Generate binary config in FXWR format (version 1)
///
/// Layout:
/// - Header (8 bytes): magic (u32), version (u16), checksum (u16)
/// - Counts (8 bytes): module_count, edge_count, reserved[6]
/// - Module section header (4 bytes): module_count, reserved, section_size (u16)
/// - Module entries (variable length each)
/// - Graph section (64 bytes): edge_count, flags, reserved[2], edges[15]
/// - Hardware section: spi_count, i2c_count, gpio_count, reserved, configs...
/// Module capability info for buffer aliasing and manifest validation.
pub struct ModuleCaps {
    pub name: String,
    /// Can safely consume from mailbox channels (header flags bit 0)
    pub mailbox_safe: bool,
    /// Uses buffer_acquire_inplace to modify buffer (header flags bit 1)
    pub in_place_writer: bool,
    pub manifest: crate::manifest::Manifest,
}

pub fn generate_config(config: &Value, _template: &ConfigBuilder, modules_dir: &Path, max_gpio: u8, pio_count: u8) -> Result<Vec<u8>> {
    generate_config_with_caps(config, _template, &[], modules_dir, max_gpio, pio_count)
}

pub fn generate_config_with_caps(config: &Value, _template: &ConfigBuilder, module_caps: &[ModuleCaps], modules_dir: &Path, max_gpio: u8, pio_count: u8) -> Result<Vec<u8>> {
    let modules = config.get("modules").ok_or_else(|| {
        Error::Config("modules section required".into())
    })?;

    // Parse graph-level sample_rate (top-level or under graph: key)
    let graph_sample_rate: u32 = config.get("sample_rate")
        .or_else(|| config.get("graph").and_then(|g| g.get("sample_rate")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // Parse tick_us (top-level or under execution:)
    let tick_us: u16 = config.get("tick_us")
        .or_else(|| config.get("execution").and_then(|e| e.get("tick_us")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    // Validate tick_us range
    if tick_us > 0 && (tick_us < 100 || tick_us > 50000) {
        return Err(Error::Config(format!(
            "tick_us {} out of range (valid: 100-50000, or 0 for default 1000)",
            tick_us
        )));
    }

    // Parse execution.domains
    let mut domain_names: Vec<String> = Vec::new();
    let mut domain_tick_us: Vec<u16> = Vec::new();
    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            for domain in domains {
                let name = domain.get("name").and_then(|n| n.as_str()).unwrap_or("default");
                domain_names.push(name.to_string());
                let dtick = domain.get("tick_us").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                domain_tick_us.push(dtick);
            }
        }
    }
    // Domain count is inferred by the kernel from module domain_id assignments.
    // domain_names is still used for edge_class validation below.

    // Warn if tick_us < 500 with many modules
    let module_list = modules.as_array().ok_or_else(|| Error::Config("modules must be a list".into()))?;
    if tick_us > 0 && tick_us < 500 && module_list.len() > 8 {
        eprintln!("warning: tick_us={} with {} modules may exceed tick budget", tick_us, module_list.len());
    }

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

    let (module_entries, module_names) = parse_modules_map(modules_ref, data_section, config, modules_dir)?;

    // Load manifests for named port resolution and type validation
    let manifests = load_module_manifests(modules_ref);

    let (edges, force_flags, from_specs, to_specs) = if config.get("wiring").is_some() {
        parse_wiring_edges(&config["wiring"], &module_names, &manifests)?
    } else {
        return Err(Error::Config("wiring section required".into()));
    };

    // Validate content-type compatibility
    validate_wiring_types(&edges, &force_flags, &module_names, &manifests, &from_specs, &to_specs)?;

    if edges.len() > MAX_GRAPH_EDGES {
        return Err(Error::Config(format!(
            "Too many graph edges: {} > {}",
            edges.len(),
            MAX_GRAPH_EDGES
        )));
    }

    // Validate per-module port indices against MAX_PORTS.
    // The kernel's populate_ports() enforces this at runtime, but catching
    // it here gives a clear build-time error instead of a cryptic boot failure.
    const MAX_PORTS: u8 = 4;
    for &(from_id, to_id, _to_port, from_port_index, to_port_index) in &edges {
        if from_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' output port index {} exceeds limit (max {})",
                module_names[from_id as usize], from_port_index, MAX_PORTS - 1
            )));
        }
        if to_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' input port index {} exceeds limit (max {})",
                module_names[to_id as usize], to_port_index, MAX_PORTS - 1
            )));
        }
    }

    // Version 1 (variable-length module entries)
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

    // Module section header (4 bytes)
    result.push(module_entries.len() as u8); // module_count
    result.push(0); // reserved
    result.extend_from_slice(&(module_section_size as u16).to_le_bytes()); // section_size

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

    // Assign buffer groups for aliasable edge chains
    let buffer_groups = assign_buffer_groups(&edges, &module_names, module_caps);

    // Resolve per-edge edge_class from wiring entries
    let edge_classes = resolve_edge_classes(config, &module_names, &domain_names);

    // Graph section (64 bytes)
    // Format: edge_count, flags, reserved[2], edges[N]
    // Edge format: from_id, to_id, byte2, port_byte
    //   byte2: (to_port << 7) | (buffer_group & 0x7F)
    //   port_byte: (from_port_index << 6) | (edge_class << 4) | to_port_index
    let mut graph_section = Vec::with_capacity(GRAPH_SECTION_SIZE);
    graph_section.push(edges.len() as u8);
    graph_section.extend_from_slice(&[0u8; 3]);
    for (i, (from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let group = buffer_groups.get(i).copied().unwrap_or(0);
        let ec = edge_classes.get(i).copied().unwrap_or(0);
        graph_section.push(*from_id);
        graph_section.push(*to_id);
        graph_section.push((to_port << 7) | (group & 0x7F));
        graph_section.push((from_port_index << 6) | ((ec & 0x03) << 4) | (to_port_index & 0x0F));
    }
    // Pad edge entries to fixed offset, then write domain metadata
    while graph_section.len() < 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE {
        graph_section.push(0);
    }
    // Domain metadata: 4 entries × (tick_us:u16 LE + exec_mode:u8 + reserved:u8) = 16 bytes
    for d in 0..4usize {
        let dtick = domain_tick_us.get(d).copied().unwrap_or(0);
        graph_section.extend_from_slice(&dtick.to_le_bytes());
        let mode = if let Some(domains) = config.get("execution").and_then(|e| e.get("domains")).and_then(|d| d.as_array()) {
            domains.get(d)
                .and_then(|dom| dom.get("exec_mode").and_then(|m| m.as_str()))
                .map(|m| match m {
                    "high_rate" | "tier1a" => 1u8,
                    "poll" | "tier3" => 3u8,
                    _ => 0u8,
                })
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
    let hw_section = build_hardware_section(&config["hardware"], &module_names, max_gpio, pio_count)?;
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
) -> Vec<u8> {
    let n = edges.len();
    let mut groups = vec![0u8; n];

    // If no module caps provided, no aliasing possible
    if module_caps.is_empty() {
        return groups;
    }

    // Build lookups: module_name -> capability flags
    let is_chain_interior_capable = |module_id: u8| -> bool {
        let id = module_id as usize;
        if id >= module_names.len() { return false; }
        let name = &module_names[id];
        // Chain interior requires BOTH: can consume mailbox AND modifies in-place
        module_caps.iter().any(|c| &c.name == name && c.mailbox_safe && c.in_place_writer)
    };

    // Count data edges per module (only data edges, to_port == 0)
    let num_modules = module_names.len();
    let mut data_in_count = vec![0u8; num_modules];
    let mut data_out_count = vec![0u8; num_modules];
    for (_, to_id, to_port, _, _) in edges {
        if *to_port == 0 {
            let idx = *to_id as usize;
            if idx < num_modules { data_in_count[idx] += 1; }
        }
        // All edges have an implicit "from out" so count from_id outputs
    }
    for (from_id, _, _, _, _) in edges {
        let idx = *from_id as usize;
        if idx < num_modules { data_out_count[idx] += 1; }
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
        edges.iter().position(|(from_id, _, _, _, _)| *from_id == module_id)
    };

    let mut next_group: u8 = 1;

    // For each edge, if destination is a chain-interior module, try to form/extend a chain
    for i in 0..n {
        let (_, to_id, to_port, _, _) = edges[i];
        // Only consider data edges
        if to_port != 0 { continue; }
        // Destination must be in-place-safe with 1-in/1-out
        if !is_chain_interior(to_id) { continue; }

        // This edge feeds an in-place module. Find the output edge from that module.
        if let Some(out_idx) = find_out_edge(to_id) {
            // Both edges (in to this module, out from this module) should share a group
            let existing_group = if groups[i] != 0 {
                groups[i]
            } else if groups[out_idx] != 0 {
                groups[out_idx]
            } else {
                let g = next_group;
                if next_group < 127 { next_group += 1; }
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
            if groups[i] == 0 { continue; }
            let (_, to_id, to_port, _, _) = edges[i];
            if to_port != 0 { continue; }
            if !is_chain_interior(to_id) { continue; }
            if let Some(out_idx) = find_out_edge(to_id) {
                if groups[out_idx] != groups[i] {
                    groups[out_idx] = groups[i];
                    changed = true;
                }
            }
        }
    }

    groups
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
                "FNV-1a hash collision: '{}' and '{}' both hash to 0x{:08x}",
                existing, name, h,
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

    // Check exclusive resource conflicts (instance-aware)
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
        None => return Err(Error::Config("services must be a mapping of service_name: provider_module".into())),
    };

    for (service_name, provider_val) in services_map {
        let provider = provider_val.as_str().ok_or_else(|| {
            Error::Config(format!("services.{}: provider must be a string", service_name))
        })?;

        // Check provider module exists in config
        // Module names come from either name or type field — check by type too
        let provider_found = module_names.iter().any(|n| n == provider);
        if !provider_found {
            return Err(Error::Config(format!(
                "services.{}: provider module '{}' not found in config modules",
                service_name, provider,
            )));
        }

        // Check provider's manifest declares this service
        if let Some(manifest) = manifests.get(provider) {
            if !manifest.provides.iter().any(|p| p == service_name) {
                return Err(Error::Config(format!(
                    "services.{}: module '{}' does not declare 'provides = [\"{}\"]' in its manifest",
                    service_name, provider, service_name,
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

    m.insert("blinky", json!({
        "modules": {
            "timer": {"type": "timer", "interval_us": 1000000, "periodic": true},
            "led": {"type": "led", "initial": 0}
        },
        "wiring": [
            {"from": "timer.out", "to": "led.in"}
        ]
    }));

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

    m.insert("button-led", json!({
        "modules": {
            "button": {"type": "button", "pin": 15, "pull": "up", "active_low": 1},
            "led": {"type": "led", "initial": 0}
        },
        "wiring": [
            {"from": "button.out", "to": "led.in"}
        ]
    }));

    m.insert("button-bootsel", json!({
        "modules": {
            "button": {"type": "button"},
            "led": {"type": "led", "initial": 0}
        },
        "wiring": [
            {"from": "button.out", "to": "led.in"}
        ]
    }));

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
