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

// Mirror of `tools/src/manifest.rs::CONTENT_TYPES`. Used here only for
// human-readable rendering when decoding compiled-config dumps. Stays
// positionally identical to the manifest table — content_type IDs are
// the on-wire byte; appending here is safe, reordering is not.
const CONTENT_TYPES: &[&str] = &[
    "OctetStream",
    "Cbor",
    "Json",
    "AudioSample",
    "AudioOpus",
    "AudioMp3",
    "AudioAac",
    "TextPlain",
    "TextHtml",
    "VideoRaster",
    "ImageJpeg",
    "ImagePng",
    "MeshEvent",
    "MeshCommand",
    "MeshState",
    "MeshHandle",
    "InputEvent",
    "GestureMatch",
    "FmpMessage",
    "EthernetFrame",
    "HciMessage",
    "AudioEncoded",
    "VideoEncoded",
    "VideoDraw",
    "VideoScanout",
    "MediaMuxed",
];

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
        .map_or_else(|| format!("Unknown({})", id), |s| s.to_string())
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
            "Unknown config magic: 0x{:08x}",
            magic
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

/// Graph edge size in bytes
const GRAPH_EDGE_SIZE: usize = 4;
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
    eprintln!(
        "warning: module domain '{}' not found in execution.domains, using default",
        domain_name
    );
    0
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
    "domain",
    "sample_rate", // injected by graph_sample_rate
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
                        format!("params.{}", inner_key)
                    } else {
                        format!("{}.{}", key, inner_key)
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
    let dotted = format!("{}.{}", outer, inner);
    out.push(dotted.replace('.', "_"));
    out.push(dotted);
    for suffix in schema::GROUPING_SUFFIXES {
        if let Some(prefix) = outer.strip_suffix(suffix) {
            out.push(format!("{}_{}", prefix, inner));
        }
    }
    out
}

fn format_hint(suggestion: Option<&str>, schema: &schema::ParamSchema) -> String {
    if let Some(s) = suggestion {
        format!(" — did you mean '{}'?", s)
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
fn closest_param_name<'a>(key: &str, schema: &'a schema::ParamSchema) -> Option<&'a str> {
    fn edit_distance(a: &str, b: &str) -> usize {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let m = a.len();
        let n = b.len();
        let mut prev: Vec<usize> = (0..=n).collect();
        let mut curr = vec![0usize; n + 1];
        for i in 1..=m {
            curr[0] = i;
            for j in 1..=n {
                let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
                curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }
        prev[n]
    }
    let threshold = (key.len() / 2).clamp(2, 4);
    let mut best: Option<(&str, usize)> = None;
    for p in &schema.params {
        let d = edit_distance(key, &p.name);
        if d <= threshold && best.is_none_or(|(_, b)| d < b) {
            best = Some((p.name.as_str(), d));
        }
    }
    best.map(|(n, _)| n)
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
                        let hex: String = uuid.iter().map(|b| format!("{:02x}", b)).collect();
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
    entry[2..6].copy_from_slice(&name_hash.to_le_bytes());

    // Module ID (byte 6)
    entry[6] = id;
    // Domain ID (byte 7) — resolved from module's "domain" field against domain_names
    let domain_id = resolve_domain_id(module, config);
    entry[7] = domain_id;

    // Track actual params length used
    let params_len: usize;

    // Some modules accept compound YAML fields that don't map 1:1 to
    // schema params (e.g. `broker: "host:port"` in mqtt). Expand them
    // into the flat fields the schema knows about before packing.
    let normalized_module = expand_compound_yaml_fields(type_name, module, config);
    let module = &normalized_module;

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
                    eprintln!("  cert_file: {} ({} bytes)", cert_path, n);
                }
            }
            Err(e) => eprintln!("  warn: cert_file: could not read '{}': {}", cert_path, e),
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
                    eprintln!("  key_file: {} ({} bytes)", key_path, n);
                }
            }
            Err(e) => eprintln!("  warn: key_file: could not read '{}': {}", key_path, e),
        }
    }

    // Calculate total entry length and write to header
    let entry_len = MODULE_ENTRY_HEADER_SIZE + params_len + extra_len;
    entry[0..2].copy_from_slice(&(entry_len as u16).to_le_bytes());

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

    for (idx, module) in list.iter().enumerate() {
        if idx >= MAX_MODULES {
            return Err(Error::Config(format!(
                "Too many modules: {} > {}",
                idx + 1,
                MAX_MODULES
            )));
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

    if let Some(arr) = config
        .get("module_search_paths")
        .and_then(|v| v.as_array())
    {
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

    paths
}

/// any additional search paths (e.g., relative to the config file).
pub fn load_module_manifests_with_extra(
    modules_config: &Value,
    extra_dirs: &[&std::path::Path],
) -> HashMap<String, Manifest> {
    let mut manifests = HashMap::new();
    // Standard fluxor module directories (relative to CWD = fluxor root).
    // Order mirrors `Manifest::from_source_tree` in `tools/src/manifest.rs`.
    // Built-ins live under `modules/builtin/<platform>/<name>/`.
    let standard: Vec<std::path::PathBuf> = vec![
        "modules/drivers".into(),
        "modules/foundation".into(),
        "modules/app".into(),
        "modules/builtin/linux".into(),
        "modules/builtin/host".into(),
        "modules/builtin/wasm".into(),
        "modules/builtin/qemu".into(),
        "modules".into(),
    ];
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

        // Search standard dirs first
        for dir in &standard {
            let manifest_path = dir.join(type_name).join("manifest.toml");
            if manifest_path.exists() {
                if let Ok(m) = Manifest::from_toml(&manifest_path) {
                    manifests.insert(name.to_string(), m);
                    found = true;
                }
                break;
            }
        }

        // Then search extra dirs (config-relative module paths)
        if !found {
            for extra in extra_dirs {
                let manifest_path = extra.join(type_name).join("manifest.toml");
                if manifest_path.exists() {
                    if let Ok(m) = Manifest::from_toml(&manifest_path) {
                        manifests.insert(name.to_string(), m);
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
        format!(
            "no manifest found for module '{}' (needed to resolve port name '{}')",
            module_name, port_part
        )
    })?;

    let (direction, index, _content_type) =
        manifest.find_port_by_name(port_part).ok_or_else(|| {
            // Build helpful error with available port names
            let available: Vec<&str> = manifest
                .ports
                .iter()
                .filter_map(|p| p.name.as_deref())
                .collect();
            if available.is_empty() {
                format!(
                    "module '{}' has no named ports in its manifest",
                    module_name
                )
            } else {
                format!(
                    "module '{}' has no port named '{}'; available: {}",
                    module_name,
                    port_part,
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
const VIDEO_PROTECTED_CAPS: &[&str] =
    &["display.protected_scanout", "video.protected_decode"];

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
                    "presentation_groups[{}]: required field `id` missing",
                    gi
                ))
            })?
            .to_string();
        if !seen_ids.insert(id.clone()) {
            return Err(Error::Config(format!(
                "presentation_groups: duplicate id `{}`",
                id
            )));
        }

        let clock_authority = g
            .get("clock_authority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{}`: required field `clock_authority` missing",
                    id
                ))
            })?
            .to_string();

        let members_raw = g
            .get("members")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{}`: required field `members` missing",
                    id
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
                "presentation_group `{}`: `members` is empty",
                id
            )));
        }
        for m in &members {
            if !module_names.iter().any(|n| n == m) {
                return Err(Error::Config(format!(
                    "presentation_group `{}`: unknown member `{}`",
                    id, m
                )));
            }
        }
        if !members.iter().any(|m| m == &clock_authority) {
            return Err(Error::Config(format!(
                "presentation_group `{}`: clock_authority `{}` is not in members {:?}",
                id, clock_authority, members
            )));
        }

        let manifest_caps = |name: &str| -> &[String] {
            manifests
                .get(name)
                .map(|m| m.capabilities.as_slice())
                .unwrap_or(&[])
        };
        let has_cap =
            |caps: &[String], wanted: &str| -> bool { caps.iter().any(|c| c == wanted) };
        let has_any_cap = |caps: &[String], wanted: &[&str]| -> bool {
            caps.iter().any(|c| wanted.contains(&c.as_str()))
        };

        if !has_cap(manifest_caps(&clock_authority), "presentation.clock") {
            return Err(Error::Config(format!(
                "presentation_group `{}`: clock_authority `{}` does not declare \
                 capability `presentation.clock` (add it to the module's manifest, \
                 or pick an authority that does)",
                id, clock_authority
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
        if g.get("protected").and_then(|v| v.as_bool()).unwrap_or(false) {
            for m in &members {
                let caps = manifest_caps(m);
                if has_any_cap(caps, AUDIO_SINK_CAPS)
                    && !has_cap(caps, "audio.protected_out")
                {
                    return Err(Error::Config(format!(
                        "presentation_group `{}`: protected=true but audio member \
                         `{}` does not declare `audio.protected_out`",
                        id, m
                    )));
                }
                if has_any_cap(caps, VIDEO_SINK_CAPS)
                    && !has_any_cap(caps, VIDEO_PROTECTED_CAPS)
                {
                    return Err(Error::Config(format!(
                        "presentation_group `{}`: protected=true but video member \
                         `{}` does not declare `display.protected_scanout` or \
                         `video.protected_decode`",
                        id, m
                    )));
                }
            }
        }

        // Multihead: at least two members must be independently bindable
        // paced display outputs.
        if g.get("multihead").and_then(|v| v.as_bool()).unwrap_or(false) {
            let scanout_count = members
                .iter()
                .filter(|m| has_cap(manifest_caps(m), "display.scanout"))
                .count();
            if scanout_count < 2 {
                return Err(Error::Config(format!(
                    "presentation_group `{}`: multihead=true but only {} member(s) \
                     declare `display.scanout` (need ≥2)",
                    id, scanout_count
                )));
            }
        }

        for k in &["latency_budget_ms", "skew_budget_ms"] {
            if let Some(v) = g.get(*k) {
                let n = v.as_u64().ok_or_else(|| {
                    Error::Config(format!(
                        "presentation_group `{}`: `{}` must be an unsigned integer (ms)",
                        id, k
                    ))
                })?;
                if n > MAX_PRESENTATION_BUDGET_MS {
                    return Err(Error::Config(format!(
                        "presentation_group `{}`: `{}` = {} ms exceeds the {} ms \
                         sanity bound (typical lip-sync budgets are ≤ 100 ms)",
                        id, k, n, MAX_PRESENTATION_BUDGET_MS
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
/// to guess.
fn unknown_module_in_wiring(name: &str) -> String {
    let hint = match name {
        "display" => Some("did you forget `platform.display:` in your config?"),
        "audio_out" => Some("did you forget `platform.audio:` in your config?"),
        _ => None,
    };
    match hint {
        Some(h) => format!("Unknown module in wiring: {} ({})", name, h),
        None => format!("Unknown module in wiring: {}", name),
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
            resolve_port_spec(from, true, manifests)
                .map_err(|e| Error::Config(format!("wiring from '{}': {}", from, e)))?;
        let (to_name, to_port_type, to_port_index) = resolve_port_spec(to, false, manifests)
            .map_err(|e| Error::Config(format!("wiring to '{}': {}", to, e)))?;

        // Map destination port type to wire format: in(0)→0, ctrl(2)→1
        let to_port = if to_port_type == 2 { 1u8 } else { 0u8 };

        let from_id = names
            .iter()
            .position(|n| n == from_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(from_name)))?
            as u8;
        let to_id = names
            .iter()
            .position(|n| n == to_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(to_name)))?
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
            &format!("hardware.spi[{}].miso", i),
            max_gpio,
        )?;
        let mosi = validate_gpio_pin(
            spi["mosi"].as_u64().unwrap_or(19),
            &format!("hardware.spi[{}].mosi", i),
            max_gpio,
        )?;
        let sck = validate_gpio_pin(
            spi["sck"].as_u64().unwrap_or(18),
            &format!("hardware.spi[{}].sck", i),
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
            &format!("hardware.i2c[{}].sda", i),
            max_gpio,
        )?;
        let scl = validate_gpio_pin(
            i2c["scl"].as_u64().unwrap_or(5),
            &format!("hardware.i2c[{}].scl", i),
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
            &format!("hardware.uart[{}].tx_pin", i),
            max_gpio,
        )?;
        let rx_pin = validate_gpio_pin(
            uart["rx_pin"].as_u64().unwrap_or(1),
            &format!("hardware.uart[{}].rx_pin", i),
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
            &format!("hardware.gpio[{}].pin", i),
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
                "hardware.pio[{}].pio_idx {} >= target pio_count {}",
                i, pio_idx, pio_count
            )));
        }
        let data_pin = validate_gpio_pin(
            pio["data_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{}].data_pin", i),
            max_gpio,
        )?;
        let clk_pin = validate_gpio_pin(
            pio["clk_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{}].clk_pin", i),
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
) -> Vec<u8> {
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
pub fn generate_config_ext(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
) -> Result<Vec<u8>> {
    generate_config_impl(
        config,
        _template,
        module_caps,
        modules_dir,
        extra_module_dirs,
        max_gpio,
        pio_count,
    )
}

pub fn generate_config_with_caps(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    max_gpio: u8,
    pio_count: u8,
) -> Result<Vec<u8>> {
    generate_config_impl(
        config,
        _template,
        module_caps,
        modules_dir,
        &[],
        max_gpio,
        pio_count,
    )
}

fn generate_config_impl(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
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
    let buffer_groups = assign_buffer_groups(&edges, &module_names, module_caps)?;

    // Resolve per-edge edge_class from wiring entries
    let edge_classes = resolve_edge_classes(config, &module_names, &domain_names);

    // Graph section (64 bytes)
    // Format: edge_count, flags, reserved[2], edges[N]
    // Edge format: from_id, to_id, byte2, port_byte
    //   byte2:     bit 7    = to_port
    //              bits 6:5 = edge_class (2 bits)
    //              bits 4:0 = buffer_group (5 bits, 0..31)
    //   port_byte: bits 7:4 = from_port_index (4 bits, 0..15)
    //              bits 3:0 = to_port_index   (4 bits, 0..15)
    // Both ports get 4 bits; the runtime cap is `MAX_PORTS=16`
    // (`src/kernel/scheduler.rs`). The 5-bit `buffer_group` ceiling
    // (31) is enforced by `assign_buffer_groups`.
    let mut graph_section = Vec::with_capacity(GRAPH_SECTION_SIZE);
    graph_section.push(edges.len() as u8);
    graph_section.extend_from_slice(&[0u8; 3]);
    for (i, (from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let group = buffer_groups.get(i).copied().unwrap_or(0);
        let ec = edge_classes.get(i).copied().unwrap_or(0);
        graph_section.push(*from_id);
        graph_section.push(*to_id);
        graph_section.push((to_port << 7) | ((ec & 0x03) << 5) | (group & 0x1F));
        graph_section.push(((from_port_index & 0x0F) << 4) | (to_port_index & 0x0F));
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
                "services.{}: provider must be a string",
                service_name
            ))
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
