//! Graph config: building the FXWR config blob from a graph YAML, and
//! decoding a built blob for inspection.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use fluxor_contracts::vocabulary::capability_and_parents;

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;
use crate::manifest::{self, Manifest, TimerClass};
use crate::schema;

/// "FXWR": the magic of the config blob a graph build emits and a booting
/// image carries.
pub const MAGIC_FXWR: u32 = crate::trust_anchors::FXWR_MAGIC;

/// The config format version the builder writes and the kernel accepts.
const FXWR_VERSION: u16 = 1;

const MAX_HW_SPI: usize = 2;
const MAX_HW_I2C: usize = 2;
const MAX_HW_UART: usize = 2;
const MAX_HW_GPIO: usize = 8;
const MAX_HW_PIO: usize = 3;

/// Fixed header: magic u32, version u16, checksum u16, module_count u8,
/// edge_count low byte u8, tick_us u16, graph_sample_rate u32.
const FXWR_HEADER_SIZE: usize = 16;
/// Module-section header: module_count u8, reserved u8, section_size u32.
const FXWR_MODULE_SECTION_HEADER: usize = 6;

/// `len` bytes of `data` at `at`, or an error naming what was cut short.
fn fxwr_slice<'a>(data: &'a [u8], at: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    at.checked_add(len)
        .and_then(|end| data.get(at..end))
        .ok_or_else(|| {
            Error::Config(format!(
                "FXWR config truncated: {what} needs bytes {at}..{} of a {}-byte blob",
                at.saturating_add(len),
                data.len()
            ))
        })
}

fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode one graph edge entry ([`GRAPH_EDGE_SIZE`] bytes; the layout is the
/// encoder's, in `generate.rs`).
fn decode_graph_edge(entry: &[u8]) -> Value {
    let byte2 = entry[2];
    let to_port = (byte2 >> 7) & 1;
    let edge_class = (byte2 >> 5) & 0x03;
    let buffer_group = byte2 & 0x1F;
    let port_byte = entry[3];
    let from_port_index = (port_byte >> 4) & 0x0F;
    let to_port_index = port_byte & 0x0F;
    let buffer_bytes = le_u32(&entry[4..8]);
    let rate_class = entry[8];
    let wake = entry[9] & 0x01 != 0;
    let mut edge = Map::new();
    edge.insert("from_id".into(), json!(entry[0]));
    edge.insert("to_id".into(), json!(entry[1]));
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
            _ => "nic_ring",
        };
        edge.insert("edge_class".into(), json!(ec_name));
    }
    if buffer_bytes != 0 {
        edge.insert("buffer_bytes".into(), json!(buffer_bytes));
    }
    let rate = match rate_class {
        0 => None,
        1 => Some("audio".to_string()),
        2 => Some("video".to_string()),
        3 => Some("bulk".to_string()),
        4 => Some("transaction".to_string()),
        n => Some(format!("unknown({n})")),
    };
    if let Some(rate) = rate {
        edge.insert("rate".into(), json!(rate));
    }
    if wake {
        edge.insert("wake".into(), json!(true));
    }
    Value::Object(edge)
}

/// Decode an FXWR config blob: the header, each module entry (identity and
/// parameter size), the graph's edges and per-domain metadata, and the
/// hardware section's counts. Every read is bounds-checked; a blob cut short
/// is an error naming the section, never a panic.
pub fn decode_config(data: &[u8]) -> Result<Value> {
    let header = fxwr_slice(data, 0, FXWR_HEADER_SIZE, "the header")?;
    let magic = le_u32(&header[0..4]);
    if magic != MAGIC_FXWR {
        return Err(Error::Config(format!(
            "unknown config magic 0x{magic:08x} (expected FXWR)"
        )));
    }
    let version = le_u16(&header[4..6]);
    if version != FXWR_VERSION {
        return Err(Error::Config(format!(
            "FXWR config version {version} is not supported (this build reads version \
             {FXWR_VERSION})"
        )));
    }
    let mut out = Map::new();
    out.insert("version".into(), json!(version));
    out.insert(
        "checksum".into(),
        json!(format!("0x{:04x}", le_u16(&header[6..8]))),
    );
    out.insert("tick_us".into(), json!(le_u16(&header[10..12])));
    out.insert("graph_sample_rate".into(), json!(le_u32(&header[12..16])));

    // Module section.
    let msec = fxwr_slice(
        data,
        FXWR_HEADER_SIZE,
        FXWR_MODULE_SECTION_HEADER,
        "the module section header",
    )?;
    let module_count = msec[0] as usize;
    let section_size = le_u32(&msec[2..6]) as usize;
    let entries_start = FXWR_HEADER_SIZE + FXWR_MODULE_SECTION_HEADER;
    let entries = fxwr_slice(data, entries_start, section_size, "the module section")?;
    let mut modules = Vec::with_capacity(module_count);
    let mut off = 0usize;
    for i in 0..module_count {
        let head = fxwr_slice(
            entries,
            off,
            MODULE_ENTRY_HEADER_SIZE,
            "a module entry header",
        )?;
        let entry_len = le_u32(&head[0..4]) as usize;
        if entry_len < MODULE_ENTRY_HEADER_SIZE || entry_len > entries.len() - off {
            return Err(Error::Config(format!(
                "FXWR module entry {i}: length {entry_len} does not fit its section"
            )));
        }
        let meta = head[9];
        let mut m = Map::new();
        m.insert("id".into(), json!(head[8]));
        m.insert(
            "name_hash".into(),
            json!(format!("0x{:08x}", le_u32(&head[4..8]))),
        );
        m.insert("domain_id".into(), json!(meta & 0x07));
        if meta & 0x10 != 0 {
            m.insert("pre_tick_drain".into(), json!(true));
        }
        m.insert(
            "param_bytes".into(),
            json!(entry_len - MODULE_ENTRY_HEADER_SIZE),
        );
        modules.push(Value::Object(m));
        off += entry_len;
    }
    out.insert("modules".into(), json!(modules));

    // Graph section: edge_count low, flags, edge_count high, slot code; the
    // edge slots; the per-domain metadata.
    let graph_at = entries_start + section_size;
    let ghead = fxwr_slice(data, graph_at, 4, "the graph section header")?;
    let edge_count = ghead[0] as usize | (ghead[2] as usize) << 8;
    if ghead[0] != header[9] {
        return Err(Error::Config(format!(
            "FXWR edge count disagrees: header says {} (low byte), graph section {}",
            header[9], ghead[0]
        )));
    }
    let slots = crate::capacity::edges_for_slots_code(ghead[3]);
    if edge_count > slots {
        return Err(Error::Config(format!(
            "FXWR graph section holds {slots} edge slots but counts {edge_count} edges"
        )));
    }
    out.insert("accept_cycles".into(), json!(ghead[1] & 0x01 != 0));
    out.insert("edge_slots".into(), json!(slots));
    let edge_bytes = fxwr_slice(
        data,
        graph_at + 4,
        edge_count * GRAPH_EDGE_SIZE,
        "the graph edges",
    )?;
    let edges: Vec<Value> = edge_bytes
        .chunks_exact(GRAPH_EDGE_SIZE)
        .map(decode_graph_edge)
        .collect();
    out.insert("graph".into(), json!(edges));
    let domains_at = graph_at + 4 + slots * GRAPH_EDGE_SIZE;
    let dmeta = fxwr_slice(data, domains_at, DOMAIN_META_SIZE, "the domain metadata")?;
    let domains: Vec<Value> = dmeta
        .chunks_exact(DOMAIN_META_ENTRY_SIZE)
        .map(|d| {
            json!({
                "tick_us": le_u16(&d[0..2]),
                "exec_mode": d[2],
                "adaptive_flags": d[3],
            })
        })
        .collect();
    out.insert("domains".into(), json!(domains));

    // Hardware section header: spi, i2c, gpio, pio, reserved, uart counts.
    let hw = fxwr_slice(
        data,
        domains_at + DOMAIN_META_SIZE,
        6,
        "the hardware section header",
    )?;
    out.insert(
        "hardware".into(),
        json!({
            "spi": hw[0],
            "i2c": hw[1],
            "gpio": hw[2],
            "pio": hw[3],
            "uart": hw[5],
        }),
    );
    Ok(Value::Object(out))
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

// ── One flat scope over sibling files ───────────────────────────────────────
// The module's areas live in sibling files pulled in via `include!` (the repo's
// SDK-file convention), so every cross-reference, const and private item
// resolves in a single scope. Each file is one cohesive area.
include!("builder.rs"); // ConfigBuilder + graph-config generation
include!("manifest.rs"); // module search paths + manifest loading
include!("validate.rs"); // presentation-group + continuity validators
include!("placement.rs"); // members composed from another node
include!("generate.rs"); // FXWR encode, ModuleCaps, generate_config_ext
include!("tests.rs"); // #[cfg(test)] suites
