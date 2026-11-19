//! Graph config: building the boot config blob (`FXCF`,
//! `fluxor_contracts::boot_config`) from a graph YAML, and decoding a built
//! blob for inspection.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use fluxor_contracts::boot_config;
use fluxor_contracts::vocabulary::capability_and_parents;

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;
use crate::manifest::{self, Manifest, TimerClass};
use crate::schema;

const MAX_HW_SPI: usize = 2;
const MAX_HW_I2C: usize = 2;
const MAX_HW_UART: usize = 2;
const MAX_HW_GPIO: usize = 8;
const MAX_HW_PIO: usize = 3;

/// A config blob decoded by the one codec the kernel links, or an error
/// naming what the codec refused.
fn decode_blob(data: &[u8]) -> Result<boot_config::BootConfig<'_>> {
    boot_config::decode(data).map_err(|e| Error::Config(format!("boot config refused: {e}")))
}

/// An edge record as `fluxor decode` shows it.
fn edge_json(e: &boot_config::EdgeRecord) -> Value {
    let mut edge = Map::new();
    edge.insert("from_id".into(), json!(e.from));
    edge.insert("to_id".into(), json!(e.to));
    edge.insert(
        "to_port".into(),
        json!(if e.to_ctrl { "ctrl" } else { "in" }),
    );
    if e.buffer_group > 0 {
        edge.insert("buffer_group".into(), json!(e.buffer_group));
    }
    if e.from_port != 0 || e.to_port != 0 {
        edge.insert("from_port_index".into(), json!(e.from_port));
        edge.insert("to_port_index".into(), json!(e.to_port));
    }
    let class = match e.class {
        boot_config::EdgeClass::Local => None,
        boot_config::EdgeClass::DmaOwned => Some("dma_owned"),
        boot_config::EdgeClass::CrossCore => Some("cross_core"),
        boot_config::EdgeClass::NicRing => Some("nic_ring"),
    };
    if let Some(class) = class {
        edge.insert("edge_class".into(), json!(class));
    }
    if e.buffer_bytes != 0 {
        edge.insert("buffer_bytes".into(), json!(e.buffer_bytes));
    }
    let rate = match e.rate_class {
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
    if e.wake_on_write {
        edge.insert("wake".into(), json!(true));
    }
    if e.retains_send {
        edge.insert("retains_send".into(), json!(true));
    }
    Value::Object(edge)
}

/// The module records of a config blob, in slot order: each one's
/// `name_hash` (FNV-1a of its type) and its params TLV.
pub fn module_entries(data: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    let cfg = decode_blob(data)?;
    Ok(cfg
        .graph()
        .modules()
        .map(|m| (m.name_hash, m.params))
        .collect())
}

/// Decode a config blob: the graph's header, each module record (identity
/// and parameter size), its edges and domains, and the counts of the other
/// sections it carries. The blob is read by the codec the kernel boots
/// with, so a blob it decodes is one the kernel accepts as well-formed.
pub fn decode_config(data: &[u8]) -> Result<Value> {
    let cfg = decode_blob(data)?;
    let graph = cfg.graph();
    let mut out = Map::new();
    out.insert("total_len".into(), json!(cfg.total_len()));
    out.insert(
        "checksum".into(),
        json!(format!("0x{:08x}", cfg.checksum())),
    );
    out.insert("tick_us".into(), json!(graph.tick_us));
    out.insert("graph_sample_rate".into(), json!(graph.graph_sample_rate));
    out.insert(
        "accept_cycles".into(),
        json!(graph.graph_flags & boot_config::GRAPH_FLAG_ACCEPT_CYCLES != 0),
    );
    let modules: Vec<Value> = graph
        .modules()
        .map(|m| {
            let mut v = Map::new();
            v.insert("id".into(), json!(m.id));
            v.insert("name_hash".into(), json!(format!("0x{:08x}", m.name_hash)));
            v.insert("domain_id".into(), json!(m.domain));
            if m.pre_pass {
                v.insert("pre_pass".into(), json!(true));
            }
            v.insert("param_bytes".into(), json!(m.params.len()));
            Value::Object(v)
        })
        .collect();
    out.insert("modules".into(), json!(modules));
    let edges: Vec<Value> = graph.edges().map(|e| edge_json(&e)).collect();
    out.insert("graph".into(), json!(edges));
    let domains: Vec<Value> = graph
        .domains()
        .map(|d| {
            json!({
                "tick_us": d.tick_us,
                "tick_min_us": d.tick_min_us,
                "tick_max_us": d.tick_max_us,
                "exec": d.exec_mode.name(),
                "adaptive_flags": d.adaptive_flags,
            })
        })
        .collect();
    out.insert("domains".into(), json!(domains));
    // The RP hardware payload opens with its counts: spi, i2c, gpio, pio,
    // reserved, uart.
    if let Some(hw) = cfg.hardware() {
        let count = |i: usize| hw.get(i).copied().unwrap_or(0);
        out.insert(
            "hardware".into(),
            json!({
                "bytes": hw.len(),
                "spi": count(0),
                "i2c": count(1),
                "gpio": count(2),
                "pio": count(3),
                "uart": count(5),
            }),
        );
    }
    if let Some(w) = cfg.workloads() {
        let list: Vec<Value> = w
            .iter()
            .map(|r| json!({ "idle_safe": r.idle_safe, "blob_bytes": r.blob.len() }))
            .collect();
        out.insert("workloads".into(), json!(list));
    }
    let pools = |p: boot_config::PoolEntries<'_>| -> Value {
        json!(p
            .iter()
            .map(|e| json!({ "pool": e.pool, "n": e.n }))
            .collect::<Vec<_>>())
    };
    if let Some(e) = cfg.envelope() {
        out.insert("envelope".into(), pools(e));
    }
    if let Some(d) = cfg.demand() {
        out.insert("demand".into(), pools(d));
    }
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
include!("generate.rs"); // boot config encode, ModuleCaps, generate_config_ext
include!("tests.rs"); // #[cfg(test)] suites
