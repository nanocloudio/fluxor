//! `fluxor monitor` — host-side telemetry viewer.
//!
//! Parses the newline-framed `MON_FAULT` / `MON_HIST` / `MON_STATE` text
//! protocol (see `docs/architecture/monitor-protocol.md`) and renders a
//! periodically-refreshed per-module dashboard.
//!
//! The serial device is opened as a plain file; baud and termios
//! configuration are left to the caller (for example:
//! `stty -F /dev/ttyACM0 115200 raw -echo`). Keeping the tool free of a
//! `serialport` dependency matters for cross-host portability of the
//! config toolchain.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

// Fault type codes (must match src/kernel/step_guard.rs::fault_type).
const FAULT_NONE: u8 = 0;
const FAULT_TIMEOUT: u8 = 1;
const FAULT_STEP_ERROR: u8 = 2;
const FAULT_HARD: u8 = 3;
const FAULT_MPU: u8 = 4;

fn fault_kind_str(k: u8) -> &'static str {
    match k {
        FAULT_NONE => "-",
        FAULT_TIMEOUT => "timeout",
        FAULT_STEP_ERROR => "step_err",
        FAULT_HARD => "hard",
        FAULT_MPU => "mpu",
        _ => "?",
    }
}

#[derive(Default, Clone)]
struct ModuleRow {
    name: String,
    protection: String,
    tier: String,
    state: String,
    fault_count: u32,
    restart_count: u32,
    last_fault_kind: u8,
    hist: [u32; 8],
}

fn parse_kv(line: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for tok in line.split_whitespace().skip(1) {
        if let Some((k, v)) = tok.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn apply_line(rows: &mut BTreeMap<u8, ModuleRow>, line: &str) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    let tag = trimmed.split_whitespace().next().unwrap_or("");
    let kv = parse_kv(trimmed);
    let module_idx = match kv.get("mod").and_then(|s| s.parse::<u8>().ok()) {
        Some(i) => i,
        None => return,
    };
    let row = rows.entry(module_idx).or_default();
    match tag {
        "MON_STATE" => {
            if let Some(n) = kv.get("name") { row.name = n.clone(); }
            if let Some(p) = kv.get("prot") { row.protection = p.clone(); }
            if let Some(t) = kv.get("tier") { row.tier = t.clone(); }
            if let Some(s) = kv.get("state") { row.state = s.clone(); }
        }
        "MON_FAULT" => {
            if let Some(v) = kv.get("kind").and_then(|s| s.parse::<u8>().ok()) {
                row.last_fault_kind = v;
            }
            if let Some(v) = kv.get("fault_count").and_then(|s| s.parse::<u32>().ok()) {
                row.fault_count = v;
            }
            if let Some(v) = kv.get("restart_count").and_then(|s| s.parse::<u32>().ok()) {
                row.restart_count = v;
            }
        }
        "MON_HIST" => {
            for i in 0..8 {
                let key = format!("b{}", i);
                if let Some(v) = kv.get(&key).and_then(|s| s.parse::<u32>().ok()) {
                    row.hist[i] = v;
                }
            }
        }
        _ => {}
    }
}

fn render(rows: &BTreeMap<u8, ModuleRow>) {
    // Clear screen (ANSI) and move cursor to top-left.
    print!("\x1b[2J\x1b[H");
    println!("fluxor monitor  —  {} modules", rows.len());
    println!();
    println!(
        "{:>3}  {:<16} {:<9} {:<9} {:<10} {:>6} {:>7} {:<9}   step-time buckets (us)",
        "idx", "name", "prot", "tier", "state", "faults", "restart", "last-kind"
    );
    println!("     buckets: <64 <128 <256 <512 <1024 <2048 <4096 >=4096");
    for (idx, row) in rows.iter() {
        println!(
            "{:>3}  {:<16} {:<9} {:<9} {:<10} {:>6} {:>7} {:<9}   {} {} {} {} {} {} {} {}",
            idx,
            truncate(&row.name, 16),
            row.protection,
            row.tier,
            row.state,
            row.fault_count,
            row.restart_count,
            fault_kind_str(row.last_fault_kind),
            row.hist[0], row.hist[1], row.hist[2], row.hist[3],
            row.hist[4], row.hist[5], row.hist[6], row.hist[7],
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

pub fn cmd_monitor(port: &str, _baud: u32, refresh_ms: u64) -> Result<()> {
    eprintln!(
        "fluxor monitor: opening {} (configure baud externally, e.g. \
         `stty -F {} 115200 raw -echo`)",
        port, port
    );
    let file = std::fs::File::open(port)
        .map_err(|e| Error::Config(format!("failed to open {}: {}", port, e)))?;
    let mut reader = BufReader::new(file);
    let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
    let mut last_render = Instant::now();
    let refresh = Duration::from_millis(refresh_ms);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => apply_line(&mut rows, &line),
            Err(e) => return Err(Error::Config(format!("read error: {}", e))),
        }
        if last_render.elapsed() >= refresh {
            render(&rows);
            last_render = Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fault_line() {
        let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
        apply_line(&mut rows, "MON_FAULT mod=3 kind=1 fault_count=2 restart_count=1 tick=500");
        let r = &rows[&3];
        assert_eq!(r.last_fault_kind, 1);
        assert_eq!(r.fault_count, 2);
        assert_eq!(r.restart_count, 1);
    }

    #[test]
    fn parse_hist_line() {
        let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
        apply_line(&mut rows, "MON_HIST mod=0 b0=10 b1=5 b2=1 b3=0 b4=0 b5=0 b6=0 b7=0");
        assert_eq!(rows[&0].hist, [10, 5, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn parse_state_line() {
        let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
        apply_line(
            &mut rows,
            "MON_STATE mod=2 name=audio_out prot=isolated tier=verified state=running",
        );
        assert_eq!(rows[&2].name, "audio_out");
        assert_eq!(rows[&2].protection, "isolated");
        assert_eq!(rows[&2].tier, "verified");
    }
}
