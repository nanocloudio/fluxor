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
            if let Some(n) = kv.get("name") {
                row.name = n.clone();
            }
            if let Some(p) = kv.get("prot") {
                row.protection = p.clone();
            }
            if let Some(t) = kv.get("tier") {
                row.tier = t.clone();
            }
            if let Some(s) = kv.get("state") {
                row.state = s.clone();
            }
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
            row.hist[0],
            row.hist[1],
            row.hist[2],
            row.hist[3],
            row.hist[4],
            row.hist[5],
            row.hist[6],
            row.hist[7],
        );
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Dispatcher — choose transport based on whether --net was set.
pub fn cmd_monitor_dispatch(
    port: &str,
    baud: u32,
    refresh_ms: u64,
    net: Option<&str>,
) -> Result<()> {
    match net {
        Some(bind) => cmd_monitor_udp(bind, refresh_ms),
        None => cmd_monitor(port, baud, refresh_ms),
    }
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

/// Bind a UDP listener for kernel-side `log_net` datagrams.
///
/// `bind_spec` accepts either a `host:port` string or a leading-colon
/// `:port` shorthand (binds `0.0.0.0:<port>`). `read_timeout` is
/// applied so the caller's loop wakes periodically for cooperative
/// idle work (rendering a dashboard, polling for shutdown, etc.); pass
/// `None` to block indefinitely on `recv_from`.
pub fn bind_udp_listener(
    bind_spec: &str,
    read_timeout: Option<Duration>,
) -> Result<std::net::UdpSocket> {
    use std::net::UdpSocket;
    let normalized = if bind_spec.starts_with(':') {
        format!("0.0.0.0{}", bind_spec)
    } else {
        bind_spec.to_string()
    };
    let sock = UdpSocket::bind(&normalized)
        .map_err(|e| Error::Config(format!("bind {}: {}", normalized, e)))?;
    if let Some(t) = read_timeout {
        sock.set_read_timeout(Some(t)).ok();
    }
    Ok(sock)
}

/// Consume MON_* lines from UDP netconsole datagrams. Each datagram may
/// carry multiple newline-framed log lines (the device batches them).
pub fn cmd_monitor_udp(bind: &str, refresh_ms: u64) -> Result<()> {
    let sock = bind_udp_listener(bind, Some(Duration::from_millis(refresh_ms)))?;
    eprintln!("fluxor monitor: listening on {} (UDP)", sock.local_addr().map_or_else(|_| bind.to_string(), |a| a.to_string()));

    let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
    let mut last_render = Instant::now();
    let refresh = Duration::from_millis(refresh_ms);
    let mut buf = [0u8; 4096];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _addr)) => {
                // A single datagram may batch several \r\n-separated lines.
                for line in buf[..n].split(|&b| b == b'\n') {
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(s) = std::str::from_utf8(line) {
                        apply_line(&mut rows, s.trim_end_matches('\r'));
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // idle tick — fall through to render
            }
            Err(e) => return Err(Error::Config(format!("udp recv: {}", e))),
        }
        if last_render.elapsed() >= refresh {
            render(&rows);
            last_render = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fault_line() {
        let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
        apply_line(
            &mut rows,
            "MON_FAULT mod=3 kind=1 fault_count=2 restart_count=1 tick=500",
        );
        let r = &rows[&3];
        assert_eq!(r.last_fault_kind, 1);
        assert_eq!(r.fault_count, 2);
        assert_eq!(r.restart_count, 1);
    }

    #[test]
    fn parse_hist_line() {
        let mut rows: BTreeMap<u8, ModuleRow> = BTreeMap::new();
        apply_line(
            &mut rows,
            "MON_HIST mod=0 b0=10 b1=5 b2=1 b3=0 b4=0 b5=0 b6=0 b7=0",
        );
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
