//! `fluxor-collect` — the host-side telemetry collector: receives a
//! device's `export_telemetry: udp` batches, resolves them against
//! the build's id-table, and serves/pushes standard formats.
//!
//!   fluxor-collect --id-table idtable.json [--listen 0.0.0.0:4317]
//!                  [--prometheus 0.0.0.0:9464]
//!                  [--otlp http://host:4318/v1/metrics] [--otlp-interval 10]
//!                  [--service fluxor]
//!
//!   * `--id-table` — the `fluxor id-table <config> -o idtable.json` export.
//!     Omitted: records resolve to synthetic names, labeled unresolved.
//!   * `--listen` — UDP bind for FXTL batches (default 0.0.0.0:4317, the
//!     `export_dst_port` default in stacks/debug.toml).
//!   * `--prometheus` — TCP bind for `GET /metrics` text exposition
//!     (default 0.0.0.0:9464, the conventional OTel-Prometheus port). OQ2:
//!     served directly — the latest-value table exists anyway.
//!   * `--otlp` — optional OTLP/JSON push target (plain http; a local OTel
//!     collector endpoint). Pushed every `--otlp-interval` seconds.
//!
//! A batch whose id-table digest mismatches the loaded table is REFUSED and
//! counted (`fluxor_collect_refused_total`) — wrong names are worse than no
//! names. Ctrl-C exits.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "operator-facing host tool; stdout/stderr are its UI"
)]

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxor_tools::collect::{Collector, IngestError, TableView};

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

struct Args {
    id_table: Option<String>,
    listen: String,
    prometheus: String,
    otlp: Option<String>,
    otlp_interval: u64,
    service: String,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        id_table: None,
        listen: "0.0.0.0:4317".into(),
        prometheus: "0.0.0.0:9464".into(),
        otlp: None,
        otlp_interval: 10,
        service: "fluxor".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} requires a value"));
        match flag.as_str() {
            "--id-table" => a.id_table = Some(val("--id-table")?),
            "--listen" => a.listen = val("--listen")?,
            "--prometheus" => a.prometheus = val("--prometheus")?,
            "--otlp" => a.otlp = Some(val("--otlp")?),
            "--otlp-interval" => {
                a.otlp_interval = val("--otlp-interval")?
                    .parse()
                    .map_err(|e| format!("--otlp-interval: {e}"))?
            }
            "--service" => a.service = val("--service")?,
            "--help" | "-h" => {
                eprintln!(
                    "fluxor-collect --id-table idtable.json [--listen 0.0.0.0:4317] \
                     [--prometheus 0.0.0.0:9464] [--otlp http://host:4318/v1/metrics] \
                     [--otlp-interval 10] [--service fluxor]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag '{other}' (see --help)")),
        }
    }
    Ok(a)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fluxor-collect: {e}");
            std::process::exit(2);
        }
    };

    let table = match &args.id_table {
        Some(path) => {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("fluxor-collect: cannot read {path}: {e}");
                    std::process::exit(2);
                }
            };
            let json: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("fluxor-collect: {path} is not JSON: {e}");
                    std::process::exit(2);
                }
            };
            match TableView::from_json(&json) {
                Ok(t) => {
                    eprintln!(
                        "fluxor-collect: id-table {path}: {} metrics, digest {:#010x}",
                        t.metrics.len(),
                        t.digest
                    );
                    Some(t)
                }
                Err(e) => {
                    eprintln!("fluxor-collect: {path}: {e}");
                    std::process::exit(2);
                }
            }
        }
        None => {
            eprintln!(
                "fluxor-collect: no --id-table — names will be synthetic and \
                 digests unverifiable"
            );
            None
        }
    };

    let collector = Arc::new(Mutex::new(Collector::new(table)));

    // ── Prometheus pull surface ─────────────────────────────────────
    {
        let collector = Arc::clone(&collector);
        let bind = args.prometheus.clone();
        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&bind) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("fluxor-collect: prometheus bind {bind}: {e}");
                    std::process::exit(2);
                }
            };
            eprintln!("fluxor-collect: prometheus text on http://{bind}/metrics");
            for stream in listener.incoming().flatten() {
                let collector = Arc::clone(&collector);
                std::thread::spawn(move || serve_prometheus(stream, &collector));
            }
        });
    }

    // ── OTLP push ───────────────────────────────────────────────────
    if let Some(otlp) = args.otlp.clone() {
        let collector = Arc::clone(&collector);
        let service = args.service.clone();
        let interval = Duration::from_secs(args.otlp_interval.max(1));
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            let doc = collector.lock().unwrap().render_otlp_json(&service);
            if let Err(e) = post_json(&otlp, &doc.to_string()) {
                eprintln!("fluxor-collect: OTLP push to {otlp}: {e}");
            }
        });
    }

    // ── UDP ingest loop ─────────────────────────────────────────────
    let sock = match UdpSocket::bind(&args.listen) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fluxor-collect: udp bind {}: {e}", args.listen);
            std::process::exit(2);
        }
    };
    eprintln!("fluxor-collect: FXTL batches on udp://{}", args.listen);
    let mut buf = [0u8; 65535];
    let mut mismatch_reported = false;
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        match collector.lock().unwrap().ingest(&buf[..n], unix_nanos()) {
            Ok(_) => {}
            Err(IngestError::DigestMismatch { envelope, table }) => {
                // Report the FIRST mismatch loudly; after that the refused
                // counter carries it (a chatty device would flood stderr).
                if !mismatch_reported {
                    eprintln!(
                        "fluxor-collect: REFUSED batch from {from}: emitter id-table \
                         digest {envelope:#010x} != loaded {table:#010x} — the device \
                         image and this id-table are from different builds; re-export \
                         with `fluxor id-table` from the deployed graph"
                    );
                    mismatch_reported = true;
                }
            }
            Err(IngestError::BadMagic) => {} // other UDP traffic; ignore
            Err(IngestError::Truncated) => {
                eprintln!("fluxor-collect: truncated batch from {from} ({n} B)");
            }
        }
    }
}

fn serve_prometheus(mut stream: TcpStream, collector: &Mutex<Collector>) {
    let mut req = [0u8; 2048];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Ok(n) = stream.read(&mut req) else { return };
    let head = String::from_utf8_lossy(&req[..n]);
    let ok = head.starts_with("GET /metrics") || head.starts_with("GET / ");
    let (status, body) = if ok {
        ("200 OK", collector.lock().unwrap().render_prometheus())
    } else {
        ("404 Not Found", "see /metrics\n".to_string())
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Minimal OTLP/JSON push: HTTP/1.1 POST over plain TCP (`http://` only —
/// this targets a LAN OTel collector; TLS termination is its job).
fn post_json(url: &str, body: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// push targets are supported")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/v1/metrics"),
    };
    let mut stream = TcpStream::connect(hostport).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(|e| e.to_string())?;
    let mut resp = [0u8; 512];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let n = stream.read(&mut resp).unwrap_or(0);
    let line = String::from_utf8_lossy(&resp[..n]);
    if line.contains(" 200 ") || line.contains(" 202 ") {
        Ok(())
    } else {
        Err(format!(
            "unexpected response: {}",
            line.lines().next().unwrap_or("<empty>")
        ))
    }
}
