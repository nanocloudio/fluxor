//! `observe-https_load` — rig backend that drives an HTTPS load probe
//! against the DUT and emits NDJSON `bytes` events the matcher can pin.
//!
//! Verb:
//!   attach   (transport) — wait for the server to come up, then run a
//!                          fixed sequence of phases against
//!                          `https://<target_ip>:<port><path>`. Each phase
//!                          emits a single one-line summary on stdout via
//!                          `{"kind":"bytes","data":"<base64 of '[https_load] phase=N name=X … OK\n'>"}`.
//!
//! Binding fields (from `[observe.https_load]` in the rig profile):
//!
//!   target_ip       (str, required)    DUT IP, e.g. "192.168.1.9".
//!   port            (int, optional)    TLS port. Default 443.
//!   path            (str, optional)    GET path. Default "/".
//!   pre_boot_wait_s (int, optional)    Sleep this long after attach
//!                                      before probing. Use to ride
//!                                      past the power-cycle window —
//!                                      otherwise the warm-up may
//!                                      succeed against the previous
//!                                      kernel still running before
//!                                      `power.cycle` lands. Default 15.
//!   boot_wait_s     (int, optional)    Max seconds to wait for the
//!                                      first successful GET. Default 30.
//!   handshake_count (int, optional)    Fresh-handshake count for phase 0.
//!                                      Default 50.
//!   throughput_s    (int, optional)    Sustained-GET phase duration.
//!                                      Default 10.
//!   throughput_floor_mbps (int, opt)   Below this, phase 1 emits ERR
//!                                      (matched by scenario fail rule).
//!                                      Default 1. Loose by design — the
//!                                      scenario file is the place to
//!                                      tighten the floor per fixture.
//!   concurrent_n    (int, optional)    Concurrent connections in phase 2.
//!                                      Default 64.
//!   concurrent_reqs (int, optional)    Requests per conn in phase 2.
//!                                      Default 50.
//!   stability_s     (int, optional)    Phase 3 duration. Default 30.
//!   stability_qps   (int, optional)    Phase 3 request rate target.
//!                                      Default 20.
//!
//! HTTP/1.1 only — drives raw `tokio::net::TcpStream` + `tokio_rustls`
//! and writes requests manually. No HTTP/2 path.
//!
//! Pass/fail wiring lives in the scenario `tests/hardware/*.toml`. This
//! backend reports facts (`OK` / `ERR` per phase plus a final `done`
//! line). The matcher decides what counts as a pass.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "rig backend streams NDJSON on stdout and diagnostics on stderr — both are part of the backend protocol"
)]

use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use futures_util::stream::{FuturesUnordered, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

const DEFAULT_PORT: u16 = 443;
const DEFAULT_PATH: &str = "/";
const DEFAULT_PRE_BOOT_WAIT_S: u64 = 15;
const DEFAULT_BOOT_WAIT_S: u64 = 30;

/// Per-request failure attribution, used to point at the layer
/// responsible instead of just counting `errors=N`.
///
///   * `connect`  — TCP refused / unreachable / reset before bytes flow.
///   * `tls`      — handshake failure (alert, cert, protocol error).
///   * `timeout`  — request didn't complete within `PER_REQUEST_TIMEOUT`.
///   * `body`     — status received, body read failed mid-stream.
///   * `other`    — everything else; should stay zero on this fixture.
#[derive(Default, Debug, Clone, Copy)]
struct ErrorTally {
    connect: u64,
    tls: u64,
    timeout: u64,
    body: u64,
    other: u64,
    /// Requests that never ran because an earlier request in the
    /// same keep-alive session failed and the driver tore down the
    /// session. Distinct from `timeout`/`body`/etc — those are the
    /// classification of the request that actually failed, while
    /// `aborted` captures the silently-lost remainder. Without this
    /// split, "1 SYN retransmit, all 256 OK" and "1 session lost
    /// 5 reqs" both rendered as `errors=1`.
    aborted: u64,
}

impl ErrorTally {
    fn total(&self) -> u64 {
        self.connect + self.tls + self.timeout + self.body + self.other + self.aborted
    }
    fn add_manual_err(&mut self, e: ManualErr) {
        match e {
            ManualErr::Connect => self.connect += 1,
            ManualErr::Tls => self.tls += 1,
            ManualErr::Timeout => self.timeout += 1,
            ManualErr::Body => self.body += 1,
            ManualErr::Other => self.other += 1,
        }
    }
    fn add_aborted(&mut self, n: u64) {
        self.aborted += n;
    }
    fn merge(&mut self, other: ErrorTally) {
        self.connect += other.connect;
        self.tls += other.tls;
        self.timeout += other.timeout;
        self.body += other.body;
        self.other += other.other;
        self.aborted += other.aborted;
    }
    fn render(&self, prefix: &str) -> String {
        format!(
            "{prefix}_connect={c} {prefix}_tls={t} {prefix}_timeout={to} {prefix}_body={b} {prefix}_other={o} {prefix}_aborted={a}",
            c = self.connect,
            t = self.tls,
            to = self.timeout,
            b = self.body,
            o = self.other,
            a = self.aborted,
        )
    }
}

/// Error class for the rustls manual path; maps the string errors
/// `timed_request` returns onto `ErrorTally`'s five buckets.
#[derive(Debug, Clone, Copy)]
enum ManualErr {
    Connect,
    Tls,
    Timeout,
    Body,
    Other,
}

fn classify_manual_err(msg: &str) -> ManualErr {
    if msg.starts_with("tcp_connect") {
        ManualErr::Connect
    } else if msg.starts_with("tls_handshake") || msg.starts_with("server_name") {
        ManualErr::Tls
    } else if msg.starts_with("write_request")
        || msg.starts_with("flush_request")
        || msg.starts_with("read_headers")
        || msg.starts_with("parse_headers")
        || msg.starts_with("bad_status")
        || msg.starts_with("read_body")
        || msg.starts_with("body_short")
        || msg.starts_with("body_overrun")
    {
        // Any failure after the TLS handshake completes is a body /
        // response problem from the load probe's POV. The detailed
        // tag survives as the `last_err` short string for triage.
        ManualErr::Body
    } else {
        ManualErr::Other
    }
}

/// Drive `timed_request` with an outer timeout so a wedged handshake
/// or a never-responding socket can't stall the phase forever.
async fn manual_request_with_timeout(
    target: &TargetUrl,
    tls_config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<StageTimings, ManualErr> {
    let fut = timed_request(&target.host, target.port, &target.path, tls_config);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(msg)) => Err(classify_manual_err(&msg)),
        Err(_) => Err(ManualErr::Timeout),
    }
}

/// Like `manual_request_with_timeout` but additionally rejects a
/// response whose body length doesn't match an externally-supplied
/// expected length. Cross-checks the rig's `Content-Length` against
/// the operator-supplied truth so a bug that flips a 1254-byte body
/// to 1255 bytes (without flipping the header in lockstep) still
/// fails the request. `expected = None` skips the cross-check.
async fn manual_request_validated(
    target: &TargetUrl,
    tls_config: Arc<ClientConfig>,
    timeout: Duration,
    expected: Option<usize>,
) -> Result<StageTimings, ManualErr> {
    let t = manual_request_with_timeout(target, tls_config, timeout).await?;
    if let Some(want) = expected {
        if t.body_bytes != want {
            return Err(ManualErr::Body);
        }
    }
    Ok(t)
}

#[derive(Clone)]
struct TargetUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_base_url(url: &str) -> Result<TargetUrl, String> {
    let after_scheme = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("url_not_https: {url}"))?;
    let (host_port, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("bad_port: {host_port}"))?;
            (h.to_string(), port)
        }
        None => (host_port.to_string(), 443u16),
    };
    Ok(TargetUrl {
        host,
        port,
        path: path.to_string(),
    })
}

const DEFAULT_HANDSHAKE_COUNT: u64 = 50;
const DEFAULT_THROUGHPUT_S: u64 = 10;
const DEFAULT_THROUGHPUT_FLOOR_MBPS: f64 = 1.0;
const DEFAULT_CONCURRENT_N: u64 = 64;
const DEFAULT_CONCURRENT_REQS: u64 = 50;
const DEFAULT_STABILITY_S: u64 = 30;
const DEFAULT_STABILITY_QPS: u64 = 20;
const BOOT_RETRY_INTERVAL: Duration = Duration::from_millis(500);
const PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(verb) = args.next() else {
        eprintln!("observe-https_load: missing verb");
        return ExitCode::from(2);
    };

    let invocation = match read_invocation() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("observe-https_load: bad invocation JSON: {e}");
            return ExitCode::from(2);
        }
    };

    match verb.as_str() {
        "attach" => match attach(&invocation).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(rc) => ExitCode::from(rc),
        },
        other => {
            eprintln!("observe-https_load: unknown verb '{other}'");
            ExitCode::from(2)
        }
    }
}

fn read_invocation() -> Result<Value, serde_json::Error> {
    let mut raw = String::new();
    if io::stdin().read_to_string(&mut raw).is_err() || raw.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&raw)
}

struct Config {
    base_url: String,
    pre_boot_wait_s: u64,
    boot_wait_s: u64,
    handshake_count: u64,
    throughput_s: u64,
    throughput_floor_mbps: f64,
    concurrent_n: u64,
    concurrent_reqs: u64,
    stability_s: u64,
    stability_qps: u64,
    /// Optional override of the diag sample count. When unset, the
    /// historical default `DIAG_SAMPLE_COUNT = 30` is used.
    /// Documented mostly so the ECDH-pool cliff at handshake #17 can
    /// be exercised by running 80–128 fresh handshakes per slot in a
    /// single rig run without restarting the kernel.
    diag_samples: u64,
    /// Optional cross-check: when set, every phase verifies that
    /// `body_bytes == expected_body_bytes` per successful request and
    /// fails the request as `body` class otherwise. Operators set
    /// this from the rig profile so a server bug that emits the wrong
    /// number of bytes (against an external truth) is caught.
    expected_body_bytes: Option<usize>,
    /// When > 1, switches phase 1 (sequential) and phase 2
    /// (concurrent) to keep-alive sessions of N requests each. The
    /// last request in every session sends `Connection: close` so
    /// the rig tears down cleanly. Per-request samples include the
    /// handshake cost ONLY on request 0 of each session, so the
    /// aggregate p50 reflects steady-state per-request cost.
    /// Default 0 keeps the historical fresh-handshake-per-request
    /// shape (matches the rig's http module before HTTP/1.1
    /// keep-alive landed in commit bdde108).
    keepalive_requests_per_conn: u64,
}

fn read_config(invocation: &Value) -> Result<Config, String> {
    let binding = invocation.get("binding").cloned().unwrap_or(Value::Null);
    let target_ip = binding
        .get("target_ip")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing required binding field `target_ip`".to_string())?
        .to_string();
    let port = binding
        .get("port")
        .and_then(Value::as_u64)
        .map(|p| p as u16)
        .unwrap_or(DEFAULT_PORT);
    let path = binding
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PATH);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let base_url = format!("https://{target_ip}:{port}{path}");
    let pre_boot_wait_s = binding
        .get("pre_boot_wait_s")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_PRE_BOOT_WAIT_S);
    let boot_wait_s = binding
        .get("boot_wait_s")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_BOOT_WAIT_S);
    let handshake_count = binding
        .get("handshake_count")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_HANDSHAKE_COUNT);
    let throughput_s = binding
        .get("throughput_s")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_THROUGHPUT_S);
    // Accept either a JSON integer (`0`, `5`) or a float (`0.75`,
    // `1.5`). `as_u64` alone silently dropped fractional profile
    // values, so a floor of `0.75 mbps` read back as the default.
    //
    // Reject negative + non-finite up front: a negative floor would
    // make phase 1 pass trivially against any measured throughput,
    // and a non-finite (NaN / ±Inf) would silently lose the
    // comparison. Non-finite *shouldn't* reach here — the rig
    // profile loader (`tools/src/rig/profile.rs`) rejects them —
    // but `read_config` also accepts direct stdin JSON for ad-hoc
    // probe invocations, so the defence stays.
    let throughput_floor_mbps = match binding.get("throughput_floor_mbps") {
        Some(v) => {
            let raw = v
                .as_f64()
                .or_else(|| v.as_u64().map(|n| n as f64))
                .ok_or_else(|| "binding.throughput_floor_mbps: must be a number".to_string())?;
            if !raw.is_finite() {
                return Err(format!(
                    "binding.throughput_floor_mbps: must be finite (got {raw})"
                ));
            }
            if raw < 0.0 {
                return Err(format!(
                    "binding.throughput_floor_mbps: must be >= 0 (got {raw})"
                ));
            }
            raw
        }
        None => DEFAULT_THROUGHPUT_FLOOR_MBPS,
    };
    let concurrent_n = binding
        .get("concurrent_n")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_CONCURRENT_N);
    let concurrent_reqs = binding
        .get("concurrent_reqs")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_CONCURRENT_REQS);
    let stability_s = binding
        .get("stability_s")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_STABILITY_S);
    let stability_qps = binding
        .get("stability_qps")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_STABILITY_QPS);
    let diag_samples = binding
        .get("diag_samples")
        .and_then(Value::as_u64)
        .unwrap_or(DIAG_SAMPLE_COUNT);
    let expected_body_bytes = binding
        .get("expected_body_bytes")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let keepalive_requests_per_conn = binding
        .get("keepalive_requests_per_conn")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Ok(Config {
        base_url,
        pre_boot_wait_s,
        boot_wait_s,
        handshake_count,
        throughput_s,
        throughput_floor_mbps,
        concurrent_n,
        concurrent_reqs,
        stability_s,
        stability_qps,
        diag_samples,
        expected_body_bytes,
        keepalive_requests_per_conn,
    })
}

async fn attach(invocation: &Value) -> Result<(), u8> {
    let cfg = match read_config(invocation) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("observe-https_load: {msg}");
            return Err(2);
        }
    };

    emit_ready();
    emit_line(&format!(
        "[https_load] startup target={} pre_boot_wait={}s boot_wait={}s probe=manual-rustls",
        cfg.base_url, cfg.pre_boot_wait_s, cfg.boot_wait_s,
    ));

    // Sleep past the rig's power-cycle window. Without this delay the
    // warm-up loop may succeed against the *previous* kernel still
    // running before `power.cycle` lands — observers attach before
    // the actuator stage, so the order is:
    //     attach → warmup-races-old-kernel → power.cycle →
    //     phase 0 spans cycle → spurious errors.
    // 15 s is comfortable against the default kasa_local
    // `off_hold_ms=3000 + boot_delay_ms=2000` plus VPU+TFTP (~20 s).
    if cfg.pre_boot_wait_s > 0 {
        emit_line(&format!(
            "[https_load] sleeping pre_boot_wait_s={}s to ride past power cycle",
            cfg.pre_boot_wait_s,
        ));
        tokio::time::sleep(Duration::from_secs(cfg.pre_boot_wait_s)).await;
    }

    // Parse `base_url` once and build a single shared rustls config
    // for every probe phase below. `parse_base_url` returns owned
    // strings so the tasks in phase 2/3 can clone freely.
    let target = match parse_base_url(&cfg.base_url) {
        Ok(t) => t,
        Err(e) => {
            emit_line(&format!("[https_load] FATAL parse_base_url: {e}"));
            return Err(1);
        }
    };
    let tls_config = match build_rustls_config_accept_any() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            emit_line(&format!("[https_load] FATAL tls_config_build: {e}"));
            return Err(1);
        }
    };

    // Wait for the server via the same manual rustls path the phases
    // use — so a probe attribute change (cert verifier, ALPN, TLS
    // version) gets exercised end-to-end before any measurement
    // happens, and the bring-up cost matches what phase 0 will see.
    let boot_start = Instant::now();
    let boot_deadline = boot_start + Duration::from_secs(cfg.boot_wait_s);
    let mut last_err: Option<String> = None;
    loop {
        if Instant::now() >= boot_deadline {
            emit_line(&format!(
                "[https_load] ERR boot_wait_timeout last_error={}",
                last_err.as_deref().unwrap_or("(none)")
            ));
            return Err(1);
        }
        // Use `timed_request` directly (not `manual_request_with_timeout`)
        // so the raw error string survives — its variant after
        // classification (ManualErr::Body, etc.) hides which stage
        // actually failed, and during boot we explicitly want to
        // see e.g. `read_headers: eof_after_0_bytes...` so the
        // operator can tell apart a half-up rig from a cert
        // mismatch.
        let attempt = tokio::time::timeout(
            PER_REQUEST_TIMEOUT,
            timed_request(&target.host, target.port, &target.path, tls_config.clone()),
        )
        .await;
        match attempt {
            Ok(Ok(t)) => {
                emit_line(&format!(
                    "[https_load] server_up status={status} body_bytes={bytes}/{cl} total_us={total} elapsed_ms={elapsed}",
                    status = t.status,
                    bytes = t.body_bytes,
                    cl = t.content_length,
                    total = t.total_us,
                    elapsed = boot_start.elapsed().as_millis(),
                ));
                break;
            }
            Ok(Err(msg)) => {
                last_err = Some(msg);
                tokio::time::sleep(BOOT_RETRY_INTERVAL).await;
            }
            Err(_) => {
                last_err = Some("warmup_timeout".to_string());
                tokio::time::sleep(BOOT_RETRY_INTERVAL).await;
            }
        }
    }

    // ── Diagnostic phase: per-stage latency breakdown ──
    //
    // The reqwest-based phases 0–3 used to dominate every request
    // with ~60 ms of client-side overhead (pool bookkeeping, fresh
    // Client::new() in the handshake phase, hyper cold-start). To
    // stop that hiding what Fluxor is actually doing, every phase
    // below now drives `tokio::net::TcpStream` + `tokio_rustls`
    // directly via `timed_request` / `manual_request_with_timeout`.
    // This phase emits the per-stage breakdown that named the
    // overhead in the first place — kept as the first signal so
    // the operator sees it before the aggregate numbers.
    run_diag_phase(&target, tls_config.clone(), cfg.diag_samples).await;

    // ── Phase 0: handshake rate ──
    // Every iteration drives a fresh TCP + TLS handshake + HTTP GET
    // via the manual rustls path so the measured rate reflects the
    // rig's actual capacity (rather than reqwest::Client::new() +
    // hyper-pool cold-start overhead, which we measured at ~60 ms
    // per request in the previous iteration of this probe).
    let t0 = Instant::now();
    let mut hs_ok: u64 = 0;
    let mut hs_errs = ErrorTally::default();
    let mut hs_samples: Vec<StageTimings> = Vec::with_capacity(cfg.handshake_count as usize);
    let expected = cfg.expected_body_bytes;
    for _ in 0..cfg.handshake_count {
        match manual_request_validated(&target, tls_config.clone(), PER_REQUEST_TIMEOUT, expected)
            .await
        {
            Ok(t) => {
                hs_ok += 1;
                hs_samples.push(t);
            }
            Err(e) => hs_errs.add_manual_err(e),
        }
    }
    let hs_elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let hs_rate = hs_ok as f64 / hs_elapsed;
    let hs_err_total = hs_errs.total();
    emit_line(&format!(
        "[https_load] phase=0 name=handshake_rate handshakes={hs_ok} elapsed_s={hs_elapsed:.2} rate_hps={hs_rate:.2} errors={hs_err_total} {hs_err_breakdown} {hs_pct} {status}",
        hs_err_breakdown = hs_errs.render("hs"),
        hs_pct = percentile_line(&hs_samples, "hs"),
        status = if hs_err_total == 0 && hs_ok > 0 { "OK" } else { "ERR" },
    ));

    // ── Phase 1: throughput (sequential, single-stream) ──
    // Two modes, picked by `keepalive_requests_per_conn` in the
    // binding:
    //   ≤ 1 (default): historical fresh-handshake-per-request
    //                  shape. Every request pays a full TCP+TLS
    //                  cycle (the http module honors the probe's
    //                  `Connection: close`). This was the shape
    //                  before the keep-alive work landed; useful
    //                  as a handshake-stress measurement.
    //   > 1:           keep-alive shape. Each TCP+TLS session
    //                  serves N requests with `Connection: keep-
    //                  alive` (the last one in each session sends
    //                  `Connection: close` so the server tears
    //                  down cleanly). Per-request samples include
    //                  the handshake cost ONLY on request 0 of
    //                  each session; subsequent requests have
    //                  tcp_us=0 / tls_us=0 so the p50 of the
    //                  aggregate is the steady-state per-request
    //                  cost.
    let t0 = Instant::now();
    let mut tp_ok: u64 = 0;
    let mut tp_errs = ErrorTally::default();
    let mut tp_bytes: u64 = 0;
    let mut tp_samples: Vec<StageTimings> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(cfg.throughput_s);
    let keepalive_n = cfg.keepalive_requests_per_conn;
    if keepalive_n > 1 {
        // Keep-alive mode: loop opening sessions, each driving up
        // to keepalive_n requests, until the throughput window
        // expires. Each session is wrapped in a timeout so a
        // wedged handshake or hung mid-stream read can't burn the
        // whole throughput_s window.
        const PHASE1_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
        while Instant::now() < deadline {
            let session_fut = drive_keepalive_session(
                &target.host,
                target.port,
                &target.path,
                tls_config.clone(),
                keepalive_n,
            );
            let (samples, err) =
                match tokio::time::timeout(PHASE1_SESSION_TIMEOUT, session_fut).await {
                    Ok(pair) => pair,
                    Err(_) => {
                        tp_errs.add_manual_err(ManualErr::Timeout);
                        continue;
                    }
                };
            for s in &samples {
                // Apply the same `expected_body_bytes` check that
                // close mode + phase 2 keep-alive use. Without this,
                // a server bug that truncates a keep-alive response
                // (Content-Length lies, or body shorter than header
                // claims) reads as OK because every sample returned
                // by `drive_keepalive_session` is treated as success.
                let body_ok = expected.map(|want| s.body_bytes == want).unwrap_or(true);
                if body_ok {
                    tp_bytes += s.body_bytes as u64;
                    tp_ok += 1;
                    tp_samples.push(*s);
                } else {
                    tp_errs.add_manual_err(ManualErr::Body);
                }
            }
            if let Some(msg) = err {
                tp_errs.add_manual_err(classify_manual_err(&msg));
                // One-shot debug emit on first session failure so an
                // operator can tell *what* rejected the requests
                // mid-keepalive without re-running with stack-traces.
                static FIRST: std::sync::OnceLock<()> = std::sync::OnceLock::new();
                if FIRST.set(()).is_ok() {
                    emit_line(&format!("[https_load] phase=1 keepalive_first_err: {msg}"));
                }
            }
        }
    } else {
        while Instant::now() < deadline {
            match manual_request_validated(
                &target,
                tls_config.clone(),
                PER_REQUEST_TIMEOUT,
                expected,
            )
            .await
            {
                Ok(t) => {
                    tp_bytes += t.body_bytes as u64;
                    tp_ok += 1;
                    tp_samples.push(t);
                }
                Err(e) => tp_errs.add_manual_err(e),
            }
        }
    } // end legacy fresh-handshake branch
    let tp_elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let tp_mbps = (tp_bytes as f64) / 1_000_000.0 / tp_elapsed;
    let tp_rate = tp_ok as f64 / tp_elapsed;
    let tp_err_total = tp_errs.total();
    let tp_status = if tp_err_total == 0 && tp_mbps >= cfg.throughput_floor_mbps {
        "OK"
    } else {
        "ERR"
    };
    let tp_mode = if keepalive_n > 1 {
        "keepalive"
    } else {
        "close"
    };
    emit_line(&format!(
        "[https_load] phase=1 name=throughput_single mode={tp_mode} ka_n={keepalive_n} bytes={tp_bytes} elapsed_s={tp_elapsed:.2} mbps={tp_mbps:.3} reqs={tp_ok} rate_rps={tp_rate:.2} errors={tp_err_total} {tp_err_breakdown} {tp_pct} floor_mbps={:.2} {tp_status}",
        cfg.throughput_floor_mbps,
        tp_err_breakdown = tp_errs.render("tp"),
        tp_pct = percentile_line(&tp_samples, "tp"),
    ));

    // ── Phase 2: concurrent connections ──
    // Two modes, picked by the same `keepalive_requests_per_conn`
    // knob phase 1 uses:
    //   ≤ 1 (default): N parallel tasks × M fresh-handshake requests
    //                  each. Measures concurrent-handshake capacity
    //                  (gated by tls/mod.rs:MAX_SESSIONS = 16 plus
    //                  ip/MAX_TCP_CONNS).
    //   > 1:           N parallel keep-alive sessions, each driving
    //                  M sequential requests. Measures steady-state
    //                  concurrent throughput with the handshake
    //                  amortized — the most production-shaped number
    //                  this probe emits.
    // Reports total time, ok count, aggregate throughput and the
    // mode tag so regressions in either correctness or capacity
    // surface in one line.
    let target_total = cfg.concurrent_n * cfg.concurrent_reqs;
    let c_mode = if keepalive_n > 1 {
        "keepalive"
    } else {
        "close"
    };
    let t0 = Instant::now();
    let mut tasks = FuturesUnordered::new();
    for _ in 0..cfg.concurrent_n {
        let task_target = target.clone();
        let task_tls = tls_config.clone();
        let reqs = cfg.concurrent_reqs;
        let task_expected = expected;
        let ka = keepalive_n;
        tasks.push(tokio::spawn(async move {
            let mut ok: u64 = 0;
            let mut errs = ErrorTally::default();
            let mut samples: Vec<StageTimings> = Vec::with_capacity(reqs as usize);
            if ka > 1 {
                // Outer per-session timeout: a wedged TLS handshake
                // or a hung mid-stream read shouldn't be able to
                // stall the whole phase. Generous bound — 32 reqs at
                // ~900 µs steady-state is ~30 ms, plus the L1/L2
                // SYN-retransmit budget (~3 s of probe-side retries),
                // plus margin.
                const PER_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
                let session_fut = drive_keepalive_session(
                    &task_target.host,
                    task_target.port,
                    &task_target.path,
                    task_tls,
                    reqs,
                );
                let (session_samples, err) =
                    match tokio::time::timeout(PER_SESSION_TIMEOUT, session_fut).await {
                        Ok(pair) => pair,
                        Err(_) => {
                            // Timeout: nothing usable returned. Treat
                            // as a Timeout class + all reqs aborted.
                            errs.add_manual_err(ManualErr::Timeout);
                            errs.add_aborted(reqs.saturating_sub(1));
                            return (ok, errs, samples);
                        }
                    };
                for t in &session_samples {
                    let body_ok = task_expected
                        .map(|want| t.body_bytes == want)
                        .unwrap_or(true);
                    if body_ok {
                        ok += 1;
                        samples.push(*t);
                    } else {
                        errs.add_manual_err(ManualErr::Body);
                    }
                }
                if let Some(msg) = err {
                    // One request failed (classified by message),
                    // and the keep-alive driver returned without
                    // running the remainder of the session. Account
                    // for the silently-lost reqs as `aborted`.
                    errs.add_manual_err(classify_manual_err(&msg));
                    let observed = session_samples.len() as u64;
                    let lost = reqs.saturating_sub(observed).saturating_sub(1);
                    errs.add_aborted(lost);
                }
            } else {
                for _ in 0..reqs {
                    match manual_request_validated(
                        &task_target,
                        task_tls.clone(),
                        PER_REQUEST_TIMEOUT,
                        task_expected,
                    )
                    .await
                    {
                        Ok(t) => {
                            ok += 1;
                            samples.push(t);
                        }
                        Err(e) => errs.add_manual_err(e),
                    }
                }
            }
            (ok, errs, samples)
        }));
    }
    let mut c_ok: u64 = 0;
    let mut c_errs = ErrorTally::default();
    let mut c_samples: Vec<StageTimings> = Vec::new();
    while let Some(joined) = tasks.next().await {
        if let Ok((ok, errs, samples)) = joined {
            c_ok += ok;
            c_errs.merge(errs);
            c_samples.extend(samples);
        }
    }
    let c_elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let c_err_total = c_errs.total();
    let c_rate = c_ok as f64 / c_elapsed;
    let c_status = if c_err_total == 0 && c_ok == target_total {
        "OK"
    } else {
        "ERR"
    };
    emit_line(&format!(
        "[https_load] phase=2 name=concurrent_{n} mode={c_mode} ka_n={ka_for_log} conns={n} reqs_per_conn={r} target={target_total} ok={c_ok} rate_rps={c_rate:.2} errors={c_err_total} {c_err_breakdown} {c_pct} elapsed_s={c_elapsed:.2} {c_status}",
        n = cfg.concurrent_n,
        r = cfg.concurrent_reqs,
        ka_for_log = keepalive_n,
        c_err_breakdown = c_errs.render("c"),
        c_pct = percentile_line(&c_samples, "c"),
    ));

    // ── Phase 3: sustained-load stability ──
    // Paces requests at target_qps for stability_s seconds; any error
    // flips the phase to ERR. Catches state-machine leaks that take
    // tens of seconds to surface — slot exhaustion, ARP cache races,
    // TimeWait accumulation, etc.
    let qps = cfg.stability_qps.max(1);
    let total_reqs = qps * cfg.stability_s;
    let per_req_budget = Duration::from_secs_f64(1.0 / qps as f64);
    let s_ok = Arc::new(Mutex::new(0u64));
    let s_err_tally = Arc::new(Mutex::new(ErrorTally::default()));
    let s_samples = Arc::new(Mutex::new(Vec::<StageTimings>::with_capacity(
        total_reqs as usize,
    )));
    let t0 = Instant::now();
    let mut tasks = FuturesUnordered::new();
    let start = Instant::now();
    for i in 0..total_reqs {
        let due = start + per_req_budget * i as u32;
        let now = Instant::now();
        if now < due {
            tokio::time::sleep(due - now).await;
        }
        let task_target = target.clone();
        let task_tls = tls_config.clone();
        let ok = s_ok.clone();
        let errs = s_err_tally.clone();
        let samples = s_samples.clone();
        let task_expected = expected;
        tasks.push(tokio::spawn(async move {
            match manual_request_validated(
                &task_target,
                task_tls,
                PER_REQUEST_TIMEOUT,
                task_expected,
            )
            .await
            {
                Ok(t) => {
                    *ok.lock().await += 1;
                    samples.lock().await.push(t);
                }
                Err(e) => errs.lock().await.add_manual_err(e),
            }
        }));
        while tasks.len() > qps as usize * 2 {
            let _ = tasks.next().await;
        }
    }
    while tasks.next().await.is_some() {}
    let s_elapsed = t0.elapsed().as_secs_f64().max(0.001);
    let s_ok_n = *s_ok.lock().await;
    let s_errs = *s_err_tally.lock().await;
    let s_err_n = s_errs.total();
    let s_samples_v = s_samples.lock().await.clone();
    let s_status = if s_err_n == 0 { "OK" } else { "ERR" };
    emit_line(&format!(
        "[https_load] phase=3 name=stability_{dur}s reqs={s_ok_n} errors={s_err_n} {s_err_breakdown} {s_pct} target_qps={qps} elapsed_s={s_elapsed:.2} {s_status}",
        dur = cfg.stability_s,
        s_err_breakdown = s_errs.render("s"),
        s_pct = percentile_line(&s_samples_v, "s"),
    ));

    // Final summary line — single anchor the scenario matcher can
    // pin to know every phase completed.
    let any_err = hs_err_total > 0
        || tp_err_total > 0
        || c_err_total > 0
        || s_err_n > 0
        || tp_mbps < cfg.throughput_floor_mbps
        || c_ok != target_total;
    emit_line(&format!(
        "[https_load] done phases=4 any_err={any_err} hs_rate_hps={hs_rate:.2} tp_rate_rps={tp_rate:.2} tp_mbps={tp_mbps:.3} conc_rate_rps={c_rate:.2} conc_ok={c_ok}/{target_total} stab_ok={s_ok_n}/{total_reqs}",
    ));
    Ok(())
}

/// Per-request latency breakdown. All fields in microseconds; sum
/// should be close to the request's wall-clock time (modulo a few µs
/// of scheduling overhead). `body_bytes` and `content_length` are
/// always equal on success — the strict-read path in `timed_request`
/// fails the request if they don't match.
#[derive(Default, Debug, Clone, Copy)]
struct StageTimings {
    tcp_us: u128,
    tls_us: u128,
    req_send_us: u128,
    ttfb_us: u128,
    body_us: u128,
    total_us: u128,
    body_bytes: usize,
    #[allow(
        dead_code,
        reason = "kept for the diag emit line which surfaces it to the matcher"
    )]
    content_length: usize,
    #[allow(
        dead_code,
        reason = "kept for the diag emit line which surfaces it to the matcher"
    )]
    status: u16,
}

/// Number of stage-timed samples the diagnostic phase collects.
/// 30 lets us see whether sustained-rate latency stays flat or
/// climbs after some N requests (TimeWait slot exhaustion, TCP
/// accept-queue backlog, etc.). Each sample is a full
/// TCP+TLS+HTTP cycle so the loop time is also a usable
/// throughput floor.
const DIAG_SAMPLE_COUNT: u64 = 30;

async fn run_diag_phase(target: &TargetUrl, tls_config: Arc<ClientConfig>, sample_count: u64) {
    let mut samples: Vec<StageTimings> = Vec::with_capacity(sample_count as usize);
    for sample_idx in 0..sample_count {
        // Wrap each sample in `PER_REQUEST_TIMEOUT` — phases 0/1/2/3
        // do this via `manual_request_with_timeout`; diag used to
        // call `timed_request` raw, so a single stalled DUT
        // mid-response would prevent the diag summary + every
        // subsequent phase from ever emitting (the matcher then
        // saw nothing and would mark the run TimedOut without
        // ever showing which sample hung).
        let fut = timed_request(&target.host, target.port, &target.path, tls_config.clone());
        let attempt = tokio::time::timeout(PER_REQUEST_TIMEOUT, fut).await;
        let result: Result<StageTimings, String> = match attempt {
            Ok(r) => r,
            Err(_) => Err(format!(
                "diag_sample_timeout: {}s",
                PER_REQUEST_TIMEOUT.as_secs()
            )),
        };
        match result {
            Ok(t) => {
                emit_line(&format!(
                    "[https_load] diag sample={sample_idx} status={status} tcp_us={tcp} tls_us={tls} req_us={req} ttfb_us={ttfb} body_us={body} body_bytes={bytes} content_length={cl} total_us={total}",
                    status = t.status,
                    tcp = t.tcp_us,
                    tls = t.tls_us,
                    req = t.req_send_us,
                    ttfb = t.ttfb_us,
                    body = t.body_us,
                    bytes = t.body_bytes,
                    cl = t.content_length,
                    total = t.total_us,
                ));
                samples.push(t);
            }
            Err(e) => {
                emit_line(&format!("[https_load] diag sample={sample_idx} ERR {e}"));
            }
        }
    }

    if samples.is_empty() {
        emit_line("[https_load] diag summary n=0 ERR no_samples");
        return;
    }

    // Median per-stage so an outlier doesn't dominate the summary.
    // Phase 0/1's mean-style headline still goes through the
    // existing aggregate path below; this is just the breakdown.
    let med_tcp = median_us(&samples, |t| t.tcp_us);
    let med_tls = median_us(&samples, |t| t.tls_us);
    let med_req = median_us(&samples, |t| t.req_send_us);
    let med_ttfb = median_us(&samples, |t| t.ttfb_us);
    let med_body = median_us(&samples, |t| t.body_us);
    let med_total = median_us(&samples, |t| t.total_us);
    emit_line(&format!(
        "[https_load] diag summary n={n} tcp_us_med={med_tcp} tls_us_med={med_tls} req_us_med={med_req} ttfb_us_med={med_ttfb} body_us_med={med_body} total_us_med={med_total}",
        n = samples.len(),
    ));
}

fn median_us<F: Fn(&StageTimings) -> u128>(samples: &[StageTimings], f: F) -> u128 {
    percentile_us(samples, f, 50)
}

/// Compute the `p`-th percentile (0..=100) of `f(t)` across the
/// samples. Uses nearest-rank selection. Empty samples → 0.
fn percentile_us<F: Fn(&StageTimings) -> u128>(samples: &[StageTimings], f: F, p: u32) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut v: Vec<u128> = samples.iter().map(f).collect();
    v.sort_unstable();
    let p = p.min(100) as usize;
    // Nearest-rank with 1-based indexing per the standard definition.
    let n = v.len();
    let rank = (p * n).div_ceil(100);
    let idx = if rank == 0 { 0 } else { rank - 1 };
    v[idx.min(n - 1)]
}

/// Render `pct=v p50=v p90=v p99=v` across `total_us` for a phase
/// summary. Cheap — one sort per call.
fn percentile_line(samples: &[StageTimings], prefix: &str) -> String {
    if samples.is_empty() {
        return format!("{prefix}_p50=0 {prefix}_p90=0 {prefix}_p99=0");
    }
    format!(
        "{prefix}_p50={p50} {prefix}_p90={p90} {prefix}_p99={p99}",
        p50 = percentile_us(samples, |t| t.total_us, 50),
        p90 = percentile_us(samples, |t| t.total_us, 90),
        p99 = percentile_us(samples, |t| t.total_us, 99),
    )
}

/// Drive one full HTTPS request stage by stage, measuring each.
/// Uses raw `TcpStream` + `tokio_rustls` so the TCP handshake and
/// TLS handshake are measured separately, and the HTTP write +
/// first-byte read + body completion get their own timestamps.
/// `Connection: close` is set explicitly so the server tears down
/// after the response (we never reuse the socket — every diag
/// sample is a clean cycle).
///
/// Correctness contract (added by patch 1):
/// - Parse the status line; reject anything that isn't `200 OK`.
/// - Parse the `Content-Length` header; reject responses without one.
/// - Read exactly `Content-Length` body bytes after the blank line.
///   - Short reads (EOF or mid-body Err before the count is met)
///     are classified `BodyShort` — not silently treated as success.
///   - Overruns (server keeps sending past Content-Length) are
///     classified `BodyOverrun` — same.
/// - Returns `body_bytes == content_length` on success so the
///   `body_bytes=` field in phase summaries reflects what was
///   actually delivered, not what was attempted.
async fn timed_request(
    host: &str,
    port: u16,
    path: &str,
    tls_config: Arc<ClientConfig>,
) -> Result<StageTimings, String> {
    let start = Instant::now();
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("tcp_connect: {e}"))?;
    let tcp_done = Instant::now();
    stream.set_nodelay(true).ok();

    let server_name: RustlsServerName<'static> =
        RustlsServerName::try_from(host.to_string()).map_err(|e| format!("server_name: {e}"))?;
    let connector = TlsConnector::from(tls_config);
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls_handshake: {e}"))?;
    let tls_done = Instant::now();

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: observe-https_load/diag\r\nAccept: */*\r\n\r\n"
    );
    tls_stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write_request: {e}"))?;
    tls_stream
        .flush()
        .await
        .map_err(|e| format!("flush_request: {e}"))?;
    let req_send_done = Instant::now();

    // Read response head until we see the `\r\n\r\n` blank line.
    // First byte arrives at `ttfb_done`. We cap the header buffer at
    // 16 KiB — any well-behaved fluxor `http` response fits in a few
    // hundred bytes; a runaway server is itself an error.
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut head_buf = Vec::<u8>::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let mut ttfb_done: Option<Instant> = None;
    let header_end;
    loop {
        let n = tls_stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read_headers: {e}"))?;
        if n == 0 {
            return Err(format!(
                "read_headers: eof_after_{}_bytes_no_blank_line",
                head_buf.len()
            ));
        }
        if ttfb_done.is_none() {
            ttfb_done = Some(Instant::now());
        }
        head_buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&head_buf) {
            header_end = end;
            break;
        }
        if head_buf.len() > MAX_HEADER_BYTES {
            return Err("read_headers: headers_too_large".to_string());
        }
    }
    let ttfb_done = ttfb_done.expect("ttfb_done captured once header bytes start arriving");

    // Parse status + body framing out of the head.
    // Include the trailing `\r\n\r\n` (4 bytes) so the parser sees
    // the CRLF terminator of the LAST header line. `find_header_end`
    // returns the offset where `\r\n\r\n` STARTS, so head[..end]
    // alone clips off the final header's terminator and the parser
    // never recognises Content-Length on a static-route response.
    let head_with_term = &head_buf[..(header_end + 4).min(head_buf.len())];
    let (status, framing) =
        parse_status_and_framing(head_with_term).map_err(|e| format!("parse_headers: {e}"))?;
    if status != 200 {
        return Err(format!("bad_status: {status}"));
    }
    // The blank line is `\r\n\r\n` (4 bytes); body starts after it.
    let body_start_in_head = header_end + 4;
    let mut body_bytes = head_buf.len().saturating_sub(body_start_in_head);

    // For Content-Length framing: read exactly `content_length`
    // body bytes total. Short reads (EOF or Err before the count is
    // met) and overruns are explicit errors — the old `Err(_) =>
    // break` swallowed all of these.
    //
    // For close-delimited framing: read until clean EOF. Any read
    // error (TLS alert, RST) before EOF is `body` class — only a
    // graceful `Ok(0)` ends the body. `body_bytes` is the actual
    // delivered count and is what the per-phase `tp_bytes` /
    // `body_bytes=` lines report.
    let content_length_reported = match framing {
        BodyFraming::ContentLength(n) => {
            while body_bytes < n {
                let want = n - body_bytes;
                let cap = tmp.len().min(want);
                let n_read = tls_stream
                    .read(&mut tmp[..cap])
                    .await
                    .map_err(|e| format!("read_body: {e}"))?;
                if n_read == 0 {
                    return Err(format!("body_short: {body_bytes}/{n}"));
                }
                body_bytes += n_read;
            }
            // Drain any close_notify / stray bytes; EOF expected.
            let extra = tls_stream.read(&mut tmp).await.unwrap_or(0);
            if extra > 0 {
                return Err(format!("body_overrun: {extra}_extra_after_cl_{n}"));
            }
            n
        }
        BodyFraming::CloseDelimited => {
            // No declared length — read until graceful EOF. Any
            // mid-stream Err is a real failure (TLS alert, RST).
            loop {
                let n_read = tls_stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("read_body: {e}"))?;
                if n_read == 0 {
                    break;
                }
                body_bytes += n_read;
            }
            // Report content_length == actual delivered count for
            // the diag line; phase-level cross-checks against
            // `expected_body_bytes` still catch mismatches against
            // an externally-supplied truth.
            body_bytes
        }
    };
    let body_done = Instant::now();

    Ok(StageTimings {
        tcp_us: tcp_done.duration_since(start).as_micros(),
        tls_us: tls_done.duration_since(tcp_done).as_micros(),
        req_send_us: req_send_done.duration_since(tls_done).as_micros(),
        ttfb_us: ttfb_done.duration_since(req_send_done).as_micros(),
        body_us: body_done.duration_since(ttfb_done).as_micros(),
        total_us: body_done.duration_since(start).as_micros(),
        body_bytes,
        content_length: content_length_reported,
        status,
    })
}

/// Drive `n_requests` HTTPS requests across a single TCP+TLS
/// session (HTTP/1.1 keep-alive). The first sample's `total_us`
/// includes the one-time TCP+TLS handshake cost, so percentile
/// rollups see "what a fresh client experiences on request #1";
/// samples 1..n include only per-request cost (tcp_us/tls_us =
/// 0) so the same rollup gives "steady-state per-request cost"
/// at p50.
///
/// Sends `Connection: keep-alive` on every request except the
/// last, which sends `Connection: close` so the server tears the
/// session down cleanly. If the server responds with a
/// `CloseDelimited` framing (i.e. it didn't honor keep-alive)
/// the driver stops early — the request was still successful but
/// the next one would race the connection close.
///
/// On any per-request error, returns the samples accumulated so
/// far PLUS the error message (so phase rollups can count
/// errors AND keep the successful samples).
async fn drive_keepalive_session(
    host: &str,
    port: u16,
    path: &str,
    tls_config: Arc<ClientConfig>,
    n_requests: u64,
) -> (Vec<StageTimings>, Option<String>) {
    if n_requests == 0 {
        return (Vec::new(), None);
    }
    let session_start = Instant::now();
    let stream = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(e) => return (Vec::new(), Some(format!("tcp_connect: {e}"))),
    };
    let tcp_done = Instant::now();
    stream.set_nodelay(true).ok();

    let server_name: RustlsServerName<'static> = match RustlsServerName::try_from(host.to_string())
    {
        Ok(n) => n,
        Err(e) => return (Vec::new(), Some(format!("server_name: {e}"))),
    };
    let connector = TlsConnector::from(tls_config);
    let mut tls_stream = match connector.connect(server_name, stream).await {
        Ok(s) => s,
        Err(e) => return (Vec::new(), Some(format!("tls_handshake: {e}"))),
    };
    let tls_done = Instant::now();

    let mut samples: Vec<StageTimings> = Vec::with_capacity(n_requests as usize);
    let mut last_done = tls_done;
    let mut early_close_reason: Option<&'static str> = None;
    for i in 0..n_requests {
        let is_last = i + 1 == n_requests;
        let connection_hdr = if is_last { "close" } else { "keep-alive" };
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: {connection_hdr}\r\nUser-Agent: observe-https_load/keepalive\r\nAccept: */*\r\n\r\n"
        );
        let req_start = if i == 0 { session_start } else { last_done };
        let send_start = Instant::now();
        if let Err(e) = tls_stream.write_all(req.as_bytes()).await {
            return (samples, Some(format!("write_request[{i}]: {e}")));
        }
        if let Err(e) = tls_stream.flush().await {
            return (samples, Some(format!("flush_request[{i}]: {e}")));
        }
        let req_send_done = Instant::now();

        // Inline copy of timed_request's response loop. Duplication
        // is intentional and bounded — both paths will collapse to a
        // single helper once we add a third (HTTP/2 / pipelining
        // probe) that proves the abstraction shape.
        const MAX_HEADER_BYTES: usize = 16 * 1024;
        let mut head_buf = Vec::<u8>::with_capacity(2048);
        let mut tmp = [0u8; 1024];
        let mut ttfb_done: Option<Instant> = None;
        let header_end;
        loop {
            let n = match tls_stream.read(&mut tmp).await {
                Ok(n) => n,
                Err(e) => return (samples, Some(format!("read_headers[{i}]: {e}"))),
            };
            if n == 0 {
                return (
                    samples,
                    Some(format!(
                        "read_headers[{i}]: eof_after_{}_bytes_no_blank_line",
                        head_buf.len()
                    )),
                );
            }
            if ttfb_done.is_none() {
                ttfb_done = Some(Instant::now());
            }
            head_buf.extend_from_slice(&tmp[..n]);
            if let Some(end) = find_header_end(&head_buf) {
                header_end = end;
                break;
            }
            if head_buf.len() > MAX_HEADER_BYTES {
                return (
                    samples,
                    Some(format!("read_headers[{i}]: headers_too_large")),
                );
            }
        }
        let ttfb_done = ttfb_done.expect("ttfb_done captured once header bytes arrive");

        // See `timed_request` for the same `+4` rationale.
        let head_with_term = &head_buf[..(header_end + 4).min(head_buf.len())];
        let (status, framing) = match parse_status_and_framing(head_with_term) {
            Ok(t) => t,
            Err(e) => return (samples, Some(format!("parse_headers[{i}]: {e}"))),
        };
        if status != 200 {
            return (samples, Some(format!("bad_status[{i}]: {status}")));
        }
        let body_start_in_head = header_end + 4;
        let mut body_bytes = head_buf.len().saturating_sub(body_start_in_head);

        let content_length_reported = match framing {
            BodyFraming::ContentLength(n) => {
                while body_bytes < n {
                    let want = n - body_bytes;
                    let cap = tmp.len().min(want);
                    let n_read = match tls_stream.read(&mut tmp[..cap]).await {
                        Ok(v) => v,
                        Err(e) => return (samples, Some(format!("read_body[{i}]: {e}"))),
                    };
                    if n_read == 0 {
                        return (samples, Some(format!("body_short[{i}]: {body_bytes}/{n}")));
                    }
                    body_bytes += n_read;
                }
                n
            }
            BodyFraming::CloseDelimited => {
                // Server didn't honor keep-alive — read to EOF then
                // stop the loop. Last sample is still valid.
                early_close_reason = Some("server_returned_close_delimited");
                loop {
                    let n_read = match tls_stream.read(&mut tmp).await {
                        Ok(v) => v,
                        Err(e) => return (samples, Some(format!("read_body[{i}]: {e}"))),
                    };
                    if n_read == 0 {
                        break;
                    }
                    body_bytes += n_read;
                }
                body_bytes
            }
        };
        let body_done = Instant::now();
        last_done = body_done;

        let tcp_us = if i == 0 {
            tcp_done.duration_since(session_start).as_micros()
        } else {
            0
        };
        let tls_us = if i == 0 {
            tls_done.duration_since(tcp_done).as_micros()
        } else {
            0
        };
        samples.push(StageTimings {
            tcp_us,
            tls_us,
            req_send_us: req_send_done.duration_since(send_start).as_micros(),
            ttfb_us: ttfb_done.duration_since(req_send_done).as_micros(),
            body_us: body_done.duration_since(ttfb_done).as_micros(),
            total_us: body_done.duration_since(req_start).as_micros(),
            body_bytes,
            content_length: content_length_reported,
            status,
        });

        if early_close_reason.is_some() {
            break;
        }
    }
    (samples, early_close_reason.map(String::from))
}

/// Return the offset of the `\r\n\r\n` sequence (HTTP head/body
/// separator) within `buf`, or None if it hasn't arrived yet.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 4 <= buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse the HTTP status line, Content-Length and Connection
/// headers out of the response head (everything up to but not
/// including the `\r\n\r\n` blank line). Case-insensitive header
/// name match.
///
/// Returns `(status_code, body_framing)`. `body_framing` is
/// `ContentLength(n)` when a `Content-Length: N` header is present,
/// or `CloseDelimited` when only `Connection: close` is signalled
/// and Content-Length is absent (HTTP/1.0-style framing). The
/// fluxor http module currently emits the latter on static routes
/// (`build_header` in modules/foundation/http/server.rs), so the
/// probe must accept both shapes.
///
/// Returns Err when the status line is unparseable or when neither
/// Content-Length nor `Connection: close` is signalled — that's
/// the "framing unknown, can't tell when body ends" case, which a
/// load probe must reject up front rather than read-forever.
fn parse_status_and_framing(head: &[u8]) -> Result<(u16, BodyFraming), &'static str> {
    let first_crlf = find_crlf(head).ok_or("status_line_no_crlf")?;
    let status_line = &head[..first_crlf];
    let mut parts = status_line.split(|c| *c == b' ');
    let _version = parts.next().ok_or("status_line_no_version")?;
    let status_bytes = parts.next().ok_or("status_line_no_status")?;
    let mut status: u32 = 0;
    for b in status_bytes {
        if !b.is_ascii_digit() {
            return Err("status_not_digits");
        }
        status = status * 10 + ((*b - b'0') as u32);
        if status > 999 {
            return Err("status_out_of_range");
        }
    }
    if status == 0 {
        return Err("status_zero");
    }

    let mut cursor = first_crlf + 2;
    let mut content_length: Option<usize> = None;
    let mut connection_close = false;
    while cursor < head.len() {
        let line_end = match find_crlf(&head[cursor..]) {
            Some(e) => cursor + e,
            None => break,
        };
        let line = &head[cursor..line_end];
        if let Some(colon) = line.iter().position(|c| *c == b':') {
            let name = &line[..colon];
            let mut value_start = colon + 1;
            while value_start < line.len()
                && (line[value_start] == b' ' || line[value_start] == b'\t')
            {
                value_start += 1;
            }
            let value = &line[value_start..];
            if name.eq_ignore_ascii_case(b"content-length") {
                let mut n: usize = 0;
                for b in value {
                    if !b.is_ascii_digit() {
                        return Err("content_length_not_digits");
                    }
                    n = n
                        .checked_mul(10)
                        .and_then(|x| x.checked_add((*b - b'0') as usize))
                        .ok_or("content_length_overflow")?;
                }
                content_length = Some(n);
            } else if name.eq_ignore_ascii_case(b"connection")
                && value
                    .split(|c| *c == b',' || *c == b' ')
                    .any(|tok| tok.eq_ignore_ascii_case(b"close"))
            {
                connection_close = true;
            }
        }
        cursor = line_end + 2;
    }

    let framing = match (content_length, connection_close) {
        (Some(n), _) => BodyFraming::ContentLength(n),
        (None, true) => BodyFraming::CloseDelimited,
        (None, false) => return Err("framing_unknown_no_cl_no_close"),
    };
    Ok((status as u16, framing))
}

#[derive(Debug, Clone, Copy)]
enum BodyFraming {
    /// Server declared `Content-Length: N`. Read exactly N body
    /// bytes; reject short reads and overruns.
    ContentLength(usize),
    /// Server only signalled `Connection: close` (no
    /// Content-Length). Read until clean EOF; the rig's static-body
    /// path currently takes this shape until the http module
    /// learns to emit Content-Length statically.
    CloseDelimited,
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 2 <= buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// rustls `ServerCertVerifier` that accepts every certificate.
/// Mirrors `reqwest::ClientBuilder::danger_accept_invalid_certs(true)`
/// for the lower-level rustls path. Safe in this context — the rig
/// fixture's self-signed cert is part of the test setup.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &RustlsServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn build_rustls_config_accept_any() -> Result<ClientConfig, String> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    // Force HTTP/1.1 ALPN. Without this the server may pick
    // h2 (the fluxor http module supports HTTP/2 via wire_h2.rs)
    // and the probe's hand-rolled HTTP/1.1 parser then sees an
    // h2 frame stream as `framing_unknown_no_cl_no_close`. The
    // probe is HTTP/1.1-only by design — both the close-framing
    // and the keep-alive modes drive that codec.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

fn emit_line(line: &str) {
    let mut payload = line.to_string();
    payload.push('\n');
    let event = json!({
        "kind": "bytes",
        "data": BASE64_STANDARD.encode(payload.as_bytes()),
    });
    println!("{event}");
    let _ = io::Write::flush(&mut io::stdout());
    eprintln!("{line}");
}

fn emit_ready() {
    println!("{}", json!({"kind": "ready"}));
    let _ = io::Write::flush(&mut io::stdout());
}
