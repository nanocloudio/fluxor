//! `observe-tls_load` — rig backend that drives TLS 1.3 handshakes against
//! the DUT's tls anchor and emits NDJSON `bytes` events the matcher can pin.
//!
//! The transport probe for the tls module, as distinct from the HTTPS one:
//! nothing above the record layer is exercised, so what it measures is the
//! handshake — the server's key exchange and its signature, which is what
//! an RSA identity changes — and the echo above it, one line per session.
//!
//! Verb:
//!   attach   (transport) — wait for the server to come up, then run four
//!                          phases against `<target_ip>:<port>`. Each phase
//!                          emits one summary line:
//!                          `{"kind":"bytes","data":"<base64 of '[tls_load] phase=N name=X … OK\n'>"}`.
//!
//! Phases:
//!   0 handshake_rate  fresh connection per handshake for `handshake_s`
//!                     seconds; reports handshakes per second, the latency
//!                     percentiles and the scheme the server signed with.
//!                     ERR on any failure or a rate under `hps_floor`.
//!   1 concurrent      `concurrent_n` clients, each `concurrent_handshakes`
//!                     sessions in turn, all with an echo. ERR on any failure.
//!   2 stability       `stability_qps` sessions per second for
//!                     `stability_s` seconds. ERR on any failure.
//!   3 echo            one session, one line, and the line (or its
//!                     uppercase) back.
//!
//! Binding fields (from `[observe.tls_load]` in the rig profile):
//!
//!   target_ip             (str, required)  DUT address.
//!   port                  (int)            TLS port. Default 9443.
//!   pre_boot_wait_s       (int)            Sleep past the power cycle. Default 45.
//!   boot_wait_s           (int)            Wait for the first handshake. Default 90.
//!   handshake_s           (int)            Phase 0 duration. Default 10.
//!   hps_floor             (int)            Phase 0 fails under this rate. Default 0.
//!   concurrent_n          (int)            Phase 1 clients. Default 4.
//!   concurrent_handshakes (int)            Phase 1 sessions per client. Default 8.
//!   stability_s           (int)            Phase 2 duration. Default 12.
//!   stability_qps         (int)            Phase 2 sessions per second. Default 4.
//!
//! The certificate is accepted whatever it is — the identity under test
//! is minted per run — and the scheme of its CertificateVerify is what is
//! recorded. Pass/fail lives in the scenario; this backend reports facts.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "rig backend streams NDJSON on stdout and diagnostics on stderr — both are part of the backend protocol"
)]

use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
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
use tokio_rustls::TlsConnector;

const DEFAULT_PORT: u16 = 9443;
const DEFAULT_PRE_BOOT_WAIT_S: u64 = 45;
const DEFAULT_BOOT_WAIT_S: u64 = 90;
const DEFAULT_HANDSHAKE_S: u64 = 10;
const DEFAULT_CONCURRENT_N: u64 = 4;
const DEFAULT_CONCURRENT_HANDSHAKES: u64 = 8;
const DEFAULT_STABILITY_S: u64 = 12;
const DEFAULT_STABILITY_QPS: u64 = 4;
const PER_SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const BOOT_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(verb) = args.next() else {
        eprintln!("observe-tls_load: missing verb");
        return ExitCode::from(2);
    };
    let invocation = match read_invocation() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("observe-tls_load: bad invocation JSON: {e}");
            return ExitCode::from(2);
        }
    };
    match verb.as_str() {
        "attach" => match attach(&invocation).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(rc) => ExitCode::from(rc),
        },
        other => {
            eprintln!("observe-tls_load: unknown verb '{other}'");
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
    host: String,
    port: u16,
    pre_boot_wait_s: u64,
    boot_wait_s: u64,
    handshake_s: u64,
    hps_floor: u64,
    concurrent_n: u64,
    concurrent_handshakes: u64,
    stability_s: u64,
    stability_qps: u64,
}

fn read_config(invocation: &Value) -> Result<Config, String> {
    let binding = invocation.get("binding").cloned().unwrap_or(Value::Null);
    let host = binding
        .get("target_ip")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing required binding field `target_ip`".to_string())?
        .to_string();
    let int = |key: &str, default: u64| binding.get(key).and_then(Value::as_u64).unwrap_or(default);
    Ok(Config {
        host,
        port: int("port", DEFAULT_PORT as u64) as u16,
        pre_boot_wait_s: int("pre_boot_wait_s", DEFAULT_PRE_BOOT_WAIT_S),
        boot_wait_s: int("boot_wait_s", DEFAULT_BOOT_WAIT_S),
        handshake_s: int("handshake_s", DEFAULT_HANDSHAKE_S),
        hps_floor: int("hps_floor", 0),
        concurrent_n: int("concurrent_n", DEFAULT_CONCURRENT_N),
        concurrent_handshakes: int("concurrent_handshakes", DEFAULT_CONCURRENT_HANDSHAKES),
        stability_s: int("stability_s", DEFAULT_STABILITY_S),
        stability_qps: int("stability_qps", DEFAULT_STABILITY_QPS),
    })
}

/// Accepts every certificate — the identity is minted per run — and
/// records the scheme of the CertificateVerify it signed.
#[derive(Debug)]
struct RecordScheme {
    scheme: Arc<Mutex<Option<SignatureScheme>>>,
}

impl ServerCertVerifier for RecordScheme {
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
        Err(RustlsError::General(
            "TLS 1.2 is not what this probe drives".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        if let Ok(mut s) = self.scheme.lock() {
            *s = Some(dss.scheme);
        }
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
        ]
    }
}

fn scheme_name(s: Option<SignatureScheme>) -> String {
    match s {
        Some(SignatureScheme::ECDSA_NISTP256_SHA256) => "ecdsa_secp256r1_sha256".into(),
        Some(SignatureScheme::RSA_PSS_SHA256) => "rsa_pss_rsae_sha256".into(),
        Some(SignatureScheme::RSA_PSS_SHA384) => "rsa_pss_rsae_sha384".into(),
        Some(SignatureScheme::RSA_PKCS1_SHA256) => "rsa_pkcs1_sha256".into(),
        Some(SignatureScheme::RSA_PKCS1_SHA384) => "rsa_pkcs1_sha384".into(),
        Some(other) => format!("{other:?}"),
        None => "none".into(),
    }
}

/// One session: connect, handshake, and when `echo`, one line whose
/// uppercase must come back. Returns the handshake's microseconds.
async fn session(host: &str, port: u16, tls: Arc<ClientConfig>, echo: bool) -> Result<u64, String> {
    let t0 = Instant::now();
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("tcp_connect: {e}"))?;
    stream.set_nodelay(true).ok();
    let server_name: RustlsServerName<'static> =
        RustlsServerName::try_from(host.to_string()).map_err(|e| format!("server_name: {e}"))?;
    let mut tls = TlsConnector::from(tls)
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls_handshake: {e}"))?;
    let handshake_us = t0.elapsed().as_micros() as u64;
    if echo {
        let line = b"tls load probe echo line\n";
        tls.write_all(line)
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut got = Vec::with_capacity(line.len());
        while got.len() < line.len() {
            let mut buf = [0u8; 256];
            let n = tls.read(&mut buf).await.map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("echo: closed early".into());
            }
            got.extend_from_slice(&buf[..n]);
        }
        // The sink echoes the line, the uppercase fixture its uppercase.
        if !got.eq_ignore_ascii_case(line) {
            return Err(format!(
                "echo: mismatch {:?}",
                String::from_utf8_lossy(&got)
            ));
        }
    }
    let _ = tls.shutdown().await;
    Ok(handshake_us)
}

async fn timed_session(
    host: &str,
    port: u16,
    tls: Arc<ClientConfig>,
    echo: bool,
) -> Result<u64, String> {
    match tokio::time::timeout(PER_SESSION_TIMEOUT, session(host, port, tls, echo)).await {
        Ok(r) => r,
        Err(_) => Err("timeout".into()),
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

async fn attach(invocation: &Value) -> Result<(), u8> {
    let cfg = match read_config(invocation) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("observe-tls_load: {msg}");
            return Err(2);
        }
    };
    emit_ready();
    emit_line(&format!(
        "[tls_load] startup target={}:{} pre_boot_wait={}s boot_wait={}s",
        cfg.host, cfg.port, cfg.pre_boot_wait_s, cfg.boot_wait_s
    ));
    // Observers attach before the power cycle; sleeping past it keeps the
    // probe off the kernel that is about to be reset.
    if cfg.pre_boot_wait_s > 0 {
        tokio::time::sleep(Duration::from_secs(cfg.pre_boot_wait_s)).await;
    }
    let scheme = Arc::new(Mutex::new(None));
    let tls = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RecordScheme {
                scheme: scheme.clone(),
            }))
            .with_no_client_auth(),
    );

    let boot_start = Instant::now();
    let boot_deadline = boot_start + Duration::from_secs(cfg.boot_wait_s);
    let mut last_err = String::from("(none)");
    loop {
        if Instant::now() >= boot_deadline {
            emit_line(&format!(
                "[tls_load] ERR boot_wait_timeout last_error={last_err}"
            ));
            return Err(1);
        }
        match timed_session(&cfg.host, cfg.port, tls.clone(), true).await {
            Ok(us) => {
                emit_line(&format!(
                    "[tls_load] server_up handshake_us={us} elapsed_ms={} scheme={}",
                    boot_start.elapsed().as_millis(),
                    scheme_name(*scheme.lock().unwrap())
                ));
                break;
            }
            Err(e) => {
                last_err = e;
                tokio::time::sleep(BOOT_RETRY_INTERVAL).await;
            }
        }
    }

    let mut any_err = false;

    // ── Phase 0: handshake rate ──
    let hps_measured = {
        let end = Instant::now() + Duration::from_secs(cfg.handshake_s);
        let mut samples: Vec<u64> = Vec::new();
        let mut errors = 0u64;
        let mut last = String::new();
        let started = Instant::now();
        while Instant::now() < end {
            match timed_session(&cfg.host, cfg.port, tls.clone(), false).await {
                Ok(us) => samples.push(us),
                Err(e) => {
                    errors += 1;
                    last = e;
                }
            }
        }
        let secs = started.elapsed().as_secs_f64().max(0.001);
        let hps_measured = samples.len() as f64 / secs;
        samples.sort_unstable();
        let ok = errors == 0 && hps_measured >= cfg.hps_floor as f64;
        any_err |= !ok;
        emit_line(&format!(
            "[tls_load] phase=0 name=handshake_rate handshakes={} errors={} hps={:.1} p50_ms={:.1} p99_ms={:.1} scheme={} floor={} last_err={} {}",
            samples.len(),
            errors,
            hps_measured,
            percentile(&samples, 0.5) as f64 / 1000.0,
            percentile(&samples, 0.99) as f64 / 1000.0,
            scheme_name(*scheme.lock().unwrap()),
            cfg.hps_floor,
            if last.is_empty() { "-".to_string() } else { last.replace(' ', "_") },
            if ok { "OK" } else { "ERR" }
        ));
        hps_measured
    };

    // ── Phase 1: concurrent clients ──
    {
        let mut tasks = FuturesUnordered::new();
        for _ in 0..cfg.concurrent_n {
            let host = cfg.host.clone();
            let port = cfg.port;
            let tls = tls.clone();
            let per = cfg.concurrent_handshakes;
            tasks.push(tokio::spawn(async move {
                let mut errors = 0u64;
                let mut worst = 0u64;
                let mut last = String::new();
                for _ in 0..per {
                    match timed_session(&host, port, tls.clone(), true).await {
                        Ok(us) => worst = worst.max(us),
                        Err(e) => {
                            errors += 1;
                            last = e;
                        }
                    }
                }
                (errors, worst, last)
            }));
        }
        let mut errors = 0u64;
        let mut worst = 0u64;
        let mut last = String::new();
        let started = Instant::now();
        while let Some(r) = tasks.next().await {
            match r {
                Ok((e, w, l)) => {
                    errors += e;
                    worst = worst.max(w);
                    if !l.is_empty() {
                        last = l;
                    }
                }
                Err(e) => {
                    errors += 1;
                    last = format!("join: {e}");
                }
            }
        }
        let ok = errors == 0;
        any_err |= !ok;
        emit_line(&format!(
            "[tls_load] phase=1 name=concurrent clients={} per_client={} errors={} worst_ms={:.1} elapsed_ms={} last_err={} {}",
            cfg.concurrent_n,
            cfg.concurrent_handshakes,
            errors,
            worst as f64 / 1000.0,
            started.elapsed().as_millis(),
            if last.is_empty() { "-".to_string() } else { last.replace(' ', "_") },
            if ok { "OK" } else { "ERR" }
        ));
    }

    // ── Phase 2: paced stability ──
    {
        let total = cfg.stability_s * cfg.stability_qps;
        let gap = Duration::from_micros(1_000_000 / cfg.stability_qps.max(1));
        let mut tasks = FuturesUnordered::new();
        let started = Instant::now();
        for i in 0..total {
            let host = cfg.host.clone();
            let port = cfg.port;
            let tls = tls.clone();
            tasks.push(tokio::spawn(async move {
                timed_session(&host, port, tls, true).await
            }));
            let due = started + gap * (i as u32 + 1);
            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
        }
        let mut errors = 0u64;
        let mut worst = 0u64;
        let mut last = String::new();
        while let Some(r) = tasks.next().await {
            match r {
                Ok(Ok(us)) => worst = worst.max(us),
                Ok(Err(e)) => {
                    errors += 1;
                    last = e;
                }
                Err(e) => {
                    errors += 1;
                    last = format!("join: {e}");
                }
            }
        }
        let ok = errors == 0;
        any_err |= !ok;
        emit_line(&format!(
            "[tls_load] phase=2 name=stability sessions={} qps={} errors={} worst_ms={:.1} elapsed_ms={} last_err={} {}",
            total,
            cfg.stability_qps,
            errors,
            worst as f64 / 1000.0,
            started.elapsed().as_millis(),
            if last.is_empty() { "-".to_string() } else { last.replace(' ', "_") },
            if ok { "OK" } else { "ERR" }
        ));
    }

    // ── Phase 3: echo ──
    {
        let (ok, detail) = match timed_session(&cfg.host, cfg.port, tls.clone(), true).await {
            Ok(us) => (true, format!("handshake_ms={:.1}", us as f64 / 1000.0)),
            Err(e) => (false, format!("last_err={}", e.replace(' ', "_"))),
        };
        any_err |= !ok;
        emit_line(&format!(
            "[tls_load] phase=3 name=echo {detail} {}",
            if ok { "OK" } else { "ERR" }
        ));
    }

    emit_line(&format!(
        "[tls_load] done any_err={any_err} hps={hps_measured:.1} scheme={}",
        scheme_name(*scheme.lock().unwrap())
    ));
    if any_err {
        Err(1)
    } else {
        Ok(())
    }
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
