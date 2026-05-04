//! `telemetry-monitor_udp` — rig backend that captures the kernel's
//! `log_net` UDP broadcast and forwards each datagram to the matcher.
//!
//! Verb:
//!   attach   (transport) — bind a UDP socket and stream received
//!                          datagrams on stdout as NDJSON
//!                          `{"kind":"bytes","data":"<base64>"}`.
//!
//! Binding fields:
//!
//!   port           (int, optional)   UDP port to bind. Defaults to
//!                                    6666 (matches the kernel-side
//!                                    `log_net` default).
//!   bind_addr      (str, optional)   Interface to bind. Defaults to
//!                                    `0.0.0.0` (any interface).
//!   client_ip      (str, optional)   If set, drop datagrams whose
//!                                    source IP doesn't match. Pin to
//!                                    the DUT's netboot client_ip when
//!                                    multiple broadcasters share the
//!                                    segment.
//!
//! Handles SIGTERM / SIGINT: close the socket and exit 0.

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use fluxor_tools::monitor::bind_udp_listener;

/// SIGTERM / SIGINT flag, polled between recv ticks. `static` so a
/// signal handler — which can't carry context — can flip it.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const DEFAULT_PORT: u16 = 6666;
const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
/// Read-timeout granularity for the recv loop. Bounds how quickly the
/// process notices a SIGTERM after the last datagram.
const RECV_POLL: Duration = Duration::from_millis(500);
/// Maximum IPv4 UDP datagram length; comfortably accommodates any
/// kernel-side `log_net` frame.
const RECV_BUF: usize = 65535;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(verb) = args.next() else {
        eprintln!("telemetry-monitor_udp: missing verb");
        return ExitCode::from(2);
    };

    let invocation = match read_invocation() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("telemetry-monitor_udp: bad invocation JSON: {e}");
            return ExitCode::from(2);
        }
    };

    match verb.as_str() {
        "attach" => match attach(&invocation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(rc) => ExitCode::from(rc),
        },
        other => {
            eprintln!("telemetry-monitor_udp: unknown verb '{other}'");
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

fn attach(invocation: &Value) -> Result<(), u8> {
    let binding = invocation.get("binding").cloned().unwrap_or(Value::Null);
    let port = binding
        .get("port")
        .and_then(Value::as_u64)
        .map(|p| p as u16)
        .unwrap_or(DEFAULT_PORT);
    let bind_addr = binding
        .get("bind_addr")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_BIND_ADDR)
        .to_string();
    let client_ip = binding
        .get("client_ip")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let bind_spec = format!("{bind_addr}:{port}");
    let sock = match bind_udp_listener(&bind_spec, Some(RECV_POLL)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("telemetry-monitor_udp: {e}");
            return Err(1);
        }
    };

    install_signal_handlers();

    emit(&json!({"kind": "ready"}));
    match &client_ip {
        Some(ip) => eprintln!(
            "telemetry-monitor_udp: bound udp://{bind_spec}, filter src={ip}"
        ),
        None => eprintln!("telemetry-monitor_udp: bound udp://{bind_spec}"),
    }

    let mut buf = vec![0u8; RECV_BUF];
    while !SHUTDOWN.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if let Some(ref ip) = client_ip {
                    if addr.ip().to_string() != *ip {
                        continue;
                    }
                }
                if n == 0 {
                    continue;
                }
                emit(&json!({
                    "kind": "bytes",
                    "data": BASE64_STANDARD.encode(&buf[..n]),
                }));
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                // poll tick (timeout) or signal-interrupted syscall —
                // re-check the shutdown flag and loop.
            }
            Err(e) => {
                eprintln!("telemetry-monitor_udp: recvfrom failed: {e}");
                return Err(1);
            }
        }
    }
    Ok(())
}

fn emit(event: &Value) {
    let line = event.to_string();
    let mut stdout = io::stdout().lock();
    if writeln!(stdout, "{line}").is_err() || stdout.flush().is_err() {
        // Parent closed the pipe — exit quietly so SIGPIPE isn't
        // promoted into a non-zero exit code.
        std::process::exit(0);
    }
}

fn install_signal_handlers() {
    extern "C" fn handler(_: libc::c_int) {
        SHUTDOWN.store(true, Ordering::Relaxed);
    }
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
}
