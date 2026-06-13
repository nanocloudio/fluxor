//! `observe-udp_capture` — generic rig observe transport that captures
//! UDP datagrams (e.g. the kernel's `platform.debug.to: net` log stream)
//! and forwards each one to the matcher so a scenario can pin regex
//! pass/fail rules against arbitrary log lines.
//!
//! This is the generic counterpart to `telemetry-monitor_udp`: identical
//! listener, but bound to the `observe.udp_capture` capability so a
//! fixture can assert on raw log content (e.g. the EL0-isolation
//! `[el0] … abort`, `MON_FAULT`, and `[sched] alive` lines) without
//! overloading the "telemetry/monitor" semantics.
//!
//! Verb:
//!   attach   (transport) — bind a UDP socket and stream received
//!                          datagrams on stdout as NDJSON
//!                          `{"kind":"bytes","data":"<base64>"}`.
//!
//! Binding fields:
//!   port        (int, optional)  UDP port to bind. Default 6666 (the
//!                                kernel-side `log_net` default).
//!   bind_addr   (str, optional)  Interface to bind. Default `0.0.0.0`.
//!   client_ip   (str, optional)  Drop datagrams whose source IP doesn't
//!                                match — pin to the DUT's client_ip so a
//!                                noisy segment can't corrupt the run.
//!
//! Handles SIGTERM / SIGINT: close the socket and exit 0.

#![allow(
    unsafe_code,
    reason = "rig backend wraps signal handler installation via libc"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "rig backend streams NDJSON to stdout and diagnostics to stderr; both are part of the protocol"
)]

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use fluxor_tools::monitor::bind_udp_listener;

/// SIGTERM / SIGINT flag, polled between recv ticks.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const DEFAULT_PORT: u16 = 6666;
const DEFAULT_BIND_ADDR: &str = "0.0.0.0";
const RECV_POLL: Duration = Duration::from_millis(500);
const RECV_BUF: usize = 65535;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(verb) = args.next() else {
        eprintln!("observe-udp_capture: missing verb");
        return ExitCode::from(2);
    };

    let invocation = match read_invocation() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("observe-udp_capture: bad invocation JSON: {e}");
            return ExitCode::from(2);
        }
    };

    match verb.as_str() {
        "attach" => match attach(&invocation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(rc) => ExitCode::from(rc),
        },
        other => {
            eprintln!("observe-udp_capture: unknown verb '{other}'");
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
            eprintln!("observe-udp_capture: {e}");
            return Err(1);
        }
    };

    install_signal_handlers();

    emit(&json!({"kind": "ready"}));
    match &client_ip {
        Some(ip) => eprintln!("observe-udp_capture: bound udp://{bind_spec}, filter src={ip}"),
        None => eprintln!("observe-udp_capture: bound udp://{bind_spec}"),
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
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("observe-udp_capture: recvfrom failed: {e}");
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
        std::process::exit(0);
    }
}

fn install_signal_handlers() {
    extern "C" fn handler(_: libc::c_int) {
        SHUTDOWN.store(true, Ordering::Relaxed);
    }
    // SAFETY: `libc::signal` is async-signal-safe; `handler` is a plain
    // C-ABI fn pointer whose only effect is a signal-safe atomic store.
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
}
