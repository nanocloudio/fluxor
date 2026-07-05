//! Linux external-process executor (rfc_k8s.md §6.8, §19.5).
//!
//! Owns one external-hosted process for a graph-resident proxy node: blocking
//! spawn/read/write/wait/kill all happen on worker threads or the caller's
//! control path — **never** in `module_step`. The proxy polls both directions
//! through bounded [`ExtBridge`] queues (§6.8: bounded, declared overload
//! policy, cannot block the scheduler or grow unbounded):
//!
//! ```text
//!   module_step ── send_stdin ──▶ [ExtBridge] ──▶ writer thread ──▶ child stdin
//!   module_step ◀─ poll_stdout ── [ExtBridge] ◀── reader thread ◀── child stdout
//! ```
//!
//! stdout rides the bridge as arbitrary chunks (byte-stream passthrough); a
//! `Block`-policy inbound bridge makes backpressure real: when the graph stops
//! draining, the reader stops reading and the pipe fills, throttling the
//! external process (§6.8).
//!
//! Owner scoping (§14 invariant 9): the executor records its owner handle and
//! the child **cannot outlive revocation** — `shutdown` follows the §6.8
//! quiesce order (stop reads → SIGTERM → bounded drain deadline → SIGKILL),
//! and `Drop` force-kills as the last line of defence.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::kernel::extbridge::{ExtBridge, OverloadPolicy, PushOutcome};
use crate::kernel::owner::OwnerHandle;

/// Bridge capacity per direction. 16 KiB absorbs bursty chunked output while
/// keeping the §10.4 per-owner buffer budget honest.
const BRIDGE_CAP: usize = 16 * 1024;
/// Reader chunk size (also the largest frame the reader produces).
const READ_CHUNK: usize = 1024;

/// One owned external process with bounded stdin/stdout bridges.
pub struct ProcExecutor {
    pub owner: OwnerHandle,
    child: Child,
    stdout_bridge: Arc<ExtBridge<BRIDGE_CAP>>,
    stdin_bridge: Arc<ExtBridge<BRIDGE_CAP>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

impl ProcExecutor {
    /// Spawn `cmd args…` with piped stdio and start the pump threads.
    /// `stdout_policy` is the inbound overload policy from the signed interface
    /// declaration (`Block` gives true end-to-end backpressure).
    pub fn spawn(
        owner: OwnerHandle,
        cmd: &str,
        args: &[&str],
        stdout_policy: OverloadPolicy,
    ) -> std::io::Result<ProcExecutor> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdout_bridge = Arc::new(ExtBridge::<BRIDGE_CAP>::new(stdout_policy));
        // Outbound is always Block: a full queue rejects the proxy's push and
        // the proxy applies its own declared policy — nothing accumulates.
        let stdin_bridge = Arc::new(ExtBridge::<BRIDGE_CAP>::new(OverloadPolicy::Block));
        let stop = Arc::new(AtomicBool::new(false));

        // Reader: child stdout → inbound bridge. Blocking read lives here, off
        // the scheduler. On overload with a rejecting policy we simply stop
        // reading (pipe fills → child throttles). Exits on EOF or stop flag.
        let reader = {
            let bridge = Arc::clone(&stdout_bridge);
            let stop = Arc::clone(&stop);
            let mut out = child.stdout.take().expect("stdout piped");
            std::thread::spawn(move || {
                let mut buf = [0u8; READ_CHUNK];
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    match out.read(&mut buf) {
                        Ok(0) | Err(_) => break, // EOF or pipe error
                        Ok(n) => {
                            let mut chunk = &buf[..n];
                            while !chunk.is_empty() && !stop.load(Ordering::Acquire) {
                                match bridge.push_frame(chunk) {
                                    PushOutcome::Rejected => {
                                        // Backpressure: hold the chunk, let the
                                        // pipe fill behind us.
                                        std::thread::sleep(Duration::from_millis(1));
                                    }
                                    _ => chunk = &[],
                                }
                            }
                        }
                    }
                }
            })
        };

        // Writer: outbound bridge → child stdin. Exits on stop flag or broken
        // pipe; parks briefly when idle.
        let writer = {
            let bridge = Arc::clone(&stdin_bridge);
            let stop = Arc::clone(&stop);
            let mut sink = child.stdin.take().expect("stdin piped");
            std::thread::spawn(move || {
                let mut buf = [0u8; BRIDGE_CAP];
                loop {
                    if let Some(n) = bridge.pop_frame(&mut buf) {
                        if sink.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = sink.flush();
                    } else {
                        if stop.load(Ordering::Acquire) {
                            break; // drained + stopping
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })
        };

        Ok(ProcExecutor {
            owner,
            child,
            stdout_bridge,
            stdin_bridge,
            stop,
            reader: Some(reader),
            writer: Some(writer),
        })
    }

    /// Non-blocking: next stdout chunk, if any. Called from `module_step`.
    pub fn poll_stdout(&self, out: &mut [u8]) -> Option<usize> {
        self.stdout_bridge.pop_frame(out)
    }

    /// Non-blocking: enqueue bytes toward child stdin. Called from
    /// `module_step`; `Rejected` means the bounded queue is full and the proxy
    /// applies its declared policy.
    pub fn send_stdin(&self, bytes: &[u8]) -> PushOutcome {
        self.stdin_bridge.push_frame(bytes)
    }

    /// Frames dropped by the inbound overload policy (owner telemetry).
    pub fn stdout_dropped(&self) -> u32 {
        self.stdout_bridge.dropped_frames()
    }

    /// NotReady latch from the inbound bridge (workload health aggregation).
    pub fn not_ready(&self) -> bool {
        self.stdout_bridge.not_ready()
    }

    /// Non-blocking liveness probe.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// §6.8 quiesce order: stop new bridge reads, signal the process (SIGTERM),
    /// wait out the bounded drain deadline, then SIGKILL. Returns true if the
    /// process exited within `grace` (false = it needed the kill).
    pub fn shutdown(&mut self, grace: Duration) -> bool {
        self.stop.store(true, Ordering::Release);
        // SAFETY: signalling our own child pid with SIGTERM.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + grace;
        let graceful = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => break false,
            }
        };
        if !graceful {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(h) = self.reader.take() {
            let _ = h.join();
        }
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
        graceful
    }
}

impl Drop for ProcExecutor {
    /// Last line of defence for §14 invariant 9: the external process cannot
    /// outlive owner revocation. Normal teardown goes through `shutdown`.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
