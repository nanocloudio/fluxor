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

/// The host-side grant a spawn is scoped by (the `proc` policy §5): the process
/// starts in `cwd` and inherits ONLY the named env vars — no ambient environment, so
/// node secrets don't leak into `do` children. Empty `cwd` = the node's cwd.
#[derive(Default, Clone)]
pub struct SpawnPolicy {
    pub cwd: Option<std::path::PathBuf>,
    pub env_allow: Vec<String>,
}

/// One owned external process with bounded stdin/stdout bridges. stdout AND stderr are
/// merged into the one inbound bridge (a build's errors go to stderr — you want them).
pub struct ProcExecutor {
    pub owner: OwnerHandle,
    child: Child,
    stdout_bridge: Arc<ExtBridge<BRIDGE_CAP>>,
    stdin_bridge: Arc<ExtBridge<BRIDGE_CAP>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

/// Pump one child pipe (stdout or stderr) into the inbound bridge. The blocking read
/// lives on this thread, off the scheduler; it exits on EOF/error or the stop flag. On
/// overload (a rejecting policy) it holds the chunk so the pipe fills and the child
/// throttles — true end-to-end backpressure.
fn pump_reader<R: Read + Send + 'static>(
    mut src: R,
    bridge: Arc<ExtBridge<BRIDGE_CAP>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break, // EOF or pipe error
                Ok(n) => {
                    let mut chunk = &buf[..n];
                    while !chunk.is_empty() && !stop.load(Ordering::Acquire) {
                        match bridge.push_frame(chunk) {
                            PushOutcome::Rejected => std::thread::sleep(Duration::from_millis(1)),
                            _ => chunk = &[],
                        }
                    }
                }
            }
        }
    })
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
        policy: &SpawnPolicy,
    ) -> std::io::Result<ProcExecutor> {
        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()); // merged into the inbound bridge below
        if let Some(dir) = &policy.cwd {
            command.current_dir(dir);
        }
        // No ambient environment — inherit ONLY the allowlisted names, so node
        // secrets never leak into a `do` child (§5 hygiene).
        command.env_clear();
        for name in &policy.env_allow {
            if let Ok(val) = std::env::var(name) {
                command.env(name, val);
            }
        }
        let mut child = command.spawn()?;

        let stdout_bridge = Arc::new(ExtBridge::<BRIDGE_CAP>::new(stdout_policy));
        // Outbound is always Block: a full queue rejects the proxy's push and
        // the proxy applies its own declared policy — nothing accumulates.
        let stdin_bridge = Arc::new(ExtBridge::<BRIDGE_CAP>::new(OverloadPolicy::Block));
        let stop = Arc::new(AtomicBool::new(false));

        // Two readers (child stdout + stderr) both pump the ONE inbound bridge,
        // so stderr is interleaved with stdout (a build's errors show up). Blocking
        // reads live off the scheduler; each exits on EOF or the stop flag.
        let out = child.stdout.take().expect("stdout piped");
        let err = child.stderr.take().expect("stderr piped");
        let reader = pump_reader(out, Arc::clone(&stdout_bridge), Arc::clone(&stop));
        let stderr_reader = pump_reader(err, Arc::clone(&stdout_bridge), Arc::clone(&stop));

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
            stderr_reader: Some(stderr_reader),
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

    /// The reader thread has finished — the child's stdout hit EOF, so no more
    /// frames will ever be pushed to the inbound bridge. Combined with an empty
    /// bridge this is the race-free "output complete" signal a consumer needs
    /// before declaring the process done (the child can exit while a final chunk
    /// is still in flight from the pipe to the bridge).
    pub fn reader_finished(&self) -> bool {
        self.reader.as_ref().map_or(true, |h| h.is_finished())
            && self
                .stderr_reader
                .as_ref()
                .map_or(true, |h| h.is_finished())
    }

    /// Bytes still buffered in the inbound (stdout) bridge, not yet drained by
    /// the consumer via `poll_stdout`.
    pub fn stdout_pending(&self) -> usize {
        self.stdout_bridge.len_bytes()
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
        if let Some(h) = self.stderr_reader.take() {
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
