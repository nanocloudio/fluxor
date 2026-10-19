//! In-process event types consumed by the matcher.
//!
//! These are NOT the wire format for backend subprocesses — see
//! `rig::backend` for that. They're the internal representation after the
//! backend-protocol decoder has translated one NDJSON line into something
//! the rule engine can evaluate.

use std::time::SystemTime;

use crate::rig::vocab::Capability;

/// Unified event stream consumed by the matcher. Every transport backend
/// the orchestrator attaches publishes into one shared channel so rule
/// evaluation sees events in arrival order. The orchestrator also pushes
/// its own markers into the same channel, so "before the power step" and
/// "after it" are positions in one ordered stream rather than a race
/// between a clock and a queue.
#[derive(Debug)]
pub enum RunEvent {
    /// Raw bytes from a console transport, tagged with the source
    /// capability that produced them. The matcher uses `source` to route
    /// bytes to the correct per-source buffer so a rule that names
    /// `console.serial` is only evaluated against serial output — not
    /// against `console.usb_cdc` bytes that happened to arrive on the
    /// same channel.
    ConsoleBytes { source: Capability, bytes: Vec<u8> },
    /// A transport reports that what follows comes from a target started
    /// for this run (see `TransportEvent::Boot`).
    Boot { source: Capability },
    /// Structured event from a deploy or similar transport.
    DeployProgress(DeployEvent),
    /// A transport exited. The matcher keeps running (another signal may
    /// still decide the verdict); `max_silence_s` rules see it as the
    /// source going quiet, and the orchestrator logs it for the run record.
    TransportClosed { source: Capability, reason: String },
    /// Pushed by the orchestrator just before the first power verb. A
    /// `Boot` that arrives after this marks its source as showing this
    /// run's target; one before it does not.
    PowerStarted,
    /// Pushed by the orchestrator when the last power verb has returned.
    /// Everything after it is this run's.
    PowerDone,
}

#[derive(Debug, Clone)]
pub enum DeployEvent {
    /// The bootloader (or the deploy stack) read our staged artifact.
    /// Triggers any `observe.netboot_fetch` rule that matches the filename.
    ArtifactFetched {
        filename: String,
        client_ip: Option<String>,
        at: SystemTime,
    },
    /// Informational — DHCP DISCOVER/REQUEST etc. Used only for run-log
    /// diagnostics, never for pass/fail evaluation.
    DhcpActivity,
    /// A deploy-side error the transport surfaced. Observers may treat
    /// this as a fail source when the rule's regex matches the message.
    Error(String),
}
