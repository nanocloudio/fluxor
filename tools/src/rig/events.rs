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
/// evaluation sees events in arrival order.
#[derive(Debug)]
pub enum RunEvent {
    /// Raw bytes from a console transport, tagged with the source
    /// capability that produced them. The matcher uses `source` to route
    /// bytes to the correct per-source buffer so a rule that names
    /// `console.serial` is only evaluated against serial output — not
    /// against `console.usb_cdc` bytes that happened to arrive on the
    /// same channel.
    ConsoleBytes { source: Capability, bytes: Vec<u8> },
    /// Structured event from a deploy or similar transport.
    DeployProgress(DeployEvent),
    /// A transport exited unexpectedly. The matcher keeps running (another
    /// signal may still decide the verdict); the orchestrator logs this
    /// for the run record.
    TransportClosed {
        source: &'static str,
        reason: String,
    },
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
