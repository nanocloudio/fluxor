//! Observability vocabulary: OpenTelemetry-aligned severity numbers, instrument
//! kinds, and the canonical attribute-key set shared across logs, metrics, and
//! traces.
//!
//! Attribute keys are the one *global* observability vocabulary — instrument
//! *names* are declared per module (see `standards/observability.md`). Keys
//! reuse OpenTelemetry semantic conventions where they exist, with a `fluxor.*`
//! namespace for engine-specific concepts. All keys are dotted lowercase,
//! matching the capability-surface grammar.

/// OpenTelemetry `SeverityNumber` for each log level. The number, not the
/// textual level, crosses the wire, so a collector can map to any backend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Severity {
    Trace = 1,
    Debug = 5,
    Info = 9,
    Warn = 13,
    Error = 17,
    Fatal = 21,
}

impl Severity {
    /// The OpenTelemetry `SeverityNumber`.
    pub const fn number(self) -> u8 {
        self as u8
    }
}

/// The three embedded-safe OpenTelemetry instrument types. No others are
/// permitted on-device (see `standards/observability.md` §3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstrumentKind {
    Counter,
    UpDownCounter,
    Histogram,
}

impl InstrumentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            InstrumentKind::Counter => "counter",
            InstrumentKind::UpDownCounter => "updowncounter",
            InstrumentKind::Histogram => "histogram",
        }
    }
}

/// Canonical attribute keys. OpenTelemetry semantic-convention keys are reused
/// verbatim; the `fluxor.*` namespace covers concepts OTel does not model.
pub mod attr {
    // Resource.
    pub const SERVICE_NAME: &str = "service.name";
    pub const SERVICE_INSTANCE_ID: &str = "service.instance.id";
    pub const SERVICE_VERSION: &str = "service.version";
    pub const HOST_ARCH: &str = "host.arch";
    pub const FLUXOR_BOARD: &str = "fluxor.board";
    pub const FLUXOR_DOMAIN: &str = "fluxor.domain";
    pub const FLUXOR_MODULE_INDEX: &str = "fluxor.module.index";

    // Network.
    pub const NETWORK_TRANSPORT: &str = "network.transport";
    pub const NETWORK_PEER_ADDRESS: &str = "network.peer.address";
    pub const NETWORK_PEER_PORT: &str = "network.peer.port";
    pub const NETWORK_IO_DIRECTION: &str = "network.io.direction";
    pub const FLUXOR_CONN_ID: &str = "fluxor.conn_id";
    pub const FLUXOR_BACKPRESSURE_STEPS: &str = "fluxor.backpressure.steps";

    // TLS.
    pub const TLS_PROTOCOL_VERSION: &str = "tls.protocol.version";
    pub const TLS_CIPHER: &str = "tls.cipher";
    pub const TLS_RESUMED: &str = "tls.resumed";
    pub const FLUXOR_TLS_HANDSHAKE_STAGE: &str = "fluxor.tls.handshake.stage";

    // HTTP.
    pub const HTTP_REQUEST_METHOD: &str = "http.request.method";
    pub const HTTP_ROUTE: &str = "http.route";
    pub const HTTP_RESPONSE_STATUS_CODE: &str = "http.response.status_code";
    pub const FLUXOR_HTTP_KEEPALIVE: &str = "fluxor.http.keepalive";

    // Storage / filesystem.
    pub const STORAGE_OPERATION: &str = "storage.operation";
    pub const STORAGE_IO_SIZE: &str = "storage.io.size";
    pub const FLUXOR_STORAGE_SURFACE: &str = "fluxor.storage.surface";
    pub const FLUXOR_FENCE: &str = "fluxor.fence";

    // Scheduler.
    pub const FLUXOR_MODULE_STEP_DURATION: &str = "fluxor.module.step.duration";
    pub const FLUXOR_TICK: &str = "fluxor.tick";
    pub const FLUXOR_FAULT_KIND: &str = "fluxor.fault.kind";
}

/// Every canonical attribute key, for validation. A declared key must appear
/// here or fall under the `fluxor.*` namespace (see `is_valid_attribute_key`).
pub const ATTRIBUTE_KEYS: &[&str] = &[
    attr::SERVICE_NAME,
    attr::SERVICE_INSTANCE_ID,
    attr::SERVICE_VERSION,
    attr::HOST_ARCH,
    attr::FLUXOR_BOARD,
    attr::FLUXOR_DOMAIN,
    attr::FLUXOR_MODULE_INDEX,
    attr::NETWORK_TRANSPORT,
    attr::NETWORK_PEER_ADDRESS,
    attr::NETWORK_PEER_PORT,
    attr::NETWORK_IO_DIRECTION,
    attr::FLUXOR_CONN_ID,
    attr::FLUXOR_BACKPRESSURE_STEPS,
    attr::TLS_PROTOCOL_VERSION,
    attr::TLS_CIPHER,
    attr::TLS_RESUMED,
    attr::FLUXOR_TLS_HANDSHAKE_STAGE,
    attr::HTTP_REQUEST_METHOD,
    attr::HTTP_ROUTE,
    attr::HTTP_RESPONSE_STATUS_CODE,
    attr::FLUXOR_HTTP_KEEPALIVE,
    attr::STORAGE_OPERATION,
    attr::STORAGE_IO_SIZE,
    attr::FLUXOR_STORAGE_SURFACE,
    attr::FLUXOR_FENCE,
    attr::FLUXOR_MODULE_STEP_DURATION,
    attr::FLUXOR_TICK,
    attr::FLUXOR_FAULT_KIND,
];

/// An attribute key is valid if it is a canonical semantic-convention key or
/// lives under the engine-specific `fluxor.*` namespace.
pub fn is_valid_attribute_key(key: &str) -> bool {
    key.starts_with("fluxor.") || ATTRIBUTE_KEYS.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_numbers_match_otel() {
        assert_eq!(Severity::Trace.number(), 1);
        assert_eq!(Severity::Debug.number(), 5);
        assert_eq!(Severity::Info.number(), 9);
        assert_eq!(Severity::Warn.number(), 13);
        assert_eq!(Severity::Error.number(), 17);
        assert_eq!(Severity::Fatal.number(), 21);
    }

    #[test]
    fn attribute_keys_are_unique_and_dotted_lowercase() {
        for (i, a) in ATTRIBUTE_KEYS.iter().enumerate() {
            assert!(
                a.contains('.')
                    && a.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "attribute key {a:?} is not dotted lowercase"
            );
            for b in &ATTRIBUTE_KEYS[i + 1..] {
                assert_ne!(a, b, "duplicate attribute key {a:?}");
            }
        }
    }

    #[test]
    fn fluxor_namespace_and_canonical_keys_validate() {
        assert!(is_valid_attribute_key("http.request.method"));
        assert!(is_valid_attribute_key("fluxor.anything.custom"));
        assert!(!is_valid_attribute_key("made.up.key"));
    }
}
