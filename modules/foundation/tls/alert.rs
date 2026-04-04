// TLS 1.3 Alert Protocol (RFC 8446 Section 6)

pub const ALERT_CLOSE_NOTIFY: u8 = 0;
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub const ALERT_BAD_RECORD_MAC: u8 = 20;
pub const ALERT_RECORD_OVERFLOW: u8 = 22;
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_BAD_CERTIFICATE: u8 = 42;
pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INTERNAL_ERROR: u8 = 80;
pub const ALERT_CERTIFICATE_REQUIRED: u8 = 116;

/// Alert level
pub const ALERT_WARNING: u8 = 1;
pub const ALERT_FATAL: u8 = 2;

/// Build a 2-byte alert record body: [level, description]
pub fn build_alert(description: u8) -> [u8; 2] {
    let level = if description == ALERT_CLOSE_NOTIFY {
        ALERT_WARNING
    } else {
        ALERT_FATAL
    };
    [level, description]
}
