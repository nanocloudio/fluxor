//! WiFi module constants.

/// Association timeout (ms)
pub const ASSOCIATE_TIMEOUT_MS: u64 = 15000;
/// Monitor poll interval (ms)
pub const MONITOR_INTERVAL_MS: u64 = 5000;
/// Reconnect delay (ms)
pub const RECONNECT_DELAY_MS: u64 = 3000;
/// Max retries before longer backoff
pub const MAX_QUICK_RETRIES: u8 = 5;

/// WiFi connection state machine phases.
///
/// Ref: IEEE 802.11 association sequence (simplified).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum WifiPhase {
    Init = 0,
    NetifOpen = 1,
    WaitReady = 2,
    Associate = 3,
    WaitConnected = 4,
    Connected = 5,
    Monitor = 6,
    Disconnected = 7,
    Scan = 8,
    ScanDone = 9,
    CollectScan = 10,
    SelectNetwork = 11,
}

/// Binary scan result record size (must match cyw43/constants.rs)
pub const SCAN_RESULT_SIZE: usize = 36;

/// Maximum scan results to track for auto-selection
pub const MAX_SCAN_RESULTS: usize = 16;

/// Max SSID / password lengths
pub const MAX_SSID_LEN: usize = 32;
pub const MAX_PASS_LEN: usize = 64;

/// Association buffer size
pub const ASSOC_BUF_SIZE: usize = 2 + MAX_SSID_LEN + MAX_PASS_LEN; // 98
