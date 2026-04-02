//! WiFi operation state machines for CYW43.
//!
//! Each WiFi operation (scan, connect, disconnect) is a multi-step sequence
//! of gSPI ioctl commands. These are driven by the main `module_step()` loop
//! when the module is in `PHASE_RUNNING`.

use super::constants::*;
use super::gspi;
use super::Cyw43State;
use super::SyscallTable;
use super::abi::dev_timer;

/// Get monotonic time in milliseconds via dev_call.
unsafe fn get_millis(s: &Cyw43State) -> u64 {
    let sys = &*s.syscalls;
    let mut buf = [0u8; 8];
    (sys.dev_call)(-1, dev_timer::MILLIS, buf.as_mut_ptr(), 8);
    u64::from_le_bytes(buf)
}

// ============================================================================
// WiFi Operation State
// ============================================================================

/// Pending WiFi operation
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WifiOp {
    None = 0,
    Connect = 1,
    Disconnect = 2,
    Scan = 3,
}

/// Connect sub-steps
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnectStep {
    SetInfra = 0,       // Entry: ampdu_ba_wsize
    SetAuth = 2,        // SET_AUTH
    SetWsec = 4,        // SET_WSEC
    // WPA2 path
    SetWpaAuth = 6,     // SET_WPA_AUTH (PSK)
    SetPmk = 8,         // SET_WSEC_PMK
    SetSsid = 10,       // SET_SSID (triggers association)
    Done = 12,
    // WPA3 path
    SetMfp = 13,        // MFP (management frame protection)
    SetWpaAuthSae = 15, // SET_WPA_AUTH (SAE)
    SetSaePassword = 17, // sae_password
    // Internal supplicant enable (for both WPA2 and WPA3)
    SetSupWpa = 19,     // sup_wpa
    SetSupWpa2Eapver = 21, // sup_wpa2_eapver
    SetSupWpaTmo = 23,  // sup_wpa_tmo
    // Delay before credentials (firmware needs time to apply supplicant config)
    DelaySaePassword = 25,
    // SET_INFRA before association (after security config)
    SetInfraPost = 26,
    // Barrier: wait for all ioctl responses before SET_SSID
    WaitIoctlBarrier = 28,
    // Backoff: AP sent Association Comeback via Timeout Interval IE
    WaitComeback = 29,
    // Limit firmware internal association retries (before SET_SSID)
    SetAssocRetry = 30,
}

// ============================================================================
// Ioctl Helpers
// ============================================================================

/// Send an ioctl SET command with a u32 payload.
/// Builds SDPCM + CDC frame and sends via WLAN function.
pub unsafe fn ioctl_set_u32(
    s: &mut Cyw43State,
    cmd: u32,
    value: u32,
) -> i32 {
    let payload = value.to_le_bytes();
    ioctl_set(s, cmd, &payload)
}

/// Send an ioctl SET command with arbitrary payload.
pub unsafe fn ioctl_set(
    s: &mut Cyw43State,
    cmd: u32,
    payload: &[u8],
) -> i32 {
    let hdr_len = gspi::build_ioctl_header(
        &mut s.frame_buf,
        SDPCM_CHAN_CONTROL,
        s.sdpcm_seq,
        cmd,
        0, // interface 0
        payload.len(),
    );

    // Copy payload after header (pointer-based to avoid bounds checks)
    let dst = s.frame_buf.as_mut_ptr().add(hdr_len);
    let mut i = 0;
    while i < payload.len() {
        *dst.add(i) = *payload.as_ptr().add(i);
        i += 1;
    }

    let total = hdr_len + payload.len();
    s.pending_ioctl_id = s.sdpcm_seq as u16; // CDC id = seq before increment
    s.pending_ioctl_status = -1; // no response yet
    s.sdpcm_seq = s.sdpcm_seq.wrapping_add(1);
    s.ioctl_send_count = s.ioctl_send_count.wrapping_add(1);

    // Send via WLAN function
    gspi::wlan_write_start(s, s.frame_buf.as_ptr(), total)
}

/// Send an ioctl SET_VAR command (set an iovar by name).
pub unsafe fn ioctl_set_var(
    s: &mut Cyw43State,
    name: &[u8],
    value: &[u8],
) -> i32 {
    // Build payload: name (null-terminated) + value
    let name_len = name.len();
    let payload_len = name_len + value.len();

    let hdr_len = gspi::build_ioctl_header(
        &mut s.frame_buf,
        SDPCM_CHAN_CONTROL,
        s.sdpcm_seq,
        WLC_SET_VAR,
        0,
        payload_len,
    );

    // Copy name (pointer-based)
    let dst = s.frame_buf.as_mut_ptr().add(hdr_len);
    let mut i = 0;
    while i < name_len {
        *dst.add(i) = *name.as_ptr().add(i);
        i += 1;
    }

    // Copy value
    let dst2 = dst.add(name_len);
    i = 0;
    while i < value.len() {
        *dst2.add(i) = *value.as_ptr().add(i);
        i += 1;
    }

    let total = hdr_len + payload_len;
    s.pending_ioctl_id = s.sdpcm_seq as u16;
    s.pending_ioctl_status = -1;
    s.sdpcm_seq = s.sdpcm_seq.wrapping_add(1);
    s.ioctl_send_count = s.ioctl_send_count.wrapping_add(1);

    gspi::wlan_write_start(s, s.frame_buf.as_ptr(), total)
}

// ============================================================================
// Synchronous Ioctl Helpers (send + txn_poll in one step)
// ============================================================================

/// Synchronous ioctl SET: send + complete gSPI transaction.
/// Returns 0 on success, negative on SPI error.
pub unsafe fn ioctl_set_sync(
    s: &mut Cyw43State,
    cmd: u32,
    payload: &[u8],
) -> i32 {
    let r = ioctl_set(s, cmd, payload);
    if r < 0 { return r; }
    gspi::txn_poll(s);
    0
}

/// Synchronous ioctl SET_VAR: send + complete gSPI transaction.
pub unsafe fn ioctl_set_var_sync(
    s: &mut Cyw43State,
    name: &[u8],
    value: &[u8],
) -> i32 {
    let r = ioctl_set_var(s, name, value);
    if r < 0 { return r; }
    gspi::txn_poll(s);
    0
}

/// Synchronous ioctl SET u32: send + complete gSPI transaction.
pub unsafe fn ioctl_set_u32_sync(
    s: &mut Cyw43State,
    cmd: u32,
    value: u32,
) -> i32 {
    let r = ioctl_set_u32(s, cmd, value);
    if r < 0 { return r; }
    gspi::txn_poll(s);
    0
}

// ============================================================================
// Ioctl GET Helpers
// ============================================================================

/// Send an ioctl GET_VAR command (read an iovar by name).
/// The variable name is sent as payload; the firmware returns the value
/// in the F2 response frame's CDC payload.
pub unsafe fn ioctl_get_var(
    s: &mut Cyw43State,
    name: &[u8],
    buf_len: usize,
) -> i32 {
    // For GET, payload_len should be max(name.len(), expected response size)
    // The firmware uses the same buffer for response data.
    let payload_len = if name.len() > buf_len { name.len() } else { buf_len };

    let hdr_len = gspi::build_ioctl_header_get(
        &mut s.frame_buf,
        SDPCM_CHAN_CONTROL,
        s.sdpcm_seq,
        WLC_GET_VAR,
        0,
        payload_len,
    );

    // Copy variable name (null-terminated)
    let dst = s.frame_buf.as_mut_ptr().add(hdr_len);
    let mut i = 0;
    while i < name.len() {
        *dst.add(i) = *name.as_ptr().add(i);
        i += 1;
    }
    // Zero-pad remaining payload
    while i < payload_len {
        *dst.add(i) = 0;
        i += 1;
    }

    let total = hdr_len + payload_len;
    s.pending_ioctl_id = s.sdpcm_seq as u16;
    s.pending_ioctl_status = -1;
    s.sdpcm_seq = s.sdpcm_seq.wrapping_add(1);
    s.ioctl_send_count = s.ioctl_send_count.wrapping_add(1);

    gspi::wlan_write_start(s, s.frame_buf.as_ptr(), total)
}

// ============================================================================
// Connect State Machine
// ============================================================================

/// Drive the WiFi connect sequence.
///
/// Matches Embassy cyw43 ioctl ordering exactly:
///   Common:  WSEC → sup_wpa → sup_wpa2_eapver → sup_wpa_tmo → [100ms]
///   WPA3:    sae_password
///   WPA2:    PMK
///   Common:  SET_INFRA → SET_AUTH → mfp → SET_WPA_AUTH → SET_SSID
///
/// Returns:
///   0 = still in progress
///   1 = connected
///   <0 = error
pub unsafe fn step_connect(s: &mut Cyw43State) -> i32 {
    match ConnectStep::from_u8(s.wifi_substep) {
        // ── Entry point: ampdu_ba_wsize=8 (Embassy sets this first) ──
        ConnectStep::SetInfra => {
            if s.security == SECURITY_OPEN {
                // Open network connect path not yet implemented
                super::log_error(s, b"cyw43: open networks not supported");
                return -1;
            }
            s.ioctl_send_count = 0;
            s.ioctl_recv_count = 0;
            s.ioctl_error_seen = false;
            s.comeback_ms = 0;
            let r = ioctl_set_var_sync(s, IOVAR_AMPDU_BA_WSIZE, &8u32.to_le_bytes());
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetWsec as u8;
            0
        }

        // ── 1. SET_WSEC (encryption type) ───────────────────────────
        ConnectStep::SetWsec => {
            let r = ioctl_set_u32_sync(s, WLC_SET_WSEC, WSEC_AES);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetSupWpa as u8;
            0
        }

        // ── 2. sup_wpa (enable internal WPA supplicant) ─────────────
        ConnectStep::SetSupWpa => {
            let mut val = [0u8; 8];
            // iface_idx = 0, value = 1 (enable)
            val[4] = 1;
            let r = ioctl_set_var_sync(s, IOVAR_BSSCFG_SUP_WPA, &val);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetSupWpa2Eapver as u8;
            0
        }

        // ── 3. sup_wpa2_eapver ──────────────────────────────────────
        ConnectStep::SetSupWpa2Eapver => {
            let mut val = [0u8; 8];
            // iface_idx = 0, value = 0xFFFFFFFF (-1, auto)
            val[4] = 0xFF; val[5] = 0xFF; val[6] = 0xFF; val[7] = 0xFF;
            let r = ioctl_set_var_sync(s, IOVAR_BSSCFG_SUP_WPA2_EAPVER, &val);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetSupWpaTmo as u8;
            0
        }

        // ── 4. sup_wpa_tmo ──────────────────────────────────────────
        ConnectStep::SetSupWpaTmo => {
            let mut val = [0u8; 8];
            // iface_idx = 0, value = 2500ms (0x09C4)
            val[4] = 0xC4; val[5] = 0x09;
            let r = ioctl_set_var_sync(s, IOVAR_BSSCFG_SUP_WPA_TMO, &val);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::DelaySaePassword as u8;
            s.delay_start = get_millis(s);
            0
        }

        // ── 5. Pre-credential delay (firmware needs time to apply supplicant config) ──
        ConnectStep::DelaySaePassword => {
            let now = get_millis(s);
            // WPA3 (SAE): 100ms for full supplicant init
            // WPA2 (PMK): 50ms is sufficient
            let delay = if s.security == SECURITY_WPA3 { 100 } else { 50 };
            if now.wrapping_sub(s.delay_start) < delay {
                return 0; // Keep waiting
            }
            // Branch: WPA3 → sae_password, WPA2 → PMK
            if s.security == SECURITY_WPA3 {
                s.wifi_substep = ConnectStep::SetSaePassword as u8;
            } else {
                s.wifi_substep = ConnectStep::SetPmk as u8;
            }
            0
        }

        // ── 6a. WPA3: sae_password ──────────────────────────────────
        ConnectStep::SetSaePassword => {
            // SaePassphraseInfo: len(u16 LE) + passphrase([u8; 128]) = 130 bytes
            let pass_len = s.pass_len as usize;
            let mut pfi = [0u8; 130];
            let pp = pfi.as_mut_ptr();
            *pp = (pass_len & 0xFF) as u8;
            *pp.add(1) = ((pass_len >> 8) & 0xFF) as u8;
            let src = s.password.as_ptr();
            let mut i = 0;
            while i < pass_len && i < 128 {
                *pp.add(2 + i) = *src.add(i);
                i += 1;
            }
            let r = ioctl_set_var_sync(s, IOVAR_SAE_PASSWORD, &pfi);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetInfraPost as u8;
            0
        }

        // ── 6b. WPA2: PMK ───────────────────────────────────────────
        ConnectStep::SetPmk => {
            let pass_len = s.pass_len as usize;
            let mut pmk = [0u8; 68];
            pmk[0] = (pass_len & 0xFF) as u8;
            pmk[1] = ((pass_len >> 8) & 0xFF) as u8;
            pmk[2] = 0x01; // flags: raw key
            let mut i = 0;
            while i < pass_len && i < MAX_PASS_LEN {
                pmk[4 + i] = s.password[i];
                i += 1;
            }
            let r = ioctl_set_sync(s, WLC_SET_WSEC_PMK, &pmk);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetInfraPost as u8;
            0
        }

        // ── 7. SET_INFRA (station mode) ─────────────────────────────
        // SET_INFRA — set station (infrastructure) mode
        ConnectStep::SetInfraPost => {
            let r = ioctl_set_u32_sync(s, WLC_SET_INFRA, INFRA_STA);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetAuth as u8;
            0
        }

        // ── 8. SET_AUTH ─────────────────────────────────────────────
        ConnectStep::SetAuth => {
            let auth = if s.security == SECURITY_WPA3 { AUTH_SAE } else { AUTH_OPEN };
            let r = ioctl_set_u32_sync(s, WLC_SET_AUTH, auth);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetMfp as u8;
            0
        }

        // ── 9. MFP (Management Frame Protection) ────────────────────
        ConnectStep::SetMfp => {
            // WPA3: MFP_REQUIRED (2), WPA2: MFP_CAPABLE (1)
            let mfp = if s.security == SECURITY_WPA3 { MFP_REQUIRED } else { MFP_CAPABLE };
            let r = ioctl_set_var_sync(s, IOVAR_MFP, &mfp.to_le_bytes());
            if r < 0 { return r; }
            // Branch by security type
            if s.security == SECURITY_WPA3 {
                s.wifi_substep = ConnectStep::SetWpaAuthSae as u8;
            } else {
                s.wifi_substep = ConnectStep::SetWpaAuth as u8;
            }
            0
        }

        // ── 10a. WPA3: SET_WPA_AUTH (SAE flag) ──────────────────────
        ConnectStep::SetWpaAuthSae => {
            let r = ioctl_set_var_sync(s, IOVAR_WPA_AUTH, &WPA3_AUTH_SAE.to_le_bytes());
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetAssocRetry as u8;
            0
        }

        // ── 10b. WPA2: SET_WPA_AUTH (PSK flag) ──────────────────────
        ConnectStep::SetWpaAuth => {
            let r = ioctl_set_u32_sync(s, WLC_SET_WPA_AUTH, WPA2_AUTH_PSK);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::SetAssocRetry as u8;
            0
        }

        // ── Limit firmware association retries to 1 ─────────────
        ConnectStep::SetAssocRetry => {
            let r = ioctl_set_var_sync(s, IOVAR_ASSOC_RETRY_MAX, &1u32.to_le_bytes());
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::WaitIoctlBarrier as u8;
            0
        }

        // ── Barrier: wait for all ioctl responses before join ──────
        ConnectStep::WaitIoctlBarrier => {
            // The firmware processes ioctls asynchronously. txn_poll only
            // confirms the SPI write reached the chip FIFO. Wait until
            // channel-0 responses arrive for every sent ioctl, proving
            // the firmware has fully applied the security config.
            // Wrapping-safe: check that (send - recv) is small and positive
            let pending = s.ioctl_send_count.wrapping_sub(s.ioctl_recv_count);
            if pending > 0 {
                return 0; // Keep polling frames (step_running falls through)
            }
            // Check if any ioctl was rejected by firmware
            if s.ioctl_error_seen {
                super::log_error(s, b"cyw43: ioctl rejected");
                return -1; // Abort connect
            }
            s.wifi_substep = ConnectStep::SetSsid as u8;
            0
        }

        // ── 11. SET_SSID (triggers association) ─────────────────────
        ConnectStep::SetSsid => {
            let ssid_len = s.ssid_len as usize;
            let mut ssid_param = [0u8; 36];
            ssid_param[0] = (ssid_len & 0xFF) as u8;
            let mut i = 0;
            while i < ssid_len && i < MAX_SSID_LEN {
                ssid_param[4 + i] = s.ssid[i];
                i += 1;
            }
            let r = ioctl_set_sync(s, WLC_SET_SSID, &ssid_param);
            if r < 0 { return r; }
            s.wifi_substep = ConnectStep::Done as u8;
            1 // Connect sequence complete (association in progress)
        }

        ConnectStep::Done => 1,

        // ── Comeback backoff: AP sent Timeout Interval IE ────────
        // Phase 1 (delay_start==0): send DISASSOC to abort firmware retries
        // Phase 2 (delay_start!=0): wait comeback_ms + margin, then restart
        ConnectStep::WaitComeback => {
            if s.delay_start == 0 {
                // Send DISASSOC to stop firmware's internal retry storm
                let r = ioctl_set_u32(s, WLC_DISASSOC, 0);
                if r < 0 { return r; }
                s.delay_start = get_millis(s);
                return 0;
            }
            // Drain DISASSOC txn (don't care about result)
            let _ = gspi::txn_poll(s);
            let now = get_millis(s);
            // Wait comeback_ms + 200ms margin (TU≈1.024ms, so add margin)
            let wait = (s.comeback_ms as u64) + 200;
            if now.wrapping_sub(s.delay_start) < wait {
                return 0; // Keep waiting
            }
            // Backoff complete — restart connect from beginning
            s.comeback_ms = 0;
            s.delay_start = 0;
            s.wifi_substep = ConnectStep::SetInfra as u8;
            0
        }
    }
}

/// Drive the WiFi disconnect sequence.
/// Single-step: send WLC_DISASSOC synchronously.
///
/// Returns:
///   1 = disconnected
///   <0 = error
pub unsafe fn step_disconnect(s: &mut Cyw43State) -> i32 {
    let r = ioctl_set_u32_sync(s, WLC_DISASSOC, 0);
    if r < 0 { return r; }
    1 // Disconnect complete
}

// ============================================================================
// Scan State Machine
// ============================================================================

/// Scan sub-steps
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanStep {
    SetPassiveScan = 0,
    SendEscan = 2,
    Collecting = 4,
    Done = 5,
}

impl ScanStep {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::SetPassiveScan,
            2 => Self::SendEscan,
            4 => Self::Collecting,
            5 => Self::Done,
            _ => Self::SetPassiveScan,
        }
    }
}

/// Drive the WiFi scan sequence.
///
/// Returns:
///   0 = still in progress
///   1 = scan complete
///   <0 = error
pub unsafe fn step_scan(s: &mut Cyw43State) -> i32 {
    match ScanStep::from_u8(s.wifi_substep) {
        ScanStep::SetPassiveScan => {
            // Active scan (passive = 0)
            let r = ioctl_set_u32_sync(s, WLC_SET_PASSIVE_SCAN, 0);
            if r < 0 { return r; }
            s.wifi_substep = ScanStep::SendEscan as u8;
            0
        }
        ScanStep::SendEscan => {
            // Build escan_params_t:
            //   version: u32 LE = 1            [0..4]
            //   action:  u16 LE = START (1)     [4..6]
            //   sync_id: u16 LE                 [6..8]
            //   scan_params_t:                  [8..]
            //     ssid_len: u32 LE = 0          [8..12]  (broadcast)
            //     ssid: [u8; 32] = zeros        [12..44]
            //     bssid: [u8; 6] = FF×6         [44..50]
            //     bss_type: i8 = ANY (2)        [50]
            //     scan_type: i8 = 0 (active)    [51]
            //     nprobes: i32 LE = -1          [52..56]
            //     active_time: i32 LE = -1      [56..60]
            //     passive_time: i32 LE = -1     [60..64]
            //     home_time: i32 LE = -1        [64..68]
            //     channel_num: i32 LE = 0       [68..72] (all channels)
            let mut params = [0u8; 72];

            // version = 1
            params[0] = 1;

            // action = WL_SCAN_ACTION_START (1)
            params[4] = 1;

            // sync_id
            s.scan_sync_id = s.scan_sync_id.wrapping_add(1);
            params[6] = (s.scan_sync_id & 0xFF) as u8;
            params[7] = (s.scan_sync_id >> 8) as u8;

            // bssid = broadcast (FF:FF:FF:FF:FF:FF)
            params[44] = 0xFF;
            params[45] = 0xFF;
            params[46] = 0xFF;
            params[47] = 0xFF;
            params[48] = 0xFF;
            params[49] = 0xFF;

            // bss_type = ANY
            params[50] = DOT11_BSSTYPE_ANY;

            // scan_type = 0 (active) — already zero

            // nprobes = -1 (default)
            params[52] = 0xFF;
            params[53] = 0xFF;
            params[54] = 0xFF;
            params[55] = 0xFF;

            // active_time = -1
            params[56] = 0xFF;
            params[57] = 0xFF;
            params[58] = 0xFF;
            params[59] = 0xFF;

            // passive_time = -1
            params[60] = 0xFF;
            params[61] = 0xFF;
            params[62] = 0xFF;
            params[63] = 0xFF;

            // home_time = -1
            params[64] = 0xFF;
            params[65] = 0xFF;
            params[66] = 0xFF;
            params[67] = 0xFF;

            // channel_num = 0 (all channels) — already zero

            let r = ioctl_set_var_sync(s, IOVAR_ESCAN, &params);
            if r < 0 { return r; }
            s.scan_active = true;
            s.scan_count = 0;

            // Write header to scan output channel
            if s.scan_out_chan >= 0 {
                let sys = &*s.syscalls;
                let msg = b"--- WiFi Scan ---\n";
                (sys.channel_write)(s.scan_out_chan, msg.as_ptr(), msg.len());
            }

            s.wifi_substep = ScanStep::Collecting as u8;
            0
        }
        ScanStep::Collecting => {
            // ESCAN_RESULT events are handled in process_rx_frame.
            // When scan_active becomes false (final event received), return 1.
            if !s.scan_active {
                s.wifi_substep = ScanStep::Done as u8;
                return 1;
            }
            0
        }
        ScanStep::Done => 1,
    }
}

// ============================================================================
// Helpers
// ============================================================================

impl ConnectStep {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::SetInfra,
            2 => Self::SetAuth,
            4 => Self::SetWsec,
            6 => Self::SetWpaAuth,
            8 => Self::SetPmk,
            10 => Self::SetSsid,
            12 => Self::Done,
            13 => Self::SetMfp,
            15 => Self::SetWpaAuthSae,
            17 => Self::SetSaePassword,
            19 => Self::SetSupWpa,
            21 => Self::SetSupWpa2Eapver,
            23 => Self::SetSupWpaTmo,
            25 => Self::DelaySaePassword,
            26 => Self::SetInfraPost,
            28 => Self::WaitIoctlBarrier,
            29 => Self::WaitComeback,
            30 => Self::SetAssocRetry,
            _ => Self::SetInfra,
        }
    }
}
