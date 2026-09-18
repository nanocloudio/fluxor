// Shared TLS 1.3 handshake state-machine pump steps. Each function
// drives one transition on a `HandshakeDriver`, queueing any outbound
// message via `driver.write_handshake_message()` and reading inbound
// flights via `driver.read_handshake_message()`. Per-transport
// modules (`tls`, `dtls`) wrap these in thin functions that supply
// the per-transport state-shape access (`s.sessions[idx].driver`
// vs `s.sessions[idx].endpoint.driver`) plus any transport-specific
// extras (TLS ALPN, mTLS, ChangeCipherSpec).

/// Build + queue Finished, save the transcript hash for app-key
/// derivation, and transition to RecvClientFinished (server) or
/// ClientDeriveAppKeys (client). Server-side mTLS callers may
/// override the next state to RecvClientCert after this returns.
unsafe fn pump_send_finished_core(driver: &mut HandshakeDriver) -> bool {
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let ks = match &driver.key_schedule {
        Some(k) => k,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let base_key = if driver.is_server {
        &ks.server_hs_secret
    } else {
        &ks.client_hs_secret
    };
    let finished_key = ks.compute_finished(base_key);
    let verify_data = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
    let msg_len = build_finished(&verify_data[..hl], hl, &mut driver.scratch);
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    if let Some(ref t) = driver.transcript {
        driver.server_finished_hash = t.current_hash();
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    if driver.is_server {
        driver.hs_state = HandshakeState::RecvClientFinished;
    } else {
        driver.hs_state = HandshakeState::ClientDeriveAppKeys;
    }
    true
}

/// Derive the application traffic secrets from the saved
/// transcript-hash-at-server-Finished, build TrafficKeys for both
/// directions, and transition to Complete. Returns the
/// `(write_keys, read_keys)` pair so per-transport callers can
/// install them onto their own session shape; returns None if the
/// key_schedule is missing.
unsafe fn pump_derive_app_keys_core(
    driver: &mut HandshakeDriver,
) -> Option<(TrafficKeys, TrafficKeys)> {
    let hl = driver.suite.hash_len();
    let transcript_hash = driver.server_finished_hash;
    let suite = driver.suite;
    let is_server = driver.is_server;
    let pair = if let Some(ref mut ks) = driver.key_schedule {
        ks.derive_app_secrets(&transcript_hash[..hl]);
        if is_server {
            (
                TrafficKeys::from_secret(suite, &ks.server_app_secret[..hl]),
                TrafficKeys::from_secret(suite, &ks.client_app_secret[..hl]),
            )
        } else {
            (
                TrafficKeys::from_secret(suite, &ks.client_app_secret[..hl]),
                TrafficKeys::from_secret(suite, &ks.server_app_secret[..hl]),
            )
        }
    } else {
        return None;
    };
    driver.hs_state = HandshakeState::Complete;
    Some(pair)
}

/// Step the ECDH ladder, finalise the shared secret on completion,
/// derive handshake secrets via the key schedule, and produce the
/// `(write_keys, read_keys)` pair. Returns `None` when the ECDH
/// ladder is still running (state unchanged) or on error
/// (`driver.hs_state = Error`); on Some, transitions to
/// SendEncryptedExtensions (server) or RecvEncryptedExtensions
/// (client). `bits_per_step` controls the ladder's per-step yield
/// granularity (0 = run to completion in one call).
unsafe fn pump_derive_handshake_keys_core(
    driver: &mut HandshakeDriver,
    bits_per_step: u8,
) -> Option<(TrafficKeys, TrafficKeys)> {
    let shared = if driver.group == GROUP_X25519 {
        // The agreement ladder, `bits_per_step` bits per call, like the
        // P-256 ladder below.
        if driver.peer_key_share_len as usize != X25519_SHARE_LEN {
            driver.hs_state = HandshakeState::Error;
            return None;
        }
        if !driver.x25519_state.is_initialised() {
            let mut peer_u = [0u8; X25519_SHARE_LEN];
            core::ptr::copy_nonoverlapping(
                driver.peer_key_share.as_ptr(),
                peer_u.as_mut_ptr(),
                X25519_SHARE_LEN,
            );
            driver.x25519_state = X25519State::new(&driver.x25519_private, &peer_u, bits_per_step);
            return None;
        }
        if !driver.x25519_state.step() {
            return None;
        }
        let shared = driver.x25519_state.shared_secret();
        driver.x25519_state.zeroise();
        match shared {
            Some(v) => v,
            None => {
                // RFC 7748 §6.1 contributory behaviour: an all-zero
                // output means the peer sent a small-order point and the
                // secret carries none of our contribution. Treating it
                // as a key would hand the session to whoever sent it.
                driver.hs_state = HandshakeState::Error;
                return None;
            }
        }
    } else {
        if !driver.ecdh_state.is_initialised() {
            let new = match ecdh_shared_secret_init(
                &driver.ecdh_private,
                &driver.peer_key_share[..driver.peer_key_share_len as usize],
                bits_per_step,
            ) {
                Some(v) => v,
                None => {
                    driver.hs_state = HandshakeState::Error;
                    return None;
                }
            };
            driver.ecdh_state = new;
            return None;
        }
        if !driver.ecdh_state.complete() {
            driver.ecdh_state.step();
            return None;
        }
        match ecdh_shared_secret_finalise(&driver.ecdh_state) {
            Some(v) => v,
            None => {
                driver.hs_state = HandshakeState::Error;
                return None;
            }
        }
    };
    driver.ecdh_state.zeroise_scalar();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return None;
        }
    };
    let hl = driver.suite.hash_len();
    let suite = driver.suite;
    let is_server = driver.is_server;
    let mut ks = KeySchedule::new(suite);
    ks.derive_handshake_secrets(&shared, &transcript_hash[..hl]);
    let pair = if is_server {
        (
            TrafficKeys::from_secret(suite, &ks.server_hs_secret[..hl]),
            TrafficKeys::from_secret(suite, &ks.client_hs_secret[..hl]),
        )
    } else {
        (
            TrafficKeys::from_secret(suite, &ks.client_hs_secret[..hl]),
            TrafficKeys::from_secret(suite, &ks.server_hs_secret[..hl]),
        )
    };
    driver.key_schedule = Some(ks);
    driver.hs_state = if is_server {
        HandshakeState::SendEncryptedExtensions
    } else {
        HandshakeState::RecvEncryptedExtensions
    };
    Some(pair)
}

/// Client side: read ServerHello, validate version + cipher suite,
/// stash the peer key share, and transition to
/// ClientDeriveHandshakeKeys.
unsafe fn pump_recv_server_hello_core(driver: &mut HandshakeDriver) -> bool {
    let (msg, total, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_SERVER_HELLO {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let hs_data = &msg[..total];
    let sh = match parse_server_hello(&msg[4..total]) {
        Some(h) => h,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    if sh.supported_version != Some(0x0304) {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    // We always offer P-256, so a HelloRetryRequest is fatal.
    if sh.random.len() == 32 && sh.random == HRR_RANDOM {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    driver.suite = match CipherSuite::from_id(sh.cipher_suite) {
        Some(cs) if suite_is_offered(sh.cipher_suite) => cs,
        _ => {
            // RFC 8446 §4.1.3: the server selects from the client's
            // offer. A suite outside it is either a downgrade attempt or
            // a broken peer; either way this endpoint declined to speak
            // it, so it must not start now.
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    if let Some(ref mut t) = driver.transcript {
        t.set_alg(driver.suite.hash_alg());
    }
    // The server selects one group out of what was offered. A P-256
    // share is admitted only if it decodes to a canonical, on-curve,
    // non-identity point; an X25519 share is any 32-byte string, with
    // the contributory-behaviour test applied to the agreement result
    // (RFC 7748 §6.1). A group that was never offered, or a share of
    // the wrong width for the group named, fails the handshake.
    match sh.key_share {
        Some((GROUP_X25519, key_data)) if key_data.len() == X25519_SHARE_LEN => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                X25519_SHARE_LEN,
            );
            driver.peer_key_share_len = X25519_SHARE_LEN as u8;
            driver.group = GROUP_X25519;
        }
        Some((GROUP_SECP256R1, key_data)) if public_point_is_valid(key_data) => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                key_data.len(),
            );
            driver.peer_key_share_len = key_data.len() as u8;
            driver.group = GROUP_SECP256R1;
        }
        _ => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(hs_data);
    }
    driver.hs_state = HandshakeState::ClientDeriveHandshakeKeys;
    true
}

/// Client side: read server Finished, verify the MAC, save the
/// transcript hash for app-key derivation, and transition to
/// SendClientFinished.
unsafe fn pump_recv_server_finished_core(driver: &mut HandshakeDriver) -> bool {
    let (data, len, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_FINISHED {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    // The body must be exactly the suite's hash length before it is
    // read; the reassembler only guarantees the peer-declared length.
    let fin = match parse_finished(&data[4..len], hl) {
        Some(f) => f,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let ks = match &driver.key_schedule {
        Some(k) => k,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let finished_key = ks.compute_finished(&ks.server_hs_secret);
    let expected = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
    let mut diff = 0u8;
    let mut i = 0;
    while i < hl {
        diff |= fin[i] ^ expected[i];
        i += 1;
    }
    if diff != 0 {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&data[..len]);
    }
    if let Some(ref t) = driver.transcript {
        driver.server_finished_hash = t.current_hash();
    }
    // mTLS: if the server sent a CertificateRequest, present our Certificate +
    // CertificateVerify before our Finished. `SendCertificate` →
    // `SendCertificateVerify` are shared with the server flow; `is_server`
    // (false here) selects the client CertificateVerify context and routes the
    // finalise transition to SendClientFinished. App keys already latched from
    // `server_finished_hash`, so the client auth messages don't perturb them.
    driver.hs_state = if driver.client_cert_requested {
        HandshakeState::SendCertificate
    } else {
        HandshakeState::SendClientFinished
    };
    true
}

/// Client side: build + queue our Finished and transition to
/// ClientDeriveAppKeys.
unsafe fn pump_send_client_finished_core(driver: &mut HandshakeDriver) -> bool {
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let ks = match &driver.key_schedule {
        Some(k) => k,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let finished_key = ks.compute_finished(&ks.client_hs_secret);
    let verify_data = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
    let msg_len = build_finished(&verify_data[..hl], hl, &mut driver.scratch);
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hs_state = HandshakeState::ClientDeriveAppKeys;
    true
}

/// Read client Finished, verify the MAC against the transcript, and
/// transition to DeriveAppKeys. Returns false when the message
/// hasn't fully arrived yet; sets `driver.hs_state = Error` on bad
/// message type or MAC mismatch.
unsafe fn pump_recv_client_finished_core(driver: &mut HandshakeDriver) -> bool {
    let (data, len, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_FINISHED {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let ks = match &driver.key_schedule {
        Some(k) => k,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let finished_key = ks.compute_finished(&ks.client_hs_secret);
    let expected = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
    // Exact suite hash length or nothing — see `parse_finished`.
    let fin = match parse_finished(&data[4..len], hl) {
        Some(f) => f,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let mut diff = 0u8;
    let mut i = 0;
    while i < hl {
        diff |= fin[i] ^ expected[i];
        i += 1;
    }
    if diff != 0 {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&data[..len]);
    }
    driver.hs_state = HandshakeState::DeriveAppKeys;
    true
}

/// Build + queue Certificate, update transcript, and transition to
/// SendCertificateVerify.
unsafe fn pump_send_certificate_core(driver: &mut HandshakeDriver, cert: &[u8]) -> bool {
    let msg_len = build_certificate(cert, &mut driver.scratch);
    if msg_len == 0 {
        // The chain does not fit a handshake message; there is no
        // shorter one to send in its place.
        driver.hs_state = HandshakeState::Error;
        return false;
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hs_state = HandshakeState::SendCertificateVerify;
    true
}

/// Build + queue ServerHello, update transcript, and transition to
/// DeriveHandshakeKeys.
unsafe fn pump_send_server_hello_core(driver: &mut HandshakeDriver) -> bool {
    // The share is copied out first: it is echoed in the group the
    // server selected, and the builder needs `scratch` mutably.
    let mut share = [0u8; P256_SHARE_LEN];
    let share_len = if driver.group == GROUP_X25519 {
        core::ptr::copy_nonoverlapping(
            driver.x25519_public.as_ptr(),
            share.as_mut_ptr(),
            X25519_SHARE_LEN,
        );
        X25519_SHARE_LEN
    } else {
        core::ptr::copy_nonoverlapping(
            driver.ecdh_public.as_ptr(),
            share.as_mut_ptr(),
            P256_SHARE_LEN,
        );
        P256_SHARE_LEN
    };
    let msg_len = build_server_hello(
        &driver.server_random,
        &driver.peer_session_id[..driver.peer_session_id_len as usize],
        driver.suite,
        driver.group,
        &share[..share_len],
        &mut driver.scratch,
    );
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hs_state = HandshakeState::DeriveHandshakeKeys;
    true
}

/// Build + queue a HelloRetryRequest, replace the transcript with a
/// synthetic `message_hash(CH1)` per RFC 8446 §4.4.1, and transition
/// to RecvSecondClientHello.
unsafe fn pump_send_hello_retry_core(driver: &mut HandshakeDriver) -> bool {
    let msg_len = build_hello_retry_request(
        &driver.peer_session_id[..driver.peer_session_id_len as usize],
        driver.suite,
        &mut driver.scratch,
    );
    if let Some(ref mut t) = driver.transcript {
        let ch1_hash = t.current_hash();
        let hl = driver.suite.hash_len();
        *t = Transcript::new(driver.suite.hash_alg());
        let mut synthetic = [0u8; 4 + 48];
        synthetic[0] = 254;
        synthetic[3] = hl as u8;
        core::ptr::copy_nonoverlapping(ch1_hash.as_ptr(), synthetic.as_mut_ptr().add(4), hl);
        t.update(&synthetic[..4 + hl]);
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hrr_sent = true;
    driver.hs_state = HandshakeState::RecvSecondClientHello;
    true
}
