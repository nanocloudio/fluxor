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
    let shared = match ecdh_shared_secret_finalise(&driver.ecdh_state) {
        Some(v) => v,
        None => {
            driver.hs_state = HandshakeState::Error;
            return None;
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
        Some(cs) => cs,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    if let Some(ref mut t) = driver.transcript {
        t.set_alg(driver.suite.hash_alg());
    }
    match sh.key_share {
        Some((_, key_data)) if key_data.len() <= 65 => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                key_data.len(),
            );
            driver.peer_key_share_len = key_data.len() as u8;
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

/// Verify a peer's CertificateVerify message against the captured
/// peer cert public key, update the transcript, and advance to the
/// next state. Server-side (mTLS, verifying the client) goes to
/// RecvClientFinished; client-side (verifying the server) goes to
/// RecvFinished. Caller picks the next state via `driver.is_server`
/// implicitly.
unsafe fn pump_recv_certificate_verify_core(driver: &mut HandshakeDriver) -> bool {
    let (data, len, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CERTIFICATE_VERIFY {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if driver.peer_cert_pubkey_len == 0 {
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
    // We're verifying the OTHER side's CV. As server we're checking
    // a client cert (mTLS); as client we're checking the server.
    let context: &[u8] = if driver.is_server {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
    let mut vc = [0u8; 200];
    let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut vc);
    let vc_hash = sha256(&vc[..vc_len]);
    let cv_body = &data[4..len];
    let ok = if let Some((_scheme, sig_der)) = parse_certificate_verify(cv_body) {
        if let Some(raw_sig) = parse_der_signature(sig_der) {
            let pk = &driver.peer_cert_pubkey[..driver.peer_cert_pubkey_len as usize];
            ecdsa_verify(pk, &vc_hash, &raw_sig)
        } else {
            false
        }
    } else {
        false
    };
    if !ok {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&data[..len]);
    }
    driver.hs_state = if driver.is_server {
        HandshakeState::RecvClientFinished
    } else {
        HandshakeState::RecvFinished
    };
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
    if let Some(ref ks) = driver.key_schedule {
        let finished_key = ks.compute_finished(&ks.server_hs_secret);
        let expected = ks.finished_verify_data(&finished_key[..hl], &transcript_hash[..hl]);
        let fin = &data[4..4 + hl];
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
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&data[..len]);
    }
    if let Some(ref t) = driver.transcript {
        driver.server_finished_hash = t.current_hash();
    }
    driver.hs_state = HandshakeState::SendClientFinished;
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
    let fin = &data[4..4 + hl];
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
unsafe fn pump_send_certificate_core(
    driver: &mut HandshakeDriver,
    cert: &[u8],
) -> bool {
    let msg_len = build_certificate(cert, &mut driver.scratch);
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
    let msg_len = build_server_hello(
        &driver.server_random,
        &driver.peer_session_id,
        driver.suite,
        &driver.ecdh_public,
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
        &driver.peer_session_id,
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
