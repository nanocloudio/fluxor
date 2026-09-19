// DTLS 1.3 (RFC 9147) state, helpers, and pump dispatcher used when
// `TlsState.transport == TRANSPORT_UDP`. Per-peer sessions live in
// `TlsState.peer_sessions`; channel handles are reused from the
// TLS-mode `cipher_in`/`cipher_out`/`clear_in`/`clear_out` ports
// (the kernel doesn't distinguish stream vs datagram channels — the
// peer wired in determines the byte format).

// ---------------------------------------------------------------------
// Session lookup / allocation
// ---------------------------------------------------------------------

/// True if a peer slot is reusable — either fresh (Idle) or in
/// a terminal state we've already given up on (Errored / Closed).
/// `Handshaking` and `Ready` peers are "live" and must NOT be
/// overwritten by a new session for a different 4-tuple.
fn dtls_slot_reusable(phase: DtlsPhase) -> bool {
    matches!(
        phase,
        DtlsPhase::Idle | DtlsPhase::Errored | DtlsPhase::Closed
    )
}

fn dtls_find_session(s: &TlsState, ip: &[u8; 4], port: u16) -> i32 {
    let mut i = 0;
    while i < MAX_PEERS {
        // Match only against live peers. Errored / Closed slots are
        // tombstones — incoming records for that 4-tuple shouldn't
        // be routed there (the peer either gave up or we tore the
        // session down). The slot stays bound to the address for
        // allocator priority (`dtls_alloc_session` below prefers
        // overwriting the address-matched tombstone before evicting
        // an unrelated one) but the record-receive path treats it
        // as if it doesn't exist.
        let phase = s.peer_sessions[i].phase;
        if (phase == DtlsPhase::Handshaking || phase == DtlsPhase::Ready)
            && s.peer_sessions[i].peer.matches(ip, port)
        {
            return i as i32;
        }
        i += 1;
    }
    -1
}

unsafe fn dtls_alloc_session(s: &mut TlsState, ip: &[u8; 4], port: u16) -> Option<usize> {
    // Two-pass allocation. First pass prefers reusing the slot
    // already keyed to this 4-tuple if it's a tombstone — this is
    // the common case after a handshake timeout where the same
    // peer retries from the same source port. Second pass takes
    // any reusable slot.
    let mut i = 0;
    while i < MAX_PEERS {
        if dtls_slot_reusable(s.peer_sessions[i].phase) && s.peer_sessions[i].peer.matches(ip, port)
        {
            return Some(dtls_init_server_session(s, i, ip, port));
        }
        i += 1;
    }
    i = 0;
    while i < MAX_PEERS {
        if dtls_slot_reusable(s.peer_sessions[i].phase) {
            return Some(dtls_init_server_session(s, i, ip, port));
        }
        i += 1;
    }
    None
}

unsafe fn dtls_init_server_session(s: &mut TlsState, i: usize, ip: &[u8; 4], port: u16) -> usize {
    let sys = &*s.syscalls;
    {
        let sess = &mut s.peer_sessions[i];
        sess.reset();
        sess.peer.ip = *ip;
        sess.peer.port = port;
        sess.phase = DtlsPhase::Handshaking;
        sess.handshake_start_step = s.step_count;
        sess.endpoint.driver.is_server = true;
        sess.endpoint.driver.hs_state = HandshakeState::RecvClientHello;
        sess.endpoint.driver.suite = CipherSuite::ChaCha20Poly1305;
    }
    // Fresh ECDH key per session (forward secrecy). Same helper
    // and same CSPRNG-failure → pool-fallback policy as TCP-TLS
    // (see `assign_fresh_ecdh_key`). On total failure, mark the
    // slot Errored so the allocator's tombstone-reuse path picks
    // it up rather than handing back a session with a zero key.
    let ok = assign_fresh_ecdh_key(
        sys,
        &mut s.peer_sessions[i].endpoint.driver,
        &mut s.eph_private,
        &s.eph_public,
        &mut s.eph_used,
        &mut s.ecdh_pool_hit,
        &mut s.ecdh_fallback_keygen,
    );
    if !ok {
        s.peer_sessions[i].phase = DtlsPhase::Errored;
    }
    i
}

unsafe fn dtls_alloc_client_session(s: &mut TlsState, ip: &[u8; 4], port: u16) -> Option<usize> {
    // Same two-pass strategy as the server-side allocator: prefer
    // overwriting a same-tuple tombstone (handshake-timeout retry
    // is the common case), then fall back to any reusable slot.
    let mut i = 0;
    while i < MAX_PEERS {
        if dtls_slot_reusable(s.peer_sessions[i].phase) && s.peer_sessions[i].peer.matches(ip, port)
        {
            return Some(dtls_init_client_session(s, i, ip, port));
        }
        i += 1;
    }
    i = 0;
    while i < MAX_PEERS {
        if dtls_slot_reusable(s.peer_sessions[i].phase) {
            return Some(dtls_init_client_session(s, i, ip, port));
        }
        i += 1;
    }
    None
}

unsafe fn dtls_init_client_session(s: &mut TlsState, i: usize, ip: &[u8; 4], port: u16) -> usize {
    let sys = &*s.syscalls;
    {
        let sess = &mut s.peer_sessions[i];
        sess.reset();
        sess.peer.ip = *ip;
        sess.peer.port = port;
        sess.phase = DtlsPhase::Handshaking;
        sess.handshake_start_step = s.step_count;
        sess.endpoint.driver.is_server = false;
        sess.endpoint.driver.hs_state = HandshakeState::SendClientHello;
        sess.endpoint.driver.suite = CipherSuite::ChaCha20Poly1305;
    }
    let ok = assign_fresh_ecdh_key(
        sys,
        &mut s.peer_sessions[i].endpoint.driver,
        &mut s.eph_private,
        &s.eph_public,
        &mut s.eph_used,
        &mut s.ecdh_pool_hit,
        &mut s.ecdh_fallback_keygen,
    );
    if !ok {
        s.peer_sessions[i].phase = DtlsPhase::Errored;
    }
    i
}

// ---------------------------------------------------------------------
// Pump dispatcher
// ---------------------------------------------------------------------

unsafe fn dtls_pump_session(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let state = s.peer_sessions[idx].endpoint.driver.hs_state;
    match state {
        HandshakeState::RecvClientHello | HandshakeState::RecvSecondClientHello => {
            dtls_pump_recv_client_hello(s, idx)
        }
        HandshakeState::SendHelloRetryRequest => {
            pump_send_hello_retry_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::SendServerHello => {
            let sys = &*s.syscalls;
            let bits_per_step = ec_bits_per_step(s);
            let driver = &mut s.peer_sessions[idx].endpoint.driver;
            if driver.group == GROUP_X25519 && !x25519_keygen_step(sys, driver, bits_per_step) {
                true
            } else {
                pump_send_server_hello_core(driver)
            }
        }
        HandshakeState::DeriveHandshakeKeys => dtls_pump_derive_handshake_keys(s, idx),
        HandshakeState::SendEncryptedExtensions => dtls_pump_send_encrypted_extensions(s, idx),
        HandshakeState::SendCertificate => {
            let cert_len = if s.cert_len <= MAX_CERT_CHAIN_BYTES {
                s.cert_len
            } else {
                0
            };
            let cert = core::slice::from_raw_parts(s.cert.as_ptr(), cert_len);
            pump_send_certificate_core(&mut s.peer_sessions[idx].endpoint.driver, cert)
        }
        HandshakeState::SendCertificateVerify => dtls_pump_send_certificate_verify(s, idx),
        HandshakeState::SendFinished => {
            pump_send_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::RecvClientFinished => {
            pump_recv_client_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::DeriveAppKeys => dtls_pump_derive_app_keys(s, idx),
        HandshakeState::SendClientHello => dtls_pump_send_client_hello(s, idx),
        HandshakeState::RecvServerHello => {
            pump_recv_server_hello_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::ClientDeriveHandshakeKeys => dtls_pump_derive_handshake_keys(s, idx),
        HandshakeState::RecvEncryptedExtensions => dtls_pump_recv_encrypted_extensions(s, idx),
        HandshakeState::RecvCertificate => dtls_pump_recv_certificate(s, idx),
        HandshakeState::RecvCertificateVerify => {
            pump_recv_certificate_verify_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::VerifyChain | HandshakeState::VerifyPeerSignature => {
            dtls_pump_rsa_verify(s, idx)
        }
        HandshakeState::RecvFinished => {
            pump_recv_server_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::SendClientFinished => {
            pump_send_client_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::ClientDeriveAppKeys => dtls_pump_derive_app_keys(s, idx),
        HandshakeState::Complete => {
            s.peer_sessions[idx].phase = DtlsPhase::Ready;
            dev_log(
                sys,
                3,
                b"[dtls] handshake complete".as_ptr(),
                b"[dtls] handshake complete".len(),
            );
            // Symmetry with TCP-TLS: emit MSG_PEER_IDENTITY for
            // the DTLS peer so RBAC / peer_router consumers see
            // the same envelope regardless of transport. The
            // peer slot index is the per-transport conn_id.
            emit_peer_identity_dtls(s, idx);
            true
        }
        HandshakeState::Error => {
            s.peer_sessions[idx].phase = DtlsPhase::Errored;
            // Drop the cached flight so the §5.8 retx sweep
            // doesn't keep replaying records to a peer whose
            // handshake we just gave up on.
            dtls_disarm_retx(&mut s.peer_sessions[idx]);
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------
// Pump steps with DTLS-specific logic
// ---------------------------------------------------------------------

unsafe fn dtls_pump_recv_client_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let driver = &mut s.peer_sessions[idx].endpoint.driver;

    let (msg, total, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CLIENT_HELLO {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let hs_data = &msg[..total];
    let ch = match parse_client_hello(&msg[4..total]) {
        Some(c) => c,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    if ch.supported_versions != Some(0x0304) {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    driver.suite = match select_cipher_suite(ch.cipher_suites) {
        Some(cs) => cs,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };

    if ch.session_id.len() <= 32 {
        core::ptr::copy_nonoverlapping(
            ch.session_id.as_ptr(),
            driver.peer_session_id.as_mut_ptr(),
            ch.session_id.len(),
        );
        driver.peer_session_id_len = ch.session_id.len() as u8;
    }
    if driver.transcript.is_none() {
        driver.transcript = Some(Transcript::new(driver.suite.hash_alg()));
    }

    // X25519 first, for the same reason as the TLS-over-TCP server: the
    // agreement scalar stays out of P-256's variable-time arithmetic.
    match (ch.key_share_x25519, ch.key_share) {
        (Some(key_data), _) if X25519_OFFERED && key_data.len() == X25519_SHARE_LEN => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                X25519_SHARE_LEN,
            );
            driver.peer_key_share_len = X25519_SHARE_LEN as u8;
            driver.group = GROUP_X25519;
        }
        (_, Some((_, key_data))) if public_point_is_valid(key_data) => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                key_data.len(),
            );
            driver.peer_key_share_len = key_data.len() as u8;
            driver.group = GROUP_SECP256R1;
        }
        _ => {
            // RFC 8446 §4.1.4: client offered no usable share. Send HRR
            // unless this is already the second ClientHello.
            if driver.hrr_sent {
                driver.hs_state = HandshakeState::Error;
                return true;
            }
            if let Some(ref mut t) = driver.transcript {
                t.update(hs_data);
            }
            driver.hs_state = HandshakeState::SendHelloRetryRequest;
            return true;
        }
    }

    if let Some(ref mut t) = driver.transcript {
        t.update(hs_data);
    }
    if dev_csprng_fill(sys, driver.server_random.as_mut_ptr(), 32) < 0 {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    driver.hs_state = HandshakeState::SendServerHello;
    true
}

unsafe fn dtls_pump_derive_handshake_keys(s: &mut TlsState, idx: usize) -> bool {
    let endpoint = &mut s.peer_sessions[idx].endpoint;
    if let Some((wk, rk)) = pump_derive_handshake_keys_core(&mut endpoint.driver, 0u8) {
        endpoint.write_keys = wk;
        endpoint.read_keys = rk;
        // RFC 9147 §6.1: Initial = epoch 0, Handshake = epoch 2.
        endpoint.recv_state.rotate_epoch(2);
        endpoint.send_state.rotate_epoch(2);
    }
    true
}

unsafe fn dtls_pump_send_encrypted_extensions(s: &mut TlsState, idx: usize) -> bool {
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let msg_len = build_encrypted_extensions(&mut driver.scratch, &[]);
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hs_state = HandshakeState::SendCertificate;
    true
}

unsafe fn dtls_pump_send_certificate_verify(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let hl = driver.suite.hash_len();
    let transcript_hash = match &driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let context = b"TLS 1.3, server CertificateVerify";
    let mut verify_content = [0u8; 200];
    let vc_len = build_verify_content(context, &transcript_hash[..hl], hl, &mut verify_content);
    let vc_hash = sha256(&verify_content[..vc_len]);

    // Sign via kernel KEY_VAULT when the identity key is held there; fall
    // back to the in-module signer on ENOSYS.
    const KV_SIGN: u32 = 0x1003;
    if s.identity_rsa_suite != 0 {
        // RSASSA-PSS-SHA256 from the vault's resumable job: the same digest
        // each call until it answers, since the transcript does not move.
        const SIGN_MODE_DIGEST: u8 = 1;
        let mut sig = [0u8; RSA_BYTES_MAX];
        let mut sign_arg = [0u8; 6 + 32 + 12];
        sign_arg[0] = SIGN_MODE_DIGEST;
        sign_arg[2..6].copy_from_slice(&32u32.to_le_bytes());
        sign_arg[6..38].copy_from_slice(&vc_hash);
        let sig_ptr = sig.as_mut_ptr() as u64;
        sign_arg[38..46].copy_from_slice(&sig_ptr.to_le_bytes());
        sign_arg[46..48].copy_from_slice(&(RSA_BYTES_MAX as u16).to_le_bytes());
        let rc = if s.key_vault_handle >= 0 {
            (sys.provider_call)(
                s.key_vault_handle,
                KV_SIGN,
                sign_arg.as_mut_ptr(),
                sign_arg.len(),
            )
        } else {
            -1
        };
        if rc == abi::errno::EAGAIN || rc == abi::errno::EBUSY {
            // In progress, or another peer's signature holds the vault's
            // one job: either way, come back next step.
            return true;
        }
        if rc != 0 {
            s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
            return true;
        }
        let sig_len = u16::from_le_bytes([sign_arg[48], sign_arg[49]]) as usize;
        let driver = &mut s.peer_sessions[idx].endpoint.driver;
        let msg_len = build_certificate_verify(
            SIG_RSA_PSS_RSAE_SHA256,
            &sig[..sig_len],
            sig_len,
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
        driver.hs_state = HandshakeState::SendFinished;
        return true;
    }
    if identity_is_p384(s) {
        // A P-384 identity signs in the module. Unlike the TLS path, which
        // splits the ladder across steps at `ecdh_bits_per_step`, this runs
        // `ecdsa384_sign` to completion in one call and does not consult
        // that budget — so a DTLS handshake costs one long step wherever
        // the ladder is slow, however small the configured budget is.
        let vc_hash384 = sha384(&verify_content[..vc_len]);
        let mut scalar = [0u8; 48];
        let n = identity_ec_scalar(&s.key[..s.key_len], &mut scalar);
        let signed = if n == 48 {
            ecdsa384_sign(&scalar, &vc_hash384)
        } else {
            None
        };
        zeroize(&mut scalar);
        let Some(sig) = signed else {
            s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
            return true;
        };
        let (der_sig, der_len) = encode_der_signature384(&sig);
        let driver = &mut s.peer_sessions[idx].endpoint.driver;
        let msg_len = build_certificate_verify(
            SIG_ECDSA_SECP384R1_SHA384,
            &der_sig,
            der_len,
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
        driver.hs_state = HandshakeState::SendFinished;
        return true;
    }
    let mut raw_sig = [0u8; 64];
    let mut signed_via_vault = false;
    if s.key_vault_handle >= 0 {
        // SIGN v1, `DIGEST` explicitly: `vc_hash` IS the digest. Leaving the
        // mode to be inferred from the key type is how a message passed here
        // gets signed as though it were one.
        const SIGN_MODE_DIGEST: u8 = 1;
        let mut sign_arg = [0u8; 6 + 32 + 12];
        sign_arg[0] = SIGN_MODE_DIGEST;
        sign_arg[2..6].copy_from_slice(&32u32.to_le_bytes());
        core::ptr::copy_nonoverlapping(vc_hash.as_ptr(), sign_arg.as_mut_ptr().add(6), 32);
        let sig_ptr = raw_sig.as_mut_ptr() as u64;
        sign_arg[38..46].copy_from_slice(&sig_ptr.to_le_bytes());
        sign_arg[46..48].copy_from_slice(&64u16.to_le_bytes());
        let rc = (sys.provider_call)(
            s.key_vault_handle,
            KV_SIGN,
            sign_arg.as_mut_ptr(),
            sign_arg.len(),
        );
        if rc == 0 {
            signed_via_vault = true;
        }
    }
    if !signed_via_vault {
        let mut k_random = [0u8; 32];
        dev_csprng_fill(sys, k_random.as_mut_ptr(), 32);
        let mut priv_key = [0u8; 32];
        if s.key_len == 32 {
            core::ptr::copy_nonoverlapping(s.key.as_ptr(), priv_key.as_mut_ptr(), 32);
        } else if s.key_len > 32 {
            extract_ec_private_key(&s.key[..s.key_len], &mut priv_key);
        }
        let signed = ecdsa_sign(&priv_key, &vc_hash, &k_random);
        let mut j = 0;
        while j < 32 {
            core::ptr::write_volatile(&mut priv_key[j], 0);
            j += 1;
        }
        match signed {
            Some(sig) => raw_sig = sig,
            None => {
                // The configured identity key is not a usable P-256
                // scalar (absent, or outside [1, n-1]). Signing under
                // it would produce a CertificateVerify no peer can
                // tie to this identity.
                s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
                return true;
            }
        }
    }

    let (der_sig, der_len) = encode_der_signature(&raw_sig);
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let msg_len = build_certificate_verify(
        SIG_ECDSA_SECP256R1_SHA256,
        &der_sig,
        der_len,
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
    driver.hs_state = HandshakeState::SendFinished;
    true
}

unsafe fn dtls_pump_derive_app_keys(s: &mut TlsState, idx: usize) -> bool {
    let endpoint = &mut s.peer_sessions[idx].endpoint;
    if let Some((wk, rk)) = pump_derive_app_keys_core(&mut endpoint.driver) {
        endpoint.write_keys = wk;
        endpoint.read_keys = rk;
    }
    // Drop handshake secrets + ECDH private — shared with TCP-TLS
    // via `zeroize_post_app_keys` so the post-handshake secret-
    // scrubbing policy is identical across transports.
    zeroize_post_app_keys(&mut endpoint.driver);
    // RFC 9147 §6.1: Application traffic = epoch 3.
    endpoint.recv_state.rotate_epoch(3);
    endpoint.send_state.rotate_epoch(3);
    true
}

unsafe fn dtls_pump_send_client_hello(s: &mut TlsState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    // Same rule as the stream path: the name is disclosed only when it is
    // also the name required of the peer's certificate.
    let sni_len = if s.peer_auth == PROFILE_CA_DNS {
        s.expected_dns_len
    } else {
        0
    };
    let mut sni_buf = [0u8; MAX_EXPECTED_DNS];
    core::ptr::copy_nonoverlapping(s.expected_dns.as_ptr(), sni_buf.as_mut_ptr(), sni_len);
    let bits_per_step = ec_bits_per_step(s);
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let mut random = [0u8; 32];
    dev_csprng_fill(sys, random.as_mut_ptr(), 32);
    let mut session_id = [0u8; 32];
    dev_csprng_fill(sys, session_id.as_mut_ptr(), 32);
    driver.peer_session_id = session_id;
    driver.peer_session_id_len = 32;

    if X25519_OFFERED && !x25519_keygen_step(sys, driver, bits_per_step) {
        return true;
    }
    let x25519_pub = driver.x25519_public;
    let msg_len = build_client_hello_sni(
        &random,
        &session_id,
        &driver.ecdh_public,
        if X25519_OFFERED {
            Some(&x25519_pub)
        } else {
            None
        },
        &[],
        &[],
        &sni_buf[..sni_len],
        TLS13_RECORD_SUITES,
        &mut driver.scratch,
    );

    driver.transcript = Some(Transcript::new(HashAlg::Sha256));
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    driver.hs_state = HandshakeState::RecvServerHello;
    true
}

unsafe fn dtls_pump_recv_encrypted_extensions(s: &mut TlsState, idx: usize) -> bool {
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let (data, len, msg_type) = match driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_ENCRYPTED_EXTENSIONS {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = driver.transcript {
        t.update(&data[..len]);
    }
    driver.hs_state = HandshakeState::RecvCertificate;
    true
}

unsafe fn dtls_pump_recv_certificate(s: &mut TlsState, idx: usize) -> bool {
    let (data, len, msg_type, is_server) = {
        let endpoint = &mut s.peer_sessions[idx].endpoint;
        let is_server = endpoint.driver.is_server;
        match endpoint.driver.read_handshake_message() {
            Some((d, l, t)) => (d, l, t, is_server),
            None => return false,
        }
    };
    if msg_type != HT_CERTIFICATE {
        s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = s.peer_sessions[idx].endpoint.driver.transcript {
        t.update(&data[..len]);
    }
    // The same acceptance decision the TCP path makes, from the same module
    // policy: a datagram transport does not get a weaker peer identity.
    let body = &data[4..len];
    let mut deferred = core::mem::replace(
        &mut s.peer_sessions[idx].endpoint.driver.deferred_links,
        DeferredLinks::empty(),
    );
    // A DTLS client dials `dtls_peer_ip`; the identity it expects is
    // `verify_hostname` when set, else the address it dialled, as an
    // `iPAddress`.
    let mut expected = [0u8; MAX_EXPECTED_DNS];
    let (expected_len, expected_is_ip) = if is_server {
        (0, false)
    } else if s.expected_dns_len > 0 {
        expected[..s.expected_dns_len].copy_from_slice(&s.expected_dns[..s.expected_dns_len]);
        (s.expected_dns_len, false)
    } else {
        expected[..4].copy_from_slice(&s.dtls_peer_ip.to_le_bytes());
        (4, true)
    };
    let mut rc = peer_cert_reason(
        s,
        is_server,
        &expected[..expected_len],
        expected_is_ip,
        body,
        Some(&mut deferred),
    );
    s.peer_sessions[idx].endpoint.driver.deferred_links = deferred;
    if rc == CERT_OK {
        rc = bind_peer_cert_key(&mut s.peer_sessions[idx].endpoint.driver, body);
    }
    if rc != CERT_OK {
        // DTLS peers have no IP-module conn_id; the peer-slot index is the
        // stable per-transport identifier, as for MSG_PEER_IDENTITY.
        log_peer_auth_failure(s, idx as u16, rc);
        s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
        return true;
    }
    s.last_peer_auth_error = CERT_OK;
    after_peer_cert(
        &mut s.peer_sessions[idx].endpoint.driver,
        &data[..len],
        HandshakeState::RecvCertificateVerify,
    );
    true
}

/// Drive the instance job for a DTLS peer in `VerifyChain` or
/// `VerifyPeerSignature`.
unsafe fn dtls_pump_rsa_verify(s: &mut TlsState, idx: usize) -> bool {
    let owner = RSA_OWNER_DTLS + idx as i32;
    if !rsa_job_available(s, owner) {
        return false;
    }
    s.rsa_owner = owner;
    let rows = rsa_rows(s);
    let selected = selected_anchor(
        s,
        s.peer_sessions[idx].endpoint.driver.deferred_links.anchor,
    );
    let anchor = core::slice::from_raw_parts(selected.as_ptr(), selected.len());
    let job: *mut RsaVerifyJob = &mut s.rsa_verify;
    let ec_bits = ec_bits_per_step(s);
    let outcome = rsa_verify_pump_core(
        &mut s.peer_sessions[idx].endpoint.driver,
        &mut *job,
        anchor,
        rows,
        ec_bits,
    );
    match outcome {
        RsaPump::Progress => true,
        RsaPump::Done => {
            s.rsa_owner = -1;
            true
        }
        RsaPump::Failed => {
            s.rsa_owner = -1;
            log_peer_auth_failure(s, idx as u16, CERT_ERR_SIGNATURE);
            s.peer_sessions[idx].endpoint.driver.hs_state = HandshakeState::Error;
            true
        }
    }
}

// ---------------------------------------------------------------------
// Record bridge
// ---------------------------------------------------------------------

/// Disarm the retx timer and clear the saved flight; called when
/// inbound progress shows the peer has responded.
unsafe fn dtls_disarm_retx(sess: &mut PeerSession) {
    sess.endpoint.retx_timer.disarm();
    sess.last_flight_len = 0;
    sess.last_flight_record_count = 0;
}

unsafe fn dtls_drain_inbound(s: &mut TlsState, idx: usize) {
    let suite;
    let is_initial;
    let inbound_len;
    {
        let sess = &mut s.peer_sessions[idx];
        if sess.inbound_len == 0 {
            return;
        }
        suite = sess.endpoint.driver.suite;
        is_initial = sess.endpoint.recv_is_initial();
        inbound_len = sess.inbound_len;
    }
    let mut datagram = [0u8; DGRAM_MAX];
    {
        let sess = &s.peer_sessions[idx];
        core::ptr::copy_nonoverlapping(
            sess.inbound_buf.as_ptr(),
            datagram.as_mut_ptr(),
            inbound_len,
        );
    }
    {
        let sess = &mut s.peer_sessions[idx];
        sess.inbound_len = 0;
    }

    // `dtls_recv_into_driver` returns `(inner_ct, recovered_seq,
    // plaintext_len)`. The recovered seq is the actual record
    // number we accepted — never a synthesised next-seq — so
    // out-of-order delivery ACKs the right record. The plaintext
    // payload lives at `datagram[DTLS_UNIFIED_HDR_LEN..]` (length
    // = plaintext_len) so we can parse a CT_DTLS_ACK body before
    // disarming the retx timer.
    let recv_epoch = s.peer_sessions[idx].endpoint.recv_state.epoch as u64;

    // Snapshot reassembler / driver state BEFORE the call so we
    // can tell whether *this* record drove the handshake forward,
    // not just whether earlier records left the session in an
    // active state. Without these snapshots a CT_DTLS_ACK record
    // could disarm the retx timer via the generic "made_progress"
    // path purely because a previous handshake fragment had set
    // `reassembler.active = true`.
    let (in_len_before, reassembler_active_before) = {
        let endpoint = &s.peer_sessions[idx].endpoint;
        (endpoint.driver.in_len, endpoint.reassembler.active)
    };

    let (record_made_progress, inner_ct, recv_seq, plaintext_len) = {
        let endpoint = &mut s.peer_sessions[idx].endpoint;
        let result = dtls_recv_into_driver(
            suite,
            is_initial,
            &mut endpoint.read_keys,
            &mut endpoint.recv_state,
            &mut endpoint.reassembler,
            &mut endpoint.driver,
            &mut datagram[..inbound_len],
        );
        // "Progress" means *this record* contributed to the
        // handshake state — either grew driver.in_len, or newly
        // activated the reassembler. An ACK record, an alert, or
        // app data hits this function but never moves these, so
        // they don't disarm the retx timer through the generic
        // path. The ACK-specific disarm logic below handles
        // CT_DTLS_ACK on its own merits.
        let driver_grew = endpoint.driver.in_len > in_len_before;
        let reassembler_newly_active = endpoint.reassembler.active && !reassembler_active_before;
        let progress = driver_grew || reassembler_newly_active;
        match result {
            Some((ct, seq, pt_len)) => (progress, Some(ct), Some(seq), pt_len),
            None => (false, None, None, 0),
        }
    };

    // RFC 9147 §7 ACK *receive*: parse the body and disarm the
    // retx timer iff the ACK is well-formed AND covers a record
    // from our current outbound flight. Earlier code disarmed on
    // any decrypted CT_DTLS_ACK — that opened a denial-of-service
    // hole where a peer could stop our retransmits with a record
    // that didn't actually acknowledge anything (including a 0-
    // entry ACK or one with bogus tuples).
    if matches!(inner_ct, Some(ct) if ct == CT_DTLS_ACK) {
        let body = &datagram[DTLS_UNIFIED_HDR_LEN..DTLS_UNIFIED_HDR_LEN + plaintext_len];
        let mut tuples = [(0u64, 0u64); 8];
        if let Some(count) = parse_dtls_ack_body(body, &mut tuples) {
            let n = if count < tuples.len() {
                count
            } else {
                tuples.len()
            };
            // Match against our last flight. With `last_flight_record_count`
            // tracking the count of records in the current flight and
            // their seqs running [send_seq - count .. send_seq), we
            // accept the ACK iff any tuple's (epoch, seq) falls in
            // that range under the current outbound epoch.
            let send_state = &s.peer_sessions[idx].endpoint.send_state;
            let our_epoch = send_state.epoch as u64;
            let flight_count = s.peer_sessions[idx].last_flight_record_count as u64;
            let flight_hi = send_state.send_seq;
            let flight_lo = flight_hi.wrapping_sub(flight_count);
            let mut covers = false;
            let mut i = 0;
            while i < n {
                let (e, sq) = tuples[i];
                if e == our_epoch && sq >= flight_lo && sq < flight_hi {
                    covers = true;
                    break;
                }
                i += 1;
            }
            if covers {
                dtls_disarm_retx(&mut s.peer_sessions[idx]);
            }
            // Body well-formed but doesn't cover us → ignore the
            // ACK. Spec-compliant peers won't send these; an
            // adversarial / lagging peer doesn't get to stop our
            // retransmits by sending unrelated record numbers.
        }
        // Malformed body (parse_dtls_ack_body returned None) is
        // silently ignored — we already authenticated the record
        // via the AEAD tag; the body just isn't actionable.
    }

    // Generic disarm path for non-ACK records that drove the
    // handshake forward (CT_HANDSHAKE fragments, mostly). The
    // `record_made_progress` flag only flips on state moved by
    // the current record — see the snapshot above — so an
    // authenticated CT_DTLS_ACK that didn't cover our flight
    // can't piggy-back on an earlier fragment's reassembler
    // state to falsely disarm.
    if record_made_progress {
        dtls_disarm_retx(&mut s.peer_sessions[idx]);
    }

    // RFC 9147 §7 ACK-the-record emission. We send an ACK back
    // when:
    //   - we successfully processed an encrypted handshake record
    //     (Initial-level plaintext records aren't ACKed — without
    //     keys the ACK would be plaintext and contribute nothing
    //     beyond the implicit next-record ACK behaviour the spec
    //     already requires the peer to handle),
    //   - the inner type is not itself an ACK (avoid ack-of-ack
    //     amplification loops),
    //   - the record didn't drive the handshake forward, but the
    //     peer should still be told their record landed so they
    //     stop retransmitting it.
    let should_ack = !is_initial && matches!(inner_ct, Some(ct) if ct == 22u8); // CT_HANDSHAKE
    if should_ack {
        if let Some(seq) = recv_seq {
            dtls_emit_ack(s, idx, (recv_epoch, seq));
        }
    }
}

/// Build, encrypt, and emit a single-record-number DTLS ACK
/// (RFC 9147 §7) on the peer's current write level. Uses the same
/// `write_keys`/`send_state` plumbing as handshake records so the
/// receiver authenticates the ACK under the in-force epoch.
unsafe fn dtls_emit_ack(s: &mut TlsState, idx: usize, acked: (u64, u64)) {
    let sys = &*s.syscalls;
    let suite = s.peer_sessions[idx].endpoint.driver.suite;
    let mut body = [0u8; 2 + 16];
    let body_len = build_dtls_ack_body(&[acked], &mut body);
    if body_len == 0 {
        return;
    }
    let mut out = [0u8; DTLS_UNIFIED_HDR_LEN + 2 + 16 + 1 + 16];
    let endpoint = &mut s.peer_sessions[idx].endpoint;
    let n = encrypt_dtls_record(
        suite,
        &mut endpoint.write_keys,
        &mut endpoint.send_state,
        CT_DTLS_ACK,
        &body[..body_len],
        &mut out,
    );
    if n == 0 {
        return;
    }
    // `encrypt_dtls_record` advances `send_state.send_seq` for us, so
    // there is deliberately no manual bump here: one would double-count
    // and emit the next outbound record with a seq one ahead of the
    // unified-header value the peer just saw.
    let peer = s.peer_sessions[idx].peer;
    dtls_send_datagram(
        sys,
        s.cipher_out,
        &s.dtls_endpoint,
        &peer,
        &out[..n],
        &mut s.net_scratch,
    );
}

/// Build the MSG_PEER_IDENTITY envelope for the DTLS peer and try
/// to write it on the optional `peer_identity` output port. Same
/// latch-on-backpressure pattern as the TCP-TLS path; the
/// envelope's `conn_id` byte carries the DTLS peer-slot index
/// (0..MAX_PEERS-1) since DTLS has no IP-module conn_id.
unsafe fn emit_peer_identity_dtls(s: &mut TlsState, idx: usize) {
    if s.peer_identity < 0 {
        return;
    }
    let pk_len = s.peer_sessions[idx].endpoint.driver.peer_cert_pubkey_len as usize;
    let mut fp_buf = [0u8; PEER_IDENTITY_MAX_FINGERPRINT];
    let fingerprint: &[u8] = if pk_len > 0 {
        let digest = sha256(&s.peer_sessions[idx].endpoint.driver.peer_cert_pubkey[..pk_len]);
        fp_buf.copy_from_slice(&digest);
        &fp_buf[..]
    } else {
        &fp_buf[..0]
    };
    // Same facts as the TCP path; see `emit_peer_identity`. `session_id`
    // carries the DTLS peer-slot index, since DTLS has no IP-module conn id.
    let (result, credential_kind, flags) = if pk_len == 0 {
        (peer_result::NO_CREDENTIAL, peer_credential::NONE, 0u32)
    } else {
        let mut f = peer_check::CHAIN | peer_check::KEY_POSSESSION | peer_check::EKU;
        if s.clock_policy == CLOCK_POLICY_REQUIRE && s.peer_auth == PROFILE_CA_DNS {
            f |= peer_check::VALIDITY;
        }
        (peer_result::OK, peer_credential::X509_MTLS, f)
    };
    let identity = PeerIdentity {
        session_id: idx as u32,
        verification_result: result,
        credential_kind,
        profile_id: u16::from(s.peer_auth),
        not_before: 0,
        not_after: 0,
        verification_flags: flags,
        key_fp_alg: peer_fp_alg::SHA256,
        key_fingerprint: fingerprint,
        principal: &[],
    };
    let mut envelope = [0u8; PEER_IDENTITY_MAX_TOTAL];
    let total = build_peer_identity_envelope(&identity, &mut envelope);
    {
        let sess = &mut s.peer_sessions[idx];
        sess.pending_peer_identity[..total].copy_from_slice(&envelope[..total]);
        sess.pending_peer_identity_len = total as u8;
    }
    try_drain_pending_peer_identity_dtls(s, idx);
}

/// Attempt one write of any pending DTLS peer-identity envelope.
unsafe fn try_drain_pending_peer_identity_dtls(s: &mut TlsState, idx: usize) {
    if s.peer_identity < 0 {
        return;
    }
    let len = s.peer_sessions[idx].pending_peer_identity_len as usize;
    if len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.peer_identity, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let ptr = s.peer_sessions[idx].pending_peer_identity.as_ptr();
    let written = (sys.channel_write)(s.peer_identity, ptr, len);
    if written == len as i32 {
        s.peer_sessions[idx].pending_peer_identity_len = 0;
    }
}

/// Per-tick sweep over DTLS peer sessions with a latched
/// peer-identity envelope. Mirrors `service_pending_peer_identity`
/// for the TCP-TLS path; called once at the top of
/// `dtls_module_step`.
unsafe fn service_pending_peer_identity_dtls(s: &mut TlsState) {
    if s.peer_identity < 0 {
        return;
    }
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].pending_peer_identity_len > 0 {
            try_drain_pending_peer_identity_dtls(s, i);
        }
        i += 1;
    }
}

unsafe fn dtls_drain_outbound(s: &mut TlsState, idx: usize) {
    loop {
        let suite;
        let is_initial;
        {
            let sess = &s.peer_sessions[idx];
            if sess.endpoint.driver.out_len == 0 {
                return;
            }
            suite = sess.endpoint.driver.suite;
            is_initial = sess.endpoint.send_is_initial();
        }
        let mut datagram = [0u8; DGRAM_MAX];
        let endpoint = &mut s.peer_sessions[idx].endpoint;
        let n = dtls_emit_from_driver(
            suite,
            is_initial,
            &mut endpoint.write_keys,
            &mut endpoint.send_state,
            &mut endpoint.next_send_msg_seq,
            &mut endpoint.current_frag_off,
            &mut endpoint.driver,
            &mut datagram,
        );
        if n == 0 {
            return;
        }

        let sys = &*s.syscalls;
        let peer = s.peer_sessions[idx].peer;
        dtls_send_datagram(
            sys,
            s.cipher_out,
            &s.dtls_endpoint,
            &peer,
            &datagram[..n],
            &mut s.net_scratch,
        );

        let sess = &mut s.peer_sessions[idx];
        let space = sess.last_flight.len() - sess.last_flight_len;
        let slot_avail = (sess.last_flight_record_count as usize) < MAX_FLIGHT_RECORDS;
        if n <= space && slot_avail && n <= u16::MAX as usize {
            core::ptr::copy_nonoverlapping(
                datagram.as_ptr(),
                sess.last_flight.as_mut_ptr().add(sess.last_flight_len),
                n,
            );
            sess.last_flight_len += n;
            let slot = sess.last_flight_record_count as usize;
            sess.last_flight_record_lens[slot] = n as u16;
            sess.last_flight_record_count += 1;
        } else if !sess.last_flight.is_empty() {
            // Flight overflowed our cache — drop the partial state so a
            // retx-timer firing doesn't replay a half-flight that the
            // peer can't reassemble. Without this drop the cache would
            // keep the first few records and silently lose the rest;
            // the peer would never see Finished and the handshake
            // would stall.
            let sys = &*s.syscalls;
            let msg = b"[dtls] flight cache overflow - retx disabled for this handshake";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
            sess.last_flight_len = 0;
            sess.last_flight_record_count = 0;
        }
        let now_ms = dev_millis(&*s.syscalls);
        sess.endpoint.retx_timer.arm(now_ms);
    }
}

/// Emit one datagram (`CMD_DG_SEND_TO`) toward `peer` via the shared
/// `datagram_endpoint` core. No-ops until the endpoint is bound.
unsafe fn dtls_send_datagram(
    sys: &SyscallTable,
    net_out: i32,
    ep: &DatagramEndpoint,
    peer: &PeerAddr,
    bytes: &[u8],
    scratch: &mut [u8; NET_SCRATCH_SIZE],
) {
    // `peer.ip` is wire-order octets; `send_to` re-serialises via `to_be_bytes`.
    let dst_ip = u32::from_be_bytes(peer.ip);
    ep.send_to(
        sys,
        net_out,
        dst_ip,
        peer.port,
        bytes.as_ptr(),
        bytes.len(),
        scratch.as_mut_ptr(),
        NET_SCRATCH_SIZE,
    );
}

unsafe fn dtls_discard_bytes(sys: &SyscallTable, ch: i32, mut count: usize) {
    let mut buf = [0u8; 64];
    while count > 0 {
        let take = if count < 64 { count } else { 64 };
        (sys.channel_read)(ch, buf.as_mut_ptr(), take);
        count -= take;
    }
}

// ---------------------------------------------------------------------
// Step entry: one tick of DTLS-mode activity. Mirrors the TLS-mode
// pump loop in `module_step` but operates on `peer_sessions` keyed
// by (peer_ip, peer_port) and reads/writes datagram opcodes.
// ---------------------------------------------------------------------

unsafe fn dtls_module_step(s: &mut TlsState) -> i32 {
    let sys = &*s.syscalls;

    // Drive the bind handshake (shared core): emits CMD_DG_BIND while unbound,
    // with backoff/retry. MSG_DG_BOUND is consumed in the recv loop below.
    s.dtls_endpoint.poll_bind(
        sys,
        s.cipher_out,
        s.dtls_port,
        s.net_scratch.as_mut_ptr(),
        NET_SCRATCH_SIZE,
    );

    // Retry any DTLS peer-identity envelopes that couldn't ship
    // at handshake completion because the consumer was backed
    // up. Symmetric with the TCP-TLS sweep in `module_step`.
    service_pending_peer_identity_dtls(s);

    // Half-open handshake idle timeout: any peer stuck in
    // Handshaking past DTLS_HANDSHAKE_TIMEOUT_STEPS is moved to
    // Errored so the slot can be reclaimed. With 4 peer slots a
    // single stuck handshake otherwise blocks 25 % of capacity
    // indefinitely. Clear the retx state at the same transition
    // — otherwise the §5.8 sweep below would keep replaying the
    // cached flight to a peer that's already given up.
    let now_step = s.step_count;
    let mut t = 0;
    while t < MAX_PEERS {
        if s.peer_sessions[t].phase == DtlsPhase::Handshaking {
            let elapsed = now_step.wrapping_sub(s.peer_sessions[t].handshake_start_step);
            if elapsed > DTLS_HANDSHAKE_TIMEOUT_STEPS {
                s.peer_sessions[t].phase = DtlsPhase::Errored;
                dtls_disarm_retx(&mut s.peer_sessions[t]);
            }
        }
        t += 1;
    }

    // RFC 9147 §5.8 retransmission timer. Gated to Handshaking
    // peers only — Errored / Closed / Ready slots never need to
    // replay a flight (Handshaking is the only phase where the
    // peer might still be waiting for a record). Belt-and-braces
    // with `dtls_clear_retx_state` above: even if a transition
    // forgot to clear the cache, the phase gate keeps the sweep
    // silent.
    let now_ms = dev_millis(sys);
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase == DtlsPhase::Handshaking
            && s.peer_sessions[i].last_flight_record_count > 0
            && s.peer_sessions[i].endpoint.retx_timer.should_retx(now_ms)
        {
            // RFC 9147 §5.8.1: each cached record was originally sent
            // as its own datagram; replay them one-per-datagram so the
            // peer's record-layer reassembler sees them the same way
            // as the original transmission. Coalescing into a single
            // datagram would deliver only the first record on the
            // receive side (one record per `dtls_recv_into_driver`
            // call).
            let peer = s.peer_sessions[i].peer;
            let count = s.peer_sessions[i].last_flight_record_count as usize;
            let mut record_off = 0usize;
            let mut buf = [0u8; NET_SCRATCH_SIZE * 2];
            core::ptr::copy_nonoverlapping(
                s.peer_sessions[i].last_flight.as_ptr(),
                buf.as_mut_ptr(),
                s.peer_sessions[i].last_flight_len,
            );
            let mut k = 0;
            while k < count {
                let rec_len = s.peer_sessions[i].last_flight_record_lens[k] as usize;
                if record_off + rec_len > s.peer_sessions[i].last_flight_len {
                    break;
                }
                dtls_send_datagram(
                    sys,
                    s.cipher_out,
                    &s.dtls_endpoint,
                    &peer,
                    &buf[record_off..record_off + rec_len],
                    &mut s.net_scratch,
                );
                record_off += rec_len;
                k += 1;
            }
            s.peer_sessions[i].endpoint.retx_timer.record_retx(now_ms);
        }
        i += 1;
    }

    // Client mode: kick off the handshake on the first tick after bind.
    if s.mode == 0 && !s.dtls_client_started && s.dtls_endpoint.is_ready() {
        let ip_bytes = s.dtls_peer_ip.to_le_bytes();
        let ip = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
        if let Some(idx) = dtls_alloc_client_session(s, &ip, s.dtls_peer_port) {
            let _ = dtls_pump_session(s, idx);
            dtls_drain_outbound(s, idx);
            s.dtls_client_started = true;
        }
    }

    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase == DtlsPhase::Handshaking {
            let mut steps = 0;
            while steps < 64 && s.peer_sessions[i].phase == DtlsPhase::Handshaking {
                dtls_drain_inbound(s, i);
                let progressed = dtls_pump_session(s, i);
                dtls_drain_outbound(s, i);
                if !progressed {
                    break;
                }
                steps += 1;
            }
        }
        i += 1;
    }

    let poll = (sys.channel_poll)(s.cipher_in, POLL_IN);
    if poll > 0 && (poll as u32 & POLL_IN) != 0 {
        let mut hdr = [0u8; 3];
        let n = (sys.channel_read)(s.cipher_in, hdr.as_mut_ptr(), 3);
        if n == 3 {
            let opcode = hdr[0];
            let payload_len = (hdr[1] as usize) | ((hdr[2] as usize) << 8);
            match opcode {
                x if x == DG_MSG_BOUND => {
                    // MSG_DG_BOUND payload: [ep_id: u8] [local_port: u16 LE].
                    // Provider may broadcast BOUND for endpoints belonging
                    // to other consumers on the shared net_out channel —
                    // accept only the one whose local_port matches our
                    // requested dtls_port.
                    let mut buf = [0u8; 16];
                    let take = if payload_len < 16 { payload_len } else { 16 };
                    if take > 0 {
                        (sys.channel_read)(s.cipher_in, buf.as_mut_ptr(), take);
                    }
                    if payload_len > take {
                        dtls_discard_bytes(sys, s.cipher_in, payload_len - take);
                    }
                    if take >= 3 {
                        let bound_port = (buf[1] as u16) | ((buf[2] as u16) << 8);
                        // Port-filter our own BOUND off the (possibly broadcast)
                        // channel, then hand the ep_id to the endpoint.
                        if bound_port == s.dtls_port && !s.dtls_endpoint.is_ready() {
                            s.dtls_endpoint.on_bound(buf[0]);
                            dev_log(sys, 3, b"[dtls] bound".as_ptr(), b"[dtls] bound".len());
                        }
                    }
                }
                x if x == DG_MSG_RX_FROM => {
                    // MSG_DG_RX_FROM IPv4 payload (datagram contract):
                    //   [ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][data...].
                    if payload_len >= 8 {
                        let mut hdr_buf = [0u8; 8];
                        (sys.channel_read)(s.cipher_in, hdr_buf.as_mut_ptr(), 8);
                        let ep_id = hdr_buf[0];
                        let ip = [hdr_buf[2], hdr_buf[3], hdr_buf[4], hdr_buf[5]];
                        let port = (hdr_buf[6] as u16) | ((hdr_buf[7] as u16) << 8);
                        let dgram_len = payload_len - 8;
                        // Drop datagrams routed to a different consumer's
                        // endpoint on the shared net_out channel.
                        if !s.dtls_endpoint.owns(ep_id) {
                            dtls_discard_bytes(sys, s.cipher_in, dgram_len);
                            return 1;
                        }
                        if dgram_len <= DGRAM_MAX {
                            let mut idx = dtls_find_session(s, &ip, port);
                            if idx < 0 {
                                if let Some(new) = dtls_alloc_session(s, &ip, port) {
                                    idx = new as i32;
                                }
                            }
                            if idx >= 0 {
                                let sess = &mut s.peer_sessions[idx as usize];
                                let want = if dgram_len < DGRAM_MAX {
                                    dgram_len
                                } else {
                                    DGRAM_MAX
                                };
                                (sys.channel_read)(
                                    s.cipher_in,
                                    sess.inbound_buf.as_mut_ptr(),
                                    want,
                                );
                                sess.inbound_len = want;
                                if dgram_len > want {
                                    dtls_discard_bytes(sys, s.cipher_in, dgram_len - want);
                                }
                            } else {
                                dtls_discard_bytes(sys, s.cipher_in, dgram_len);
                            }
                        } else {
                            dtls_discard_bytes(sys, s.cipher_in, dgram_len);
                        }
                    } else {
                        dtls_discard_bytes(sys, s.cipher_in, payload_len);
                    }
                }
                _ => {
                    dtls_discard_bytes(sys, s.cipher_in, payload_len);
                }
            }
        }
    }

    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase == DtlsPhase::Handshaking && s.peer_sessions[i].inbound_len > 0
        {
            let mut steps = 0;
            while steps < 64 && s.peer_sessions[i].phase == DtlsPhase::Handshaking {
                dtls_drain_inbound(s, i);
                let progressed = dtls_pump_session(s, i);
                dtls_drain_outbound(s, i);
                if !progressed {
                    break;
                }
                steps += 1;
            }
        }
        i += 1;
    }

    1
}
