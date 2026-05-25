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
    matches!(phase, DtlsPhase::Idle | DtlsPhase::Errored | DtlsPhase::Closed)
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
        if dtls_slot_reusable(s.peer_sessions[i].phase)
            && s.peer_sessions[i].peer.matches(ip, port)
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

unsafe fn dtls_init_server_session(
    s: &mut TlsState,
    i: usize,
    ip: &[u8; 4],
    port: u16,
) -> usize {
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

unsafe fn dtls_alloc_client_session(
    s: &mut TlsState,
    ip: &[u8; 4],
    port: u16,
) -> Option<usize> {
    // Same two-pass strategy as the server-side allocator: prefer
    // overwriting a same-tuple tombstone (handshake-timeout retry
    // is the common case), then fall back to any reusable slot.
    let mut i = 0;
    while i < MAX_PEERS {
        if dtls_slot_reusable(s.peer_sessions[i].phase)
            && s.peer_sessions[i].peer.matches(ip, port)
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

unsafe fn dtls_init_client_session(
    s: &mut TlsState,
    i: usize,
    ip: &[u8; 4],
    port: u16,
) -> usize {
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
            pump_send_server_hello_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::DeriveHandshakeKeys => dtls_pump_derive_handshake_keys(s, idx),
        HandshakeState::SendEncryptedExtensions => dtls_pump_send_encrypted_extensions(s, idx),
        HandshakeState::SendCertificate => {
            let cert_len = if s.cert_len <= MAX_CERT_LEN { s.cert_len } else { 0 };
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
        HandshakeState::RecvFinished => {
            pump_recv_server_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::SendClientFinished => {
            pump_send_client_finished_core(&mut s.peer_sessions[idx].endpoint.driver)
        }
        HandshakeState::ClientDeriveAppKeys => dtls_pump_derive_app_keys(s, idx),
        HandshakeState::Complete => {
            s.peer_sessions[idx].phase = DtlsPhase::Ready;
            dev_log(sys, 3, b"[dtls] handshake complete".as_ptr(), b"[dtls] handshake complete".len());
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

    match ch.key_share {
        Some((_, key_data)) if key_data.len() <= 65 => {
            core::ptr::copy_nonoverlapping(
                key_data.as_ptr(),
                driver.peer_key_share.as_mut_ptr(),
                key_data.len(),
            );
            driver.peer_key_share_len = key_data.len() as u8;
        }
        _ => {
            // RFC 8446 §4.1.4: client offered no P-256 share. Send HRR
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
    let mut raw_sig = [0u8; 64];
    let mut signed_via_vault = false;
    if s.key_vault_handle >= 0 {
        let mut sign_arg = [0u8; 4 + 32 + 64];
        sign_arg[0] = 32;
        core::ptr::copy_nonoverlapping(vc_hash.as_ptr(), sign_arg.as_mut_ptr().add(4), 32);
        let rc = (sys.provider_call)(s.key_vault_handle, KV_SIGN, sign_arg.as_mut_ptr(), sign_arg.len());
        if rc == 0 {
            core::ptr::copy_nonoverlapping(sign_arg.as_ptr().add(4 + 32), raw_sig.as_mut_ptr(), 64);
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
        raw_sig = ecdsa_sign(&priv_key, &vc_hash, &k_random);
        let mut j = 0;
        while j < 32 {
            core::ptr::write_volatile(&mut priv_key[j], 0);
            j += 1;
        }
    }

    let (der_sig, der_len) = encode_der_signature(&raw_sig);
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let msg_len = build_certificate_verify(&der_sig, der_len, &mut driver.scratch);
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
    let driver = &mut s.peer_sessions[idx].endpoint.driver;
    let mut random = [0u8; 32];
    dev_csprng_fill(sys, random.as_mut_ptr(), 32);
    let mut session_id = [0u8; 32];
    dev_csprng_fill(sys, session_id.as_mut_ptr(), 32);
    driver.peer_session_id = session_id;
    driver.peer_session_id_len = 32;

    let msg_len = build_client_hello(
        &random,
        &session_id,
        &driver.ecdh_public,
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
    // Snapshot the TLS-state-level CA + trust-domain config off the
    // shared `TlsState` so the same chain-of-trust rules apply to
    // DTLS. Earlier code skipped both checks and just copied the
    // leaf public key — the TCP-TLS hardening in extract_peer_cert_key
    // wasn't reaching DTLS peers (audit finding #6).
    let ca_pk_ptr: Option<&[u8]> = if s.require_ca && s.ca_pubkey_len > 0 {
        Some(&s.ca_pubkey[..s.ca_pubkey_len as usize])
    } else {
        None
    };
    let td_ptr: Option<&[u8]> = if s.trust_domain_len > 0 {
        Some(&s.trust_domain[..s.trust_domain_len])
    } else {
        None
    };
    let endpoint = &mut s.peer_sessions[idx].endpoint;
    let (data, len, msg_type) = match endpoint.driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CERTIFICATE {
        endpoint.driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = endpoint.driver.transcript {
        t.update(&data[..len]);
    }
    let body = &data[4..len];
    if !validate_and_extract_peer_cert(body, &mut endpoint.driver, ca_pk_ptr, td_ptr) {
        endpoint.driver.hs_state = HandshakeState::Error;
        return true;
    }
    endpoint.driver.hs_state = HandshakeState::RecvCertificateVerify;
    true
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
        let reassembler_newly_active =
            endpoint.reassembler.active && !reassembler_active_before;
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
        let body =
            &datagram[DTLS_UNIFIED_HDR_LEN..DTLS_UNIFIED_HDR_LEN + plaintext_len];
        let mut tuples = [(0u64, 0u64); 8];
        if let Some(count) = parse_dtls_ack_body(body, &mut tuples) {
            let n = if count < tuples.len() { count } else { tuples.len() };
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
    let should_ack = !is_initial
        && matches!(inner_ct, Some(ct) if ct == 22u8); // CT_HANDSHAKE
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
    // `encrypt_dtls_record` advances `send_state.send_seq` for us;
    // a manual bump here would double-count and emit the next
    // outbound record with a seq one ahead of the unified-header
    // value the peer just saw. Caught by the audit pass — first
    // version had `send_state.send_seq += 1` here on top of the
    // increment inside encrypt_dtls_record.
    let peer = s.peer_sessions[idx].peer;
    dtls_send_datagram(
        sys,
        s.cipher_out,
        s.dtls_listen_ep,
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
    if s.peer_identity < 0 { return; }
    let pk_len = s.peer_sessions[idx].endpoint.driver.peer_cert_pubkey_len as usize;
    let mut svid_buf = [0u8; PEER_IDENTITY_MAX_SVID];
    let svid_slice: &[u8] = if pk_len > 0 {
        let digest = sha256(&s.peer_sessions[idx].endpoint.driver.peer_cert_pubkey[..pk_len]);
        svid_buf.copy_from_slice(&digest);
        &svid_buf[..]
    } else {
        &svid_buf[..0]
    };
    let conn_id = idx as u8;
    let mut envelope = [0u8; PEER_IDENTITY_MAX_TOTAL];
    let total = build_peer_identity_envelope(conn_id, svid_slice, &mut envelope);
    {
        let sess = &mut s.peer_sessions[idx];
        sess.pending_peer_identity[..total].copy_from_slice(&envelope[..total]);
        sess.pending_peer_identity_len = total as u8;
    }
    try_drain_pending_peer_identity_dtls(s, idx);
}

/// Attempt one write of any pending DTLS peer-identity envelope.
unsafe fn try_drain_pending_peer_identity_dtls(s: &mut TlsState, idx: usize) {
    if s.peer_identity < 0 { return; }
    let len = s.peer_sessions[idx].pending_peer_identity_len as usize;
    if len == 0 { return; }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.peer_identity, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
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
    if s.peer_identity < 0 { return; }
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
            s.dtls_listen_ep,
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

unsafe fn dtls_send_datagram(
    sys: &SyscallTable,
    net_out: i32,
    ep: i16,
    peer: &PeerAddr,
    bytes: &[u8],
    scratch: &mut [u8; NET_SCRATCH_SIZE],
) {
    // CMD_DG_SEND_TO IPv4 (modules/sdk/contracts/net/datagram.rs):
    //   [opcode 0x21][len LE u16][ep_id:1][af:1=4][addr:4 BE][port:2 LE][payload]
    if ep < 0 {
        return;
    }
    let payload_len = 1 + 1 + 4 + 2 + bytes.len();
    let frame_len = 3 + payload_len;
    if frame_len > scratch.len() {
        return;
    }
    scratch[0] = DG_CMD_SEND_TO;
    scratch[1] = payload_len as u8;
    scratch[2] = (payload_len >> 8) as u8;
    scratch[3] = ep as u8;
    scratch[4] = DG_AF_INET;
    scratch[5] = peer.ip[0];
    scratch[6] = peer.ip[1];
    scratch[7] = peer.ip[2];
    scratch[8] = peer.ip[3];
    scratch[9] = (peer.port & 0xFF) as u8;
    scratch[10] = (peer.port >> 8) as u8;
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch.as_mut_ptr().add(11), bytes.len());
    (sys.channel_write)(net_out, scratch.as_ptr(), frame_len);
}

unsafe fn dtls_send_bind(s: &mut TlsState) {
    let sys = &*s.syscalls;
    // CMD_DG_BIND payload (modules/sdk/contracts/net/datagram.rs):
    //   [port: u16 LE] [flags: u8].
    let payload: [u8; 3] = [
        (s.dtls_port & 0xFF) as u8,
        (s.dtls_port >> 8) as u8,
        0,
    ];
    let frame_len = 3 + payload.len();
    let mut frame = [0u8; 8];
    frame[0] = DG_CMD_BIND;
    frame[1] = payload.len() as u8;
    frame[2] = (payload.len() >> 8) as u8;
    let mut i = 0;
    while i < payload.len() {
        frame[3 + i] = payload[i];
        i += 1;
    }
    (sys.channel_write)(s.cipher_out, frame.as_ptr(), frame_len);
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

    if !s.dtls_bound {
        dtls_send_bind(s);
        s.dtls_bound = true;
        return 1;
    }

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
                    s.dtls_listen_ep,
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
    if s.mode == 0 && !s.dtls_client_started && s.dtls_listen_ep >= 0 {
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
                        if bound_port == s.dtls_port && s.dtls_listen_ep < 0 {
                            s.dtls_listen_ep = buf[0] as i16;
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
                        let ep_id = hdr_buf[0] as i16;
                        let ip = [hdr_buf[2], hdr_buf[3], hdr_buf[4], hdr_buf[5]];
                        let port = (hdr_buf[6] as u16) | ((hdr_buf[7] as u16) << 8);
                        let dgram_len = payload_len - 8;
                        // Drop datagrams routed to a different consumer's
                        // endpoint on the shared net_out channel.
                        if ep_id != s.dtls_listen_ep {
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
                                let want = if dgram_len < DGRAM_MAX { dgram_len } else { DGRAM_MAX };
                                (sys.channel_read)(s.cipher_in, sess.inbound_buf.as_mut_ptr(), want);
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
        if s.peer_sessions[i].phase == DtlsPhase::Handshaking
            && s.peer_sessions[i].inbound_len > 0
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
