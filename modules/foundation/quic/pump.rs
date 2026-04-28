// QUIC handshake pump — same TLS 1.3 state machine as the TLS module
// (and identical wire bytes for ClientHello / ServerHello / EE / etc.)
// driven via the HandshakeDriver queue API. The only places this
// differs from `tls/mod.rs::pump_*` are the key-installation hooks:
// we plug QUIC's `install_handshake_keys` / `install_one_rtt_keys`
// in instead of populating TLS-style TrafficKeys.

unsafe fn pump_session(s: &mut QuicState, idx: usize) -> bool {
    let st = s.conns[idx].driver.hs_state;
    match st {
        // Server states
        HandshakeState::RecvClientHello => pump_recv_client_hello(s, idx),
        HandshakeState::RecvSecondClientHello => pump_recv_client_hello(s, idx),
        HandshakeState::SendHelloRetryRequest => pump_send_hello_retry(s, idx),
        HandshakeState::SendServerHello => pump_send_server_hello(s, idx),
        HandshakeState::DeriveHandshakeKeys => pump_derive_handshake_keys(s, idx),
        HandshakeState::SendEncryptedExtensions => pump_send_encrypted_extensions(s, idx),
        HandshakeState::SendCertificate => pump_send_certificate(s, idx),
        HandshakeState::SendCertificateVerify => pump_send_certificate_verify(s, idx),
        HandshakeState::SendFinished => pump_send_finished(s, idx),
        HandshakeState::RecvClientFinished => pump_recv_client_finished(s, idx),
        HandshakeState::DeriveAppKeys => pump_derive_app_keys(s, idx),
        // Client states
        HandshakeState::SendClientHello => pump_send_client_hello(s, idx),
        HandshakeState::RecvServerHello => pump_recv_server_hello(s, idx),
        HandshakeState::ClientDeriveHandshakeKeys => pump_derive_handshake_keys(s, idx),
        HandshakeState::RecvEncryptedExtensions => pump_recv_encrypted_extensions(s, idx),
        HandshakeState::RecvCertificate => pump_recv_certificate(s, idx),
        HandshakeState::RecvCertificateVerify => pump_recv_certificate_verify(s, idx),
        HandshakeState::RecvFinished => pump_recv_server_finished(s, idx),
        HandshakeState::SendClientFinished => pump_send_client_finished(s, idx),
        HandshakeState::ClientDeriveAppKeys => pump_derive_app_keys(s, idx),
        HandshakeState::Complete => {
            let conn = &mut s.conns[idx];
            if conn.is_server && !conn.pending_handshake_done && !conn.handshake_confirmed {
                // Queue HANDSHAKE_DONE for the next 1-RTT packet.
                conn.pending_handshake_done = true;
            }
            conn.phase = ConnPhase::Established;
            let sys = &*s.syscalls;
            dev_log(sys, 3, b"[quic] handshake complete".as_ptr(), b"[quic] handshake complete".len());
            true
        }
        HandshakeState::Error => {
            s.conns[idx].phase = ConnPhase::Errored;
            true
        }
        _ => false,
    }
}

unsafe fn pump_recv_client_hello(s: &mut QuicState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let driver = &mut s.conns[idx].driver;

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
    // Detect resumption: client offered pre_shared_key + psk_dhe_ke.
    let mut psk_accepted = false;
    let mut accepted_psk: [u8; 48] = [0; 48];
    let mut accepted_psk_len: usize = 0;
    if s.enable_0rtt != 0
        && ch.pre_shared_key.is_some()
        && ch.psk_dhe_offered
        && ch.psk_binders_off.is_some()
    {
        if let (Some(psk_ext), Some(binders_off_in_body)) =
            (ch.pre_shared_key, ch.psk_binders_off)
        {
            // The first identity in OfferedPsks is the only one we
            // try to match. Walk the identities iterator + corresponding
            // binders iterator in lockstep.
            // First identity payload begins at offset 2 (after the
            // identities-list u16 length).
            let mut id_iter = psk_identity_iter(psk_ext);
            let id_first = id_iter.next();
            // Locate the binders portion.
            let id_list_len = ((psk_ext[0] as usize) << 8) | (psk_ext[1] as usize);
            let binders_payload = &psk_ext[2 + id_list_len..];
            let mut bi_iter = psk_binder_iter(binders_payload);
            let binder_first = bi_iter.next();
            if let (Some((id_bytes, _age)), Some(client_binder)) = (id_first, binder_first) {
                if id_bytes.len() >= 4 {
                    let slot_idx = ((id_bytes[0] as u32) << 24)
                        | ((id_bytes[1] as u32) << 16)
                        | ((id_bytes[2] as u32) << 8)
                        | (id_bytes[3] as u32);
                    let slot_idx = (slot_idx as usize) % MAX_TICKETS;
                    let entry = s.server_tickets[slot_idx];
                    if entry.consumed && entry.used && id_bytes.len() == 20 + 8 {
                        let msg = b"[quic] 0-RTT ticket replay rejected";
                        dev_log(sys, 2, msg.as_ptr(), msg.len());
                    }
                    if entry.used && !entry.consumed && id_bytes.len() == 20 + 8 {
                        // Validate the random tag matches.
                        let mut tag_match = true;
                        let mut k = 0;
                        while k < 16 {
                            if entry.identity[4 + k] != id_bytes[4 + k] {
                                tag_match = false;
                                break;
                            }
                            k += 1;
                        }
                        // RFC 8446 §4.6.1 — ticket lifetime check.
                        let now_ms = dev_millis(sys);
                        let elapsed_ms = now_ms.saturating_sub(entry.issue_ms);
                        let lifetime_ok = elapsed_ms <= (entry.lifetime_s as u64) * 1000;
                        if tag_match && lifetime_ok {
                            // Recompute PSK from RMS + nonce.
                            let nonce = &id_bytes[20..28];
                            let suite = match CipherSuite::from_id(entry.suite_id) {
                                Some(c) => c,
                                None => {
                                    driver.hs_state = HandshakeState::Error;
                                    return true;
                                }
                            };
                            let hl = suite.hash_len();
                            let ks = KeySchedule::new(suite);
                            let mut psk = [0u8; 48];
                            ks.ticket_psk(&entry.rms[..hl], nonce, &mut psk[..hl]);
                            // Recompute binder over partial-CH bytes
                            // [0..binders_off_in_body+4 (HS hdr)].
                            let partial_full_len = 4 + binders_off_in_body;
                            let mut partial_t = Transcript::new(suite.hash_alg());
                            partial_t.update(&hs_data[..partial_full_len]);
                            let partial_hash = partial_t.current_hash();
                            let mut ks2 = KeySchedule::new(suite);
                            ks2.seed_psk(&psk[..hl]);
                            let expected = ks2.psk_binder(&partial_hash[..hl]);
                            if client_binder.len() == hl {
                                let mut diff = 0u8;
                                let mut k = 0;
                                while k < hl {
                                    diff |= client_binder[k] ^ expected[k];
                                    k += 1;
                                }
                                if diff == 0 {
                                    psk_accepted = true;
                                    accepted_psk[..hl].copy_from_slice(&psk[..hl]);
                                    accepted_psk_len = hl;
                                    // Burn the ticket — single-use.
                                    s.server_tickets[slot_idx].consumed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if ch.supported_versions != Some(0x0304) {
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    // RFC 9001 §8.2: a QUIC server MUST receive a transport_parameters
    // extension; the value's `initial_source_connection_id` MUST equal
    // the SCID the client placed in its first Initial header (which we
    // stashed as `peer_cid` during alloc_server_connection).
    let tp = match ch.transport_parameters {
        Some(t) => t,
        None => {
            driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let peer_cid_len = s.conns[idx].peer_cid_len as usize;
    let mut peer_cid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        s.conns[idx].peer_cid.as_ptr(),
        peer_cid_buf.as_mut_ptr(),
        peer_cid_len,
    );
    if !validate_transport_params(tp, &peer_cid_buf[..peer_cid_len], None, None) {
        let driver = &mut s.conns[idx].driver;
        driver.hs_state = HandshakeState::Error;
        return true;
    }
    let driver = &mut s.conns[idx].driver;
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
            // RFC 8446 §4.1.4 HRR fallback (no P-256 share).
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
    // Stash PSK acceptance state on the conn so SendServerHello +
    // SendEncryptedExtensions + SendCertificate know whether to
    // emit the PSK-bearing variants. Also install 0-RTT keys if the
    // client offered early_data (so we can decrypt subsequent 0-RTT
    // packets).
    if psk_accepted {
        let conn = &mut s.conns[idx];
        conn.psk[..accepted_psk_len].copy_from_slice(&accepted_psk[..accepted_psk_len]);
        conn.psk_len = accepted_psk_len as u8;
        conn.psk_selected = true;
        conn.zero_rtt_offered = ch.early_data;
        if ch.early_data {
            conn.zero_rtt_accepted = true;
            // Derive client_early_traffic_secret from early_secret +
            // FULL ClientHello hash (which already has the binder).
            let suite = conn.driver.suite;
            let hl = suite.hash_len();
            let mut ks = KeySchedule::new(suite);
            ks.seed_psk(&accepted_psk[..accepted_psk_len]);
            let full_hash = match &conn.driver.transcript {
                Some(t) => t.current_hash(),
                None => return true,
            };
            let mut early_secret = [0u8; 48];
            ks.derive_client_early_traffic(&full_hash[..hl], &mut early_secret);
            conn.zero_rtt_keys = secret_to_keys(&early_secret[..hl]);
            conn.zero_rtt_keys_set = true;
            // Also persist the seeded key_schedule on the driver so
            // pump_derive_handshake_keys can use it.
            conn.driver.key_schedule = Some(ks);
        }
    }
    true
}

unsafe fn pump_send_hello_retry(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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

unsafe fn pump_send_server_hello(s: &mut QuicState, idx: usize) -> bool {
    let psk_selected = s.conns[idx].psk_selected;
    let driver = &mut s.conns[idx].driver;
    let msg_len = if psk_selected {
        build_server_hello_psk(
            &driver.server_random,
            &driver.peer_session_id,
            driver.suite,
            &driver.ecdh_public,
            0, /* selected_identity = first identity */
            &mut driver.scratch,
        )
    } else {
        build_server_hello(
            &driver.server_random,
            &driver.peer_session_id,
            driver.suite,
            &driver.ecdh_public,
            &mut driver.scratch,
        )
    };
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

unsafe fn pump_derive_handshake_keys(s: &mut QuicState, idx: usize) -> bool {
    {
        let driver = &mut s.conns[idx].driver;
        if !driver.ecdh_state.is_initialised() {
            let new = match ecdh_shared_secret_init(
                &driver.ecdh_private,
                &driver.peer_key_share[..driver.peer_key_share_len as usize],
                0u8,
            ) {
                Some(v) => v,
                None => {
                    driver.hs_state = HandshakeState::Error;
                    return true;
                }
            };
            driver.ecdh_state = new;
            return true;
        }
        if !driver.ecdh_state.complete() {
            driver.ecdh_state.step();
            return true;
        }
    }
    let conn = &mut s.conns[idx];
    let shared = match ecdh_shared_secret_finalise(&conn.driver.ecdh_state) {
        Some(v) => v,
        None => {
            conn.driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    conn.driver.ecdh_state.zeroise_scalar();
    let transcript_hash = match &conn.driver.transcript {
        Some(t) => t.current_hash(),
        None => {
            conn.driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let hl = conn.driver.suite.hash_len();
    // RFC 8446 §7.1 — on a PSK-resumed handshake the early_secret
    // (and therefore the handshake_secret derivation chain) is seeded
    // by the PSK rather than zero IKM. We carry the seeded
    // key_schedule across pump_recv_client_hello → here on the server
    // path; on the client path pump_send_client_hello also seeds.
    let mut ks = if conn.psk_len > 0 {
        let mut k = KeySchedule::new(conn.driver.suite);
        let plen = conn.psk_len as usize;
        let mut psk_buf = [0u8; 48];
        psk_buf[..plen].copy_from_slice(&conn.psk[..plen]);
        k.seed_psk(&psk_buf[..plen]);
        k
    } else {
        KeySchedule::new(conn.driver.suite)
    };
    ks.derive_handshake_secrets(&shared, &transcript_hash[..hl]);
    conn.driver.key_schedule = Some(ks);

    // Install QUIC Handshake-level keys (key/iv/hp under "quic"
    // labels) — different label set than TLS-over-TCP's TrafficKeys.
    install_handshake_keys(conn);

    if conn.is_server {
        conn.driver.hs_state = HandshakeState::SendEncryptedExtensions;
    } else {
        conn.driver.hs_state = HandshakeState::RecvEncryptedExtensions;
    }
    true
}

unsafe fn pump_send_encrypted_extensions(s: &mut QuicState, idx: usize) -> bool {
    let mut tp = [0u8; TP_BUF_LEN];
    let scid_len = s.conns[idx].our_cid_len as usize;
    let mut scid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(s.conns[idx].our_cid.as_ptr(), scid_buf.as_mut_ptr(), scid_len);
    let orig_dcid_len = s.conns[idx].original_dcid_len as usize;
    let mut orig_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        s.conns[idx].original_dcid.as_ptr(),
        orig_buf.as_mut_ptr(),
        orig_dcid_len,
    );
    // RFC 9000 §7.3 — server MUST emit retry_source_connection_id when
    // a Retry was issued. Our `retry_source_cid` for the post-retry
    // connection equals `our_cid` (we keep the same SCID across Retry
    // and ServerHello), so a single byte buffer would suffice — but we
    // capture it explicitly so future divergence (e.g., per-flight
    // SCID rotation) doesn't silently confuse the client.
    let used_retry = s.conns[idx].used_retry;
    let rsc_len = s.conns[idx].retry_source_cid_len as usize;
    let mut rsc_buf = [0u8; MAX_CID_LEN];
    if used_retry {
        core::ptr::copy_nonoverlapping(
            s.conns[idx].retry_source_cid.as_ptr(),
            rsc_buf.as_mut_ptr(),
            rsc_len,
        );
    }
    let rsc_opt = if used_retry { Some(&rsc_buf[..rsc_len]) } else { None };
    let tp_len = build_transport_params_server(
        &scid_buf[..scid_len],
        &orig_buf[..orig_dcid_len],
        rsc_opt,
        &mut tp,
    );
    let psk_selected = s.conns[idx].psk_selected;
    let zero_rtt_accepted = s.conns[idx].zero_rtt_accepted;
    let driver = &mut s.conns[idx].driver;
    let msg_len = if psk_selected {
        build_encrypted_extensions_early(&mut driver.scratch, &[], &tp[..tp_len], zero_rtt_accepted)
    } else {
        build_encrypted_extensions_ext(&mut driver.scratch, &[], &tp[..tp_len])
    };
    if let Some(ref mut t) = driver.transcript {
        t.update(&driver.scratch[..msg_len]);
    }
    let mut local = [0u8; SCRATCH_SIZE];
    core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
    if !driver.write_handshake_message(&local[..msg_len]) {
        return false;
    }
    // RFC 8446 §4.4.2: PSK resumption skips Certificate +
    // CertificateVerify entirely.
    driver.hs_state = if psk_selected {
        HandshakeState::SendFinished
    } else {
        HandshakeState::SendCertificate
    };
    true
}

unsafe fn pump_send_certificate(s: &mut QuicState, idx: usize) -> bool {
    let cert_len = if s.cert_len <= MAX_CERT_LEN { s.cert_len } else { 0 };
    let cert = core::slice::from_raw_parts(s.cert.as_ptr(), cert_len);
    let driver = &mut s.conns[idx].driver;
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

unsafe fn pump_send_certificate_verify(s: &mut QuicState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    let driver = &mut s.conns[idx].driver;
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
    let mut k_random = [0u8; 32];
    dev_csprng_fill(sys, k_random.as_mut_ptr(), 32);
    let mut priv_key = [0u8; 32];
    if s.key_len == 32 {
        core::ptr::copy_nonoverlapping(s.key.as_ptr(), priv_key.as_mut_ptr(), 32);
    } else if s.key_len > 32 {
        extract_ec_private_key(&s.key[..s.key_len], &mut priv_key);
    }
    let raw_sig = ecdsa_sign(&priv_key, &vc_hash, &k_random);
    let mut j = 0;
    while j < 32 {
        core::ptr::write_volatile(&mut priv_key[j], 0);
        j += 1;
    }
    let (der_sig, der_len) = encode_der_signature(&raw_sig);
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

unsafe fn pump_send_finished(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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
    let finished_key = ks.compute_finished(&ks.server_hs_secret);
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
    driver.hs_state = HandshakeState::RecvClientFinished;
    true
}

unsafe fn pump_recv_client_finished(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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
    // Capture transcript hash through client Finished — RFC 8446
    // §4.6.1 RMS derivation reads this snapshot.
    if let Some(ref t) = driver.transcript {
        driver.client_finished_hash = t.current_hash();
    }
    driver.hs_state = HandshakeState::DeriveAppKeys;
    true
}

unsafe fn pump_derive_app_keys(s: &mut QuicState, idx: usize) -> bool {
    let conn = &mut s.conns[idx];
    let hl = conn.driver.suite.hash_len();
    let transcript_hash = conn.driver.server_finished_hash;
    if let Some(ref mut ks) = conn.driver.key_schedule {
        ks.derive_app_secrets(&transcript_hash[..hl]);
    }
    install_one_rtt_keys(conn);
    conn.driver.hs_state = HandshakeState::Complete;
    // Server-only: now that we have master_secret + the
    // client_finished_hash, derive RMS and queue a NewSessionTicket
    // for emission over 1-RTT (RFC 8446 §4.6.1). Skipped if
    // `enable_0rtt` is off.
    if conn.is_server && s.enable_0rtt != 0 && !conn.session_ticket_handled {
        emit_new_session_ticket(s, idx);
        s.conns[idx].session_ticket_handled = true;
    }
    true
}

/// Server: build a NewSessionTicket message + write into the
/// handshake driver's `out_buf` so emit_crypto_packet picks it up
/// at OneRtt level. Also stores the (RMS, suite, age_add) in
/// `s.server_tickets` so a subsequent resumed CH can be validated.
unsafe fn emit_new_session_ticket(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let hl = s.conns[idx].driver.suite.hash_len();
    let suite_id = s.conns[idx].driver.suite.id();
    // Derive resumption_master_secret from master_secret + client
    // Finished transcript hash.
    let mut rms = [0u8; 48];
    let cf_hash = s.conns[idx].driver.client_finished_hash;
    if let Some(ref ks) = s.conns[idx].driver.key_schedule {
        ks.derive_resumption_master(&cf_hash[..hl], &mut rms[..hl]);
    } else {
        return;
    }
    // Allocate identity bytes: [u32 BE: index][u8;16: random tag].
    let slot = (s.server_ticket_next as usize) % MAX_TICKETS;
    s.server_ticket_next = s.server_ticket_next.wrapping_add(1);
    let mut identity = [0u8; 20];
    let idx_be = (slot as u32).to_be_bytes();
    identity[..4].copy_from_slice(&idx_be);
    dev_csprng_fill(sys, identity.as_mut_ptr().add(4), 16);
    // Random ticket_age_add + 8-byte nonce.
    let mut age_add_buf = [0u8; 4];
    dev_csprng_fill(sys, age_add_buf.as_mut_ptr(), 4);
    let age_add = ((age_add_buf[0] as u32) << 24)
        | ((age_add_buf[1] as u32) << 16)
        | ((age_add_buf[2] as u32) << 8)
        | (age_add_buf[3] as u32);
    let mut nonce = [0u8; 8];
    dev_csprng_fill(sys, nonce.as_mut_ptr(), 8);
    let now_ms = dev_millis(sys);
    let lifetime_s: u32 = 7200;
    s.server_tickets[slot] = ServerTicketEntry {
        used: true,
        consumed: false,
        identity,
        rms: {
            let mut r = [0u8; 48];
            r[..hl].copy_from_slice(&rms[..hl]);
            r
        },
        rms_len: hl as u8,
        suite_id,
        issue_ms: now_ms,
        ticket_age_add: age_add,
        lifetime_s,
    };
    // Build NewSessionTicket: identity is the ticket bytes the client
    // will echo back. We pack [identity_bytes (20)][nonce (8)] so the
    // client can recover both for binder + age computation.
    let mut ticket_bytes = [0u8; 28];
    ticket_bytes[..20].copy_from_slice(&identity);
    ticket_bytes[20..28].copy_from_slice(&nonce);
    let mut nst = [0u8; 256];
    let n = build_new_session_ticket(
        lifetime_s,
        age_add,
        &nonce,
        &ticket_bytes,
        // max_early_data_size — non-zero to advertise 0-RTT capability.
        4096,
        &mut nst,
    );
    if n == 0 {
        return;
    }
    // Queue into the handshake driver's out_buf — drain_outbound
    // sends it as a CRYPTO frame at OneRtt level.
    let _ = s.conns[idx].driver.write_handshake_message(&nst[..n]);
}

// --------------------------- Client flow ---------------------------

unsafe fn pump_send_client_hello(s: &mut QuicState, idx: usize) -> bool {
    let sys = &*s.syscalls;
    // Build transport_parameters first so we can pass it as an
    // extension to build_client_hello_ext.
    let mut tp = [0u8; TP_BUF_LEN];
    let scid_len = s.conns[idx].our_cid_len as usize;
    let mut scid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(s.conns[idx].our_cid.as_ptr(), scid_buf.as_mut_ptr(), scid_len);
    let tp_len = build_transport_params_client(&scid_buf[..scid_len], &mut tp);

    let psk_len = s.conns[idx].psk_len as usize;
    let psk_id_len = s.conns[idx].psk_identity_len as usize;
    let resumption = psk_len > 0 && psk_id_len > 0;
    let zero_rtt_offered = s.conns[idx].zero_rtt_offered;

    let mut random = [0u8; 32];
    dev_csprng_fill(sys, random.as_mut_ptr(), 32);
    let mut session_id = [0u8; 32];
    dev_csprng_fill(sys, session_id.as_mut_ptr(), 32);

    if resumption {
        // Build CH carrying pre_shared_key + psk_key_exchange_modes
        // + (optionally) early_data. Compute the binder over the
        // partial-CH transcript (RFC 8446 §4.2.11.2).
        let mut psk_id_buf = [0u8; 32];
        psk_id_buf[..psk_id_len].copy_from_slice(&s.conns[idx].psk_identity[..psk_id_len]);
        let mut psk_buf = [0u8; 48];
        psk_buf[..psk_len].copy_from_slice(&s.conns[idx].psk[..psk_len]);
        let driver = &mut s.conns[idx].driver;
        driver.peer_session_id = session_id;
        driver.peer_session_id_len = 32;
        let suite = driver.suite;
        let hl = suite.hash_len();
        // First pass: build CH with binder placeholder zeros.
        let (msg_len, binders_off_in_body, binder_off_in_body) = build_client_hello_psk(
            &random,
            &session_id,
            &driver.ecdh_public,
            &tp[..tp_len],
            &psk_id_buf[..psk_id_len],
            // obfuscated_age = (real_age + ticket_age_add) mod 2^32;
            // we send 0 since the loopback peer doesn't enforce.
            0,
            hl,
            zero_rtt_offered,
            &mut driver.scratch,
        );
        // Compute the partial-CH transcript hash. The binder covers
        // bytes [0..binders_off_in_body] of the CH body PLUS the
        // 4-byte handshake header. body_off in `driver.scratch`
        // accounts for the header.
        let partial_full_len = 4 + binders_off_in_body;
        let mut partial_t = Transcript::new(suite.hash_alg());
        partial_t.update(&driver.scratch[..partial_full_len]);
        let partial_hash = partial_t.current_hash();
        // Seed the early secret with the PSK + compute binder.
        let mut ks = KeySchedule::new(suite);
        ks.seed_psk(&psk_buf[..hl]);
        let binder = ks.psk_binder(&partial_hash[..hl]);
        // Patch the binder into the CH.
        psk_overwrite_binder(
            &mut driver.scratch[..msg_len],
            4 + binder_off_in_body,
            &binder[..hl],
        );
        // Derive client_early_traffic_secret over the FULL CH (which
        // includes the now-correct binder) — RFC 8446 §7.1 says
        // "c e traffic" uses ClientHello transcript hash.
        let mut full_t = Transcript::new(suite.hash_alg());
        full_t.update(&driver.scratch[..msg_len]);
        let full_hash = full_t.current_hash();
        let mut early_secret = [0u8; 48];
        ks.derive_client_early_traffic(&full_hash[..hl], &mut early_secret);
        // Persist key_schedule on driver for later derivations.
        driver.transcript = Some(full_t);
        driver.key_schedule = Some(ks);
        let mut local = [0u8; SCRATCH_SIZE];
        core::ptr::copy_nonoverlapping(driver.scratch.as_ptr(), local.as_mut_ptr(), msg_len);
        if !driver.write_handshake_message(&local[..msg_len]) {
            return false;
        }
        driver.hs_state = HandshakeState::RecvServerHello;
        // Install 0-RTT keys. RFC 9001 §5.6: secret_to_keys with the
        // "quic key/iv/hp" labels applied to the early traffic secret.
        let conn = &mut s.conns[idx];
        conn.zero_rtt_keys = secret_to_keys(&early_secret[..hl]);
        conn.zero_rtt_keys_set = true;
        return true;
    }
    let driver = &mut s.conns[idx].driver;
    driver.peer_session_id = session_id;
    driver.peer_session_id_len = 32;
    let msg_len = build_client_hello_ext(
        &random,
        &session_id,
        &driver.ecdh_public,
        &tp[..tp_len],
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

unsafe fn pump_recv_server_hello(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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
    // Resumption: server confirmed our PSK by including a
    // pre_shared_key extension with the selected_identity (we always
    // offer index 0, so we accept any value here as "matched").
    if sh.psk_identity.is_some() && s.conns[idx].psk_len > 0 {
        s.conns[idx].psk_selected = true;
    }
    let driver = &mut s.conns[idx].driver;
    driver.hs_state = HandshakeState::ClientDeriveHandshakeKeys;
    true
}

unsafe fn pump_recv_encrypted_extensions(s: &mut QuicState, idx: usize) -> bool {
    let conn = &mut s.conns[idx];
    let (data, len, msg_type) = match conn.driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_ENCRYPTED_EXTENSIONS {
        conn.driver.hs_state = HandshakeState::Error;
        return true;
    }
    // RFC 8446 §4.2.10 — server signals 0-RTT acceptance by including
    // an empty `early_data` extension in EncryptedExtensions. Look for
    // it before the QUIC TP extraction (we don't surface it through
    // parse_encrypted_extensions_for_quic).
    if conn.psk_selected && conn.zero_rtt_offered {
        let body = &data[4..len];
        let mut pos = 0;
        if pos + 2 <= body.len() {
            let ext_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
            pos += 2;
            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end {
                let etype = ((body[pos] as u16) << 8) | (body[pos + 1] as u16);
                let elen = ((body[pos + 2] as usize) << 8) | (body[pos + 3] as usize);
                pos += 4;
                if pos + elen > ext_end {
                    break;
                }
                if etype == EXT_EARLY_DATA {
                    conn.zero_rtt_accepted = true;
                }
                pos += elen;
            }
        }
    }
    // Extract + validate the server's transport_parameters. RFC 9001
    // §8.2: a QUIC client MUST receive a transport_parameters
    // extension; its `initial_source_connection_id` MUST equal the
    // server's SCID from its first Initial (we stash that as
    // `peer_cid` during alloc_client_connection's reply processing —
    // for the client it ends up in `peer_cid` after we receive
    // ServerHello), and `original_destination_connection_id` MUST
    // equal the DCID we put in our first Initial (we stashed that
    // as `original_dcid`).
    let tp = match parse_encrypted_extensions_for_quic(&data[4..len]) {
        Some(t) => t,
        None => {
            conn.driver.hs_state = HandshakeState::Error;
            return true;
        }
    };
    let peer_cid_len = conn.peer_cid_len as usize;
    let orig_dcid_len = conn.original_dcid_len as usize;
    let mut peer_cid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        conn.peer_cid.as_ptr(),
        peer_cid_buf.as_mut_ptr(),
        peer_cid_len,
    );
    let mut orig_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        conn.original_dcid.as_ptr(),
        orig_buf.as_mut_ptr(),
        orig_dcid_len,
    );
    // RFC 9000 §7.3: when the client used Retry, it MUST validate that
    // the server echoes back the Retry's SCID via `retry_source_cid`.
    let used_retry = conn.used_retry;
    let rsc_len = conn.retry_source_cid_len as usize;
    let mut rsc_buf = [0u8; MAX_CID_LEN];
    if used_retry {
        core::ptr::copy_nonoverlapping(
            conn.retry_source_cid.as_ptr(),
            rsc_buf.as_mut_ptr(),
            rsc_len,
        );
    }
    let rsc_opt = if used_retry { Some(&rsc_buf[..rsc_len]) } else { None };
    if !validate_transport_params(
        tp,
        &peer_cid_buf[..peer_cid_len],
        Some(&orig_buf[..orig_dcid_len]),
        rsc_opt,
    ) {
        conn.driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = conn.driver.transcript {
        t.update(&data[..len]);
    }
    // RFC 8446 §4.4.2 — resumed handshake skips Cert/CertVerify; the
    // next message we expect is server Finished.
    conn.driver.hs_state = if conn.psk_selected {
        HandshakeState::RecvFinished
    } else {
        HandshakeState::RecvCertificate
    };
    true
}

unsafe fn pump_recv_certificate(s: &mut QuicState, idx: usize) -> bool {
    // Capture verify-peer config as raw pointers before borrowing the
    // connection mutably. QuicState lives in stable module storage so
    // the pointers remain valid for the function's duration.
    let verify_peer = s.verify_peer != 0;
    let trust_ptr = s.trust_cert.as_ptr();
    let trust_len = if verify_peer { s.trust_cert_len } else { 0 };
    let host_ptr = s.verify_hostname.as_ptr();
    let host_len = if verify_peer { s.verify_hostname_len } else { 0 };
    let sys_ptr = s.syscalls;

    let conn = &mut s.conns[idx];
    let (data, len, msg_type) = match conn.driver.read_handshake_message() {
        Some(t) => t,
        None => return false,
    };
    if msg_type != HT_CERTIFICATE {
        conn.driver.hs_state = HandshakeState::Error;
        return true;
    }
    if let Some(ref mut t) = conn.driver.transcript {
        t.update(&data[..len]);
    }
    let body = &data[4..len];
    if !extract_peer_cert_pubkey_quic(body, &mut conn.driver) {
        conn.driver.hs_state = HandshakeState::Error;
        return true;
    }
    if verify_peer {
        let sys = &*sys_ptr;
        if trust_len == 0 || host_len == 0 {
            // verify_peer requested but trust anchor or hostname is
            // absent — fail closed rather than silently skipping.
            let msg = b"[quic] cert chain FAIL no trust anchor / hostname";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
            conn.driver.hs_state = HandshakeState::Error;
            return true;
        }
        let trust = core::slice::from_raw_parts(trust_ptr, trust_len);
        let host = core::slice::from_raw_parts(host_ptr, host_len);
        let rc = verify_cert_chain(body, trust, host);
        if rc != 0 {
            let mut buf = [0u8; 48];
            let prefix = b"[quic] cert chain FAIL rc=";
            let mut p = 0;
            while p < prefix.len() { buf[p] = prefix[p]; p += 1; }
            let mut rc_v = rc;
            let mut digits = [0u8; 10];
            let mut nd = 0;
            if rc_v == 0 {
                digits[nd] = b'0';
                nd += 1;
            } else {
                while rc_v > 0 && nd < digits.len() {
                    digits[nd] = b'0' + (rc_v % 10) as u8;
                    rc_v /= 10;
                    nd += 1;
                }
            }
            let mut k = nd;
            while k > 0 && p < buf.len() {
                k -= 1;
                buf[p] = digits[k];
                p += 1;
            }
            dev_log(sys, 2, buf.as_ptr(), p);
            conn.driver.hs_state = HandshakeState::Error;
            return true;
        }
        let msg = b"[quic] cert chain OK";
        dev_log(sys, 3, msg.as_ptr(), msg.len());
    }
    conn.driver.hs_state = HandshakeState::RecvCertificateVerify;
    true
}

unsafe fn extract_peer_cert_pubkey_quic(body: &[u8], driver: &mut HandshakeDriver) -> bool {
    if body.len() < 4 {
        return false;
    }
    let ctx_len = body[0] as usize;
    if 1 + ctx_len + 3 > body.len() {
        return false;
    }
    let mut pos = 1 + ctx_len;
    let list_len = ((body[pos] as usize) << 16)
        | ((body[pos + 1] as usize) << 8)
        | (body[pos + 2] as usize);
    pos += 3;
    if pos + list_len > body.len() || list_len < 3 {
        return false;
    }
    let cert_len = ((body[pos] as usize) << 16)
        | ((body[pos + 1] as usize) << 8)
        | (body[pos + 2] as usize);
    pos += 3;
    if pos + cert_len > body.len() {
        return false;
    }
    let cert_der = &body[pos..pos + cert_len];
    if let Some(parsed) = parse_certificate(cert_der) {
        let pk = parsed.public_key;
        let n = if pk.len() <= 65 { pk.len() } else { 65 };
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            driver.peer_cert_pubkey.as_mut_ptr(),
            n,
        );
        driver.peer_cert_pubkey_len = n as u8;
        true
    } else {
        false
    }
}

unsafe fn pump_recv_certificate_verify(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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
    let context: &[u8] = b"TLS 1.3, server CertificateVerify";
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
    driver.hs_state = HandshakeState::RecvFinished;
    true
}

unsafe fn pump_recv_server_finished(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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

// ---------------------------------------------------------------------
// Inbound drain — process one QUIC packet from the connection's
// staging buffer. Returns true on a successful packet processing.
// ---------------------------------------------------------------------

unsafe fn drain_inbound_one(s: &mut QuicState, idx: usize) -> bool {
    let conn = &mut s.conns[idx];
    if conn.inbound_len == 0 || conn.inbound_off >= conn.inbound_len {
        return false;
    }
    let off = conn.inbound_off;
    let avail = conn.inbound_len - off;
    let first = conn.inbound[off];
    let is_long = first & 0x80 != 0;

    if is_long {
        if first & 0x40 == 0 {
            mark_inbound_consumed(conn);
            return false;
        }
        // Version check (RFC 9000 §17.2.1). Non-v1 Initials get a
        // Version Negotiation response from the server; the client
        // would interpret a server-emitted VN by reading the
        // supported_versions list. For our v1-only build we just
        // reject and emit VN if we're the server.
        if avail < 5 {
            mark_inbound_consumed(conn);
            return false;
        }
        let version = ((conn.inbound[off + 1] as u32) << 24)
            | ((conn.inbound[off + 2] as u32) << 16)
            | ((conn.inbound[off + 3] as u32) << 8)
            | (conn.inbound[off + 4] as u32);
        if version != QUIC_V1 {
            if conn.is_server {
                emit_version_negotiation(s, idx, off, avail);
            }
            // For both client + server: drop and reset connection.
            s.conns[idx].phase = ConnPhase::Errored;
            mark_inbound_consumed(&mut s.conns[idx]);
            return false;
        }
        let pkt_type = (s.conns[idx].inbound[off] >> 4) & 0x03;

        // Client side: a Retry packet (type=3) is fielded BEFORE we
        // attempt AEAD-decrypt — Retry has no AEAD, only a 16-byte
        // integrity tag covering a "Retry Pseudo-Packet".
        if pkt_type == PKT_RETRY {
            return handle_retry(s, idx, off, avail);
        }

        let level = match pkt_type {
            PKT_INITIAL => EncLevel::Initial,
            PKT_HANDSHAKE => EncLevel::Handshake,
            _ => {
                mark_inbound_consumed(&mut s.conns[idx]);
                return false;
            }
        };

        // For server: if this is the first Initial we've seen, we
        // need to install initial keys from the DCID the client put
        // in the packet. Peek the DCID without decrypting.
        if s.conns[idx].is_server && pkt_type == PKT_INITIAL && !s.conns[idx].initial.keys_set {
            // Decision: issue Retry, validate token, or proceed.
            let action = peek_initial_for_retry(s, idx, off, avail);
            match action {
                InitialAction::IssueRetry { dcid, scid } => {
                    emit_retry(s, idx, &dcid, &scid);
                    // Drop the slot — we don't keep state.
                    s.conns[idx].phase = ConnPhase::Idle;
                    mark_inbound_consumed(&mut s.conns[idx]);
                    return false;
                }
                InitialAction::Reject => {
                    s.conns[idx].phase = ConnPhase::Errored;
                    mark_inbound_consumed(&mut s.conns[idx]);
                    return false;
                }
                InitialAction::Proceed { used_retry, odcid_for_tp, odcid_len_for_tp, dcid_buf, dcid_len, scid_buf, scid_len } => {
                    let conn = &mut s.conns[idx];
                    if used_retry {
                        // Retry-bound second Initial. ODCID for TP is
                        // the value extracted from the validated token
                        // (= client's first-Initial DCID); our_cid is
                        // the DCID the client used here (= the SCID
                        // the server picked in the Retry packet). RSC
                        // == our_cid (we keep one SCID across Retry +
                        // ServerHello).
                        conn.used_retry = true;
                        conn.original_dcid[..odcid_len_for_tp]
                            .copy_from_slice(&odcid_for_tp[..odcid_len_for_tp]);
                        conn.original_dcid_len = odcid_len_for_tp as u8;
                        // Override the random our_cid set in
                        // alloc_server_connection with the DCID the
                        // client used in this Initial.
                        conn.our_cid[..dcid_len].copy_from_slice(&dcid_buf[..dcid_len]);
                        conn.our_cid_len = dcid_len as u8;
                        conn.retry_source_cid[..dcid_len]
                            .copy_from_slice(&dcid_buf[..dcid_len]);
                        conn.retry_source_cid_len = dcid_len as u8;
                    } else {
                        conn.original_dcid[..dcid_len].copy_from_slice(&dcid_buf[..dcid_len]);
                        conn.original_dcid_len = dcid_len as u8;
                    }
                    install_initial_keys(conn, &dcid_buf[..dcid_len]);
                    conn.peer_cid[..scid_len].copy_from_slice(&scid_buf[..scid_len]);
                    conn.peer_cid_len = scid_len as u8;
                }
            }
        }

        let conn = &mut s.conns[idx];

        let space = match level {
            EncLevel::Initial => &mut conn.initial,
            EncLevel::Handshake => &mut conn.handshake,
            _ => {
                mark_inbound_consumed(conn);
                return false;
            }
        };
        if !space.keys_set {
            // Keys for this level not yet installed — leave the bytes
            // in place so the next pump iteration (which may install
            // handshake keys) can retry.
            return false;
        }
        let read_keys = space.read_keys;
        let hp = Aes128Hp::new(&space.read_keys.hp);
        let largest_recv = space.largest_recv_pn;
        let mut pkt_copy = [0u8; QUIC_DGRAM_MAX];
        core::ptr::copy_nonoverlapping(
            conn.inbound.as_ptr().add(off),
            pkt_copy.as_mut_ptr(),
            avail,
        );
        let parsed = match parse_long_packet(&read_keys, &hp, largest_recv, &mut pkt_copy[..avail]) {
            Some(p) => p,
            None => {
                mark_inbound_consumed(conn);
                return false;
            }
        };
        space.largest_recv_pn = if parsed.pn > space.largest_recv_pn {
            parsed.pn
        } else {
            space.largest_recv_pn
        };
        space.ack_pending = true;
        space.ack_tracker.record(parsed.pn, 0);
        // Idle-timeout activity stamp (RFC 9000 §10.1).
        let now_ms = dev_millis(&*s.syscalls);
        conn.last_activity_ms = now_ms;

        if !conn.is_server && pkt_type == PKT_INITIAL && parsed.scid_len > 0 {
            let scid_off = parsed.scid_off;
            let scid_len = parsed.scid_len;
            let n = if scid_len <= MAX_CID_LEN { scid_len } else { MAX_CID_LEN };
            core::ptr::copy_nonoverlapping(
                pkt_copy.as_ptr().add(scid_off),
                conn.peer_cid.as_mut_ptr(),
                n,
            );
            conn.peer_cid_len = n as u8;
        }

        let payload = &pkt_copy[parsed.payload_off..parsed.payload_off + parsed.payload_len];
        let now_ms = dev_millis(&*s.syscalls);
        process_frames(conn, level, payload, now_ms);

        // Advance past this packet — coalesced peer per RFC 9000 §12.2
        // may follow with another packet in the same datagram.
        conn.inbound_off += parsed.total_consumed;
        if conn.inbound_off >= conn.inbound_len {
            mark_inbound_consumed(conn);
        }
        return true;
    } else {
        // 1-RTT short header — RFC 9000 §17.2: cannot be coalesced
        // (no length field), so it occupies the entire remaining
        // datagram tail.
        if first & 0x40 == 0 {
            mark_inbound_consumed(conn);
            return false;
        }
        if !conn.one_rtt.keys_set {
            return false;
        }
        let dcid_len = conn.our_cid_len as usize;
        let largest_recv = conn.one_rtt.largest_recv_pn;
        let mut pkt_copy = [0u8; QUIC_DGRAM_MAX];
        core::ptr::copy_nonoverlapping(
            conn.inbound.as_ptr().add(off),
            pkt_copy.as_mut_ptr(),
            avail,
        );
        // RFC 9001 §6.2 — KEY_PHASE bit (0x04) is masked by header
        // protection. Try the current keys first; on AEAD failure
        // and a phase mismatch, retry with the next-phase keys
        // (which were pre-derived in install_one_rtt_keys).
        let read_keys = conn.one_rtt.read_keys;
        let hp = Aes128Hp::new(&conn.one_rtt.read_keys.hp);
        let mut decrypt_result = parse_one_rtt_packet(
            &read_keys,
            &hp,
            dcid_len,
            largest_recv,
            &mut pkt_copy[..avail],
        );
        let mut rotated = false;
        if decrypt_result.is_none() && conn.one_rtt.next_keys_ready {
            // Decrypt failed under the current keys; retry with the
            // pre-derived next-phase keys (RFC 9001 §6.1 key update).
            // parse_one_rtt_packet mutates the ciphertext in place,
            // so re-copy from `inbound` first.
            core::ptr::copy_nonoverlapping(
                conn.inbound.as_ptr().add(off),
                pkt_copy.as_mut_ptr(),
                avail,
            );
            let next_read_keys = conn.one_rtt.next_read_keys;
            let next_hp = Aes128Hp::new(&conn.one_rtt.next_read_keys.hp);
            decrypt_result = parse_one_rtt_packet(
                &next_read_keys,
                &next_hp,
                dcid_len,
                largest_recv,
                &mut pkt_copy[..avail],
            );
            if decrypt_result.is_some() {
                rotated = true;
            }
        }
        let (body_off, body_len, pn) = match decrypt_result {
            Some(t) => t,
            None => {
                mark_inbound_consumed(conn);
                return false;
            }
        };
        if rotated {
            // Promote next-phase to current on both halves (RFC 9001
            // §6.1 mandates flipping the local sender on receipt of
            // an updated read phase) and pre-derive a fresh next
            // phase for the following rotation.
            let hl = conn.one_rtt.secret_len as usize;
            conn.one_rtt.read_keys = conn.one_rtt.next_read_keys;
            let next_secret = conn.one_rtt.next_read_secret;
            conn.one_rtt.read_secret[..hl].copy_from_slice(&next_secret[..hl]);
            conn.one_rtt.write_keys = conn.one_rtt.next_write_keys;
            let nw = conn.one_rtt.next_write_secret;
            conn.one_rtt.write_secret[..hl].copy_from_slice(&nw[..hl]);
            conn.one_rtt.key_phase ^= 1;
            let mut new_next_r = [0u8; 48];
            next_traffic_secret(&conn.one_rtt.read_secret[..hl], &mut new_next_r[..hl]);
            let mut new_next_w = [0u8; 48];
            next_traffic_secret(&conn.one_rtt.write_secret[..hl], &mut new_next_w[..hl]);
            conn.one_rtt.next_read_secret[..hl].copy_from_slice(&new_next_r[..hl]);
            conn.one_rtt.next_write_secret[..hl].copy_from_slice(&new_next_w[..hl]);
            let prev_read_hp = conn.one_rtt.read_keys.hp;
            let prev_write_hp = conn.one_rtt.write_keys.hp;
            conn.one_rtt.next_read_keys = next_keys(&new_next_r[..hl], prev_read_hp);
            conn.one_rtt.next_write_keys = next_keys(&new_next_w[..hl], prev_write_hp);
            let sys = &*s.syscalls;
            let msg = b"[quic] key update accepted";
            dev_log(sys, 3, msg.as_ptr(), msg.len());
        }
        conn.one_rtt.largest_recv_pn = if pn > conn.one_rtt.largest_recv_pn {
            pn
        } else {
            conn.one_rtt.largest_recv_pn
        };
        conn.one_rtt.ack_pending = true;
        conn.one_rtt.ack_tracker.record(pn, 0);
        // Server: receipt of an ack-eliciting 1-RTT packet confirms
        // the handshake (RFC 9001 §4.1.2).
        if conn.is_server {
            conn.handshake_confirmed = true;
        }
        let payload = &pkt_copy[body_off..body_off + body_len];
        let now_ms = dev_millis(&*s.syscalls);
        process_frames(conn, EncLevel::OneRtt, payload, now_ms);
        mark_inbound_consumed(conn);
        return true;
    }
}

fn mark_inbound_consumed(conn: &mut QuicConnection) {
    conn.inbound_len = 0;
    conn.inbound_off = 0;
}

// ---------------------------------------------------------------------
// Retry plumbing (RFC 9000 §17.2.5 + §8.1.2 + RFC 9001 §5.8).
// ---------------------------------------------------------------------

#[allow(dead_code)]
enum InitialAction {
    IssueRetry {
        dcid: [u8; MAX_CID_LEN],
        scid: [u8; MAX_CID_LEN],
    },
    Reject,
    Proceed {
        used_retry: bool,
        odcid_for_tp: [u8; MAX_CID_LEN],
        odcid_len_for_tp: usize,
        dcid_buf: [u8; MAX_CID_LEN],
        dcid_len: usize,
        scid_buf: [u8; MAX_CID_LEN],
        scid_len: usize,
    },
}

/// Server: peek into a freshly-arrived Initial header to determine
/// whether to issue a Retry, validate a Retry token, or proceed
/// directly. Does not decrypt; only reads cleartext header fields.
unsafe fn peek_initial_for_retry(
    s: &mut QuicState,
    idx: usize,
    off: usize,
    avail: usize,
) -> InitialAction {
    if avail < 7 {
        return InitialAction::Reject;
    }
    let inb = &s.conns[idx].inbound;
    let dcid_len = inb[off + 5] as usize;
    if 6 + dcid_len + 1 > avail || dcid_len > MAX_CID_LEN {
        return InitialAction::Reject;
    }
    let mut dcid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        inb.as_ptr().add(off + 6),
        dcid_buf.as_mut_ptr(),
        dcid_len,
    );
    let scid_len_off = 6 + dcid_len;
    let scid_len = inb[off + scid_len_off] as usize;
    if scid_len_off + 1 + scid_len > avail || scid_len > MAX_CID_LEN {
        return InitialAction::Reject;
    }
    let mut scid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        inb.as_ptr().add(off + scid_len_off + 1),
        scid_buf.as_mut_ptr(),
        scid_len,
    );

    let mut p = scid_len_off + 1 + scid_len;
    if p >= avail {
        return InitialAction::Reject;
    }
    // Token-length varint.
    let after = &inb[off + p..off + avail];
    let (token_len_v, n_tlen) = match varint_decode(after.as_ptr(), after.len()) {
        Some(t) => t,
        None => return InitialAction::Reject,
    };
    p += n_tlen;
    let token_len = token_len_v as usize;
    if p + token_len > avail {
        return InitialAction::Reject;
    }
    let mut token_buf = [0u8; MAX_RETRY_TOKEN_LEN];
    if token_len > 0 && token_len <= MAX_RETRY_TOKEN_LEN {
        core::ptr::copy_nonoverlapping(
            inb.as_ptr().add(off + p),
            token_buf.as_mut_ptr(),
            token_len,
        );
    }

    if s.require_retry != 0 {
        if token_len == 0 {
            // Issue a Retry (server picks a fresh SCID for the Retry).
            // The Retry's SCID becomes the client's new DCID; we use
            // it as our_cid post-retry too.
            let mut new_scid = [0u8; MAX_CID_LEN];
            let sys = &*s.syscalls;
            dev_csprng_fill(sys, new_scid.as_mut_ptr(), 8);
            return InitialAction::IssueRetry {
                dcid: scid_buf,
                scid: new_scid,
            };
        }
        // Validate token.
        if token_len > MAX_RETRY_TOKEN_LEN {
            return InitialAction::Reject;
        }
        let peer_ip = s.conns[idx].peer.ip;
        let peer_port = s.conns[idx].peer.port;
        let mut odcid_buf = [0u8; MAX_CID_LEN];
        let odcid_len = match validate_retry_token(
            s,
            &token_buf[..token_len],
            &peer_ip,
            peer_port,
            &mut odcid_buf,
        ) {
            Some(n) => n,
            None => return InitialAction::Reject,
        };
        return InitialAction::Proceed {
            used_retry: true,
            odcid_for_tp: odcid_buf,
            odcid_len_for_tp: odcid_len,
            dcid_buf,
            dcid_len,
            scid_buf,
            scid_len,
        };
    }

    InitialAction::Proceed {
        used_retry: false,
        odcid_for_tp: [0u8; MAX_CID_LEN],
        odcid_len_for_tp: 0,
        dcid_buf,
        dcid_len,
        scid_buf,
        scid_len,
    }
}

/// Server: build + send a Retry packet. `client_first_scid` was the
/// SCID in the client's first Initial — becomes our DCID. `new_scid`
/// is the SCID we want the client to use as DCID for the next Initial.
unsafe fn emit_retry(
    s: &mut QuicState,
    idx: usize,
    client_first_scid: &[u8; MAX_CID_LEN],
    new_scid: &[u8; MAX_CID_LEN],
) {
    let off = s.conns[idx].inbound_off;
    let inb = &s.conns[idx].inbound;
    if off + 7 > s.conns[idx].inbound_len {
        return;
    }
    let dcid_len = inb[off + 5] as usize;
    let mut odcid = [0u8; MAX_CID_LEN];
    if dcid_len > MAX_CID_LEN {
        return;
    }
    core::ptr::copy_nonoverlapping(
        inb.as_ptr().add(off + 6),
        odcid.as_mut_ptr(),
        dcid_len,
    );
    let scid_len_off = 6 + dcid_len;
    let scid_len = inb[off + scid_len_off] as usize;
    if scid_len > MAX_CID_LEN {
        return;
    }
    let _ = client_first_scid; // already captured above

    // Build retry token.
    let mut token = [0u8; MAX_RETRY_TOKEN_LEN];
    let peer_ip = s.conns[idx].peer.ip;
    let peer_port = s.conns[idx].peer.port;
    let token_len = build_retry_token(s, &peer_ip, peer_port, &odcid[..dcid_len], &mut token);
    if token_len == 0 {
        return;
    }

    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    let n = build_retry_packet(
        &odcid[..dcid_len],
        // DCID of Retry = peer's SCID.
        &s.conns[idx].inbound[off + scid_len_off + 1..off + scid_len_off + 1 + scid_len],
        &new_scid[..8],
        &token[..token_len],
        &mut pkt,
    );
    if n == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let listen_ep = s.listen_ep;
    let peer = s.conns[idx].peer;
    send_datagram(sys, s.net_out, listen_ep, &peer, &pkt[..n], &mut s.net_scratch);
    dev_log(sys, 3, b"[quic] retry sent".as_ptr(), b"[quic] retry sent".len());
}

/// Client: handle a freshly-arrived Retry packet. Validates the
/// integrity tag against the original DCID, captures the new SCID +
/// token, re-derives Initial keys, resets handshake driver / Initial
/// space, and re-emits the ClientHello with the token included in the
/// next Initial header.
unsafe fn handle_retry(s: &mut QuicState, idx: usize, off: usize, avail: usize) -> bool {
    if s.conns[idx].is_server {
        // Servers never accept Retry packets.
        mark_inbound_consumed(&mut s.conns[idx]);
        return false;
    }
    if s.conns[idx].used_retry {
        // RFC 9000 §17.2.5 — only one Retry per connection.
        mark_inbound_consumed(&mut s.conns[idx]);
        return false;
    }
    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    let n = if avail < QUIC_DGRAM_MAX { avail } else { QUIC_DGRAM_MAX };
    core::ptr::copy_nonoverlapping(
        s.conns[idx].inbound.as_ptr().add(off),
        pkt.as_mut_ptr(),
        n,
    );
    let odcid_len = s.conns[idx].original_dcid_len as usize;
    let mut odcid_buf = [0u8; MAX_CID_LEN];
    core::ptr::copy_nonoverlapping(
        s.conns[idx].original_dcid.as_ptr(),
        odcid_buf.as_mut_ptr(),
        odcid_len,
    );
    let parsed = match parse_retry_packet(&pkt[..n], &odcid_buf[..odcid_len]) {
        Some(p) => p,
        None => {
            // Integrity tag failure: drop.
            mark_inbound_consumed(&mut s.conns[idx]);
            return false;
        }
    };
    if parsed.token_len > MAX_RETRY_TOKEN_LEN || parsed.scid_len > MAX_CID_LEN {
        mark_inbound_consumed(&mut s.conns[idx]);
        return false;
    }
    // Capture token + retry_source_cid.
    let conn = &mut s.conns[idx];
    conn.retry_token[..parsed.token_len]
        .copy_from_slice(&pkt[parsed.token_off..parsed.token_off + parsed.token_len]);
    conn.retry_token_len = parsed.token_len;
    conn.retry_source_cid[..parsed.scid_len]
        .copy_from_slice(&pkt[parsed.scid_off..parsed.scid_off + parsed.scid_len]);
    conn.retry_source_cid_len = parsed.scid_len as u8;
    conn.used_retry = true;

    // New peer_cid (= DCID we'll use in next Initial) = Retry's SCID.
    conn.peer_cid[..parsed.scid_len]
        .copy_from_slice(&pkt[parsed.scid_off..parsed.scid_off + parsed.scid_len]);
    conn.peer_cid_len = parsed.scid_len as u8;

    // Re-derive Initial keys from the new DCID.
    let mut new_dcid = [0u8; MAX_CID_LEN];
    new_dcid[..parsed.scid_len]
        .copy_from_slice(&pkt[parsed.scid_off..parsed.scid_off + parsed.scid_len]);
    install_initial_keys(conn, &new_dcid[..parsed.scid_len]);

    // Reset the Initial-level state so the re-sent ClientHello starts
    // at PN 0, offset 0 again. Other levels' state is untouched.
    conn.initial.next_send_pn = 0;
    conn.initial.largest_recv_pn = 0;
    conn.initial.crypto_recv_offset = 0;
    conn.initial.crypto_send_offset = 0;
    conn.initial.ack_pending = false;
    conn.initial.ack_tracker = AckTracker::new();
    conn.initial.reassembler.reset();
    conn.initial.last_emitted_len = 0;
    conn.initial.last_emitted_ms = 0;
    conn.initial.peer_acked_seen = false;

    // Re-prime the handshake driver to re-emit ClientHello. Retry
    // does NOT factor into the TLS transcript (RFC 9001 §8.1), so we
    // start a fresh transcript at the new ClientHello. We keep the
    // ECDH keypair from the slot's `eph_private/public` so the second
    // ClientHello carries the same key_share — saves a costly P-256
    // keygen and exercises the same shared-secret derivation path.
    let saved_eph_priv = s.eph_private[idx];
    let saved_eph_pub = s.eph_public[idx];
    let conn = &mut s.conns[idx];
    conn.driver.reset();
    conn.driver.is_server = false;
    conn.driver.hs_state = HandshakeState::SendClientHello;
    conn.driver.suite = CipherSuite::ChaCha20Poly1305;
    conn.driver.ecdh_private = saved_eph_priv;
    conn.driver.ecdh_public = saved_eph_pub;

    mark_inbound_consumed(conn);
    let sys = &*s.syscalls;
    dev_log(sys, 3, b"[quic] retry recv'd".as_ptr(), b"[quic] retry recv'd".len());
    true
}

/// Emit a Version Negotiation packet in response to an unsupported
/// version. The DCID/SCID in the response mirror what the peer sent
/// (peer's SCID becomes our DCID and vice versa), per RFC 9000
/// §17.2.1.
unsafe fn emit_version_negotiation(s: &mut QuicState, idx: usize, off: usize, avail: usize) {
    if avail < 7 {
        return;
    }
    let dcid_len = s.conns[idx].inbound[off + 5] as usize;
    if 6 + dcid_len + 1 > avail {
        return;
    }
    let scid_len_off = 6 + dcid_len;
    let scid_len = s.conns[idx].inbound[off + scid_len_off] as usize;
    if scid_len_off + 1 + scid_len > avail {
        return;
    }
    // Mirror DCID/SCID — peer's SCID becomes our DCID and vice versa.
    let mut peer_dcid = [0u8; MAX_CID_LEN];
    let mut peer_scid = [0u8; MAX_CID_LEN];
    let dn = if dcid_len <= MAX_CID_LEN { dcid_len } else { MAX_CID_LEN };
    let sn = if scid_len <= MAX_CID_LEN { scid_len } else { MAX_CID_LEN };
    core::ptr::copy_nonoverlapping(
        s.conns[idx].inbound.as_ptr().add(off + 6),
        peer_dcid.as_mut_ptr(),
        dn,
    );
    core::ptr::copy_nonoverlapping(
        s.conns[idx].inbound.as_ptr().add(off + scid_len_off + 1),
        peer_scid.as_mut_ptr(),
        sn,
    );
    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    let n = build_version_negotiation(&peer_scid[..sn], &peer_dcid[..dn], &mut pkt);
    if n == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let peer = s.conns[idx].peer;
    let listen_ep = s.listen_ep;
    send_datagram(sys, s.net_out, listen_ep, &peer, &pkt[..n], &mut s.net_scratch);
}

/// Walk a decrypted packet payload and dispatch each frame.
unsafe fn process_frames(
    conn: &mut QuicConnection,
    level: EncLevel,
    payload: &[u8],
    now_ms: u64,
) {
    let mut pos = 0;
    while pos < payload.len() {
        let frame_type = payload[pos];
        match frame_type {
            FRAME_PADDING => {
                // Skip runs of zero bytes.
                while pos < payload.len() && payload[pos] == 0 {
                    pos += 1;
                }
            }
            FRAME_PING => {
                pos += 1;
            }
            FRAME_CRYPTO => {
                pos += 1;
                let after = &payload[pos..];
                let (offset, off_len) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += off_len;
                let after = &payload[pos..];
                let (length_v, len_len) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += len_len;
                let length = length_v as usize;
                if pos + length > payload.len() {
                    return;
                }
                handle_crypto_frame(conn, level, offset, &payload[pos..pos + length]);
                pos += length;
            }
            FRAME_ACK | FRAME_ACK_ECN => {
                pos += 1;
                let after = &payload[pos..];
                let (largest, n1) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n1;
                let after = &payload[pos..];
                let (_delay, n2) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n2;
                let after = &payload[pos..];
                let (range_count, n3) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n3;
                let after = &payload[pos..];
                let (first_range, n4) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n4;
                // Walk the ranges + collect the set of acked PNs. RFC
                // 9000 §19.3.1: the first range covers
                // [largest - first_range .. largest]; subsequent ranges
                // descend, each preceded by a gap.
                let mut ack_ranges: [(u64, u64); 16] = [(0, 0); 16];
                let mut nranges = 0usize;
                let r0_low = largest.saturating_sub(first_range);
                if nranges < ack_ranges.len() {
                    ack_ranges[nranges] = (r0_low, largest);
                    nranges += 1;
                }
                let mut cur_low = r0_low;
                let mut k = 0u64;
                while k < range_count {
                    let after = &payload[pos..];
                    let (gap, ng) = match varint_decode(after.as_ptr(), after.len()) {
                        Some(t) => t,
                        None => return,
                    };
                    pos += ng;
                    let after = &payload[pos..];
                    let (rng, nr) = match varint_decode(after.as_ptr(), after.len()) {
                        Some(t) => t,
                        None => return,
                    };
                    pos += nr;
                    // RFC 9000 §19.3.1 — gap = (cur_low - 2) - new_high.
                    if cur_low < gap.saturating_add(2) {
                        break;
                    }
                    let new_high = cur_low - gap - 2;
                    let new_low = new_high.saturating_sub(rng);
                    if nranges < ack_ranges.len() {
                        ack_ranges[nranges] = (new_low, new_high);
                        nranges += 1;
                    }
                    cur_low = new_low;
                    k += 1;
                }
                if frame_type == FRAME_ACK_ECN {
                    let mut e = 0;
                    while e < 3 {
                        let after = &payload[pos..];
                        let (_v, nv) = match varint_decode(after.as_ptr(), after.len()) {
                            Some(t) => t,
                            None => return,
                        };
                        pos += nv;
                        e += 1;
                    }
                }
                // Per RFC 9002 §5.3, only sample RTT when the largest
                // newly-acked packet was ack-eliciting AND we have a
                // matching record in our sent-packet ring.
                let mut new_rtt_sample: Option<u32> = None;
                let mut acked_bytes_total: u64 = 0;
                {
                    let space = match level {
                        EncLevel::Initial => &mut conn.initial,
                        EncLevel::Handshake => &mut conn.handshake,
                        EncLevel::OneRtt => &mut conn.one_rtt,
                    };
                    if !space.peer_acked_seen || largest > space.peer_acked_largest {
                        space.peer_acked_largest = largest;
                        space.peer_acked_seen = true;
                    }
                    // For each acked PN in our ranges, walk the sent
                    // ring + clear it. Sum the bytes of newly-acked
                    // ack-eliciting packets to drive cc.
                    let mut ri = 0;
                    while ri < nranges {
                        let (lo, hi) = ack_ranges[ri];
                        let mut ix = 0;
                        while ix < SENT_PACKET_RING {
                            let p = space.sent_packets[ix];
                            if p.live && p.pn >= lo && p.pn <= hi {
                                if p.in_flight {
                                    acked_bytes_total =
                                        acked_bytes_total.saturating_add(p.bytes as u64);
                                }
                                if p.pn == largest && p.ack_eliciting && p.sent_ms > 0 {
                                    let dt = now_ms.saturating_sub(p.sent_ms);
                                    if dt < u32::MAX as u64 {
                                        new_rtt_sample = Some(dt as u32);
                                    }
                                }
                                space.sent_packets[ix].live = false;
                            }
                            ix += 1;
                        }
                        ri += 1;
                    }
                    if space.last_emitted_len > 0 && space.last_emitted_pn <= largest {
                        space.last_emitted_len = 0;
                        space.last_emitted_ms = 0;
                    }
                }
                if let Some(sample) = new_rtt_sample {
                    conn.rtt.update(sample);
                }
                // Drive NewReno (RFC 9002 §B.5). `cc_on_ack` decrements
                // bytes_in_flight + grows the window via slow-start or
                // congestion-avoidance depending on cwnd vs ssthresh.
                if acked_bytes_total > 0 {
                    conn.cc_on_ack(acked_bytes_total, now_ms);
                }
                // RFC 9002 §6.1 loss detection: a packet is lost if
                // its PN is ≤ largest_acked - 3 (§6.1.1) or it was
                // sent more than 9/8 × max(srtt, latest_rtt) ago
                // (§6.1.2).
                let mut total_lost: u64 = 0;
                let oldest_loss_time;
                {
                    let space = match level {
                        EncLevel::Initial => &mut conn.initial,
                        EncLevel::Handshake => &mut conn.handshake,
                        EncLevel::OneRtt => &mut conn.one_rtt,
                    };
                    let pkt_threshold = space.peer_acked_largest.saturating_sub(3);
                    let rtt_max = conn.rtt.smoothed_rtt.max(conn.rtt.latest_rtt) as u64;
                    let time_threshold_ms = rtt_max + (rtt_max >> 3);
                    let mut earliest_lost_ms: u64 = 0;
                    let mut ix = 0;
                    while ix < SENT_PACKET_RING {
                        let p = space.sent_packets[ix];
                        if !p.live {
                            ix += 1;
                            continue;
                        }
                        let mut lost = false;
                        if space.peer_acked_seen && p.pn <= pkt_threshold {
                            lost = true;
                        }
                        if !lost && time_threshold_ms > 0
                            && p.sent_ms > 0
                            && now_ms.saturating_sub(p.sent_ms) > time_threshold_ms
                        {
                            lost = true;
                        }
                        if lost {
                            if p.in_flight {
                                total_lost = total_lost.saturating_add(p.bytes as u64);
                            }
                            if earliest_lost_ms == 0 || p.sent_ms < earliest_lost_ms {
                                earliest_lost_ms = p.sent_ms;
                            }
                            space.sent_packets[ix].live = false;
                        }
                        ix += 1;
                    }
                    oldest_loss_time = earliest_lost_ms;
                }
                if total_lost > 0 {
                    conn.cc_on_loss(total_lost, oldest_loss_time);
                }
            }
            FRAME_MAX_DATA => {
                pos += 1;
                let after = &payload[pos..];
                let (max, n) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n;
                // Peer is bumping our connection-level send window.
                // Track but don't yet use for emission backpressure.
                let _ = max;
            }
            FRAME_MAX_STREAM_DATA => {
                pos += 1;
                let after = &payload[pos..];
                let (_id, n1) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n1;
                let after = &payload[pos..];
                let (_max, n2) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n2;
            }
            FRAME_DATA_BLOCKED => {
                pos += 1;
                let after = &payload[pos..];
                let (_lim, n) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n;
                // Peer is connection-blocked; a full implementation
                // responds with MAX_DATA to unblock.
            }
            FRAME_NEW_CONNECTION_ID => {
                pos += 1;
                let after = &payload[pos..];
                let (_seq, n1) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n1;
                let after = &payload[pos..];
                let (_retire, n2) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n2;
                if pos >= payload.len() {
                    return;
                }
                let cid_len = payload[pos] as usize;
                pos += 1;
                if pos + cid_len + 16 > payload.len() {
                    return;
                }
                // Production: store the new CID + token in a per-conn
                // CID pool, swap to it on connection migration. We
                // accept the frame structurally so peers don't get
                // FRAME_ENCODING_ERROR, but don't migrate.
                pos += cid_len + 16;
            }
            FRAME_RETIRE_CONNECTION_ID => {
                pos += 1;
                let after = &payload[pos..];
                let (_seq, n) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n;
            }
            FRAME_CONNECTION_CLOSE_TRANSPORT | FRAME_CONNECTION_CLOSE_APP => {
                let app = frame_type == FRAME_CONNECTION_CLOSE_APP;
                pos += 1;
                let after = &payload[pos..];
                let (err, n) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n;
                if !app {
                    let after = &payload[pos..];
                    let (_fc, nn) = match varint_decode(after.as_ptr(), after.len()) {
                        Some(t) => t,
                        None => return,
                    };
                    pos += nn;
                }
                let after = &payload[pos..];
                let (rlen, nr) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += nr;
                let rl = rlen as usize;
                if pos + rl > payload.len() {
                    return;
                }
                pos += rl;
                // RFC 9000 §10.2 — peer signalled close. Move to
                // Closed; an idle-tick will free the slot.
                conn.phase = ConnPhase::Closed;
                let _ = err;
            }
            FRAME_RESET_STREAM => {
                pos += 1;
                let after = &payload[pos..];
                let (_sid, n1) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n1;
                let after = &payload[pos..];
                let (_err, n2) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n2;
                let after = &payload[pos..];
                let (_fs, n3) = match varint_decode(after.as_ptr(), after.len()) {
                    Some(t) => t,
                    None => return,
                };
                pos += n3;
            }
            FRAME_HANDSHAKE_DONE => {
                pos += 1;
                // RFC 9001 §4.1.2: a client that receives HANDSHAKE_DONE
                // marks the handshake as confirmed.
                if !conn.is_server && matches!(level, EncLevel::OneRtt) {
                    conn.handshake_confirmed = true;
                }
            }
            t if t >= FRAME_STREAM_BASE && t <= FRAME_STREAM_END => {
                pos += 1;
                let after = &payload[pos..];
                let (sf, n) = match parse_stream(t, after) {
                    Some(t) => t,
                    None => return,
                };
                pos += n;
                if matches!(level, EncLevel::OneRtt) {
                    handle_stream_frame(conn, &sf);
                }
            }
            _ => {
                // Unknown / unhandled frame — abort.
                return;
            }
        }
    }
}

/// Handle an inbound STREAM frame. stream_id 0 lands in the
/// `stream_recv_buf` path; other bidi-shaped ids go to the
/// `bidi_extra_streams` pool; uni-shaped ids go to the
/// `extra_streams` table (RFC 9000 §2.1 stream-id encoding). Partial
/// overlap is accepted; out-of-order arrivals are dropped and rely
/// on the peer's retransmission.
unsafe fn handle_stream_frame(conn: &mut QuicConnection, sf: &StreamFrame<'_>) {
    if sf.stream_id == 0 {
        let base = conn.stream_recv_off;
        let frame_end = sf.offset + sf.data.len() as u64;
        if frame_end <= base {
            return;
        }
        let data_slice = if sf.offset < base {
            let s = (base - sf.offset) as usize;
            &sf.data[s..]
        } else if sf.offset == base {
            sf.data
        } else {
            return;
        };
        let space = conn.stream_recv_buf.len() - conn.stream_recv_buf_len;
        let n = data_slice.len().min(space);
        if n == 0 && !data_slice.is_empty() {
            return;
        }
        core::ptr::copy_nonoverlapping(
            data_slice.as_ptr(),
            conn.stream_recv_buf.as_mut_ptr().add(conn.stream_recv_buf_len),
            n,
        );
        conn.stream_recv_buf_len += n;
        conn.stream_recv_off += n as u64;
        if sf.fin && n == data_slice.len() {
            conn.stream_recv_fin = true;
        }
        return;
    }

    // RFC 9000 §2.1: bit 1 of `stream_id` is 0 for bidi, 1 for uni.
    let is_bidi = (sf.stream_id & 0x2) == 0;
    if is_bidi {
        let slot_idx = match bidi_find(conn, sf.stream_id) {
            Some(i) => i,
            None => match bidi_alloc(conn, sf.stream_id, false) {
                Some(i) => i,
                None => return,
            },
        };
        let slot = &mut conn.bidi_extra_streams[slot_idx];
        let base = slot.recv_off;
        let frame_end = sf.offset + sf.data.len() as u64;
        if frame_end <= base {
            return;
        }
        let data_slice = if sf.offset < base {
            let s = (base - sf.offset) as usize;
            &sf.data[s..]
        } else if sf.offset == base {
            sf.data
        } else {
            return;
        };
        let space = slot.recv_buf.len() - slot.recv_buf_len;
        let n = data_slice.len().min(space);
        if n == 0 && !data_slice.is_empty() {
            return;
        }
        core::ptr::copy_nonoverlapping(
            data_slice.as_ptr(),
            slot.recv_buf.as_mut_ptr().add(slot.recv_buf_len),
            n,
        );
        slot.recv_buf_len += n;
        slot.recv_off += n as u64;
        if sf.fin && n == data_slice.len() {
            slot.recv_fin = true;
        }
        return;
    }

    // Uni stream id: route into extra_streams.
    let slot_idx = match extra_find(conn, sf.stream_id) {
        Some(i) => i,
        None => match extra_alloc(conn, sf.stream_id, false) {
            Some(i) => i,
            None => return,
        },
    };
    let slot = &mut conn.extra_streams[slot_idx];
    let base = slot.recv_off;
    let frame_end = sf.offset + sf.data.len() as u64;
    if frame_end <= base {
        return;
    }
    let data_slice = if sf.offset < base {
        let s = (base - sf.offset) as usize;
        &sf.data[s..]
    } else if sf.offset == base {
        sf.data
    } else {
        return;
    };
    let space = slot.recv_buf.len() - slot.recv_buf_len;
    let n = data_slice.len().min(space);
    if n == 0 && !data_slice.is_empty() {
        return;
    }
    core::ptr::copy_nonoverlapping(
        data_slice.as_ptr(),
        slot.recv_buf.as_mut_ptr().add(slot.recv_buf_len),
        n,
    );
    slot.recv_buf_len += n;
    slot.recv_off += n as u64;
    if sf.fin && n == data_slice.len() {
        slot.recv_fin = true;
    }
}

/// Feed a CRYPTO frame's data into the HandshakeDriver, reassembling
/// out-of-order arrivals via the per-EncLevel `CryptoReassembler`.
/// Duplicate prefixes are silently truncated; gaps are filled in as
/// later frames arrive.
unsafe fn handle_crypto_frame(
    conn: &mut QuicConnection,
    level: EncLevel,
    offset: u64,
    data: &[u8],
) {
    let space = match level {
        EncLevel::Initial => &mut conn.initial,
        EncLevel::Handshake => &mut conn.handshake,
        EncLevel::OneRtt => &mut conn.one_rtt,
    };

    // Skip any prefix that's already been delivered.
    let base = space.crypto_recv_offset;
    if offset + data.len() as u64 <= base {
        return; // Pure duplicate.
    }
    let (skip, data) = if offset < base {
        let s = (base - offset) as usize;
        (s, &data[s..])
    } else {
        (0, data)
    };
    let rel_off = (offset + skip as u64 - base) as usize;
    let high = space.reassembler.insert(rel_off, data);

    // Drain the contiguous prefix now exposed at the front of the hold.
    if high == 0 {
        return;
    }
    // Snapshot the contiguous bytes out of the hold buffer so we can
    // shift before feeding the driver (avoids overlapping borrows).
    let mut tmp = [0u8; CRYPTO_HOLD_LEN];
    core::ptr::copy_nonoverlapping(
        space.reassembler.buf.as_ptr(),
        tmp.as_mut_ptr(),
        high,
    );
    space.reassembler.shift(high);
    space.crypto_recv_offset += high as u64;

    // Post-handshake CRYPTO at OneRtt = NewSessionTicket / KeyUpdate
    // / handshake_done extensions (RFC 8446 §4.6 + §4.6.3). We bypass
    // the in_buf queue and parse directly so we don't confuse the
    // pump_recv_* readers that look at in_buf.
    if matches!(level, EncLevel::OneRtt) && !conn.is_server {
        handle_post_handshake_crypto(conn, &tmp[..high]);
        return;
    }
    let _ = conn.driver.feed_handshake(level, &tmp[..high]);
}

/// Client-side post-handshake CRYPTO bytes: the only message we
/// recognise is NewSessionTicket (handshake type 4). On parse, we
/// derive the ticket-specific PSK + cache it for future resumption.
unsafe fn handle_post_handshake_crypto(conn: &mut QuicConnection, mut data: &[u8]) {
    // The peer may concatenate multiple post-handshake messages —
    // walk them. Each starts with a 4-byte handshake header.
    while data.len() >= 4 {
        let msg_type = data[0];
        let body_len = ((data[1] as usize) << 16)
            | ((data[2] as usize) << 8)
            | (data[3] as usize);
        if 4 + body_len > data.len() {
            break;
        }
        let body = &data[4..4 + body_len];
        if msg_type == 4 /* HT_NEW_SESSION_TICKET */ {
            if let Some(parsed) = parse_new_session_ticket(body) {
                let _ = parsed.lifetime_s;
                let _ = parsed; // surfaced via the conn-level callback
                // Derive the per-ticket PSK = HKDF-Expand-Label(
                //   resumption_master_secret, "resumption", ticket_nonce, hash_len
                // ). For that we need the RMS — derive it now from
                // master_secret + client Finished hash if not already.
                // The client uses its own server_finished_hash plus the
                // post-finished transcript update — for simplicity we
                // re-derive RMS using the current transcript hash
                // (which on the client at this point includes its own
                // Finished, equivalent to the server's view).
                conn.session_ticket_handled = true;
                // Stash identity + parsed bytes on the conn for the
                // outer pump to copy into the client_tickets cache.
                let id_len = parsed.ticket.len().min(conn.psk_identity.len());
                conn.psk_identity[..id_len].copy_from_slice(&parsed.ticket[..id_len]);
                conn.psk_identity_len = id_len as u8;
                // PSK derivation: needs RMS + nonce. Compute RMS from
                // current key_schedule + transcript.
                let hl = conn.driver.suite.hash_len();
                let mut rms = [0u8; 48];
                let transcript_hash = match &conn.driver.transcript {
                    Some(t) => t.current_hash(),
                    None => return,
                };
                if let Some(ref ks) = conn.driver.key_schedule {
                    ks.derive_resumption_master(&transcript_hash[..hl], &mut rms[..hl]);
                    let mut psk = [0u8; 48];
                    ks.ticket_psk(&rms[..hl], parsed.nonce, &mut psk[..hl]);
                    conn.psk[..hl].copy_from_slice(&psk[..hl]);
                    conn.psk_len = hl as u8;
                }
            }
        }
        data = &data[4 + body_len..];
    }
}

// ---------------------------------------------------------------------
// Outbound drain — pull queued handshake bytes, frame as CRYPTO,
// pack into a packet of the appropriate EncLevel, send via UDP.
// ---------------------------------------------------------------------

fn current_send_level(conn: &QuicConnection) -> EncLevel {
    if conn.one_rtt.keys_set
        && (matches!(conn.driver.hs_state, HandshakeState::Complete)
            || matches!(conn.driver.hs_state, HandshakeState::ClientDeriveAppKeys)
            || matches!(conn.driver.hs_state, HandshakeState::DeriveAppKeys))
    {
        EncLevel::OneRtt
    } else if conn.handshake.keys_set {
        EncLevel::Handshake
    } else {
        EncLevel::Initial
    }
}

unsafe fn drain_outbound(s: &mut QuicState, idx: usize) {
    loop {
        let mut send_len;
        let level;
        let mut emit_ack_only = false;
        // `force_ack_only` is the stronger sibling of `emit_ack_only`:
        // when true, `emit_crypto_packet` will suppress every
        // ack-eliciting frame and pack only the pending ACK. We set
        // this when CC blocks ack-eliciting traffic but there's still
        // an ACK that needs to ship (RFC 9002 §A.1 — ACKs aren't
        // congestion-controlled).
        let mut force_ack_only = false;
        {
            let conn = &s.conns[idx];
            let lvl_now = current_send_level(conn);

            // Survey 1-RTT ack-eliciting work pending in any of the four
            // sources (main stream, HANDSHAKE_DONE, h3 unidirectional
            // extra streams, h3 bidirectional extra streams). Each one
            // adds ack-eliciting frames to the packet and so must be
            // gated by congestion control under RFC 9002 §7.
            let has_extra_pending = {
                let mut found = false;
                let mut k = 0;
                while k < MAX_EXTRA_STREAMS {
                    let st = &conn.extra_streams[k];
                    if st.allocated
                        && st.locally_initiated
                        && (st.send_buf_len > 0
                            || (st.send_fin_pending && !st.send_fin_emitted))
                    {
                        found = true;
                        break;
                    }
                    k += 1;
                }
                if !found {
                    let mut k = 0;
                    while k < MAX_BIDI_EXTRA_STREAMS {
                        let st = &conn.bidi_extra_streams[k];
                        if st.allocated
                            && (st.send_buf_len > 0
                                || (st.send_fin_pending && !st.send_fin_emitted))
                        {
                            found = true;
                            break;
                        }
                        k += 1;
                    }
                }
                found
            };
            let one_rtt_ack_eliciting_pending = conn.stream_send_buf_len > 0
                || conn.stream_send_fin
                || conn.pending_handshake_done
                || has_extra_pending;

            // RFC 9002 §7 — congestion control gates every ack-eliciting
            // 1-RTT send. Initial / Handshake packets are exempt so an
            // early window collapse can't deadlock the handshake; ACK
            // frames are also exempt (RFC 9002 §A.1, §7) because they
            // aren't ack-eliciting and don't count toward bytes_in_flight.
            //
            // 1-RTT data falls in two flavours, both ack-eliciting:
            //   • CRYPTO bytes pending in driver.out_buf at OneRtt
            //     level (post-handshake key updates, server's
            //     NewSessionTicket frame) — `lvl_now == OneRtt &&
            //     driver.out_len > 0`.
            //   • Other 1-RTT frames: STREAM, HANDSHAKE_DONE, h3
            //     extra-stream / bidi-extra-stream STREAMs.
            //
            // Both categories must be CC-gated; previously only the
            // second was, letting NewSessionTicket bypass cwnd.
            let level_at_one_rtt = matches!(lvl_now, EncLevel::OneRtt);
            let one_rtt_crypto_pending = level_at_one_rtt && conn.driver.out_len > 0;
            let one_rtt_data_pending =
                one_rtt_crypto_pending || (level_at_one_rtt && one_rtt_ack_eliciting_pending);
            let one_rtt_cc_blocked = one_rtt_data_pending
                && !conn.cc_can_send(MAX_DATAGRAM_SIZE);

            // ACKs are not congestion-controlled (RFC 9002 §A.1, §7),
            // so a CC-blocked 1-RTT path must NOT suppress pending
            // lower-level ACKs. The early-return only fires when CC
            // blocks AND every level's ACK is empty — otherwise fall
            // through to the level selector below which will pick the
            // lowest level with a pending ACK.
            let any_ack_sendable = (conn.initial.ack_pending && conn.initial.keys_set)
                || (conn.handshake.ack_pending && conn.handshake.keys_set)
                || (conn.one_rtt.ack_pending && conn.one_rtt.keys_set);
            if one_rtt_cc_blocked && !any_ack_sendable {
                // CC blocks all ack-eliciting work and there's no
                // piggyback ACK at any level — nothing useful to
                // send this tick.
                return;
            }

            if conn.driver.out_len > 0 && !one_rtt_cc_blocked {
                // CRYPTO can ship: either at Initial / Handshake
                // (CC-exempt) or at OneRtt with cwnd available.
                send_len = conn.driver.out_len;
                level = current_send_level(conn);
            } else {
                // Either driver.out_buf is empty, or a 1-RTT CRYPTO
                // payload is sitting in it but blocked by CC. In the
                // latter case the CRYPTO bytes stay in the buffer for
                // the next tick. Pick the lowest level with a pending
                // ACK first (RFC 9000 §17.2 forbids 1-RTT before
                // handshake completes, server-side); these are CC
                // exempt and ship even when 1-RTT is blocked.
                send_len = 0;
                if conn.initial.ack_pending && conn.initial.keys_set {
                    level = EncLevel::Initial;
                    emit_ack_only = true;
                } else if conn.handshake.ack_pending && conn.handshake.keys_set {
                    level = EncLevel::Handshake;
                    emit_ack_only = true;
                } else if (conn.one_rtt.ack_pending
                    || one_rtt_ack_eliciting_pending
                    || one_rtt_crypto_pending)
                    && conn.one_rtt.keys_set
                {
                    level = EncLevel::OneRtt;
                    emit_ack_only = true;
                    // CC-blocked but ACK pending → suppress every
                    // ack-eliciting frame (and 1-RTT CRYPTO) so this
                    // packet ships as a pure ACK without overshooting
                    // cwnd.
                    if one_rtt_cc_blocked {
                        force_ack_only = true;
                    }
                } else {
                    return;
                }
            }

            // Ring-full back-pressure gate. If this emit would be
            // ack-eliciting (CRYPTO at any level, or 1-RTT data when
            // not in force_ack_only mode), the chosen level's
            // sent_packets ring must have a free slot. Without this
            // gate, ack-eliciting traffic that exceeds SENT_PACKET_RING
            // outstanding entries would overwrite still-live tracking
            // records — incoming ACKs could no longer find them, so
            // bytes_in_flight would never be credited back and CC
            // would stall artificially.
            //
            // Pure-ACK / CONNECTION_CLOSE-style packets aren't
            // tracked, so they skip the gate.
            let would_be_ack_eliciting = if force_ack_only {
                false
            } else if send_len > 0 {
                true
            } else {
                matches!(level, EncLevel::OneRtt) && one_rtt_ack_eliciting_pending
            };
            if would_be_ack_eliciting {
                let space = match level {
                    EncLevel::Initial => &conn.initial,
                    EncLevel::Handshake => &conn.handshake,
                    EncLevel::OneRtt => &conn.one_rtt,
                };
                if !space.has_free_sent_slot() {
                    // Ring full at the chosen level. ACKs aren't
                    // ring-tracked (RFC 9002 §A.1, §6.1 — only
                    // ack-eliciting packets feed loss/RTT) so a
                    // 1-RTT ACK can still ship. Downgrade to
                    // ack-only — same shape as the cc_blocked
                    // fallback above. Initial / Handshake CRYPTO
                    // can't downgrade (CRYPTO IS the payload at
                    // those levels), so we bail there and wait
                    // for ACKs to free a slot.
                    if matches!(level, EncLevel::OneRtt) && conn.one_rtt.ack_pending {
                        force_ack_only = true;
                        emit_ack_only = true;
                        send_len = 0;
                    } else {
                        return;
                    }
                }
            }
        }
        let (emitted, crypto_consumed) =
            emit_crypto_packet(s, idx, level, send_len, force_ack_only);
        if !emitted {
            // No packet went on the wire — final build failed (packet
            // overflow / encoding error) or there was nothing to pack.
            // Bail out for both CRYPTO and ack-only paths; otherwise
            // drain_outbound would spin re-trying the same emit against
            // the same unchanged conn state. The pending state survives
            // for the next tick to retry once new conditions apply.
            return;
        }
        if !emit_ack_only {
            // CRYPTO path: trim only what was actually packed.
            let conn = &mut s.conns[idx];
            if crypto_consumed > 0 {
                let remain = conn.driver.out_len - crypto_consumed;
                if remain > 0 {
                    core::ptr::copy(
                        conn.driver.out_buf.as_ptr().add(crypto_consumed),
                        conn.driver.out_buf.as_mut_ptr(),
                        remain,
                    );
                }
                conn.driver.out_len = remain;
            }
        }
    }
}

/// Build + send one packet at `level` carrying a single CRYPTO frame
/// with the next `send_len` bytes from `conn.driver.out_buf`.
///
/// `ack_only_mode = true` suppresses every ack-eliciting frame
/// (CRYPTO, HANDSHAKE_DONE, STREAM, extra/bidi STREAM) so the caller
/// can ship a pure-ACK packet when congestion control is blocking
/// ack-eliciting traffic. ACK frames are not congestion-controlled
/// (RFC 9002 §A.1, §7) and so must be allowed through even when
/// `cc_can_send` is false; otherwise the peer's loss recovery stalls.
///
/// Returns `(emitted, crypto_packed)`:
///   * `emitted` is true iff a packet was actually written to the wire.
///     If false, the caller must not advance any driver state and must
///     not loop back into the same emit path this tick — the pending
///     state will retry on a future tick once conditions change.
///   * `crypto_packed` is the number of CRYPTO bytes that made it into
///     the emitted packet (≤ `send_len`; always 0 in ack-only mode).
///     The caller advances `driver.out_buf` by exactly that many
///     bytes. Large flights are fragmented across multiple
///     `drain_outbound` iterations.
///
/// All other connection-state mutations (PN advance, ack_pending,
/// pending_handshake_done, per-stream send buffers) are deferred to
/// the success path so a build failure leaves no "sent" residue.
unsafe fn emit_crypto_packet(
    s: &mut QuicState,
    idx: usize,
    level: EncLevel,
    send_len: usize,
    ack_only_mode: bool,
) -> (bool, usize) {
    let sys = &*s.syscalls;

    // Snapshot necessary fields out of the connection so we can build
    // payloads without holding a borrow on the conn during send.
    let (offset, our_cid, our_cid_len, peer_cid, peer_cid_len, peer, is_server) = {
        let conn = &s.conns[idx];
        let space = match level {
            EncLevel::Initial => &conn.initial,
            EncLevel::Handshake => &conn.handshake,
            EncLevel::OneRtt => &conn.one_rtt,
        };
        (
            space.crypto_send_offset,
            conn.our_cid,
            conn.our_cid_len,
            conn.peer_cid,
            conn.peer_cid_len,
            conn.peer,
            conn.is_server,
        )
    };

    // Assemble the cleartext payload: optional ACK frame + optional
    // CRYPTO frame + (Initial-only) PADDING to ≥1200 bytes.
    //
    // Connection-state mutations (clearing pending_handshake_done,
    // zeroing per-stream send_buf_len, advancing offsets, advancing
    // PNs, clearing ack_pending) are deferred to the success path at
    // the bottom of this function so a packet-build failure doesn't
    // leak "sent" state for bytes that never made it onto the wire.
    let mut payload = [0u8; QUIC_DGRAM_MAX];
    let mut payload_len = 0;

    // ACK frame (if a packet number space has unacknowledged ACK).
    let mut had_ack = false;
    {
        let conn = &s.conns[idx];
        let space = match level {
            EncLevel::Initial => &conn.initial,
            EncLevel::Handshake => &conn.handshake,
            EncLevel::OneRtt => &conn.one_rtt,
        };
        if space.ack_pending && space.ack_tracker.count > 0 {
            let n = build_ack_frame(&space.ack_tracker, 0, &mut payload[payload_len..]);
            if n > 0 {
                payload_len += n;
                had_ack = true;
            }
        }
    }

    // CRYPTO frame (if we're sending handshake bytes). RFC 9000 §7.5
    // explicitly permits — and large flights (cert chains) require —
    // splitting handshake bytes across multiple QUIC packets via
    // multiple CRYPTO frames at increasing offsets. We cap the data
    // packed into this packet so a 1.3KB+ flight ships as N back-to-back
    // packets instead of stalling forever on a single-packet build that
    // can't fit. The remaining bytes stay in `driver.out_buf` and the
    // next `drain_outbound` iteration picks them up.
    //
    // MAX_CRYPTO_FRAME_PAYLOAD is sized so the resulting QUIC packet
    // (header + pn + payload + AEAD tag) comfortably fits in the
    // 1500-byte `pkt` buffer used by `build_*_packet`. The leftover
    // headroom (~200B) covers worst-case long-header packets:
    // 1B first + 4B version + 1B + DCID(20) + 1B + SCID(20) + token
    // varint + token + length varint + 4B pn + 16B AEAD tag.
    const MAX_CRYPTO_FRAME_PAYLOAD: usize = 1300;
    // ack_only_mode only suppresses CRYPTO at 1-RTT — Initial /
    // Handshake CRYPTO carries the handshake itself and is exempt
    // from CC, so we never want to skip it. The caller is expected
    // to only set ack_only_mode when level == OneRtt; this guard is
    // defense-in-depth.
    let suppress_crypto = ack_only_mode && matches!(level, EncLevel::OneRtt);
    let mut crypto_packed: usize = 0;
    if send_len > 0 && !suppress_crypto {
        // Reserve room for the CRYPTO frame's own header (type byte +
        // varint offset + varint length, max 17 bytes total) plus
        // anything already in the payload (typically the ACK frame).
        let frame_overhead = 1 + 8 + 8;
        let avail = MAX_CRYPTO_FRAME_PAYLOAD
            .saturating_sub(payload_len)
            .saturating_sub(frame_overhead);
        let send_now = if avail == 0 {
            0
        } else if send_len < avail {
            send_len
        } else {
            avail
        };
        if send_now > 0 {
            let mut frame_buf = [0u8; QUIC_DGRAM_MAX];
            let frame_len = build_crypto(
                offset,
                &s.conns[idx].driver.out_buf[..send_now],
                &mut frame_buf,
            );
            if frame_len == 0 || payload_len + frame_len > payload.len() {
                // Frame builder rejected our budget — abort without
                // mutating per-conn state so the caller retries with
                // identical inputs next tick (defensive: the cap above
                // should make this unreachable).
                return (false, 0);
            }
            payload[payload_len..payload_len + frame_len]
                .copy_from_slice(&frame_buf[..frame_len]);
            payload_len += frame_len;
            crypto_packed = send_now;
        }
    }

    // HANDSHAKE_DONE (1-RTT only, server-only, queued at Complete).
    let mut had_handshake_done = false;
    if matches!(level, EncLevel::OneRtt)
        && !ack_only_mode
        && s.conns[idx].pending_handshake_done
    {
        if payload_len + 1 <= payload.len() {
            payload[payload_len] = FRAME_HANDSHAKE_DONE;
            payload_len += 1;
            had_handshake_done = true;
        }
    }

    // STREAM frame (1-RTT only) carrying app data on stream id 0.
    let mut had_main_stream = false;
    let mut main_stream_buf_len: usize = 0;
    let mut main_stream_fin_emitted = false;
    let mut had_extra_stream = [false; MAX_EXTRA_STREAMS];
    let mut extra_stream_buf_len = [0usize; MAX_EXTRA_STREAMS];
    let mut extra_stream_fin_emitted = [false; MAX_EXTRA_STREAMS];
    let mut had_bidi_stream = [false; MAX_BIDI_EXTRA_STREAMS];
    let mut bidi_stream_buf_len = [0usize; MAX_BIDI_EXTRA_STREAMS];
    let mut bidi_stream_fin_emitted = [false; MAX_BIDI_EXTRA_STREAMS];
    if matches!(level, EncLevel::OneRtt) && !ack_only_mode {
        let conn = &s.conns[idx];
        if conn.stream_send_buf_len > 0 || conn.stream_send_fin {
            let mut frame_buf = [0u8; QUIC_DGRAM_MAX];
            let n = build_stream(
                0,
                conn.stream_send_off,
                conn.stream_send_fin,
                &conn.stream_send_buf[..conn.stream_send_buf_len],
                &mut frame_buf,
            );
            if n > 0 && payload_len + n <= payload.len() {
                payload[payload_len..payload_len + n].copy_from_slice(&frame_buf[..n]);
                payload_len += n;
                had_main_stream = true;
                main_stream_buf_len = conn.stream_send_buf_len;
                main_stream_fin_emitted = conn.stream_send_fin;
            }
        }
        // Extra streams (h3 control + qpack-enc + qpack-dec). One
        // STREAM frame per slot; multiple may be packed into the same
        // QUIC packet.
        let mut k = 0;
        while k < MAX_EXTRA_STREAMS {
            let slot = &conn.extra_streams[k];
            if slot.allocated && slot.locally_initiated
                && (slot.send_buf_len > 0
                    || (slot.send_fin_pending && !slot.send_fin_emitted))
            {
                let stream_id = slot.stream_id;
                let send_off = slot.send_off;
                let fin = slot.send_fin_pending;
                let buf_len = slot.send_buf_len;
                let mut frame_buf = [0u8; 384];
                let n = build_stream(
                    stream_id,
                    send_off,
                    fin,
                    &slot.send_buf[..buf_len],
                    &mut frame_buf,
                );
                if n > 0 && payload_len + n <= payload.len() {
                    payload[payload_len..payload_len + n].copy_from_slice(&frame_buf[..n]);
                    payload_len += n;
                    had_extra_stream[k] = true;
                    extra_stream_buf_len[k] = buf_len;
                    extra_stream_fin_emitted[k] = fin;
                }
            }
            k += 1;
        }
        // Bidi extra streams (additional concurrent request streams).
        // One STREAM frame per occupied slot per packet.
        let mut k = 0;
        while k < MAX_BIDI_EXTRA_STREAMS {
            let slot = &conn.bidi_extra_streams[k];
            if slot.allocated
                && (slot.send_buf_len > 0
                    || (slot.send_fin_pending && !slot.send_fin_emitted))
            {
                let stream_id = slot.stream_id;
                let send_off = slot.send_off;
                let fin = slot.send_fin_pending;
                let buf_len = slot.send_buf_len;
                let mut frame_buf = [0u8; QUIC_DGRAM_MAX];
                let n = build_stream(
                    stream_id,
                    send_off,
                    fin,
                    &slot.send_buf[..buf_len],
                    &mut frame_buf,
                );
                if n > 0 && payload_len + n <= payload.len() {
                    payload[payload_len..payload_len + n].copy_from_slice(&frame_buf[..n]);
                    payload_len += n;
                    had_bidi_stream[k] = true;
                    bidi_stream_buf_len[k] = buf_len;
                    bidi_stream_fin_emitted[k] = fin;
                }
            }
            k += 1;
        }
    }

    if payload_len == 0 {
        return (false, 0);
    }

    // For client Initial packets, RFC 9000 §14.1 mandates ≥1200 byte
    // datagrams. We pad the payload with 0x00 (PADDING) frames.
    let pad_to_min_initial = matches!(level, EncLevel::Initial) && !is_server;

    let pn_len = 4;
    let dcid: &[u8] = match level {
        EncLevel::Initial => {
            // Client's first Initial carries the random "original DCID";
            // later packets use the server's SCID. Both end up in
            // `peer_cid` by the time we serialise.
            &peer_cid[..peer_cid_len as usize]
        }
        _ => &peer_cid[..peer_cid_len as usize],
    };
    let scid: &[u8] = &our_cid[..our_cid_len as usize];

    // Pre-compute total length to decide padding for Initial.
    // Token-length varint + token bytes need to be accounted for if
    // the client carries a Retry token.
    let token_inline_len = if matches!(level, EncLevel::Initial)
        && !is_server
        && s.conns[idx].retry_token_len > 0
    {
        s.conns[idx].retry_token_len
    } else {
        0
    };
    if pad_to_min_initial {
        let token_len_size = if token_inline_len == 0 { 1 } else { 2 };
        let est_length_size = 4; // varint(len) — bumped pessimistically
        let hdr = 1 + 4 + 1 + dcid.len() + 1 + scid.len()
            + token_len_size + token_inline_len + est_length_size;
        let aead = pn_len + payload_len + 16;
        let total = hdr + aead;
        if total < 1200 {
            let pad = 1200 - total;
            if payload_len + pad <= payload.len() {
                payload_len += pad;
            }
        }
    }

    // Pick keys + hp + key_phase for this level. PN and crypto offset
    // are *read* here but the write-back is deferred until after
    // `build_*_packet` succeeds (see post-build state-mutation block
    // below) so a build failure doesn't burn a PN or skip CRYPTO bytes.
    let keys: QuicKeys;
    let hp_key: [u8; QUIC_HP_KEY_LEN];
    let pn: u64;
    let key_phase: u8;
    {
        let conn = &s.conns[idx];
        let space = match level {
            EncLevel::Initial => &conn.initial,
            EncLevel::Handshake => &conn.handshake,
            EncLevel::OneRtt => &conn.one_rtt,
        };
        keys = space.write_keys;
        hp_key = space.write_keys.hp;
        pn = space.next_send_pn;
        key_phase = if matches!(level, EncLevel::OneRtt) {
            conn.one_rtt.key_phase
        } else {
            0
        };
    }
    let hp = Aes128Hp::new(&hp_key);

    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    // Retry token (client-side, post-Retry only) — included in the
    // header of every subsequent Initial packet (RFC 9000 §17.2.5).
    let mut token_buf = [0u8; MAX_RETRY_TOKEN_LEN];
    let token: &[u8] = if matches!(level, EncLevel::Initial)
        && !s.conns[idx].is_server
        && s.conns[idx].retry_token_len > 0
    {
        let t_len = s.conns[idx].retry_token_len;
        token_buf[..t_len]
            .copy_from_slice(&s.conns[idx].retry_token[..t_len]);
        &token_buf[..t_len]
    } else {
        &[]
    };
    let n = match level {
        EncLevel::Initial => build_initial_packet(
            &keys, &hp, pn, pn_len, dcid, scid, token, &payload[..payload_len], &mut pkt,
        ),
        EncLevel::Handshake => build_handshake_packet(
            &keys, &hp, pn, pn_len, dcid, scid, &payload[..payload_len], &mut pkt,
        ),
        EncLevel::OneRtt => build_one_rtt_packet(
            &keys, &hp, pn, pn_len, key_phase, dcid, &payload[..payload_len], &mut pkt,
        ),
    };
    if n == 0 {
        // Final packet build failed — leave every per-conn field
        // intact (PN, crypto offset, ack_pending, pending_handshake_done,
        // stream send buffers) so the next tick retries from a clean
        // state. Returning (false, 0) also signals drain_outbound to
        // bail this tick instead of looping on the same failure.
        return (false, 0);
    }

    let listen_ep = s.listen_ep;
    send_datagram(sys, s.net_out, listen_ep, &peer, &pkt[..n], &mut s.net_scratch);
    // Idle-timeout activity stamp on emit too (RFC 9000 §10.1.2).
    s.conns[idx].last_activity_ms = dev_millis(sys);

    // ── Apply deferred state mutations ─────────────────────────────
    // Now that the packet is on the wire we can safely advance
    // sender-side state. Anything cleared here must have been
    // recorded into the local `had_*` flags above so a build failure
    // would have left the conn untouched.
    {
        let conn = &mut s.conns[idx];
        if had_handshake_done {
            conn.pending_handshake_done = false;
        }
        if had_main_stream {
            conn.stream_send_off += main_stream_buf_len as u64;
            conn.stream_send_buf_len = 0;
            if main_stream_fin_emitted {
                conn.stream_send_fin = false;
            }
        }
        let mut k = 0;
        while k < MAX_EXTRA_STREAMS {
            if had_extra_stream[k] {
                let slot = &mut conn.extra_streams[k];
                slot.send_off += extra_stream_buf_len[k] as u64;
                slot.send_buf_len = 0;
                if extra_stream_fin_emitted[k] {
                    slot.send_fin_emitted = true;
                    slot.send_fin_pending = false;
                }
            }
            k += 1;
        }
        let mut k = 0;
        while k < MAX_BIDI_EXTRA_STREAMS {
            if had_bidi_stream[k] {
                let slot = &mut conn.bidi_extra_streams[k];
                slot.send_off += bidi_stream_buf_len[k] as u64;
                slot.send_buf_len = 0;
                if bidi_stream_fin_emitted[k] {
                    slot.send_fin_emitted = true;
                    slot.send_fin_pending = false;
                }
            }
            k += 1;
        }
        let space = match level {
            EncLevel::Initial => &mut conn.initial,
            EncLevel::Handshake => &mut conn.handshake,
            EncLevel::OneRtt => &mut conn.one_rtt,
        };
        space.next_send_pn = pn + 1;
        space.crypto_send_offset += crypto_packed as u64;
        if had_ack {
            space.ack_pending = false;
        }
    }

    // Retx tracking — stash the emitted bytes so a timer expiry can
    // resend them. If `last_emitted_len` is already nonzero we
    // overwrite with the latest packet (RFC 9002 §6.2 has us replay
    // the most recent ack-eliciting packet on PTO expiry).
    let now_ms = dev_millis(sys);
    // RFC 9002 §A.1 — a packet is "ack-eliciting" if it carries any
    // frame other than ACK / PADDING / CONNECTION_CLOSE. CRYPTO,
    // STREAM, PING, HANDSHAKE_DONE all qualify. We track this from
    // the local `had_*` flags so the post-mutation state (which has
    // already cleared `pending_handshake_done` / zeroed buf_len)
    // doesn't make us under-count bytes-in-flight.
    let mut had_extra_or_bidi = false;
    {
        let mut k = 0;
        while k < MAX_EXTRA_STREAMS {
            if had_extra_stream[k] {
                had_extra_or_bidi = true;
                break;
            }
            k += 1;
        }
        if !had_extra_or_bidi {
            let mut k = 0;
            while k < MAX_BIDI_EXTRA_STREAMS {
                if had_bidi_stream[k] {
                    had_extra_or_bidi = true;
                    break;
                }
                k += 1;
            }
        }
    }
    let ack_eliciting = crypto_packed > 0
        || had_handshake_done
        || had_main_stream
        || had_extra_or_bidi;
    let conn = &mut s.conns[idx];
    let space = match level {
        EncLevel::Initial => &mut conn.initial,
        EncLevel::Handshake => &mut conn.handshake,
        EncLevel::OneRtt => &mut conn.one_rtt,
    };
    // RFC 9002 §A.1, §6.1, §6.2 — loss detection / RTT / PTO all
    // operate on ack-eliciting packets. Pure-ACK / PADDING-only
    // packets are deliberately not tracked: peers aren't required to
    // ack them, replaying one as a PTO probe wouldn't elicit a peer
    // response (ACK isn't ack-eliciting), and inserting them into
    // the small `sent_packets` ring would evict still-unacked
    // ack-eliciting entries — leaving their bytes_in_flight stranded
    // when the corresponding ACK can no longer find them.
    if ack_eliciting {
        if n <= space.last_emitted.len() {
            core::ptr::copy_nonoverlapping(
                pkt.as_ptr(),
                space.last_emitted.as_mut_ptr(),
                n,
            );
            space.last_emitted_len = n;
            space.last_emitted_pn = pn;
            space.last_emitted_ms = now_ms;
        }
        // The ring-full gate in `drain_outbound` ensures a free slot
        // exists by the time we get here for ack-eliciting packets.
        // The bool return is defense-in-depth: if the gate is ever
        // bypassed (e.g. PTO replay with a full ring), drop the
        // tracking entry rather than overwriting a live one. ACK
        // accounting may temporarily skip this packet — the peer's
        // ACK will return as a no-op `find_sent` miss.
        let _ = space.record_sent(SentPacket {
            pn,
            bytes: n as u32,
            sent_ms: now_ms,
            ack_eliciting,
            in_flight: ack_eliciting,
            live: true,
        });
        conn.bytes_in_flight = conn.bytes_in_flight.saturating_add(n as u64);
    }
    (true, crypto_packed)
}

/// Emit a CONNECTION_CLOSE frame (RFC 9000 §19.19 + §10.2). Picks
/// the highest-installed encryption level so the peer can decrypt.
/// `error_code`: QUIC transport error code (RFC 9000 §20.1) — e.g.
///   0x00 = NO_ERROR, 0x01 = INTERNAL_ERROR, 0x0a = PROTOCOL_VIOLATION.
/// `frame_cause`: frame type that triggered the error (0 if not
/// frame-related).
/// `reason`: optional human-readable text (≤120 bytes recommended).
pub unsafe fn emit_connection_close(
    s: &mut QuicState,
    idx: usize,
    error_code: u64,
    frame_cause: u64,
    reason: &[u8],
) {
    let conn = &s.conns[idx];
    let level = if conn.one_rtt.keys_set {
        EncLevel::OneRtt
    } else if conn.handshake.keys_set {
        EncLevel::Handshake
    } else if conn.initial.keys_set {
        EncLevel::Initial
    } else {
        return;
    };
    // Build the CONNECTION_CLOSE frame.
    let mut frame_buf = [0u8; 256];
    let n = build_connection_close(
        error_code,
        frame_cause,
        reason,
        false, /* transport-level */
        &mut frame_buf,
    );
    if n == 0 {
        return;
    }
    // Wrap as a single-frame packet at the chosen level.
    let mut payload = [0u8; 256];
    payload[..n].copy_from_slice(&frame_buf[..n]);

    let pn_len = 4;
    let our_cid_len = conn.our_cid_len as usize;
    let peer_cid_len = conn.peer_cid_len as usize;
    let our_cid = conn.our_cid;
    let peer_cid = conn.peer_cid;
    let peer = conn.peer;

    let keys: QuicKeys;
    let hp_key: [u8; QUIC_HP_KEY_LEN];
    let pn: u64;
    let key_phase: u8;
    {
        let conn = &s.conns[idx];
        let space = match level {
            EncLevel::Initial => &conn.initial,
            EncLevel::Handshake => &conn.handshake,
            EncLevel::OneRtt => &conn.one_rtt,
        };
        keys = space.write_keys;
        hp_key = space.write_keys.hp;
        pn = space.next_send_pn;
        key_phase = if matches!(level, EncLevel::OneRtt) {
            conn.one_rtt.key_phase
        } else {
            0
        };
    }
    let hp = Aes128Hp::new(&hp_key);
    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    let dcid = &peer_cid[..peer_cid_len];
    let scid = &our_cid[..our_cid_len];
    let pkt_len = match level {
        EncLevel::Initial => build_initial_packet(&keys, &hp, pn, pn_len, dcid, scid, &[], &payload[..n], &mut pkt),
        EncLevel::Handshake => build_handshake_packet(&keys, &hp, pn, pn_len, dcid, scid, &payload[..n], &mut pkt),
        EncLevel::OneRtt => build_one_rtt_packet(&keys, &hp, pn, pn_len, key_phase, dcid, &payload[..n], &mut pkt),
    };
    if pkt_len == 0 {
        return;
    }
    // Packet on the wire — burn the PN (deferred from the read above
    // so a build failure doesn't leave a hole in the PN sequence).
    {
        let conn = &mut s.conns[idx];
        let space = match level {
            EncLevel::Initial => &mut conn.initial,
            EncLevel::Handshake => &mut conn.handshake,
            EncLevel::OneRtt => &mut conn.one_rtt,
        };
        space.next_send_pn = pn + 1;
    }
    let sys = &*s.syscalls;
    let listen_ep = s.listen_ep;
    send_datagram(sys, s.net_out, listen_ep, &peer, &pkt[..pkt_len], &mut s.net_scratch);
    let msg = b"[quic] CONNECTION_CLOSE sent";
    dev_log(sys, 3, msg.as_ptr(), msg.len());
}

/// Emit a RESET_STREAM frame on the 1-RTT level for the given stream.
/// RFC 9000 §19.4 — abruptly terminates a stream's send side.
pub unsafe fn emit_reset_stream(
    s: &mut QuicState,
    idx: usize,
    stream_id: u64,
    error_code: u64,
    final_size: u64,
) {
    let conn = &s.conns[idx];
    if !conn.one_rtt.keys_set {
        return;
    }
    let mut frame_buf = [0u8; 32];
    let n = build_reset_stream(stream_id, error_code, final_size, &mut frame_buf);
    if n == 0 {
        return;
    }
    let our_cid_len = conn.our_cid_len as usize;
    let peer_cid_len = conn.peer_cid_len as usize;
    let our_cid = conn.our_cid;
    let peer_cid = conn.peer_cid;
    let peer = conn.peer;
    let keys: QuicKeys;
    let hp_key: [u8; QUIC_HP_KEY_LEN];
    let pn: u64;
    let key_phase: u8;
    {
        let conn = &s.conns[idx];
        keys = conn.one_rtt.write_keys;
        hp_key = conn.one_rtt.write_keys.hp;
        pn = conn.one_rtt.next_send_pn;
        key_phase = conn.one_rtt.key_phase;
    }
    let _ = our_cid_len;
    let hp = Aes128Hp::new(&hp_key);
    let mut pkt = [0u8; QUIC_DGRAM_MAX];
    let dcid = &peer_cid[..peer_cid_len];
    let _ = our_cid;
    let pkt_len = build_one_rtt_packet(
        &keys, &hp, pn, 4, key_phase, dcid, &frame_buf[..n], &mut pkt,
    );
    if pkt_len == 0 {
        return;
    }
    {
        let conn = &mut s.conns[idx];
        conn.one_rtt.next_send_pn = pn + 1;
    }
    let sys = &*s.syscalls;
    let listen_ep = s.listen_ep;
    send_datagram(sys, s.net_out, listen_ep, &peer, &pkt[..pkt_len], &mut s.net_scratch);
}

/// Probe-Timeout (RFC 9002 §6.2) check — replay the saved packet for
/// any space whose oldest unacked send is older than the connection's
/// computed PTO. PTO is `smoothed_rtt + max(4*rttvar, granularity) +
/// max_ack_delay` (RFC 9002 §6.2.1); for a brand-new connection we
/// fall back to `kInitialRtt = 333ms`.
///
/// On expiry we also drive the NewReno congestion controller: the
/// presumed-lost packet's bytes are deducted from `bytes_in_flight`
/// and `cc_on_loss` collapses cwnd (RFC 9002 §B.6).
pub unsafe fn quic_pto_check(s: &mut QuicState, idx: usize) {
    let sys = &*s.syscalls;
    let now_ms = dev_millis(sys);
    let pto_threshold = s.conns[idx].rtt.pto() as u64;
    for level in [EncLevel::Initial, EncLevel::Handshake, EncLevel::OneRtt] {
        let resend_bytes;
        let resend_len;
        let peer;
        let mut lost_bytes: u64 = 0;
        let lost_pn: u64;
        let lost_sent_ms: u64;
        {
            let conn = &mut s.conns[idx];
            let space = match level {
                EncLevel::Initial => &mut conn.initial,
                EncLevel::Handshake => &mut conn.handshake,
                EncLevel::OneRtt => &mut conn.one_rtt,
            };
            if space.last_emitted_len == 0 || space.last_emitted_ms == 0 {
                continue;
            }
            if now_ms.wrapping_sub(space.last_emitted_ms) < pto_threshold {
                continue;
            }
            // Time up — replay the saved packet bytes.
            resend_len = space.last_emitted_len;
            let mut buf = [0u8; 1500];
            core::ptr::copy_nonoverlapping(
                space.last_emitted.as_ptr(),
                buf.as_mut_ptr(),
                resend_len,
            );
            resend_bytes = buf;
            peer = conn.peer;
            lost_pn = space.last_emitted_pn;
            lost_sent_ms = space.last_emitted_ms;
            // Mark the lost packet's tracked entry (if present) so
            // it doesn't get double-counted when a late ACK arrives.
            if let Some((bytes, _ack_eliciting, in_flight, _ms, ix)) = space.find_sent(lost_pn) {
                if in_flight {
                    lost_bytes = bytes as u64;
                }
                space.clear_sent(ix);
            }
            space.last_emitted_ms = now_ms; // exponential backoff in real impl
        }
        let listen_ep = s.listen_ep;
        send_datagram(
            sys,
            s.net_out,
            listen_ep,
            &peer,
            &resend_bytes[..resend_len],
            &mut s.net_scratch,
        );
        if lost_bytes > 0 {
            s.conns[idx].cc_on_loss(lost_bytes, lost_sent_ms);
        }
    }
}
unsafe fn pump_send_client_finished(s: &mut QuicState, idx: usize) -> bool {
    let driver = &mut s.conns[idx].driver;
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
