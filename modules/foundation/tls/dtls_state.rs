// DTLS 1.3 (RFC 9147) state, helpers, and pump dispatcher used when
// `TlsState.transport == TRANSPORT_UDP`. Per-peer sessions live in
// `TlsState.peer_sessions`; channel handles are reused from the
// TLS-mode `cipher_in`/`cipher_out`/`clear_in`/`clear_out` ports
// (the kernel doesn't distinguish stream vs datagram channels — the
// peer wired in determines the byte format).

// ---------------------------------------------------------------------
// Session lookup / allocation
// ---------------------------------------------------------------------

fn dtls_find_session(s: &TlsState, ip: &[u8; 4], port: u16) -> i32 {
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase != DtlsPhase::Idle
            && s.peer_sessions[i].peer.matches(ip, port)
        {
            return i as i32;
        }
        i += 1;
    }
    -1
}

unsafe fn dtls_alloc_session(s: &mut TlsState, ip: &[u8; 4], port: u16) -> Option<usize> {
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase == DtlsPhase::Idle {
            let sess = &mut s.peer_sessions[i];
            sess.reset();
            sess.peer.ip = *ip;
            sess.peer.port = port;
            sess.phase = DtlsPhase::Handshaking;
            sess.endpoint.driver.is_server = true;
            sess.endpoint.driver.hs_state = HandshakeState::RecvClientHello;
            sess.endpoint.driver.suite = CipherSuite::ChaCha20Poly1305;
            sess.endpoint.driver.ecdh_private = s.eph_private[i];
            sess.endpoint.driver.ecdh_public = s.eph_public[i];
            s.eph_used[i] = true;
            return Some(i);
        }
        i += 1;
    }
    None
}

unsafe fn dtls_alloc_client_session(
    s: &mut TlsState,
    ip: &[u8; 4],
    port: u16,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase == DtlsPhase::Idle {
            let sess = &mut s.peer_sessions[i];
            sess.reset();
            sess.peer.ip = *ip;
            sess.peer.port = port;
            sess.phase = DtlsPhase::Handshaking;
            sess.endpoint.driver.is_server = false;
            sess.endpoint.driver.hs_state = HandshakeState::SendClientHello;
            sess.endpoint.driver.suite = CipherSuite::ChaCha20Poly1305;
            sess.endpoint.driver.ecdh_private = s.eph_private[i];
            sess.endpoint.driver.ecdh_public = s.eph_public[i];
            s.eph_used[i] = true;
            return Some(i);
        }
        i += 1;
    }
    None
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
            true
        }
        HandshakeState::Error => {
            s.peer_sessions[idx].phase = DtlsPhase::Errored;
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
    if !dtls_extract_peer_cert_pubkey(body, &mut endpoint.driver) {
        endpoint.driver.hs_state = HandshakeState::Error;
        return true;
    }
    endpoint.driver.hs_state = HandshakeState::RecvCertificateVerify;
    true
}

/// Pull the peer's X.509 certificate public key from a TLS 1.3
/// Certificate message body.
unsafe fn dtls_extract_peer_cert_pubkey(body: &[u8], driver: &mut HandshakeDriver) -> bool {
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
        core::ptr::copy_nonoverlapping(pk.as_ptr(), driver.peer_cert_pubkey.as_mut_ptr(), n);
        driver.peer_cert_pubkey_len = n as u8;
        true
    } else {
        false
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

    let made_progress = {
        let endpoint = &mut s.peer_sessions[idx].endpoint;
        let _ = dtls_recv_into_driver(
            suite,
            is_initial,
            &mut endpoint.read_keys,
            &mut endpoint.recv_state,
            &mut endpoint.reassembler,
            &mut endpoint.driver,
            &mut datagram[..inbound_len],
        );
        endpoint.driver.in_len > 0 || endpoint.reassembler.active
    };

    if made_progress {
        dtls_disarm_retx(&mut s.peer_sessions[idx]);
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

    // RFC 9147 §5.8 retransmission timer.
    let now_ms = dev_millis(sys);
    let mut i = 0;
    while i < MAX_PEERS {
        if s.peer_sessions[i].phase != DtlsPhase::Idle
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
