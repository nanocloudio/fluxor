// SIP User Agent: state machine, message builders, parsers, media control.
//
// Controls the jitter buffer (internal) and rtp module (external via ctrl channel).

// ============================================================================
// SIP Constants
// ============================================================================

const SIP_PORT_DEFAULT: u16 = 5060;
const RTP_PORT_DEFAULT: u16 = 5004;
const T1_MS: u64 = 500;
const MAX_RETRANSMIT: u8 = 7;

/// SIP user agent phases (RFC 3261 simplified).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SipPhase {
    Init = 0,
    BindWait = 1,
    ConnectWait = 2,
    Ready = 3,
    Inviting = 4,
    WaitAck = 5,
    Active = 6,
    Error = 7,
    ByeSent = 8,
}

// ============================================================================
// SIP State Machine
// ============================================================================

unsafe fn step_sip(s: &mut VoipState) {
    match s.sip_state {
        SipPhase::Init => sip_step_init(s),
        SipPhase::BindWait => sip_step_bind_wait(s),
        SipPhase::ConnectWait => sip_step_connect_wait(s),
        SipPhase::Ready => sip_step_ready(s),
        SipPhase::Inviting => sip_step_inviting(s),
        SipPhase::WaitAck => sip_step_wait_ack(s),
        SipPhase::Active => sip_step_active(s),
        SipPhase::ByeSent => sip_step_bye_sent(s),
        _ => {}
    }
}

// ============================================================================
// Init — send CMD_BIND via SIP net channel
// ============================================================================

unsafe fn sip_step_init(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if s.sip_net_out < 0 {
        dev_log(sys, 1, b"[voip] sip no net".as_ptr(), 17);
        s.sip_state = SipPhase::Error;
        return;
    }

    // CMD_BIND payload: [port: u16 LE]
    let port_le = s.local_sip_port.to_le_bytes();
    let wrote = net_write_frame(
        sys, s.sip_net_out, NET_CMD_BIND,
        port_le.as_ptr(), 2,
        s.sip_net_buf.as_mut_ptr(), NET_BUF_SIZE,
    );
    if wrote == 0 {
        return; // Channel full, retry next tick
    }

    s.sip_state = SipPhase::BindWait;
}

unsafe fn sip_step_bind_wait(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if s.sip_net_in < 0 { return; }

    let poll = (sys.channel_poll)(s.sip_net_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.sip_net_buf.as_mut_ptr();
    let (msg_type, _payload_len) = net_read_frame(sys, s.sip_net_in, buf, NET_BUF_SIZE);

    if msg_type == NET_MSG_ERROR {
        dev_log(sys, 1, b"[voip] sip bind fail".as_ptr(), 20);
        s.sip_state = SipPhase::Error;
        return;
    }
    if msg_type != NET_MSG_BOUND {
        return;
    }

    // Bound — now send CMD_CONNECT: [sock_type: u8][ip: u32 LE][port: u16 LE]
    let ip_le = s.peer_ip.to_le_bytes();
    let port_le = s.peer_sip_port.to_le_bytes();
    let payload = s.sip_net_buf.as_mut_ptr();
    *payload = SOCK_TYPE_DGRAM;
    *payload.add(1) = ip_le[0];
    *payload.add(2) = ip_le[1];
    *payload.add(3) = ip_le[2];
    *payload.add(4) = ip_le[3];
    *payload.add(5) = port_le[0];
    *payload.add(6) = port_le[1];

    let scratch = s.sip_tx_buf.as_mut_ptr(); // Reuse sip_tx_buf as scratch
    let wrote = net_write_frame(
        sys, s.sip_net_out, NET_CMD_CONNECT,
        payload, 7,
        scratch, SIP_TX_BUF_SIZE,
    );
    if wrote == 0 {
        return;
    }

    s.sip_state = SipPhase::ConnectWait;
}

unsafe fn sip_step_connect_wait(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if s.sip_net_in < 0 { return; }

    let poll = (sys.channel_poll)(s.sip_net_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.sip_net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, s.sip_net_in, buf, NET_BUF_SIZE);

    if msg_type == NET_MSG_ERROR {
        dev_log(sys, 1, b"[voip] sip conn err".as_ptr(), 19);
        s.sip_state = SipPhase::Error;
        return;
    }
    if msg_type == NET_MSG_CONNECTED && payload_len >= 1 {
        s.sip_conn_id = *buf.add(NET_FRAME_HDR);
        dev_log(sys, 3, b"[voip] sip listening".as_ptr(), 20);
        s.sip_state = SipPhase::Ready;
    }
}

// ============================================================================
// Ready — waiting for trigger or incoming INVITE
// ============================================================================

unsafe fn sip_step_ready(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if s.ctrl_chan >= 0 {
        let poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
        if poll > 0 && ((poll as u32) & POLL_IN) != 0 {
            let mut buf = [0u8; 1];
            let read = (sys.channel_read)(s.ctrl_chan, buf.as_mut_ptr(), 1);
            if read > 0 {
                sip_initiate_call(s);
                return;
            }
        }
    }

    sip_try_receive(s);
    if s.sip_rx_have > 0 {
        sip_handle_incoming_ready(s);
    }
}

// ============================================================================
// Inviting — sent INVITE, waiting for 200 OK
// ============================================================================

unsafe fn sip_step_inviting(s: &mut VoipState) {
    let sys = &*s.syscalls;

    let now = dev_millis(sys);
    let elapsed = now.wrapping_sub(s.sip_last_retransmit_ms);
    let timeout = T1_MS << (s.sip_retransmit_count as u64);

    if elapsed >= timeout {
        if s.sip_retransmit_count >= MAX_RETRANSMIT {
            dev_log(sys, 2, b"[voip] invite timeout".as_ptr(), 21);
            s.sip_state = SipPhase::Ready;
            return;
        }
        sip_flush_tx(s);
        s.sip_retransmit_count += 1;
        s.sip_last_retransmit_ms = now;
    }

    sip_try_receive(s);
    if s.sip_rx_have > 0 {
        sip_handle_incoming_inviting(s);
    }
}

// ============================================================================
// WaitAck — sent 200 OK (incoming call), waiting for ACK
// ============================================================================

unsafe fn sip_step_wait_ack(s: &mut VoipState) {
    let sys = &*s.syscalls;

    let now = dev_millis(sys);
    let elapsed = now.wrapping_sub(s.sip_last_retransmit_ms);
    let timeout = T1_MS << (s.sip_retransmit_count as u64);

    if elapsed >= timeout {
        if s.sip_retransmit_count >= MAX_RETRANSMIT {
            dev_log(sys, 2, b"[voip] ack timeout".as_ptr(), 18);
            s.sip_state = SipPhase::Ready;
            return;
        }
        sip_flush_tx(s);
        s.sip_retransmit_count += 1;
        s.sip_last_retransmit_ms = now;
    }

    sip_try_receive(s);
    if s.sip_rx_have > 0 {
        sip_handle_incoming_wait_ack(s);
    }
}

// ============================================================================
// Active — call in progress
// ============================================================================

unsafe fn sip_step_active(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if s.ctrl_chan >= 0 {
        let poll = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
        if poll > 0 && ((poll as u32) & POLL_IN) != 0 {
            let mut buf = [0u8; 1];
            let read = (sys.channel_read)(s.ctrl_chan, buf.as_mut_ptr(), 1);
            if read > 0 {
                sip_send_bye(s);
                sip_stop_media(s);
                s.sip_state = SipPhase::ByeSent;
                s.sip_retransmit_count = 0;
                s.sip_last_retransmit_ms = dev_millis(sys);
                return;
            }
        }
    }

    sip_try_receive(s);
    if s.sip_rx_have > 0 {
        sip_handle_incoming_active(s);
    }
}

// ============================================================================
// BYE sent — waiting for 200 OK
// ============================================================================

unsafe fn sip_step_bye_sent(s: &mut VoipState) {
    let sys = &*s.syscalls;

    let now = dev_millis(sys);
    let elapsed = now.wrapping_sub(s.sip_last_retransmit_ms);
    let timeout = T1_MS << (s.sip_retransmit_count as u64);

    if elapsed >= timeout {
        if s.sip_retransmit_count >= MAX_RETRANSMIT {
            s.sip_state = SipPhase::Ready;
            return;
        }
        sip_flush_tx(s);
        s.sip_retransmit_count += 1;
        s.sip_last_retransmit_ms = now;
    }

    sip_try_receive(s);
    if s.sip_rx_have > 0 {
        let code = sip_parse_status_code(s);
        if code >= 200 {
            dev_log(sys, 3, b"[voip] bye confirmed".as_ptr(), 20);
            s.sip_state = SipPhase::Ready;
        }
    }
}

// ============================================================================
// Call Initiation
// ============================================================================

unsafe fn sip_initiate_call(s: &mut VoipState) {
    let sys = &*s.syscalls;

    s.call_id_counter = s.call_id_counter.wrapping_add(1);
    s.call_id_len = fmt_hex16(s.call_id.as_mut_ptr(), s.call_id_counter ^ s.from_tag);
    s.cseq = 1;
    s.to_tag = 0;
    s.branch_counter = s.branch_counter.wrapping_add(1);

    sip_build_invite(s);
    sip_flush_tx(s);

    s.sip_retransmit_count = 0;
    s.sip_last_retransmit_ms = dev_millis(sys);
    s.sip_state = SipPhase::Inviting;

    dev_log(sys, 3, b"[voip] inviting".as_ptr(), 15);
}

// ============================================================================
// Incoming Message Handlers
// ============================================================================

unsafe fn sip_handle_incoming_ready(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if starts_with(s.sip_rx_buf.as_ptr(), s.sip_rx_have as usize, b"INVITE ") {
        if !sip_parse_sdp_endpoint(s) {
            dev_log(sys, 2, b"[voip] bad sdp".as_ptr(), 14);
            s.sip_rx_have = 0;
            return;
        }

        sip_extract_call_id(s);
        sip_extract_from_tag_as_to(s);

        if s.auto_answer != 0 {
            s.to_tag = s.from_tag.wrapping_add(1);
            s.branch_counter = s.branch_counter.wrapping_add(1);
            sip_build_200_ok(s);
            sip_flush_tx(s);

            sip_start_media(s);

            s.sip_retransmit_count = 0;
            s.sip_last_retransmit_ms = dev_millis(sys);
            s.sip_state = SipPhase::WaitAck;

            dev_log(sys, 3, b"[voip] answering".as_ptr(), 16);
        }
    }

    s.sip_rx_have = 0;
}

unsafe fn sip_handle_incoming_inviting(s: &mut VoipState) {
    let sys = &*s.syscalls;

    let code = sip_parse_status_code(s);

    if code >= 100 && code < 200 {
        s.sip_retransmit_count = 0;
        s.sip_last_retransmit_ms = dev_millis(sys);
    } else if code >= 200 && code < 300 {
        if sip_parse_sdp_endpoint(s) {
            sip_extract_to_tag(s);
            sip_build_ack(s);
            sip_flush_tx(s);

            sip_start_media(s);
            s.sip_state = SipPhase::Active;

            dev_log(sys, 3, b"[voip] call active".as_ptr(), 18);
        } else {
            dev_log(sys, 2, b"[voip] bad 200 sdp".as_ptr(), 18);
            sip_build_ack(s);
            sip_flush_tx(s);
            s.sip_state = SipPhase::Ready;
        }
    } else if code >= 300 {
        dev_log(sys, 2, b"[voip] rejected".as_ptr(), 15);
        sip_build_ack(s);
        sip_flush_tx(s);
        s.sip_state = SipPhase::Ready;
    }

    s.sip_rx_have = 0;
}

unsafe fn sip_handle_incoming_wait_ack(s: &mut VoipState) {
    if starts_with(s.sip_rx_buf.as_ptr(), s.sip_rx_have as usize, b"ACK ") {
        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[voip] call active".as_ptr(), 18);
        s.sip_state = SipPhase::Active;
    } else if starts_with(s.sip_rx_buf.as_ptr(), s.sip_rx_have as usize, b"INVITE ") {
        sip_flush_tx(s);
    }

    s.sip_rx_have = 0;
}

unsafe fn sip_handle_incoming_active(s: &mut VoipState) {
    let sys = &*s.syscalls;

    if starts_with(s.sip_rx_buf.as_ptr(), s.sip_rx_have as usize, b"BYE ") {
        sip_stop_media(s);
        sip_build_bye_200(s);
        sip_flush_tx(s);
        s.sip_state = SipPhase::Ready;
        dev_log(sys, 3, b"[voip] call ended".as_ptr(), 17);
    }

    s.sip_rx_have = 0;
}

// ============================================================================
// SIP Message Builders
// ============================================================================

unsafe fn sip_build_invite(s: &mut VoipState) {
    let mut w = BufWriter::new(s.sip_tx_buf.as_mut_ptr(), SIP_TX_BUF_SIZE);

    w.write(b"INVITE sip:");
    w.write_ip(s.peer_ip);
    w.write(b":");
    w.write_u16(s.peer_sip_port);
    w.write(b" SIP/2.0\r\n");

    w.write(b"Via: SIP/2.0/UDP ");
    w.write_ip(s.local_ip);
    w.write(b":");
    w.write_u16(s.local_sip_port);
    w.write(b";branch=z9hG4bK");
    w.write_hex16(s.branch_counter);
    w.write(b"\r\n");

    w.write(b"Max-Forwards: 70\r\n");

    w.write(b"From: <sip:");
    w.write_ip(s.local_ip);
    w.write(b">;tag=");
    w.write_hex16(s.from_tag);
    w.write(b"\r\n");

    w.write(b"To: <sip:");
    w.write_ip(s.peer_ip);
    w.write(b">\r\n");

    w.write(b"Call-ID: ");
    w.write_n(s.call_id.as_ptr(), s.call_id_len as usize);
    w.write(b"@");
    w.write_ip(s.local_ip);
    w.write(b"\r\n");

    w.write(b"CSeq: ");
    w.write_u32(s.cseq);
    w.write(b" INVITE\r\n");

    w.write(b"Contact: <sip:");
    w.write_ip(s.local_ip);
    w.write(b":");
    w.write_u16(s.local_sip_port);
    w.write(b">\r\n");

    let slen = sdp_len(s.local_ip, s.rtp_port);
    w.write(b"Content-Type: application/sdp\r\n");
    w.write(b"Content-Length: ");
    w.write_u16(slen as u16);
    w.write(b"\r\n\r\n");
    write_sdp(&mut w, s.local_ip, s.rtp_port);

    s.sip_tx_len = w.pos as u16;
}

unsafe fn sip_build_200_ok(s: &mut VoipState) {
    let mut w = BufWriter::new(s.sip_tx_buf.as_mut_ptr(), SIP_TX_BUF_SIZE);

    w.write(b"SIP/2.0 200 OK\r\n");

    w.write(b"Via: SIP/2.0/UDP ");
    w.write_ip(s.peer_ip);
    w.write(b":");
    w.write_u16(s.peer_sip_port);
    w.write(b"\r\n");

    w.write(b"From: <sip:");
    w.write_ip(s.peer_ip);
    w.write(b">;tag=");
    w.write_hex16(s.to_tag);
    w.write(b"\r\n");

    w.write(b"To: <sip:");
    w.write_ip(s.local_ip);
    w.write(b">;tag=");
    w.write_hex16(s.from_tag);
    w.write(b"\r\n");

    w.write(b"Call-ID: ");
    w.write_n(s.call_id.as_ptr(), s.call_id_len as usize);
    w.write(b"\r\n");

    w.write(b"CSeq: ");
    w.write_u32(s.cseq);
    w.write(b" INVITE\r\n");

    w.write(b"Contact: <sip:");
    w.write_ip(s.local_ip);
    w.write(b":");
    w.write_u16(s.local_sip_port);
    w.write(b">\r\n");

    let slen = sdp_len(s.local_ip, s.rtp_port);
    w.write(b"Content-Type: application/sdp\r\n");
    w.write(b"Content-Length: ");
    w.write_u16(slen as u16);
    w.write(b"\r\n\r\n");
    write_sdp(&mut w, s.local_ip, s.rtp_port);

    s.sip_tx_len = w.pos as u16;
}

unsafe fn sip_build_ack(s: &mut VoipState) {
    let mut w = BufWriter::new(s.sip_tx_buf.as_mut_ptr(), SIP_TX_BUF_SIZE);

    w.write(b"ACK sip:");
    w.write_ip(s.peer_ip);
    w.write(b":");
    w.write_u16(s.peer_sip_port);
    w.write(b" SIP/2.0\r\n");

    w.write(b"Via: SIP/2.0/UDP ");
    w.write_ip(s.local_ip);
    w.write(b":");
    w.write_u16(s.local_sip_port);
    w.write(b";branch=z9hG4bK");
    w.write_hex16(s.branch_counter);
    w.write(b"\r\n");

    w.write(b"Max-Forwards: 70\r\n");

    w.write(b"From: <sip:");
    w.write_ip(s.local_ip);
    w.write(b">;tag=");
    w.write_hex16(s.from_tag);
    w.write(b"\r\n");

    w.write(b"To: <sip:");
    w.write_ip(s.peer_ip);
    if s.to_tag != 0 {
        w.write(b">;tag=");
        w.write_hex16(s.to_tag);
        w.write(b"\r\n");
    } else {
        w.write(b">\r\n");
    }

    w.write(b"Call-ID: ");
    w.write_n(s.call_id.as_ptr(), s.call_id_len as usize);
    w.write(b"@");
    w.write_ip(s.local_ip);
    w.write(b"\r\n");

    w.write(b"CSeq: ");
    w.write_u32(s.cseq);
    w.write(b" ACK\r\n");

    w.write(b"Content-Length: 0\r\n\r\n");

    s.sip_tx_len = w.pos as u16;
}

unsafe fn sip_send_bye(s: &mut VoipState) {
    s.cseq += 1;
    s.branch_counter = s.branch_counter.wrapping_add(1);
    let mut w = BufWriter::new(s.sip_tx_buf.as_mut_ptr(), SIP_TX_BUF_SIZE);

    w.write(b"BYE sip:");
    w.write_ip(s.peer_ip);
    w.write(b":");
    w.write_u16(s.peer_sip_port);
    w.write(b" SIP/2.0\r\n");

    w.write(b"Via: SIP/2.0/UDP ");
    w.write_ip(s.local_ip);
    w.write(b":");
    w.write_u16(s.local_sip_port);
    w.write(b";branch=z9hG4bK");
    w.write_hex16(s.branch_counter);
    w.write(b"\r\n");

    w.write(b"Max-Forwards: 70\r\n");

    w.write(b"From: <sip:");
    w.write_ip(s.local_ip);
    w.write(b">;tag=");
    w.write_hex16(s.from_tag);
    w.write(b"\r\n");

    w.write(b"To: <sip:");
    w.write_ip(s.peer_ip);
    if s.to_tag != 0 {
        w.write(b">;tag=");
        w.write_hex16(s.to_tag);
        w.write(b"\r\n");
    } else {
        w.write(b">\r\n");
    }

    w.write(b"Call-ID: ");
    w.write_n(s.call_id.as_ptr(), s.call_id_len as usize);
    w.write(b"@");
    w.write_ip(s.local_ip);
    w.write(b"\r\n");

    w.write(b"CSeq: ");
    w.write_u32(s.cseq);
    w.write(b" BYE\r\n");

    w.write(b"Content-Length: 0\r\n\r\n");

    s.sip_tx_len = w.pos as u16;
}

unsafe fn sip_build_bye_200(s: &mut VoipState) {
    let mut w = BufWriter::new(s.sip_tx_buf.as_mut_ptr(), SIP_TX_BUF_SIZE);

    w.write(b"SIP/2.0 200 OK\r\n");

    w.write(b"Via: SIP/2.0/UDP ");
    w.write_ip(s.peer_ip);
    w.write(b":");
    w.write_u16(s.peer_sip_port);
    w.write(b"\r\n");

    w.write(b"From: <sip:");
    w.write_ip(s.peer_ip);
    w.write(b">\r\n");

    w.write(b"To: <sip:");
    w.write_ip(s.local_ip);
    w.write(b">;tag=");
    w.write_hex16(s.from_tag);
    w.write(b"\r\n");

    w.write(b"Call-ID: ");
    w.write_n(s.call_id.as_ptr(), s.call_id_len as usize);
    w.write(b"\r\n");

    w.write(b"CSeq: ");
    w.write_u32(s.cseq);
    w.write(b" BYE\r\n");

    w.write(b"Content-Length: 0\r\n\r\n");

    s.sip_tx_len = w.pos as u16;
}

// ============================================================================
// SDP Writer
// ============================================================================

unsafe fn write_sdp(w: &mut BufWriter, ip: u32, port: u16) {
    w.write(b"v=0\r\no=- 0 0 IN IP4 ");
    w.write_ip(ip);
    w.write(b"\r\ns=-\r\nc=IN IP4 ");
    w.write_ip(ip);
    w.write(b"\r\nt=0 0\r\nm=audio ");
    w.write_u16(port);
    w.write(b" RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
}

fn sdp_len(ip: u32, port: u16) -> usize {
    let fixed = 20 + 17 + 17 + 35; // 89
    fixed + ip_str_len(ip) * 2 + u16_str_len(port)
}

fn ip_str_len(ip: u32) -> usize {
    let b = ip.to_be_bytes();
    u8_str_len(b[0]) + 1 + u8_str_len(b[1]) + 1 + u8_str_len(b[2]) + 1 + u8_str_len(b[3])
}

fn u8_str_len(v: u8) -> usize {
    if v >= 100 { 3 } else if v >= 10 { 2 } else { 1 }
}

fn u16_str_len(v: u16) -> usize {
    if v >= 10000 { 5 } else if v >= 1000 { 4 } else if v >= 100 { 3 } else if v >= 10 { 2 } else { 1 }
}

// ============================================================================
// SIP Parsing Helpers
// ============================================================================

unsafe fn sip_parse_status_code(s: &VoipState) -> u16 {
    let buf = s.sip_rx_buf.as_ptr();
    let len = s.sip_rx_have as usize;
    if len < 12 {
        return 0;
    }
    if !starts_with(buf, len, b"SIP/2.0 ") {
        return 0;
    }
    let d0 = *buf.add(8);
    let d1 = *buf.add(9);
    let d2 = *buf.add(10);
    if d0 < b'0' || d0 > b'9' || d1 < b'0' || d1 > b'9' || d2 < b'0' || d2 > b'9' {
        return 0;
    }
    ((d0 - b'0') as u16) * 100 + ((d1 - b'0') as u16) * 10 + ((d2 - b'0') as u16)
}

unsafe fn sip_parse_sdp_endpoint(s: &mut VoipState) -> bool {
    let buf = s.sip_rx_buf.as_ptr();
    let len = s.sip_rx_have as usize;

    let mut found_port = false;
    let mut found_ip = false;

    if let Some(pos) = find_bytes(buf, len, b"m=audio ") {
        let start = pos + 8;
        let port = parse_decimal_u16(buf.add(start), len - start);
        if port > 0 {
            s.peer_rtp_port = port;
            found_port = true;
        }
    }

    if let Some(pos) = find_bytes(buf, len, b"c=IN IP4 ") {
        let start = pos + 9;
        let ip = parse_ip4(buf.add(start), len - start);
        if ip != 0 {
            s.peer_rtp_ip = ip;
            found_ip = true;
        }
    }

    if !found_ip {
        s.peer_rtp_ip = s.peer_ip;
        found_ip = true;
    }

    found_port && found_ip
}

unsafe fn sip_extract_call_id(s: &mut VoipState) {
    let buf = s.sip_rx_buf.as_ptr();
    let len = s.sip_rx_have as usize;

    if let Some(pos) = find_header(buf, len, b"Call-ID: ") {
        let start = pos;
        let mut end = start;
        while end < len && *buf.add(end) != b'\r' && *buf.add(end) != b'\n' {
            end += 1;
        }
        let id_len = end - start;
        let copy = if id_len > CALL_ID_SIZE { CALL_ID_SIZE } else { id_len };
        __aeabi_memcpy(s.call_id.as_mut_ptr(), buf.add(start), copy);
        s.call_id_len = copy as u8;
    }
}

unsafe fn sip_extract_from_tag_as_to(s: &mut VoipState) {
    let buf = s.sip_rx_buf.as_ptr();
    let len = s.sip_rx_have as usize;

    if let Some(pos) = find_bytes(buf, len, b"From:") {
        let line_start = pos;
        let mut end = line_start;
        while end < len && *buf.add(end) != b'\r' {
            end += 1;
        }
        if let Some(tag_pos) = find_bytes(buf.add(line_start), end - line_start, b";tag=") {
            let tag_start = line_start + tag_pos + 5;
            s.to_tag = parse_hex16(buf.add(tag_start), len - tag_start);
        }
    }
}

unsafe fn sip_extract_to_tag(s: &mut VoipState) {
    let buf = s.sip_rx_buf.as_ptr();
    let len = s.sip_rx_have as usize;

    if let Some(pos) = find_bytes(buf, len, b"\nTo:") {
        let line_start = pos + 1;
        let mut end = line_start;
        while end < len && *buf.add(end) != b'\r' {
            end += 1;
        }
        if let Some(tag_pos) = find_bytes(buf.add(line_start), end - line_start, b";tag=") {
            let tag_start = line_start + tag_pos + 5;
            s.to_tag = parse_hex16(buf.add(tag_start), len - tag_start);
        }
    }
}

// ============================================================================
// Network I/O
// ============================================================================

unsafe fn sip_flush_tx(s: &mut VoipState) {
    if s.sip_tx_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    if s.sip_net_out < 0 { return; }

    // Build CMD_SEND frame: [CMD_SEND][len_lo][len_hi][conn_id][sip_data...]
    let data_len = s.sip_tx_len as usize;
    let scratch = s.sip_net_buf.as_mut_ptr();
    let frame_payload_len = 1 + data_len; // conn_id + SIP data
    if frame_payload_len + NET_FRAME_HDR <= NET_BUF_SIZE {
        *scratch = NET_CMD_SEND;
        *scratch.add(1) = (frame_payload_len & 0xFF) as u8;
        *scratch.add(2) = ((frame_payload_len >> 8) & 0xFF) as u8;
        *scratch.add(NET_FRAME_HDR) = s.sip_conn_id;
        core::ptr::copy_nonoverlapping(
            s.sip_tx_buf.as_ptr(), scratch.add(NET_FRAME_HDR + 1), data_len,
        );
        let frame_total = NET_FRAME_HDR + frame_payload_len;
        let sent = (sys.channel_write)(s.sip_net_out, scratch, frame_total);
        if sent < 0 && sent != E_AGAIN {
            dev_log(sys, 2, b"[voip] send err".as_ptr(), 15);
        }
    }
}

unsafe fn sip_try_receive(s: &mut VoipState) {
    let sys = &*s.syscalls;
    s.sip_rx_have = 0;

    if s.sip_net_in < 0 { return; }

    let poll = (sys.channel_poll)(s.sip_net_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return;
    }

    let buf = s.sip_net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, s.sip_net_in, buf, NET_BUF_SIZE);

    if msg_type == NET_MSG_DATA && payload_len > 1 {
        // MSG_DATA payload: [conn_id: u8][data...] — copy data to sip_rx_buf
        let data_len = payload_len - 1;
        let copy_len = if data_len > SIP_RX_BUF_SIZE { SIP_RX_BUF_SIZE } else { data_len };
        __aeabi_memcpy(
            s.sip_rx_buf.as_mut_ptr(),
            buf.add(NET_FRAME_HDR + 1),
            copy_len,
        );
        s.sip_rx_have = copy_len as u16;
    }
}

// ============================================================================
// Media Control (internal jitter + external rtp)
// ============================================================================

unsafe fn sip_start_media(s: &mut VoipState) {
    let sys = &*s.syscalls;

    // Internal: start jitter buffer
    jitter_set_endpoint(s, s.peer_rtp_ip, s.peer_rtp_port);
    jitter_start(s);

    // External: send ctrl to rtp TX module
    if s.out_ctrl_rtp >= 0 {
        send_ctrl(sys, s.out_ctrl_rtp, CTRL_SET_ENDPOINT, s.peer_rtp_ip, s.peer_rtp_port, &mut s.ctrl_out);
        send_ctrl(sys, s.out_ctrl_rtp, CTRL_START, 0, 0, &mut s.ctrl_out);
    }

    dev_log(sys, 3, b"[voip] media started".as_ptr(), 20);
}

unsafe fn sip_stop_media(s: &mut VoipState) {
    let sys = &*s.syscalls;

    // Internal: stop jitter buffer
    jitter_stop(s);

    // External: stop rtp TX module
    if s.out_ctrl_rtp >= 0 {
        send_ctrl(sys, s.out_ctrl_rtp, CTRL_STOP, 0, 0, &mut s.ctrl_out);
    }

    dev_log(sys, 3, b"[voip] media stopped".as_ptr(), 20);
}

unsafe fn send_ctrl(sys: &SyscallTable, chan: i32, cmd: u8, addr: u32, port: u16, buf: &mut [u8; CTRL_MSG_SIZE]) {
    buf[0] = cmd;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&port.to_le_bytes());
    buf[4..8].copy_from_slice(&addr.to_le_bytes());
    (sys.channel_write)(chan, buf.as_ptr(), CTRL_MSG_SIZE);
}

// ============================================================================
// String / Number Formatting Helpers
// ============================================================================

struct BufWriter {
    ptr: *mut u8,
    cap: usize,
    pos: usize,
}

impl BufWriter {
    fn new(ptr: *mut u8, cap: usize) -> Self {
        Self { ptr, cap, pos: 0 }
    }

    unsafe fn write(&mut self, data: &[u8]) {
        let avail = self.cap - self.pos;
        let n = if data.len() < avail { data.len() } else { avail };
        if n > 0 {
            __aeabi_memcpy(self.ptr.add(self.pos), data.as_ptr(), n);
            self.pos += n;
        }
    }

    unsafe fn write_n(&mut self, data: *const u8, len: usize) {
        let avail = self.cap - self.pos;
        let n = if len < avail { len } else { avail };
        if n > 0 {
            __aeabi_memcpy(self.ptr.add(self.pos), data, n);
            self.pos += n;
        }
    }

    unsafe fn write_ip(&mut self, ip: u32) {
        let bytes = ip.to_be_bytes();
        self.write_u8_decimal(bytes[0]);
        self.write(b".");
        self.write_u8_decimal(bytes[1]);
        self.write(b".");
        self.write_u8_decimal(bytes[2]);
        self.write(b".");
        self.write_u8_decimal(bytes[3]);
    }

    unsafe fn write_u8_decimal(&mut self, val: u8) {
        if val >= 100 {
            let d = val / 100;
            let r = val % 100;
            self.write_byte(b'0' + d);
            self.write_byte(b'0' + r / 10);
            self.write_byte(b'0' + r % 10);
        } else if val >= 10 {
            self.write_byte(b'0' + val / 10);
            self.write_byte(b'0' + val % 10);
        } else {
            self.write_byte(b'0' + val);
        }
    }

    unsafe fn write_u16(&mut self, val: u16) {
        let mut buf = [0u8; 10];
        let len = fmt_u32_raw(buf.as_mut_ptr(), val as u32);
        self.write_n(buf.as_ptr(), len);
    }

    unsafe fn write_u32(&mut self, val: u32) {
        let mut buf = [0u8; 10];
        let len = fmt_u32_raw(buf.as_mut_ptr(), val);
        self.write_n(buf.as_ptr(), len);
    }

    unsafe fn write_hex16(&mut self, val: u16) {
        let mut buf = [0u8; 4];
        let len = fmt_hex16_buf(&mut buf, val);
        self.write_n(buf.as_ptr(), len);
    }

    unsafe fn write_byte(&mut self, b: u8) {
        if self.pos < self.cap {
            *self.ptr.add(self.pos) = b;
            self.pos += 1;
        }
    }
}


const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn fmt_hex16_buf(buf: &mut [u8; 4], val: u16) -> usize {
    buf[0] = HEX_CHARS[((val >> 12) & 0xF) as usize];
    buf[1] = HEX_CHARS[((val >> 8) & 0xF) as usize];
    buf[2] = HEX_CHARS[((val >> 4) & 0xF) as usize];
    buf[3] = HEX_CHARS[(val & 0xF) as usize];
    4
}

unsafe fn fmt_hex16(buf: *mut u8, val: u16) -> u8 {
    *buf = HEX_CHARS[((val >> 12) & 0xF) as usize];
    *buf.add(1) = HEX_CHARS[((val >> 8) & 0xF) as usize];
    *buf.add(2) = HEX_CHARS[((val >> 4) & 0xF) as usize];
    *buf.add(3) = HEX_CHARS[(val & 0xF) as usize];
    4
}

// ============================================================================
// String Search / Parse Helpers
// ============================================================================

unsafe fn starts_with(buf: *const u8, len: usize, prefix: &[u8]) -> bool {
    if len < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if *buf.add(i) != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn find_bytes(buf: *const u8, len: usize, needle: &[u8]) -> Option<usize> {
    if needle.len() > len {
        return None;
    }
    let max = len - needle.len();
    let mut i = 0;
    while i <= max {
        let mut found = true;
        let mut j = 0;
        while j < needle.len() {
            if *buf.add(i + j) != needle[j] {
                found = false;
                break;
            }
            j += 1;
        }
        if found {
            return Some(i);
        }
        i += 1;
    }
    None
}

unsafe fn find_header(buf: *const u8, len: usize, header: &[u8]) -> Option<usize> {
    find_bytes(buf, len, header).map(|pos| pos + header.len())
}

unsafe fn parse_decimal_u16(buf: *const u8, max_len: usize) -> u16 {
    let mut val: u16 = 0;
    let mut i = 0;
    while i < max_len {
        let c = *buf.add(i);
        if c < b'0' || c > b'9' {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u16);
        i += 1;
    }
    val
}

unsafe fn parse_decimal_u32(buf: *const u8, max_len: usize) -> u32 {
    let mut val: u32 = 0;
    let mut i = 0;
    while i < max_len {
        let c = *buf.add(i);
        if c < b'0' || c > b'9' {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u32);
        i += 1;
    }
    val
}

unsafe fn parse_ip4(buf: *const u8, max_len: usize) -> u32 {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut val: u16 = 0;
    let mut i = 0;

    while i < max_len && octet_idx < 4 {
        let c = *buf.add(i);
        if c >= b'0' && c <= b'9' {
            val = val * 10 + (c - b'0') as u16;
        } else if c == b'.' {
            if val > 255 {
                return 0;
            }
            octets[octet_idx] = val as u8;
            octet_idx += 1;
            val = 0;
        } else {
            break;
        }
        i += 1;
    }

    if octet_idx < 4 && val <= 255 {
        octets[octet_idx] = val as u8;
        octet_idx += 1;
    }

    if octet_idx != 4 {
        return 0;
    }

    u32::from_be_bytes(octets)
}

unsafe fn parse_hex16(buf: *const u8, max_len: usize) -> u16 {
    let mut val: u16 = 0;
    let mut i = 0;
    while i < max_len && i < 4 {
        let c = *buf.add(i);
        let digit = if c >= b'0' && c <= b'9' {
            (c - b'0') as u16
        } else if c >= b'a' && c <= b'f' {
            (c - b'a' + 10) as u16
        } else if c >= b'A' && c <= b'F' {
            (c - b'A' + 10) as u16
        } else {
            break;
        };
        val = (val << 4) | digit;
        i += 1;
    }
    val
}
