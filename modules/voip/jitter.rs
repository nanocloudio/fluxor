// Jitter buffer: RTP receive socket, packet buffering, playout at fixed rate.
//
// State machine: IDLE → INIT → BIND_WAIT → CONNECT_WAIT → BUFFERING → RUNNING
// SIP controls transitions via jitter_set_endpoint() / jitter_start() / jitter_stop().
// Playout writes to jitter_out_buf for step_decode() to consume.

// ============================================================================
// Constants
// ============================================================================

/// RTP header size (V2, no CSRC, no extensions)
const RTP_HEADER_SIZE: usize = 12;

/// Payload size per slot (20ms @ 8kHz G.711 = 160 bytes)
const SLOT_SIZE: usize = 160;

/// Number of jitter buffer slots (supports up to 320ms at 20ms ptime)
const MAX_SLOTS: usize = 16;

/// Max RTP packet we can receive
const JITTER_RX_BUF_SIZE: usize = RTP_HEADER_SIZE + SLOT_SIZE;

/// G.711 u-law silence byte (decodes to linear 0)
const ULAW_SILENCE: u8 = 0xFF;

/// Jitter buffer state machine phases.
///
/// IDLE → INIT → BIND_WAIT → CONNECT_WAIT → BUFFERING → RUNNING
/// SIP controls transitions via jitter_start() / jitter_stop().
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum JitterPhase {
    Idle = 0,
    Init = 1,
    BindWait = 2,
    ConnectWait = 3,
    Buffering = 4,
    Running = 5,
    Error = 6,
}

// ============================================================================
// Jitter Buffer Slot
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone)]
struct JitterSlot {
    data: [u8; SLOT_SIZE],
    seq: u16,
    len: u16,
}

impl JitterSlot {
    const fn empty() -> Self {
        Self { data: [0u8; SLOT_SIZE], seq: 0, len: 0 }
    }
}

// ============================================================================
// Jitter State Machine
// ============================================================================

unsafe fn step_jitter(s: &mut VoipState) {
    match s.jitter_phase {
        JitterPhase::Idle => {}
        JitterPhase::Init => jitter_step_init(s),
        JitterPhase::BindWait => jitter_step_bind_wait(s),
        JitterPhase::ConnectWait => jitter_step_connect_wait(s),
        JitterPhase::Buffering => jitter_step_buffering(s),
        JitterPhase::Running => jitter_step_running(s),
        _ => {} // JitterPhase::Error
    }
}

// ============================================================================
// Init — open and bind RTP receive socket
// ============================================================================

unsafe fn jitter_step_init(s: &mut VoipState) {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let mut sock_arg = [SOCK_TYPE_DGRAM];
    let handle = (dev_call)(-1, DEV_SOCKET_OPEN, sock_arg.as_mut_ptr(), 1);
    if handle < 0 {
        dev_log(sys, 1, b"[voip] jbuf socket fail".as_ptr(), 23);
        s.jitter_phase = JitterPhase::Error;
        return;
    }
    s.jitter_socket = handle;

    let mut port_arg = s.rtp_port.to_le_bytes();
    let rc = (dev_call)(handle, DEV_SOCKET_BIND, port_arg.as_mut_ptr(), 2);
    if rc < 0 && rc != E_INPROGRESS {
        dev_log(sys, 1, b"[voip] jbuf bind fail".as_ptr(), 21);
        (dev_call)(handle, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
        s.jitter_phase = JitterPhase::Error;
        return;
    }

    s.jitter_phase = JitterPhase::BindWait;
}

unsafe fn jitter_step_bind_wait(s: &mut VoipState) {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let addr = ChannelAddr::new(s.jitter_remote_ip, s.jitter_remote_port);
    let rc = (dev_call)(
        s.jitter_socket,
        DEV_SOCKET_CONNECT,
        &addr as *const _ as *mut u8,
        core::mem::size_of::<ChannelAddr>(),
    );

    if rc == E_BUSY {
        return;
    }
    if rc < 0 && rc != E_INPROGRESS {
        dev_log(sys, 1, b"[voip] jbuf conn fail".as_ptr(), 21);
        s.jitter_phase = JitterPhase::Error;
        return;
    }

    s.jitter_phase = JitterPhase::ConnectWait;
}

unsafe fn jitter_step_connect_wait(s: &mut VoipState) {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    let mut poll_arg = [POLL_CONN | POLL_ERR];
    let poll = (dev_call)(s.jitter_socket, DEV_SOCKET_POLL, poll_arg.as_mut_ptr(), 1);

    if poll > 0 && ((poll as u8) & POLL_ERR) != 0 {
        dev_log(sys, 1, b"[voip] jbuf poll err".as_ptr(), 20);
        s.jitter_phase = JitterPhase::Error;
        return;
    }
    if poll > 0 && ((poll as u8) & POLL_CONN) != 0 {
        dev_log(sys, 3, b"[voip] jbuf buffering".as_ptr(), 21);
        s.jitter_phase = JitterPhase::Buffering;
    }
}

// ============================================================================
// Buffering — receive packets until target fill reached
// ============================================================================

unsafe fn jitter_step_buffering(s: &mut VoipState) {
    jitter_receive_packets(s);

    if s.fill_count >= s.target_fill {
        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[voip] jbuf playing".as_ptr(), 19);
        s.jitter_started = 1;
        s.last_output_ms = dev_millis(&*s.syscalls);
        s.jitter_phase = JitterPhase::Running;
    }
}

// ============================================================================
// Running — receive packets + playout at fixed rate
// ============================================================================

unsafe fn jitter_step_running(s: &mut VoipState) {
    let sys = &*s.syscalls;

    // Always try to receive incoming packets
    jitter_receive_packets(s);

    // Only produce new playout data when previous is fully consumed by decode
    if s.jitter_out_len != 0 {
        return;
    }

    // Rate-limit: output one packet per ptime interval
    let now = dev_millis(sys);
    let elapsed = now.wrapping_sub(s.last_output_ms);
    if elapsed < s.ptime as u64 {
        return;
    }

    // Get the slot for the current playout sequence number
    let slot_idx = (s.play_seq as usize) % MAX_SLOTS;
    let slot = &mut s.slots[slot_idx];

    let ptime_bytes = (s.ptime as usize) * 8; // 8 samples/ms at 8kHz
    let output_len = if ptime_bytes > SLOT_SIZE { SLOT_SIZE } else { ptime_bytes };

    if slot.seq == s.play_seq && slot.len > 0 {
        // Packet present — copy to output buffer
        let copy_len = if (slot.len as usize) < output_len { slot.len as usize } else { output_len };
        __aeabi_memcpy(s.jitter_out_buf.as_mut_ptr(), slot.data.as_ptr(), copy_len);
        if copy_len < output_len {
            __aeabi_memset(s.jitter_out_buf.as_mut_ptr().add(copy_len), output_len - copy_len, ULAW_SILENCE as i32);
        }
        slot.len = 0;
    } else {
        // Packet missing — output silence
        __aeabi_memset(s.jitter_out_buf.as_mut_ptr(), output_len, ULAW_SILENCE as i32);
        s.packets_lost = s.packets_lost.wrapping_add(1);
    }

    s.jitter_out_len = output_len as u16;
    s.jitter_out_offset = 0;

    // Advance playout pointer
    s.play_seq = s.play_seq.wrapping_add(1);
    s.last_output_ms = now;

    if s.fill_count > 0 {
        s.fill_count -= 1;
    }
}

// ============================================================================
// Packet Reception
// ============================================================================

unsafe fn jitter_receive_packets(s: &mut VoipState) {
    let dev_call = (&*s.syscalls).dev_call;

    loop {
        let read = (dev_call)(
            s.jitter_socket,
            DEV_SOCKET_RECV,
            s.jitter_rx_buf.as_mut_ptr(),
            JITTER_RX_BUF_SIZE,
        );

        if read <= 0 {
            break;
        }

        let pkt_len = read as usize;
        if pkt_len < RTP_HEADER_SIZE {
            continue;
        }

        let pkt = s.jitter_rx_buf.as_ptr();
        let version = (*pkt >> 6) & 0x03;
        if version != 2 {
            continue;
        }

        let cc = *pkt & 0x0F;
        let header_len = RTP_HEADER_SIZE + (cc as usize * 4);
        if pkt_len <= header_len {
            continue;
        }

        let seq = ((*pkt.add(2) as u16) << 8) | (*pkt.add(3) as u16);
        let payload_len = pkt_len - header_len;

        s.packets_received = s.packets_received.wrapping_add(1);

        // First packet: initialize play_seq
        if s.packets_received == 1 {
            s.play_seq = seq;
        }

        // Check if packet is too old or too far ahead
        let distance = seq.wrapping_sub(s.play_seq);
        if distance >= MAX_SLOTS as u16 && distance < 0xFF00 {
            continue;
        }
        if distance >= 0xFF00 {
            continue;
        }

        // Store in slot
        let slot_idx = (seq as usize) % MAX_SLOTS;
        let slot = &mut s.slots[slot_idx];

        if slot.len == 0 || slot.seq != seq {
            let copy_len = if payload_len > SLOT_SIZE { SLOT_SIZE } else { payload_len };
            __aeabi_memcpy(slot.data.as_mut_ptr(), pkt.add(header_len), copy_len);
            slot.seq = seq;
            slot.len = copy_len as u16;
            s.fill_count = s.fill_count.wrapping_add(1);
        }
    }
}

// ============================================================================
// Control Interface (called by SIP)
// ============================================================================

unsafe fn jitter_set_endpoint(s: &mut VoipState, ip: u32, port: u16) {
    s.jitter_remote_ip = ip;
    s.jitter_remote_port = port;
}

unsafe fn jitter_start(s: &mut VoipState) {
    if s.jitter_remote_ip == 0 {
        return;
    }
    // Reset playout state
    s.play_seq = 0;
    s.jitter_started = 0;
    s.fill_count = 0;
    s.last_output_ms = 0;
    s.packets_received = 0;
    s.packets_lost = 0;
    s.jitter_out_len = 0;
    s.jitter_out_offset = 0;
    let mut i = 0;
    while i < MAX_SLOTS {
        s.slots[i].len = 0;
        i += 1;
    }
    s.jitter_phase = JitterPhase::Init;
    dev_log(&*s.syscalls, 3, b"[voip] jbuf starting".as_ptr(), 20);
}

unsafe fn jitter_stop(s: &mut VoipState) {
    if s.jitter_socket >= 0 {
        let dev_call = (&*s.syscalls).dev_call;
        (dev_call)(s.jitter_socket, DEV_SOCKET_CLOSE, core::ptr::null_mut(), 0);
        s.jitter_socket = -1;
    }
    s.jitter_out_len = 0;
    s.jitter_out_offset = 0;
    s.jitter_phase = JitterPhase::Idle;
    dev_log(&*s.syscalls, 3, b"[voip] jbuf stopped".as_ptr(), 19);
}
