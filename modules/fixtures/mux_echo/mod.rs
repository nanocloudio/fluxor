//! `mux_echo` — the transport self-test's application.
//!
//! Fluxor has to be able to prove its own QUIC transport carries a real,
//! multiplexed exchange using only Fluxor. The dependency direction forbids the
//! obvious alternative: a consumer depends on Fluxor, never the reverse, so
//! `quic` cannot be tested through a consumer's `http`.
//!
//! The point of this module is that it is SMALL: proving a transport needs an
//! application, not a protocol. An HTTP responder would work, but it would make
//! the transport's self-test an HTTP server and put a second implementation of
//! somebody else's protocol in this repo to maintain.
//!
//! What it does is echo. On the `mux` contract — the surface `quic` actually
//! exposes — it takes each accepted stream's bytes and sends them straight back
//! on the same `(session, stream)`, then closes. That exercises exactly what a
//! transport must get right and nothing else:
//!
//!   * a stream is ACCEPTED and surfaces to the application with its ids intact;
//!   * inbound bytes arrive on the stream they were sent on;
//!   * the application can send on that stream and the bytes reach the peer;
//!   * closing frees the slot, so the next stream is not starved.
//!
//! Anything above that — methods, paths, header compression — belongs to a
//! protocol, and protocols belong to the consumer.
//!
//! # Two roles, one fixture
//!
//! `role = 0` (default) ECHOES: it answers every accepted stream. `role = 1`
//! DRIVES: it opens a stream, writes a known probe, and checks that exactly
//! those bytes come back on the same stream, logging `[mux_echo] verified N`
//! when they do.
//!
//! Both halves live here rather than in a pair of fixtures because the property
//! is a round trip: the driver's assertion is only meaningful against the
//! echo's reply, and splitting them across two modules would let each half pass
//! while the pair was broken.
//!
//! # Wiring
//!
//! ```text
//!   quic.app_out  →  mux_echo.mux_in
//!   mux_echo.mux_out  →  quic.app_in
//! ```
//!
//! # Frames
//!
//! Every message is the universal `[msg_type u8][len u16 LE][payload]` TLV, and
//! stream-scoped payloads begin `[session_id u32 LE][stream_id u32 LE]`. The
//! echo reply reuses the inbound prefix verbatim rather than rebuilding it: a
//! self-test that re-derived the ids could agree with itself while disagreeing
//! with the transport.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

#[path = "../../sdk/contracts/net/mux.rs"]
mod mux;

/// Frame scratch. One mux frame carries at most a QUIC stream's worth of data
/// per delivery; 8 KiB matches the port's declared ring so a whole frame always
/// fits and a short read can never present as a truncated message.
const BUF: usize = 8192;

/// Answer accepted streams.
const ROLE_ECHO: u8 = 0;
/// Open a stream, probe it, and verify the reply.
const ROLE_DRIVE: u8 = 1;

/// The probe the driver writes and expects back verbatim. Fixed and
/// recognisable so a reply that is merely well-formed cannot pass for the right
/// one — the bytes have to be THESE bytes, on THIS stream.
const PROBE: &[u8] = b"fluxor-mux-selftest";

/// Ticks between driver attempts, so a handshake that is still completing is
/// retried rather than treated as a failure.
const DRIVE_RETRY_TICKS: u32 = 200;

#[repr(C)]
struct EchoState {
    syscalls: *const SyscallTable,
    mux_in: i32,
    mux_out: i32,
    /// Streams echoed since boot. A counter rather than a flag so "it answered
    /// once" and "it kept answering" are distinguishable.
    echoed: u32,
    /// Round trips the driver has verified.
    verified: u32,
    role: u8,
    /// 1 once the driver has a stream id from the transport.
    have_stream: u8,
    /// 1 once MSG_MUX_SESSION_OPENED has told us which session exists.
    ///
    /// The fixture waits for it rather than assuming session 0. Assuming
    /// is what the contract forbids, and a self-test that assumed would
    /// keep passing after the transport stopped announcing sessions at
    /// all — which is the failure most likely to matter to a real
    /// application.
    have_session: u8,
    _pad: [u8; 1],
    session_id: u32,
    stream_id: u32,
    ticks: u32,
    buf: [u8; BUF],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<EchoState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<EchoState>() {
            return -6;
        }
        let s = &mut *(state as *mut EchoState);
        s.syscalls = syscalls as *const SyscallTable;
        s.mux_in = in_chan;
        s.mux_out = out_chan;
        s.echoed = 0;
        s.verified = 0;
        s.have_stream = 0;
        s.have_session = 0;
        s.session_id = 0;
        s.stream_id = 0;
        s.ticks = 0;
        s.role = ROLE_ECHO;
        // The composer maps a graph's `role:` onto this tag by reading the
        // schema `define_params!` embeds in the artefact. Parsing the TLV by
        // hand here would compile and run and silently ignore the parameter,
        // because the name would never have been declared for the composer to
        // find — the module would default, and a graph asking for the driver
        // role would get a second echo.
        params_def::parse_tlv(s, params, params_len);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut EchoState);
        if s.syscalls.is_null() || s.mux_in < 0 {
            return -1;
        }
        let sys = &*s.syscalls;

        if s.role == ROLE_DRIVE {
            drive(s);
        }

        // Bounded per tick. A transport delivering faster than this fixture
        // drains is the transport's backpressure to apply, not a reason for one
        // module to hold the domain.
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.mux_in, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                return 0;
            }
            let n = (sys.channel_read)(s.mux_in, s.buf.as_mut_ptr(), BUF);
            if n < mux::FRAME_HDR as i32 {
                return 0;
            }
            handle_frames(s, n as usize);
        }
        0
    }
}

/// Walk every complete TLV in the read buffer.
///
/// A single read can return several concatenated frames, and dropping the tail
/// of a batch is the kind of fault a self-test must never have: it would look
/// like the transport losing a stream.
unsafe fn handle_frames(s: &mut EchoState, len: usize) {
    let mut off = 0usize;
    while off + mux::FRAME_HDR <= len {
        let t = s.buf[off];
        let plen = (s.buf[off + 1] as usize) | ((s.buf[off + 2] as usize) << 8);
        let body = off + mux::FRAME_HDR;
        if body + plen > len {
            return; // partial trailing frame — wait for the rest
        }
        if t == mux::MSG_MUX_SESSION_OPENED && plen >= mux::SESSION_OPENED_BODY_MIN + 1 {
            latch_session(s, body, plen);
        } else if s.role == ROLE_DRIVE {
            driver_frame(s, t, body, plen);
        } else if t == mux::MSG_MUX_STREAM_RX && plen >= mux::STREAM_DATA_PREFIX {
            // ONLY on stream bytes. An accepted-stream event shares the
            // `[session][stream]` prefix but its remaining bytes are the
            // event's own fields — direction flags and the transport
            // stream id — not stream content. Echoing those back put a
            // spurious prefix on the wire ahead of the real reply, which
            // the peer then read as part of the message.
            ack_bytes(s, body, plen - mux::STREAM_DATA_PREFIX);
            echo_stream(s, body, plen);
        }
        off = body + plen;
    }
}

/// Record which session the transport announced, and its ALPN.
///
/// `[session_id u32][status][flags][alpn_len][alpn]`.
unsafe fn latch_session(s: &mut EchoState, body: usize, _plen: usize) {
    let sys = &*s.syscalls;
    if s.buf[body + mux::SESSION_ID_BYTES] != mux::STATUS_OK {
        return;
    }
    s.session_id = u32::from_le_bytes([
        s.buf[body],
        s.buf[body + 1],
        s.buf[body + 2],
        s.buf[body + 3],
    ]);
    s.have_session = 1;
    dev_log(sys, 3, b"[mux_echo] session up".as_ptr(), 21);
}

/// Return per-stream flow-control credit for bytes this fixture has
/// consumed.
///
/// The transport advances MAX_STREAM_DATA and MAX_DATA from these
/// acknowledgements and from nothing else. That is the correct division —
/// it cannot know the application has drained its buffer — but it means a
/// consumer that never acknowledges eventually stalls the peer. This
/// fixture acknowledges so the credit path is exercised rather than
/// merely present.
unsafe fn ack_bytes(s: &mut EchoState, body: usize, data_len: usize) {
    let sys = &*s.syscalls;
    if s.mux_out < 0 || data_len == 0 {
        return;
    }
    let plen = mux::STREAM_DATA_PREFIX + 4;
    let mut f = [0u8; mux::FRAME_HDR + mux::STREAM_DATA_PREFIX + 4];
    f[0] = mux::CMD_MUX_STREAM_ACK;
    f[1] = plen as u8;
    f[2] = 0;
    core::ptr::copy_nonoverlapping(
        s.buf.as_ptr().add(body),
        f.as_mut_ptr().add(mux::FRAME_HDR),
        mux::STREAM_DATA_PREFIX,
    );
    let n = (data_len as u32).to_le_bytes();
    f[mux::FRAME_HDR + mux::STREAM_DATA_PREFIX..].copy_from_slice(&n);
    let _ = (sys.channel_write)(s.mux_out, f.as_ptr(), f.len());
}

/// Send the payload back on the stream it arrived on, then close that stream.
///
/// The `(session_id, stream_id)` prefix is copied from the inbound frame rather
/// than reconstructed. That is deliberate: the property under test is that the
/// transport delivers a stream's bytes to the application *with its identity
/// intact*, and a fixture that rebuilt the ids from its own state could pass
/// while the transport mixed two streams up.
unsafe fn echo_stream(s: &mut EchoState, body: usize, plen: usize) {
    let sys = &*s.syscalls;
    if s.mux_out < 0 {
        return;
    }
    let data_len = plen - mux::STREAM_DATA_PREFIX;

    // A zero-length delivery is an accept with no bytes yet: nothing to echo,
    // and closing here would race the peer's first write.
    if data_len == 0 {
        return;
    }

    let total = mux::FRAME_HDR + plen;
    if total > BUF {
        return;
    }

    // Build in place behind the inbound frame: [type][len][session][stream][data]
    let mut out = [0u8; BUF];
    out[0] = mux::CMD_MUX_STREAM_SEND;
    out[1] = (plen & 0xFF) as u8;
    out[2] = ((plen >> 8) & 0xFF) as u8;
    core::ptr::copy_nonoverlapping(s.buf.as_ptr().add(body), out.as_mut_ptr().add(3), plen);
    if (sys.channel_write)(s.mux_out, out.as_ptr(), total) <= 0 {
        // The transport is not ready. Drop rather than spin: the peer retries,
        // and a self-test that blocked here would report a transport fault that
        // is really its own backpressure.
        return;
    }

    // Close our half so the stream slot is reclaimed. Payload is the id prefix
    // alone.
    let mut fin = [0u8; mux::FRAME_HDR + mux::STREAM_DATA_PREFIX];
    fin[0] = mux::CMD_MUX_STREAM_CLOSE;
    fin[1] = mux::STREAM_DATA_PREFIX as u8;
    fin[2] = 0;
    core::ptr::copy_nonoverlapping(
        s.buf.as_ptr().add(body),
        fin.as_mut_ptr().add(3),
        mux::STREAM_DATA_PREFIX,
    );
    let _ = (sys.channel_write)(s.mux_out, fin.as_ptr(), fin.len());

    s.echoed = s.echoed.wrapping_add(1);
    // The readiness signal the suite keys on. Recurring per stream rather than a
    // one-shot boot banner, so a scenario cannot pass on a line that fired
    // before anything was observed.
    let mut line = [0u8; 32];
    line[..18].copy_from_slice(b"[mux_echo] echoed ");
    let n = fmt_u32_raw(line.as_mut_ptr().add(18), s.echoed);
    dev_log(sys, 3, line.as_ptr(), 18 + n);
}

// ── Driver role ────────────────────────────────────────────────────────────

/// Ask the transport for a stream, then keep asking until it answers.
///
/// The retry matters: at boot the QUIC handshake has not completed, so the
/// first open is expected to go unanswered. A self-test that gave up there
/// would report a transport failure that is really its own impatience.
unsafe fn drive(s: &mut EchoState) {
    s.ticks = s.ticks.wrapping_add(1);
    if s.have_stream != 0 || s.have_session == 0 || s.mux_out < 0 {
        return;
    }
    if s.ticks % DRIVE_RETRY_TICKS != 1 {
        return;
    }
    let sys = &*s.syscalls;
    let plen = mux::SESSION_ID_BYTES + 1;
    let mut f = [0u8; mux::FRAME_HDR + mux::SESSION_ID_BYTES + 1];
    f[0] = mux::CMD_MUX_STREAM_OPEN;
    f[1] = plen as u8;
    f[2] = 0;
    // The session the transport announced — not an assumed 0.
    f[mux::FRAME_HDR..mux::FRAME_HDR + mux::SESSION_ID_BYTES]
        .copy_from_slice(&s.session_id.to_le_bytes());
    f[mux::FRAME_HDR + mux::SESSION_ID_BYTES] = mux::STREAM_FLAG_BIDI;
    let _ = (sys.channel_write)(s.mux_out, f.as_ptr(), f.len());
}

/// Handle a frame in driver role: latch the stream id, then check the echo.
unsafe fn driver_frame(s: &mut EchoState, t: u8, body: usize, plen: usize) {
    let sys = &*s.syscalls;
    if t == mux::MSG_MUX_STREAM_OPENED && plen >= mux::STREAM_DATA_PREFIX + mux::STREAM_OPENED_BODY
    {
        // A refused open is answered too, with STATUS_NO_CAPACITY and no
        // usable handle. Treating that as success would write the probe
        // onto a stream that does not exist and then wait forever for a
        // reply, which reads as a transport fault rather than a full pool.
        if s.buf[body + mux::STREAM_DATA_PREFIX] != mux::STATUS_OK {
            return;
        }
        s.session_id = u32::from_le_bytes([
            s.buf[body],
            s.buf[body + 1],
            s.buf[body + 2],
            s.buf[body + 3],
        ]);
        s.stream_id = u32::from_le_bytes([
            s.buf[body + 4],
            s.buf[body + 5],
            s.buf[body + 6],
            s.buf[body + 7],
        ]);
        s.have_stream = 1;

        // Write the probe on the stream the transport just handed us.
        let payload = mux::STREAM_DATA_PREFIX + PROBE.len();
        let mut f = [0u8; mux::FRAME_HDR + mux::STREAM_DATA_PREFIX + 32];
        f[0] = mux::CMD_MUX_STREAM_SEND;
        f[1] = (payload & 0xFF) as u8;
        f[2] = ((payload >> 8) & 0xFF) as u8;
        core::ptr::copy_nonoverlapping(
            s.buf.as_ptr().add(body),
            f.as_mut_ptr().add(3),
            mux::STREAM_DATA_PREFIX,
        );
        core::ptr::copy_nonoverlapping(
            PROBE.as_ptr(),
            f.as_mut_ptr().add(3 + mux::STREAM_DATA_PREFIX),
            PROBE.len(),
        );
        let _ = (sys.channel_write)(s.mux_out, f.as_ptr(), mux::FRAME_HDR + payload);

        // End our send half immediately: the probe is the whole of what
        // this side has to say. Without the FIN the stream never
        // finishes, so its slot is never reclaimed — and since the pool
        // is fixed, the driver stops being able to open streams after a
        // few round trips. That reads as the transport wedging, when it
        // is the application holding every stream open.
        let mut fin = [0u8; mux::FRAME_HDR + mux::STREAM_DATA_PREFIX];
        fin[0] = mux::CMD_MUX_STREAM_CLOSE;
        fin[1] = mux::STREAM_DATA_PREFIX as u8;
        fin[2] = 0;
        core::ptr::copy_nonoverlapping(
            s.buf.as_ptr().add(body),
            fin.as_mut_ptr().add(mux::FRAME_HDR),
            mux::STREAM_DATA_PREFIX,
        );
        let _ = (sys.channel_write)(s.mux_out, fin.as_ptr(), fin.len());
        return;
    }

    if t != mux::MSG_MUX_STREAM_RX || plen < mux::STREAM_DATA_PREFIX + PROBE.len() {
        return;
    }

    // The reply must be on OUR stream and carry OUR bytes. Checking both is the
    // point: a transport that answered the right bytes on the wrong stream, or
    // the wrong bytes on the right stream, has failed in a way that a
    // length-only or id-only check would call a pass.
    let sid = u32::from_le_bytes([
        s.buf[body + 4],
        s.buf[body + 5],
        s.buf[body + 6],
        s.buf[body + 7],
    ]);
    if sid != s.stream_id {
        dev_log(sys, 1, b"[mux_echo] WRONG STREAM".as_ptr(), 23);
        return;
    }
    ack_bytes(s, body, plen - mux::STREAM_DATA_PREFIX);
    let at = body + mux::STREAM_DATA_PREFIX;
    let mut i = 0usize;
    while i < PROBE.len() {
        if s.buf[at + i] != PROBE[i] {
            dev_log(sys, 1, b"[mux_echo] WRONG BYTES".as_ptr(), 22);
            return;
        }
        i += 1;
    }

    s.verified = s.verified.wrapping_add(1);
    // Steady-state signal the suite keys on, one line per verified round trip.
    let mut line = [0u8; 40];
    line[..20].copy_from_slice(b"[mux_echo] verified ");
    let n = fmt_u32_raw(line.as_mut_ptr().add(20), s.verified);
    dev_log(sys, 3, line.as_ptr(), 20 + n);

    // Open another so the signal recurs — a self-test that fired once could not
    // tell "it works" from "it worked once and then wedged".
    s.have_stream = 0;
    s.ticks = 0;
}

// ── Param schema ───────────────────────────────────────────────────────────

mod params_def {
    use super::p_u8;
    use super::EchoState;
    use super::SCHEMA_MAX;

    define_params! {
        EchoState;

        1, role, u8, 0
            => |s, d, len| { s.role = p_u8(d, len, 0, 0); };
    }
}

/// Streams echoed so far. Host-test only.
///
/// # Safety
/// `state` must be an initialised `EchoState` from `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_echoed(state: *const u8) -> u32 {
    (*(state as *const EchoState)).echoed
}

/// Round trips the driver verified. Host-test only.
///
/// # Safety
/// `state` must be an initialised `EchoState` from `module_new`.
#[cfg(feature = "host-test")]
pub unsafe fn test_verified(state: *const u8) -> u32 {
    (*(state as *const EchoState)).verified
}

include!("../../sdk/runtime/wasm_entry.rs");
