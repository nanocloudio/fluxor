//! SNTP client (RFC 4330) anchoring the wall clock of a board with no RTC.
//!
//! See the manifest for the contract. One round: send a client request to
//! every configured server, take each valid reply as an anchor at its arrival
//! (unix = T3 + delay/2), and when `quorum` of them agree within `agree_ms`
//! hand the kernel the tightest of those through `timer::DISCIPLINE`.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
use abi::kernel_abi::{timer, trusted_time as tt};
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/cores/datagram_endpoint.rs");

pub const MAX_SERVERS: usize = 4;
const NTP_PORT: u16 = 123;
pub const NTP_LEN: usize = 48;
/// Seconds from the NTP prime epoch (1900-01-01) to the Unix epoch.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
/// How long a round waits for replies.
const ROUND_MS: u64 = 2_000;
/// Read granularity of the clocks the anchor is built from.
const TICK_ERR_US: u64 = 1_000;
const HB_MS: u64 = 30_000;
const SCRATCH: usize = 256;
/// Shortest interval between requests to one server: RFC 4330 §10 forbids
/// polling more often than every 15 s under any conditions.
pub const MIN_POLL_S: u32 = 15;
/// Longest interval between rounds: half the kernel's one-hour anchor
/// staleness (`timer::DISCIPLINE`), so one failed round never lets the clock
/// go stale.
pub const MAX_POLL_S: u32 = 1_800;
/// A failed round's retry interval doubles per consecutive failure, at most
/// this many times (and never past `poll_s`).
const MAX_BACKOFF_SHIFT: u32 = 6;

const SV_IDLE: u8 = 0;
const SV_SENT: u8 = 1;
const SV_GOT: u8 = 2;

const PH_BOOT: u8 = 0;
const PH_IDLE: u8 = 1;
const PH_ROUND: u8 = 2;

#[derive(Clone, Copy)]
struct Server {
    ip: u32,
    state: u8,
    /// The server sent a `DENY` or `RSTR` kiss-o'-death: it is never asked
    /// again (RFC 5905 §7.4).
    denied: bool,
    nonce: [u8; 8],
    sent_mono_us: u64,
    /// No request to this server before this uptime (a `RATE` kiss).
    hold_until_ms: u64,
    /// The anchor this server's reply gives: Unix µs at monotonic `mono_us`.
    unix_us: u64,
    mono_us: u64,
    err_us: u64,
}

const SERVER0: Server = Server {
    ip: 0,
    state: SV_IDLE,
    denied: false,
    nonce: [0; 8],
    sent_mono_us: 0,
    hold_until_ms: 0,
    unix_us: 0,
    mono_us: 0,
    err_us: 0,
};

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,
    ep: DatagramEndpoint,
    servers: [Server; MAX_SERVERS],
    quorum: u8,
    phase: u8,
    synced: u8,
    _pad: u8,
    agree_ms: u32,
    poll_s: u32,
    retry_s: u32,
    boot_delay_ms: u32,
    rounds: u32,
    syncs: u32,
    /// Consecutive rounds that ended without an anchor.
    fails: u32,
    last_rc: i32,
    last_err_us: u32,
    next_round_ms: u64,
    round_deadline_ms: u64,
    last_hb_ms: u64,
    scratch: [u8; SCRATCH],
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::{p_u32, p_u8};

    define_params! {
        State;

        1, server0, u32, 0
            => |s, d, len| { s.servers[0].ip = p_u32(d, len, 0, 0); };

        2, server1, u32, 0
            => |s, d, len| { s.servers[1].ip = p_u32(d, len, 0, 0); };

        3, server2, u32, 0
            => |s, d, len| { s.servers[2].ip = p_u32(d, len, 0, 0); };

        4, server3, u32, 0
            => |s, d, len| { s.servers[3].ip = p_u32(d, len, 0, 0); };

        5, quorum, u8, 2
            => |s, d, len| { s.quorum = p_u8(d, len, 0, 2); };

        6, agree_ms, u32, 1000
            => |s, d, len| { s.agree_ms = p_u32(d, len, 0, 1000); };

        7, poll_s, u32, 600
            => |s, d, len| { s.poll_s = p_u32(d, len, 0, 600); };

        8, retry_s, u32, 15
            => |s, d, len| { s.retry_s = p_u32(d, len, 0, 15); };

        9, boot_delay_ms, u32, 5000
            => |s, d, len| { s.boot_delay_ms = p_u32(d, len, 0, 5000); };
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.ep = DatagramEndpoint::new();
        s.servers = [SERVER0; MAX_SERVERS];
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if s.quorum == 0 {
            s.quorum = 1;
        }
        s.poll_s = s.poll_s.clamp(MIN_POLL_S, MAX_POLL_S);
        s.retry_s = s.retry_s.clamp(MIN_POLL_S, s.poll_s);
    }
    0
}

fn be32(b: &[u8; NTP_LEN], at: usize) -> u64 {
    match b.get(at..at + 4) {
        Some(x) => u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64,
        None => 0,
    }
}

/// An NTP timestamp's seconds field as Unix seconds. The 32-bit field wraps
/// every 136 years; RFC 4330 §3 resolves the era by its top bit: set, era 0
/// (1968–2036); clear, era 1 (2036–2104). `None` before the Unix epoch.
pub fn ntp_secs_to_unix(secs: u32) -> Option<u64> {
    let secs = secs as u64;
    let secs = if secs & 0x8000_0000 != 0 {
        secs
    } else {
        secs + (1u64 << 32)
    };
    secs.checked_sub(NTP_UNIX_OFFSET)
}

/// The NTP timestamp at `at` as Unix microseconds, or `None` before 1970.
fn ntp_unix_us(b: &[u8; NTP_LEN], at: usize) -> Option<u64> {
    let secs = ntp_secs_to_unix(be32(b, at) as u32)?;
    let frac = be32(b, at + 4);
    Some(secs * 1_000_000 + ((frac * 1_000_000) >> 32))
}

/// A 16.16 fixed-point NTP short (seconds) as microseconds.
fn short_us(b: &[u8; NTP_LEN], at: usize) -> u64 {
    (be32(b, at) * 1_000_000) >> 16
}

/// What one reply says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A valid time sample: at monotonic `mono_us` it was `unix_us`, within
    /// `err_us`.
    Anchor {
        unix_us: u64,
        mono_us: u64,
        err_us: u64,
    },
    /// A kiss-o'-death (stratum 0) answering our request, with its code.
    Kiss([u8; 4]),
    /// Not an answer to our request, or not a usable one.
    Invalid,
}

/// Validate one reply against the request we sent (`nonce` in its transmit
/// timestamp at monotonic `sent_mono_us`) and read it, the reply having
/// arrived at monotonic `t4`.
///
/// The origin timestamp must echo the nonce before anything else is
/// believed, a kiss-o'-death included: an off-path sender cannot guess it,
/// and a replayed reply carries an older one.
pub fn read_reply(nonce: &[u8; 8], sent_mono_us: u64, b: &[u8; NTP_LEN], t4: u64) -> Reply {
    let leap = b[0] >> 6;
    let mode = b[0] & 0x07;
    let stratum = b[1];
    if mode != 4 || b[24..32] != nonce[..] {
        return Reply::Invalid;
    }
    if stratum == 0 {
        return Reply::Kiss([b[12], b[13], b[14], b[15]]);
    }
    // Leap indicator 3: the server's own clock is unsynchronised.
    if leap == 3 || stratum > 15 {
        return Reply::Invalid;
    }
    if b[40..48].iter().all(|&x| x == 0) {
        return Reply::Invalid;
    }
    let (Some(t2), Some(t3)) = (ntp_unix_us(b, 32), ntp_unix_us(b, 40)) else {
        return Reply::Invalid;
    };
    if t3 < t2 || t4 < sent_mono_us {
        return Reply::Invalid;
    }
    // The round trip less the server's hold time. The true time at `t4` lies
    // in `[t3, t3 + delay]`, so its midpoint is off by at most `delay / 2`;
    // the server's own distance from its reference adds the rest.
    let delay = (t4 - sent_mono_us).saturating_sub(t3 - t2);
    Reply::Anchor {
        unix_us: t3 + delay / 2,
        mono_us: t4,
        err_us: delay / 2 + short_us(b, 4) / 2 + short_us(b, 8) + TICK_ERR_US,
    }
}

/// The servers that agree: the largest set of samples lying within
/// `agree_us` of each other, its spread, and its tightest member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agreement {
    pub count: u32,
    pub spread_us: u64,
    /// Index of the member with the smallest error bound.
    pub best: usize,
}

/// Choose the agreement among `samples` — `(unix_us at a common instant,
/// err_us)` per server, `None` for no sample. The largest agreeing set wins,
/// a tie going to the set whose tightest member is tighter, so one wrong
/// server among several right ones is outvoted rather than spoiling the
/// round.
pub fn agree(samples: &[Option<(u64, u64)>], agree_us: u64) -> Option<Agreement> {
    let mut chosen: Option<(Agreement, u64)> = None;
    for &(lo, _) in samples.iter().flatten() {
        let mut count = 0u32;
        let mut hi = lo;
        let mut best: Option<(usize, u64)> = None;
        for (j, s) in samples.iter().enumerate() {
            let Some((at, err)) = *s else { continue };
            if at < lo || at - lo > agree_us {
                continue;
            }
            count += 1;
            hi = hi.max(at);
            if best.is_none_or(|(_, e)| err < e) {
                best = Some((j, err));
            }
        }
        let Some((best, best_err)) = best else {
            continue;
        };
        let a = Agreement {
            count,
            spread_us: hi - lo,
            best,
        };
        let better = match chosen {
            None => true,
            Some((c, c_err)) => count > c.count || (count == c.count && best_err < c_err),
        };
        if better {
            chosen = Some((a, best_err));
        }
    }
    chosen.map(|(a, _)| a)
}

/// Append decimal `v` at `msg[len..]`.
fn put_dec(msg: &mut [u8], mut len: usize, v: i64) -> usize {
    let mut x = if v < 0 {
        if let Some(b) = msg.get_mut(len) {
            *b = b'-';
            len += 1;
        }
        v.unsigned_abs()
    } else {
        v as u64
    };
    let mut digits = [0u8; 20];
    let mut d = 0usize;
    loop {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
        if x == 0 || d >= digits.len() {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        match msg.get_mut(len) {
            Some(b) => {
                *b = digits[d];
                len += 1;
            }
            None => break,
        }
    }
    len
}

fn put(msg: &mut [u8], mut len: usize, s: &[u8]) -> usize {
    for &c in s {
        match msg.get_mut(len) {
            Some(b) => {
                *b = c;
                len += 1;
            }
            None => break,
        }
    }
    len
}

unsafe fn report(sys: &SyscallTable, head: &[u8], kv: &[(&[u8], i64)]) {
    let mut msg = [0u8; 160];
    let mut len = put(&mut msg, 0, b"[sntp] ");
    len = put(&mut msg, len, head);
    for (k, v) in kv {
        len = put(&mut msg, len, b" ");
        len = put(&mut msg, len, k);
        len = put(&mut msg, len, b"=");
        len = put_dec(&mut msg, len, *v);
    }
    dev_log(sys, 3, msg.as_ptr(), len);
}

unsafe fn nonce(sys: &SyscallTable, out: &mut [u8; 8]) {
    let rc = (sys.provider_call)(
        -1,
        abi::kernel_abi::RANDOM_FILL,
        out.as_mut_ptr(),
        out.len(),
    );
    if rc < 0 {
        // No entropy source: still unique per request, which is what the
        // origin check needs against stale replies.
        *out = dev_micros(sys).to_le_bytes();
    }
}

/// Send every configured server that has not been sent this round and may
/// be asked now.
unsafe fn send_pending(sys: &SyscallTable, s: &mut State, now_ms: u64) {
    for i in 0..MAX_SERVERS {
        let sv = s.servers[i];
        if sv.ip == 0 || sv.denied || sv.state != SV_IDLE || now_ms < sv.hold_until_ms {
            continue;
        }
        let mut n = [0u8; 8];
        nonce(sys, &mut n);
        let mut pkt = [0u8; NTP_LEN];
        pkt[0] = 0x23; // LI 0, VN 4, mode 3 (client)
        for (k, &b) in n.iter().enumerate() {
            pkt[40 + k] = b;
        }
        let now = dev_micros(sys);
        let sent = s.ep.send_to(
            sys,
            s.net_out,
            sv.ip,
            NTP_PORT,
            pkt.as_ptr(),
            pkt.len(),
            s.scratch.as_mut_ptr(),
            SCRATCH,
        );
        if sent == 0 {
            return; // channel full or not bound: retry next step
        }
        let sv = &mut s.servers[i];
        sv.nonce = n;
        sv.sent_mono_us = now;
        sv.state = SV_SENT;
    }
}

/// Whether server `sv` still owes this round a reply.
fn awaited(sv: &Server, now_ms: u64) -> bool {
    sv.ip != 0 && !sv.denied && now_ms >= sv.hold_until_ms && sv.state != SV_GOT
}

/// Close the round: anchor the clock if a quorum agrees.
unsafe fn finish_round(sys: &SyscallTable, s: &mut State, now_ms: u64) {
    let now_us = dev_micros(sys);
    let mut samples = [None; MAX_SERVERS];
    let mut got = 0u32;
    for (i, sv) in s.servers.iter().enumerate() {
        if sv.state == SV_GOT {
            got += 1;
            // Every sample carried forward to one instant, so they compare.
            samples[i] = Some((sv.unix_us + now_us.saturating_sub(sv.mono_us), sv.err_us));
        }
    }
    s.rounds += 1;
    let agreement = agree(&samples, s.agree_ms as u64 * 1_000);
    let anchored = match agreement {
        Some(a) if a.count >= s.quorum as u32 => {
            let b = s.servers[a.best];
            // Disagreement between agreeing servers widens the bound.
            let err = b.err_us.saturating_add(a.spread_us).min(u32::MAX as u64);
            let mut arg = [0u8; 20];
            arg[..8].copy_from_slice(&b.unix_us.to_le_bytes());
            arg[8..16].copy_from_slice(&b.mono_us.to_le_bytes());
            arg[16..].copy_from_slice(&(err as u32).to_le_bytes());
            let rc = (sys.provider_call)(-1, timer::DISCIPLINE, arg.as_mut_ptr(), arg.len());
            s.last_rc = rc;
            s.last_err_us = err as u32;
            if rc == 0 {
                s.synced = 1;
                s.syncs += 1;
            }
            report(
                sys,
                b"sync",
                &[
                    (b"n", a.count as i64),
                    (b"got", got as i64),
                    (b"spread_us", a.spread_us as i64),
                    (b"err_us", err as i64),
                    (b"unix_ms", (b.unix_us / 1_000) as i64),
                    (b"rc", rc as i64),
                ],
            );
            rc == 0
        }
        _ => {
            let (n, spread) = agreement.map_or((0, 0), |a| (a.count, a.spread_us));
            report(
                sys,
                b"no_quorum",
                &[
                    (b"got", got as i64),
                    (b"n", n as i64),
                    (b"spread_us", spread as i64),
                ],
            );
            false
        }
    };
    s.next_round_ms = if anchored {
        s.fails = 0;
        now_ms + s.poll_s as u64 * 1_000
    } else {
        s.fails = s.fails.saturating_add(1);
        let shift = (s.fails - 1).min(MAX_BACKOFF_SHIFT);
        let retry_s = ((s.retry_s as u64) << shift).min(s.poll_s as u64);
        now_ms + retry_s * 1_000
    };
    for sv in s.servers.iter_mut() {
        sv.state = SV_IDLE;
    }
    s.phase = PH_IDLE;
}

/// Act on a kiss-o'-death from server `i` (RFC 5905 §7.4): `DENY` and `RSTR`
/// end all requests to it; `RATE` holds it off for a full poll interval.
/// Any other code only voids this round's sample.
unsafe fn on_kiss(sys: &SyscallTable, s: &mut State, i: usize, code: [u8; 4], now_ms: u64) {
    let poll_ms = s.poll_s as u64 * 1_000;
    let sv = &mut s.servers[i];
    sv.state = SV_IDLE;
    let action: &[u8] = if code == *b"DENY" || code == *b"RSTR" {
        sv.denied = true;
        b"kod_denied"
    } else if code == *b"RATE" {
        sv.hold_until_ms = now_ms + poll_ms;
        b"kod_rate"
    } else {
        b"kod"
    };
    report(sys, action, &[(b"server", i as i64)]);
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        let sys = &*s.syscalls;
        let now_ms = dev_millis(sys);

        if now_ms.saturating_sub(s.last_hb_ms) >= HB_MS {
            s.last_hb_ms = now_ms;
            // The kernel's own verdict on the clock, beside this client's.
            let mut rec = [0u8; tt::LEN];
            let _ = (sys.provider_call)(-1, timer::TRUSTED_UNIX, rec.as_mut_ptr(), rec.len());
            let mut secs = [0u8; 8];
            secs.copy_from_slice(&rec[tt::OFF_UNIX_SECONDS..tt::OFF_UNIX_SECONDS + 8]);
            let mut unc = [0u8; 4];
            unc.copy_from_slice(&rec[tt::OFF_UNCERTAINTY_MS..tt::OFF_UNCERTAINTY_MS + 4]);
            report(
                sys,
                b"hb",
                &[
                    (b"synced", s.synced as i64),
                    (b"rounds", s.rounds as i64),
                    (b"syncs", s.syncs as i64),
                    (b"rc", s.last_rc as i64),
                    (b"err_us", s.last_err_us as i64),
                    (b"cls", rec[tt::OFF_SOURCE_CLASS] as i64),
                    (b"flags", rec[tt::OFF_FLAGS] as i64),
                    (b"unc_ms", u32::from_le_bytes(unc) as i64),
                    (b"unix_s", u64::from_le_bytes(secs) as i64),
                ],
            );
        }

        let scratch = s.scratch.as_mut_ptr();
        s.ep.poll_bind(sys, s.net_out, 0, scratch, SCRATCH);
        while let Some(ev) = dg_recv(sys, s.net_in, scratch, SCRATCH) {
            match ev {
                DgEvent::Bound { ep_id, .. } => s.ep.on_bound(ep_id),
                DgEvent::Err { .. } => s.ep.on_error(sys),
                DgEvent::Rx {
                    src_ip,
                    src_port,
                    data,
                    len,
                    ..
                } => {
                    if src_port != NTP_PORT || len < NTP_LEN || data.is_null() {
                        continue;
                    }
                    let t4 = dev_micros(sys);
                    let mut b = [0u8; NTP_LEN];
                    core::ptr::copy_nonoverlapping(data, b.as_mut_ptr(), NTP_LEN);
                    for i in 0..MAX_SERVERS {
                        let sv = s.servers[i];
                        if sv.ip != src_ip || sv.state != SV_SENT {
                            continue;
                        }
                        match read_reply(&sv.nonce, sv.sent_mono_us, &b, t4) {
                            Reply::Anchor {
                                unix_us,
                                mono_us,
                                err_us,
                            } => {
                                let sv = &mut s.servers[i];
                                sv.unix_us = unix_us;
                                sv.mono_us = mono_us;
                                sv.err_us = err_us;
                                sv.state = SV_GOT;
                            }
                            Reply::Kiss(code) => on_kiss(sys, s, i, code, now_ms),
                            Reply::Invalid => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if !s.ep.is_ready() {
            return 0;
        }

        match s.phase {
            PH_BOOT => {
                if now_ms >= s.boot_delay_ms as u64 {
                    s.phase = PH_IDLE;
                    s.next_round_ms = now_ms;
                }
            }
            PH_IDLE => {
                if now_ms >= s.next_round_ms {
                    for sv in s.servers.iter_mut() {
                        sv.state = SV_IDLE;
                    }
                    s.round_deadline_ms = now_ms + ROUND_MS;
                    s.phase = PH_ROUND;
                    send_pending(sys, s, now_ms);
                }
            }
            PH_ROUND => {
                send_pending(sys, s, now_ms);
                let waiting = s.servers.iter().any(|sv| awaited(sv, now_ms));
                if !waiting || now_ms >= s.round_deadline_ms {
                    finish_round(sys, s, now_ms);
                }
            }
            _ => {}
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
