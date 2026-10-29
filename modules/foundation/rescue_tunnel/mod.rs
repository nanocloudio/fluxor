//! rescue_tunnel — the ingress cell's authenticated tunnel to a remote
//! anchor, both ends in one module.
//!
//! **Ingress end.** A director that finds a flow's anchor on another host
//! disposes its packet `TUNNEL` with `[anchor_id:u16 LE][flow_epoch:u32 LE]`;
//! `ip` hands the frame to its forward port, and this module (directly, or
//! behind `fwd_split`) seals the IP packet whole (`cores/rescue_tunnel.rs`:
//! the service, the route generation, the flow epoch, the anchor and the
//! original ingress host — this one — under the cell's key and this host's
//! next sequence) and sends it over `ip`'s datagram surface to UDP `RT_PORT`
//! on the anchor's host. A forward record does not say which interface or
//! queue the packet arrived on, so the header's `ingress_if` and `rx_queue`
//! are 0. The IP packet is the frame's payload cut to the packet's own
//! length (Ethernet padding is not part of it); a frame that is not
//! untagged IPv4 or IPv6, or whose packet is longer than the frame, is
//! refused (`malformed`).
//!
//! The sequence starts at this host's wall-clock time in milliseconds
//! shifted left by 20 bits and counts up from there, so an ingress host
//! that starts again carries on above the sequence its previous run reached
//! (unless that run averaged over 2^20 packets a millisecond) and the
//! anchor's window for it takes its packets. A platform with no real-time
//! clock starts at 1, and says so: after a restart there, the anchor refuses
//! this host's packets as replays until its own window is reset.
//!
//! The sealed datagram is the IP packet plus `RT_OVERHEAD` bytes, inside
//! UDP and IP on the fabric, and `ip` sends no datagram larger than one
//! frame and fragments none: a packet too large to fit is refused by `ip`
//! (`MSG_DG_ERROR`), which this end counts (`send_refused`). The fabric's
//! frame must exceed the service's by the tunnel's overhead, or the
//! service's segments be kept small enough (its MSS) to fit.
//!
//! **Anchor end.** A datagram on `RT_PORT` is opened only when its tag
//! verifies under the cell's key and its sequence passes the ingress host's
//! 64-packet window, it is for this host's service (`service_id`) and its
//! anchor is one this host serves (`serve`), and the inner packet's own
//! length is the length the header gives it; then the inner packet is
//! handed to this host's `ip` as an Ethernet frame on
//! `frames_out` (wired into `ip.frames_rx` through the NIC's merge), as if it
//! had arrived here. Everything else is refused and counted by reason.
//!
//! Ports: in[0] `fwd_in` (forward records), in[1] `dg_in` (from `ip`'s
//! `net_out`: the datagram surface); out[0] `dg_out` (to `ip.net_in`),
//! out[1] `frames_out` (to `ip.frames_rx`, `[len:u16 LE][frame]`).
//!
//! Params: `key` (64 hex: the cell's rescue key) or `key_label` (the cell's
//! HMAC-SHA256 key provisioned in this host's vault under that label: the
//! vault makes every tag and the key never leaves it), `host_id` (16 hex: this
//! ingress host, unique in the cell and required with `anchors`), `service_id` (32 hex: the service sealed for, and the only
//! one opened for), `route_gen` (u32), `anchors`
//! (`id=a.b.c.d,…`: the host each anchor id is on), `serve` (`id,…`: the
//! anchors this host is), `mac` (12 hex: the destination MAC injected frames
//! carry — `ip` accepts any).

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

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::contracts::key_vault as kv;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/cores/rescue_tunnel.rs");

const HDR: usize = 3;
pub const FRAME_MAX: usize = 1600;
const ANCHORS: usize = 16;
const PER_STEP: usize = 32;
const LOG_PERIOD: u32 = 4096;

const MSG_PKT_FORWARD: u8 = 0x65;
const DISP_TUNNEL: u8 = 3;
const CMD_DG_BIND: u8 = 0x20;
const CMD_DG_SEND_TO: u8 = 0x21;
const MSG_DG_BOUND: u8 = 0x40;
const MSG_DG_RX_FROM: u8 = 0x41;
const MSG_DG_ERROR: u8 = 0x43;
const ETH_HDR: usize = 14;

/// Counters, by reason.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct RtStats {
    pub sealed: u32,
    pub sent: u32,
    pub opened: u32,
    pub injected: u32,
    pub not_tunnel: u32,
    pub no_anchor: u32,
    pub malformed: u32,
    pub tag: u32,
    pub replay: u32,
    pub capacity: u32,
    pub not_served: u32,
    pub unbound: u32,
    /// Sealed datagrams `ip` refused to send (`MSG_DG_ERROR`): too large
    /// for one frame, or no route to the anchor's host.
    pub send_refused: u32,
}

#[repr(C)]
pub struct RtState {
    syscalls: *const SyscallTable,
    fwd_in: i32,
    dg_in: i32,
    dg_out: i32,
    frames_out: i32,
    key: [u8; 32],
    key_set: bool,
    /// `key_label`: the cell's key provisioned in this host's vault (an
    /// HMAC-SHA256 key, by label); empty for the `key` param.
    key_label: [u8; kv::MAX_LABEL],
    key_label_len: u8,
    /// The vault's HMAC-SHA256 slot it names, or -1: its tags are made by
    /// the vault (`SIGN`) and the key never leaves it.
    cell_key: i32,
    host_id: [u8; 8],
    service_id: [u8; 16],
    route_gen: u32,
    anchor_ids: [u16; ANCHORS],
    /// Each anchor host's address, sixteen bytes: IPv6, or IPv4 in the
    /// last four with `anchor_v6` clear.
    anchor_ips: [[u8; 16]; ANCHORS],
    anchor_v6: [bool; ANCHORS],
    anchors: u8,
    serve: [u16; ANCHORS],
    serves: u8,
    mac: [u8; 6],
    /// The id of the first param that did not parse (0 none).
    bad_param: u8,
    ep_id: u8,
    bound: bool,
    bind_sent: bool,
    seq: u64,
    windows: RtWindows,
    step_count: u32,
    logged: [u32; 5],
    pub stats: RtStats,
    rx: [u8; FRAME_MAX + 64],
    tx: [u8; FRAME_MAX + 64],
}

fn hexv(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Exactly `out.len()` bytes of hex.
pub fn parse_hex(t: &[u8], out: &mut [u8]) -> bool {
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    if t.len() != out.len() * 2 {
        return false;
    }
    for (i, o) in out.iter_mut().enumerate() {
        match (hexv(t[2 * i]), hexv(t[2 * i + 1])) {
            (Some(a), Some(b)) => *o = (a << 4) | b,
            _ => return false,
        }
    }
    true
}

fn parse_u16(t: &[u8]) -> Option<u16> {
    if t.is_empty() || t.len() > 5 {
        return None;
    }
    let mut v = 0u32;
    for &b in t {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(b - b'0');
    }
    u16::try_from(v).ok()
}

fn parse_ipv4(t: &[u8]) -> Option<u32> {
    let mut v = 0u32;
    let mut parts = 0;
    for p in t.split(|&b| b == b'.') {
        let n = parse_u16(p)?;
        if n > 255 {
            return None;
        }
        v = (v << 8) | u32::from(n);
        parts += 1;
    }
    (parts == 4).then_some(v)
}

fn trim(mut t: &[u8]) -> &[u8] {
    while let [b' ', r @ ..] = t {
        t = r;
    }
    while let [r @ .., b' '] = t {
        t = r;
    }
    t
}

/// RFC 4291 text (`2001:db8::1`, `::`), sixteen bytes.
pub fn parse_ipv6(t: &[u8]) -> Option<[u8; 16]> {
    let mut head = [0u16; 8];
    let mut tail = [0u16; 8];
    let (mut nh, mut nt) = (0usize, 0usize);
    let (h, tl) = match t.windows(2).position(|w| w == b"::") {
        Some(i) => (&t[..i], Some(&t[i + 2..])),
        None => (t, None),
    };
    let group = |g: &[u8]| -> Option<u16> {
        if g.is_empty() || g.len() > 4 {
            return None;
        }
        let mut v = 0u16;
        for &b in g {
            v = (v << 4) | u16::from(hexv(b)?);
        }
        Some(v)
    };
    if !h.is_empty() {
        for g in h.split(|&b| b == b':') {
            if nh == 8 {
                return None;
            }
            head[nh] = group(g)?;
            nh += 1;
        }
    }
    if let Some(tl) = tl {
        if !tl.is_empty() {
            for g in tl.split(|&b| b == b':') {
                if nt == 8 {
                    return None;
                }
                tail[nt] = group(g)?;
                nt += 1;
            }
        }
        if nh + nt > 7 {
            return None;
        }
    } else if nh != 8 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, g) in head.iter().take(nh).enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
    }
    for (i, g) in tail.iter().take(nt).enumerate() {
        let at = 16 - 2 * (nt - i);
        out[at..at + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

/// `id=a.b.c.d,…` or `id=[2001:db8::2],…`.
pub fn parse_anchors(
    t: &[u8],
    ids: &mut [u16; ANCHORS],
    ips: &mut [[u8; 16]; ANCHORS],
    v6: &mut [bool; ANCHORS],
) -> Option<u8> {
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    let mut n = 0usize;
    for item in t.split(|&b| b == b',') {
        let item = trim(item);
        if item.is_empty() {
            continue;
        }
        let eq = item.iter().position(|&b| b == b'=')?;
        if n == ANCHORS {
            return None;
        }
        ids[n] = parse_u16(trim(&item[..eq]))?;
        let a = trim(&item[eq + 1..]);
        if let [b'[', inner @ .., b']'] = a {
            ips[n] = parse_ipv6(inner)?;
            v6[n] = true;
        } else {
            ips[n] = [0; 16];
            ips[n][12..].copy_from_slice(&parse_ipv4(a)?.to_be_bytes());
            v6[n] = false;
        }
        n += 1;
    }
    Some(n as u8)
}

/// `id,…`.
pub fn parse_serve(t: &[u8], ids: &mut [u16; ANCHORS]) -> Option<u8> {
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    let mut n = 0usize;
    for item in t.split(|&b| b == b',') {
        let item = trim(item);
        if item.is_empty() {
            continue;
        }
        if n == ANCHORS {
            return None;
        }
        ids[n] = parse_u16(item)?;
        n += 1;
    }
    Some(n as u8)
}

/// A string param's text up to its NUL, or None when it is empty: the
/// defaults pass hands every `str` param its zero default first, which is
/// the param unset, not one that failed to parse.
unsafe fn text<'a>(d: *const u8, len: usize) -> Option<&'a [u8]> {
    let t = core::slice::from_raw_parts(d, len);
    let t = t.split(|&b| b == 0).next().unwrap_or(&[]);
    (!t.is_empty()).then_some(t)
}

/// Open the cell's provisioned HMAC-SHA256 key `label` in this host's
/// vault (imported there, the same key on every host of the cell; never
/// made here): a handle that answers tags (`SIGN`), or -1.
unsafe fn open_cell_key(sys: &SyscallTable, label: &[u8]) -> i32 {
    let mut arg = [0u8; 8 + kv::MAX_LABEL + 12];
    arg[0..2].copy_from_slice(&kv::suite::HMAC_SHA256.to_le_bytes());
    let usage = kv::usage::SIGN | kv::usage::VERIFY | kv::usage::PERSIST;
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[7] = label.len() as u8;
    arg[8..8 + label.len()].copy_from_slice(label);
    let t = 8 + label.len();
    let h = (sys.provider_call)(-1, kv::OPEN, arg.as_mut_ptr(), t + 12);
    if h < 0 {
        -1
    } else {
        h
    }
}

/// HMAC-SHA256 of `data` by the vault's slot `h` (`SIGN`, `RAW`).
unsafe fn vault_hmac(sys: &SyscallTable, h: i32, data: &[u8]) -> Option<[u8; 32]> {
    let mut arg = [0u8; 6 + FRAME_MAX + 64 + 12];
    if data.len() > FRAME_MAX + 64 {
        return None;
    }
    arg[0] = kv::sign_mode::RAW;
    arg[2..6].copy_from_slice(&(data.len() as u32).to_le_bytes());
    arg[6..6 + data.len()].copy_from_slice(data);
    let mut tag = [0u8; 32];
    let t = 6 + data.len();
    arg[t..t + 8].copy_from_slice(&(tag.as_mut_ptr() as u64).to_le_bytes());
    arg[t + 8..t + 10].copy_from_slice(&32u16.to_le_bytes());
    let rc = (sys.provider_call)(h, kv::SIGN, arg.as_mut_ptr(), t + 12);
    let len = u16::from_le_bytes([arg[t + 10], arg[t + 11]]);
    (rc == 0 && len == 32).then_some(tag)
}

/// The IP packet at the start of `b` (IPv4 or IPv6), cut to its own
/// length: `None` unless it is one, whole.
fn ip_packet(b: &[u8]) -> Option<&[u8]> {
    let len = match b.first()? >> 4 {
        4 if b.len() >= 20 => usize::from(u16::from_be_bytes([b[2], b[3]])),
        6 if b.len() >= 40 => 40 + usize::from(u16::from_be_bytes([b[4], b[5]])),
        _ => return None,
    };
    // IPv4's header (IHL words) lies inside the packet; IPv6's is 40 bytes.
    let min = if b[0] >> 4 == 4 {
        usize::from(b[0] & 0x0F) * 4
    } else {
        40
    };
    if min < 20 || len < min || len > b.len() {
        return None;
    }
    Some(&b[..len])
}

/// Note the first param that did not parse.
fn bad(s: &mut RtState, id: u8) {
    if s.bad_param == 0 {
        s.bad_param = id;
    }
}

mod params_def {
    use super::*;
    define_params! {
        RtState;
        1, key, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            if parse_hex(t, &mut s.key) { s.key_set = true; } else { bad(s, 1); }
        };
        2, host_id, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            if !parse_hex(t, &mut s.host_id) { bad(s, 2); }
        };
        3, service_id, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            if !parse_hex(t, &mut s.service_id) { bad(s, 3); }
        };
        4, route_gen, u32, 1 => |s, d, len| { s.route_gen = p_u32(d, len, 0, 1); };
        5, anchors, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            match parse_anchors(t, &mut s.anchor_ids, &mut s.anchor_ips, &mut s.anchor_v6) {
                Some(n) => s.anchors = n,
                None => bad(s, 5),
            }
        };
        6, serve, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            match parse_serve(t, &mut s.serve) {
                Some(n) => s.serves = n,
                None => bad(s, 6),
            }
        };
        8, key_label, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            if t.len() > kv::MAX_LABEL { bad(s, 8); return; }
            s.key_label[..t.len()].copy_from_slice(t);
            s.key_label_len = t.len() as u8;
        };
        7, mac, str, 0 => |s, d, len| {
            let Some(t) = text(d, len) else { return };
            if !parse_hex(t, &mut s.mac) { bad(s, 7); }
        };
    }
}

unsafe fn write_frame(
    sys: &SyscallTable,
    ch: i32,
    kind: u8,
    parts: &[&[u8]],
    scratch: &mut [u8],
) -> bool {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    if ch < 0 || HDR + len > scratch.len() {
        return false;
    }
    scratch[0] = kind;
    scratch[1..3].copy_from_slice(&(len as u16).to_le_bytes());
    let mut at = HDR;
    for p in parts {
        scratch[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    (sys.channel_write)(ch, scratch.as_ptr(), at) == at as i32
}

/// Bind the tunnel's port on `ip`'s datagram surface, once.
unsafe fn bind(s: &mut RtState) {
    if s.bind_sent || s.dg_out < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let port = RT_PORT.to_le_bytes();
    let mut f = [0u8; 16];
    if write_frame(sys, s.dg_out, CMD_DG_BIND, &[&port, &[0]], &mut f) {
        s.bind_sent = true;
    }
}

/// Ingress: forward records → sealed datagrams.
unsafe fn ingress(s: &mut RtState) {
    let sys = &*s.syscalls;
    for _ in 0..PER_STEP {
        if s.fwd_in < 0 || (sys.channel_peek)(s.fwd_in, s.rx.as_mut_ptr(), HDR) < HDR as i32 {
            return;
        }
        let kind = s.rx[0];
        let total = HDR + u16::from_le_bytes([s.rx[1], s.rx[2]]) as usize;
        if total > s.rx.len() {
            // Not ours to hold: skip it whole.
            let mut skip = total;
            while skip > 0 {
                let n = (sys.channel_read)(s.fwd_in, s.rx.as_mut_ptr(), skip.min(s.rx.len()));
                if n <= 0 {
                    break;
                }
                skip -= n as usize;
            }
            s.stats.capacity = s.stats.capacity.wrapping_add(1);
            continue;
        }
        if (sys.channel_peek)(s.fwd_in, s.rx.as_mut_ptr(), total) < total as i32 {
            return;
        }
        if !s.bound {
            // Wait for the bind: the record holds the stream until then.
            return;
        }
        let ok = (|| {
            // [pkt_id 4][disposition 1][args 6][frame]
            if kind != MSG_PKT_FORWARD || total < HDR + 11 + ETH_HDR + 20 {
                return Err(&mut s.stats.malformed as *mut u32);
            }
            let p = &s.rx[HDR..total];
            if p[4] & 0x7F != DISP_TUNNEL {
                return Err(&mut s.stats.not_tunnel as *mut u32);
            }
            let anchor = u16::from_le_bytes([p[5], p[6]]);
            let epoch = u32::from_le_bytes([p[7], p[8], p[9], p[10]]);
            let frame = &p[11..];
            let et = u16::from_be_bytes([frame[12], frame[13]]);
            let Some(inner) = ip_packet(&frame[ETH_HDR..]) else {
                return Err(&mut s.stats.malformed as *mut u32);
            };
            if (et == 0x0800) != (inner[0] >> 4 == 4) || !matches!(et, 0x0800 | 0x86DD) {
                return Err(&mut s.stats.malformed as *mut u32);
            }
            let Some(k) = s.anchor_ids[..s.anchors as usize]
                .iter()
                .position(|&a| a == anchor)
            else {
                return Err(&mut s.stats.no_anchor as *mut u32);
            };
            let ctx = RtContext {
                service_id: s.service_id,
                route_generation: u64::from(s.route_gen),
                flow_epoch: epoch,
                anchor_id: anchor,
                ingress_host: s.host_id,
                ingress_if: 0,
                rx_queue: 0,
            };
            let seq = s.seq + 1;
            let mut sealed = [0u8; FRAME_MAX + RT_OVERHEAD];
            let sealed_n = if s.cell_key >= 0 {
                let h = s.cell_key;
                rt_seal_mac(
                    &mut |d| vault_hmac(sys, h, d),
                    &ctx,
                    seq,
                    inner,
                    &mut sealed,
                )
            } else {
                rt_seal(&s.key, &ctx, seq, inner, &mut sealed)
            };
            let n = match sealed_n {
                Ok(n) => n,
                Err(_) => return Err(&mut s.stats.capacity as *mut u32),
            };
            s.seq = seq;
            s.stats.sealed = s.stats.sealed.wrapping_add(1);
            let port = RT_PORT.to_le_bytes();
            let a = s.anchor_ips[k];
            let sent = if s.anchor_v6[k] {
                write_frame(
                    sys,
                    s.dg_out,
                    CMD_DG_SEND_TO,
                    &[&[s.ep_id, 6], &a, &port, &sealed[..n]],
                    &mut s.tx,
                )
            } else {
                write_frame(
                    sys,
                    s.dg_out,
                    CMD_DG_SEND_TO,
                    &[&[s.ep_id, 4], &a[12..], &port, &sealed[..n]],
                    &mut s.tx,
                )
            };
            if sent {
                s.stats.sent = s.stats.sent.wrapping_add(1);
            } else {
                s.stats.capacity = s.stats.capacity.wrapping_add(1);
            }
            Ok(())
        })();
        if let Err(c) = ok {
            *c = (*c).wrapping_add(1);
        }
        (sys.channel_discard)(s.fwd_in, total);
    }
}

/// Anchor: datagrams → opened → injected frames. Also takes the bind's
/// answer.
unsafe fn anchor(s: &mut RtState) {
    let sys = &*s.syscalls;
    for _ in 0..PER_STEP {
        if s.dg_in < 0 || (sys.channel_peek)(s.dg_in, s.rx.as_mut_ptr(), HDR) < HDR as i32 {
            return;
        }
        let kind = s.rx[0];
        let total = HDR + u16::from_le_bytes([s.rx[1], s.rx[2]]) as usize;
        if total > s.rx.len() {
            let mut skip = total;
            while skip > 0 {
                let n = (sys.channel_read)(s.dg_in, s.rx.as_mut_ptr(), skip.min(s.rx.len()));
                if n <= 0 {
                    break;
                }
                skip -= n as usize;
            }
            s.stats.capacity = s.stats.capacity.wrapping_add(1);
            continue;
        }
        if (sys.channel_peek)(s.dg_in, s.rx.as_mut_ptr(), total) < total as i32 {
            return;
        }
        match kind {
            MSG_DG_BOUND if total >= HDR + 3 => {
                let port = u16::from_le_bytes([s.rx[4], s.rx[5]]);
                if port == RT_PORT {
                    s.ep_id = s.rx[3];
                    s.bound = true;
                }
            }
            // [ep_id][af=4][src 4][src_port 2][data], or af=6 with 16
            MSG_DG_RX_FROM
                if s.bound
                    && s.rx[3] == s.ep_id
                    && ((s.rx[4] == 4 && total >= HDR + 8)
                        || (s.rx[4] == 6 && total >= HDR + 20)) =>
            {
                let data_off = HDR + if s.rx[4] == 6 { 20 } else { 8 };
                let mut frame = [0u8; ETH_HDR + FRAME_MAX];
                let ok = {
                    let data = &s.rx[data_off..total];
                    let opened = if s.cell_key >= 0 {
                        let h = s.cell_key;
                        rt_open_mac(&mut |d| vault_hmac(sys, h, d), data, &mut s.windows)
                    } else {
                        rt_open(&s.key, data, &mut s.windows)
                    };
                    match opened {
                        Ok(o) => {
                            if o.ctx.service_id != s.service_id
                                || !s.serve[..s.serves as usize].contains(&o.ctx.anchor_id)
                            {
                                Err(&mut s.stats.not_served as *mut u32)
                            } else if o.inner.len() + ETH_HDR > frame.len()
                                || ip_packet(o.inner).map(<[u8]>::len) != Some(o.inner.len())
                            {
                                Err(&mut s.stats.malformed as *mut u32)
                            } else {
                                frame[0..6].copy_from_slice(&s.mac);
                                frame[6..12].copy_from_slice(&[0x02, 0x52, 0x54, 0, 0, 0x01]);
                                // The inner packet's own family.
                                let et: u16 = if o.inner[0] >> 4 == 6 { 0x86DD } else { 0x0800 };
                                frame[12..14].copy_from_slice(&et.to_be_bytes());
                                frame[ETH_HDR..ETH_HDR + o.inner.len()].copy_from_slice(o.inner);
                                s.stats.opened = s.stats.opened.wrapping_add(1);
                                Ok(ETH_HDR + o.inner.len())
                            }
                        }
                        Err(RtWhy::Tag) => Err(&mut s.stats.tag as *mut u32),
                        Err(RtWhy::Replay) => Err(&mut s.stats.replay as *mut u32),
                        Err(RtWhy::Capacity) => Err(&mut s.stats.capacity as *mut u32),
                        Err(RtWhy::Malformed) => Err(&mut s.stats.malformed as *mut u32),
                    }
                };
                match ok {
                    Ok(n) => {
                        // `[len:u16 LE][frame]`, whole, as a frame driver writes.
                        let mut out = [0u8; 2 + ETH_HDR + FRAME_MAX];
                        out[..2].copy_from_slice(&(n as u16).to_le_bytes());
                        out[2..2 + n].copy_from_slice(&frame[..n]);
                        if s.frames_out >= 0
                            && (sys.channel_write)(s.frames_out, out.as_ptr(), 2 + n)
                                == (2 + n) as i32
                        {
                            s.stats.injected = s.stats.injected.wrapping_add(1);
                        } else {
                            s.stats.capacity = s.stats.capacity.wrapping_add(1);
                        }
                    }
                    Err(c) => *c = (*c).wrapping_add(1),
                }
            }
            MSG_DG_RX_FROM => s.stats.unbound = s.stats.unbound.wrapping_add(1),
            // `[ep_id][errno]`: a sealed datagram `ip` would not send.
            MSG_DG_ERROR if total >= HDR + 2 && s.bound && s.rx[3] == s.ep_id => {
                s.stats.send_refused = s.stats.send_refused.wrapping_add(1);
            }
            _ => {}
        }
        (sys.channel_discard)(s.dg_in, total);
    }
}

unsafe fn heartbeat(s: &mut RtState) {
    let st = s.stats;
    let now = [
        st.sent,
        st.injected,
        st.tag.wrapping_add(st.replay),
        st.malformed,
        st.send_refused,
    ];
    if now == s.logged {
        return;
    }
    s.logged = now;
    let mut line = [0u8; 160];
    let mut at = 0;
    let mut num = [0u8; 10];
    for (label, v) in [
        (&b"[rescue_tunnel] sent="[..], st.sent),
        (&b" injected="[..], st.injected),
        (&b" tag="[..], st.tag),
        (&b" replay="[..], st.replay),
        (&b" not_served="[..], st.not_served),
        (&b" malformed="[..], st.malformed),
        (&b" send_refused="[..], st.send_refused),
    ] {
        line[at..at + label.len()].copy_from_slice(label);
        at += label.len();
        let k = fmt_u32_raw(num.as_mut_ptr(), v);
        line[at..at + k].copy_from_slice(&num[..k]);
        at += k;
    }
    dev_log(&*s.syscalls, 3, line.as_ptr(), at);
}

declare_module_state_bytes!(RtState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<RtState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, `params`
/// the config TLV blob.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -22;
    }
    if state_size < core::mem::size_of::<RtState>() {
        return -6;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<RtState>());
    let s = &mut *(state as *mut RtState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.fwd_in = in_chan;
    s.dg_out = out_chan;
    s.dg_in = dev_channel_port(sys, 0, 1);
    s.frames_out = dev_channel_port(sys, 1, 1);
    s.route_gen = 1;
    s.windows = RtWindows::new();
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    s.cell_key = -1;
    if s.bad_param == 0 && s.key_label_len != 0 {
        s.cell_key = open_cell_key(sys, &s.key_label[..usize::from(s.key_label_len)]);
        if s.cell_key < 0 {
            let m = b"[rescue_tunnel] refusing to construct: no HMAC-SHA256 key under key_label in this vault";
            dev_log(sys, 1, m.as_ptr(), m.len());
            return -22;
        }
        s.key_set = true;
    }
    if s.bad_param != 0 || !s.key_set {
        // Which param: key 1, host_id 2, service_id 3, anchors 5, serve 6,
        // mac 7, key_label 8 (0: key missing).
        let mut m =
            *b"[rescue_tunnel] refusing to construct: key (64 hex) required; param 0 did not parse";
        let at = m.len() - 15;
        m[at] = b'0' + s.bad_param % 10;
        dev_log(sys, 1, m.as_ptr(), m.len());
        return -22;
    }
    if s.anchors != 0 && s.host_id == [0; 8] {
        // The anchor keeps one window per ingress host: two ingress hosts
        // under one identity would refuse each other's packets as replays.
        let m = b"[rescue_tunnel] refusing to construct: an ingress (anchors) needs its host_id";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return -22;
    }
    // Above anything an earlier run of this host can have sent (see the
    // module docs): wall-clock milliseconds, 2^20 sequence numbers each.
    s.seq = dev_unix_millis(sys) << 20;
    if s.seq == 0 && s.anchors != 0 {
        let m = b"[rescue_tunnel] no real-time clock: after a restart the anchor refuses this host's packets until its window is reset";
        dev_log(sys, 2, m.as_ptr(), m.len());
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut RtState);
    s.step_count = s.step_count.wrapping_add(1);
    bind(s);
    anchor(s);
    ingress(s);
    if s.step_count.is_multiple_of(LOG_PERIOD) {
        heartbeat(s);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_arena_size() -> u32 {
    0
}
