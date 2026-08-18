//! OTA registry puller — pull a graph image from an OCI distribution
//! registry and activate it through the kernel OTA staging surface.
//!
//! See manifest.toml for the wiring (net pair through `tls` in client
//! mode) and the per-attempt sequence. The module is a straight-line
//! state machine: manifest GET → epoch gate → blob GET (streamed into
//! `OTA_STAGE_WRITE` under an incremental SHA-256) → digest check →
//! `OTA_STAGE_CTRL` COMMIT. One TCP connection per request
//! (`Connection: close`), exponential backoff on any failure, and an
//! optional re-poll interval for long-running graphs.
//!
//! HTTP subset: HTTP/1.1 responses framed by `Content-Length` (what the
//! nanocloud registry serves). A chunked response is treated as an
//! error and logged — not silently mis-read.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::too_many_arguments,
    reason = "fluxor module ABI: raw-pointer entry points are the contract and ABI fns carry a fixed arity"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::internal::reconfigure::{OTA_STAGE_CTRL, OTA_STAGE_WRITE};
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/crypto/sha384.rs");
include!("../../sdk/crypto/hmac.rs");
include!("../../sdk/crypto/p256.rs");
include!("../../sdk/crypto/ed25519.rs");

// ── net_proto vocabulary (contracts/net/net_proto.rs) ────────────────

const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;

// ── OTA_STAGE_CTRL commands (internal/reconfigure.rs) ────────────────

const CTRL_COMMIT: u8 = 0;
const CTRL_ABORT: u8 = 1;
const CTRL_EPOCH: u8 = 2;

// ── Sizing ───────────────────────────────────────────────────────────

/// One MSG_DATA fragment (net_proto MAX_CMD_DATA) + conn id + header.
const NET_BUF_SIZE: usize = 3 + 2 + 8192;
/// HTTP response header accumulator.
const HDR_BUF_SIZE: usize = 2048;
/// Whole-manifest buffer. A layered image manifest carries one layer
/// object (~250 bytes) per fmod plus skeleton/config — ~10 KB for a
/// 30-module graph.
const MANIFEST_BUF_SIZE: usize = 16384;
/// Layer table capacity (skeleton + fmods + config).
const MAX_LAYERS: usize = 48;
/// Directive record: `[0x44][counter u64 LE][tag_len u8][tag][sig 64]`,
/// Ed25519 over `counter_le ‖ tag` (rfc_oci_distribution.md §7.2).
const DIRECTIVE_MAGIC: u8 = 0x44;
const PORT_IN_DIRECTIVE: u32 = 1;
/// Request builder.
const TX_BUF_SIZE: usize = 512;
/// `OTA_STAGE_WRITE` arg: 4-byte offset prefix + one fragment.
const STAGE_ARG_SIZE: usize = 4 + 8192;

const MAX_HOST_LEN: usize = 64;
const MAX_REPO_LEN: usize = 64;
const MAX_TAG_LEN: usize = 32;

const CONNECT_TIMEOUT_MS: u64 = 10_000;
const RESPONSE_TIMEOUT_MS: u64 = 30_000;
const BACKOFF_INIT_MS: u64 = 2_000;
const BACKOFF_MAX_MS: u64 = 60_000;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// Waiting out the boot delay (DHCP / TLS bring-up).
    Init = 0,
    /// CMD_CONNECT queued for the current request.
    Connecting = 1,
    /// Waiting for MSG_CONNECTED with our requester tag.
    WaitConnect = 2,
    /// Request bytes queued; response header not complete yet.
    RecvHeader = 3,
    /// Response body streaming (manifest buffer or stage writes).
    RecvBody = 4,
    /// Waiting for the next poll interval (or parked when poll_s = 0).
    Idle = 5,
    /// Waiting out a failure backoff, then restart from the manifest.
    Backoff = 6,
}

/// Which request the connection is carrying.
const FETCH_MANIFEST: u8 = 0;
const FETCH_BLOB: u8 = 1;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    net_in: i32,
    net_out: i32,

    // Params.
    registry_ip: u32,
    registry_port: u16,
    poll_s: u16,
    boot_delay_ms: u32,
    /// 0 = fetch the whole blob per connection; N = fetch N-byte Range
    /// chunks, one connection each. Bounds how much a single transport
    /// failure can cost, and keeps each transfer under stream-length
    /// limits of constrained bearers.
    chunk_bytes: u32,
    host: [u8; MAX_HOST_LEN],
    host_len: u8,
    repo: [u8; MAX_REPO_LEN],
    repo_len: u8,
    tag: [u8; MAX_TAG_LEN],
    tag_len: u8,

    phase: Phase,
    fetching: u8,
    conn_id: u16,
    /// The previously used conn id: late MSG_ERROR events from a
    /// connection we already finished with must not abort the current
    /// request (they cost a needless backoff + manifest refetch per
    /// chunk on the chunked path).
    prev_conn_id: u16,
    conn_present: u8,
    started: u8,

    state_start_ms: u64,
    backoff_ms: u64,
    next_poll_ms: u64,

    // HTTP response parsing.
    hdr_fill: u32,
    content_length: u32,
    body_received: u32,

    // Manifest results. `layers_count == 0` after a parse means the
    // packed (single-blob) form: `blob_digest`/`blob_size` describe it.
    // Layered form: per-layer digest/size/offset tables, fetched in
    // offset order; `layer_idx`/`intra_offset` are the fetch cursor.
    manifest_fill: u32,
    image_epoch: u64,
    blob_size: u32,
    blob_digest: [u8; 32],
    layers_count: u16,
    layer_idx: u16,
    intra_offset: u32,
    layer_size: [u32; MAX_LAYERS],
    layer_offset: [u32; MAX_LAYERS],
    layer_digest: [[u8; 32]; MAX_LAYERS],

    // Directive port (index 1, optional): signed tag re-point /
    // check-now commands. `directive_counter` is the anti-replay
    // watermark (module state; see the RFC's recorded limitation).
    directive_chan: i32,
    directive_ready: u8,
    directive_counter: u64,
    directive_pubkey: [u8; 32],
    directive_pubkey_len: u8,

    // Blob staging. `resume_offset` carries staged progress across
    // failed attempts (the AEAD layer guarantees every staged byte is
    // authentic server data, and the final digest seals the whole
    // image); the hasher persists with it. Both reset when the
    // manifest's blob digest changes between attempts.
    stage_offset: u32,
    resume_offset: u32,
    last_blob_digest: [u8; 32],
    hasher: Sha256,

    // TX request in flight.
    tx_len: u16,
    tx_sent: u16,

    hdr_buf: [u8; HDR_BUF_SIZE],
    manifest_buf: [u8; MANIFEST_BUF_SIZE],
    tx_buf: [u8; TX_BUF_SIZE],
    net_buf: [u8; NET_BUF_SIZE],
    stage_arg: [u8; STAGE_ARG_SIZE],
}

mod params_def {
    use super::ptr_copy;
    use super::p_u16;
    use super::p_u32;
    use super::State;
    use super::SCHEMA_MAX;
    use super::{MAX_HOST_LEN, MAX_REPO_LEN, MAX_TAG_LEN};

    define_params! {
        State;

        1, registry_ip, u32, 0
            => |s, d, len| { s.registry_ip = p_u32(d, len, 0, 0); };

        2, registry_port, u16, 5000
            => |s, d, len| { s.registry_port = p_u16(d, len, 0, 5000); };

        3, host, str, 0
            => |s, d, len| {
                let n = if len > MAX_HOST_LEN { MAX_HOST_LEN } else { len };
                s.host_len = n as u8;
                if n > 0 { ptr_copy(s.host.as_mut_ptr(), d, n); }
            };

        4, repo, str, 0
            => |s, d, len| {
                let n = if len > MAX_REPO_LEN { MAX_REPO_LEN } else { len };
                s.repo_len = n as u8;
                if n > 0 { ptr_copy(s.repo.as_mut_ptr(), d, n); }
            };

        5, tag, str, 0
            => |s, d, len| {
                let n = if len > MAX_TAG_LEN { MAX_TAG_LEN } else { len };
                s.tag_len = n as u8;
                if n > 0 { ptr_copy(s.tag.as_mut_ptr(), d, n); }
            };

        6, poll_s, u16, 0
            => |s, d, len| { s.poll_s = p_u16(d, len, 0, 0); };

        7, boot_delay_ms, u32, 2000
            => |s, d, len| { s.boot_delay_ms = p_u32(d, len, 0, 2000); };

        8, chunk_bytes, u32, 0
            => |s, d, len| { s.chunk_bytes = p_u32(d, len, 0, 0); };

        9, directive_pubkey, str, 0
            => |s, d, len| {
                // 64 hex chars -> 32-byte Ed25519 public key.
                if len == 64 {
                    let mut ok = true;
                    let mut i = 0;
                    while i < 32 {
                        let hi = super::hex_nibble(unsafe { *d.add(i * 2) });
                        let lo = super::hex_nibble(unsafe { *d.add(i * 2 + 1) });
                        match (hi, lo) {
                            (Some(h), Some(l)) => s.directive_pubkey[i] = (h << 4) | l,
                            _ => { ok = false; break; }
                        }
                        i += 1;
                    }
                    s.directive_pubkey_len = if ok { 32 } else { 0 };
                }
            };
    }
}

/// Resolve an extra input port by index via the `channel::PORT` opcode.
/// Returns -1 if unwired.
unsafe fn channel_port_in(sys: &SyscallTable, index: u32) -> i32 {
    let mut arg = [0u8, index as u8]; // 0 = in
    (sys.provider_call)(-1, abi::kernel_abi::channel::PORT, arg.as_mut_ptr(), arg.len())
}

#[inline(always)]
unsafe fn ptr_copy(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

#[inline(always)]
unsafe fn log_msg(s: &State, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

#[inline(always)]
unsafe fn log_err(s: &State, msg: &[u8]) {
    dev_log(&*s.syscalls, 1, msg.as_ptr(), msg.len());
}

/// Log a message with one appended decimal number (bounded formatter —
/// no core::fmt in the PIC hot path).
unsafe fn log_msg_num(s: &State, msg: &[u8], num: u64) {
    let mut buf = [0u8; 96];
    let n = msg.len().min(72);
    buf[..n].copy_from_slice(&msg[..n]);
    let mut digits = [0u8; 20];
    let mut v = num;
    let mut d = 0;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
        if v == 0 {
            break;
        }
    }
    let mut o = n;
    while d > 0 {
        d -= 1;
        buf[o] = digits[d];
        o += 1;
    }
    dev_log(&*s.syscalls, 3, buf.as_ptr(), o);
}

// ── Small helpers ────────────────────────────────────────────────────

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() - needle.len() {
        return None;
    }
    let mut i = from;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse an unsigned decimal starting at `at`; returns (value, digits).
fn parse_dec(b: &[u8], at: usize) -> (u64, usize) {
    let mut v: u64 = 0;
    let mut i = at;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((b[i] - b'0') as u64);
        i += 1;
    }
    (v, i - at)
}

/// One hex nibble (lowercase or uppercase digit set of the CA/pubkey
/// params).
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse 64 lowercase hex chars at `at` into `out`.
fn parse_hex32(b: &[u8], at: usize, out: &mut [u8; 32]) -> bool {
    if at + 64 > b.len() {
        return false;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < 32 {
        let (hi, lo) = (nib(b[at + i * 2]), nib(b[at + i * 2 + 1]));
        match (hi, lo) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return false,
        }
        i += 1;
    }
    true
}

// ── State machine ────────────────────────────────────────────────────

unsafe fn enter_backoff(s: &mut State) {
    let sys = &*s.syscalls;
    if s.conn_present == 1 {
        let mut payload = [0u8; 2];
        payload[..2].copy_from_slice(&s.conn_id.to_le_bytes());
        let _ = net_write_frame(
            sys,
            s.net_out,
            NET_CMD_CLOSE,
            payload.as_ptr(),
            2,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        s.prev_conn_id = s.conn_id;
        s.conn_present = 0;
    }
    if s.fetching == FETCH_BLOB && s.stage_offset > 0 {
        // Keep the staged prefix; the next attempt resumes with a
        // Range request instead of refetching from zero. A resumed
        // retry only refetches the remainder, so it stays on the
        // short flat backoff instead of the exponential ramp — the
        // ramp is for failures that make no progress.
        s.resume_offset = s.stage_offset;
        log_msg_num(s, b"[ota_reg] will resume blob at ", s.stage_offset as u64);
        s.backoff_ms = BACKOFF_INIT_MS;
    } else {
        s.backoff_ms = if s.backoff_ms == 0 {
            BACKOFF_INIT_MS
        } else {
            (s.backoff_ms * 2).min(BACKOFF_MAX_MS)
        };
    }
    s.state_start_ms = dev_millis(sys);
    s.phase = Phase::Backoff;
}

/// Reset per-request parse state and queue the CMD_CONNECT.
unsafe fn start_request(s: &mut State, fetching: u8) {
    s.fetching = fetching;
    s.hdr_fill = 0;
    s.content_length = 0;
    s.body_received = 0;
    s.tx_len = 0;
    s.tx_sent = 0;
    s.conn_present = 0;
    if fetching == FETCH_MANIFEST {
        s.manifest_fill = 0;
    } else if s.resume_offset > 0 && s.blob_digest == s.last_blob_digest {
        // Resume a partially staged image: the kernel staging buffer
        // still holds `resume_offset` verified-prefix bytes and the
        // hasher matches them (packed: whole image; layered: the
        // in-flight layer, from `intra_offset`).
        s.stage_offset = s.resume_offset;
    } else {
        s.stage_offset = 0;
        s.resume_offset = 0;
        s.layer_idx = 0;
        s.intra_offset = 0;
        s.hasher = Sha256::new();
        if s.layers_count > 0 {
            // First write must land at the first layer's offset (0 =
            // the skeleton, which also resets the kernel stage).
            s.stage_offset = s.layer_offset[0];
        }
    }
    s.last_blob_digest = s.blob_digest;
    s.phase = Phase::Connecting;
}

/// The blob digest the CURRENT fetch requests: the in-flight layer's
/// (layered) or the whole image's (packed).
unsafe fn cur_fetch_digest(s: &State) -> [u8; 32] {
    if s.layers_count > 0 {
        s.layer_digest[s.layer_idx as usize]
    } else {
        s.blob_digest
    }
}

/// Size of the current fetch unit (layer or whole blob).
unsafe fn cur_fetch_size(s: &State) -> u32 {
    if s.layers_count > 0 {
        s.layer_size[s.layer_idx as usize]
    } else {
        s.blob_size
    }
}

/// Progress within the current fetch unit.
unsafe fn cur_fetch_pos(s: &State) -> u32 {
    if s.layers_count > 0 {
        s.intra_offset
    } else {
        s.stage_offset
    }
}

/// Build the GET request for the current fetch into tx_buf.
unsafe fn build_request(s: &mut State) -> usize {
    let mut o = 0usize;
    let mut put = |s: &mut State, bytes: &[u8]| {
        let n = bytes.len().min(TX_BUF_SIZE - o);
        s.tx_buf[o..o + n].copy_from_slice(&bytes[..n]);
        o += n;
    };
    put(s, b"GET /v2/");
    let repo_len = s.repo_len as usize;
    let repo = s.repo;
    put(s, &repo[..repo_len]);
    if s.fetching == FETCH_MANIFEST {
        put(s, b"/manifests/");
        let tag_len = s.tag_len as usize;
        let tag = s.tag;
        put(s, &tag[..tag_len]);
    } else {
        put(s, b"/blobs/sha256:");
        let digest = cur_fetch_digest(s);
        let mut hex = [0u8; 64];
        let mut i = 0;
        while i < 32 {
            const H: &[u8; 16] = b"0123456789abcdef";
            hex[i * 2] = H[(digest[i] >> 4) as usize];
            hex[i * 2 + 1] = H[(digest[i] & 0x0F) as usize];
            i += 1;
        }
        put(s, &hex);
    }
    put(s, b" HTTP/1.1\r\nHost: ");
    let host_len = s.host_len as usize;
    let host = s.host;
    put(s, &host[..host_len]);
    if s.fetching == FETCH_MANIFEST {
        put(s, b"\r\nAccept: application/vnd.oci.image.manifest.v1+json");
    } else if cur_fetch_pos(s) > 0 || s.chunk_bytes > 0 {
        // Resume and/or chunked fetch: a bounded range WITHIN the
        // current fetch unit (a layer, or the packed image).
        put(s, b"\r\nRange: bytes=");
        let mut v = cur_fetch_pos(s);
        let mut digits = [0u8; 10];
        let mut d = 0;
        loop {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
            if v == 0 {
                break;
            }
        }
        while d > 0 {
            d -= 1;
            put(s, &[digits[d]]);
        }
        put(s, b"-");
        if s.chunk_bytes > 0 {
            let end = (cur_fetch_pos(s) + s.chunk_bytes).min(cur_fetch_size(s)) - 1;
            let mut v = end;
            let mut d = 0;
            loop {
                digits[d] = b'0' + (v % 10) as u8;
                v /= 10;
                d += 1;
                if v == 0 {
                    break;
                }
            }
            while d > 0 {
                d -= 1;
                put(s, &[digits[d]]);
            }
        }
    }
    put(s, b"\r\nConnection: close\r\n\r\n");
    o
}

/// Flush pending request bytes as CMD_SEND frames. Returns true when
/// everything is sent.
unsafe fn flush_tx(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    while s.tx_sent < s.tx_len {
        let remaining = (s.tx_len - s.tx_sent) as usize;
        let chunk = remaining.min(1024);
        let mut payload = [0u8; 2 + 1024];
        payload[..2].copy_from_slice(&s.conn_id.to_le_bytes());
        payload[2..2 + chunk]
            .copy_from_slice(&s.tx_buf[s.tx_sent as usize..s.tx_sent as usize + chunk]);
        let wrote = net_write_frame(
            sys,
            s.net_out,
            NET_CMD_SEND,
            payload.as_ptr(),
            2 + chunk,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        if wrote == 0 {
            return false; // backpressure; retry next step
        }
        s.tx_sent += chunk as u16;
    }
    true
}

/// Extract image-layer digest/size + epoch annotation from the manifest.
unsafe fn parse_manifest(s: &mut State) -> bool {
    // Layered form first (rfc_oci_distribution.md §7.1): a skeleton
    // layer marks it. Layers appear in JSON in publisher order =
    // ascending offset; each carries digest, size and the
    // `io.fluxor.image.offset` annotation. Field order within a layer
    // object is fixed by our own serializer (mediaType, digest, size,
    // annotations), so a sequential scan is sound.
    s.layers_count = 0;
    {
        // Copy out of self to scan while mutating the tables.
        let fill = s.manifest_fill as usize;
        if find(&s.manifest_buf[..fill], b"image.skeleton", 0).is_some() {
            let mut pos = match find(&s.manifest_buf[..fill], b"\"layers\"", 0) {
                Some(p) => p,
                None => return false,
            };
            let mut n = 0usize;
            loop {
                let m2 = &s.manifest_buf[..fill];
                let dkey = b"\"digest\":\"sha256:";
                let d_at = match find(m2, dkey, pos) {
                    Some(p) => p + dkey.len(),
                    None => break,
                };
                let mut digest = [0u8; 32];
                if !parse_hex32(m2, d_at, &mut digest) {
                    log_err(s, b"[ota_reg] layered manifest: bad digest");
                    return false;
                }
                let skey = b"\"size\":";
                let (size, ndig) = match find(m2, skey, d_at) {
                    Some(p) => parse_dec(m2, p + skey.len()),
                    None => (0, 0),
                };
                let okey = b"\"io.fluxor.image.offset\":\"";
                let (off, odig) = match find(m2, okey, d_at) {
                    Some(p) => parse_dec(m2, p + okey.len()),
                    None => (0, 0),
                };
                if ndig == 0 || odig == 0 || n >= MAX_LAYERS {
                    log_err(s, b"[ota_reg] layered manifest: layer table overflow/short");
                    return false;
                }
                s.layer_digest[n] = digest;
                s.layer_size[n] = size as u32;
                s.layer_offset[n] = off as u32;
                n += 1;
                pos = d_at + 64;
            }
            if n < 2 {
                log_err(s, b"[ota_reg] layered manifest: too few layers");
                return false;
            }
            s.layers_count = n as u16;
            // Change detector for resume: the skeleton digest.
            s.blob_digest = s.layer_digest[0];
            // Total assembled size = last layer's end (layers are in
            // offset order).
            s.blob_size = s.layer_offset[n - 1] + s.layer_size[n - 1];
            let ekey = b"\"io.fluxor.image.epoch\":\"";
            let m2 = &s.manifest_buf[..fill];
            s.image_epoch = match find(m2, ekey, 0) {
                Some(p) => parse_dec(m2, p + ekey.len()).0,
                None => 0,
            };
            log_msg_num(s, b"[ota_reg] layered manifest, layers ", n as u64);
            return true;
        }
    }
    let m = &s.manifest_buf[..s.manifest_fill as usize];
    // The image layer: our own publisher orders Descriptor fields
    // mediaType, digest, size — so the digest/size following the image
    // media type belong to that layer.
    let at = match find(m, b"application/vnd.nanocloud.fluxor.image.v1", 0) {
        // Skip the artifactType occurrence (it precedes `config`); take
        // the LAST occurrence, which is the layer's own mediaType.
        Some(first) => {
            let mut last = first;
            let mut from = first + 1;
            while let Some(next) = find(m, b"application/vnd.nanocloud.fluxor.image.v1", from) {
                last = next;
                from = next + 1;
            }
            last
        }
        None => {
            log_err(s, b"[ota_reg] manifest has no image layer");
            return false;
        }
    };
    let dkey = b"\"digest\":\"sha256:";
    let d_at = match find(m, dkey, at) {
        Some(p) => p + dkey.len(),
        None => {
            log_err(s, b"[ota_reg] image layer digest missing");
            return false;
        }
    };
    let mut digest = [0u8; 32];
    if !parse_hex32(m, d_at, &mut digest) {
        log_err(s, b"[ota_reg] image layer digest malformed");
        return false;
    }
    s.blob_digest = digest;
    let skey = b"\"size\":";
    let (size, ndig) = match find(m, skey, d_at) {
        Some(p) => parse_dec(m, p + skey.len()),
        None => (0, 0),
    };
    if ndig == 0 || size == 0 {
        log_err(s, b"[ota_reg] image layer size missing");
        return false;
    }
    s.blob_size = size as u32;
    // Epoch annotation (manifest-level).
    let ekey = b"\"io.fluxor.image.epoch\":\"";
    s.image_epoch = match find(m, ekey, 0) {
        Some(p) => parse_dec(m, p + ekey.len()).0,
        None => 0,
    };
    true
}

/// Response-header completion: parse status + Content-Length. Returns
/// false on any refusal (caller backs off).
unsafe fn parse_response_header(s: &mut State, header_end: usize) -> bool {
    let h = &s.hdr_buf[..header_end];
    // Status line: "HTTP/1.1 NNN ..."
    let (status, _) = if h.len() > 9 {
        parse_dec(h, 9)
    } else {
        (0, 0)
    };
    let resumed =
        s.fetching == FETCH_BLOB && (cur_fetch_pos(s) > 0 || s.chunk_bytes > 0);
    let ok_status = if resumed { 206 } else { 200 };
    if status != ok_status {
        // A server that ignores Range answers 200 with the full body;
        // restart the current unit from zero rather than mis-append.
        if resumed && status == 200 && s.layers_count == 0 {
            s.stage_offset = 0;
            s.resume_offset = 0;
            s.hasher = Sha256::new();
        } else {
            log_msg_num(s, b"[ota_reg] http status ", status);
            return false;
        }
    }
    // Case-insensitive Content-Length scan.
    let mut cl: u64 = 0;
    let mut have_cl = false;
    let mut i = 0;
    while i + 16 <= h.len() {
        if h[i] == b'\n' {
            let line = &h[i + 1..];
            if line.len() >= 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
                let mut j = 15;
                while j < line.len() && line[j] == b' ' {
                    j += 1;
                }
                let (v, n) = parse_dec(line, j);
                if n > 0 {
                    cl = v;
                    have_cl = true;
                }
            }
            if line.len() >= 18 && line[..18].eq_ignore_ascii_case(b"transfer-encoding:") {
                log_err(s, b"[ota_reg] chunked response unsupported");
                return false;
            }
        }
        i += 1;
    }
    if !have_cl {
        log_err(s, b"[ota_reg] response missing content-length");
        return false;
    }
    let cap = if s.fetching == FETCH_MANIFEST {
        MANIFEST_BUF_SIZE as u64
    } else {
        // Stage capacity bound is enforced kernel-side too.
        8 * 1024 * 1024
    };
    if cl == 0 || cl > cap {
        log_msg_num(s, b"[ota_reg] bad content-length ", cl);
        return false;
    }
    if s.fetching == FETCH_BLOB {
        let mut expect = cur_fetch_size(s) - cur_fetch_pos(s);
        if s.chunk_bytes > 0 && s.chunk_bytes < expect {
            expect = s.chunk_bytes;
        }
        if cl != expect as u64 {
            log_err(s, b"[ota_reg] blob size mismatch vs manifest");
            return false;
        }
    }
    s.content_length = cl as u32;
    true
}

/// Feed `data` into the current body sink (manifest buffer or the
/// staging surface + hasher). Returns false on a hard failure.
unsafe fn body_bytes(s: &mut State, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    if s.fetching == FETCH_MANIFEST {
        let fill = s.manifest_fill as usize;
        let n = data.len().min(MANIFEST_BUF_SIZE - fill);
        s.manifest_buf[fill..fill + n].copy_from_slice(&data[..n]);
        s.manifest_fill += n as u32;
    } else {
        let sys = &*s.syscalls;
        s.hasher.update(data);
        let mut off = 0usize;
        while off < data.len() {
            let chunk = (data.len() - off).min(STAGE_ARG_SIZE - 4);
            s.stage_arg[..4].copy_from_slice(&s.stage_offset.to_le_bytes());
            s.stage_arg[4..4 + chunk].copy_from_slice(&data[off..off + chunk]);
            let rc = (sys.provider_call)(
                -1,
                OTA_STAGE_WRITE,
                s.stage_arg.as_mut_ptr(),
                4 + chunk,
            );
            if rc < 0 {
                log_msg_num(s, b"[ota_reg] stage write failed rc=-", (-rc) as u64);
                return false;
            }
            s.stage_offset += chunk as u32;
            off += chunk;
        }
        s.intra_offset += data.len() as u32;
    }
    s.body_received += data.len() as u32;
    true
}

/// The current request's body is complete — advance the pipeline.
/// Returns false to enter backoff.
unsafe fn body_complete(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    // The request cycle is over (Connection: close): close our side so
    // the ip conn slot is reclaimed rather than parking in CloseWait —
    // a long retry run would otherwise exhaust the conn table.
    if s.conn_present == 1 {
        let mut payload = [0u8; 2];
        payload[..2].copy_from_slice(&s.conn_id.to_le_bytes());
        let _ = net_write_frame(
            sys,
            s.net_out,
            NET_CMD_CLOSE,
            payload.as_ptr(),
            2,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        s.prev_conn_id = s.conn_id;
        s.conn_present = 0;
    }
    if s.fetching == FETCH_MANIFEST {
        if !parse_manifest(s) {
            return false;
        }
        // Epoch gate: fetch the blob only when it is newer than live.
        let mut cmd = [CTRL_EPOCH];
        let live = (sys.provider_call)(-1, OTA_STAGE_CTRL, cmd.as_mut_ptr(), 1);
        if live >= 0 && s.image_epoch <= live as u64 && live > 0 {
            log_msg_num(s, b"[ota_reg] up to date at epoch ", live as u64);
            s.phase = Phase::Idle;
            s.next_poll_ms = dev_millis(sys) + (s.poll_s as u64) * 1000;
            return true;
        }
        log_msg_num(s, b"[ota_reg] manifest ok; image epoch ", s.image_epoch);
        start_request(s, FETCH_BLOB);
        true
    } else {
        // More of the CURRENT unit (layer or packed image) remains —
        // chain the next chunk immediately (progress, not failure).
        if cur_fetch_pos(s) < cur_fetch_size(s) {
            s.resume_offset = s.stage_offset;
            s.backoff_ms = 0;
            log_msg_num(s, b"[ota_reg] blob progress ", s.stage_offset as u64);
            start_request(s, FETCH_BLOB);
            return true;
        }
        if s.layers_count > 0 {
            // Layer complete: verify ITS digest (transfer-time
            // integrity per layer; the kernel still verifies the
            // whole assembled image at commit).
            let digest = s.hasher.clone().finalize();
            if digest[..] != s.layer_digest[s.layer_idx as usize][..] {
                log_err(s, b"[ota_reg] layer sha256 mismatch; restarting layer");
                s.intra_offset = 0;
                s.stage_offset = s.layer_offset[s.layer_idx as usize];
                s.hasher = Sha256::new();
                return false;
            }
            if (s.layer_idx as usize) < s.layers_count as usize - 1 {
                s.layer_idx += 1;
                s.intra_offset = 0;
                s.hasher = Sha256::new();
                s.stage_offset = s.layer_offset[s.layer_idx as usize];
                s.resume_offset = s.stage_offset;
                s.backoff_ms = 0;
                log_msg_num(s, b"[ota_reg] layer done, next ", s.layer_idx as u64);
                start_request(s, FETCH_BLOB);
                return true;
            }
            // Last layer landed: the assembled image is complete.
            s.resume_offset = 0;
        } else {
            // Packed image complete: verify the manifest digest.
            s.resume_offset = 0;
            let digest = s.hasher.clone().finalize();
            if digest[..] != s.blob_digest[..] {
                log_err(s, b"[ota_reg] blob sha256 mismatch; discarding");
                let mut cmd = [CTRL_ABORT];
                let _ = (sys.provider_call)(-1, OTA_STAGE_CTRL, cmd.as_mut_ptr(), 1);
                return false;
            }
        }
        let mut cmd = [CTRL_COMMIT];
        let rc = (sys.provider_call)(-1, OTA_STAGE_CTRL, cmd.as_mut_ptr(), 1);
        if rc == 0 {
            log_msg_num(s, b"[ota_reg] committed image epoch ", s.image_epoch);
            s.backoff_ms = 0;
            s.phase = Phase::Idle;
            s.next_poll_ms = dev_millis(sys) + (s.poll_s as u64) * 1000;
            true
        } else if rc == E_BUSY {
            log_msg(s, b"[ota_reg] image already live (epoch not newer)");
            s.phase = Phase::Idle;
            s.next_poll_ms = dev_millis(sys) + (s.poll_s as u64) * 1000;
            true
        } else {
            log_msg_num(s, b"[ota_reg] commit refused rc=-", (-rc) as u64);
            false
        }
    }
}

/// Drain one inbound net frame. Returns false when nothing was read.
unsafe fn pump_net(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    if s.net_in < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(s.net_in, POLL_IN);
    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
        return false;
    }
    let nbuf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, s.net_in, nbuf, NET_BUF_SIZE);
    if msg_type == 0 {
        return false;
    }
    let payload = core::slice::from_raw_parts(nbuf.add(3), payload_len);
    match msg_type {
        NET_MSG_CONNECTED => {
            // [conn_id: u16][requester_tag: u8]
            if s.phase == Phase::WaitConnect && payload_len >= 2 {
                let tag = if payload_len >= 3 { payload[2] } else { 0 };
                if tag == 0 || tag == dev_requester_tag(sys) {
                    s.conn_id = u16::from_le_bytes([payload[0], payload[1]]);
                    s.conn_present = 1;
                    let len = build_request(s);
                    s.tx_len = len as u16;
                    s.tx_sent = 0;
                    s.state_start_ms = dev_millis(sys);
                    s.phase = Phase::RecvHeader;
                    let _ = flush_tx(s);
                }
            }
        }
        NET_MSG_DATA => {
            if payload_len < 2 {
                return true;
            }
            let cid = u16::from_le_bytes([payload[0], payload[1]]);
            if s.conn_present == 0 || cid != s.conn_id {
                return true;
            }
            let mut data = &payload[2..];
            if s.phase == Phase::RecvHeader {
                // Accumulate into hdr_buf until CRLFCRLF.
                let fill = s.hdr_fill as usize;
                let n = data.len().min(HDR_BUF_SIZE - fill);
                s.hdr_buf[fill..fill + n].copy_from_slice(&data[..n]);
                s.hdr_fill += n as u32;
                let have = &s.hdr_buf[..s.hdr_fill as usize];
                if let Some(hdr_end) = find(have, b"\r\n\r\n", 0) {
                    if !parse_response_header(s, hdr_end) {
                        enter_backoff(s);
                        return true;
                    }
                    s.phase = Phase::RecvBody;
                    // Bytes past the header in the accumulator are body.
                    let body_in_hdr_start = hdr_end + 4;
                    let body_in_hdr_len = s.hdr_fill as usize - body_in_hdr_start;
                    if body_in_hdr_len > 0 {
                        let mut tmp = [0u8; HDR_BUF_SIZE];
                        tmp[..body_in_hdr_len].copy_from_slice(
                            &s.hdr_buf[body_in_hdr_start..s.hdr_fill as usize],
                        );
                        if !body_bytes(s, &tmp[..body_in_hdr_len]) {
                            enter_backoff(s);
                            return true;
                        }
                    }
                    // Any remaining bytes of THIS frame beyond what went
                    // into hdr_buf are also body.
                    if n < data.len() {
                        data = &data[n..];
                        let mut tmp = [0u8; 8192];
                        let m = data.len().min(8192);
                        tmp[..m].copy_from_slice(&data[..m]);
                        if !body_bytes(s, &tmp[..m]) {
                            enter_backoff(s);
                            return true;
                        }
                    }
                    if s.body_received >= s.content_length && !body_complete(s) {
                        enter_backoff(s);
                    }
                } else if s.hdr_fill as usize >= HDR_BUF_SIZE {
                    log_err(s, b"[ota_reg] oversized response header");
                    enter_backoff(s);
                }
            } else if s.phase == Phase::RecvBody {
                let remaining = (s.content_length - s.body_received) as usize;
                let take = data.len().min(remaining);
                let mut tmp = [0u8; 8192];
                let m = take.min(8192);
                tmp[..m].copy_from_slice(&data[..m]);
                if !body_bytes(s, &tmp[..m]) {
                    enter_backoff(s);
                    return true;
                }
                if s.body_received >= s.content_length && !body_complete(s) {
                    enter_backoff(s);
                }
            }
        }
        NET_MSG_CLOSED => {
            if payload_len >= 2 {
                let cid = u16::from_le_bytes([payload[0], payload[1]]);
                if s.conn_present == 1 && cid == s.conn_id {
                    s.conn_present = 0;
                    // A close mid-transfer is a failure; a close after
                    // completion (Idle / next request already started)
                    // is the server honouring Connection: close.
                    if s.phase == Phase::RecvHeader || s.phase == Phase::RecvBody {
                        log_err(s, b"[ota_reg] connection closed mid-response");
                        enter_backoff(s);
                    }
                }
            }
        }
        NET_MSG_ERROR => {
            // Payload: [conn_id u16][errno][tag]. Claim only errors for
            // the CURRENT connection (established) or a connect-phase
            // failure that isn't a late event from the previous conn.
            let cid = if payload_len >= 2 {
                u16::from_le_bytes([payload[0], payload[1]])
            } else {
                0
            };
            let stale = payload_len >= 2 && cid == s.prev_conn_id && cid != s.conn_id;
            if (s.conn_present == 1 && cid == s.conn_id)
                || (s.phase == Phase::WaitConnect && !stale)
            {
                log_err(s, b"[ota_reg] net error");
                enter_backoff(s);
            }
        }
        _ => {}
    }
    true
}

/// Drain the optional directive port: signed tag re-point / check-now
/// records (rfc_oci_distribution.md §7.2). Silently drops anything
/// that fails shape, signature, or the anti-replay counter — a
/// directive channel is untrusted input by definition.
unsafe fn pump_directives(s: &mut State) {
    let sys = &*s.syscalls;
    if s.directive_ready == 0 {
        s.directive_chan = channel_port_in(sys, PORT_IN_DIRECTIVE);
        s.directive_ready = 1;
    }
    if s.directive_chan < 0 || s.directive_pubkey_len != 32 {
        return;
    }
    let mut drained = 0;
    while drained < 4 {
        drained += 1;
        let poll = (sys.channel_poll)(s.directive_chan, POLL_IN);
        if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
            return;
        }
        // FMP-style frame: [type u8][len u16 LE][payload]. Accept the
        // payload as the raw directive record.
        let mut hdr = [0u8; 3];
        if (sys.channel_read)(s.directive_chan, hdr.as_mut_ptr(), 3) < 3 {
            return;
        }
        let len = u16::from_le_bytes([hdr[1], hdr[2]]) as usize;
        let mut rec = [0u8; 256];
        if len == 0 || len > rec.len() {
            // Drain and drop an oversized frame to stay aligned.
            let mut left = len;
            while left > 0 {
                let take = left.min(rec.len());
                (sys.channel_read)(s.directive_chan, rec.as_mut_ptr(), take);
                left -= take;
            }
            continue;
        }
        if ((sys.channel_read)(s.directive_chan, rec.as_mut_ptr(), len) as usize) < len {
            return;
        }
        // Record: [0x44][counter u64 LE][tag_len u8][tag][sig 64].
        if len < 1 + 8 + 1 + 1 + 64 || rec[0] != DIRECTIVE_MAGIC {
            continue;
        }
        let counter = u64::from_le_bytes(rec[1..9].try_into().unwrap());
        let tag_len = rec[9] as usize;
        if tag_len == 0 || tag_len > MAX_TAG_LEN || 10 + tag_len + 64 != len {
            continue;
        }
        let msg_end = 10 + tag_len;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&rec[msg_end..msg_end + 64]);
        if counter <= s.directive_counter {
            log_msg(s, b"[ota_reg] directive replayed; ignored");
            continue;
        }
        // Signed message is `counter_le ‖ tag` (the framing length byte
        // is transport, not signed content).
        let mut msg = [0u8; 8 + MAX_TAG_LEN];
        msg[..8].copy_from_slice(&rec[1..9]);
        msg[8..8 + tag_len].copy_from_slice(&rec[10..10 + tag_len]);
        if !ed25519_verify(&s.directive_pubkey, &msg[..8 + tag_len], &sig) {
            log_err(s, b"[ota_reg] directive signature invalid");
            continue;
        }
        s.directive_counter = counter;
        s.tag[..tag_len].copy_from_slice(&rec[10..10 + tag_len]);
        s.tag_len = tag_len as u8;
        log_msg(s, b"[ota_reg] directive accepted; checking now");
        // Fresh pull cycle against the (possibly new) tag.
        s.backoff_ms = 0;
        start_request(s, FETCH_MANIFEST);
    }
}

unsafe fn pump(s: &mut State) -> i32 {
    let sys = &*s.syscalls;
    pump_directives(s);
    // Drain inbound frames first (bounded per step). The bound covers a
    // whole burst of decrypted-record frames from the TLS module's step
    // (its cipher ring is 16 KiB), so the clear ring never backs up
    // during the blob stream.
    let mut drained = 0;
    while drained < 64 && pump_net(s) {
        drained += 1;
    }
    match s.phase {
        Phase::Init => {
            if dev_millis(sys) >= s.boot_delay_ms as u64 {
                log_msg(s, b"[ota_reg] starting pull");
                start_request(s, FETCH_MANIFEST);
            }
            0
        }
        Phase::Connecting => {
            if s.net_out < 0 {
                return 0;
            }
            let mut payload = [0u8; 8];
            payload[0] = SOCK_TYPE_STREAM;
            payload[1..5].copy_from_slice(&s.registry_ip.to_le_bytes());
            payload[5..7].copy_from_slice(&s.registry_port.to_le_bytes());
            payload[7] = dev_requester_tag(sys);
            let wrote = net_write_frame(
                sys,
                s.net_out,
                NET_CMD_CONNECT,
                payload.as_ptr(),
                8,
                s.net_buf.as_mut_ptr(),
                NET_BUF_SIZE,
            );
            if wrote > 0 {
                s.state_start_ms = dev_millis(sys);
                s.phase = Phase::WaitConnect;
            }
            0
        }
        Phase::WaitConnect => {
            if dev_millis(sys).wrapping_sub(s.state_start_ms) > CONNECT_TIMEOUT_MS {
                log_err(s, b"[ota_reg] connect timeout");
                enter_backoff(s);
            }
            0
        }
        Phase::RecvHeader | Phase::RecvBody => {
            if s.tx_sent < s.tx_len {
                let _ = flush_tx(s);
            }
            if dev_millis(sys).wrapping_sub(s.state_start_ms) > RESPONSE_TIMEOUT_MS {
                log_err(s, b"[ota_reg] response timeout");
                enter_backoff(s);
            }
            0
        }
        Phase::Idle => {
            if s.poll_s > 0 && dev_millis(sys) >= s.next_poll_ms {
                start_request(s, FETCH_MANIFEST);
            }
            0
        }
        Phase::Backoff => {
            if dev_millis(sys).wrapping_sub(s.state_start_ms) >= s.backoff_ms {
                start_request(s, FETCH_MANIFEST);
            }
            0
        }
    }
}

// ── Module ABI entry points ──────────────────────────────────────────

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        s.syscalls = syscalls as *const SyscallTable;
        s.net_in = in_chan;
        s.net_out = out_chan;
        s.phase = Phase::Init;
        s.directive_chan = -1;
        s.hasher = Sha256::new();
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
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
        pump(s)
    }
}
