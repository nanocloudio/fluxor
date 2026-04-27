//! HTTP/2 connection state machine — server side, h2c (cleartext) and
//! h2-over-TLS (ALPN).
//!
//! Drives one TCP/TLS connection through the h2 lifecycle: SETTINGS
//! exchange, HEADERS / DATA / control-frame processing, response
//! emission. The matching route is looked up against the existing
//! `ServerState.routes` table so the same YAML config that drives h1
//! routes drives h2.
//!
//! # Scope
//!
//! - up to `MAX_STREAMS` (4) concurrent client streams. Streams beyond
//!   the limit are refused with REFUSED_STREAM.
//! - `HANDLER_STATIC`, `HANDLER_TEMPLATE` (inline + file-cached), and
//!   `HANDLER_FILE` are streamed via `Sub::SendingBody`. Each tick
//!   advances one slot's emission round-robin via `emit_cursor` so
//!   multiple streams' HEADERS and DATA frames interleave on the wire.
//!   `file_chan` and the body cache are guarded by a single
//!   `file_owner` mutex; only one HANDLER_FILE / cache-fetch slot runs
//!   at a time, while inline streams continue to interleave alongside.
//! - `HANDLER_WEBSOCKET`: extended CONNECT (RFC 8441) is accepted —
//!   the server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`,
//!   replies `:status = 200`, and from then on tunnels RFC 6455 frames
//!   inside DATA frames in both directions. WS frames may span multiple
//!   DATA frames; payloads accumulate in `H2State.ws_buf` and a drain
//!   loop pops complete frames as they appear. Frames larger than
//!   `WS_BUF_SIZE` close with 1009 (Message Too Big). At most one WS
//!   stream per connection (the buffer is shared).
//! - GET / POST / PUT / PATCH / DELETE / HEAD; request bodies are
//!   discarded (the static / template / file handlers don't read them).
//! - flow control: connection- and stream-level recv windows refilled
//!   via WINDOW_UPDATE when they cross `RECV_WINDOW_THRESHOLD`; DATA
//!   emission caps each chunk by `min(conn_send_window, stream_send_window)`
//!   and honours peer-sent SETTINGS_INITIAL_WINDOW_SIZE adjustments.
//! - no Huffman string compression on either side.
//! - no PUSH (`SETTINGS_ENABLE_PUSH = 0`).
//! - no CONTINUATION; HEADERS frames must carry END_HEADERS.
//! - frames whose declared length exceeds `RECV_BUF_SIZE` are refused
//!   with `GOAWAY(FRAME_SIZE_ERROR)`.

use super::connection::{NET_BUF_SIZE, NET_CMD_SEND};
use super::server::{
    HANDLER_FILE, HANDLER_STATIC, HANDLER_TEMPLATE, HANDLER_WEBSOCKET, MAX_PATH, RECV_BUF_SIZE,
    SEND_BUF_SIZE,
};

/// Per-stream WebSocket reassembly buffer. Cross-DATA-frame WS frames
/// land here until a complete RFC 6455 frame can be parsed and echoed.
/// Bound matches the largest WS frame the server is willing to handle;
/// frames that don't fit close with 1009 (Message Too Big).
const WS_BUF_SIZE: usize = 512;

/// Maximum concurrent client-initiated streams. Advertised in our
/// SETTINGS frame. Sized for the embedded memory budget; bump the
/// constant if `H2State` can absorb additional slots.
pub(crate) const MAX_STREAMS: usize = 4;

/// Initial connection-level recv window — RFC 7540 §6.9.2 default.
const RECV_WINDOW_INITIAL: i32 = 65535;
/// Below this, we proactively send WINDOW_UPDATE to refill so peer
/// keeps streaming. Picked at half the initial window to leave a
/// generous in-flight buffer.
const RECV_WINDOW_THRESHOLD: i32 = 32768;
/// Initial conn-level + per-stream send window — RFC 7540 §6.9.2
/// default. Adjusted by peer SETTINGS_INITIAL_WINDOW_SIZE (per-stream)
/// or peer WINDOW_UPDATE deltas.
const SEND_WINDOW_INITIAL: i32 = 65535;
use super::wire_h2 as h2w;
use super::wire_ws as ws;
use super::HttpState;
use super::{
    dev_channel_ioctl, dev_log, net_write_frame, IOCTL_FLUSH, IOCTL_NOTIFY, IOCTL_POLL_NOTIFY,
    NET_FRAME_HDR,
};

// ── Sub-state within `Phase::H2Active` ────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Sub {
    /// Send our initial SETTINGS frame.
    SendSettings = 0,
    /// Frame loop: read frames from `recv_buf`, dispatch, queue
    /// responses into `send_buf`.
    Active = 1,
    /// At least one slot is mid-response. Each tick drives one cache
    /// fetch step (if any slot is `Fetching`) and emits one DATA / HEADERS
    /// frame for the next round-robin Sending slot.
    SendingBody = 2,
    /// Drain a queued GOAWAY then close.
    Closing = 3,
}

/// Per-stream slot state. Each `StreamSlot` tracks one concurrent
/// client-initiated stream; the connection serializes body emission
/// (only one slot at a time can fill `send_buf`).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SlotState {
    /// Slot is unused (`id == 0`).
    Idle = 0,
    /// HEADERS arrived; awaiting END_STREAM via DATA frames.
    Open = 1,
    /// Request fully received; waiting for an emitter slot to free up.
    Pending = 2,
    /// Currently the active sender. `Sub::SendingBody` operates on
    /// this slot; only one slot in this state at any time.
    Sending = 3,
    /// Cache fetch in progress for this slot; only one slot in this
    /// state at any time.
    Fetching = 4,
    /// Upgraded to WebSocket-over-h2; DATA frames carry WS frames.
    WsActive = 5,
}

#[repr(C)]
pub(crate) struct StreamSlot {
    pub(crate) id: u32,
    pub(crate) state: SlotState,
    /// 1 = body-less (GET/HEAD), 2 = extended CONNECT, 3 = body-bearing
    /// (POST/PUT/PATCH/DELETE).
    pub(crate) method_kind: u8,
    pub(crate) end_stream_in: u8,
    pub(crate) req_path_len: u8,
    /// 1 = a per-stream WINDOW_UPDATE owes peer, queued by the active
    /// loop the next time `send_buf` is free.
    pub(crate) window_update_pending: u8,
    /// Per-slot rendering state. Set by `dispatch_request`; consumed
    /// lazily by the round-robin emitter in `step_sending_body`.
    pub(crate) headers_sent: u8,
    pub(crate) body_handler: u8,
    pub(crate) matched_route: i8,
    pub(crate) file_index: i16,
    pub(crate) tmpl_pos: u16,
    /// Stream-level recv flow-control window (RFC 7540 §6.9.1). Starts
    /// at 65535; decremented as peer sends DATA on this stream;
    /// refilled with a per-stream WINDOW_UPDATE when low.
    pub(crate) recv_window: i32,
    /// Stream-level send flow-control window. Starts at peer's
    /// SETTINGS_INITIAL_WINDOW_SIZE (default 65535); decremented as
    /// we emit DATA on this stream; bumped by peer's per-stream
    /// WINDOW_UPDATE.
    pub(crate) send_window: i32,
    pub(crate) req_path: [u8; MAX_PATH],
}

impl StreamSlot {
    pub(crate) const fn zeroed() -> Self {
        Self {
            id: 0,
            state: SlotState::Idle,
            method_kind: 0,
            end_stream_in: 0,
            req_path_len: 0,
            window_update_pending: 0,
            headers_sent: 0,
            body_handler: 0,
            matched_route: -1,
            file_index: -1,
            tmpl_pos: 0,
            recv_window: RECV_WINDOW_INITIAL,
            send_window: SEND_WINDOW_INITIAL,
            req_path: [0; MAX_PATH],
        }
    }
}

#[repr(C)]
pub(crate) struct H2State {
    pub(crate) sub: Sub,
    pub(crate) settings_acked: u8,
    /// Round-robin cursor: index of the slot that emitted the most
    /// recent frame. `step_sending_body` advances this each tick to
    /// pick the next Sending slot.
    pub(crate) emit_cursor: i8,
    /// Index of the slot currently using `file_chan` /
    /// `body_pool` cache fetch. Only one such slot can be Sending at
    /// a time; other file/cache slots stay Pending.
    pub(crate) file_owner: i8,
    pub(crate) last_stream_id: u32,
    pub(crate) ws_active: u8, // 1 when any slot is WsActive (capped at one)
    /// 1 if a WINDOW_UPDATE frame should be queued as soon as
    /// `send_buf` is free again. See `recv_window` below.
    pub(crate) window_update_pending: u8,
    pub(crate) ws_buf_len: u16,
    pub(crate) ws_stream_id: u32,
    /// Connection-level recv flow-control window (RFC 7540 §6.9.1).
    /// Decremented as peer's DATA frames arrive; refilled with
    /// WINDOW_UPDATE when it crosses the threshold.
    pub(crate) recv_window: i32,
    /// Connection-level send flow-control window (RFC 7540 §6.9.1).
    /// Decremented as we emit DATA across all streams; bumped by
    /// peer's connection-level WINDOW_UPDATE (stream_id == 0).
    pub(crate) send_window: i32,
    /// Most-recent value of peer's SETTINGS_INITIAL_WINDOW_SIZE;
    /// changes here adjust every open stream's `send_window` by the
    /// delta (RFC 7540 §6.9.2).
    pub(crate) peer_initial_window_size: i32,
    pub(crate) streams: [StreamSlot; MAX_STREAMS],
    /// WebSocket reassembly buffer. Shared across the (at most one)
    /// WS-active stream. RFC 6455 frames may span multiple h2 DATA
    /// frames; raw payloads accumulate here until parsed and echoed.
    pub(crate) ws_buf: [u8; WS_BUF_SIZE],
}

impl H2State {
    pub(crate) const fn zeroed() -> Self {
        const SLOT: StreamSlot = StreamSlot::zeroed();
        Self {
            sub: Sub::SendSettings,
            settings_acked: 0,
            emit_cursor: -1,
            file_owner: -1,
            last_stream_id: 0,
            ws_active: 0,
            window_update_pending: 0,
            ws_buf_len: 0,
            ws_stream_id: 0,
            recv_window: RECV_WINDOW_INITIAL,
            send_window: SEND_WINDOW_INITIAL,
            peer_initial_window_size: SEND_WINDOW_INITIAL,
            streams: [SLOT; MAX_STREAMS],
            ws_buf: [0; WS_BUF_SIZE],
        }
    }
}

// ── Stream-slot lookup helpers ────────────────────────────────────────────

/// Return the index into `streams` whose `id` matches, or `-1`.
unsafe fn slot_for_id(s: &HttpState, id: u32) -> i8 {
    if id == 0 {
        return -1;
    }
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
        if slot.id == id && slot.state != SlotState::Idle {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Allocate an Idle slot for a new stream id. Returns `-1` if the table
/// is full (caller should respond REFUSED_STREAM).
unsafe fn alloc_slot(s: &mut HttpState, id: u32) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *s.server.h2.streams.as_mut_ptr().add(i as usize);
        if slot.state == SlotState::Idle {
            slot.id = id;
            slot.state = SlotState::Open;
            slot.method_kind = 0;
            slot.end_stream_in = 0;
            slot.req_path_len = 0;
            slot.window_update_pending = 0;
            slot.recv_window = RECV_WINDOW_INITIAL;
            // Each new stream inherits peer's most-recent advertised
            // initial window size (default 65535).
            slot.send_window = s.server.h2.peer_initial_window_size;
            return i as i8;
        }
        i += 1;
    }
    -1
}

unsafe fn free_slot(s: &mut HttpState, idx: i8) {
    if idx < 0 {
        return;
    }
    let slot = &mut *s.server.h2.streams.as_mut_ptr().add(idx as usize);
    slot.id = 0;
    slot.state = SlotState::Idle;
}

/// Find any Pending slot — caller has just finished emitting a body
/// and wants to start the next one. Returns `-1` if none.
unsafe fn find_pending_slot(s: &HttpState) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Pending {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// True when at least one slot is currently in the Sending state.
unsafe fn any_sending_slot(s: &HttpState) -> bool {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Sending {
            return true;
        }
        i += 1;
    }
    false
}

/// Returns the slot index currently doing a cache fetch, or `-1`. At
/// most one slot can be in this state — the `file_owner` mutex
/// enforces serialisation across HANDLER_FILE / cache-fetch handlers.
unsafe fn fetching_slot(s: &HttpState) -> i8 {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
        if slot.state == SlotState::Fetching {
            return i as i8;
        }
        i += 1;
    }
    -1
}

/// Drive one tick of the cache fetch loop for the slot currently
/// holding `file_owner`. Bridges into `arm_slot_for_emission` once the
/// fetch completes so the same emission round-robin picks the slot up.
/// Returns true if `send_buf` got new bytes (caller should yield to
/// flush them).
unsafe fn drive_cache_fetch(s: &mut HttpState) -> bool {
    use super::server::{cache_fetch_step, CacheStepResult};
    let slot_idx = fetching_slot(s);
    if slot_idx < 0 {
        return false;
    }
    match cache_fetch_step(s) {
        CacheStepResult::Pending => false,
        CacheStepResult::Ready => {
            let handler =
                (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).body_handler;
            let matched =
                (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).matched_route;
            arm_slot_for_emission(s, slot_idx, handler, -1, matched);
            false
        }
        CacheStepResult::Error => {
            let stream_id = (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).id;
            emit_response(s, stream_id, b"500", b"text/plain", b"cache fetch failed\n");
            free_slot(s, slot_idx);
            s.server.h2.file_owner = -1;
            true
        }
    }
}

// ── Public entry from server.rs ───────────────────────────────────────────

pub(crate) unsafe fn enter(s: &mut HttpState) {
    s.server.h2 = H2State::zeroed();
    s.server.send_offset = 0;
    s.server.send_len = 0;
    log(s, b"[http] h2c connection upgraded");
}

/// Drive one tick of the h2 state machine. Mirrors the server.rs step
/// contract: returns 0 normally, 1 to indicate "done — close
/// connection", -1 on hard error.
pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    // Always try to flush pending outbound bytes first.
    if s.server.send_len > 0 && s.server.send_offset < s.server.send_len {
        let remaining = (s.server.send_len - s.server.send_offset) as usize;
        let sent = net_send(
            s,
            s.server.send_buf.as_ptr().add(s.server.send_offset as usize),
            remaining,
        );
        if sent > 0 {
            s.server.send_offset += sent as u16;
        }
        if s.server.send_offset < s.server.send_len {
            return 0;
        }
        s.server.send_offset = 0;
        s.server.send_len = 0;
        if s.server.h2.sub == Sub::Closing {
            return 1;
        }
    }

    match s.server.h2.sub {
        Sub::SendSettings => {
            let n = h2w::write_settings(
                s.server.send_buf.as_mut_ptr(),
                &[
                    (h2w::SETTINGS_ENABLE_PUSH, 0),
                    (h2w::SETTINGS_MAX_CONCURRENT_STREAMS, MAX_STREAMS as u32),
                    (h2w::SETTINGS_HEADER_TABLE_SIZE, 0),
                    (h2w::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
                ],
            );
            s.server.send_len = n as u16;
            s.server.h2.sub = Sub::Active;
            return 0;
        }
        Sub::Active => return active(s),
        Sub::SendingBody => return step_sending_body(s),
        Sub::Closing => {
            // Pending GOAWAY already drained by the flush above.
            return 1;
        }
    }
}

// ── Body streaming substate ───────────────────────────────────────────────

unsafe fn step_sending_body(s: &mut HttpState) -> i32 {
    // Drive any in-progress cache fetch first. Reads from `file_chan`
    // never touch `send_buf`, so a fetch tick happens regardless of
    // whether we have outbound bytes still draining. If the fetch
    // completes mid-call the slot transitions to Sending and is
    // picked up by the round-robin below in the same tick.
    if drive_cache_fetch(s) && s.server.send_len > 0 {
        return 2;
    }

    if s.server.send_len > 0 {
        return 0;
    }

    // Pick the next Sending slot via round-robin starting just after
    // `emit_cursor`. Each call emits at most one frame, so multiple
    // Sending slots interleave their HEADERS / DATA on the wire.
    let n = MAX_STREAMS;
    let cursor_start = ((s.server.h2.emit_cursor as i32 + 1).max(0) as usize) % n;
    let mut emit_idx: i8 = -1;
    for offset in 0..n {
        let i = (cursor_start + offset) % n;
        let slot = &*s.server.h2.streams.as_ptr().add(i);
        if slot.state == SlotState::Sending {
            emit_idx = i as i8;
            break;
        }
    }

    if emit_idx < 0 {
        // No more Sending slots. If a Fetching slot is still in flight
        // we stay in `Sub::SendingBody` so its `cache_fetch_step`
        // keeps ticking; otherwise fall back to Active to pick up
        // Pending slots / inbound frames.
        if fetching_slot(s) >= 0 {
            return 0;
        }
        s.server.h2.sub = Sub::Active;
        s.server.h2.emit_cursor = -1;
        try_dispatch_pending(s);
        if s.server.send_len > 0 {
            return 2;
        }
        return 0;
    }

    s.server.h2.emit_cursor = emit_idx;
    let slot_ptr = s.server.h2.streams.as_ptr().add(emit_idx as usize);
    let slot_id = (*slot_ptr).id;
    let body_handler = (*slot_ptr).body_handler;
    let headers_sent = (*slot_ptr).headers_sent;
    let stream_send_window = (*slot_ptr).send_window;
    let slot_matched = (*slot_ptr).matched_route;
    let slot_tmpl_pos = (*slot_ptr).tmpl_pos;
    let slot_file_index = (*slot_ptr).file_index;

    if headers_sent == 0 {
        emit_slot_headers(s, emit_idx, body_handler, slot_file_index, slot_id);
        let slot_mut = &mut *s.server.h2.streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.headers_sent = 1;
        return 2;
    }

    // Render a DATA chunk for this slot. Cap by send_window.
    let mut avail = s.server.h2.send_window.min(stream_send_window);
    if avail <= 0 {
        // Drain incoming frames so a queued WINDOW_UPDATE bumps our
        // windows. If we ack/queue something, exit and flush.
        while pump_inbound(s) {
            loop {
                match peek_frame_complete(s) {
                    FrameStatus::Complete => {}
                    FrameStatus::NeedMore => break,
                    FrameStatus::TooBig => {
                        queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
                        return 2;
                    }
                }
                if process_one_frame(s) < 0 {
                    return 0;
                }
                if s.server.send_len > 0 {
                    return 2;
                }
            }
        }
        let refreshed_stream =
            (*s.server.h2.streams.as_ptr().add(emit_idx as usize)).send_window;
        avail = s.server.h2.send_window.min(refreshed_stream);
        if avail <= 0 {
            return 0;
        }
    }

    // Swap in slot's render state for the renderer to consume.
    s.server.matched_route = slot_matched;
    s.server.tmpl_pos = slot_tmpl_pos;
    s.server.file_index = slot_file_index;

    let buf = s.server.send_buf.as_mut_ptr();
    let dst = buf.add(h2w::FRAME_HEADER_LEN);
    let raw_cap = SEND_BUF_SIZE - h2w::FRAME_HEADER_LEN;
    let dst_cap = raw_cap.min(avail as usize);

    let (n, more) = match body_handler {
        HANDLER_STATIC => super::server::render_static_into(s, dst, dst_cap),
        HANDLER_TEMPLATE => super::server::render_template_into(s, dst, dst_cap),
        HANDLER_FILE => {
            if slot_file_index < 0 {
                super::server::render_index_into(s, dst, dst_cap)
            } else {
                super::server::render_file_into(s, dst, dst_cap)
            }
        }
        _ => (0, false),
    };

    // Save updated render state back into the slot.
    {
        let slot_mut = &mut *s.server.h2.streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.tmpl_pos = s.server.tmpl_pos;
    }

    if n == 0 && more {
        return 0;
    }

    h2w::write_data_frame_header(buf, n, slot_id, !more);
    s.server.send_len = (h2w::FRAME_HEADER_LEN + n) as u16;
    s.server.send_offset = 0;
    s.server.h2.send_window = s.server.h2.send_window.saturating_sub(n as i32);
    if more {
        let slot_mut = &mut *s.server.h2.streams.as_mut_ptr().add(emit_idx as usize);
        slot_mut.send_window = slot_mut.send_window.saturating_sub(n as i32);
    } else {
        // END_STREAM emitted — release the slot now so a peer can
        // open a fresh stream in this position before we tick again.
        let was_owner = s.server.h2.file_owner == emit_idx;
        free_slot(s, emit_idx);
        if was_owner {
            s.server.h2.file_owner = -1;
        }
    }
    2
}

/// Lazy HEADERS emission for a slot. Picks the appropriate
/// content-type from the handler kind / file_index. Status code is
/// always 200 — error responses go through `emit_response` (single
/// HEADERS+DATA frame) and never reach the streaming path.
unsafe fn emit_slot_headers(
    s: &mut HttpState,
    _slot_idx: i8,
    body_handler: u8,
    file_index: i16,
    stream_id: u32,
) {
    let content_type: &[u8] = match body_handler {
        HANDLER_STATIC | HANDLER_TEMPLATE => b"text/html",
        HANDLER_FILE => {
            if file_index < 0 {
                b"text/plain"
            } else {
                b"application/octet-stream"
            }
        }
        _ => b"text/plain",
    };

    let buf = s.server.send_buf.as_mut_ptr();
    let cap = SEND_BUF_SIZE;
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;
    o += super::hpack::encode_header(buf.add(o), cap - o, b":status", b"200");
    o += super::hpack::encode_header(buf.add(o), cap - o, b"content-type", content_type);
    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);
    s.server.send_len = o as u16;
    s.server.send_offset = 0;
}

// ── Active loop ───────────────────────────────────────────────────────────

unsafe fn active(s: &mut HttpState) -> i32 {
    // Refill recv flow-control windows first: if we owe peer a
    // connection-level OR per-stream WINDOW_UPDATE and `send_buf` is
    // free, emit one before anything else so the peer keeps streaming.
    // `queue_window_update` emits at most one frame per call; the
    // active loop comes back here on subsequent ticks to drain the
    // rest of the queue.
    if s.server.send_len == 0
        && (s.server.h2.window_update_pending != 0 || any_stream_window_pending(s))
    {
        queue_window_update(s);
        if s.server.send_len > 0 {
            return 2;
        }
    }

    // If we left a partial WS frame queue from a previous tick, try to
    // drain another frame now that send_buf is free again.
    if s.server.h2.ws_active != 0 && s.server.send_len == 0 && s.server.h2.ws_buf_len > 0 {
        ws_drain_buf(s);
        if s.server.send_len > 0 {
            return 2;
        }
    }

    // Pull more bytes from the wire if we don't have a full frame yet.
    match peek_frame_complete(s) {
        FrameStatus::NeedMore => {
            if !pump_inbound(s) {
                return 0;
            }
        }
        FrameStatus::TooBig => {
            queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
            return 2;
        }
        FrameStatus::Complete => {}
    }

    loop {
        match peek_frame_complete(s) {
            FrameStatus::Complete => {}
            FrameStatus::NeedMore => break,
            FrameStatus::TooBig => {
                queue_goaway(s, h2w::ERR_FRAME_SIZE_ERROR);
                return 2;
            }
        }
        if process_one_frame(s) < 0 {
            return 0;
        }
        if s.server.send_len > 0 {
            return 2;
        }
    }
    0
}

enum FrameStatus {
    Complete,
    NeedMore,
    /// Peer announced a frame larger than `recv_buf` can hold. Caller
    /// should respond with GOAWAY(FRAME_SIZE_ERROR) and close — RFC
    /// 7540 §4.2 lets a receiver bound the maximum frame size below
    /// the spec default by emitting a connection error.
    TooBig,
}

unsafe fn peek_frame_complete(s: &HttpState) -> FrameStatus {
    let len = s.server.recv_len as usize;
    let hdr = match h2w::parse_header(s.server.recv_buf.as_ptr(), len) {
        Some(h) => h,
        None => return FrameStatus::NeedMore,
    };
    let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
    if total > RECV_BUF_SIZE {
        return FrameStatus::TooBig;
    }
    if total > len {
        FrameStatus::NeedMore
    } else {
        FrameStatus::Complete
    }
}

/// Read one MSG_DATA frame from `net_in` and append the contents to
/// `recv_buf`. Returns true if any progress was made. Backs off (no
/// `channel_read`) when `recv_buf` doesn't have worst-case headroom
/// for the next message — peer naturally stalls when our channel
/// queue fills, providing real flow control instead of GOAWAY.
unsafe fn pump_inbound(s: &mut HttpState) -> bool {
    use super::connection::{NET_MSG_CLOSED, NET_MSG_DATA};
    use super::{net_read_frame, POLL_IN};

    if s.net_in_chan < 0 {
        return false;
    }

    // Worst-case payload for a single MSG_DATA is (NET_BUF_SIZE - 4
    // (msg header) - 1 (conn_id)). Refuse to pump if recv_buf can't
    // hold it; the channel will backpressure linux_net and ultimately
    // the TCP peer.
    let worst_case = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    if s.server.recv_len as usize + worst_case > RECV_BUF_SIZE {
        return false;
    }

    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    let poll = (sys.channel_poll)(chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return false;
    }

    let buf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
    if msg_type == NET_MSG_CLOSED {
        // Peer closed mid-connection; abort.
        s.server.h2.sub = Sub::Closing;
        return true;
    }
    if msg_type != NET_MSG_DATA || payload_len < 1 {
        return false;
    }

    let data_ptr = s.net_buf.as_ptr().add(NET_FRAME_HDR + 1);
    let data_len = payload_len - 1;
    let space = RECV_BUF_SIZE - s.server.recv_len as usize;
    let to_copy = data_len.min(space);
    if to_copy > 0 {
        let dst = s.server.recv_buf.as_mut_ptr().add(s.server.recv_len as usize);
        core::ptr::copy_nonoverlapping(data_ptr, dst, to_copy);
        s.server.recv_len += to_copy as u16;
    }
    // The headroom check above guarantees `data_len <= space`, so any
    // truncation would be an upstream framing bug rather than a flow
    // control issue.
    true
}

/// Process exactly one complete frame from the head of `recv_buf` and
/// shift the remainder. Returns 0 normally, -1 if a connection-level
/// error has been queued (caller should drain and close).
unsafe fn process_one_frame(s: &mut HttpState) -> i32 {
    let len = s.server.recv_len as usize;
    let hdr = match h2w::parse_header(s.server.recv_buf.as_ptr(), len) {
        Some(h) => h,
        None => return 0, // peek_frame_complete already verified completeness
    };
    let total = h2w::FRAME_HEADER_LEN + hdr.length as usize;
    let payload_ptr = s.server.recv_buf.as_ptr().add(h2w::FRAME_HEADER_LEN);
    let stream_id = hdr.stream_id;

    let result = match hdr.ftype {
        h2w::FRAME_SETTINGS => handle_settings(s, &hdr, payload_ptr),
        h2w::FRAME_PING => handle_ping(s, &hdr, payload_ptr),
        h2w::FRAME_HEADERS => handle_headers(s, &hdr, payload_ptr),
        h2w::FRAME_DATA => handle_data(s, &hdr, payload_ptr),
        h2w::FRAME_WINDOW_UPDATE => handle_window_update(s, &hdr, payload_ptr),
        h2w::FRAME_PRIORITY => Ok(()),      // ignored — no priority enforcement
        h2w::FRAME_RST_STREAM => {
            let idx = slot_for_id(s, stream_id);
            if idx >= 0 {
                let slot_state = (*s.server.h2.streams.as_ptr().add(idx as usize)).state;
                if s.server.h2.file_owner == idx {
                    s.server.h2.file_owner = -1;
                }
                if slot_state == SlotState::WsActive {
                    s.server.h2.ws_active = 0;
                    s.server.h2.ws_buf_len = 0;
                    s.server.h2.ws_stream_id = 0;
                }
                free_slot(s, idx);
                // If no Sending or Fetching slots remain, fall back
                // to Active so the loop picks up Pending or new
                // inbound work. A surviving Fetching slot keeps us in
                // `SendingBody` so `drive_cache_fetch` keeps ticking.
                if !any_sending_slot(s) && fetching_slot(s) < 0 {
                    s.server.h2.sub = Sub::Active;
                    s.server.h2.emit_cursor = -1;
                }
            }
            Ok(())
        }
        h2w::FRAME_GOAWAY => {
            // Peer is closing; drain remaining frames then close.
            s.server.h2.sub = Sub::Closing;
            Ok(())
        }
        h2w::FRAME_PUSH_PROMISE => Err(h2w::ERR_PROTOCOL_ERROR),
        h2w::FRAME_CONTINUATION => Err(h2w::ERR_PROTOCOL_ERROR), // we cap headers at one frame
        _ => Ok(()), // unknown frame types are ignored per §5.5
    };

    // Shift consumed bytes off the front of recv_buf.
    let leftover = len - total;
    if leftover > 0 {
        let p = s.server.recv_buf.as_mut_ptr();
        let mut i = 0;
        while i < leftover {
            *p.add(i) = *p.add(total + i);
            i += 1;
        }
    }
    s.server.recv_len = leftover as u16;

    if let Err(code) = result {
        queue_goaway(s, code);
        return -1;
    }
    0
}

// ── Per-frame handlers ────────────────────────────────────────────────────

unsafe fn handle_settings(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) -> Result<(), u32> {
    if hdr.stream_id != 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_ACK) != 0 {
        if hdr.length != 0 {
            return Err(h2w::ERR_FRAME_SIZE_ERROR);
        }
        s.server.h2.settings_acked = 1;
        return Ok(());
    }
    if hdr.length % 6 != 0 {
        return Err(h2w::ERR_FRAME_SIZE_ERROR);
    }
    // Walk SETTINGS payload (each entry: 2-byte id, 4-byte value).
    // We honor SETTINGS_INITIAL_WINDOW_SIZE so per-stream send_window
    // adjustments stay correct; other settings are tolerated as ack.
    let mut i = 0usize;
    let total = hdr.length as usize;
    while i + 6 <= total {
        let id = ((*payload.add(i) as u16) << 8) | (*payload.add(i + 1) as u16);
        let val = ((*payload.add(i + 2) as u32) << 24)
            | ((*payload.add(i + 3) as u32) << 16)
            | ((*payload.add(i + 4) as u32) << 8)
            | (*payload.add(i + 5) as u32);
        if id == h2w::SETTINGS_INITIAL_WINDOW_SIZE {
            // Per RFC 7540 §6.9.2: must fit in i32 (≤ 2^31-1).
            if val > 0x7FFF_FFFF {
                return Err(h2w::ERR_FLOW_CONTROL_ERROR);
            }
            apply_initial_window_size(s, val as i32);
        }
        i += 6;
    }
    let n = h2w::write_settings_ack(s.server.send_buf.as_mut_ptr());
    s.server.send_len = n as u16;
    s.server.send_offset = 0;
    Ok(())
}

/// Apply a new SETTINGS_INITIAL_WINDOW_SIZE: bump every open stream's
/// `send_window` by the delta between old and new (RFC 7540 §6.9.2).
unsafe fn apply_initial_window_size(s: &mut HttpState, new_val: i32) {
    let old_val = s.server.h2.peer_initial_window_size;
    let delta = (new_val as i64) - (old_val as i64);
    s.server.h2.peer_initial_window_size = new_val;
    if delta == 0 {
        return;
    }
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *s.server.h2.streams.as_mut_ptr().add(i as usize);
        if slot.id != 0 && slot.state != SlotState::Idle {
            // Saturate to i32 range to avoid overflow if peer sends
            // back-to-back wild SETTINGS values.
            let new_w = (slot.send_window as i64).saturating_add(delta);
            slot.send_window = new_w.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        }
        i += 1;
    }
}

/// Apply a WINDOW_UPDATE: bumps connection-level `send_window` (when
/// `stream_id == 0`) or the matching stream's `send_window`.
unsafe fn handle_window_update(
    s: &mut HttpState,
    hdr: &h2w::Header,
    payload: *const u8,
) -> Result<(), u32> {
    if hdr.length != 4 {
        return Err(h2w::ERR_FRAME_SIZE_ERROR);
    }
    let delta = (((*payload as u32) << 24)
        | ((*payload.add(1) as u32) << 16)
        | ((*payload.add(2) as u32) << 8)
        | (*payload.add(3) as u32))
        & 0x7FFF_FFFF;
    if delta == 0 {
        // RFC 7540 §6.9: 0 is a PROTOCOL_ERROR (or stream-level error
        // — we conservatively treat both as connection error).
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if hdr.stream_id == 0 {
        s.server.h2.send_window = s.server.h2.send_window.saturating_add(delta as i32);
    } else {
        let idx = slot_for_id(s, hdr.stream_id);
        if idx >= 0 {
            let slot = &mut *s.server.h2.streams.as_mut_ptr().add(idx as usize);
            slot.send_window = slot.send_window.saturating_add(delta as i32);
        }
        // Unknown stream — silently drop; peer might be referring to a
        // stream we already closed.
    }
    Ok(())
}

unsafe fn handle_ping(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) -> Result<(), u32> {
    if hdr.stream_id != 0 || hdr.length != 8 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_ACK) != 0 {
        return Ok(()); // peer ack'd our (nonexistent) ping; ignore
    }
    let n = h2w::write_ping_ack(s.server.send_buf.as_mut_ptr(), payload);
    s.server.send_len = n as u16;
    s.server.send_offset = 0;
    Ok(())
}

unsafe fn handle_headers(
    s: &mut HttpState,
    hdr: &h2w::Header,
    payload: *const u8,
) -> Result<(), u32> {
    if hdr.stream_id == 0 || (hdr.stream_id & 1) == 0 {
        // §5.1.1: client-initiated streams must use odd, nonzero ids.
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    if (hdr.flags & h2w::FLAG_END_HEADERS) == 0 {
        // CONTINUATION frames not yet supported.
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }
    // §5.1.1: stream ids must monotonically increase.
    if hdr.stream_id <= s.server.h2.last_stream_id {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }

    let slot_idx = alloc_slot(s, hdr.stream_id);
    if slot_idx < 0 {
        // Stream table full — refuse this stream, leave existing ones alone.
        let n = h2w::write_rst_stream(
            s.server.send_buf.as_mut_ptr(),
            hdr.stream_id,
            h2w::ERR_REFUSED_STREAM,
        );
        s.server.send_len = n as u16;
        s.server.send_offset = 0;
        return Ok(());
    }

    let (block_off, block_len) =
        super::wire_h2::headers_block_extent(payload, hdr.length, hdr.flags)
            .map_err(|_| h2w::ERR_PROTOCOL_ERROR)?;
    let block_ptr = payload.add(block_off);

    s.server.h2.last_stream_id = hdr.stream_id;
    let end_stream = (hdr.flags & h2w::FLAG_END_STREAM) != 0;

    // Decode into stack-local scratch; raw-pointer scratch avoids the
    // closure-borrow miscompile under -O on PIC aarch64.
    let mut method_kind: u8 = 0;
    let mut protocol_ws: u8 = 0;
    let mut path_buf = [0u8; MAX_PATH];
    let mut path_len: u8 = 0;
    let mk_ptr = &mut method_kind as *mut u8;
    let pr_ptr = &mut protocol_ws as *mut u8;
    let pl_ptr = &mut path_len as *mut u8;
    let pb_ptr = path_buf.as_mut_ptr();

    let dec = super::hpack::decode_block(block_ptr, block_len, |name, value| {
        if bytes_eq(name, b":method") {
            if bytes_eq(value, b"GET") || bytes_eq(value, b"HEAD") {
                *mk_ptr = 1;
            } else if bytes_eq(value, b"CONNECT") {
                *mk_ptr = 2;
            } else if bytes_eq(value, b"POST")
                || bytes_eq(value, b"PUT")
                || bytes_eq(value, b"PATCH")
                || bytes_eq(value, b"DELETE")
            {
                *mk_ptr = 3;
            }
        } else if bytes_eq(name, b":path") {
            let n = value.len().min(MAX_PATH);
            let mut i = 0;
            while i < n {
                *pb_ptr.add(i) = value[i];
                i += 1;
            }
            *pl_ptr = n as u8;
        } else if bytes_eq(name, b":protocol") {
            if bytes_eq(value, b"websocket") {
                *pr_ptr = 1;
            }
        }
    });
    if dec.is_err() {
        free_slot(s, slot_idx);
        return Err(h2w::ERR_COMPRESSION_ERROR);
    }

    let slot = &mut *s.server.h2.streams.as_mut_ptr().add(slot_idx as usize);
    slot.method_kind = method_kind;
    slot.req_path_len = path_len;
    slot.end_stream_in = if end_stream { 1 } else { 0 };
    let mut ci = 0usize;
    while ci < path_len as usize {
        slot.req_path[ci] = path_buf[ci];
        ci += 1;
    }

    if method_kind == 0 || path_len == 0 {
        let n = h2w::write_rst_stream(
            s.server.send_buf.as_mut_ptr(),
            hdr.stream_id,
            h2w::ERR_PROTOCOL_ERROR,
        );
        s.server.send_len = n as u16;
        s.server.send_offset = 0;
        free_slot(s, slot_idx);
        return Ok(());
    }

    // Extended CONNECT (RFC 8441) — WS-over-h2 upgrade. Must not have
    // END_STREAM and we cap WS at one stream per connection.
    if method_kind == 2 && protocol_ws == 1 {
        if end_stream || s.server.h2.ws_active != 0 {
            let n = h2w::write_rst_stream(
                s.server.send_buf.as_mut_ptr(),
                hdr.stream_id,
                if end_stream { h2w::ERR_PROTOCOL_ERROR } else { h2w::ERR_REFUSED_STREAM },
            );
            s.server.send_len = n as u16;
            s.server.send_offset = 0;
            free_slot(s, slot_idx);
            return Ok(());
        }
        accept_ws_upgrade(s, slot_idx);
        return Ok(());
    }

    if method_kind != 1 && method_kind != 3 {
        // CONNECT without `:protocol = websocket` not supported.
        emit_response(
            s,
            hdr.stream_id,
            b"501",
            b"text/plain",
            b"method unsupported on h2\n",
        );
        free_slot(s, slot_idx);
        return Ok(());
    }

    if end_stream {
        // Request fully received; mark Pending. The active loop will
        // pick this slot up once any in-flight emitter finishes.
        slot.state = SlotState::Pending;
        try_dispatch_pending(s);
    }
    // Else slot stays Open until DATA frame with END_STREAM arrives.
    Ok(())
}

unsafe fn handle_data(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) -> Result<(), u32> {
    if hdr.stream_id == 0 {
        return Err(h2w::ERR_PROTOCOL_ERROR);
    }

    // Account for the bytes against connection-level + stream-level
    // recv windows. The window doesn't care whether we kept the
    // payload or discarded it.
    consume_recv_window(s, hdr.length);
    let idx = slot_for_id(s, hdr.stream_id);
    if idx >= 0 {
        consume_slot_recv_window(s, idx, hdr.length);
    }
    if idx < 0 {
        let n = h2w::write_rst_stream(
            s.server.send_buf.as_mut_ptr(),
            hdr.stream_id,
            h2w::ERR_STREAM_CLOSED,
        );
        s.server.send_len = n as u16;
        s.server.send_offset = 0;
        return Ok(());
    }

    let slot_state = (*s.server.h2.streams.as_ptr().add(idx as usize)).state;
    if slot_state == SlotState::WsActive {
        ws_handle_data(s, hdr, payload);
        return Ok(());
    }

    // Request body for non-WS streams is discarded; END_STREAM moves
    // the slot to Pending and the active loop picks it up.
    let end_stream = (hdr.flags & h2w::FLAG_END_STREAM) != 0;
    if end_stream {
        let slot = &mut *s.server.h2.streams.as_mut_ptr().add(idx as usize);
        slot.end_stream_in = 1;
        if slot.state == SlotState::Open {
            slot.state = SlotState::Pending;
        }
        try_dispatch_pending(s);
    }
    Ok(())
}

/// Decrement connection-level `recv_window` by `n` bytes. If it
/// crosses the refill threshold, mark `H2State.window_update_pending`
/// so the active loop emits a connection-level WINDOW_UPDATE the next
/// time `send_buf` is free.
unsafe fn consume_recv_window(s: &mut HttpState, n: u32) {
    s.server.h2.recv_window = s.server.h2.recv_window.saturating_sub(n as i32);
    if s.server.h2.recv_window <= RECV_WINDOW_THRESHOLD {
        s.server.h2.window_update_pending = 1;
    }
}

/// Decrement a stream's `recv_window` by `n` bytes. Sets the slot's
/// own `window_update_pending` flag when it crosses the threshold.
unsafe fn consume_slot_recv_window(s: &mut HttpState, slot_idx: i8, n: u32) {
    if slot_idx < 0 {
        return;
    }
    let slot = &mut *s.server.h2.streams.as_mut_ptr().add(slot_idx as usize);
    slot.recv_window = slot.recv_window.saturating_sub(n as i32);
    if slot.recv_window <= RECV_WINDOW_THRESHOLD {
        slot.window_update_pending = 1;
    }
}

/// Returns true if any stream slot needs a per-stream WINDOW_UPDATE.
/// Used so the active loop knows whether to call `queue_window_update`
/// even when the connection-level window is full.
unsafe fn any_stream_window_pending(s: &HttpState) -> bool {
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
        if slot.id != 0
            && slot.window_update_pending != 0
            && slot.state != SlotState::Idle
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Queue a WINDOW_UPDATE frame in `send_buf` (caller must have
/// verified it's free). Connection-level pending takes priority; if
/// none, scan slots and emit a per-stream WINDOW_UPDATE for the first
/// pending one. Each call emits at most one frame; subsequent ticks
/// drain the rest until the queue is empty.
unsafe fn queue_window_update(s: &mut HttpState) {
    if s.server.h2.window_update_pending != 0 {
        let delta = (RECV_WINDOW_INITIAL - s.server.h2.recv_window) as u32;
        if delta != 0 {
            let n = h2w::write_window_update(s.server.send_buf.as_mut_ptr(), 0, delta);
            s.server.send_len = n as u16;
            s.server.send_offset = 0;
            s.server.h2.recv_window = RECV_WINDOW_INITIAL;
        }
        s.server.h2.window_update_pending = 0;
        return;
    }
    // Per-stream pending — find one and emit it.
    let mut i = 0u8;
    while (i as usize) < MAX_STREAMS {
        let slot = &mut *s.server.h2.streams.as_mut_ptr().add(i as usize);
        if slot.id != 0
            && slot.window_update_pending != 0
            && slot.state != SlotState::Idle
        {
            let delta = (RECV_WINDOW_INITIAL - slot.recv_window) as u32;
            if delta != 0 {
                let n =
                    h2w::write_window_update(s.server.send_buf.as_mut_ptr(), slot.id, delta);
                s.server.send_len = n as u16;
                s.server.send_offset = 0;
                slot.recv_window = RECV_WINDOW_INITIAL;
            }
            slot.window_update_pending = 0;
            return;
        }
        i += 1;
    }
}

// ── WebSocket-over-h2 (RFC 8441) ──────────────────────────────────────────

/// Validate that a CONNECT + `:protocol = websocket` request maps to a
/// HANDLER_WEBSOCKET route, then queue the 200 HEADERS frame and arm
/// `ws_active`. RFC 8441 §5: the response carries no
/// `Sec-WebSocket-Accept` (that header only applies to the h1
/// handshake); the 200 alone signals the upgrade.
unsafe fn accept_ws_upgrade(s: &mut HttpState, slot_idx: i8) {
    let stream_id = (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).id;
    let plen =
        (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).req_path_len as usize;
    s.server.req_path_len = plen as u8;
    let mut i = 0usize;
    while i < plen {
        s.server.req_path[i] =
            (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).req_path[i];
        i += 1;
    }

    let matched = super::server::match_route(s);
    if matched < 0 {
        emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
        free_slot(s, slot_idx);
        return;
    }
    let route = &*s.server.routes.as_ptr().add(matched as usize);
    if route.handler != HANDLER_WEBSOCKET {
        emit_response(
            s,
            stream_id,
            b"404",
            b"text/plain",
            b"Not a WebSocket route\n",
        );
        free_slot(s, slot_idx);
        return;
    }
    s.server.matched_route = matched;

    // 200 HEADERS, no END_STREAM (DATA frames will follow with WS
    // frames in both directions).
    let buf = s.server.send_buf.as_mut_ptr();
    let cap = SEND_BUF_SIZE;
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;
    o += super::hpack::encode_header(buf.add(o), cap - o, b":status", b"200");
    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);
    s.server.send_len = o as u16;
    s.server.send_offset = 0;

    s.server.h2.ws_active = 1;
    s.server.h2.ws_stream_id = stream_id;
    (*s.server.h2.streams.as_mut_ptr().add(slot_idx as usize)).state = SlotState::WsActive;
    log(s, b"[http] websocket upgraded (h2)");
}

unsafe fn ws_handle_data(s: &mut HttpState, hdr: &h2w::Header, payload: *const u8) {
    let plen = hdr.length as usize;
    let cur = s.server.h2.ws_buf_len as usize;
    if cur + plen > WS_BUF_SIZE {
        queue_ws_close(s, ws::CLOSE_MESSAGE_TOO_BIG);
        return;
    }
    if plen > 0 {
        core::ptr::copy_nonoverlapping(
            payload,
            s.server.h2.ws_buf.as_mut_ptr().add(cur),
            plen,
        );
        s.server.h2.ws_buf_len = (cur + plen) as u16;
    }
    ws_drain_buf(s);
}

/// Pop and echo as many complete RFC 6455 frames as possible from
/// `ws_buf`. Stops when (a) the buffer holds only an incomplete frame
/// or (b) `send_buf` is busy with a queued echo (next tick will retry
/// after the wire drains).
pub(crate) unsafe fn ws_drain_buf(s: &mut HttpState) {
    while s.server.h2.ws_active != 0
        && s.server.send_len == 0
        && s.server.h2.ws_buf_len > 0
    {
        let buflen = s.server.h2.ws_buf_len as usize;
        let frame = match ws::parse_frame(s.server.h2.ws_buf.as_ptr(), buflen) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(()) => {
                queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
                return;
            }
        };
        let total = frame.header_len as usize + frame.payload_len as usize;
        if total > buflen {
            return; // need more bytes
        }
        if !frame.masked {
            // RFC 6455 §5.3 / RFC 8441 §5.1 — client→server frames
            // must be masked.
            queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
            return;
        }

        let pl_ptr = s.server.h2.ws_buf.as_mut_ptr().add(frame.header_len as usize);
        ws::unmask(pl_ptr, frame.payload_len, &frame.mask_key);

        let mut consume_only = false;
        match frame.opcode {
            ws::OP_CLOSE => {
                queue_ws_frame(s, ws::OP_CLOSE, pl_ptr, frame.payload_len as usize, true);
                let ws_idx = slot_for_id(s, s.server.h2.ws_stream_id);
                if ws_idx >= 0 {
                    free_slot(s, ws_idx);
                }
                s.server.h2.ws_active = 0;
                s.server.h2.ws_stream_id = 0;
                s.server.h2.ws_buf_len = 0;
                return;
            }
            ws::OP_PING => {
                queue_ws_frame(
                    s,
                    ws::OP_PONG,
                    pl_ptr,
                    frame.payload_len as usize,
                    false,
                );
            }
            ws::OP_PONG => consume_only = true, // drop silently
            ws::OP_TEXT | ws::OP_BINARY | ws::OP_CONTINUATION => {
                queue_ws_frame(
                    s,
                    frame.opcode,
                    pl_ptr,
                    frame.payload_len as usize,
                    false,
                );
            }
            _ => {
                queue_ws_close(s, ws::CLOSE_PROTOCOL_ERROR);
                return;
            }
        }

        // Shift the consumed frame off the front of ws_buf.
        let leftover = buflen - total;
        if leftover > 0 {
            let p = s.server.h2.ws_buf.as_mut_ptr();
            let mut i = 0;
            while i < leftover {
                *p.add(i) = *p.add(total + i);
                i += 1;
            }
        }
        s.server.h2.ws_buf_len = leftover as u16;
        if !consume_only {
            // We queued an echo; send_buf is busy. Bail and let the
            // next tick drain the wire and resume.
            return;
        }
    }
}

/// Wrap a single RFC 6455 frame in an h2 DATA frame on the WS stream.
/// `end_stream` set on a CLOSE echo terminates the WS stream.
unsafe fn queue_ws_frame(
    s: &mut HttpState,
    opcode: u8,
    payload: *const u8,
    payload_len: usize,
    end_stream: bool,
) {
    let stream_id = s.server.h2.ws_stream_id;
    let buf = s.server.send_buf.as_mut_ptr();
    let dst = buf.add(h2w::FRAME_HEADER_LEN);
    let dst_cap = SEND_BUF_SIZE - h2w::FRAME_HEADER_LEN;
    let written = ws::write_frame(dst, dst_cap, true, opcode, payload, payload_len);
    h2w::write_data_frame_header(buf, written, stream_id, end_stream);
    s.server.send_len = (h2w::FRAME_HEADER_LEN + written) as u16;
    s.server.send_offset = 0;
}

unsafe fn queue_ws_close(s: &mut HttpState, code: u16) {
    let payload = [(code >> 8) as u8, (code & 0xFF) as u8];
    queue_ws_frame(s, ws::OP_CLOSE, payload.as_ptr(), 2, true);
    let ws_idx = slot_for_id(s, s.server.h2.ws_stream_id);
    if ws_idx >= 0 {
        free_slot(s, ws_idx);
    }
    s.server.h2.ws_active = 0;
    s.server.h2.ws_stream_id = 0;
}

// ── Request dispatch ──────────────────────────────────────────────────────

/// Pick the next Pending slot that can be dispatched and arm it for
/// emission. Multiple Sending slots interleave — the only constraint
/// is the `file_owner` mutex for handlers that touch `file_chan` /
/// the body cache. Called after HEADERS / DATA arrival and after each
/// body completes.
unsafe fn try_dispatch_pending(s: &mut HttpState) {
    loop {
        let mut chosen: i8 = -1;
        let mut i = 0u8;
        while (i as usize) < MAX_STREAMS {
            let slot = &*s.server.h2.streams.as_ptr().add(i as usize);
            if slot.state == SlotState::Pending {
                if needs_exclusive_for_request(s, i as i8) && s.server.h2.file_owner != -1 {
                    // file_chan is busy with another stream; defer
                    // until the current owner finishes.
                    i += 1;
                    continue;
                }
                chosen = i as i8;
                break;
            }
            i += 1;
        }
        if chosen < 0 {
            return;
        }
        dispatch_request(s, chosen);
        // dispatch_request may have queued send_buf (404/501 single
        // frames), in which case we should bail and let the flush
        // happen.
        if s.server.send_len > 0 {
            return;
        }
        // Else loop and try to dispatch more inline streams.
    }
}

/// Returns true if the slot's request will need exclusive access to
/// `file_chan` / the body cache. Only one such slot can be in
/// Sending or Fetching state at a time. Raw-pointer iteration so the
/// PIC aarch64 codegen doesn't pull in slice-bounds panic stubs.
unsafe fn needs_exclusive_for_request(s: &HttpState, slot_idx: i8) -> bool {
    let slot = &*s.server.h2.streams.as_ptr().add(slot_idx as usize);
    let plen = slot.req_path_len as usize;
    if plen == 0 {
        return false;
    }
    let req = slot.req_path.as_ptr();
    let mut j = 0u8;
    while (j as usize) < s.server.route_count as usize {
        let r = &*s.server.routes.as_ptr().add(j as usize);
        let rlen = r.path_len as usize;
        if rlen > 0 && plen >= rlen {
            let path_ptr = r.path.as_ptr();
            let mut k = 0usize;
            let mut ok = true;
            while k < rlen {
                if *req.add(k) != *path_ptr.add(k) {
                    ok = false;
                    break;
                }
                k += 1;
            }
            if ok {
                return r.handler == HANDLER_FILE
                    || ((r.handler == HANDLER_STATIC || r.handler == HANDLER_TEMPLATE)
                        && r.source_index >= 0);
            }
        }
        j += 1;
    }
    false
}

unsafe fn dispatch_request(s: &mut HttpState, slot_idx: i8) {
    let stream_id = (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).id;
    let plen =
        (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).req_path_len as usize;

    // Copy the slot's request path into the shared request scratch the
    // route matcher and file-index parser read from.
    s.server.req_path_len = plen as u8;
    let mut i = 0;
    while i < plen {
        s.server.req_path[i] =
            (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).req_path[i];
        i += 1;
    }

    let matched = super::server::match_route(s);
    if matched < 0 {
        emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
        free_slot(s, slot_idx);
        return;
    }
    s.server.matched_route = matched;

    let route = &*s.server.routes.as_ptr().add(matched as usize);
    let handler_kind = route.handler;
    let src_idx = route.source_index;
    s.server.tmpl_pos = 0;

    match handler_kind {
        HANDLER_STATIC => {
            if src_idx >= 0 {
                begin_cached_response(s, slot_idx, HANDLER_STATIC);
            } else {
                arm_slot_for_emission(s, slot_idx, HANDLER_STATIC, -1, matched);
            }
        }
        HANDLER_TEMPLATE => {
            if src_idx >= 0 {
                begin_cached_response(s, slot_idx, HANDLER_TEMPLATE);
            } else {
                arm_slot_for_emission(s, slot_idx, HANDLER_TEMPLATE, -1, matched);
            }
        }
        HANDLER_FILE => begin_file_response(s, slot_idx, matched),
        _ => {
            emit_response(
                s,
                stream_id,
                b"501",
                b"text/plain",
                b"handler unsupported on h2\n",
            );
            free_slot(s, slot_idx);
        }
    }
}

/// Populate slot's render state and mark Sending. The actual HEADERS
/// frame is emitted lazily by `step_sending_body` so multiple slots'
/// HEADERS can interleave on the wire.
unsafe fn arm_slot_for_emission(
    s: &mut HttpState,
    slot_idx: i8,
    handler: u8,
    file_index: i16,
    matched_route: i8,
) {
    let slot = &mut *s.server.h2.streams.as_mut_ptr().add(slot_idx as usize);
    slot.body_handler = handler;
    slot.matched_route = matched_route;
    slot.file_index = file_index;
    slot.tmpl_pos = 0;
    slot.headers_sent = 0;
    slot.state = SlotState::Sending;
    s.server.h2.sub = Sub::SendingBody;
}

/// Try the body cache; on hit, arm for emission. On miss, mark the
/// slot `Fetching`, claim `file_owner`, and stay in `Sub::SendingBody`
/// so `drive_cache_fetch` ticks each step until the cache is filled —
/// without blocking other in-flight inline streams.
unsafe fn begin_cached_response(s: &mut HttpState, slot_idx: i8, handler: u8) {
    use super::server::{cache_try_or_fetch, CacheLookup};
    let matched = s.server.matched_route;
    match cache_try_or_fetch(s, matched) {
        CacheLookup::Hit | CacheLookup::NoSource => {
            arm_slot_for_emission(s, slot_idx, handler, -1, matched);
        }
        CacheLookup::Pending => {
            let slot = &mut *s.server.h2.streams.as_mut_ptr().add(slot_idx as usize);
            slot.state = SlotState::Fetching;
            slot.body_handler = handler;
            slot.matched_route = matched;
            slot.file_index = -1;
            slot.tmpl_pos = 0;
            slot.headers_sent = 0;
            s.server.h2.file_owner = slot_idx;
            s.server.h2.sub = Sub::SendingBody;
        }
    }
}

/// Open `file_chan` for the requested index (or list mode) and arm
/// the slot for streaming. Claims `file_owner` for the duration —
/// other HANDLER_FILE / cache slots wait Pending.
unsafe fn begin_file_response(s: &mut HttpState, slot_idx: i8, matched_route: i8) {
    let stream_id = (*s.server.h2.streams.as_ptr().add(slot_idx as usize)).id;
    let fi = super::server::parse_file_index(s);
    s.server.file_index = fi;
    let sys = &*s.syscalls;

    if fi == -1 {
        if s.server.file_chan >= 0 {
            let mut count: u32 = 0;
            let count_ptr = &mut count as *mut u32 as *mut u8;
            let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_POLL_NOTIFY, count_ptr);
            if r >= 0 {
                s.server.file_count = count as u16;
            }
        }
        s.server.index_pos = 0;
        s.server.h2.file_owner = slot_idx;
        arm_slot_for_emission(s, slot_idx, HANDLER_FILE, -1, matched_route);
    } else if fi >= 0 {
        if s.server.file_chan < 0 {
            emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
            free_slot(s, slot_idx);
            return;
        }
        dev_channel_ioctl(sys, s.server.file_chan, IOCTL_FLUSH, core::ptr::null_mut());
        let mut pos = fi as u32;
        let pos_ptr = &mut pos as *mut u32 as *mut u8;
        let r = dev_channel_ioctl(sys, s.server.file_chan, IOCTL_NOTIFY, pos_ptr);
        if r < 0 {
            emit_response(s, stream_id, b"404", b"text/plain", b"Not Found\n");
            free_slot(s, slot_idx);
            return;
        }
        s.server.h2.file_owner = slot_idx;
        arm_slot_for_emission(s, slot_idx, HANDLER_FILE, fi, matched_route);
    } else {
        emit_response(s, stream_id, b"400", b"text/plain", b"Bad Request\n");
        free_slot(s, slot_idx);
    }
}

/// Build a HEADERS + DATA pair into `send_buf`. The DATA frame carries
/// END_STREAM. Caller must guarantee the combined payload fits within
/// `SEND_BUF_SIZE` (current bodies do; static routes are capped by the
/// body pool).
unsafe fn emit_response(
    s: &mut HttpState,
    stream_id: u32,
    status: &[u8],
    content_type: &[u8],
    body: &[u8],
) {
    let buf = s.server.send_buf.as_mut_ptr();
    let cap = SEND_BUF_SIZE;

    // Encode the header block starting at offset 9 — leaving room for
    // the HEADERS frame header that comes back-filled below.
    let block_start = h2w::FRAME_HEADER_LEN;
    let mut o = block_start;

    o += super::hpack::encode_header(buf.add(o), cap - o, b":status", status);
    o += super::hpack::encode_header(buf.add(o), cap - o, b"content-type", content_type);

    let mut clen = [0u8; 11];
    let n = super::fmt_u32_raw(clen.as_mut_ptr(), body.len() as u32);
    o += super::hpack::encode_header(
        buf.add(o),
        cap - o,
        b"content-length",
        core::slice::from_raw_parts(clen.as_ptr(), n),
    );

    let block_len = o - block_start;
    h2w::write_headers_frame_header(buf, block_len, stream_id, false, true);

    // DATA frame follows immediately after the HEADERS frame.
    let data_hdr_off = o;
    let data_off = data_hdr_off + h2w::FRAME_HEADER_LEN;
    if data_off + body.len() > cap {
        // Body too large for our send buffer in this slice — close the
        // stream rather than emit a malformed frame.
        let n = h2w::write_rst_stream(buf, stream_id, h2w::ERR_INTERNAL_ERROR);
        s.server.send_len = n as u16;
        s.server.send_offset = 0;
        return;
    }

    h2w::write_data_frame_header(buf.add(data_hdr_off), body.len(), stream_id, true);
    if !body.is_empty() {
        core::ptr::copy_nonoverlapping(body.as_ptr(), buf.add(data_off), body.len());
    }
    s.server.send_len = (data_off + body.len()) as u16;
    s.server.send_offset = 0;
}

// ── Connection-level error path ───────────────────────────────────────────

unsafe fn queue_goaway(s: &mut HttpState, code: u32) {
    let n = h2w::write_goaway(
        s.server.send_buf.as_mut_ptr(),
        s.server.h2.last_stream_id,
        code,
    );
    s.server.send_len = n as u16;
    s.server.send_offset = 0;
    s.server.h2.sub = Sub::Closing;
}

// ── Outbound CMD_SEND helper (mirrors server.rs::net_send) ───────────────

unsafe fn net_send(s: &mut HttpState, data: *const u8, len: usize) -> i32 {
    if s.net_out_chan < 0 {
        return 0;
    }
    let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    let to_send = len.min(max_data);
    if to_send == 0 {
        return 0;
    }

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let conn_id = s.server.conn_id;
    let scratch = s.net_buf.as_mut_ptr();
    let payload_len = 1 + to_send;
    *scratch = NET_CMD_SEND;
    *scratch.add(1) = (payload_len & 0xFF) as u8;
    *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
    *scratch.add(3) = conn_id;
    core::ptr::copy_nonoverlapping(data, scratch.add(4), to_send);
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written >= total as i32 {
        to_send as i32
    } else {
        0
    }
}

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

/// Byte-by-byte slice equality using raw-pointer iteration. Slice
/// indexing in -O builds can be lifted to a memcmp call which the PIC
/// loader can't satisfy; raw-pointer arithmetic stays inline.
#[inline]
unsafe fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let n = a.len();
    if n != b.len() {
        return false;
    }
    let ap = a.as_ptr();
    let bp = b.as_ptr();
    let mut i = 0usize;
    while i < n {
        if *ap.add(i) != *bp.add(i) {
            return false;
        }
        i += 1;
    }
    true
}
