//! `wasm_browser_ws` built-in: the browser as an addressed WebSocket
//! connector.
//!
//! A consumer holding several links addresses them by index, and that index
//! rides in `WsFrame`'s `conn` field. `open_in` names which link to open on
//! which resource, `ws_in` carries messages to send, `ws_out` carries
//! messages received, and `event_out` says what became of a link — the same
//! four ports, records and link count a socket-backed connector offers, so a
//! consumer moves between the two by wiring alone. The records are the
//! `ws_control` and `ws_frame` contracts; what this module does with them is
//! here.
//!
//! A path names the resource and the `origin` param names where: a consumer
//! chooses what to open, never where, and a program cannot point a link at
//! a host the graph did not name.
//!
//! A browser sends and receives whole messages, so fragments arriving on
//! `ws_in` are assembled here until their final frame and sent as one, and a
//! received message longer than one envelope leaves on `ws_out` as fragments
//! whose last carries `fin`. A consumer that reassembles by RFC 6455 sees the
//! same stream either way.
//!
//! State: heap-allocated; the `BuiltInModule`'s inline state holds a
//! `*mut WsState`.

use crate::abi::contracts::net::ws_control::{event, parse_open, write_event, WS_LINKS};
use crate::abi::contracts::net::ws_frame as wsf;
use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Open one link to `path` on the module's origin (or the page's).
    /// Returns a non-negative handle, or negative when the socket could not
    /// even be constructed. The handshake completes asynchronously and is
    /// reported through `host_ws_link_event`.
    fn host_ws_link_open(
        origin_ptr: *const u8,
        origin_len: usize,
        path_ptr: *const u8,
        path_len: usize,
    ) -> i32;

    /// Pop the next thing that became of the link: `0` when nothing has,
    /// otherwise `(kind << 16) | code` with `kind` a `ws_control::event`
    /// value. A close is reported only after every message that preceded it
    /// has been taken.
    fn host_ws_link_event(handle: i32) -> i32;

    /// Send one whole message with the given RFC 6455 opcode. Returns the
    /// bytes accepted, or negative when the socket refused them.
    fn host_ws_link_send(handle: i32, opcode: u32, data: *const u8, len: usize) -> i32;

    /// Describe the oldest message still to be taken: `-1` when there is
    /// none, otherwise `(opcode << 24) | bytes_remaining`.
    fn host_ws_link_next(handle: i32) -> i32;

    /// Copy the next bytes of the oldest message into `buf`. Returns the
    /// count; a message is consumed once its last byte is taken.
    fn host_ws_link_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Close the link with `code`, or drop it outright if it never opened.
    fn host_ws_link_close(handle: i32, code: u32) -> i32;
}

/// The largest message either direction, and the whole of what a
/// consumer's `WsFrame` ring must carry with its header.
const MESSAGE_MAX: usize = 8192;
/// One outbound fragment on `ws_out`. Sized to fit its ring twice over.
const RX_CHUNK: usize = 4096;
/// The largest origin a graph may name.
const ORIGIN_MAX: usize = 256;
/// Bytes of an open record: the link byte and the longest path.
const OPEN_MAX: usize = 129;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;

const LINK_FREE: u8 = 0;
const LINK_OPENING: u8 = 1;
const LINK_OPEN: u8 = 2;

#[repr(C)]
struct Link {
    handle: i32,
    phase: u8,
    /// The opcode of the message being assembled from `ws_in`.
    tx_opcode: u8,
    /// The next fragment emitted on `ws_out` starts a message.
    rx_first: bool,
    tx_len: u32,
    tx: [u8; MESSAGE_MAX],
}

#[repr(C)]
pub(crate) struct WsState {
    open_in: i32,
    ws_in: i32,
    ws_out: i32,
    event_out: i32,
    origin_len: u16,
    event_len: u16,
    stage_len: u32,
    /// Bytes of an over-ceiling frame still to arrive and be discarded.
    skip: u32,
    out_len: u32,
    origin: [u8; ORIGIN_MAX],
    /// One link event composed and waiting for `event_out`.
    event: [u8; event::LEN],
    /// Inbound `ws_in` assembly: one whole envelope.
    stage: [u8; wsf::FRAME_HDR + MESSAGE_MAX],
    /// One outbound envelope waiting for `ws_out`.
    out: [u8; wsf::FRAME_HDR + RX_CHUNK],
    links: [Link; WS_LINKS],
}

unsafe fn alloc_state(
    open_in: i32,
    ws_in: i32,
    ws_out: i32,
    event_out: i32,
    origin: &[u8],
) -> *mut WsState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<WsState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut WsState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Initialised in place: every buffer starts zeroed and only the scalars
    // need a value, so the state is never composed on the stack first.
    core::ptr::write_bytes(raw, 0, 1);
    let st = &mut *raw;
    st.open_in = open_in;
    st.ws_in = ws_in;
    st.ws_out = ws_out;
    st.event_out = event_out;
    let origin_len = origin.len().min(ORIGIN_MAX);
    st.origin[..origin_len].copy_from_slice(&origin[..origin_len]);
    st.origin_len = origin_len as u16;
    for link in st.links.iter_mut() {
        reset_link(link);
    }
    raw
}

/// Return a link to the free state.
fn reset_link(link: &mut Link) {
    link.handle = -1;
    link.phase = LINK_FREE;
    link.tx_opcode = 0;
    link.rx_first = true;
    link.tx_len = 0;
}

/// Whether a path names a resource on the origin rather than a place of
/// its own.
fn path_ok(path: &[u8]) -> bool {
    path.first() == Some(&b'/') && !path.windows(3).any(|w| w == b"://")
}

/// Compose a link event and hold it for `event_out`. Nothing waits on the
/// port: a consumer not wired for events does not need them.
fn stage_event(st: &mut WsState, conn: usize, kind: u8, code: u16) {
    if st.event_out < 0 {
        return;
    }
    if let Some(n) = write_event(conn as u8, kind, code, &mut st.event) {
        st.event_len = n as u16;
    }
}

unsafe fn flush_event(st: &mut WsState) -> bool {
    let n = st.event_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.event_out, st.event.as_ptr(), n) != n as i32 {
        return false;
    }
    st.event_len = 0;
    true
}

unsafe fn flush_out(st: &mut WsState) -> bool {
    let n = st.out_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.ws_out, st.out.as_ptr(), n) != n as i32 {
        return false;
    }
    st.out_len = 0;
    true
}

/// Forget a link whose socket is gone.
fn free_link(st: &mut WsState, i: usize) {
    reset_link(&mut st.links[i]);
}

/// Take one open request, if the event slot can carry its outcome.
unsafe fn take_open(st: &mut WsState) {
    if st.open_in < 0 || st.event_len != 0 {
        return;
    }
    let mut record = [0u8; OPEN_MAX];
    let n = channel::channel_read(st.open_in, record.as_mut_ptr(), record.len());
    if n <= 0 {
        return;
    }
    let Some((want, path)) = parse_open(&record[..n as usize]) else {
        return;
    };
    // The link is already spoken for, or the path names its own host.
    // Saying so is better than opening a second socket the consumer will
    // address as the first.
    if st.links[want].phase != LINK_FREE || !path_ok(path) {
        stage_event(st, want, event::FAILED, 0);
        return;
    }
    let handle = host_ws_link_open(
        st.origin.as_ptr(),
        st.origin_len as usize,
        path.as_ptr(),
        path.len(),
    );
    if handle < 0 {
        stage_event(st, want, event::FAILED, 0);
        return;
    }
    reset_link(&mut st.links[want]);
    st.links[want].handle = handle;
    st.links[want].phase = LINK_OPENING;
}

/// Report what became of each link, one event per step.
unsafe fn poll_events(st: &mut WsState) {
    for i in 0..WS_LINKS {
        if st.event_len != 0 {
            return;
        }
        if st.links[i].phase == LINK_FREE {
            continue;
        }
        let ev = host_ws_link_event(st.links[i].handle);
        if ev <= 0 {
            continue;
        }
        let kind = (ev >> 16) as u8;
        let code = (ev & 0xFFFF) as u16;
        match kind {
            event::OPEN => st.links[i].phase = LINK_OPEN,
            event::CLOSED | event::FAILED => {
                host_ws_link_close(st.links[i].handle, 0);
                free_link(st, i);
            }
            _ => continue,
        }
        stage_event(st, i, kind, code);
    }
}

/// Discard `total..stage_len` after a frame was consumed.
fn consume(st: &mut WsState, total: usize) {
    let len = st.stage_len as usize;
    st.stage.copy_within(total..len, 0);
    st.stage_len = (len - total) as u32;
}

/// End a link from this side. The socket reports the close when it
/// completes, and that report is what frees the link.
unsafe fn close_link(st: &mut WsState, i: usize, code: u16) {
    host_ws_link_close(st.links[i].handle, u32::from(code));
    st.links[i].tx_len = 0;
}

/// Carry the frame at the head of the stage to its link. False when the
/// frame must wait — its link is still opening.
unsafe fn send_frame(st: &mut WsState, total: usize) -> bool {
    let i = wsf::conn_id(&st.stage) as usize;
    if i >= WS_LINKS || st.links[i].phase == LINK_FREE {
        return true;
    }
    if st.links[i].phase != LINK_OPEN {
        return false;
    }
    let opcode = wsf::opcode(&st.stage);
    let fin = wsf::fin(&st.stage) != 0;
    let payload = &st.stage[wsf::FRAME_HDR..total];
    match opcode {
        OP_CLOSE => close_link(st, i, 1000),
        OP_CONTINUATION | OP_TEXT | OP_BINARY => {
            let have = st.links[i].tx_len as usize;
            if have == 0 {
                st.links[i].tx_opcode = if opcode == OP_CONTINUATION {
                    OP_BINARY
                } else {
                    opcode
                };
            }
            if have + payload.len() > MESSAGE_MAX {
                // Longer than a message may be. Dropping part of it would
                // be a hole in the stream a consumer cannot see, so the
                // link ends instead.
                close_link(st, i, 1009);
                return true;
            }
            st.links[i].tx[have..have + payload.len()].copy_from_slice(payload);
            st.links[i].tx_len = (have + payload.len()) as u32;
            if fin {
                let link = &st.links[i];
                host_ws_link_send(
                    link.handle,
                    u32::from(link.tx_opcode),
                    link.tx.as_ptr(),
                    link.tx_len as usize,
                );
                st.links[i].tx_len = 0;
            }
        }
        // Ping and pong are the socket's own to answer.
        _ => {}
    }
    true
}

/// Take frames off `ws_in`. The channel is a byte stream, so envelopes are
/// assembled here; one wider than the stage is drained and dropped so the
/// stream re-aligns on the header behind it.
unsafe fn pump_ws_in(st: &mut WsState) {
    if st.ws_in < 0 {
        return;
    }
    let cap = st.stage.len();
    if st.skip > 0 {
        let want = (st.skip as usize).min(cap);
        let n = channel::channel_read(st.ws_in, st.stage.as_mut_ptr(), want);
        if n > 0 {
            st.skip -= n as u32;
        }
        return;
    }
    let have = st.stage_len as usize;
    if have < cap {
        let n = channel::channel_read(st.ws_in, st.stage.as_mut_ptr().add(have), cap - have);
        if n > 0 {
            st.stage_len += n as u32;
        }
    }
    loop {
        let have = st.stage_len as usize;
        if have < wsf::FRAME_HDR {
            return;
        }
        let total = wsf::FRAME_HDR + usize::from(wsf::payload_len(&st.stage));
        if total > cap {
            st.skip = (total - have) as u32;
            st.stage_len = 0;
            return;
        }
        if have < total {
            return;
        }
        if !send_frame(st, total) {
            return;
        }
        consume(st, total);
    }
}

/// Carry received messages to `ws_out`, one fragment per envelope.
unsafe fn pump_ws_out(st: &mut WsState) {
    if st.ws_out < 0 {
        return;
    }
    for i in 0..WS_LINKS {
        if st.out_len != 0 {
            return;
        }
        if st.links[i].phase != LINK_OPEN {
            continue;
        }
        let handle = st.links[i].handle;
        loop {
            let meta = host_ws_link_next(handle);
            if meta < 0 {
                break;
            }
            let opcode = (meta >> 24) as u8;
            let remaining = (meta & 0x00FF_FFFF) as usize;
            let take = remaining.min(RX_CHUNK);
            let n = host_ws_link_recv(handle, st.out.as_mut_ptr().add(wsf::FRAME_HDR), take);
            if n < 0 {
                break;
            }
            let n = n as usize;
            let fin = n == remaining;
            let op = if st.links[i].rx_first {
                opcode
            } else {
                OP_CONTINUATION
            };
            st.links[i].rx_first = fin;
            wsf::put_header(&mut st.out, i as u32, op, u8::from(fin), n as u16);
            st.out_len = (wsf::FRAME_HDR + n) as u32;
            if !flush_out(st) {
                return;
            }
        }
    }
}

fn ws_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this
    // module instance, holding the `*mut WsState` written by `build`; every
    // buffer touched below lives inside that allocation, and the host
    // imports read only the slices they are handed.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut WsState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if !flush_event(st) || !flush_out(st) {
            return 0;
        }
        take_open(st);
        poll_events(st);
        pump_ws_in(st);
        pump_ws_out(st);
        flush_event(st);
        0
    }
}

pub(crate) unsafe fn build(
    origin: &[u8],
    open_in: i32,
    ws_in: i32,
    ws_out: i32,
    event_out: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_ws", ws_step);
    let raw = alloc_state(open_in, ws_in, ws_out, event_out, origin);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut WsState, raw);
    m
}
