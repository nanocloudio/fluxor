//! `wasm_browser_http` built-in: the browser as an HTTP exchange provider.
//!
//! A request arrives on `publish_in` as an `http_exchange` record inside an
//! ordered-ack `Publish`; the page's `fetch()` performs it; the answer leaves
//! on `reply_out` under the same correlation, echoing the request's key. An
//! extended request is answered with the response head and its body streams
//! on `file_ctrl` as length-framed chunks ending with an empty one, exactly
//! as a socket-backed HTTP client answers the same record.
//!
//! What the records mean is the `http_exchange` contract; what this module
//! does with them is here. A path names the resource and the `origin` param
//! names where — a request never chooses its own host, so a graph moved to a
//! different page keeps working and a program cannot be pointed at a server
//! the graph did not name. The browser's own cross-origin policy is the
//! enforcement behind that: a fetch the page may not make fails, and a
//! failed fetch is an unroutable request.
//!
//! One exchange is in flight at a time. A graph that wants concurrency
//! instantiates more of these, which is also how it gets more connections.
//!
//! State: heap-allocated; the `BuiltInModule`'s inline state holds a
//! `*mut HttpState`.

use crate::abi::contracts::exchange::{
    Publish, Reply, FLAG_BROADCAST, KEY_MAX, MSG_PUBLISH, MSG_REPLY, PAYLOAD_MAX,
    PUBLISH_FRAME_MAX, REFUSE_OVERSIZE, REFUSE_UNROUTABLE, REFUSE_UPSTREAM, REPLY_FRAME_MAX,
    STATUS_OK,
};
use crate::abi::contracts::net::http_exchange::{
    method_name, parse_request, write_chunk, write_reply_head, Limits, RequestParse, CHUNK_HEAD,
    METHOD_CONNECT, RESP_HEAD,
};
use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Start one request. `method` is the request-line token, `path` is
    /// resolved against the module's origin (or the page's), `headers` is a
    /// CRLF-terminated block the shim splits into fields, and `body` goes as
    /// the request body when the method carries one. Returns a non-negative
    /// handle, or negative when the request could not even be started.
    fn host_http_open(
        method_ptr: *const u8,
        method_len: usize,
        origin_ptr: *const u8,
        origin_len: usize,
        path_ptr: *const u8,
        path_len: usize,
        headers_ptr: *const u8,
        headers_len: usize,
        body_ptr: *const u8,
        body_len: usize,
    ) -> i32;

    /// The response status: `>= 0` once the head has arrived, `-3` while the
    /// request is still in flight, `-2` when the transport failed.
    fn host_http_status(handle: i32) -> i32;

    /// Copy the response's header block — each field a line ending CRLF —
    /// into `buf`. Returns its length, or `-2` when `len` cannot hold it.
    fn host_http_head(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Copy the next response-body bytes into `buf`. Returns the count,
    /// `0` while nothing has arrived, `-1` at the end of the body, `-2` on a
    /// transport failure.
    fn host_http_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Release the handle, cancelling any body still arriving.
    fn host_http_close(handle: i32) -> i32;
}

/// The 3-byte channel envelope every exchange frame rides:
/// `[msg_type][len:u16 LE]`.
const ENVELOPE: usize = 3;
/// Inbound staging: one whole publish frame behind its envelope.
const STAGE_BYTES: usize = ENVELOPE + PUBLISH_FRAME_MAX;
/// Outbound reply: one whole reply frame behind its envelope.
const OUT_BYTES: usize = ENVELOPE + REPLY_FRAME_MAX;
/// The largest origin a graph may name.
const ORIGIN_MAX: usize = 256;
/// The largest path a request may name.
const PATH_MAX: usize = 2048;
/// One streamed body chunk. Sized to fit `file_ctrl`'s ring twice over, so
/// a chunk is never refused for being the only thing that cannot fit.
const BODY_CHUNK: usize = 1024;

const PHASE_IDLE: u8 = 0;
/// The request is with the page; nothing has been answered.
const PHASE_PERFORMING: u8 = 1;
/// An extended exchange whose head is answered; the body is streaming.
const PHASE_STREAMING: u8 = 2;
/// The one reply is composed and waits for `reply_out` to take it.
const PHASE_ANSWERING: u8 = 3;

#[repr(C)]
pub(crate) struct HttpState {
    publish_in: i32,
    reply_out: i32,
    file_ctrl: i32,
    handle: i32,
    phase: u8,
    extended: bool,
    surface_status: bool,
    oversize: bool,
    /// The body's end has been framed; the exchange ends when it is taken.
    body_done: bool,
    status: u16,
    key_len: u16,
    origin_len: u16,
    corr: u64,
    stage_len: u32,
    /// Bytes of an over-ceiling frame still to arrive and be discarded.
    skip: u32,
    reply_len: u32,
    out_len: u32,
    chunk_len: u32,
    origin: [u8; ORIGIN_MAX],
    key: [u8; KEY_MAX],
    stage: [u8; STAGE_BYTES],
    /// The reply's payload: an accumulated body, a composed head, or the
    /// two status bytes of an upstream refusal.
    reply: [u8; PAYLOAD_MAX],
    /// The response head as the page reports it, and the landing buffer
    /// for body bytes on their way to a chunk.
    scratch: [u8; PAYLOAD_MAX],
    out: [u8; OUT_BYTES],
    chunk: [u8; CHUNK_HEAD + BODY_CHUNK],
}

unsafe fn alloc_state(
    publish_in: i32,
    reply_out: i32,
    file_ctrl: i32,
    origin: &[u8],
    surface_status: bool,
) -> *mut HttpState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<HttpState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut HttpState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Initialised in place: every buffer starts zeroed and only the scalars
    // need a value, so the state is never composed on the stack first.
    core::ptr::write_bytes(raw, 0, 1);
    let st = &mut *raw;
    st.publish_in = publish_in;
    st.reply_out = reply_out;
    st.file_ctrl = file_ctrl;
    st.handle = -1;
    st.surface_status = surface_status;
    let origin_len = origin.len().min(ORIGIN_MAX);
    st.origin[..origin_len].copy_from_slice(&origin[..origin_len]);
    st.origin_len = origin_len as u16;
    raw
}

/// The `host[:port]` of an origin such as `https://api.example:8443`: what
/// a record's trailing authority is compared against.
fn origin_host(origin: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 2 < origin.len() {
        if &origin[i..i + 3] == b"://" {
            return &origin[i + 3..];
        }
        i += 1;
    }
    origin
}

/// Whether a path names a resource on the origin rather than a place of
/// its own: it starts at the root and carries no scheme.
fn path_ok(path: &[u8]) -> bool {
    if path.first() != Some(&b'/') || path.len() > PATH_MAX {
        return false;
    }
    !path.windows(3).any(|w| w == b"://")
}

/// Compose the one reply this exchange gets and hold it for `reply_out`.
fn answer(st: &mut HttpState, status: u8, payload_len: usize) {
    let key_len = st.key_len as usize;
    let payload_len = payload_len.min(PAYLOAD_MAX);
    let encoded = Reply {
        corr: st.corr,
        status,
        msg_key: &st.key[..key_len],
        payload: &st.reply[..payload_len],
    }
    .encode(&mut st.out[ENVELOPE..]);
    if let Some(n) = encoded {
        st.out[0] = MSG_REPLY;
        st.out[1..ENVELOPE].copy_from_slice(&(n as u16).to_le_bytes());
        st.out_len = (ENVELOPE + n) as u32;
    }
}

/// Release the page's handle, if one is held.
unsafe fn release(st: &mut HttpState) {
    if st.handle >= 0 {
        host_http_close(st.handle);
        st.handle = -1;
    }
}

/// Adopt a decoded publish as the exchange in flight.
fn adopt(st: &mut HttpState, corr: u64, key: &[u8]) {
    let n = key.len().min(KEY_MAX);
    st.key[..n].copy_from_slice(&key[..n]);
    st.key_len = n as u16;
    st.corr = corr;
    st.reply_len = 0;
    st.oversize = false;
    st.body_done = false;
    st.status = 0;
    st.extended = false;
}

/// Refuse the adopted exchange and go to answering.
fn refuse(st: &mut HttpState, status: u8) {
    st.phase = PHASE_ANSWERING;
    answer(st, status, 0);
}

/// Offer the composed reply to `reply_out`. True once it is taken.
unsafe fn flush_reply(st: &mut HttpState) -> bool {
    let n = st.out_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.reply_out, st.out.as_ptr(), n) != n as i32 {
        return false;
    }
    st.out_len = 0;
    if st.phase == PHASE_ANSWERING {
        st.phase = PHASE_IDLE;
        st.corr = 0;
    }
    true
}

/// Offer the framed body chunk to `file_ctrl`. True once it is taken.
unsafe fn flush_chunk(st: &mut HttpState) -> bool {
    let n = st.chunk_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.file_ctrl, st.chunk.as_ptr(), n) != n as i32 {
        return false;
    }
    st.chunk_len = 0;
    if st.body_done {
        st.phase = PHASE_IDLE;
        st.corr = 0;
    }
    true
}

/// Frame `bytes` as the next body chunk. An empty slice ends the body.
fn stage_chunk(st: &mut HttpState, len: usize) {
    let (chunk, scratch) = (&mut st.chunk, &st.scratch);
    if let Some(n) = write_chunk(&scratch[..len], chunk) {
        st.chunk_len = n as u32;
    }
    if len == 0 {
        st.body_done = true;
    }
}

/// Discard `total..stage_len` after a frame was consumed, keeping whatever
/// arrived behind it.
fn consume(st: &mut HttpState, total: usize) {
    let len = st.stage_len as usize;
    let rest = len - total;
    st.stage.copy_within(total..len, 0);
    st.stage_len = rest as u32;
}

/// Take one request off `publish_in`, if a whole one has arrived, and hand
/// it to the page or answer it with a refusal.
///
/// The channel is a byte stream, so frames are assembled here: a read may
/// end mid-frame or carry the start of the next one. A frame wider than the
/// contract's ceiling is drained and dropped so the stream re-aligns on the
/// envelope behind it, and a frame that is not a publish is dropped by its
/// declared length for the same reason.
unsafe fn take_request(st: &mut HttpState) {
    if st.publish_in < 0 {
        return;
    }
    if st.skip > 0 {
        let want = (st.skip as usize).min(STAGE_BYTES);
        let n = channel::channel_read(st.publish_in, st.stage.as_mut_ptr(), want);
        if n > 0 {
            st.skip -= n as u32;
        }
        return;
    }
    let have = st.stage_len as usize;
    if have < STAGE_BYTES {
        let n = channel::channel_read(
            st.publish_in,
            st.stage.as_mut_ptr().add(have),
            STAGE_BYTES - have,
        );
        if n > 0 {
            st.stage_len += n as u32;
        }
    }
    loop {
        let have = st.stage_len as usize;
        if have < ENVELOPE {
            return;
        }
        let msg = st.stage[0];
        let len = usize::from(u16::from_le_bytes([st.stage[1], st.stage[2]]));
        let total = ENVELOPE + len;
        if total > STAGE_BYTES {
            st.skip = (total - have) as u32;
            st.stage_len = 0;
            return;
        }
        if have < total {
            return;
        }
        if msg != MSG_PUBLISH {
            consume(st, total);
            continue;
        }
        let taken = perform(st, total);
        consume(st, total);
        if taken {
            return;
        }
    }
}

/// Decode the publish frame at the head of the stage and act on it. True
/// when the exchange is now in flight or answering, which is when no further
/// frame may be taken.
unsafe fn perform(st: &mut HttpState, total: usize) -> bool {
    // The frame is read through a raw slice so that adopting and answering
    // it — which write the key, the reply and the outbound frame, never the
    // stage — can proceed while its fields are still in use. The stage is
    // consumed only after this returns.
    let frame = core::slice::from_raw_parts(st.stage.as_ptr().add(ENVELOPE), total - ENVELOPE);
    let Some(publish) = Publish::decode(frame) else {
        // Without a correlation there is nobody to answer.
        return false;
    };
    let corr = publish.corr;
    let broadcast = publish.flags & FLAG_BROADCAST != 0;
    let mut key = [0u8; KEY_MAX];
    let key_len = publish.msg_key.len().min(KEY_MAX);
    key[..key_len].copy_from_slice(&publish.msg_key[..key_len]);
    let parsed = parse_request(
        publish.payload,
        &Limits {
            path: PATH_MAX,
            headers: PAYLOAD_MAX,
            body: PAYLOAD_MAX,
        },
    );
    adopt(st, corr, &key[..key_len]);
    // From here every outcome answers: the frame decoded, so the producer is
    // owed exactly one reply.
    let request = match parsed {
        RequestParse::Ok(request) => request,
        RequestParse::Oversize => {
            refuse(st, REFUSE_OVERSIZE);
            return true;
        }
        RequestParse::Malformed => {
            refuse(st, REFUSE_UNROUTABLE);
            return true;
        }
    };
    let method = method_name(request.method);
    // A browser cannot CONNECT, a fan-out to one origin is a delivery that
    // did not happen, a path that names its own host is a request the graph
    // did not authorise, and an extended answer with nowhere to stream the
    // body would be a head with the response dropped behind it.
    if broadcast
        || method.is_empty()
        || request.method == METHOD_CONNECT
        || !path_ok(request.path)
        || (request.extended && st.file_ctrl < 0)
    {
        refuse(st, REFUSE_UNROUTABLE);
        return true;
    }
    st.extended = request.extended;
    // Where the request goes. The record may name its authority in the
    // trailing field: a connector whose `origin` is set dials that and
    // refuses a record naming another host (a pinned client is pinned); a
    // connector with no origin dials the record's, over https — the browser
    // is the resolver, and the page's own cross-origin policy still applies.
    let mut open_origin = [0u8; ORIGIN_MAX];
    let (origin_ptr, origin_len) = if request.authority.is_empty() {
        (st.origin.as_ptr(), st.origin_len as usize)
    } else if st.origin_len > 0 {
        if origin_host(&st.origin[..st.origin_len as usize]) != request.authority {
            refuse(st, REFUSE_UNROUTABLE);
            return true;
        }
        (st.origin.as_ptr(), st.origin_len as usize)
    } else {
        const SCHEME: &[u8] = b"https://";
        let n = SCHEME.len() + request.authority.len();
        if n > ORIGIN_MAX {
            refuse(st, REFUSE_UNROUTABLE);
            return true;
        }
        open_origin[..SCHEME.len()].copy_from_slice(SCHEME);
        open_origin[SCHEME.len()..n].copy_from_slice(request.authority);
        (open_origin.as_ptr(), n)
    };
    let handle = host_http_open(
        method.as_ptr(),
        method.len(),
        origin_ptr,
        origin_len,
        request.path.as_ptr(),
        request.path.len(),
        request.headers.as_ptr(),
        request.headers.len(),
        request.body.as_ptr(),
        request.body.len(),
    );
    if handle < 0 {
        refuse(st, REFUSE_UNROUTABLE);
        return true;
    }
    st.handle = handle;
    st.phase = PHASE_PERFORMING;
    true
}

/// The transport failed. Before the head is answered that is a refusal;
/// after it, the body simply ends, and the empty chunk says so.
unsafe fn fail(st: &mut HttpState) {
    release(st);
    if st.phase == PHASE_STREAMING {
        stage_chunk(st, 0);
        return;
    }
    refuse(st, REFUSE_UNROUTABLE);
}

/// The body has ended. Answer a plain exchange with what accumulated;
/// end an extended one's stream.
unsafe fn finish(st: &mut HttpState) {
    release(st);
    if st.phase == PHASE_STREAMING {
        stage_chunk(st, 0);
        return;
    }
    st.phase = PHASE_ANSWERING;
    if st.oversize {
        answer(st, REFUSE_OVERSIZE, 0);
        return;
    }
    // With status surfacing armed, a 400 or above answers as a refusal
    // carrying the code, so a producer can tell a 503 worth retrying from a
    // 404 worth dropping without knowing the body's shape. Off by default:
    // for most consumers an error body is the answer.
    if st.surface_status && st.status >= 400 {
        st.reply[..2].copy_from_slice(&st.status.to_le_bytes());
        answer(st, REFUSE_UPSTREAM, 2);
        return;
    }
    let len = st.reply_len as usize;
    answer(st, STATUS_OK, len);
}

/// Answer an extended exchange with the response head, whole or not at all:
/// a block clipped to fit would still parse, and a consumer could not tell
/// that the field it wanted is the one that did not fit.
unsafe fn send_head(st: &mut HttpState) {
    let room = PAYLOAD_MAX - RESP_HEAD;
    let n = host_http_head(st.handle, st.scratch.as_mut_ptr(), room);
    if n < 0 || n as usize > room {
        release(st);
        refuse(st, REFUSE_OVERSIZE);
        return;
    }
    let (reply, scratch) = (&mut st.reply, &st.scratch);
    let Some(len) = write_reply_head(st.status, &scratch[..n as usize], reply) else {
        release(st);
        refuse(st, REFUSE_OVERSIZE);
        return;
    };
    st.phase = PHASE_STREAMING;
    answer(st, STATUS_OK, len);
}

/// Move the exchange in flight along: learn the status, answer the head,
/// and carry the body — into the reply for a plain exchange, out as chunks
/// for an extended one.
unsafe fn poll(st: &mut HttpState) {
    if st.phase == PHASE_PERFORMING {
        let status = host_http_status(st.handle);
        if status == -3 {
            return;
        }
        if status < 0 {
            fail(st);
            return;
        }
        st.status = status as u16;
        if st.extended {
            send_head(st);
            return;
        }
    }
    loop {
        let room = if st.phase == PHASE_STREAMING {
            BODY_CHUNK
        } else {
            PAYLOAD_MAX
        };
        let n = host_http_recv(st.handle, st.scratch.as_mut_ptr(), room);
        if n == 0 {
            return;
        }
        if n == -1 {
            finish(st);
            return;
        }
        if n < 0 {
            fail(st);
            return;
        }
        let n = n as usize;
        if st.phase == PHASE_STREAMING {
            stage_chunk(st, n);
            if !flush_chunk(st) {
                return;
            }
            continue;
        }
        // A plain exchange answers with the whole body in one record. An
        // overrun is recorded rather than truncated: a short body that looks
        // complete is the failure a consumer cannot detect.
        let have = st.reply_len as usize;
        if st.oversize || have + n > PAYLOAD_MAX {
            st.oversize = true;
            continue;
        }
        st.reply[have..have + n].copy_from_slice(&st.scratch[..n]);
        st.reply_len = (have + n) as u32;
    }
}

fn http_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this
    // module instance, holding the `*mut HttpState` written by `build`; every
    // buffer touched below lives inside that allocation, and the host
    // imports read only the slices they are handed.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut HttpState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if !flush_reply(st) || !flush_chunk(st) {
            return 0;
        }
        match st.phase {
            PHASE_IDLE => take_request(st),
            PHASE_PERFORMING | PHASE_STREAMING => poll(st),
            _ => {}
        }
        // Whatever the step composed goes out now rather than next tick, so
        // a refusal or a head answers in the step that decided it.
        if flush_reply(st) {
            flush_chunk(st);
        }
        0
    }
}

pub(crate) unsafe fn build(
    origin: &[u8],
    surface_status: bool,
    publish_in: i32,
    reply_out: i32,
    file_ctrl: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_http", http_step);
    let raw = alloc_state(publish_in, reply_out, file_ctrl, origin, surface_status);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut HttpState, raw);
    m
}
