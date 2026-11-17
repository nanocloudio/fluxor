//! `wasm_browser_http` built-in: the browser as an HTTP exchange provider.
//!
//! A provider of the exchange contract (`contracts/exchange.rs`) speaking its
//! HTTP binding (`contracts/exchange_http.rs`): request records arrive on
//! `request_in`, the page's `fetch()` performs each one, and the answer leaves
//! on `response_out` under the request's own exchange id — a response HEAD
//! carrying the status as its detail, the response's header fields as meta
//! and the first body bytes, then BODY records while more of the body
//! arrives, sent only as far as the requester's credit reaches.
//!
//! A request is collected whole before it is performed: `fetch()` takes its
//! body in one piece. A request's target is a path and the `origin` param names
//! where — a request never chooses a host the graph did not name, so a graph
//! moved to a different page keeps working and a program cannot be pointed at
//! a server the graph did not authorise. A request may name its authority in a
//! `host` header: with `origin` set, one naming that origin's host is performed
//! and one naming another is refused; with no `origin`, the named authority is
//! where the request goes, over https. The browser's own cross-origin policy is
//! the enforcement behind both: a fetch the page may not make fails, and a
//! failed fetch is a peer that could not be reached.
//!
//! What it answers itself: 400 for a request it cannot perform (anything but
//! a call with a method, a fan-out, a target that names its own host, a
//! header value that would split its line); 413 for a request past what it collects; 503 when more
//! exchanges arrive at once than it holds; 502 when the fetch fails before the
//! response head, or the head is too large to carry back. A fetch that fails
//! after the head is an ABORT — the body the requester already holds is not the
//! whole answer.
//!
//! One exchange is performed at a time; others wait collected. A graph that
//! wants concurrency instantiates more of these.
//!
//! State: heap-allocated; the `BuiltInModule`'s inline state holds a
//! `*mut HttpState`.

use crate::abi::contracts::exchange::{
    self as ex, abort, flag, op, Collector, ExchangeId, PAYLOAD_MAX, RECORD_MAX, RESP_HEAD_FIXED,
};
use crate::abi::contracts::exchange_http::{
    self as http, header_lines_from_meta, meta_from_header_lines, method_name, status, Http,
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

/// Exchanges collected at once: the one being performed and the ones waiting
/// behind it.
const SLOTS: usize = 2;
/// The largest target a request may name.
const TARGET_MAX: usize = 2048;
/// The largest request meta.
const META_MAX: usize = 2048;
/// The largest origin a graph may name.
const ORIGIN_MAX: usize = 256;
/// Records taken off `request_in` per step.
const RECORDS_PER_STEP: usize = 8;
/// A control record: a CREDIT, or a refusal (a response HEAD without body).
const CTL_MAX: usize = ex::HDR + RESP_HEAD_FIXED + 4;
/// The largest meta a response HEAD can carry beside its fixed part, and the
/// largest header block the page's response head may be. A request's header
/// block is composed in the same buffer before the request goes: a field
/// takes one byte more as a header line than as meta, and is at least four
/// bytes as meta, so `META_MAX` of meta is a block of at most
/// `META_MAX * 5 / 4`.
const PAGE_HEAD_MAX: usize = RECORD_MAX - ex::HDR - RESP_HEAD_FIXED;
const _: () = assert!(META_MAX * 5 / 4 <= PAGE_HEAD_MAX);

type Requests = Collector<Http, SLOTS, TARGET_MAX, META_MAX, PAYLOAD_MAX>;

const PHASE_IDLE: u8 = 0;
/// The request is with the page; nothing has been answered.
const PHASE_PERFORMING: u8 = 1;
/// The response HEAD is composed and gathering its inline body.
const PHASE_HEAD: u8 = 2;
/// The HEAD is away; the body follows in BODY records.
const PHASE_BODY: u8 = 3;

#[repr(C)]
pub(crate) struct HttpState {
    request_in: i32,
    response_out: i32,
    handle: i32,
    phase: u8,
    origin_len: u16,
    /// The collector slot of the exchange being performed, and its id.
    slot: usize,
    id: ExchangeId,
    /// Response-body bytes sent for the exchange being performed.
    sent: u32,
    /// Where the body starts in `out` for the record being composed, and how
    /// many body bytes it holds.
    body_at: u32,
    body_len: u32,
    /// `out` holds a whole record waiting for `response_out`.
    out_len: u32,
    /// `ctl` likewise.
    ctl_len: u32,
    /// Completed requests in arrival order, `(slot, id)`; `queued` of them.
    queue: [(usize, ExchangeId); SLOTS],
    queued: usize,
    origin: [u8; ORIGIN_MAX],
    requests: Requests,
    /// One inbound record.
    rec: [u8; RECORD_MAX],
    /// The request's header block as the page is handed it, then the
    /// response's as the page reports it.
    page_head: [u8; PAGE_HEAD_MAX],
    /// The record being composed for the exchange being performed.
    out: [u8; RECORD_MAX],
    /// A CREDIT or refusal, kept apart so it never waits behind a body.
    ctl: [u8; CTL_MAX],
}

unsafe fn alloc_state(request_in: i32, response_out: i32, origin: &[u8]) -> *mut HttpState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<HttpState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut HttpState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Initialised in place: the buffers start zeroed and only the scalars and
    // the collector need a value, so the state is never composed on the stack.
    core::ptr::write_bytes(raw, 0, 1);
    core::ptr::addr_of_mut!((*raw).requests).write(Requests::new());
    let st = &mut *raw;
    st.request_in = request_in;
    st.response_out = response_out;
    st.handle = -1;
    let origin_len = origin.len().min(ORIGIN_MAX);
    st.origin[..origin_len].copy_from_slice(&origin[..origin_len]);
    st.origin_len = origin_len as u16;
    raw
}

/// The `host[:port]` of an origin such as `https://api.example:8443`: what a
/// request's `host` header is compared against.
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

/// Whether a target names a resource on the origin rather than a place of
/// its own: it starts at the root and carries no scheme.
fn path_ok(path: &[u8]) -> bool {
    if path.first() != Some(&b'/') {
        return false;
    }
    !path.windows(3).any(|w| w == b"://")
}

/// Release the page's handle, if one is held.
unsafe fn release(st: &mut HttpState) {
    if st.handle >= 0 {
        host_http_close(st.handle);
        st.handle = -1;
    }
}

/// The exchange being performed is answered: free everything it held.
unsafe fn finish(st: &mut HttpState) {
    release(st);
    st.requests.release(st.slot);
    st.phase = PHASE_IDLE;
}

/// Offer `ctl` to `response_out`. True once nothing is held there.
unsafe fn flush_ctl(st: &mut HttpState) -> bool {
    let n = st.ctl_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.response_out, st.ctl.as_ptr(), n) > 0 {
        st.ctl_len = 0;
    }
    st.ctl_len == 0
}

/// Offer `out` to `response_out`. True once nothing is held there.
unsafe fn flush_out(st: &mut HttpState) -> bool {
    let n = st.out_len as usize;
    if n == 0 {
        return true;
    }
    if channel::channel_write(st.response_out, st.out.as_ptr(), n) > 0 {
        st.out_len = 0;
    }
    st.out_len == 0
}

/// Refuse an exchange with a status this provider raised, in `out`.
fn answer_status(st: &mut HttpState, id: &ExchangeId, code: u16) {
    if let Some(n) = http::write_refusal(id, code, &mut st.out) {
        st.out_len = n as u32;
    }
}

/// Take what has arrived on `request_in`, answering what the collector owes:
/// the credit that lets a request body come, and a refusal for a request it
/// will not hold.
unsafe fn take_requests(st: &mut HttpState) {
    if st.request_in < 0 {
        return;
    }
    for _ in 0..RECORDS_PER_STEP {
        if !flush_ctl(st) {
            return;
        }
        let n = channel::channel_read(st.request_in, st.rec.as_mut_ptr(), RECORD_MAX);
        if n <= 0 {
            return;
        }
        let (requests, rec) = (&mut st.requests, &st.rec);
        if let Ok(Some(at)) = requests.accept(&rec[..n as usize]) {
            if let Some(req) = requests.request(at) {
                if st.queued < SLOTS {
                    st.queue[st.queued] = (at, req.id);
                    st.queued += 1;
                }
            }
        }
        if let Some((id, bytes)) = st.requests.take_grant() {
            if let Some(len) = ex::write_credit(&id, bytes, &mut st.ctl) {
                st.ctl_len = len as u32;
            }
        }
        if let Some((id, why)) = st.requests.take_refusal() {
            if let Some(len) = ex::write_refusal(&id, why.outcome(), &mut st.ctl) {
                st.ctl_len = len as u32;
            }
        }
    }
}

/// The next collected request still waiting, oldest first. An entry whose
/// slot no longer holds that exchange — aborted while it waited — is skipped.
fn next_request(st: &mut HttpState) -> Option<(usize, ExchangeId)> {
    while st.queued > 0 {
        let (at, id) = st.queue[0];
        st.queue.copy_within(1..st.queued, 0);
        st.queued -= 1;
        if st.requests.request(at).is_some_and(|r| r.id == id) {
            return Some((at, id));
        }
    }
    None
}

/// Hand the next waiting request to the page, or answer it with a refusal.
unsafe fn start(st: &mut HttpState) {
    let Some((at, id)) = next_request(st) else {
        return;
    };
    let Some(req) = st.requests.request(at) else {
        return;
    };
    let method = method_name(req.verb);
    // fetch() performs a call with a method: a publish is not an HTTP
    // request, a session (a CONNECT, an upgrade) has no fetch() to carry it,
    // a fan-out to one origin is a delivery that did not happen, and a target
    // naming its own host is a request the graph did not authorise.
    let block = header_lines_from_meta(req.meta, &mut st.page_head);
    let refused = req.op != op::CALL
        || method.is_empty()
        || req.flags & flag::BROADCAST != 0
        || !path_ok(req.target)
        || block.is_none();
    // Where the request goes: the graph's origin, checked against a `host`
    // the request names; or, with no origin, the named host over https.
    let authority = ex::meta_get(req.meta, b"host").unwrap_or(&[]);
    let origin = &st.origin[..st.origin_len as usize];
    let mut open_origin = [0u8; ORIGIN_MAX];
    let mut open_len = 0usize;
    let routed = if authority.is_empty() || !origin.is_empty() {
        authority.is_empty() || origin_host(origin) == authority
    } else {
        const SCHEME: &[u8] = b"https://";
        open_len = SCHEME.len() + authority.len();
        if open_len <= ORIGIN_MAX {
            open_origin[..SCHEME.len()].copy_from_slice(SCHEME);
            open_origin[SCHEME.len()..open_len].copy_from_slice(authority);
            true
        } else {
            false
        }
    };
    if refused || !routed {
        st.requests.release(at);
        answer_status(st, &id, status::BAD_REQUEST);
        return;
    }
    let (origin_ptr, origin_len) = if open_len > 0 {
        (open_origin.as_ptr(), open_len)
    } else {
        (origin.as_ptr(), origin.len())
    };
    let handle = host_http_open(
        method.as_ptr(),
        method.len(),
        origin_ptr,
        origin_len,
        req.target.as_ptr(),
        req.target.len(),
        st.page_head.as_ptr(),
        block.unwrap_or(0),
        req.body.as_ptr(),
        req.body.len(),
    );
    if handle < 0 {
        st.requests.release(at);
        answer_status(st, &id, status::BAD_GATEWAY);
        return;
    }
    st.handle = handle;
    st.slot = at;
    st.id = id;
    st.sent = 0;
    st.phase = PHASE_PERFORMING;
}

/// Whether the requester still wants the exchange being performed: an ABORT
/// from it frees the slot, and a slot that no longer holds this exchange
/// means nothing more is written for it.
fn still_wanted(st: &HttpState) -> bool {
    st.requests.request(st.slot).is_some_and(|r| r.id == st.id)
}

/// Response-body bytes the requester has granted and not yet received.
fn credit(st: &HttpState) -> usize {
    st.requests
        .request(st.slot)
        .map_or(0, |r| r.resp_credit.saturating_sub(st.sent) as usize)
}

/// The head has arrived: compose the response HEAD in `out`, its body still
/// to come. A header block whose meta does not fit one record, or a status
/// the binding does not carry, is answered 502 — whole or not at all, since a
/// block clipped to fit would still parse and a requester could not tell the
/// field it wanted is the one that was dropped.
unsafe fn compose_head(st: &mut HttpState, code: u16) {
    let n = host_http_head(st.handle, st.page_head.as_mut_ptr(), PAGE_HEAD_MAX);
    let block = if n < 0 {
        None
    } else {
        st.page_head.get(..n as usize)
    };
    let Some(block) = block else {
        let id = st.id;
        finish(st);
        answer_status(st, &id, status::BAD_GATEWAY);
        return;
    };
    // The fields go in place as the HEAD's meta, in the page's order, and the
    // fixed part is sealed in front of them.
    let meta_at = ex::HDR + RESP_HEAD_FIXED;
    let meta_len = meta_from_header_lines(block, &mut st.out[meta_at..]);
    let sealed = match (meta_len, http::outcome_of(code)) {
        (Some(ml), Some(outcome)) => {
            ex::seal_response_in_place::<Http>(&st.id, 0, outcome, code, ml, 0, &mut st.out)
        }
        _ => None,
    };
    let Some(hdrs_at) = sealed else {
        let id = st.id;
        finish(st);
        answer_status(st, &id, status::BAD_GATEWAY);
        return;
    };
    st.body_at = hdrs_at as u32;
    st.body_len = 0;
    st.phase = PHASE_HEAD;
}

/// Pull body bytes from the page into `out` behind `body_at`, as far as the
/// record and the requester's credit allow. Returns the page's last answer:
/// `0` nothing more right now (or no room), `-1` the body ended, `-2` failed.
/// With no room left the page is still asked, for nothing: an empty read
/// takes no bytes and still says whether the body has ended, so a requester
/// out of credit learns of an end it needs no credit for.
unsafe fn gather(st: &mut HttpState) -> i32 {
    loop {
        let at = (st.body_at + st.body_len) as usize;
        let room = (RECORD_MAX - at).min(credit(st).saturating_sub(st.body_len as usize));
        if room == 0 {
            return host_http_recv(
                st.handle,
                st.out.as_mut_ptr().add(at.min(RECORD_MAX - 1)),
                0,
            )
            .min(0);
        }
        let n = host_http_recv(st.handle, st.out.as_mut_ptr().add(at), room);
        if n <= 0 {
            return n;
        }
        st.body_len += n as u32;
    }
}

/// Whether the record being composed has no more room for body bytes, by
/// the record's size or by the requester's credit.
fn record_full(st: &HttpState) -> bool {
    let at = (st.body_at + st.body_len) as usize;
    at >= RECORD_MAX || st.body_len as usize >= credit(st)
}

/// Seal the record in `out` with `flags` and hold it for `response_out`.
fn seal(st: &mut HttpState, more: bool) {
    st.out[1] = if more { flag::MORE } else { 0 };
    st.out_len = st.body_at + st.body_len;
    st.sent = st.sent.saturating_add(st.body_len);
}

/// Move the exchange being performed along: learn the status, answer the
/// HEAD, carry the body.
unsafe fn advance(st: &mut HttpState) {
    if !still_wanted(st) {
        // Aborted by the requester: stop, and write nothing more for it.
        release(st);
        st.out_len = 0;
        st.phase = PHASE_IDLE;
        return;
    }
    if st.phase == PHASE_PERFORMING {
        let code = host_http_status(st.handle);
        if code == -3 {
            return;
        }
        if code < 0 {
            let id = st.id;
            finish(st);
            answer_status(st, &id, status::BAD_GATEWAY);
            return;
        }
        compose_head(st, code as u16);
        if st.phase != PHASE_HEAD {
            return;
        }
    }
    let got = gather(st);
    match st.phase {
        PHASE_HEAD => {
            if got == -1 {
                seal(st, false);
                finish(st);
            } else if got < -1 {
                // The head never left: the requester has heard nothing, so
                // the failure is still a status.
                let id = st.id;
                finish(st);
                answer_status(st, &id, status::BAD_GATEWAY);
            } else if record_full(st) || st.body_len > 0 {
                // The HEAD goes once the body has started and the page has no
                // more right now, or once it is as full as it may be — never
                // holding a response's status back for a body still to come.
                seal(st, true);
                st.phase = PHASE_BODY;
                st.body_at = ex::HDR as u32;
                st.body_len = 0;
            }
        }
        PHASE_BODY => {
            if got == -1 {
                seal_body(st, false);
                finish(st);
            } else if got < -1 {
                // Part of the body is with the requester already; what it
                // holds is not the whole answer.
                let id = st.id;
                finish(st);
                if let Some(n) = ex::write_abort(&id, abort::PEER_GONE, &mut st.out) {
                    st.out_len = n as u32;
                }
            } else if st.body_len > 0 {
                seal_body(st, true);
                st.body_at = ex::HDR as u32;
                st.body_len = 0;
            }
        }
        _ => {}
    }
}

/// Seal a BODY record whose bytes are in place behind the prefix.
fn seal_body(st: &mut HttpState, more: bool) {
    let flags = if more { flag::MORE } else { 0 };
    let len = st.body_len as usize;
    if let Some(n) = ex::seal_body(&st.id, flags, len, &mut st.out) {
        st.out_len = n as u32;
        st.sent = st.sent.saturating_add(len as u32);
    }
}

/// # Safety
/// `state` is this module's own 64-byte state buffer, exclusively the
/// step's for its duration.
unsafe fn http_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this
    // module instance, holding the `*mut HttpState` written by `build`; every
    // buffer touched below lives inside that allocation, and the host
    // imports read and write only the slices they are handed.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut HttpState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        take_requests(st);
        // A record still held means the requester is not reading; nothing
        // further is composed until it is.
        if !flush_ctl(st) || !flush_out(st) {
            return 0;
        }
        match st.phase {
            PHASE_IDLE => start(st),
            PHASE_PERFORMING | PHASE_HEAD | PHASE_BODY => advance(st),
            _ => {}
        }
        // Whatever the step composed goes out now rather than next tick, so
        // a refusal or a head answers in the step that decided it.
        flush_out(st);
        0
    }
}

pub(crate) unsafe fn build(
    origin: &[u8],
    request_in: i32,
    response_out: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_http", http_step);
    let raw = alloc_state(request_in, response_out, origin);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut HttpState, raw);
    m
}
