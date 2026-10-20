//! object_exchange — the exchange front of `storage.object`.
//!
//! An exchange PROVIDER (`modules/sdk/contracts/exchange.rs`): it answers
//! each request on `request_in` by reading or writing objects through the
//! `storage.object` provider the graph binds, and writes the answers to
//! `response_out`. A graph that wires its requester to this module reaches
//! storage through ordinary exchange edges; whether the store is embedded or
//! remote is a placement choice made by the graph, not by the requester.
//!
//! It never holds an object whole. A `GET` streams the object through
//! `RANGE_GET` straight into response records, never past the response credit
//! the requester granted. A `PUT` whose body continues past its HEAD moves to
//! the provider's `PUT_STREAMED_*` sequence chunk by chunk, granting
//! request-body credit only as the stream takes what it was sent.
//!
//! The provider's "not yet" is never an answer: a read that answers `EAGAIN`
//! and a write that answers `EINPROGRESS` are asked again on a later step
//! with the same request, and a streamed chunk the provider pushes back is
//! sent again, whole and first, on a later step.
//!
//! Every exchange is answered exactly once — a terminal response record or
//! an ABORT — and every record leaves through one `ExchangeOutbox`, so a full
//! `response_out` holds the answer rather than dropping it.
//!
//! Given a `scope` and a `capability`, the module presents them to the store
//! (`PRESENT`) once and makes every call under the grant the store answers,
//! for every request. Without them every call names no grant (`-1`). Who may
//! send requests is the graph's wiring; what the requests may do is the
//! grant, which the store checks on each call.
//!
//! The scope is the front's root: a target `/<rest>` names the object
//! `<scope><rest>`, a listing's `prefix` and `after` are taken relative to the
//! scope, and every name a listing answers is written with the scope taken
//! off. Names are opaque bytes, so the concatenation alone keeps every target
//! inside the scope.
//!
//! The surface — targets, headers, statuses, limits — is in `README.md`.

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
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::exchange as ex;
use abi::contracts::mesh::capability as cap;
use abi::contracts::storage::handle::STORAGE_KEY_MAX;
use abi::contracts::storage::object as obj;
use abi::fence::{Fence, WIRE_MAX_LEN};
use abi::kernel_abi::errno;
use ex::{ExchangeId, Record, RECORD_MAX};

// ── Ceilings ──────────────────────────────────────────────────────────────

/// Exchanges served at once. A HEAD that finds every slot taken is refused
/// `503` at once, so a full table never holds back the records of the
/// exchanges it is serving. Each slot carries a window-sized buffer, so an
/// MCU holds two.
pub const EXCHANGE_SLOTS: usize = if abi::config::TARGET_CLASS == abi::config::target_class::HOST {
    16
} else {
    2
};
/// Longest entity tag an `if-match` precondition may name, in bytes (twice
/// that in hex). A longer one is refused `400` rather than cut, since a cut
/// tag names nothing.
pub const ETAG_MAX: usize = 32;
/// Request records one step reads, and response records one step writes.
pub const STEP_RECORD_BUDGET: usize = 16;

/// Longest object name: the contract's key bound.
const NAME_MAX: usize = STORAGE_KEY_MAX;
/// Longest content type: the contract's `u8` length prefix.
const CT_MAX: usize = u8::MAX as usize;
/// Each exchange's own buffer: a streamed put's request-body window (the
/// credit it holds out, and the bytes it keeps while the provider pushes
/// back), a single-shot put's body, a `HEAD` record, or one `LIST` page. One
/// body record's worth.
const WINDOW: usize = ex::BODY_MAX;
const _: () = assert!(
    WINDOW >= RECORD_MAX - ex::HDR - ex::REQ_HEAD_FIXED,
    "a request HEAD's inline body fits the window"
);
const _: () = assert!(
    WINDOW >= obj::list::min_out_cap(NAME_MAX, u8::MAX as usize),
    "a LIST page in the window holds the longest entry"
);
/// A `PUT`, `PUT_STREAMED_OPEN` or `DELETE` request, or a `LIST` request,
/// whichever is longer: kept whole while the provider may be asked again.
const ARG_LEN: usize = {
    let put = 2 + NAME_MAX + 1 + CT_MAX + 8 + 8 + 1 + 1 + ETAG_MAX + 8 + 2;
    let list = obj::list::REQUEST_FIXED_LEN + 2 * NAME_MAX;
    if put > list {
        put
    } else {
        list
    }
};
/// A response's header block: `content-length`, a hex entity tag of the
/// longest a `HEAD` record carries, a hex fence and a `content-range`, or a
/// listing's encoded `next` cursor.
const HEADERS_LEN: usize = 1280;
/// Steps between telemetry reports.
const TLM_PERIOD: u32 = 4096;
/// Longest `scope`: a key prefix, bounded as keys are.
const SCOPE_MAX: usize = obj::grant::SCOPE_MAX;
/// A `PRESENT` request: the refusal byte, the scope and the chain, each
/// behind its length.
const PRESENT_LEN: usize = 1 + 2 + SCOPE_MAX + 2 + cap::MAX_CHAIN_BYTES;

// ── State ─────────────────────────────────────────────────────────────────

/// Where an exchange stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Free,
    /// A bodiless terminal HEAD waits for the outbox: `status`, `raised`,
    /// and the `reply` headers.
    Reply,
    /// An ABORT (`abort_reason`) waits for the outbox.
    Abort,
    /// The object's `HEAD` record is being read (asked again on `EAGAIN`).
    Meta,
    /// The object is being opened for ranged reads (asked again on `EAGAIN`).
    Open,
    /// A read's response goes out: the HEAD, then the body as credit allows.
    Stream,
    /// A single-shot `PUT` is being decided (asked again on `EINPROGRESS`).
    PutOne,
    /// `PUT_STREAMED_OPEN` is asked (again, after "not now").
    PutOpen,
    /// The body moves to the stream.
    PutBody,
    /// The stream is committing (asked again on `EINPROGRESS`).
    PutCommit,
    /// A `DELETE` is being decided (asked again on `EINPROGRESS`).
    Delete,
    /// A `LIST` page is being read (asked again on `EAGAIN`).
    List,
    /// The listing goes out: the HEAD, then its lines as credit allows.
    ListOut,
}

/// Where the module's authority with the store stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Authority {
    /// No capability was given: every call names no grant (`-1`).
    None = 0,
    /// The capability is presented and the store has not decided: asked
    /// again, with the same request, on every step until it does. Requests
    /// wait.
    Presenting,
    /// The store had no room for the grant (`ENOMEM`, `EBUSY`): presented
    /// again, at most once a step, when a request needs the store, and the
    /// request is answered `503` if the store is still busy.
    Busy,
    /// Granted: every call names `grant`.
    Granted,
    /// Refused: every request is answered `403`, and nothing reaches the
    /// store.
    Refused,
}

/// Extra headers a `Reply` carries.
mod reply {
    /// `fence:` — the fence the provider reported.
    pub const FENCE: u8 = 1;
    /// `content-range: bytes */<size>` — an unsatisfiable range.
    pub const RANGE: u8 = 2;
}

/// A request's `range` header, before the object's size is known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RangeSpec {
    Whole,
    /// `bytes=a-` (`None`) or `bytes=a-b`.
    From(u64, Option<u64>),
    /// `bytes=-n`: the last `n` bytes.
    Suffix(u64),
}

struct Exchange {
    phase: Phase,
    id: ExchangeId,
    method: u8,
    /// Response-body bytes the requester has granted and not yet received.
    resp_credit: u32,
    head_sent: bool,
    name: [u8; NAME_MAX],
    name_len: u16,
    // A reply waiting for the outbox.
    status: u16,
    raised: bool,
    reply: u8,
    abort_reason: u8,
    // Reads.
    range: RangeSpec,
    handle: i32,
    offset: u64,
    end: u64,
    size: u64,
    /// The `HEAD` record's length at the front of `buf`.
    head_len: u16,
    // Writes. Every buffer a pending call names by address lives here, so it
    // stays put while the provider is asked again.
    arg: [u8; ARG_LEN],
    arg_len: u16,
    fence: [u8; WIRE_MAX_LEN],
    // A streamed put's body.
    /// Further request-body records are coming.
    body_open: bool,
    /// The body has ended; the stream commits once nothing of it waits.
    put_last: bool,
    /// Request-body credit granted and not yet received.
    credit_out: u32,
    /// Request-body credit owed to the requester and not yet written.
    grant: u32,
    /// Body bytes taken from the requester and not yet by the provider, at
    /// the front of `buf`, in body order.
    stash_len: u32,
    /// Length of the chunk at the stash's front the provider pushed back:
    /// sent again as the same chunk. 0 when none was refused.
    stash_retry: u32,
    /// The step the provider last pushed that chunk back in: it is not asked
    /// again within it.
    refused_at: u32,
    // A listing.
    page_len: u16,
    /// Entries of the page already sent whole.
    list_idx: u16,
    /// Bytes of the current entry's line already sent.
    line_off: u16,
    buf: [u8; WINDOW],
}

impl Exchange {
    /// Ready the slot for a new exchange. The arrays are written before they
    /// are read, so only the scalars and the fence are reset — never a whole
    /// slot through a temporary, which an MCU's stack could not hold.
    fn reset(&mut self) {
        self.phase = Phase::Free;
        self.id = ExchangeId::NONE;
        self.method = 0;
        self.resp_credit = 0;
        self.head_sent = false;
        self.name_len = 0;
        self.status = 0;
        self.raised = false;
        self.reply = 0;
        self.abort_reason = 0;
        self.range = RangeSpec::Whole;
        self.handle = -1;
        self.offset = 0;
        self.end = 0;
        self.size = 0;
        self.head_len = 0;
        self.arg_len = 0;
        self.fence = [0; WIRE_MAX_LEN];
        self.body_open = false;
        self.put_last = false;
        self.credit_out = 0;
        self.grant = 0;
        self.stash_len = 0;
        self.stash_retry = 0;
        self.refused_at = 0;
        self.page_len = 0;
        self.list_idx = 0;
        self.line_off = 0;
    }
}

/// Metric ids, in `[observability].metrics` order.
mod metric {
    pub const REQUESTS: usize = 0;
    pub const BYTES_IN: usize = 1;
    pub const BYTES_OUT: usize = 2;
    pub const ERRORS: usize = 3;
    pub const REFUSED: usize = 4;
    pub const ABORTS: usize = 5;
    pub const COUNT: usize = 6;
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    request_in: i32,
    response_out: i32,
    steps: u32,
    /// Where the next pass over the exchanges starts writing, so one long
    /// response does not starve the others.
    rr: usize,
    /// A request record read and not yet taken: it waits for the outbox.
    held_len: usize,
    /// The record staged in `rout`, and the exchange it belongs to.
    outbox: ExchangeOutbox,
    out_id: ExchangeId,
    tlm: [u64; metric::COUNT],
    rin: [u8; RECORD_MAX],
    rout: [u8; RECORD_MAX],
    hdr: [u8; HEADERS_LEN],
    // The capability.
    auth: Authority,
    /// The grant every call names: the store's answer to `PRESENT`, or `-1`.
    grant: i32,
    /// The step the store last answered the presentation busy in.
    busy_step: u32,
    /// A `scope` or `capability` param past its bound.
    param_over: bool,
    scope_len: u16,
    cap_len: u16,
    scope: [u8; SCOPE_MAX],
    /// The capability's `fxcap1.` text, as given.
    cap_text: [u8; cap::MAX_TEXT_LEN],
    /// The `PRESENT` request, kept whole while the store is asked again.
    present_len: u16,
    present: [u8; PRESENT_LEN],
    ex: [Exchange; EXCHANGE_SLOTS],
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::{cap, SCOPE_MAX};

    define_params! {
        State;
        // The key prefix the capability grants, ending `/`.
        1, scope, str, 0 => |s, d, len| {
            if len > SCOPE_MAX {
                s.param_over = true;
            } else if len > 0 {
                core::ptr::copy_nonoverlapping(d, s.scope.as_mut_ptr(), len);
                s.scope_len = len as u16;
            }
        };
        // The capability chain in its text form (`fxcap1.…`), longer than
        // one entry: each chunk is appended.
        2, capability, str_chunked, 0 => |s, d, len| {
            let at = s.cap_len as usize;
            if at + len > cap::MAX_TEXT_LEN {
                s.param_over = true;
            } else if len > 0 {
                core::ptr::copy_nonoverlapping(d, s.cap_text.as_mut_ptr().add(at), len);
                s.cap_len = (at + len) as u16;
            }
        };
    }
}

// ── Small writers and parsers ─────────────────────────────────────────────

/// Appends to a byte buffer; `over` records that something did not fit, so a
/// header block is never sent short.
struct W<'a> {
    buf: &'a mut [u8],
    len: usize,
    over: bool,
}

impl<'a> W<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        W {
            buf,
            len: 0,
            over: false,
        }
    }

    fn put(&mut self, b: &[u8]) {
        match self.buf.get_mut(self.len..self.len + b.len()) {
            Some(d) => {
                d.copy_from_slice(b);
                self.len += b.len();
            }
            None => self.over = true,
        }
    }

    fn byte(&mut self, b: u8) {
        self.put(&[b]);
    }

    fn dec(&mut self, mut v: u64) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.byte(digits[n]);
        }
    }

    fn hex(&mut self, b: &[u8]) {
        for &c in b {
            self.byte(hex_digit(c >> 4));
            self.byte(hex_digit(c & 0xF));
        }
    }

    /// `name` percent-encoded, whole or not at all.
    fn encoded(&mut self, name: &[u8]) {
        let rest = self.buf.get_mut(self.len..).unwrap_or(&mut []);
        let (n, done) = encode_from(name, 0, rest);
        if done {
            self.len += n;
        } else {
            self.over = true;
        }
    }
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Whether a name byte is written `%XX` in a listing line, a `next` header
/// and a listing query value: the bytes that would end or split one of
/// those, and `%` itself.
fn escaped(c: u8) -> bool {
    c <= 0x20 || c == 0x7F || matches!(c, b'%' | b'&' | b'=' | b'#')
}

/// `name` percent-encoded, skipping the first `skip` encoded bytes, into
/// `out`. Returns `(written, finished)`: `finished` when the encoding ended
/// inside `out`.
fn encode_from(name: &[u8], skip: usize, out: &mut [u8]) -> (usize, bool) {
    let mut at = 0usize;
    let mut w = 0usize;
    for &c in name {
        let piece = if escaped(c) {
            [b'%', hex_digit(c >> 4), hex_digit(c & 0xF)]
        } else {
            [c, 0, 0]
        };
        let plen = if escaped(c) { 3 } else { 1 };
        for &p in piece.get(..plen).unwrap_or(&[]) {
            if at >= skip {
                match out.get_mut(w) {
                    Some(o) => *o = p,
                    None => return (w, false),
                }
                w += 1;
            }
            at += 1;
        }
    }
    (w, true)
}

/// Decode a percent-encoded query value into `out`; its length, or `None`
/// when a `%` is not followed by two hex digits or the value does not fit.
fn percent_decode(v: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut n = 0usize;
    while i < v.len() {
        let c = *v.get(i)?;
        let b = if c == b'%' {
            let h = hex_val(*v.get(i + 1)?)?;
            let l = hex_val(*v.get(i + 2)?)?;
            i += 3;
            (h << 4) | l
        } else {
            i += 1;
            c
        };
        *out.get_mut(n)? = b;
        n += 1;
    }
    Some(n)
}

/// A decimal `u64`: digits only, no sign; `None` for anything else.
fn digits(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 {
        return None;
    }
    let mut n = 0u64;
    for &c in v {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    Some(n)
}

/// A `range` header value: one `bytes=` range. `None` for any other form,
/// a list of ranges included.
fn parse_range(v: &[u8]) -> Option<RangeSpec> {
    let spec = v.strip_prefix(b"bytes=")?;
    let dash = spec.iter().position(|&c| c == b'-')?;
    let (a, b) = (spec.get(..dash)?, spec.get(dash + 1..)?);
    if a.is_empty() {
        return Some(RangeSpec::Suffix(digits(b)?));
    }
    let a = digits(a)?;
    if b.is_empty() {
        return Some(RangeSpec::From(a, None));
    }
    let b = digits(b)?;
    if b < a {
        return None;
    }
    Some(RangeSpec::From(a, Some(b)))
}

/// The status a provider's refusal answers. Each is the storage provider's
/// own answer, so none is marked RAISED.
fn status_of(rc: i32, write: bool) -> u16 {
    match rc {
        errno::ENXIO | errno::ENOENT => 404,
        errno::EEXIST => 412,
        // On a write's decision, `EAGAIN` is a lost `ETAG` precondition.
        errno::EAGAIN if write => 412,
        errno::EACCES => 403,
        errno::EINVAL => ex::status::BAD_REQUEST,
        errno::E2BIG | errno::ENOSPC => ex::status::TOO_LARGE,
        errno::EBUSY | errno::ENOMEM | errno::EAGAIN => ex::status::BUSY,
        errno::ENOSYS | errno::ENOTSUP => 501,
        _ => ex::status::FAILED,
    }
}

// ── Entry points ──────────────────────────────────────────────────────────

declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
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
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    // SAFETY: the loader hands a block of at least `State`'s size, zeroed
    // here before it is read as a `State`; every field is valid at all-zero
    // bytes.
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.request_in = in_chan;
        s.response_out = out_chan;
        s.outbox = ExchangeOutbox::new();
        for e in s.ex.iter_mut() {
            e.reset();
        }
        s.grant = -1;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        }
        if let Err(why) = bind(s) {
            log(s, why);
            return -3;
        }
    }
    0
}

/// Check the `scope` and `capability` params and lay out the `PRESENT`
/// request they make. Both or neither: with neither the module has no
/// capability, and every call names no grant. A refusal names what is wrong.
fn bind(s: &mut State) -> Result<(), &'static [u8]> {
    if s.param_over {
        return Err(b"[object_exchange] scope or capability is longer than its bound");
    }
    let (sl, cl) = (usize::from(s.scope_len), usize::from(s.cap_len));
    match (sl > 0, cl > 0) {
        (false, false) => return Ok(()),
        (true, true) => {}
        _ => {
            return Err(b"[object_exchange] scope and capability are given together or not at all")
        }
    }
    let scope = s.scope.get(..sl).unwrap_or(&[]);
    if !obj::grant::valid_scope(scope) {
        return Err(b"[object_exchange] scope is not a key prefix ending `/`");
    }
    // [refusal][scope_len][scope][chain_len][chain], the chain decoded in
    // place.
    let at = 3 + sl;
    let text = s.cap_text.get(..cl).unwrap_or(&[]);
    let Some(chain_out) = s.present.get_mut(at + 2..) else {
        return Err(b"[object_exchange] capability is not fxcap1 text");
    };
    let Some(n) = cap::decode_text(text, chain_out) else {
        return Err(b"[object_exchange] capability is not fxcap1 text");
    };
    if cap::Chain::parse(chain_out.get(..n).unwrap_or(&[])).is_err() {
        return Err(b"[object_exchange] capability is not a capability chain");
    }
    s.present[0] = 0;
    s.present[1..3].copy_from_slice(&(sl as u16).to_le_bytes());
    s.present[3..at].copy_from_slice(scope);
    s.present[at..at + 2].copy_from_slice(&(n as u16).to_le_bytes());
    s.present_len = (at + 2 + n) as u16;
    s.auth = Authority::Presenting;
    Ok(())
}

/// Ask the store again about a presentation it has not decided, once a
/// step, before any request is driven.
unsafe fn authorize(s: &mut State) {
    if s.auth == Authority::Presenting {
        present(s);
    }
}

/// Present the capability and settle what every request runs under. "Not
/// yet" (`EAGAIN`, `EINPROGRESS`) is asked again on the next step with the
/// same request. A refusal — the chain refused (`EACCES`), a store that
/// keeps no authority (`ENOSYS`), anything else but a busy store — is final
/// and logged once.
unsafe fn present(s: &mut State) {
    s.present[obj::grant::REFUSAL_AT] = 0;
    let len = usize::from(s.present_len);
    let rc = call(s.syscalls, -1, obj::PRESENT, s.present.as_mut_ptr(), len);
    s.auth = match rc {
        errno::EAGAIN | errno::EINPROGRESS => Authority::Presenting,
        errno::ENOMEM | errno::EBUSY => {
            s.busy_step = s.steps;
            Authority::Busy
        }
        h if h >= 0 => {
            s.grant = h;
            Authority::Granted
        }
        errno::ENOSYS => {
            log(
                s,
                b"[object_exchange] the store keeps no authority, so the capability would be \
                  enforced by nothing; every request is refused 403",
            );
            Authority::Refused
        }
        _ => {
            log(
                s,
                b"[object_exchange] the store refused the capability; every request is refused 403",
            );
            Authority::Refused
        }
    };
}

/// Whether an exchange in `phase` waits on a call to the store.
fn awaits_store(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Meta
            | Phase::Open
            | Phase::PutOne
            | Phase::PutOpen
            | Phase::PutBody
            | Phase::PutCommit
            | Phase::Delete
            | Phase::List
    )
}

unsafe fn log(s: &State, msg: &[u8]) {
    dev_log(&*s.syscalls, 2, msg.as_ptr(), msg.len());
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: the kernel passes the state it validated in `module_new` and
    // steps this module single-threaded.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    s.steps = s.steps.wrapping_add(1);
    // SAFETY: every syscall below goes through the table set in `module_new`.
    unsafe {
        flush(s);
        authorize(s);
        take_records(s);
        for i in 0..EXCHANGE_SLOTS {
            drive(s, i);
        }
        emit(s);
        report(s);
    }
    0
}

/// Release every provider handle an exchange still holds: a streamed put is
/// aborted, a read handle closed.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_destroy(state: *mut u8) {
    if state.is_null() {
        return;
    }
    // SAFETY: as in `module_step`; the kernel destroys a module it stepped.
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return;
    }
    for i in 0..EXCHANGE_SLOTS {
        // SAFETY: the syscall table was set in `module_new`.
        unsafe { release(s, i) };
    }
    if s.auth == Authority::Granted {
        // SAFETY: as above. `CLOSE` on a grant drops it.
        unsafe { call(s.syscalls, s.grant, obj::CLOSE, core::ptr::null_mut(), 0) };
        s.grant = -1;
    }
}

// ── Telemetry ─────────────────────────────────────────────────────────────

unsafe fn report(s: &mut State) {
    if !s.steps.is_multiple_of(TLM_PERIOD) {
        return;
    }
    let sys = &*s.syscalls;
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    for (id, v) in s.tlm.iter().enumerate() {
        dev_telemetry_metric(sys, -1, me as u16, t, counter, id as u16, *v);
    }
}

fn count(s: &mut State, m: usize, n: u64) {
    if let Some(v) = s.tlm.get_mut(m) {
        *v = v.wrapping_add(n);
    }
}

// ── Provider calls ────────────────────────────────────────────────────────

unsafe fn call(sys: *const SyscallTable, handle: i32, op: u32, arg: *mut u8, len: usize) -> i32 {
    ((*sys).provider_call)(handle, op, arg, len)
}

/// Release whatever provider handle exchange `i` holds: a streamed put is
/// aborted (nothing of it lands), a read handle is closed.
unsafe fn release(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    if e.handle < 0 {
        return;
    }
    let op = match e.phase {
        Phase::PutBody | Phase::PutCommit => obj::PUT_STREAMED_ABORT,
        _ => obj::CLOSE,
    };
    call(s.syscalls, e.handle, op, core::ptr::null_mut(), 0);
    e.handle = -1;
}

/// End exchange `i` with a bodiless terminal HEAD, sent once the outbox is
/// clear. After its response has begun, the exchange is aborted instead.
unsafe fn finish(s: &mut State, i: usize, status: u16, raised: bool, headers: u8) {
    release(s, i);
    let e = &mut s.ex[i];
    if e.head_sent {
        e.abort_reason = ex::abort::FAILED;
        e.phase = Phase::Abort;
        return;
    }
    e.status = status;
    e.raised = raised;
    e.reply = headers;
    e.phase = Phase::Reply;
}

/// End exchange `i` with an ABORT, sent once the outbox is clear.
unsafe fn abort_with(s: &mut State, i: usize, reason: u8) {
    release(s, i);
    s.ex[i].abort_reason = reason;
    s.ex[i].phase = Phase::Abort;
}

fn free(s: &mut State, i: usize) {
    s.ex[i].phase = Phase::Free;
    s.ex[i].handle = -1;
}

// ── Outbound ──────────────────────────────────────────────────────────────

/// Place the held record, if any.
unsafe fn flush(s: &mut State) {
    let sys = &*s.syscalls;
    s.outbox.flush(sys, s.response_out, &s.rout);
}

/// Send the `len`-byte record staged in `rout` for exchange `id`: placed now,
/// or held and placed on a later step.
unsafe fn send(s: &mut State, id: ExchangeId, len: usize) {
    let sys = &*s.syscalls;
    s.out_id = id;
    s.outbox.send(sys, s.response_out, &s.rout, len);
}

/// Write every record owed, as far as the outbox and the step's budget allow,
/// one record per exchange per pass.
unsafe fn emit(s: &mut State) {
    let mut sent = 0usize;
    loop {
        let mut progress = false;
        for k in 0..EXCHANGE_SLOTS {
            if s.outbox.holding() || sent >= STEP_RECORD_BUDGET {
                return;
            }
            let i = (s.rr + k) % EXCHANGE_SLOTS;
            if emit_one(s, i) {
                progress = true;
                sent += 1;
            }
        }
        s.rr = (s.rr + 1) % EXCHANGE_SLOTS;
        if !progress {
            return;
        }
    }
}

/// Stage and send exchange `i`'s next record, if it owes one. True when a
/// record was sent or is held.
unsafe fn emit_one(s: &mut State, i: usize) -> bool {
    match s.ex[i].phase {
        Phase::Reply => {
            emit_reply(s, i);
            true
        }
        Phase::Abort => {
            emit_abort(s, i);
            true
        }
        Phase::Stream => emit_stream(s, i),
        Phase::ListOut => emit_list(s, i),
        Phase::PutBody if s.ex[i].grant > 0 && s.ex[i].stash_len == 0 => {
            let e = &mut s.ex[i];
            let (id, grant) = (e.id, e.grant);
            e.credit_out = e.credit_out.saturating_add(grant);
            e.grant = 0;
            match ex::write_credit(&id, grant, &mut s.rout) {
                Some(n) => {
                    send(s, id, n);
                    true
                }
                None => false,
            }
        }
        _ => false,
    }
}

/// The `fence:` header for the fence in `fence`, when it decodes.
fn put_fence(w: &mut W<'_>, fence: &[u8; WIRE_MAX_LEN]) {
    if let Some((_, n)) = Fence::decode(fence) {
        w.put(b"fence: ");
        w.hex(fence.get(..n).unwrap_or(&[]));
        w.put(b"\r\n");
    }
}

unsafe fn emit_reply(s: &mut State, i: usize) {
    let e = &s.ex[i];
    let (id, status, raised, flags, size) = (e.id, e.status, e.raised, e.reply, e.size);
    let mut w = W::new(&mut s.hdr);
    if flags & reply::FENCE != 0 {
        put_fence(&mut w, &e.fence);
    }
    if flags & reply::RANGE != 0 {
        w.put(b"content-range: bytes */");
        w.dec(size);
        w.put(b"\r\n");
    }
    let hl = if w.over { 0 } else { w.len };
    if status >= 400 {
        count(s, metric::ERRORS, 1);
    }
    free(s, i);
    let head = ex::ResponseHead {
        id,
        flags: if raised { ex::flag::RAISED } else { 0 },
        status,
        content_type: &[],
        headers: s.hdr.get(..hl).unwrap_or(&[]),
        body: &[],
    };
    if let Some(n) = ex::write_response_head(&head, &mut s.rout) {
        send(s, id, n);
    }
}

unsafe fn emit_abort(s: &mut State, i: usize) {
    let (id, reason) = (s.ex[i].id, s.ex[i].abort_reason);
    count(s, metric::ERRORS, 1);
    free(s, i);
    if let Some(n) = ex::write_abort(&id, reason, &mut s.rout) {
        send(s, id, n);
    }
}

/// Read object bytes `[offset, offset + want)` through `RANGE_GET` into
/// `out`. `Ok(n)` with fewer bytes than asked when the provider answered "not
/// yet"; `Err` when the read failed or the object ended early.
unsafe fn read_range(
    sys: *const SyscallTable,
    handle: i32,
    offset: u64,
    out: *mut u8,
    want: usize,
) -> Result<usize, ()> {
    let mut got = 0usize;
    while got < want {
        let mut arg = [0u8; 20];
        arg[..8].copy_from_slice(&(offset + got as u64).to_le_bytes());
        arg[8..12].copy_from_slice(&((want - got) as u32).to_le_bytes());
        arg[12..20].copy_from_slice(&(out.add(got) as u64).to_le_bytes());
        let rc = call(sys, handle, obj::RANGE_GET, arg.as_mut_ptr(), arg.len());
        if rc == errno::EAGAIN {
            break;
        }
        if rc <= 0 {
            return Err(());
        }
        got += rc as usize;
    }
    Ok(got)
}

/// A read's response: the HEAD first, carrying as much of the body as credit
/// and the record allow, then BODY records as credit arrives.
unsafe fn emit_stream(s: &mut State, i: usize) -> bool {
    if !s.ex[i].head_sent {
        return emit_stream_head(s, i);
    }
    let e = &s.ex[i];
    let left = e.end - e.offset;
    let want = left.min(u64::from(e.resp_credit)).min(ex::BODY_MAX as u64) as usize;
    if want == 0 {
        return false;
    }
    let (id, handle, offset) = (e.id, e.handle, e.offset);
    let out = s.rout.as_mut_ptr().add(ex::HDR);
    let got = match read_range(s.syscalls, handle, offset, out, want) {
        Ok(0) => return false,
        Ok(n) => n,
        Err(()) => {
            abort_with(s, i, ex::abort::FAILED);
            emit_abort(s, i);
            return true;
        }
    };
    let e = &mut s.ex[i];
    e.offset += got as u64;
    e.resp_credit -= got as u32;
    let last = e.offset == e.end;
    let flags = if last { 0 } else { ex::flag::MORE };
    let Some(n) = ex::seal_body(&id, flags, got, &mut s.rout) else {
        abort_with(s, i, ex::abort::FAILED);
        emit_abort(s, i);
        return true;
    };
    count(s, metric::BYTES_OUT, got as u64);
    if last {
        release(s, i);
        free(s, i);
    }
    send(s, id, n);
    true
}

/// The response HEAD of a read: its status, the object's content type, and
/// `content-length`, `etag`, `fence` and (for a range) `content-range`.
unsafe fn emit_stream_head(s: &mut State, i: usize) -> bool {
    let head_len = usize::from(s.ex[i].head_len);
    // The record is in the exchange's own buffer, which nothing below writes.
    let record: &[u8] = core::slice::from_raw_parts(s.ex[i].buf.as_ptr(), head_len);
    let Some((_, ct, etag)) = obj::range::decode_head(record) else {
        finish(s, i, ex::status::FAILED, true, 0);
        emit_reply(s, i);
        return true;
    };
    let e = &s.ex[i];
    let partial = e.range != RangeSpec::Whole;
    let mut w = W::new(&mut s.hdr);
    w.put(b"content-length: ");
    w.dec(e.end - e.offset);
    w.put(b"\r\n");
    if !etag.is_empty() {
        w.put(b"etag: ");
        w.hex(etag);
        w.put(b"\r\n");
    }
    put_fence(&mut w, &e.fence);
    if partial {
        w.put(b"content-range: bytes ");
        w.dec(e.offset);
        w.byte(b'-');
        w.dec(e.end.saturating_sub(1));
        w.byte(b'/');
        w.dec(e.size);
        w.put(b"\r\n");
    }
    let (hl, over) = (w.len, w.over);
    let id = e.id;
    let head = ex::ResponseHead {
        id,
        flags: 0,
        status: if partial { 206 } else { 200 },
        content_type: ct,
        headers: s.hdr.get(..hl).unwrap_or(&[]),
        body: &[],
    };
    let written = if over {
        None
    } else {
        ex::write_response_head(&head, &mut s.rout)
    };
    let Some(n) = written else {
        finish(s, i, ex::status::FAILED, true, 0);
        emit_reply(s, i);
        return true;
    };
    let e = &s.ex[i];
    let left = e.end - e.offset;
    let has_body = e.method != ex::METHOD_HEAD && left > 0;
    let want = if has_body {
        left.min(u64::from(e.resp_credit))
            .min((RECORD_MAX - n) as u64) as usize
    } else {
        0
    };
    let (handle, offset) = (e.handle, e.offset);
    let out = s.rout.as_mut_ptr().add(n);
    let got = if want > 0 {
        match read_range(s.syscalls, handle, offset, out, want) {
            Ok(g) => g,
            Err(()) => {
                finish(s, i, ex::status::FAILED, true, 0);
                emit_reply(s, i);
                return true;
            }
        }
    } else {
        0
    };
    let e = &mut s.ex[i];
    e.head_sent = true;
    e.offset += got as u64;
    e.resp_credit -= got as u32;
    let last = !has_body || e.offset == e.end;
    if let Some(f) = s.rout.get_mut(1) {
        *f = if last { 0 } else { ex::flag::MORE };
    }
    count(s, metric::BYTES_OUT, got as u64);
    if last {
        release(s, i);
        free(s, i);
    }
    send(s, id, n + got);
    true
}

/// Lines of `page` from entry `idx`, `line_off` bytes into its line, into
/// `out`: each name with its first `root` bytes (the scope) taken off,
/// percent-encoded and ended by `\n`. Returns `(written, idx, line_off)`
/// where it stopped.
fn render_lines(
    page: &obj::list::Page<'_>,
    root: usize,
    mut idx: usize,
    mut line_off: usize,
    out: &mut [u8],
) -> (usize, usize, usize) {
    let mut w = 0usize;
    for entry in page.entries().skip(idx) {
        let name = entry.key.get(root..).unwrap_or(&[]);
        let (n, done) = encode_from(name, line_off, out.get_mut(w..).unwrap_or(&mut []));
        w += n;
        line_off += n;
        if !done {
            break;
        }
        match out.get_mut(w) {
            Some(b) => *b = b'\n',
            None => break,
        }
        w += 1;
        idx += 1;
        line_off = 0;
    }
    (w, idx, line_off)
}

/// A listing's response: the HEAD (with the fence the page was read at, and
/// `next` when the page is not the last), then one percent-encoded name per
/// line, as credit allows.
unsafe fn emit_list(s: &mut State, i: usize) -> bool {
    let e = &s.ex[i];
    let id = e.id;
    let first = !e.head_sent;
    // The page is in the exchange's own buffer, which nothing below writes.
    let page_bytes: &[u8] = core::slice::from_raw_parts(e.buf.as_ptr(), usize::from(e.page_len));
    let Some(page) = obj::list::decode_page(page_bytes) else {
        finish(s, i, ex::status::FAILED, true, 0);
        emit_reply(s, i);
        return true;
    };
    let at = if first {
        let mut w = W::new(&mut s.hdr);
        put_fence(&mut w, &e.fence);
        if !page.is_last() {
            w.put(b"next: ");
            w.encoded(page.cursor().get(usize::from(s.scope_len)..).unwrap_or(&[]));
            w.put(b"\r\n");
        }
        let (hl, over) = (w.len, w.over);
        let head = ex::ResponseHead {
            id,
            flags: 0,
            status: 200,
            content_type: b"text/plain",
            headers: s.hdr.get(..hl).unwrap_or(&[]),
            body: &[],
        };
        let written = if over {
            None
        } else {
            ex::write_response_head(&head, &mut s.rout)
        };
        let Some(n) = written else {
            finish(s, i, ex::status::FAILED, true, 0);
            emit_reply(s, i);
            return true;
        };
        n
    } else {
        ex::HDR
    };
    let e = &s.ex[i];
    let room = (RECORD_MAX - at).min(e.resp_credit as usize);
    let out = s.rout.get_mut(at..at + room).unwrap_or(&mut []);
    let (w, idx, line_off) = render_lines(
        &page,
        usize::from(s.scope_len),
        usize::from(e.list_idx),
        usize::from(e.line_off),
        out,
    );
    if !first && w == 0 {
        return false;
    }
    let done = idx >= usize::from(page.count());
    let e = &mut s.ex[i];
    e.list_idx = idx as u16;
    e.line_off = line_off as u16;
    e.resp_credit -= w as u32;
    e.head_sent = true;
    let flags = if done { 0 } else { ex::flag::MORE };
    let len = if first {
        if let Some(f) = s.rout.get_mut(1) {
            *f = flags;
        }
        at + w
    } else {
        match ex::seal_body(&id, flags, w, &mut s.rout) {
            Some(n) => n,
            None => {
                abort_with(s, i, ex::abort::FAILED);
                emit_abort(s, i);
                return true;
            }
        }
    };
    count(s, metric::BYTES_OUT, w as u64);
    if done {
        free(s, i);
    }
    send(s, id, len);
    true
}

// ── Records in ────────────────────────────────────────────────────────────

/// Read request records and hand each to its exchange. A record that needs
/// the outbox while it is full — the refusal of a HEAD no slot can take —
/// stays read, and is taken on a later step before anything else is read.
unsafe fn take_records(s: &mut State) {
    let sys = &*s.syscalls;
    for _ in 0..STEP_RECORD_BUDGET {
        if s.held_len == 0 {
            let ready = (sys.channel_poll)(s.request_in, POLL_IN);
            if ready <= 0 || (ready as u32 & POLL_IN) == 0 {
                return;
            }
            let n = (sys.channel_read)(s.request_in, s.rin.as_mut_ptr(), RECORD_MAX);
            if n <= 0 {
                return;
            }
            s.held_len = n as usize;
        }
        if !take(s) {
            return;
        }
        s.held_len = 0;
    }
}

fn find(s: &State, id: &ExchangeId) -> Option<usize> {
    s.ex.iter()
        .position(|e| e.phase != Phase::Free && e.id == *id)
}

/// Drop the record the outbox holds when it belongs to exchange `id`: the
/// requester ended that exchange, or issued it again.
fn withdraw(s: &mut State, id: &ExchangeId) {
    if s.outbox.holding() && s.out_id == *id {
        s.outbox = ExchangeOutbox::new();
    }
}

/// Answer `id` at once with a refusal raised here. False when the outbox is
/// full, and the record that needs it must wait.
unsafe fn refuse_now(s: &mut State, id: ExchangeId, status: u16) -> bool {
    if s.outbox.holding() {
        return false;
    }
    count(s, metric::ERRORS, 1);
    if let Some(n) = ex::write_refusal(&id, status, &mut s.rout) {
        send(s, id, n);
    }
    true
}

/// Take the held request record. False when it must wait for the outbox.
unsafe fn take(s: &mut State) -> bool {
    // The record stays in `rin` until it is taken; nothing below reads into
    // `rin`.
    let raw: &[u8] = core::slice::from_raw_parts(s.rin.as_ptr(), s.held_len);
    let Some(rec) = ex::parse_request(raw) else {
        // A HEAD whose lengths disagree with its record still names its
        // exchange, and is owed an answer; anything else malformed has
        // nowhere to send one.
        if ex::record_kind(raw) == Some(ex::kind::HEAD) {
            if let Some(id) = ex::record_id(raw) {
                return refuse_now(s, id, ex::status::BAD_REQUEST);
            }
        }
        return true;
    };
    match rec {
        Record::Head(h) => {
            // A HEAD under an id already in use issues that exchange again:
            // the newer request is the one answered, so a record still held
            // for the earlier issue is withdrawn, as for an ABORT.
            withdraw(s, &h.id);
            let Some(i) =
                s.ex.iter()
                    .position(|e| e.phase != Phase::Free && e.id == h.id)
                    .or_else(|| s.ex.iter().position(|e| e.phase == Phase::Free))
            else {
                if !refuse_now(s, h.id, ex::status::BUSY) {
                    return false;
                }
                count(s, metric::REFUSED, 1);
                return true;
            };
            // A repeat HEAD for an exchange already open restarts it in its
            // own slot.
            release(s, i);
            count(s, metric::REQUESTS, 1);
            begin(s, i, &h);
            true
        }
        Record::Body { id, flags, data } => {
            if let Some(i) = find(s, &id) {
                body(s, i, data, flags & ex::flag::MORE == 0);
            }
            true
        }
        Record::Credit { id, bytes } => {
            if let Some(i) = find(s, &id) {
                s.ex[i].resp_credit = s.ex[i].resp_credit.saturating_add(bytes);
            }
            true
        }
        Record::Abort { id, .. } => {
            // Nothing is written for an exchange after its requester ends it.
            withdraw(s, &id);
            if let Some(i) = find(s, &id) {
                count(s, metric::ABORTS, 1);
                release(s, i);
                free(s, i);
            }
            true
        }
        Record::Datagram { .. } | Record::Link { .. } => true,
    }
}

// ── Opening an exchange ───────────────────────────────────────────────────

/// What a request target asks for.
enum Target<'a> {
    /// `/<name>`.
    Object(&'a [u8]),
    /// `/?<query>`.
    List(&'a [u8]),
}

/// The target's name below the scope, or its listing query. `None` for a
/// target this module cannot route: one not starting `/`, an empty name, or a
/// name longer than `room`, what the contract's key bound leaves after the
/// scope.
fn route(target: &[u8], room: usize) -> Option<Target<'_>> {
    let rest = target.strip_prefix(b"/")?;
    if let Some(q) = rest.strip_prefix(b"?") {
        return Some(Target::List(q));
    }
    if rest.is_empty() || rest.len() > room {
        return None;
    }
    Some(Target::Object(rest))
}

/// Open exchange `i` for a request HEAD and start the operation it asks for.
unsafe fn begin(s: &mut State, i: usize, h: &ex::RequestHead<'_>) {
    let e = &mut s.ex[i];
    e.reset();
    e.phase = Phase::Reply;
    e.id = h.id;
    e.method = h.method;
    e.resp_credit = h.resp_credit;
    let more = h.flags & ex::flag::MORE != 0;
    let refused_flags = ex::flag::WEBSOCKET | ex::flag::WEBTRANSPORT | ex::flag::BROADCAST;
    if h.flags & refused_flags != 0 {
        return finish(s, i, ex::status::BAD_REQUEST, true, 0);
    }
    let sl = usize::from(s.scope_len);
    let outcome = match (h.method, route(h.target, NAME_MAX - sl)) {
        (ex::METHOD_GET, Some(Target::List(q))) => begin_list(s, i, q),
        // `/?…` is the listing's own target, so no object name starts `?`.
        (_, Some(Target::List(_))) | (_, None) => Err(ex::status::BAD_REQUEST),
        (method, Some(Target::Object(rest))) => {
            // The object is `<scope><rest>`: the scope is the front's root.
            let e = &mut s.ex[i];
            e.name[..sl].copy_from_slice(&s.scope[..sl]);
            e.name[sl..sl + rest.len()].copy_from_slice(rest);
            e.name_len = (sl + rest.len()) as u16;
            match method {
                ex::METHOD_GET | ex::METHOD_HEAD => begin_read(s, i, h.headers),
                ex::METHOD_PUT => begin_put(s, i, h.headers, h.body, more),
                ex::METHOD_DELETE => begin_delete(s, i, h.headers),
                _ => Err(ex::status::BAD_REQUEST),
            }
        }
    };
    if let Err(status) = outcome {
        finish(s, i, status, true, 0);
    }
}

fn begin_read(s: &mut State, i: usize, headers: &[u8]) -> Result<(), u16> {
    let e = &mut s.ex[i];
    e.range = match ex::header(headers, b"range") {
        Some(v) if e.method == ex::METHOD_GET => parse_range(v).ok_or(ex::status::BAD_REQUEST)?,
        _ => RangeSpec::Whole,
    };
    e.phase = Phase::Meta;
    Ok(())
}

/// The precondition a write's headers state: `if-none-match: *` is ABSENT,
/// `if-match: <hex etag>` (quoted or not) is ETAG, neither is ANY. The etag
/// goes into `etag`; returns `(precondition, etag_len)`.
fn precondition(
    headers: &[u8],
    allow_absent: bool,
    etag: &mut [u8; ETAG_MAX],
) -> Result<(u8, usize), u16> {
    let bad = ex::status::BAD_REQUEST;
    match (
        ex::header(headers, b"if-none-match"),
        ex::header(headers, b"if-match"),
    ) {
        (Some(_), Some(_)) => Err(bad),
        (Some(b"*"), None) if allow_absent => Ok((obj::precondition::ABSENT, 0)),
        (Some(_), None) => Err(bad),
        (None, Some(v)) => {
            let hex = v
                .strip_prefix(b"\"")
                .and_then(|v| v.strip_suffix(b"\""))
                .unwrap_or(v);
            if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 2 * ETAG_MAX {
                return Err(bad);
            }
            for (k, pair) in hex.chunks(2).enumerate() {
                let h = pair.first().and_then(|&c| hex_val(c));
                let l = pair.get(1).and_then(|&c| hex_val(c));
                match (h, l, etag.get_mut(k)) {
                    (Some(h), Some(l), Some(o)) => *o = (h << 4) | l,
                    _ => return Err(bad),
                }
            }
            Ok((obj::precondition::ETAG, hex.len() / 2))
        }
        (None, None) => Ok((obj::precondition::ANY, 0)),
    }
}

/// Lays out a provider request in an exchange's `arg`.
struct ArgW<'a> {
    arg: &'a mut [u8; ARG_LEN],
    at: usize,
}

impl ArgW<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), u16> {
        let d = self
            .arg
            .get_mut(self.at..self.at + b.len())
            .ok_or(ex::status::FAILED)?;
        d.copy_from_slice(b);
        self.at += b.len();
        Ok(())
    }
}

/// A put: single-shot when the HEAD carries the whole body, streamed when
/// the body continues (`more`). `content-type` is stored with the object,
/// `content-length` is the streamed put's size hint, and `if-none-match: *`
/// or `if-match` make the write conditional.
fn begin_put(
    s: &mut State,
    i: usize,
    headers: &[u8],
    inline: &[u8],
    more: bool,
) -> Result<(), u16> {
    let bad = ex::status::BAD_REQUEST;
    let ct = ex::header(headers, b"content-type").unwrap_or(b"");
    if ct.len() > CT_MAX {
        return Err(bad);
    }
    let mut etag = [0u8; ETAG_MAX];
    let (pre, etag_len) = precondition(headers, true, &mut etag)?;
    let expected = match ex::header(headers, b"content-length") {
        Some(v) => digits(v).ok_or(bad)?,
        None => 0,
    };
    if inline.len() > WINDOW {
        return Err(ex::status::TOO_LARGE);
    }
    count(s, metric::BYTES_IN, inline.len() as u64);
    let e = &mut s.ex[i];
    // The body taken so far: a single-shot put's whole body, or the first
    // bytes of a streamed one, kept until the stream takes them.
    e.buf[..inline.len()].copy_from_slice(inline);
    e.stash_len = inline.len() as u32;
    let name_len = usize::from(e.name_len);
    let body_ptr = e.buf.as_ptr() as u64;
    let fence_ptr = e.fence.as_mut_ptr() as u64;
    let mut a = ArgW {
        arg: &mut e.arg,
        at: 0,
    };
    a.put(&(name_len as u16).to_le_bytes())?;
    a.put(e.name.get(..name_len).unwrap_or(&[]))?;
    a.put(&[ct.len() as u8])?;
    a.put(ct)?;
    if more {
        a.put(&expected.to_le_bytes())?;
    } else {
        a.put(&body_ptr.to_le_bytes())?;
        a.put(&(inline.len() as u64).to_le_bytes())?;
    }
    a.put(&[pre, etag_len as u8])?;
    a.put(etag.get(..etag_len).unwrap_or(&[]))?;
    if !more {
        a.put(&fence_ptr.to_le_bytes())?;
        a.put(&(WIRE_MAX_LEN as u16).to_le_bytes())?;
    }
    e.arg_len = a.at as u16;
    if more {
        e.body_open = true;
        e.phase = Phase::PutOpen;
    } else {
        e.phase = Phase::PutOne;
    }
    Ok(())
}

/// A delete, conditional on `if-match` when it names an etag.
fn begin_delete(s: &mut State, i: usize, headers: &[u8]) -> Result<(), u16> {
    let mut etag = [0u8; ETAG_MAX];
    let (pre, etag_len) = precondition(headers, false, &mut etag)?;
    let e = &mut s.ex[i];
    let name_len = usize::from(e.name_len);
    let fence_ptr = e.fence.as_mut_ptr() as u64;
    let mut a = ArgW {
        arg: &mut e.arg,
        at: 0,
    };
    a.put(&(name_len as u16).to_le_bytes())?;
    a.put(e.name.get(..name_len).unwrap_or(&[]))?;
    a.put(&[pre, etag_len as u8])?;
    a.put(etag.get(..etag_len).unwrap_or(&[]))?;
    a.put(&fence_ptr.to_le_bytes())?;
    a.put(&(WIRE_MAX_LEN as u16).to_le_bytes())?;
    e.arg_len = a.at as u16;
    e.phase = Phase::Delete;
    Ok(())
}

/// A listing query: `list`, then `prefix` and `after` (percent-encoded) and
/// `max` (1 to `LIST_PAGE_MAX`), each at most once, in any order. Anything
/// else is refused `400`. `prefix` and `after` are below the scope: the store
/// is asked for `<scope><prefix>` and, when `after` names a key,
/// `<scope><after>`; either longer than the key bound is refused `400`.
fn begin_list(s: &mut State, i: usize, query: &[u8]) -> Result<(), u16> {
    let bad = ex::status::BAD_REQUEST;
    let sl = usize::from(s.scope_len);
    let scope = s.scope.get(..sl).unwrap_or(&[]);
    let mut prefix = [0u8; NAME_MAX];
    let mut after = [0u8; NAME_MAX];
    prefix[..sl].copy_from_slice(scope);
    after[..sl].copy_from_slice(scope);
    let (mut pl, mut al, mut max) = (None, None, None);
    let mut listed = false;
    for item in query.split(|&c| c == b'&') {
        let (k, v) = match item.iter().position(|&c| c == b'=') {
            Some(p) => (item.get(..p).unwrap_or(&[]), item.get(p + 1..)),
            None => (item, None),
        };
        match (k, v) {
            (b"list", None) if !listed => listed = true,
            (b"prefix", Some(v)) if pl.is_none() => {
                pl = Some(percent_decode(v, &mut prefix[sl..]).ok_or(bad)?)
            }
            (b"after", Some(v)) if al.is_none() => {
                al = Some(percent_decode(v, &mut after[sl..]).ok_or(bad)?)
            }
            (b"max", Some(v)) if max.is_none() => {
                let m = digits(v).ok_or(bad)?;
                if m == 0 || m > u64::from(obj::LIST_PAGE_MAX) {
                    return Err(bad);
                }
                max = Some(m as u16);
            }
            _ => return Err(bad),
        }
    }
    if !listed {
        return Err(bad);
    }
    // An empty `after` is the first page, as no `after` is.
    let cursor_len = match al {
        Some(n) if n > 0 => sl + n,
        _ => 0,
    };
    let e = &mut s.ex[i];
    let req = obj::list::Request {
        prefix: prefix.get(..sl + pl.unwrap_or(0)).unwrap_or(&[]),
        cursor: after.get(..cursor_len).unwrap_or(&[]),
        max_keys: max.unwrap_or(obj::LIST_PAGE_MAX),
        out_ptr: e.buf.as_mut_ptr() as u64,
        out_cap: WINDOW as u32,
        fence_out_ptr: e.fence.as_mut_ptr() as u64,
        fence_out_cap: WIRE_MAX_LEN as u16,
    };
    let n = obj::list::encode_request(&mut e.arg, &req).ok_or(ex::status::FAILED)?;
    e.arg_len = n as u16;
    e.phase = Phase::List;
    Ok(())
}

// ── Request bodies ────────────────────────────────────────────────────────

/// A request-body record for exchange `i`. Only a streamed put reads one;
/// any other exchange's body is not read.
unsafe fn body(s: &mut State, i: usize, data: &[u8], last: bool) {
    let e = &mut s.ex[i];
    let phase = e.phase;
    if !matches!(phase, Phase::PutOpen | Phase::PutBody) || !e.body_open {
        return;
    }
    let len = data.len();
    if len as u64 > u64::from(e.credit_out) || e.stash_len as usize + len > WINDOW {
        return abort_with(s, i, ex::abort::CREDIT_OVERRUN);
    }
    e.credit_out -= len as u32;
    if last {
        e.body_open = false;
        e.put_last = true;
    }
    let steps = s.steps;
    // Straight to the stream while nothing of the body waits; behind what
    // waits otherwise.
    if phase == Phase::PutBody && e.stash_len == 0 && len > 0 {
        let rc = call(
            s.syscalls,
            e.handle,
            obj::PUT_STREAMED_WRITE,
            data.as_ptr() as *mut u8,
            len,
        );
        if rc == 0 {
            count(s, metric::BYTES_IN, len as u64);
            return;
        }
        if rc != errno::EAGAIN {
            return finish(s, i, status_of(rc, true), false, 0);
        }
        e.stash_retry = len as u32;
        e.refused_at = steps;
    }
    let at = e.stash_len as usize;
    e.buf[at..at + len].copy_from_slice(data);
    e.stash_len += len as u32;
    count(s, metric::BYTES_IN, len as u64);
}

// ── The exchanges' own work ───────────────────────────────────────────────

/// Move exchange `i` on by the provider work it waits on, once the module's
/// authority is settled: while the capability waits on the store so does
/// the exchange, and a refused one is answered without a call.
unsafe fn drive(s: &mut State, i: usize) {
    if awaits_store(s.ex[i].phase) {
        if s.auth == Authority::Busy && s.busy_step != s.steps {
            present(s);
        }
        match s.auth {
            Authority::None | Authority::Granted => {}
            Authority::Presenting => return,
            Authority::Busy => return finish(s, i, ex::status::BUSY, false, 0),
            Authority::Refused => return finish(s, i, 403, false, 0),
        }
    }
    match s.ex[i].phase {
        Phase::Meta => meta(s, i),
        Phase::Open => open(s, i),
        Phase::PutOne => put_one(s, i),
        Phase::PutOpen => put_open(s, i),
        Phase::PutBody => put_drain(s, i),
        Phase::PutCommit => put_commit(s, i),
        Phase::Delete => delete(s, i),
        Phase::List => list(s, i),
        _ => {}
    }
}

/// The object's `HEAD` record — its size, content type and entity tag — and
/// the fence it was read at. Then the range is judged against the size.
unsafe fn meta(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let name_len = usize::from(e.name_len);
    let mut arg = [0u8; 2 + NAME_MAX + 22];
    arg[..2].copy_from_slice(&(name_len as u16).to_le_bytes());
    arg[2..2 + name_len].copy_from_slice(&e.name[..name_len]);
    let p = 2 + name_len;
    arg[p..p + 8].copy_from_slice(&(e.buf.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 8..p + 12].copy_from_slice(&(WINDOW as u32).to_le_bytes());
    arg[p + 12..p + 20].copy_from_slice(&(e.fence.as_mut_ptr() as u64).to_le_bytes());
    arg[p + 20..p + 22].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
    let rc = call(s.syscalls, s.grant, obj::HEAD, arg.as_mut_ptr(), p + 22);
    if rc == errno::EAGAIN {
        return;
    }
    if rc < 0 {
        return finish(s, i, status_of(rc, false), false, 0);
    }
    let size =
        obj::range::decode_head(e.buf.get(..rc as usize).unwrap_or(&[])).map(|(h, _, _)| h.size);
    let Some(size) = size else {
        return finish(s, i, ex::status::FAILED, true, 0);
    };
    e.head_len = rc as u16;
    e.size = size;
    let bounds = match e.range {
        RangeSpec::Whole => Some((0, size)),
        RangeSpec::From(a, b) if a < size => Some((a, b.map_or(size, |b| (b + 1).min(size)))),
        RangeSpec::Suffix(n) if n > 0 && size > 0 => Some((size - n.min(size), size)),
        _ => None,
    };
    let Some((start, end)) = bounds else {
        return finish(s, i, 416, false, reply::RANGE);
    };
    e.offset = start;
    e.end = end;
    // A `HEAD`, or an empty object read whole, has no body to open.
    e.phase = if e.method == ex::METHOD_HEAD || start == end {
        Phase::Stream
    } else {
        Phase::Open
    };
}

/// Open the object for ranged reads. The handle's own fence replaces the one
/// the `HEAD` record was read at, since it names what is served.
unsafe fn open(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let h = call(
        s.syscalls,
        s.grant,
        obj::GET,
        e.name.as_mut_ptr(),
        usize::from(e.name_len),
    );
    if h == errno::EAGAIN {
        return;
    }
    if h < 0 {
        return finish(s, i, status_of(h, false), false, 0);
    }
    let mut fence = [0u8; WIRE_MAX_LEN];
    let q = ((*s.syscalls).provider_query)(
        h,
        abi::kernel_abi::query_key::LAST_FENCE,
        fence.as_mut_ptr(),
        WIRE_MAX_LEN,
    );
    if q > 0 && Fence::decode(&fence).is_some() {
        e.fence = fence;
    }
    e.handle = h;
    e.phase = Phase::Stream;
}

/// A single-shot put, asked again with the same request until decided.
unsafe fn put_one(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let (arg, len) = (e.arg.as_mut_ptr(), usize::from(e.arg_len));
    match obj::write_answer(call(s.syscalls, s.grant, obj::PUT, arg, len)) {
        obj::WriteAnswer::Pending => {}
        obj::WriteAnswer::Decided(0) => finish(s, i, 200, false, reply::FENCE),
        obj::WriteAnswer::Decided(rc) => finish(s, i, status_of(rc, true), false, 0),
    }
}

/// Open the streamed put, asked again while the provider has no slot free
/// yet. Once open the body flows: what waited goes first, and credit for the
/// rest is granted as the stream takes it.
unsafe fn put_open(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let h = call(
        s.syscalls,
        s.grant,
        obj::PUT_STREAMED_OPEN,
        e.arg.as_mut_ptr(),
        usize::from(e.arg_len),
    );
    if h == errno::EAGAIN {
        return;
    }
    if h < 0 {
        return finish(s, i, status_of(h, true), false, 0);
    }
    e.handle = h;
    e.phase = Phase::PutBody;
    put_drain(s, i);
}

/// Send what the stash holds, in order, until the provider pushes back or it
/// is empty; then commit once the body has ended, or owe the credit that
/// lets the next window come.
unsafe fn put_drain(s: &mut State, i: usize) {
    let steps = s.steps;
    let e = &mut s.ex[i];
    e.grant = 0;
    while e.stash_len > 0 {
        // Pushed back in this step: the provider has had no chance to make
        // room.
        if e.stash_retry != 0 && e.refused_at == steps {
            return;
        }
        let n = if e.stash_retry != 0 {
            e.stash_retry
        } else {
            e.stash_len
        } as usize;
        let rc = call(
            s.syscalls,
            e.handle,
            obj::PUT_STREAMED_WRITE,
            e.buf.as_mut_ptr(),
            n,
        );
        if rc == errno::EAGAIN {
            e.stash_retry = n as u32;
            e.refused_at = steps;
            return;
        }
        if rc < 0 {
            return finish(s, i, status_of(rc, true), false, 0);
        }
        e.buf.copy_within(n..e.stash_len as usize, 0);
        e.stash_len -= n as u32;
        e.stash_retry = 0;
    }
    if e.put_last {
        let fence_ptr = e.fence.as_mut_ptr() as u64;
        e.arg[..8].copy_from_slice(&fence_ptr.to_le_bytes());
        e.arg[8..10].copy_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
        e.arg_len = 10;
        e.phase = Phase::PutCommit;
        return put_commit(s, i);
    }
    if e.body_open {
        e.grant = (WINDOW as u32).saturating_sub(e.credit_out);
    }
}

/// Commit the streamed put, asked again with the same request until decided.
/// The answer names the fence the commit achieved.
unsafe fn put_commit(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let h = e.handle;
    let (arg, len) = (e.arg.as_mut_ptr(), usize::from(e.arg_len));
    let answer = obj::write_answer(call(s.syscalls, h, obj::PUT_STREAMED_COMMIT, arg, len));
    let obj::WriteAnswer::Decided(rc) = answer else {
        return;
    };
    // Committed or refused, the handle is no longer writable and is closed
    // either way.
    call(s.syscalls, h, obj::CLOSE, core::ptr::null_mut(), 0);
    e.handle = -1;
    if rc == 0 {
        finish(s, i, 200, false, reply::FENCE);
    } else {
        finish(s, i, status_of(rc, true), false, 0);
    }
}

unsafe fn delete(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let (arg, len) = (e.arg.as_mut_ptr(), usize::from(e.arg_len));
    match obj::write_answer(call(s.syscalls, s.grant, obj::DELETE, arg, len)) {
        obj::WriteAnswer::Pending => {}
        obj::WriteAnswer::Decided(0) => finish(s, i, 204, false, reply::FENCE),
        obj::WriteAnswer::Decided(rc) => finish(s, i, status_of(rc, true), false, 0),
    }
}

unsafe fn list(s: &mut State, i: usize) {
    let e = &mut s.ex[i];
    let rc = call(
        s.syscalls,
        s.grant,
        obj::LIST,
        e.arg.as_mut_ptr(),
        usize::from(e.arg_len),
    );
    if rc == errno::EAGAIN {
        return;
    }
    if rc < 0 {
        return finish(s, i, status_of(rc, false), false, 0);
    }
    let n = rc as usize;
    let scope = s.scope.get(..usize::from(s.scope_len)).unwrap_or(&[]);
    let carried = n <= WINDOW
        && obj::list::decode_page(e.buf.get(..n).unwrap_or(&[]))
            .is_some_and(|page| within(&page, scope));
    if !carried {
        return finish(s, i, ex::status::FAILED, true, 0);
    }
    e.page_len = n as u16;
    e.phase = Phase::ListOut;
}

/// Whether every name of `page`, and its cursor when another page follows,
/// lies under `scope`: what a listing writes is each with the scope taken
/// off, so a page naming anything else is not one this front can answer.
fn within(page: &obj::list::Page<'_>, scope: &[u8]) -> bool {
    page.entries().all(|e| e.key.starts_with(scope))
        && (page.is_last() || page.cursor().starts_with(scope))
}
