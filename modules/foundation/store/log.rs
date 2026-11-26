// ── The log ───────────────────────────────────────────────────────────

/// Log record ops.
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;
/// `[rev u64][op u8][key_len u16][val_len u32]`.
const LOG_HEADER_LEN: usize = 15;

/// Bytes one read or write of the open's copy moves.
const IO_BUF: usize = 4096;
/// Filesystem calls one step of the open makes at most.
const OPEN_CALLS_PER_STEP: u32 = 16;

const LOG_NAME: &[u8] = b"/store.log";
const BAK_NAME: &[u8] = b"/store.bak";
const CPY_NAME: &[u8] = b"/store.cpy";

/// The filesystem operations the durable store cannot run without.
const FS_NEEDS: u32 = fs::caps::OPEN
    | fs::caps::OPEN_CREATE
    | fs::caps::WRITE
    | fs::caps::FSYNC
    | fs::caps::UNLINK
    | fs::caps::MKDIR
    | fs::caps::RENAME
    | fs::caps::TRUNCATE;

// Open phases, in order.
const OPEN_CAPS: u8 = 0;
const OPEN_MKDIR: u8 = 1;
const OPEN_CLEAN: u8 = 2;
const OPEN_BAK: u8 = 3;
const OPEN_LOG: u8 = 4;
const OPEN_PARSE: u8 = 5;
const OPEN_CPY_CREATE: u8 = 6;
const OPEN_CPY_SOURCE: u8 = 7;
const OPEN_CPY_COPY: u8 = 8;
const OPEN_CPY_FSYNC: u8 = 9;
const OPEN_CPY_PUBLISH: u8 = 10;
const OPEN_BAK_NAME: u8 = 11;
const OPEN_TRUNC: u8 = 12;
const OPEN_LOG_CREATE: u8 = 13;
const OPEN_LOG_SOURCE: u8 = 14;
const OPEN_LOG_COPY: u8 = 15;
const OPEN_LOG_FSYNC: u8 = 16;
const OPEN_BAK_UNLINK: u8 = 17;
const OPEN_BAK_GONE: u8 = 18;
const OPEN_FRESH: u8 = 19;
const OPEN_FRESH_NAME: u8 = 20;
const OPEN_READY: u8 = 21;

// Parser states.
const PARSE_HDR: u8 = 0;
const PARSE_KEY: u8 = 1;
const PARSE_VAL: u8 = 2;

/// The open in progress, resumable across steps.
#[repr(C)]
struct Open {
    phase: u8,
    /// The store has answered `Ready`.
    announced: u8,
    /// The open could not finish: every op answers `EIO`.
    failed: u8,
    /// `store.bak` existed: it is the authority this open replays.
    from_bak: u8,
    caps: u32,
    /// The `dir` level `MKDIR` reached.
    level: u16,
    src: i32,
    dst: i32,
    /// Bytes of the source the copy has read, and of the destination it
    /// has written.
    read: u64,
    written: u64,
    /// The source's valid records: what the copy carries.
    valid: u64,
    /// The copy buffer's bytes not yet written.
    buf_at: u32,
    buf_len: u32,
    // ── the parser ──
    pstate: u8,
    hdr: [u8; LOG_HEADER_LEN],
    hdr_got: u8,
    rev: u64,
    op: u8,
    kl: u16,
    vl: u32,
    key_got: u16,
    block: *mut u8,
    val_got: u32,
    /// Bytes parsed so far.
    parsed: u64,
}

impl Open {
    const fn new() -> Self {
        Self {
            phase: OPEN_CAPS,
            announced: 0,
            failed: 0,
            from_bak: 0,
            caps: 0,
            level: 0,
            src: -1,
            dst: -1,
            read: 0,
            written: 0,
            valid: 0,
            buf_at: 0,
            buf_len: 0,
            pstate: PARSE_HDR,
            hdr: [0; LOG_HEADER_LEN],
            hdr_got: 0,
            rev: 0,
            op: 0,
            kl: 0,
            vl: 0,
            key_got: 0,
            block: core::ptr::null_mut(),
            val_got: 0,
            parsed: 0,
        }
    }
}

enum OpenStep {
    Pending,
    Ready,
    Failed(i32),
}

/// A filesystem answer that is not yet a decision: the call is asked again
/// next step (`EAGAIN`), byte-identical (`EINPROGRESS`).
fn undecided(rc: i32) -> bool {
    rc == EAGAIN || rc == EINPROGRESS
}

fn fs_call(s: &State, handle: i32, op: u32, arg: &mut [u8]) -> i32 {
    // SAFETY: `arg` is live for the call.
    unsafe {
        (s.sys().provider_call)(
            handle,
            op,
            arg.as_mut_ptr(),
            arg.len(),
            core::ptr::null_mut(),
            0,
        )
    }
}

/// A bulk op (`READ`, `WRITE`): its bytes in `data`, its `arg` empty.
fn fs_bulk(s: &State, handle: i32, op: u32, data: *mut u8, len: usize) -> i32 {
    // SAFETY: `data` names `len` bytes the caller owns for the call.
    unsafe { (s.sys().provider_call)(handle, op, core::ptr::null_mut(), 0, data, len) }
}

/// `<dir><name>` into `out`; its length.
fn path_of(s: &State, name: &[u8], out: &mut [u8; PATH_MAX]) -> usize {
    let d = s.dir();
    out[..d.len()].copy_from_slice(d);
    out[d.len()..d.len() + name.len()].copy_from_slice(name);
    d.len() + name.len()
}

fn fs_path(s: &State, op: u32, name: &[u8]) -> i32 {
    let mut p = [0u8; PATH_MAX];
    let n = path_of(s, name, &mut p);
    fs_call(s, -1, op, &mut p[..n])
}

/// `FSYNC_NAME` of `name`, where the filesystem offers it.
fn fs_publish(s: &State, name: &[u8]) -> i32 {
    if s.open.caps & fs::caps::FSYNC_NAME == 0 {
        return 0;
    }
    fs_path(s, fs::FSYNC_NAME, name)
}

fn fs_close(s: &State, fd: i32) {
    if fd >= 0 {
        let _ = fs_call(s, fd, fs::CLOSE, &mut []);
    }
}

/// The device a `LocalDurable` fence on `fd` names.
fn fs_device(s: &State, fd: i32) -> Option<u64> {
    let mut out = [0u8; abi::fence::WIRE_MAX_LEN];
    // SAFETY: `out` is writable for its length.
    let rc =
        unsafe { (s.sys().provider_query)(fd, query_key::LAST_FENCE, out.as_mut_ptr(), out.len()) };
    if rc <= 0 {
        return None;
    }
    match Fence::decode(&out[..rc as usize]) {
        Some((Fence::LocalDurable { device_id }, _)) => Some(device_id),
        _ => None,
    }
}

/// The open cannot finish: say where and why, close what it holds, and
/// answer `EIO` from now on. Phases and errnos are numbers in the log line
/// (the open's phases are the `OPEN_*` constants of `log.rs`).
fn open_fail(s: &mut State, e: i32) -> OpenStep {
    let mut msg = [0u8; 64];
    let head = b"[store] log open failed: phase ";
    msg[..head.len()].copy_from_slice(head);
    let mut n = head.len();
    n += fmt_u32(u32::from(s.open.phase), &mut msg[n..]);
    let mid = b" errno -";
    msg[n..n + mid.len()].copy_from_slice(mid);
    n += mid.len();
    n += fmt_u32(e.unsigned_abs(), &mut msg[n..]);
    log(s, 1, &msg[..n]);
    fs_close(s, s.open.src);
    fs_close(s, s.open.dst);
    s.open.src = -1;
    s.open.dst = -1;
    s.open.failed = 1;
    OpenStep::Failed(e)
}

/// `v` in decimal into `out`; the digits written.
fn fmt_u32(mut v: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
    let mut n = 0usize;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

/// Run the open as far as one step's budget of calls allows.
fn open_step(s: &mut State) -> OpenStep {
    let mut calls = OPEN_CALLS_PER_STEP;
    while calls > 0 {
        calls -= 1;
        match open_phase(s) {
            Ok(true) => {}
            Ok(false) => return OpenStep::Pending,
            Err(e) => return open_fail(s, e),
        }
        if s.open.phase == OPEN_READY {
            s.open.announced = 1;
            log(s, 3, b"[store] log open: ready");
            return OpenStep::Ready;
        }
    }
    OpenStep::Pending
}

type PhaseResult = Result<bool, i32>;

/// One call of the open. `Ok(true)`: it moved on; `Ok(false)`: the
/// filesystem has not decided, ask again next step.
fn open_phase(s: &mut State) -> PhaseResult {
    match s.open.phase {
        OPEN_CAPS => {
            let mut w = [0u8; 4];
            let rc = fs_call(s, -1, fs::CAPS, &mut w);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(EIO);
            }
            s.open.caps = u32::from_le_bytes(w);
            if s.open.caps & FS_NEEDS != FS_NEEDS {
                return Err(ENOSYS);
            }
            s.open.phase = OPEN_MKDIR;
            s.open.level = 1;
            Ok(true)
        }
        OPEN_MKDIR => {
            let d = s.dir();
            let lvl = usize::from(s.open.level);
            if lvl > d.len() {
                s.open.phase = OPEN_CLEAN;
                return Ok(true);
            }
            let end = d[lvl..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(d.len(), |p| lvl + p);
            let mut p = [0u8; PATH_MAX];
            p[..end].copy_from_slice(&d[..end]);
            let rc = fs_call(s, -1, fs::MKDIR, &mut p[..end]);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 && rc != EEXIST {
                return Err(rc);
            }
            s.open.level = (end + 1) as u16;
            Ok(true)
        }
        OPEN_CLEAN => {
            let rc = fs_path(s, fs::UNLINK, CPY_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            s.open.phase = OPEN_BAK;
            Ok(true)
        }
        OPEN_BAK => {
            let rc = fs_path(s, fs::OPEN, BAK_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc >= 0 {
                s.open.from_bak = 1;
                s.open.src = rc;
                s.open.phase = OPEN_PARSE;
                log(
                    s,
                    2,
                    b"[store] replaying store.bak: the last open was interrupted",
                );
            } else {
                s.open.phase = OPEN_LOG;
            }
            Ok(true)
        }
        OPEN_LOG => {
            let rc = fs_path(s, fs::OPEN, LOG_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc == ENOENT {
                s.open.phase = OPEN_FRESH;
            } else if rc < 0 {
                return Err(rc);
            } else {
                s.open.src = rc;
                s.open.phase = OPEN_PARSE;
            }
            Ok(true)
        }
        OPEN_PARSE => parse_some(s),
        OPEN_CPY_CREATE => {
            let rc = fs_path(s, fs::OPEN_CREATE, CPY_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.open.dst = rc;
            s.open.phase = OPEN_CPY_SOURCE;
            Ok(true)
        }
        OPEN_CPY_SOURCE => {
            let rc = fs_path(s, fs::OPEN, LOG_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            copy_begin(s, rc);
            s.open.phase = OPEN_CPY_COPY;
            Ok(true)
        }
        OPEN_CPY_COPY => copy_some(s, OPEN_CPY_FSYNC),
        OPEN_CPY_FSYNC => {
            let rc = fs_call(s, s.open.dst, fs::FSYNC, &mut []);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            fs_close(s, s.open.src);
            fs_close(s, s.open.dst);
            s.open.src = -1;
            s.open.dst = -1;
            s.open.phase = OPEN_CPY_PUBLISH;
            Ok(true)
        }
        OPEN_CPY_PUBLISH => {
            let mut from = [0u8; PATH_MAX];
            let fl = path_of(s, CPY_NAME, &mut from);
            let mut to = [0u8; PATH_MAX];
            let tl = path_of(s, BAK_NAME, &mut to);
            let mut arg = [0u8; 2 * PATH_MAX + 4];
            arg[..2].copy_from_slice(&(fl as u16).to_le_bytes());
            arg[2..2 + fl].copy_from_slice(&from[..fl]);
            arg[2 + fl..4 + fl].copy_from_slice(&(tl as u16).to_le_bytes());
            arg[4 + fl..4 + fl + tl].copy_from_slice(&to[..tl]);
            let rc = fs_call(s, -1, fs::RENAME, &mut arg[..4 + fl + tl]);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.open.phase = OPEN_BAK_NAME;
            Ok(true)
        }
        OPEN_BAK_NAME => {
            let rc = fs_publish(s, BAK_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.open.phase = OPEN_TRUNC;
            Ok(true)
        }
        OPEN_TRUNC => {
            let mut p = [0u8; PATH_MAX + 8];
            let mut name = [0u8; PATH_MAX];
            let n = path_of(s, LOG_NAME, &mut name);
            p[8..8 + n].copy_from_slice(&name[..n]);
            let rc = fs_call(s, -1, fs::TRUNCATE, &mut p[..8 + n]);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 && rc != ENOENT {
                return Err(rc);
            }
            s.open.phase = OPEN_LOG_CREATE;
            Ok(true)
        }
        OPEN_LOG_CREATE => {
            let rc = fs_path(s, fs::OPEN_CREATE, LOG_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.open.dst = rc;
            s.open.phase = OPEN_LOG_SOURCE;
            Ok(true)
        }
        OPEN_LOG_SOURCE => {
            let rc = fs_path(s, fs::OPEN, BAK_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            copy_begin(s, rc);
            s.open.phase = OPEN_LOG_COPY;
            Ok(true)
        }
        OPEN_LOG_COPY => copy_some(s, OPEN_LOG_FSYNC),
        OPEN_LOG_FSYNC => {
            let rc = fs_call(s, s.open.dst, fs::FSYNC, &mut []);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            if let Some(d) = fs_device(s, s.open.dst) {
                s.device = d;
                s.device_known = 1;
            }
            fs_close(s, s.open.src);
            s.open.src = -1;
            s.log_fd = s.open.dst;
            s.log_len = s.open.valid;
            s.open.dst = -1;
            s.open.phase = OPEN_BAK_UNLINK;
            Ok(true)
        }
        OPEN_BAK_UNLINK => {
            let rc = fs_path(s, fs::UNLINK, BAK_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 && rc != ENOENT {
                return Err(rc);
            }
            s.open.phase = OPEN_BAK_GONE;
            Ok(true)
        }
        OPEN_BAK_GONE => {
            let rc = fs_publish(s, BAK_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            s.open.phase = OPEN_READY;
            Ok(true)
        }
        OPEN_FRESH => {
            let rc = fs_path(s, fs::OPEN_CREATE, LOG_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.log_fd = rc;
            s.log_len = 0;
            s.open.phase = OPEN_FRESH_NAME;
            Ok(true)
        }
        OPEN_FRESH_NAME => {
            let rc = fs_publish(s, LOG_NAME);
            if undecided(rc) {
                return Ok(false);
            }
            if rc < 0 {
                return Err(rc);
            }
            s.open.phase = OPEN_READY;
            Ok(true)
        }
        _ => Ok(true),
    }
}

fn io_buf(s: &State) -> &[u8] {
    // SAFETY: `construct` took `IO_BUF` bytes for a durable store.
    unsafe { core::slice::from_raw_parts(s.io_buf, IO_BUF) }
}

/// Read the source and replay what it holds. At its end, the valid length
/// is what the copies carry; a record that cannot be applied fails the
/// open rather than dropping it and everything behind it.
fn parse_some(s: &mut State) -> PhaseResult {
    let n = fs_bulk(s, s.open.src, fs::READ, s.io_buf, IO_BUF);
    if undecided(n) {
        return Ok(false);
    }
    if n < 0 {
        return Err(n);
    }
    if n == 0 {
        // A torn tail is everything past the last whole record.
        if s.open.pstate != PARSE_HDR {
            block_release(s, s.open.block);
            s.open.block = core::ptr::null_mut();
        }
        s.open.valid = s.open.parsed;
        fs_close(s, s.open.src);
        s.open.src = -1;
        s.open.phase = if s.open.from_bak != 0 {
            OPEN_TRUNC
        } else {
            OPEN_CPY_CREATE
        };
        return Ok(true);
    }
    let mut at = 0usize;
    while at < n as usize {
        feed(s, &mut at, n as usize)?;
    }
    Ok(true)
}

/// Feed the parser from `io_buf[*at..end]`, at least one byte.
fn feed(s: &mut State, at: &mut usize, end: usize) -> Result<(), i32> {
    match s.open.pstate {
        PARSE_HDR => {
            let want = LOG_HEADER_LEN - usize::from(s.open.hdr_got);
            let take = want.min(end - *at);
            let got = usize::from(s.open.hdr_got);
            let src = io_buf(s)[*at..*at + take].as_ptr();
            // SAFETY: `take` bytes of the buffer into the header's rest.
            unsafe {
                core::ptr::copy_nonoverlapping(src, s.open.hdr[got..].as_mut_ptr(), take);
            }
            s.open.hdr_got += take as u8;
            *at += take;
            if usize::from(s.open.hdr_got) == LOG_HEADER_LEN {
                let h = s.open.hdr;
                let mut r = [0u8; 8];
                r.copy_from_slice(&h[..8]);
                s.open.rev = u64::from_le_bytes(r);
                s.open.op = h[8];
                s.open.kl = u16::from_le_bytes([h[9], h[10]]);
                s.open.vl = u32::from_le_bytes([h[11], h[12], h[13], h[14]]);
                if s.open.op != OP_PUT && s.open.op != OP_DELETE {
                    return Err(EIO);
                }
                if s.open.kl == 0 {
                    return Err(EIO);
                }
                // The record's block, its key written in as it is read: a
                // put's with room for its value, a delete's the key alone.
                let vl = if s.open.op == OP_PUT { s.open.vl } else { 0 };
                let b = block_alloc_raw(s, usize::from(s.open.kl), vl);
                if b.is_null() {
                    return Err(ENOSPC);
                }
                s.open.block = b;
                s.open.key_got = 0;
                s.open.pstate = PARSE_KEY;
            }
        }
        PARSE_KEY => {
            let want = usize::from(s.open.kl - s.open.key_got);
            let take = want.min(end - *at);
            let got = usize::from(s.open.key_got);
            let src = io_buf(s)[*at..*at + take].as_ptr();
            // SAFETY: `take` bytes into the block's key, past what is in.
            unsafe {
                core::ptr::copy_nonoverlapping(src, s.open.block.add(BLOCK_HDR + got), take);
            }
            s.open.key_got += take as u16;
            *at += take;
            if s.open.key_got == s.open.kl {
                if !utf8_valid(block_key(s.open.block, s.open.kl)) {
                    return Err(EIO);
                }
                s.open.val_got = 0;
                s.open.pstate = PARSE_VAL;
                if s.open.vl == 0 {
                    return replay_record(s);
                }
            }
        }
        _ => {
            let want = (s.open.vl - s.open.val_got) as usize;
            let take = want.min(end - *at);
            if s.open.op == OP_PUT {
                let src = io_buf(s)[*at..*at + take].as_ptr();
                let dst = block_val(s.open.block, s.open.kl, s.open.vl)[s.open.val_got as usize..]
                    .as_mut_ptr();
                // SAFETY: `take` bytes into the value's rest.
                unsafe { core::ptr::copy_nonoverlapping(src, dst, take) };
            }
            s.open.val_got += take as u32;
            *at += take;
            if s.open.val_got == s.open.vl {
                return replay_record(s);
            }
        }
    }
    Ok(())
}

/// Apply the record the parser holds whole.
fn replay_record(s: &mut State) -> Result<(), i32> {
    let kl = usize::from(s.open.kl);
    let rec_len = (LOG_HEADER_LEN + kl) as u64 + u64::from(s.open.vl);
    let rev = s.open.rev;
    let b = s.open.block;
    s.open.block = core::ptr::null_mut();
    let key = block_key(b, s.open.kl);
    if s.open.op == OP_PUT {
        let Some((slot, at)) = slot_for(s, key) else {
            block_release(s, b);
            return Err(ENOMEM);
        };
        apply_put(s, slot, at, b, s.open.kl, s.open.vl, rev);
    } else {
        if let Some(slot) = live_slot(s, key) {
            apply_delete(s, slot, rev);
        } else {
            // A delete of a key the log never held live leaves nothing, and
            // takes its revision.
            s.revision = s.revision.max(rev);
        }
        block_release(s, b);
    }
    s.open.parsed += rec_len;
    s.open.hdr_got = 0;
    s.open.pstate = PARSE_HDR;
    Ok(())
}

fn copy_begin(s: &mut State, src: i32) {
    s.open.src = src;
    s.open.read = 0;
    s.open.written = 0;
    s.open.buf_at = 0;
    s.open.buf_len = 0;
}

/// Copy the source's valid bytes to the destination, then move to `next`.
fn copy_some(s: &mut State, next: u8) -> PhaseResult {
    if s.open.written == s.open.valid {
        s.open.phase = next;
        return Ok(true);
    }
    if s.open.buf_at == s.open.buf_len {
        let want = (s.open.valid - s.open.read).min(IO_BUF as u64) as usize;
        let n = fs_bulk(s, s.open.src, fs::READ, s.io_buf, want);
        if undecided(n) {
            return Ok(false);
        }
        if n <= 0 {
            return Err(EIO);
        }
        s.open.read += n as u64;
        s.open.buf_at = 0;
        s.open.buf_len = n as u32;
    }
    let at = s.open.buf_at as usize;
    let len = (s.open.buf_len - s.open.buf_at) as usize;
    // SAFETY: the unwritten bytes of the buffer.
    let p = unsafe { s.io_buf.add(at) };
    let n = fs_bulk(s, s.open.dst, fs::WRITE, p, len);
    if undecided(n) {
        return Ok(false);
    }
    if n <= 0 {
        return Err(if n < 0 { n } else { ENOSPC });
    }
    s.open.buf_at += n as u32;
    s.open.written += n as u64;
    Ok(true)
}

// ── Writes ────────────────────────────────────────────────────────────

const W_APPEND: u8 = 0;
const W_FENCE: u8 = 1;

/// The one write in flight: its record appended and fenced before it
/// applies.
#[repr(C)]
struct InFlight {
    live: u8,
    op: u8,
    stage: u8,
    /// The slot's index position for a new key, or `u32::MAX`.
    at: u32,
    slot: u32,
    /// The streamed-write slot it commits, or -1.
    stream: i16,
    ask: [u8; 32],
    rev: u64,
    block: *mut u8,
    kl: u16,
    vl: u32,
    /// The record's header and key.
    hdr: [u8; LOG_HEADER_LEN + STORAGE_KEY_MAX],
    hdr_len: u16,
    written: u64,
}

impl InFlight {
    const EMPTY: Self = Self {
        live: 0,
        op: 0,
        stage: 0,
        at: 0,
        slot: 0,
        stream: -1,
        ask: [0; 32],
        rev: 0,
        block: core::ptr::null_mut(),
        kl: 0,
        vl: 0,
        hdr: [0; LOG_HEADER_LEN + STORAGE_KEY_MAX],
        hdr_len: 0,
        written: 0,
    };
}

/// A write the store's step decided with no caller asking: its answer,
/// kept for the ask that collects it.
#[repr(C)]
struct Settled {
    live: u8,
    ask: [u8; 32],
    rc: i32,
    rev: u64,
}

/// What identifies a request asked again: the calling module, the op and
/// its record (the `arg` before the fence trailer), and the body's length.
fn ask_of(s: &State, opcode: u32, a: &[u8], extra: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&caller_module(s));
    h.update(&opcode.to_le_bytes());
    h.update(trailer::record(a).unwrap_or(a));
    h.update(&extra.to_le_bytes());
    h.finalize()
}

/// Begin a write of `block` (a put, `op` OP_PUT) or of `slot`'s delete into
/// the log, decided now when the log takes it whole and fenced inside this
/// call. `Some(rc)` decided, `None` in flight.
#[allow(
    clippy::too_many_arguments,
    reason = "a write's whole description: the ask, op, slot, its place and the block's parts"
)]
fn begin_write(
    s: &mut State,
    ask: [u8; 32],
    op: u8,
    slot: u32,
    at: Option<usize>,
    block: *mut u8,
    kl: u16,
    vl: u32,
    stream: i16,
) -> Option<i32> {
    let rev = s.revision + 1;
    if s.durable == DURABLE_OFF {
        land(s, op, slot, at, block, kl, vl, rev);
        return Some(0);
    }
    let w = &mut s.inflight;
    *w = InFlight::EMPTY;
    w.live = 1;
    w.op = op;
    w.stage = W_APPEND;
    w.at = at.map_or(u32::MAX, |p| p as u32);
    w.slot = slot;
    w.stream = stream;
    w.ask = ask;
    w.rev = rev;
    w.block = block;
    w.kl = kl;
    w.vl = vl;
    w.hdr[..8].copy_from_slice(&rev.to_le_bytes());
    w.hdr[8] = op;
    w.hdr[9..11].copy_from_slice(&kl.to_le_bytes());
    w.hdr[11..15].copy_from_slice(&vl.to_le_bytes());
    let key = if op == OP_PUT {
        block_key(block, kl)
    } else {
        key_of(s, slot)
    };
    let mut k = [0u8; STORAGE_KEY_MAX];
    k[..key.len()].copy_from_slice(key);
    let w = &mut s.inflight;
    w.hdr[LOG_HEADER_LEN..LOG_HEADER_LEN + usize::from(kl)].copy_from_slice(&k[..usize::from(kl)]);
    w.hdr_len = (LOG_HEADER_LEN + usize::from(kl)) as u16;
    drive(s)
}

/// Install a write that has reached the log.
#[allow(
    clippy::too_many_arguments,
    reason = "the landed write's whole description: op, slot, its place, the block's parts and its revision"
)]
fn land(
    s: &mut State,
    op: u8,
    slot: u32,
    at: Option<usize>,
    block: *mut u8,
    kl: u16,
    vl: u32,
    rev: u64,
) {
    let key = {
        let mut k = [0u8; STORAGE_KEY_MAX];
        let src = if op == OP_PUT {
            block_key(block, kl)
        } else {
            key_of(s, slot)
        };
        k[..src.len()].copy_from_slice(src);
        (k, src.len())
    };
    if op == OP_PUT {
        apply_put(s, slot, at, block, kl, vl, rev);
    } else {
        apply_delete(s, slot, rev);
    }
    ring_matching(s, &key.0[..key.1]);
}

/// Carry the write in flight one call further. `Some(rc)` once decided:
/// 0 with the write landed, or the failure with nothing landed.
fn drive(s: &mut State) -> Option<i32> {
    if s.inflight.live == 0 {
        return None;
    }
    loop {
        match s.inflight.stage {
            W_APPEND => {
                let (op, hdr_len, written, block, kl, vl) = {
                    let w = &s.inflight;
                    (w.op, u64::from(w.hdr_len), w.written, w.block, w.kl, w.vl)
                };
                let rec = hdr_len + u64::from(if op == OP_PUT { vl } else { 0 });
                if written == rec {
                    s.inflight.stage = W_FENCE;
                    continue;
                }
                let (p, len) = if written < hdr_len {
                    let at = written as usize;
                    (
                        // SAFETY: the record header's unwritten rest.
                        unsafe { s.inflight.hdr.as_mut_ptr().add(at) },
                        hdr_len as usize - at,
                    )
                } else {
                    let at = (written - hdr_len) as usize;
                    let v = block_val(block, kl, vl);
                    (v[at..].as_mut_ptr(), v.len() - at)
                };
                let n = fs_bulk(s, s.log_fd, fs::WRITE, p, len);
                if undecided(n) {
                    return None;
                }
                if n <= 0 {
                    return Some(write_failed(s));
                }
                s.inflight.written += n as u64;
            }
            _ => {
                let rc = fs_call(s, s.log_fd, fs::FSYNC, &mut []);
                if undecided(rc) {
                    return None;
                }
                if rc < 0 {
                    return Some(write_failed(s));
                }
                if let Some(d) = fs_device(s, s.log_fd) {
                    s.device = d;
                    s.device_known = 1;
                }
                let w = &s.inflight;
                let (op, slot, block, kl, vl, rev, stream) =
                    (w.op, w.slot, w.block, w.kl, w.vl, w.rev, w.stream);
                let at = (w.at != u32::MAX).then_some(w.at as usize);
                s.log_len += w.written;
                s.inflight.live = 0;
                land(s, op, slot, at, block, kl, vl, rev);
                if stream >= 0 {
                    writes_mut(s)[stream as usize].committed = 1;
                }
                return Some(0);
            }
        }
    }
}

/// A write the log refused: nothing lands. The log may now end in part of
/// its record, so it is rewritten from its fenced records the way an open
/// rewrites it (copied out to `store.bak`, then back), which cuts the part
/// off; the store answers `EAGAIN` until that is done.
fn write_failed(s: &mut State) -> i32 {
    log(
        s,
        1,
        b"[store] a write to store.log failed; the log is rewritten from its fenced records",
    );
    let w = &s.inflight;
    let (op, block) = (w.op, w.block);
    s.inflight.live = 0;
    if op == OP_PUT {
        block_release(s, block);
    }
    fs_close(s, s.log_fd);
    s.log_fd = -1;
    s.open.valid = s.log_len;
    s.open.from_bak = 0;
    s.open.announced = 0;
    s.open.phase = OPEN_CPY_CREATE;
    ERROR
}

/// The store's step: an undecided write whose caller stopped asking is
/// carried on, and its decision kept for the ask that collects it.
fn carry_inflight(s: &mut State) {
    if s.inflight.live == 0 {
        return;
    }
    let ask = s.inflight.ask;
    let rev = s.inflight.rev;
    if let Some(rc) = drive(s) {
        s.settled = Settled {
            live: 1,
            ask,
            rc,
            rev,
        };
    }
}

/// Answer a write asked again: the write in flight driven on, a decision
/// the step kept, or `None` for a request not seen before. `EBUSY` while a
/// different write is in flight.
fn reask(s: &mut State, ask: &[u8; 32], arg: &mut [u8]) -> Option<i32> {
    if s.inflight.live != 0 {
        if &s.inflight.ask != ask {
            return Some(EBUSY);
        }
        let rev = s.inflight.rev;
        return Some(match drive(s) {
            None => EINPROGRESS,
            Some(0) => {
                write_fence(write_fence_of(s, rev), arg);
                0
            }
            Some(e) => e,
        });
    }
    if s.settled.live != 0 && &s.settled.ask == ask {
        s.settled.live = 0;
        let (rc, rev) = (s.settled.rc, s.settled.rev);
        if rc == 0 {
            write_fence(write_fence_of(s, rev), arg);
        }
        return Some(rc);
    }
    None
}

/// The answer of a write `begin_write` started.
fn answer_write(s: &mut State, started: Option<i32>, arg: &mut [u8]) -> i32 {
    match started {
        None => EINPROGRESS,
        Some(0) => {
            let rev = s.revision;
            write_fence(write_fence_of(s, rev), arg);
            0
        }
        Some(e) => e,
    }
}
