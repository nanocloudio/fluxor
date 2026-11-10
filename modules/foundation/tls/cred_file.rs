// Credentials named by path and read at runtime.
//
// `cert_file`, `key_file` and `trust` given as a plain path are read by the
// instance itself, through the `fs` contract (class `fs`: OPEN / READ /
// CLOSE), so an image carries no credential and no deployment's trust: the
// platform's file surface supplies them where the instance runs. On the
// Linux host that surface is the caller's — the host's paths for a node
// graph, and for a workload its owner root and the volumes lent to it (a
// lent credential volume). The build-time form, `${file:<path>}`, is the builder's
// to embed (extended tags 10/11/12) and never reaches this file.
//
// A file is PEM or DER. PEM takes the blocks its kind names (every
// CERTIFICATE for a certificate chain or a trust bundle, the first PRIVATE
// KEY / EC PRIVATE KEY / RSA PRIVATE KEY for a key) and skips every other
// block, as an `openssl ecparam -genkey` file's EC PARAMETERS; an encrypted
// key, a block that does not decode or a file with no block is malformed.
// A file whose first byte is a DER SEQUENCE tag is taken as it is.
//
// Readiness. Until every configured file has been read whole and adopted,
// the instance is not ready: a server refuses handshakes before presenting
// anything and a client answers a dial `EAGAIN`, exactly as an uncertified
// `identity_label` does. A file that cannot be opened or read (absent,
// unreadable, no `fs` provider) is retried every `CRED_RETRY_MS`; one that
// is malformed, or whose content the instance refuses, is retried as often
// and reported once per distinct content (its SHA-256), so a fixed file
// takes effect without a restart and a broken one does not flood the log.
//
// Rotation (targets with `CRED_ROTATE`): adopted files are re-read every
// `CRED_RECHECK_MS`. A changed set is adopted only when two consecutive
// reads of every file agree, which a volume swapping its files at once
// between two files' reads cannot satisfy; the instance then validates it and
// installs it between handshakes. A rotation that does not validate keeps
// the credentials in use and is reported. Where `CRED_ROTATE` is false the
// files are read once and decoded straight into the live buffers, which
// costs no staging memory; a change there takes a restart.

/// Longest path a credential parameter may name (a basic TLV string).
const CRED_PATH_MAX: usize = 255;
/// Bytes asked of one `READ`.
const CRED_CHUNK: usize = 256;
/// `READ`s one step may spend on credentials.
const CRED_READS_PER_STEP: usize = 16;
/// Raw file bytes a credential may take: a PEM bundle of `MAX_ANCHORS`
/// large certificates fits well inside.
const CRED_RAW_MAX: usize = 64 * 1024;
/// Between attempts while a file is unreadable or refused.
const CRED_RETRY_MS: u64 = 1000;
/// Between re-reads of adopted files.
const CRED_RECHECK_MS: u64 = 10_000;
/// How long a validated rotation may wait for in-flight handshakes before
/// it is installed regardless.
const CRED_DEFER_MAX_MS: u64 = 2000;
/// Whether adopted files are re-read and a change installed live. Needs
/// staging buffers beside the live ones, so it is the aarch64 targets'.
const CRED_ROTATE: bool = cfg!(target_arch = "aarch64");

/// The slots of a credential set, in the order they are read.
const CRED_CERT: usize = 0;
const CRED_KEY: usize = 1;
const CRED_TRUST: usize = 2;
const CRED_SLOTS: usize = 3;

/// One read's outcome.
const CF_PENDING: u8 = 0;
const CF_DONE: u8 = 1;
const CF_UNREADABLE: u8 = 2;
const CF_MALFORMED: u8 = 3;

/// What `CredSet::step` asks of its instance.
const CS_IDLE: u8 = 0;
/// Every configured file was read: validate `staged` and install it, then
/// answer `adopt` or `refuse`.
const CS_CANDIDATE: u8 = 1;

/// A streaming PEM / DER decoder writing into a caller's buffer.
#[derive(Clone, Copy)]
struct PemDec {
    /// Take one key block (`true`) or every certificate block.
    key: bool,
    /// 0 undecided, 1 DER, 2 PEM.
    mode: u8,
    /// 0 between blocks, 1 inside a block taken, 2 inside a block skipped.
    block: u8,
    line: [u8; 96],
    line_len: u8,
    quad: [u8; 4],
    quad_len: u8,
    /// '=' seen in the current block: no data may follow.
    padded: bool,
    blocks: u8,
    bad: bool,
}

impl PemDec {
    const fn new(key: bool) -> Self {
        Self {
            key,
            mode: 0,
            block: 0,
            line: [0; 96],
            line_len: 0,
            quad: [0; 4],
            quad_len: 0,
            padded: false,
            blocks: 0,
            bad: false,
        }
    }

    /// Feed `data`, writing decoded bytes at `out[*len..cap]`.
    unsafe fn feed(&mut self, data: &[u8], out: *mut u8, cap: usize, len: &mut usize) {
        for &b in data {
            if self.bad {
                return;
            }
            if self.mode == 0 {
                self.mode = if b == 0x30 { 1 } else { 2 };
            }
            if self.mode == 1 {
                if *len >= cap {
                    self.bad = true;
                    return;
                }
                *out.add(*len) = b;
                *len += 1;
                continue;
            }
            if b == b'\n' {
                self.end_line(out, cap, len);
                continue;
            }
            if b == b'\r' {
                continue;
            }
            if self.line_len as usize >= self.line.len() {
                // A long line inside a taken block is base64 of any line
                // length; anywhere else it is text that names no marker.
                if self.block == 1 && self.line[0] != b'-' {
                    self.data_line(out, cap, len);
                } else if self.line[0] == b'-' {
                    self.bad = true;
                    return;
                } else {
                    // Free text: keep only its start, which says it is
                    // not a marker.
                    self.line_len = 1;
                }
            }
            self.line[self.line_len as usize] = b;
            self.line_len += 1;
        }
    }

    /// The end of the file: the decision.
    unsafe fn finish(&mut self, out: *mut u8, cap: usize, len: &mut usize) -> bool {
        if self.mode == 2 && self.line_len > 0 {
            self.end_line(out, cap, len);
        }
        match self.mode {
            1 => !self.bad && *len > 0,
            2 => !self.bad && self.block == 0 && self.blocks > 0,
            _ => false,
        }
    }

    unsafe fn end_line(&mut self, out: *mut u8, cap: usize, len: &mut usize) {
        let n = self.line_len as usize;
        let mut a = 0;
        let mut z = n;
        while a < z && (self.line[a] == b' ' || self.line[a] == b'\t') {
            a += 1;
        }
        while z > a && (self.line[z - 1] == b' ' || self.line[z - 1] == b'\t') {
            z -= 1;
        }
        let line = self.line;
        let t = &line[a..z];
        if let Some(label) = marker(t, b"-----BEGIN ") {
            if self.block != 0 {
                self.bad = true;
            } else if self.key {
                if label == b"ENCRYPTED PRIVATE KEY" {
                    // Nothing here can decrypt it; serving without it
                    // would be serving a different identity.
                    self.bad = true;
                } else if self.blocks == 0
                    && (label == b"PRIVATE KEY"
                        || label == b"EC PRIVATE KEY"
                        || label == b"RSA PRIVATE KEY")
                {
                    self.block = 1;
                } else {
                    self.block = 2;
                }
            } else if label == b"CERTIFICATE" {
                self.block = 1;
            } else {
                self.block = 2;
            }
            self.quad_len = 0;
            self.padded = false;
        } else if marker(t, b"-----END ").is_some() {
            if self.block == 1 {
                if self.quad_len != 0 {
                    self.bad = true;
                }
                self.blocks = self.blocks.saturating_add(1);
            } else if self.block == 0 {
                self.bad = true;
            }
            self.block = 0;
        } else if self.block == 1 {
            // A header line (`Proc-Type: 4,ENCRYPTED`) is an encrypted or
            // legacy block this decoder cannot honour.
            if has_byte(t, b':') {
                self.bad = true;
            } else {
                self.line_len = n as u8;
                self.data_line(out, cap, len);
            }
        }
        self.line_len = 0;
    }

    /// Decode the line buffer as base64 data and empty it.
    unsafe fn data_line(&mut self, out: *mut u8, cap: usize, len: &mut usize) {
        let n = self.line_len as usize;
        let mut i = 0;
        while i < n && !self.bad {
            let c = self.line[i];
            i += 1;
            if c == b' ' || c == b'\t' {
                continue;
            }
            if c == b'=' {
                self.padded = true;
                self.quad[self.quad_len as usize] = 64;
                self.quad_len += 1;
            } else {
                let v = b64_value(c);
                if v > 63 || self.padded {
                    self.bad = true;
                    return;
                }
                self.quad[self.quad_len as usize] = v;
                self.quad_len += 1;
            }
            if self.quad_len == 4 {
                self.quad_len = 0;
                let q = self.quad;
                let take = if q[2] == 64 {
                    if q[3] != 64 {
                        self.bad = true;
                        return;
                    }
                    1
                } else if q[3] == 64 {
                    2
                } else {
                    3
                };
                if q[0] == 64 || q[1] == 64 || *len + take > cap {
                    self.bad = true;
                    return;
                }
                let bytes = [
                    (q[0] << 2) | (q[1] >> 4),
                    (q[1] << 4) | ((q[2] & 0x3F) >> 2),
                    ((q[2] & 0x3F) << 6) | (q[3] & 0x3F),
                ];
                let mut k = 0;
                while k < take {
                    *out.add(*len) = bytes[k];
                    *len += 1;
                    k += 1;
                }
            }
        }
        self.line_len = 0;
    }
}

/// The label of a PEM marker line `-----BEGIN <label>-----`.
fn marker<'a>(t: &'a [u8], head: &[u8]) -> Option<&'a [u8]> {
    if t.len() < head.len() + 5 || &t[..head.len()] != head || &t[t.len() - 5..] != b"-----" {
        return None;
    }
    Some(&t[head.len()..t.len() - 5])
}

/// Whether `b` occurs in `t`. A loop rather than `<[u8]>::contains`, whose
/// byte specialisation calls into `core`'s `memchr`, which a module image
/// does not link.
fn has_byte(t: &[u8], b: u8) -> bool {
    let mut i = 0;
    while i < t.len() {
        if t[i] == b {
            return true;
        }
        i += 1;
    }
    false
}

/// A base64 digit's value, or 255.
fn b64_value(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 255,
    }
}

/// One credential file: its path, and the read in progress.
struct CredFile {
    path: [u8; CRED_PATH_MAX],
    path_len: u8,
    /// The path was longer than `CRED_PATH_MAX`, or not absolute.
    bad_path: bool,
    fd: i32,
    raw: usize,
    out_len: usize,
    dec: PemDec,
    hash: Sha256,
    /// The last whole read: its digest and decoded length.
    digest: [u8; 32],
    len: usize,
    /// The last unreadable answer.
    errno: i32,
}

impl CredFile {
    fn set_path(&mut self, d: &[u8]) {
        if d.is_empty() {
            return;
        }
        if d.len() > CRED_PATH_MAX || d[0] != b'/' || has_byte(d, 0) {
            self.bad_path = true;
            return;
        }
        self.path[..d.len()].copy_from_slice(d);
        self.path_len = d.len() as u8;
    }

    fn configured(&self) -> bool {
        self.path_len > 0
    }

    fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Drop a read in progress.
    unsafe fn abandon(&mut self, sys: &SyscallTable) {
        if self.fd >= 0 {
            let _ = (sys.provider_call)(
                self.fd,
                abi::contracts::storage::fs::CLOSE,
                core::ptr::null_mut(),
                0,
            );
            self.fd = -1;
        }
    }

    /// One bounded slice of a whole read of the file into `out[..cap]`.
    unsafe fn pump(&mut self, sys: &SyscallTable, out: *mut u8, cap: usize) -> u8 {
        use abi::contracts::storage::fs;
        if self.fd < 0 {
            let mut p = [0u8; CRED_PATH_MAX + 1];
            let n = self.path_len as usize;
            p[..n].copy_from_slice(&self.path[..n]);
            let rc = (sys.provider_call)(-1, fs::OPEN, p.as_mut_ptr(), n);
            if rc == abi::errno::EAGAIN || rc == abi::errno::EINPROGRESS {
                return CF_PENDING;
            }
            if rc < 0 {
                self.errno = rc;
                return CF_UNREADABLE;
            }
            self.fd = rc;
            self.raw = 0;
            self.out_len = 0;
            self.dec = PemDec::new(self.dec.key);
            self.hash = Sha256::new();
        }
        let mut reads = 0;
        let mut chunk = [0u8; CRED_CHUNK];
        while reads < CRED_READS_PER_STEP {
            reads += 1;
            let r = (sys.provider_call)(self.fd, fs::READ, chunk.as_mut_ptr(), CRED_CHUNK);
            if r == abi::errno::EAGAIN {
                return CF_PENDING;
            }
            if r < 0 || r as usize > CRED_CHUNK {
                self.errno = if r < 0 { r } else { abi::errno::EINVAL };
                self.abandon(sys);
                return CF_UNREADABLE;
            }
            if r == 0 {
                self.abandon(sys);
                let mut len = self.out_len;
                let ok = self.dec.finish(out, cap, &mut len);
                let h = core::mem::take(&mut self.hash);
                self.digest = h.finalize();
                self.len = len;
                return if ok { CF_DONE } else { CF_MALFORMED };
            }
            let got = &chunk[..r as usize];
            self.raw += got.len();
            if self.raw > CRED_RAW_MAX {
                self.abandon(sys);
                self.digest = [0xFF; 32];
                self.len = 0;
                return CF_MALFORMED;
            }
            self.hash.update(got);
            let mut len = self.out_len;
            self.dec.feed(got, out, cap, &mut len);
            self.out_len = len;
        }
        CF_PENDING
    }
}

/// The credential files of one instance and where its reads stand.
struct CredSet {
    files: [CredFile; CRED_SLOTS],
    /// The slot being read; `CRED_SLOTS` between passes.
    cur: u8,
    /// A pass's files are all read and await the instance's answer.
    candidate: bool,
    /// Adopted at least once: the instance is ready.
    ready: bool,
    next_at: u64,
    /// Digests of the files in use.
    adopted: [[u8; 32]; CRED_SLOTS],
    /// Digests of the previous pass of a rotation, which the next must match.
    pass: [[u8; 32]; CRED_SLOTS],
    have_pass: bool,
    /// When a validated rotation first waited for in-flight handshakes.
    defer_since: u64,
    /// What was last reported per slot, so a state is said once.
    said: [u8; CRED_SLOTS],
    said_digest: [[u8; 32]; CRED_SLOTS],
    said_errno: [i32; CRED_SLOTS],
}

impl CredSet {
    /// Initialise in place, so module state need not hold a second copy on
    /// the stack: zeroed, then the fields whose idle value is not zero.
    unsafe fn init(c: *mut CredSet) {
        core::ptr::write_bytes(c as *mut u8, 0, core::mem::size_of::<CredSet>());
        let c = &mut *c;
        let mut i = 0;
        while i < CRED_SLOTS {
            c.files[i].fd = -1;
            c.files[i].dec.key = i == CRED_KEY;
            c.files[i].hash = Sha256::new();
            i += 1;
        }
        c.cur = CRED_SLOTS as u8;
    }

    /// Any credential named by path.
    fn configured(&self) -> bool {
        self.files.iter().any(|f| f.configured())
    }

    fn bad_path(&self) -> bool {
        self.files.iter().any(|f| f.bad_path)
    }

    /// Ready to serve: nothing named by path, or every such file adopted.
    fn ready(&self) -> bool {
        self.ready || !self.configured()
    }

    /// The next configured slot at or after `from`, or `CRED_SLOTS`.
    fn next_slot(&self, from: usize) -> usize {
        let mut i = from;
        while i < CRED_SLOTS && !self.files[i].configured() {
            i += 1;
        }
        i
    }

    /// One step. `dest[i]` is where slot `i` decodes (pointer, capacity).
    /// `CS_CANDIDATE` when a pass is complete and awaits `adopt` / `refuse`
    /// (the decoded lengths are `files[i].len`); `CS_IDLE` otherwise.
    unsafe fn step(
        &mut self,
        sys: &SyscallTable,
        tag: &[u8],
        dest: &[(*mut u8, usize); CRED_SLOTS],
    ) -> u8 {
        if !self.configured() {
            return CS_IDLE;
        }
        if self.candidate {
            return CS_CANDIDATE;
        }
        let now = dev_millis(sys);
        if self.cur as usize >= CRED_SLOTS {
            if now < self.next_at {
                return CS_IDLE;
            }
            self.cur = self.next_slot(0) as u8;
        }
        while (self.cur as usize) < CRED_SLOTS {
            let i = self.cur as usize;
            let (p, cap) = dest[i];
            match self.files[i].pump(sys, p, cap) {
                CF_PENDING => return CS_IDLE,
                CF_DONE => {
                    self.cur = self.next_slot(i + 1) as u8;
                }
                outcome => {
                    self.cur = CRED_SLOTS as u8;
                    self.have_pass = false;
                    self.next_at = now + CRED_RETRY_MS;
                    self.report(sys, tag, i, outcome);
                    return CS_IDLE;
                }
            }
        }
        // A whole pass.
        let mut digests = [[0u8; 32]; CRED_SLOTS];
        let mut i = 0;
        while i < CRED_SLOTS {
            digests[i] = self.files[i].digest;
            i += 1;
        }
        if self.ready {
            if digests == self.adopted {
                self.have_pass = false;
                self.next_at = now + CRED_RECHECK_MS;
                return CS_IDLE;
            }
            if !self.have_pass || digests != self.pass {
                // Read once more before believing a change: a set swapped
                // between two files' reads does not read the same twice.
                self.pass = digests;
                self.have_pass = true;
                self.next_at = now;
                return CS_IDLE;
            }
        }
        self.candidate = true;
        CS_CANDIDATE
    }

    /// The candidate was installed.
    unsafe fn adopt(&mut self, sys: &SyscallTable, tag: &[u8]) {
        let rotation = self.ready;
        let mut i = 0;
        while i < CRED_SLOTS {
            self.adopted[i] = self.files[i].digest;
            self.said[i] = CF_DONE;
            i += 1;
        }
        self.candidate = false;
        self.ready = true;
        self.have_pass = false;
        self.defer_since = 0;
        self.next_at = if CRED_ROTATE {
            dev_millis(sys) + CRED_RECHECK_MS
        } else {
            u64::MAX
        };
        let mut line = [0u8; 64];
        let mut w = cf_put(&mut line, 0, tag);
        w = cf_put(
            &mut line,
            w,
            if rotation {
                b" credentials rotated from their files"
            } else {
                b" credentials read from their files: ready"
            },
        );
        dev_log(sys, 3, line.as_ptr(), w);
    }

    /// The candidate was refused by the instance: `why` says what it found.
    /// Credentials in use stay in use; the files are read again later.
    unsafe fn refuse(&mut self, sys: &SyscallTable, tag: &[u8], slot: usize, why: &[u8]) {
        self.candidate = false;
        self.have_pass = false;
        self.defer_since = 0;
        self.next_at = dev_millis(sys) + CRED_RETRY_MS;
        let f = &self.files[slot];
        if self.said[slot] == CF_MALFORMED && self.said_digest[slot] == f.digest {
            return;
        }
        self.said[slot] = CF_MALFORMED;
        self.said_digest[slot] = f.digest;
        self.log_slot(sys, tag, slot, why, 0);
    }

    /// A validated rotation waits for in-flight handshakes. True when it
    /// has waited long enough to be installed regardless.
    unsafe fn deferred_long_enough(&mut self, sys: &SyscallTable) -> bool {
        let now = dev_millis(sys).max(1);
        if self.defer_since == 0 {
            self.defer_since = now;
        }
        now.saturating_sub(self.defer_since) >= CRED_DEFER_MAX_MS
    }

    unsafe fn report(&mut self, sys: &SyscallTable, tag: &[u8], slot: usize, outcome: u8) {
        let f = &self.files[slot];
        let repeat = self.said[slot] == outcome
            && match outcome {
                CF_UNREADABLE => self.said_errno[slot] == f.errno,
                _ => self.said_digest[slot] == f.digest,
            };
        if repeat {
            return;
        }
        self.said[slot] = outcome;
        self.said_errno[slot] = f.errno;
        self.said_digest[slot] = f.digest;
        let errno = f.errno;
        if outcome == CF_UNREADABLE {
            self.log_slot(sys, tag, slot, b"cannot be read, errno ", errno);
        } else {
            self.log_slot(sys, tag, slot, b"is malformed (PEM or DER expected)", 0);
        }
    }

    unsafe fn log_slot(&self, sys: &SyscallTable, tag: &[u8], slot: usize, why: &[u8], errno: i32) {
        let mut line = [0u8; 400];
        let mut w = cf_put(&mut line, 0, tag);
        w = cf_put(
            &mut line,
            w,
            match slot {
                CRED_CERT => b" cert_file ",
                CRED_KEY => b" key_file ",
                _ => b" trust ",
            },
        );
        w = cf_put(&mut line, w, self.files[slot].path());
        w = cf_put(&mut line, w, b" ");
        w = cf_put(&mut line, w, why);
        if errno < 0 {
            w = cf_put(&mut line, w, b"-");
            w += fmt_u32_raw(line.as_mut_ptr().add(w), errno.unsigned_abs());
        }
        if self.ready {
            w = cf_put(&mut line, w, b"; keeping the credentials in use");
        } else {
            w = cf_put(&mut line, w, b"; not ready, retrying");
        }
        dev_log(sys, 1, line.as_ptr(), w);
    }
}

fn cf_put(line: &mut [u8], at: usize, text: &[u8]) -> usize {
    let n = text.len().min(line.len().saturating_sub(at + 12));
    line[at..at + n].copy_from_slice(&text[..n]);
    at + n
}

/// The spans of the concatenated DER certificates at `src[..len]`, each a
/// SEQUENCE of at most `slot_len` bytes that parses as a certificate, at
/// most `max` (and `MAX_ANCHORS`) of them. The count, or `None` when refused.
unsafe fn certificate_spans(
    src: *const u8,
    len: usize,
    slot_len: usize,
    max: usize,
    spans: &mut [(usize, usize); MAX_ANCHORS],
) -> Option<usize> {
    let bundle = core::slice::from_raw_parts(src, len);
    let (mut pos, mut n) = (0usize, 0usize);
    while pos < len {
        let (_, _, total) = der_tlv(bundle, pos)?;
        if total == 0
            || pos + total > len
            || bundle[pos] != 0x30
            || n >= max
            || n >= MAX_ANCHORS
            || total > slot_len
            || parse_certificate(&bundle[pos..pos + total]).is_none()
        {
            return None;
        }
        spans[n] = (pos, total);
        n += 1;
        pos += total;
    }
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

/// How many certificates [`split_certificates`] would place, or `None`.
unsafe fn count_certificates(
    src: *const u8,
    len: usize,
    slot_len: usize,
    max: usize,
) -> Option<usize> {
    let mut spans = [(0usize, 0usize); MAX_ANCHORS];
    certificate_spans(src, len, slot_len, max, &mut spans)
}

/// Split concatenated DER certificates at `src[..len]` into fixed slots of
/// `slot_len` bytes starting at `dst` (slot `k` at `dst + k * slot_len`),
/// as [`certificate_spans`] admits them, validated whole before anything
/// is written; `src` may be the slot region itself. Each placed length is
/// written to `lens`; the count, or `None` when refused.
unsafe fn split_certificates(
    src: *const u8,
    len: usize,
    dst: *mut u8,
    slot_len: usize,
    max: usize,
    lens: &mut [u16; MAX_ANCHORS],
) -> Option<usize> {
    let mut spans = [(0usize, 0usize); MAX_ANCHORS];
    let n = certificate_spans(src, len, slot_len, max, &mut spans)?;
    // Last first: certificate `k` moves to an offset no lower than its own,
    // over no byte of one not yet moved.
    let mut k = n;
    while k > 0 {
        k -= 1;
        let (at, total) = spans[k];
        core::ptr::copy(src.add(at), dst.add(k * slot_len), total);
        lens[k] = total as u16;
    }
    Some(n)
}

/// Is `chain[..len]` one or more certificates, leaf first, each parsing?
fn chain_parses(chain: &[u8]) -> bool {
    let mut pos = 0;
    let mut n = 0;
    while pos < chain.len() {
        let Some((_, _, total)) = der_tlv(chain, pos) else {
            return false;
        };
        if total == 0
            || pos + total > chain.len()
            || chain[pos] != 0x30
            || n >= MAX_CHAIN_LEN
            || parse_certificate(&chain[pos..pos + total]).is_none()
        {
            return false;
        }
        n += 1;
        pos += total;
    }
    n > 0
}
