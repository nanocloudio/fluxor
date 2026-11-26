// ── Token custody: the `key_custody` client ─────────────────────────────
//
// With `custody = token`, labelled P-256 keys asked to persist with uses the
// token gives, and every unnamed P-256 key, are made and held by the
// `key_custody` provider; their slots here carry the token's handle. Every
// token call is resumable (the provider answers `EAGAIN` until it has
// answered, and the identical repeat collects), and the provider takes one
// call at a time from this vault, so the vault holds one token job: the
// caller, op and bytes it serves, the stage it is at and each finished
// stage's answer. A vault call makes at most one token call; a vault op
// needing two answers `EAGAIN` between them and, repeated unchanged, replays
// the finished stage and makes the next. Another caller's op waits
// (`EAGAIN`) until the job finishes or is abandoned past the sign-job idle
// bound.
//
// A provider that is not there (`ENOSYS`, `ENODEV`) is a refusal, never a
// cue to make the key in software.

use abi::contracts::key_custody as kc;

/// Bytes a stage's answer keeps: the longest `arg` a token op answers.
const ANSWER_MAX: usize = kc::find::OUT_LEN;
/// Stages a vault op may take.
const STAGES: usize = 2;

/// Who a token job serves: the caller, the vault op, its handle and the
/// SHA-256 of its `arg` and `data` as they arrived.
#[derive(Clone, Copy, PartialEq, Eq)]
struct JobKey {
    occupancy: [u8; 8],
    op: u32,
    handle: i32,
    fingerprint: [u8; 32],
}

impl JobKey {
    const fn none() -> Self {
        Self {
            occupancy: [0xFF; 8],
            op: 0,
            handle: -1,
            fingerprint: [0; 32],
        }
    }
}

#[repr(C)]
struct CustodyCall {
    key: JobKey,
    active: u8,
    /// The next stage to call.
    stage: u8,
    /// A token call was made in this vault call.
    issued: u8,
    _pad: u8,
    rc: [i32; STAGES],
    answer: [[u8; ANSWER_MAX]; STAGES],
    touched: u64,
}

impl Slot {
    /// The token's handle for the key this slot stands for.
    fn token_handle(&self) -> i32 {
        i32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }
}

/// The key of the vault op now being served.
fn job_key(s: &State, op: u32, handle: i32, arg: &[u8], data: &[u8]) -> JobKey {
    let mut h = Sha256::new();
    h.update(&(arg.len() as u32).to_le_bytes());
    h.update(arg);
    h.update(data);
    JobKey {
        occupancy: caller(s).map_or([0xFF; 8], |c| c.occupancy),
        op,
        handle,
        fingerprint: h.finalize(),
    }
}

/// Stage `stage` of the job `jk`: token op `op` on `handle` with `arg`,
/// whose answer is written back over `arg`. The finished stage's answer,
/// `EAGAIN` while the token or another job is in the way, or the token's
/// refusal.
fn token_call(s: &mut State, jk: &JobKey, stage: u8, op: u32, handle: i32, arg: &mut [u8]) -> i32 {
    let now = now_ms(s);
    let cc = &mut s.custody_call;
    if cc.active != 0 && cc.key != *jk {
        if now.saturating_sub(cc.touched) < kv::sign::JOB_IDLE_MS {
            return EAGAIN;
        }
        *cc = CustodyCall::idle();
    }
    if cc.active == 0 {
        cc.active = 1;
        cc.key = *jk;
        cc.stage = 0;
    }
    cc.touched = now;
    let st = usize::from(stage);
    if st >= STAGES {
        return EINVAL;
    }
    if stage < cc.stage {
        let n = arg.len().min(ANSWER_MAX);
        arg[..n].copy_from_slice(&cc.answer[st][..n]);
        return cc.rc[st];
    }
    if stage > cc.stage || cc.issued != 0 {
        return EAGAIN;
    }
    cc.issued = 1;
    let rc = kcall(s, handle, op, arg, &mut []);
    let rc = match rc {
        EAGAIN | EBUSY => return EAGAIN,
        // No provider: refused, and the job is over.
        ENOSYS | ENODEV => {
            s.custody_call = CustodyCall::idle();
            return ENODEV;
        }
        rc => rc,
    };
    let cc = &mut s.custody_call;
    let n = arg.len().min(ANSWER_MAX);
    cc.answer[st][..n].copy_from_slice(&arg[..n]);
    cc.rc[st] = rc;
    cc.stage = stage + 1;
    rc
}

impl CustodyCall {
    const fn idle() -> Self {
        Self {
            key: JobKey::none(),
            active: 0,
            stage: 0,
            issued: 0,
            _pad: 0,
            rc: [0; STAGES],
            answer: [[0; ANSWER_MAX]; STAGES],
            touched: 0,
        }
    }
}

/// The job `jk` is over: its answers go.
fn token_done(s: &mut State, jk: &JobKey) {
    if s.custody_call.active != 0 && s.custody_call.key == *jk {
        let issued = s.custody_call.issued;
        zeroize(&mut s.custody_call.answer[0]);
        zeroize(&mut s.custody_call.answer[1]);
        s.custody_call = CustodyCall::idle();
        s.custody_call.issued = issued;
    }
}

/// `e` as the vault op's answer: the job stays for an `EAGAIN`, and is
/// over otherwise.
fn token_settle(s: &mut State, jk: &JobKey, e: i32) -> i32 {
    if e != EAGAIN {
        token_done(s, jk);
    }
    e
}

/// Mint a slot holding token handle `th` for the caller.
fn token_slot(
    s: &mut State,
    th: i32,
    usage: u32,
    persisted: bool,
    who: Caller,
    scope: Scope,
    label: &[u8],
) -> Result<i32, i32> {
    let Some(i) = alloc_slot(s) else {
        return Err(ENOMEM);
    };
    label_slot(s, i, label);
    let flags = FLAG_IN_USE | FLAG_TOKEN | if persisted { FLAG_PERSISTED } else { 0 };
    fill_slot(s, i, kv::suite::P256, usage, &th.to_le_bytes(), flags);
    Ok(mint(s, i, who, scope))
}

/// `GENERATE` of an unnamed P-256 key on the token.
fn token_generate(
    s: &mut State,
    handle: i32,
    arg: &mut [u8],
    buf: &mut [u8],
    usage: u32,
    flags: u8,
) -> i32 {
    let _ = flags;
    if usage == 0 || usage & !kc::USAGE != 0 {
        return EINVAL;
    }
    if buf.len() < kc::PUB_LEN {
        kv::generate::set_len(arg, kc::PUB_LEN);
        return ERANGE;
    }
    let jk = job_key(s, kv::GENERATE, handle, arg, &[]);
    let Some((who, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    // An unnamed key has no name to come back by: never persisted.
    let mut a = [0u8; kc::generate::ARG_LEN];
    if kc::generate::encode(scope.namespace, usage & !kv::usage::PERSIST, &[], &mut a).is_none() {
        return EINVAL;
    }
    let th = token_call(s, &jk, 0, kc::GENERATE, -1, &mut a);
    if th < 0 {
        return token_settle(s, &jk, th);
    }
    token_done(s, &jk);
    buf[..kc::PUB_LEN].copy_from_slice(&a[..kc::PUB_LEN]);
    kv::generate::set_len(arg, kc::PUB_LEN);
    match token_slot(s, th, usage & !kv::usage::PERSIST, false, who, scope, &[]) {
        Ok(h) => h,
        Err(e) => e,
    }
}

/// `OPEN` / `OPEN_OR_GENERATE` of a label no slot holds and this vault's
/// records lack: the token's key, else (for `OPEN_OR_GENERATE`) made on the
/// token when it is asked to persist with uses the token gives, in software
/// otherwise.
fn token_open(
    s: &mut State,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    buf: &mut [u8],
    who: Caller,
    scope: Scope,
    label: &[u8],
    usage: u32,
) -> i32 {
    let jk = job_key(s, opcode, handle, arg, &[]);
    let mut a = [0u8; kc::find::ARG_LEN];
    a[..4].copy_from_slice(&scope.namespace.to_le_bytes());
    a[4] = label.len() as u8;
    a[5..5 + label.len()].copy_from_slice(label);
    let rc = token_call(s, &jk, 0, kc::FIND, -1, &mut a);
    if rc >= 0 {
        let Some(found) = kc::find::parse_found(&a) else {
            return token_settle(s, &jk, ERROR);
        };
        token_done(s, &jk);
        // The mask is checked against the key's sealed uses, never applied.
        if usage & !found.usage != 0 {
            return EACCES;
        }
        buf[..kc::PUB_LEN].copy_from_slice(&found.public);
        kv::open::set_len(arg, kc::PUB_LEN);
        return match token_slot(s, rc, found.usage, found.persisted, who, scope, label) {
            Ok(h) => h,
            Err(e) => e,
        };
    }
    if rc != ENOENT {
        return token_settle(s, &jk, rc);
    }
    if opcode == kv::OPEN {
        token_done(s, &jk);
        return ENOENT;
    }
    // A use the token cannot give (WRAP: its key's bytes are nowhere to
    // wrap) keeps the key in software.
    if usage & kv::usage::PERSIST == 0 || usage & !kc::USAGE != 0 {
        token_done(s, &jk);
        return open_software(
            s,
            opcode,
            arg,
            buf,
            who,
            scope,
            label,
            kv::suite::P256,
            usage,
        );
    }
    let mut g = [0u8; kc::generate::ARG_LEN];
    if kc::generate::encode(scope.namespace, usage, label, &mut g).is_none() {
        return token_settle(s, &jk, EINVAL);
    }
    let th = token_call(s, &jk, 1, kc::GENERATE, -1, &mut g);
    if th < 0 {
        return token_settle(s, &jk, th);
    }
    token_done(s, &jk);
    buf[..kc::PUB_LEN].copy_from_slice(&g[..kc::PUB_LEN]);
    kv::open::set_len(arg, kc::PUB_LEN);
    match token_slot(s, th, usage, true, who, scope, label) {
        Ok(h) => h,
        Err(e) => e,
    }
}

/// A token key already open under the label, returned to its owner: its
/// public half from the token.
fn token_open_existing(
    s: &mut State,
    i: usize,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    buf: &mut [u8],
) -> i32 {
    let jk = job_key(s, opcode, handle, arg, &[]);
    let mut p = [0u8; 65];
    if let Err(e) = token_public_of(s, &jk, i, &mut p) {
        return token_settle(s, &jk, e);
    }
    token_done(s, &jk);
    buf[..65].copy_from_slice(&p);
    kv::open::set_len(arg, 65);
    i as i32
}

/// Slot `i`'s public half from the token, as stage 0 of `jk`.
fn token_public_of(s: &mut State, jk: &JobKey, i: usize, out: &mut [u8; 65]) -> Result<(), i32> {
    let th = slots(s)[i].token_handle();
    let mut a = [0u8; kc::public::ARG_LEN];
    let rc = token_call(s, jk, 0, kc::PUBLIC, th, &mut a);
    if rc < 0 {
        return Err(rc);
    }
    if rc as usize != kc::PUB_LEN {
        return Err(ERROR);
    }
    out.copy_from_slice(&a[..kc::PUB_LEN]);
    Ok(())
}

/// The token's agreement with `peer` on slot `i`, and its public half: the
/// opener of a share envelope held by the token.
fn token_agree(
    s: &mut State,
    jk: &JobKey,
    i: usize,
    peer: &[u8],
    shared: &mut [u8; 32],
) -> Result<[u8; 65], i32> {
    let sl = slots(s)[i];
    if !sl.permits(kv::usage::AGREE) || !sl.permits(kv::usage::EXPORT_PUBLIC) {
        return Err(EACCES);
    }
    let mut public = [0u8; 65];
    token_public_of(s, jk, i, &mut public)?;
    let mut a = [0u8; kc::ecdh::ARG_LEN];
    if kc::ecdh::encode(peer, &mut a).is_none() {
        return Err(EINVAL);
    }
    let rc = token_call(s, jk, 1, kc::ECDH, sl.token_handle(), &mut a);
    if rc < 0 {
        return Err(rc);
    }
    if rc as usize != kc::SECRET_LEN {
        return Err(ERROR);
    }
    shared.copy_from_slice(&a[..32]);
    zeroize(&mut a);
    Ok(public)
}

/// The token half of `DESTROY_BY_LABEL`: `FIND`, then `DESTROY` with
/// `REMOVE`. Whether the token held the key.
fn token_destroy_by_label(
    s: &mut State,
    handle: i32,
    arg: &[u8],
    scope: Scope,
    label: &[u8],
) -> Result<bool, i32> {
    let jk = job_key(s, kv::DESTROY_BY_LABEL, handle, arg, &[]);
    let mut a = [0u8; kc::find::ARG_LEN];
    a[..4].copy_from_slice(&scope.namespace.to_le_bytes());
    a[4] = label.len() as u8;
    a[5..5 + label.len()].copy_from_slice(label);
    let th = token_call(s, &jk, 0, kc::FIND, -1, &mut a);
    if th == ENOENT {
        token_done(s, &jk);
        return Ok(false);
    }
    if th < 0 {
        return Err(token_settle(s, &jk, th));
    }
    let mut d = [kc::destroy::REMOVE];
    let rc = token_call(s, &jk, 1, kc::DESTROY, th, &mut d);
    if rc < 0 && rc != ENOENT {
        return Err(token_settle(s, &jk, rc));
    }
    token_done(s, &jk);
    // Every handle open on the name is retired by the token: their slots go.
    for i in 0..usize::from(s.n_slots) {
        let sl = slots(s)[i];
        if sl.filed_as(scope, label) && sl.flags & FLAG_TOKEN != 0 {
            free_token_slot(s, i);
        }
    }
    Ok(true)
}

/// Free a token slot outright: its token handle is gone already.
fn free_token_slot(s: &mut State, i: usize) {
    slots(s)[i].flags &= !FLAG_TOKEN;
    zeroise_slot(s, i);
}

/// `SIGN` with a token key: P-256 over a digest, whole.
fn token_sign(
    s: &mut State,
    idx: usize,
    handle: i32,
    mode: u8,
    input_len: usize,
    arg: &mut [u8],
    buf: &mut [u8],
) -> i32 {
    if mode != kv::sign_mode::DIGEST || input_len == 0 || input_len > kv::sign::DIGEST_MAX {
        return EINVAL;
    }
    if input_len > buf.len() {
        return EINVAL;
    }
    if buf.len() < kc::SIG_LEN {
        kv::sign::set_len(arg, kc::SIG_LEN);
        return ERANGE;
    }
    let jk = job_key(s, kv::SIGN, handle, arg, &buf[..input_len]);
    let mut a = [0u8; kc::sign::ARG_LEN];
    if kc::sign::encode(&buf[..input_len], &mut a).is_none() {
        return EINVAL;
    }
    let th = slots(s)[idx].token_handle();
    let rc = token_call(s, &jk, 0, kc::SIGN, th, &mut a);
    if rc < 0 {
        return token_settle(s, &jk, rc);
    }
    token_done(s, &jk);
    buf[..kc::SIG_LEN].copy_from_slice(&a[..kc::SIG_LEN]);
    kc::SIG_LEN as i32
}

/// An op on a key the token holds.
fn token_key_op(
    s: &mut State,
    idx: usize,
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: &mut [u8],
) -> i32 {
    let sl = slots(s)[idx];
    match opcode {
        kv::SIGN => sign(s, idx, handle, arg, data),
        kv::DESCRIBE => {
            let d = kv::describe::Described {
                suite: kv::suite::P256,
                usage: sl.usage,
                custody: kv::custody::PROCESS_HW,
                persisted: if sl.flags & FLAG_PERSISTED != 0 {
                    kv::persisted::SEALED
                } else {
                    kv::persisted::NO
                },
            };
            let Some(out) = arg.get_mut(..kv::describe::ARG_LEN) else {
                return EINVAL;
            };
            out.copy_from_slice(&kv::describe::encode(&d));
            kv::describe::ARG_LEN as i32
        }
        kv::PUBLIC => {
            if !sl.permits(kv::usage::EXPORT_PUBLIC) {
                return EACCES;
            }
            if data.len() < kc::PUB_LEN {
                kv::public::set_len(arg, kc::PUB_LEN);
                return ERANGE;
            }
            let jk = job_key(s, opcode, handle, arg, &[]);
            let mut p = [0u8; 65];
            if let Err(e) = token_public_of(s, &jk, idx, &mut p) {
                return token_settle(s, &jk, e);
            }
            token_done(s, &jk);
            data[..65].copy_from_slice(&p);
            65
        }
        kv::ECDH => {
            let Some(peer_len) = kv::ecdh::parse(arg) else {
                return EINVAL;
            };
            if !sl.permits(kv::usage::AGREE) {
                return EACCES;
            }
            if peer_len == 0 || peer_len > data.len() {
                return EINVAL;
            }
            if data.len() < 32 {
                kv::ecdh::set_len(arg, 32);
                return ERANGE;
            }
            let jk = job_key(s, opcode, handle, arg, &data[..peer_len]);
            let mut a = [0u8; kc::ecdh::ARG_LEN];
            if kc::ecdh::encode(&data[..peer_len], &mut a).is_none() {
                return EINVAL;
            }
            let rc = token_call(s, &jk, 0, kc::ECDH, sl.token_handle(), &mut a);
            if rc < 0 {
                return token_settle(s, &jk, rc);
            }
            token_done(s, &jk);
            data[..32].copy_from_slice(&a[..32]);
            zeroize(&mut a);
            32
        }
        kv::DESTROY => {
            let jk = job_key(s, opcode, handle, arg, &[]);
            let mut d = [0u8; kc::destroy::ARG_LEN];
            let rc = token_call(s, &jk, 0, kc::DESTROY, sl.token_handle(), &mut d);
            if rc == EAGAIN {
                return EAGAIN;
            }
            token_done(s, &jk);
            // The handle is the caller's no more whatever the token said: a
            // token that is gone took its session keys with it.
            free_token_slot(s, idx);
            0
        }
        kv::ATTEST_COMPOSITION => token_attest_composition(s, idx, handle, arg, data),
        // A key held where its bytes cannot be read cannot be split, wrapped
        // or used to unwrap.
        _ => ENOSYS,
    }
}

/// `ATTEST_COMPOSITION` with a token signer: the record, its SHA-256 signed
/// inside the token.
fn token_attest_composition(
    s: &mut State,
    idx: usize,
    handle: i32,
    arg: &mut [u8],
    buf: &mut [u8],
) -> i32 {
    let Some(challenge) = kv::attest_composition::parse(arg) else {
        return EINVAL;
    };
    if arg.len() < kv::attest_composition::ARG_LEN {
        return EINVAL;
    }
    let sl = slots(s)[idx];
    if !sl.permits(kv::usage::SIGN) {
        return EACCES;
    }
    let jk = job_key(s, kv::ATTEST_COMPOSITION, handle, arg, &[]);
    let room = buf.len().saturating_sub(kc::SIG_LEN);
    let rec_len = match composition_record(s, &challenge, kv::custody::PROCESS_HW, &mut buf[..room])
    {
        Ok(n) => n,
        Err(0) => return ENOMEM,
        Err(need) => {
            kv::attest_composition::set_len(arg, need + kc::SIG_LEN);
            return ERANGE;
        }
    };
    let mut h = Sha256::new();
    h.update(&buf[..rec_len]);
    let digest = h.finalize();
    let mut a = [0u8; kc::sign::ARG_LEN];
    if kc::sign::encode(&digest, &mut a).is_none() {
        return EINVAL;
    }
    let rc = token_call(s, &jk, 0, kc::SIGN, sl.token_handle(), &mut a);
    if rc < 0 {
        return token_settle(s, &jk, rc);
    }
    token_done(s, &jk);
    buf[rec_len..rec_len + kc::SIG_LEN].copy_from_slice(&a[..kc::SIG_LEN]);
    (rec_len + kc::SIG_LEN) as i32
}

/// The vault's own token work, each step: the token handles of keys whose
/// owners are gone are released, one call at a time.
fn custody_step(s: &mut State) {
    if s.custody != custody_mode::TOKEN || s.slots.is_null() {
        return;
    }
    s.custody_call.issued = 0;
    // A gone owner's token keys are released without waiting for the next
    // allocation to find them.
    reap_orphans(s);
    let Some(i) = slots(s)
        .iter()
        .position(|sl| sl.flags == FLAG_TOKEN_RELEASE)
    else {
        return;
    };
    let th = slots(s)[i].token_handle();
    let jk = JobKey {
        occupancy: [0xFE; 8],
        op: kc::DESTROY,
        handle: th,
        fingerprint: [0; 32],
    };
    let mut d = [0u8; kc::destroy::ARG_LEN];
    if token_call(s, &jk, 0, kc::DESTROY, th, &mut d) == EAGAIN {
        return;
    }
    token_done(s, &jk);
    let sl = &mut slots(s)[i];
    sl.flags = 0;
    zeroize(&mut sl.data);
}
