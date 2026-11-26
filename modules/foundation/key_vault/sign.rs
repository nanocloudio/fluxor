// ── Signing ─────────────────────────────────────────────────────────────
//
// A suite whose signature is not cheap inside one caller step signs as a
// job kept against the key (`key_vault` contract, "Resumable SIGN"): the
// call that starts it answers EAGAIN, each identical call advances it, and
// the last writes the signature. A job is identified by its key's handle and
// the SHA-256 of `mode ‖ input`, so a repeat is recognised without keeping
// the input.

struct SignJob {
    /// The key's slot, or -1 for a free entry.
    slot: i32,
    /// The handle the job was started through.
    handle: i32,
    /// SHA-256 of `mode ‖ input`.
    fingerprint: [u8; 32],
    /// When the job was last advanced (ms since boot).
    touched: u64,
    p256: p256::EcdsaSignState,
}

impl SignJob {
    const fn empty() -> Self {
        Self {
            slot: -1,
            handle: -1,
            fingerprint: [0; 32],
            touched: 0,
            p256: p256::EcdsaSignState::empty(),
        }
    }

    fn idle(&self, now: u64) -> bool {
        now.saturating_sub(self.touched) >= kv::sign::JOB_IDLE_MS
    }

    /// Wipe the job: its nonce and key copy, then the entry.
    fn clear(&mut self) {
        self.p256.zeroise_secrets();
        self.p256 = p256::EcdsaSignState::empty();
        self.slot = -1;
        self.handle = -1;
        self.fingerprint = [0; 32];
    }
}

fn jobs(s: &mut State) -> &mut [SignJob] {
    // SAFETY: `jobs` names `n_jobs` entries of this instance's heap, taken
    // and initialised at construction; one call at a time.
    unsafe { core::slice::from_raw_parts_mut(s.jobs, usize::from(s.n_jobs)) }
}

/// Ladder bits a P-256 job advances per call: `sign_bits`, or the target's
/// default — the whole signature where a core signs well inside a step, a
/// bounded slice on a microcontroller. 0 runs to completion.
fn p256_bits_per_call(s: &State) -> u8 {
    match s.sign_bits {
        0 if cfg!(target_arch = "arm") => 16,
        0 => 0,
        n => n.min(255) as u8,
    }
}

/// Drop every job on slot `i`.
fn drop_jobs_of(s: &mut State, i: usize) {
    for j in jobs(s).iter_mut() {
        if j.slot == i as i32 {
            j.clear();
        }
    }
    #[cfg(feature = "rsa")]
    if rsa_scratch(s).job_slot == i as i32 {
        let r = rsa_scratch(s);
        r.job.zeroize();
        r.job_slot = -1;
    }
}

/// Free the RSA job if `slot` holds it.
#[cfg(feature = "rsa")]
fn rsa_job_drop_if(s: &mut State, slot: i32) {
    let r = rsa_scratch(s);
    if r.job_slot == slot {
        r.job.zeroize();
        r.job_slot = -1;
    }
}

/// `SIGN` on slot `idx`.
fn sign(s: &mut State, idx: usize, handle: i32, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some((mode, input_len)) = kv::sign::parse(arg) else {
        return EINVAL;
    };
    let sl = slots(s)[idx];
    if !sl.permits(kv::usage::SIGN) {
        return EACCES;
    }
    #[cfg(not(target_arch = "arm"))]
    if sl.flags & FLAG_TOKEN != 0 {
        return token_sign(s, idx, handle, mode, input_len, arg, buf);
    }
    let sig_len = suite_signature_len(sl.suite);
    let Some(want_mode) = sign_mode_of(sl.suite) else {
        return ENOSYS;
    };
    if sig_len == 0 {
        return ENOSYS;
    }
    if mode != want_mode || input_len == 0 || input_len > buf.len() {
        return EINVAL;
    }
    if (sl.suite == kv::suite::P256 && input_len > kv::sign::DIGEST_MAX)
        || (is_rsa_suite(sl.suite) && input_len != 32)
    {
        return EINVAL;
    }
    if buf.len() < sig_len {
        kv::sign::set_len(arg, sig_len);
        return ERANGE;
    }
    if signs_resumably(sl.suite) {
        return sign_job(s, idx, handle, mode, input_len, buf, sig_len);
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&sl.data[..32]);
    let n = match sl.suite {
        kv::suite::HMAC_SHA256 => {
            let mut tag = hmac_sha256(&priv_key, &[&buf[..input_len]]);
            buf[..32].copy_from_slice(&tag);
            zeroize(&mut tag);
            32
        }
        kv::suite::ED25519 => {
            let sig = ed25519::ed25519_sign(&priv_key, &buf[..input_len]);
            buf[..64].copy_from_slice(&sig);
            64
        }
        _ => {
            zeroize(&mut priv_key);
            return ENOSYS;
        }
    };
    zeroize(&mut priv_key);
    n
}

/// Run `SIGN` on slot `idx` as a job: start it (EAGAIN), advance it
/// (EAGAIN), or finish it (the signature over `buf`, its length).
fn sign_job(
    s: &mut State,
    idx: usize,
    handle: i32,
    mode: u8,
    input_len: usize,
    buf: &mut [u8],
    sig_len: usize,
) -> i32 {
    let mut h = Sha256::new();
    h.update(&[mode]);
    h.update(&buf[..input_len]);
    let fingerprint = h.finalize();
    let now = now_ms(s);
    let suite = slots(s)[idx].suite;

    if let Some(j) = jobs(s)
        .iter()
        .position(|j| j.slot == idx as i32 && j.handle == handle)
    {
        if jobs(s)[j].fingerprint == fingerprint {
            jobs(s)[j].touched = now;
            return advance_job(s, j, idx, input_len, buf, sig_len);
        }
        // Another signature on this key is under way; one left alone past
        // the idle bound was abandoned and gives way.
        if !jobs(s)[j].idle(now) {
            return EBUSY;
        }
        #[cfg(feature = "rsa")]
        if is_rsa_suite(suite) {
            rsa_job_drop_if(s, idx as i32);
        }
        jobs(s)[j].clear();
    }
    // The RSA state is one job wide.
    #[cfg(feature = "rsa")]
    if is_rsa_suite(suite) && rsa_scratch(s).job_slot >= 0 {
        let rsa_slot = rsa_scratch(s).job_slot;
        if let Some(j) = jobs(s).iter().position(|j| j.slot == rsa_slot) {
            if !jobs(s)[j].idle(now) {
                return EBUSY;
            }
            jobs(s)[j].clear();
        }
        rsa_job_drop_if(s, rsa_slot);
    }
    let _ = suite;
    let free = match jobs(s).iter().position(|j| j.slot < 0) {
        Some(f) => f,
        None => match jobs(s).iter().position(|j| j.idle(now)) {
            Some(stale) => {
                #[cfg(feature = "rsa")]
                {
                    let held = jobs(s)[stale].slot;
                    rsa_job_drop_if(s, held);
                }
                jobs(s)[stale].clear();
                stale
            }
            None => return EBUSY,
        },
    };
    let started = start_job(s, free, idx, &buf[..input_len]);
    if started != 0 {
        return started;
    }
    let job = &mut jobs(s)[free];
    job.slot = idx as i32;
    job.handle = handle;
    job.fingerprint = fingerprint;
    job.touched = now;
    EAGAIN
}

/// Set up job `j` for slot `idx` over `input`: 0, or the refusal.
fn start_job(s: &mut State, j: usize, idx: usize, input: &[u8]) -> i32 {
    let sl = slots(s)[idx];
    match sl.suite {
        kv::suite::P256 => {
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&sl.data[..32]);
            let st = p256::ecdsa_sign_init(&priv_key, input, p256_bits_per_call(s));
            zeroize(&mut priv_key);
            match st {
                Some(st) => {
                    jobs(s)[j].p256 = st;
                    0
                }
                None => EINVAL,
            }
        }
        #[cfg(feature = "rsa")]
        su if is_rsa_suite(su) => {
            let entry = usize::from(sl.data[0]);
            if sl.key_len != 1 || entry >= RSA_ENTRIES {
                return EINVAL;
            }
            let mut salt = [0u8; 32];
            if !random(s, &mut salt) {
                return ERROR;
            }
            let r = rsa_scratch(s);
            let key = &r.keys[entry];
            let k = key.n.byte_len();
            let mut em = [0u8; rsa::RSA_BYTES_MAX];
            if !rsa::rsa_pss_encode(
                rsa::RsaHash::Sha256,
                input,
                &salt,
                &mut em[..k],
                key.n.bits(),
            ) || !r.job.start(key, &em[..k])
            {
                return ERROR;
            }
            r.job_slot = idx as i32;
            0
        }
        // ML-DSA signs whole on the call that finishes the job.
        _ => 0,
    }
}

/// Advance job `j` by one call's budget: EAGAIN, or the signature written
/// over `buf` and its length.
fn advance_job(
    s: &mut State,
    j: usize,
    idx: usize,
    input_len: usize,
    buf: &mut [u8],
    sig_len: usize,
) -> i32 {
    let suite = slots(s)[idx].suite;
    let rc = match suite {
        kv::suite::P256 => {
            let st = &mut jobs(s)[j].p256;
            if !st.scalar_mul.complete() && !st.scalar_mul.step() {
                return EAGAIN;
            }
            let st = core::mem::replace(&mut jobs(s)[j].p256, p256::EcdsaSignState::empty());
            let sig = p256::ecdsa_sign_finalise(st);
            buf[..64].copy_from_slice(&sig);
            64
        }
        #[cfg(feature = "rsa")]
        su if is_rsa_suite(su) => {
            let entry = usize::from(slots(s)[idx].data[0]);
            let r = rsa_scratch(s);
            let key = &r.keys[entry];
            if r.job.step(key, rsa_sign_rows_per_call(key)) == rsa::RsaStep::Pending {
                return EAGAIN;
            }
            let signature = r.job.signature();
            let n = signature.len();
            buf[..n].copy_from_slice(signature);
            r.job.zeroize();
            r.job_slot = -1;
            n as i32
        }
        _ => match ml_dsa_sign(s, idx, buf, input_len, sig_len) {
            Some(n) => n as i32,
            None => ERROR,
        },
    };
    jobs(s)[j].clear();
    rc
}

/// ML-DSA over `buf[..input_len]` with slot `idx`'s seed, the signature
/// written over `buf`.
fn ml_dsa_sign(
    s: &mut State,
    idx: usize,
    buf: &mut [u8],
    input_len: usize,
    sig_len: usize,
) -> Option<usize> {
    #[cfg(feature = "ml_dsa")]
    if let Some(set) = ml_dsa_set_for(slots(s)[idx].suite) {
        let mut seed = [0u8; ml_dsa::SEED_LEN];
        seed.copy_from_slice(&slots(s)[idx].data[..ml_dsa::SEED_LEN]);
        let m = ml(s);
        let signed = ml_dsa::ml_dsa_sign_seed(
            set,
            &seed,
            &[],
            &buf[..input_len],
            &mut m.ws,
            &mut m.sig[..sig_len],
        )
        .is_ok();
        m.ws.zeroize();
        zeroize(&mut seed);
        if !signed {
            return None;
        }
        buf[..sig_len].copy_from_slice(&m.sig[..sig_len]);
        return Some(sig_len);
    }
    let _ = (s, idx, buf, input_len, sig_len);
    None
}

/// Sign `msg` whole with slot `idx` in its suite's convention (ECDSA over
/// its SHA-256 for P-256), the signature into `out`.
fn sign_bytes(s: &mut State, idx: usize, msg: &[u8], out: &mut [u8]) -> Option<usize> {
    let sl = slots(s)[idx];
    #[cfg(feature = "ml_dsa")]
    if let Some(set) = ml_dsa_set_for(sl.suite) {
        let mut seed = [0u8; ml_dsa::SEED_LEN];
        seed.copy_from_slice(&sl.data[..ml_dsa::SEED_LEN]);
        let m = ml(s);
        let signed = ml_dsa::ml_dsa_sign_seed(set, &seed, &[], msg, &mut m.ws, out).is_ok();
        m.ws.zeroize();
        zeroize(&mut seed);
        return signed.then_some(out.len());
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&sl.data[..32]);
    let sig = match sl.suite {
        kv::suite::P256 => {
            let mut h = Sha256::new();
            h.update(msg);
            let digest = h.finalize();
            p256::ecdsa_sign(&priv_key, &digest, &[0u8; 32])
        }
        kv::suite::ED25519 => Some(ed25519::ed25519_sign(&priv_key, msg)),
        _ => None,
    };
    zeroize(&mut priv_key);
    let sig = sig?;
    let n = out.len().min(64);
    out[..n].copy_from_slice(&sig[..n]);
    Some(n)
}
