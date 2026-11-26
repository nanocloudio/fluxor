// ── Attestation ─────────────────────────────────────────────────────────
//
// The composition record is the kernel's (`COMPOSITION_RECORD`): only it
// knows what the node runs. The vault signs it, and binds key wraps and key
// attestations to its digest.

use abi::kernel_abi::composition::DIGEST as COMPOSITION_DIGEST;

/// The composition digest under `custody`.
fn composition_digest(s: &State, custody: u8) -> Option<[u8; 32]> {
    let mut a = [0u8; 33];
    a[32] = custody | COMPOSITION_DIGEST;
    let mut d = [0u8; 32];
    (kcall(s, -1, abi::kernel_abi::COMPOSITION_RECORD, &mut a, &mut d) == 32).then_some(d)
}

/// The composition record for `challenge` under `custody`, into `out`: its
/// length, or `Err(needed)` when `out` is short, `Err(0)` on refusal.
fn composition_record(
    s: &State,
    challenge: &[u8; 32],
    custody: u8,
    out: &mut [u8],
) -> Result<usize, usize> {
    let mut a = [0u8; 33];
    a[..32].copy_from_slice(challenge);
    a[32] = custody;
    let rc = kcall(s, -1, abi::kernel_abi::COMPOSITION_RECORD, &mut a, out);
    if rc >= 0 {
        return Ok(rc as usize);
    }
    if rc == ERANGE {
        return Err(u32::from_le_bytes([a[0], a[1], a[2], a[3]]) as usize);
    }
    Err(0)
}

/// `ATTEST_COMPOSITION` with a key this vault holds: the record, then its
/// signature, both written into the caller's `buf`.
fn attest_composition(s: &mut State, idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
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
    let sig_len = suite_signature_len(sl.suite);
    if sig_len == 0 {
        return ENOSYS;
    }
    let custody = current_custody(s);
    let room = buf.len().saturating_sub(sig_len);
    let rec_len = match composition_record(s, &challenge, custody, &mut buf[..room]) {
        Ok(n) => n,
        Err(0) => return ENOMEM,
        Err(need) => {
            kv::attest_composition::set_len(arg, need + sig_len);
            return ERANGE;
        }
    };
    let Some((rec, sig)) = buf.split_at_mut_checked(rec_len) else {
        return ERROR;
    };
    let Some(written) = sign_bytes(s, idx, rec, &mut sig[..sig_len]) else {
        return ERROR;
    };
    (rec_len + written) as i32
}

/// `ATTEST_KEY`: evidence of what `subject` is, bound to the caller's
/// challenge, never its bytes.
fn attest_key(s: &mut State, subject: i32, args: &[u8], out: &mut [u8]) -> i32 {
    use kv::attest_key as a;
    if args.len() < a::ARG_LEN {
        return EINVAL;
    }
    let jk = job_key(s, kv::ATTEST_KEY, subject, args, &[]);
    let i = match resolve(s, subject) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if out.len() < a::RECORD_LEN {
        return ERANGE;
    }
    let sl = slots(s)[i];
    let mut record = [0u8; a::RECORD_LEN];
    record[..4].copy_from_slice(&a::MAGIC);
    record[a::R_CHALLENGE..a::R_CHALLENGE + 32].copy_from_slice(&args[..32]);
    record[a::R_SUITE..a::R_SUITE + 2].copy_from_slice(&sl.suite.to_le_bytes());
    record[a::R_USAGE..a::R_USAGE + 4].copy_from_slice(&sl.usage.to_le_bytes());
    record[a::R_NAMESPACE..a::R_NAMESPACE + 4].copy_from_slice(&sl.namespace.to_le_bytes());
    record[a::R_PERSISTED] = u8::from(sl.flags & FLAG_PERSISTED != 0);
    #[cfg(not(target_arch = "arm"))]
    if sl.flags & FLAG_TOKEN != 0 {
        // The token holds the key where no commitment can be computed; the
        // public half identifies it.
        record[a::R_BACKEND] = a::backend::PKCS11;
        if sl.permits(kv::usage::EXPORT_PUBLIC) {
            let mut p = [0u8; 65];
            match token_public_of(s, &jk, i, &mut p) {
                Ok(()) => {}
                Err(e) => return token_settle(s, &jk, e),
            }
            token_done(s, &jk);
            let mut h = Sha256::new();
            h.update(&p);
            record[a::R_THUMBPRINT..a::R_THUMBPRINT + 32].copy_from_slice(&h.finalize());
        }
        return attest_record_out(s, kv::custody::PROCESS_HW, &mut record, out);
    }
    #[cfg(target_arch = "arm")]
    let _ = jk;
    if is_rsa_suite(sl.suite) || sl.key_len == 0 {
        return ENOSYS;
    }
    let custody = if sl.flags & FLAG_CLEAR != 0 {
        kv::custody::SOFTWARE
    } else {
        current_custody(s)
    };
    record[a::R_BACKEND] = a::backend::KERNEL;
    // A local, not a promoted constant: a table of slices in `.rodata`
    // would carry absolute pointers.
    let label: &[u8] = a::COMMITMENT_LABEL;
    let commitment = hmac_sha256(&sl.data[..usize::from(sl.key_len)], &[label]);
    record[a::R_COMMITMENT..a::R_COMMITMENT + 32].copy_from_slice(&commitment);
    let pub_len = suite_public_len(sl.suite);
    if pub_len != 0 && pub_len <= 65 && sl.permits(kv::usage::EXPORT_PUBLIC) {
        let mut p = [0u8; 65];
        if !write_public(s, i, &mut p[..pub_len]) {
            return ERROR;
        }
        let mut h = Sha256::new();
        h.update(&p[..pub_len]);
        record[a::R_THUMBPRINT..a::R_THUMBPRINT + 32].copy_from_slice(&h.finalize());
    } else if pub_len > 65 && sl.permits(kv::usage::EXPORT_PUBLIC) {
        let Some(t) = wide_public_thumbprint(s, i) else {
            return ERROR;
        };
        record[a::R_THUMBPRINT..a::R_THUMBPRINT + 32].copy_from_slice(&t);
    }
    attest_record_out(s, custody, &mut record, out)
}

/// An `ATTEST_KEY` record under `custody`, completed with the composition
/// digest and written to `out`.
fn attest_record_out(
    s: &mut State,
    custody: u8,
    record: &mut [u8; kv::attest_key::RECORD_LEN],
    out: &mut [u8],
) -> i32 {
    use kv::attest_key as a;
    record[a::R_CUSTODY] = custody;
    let Some(composition) = composition_digest(s, custody) else {
        return ENOMEM;
    };
    record[a::R_COMPOSITION..a::R_COMPOSITION + 32].copy_from_slice(&composition);
    out[..a::RECORD_LEN].copy_from_slice(record);
    a::RECORD_LEN as i32
}

/// The SHA-256 of an ML-DSA key's public half, derived in the ML-DSA
/// scratch.
fn wide_public_thumbprint(s: &mut State, idx: usize) -> Option<[u8; 32]> {
    #[cfg(feature = "ml_dsa")]
    {
        let sl = slots(s)[idx];
        let set = ml_dsa_set_for(sl.suite)?;
        let n = set.params().pk_len;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sl.data[..32]);
        let m = ml(s);
        let ok = ml_dsa::ml_dsa_public_key(set, &seed, &mut m.ws, &mut m.pk[..n]).is_ok();
        m.ws.zeroize();
        zeroize(&mut seed);
        if !ok {
            return None;
        }
        let mut h = Sha256::new();
        h.update(&m.pk[..n]);
        Some(h.finalize())
    }
    #[cfg(not(feature = "ml_dsa"))]
    {
        let _ = (s, idx);
        None
    }
}
