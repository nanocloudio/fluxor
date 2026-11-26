// ── The contract's ops ──────────────────────────────────────────────────

/// Dispatch one `key_vault` op.
fn dispatch(s: &mut State, handle: i32, opcode: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    #[cfg(not(target_arch = "arm"))]
    {
        s.custody_call.issued = 0;
    }
    match opcode {
        kv::DESCRIBE_SUITE => return describe_suite(s, arg),
        kv::CUSTODY => {
            let Some(t) = arg.first_mut() else {
                return EINVAL;
            };
            // The custody of the backend that holds the identity keys a node
            // attests with; each key's own custody is its `DESCRIBE`.
            *t = if s.custody == custody_mode::TOKEN {
                kv::custody::PROCESS_HW
            } else {
                current_custody(s)
            };
            return 1;
        }
        kv::STORE => return store_op(s, arg, data),
        kv::VERIFY => return verify(s, handle, arg, data),
        kv::GENERATE => return generate(s, handle, arg, data),
        kv::OPEN | kv::OPEN_OR_GENERATE => return open_by_label(s, handle, opcode, arg, data),
        kv::DESTROY_BY_LABEL => return destroy_by_label(s, handle, arg),
        kv::SHARE_REWRAP => return share_rewrap(s, handle, arg, data),
        kv::SHARE_COMBINE => return share_combine(s, handle, arg, data),
        kv::ATTEST_KEY => return attest_key(s, handle, arg, data),
        _ => {}
    }
    let idx = match resolve(s, handle) {
        Ok(i) => i,
        Err(e) => return e,
    };
    #[cfg(not(target_arch = "arm"))]
    if slots(s)[idx].flags & FLAG_TOKEN != 0 {
        return token_key_op(s, idx, handle, opcode, arg, data);
    }
    match opcode {
        kv::DESTROY => {
            zeroise_slot(s, idx);
            0
        }
        kv::SIGN => sign(s, idx, handle, arg, data),
        kv::ECDH => ecdh(s, idx, arg, data),
        kv::PUBLIC => public(s, idx, arg, data),
        kv::DESCRIBE => describe(s, idx, arg),
        kv::ATTEST_COMPOSITION => attest_composition(s, idx, arg, data),
        kv::KEY_WRAP => key_wrap(s, idx, arg, data),
        kv::KEY_UNWRAP => key_unwrap(s, idx, data),
        kv::AEAD_SEAL => aead_seal(s, idx, arg, data),
        kv::AEAD_OPEN => aead_open(s, idx, arg, data),
        kv::DERIVE => derive(s, idx, arg),
        kv::AEAD_SEAL_UNITS => seal_unit(s, idx, arg, data),
        kv::AEAD_OPEN_UNITS => open_unit(s, idx, arg, data),
        kv::SHARE_SPLIT => share_split(s, idx, arg, data),
        _ => ENOSYS,
    }
}

/// `DESCRIBE` of a key this vault holds itself.
fn describe(s: &mut State, idx: usize, arg: &mut [u8]) -> i32 {
    let sl = slots(s)[idx];
    let d = kv::describe::Described {
        suite: sl.suite,
        usage: sl.usage,
        custody: if sl.flags & FLAG_CLEAR != 0 {
            kv::custody::SOFTWARE
        } else {
            current_custody(s)
        },
        persisted: if sl.flags & FLAG_PERSISTED == 0 {
            kv::persisted::NO
        } else if sl.flags & FLAG_CLEAR != 0 {
            kv::persisted::CLEAR
        } else {
            kv::persisted::SEALED
        },
    };
    let Some(out) = arg.get_mut(..kv::describe::ARG_LEN) else {
        return EINVAL;
    };
    out.copy_from_slice(&kv::describe::encode(&d));
    kv::describe::ARG_LEN as i32
}

/// `STORE`.
fn store_op(s: &mut State, arg: &[u8], key: &[u8]) -> i32 {
    let Some((suite, usage)) = kv::store::parse(arg) else {
        return EINVAL;
    };
    let key_len = key.len();
    let want = suite_private_len(suite);
    let fits = if is_rsa_suite(suite) {
        key_len > 0 && key_len <= want
    } else {
        key_len == want
    };
    if want == 0 || !fits {
        return EINVAL;
    }
    if usage == 0 || usage & !suite_usage(suite) != 0 {
        return EINVAL;
    }
    if suite == kv::suite::P256 {
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&key[..32]);
        let in_range = p256_scalar_in_range(&scalar);
        zeroize(&mut scalar);
        if !in_range {
            return EINVAL;
        }
    }
    let Some((c, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    let Some(idx) = alloc_slot(s) else {
        return ENOMEM;
    };
    #[cfg(feature = "rsa")]
    if is_rsa_suite(suite) {
        // The DER goes into an RSA entry, checked and prepared there; the
        // slot names the entry. A key whose width is not the suite's is
        // refused.
        let r = rsa_scratch(s);
        let Some(entry) = r.keys.iter().position(|k| !k.is_loaded()) else {
            return ENOMEM;
        };
        let k = &mut r.keys[entry];
        if !k.load_pkcs1_der(key) || rsa_suite_for_bits(k.n.bits()) != suite {
            k.zeroize();
            return EINVAL;
        }
        fill_slot(s, idx, suite, usage, &[entry as u8], FLAG_IN_USE);
        return mint(s, idx, c, scope);
    }
    fill_slot(s, idx, suite, usage, key, FLAG_IN_USE);
    mint(s, idx, c, scope)
}

/// `ECDH`.
fn ecdh(s: &mut State, idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some(peer_len) = kv::ecdh::parse(arg) else {
        return EINVAL;
    };
    let sl = slots(s)[idx];
    if sl.suite != kv::suite::P256 || sl.key_len != 32 {
        return EINVAL;
    }
    if !sl.permits(kv::usage::AGREE) {
        return EACCES;
    }
    if peer_len == 0 || peer_len > buf.len() {
        return EINVAL;
    }
    if buf.len() < 32 {
        kv::ecdh::set_len(arg, 32);
        return ERANGE;
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&sl.data[..32]);
    let result = p256::ecdh_shared_secret(&priv_key, &buf[..peer_len]);
    zeroize(&mut priv_key);
    match result {
        Some(mut shared) => {
            buf[..32].copy_from_slice(&shared);
            zeroize(&mut shared);
            32
        }
        None => EINVAL,
    }
}

/// `VERIFY`: with a key's handle, an HMAC tag in constant time; with -1,
/// ECDSA P-256 under the caller's public key.
fn verify(s: &mut State, handle: i32, arg: &[u8], data: &[u8]) -> i32 {
    let Some(lens) = kv::verify::parse(arg) else {
        return EINVAL;
    };
    let Some((msg, sig, pk)) = kv::verify::split(data, lens) else {
        return EINVAL;
    };
    if handle >= 0 {
        let i = match resolve(s, handle) {
            Ok(i) => i,
            Err(e) => return e,
        };
        let sl = slots(s)[i];
        if sl.suite != kv::suite::HMAC_SHA256 || sl.flags & FLAG_TOKEN != 0 {
            return EINVAL;
        }
        if !sl.permits(kv::usage::VERIFY) {
            return EACCES;
        }
        if msg.is_empty() || sig.len() != 32 || !pk.is_empty() {
            return EINVAL;
        }
        let mut expect = hmac_sha256(&sl.data[..32], &[msg]);
        let mut diff: u8 = 0;
        for (a, b) in expect.iter().zip(sig) {
            diff |= a ^ b;
        }
        zeroize(&mut expect);
        return i32::from(diff == 0);
    }
    if msg.is_empty() || sig.len() != 64 || pk.len() < 64 {
        return EINVAL;
    }
    i32::from(p256::ecdsa_verify(pk, msg, sig))
}

/// `GENERATE`: an unnamed key; P-256 on the token when `custody = token`.
fn generate(s: &mut State, handle: i32, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some((suite, usage, flags)) = kv::generate::parse(arg) else {
        return EINVAL;
    };
    #[cfg(not(target_arch = "arm"))]
    if suite == kv::suite::P256 && s.custody == custody_mode::TOKEN {
        return token_generate(s, handle, arg, buf, usage, flags);
    }
    #[cfg(target_arch = "arm")]
    let _ = handle;
    let priv_len = suite_private_len(suite);
    let pub_len = suite_public_len(suite);
    // RSA keys are imported, never minted here.
    if priv_len == 0 || is_rsa_suite(suite) {
        return ENOSYS;
    }
    if usage == 0 || usage & !suite_usage(suite) != 0 {
        return EINVAL;
    }
    // Non-extractability is a guarantee a key in this heap cannot have.
    if flags & kv::generate::flags::NON_EXTRACTABLE != 0 {
        return ENOSYS;
    }
    if buf.len() < pub_len {
        kv::generate::set_len(arg, pub_len);
        return ERANGE;
    }
    let Some((c, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    let Some(idx) = alloc_slot(s) else {
        return ENOMEM;
    };
    let mut key = [0u8; MAX_KEY_BYTES];
    if !generate_into(s, suite, &mut key[..priv_len]) {
        zeroize(&mut key);
        return ERROR;
    }
    fill_slot(s, idx, suite, usage, &key[..priv_len], FLAG_IN_USE);
    zeroize(&mut key);
    if !write_public(s, idx, &mut buf[..pub_len]) {
        zeroise_slot(s, idx);
        return ERROR;
    }
    kv::generate::set_len(arg, pub_len);
    mint(s, idx, c, scope)
}

/// `PUBLIC`.
fn public(s: &mut State, idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let sl = slots(s)[idx];
    if !sl.permits(kv::usage::EXPORT_PUBLIC) {
        return EACCES;
    }
    let pub_len = suite_public_len(sl.suite);
    if pub_len == 0 {
        return ENOSYS;
    }
    #[cfg(feature = "rsa")]
    if is_rsa_suite(sl.suite) {
        let entry = usize::from(sl.data[0]);
        if sl.key_len != 1 || entry >= RSA_ENTRIES {
            return EINVAL;
        }
        let mut der = [0u8; 526];
        let Some(n) = rsa_scratch(s).keys[entry].public_key_der(&mut der) else {
            return ERROR;
        };
        if buf.len() < n {
            kv::public::set_len(arg, n);
            return ERANGE;
        }
        buf[..n].copy_from_slice(&der[..n]);
        return n as i32;
    }
    if buf.len() < pub_len {
        kv::public::set_len(arg, pub_len);
        return ERANGE;
    }
    if !write_public(s, idx, &mut buf[..pub_len]) {
        return ERROR;
    }
    pub_len as i32
}

/// `AEAD_SEAL`.
fn aead_seal(s: &mut State, idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    use kv::aead as a;
    let sl = slots(s)[idx];
    if sl.suite != kv::suite::AEAD_KEY {
        return EINVAL;
    }
    if !sl.permits(kv::usage::SEAL) {
        return EACCES;
    }
    let Some(req) = a::parse(arg) else {
        return EINVAL;
    };
    let pt_len = req.len;
    if pt_len > a::MAX_LEN {
        return EINVAL;
    }
    let need = pt_len + a::TAG_LEN;
    if buf.len() < need {
        a::set_len(arg, need);
        return ERANGE;
    }
    let mut nonce = [0u8; a::NONCE_LEN];
    if !random(s, &mut nonce) {
        return ERROR;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&sl.data[..32]);
    let tag = chacha20_poly1305_encrypt(&key, &nonce, req.aad, &mut buf[..pt_len]);
    zeroize(&mut key);
    buf[pt_len..need].copy_from_slice(&tag[..a::TAG_LEN]);
    a::set_nonce(arg, &nonce);
    need as i32
}

/// `AEAD_OPEN`.
fn aead_open(s: &mut State, idx: usize, arg: &[u8], buf: &mut [u8]) -> i32 {
    use kv::aead as a;
    let sl = slots(s)[idx];
    if sl.suite != kv::suite::AEAD_KEY {
        return EINVAL;
    }
    if !sl.permits(kv::usage::OPEN) {
        return EACCES;
    }
    let Some(req) = a::parse(arg) else {
        return EINVAL;
    };
    let len = req.len;
    if len < a::TAG_LEN || len - a::TAG_LEN > a::MAX_LEN || len > buf.len() {
        return EINVAL;
    }
    let pt_len = len - a::TAG_LEN;
    let mut key = [0u8; 32];
    key.copy_from_slice(&sl.data[..32]);
    let mut tag = [0u8; a::TAG_LEN];
    tag.copy_from_slice(&buf[pt_len..len]);
    let ok = chacha20_poly1305_decrypt(&key, &req.nonce, req.aad, &mut buf[..pt_len], &tag);
    zeroize(&mut key);
    if !ok {
        zeroize(&mut buf[..len]);
        return EINVAL;
    }
    pt_len as i32
}

/// A purpose key: HKDF-SHA256, one block — `salt = derive::SALT`,
/// `ikm = master`, `info = label ‖ context`.
fn derive_key(master: &[u8], label: &[u8], context: &[u8], out: &mut [u8; 32]) {
    let mut prk = hmac_sha256(kv::derive::SALT, &[master]);
    let okm = hmac_sha256(&prk, &[label, context, &[1u8]]);
    zeroize(&mut prk);
    out.copy_from_slice(&okm);
}

/// `DERIVE`.
fn derive(s: &mut State, idx: usize, arg: &[u8]) -> i32 {
    let master = slots(s)[idx];
    if master.suite != kv::suite::KDF_KEY {
        return EINVAL;
    }
    if !master.permits(kv::usage::DERIVE) {
        return EACCES;
    }
    let Some(req) = kv::derive::parse(arg) else {
        return EINVAL;
    };
    let (suite, usage) = (req.suite, req.usage);
    // A derived key is the same 32 bytes whenever it is derived, so it is
    // never persisted.
    let derivable = matches!(
        suite,
        kv::suite::AEAD_KEY
            | kv::suite::AEAD_AES256_GCM
            | kv::suite::HMAC_SHA256
            | kv::suite::KDF_KEY
    );
    if !derivable || suite_private_len(suite) != 32 {
        return if derivable { ENOSYS } else { EINVAL };
    }
    if usage == 0 || usage & !suite_usage(suite) != 0 || usage & kv::usage::PERSIST != 0 {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    derive_key(
        &master.data[..usize::from(master.key_len)],
        req.label,
        req.context,
        &mut key,
    );
    let Some((c, scope)) = caller_scope(s) else {
        zeroize(&mut key);
        return EINVAL;
    };
    let Some(new) = alloc_slot(s) else {
        zeroize(&mut key);
        return ENOMEM;
    };
    fill_slot(s, new, suite, usage, &key, FLAG_IN_USE);
    zeroize(&mut key);
    mint(s, new, c, scope)
}

/// The cipher a unit key seals under: false for ChaCha20-Poly1305, true for
/// AES-256-GCM; `Err` for a key that is not a unit key.
fn unit_key(s: &mut State, idx: usize, want: u32, key: &mut [u8; 32]) -> Result<bool, i32> {
    let sl = slots(s)[idx];
    let aes = match sl.suite {
        kv::suite::AEAD_KEY => false,
        kv::suite::AEAD_AES256_GCM => true,
        _ => return Err(EINVAL),
    };
    if !sl.permits(want) {
        return Err(EACCES);
    }
    key.copy_from_slice(&sl.data[..32]);
    Ok(aes)
}

/// `AEAD_SEAL_UNITS`: one unit in place.
fn seal_unit(s: &mut State, idx: usize, arg: &mut [u8], unit: &mut [u8]) -> i32 {
    use kv::units as u;
    let Some(req) = u::parse(arg) else {
        return EINVAL;
    };
    if unit.len() > u::MAX_UNIT {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    let aes = match unit_key(s, idx, kv::usage::SEAL, &mut key) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let tag = if aes {
        fluxor_sdk::crypto::aes_gcm::AesGcm::new_256(&key).encrypt(&req.nonce, req.aad, unit)
    } else {
        chacha20_poly1305_encrypt(&key, &req.nonce, req.aad, unit)
    };
    zeroize(&mut key);
    let mut t = [0u8; u::TAG_LEN];
    t.copy_from_slice(&tag[..u::TAG_LEN]);
    u::set_tag(arg, &t);
    0
}

/// `AEAD_OPEN_UNITS`: one unit in place; never leaves unauthenticated
/// plaintext behind.
fn open_unit(s: &mut State, idx: usize, arg: &[u8], unit: &mut [u8]) -> i32 {
    use kv::units as u;
    let Some(req) = u::parse(arg) else {
        return EINVAL;
    };
    if unit.len() > u::MAX_UNIT {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    let aes = match unit_key(s, idx, kv::usage::OPEN, &mut key) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ok = if aes {
        fluxor_sdk::crypto::aes_gcm::AesGcm::new_256(&key)
            .decrypt(&req.nonce, req.aad, unit, &req.tag)
    } else {
        chacha20_poly1305_decrypt(&key, &req.nonce, req.aad, unit, &req.tag)
    };
    zeroize(&mut key);
    if ok {
        0
    } else {
        zeroize(unit);
        EINVAL
    }
}

// ── Labelled keys ───────────────────────────────────────────────────────

/// `OPEN` / `OPEN_OR_GENERATE`. A key already open under the label is
/// returned to its owner as-is; one the token holds is answered by the
/// token. Otherwise this vault's records first, then (P-256 with
/// `custody = token`, node callers) the token; a key that exists somewhere
/// is never made again somewhere else.
fn open_by_label(s: &mut State, handle: i32, opcode: u32, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some(req) = kv::open::parse(arg) else {
        return EINVAL;
    };
    let (suite, usage) = (req.suite, req.usage);
    let label_len = req.label.len();
    let mut lbuf = [0u8; MAX_LABEL];
    lbuf[..label_len].copy_from_slice(req.label);
    let label = &lbuf[..label_len];
    let Some((who, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    let token = cfg!(not(target_arch = "arm"))
        && s.custody == custody_mode::TOKEN
        && suite == kv::suite::P256
        && scope.is_node();
    let pub_len = if token { 65 } else { suite_public_len(suite) };
    if !token && suite_private_len(suite) == 0 {
        return ENOSYS;
    }
    // Sized before anything is opened or made.
    if buf.len() < pub_len {
        kv::open::set_len(arg, pub_len);
        return ERANGE;
    }
    // A vault kept under its owner's key answers no label before the key.
    if s.key_state == record_key::AWAITING {
        return EAGAIN;
    }
    reap_orphans(s);
    let existing = slots(s).iter().position(|sl| sl.filed_as(scope, label));
    if let Some(i) = existing {
        let sl = slots(s)[i];
        if sl.occupancy != who.occupancy {
            return EBUSY;
        }
        if sl.suite != suite || usage & !sl.usage != 0 {
            return EACCES;
        }
        #[cfg(not(target_arch = "arm"))]
        if sl.flags & FLAG_TOKEN != 0 {
            return token_open_existing(s, i, handle, opcode, arg, buf);
        }
        if !write_public(s, i, &mut buf[..pub_len]) {
            return ERROR;
        }
        kv::open::set_len(arg, pub_len);
        return i as i32;
    }
    if !token {
        return open_software(s, opcode, arg, buf, who, scope, label, suite, usage);
    }
    // Software first: a key persisted here before the token was configured
    // keeps its identity.
    let rc = open_software(s, kv::OPEN, arg, buf, who, scope, label, suite, usage);
    if rc != ENOENT {
        return rc;
    }
    #[cfg(not(target_arch = "arm"))]
    {
        token_open(s, handle, opcode, arg, buf, who, scope, label, usage)
    }
    #[cfg(target_arch = "arm")]
    {
        let _ = handle;
        ENODEV
    }
}

/// `OPEN` / `OPEN_OR_GENERATE` against this vault's own keys.
fn open_software(
    s: &mut State,
    opcode: u32,
    arg: &mut [u8],
    buf: &mut [u8],
    who: Caller,
    scope: Scope,
    label: &[u8],
    suite: u16,
    usage: u32,
) -> i32 {
    let priv_len = suite_private_len(suite);
    let pub_len = suite_public_len(suite);
    if priv_len == 0 {
        return ENOSYS;
    }
    // A store that cannot be read yet is not an empty one.
    if store_not_ready(s) {
        return EAGAIN;
    }
    let idx = match find_persisted(s, scope, label) {
        Err(e) => return e,
        Ok(Some(pi)) => {
            let e = persisted(s)[pi];
            // The suite must be the one the key was born with, and the mask
            // is CHECKED against its uses, never applied.
            if e.suite != suite || usage & !e.usage != 0 {
                return EACCES;
            }
            if let Err(e) = settle(s, pi) {
                return e;
            }
            match open_persisted(s, pi) {
                Ok(i) => i,
                Err(e) => {
                    log(
                        s,
                        2,
                        b"[key_vault] open refused: persisted record would not reopen",
                    );
                    return e;
                }
            }
        }
        Ok(None) => {
            if opcode == kv::OPEN {
                return ENOENT;
            }
            if usage == 0 || usage & !suite_usage(suite) != 0 {
                return EINVAL;
            }
            let Some(i) = alloc_slot(s) else {
                log(s, 2, b"[key_vault] open refused: no free slot");
                return ENOMEM;
            };
            let mut key = [0u8; MAX_KEY_BYTES];
            if !generate_into(s, suite, &mut key[..priv_len]) {
                zeroize(&mut key);
                return ERROR;
            }
            label_slot(s, i, label);
            fill_slot(s, i, suite, usage, &key[..priv_len], 0);
            let persisted = if usage & kv::usage::PERSIST != 0 {
                persist_key(s, scope, label, suite, usage, &key[..priv_len])
            } else {
                Persist::Unavailable
            };
            zeroize(&mut key);
            match persisted {
                // A key asked to persist that could not be kept is not
                // handed out: its owner would build on a key that does not
                // come back.
                Persist::Failed => {
                    zeroise_slot(s, i);
                    return ERROR;
                }
                // In the image, not yet on the medium: asked again, the
                // same key is answered once it is there.
                Persist::Pending(_) => {
                    zeroise_slot(s, i);
                    return EAGAIN;
                }
                Persist::Durable => {
                    slots(s)[i].flags =
                        FLAG_IN_USE | FLAG_PERSISTED | if keeps_clear(s) { FLAG_CLEAR } else { 0 };
                }
                Persist::Unavailable => slots(s)[i].flags = FLAG_IN_USE,
            }
            i
        }
    };
    if !write_public(s, idx, &mut buf[..pub_len]) {
        zeroise_slot(s, idx);
        return ERROR;
    }
    kv::open::set_len(arg, pub_len);
    mint(s, idx, who, scope)
}

/// `DESTROY_BY_LABEL`: the live slot and the record (and the token's
/// object), so a revocation that used it revokes.
fn destroy_by_label(s: &mut State, handle: i32, arg: &mut [u8]) -> i32 {
    let Some(l) = kv::destroy_by_label::parse(arg) else {
        return EINVAL;
    };
    let mut lbuf = [0u8; MAX_LABEL];
    lbuf[..l.len()].copy_from_slice(l);
    let label = &lbuf[..l.len()];
    let Some((_, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    if store_not_ready(s) {
        return EAGAIN;
    }
    // The token's object first: it takes calls, and the local half is
    // answered once, after it.
    #[cfg(not(target_arch = "arm"))]
    let hw = if s.custody == custody_mode::TOKEN && scope.is_node() {
        match token_destroy_by_label(s, handle, arg, scope, label) {
            Ok(found) => found,
            Err(e) => return e,
        }
    } else {
        false
    };
    #[cfg(target_arch = "arm")]
    let hw = {
        let _ = handle;
        false
    };
    let mut found = false;
    for i in 0..usize::from(s.n_slots) {
        if slots(s)[i].filed_as(scope, label) && slots(s)[i].flags & FLAG_TOKEN == 0 {
            zeroise_slot(s, i);
            found = true;
        }
    }
    let (had, removed) = forget_persisted(s, scope, label);
    // The repeat of a removal waiting on the medium finds nothing left to
    // remove: it is that removal's answer.
    let waiting = !found && !had && s.removing.is(scope, label);
    let removed = if waiting {
        store_durability(s, s.removing.seq)
    } else {
        removed
    };
    match removed {
        Durability::Durable => {
            if waiting {
                s.removing = Removal::NONE;
                return 0;
            }
        }
        // Gone from the image, still on the medium: answered once the
        // medium lacks it too.
        Durability::Pending(seq) => {
            s.removing = Removal::of(scope, label, seq);
            return EAGAIN;
        }
        Durability::Failed => {
            log(
                s,
                2,
                b"[key_vault] destroy: the record could not be removed",
            );
            return ERROR;
        }
    }
    if found || had || hw {
        0
    } else {
        ENOENT
    }
}

/// A `DESTROY_BY_LABEL` whose removal waits on the medium.
#[derive(Clone, Copy)]
struct Removal {
    namespace: u32,
    realm: [u8; 16],
    label: [u8; MAX_LABEL],
    label_len: u8,
    seq: u64,
}

impl Removal {
    const NONE: Removal = Removal {
        namespace: 0,
        realm: NODE_REALM,
        label: [0; MAX_LABEL],
        label_len: 0,
        seq: 0,
    };

    fn of(scope: Scope, label: &[u8], seq: u64) -> Removal {
        let mut r = Removal::NONE;
        r.namespace = scope.namespace;
        r.realm = scope.realm;
        r.label[..label.len()].copy_from_slice(label);
        r.label_len = label.len() as u8;
        r.seq = seq;
        r
    }

    fn is(&self, scope: Scope, label: &[u8]) -> bool {
        self.seq != 0
            && self.namespace == scope.namespace
            && self.realm == scope.realm
            && &self.label[..usize::from(self.label_len)] == label
    }
}
