// ── Destination-bound key wrap ──────────────────────────────────────────
//
// `KEY_WRAP` seals a slot's key for the holder of a P-256 public key, bound
// to that destination's composition digest (`cores::custody_wrap`);
// `KEY_UNWRAP` opens such an object only while this node's composition is
// the one attested.

use fluxor_sdk::cores::custody_wrap as cw;

/// `KEY_WRAP`.
fn key_wrap(s: &mut State, idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    use kv::wrap as w;
    let Some((dest, attest_in)) = kv::key_wrap::parse(arg) else {
        return EINVAL;
    };
    let sl = slots(s)[idx];
    if !sl.permits(kv::usage::WRAP) {
        return EACCES;
    }
    let mut dest_pub = [0u8; w::EPH_PUB_LEN];
    dest_pub.copy_from_slice(dest);
    let mut attest = [0u8; 32];
    attest.copy_from_slice(attest_in);
    if !p256::public_point_is_valid(&dest_pub) {
        return EINVAL;
    }
    let key_len = usize::from(sl.key_len);
    let need = w::SEALED_OFF + w::SEALED_PREFIX + key_len + w::TAG_LEN;
    if buf.len() < need {
        kv::key_wrap::set_len(arg, need);
        return ERANGE;
    }
    // Ephemeral agreement key, used once and zeroised.
    let Some(mut eph) = random_p256_scalar(s) else {
        return ERROR;
    };
    let Some(eph_pub) = p256::public_key_from_scalar(&eph) else {
        zeroize(&mut eph);
        return ERROR;
    };
    let shared = p256::ecdh_shared_secret(&eph, &dest_pub);
    zeroize(&mut eph);
    let Some(mut shared) = shared else {
        return EINVAL;
    };
    let mut nonce = [0u8; 12];
    if !random(s, &mut nonce) {
        zeroize(&mut shared);
        return ERROR;
    }
    let sealed = cw::kw_seal(
        &shared,
        &eph_pub,
        &dest_pub,
        &attest,
        &nonce,
        sl.suite,
        sl.usage,
        &sl.data[..key_len],
        &mut buf[..need],
    );
    zeroize(&mut shared);
    if sealed != Some(need) {
        zeroize(&mut buf[..need]);
        return ERROR;
    }
    need as i32
}

/// `KEY_UNWRAP`: the object in `blob`, opened with slot `idx`'s P-256 key,
/// becomes a new key of the caller's.
fn key_unwrap(s: &mut State, idx: usize, blob: &[u8]) -> i32 {
    use kv::wrap as w;
    if blob.len() < w::SEALED_OFF + w::SEALED_PREFIX + w::TAG_LEN || blob[..4] != w::MAGIC {
        return EINVAL;
    }
    let sl = slots(s)[idx];
    if sl.suite != kv::suite::P256 || sl.key_len != 32 {
        return EINVAL;
    }
    if !sl.permits(kv::usage::AGREE) {
        return EACCES;
    }
    let Some(attest) = cw::kw_attest(blob) else {
        return EINVAL;
    };
    let Some(ours) = composition_digest(s, current_custody(s)) else {
        return ENOMEM;
    };
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= ours[i] ^ attest[i];
    }
    if diff != 0 {
        return EACCES;
    }
    let Some(eph_pub) = cw::kw_eph_pub(blob) else {
        return EINVAL;
    };
    let mut my_priv = [0u8; 32];
    my_priv.copy_from_slice(&sl.data[..32]);
    let shared = p256::ecdh_shared_secret(&my_priv, eph_pub);
    let my_pub = p256::public_key_from_scalar(&my_priv);
    zeroize(&mut my_priv);
    let Some(mut shared) = shared else {
        return EINVAL;
    };
    let Some(my_pub) = my_pub else {
        zeroize(&mut shared);
        return ERROR;
    };
    let mut key = [0u8; MAX_KEY_BYTES];
    let opened = cw::kw_open(&shared, &my_pub, &attest, blob, &mut key);
    zeroize(&mut shared);
    let Ok(opened) = opened else {
        zeroize(&mut key);
        return EINVAL;
    };
    let (suite, usage, key_len) = (opened.suite, opened.usage, opened.key_len);
    if suite_private_len(suite) != key_len || usage & !suite_usage(suite) != 0 || usage == 0 {
        zeroize(&mut key);
        return EINVAL;
    }
    let Some((c, scope)) = caller_scope(s) else {
        zeroize(&mut key);
        return EINVAL;
    };
    let Some(new_slot) = alloc_slot(s) else {
        zeroize(&mut key);
        return ENOMEM;
    };
    fill_slot(s, new_slot, suite, usage, &key[..key_len], FLAG_IN_USE);
    zeroize(&mut key);
    mint(s, new_slot, c, scope)
}
