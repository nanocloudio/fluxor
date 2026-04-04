// HMAC (RFC 2104) and HKDF (RFC 5869) for TLS 1.3
// Supports both SHA-256 (32-byte hash, 64-byte block) and SHA-384 (48-byte hash, 128-byte block)
// Pure Rust, no_std, no heap

/// Maximum hash output length (SHA-384 = 48 bytes)
const MAX_HASH_LEN: usize = 48;
/// Maximum block length (SHA-512/384 = 128 bytes)
const MAX_BLOCK_LEN: usize = 128;

/// Hash algorithm selector
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub const fn digest_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
    pub const fn block_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 64,
            HashAlg::Sha384 => 128,
        }
    }
}

/// Compute hash using selected algorithm
fn hash(alg: HashAlg, data: &[u8], out: &mut [u8]) {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(data);
            let digest = h.finalize();
            let n = if out.len() < 32 { out.len() } else { 32 };
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out.as_mut_ptr(), n); }
        }
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            h.update(data);
            let digest = h.finalize();
            let n = if out.len() < 48 { out.len() } else { 48 };
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out.as_mut_ptr(), n); }
        }
    }
}

/// HMAC computation
pub fn hmac(alg: HashAlg, key: &[u8], message: &[u8], out: &mut [u8]) {
    let block_len = alg.block_len();
    let hash_len = alg.digest_len();

    // Derive block-sized key
    let mut k_pad = [0u8; MAX_BLOCK_LEN];
    if key.len() > block_len {
        hash(alg, key, &mut k_pad[..hash_len]);
    } else {
        unsafe { core::ptr::copy_nonoverlapping(key.as_ptr(), k_pad.as_mut_ptr(), key.len()); }
    }

    // Inner: H((K ^ ipad) || message)
    let mut ipad = [0x36u8; MAX_BLOCK_LEN];
    let mut i = 0;
    while i < block_len {
        ipad[i] ^= k_pad[i];
        i += 1;
    }

    let mut inner_hash = [0u8; MAX_HASH_LEN];
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(&ipad[..block_len]);
            h.update(message);
            let d = h.finalize();
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), inner_hash.as_mut_ptr(), 32); }
        }
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            h.update(&ipad[..block_len]);
            h.update(message);
            let d = h.finalize();
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), inner_hash.as_mut_ptr(), 48); }
        }
    }

    // Outer: H((K ^ opad) || inner_hash)
    let mut opad = [0x5cu8; MAX_BLOCK_LEN];
    i = 0;
    while i < block_len {
        opad[i] ^= k_pad[i];
        i += 1;
    }

    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(&opad[..block_len]);
            h.update(&inner_hash[..32]);
            let d = h.finalize();
            let n = if out.len() < 32 { out.len() } else { 32 };
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), out.as_mut_ptr(), n); }
        }
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            h.update(&opad[..block_len]);
            h.update(&inner_hash[..48]);
            let d = h.finalize();
            let n = if out.len() < 48 { out.len() } else { 48 };
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), out.as_mut_ptr(), n); }
        }
    }
}

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
pub fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
    let hash_len = alg.digest_len();
    let effective_salt = if salt.is_empty() {
        // If no salt, use hash_len zero bytes
        &[0u8; MAX_HASH_LEN][..hash_len]
    } else {
        salt
    };
    hmac(alg, effective_salt, ikm, &mut prk[..hash_len]);
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... (truncated to length)
pub fn hkdf_expand(alg: HashAlg, prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let hash_len = alg.digest_len();
    let n = (okm.len() + hash_len - 1) / hash_len;
    let mut t = [0u8; MAX_HASH_LEN];
    let mut t_len = 0usize;
    let mut offset = 0;

    let mut i: u8 = 1;
    while (i as usize) <= n {
        // HMAC(PRK, T(i-1) || info || i)
        // Build message: previous T || info || counter byte
        let msg_len = t_len + info.len() + 1;
        // max: hash(48) + HkdfLabel(520) + counter(1) = 569
        let mut msg = [0u8; 576];
        if t_len > 0 {
            unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), msg.as_mut_ptr(), t_len); }
        }
        unsafe { core::ptr::copy_nonoverlapping(info.as_ptr(), msg.as_mut_ptr().add(t_len), info.len()); }
        msg[t_len + info.len()] = i;

        hmac(alg, prk, &msg[..msg_len], &mut t[..hash_len]);
        t_len = hash_len;

        let copy_len = if okm.len() - offset < hash_len { okm.len() - offset } else { hash_len };
        unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), okm.as_mut_ptr().add(offset), copy_len); }
        offset += copy_len;

        i += 1;
    }
}

/// HKDF-Expand-Label (RFC 8446 Section 7.1)
/// HkdfLabel = uint16 length || opaque label<7..255> || opaque context<0..255>
pub fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],     // WITHOUT "tls13 " prefix
    context: &[u8],
    out: &mut [u8],
) {
    // Build HkdfLabel struct
    let label_with_prefix_len = 6 + label.len(); // "tls13 " + label
    let total = 2 + 1 + label_with_prefix_len + 1 + context.len();
    let mut info = [0u8; 520]; // max: 2 + 1 + (6+255) + 1 + 255 = 520
    let length = out.len() as u16;
    info[0] = (length >> 8) as u8;
    info[1] = length as u8;
    info[2] = label_with_prefix_len as u8;
    info[3] = b't'; info[4] = b'l'; info[5] = b's';
    info[6] = b'1'; info[7] = b'3'; info[8] = b' ';
    unsafe { core::ptr::copy_nonoverlapping(label.as_ptr(), info.as_mut_ptr().add(9), label.len()); }
    let ctx_off = 9 + label.len();
    info[ctx_off] = context.len() as u8;
    if context.len() > 0 {
        unsafe { core::ptr::copy_nonoverlapping(context.as_ptr(), info.as_mut_ptr().add(ctx_off + 1), context.len()); }
    }
    let info_len = ctx_off + 1 + context.len();

    hkdf_expand(alg, secret, &info[..info_len], out);
}

/// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length)
pub fn derive_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) {
    hkdf_expand_label(alg, secret, label, transcript_hash, out);
}
