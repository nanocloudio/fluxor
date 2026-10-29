// custody_wrap — the destination-bound key wrap a vault's KEY_WRAP /
// KEY_UNWRAP perform, as a pure core.
//
// The kernel vault (`src/kernel/security/key_vault.rs`) answers KEY_WRAP and
// KEY_UNWRAP with exactly this code; it is here so that anything holding the
// same inputs — a host harness standing in for a vault, a peer checking a
// transfer — computes the same bytes rather than a model of them. The core
// holds no key and draws no randomness: the caller supplies the ECDH shared
// secret (computed in its vault from the ephemeral scalar it drew, or from
// the recipient's private key on unwrap) and the nonce.
//
// The wrapped object (`FXKW`, `contracts/key_vault.rs` `wrap`):
//
//   magic        [4]   = b"FXKW"
//   eph_pub      [65]  the ephemeral P-256 agreement key (uncompressed)
//   attest       [32]  the destination's composition digest
//   nonce        [12]
//   sealed       [7 + key_len]  ChaCha20-Poly1305 under the KEK,
//                AAD = the 113 header bytes before it (magic to nonce),
//                plaintext = [suite:u16 LE][usage:u32 LE][key_len:u8][key]
//   tag          [16]
//
// The whole header is authenticated, so an object opens only exactly as
// it was sealed: `eph_pub` is not in the KEK's derivation, and the ECDH
// secret is the x-coordinate alone, so without it in the AAD the point's
// negation (the same x) would open the same key from a different object.
//
// KEK = HKDF-SHA256 (RFC 5869), one block:
//   salt = attest, ikm = ECDH shared secret,
//   info = "fluxor key_wrap" ‖ dest_pub ‖ 0x01
// Salting with the destination's composition digest is what binds the wrap
// to it: a vault opens the object only while its own composition is the one
// attested, and only with the private half of `dest_pub`.
//
// Needs `Sha256` and `chacha20_poly1305_encrypt` / `_decrypt` in scope
// (`crypto/sha256.rs`, `crypto/chacha20.rs`). `no_std`, allocation-free.

/// The object's magic.
pub const KW_MAGIC: [u8; 4] = *b"FXKW";
/// An uncompressed P-256 public point.
pub const KW_PUB_LEN: usize = 65;
pub const KW_ATTEST_OFF: usize = 4 + KW_PUB_LEN;
pub const KW_NONCE_OFF: usize = KW_ATTEST_OFF + 32;
pub const KW_SEALED_OFF: usize = KW_NONCE_OFF + 12;
/// `[suite:u16][usage:u32][key_len:u8]` before the key bytes.
pub const KW_SEALED_PREFIX: usize = 2 + 4 + 1;
pub const KW_TAG_LEN: usize = 16;
/// The longest key one object carries (its length is a byte).
pub const KW_KEY_MAX: usize = 255;
/// HKDF info label.
pub const KW_INFO: &[u8] = b"fluxor key_wrap";

/// Why an object does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KwWhy {
    /// Too short, too long, or not `FXKW`.
    Malformed,
    /// It names another composition than the one the opener is.
    Composition,
    /// The AEAD refused it: another recipient, or altered.
    Tag,
    /// It opened, but the sealed prefix is impossible (its length).
    Contents,
    /// The output buffer cannot hold it.
    Capacity,
}

/// The length of the object wrapping a `key_len`-byte key.
pub const fn kw_wrapped_len(key_len: usize) -> usize {
    KW_SEALED_OFF + KW_SEALED_PREFIX + key_len + KW_TAG_LEN
}

fn kw_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    let out = outer.finalize();
    kw_zero(&mut k);
    kw_zero(&mut ipad);
    kw_zero(&mut opad);
    out
}

fn kw_zero(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a live, exclusively borrowed byte.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
}

/// The key-encryption key for a wrap to `dest_pub` bound to `attest`.
pub fn kw_kek(shared: &[u8; 32], attest: &[u8; 32], dest_pub: &[u8]) -> [u8; 32] {
    let mut prk = kw_hmac(attest, &[shared]);
    let okm = kw_hmac(&prk, &[KW_INFO, dest_pub, &[1u8]]);
    kw_zero(&mut prk);
    okm
}

/// Seal `key` (of `suite`, permitted `usage`) into `out` as an object for
/// the holder of `dest_pub`'s private half, under the composition `attest`.
/// `shared` is the ECDH secret of the ephemeral scalar behind `eph_pub` and
/// `dest_pub`; `nonce` must never repeat under one KEK (a fresh ephemeral
/// key per wrap makes every KEK fresh). The object's length, or `None` when
/// `key` is too long or `out` too short.
#[allow(
    clippy::too_many_arguments,
    reason = "the wrap is a function of its inputs; a struct of them would be built and taken apart at its one call site in the vault"
)]
pub fn kw_seal(
    shared: &[u8; 32],
    eph_pub: &[u8; KW_PUB_LEN],
    dest_pub: &[u8],
    attest: &[u8; 32],
    nonce: &[u8; 12],
    suite: u16,
    usage: u32,
    key: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let key_len = key.len();
    let need = kw_wrapped_len(key_len);
    if key_len > KW_KEY_MAX || out.len() < need {
        return None;
    }
    let mut kek = kw_kek(shared, attest, dest_pub);
    let sealed_len = KW_SEALED_PREFIX + key_len;
    out[..4].copy_from_slice(&KW_MAGIC);
    out[4..4 + KW_PUB_LEN].copy_from_slice(eph_pub);
    out[KW_ATTEST_OFF..KW_ATTEST_OFF + 32].copy_from_slice(attest);
    out[KW_NONCE_OFF..KW_NONCE_OFF + 12].copy_from_slice(nonce);
    let mut aad = [0u8; KW_SEALED_OFF];
    aad.copy_from_slice(&out[..KW_SEALED_OFF]);
    let sealed = &mut out[KW_SEALED_OFF..KW_SEALED_OFF + sealed_len];
    sealed[0..2].copy_from_slice(&suite.to_le_bytes());
    sealed[2..6].copy_from_slice(&usage.to_le_bytes());
    sealed[6] = key_len as u8;
    sealed[7..].copy_from_slice(key);
    let tag = chacha20_poly1305_encrypt(&kek, nonce, &aad, sealed);
    kw_zero(&mut kek);
    out[KW_SEALED_OFF + sealed_len..need].copy_from_slice(&tag);
    Some(need)
}

/// The composition digest an object names, if it is shaped as one.
pub fn kw_attest(blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() < kw_wrapped_len(0) || blob[..4] != KW_MAGIC {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&blob[KW_ATTEST_OFF..KW_ATTEST_OFF + 32]);
    Some(a)
}

/// The ephemeral public key an object carries, which the opener's vault
/// agrees with to compute `shared`.
pub fn kw_eph_pub(blob: &[u8]) -> Option<&[u8]> {
    kw_attest(blob)?;
    Some(&blob[4..4 + KW_PUB_LEN])
}

/// What an opened object holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KwOpened {
    pub suite: u16,
    pub usage: u32,
    pub key_len: usize,
}

/// Open `blob` as its recipient: `shared` is the ECDH secret of the
/// recipient's private key and the object's ephemeral key, `my_pub` the
/// recipient's public key, `composition` what the opener's vault attests it
/// is now. The key goes to `key_out`; nothing is written there unless the
/// object opens whole.
pub fn kw_open(
    shared: &[u8; 32],
    my_pub: &[u8],
    composition: &[u8; 32],
    blob: &[u8],
    key_out: &mut [u8],
) -> Result<KwOpened, KwWhy> {
    let attest = kw_attest(blob).ok_or(KwWhy::Malformed)?;
    if blob.len() > kw_wrapped_len(KW_KEY_MAX) {
        return Err(KwWhy::Malformed);
    }
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= attest[i] ^ composition[i];
    }
    if diff != 0 {
        return Err(KwWhy::Composition);
    }
    let sealed_len = blob.len() - KW_SEALED_OFF - KW_TAG_LEN;
    let mut sealed = [0u8; KW_SEALED_PREFIX + KW_KEY_MAX];
    sealed[..sealed_len].copy_from_slice(&blob[KW_SEALED_OFF..KW_SEALED_OFF + sealed_len]);
    let mut tag = [0u8; KW_TAG_LEN];
    tag.copy_from_slice(&blob[KW_SEALED_OFF + sealed_len..]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[KW_NONCE_OFF..KW_NONCE_OFF + 12]);
    let mut kek = kw_kek(shared, &attest, my_pub);
    let ok = chacha20_poly1305_decrypt(
        &kek,
        &nonce,
        &blob[..KW_SEALED_OFF],
        &mut sealed[..sealed_len],
        &tag,
    );
    kw_zero(&mut kek);
    if !ok {
        kw_zero(&mut sealed);
        return Err(KwWhy::Tag);
    }
    let key_len = sealed[6] as usize;
    if KW_SEALED_PREFIX + key_len != sealed_len {
        kw_zero(&mut sealed);
        return Err(KwWhy::Contents);
    }
    if key_out.len() < key_len {
        kw_zero(&mut sealed);
        return Err(KwWhy::Capacity);
    }
    key_out[..key_len].copy_from_slice(&sealed[KW_SEALED_PREFIX..sealed_len]);
    let opened = KwOpened {
        suite: u16::from_le_bytes([sealed[0], sealed[1]]),
        usage: u32::from_le_bytes([sealed[2], sealed[3], sealed[4], sealed[5]]),
        key_len,
    };
    kw_zero(&mut sealed);
    Ok(opened)
}
