// ── Suites ──────────────────────────────────────────────────────────────
//
// What this build serves: the variant's suites. Every length, usage mask
// and enumeration flows from `suite_private_len`, so `DESCRIBE_SUITE` and
// the ops cannot disagree about what is supported.

/// P-256 group order n (big-endian). Every P-256 scalar this vault holds
/// lies in [1, n-1].
const P256_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// The ML-DSA parameter set a suite names, `None` without ML-DSA.
#[cfg(feature = "ml_dsa")]
const fn ml_dsa_set_for(suite: u16) -> Option<ml_dsa::MlDsaSet> {
    match suite {
        kv::suite::ML_DSA_44 => Some(ml_dsa::MlDsaSet::MlDsa44),
        kv::suite::ML_DSA_65 => Some(ml_dsa::MlDsaSet::MlDsa65),
        kv::suite::ML_DSA_87 => Some(ml_dsa::MlDsaSet::MlDsa87),
        _ => None,
    }
}

/// Whether `suite` is an ML-DSA suite this build serves.
const fn is_ml_dsa(suite: u16) -> bool {
    #[cfg(feature = "ml_dsa")]
    {
        ml_dsa_set_for(suite).is_some()
    }
    #[cfg(not(feature = "ml_dsa"))]
    {
        let _ = suite;
        false
    }
}

/// Scratch for ML-DSA: one workspace at the widest dimensions serves all
/// three sets, with staging for a signature and a public key. From the heap
/// (`pq`, `full` variants).
#[cfg(feature = "ml_dsa")]
#[repr(C)]
struct MlScratch {
    ws: ml_dsa::SignWorkspace<{ ml_dsa::K_MAX }, { ml_dsa::L_MAX }>,
    sig: [u8; ml_dsa::SIG_MAX],
    pk: [u8; ml_dsa::PK_MAX],
}

#[cfg(feature = "ml_dsa")]
fn ml(s: &mut State) -> &mut MlScratch {
    // SAFETY: taken from the heap at construction, one call at a time.
    unsafe { &mut *s.ml }
}

/// RSA keys this vault holds and the one signing job over them. A CRT key
/// is kilobytes, so an RSA slot's `data[0]` names an entry here. Two
/// entries: an identity and its successor during a rotation.
#[cfg(feature = "rsa")]
const RSA_ENTRIES: usize = 2;

#[cfg(feature = "rsa")]
#[repr(C)]
struct RsaScratch {
    keys: [rsa::RsaPrivateKey; RSA_ENTRIES],
    job: rsa::RsaSignJob,
    /// The slot whose signature `job` holds, or -1.
    job_slot: i32,
}

#[cfg(feature = "rsa")]
fn rsa_scratch(s: &mut State) -> &mut RsaScratch {
    // SAFETY: taken from the heap at construction, one call at a time.
    unsafe { &mut *s.rsa }
}

#[cfg(feature = "rsa")]
fn rsa_init(s: &mut State) {
    let r = s.rsa;
    // SAFETY: `r` names a whole `RsaScratch` of this instance's heap.
    unsafe {
        core::ptr::write(
            r,
            RsaScratch {
                keys: [rsa::RsaPrivateKey::empty(), rsa::RsaPrivateKey::empty()],
                job: rsa::RsaSignJob::new(),
                job_slot: -1,
            },
        );
    }
}

/// Free slot `i`'s RSA entry, if it names one.
#[cfg(feature = "rsa")]
fn rsa_release(s: &mut State, i: usize) {
    let sl = slots(s)[i];
    if is_rsa_suite(sl.suite) && sl.key_len == 1 {
        let entry = usize::from(sl.data[0]);
        if entry < RSA_ENTRIES {
            rsa_scratch(s).keys[entry].zeroize();
        }
    }
}

/// Limb-rows of a Montgomery product one `SIGN` call advances an RSA job by.
#[cfg(feature = "rsa")]
const RSA_SIGN_LIMB_ROWS_PER_CALL: usize = 256 * 16;

#[cfg(feature = "rsa")]
fn rsa_sign_rows_per_call(key: &rsa::RsaPrivateKey) -> usize {
    let limb_bits = core::mem::size_of::<rsa::RsaLimb>() * 8;
    let half_limbs = (key.n.bits() / 2).div_ceil(limb_bits).max(1);
    (RSA_SIGN_LIMB_ROWS_PER_CALL / half_limbs).max(1)
}

#[cfg(feature = "rsa")]
const fn rsa_suite_for_bits(bits: usize) -> u16 {
    match bits {
        2048 => kv::suite::RSA_2048,
        3072 => kv::suite::RSA_3072,
        4096 => kv::suite::RSA_4096,
        _ => kv::suite::NONE,
    }
}

const fn is_rsa_suite(suite: u16) -> bool {
    matches!(
        suite,
        kv::suite::RSA_2048 | kv::suite::RSA_3072 | kv::suite::RSA_4096
    )
}

/// Private-key length for a suite, or 0 when this build cannot use it.
const fn suite_private_len(suite: u16) -> usize {
    match suite {
        kv::suite::P256 | kv::suite::ED25519 => 32,
        kv::suite::AEAD_KEY | kv::suite::HMAC_SHA256 | kv::suite::KDF_KEY => 32,
        // Only where the block cipher is constant-time.
        kv::suite::AEAD_AES256_GCM if fluxor_sdk::crypto::aes_gcm::AES_IS_CONSTANT_TIME => 32,
        // The ML-DSA private key held is the 32-byte FIPS 204 seed.
        #[cfg(feature = "ml_dsa")]
        _ if ml_dsa_set_for(suite).is_some() => ml_dsa::SEED_LEN,
        // The PKCS#1 RSAPrivateKey DER with CRT fields, at its ceiling.
        #[cfg(feature = "rsa")]
        kv::suite::RSA_2048 => 1216,
        #[cfg(feature = "rsa")]
        kv::suite::RSA_3072 => 1792,
        #[cfg(feature = "rsa")]
        kv::suite::RSA_4096 => 2368,
        _ => 0,
    }
}

/// Public-key length for a suite, or 0.
const fn suite_public_len(suite: u16) -> usize {
    match suite {
        kv::suite::P256 => 65,
        kv::suite::ED25519 => 32,
        kv::suite::RSA_2048 => 270,
        kv::suite::RSA_3072 => 398,
        kv::suite::RSA_4096 => 526,
        #[cfg(feature = "ml_dsa")]
        _ => match ml_dsa_set_for(suite) {
            Some(set) => set.params().pk_len,
            None => 0,
        },
        #[cfg(not(feature = "ml_dsa"))]
        _ => 0,
    }
}

/// Signature length for a suite, or 0.
const fn suite_signature_len(suite: u16) -> usize {
    match suite {
        kv::suite::P256 | kv::suite::ED25519 => 64,
        kv::suite::HMAC_SHA256 => 32,
        kv::suite::RSA_2048 => 256,
        kv::suite::RSA_3072 => 384,
        kv::suite::RSA_4096 => 512,
        #[cfg(feature = "ml_dsa")]
        _ => match ml_dsa_set_for(suite) {
            Some(set) => set.params().sig_len,
            None => 0,
        },
        #[cfg(not(feature = "ml_dsa"))]
        _ => 0,
    }
}

/// What this vault permits for a suite it supports.
const fn suite_usage(suite: u16) -> u32 {
    use kv::usage as u;
    match suite {
        // Imported each boot by an operator's tooling; the record format is
        // sized for a 64-byte key.
        kv::suite::RSA_2048 | kv::suite::RSA_3072 | kv::suite::RSA_4096 => {
            u::SIGN | u::EXPORT_PUBLIC
        }
        kv::suite::P256 => u::SIGN | u::VERIFY | u::AGREE | u::EXPORT_PUBLIC | u::PERSIST | u::WRAP,
        kv::suite::ED25519 => u::SIGN | u::VERIFY | u::EXPORT_PUBLIC | u::PERSIST | u::WRAP,
        kv::suite::AEAD_KEY | kv::suite::AEAD_AES256_GCM => {
            u::SEAL | u::OPEN | u::PERSIST | u::WRAP
        }
        kv::suite::KDF_KEY => u::DERIVE | u::PERSIST | u::WRAP,
        kv::suite::HMAC_SHA256 => u::SIGN | u::VERIFY | u::PERSIST | u::WRAP,
        _ if is_ml_dsa(suite) => u::SIGN | u::VERIFY | u::EXPORT_PUBLIC | u::PERSIST,
        _ => 0,
    }
}

/// The sign mode `suite` takes, or `None` for a suite that does not sign.
/// It is the one the suite actually uses: a P-256 key handed `RAW` would
/// sign a message as though it were a digest.
const fn sign_mode_of(suite: u16) -> Option<u8> {
    match suite {
        kv::suite::P256 => Some(kv::sign_mode::DIGEST),
        kv::suite::ED25519 | kv::suite::HMAC_SHA256 => Some(kv::sign_mode::RAW),
        kv::suite::RSA_2048 | kv::suite::RSA_3072 | kv::suite::RSA_4096 => {
            Some(kv::sign_mode::DIGEST)
        }
        _ if is_ml_dsa(suite) => Some(kv::sign_mode::RAW),
        _ => None,
    }
}

/// Whether `suite` signs as a resumable job.
const fn signs_resumably(suite: u16) -> bool {
    suite == kv::suite::P256 || is_rsa_suite(suite) || is_ml_dsa(suite)
}

/// True iff `k` (big-endian) is a valid P-256 scalar: 1 <= k < n.
fn p256_scalar_in_range(k: &[u8; 32]) -> bool {
    let mut less_than_n = false;
    for i in 0..32 {
        if k[i] < P256_ORDER_BE[i] {
            less_than_n = true;
            break;
        }
        if k[i] > P256_ORDER_BE[i] {
            return false;
        }
    }
    less_than_n && k.iter().any(|&b| b != 0)
}

/// Generate a fresh private key for `suite` into `out`, which is
/// `suite_private_len(suite)` bytes.
fn generate_into(s: &State, suite: u16, out: &mut [u8]) -> bool {
    match suite {
        kv::suite::AEAD_KEY
        | kv::suite::AEAD_AES256_GCM
        | kv::suite::HMAC_SHA256
        | kv::suite::KDF_KEY
        | kv::suite::ED25519 => out.len() == 32 && random(s, &mut out[..32]),
        kv::suite::P256 => {
            if out.len() != 32 {
                return false;
            }
            // Rejection sampling into [1, n-1].
            for _ in 0..128 {
                if !random(s, &mut out[..32]) {
                    return false;
                }
                let mut scalar = [0u8; 32];
                scalar.copy_from_slice(out);
                let ok = p256_scalar_in_range(&scalar);
                zeroize(&mut scalar);
                if ok {
                    return true;
                }
            }
            false
        }
        _ if is_ml_dsa(suite) => out.len() == 32 && random(s, &mut out[..32]),
        _ => false,
    }
}

/// Slot `idx`'s public key into `out`, whose length is
/// `suite_public_len` of the slot's suite.
fn write_public(s: &mut State, idx: usize, out: &mut [u8]) -> bool {
    let pub_len = out.len();
    let sl = slots(s)[idx];
    if suite_public_len(sl.suite) == 0 {
        return pub_len == 0;
    }
    if usize::from(sl.key_len) != 32 {
        return false;
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&sl.data[..32]);
    let ok = match sl.suite {
        kv::suite::P256 => match p256::public_key_from_scalar(&priv_key) {
            Some(pk) if pub_len == 65 => {
                out.copy_from_slice(&pk);
                true
            }
            _ => false,
        },
        kv::suite::ED25519 if pub_len == 32 => {
            out.copy_from_slice(&ed25519::ed25519_public_key(&priv_key));
            true
        }
        #[cfg(feature = "ml_dsa")]
        suite => match ml_dsa_set_for(suite) {
            Some(set) if pub_len == set.params().pk_len => {
                let m = ml(s);
                let ok = ml_dsa::ml_dsa_public_key(set, &priv_key, &mut m.ws, &mut m.pk[..pub_len])
                    .is_ok();
                m.ws.zeroize();
                if ok {
                    out.copy_from_slice(&m.pk[..pub_len]);
                }
                ok
            }
            _ => false,
        },
        #[cfg(not(feature = "ml_dsa"))]
        _ => false,
    };
    zeroize(&mut priv_key);
    ok
}

/// The record of the first suite this vault supports at or after `cursor`,
/// the token's P-256 record standing in for its own when `custody = token`
/// (a labelled persisted P-256 key is made there).
fn suite_record(s: &State, cursor: u16) -> Option<kv::describe_suite::Record> {
    use kv::describe_suite as ds;
    let mut c = cursor;
    while c <= kv::suite::MAX_ID {
        if c == kv::suite::P256 && s.custody == custody_mode::TOKEN {
            // `GENERATE` sends P-256 to the token: its record, which takes
            // no private key and signs whole.
            return Some(ds::Record {
                suite: c,
                next: c + 1,
                usage: abi::contracts::key_custody::USAGE,
                priv_len: 0,
                pub_len: 65,
                sig_len: 64,
                secret_len: 32,
                flags: ds::flags::GENERATE,
            });
        }
        let priv_len = suite_private_len(c);
        if priv_len != 0 {
            let mut flags = ds::flags::IMPORT;
            if !is_rsa_suite(c) {
                flags |= ds::flags::GENERATE;
            }
            if signs_resumably(c) {
                flags |= ds::flags::RESUMABLE_SIGN;
            }
            return Some(ds::Record {
                suite: c,
                next: c + 1,
                usage: suite_usage(c),
                priv_len: priv_len as u16,
                pub_len: suite_public_len(c) as u16,
                sig_len: suite_signature_len(c) as u16,
                secret_len: if c == kv::suite::P256 { 32 } else { 0 },
                flags,
            });
        }
        c += 1;
    }
    None
}

/// `DESCRIBE_SUITE`.
fn describe_suite(s: &State, arg: &mut [u8]) -> i32 {
    use kv::describe_suite as ds;
    let Some(cursor) = ds::parse_cursor(arg) else {
        return EINVAL;
    };
    if arg.len() < ds::LEN {
        return EINVAL;
    }
    match suite_record(s, cursor) {
        Some(r) => {
            arg[..ds::LEN].copy_from_slice(&ds::encode(&r));
            ds::LEN as i32
        }
        None => ENOENT,
    }
}
