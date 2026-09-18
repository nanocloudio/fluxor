//! What an identity `key_file` is, read at compose.
//!
//! A tls instance signs its CertificateVerify with the key the graph names,
//! and an RSA key can only be signed with by a vault that holds RSA — a
//! per-target capability (`target_facts::vault_suites`). The composer reads
//! enough of the DER to know which kind of key it is, so a graph that names
//! an RSA identity on a target that cannot sign with one is refused here,
//! with the reason, rather than at the module's first handshake.
//!
//! Only the shape is read: the outer SEQUENCE, the version, and either the
//! modulus (PKCS#1 `RSAPrivateKey`) or the algorithm identifier and the
//! wrapped key (PKCS#8 `PrivateKeyInfo` for `rsaEncryption`). Nothing
//! secret is interpreted and nothing is kept.

use crate::target_facts::vault_suite;

/// The vault suite an RSA modulus width belongs to, as the key-vault
/// contract numbers them.
pub fn vault_suite_for_rsa_bits(bits: usize) -> Option<u16> {
    match bits {
        2048 => Some(vault_suite::RSA_2048),
        3072 => Some(vault_suite::RSA_3072),
        4096 => Some(vault_suite::RSA_4096),
        _ => None,
    }
}

/// What a `key_file` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKey {
    /// An RSA private key of this modulus width, in PKCS#1 or PKCS#8 form.
    Rsa { bits: usize },
    /// Anything else this reader recognises as a private key of another
    /// algorithm (an EC key in SEC1 or PKCS#8 form).
    Other,
    /// Not a private key this reader can place at all.
    Unknown,
}

const OID_RSA_ENCRYPTION: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// A DER TLV at `at`: `(tag, content_start, content_len)`.
fn tlv(d: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    if at + 2 > d.len() {
        return None;
    }
    let tag = d[at];
    let first = d[at + 1];
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || at + 2 + n > d.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | d[at + 2 + i] as usize;
        }
        (len, 2 + n)
    };
    let start = at + hdr;
    if start + len > d.len() {
        return None;
    }
    Some((tag, start, len))
}

/// The bit width of a big-endian INTEGER's magnitude.
fn integer_bits(body: &[u8]) -> usize {
    let mag = if !body.is_empty() && body[0] == 0 {
        &body[1..]
    } else {
        body
    };
    match mag.iter().position(|&b| b != 0) {
        Some(i) => (mag.len() - i) * 8 - mag[i].leading_zeros() as usize,
        None => 0,
    }
}

/// Classify a PKCS#1 `RSAPrivateKey` body: `SEQUENCE { version, n, … }`.
fn pkcs1(d: &[u8]) -> IdentityKey {
    let Some((0x30, start, len)) = tlv(d, 0) else {
        return IdentityKey::Unknown;
    };
    let Some((0x02, v_start, v_len)) = tlv(d, start) else {
        return IdentityKey::Unknown;
    };
    if v_len != 1 || d[v_start] != 0 {
        return IdentityKey::Unknown;
    }
    let Some((0x02, n_start, n_len)) = tlv(d, v_start + v_len) else {
        return IdentityKey::Unknown;
    };
    if n_start + n_len > start + len {
        return IdentityKey::Unknown;
    }
    IdentityKey::Rsa {
        bits: integer_bits(&d[n_start..n_start + n_len]),
    }
}

/// Classify a private-key DER.
pub fn classify(der: &[u8]) -> IdentityKey {
    let Some((0x30, start, _)) = tlv(der, 0) else {
        return IdentityKey::Unknown;
    };
    let Some((first_tag, v_start, v_len)) = tlv(der, start) else {
        return IdentityKey::Unknown;
    };
    if first_tag != 0x02 {
        return IdentityKey::Unknown;
    }
    let after_version = v_start + v_len;
    match tlv(der, after_version) {
        // PKCS#1: the modulus follows the version.
        Some((0x02, _, _)) => pkcs1(der),
        // PKCS#8: an AlgorithmIdentifier follows, then the wrapped key.
        Some((0x30, alg_start, alg_len)) => {
            let Some((0x06, oid_start, oid_len)) = tlv(der, alg_start) else {
                return IdentityKey::Unknown;
            };
            let oid = &der[oid_start..oid_start + oid_len];
            let Some((0x04, key_start, key_len)) = tlv(der, alg_start + alg_len) else {
                return IdentityKey::Unknown;
            };
            if oid == OID_RSA_ENCRYPTION {
                pkcs1(&der[key_start..key_start + key_len])
            } else {
                IdentityKey::Other
            }
        }
        // SEC1 ECPrivateKey: version 1 then an OCTET STRING.
        Some((0x04, _, _)) if v_len == 1 && der[v_start] == 1 => IdentityKey::Other,
        _ => IdentityKey::Unknown,
    }
}

/// Whether a target whose vault holds `vault_suites` can sign with `key`.
/// `Ok(())` when it can, or when the key is not RSA (every target signs
/// P-256 in-module); `Err` names the width and what the target lacks.
pub fn admit_identity(key: IdentityKey, target: &str, vault_suites: &[u16]) -> Result<(), String> {
    match key {
        IdentityKey::Rsa { bits } => match vault_suite_for_rsa_bits(bits) {
            Some(suite) if vault_suites.contains(&suite) => Ok(()),
            Some(_) => Err(format!(
                "key_file is an RSA-{bits} identity, and the {target} vault holds no RSA suite \
                 (a private operation is far past its step budget); use a P-256 identity here, \
                 or a target whose kernel carries `rsa-vault`"
            )),
            None => Err(format!(
                "key_file is an RSA key of {bits} bits; the tls module signs with 2048, 3072 \
                 or 4096"
            )),
        },
        IdentityKey::Other | IdentityKey::Unknown => Ok(()),
    }
}
