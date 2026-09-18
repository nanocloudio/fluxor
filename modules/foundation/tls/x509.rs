// X.509 DER parser and constrained-path certificate validator.
//
// The supported profile is deliberately narrow: ECDSA-with-SHA-256 over a
// P-256 subject key, DER only, one path built in the order the peer sent it,
// no revocation, no name constraints, no policy processing, one trust anchor.
// Anything outside the profile is refused rather than partially interpreted —
// a certificate that parses under looser rules than it was signed under is a
// certificate whose validated meaning differs from its signed meaning.
//
// Pure Rust, no_std, no heap.

/// DER tag types
const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OID: u8 = 0x06;
/// ASN.1 NULL, the explicit `parameters` of an RSA AlgorithmIdentifier.
const TAG_NULL: u8 = 0x05;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_1: u8 = 0xA1;
const TAG_CONTEXT_2: u8 = 0xA2;
const TAG_CONTEXT_3: u8 = 0xA3;

/// dNSName inside a SAN GeneralName ([2] IMPLICIT IA5String).
const TAG_SAN_DNS: u8 = 0x82;

/// uniformResourceIdentifier inside a SAN GeneralName
/// ([6] IMPLICIT IA5String). This is where a SPIFFE ID lives.
const TAG_SAN_URI: u8 = 0x86;

/// OID for SubjectAltName: 2.5.29.17
const OID_SAN: [u8; 3] = [0x55, 0x1D, 0x11];
/// OID for BasicConstraints: 2.5.29.19
const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
/// OID for KeyUsage: 2.5.29.15
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];
/// OID for ExtKeyUsage: 2.5.29.37
const OID_EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x25];

/// OID for id-kp-serverAuth: 1.3.6.1.5.5.7.3.1
const OID_KP_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// OID for id-kp-clientAuth: 1.3.6.1.5.5.7.3.2
const OID_KP_CLIENT_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// OID for ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBKEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// OID for prime256v1 (P-256): 1.2.840.10045.3.1.7
const OID_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// OID for prime384v1 (P-384): 1.3.132.0.34
const OID_P384: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];

/// OID for ecdsa-with-SHA256: 1.2.840.10045.4.3.2
const OID_ECDSA_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// OID for ecdsa-with-SHA384: 1.2.840.10045.4.3.3
const OID_ECDSA_SHA384: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// OID for id-Ed25519: 1.3.101.112. Ed25519 names one OID for both the
/// key and the signature — there is no separate hash to name.
const OID_ED25519: [u8; 3] = [0x2B, 0x65, 0x70];

/// OID for rsaEncryption: 1.2.840.113549.1.1.1. An RSA key's
/// AlgorithmIdentifier carries an explicit NULL `parameters`.
const OID_RSA_ENCRYPTION: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// OID for sha256WithRSAEncryption: 1.2.840.113549.1.1.11.
const OID_SHA256_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// OID for sha384WithRSAEncryption: 1.2.840.113549.1.1.12.
const OID_SHA384_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
/// OID for id-RSASSA-PSS: 1.2.840.113549.1.1.10. Named so the log can say
/// what it met; not verified.
const OID_RSASSA_PSS: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

/// OIDs for ML-DSA (FIPS 204), 2.16.840.1.101.3.4.3.17/18/19.
const OID_ML_DSA_44: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
const OID_ML_DSA_65: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
const OID_ML_DSA_87: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

/// Certificate suites: a key type paired with the hash it signs under.
///
/// A suite id is what the rest of the stack carries instead of an OID. It
/// exists so a size, a policy decision or a capability check is a lookup
/// rather than a constant someone chose when only one algorithm existed.
/// Every bound below was a literal `64`, `65` or `4` somewhere; those
/// numbers are true for P-256 and wrong for everything else, and an
/// ML-DSA-65 certificate is roughly 4 KB against P-256's few hundred bytes.
///
/// **Naming a suite is not implementing it.** [`is_implemented`] is the
/// only thing that says whether this build can verify one, and
/// `verify_chain` refuses anything else with
/// [`CERT_ERR_UNSUPPORTED_SUITE`]. The ids exist so the interfaces do not
/// have to change when the primitives arrive; they do not make a
/// post-quantum certificate verifiable today.
pub mod suite {
    /// An algorithm this build could not resolve to a suite at all.
    ///
    /// Distinct from a suite that is known but not implemented: the first
    /// is "we do not know what this is", the second "we know and cannot
    /// check it". Both are refused, and the operator log tells them apart.
    pub const UNKNOWN: u16 = 0;
    pub const ECDSA_P256_SHA256: u16 = 1;
    pub const ECDSA_P384_SHA384: u16 = 2;
    pub const ED25519: u16 = 3;
    pub const ML_DSA_44: u16 = 4;
    pub const ML_DSA_65: u16 = 5;
    pub const ML_DSA_87: u16 = 6;
    /// RSA KEYS, by modulus width. A key suite rather than a signature
    /// suite: an RSA key signs under more than one hash, so the width is
    /// what the key says and the hash is what the signature says.
    pub const RSA_2048: u16 = 7;
    pub const RSA_3072: u16 = 8;
    pub const RSA_4096: u16 = 9;
    /// RSA SIGNATURES: RSASSA-PKCS1-v1_5 under the named hash, made by a
    /// key of any RSA width.
    pub const RSA_PKCS1_SHA256: u16 = 10;
    pub const RSA_PKCS1_SHA384: u16 = 11;
    /// RSASSA-PSS as a certificate signature. Named, refused: no public
    /// issuer signs certificates with it.
    pub const RSA_PSS: u16 = 12;

    /// Highest suite id this registry defines.
    pub const MAX_ID: u16 = RSA_PSS;

    /// Whether this build can actually verify a signature in `suite`.
    ///
    /// P-256 and the three ML-DSA parameter sets. P-384 and Ed25519 are
    /// named but not verified here: the ids exist so sizes, policies and
    /// error reporting are suite-shaped ahead of the primitives, and
    /// `verify_chain` refuses anything this returns false for rather than
    /// treating an unrecognised algorithm as an unchecked one.
    #[must_use]
    pub const fn is_implemented(suite: u16) -> bool {
        matches!(
            suite,
            ECDSA_P256_SHA256
                | ML_DSA_44
                | ML_DSA_65
                | ML_DSA_87
                | RSA_2048
                | RSA_3072
                | RSA_4096
                | RSA_PKCS1_SHA256
                | RSA_PKCS1_SHA384
        )
    }

    /// The algorithm family a suite belongs to, for the downgrade rule.
    ///
    /// A chain is only as strong as its weakest issuer, and within one
    /// family a weaker issuer vouching for a stronger key is refused. Across
    /// families the comparison is not made: the public web is built of
    /// RSA-2048 intermediates issuing P-256 leaves, every root program
    /// admits that shape, and the chain's strength is bounded by the anchor
    /// the operator chose in any case. A suite this build cannot place in a
    /// family compares against everything, so `UNKNOWN` stays the weaker
    /// side of every comparison.
    #[must_use]
    pub const fn family(suite: u16) -> u8 {
        match suite {
            ECDSA_P256_SHA256 | ECDSA_P384_SHA384 => 1,
            ED25519 => 2,
            ML_DSA_44 | ML_DSA_65 | ML_DSA_87 => 3,
            RSA_2048 | RSA_3072 | RSA_4096 | RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PSS => 4,
            _ => 0,
        }
    }

    /// Whether `issuer` vouching for `subject` is a downgrade: the issuer's
    /// key is weaker than the key it signs, within one family (see
    /// [`family`]).
    #[must_use]
    pub const fn is_downgrade(issuer: u16, subject: u16) -> bool {
        let same_family = family(issuer) == family(subject) || family(issuer) == 0;
        same_family && security_bits(issuer) < security_bits(subject)
    }

    /// Whether a key of `key_suite` is one that makes signatures of
    /// `sig_suite`. For every suite but RSA the two are the same id; an
    /// RSA key of any width signs PKCS#1 v1.5 under either hash.
    #[must_use]
    pub const fn key_signs(key_suite: u16, sig_suite: u16) -> bool {
        match key_suite {
            RSA_2048 | RSA_3072 | RSA_4096 => {
                matches!(sig_suite, RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384)
            }
            _ => key_suite == sig_suite && key_suite != UNKNOWN,
        }
    }

    /// Classical-equivalent security level in bits. Used to detect a
    /// downgrade: an issuer weaker than the key it signs makes that key
    /// only as strong as the issuer.
    #[must_use]
    pub const fn security_bits(suite: u16) -> u16 {
        match suite {
            ECDSA_P256_SHA256 | ED25519 | ML_DSA_44 => 128,
            ECDSA_P384_SHA384 | ML_DSA_65 => 192,
            ML_DSA_87 => 256,
            // SP 800-57 Part 1 tabulates 2048 → 112 and 3072 → 128 and does
            // not list 4096; the conservative tabulated row is used rather
            // than an interpolation.
            RSA_2048 => 112,
            RSA_3072 | RSA_4096 => 128,
            // A signature suite's strength is its hash's; the key it was
            // made with is the bound that matters and is compared as a key.
            RSA_PKCS1_SHA256 | RSA_PSS => 128,
            RSA_PKCS1_SHA384 => 192,
            // An unresolvable suite is worth nothing, so it can never be
            // the stronger side of a comparison.
            _ => 0,
        }
    }

    /// Longest subject public key, in bytes.
    #[must_use]
    pub const fn max_public_key_len(suite: u16) -> usize {
        match suite {
            ECDSA_P256_SHA256 => 65, // uncompressed point: 0x04 || X || Y
            ECDSA_P384_SHA384 => 97,
            ED25519 => 32,
            ML_DSA_44 => 1312,
            ML_DSA_65 => 1952,
            ML_DSA_87 => 2592,
            // RSAPublicKey DER: SEQUENCE, INTEGER n with its sign octet,
            // INTEGER e of up to four bytes.
            RSA_2048 => 270,
            RSA_3072 => 398,
            RSA_4096 => 526,
            _ => 0,
        }
    }

    /// Longest signature, in bytes. DER-encoded for ECDSA, which is why
    /// these exceed the raw `r‖s` length.
    #[must_use]
    pub const fn max_signature_len(suite: u16) -> usize {
        match suite {
            ECDSA_P256_SHA256 => 72,
            ECDSA_P384_SHA384 => 104,
            ED25519 => 64,
            ML_DSA_44 => 2420,
            ML_DSA_65 => 3309,
            ML_DSA_87 => 4627,
            RSA_2048 => 256,
            RSA_3072 => 384,
            // A PKCS#1 signature is the modulus width, so a signature suite
            // is bounded by the widest key that may make one.
            RSA_4096 | RSA_PKCS1_SHA256 | RSA_PKCS1_SHA384 | RSA_PSS => 512,
            _ => 0,
        }
    }

    /// Buffer a single certificate in this suite must fit in.
    ///
    /// The names, extensions and DER framing around the key and signature
    /// are bounded generously and identically across suites; what varies
    /// is the two variable-length fields, so the bound is derived from
    /// them rather than picked.
    #[must_use]
    pub const fn max_certificate_len(suite: u16) -> usize {
        /// Names, validity, extensions and DER framing.
        const ENVELOPE: usize = 1024;
        if suite == UNKNOWN {
            return 0;
        }
        ENVELOPE + max_public_key_len(suite) + max_signature_len(suite)
    }

    /// Buffer a whole chain in this suite must fit in.
    #[must_use]
    pub const fn max_chain_len_bytes(suite: u16) -> usize {
        max_certificate_len(suite) * super::MAX_CHAIN_LEN
    }

    /// This suite's bit in an `allowed_suites` mask. `UNKNOWN` and any id
    /// past [`MAX_ID`] have no bit, so they can never be allowed.
    #[must_use]
    pub const fn mask(suite: u16) -> u32 {
        if suite == UNKNOWN || suite > MAX_ID {
            0
        } else {
            1u32 << suite
        }
    }

    /// Every suite this build can verify. The sane default for a policy.
    ///
    /// Derived from [`is_implemented`] rather than listed again, so a
    /// suite cannot become verifiable without becoming permissible by
    /// default — or, worse, the reverse.
    pub const IMPLEMENTED: u32 = {
        let mut allowed = 0u32;
        let mut suite = 1u16;
        while suite <= MAX_ID {
            if is_implemented(suite) {
                allowed |= mask(suite);
            }
            suite += 1;
        }
        allowed
    };

    /// Short stable token for a suite, for the operator-facing log line.
    #[must_use]
    pub const fn text(suite: u16) -> &'static [u8] {
        match suite {
            ECDSA_P256_SHA256 => b"ecdsa-p256-sha256",
            ECDSA_P384_SHA384 => b"ecdsa-p384-sha384",
            ED25519 => b"ed25519",
            ML_DSA_44 => b"ml-dsa-44",
            ML_DSA_65 => b"ml-dsa-65",
            ML_DSA_87 => b"ml-dsa-87",
            RSA_2048 => b"rsa-2048",
            RSA_3072 => b"rsa-3072",
            RSA_4096 => b"rsa-4096",
            RSA_PKCS1_SHA256 => b"rsa-pkcs1-sha256",
            RSA_PKCS1_SHA384 => b"rsa-pkcs1-sha384",
            RSA_PSS => b"rsa-pss",
            _ => b"unknown",
        }
    }
}

/// The key suite an RSA modulus of `bits` belongs to, or `UNKNOWN` for a
/// width this registry does not name. Widths between the named ones are
/// keys no issuer mints and no size here is derived for.
#[must_use]
const fn rsa_key_suite_for_bits(bits: usize) -> u16 {
    match bits {
        2048 => suite::RSA_2048,
        3072 => suite::RSA_3072,
        4096 => suite::RSA_4096,
        _ => suite::UNKNOWN,
    }
}

/// Resolve a `signatureAlgorithm` OID to a suite id.
///
/// Returns [`suite::UNKNOWN`] rather than failing: an algorithm nobody
/// here recognises is a policy answer, not a parse error, and reporting it
/// as malformed DER would send an operator looking for a corrupt file.
#[must_use]
fn suite_from_signature_oid(oid: &[u8]) -> u16 {
    if oid == OID_ECDSA_SHA256 {
        suite::ECDSA_P256_SHA256
    } else if oid == OID_ECDSA_SHA384 {
        suite::ECDSA_P384_SHA384
    } else if oid == OID_ED25519 {
        suite::ED25519
    } else if oid == OID_ML_DSA_44 {
        suite::ML_DSA_44
    } else if oid == OID_ML_DSA_65 {
        suite::ML_DSA_65
    } else if oid == OID_ML_DSA_87 {
        suite::ML_DSA_87
    } else if oid == OID_SHA256_WITH_RSA {
        suite::RSA_PKCS1_SHA256
    } else if oid == OID_SHA384_WITH_RSA {
        suite::RSA_PKCS1_SHA384
    } else if oid == OID_RSASSA_PSS {
        suite::RSA_PSS
    } else {
        suite::UNKNOWN
    }
}

/// KeyUsage bit positions (RFC 5280 §4.2.1.3), numbered from the most
/// significant bit of the first content octet.
const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
const KU_KEY_CERT_SIGN: u16 = 1 << 5;

/// Parse a DER length field. Returns (length, bytes_consumed).
///
/// DER (X.690 §10.1) admits exactly one encoding per length: the short
/// form below 128, and otherwise the shortest long form with no
/// leading zero octet. The indefinite form (0x80) is BER only. A
/// parser that accepts the redundant encodings gives every certificate
/// several byte representations, which breaks the assumption that
/// signing the bytes signs the structure.
fn der_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    let first = data[pos];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        if pos + 1 >= data.len() {
            return None;
        }
        let len = data[pos + 1] as usize;
        if len < 0x80 {
            return None;
        } // must have used the short form
        Some((len, 2))
    } else if first == 0x82 {
        if pos + 2 >= data.len() {
            return None;
        }
        if data[pos + 1] == 0 {
            return None;
        } // non-minimal
        let len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        Some((len, 3))
    } else if first == 0x83 {
        if pos + 3 >= data.len() {
            return None;
        }
        if data[pos + 1] == 0 {
            return None;
        } // non-minimal
        let len = ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        Some((len, 4))
    } else {
        None
    }
}

/// Parse DER tag+length, return (content_start, content_length, total_consumed)
fn der_tlv(data: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    let _tag = data[pos];
    let (len, len_bytes) = der_length(data, pos + 1)?;
    let content_start = pos + 1 + len_bytes;
    if content_start + len > data.len() {
        return None;
    }
    Some((content_start, len, 1 + len_bytes + len))
}

// ======================================================================
// Validation reason codes
//
// One code per distinguishable cause. An operator must be able to tell
// wrong-authority from wrong-name from expired from malformed; a gate that
// fails closed for the wrong reason is a gate that will open again when that
// reason is fixed, so tests assert the code, not merely the refusal.
// ======================================================================

pub const CERT_OK: u32 = 0;
/// The Certificate message itself did not parse.
pub const CERT_ERR_MSG_MALFORMED: u32 = 1;
/// The Certificate message carried no certificate.
pub const CERT_ERR_EMPTY_CHAIN: u32 = 2;
/// A certificate in the path is outside the supported profile.
pub const CERT_ERR_MALFORMED: u32 = 3;
/// The configured trust anchor did not parse.
pub const CERT_ERR_ANCHOR_MALFORMED: u32 = 4;
/// More certificates than [`MAX_CHAIN_LEN`].
pub const CERT_ERR_CHAIN_TOO_LONG: u32 = 5;
/// Issuer and subject names do not chain in the order the peer sent them.
pub const CERT_ERR_ISSUER_MISMATCH: u32 = 6;
/// A certificate's signature did not verify under its stated issuer's key.
pub const CERT_ERR_SIGNATURE: u32 = 7;
/// The path reaches no configured trust anchor.
pub const CERT_ERR_NO_ANCHOR: u32 = 8;
/// An issuing certificate lacks `basicConstraints cA = TRUE`.
pub const CERT_ERR_NOT_CA: u32 = 9;
/// An issuing certificate lacks `keyUsage keyCertSign`.
pub const CERT_ERR_NO_KEY_CERT_SIGN: u32 = 10;
/// `pathLenConstraint` exceeded.
pub const CERT_ERR_PATH_LEN: u32 = 11;
/// The end entity asserts `cA = TRUE`.
pub const CERT_ERR_LEAF_IS_CA: u32 = 12;
/// The end entity's `keyUsage` excludes `digitalSignature`.
pub const CERT_ERR_LEAF_KEY_USAGE: u32 = 13;
/// The end entity's extended key usage is absent or names another purpose.
pub const CERT_ERR_LEAF_EKU: u32 = 14;
/// The end entity's names do not include the expected name.
pub const CERT_ERR_NAME_MISMATCH: u32 = 15;
/// The end entity carries no `dNSName` SAN at all.
pub const CERT_ERR_NAME_ABSENT: u32 = 16;
/// A critical extension the profile does not understand.
pub const CERT_ERR_CRITICAL_EXT: u32 = 17;
/// `now > notAfter`.
pub const CERT_ERR_EXPIRED: u32 = 18;
/// `now < notBefore`.
pub const CERT_ERR_NOT_YET_VALID: u32 = 19;
/// Validity is enforced but the platform has no synchronised wall clock.
pub const CERT_ERR_NO_CLOCK: u32 = 20;
/// The pinned profile's leaf key is not the pinned key.
pub const CERT_ERR_PIN_MISMATCH: u32 = 21;
/// A subject public key is not a valid P-256 point.
pub const CERT_ERR_BAD_KEY: u32 = 22;
/// No peer-authentication profile was selected.
pub const CERT_ERR_NO_PROFILE: u32 = 23;
/// A certificate in the chain uses a suite the policy does not allow, or
/// that this build cannot verify at all.
///
/// Distinct from [`CERT_ERR_MALFORMED`]: the DER was fine and the
/// algorithm was legible. Answering "malformed" for an unsupported
/// algorithm is how a deployment ends up hunting a corrupt file that is
/// not corrupt.
pub const CERT_ERR_UNSUPPORTED_SUITE: u32 = 24;
/// An issuer's suite is weaker than the key it signed.
///
/// A signature is worth the weaker of the two: a P-256 key vouched for by
/// a CA whose own signature is 80-bit is an 80-bit key with a 128-bit key
/// inside it. Refused rather than reported, because the whole point of
/// deploying the stronger key was not to have this happen.
pub const CERT_ERR_DOWNGRADE: u32 = 25;

/// Short stable token for a reason code, for the operator-facing log line.
pub fn cert_error_text(code: u32) -> &'static [u8] {
    match code {
        CERT_OK => b"ok",
        CERT_ERR_MSG_MALFORMED => b"message-malformed",
        CERT_ERR_EMPTY_CHAIN => b"empty-chain",
        CERT_ERR_MALFORMED => b"malformed",
        CERT_ERR_ANCHOR_MALFORMED => b"anchor-malformed",
        CERT_ERR_CHAIN_TOO_LONG => b"chain-too-long",
        CERT_ERR_ISSUER_MISMATCH => b"issuer-mismatch",
        CERT_ERR_SIGNATURE => b"signature",
        CERT_ERR_NO_ANCHOR => b"unknown-ca",
        CERT_ERR_NOT_CA => b"not-ca",
        CERT_ERR_NO_KEY_CERT_SIGN => b"no-key-cert-sign",
        CERT_ERR_PATH_LEN => b"path-len",
        CERT_ERR_LEAF_IS_CA => b"leaf-is-ca",
        CERT_ERR_LEAF_KEY_USAGE => b"leaf-key-usage",
        CERT_ERR_LEAF_EKU => b"leaf-eku",
        CERT_ERR_NAME_MISMATCH => b"name-mismatch",
        CERT_ERR_NAME_ABSENT => b"name-absent",
        CERT_ERR_CRITICAL_EXT => b"critical-ext",
        CERT_ERR_EXPIRED => b"expired",
        CERT_ERR_NOT_YET_VALID => b"not-yet-valid",
        CERT_ERR_NO_CLOCK => b"no-clock",
        CERT_ERR_PIN_MISMATCH => b"pin-mismatch",
        CERT_ERR_BAD_KEY => b"bad-key",
        CERT_ERR_NO_PROFILE => b"no-profile",
        CERT_ERR_UNSUPPORTED_SUITE => b"unsupported-suite",
        CERT_ERR_DOWNGRADE => b"downgrade",
        _ => b"unknown",
    }
}

/// TLS alert (RFC 8446 §6.2) that tells the peer as much as it may know.
pub fn cert_error_alert(code: u32) -> u8 {
    match code {
        CERT_ERR_NO_ANCHOR | CERT_ERR_PIN_MISMATCH | CERT_ERR_SIGNATURE => 48, // unknown_ca
        CERT_ERR_EXPIRED | CERT_ERR_NOT_YET_VALID | CERT_ERR_NO_CLOCK => 45, // certificate_expired
        CERT_ERR_NAME_MISMATCH | CERT_ERR_NAME_ABSENT => 49,                 // access_denied
        _ => 42,                                                             // bad_certificate
    }
}

// ======================================================================
// Certificate parsing
// ======================================================================

/// X.509 certificate parsed fields
pub struct X509Cert<'a> {
    /// Raw TBSCertificate (for signature verification)
    pub tbs_raw: &'a [u8],
    /// The suite this certificate's own signature is in — how its issuer
    /// signed it. [`suite::UNKNOWN`] when the algorithm OID resolved to
    /// nothing this build knows.
    ///
    /// Separate from `key_suite` because they are separate facts: a P-256
    /// key signed by a P-384 CA is an ordinary, correct certificate. A
    /// single `suite` field would have to pick one and silently lose the
    /// other, and the one it lost is the one a downgrade check needs.
    pub suite: u16,
    /// The suite of the subject public key — what this certificate is
    /// *about*, as opposed to who vouched for it.
    pub key_suite: u16,
    /// Subject public key. Its encoding is `key_suite`'s: an uncompressed
    /// point for EC, the raw key for everything else. Never interpret it
    /// without reading `key_suite` first.
    pub public_key: &'a [u8],
    /// Signature algorithm OID bytes
    pub sig_alg: &'a [u8],
    /// Signature value bytes (DER-encoded for ECDSA)
    pub signature: &'a [u8],
    /// Raw DER of the issuer Name, for path construction. Names are
    /// compared as bytes: the profile admits no normalisation, so two
    /// encodings of "the same" name are two names.
    pub issuer_raw: &'a [u8],
    /// Raw DER of the subject Name.
    pub subject_raw: &'a [u8],
    /// `notBefore` / `notAfter` as seconds since the Unix epoch.
    pub not_before: u64,
    pub not_after: u64,
    /// Offset and length of the extensions `[3]` SEQUENCE content, within
    /// the certificate DER. Length 0 when the certificate has none. An
    /// offset rather than a slice so an extension's own offsets stay
    /// comparable with the buffer the signature covered.
    pub ext_off: usize,
    pub ext_len: usize,
}

/// Parse X.509 DER certificate.
///
/// The supported profile is a single shape: an ECDSA-with-SHA-256
/// signature over a certificate whose subject key is a P-256 point.
/// Everything the profile fixes is checked here rather than at the
/// call sites, so no caller can consume a certificate that only
/// partly matches:
///
///   - the outer SEQUENCE spans the whole input, with no trailing
///     bytes to carry a second structure a different parser might see;
///   - `Certificate.signatureAlgorithm` equals
///     `tbsCertificate.signature`, so the algorithm covered by the
///     signature is the algorithm used to check it (RFC 5280 §4.1.1.2);
///   - both are `ecdsa-with-SHA256`;
///   - the signatureValue BIT STRING is whole-octet;
///   - every TBSCertificate field is at its ASN.1 position, so no field
///     is located by guessing an index.
pub fn parse_certificate(cert: &[u8]) -> Option<X509Cert<'_>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    if cert.len() < 10 {
        return None;
    }
    if cert[0] != TAG_SEQUENCE {
        return None;
    }
    let (cert_start, cert_len, cert_total) = der_tlv(cert, 0)?;
    if cert_total != cert.len() {
        return None;
    } // trailing bytes
    let cert_end = cert_start + cert_len;

    // Parse TBSCertificate
    let tbs_tag_pos = cert_start;
    if cert[tbs_tag_pos] != TAG_SEQUENCE {
        return None;
    }
    let (tbs_start, tbs_len, tbs_total) = der_tlv(cert, tbs_tag_pos)?;
    let tbs_raw = &cert[tbs_tag_pos..tbs_tag_pos + tbs_total];

    // Parse signatureAlgorithm
    let sig_alg_pos = tbs_tag_pos + tbs_total;
    if sig_alg_pos >= cert_end {
        return None;
    }
    if cert[sig_alg_pos] != TAG_SEQUENCE {
        return None;
    }
    let (_sa_start, _sa_len, sa_total) = der_tlv(cert, sig_alg_pos)?;
    let sig_alg = extract_oid(cert, sig_alg_pos)?;
    let sig_suite = suite_from_signature_oid(sig_alg);

    // Parse signatureValue (BIT STRING)
    let sig_pos = sig_alg_pos + sa_total;
    if sig_pos >= cert_end || cert[sig_pos] != TAG_BIT_STRING {
        return None;
    }
    let (sig_start, sig_len, sig_total) = der_tlv(cert, sig_pos)?;
    if sig_pos + sig_total != cert_end {
        return None;
    } // trailing bytes
    if sig_len < 2 || cert[sig_start] != 0 {
        return None;
    } // unused-bits must be 0
    let signature = &cert[sig_start + 1..sig_start + sig_len];

    let tbs = parse_tbs(cert, tbs_start, tbs_len)?;

    // The inner `tbsCertificate.signature` must name the same
    // algorithm; a mismatch means the signature covers a claim the
    // outer field contradicts.
    if tbs.inner_sig_alg != sig_alg {
        return None;
    }

    // A signature longer than its suite allows is not that suite's
    // signature. Refused here so no verifier is handed a length its
    // suite says cannot exist.
    if sig_suite != suite::UNKNOWN && signature.len() > suite::max_signature_len(sig_suite) {
        return None;
    }

    Some(X509Cert {
        tbs_raw,
        suite: sig_suite,
        key_suite: tbs.key_suite,
        public_key: tbs.public_key,
        sig_alg,
        signature,
        issuer_raw: tbs.issuer_raw,
        subject_raw: tbs.subject_raw,
        not_before: tbs.not_before,
        not_after: tbs.not_after,
        ext_off: tbs.ext_off,
        ext_len: tbs.ext_len,
    })
}

struct Tbs<'a> {
    /// Suite of the subject public key, resolved from the SPKI
    /// AlgorithmIdentifier.
    key_suite: u16,
    inner_sig_alg: &'a [u8],
    issuer_raw: &'a [u8],
    subject_raw: &'a [u8],
    not_before: u64,
    not_after: u64,
    public_key: &'a [u8],
    ext_off: usize,
    ext_len: usize,
}

/// Walk TBSCertificate positionally (RFC 5280 §4.1.2). Every field is read
/// at its ASN.1 position; nothing is located by scanning for a tag, because a
/// scan finds whichever copy an attacker placed first.
fn parse_tbs(cert: &[u8], start: usize, len: usize) -> Option<Tbs<'_>> {
    let end = start + len;
    let mut pos = start;

    // version [0] EXPLICIT, optional
    if pos < end && cert[pos] == TAG_CONTEXT_0 {
        let (_, _, total) = der_tlv(cert, pos)?;
        pos += total;
    }
    // serialNumber
    if pos >= end || cert[pos] != TAG_INTEGER {
        return None;
    }
    let (_, _, total) = der_tlv(cert, pos)?;
    pos += total;
    // signature AlgorithmIdentifier
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let inner_sig_alg = extract_oid(cert, pos)?;
    let (_, _, total) = der_tlv(cert, pos)?;
    pos += total;
    // issuer Name
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let (_, _, total) = der_tlv(cert, pos)?;
    let issuer_raw = &cert[pos..pos + total];
    pos += total;
    // validity SEQUENCE { notBefore, notAfter }
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let (v_start, v_len, total) = der_tlv(cert, pos)?;
    let (not_before, nb_total) = parse_time(cert, v_start)?;
    let (not_after, na_total) = parse_time(cert, v_start + nb_total)?;
    if nb_total + na_total != v_len {
        return None;
    } // exactly two times
    pos += total;
    // subject Name
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let (_, _, total) = der_tlv(cert, pos)?;
    let subject_raw = &cert[pos..pos + total];
    pos += total;
    // subjectPublicKeyInfo
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let (spki_start, spki_len, total) = der_tlv(cert, pos)?;
    let (key_suite, public_key) = extract_pubkey(cert, spki_start, spki_len)?;
    pos += total;
    // issuerUniqueID [1] / subjectUniqueID [2], both optional and unused
    if pos < end && cert[pos] == TAG_CONTEXT_1 {
        let (_, _, total) = der_tlv(cert, pos)?;
        pos += total;
    }
    if pos < end && cert[pos] == TAG_CONTEXT_2 {
        let (_, _, total) = der_tlv(cert, pos)?;
        pos += total;
    }
    // extensions [3] EXPLICIT SEQUENCE OF Extension, optional
    let mut ext_off = 0usize;
    let mut ext_len = 0usize;
    if pos < end && cert[pos] == TAG_CONTEXT_3 {
        let (e_start, e_len, total) = der_tlv(cert, pos)?;
        if e_start >= cert.len() || cert[e_start] != TAG_SEQUENCE {
            return None;
        }
        let (s_start, s_len, s_total) = der_tlv(cert, e_start)?;
        if s_total != e_len {
            return None;
        } // one SEQUENCE, no trailing bytes
        ext_off = s_start;
        ext_len = s_len;
        pos += total;
    }
    if pos != end {
        return None;
    } // no unexpected trailing TBS members

    Some(Tbs {
        inner_sig_alg,
        issuer_raw,
        subject_raw,
        not_before,
        not_after,
        key_suite,
        public_key,
        ext_off,
        ext_len,
    })
}

/// Parse an ASN.1 `Time` into seconds since the Unix epoch, returning
/// (seconds, bytes_consumed).
///
/// Only the UTC form is accepted for either encoding — RFC 5280 §4.1.2.5
/// requires `Z`, and a local-time offset would make a certificate's lifetime
/// depend on where it is read.
fn parse_time(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let tag = data[pos];
    let (start, len, total) = der_tlv(data, pos)?;
    let body = &data[start..start + len];
    let (year, rest) = match tag {
        TAG_UTC_TIME => {
            // YYMMDDHHMMSSZ
            if body.len() != 13 || body[12] != b'Z' {
                return None;
            }
            let yy = two_digits(body, 0)? as u32;
            // RFC 5280 §4.1.2.5.1: 00..49 is 2000..2049, 50..99 is 1950..1999.
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, &body[2..12])
        }
        TAG_GENERALIZED_TIME => {
            // YYYYMMDDHHMMSSZ
            if body.len() != 15 || body[14] != b'Z' {
                return None;
            }
            let year = (two_digits(body, 0)? as u32) * 100 + two_digits(body, 2)? as u32;
            (year, &body[4..14])
        }
        _ => return None,
    };
    let month = two_digits(rest, 0)? as u32;
    let day = two_digits(rest, 2)? as u32;
    let hour = two_digits(rest, 4)? as u32;
    let minute = two_digits(rest, 6)? as u32;
    let second = two_digits(rest, 8)? as u32;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        // A leap second is a legal ASN.1 time; it is one second, not a
        // reason to refuse a certificate.
        || second > 60
    {
        return None;
    }
    Some((unix_seconds(year, month, day, hour, minute, second), total))
}

fn two_digits(b: &[u8], at: usize) -> Option<u8> {
    if at + 1 >= b.len() {
        return None;
    }
    let hi = b[at];
    let lo = b[at + 1];
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return None;
    }
    Some((hi - b'0') * 10 + (lo - b'0'))
}

/// Days from 1970-01-01 to the given civil date, then seconds. Uses the
/// days-from-civil algorithm (era arithmetic) so no lookup table lands in
/// `.rodata` — absolute addresses there are not relocated in a PIC module.
/// The civil-date arithmetic is deliberately 32-bit: a four-digit year and a
/// day count both fit in `u32`, and a 64-bit divide would need the compiler's
/// `__aeabi_uldivmod`, which is not linked into a PIC module on a 32-bit
/// target. Only the final second count is widened.
fn unix_seconds(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let m = month;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe;
    // 719_468 = days from 0000-03-01 to 1970-01-01.
    let unix_days = days - 719_468;
    (unix_days as u64) * 86_400 + (hour as u64) * 3600 + (minute as u64) * 60 + second as u64
}

/// Divide a 64-bit value by a small divisor without the compiler's 64-bit
/// division helper, which a PIC module cannot link on a 32-bit target. Bitwise
/// long division: shifts, compares and subtraction only.
pub fn div_u64(n: u64, d: u32) -> u64 {
    let d = d as u64;
    if d == 0 {
        return 0;
    }
    let mut rem: u64 = 0;
    let mut quo: u64 = 0;
    let mut i: i32 = 63;
    while i >= 0 {
        rem = (rem << 1) | ((n >> i) & 1);
        if rem >= d {
            rem -= d;
            quo |= 1u64 << i;
        }
        i -= 1;
    }
    quo
}

/// Extract first OID from a SEQUENCE
fn extract_oid(data: &[u8], seq_pos: usize) -> Option<&[u8]> {
    let (seq_start, seq_len, _) = der_tlv(data, seq_pos)?;
    let mut pos = seq_start;
    let end = seq_start + seq_len;
    while pos < end {
        if data[pos] == TAG_OID {
            let (oid_start, oid_len, _) = der_tlv(data, pos)?;
            return Some(&data[oid_start..oid_start + oid_len]);
        }
        let (_, _, tlv_total) = der_tlv(data, pos)?;
        pos += tlv_total;
    }
    None
}

/// Extract the EC public key bytes from SubjectPublicKeyInfo.
///
/// The AlgorithmIdentifier is read, not assumed: the curve or algorithm it
/// names decides the key's suite, and the key bytes travel with that suite
/// from here on. Without that binding a key encoded for a different curve
/// (or a different algorithm entirely) would be handed to the P-256 code as
/// a bare point, and its wire bytes would be reinterpreted rather than
/// rejected.
///
/// An algorithm this build does not recognise yields
/// [`suite::UNKNOWN`] and the raw key bytes. That is deliberately not a
/// parse failure: `verify_chain` refuses it with
/// [`CERT_ERR_UNSUPPORTED_SUITE`], which tells an operator what is actually
/// wrong. Reporting it as malformed DER — which is what this did when the
/// profile was one shape — sent them looking for a corrupt file.
///
/// Shape rules still hold for every suite: an EC AlgorithmIdentifier is
/// exactly two OIDs, a non-EC one is exactly one OID with no parameters,
/// the BIT STRING is whole-octet, and the SPKI has no third member.
fn extract_pubkey(cert: &[u8], spki_start: usize, spki_len: usize) -> Option<(u16, &[u8])> {
    let mut pos = spki_start;
    let end = spki_start + spki_len;

    // AlgorithmIdentifier SEQUENCE { algorithm OID [, parameters OID] }
    if pos >= end || cert[pos] != TAG_SEQUENCE {
        return None;
    }
    let (alg_start, alg_len, alg_total) = der_tlv(cert, pos)?;
    let alg_end = alg_start + alg_len;

    let mut ap = alg_start;
    if ap >= alg_end || cert[ap] != TAG_OID {
        return None;
    }
    let (a_start, a_len, a_total) = der_tlv(cert, ap)?;
    let alg_oid = &cert[a_start..a_start + a_len];
    ap += a_total;

    let key_suite = if alg_oid == OID_EC_PUBKEY {
        // EC keys name their curve in `parameters`, and the curve is what
        // decides the suite — `ecPublicKey` alone says nothing about size.
        if ap >= alg_end || cert[ap] != TAG_OID {
            return None;
        }
        let (c_start, c_len, c_total) = der_tlv(cert, ap)?;
        let curve = &cert[c_start..c_start + c_len];
        ap += c_total;
        if curve == OID_P256 {
            suite::ECDSA_P256_SHA256
        } else if curve == OID_P384 {
            suite::ECDSA_P384_SHA384
        } else {
            suite::UNKNOWN
        }
    } else if alg_oid == OID_RSA_ENCRYPTION {
        // An RSA key's `parameters` is an explicit NULL (RFC 3279 §2.3.1):
        // exactly `05 00`, and nothing else is admitted.
        if ap + 2 > alg_end || cert[ap] != TAG_NULL || cert[ap + 1] != 0 {
            return None;
        }
        ap += 2;
        // The width is read from the key itself, below; the suite is
        // settled once the BIT STRING is in hand.
        suite::RSA_2048
    } else {
        // Everything else names the algorithm in one OID and takes no
        // parameters. An absent `parameters` is the point: a present one
        // would mean this is a shape we have not been taught to read.
        if alg_oid == OID_ED25519 {
            suite::ED25519
        } else if alg_oid == OID_ML_DSA_44 {
            suite::ML_DSA_44
        } else if alg_oid == OID_ML_DSA_65 {
            suite::ML_DSA_65
        } else if alg_oid == OID_ML_DSA_87 {
            suite::ML_DSA_87
        } else {
            suite::UNKNOWN
        }
    };
    if ap != alg_end {
        return None;
    } // no extra AlgorithmIdentifier members

    pos += alg_total;

    // subjectPublicKey BIT STRING
    if pos >= end || cert[pos] != TAG_BIT_STRING {
        return None;
    }
    let (bs_start, bs_len, bs_total) = der_tlv(cert, pos)?;
    if bs_len < 2 || cert[bs_start] != 0 {
        return None;
    } // whole-octet only
    if pos + bs_total != end {
        return None;
    } // SPKI has exactly two members
    let key_bytes = &cert[bs_start + 1..bs_start + bs_len];

    // An RSA key's suite is its modulus width, which the RSAPublicKey
    // inside the BIT STRING says. A width this registry does not name is
    // an unknown suite, which the log names as such, not a corrupt file.
    let key_suite = if alg_oid == OID_RSA_ENCRYPTION {
        match rsa_public_key_parse(key_bytes) {
            Some(k) => rsa_key_suite_for_bits(rsa_public_key_bits(&k)),
            None => suite::UNKNOWN,
        }
    } else {
        key_suite
    };

    // A key longer than its suite can hold is not that suite's key. Checked
    // here so no downstream buffer is sized from a suite the bytes contradict.
    if key_suite != suite::UNKNOWN && key_bytes.len() > suite::max_public_key_len(key_suite) {
        return None;
    }
    Some((key_suite, key_bytes))
}

// ======================================================================
// Extensions
// ======================================================================

/// What the profile understands about one certificate's extensions.
/// Every field is a decision input; an extension outside this set that is
/// marked critical sets `unknown_critical`, which is fatal.
struct CertExts {
    unknown_critical: bool,
    /// `basicConstraints` present, and its `cA` value.
    bc_present: bool,
    bc_is_ca: bool,
    /// `pathLenConstraint`, when the extension carried one.
    bc_path_len: Option<u32>,
    ku_present: bool,
    ku_bits: u16,
    eku_present: bool,
    eku_server_auth: bool,
    eku_client_auth: bool,
    /// Offset/length of the SAN extension value within the certificate, so
    /// name matching reads the extension the path validation saw.
    san: Option<(usize, usize)>,
    /// Malformed extension encoding.
    malformed: bool,
}

impl CertExts {
    fn empty() -> Self {
        Self {
            unknown_critical: false,
            bc_present: false,
            bc_is_ca: false,
            bc_path_len: None,
            ku_present: false,
            ku_bits: 0,
            eku_present: false,
            eku_server_auth: false,
            eku_client_auth: false,
            san: None,
            malformed: false,
        }
    }
}

/// Walk one certificate's extension list. `cert` is the whole certificate
/// DER, so the returned SAN offsets index it directly.
fn parse_extensions(cert: &[u8], ext_off: usize, ext_len: usize) -> CertExts {
    let mut out = CertExts::empty();
    if ext_len == 0 {
        return out;
    }
    let mut pos = ext_off;
    let end = ext_off + ext_len;
    if end > cert.len() {
        out.malformed = true;
        return out;
    }
    while pos < end {
        if cert[pos] != TAG_SEQUENCE {
            out.malformed = true;
            return out;
        }
        let (e_start, e_len, e_total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => {
                out.malformed = true;
                return out;
            }
        };
        let e_end = e_start + e_len;
        let mut ip = e_start;
        if ip >= e_end || cert[ip] != TAG_OID {
            out.malformed = true;
            return out;
        }
        let (oid_start, oid_len, oid_total) = match der_tlv(cert, ip) {
            Some(v) => v,
            None => {
                out.malformed = true;
                return out;
            }
        };
        let oid = &cert[oid_start..oid_start + oid_len];
        ip += oid_total;
        let mut critical = false;
        if ip < e_end && cert[ip] == TAG_BOOLEAN {
            let (b_start, b_len, b_total) = match der_tlv(cert, ip) {
                Some(v) => v,
                None => {
                    out.malformed = true;
                    return out;
                }
            };
            // DER: a BOOLEAN is one octet, TRUE is 0xFF exactly.
            if b_len != 1 || (cert[b_start] != 0x00 && cert[b_start] != 0xFF) {
                out.malformed = true;
                return out;
            }
            critical = cert[b_start] == 0xFF;
            ip += b_total;
        }
        if ip >= e_end || cert[ip] != TAG_OCTET_STRING {
            out.malformed = true;
            return out;
        }
        let (v_start, v_len, v_total) = match der_tlv(cert, ip) {
            Some(v) => v,
            None => {
                out.malformed = true;
                return out;
            }
        };
        if ip + v_total != e_end {
            out.malformed = true;
            return out;
        }

        if oid == OID_BASIC_CONSTRAINTS {
            out.bc_present = true;
            if !parse_basic_constraints(cert, v_start, v_len, &mut out) {
                out.malformed = true;
                return out;
            }
        } else if oid == OID_KEY_USAGE {
            out.ku_present = true;
            match parse_key_usage(cert, v_start, v_len) {
                Some(bits) => out.ku_bits = bits,
                None => {
                    out.malformed = true;
                    return out;
                }
            }
        } else if oid == OID_EXT_KEY_USAGE {
            out.eku_present = true;
            if !parse_eku(cert, v_start, v_len, &mut out) {
                out.malformed = true;
                return out;
            }
        } else if oid == OID_SAN {
            out.san = Some((v_start, v_len));
        } else if critical {
            // An extension the profile cannot interpret, which the issuer
            // marked as one the relying party must interpret.
            out.unknown_critical = true;
        }

        pos += e_total;
    }
    out
}

/// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
///                                 pathLenConstraint INTEGER (0..MAX) OPTIONAL }
fn parse_basic_constraints(cert: &[u8], start: usize, len: usize, out: &mut CertExts) -> bool {
    if len == 0 || cert[start] != TAG_SEQUENCE {
        return false;
    }
    let (s_start, s_len, s_total) = match der_tlv(cert, start) {
        Some(v) => v,
        None => return false,
    };
    if s_total != len {
        return false;
    }
    let end = s_start + s_len;
    let mut pos = s_start;
    if pos < end && cert[pos] == TAG_BOOLEAN {
        let (b_start, b_len, b_total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => return false,
        };
        if b_len != 1 {
            return false;
        }
        // DER omits the DEFAULT FALSE encoding, so an explicit FALSE is not
        // a legal encoding of "not a CA" — but treating it as malformed
        // would refuse certificates OpenSSL emits, so it is read as FALSE.
        out.bc_is_ca = cert[b_start] == 0xFF;
        pos += b_total;
    }
    if pos < end && cert[pos] == TAG_INTEGER {
        let (i_start, i_len, i_total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => return false,
        };
        // A path length longer than the chain limit is not a constraint the
        // profile can exceed; clamp rather than overflow.
        if i_len == 0 || i_len > 4 {
            return false;
        }
        let mut v: u32 = 0;
        let mut i = 0;
        while i < i_len {
            v = (v << 8) | cert[i_start + i] as u32;
            i += 1;
        }
        out.bc_path_len = Some(v);
        pos += i_total;
    }
    pos == end
}

/// KeyUsage ::= BIT STRING, bit 0 the most significant bit of the first
/// content octet (RFC 5280 §4.2.1.3).
fn parse_key_usage(cert: &[u8], start: usize, len: usize) -> Option<u16> {
    if len == 0 || cert[start] != TAG_BIT_STRING {
        return None;
    }
    let (b_start, b_len, b_total) = der_tlv(cert, start)?;
    if b_total != len || b_len < 1 {
        return None;
    }
    let unused = cert[b_start] as usize;
    if unused > 7 {
        return None;
    }
    let mut bits: u16 = 0;
    let mut byte = 0;
    while byte < b_len - 1 && byte < 2 {
        let v = cert[b_start + 1 + byte];
        let mut bit = 0;
        while bit < 8 {
            if v & (0x80 >> bit) != 0 {
                bits |= 1u16 << (byte * 8 + bit);
            }
            bit += 1;
        }
        byte += 1;
    }
    Some(bits)
}

/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
fn parse_eku(cert: &[u8], start: usize, len: usize, out: &mut CertExts) -> bool {
    if len == 0 || cert[start] != TAG_SEQUENCE {
        return false;
    }
    let (s_start, s_len, s_total) = match der_tlv(cert, start) {
        Some(v) => v,
        None => return false,
    };
    if s_total != len {
        return false;
    }
    let end = s_start + s_len;
    let mut pos = s_start;
    while pos < end {
        if cert[pos] != TAG_OID {
            return false;
        }
        let (o_start, o_len, o_total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => return false,
        };
        let oid = &cert[o_start..o_start + o_len];
        if oid == OID_KP_SERVER_AUTH {
            out.eku_server_auth = true;
        } else if oid == OID_KP_CLIENT_AUTH {
            out.eku_client_auth = true;
        }
        pos += o_total;
    }
    pos == end
}

// ======================================================================
// Names
// ======================================================================

/// Walk a SAN extension value yielding each `dNSName`. `callback` returning
/// true stops the walk. Returns true if at least one `dNSName` was present.
fn walk_san_dns(
    cert: &[u8],
    start: usize,
    len: usize,
    callback: &mut impl FnMut(&[u8]) -> bool,
) -> bool {
    if len == 0 || cert[start] != TAG_SEQUENCE {
        return false;
    }
    let (s_start, s_len, _) = match der_tlv(cert, start) {
        Some(v) => v,
        None => return false,
    };
    let end = s_start + s_len;
    let mut pos = s_start;
    let mut any = false;
    while pos < end {
        let tag = cert[pos];
        let (c_start, c_len, total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => break,
        };
        if tag == TAG_SAN_DNS {
            any = true;
            if callback(&cert[c_start..c_start + c_len]) {
                return true;
            }
        }
        pos += total;
    }
    any
}

/// Walk a SAN extension value yielding each `uniformResourceIdentifier`.
/// `callback` returning true stops the walk. Returns true if at least one
/// URI was present.
fn walk_san_uri(
    cert: &[u8],
    start: usize,
    len: usize,
    callback: &mut impl FnMut(&[u8]) -> bool,
) -> bool {
    if len == 0 || cert[start] != TAG_SEQUENCE {
        return false;
    }
    let (s_start, s_len, _) = match der_tlv(cert, start) {
        Some(v) => v,
        None => return false,
    };
    let end = s_start + s_len;
    let mut pos = s_start;
    let mut any = false;
    while pos < end {
        let tag = cert[pos];
        let (c_start, c_len, total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => break,
        };
        if tag == TAG_SAN_URI {
            any = true;
            if callback(&cert[c_start..c_start + c_len]) {
                return true;
            }
        }
        pos += total;
    }
    any
}

impl X509Cert<'_> {
    /// Yield each `uniformResourceIdentifier` SAN in this certificate.
    ///
    /// `callback` returning true stops the walk. Returns true if at least one
    /// URI SAN was present.
    ///
    /// A method on the PARSED certificate, deliberately, and not a free
    /// function over raw DER. The identity in a SPIFFE leaf is only worth
    /// anything once the chain and profile have been validated, and a
    /// `extract_san_uris(cert_der, ..)` shape invites exactly the mistake of
    /// reading a name out of bytes nobody has verified. To get one of these
    /// you must already hold a `X509Cert`, and to trust what it says you must
    /// have put it through `verify_chain`.
    ///
    /// The `cert` argument is the same DER the certificate was parsed from.
    /// Extensions are held as offsets into it rather than as copies, because
    /// a module has no allocator to copy into — and because an extension's
    /// offsets must stay comparable with the buffer the signature covered.
    pub fn san_uris(&self, cert: &[u8], callback: &mut impl FnMut(&[u8]) -> bool) -> bool {
        if self.ext_len == 0 {
            return false;
        }
        match parse_extensions(cert, self.ext_off, self.ext_len).san {
            Some((start, len)) => walk_san_uri(cert, start, len, callback),
            None => false,
        }
    }
}

/// RFC 6125 §6.4.1 — case-insensitive ASCII match with optional
/// leftmost-label wildcard (`*.example.com`). Returns true on match.
pub fn dns_name_matches(presented: &[u8], expected: &[u8]) -> bool {
    if presented.is_empty() || expected.is_empty() {
        return false;
    }
    if presented[0] == b'*' && presented.len() >= 2 && presented[1] == b'.' {
        // Wildcard — match the rightmost portion of expected.
        let suffix = &presented[1..]; // ".example.com"
        if expected.len() <= suffix.len() {
            return false;
        }
        // Find first dot in expected; the leftmost label of expected
        // must be entirely covered by '*' (no partial wildcards).
        let mut dot = 0;
        while dot < expected.len() && expected[dot] != b'.' {
            dot += 1;
        }
        if dot == expected.len() {
            return false;
        }
        let exp_suffix = &expected[dot..];
        if exp_suffix.len() != suffix.len() {
            return false;
        }
        let mut i = 0;
        while i < suffix.len() {
            if ascii_lower(suffix[i]) != ascii_lower(exp_suffix[i]) {
                return false;
            }
            i += 1;
        }
        return true;
    }
    if presented.len() != expected.len() {
        return false;
    }
    let mut i = 0;
    while i < presented.len() {
        if ascii_lower(presented[i]) != ascii_lower(expected[i]) {
            return false;
        }
        i += 1;
    }
    true
}

fn ascii_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// True when `name` is a dotted-quad IPv4 literal. RFC 6066 §3 forbids one
/// in SNI, and an address is not a DNS identity.
pub fn is_ip_literal(name: &[u8]) -> bool {
    let mut labels = 0;
    let mut digits = 0;
    let mut value: u32 = 0;
    let mut i = 0;
    while i < name.len() {
        let b = name[i];
        if b.is_ascii_digit() {
            digits += 1;
            if digits > 3 {
                return false;
            }
            value = value * 10 + (b - b'0') as u32;
            if value > 255 {
                return false;
            }
        } else if b == b'.' {
            if digits == 0 {
                return false;
            }
            labels += 1;
            digits = 0;
            value = 0;
        } else {
            return false;
        }
        i += 1;
    }
    labels == 3 && digits > 0
}

// ======================================================================
// Signature verification
// ======================================================================

/// The ML-DSA parameter set a CERTIFICATE suite names.
///
/// The crossing between this module's suite registry and the primitive's
/// own naming is this one function, so certificate ids can be renumbered
/// without the assumption leaking into every call site.
#[must_use]
fn ml_dsa_set_for(cert_suite: u16) -> Option<MlDsaSet> {
    match cert_suite {
        suite::ML_DSA_44 => Some(MlDsaSet::MlDsa44),
        suite::ML_DSA_65 => Some(MlDsaSet::MlDsa65),
        suite::ML_DSA_87 => Some(MlDsaSet::MlDsa87),
        _ => None,
    }
}

/// Whether `key` is a well-formed public key for `suite`.
///
/// Suite-aware because what the key bytes MEAN depends on the suite: the
/// P-256 check is a curve-membership test, and running it over a lattice
/// key would be reinterpreting bytes — the exact confusion the suite
/// field exists to prevent.
#[must_use]
pub fn key_is_valid(suite: u16, key: &[u8]) -> bool {
    match suite {
        suite::ECDSA_P256_SHA256 => public_point_is_valid(key),
        suite::RSA_2048 | suite::RSA_3072 | suite::RSA_4096 => match rsa_public_key_parse(key) {
            Some(k) => rsa_key_suite_for_bits(rsa_public_key_bits(&k)) == suite,
            None => false,
        },
        suite::ML_DSA_44 | suite::ML_DSA_65 | suite::ML_DSA_87 => {
            // A lattice public key has no structure to check beyond its
            // length: every byte string of the right size decodes, and
            // whether it decodes to a key anyone holds is what the
            // signature check answers.
            key.len() == suite::max_public_key_len(suite)
        }
        _ => false,
    }
}

/// Verify a certificate's signature under its issuer's public key.
///
/// `issuer_key_suite` is what the issuer's OWN certificate said its key
/// is, and it must match the algorithm this certificate claims to be
/// signed with. Without that check an ML-DSA-87 signature could be
/// offered against a key its issuer published as ML-DSA-44 — the
/// signature would fail, but only by accident of length, and a suite
/// whose sizes happened to line up would not fail at all.
pub fn verify_cert_signature(
    cert_bytes: &[u8],
    issuer_key_suite: u16,
    issuer_pubkey: &[u8],
) -> bool {
    let cert = match parse_certificate(cert_bytes) {
        Some(c) => c,
        None => return false,
    };
    if !suite::key_signs(issuer_key_suite, cert.suite)
        || !key_is_valid(issuer_key_suite, issuer_pubkey)
    {
        return false;
    }
    match cert.suite {
        suite::ECDSA_P256_SHA256 => {
            if cert.sig_alg != OID_ECDSA_SHA256 {
                return false;
            }
            let tbs_hash = sha256(cert.tbs_raw);
            let raw_sig = match parse_der_signature(cert.signature) {
                Some(s) => s,
                None => return false,
            };
            ecdsa_verify(issuer_pubkey, &tbs_hash, &raw_sig)
        }
        suite::RSA_PKCS1_SHA256 | suite::RSA_PKCS1_SHA384 => {
            // The signature is the BIT STRING contents, the modulus width
            // exactly; the digest is of tbsCertificate under the hash the
            // signature suite names. The exponentiation runs whole here:
            // this is the host's and the vault's path, and the handshake on
            // a budgeted target verifies through its stepped job instead.
            let Some(key) = rsa_public_key_parse(issuer_pubkey) else {
                return false;
            };
            let mut job = RsaVerifyJob::new();
            if cert.suite == suite::RSA_PKCS1_SHA256 {
                let tbs_hash = sha256(cert.tbs_raw);
                rsa_pkcs1_v15_verify(&mut job, &key, RsaHash::Sha256, &tbs_hash, cert.signature)
            } else {
                let tbs_hash = sha384(cert.tbs_raw);
                rsa_pkcs1_v15_verify(&mut job, &key, RsaHash::Sha384, &tbs_hash, cert.signature)
            }
        }
        suite::ML_DSA_44 | suite::ML_DSA_65 | suite::ML_DSA_87 => {
            // The signature is the BIT STRING contents as they stand: no
            // DER wrapper, no digest step. FIPS 204's pure variant signs
            // the tbsCertificate bytes themselves, under the empty
            // context — a certificate is already domain-separated by
            // everything inside it.
            let Some(set) = ml_dsa_set_for(cert.suite) else {
                return false;
            };
            if cert.signature.len() != set.params().sig_len {
                return false;
            }
            // The workspace is a LOCAL: a position-independent module has
            // no `.bss` — its state arrives as a pointer from the kernel —
            // so a static is not available here at all. One workspace at
            // the widest dimensions rather than one per set, because a
            // chain may mix sets and a frame whose size does not depend on
            // which certificate arrived is the one that can be checked
            // against the module's stack. 13 KB, of the 64 KB it gets.
            let mut ws: VerifyWorkspace<L_MAX> = VerifyWorkspace::new();
            ml_dsa_verify(
                set,
                issuer_pubkey,
                &[],
                cert.tbs_raw,
                cert.signature,
                &mut ws,
            )
        }
        _ => false,
    }
}

fn pubkey_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

fn der_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    pubkey_eq(a, b)
}

// ======================================================================
// Constrained-path validation
// ======================================================================

/// The most certificates one Certificate message may carry.
pub const MAX_CHAIN_LEN: usize = 4;

/// Peer-authentication profiles. `PROFILE_NONE` is not a profile: it is
/// the absence of one, and every entry point refuses it.
pub const PROFILE_NONE: u8 = 0;
pub const PROFILE_PINNED: u8 = 1;
pub const PROFILE_CA_DNS: u8 = 2;
/// Chain to a CA, then match a URI SAN exactly.
///
/// The SPIFFE case. A SPIFFE ID is a URI and its comparison is byte
/// equality — none of `PROFILE_CA_DNS`'s wildcard or label rules apply,
/// and applying them to a URI would make `spiffe://a.b/x` match things it
/// must not. A separate profile rather than a flag, so a policy cannot be
/// written that asks for both name rules and gets whichever the code
/// checks first.
pub const PROFILE_CA_URI: u8 = 3;
pub const PROFILE_INSECURE_NO_VERIFY: u8 = 255;

/// Required extended key usage on the end entity.
pub const EKU_SERVER_AUTH: u8 = 0;
pub const EKU_CLIENT_AUTH: u8 = 1;

/// Everything the validator is allowed to consult. Held by value so the
/// caller cannot leave half of a policy behind: a policy with an anchor but
/// no name is refused, not silently downgraded.
pub struct ChainPolicy<'a> {
    pub profile: u8,
    /// DER of the configured anchor. Under `PROFILE_PINNED` this is the
    /// certificate whose subject public key is pinned; under
    /// `PROFILE_CA_DNS` it is the certificate authority.
    pub anchor_der: &'a [u8],
    /// Expected DNS name, for `PROFILE_CA_DNS`. Empty means "no name rule",
    /// which is the mTLS server case.
    pub expected_dns: &'a [u8],
    /// Expected URI SAN, for `PROFILE_CA_URI`. Compared as bytes: a URI is
    /// not a hostname and admits no wildcard, no case folding and no
    /// trailing-dot equivalence.
    ///
    /// Empty under `PROFILE_CA_URI` is a refusal, not "no name rule". A
    /// profile whose entire purpose is to match a name cannot be satisfied
    /// by a policy that names none.
    pub expected_uri: &'a [u8],
    /// Bitmask of permitted suites — `1 << suite_id`, see [`suite::mask`].
    ///
    /// Every certificate in the chain, the anchor included, must be in it.
    /// [`suite::IMPLEMENTED`] is the sane default; `0` permits nothing and
    /// is a valid, fail-closed way to say "not configured yet".
    pub allowed_suites: u32,
    /// Wall clock in seconds since the Unix epoch; 0 means the platform has
    /// no synchronised clock.
    pub now_unix_secs: u64,
    /// When true, a certificate is only acceptable inside its validity
    /// window and the absence of a clock is itself a failure.
    pub require_clock: bool,
    pub require_eku: u8,
}

/// Whether `cert`'s two suites are both permitted by `policy` and both
/// verifiable by this build.
///
/// Applied to every certificate including the anchor. An anchor exempted
/// from the suite rule would be a trust root the policy never examined,
/// which is the one certificate it least makes sense to skip.
fn check_suites(cert: &X509Cert<'_>, policy: &ChainPolicy<'_>) -> u32 {
    for s in [cert.suite, cert.key_suite] {
        if !suite::is_implemented(s) {
            return CERT_ERR_UNSUPPORTED_SUITE;
        }
        if policy.allowed_suites & suite::mask(s) == 0 {
            return CERT_ERR_UNSUPPORTED_SUITE;
        }
    }
    CERT_OK
}

/// Where the bytes of a deferred RSA link live: in the Certificate
/// message the peer sent, or in the configured anchor.
pub const LINK_IN_MESSAGE: u8 = 0;
pub const LINK_IN_ANCHOR: u8 = 1;

/// One signature the chain walk left for a stepped job — RSA, or ECDSA
/// P-256, which on the slowest target is the more expensive of the two:
/// the certificate it is over, the key that made it, and the suite. Offsets
/// rather than slices, because the job outlives the call that found them
/// and the message buffer is the only place the bytes are.
#[derive(Clone, Copy)]
pub struct DeferredLink {
    /// `LINK_IN_MESSAGE` for the subject certificate (always) and
    /// where the issuer key is read from.
    pub issuer_source: u8,
    /// The signature suite (`RSA_PKCS1_SHA256` or `RSA_PKCS1_SHA384`).
    pub sig_suite: u16,
    /// `tbsCertificate` of the subject, within the message.
    pub tbs_off: u16,
    pub tbs_len: u16,
    /// The signature's BIT STRING body, within the message.
    pub sig_off: u16,
    pub sig_len: u16,
    /// The issuer's `subjectPublicKey` body, within `issuer_source`.
    pub key_off: u16,
    pub key_len: u16,
}

impl DeferredLink {
    pub const EMPTY: DeferredLink = DeferredLink {
        issuer_source: LINK_IN_MESSAGE,
        sig_suite: 0,
        tbs_off: 0,
        tbs_len: 0,
        sig_off: 0,
        sig_len: 0,
        key_off: 0,
        key_len: 0,
    };
}

/// The links a walk deferred, in chain order.
pub struct DeferredLinks {
    pub links: [DeferredLink; MAX_CHAIN_LEN],
    pub len: u8,
    /// The next link to verify.
    pub next: u8,
}

impl DeferredLinks {
    pub const fn empty() -> Self {
        Self {
            links: [DeferredLink::EMPTY; MAX_CHAIN_LEN],
            len: 0,
            next: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }

    pub fn pending(&self) -> bool {
        self.next < self.len
    }
}

/// Offset of `inner` within `outer`, both borrowed from the same buffer.
fn span_of(outer: &[u8], inner: &[u8]) -> Option<(u16, u16)> {
    let base = outer.as_ptr() as usize;
    let at = inner.as_ptr() as usize;
    if at < base || at + inner.len() > base + outer.len() {
        return None;
    }
    let off = at - base;
    if off > u16::MAX as usize || inner.len() > u16::MAX as usize {
        return None;
    }
    Some((off as u16, inner.len() as u16))
}

/// What a link check may do with an RSA or ECDSA signature: verify it
/// now, or record it for a stepped job. ML-DSA is verified now either way.
struct LinkMode<'a> {
    message: &'a [u8],
    anchor: &'a [u8],
    deferred: Option<&'a mut DeferredLinks>,
}

impl LinkMode<'_> {
    /// Check `subject`'s signature under `issuer`, deferring an RSA one
    /// when the mode asks for it. `issuer_source` says where the issuer's
    /// bytes live.
    fn signature(
        &mut self,
        subject: &X509Cert<'_>,
        subject_der: &[u8],
        issuer: &X509Cert<'_>,
        issuer_source: u8,
    ) -> u32 {
        let steppable = matches!(
            subject.suite,
            suite::RSA_PKCS1_SHA256 | suite::RSA_PKCS1_SHA384 | suite::ECDSA_P256_SHA256
        );
        if !steppable || self.deferred.is_none() {
            return if verify_cert_signature(subject_der, issuer.key_suite, issuer.public_key) {
                CERT_OK
            } else {
                CERT_ERR_SIGNATURE
            };
        }
        // Everything the job will not re-derive is checked here: the key
        // is one that makes this signature, is well formed, and the
        // signature is the key's width.
        if !suite::key_signs(issuer.key_suite, subject.suite)
            || !key_is_valid(issuer.key_suite, issuer.public_key)
        {
            return CERT_ERR_SIGNATURE;
        }
        let issuer_bytes = if issuer_source == LINK_IN_ANCHOR {
            self.anchor
        } else {
            self.message
        };
        let (Some((tbs_off, tbs_len)), Some((sig_off, sig_len)), Some((key_off, key_len))) = (
            span_of(self.message, subject.tbs_raw),
            span_of(self.message, subject.signature),
            span_of(issuer_bytes, issuer.public_key),
        ) else {
            return CERT_ERR_MALFORMED;
        };
        let Some(d) = self.deferred.as_deref_mut() else {
            return CERT_ERR_SIGNATURE;
        };
        if d.len as usize >= MAX_CHAIN_LEN {
            return CERT_ERR_CHAIN_TOO_LONG;
        }
        d.links[d.len as usize] = DeferredLink {
            issuer_source,
            sig_suite: subject.suite,
            tbs_off,
            tbs_len,
            sig_off,
            sig_len,
            key_off,
            key_len,
        };
        d.len += 1;
        CERT_OK
    }
}

/// The bytes a deferred link names: `(tbs, signature, issuer key)`.
pub fn deferred_link_bytes<'a>(
    link: &DeferredLink,
    message: &'a [u8],
    anchor: &'a [u8],
) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
    let issuer_bytes = if link.issuer_source == LINK_IN_ANCHOR {
        anchor
    } else {
        message
    };
    Some((
        message.get(link.tbs_off as usize..(link.tbs_off + link.tbs_len) as usize)?,
        message.get(link.sig_off as usize..(link.sig_off + link.sig_len) as usize)?,
        issuer_bytes.get(link.key_off as usize..(link.key_off + link.key_len) as usize)?,
    ))
}

/// Verify one deferred link in full, for a caller with no step budget.
pub fn verify_deferred_link(link: &DeferredLink, message: &[u8], anchor: &[u8]) -> bool {
    let Some((tbs, sig, key)) = deferred_link_bytes(link, message, anchor) else {
        return false;
    };
    match link.sig_suite {
        suite::ECDSA_P256_SHA256 => match parse_der_signature(sig) {
            Some(raw) => ecdsa_verify(key, &sha256(tbs), &raw),
            None => false,
        },
        suite::RSA_PKCS1_SHA256 | suite::RSA_PKCS1_SHA384 => {
            let Some(key) = rsa_public_key_parse(key) else {
                return false;
            };
            let mut job = RsaVerifyJob::new();
            if link.sig_suite == suite::RSA_PKCS1_SHA256 {
                rsa_pkcs1_v15_verify(&mut job, &key, RsaHash::Sha256, &sha256(tbs), sig)
            } else {
                rsa_pkcs1_v15_verify(&mut job, &key, RsaHash::Sha384, &sha384(tbs), sig)
            }
        }
        _ => false,
    }
}

/// Whether a deferred link's recovered encoded message is the encoding of
/// its subject's digest: the check a stepped job ends with.
pub fn deferred_link_rsa_check(link: &DeferredLink, message: &[u8], em: &[u8]) -> bool {
    let Some(tbs) = message.get(link.tbs_off as usize..(link.tbs_off + link.tbs_len) as usize)
    else {
        return false;
    };
    match link.sig_suite {
        suite::RSA_PKCS1_SHA256 => rsa_pkcs1_v15_check(RsaHash::Sha256, &sha256(tbs), em),
        suite::RSA_PKCS1_SHA384 => rsa_pkcs1_v15_check(RsaHash::Sha384, &sha384(tbs), em),
        _ => false,
    }
}

/// Validate a peer's Certificate message under `policy`. Returns
/// [`CERT_OK`] or the reason code the failure is classified as.
///
/// This is the only certificate-acceptance path. The chain is built exactly
/// once, leaf first, from the list the peer sent, in the order it sent it:
/// no alternative path is searched, so a peer cannot make the validator try
/// again with a different arrangement of the same certificates.
pub fn verify_chain(cert_msg_body: &[u8], policy: &ChainPolicy<'_>) -> u32 {
    verify_chain_with(cert_msg_body, policy, None)
}

/// As [`verify_chain`], but with `deferred` given, every RSA-signed link
/// is recorded there instead of verified, and [`CERT_OK`] means "accepted
/// once every deferred link verifies". Everything else — shape, names,
/// policy, lifetimes, and every non-RSA signature — is decided here, so a
/// caller stepping the deferred links has nothing left to check but them.
pub fn verify_chain_with(
    cert_msg_body: &[u8],
    policy: &ChainPolicy<'_>,
    deferred: Option<&mut DeferredLinks>,
) -> u32 {
    let mut mode = LinkMode {
        message: cert_msg_body,
        anchor: policy.anchor_der,
        deferred,
    };
    if let Some(d) = mode.deferred.as_deref_mut() {
        d.clear();
    }
    if policy.profile == PROFILE_NONE {
        return CERT_ERR_NO_PROFILE;
    }
    if policy.profile == PROFILE_INSECURE_NO_VERIFY {
        return CERT_OK;
    }

    let mut chain: [&[u8]; MAX_CHAIN_LEN] = [&[]; MAX_CHAIN_LEN];
    let n = match parse_cert_chain(cert_msg_body, &mut chain) {
        Ok(n) => n,
        Err(code) => return code,
    };
    if n == 0 {
        return CERT_ERR_EMPTY_CHAIN;
    }

    let anchor = match parse_certificate(policy.anchor_der) {
        Some(c) => c,
        None => return CERT_ERR_ANCHOR_MALFORMED,
    };
    let leaf_der = chain[0];
    let leaf = match parse_certificate(leaf_der) {
        Some(c) => c,
        None => return CERT_ERR_MALFORMED,
    };
    // The suite gate runs before anything reads the key, because what the
    // key bytes MEAN depends on the suite. `key_is_valid` dispatches on
    // it for that reason: the P-256 branch is a curve-membership test,
    // and running it over a lattice key would be reinterpreting bytes,
    // which is the thing the suite field exists to stop.
    let rc = check_suites(&leaf, policy);
    if rc != CERT_OK {
        return rc;
    }
    let rc = check_suites(&anchor, policy);
    if rc != CERT_OK {
        return rc;
    }
    if !key_is_valid(leaf.key_suite, leaf.public_key) {
        return CERT_ERR_BAD_KEY;
    }

    if policy.profile == PROFILE_PINNED {
        // The pin is the whole policy: no chain, no name, no lifetime.
        if !pubkey_eq(leaf.public_key, anchor.public_key) {
            return CERT_ERR_PIN_MISMATCH;
        }
        return CERT_OK;
    }

    // --- leaf rules -----------------------------------------------------
    let leaf_exts = parse_extensions(leaf_der, leaf.ext_off, leaf.ext_len);
    if leaf_exts.malformed {
        return CERT_ERR_MALFORMED;
    }
    if leaf_exts.unknown_critical {
        return CERT_ERR_CRITICAL_EXT;
    }
    if leaf_exts.bc_present && leaf_exts.bc_is_ca {
        return CERT_ERR_LEAF_IS_CA;
    }
    if leaf_exts.ku_present && leaf_exts.ku_bits & KU_DIGITAL_SIGNATURE == 0 {
        return CERT_ERR_LEAF_KEY_USAGE;
    }
    // Absent extended key usage is a refusal, not a permission: a
    // certificate that does not say what it is for is not authorised for
    // this purpose.
    let eku_ok = match policy.require_eku {
        EKU_CLIENT_AUTH => leaf_exts.eku_client_auth,
        _ => leaf_exts.eku_server_auth,
    };
    if !leaf_exts.eku_present || !eku_ok {
        return CERT_ERR_LEAF_EKU;
    }
    let rc = check_validity(&leaf, policy);
    if rc != CERT_OK {
        return rc;
    }

    // --- path -----------------------------------------------------------
    let mut cur = leaf;
    let mut cur_der = leaf_der;
    let mut anchored = pubkey_eq(cur.public_key, anchor.public_key)
        && der_bytes_eq(cur.subject_raw, anchor.subject_raw);
    let mut depth = 0usize; // certificates between the issuer and the leaf
    let mut i = 1;
    while i < n && !anchored {
        let issuer_der = chain[i];
        let issuer = match parse_certificate(issuer_der) {
            Some(c) => c,
            None => return CERT_ERR_MALFORMED,
        };
        let rc = check_suites(&issuer, policy);
        if rc != CERT_OK {
            return rc;
        }
        if !key_is_valid(issuer.key_suite, issuer.public_key) {
            return CERT_ERR_BAD_KEY;
        }
        // The issuer's KEY is what verifies `cur`'s signature, so the
        // strength of `cur` is capped by it. Compared against the key
        // being vouched for, not against `cur`'s own signature suite —
        // those are the same value here, but they will not be once a
        // chain can mix suites, and the key is the one that matters.
        if suite::is_downgrade(issuer.key_suite, cur.key_suite) {
            return CERT_ERR_DOWNGRADE;
        }
        let rc = check_issuer(&issuer, issuer_der, &cur, cur_der, policy, depth, &mut mode);
        if rc != CERT_OK {
            return rc;
        }
        anchored = pubkey_eq(issuer.public_key, anchor.public_key)
            && der_bytes_eq(issuer.subject_raw, anchor.subject_raw);
        cur = issuer;
        cur_der = issuer_der;
        depth += 1;
        i += 1;
    }

    if !anchored {
        // The peer did not send the anchor; the top-most certificate it did
        // send must have been issued by it.
        if !der_bytes_eq(cur.issuer_raw, anchor.subject_raw) {
            return CERT_ERR_NO_ANCHOR;
        }
        let rc = check_ca_shape(&anchor, policy.anchor_der, depth);
        if rc != CERT_OK {
            return rc;
        }
        if suite::is_downgrade(anchor.key_suite, cur.key_suite) {
            return CERT_ERR_DOWNGRADE;
        }
        let rc = check_validity(&anchor, policy);
        if rc != CERT_OK {
            return rc;
        }
        let rc = mode.signature(&cur, cur_der, &anchor, LINK_IN_ANCHOR);
        if rc != CERT_OK {
            return rc;
        }
    }

    // --- name rule ------------------------------------------------------
    if policy.profile == PROFILE_CA_URI {
        // A URI SAN, matched byte-for-byte. An empty expectation cannot be
        // satisfied and is refused rather than treated as "match
        // anything" — under this profile the name IS the authorisation.
        if policy.expected_uri.is_empty() {
            return CERT_ERR_NAME_ABSENT;
        }
        let (san_start, san_len) = match leaf_exts.san {
            Some(v) => v,
            None => return CERT_ERR_NAME_ABSENT,
        };
        let mut matched = false;
        let any = walk_san_uri(leaf_der, san_start, san_len, &mut |uri| {
            if uri == policy.expected_uri {
                matched = true;
                return true;
            }
            false
        });
        if !any {
            return CERT_ERR_NAME_ABSENT;
        }
        if !matched {
            return CERT_ERR_NAME_MISMATCH;
        }
    } else if !policy.expected_dns.is_empty() {
        let (san_start, san_len) = match leaf_exts.san {
            Some(v) => v,
            None => return CERT_ERR_NAME_ABSENT,
        };
        let mut matched = false;
        let any = walk_san_dns(leaf_der, san_start, san_len, &mut |dns| {
            if dns_name_matches(dns, policy.expected_dns) {
                matched = true;
                return true;
            }
            false
        });
        if !any {
            return CERT_ERR_NAME_ABSENT;
        }
        if !matched {
            return CERT_ERR_NAME_MISMATCH;
        }
    }

    CERT_OK
}

/// Check `issuer` may issue `subject`, and that it did.
fn check_issuer(
    issuer: &X509Cert<'_>,
    issuer_der: &[u8],
    subject: &X509Cert<'_>,
    subject_der: &[u8],
    policy: &ChainPolicy<'_>,
    depth: usize,
    mode: &mut LinkMode<'_>,
) -> u32 {
    if !der_bytes_eq(subject.issuer_raw, issuer.subject_raw) {
        return CERT_ERR_ISSUER_MISMATCH;
    }
    let rc = check_ca_shape(issuer, issuer_der, depth);
    if rc != CERT_OK {
        return rc;
    }
    let rc = check_validity(issuer, policy);
    if rc != CERT_OK {
        return rc;
    }
    mode.signature(subject, subject_der, issuer, LINK_IN_MESSAGE)
}

/// A certificate used as an issuer must say it is one, must be permitted to
/// sign certificates, and must not have constrained the path shorter than
/// the one being built.
fn check_ca_shape(cert: &X509Cert<'_>, der: &[u8], depth: usize) -> u32 {
    let exts = parse_extensions(der, cert.ext_off, cert.ext_len);
    if exts.malformed {
        return CERT_ERR_MALFORMED;
    }
    if exts.unknown_critical {
        return CERT_ERR_CRITICAL_EXT;
    }
    if !exts.bc_present || !exts.bc_is_ca {
        return CERT_ERR_NOT_CA;
    }
    // Absent keyUsage on a CA is a refusal, not a permission.
    if !exts.ku_present || exts.ku_bits & KU_KEY_CERT_SIGN == 0 {
        return CERT_ERR_NO_KEY_CERT_SIGN;
    }
    if let Some(limit) = exts.bc_path_len {
        if depth as u32 > limit {
            return CERT_ERR_PATH_LEN;
        }
    }
    CERT_OK
}

/// Lifetime, per the configured clock posture.
fn check_validity(cert: &X509Cert<'_>, policy: &ChainPolicy<'_>) -> u32 {
    if !policy.require_clock {
        return CERT_OK;
    }
    if policy.now_unix_secs == 0 {
        return CERT_ERR_NO_CLOCK;
    }
    if policy.now_unix_secs < cert.not_before {
        return CERT_ERR_NOT_YET_VALID;
    }
    if policy.now_unix_secs > cert.not_after {
        return CERT_ERR_EXPIRED;
    }
    CERT_OK
}

/// Parse a Certificate handshake message body (RFC 8446 §4.4.2) into raw
/// certificate DER slices, leaf first. Returns the count, or a reason code.
pub fn parse_cert_chain<'a>(
    body: &'a [u8],
    out: &mut [&'a [u8]; MAX_CHAIN_LEN],
) -> Result<usize, u32> {
    if body.len() < 4 {
        return Err(CERT_ERR_MSG_MALFORMED);
    }
    let ctx_len = body[0] as usize;
    if 1 + ctx_len + 3 > body.len() {
        return Err(CERT_ERR_MSG_MALFORMED);
    }
    let mut pos = 1 + ctx_len;
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | (body[pos + 2] as usize);
    pos += 3;
    let list_end = pos + list_len;
    if list_end > body.len() {
        return Err(CERT_ERR_MSG_MALFORMED);
    }
    let mut n = 0;
    while pos + 3 <= list_end {
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if pos + cert_len + 2 > list_end {
            return Err(CERT_ERR_MSG_MALFORMED);
        }
        if n == MAX_CHAIN_LEN {
            return Err(CERT_ERR_CHAIN_TOO_LONG);
        }
        out[n] = &body[pos..pos + cert_len];
        n += 1;
        pos += cert_len;
        let ext_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
        pos += 2 + ext_len;
        if pos > list_end {
            return Err(CERT_ERR_MSG_MALFORMED);
        }
    }
    if pos != list_end {
        return Err(CERT_ERR_MSG_MALFORMED);
    }
    Ok(n)
}

/// Validate a server chain against a CA anchor and an expected hostname.
/// Callers holding no clock policy of their own get the `ca_dns` profile
/// with validity unchecked.
pub fn verify_cert_chain(
    cert_msg_body: &[u8],
    trust_anchor_der: &[u8],
    expected_hostname: &[u8],
) -> u32 {
    verify_cert_chain_with(cert_msg_body, trust_anchor_der, expected_hostname, None)
}

/// As [`verify_cert_chain`], deferring RSA links (see [`verify_chain_with`]).
pub fn verify_cert_chain_with(
    cert_msg_body: &[u8],
    trust_anchor_der: &[u8],
    expected_hostname: &[u8],
    deferred: Option<&mut DeferredLinks>,
) -> u32 {
    verify_chain_with(
        cert_msg_body,
        &ChainPolicy {
            profile: PROFILE_CA_DNS,
            anchor_der: trust_anchor_der,
            expected_dns: expected_hostname,
            expected_uri: &[],
            allowed_suites: suite::IMPLEMENTED,
            now_unix_secs: 0,
            require_clock: false,
            require_eku: EKU_SERVER_AUTH,
        },
        deferred,
    )
}

/// Extract a 32-byte P-256 scalar from a DER-encoded ECPrivateKey
/// (SEC1 §C.4) or PKCS#8 PrivateKeyInfo wrapping it. Used by both
/// the TLS module (server CertificateVerify) and the DTLS module.
/// Writes the scalar bytes into `out`; on parse failure leaves `out`
/// untouched.
///
/// # Safety
/// `der` is a kernel-owned blob; the body bounds-checks every read
/// against `der.len()` before indexing.
pub unsafe fn extract_ec_private_key(der: &[u8], out: &mut [u8; 32]) {
    if der.len() < 4 {
        return;
    }
    if der[0] != 0x30 {
        return;
    }
    let (seq_start, _seq_len, _) = match der_tlv(der, 0) {
        Some(v) => v,
        None => return,
    };

    let mut pos = seq_start;
    if pos >= der.len() || der[pos] != 0x02 {
        return;
    }
    let (int_start, int_len, int_total) = match der_tlv(der, pos) {
        Some(v) => v,
        None => return,
    };
    let version = if int_len == 1 { der[int_start] } else { 0xFF };
    pos += int_total;

    if version == 1 {
        // SEC1 ECPrivateKey: OCTET STRING with the private key.
        if pos < der.len() && der[pos] == 0x04 {
            let (os_start, os_len, _) = match der_tlv(der, pos) {
                Some(v) => v,
                None => return,
            };
            if os_len == 32 && os_start + 32 <= der.len() {
                core::ptr::copy_nonoverlapping(der.as_ptr().add(os_start), out.as_mut_ptr(), 32);
            }
        }
    } else if version == 0 {
        // PKCS#8: skip AlgorithmIdentifier, then OCTET STRING with
        // the SEC1 ECPrivateKey nested inside.
        if pos < der.len() && der[pos] == 0x30 {
            let (_, _, alg_total) = match der_tlv(der, pos) {
                Some(v) => v,
                None => return,
            };
            pos += alg_total;
        }
        if pos < der.len() && der[pos] == 0x04 {
            let (inner_start, inner_len, _) = match der_tlv(der, pos) {
                Some(v) => v,
                None => return,
            };
            let inner = &der[inner_start..inner_start + inner_len];
            extract_ec_private_key(inner, out);
        }
    }
}
