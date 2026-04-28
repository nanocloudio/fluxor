// Minimal X.509 DER parser for TLS 1.3
// Extracts: TBSCertificate, SubjectPublicKeyInfo, SAN extension, SPIFFE URIs
// Pure Rust, no_std, no heap

/// DER tag types
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_3: u8 = 0xA3;
const TAG_CONTEXT_6: u8 = 0x86; // uniformResourceIdentifier in SAN

/// OID for SubjectAltName: 2.5.29.17
const OID_SAN: [u8; 3] = [0x55, 0x1D, 0x11];

/// OID for ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBKEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// OID for prime256v1 (P-256): 1.2.840.10045.3.1.7
const OID_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// OID for ecdsa-with-SHA256: 1.2.840.10045.4.3.2
const OID_ECDSA_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// Parse DER length field. Returns (length, bytes_consumed).
fn der_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() { return None; }
    let first = data[pos];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        if pos + 1 >= data.len() { return None; }
        Some((data[pos + 1] as usize, 2))
    } else if first == 0x82 {
        if pos + 2 >= data.len() { return None; }
        let len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        Some((len, 3))
    } else if first == 0x83 {
        if pos + 3 >= data.len() { return None; }
        let len = ((data[pos + 1] as usize) << 16) | ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        Some((len, 4))
    } else {
        None
    }
}

/// Parse DER tag+length, return (content_start, content_length, total_consumed)
fn der_tlv(data: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    if pos >= data.len() { return None; }
    let _tag = data[pos];
    let (len, len_bytes) = der_length(data, pos + 1)?;
    let content_start = pos + 1 + len_bytes;
    if content_start + len > data.len() { return None; }
    Some((content_start, len, 1 + len_bytes + len))
}

/// X.509 certificate parsed fields
pub struct X509Cert<'a> {
    /// Raw TBSCertificate (for signature verification)
    pub tbs_raw: &'a [u8],
    /// Subject public key (uncompressed point for EC)
    pub public_key: &'a [u8],
    /// Signature algorithm OID bytes
    pub sig_alg: &'a [u8],
    /// Signature value bytes (DER-encoded for ECDSA)
    pub signature: &'a [u8],
}

/// Parse X.509 DER certificate
pub fn parse_certificate(cert: &[u8]) -> Option<X509Cert<'_>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    if cert.len() < 10 { return None; }
    if cert[0] != TAG_SEQUENCE { return None; }
    let (cert_start, _cert_len, _) = der_tlv(cert, 0)?;

    // Parse TBSCertificate
    let tbs_tag_pos = cert_start;
    if cert[tbs_tag_pos] != TAG_SEQUENCE { return None; }
    let (tbs_start, tbs_len, tbs_total) = der_tlv(cert, tbs_tag_pos)?;
    let tbs_raw = &cert[tbs_tag_pos..tbs_tag_pos + tbs_total];

    // Parse signatureAlgorithm
    let sig_alg_pos = tbs_tag_pos + tbs_total;
    if sig_alg_pos >= cert.len() { return None; }
    let (_sa_start, _sa_len, sa_total) = der_tlv(cert, sig_alg_pos)?;
    let sig_alg = extract_oid(cert, sig_alg_pos)?;

    // Parse signatureValue (BIT STRING)
    let sig_pos = sig_alg_pos + sa_total;
    if sig_pos >= cert.len() || cert[sig_pos] != TAG_BIT_STRING { return None; }
    let (sig_start, sig_len, _) = der_tlv(cert, sig_pos)?;
    // Skip unused bits byte
    let signature = if sig_len > 1 { &cert[sig_start + 1..sig_start + sig_len] } else { &[] };

    // Extract public key from TBSCertificate
    let public_key = extract_subject_pubkey(cert, tbs_start, tbs_len)?;

    Some(X509Cert {
        tbs_raw,
        public_key,
        sig_alg,
        signature,
    })
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

/// Extract SubjectPublicKeyInfo from TBSCertificate
fn extract_subject_pubkey(cert: &[u8], tbs_start: usize, tbs_len: usize) -> Option<&[u8]> {
    let mut pos = tbs_start;
    let end = tbs_start + tbs_len;
    let mut field_idx = 0;

    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = der_tlv(cert, pos)?;

        // TBSCertificate fields:
        // [0] version (OPTIONAL, context 0)
        // serialNumber INTEGER
        // signature AlgorithmIdentifier
        // issuer Name
        // validity Validity
        // subject Name
        // subjectPublicKeyInfo SubjectPublicKeyInfo
        match field_idx {
            0 if tag == TAG_CONTEXT_0 => {
                // version field (optional context tag)
                pos += total;
                field_idx += 1;
                continue;
            }
            6 | 7 => {
                // SubjectPublicKeyInfo (field 6 if version present, 7th item)
                if tag == TAG_SEQUENCE {
                    // Check it contains ecPublicKey OID
                    return extract_ec_pubkey(cert, content_start, content_len);
                }
            }
            _ => {}
        }

        pos += total;
        field_idx += 1;
    }
    None
}

/// Extract EC public key bytes from SubjectPublicKeyInfo
fn extract_ec_pubkey(cert: &[u8], spki_start: usize, spki_len: usize) -> Option<&[u8]> {
    let mut pos = spki_start;
    let end = spki_start + spki_len;

    // AlgorithmIdentifier SEQUENCE
    if pos >= end || cert[pos] != TAG_SEQUENCE { return None; }
    let (_, _, alg_total) = der_tlv(cert, pos)?;
    pos += alg_total;

    // subjectPublicKey BIT STRING
    if pos >= end || cert[pos] != TAG_BIT_STRING { return None; }
    let (bs_start, bs_len, _) = der_tlv(cert, pos)?;
    if bs_len < 2 { return None; }
    // Skip unused bits byte
    let key_bytes = &cert[bs_start + 1..bs_start + bs_len];
    Some(key_bytes)
}

/// Extract SAN extension URIs from a DER certificate
/// Returns iterator-like: calls callback for each URI found
pub fn extract_san_uris(cert: &[u8], mut callback: impl FnMut(&[u8]) -> bool) -> bool {
    // Parse cert to find TBSCertificate
    if cert.len() < 10 || cert[0] != TAG_SEQUENCE { return false; }
    let (cert_start, _, _) = match der_tlv(cert, 0) { Some(v) => v, None => return false };

    // Find TBSCertificate
    let (tbs_start, tbs_len, _) = match der_tlv(cert, cert_start) { Some(v) => v, None => return false };

    // Walk TBSCertificate to find extensions [3]
    let mut pos = tbs_start;
    let end = tbs_start + tbs_len;
    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = match der_tlv(cert, pos) { Some(v) => v, None => return false };

        if tag == TAG_CONTEXT_3 {
            // extensions [3] EXPLICIT SEQUENCE OF Extension
            return walk_extensions_for_san(cert, content_start, content_len, &mut callback);
        }
        pos += total;
    }
    false
}

fn walk_extensions_for_san(cert: &[u8], ext_start: usize, ext_len: usize, callback: &mut impl FnMut(&[u8]) -> bool) -> bool {
    // Extensions is a SEQUENCE of Extension
    if cert[ext_start] != TAG_SEQUENCE { return false; }
    let (seq_start, seq_len, _) = match der_tlv(cert, ext_start) { Some(v) => v, None => return false };

    let mut pos = seq_start;
    let end = seq_start + seq_len;
    while pos < end {
        // Each Extension is SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        if cert[pos] != TAG_SEQUENCE { break; }
        let (ext_content_start, ext_content_len, ext_total) = match der_tlv(cert, pos) { Some(v) => v, None => break };

        // Check OID
        let mut inner_pos = ext_content_start;
        let inner_end = ext_content_start + ext_content_len;
        if inner_pos < inner_end && cert[inner_pos] == TAG_OID {
            let (oid_start, oid_len, oid_total) = match der_tlv(cert, inner_pos) { Some(v) => v, None => break };

            if oid_len == OID_SAN.len() && &cert[oid_start..oid_start + oid_len] == &OID_SAN {
                // Found SAN extension — parse extnValue
                inner_pos += oid_total;
                // Skip optional BOOLEAN (critical)
                if inner_pos < inner_end && cert[inner_pos] == 0x01 {
                    let (_, _, bool_total) = match der_tlv(cert, inner_pos) { Some(v) => v, None => break };
                    inner_pos += bool_total;
                }
                // OCTET STRING wrapping the SAN value
                if inner_pos < inner_end && cert[inner_pos] == TAG_OCTET_STRING {
                    let (os_start, os_len, _) = match der_tlv(cert, inner_pos) { Some(v) => v, None => break };
                    return parse_san_value(cert, os_start, os_len, callback);
                }
            }
        }

        pos += ext_total;
    }
    false
}

fn parse_san_value(cert: &[u8], san_start: usize, san_len: usize, callback: &mut impl FnMut(&[u8]) -> bool) -> bool {
    // GeneralNames ::= SEQUENCE OF GeneralName
    if cert[san_start] != TAG_SEQUENCE { return false; }
    let (seq_start, seq_len, _) = match der_tlv(cert, san_start) { Some(v) => v, None => return false };

    let mut pos = seq_start;
    let end = seq_start + seq_len;
    let mut found = false;
    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = match der_tlv(cert, pos) { Some(v) => v, None => break };

        if tag == TAG_CONTEXT_6 {
            // uniformResourceIdentifier [6] IA5String
            let uri = &cert[content_start..content_start + content_len];
            if callback(uri) {
                found = true;
            }
        }
        pos += total;
    }
    found
}

/// Check if URI matches SPIFFE pattern: spiffe://{trust_domain}/...
pub fn is_spiffe_match(uri: &[u8], trust_domain: &[u8]) -> bool {
    let prefix = b"spiffe://";
    if uri.len() < prefix.len() + trust_domain.len() { return false; }

    // Check "spiffe://" prefix
    let mut i = 0;
    while i < prefix.len() {
        if uri[i] != prefix[i] { return false; }
        i += 1;
    }

    // Check trust domain
    let mut j = 0;
    while j < trust_domain.len() {
        if i + j >= uri.len() { return false; }
        if uri[i + j] != trust_domain[j] { return false; }
        j += 1;
    }

    // Must be followed by '/' or end of string
    let after = i + j;
    after == uri.len() || (after < uri.len() && uri[after] == b'/')
}

/// Verify ECDSA-SHA256 signature on a certificate
pub fn verify_cert_signature(cert_bytes: &[u8], issuer_pubkey: &[u8]) -> bool {
    let cert = match parse_certificate(cert_bytes) {
        Some(c) => c,
        None => return false,
    };

    // Check signature algorithm is ECDSA-SHA256
    if cert.sig_alg != OID_ECDSA_SHA256 {
        return false;
    }

    // Hash TBSCertificate
    let tbs_hash = sha256(cert.tbs_raw);

    // Parse DER signature
    let raw_sig = match parse_der_signature(cert.signature) {
        Some(s) => s,
        None => return false,
    };

    // Verify
    ecdsa_verify(issuer_pubkey, &tbs_hash, &raw_sig)
}

// ----------------------------------------------------------------------
// SAN dNSName + Subject CN extraction (RFC 5280 §4.2.1.6 + §4.1.2.6)
// ----------------------------------------------------------------------

const TAG_CONTEXT_2: u8 = 0x82; // dNSName in SAN GeneralName

/// OID for commonName (CN): 2.5.4.3
const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];

const TAG_PRINTABLESTRING: u8 = 0x13;
const TAG_UTF8STRING: u8 = 0x0C;
const TAG_IA5STRING: u8 = 0x16;

/// Walk the SAN extension yielding each dNSName. Returns true if at
/// least one dNSName was visited.
pub fn extract_san_dns(cert: &[u8], mut callback: impl FnMut(&[u8]) -> bool) -> bool {
    if cert.len() < 10 || cert[0] != TAG_SEQUENCE {
        return false;
    }
    let (cert_start, _, _) = match der_tlv(cert, 0) {
        Some(v) => v,
        None => return false,
    };
    let (tbs_start, tbs_len, _) = match der_tlv(cert, cert_start) {
        Some(v) => v,
        None => return false,
    };
    let mut pos = tbs_start;
    let end = tbs_start + tbs_len;
    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => return false,
        };
        if tag == TAG_CONTEXT_3 {
            return walk_extensions_for_san_dns(cert, content_start, content_len, &mut callback);
        }
        pos += total;
    }
    false
}

fn walk_extensions_for_san_dns(
    cert: &[u8],
    ext_start: usize,
    _ext_len: usize,
    callback: &mut impl FnMut(&[u8]) -> bool,
) -> bool {
    if cert[ext_start] != TAG_SEQUENCE {
        return false;
    }
    let (seq_start, seq_len, _) = match der_tlv(cert, ext_start) {
        Some(v) => v,
        None => return false,
    };
    let mut pos = seq_start;
    let end = seq_start + seq_len;
    while pos < end {
        if cert[pos] != TAG_SEQUENCE {
            break;
        }
        let (ec_start, ec_len, ec_total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => break,
        };
        let mut inner = ec_start;
        let inner_end = ec_start + ec_len;
        if inner < inner_end && cert[inner] == TAG_OID {
            let (oid_start, oid_len, oid_total) = match der_tlv(cert, inner) {
                Some(v) => v,
                None => break,
            };
            if oid_len == OID_SAN.len()
                && cert[oid_start..oid_start + oid_len] == OID_SAN
            {
                inner += oid_total;
                if inner < inner_end && cert[inner] == 0x01 {
                    let (_, _, b_total) = match der_tlv(cert, inner) {
                        Some(v) => v,
                        None => break,
                    };
                    inner += b_total;
                }
                if inner < inner_end && cert[inner] == TAG_OCTET_STRING {
                    let (os_start, os_len, _) = match der_tlv(cert, inner) {
                        Some(v) => v,
                        None => break,
                    };
                    return parse_san_dns_value(cert, os_start, os_len, callback);
                }
            }
        }
        pos += ec_total;
    }
    false
}

fn parse_san_dns_value(
    cert: &[u8],
    san_start: usize,
    _san_len: usize,
    callback: &mut impl FnMut(&[u8]) -> bool,
) -> bool {
    if cert[san_start] != TAG_SEQUENCE {
        return false;
    }
    let (seq_start, seq_len, _) = match der_tlv(cert, san_start) {
        Some(v) => v,
        None => return false,
    };
    let mut pos = seq_start;
    let end = seq_start + seq_len;
    let mut found = false;
    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = match der_tlv(cert, pos) {
            Some(v) => v,
            None => break,
        };
        if tag == TAG_CONTEXT_2 {
            let dns = &cert[content_start..content_start + content_len];
            if callback(dns) {
                found = true;
            }
        }
        pos += total;
    }
    found
}

/// Extract the Subject DN's commonName attribute. RFC 6125 §6.4.4
/// allows falling back to CN when SAN is absent (deprecated for new
/// certs but still common with self-signed). Returns the CN bytes
/// (UTF8String / PrintableString / IA5String).
pub fn extract_subject_cn(cert: &[u8]) -> Option<&[u8]> {
    if cert.len() < 10 || cert[0] != TAG_SEQUENCE {
        return None;
    }
    let (cert_start, _, _) = der_tlv(cert, 0)?;
    let (tbs_start, tbs_len, _) = der_tlv(cert, cert_start)?;
    let mut pos = tbs_start;
    let end = tbs_start + tbs_len;
    let mut field_idx = 0;
    while pos < end {
        let tag = cert[pos];
        let (content_start, content_len, total) = der_tlv(cert, pos)?;
        match field_idx {
            0 if tag == TAG_CONTEXT_0 => {
                pos += total;
                field_idx += 1;
                continue;
            }
            // Field 5 = subject (after version[0], serial, sigAlg,
            // issuer, validity).
            5 if tag == TAG_SEQUENCE => {
                return walk_rdn_for_cn(cert, content_start, content_len);
            }
            _ => {}
        }
        pos += total;
        field_idx += 1;
    }
    None
}

fn walk_rdn_for_cn(cert: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let mut pos = start;
    let end = start + len;
    while pos < end {
        if cert[pos] != TAG_SET {
            break;
        }
        let (set_start, set_len, set_total) = der_tlv(cert, pos)?;
        let (av_start, av_len, _) = der_tlv(cert, set_start)?;
        let _ = av_len;
        let _ = set_len;
        let mut inner = av_start;
        let inner_end = av_start + av_len;
        if inner < inner_end && cert[inner] == TAG_OID {
            let (oid_start, oid_len, oid_total) = der_tlv(cert, inner)?;
            if oid_len == OID_CN.len()
                && cert[oid_start..oid_start + oid_len] == OID_CN
            {
                inner += oid_total;
                if inner < inner_end {
                    let val_tag = cert[inner];
                    if val_tag == TAG_PRINTABLESTRING
                        || val_tag == TAG_UTF8STRING
                        || val_tag == TAG_IA5STRING
                    {
                        let (vs, vl, _) = der_tlv(cert, inner)?;
                        return Some(&cert[vs..vs + vl]);
                    }
                }
            }
        }
        pos += set_total;
    }
    None
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
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ----------------------------------------------------------------------
// Certificate-message chain walker (TLS 1.3 §4.4.2)
// ----------------------------------------------------------------------

pub const MAX_CHAIN_LEN: usize = 4;

/// Parse a Certificate handshake message body (with the 1-byte
/// certificate_request_context length prefix already at offset 0).
/// Stores raw cert DER slices into `out` up to `out.len()` entries.
/// Returns the number of certs found, or 0 on parse failure.
pub fn parse_cert_chain<'a>(body: &'a [u8], out: &mut [&'a [u8]; MAX_CHAIN_LEN]) -> usize {
    if body.len() < 4 {
        return 0;
    }
    let ctx_len = body[0] as usize;
    if 1 + ctx_len + 3 > body.len() {
        return 0;
    }
    let mut pos = 1 + ctx_len;
    let list_len = ((body[pos] as usize) << 16)
        | ((body[pos + 1] as usize) << 8)
        | (body[pos + 2] as usize);
    pos += 3;
    let list_end = pos + list_len;
    if list_end > body.len() {
        return 0;
    }
    let mut n = 0;
    while pos + 3 <= list_end && n < out.len() {
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if pos + cert_len + 2 > list_end {
            break;
        }
        out[n] = &body[pos..pos + cert_len];
        n += 1;
        pos += cert_len;
        let ext_len = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
        pos += 2 + ext_len;
    }
    n
}

/// Verify a server certificate chain against a trust anchor + an
/// expected hostname (RFC 5280 + RFC 6125).
///
/// `cert_msg_body`: the Certificate handshake message body (4-byte
/// HS header already stripped).
/// `trust_anchor_der`: DER-encoded trust anchor cert. The chain is
/// accepted if any of its certs has a SubjectPublicKey identical to
/// the trust anchor's. Self-signed deployments pass the leaf itself
/// here; chained deployments pass the root CA.
/// `expected_hostname`: ASCII hostname; matched against leaf SAN
/// dNSNames (preferred) or Subject CN (fallback).
///
/// Validity-date checks are not performed — embedded targets often
/// lack a synced wall clock. The expectation is that
/// short-lived/pinned certs are managed out of band.
/// Verify a server cert chain (RFC 5280 + RFC 6125). Returns 0 on
/// success, non-zero error code for diagnostics.
///
/// `cert_msg_body` is the TLS Certificate message body (4-byte HS
/// header already stripped). `trust_anchor_der` is the pinned trust
/// anchor (for self-signed deployments this is the leaf itself; for
/// CA-issued chains it's the root CA). `expected_hostname` is the
/// hostname expected to appear in the leaf's SAN dNSName or Subject
/// CN (RFC 6125 §6.4.4 fallback).
pub fn verify_cert_chain(
    cert_msg_body: &[u8],
    trust_anchor_der: &[u8],
    expected_hostname: &[u8],
) -> u32 {
    // Walk the leaf entry by hand. Body layout (RFC 8446 §4.4.2):
    //   ctx_len (1) | ctx (ctx_len) | list_len (3) | entry...
    // entry = cert_len (3) | cert (cert_len) | ext_len (2) | ext
    if cert_msg_body.len() < 1 + 3 + 3 + 2 {
        return 1;
    }
    let ctx_len = cert_msg_body[0] as usize;
    if 1 + ctx_len + 3 > cert_msg_body.len() {
        return 2;
    }
    let list_off = 1 + ctx_len + 3;
    if list_off + 3 > cert_msg_body.len() {
        return 3;
    }
    let cert_len = ((cert_msg_body[list_off] as usize) << 16)
        | ((cert_msg_body[list_off + 1] as usize) << 8)
        | (cert_msg_body[list_off + 2] as usize);
    let cert_off = list_off + 3;
    if cert_off + cert_len > cert_msg_body.len() {
        return 4;
    }
    let leaf_der = &cert_msg_body[cert_off..cert_off + cert_len];
    let leaf = match parse_certificate(leaf_der) {
        Some(c) => c,
        None => return 5,
    };
    let trust = match parse_certificate(trust_anchor_der) {
        Some(c) => c,
        None => return 6,
    };
    // Either the leaf's pubkey matches the trust anchor (pinned-leaf
    // deployment) or one of the intermediate certs in the message
    // chains up to the anchor.
    let mut found_anchor = pubkey_eq(leaf.public_key, trust.public_key);
    if !found_anchor {
        // Try subsequent certs in the message.
        let mut pos = cert_off + cert_len;
        if pos + 2 > cert_msg_body.len() {
            return 7;
        }
        let leaf_ext_len = ((cert_msg_body[pos] as usize) << 8)
            | (cert_msg_body[pos + 1] as usize);
        pos += 2 + leaf_ext_len;
        // Verify leaf signature against next cert + recurse upwards.
        let mut prev_der = leaf_der;
        while pos + 3 <= cert_msg_body.len() {
            let nlen = ((cert_msg_body[pos] as usize) << 16)
                | ((cert_msg_body[pos + 1] as usize) << 8)
                | (cert_msg_body[pos + 2] as usize);
            let noff = pos + 3;
            if noff + nlen > cert_msg_body.len() {
                return 8;
            }
            let next_der = &cert_msg_body[noff..noff + nlen];
            let next = match parse_certificate(next_der) {
                Some(c) => c,
                None => return 9,
            };
            if !verify_cert_signature(prev_der, next.public_key) {
                return 10;
            }
            if pubkey_eq(next.public_key, trust.public_key) {
                found_anchor = true;
                break;
            }
            prev_der = next_der;
            pos = noff + nlen;
            if pos + 2 > cert_msg_body.len() {
                return 11;
            }
            let next_ext_len = ((cert_msg_body[pos] as usize) << 8)
                | (cert_msg_body[pos + 1] as usize);
            pos += 2 + next_ext_len;
        }
    }
    if !found_anchor {
        return 12;
    }
    // Hostname check. Prefer SAN dNSName; fall back to Subject CN.
    let mut hostname_ok = false;
    extract_san_dns(leaf_der, |dns| {
        if dns_name_matches(dns, expected_hostname) {
            hostname_ok = true;
        }
        false
    });
    if !hostname_ok {
        if let Some(cn) = extract_subject_cn(leaf_der) {
            if dns_name_matches(cn, expected_hostname) {
                hostname_ok = true;
            }
        }
    }
    if !hostname_ok {
        return 13;
    }
    0
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

/// Extract a 32-byte P-256 scalar from a DER-encoded ECPrivateKey
/// (SEC1 §C.4) or PKCS#8 PrivateKeyInfo wrapping it. Used by both
/// the TLS module (server CertificateVerify) and the DTLS module.
/// Writes the scalar bytes into `out`; on parse failure leaves `out`
/// untouched.
pub unsafe fn extract_ec_private_key(der: &[u8], out: &mut [u8; 32]) {
    if der.len() < 4 { return; }
    if der[0] != 0x30 { return; }
    let (seq_start, _seq_len, _) = match der_tlv(der, 0) { Some(v) => v, None => return };

    let mut pos = seq_start;
    if pos >= der.len() || der[pos] != 0x02 { return; }
    let (int_start, int_len, int_total) = match der_tlv(der, pos) { Some(v) => v, None => return };
    let version = if int_len == 1 { der[int_start] } else { 0xFF };
    pos += int_total;

    if version == 1 {
        // SEC1 ECPrivateKey: OCTET STRING with the private key.
        if pos < der.len() && der[pos] == 0x04 {
            let (os_start, os_len, _) = match der_tlv(der, pos) { Some(v) => v, None => return };
            if os_len == 32 && os_start + 32 <= der.len() {
                core::ptr::copy_nonoverlapping(der.as_ptr().add(os_start), out.as_mut_ptr(), 32);
            }
        }
    } else if version == 0 {
        // PKCS#8: skip AlgorithmIdentifier, then OCTET STRING with
        // the SEC1 ECPrivateKey nested inside.
        if pos < der.len() && der[pos] == 0x30 {
            let (_, _, alg_total) = match der_tlv(der, pos) { Some(v) => v, None => return };
            pos += alg_total;
        }
        if pos < der.len() && der[pos] == 0x04 {
            let (inner_start, inner_len, _) = match der_tlv(der, pos) { Some(v) => v, None => return };
            let inner = &der[inner_start..inner_start + inner_len];
            extract_ec_private_key(inner, out);
        }
    }
}
