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
