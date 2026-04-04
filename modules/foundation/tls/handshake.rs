// TLS 1.3 Handshake State Machine (RFC 8446 Section 4)
// Server and client handshake, message construction/parsing

/// Handshake message types
const HT_CLIENT_HELLO: u8 = 1;
const HT_SERVER_HELLO: u8 = 2;
const HT_HELLO_RETRY_REQUEST: u8 = 2; // Same type as ServerHello, distinguished by random
const HT_ENCRYPTED_EXTENSIONS: u8 = 8;
const HT_CERTIFICATE: u8 = 11;
const HT_CERTIFICATE_REQUEST: u8 = 13;
const HT_CERTIFICATE_VERIFY: u8 = 15;
const HT_FINISHED: u8 = 20;

/// Extension types
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_COOKIE: u16 = 44;

/// Named group for P-256
const GROUP_SECP256R1: u16 = 0x0017;

/// Signature algorithm: ecdsa_secp256r1_sha256
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// TLS 1.3 version
const TLS13_VERSION: u16 = 0x0304;

/// Handshake sub-states
#[derive(Clone, Copy, PartialEq)]
pub enum HandshakeState {
    // Server states
    RecvClientHello,
    SendHelloRetryRequest,
    RecvSecondClientHello,
    SendServerHello,
    DeriveHandshakeKeys,
    SendEncryptedExtensions,
    SendCertificateRequest,
    SendCertificate,
    SendCertificateVerify,
    SendFinished,
    RecvClientCert,
    RecvClientCertVerify,
    RecvClientFinished,
    DeriveAppKeys,

    // Client states
    SendClientHello,
    RecvServerHello,
    ClientDeriveHandshakeKeys,
    RecvEncryptedExtensions,
    RecvCertificate,
    RecvCertificateVerify,
    RecvFinished,
    SendClientCert,
    SendClientCertVerify,
    SendClientFinished,
    ClientDeriveAppKeys,

    // Terminal
    Complete,
    Error,
}

/// Transcript hasher — maintains running hash of handshake messages
pub struct Transcript {
    sha256: Sha256,
    sha384: Sha384,
    alg: HashAlg,
}

impl Transcript {
    pub fn new(alg: HashAlg) -> Self {
        Self {
            sha256: Sha256::new(),
            sha384: Sha384::new(),
            alg,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        // Always update both hashers — cipher suite may not be known yet
        self.sha256.update(data);
        self.sha384.update(data);
    }

    /// Switch the active hash algorithm (e.g., after cipher suite negotiation)
    pub fn set_alg(&mut self, alg: HashAlg) {
        self.alg = alg;
    }

    pub fn current_hash(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        match self.alg {
            HashAlg::Sha256 => {
                let h = self.sha256.clone().finalize();
                unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), out.as_mut_ptr(), 32); }
            }
            HashAlg::Sha384 => {
                let h = self.sha384.clone().finalize();
                unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), out.as_mut_ptr(), 48); }
            }
        }
        out
    }

    pub fn hash_len(&self) -> usize {
        self.alg.digest_len()
    }
}

/// Build ClientHello message body (without record header).
/// Returns length written to `out`.
pub fn build_client_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    pub_key: &[u8; 65],  // uncompressed P-256 public key
    out: &mut [u8],
) -> usize {
    let mut pos = 0;

    // Handshake header: type(1) + length(3) — we'll fill length later
    out[pos] = HT_CLIENT_HELLO; pos += 1;
    let len_pos = pos; pos += 3;

    // ClientHello body
    // legacy_version = TLS 1.2
    out[pos] = 0x03; out[pos + 1] = 0x03; pos += 2;
    // random (32 bytes)
    unsafe { core::ptr::copy_nonoverlapping(random.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // legacy_session_id (32 bytes)
    out[pos] = 32; pos += 1;
    unsafe { core::ptr::copy_nonoverlapping(session_id.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // All 3 TLS 1.3 cipher suites
    out[pos] = 0; out[pos + 1] = 6; pos += 2;
    put_u16(out, pos, 0x1303); pos += 2; // ChaCha20-Poly1305 (preferred)
    put_u16(out, pos, 0x1301); pos += 2; // AES-128-GCM
    put_u16(out, pos, 0x1302); pos += 2; // AES-256-GCM
    // legacy_compression_methods = [null]
    out[pos] = 1; pos += 1;
    out[pos] = 0; pos += 1;

    // Extensions
    let ext_len_pos = pos; pos += 2;
    let ext_start = pos;

    // supported_versions
    pos = write_ext_supported_versions(out, pos);
    // key_share (P-256)
    pos = write_ext_key_share_client(out, pos, pub_key);
    // signature_algorithms
    pos = write_ext_signature_algorithms(out, pos);

    // Fill extension length
    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

    // Fill handshake length
    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;

    pos
}

/// Build ServerHello message body.
/// Returns length written to `out`.
pub fn build_server_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    suite: CipherSuite,
    pub_key: &[u8; 65],
    out: &mut [u8],
) -> usize {
    let mut pos = 0;

    out[pos] = HT_SERVER_HELLO; pos += 1;
    let len_pos = pos; pos += 3;

    // legacy_version
    out[pos] = 0x03; out[pos + 1] = 0x03; pos += 2;
    // random
    unsafe { core::ptr::copy_nonoverlapping(random.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // session_id (echo back)
    out[pos] = 32; pos += 1;
    unsafe { core::ptr::copy_nonoverlapping(session_id.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // cipher_suite
    put_u16(out, pos, suite.id()); pos += 2;
    // compression_method
    out[pos] = 0; pos += 1;

    // Extensions
    let ext_len_pos = pos; pos += 2;
    let ext_start = pos;

    // supported_versions (TLS 1.3)
    put_u16(out, pos, EXT_SUPPORTED_VERSIONS); pos += 2;
    put_u16(out, pos, 2); pos += 2; // extension data length
    put_u16(out, pos, TLS13_VERSION); pos += 2;

    // key_share
    put_u16(out, pos, EXT_KEY_SHARE); pos += 2;
    // key_share data: group(2) + key_len(2) + key(65)
    put_u16(out, pos, 2 + 2 + 65); pos += 2;
    put_u16(out, pos, GROUP_SECP256R1); pos += 2;
    put_u16(out, pos, 65); pos += 2;
    unsafe { core::ptr::copy_nonoverlapping(pub_key.as_ptr(), out.as_mut_ptr().add(pos), 65); }
    pos += 65;

    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;

    pos
}

/// SHA-256 hash of "HelloRetryRequest" — magic random for HRR
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Build HelloRetryRequest (special ServerHello requesting P-256 key share)
pub fn build_hello_retry_request(
    session_id: &[u8; 32],
    suite: CipherSuite,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    out[pos] = HT_SERVER_HELLO; pos += 1;
    let len_pos = pos; pos += 3;

    // legacy_version
    out[pos] = 0x03; out[pos + 1] = 0x03; pos += 2;
    // HRR magic random
    unsafe { core::ptr::copy_nonoverlapping(HRR_RANDOM.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // session_id (echo)
    out[pos] = 32; pos += 1;
    unsafe { core::ptr::copy_nonoverlapping(session_id.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    // cipher_suite
    put_u16(out, pos, suite.id()); pos += 2;
    // compression
    out[pos] = 0; pos += 1;

    // Extensions
    let ext_len_pos = pos; pos += 2;
    let ext_start = pos;

    // supported_versions (TLS 1.3)
    put_u16(out, pos, EXT_SUPPORTED_VERSIONS); pos += 2;
    put_u16(out, pos, 2); pos += 2;
    put_u16(out, pos, TLS13_VERSION); pos += 2;

    // key_share: request P-256 (named_group only, no key_exchange)
    put_u16(out, pos, EXT_KEY_SHARE); pos += 2;
    put_u16(out, pos, 2); pos += 2; // extension data: just the group
    put_u16(out, pos, GROUP_SECP256R1); pos += 2;

    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;
    pos
}

/// Build CertificateRequest message (for mTLS)
pub fn build_certificate_request(out: &mut [u8]) -> usize {
    let mut pos = 0;
    out[pos] = HT_CERTIFICATE_REQUEST; pos += 1;
    let len_pos = pos; pos += 3;

    // certificate_request_context (empty)
    out[pos] = 0; pos += 1;

    // extensions: signature_algorithms
    let ext_len_pos = pos; pos += 2;
    let ext_start = pos;
    // signature_algorithms extension
    put_u16(out, pos, EXT_SIGNATURE_ALGORITHMS); pos += 2;
    put_u16(out, pos, 4); pos += 2; // ext data len
    put_u16(out, pos, 2); pos += 2; // list len
    put_u16(out, pos, SIG_ECDSA_SECP256R1_SHA256); pos += 2;

    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;
    pos
}

/// Build EncryptedExtensions (empty — no extensions needed)
pub fn build_encrypted_extensions(out: &mut [u8]) -> usize {
    out[0] = HT_ENCRYPTED_EXTENSIONS;
    out[1] = 0; out[2] = 0; out[3] = 2; // length = 2
    out[4] = 0; out[5] = 0; // extensions length = 0
    6
}

/// Build Certificate message with a single cert
pub fn build_certificate(cert_der: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;

    out[pos] = HT_CERTIFICATE; pos += 1;
    let len_pos = pos; pos += 3;

    // certificate_request_context (empty)
    out[pos] = 0; pos += 1;

    // certificate_list length
    let list_len = 3 + cert_der.len() + 2; // cert_data_len(3) + cert_data + extensions_len(2)
    let list_len_pos = pos; pos += 3;

    // CertificateEntry
    // cert_data length (3 bytes)
    out[pos] = (cert_der.len() >> 16) as u8;
    out[pos + 1] = (cert_der.len() >> 8) as u8;
    out[pos + 2] = cert_der.len() as u8;
    pos += 3;
    // cert_data
    unsafe { core::ptr::copy_nonoverlapping(cert_der.as_ptr(), out.as_mut_ptr().add(pos), cert_der.len()); }
    pos += cert_der.len();
    // extensions (empty)
    out[pos] = 0; out[pos + 1] = 0; pos += 2;

    // Fill lengths
    out[list_len_pos] = (list_len >> 16) as u8;
    out[list_len_pos + 1] = (list_len >> 8) as u8;
    out[list_len_pos + 2] = list_len as u8;

    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;

    pos
}

/// Build CertificateVerify message
pub fn build_certificate_verify(
    signature_der: &[u8],
    sig_len: usize,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;

    out[pos] = HT_CERTIFICATE_VERIFY; pos += 1;
    let body_len = 2 + 2 + sig_len; // sig_algorithm(2) + sig_len(2) + sig
    out[pos] = (body_len >> 16) as u8;
    out[pos + 1] = (body_len >> 8) as u8;
    out[pos + 2] = body_len as u8;
    pos += 3;

    // SignatureScheme
    put_u16(out, pos, SIG_ECDSA_SECP256R1_SHA256); pos += 2;
    // Signature
    put_u16(out, pos, sig_len as u16); pos += 2;
    unsafe { core::ptr::copy_nonoverlapping(signature_der.as_ptr(), out.as_mut_ptr().add(pos), sig_len); }
    pos += sig_len;

    pos
}

/// Build Finished message
pub fn build_finished(verify_data: &[u8], hash_len: usize, out: &mut [u8]) -> usize {
    out[0] = HT_FINISHED;
    out[1] = (hash_len >> 16) as u8;
    out[2] = (hash_len >> 8) as u8;
    out[3] = hash_len as u8;
    unsafe { core::ptr::copy_nonoverlapping(verify_data.as_ptr(), out.as_mut_ptr().add(4), hash_len); }
    4 + hash_len
}

// ============================================================================
// Parsing
// ============================================================================

/// Parsed ClientHello
pub struct ClientHello<'a> {
    pub random: &'a [u8],     // 32 bytes
    pub session_id: &'a [u8], // 0-32 bytes
    pub cipher_suites: &'a [u8], // raw bytes
    pub key_share: Option<(u16, &'a [u8])>, // (group, key_exchange)
    pub supported_versions: Option<u16>,
}

/// Parse ClientHello from handshake message body (after type+length)
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello<'_>> {
    if data.len() < 38 { return None; }
    let mut pos = 0;

    // legacy_version (skip)
    pos += 2;
    // random
    let random = &data[pos..pos + 32]; pos += 32;
    // session_id
    let sid_len = data[pos] as usize; pos += 1;
    if pos + sid_len > data.len() { return None; }
    let session_id = &data[pos..pos + sid_len]; pos += sid_len;
    // cipher_suites
    if pos + 2 > data.len() { return None; }
    let cs_len = get_u16(data, pos) as usize; pos += 2;
    if pos + cs_len > data.len() { return None; }
    let cipher_suites = &data[pos..pos + cs_len]; pos += cs_len;
    // compression_methods (skip)
    if pos >= data.len() { return None; }
    let comp_len = data[pos] as usize; pos += 1;
    pos += comp_len;

    // Extensions
    let mut key_share: Option<(u16, &[u8])> = None;
    let mut supported_versions: Option<u16> = None;

    if pos + 2 <= data.len() {
        let ext_len = get_u16(data, pos) as usize; pos += 2;
        let ext_end = pos + ext_len;
        while pos + 4 <= ext_end {
            let ext_type = get_u16(data, pos); pos += 2;
            let ext_data_len = get_u16(data, pos) as usize; pos += 2;
            if pos + ext_data_len > ext_end { break; }
            let ext_data = &data[pos..pos + ext_data_len];

            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    // List of supported versions
                    if ext_data.len() >= 3 {
                        let list_len = ext_data[0] as usize;
                        let mut vpos = 1;
                        while vpos + 1 < 1 + list_len && vpos + 1 < ext_data.len() {
                            let v = get_u16(ext_data, vpos);
                            if v == TLS13_VERSION {
                                supported_versions = Some(v);
                            }
                            vpos += 2;
                        }
                    }
                }
                EXT_KEY_SHARE => {
                    // ClientHello key_share: client_shares_length(2) + entries
                    if ext_data.len() >= 4 {
                        let shares_len = get_u16(ext_data, 0) as usize;
                        let mut spos = 2;
                        let send = 2 + shares_len;
                        while spos + 4 <= send && spos + 4 <= ext_data.len() {
                            let group = get_u16(ext_data, spos); spos += 2;
                            let klen = get_u16(ext_data, spos) as usize; spos += 2;
                            if spos + klen > ext_data.len() { break; }
                            if group == GROUP_SECP256R1 {
                                key_share = Some((group, &ext_data[spos..spos + klen]));
                            }
                            spos += klen;
                        }
                    }
                }
                _ => {}
            }
            pos += ext_data_len;
        }
    }

    Some(ClientHello {
        random,
        session_id,
        cipher_suites,
        key_share,
        supported_versions,
    })
}

/// Parsed ServerHello
pub struct ServerHello<'a> {
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suite: u16,
    pub key_share: Option<(u16, &'a [u8])>,
    pub supported_version: Option<u16>,
}

/// Parse ServerHello
pub fn parse_server_hello(data: &[u8]) -> Option<ServerHello<'_>> {
    if data.len() < 38 { return None; }
    let mut pos = 0;

    pos += 2; // legacy_version
    let random = &data[pos..pos + 32]; pos += 32;
    let sid_len = data[pos] as usize; pos += 1;
    if pos + sid_len > data.len() { return None; }
    let session_id = &data[pos..pos + sid_len]; pos += sid_len;
    if pos + 3 > data.len() { return None; }
    let cipher_suite = get_u16(data, pos); pos += 2;
    pos += 1; // compression

    let mut key_share = None;
    let mut supported_version = None;

    if pos + 2 <= data.len() {
        let ext_len = get_u16(data, pos) as usize; pos += 2;
        let ext_end = pos + ext_len;
        while pos + 4 <= ext_end {
            let ext_type = get_u16(data, pos); pos += 2;
            let ext_data_len = get_u16(data, pos) as usize; pos += 2;
            if pos + ext_data_len > ext_end { break; }
            let ext_data = &data[pos..pos + ext_data_len];

            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if ext_data.len() >= 2 {
                        supported_version = Some(get_u16(ext_data, 0));
                    }
                }
                EXT_KEY_SHARE => {
                    if ext_data.len() >= 4 {
                        let group = get_u16(ext_data, 0);
                        let klen = get_u16(ext_data, 2) as usize;
                        if 4 + klen <= ext_data.len() {
                            key_share = Some((group, &ext_data[4..4 + klen]));
                        }
                    }
                }
                _ => {}
            }
            pos += ext_data_len;
        }
    }

    Some(ServerHello {
        random,
        session_id,
        cipher_suite,
        key_share,
        supported_version,
    })
}

/// Select best cipher suite from client's list
pub fn select_cipher_suite(client_suites: &[u8]) -> Option<CipherSuite> {
    // Server preference: ChaCha20 > AES-128-GCM > AES-256-GCM
    let prefs = [0x1303u16, 0x1301, 0x1302];
    for pref in &prefs {
        let mut i = 0;
        while i + 1 < client_suites.len() {
            let cs = get_u16(client_suites, i);
            if cs == *pref {
                return CipherSuite::from_id(cs);
            }
            i += 2;
        }
    }
    None
}

/// Parse Certificate message body
pub fn parse_certificate_msg(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 { return None; }
    let ctx_len = data[0] as usize;
    let mut pos = 1 + ctx_len;
    if pos + 3 > data.len() { return None; }
    let list_len = get_u24(data, pos); pos += 3;
    if pos + list_len > data.len() { return None; }
    // First CertificateEntry
    if list_len < 3 { return None; }
    let cert_len = get_u24(data, pos); pos += 3;
    if pos + cert_len > data.len() { return None; }
    Some(&data[pos..pos + cert_len])
}

/// Parse CertificateVerify message body
pub fn parse_certificate_verify(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 { return None; }
    let scheme = get_u16(data, 0);
    let sig_len = get_u16(data, 2) as usize;
    if 4 + sig_len > data.len() { return None; }
    Some((scheme, &data[4..4 + sig_len]))
}

/// Parse Finished message body
pub fn parse_finished(data: &[u8], expected_len: usize) -> Option<&[u8]> {
    if data.len() < expected_len { return None; }
    Some(&data[..expected_len])
}

/// Build CertificateVerify signing content
/// context_string: "TLS 1.3, server CertificateVerify" or "TLS 1.3, client CertificateVerify"
pub fn build_verify_content(context: &[u8], transcript_hash: &[u8], hash_len: usize, out: &mut [u8]) -> usize {
    // 64 spaces + context_string + 0x00 + transcript_hash
    let mut pos = 0;
    let mut i = 0;
    while i < 64 { out[pos] = 0x20; pos += 1; i += 1; }
    unsafe { core::ptr::copy_nonoverlapping(context.as_ptr(), out.as_mut_ptr().add(pos), context.len()); }
    pos += context.len();
    out[pos] = 0x00; pos += 1;
    unsafe { core::ptr::copy_nonoverlapping(transcript_hash.as_ptr(), out.as_mut_ptr().add(pos), hash_len); }
    pos += hash_len;
    pos
}

// ============================================================================
// Extension builders
// ============================================================================

fn write_ext_supported_versions(out: &mut [u8], mut pos: usize) -> usize {
    put_u16(out, pos, EXT_SUPPORTED_VERSIONS); pos += 2;
    put_u16(out, pos, 3); pos += 2; // ext data length
    out[pos] = 2; pos += 1; // list length
    put_u16(out, pos, TLS13_VERSION); pos += 2;
    pos
}

fn write_ext_key_share_client(out: &mut [u8], mut pos: usize, pub_key: &[u8; 65]) -> usize {
    put_u16(out, pos, EXT_KEY_SHARE); pos += 2;
    // ext data: shares_len(2) + group(2) + key_len(2) + key(65)
    put_u16(out, pos, 2 + 2 + 2 + 65); pos += 2;
    put_u16(out, pos, 2 + 2 + 65); pos += 2; // client_shares length
    put_u16(out, pos, GROUP_SECP256R1); pos += 2;
    put_u16(out, pos, 65); pos += 2;
    unsafe { core::ptr::copy_nonoverlapping(pub_key.as_ptr(), out.as_mut_ptr().add(pos), 65); }
    pos += 65;
    pos
}

fn write_ext_signature_algorithms(out: &mut [u8], mut pos: usize) -> usize {
    put_u16(out, pos, EXT_SIGNATURE_ALGORITHMS); pos += 2;
    put_u16(out, pos, 4); pos += 2; // ext data length
    put_u16(out, pos, 2); pos += 2; // list length
    put_u16(out, pos, SIG_ECDSA_SECP256R1_SHA256); pos += 2;
    pos
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
fn put_u16(buf: &mut [u8], pos: usize, val: u16) {
    buf[pos] = (val >> 8) as u8;
    buf[pos + 1] = val as u8;
}

#[inline(always)]
fn get_u16(buf: &[u8], pos: usize) -> u16 {
    ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16)
}

#[inline(always)]
fn get_u24(buf: &[u8], pos: usize) -> usize {
    ((buf[pos] as usize) << 16) | ((buf[pos + 1] as usize) << 8) | (buf[pos + 2] as usize)
}
