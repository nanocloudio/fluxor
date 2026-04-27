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
const EXT_ALPN: u16 = 16;

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
    // ALPN — offer h2 then http/1.1 so an h2-capable peer can pick the
    // upgrade. RFC 7301 §3.1 wire format: ext_type=16, ext_len(u16),
    // list_len(u16), [proto_len(u8), proto_bytes]+
    pos = write_ext_alpn_client(out, pos);

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
///
/// Uses raw pointer writes throughout — array indexing generates
/// bounds-check stubs that miscompile on PIC aarch64.
pub fn build_server_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    suite: CipherSuite,
    pub_key: &[u8; 65],
    out: &mut [u8],
) -> usize {
    unsafe {
        use core::ptr::write_volatile as wv;
        let p = out.as_mut_ptr();
        let mut pos: usize = 0;

        wv(p.add(pos), HT_SERVER_HELLO); pos += 1;
        let len_pos = pos; pos += 3;

        // legacy_version
        wv(p.add(pos), 0x03u8); wv(p.add(pos + 1), 0x03u8); pos += 2;
        // random
        core::ptr::copy_nonoverlapping(random.as_ptr(), p.add(pos), 32);
        pos += 32;
        // session_id (echo back)
        wv(p.add(pos), 32u8); pos += 1;
        core::ptr::copy_nonoverlapping(session_id.as_ptr(), p.add(pos), 32);
        pos += 32;
        // cipher_suite
        let sid = suite.id();
        wv(p.add(pos), (sid >> 8) as u8); wv(p.add(pos + 1), sid as u8); pos += 2;
        // compression_method
        wv(p.add(pos), 0u8); pos += 1;

        // Extensions
        let ext_len_pos = pos; pos += 2;
        let ext_start = pos;

        // supported_versions (TLS 1.3)
        pu16(p, &mut pos, EXT_SUPPORTED_VERSIONS);
        pu16(p, &mut pos, 2); // extension data length
        pu16(p, &mut pos, TLS13_VERSION);

        // key_share
        pu16(p, &mut pos, EXT_KEY_SHARE);
        pu16(p, &mut pos, 2 + 2 + 65); // key_share data length
        pu16(p, &mut pos, GROUP_SECP256R1);
        pu16(p, &mut pos, 65); // key length
        core::ptr::copy_nonoverlapping(pub_key.as_ptr(), p.add(pos), 65);
        pos += 65;

        let ext_len = (pos - ext_start) as u16;
        wv(p.add(ext_len_pos), (ext_len >> 8) as u8);
        wv(p.add(ext_len_pos + 1), ext_len as u8);

        let body_len = pos - len_pos - 3;
        wv(p.add(len_pos), (body_len >> 16) as u8);
        wv(p.add(len_pos + 1), (body_len >> 8) as u8);
        wv(p.add(len_pos + 2), body_len as u8);

        pos
    }
}

/// Write a u16 big-endian at *p.add(pos), advance pos by 2.
#[inline(never)]
pub unsafe fn pu16(p: *mut u8, pos: &mut usize, val: u16) {
    core::ptr::write_volatile(p.add(*pos), (val >> 8) as u8);
    core::ptr::write_volatile(p.add(*pos + 1), val as u8);
    *pos += 2;
}

/// SHA-256 hash of "HelloRetryRequest" — magic random for HRR
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Build HelloRetryRequest (special ServerHello requesting P-256 key share).
/// Uses raw pointer writes throughout for PIC aarch64 safety.
pub fn build_hello_retry_request(
    session_id: &[u8; 32],
    suite: CipherSuite,
    out: &mut [u8],
) -> usize {
    unsafe {
        use core::ptr::write_volatile as wv;
        let p = out.as_mut_ptr();
        let mut pos: usize = 0;

        // Use write_volatile for ALL stores to prevent dead-store elimination
        // and ensure correct codegen on PIC aarch64
        wv(p.add(pos), HT_SERVER_HELLO); pos += 1;
        let len_pos = pos; pos += 3;

        // legacy_version
        wv(p.add(pos), 0x03u8); wv(p.add(pos + 1), 0x03u8); pos += 2;
        // HRR magic random — write each byte individually with write_volatile
        // to prevent LLVM from using ADRP-based const loading (broken in PIC)
        wv(p.add(pos), 0xCFu8); wv(p.add(pos+1), 0x21u8);
        wv(p.add(pos+2), 0xADu8); wv(p.add(pos+3), 0x74u8);
        wv(p.add(pos+4), 0xE5u8); wv(p.add(pos+5), 0x9Au8);
        wv(p.add(pos+6), 0x61u8); wv(p.add(pos+7), 0x11u8);
        wv(p.add(pos+8), 0xBEu8); wv(p.add(pos+9), 0x1Du8);
        wv(p.add(pos+10), 0x8Cu8); wv(p.add(pos+11), 0x02u8);
        wv(p.add(pos+12), 0x1Eu8); wv(p.add(pos+13), 0x65u8);
        wv(p.add(pos+14), 0xB8u8); wv(p.add(pos+15), 0x91u8);
        wv(p.add(pos+16), 0xC2u8); wv(p.add(pos+17), 0xA2u8);
        wv(p.add(pos+18), 0x11u8); wv(p.add(pos+19), 0x16u8);
        wv(p.add(pos+20), 0x7Au8); wv(p.add(pos+21), 0xBBu8);
        wv(p.add(pos+22), 0x8Cu8); wv(p.add(pos+23), 0x5Eu8);
        wv(p.add(pos+24), 0x07u8); wv(p.add(pos+25), 0x9Eu8);
        wv(p.add(pos+26), 0x09u8); wv(p.add(pos+27), 0xE2u8);
        wv(p.add(pos+28), 0xC8u8); wv(p.add(pos+29), 0xA8u8);
        wv(p.add(pos+30), 0x33u8); wv(p.add(pos+31), 0x9Cu8);
        pos += 32;
        // session_id (echo)
        wv(p.add(pos), 32u8); pos += 1;
        core::ptr::copy_nonoverlapping(session_id.as_ptr(), p.add(pos), 32);
        pos += 32;
        // cipher_suite
        let sid = suite.id();
        *p.add(pos) = (sid >> 8) as u8; *p.add(pos + 1) = sid as u8; pos += 2;
        // compression
        *p.add(pos) = 0; pos += 1;

        // Extensions
        let ext_len_pos = pos; pos += 2;
        let ext_start = pos;

        // supported_versions (TLS 1.3)
        pu16(p, &mut pos, EXT_SUPPORTED_VERSIONS);
        pu16(p, &mut pos, 2);
        pu16(p, &mut pos, TLS13_VERSION);

        // key_share: request P-256 (named_group only, no key_exchange)
        pu16(p, &mut pos, EXT_KEY_SHARE);
        pu16(p, &mut pos, 2); // extension data: just the group
        pu16(p, &mut pos, GROUP_SECP256R1);

        let ext_len = (pos - ext_start) as u16;
        *p.add(ext_len_pos) = (ext_len >> 8) as u8;
        *p.add(ext_len_pos + 1) = ext_len as u8;

        let body_len = pos - len_pos - 3;
        *p.add(len_pos) = (body_len >> 16) as u8;
        *p.add(len_pos + 1) = (body_len >> 8) as u8;
        *p.add(len_pos + 2) = body_len as u8;
        pos
    }
}

/// Build CertificateRequest message (for mTLS, raw pointer writes)
pub fn build_certificate_request(out: &mut [u8]) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        let mut pos = 0;
        *p.add(pos) = HT_CERTIFICATE_REQUEST; pos += 1;
        let len_pos = pos; pos += 3;

        *p.add(pos) = 0; pos += 1; // empty context

        let ext_len_pos = pos; pos += 2;
        let ext_start = pos;
        pu16(p, &mut pos, EXT_SIGNATURE_ALGORITHMS);
        pu16(p, &mut pos, 4);
        pu16(p, &mut pos, 2);
        pu16(p, &mut pos, SIG_ECDSA_SECP256R1_SHA256);

        let ext_len = (pos - ext_start) as u16;
        *p.add(ext_len_pos) = (ext_len >> 8) as u8;
        *p.add(ext_len_pos + 1) = ext_len as u8;

        let body_len = pos - len_pos - 3;
        *p.add(len_pos) = (body_len >> 16) as u8;
        *p.add(len_pos + 1) = (body_len >> 8) as u8;
        *p.add(len_pos + 2) = body_len as u8;
        pos
    }
}

/// Build EncryptedExtensions. If `alpn` is non-empty, includes an ALPN
/// extension (RFC 7301 + RFC 8446 §4.6.1) selecting the named
/// protocol. `alpn` should be a single protocol name like `b"h2"` or
/// `b"http/1.1"` — pass an empty slice to omit ALPN.
pub fn build_encrypted_extensions(out: &mut [u8], alpn: &[u8]) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        // Handshake header: type(1) + length(3) — back-filled.
        *p.add(0) = HT_ENCRYPTED_EXTENSIONS;
        let mut pos = 4;

        // Extensions block — 2-byte total length, back-filled.
        let ext_len_pos = pos;
        pos += 2;
        let ext_start = pos;

        if !alpn.is_empty() && alpn.len() <= 255 {
            //   ext_type   = 16 (ALPN)
            //   ext_data_len   = 2 + 1 + name_len      (u16)
            //     list_len     = 1 + name_len           (u16)
            //       name_len   = name.len()             (u8)
            //       name       = alpn bytes
            let nlen = alpn.len();
            let ext_data_len: u16 = (2 + 1 + nlen) as u16;
            let list_len: u16 = (1 + nlen) as u16;
            *p.add(pos) = 0;
            *p.add(pos + 1) = 16;
            *p.add(pos + 2) = (ext_data_len >> 8) as u8;
            *p.add(pos + 3) = ext_data_len as u8;
            *p.add(pos + 4) = (list_len >> 8) as u8;
            *p.add(pos + 5) = list_len as u8;
            *p.add(pos + 6) = nlen as u8;
            core::ptr::copy_nonoverlapping(alpn.as_ptr(), p.add(pos + 7), nlen);
            pos += 7 + nlen;
        }

        let ext_len = (pos - ext_start) as u16;
        *p.add(ext_len_pos) = (ext_len >> 8) as u8;
        *p.add(ext_len_pos + 1) = ext_len as u8;

        let body_len = (pos - 4) as u32;
        *p.add(1) = (body_len >> 16) as u8;
        *p.add(2) = (body_len >> 8) as u8;
        *p.add(3) = body_len as u8;

        pos
    }
}

/// Build Certificate message with a single cert.
/// Uses raw pointer writes — array indexing generates bounds-check panics
/// that crash on PIC aarch64 (panic handler accesses .rodata via ADRP).
pub fn build_certificate(cert_der: &[u8], out: &mut [u8]) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        let mut pos = 0;

        *p.add(pos) = HT_CERTIFICATE; pos += 1;
        let len_pos = pos; pos += 3;

        // certificate_request_context (empty)
        *p.add(pos) = 0; pos += 1;

        // certificate_list length
        let list_len = 3 + cert_der.len() + 2;
        let list_len_pos = pos; pos += 3;

        // CertificateEntry: cert_data length (3 bytes)
        *p.add(pos) = (cert_der.len() >> 16) as u8;
        *p.add(pos + 1) = (cert_der.len() >> 8) as u8;
        *p.add(pos + 2) = cert_der.len() as u8;
        pos += 3;
        // cert_data
        core::ptr::copy_nonoverlapping(cert_der.as_ptr(), p.add(pos), cert_der.len());
        pos += cert_der.len();
        // extensions (empty)
        *p.add(pos) = 0; *p.add(pos + 1) = 0; pos += 2;

        // Fill lengths
        *p.add(list_len_pos) = (list_len >> 16) as u8;
        *p.add(list_len_pos + 1) = (list_len >> 8) as u8;
        *p.add(list_len_pos + 2) = list_len as u8;

        let body_len = pos - len_pos - 3;
        *p.add(len_pos) = (body_len >> 16) as u8;
        *p.add(len_pos + 1) = (body_len >> 8) as u8;
        *p.add(len_pos + 2) = body_len as u8;

        pos
    }
}

/// Build CertificateVerify message (raw pointer writes for PIC safety)
pub fn build_certificate_verify(
    signature_der: &[u8],
    sig_len: usize,
    out: &mut [u8],
) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        let mut pos = 0;

        *p.add(pos) = HT_CERTIFICATE_VERIFY; pos += 1;
        let body_len = 2 + 2 + sig_len;
        *p.add(pos) = (body_len >> 16) as u8;
        *p.add(pos + 1) = (body_len >> 8) as u8;
        *p.add(pos + 2) = body_len as u8;
        pos += 3;

        // SignatureScheme
        pu16(p, &mut pos, SIG_ECDSA_SECP256R1_SHA256);
        // Signature
        pu16(p, &mut pos, sig_len as u16);
        core::ptr::copy_nonoverlapping(signature_der.as_ptr(), p.add(pos), sig_len);
        pos += sig_len;

        pos
    }
}

/// Build Finished message (raw pointer writes for PIC safety)
pub fn build_finished(verify_data: &[u8], hash_len: usize, out: &mut [u8]) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        *p.add(0) = HT_FINISHED;
        *p.add(1) = (hash_len >> 16) as u8;
        *p.add(2) = (hash_len >> 8) as u8;
        *p.add(3) = hash_len as u8;
        core::ptr::copy_nonoverlapping(verify_data.as_ptr(), p.add(4), hash_len);
    }
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
    /// Raw ALPN ProtocolNameList payload (RFC 7301 §3.1):
    ///
    ///   `[2-byte total length][1-byte name length][name bytes]…`
    ///
    /// Use `alpn_iter` to walk the list. `None` if the client did not
    /// send the ALPN extension.
    pub alpn_protos: Option<&'a [u8]>,
}

/// Iterator over an ALPN ProtocolNameList. Yields each protocol name
/// as a byte slice. Skips malformed entries; returns nothing if the
/// outer length prefix is short.
pub fn alpn_iter(list: &[u8]) -> impl Iterator<Item = &[u8]> {
    let inner = if list.len() >= 2 {
        let n = ((list[0] as usize) << 8) | (list[1] as usize);
        let end = (2 + n).min(list.len());
        &list[2..end]
    } else {
        &[][..]
    };
    AlpnIter { rem: inner }
}

struct AlpnIter<'a> {
    rem: &'a [u8],
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rem.is_empty() {
            return None;
        }
        let n = self.rem[0] as usize;
        if n == 0 || 1 + n > self.rem.len() {
            return None;
        }
        let name = &self.rem[1..1 + n];
        self.rem = &self.rem[1 + n..];
        Some(name)
    }
}

/// Parse ClientHello from handshake message body (after type+length)
/// Parse ClientHello handshake message body.
///
/// Uses raw pointer reads to avoid array-indexing bounds checks that
/// miscompile on PIC aarch64.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello<'_>> {
    if data.len() < 38 { return None; }
    let dlen = data.len();
    let dp = data.as_ptr();
    let mut pos: usize = 0;

    unsafe {
        // legacy_version (skip)
        pos += 2;
        // random
        let random = core::slice::from_raw_parts(dp.add(pos), 32); pos += 32;
        // session_id
        let sid_len = *dp.add(pos) as usize; pos += 1;
        if pos + sid_len > dlen { return None; }
        let session_id = core::slice::from_raw_parts(dp.add(pos), sid_len); pos += sid_len;
        // cipher_suites
        if pos + 2 > dlen { return None; }
        let cs_len = get_u16(data, pos) as usize; pos += 2;
        if pos + cs_len > dlen { return None; }
        let cipher_suites = core::slice::from_raw_parts(dp.add(pos), cs_len); pos += cs_len;
        // compression_methods (skip)
        if pos >= dlen { return None; }
        let comp_len = *dp.add(pos) as usize; pos += 1;
        pos += comp_len;

        // Extensions
        let mut key_share: Option<(u16, &[u8])> = None;
        let mut supported_versions: Option<u16> = None;
        let mut alpn_protos: Option<&[u8]> = None;

        if pos + 2 <= dlen {
            let ext_len = get_u16(data, pos) as usize; pos += 2;
            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end {
                let ext_type = get_u16(data, pos); pos += 2;
                let ext_data_len = get_u16(data, pos) as usize; pos += 2;
                if pos + ext_data_len > ext_end { break; }
                let ext_data = core::slice::from_raw_parts(dp.add(pos), ext_data_len);

                match ext_type {
                    EXT_SUPPORTED_VERSIONS => {
                        if ext_data_len >= 3 {
                            let list_len = *dp.add(pos) as usize;
                            let mut vpos = 1usize;
                            while vpos + 1 < 1 + list_len && vpos + 1 < ext_data_len {
                                let v = get_u16(ext_data, vpos);
                                if v == TLS13_VERSION {
                                    supported_versions = Some(v);
                                }
                                vpos += 2;
                            }
                        }
                    }
                    EXT_KEY_SHARE => {
                        if ext_data_len >= 4 {
                            let shares_len = get_u16(ext_data, 0) as usize;
                            let mut spos = 2usize;
                            let send = 2 + shares_len;
                            while spos + 4 <= send && spos + 4 <= ext_data_len {
                                let group = get_u16(ext_data, spos); spos += 2;
                                let klen = get_u16(ext_data, spos) as usize; spos += 2;
                                if spos + klen > ext_data_len { break; }
                                if group == GROUP_SECP256R1 {
                                    key_share = Some((group, core::slice::from_raw_parts(ext_data.as_ptr().add(spos), klen)));
                                }
                                spos += klen;
                            }
                        }
                    }
                    EXT_ALPN => {
                        // Surface the raw payload; the server picks a
                        // protocol via `alpn_iter`.
                        alpn_protos = Some(ext_data);
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
            alpn_protos,
        })
    }
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

/// Select best cipher suite from client's list.
/// Currently restricted to ChaCha20-Poly1305 only — AES-GCM requires SBOX
/// lookup tables in .rodata which miscompile on PIC aarch64.
pub fn select_cipher_suite(client_suites: &[u8]) -> Option<CipherSuite> {
    // Only ChaCha20-Poly1305 is PIC-safe (no lookup tables, no .rodata consts)
    let mut i = 0;
    while i + 1 < client_suites.len() {
        let cs = get_u16(client_suites, i);
        if cs == 0x1303 {
            return Some(CipherSuite::ChaCha20Poly1305);
        }
        i += 2;
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

/// Offer ALPN protocols `h2` and `http/1.1` (in that preference
/// order) — the http module's only consumer wants those two.
/// Raw pointer writes for PIC aarch64 safety.
fn write_ext_alpn_client(out: &mut [u8], mut pos: usize) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        // ext_type = 16 (ALPN)
        *p.add(pos) = 0;
        *p.add(pos + 1) = 16;
        pos += 2;
        // protocol list — encoded once so we can compute lengths.
        // [name_len=2, "h2", name_len=8, "http/1.1"]  → 13 bytes
        let list_len: u16 = 1 + 2 + 1 + 8;
        let ext_data_len: u16 = 2 + list_len;
        *p.add(pos) = (ext_data_len >> 8) as u8;
        *p.add(pos + 1) = ext_data_len as u8;
        pos += 2;
        *p.add(pos) = (list_len >> 8) as u8;
        *p.add(pos + 1) = list_len as u8;
        pos += 2;
        *p.add(pos) = 2;
        *p.add(pos + 1) = b'h';
        *p.add(pos + 2) = b'2';
        pos += 3;
        *p.add(pos) = 8;
        *p.add(pos + 1) = b'h';
        *p.add(pos + 2) = b't';
        *p.add(pos + 3) = b't';
        *p.add(pos + 4) = b'p';
        *p.add(pos + 5) = b'/';
        *p.add(pos + 6) = b'1';
        *p.add(pos + 7) = b'.';
        *p.add(pos + 8) = b'1';
        pos += 9;
    }
    pos
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
fn put_u16(buf: &mut [u8], pos: usize, val: u16) {
    // Use raw pointer writes — array indexing miscompiles on PIC aarch64
    unsafe {
        let p = buf.as_mut_ptr();
        *p.add(pos) = (val >> 8) as u8;
        *p.add(pos + 1) = val as u8;
    }
}

#[inline(always)]
fn get_u16(buf: &[u8], pos: usize) -> u16 {
    // Use raw pointer reads — array indexing miscompiles on PIC aarch64
    unsafe {
        let p = buf.as_ptr();
        ((*p.add(pos) as u16) << 8) | (*p.add(pos + 1) as u16)
    }
}

#[inline(always)]
fn get_u24(buf: &[u8], pos: usize) -> usize {
    ((buf[pos] as usize) << 16) | ((buf[pos + 1] as usize) << 8) | (buf[pos + 2] as usize)
}
