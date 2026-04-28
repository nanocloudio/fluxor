// TLS 1.3 Handshake State Machine (RFC 8446 Section 4)
// Server and client handshake, message construction/parsing
//
// FUTURE — Phase A of docs/architecture/datagram_secure_transports.md
// will extract a record-agnostic `HandshakeDriver` from this file (and
// `mod.rs`) into `handshake_driver.rs`. The driver consumes plain
// handshake bytes per `EncLevel { Initial, Handshake, OneRtt }` and
// exposes `feed_handshake` / `poll_handshake` / `read_secret`, so DTLS
// (Phase B) and QUIC (Phase C) can drive the same state machine via
// their own record / CRYPTO-frame layers without forking this code.

/// Handshake message types
const HT_CLIENT_HELLO: u8 = 1;
const HT_SERVER_HELLO: u8 = 2;
const HT_HELLO_RETRY_REQUEST: u8 = 2; // Same type as ServerHello, distinguished by random
const HT_NEW_SESSION_TICKET: u8 = 4;
const HT_END_OF_EARLY_DATA: u8 = 5;
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
/// QUIC transport_parameters extension (RFC 9001 §8.2). Carried in
/// ClientHello and EncryptedExtensions during the QUIC handshake;
/// must be empty for TLS-over-TCP and DTLS.
pub const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

/// 0-RTT-related TLS extensions (RFC 8446 §4.2.10 + §4.2.11).
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_EARLY_DATA: u16 = 42;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;

pub const PSK_KE_MODE_PSK: u8 = 0;
pub const PSK_KE_MODE_PSK_DHE: u8 = 1;

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
    build_client_hello_ext(random, session_id, pub_key, &[], out)
}

/// Variant taking a QUIC `transport_parameters` extension payload.
/// `quic_tp` is the inner extension *value* (the raw transport-
/// parameters varint TLV list per RFC 9000 §18); the function wraps
/// it in the [type(2)][length(2)][data] extension envelope. An
/// empty `quic_tp` is equivalent to `build_client_hello`.
pub fn build_client_hello_ext(
    random: &[u8; 32],
    session_id: &[u8; 32],
    pub_key: &[u8; 65],
    quic_tp: &[u8],
    out: &mut [u8],
) -> usize {
    let mut pos = 0;

    // Handshake header: type(1) + length(3) — we'll fill length later
    out[pos] = HT_CLIENT_HELLO; pos += 1;
    let len_pos = pos; pos += 3;

    // ClientHello body
    out[pos] = 0x03; out[pos + 1] = 0x03; pos += 2;
    unsafe { core::ptr::copy_nonoverlapping(random.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    out[pos] = 32; pos += 1;
    unsafe { core::ptr::copy_nonoverlapping(session_id.as_ptr(), out.as_mut_ptr().add(pos), 32); }
    pos += 32;
    out[pos] = 0; out[pos + 1] = 6; pos += 2;
    put_u16(out, pos, 0x1303); pos += 2;
    put_u16(out, pos, 0x1301); pos += 2;
    put_u16(out, pos, 0x1302); pos += 2;
    out[pos] = 1; pos += 1;
    out[pos] = 0; pos += 1;

    let ext_len_pos = pos; pos += 2;
    let ext_start = pos;
    pos = write_ext_supported_versions(out, pos);
    pos = write_ext_key_share_client(out, pos, pub_key);
    pos = write_ext_signature_algorithms(out, pos);
    pos = write_ext_alpn_client(out, pos);
    if !quic_tp.is_empty() {
        put_u16(out, pos, EXT_QUIC_TRANSPORT_PARAMETERS); pos += 2;
        put_u16(out, pos, quic_tp.len() as u16); pos += 2;
        unsafe {
            core::ptr::copy_nonoverlapping(
                quic_tp.as_ptr(),
                out.as_mut_ptr().add(pos),
                quic_tp.len(),
            );
        }
        pos += quic_tp.len();
    }

    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

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
    build_encrypted_extensions_ext(out, alpn, &[])
}

/// Variant taking a QUIC `transport_parameters` extension payload —
/// see `build_client_hello_ext` for the framing convention. Used by
/// the QUIC server to advertise its transport parameters in EE.
pub fn build_encrypted_extensions_ext(out: &mut [u8], alpn: &[u8], quic_tp: &[u8]) -> usize {
    unsafe {
        let p = out.as_mut_ptr();
        *p.add(0) = HT_ENCRYPTED_EXTENSIONS;
        let mut pos = 4;

        let ext_len_pos = pos;
        pos += 2;
        let ext_start = pos;

        if !alpn.is_empty() && alpn.len() <= 255 {
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

        if !quic_tp.is_empty() {
            *p.add(pos) = (EXT_QUIC_TRANSPORT_PARAMETERS >> 8) as u8;
            *p.add(pos + 1) = EXT_QUIC_TRANSPORT_PARAMETERS as u8;
            *p.add(pos + 2) = (quic_tp.len() >> 8) as u8;
            *p.add(pos + 3) = quic_tp.len() as u8;
            core::ptr::copy_nonoverlapping(quic_tp.as_ptr(), p.add(pos + 4), quic_tp.len());
            pos += 4 + quic_tp.len();
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
    /// QUIC `transport_parameters` (RFC 9001 §8.2). `None` for
    /// TLS-over-TCP / DTLS clients that don't carry the extension.
    pub transport_parameters: Option<&'a [u8]>,
    /// Raw ALPN ProtocolNameList payload (RFC 7301 §3.1):
    ///
    ///   `[2-byte total length][1-byte name length][name bytes]…`
    ///
    /// Use `alpn_iter` to walk the list. `None` if the client did not
    /// send the ALPN extension.
    pub alpn_protos: Option<&'a [u8]>,
    /// Raw `pre_shared_key` extension payload (RFC 8446 §4.2.11). The
    /// extension is `OfferedPsks { identities, binders }`. Only present
    /// on resumption attempts. Walk via `psk_identity_iter`.
    pub pre_shared_key: Option<&'a [u8]>,
    /// Offset of the binders portion of the `pre_shared_key` extension
    /// within the original ClientHello body — i.e. the byte index in the
    /// 4-byte-header-stripped CH where binders start. The PSK binder
    /// transcript hash covers everything in the CH up to but not
    /// including this offset (RFC 8446 §4.2.11.2).
    pub psk_binders_off: Option<usize>,
    /// Whether the `psk_key_exchange_modes` extension was present and
    /// included `psk_dhe_ke` (mode 1). Required when negotiating PSK.
    pub psk_dhe_offered: bool,
    /// Whether the `early_data` extension was present (RFC 8446 §4.2.10).
    pub early_data: bool,
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
        let mut transport_parameters: Option<&[u8]> = None;
        let mut pre_shared_key: Option<&[u8]> = None;
        let mut psk_binders_off: Option<usize> = None;
        let mut psk_dhe_offered = false;
        let mut early_data = false;

        if pos + 2 <= dlen {
            let ext_len = get_u16(data, pos) as usize; pos += 2;
            let ext_end = pos + ext_len;
            while pos + 4 <= ext_end {
                let ext_type = get_u16(data, pos); pos += 2;
                let ext_data_len = get_u16(data, pos) as usize; pos += 2;
                if pos + ext_data_len > ext_end { break; }
                let ext_data = core::slice::from_raw_parts(dp.add(pos), ext_data_len);

                match ext_type {
                    EXT_PSK_KEY_EXCHANGE_MODES => {
                        // Single-byte length + byte modes (RFC 8446 §4.2.9).
                        if ext_data_len >= 2 {
                            let n = ext_data[0] as usize;
                            let mut k = 0;
                            while k < n && k + 1 < ext_data_len {
                                if ext_data[1 + k] == PSK_KE_MODE_PSK_DHE {
                                    psk_dhe_offered = true;
                                }
                                k += 1;
                            }
                        }
                    }
                    EXT_EARLY_DATA => {
                        early_data = true;
                    }
                    EXT_PRE_SHARED_KEY => {
                        // Capture the raw payload + the absolute offset
                        // of the binders within the CH body so the
                        // server can compute the PSK binder hash over
                        // bytes [0..binders_off].
                        pre_shared_key = Some(ext_data);
                        // OfferedPsks payload layout:
                        //   identities<7..2^16-1>: each {identity<1..2^16-1>, obfuscated_ticket_age(u32)}
                        //   binders<33..2^16-1>: each {binder<32..255>}
                        if ext_data_len >= 2 {
                            let id_list_len = get_u16(ext_data, 0) as usize;
                            let after_ids = 2 + id_list_len;
                            if after_ids <= ext_data_len {
                                // The binders length follows the identities.
                                psk_binders_off = Some(pos + after_ids);
                            }
                        }
                    }
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
                    EXT_QUIC_TRANSPORT_PARAMETERS => {
                        transport_parameters = Some(ext_data);
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
            transport_parameters,
            pre_shared_key,
            psk_binders_off,
            psk_dhe_offered,
            early_data,
        })
    }
}

/// Walk an OfferedPsks payload and yield each (identity, obfuscated_age)
/// tuple. Returns (identity_bytes, age) or empty if the payload is
/// malformed.
pub fn psk_identity_iter(offered: &[u8]) -> impl Iterator<Item = (&[u8], u32)> {
    PskIdentityIter { buf: offered, off: 0, end: 0, init: false }
}

/// Walk the binders portion of an OfferedPsks payload (the part after
/// `identities`). Yields each binder slice in order.
pub fn psk_binder_iter(binders: &[u8]) -> impl Iterator<Item = &[u8]> {
    PskBinderIter { buf: binders, off: 0, end: 0, init: false }
}

pub struct PskIdentityIter<'a> {
    buf: &'a [u8],
    off: usize,
    end: usize,
    init: bool,
}

impl<'a> Iterator for PskIdentityIter<'a> {
    type Item = (&'a [u8], u32);
    fn next(&mut self) -> Option<Self::Item> {
        if !self.init {
            if self.buf.len() < 2 {
                return None;
            }
            self.end = 2 + (((self.buf[0] as usize) << 8) | (self.buf[1] as usize));
            self.off = 2;
            self.init = true;
        }
        if self.off + 2 > self.end || self.off + 2 > self.buf.len() {
            return None;
        }
        let id_len = ((self.buf[self.off] as usize) << 8) | (self.buf[self.off + 1] as usize);
        self.off += 2;
        if self.off + id_len + 4 > self.end || self.off + id_len + 4 > self.buf.len() {
            return None;
        }
        let id = &self.buf[self.off..self.off + id_len];
        self.off += id_len;
        let age = ((self.buf[self.off] as u32) << 24)
            | ((self.buf[self.off + 1] as u32) << 16)
            | ((self.buf[self.off + 2] as u32) << 8)
            | (self.buf[self.off + 3] as u32);
        self.off += 4;
        Some((id, age))
    }
}

pub struct PskBinderIter<'a> {
    buf: &'a [u8],
    off: usize,
    end: usize,
    init: bool,
}

impl<'a> Iterator for PskBinderIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if !self.init {
            if self.buf.len() < 2 {
                return None;
            }
            self.end = 2 + (((self.buf[0] as usize) << 8) | (self.buf[1] as usize));
            self.off = 2;
            self.init = true;
        }
        if self.off >= self.end {
            return None;
        }
        let b_len = self.buf[self.off] as usize;
        self.off += 1;
        if self.off + b_len > self.end || self.off + b_len > self.buf.len() {
            return None;
        }
        let b = &self.buf[self.off..self.off + b_len];
        self.off += b_len;
        Some(b)
    }
}

/// Parsed ServerHello
pub struct ServerHello<'a> {
    pub random: &'a [u8],
    pub session_id: &'a [u8],
    pub cipher_suite: u16,
    pub key_share: Option<(u16, &'a [u8])>,
    pub supported_version: Option<u16>,
    pub transport_parameters: Option<&'a [u8]>,
    /// Selected PSK identity index when the server is accepting a
    /// resumption (RFC 8446 §4.2.11). `None` when the server didn't
    /// include `pre_shared_key`. Identity-based; the client matches
    /// this against the order it offered identities in CH.
    pub psk_identity: Option<u16>,
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
    let mut transport_parameters = None;
    let mut psk_identity = None;

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
                EXT_QUIC_TRANSPORT_PARAMETERS => {
                    transport_parameters = Some(ext_data);
                }
                EXT_PRE_SHARED_KEY => {
                    // ServerHello PSK ext is just the selected_identity (u16).
                    if ext_data.len() >= 2 {
                        psk_identity = Some(get_u16(ext_data, 0));
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
        transport_parameters,
        psk_identity,
    })
}

/// Parse the EncryptedExtensions message body (without the 4-byte
/// handshake header) for extensions of interest. Currently only
/// extracts the QUIC `transport_parameters` payload — TLS / DTLS
/// don't yet need to surface anything else from EE.
pub fn parse_encrypted_extensions_for_quic(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 2 {
        return None;
    }
    let ext_len = get_u16(body, 0) as usize;
    let mut pos = 2;
    let ext_end = pos + ext_len;
    if ext_end > body.len() {
        return None;
    }
    while pos + 4 <= ext_end {
        let ext_type = get_u16(body, pos);
        pos += 2;
        let ext_data_len = get_u16(body, pos) as usize;
        pos += 2;
        if pos + ext_data_len > ext_end {
            break;
        }
        if ext_type == EXT_QUIC_TRANSPORT_PARAMETERS {
            return Some(&body[pos..pos + ext_data_len]);
        }
        pos += ext_data_len;
    }
    None
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

#[inline(always)]
fn put_u32(buf: &mut [u8], pos: usize, val: u32) {
    unsafe {
        let p = buf.as_mut_ptr();
        *p.add(pos) = (val >> 24) as u8;
        *p.add(pos + 1) = (val >> 16) as u8;
        *p.add(pos + 2) = (val >> 8) as u8;
        *p.add(pos + 3) = val as u8;
    }
}

#[inline(always)]
fn get_u32(buf: &[u8], pos: usize) -> u32 {
    unsafe {
        let p = buf.as_ptr();
        ((*p.add(pos) as u32) << 24)
            | ((*p.add(pos + 1) as u32) << 16)
            | ((*p.add(pos + 2) as u32) << 8)
            | (*p.add(pos + 3) as u32)
    }
}

// ============================================================================
// NewSessionTicket (RFC 8446 §4.6.1)
// ============================================================================

/// Build a NewSessionTicket message body. Format:
///
///   ticket_lifetime (u32)
///   ticket_age_add  (u32)
///   ticket_nonce    <0..255>
///   ticket          <1..2^16-1>
///   extensions      <0..2^16-2>     (only `early_data` here)
///
/// `max_early_data` 0 means "don't advertise early_data". Anything
/// non-zero advertises that much early-data quota in bytes.
pub fn build_new_session_ticket(
    lifetime_s: u32,
    age_add: u32,
    nonce: &[u8],
    ticket: &[u8],
    max_early_data: u32,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    out[pos] = HT_NEW_SESSION_TICKET;
    pos += 1;
    let len_pos = pos;
    pos += 3;
    put_u32(out, pos, lifetime_s);
    pos += 4;
    put_u32(out, pos, age_add);
    pos += 4;
    out[pos] = nonce.len() as u8;
    pos += 1;
    if !nonce.is_empty() {
        unsafe {
            core::ptr::copy_nonoverlapping(
                nonce.as_ptr(),
                out.as_mut_ptr().add(pos),
                nonce.len(),
            );
        }
        pos += nonce.len();
    }
    put_u16(out, pos, ticket.len() as u16);
    pos += 2;
    if !ticket.is_empty() {
        unsafe {
            core::ptr::copy_nonoverlapping(
                ticket.as_ptr(),
                out.as_mut_ptr().add(pos),
                ticket.len(),
            );
        }
        pos += ticket.len();
    }
    let exts_len_pos = pos;
    pos += 2;
    if max_early_data > 0 {
        put_u16(out, pos, EXT_EARLY_DATA);
        pos += 2;
        put_u16(out, pos, 4);
        pos += 2;
        put_u32(out, pos, max_early_data);
        pos += 4;
    }
    let exts_len = pos - exts_len_pos - 2;
    put_u16(out, exts_len_pos, exts_len as u16);
    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;
    pos
}

pub struct ParsedNewSessionTicket<'a> {
    pub lifetime_s: u32,
    pub age_add: u32,
    pub nonce: &'a [u8],
    pub ticket: &'a [u8],
    pub max_early_data: u32,
}

/// Parse a NewSessionTicket body (the 4-byte handshake header has been
/// stripped). Returns None on truncation / malformed bytes.
pub fn parse_new_session_ticket(body: &[u8]) -> Option<ParsedNewSessionTicket<'_>> {
    if body.len() < 4 + 4 + 1 {
        return None;
    }
    let lifetime_s = get_u32(body, 0);
    let age_add = get_u32(body, 4);
    let nonce_len = body[8] as usize;
    let mut p = 9;
    if p + nonce_len + 2 > body.len() {
        return None;
    }
    let nonce = &body[p..p + nonce_len];
    p += nonce_len;
    let ticket_len = ((body[p] as usize) << 8) | (body[p + 1] as usize);
    p += 2;
    if p + ticket_len + 2 > body.len() {
        return None;
    }
    let ticket = &body[p..p + ticket_len];
    p += ticket_len;
    let exts_len = ((body[p] as usize) << 8) | (body[p + 1] as usize);
    p += 2;
    if p + exts_len > body.len() {
        return None;
    }
    let mut max_early_data = 0u32;
    let mut q = p;
    let q_end = p + exts_len;
    while q + 4 <= q_end {
        let etype = ((body[q] as u16) << 8) | (body[q + 1] as u16);
        let elen = ((body[q + 2] as usize) << 8) | (body[q + 3] as usize);
        q += 4;
        if q + elen > q_end {
            break;
        }
        if etype == EXT_EARLY_DATA && elen >= 4 {
            max_early_data = get_u32(body, q);
        }
        q += elen;
    }
    Some(ParsedNewSessionTicket {
        lifetime_s,
        age_add,
        nonce,
        ticket,
        max_early_data,
    })
}

// ============================================================================
// PSK-bearing ClientHello (RFC 8446 §4.2.11) + binder helpers.
// ============================================================================

/// Build a ClientHello carrying a single PSK identity + binder
/// placeholder. The caller is responsible for computing the binder
/// over the partial-CH bytes (everything up to the binders array)
/// and overwriting the placeholder via `psk_overwrite_binder`.
///
/// Returns (msg_len, binders_off_in_body, binder_placeholder_off_in_body).
/// `binders_off_in_body` is the 4-byte-header-stripped offset where
/// the binders length field begins; the partial transcript hash for
/// the binder MUST cover `body[..binders_off_in_body]` only (RFC 8446
/// §4.2.11.2). Single-binder layout: binders_len (u16) + binder_len (u8) + binder (hash_len bytes).
pub fn build_client_hello_psk(
    random: &[u8; 32],
    session_id: &[u8; 32],
    pub_key: &[u8; 65],
    quic_tp: &[u8],
    psk_identity: &[u8],
    obfuscated_age: u32,
    binder_len: usize,
    include_early_data: bool,
    out: &mut [u8],
) -> (usize, usize, usize) {
    let mut pos = 0;
    out[pos] = HT_CLIENT_HELLO;
    pos += 1;
    let len_pos = pos;
    pos += 3;
    let body_start = pos;

    out[pos] = 0x03;
    out[pos + 1] = 0x03;
    pos += 2;
    unsafe {
        core::ptr::copy_nonoverlapping(random.as_ptr(), out.as_mut_ptr().add(pos), 32);
    }
    pos += 32;
    out[pos] = 32;
    pos += 1;
    unsafe {
        core::ptr::copy_nonoverlapping(session_id.as_ptr(), out.as_mut_ptr().add(pos), 32);
    }
    pos += 32;
    out[pos] = 0;
    out[pos + 1] = 6;
    pos += 2;
    put_u16(out, pos, 0x1303);
    pos += 2;
    put_u16(out, pos, 0x1301);
    pos += 2;
    put_u16(out, pos, 0x1302);
    pos += 2;
    out[pos] = 1;
    pos += 1;
    out[pos] = 0;
    pos += 1;

    let ext_len_pos = pos;
    pos += 2;
    let ext_start = pos;
    pos = write_ext_supported_versions(out, pos);
    pos = write_ext_key_share_client(out, pos, pub_key);
    pos = write_ext_signature_algorithms(out, pos);
    pos = write_ext_alpn_client(out, pos);
    if !quic_tp.is_empty() {
        put_u16(out, pos, EXT_QUIC_TRANSPORT_PARAMETERS);
        pos += 2;
        put_u16(out, pos, quic_tp.len() as u16);
        pos += 2;
        unsafe {
            core::ptr::copy_nonoverlapping(
                quic_tp.as_ptr(),
                out.as_mut_ptr().add(pos),
                quic_tp.len(),
            );
        }
        pos += quic_tp.len();
    }
    // psk_key_exchange_modes — RFC 8446 §4.2.9: 1-byte length + bytes.
    put_u16(out, pos, EXT_PSK_KEY_EXCHANGE_MODES);
    pos += 2;
    put_u16(out, pos, 2);
    pos += 2;
    out[pos] = 1;
    pos += 1;
    out[pos] = PSK_KE_MODE_PSK_DHE;
    pos += 1;
    if include_early_data {
        put_u16(out, pos, EXT_EARLY_DATA);
        pos += 2;
        put_u16(out, pos, 0);
        pos += 2;
    }
    // pre_shared_key extension MUST be the LAST extension (RFC 8446 §4.2.11).
    // Layout:
    //   identities<7..2^16-1>:
    //     PskIdentity { identity<1..2^16-1>, obfuscated_ticket_age (u32) }
    //   binders<33..2^16-1>:
    //     PskBinderEntry { binder<32..255> }
    put_u16(out, pos, EXT_PRE_SHARED_KEY);
    pos += 2;
    let psk_len_pos = pos;
    pos += 2;
    // identities
    let id_list_len = 2 + psk_identity.len() + 4;
    put_u16(out, pos, id_list_len as u16);
    pos += 2;
    put_u16(out, pos, psk_identity.len() as u16);
    pos += 2;
    unsafe {
        core::ptr::copy_nonoverlapping(
            psk_identity.as_ptr(),
            out.as_mut_ptr().add(pos),
            psk_identity.len(),
        );
    }
    pos += psk_identity.len();
    put_u32(out, pos, obfuscated_age);
    pos += 4;
    // binders — placeholder (zeros). Caller overwrites via
    // psk_overwrite_binder once the partial-CH transcript hash is known.
    let binders_off_in_body = pos - body_start;
    let total_binders_len = 1 + binder_len;
    put_u16(out, pos, total_binders_len as u16);
    pos += 2;
    out[pos] = binder_len as u8;
    pos += 1;
    let binder_placeholder_off_in_body = pos - body_start;
    let mut k = 0;
    while k < binder_len {
        out[pos + k] = 0;
        k += 1;
    }
    pos += binder_len;
    let psk_total = pos - psk_len_pos - 2;
    put_u16(out, psk_len_pos, psk_total as u16);

    let ext_len = pos - ext_start;
    put_u16(out, ext_len_pos, ext_len as u16);

    let body_len = pos - len_pos - 3;
    out[len_pos] = (body_len >> 16) as u8;
    out[len_pos + 1] = (body_len >> 8) as u8;
    out[len_pos + 2] = body_len as u8;
    (pos, binders_off_in_body, binder_placeholder_off_in_body)
}

/// Overwrite the binder placeholder bytes with the actual binder.
/// `body_off` is the offset into the FULL CH (with handshake header)
/// where the binder bytes start; pass `4 + binder_placeholder_off_in_body`.
pub fn psk_overwrite_binder(buf: &mut [u8], full_ch_off: usize, binder: &[u8]) {
    if full_ch_off + binder.len() > buf.len() {
        return;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            binder.as_ptr(),
            buf.as_mut_ptr().add(full_ch_off),
            binder.len(),
        );
    }
}

/// Build a ServerHello indicating a PSK selection. Embeds the
/// `pre_shared_key` extension carrying `selected_identity` (a u16).
pub fn build_server_hello_psk(
    random: &[u8; 32],
    session_id: &[u8; 32],
    suite: CipherSuite,
    pub_key: &[u8; 65],
    selected_identity: u16,
    out: &mut [u8],
) -> usize {
    unsafe {
        use core::ptr::write_volatile as wv;
        let p = out.as_mut_ptr();
        let mut pos: usize = 0;

        wv(p.add(pos), HT_SERVER_HELLO);
        pos += 1;
        let len_pos = pos;
        pos += 3;
        wv(p.add(pos), 0x03);
        wv(p.add(pos + 1), 0x03);
        pos += 2;
        core::ptr::copy_nonoverlapping(random.as_ptr(), p.add(pos), 32);
        pos += 32;
        wv(p.add(pos), 32);
        pos += 1;
        core::ptr::copy_nonoverlapping(session_id.as_ptr(), p.add(pos), 32);
        pos += 32;
        let cs = suite.id();
        wv(p.add(pos), (cs >> 8) as u8);
        wv(p.add(pos + 1), cs as u8);
        pos += 2;
        wv(p.add(pos), 0);
        pos += 1;

        // Extensions
        let ext_len_pos = pos;
        pos += 2;
        let ext_start = pos;

        // supported_versions
        wv(p.add(pos), (EXT_SUPPORTED_VERSIONS >> 8) as u8);
        wv(p.add(pos + 1), EXT_SUPPORTED_VERSIONS as u8);
        pos += 2;
        wv(p.add(pos), 0);
        wv(p.add(pos + 1), 2);
        pos += 2;
        wv(p.add(pos), 0x03);
        wv(p.add(pos + 1), 0x04);
        pos += 2;

        // key_share
        wv(p.add(pos), (EXT_KEY_SHARE >> 8) as u8);
        wv(p.add(pos + 1), EXT_KEY_SHARE as u8);
        pos += 2;
        let ks_len = 4 + 65;
        wv(p.add(pos), (ks_len >> 8) as u8);
        wv(p.add(pos + 1), ks_len as u8);
        pos += 2;
        wv(p.add(pos), (GROUP_SECP256R1 >> 8) as u8);
        wv(p.add(pos + 1), GROUP_SECP256R1 as u8);
        pos += 2;
        wv(p.add(pos), 0);
        wv(p.add(pos + 1), 65);
        pos += 2;
        core::ptr::copy_nonoverlapping(pub_key.as_ptr(), p.add(pos), 65);
        pos += 65;

        // pre_shared_key — payload is selected_identity (u16).
        wv(p.add(pos), (EXT_PRE_SHARED_KEY >> 8) as u8);
        wv(p.add(pos + 1), EXT_PRE_SHARED_KEY as u8);
        pos += 2;
        wv(p.add(pos), 0);
        wv(p.add(pos + 1), 2);
        pos += 2;
        wv(p.add(pos), (selected_identity >> 8) as u8);
        wv(p.add(pos + 1), selected_identity as u8);
        pos += 2;

        let ext_len = pos - ext_start;
        wv(p.add(ext_len_pos), (ext_len >> 8) as u8);
        wv(p.add(ext_len_pos + 1), ext_len as u8);

        let body_len = pos - len_pos - 3;
        wv(p.add(len_pos), (body_len >> 16) as u8);
        wv(p.add(len_pos + 1), (body_len >> 8) as u8);
        wv(p.add(len_pos + 2), body_len as u8);
        pos
    }
}

/// Build EncryptedExtensions including the `early_data` extension when
/// the server is accepting 0-RTT (RFC 8446 §4.2.10). Wraps the existing
/// `build_encrypted_extensions_ext` and appends the early_data marker.
pub fn build_encrypted_extensions_early(
    out: &mut [u8],
    alpn: &[u8],
    quic_tp: &[u8],
    accept_early_data: bool,
) -> usize {
    let pos = build_encrypted_extensions_ext(out, alpn, quic_tp);
    if !accept_early_data {
        return pos;
    }
    // Find the existing 2-byte ext_len at offset 4 (HS hdr) + body
    // — easier to rebuild from scratch. The prior helper writes
    // body[0..2] = ext_len; we patch by appending the early_data
    // extension and bumping all length fields.
    // Simpler: shift in-place. The existing format is:
    //   [HS hdr 4][ext_len u16][exts...]
    // We add the early_data ext (4 bytes: type+len), then patch the
    // body length and ext_len.
    let new_pos = pos + 4;
    if new_pos > out.len() {
        return pos;
    }
    let ext_len_pos = 4;
    let mut ext_len = ((out[ext_len_pos] as u16) << 8) | (out[ext_len_pos + 1] as u16);
    out[pos] = (EXT_EARLY_DATA >> 8) as u8;
    out[pos + 1] = EXT_EARLY_DATA as u8;
    out[pos + 2] = 0;
    out[pos + 3] = 0;
    ext_len += 4;
    out[ext_len_pos] = (ext_len >> 8) as u8;
    out[ext_len_pos + 1] = ext_len as u8;
    // Bump the 3-byte body length in the HS header.
    let body_len = ((out[1] as usize) << 16) | ((out[2] as usize) << 8) | (out[3] as usize);
    let new_body_len = body_len + 4;
    out[1] = (new_body_len >> 16) as u8;
    out[2] = (new_body_len >> 8) as u8;
    out[3] = new_body_len as u8;
    new_pos
}
