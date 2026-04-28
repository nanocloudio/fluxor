// TLS 1.3 Key Schedule (RFC 8446 Section 7.1)
// Derives handshake and application traffic keys from shared secret

/// Key schedule state for a TLS 1.3 connection
pub struct KeySchedule {
    pub suite: CipherSuite,
    pub alg: HashAlg,
    pub hash_len: usize,
    pub early_secret: [u8; 48],
    pub handshake_secret: [u8; 48],
    pub master_secret: [u8; 48],
    pub client_hs_secret: [u8; 48],
    pub server_hs_secret: [u8; 48],
    pub client_app_secret: [u8; 48],
    pub server_app_secret: [u8; 48],
}

impl KeySchedule {
    pub fn new(suite: CipherSuite) -> Self {
        let alg = suite.hash_alg();
        let hash_len = suite.hash_len();

        // Early Secret = HKDF-Extract(0, 0...0)
        // Without PSK, IKM is hash_len zero bytes
        let zero_ikm = [0u8; 48];
        let mut early = [0u8; 48];
        hkdf_extract(alg, &[], &zero_ikm[..hash_len], &mut early[..hash_len]);

        Self {
            suite,
            alg,
            hash_len,
            early_secret: early,
            handshake_secret: [0; 48],
            master_secret: [0; 48],
            client_hs_secret: [0; 48],
            server_hs_secret: [0; 48],
            client_app_secret: [0; 48],
            server_app_secret: [0; 48],
        }
    }

    /// Derive handshake secrets from ECDH shared secret and transcript hash
    /// (hash of ClientHello..ServerHello)
    pub fn derive_handshake_secrets(
        &mut self,
        ecdh_shared: &[u8; 32],
        transcript_hash: &[u8],
    ) {
        let hl = self.hash_len;
        let alg = self.alg;

        // Derive-Secret(Early Secret, "derived", "")
        let mut empty_hash = [0u8; 48];
        hash_empty(alg, &mut empty_hash[..hl]);

        let mut derived = [0u8; 48];
        derive_secret(alg, &self.early_secret[..hl], b"derived", &empty_hash[..hl], &mut derived[..hl]);

        // Handshake Secret = HKDF-Extract(Derived, ECDH)
        hkdf_extract(alg, &derived[..hl], ecdh_shared, &mut self.handshake_secret[..hl]);

        // The early secret and the intermediate HKDF derivation are no
        // longer needed once the handshake secret has been extracted.
        zeroize(&mut self.early_secret);
        zeroize(&mut derived);

        // client/server handshake traffic secrets
        derive_secret(alg, &self.handshake_secret[..hl], b"c hs traffic", transcript_hash, &mut self.client_hs_secret[..hl]);
        derive_secret(alg, &self.handshake_secret[..hl], b"s hs traffic", transcript_hash, &mut self.server_hs_secret[..hl]);
    }

    /// Derive application traffic secrets from transcript hash
    /// (hash of ClientHello..server Finished)
    pub fn derive_app_secrets(&mut self, transcript_hash: &[u8]) {
        let hl = self.hash_len;
        let alg = self.alg;

        // Derive-Secret(Handshake Secret, "derived", "")
        let mut empty_hash = [0u8; 48];
        hash_empty(alg, &mut empty_hash[..hl]);

        let mut derived = [0u8; 48];
        derive_secret(alg, &self.handshake_secret[..hl], b"derived", &empty_hash[..hl], &mut derived[..hl]);

        // Master Secret = HKDF-Extract(Derived, 0)
        let zero = [0u8; 48];
        hkdf_extract(alg, &derived[..hl], &zero[..hl], &mut self.master_secret[..hl]);

        zeroize(&mut derived);

        // Application traffic secrets
        derive_secret(alg, &self.master_secret[..hl], b"c ap traffic", transcript_hash, &mut self.client_app_secret[..hl]);
        derive_secret(alg, &self.master_secret[..hl], b"s ap traffic", transcript_hash, &mut self.server_app_secret[..hl]);
    }

    /// Compute Finished verify_data
    pub fn compute_finished(&self, base_key: &[u8]) -> [u8; 48] {
        let hl = self.hash_len;
        let alg = self.alg;

        // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        let mut finished_key = [0u8; 48];
        hkdf_expand_label(alg, &base_key[..hl], b"finished", &[], &mut finished_key[..hl]);

        // Return the finished_key — the actual verify_data is HMAC(finished_key, transcript_hash)
        // computed by caller with the current transcript hash
        finished_key
    }

    /// HMAC for Finished verify_data
    pub fn finished_verify_data(&self, finished_key: &[u8], transcript_hash: &[u8]) -> [u8; 48] {
        let hl = self.hash_len;
        let mut out = [0u8; 48];
        hmac(self.alg, &finished_key[..hl], transcript_hash, &mut out[..hl]);
        out
    }
}

/// 0-RTT / resumption key schedule additions (RFC 8446 §7.1).
///
/// The early secret is HKDF-Extract(0, PSK). For non-resumed handshakes
/// PSK = 0^hash_len; for resumed handshakes it's the per-ticket PSK
/// derived from the resumption_master_secret + ticket_nonce.
impl KeySchedule {
    /// Re-seed the early secret using an external PSK. Call this BEFORE
    /// `derive_handshake_secrets` on a resumption attempt; the PSK
    /// becomes part of the key schedule chain.
    pub fn seed_psk(&mut self, psk: &[u8]) {
        let alg = self.alg;
        let hl = self.hash_len;
        // Early Secret = HKDF-Extract(salt=0, IKM=PSK)
        hkdf_extract(alg, &[], psk, &mut self.early_secret[..hl]);
    }

    /// Derive `client_early_traffic_secret` from the early secret +
    /// transcript hash through the truncated ClientHello (i.e. up to
    /// but not including the binders array, RFC 8446 §4.2.11.2).
    pub fn derive_client_early_traffic(
        &self,
        ch_truncated_hash: &[u8],
        out: &mut [u8],
    ) {
        let alg = self.alg;
        let hl = self.hash_len;
        derive_secret(alg, &self.early_secret[..hl], b"c e traffic", ch_truncated_hash, &mut out[..hl]);
    }

    /// Compute the PSK binder. binder = HMAC(finished_key,
    /// hash(truncated CH)) where finished_key =
    /// HKDF-Expand-Label(binder_key, "finished", "", hash_len) and
    /// binder_key = Derive-Secret(early_secret, "res binder", hash("")).
    pub fn psk_binder(&self, ch_truncated_hash: &[u8]) -> [u8; 48] {
        let alg = self.alg;
        let hl = self.hash_len;
        let mut empty_hash = [0u8; 48];
        hash_empty(alg, &mut empty_hash[..hl]);
        let mut binder_key = [0u8; 48];
        derive_secret(alg, &self.early_secret[..hl], b"res binder", &empty_hash[..hl], &mut binder_key[..hl]);
        let mut finished_key = [0u8; 48];
        hkdf_expand_label(alg, &binder_key[..hl], b"finished", &[], &mut finished_key[..hl]);
        let mut out = [0u8; 48];
        hmac(alg, &finished_key[..hl], ch_truncated_hash, &mut out[..hl]);
        out
    }

    /// Derive resumption_master_secret from master_secret + transcript
    /// hash through client Finished (RFC 8446 §7.1).
    pub fn derive_resumption_master(&self, transcript_hash: &[u8], out: &mut [u8]) {
        let alg = self.alg;
        let hl = self.hash_len;
        derive_secret(alg, &self.master_secret[..hl], b"res master", transcript_hash, &mut out[..hl]);
    }

    /// Derive a PSK from RMS + ticket_nonce (RFC 8446 §4.6.1):
    /// PSK = HKDF-Expand-Label(RMS, "resumption", ticket_nonce, hash_len)
    pub fn ticket_psk(&self, rms: &[u8], ticket_nonce: &[u8], out: &mut [u8]) {
        let alg = self.alg;
        let hl = self.hash_len;
        hkdf_expand_label(alg, &rms[..hl], b"resumption", ticket_nonce, &mut out[..hl]);
    }
}

/// Hash of empty input for the selected algorithm
fn hash_empty(alg: HashAlg, out: &mut [u8]) {
    match alg {
        HashAlg::Sha256 => {
            let h = Sha256::new();
            let digest = h.finalize();
            let n = if out.len() < 32 { out.len() } else { 32 };
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out.as_mut_ptr(), n); }
        }
        HashAlg::Sha384 => {
            let h = Sha384::new();
            let digest = h.finalize();
            let n = if out.len() < 48 { out.len() } else { 48 };
            unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out.as_mut_ptr(), n); }
        }
    }
}
