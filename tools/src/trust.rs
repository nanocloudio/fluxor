//! Workload signing trust + revocation policy.
//!
//! System and workload-publisher signing authorities are **separate trust
//! roots** with independent rotation — overlapping validity is just multiple
//! keys per root, so a successor key can be trusted before its predecessor is
//! retired. **Revocation is first-class**: an artifact signed only by a revoked
//! key fails admission even if the key would otherwise be trusted.
//!
//! The Ed25519 signature check itself is [`crate::crypto::verify`] (the same
//! verify path the kernel loader runs); the node agent verifies a signature to
//! establish the signer key, then consults this policy for the trust/revocation
//! *decision*. Keeping the decision separate from the crypto keeps it
//! exhaustively testable, and keeps the two questions apart: a valid signature
//! establishes only *who* signed, never that the signer is allowed to.

/// An Ed25519 public key identifies a signing authority.
pub type KeyId = [u8; 32];

/// Which trust root a signature claims to come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRole {
    System,
    Publisher,
}

/// Admission outcome for a verified signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    Admit,
    /// Signer key is on the revocation list (overrides trust).
    RejectRevoked,
    /// Signer key is not a trusted anchor for the claimed role.
    RejectUntrusted,
}

/// Trust configuration: the trusted keys per root and the revocation list.
#[derive(Clone, Debug, Default)]
pub struct TrustPolicy {
    pub system_anchors: Vec<KeyId>,
    pub publisher_keys: Vec<KeyId>,
    pub revoked: Vec<KeyId>,
}

impl TrustPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide admission for a signer whose signature has already been verified.
    /// Revocation is checked first so a compromised key is refused regardless of
    /// trust-root membership.
    pub fn admit(&self, signer: &KeyId, role: SignerRole) -> Admission {
        if self.revoked.iter().any(|k| k == signer) {
            return Admission::RejectRevoked;
        }
        let trusted = match role {
            SignerRole::System => self.system_anchors.iter().any(|k| k == signer),
            SignerRole::Publisher => self.publisher_keys.iter().any(|k| k == signer),
        };
        if trusted {
            Admission::Admit
        } else {
            Admission::RejectUntrusted
        }
    }

    /// Add a key to the revocation list (idempotent). Future admission of any
    /// artifact signed only by this key fails; a running workload is not torn
    /// down here — that is the caller's restart-eligibility decision.
    pub fn revoke(&mut self, key: KeyId) {
        if !self.revoked.contains(&key) {
            self.revoked.push(key);
        }
    }

    /// True if every signer in `signers` admits for its role — i.e. the bundle
    /// and all referenced artifacts are covered by trusted, non-revoked keys.
    pub fn admits_all(&self, signers: &[(KeyId, SignerRole)]) -> bool {
        signers
            .iter()
            .all(|(k, role)| self.admit(k, *role) == Admission::Admit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> KeyId {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    #[test]
    fn trusted_system_key_admits() {
        let mut p = TrustPolicy::new();
        p.system_anchors.push(key(1));
        assert_eq!(p.admit(&key(1), SignerRole::System), Admission::Admit);
    }

    #[test]
    fn untrusted_key_rejected() {
        let p = TrustPolicy::new();
        assert_eq!(
            p.admit(&key(9), SignerRole::Publisher),
            Admission::RejectUntrusted
        );
    }

    #[test]
    fn role_roots_are_separate() {
        let mut p = TrustPolicy::new();
        p.publisher_keys.push(key(2));
        // a publisher key is not a system anchor
        assert_eq!(p.admit(&key(2), SignerRole::Publisher), Admission::Admit);
        assert_eq!(
            p.admit(&key(2), SignerRole::System),
            Admission::RejectUntrusted
        );
    }

    #[test]
    fn revocation_overrides_trust() {
        let mut p = TrustPolicy::new();
        p.publisher_keys.push(key(3));
        assert_eq!(p.admit(&key(3), SignerRole::Publisher), Admission::Admit);
        p.revoke(key(3));
        assert_eq!(
            p.admit(&key(3), SignerRole::Publisher),
            Admission::RejectRevoked
        );
        // idempotent
        p.revoke(key(3));
        assert_eq!(p.revoked.len(), 1);
    }

    #[test]
    fn overlapping_rotation_admits_both_keys() {
        let mut p = TrustPolicy::new();
        // predecessor + successor both valid during the rotation window
        p.system_anchors.push(key(10));
        p.system_anchors.push(key(11));
        assert_eq!(p.admit(&key(10), SignerRole::System), Admission::Admit);
        assert_eq!(p.admit(&key(11), SignerRole::System), Admission::Admit);
    }

    #[test]
    fn admits_all_requires_every_signer() {
        let mut p = TrustPolicy::new();
        p.system_anchors.push(key(1));
        p.publisher_keys.push(key(2));
        assert!(p.admits_all(&[
            (key(1), SignerRole::System),
            (key(2), SignerRole::Publisher)
        ]));
        // one revoked → whole bundle fails
        p.revoke(key(2));
        assert!(!p.admits_all(&[
            (key(1), SignerRole::System),
            (key(2), SignerRole::Publisher)
        ]));
    }
}
