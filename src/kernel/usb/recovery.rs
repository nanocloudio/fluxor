//! Forced BOOTSEL entry and who is allowed to ask for it.
//!
//! A running image can be told to reboot into BOOTSEL, which hands the board
//! to host tooling with full read/write access to flash. That is exactly what
//! a development rig needs and exactly what a deployed device must not offer
//! to anything that can reach its USB port.
//!
//! So there are two postures, and a build declares which it is:
//!
//! - **Development** — any host that can speak to the recovery interface may
//!   request BOOTSEL. Convenient, and appropriate only for a board on a desk
//!   or in a rig.
//! - **Managed** — a request must be signed by an authorised key and must
//!   carry a counter higher than any previously accepted. Both halves are
//!   needed: a signature alone is replayable, and a counter alone is
//!   forgeable.
//!
//! # Why replay protection is not optional
//!
//! A signed recovery command is a small, fixed byte string. Anyone who
//! observes one on the wire — or lifts it from a log, a script, or a CI
//! artefact — holds a working key to that device forever unless the device
//! refuses to accept it twice. The counter is what makes a captured command
//! worthless the moment it has been used.

use crate::kernel::security::crypto::ed25519;

/// What a build allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posture {
    /// Any host may force BOOTSEL. Development and rig use only.
    Development,
    /// A request must be signed and non-replayable.
    Managed,
}

/// Why a recovery request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// The request was malformed.
    Malformed,
    /// No authorised key is configured, so nothing can be authorised.
    NoAuthorisedKey,
    /// The signature did not verify against the authorised key.
    BadSignature,
    /// The counter is not higher than the last accepted one: a replay.
    Replayed,
    /// The request names a different device.
    WrongDevice,
}

/// Bytes of a recovery request: counter, device id, then the signature.
pub const REQUEST_LEN: usize = 8 + 8 + 64;

/// A parsed recovery request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// Monotonic counter. Must exceed the last accepted value.
    pub counter: u64,
    /// The device this request is for.
    pub device_id: u64,
    /// Ed25519 signature over the counter and device id.
    pub signature: [u8; 64],
}

impl Request {
    /// Decode a request from the wire.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() != REQUEST_LEN {
            return Err(RecoveryError::Malformed);
        }
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&bytes[0..8]);
        let mut device_id = [0u8; 8];
        device_id.copy_from_slice(&bytes[8..16]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[16..80]);
        Ok(Self {
            counter: u64::from_le_bytes(counter),
            device_id: u64::from_le_bytes(device_id),
            signature,
        })
    }

    /// The bytes the signature covers.
    ///
    /// **The device id is signed, not merely compared.** Signing only the
    /// counter would make one authorised command valid on every device that
    /// shares the key — capture it from a development board and it unlocks
    /// the fleet.
    pub fn signed_bytes(&self) -> [u8; 16] {
        let mut m = [0u8; 16];
        m[0..8].copy_from_slice(&self.counter.to_le_bytes());
        m[8..16].copy_from_slice(&self.device_id.to_le_bytes());
        m
    }
}

/// Recovery authorisation state.
pub struct RecoveryPolicy {
    posture: Posture,
    authorised_key: Option<[u8; 32]>,
    device_id: u64,
    /// Highest counter accepted so far. Persisted by the caller; holding it
    /// only in RAM means a power cycle re-opens every captured command.
    last_counter: u64,
}

impl RecoveryPolicy {
    /// A development-posture policy: anything may request BOOTSEL.
    pub const fn development(device_id: u64) -> Self {
        Self {
            posture: Posture::Development,
            authorised_key: None,
            device_id,
            last_counter: 0,
        }
    }

    /// A managed policy requiring signed, non-replayable requests.
    pub const fn managed(device_id: u64, key: [u8; 32], last_counter: u64) -> Self {
        Self {
            posture: Posture::Managed,
            authorised_key: Some(key),
            device_id,
            last_counter,
        }
    }

    /// The posture this build declares.
    pub const fn posture(&self) -> Posture {
        self.posture
    }

    /// The highest counter accepted so far, for the caller to persist.
    pub const fn last_counter(&self) -> u64 {
        self.last_counter
    }

    /// Whether an unauthenticated request is honoured.
    ///
    /// True only in development posture. This is the single question a
    /// transport should ask before acting on a bare "please reboot to
    /// BOOTSEL" with no credentials attached.
    pub const fn allows_unauthenticated(&self) -> bool {
        matches!(self.posture, Posture::Development)
    }

    /// Authorise a recovery request, advancing the replay counter on success.
    ///
    /// Order matters. The signature is checked **before** the counter is
    /// advanced, so an unsigned request cannot burn counter values and lock
    /// out the legitimate holder of the key.
    pub fn authorise(&mut self, request: &Request) -> Result<(), RecoveryError> {
        if request.device_id != self.device_id {
            return Err(RecoveryError::WrongDevice);
        }
        // Strictly greater: accepting an equal counter is accepting the same
        // command twice, which is the replay this exists to stop.
        if request.counter <= self.last_counter {
            return Err(RecoveryError::Replayed);
        }

        let Some(key) = self.authorised_key else {
            return Err(RecoveryError::NoAuthorisedKey);
        };
        if !ed25519::verify(&key, &request.signed_bytes(), &request.signature) {
            return Err(RecoveryError::BadSignature);
        }

        self.last_counter = request.counter;
        Ok(())
    }
}
