// TRANSPORT_CONTINUITY — the wire vocabulary of the single-flow continuity
// surface: the frames an anchor and a provider exchange over the
// `tc_ctl` / `tc_evt` port pair, and the magics and versions that open the
// canonical record, its checkpoint chunks and its ordered mirror deltas.
//
// The record's codec, its deterministic transition and the standby's
// assembler are a library, not this contract: `fluxor_sdk::cores::
// transport_continuity_record`, which an anchor and a provider link.
//
// Frames are `[op u8][len u16 LE][payload]`. Every payload after
// PAIR_PREPARE and TOMBSTONE leads with the handle the provider issued; a
// handle the provider no longer holds is refused `STALE_HANDLE` before
// anything is mutated.

pub const TS_MAGIC: [u8; 4] = *b"TCRC";
pub const TS_VERSION: u8 = 1;
pub const CKPT_CHUNK_MAGIC: [u8; 4] = *b"TCCC";
pub const MD_MAGIC: [u8; 4] = *b"TCMD";
pub const MD_VERSION: u8 = 1;
pub const TC_QUIC_MAGIC: [u8; 4] = *b"TCQ1";
pub const TC_QUIC_VERSION: u8 = 1;
pub const TC_FRAME_HDR: usize = 3;
pub const TC_HANDLE_LEN: usize = 8;

/// Anchor → provider operations.
pub mod tc_op {
    /// `[null handle 8][TcPair]` → STATUS carries the handle it issues.
    /// A primary pairs a connection it holds; a standby reserves an empty,
    /// non-emitting shadow.
    pub const PAIR_PREPARE: u8 = 1;
    /// Primary: `[handle][checkpoint_id u64]` → CHUNK… then STATUS.
    pub const CHECKPOINT_BEGIN: u8 = 2;
    /// Standby: `[handle][chunk bytes]`.
    pub const CHECKPOINT_NEXT: u8 = 3;
    /// Standby: `[handle][checkpoint_id u64]` → publish the shadow; APPLIED(0).
    pub const CHECKPOINT_COMMIT: u8 = 4;
    /// Standby: `[handle][delta frame]` → APPLIED(seq) or REJECTED.
    pub const DELTA_APPLY: u8 = 5;
    /// Primary: `[handle][acked seq u64]` → HORIZON.
    pub const DELTA_ACK: u8 = 6;
    /// Primary: `[handle]`: close the window, stop new application
    /// delivery, finish in-progress record construction.
    pub const QUIESCE_BEGIN: u8 = 7;
    /// Primary: `[handle]` → STATUS (value 1 once quiescent).
    pub const QUIESCE_STATUS: u8 = 8;
    /// Primary: `[handle]` → CUT (the final manifest).
    pub const CUT_EXPORT: u8 = 9;
    /// Standby: `[handle][cut manifest]` → STATUS (verified against shadow).
    pub const CUT_IMPORT: u8 = 10;
    /// Standby: `[handle]` → imported state and route identity ready,
    /// transmission still disabled.
    pub const EMISSION_ARM: u8 = 11;
    /// Standby: `[handle][new_epoch u32][fence_gen u32][capability 16]`:
    /// the provider rebuilds the per-flow emission token (`TcFlowToken`,
    /// naming its own anchor) and enables emission only if the verifier it
    /// was handed accepts it.
    pub const ACTIVATE: u8 = 12;
    /// `[handle]`: destroy transport keys and replicated buffers.
    pub const RETIRE: u8 = 13;
    /// `[handle]`: drop the pairing; a primary continues unprotected.
    pub const ABORT: u8 = 14;
    /// Primary: `[handle]`: the enforceable local emission-disable hook;
    /// STATUS value = the custody generation of the cutoff.
    pub const EMISSION_DISABLE: u8 = 15;
    /// `[null handle 8][flow_id 16][epoch u32][ttl_ms u32]`: suppress
    /// resets for a migrated flow. Until the tombstone expires a
    /// segment for `flow_id` that finds no live connection here is dropped
    /// silently — no RST, no new connection. A host may hold no pairing
    /// for the flow, hence the null handle. STATUS value 1 = installed;
    /// `CAPACITY` when the table is full of live tombstones (never
    /// evicted).
    pub const TOMBSTONE: u8 = 16;
    /// Standby: `[handle][challenge 32]`: its vault makes a fresh P-256
    /// recipient key for this flow and attests it (`key_vault`
    /// `ATTEST_KEY`) over the challenge → CUSTODY (`tc_custody::EVIDENCE`),
    /// then STATUS. The challenge is the transfer's, chosen by whoever
    /// decides it, so the evidence is good for that transfer alone.
    pub const CUSTODY_ATTEST: u8 = 17;
    /// Primary: `[handle][challenge 32][evidence]`: the evidence goes to the
    /// authority the provider was handed; on its verdict the provider's
    /// vault checks the evidence answers `challenge`, names an ephemeral
    /// agreement key and is signed by its signer, and wraps the flow's
    /// continuity key to that recipient, bound to the composition it
    /// attests (`KEY_WRAP`) → CUSTODY (`tc_custody::WRAPPED`), then STATUS.
    /// A refusal is STATUS `UNAUTHORIZED` (the authority's code as
    /// `reason`) or `INVALID` (`tc_custody::why`).
    pub const CUSTODY_WRAP: u8 = 18;
    /// Standby: `[handle][wrapped]`: its vault unwraps the key with the
    /// recipient CUSTODY_ATTEST made (`KEY_UNWRAP`; only that recipient, and
    /// only while its composition is the one attested, opens it) and keeps it
    /// for the flow's import → STATUS.
    pub const CUSTODY_UNWRAP: u8 = 19;
    /// A QUIC primary (the QUIC section below): `[handle][grant record]` — the durable
    /// packet-number reservation grant (`session_ctrl.rs`
    /// `CMD_SC_RESERVATION_GRANT`) a crash-continuous QUIC pairing emits
    /// under, passed to the provider's QUIC layer → STATUS.
    pub const RESERVATION_GRANT: u8 = 20;
}

/// Provider → anchor events.
pub mod tc_evt {
    /// `[op u8][status u8][reason u8][reserved u8][handle 8][value u64]
    ///  [flow_id 16]` (`TcStatus`).
    pub const STATUS: u8 = 0x81;
    /// Primary: `[handle][chunk bytes]`.
    pub const CHUNK: u8 = 0x82;
    /// Primary: `[handle][delta frame]`.
    pub const DELTA: u8 = 0x83;
    /// Standby: `[handle][checkpoint_id u64][applied seq u64]`.
    pub const APPLIED: u8 = 0x84;
    /// Standby: `[handle][reason u8]`: the stream cannot be applied; a
    /// full checkpoint is required (`tc_rej`).
    pub const REJECTED: u8 = 0x85;
    /// Primary: `[handle][acked u64][rx_limit u32][tx_limit u32]
    ///  [credits u16][flags u16]` (flags bit 0: the window is closed).
    pub const HORIZON: u8 = 0x86;
    /// Primary: `[handle][cut manifest]`.
    pub const CUT: u8 = 0x87;
    /// `[handle][kind u8][bytes]` (`tc_custody`): a standby's evidence, a
    /// primary's wrapped key.
    pub const CUSTODY: u8 = 0x88;
    /// `[handle][why u8][dir u8]` (`tc_end`): the flow ended — not a loss.
    /// The connection is over, so there is nothing to protect: a primary
    /// stops its pairing without an `ABORT` / `MIRROR` STATUS (an anchor
    /// counts no downgrade), and a standby whose shadow applied the end
    /// holds the flow's tombstone and refuses `EMISSION_ARM`, `ACTIVATE`
    /// and `CUT_IMPORT` with `tc_end::REFUSED`. On a reset the primary sends
    /// it once its standby holds the `Reset` delta (ours) or at once (the
    /// peer's); the standby sends it when it applies that delta. Either side
    /// answers a later `RETIRE` / `ABORT` with `OK` and lets the slot go.
    pub const ENDED: u8 = 0x89;
}

/// How a flow ended (`tc_evt::ENDED`).
pub mod tc_end {
    /// A reset; `dir` is whose (`MD_DIR_IN` the peer's, `MD_DIR_OUT` ours).
    pub const RESET: u8 = 1;
    /// The connection closed: both FINs exchanged and ours acknowledged,
    /// TIME-WAIT over, or a closing state's bound spent; `dir` 0.
    pub const CLOSED: u8 = 2;
    /// STATUS `reason` (with `tc_st::UNSUPPORTED`) refusing an operation on
    /// a flow that ended: there is no connection to arm, activate, import,
    /// quiesce or export.
    pub const REFUSED: u8 = 0x90;
}

/// The vault-to-vault transfer CUSTODY_* carries: opaque to an anchor, which
/// relays the standby's evidence to the primary and the primary's wrapped
/// key back, and to the authority, which decides whether this recipient may
/// receive this flow's key. No byte of either is a key.
///
/// Evidence: `[record 148][recipient_pub 65][signer_pub 65][sig_len u16]
/// [sig]` — `record` is `key_vault` `ATTEST_KEY`'s `FXHA` record for the
/// recipient key (challenge, composition digest, backend, tier, persistence,
/// suite, uses, owner namespace, commitment, public thumbprint) and `sig`
/// the signer's P-256 `r‖s` over its SHA-256. The signer is the standby
/// host's custody identity; that it is the host the transfer was decided
/// for is the authority's question, not the provider's. Wrapped: the 168-byte
/// `key_vault` `FXKW` blob of the 32-byte continuity key.
pub mod tc_custody {
    /// CUSTODY event kinds.
    pub const EVIDENCE: u8 = 1;
    pub const WRAPPED: u8 = 2;

    pub const RECORD_LEN: usize = 148;
    pub const PUB_LEN: usize = 65;
    pub const RECIPIENT: usize = RECORD_LEN;
    pub const SIGNER: usize = RECIPIENT + PUB_LEN;
    pub const SIG_LEN: usize = SIGNER + PUB_LEN;
    pub const SIG: usize = SIG_LEN + 2;
    pub const SIG_MAX: usize = 64;
    pub const EVIDENCE_MIN: usize = SIG + 1;
    pub const EVIDENCE_MAX: usize = SIG + SIG_MAX;
    pub const WRAPPED_LEN: usize = 4 + 65 + 32 + 12 + 7 + 32 + 16;

    /// The `FXHA` record's fields (`key_vault::attest_key`).
    pub const R_MAGIC: [u8; 4] = *b"FXHA";
    pub const R_CHALLENGE: usize = 4;
    pub const R_COMPOSITION: usize = 36;
    pub const R_BACKEND: usize = 68;
    pub const R_TIER: usize = 69;
    pub const R_PERSISTED: usize = 70;
    pub const R_SUITE: usize = 72;
    pub const R_USAGE: usize = 76;
    pub const R_THUMBPRINT: usize = 116;
    /// `key_vault` suite P-256 and the uses a recipient must and must not
    /// have.
    pub const SUITE_P256: u16 = 1;
    pub const USAGE_AGREE: u32 = 1 << 2;
    pub const USAGE_PERSIST: u32 = 1 << 4;

    /// Why the evidence was refused (STATUS `reason` with `INVALID`).
    pub mod why {
        /// It does not parse.
        pub const EVIDENCE: u8 = 0xD1;
        /// It answers another challenge.
        pub const CHALLENGE: u8 = 0xD2;
        /// Its signature does not verify under its signer.
        pub const SIGNATURE: u8 = 0xD3;
        /// Its recipient is not an ephemeral P-256 agreement key, or its
        /// thumbprint is not the recipient's public key's.
        pub const RECIPIENT: u8 = 0xD4;
        /// No recipient is held for the flow (UNWRAP before ATTEST).
        pub const NO_RECIPIENT: u8 = 0xD5;
        /// The vault refused the wrap or the unwrap.
        pub const VAULT: u8 = 0xD6;
    }
}

/// Provider statuses (STATUS `status`).
pub mod tc_st {
    pub const OK: u8 = 0;
    pub const STALE_HANDLE: u8 = 1;
    pub const STALE_EPOCH: u8 = 2;
    pub const NOT_READY: u8 = 3;
    pub const INVALID: u8 = 4;
    pub const CAPACITY: u8 = 5;
    /// ACTIVATE refused: the token does not name the committed binding
    /// (STATUS `reason` carries the verifier's refusal code).
    pub const UNAUTHORIZED: u8 = 6;
    pub const UNSUPPORTED: u8 = 7;
}

/// REJECTED reasons: why a standby discarded its shadow.
pub mod tc_rej {
    /// A checkpoint chunk out of order, conflicting or malformed.
    pub const CHUNK: u8 = 1;
    /// The published shadow names a key the vault here does not hold.
    pub const KEYS: u8 = 2;
    /// CHECKPOINT_COMMIT of an incomplete or unvalidated record.
    pub const COMMIT: u8 = 3;
    /// A delta before any checkpoint was published.
    pub const NO_SHADOW: u8 = 4;
    /// A delta frame that does not parse.
    pub const MALFORMED: u8 = 5;
    /// A KeyUpdate the vault here could not derive.
    pub const DERIVE: u8 = 6;
    /// A delta whose transition would leave the state invalid.
    pub const TRANSITION: u8 = 7;
    /// A gap, a conflicting duplicate, a broken chain or a newer history.
    pub const ORDER: u8 = 8;
}

/// Provider capability bits, reported for the active generation. Each
/// names one enforceable surface; a provider reports only what it
/// enforces.
pub mod tc_cap {
    /// Canonical TCP checkpoint/delta codec.
    pub const TCP_CODEC: u32 = 1 << 0;
    /// Canonical TLS 1.3 established-state codec.
    pub const TLS13_CODEC: u32 = 1 << 1;
    /// QUIC 1-RTT connection-state export/import.
    pub const QUIC_CODEC: u32 = 1 << 2;
    /// The receive-ACK and outbound-emission horizon gate.
    pub const HORIZON_GATE: u32 = 1 << 3;
    /// Owner-scoped destination-bound vault transfer of continuity secrets
    /// (CUSTODY_ATTEST / WRAP / UNWRAP).
    pub const VAULT_TRANSFER: u32 = 1 << 4;
    /// Per-flow import / arm / activate.
    pub const FLOW_IMPORT_ARM: u32 = 1 << 5;
    /// Cross-host authenticated ordered remote channel.
    pub const REMOTE_CHANNEL: u32 = 1 << 6;
    /// Enforceable local emission-disable hook.
    pub const EMISSION_DISABLE: u32 = 1 << 7;
    /// Migrated-flow reset suppression (tombstones).
    pub const RESET_SUPPRESSION: u32 = 1 << 8;
    /// Authority counter/key custody (reservations, floors, transfer grants).
    pub const COUNTER_CUSTODY: u32 = 1 << 9;
    /// Native QUIC path validation after takeover.
    pub const PATH_VALIDATION: u32 = 1 << 10;
    /// A protocol adapter for an on-wire-sequence datagram protocol.
    pub const DATAGRAM_ADAPTER: u32 = 1 << 11;
    /// Every bit this version defines; a report with another is refused.
    pub const ALL: u32 = (1 << 12) - 1;
}
