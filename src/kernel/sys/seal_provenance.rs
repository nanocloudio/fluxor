// Deciding whether a hardware-read sealing key may be believed.
//
// A shared core rather than platform code, and that placement is the point:
// the READ is per-board MMIO that cannot run anywhere but the board, while
// this DECISION is portable logic and is where the expensive mistake lives.
// Splitting them means the dangerous half is tested even on platforms whose
// driver does not exist yet — and none of the bare-metal boards run in CI,
// so anything tested only on hardware is not tested.
//
// `include!`d by `src/kernel/sys/hal.rs` and by the harness test that
// exercises it, the same way the crypto cores are shared with `tls`.

/// Where a platform's sealing key comes from — and therefore what sealing
/// is worth on it.
///
/// This is the whole reason persistence cannot be read as raising a vault's
/// isolation tier. A key sealed under something the host can also read
/// survives a restart and protects nothing from the host, which is exactly
/// what `tier::SOFTWARE` already says. The variants exist so that fact is
/// carried rather than assumed either way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealProvenance {
    /// No sealing available. A vault here holds keys in RAM and loses them
    /// on reset.
    None,
    /// A key derived from material the host can also read — a file, an
    /// environment variable, a fixed constant. Sealing works: the blob is
    /// opaque to a compromised MODULE. It is not opaque to a compromised
    /// HOST, so the vault's tier stays `SOFTWARE`.
    HostReadable,
    /// A key bound to this device and not extractable from it — fuses, OTP,
    /// a TPM's storage root. Sealing here isolates against host compromise
    /// to the extent the hardware does, and only this variant may raise the
    /// tier.
    DeviceUnique,
}

/// The marker a device-unique sealing key must carry to be believed.
///
/// A platform that reads a sealing key out of hardware — OTP fuses, a
/// one-time-programmable region, a security block — has to answer one
/// question before it may report [`SealProvenance::DeviceUnique`]: **is
/// there actually a provisioned key here, or is this what an unprogrammed
/// or mis-addressed read looks like?**
///
/// Getting that wrong is the single most expensive mistake in this file.
/// `DeviceUnique` is the only variant that RAISES a vault's tier, and the
/// tier is what `key_custody` refuses production on — so a platform that
/// claims it wrongly converts a fail-closed refusal into a silent pass, and
/// every consumer checking `tier >= DEVICE_HW` believes keys are
/// hardware-protected when they are not.
///
/// So the key is not believed on its own: it must be preceded by this
/// magic, written at provisioning time. Unprogrammed fuses read as all-zero
/// or all-one, and a mis-addressed read returns whatever else is mapped —
/// none of which is this value except by an accident of one in 2^32.
pub const SEAL_KEY_MAGIC: [u8; 4] = [0x4B, 0x53, 0x4B, 0x31]; // "KSK1"

/// Fewest bytes of key material a hardware key may carry: 224 bits.
///
/// The floor is what the tightest real part leaves, not a round number.
/// BCM2712's customer OTP is eight 32-bit rows — 32 bytes — and the magic
/// must live in-band, since it is the guard against a mis-addressed read;
/// that leaves 28 for the key. 224 bits of provisioned entropy is far
/// beyond the 128-bit floor everything else in this ecosystem targets, so
/// naming the real minimum costs nothing a caller depends on.
///
/// A platform whose key is this short derives its working seal key by
/// domain-separated expansion — `SHA-256(context || raw_key)` — AFTER this
/// rule has validated the raw bytes, never before: a KDF run first would
/// launder unprogrammed zeros into entropy-looking output and defeat the
/// degenerate-key check below.
pub const MIN_DEVICE_KEY_BYTES: usize = 28;

/// Decide a provenance from what a hardware key read produced.
///
/// Split out from any particular platform, and unit-tested, DELIBERATELY.
/// The read itself is per-board MMIO that cannot run anywhere but the board;
/// this decision is portable logic, it is where the dangerous mistake lives,
/// and separating them means the dangerous half is tested even on platforms
/// whose driver does not exist yet.
///
/// `read_ok` is whether the hardware read succeeded at all. `blob` is
/// [`SEAL_KEY_MAGIC`] followed by the key material.
///
/// Every path that is not "a read succeeded and produced a magic-tagged,
/// non-degenerate key" answers [`SealProvenance::None`]. There is no
/// half-credit: `HostReadable` would be a claim about a key this function
/// never saw.
#[must_use]
pub fn provenance_from_hardware_key(read_ok: bool, blob: &[u8]) -> SealProvenance {
    if !read_ok {
        return SealProvenance::None;
    }
    if blob.len() < SEAL_KEY_MAGIC.len() + MIN_DEVICE_KEY_BYTES {
        return SealProvenance::None;
    }
    let (magic, key) = blob.split_at(SEAL_KEY_MAGIC.len());
    if magic != SEAL_KEY_MAGIC {
        return SealProvenance::None;
    }
    // Hardware keys live in 32-bit rows, and a key that is not a whole
    // number of rows is not a hardware key this rule understands — refused
    // rather than checked partially, because the unchecked tail would be
    // the part a wrong length was hiding.
    if !key.len().is_multiple_of(4) {
        return SealProvenance::None;
    }
    // Unprogrammed OTP reads as all-zero on some parts and all-one on
    // others — and OTP is blown ROW BY ROW, so an interrupted provisioning
    // run leaves some rows programmed and the rest degenerate. A whole-key
    // check misses that: magic plus two real rows plus five zero rows is
    // "not all zero" while carrying a fraction of the entropy the tier
    // claims. So the check is per row, over EVERY row of the key material:
    // any all-zero or all-one row is a provisioning failure worth failing
    // closed on. The false-reject cost on a genuinely random key is
    // rows x 2^-31 — negligible — and checked AFTER the magic because a
    // device whose magic matched but whose key is degenerate is a
    // provisioning failure, not a device without a key.
    if key
        .chunks_exact(4)
        .any(|row| row.iter().all(|b| *b == 0x00) || row.iter().all(|b| *b == 0xFF))
    {
        return SealProvenance::None;
    }
    SealProvenance::DeviceUnique
}

