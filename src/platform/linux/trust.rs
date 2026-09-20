use fluxor::abi::contracts::trust as wire;
use fluxor::kernel::sys::errno;
use std::sync::OnceLock;

/// Where a distribution keeps the concatenated public roots, in PEM. The
/// first of these that exists wins, and `FLUXOR_CA_BUNDLE` wins over all of
/// them when it names an existing file — which is how a deployment keeping the
/// bundle elsewhere points at it, and how a test pins a known set. One file
/// is read; the per-anchor `/etc/ssl/certs` hash directory is not scanned.
const BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

struct Roots {
    verifier: Option<std::sync::Arc<rustls::client::WebPkiServerVerifier>>,
    count: usize,
}

static ROOTS: OnceLock<Roots> = OnceLock::new();

/// Load the system roots once, on the first call. A PEM entry that does not
/// decode, or that the root store rejects, is skipped, so `count` is the
/// anchors actually admitted rather than the certificates the file held.
///
/// A failure here is not fatal to the runtime: it leaves the provider present
/// but answering every VERIFY with `UNKNOWN_CA`, which is the safe direction
/// — a graph that asked for system trust and cannot have it must not fall
/// through to trusting more. The contract carries no "could not tell"
/// verdict, so the warning logged here is the only place a missing store
/// reads as anything other than a refusal.
fn roots() -> &'static Roots {
    ROOTS.get_or_init(|| {
        let mut store = rustls::RootCertStore::empty();
        let mut loaded = 0usize;
        let chosen = std::env::var("FLUXOR_CA_BUNDLE")
            .ok()
            .filter(|p| std::path::Path::new(p).is_file())
            .or_else(|| {
                BUNDLE_PATHS
                    .iter()
                    .find(|p| std::path::Path::new(p).is_file())
                    .map(|p| (*p).to_string())
            });
        if let Some(path) = chosen.as_deref() {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut reader = std::io::BufReader::new(file);
                    for entry in rustls_pemfile::certs(&mut reader) {
                        let Ok(der) = entry else { continue };
                        if store.add(der).is_ok() {
                            loaded += 1;
                        }
                    }
                }
                Err(e) => log::warn!("[trust] cannot read {path}: {e}"),
            }
        } else {
            log::warn!("[trust] no system CA bundle found; every chain will be refused");
        }
        let verifier = if loaded == 0 {
            None
        } else {
            rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(store))
                .build()
                .map_err(|e| log::warn!("[trust] cannot build the platform verifier: {e}"))
                .ok()
        };
        if let Some(path) = chosen.as_deref() {
            log::info!("[trust] system store: {loaded} anchor(s) from {path}");
        }
        Roots {
            verifier,
            count: loaded,
        }
    })
}

/// Everything a VERIFY asked, decoded from the flat arg.
struct Request<'a> {
    purpose: u8,
    name: &'a [u8],
    unix_seconds: u64,
    chain: Vec<&'a [u8]>,
    out_at: usize,
}

fn decode(arg: &[u8]) -> Option<Request<'_>> {
    let purpose = *arg.get(wire::offset::PURPOSE)?;
    let name_len = usize::from(*arg.get(wire::offset::NAME_LEN)?);
    let cert_count = usize::from(*arg.get(wire::offset::CERT_COUNT)?);
    if name_len > wire::MAX_NAME || cert_count > wire::MAX_CHAIN || cert_count == 0 {
        return None;
    }
    let seconds_at = wire::offset::UNIX_SECONDS;
    let seconds = u64::from_le_bytes(arg.get(seconds_at..seconds_at + 8)?.try_into().ok()?);
    let name = arg.get(wire::offset::NAME..wire::offset::NAME + name_len)?;
    let mut at = wire::offset::NAME + name_len;
    let mut chain = Vec::with_capacity(cert_count);
    for _ in 0..cert_count {
        let len = usize::from(u16::from_le_bytes(arg.get(at..at + 2)?.try_into().ok()?));
        at += 2;
        if len == 0 || len > wire::MAX_CERT {
            return None;
        }
        chain.push(arg.get(at..at + len)?);
        at += len;
    }
    // The caller must have left room for the answer.
    if arg.len() < at + wire::OUT_LEN {
        return None;
    }
    Some(Request {
        purpose,
        name,
        unix_seconds: seconds,
        chain,
        out_at: at,
    })
}

fn answer(arg: &mut [u8], at: usize, result: u8, checks: u8, reason: u8) {
    if let Some(out) = arg.get_mut(at..at + wire::OUT_LEN) {
        out[0] = result;
        out[1] = checks;
        out[2] = reason;
        out[3] = 0;
    }
}

/// Map a verifier error onto the contract's advisory vocabulary. rustls does
/// not promise these strings, so the mapping is best-effort by design and the
/// verdict never depends on it.
fn reason_of(error: &rustls::Error) -> u8 {
    use rustls::CertificateError as C;
    match error {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer => wire::reason::UNKNOWN_CA,
            C::NotValidForName | C::NotValidForNameContext { .. } => wire::reason::NAME_MISMATCH,
            C::Expired
            | C::ExpiredContext { .. }
            | C::NotValidYet
            | C::NotValidYetContext { .. } => wire::reason::EXPIRED,
            C::Revoked => wire::reason::REVOKED,
            C::BadEncoding
            | C::BadSignature
            | C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => wire::reason::MALFORMED,
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => wire::reason::BAD_PURPOSE,
            _ => wire::reason::OTHER,
        },
        _ => wire::reason::OTHER,
    }
}

/// The policy `WebPkiServerVerifier` applies: a path built to an admitted
/// anchor, the server name matched against the leaf's SANs (RFC 6125 — a
/// CN-only certificate does not match), validity dates against the time the
/// consumer supplied, serverAuth EKU, and RFC 5280 name constraints along the
/// path. Revocation is absent on purpose — no CRLs are given to the builder
/// and no stapled OCSP response is passed to the verify call — so its bit
/// stays clear. Reported on both answers; on a refusal it names this policy,
/// not the checks that were reached, because verification stops at the first
/// failure.
const CHECKS_APPLIED: u8 = wire::check::PATH
    | wire::check::NAME
    | wire::check::TIME
    | wire::check::EKU
    | wire::check::CONSTRAINTS;

/// PROBE and VERIFY for class 0x1D, on `handle = -1`.
///
/// Returns 1 for PROBE, 0 for a VERIFY that produced a verdict — written
/// into the caller's trailing out block, never returned in the status —
/// `EINVAL` for a handle-scoped call or an arg that does not decode, and
/// `ENOSYS` for any other opcode. A verdict is an answer: 0 is returned for
/// a refusal exactly as for a pass.
///
/// # Safety
/// `arg` points to at least `arg_len` bytes owned by the caller for the
/// duration of the call, as the provider contract requires. The buffer is
/// borrowed only for this call and the only bytes written are the four the
/// request's own header located.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if handle >= 0 {
        return errno::EINVAL;
    }
    match opcode {
        wire::PROBE => {
            // Present even when the store could not be read: a graph that
            // asked for system trust should start and then refuse chains,
            // not silently compose against a different trust source.
            1
        }
        wire::VERIFY => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let buffer = core::slice::from_raw_parts_mut(arg, arg_len);
            let Some(request) = decode(buffer) else {
                return errno::EINVAL;
            };
            let out_at = request.out_at;
            if request.purpose != wire::purpose::SERVER {
                // This provider answers for SERVER only: the verifier it
                // holds is a server-certificate verifier, so a CLIENT
                // request is refused as a purpose it does not serve rather
                // than judged under server policy.
                answer(
                    buffer,
                    out_at,
                    wire::result::REFUSED,
                    0,
                    wire::reason::BAD_PURPOSE,
                );
                return 0;
            }
            if request.unix_seconds == 0 {
                // No trusted time, and no clock of our own to substitute:
                // refuse rather than verify a chain with expiry skipped.
                answer(
                    buffer,
                    out_at,
                    wire::result::REFUSED,
                    0,
                    wire::reason::NO_TIME,
                );
                return 0;
            }
            let Some(verifier) = roots().verifier.clone() else {
                answer(
                    buffer,
                    out_at,
                    wire::result::REFUSED,
                    0,
                    wire::reason::UNKNOWN_CA,
                );
                return 0;
            };
            // A name that is not UTF-8, or that is not a DNS name or IP
            // literal the verifier can match (an empty one included), can
            // match no leaf: answer the mismatch rather than an error, since
            // the outcome for the consumer is the same refusal.
            let Ok(name) = core::str::from_utf8(request.name) else {
                answer(
                    buffer,
                    out_at,
                    wire::result::REFUSED,
                    0,
                    wire::reason::NAME_MISMATCH,
                );
                return 0;
            };
            let Ok(server_name) = rustls_pki_types::ServerName::try_from(name) else {
                answer(
                    buffer,
                    out_at,
                    wire::result::REFUSED,
                    0,
                    wire::reason::NAME_MISMATCH,
                );
                return 0;
            };
            let leaf = rustls_pki_types::CertificateDer::from(request.chain[0]);
            let intermediates: Vec<rustls_pki_types::CertificateDer<'_>> = request
                .chain
                .get(1..)
                .unwrap_or(&[])
                .iter()
                .map(|d| rustls_pki_types::CertificateDer::from(*d))
                .collect();
            let now = rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                request.unix_seconds,
            ));
            use rustls::client::danger::ServerCertVerifier;
            match verifier.verify_server_cert(
                &leaf,
                &intermediates,
                &server_name.to_owned(),
                &[],
                now,
            ) {
                Ok(_) => {
                    answer(
                        buffer,
                        out_at,
                        wire::result::TRUSTED,
                        CHECKS_APPLIED,
                        wire::reason::NONE,
                    );
                    0
                }
                Err(e) => {
                    let reason = reason_of(&e);
                    answer(
                        buffer,
                        out_at,
                        wire::result::REFUSED,
                        CHECKS_APPLIED,
                        reason,
                    );
                    0
                }
            }
        }
        _ => errno::ENOSYS,
    }
}

/// Anchors loaded, for the startup line and for tests.
pub fn anchor_count() -> usize {
    roots().count
}
