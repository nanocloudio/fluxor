use fluxor::abi::contracts::trust as wire;
use fluxor::kernel::module::user_span::UserSpan;
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

/// Everything a VERIFY asked, decoded from the request in `data`.
struct Request<'a> {
    purpose: u8,
    name: &'a [u8],
    unix_seconds: u64,
    chain: Vec<&'a [u8]>,
}

fn decode(arg: &[u8]) -> Option<Request<'_>> {
    let r = wire::parse_request(arg)?;
    Some(Request {
        purpose: r.purpose,
        name: r.name,
        unix_seconds: r.unix_seconds,
        chain: r.certs().collect(),
    })
}

fn answer(out: &mut [u8], result: u8, checks: u8, reason: u8) {
    out.copy_from_slice(&[result, checks, reason, 0]);
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

/// VERIFY for class `trust`, on `handle = -1`.
///
/// VERIFY reads the request from `data` and writes the verdict
/// `[result u8][checks u8][reason u8][0 u8]` into `arg`. Returns 0 for a
/// VERIFY that produced a verdict — never returned in the status — `EINVAL` for a handle-scoped call, an `arg` shorter than the
/// verdict or a request that does not decode, and `ENOSYS` for any other
/// opcode. A verdict is an answer: 0 is returned for a refusal exactly as
/// for a pass.
pub fn dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    if handle >= 0 {
        return errno::EINVAL;
    }
    match opcode {
        wire::VERIFY => {
            let Some(buffer) = arg.get_mut(..wire::OUT_LEN) else {
                return errno::EINVAL;
            };
            let Some(request) = decode(data.as_slice()) else {
                return errno::EINVAL;
            };
            if request.purpose != wire::purpose::SERVER {
                // This provider answers for SERVER only: the verifier it
                // holds is a server-certificate verifier, so a CLIENT
                // request is refused as a purpose it does not serve rather
                // than judged under server policy.
                answer(
                    buffer,
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
                    wire::result::REFUSED,
                    0,
                    wire::reason::NO_TIME,
                );
                return 0;
            }
            let Some(verifier) = roots().verifier.clone() else {
                answer(
                    buffer,
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
                    wire::result::REFUSED,
                    0,
                    wire::reason::NAME_MISMATCH,
                );
                return 0;
            };
            let Ok(server_name) = rustls_pki_types::ServerName::try_from(name) else {
                answer(
                    buffer,
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
