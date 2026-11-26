//! Trust anchors for `tls` and `quic`: the `trust` parameter's bundle at
//! build time, and the operator's `--ca` widening of client instances at
//! launch.
//!
//! A consumer's anchors reach it one way: as concatenated DER in an
//! extended-TLV blob of its module entry. The deployment's set travels
//! under tag 12, resolved from `trust: "${file:<path>}"` when the graph is
//! built; the operator's set travels under tag 16, appended to an
//! already-built config blob by `fluxor run --ca` / `fluxor exec --ca`. A
//! module feeds both into one table through one walk; the tls module names
//! the origin — deployment, operator, or both — on its accepted-chain log
//! line.
//!
//! A module takes tag 16 wherever it finds it, whatever the instance's
//! mode, so the client-mode-only rule the operator channel is sold on is
//! enforced here, in [`append_operator_anchors`], and nowhere else.
//!
//! The limits here mirror the tls table: [`MAX_ANCHORS`] slots of at most
//! [`MAX_ANCHOR_DER`] bytes each, checked while the graph is built, so a
//! bundle past either names the file rather than reaching a module that
//! would refuse to construct. A quic instance holds the same eight slots
//! but only 1024 bytes in each, so an anchor between that and
//! [`MAX_ANCHOR_DER`] passes this check and is refused there.

use std::path::Path;

use fluxor_contracts::boot_config::{self, BootConfigSpec};
use fluxor_contracts::graph::{self, GraphSpec, ModuleRecord};

use crate::hash::fnv1a_hash;

/// Most anchors one instance holds — `MAX_ANCHORS` in the tls and quic
/// modules. A private domain has one; a rotation has two.
pub const MAX_ANCHORS: usize = 8;

/// Longest anchor the tls module retains (`MAX_CERT_LEN`). The quic module
/// retains 1024 and refuses a longer one when it constructs.
pub const MAX_ANCHOR_DER: usize = 2048;

/// Extended-TLV tag of the deployment's anchors (`trust`).
pub const TAG_TRUST: u8 = 12;

/// Extended-TLV tag of the operator's anchors (`--ca`).
pub const TAG_OPERATOR_TRUST: u8 = 16;

/// Extended-TLV tag of `trust: "system"`: one byte, 1. It carries no
/// anchors BECAUSE there are none to carry — the platform verifies and
/// answers, and no anchor DER crosses the boundary. A module seeing this tag
/// asks the `trust` contract instead of its own verifier.
pub const TAG_TRUST_SYSTEM: u8 = 17;

/// The value that names the platform's own trust store, served by the
/// `trust` contract.
pub const SYSTEM_SPEC: &str = "system";

/// The path a `${file:<path>}` source spec names; `None` for any other
/// shape — including [`SYSTEM_SPEC`], which names the platform's verifier
/// rather than a file and is handled before this is reached. The spec form
/// is the build-time one, embedded by the builder; a bare path is a file the
/// module reads at runtime and never reaches here.
pub fn file_source(spec: &str) -> Option<&str> {
    let inner = spec.strip_prefix("${file:")?.strip_suffix('}')?;
    if inner.is_empty() || inner.contains('}') {
        return None;
    }
    Some(inner)
}

/// Extract DER certificates from a PEM bundle. Anything outside
/// `BEGIN/END CERTIFICATE` markers is ignored; a block whose base64 does
/// not decode is skipped.
pub fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(der) = crate::b64::decode(&b64) {
                out.push(der);
            }
            in_cert = false;
        } else if in_cert {
            b64.push_str(line);
        }
    }
    out
}

/// The first PEM block in `text` labelled one of `labels`, decoded.
pub fn pem_block(text: &str, labels: &[&str]) -> Option<Vec<u8>> {
    let mut label: Option<&str> = None;
    let mut b64 = String::new();
    for line in text.lines() {
        let line = line.trim();
        match label {
            None => {
                label = labels.iter().copied().find(|l| {
                    line.strip_prefix("-----BEGIN ")
                        .and_then(|r| r.strip_suffix("-----"))
                        == Some(*l)
                });
            }
            Some(l) => {
                if line
                    .strip_prefix("-----END ")
                    .and_then(|r| r.strip_suffix("-----"))
                    == Some(l)
                {
                    return crate::b64::decode(&b64);
                }
                b64.push_str(line);
            }
        }
    }
    None
}

/// A certificate or private-key file as the DER a `tls` / `quic` instance
/// embeds: PEM (the first block labelled one of `labels`) or DER as is.
pub fn read_der_file(path: &Path, labels: &[&str]) -> Result<Vec<u8>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("'{}' is empty", path.display()));
    }
    let Some(text) = std::str::from_utf8(&bytes)
        .ok()
        .filter(|t| t.contains("-----BEGIN "))
    else {
        return Ok(bytes);
    };
    if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Err(format!(
            "'{}' holds an encrypted private key; give the key unencrypted",
            path.display()
        ));
    }
    pem_block(text, labels).ok_or_else(|| {
        format!(
            "'{}' is PEM with no decodable {} block",
            path.display(),
            labels.join(" / ")
        )
    })
}

/// PEM labels a `cert_file` may hold.
pub const CERT_LABELS: &[&str] = &["CERTIFICATE"];
/// PEM labels a `key_file` may hold: PKCS#8, SEC1 or PKCS#1.
pub const KEY_LABELS: &[&str] = &["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"];

/// Split concatenated DER into its top-level SEQUENCEs. Every byte must
/// belong to a well-formed SEQUENCE with a definite, minimal length: a
/// trailing fragment is refused rather than dropped, since a file with a
/// truncated certificate at its end is a file somebody edited by hand.
pub fn der_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] != 0x30 {
            return Err(format!(
                "byte {pos} is 0x{:02x}, not the start of a DER SEQUENCE",
                bytes[pos]
            ));
        }
        let (len, len_bytes) = der_length(bytes, pos + 1)
            .ok_or_else(|| format!("certificate at byte {pos} has a malformed DER length"))?;
        let total = 1 + len_bytes + len;
        if pos + total > bytes.len() {
            return Err(format!(
                "certificate at byte {pos} claims {total} bytes but only {} remain",
                bytes.len() - pos
            ));
        }
        out.push(bytes[pos..pos + total].to_vec());
        pos += total;
    }
    Ok(out)
}

/// DER length at `pos`: `(length, bytes the length field took)`. Short
/// form below 128, else the shortest long form (X.690 §10.1).
fn der_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)?;
    match first {
        0..=0x7F => Some((first as usize, 1)),
        0x81 => {
            let len = *data.get(pos + 1)? as usize;
            (len >= 0x80).then_some((len, 2))
        }
        0x82 => {
            let hi = *data.get(pos + 1)? as usize;
            let lo = *data.get(pos + 2)? as usize;
            (hi != 0).then_some(((hi << 8) | lo, 3))
        }
        _ => None,
    }
}

/// The certificates in a bundle file's bytes: PEM when a `CERTIFICATE`
/// block is present, else concatenated DER. Empty is an error — a file
/// with no anchor in it is not a trust decision.
pub fn parse_bundle(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.is_empty() {
        return Err("the file is empty".to_string());
    }
    let certs = match std::str::from_utf8(bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            let certs = pem_certificates(text);
            if certs.is_empty() {
                return Err("no CERTIFICATE block decodes".to_string());
            }
            certs
        }
        _ => der_certificates(bytes)?,
    };
    check_limits(&certs)?;
    Ok(certs)
}

/// The module's table limits, applied to a set about to be embedded.
pub fn check_limits(certs: &[Vec<u8>]) -> Result<(), String> {
    if certs.len() > MAX_ANCHORS {
        return Err(format!(
            "{} anchors, over the {MAX_ANCHORS} an instance holds",
            certs.len()
        ));
    }
    for (i, der) in certs.iter().enumerate() {
        if der.len() > MAX_ANCHOR_DER {
            return Err(format!(
                "anchor {} is {} bytes, over the {MAX_ANCHOR_DER}-byte limit",
                i + 1,
                der.len()
            ));
        }
    }
    Ok(())
}

/// Read and parse a bundle file. The error names the file; the caller
/// names the instance.
pub fn load_bundle(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    parse_bundle(&bytes).map_err(|e| format!("'{}': {e}", path.display()))
}

/// One extended-TLV entry: `[tag][0x00][len_hi][len_lo][concatenated DER]`.
pub fn encode_ext(tag: u8, certs: &[Vec<u8>]) -> Vec<u8> {
    let n: usize = certs.iter().map(Vec::len).sum();
    debug_assert!(n <= u16::MAX as usize);
    let mut out = Vec::with_capacity(4 + n);
    out.push(tag);
    out.push(0x00);
    out.push((n >> 8) as u8);
    out.push(n as u8);
    for der in certs {
        out.extend_from_slice(der);
    }
    out
}

// ---------------------------------------------------------------------------
// The operator channel: widening client instances of a built config blob
// ---------------------------------------------------------------------------

/// What `--ca` did to a blob.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Widened {
    /// Module ids of the client instances that gained the anchors.
    pub instances: Vec<u16>,
}

/// Append `anchors` to every CLIENT-MODE `tls` and `quic` instance in a
/// built config blob, under [`TAG_OPERATOR_TRUST`], and return the
/// re-sealed blob.
///
/// A server instance is never touched, whether or not it verifies its
/// clients: whoever controls a launch controls its arguments, and an
/// operator channel that could add a client-certificate authority to a
/// `verify_peer` server would be an mTLS bypass. An instance whose table
/// would overflow fails the whole operation, naming the instance; an
/// instance whose configured tag-12 blob does not split into certificates
/// counts as a full table, and so fails it the same way.
pub fn append_operator_anchors(
    blob: &[u8],
    anchors: &[Vec<u8>],
) -> Result<(Vec<u8>, Widened), String> {
    if anchors.is_empty() {
        return Err("no anchors to append".to_string());
    }
    check_limits(anchors)?;
    let tls_hash = fnv1a_hash(b"tls");
    let quic_hash = fnv1a_hash(b"quic");
    let ext = encode_ext(TAG_OPERATOR_TRUST, anchors);
    extend_entries(blob, &mut |name_hash, id, params| {
        // The mode tag and its default differ per module: tls tag 1
        // (default client), quic tag 2 (default server).
        let client = if name_hash == tls_hash {
            basic_param_u8(params, 1).unwrap_or(0) == 0
        } else if name_hash == quic_hash {
            basic_param_u8(params, 2).unwrap_or(1) == 0
        } else {
            false
        };
        if !client {
            return Ok(None);
        }
        let held = ext_blob(params, TAG_TRUST)
            .map(|b| der_certificates(b).map(|c| c.len()).unwrap_or(MAX_ANCHORS))
            .unwrap_or(0);
        if held + anchors.len() > MAX_ANCHORS {
            return Err(format!(
                "module id {id}: {held} configured anchor(s) plus {} from --ca exceed the \
                 {MAX_ANCHORS} an instance holds",
                anchors.len()
            ));
        }
        Ok(Some(ext.clone()))
    })
}

/// The tls extended tags an operator identity rides: the certificate chain
/// and the private key, as `cert_file` / `key_file` put them.
pub const TAG_CERT: u8 = 10;
pub const TAG_KEY: u8 = 11;

/// The extended tags under which the builder (`${file:..}`) or a launch
/// (`fluxor exec --identity` / `--ca`) gives a value of credential param
/// `param`, in place of the param's own entry: its claims are exercised by
/// either (`Manifest::conditions_for`). Empty for any other param.
pub fn embedded_tags(param: &str) -> &'static [u8] {
    match param {
        "cert_file" => &[TAG_CERT],
        "key_file" => &[TAG_KEY],
        "trust" => &[TAG_TRUST, TAG_OPERATOR_TRUST],
        _ => &[],
    }
}
/// The longest certificate chain a tls instance holds (its
/// `MAX_CERT_CHAIN_BYTES`); a longer one refuses to construct.
pub const MAX_CHAIN_DER: usize = 3072;
/// The longest identity key a tls instance holds (its `MAX_KEY_LEN`); a
/// longer one refuses to construct.
pub const MAX_KEY_DER: usize = 2400;
/// tls's `identity_label` (basic tag 19): an identity the vault holds.
const TAG_IDENTITY_LABEL: u8 = 19;
/// tls's `cert_file` / `key_file` named by path (basic tags 6 / 7): an
/// identity the instance reads at runtime.
const TAG_CERT_PATH: u8 = 6;
const TAG_KEY_PATH: u8 = 7;
/// An env bind record (`schema::env_bind::BIND_TAG`): its first byte is the
/// tag of the param it fills.
const TAG_ENV_BIND: u8 = 0xED;

/// Give every CLIENT-MODE `tls` instance that carries no identity of its
/// own the operator's: `cert` (DER chain, leaf first) under [`TAG_CERT`]
/// and `key` (DER) under [`TAG_KEY`]. A published applet then holds no
/// operator credential — each run brings its operator's. A server instance
/// is never given one, and an instance the graph already named an identity
/// for (a certificate, a key, or a vault label) keeps it.
pub fn append_operator_identity(
    blob: &[u8],
    cert: &[u8],
    key: &[u8],
) -> Result<(Vec<u8>, Widened), String> {
    if cert.is_empty() || key.is_empty() {
        return Err("an identity needs a certificate and a key".to_string());
    }
    if cert.len() > MAX_CHAIN_DER {
        return Err(format!(
            "the certificate chain is {} bytes, over the {MAX_CHAIN_DER} a tls instance holds",
            cert.len()
        ));
    }
    if key.len() > MAX_KEY_DER {
        return Err(format!(
            "the key is {} bytes, over the {MAX_KEY_DER} a tls instance holds",
            key.len()
        ));
    }
    let mut ext = Vec::with_capacity(8 + cert.len() + key.len());
    for (tag, bytes) in [(TAG_CERT, cert), (TAG_KEY, key)] {
        ext.push(tag);
        ext.push(0x00);
        ext.push((bytes.len() >> 8) as u8);
        ext.push(bytes.len() as u8);
        ext.extend_from_slice(bytes);
    }
    extend_entries(blob, &mut |name_hash, _id, params| {
        Ok(takes_operator_identity(name_hash, params).then(|| ext.clone()))
    })
}

/// Whether [`append_operator_identity`] gives the module named by
/// `name_hash`, with packed params `params`, the operator's identity: a
/// client-mode `tls` that names no identity of its own.
pub fn takes_operator_identity(name_hash: u32, params: &[u8]) -> bool {
    let client = name_hash == fnv1a_hash(b"tls") && basic_param_u8(params, 1).unwrap_or(0) == 0;
    let named = ext_blob(params, TAG_CERT).is_some()
        || ext_blob(params, TAG_KEY).is_some()
        || basic_param_len(params, TAG_IDENTITY_LABEL).unwrap_or(0) > 0
        || basic_param_len(params, TAG_CERT_PATH).unwrap_or(0) > 0
        || basic_param_len(params, TAG_KEY_PATH).unwrap_or(0) > 0
        || basic_entries(params, TAG_ENV_BIND).any(|r| {
            r.first()
                .is_some_and(|t| *t == TAG_CERT_PATH || *t == TAG_KEY_PATH)
        });
    client && !named
}

/// Give the applet's data directory `dir` to every string param of a built
/// config blob that names it: a basic TLV entry whose value is
/// [`crate::packaging::APPLET_DATA_DIR`], or begins with it and a `/`, has
/// the placeholder replaced by `dir`. The re-sealed blob and the module ids
/// given it; none when the graph names no data directory. A value the
/// directory makes longer than one entry holds (255 bytes) is refused.
///
/// `bound` answers the byte bounds the module's schema declares for a param
/// (`(type hash, tag)`, `fluxor_abi::wire::param_schema`); a rewritten value
/// outside them is refused, as the composer refuses one at build.
pub fn give_applet_data_dir(
    blob: &[u8],
    dir: &[u8],
    bound: &dyn Fn(u32, u8) -> Option<(u32, u32)>,
) -> Result<(Vec<u8>, Widened), String> {
    rewrite_entries(blob, &mut |name_hash, id, params| {
        let Some(end) = basic_end(params) else {
            return Ok(None);
        };
        let mut out = params[..4].to_vec();
        let mut given = false;
        let mut pos = 4usize;
        while pos + 2 <= end {
            let tag = params[pos];
            if tag == 0xFF {
                break;
            }
            let len = params[pos + 1] as usize;
            let Some(value) = params.get(pos + 2..pos + 2 + len) else {
                return Ok(None);
            };
            pos += 2 + len;
            let Some(rest) = data_dir_rest(value) else {
                out.extend_from_slice(&params[pos - 2 - len..pos]);
                continue;
            };
            let n = dir.len() + rest.len();
            if n > usize::from(u8::MAX) {
                return Err(format!(
                    "module id {id}: param tag {tag} would be {n} bytes with the data \
                     directory '{}', over the 255 one param holds",
                    String::from_utf8_lossy(dir)
                ));
            }
            if let Some((min, max)) = bound(name_hash, tag) {
                if (n as u64) < u64::from(min) || (n as u64) > u64::from(max) {
                    return Err(format!(
                        "module id {id}: param tag {tag} would be {n} bytes with the data \
                         directory '{}', outside the {min}..={max} bytes its schema bounds it to",
                        String::from_utf8_lossy(dir)
                    ));
                }
            }
            out.extend_from_slice(&[tag, n as u8]);
            out.extend_from_slice(dir);
            out.extend_from_slice(rest);
            given = true;
        }
        if !given {
            return Ok(None);
        }
        // The header's advisory length covers the basic section through its
        // terminator; the terminator and every extended entry after it are
        // carried over as they were.
        let payload = u16::try_from(out.len() + 2 - 4).unwrap_or(u16::MAX);
        out[2..4].copy_from_slice(&payload.to_le_bytes());
        out.extend_from_slice(&params[pos..]);
        Ok(Some(out))
    })
}

/// Whether any module of a built config blob names the applet's data
/// directory (see [`give_applet_data_dir`]).
pub fn names_applet_data_dir(blob: &[u8]) -> Result<bool, String> {
    let cfg = boot_config::decode(blob).map_err(|e| format!("config blob refused: {e}"))?;
    let section = cfg.graph();
    let named = section
        .composed()
        .modules()
        .any(|m| basic_values(m.params).any(|v| data_dir_rest(v).is_some()));
    Ok(named)
}

/// What follows the data-directory placeholder in a param value that names
/// it: nothing, or a path from a `/`.
fn data_dir_rest(value: &[u8]) -> Option<&[u8]> {
    value
        .strip_prefix(crate::packaging::APPLET_DATA_DIR.as_bytes())
        .filter(|rest| rest.is_empty() || rest[0] == b'/')
}

/// Every basic TLV entry's value, in order.
fn basic_values(params: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = basic_end(params).unwrap_or(0);
    let mut pos = 4;
    core::iter::from_fn(move || {
        if pos + 2 > end || params[pos] == 0xFF {
            return None;
        }
        let len = params[pos + 1] as usize;
        let v = params.get(pos + 2..pos + 2 + len)?;
        pos += 2 + len;
        Some(v)
    })
}

/// An entry rewriter for [`extend_entries`]: module type hash, module index
/// and params in; the extended entry to append (or `None`) out.
type Extend<'a> = dyn FnMut(u32, u16, &[u8]) -> Result<Option<Vec<u8>>, String> + 'a;

/// Append to the module records of a built config blob and re-seal it.
/// `extend` sees each record's module type, index and params, and answers the
/// bytes to append to that record's params (an extended TLV entry), or
/// `None` to leave it as it was.
fn extend_entries(blob: &[u8], extend: &mut Extend<'_>) -> Result<(Vec<u8>, Widened), String> {
    rewrite_entries(blob, &mut |hash, id, params| {
        Ok(extend(hash, id, params)?.map(|ext| {
            let mut p = params.to_vec();
            p.extend_from_slice(&ext);
            p
        }))
    })
}

/// Rewrite the module records of a built config blob and re-seal it.
/// `rewrite` sees each record's module type, index and params, and answers
/// the record's new params, or `None` to leave it as it was. The blob is
/// decoded and re-encoded by the codec the kernel boots with: every other
/// record and section is carried over as decoded, and the new blob has its
/// own length and checksum.
fn rewrite_entries(blob: &[u8], rewrite: &mut Extend<'_>) -> Result<(Vec<u8>, Widened), String> {
    let cfg = boot_config::decode(blob).map_err(|e| format!("config blob refused: {e}"))?;
    let section = cfg.graph();
    let composed = section.composed();
    let mut widened = Widened::default();
    let mut params: Vec<Vec<u8>> = Vec::with_capacity(usize::from(composed.module_count()));
    for (i, m) in composed.modules().enumerate() {
        let id = i as u16;
        match rewrite(m.name_hash, id, m.params)? {
            Some(p) => {
                params.push(p);
                widened.instances.push(id);
            }
            None => params.push(m.params.to_vec()),
        }
    }
    let modules: Vec<ModuleRecord<'_>> = composed
        .modules()
        .zip(&params)
        .map(|(m, p)| ModuleRecord { params: p, ..m })
        .collect();
    let edges: Vec<graph::EdgeRecord> = composed.edges().collect();
    let order: Vec<u16> = composed.order().collect();
    let domains: Vec<boot_config::DomainRecord> = section.domains().collect();
    let workloads: Option<Vec<boot_config::WorkloadRecord<'_>>> =
        cfg.workloads().map(|w| w.iter().collect());
    let envelope: Option<Vec<boot_config::PoolEntry>> = cfg.envelope().map(|e| e.iter().collect());
    let demand: Option<Vec<boot_config::PoolEntry>> = cfg.demand().map(|d| d.iter().collect());
    let out = boot_config::encode(&BootConfigSpec {
        tick_us: section.tick_us,
        graph_sample_rate: section.graph_sample_rate,
        domains: &domains,
        graph: GraphSpec {
            order: &order,
            modules: &modules,
            edges: &edges,
            ..GraphSpec::default()
        },
        hardware: cfg.hardware(),
        workloads: workloads.as_deref(),
        envelope: envelope.as_deref(),
        demand: demand.as_deref(),
    })
    .map_err(|e| e.to_string())?;
    Ok((out, widened))
}

/// A one-byte value from the basic TLV section of a params blob:
/// `[0xFE][0x01][payload_len u16 LE]` then `[tag][len][value…]` entries up
/// to the `0xFF` end marker.
fn basic_param_u8(params: &[u8], want: u8) -> Option<u8> {
    basic_param(params, want)?.first().copied()
}

/// The length of a basic TLV entry's value, when the entry is present.
fn basic_param_len(params: &[u8], want: u8) -> Option<usize> {
    basic_param(params, want).map(<[u8]>::len)
}

/// Every basic TLV entry tagged `want`, in order.
fn basic_entries(params: &[u8], want: u8) -> impl Iterator<Item = &[u8]> {
    let end = basic_end(params).unwrap_or(0);
    let mut pos = 4;
    core::iter::from_fn(move || {
        while pos + 2 <= end {
            let tag = params[pos];
            if tag == 0xFF {
                return None;
            }
            let len = params[pos + 1] as usize;
            if pos + 2 + len > end {
                return None;
            }
            let at = pos;
            pos += 2 + len;
            if tag == want {
                return Some(&params[at + 2..at + 2 + len]);
            }
        }
        None
    })
}

/// A basic TLV entry's value, when the entry is present.
fn basic_param(params: &[u8], want: u8) -> Option<&[u8]> {
    let end = basic_end(params)?;
    let mut pos = 4;
    while pos + 2 <= end {
        let tag = params[pos];
        if tag == 0xFF {
            break;
        }
        let len = params[pos + 1] as usize;
        if pos + 2 + len > end {
            break;
        }
        if tag == want {
            return Some(&params[pos + 2..pos + 2 + len]);
        }
        pos += 2 + len;
    }
    None
}

/// Where the basic TLV section ends and the extended entries begin: past its
/// `0xFF 0x00` terminator, walked from the entries (the header's u16 length
/// is advisory and saturates past 64 KiB).
fn basic_end(params: &[u8]) -> Option<usize> {
    if params.len() < 4 || params[0] != 0xFE || params[1] != 0x01 {
        return None;
    }
    let mut pos = 4usize;
    while pos + 2 <= params.len() {
        if params[pos] == 0xFF {
            return Some(pos + 2);
        }
        pos += 2 + params[pos + 1] as usize;
    }
    None
}

/// The payload of the first extended entry carrying `want`, scanned the
/// way the modules scan: `[tag][0x00][len_hi][len_lo][payload]` from the
/// end of the basic section, skipping each entry with a known tag whole.
/// The known set here is the union of the tls and quic ones, 10 to 16.
fn ext_blob(params: &[u8], want: u8) -> Option<&[u8]> {
    let mut pos = basic_end(params)?;
    while pos + 4 <= params.len() {
        let tag = params[pos];
        let known = matches!(tag, 10..=16);
        if known && params[pos + 1] == 0x00 {
            let len = ((params[pos + 2] as usize) << 8) | params[pos + 3] as usize;
            let start = pos + 4;
            if start + len > params.len() {
                return None;
            }
            if tag == want {
                return Some(&params[start..start + len]);
            }
            pos = start + len;
        } else {
            pos += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid DER SEQUENCE of `n` content bytes.
    fn seq(n: usize, fill: u8) -> Vec<u8> {
        let mut v = vec![0x30];
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend_from_slice(&[0x81, n as u8]);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend(std::iter::repeat_n(fill, n));
        v
    }

    #[test]
    fn file_source_accepts_only_the_spec_form() {
        assert_eq!(file_source("${file:pki/ca.der}"), Some("pki/ca.der"));
        assert_eq!(file_source("${file:/abs/ca.pem}"), Some("/abs/ca.pem"));
        assert_eq!(file_source("pki/ca.der"), None);
        assert_eq!(file_source("${file:}"), None);
        assert_eq!(file_source("platform"), None);
        assert_eq!(file_source("${env:CA}"), None);
    }

    #[test]
    fn der_bundle_splits_and_refuses_fragments() {
        let a = seq(3, 1);
        let b = seq(200, 2);
        let mut bundle = a.clone();
        bundle.extend_from_slice(&b);
        assert_eq!(
            der_certificates(&bundle).unwrap(),
            vec![a.clone(), b.clone()]
        );
        // A truncated tail is refused, not dropped.
        let truncated = &bundle[..bundle.len() - 1];
        assert!(der_certificates(truncated).is_err());
        // Not a SEQUENCE.
        assert!(der_certificates(&[0x02, 0x01, 0x00]).is_err());
    }

    #[test]
    fn pem_bundle_is_recognised_and_limits_apply() {
        let der = seq(4, 9);
        let b64 = crate::b64::encode(&der);
        let block = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        let two = format!("{block}{block}");
        assert_eq!(parse_bundle(two.as_bytes()).unwrap().len(), 2);
        let nine = block.repeat(9);
        let err = parse_bundle(nine.as_bytes()).unwrap_err();
        assert!(err.contains("9 anchors"), "{err}");
        assert!(parse_bundle(b"").is_err());
        assert!(
            parse_bundle(b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_err()
        );
        let big = seq(MAX_ANCHOR_DER + 1, 0);
        assert!(parse_bundle(&big).unwrap_err().contains("over the"));
    }

    /// A module record of the given type at index `id`: domain 1, pre-pass
    /// set, so a re-seal that dropped either would show.
    struct Entry {
        name_hash: u32,
        id: u16,
        params: Vec<u8>,
    }

    fn entry(type_name: &str, id: u16, basic: &[(u8, u8)], ext: &[u8]) -> Entry {
        let mut body = Vec::new();
        for (tag, v) in basic {
            body.extend_from_slice(&[*tag, 1, *v]);
        }
        body.push(0xFF);
        body.push(0x00);
        let mut params = vec![0xFE, 0x01, body.len() as u8, (body.len() >> 8) as u8];
        params.extend_from_slice(&body);
        params.extend_from_slice(ext);
        Entry {
            name_hash: fnv1a_hash(type_name.as_bytes()),
            id,
            params,
        }
    }

    fn record(e: &Entry) -> ModuleRecord<'_> {
        ModuleRecord {
            name_hash: e.name_hash,
            domain: 1,
            pre_pass: true,
            step_deadline_us: 1500,
            burst_us: 9000,
            fault_policy: graph::FaultPolicy::Tolerate,
            params: &e.params,
        }
    }

    /// The record at index 0, so the entries' indices start at 1.
    const PAD: ModuleRecord<'static> = ModuleRecord {
        name_hash: 0x0BAD_CAFE,
        domain: 1,
        pre_pass: true,
        step_deadline_us: 1500,
        burst_us: 9000,
        fault_policy: graph::FaultPolicy::Tolerate,
        params: &[],
    };

    const EDGES: [graph::EdgeRecord; 1] = [graph::EdgeRecord {
        from: graph::Endpoint::New(0),
        to: graph::Endpoint::New(1),
        from_port: 2,
        to_port: 3,
        to_ctrl: true,
        class: graph::EdgeClass::CrossCore,
        buffer_group: 4,
        rate_class: 1,
        wake_on_write: false,
        retains_send: true,
        buffer_bytes: 4096,
    }];
    const DOMAINS: [boot_config::DomainRecord; 2] = [
        boot_config::DomainRecord {
            tick_us: 1000,
            tick_min_us: 500,
            tick_max_us: 4000,
            exec_mode: boot_config::ExecMode::Tick,
            adaptive_flags: boot_config::ADAPTIVE_CADENCE,
        },
        boot_config::DomainRecord {
            tick_us: 250,
            tick_min_us: 0,
            tick_max_us: 0,
            exec_mode: boot_config::ExecMode::Poll,
            adaptive_flags: 0,
        },
    ];
    const HARDWARE: [u8; 6] = [0, 0, 0, 0, 0, 0];
    const WORKLOAD: [u8; 3] = [7, 8, 9];
    const ENVELOPE: [boot_config::PoolEntry; 1] = [boot_config::PoolEntry { pool: 5, n: 33 }];
    const DEMAND: [boot_config::PoolEntry; 1] = [boot_config::PoolEntry { pool: 10, n: 2 }];

    /// A built config holding `entries` at indices 1.., with an edge, a
    /// stepping order, two domains, a hardware payload, a resident workload,
    /// an envelope and a demand section beside them, so a re-seal that lost
    /// any of them would show.
    fn blob(entries: &[Entry]) -> Vec<u8> {
        for (k, e) in entries.iter().enumerate() {
            assert_eq!(usize::from(e.id), k + 1, "an entry's id is its index");
        }
        let modules: Vec<ModuleRecord<'_>> = std::iter::once(PAD)
            .chain(entries.iter().map(record))
            .collect();
        let order = order(modules.len());
        let workloads = [boot_config::WorkloadRecord {
            idle_safe: true,
            endpoints: &[],
            blob: &WORKLOAD,
        }];
        boot_config::encode(&BootConfigSpec {
            tick_us: 1000,
            graph_sample_rate: 48_000,
            graph: GraphSpec {
                order: &order,
                modules: &modules,
                edges: &EDGES,
                ..GraphSpec::default()
            },
            domains: &DOMAINS,
            hardware: Some(&HARDWARE),
            workloads: Some(&workloads),
            envelope: Some(&ENVELOPE),
            demand: Some(&DEMAND),
        })
        .expect("encodes")
    }

    /// A stepping order that steps the last module first.
    fn order(n: usize) -> Vec<u16> {
        (0..n as u16).rev().collect()
    }

    /// Everything but the module params decodes from `after` as `blob`
    /// built it; returns each entry's `(id, params)`.
    fn reseal_kept_the_rest(after: &[u8], ids: &[u16]) -> Vec<(u16, Vec<u8>)> {
        let cfg = boot_config::decode(after).expect("the re-sealed blob decodes");
        assert_eq!(cfg.total_len(), after.len());
        let g = cfg.graph();
        assert_eq!((g.tick_us, g.graph_sample_rate), (1000, 48_000));
        let c = g.composed();
        assert_eq!(c.edges().collect::<Vec<_>>(), EDGES);
        assert_eq!(c.order().collect::<Vec<_>>(), order(ids.len() + 1));
        assert_eq!(g.domains().collect::<Vec<_>>(), DOMAINS);
        assert_eq!(cfg.hardware(), Some(&HARDWARE[..]));
        let w: Vec<_> = cfg.workloads().expect("WKLD").iter().collect();
        assert_eq!(
            w,
            [boot_config::WorkloadRecord {
                idle_safe: true,
                endpoints: &[],
                blob: &WORKLOAD
            }]
        );
        assert_eq!(
            cfg.envelope().expect("ENVL").iter().collect::<Vec<_>>(),
            ENVELOPE
        );
        assert_eq!(
            cfg.demand().expect("DMND").iter().collect::<Vec<_>>(),
            DEMAND
        );
        let modules: Vec<_> = c.modules().collect();
        assert_eq!(modules[0], PAD);
        let entries = &modules[1..];
        assert_eq!(entries.len(), ids.len());
        assert!(entries
            .iter()
            .all(|m| m.domain == 1 && m.pre_pass && m.step_deadline_us == 1500));
        assert!(entries
            .iter()
            .all(|m| m.burst_us == 9000 && m.fault_policy == graph::FaultPolicy::Tolerate));
        ids.iter()
            .zip(entries)
            .map(|(&id, m)| (id, m.params.to_vec()))
            .collect()
    }

    #[test]
    fn only_client_instances_are_widened() {
        let ca = seq(5, 7);
        let deployment = encode_ext(TAG_TRUST, std::slice::from_ref(&ca));
        let client = entry("tls", 1, &[(1, 0), (11, 2)], &deployment);
        let server = entry("tls", 2, &[(1, 1), (2, 1), (11, 2)], &deployment);
        let quic_client = entry("quic", 3, &[(2, 0), (9, 1)], &deployment);
        let quic_server = entry("quic", 4, &[(9, 1)], &deployment); // mode absent = server
        let other = entry("ip", 5, &[(1, 0)], &[]);
        let before_params: Vec<Vec<u8>> = [&client, &server, &quic_client, &quic_server, &other]
            .iter()
            .map(|e| e.params.clone())
            .collect();
        let before = blob(&[client, server, quic_client, quic_server, other]);

        let extra = vec![seq(6, 8)];
        let (after, widened) = append_operator_anchors(&before, &extra).unwrap();
        assert_eq!(widened.instances, vec![1, 3]);

        // The client records gain exactly the operator blob after their
        // deployment tag; every other record is byte-identical, and every
        // other section survives.
        let ext = encode_ext(TAG_OPERATOR_TRUST, &extra);
        let modules = reseal_kept_the_rest(&after, &[1, 2, 3, 4, 5]);
        for (i, (id, params)) in modules.iter().enumerate() {
            let widened = *id == 1 || *id == 3;
            let mut expected = before_params[i].clone();
            if widened {
                expected.extend_from_slice(&ext);
            }
            assert_eq!(params, &expected, "module {id}");
            assert_eq!(
                ext_blob(params, TAG_OPERATOR_TRUST).map(<[u8]>::to_vec),
                widened.then(|| extra[0].clone()),
                "module {id}"
            );
        }
        assert_eq!(after.len(), before.len() + 2 * ext.len());
    }

    /// The extended entries of the `n`th entry: (id, cert, key).
    fn identity_of(after: &[u8], n: usize) -> (u16, Option<Vec<u8>>, Option<Vec<u8>>) {
        let cfg = boot_config::decode(after).expect("decodes");
        let m = cfg.graph().composed().modules().nth(n + 1).expect("module");
        (
            n as u16 + 1,
            ext_blob(m.params, TAG_CERT).map(<[u8]>::to_vec),
            ext_blob(m.params, TAG_KEY).map(<[u8]>::to_vec),
        )
    }

    #[test]
    fn an_operator_identity_reaches_only_clients_that_name_none() {
        let cert = seq(40, 3);
        let key = seq(30, 4);
        let mine = {
            let mut e = vec![TAG_CERT, 0, 0, 3];
            e.extend_from_slice(&[9, 9, 9]);
            e
        };
        let bare_client = entry("tls", 1, &[(1, 0), (11, 2)], &[]);
        let server = entry("tls", 2, &[(1, 1)], &[]);
        let own_client = entry("tls", 3, &[(1, 0)], &mine);
        let labelled = entry("tls", 4, &[(1, 0), (19, 7)], &[]);
        let quic_client = entry("quic", 5, &[(2, 0)], &[]);
        let own_key = {
            let mut e = vec![TAG_KEY, 0, 0, 2];
            e.extend_from_slice(&[8, 8]);
            e
        };
        let keyed_client = entry("tls", 6, &[(1, 0)], &own_key);
        // A certificate named by path (basic tag 6), read at runtime, and a
        // key bound to the environment (an env bind record filling tag 7).
        let path_client = entry("tls", 7, &[(1, 0), (TAG_CERT_PATH, b'/')], &[]);
        let env_client = entry("tls", 8, &[(1, 0), (TAG_ENV_BIND, TAG_KEY_PATH)], &[]);
        let before = blob(&[
            bare_client,
            server,
            own_client,
            labelled,
            quic_client,
            keyed_client,
            path_client,
            env_client,
        ]);

        let (after, given) = append_operator_identity(&before, &cert, &key).unwrap();
        assert_eq!(given.instances, vec![1]);
        reseal_kept_the_rest(&after, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            identity_of(&after, 0),
            (1, Some(cert.clone()), Some(key.clone()))
        );
        assert_eq!(
            identity_of(&after, 1),
            (2, None, None),
            "a server is never given one"
        );
        assert_eq!(
            identity_of(&after, 2),
            (3, Some(vec![9, 9, 9]), None),
            "a named identity is kept"
        );
        assert_eq!(
            identity_of(&after, 3),
            (4, None, None),
            "a vault-label identity is kept"
        );
        assert_eq!(identity_of(&after, 4), (5, None, None));
        assert_eq!(
            identity_of(&after, 5),
            (6, None, Some(vec![8, 8])),
            "a named key is kept, and no second key is appended"
        );
        assert_eq!(
            identity_of(&after, 6),
            (7, None, None),
            "an identity read from a path at runtime is kept"
        );
        assert_eq!(
            identity_of(&after, 7),
            (8, None, None),
            "an identity bound to the environment is kept"
        );
        assert!(append_operator_identity(&before, &[], &key).is_err());
    }

    /// A blob the codec refuses is refused here too, naming why, and
    /// nothing is re-sealed from it.
    #[test]
    fn a_corrupt_blob_is_refused_not_resealed() {
        let mut before = blob(&[entry("tls", 1, &[(1, 0)], &[])]);
        let last = before.len() - 1;
        before[last] ^= 0x01;
        let err = append_operator_anchors(&before, &[seq(2, 9)]).unwrap_err();
        assert!(err.contains("refused"), "{err}");
    }

    #[test]
    fn an_operator_key_longer_than_an_instance_holds_is_refused() {
        let before = blob(&[entry("tls", 1, &[(1, 0)], &[])]);
        let cert = seq(40, 3);
        assert!(append_operator_identity(&before, &cert, &seq(MAX_KEY_DER - 4, 4)).is_ok());
        let err = append_operator_identity(&before, &cert, &seq(MAX_KEY_DER, 4)).unwrap_err();
        assert!(err.contains("2400"), "the limit is named: {err}");
    }

    #[test]
    fn widening_past_the_table_is_refused() {
        let eight: Vec<Vec<u8>> = (0..8).map(|i| seq(2, i)).collect();
        let deployment = encode_ext(TAG_TRUST, &eight);
        let client = entry("tls", 1, &[(1, 0)], &deployment);
        let before = blob(&[client]);
        let err = append_operator_anchors(&before, &[seq(2, 9)]).unwrap_err();
        assert!(err.contains("module id 1"), "{err}");
        assert!(err.contains("exceed"), "{err}");
    }

    /// An entry with string-valued basic params and extended bytes after
    /// the terminator.
    fn str_entry(type_name: &str, id: u16, basic: &[(u8, &[u8])], ext: &[u8]) -> Entry {
        let mut body = Vec::new();
        for (tag, v) in basic {
            body.extend_from_slice(&[*tag, v.len() as u8]);
            body.extend_from_slice(v);
        }
        body.extend_from_slice(&[0xFF, 0x00]);
        let mut params = vec![0xFE, 0x01];
        params.extend_from_slice(&(body.len() as u16).to_le_bytes());
        params.extend_from_slice(&body);
        params.extend_from_slice(ext);
        Entry {
            name_hash: fnv1a_hash(type_name.as_bytes()),
            id,
            params,
        }
    }

    /// `${applet:data_dir}` is replaced by the directory in every string
    /// param that names it, alone or before a `/`, and nowhere else; the
    /// header's advisory length follows the basic section, the extended
    /// entries after it are kept, and an entry the directory makes too long
    /// is refused.
    #[test]
    fn an_applets_data_dir_is_given_where_the_graph_names_it() {
        let ext = encode_ext(TAG_TRUST, &[seq(4, 1)]);
        let store = str_entry(
            "store",
            1,
            &[(1, b"${applet:data_dir}/store"), (2, b"keep")],
            &[],
        );
        let alone = str_entry("other", 2, &[(3, b"${applet:data_dir}")], &ext);
        let near_miss = str_entry(
            "other",
            3,
            &[(3, b"${applet:data_dir}x"), (4, b"/a/${applet:data_dir}")],
            &[],
        );
        let untouched = near_miss.params.clone();
        let before = blob(&[store, alone, near_miss]);
        let dir = b"/home/op/.local/share/tool";
        let (after, given) = give_applet_data_dir(&before, dir, &|_, _| None).unwrap();
        assert_eq!(given.instances, vec![1, 2]);
        assert!(names_applet_data_dir(&before).unwrap());
        let p = reseal_kept_the_rest(&after, &[1, 2, 3]);
        let want_store = b"/home/op/.local/share/tool/store".to_vec();
        assert_eq!(basic_param(&p[0].1, 1), Some(&want_store[..]));
        assert_eq!(basic_param(&p[0].1, 2), Some(&b"keep"[..]));
        let end = basic_end(&p[0].1).unwrap();
        assert_eq!(
            usize::from(u16::from_le_bytes([p[0].1[2], p[0].1[3]])),
            end - 4,
            "the header's length is the basic section's"
        );
        assert_eq!(basic_param(&p[1].1, 3), Some(&dir[..]));
        assert_eq!(ext_blob(&p[1].1, TAG_TRUST), Some(&seq(4, 1)[..]));
        assert_eq!(p[2].1, untouched, "a value that only resembles it is kept");

        // Nothing to give: no instance is touched.
        let plain = blob(&[str_entry("store", 1, &[(1, b"/var/lib/x")], &[])]);
        assert!(!names_applet_data_dir(&plain).unwrap());
        assert!(give_applet_data_dir(&plain, dir, &|_, _| None)
            .unwrap()
            .1
            .instances
            .is_empty());

        // A directory that makes a value longer than one entry holds.
        let long = vec![b'd'; 250];
        let e = give_applet_data_dir(&before, &long, &|_, _| None).unwrap_err();
        assert!(e.contains("over the 255 one param holds"), "{e}");

        // A rewrite past the param's schema bound is refused, naming it.
        let store_hash = fnv1a_hash(b"store");
        let bound = move |h: u32, tag: u8| (h == store_hash && tag == 1).then_some((0, 30));
        let e = give_applet_data_dir(&before, dir, &bound).unwrap_err();
        assert!(e.contains("outside the 0..=30 bytes"), "{e}");
        let fits = move |h: u32, tag: u8| (h == store_hash && tag == 1).then_some((0, 96));
        assert!(give_applet_data_dir(&before, dir, &fits).is_ok());
    }
}
