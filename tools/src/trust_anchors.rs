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

use crate::hash::{crc16_ccitt, fnv1a_hash};

/// The FXWR config-blob magic (`kernel::config::MAGIC_CONFIG`), the one
/// definition the writer (`config::MAGIC_LEGACY`) and the re-sealer share.
pub const FXWR_MAGIC: u32 = 0x5257_5846;

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

/// The value that names the platform's own trust store. Spelled `system`
/// and not `platform`: `trust: "platform"` already means an ISR trust LEVEL
/// on a module entry (`tools/src/board.rs`), and reusing the literal would
/// make two unrelated things read the same in a graph.
pub const SYSTEM_SPEC: &str = "system";

/// The path a `${file:<path>}` source spec names; `None` for any other
/// shape — including [`SYSTEM_SPEC`], which names the platform's verifier
/// rather than a file and is handled before this is reached. The spec form
/// is the only file shape accepted: a bare path in a checked-in graph states
/// no indirection.
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

/// Size of the FXWR header (`kernel::config::read_config_from_slice`).
const HEADER_SIZE: usize = 16;
/// Size of the graph section that follows the module section: a 4-byte
/// header, `MAX_GRAPH_EDGES` (128) edges of 12 bytes, and four 4-byte
/// domain-metadata entries (`kernel::config::GRAPH_SECTION_SIZE`).
const GRAPH_SECTION_SIZE: usize = 4 + 128 * 12 + 4 * 4;
/// Per-entry sizes of the hardware section, after its 6-byte header
/// (spi, i2c, gpio, pio, reserved, uart counts).
const SPI_CONFIG_BIN_SIZE: usize = 8;
const I2C_CONFIG_BIN_SIZE: usize = 8;
const UART_CONFIG_BIN_SIZE: usize = 8;
const GPIO_CONFIG_BIN_SIZE: usize = 5;
const PIO_CONFIG_BIN_SIZE: usize = 4;
/// Module-entry header: entry_length u32, name_hash u32, id u8, meta u8.
const ENTRY_HEADER: usize = 10;

/// What `--ca` did to a blob.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Widened {
    /// Module ids of the client instances that gained the anchors.
    pub instances: Vec<u8>,
}

/// Append `anchors` to every CLIENT-MODE `tls` and `quic` instance in a
/// built FXWR config blob, under [`TAG_OPERATOR_TRUST`], and return the
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
    if blob.len() < HEADER_SIZE + 6 {
        return Err("config blob too short".to_string());
    }
    if u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) != FXWR_MAGIC {
        return Err("config blob has no FXWR header".to_string());
    }
    let module_count = blob[HEADER_SIZE] as usize;
    let section_size = u32::from_le_bytes([
        blob[HEADER_SIZE + 2],
        blob[HEADER_SIZE + 3],
        blob[HEADER_SIZE + 4],
        blob[HEADER_SIZE + 5],
    ]) as usize;
    let entries_start = HEADER_SIZE + 6;
    let entries_end = entries_start + section_size;
    if entries_end > blob.len() {
        return Err("module section runs past the blob".to_string());
    }

    let tls_hash = fnv1a_hash(b"tls");
    let quic_hash = fnv1a_hash(b"quic");
    let ext = encode_ext(TAG_OPERATOR_TRUST, anchors);

    let mut entries: Vec<u8> = Vec::with_capacity(section_size + ext.len() * module_count);
    let mut widened = Widened::default();
    let mut off = entries_start;
    for _ in 0..module_count {
        if off + ENTRY_HEADER > entries_end {
            return Err("module entry header runs past the section".to_string());
        }
        let entry_len =
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        if entry_len < ENTRY_HEADER || off + entry_len > entries_end {
            return Err("module entry length out of range".to_string());
        }
        let entry = &blob[off..off + entry_len];
        let name_hash = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let id = entry[8];
        let params = &entry[ENTRY_HEADER..];
        // The mode tag and its default differ per module: tls tag 1
        // (default client), quic tag 2 (default server).
        let client = if name_hash == tls_hash {
            basic_param_u8(params, 1).unwrap_or(0) == 0
        } else if name_hash == quic_hash {
            basic_param_u8(params, 2).unwrap_or(1) == 0
        } else {
            false
        };
        if client {
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
            let new_len = entry_len + ext.len();
            entries.extend_from_slice(&(new_len as u32).to_le_bytes());
            entries.extend_from_slice(&entry[4..]);
            entries.extend_from_slice(&ext);
            widened.instances.push(id);
        } else {
            entries.extend_from_slice(entry);
        }
        off += entry_len;
    }

    // Re-seal: the body the header's CRC covers is the header tail, the
    // module section, the graph section and the hardware section; the
    // adaptive post-body and the section chain after it are copied as
    // they were.
    let hw_off = entries_end + GRAPH_SECTION_SIZE;
    if blob.len() < hw_off + 6 {
        return Err("hardware section header runs past the blob".to_string());
    }
    let hw = &blob[hw_off..hw_off + 6];
    let hw_size = 6
        + hw[0] as usize * SPI_CONFIG_BIN_SIZE
        + hw[1] as usize * I2C_CONFIG_BIN_SIZE
        + hw[2] as usize * GPIO_CONFIG_BIN_SIZE
        + hw[3] as usize * PIO_CONFIG_BIN_SIZE
        + hw[5] as usize * UART_CONFIG_BIN_SIZE;
    let body_end = hw_off + hw_size;
    if body_end > blob.len() {
        return Err("hardware section runs past the blob".to_string());
    }

    let mut out = Vec::with_capacity(blob.len() + ext.len() * widened.instances.len());
    out.extend_from_slice(&blob[..HEADER_SIZE]);
    out.push(blob[HEADER_SIZE]);
    out.push(blob[HEADER_SIZE + 1]);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.extend_from_slice(&entries);
    out.extend_from_slice(&blob[entries_end..body_end]);
    let checksum = crc16_ccitt(&out[8..]);
    out[6..8].copy_from_slice(&checksum.to_le_bytes());
    out.extend_from_slice(&blob[body_end..]);
    Ok((out, widened))
}

/// A one-byte value from the basic TLV section of a params blob:
/// `[0xFE][0x01][payload_len u16 LE]` then `[tag][len][value…]` entries up
/// to the `0xFF` end marker.
fn basic_param_u8(params: &[u8], want: u8) -> Option<u8> {
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
        if tag == want && len >= 1 {
            return Some(params[pos + 2]);
        }
        pos += 2 + len;
    }
    None
}

/// Where the basic TLV section ends and the extended entries begin.
fn basic_end(params: &[u8]) -> Option<usize> {
    if params.len() < 4 || params[0] != 0xFE || params[1] != 0x01 {
        return None;
    }
    let payload_len = params[2] as usize | ((params[3] as usize) << 8);
    let end = 4 + payload_len;
    (end <= params.len()).then_some(end)
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

    /// A minimal FXWR blob: header, module section with the given entries,
    /// an empty graph section, an empty hardware section, the 16-byte
    /// adaptive post-body and a trailing section-chain payload.
    fn blob(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&FXWR_MAGIC.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(entries.len() as u8);
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let section: usize = entries.iter().map(Vec::len).sum();
        out.push(entries.len() as u8);
        out.push(0);
        out.extend_from_slice(&(section as u32).to_le_bytes());
        for e in entries {
            out.extend_from_slice(e);
        }
        out.extend_from_slice(&[0u8; GRAPH_SECTION_SIZE]);
        out.extend_from_slice(&[0u8; 6]);
        let crc = crc16_ccitt(&out[8..]);
        out[6..8].copy_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(b"TAIL");
        out
    }

    fn entry(type_name: &str, id: u8, basic: &[(u8, u8)], ext: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, v) in basic {
            body.extend_from_slice(&[*tag, 1, *v]);
        }
        body.push(0xFF);
        body.push(0x00);
        let mut params = vec![0xFE, 0x01, body.len() as u8, (body.len() >> 8) as u8];
        params.extend_from_slice(&body);
        params.extend_from_slice(ext);
        let mut e = Vec::new();
        e.extend_from_slice(&((ENTRY_HEADER + params.len()) as u32).to_le_bytes());
        e.extend_from_slice(&fnv1a_hash(type_name.as_bytes()).to_le_bytes());
        e.push(id);
        e.push(0);
        e.extend_from_slice(&params);
        e
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
        let before = blob(&[
            client.clone(),
            server.clone(),
            quic_client.clone(),
            quic_server.clone(),
            other.clone(),
        ]);

        let extra = vec![seq(6, 8)];
        let (after, widened) = append_operator_anchors(&before, &extra).unwrap();
        assert_eq!(widened.instances, vec![1, 3]);

        // Header counts and the tail survive; the section grew by exactly
        // two operator blobs; the CRC re-seals the new body.
        let ext = encode_ext(TAG_OPERATOR_TRUST, &extra);
        let section = u32::from_le_bytes([after[18], after[19], after[20], after[21]]) as usize;
        let expected: usize = [&client, &server, &quic_client, &quic_server, &other]
            .iter()
            .map(|e| e.len())
            .sum::<usize>()
            + 2 * ext.len();
        assert_eq!(section, expected);
        assert!(after.ends_with(b"TAIL"));
        let body_end = after.len() - 16 - 4;
        let crc = crc16_ccitt(&after[8..body_end]);
        assert_eq!(u16::from_le_bytes([after[6], after[7]]), crc);

        // The client entries carry the operator tag after their deployment
        // tag; the server entries are byte-identical.
        let mut off = HEADER_SIZE + 6;
        let mut seen = Vec::new();
        for _ in 0..5 {
            let len =
                u32::from_le_bytes([after[off], after[off + 1], after[off + 2], after[off + 3]])
                    as usize;
            let e = &after[off..off + len];
            let params = &e[ENTRY_HEADER..];
            seen.push((
                e[8],
                ext_blob(params, TAG_OPERATOR_TRUST).map(<[u8]>::to_vec),
            ));
            off += len;
        }
        assert_eq!(seen[0], (1, Some(extra[0].clone())));
        assert_eq!(seen[1], (2, None));
        assert_eq!(seen[2], (3, Some(extra[0].clone())));
        assert_eq!(seen[3], (4, None));
        assert_eq!(seen[4], (5, None));
        assert_eq!(
            &after[off..off + 2 * ext.len() - 2 * ext.len()],
            &[] as &[u8]
        );
        let server_after = {
            let mut o = HEADER_SIZE + 6;
            let l0 =
                u32::from_le_bytes([after[o], after[o + 1], after[o + 2], after[o + 3]]) as usize;
            o += l0;
            let l1 =
                u32::from_le_bytes([after[o], after[o + 1], after[o + 2], after[o + 3]]) as usize;
            after[o..o + l1].to_vec()
        };
        assert_eq!(server_after, server);
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
}
