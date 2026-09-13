//! Remote OCI distribution (distribution-spec v2) push/pull between the
//! local store and a registry (e.g. `registry.nanocloud.io`).
//!
//! This is the ONE place in the tools tree that touches the network for
//! artifacts: the offline-first invariant (`standards/dependencies.md`)
//! holds because every consume path reads only the local store — network
//! happens exclusively in the explicit `fluxor store push` / `fluxor
//! store pull` verbs that call into this module.
//!
//! Wire model: plain distribution-spec v2 against a stock registry —
//! `GET/HEAD /v2/<repo>/manifests/<ref>`, `GET/HEAD /v2/<repo>/blobs/<digest>`,
//! `POST /v2/<repo>/blobs/uploads/` + monolithic `PUT`. Every pulled byte
//! is digest-verified before it lands in the store; every push sends
//! content the local store already addresses by digest, so a re-push is
//! a set of cheap `HEAD` hits. Tags are mutable pointers on the wire
//! exactly as they are locally; digests are the identity.
//!
//! TLS: rustls against the webpki roots, with `--ca <pem>` adding a
//! private trust anchor (the nanocloud deployment CA that signs
//! `registry.nanocloud.io:5000`'s leaf). `http://` is honoured only when
//! the reference says so explicitly — the default scheme is `https`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::oci_store::{Descriptor, ImageManifest, OciStore, MT_OCI_MANIFEST};

// ── Remote reference ──────────────────────────────────────────────────

/// A parsed remote artifact reference:
/// `[scheme://]host[:port]/<repo>[:tag|@sha256:<hex>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRef {
    /// `true` = plain HTTP (explicit `http://` only).
    pub plain_http: bool,
    pub host: String,
    pub port: u16,
    /// Repository path (`fluxor/lattice-cdc`).
    pub repo: String,
    /// Tag or `sha256:<hex>` digest.
    pub reference: String,
}

impl RemoteRef {
    pub fn parse(s: &str) -> Result<RemoteRef> {
        let (plain_http, rest) = if let Some(r) = s.strip_prefix("http://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("https://") {
            (false, r)
        } else {
            (false, s)
        };
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| Error::Remote(format!("remote ref '{s}' has no repository path")))?;
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| Error::Remote(format!("bad port in '{s}'")))?,
            ),
            _ => (authority.to_string(), if plain_http { 80 } else { 443 }),
        };
        if host.is_empty() {
            return Err(Error::Remote(format!("remote ref '{s}' has no host")));
        }
        // Digest reference (`@sha256:...`) wins over a tag (`:tag`); the
        // tag split must not eat the digest's own colon.
        let (repo, reference) = if let Some((r, d)) = path.split_once('@') {
            (r.to_string(), d.to_string())
        } else if let Some((r, t)) = path.rsplit_once(':') {
            (r.to_string(), t.to_string())
        } else {
            (path.to_string(), "latest".to_string())
        };
        if repo.is_empty() || reference.is_empty() {
            return Err(Error::Remote(format!(
                "remote ref '{s}' needs '<host>/<repo>[:tag|@sha256:...]'"
            )));
        }
        Ok(RemoteRef {
            plain_http,
            host,
            port,
            repo,
            reference,
        })
    }

    fn base(&self) -> String {
        format!("/v2/{}", self.repo)
    }
}

// ── Transport ─────────────────────────────────────────────────────────

enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => match s.read(buf) {
                // rustls surfaces a close without close_notify as an
                // error; a body bounded by Content-Length never hits
                // this, and a read-to-EOF body treats it as EOF.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
                r => r,
            },
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// Client for one registry authority. One TCP+TLS connection per
/// request (`Connection: close`) — artifact counts are small and the
/// simplicity keeps the response framing unambiguous.
pub struct RemoteClient {
    plain_http: bool,
    host: String,
    port: u16,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

/// One parsed HTTP response.
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

const MAX_REDIRECTS: usize = 3;
/// Upper bound on any single response body (manifests are KBs; blobs are
/// graph images / firmware, well under this).
const MAX_BODY: usize = 256 * 1024 * 1024;

impl RemoteClient {
    /// Build a client for `remote`. `extra_ca_pem` adds trust anchors
    /// (PEM, possibly several certificates) beyond the webpki roots.
    pub fn new(remote: &RemoteRef, extra_ca_pem: Option<&Path>) -> Result<RemoteClient> {
        let tls_config = if remote.plain_http {
            None
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(pem_path) = extra_ca_pem {
                let pem = std::fs::read_to_string(pem_path)?;
                let mut added = 0usize;
                for der in pem_certificates(&pem) {
                    roots
                        .add(rustls::pki_types::CertificateDer::from(der))
                        .map_err(|e| {
                            Error::Remote(format!(
                                "bad CA certificate in {}: {e}",
                                pem_path.display()
                            ))
                        })?;
                    added += 1;
                }
                if added == 0 {
                    return Err(Error::Remote(format!(
                        "no certificates found in {}",
                        pem_path.display()
                    )));
                }
            }
            Some(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        };
        Ok(RemoteClient {
            plain_http: remote.plain_http,
            host: remote.host.clone(),
            port: remote.port,
            tls_config,
        })
    }

    fn connect(&self) -> Result<Conn> {
        let sock = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|e| Error::Remote(format!("connect {}:{}: {e}", self.host, self.port)))?;
        if self.plain_http {
            return Ok(Conn::Plain(sock));
        }
        let cfg = self.tls_config.as_ref().expect("tls config for https");
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|e| Error::Remote(format!("bad server name '{}': {e}", self.host)))?;
        let conn = rustls::ClientConnection::new(cfg.clone(), name)
            .map_err(|e| Error::Remote(format!("tls setup: {e}")))?;
        Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
    }

    /// Issue one request; follows same-authority redirects (registry blob
    /// GETs commonly 307 to a storage path).
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response> {
        let mut path = path.to_string();
        for _ in 0..=MAX_REDIRECTS {
            let resp = self.request_once(method, &path, headers, body)?;
            if matches!(resp.status, 301 | 302 | 307 | 308) {
                let loc = resp
                    .header("location")
                    .ok_or_else(|| Error::Remote("redirect without Location".into()))?;
                path = self.rebase_location(loc)?;
                continue;
            }
            return Ok(resp);
        }
        Err(Error::Remote(format!(
            "too many redirects for {method} {path}"
        )))
    }

    /// Resolve a redirect Location to a same-authority path. Cross-host
    /// redirects are refused rather than silently followed: the trust
    /// decision was made for this authority.
    fn rebase_location(&self, loc: &str) -> Result<String> {
        if let Some(rest) = loc
            .strip_prefix("https://")
            .or_else(|| loc.strip_prefix("http://"))
        {
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let host_only = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
            if host_only != self.host {
                return Err(Error::Remote(format!(
                    "refusing cross-host redirect to '{loc}'"
                )));
            }
            Ok(format!("/{path}"))
        } else if loc.starts_with('/') {
            Ok(loc.to_string())
        } else {
            Err(Error::Remote(format!(
                "unsupported redirect target '{loc}'"
            )))
        }
    }

    fn request_once(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response> {
        let mut conn = self.connect()?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host);
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.map_or(0, <[u8]>::len)
        ));
        conn.write_all(req.as_bytes())?;
        if let Some(b) = body {
            conn.write_all(b)?;
        }
        conn.flush()?;
        read_response(&mut conn, method == "HEAD")
    }
}

/// Extract DER certificates from a PEM bundle. Anything outside
/// `BEGIN/END CERTIFICATE` markers is ignored.
fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64) {
                out.push(der);
            }
            in_cert = false;
        } else if in_cert {
            b64.push_str(line);
        }
    }
    out
}

/// Read one HTTP/1.1 response. `head` suppresses body reading (HEAD
/// responses carry Content-Length but no body).
fn read_response(conn: &mut Conn, head: bool) -> Result<Response> {
    // Header block first: read until CRLFCRLF.
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::Remote("oversized response header".into()));
        }
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            return Err(Error::Remote("connection closed mid-header".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Remote("empty response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Remote(format!("bad status line '{status_line}'")))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    let mut resp = Response {
        status,
        headers,
        body: Vec::new(),
    };
    let mut rest = buf[header_end + 4..].to_vec();
    if head || status == 204 || status == 304 {
        return Ok(resp);
    }

    if let Some(cl) = resp.header("content-length") {
        let len: usize = cl
            .parse()
            .map_err(|_| Error::Remote(format!("bad Content-Length '{cl}'")))?;
        if len > MAX_BODY {
            return Err(Error::Remote(format!("response body too large ({len})")));
        }
        while rest.len() < len {
            let n = conn.read(&mut chunk)?;
            if n == 0 {
                return Err(Error::Remote("connection closed mid-body".into()));
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest.truncate(len);
        resp.body = rest;
    } else if resp
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        resp.body = read_chunked(conn, rest)?;
    } else {
        // Connection: close framing — read to EOF.
        loop {
            let n = conn.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if rest.len() + n > MAX_BODY {
                return Err(Error::Remote("response body too large".into()));
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        resp.body = rest;
    }
    Ok(resp)
}

/// Decode a chunked body. `pending` is whatever the header read
/// over-consumed.
fn read_chunked(conn: &mut Conn, mut pending: Vec<u8>) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut fill = |pending: &mut Vec<u8>, needed: usize| -> Result<()> {
        while pending.len() < needed {
            let n = conn.read(&mut chunk)?;
            if n == 0 {
                return Err(Error::Remote("connection closed mid-chunk".into()));
            }
            pending.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    };
    loop {
        // Chunk-size line.
        let line_end = loop {
            if let Some(pos) = find_subslice(&pending, b"\r\n") {
                break pos;
            }
            let need = pending.len() + 1;
            fill(&mut pending, need)?;
        };
        let size_text = String::from_utf8_lossy(&pending[..line_end]).to_string();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| Error::Remote(format!("bad chunk size '{size_text}'")))?;
        pending.drain(..line_end + 2);
        if size == 0 {
            return Ok(body);
        }
        if body.len() + size > MAX_BODY {
            return Err(Error::Remote("chunked body too large".into()));
        }
        fill(&mut pending, size + 2)?;
        body.extend_from_slice(&pending[..size]);
        pending.drain(..size + 2); // chunk + trailing CRLF
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest.as_slice() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ── Pull ──────────────────────────────────────────────────────────────

/// Media types a pull accepts for the manifest GET.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json";

/// Pull `remote` into `store`, tagging it `local_ref` (default: the
/// remote's `<repo>:<tag>`). Every blob is digest-verified before it is
/// written; blobs the store already holds are not re-fetched. Returns
/// the tagged descriptor.
pub fn pull(
    store: &OciStore,
    remote: &RemoteRef,
    client: &RemoteClient,
    local_ref: Option<&str>,
) -> Result<Descriptor> {
    let path = format!("{}/manifests/{}", remote.base(), remote.reference);
    let resp = client.request("GET", &path, &[("Accept", MANIFEST_ACCEPT)], None)?;
    if resp.status != 200 {
        return Err(Error::Remote(format!(
            "GET {path}: HTTP {} ({})",
            resp.status,
            String::from_utf8_lossy(&resp.body[..resp.body.len().min(200)])
        )));
    }
    let manifest_digest = sha256_hex(&resp.body);
    if let Some(want) = remote.reference.strip_prefix("sha256:") {
        if manifest_digest != format!("sha256:{want}") {
            return Err(Error::Remote(format!(
                "manifest digest mismatch: asked {want}, got {manifest_digest}"
            )));
        }
    }
    let manifest: ImageManifest = serde_json::from_slice(&resp.body)?;

    // Fetch config + layers (skip blobs the store already holds).
    let mut fetched = 0usize;
    for desc in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if store.has_blob(&desc.digest) {
            continue;
        }
        let bpath = format!("{}/blobs/{}", remote.base(), desc.digest);
        let bresp = client.request("GET", &bpath, &[], None)?;
        if bresp.status != 200 {
            return Err(Error::Remote(format!("GET {bpath}: HTTP {}", bresp.status)));
        }
        let got = sha256_hex(&bresp.body);
        if got != desc.digest {
            return Err(Error::Remote(format!(
                "blob digest mismatch for {}: got {got}",
                desc.digest
            )));
        }
        if bresp.body.len() as u64 != desc.size {
            return Err(Error::Remote(format!(
                "blob size mismatch for {}: manifest says {}, got {}",
                desc.digest,
                desc.size,
                bresp.body.len()
            )));
        }
        store.put_blob(&bresp.body)?;
        fetched += 1;
    }
    let _ = fetched;

    let tag = match local_ref {
        Some(t) => t.to_string(),
        None => format!("{}:{}", remote.repo, remote.reference),
    };
    store.tag_manifest(&manifest, &tag)
}

// ── Push ──────────────────────────────────────────────────────────────

/// Push the local artifact `local_ref` to `remote`. Blobs the registry
/// already holds (`HEAD` 200) are skipped; the manifest is PUT last so
/// the remote tag only ever points at fully-present content.
pub fn push(
    store: &OciStore,
    local_ref: &str,
    remote: &RemoteRef,
    client: &RemoteClient,
) -> Result<Descriptor> {
    let desc = store.resolve(local_ref)?;
    let manifest = store.read_manifest(&desc)?;
    let manifest_bytes = store.read_blob(&desc.digest)?;

    for d in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        let head_path = format!("{}/blobs/{}", remote.base(), d.digest);
        let head = client.request("HEAD", &head_path, &[], None)?;
        if head.status == 200 {
            continue;
        }
        let blob = store.read_blob(&d.digest)?;
        // Monolithic upload: POST an upload session, PUT the bytes.
        let post_path = format!("{}/blobs/uploads/", remote.base());
        let post = client.request("POST", &post_path, &[], None)?;
        if post.status != 202 {
            return Err(Error::Remote(format!(
                "POST {post_path}: HTTP {} ({})",
                post.status,
                String::from_utf8_lossy(&post.body[..post.body.len().min(200)])
            )));
        }
        let loc = post
            .header("location")
            .ok_or_else(|| Error::Remote("upload POST without Location".into()))?;
        let loc = client.rebase_location(loc)?;
        let sep = if loc.contains('?') { '&' } else { '?' };
        let put_path = format!("{loc}{sep}digest={}", d.digest);
        let put = client.request(
            "PUT",
            &put_path,
            &[("Content-Type", "application/octet-stream")],
            Some(&blob),
        )?;
        if put.status != 201 {
            return Err(Error::Remote(format!(
                "PUT blob {}: HTTP {}",
                d.digest, put.status
            )));
        }
    }

    let man_path = format!("{}/manifests/{}", remote.base(), remote.reference);
    let mt = if manifest.media_type.is_empty() {
        MT_OCI_MANIFEST
    } else {
        manifest.media_type.as_str()
    };
    let put = client.request(
        "PUT",
        &man_path,
        &[("Content-Type", mt)],
        Some(&manifest_bytes),
    )?;
    if put.status != 201 {
        return Err(Error::Remote(format!(
            "PUT {man_path}: HTTP {} ({})",
            put.status,
            String::from_utf8_lossy(&put.body[..put.body.len().min(200)])
        )));
    }
    Ok(desc)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn parses_remote_refs() {
        let r = RemoteRef::parse("registry.nanocloud.io/fluxor/lattice-cdc:v1").unwrap();
        assert!(!r.plain_http);
        assert_eq!(r.host, "registry.nanocloud.io");
        assert_eq!(r.port, 443);
        assert_eq!(r.repo, "fluxor/lattice-cdc");
        assert_eq!(r.reference, "v1");

        let r = RemoteRef::parse("http://127.0.0.1:5000/fluxor/x").unwrap();
        assert!(r.plain_http);
        assert_eq!(r.port, 5000);
        assert_eq!(r.reference, "latest");

        let r = RemoteRef::parse(
            "registry.nanocloud.io:5000/fluxor/x@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(r.port, 5000);
        assert!(r.reference.starts_with("sha256:"));

        assert!(RemoteRef::parse("no-repo-path").is_err());
    }

    #[test]
    fn pem_extraction_handles_bundles() {
        let der1 = vec![1u8, 2, 3, 4];
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der1);
        let pem = format!(
            "junk\n-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\ntrailer\n-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n"
        );
        let certs = pem_certificates(&pem);
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], der1);
    }

    /// A one-thread stub registry speaking just enough distribution v2
    /// over plain HTTP for the client paths under test.
    struct StubRegistry {
        addr: std::net::SocketAddr,
        handle: Option<std::thread::JoinHandle<Vec<String>>>,
    }

    impl StubRegistry {
        /// `responses`: (path-suffix match, status line + headers + body) pairs
        /// consumed per request; requests are logged and returned by `stop`.
        fn start(script: Vec<(&'static str, String)>) -> StubRegistry {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = std::thread::spawn(move || {
                let mut log = Vec::new();
                for _ in 0..script.len() {
                    let (mut sock, _) = listener.accept().unwrap();
                    let mut reader = BufReader::new(sock.try_clone().unwrap());
                    let mut req_line = String::new();
                    reader.read_line(&mut req_line).unwrap();
                    // Drain headers; capture content-length for bodies.
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        let t = line.trim();
                        if t.is_empty() {
                            break;
                        }
                        if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    if content_len > 0 {
                        let mut body = vec![0u8; content_len];
                        reader.read_exact(&mut body).unwrap();
                    }
                    let req = req_line.trim().to_string();
                    let resp = script
                        .iter()
                        .find(|(m, _)| req.contains(m))
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                        });
                    log.push(req);
                    sock.write_all(resp.as_bytes()).unwrap();
                }
                log
            });
            StubRegistry {
                addr,
                handle: Some(handle),
            }
        }

        fn stop(mut self) -> Vec<String> {
            self.handle.take().unwrap().join().unwrap()
        }
    }

    fn body_response(status: &str, extra_headers: &str, body: &[u8]) -> String {
        format!(
            "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        )
    }

    fn temp_store() -> (tempfile::TempDir, OciStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = OciStore::open(dir.path().join("store")).unwrap();
        (dir, store)
    }

    fn manifest_with_one_layer(layer: &[u8]) -> (ImageManifest, Vec<u8>) {
        let config = crate::oci_store::MT_OCI_EMPTY;
        let cfg_bytes = b"{}".to_vec();
        let m = ImageManifest {
            schema_version: 2,
            media_type: MT_OCI_MANIFEST.to_string(),
            artifact_type: Some("application/vnd.nanocloud.fluxor.image.v1".to_string()),
            config: Descriptor {
                media_type: config.to_string(),
                digest: sha256_hex(&cfg_bytes),
                size: cfg_bytes.len() as u64,
                annotations: Default::default(),
            },
            layers: vec![Descriptor {
                media_type: "application/vnd.nanocloud.fluxor.image.v1".to_string(),
                digest: sha256_hex(layer),
                size: layer.len() as u64,
                annotations: Default::default(),
            }],
            annotations: Default::default(),
        };
        let bytes = serde_json::to_vec(&m).unwrap();
        (m, bytes)
    }

    #[test]
    fn pull_verifies_and_stores() {
        let layer = b"graph-image-bytes".to_vec();
        let cfg_bytes = b"{}".to_vec();
        let (m, manifest_bytes) = manifest_with_one_layer(&layer);
        let stub = StubRegistry::start(vec![
            (
                "/v2/fluxor/x/manifests/v1",
                body_response("200 OK", "", &manifest_bytes),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.config.digest).leak(),
                body_response("200 OK", "", &cfg_bytes),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.layers[0].digest).leak(),
                body_response("200 OK", "", &layer),
            ),
        ]);
        let remote = RemoteRef::parse(&format!(
            "http://127.0.0.1:{}/fluxor/x:v1",
            stub.addr.port()
        ))
        .unwrap();
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let desc = pull(&store, &remote, &client, None).unwrap();
        assert!(store.has_blob(&desc.digest));
        assert!(store.has_blob(&m.layers[0].digest));
        let resolved = store.resolve("fluxor/x:v1").unwrap();
        assert_eq!(resolved.digest, desc.digest);
        stub.stop();
    }

    #[test]
    fn pull_rejects_corrupt_blob() {
        let layer = b"real-bytes".to_vec();
        let cfg_bytes = b"{}".to_vec();
        let (m, manifest_bytes) = manifest_with_one_layer(&layer);
        let stub = StubRegistry::start(vec![
            (
                "/v2/fluxor/x/manifests/v1",
                body_response("200 OK", "", &manifest_bytes),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.config.digest).leak(),
                body_response("200 OK", "", &cfg_bytes),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.layers[0].digest).leak(),
                body_response("200 OK", "", b"tampered!!"),
            ),
        ]);
        let remote = RemoteRef::parse(&format!(
            "http://127.0.0.1:{}/fluxor/x:v1",
            stub.addr.port()
        ))
        .unwrap();
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let err = pull(&store, &remote, &client, None).unwrap_err();
        assert!(format!("{err}").contains("digest mismatch"), "{err}");
        // Tampered blob must not have landed.
        assert!(!store.has_blob(&m.layers[0].digest));
        stub.stop();
    }

    #[test]
    fn push_uploads_missing_blobs_then_manifest() {
        let layer = b"push-me".to_vec();
        let (_dir, store) = temp_store();
        let (cfg_digest, _) = store.put_blob(b"{}").unwrap();
        let (layer_digest, _) = store.put_blob(&layer).unwrap();
        let m = ImageManifest {
            schema_version: 2,
            media_type: MT_OCI_MANIFEST.to_string(),
            artifact_type: Some("application/vnd.nanocloud.fluxor.image.v1".to_string()),
            config: Descriptor {
                media_type: crate::oci_store::MT_OCI_EMPTY.to_string(),
                digest: cfg_digest.clone(),
                size: 2,
                annotations: Default::default(),
            },
            layers: vec![Descriptor {
                media_type: "application/vnd.nanocloud.fluxor.image.v1".to_string(),
                digest: layer_digest.clone(),
                size: layer.len() as u64,
                annotations: Default::default(),
            }],
            annotations: Default::default(),
        };
        store.tag_manifest(&m, "fluxor/x:v1").unwrap();

        let stub = StubRegistry::start(vec![
            // HEAD config blob → present.
            (
                format!("HEAD /v2/fluxor/x/blobs/{cfg_digest}").leak(),
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_string(),
            ),
            // HEAD layer blob → missing.
            (
                format!("HEAD /v2/fluxor/x/blobs/{layer_digest}").leak(),
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
            ),
            (
                "POST /v2/fluxor/x/blobs/uploads/",
                "HTTP/1.1 202 Accepted\r\nLocation: /v2/fluxor/x/blobs/uploads/uuid1\r\nContent-Length: 0\r\n\r\n"
                    .to_string(),
            ),
            (
                "PUT /v2/fluxor/x/blobs/uploads/uuid1?digest=",
                "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".to_string(),
            ),
            (
                "PUT /v2/fluxor/x/manifests/v1",
                "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n".to_string(),
            ),
        ]);
        let remote = RemoteRef::parse(&format!(
            "http://127.0.0.1:{}/fluxor/x:v1",
            stub.addr.port()
        ))
        .unwrap();
        let client = RemoteClient::new(&remote, None).unwrap();
        push(&store, "fluxor/x:v1", &remote, &client).unwrap();
        let log = stub.stop();
        assert_eq!(log.len(), 5, "{log:?}");
        assert!(
            log[4].starts_with("PUT /v2/fluxor/x/manifests/v1"),
            "{log:?}"
        );
    }

    #[test]
    fn chunked_bodies_decode() {
        let stub = StubRegistry::start(vec![(
            "/v2/fluxor/x/manifests/tag-chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                .to_string(),
        )]);
        let remote = RemoteRef::parse(&format!(
            "http://127.0.0.1:{}/fluxor/x:tag-chunked",
            stub.addr.port()
        ))
        .unwrap();
        let client = RemoteClient::new(&remote, None).unwrap();
        let resp = client
            .request("GET", "/v2/fluxor/x/manifests/tag-chunked", &[], None)
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
        stub.stop();
    }
}
