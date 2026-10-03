//! Remote OCI distribution (distribution-spec v2) push/pull between the
//! local store and a registry (e.g. `registry.nanocloud.io`).
//!
//! This is the ONE place in the tools tree that touches the network for
//! artifacts: the offline-first invariant
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
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return Err(Error::Remote(format!(
                "remote ref '{}' has no usable host (letters, digits, '.', '-', '_' only)",
                snippet(s.as_bytes())
            )));
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
        // Everything below is interpolated into a request line, so it is
        // held to the registry naming grammar: nothing that can end the
        // line, start a header or climb a path gets through.
        let name_ok = |c: &str| {
            let b = c.as_bytes();
            !b.is_empty()
                && b.iter()
                    .all(|x| matches!(x, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
                && b[0].is_ascii_alphanumeric()
                && b[b.len() - 1].is_ascii_alphanumeric()
        };
        if !repo.split('/').all(name_ok) {
            return Err(Error::Remote(format!(
                "remote ref '{}': repository '{}' is not a valid name",
                snippet(s.as_bytes()),
                snippet(repo.as_bytes())
            )));
        }
        let reference_ok = if reference.starts_with("sha256:") {
            valid_digest(&reference)
        } else {
            let b = reference.as_bytes();
            b.len() <= 128
                && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
                && b.iter()
                    .all(|x| x.is_ascii_alphanumeric() || matches!(x, b'.' | b'_' | b'-'))
        };
        if !reference_ok {
            return Err(Error::Remote(format!(
                "remote ref '{}': reference '{}' is neither a tag nor a sha256:<64 hex> digest",
                snippet(s.as_bytes()),
                snippet(reference.as_bytes())
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

    /// `<repo>:<tag>` or `<repo>@sha256:<hex>`, as a reference spells it.
    pub fn name(&self) -> String {
        let sep = if self.reference.starts_with("sha256:") {
            '@'
        } else {
            ':'
        };
        format!("{}{sep}{}", self.repo, self.reference)
    }

    fn base(&self) -> String {
        format!("/v2/{}", self.repo)
    }
}

// ── Transport ─────────────────────────────────────────────────────────

/// Longest a single read or write may block before the request fails.
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest one request (connect, send, receive) may take in total, so a
/// server that drips a byte inside every read timeout still ends.
const REQUEST_DEADLINE: Duration = Duration::from_secs(900);
/// Header block ceiling.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Ceiling on one chunk-size line (hex size plus extensions).
const MAX_CHUNK_LINE: usize = 1024;
/// Ceiling on the trailer section of a chunked body.
const MAX_TRAILER_BYTES: usize = 16 * 1024;
const MAX_REDIRECTS: usize = 3;
/// Upper bound on any single response body (blobs are graph images and
/// firmware, well under this).
const MAX_BODY: usize = 256 * 1024 * 1024;
/// Upper bound on a manifest body.
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
/// Upper bound on the layers one manifest may name.
const MAX_LAYERS: usize = 4096;

/// A socket whose every read and write is bounded by the per-operation
/// timeout AND by what is left of the request deadline. The bound sits at
/// the socket, under TLS, so it also covers the reads and writes TLS makes
/// on its own: the handshake, and a record that arrives a byte at a time.
struct DeadlineSock {
    sock: TcpStream,
    deadline: Instant,
    io_timeout: Duration,
}

impl DeadlineSock {
    fn slice(&self) -> std::io::Result<Duration> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline exceeded")
            })?;
        Ok(left.min(self.io_timeout).max(Duration::from_millis(1)))
    }
}

impl Read for DeadlineSock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let t = self.slice()?;
        self.sock.set_read_timeout(Some(t))?;
        self.sock.read(buf)
    }
}

impl Write for DeadlineSock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let t = self.slice()?;
        self.sock.set_write_timeout(Some(t))?;
        self.sock.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.sock.flush()
    }
}

/// One request's connection, plain or TLS, over a [`DeadlineSock`].
enum Conn {
    Plain(DeadlineSock),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, DeadlineSock>>),
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
/// simplicity keeps the response framing unambiguous. No credentials are
/// ever sent: the registry is reached anonymously, so none can appear in a
/// request, a redirect or an error message.
pub struct RemoteClient {
    plain_http: bool,
    host: String,
    port: u16,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    io_timeout: Duration,
    request_deadline: Duration,
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

/// A request target is printable ASCII with no space: nothing a server (or
/// a manifest it served) names can end the request line or start a header.
fn check_target(path: &str) -> Result<()> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.bytes().any(|b| !(0x21..=0x7e).contains(&b))
    {
        return Err(Error::Remote("refusing an unsafe request target".into()));
    }
    Ok(())
}

fn check_header(name: &str, value: &str) -> Result<()> {
    let ok = |s: &str| s.bytes().all(|b| b != b'\r' && b != b'\n' && b != 0);
    if name.is_empty() || !ok(name) || !ok(value) || name.contains(':') {
        return Err(Error::Remote("refusing an unsafe request header".into()));
    }
    Ok(())
}

/// Printable-ASCII excerpt of untrusted bytes, for an error message: a
/// registry cannot inject terminal control sequences through one.
fn snippet(body: &[u8]) -> String {
    body.iter()
        .take(200)
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

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
            io_timeout: IO_TIMEOUT,
            request_deadline: REQUEST_DEADLINE,
        })
    }

    fn connect(&self, deadline: Instant) -> Result<Conn> {
        let addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| Error::Remote(format!("resolve {}:{}: {e}", self.host, self.port)))?;
        let mut last = None;
        let mut sock = None;
        for addr in addrs {
            // `connect_timeout` refuses a zero duration; an exhausted
            // deadline ends the attempt instead.
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match TcpStream::connect_timeout(&addr, self.io_timeout.min(left)) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let sock = sock.ok_or_else(|| {
            Error::Remote(format!(
                "connect {}:{}: {}",
                self.host,
                self.port,
                last.map_or_else(|| "no address".to_string(), |e| e.to_string())
            ))
        })?;
        let sock = DeadlineSock {
            sock,
            deadline,
            io_timeout: self.io_timeout,
        };
        if self.plain_http {
            Ok(Conn::Plain(sock))
        } else {
            let cfg = self.tls_config.as_ref().expect("tls config for https");
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| Error::Remote(format!("bad server name '{}': {e}", self.host)))?;
            let conn = rustls::ClientConnection::new(cfg.clone(), name)
                .map_err(|e| Error::Remote(format!("tls setup: {e}")))?;
            Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
        }
    }

    /// Issue one request with the default body ceiling.
    fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response> {
        self.request_limited(method, path, headers, body, MAX_BODY)
    }

    /// Issue one request whose response body may not exceed `limit` bytes.
    /// Follows same-authority redirects (registry blob GETs commonly 307 to
    /// a storage path): GET and HEAD for any redirect status, other methods
    /// only for 307/308, which preserve the method and body.
    fn request_limited(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Response> {
        let mut path = path.to_string();
        for _ in 0..=MAX_REDIRECTS {
            let resp = self.request_once(method, &path, headers, body, limit)?;
            if matches!(resp.status, 301 | 302 | 307 | 308) {
                let keeps_method = matches!(resp.status, 307 | 308);
                if !keeps_method && !matches!(method, "GET" | "HEAD") {
                    return Err(Error::Remote(format!(
                        "{method} answered with a redirect (HTTP {}) that does not preserve the method",
                        resp.status
                    )));
                }
                let loc = resp
                    .header("location")
                    .ok_or_else(|| Error::Remote("redirect without Location".into()))?;
                path = self.rebase_location(loc)?;
                continue;
            }
            return Ok(resp);
        }
        Err(Error::Remote(format!(
            "more than {MAX_REDIRECTS} redirects for {method}"
        )))
    }

    /// Resolve a redirect Location to a same-authority path. A redirect to
    /// another scheme, host, port or one carrying userinfo is refused: the
    /// trust decision was made for this authority, and the refusal names
    /// only the host, never the URL (it may carry a signed token).
    fn rebase_location(&self, loc: &str) -> Result<String> {
        let loc = loc.split('#').next().unwrap_or("");
        let path = if let Some((scheme, rest)) = loc.split_once("://") {
            let want = if self.plain_http { "http" } else { "https" };
            let end = rest.find(['/', '?']).unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(end);
            let host_shown = snippet(authority.rsplit('@').next().unwrap_or(authority).as_bytes());
            if !scheme.eq_ignore_ascii_case(want) || authority.contains('@') {
                return Err(Error::Remote(format!(
                    "refusing a redirect to another scheme or with credentials (host '{host_shown}')"
                )));
            }
            let default_port = if self.plain_http { 80 } else { 443 };
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                    (h, p.parse::<u16>().unwrap_or(0))
                }
                _ => (authority, default_port),
            };
            if !host.eq_ignore_ascii_case(&self.host) || port != self.port {
                return Err(Error::Remote(format!(
                    "refusing cross-host redirect to '{}'",
                    snippet(host.as_bytes())
                )));
            }
            if tail.starts_with('/') {
                tail.to_string()
            } else {
                format!("/{tail}")
            }
        } else if loc.starts_with('/') && !loc.starts_with("//") {
            loc.to_string()
        } else {
            return Err(Error::Remote("unsupported redirect target".into()));
        };
        check_target(&path)?;
        Ok(path)
    }

    fn request_once(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Response> {
        check_target(path)?;
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(Error::Remote("refusing an unsafe request method".into()));
        }
        for (k, v) in headers {
            check_header(k, v)?;
        }
        let deadline = Instant::now() + self.request_deadline;
        let mut conn = self.connect(deadline)?;
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
        read_response(&mut conn, method == "HEAD", limit)
    }
}

use crate::trust_anchors::pem_certificates;

/// Read one HTTP/1.1 response. `head` suppresses body reading (HEAD
/// responses carry Content-Length but no body); `limit` bounds the body,
/// and a declared length above it fails before any of the body is read.
fn read_response<R: Read>(conn: &mut R, head: bool, limit: usize) -> Result<Response> {
    // Header block first: read until CRLFCRLF.
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
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
    if !status_line.starts_with("HTTP/1.") {
        return Err(Error::Remote("not an HTTP/1.x response".into()));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Remote("bad status line".to_string()))?;
    if (100..200).contains(&status) {
        return Err(Error::Remote(format!(
            "unexpected informational response (HTTP {status})"
        )));
    }
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

    let lengths: Vec<&str> = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    // The only transfer coding accepted is a lone `chunked`: several
    // Transfer-Encoding headers, a coding list or any other coding fail.
    let codings: Vec<&str> = resp
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    let chunked = match codings.as_slice() {
        [] => false,
        [v] if v.eq_ignore_ascii_case("chunked") => true,
        _ => return Err(Error::Remote("unsupported Transfer-Encoding".into())),
    };
    if chunked && !lengths.is_empty() {
        return Err(Error::Remote(
            "response carries both Content-Length and chunked framing".into(),
        ));
    }
    if lengths.windows(2).any(|w| w[0] != w[1]) {
        return Err(Error::Remote("conflicting Content-Length headers".into()));
    }

    if let Some(cl) = lengths.first() {
        let len: usize = cl
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| cl.parse().ok())
            .flatten()
            .ok_or_else(|| Error::Remote("bad Content-Length".to_string()))?;
        if len > limit {
            return Err(Error::Remote(format!(
                "response body too large ({len} > {limit})"
            )));
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
    } else if chunked {
        resp.body = read_chunked(conn, rest, limit)?;
    } else {
        // Connection: close framing — read to EOF.
        if rest.len() > limit {
            return Err(Error::Remote("response body too large".into()));
        }
        loop {
            let n = conn.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if rest.len().saturating_add(n) > limit {
                return Err(Error::Remote("response body too large".into()));
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        resp.body = rest;
    }
    Ok(resp)
}

/// Bytes already read past the header block plus the connection they came
/// from, with the two reads a chunked body needs: a bounded line and an
/// exact count.
struct Pending<'a, R: Read> {
    conn: &'a mut R,
    buf: Vec<u8>,
}

impl<R: Read> Pending<'_, R> {
    fn fill(&mut self) -> Result<()> {
        let mut chunk = [0u8; 8192];
        let n = self.conn.read(&mut chunk)?;
        if n == 0 {
            return Err(Error::Remote("connection closed mid-chunk".into()));
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    /// One CRLF-terminated line, at most `max` bytes before the CRLF.
    fn line(&mut self, max: usize) -> Result<Vec<u8>> {
        loop {
            if let Some(pos) = find_subslice(&self.buf, b"\r\n") {
                if pos > max {
                    return Err(Error::Remote("chunked framing line too long".into()));
                }
                let line = self.buf[..pos].to_vec();
                self.buf.drain(..pos + 2);
                return Ok(line);
            }
            if self.buf.len() > max {
                return Err(Error::Remote("chunked framing line too long".into()));
            }
            self.fill()?;
        }
    }

    /// Exactly `n` bytes.
    fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.buf.len() < n {
            self.fill()?;
        }
        Ok(self.buf.drain(..n).collect())
    }
}

/// Decode a chunked body of at most `limit` bytes. `pending` is whatever
/// the header read over-consumed. The announced size is checked against the
/// limit before a byte of the chunk is read, so a hostile size can neither
/// overflow nor reserve memory.
fn read_chunked<R: Read>(conn: &mut R, pending: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
    let mut input = Pending { conn, buf: pending };
    let mut body: Vec<u8> = Vec::new();
    loop {
        let line = input.line(MAX_CHUNK_LINE)?;
        let text =
            std::str::from_utf8(&line).map_err(|_| Error::Remote("bad chunk size".to_string()))?;
        let size_text = text.split(';').next().unwrap_or("").trim();
        if size_text.is_empty()
            || size_text.len() > 16
            || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Remote("bad chunk size".into()));
        }
        let size = usize::try_from(
            u64::from_str_radix(size_text, 16)
                .map_err(|_| Error::Remote("bad chunk size".to_string()))?,
        )
        .map_err(|_| Error::Remote("chunk size out of range".to_string()))?;
        if size == 0 {
            // Trailer section: header lines up to an empty one, bounded.
            let mut total = 0usize;
            loop {
                let t = input.line(MAX_TRAILER_BYTES)?;
                total = total.saturating_add(t.len() + 2);
                if total > MAX_TRAILER_BYTES {
                    return Err(Error::Remote("chunked trailer too long".into()));
                }
                if t.is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len().checked_add(size).is_none_or(|n| n > limit) {
            return Err(Error::Remote("chunked body too large".into()));
        }
        body.extend_from_slice(&input.take(size)?);
        if input.take(2)? != b"\r\n" {
            return Err(Error::Remote("chunk not terminated by CRLF".into()));
        }
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

/// `sha256:` followed by exactly 64 lowercase hex digits: the only digest
/// spelling that is ever interpolated into a request.
fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

// ── Pull ──────────────────────────────────────────────────────────────

/// Media types a pull accepts for the manifest GET.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json";

/// Pull `remote` into `store`, tagging it `local_ref` (default: the
/// remote's `<repo>:<tag>`). Every blob is digest-verified before it is
/// written; blobs the store already holds are not re-fetched. Returns
/// the tagged descriptor.
///
/// The manifest is stored byte for byte as received, so the digest the
/// store knows it by is the digest the registry does. A digest reference
/// is verified against the bytes. A tag reference cannot be: the tag is
/// whatever the registry says it is today, so the resulting digest is the
/// identity (trust on first use) and is what the caller should pin. When
/// the registry sends `Docker-Content-Digest` it must equal the digest of
/// the bytes received, or the pull fails; a registry that omits the header
/// is accepted, since the bytes are hashed locally either way.
pub fn pull(
    store: &OciStore,
    remote: &RemoteRef,
    client: &RemoteClient,
    local_ref: Option<&str>,
) -> Result<Descriptor> {
    let path = format!("{}/manifests/{}", remote.base(), remote.reference);
    let resp = client.request_limited(
        "GET",
        &path,
        &[("Accept", MANIFEST_ACCEPT)],
        None,
        MAX_MANIFEST,
    )?;
    if resp.status != 200 {
        return Err(Error::Remote(format!(
            "GET {path}: HTTP {} ({})",
            resp.status,
            snippet(&resp.body)
        )));
    }
    let manifest_digest = sha256_hex(&resp.body);
    if valid_digest(&remote.reference) && manifest_digest != remote.reference {
        return Err(Error::Remote(format!(
            "manifest digest mismatch: asked {}, got {manifest_digest}",
            remote.reference
        )));
    }
    if let Some(claimed) = resp.header("docker-content-digest") {
        // Only a sha256 claim can be checked against what was hashed here.
        if claimed.starts_with("sha256:") && claimed != manifest_digest {
            return Err(Error::Remote(format!(
                "manifest digest mismatch: registry says {}, bytes hash to {manifest_digest}",
                snippet(claimed.as_bytes())
            )));
        }
    }
    let manifest: ImageManifest = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Remote(format!("manifest does not parse: {e}")))?;
    if manifest.schema_version != 2
        || !(manifest.media_type.is_empty() || manifest.media_type == MT_OCI_MANIFEST)
    {
        return Err(Error::Remote(
            "remote reference is not an OCI image manifest (schemaVersion 2)".into(),
        ));
    }
    if manifest.layers.len() > MAX_LAYERS {
        return Err(Error::Remote(format!(
            "manifest names {} layers (limit {MAX_LAYERS})",
            manifest.layers.len()
        )));
    }
    for desc in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if !valid_digest(&desc.digest) {
            return Err(Error::Remote(format!(
                "manifest names a malformed digest '{}'",
                snippet(desc.digest.as_bytes())
            )));
        }
        if desc.size > MAX_BODY as u64 {
            return Err(Error::Remote(format!(
                "manifest declares a {}-byte blob (limit {MAX_BODY})",
                desc.size
            )));
        }
    }

    // Fetch config + layers (skip blobs the store already holds).
    for desc in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if store.has_blob(&desc.digest) {
            continue;
        }
        let bpath = format!("{}/blobs/{}", remote.base(), desc.digest);
        let bresp = client.request_limited("GET", &bpath, &[], None, desc.size as usize)?;
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
    }

    let tag = match local_ref {
        Some(t) => t.to_string(),
        None => format!("{}:{}", remote.repo, remote.reference),
    };
    store.tag_manifest_bytes(&resp.body, &tag)
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
                snippet(&post.body)
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
            snippet(&put.body)
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
        assert_eq!(r.name(), format!("fluxor/x@sha256:{}", "0".repeat(64)));

        assert!(RemoteRef::parse("no-repo-path").is_err());
    }

    #[test]
    fn pem_extraction_handles_bundles() {
        let der1 = vec![1u8, 2, 3, 4];
        let b64 = crate::b64::encode(&der1);
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

    fn remote_for(stub: &StubRegistry, tail: &str) -> RemoteRef {
        RemoteRef::parse(&format!("http://127.0.0.1:{}/{tail}", stub.addr.port())).unwrap()
    }

    /// A manifest naming a digest that carries CRLF is refused before any
    /// request is built from it: the registry sees the manifest GET and
    /// nothing else, and no injected header ever reaches the wire.
    #[test]
    fn a_manifest_digest_cannot_inject_into_a_request() {
        let evil = "sha256:aa\r\nX-Evil: 1";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MT_OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                       "digest": evil, "size": 2},
            "layers": [],
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let stub = StubRegistry::start(vec![(
            "/v2/fluxor/x/manifests/v1",
            body_response("200 OK", "", &bytes),
        )]);
        let remote = remote_for(&stub, "fluxor/x:v1");
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let err = pull(&store, &remote, &client, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("malformed digest"), "{err}");
        assert!(!err.contains('\r') && !err.contains('\n'), "{err:?}");
        let log = stub.stop();
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(!log[0].contains("Evil"));
    }

    #[test]
    fn remote_refs_with_unsafe_parts_are_refused() {
        for bad in [
            "reg.example/a b/x:v1",
            "reg.example/a/x:v\r\n1",
            "reg.example/../x:v1",
            "reg.example/x:v1@sha256:zz",
            "reg.example/x@sha256:ABCDEF0000000000000000000000000000000000000000000000000000000000",
            "reg\r\n.example/x:v1",
            "reg.example/X:v1",
        ] {
            assert!(RemoteRef::parse(bad).is_err(), "{bad:?}");
        }
        assert!(RemoteRef::parse("reg.example:5000/a/b-c_d.e:1.0-rc_1").is_ok());
    }

    #[test]
    fn chunked_decoding_survives_hostile_framing() {
        let ok = |wire: &[u8], limit: usize| {
            read_chunked(
                &mut std::io::Cursor::new(Vec::<u8>::new()),
                wire.to_vec(),
                limit,
            )
        };
        assert_eq!(ok(b"3\r\nabc\r\n0\r\n\r\n", 10).unwrap(), b"abc");
        // Trailers are consumed and bounded.
        assert_eq!(ok(b"1\r\na\r\n0\r\nX-T: v\r\n\r\n", 10).unwrap(), b"a");
        let long_trailer = format!("0\r\nX: {}\r\n\r\n", "y".repeat(MAX_TRAILER_BYTES + 10));
        assert!(ok(long_trailer.as_bytes(), 10).is_err());
        // Sizes that overflow, exceed the limit or are not hex.
        assert!(ok(b"ffffffffffffffff\r\n", usize::MAX).is_err());
        assert!(ok(b"10000000000000000\r\n", usize::MAX).is_err());
        assert!(ok(b"fffffffffffffffe\r\nx", 1 << 20).is_err());
        assert!(ok(b"-1\r\n", 10).is_err());
        assert!(ok(b"\r\n", 10).is_err());
        assert!(ok(b"0x4\r\nabcd\r\n0\r\n\r\n", 10).is_err());
        // Two chunks that individually fit but together pass the limit.
        assert!(ok(b"4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n", 7).is_err());
        // A chunk not terminated by CRLF.
        assert!(ok(b"3\r\nabcXY0\r\n\r\n", 10).is_err());
        // An endless size line is cut off, not buffered.
        let endless = vec![b'1'; MAX_CHUNK_LINE + 100];
        assert!(ok(&endless, 10).is_err());
        // Truncation mid-chunk.
        assert!(ok(b"5\r\nab", 10).is_err());
    }

    #[test]
    fn declared_body_lengths_past_the_limit_fail_before_reading() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n";
        let err = read_response(&mut std::io::Cursor::new(wire.to_vec()), false, 1024)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("too large"), "{err}");
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(read_response(&mut std::io::Cursor::new(both.to_vec()), false, 1024).is_err());
        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab";
        assert!(
            read_response(&mut std::io::Cursor::new(conflicting.to_vec()), false, 1024).is_err()
        );
    }

    /// The registry's `Docker-Content-Digest` must equal the hash of the
    /// bytes received; a registry that sends none is accepted, and the
    /// digest the store records is the one the bytes hash to.
    #[test]
    fn pull_checks_the_registry_digest_header_against_the_bytes() {
        let layer = b"layer".to_vec();
        let cfg = b"{}".to_vec();
        let (m, manifest_bytes) = manifest_with_one_layer(&layer);
        let blobs = |m: &ImageManifest| -> Vec<(&'static str, String)> {
            vec![
                (
                    format!("/v2/fluxor/x/blobs/{}", m.config.digest).leak(),
                    body_response("200 OK", "", &cfg),
                ),
                (
                    format!("/v2/fluxor/x/blobs/{}", m.layers[0].digest).leak(),
                    body_response("200 OK", "", &layer),
                ),
            ]
        };
        let wrong = format!("Docker-Content-Digest: sha256:{}\r\n", "0".repeat(64));
        let script = vec![(
            "/v2/fluxor/x/manifests/v1",
            body_response("200 OK", &wrong, &manifest_bytes),
        )];
        let stub = StubRegistry::start(script);
        let remote = remote_for(&stub, "fluxor/x:v1");
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let err = pull(&store, &remote, &client, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch"), "{err}");
        assert!(store.resolve("fluxor/x:v1").is_err());
        stub.stop();

        let right = format!("Docker-Content-Digest: {}\r\n", sha256_hex(&manifest_bytes));
        let mut script = vec![(
            "/v2/fluxor/x/manifests/v1",
            body_response("200 OK", &right, &manifest_bytes),
        )];
        script.extend(blobs(&m));
        let stub = StubRegistry::start(script);
        let remote = remote_for(&stub, "fluxor/x:v1");
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        assert!(pull(&store, &remote, &client, None).is_ok());
        stub.stop();

        // A digest reference is verified against the bytes asked for.
        let asked = format!("sha256:{}", "1".repeat(64));
        let stub = StubRegistry::start(vec![(
            "/v2/fluxor/x/manifests/sha256:",
            body_response("200 OK", "", &manifest_bytes),
        )]);
        let remote = remote_for(&stub, &format!("fluxor/x@{asked}"));
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let err = pull(&store, &remote, &client, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch"), "{err}");
        stub.stop();
    }

    /// The manifest lands exactly as served — whitespace, key order and
    /// unknown fields included — so its digest is the registry's.
    #[test]
    fn pull_stores_manifest_bytes_exactly_as_received() {
        let layer = b"layer-bytes".to_vec();
        let cfg = b"{}".to_vec();
        let (m, canonical) = manifest_with_one_layer(&layer);
        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["x-vendor-extension"] = serde_json::json!({"keep": "me"});
        let served = format!("  {}\n", serde_json::to_string_pretty(&value).unwrap()).into_bytes();
        assert_ne!(served, canonical);
        let stub = StubRegistry::start(vec![
            (
                "/v2/fluxor/x/manifests/v1",
                body_response("200 OK", "", &served),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.config.digest).leak(),
                body_response("200 OK", "", &cfg),
            ),
            (
                format!("/v2/fluxor/x/blobs/{}", m.layers[0].digest).leak(),
                body_response("200 OK", "", &layer),
            ),
        ]);
        let remote = remote_for(&stub, "fluxor/x:v1");
        let client = RemoteClient::new(&remote, None).unwrap();
        let (_dir, store) = temp_store();
        let desc = pull(&store, &remote, &client, None).unwrap();
        assert_eq!(desc.digest, sha256_hex(&served));
        assert_eq!(store.read_blob(&desc.digest).unwrap(), served);
        stub.stop();
    }

    /// One-shot hostile server: accepts a connection, reads the request,
    /// then writes `script` pieces separated by `gap`, and holds the socket.
    fn hostile_server(pieces: Vec<Vec<u8>>, gap: Duration) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut seen = Vec::new();
            let mut b = [0u8; 512];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&b[..n]),
                }
            }
            for p in pieces {
                if sock.write_all(&p).is_err() {
                    return;
                }
                std::thread::sleep(gap);
            }
            std::thread::sleep(Duration::from_secs(5));
        });
        addr
    }

    fn client_for(addr: std::net::SocketAddr, io: Duration, total: Duration) -> RemoteClient {
        let remote =
            RemoteRef::parse(&format!("http://127.0.0.1:{}/fluxor/x:v1", addr.port())).unwrap();
        let mut c = RemoteClient::new(&remote, None).unwrap();
        c.io_timeout = io;
        c.request_deadline = total;
        c
    }

    /// A server that stalls mid-header is cut off by the read timeout.
    #[test]
    fn a_stalled_response_times_out() {
        let addr = hostile_server(
            vec![b"HTTP/1.1 200 OK\r\nContent-".to_vec()],
            Duration::ZERO,
        );
        let c = client_for(addr, Duration::from_millis(300), Duration::from_secs(30));
        let t = Instant::now();
        let err = c.request("GET", "/v2/x/manifests/v1", &[], None);
        assert!(err.is_err());
        assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    }

    /// Slow-loris: a byte inside every read timeout still ends at the
    /// request deadline.
    #[test]
    fn a_dripping_response_ends_at_the_request_deadline() {
        let drip: Vec<Vec<u8>> = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
            .iter()
            .chain(std::iter::repeat_n(&b'x', 60))
            .map(|b| vec![*b])
            .collect();
        let addr = hostile_server(drip, Duration::from_millis(60));
        let c = client_for(addr, Duration::from_secs(2), Duration::from_millis(500));
        let t = Instant::now();
        let err = c.request("GET", "/v2/x/manifests/v1", &[], None);
        assert!(err.is_err());
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    /// A hostile chunk size over the wire fails cleanly (no panic, no
    /// allocation) and a redirect to another host is refused without
    /// echoing the URL.
    #[test]
    fn hostile_wire_responses_fail_cleanly() {
        let addr = hostile_server(
            vec![
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n"
                    .to_vec(),
            ],
            Duration::ZERO,
        );
        let c = client_for(addr, Duration::from_secs(2), Duration::from_secs(5));
        let err = c
            .request("GET", "/v2/x/manifests/v1", &[], None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("chunked body too large"), "{err}");

        let addr = hostile_server(
            vec![b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://evil.example/p?token=SECRET\r\nContent-Length: 0\r\n\r\n".to_vec()],
            Duration::ZERO,
        );
        let c = client_for(addr, Duration::from_secs(2), Duration::from_secs(5));
        let err = c
            .request("GET", "/v2/x/manifests/v1", &[], None)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("evil.example") && !err.contains("SECRET"),
            "{err}"
        );
    }

    /// Framing headers are taken only in their one unambiguous spelling.
    #[test]
    fn ambiguous_framing_headers_are_refused() {
        let parse =
            |wire: &[u8]| read_response(&mut std::io::Cursor::new(wire.to_vec()), false, 1024);
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab")
                .unwrap()
                .body,
            b"ab"
        );
        for wire in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nab"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        ] {
            assert!(parse(wire).is_err(), "{}", snippet(wire));
        }
    }

    /// Run `f` on its own thread and fail the test if it has not returned
    /// within `limit`: a client that hangs is a failure, never a pass.
    fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit)
            .expect("the client was still blocked past its deadline")
    }

    /// One-shot server for the TLS path: accepts, reads the ClientHello,
    /// writes `pieces` separated by `gap`, then holds the socket open.
    fn tls_hostile_server(pieces: Vec<Vec<u8>>, gap: Duration) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut b = [0u8; 4096];
            if !matches!(sock.read(&mut b), Ok(n) if n > 0) {
                return;
            }
            for p in pieces {
                if sock.write_all(&p).is_err() {
                    return;
                }
                std::thread::sleep(gap);
            }
            std::thread::sleep(Duration::from_secs(20));
        });
        addr
    }

    fn tls_client_for(addr: std::net::SocketAddr, io: Duration, total: Duration) -> RemoteClient {
        let remote =
            RemoteRef::parse(&format!("https://127.0.0.1:{}/fluxor/x:v1", addr.port())).unwrap();
        let mut c = RemoteClient::new(&remote, None).unwrap();
        c.io_timeout = io;
        c.request_deadline = total;
        c
    }

    /// A server that accepts and never answers the ClientHello is cut off
    /// by the read timeout: the handshake's own reads are bounded too.
    #[test]
    fn a_silent_tls_server_times_out_in_the_handshake() {
        let addr = tls_hostile_server(Vec::new(), Duration::ZERO);
        let c = tls_client_for(addr, Duration::from_millis(300), Duration::from_secs(30));
        let (failed, took) = within(Duration::from_secs(10), move || {
            let t = Instant::now();
            let r = c.request("GET", "/v2/x/manifests/v1", &[], None);
            (r.is_err(), t.elapsed())
        });
        assert!(failed);
        assert!(took < Duration::from_secs(4), "{took:?}");
    }

    /// A handshake record dripped a byte inside every read timeout still
    /// ends at the request deadline.
    #[test]
    fn a_dripping_tls_handshake_ends_at_the_request_deadline() {
        let mut drip = vec![vec![0x16, 0x03, 0x03, 0x40, 0x00]];
        drip.extend(std::iter::repeat_n(vec![0u8], 200));
        let addr = tls_hostile_server(drip, Duration::from_millis(50));
        let c = tls_client_for(addr, Duration::from_secs(2), Duration::from_millis(500));
        let (failed, took) = within(Duration::from_secs(10), move || {
            let t = Instant::now();
            let r = c.request("GET", "/v2/x/manifests/v1", &[], None);
            (r.is_err(), t.elapsed())
        });
        assert!(failed);
        assert!(took < Duration::from_secs(3), "{took:?}");
    }

    #[test]
    fn redirects_are_same_authority_only() {
        let remote = RemoteRef::parse("http://127.0.0.1:5000/fluxor/x:v1").unwrap();
        let c = RemoteClient::new(&remote, None).unwrap();
        assert_eq!(
            c.rebase_location("http://127.0.0.1:5000/blob/1?a=b")
                .unwrap(),
            "/blob/1?a=b"
        );
        assert_eq!(c.rebase_location("/blob/2").unwrap(), "/blob/2");
        for bad in [
            "http://127.0.0.1:5001/x",
            "https://127.0.0.1:5000/x",
            "http://user:pw@127.0.0.1:5000/x",
            "//evil.example/x",
            "relative/path",
            "/a b",
            "/a\r\nX: y",
        ] {
            assert!(c.rebase_location(bad).is_err(), "{bad:?}");
        }
        // A refusal quotes the host, never terminal control bytes from it.
        let err = c
            .rebase_location("http://ev\x1b[2Jil.example/x")
            .unwrap_err()
            .to_string();
        assert!(!err.contains('\x1b'), "{err:?}");
    }
}
