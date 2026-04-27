# Datagram-Secured Transports — DTLS, QUIC, HTTP/3

This document specifies how Fluxor's TLS 1.3 / DTLS 1.3 / QUIC v1 /
HTTP/3 stack is structured. It is the canonical reference for which
modules own which protocols, which primitives live in the SDK, and
which contracts the network providers expose.

## Module layout

```
modules/
├── foundation/
│   ├── tls/                  # TLS 1.3 + DTLS 1.3
│   │   ├── mod.rs            # Server + client state machines
│   │   ├── handshake.rs      # ClientHello / ServerHello / Finished etc.
│   │   ├── handshake_driver.rs   # Record-agnostic handshake state
│   │   ├── record.rs         # TLS record framing
│   │   ├── dtls_record.rs    # DTLS record framing (seq num + retx)
│   │   ├── key_schedule.rs
│   │   ├── x509.rs
│   │   └── alert.rs
│   ├── quic/                 # QUIC v1 (RFC 9000)
│   │   ├── mod.rs            # Connection state, demuxing
│   │   ├── packet.rs         # Long/short headers, header protection
│   │   ├── frame.rs          # STREAM / ACK / CRYPTO / NEW_CONNECTION_ID …
│   │   ├── ack.rs            # ACK ranges + RTT estimation
│   │   ├── streams.rs        # Bidi/unidi stream multiplexing
│   │   └── manifest.toml
│   └── http/                 # h1 + h2 + h3
│       ├── mod.rs
│       ├── ...
│       ├── wire_h3.rs        # HTTP/3 frame format
│       ├── qpack.rs          # RFC 9204 header compression
│       └── h3.rs             # Connection-level h3 dispatch
└── sdk/
    ├── varint.rs             # RFC 9000 §16 (used by QUIC, h3, QPACK)
    ├── aes_gcm.rs            # AES-128/256-GCM
    ├── chacha20.rs           # ChaCha20-Poly1305
    ├── hmac.rs               # HMAC + HKDF (extract/expand/expand_label)
    ├── sha256.rs             # FIPS 180-4 SHA-256
    ├── sha384.rs             # FIPS 180-4 SHA-384
    └── p256.rs               # P-256 ECDH + ECDSA
```

## SDK primitives

### Crypto

The TLS-1.3-grade primitives live in `modules/sdk/`:

- `sha256.rs`, `sha384.rs` — FIPS 180-4 hashes.
- `hmac.rs` — HMAC + HKDF (`hkdf_extract`, `hkdf_expand`,
  `hkdf_expand_label`, `derive_secret`).
- `aes_gcm.rs` — AES-128/256-GCM (`Aes128Gcm`, `Aes256Gcm`).
- `chacha20.rs` — ChaCha20-Poly1305 (`chacha20_poly1305_encrypt/decrypt`).
- `p256.rs` — P-256 ECDH + ECDSA, with a step-split scalar-mul
  ladder (`ScalarMulState`) so a single handshake can't block a
  concurrent one.

Modules that consume these include them with `include!`:

```rust
include!("../../sdk/aes_gcm.rs");
include!("../../sdk/hmac.rs");
```

Every primitive uses raw-pointer writes or `write_volatile` to dodge
ADRP-based const loads that miscompile on PIC aarch64. Callers are
expected to follow the same discipline in any code that touches
crypto state.

### Variable-length integer codec

`modules/sdk/varint.rs` implements RFC 9000 §16 variable-length
integers (1, 2, 4, or 8 bytes; max value 2^62 − 1). The same encoding
is reused verbatim by HTTP/3 (RFC 9114 §7.1) and QPACK (RFC 9204 §4.5),
so this single file serves the QUIC frame layer, the HTTP/3 frame
layer, and the QPACK encoder/decoder.

API: `varint_encode`, `varint_decode`, `varint_size`,
`varint_size_from_first` — all `unsafe fn` operating on raw pointers
with explicit length bounds, matching the rest of the wire-format
helpers in this codebase.

## Channel contracts

QUIC and DTLS bind through the existing **datagram** surface
(`modules/sdk/contracts/net/datagram.rs`, opcode range `0x20..0x43`).
Endpoints carry their source address on every RX so a connection can
survive peer migration. The same surface is consumed today by DNS,
RTP, and log_net, and is provided by linux_net (`SOCK_DGRAM`) and the
bare-metal `ip` module.

QUIC publishes its application surface over the **mux** contract
(`modules/sdk/contracts/net/mux.rs`, opcode range `0xB0..0xCF`) so an
HTTP/3 module sees QUIC streams as a multiplexed-session channel
without having to know anything about packet protection.

## Handshake driver

The TLS 1.3 handshake state machine lives in
`tls/handshake_driver.rs`. It is record-agnostic — it consumes plain
handshake bytes per encryption level and produces plain handshake
bytes — so all three transports drive it the same way:

```rust
/// Encryption levels TLS exposes (RFC 8446 §7.1, RFC 9001 §4).
pub enum EncLevel { Initial, Handshake, OneRtt }

pub struct HandshakeDriver { /* … */ }
impl HandshakeDriver {
    pub fn feed_handshake(&mut self, level: EncLevel, bytes: &[u8]);
    pub fn poll_handshake(&mut self, level: EncLevel, out: &mut [u8]) -> usize;
    pub fn read_secret(&self, level: EncLevel, send: bool) -> Option<&[u8]>;
    pub fn is_handshake_complete(&self) -> bool;
}
```

- **TLS over TCP** — `record.rs` decrypts inbound records and feeds the
  plaintext into `feed_handshake`; outbound bytes from
  `poll_handshake` are encrypted into records.
- **DTLS over UDP** — `dtls_record.rs` adds sequence numbers,
  per-record nonces, fragment reassembly, and a coarse retransmission
  timer, then drives the same handshake driver.
- **QUIC** — `quic/mod.rs` ferries handshake bytes via QUIC CRYPTO
  frames and queries `read_secret` for the keys it derives its packet
  protection from.

## QUIC

`modules/foundation/quic/` owns the transport. Source layout:

- `mod.rs` — connection state machine: per-connection ID, packet
  number space tracking, encryption level transitions, demuxing
  inbound packets to the handshake driver vs. the frame handler.
- `packet.rs` — long/short header parse and build, header protection
  (AES-ECB or ChaCha20 keystream applied to the packet number bytes).
- `frame.rs` — STREAM, ACK, CRYPTO, NEW_CONNECTION_ID,
  CONNECTION_CLOSE, MAX_DATA, MAX_STREAM_DATA, etc. Uses the SDK
  `varint` codec.
- `ack.rs` — ACK range tracking + RTT estimation (RFC 9002 §5.3) +
  the retransmission queue.
- `streams.rs` — bidirectional/unidirectional QUIC streams with
  send-window/recv-window tracking. The data structures parallel the
  h2 server's per-stream window logic
  (`StreamSlot.recv_window` / `send_window`).

Inbound packets arrive on a datagram channel; the connection-ID
demultiplexes them across multiple QUIC connections sharing the same
UDP socket. The application surface is exposed to consumers (e.g.
HTTP/3) via the mux contract.

## HTTP/3

HTTP/3 lives alongside h1 and h2 inside `modules/foundation/http/`:

- `wire_h3.rs` — HTTP/3 frame format (HEADERS, DATA, SETTINGS,
  GOAWAY, etc.).
- `qpack.rs` — RFC 9204 header compression. The static table follows
  HPACK's PIC-safe `match`-based lookup pattern (see `hpack.rs`); the
  larger QPACK static table is encoded the same way.
- `h3.rs` — connection-level h3 dispatch. Mirrors `h2.rs`'s
  `StreamSlot` table on top of QUIC streams instead of h2 streams,
  arms emission via the same `arm_slot_for_emission` pattern, and
  reuses `server.rs`'s body renderers (`render_static_into`,
  `render_template_into`, `render_file_into`, `render_index_into`)
  unchanged — they already take `(dst, cap)` and return `(n, more)`.

A single fluxor process can serve all three HTTP versions over the
same logical port. The h1/h2 path is a TCP listener
(`linux_net.net_out → http.net_in`); h2c is detected via preface
sniff inside that path. The h3 path is a UDP listener
(`linux_net.dgram → quic.dgram_in → quic.app_out → http.h3_in`).

WebSocket-over-HTTP/3 (RFC 9220) reuses the same extended-CONNECT
upgrade path the existing `accept_ws_upgrade` already implements; the
h3 dispatch picks it up identically to h2.

## Implementation phases

The protocols above are landed in stages. Each phase is independently
buildable, leaves earlier phases byte-for-byte intact, and avoids
refactoring the contracts/abstractions that earlier phases settled.

| Phase | Scope                                                       |
|-------|-------------------------------------------------------------|
| A     | Extract `HandshakeDriver` from `tls/mod.rs` (no DTLS yet).  |
| B     | DTLS 1.3 record layer + retransmission timer.               |
| C     | QUIC v1 transport (`modules/foundation/quic/`).             |
| D     | HTTP/3 + QPACK (`wire_h3.rs`, `qpack.rs`, `h3.rs`).         |
| E     | WebSocket over HTTP/3 (RFC 9220).                           |

## Capability matrix at end-state

| Surface | Server | Client |
|---|---|---|
| HTTP/1.1 | ✅ | ✅ |
| HTTP/2 cleartext | ✅ | ✅ |
| HTTP/2 over TLS (ALPN h2) | ✅ | ✅ |
| HTTP/3 over QUIC | Phase D | Phase D |
| WebSocket on h1 | ✅ | — |
| WebSocket on h2 | ✅ | ✅ |
| WebSocket on h3 (RFC 9220) | Phase E | Phase E |
| TLS 1.3 over TCP | ✅ | ✅ |
| DTLS 1.3 over UDP | Phase B | Phase B |
| QUIC v1 (RFC 9000) | Phase C | Phase C |
| Plain UDP datagram (DNS, RTP, syslog) | ✅ | ✅ |
