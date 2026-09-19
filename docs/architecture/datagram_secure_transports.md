# Datagram-Secured Transports — DTLS and QUIC

This document describes how Fluxor's TLS 1.3, DTLS 1.3, and QUIC v1
stack is structured: which modules own which protocols, which
primitives live in the SDK, and which channel contracts the transports
expose. Fluxor owns the secure transports; the HTTP request layer
(HTTP/1.x, HTTP/2, and the HTTP/3 request path) lives in a consuming
sibling and reaches these transports over channel contracts.

## Module layout

```
modules/
├── foundation/
│   ├── tls/                  # TLS 1.3 + DTLS 1.3
│   │   ├── mod.rs            # Module surface, params, server + client roles
│   │   ├── handshake.rs      # ClientHello / ServerHello / Finished etc.
│   │   ├── handshake_driver.rs  # Record-agnostic handshake state machine
│   │   ├── handshake_pump.rs # Drives the driver per connection
│   │   ├── record.rs         # TLS record framing (TCP)
│   │   ├── dtls_record.rs    # DTLS 1.3 record layer (RFC 9147)
│   │   ├── dtls_state.rs     # Per-peer DTLS sessions, server + client
│   │   ├── key_schedule.rs
│   │   ├── x509.rs
│   │   └── alert.rs
│   └── quic/                 # QUIC v1 (RFC 9000/9001/9002)
│       ├── mod.rs            # Module surface, channel plumbing
│       ├── connection.rs     # Per-connection state, RTT, stream state
│       ├── pump.rs           # Handshake pump, loss recovery, send path
│       ├── packet.rs         # Long/short header parse, PN reconstruction
│       ├── wire.rs           # Packet build + protection application
│       ├── keys.rs           # Initial keys, AEAD schedule, header protection
│       ├── frame.rs          # Frame parsers/builders
│       └── ack.rs            # Sliding ACK range tracker
└── sdk/
    ├── wire/varint.rs        # RFC 9000 §16 varints
    ├── cores/datagram_endpoint.rs  # Shared bind/send/recv datagram core
    └── crypto/
        ├── aes_gcm.rs        # AES-GCM (AesGcm::new_128 / new_256) + Aes128Hp
        ├── chacha20.rs       # ChaCha20-Poly1305
        ├── hmac.rs           # HMAC + HKDF
        ├── sha256.rs, sha384.rs  # FIPS 180-4 hashes
        ├── p256.rs           # P-256 ECDH + ECDSA
        └── ed25519.rs
```

## SDK primitives

Source: `modules/sdk/crypto/`, `modules/sdk/wire/varint.rs`.

The TLS-1.3-grade primitives:

- `sha256.rs`, `sha384.rs` — FIPS 180-4 hashes.
- `hmac.rs` — HMAC + HKDF (`hkdf_extract`, `hkdf_expand`,
  `hkdf_expand_label`, `derive_secret`).
- `aes_gcm.rs` — AES-GCM via one `AesGcm` type with `new_128` /
  `new_256` constructors, plus `Aes128Hp` for QUIC header protection.
- `chacha20.rs` — ChaCha20-Poly1305
  (`chacha20_poly1305_encrypt` / `chacha20_poly1305_decrypt`).
- `p256.rs` — P-256 ECDH + ECDSA, with a step-split scalar-mul ladder
  (`ScalarMulState`) so a single handshake cannot block a concurrent
  one.

Modules that consume these include them with `include!`:

```rust
include!("../../sdk/crypto/aes_gcm.rs");
include!("../../sdk/crypto/hmac.rs");
```

Every primitive is `no_std` and allocation-free, and the signing,
key-agreement and AEAD primitives zeroise their intermediate secrets
with `write_volatile` before returning; callers follow the same
discipline in code that touches crypto state. Constant tables are plain
`static` data: a module reaches them PC-relative, so they need no
relocation (see [module_architecture.md](module_architecture.md),
"Position-independent data").

`modules/sdk/wire/varint.rs` implements RFC 9000 §16 variable-length
integers (1, 2, 4, or 8 bytes; maximum value 2^62 − 1). The same
encoding is used by the QUIC frame layer and the HTTP/3 preamble
codecs. API: `varint_encode`, `varint_decode`, `varint_size`,
`varint_size_from_first`.

## Channel contracts

QUIC and DTLS bind through the **datagram** surface
(`modules/sdk/contracts/net/datagram.rs`, opcodes `0x20..0x43`).
Endpoints carry their source address on every RX, so a connection can
survive peer migration. The same surface is consumed by DNS, log_net,
and transport_buffer, and is provided by `linux_net` (host `SOCK_DGRAM`
sockets) and the bare-metal `ip` module.

QUIC publishes its application surface over the **mux** contract
(`modules/sdk/contracts/net/mux.rs`, opcodes `0xB0..0xCF`), so a
consumer sees QUIC streams as a multiplexed-session channel without
knowing anything about packet protection. Every application stream is
surfaced this way; the transport does not speak the protocols carried
on its streams.

## Handshake driver

Source: `modules/foundation/tls/handshake_driver.rs`.

The TLS 1.3 handshake state machine is record-agnostic: it consumes
plain handshake bytes per encryption level and produces plain handshake
bytes, so all three transports drive it the same way.

```rust
/// Encryption levels TLS exposes (RFC 8446 §7.1, RFC 9001 §4).
pub enum EncLevel { Initial, Handshake, OneRtt }

impl HandshakeDriver {
    pub fn feed_handshake(&mut self, level: EncLevel, bytes: &[u8]) -> usize;
    pub fn poll_handshake(&mut self, level: EncLevel, out: &mut [u8]) -> usize;
    pub fn read_secret(&self, level: EncLevel, send: bool) -> Option<&[u8]>;
    pub fn is_handshake_complete(&self) -> bool;
}
```

- **TLS over TCP** — `record.rs` decrypts inbound records and feeds the
  plaintext into `feed_handshake`; outbound bytes from
  `poll_handshake` are encrypted into records.
- **DTLS over UDP** — `dtls_record.rs` adds sequence numbers,
  per-record nonces, fragment reassembly, and a retransmission timer,
  then drives the same handshake driver.
- **QUIC** — `pump.rs` ferries handshake bytes via QUIC CRYPTO frames
  and queries `read_secret` for the keys it derives its packet
  protection from.

## DTLS 1.3

Source: `modules/foundation/tls/dtls_record.rs`,
`modules/foundation/tls/dtls_state.rs`.

DTLS 1.3 (RFC 9147) is a mode of the `tls` module, not a separate
module. The `transport` param (id 4) selects it: `0` runs TLS records
over a stream channel, `1` runs DTLS records over a datagram channel.
Companion params: `dtls_port` (id 5, default 4433) — the port the
server binds — and `authority` (id 17), the peer a client dials,
written `host[:port]` with port 4433 when it names none. It is a v4
literal: a datagram session is keyed by the address its records arrive
from, so a peer known only by name has nothing to key on until it
answers, and `verify_hostname` is what names a peer reached by address.
A stream instance (`transport: 0`) that names an `authority` is refused
at construction: it takes each session's peer from the `CMD_CONNECT_TO`
it forwards, so the parameter there would be a fact nothing reads.
Both roles are implemented: the server accepts sessions demultiplexed
per peer 4-tuple, and the client dials its authority.

In DTLS mode the module keeps its `cipher_in` / `cipher_out` ports but
speaks datagram-contract opcodes on them: it binds with `CMD_DG_BIND`
and receives `MSG_DG_RX_FROM` frames. The record layer implements the
RFC 9147 unified header, sequence-number reconstruction and
anti-replay windows, handshake fragment reassembly, the retransmission
timer, and ACK records. Half-open handshakes are dropped after an idle
timeout.

## QUIC v1

Source: `modules/foundation/quic/`.

The `quic` module carries connections and streams; it does not speak
the protocols on them. Scope:

- `connection.rs` — per-connection state: connection ids, packet
  number spaces, encryption-level transitions, RTT estimation and PTO
  (RFC 9002), stream state.
- `pump.rs` — the handshake pump across Initial / Handshake / 1-RTT
  levels, loss detection, retransmission, and the send path.
- `packet.rs` — long/short header parsing and packet-number
  reconstruction; `wire.rs` builds packets and applies protection;
  `keys.rs` derives Initial keys, the AEAD schedule, and header
  protection masks.
- `frame.rs` — parsers and builders for CRYPTO, STREAM, ACK,
  CONNECTION_CLOSE, RESET_STREAM, NEW_CONNECTION_ID, MAX_DATA /
  MAX_STREAM_DATA / DATA_BLOCKED, and RFC 9221 DATAGRAM frames.
- `ack.rs` — the sliding ACK range tracker.

The single cipher suite is `TLS_AES_128_GCM_SHA256` (0x1301); header
protection is the AES-ECB mask. A client rejects any other suite in
the ServerHello.

Features beyond the base transport: Retry with HMAC retry tokens
(`require_retry`), 0-RTT with single-use tickets (`enable_0rtt`), ALPN
configuration (`alpn`), connection migration with
PATH_CHALLENGE / PATH_RESPONSE (enabled unless `disable_migration`),
key update, and RFC 9221 datagrams.

Channel surface: `net_in` / `net_out` carry datagram-contract frames
to the network provider; `app_in` / `app_out` carry the mux-contract
application surface. Inbound packets are demultiplexed by connection
id, so multiple QUIC connections share one UDP socket. A loopback
graph runs a server and a client instance in one process against
`linux_net`.

## The HTTP/3 boundary

No HTTP/3 lives in this transport. It carries QUIC — sessions,
streams, ordered bytes, FIN, reset, stop-sending, flow-control credit,
datagrams — and projects all of it through the protocol-neutral mux
contract on `app_in` / `app_out`.

That includes the HTTP/3 connection preamble. A QUIC unidirectional
stream is transport; the meaning of the first application byte on that
stream is not. The control and QPACK streams are opened by the
application, their stream-type prefixes and SETTINGS are written by the
application, and every byte a peer sends on a unidirectional stream
reaches the application unmodified — the leading type varint included.
The transport does not read it, classify it, or discard it.

The negotiated ALPN crosses as opaque bytes on
`MSG_MUX_SESSION_OPENED`. This module performs the negotiation and
never compares the result against a token; selecting HTTP/3 because of
it is the consumer's decision. A consuming `http` module owns that
choice, along with SETTINGS, GOAWAY, QPACK, priority, push policy,
request and response semantics, and WebSocket-over-HTTP/3 extended
CONNECT (RFC 9220) entirely.

A hosted h3 graph wires:

```yaml
wiring:
  - from: linux_net.net_out
    to: quic.net_in
  - from: quic.net_out
    to: linux_net.net_in
  - from: quic.app_out
    to: http.net_in
  - from: http.net_out
    to: quic.app_in
```

## Related Documentation

- `protocol_surfaces.md` — the datagram, packet, and mux contracts in
  the surface taxonomy
- `network.md` — the stream contract, drivers, TLS as channel
  transformer
- `security.md` — key custody, certificate handling, trust model
