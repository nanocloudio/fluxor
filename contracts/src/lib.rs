//! Public Fluxor contracts and shared vocabulary.
//!
//! Fluxor owns the storage-surface vocabulary, the typed `Fence` enum
//! that operations return, and the wire-byte content-type table used
//! by every module manifest. Downstream implementers (Loam, FAT32-backed
//! providers, sibling projects authoring module manifests) depend on
//! this crate and use these names directly instead of duplicating
//! string constants.
//!
//! This crate is deliberately small and dependency-free so it can be
//! pulled in by anything that needs the vocabulary without dragging in
//! the kernel, platform code, or any chip/host feature. Enable the
//! `serde` feature to get `Serialize`/`Deserialize` on every type.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod log_ring;
pub mod observability;
pub mod vocabulary;

/// Canonical content-type identifiers for the four storage surfaces
/// Fluxor publishes. Implementers expose themselves on the mesh under
/// one of these strings.
pub mod content_type {
    pub const STORAGE_BLOCK: &str = "storage.block";
    pub const FILE_DATA: &str = "file.data";
    pub const STORAGE_NAMESPACE: &str = "storage.namespace";
    pub const STORAGE_OBJECT: &str = "storage.object";
}

// ── Content type string→u8 mapping (single source of truth) ─────────────────
//
// Position in this table is the on-wire content_type byte used in every
// compiled module manifest and every wired edge. Manifest authors reference
// these names in `[[ports]].content_type`; tooling parses the name and writes
// the byte index. The kernel routes by byte, never by name.
//
// AV surface family:
//   - AudioSample  — decoded sample-domain audio
//   - AudioEncoded — codec-domain audio access units (Opus/MP3/AAC/G.711/...)
//   - VideoEncoded — codec-domain video access units (H.264/H.265/AV1/...)
//   - VideoDraw    — retained/replayable draw lists (UI, browser, dashboards)
//   - VideoRaster  — pixel-domain frames
//   - VideoScanout — present-ready output to a paced display sink
//   - MediaMuxed   — deliberate combined AV/timing/container streams
//
// Codec identity is deliberately NOT part of this table. Encoded surfaces
// are generic (AudioEncoded / VideoEncoded): a content type names a
// substitution surface, not an implementation enumeration, so per-codec
// forks are rejected at review. Codec identity travels in-band — encoded
// access units and container formats are self-describing — or as a
// capability fact on the wiring edge. Whole encoded images ride
// OctetStream (magic-byte self-describing). See the vocabulary admission
// test in `docs/architecture/abi_layers.md`.

/// Content-type byte → friendly name. Single source of truth re-exported
/// by `fluxor-tools` so manifest parsing and compiled-config decoding
/// share one table. Position in this slice is the on-wire byte.
/// **Appending is safe; reordering or removing entries is a wire-format
/// break** that would silently mis-route every wired edge in every
/// existing config blob.
pub const CONTENT_TYPES: &[&str] = &[
    "OctetStream",
    "Cbor",
    "Json",
    "AudioSample",
    "TextPlain",
    "TextHtml",
    "VideoRaster",
    "MeshEvent",
    "MeshCommand",
    "MeshState",
    "MeshHandle",
    "InputEvent",
    "GestureMatch",
    "FmpMessage",
    "EthernetFrame",
    "HciMessage",
    "AudioEncoded",
    "VideoEncoded",
    "VideoDraw",
    "VideoScanout",
    "MediaMuxed",
    // WebSocket frame surface — header `{conn_id u32, opcode u8, fin u8,
    // payload_len u16}` followed by `payload_len` bytes. Carried on a port
    // when foundation/http (or another transport gateway) is configured to
    // fan out upgraded connections to a downstream module instead of
    // handling frames internally.
    "WsFrame",
    // Input surface primitive (see input_capability_surface.md §6).
    "InputBinaryState",
    // Generic event-timeline surfaces — variable-size packets carrying
    // event records with stream-time / t-state timestamps. Used to
    // bridge a compute core (e.g. an emulator core) to platform-
    // specific renderer modules without leaking the producer's
    // domain-specific identity. Receivers parse the inner packet
    // shape; the surface itself only declares "frame-aligned event
    // stream, video flavour" or "frame-aligned event stream, audio
    // flavour".
    "EventTimelineVideo",
    "EventTimelineAudio",
    // Net protocol framing — `[msg_type:u8][len:u16 LE][payload]`
    // delivered atomically on a byte-stream channel. Used between
    // network stacks (IP, TLS, QUIC) and their consumers. Distinct
    // from `OctetStream` because consumers cannot parse it without
    // the per-frame TLV; auto-inserted tee/merge modules need this
    // discriminant to preserve frame boundaries during fan-out.
    "NetProto",
    // Per-class input event surfaces (see
    // docs/architecture/input_capability_surface.md). Each carries a
    // packed C-repr record on the wire — pointer/key/gamepad shapes
    // documented in `modules/sdk/contracts/input/*.rs`. The legacy
    // generic "InputEvent" stays in the table for back-compat with
    // older modules, but new graphs wire one of the per-class names
    // below so the kernel and shell stay narrow.
    "PointerEvents",
    "KeyEvents",
    "GamepadEvents",
    // Pre-decoded MIDI channel-voice events — fixed 4-byte frame per
    // `modules/sdk/contracts/input/midi.rs`. Carries
    // `[event_kind, channel, data1, data2]`. Producers: browser Web
    // MIDI, Linux ALSA seq, class-compliant USB-MIDI hosts.
    "MidiEvents",
    // Observability telemetry envelope — fixed-layout `TelemetryRecord`
    // (`modules/sdk/contracts/telemetry.rs`) carrying one metric or span
    // signal. Module-scope telemetry flows on this content type to the
    // `observe` collector; logs ride `log_ring` separately. See
    // `standards/observability.md`.
    "Telemetry",
    // Runtime environment-plane descriptor — fixed 24-byte `MSG_TRAITS`
    // record per `modules/sdk/contracts/input/surface_traits.rs`. The
    // host platform adapter publishes viewport / orientation / size-class
    // / input-modality / audio-config snapshots on this content type; a
    // module that wants to adapt to its surface wires an input port to
    // it. See `.context/rfc_surface_traits.md`.
    "SurfaceTraits",
    // Resolved presentation layout — the `presentation.layout` record per
    // `tools/src/presentation_resolver.rs`: per-control disposition (chrome /
    // content / bound / hidden), plane, flags, and a physical-button legend.
    // The `presentation_resolver` module emits it from a SurfaceTraits stream;
    // chrome/content renderers consume it. See
    // `.context/rfc_adaptive_presentation.md`.
    "PresentationLayout",
    // HTTP application fan-out surface — the request half. Header
    // `{conn_id u16, stream_id u16, method u8, flags u8, path_len u16,
    // hdr_len u16, body_len u16}` followed by `path_len + hdr_len +
    // body_len` bytes. Carried on a port when a transport gateway — a
    // consuming HTTP module — is configured to hand a matched route's
    // requests to a downstream module instead of answering them itself.
    //
    // The pair with `HttpResponse` is what lets a graph serve an API
    // whose meaning lives in an application module: the gateway keeps
    // owning HTTP framing, connection state and bounded body handling,
    // and owns none of the request's meaning. `stream_id` is carried
    // beside `conn_id` because HTTP/2 multiplexes many requests over one
    // connection — correlating on `conn_id` alone misroutes the moment a
    // client opens parallel streams.
    "HttpRequest",
    // HTTP application fan-out surface — the response half. Header
    // `{conn_id u16, stream_id u16, status u16, flags u8, ct_len u8,
    // hdr_len u16, body_len u16}` followed by `ct_len + hdr_len +
    // body_len` bytes. The gateway matches it back to the originating
    // request by `(conn_id, stream_id)`.
    "HttpResponse",
    // Control-plane store change surface — one record per key mutation,
    // emitted by the `storage.namespace` SUBSCRIBE stream. Payload
    // `{revision u64, kind u8, key_len u16, val_len u32}` followed by
    // `key_len + val_len` bytes, inside a mesh Event envelope. A watcher
    // routes on this byte to tell a store change from every other event
    // sharing its sink.
    "NamespaceChange",
    // Generic GPU work — the request stream of `modules/sdk/wire/gpu_wire.rs`
    // (query, resource, program, transfer, submission, fence, control and
    // surface records) flowing from a producer to a GPU provider.
    //
    // A distinct type rather than `OctetStream` because what a port speaks is
    // decided at graph construction, never by sniffing bytes: a port carrying
    // this stream is typed for it, and the record header's magic is then a
    // framing check rather than a discriminator.
    "GpuCommand",
    // Generic GPU outcomes — the reply half: acceptance, handles,
    // capabilities, readback bytes, surface leases and exactly one terminal
    // outcome per accepted request.
    "GpuOutcome",
];

// ── Rate classes ────────────────────────────────────────────────────────────

/// Sustained-throughput class of a stream. Attached to content types
/// (defaults below) and overridable per wiring edge (`rate:`). The
/// config compiler validates each edge's granted ring against its
/// class floor at build time; the kernel derives per-step pump
/// budgets from it (`MODULE_FLOW_BUDGET`).
///
/// Deliberately does **not** derive `PartialOrd`/`Ord`: declaration
/// order here is wire-stable (see the on-wire byte mapping in
/// `kernel/config.rs`) and does not match the "how demanding is this
/// edge" severity order the config validator actually needs — notably
/// `Transaction` is declared last but ranks least-demanding after
/// `Control`. Use [`RateClass::severity`] for any comparison; a derived
/// `Ord` here would silently compare the wrong thing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum RateClass {
    Control = 0,
    Audio = 1,
    Video = 2,
    Bulk = 3,
    /// Latency-sensitive request/response traffic. Kept distinct from
    /// media classes even though its initial byte-rate floor matches audio:
    /// transaction graphs should not have to claim an audio contract merely
    /// to opt into bounded flow pacing and stall detection.
    Transaction = 4,
}

impl RateClass {
    pub fn from_str_opt(s: &str) -> Option<RateClass> {
        match s {
            "control" => Some(Control),
            "audio" => Some(Audio),
            "video" => Some(Video),
            "bulk" => Some(Bulk),
            "transaction" => Some(Transaction),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Control => "control",
            Audio => "audio",
            Video => "video",
            Bulk => "bulk",
            Transaction => "transaction",
        }
    }
    /// How demanding this class is to provision for, least to most:
    /// `Control < Transaction < Audio < Video < Bulk`. The single
    /// source of truth for "does edge class A exceed cap B" — never
    /// compare `RateClass` values any other way.
    pub fn severity(&self) -> u8 {
        match self {
            Control => 0,
            Transaction => 1,
            Audio => 2,
            Video => 3,
            Bulk => 4,
        }
    }
    /// True if `self` demands more than `cap` allows.
    pub fn exceeds(&self, cap: RateClass) -> bool {
        self.severity() > cap.severity()
    }
}

use RateClass::{Audio, Bulk, Control, Transaction, Video};

/// Default rate class per content type — POSITION-PARALLEL with
/// `CONTENT_TYPES` (compile-time length guard below). These are
/// conservative floors, not aspirations: a class is what every edge
/// of that type must be provisioned for by default, so types with
/// legitimately slow uses default low and fast graphs override at
/// the edge. Notably `VideoRaster` defaults to `audio` (≈1 MB/s):
/// embedded image viewers stream one raster occasionally and must
/// not fail validation on small-profile targets; genuine motion-
/// raster pipelines declare `rate: video` on the edge.
pub const CONTENT_RATE_CLASS: &[RateClass] = &[
    Control, // OctetStream (carrier — class comes from the edge)
    Control, // Cbor
    Control, // Json
    Audio,   // AudioSample
    Control, // TextPlain
    Control, // TextHtml
    Audio,   // VideoRaster (see note above)
    Control, // MeshEvent
    Control, // MeshCommand
    Control, // MeshState
    Control, // MeshHandle
    Control, // InputEvent
    Control, // GestureMatch
    Control, // FmpMessage
    Audio,   // EthernetFrame (embedded NICs are legitimate slow users;
    // gigabit-class graphs override at the edge)
    Control, // HciMessage
    Audio,   // AudioEncoded
    Video,   // VideoEncoded
    Video,   // VideoDraw
    Video,   // VideoScanout
    Video,   // MediaMuxed
    Control, // WsFrame (bursty envelopes; streaming uses override)
    Control, // InputBinaryState
    Video,   // EventTimelineVideo
    Audio,   // EventTimelineAudio
    Audio,   // NetProto (same reasoning as EthernetFrame)
    Control, // PointerEvents
    Control, // KeyEvents
    Control, // GamepadEvents
    Control, // MidiEvents
    Control, // Telemetry
    Control, // SurfaceTraits
    Control, // PresentationLayout
    // Request and response envelopes are bursty control traffic by
    // default, on the same reasoning as WsFrame: one envelope per
    // request/response, not a sustained stream. A route that carries
    // bulk bodies (artefact push/pull, media upload) declares `rate:`
    // on the edge rather than reclassifying the type for everyone.
    Control, // HttpRequest
    Control, // HttpResponse
    // One record per key mutation — bursty control traffic, not a stream.
    Control, // NamespaceChange
    // Bulk by nature: uploads and readbacks move in runs of 64 KiB chunks, so
    // an edge provisioned for control traffic would throttle the transfer path
    // that the contract's bounded-chunk design exists to keep fast.
    Video, // GpuCommand
    Video, // GpuOutcome
];

const _: () = assert!(CONTENT_RATE_CLASS.len() == CONTENT_TYPES.len());

// ── Framing ─────────────────────────────────────────────────────────────────

/// How a channel must deliver a content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Bytes. A reader may be handed any split of the stream and
    /// reassemble it — the default channel is a byte FIFO, and that is
    /// the right shape.
    Streamed,
    /// Whole records. One write is one envelope with a header declaring
    /// its own length, so a reader handed half of one cannot recover:
    /// it parses the header of a fragment and reads a length that is not
    /// there. Edges carrying these must be in mailbox mode, which is
    /// what a non-zero `buffer_group:` selects.
    Framed,
}

use Framing::{Framed, Streamed};

/// Framing per content type — POSITION-PARALLEL with `CONTENT_TYPES`
/// (compile-time length guard below).
///
/// `Framed` is the narrow case and is claimed only where fragmenting is
/// a known correctness failure rather than a performance one. It is a
/// property of the TYPE, not of a port: producer and consumer cannot be
/// allowed to disagree about whether a record may arrive in pieces, and
/// a per-manifest field would let them.
pub const CONTENT_FRAMING: &[Framing] = &[
    Streamed, // OctetStream
    Streamed, // Cbor
    Streamed, // Json
    Streamed, // AudioSample
    Streamed, // TextPlain
    Streamed, // TextHtml
    Streamed, // VideoRaster
    Streamed, // MeshEvent
    Streamed, // MeshCommand
    Streamed, // MeshState
    Streamed, // MeshHandle
    Streamed, // InputEvent
    Streamed, // GestureMatch
    Streamed, // FmpMessage
    Streamed, // EthernetFrame
    Streamed, // HciMessage
    Streamed, // AudioEncoded
    Streamed, // VideoEncoded
    Streamed, // VideoDraw
    Streamed, // VideoScanout
    Streamed, // MediaMuxed
    Framed,   // WsFrame — fan-out envelope, header-framed per frame
    Streamed, // InputBinaryState
    Streamed, // EventTimelineVideo
    Streamed, // EventTimelineAudio
    Streamed, // NetProto
    Streamed, // PointerEvents
    Streamed, // KeyEvents
    Streamed, // GamepadEvents
    Streamed, // MidiEvents
    Streamed, // Telemetry
    Streamed, // SurfaceTraits
    Streamed, // PresentationLayout
    Framed,   // HttpRequest
    Framed,   // HttpResponse
    // One record per key mutation, inside a mesh Event envelope — a reader
    // that was handed half of one could not tell which key changed.
    Framed, // NamespaceChange
    // Streamed, deliberately. Every record declares its own length in a
    // fixed 16-byte header and the decoder buffers a partial one, so a split
    // is recoverable — which is what lets a 64 KiB upload chunk cross a
    // smaller ring instead of demanding one sized for the largest record.
    Streamed, // GpuCommand
    Streamed, // GpuOutcome
];

const _: () = assert!(CONTENT_FRAMING.len() == CONTENT_TYPES.len());

/// Per-class sustained-rate floor in bytes/second, per profile family.
/// `None` = the class is unsatisfiable on that profile (64 KiB buffer
/// arenas cannot host video/bulk rings) — wiring such an edge is a
/// validation error, not a per-edge arithmetic failure.
pub fn rate_class_floor(class: RateClass, embedded: bool) -> Option<u32> {
    match (class, embedded) {
        (Control, false) => Some(64 * 1024),
        (Audio, false) => Some(1024 * 1024),
        (Video, false) => Some(16 * 1024 * 1024),
        (Bulk, false) => Some(64 * 1024 * 1024),
        (Transaction, false) => Some(1024 * 1024),
        (Control, true) => Some(8 * 1024),
        (Audio, true) => Some(256 * 1024),
        (Transaction, true) => Some(256 * 1024),
        (Video, true) | (Bulk, true) => None,
    }
}

/// Per-operation fence: the actual guarantee a returning operation
/// achieved. Operations MUST NOT advertise a fence stronger than the
/// underlying graph produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum Fence {
    Volatile,
    LocalDurable,
    ReplicatedDurable {
        quorum: u32,
        epoch: u64,
        witness: ClustorFenceWitness,
    },
    ContentHashed {
        algo: HashAlgo,
        digest: Vec<u8>,
    },
    RevisionMonotone {
        revision: u64,
    },
    ViewConsistent {
        view_epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum HashAlgo {
    Sha256,
    Blake3,
}

/// Externally observable proof that a replicated-durable fence
/// completed. Constructed by the Clustor binding the operation went
/// through; carried on `Fence::ReplicatedDurable` so downstream
/// consumers can verify the fence was real.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ClustorFenceWitness {
    pub fence_epoch: u64,
    pub manifest_id: String,
    pub quorum: u32,
    pub acked_participants: Vec<String>,
}

impl ClustorFenceWitness {
    pub fn new(
        fence_epoch: u64,
        manifest_id: impl Into<String>,
        quorum: u32,
        acked: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut acked: Vec<String> = acked.into_iter().map(Into::into).collect();
        acked.sort();
        Self {
            fence_epoch,
            manifest_id: manifest_id.into(),
            quorum,
            acked_participants: acked,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.acked_participants.is_empty()
    }
}

/// A leased handle into the mesh, returned when a caller opens a
/// namespace or object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StorageHandle {
    pub surface: StorageSurface,
    pub content_type: &'static str,
    pub mesh_handle_id: u64,
    pub lease_epoch: u64,
}

/// Identifier for which of the four Fluxor-owned surfaces a handle or
/// descriptor refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StorageSurface {
    Block,
    FileData,
    Namespace,
    Object,
}

impl StorageSurface {
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Block => content_type::STORAGE_BLOCK,
            Self::FileData => content_type::FILE_DATA,
            Self::Namespace => content_type::STORAGE_NAMESPACE,
            Self::Object => content_type::STORAGE_OBJECT,
        }
    }
}
