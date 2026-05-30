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
// AudioOpus / AudioMp3 / AudioAac / ImageJpeg / ImagePng are codec-tagged
// variants kept distinct from the generic AudioEncoded / VideoEncoded
// surfaces so `content_type` can carry codec identity without sideband.

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
    "AudioOpus",
    "AudioMp3",
    "AudioAac",
    "TextPlain",
    "TextHtml",
    "VideoRaster",
    "ImageJpeg",
    "ImagePng",
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
];

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
