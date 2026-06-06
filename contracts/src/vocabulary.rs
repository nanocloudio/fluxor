//! Canonical build-time vocabulary: the role/surface capabilities accepted in
//! a manifest's `capabilities = [...]` list and the privileged provider-contract
//! names accepted in `requires_contract`.
//!
//! This module is the single source of truth for these naming layers so the
//! kernel, the host tooling, and sibling projects authoring module manifests
//! all share one set of constants instead of duplicating strings. The on-wire
//! `CONTENT_TYPES` byte table (crate root) is a separate, append-only concern.

/// Canonical capability registry accepted in a manifest's top-level
/// `capabilities = [...]` list. Two tiers share one registry: hardware-facing
/// roles (the role a module plays — paced scanout, group clock, protected
/// output, mapper) and service-level surfaces (the substitutable data a
/// producer or consumer carries). Unknown names are rejected at parse time so
/// `display.scaneout` and friends fail the build.
///
/// Grammar is domain-leading lowercase dotted, with the role noun before any
/// refinement (`display.scanout.protected`). Quantities and limits are
/// capability facts, not name segments.
///
/// Documented in `docs/architecture/av_capability_surface.md` (AV/presentation)
/// and `docs/architecture/input_capability_surface.md` (input).
pub const CAPABILITY_NAMES: &[&str] = &[
    // Hardware-facing roles.
    "display.scanout",
    "display.multihead",
    "display.scanout.protected",
    "video.decode",
    "video.encode",
    "video.decode.protected",
    "audio.output.protected",
    "audio.output.rate_trim",
    "gpu.render",
    "presentation.clock",
    // Service-level surfaces (mirror the canonical content-type surface family).
    "audio.sample",
    "audio.encoded",
    "video.encoded",
    "video.draw",
    "video.raster",
    "video.scanout",
    "media.muxed",
    "media.path.protected",
    "presentation.group",
    // Input (added as modules declare them; see input_capability_surface.md §5).
    "input.mapper",
    "input.gamepad",
    "input.virtual",
    "input.remote",
    // MIDI surface — paired with the `input::midi` contract and the
    // `MidiEvents` content type. Declared by the per-platform MIDI drivers
    // (Web MIDI on wasm, ALSA seq on linux, class-compliant USB-MIDI on
    // rp2350 / cm5).
    "midi.input",
    "midi.output",
];

/// Canonical provider-contract names accepted in
/// `[[resources]].requires_contract`. Lowercase `snake_case` naming a stable
/// privileged operation family, with the two storage surfaces in their dotted
/// spelling because they mirror the public semantic storage surfaces. The
/// ABI-coupled numeric dispatch IDs live in `fluxor-tools`
/// (`manifest::contract_id_from_name`); this is the name vocabulary only.
pub const PROVIDER_CONTRACTS: &[&str] = &[
    "gpio",
    "spi",
    "i2c",
    "pio",
    "channel",
    "timer",
    "platform_nic_ring",
    "platform_dma",
    "fs",
    "buffer",
    "event",
    "uart",
    "adc",
    "pwm",
    "platform_dma_fd",
    "pcie_device",
    "storage.namespace",
    "storage.object",
    "usb_host",
];

/// The naming layer a rename touches. Part of every `RenameEntry`'s
/// identity: the same legacy spelling may legitimately appear in more
/// than one layer (e.g. `audio.pcm` is both a semantic-surface rename
/// to `audio.sample` and a documentation correction to the wire id
/// `AudioSample`), so `(legacy, layer)` — not `legacy` alone — is the
/// uniqueness key the drift guard enforces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layer {
    /// On-wire `content_type` identifier (UpperCamelCase). Only ever
    /// the target of a `doc_only` correction — the positional byte
    /// table itself is append-only and never renamed.
    WireContent,
    /// Substitutable producer/consumer data surface (`audio.sample`).
    Surface,
    /// Hardware-facing or service role capability (`audio.output`).
    Role,
    /// Privileged provider-contract name in `requires_contract`.
    Provider,
    /// A capability fact (quantity/limit), not a name segment.
    Fact,
}

impl Layer {
    /// Stable lowercase token rendered into `vocabulary_map.toml`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Layer::WireContent => "wire_content",
            Layer::Surface => "surface",
            Layer::Role => "role",
            Layer::Provider => "provider",
            Layer::Fact => "fact",
        }
    }
}

/// Whether a rename rewrites executable build-time strings (`rename`)
/// or only corrects prose/examples that used a semantic-surface name
/// where a compiled `content_type` identifier is required (`doc_only`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RenameKind {
    /// Rewrite the spelling at every call site; the parser then
    /// accepts only the canonical form.
    Rename,
    /// Documentation-only correction; no runtime string changes.
    DocOnly,
}

impl RenameKind {
    /// Stable lowercase token rendered into `vocabulary_map.toml`.
    pub const fn as_str(self) -> &'static str {
        match self {
            RenameKind::Rename => "rename",
            RenameKind::DocOnly => "doc_only",
        }
    }
}

/// One legacy→canonical vocabulary rename, the per-entry schema of the
/// machine-readable migration map (`.context/rfc_capability_refinement.md`
/// §8.7). Siblings consume the generated `contracts/vocabulary_map.toml`
/// instead of hand-copying constant lists; this slice is its source of
/// truth, drift-guarded by `tools/tests/vocabulary_map_drift.rs`.
///
/// Per decision 16 this is a *rename* map — there are no alias or
/// deprecation-window fields. `mechanical = false` flags entries that
/// are not a blind 1:1 rewrite and need per-site judgement.
pub struct RenameEntry {
    /// The old spelling to find and rewrite.
    pub legacy: &'static str,
    /// The new spelling to write. For `mechanical = false` entries
    /// this is the representative/default target; the actual canonical
    /// is chosen per call site (e.g. `socket` → the transport surface
    /// it really is).
    pub canonical: &'static str,
    /// Which naming layer the rename touches.
    pub layer: Layer,
    /// Runtime rename vs. documentation-only correction.
    pub kind: RenameKind,
    /// `true` = safe blind codemod; `false` = needs per-site judgement.
    pub mechanical: bool,
}

/// The canonical vocabulary migration map. Rendered verbatim into
/// `contracts/vocabulary_map.toml`; never hand-edit the `.toml`.
///
/// Coverage mirrors `.context/rfc_capability_refinement.md` §8.1–§8.6.
/// The append-only `CONTENT_TYPES` wire table is intentionally absent —
/// its byte positions stay locked by `content_type_byte_positions.rs`.
/// The names in §8.5 ("should not change") are likewise absent.
pub const RENAME_MAP: &[RenameEntry] = &[
    // ── §8.1 Graph capability renames ───────────────────────────────
    e(
        "frame",
        "net.frame",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "frame.wifi",
        "net.frame.wifi",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "frame.ethernet",
        "net.frame.ethernet",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "link.wifi",
        "net.link.wifi",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "packet.net",
        "transport.packet",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "security.dtls13",
        "security.dtls13.datagram",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "audio.out",
        "audio.output",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "audio.in",
        "audio.capture",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "display.touch",
        "input.touch",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "display.protected_scanout",
        "display.scanout.protected",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "video.protected_decode",
        "video.decode.protected",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "audio.protected_out",
        "audio.output.protected",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "audio.rate_trim",
        "audio.output.rate_trim",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "media.protected_path",
        "media.path.protected",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "capture.protected_in",
        "capture.input.protected",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    e(
        "replicated_state_machine",
        "replication.state_machine",
        Layer::Role,
        RenameKind::Rename,
        true,
    ),
    // ── §8.2 Legacy name replacement ────────────────────────────────
    // `socket` is the one rename that cannot be a blind codemod: each
    // site reclassifies to the transport it actually is. The canonical
    // here is the representative default; mechanical = false gates it.
    e(
        "socket",
        "transport.stream",
        Layer::Surface,
        RenameKind::Rename,
        false,
    ),
    // `display.still` / `display.video` both collapse to `display.scanout`
    // but each needs a `max_refresh_hz` / minimum-refresh fact added.
    e(
        "display.still",
        "display.scanout",
        Layer::Role,
        RenameKind::Rename,
        false,
    ),
    e(
        "display.video",
        "display.scanout",
        Layer::Role,
        RenameKind::Rename,
        false,
    ),
    e(
        "audio.pcm",
        "audio.sample",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "display.draw",
        "video.draw",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    // Maps to the landed input identifier (or a richer appended
    // `InputTouchEvent` envelope once it lands) — per-site judgement.
    e(
        "display.touch_event",
        "input.touch_event",
        Layer::Surface,
        RenameKind::Rename,
        false,
    ),
    // ── §8.3 Documentation-only wire-name corrections ───────────────
    e(
        "audio.pcm",
        "AudioSample",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "audio.encoded",
        "AudioEncoded",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "display.draw",
        "VideoDraw",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "frame.ethernet",
        "EthernetFrame",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "control.fmp",
        "FmpMessage",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.stream.cmd.v1",
        "NetStreamCmdV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.stream.evt.v1",
        "NetStreamEvtV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.datagram.tx.v1",
        "NetDatagramTxV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.datagram.rx.v1",
        "NetDatagramRxV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.packet.v1",
        "NetPacketV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.mux.cmd.v1",
        "NetMuxCmdV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.mux.evt.v1",
        "NetMuxEvtV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    e(
        "net.session.ctrl.v1",
        "NetSessionCtrlV1",
        Layer::WireContent,
        RenameKind::DocOnly,
        true,
    ),
    // ── §8.4 ABI-expansion naming refinements ───────────────────────
    e(
        "storage.block.v1",
        "storage.block",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "buffer.lease_ring.v1",
        "buffer.lease_ring",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "net.stream.scaled.v1",
        "transport.stream",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "net.packet.v1",
        "transport.packet",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    e(
        "fpga.region.v1",
        "fpga_region",
        Layer::Provider,
        RenameKind::Rename,
        true,
    ),
    e(
        "accelerator.queue.v1",
        "accelerator.queue",
        Layer::Surface,
        RenameKind::Rename,
        true,
    ),
    // ── §8.6 Provider-contract spelling normalization ───────────────
    e(
        "namespace",
        "storage.namespace",
        Layer::Provider,
        RenameKind::Rename,
        true,
    ),
    e(
        "object",
        "storage.object",
        Layer::Provider,
        RenameKind::Rename,
        true,
    ),
];

/// `const`-fn constructor so `RENAME_MAP` reads as a compact table.
const fn e(
    legacy: &'static str,
    canonical: &'static str,
    layer: Layer,
    kind: RenameKind,
    mechanical: bool,
) -> RenameEntry {
    RenameEntry {
        legacy,
        canonical,
        layer,
        kind,
        mechanical,
    }
}
