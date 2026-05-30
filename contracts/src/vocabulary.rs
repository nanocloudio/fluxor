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
