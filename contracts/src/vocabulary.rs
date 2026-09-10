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
    // Produces frames of a display that exists somewhere else — a shared
    // screen, window, or tab — as opposed to *being* a display
    // (`display.scanout`) or being a camera. A viewer that cannot tell a
    // shared screen from a camera cannot tell a person what is being shared,
    // so the distinction is a declared role rather than a convention.
    "display.capture",
    "video.decode",
    "video.encode",
    "video.decode.protected",
    "audio.output.protected",
    "audio.output.rate_trim",
    "gpu.render",
    "gpu.compute",
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
    // rp2350 / bcm2712).
    "midi.input",
    "midi.output",
    // Transport surfaces + continuity roles (protocol_surfaces.md,
    // capability_surface.md §Transport Surface / §Continuity Role;
    // validated as graph structure by the `continuity` config block).
    "transport.stream",
    "transport.stream.tcp",
    "transport.stream.secure",
    "transport.datagram",
    "transport.datagram.udp",
    "transport.datagram.secure",
    "transport.mux",
    "transport.mux.quic",
    "transport.packet",
    "transport.anchor.stream",
    "transport.anchor.stream.secure",
    "transport.anchor.datagram",
    "transport.anchor.mux",
    "session.worker",
    "session.directory",
    "session.resume",
    "session.handoff",
    "session.reservation",
    "security.tls13.stream",
    "security.dtls13.datagram",
    "security.key_wrap",
    "fence.enforceable",
    "durable.rpo_zero",
    // Calendar time — seconds since the Unix epoch — with evidence of
    // synchronisation, as the kernel's `timer::TRUSTED_UNIX` reports it.
    // Provided by the TARGET, not by a module: it is a property of the
    // platform's HAL, answered per target in the composer's target-facts
    // table, and a manifest names it in `[[requires_when]]` to be refused
    // at compose on a target that cannot back it. Distinct from
    // `timer_class = "wall_clock"`, which is about monotonic elapsed time.
    "time.wall",
    "replication.state_machine",
    // The ordered-ack exchange surface (`modules/sdk/contracts/exchange.rs`):
    // ordered publishes in, durable acks out, and — for a provider that
    // answers — a reply carrying data on the same correlation.
    //
    // Three names — one parent and two roles — because the roles are not
    // interchangeable in both directions. An exchange does everything a sink
    // does and more, so a consumer that only publishes requires the PARENT
    // and the parent-matches-child rule accepts either role; a consumer that
    // needs an answer requires `.exchange`, which a sink correctly fails to
    // satisfy.
    "stream.ordered_ack",
    "stream.ordered_ack.sink",
    "stream.ordered_ack.exchange",
    // ── Effect surfaces ────────────────────────────────────────────────
    // Substitutable application-effect providers: what a graph binds when a
    // stage publishes, subscribes, or calls out, as opposed to the transport
    // it rides. Named domain-leading like every other entry (`stream.*`,
    // `request.*`) — there is no `effect.` meta-prefix, because every name in
    // this registry already denotes one.
    //
    // `stream.publish` generalises `stream.ordered_ack`. The narrower name
    // is a capability of its own rather than a fact on this one, because it
    // additionally promises the durable-ack session protocol in
    // `modules/sdk/contracts/exchange.rs` — link-state signals and
    // replay-after-LINK_DOWN, which is NOT a plain call. `stream.publish` is
    // the substitutable fire-and-collect surface a pipeline stage or a
    // program binds. A provider may declare both.
    //
    // Profile differences are CAPABILITY FACTS (`CAPABILITY_FACTS` below),
    // never name forks: `stream.publish` with `broadcast = "fanout"` is
    // Kafka's genuine multi-partition ack, and with `broadcast =
    // "degenerate"` is MQTT's single ordering unit.
    "stream.publish",
    "stream.subscribe",
    // A line-oriented text stream: the shell-pipe surface. One command's
    // output feeds the next command's input, unidirectional, backpressured by
    // the channel, with no correlation and no acks — deliberately NOT the
    // ordered-ack surface, which exists to answer "did this record land
    // durably?", a question a pipe never asks.
    //
    // Declared by a producer, required by a consuming port: the pairing of
    // an output stream to the input it feeds is otherwise a naming
    // convention with nothing verifying the join.
    "stream.line",
    "request.http",
    "request.record",
];

/// The values one fact admits: an enumerated set, or [`FACT_NUMERIC`] when
/// the fact takes a `u32`.
pub type FactValues = &'static [&'static str];

/// One fact and what it admits — `("ordering", &["per_key", "single"])`.
pub type Fact = (&'static str, FactValues);

/// One capability and the facts it carries.
pub type CapabilityFacts = (&'static str, &'static [Fact]);

/// Facts a capability carries, and the values each fact admits.
///
/// The capability name says WHAT a provider offers; a fact says on what
/// terms. Keeping terms as facts rather than name forks is what lets one
/// consumer requirement match an MQTT, Kafka or AMQP provider alike while
/// still refusing the one whose terms are too weak — the rule the
/// capability-surface document states for quantitative constraints.
///
/// A fact whose admitted-value list is [`FACT_NUMERIC`] takes a `u32`
/// instead of an enumerated string. `max_payload` is the load-bearing one:
/// a provider's ceiling is whatever THAT provider can accept — a broker
/// build, a frame negotiation, a column width — and in practice it lands
/// far below the suite's 8192-byte record. It cannot be inferred from the
/// protocol name, which is exactly why it is a declared fact; validating it
/// against the producing port's `max_record` is what turns a runtime
/// OVERSIZE refusal into a build failure.
///
/// Unknown fact names and unadmitted values are rejected at manifest parse
/// with a did-you-mean, for the same reason the name registries exist: a
/// typo in `ordering` must not read as "unconstrained".
pub const CAPABILITY_FACTS: &[CapabilityFacts] = &[
    (
        // Declared on the PARENT: `.sink` and `.exchange` differ only in
        // whether an answer comes back, which the name already says, so the
        // terms below are the same for both and are stated once. Whether a
        // provider replies is deliberately NOT a fact — a second spelling of
        // the role could contradict the name.
        "stream.ordered_ack",
        &[
            ("ack", &["durable", "transport", "none"]),
            ("ordering", &["per_key", "single", "none"]),
            ("broadcast", &["fanout", "degenerate", "unsupported"]),
            ("max_payload", FACT_NUMERIC),
        ],
    ),
    (
        "stream.publish",
        &[
            // Whether an ack means the provider durably accepted the record,
            // or merely wrote it to a socket.
            ("ack", &["durable", "transport", "none"]),
            // Ordering the provider guarantees between records sharing a key.
            ("ordering", &["per_key", "single", "none"]),
            // Whether a broadcast is a genuine fan-out the provider acks
            // across every ordering unit (Kafka), or degenerates to a plain
            // publish because there is only one (MQTT, AMQP).
            ("broadcast", &["fanout", "degenerate", "unsupported"]),
            ("max_payload", FACT_NUMERIC),
        ],
    ),
    (
        "stream.line",
        &[
            // Whether the stream is delimited into lines or is an opaque
            // byte run: a byte-oriented producer feeding a line-oriented
            // consumer is a mismatch the port types alone do not catch.
            ("framing", &["line", "byte"]),
            ("max_payload", FACT_NUMERIC),
        ],
    ),
    (
        "stream.subscribe",
        &[
            (
                "delivery",
                &["at_least_once", "at_most_once", "exactly_once"],
            ),
            ("replay", &["yes", "no"]),
            ("max_payload", FACT_NUMERIC),
        ],
    ),
    (
        "request.http",
        &[
            ("tls", &["yes", "no"]),
            ("streaming_body", &["yes", "no"]),
            ("max_payload", FACT_NUMERIC),
        ],
    ),
    (
        "request.record",
        &[("txn", &["yes", "no"]), ("max_payload", FACT_NUMERIC)],
    ),
    (
        // How a resumable session resumes. `scope`: `local` — the ticket
        // names state only the minting host holds; `fleet` — the ticket IS
        // the state, sealed under a vault-held key any admitted host with
        // that key generation can open. `early_data`: `off` — 0-RTT is
        // never accepted, every resumption is a full round trip with a
        // fresh key share; `local_single_use` — 0-RTT only against the
        // minting host's single-use record.
        "session.resume",
        &[
            ("scope", &["local", "fleet"]),
            ("early_data", &["off", "local_single_use"]),
        ],
    ),
    (
        // What a fence's cutoff boundary is worth. `ring_handoff`: nothing
        // sourced from the fenced address is handed to the driver ring
        // after the fence answers, but frames already in the ring may still
        // leave — what an IP stack alone can prove. `wire`: a driver that
        // drains and reports its completed transmit index proves no later
        // frame left the NIC.
        "fence.enforceable",
        &[("cutoff", &["ring_handoff", "wire"])],
    ),
    (
        // What a GPU provider offers, on terms a composer can check before
        // anything runs. Deliberately NOT the numeric capability record —
        // allocation limits, workgroup shapes and per-type arithmetic are
        // runtime facts a provider answers to `QUERY_CAPS`, and a compose-time
        // copy of them would be a second source of truth that drifts. These
        // three are the ones that decide whether a graph can be built at all.
        //
        // Declared on the parent, so `gpu.compute` and `gpu.render` share one
        // schema through the parent walk rather than repeating it: a device
        // that does both declares both names on the same terms, because it is
        // one device.
        "gpu",
        &[
            (
                // Which implementation answers. Reported so a measurement can
                // name its provider, never requested — a consumer that needs
                // a property asks for the property.
                "backend",
                &["replay", "webgpu", "wgpu_native"],
            ),
            // Whether results can come back to the CPU at all. A headless
            // compute graph that cannot read its own output is a composition
            // error worth catching at build time.
            ("readback", &["yes", "no"]),
            // Whether a device-resident resource can be handed to a sink
            // without a CPU round trip.
            ("shared_surface", &["yes", "no"]),
        ],
    ),
    (
        // What a scanout surface actually costs to hand on. A zero-copy claim
        // is a measurement, so `unproven` is the honest default and the only
        // value a provider may declare before it has one — the alternative is
        // a graph composed on the belief that a copy it is paying for is not
        // happening.
        "video.scanout",
        &[("transfer", &["zero_copy", "readback_copy", "unproven"])],
    ),
    (
        // Where a target's calendar time comes from — the strongest source
        // class its HAL can report `TRUSTED`, in `trusted_time::source`
        // terms. A target with none does not carry the capability at all.
        "time.wall",
        &[("source", &["rtc", "network_sync", "signed_authority"])],
    ),
];

/// Capabilities a TARGET provides rather than a module: properties of the
/// platform HAL that a manifest can require but nothing in a graph declares.
/// Answered per target by the composer's target-facts table; a
/// `[[requires_when]]` naming any other capability is a manifest error.
pub const TARGET_CAPABILITIES: &[&str] = &["time.wall"];

/// Marker for a fact whose value is a `u32` rather than one of an
/// enumerated set. Compared by identity of the empty slice's contents, so a
/// fact table entry spells it as this constant rather than `&[]`.
pub const FACT_NUMERIC: FactValues = &["<u32>"];

/// The facts admitted for `capability`, or `None` when the capability
/// carries none.
pub fn facts_for(capability: &str) -> Option<&'static [Fact]> {
    capability_and_parents(capability).find_map(|probe| {
        CAPABILITY_FACTS
            .iter()
            .find(|(name, _)| *name == probe)
            .map(|(_, facts)| *facts)
    })
}

/// `capability` followed by each of its dot-separated parents, most
/// specific first: `a.b.c`, then `a.b`, then `a`.
///
/// Sibling roles under one parent (`stream.ordered_ack.sink` and
/// `.exchange`) share the parent's fact schema rather than repeating it, so
/// resolving a name means walking this sequence. Both the registry lookup
/// above and the build-time manifest checks use the same walk, so a name
/// resolves identically wherever it is read.
pub fn capability_and_parents(capability: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(capability);
    core::iter::from_fn(move || {
        let current = next?;
        next = current.rfind('.').map(|dot| &current[..dot]);
        Some(current)
    })
}

/// Whether `fact` on `capability` takes a numeric value.
pub fn fact_is_numeric(capability: &str, fact: &str) -> bool {
    facts_for(capability)
        .and_then(|facts| facts.iter().find(|(name, _)| *name == fact))
        .is_some_and(|(_, admitted)| *admitted == FACT_NUMERIC)
}

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

/// Names accepted in a module manifest's `provides = [..]` field — the
/// producer side of a resolvable dependency. A superset of the
/// `PROVIDER_CONTRACTS` service/contract names above with the storage
/// **surface** family (`storage_capability_surface.md` §1): `storage.block`
/// and `file.data` are surfaces a provider advertises but are not
/// class-byte-dispatched contracts, so they live here rather than in
/// `PROVIDER_CONTRACTS`. Validated case-insensitively at manifest parse so a
/// typo (`file.dat`, `storage.blocks`) fails the build instead of silently
/// never resolving.
pub const PROVIDER_SURFACES: &[&str] = &["storage.block", "file.data"];

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
