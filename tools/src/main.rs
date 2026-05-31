//! Fluxor Config Tool
//!
//! Host-side tools for building and extracting Fluxor firmware configuration.
//!
//! Usage:
//!     fluxor decode firmware.uf2           # Decode config from UF2
//!     fluxor info firmware.uf2             # Show UF2 file info
//!     fluxor generate config.yaml -o config.uf2  # Generate config UF2

#![allow(
    unsafe_code,
    reason = "host CLI wraps libc, mmap, ELF parsing, UF2 packing, and IPC primitives"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI is the user-facing product surface; `println!`/`eprintln!` is intentional output, not log misuse"
)]
//!     fluxor combine firmware.uf2 config.yaml -o combined.uf2
//!     fluxor example blinky                # Show example config
//!     fluxor pack module.o -o module.fmod # Pack ELF into .fmod module

mod asset_bank;
mod board;
mod cargo_index;
mod ci;
mod config;
mod crypto;
mod error;
mod hash;
mod hygiene;
mod lockfile;
mod manifest;
mod modules;
mod modules_build;
mod monitor;
mod project;
mod project_meta;
mod publish;
pub mod reconfigure;
mod registry;
mod render_template;
pub mod rig;
mod scenario;
mod schema;
mod stack_expand;
mod sync;
pub mod target;
mod text_distance;
mod uf2;
mod up;
mod wasm_bundle;
mod workspace;

/// Wire-format constants — path-mounted from `modules/sdk/wire.rs` so
/// the host tools see the exact same `ABI_VERSION` byte and `fnv1a32`
/// implementation the kernel uses. The lib facade in `tools/src/lib.rs`
/// mounts the same file for integration tests. `#[allow(dead_code)]`
/// because tools only need a subset of the constants (e.g.
/// `CHANNEL_HINT_WIRE_BYTES` is kernel-side only) but the file is
/// shared verbatim.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[path = "../../modules/sdk/wire.rs"]
mod wire;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::config::{decode_config, generate_config_ext, ConfigBuilder, ModuleCaps, EXAMPLES};
use crate::error::{Error, Result};
use crate::modules::{build_module_table, pack_fmod, parse_modules_from_config_multi};
use crate::monitor::cmd_monitor_dispatch;
use crate::uf2::{create_uf2_blocks, fix_uf2_block_numbers, parse_uf2, UF2_FAMILY_RP2350};

/// Flash layout constants
const XIP_BASE: u32 = 0x10000000;

/// Trailer format (placed right after firmware, before modules/config)
const TRAILER_MAGIC: u32 = 0x544C5846; // "FXLT"
const TRAILER_VERSION: u8 = 1;

#[derive(Parser)]
#[command(name = "fluxor")]
#[command(about = "Fluxor Config Tool - Build and extract configuration for Fluxor firmware")]
#[command(version)]
struct Cli {
    /// Verbose mode - show detailed output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode configuration from UF2 firmware file
    Decode {
        /// UF2 file to decode
        file: PathBuf,
        /// Output format (json or yaml)
        #[arg(short, long, default_value = "yaml")]
        format: String,
    },
    /// Show UF2 file information
    Info {
        /// UF2 file to inspect
        file: PathBuf,
    },
    /// Generate config UF2 from YAML/JSON file
    Generate {
        /// Config file (YAML or JSON)
        config: PathBuf,
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Override modules directory (default: target/fluxor/{silicon}/modules)
        #[arg(short = 'm', long)]
        modules_dir: Option<PathBuf>,
        /// Output raw binary instead of UF2
        #[arg(long)]
        binary: bool,
    },
    /// Combine firmware + config into single UF2
    Combine {
        /// Firmware UF2 file
        firmware: PathBuf,
        /// Config file (YAML, JSON, or UF2)
        config: PathBuf,
        /// Output combined UF2
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Build an OTA slot image (modules + config + slot header) for
    /// writing to a graph_slot A/B region. Excludes firmware.
    SlotImage {
        /// Config file (YAML or JSON)
        config: PathBuf,
        /// Output slot image (raw binary sized to the slot)
        #[arg(short, long)]
        output: PathBuf,
        /// Target override (default: read from config YAML 'target:' field)
        #[arg(short, long)]
        target: Option<String>,
        /// Epoch to embed in the slot header. Must exceed the currently
        /// live slot's epoch for activation to succeed.
        #[arg(long, default_value = "1")]
        epoch: u64,
    },
    /// Show example configuration
    Example {
        /// Example name: blinky, sd-audio, playlist, test-tone, gesture-led
        #[arg(default_value = "blinky")]
        name: String,
    },
    /// Pack ELF object file into .fmod module format
    Pack {
        /// Input ELF object file (.o or .a)
        input: PathBuf,
        /// Output .fmod file
        #[arg(short, long)]
        output: PathBuf,
        /// Module name (default: derived from filename)
        #[arg(short, long)]
        name: Option<String>,
        /// Module type: 1=Source, 2=Transformer, 3=Sink, 4=EventHandler, 5=Protocol
        #[arg(short = 't', long, default_value = "2")]
        module_type: u8,
        /// Path to manifest.toml (default: auto-detect next to input)
        #[arg(short = 'm', long)]
        manifest: Option<PathBuf>,
    },
    /// Validate config file against target constraints
    Validate {
        /// Config file (YAML or JSON)
        config: PathBuf,
        /// Target override (default: read from config YAML 'target:' field, fallback: pico2w)
        #[arg(short, long)]
        target: Option<String>,
    },
    /// Show target configuration details
    TargetInfo {
        /// Target name (board or silicon, e.g. pico2w, rp2350a, rp2040)
        target: String,
        /// Query a specific field (rust_target, cargo_features, uf2_family_id, max_pin, module_target)
        #[arg(long)]
        field: Option<String>,
    },
    /// List available targets
    Targets,
    /// Build module table blob from .fmod files
    Mktable {
        /// Directory containing .fmod files
        dir: PathBuf,
        /// Output binary file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Build a module table blob from modules referenced by a config file
    MktableConfig {
        /// Config file (YAML or JSON)
        config: PathBuf,
        /// Directory containing built .fmod files (repeatable)
        #[arg(short = 'm', long, action = clap::ArgAction::Append)]
        modules_dir: Vec<PathBuf>,
        /// Output binary file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Show transition plan between two config files (live reconfigure diff)
    Diff {
        /// Old config file (YAML)
        old_config: PathBuf,
        /// New config file (YAML)
        new_config: PathBuf,
        /// Target override (default: read from new config YAML 'target:' field, fallback: pico2w)
        #[arg(short, long)]
        target: Option<String>,
    },
    /// Build one config or all configs in a directory
    Build {
        /// Config file (YAML) or directory containing YAML files
        path: PathBuf,
        /// Output file (default: auto-derived from target)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Build and run a config (Linux or QEMU targets), or run a
    /// deployment scenario (`kind: scenario`).
    ///
    /// Scenario flags (see `.context/rfc_deployment_scenarios.md`):
    ///   --print-synthesised      dump the synthesised host graph YAML
    ///                            and exit (no spawning).
    ///   --print-merged <comp>    dump the binding-augmented config
    ///                            for the named component and exit
    ///                            (PR 2; reports not-yet-impl in PR 1).
    ///   --validate-only          parse, validate, exit (CI-friendly).
    ///   --list [dir]             enumerate scenario files in `dir`
    ///                            (or CWD) and exit. `<config>` may be
    ///                            omitted.
    ///   --graph                  emit Graphviz DOT of the scenario
    ///                            (nodes = components, edges = bindings).
    Run {
        /// Config file (YAML).  Optional only when `--list` is given.
        config: Option<PathBuf>,
        /// Scenario only: dump the synthesised host graph YAML and exit.
        #[arg(long)]
        print_synthesised: bool,
        /// Scenario only: dump the binding-augmented config for the
        /// named component and exit (PR 2; PR 1 errors not-yet-impl).
        #[arg(long, value_name = "COMPONENT")]
        print_merged: Option<String>,
        /// Scenario only: parse + validate the scenario, exit without
        /// spawning anything.
        #[arg(long)]
        validate_only: bool,
        /// Scenario only: emit Graphviz DOT of the scenario.
        #[arg(long)]
        graph: bool,
        /// List scenarios in the given directory (default: CWD) and
        /// exit.  When set, `<config>` is ignored.
        #[arg(long, value_name = "DIR", num_args = 0..=1, default_missing_value = ".")]
        list: Option<PathBuf>,
        /// Scenario only: after the readiness probe fires, launch the
        /// system browser (`xdg-open` on linux, `open` on macOS) on
        /// the synthesised-host URL.
        #[arg(long)]
        open: bool,
    },
    /// Build and flash a config to hardware
    Flash {
        /// Config file (YAML)
        config: PathBuf,
    },
    /// Render a YAML config template by substituting `__KEY__`
    /// placeholders with `--var KEY=VALUE` pairs. Writes the
    /// rendered text to stdout (or `--output`).
    ///
    /// Fails if any `__KEY__` placeholder remains unresolved after
    /// substitution — the common failure mode is a typo in a var
    /// name and surfacing it at render time beats a confusing parse
    /// error at `fluxor run` time.
    ///
    /// Example — render the per-node yaml of a 3-replica template:
    ///   fluxor render-template configs/multi-3node.yaml \
    ///       --var SELF_ID=0 --var LISTEN_PORT=9090 \
    ///       --var PEER0_PORT=9090 --var PEER1_PORT=9091 \
    ///       --var PEER2_PORT=9092 --var HTTP_PORT=19090
    RenderTemplate {
        /// Template file (YAML, JSON, or any text format using
        /// `__KEY__` placeholders).
        template: PathBuf,
        /// `KEY=VALUE` pair. Keys are uppercase ASCII letters,
        /// digits, and underscores. Repeat for every placeholder.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Write rendered output to this path instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Render a template N times and spawn N `fluxor run` processes
    /// side-by-side, tailing their stderr until Ctrl+C. Designed
    /// for local multi-replica bring-up (Raft clusters, partition
    /// experiments, etc).
    ///
    /// The conventional placeholder set the template should use:
    ///   __SELF_ID__       — replica index (0..replicas-1)
    ///   __LISTEN_PORT__   — base_port + self_id
    ///   __PEER<i>_PORT__  — base_port + i for i in 0..replicas-1
    ///   __HTTP_PORT__     — listen_port + http_offset
    ///
    /// Anything else can be passed via `--var KEY=VALUE` and is
    /// applied uniformly to every replica.
    Up {
        /// Template config to render per replica.
        template: PathBuf,
        /// Number of replicas to spawn.
        #[arg(short = 'r', long, default_value = "3")]
        replicas: u8,
        /// Base wire (`peer_router.listen_port`) port. Replica i
        /// listens on `base_port + i`.
        #[arg(short = 'b', long, default_value = "9090")]
        base_port: u16,
        /// Offset added to `LISTEN_PORT` to derive `HTTP_PORT`.
        /// Default 10000 matches the clustor diagnostic-surface
        /// convention.
        #[arg(long, default_value = "10000")]
        http_offset: u16,
        /// Extra `KEY=VALUE` placeholder substitutions, applied
        /// uniformly to every replica. Repeat for multiple.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },
    /// Stream live fault stats, protection levels, and step timing
    /// histograms from a running Fluxor device.
    ///
    /// Expects the device to emit newline-framed telemetry lines on the
    /// given serial port. See `docs/architecture/monitor-protocol.md`
    /// (text protocol: `MON_FAULT`, `MON_HIST`, `MON_STATE`).
    Monitor {
        /// Serial device path (default: /dev/ttyACM0)
        #[arg(short = 'p', long, default_value = "/dev/ttyACM0")]
        port: String,
        /// Baud rate (default: 115200)
        #[arg(short = 'b', long, default_value = "115200")]
        baud: u32,
        /// Refresh period in milliseconds (default: 500)
        #[arg(long, default_value = "500")]
        refresh_ms: u64,
        /// Consume MON_* lines from UDP netconsole instead of a serial
        /// port. Pass a bind spec like `:6666` or `0.0.0.0:6666`. When
        /// set, --port is ignored.
        #[arg(long)]
        net: Option<String>,
    },
    /// Sign a packed .fmod module with an Ed25519 private key.
    ///
    /// Overwrites the module's manifest with a v2 manifest carrying a valid
    /// Ed25519 signature over the existing SHA-256 integrity hash plus the
    /// signer's public-key fingerprint. The module's code/data/export
    /// sections are unchanged.
    Sign {
        /// Input .fmod file (modified in place unless --output is given)
        input: PathBuf,
        /// Path to a 32-byte raw Ed25519 seed (private key) file.
        /// Generate with `head -c 32 /dev/urandom > key.raw`.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// Output path (default: overwrite input in place)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Hardware-rig orchestration (`rig test --scenario …`, `rig power`, …).
    ///
    /// Host-side hardware-rig orchestration with a board-agnostic
    /// contract. See `.context/rfc_hardware_rig.md` for the model; scenarios
    /// live in `tests/hardware/`, rig profiles live outside the repo in
    /// `~/.config/fluxor/labs/<lab>/rigs/<rig>.toml`.
    #[command(subcommand_value_name = "RIG_SUBCOMMAND")]
    Rig(rig::cli::RigArgs),

    /// Describe what `fluxor` resolves to from your current working
    /// directory: the project root (and how it was discovered),
    /// available targets and stacks, and — when a config is given —
    /// the resolved target, expanded stack modules, and module
    /// search paths. The diagnostic surface for "why doesn't my
    /// build see this stack?" / "is fluxor pointed at the right
    /// tree?". See `tools/src/project.rs` for the resolution order.
    Inspect {
        /// Optional config (YAML / JSON) to also resolve the target,
        /// expanded stacks, and module search paths for. Without
        /// this argument `inspect` prints project-level info only.
        config: Option<PathBuf>,
        /// Emit machine-readable JSON instead of the default
        /// human-friendly text. The shape is stable v1: a top-level
        /// object with `project_root`, `install_root`, `targets`,
        /// `stacks`, `rig`, `scenarios` keys (plus `config` when a
        /// config arg is supplied). Use this for CI/IDE/dashboard
        /// integrations that want to react to discovery state.
        #[arg(long)]
        json: bool,
    },

    /// Source-tree lint suite. Each subcommand enforces one rule
    /// over the workspace.
    Lint {
        #[command(subcommand)]
        action: LintAction,
    },

    /// PIC module build orchestration. In-process discovery +
    /// compile + pack pipeline; flags are documented per subcommand.
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },

    /// Full CI gate. Runs in order: fmt-check, clippy, workspace-lint
    /// opt-in audit, hygiene scan, template render, version-skew
    /// check, cargo unit tests, modules build (strict), and cargo
    /// integration tests. Every phase runs even when an earlier one
    /// fails; the summary lists all failures and exits non-zero.
    Ci {
        /// Skip an individual phase for local iteration. Rejected
        /// when `$CI=1` so production CI always runs the full set.
        /// Allowed values: cargo, modules, lint, hygiene, templates.
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// Publish artefacts to the local Fluxor registry
    /// (`~/.fluxor/registry/`).
    ///
    /// `fluxor publish --local` (no subcommand) publishes every
    /// publishable artefact in the project with content-hashed `-local.<sha>`
    /// names, for path/git override workflows. Workspace mode
    /// (`~/.fluxor/workspace.toml`) is the preferred way to iterate
    /// across projects without needing publish-local at all.
    Publish {
        #[command(subcommand)]
        action: Option<PublishAction>,
        /// Local-publish all publishable artefacts (no subcommand form).
        /// Each artefact gets a `-local.<content-hash>` suffix.
        #[arg(long, conflicts_with = "action")]
        local: bool,
        /// Project root override. Defaults to the directory resolved
        /// by `fluxor inspect`.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// Regenerate `fluxor.lock` from the current `fluxor.toml` and the
    /// registry's available versions.
    Update {
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Features to activate when resolving `[dependencies]`.
        /// Optional deps (those declared with `optional = true`)
        /// participate only when at least one active feature lists
        /// them under `[features]`. Repeat the flag or pass a
        /// comma-separated list.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
    },

    /// Install lockfile-resolved fmods into
    /// `<project>/target/fluxor/<target>/modules/`. The symmetric
    /// half of `fluxor publish fmod`: where publish writes into the
    /// registry, sync copies *from* the registry into the local
    /// build tree where `fluxor modules build` / `fluxor flash`
    /// expect to find foundation fmods.
    ///
    /// Hash-verified against the lockfile. Idempotent: re-running
    /// is a no-op when destination hashes match.
    Sync {
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Don't copy — list what would change.
        #[arg(long)]
        dry_run: bool,
    },

    /// Inspect and maintain the local Fluxor registry.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },

    /// Inspect the live-workspace state (`~/.fluxor/workspace.toml`).
    ///
    /// Workspace mode is detected positionally — by whether the CWD
    /// sits inside a listed member. This command shows whether the
    /// workspace file is present, which members it lists, and whether
    /// the current working directory triggers live-mode resolution.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
}

#[derive(Subcommand)]
enum PublishAction {
    /// Publish `fluxor-abi` (fluxor repo only).
    Abi {
        /// Content-hashed `-local.<sha>` suffix for the published
        /// artefact — for cross-project iteration without committing
        /// to a canonical version.
        #[arg(long)]
        local: bool,
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish `fluxor-sdk` and `fluxor-sdk-macros` (fluxor repo only).
    Sdk {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish `<project>-common` (every downstream project).
    Common {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish compiled `.fmod` artefacts. Defaults to every
    /// `(target, module)` declared in `fluxor.toml::[ci].targets ×
    /// modules/`.
    Fmod {
        /// Limit to one target.
        #[arg(long)]
        target: Option<String>,
        /// Limit to one module.
        #[arg(long)]
        module: Option<String>,
        #[arg(long)]
        local: bool,
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish a host runtime binary (e.g. `fluxor-linux`). Reads
    /// `<project>/target/<host-target>/release/<binary>` and copies
    /// to `~/.fluxor/registry/bin/<project>/<host-target>/<binary>/
    /// <version>`. Downstream `fluxor run` resolves the runtime via
    /// this registry path.
    Runtime {
        /// Binary name (cargo `[[bin]] name`). For fluxor itself,
        /// `fluxor-linux`.
        #[arg(long)]
        binary: String,
        /// Host triple — e.g. `aarch64-unknown-linux-gnu`. Defaults
        /// to the running CLI's host target.
        #[arg(long)]
        host_target: Option<String>,
        #[arg(long)]
        local: bool,
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RegistryAction {
    /// Bootstrap the registry index — create `~/.fluxor/registry/`,
    /// initialise the cargo git-index at `index/`, write
    /// `config.json`. Idempotent; safe to re-run.
    Init,
    /// Inventory the local registry: source crates and fmod palettes
    /// keyed by `(project, target, version)`.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Trim old `-local.<sha>` and `-live.<sha>` artefacts from the
    /// local registry. Default policy: keep newest N per
    /// `(project, target, name)` plus anything younger than M days.
    Gc {
        /// Don't actually delete — list what would be removed.
        #[arg(long)]
        dry_run: bool,
    },
    /// Add the `[registries.fluxor]` alias to `~/.cargo/config.toml`
    /// so cargo can resolve fluxor-published crates by name.
    /// Idempotent: updates a sentinel-bounded block, preserves the
    /// rest of the file.
    SetupCargo,
}

#[derive(Subcommand)]
enum WorkspaceAction {
    /// Print the current workspace state: file location, members,
    /// CWD, and whether live-mode resolution applies to this
    /// invocation.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LintAction {
    /// AST-based hygiene scanner. Bans inline tests in tiers listed
    /// in `fluxor.toml::[ci.hygiene].forbid_inline_tests` and
    /// requires `reason = "..."` on every `#[allow(...)]`. Reports
    /// every violation in one pass.
    Hygiene {
        /// Project root override. Defaults to the directory resolved
        /// by `fluxor inspect` (env > marker walk > CWD).
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Emit machine-readable JSON instead of human-friendly text.
        #[arg(long)]
        json: bool,
    },
    /// Observability instrumentation-contract check
    /// (standards/observability.md §6): every data-moving module declares
    /// `[observability]` metrics/spans or an `exempt` reason, and instrument
    /// names are dotted lowercase. Reports the uninstrumented-module gap list;
    /// fails only on malformed names.
    Observability {
        /// Project root override (defaults to the resolved project root).
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Emit machine-readable JSON instead of human-friendly text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ModulesAction {
    /// Build PIC / wasm modules. `--target T` builds a single target;
    /// `--all` reads the list from `fluxor.toml::[ci].targets`.
    /// `--strict` enables `rustc -D warnings` (CI mode); `--lenient`
    /// (default) keeps warnings as warnings except for unfulfilled
    /// `#[expect(...)]` which always fails.
    Build {
        /// Single target to build (e.g. `bcm2712`, `rp2350`, `cm5`).
        /// Mutually exclusive with `--all`.
        #[arg(long, conflicts_with = "all")]
        target: Option<String>,
        /// Build every target from `[ci].targets`. Mutually exclusive
        /// with `--target`.
        #[arg(long, conflicts_with = "target")]
        all: bool,
        /// Output root for `<silicon>/modules/<name>.fmod`. Defaults
        /// to `target/fluxor` per the standard's §2 path. Pass
        /// `--out target` to land artefacts at the legacy
        /// `target/<silicon>/modules/` layout the existing combine /
        /// run tooling expects.
        #[arg(long, default_value = "target/fluxor")]
        out: PathBuf,
        /// `rustc -D warnings` mode. Required for `fluxor ci`.
        #[arg(long, conflicts_with = "lenient")]
        strict: bool,
        /// `rustc -W warnings` mode. Default when neither flag is
        /// given — but `unfulfilled_lint_expectations` stays denied
        /// so `#[expect]` is honest in either mode.
        #[arg(long, conflicts_with = "strict")]
        lenient: bool,
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Remove module artefacts under the resolved output root.
    Clean {
        /// Output root to clean (defaults match `build`'s default).
        #[arg(long, default_value = "target/fluxor")]
        out: PathBuf,
    },
    /// Inventory the modules discovered under `modules/{drivers,
    /// foundation,app}/<name>/manifest.toml`.
    List {
        #[arg(long)]
        project_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print the resolved `<out>/<silicon>/modules` path for a target.
    /// Lets Makefiles and harness scripts refer to the artefact dir
    /// without hard-coding the layout.
    Resolve {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "target/fluxor")]
        out: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let verbose = cli.verbose;

    let result = match cli.command {
        Commands::Decode { file, format } => cmd_decode(&file, &format),
        Commands::Info { file } => cmd_info(&file),
        Commands::Generate {
            config,
            output,
            modules_dir,
            binary,
        } => cmd_generate(&config, output.as_deref(), modules_dir.as_deref(), binary),
        Commands::Combine {
            firmware,
            config,
            output,
        } => cmd_combine(&firmware, &config, &output, verbose),
        Commands::SlotImage {
            config,
            output,
            target,
            epoch,
        } => cmd_slot_image(&config, &output, target.as_deref(), epoch, verbose),
        Commands::Example { name } => cmd_example(&name),
        Commands::Pack {
            input,
            output,
            name,
            module_type,
            manifest,
        } => cmd_pack(&input, &output, name, module_type, manifest, verbose),
        Commands::Validate { config, target } => cmd_validate(&config, target.as_deref()),
        Commands::TargetInfo { target, field } => cmd_target_info(&target, field.as_deref()),
        Commands::Targets => cmd_targets(),
        Commands::Mktable { dir, output } => cmd_mktable(&dir, &output),
        Commands::MktableConfig {
            config,
            modules_dir,
            output,
        } => cmd_mktable_config(&config, &modules_dir, &output),
        Commands::Diff {
            old_config,
            new_config,
            target,
        } => cmd_diff(&old_config, &new_config, target.as_deref()),
        Commands::Build { path, output } => cmd_build(&path, output.as_deref(), verbose),
        Commands::Run {
            config,
            print_synthesised,
            print_merged,
            validate_only,
            graph,
            list,
            open,
        } => cmd_run_dispatch(
            config.as_ref(),
            RunFlags {
                print_synthesised,
                print_merged,
                validate_only,
                graph,
                list,
                open,
            },
            verbose,
        ),
        Commands::Flash { config } => cmd_flash(&config, verbose),
        Commands::RenderTemplate {
            template,
            vars,
            output,
        } => render_template::cmd_render_template(&template, &vars, output.as_deref()),
        Commands::Up {
            template,
            replicas,
            base_port,
            http_offset,
            vars,
        } => up::cmd_up(&template, replicas, base_port, http_offset, &vars, None),
        Commands::Sign { input, key, output } => cmd_sign(&input, &key, output.as_deref(), verbose),
        Commands::Monitor {
            port,
            baud,
            refresh_ms,
            net,
        } => cmd_monitor_dispatch(&port, baud, refresh_ms, net.as_deref()),
        Commands::Rig(args) => rig::cli::dispatch(args),
        Commands::Inspect { config, json } => cmd_inspect(config.as_deref(), json),
        Commands::Lint { action } => match action {
            LintAction::Hygiene { project_root, json } => {
                cmd_lint_hygiene(project_root.as_deref(), json)
            }
            LintAction::Observability { project_root, json } => {
                cmd_lint_observability(project_root.as_deref(), json)
            }
        },
        Commands::Ci { skip, project_root } => cmd_ci(&skip, project_root.as_deref(), verbose),
        Commands::Modules { action } => match action {
            ModulesAction::Build {
                target,
                all,
                out,
                strict,
                lenient,
                project_root,
            } => cmd_modules_build(
                target,
                all,
                &out,
                strict,
                lenient,
                project_root.as_deref(),
                verbose,
            ),
            ModulesAction::Clean { out } => cmd_modules_clean(&out),
            ModulesAction::List { project_root, json } => {
                cmd_modules_list(project_root.as_deref(), json)
            }
            ModulesAction::Resolve { target, out } => cmd_modules_resolve(&target, &out),
        },
        Commands::Publish {
            action,
            local,
            project_root,
        } => match action {
            None => publish::cmd_publish_all(local, project_root.as_deref()),
            Some(PublishAction::Abi {
                local: sub_local,
                project_root: sub_root,
            }) => publish::cmd_publish_abi(local || sub_local, sub_root.as_deref()),
            Some(PublishAction::Sdk {
                local: sub_local,
                project_root: sub_root,
            }) => publish::cmd_publish_sdk(local || sub_local, sub_root.as_deref()),
            Some(PublishAction::Common {
                local: sub_local,
                project_root: sub_root,
            }) => publish::cmd_publish_common(local || sub_local, sub_root.as_deref()),
            Some(PublishAction::Fmod {
                target,
                module,
                local: sub_local,
                project_root: sub_root,
            }) => publish::cmd_publish_fmod(
                target.as_deref(),
                module.as_deref(),
                local || sub_local,
                sub_root.as_deref(),
            ),
            Some(PublishAction::Runtime {
                binary,
                host_target,
                local: sub_local,
                project_root: sub_root,
            }) => publish::cmd_publish_runtime(
                &binary,
                host_target.as_deref(),
                local || sub_local,
                sub_root.as_deref(),
            ),
        },
        Commands::Update {
            project_root,
            features,
        } => lockfile::cmd_update(project_root.as_deref(), &features),
        Commands::Sync {
            project_root,
            dry_run,
        } => sync::cmd_sync(project_root.as_deref(), dry_run),
        Commands::Registry { action } => match action {
            RegistryAction::Init => cargo_index::cmd_registry_init(),
            RegistryAction::List { json } => registry::cmd_registry_list(json),
            RegistryAction::Gc { dry_run } => registry::cmd_registry_gc(dry_run),
            RegistryAction::SetupCargo => cargo_index::cmd_registry_setup_cargo(),
        },
        Commands::Workspace { action } => match action {
            WorkspaceAction::Status { json } => workspace::cmd_workspace_status(json),
        },
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {e}");
        std::process::exit(1);
    }
}

fn cmd_decode(file: &PathBuf, format: &str) -> Result<()> {
    let content = std::fs::read(file)?;
    let memory = parse_uf2(&content)?;

    // Read trailer to find config address
    let config_addr = read_trailer_config_addr(&memory)?;

    // Extract config region
    let config_data = {
        let mut data = Vec::new();
        for i in 0..4096u32 {
            if let Some(&byte) = memory.get(&(config_addr + i)) {
                data.push(byte);
            } else if !data.is_empty() {
                break; // End of contiguous region
            }
        }
        if data.len() < 64 {
            return Err(error::Error::Config(
                "No config found at expected address".into(),
            ));
        }
        data
    };

    let config = decode_config(&config_data, &memory)?;

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&config)?),
        _ => println!("{}", serde_yaml::to_string(&config)?),
    }

    Ok(())
}

/// Find and read trailer from memory map
/// Scans 256-byte aligned addresses looking for TRAILER_MAGIC
fn find_trailer(memory: &std::collections::BTreeMap<u32, u8>) -> Result<(u32, u32, u32)> {
    // Scan 256-byte aligned addresses for trailer magic
    let min_addr = *memory
        .keys()
        .min()
        .ok_or_else(|| error::Error::Config("Empty memory".into()))?;
    let max_addr = *memory.keys().max().unwrap();

    let mut addr = (min_addr + 255) & !255; // Start at first 256-byte boundary
    while addr <= max_addr {
        if let Some(data) = uf2::extract_region(memory, addr, 16) {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if magic == TRAILER_MAGIC {
                let modules_addr = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                let config_addr = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
                return Ok((addr, modules_addr, config_addr));
            }
        }
        addr += 256;
    }

    Err(error::Error::Config("No trailer found".into()))
}

/// Read config address from trailer
fn read_trailer_config_addr(memory: &std::collections::BTreeMap<u32, u8>) -> Result<u32> {
    let (_, _, config_addr) = find_trailer(memory)?;
    Ok(config_addr)
}

fn cmd_info_fmod(file: &Path) -> Result<()> {
    let m = modules::ModuleInfo::from_file(file)?;
    let type_str = match m.module_type {
        1 => "Source",
        2 => "Transformer",
        3 => "Sink",
        4 => "EventHandler",
        5 => "Protocol",
        _ => "Unknown",
    };
    println!("Module: {} ({})", file.display(), m.name);
    println!(
        "  type: {} ({}), size: {} bytes",
        type_str,
        m.module_type,
        m.data.len()
    );
    println!(
        "  mailbox_safe: {}, in_place_writer: {}",
        m.mailbox_safe, m.in_place_writer
    );
    if let Some(schema) = &m.schema {
        println!("  param_schema: {} bytes", schema.len());
    }
    println!("  manifest:");
    println!("{}", m.manifest.display());
    Ok(())
}

fn cmd_info(file: &PathBuf) -> Result<()> {
    // Handle .fmod files directly
    if file.extension().is_some_and(|ext| ext == "fmod") {
        return cmd_info_fmod(file);
    }

    let content = std::fs::read(file)?;
    let memory = parse_uf2(&content)?;

    if memory.is_empty() {
        println!("Empty UF2 file");
        return Ok(());
    }

    let addresses: Vec<u32> = memory.keys().copied().collect();
    let min_addr = *addresses.iter().min().unwrap();
    let max_addr = *addresses.iter().max().unwrap();

    // Find segments (gaps > 256 bytes)
    let mut segments = Vec::new();
    let mut sorted_addrs: Vec<u32> = addresses.clone();
    sorted_addrs.sort();

    let mut seg_start = sorted_addrs[0];
    let mut prev_addr = sorted_addrs[0];

    for &addr in &sorted_addrs[1..] {
        if addr - prev_addr > 256 {
            segments.push((seg_start, prev_addr));
            seg_start = addr;
        }
        prev_addr = addr;
    }
    segments.push((seg_start, prev_addr));

    println!("UF2 File: {}", file.display());
    println!("Total bytes: {}", memory.len());
    println!("Address range: 0x{min_addr:08x} - 0x{max_addr:08x}");
    println!("Segments: {}", segments.len());

    for (i, (start, end)) in segments.iter().enumerate() {
        let size = end - start + 1;
        println!("  [{i}] 0x{start:08x} - 0x{end:08x} ({size} bytes)");
    }

    // Check for trailer
    println!();
    if let Ok((trailer_addr, modules_addr, config_addr)) = find_trailer(&memory) {
        println!("Trailer: Present at 0x{trailer_addr:08x}");
        if modules_addr != 0 {
            println!("  Modules: 0x{modules_addr:08x}");
        } else {
            println!("  Modules: None");
        }
        println!("  Config:  0x{config_addr:08x}");

        // Check config magic
        if let Some(header_data) = uf2::extract_region(&memory, config_addr, 4) {
            let magic = u32::from_le_bytes([
                header_data[0],
                header_data[1],
                header_data[2],
                header_data[3],
            ]);
            if magic == config::MAGIC_CONFIG {
                println!("  Config magic: Valid (0x{magic:08x})");
            } else {
                println!("  Config magic: Invalid (0x{magic:08x})");
            }
        }

        // Parse and display module table
        if modules_addr != 0 {
            if let Some(table_header) =
                uf2::extract_region(&memory, modules_addr, modules::TABLE_HEADER_SIZE)
            {
                let table_magic = u32::from_le_bytes([
                    table_header[0],
                    table_header[1],
                    table_header[2],
                    table_header[3],
                ]);
                if table_magic == modules::MODULE_TABLE_MAGIC {
                    let module_count = table_header[5] as usize;
                    println!("\nModules: {module_count} embedded");

                    // Read entries
                    let entries_start = modules_addr + modules::TABLE_HEADER_SIZE as u32;
                    for i in 0..module_count {
                        let entry_addr = entries_start + (i as u32 * modules::ENTRY_SIZE as u32);
                        if let Some(entry) =
                            uf2::extract_region(&memory, entry_addr, modules::ENTRY_SIZE)
                        {
                            let name_hash =
                                u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                            let fmod_offset =
                                u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                            let fmod_size =
                                u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]])
                                    as usize;
                            let mod_type = entry[12];

                            let fmod_addr = modules_addr + fmod_offset;
                            if let Some(fmod_header) =
                                uf2::extract_region(&memory, fmod_addr, modules::MODULE_HEADER_SIZE)
                            {
                                // Extract name from header (offset 28, 32 bytes)
                                let name_bytes = &fmod_header[28..60];
                                let name_end =
                                    name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
                                let name = String::from_utf8_lossy(&name_bytes[..name_end]);
                                let abi = fmod_header[5];

                                let type_str = match mod_type {
                                    1 => "Source",
                                    2 => "Transformer",
                                    3 => "Sink",
                                    4 => "EventHandler",
                                    5 => "Protocol",
                                    _ => "Unknown",
                                };

                                println!("\n  [{i}] {name} (hash=0x{name_hash:08x})");
                                println!(
                                    "      type: {type_str} ({mod_type}), abi: v{abi}, size: {fmod_size} bytes"
                                );

                                // Read manifest from fmod (ABI v2)
                                if abi >= 2 {
                                    let code_size = u32::from_le_bytes([
                                        fmod_header[8],
                                        fmod_header[9],
                                        fmod_header[10],
                                        fmod_header[11],
                                    ]) as usize;
                                    let data_size = u32::from_le_bytes([
                                        fmod_header[12],
                                        fmod_header[13],
                                        fmod_header[14],
                                        fmod_header[15],
                                    ]) as usize;
                                    let export_count =
                                        u16::from_le_bytes([fmod_header[24], fmod_header[25]])
                                            as usize;
                                    let schema_size =
                                        u16::from_le_bytes([fmod_header[62], fmod_header[63]])
                                            as usize;
                                    let manifest_size =
                                        u16::from_le_bytes([fmod_header[64], fmod_header[65]])
                                            as usize;

                                    let manifest_offset = modules::MODULE_HEADER_SIZE
                                        + code_size
                                        + data_size
                                        + export_count * 8
                                        + schema_size;
                                    let manifest_addr = fmod_addr + manifest_offset as u32;

                                    if manifest_size > 0 {
                                        if let Some(manifest_data) = uf2::extract_region(
                                            &memory,
                                            manifest_addr,
                                            manifest_size,
                                        ) {
                                            match manifest::Manifest::from_bytes(&manifest_data) {
                                                Ok(m) => println!("{}", m.display()),
                                                Err(e) => println!("      manifest: error: {e}"),
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        println!("Trailer: Not present");
    }

    Ok(())
}

/// Substitute `${VAR}` and `${VAR:-default}` patterns with environment variable values.
/// Escape literal `${` with `$${`.
/// True iff `s` is a POSIX-valid environment variable identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`). Anything else inside `${...}` is
/// treated as a literal pass-through so YAML config can embed JS
/// template-literal source without the substitution treating its
/// `${expr}` syntax as missing env vars.
fn is_env_var_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn substitute_env_vars(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(pos) = rest.find("${") {
        // Check for escape: $${
        if pos > 0 && rest.as_bytes()[pos - 1] == b'$' {
            // Push everything up to (but not including) the extra '$', then literal '${'
            out.push_str(&rest[..pos - 1]);
            out.push_str("${");
            rest = &rest[pos + 2..];
            continue;
        }

        // Push text before '${'
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 2..];

        // Find closing '}'
        let end = rest
            .find('}')
            .ok_or_else(|| crate::error::Error::Config("Unclosed ${} in config".to_string()))?;

        let expr = &rest[..end];
        if expr.is_empty() {
            return Err(crate::error::Error::Config(
                "Empty variable name in ${}".to_string(),
            ));
        }

        // Split on ":-" for default value
        let (var_name, default) = if let Some(sep) = expr.find(":-") {
            (&expr[..sep], Some(&expr[sep + 2..]))
        } else {
            (expr, None)
        };

        // POSIX-valid env-var name: `[A-Za-z_][A-Za-z0-9_]*`. Any
        // other shape (dots, spaces, hyphens, etc.) is a JS-side
        // template literal that just happens to look like `${...}`
        // when YAML embeds JS source (e.g. the canonical wasm
        // runtime shell embeds JS that does
        // `\`${window.__fluxorBase}host_shims.js\``). Treat
        // non-env-shaped names as inert — emit the literal
        // `${...}` back into the output unchanged. Only well-formed
        // names participate in substitution, so unset env vars
        // still error loudly.
        if !is_env_var_name(var_name) {
            out.push_str("${");
            out.push_str(expr);
            out.push('}');
            rest = &rest[end + 1..];
            continue;
        }

        match std::env::var(var_name) {
            Ok(val) => out.push_str(&val),
            Err(_) => {
                if let Some(def) = default {
                    out.push_str(def);
                } else {
                    return Err(crate::error::Error::Config(format!(
                        "Environment variable '{var_name}' is not set (referenced in config). \
                         Use ${{{var_name}:-default}} to provide a fallback.",
                    )));
                }
            }
        }

        rest = &rest[end + 1..];
    }

    // Push remaining text
    out.push_str(rest);
    Ok(out)
}

/// Tiny base64 encoder for binary `body_file` payloads. Avoids
/// pulling in a base64 crate just for this single call site.
fn base64_encode(bytes: &[u8], out: &mut String) {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let v = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 6) & 0x3F) as usize] as char);
        out.push(CHARS[(v & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let v = (bytes[i] as u32) << 16;
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let v = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(CHARS[((v >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 12) & 0x3F) as usize] as char);
        out.push(CHARS[((v >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
}

/// Walk every module's `routes:` array and rewrite `body_file: <path>`
/// into `body: <contents>`. Paths are resolved relative to the YAML's
/// directory, so a config can reference a runtime asset by path without
/// the human-edited YAML containing a copy of that asset's bytes. This
/// is the inclusion primitive that lets one runtime file feed many
/// configs.
fn inline_route_body_files(
    config: &mut serde_json::Value,
    yaml_dir: &std::path::Path,
) -> Result<()> {
    let modules = match config.get_mut("modules").and_then(|v| v.as_array_mut()) {
        Some(m) => m,
        None => return Ok(()),
    };
    for module in modules.iter_mut() {
        let routes = match module.get_mut("routes").and_then(|v| v.as_array_mut()) {
            Some(r) => r,
            None => continue,
        };
        for route in routes.iter_mut() {
            let route_obj = match route.as_object_mut() {
                Some(o) => o,
                None => continue,
            };
            let body_file = match route_obj.remove("body_file") {
                Some(serde_json::Value::String(s)) => s,
                Some(other) => {
                    return Err(Error::Config(format!(
                        "route body_file must be a string path, got {other}"
                    )));
                }
                None => continue,
            };
            let resolved = yaml_dir.join(&body_file);
            let bytes = std::fs::read(&resolved).map_err(|e| {
                Error::Config(format!("route body_file {}: {}", resolved.display(), e))
            })?;
            // JSON strings only carry valid UTF-8. For binary bodies
            // (e.g. `.wasm`) we encode as base64 with a "base64:"
            // sentinel; the schema-side body decoder strips it and
            // restores the bytes.
            let body_value = match core::str::from_utf8(&bytes) {
                Ok(text) => text.to_string(),
                Err(_) => {
                    let mut encoded = String::from("base64:");
                    base64_encode(&bytes, &mut encoded);
                    encoded
                }
            };
            route_obj.insert("body".to_string(), serde_json::Value::String(body_value));
        }
    }
    Ok(())
}

fn cmd_generate(
    config_path: &Path,
    output: Option<&std::path::Path>,
    modules_dir_override: Option<&std::path::Path>,
    binary: bool,
) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let yaml_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    inline_route_body_files(&mut config, yaml_dir)?;
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let builder = ConfigBuilder::new();
    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config
            .get("hardware")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let hw_obj = hw.as_object().cloned().unwrap_or_default();
        let def_obj = defaults.as_object().unwrap();
        let mut merged = hw_obj;
        for (key, val) in def_obj {
            if !merged.contains_key(key) {
                merged.insert(key.clone(), val.clone());
            }
        }
        config["hardware"] = serde_json::Value::Object(merged);
    }
    let modules_dir_default = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = modules_dir_override.unwrap_or(std::path::Path::new(&modules_dir_default));

    // Manifest search paths: explicit `module_search_paths:` from the
    // YAML plus the implicit <config-parent>/../modules default. See
    // `config::extract_module_search_paths` for ordering.
    let search_paths = config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();

    let binary_data = config::generate_config_ext(
        &config,
        &builder,
        &[],
        modules_dir,
        &extra_dirs,
        target_desc.max_pin + 1,
        target_desc.pio_count,
        Some(&target_desc.id),
    )?;

    eprintln!("Config size: {} bytes", binary_data.len());
    eprintln!("Note: Use 'combine' command to create a complete UF2 with trailer");

    if let Some(output_path) = output {
        if binary {
            std::fs::write(output_path, &binary_data)?;
            println!("Wrote binary config to {}", output_path.display());
        } else {
            return Err(error::Error::Config(
                "Standalone config UF2 no longer supported. Use 'combine' command instead.".into(),
            ));
        }
    } else {
        // Hex dump to stdout (relative offsets)
        for i in (0..binary_data.len()).step_by(16) {
            let end = (i + 16).min(binary_data.len());
            let hex: String = binary_data[i..end]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            println!("{i:04x}: {hex}");
        }
    }

    Ok(())
}

fn cmd_combine(
    firmware_path: &PathBuf,
    config_path: &PathBuf,
    output_path: &PathBuf,
    verbose: bool,
) -> Result<()> {
    // Parse config file (substitute env vars before YAML parse)
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let yaml_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    inline_route_body_files(&mut config, yaml_dir)?;
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root();
    let stack_added =
        stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    if verbose && !stack_added.is_empty() {
        eprintln!("Auto-added from platform: {}", stack_added.join(", "));
    }
    if verbose {
        eprintln!("Target: {}", target_desc.display_name());
    }

    // Detect aarch64 targets — they use raw binary output (no UF2).
    // Pi 5 VPU loads kernel as a raw binary to 0x80000.
    let is_aarch64 = target_desc
        .build
        .as_ref()
        .map(|b| b.rust_target.starts_with("aarch64"))
        .unwrap_or(false);
    const AARCH64_LOAD_BASE: u32 = 0x0008_0000;

    // Read firmware - keep as UF2 blocks to preserve non-contiguous sections like .end_block
    // Use the target's UF2 family ID so the correct chip accepts the image (e.g. RP2040 vs RP2350).
    let (firmware_data, firmware_max_addr) =
        if firmware_path.extension().is_some_and(|ext| ext == "bin") {
            let data = std::fs::read(firmware_path)?;
            if is_aarch64 {
                let end = AARCH64_LOAD_BASE + data.len() as u32;
                (data, end) // raw binary, not UF2
            } else {
                let end = XIP_BASE + data.len() as u32;
                let family_id = target_desc
                    .build
                    .as_ref()
                    .map(|b| b.uf2_family_id)
                    .unwrap_or(UF2_FAMILY_RP2350);
                (create_uf2_blocks(&data, XIP_BASE, family_id), end)
            }
        } else {
            // Keep original UF2 blocks intact - they may contain non-contiguous sections
            // like .end_block that the RP2350 boot ROM requires
            let uf2_content = std::fs::read(firmware_path)?;
            let memory = parse_uf2(&uf2_content)?;

            // Find the maximum address used (not just contiguous from XIP_BASE)
            let max_addr = memory.keys().max().copied().unwrap_or(XIP_BASE) + 1;

            (uf2_content, max_addr)
        };

    if verbose {
        let fmt = if is_aarch64 { "raw" } else { "UF2" };
        eprintln!("Firmware: {fmt} ends at 0x{firmware_max_addr:08x}");
    }

    // Merge board hardware defaults for sections the YAML doesn't specify
    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config
            .get("hardware")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let hw_obj = hw.as_object().cloned().unwrap_or_default();
        let def_obj = defaults.as_object().unwrap();
        let mut merged = hw_obj;
        for (key, val) in def_obj {
            if !merged.contains_key(key) {
                merged.insert(key.clone(), val.clone());
            }
        }
        config["hardware"] = serde_json::Value::Object(merged);
    }

    let validation = board::validate_config(&config, &target_desc)?;
    for warning in &validation.warnings {
        eprintln!("  \x1b[1;33mWARNING:\x1b[0m {warning}");
    }
    if !validation.is_ok() {
        for err in &validation.errors {
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {err}");
        }
        return Err(error::Error::Config(
            "Config validation failed for target".into(),
        ));
    }

    // Parse modules first (needed for in_place_safe caps in config generation).
    // External-app configs live outside fluxor's modules/ tree
    // and either declare `module_search_paths:` or rely on the implicit
    // `<config-parent>/../modules` default — same mechanism the linux build
    // path uses (`cmd_generate`). Without this, fan modules like
    // media_loader fail port-name resolution.
    let modules_dir_path = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);
    let search_paths = config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
    let modules = parse_modules_from_config_multi(&config, modules_dir, &extra_dirs)?;

    // Build module caps for buffer aliasing and manifest validation
    let caps: Vec<ModuleCaps> = modules
        .iter()
        .map(|m| ModuleCaps {
            name: m.name.clone(),
            mailbox_safe: m.mailbox_safe,
            in_place_writer: m.in_place_writer,
            manifest: m.manifest.clone(),
        })
        .collect();

    // Generate config binary (with module capabilities for chain detection)
    let builder = ConfigBuilder::new();
    let config_data = generate_config_ext(
        &config,
        &builder,
        &caps,
        modules_dir,
        &extra_dirs,
        target_desc.max_pin + 1,
        target_desc.pio_count,
        Some(&target_desc.id),
    )?;

    let modules_data = if !modules.is_empty() {
        if verbose {
            eprintln!("Embedding {} module(s):", modules.len());
            for module in &modules {
                eprintln!(
                    "  - {} ({} bytes, type={})",
                    module.name,
                    module.data.len(),
                    module.module_type
                );
            }
        }
        Some(build_module_table(&modules)?)
    } else {
        None
    };

    // Calculate addresses - trailer goes right after firmware, then modules, then config
    // All sections 256-byte aligned (UF2 block payload size)
    const UF2_BLOCK_ALIGN: u32 = 256;
    // aarch64 PIC modules use ADRP which requires code_base to be 4KB aligned.
    // The combine tool aligns WITHIN the blob so offset+header = 4KB boundary,
    // but modules_addr itself must also be 4KB aligned for absolute addresses.
    const MODULES_ALIGN: u32 = 4096;

    // Trailer immediately after firmware (256-byte aligned)
    let trailer_addr = (firmware_max_addr + UF2_BLOCK_ALIGN - 1) & !(UF2_BLOCK_ALIGN - 1);

    // Modules after trailer: 4KB aligned for aarch64 ADRP compatibility
    let modules_addr = if modules_data.is_some() {
        let raw = trailer_addr + UF2_BLOCK_ALIGN;
        (raw + MODULES_ALIGN - 1) & !(MODULES_ALIGN - 1)
    } else {
        0 // Sentinel for "no modules"
    };

    // Config after modules (or after trailer if no modules)
    let config_addr = if let Some(ref mdata) = modules_data {
        let after_modules = modules_addr + mdata.len() as u32;
        (after_modules + UF2_BLOCK_ALIGN - 1) & !(UF2_BLOCK_ALIGN - 1)
    } else {
        trailer_addr + UF2_BLOCK_ALIGN
    };

    // Ensure combined image doesn't overlap any reserved flash region:
    // graph slot A (OTA), graph slot B (OTA), blob store, or the runtime
    // parameter store. Only applies to flash-based targets.
    if !is_aarch64 {
        const SLOT_A_ADDR: u32 = 0x1000_0000 + 0x002F_D000;
        let config_end = config_addr + config_data.len() as u32;
        if config_end > SLOT_A_ADDR {
            return Err(error::Error::Config(format!(
                "Combined image end ({config_end:#010x}) overlaps reserved OTA/store region at {SLOT_A_ADDR:#010x}. Reduce firmware/config size."
            )));
        }
    }

    if verbose {
        let base_str = if is_aarch64 {
            AARCH64_LOAD_BASE
        } else {
            XIP_BASE
        };
        eprintln!("Layout:");
        eprintln!("  Firmware:  0x{base_str:08x} - 0x{firmware_max_addr:08x}");
        eprintln!("  Trailer:   0x{trailer_addr:08x} (16 bytes)");
        if let Some(ref mdata) = modules_data {
            eprintln!(
                "  Modules:   0x{:08x} ({} bytes)",
                modules_addr,
                mdata.len()
            );
        }
        eprintln!(
            "  Config:    0x{:08x} ({} bytes)",
            config_addr,
            config_data.len()
        );
    }

    // Compute CRC-16/XMODEM over the payload (modules + config) for integrity check
    let payload_crc: u16 = 0; // reserved

    // Build trailer (16 bytes)
    let mut trailer = Vec::with_capacity(16);
    trailer.extend_from_slice(&TRAILER_MAGIC.to_le_bytes());
    trailer.push(TRAILER_VERSION);
    trailer.push(0); // flags
    trailer.extend_from_slice(&payload_crc.to_le_bytes()); // CRC-16 of payload
    trailer.extend_from_slice(&modules_addr.to_le_bytes());
    trailer.extend_from_slice(&config_addr.to_le_bytes());
    assert_eq!(trailer.len(), 16);

    // Build the combined image.
    // aarch64: raw binary (firmware + padding + trailer + modules + config)
    // RP:      UF2 container with blocks for each section
    let (combined, firmware_size) = if is_aarch64 {
        let base = AARCH64_LOAD_BASE;
        let mut raw = firmware_data; // already raw bytes for aarch64
        let fw_size = raw.len();

        // Pad to trailer address
        let pad_to = (trailer_addr - base) as usize;
        if pad_to > raw.len() {
            raw.resize(pad_to, 0);
        }

        // Append trailer
        raw.extend_from_slice(&trailer);

        // Pad to modules address (if modules exist)
        if let Some(ref mdata) = modules_data {
            let mod_off = (modules_addr - base) as usize;
            if mod_off > raw.len() {
                raw.resize(mod_off, 0);
            }
            raw.extend_from_slice(mdata);
        }

        // Pad to config address
        let cfg_off = (config_addr - base) as usize;
        if cfg_off > raw.len() {
            raw.resize(cfg_off, 0);
        }
        raw.extend_from_slice(&config_data);

        (raw, fw_size)
    } else {
        // UF2 path for RP targets
        let firmware_family_id = {
            if firmware_data.len() >= 32 {
                u32::from_le_bytes([
                    firmware_data[28],
                    firmware_data[29],
                    firmware_data[30],
                    firmware_data[31],
                ])
            } else {
                UF2_FAMILY_RP2350
            }
        };

        let modules_uf2 = modules_data
            .as_ref()
            .map(|mdata| create_uf2_blocks(mdata, modules_addr, firmware_family_id));
        let trailer_uf2 = create_uf2_blocks(&trailer, trailer_addr, firmware_family_id);
        let config_uf2 = create_uf2_blocks(&config_data, config_addr, firmware_family_id);

        let firmware_size = firmware_data.len();
        let mut combined = firmware_data;
        combined.extend_from_slice(&trailer_uf2);
        if let Some(muf2) = modules_uf2 {
            combined.extend_from_slice(&muf2);
        }
        combined.extend_from_slice(&config_uf2);

        fix_uf2_block_numbers(&mut combined);
        (combined, firmware_size)
    };

    std::fs::write(output_path, &combined)?;

    if verbose {
        println!(
            "\x1b[1;32mSuccess:\x1b[0m Wrote {} ({} bytes)",
            output_path.display(),
            combined.len()
        );
    } else {
        // Concise output: filename modules config total
        let modules_size = modules_data.as_ref().map(|m| m.len()).unwrap_or(0);
        println!(
            "\x1b[1;32mSuccess\x1b[0m {} fw={}K mod={}K cfg={}K total={}K",
            output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            firmware_size / 1024,
            modules_size / 1024,
            config_data.len() / 1024,
            combined.len() / 1024
        );
    }

    Ok(())
}

fn load_config_with_defaults(
    config_path: &PathBuf,
    verbose: bool,
) -> Result<(serde_json::Value, target::TargetDescriptor)> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;

    // Resolve target first — stack expansion needs board_id and family
    let target_desc = resolve_target(&config, None)?;
    if verbose {
        eprintln!("Target: {}", target_desc.display_name());
    }

    // Expand platform: stacks (TOML-driven)
    let project_root = crate::project::root();
    let stack_added =
        stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    if verbose && !stack_added.is_empty() {
        eprintln!("Auto-added from platform: {}", stack_added.join(", "));
    }

    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config
            .get("hardware")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let hw_obj = hw.as_object().cloned().unwrap_or_default();
        let def_obj = defaults.as_object().unwrap();
        let mut merged = hw_obj;
        for (key, val) in def_obj {
            if !merged.contains_key(key) {
                merged.insert(key.clone(), val.clone());
            }
        }
        config["hardware"] = serde_json::Value::Object(merged);
    }

    let validation = board::validate_config(&config, &target_desc)?;
    for warning in &validation.warnings {
        eprintln!("  \x1b[1;33mWARNING:\x1b[0m {warning}");
    }
    if !validation.is_ok() {
        for err in &validation.errors {
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {err}");
        }
        return Err(error::Error::Config(
            "Config validation failed for target".into(),
        ));
    }

    Ok((config, target_desc))
}

fn build_packaged_blobs(
    config: &serde_json::Value,
    modules_dir: &std::path::Path,
    extra_dirs: &[&std::path::Path],
    target_desc: &target::TargetDescriptor,
    verbose: bool,
) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
    let modules = parse_modules_from_config_multi(config, modules_dir, extra_dirs)?;

    let caps: Vec<ModuleCaps> = modules
        .iter()
        .map(|m| ModuleCaps {
            name: m.name.clone(),
            mailbox_safe: m.mailbox_safe,
            in_place_writer: m.in_place_writer,
            manifest: m.manifest.clone(),
        })
        .collect();

    let builder = ConfigBuilder::new();
    let config_data = generate_config_ext(
        config,
        &builder,
        &caps,
        modules_dir,
        &[],
        target_desc.max_pin + 1,
        target_desc.pio_count,
        Some(&target_desc.id),
    )?;

    let modules_data = if !modules.is_empty() {
        if verbose {
            eprintln!("Embedding {} module(s):", modules.len());
            for module in &modules {
                eprintln!(
                    "  - {} ({} bytes, type={})",
                    module.name,
                    module.data.len(),
                    module.module_type
                );
            }
        }
        Some(build_module_table(&modules)?)
    } else {
        None
    };

    Ok((modules_data, config_data))
}

/// Emit an OTA slot image: 256-byte header + modules table + static config,
/// padded to the slot size. Layout mirrors `abi::graph_slot`.
///
/// The header records the epoch, the in-slot offsets and sizes of the
/// modules and config regions, and a SHA-256 over their concatenation.
/// `graph_slot::ACTIVATE` recomputes the hash from flash and rejects
/// mismatches.
fn cmd_slot_image(
    config_path: &PathBuf,
    output_path: &PathBuf,
    target_override: Option<&str>,
    epoch: u64,
    verbose: bool,
) -> Result<()> {
    // Slot layout constants mirror modules/sdk/abi.rs :: graph_slot.
    const SLOT_SIZE: usize = 0x0008_0000;
    const HEADER_SIZE: usize = 256;
    const MODULES_ALIGN: usize = 4096;
    const SECTION_ALIGN: usize = 256;
    const MAGIC: u32 = 0x4C53_5846; // "FXSL"
    const VERSION: u8 = 1;

    // Parse config (reusing the same path as cmd_combine).
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let mut config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let target_desc = resolve_target(&config, target_override)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config
            .get("hardware")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let hw_obj = hw.as_object().cloned().unwrap_or_default();
        let def_obj = defaults.as_object().unwrap();
        let mut merged = hw_obj;
        for (key, val) in def_obj {
            if !merged.contains_key(key) {
                merged.insert(key.clone(), val.clone());
            }
        }
        config["hardware"] = serde_json::Value::Object(merged);
    }

    let validation = board::validate_config(&config, &target_desc)?;
    if !validation.is_ok() {
        for err in &validation.errors {
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {err}");
        }
        return Err(error::Error::Config(
            "Config validation failed for target".into(),
        ));
    }

    let modules_dir_path = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);
    let (modules_data, config_data) =
        build_packaged_blobs(&config, modules_dir, &[], &target_desc, verbose)?;
    let modules_data = modules_data
        .ok_or_else(|| error::Error::Config("Slot image requires at least one module".into()))?;

    // Lay out the slot: header | pad → 4KB | modules | pad → 256B | config.
    let modules_offset = HEADER_SIZE.div_ceil(MODULES_ALIGN) * MODULES_ALIGN;
    let modules_end = modules_offset + modules_data.len();
    let config_offset = modules_end.div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
    let config_end = config_offset + config_data.len();
    if config_end > SLOT_SIZE {
        return Err(error::Error::Config(format!(
            "Slot image ({config_end} bytes) exceeds slot size ({SLOT_SIZE} bytes). Reduce modules/config."
        )));
    }

    // Build the payload bytes that are covered by the SHA-256.
    let mut payload = Vec::with_capacity(modules_data.len() + config_data.len());
    payload.extend_from_slice(&modules_data);
    payload.extend_from_slice(&config_data);
    let digest = {
        use sha2::Digest;
        sha2::Sha256::digest(&payload)
    };

    // Compose the final slot image.
    let mut out = vec![0xFFu8; SLOT_SIZE];
    // Header.
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4] = VERSION;
    out[8..16].copy_from_slice(&epoch.to_le_bytes());
    out[16..20].copy_from_slice(&(modules_offset as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(modules_data.len() as u32).to_le_bytes());
    out[24..28].copy_from_slice(&(config_offset as u32).to_le_bytes());
    out[28..32].copy_from_slice(&(config_data.len() as u32).to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    // Payload.
    out[modules_offset..modules_offset + modules_data.len()].copy_from_slice(&modules_data);
    out[config_offset..config_offset + config_data.len()].copy_from_slice(&config_data);

    std::fs::write(output_path, &out)?;
    if verbose {
        eprintln!(
            "slot image: modules_off=0x{:x} ({} bytes), config_off=0x{:x} ({} bytes), epoch={}",
            modules_offset,
            modules_data.len(),
            config_offset,
            config_data.len(),
            epoch,
        );
    }
    println!(
        "\x1b[1;32mSuccess\x1b[0m {} modules={}K config={}K size={}K epoch={}",
        output_path.display(),
        modules_data.len() / 1024,
        config_data.len() / 1024,
        SLOT_SIZE / 1024,
        epoch,
    );
    Ok(())
}

fn cmd_example(name: &str) -> Result<()> {
    if let Some(example) = EXAMPLES.get(name) {
        println!("{}", serde_json::to_string_pretty(example)?);
        Ok(())
    } else {
        let available: Vec<_> = EXAMPLES.keys().copied().collect();
        println!("Available examples: {}", available.join(", "));
        Err(error::Error::Config(format!("Unknown example: {name}")))
    }
}

fn cmd_pack(
    input: &Path,
    output: &Path,
    name: Option<String>,
    module_type: u8,
    manifest: Option<PathBuf>,
    verbose: bool,
) -> Result<()> {
    // Derive module name from filename if not provided
    let module_name = name.unwrap_or_else(|| {
        input
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.strip_prefix("lib").unwrap_or(s).to_string())
            .unwrap_or_else(|| "module".to_string())
    });

    let manifest_path = manifest.as_deref();
    // Detect a wasm payload by the wasm magic at the file start. Wasm
    // modules go through `pack_fmod_wasm`, which skips ELF parsing and
    // wraps the wasm bytes verbatim as the .fmod code payload.
    let is_wasm = std::fs::read(input)
        .map(|bytes| bytes.len() >= 4 && &bytes[..4] == b"\0asm")
        .unwrap_or(false);
    let result = if is_wasm {
        modules::pack_fmod_wasm(input, output, &module_name, module_type, manifest_path)?
    } else {
        pack_fmod(input, output, &module_name, module_type, manifest_path)?
    };

    if verbose {
        println!("\x1b[1;32mPacked module:\x1b[0m {}", output.display());
        println!("  Name: {}", result.name);
        println!("  Code size: {} bytes", result.code_size);
        println!("  Data size: {} bytes", result.data_size);
        println!("  BSS size: {} bytes", result.bss_size);
        println!("  Init offset: 0x{:x}", result.init_offset);
        println!("  Exports: {}", result.exports.len());
        for (name, offset, hash) in &result.exports {
            println!("    {name}: 0x{offset:x} (hash: 0x{hash:08x})");
        }
        println!("  Total size: {} bytes", result.total_size);
    } else {
        // Concise single-line output: name code+data+bss=total
        println!(
            "\x1b[1;32mSuccess\x1b[0m {} {}+{}+{}={} bytes",
            result.name, result.code_size, result.data_size, result.bss_size, result.total_size
        );
    }

    Ok(())
}

/// Resolve target from CLI override or config YAML `target:` field.
///
/// Target lookup walks `crate::project::root()/targets/` — not raw
/// CWD — so `fluxor build` invoked from a subdirectory of the project
/// (or from an external project directory with a `.fluxor` marker)
/// still finds the same targets the build would see when run from
/// the source-tree root.
fn resolve_target(
    config: &serde_json::Value,
    cli_override: Option<&str>,
) -> Result<target::TargetDescriptor> {
    let name = cli_override
        .or_else(|| config.get("target").and_then(|t| t.as_str()))
        .unwrap_or("pico2w");
    let root = crate::project::root();
    target::load_target(name, &root)
}

fn cmd_validate(config_path: &PathBuf, target_override: Option<&str>) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let target_desc = resolve_target(&config, target_override)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    println!(
        "Validating {} against target '{}'...",
        config_path.display(),
        target_desc.display_name()
    );

    let mut result = board::validate_config(&config, &target_desc)?;

    // Validate the `presentation_groups` block here as well as in the
    // build path so `fluxor validate` catches authority / multihead /
    // protected-path errors without compiling. The module-search dirs
    // mirror `cmd_build`'s derivation so a project-local manifest
    // reachable from `fluxor build` is also reachable from `fluxor
    // validate`.
    if let Some(modules) = config.get("modules") {
        let module_names: Vec<String> = modules
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let search_paths = crate::config::extract_module_search_paths(&config, config_path);
        let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
        let manifests = crate::config::load_module_manifests_with_extra(modules, &extra_dirs);
        if let Err(e) =
            crate::config::validate_presentation_groups(&config, &module_names, &manifests)
        {
            result.add_error(e.to_string());
        }
    }

    // Dry-run the full config-generation pipeline so missing
    // manifests, malformed wiring, unknown content types, and tier
    // admission errors all surface as `fluxor validate` failures
    // instead of waiting for `fluxor build` (which needs firmware
    // + .fmod files on disk). The result blob is discarded —
    // validate is read-only.
    //
    // The module directory and pin/pio bounds use the target's
    // declared geometry so a host-target validate doesn't try to
    // load .fmod files from an embedded target tree.
    let modules_dir_default = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::PathBuf::from(&modules_dir_default);
    let search_paths = crate::config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
    let dry_run_builder = ConfigBuilder::new();
    if let Err(e) = config::generate_config_ext(
        &config,
        &dry_run_builder,
        &[],
        &modules_dir,
        &extra_dirs,
        target_desc.max_pin + 1,
        target_desc.pio_count,
        Some(&target_desc.id),
    ) {
        result.add_error(format!("{e}"));
    }

    // Print warnings (yellow)
    for warning in &result.warnings {
        println!("  \x1b[1;33mWARNING:\x1b[0m {warning}");
    }

    // Print errors (red)
    for error in &result.errors {
        println!("  \x1b[1;31mERROR:\x1b[0m {error}");
    }

    // Summary
    println!();
    if result.is_ok() {
        if result.warnings.is_empty() {
            println!("\x1b[1;32mValidation passed.\x1b[0m");
        } else {
            println!(
                "\x1b[1;32mValidation passed\x1b[0m with {} warning(s).",
                result.warnings.len()
            );
        }
        Ok(())
    } else {
        println!(
            "\x1b[1;31mValidation FAILED:\x1b[0m {} error(s), {} warning(s)",
            result.errors.len(),
            result.warnings.len()
        );
        Err(error::Error::Config("Validation failed".into()))
    }
}

fn cmd_target_info(target_name: &str, field: Option<&str>) -> Result<()> {
    let root = crate::project::root();
    let desc = target::load_target(target_name, &root)?;

    if let Some(field) = field {
        // Machine-readable: print just the requested field value
        match field {
            "rust_target" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.rust_target);
                }
            }
            "cargo_features" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.cargo_features.join(","));
                }
            }
            "uf2_family_id" => {
                if let Some(ref b) = desc.build {
                    println!("0x{:08x}", b.uf2_family_id);
                }
            }
            "module_target" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.module_target);
                }
            }
            "max_pin" => println!("{}", desc.max_pin),
            "family" => println!("{}", desc.family),
            "id" => println!("{}", desc.id),
            "pio_count" => println!("{}", desc.pio_count),
            "spi_count" => println!("{}", desc.spi_count),
            "i2c_count" => println!("{}", desc.i2c_count),
            "dma_channels" => println!("{}", desc.dma_channels),
            _ => {
                return Err(error::Error::Config(format!(
                    "Unknown field '{field}'. Available: rust_target, cargo_features, uf2_family_id, \
                     module_target, max_pin, family, id, pio_count, spi_count, i2c_count, dma_channels"
                )));
            }
        }
        return Ok(());
    }

    // Human-readable output
    println!("Target: {}", desc.display_name());
    println!("  Silicon: {} ({})", desc.id, desc.family);
    if let Some(ref board) = desc.board_id {
        println!(
            "  Board: {} ({})",
            board,
            desc.board_description.as_deref().unwrap_or("")
        );
    }
    if let Some(ref b) = desc.build {
        println!("  Rust target: {}", b.rust_target);
        println!("  Features: {}", b.cargo_features.join(", "));
        println!("  UF2 family: 0x{:08x}", b.uf2_family_id);
        println!("  Module target: {}", b.module_target);
    } else {
        println!("  Build: validation only (no kernel build support)");
    }
    println!(
        "  GPIO: 0-{} (reserved: {})",
        desc.max_pin,
        if desc.reserved_pins.is_empty() {
            "none".to_string()
        } else {
            desc.reserved_pins
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "  Peripherals: SPI={}, I2C={}, UART={}, ADC={}, PWM={}, PIO={} ({}SM each), DMA={}",
        desc.spi_count,
        desc.i2c_count,
        desc.uart_count,
        desc.adc_channels,
        desc.pwm_slices,
        desc.pio_count,
        desc.pio_state_machines,
        desc.dma_channels
    );
    if let Some(ref mem) = desc.memory {
        println!(
            "  Memory: flash={}K @ 0x{:08x}, RAM={}K @ 0x{:08x}",
            mem.flash_size / 1024,
            mem.flash_base,
            mem.ram_size / 1024,
            mem.ram_base
        );
    }

    Ok(())
}

fn cmd_targets() -> Result<()> {
    let root = crate::project::root();
    let names = target::list_targets(&root);

    if names.is_empty() {
        println!("No targets found. Check targets/ directory.");
        return Ok(());
    }

    println!("Available targets:");
    for name in &names {
        match target::load_target(name, &root) {
            Ok(desc) => {
                let kind = if desc.board_id.is_some() {
                    "board"
                } else if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                println!("  {:20} {:12} {}", name, kind, desc.description);
            }
            Err(_) => {
                println!("  {name:20} (error loading)");
            }
        }
    }

    Ok(())
}

/// `fluxor inspect [config] [--json]` — diagnostic surface for
/// "what does fluxor resolve to from here?" Prints:
///
/// 1. The resolved project root + how it was discovered (env var,
///    `.fluxor` marker, source-tree heuristic, CWD fallback) plus
///    the `$FLUXOR_PROJECT_ROOT` setting if any.
/// 2. The available targets (`targets/boards/*.toml` +
///    `targets/silicon/*.toml`) — same listing as `fluxor targets`.
/// 3. The available stacks (`stacks/*.toml`) — file listing only;
///    expansion happens against a specific platform during build.
/// 4. **If a config is given**: the YAML's declared target, the
///    resolved target descriptor, the platform stacks the build
///    would expand, and the manifest search paths
///    `extract_module_search_paths` produces.
///
/// With `--json`, emits the same data as a stable JSON object
/// (top-level keys: `project_root`, `install_root`, `targets`,
/// `stacks`, `rig`, `scenarios`, optionally `config`).
///
/// This subcommand is read-only — it never touches `target/` or
/// produces build artefacts. Safe to run from anywhere.
fn cmd_inspect(config_path: Option<&Path>, json: bool) -> Result<()> {
    if json {
        return cmd_inspect_json(config_path);
    }
    let pr = crate::project::discover();

    println!("Project root");
    println!("  path:                 {}", pr.path.display());
    println!(
        "  source:               {}",
        format_discovery_source(&pr.source)
    );
    if pr.starting_cwd != pr.path {
        println!("  cwd:                  {}", pr.starting_cwd.display());
    }
    match &pr.env_var_value {
        Some(v) if pr.source == crate::project::DiscoverySource::EnvVar => {
            println!("  $FLUXOR_PROJECT_ROOT: {v} (active)");
        }
        Some(v) => {
            println!("  $FLUXOR_PROJECT_ROOT: {v} (set but unusable; ignored)");
        }
        None => {
            println!("  $FLUXOR_PROJECT_ROOT: <unset>");
        }
    }

    // Install root — separate from project root so an external
    // user project can ship its own targets/stacks while still
    // falling back to bundled defaults. `target::load_target` and
    // `stack_expand::load_stack` consult this layered lookup
    // automatically; `inspect` surfaces it so the user knows what
    // fluxor would fall back to.
    match crate::project::install_root() {
        Some(install) => {
            println!("  install root:         {}", install.path.display());
            println!(
                "    via:                {}",
                format_install_source(&install.source)
            );
            if install.path == pr.path {
                println!("    (same as project root — no fallback in effect)");
            }
        }
        None => {
            println!("  install root:         <none discovered>");
        }
    }
    println!();

    // Targets — merged view across project root + install root.
    // `target::load_target` falls back from project to install at
    // runtime; inspect must mirror that, otherwise an external
    // `.fluxor` project with no local `targets/` would report
    // "no targets" while the build pipeline would happily resolve
    // bundled ones. Source annotation per entry shows which root
    // each target lives under (and which one "wins" when both
    // carry the same name).
    let install_root = crate::project::install_root();
    let install_path_ref = install_root.as_ref().map(|i| i.path.as_path());
    let install_distinct = install_path_ref.filter(|p| **p != *pr.path);
    print_inspect_targets_block(&pr.path, install_distinct);

    // Stacks — same dual-root pattern. Stacks are file-listings
    // (expansion is per-target) so the annotation is just "which
    // root carries this file and is it shadowed by a project-side
    // override."
    print_inspect_stacks_block(&pr.path, install_distinct);

    // Rig configuration. Tangential to the build path but the same
    // discoverability question — "what rigs does fluxor see from
    // here?" — so the unified `inspect` surface answers it
    // alongside targets/stacks rather than forcing the user to
    // remember a separate `fluxor rig list` verb.
    inspect_rig_config();

    // Scenarios. Same discoverability principle: `fluxor run
    // --list <dir>` is the focused enumerator, but a one-screen
    // `inspect` should surface what's available without forcing
    // the user to know where scenarios live.
    inspect_scenarios(&pr.path);

    // Per-config resolution.
    if let Some(cfg_path) = config_path {
        inspect_config(cfg_path, &pr.path)?;
    } else {
        println!("Tip: pass a config (`fluxor inspect path/to/graph.yaml`) to see the");
        println!("     resolved target, expanded stacks, and module search paths for it.");
    }

    Ok(())
}

/// Machine-readable shape of `fluxor inspect`. The JSON form is the
/// stable v1 surface for CI / IDE / dashboard integrations. Field
/// names map 1:1 to the text rendering so a user can grep either
/// output and find the same data:
///
/// ```text
/// {
///   "project_root": { "path", "source", "starting_cwd", "env_var": {…} },
///   "install_root": null | { "path", "source" },
///   "targets":      [ { "name", "kind", "description" } ],
///   "stacks":       [ "audio", "debug", … ],
///   "rig":          { "active_lab", "lab_env_set", "available_labs", "rigs" },
///   "scenarios":    { "scanned_dirs", "found", "errors" },
///   "config":       null | { "path", "declared_target", … }
/// }
/// ```
///
/// Order of keys is stable but unspecified by JSON; downstream
/// consumers should pick by name, not position.
fn cmd_inspect_json(config_path: Option<&Path>) -> Result<()> {
    let pr = crate::project::discover();
    let mut out = serde_json::json!({});

    // Project root.
    out["project_root"] = serde_json::json!({
        "path": pr.path.display().to_string(),
        "source": match pr.source {
            crate::project::DiscoverySource::EnvVar => "env_var",
            crate::project::DiscoverySource::DotFluxorMarker => "dot_fluxor_marker",
            crate::project::DiscoverySource::SourceTreeMarker => "source_tree_marker",
            crate::project::DiscoverySource::CwdFallback => "cwd_fallback",
        },
        "starting_cwd": pr.starting_cwd.display().to_string(),
        "env_var": match &pr.env_var_value {
            Some(v) => serde_json::json!({
                "value": v,
                "active": pr.source == crate::project::DiscoverySource::EnvVar,
            }),
            None => serde_json::Value::Null,
        },
    });

    // Install root.
    out["install_root"] = match crate::project::install_root() {
        Some(install) => {
            let (source_tag, project_name) = match &install.source {
                crate::project::InstallDiscoverySource::EnvVar => ("env_var", None),
                crate::project::InstallDiscoverySource::WorkspaceMember { project_name } => {
                    ("workspace_member", Some(project_name.clone()))
                }
                crate::project::InstallDiscoverySource::ExePrefixShare => {
                    ("exe_prefix_share", None)
                }
                crate::project::InstallDiscoverySource::ExePrefixFlat => ("exe_prefix_flat", None),
            };
            let mut entry = serde_json::json!({
                "path": install.path.display().to_string(),
                "source": source_tag,
                "same_as_project": install.path == pr.path,
            });
            if let Some(name) = project_name {
                entry["workspace_project"] = serde_json::Value::String(name);
            }
            entry
        }
        None => serde_json::Value::Null,
    };

    // Targets — merged project + install view with per-entry
    // source annotation. Mirrors the text output's dual-root
    // semantics. Each entry carries `source` ∈ {"project",
    // "install", "project+install"} (last value = present in
    // both, project wins). Stable v1 shape.
    let install_root_for_json = crate::project::install_root();
    let install_path_for_json = install_root_for_json
        .as_ref()
        .map(|i| i.path.clone())
        .filter(|p| *p != pr.path);
    let project_target_names = target::list_targets_under(&pr.path);
    let install_target_names: Vec<String> = install_path_for_json
        .as_deref()
        .map(target::list_targets_under)
        .unwrap_or_default();
    let mut targets_arr = Vec::new();
    use std::collections::BTreeMap;
    let mut tgt_by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_target_names {
        tgt_by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_target_names {
        tgt_by_name.entry(n.clone()).or_default().1 = true;
    }
    for (name, (in_project, in_install)) in &tgt_by_name {
        let source = match (in_project, in_install) {
            (true, true) => "project+install",
            (true, false) => "project",
            (false, true) => "install",
            (false, false) => "unknown",
        };
        let entry = match target::load_target(name, &pr.path) {
            Ok(desc) => {
                let kind = if desc.board_id.is_some() {
                    "board"
                } else if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                serde_json::json!({
                    "name": name,
                    "kind": kind,
                    "description": desc.description,
                    "source": source,
                })
            }
            Err(e) => serde_json::json!({
                "name": name,
                "kind": "error",
                "description": e.to_string(),
                "source": source,
            }),
        };
        targets_arr.push(entry);
    }
    out["targets"] = serde_json::Value::Array(targets_arr);

    // Stacks — same dual-root pattern. v1 shape change: stacks
    // is now an array of objects `{"name", "source"}` instead of
    // an array of name strings. Tooling consumers that ignore
    // extra fields keep working; the source annotation is new.
    let project_stack_names = stack_expand::list_available_stack_names(&pr.path);
    let install_stack_names: Vec<String> = install_path_for_json
        .as_deref()
        .map(stack_expand::list_available_stack_names)
        .unwrap_or_default();
    let mut stk_by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_stack_names {
        stk_by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_stack_names {
        stk_by_name.entry(n.clone()).or_default().1 = true;
    }
    let stacks: Vec<serde_json::Value> = stk_by_name
        .iter()
        .map(|(name, (in_project, in_install))| {
            let source = match (in_project, in_install) {
                (true, true) => "project+install",
                (true, false) => "project",
                (false, true) => "install",
                (false, false) => "unknown",
            };
            serde_json::json!({ "name": name, "source": source })
        })
        .collect();
    out["stacks"] = serde_json::json!(stacks);

    // Rig.
    let lab_env = std::env::var("FLUXOR_LAB").ok();
    let active_lab = lab_env.clone().unwrap_or_else(|| "default".to_string());
    let labs = crate::rig::enumerate_labs().unwrap_or_default();
    let rigs = crate::rig::enumerate_rigs(&active_lab).unwrap_or_default();
    let rigs_json: Vec<serde_json::Value> = rigs
        .iter()
        .map(|r| {
            let path =
                crate::rig::default_profile_path(&active_lab, r).map(|p| p.display().to_string());
            serde_json::json!({ "name": r, "profile_path": path })
        })
        .collect();
    out["rig"] = serde_json::json!({
        "active_lab": active_lab,
        "lab_env_set": lab_env.is_some(),
        "available_labs": labs,
        "rigs": rigs_json,
    });

    // Scenarios.
    let scenario_dirs = [
        pr.path.join("examples"),
        pr.path.join("examples/test_harness"),
        pr.path.join("tests/hardware"),
    ];
    let mut scanned: Vec<String> = Vec::new();
    let mut found_pairs: Vec<(PathBuf, String)> = Vec::new();
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for dir in &scenario_dirs {
        if !dir.is_dir() {
            continue;
        }
        scanned.push(dir.display().to_string());
        match scenario::list_scenarios(dir) {
            Ok(rows) => found_pairs.extend(rows),
            Err(e) => errors.push(serde_json::json!({
                "dir": dir.display().to_string(),
                "message": e.to_string(),
            })),
        }
    }
    // Dedupe by canonical path.
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    found_pairs.retain(|(p, _)| {
        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
        seen.insert(key)
    });
    found_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let found_arr: Vec<serde_json::Value> = found_pairs
        .iter()
        .map(|(path, name)| {
            let rel = path
                .strip_prefix(&pr.path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());
            serde_json::json!({
                "path": path.display().to_string(),
                "relative_path": rel,
                "name": name,
            })
        })
        .collect();
    out["scenarios"] = serde_json::json!({
        "scanned_dirs": scanned,
        "found": found_arr,
        "errors": errors,
    });

    // Optional per-config block.
    if let Some(cfg_path) = config_path {
        out["config"] = config_inspection_json(cfg_path, &pr.path);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&out)
            .map_err(|e| error::Error::Config(format!("inspect json: {e}")))?
    );
    Ok(())
}

/// Build the JSON sub-object for the `config` block — mirrors the
/// human-text `Config:` rendering. Read-only; never mutates state.
fn config_inspection_json(config_path: &Path, project_root: &Path) -> serde_json::Value {
    let raw = match std::fs::read_to_string(config_path)
        .and_then(|s| substitute_env_vars(&s).map_err(|e| std::io::Error::other(e.to_string())))
    {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({
                "path": config_path.display().to_string(),
                "error": format!("read: {e}"),
            })
        }
    };
    let parse_result: std::result::Result<serde_json::Value, String> = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&raw).map_err(|e| e.to_string())
    } else {
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    };
    let parsed = match parse_result {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "path": config_path.display().to_string(),
                "error": format!("parse: {e}"),
            })
        }
    };

    let declared = parsed
        .get("target")
        .and_then(|v| v.as_str())
        .map(String::from);
    let resolved = match resolve_target(&parsed, None) {
        Ok(desc) => Some(serde_json::json!({
            "id": desc.id,
            "kind": if desc.board_id.is_some() {
                "board"
            } else if desc.build.is_some() {
                "silicon"
            } else {
                "validation"
            },
            "board_id": desc.board_id.as_ref(),
        })),
        Err(_) => None,
    };

    let mut probe = parsed.clone();
    let probe_yaml_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = inline_route_body_files(&mut probe, &probe_yaml_dir);
    let expanded_stack_modules: Vec<String> = if let Ok(desc) = resolve_target(&parsed, None) {
        stack_expand::expand_platform_stacks(&mut probe, &desc, project_root).unwrap_or_default()
    } else {
        Vec::new()
    };

    let search_paths: Vec<String> = config::extract_module_search_paths(&probe, config_path)
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    serde_json::json!({
        "path": config_path.display().to_string(),
        "declared_target": declared,
        "resolved_target": resolved,
        "expanded_stack_modules": expanded_stack_modules,
        "module_search_paths": search_paths,
    })
}

/// Aggregate scenario discovery across the conventional roots
/// (`examples/`, `examples/test_harness/`, `tests/hardware/`). Calls
/// `scenario::list_scenarios` per directory — it already filters for
/// `kind: scenario` files and graphs with inline `scenario:` blocks,
/// so this function just unions the results.
///
/// Output mirrors `fluxor run --list <dir>` but unified across the
/// well-known locations so the user sees the whole catalogue at a
/// glance. Paths are rendered relative to the project root so the
/// output stays terse on long absolute paths.
fn inspect_scenarios(project_root: &Path) {
    let candidate_dirs = [
        project_root.join("examples"),
        project_root.join("examples/test_harness"),
        project_root.join("tests/hardware"),
    ];

    println!("Scenarios");

    let mut findings: Vec<(PathBuf, String)> = Vec::new();
    let mut errors: Vec<(PathBuf, String)> = Vec::new();
    let mut scanned_dirs: Vec<PathBuf> = Vec::new();
    for dir in &candidate_dirs {
        if !dir.is_dir() {
            continue;
        }
        scanned_dirs.push(dir.clone());
        match scenario::list_scenarios(dir) {
            Ok(rows) => findings.extend(rows),
            Err(e) => errors.push((dir.clone(), e.to_string())),
        }
    }

    if scanned_dirs.is_empty() {
        println!(
            "  <no conventional scenario directories under {}>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("  scanned:");
    for dir in &scanned_dirs {
        println!("    {}", dir.display());
    }

    // Dedupe by canonical path. `list_scenarios` already dedupes
    // within a directory; the cross-directory case fires when the
    // same scenario is symlinked, which is rare but worth handling
    // so the count is accurate.
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    findings.retain(|(p, _)| {
        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
        seen.insert(key)
    });
    findings.sort_by(|a, b| a.0.cmp(&b.0));

    if findings.is_empty() {
        println!("  <no scenarios found>");
    } else {
        println!("  found:");
        for (path, name) in &findings {
            // Render path relative to project_root for terseness.
            let rel = path
                .strip_prefix(project_root)
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|_| path.clone());
            println!("    {:40} {}", rel.display(), name);
        }
    }
    for (dir, msg) in errors {
        println!("  warning: enumerating {}: {}", dir.display(), msg);
    }
    println!();
}

/// Render the `Targets` block with project + install merge and
/// per-entry source annotation. Mirrors the build path's
/// `target::load_target` fallback behaviour so an external
/// project with no local `targets/` still sees bundled targets
/// listed (with `[install]` annotation), and a project-side
/// override of a bundled name surfaces both copies — the project
/// one marked `[project, shadows install]` and the install one
/// marked `[install, shadowed]`.
///
/// `install_distinct` is `Some` only when an install root is
/// discovered AND distinct from the project root (running from
/// the fluxor source tree puts them at the same path, in which
/// case no source annotation adds signal).
fn print_inspect_targets_block(project_root: &Path, install_distinct: Option<&Path>) {
    let project_names = target::list_targets_under(project_root);
    let install_names: Vec<String> = install_distinct
        .map(target::list_targets_under)
        .unwrap_or_default();

    if project_names.is_empty() && install_names.is_empty() {
        println!("Targets");
        println!(
            "  <none — neither {} nor any install root has a targets/ dir>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("Targets");
    println!(
        "  project root:         {}",
        project_root.join("targets").display()
    );
    if let Some(install) = install_distinct {
        println!(
            "  install root:         {}",
            install.join("targets").display()
        );
    }

    // Build a deduped name list with per-name source info.
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_names {
        by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_names {
        by_name.entry(n.clone()).or_default().1 = true;
    }

    if by_name.is_empty() {
        println!("  <no targets found in either root>");
    } else {
        for (name, (in_project, in_install)) in &by_name {
            // Resolve from project_root so the layered lookup
            // matches the build path. `load_target` consults the
            // install root on miss, so the description always
            // reflects the resolved descriptor.
            let desc_line = match target::load_target(name, project_root) {
                Ok(desc) => {
                    let kind = if desc.board_id.is_some() {
                        "board"
                    } else if desc.build.is_some() {
                        "silicon"
                    } else {
                        "validation"
                    };
                    format!("{kind:9}  {}", desc.description)
                }
                Err(_) => "<error loading>".to_string(),
            };
            let source_tag = match (install_distinct.is_some(), in_project, in_install) {
                // No install root → no annotation needed.
                (false, _, _) => String::new(),
                // Both → project shadows install.
                (true, true, true) => "  [project, shadows install]".to_string(),
                (true, true, false) => "  [project]".to_string(),
                (true, false, true) => "  [install]".to_string(),
                // BTreeMap entries always have at least one source.
                (true, false, false) => String::new(),
            };
            println!("  {name:20} {desc_line}{source_tag}");
        }
    }
    println!();
}

/// Render the `Stacks` block with the same dual-root merge as the
/// targets block. `load_stack` walks project then install; this
/// view reflects that.
fn print_inspect_stacks_block(project_root: &Path, install_distinct: Option<&Path>) {
    let project_names = stack_expand::list_available_stack_names(project_root);
    let install_names: Vec<String> = install_distinct
        .map(stack_expand::list_available_stack_names)
        .unwrap_or_default();

    if project_names.is_empty() && install_names.is_empty() {
        println!("Stacks");
        println!(
            "  <none — neither {} nor any install root has a stacks/ dir>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("Stacks");
    println!(
        "  project root:         {}",
        project_root.join("stacks").display()
    );
    if let Some(install) = install_distinct {
        println!(
            "  install root:         {}",
            install.join("stacks").display()
        );
    }

    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_names {
        by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_names {
        by_name.entry(n.clone()).or_default().1 = true;
    }
    if by_name.is_empty() {
        println!("  <no stacks found in either root>");
    } else {
        for (name, (in_project, in_install)) in &by_name {
            let source_tag = match (install_distinct.is_some(), in_project, in_install) {
                (false, _, _) => String::new(),
                (true, true, true) => "  [project, shadows install]".to_string(),
                (true, true, false) => "  [project]".to_string(),
                (true, false, true) => "  [install]".to_string(),
                (true, false, false) => String::new(),
            };
            println!("  {name}{source_tag}");
        }
    }
    println!();
}

fn inspect_rig_config() {
    println!("Rig configuration");

    // Active lab: $FLUXOR_LAB → "default". Same precedence
    // `rig::cli` uses to pick the lab namespace.
    let lab_env = std::env::var("FLUXOR_LAB").ok();
    let active_lab = lab_env.clone().unwrap_or_else(|| "default".to_string());
    println!("  active lab:           {active_lab}");
    match lab_env {
        Some(_) => println!("  $FLUXOR_LAB:          set"),
        None => println!("  $FLUXOR_LAB:          <unset> (defaulting to 'default')"),
    }

    // Available labs.
    let labs_root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".config/fluxor/labs"));
    if let Some(ref dir) = labs_root {
        match crate::rig::enumerate_labs() {
            Ok(labs) if labs.is_empty() => {
                println!(
                    "  available labs:       <none configured under {}>",
                    dir.display()
                );
            }
            Ok(labs) => {
                println!("  available labs:");
                for lab in &labs {
                    let marker = if *lab == active_lab { " (active)" } else { "" };
                    println!("    {lab}{marker}");
                }
            }
            Err(e) => {
                println!("  available labs:       <error: {e}>");
            }
        }
    } else {
        println!("  available labs:       <$HOME unset; cannot enumerate>");
    }

    // Rigs in the active lab.
    match crate::rig::enumerate_rigs(&active_lab) {
        Ok(rigs) if rigs.is_empty() => {
            println!("  rigs in active lab:   <none>");
            if let Some(ref dir) = labs_root {
                println!(
                    "  (rig profiles live under {}/{}/rigs/<rig>.toml)",
                    dir.display(),
                    active_lab
                );
            }
        }
        Ok(rigs) => {
            println!("  rigs in active lab:");
            for r in &rigs {
                // Resolve each rig's profile path so the user knows
                // where the descriptor lives without grepping for
                // `default_profile_path`.
                let path = crate::rig::default_profile_path(&active_lab, r)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<$HOME unset>".into());
                println!("    {r:24} {path}");
            }
        }
        Err(e) => {
            println!("  rigs in active lab:   <error: {e}>");
        }
    }

    println!();
}

fn format_discovery_source(source: &crate::project::DiscoverySource) -> &'static str {
    match source {
        crate::project::DiscoverySource::EnvVar => "$FLUXOR_PROJECT_ROOT override",
        crate::project::DiscoverySource::DotFluxorMarker => ".fluxor marker file",
        crate::project::DiscoverySource::SourceTreeMarker => {
            "source-tree heuristic (targets/ + stacks/)"
        }
        crate::project::DiscoverySource::CwdFallback => "CWD fallback (no marker found)",
    }
}

fn format_install_source(source: &crate::project::InstallDiscoverySource) -> String {
    match source {
        crate::project::InstallDiscoverySource::EnvVar => "$FLUXOR_INSTALL_ROOT override".into(),
        crate::project::InstallDiscoverySource::WorkspaceMember { project_name } => {
            format!("workspace member `{project_name}`")
        }
        crate::project::InstallDiscoverySource::ExePrefixShare => {
            "exe-prefix `<prefix>/share/fluxor/`".into()
        }
        crate::project::InstallDiscoverySource::ExePrefixFlat => "exe-prefix `<prefix>/`".into(),
    }
}

fn inspect_config(config_path: &Path, project_root: &Path) -> Result<()> {
    // Wrap the read with explicit path context so a missing file
    // (the common typo case for `fluxor inspect`) surfaces as
    // "Cannot read config /path/foo.yaml: No such file…" rather
    // than the bare "No such file or directory" the IO error's
    // Display gives.
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        error::Error::Config(format!("Cannot read config {}: {e}", config_path.display()))
    })?;
    let content = substitute_env_vars(&content)?;
    let raw: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content).map_err(|e| {
            error::Error::Config(format!(
                "Cannot parse {} as YAML: {e}",
                config_path.display()
            ))
        })?
    } else {
        serde_json::from_str(&content).map_err(|e| {
            error::Error::Config(format!(
                "Cannot parse {} as JSON: {e}",
                config_path.display()
            ))
        })?
    };

    println!("Config: {}", config_path.display());

    let declared = raw
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("<not set>");
    println!("  declared target:      {declared}");

    // Resolve target. When `declared` names a board, the loader
    // walks the board → silicon link and returns the silicon
    // descriptor with `desc.id` = silicon id and `desc.board_id`
    // = the original board name. Display both so the user sees
    // exactly what the build resolved to.
    match resolve_target(&raw, None) {
        Ok(desc) => {
            if let Some(board_id) = &desc.board_id {
                println!("  resolved target:      {board_id} (board)");
                println!("  via board → silicon:  {}", desc.id);
            } else {
                let kind = if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                println!("  resolved target:      {} ({})", desc.id, kind);
            }
        }
        Err(e) => {
            println!("  resolved target:      <error: {e}>");
        }
    }

    // Stack expansion preview. Cloning here so the inspection
    // doesn't mutate the original (in case future expansion does
    // more in place).
    let mut probe = raw.clone();
    if let Ok(desc) = resolve_target(&raw, None) {
        let mut probe_yaml_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        if probe_yaml_dir.as_os_str().is_empty() {
            probe_yaml_dir = std::path::PathBuf::from(".");
        }
        let _ = inline_route_body_files(&mut probe, &probe_yaml_dir);
        match stack_expand::expand_platform_stacks(&mut probe, &desc, project_root) {
            Ok(added) if added.is_empty() => {
                println!("  expanded stacks:      <none added>");
            }
            Ok(added) => {
                println!("  expanded stacks:      {} module(s) added", added.len());
                for m in &added {
                    println!("    + {m}");
                }
            }
            Err(e) => {
                println!("  expanded stacks:      <error: {e}>");
            }
        }
    }

    // Manifest search paths.
    let search_paths = config::extract_module_search_paths(&probe, config_path);
    println!("  module search paths:");
    if search_paths.is_empty() {
        println!("    <none>");
    } else {
        for p in &search_paths {
            println!("    {}", p.display());
        }
    }

    Ok(())
}

/// Build a module table blob from .fmod files in a directory.
fn cmd_mktable(dir: &PathBuf, output: &PathBuf) -> Result<()> {
    use std::fs;

    let mut fmod_files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("fmod") {
            fmod_files.push(path);
        }
    }
    fmod_files.sort();

    if fmod_files.is_empty() {
        return Err(Error::Module("No .fmod files found".into()));
    }

    let mut modules = Vec::new();
    for path in &fmod_files {
        let info = modules::ModuleInfo::from_file(path)?;
        modules.push(info);
    }

    let table = build_module_table(&modules)?;
    fs::write(output, &table)?;

    println!(
        "{} modules, {} bytes → {}",
        modules.len(),
        table.len(),
        output.display()
    );
    for m in &modules {
        println!("  {} ({} bytes)", m.name, m.data.len());
    }

    Ok(())
}

fn cmd_mktable_config(config_path: &Path, modules_dirs: &[PathBuf], output: &Path) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let mut config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let yaml_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    inline_route_body_files(&mut config, yaml_dir)?;

    // Apply platform-stack injection so configs using e.g.
    // `platform: storage: { media: nvme }` report the full injected
    // module set — matches the behaviour of `combine` / `validate`.
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let primary_dir = if modules_dirs.is_empty() {
        return Err(Error::Module("--modules-dir is required".into()));
    } else {
        &modules_dirs[0]
    };
    let extra_dirs: Vec<&std::path::Path> =
        modules_dirs.iter().skip(1).map(|p| p.as_path()).collect();
    let modules = parse_modules_from_config_multi(&config, primary_dir, &extra_dirs)?;
    // All-builtin configs (e.g. linux_display + host_image_codec) leave
    // `modules` empty; emit a valid 16-byte header-only table so the
    // host loader sees module_count=0 and instantiates only built-ins.
    let table = build_module_table(&modules)?;
    std::fs::write(output, &table)?;

    println!(
        "{} modules from {} → {}",
        modules.len(),
        config_path.display(),
        output.display()
    );
    for m in &modules {
        println!("  {} ({} bytes)", m.name, m.data.len());
    }

    Ok(())
}

fn cmd_diff(old_path: &PathBuf, new_path: &PathBuf, target_override: Option<&str>) -> Result<()> {
    let old_content = substitute_env_vars(&std::fs::read_to_string(old_path)?)?;
    let new_content = substitute_env_vars(&std::fs::read_to_string(new_path)?)?;

    let old_config: serde_json::Value = serde_yaml::from_str(&old_content)?;
    let new_config: serde_json::Value = serde_yaml::from_str(&new_content)?;

    let target_desc = resolve_target(&new_config, target_override)?;
    let modules_dir_path = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);

    let plan = reconfigure::compute_transition_plan(&old_config, &new_config, modules_dir);

    print!("{}", reconfigure::format_plan(&plan));

    Ok(())
}

// ── Build / Run / Flash ────────────────────────────────────────────────────

/// Result of a successful single-config build.
struct BuildResult {
    output_path: PathBuf,
    family: String,
    board_id: Option<String>,
}

/// Derive the output subdirectory from a YAML path relative to `examples/`.
/// e.g. `examples/led_patterns/pico2w.yaml` -> "pico2w", otherwise empty string.
fn subdir_from_path(yaml_path: &std::path::Path) -> String {
    // Walk components looking for "examples" then take the next component
    let components: Vec<_> = yaml_path.components().collect();
    for (i, c) in components.iter().enumerate() {
        if let std::path::Component::Normal(s) = c {
            if *s == "examples" {
                if let Some(std::path::Component::Normal(next)) = components.get(i + 1) {
                    // Only use as subdir if the YAML is deeper (not directly in examples/)
                    if i + 2 < components.len() {
                        return next.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// Build a single YAML config into its output artifact.
fn build_one(
    yaml_path: &std::path::Path,
    output_override: Option<&std::path::Path>,
    verbose: bool,
) -> Result<BuildResult> {
    // Load and parse config
    let content = substitute_env_vars(&std::fs::read_to_string(yaml_path)?)?;
    let config: serde_json::Value = if yaml_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    let family = target_desc.family.clone();
    let silicon_id = target_desc.id.clone();
    let build_id = target_desc.build_id().to_string();
    let board_id = target_desc.board_id.clone();

    // Artifact layout:
    //   firmware  target/{build_id}/firmware.bin   (board-specific when cargo
    //                                               features differ per board)
    //   modules   target/fluxor/{silicon_id}/modules/  (byte-identical per
    //                                               silicon + module target)
    //   output    target/{build_id}/{images|uf2}/<subdir>/<name>.{img|uf2}
    let firmware_path = PathBuf::from(format!("target/{build_id}/firmware.bin"));
    let modules_dir = PathBuf::from(format!("target/fluxor/{silicon_id}/modules"));

    let name = yaml_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let subdir = subdir_from_path(yaml_path);

    let output_path = if let Some(o) = output_override {
        o.to_path_buf()
    } else {
        match family.as_str() {
            "rp2" => {
                let mut p = PathBuf::from(format!("target/{build_id}/uf2"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.uf2"));
                p
            }
            "bcm" => {
                let mut p = PathBuf::from(format!("target/{build_id}/images"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.img"));
                p
            }
            "linux" => {
                let mut p = PathBuf::from(format!("target/linux/{name}"));
                // Linux produces two files; the "output_path" is the directory
                p.push("config.bin");
                p
            }
            "wasm" => {
                let mut p = PathBuf::from(format!("target/{build_id}/wasm"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.wasm"));
                p
            }
            _ => {
                return Err(Error::Config(format!(
                    "Unsupported target family '{family}' for build"
                )));
            }
        }
    };

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match family.as_str() {
        "rp2" | "bcm" => {
            if !firmware_path.exists() {
                let abs = firmware_path.canonicalize().unwrap_or_else(|_| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join(&firmware_path)
                });
                return Err(Error::Config(format!(
                    "Firmware not found at {} (resolved to {}). Run 'make firmware TARGET={}' from the \
                     project root (`fluxor inspect` shows where that is) to produce it.",
                    firmware_path.display(),
                    abs.display(),
                    build_id
                )));
            }
            if !modules_dir.exists() {
                let abs = modules_dir.canonicalize().unwrap_or_else(|_| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join(&modules_dir)
                });
                return Err(Error::Config(format!(
                    "Modules not found at {} (resolved to {}). Run 'make modules TARGET={}' from the \
                     project root (`fluxor inspect` shows where that is) to produce them.",
                    modules_dir.display(),
                    abs.display(),
                    build_id
                )));
            }
            cmd_combine(
                &firmware_path,
                &yaml_path.to_path_buf(),
                &output_path,
                verbose,
            )?;
        }
        "linux" => {
            let out_dir = output_path
                .parent()
                .unwrap_or(std::path::Path::new("target/linux"));
            std::fs::create_dir_all(out_dir)?;

            let config_bin_path = out_dir.join("config.bin");
            let modules_bin_path = out_dir.join("modules.bin");

            // Linux host reuses the aarch64 PIC modules built for bcm2712.
            // When fluxor is consumed as a submodule, accept a sibling copy
            // at ../deps/fluxor/target/fluxor/bcm2712/modules.
            let modules_dir = PathBuf::from("target/fluxor/bcm2712/modules");
            let mut fmod_dirs: Vec<PathBuf> = Vec::new();
            if modules_dir.exists() {
                fmod_dirs.push(modules_dir.clone());
            }
            if let Some(config_parent) = yaml_path.parent().and_then(|p| p.parent()) {
                let ext_modules = config_parent.join("deps/fluxor/target/fluxor/bcm2712/modules");
                if ext_modules.exists() {
                    fmod_dirs.push(ext_modules);
                }
            }
            if fmod_dirs.is_empty() {
                return Err(Error::Config(
                    "Modules not found at target/fluxor/bcm2712/modules. Run 'make modules TARGET=bcm2712' first.".into()
                ));
            }
            // Cross-check the YAML against the linux binary's
            // compiled-in features (host-image / host-window /
            // host-playback). A YAML that asks for a backend the
            // binary can't provide fails here with the matching
            // `cargo build` command in the error message.
            validate_linux_runtime_features(yaml_path)?;
            cmd_mktable_config(yaml_path, &fmod_dirs, &modules_bin_path)?;
            cmd_generate(
                yaml_path,
                Some(config_bin_path.as_path()),
                Some(modules_dir.as_path()),
                true,
            )?;
        }
        "wasm" => {
            // wasm produces one self-contained `.wasm` file: the
            // kernel `firmware.wasm` with its embedded modules-blob
            // and config-blob placeholders rewritten in-place. See
            // `docs/architecture/wasm_platform.md` and the
            // `wasm_bundle` module for the rewrite mechanics.
            let kernel_wasm_path = PathBuf::from(format!("target/{build_id}/firmware.wasm"));
            if !kernel_wasm_path.exists() {
                return Err(Error::Config(format!(
                    "Kernel wasm not found at {}. Run 'make firmware TARGET=wasm' first.",
                    kernel_wasm_path.display()
                )));
            }
            if !modules_dir.exists() {
                return Err(Error::Config(format!(
                    "Modules not found at {}. Run 'make modules TARGET=wasm' first.",
                    modules_dir.display()
                )));
            }

            // Build modules.bin and config.bin in a workspace dir so
            // intermediate artifacts are inspectable but don't
            // pollute the final output path.
            let work_dir = output_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(format!("target/{build_id}/wasm")));
            std::fs::create_dir_all(&work_dir)?;
            let modules_bin_path = work_dir.join(format!("{name}.modules.bin"));
            let config_bin_path = work_dir.join(format!("{name}.config.bin"));

            let extra_dirs: Vec<PathBuf> = Vec::new();
            let fmod_dirs: Vec<PathBuf> = std::iter::once(modules_dir.clone())
                .chain(extra_dirs)
                .collect();
            cmd_mktable_config(yaml_path, &fmod_dirs, &modules_bin_path)?;
            cmd_generate(
                yaml_path,
                Some(config_bin_path.as_path()),
                Some(modules_dir.as_path()),
                true,
            )?;

            let kernel_bytes = std::fs::read(&kernel_wasm_path)?;
            let modules_bin = std::fs::read(&modules_bin_path)?;
            let config_bin = std::fs::read(&config_bin_path)?;
            let mut bundled = wasm_bundle::bundle(&kernel_bytes, &modules_bin, &config_bin)?;

            // Asset bank: bake graph-declared assets into the wasm via
            // a `fluxor.assets` custom section. Off when no `assets:`
            // block is present. Resolves paths relative to the graph
            // YAML's directory so demos can use `../../assets/foo.png`.
            let assets = extract_asset_pairs(&config, yaml_path)?;
            let asset_count = assets.len();
            let entries = asset_bank::load_assets(&assets)?;
            let asset_bytes: usize = entries.iter().map(|e| e.bytes.len()).sum();
            asset_bank::append_asset_bank(&mut bundled, &entries)?;

            std::fs::write(&output_path, &bundled)?;

            if verbose {
                eprintln!(
                    "wasm bundle: {} bytes (modules={} config={} assets={}/{} bytes)",
                    bundled.len(),
                    modules_bin.len(),
                    config_bin.len(),
                    asset_count,
                    asset_bytes,
                );
            }
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{family}' for build"
            )));
        }
    }

    Ok(BuildResult {
        output_path,
        family,
        board_id,
    })
}

/// Pull `assets:` out of a graph YAML and return resolved `(name, path)`
/// pairs the asset-bank builder can consume. Two shapes are accepted:
///
/// 1. Bare string — `assets: [examples/test_harness/assets/spiral.png, ...]`.
///    The asset's logical name is the basename. Paths resolve
///    relative to the graph YAML's directory.
/// 2. Per-entry map — `assets: [{ path: ..., name: spiral.png }, ...]`.
///    Explicit name override is useful when two folders ship files
///    with the same basename.
///
/// Returns an empty vec when the YAML has no `assets:` field. Errors
/// on schema mismatch or a relative-path traversal trying to escape
/// the workspace via excessive `..` segments.
fn extract_asset_pairs(
    config: &serde_json::Value,
    yaml_path: &std::path::Path,
) -> Result<Vec<(String, PathBuf)>> {
    let Some(arr) = config.get("assets").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let base_dir = yaml_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut out = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let (raw_path, override_name) = match entry {
            serde_json::Value::String(s) => (s.clone(), None),
            serde_json::Value::Object(m) => {
                let p = m
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::Config(format!(
                            "graph `{}`: assets[{}] missing `path:` field",
                            yaml_path.display(),
                            i
                        ))
                    })?
                    .to_string();
                let n = m
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (p, n)
            }
            _ => {
                return Err(Error::Config(format!(
                    "graph `{}`: assets[{}] must be a string or a map with `path:`",
                    yaml_path.display(),
                    i
                )));
            }
        };

        let resolved = base_dir.join(&raw_path);
        let name = override_name.unwrap_or_else(|| {
            std::path::Path::new(&raw_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&raw_path)
                .to_string()
        });
        out.push((name, resolved));
    }
    Ok(out)
}

fn cmd_build(path: &Path, output: Option<&std::path::Path>, verbose: bool) -> Result<()> {
    if path.is_dir() {
        // Glob for all YAML files recursively
        let mut yamls: Vec<PathBuf> = Vec::new();
        collect_yaml_files(path, &mut yamls);
        yamls.sort();

        if yamls.is_empty() {
            return Err(Error::Config(format!(
                "No YAML files found in {}",
                path.display()
            )));
        }

        let total = yamls.len();
        let mut built = 0;
        let mut failed = 0;

        for yaml in &yamls {
            match build_one(yaml, None, verbose) {
                Ok(_) => built += 1,
                Err(e) => {
                    eprintln!("\x1b[1;33mWarn:\x1b[0m {} -- {}", yaml.display(), e);
                    failed += 1;
                }
            }
        }

        println!("\nBuilt {built}/{total} configs ({failed} failed)");
        if failed > 0 && built == 0 {
            return Err(Error::Config("All builds failed".into()));
        }
        Ok(())
    } else {
        build_one(path, output, verbose)?;
        Ok(())
    }
}

/// Recursively collect *.yaml files from a directory.
fn collect_yaml_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_yaml_files(&p, out);
            } else if p
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                out.push(p);
            }
        }
    }
}

/// Cross-check a Linux YAML config against the `fluxor-linux` binary's
/// compiled-in features. Module types and per-mode values that need an
/// optional backend are matched against the feature set the binary
/// reports via `--print-features`; any mismatch fails the build with
/// the matching `cargo build` invocation in the error message.
///
/// Skipped silently when the binary is absent (`build_one` errors on
/// that path before we reach here) or when `--print-features` exits
/// non-zero (the binary is too old to expose its feature set).
fn validate_linux_runtime_features(yaml_path: &std::path::Path) -> Result<()> {
    let linux_bin = PathBuf::from("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux_bin.exists() {
        return Ok(());
    }

    let output = std::process::Command::new(&linux_bin)
        .arg("--print-features")
        .output()
        .map_err(|e| {
            Error::Config(format!(
                "failed to query features from {}: {}",
                linux_bin.display(),
                e
            ))
        })?;
    if !output.status.success() {
        eprintln!(
            "warning: {} --print-features failed; skipping feature cross-check",
            linux_bin.display()
        );
        return Ok(());
    }
    let features: std::collections::HashSet<String> = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Parse the YAML and walk modules. We don't reuse the full
    // generation pipeline — we just need module type + relevant fields.
    let content = substitute_env_vars(&std::fs::read_to_string(yaml_path)?)?;
    let mut config: serde_json::Value = if yaml_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let modules = match config.get("modules").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return Ok(()),
    };
    for entry in modules {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        let module_type = entry.get("type").and_then(|v| v.as_str()).unwrap_or(name);

        // Module-presence checks: if the YAML uses a module type that
        // requires a feature absent from the binary, fail.
        let required_for_type: Option<&str> = match module_type {
            "host_image_codec" => Some("host-image"),
            _ => None,
        };
        if let Some(feat) = required_for_type {
            if !features.contains(feat) {
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') requires `fluxor-linux` to be built \
                     with `--features {feat}` — current binary lacks it. \
                     Rebuild with: cargo build --release --bin fluxor-linux \
                     --no-default-features --features {feat} \
                     --target aarch64-unknown-linux-gnu",
                )));
            }
        }

        // Per-mode-value checks for built-ins where the mode picks an
        // optional backend.
        let mode_value = entry
            .get("mode")
            .or_else(|| {
                entry
                    .get("params")
                    .and_then(|p| p.as_object())
                    .and_then(|p| p.get("mode"))
            })
            .and_then(|v| v.as_str());
        let required_for_mode: Option<&str> = match (module_type, mode_value) {
            ("linux_display", Some("window")) => Some("host-window"),
            ("linux_audio", Some("playback")) => Some("host-playback"),
            _ => None,
        };
        if let Some(feat) = required_for_mode {
            if !features.contains(feat) {
                return Err(Error::Config(format!(
                    "module '{}' (type '{}', mode '{}') requires `fluxor-linux` \
                     to be built with `--features {}` — current binary lacks it. \
                     Either change `mode:` or rebuild with: cargo build --release \
                     --bin fluxor-linux --no-default-features --features {} \
                     --target aarch64-unknown-linux-gnu",
                    name,
                    module_type,
                    mode_value.unwrap_or(""),
                    feat,
                    feat,
                )));
            }
        }
    }
    Ok(())
}

/// Optional flags accepted by `fluxor run` for scenario YAMLs. For
/// graph YAMLs they are all ignored (and we error out if the user
/// passed one alongside a graph — see [`cmd_run_dispatch`]).
struct RunFlags {
    print_synthesised: bool,
    print_merged: Option<String>,
    validate_only: bool,
    graph: bool,
    /// `Some(dir)` if `--list[=DIR]` was set on the command line.
    list: Option<PathBuf>,
    open: bool,
}

impl RunFlags {
    /// True when at least one scenario-only flag was set.  `--open`
    /// counts here too — but unlike the dump flags it does NOT
    /// short-circuit the spawn (it triggers after readiness fires).
    fn any_scenario_flag(&self) -> bool {
        self.print_synthesised
            || self.print_merged.is_some()
            || self.validate_only
            || self.graph
            || self.list.is_some()
            || self.open
    }
}

/// Top-level dispatch for `fluxor run`. Sniffs the YAML's `kind:`
/// field; routes graph YAMLs to [`cmd_run`] (unchanged from
/// pre-scenario behaviour) and scenario YAMLs to [`cmd_run_scenario`].
fn cmd_run_dispatch(config_path: Option<&PathBuf>, flags: RunFlags, verbose: bool) -> Result<()> {
    // `--list` short-circuits: enumerate, print, exit.
    if let Some(dir) = &flags.list {
        let scenarios = scenario::list_scenarios(dir)?;
        if scenarios.is_empty() {
            eprintln!("(no scenarios in {})", dir.display());
        } else {
            for (path, name) in scenarios {
                println!("{}\t{}", path.display(), name);
            }
        }
        return Ok(());
    }

    let config_path = config_path.ok_or_else(|| {
        Error::Config("fluxor run: missing <CONFIG> argument (omit only with --list)".into())
    })?;

    if scenario::is_scenario_file(config_path) {
        return cmd_run_scenario(config_path, &flags, verbose);
    }

    // Inline-scenario fast path: the graph YAML may carry a top-level
    // `scenario:` block (orchestration baked into the same file as the
    // graph). When present, synthesise a `Scenario` in memory and
    // dispatch through the regular scenario flow — same code path as
    // a standalone `kind: scenario` file, one less file per example.
    if let Some(synth) = scenario::synthesize_from_graph(config_path)? {
        return cmd_run_inline_scenario(synth, config_path, &flags, verbose);
    }

    // Bare graph YAML — every scenario-only flag is a user error.
    if flags.any_scenario_flag() {
        return Err(Error::Config(format!(
            "fluxor run {}: the supplied YAML is a graph (no `kind: scenario`); \
             scenario-only flags (--print-synthesised, --print-merged, --validate-only, \
             --graph) require a scenario YAML or an inline `scenario:` block on the graph.",
            config_path.display()
        )));
    }

    cmd_run(config_path, verbose)
}

/// Scenario flow for an in-memory `Scenario` synthesised from a graph
/// YAML's inline `scenario:` block. Mirrors `cmd_run_scenario` but
/// skips the file parse (the caller has already done it). `host_path`
/// is the graph YAML — used by `revalidate_all` for path resolution
/// (companion graph references resolve relative to it) and by error
/// messages.
fn cmd_run_inline_scenario(
    s: scenario::Scenario,
    host_path: &Path,
    flags: &RunFlags,
    verbose: bool,
) -> Result<()> {
    scenario::validate(&s, host_path)?;

    if flags.validate_only {
        scenario::revalidate_all(&s, host_path)?;
        println!(
            "graph {} (inline scenario): validation passed ({} component(s), {} binding(s); \
             merged-config re-validation green).",
            host_path.display(),
            s.components.len(),
            s.bindings.len()
        );
        return Ok(());
    }
    if flags.print_synthesised {
        match scenario::render_synthesised_host(&s, host_path)? {
            Some(yaml) => print!("{yaml}"),
            None => eprintln!(
                "graph {}: no synthesised host (every binding has an explicit `on:` and no \
                 `host:` block is declared).",
                host_path.display()
            ),
        }
        return Ok(());
    }
    if let Some(comp) = &flags.print_merged {
        print!(
            "{}",
            scenario::render_merged_component(comp, &s, host_path)?
        );
        return Ok(());
    }
    if flags.graph {
        print!("{}", scenario::render_graphviz(&s));
        return Ok(());
    }

    spawn_scenario(&s, host_path, flags, verbose)
}

/// Scenario dispatcher.  PR 1 implements the dump-only flags and
/// validation; spawning lands in PR 3.
fn cmd_run_scenario(scenario_path: &Path, flags: &RunFlags, _verbose: bool) -> Result<()> {
    let s = scenario::parse(scenario_path)?;
    scenario::validate(&s, scenario_path)?;

    if flags.validate_only {
        scenario::revalidate_all(&s, scenario_path)?;
        println!(
            "scenario {}: validation passed ({} component(s), {} binding(s); \
             merged-config re-validation green).",
            scenario_path.display(),
            s.components.len(),
            s.bindings.len()
        );
        return Ok(());
    }

    if flags.print_synthesised {
        match scenario::render_synthesised_host(&s, scenario_path)? {
            Some(yaml) => print!("{yaml}"),
            None => {
                eprintln!(
                    "scenario {}: no synthesised host (every binding has an explicit `on:` \
                     and no `host:` block is declared).",
                    scenario_path.display()
                );
            }
        }
        return Ok(());
    }

    if let Some(comp) = &flags.print_merged {
        print!(
            "{}",
            scenario::render_merged_component(comp, &s, scenario_path)?
        );
        return Ok(());
    }

    if flags.graph {
        print!("{}", scenario::render_graphviz(&s));
        return Ok(());
    }

    // Real spawn (PR 3 single-component + PR 4 multi-component &
    // sequential mode).
    spawn_scenario(&s, scenario_path, flags, _verbose)
}

/// PR 3 + PR 4: spawn a scenario.
///
/// Single-component scenarios (`is_single_component` true) take the
/// PR 3 path: build component → write synth host → build host → spawn
/// fluxor-linux → readiness probe → wait → propagate exit.
///
/// Multi-component scenarios take the PR 4 path: build every wasm
/// component (passive — bundles served as static artefacts) and every
/// non-wasm component (active — gets a fluxor-linux process each),
/// plus the synth host if `host:` is declared. Then:
///
///   - `sequential: true` runs active components one at a time in
///     declaration order, propagating the first non-zero exit and
///     enforcing per-component `duration:` (SIGTERM → SIGKILL after
///     2 s). This is the codec-test-harness mode.
///   - Otherwise spawn all actives in parallel, wait for any to exit,
///     SIGTERM the rest, and propagate the first exit.
///
/// In both cases Ctrl-C in the terminal sends SIGINT to the
/// foreground process group; each spawned `fluxor-linux` inherits it
/// and dies, and our `.wait()` returns the propagated exit status.
fn spawn_scenario(
    scenario: &scenario::Scenario,
    scenario_path: &Path,
    flags: &RunFlags,
    verbose: bool,
) -> Result<()> {
    scenario::revalidate_all(scenario, scenario_path)?;

    let scenario_dir = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;

    let linux_bin = PathBuf::from("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux_bin.exists() {
        return Err(Error::Config(format!(
            "fluxor-linux binary not found at {}. Run `make linux` first.",
            linux_bin.display()
        )));
    }

    // --- 1: build every component, classified by effective target. ---
    let mut actives: Vec<ActiveComponent> = Vec::new();
    for (comp_name, comp) in &scenario.components {
        let target = scenario::effective_target(scenario_path, comp);
        if target == "wasm" {
            // Passive: build the bundle into the canonical location
            // the synthesised host's fs_path: route already points at.
            let graph_rel = comp
                .graph
                .as_ref()
                .ok_or_else(|| Error::Config(format!("component `{comp_name}` has no `graph:`")))?;
            let graph_abs = scenario_dir.join(graph_rel);
            let bundle_target = scenario::wasm_bundle_target_path(comp_name, comp)?;
            eprintln!(
                "[scenario] {}: building component `{}` (wasm, {}) → {}",
                scenario.name,
                comp_name,
                graph_abs.display(),
                bundle_target.display()
            );
            build_one(&graph_abs, Some(&bundle_target), verbose)?;
            continue;
        }

        // Active: merge bindings into the component's graph, write to
        // disk, build, and queue for spawn.
        let merged_yaml =
            scenario::write_merged_component_yaml(comp_name, scenario, scenario_path)?;
        eprintln!(
            "[scenario] {}: building component `{}` ({}) → {}",
            scenario.name,
            comp_name,
            target,
            merged_yaml.display()
        );
        let build = build_one(&merged_yaml, None, verbose)?;
        if build.family != "linux" {
            return Err(Error::Config(format!(
                "scenario {}: component `{}` built for family {:?}; PR 3-4 only spawn linux \
                 components (use `runtime_override: linux` for cm5 graphs).",
                scenario_path.display(),
                comp_name,
                build.family
            )));
        }
        let dir = build.output_path.parent().ok_or_else(|| {
            Error::Config(format!(
                "component `{comp_name}` build has no output parent"
            ))
        })?;
        let merged_config: serde_json::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&merged_yaml)?)
                .map_err(|e| Error::Config(format!("parse merged yaml: {e}")))?;
        let port = scenario::extract_http_port(&merged_config);
        actives.push(ActiveComponent {
            display: comp_name.clone(),
            config_bin: dir.join("config.bin"),
            modules_bin: dir.join("modules.bin"),
            port,
            url: port.map(|p| format!("http://localhost:{p}/")),
            duration: comp
                .duration
                .map(|d| std::time::Duration::from_secs(d as u64)),
        });
    }

    // --- 2: synthesised host (acts like another active component). ---
    if let Some(host_yaml) = scenario::write_synthesised_host_yaml(scenario, scenario_path)? {
        eprintln!(
            "[scenario] {}: synthesised host written to {}",
            scenario.name,
            host_yaml.display()
        );
        let host_build = build_one(&host_yaml, None, verbose)?;
        if host_build.family != "linux" {
            return Err(Error::Config(format!(
                "scenario {}: synthesised host built for family {:?}; expected linux",
                scenario_path.display(),
                host_build.family
            )));
        }
        let dir = host_build
            .output_path
            .parent()
            .ok_or_else(|| Error::Config("host build has no output parent".into()))?;
        actives.push(ActiveComponent {
            display: "host".into(),
            config_bin: dir.join("config.bin"),
            modules_bin: dir.join("modules.bin"),
            port: scenario::synthesised_host_port(scenario),
            url: scenario::synthesised_host_url(scenario),
            duration: None,
        });
    }

    if actives.is_empty() {
        return Err(Error::Config(format!(
            "scenario {}: no active components to spawn (every component is wasm and no \
             `host:` block is declared).",
            scenario_path.display()
        )));
    }

    // --- 3: spawn — sequential or parallel. ---
    if scenario.sequential {
        run_actives_sequential(&scenario.name, &linux_bin, actives, flags, scenario_path)
    } else {
        run_actives_parallel(&scenario.name, &linux_bin, actives, flags, scenario_path)
    }
}

/// One active (= spawned-as-a-kernel-process) component in a
/// scenario. Built ahead of the spawn loop; the spawn loop just
/// invokes `fluxor-linux` with the config / modules pair.
struct ActiveComponent {
    /// Display name — the scenario component name, or `"host"` for
    /// the synthesised host.
    display: String,
    config_bin: PathBuf,
    modules_bin: PathBuf,
    /// http listen port (sniffed from the merged config). `None` for
    /// headless components — the readiness probe degrades to "child
    /// still alive after a startup grace period".
    port: Option<u16>,
    url: Option<String>,
    duration: Option<std::time::Duration>,
}

/// Sequential mode: run actives one at a time. First non-zero exit
/// aborts the scenario.
fn run_actives_sequential(
    name: &str,
    linux_bin: &Path,
    actives: Vec<ActiveComponent>,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<()> {
    for (i, a) in actives.into_iter().enumerate() {
        eprintln!(
            "[scenario] {}: [sequential {}/N] starting `{}`",
            name,
            i + 1,
            a.display
        );
        let status = spawn_and_wait_one(name, linux_bin, &a, flags, scenario_path)?;
        eprintln!(
            "[scenario] {}: [sequential {}/N] `{}` exit {}",
            name,
            i + 1,
            a.display,
            status
        );
        if !status.success() {
            return Err(Error::Config(format!(
                "scenario {}: sequential mode aborted — `{}` exited with status {}",
                scenario_path.display(),
                a.display,
                status
            )));
        }
    }
    Ok(())
}

/// Parallel mode: spawn every active, race them for exit. First to
/// exit propagates its status; the rest get SIGTERMed (then SIGKILL
/// after 2 s if they linger).
fn run_actives_parallel(
    name: &str,
    linux_bin: &Path,
    actives: Vec<ActiveComponent>,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<()> {
    let mut spawned: Vec<SpawnedActive> = Vec::new();
    for a in actives {
        eprintln!(
            "[scenario] {}: spawning `{}` (config={}, modules={})",
            name,
            a.display,
            a.config_bin.display(),
            a.modules_bin.display()
        );
        let s = spawn_one(linux_bin, &a, scenario_path)?;
        spawned.push(s);
    }

    // Run readiness probes for each spawned child in parallel.
    let deadline_per_child = std::time::Duration::from_secs(5);
    let mut probe_error: Option<(String, ReadyOutcome)> = None;
    for s in spawned.iter_mut() {
        let outcome = race_probe(&mut s.child, &s.probe, s.port, deadline_per_child);
        match outcome {
            ReadyOutcome::Ready => {
                if let Some(u) = &s.url {
                    eprintln!("[scenario] {}: ready — `{}` at {}", name, s.display, u);
                }
            }
            other => {
                let disp = s.display.clone();
                probe_error = Some((disp, other));
                break;
            }
        }
    }
    if let Some((disp, outcome)) = probe_error {
        match outcome {
            ReadyOutcome::ChildExited(status) => {
                eprintln!("[scenario] {name}: `{disp}` exited during startup ({status})");
                teardown_remaining(&mut spawned);
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` exited before its http listener bound \
                     (status {}). The kernel's diagnostic appears above.",
                    scenario_path.display(),
                    disp,
                    status
                )));
            }
            ReadyOutcome::Timeout => {
                eprintln!("[scenario] {name}: `{disp}` did not bind within 5 s");
                teardown_remaining(&mut spawned);
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` did not bind its http listener within 5 s.",
                    scenario_path.display(),
                    disp
                )));
            }
            ReadyOutcome::Ready => unreachable!(),
        }
    }

    // Optional --open: launch the browser on the first non-host URL,
    // falling back to the synth host URL.
    if flags.open {
        if let Some(s) = spawned
            .iter()
            .find(|s| s.url.is_some() && s.display != "host")
            .or_else(|| spawned.iter().find(|s| s.url.is_some()))
        {
            launch_browser(s.url.as_ref().unwrap());
        }
    }

    // Wait for any spawned child to exit; tear down the rest.
    let first_exit = wait_first_exit(&mut spawned);
    teardown_remaining(&mut spawned);
    if !first_exit.success() {
        return Err(Error::Config(format!(
            "scenario {}: one component exited with status {}",
            scenario_path.display(),
            first_exit
        )));
    }
    eprintln!("[scenario] {name}: terminated cleanly");
    Ok(())
}

/// Spawn one active and wait for it, honouring `duration:` if set.
fn spawn_and_wait_one(
    name: &str,
    linux_bin: &Path,
    active: &ActiveComponent,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<std::process::ExitStatus> {
    let mut s = spawn_one(linux_bin, active, scenario_path)?;
    let outcome = race_probe(
        &mut s.child,
        &s.probe,
        s.port,
        std::time::Duration::from_secs(5),
    );
    match outcome {
        ReadyOutcome::Ready => {
            if let Some(u) = &s.url {
                eprintln!("[scenario] {}: ready — `{}` at {}", name, s.display, u);
            }
            if flags.open {
                if let Some(u) = &s.url {
                    launch_browser(u);
                }
            }
        }
        ReadyOutcome::ChildExited(status) => {
            if let Some(p) = s.probe.take() {
                p.join();
            }
            return Err(Error::Config(format!(
                "scenario {}: component `{}` exited before its http listener bound \
                 (status {}). The kernel's diagnostic appears above.",
                scenario_path.display(),
                s.display,
                status
            )));
        }
        ReadyOutcome::Timeout => {
            let _ = s.child.kill();
            let _ = s.child.wait();
            if let Some(p) = s.probe.take() {
                p.join();
            }
            return Err(Error::Config(format!(
                "scenario {}: component `{}` did not bind its http listener within 5 s.",
                scenario_path.display(),
                s.display
            )));
        }
    }

    let outcome = if let Some(d) = active.duration {
        wait_with_duration(&mut s.child, d)
    } else {
        let status = s
            .child
            .wait()
            .map_err(|e| Error::Config(format!("waiting for {}: {}", s.display, e)))?;
        DurationOutcome::NaturalExit(status)
    };
    if let Some(p) = s.probe.take() {
        p.join();
    }
    Ok(match outcome {
        // Natural exit on its own → caller decides based on status.
        DurationOutcome::NaturalExit(s) => s,
        // Duration expired → component ran for as long as the
        // scenario asked. Treat as success regardless of the signal
        // we used to wind it down.
        DurationOutcome::DurationExpired => synthetic_success_exit_status(),
    })
}

/// Outcome of [`wait_with_duration`]. Distinguishes "child exited on
/// its own" (caller decides based on the status) from "we killed it
/// because its `duration:` expired" (sequential mode treats that as
/// success — the scenario specified that wall-clock budget).
enum DurationOutcome {
    NaturalExit(std::process::ExitStatus),
    DurationExpired,
}

fn synthetic_success_exit_status() -> std::process::ExitStatus {
    // Build a "exit 0" ExitStatus.  Unix-only; PR 3+4 spawn paths are
    // Linux/macOS only by construction.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
    #[cfg(not(unix))]
    {
        unimplemented!("scenario runner is unix-only");
    }
}

struct SpawnedActive {
    display: String,
    child: std::process::Child,
    probe: Option<scenario_readiness_probe::Probe>,
    port: Option<u16>,
    url: Option<String>,
}

fn spawn_one(
    linux_bin: &Path,
    active: &ActiveComponent,
    _scenario_path: &Path,
) -> Result<SpawnedActive> {
    let mut child = std::process::Command::new(linux_bin)
        .arg("--config")
        .arg(&active.config_bin)
        .arg("--modules")
        .arg(&active.modules_bin)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            Error::Config(format!(
                "spawning fluxor-linux for `{}`: {}",
                active.display, e
            ))
        })?;
    let stderr_pipe = child.stderr.take().ok_or_else(|| {
        Error::Config(format!(
            "`{}`: fluxor-linux has no stderr pipe",
            active.display
        ))
    })?;
    let probe = scenario_readiness_probe::Probe::start(stderr_pipe, active.port.unwrap_or(0));
    Ok(SpawnedActive {
        display: active.display.clone(),
        child,
        probe: Some(probe),
        port: active.port,
        url: active.url.clone(),
    })
}

fn race_probe(
    child: &mut std::process::Child,
    probe: &Option<scenario_readiness_probe::Probe>,
    port: Option<u16>,
    deadline: std::time::Duration,
) -> ReadyOutcome {
    let probe = probe.as_ref().expect("probe must exist while spawned");
    let start = std::time::Instant::now();
    // For headless components (no port) the probe never fires; we
    // grant a short startup grace period then declare "ready" if the
    // child is still alive.
    let headless_grace = std::time::Duration::from_millis(500);
    loop {
        if probe.ready() {
            return ReadyOutcome::Ready;
        }
        if let Some(status) = child.try_wait().ok().flatten() {
            return ReadyOutcome::ChildExited(status);
        }
        let elapsed = start.elapsed();
        if port.is_none() && elapsed >= headless_grace {
            return ReadyOutcome::Ready;
        }
        if elapsed >= deadline {
            return ReadyOutcome::Timeout;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Wait up to `duration` for the child to exit on its own. After
/// the deadline, SIGTERM; after another 2 s, SIGKILL. Returns
/// [`DurationOutcome::NaturalExit`] iff the child died on its own,
/// otherwise [`DurationOutcome::DurationExpired`].
fn wait_with_duration(
    child: &mut std::process::Child,
    duration: std::time::Duration,
) -> DurationOutcome {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if let Some(s) = child.try_wait().ok().flatten() {
            return DurationOutcome::NaturalExit(s);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Duration expired — wind the child down. SIGTERM, 2 s grace,
    // SIGKILL. We treat all of these as "duration expired", not
    // failure — the scenario asked for this wall-clock budget.
    let _ = child.kill();
    let grace = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < grace {
        if child.try_wait().ok().flatten().is_some() {
            return DurationOutcome::DurationExpired;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.wait();
    DurationOutcome::DurationExpired
}

fn wait_first_exit(spawned: &mut [SpawnedActive]) -> std::process::ExitStatus {
    loop {
        for s in spawned.iter_mut() {
            if let Some(status) = s.child.try_wait().ok().flatten() {
                return status;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn teardown_remaining(spawned: &mut [SpawnedActive]) {
    for s in spawned.iter_mut() {
        if s.child.try_wait().ok().flatten().is_none() {
            let _ = s.child.kill();
        }
    }
    // Grace period.
    std::thread::sleep(std::time::Duration::from_millis(500));
    for s in spawned.iter_mut() {
        let _ = s.child.wait();
    }
    for s in spawned.iter_mut() {
        if let Some(probe) = s.probe.take() {
            probe.join();
        }
    }
}

fn launch_browser(url: &str) {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    match std::process::Command::new(cmd).arg(url).spawn() {
        Ok(_) => eprintln!("[scenario]   --open: launched `{cmd}` on {url}"),
        Err(e) => eprintln!(
            "[scenario]   --open: WARNING failed to launch `{cmd}` ({e}); open {url} manually"
        ),
    }
}

/// Outcome of racing the readiness probe against the spawned
/// fluxor-linux's exit status.  Used by
/// [`spawn_single_component_scenario`].
enum ReadyOutcome {
    Ready,
    ChildExited(std::process::ExitStatus),
    Timeout,
}

/// Readiness-probe machinery for the scenario runner.  The probe
/// runs one thread:
///
///   - **stderr tee**: reads `fluxor-linux`'s stderr line-by-line,
///     forwards each line to our own stderr (so the user still sees
///     kernel logs in real time), and signals "ready" the first time
///     it sees `[linux_net] listening on port <PORT>`.
///
/// PR 3 deliberately drops the port-poll fallback referenced in RFC
/// §9 — TCP connect-success false-positives when another process
/// already holds the port (e.g. a stale `python3 -m http.server`
/// from a prior debugging session).  The kernel's
/// `linux_net::cmd_bind` log line is reliable, so the stderr signal
/// is sufficient on its own.  Re-introduce the fallback only if we
/// hit a runtime where stderr is muted by default.
mod scenario_readiness_probe {
    use std::io::{BufRead, BufReader, Read};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    pub struct Probe {
        ready: Arc<AtomicBool>,
        tee_handle: Option<std::thread::JoinHandle<()>>,
        stop: Arc<AtomicBool>,
    }

    impl Probe {
        pub fn start<R: Read + Send + 'static>(stderr: R, _port: u16) -> Self {
            let ready = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));

            let tee_ready = ready.clone();
            let tee_handle = std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    // Tee: forward to our own stderr so users see logs.
                    eprintln!("{line}");
                    if line.contains("[linux_net] listening on port") {
                        tee_ready.store(true, Ordering::Release);
                    }
                }
            });

            Self {
                ready,
                tee_handle: Some(tee_handle),
                stop,
            }
        }

        /// Block until the probe fires or `timeout` elapses.  Returns
        /// `true` iff the probe fired.  Kept for the non-racing case;
        /// the scenario runner usually polls [`ready`] in its own loop
        /// alongside `child.try_wait()` so a child crash short-circuits
        /// the 5 s wait.
        #[allow(
            dead_code,
            reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
        )]
        pub fn wait(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.ready.load(Ordering::Acquire) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            self.ready.load(Ordering::Acquire)
        }

        /// Non-blocking: has the probe signalled "ready"?
        pub fn ready(&self) -> bool {
            self.ready.load(Ordering::Acquire)
        }

        /// Tear down the probe.  The stderr tee thread terminates on
        /// EOF, which happens when fluxor-linux's stderr closes (i.e.
        /// when the child exits).
        pub fn join(mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(h) = self.tee_handle.take() {
                let _ = h.join();
            }
        }
    }
}

fn cmd_run(config_path: &PathBuf, verbose: bool) -> Result<()> {
    const QEMU_CONFIG_BLOB_ADDR: u64 = 0x4100_0000;
    const QEMU_MODULES_BLOB_ADDR: u64 = 0x4200_0000;

    let result = build_one(config_path, None, verbose)?;

    match result.family.as_str() {
        "linux" => {
            let out_dir = result.output_path.parent().unwrap();
            let config_bin = out_dir.join("config.bin");
            let modules_bin = out_dir.join("modules.bin");
            let linux_bin = PathBuf::from("target/aarch64-unknown-linux-gnu/release/fluxor-linux");

            if !linux_bin.exists() {
                return Err(Error::Config(format!(
                    "Linux binary not found at {}. Run 'make linux' first.",
                    linux_bin.display()
                )));
            }

            eprintln!(
                "Running: {} --config {} --modules {}",
                linux_bin.display(),
                config_bin.display(),
                modules_bin.display()
            );

            let status = std::process::Command::new(&linux_bin)
                .arg("--config")
                .arg(&config_bin)
                .arg("--modules")
                .arg(&modules_bin)
                .status()?;

            if !status.success() {
                return Err(Error::Config(format!(
                    "fluxor-linux exited with status {status}"
                )));
            }
        }
        "bcm" => {
            // Check if this is qemu-virt board
            let is_qemu = result
                .board_id
                .as_deref()
                .map(|b| b == "qemu-virt")
                .unwrap_or(false);

            if is_qemu {
                let elf_path = PathBuf::from("target/aarch64-unknown-none/release/fluxor");
                if !elf_path.exists() {
                    return Err(Error::Config(format!(
                        "Firmware ELF not found at {}. Run 'make firmware TARGET=bcm2712' first.",
                        elf_path.display()
                    )));
                }

                let out_dir = result.output_path.parent().unwrap();
                let config_blob = out_dir.join("config.bin");
                let modules_blob = out_dir.join("modules.bin");

                let (config, target_desc) = load_config_with_defaults(config_path, verbose)?;
                let modules_dir =
                    PathBuf::from(format!("target/fluxor/{}/modules", target_desc.id));
                if !modules_dir.exists() {
                    return Err(Error::Config(format!(
                        "Modules not found at {}. Run 'make modules TARGET={}' first.",
                        modules_dir.display(),
                        target_desc.id
                    )));
                }
                let (modules_data, config_data) = build_packaged_blobs(
                    &config,
                    modules_dir.as_path(),
                    &[],
                    &target_desc,
                    verbose,
                )?;
                let modules_data = modules_data.ok_or_else(|| {
                    Error::Config("QEMU bare-metal run requires at least one module blob".into())
                })?;
                std::fs::write(&config_blob, &config_data)?;
                std::fs::write(&modules_blob, &modules_data)?;

                // Extract HTTP port from config YAML for QEMU port forwarding
                let yaml_text = std::fs::read_to_string(config_path)?;
                let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_text)
                    .map_err(|e| Error::Config(format!("YAML parse: {e}")))?;
                let guest_port = yaml
                    .get("modules")
                    .and_then(|m| m.as_sequence())
                    .and_then(|mods| {
                        mods.iter()
                            .find(|m| m.get("name").and_then(|n| n.as_str()) == Some("http"))
                    })
                    .and_then(|http| http.get("port"))
                    .and_then(|p| p.as_u64())
                    .unwrap_or(80);
                let host_port = if guest_port < 1024 {
                    guest_port + 18000
                } else {
                    guest_port
                };
                let hostfwd = format!("user,id=net0,hostfwd=tcp::{host_port}-:{guest_port}");

                eprintln!(
                    "Running: qemu-system-aarch64 -kernel {}",
                    elf_path.display()
                );
                eprintln!("  Port forward: host {host_port} -> guest {guest_port}");
                eprintln!(
                    "  Side-load: config={} @ 0x{:08x}, modules={} @ 0x{:08x}",
                    config_blob.display(),
                    QEMU_CONFIG_BLOB_ADDR,
                    modules_blob.display(),
                    QEMU_MODULES_BLOB_ADDR
                );

                let mut qemu_args: Vec<&str> = vec![
                    "-machine",
                    "virt",
                    "-cpu",
                    "cortex-a76",
                    "-smp",
                    "1",
                    "-m",
                    "256M",
                    "-nographic",
                ];
                qemu_args.extend_from_slice(&[
                    "-device",
                    "virtio-net-device,netdev=net0,mac=52:54:00:12:34:56",
                ]);
                let hostfwd_ref: &str = &hostfwd;
                let config_loader = format!(
                    "loader,file={},addr=0x{:x},force-raw=on",
                    config_blob.display(),
                    QEMU_CONFIG_BLOB_ADDR
                );
                let modules_loader = format!(
                    "loader,file={},addr=0x{:x},force-raw=on",
                    modules_blob.display(),
                    QEMU_MODULES_BLOB_ADDR
                );
                qemu_args.extend_from_slice(&[
                    "-netdev",
                    hostfwd_ref,
                    "-device",
                    config_loader.as_str(),
                    "-device",
                    modules_loader.as_str(),
                    "-kernel",
                ]);

                let status = std::process::Command::new("qemu-system-aarch64")
                    .args(&qemu_args)
                    .arg(&elf_path)
                    .status()?;

                if !status.success() {
                    return Err(Error::Config(format!("QEMU exited with status {status}")));
                }
            } else {
                eprintln!("Use 'fluxor flash' for hardware targets");
                return Err(Error::Config(
                    "Cannot run BCM hardware targets directly. Use 'fluxor flash' instead.".into(),
                ));
            }
        }
        "rp2" => {
            eprintln!("Use 'fluxor flash' for hardware targets");
            return Err(Error::Config(
                "Cannot run RP targets directly. Use 'fluxor flash' instead.".into(),
            ));
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{}' for run",
                result.family
            )));
        }
    }

    Ok(())
}

fn cmd_flash(config_path: &Path, verbose: bool) -> Result<()> {
    let result = build_one(config_path, None, verbose)?;

    match result.family.as_str() {
        "rp2" => {
            // Look for mounted Pico in BOOTSEL mode
            let mut mount_point = None;
            if let Ok(entries) = std::fs::read_dir("/media") {
                for entry in entries.flatten() {
                    let user_dir = entry.path();
                    if user_dir.is_dir() {
                        if let Ok(sub_entries) = std::fs::read_dir(&user_dir) {
                            for sub in sub_entries.flatten() {
                                let p = sub.path();
                                if p.file_name().is_some_and(|n| n == "RPI-RP2") {
                                    mount_point = Some(p);
                                    break;
                                }
                            }
                        }
                    }
                    if mount_point.is_some() {
                        break;
                    }
                }
            }

            // Also check /run/media/ (some distros)
            if mount_point.is_none() {
                if let Ok(entries) = std::fs::read_dir("/run/media") {
                    for entry in entries.flatten() {
                        let user_dir = entry.path();
                        if user_dir.is_dir() {
                            if let Ok(sub_entries) = std::fs::read_dir(&user_dir) {
                                for sub in sub_entries.flatten() {
                                    let p = sub.path();
                                    if p.file_name().is_some_and(|n| n == "RPI-RP2") {
                                        mount_point = Some(p);
                                        break;
                                    }
                                }
                            }
                        }
                        if mount_point.is_some() {
                            break;
                        }
                    }
                }
            }

            if let Some(ref mp) = mount_point {
                let dest = mp.join(result.output_path.file_name().unwrap_or_default());
                eprintln!(
                    "Copying {} -> {}",
                    result.output_path.display(),
                    dest.display()
                );
                std::fs::copy(&result.output_path, &dest)?;
                println!(
                    "\x1b[1;32mFlashed\x1b[0m {}",
                    result
                        .output_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
            } else {
                // Try picotool as fallback
                let picotool = std::process::Command::new("picotool")
                    .args(["load", "-f"])
                    .arg(&result.output_path)
                    .status();

                match picotool {
                    Ok(status) if status.success() => {
                        println!(
                            "\x1b[1;32mFlashed\x1b[0m {} via picotool",
                            result
                                .output_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                        );
                    }
                    _ => {
                        return Err(Error::Config(
                            "No Pico found in BOOTSEL mode (checked /media/*/RPI-RP2/) and picotool not available. \
                             Hold BOOTSEL and plug in the Pico, then retry."
                                .into(),
                        ));
                    }
                }
            }
        }
        "bcm" => {
            let is_cm5 = result
                .board_id
                .as_deref()
                .map(|b| b == "cm5")
                .unwrap_or(false);

            if is_cm5 {
                let dest = PathBuf::from("/boot/firmware/kernel8.img");
                eprintln!(
                    "\x1b[1;33mWarning:\x1b[0m This will replace {}",
                    dest.display()
                );
                eprintln!(
                    "Copying {} -> {}",
                    result.output_path.display(),
                    dest.display()
                );
                std::fs::copy(&result.output_path, &dest)?;
                println!("\x1b[1;32mFlashed\x1b[0m kernel8.img — reboot to apply");
            } else {
                return Err(Error::Config(
                    "Only CM5 targets support flash. Use 'fluxor run' for QEMU targets.".into(),
                ));
            }
        }
        "linux" => {
            return Err(Error::Config(
                "Linux targets run directly. Use 'fluxor run' instead.".into(),
            ));
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{}' for flash",
                result.family
            )));
        }
    }

    Ok(())
}

/// Sign a packed .fmod module with an Ed25519 seed, appending a v2 manifest
/// carrying the signature + signer fingerprint. Writes either in place or to
/// `output`.
fn cmd_sign(
    input: &PathBuf,
    key_path: &PathBuf,
    output: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    use std::fs;

    let seed_bytes = fs::read(key_path)
        .map_err(|e| Error::Module(format!("read key {}: {}", key_path.display(), e)))?;
    if seed_bytes.len() != 32 {
        return Err(Error::Module(format!(
            "key must be exactly 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let fmod =
        fs::read(input).map_err(|e| Error::Module(format!("read {}: {}", input.display(), e)))?;
    use modules::MODULE_HEADER_SIZE;
    if fmod.len() < MODULE_HEADER_SIZE {
        return Err(Error::Module("fmod file too small".into()));
    }

    // Locate the manifest section from the module header.
    let code_size = u32::from_le_bytes([fmod[8], fmod[9], fmod[10], fmod[11]]) as usize;
    let data_size = u32::from_le_bytes([fmod[12], fmod[13], fmod[14], fmod[15]]) as usize;
    let export_count = u16::from_le_bytes([fmod[24], fmod[25]]) as usize;
    let export_table_size = export_count * 8;
    let schema_size = u16::from_le_bytes([fmod[62], fmod[63]]) as usize;
    let manifest_size = u16::from_le_bytes([fmod[64], fmod[65]]) as usize;

    let manifest_offset =
        MODULE_HEADER_SIZE + code_size + data_size + export_table_size + schema_size;
    if manifest_offset + manifest_size > fmod.len() {
        return Err(Error::Module("fmod truncated before manifest".into()));
    }

    let mut manifest =
        manifest::Manifest::from_bytes(&fmod[manifest_offset..manifest_offset + manifest_size])?;

    // Re-derive the integrity hash from the file (matches what the kernel
    // computes). Signature covers this hash.
    use sha2::Digest as _;
    let code_data = &fmod[MODULE_HEADER_SIZE..MODULE_HEADER_SIZE + code_size + data_size];
    let mut h = sha2::Sha256::new();
    h.update(code_data);
    let hh = h.finalize();
    let mut integrity_hash = [0u8; 32];
    integrity_hash.copy_from_slice(&hh);

    let (pk, sig) = crypto::sign(&seed, &integrity_hash);
    let signer_fp = crypto::sha256(&pk);
    if !crypto::verify(&pk, &integrity_hash, &sig) {
        return Err(Error::Module("internal: round-trip verify failed".into()));
    }

    manifest.integrity_hash = Some(integrity_hash);
    manifest.signature = Some(sig);
    manifest.signer_fp = Some(signer_fp);
    let new_manifest_bytes = manifest.to_bytes();
    let new_manifest_size = new_manifest_bytes.len();

    let mut out_bytes = Vec::with_capacity(manifest_offset + new_manifest_size);
    out_bytes.extend_from_slice(&fmod[..manifest_offset]);
    out_bytes.extend_from_slice(&new_manifest_bytes);

    let manifest_size_le = (new_manifest_size as u16).to_le_bytes();
    out_bytes[64] = manifest_size_le[0];
    out_bytes[65] = manifest_size_le[1];

    let out_path = output.unwrap_or(input.as_path());
    fs::write(out_path, &out_bytes)
        .map_err(|e| Error::Module(format!("write {}: {}", out_path.display(), e)))?;

    fn hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for &x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }

    if verbose {
        println!("Signed {} ({} bytes)", out_path.display(), out_bytes.len());
        println!("  pubkey:    {}", hex(&pk));
        println!("  signer_fp: {}", hex(&signer_fp));
    } else {
        let full = hex(&pk);
        println!(
            "\x1b[1;32mSigned\x1b[0m {} pubkey={}...{}",
            out_path.display(),
            &full[..8],
            &full[full.len() - 8..]
        );
    }

    Ok(())
}

/// `fluxor lint hygiene` — drive the AST scanner over a project root,
/// honour `fluxor.toml::[ci.hygiene]`, and surface every violation in
/// a single pass. Exit code is non-zero on any violation or stale
/// exemption row.
fn cmd_lint_hygiene(project_root_override: Option<&Path>, json: bool) -> Result<()> {
    let root = match project_root_override {
        Some(p) => p.to_path_buf(),
        None => crate::project::root(),
    };

    let config = hygiene::Config::load(&root)
        .map_err(|e| Error::Config(format!("loading fluxor.toml: {e}")))?;
    let report =
        hygiene::scan(&root, &config).map_err(|e| Error::Config(format!("scanning: {e}")))?;

    if json {
        let payload = serde_json::json!({
            "files_scanned": report.files_scanned,
            "mode": match config.mode {
                hygiene::Mode::Strict => "strict",
                hygiene::Mode::Permissive => "permissive",
            },
            "violations": report.violations.iter().map(|v| serde_json::json!({
                "path": v.path.to_string_lossy(),
                "line": v.line,
                "rule": v.rule.as_str(),
                "message": v.message,
            })).collect::<Vec<_>>(),
            "stale_exemptions": report.stale_exemptions.iter().map(|s| serde_json::json!({
                "path": s.path.to_string_lossy(),
                "rule": s.rule.as_str(),
                "reason": s.kind.as_str(),
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        if !report.ok() {
            std::process::exit(1);
        }
        return Ok(());
    }

    for v in &report.violations {
        eprintln!(
            "\x1b[1;31m{rule}\x1b[0m {path}:{line}: {message}",
            rule = v.rule.as_str(),
            path = v.path.display(),
            line = v.line,
            message = v.message,
        );
    }
    for s in &report.stale_exemptions {
        eprintln!(
            "\x1b[1;33mstale-exemption\x1b[0m {path} (rule={rule}): {reason}",
            path = s.path.display(),
            rule = s.rule.as_str(),
            reason = s.kind.as_str(),
        );
    }

    let n_v = report.violations.len();
    let n_s = report.stale_exemptions.len();
    if n_v == 0 && n_s == 0 {
        eprintln!(
            "\x1b[1;32mhygiene clean\x1b[0m ({} files scanned)",
            report.files_scanned,
        );
        return Ok(());
    }
    eprintln!(
        "\x1b[1;31mhygiene\x1b[0m {n_v} violation(s), {n_s} stale exemption(s) across {} files",
        report.files_scanned,
    );
    std::process::exit(1);
}

fn resolve_project_root(override_arg: Option<&Path>) -> PathBuf {
    override_arg
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::project::root)
}

/// `fluxor lint observability` — check the instrumentation contract across
/// every module manifest. Reports the gap list (data-moving modules with no
/// `[observability]`); fails only on malformed instrument names
/// (standards/observability.md §6, §9).
fn cmd_lint_observability(project_root_override: Option<&Path>, json: bool) -> Result<()> {
    let root = resolve_project_root(project_root_override);
    let report = fluxor_tools::observability::lint(&root.join("modules"));

    if json {
        let payload = serde_json::json!({
            "scanned": report.scanned,
            "instrumented": report.instrumented,
            "uninstrumented": report.uninstrumented,
            "exempt": report.exempt.iter()
                .map(|(m, r)| serde_json::json!({ "module": m, "reason": r }))
                .collect::<Vec<_>>(),
            "invalid_names": report.invalid_names.iter()
                .map(|(m, n)| serde_json::json!({ "module": m, "name": n }))
                .collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        if report.has_errors() {
            std::process::exit(1);
        }
        return Ok(());
    }

    for (m, n) in &report.invalid_names {
        eprintln!(
            "\x1b[1;31mobservability\x1b[0m {m}: invalid instrument name {n:?} \
             (instrument names are dotted lowercase)"
        );
    }
    for m in &report.uninstrumented {
        eprintln!(
            "\x1b[1;33mobservability\x1b[0m {m}: data-moving module declares no \
             `[observability]` metrics/spans and no `exempt` reason"
        );
    }
    eprintln!(
        "\x1b[1;32mobservability\x1b[0m {} scanned, {} instrumented, {} exempt, \
         {} uninstrumented, {} invalid",
        report.scanned,
        report.instrumented,
        report.exempt.len(),
        report.uninstrumented.len(),
        report.invalid_names.len(),
    );
    if report.has_errors() {
        std::process::exit(1);
    }
    Ok(())
}

/// `fluxor modules build` — drive the PIC / wasm module pipeline.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "CLI boolean flags map 1:1 to clap fields; collapsing them adds indirection without clarifying intent"
)]
fn cmd_modules_build(
    target: Option<String>,
    all: bool,
    out: &Path,
    strict: bool,
    lenient: bool,
    project_root: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };

    let selector = match (target, all) {
        (Some(t), false) => modules_build::TargetSelector::One(t),
        (None, true) => modules_build::TargetSelector::All,
        (None, false) => {
            return Err(Error::Module(
                "`fluxor modules build` requires `--target T` or `--all`".to_string(),
            ));
        }
        (Some(_), true) => {
            // clap's `conflicts_with` should catch this, but guard
            // anyway so the error surfaces as a Module error rather
            // than a clap panic.
            return Err(Error::Module(
                "`--target` and `--all` are mutually exclusive".to_string(),
            ));
        }
    };

    let opts = modules_build::BuildOpts {
        project_root,
        selector,
        out_root,
        // `--lenient` is the implicit default when neither flag is set.
        strict: strict && !lenient,
        verbose,
    };
    let report = modules_build::run(&opts)?;
    let mut had_failure = false;
    for tr in &report.per_target {
        println!(
            "Modules ({target}/{silicon}): built {} of {}, up-to-date {}, skipped {}, failed {}",
            tr.built.len(),
            tr.built.len() + tr.up_to_date.len() + tr.skipped.len() + tr.failed.len(),
            tr.up_to_date.len(),
            tr.skipped.len(),
            tr.failed.len(),
            target = tr.target,
            silicon = tr.silicon,
        );
        for (name, reason) in &tr.skipped {
            println!("  skipped: {name} — {reason}");
        }
        for (name, reason) in &tr.failed {
            eprintln!("  FAILED:  {name} — {reason}");
            had_failure = true;
        }
    }
    if had_failure {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_modules_clean(out: &Path) -> Result<()> {
    let project_root = crate::project::root();
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };
    let opts = modules_build::BuildOpts {
        project_root,
        selector: modules_build::TargetSelector::All,
        out_root,
        strict: false,
        verbose: false,
    };
    let removed = modules_build::clean(&opts)?;
    println!("modules clean: removed {removed} artefact file(s)");
    Ok(())
}

fn cmd_modules_list(project_root: Option<&Path>, json: bool) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let summaries = modules_build::list(&project_root)?;
    if json {
        let payload = serde_json::json!({
            "project_root": project_root.to_string_lossy(),
            "modules": summaries.iter().map(|s| serde_json::json!({
                "name": s.name,
                "entry": s.entry.to_string_lossy(),
                "manifest": s.manifest.to_string_lossy(),
                "hardware_targets": s.hardware_targets,
                "type_id": s.type_id,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return Ok(());
    }
    println!("Modules under {}:", project_root.display());
    for s in &summaries {
        let targets = if s.hardware_targets.is_empty() {
            "<all>".to_string()
        } else {
            s.hardware_targets.join(",")
        };
        println!(
            "  {name:24} type={type_id} targets={targets} entry={entry}",
            name = s.name,
            type_id = s.type_id,
            entry = s.entry.display(),
        );
    }
    println!("({} modules)", summaries.len());
    Ok(())
}

fn cmd_modules_resolve(target: &str, out: &Path) -> Result<()> {
    let project_root = crate::project::root();
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };
    let path = modules_build::resolve(&out_root, target);
    println!("{}", path.display());
    Ok(())
}

/// `fluxor ci` — orchestrate the full CI gate.
fn cmd_ci(skip: &[String], project_root: Option<&Path>, verbose: bool) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let skip_set = ci::SkipSet::from_strs(skip).map_err(Error::Config)?;
    let results = ci::run(&project_root, &skip_set, verbose)?;
    println!("{}", ci::format_summary(&results));
    if !ci::all_ok(&results) {
        std::process::exit(1);
    }
    Ok(())
}
