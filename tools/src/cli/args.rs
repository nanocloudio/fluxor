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
    /// Combine firmware + config into single UF2.
    ///
    /// Dev-flash convenience only: the trailer-embedded modules/config
    /// this produces are NOT an OTA path. OTA-capable devices update
    /// runtime modules exclusively through `slot-image` (graph_slot A/B),
    /// keeping kernel and graph formally separate with independent
    /// rollback.
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
    ///
    /// This is the ONLY sanctioned module-delivery path for OTA-capable
    /// devices: the graph slot is the sole runtime-module source, the
    /// kernel image carries built-ins only, and the two are pinned to
    /// each other by the ABI-surface digest in the slot header. The
    /// `combine` trailer path is a dev-flash convenience, never an
    /// update path.
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
    /// Run an installed applet: resolve <NAME> through the applet
    /// registry (or the project's `target/fluxor/<NAME>/` bundle) and exec
    /// its cached bundle, passing everything after `--` to the app
    /// (rfc_cli_execution.md §5.1).
    Exec {
        /// Applet name.
        name: String,
        /// App argv, after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Register an applet: map a name to a cached workload bundle
    /// (rfc_cli_execution.md §5.2). Accepts a bundle dir or a source
    /// manifest (`app.fluxor.toml` — builds first).
    Install {
        /// Bundle dir, or app.fluxor.toml to build-and-install.
        bundle: PathBuf,
        /// Applet name (default: the bundle's workload name).
        #[arg(long)]
        name: Option<String>,
        /// Also drop a busybox symlink `<DIR>/<name> -> fluxor` so the
        /// applet dispatches by argv[0] (rfc_cli_execution.md §5.3).
        #[arg(long, value_name = "DIR")]
        link: Option<PathBuf>,
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
    /// Generate / inspect an Ed25519 module-signing keypair.
    ///
    /// Prints the 64-hex-char PUBLIC key to stdout (for the kernel's
    /// `FLUXOR_SIGNING_PUBKEY_HEX` build env) and ensures the 32-byte private
    /// seed exists at `--key` (generated 0600 from the OS RNG if absent). The
    /// matching seed is what `fluxor sign` consumes. Idempotent: re-running
    /// with an existing key just re-prints its pubkey (use `--force` to rotate).
    Keygen {
        /// Path to the 32-byte Ed25519 seed (private key). Created if absent.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// Overwrite an existing key with a freshly-generated one (rotate).
        #[arg(long)]
        force: bool,
    },
    /// Hardware-rig orchestration (`rig test --scenario …`, `rig power`, …).
    ///
    /// Host-side hardware-rig orchestration with a board-agnostic
    /// contract. See `.context/rfc_hardware_rig.md` for the model; scenarios
    /// live in `tests/hardware/`, rig profiles live outside the repo in
    /// `~/.config/fluxor/labs/<lab>/rigs/<rig>.toml`.
    /// Node-agent operations (reconcile/commit/publish plans)
    Agent(agent_cli::AgentArgs),
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
    /// opt-in audit, hygiene scan, observability + presentation lints,
    /// template render, version-skew check, cargo unit tests, modules
    /// build (strict), and cargo integration tests. Every phase runs even
    /// when an earlier one fails; the summary lists all failures and exits
    /// non-zero.
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

    /// Inspect and maintain the local OCI artifact store
    /// (`$XDG_DATA_HOME/fluxor/store`, override `$FLUXOR_STORE`).
    /// Modules and workload bundles publish into it as OCI artifacts
    /// with provenance annotations; consume paths read only from it
    /// (offline-first).
    Store(store_cli::StoreArgs),

    /// Workload-bundle operations against the local OCI store.
    Bundle(store_cli::BundleArgs),

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
        /// Enforcement mode (CI): treat any data-moving module that is neither
        /// instrumented nor `exempt` as a hard error, not just a warning. The
        /// `fluxor ci` observability phase runs with this on.
        #[arg(long)]
        strict: bool,
    },
    /// Presentation placement check (rfc_adaptive_presentation.md §9): runs the
    /// placement resolver over every config's `presentation.shell` against the
    /// surface it targets, and fails on any `essential` control that cannot be
    /// surfaced there (no chrome/content plane and no `bind_physical`). Catches
    /// "this control is dead on this device" at build time.
    Presentation {
        /// Project root override (defaults to the resolved project root).
        #[arg(long)]
        project_root: Option<PathBuf>,
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
    /// Publish built `.fmod`s into the local OCI artifact store as
    /// content-addressed artifacts tagged `<target>/<name>:<version>`,
    /// annotated `io.fluxor.provenance=local-build` (or `published`
    /// with --published) and `io.fluxor.source-rev=<git sha>`.
    Publish {
        /// Store directory (default: $XDG_DATA_HOME/fluxor/store,
        /// override with $FLUXOR_STORE).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Single silicon target (default: every built target).
        #[arg(long)]
        target: Option<String>,
        /// Single module (default: every owned module with a built fmod).
        #[arg(long)]
        module: Option<String>,
        /// Tag override (`name:version`); requires the selection to
        /// match exactly one (target, module) pair.
        #[arg(long)]
        tag: Option<String>,
        /// Annotate provenance=published instead of local-build.
        #[arg(long)]
        published: bool,
        /// Also record each published artifact as a `[[oci_module]]`
        /// digest pin in fluxor.lock (consume-side resolution, P2).
        #[arg(long)]
        pin: bool,
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
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
