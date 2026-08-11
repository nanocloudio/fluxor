#[derive(Parser)]
#[command(name = "fluxor")]
#[command(about = "Fluxor Config Tool - Build and extract configuration for Fluxor firmware")]
#[command(version)]
// `help` is a real subcommand here: it carries `--make`, which emits the
// canonical `make help` block for the checkout. It still forwards to
// clap's rendering for `fluxor help [COMMAND]`, so the built-in shape is
// preserved — only the owner changes.
#[command(disable_help_subcommand = true)]
struct Cli {
    /// Verbose mode - show detailed output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Source → artefacts, at two scopes: the whole project (no
    /// argument) or one named config (a path).
    ///
    /// With no argument this is **the lifecycle build**, what `make
    /// build` delegates to: stage `target/fluxor` when the tree mounts
    /// it, build the cargo tree, then build this project's PIC modules.
    ///
    /// With a config file or directory: build that config into its
    /// artefacts. `--check` validates against target constraints and
    /// writes nothing; `--emit` selects a specific device encoding.
    ///
    /// The two forms are the same stage at two scopes — the whole
    /// project, or one named config — and are told apart by the
    /// presence of the argument. Every flag below belongs to the
    /// config form.
    ///
    /// Emit forms (flash/deploy encodings — never store artifacts):
    ///   uf2       config UF2 for drag-drop flashing
    ///   bin       raw config binary
    ///   combined  firmware + config in one UF2. Dev-flash convenience
    ///             only: the trailer-embedded modules/config are NOT an
    ///             OTA path — OTA devices update runtime modules
    ///             exclusively through `--emit=slot`.
    ///   slot      OTA slot image (modules + config + slot header) for
    ///             a graph_slot A/B region; excludes firmware. The ONLY
    ///             sanctioned module-delivery path for OTA devices; the
    ///             slot header pins kernel and graph to each other by
    ///             the ABI-surface digest.
    ///   table     module table blob from the modules the config names
    Build {
        /// Config file (YAML) or directory containing YAML files.
        /// Omit for the lifecycle build.
        path: Option<PathBuf>,
        /// Output file (default: auto-derived from target; required
        /// for --emit=combined|slot|table).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Emit a device encoding: uf2|bin|combined|slot|table.
        #[arg(long)]
        emit: Option<String>,
        /// Validate the config against target constraints and exit
        /// without building anything.
        #[arg(long)]
        check: bool,
        /// --emit=combined: the firmware UF2 to combine with.
        #[arg(long)]
        firmware: Option<PathBuf>,
        /// Modules directory override (default:
        /// target/fluxor/{silicon}/modules). Single dir for uf2/bin;
        /// repeatable for --emit=table.
        #[arg(short = 'm', long = "modules-dir", action = clap::ArgAction::Append)]
        modules_dir: Vec<PathBuf>,
        /// Target override (--check / --emit=slot; default: read from
        /// the config's `target:` field).
        #[arg(short, long)]
        target: Option<String>,
        /// --emit=slot: epoch to embed in the slot header. Must exceed
        /// the currently live slot's epoch for activation to succeed.
        #[arg(long, default_value = "1")]
        epoch: u64,
    },
    /// Recompute and rewrite the ABI-surface pin in all checked-in sites
    /// (`abi_surface_srcpin.rs` src-hash + digest, the `tools/src/hash.rs`
    /// lock, and the harness lock). Run after any `modules/sdk` edit — it is
    /// the single writer, so the sites can never drift. `--check` verifies
    /// they are current (CI) and writes nothing.
    AbiRegen {
        /// Verify the pins are current and exit non-zero if stale; do not write.
        #[arg(long)]
        check: bool,
    },
    /// Build and run a config (Linux or QEMU targets), or run a
    /// deployment scenario (`kind: scenario`), or — with `--replicas`
    /// — render a `__KEY__` template N times and spawn N processes
    /// side-by-side (local multi-replica bring-up: Raft clusters,
    /// partition experiments, …).
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
    ///
    /// Replica mode: the template should use the conventional
    /// placeholder set __SELF_ID__, __LISTEN_PORT__ (base_port +
    /// self_id), __PEER<i>_PORT__ (base_port + i), __HTTP_PORT__
    /// (listen_port + http_offset); anything else via `--var`.
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
        /// Spawn N replicas from a `__KEY__` template config instead
        /// of running it once, tailing their stderr until Ctrl+C.
        #[arg(short = 'r', long)]
        replicas: Option<u8>,
        /// Replica mode: base wire (`peer_router.listen_port`) port.
        /// Replica i listens on `base_port + i`.
        #[arg(short = 'b', long, default_value = "9090")]
        base_port: u16,
        /// Replica mode: offset added to `LISTEN_PORT` to derive
        /// `HTTP_PORT`. Default 10000 matches the clustor
        /// diagnostic-surface convention.
        #[arg(long, default_value = "10000")]
        http_offset: u16,
        /// Replica mode: extra `KEY=VALUE` placeholder substitutions,
        /// applied uniformly to every replica. Repeat for multiple.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },
    /// Run an installed applet: resolve <NAME> through the applet
    /// catalogue (or the project's `target/fluxor/<NAME>/` bundle) and exec
    /// its cached bundle, passing everything after `--` to the app
    /// (rfc_cli_execution.md §5.1).
    Exec {
        /// Applet name.
        name: String,
        /// App argv, after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Register an applet: map a name to a workload bundle
    /// (rfc_cli_execution.md §5.2). Accepts a store bundle reference
    /// (`<name>`, `<name>:<ver>`, `sha256:…` digest or unambiguous
    /// prefix — resolved from the local OCI store), a built bundle
    /// dir, or a source manifest (`app.fluxor.toml` — builds first).
    Install {
        /// Store bundle reference, bundle dir, or app.fluxor.toml.
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
    /// Node-agent operations (reconcile/commit/publish plans)
    Agent(agent_cli::AgentArgs),
    /// Hardware-rig orchestration (`rig test --scenario …`, `rig power`,
    /// `rig monitor`, …) with a board-agnostic contract. See
    /// `.context/rfc_hardware_rig.md` for the model; scenarios live in
    /// `tests/hardware/`, rig profiles live outside the repo in
    /// `~/.config/fluxor/labs/<lab>/rigs/<rig>.toml`.
    #[command(subcommand_value_name = "RIG_SUBCOMMAND")]
    Rig(rig::cli::RigArgs),

    /// THE read-only verb, polymorphic over its subject:
    ///   (nothing)      project info — root (and how it was
    ///                  discovered), available targets, stacks, rig,
    ///                  scenarios. The diagnostic surface for "is
    ///                  fluxor pointed at the right tree?"
    ///   config.yaml    the above plus the resolved target, expanded
    ///                  stack modules, and module search paths
    ///   firmware.uf2   UF2 block/family/trailer info;
    ///                  `--emit-config` decodes and prints the
    ///                  embedded config
    ///   store ref      tag, `sha256:…` digest, or unambiguous digest
    ///                  prefix — shows kind, tags, epoch vs the
    ///                  current ABI surface, input digest, ci digest,
    ///                  provenance, source rev, and layers
    ///
    /// A subject naming an existing file wins over a store reference;
    /// `--store` forces the store interpretation. `--against OLD`
    /// shows the live-reconfigure transition plan from OLD to the
    /// subject config.
    Inspect {
        /// Config / UF2 path, store reference, or nothing (project
        /// info only).
        subject: Option<String>,
        /// Emit machine-readable JSON instead of the default
        /// human-friendly text. For project/config subjects the shape
        /// is stable v1: a top-level object with `project_root`,
        /// `install_root`, `targets`, `stacks`, `rig`, `scenarios`
        /// keys (plus `config` when a config subject is supplied).
        #[arg(long)]
        json: bool,
        /// UF2 subject: decode and print the embedded config instead
        /// of block info.
        #[arg(long)]
        emit_config: bool,
        /// Output format for --emit-config (yaml or json).
        #[arg(short, long, default_value = "yaml")]
        format: String,
        /// Config subject: old config to show the live-reconfigure
        /// transition plan against (old → subject).
        #[arg(long, value_name = "OLD_CONFIG")]
        against: Option<PathBuf>,
        /// Target override for --against (default: read from the
        /// subject config's `target:` field, fallback: pico2w).
        #[arg(short, long)]
        target: Option<String>,
        /// Force store-reference interpretation of <SUBJECT>.
        #[arg(long)]
        store: bool,
    },

    /// The source-tree lint suite — one rule per subcommand, or the
    /// lifecycle lint with no subcommand.
    ///
    /// With no subcommand this is **the lifecycle lint**, what `make
    /// lint` delegates to: `cargo fmt --all -- --check` and `cargo
    /// clippy … -D warnings` where a cargo tree exists, then `fluxor
    /// lint hygiene`. Those are the precise checks the gate runs, minus
    /// the ones that need a build — module fmt/clippy compile PIC
    /// sources per target and stay `fluxor ci` phases.
    Lint {
        #[command(subcommand)]
        action: Option<LintAction>,
        /// Project root override (lifecycle form).
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// The lifecycle test stage — what `make test` delegates to.
    ///
    /// Runs, for whichever of the three a project has: `fluxor modules
    /// test` (declared module harnesses), `cargo test` over the cargo
    /// tree, and the `[ci.test] scripts` globs through `fluxor ci`'s own
    /// project-e2e runner. Fails fast, unlike the gate.
    Test {
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// The lifecycle clean stage — what `make clean` delegates to.
    ///
    /// Removes this project's module artefacts, runs `cargo clean`
    /// where a cargo tree exists, and removes the generated module-test
    /// crates under `target/fluxor/moduletests`. The staged source
    /// trees under `target/fluxor/<name>/` are store-materialised, not
    /// build output, and survive.
    Clean {
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// Show CLI help, or — with `--make` — this checkout's `make help`
    /// block.
    ///
    /// `--make` emits lifecycle lines, the CLI commands that are
    /// deliberately not make targets, every script under `tools/` and
    /// `scripts/` (marked `(ci)` when `[ci.test] scripts` runs it), and
    /// the one-time setup line. A Makefile's `help:` recipe is
    /// `@fluxor help --make`, so the text cannot drift from the tree.
    Help {
        /// Emit the `make help` block for this project instead of CLI help.
        #[arg(long)]
        make: bool,
        /// Project root override (with `--make`).
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Show help for this subcommand instead of the top-level help.
        command: Option<String>,
    },

    /// PIC module build orchestration plus the module-artefact verbs
    /// (`pack`, `sign`, `keygen`) and the hermetic module-core test
    /// lane (`test`). In-process discovery + compile + pack pipeline;
    /// flags are documented per subcommand.
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },

    /// Full CI gate. Runs in order: fmt-check, clippy, workspace-lint
    /// opt-in audit, hygiene scan, observability + presentation lints,
    /// template render, version-skew check, lockfile consistency,
    /// live-staleness, cargo unit tests, modules build (strict), and
    /// cargo integration tests. Every phase runs even when an earlier
    /// one fails; the summary lists all failures and exits non-zero.
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

    /// Publish this project's artifacts into the local OCI store —
    /// the single store-write verb. Every artifact is annotated with
    /// its epoch (ABI-surface digest), token-canonical input digest,
    /// provenance, and source rev; tags and the project index repoint
    /// in one transactional index swap. In the fluxor repo, `runtime`
    /// includes the CLI itself (the launcher resolves it on the next
    /// invocation). `publish bundle` publishes a built workload
    /// bundle directory.
    Publish {
        #[command(subcommand)]
        action: Option<PublishAction>,
        /// Restrict the publish sweep to artifact kinds:
        /// `source` (aliases: abi, sdk, common), `fmod`, `runtime`.
        /// Repeat or comma-separate. Empty = everything publishable.
        /// Rejected alongside a subcommand (which already names the
        /// kinds).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Project root override. Defaults to the directory resolved
        /// by `fluxor inspect`.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// Advance `fluxor.lock` pins: resolve every declared
    /// `[dependencies]` project against the store's project indexes
    /// (`<dep>/meta:latest`) and rewrite the `[[artifact]]` pin set.
    /// The deliberate "take upstream's new state" verb — `sync` only
    /// re-resolves workspace members.
    Update {
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Set the pins from a store snapshot instead of the deps'
        /// latest published state: `--from snapshot/<name>` (the
        /// `snapshot/` prefix is optional).
        #[arg(long, value_name = "SNAPSHOT")]
        from: Option<String>,
    },

    /// Materialise `fluxor.lock` into the tree from the OCI store:
    /// fmods → `target/fluxor/<silicon>/modules/`, source trees →
    /// `target/fluxor/<name>/`, runtimes → `target/<triple>/release/`.
    /// Workspace members' pins re-resolve `:latest` (write-through);
    /// everyone else's pins replay verbatim. Digest- and
    /// epoch-verified; per-artifact staleness advisories warn and
    /// never block.
    Sync {
        #[arg(long)]
        project_root: Option<PathBuf>,
        /// Don't copy — list what would change.
        #[arg(long)]
        dry_run: bool,
    },

    /// Maintain the local OCI artifact store
    /// (`$XDG_DATA_HOME/fluxor/store`, override `$FLUXOR_STORE`):
    /// `ls`, `rm`, `pin`, `snapshot`. Modules and workload bundles
    /// publish into it as OCI artifacts with provenance annotations;
    /// consume paths read only from it (offline-first). Read-only
    /// artifact display lives on `fluxor inspect <ref>`.
    Store(store_cli::StoreArgs),

    /// Live-workspace policy surface (`~/.fluxor/workspace.toml`).
    ///
    /// Workspace membership is the whole live/pinned distinction:
    /// `sync` write-through-resolves `:latest` for members and
    /// replays pins for everyone else. `status` shows the state,
    /// `publish` republishes every dirty member in dependency order,
    /// `add`/`rm` edit the member list.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
}

#[derive(Subcommand)]
enum PublishAction {
    /// Publish source-tree artifacts (alias of `--only source`; in
    /// the fluxor repo that is `fluxor-abi` + `fluxor-contracts`).
    Abi {
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish source-tree artifacts (alias of `--only source`).
    Sdk {
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish source-tree artifacts (alias of `--only source`; in a
    /// sibling repo that is `<project>-common`).
    Common {
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish every built `.fmod` this project owns, across every
    /// built target shelf.
    Fmod {
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish the `[project].runtimes` binaries (plus, in the fluxor
    /// repo, the CLI itself) as runtime artifacts.
    Runtime {
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// Publish a workload bundle directory (workload.json +
    /// resources.json + graph.yaml) into the local OCI store. Every
    /// module digest the manifest pins must already be in the store.
    Bundle {
        /// Bundle directory.
        bundle_dir: PathBuf,
        /// Store directory (default: $XDG_DATA_HOME/fluxor/store,
        /// override with $FLUXOR_STORE).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Tag override (default: `<name>:<version>` from workload.json).
        #[arg(long)]
        tag: Option<String>,
        /// Annotate provenance=published instead of local-build.
        #[arg(long)]
        published: bool,
    },
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
    /// For every member whose input digests differ from its published
    /// artifacts, run its module build and publish it — topologically
    /// ordered by the members' `fluxor.toml` dependency declarations.
    /// Aborts at the first failed member; the published prefix stands.
    Publish {
        /// Report what would publish without building or publishing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a project checkout to the workspace member list (creates
    /// `~/.fluxor/workspace.toml` if absent).
    Add {
        /// Path to the project checkout.
        path: PathBuf,
    },
    /// Remove a project checkout from the workspace member list.
    Rm {
        /// Path to the project checkout.
        path: PathBuf,
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
        /// Single target to build (e.g. `bcm2712`, `rp2350`, `rp2040`, `wasm`).
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
    /// Inventory every module discovered under the standard's tier
    /// directories (standards/fluxor-modules.md §0.1) —
    /// `<tier>/<name>/manifest.toml`.
    ///
    /// A declaration-only manifest — a kernel-resident built-in, with
    /// no PIC artefact to build — is marked `entry=<builtin>` in the
    /// text output and carries `builtin: true` in `--json`.
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
    /// Pack an ELF object file into the `.fmod` module format.
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
        /// Generate with `fluxor modules keygen -k key.raw`.
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
    /// matching seed is what `fluxor modules sign` consumes. Idempotent:
    /// re-running with an existing key just re-prints its pubkey (use
    /// `--force` to rotate).
    Keygen {
        /// Path to the 32-byte Ed25519 seed (private key). Created if absent.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// Overwrite an existing key with a freshly-generated one (rotate).
        #[arg(long)]
        force: bool,
    },
    /// Unit-test modules' `include!`d cores on the host.
    ///
    /// A core is `no_std` source that is included, not linked, so `cargo test`
    /// cannot reach it. A module declares a harness in its manifest
    /// (`[test] harness = "tests/harness.rs"`) that mounts its cores exactly as
    /// the module does; this generates a disposable crate around that harness
    /// and runs it. Mounting cannot be derived — include order is load-bearing
    /// and some cores need a `SyscallTable` in scope — so the module owns the
    /// harness and fluxor owns the mechanical part.
    Test {
        /// Limit to one module.
        #[arg(long)]
        module: Option<String>,
        #[arg(long)]
        project_root: Option<std::path::PathBuf>,
        /// Show cargo's full output.
        #[arg(short, long)]
        verbose: bool,
    },
}
