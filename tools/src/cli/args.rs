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
    ///             exclusively through `--emit=image`.
    ///   image     graph image (modules + config + header): the
    ///             packaged deployable graph — what an RP flash A/B
    ///             graph slot holds and what an OTA device pulls;
    ///             excludes firmware. The ONLY sanctioned
    ///             module-delivery path for OTA devices; its header
    ///             pins kernel and graph to each other by the
    ///             ABI-surface digest.
    ///   table     module table blob from the modules the config names
    Build {
        /// Config file (YAML) or directory containing YAML files.
        /// Omit for the lifecycle build.
        path: Option<PathBuf>,
        /// Output file (default: auto-derived from target; required
        /// for --emit=combined|image|table).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Emit a device encoding: uf2|bin|combined|image|table.
        #[arg(long)]
        emit: Option<String>,
        /// Validate the config against target constraints and exit
        /// without building anything.
        #[arg(long)]
        check: bool,
        /// --emit=combined: the firmware UF2 to combine with.
        #[arg(long)]
        firmware: Option<PathBuf>,
        /// Directory holding the `.fmod` modules to use, instead of the
        /// project's `target/fluxor/<silicon>/modules`. Falls back to
        /// `$FLUXOR_MODULE_ROOT`, then that default. A root given here
        /// or by the variable must be an existing directory containing
        /// at least one `.fmod`; it is never silently replaced.
        #[arg(long, value_name = "DIR")]
        module_root: Option<PathBuf>,
        /// Target override (--check / --emit=image; default: read from
        /// the config's `target:` field).
        #[arg(short, long)]
        target: Option<String>,
        /// --emit=image: epoch to embed in the image header. Must
        /// exceed the live image's epoch for activation to succeed.
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
    /// Scenario flags:
    ///   --print-synthesised      dump the synthesised host graph YAML
    ///                            and exit (no spawning).
    ///   --print-merged <comp>    dump the binding-augmented config
    ///                            for the named component and exit.
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
        /// Config file (YAML), or `-` to read the config from stdin
        /// (heredoc-friendly; works with `--replicas` templates too); a
        /// workload bundle (source manifest or bundle dir); or the name of
        /// a bundle `fluxor.lock` pins. Optional only when `--list` is
        /// given.
        config: Option<PathBuf>,
        /// Scenario only: dump the synthesised host graph YAML and exit.
        #[arg(long)]
        print_synthesised: bool,
        /// Scenario only: dump the binding-augmented config for the
        /// named component and exit.
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
        /// `HTTP_PORT`. Default 10000 matches the diagnostic-surface
        /// convention.
        #[arg(long, default_value = "10000")]
        http_offset: u16,
        /// Replica mode: extra `KEY=VALUE` placeholder substitutions,
        /// applied uniformly to every replica. Repeat for multiple.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Service bundle: one parameter value, typed by the bundle's
        /// declared schema. Repeatable; overrides `--params`.
        #[arg(long = "param", value_name = "NAME=VALUE")]
        params: Vec<String>,
        /// Service bundle: a values file — one flat TOML table of
        /// `name = value`, typed values checked against the schema.
        #[arg(long = "params", value_name = "FILE")]
        params_file: Option<PathBuf>,
        /// Append the certificates in this PEM file to the trust anchors
        /// of every CLIENT-MODE `tls` / `quic` instance for this run. A
        /// server instance is never widened, whether or not it verifies
        /// its clients. A linux graph or a bundle only — not a scenario
        /// and not `--replicas`; there is no environment-variable form.
        #[arg(long, value_name = "PEM")]
        ca: Option<PathBuf>,
        /// Directory holding the `.fmod` modules to use (graph, scenario or
        /// `--replicas` runs; every replica gets the same root), instead of the
        /// project's `target/fluxor/<silicon>/modules`. Falls back to
        /// `$FLUXOR_MODULE_ROOT`, then that default. A root given here
        /// or by the variable must be an existing directory containing
        /// at least one `.fmod`; it is never silently replaced.
        #[arg(long, value_name = "DIR")]
        module_root: Option<PathBuf>,
        /// Program argv, after `--`. Forwarded to the graph's `cli_in`
        /// exactly as `fluxor exec` forwards an applet's, so a graph that
        /// takes arguments can be run from its source as well as from an
        /// installed bundle. Linux graphs only: nothing else has an argv.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run an installed applet: resolve <NAME> through the applet catalogue
    /// (or the project's `target/fluxor/<NAME>/` bundle) and exec its
    /// cached bundle, passing everything after `--` to the app.
    Exec {
        /// Applet name.
        name: String,
        /// Append the certificates in this PEM file to the trust anchors
        /// of every CLIENT-MODE `tls` / `quic` instance for this run. A
        /// server instance is never widened. The cached bundle is not
        /// modified.
        #[arg(long, value_name = "PEM")]
        ca: Option<PathBuf>,
        /// App argv, after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Register an applet: map a name to a workload bundle. Accepts
    /// a store bundle reference (`<name>`, `<name>:<ver>`,
    /// `sha256:…` digest or unambiguous prefix — resolved from the
    /// local OCI store), a built bundle dir, or a source manifest
    /// (`app.fluxor.toml` — builds first).
    Install {
        /// Store bundle reference, bundle dir, or app.fluxor.toml.
        bundle: PathBuf,
        /// Applet name (default: the bundle's workload name).
        #[arg(long)]
        name: Option<String>,
        /// Also drop a busybox symlink `<DIR>/<name> -> fluxor` so the
        /// applet dispatches by argv[0].
        #[arg(long, value_name = "DIR")]
        link: Option<PathBuf>,
    },
    /// Installed applets: the runtime's log records from their runs.
    Applet {
        #[command(subcommand)]
        action: AppletAction,
    },
    /// Build and flash a config to hardware
    Flash {
        /// Config file (YAML)
        config: PathBuf,
        /// Directory holding the `.fmod` modules to use, instead of the
        /// project's `target/fluxor/<silicon>/modules`. Falls back to
        /// `$FLUXOR_MODULE_ROOT`, then that default. A root given here
        /// or by the variable must be an existing directory containing
        /// at least one `.fmod`; it is never silently replaced.
        #[arg(long, value_name = "DIR")]
        module_root: Option<PathBuf>,
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
    /// `rig monitor`, …). The contract is board-agnostic: a board declares
    /// which deploy, console, observe and power capabilities it offers, a
    /// scenario asks for the ones it needs, and backends on the discovery
    /// path supply them. Which board is attached and how it is reached is a
    /// rig profile, held outside the repository in
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

    /// Offline GPU program packs: build, inspect, validate.
    ///
    /// A pack is the only way an executable reaches a GPU provider, and a
    /// provider refuses one whose identity, target, bindings or requirements
    /// it cannot honour. These verbs move that refusal from load time on a
    /// device to build time on a host.
    Gpu {
        #[command(subcommand)]
        action: GpuAction,
    },

    /// Full CI gate. Phases run in this order, each only where the project
    /// has what it checks: fmt-check, clippy, workspace-lint-opt-in,
    /// hygiene, observability, presentation, makefile, fluxor-toml-schema,
    /// template-render, version-skew, lockfile-consistency, catalog-drift,
    /// sdk-materialisation, live-staleness, limit-register,
    /// abi-surface-pin, modules-build (strict), host-binary, cargo unit
    /// tests, wasm-host-shims (node), examples, service-bundles,
    /// kernel-link (rp), project-e2e, and the cargo integration tests.
    /// Every phase runs even when an earlier one fails; the summary lists
    /// every phase and the exit status is non-zero if any failed. A
    /// warning does not fail the run.
    ///
    /// Subprocess phases run against THIS `fluxor`, not whichever one is
    /// installed: their PATH begins with a directory whose `fluxor` is the
    /// running binary, and `$FLUXOR_BIN` names it. The modules and the
    /// host runtime `fluxor-linux` are built ahead of every test suite and
    /// e2e script (incrementally, so a no-op when current), so no test runs
    /// against an artefact built from another tree, and a failed build fails
    /// the run.
    Ci {
        /// Skip phases for local iteration (comma-separated or repeated):
        /// `cargo` (unit, integration, node, host-binary and project-e2e
        /// tests), `modules` (strict module build), `lint` (fmt-check,
        /// clippy, workspace-lint-opt-in, presentation, makefile, examples,
        /// service-bundles),
        /// `hygiene` (hygiene, observability), `templates`
        /// (template-render), `kernel` (kernel-link). Rejected when
        /// `$CI` is set, so production CI always runs the full set; a run
        /// with any skip does not record a green stamp.
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
        /// Project root override.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },

    /// Publish this project's artifacts into the local OCI store —
    /// the single store-write verb. Every artifact is annotated with
    /// its epoch (ABI-surface digest) and token-canonical input digest,
    /// and its provenance, source rev and ci digest are filed beside the
    /// manifest; tags and the project index repoint in one transactional
    /// index swap. Publishing writes what is built and never builds. In the fluxor repo, `runtime`
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
        /// Print the displacement report — which manifests this publish
        /// would move off their tags, and which checkouts on this
        /// machine still pin them — and write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Refuse the publish if it would displace a manifest another
        /// checkout pins. Their pins stay resolvable either way; this is
        /// for a release publish that wants no stale consumers at all.
        #[arg(long)]
        strict_pins: bool,
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
    /// `ls`, `rm`, `pin`, `snapshot`, `push`, `pull`, `adopt`, `fsck`,
    /// `gc`. Modules and workload bundles publish into it as OCI
    /// artifacts; consume paths read only from it (offline-first), and
    /// `push`/`pull` are the only verbs that touch the network.
    /// Read-only artifact display lives on `fluxor inspect <ref>`.
    Store(store_cli::StoreArgs),

    /// Export a graph's observability id-table as JSON: instrument names,
    /// per-instrument kinds / histogram bounds / dimension domains, and the
    /// table digest carried by the FXTL batch envelope. `fluxor-collect`
    /// loads this file to resolve id-interned telemetry records; a digest
    /// mismatch there refuses resolution rather than reporting wrong names.
    IdTable {
        /// Graph config YAML — module index = position in `modules:`.
        config: PathBuf,
        /// Output path (defaults to stdout).
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Extra module-tree roots to resolve types against, searched after
        /// the project's `modules/` (e.g. a sibling fluxor checkout's).
        #[arg(long)]
        modules_dir: Vec<PathBuf>,
    },

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
    /// Publish a built graph image (`fluxor build --emit=image`) as a
    /// device artifact: the packaged deployable graph a device pulls
    /// from a registry (`fluxor store push` serves it onward). Target,
    /// epoch and ABI pin are read from the FXSL header and mirrored as
    /// annotations for pre-fetch admission. By default the image is
    /// EXPLODED into layers (skeleton + one layer per fmod + config,
    /// offsets annotated) so registries deduplicate module content and
    /// devices fetch only what changed; `--packed` keeps the single
    ///-blob form (the RP flash-slot path's shape).
    Image {
        /// The graph image file.
        file: PathBuf,
        /// Publish as one packed blob instead of exploded layers.
        #[arg(long)]
        packed: bool,
        /// Artifact name (default: file stem).
        #[arg(long)]
        name: Option<String>,
        /// Target id annotation (e.g. pi5, rp2350).
        #[arg(long)]
        target: String,
        /// Tag (default: `<name>:latest`).
        #[arg(long)]
        tag: Option<String>,
        /// Store directory (default: $XDG_DATA_HOME/fluxor/store,
        /// override with $FLUXOR_STORE).
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Publish a boot image (e.g. Pi 5 `kernel_2712.img`) as a device
    /// artifact for staging hosts (TFTP root, SD writers) to pull.
    Firmware {
        /// The firmware image file.
        file: PathBuf,
        /// Artifact name (default: file stem).
        #[arg(long)]
        name: Option<String>,
        /// Target id annotation (e.g. pi5).
        #[arg(long)]
        target: String,
        /// Tag (default: `<name>:latest`).
        #[arg(long)]
        tag: Option<String>,
        /// Store directory (default: $XDG_DATA_HOME/fluxor/store,
        /// override with $FLUXOR_STORE).
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Publish a workload bundle into the local OCI store, under the
    /// project its tree belongs to. Takes a source manifest
    /// (`workload.toml`, emitted first) or a bundle directory. The bundle
    /// carries the `.fmod` bytes of every module `workload.json` pins.
    Bundle {
        /// Source manifest or bundle directory.
        bundle: PathBuf,
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

/// Offline GPU program packs (`modules/sdk/cores/gpu_pack.rs`).
///
/// Shares the device's own decoder, so a pack this accepts is a pack that
/// provider accepts — not one that passes a second implementation of the
/// same rules.
#[derive(Subcommand)]
enum GpuAction {
    /// Build a program pack from a compiled artifact and a manifest.
    ///
    /// The manifest is the point: the artifact bytes alone say nothing about
    /// which ISA they are, what bindings they expect, or what they cost. A
    /// provider refuses a pack whose declarations it cannot honour, and
    /// declaring them here is what makes that refusal a build-time answer.
    Pack {
        /// Compiled artifact — WGSL source, a SPIR-V module, a QPU pack.
        artifact: PathBuf,
        /// Output pack path.
        #[arg(short, long)]
        output: PathBuf,
        /// Entry-point name inside the artifact.
        #[arg(short, long, default_value = "main")]
        entry: String,
        /// Target ISA: wgsl|spirv|v3d|replay.
        #[arg(short, long, default_value = "wgsl")]
        target: String,
        /// Target revision the artifact was built for (e.g. 0x0701 for V3D
        /// 7.1). Zero means "any revision the device accepts".
        #[arg(long, default_value_t = 0)]
        target_rev: u32,
        /// Toolchain identity: 32 hex characters, or a version string to be
        /// hashed into one. Recorded so a pack can be traced to the compiler
        /// that produced it.
        #[arg(long)]
        toolchain: Option<String>,
        /// Workgroup shape, e.g. `64x1x1`.
        #[arg(long, default_value = "64x1x1")]
        workgroup: String,
        /// Alignment every bound view's offset must satisfy.
        #[arg(long, default_value_t = 64)]
        min_align: u32,
        /// A declared binding: `slot:kind:access:min_size:align`, where kind
        /// is storage|uniform|texture|sampler|vertex|index and access is
        /// r|w|rw. Repeat per binding.
        #[arg(short, long = "binding")]
        bindings: Vec<String>,
        /// Resident bytes the program needs.
        #[arg(long, default_value_t = 0)]
        budget_resident: u64,
        /// Scratch bytes the program needs.
        #[arg(long, default_value_t = 0)]
        budget_scratch: u64,
    },
    /// Print a pack's manifest: target, entry, bindings, budgets, and both
    /// digests — the artifact's content identity and the whole-manifest
    /// identity a pipeline cache is keyed on.
    Inspect {
        /// Pack to read.
        pack: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write a provider's capability record to a file.
    ///
    /// `validate` needs a device's published facts, and the replay
    /// provider is the one device every checkout has. For any other backend,
    /// capture the `OUT_CAPS` record it answers with.
    Caps {
        /// Provider whose facts to emit. Only `replay` can be stated without
        /// a device present.
        #[arg(long, default_value = "replay")]
        provider: String,
        /// Output path for the capability record.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Check a pack against a device's published capability record.
    ///
    /// `--caps` takes the 152 bytes a provider answers `QUERY_CAPS` with, so
    /// the check is against facts the device published rather than against a
    /// hand-written description of it that has gone stale.
    Validate {
        /// Pack to check.
        pack: PathBuf,
        /// File holding the device's capability record.
        #[arg(long)]
        caps: PathBuf,
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
pub enum AppletAction {
    /// The runtime's log records from an applet's latest run: what the
    /// kernel and platform said while the program ran. These records go to
    /// the runtime's own log store, never to the program's stderr, so the
    /// applet's output stays exactly what the applet itself wrote.
    Logs {
        /// Applet name.
        name: String,
        /// Lines from the end of each run; 0 for the whole run.
        #[arg(long, default_value = "50")]
        tail: usize,
        /// Every kept run, oldest first, rather than the latest.
        #[arg(long)]
        all: bool,
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
    /// Observability instrumentation-contract check: every data-moving module declares
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
    /// Presentation placement check: runs the placement resolver over every
    /// config's `presentation.shell` against the surface it targets, and fails
    /// on any `essential` control that cannot be surfaced there (no
    /// chrome/content plane and no `bind_physical`). Catches "this control is
    /// dead on this device" at build time.
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
        /// to `target/fluxor`. A consumer reads artefacts from another
        /// root through `--module-root <out>/<silicon>/modules` (or
        /// `$FLUXOR_MODULE_ROOT`).
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
    /// Inventory every module discovered under the tier directories —
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
    /// Print the module root for a target: `--module-root`, else
    /// `$FLUXOR_MODULE_ROOT`, else `<out>/<silicon>/modules` (the
    /// target's silicon, so a board resolves to its silicon's
    /// directory). Lets Makefiles and harness scripts refer to the
    /// artefact dir without hard-coding the layout.
    Resolve {
        /// Target whose modules directory to print (silicon, host or
        /// board).
        #[arg(long)]
        target: String,
        /// Output root the default location is under, matching
        /// `modules build --out`.
        #[arg(long, default_value = "target/fluxor")]
        out: PathBuf,
        /// Directory holding the `.fmod` modules to use, instead of the
        /// project's `target/fluxor/<silicon>/modules`. Falls back to
        /// `$FLUXOR_MODULE_ROOT`, then that default. A root given here
        /// or by the variable must be an existing directory containing
        /// at least one `.fmod`; it is never silently replaced.
        #[arg(long, value_name = "DIR")]
        module_root: Option<PathBuf>,
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
    /// Issue and check mesh capability chains, signed with `keygen` seeds.
    ///
    /// The codec and chain rules are the SDK's mesh capability contract, the
    /// same source every verifying module links. A key's public half (what
    /// `keygen` prints) is a root's verifiers' trust anchor.
    Cap {
        #[command(subcommand)]
        action: CapAction,
    },
}

/// `fluxor modules cap` actions. A time is unix seconds, `now`, `now+N` or
/// `now-N`; an object is 32 hex digits or a UUID; permissions are a comma
/// list of `read_state subscribe send_command configure admin delegate`; a
/// chain is its text form, `fxcap1.…`.
#[derive(Subcommand)]
enum CapAction {
    /// Grant permissions on an object. Prints the chain.
    Mint {
        /// The issuing key's seed.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// The object granted on: 32 hex digits or a UUID.
        #[arg(long, conflicts_with = "scope", required_unless_present = "scope")]
        object: Option<String>,
        /// A storage scope granted on instead: a key prefix ending `/`
        /// (`photos/`), as a store's `PRESENT` names it.
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        perms: String,
        #[arg(long)]
        not_before: String,
        #[arg(long)]
        not_after: String,
        /// The chain that authorises the issuing key; omitted for a root.
        #[arg(long)]
        chain: Option<String>,
    },
    /// Authorise another key to grant within the given permissions, which
    /// must include `delegate`. Prints the chain.
    Delegate {
        /// The issuing key's seed.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// The delegate's public key, 64 hex digits.
        #[arg(long)]
        to: String,
        #[arg(long)]
        perms: String,
        #[arg(long)]
        not_before: String,
        #[arg(long)]
        not_after: String,
        /// The chain that authorises the issuing key; omitted for a root.
        #[arg(long)]
        chain: Option<String>,
    },
    /// Verify a chain under a root for one operation, against this host's
    /// clock. Exits non-zero with the refusal on any failure.
    Verify {
        /// The root public key, 64 hex digits.
        #[arg(long)]
        root: String,
        #[arg(long)]
        object: String,
        #[arg(long)]
        perms: String,
        chain: String,
    },
    /// Print every link of a chain.
    Inspect { chain: String },
}
