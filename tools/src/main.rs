//! Fluxor Config Tool
//!
//! Host-side tools for building and extracting Fluxor firmware configuration.
//!
//! Usage:
//!     fluxor build config.yaml --emit=uf2 -o config.uf2   # config UF2
//!     fluxor inspect firmware.uf2                         # UF2 info
//!     fluxor inspect firmware.uf2 --emit-config           # embedded config

#![allow(
    unsafe_code,
    reason = "host CLI wraps libc, mmap, ELF parsing, UF2 packing, and IPC primitives"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI is the user-facing product surface; `println!`/`eprintln!` is intentional output, not log misuse"
)]
//!     fluxor build config.yaml --emit=combined --firmware fw.uf2 -o out.uf2
//!     fluxor modules pack module.o -o module.fmod  # Pack ELF into .fmod

mod abi_pin;
mod add_subgraph;
mod agent_cli;
mod asset_bank;
mod board;
mod capacity;
mod ci;
mod config;
mod crypto;
mod error;
mod gpu_contract;
mod gpu_pack;
mod hash;
mod hygiene;
mod manifest;
mod modules;
mod modules_build;
mod monitor;
// `ci.rs` is shared between the lib and this bin; it refers to the
// observability lint as `crate::observability`. Re-export the lib's single
// copy here so the bin doesn't recompile the (mostly bin-dead) id-table
// generator that lives alongside the lint.
pub(crate) use fluxor_tools::observability;
// `config.rs` calls `crate::presentation_shell::validate`; re-export the
// lib's single copy (dependency-light, no bin-only refs) rather than
// `mod` it twice.
pub(crate) use fluxor_tools::presentation_shell;
// `ci.rs` runs the placement lint as `crate::presentation_resolver`; re-export
// the lib's copy for the bin (same pattern as observability/presentation_shell).
pub(crate) use fluxor_tools::presentation_resolver;
// Dual-context files (`ci.rs`, `modules_build.rs`) reach the lib-only
// store flow as `crate::store_resolve` / `crate::store_sync`; re-export
// the lib's single copies here so both compile contexts resolve them
// (same pattern as observability above).
pub(crate) use fluxor_tools::store_resolve;
pub(crate) use fluxor_tools::store_sync;
// `ci.rs` runs the `fluxor.toml` schema and Makefile-conformance
// phases as `crate::ci_schema` / `crate::makefile_lint`; both are
// lib-only (the schema phase reads the project shape through
// `lifecycle`), so re-export the lib's single copies.
pub(crate) use fluxor_tools::ci_schema;
pub(crate) use fluxor_tools::makefile_lint;
mod project;
pub mod reconfigure;
mod render_template;
pub mod rig;
mod scenario;
mod schema;
mod stack_expand;
mod store_cli;
pub mod target;
mod target_facts;
mod text_distance;
mod uf2;
mod up;
mod wasm_bundle;
mod workload_src;
mod workspace;

/// Wire-format constants — path-mounted from `modules/sdk/wire/wire.rs` so
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
#[path = "../../modules/sdk/wire/wire.rs"]
mod wire;

/// Canonical ABI wire-surface encoding (see `tools/src/lib.rs` mount).
#[path = "../../modules/sdk/abi_surface.rs"]
mod abi_surface;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use crate::config::{decode_config, generate_config_ext, ConfigBuilder, ModuleCaps};
use crate::error::{Error, Result};
use crate::modules::{build_module_table, pack_fmod, parse_modules_from_config_multi};
use crate::uf2::{create_uf2_blocks, fix_uf2_block_numbers, parse_uf2, UF2_FAMILY_RP2350};

/// Flash layout constants
const XIP_BASE: u32 = 0x10000000;

/// Trailer format (placed right after firmware, before modules/config)
const TRAILER_MAGIC: u32 = 0x544C5846; // "FXLT"
const TRAILER_VERSION: u8 = 1;

fn main() {
    // Busybox multi-call dispatch: invoked through a symlink whose basename
    // isn't `fluxor`, dispatch as `fluxor exec <basename> -- <args…>`
    // BEFORE clap sees argv (clap would try to parse argv[1] as a
    // subcommand). argv[0] and argv[1] are on different axes, so applet
    // names never shadow real subcommands.
    let argv0_stem = std::env::args_os()
        .next()
        .map(std::path::PathBuf::from)
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()));
    if let Some(stem) = argv0_stem {
        if stem != "fluxor" {
            let args: Vec<String> = std::env::args().skip(1).collect();
            match workload_src::exec_applet(&stem, &args, false) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("\x1b[1;31mError:\x1b[0m {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    let cli = Cli::parse();
    let verbose = cli.verbose;

    let result = match cli.command {
        Commands::Build {
            path,
            output,
            emit,
            check,
            firmware,
            modules_dir,
            target,
            epoch,
        } => cmd_build_dispatch(
            path.as_ref(),
            BuildFlags {
                output,
                emit,
                check,
                firmware,
                modules_dir,
                target,
                epoch,
            },
            verbose,
        ),
        Commands::Run {
            config,
            print_synthesised,
            print_merged,
            validate_only,
            graph,
            list,
            open,
            replicas,
            base_port,
            http_offset,
            vars,
        } => (|| {
            // `-` reads the config from stdin into a scratch file, so a
            // heredoc can feed `fluxor run` (and `--replicas` templates)
            // without a checked-in config.
            let config = match config {
                Some(p) if p.as_os_str() == "-" => Some(stdin_config()?),
                other => other,
            };
            match replicas {
                // `--replicas` = the old `up`: render the template per
                // replica and spawn them side-by-side.
                Some(n) => match config.as_ref() {
                    Some(template) => up::cmd_up(template, n, base_port, http_offset, &vars, None),
                    None => Err(Error::Config(
                        "run --replicas needs a template config argument".into(),
                    )),
                },
                None => cmd_run_dispatch(
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
            }
        })(),
        Commands::Exec { name, args } => workload_src::exec_applet(&name, &args, verbose),
        Commands::Applet { action } => match action {
            AppletAction::Logs { name, tail, all } => workload_src::applet_logs(&name, tail, all),
        },
        Commands::Install { bundle, name, link } => {
            workload_src::install_applet(&bundle, name.as_deref(), link.as_deref(), verbose)
        }
        Commands::Flash { config } => cmd_flash(&config, verbose),
        Commands::RenderTemplate {
            template,
            vars,
            output,
        } => render_template::cmd_render_template(&template, &vars, output.as_deref()),
        Commands::AbiRegen { check } => cmd_abi_regen(check),
        Commands::Agent(args) => agent_cli::dispatch(args),
        Commands::Rig(args) => rig::cli::dispatch(args),
        Commands::Inspect {
            subject,
            json,
            emit_config,
            format,
            against,
            target,
            store,
        } => cmd_inspect_dispatch(
            subject.as_deref(),
            InspectFlags {
                json,
                emit_config,
                format,
                against,
                target,
                store,
            },
        ),
        Commands::Lint {
            action,
            project_root,
        } => match action {
            None => lifted(fluxor_tools::lifecycle::lint(&resolve_project_root(
                project_root.as_deref(),
            ))),
            Some(LintAction::Hygiene { project_root, json }) => {
                cmd_lint_hygiene(project_root.as_deref(), json)
            }
            Some(LintAction::Observability {
                project_root,
                json,
                strict,
            }) => cmd_lint_observability(project_root.as_deref(), json, strict),
            Some(LintAction::Presentation { project_root }) => {
                cmd_lint_presentation(project_root.as_deref())
            }
        },
        Commands::Test { project_root } => lifted(fluxor_tools::lifecycle::test(
            &resolve_project_root(project_root.as_deref()),
            verbose,
        )),
        Commands::Clean { project_root } => lifted(fluxor_tools::lifecycle::clean(
            &resolve_project_root(project_root.as_deref()),
        )),
        Commands::Help {
            make,
            project_root,
            command,
        } => cmd_help(make, project_root.as_deref(), command.as_deref()),
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
            ModulesAction::Pack {
                input,
                output,
                name,
                module_type,
                manifest,
            } => cmd_pack(&input, &output, name, module_type, manifest, verbose),
            ModulesAction::Sign { input, key, output } => {
                cmd_sign(&input, &key, output.as_deref(), verbose)
            }
            ModulesAction::Keygen { key, force } => cmd_keygen(&key, force),
        },
        Commands::Gpu { action } => match action {
            GpuAction::Pack {
                artifact,
                output,
                entry,
                target,
                target_rev,
                toolchain,
                workgroup,
                min_align,
                bindings,
                budget_resident,
                budget_scratch,
            } => gpu_pack::cmd_pack(
                &artifact,
                &output,
                &entry,
                &target,
                target_rev,
                toolchain.as_deref(),
                &workgroup,
                min_align,
                &bindings,
                budget_resident,
                budget_scratch,
            ),
            GpuAction::Caps { provider, output } => gpu_pack::cmd_caps(&provider, &output),
            GpuAction::Inspect { pack, json } => gpu_pack::cmd_inspect(&pack, json),
            GpuAction::Validate { pack, caps } => gpu_pack::cmd_validate(&pack, &caps),
        },
        Commands::Publish {
            action,
            only,
            project_root,
        } => cmd_publish(action, &only, project_root.as_deref(), verbose),
        Commands::Update { project_root, from } => {
            let pr = project_root.unwrap_or_else(crate::project::root);
            store_resolve::cmd_update(&pr, from.as_deref())
                .map_err(|e| Error::Config(e.to_string()))
        }
        Commands::Sync {
            project_root,
            dry_run,
        } => cmd_sync(project_root.as_deref(), dry_run),
        Commands::Workspace { action } => match action {
            WorkspaceAction::Status { json } => workspace::cmd_workspace_status(json),
            WorkspaceAction::Publish { dry_run } => cmd_workspace_publish(dry_run),
            WorkspaceAction::Add { path } => workspace::cmd_workspace_add(&path),
            WorkspaceAction::Rm { path } => workspace::cmd_workspace_rm(&path),
        },
        Commands::Store(args) => store_cli::dispatch_store(args),
        Commands::IdTable {
            config,
            out,
            modules_dir,
        } => cmd_id_table(&config, out.as_deref(), &modules_dir),
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {e}");
        std::process::exit(1);
    }
}

/// The lib and the bin each carry their own `error::Error` (the bin
/// compiles `error.rs` a second time), so a lib-side lifecycle result
/// crosses into the bin's `Result` here rather than at six call sites.
/// Persist a config piped on stdin (`fluxor run -`) to a scratch
/// file and return its path. Pid-suffixed so parallel invocations
/// stay apart.
fn stdin_config() -> Result<PathBuf> {
    use std::io::Read as _;
    let mut yaml = String::new();
    std::io::stdin()
        .read_to_string(&mut yaml)
        .map_err(|e| Error::Config(format!("reading config from stdin: {e}")))?;
    if yaml.trim().is_empty() {
        return Err(Error::Config("stdin config is empty".into()));
    }
    let path = std::env::temp_dir().join(format!("fluxor-stdin-{}.yaml", std::process::id()));
    std::fs::write(&path, yaml)
        .map_err(|e| Error::Config(format!("writing stdin config {}: {e}", path.display())))?;
    Ok(path)
}

fn lifted(r: std::result::Result<(), fluxor_tools::error::Error>) -> Result<()> {
    r.map_err(|e| Error::Config(e.to_string()))
}

/// `fluxor publish` — the single store-write verb. The optional
/// subcommand (`abi|sdk|common|fmod|runtime`) and the `--only` flag
/// both narrow the artifact kinds; `publish bundle <dir>` publishes a
/// built workload bundle; bare `publish` sweeps everything
/// publishable (sources, built fmods, `[project].runtimes` binaries —
/// and, in the fluxor repo, the CLI itself).
fn cmd_publish(
    action: Option<PublishAction>,
    only: &[String],
    project_root: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    // clap can't express subcommand-vs-flag conflicts (`conflicts_with`
    // only names sibling args), so enforce it here.
    if action.is_some() && !only.is_empty() {
        return Err(Error::Config(
            "`--only` conflicts with a publish subcommand (the subcommand already names the kinds)"
                .into(),
        ));
    }
    if let Some(PublishAction::Bundle {
        bundle_dir,
        store,
        tag,
        published,
    }) = action
    {
        return store_cli::cmd_bundle_publish(
            &bundle_dir,
            store.as_deref(),
            tag.as_deref(),
            published,
        );
    }
    if let Some(PublishAction::Image {
        ref file,
        ref packed,
        ref name,
        ref target,
        ref tag,
        ref store,
    }) = action
    {
        return store_cli::cmd_device_artifact_publish(
            if *packed { "image-packed" } else { "image" },
            file,
            name.as_deref(),
            target,
            tag.as_deref(),
            store.as_deref(),
        );
    }
    if let Some(PublishAction::Firmware {
        ref file,
        ref name,
        ref target,
        ref tag,
        ref store,
    }) = action
    {
        return store_cli::cmd_device_artifact_publish(
            "firmware",
            file,
            name.as_deref(),
            target,
            tag.as_deref(),
            store.as_deref(),
        );
    }
    let (kinds, sub_root): (Vec<&str>, Option<PathBuf>) = match action {
        // abi/sdk/common all name the source tier — the store publisher
        // sweeps every source artifact the project owns.
        Some(
            PublishAction::Abi { project_root: r }
            | PublishAction::Sdk { project_root: r }
            | PublishAction::Common { project_root: r },
        ) => (vec!["source"], r),
        Some(PublishAction::Fmod { project_root: r }) => (vec!["fmod"], r),
        Some(PublishAction::Runtime { project_root: r }) => (vec!["runtime"], r),
        // Handled by the early returns above.
        Some(
            PublishAction::Bundle { .. }
            | PublishAction::Image { .. }
            | PublishAction::Firmware { .. },
        ) => {
            unreachable!("publish bundle/image/firmware handled above")
        }
        None => {
            let mut kinds = Vec::new();
            for o in only {
                kinds.push(match o.as_str() {
                    "abi" | "sdk" | "common" | "source" => "source",
                    "fmod" => "fmod",
                    "runtime" => "runtime",
                    other => {
                        return Err(Error::Config(format!(
                            "unknown --only kind '{other}' (expected source|fmod|runtime)"
                        )))
                    }
                });
            }
            kinds.dedup();
            (kinds, None)
        }
    };
    let pr = sub_root
        .or_else(|| project_root.map(Path::to_path_buf))
        .unwrap_or_else(crate::project::root);
    let tags = fluxor_tools::store_publish::publish_project_to_store(&pr, &kinds, verbose)
        .map_err(|e| Error::Config(e.to_string()))?;
    for tag in &tags {
        println!("{tag}");
    }
    println!("published {} tag(s)", tags.len());
    Ok(())
}

/// `fluxor sync` — store → tree via the uniform lockfile.
fn cmd_sync(project_root: Option<&Path>, dry_run: bool) -> Result<()> {
    let pr = project_root
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::project::root);
    let report =
        store_sync::sync_project(&pr, dry_run).map_err(|e| Error::Config(e.to_string()))?;
    for line in &report.materialized {
        println!("{line}");
    }
    if report.lockfile_written {
        println!(
            "wrote fluxor.lock ({} artifact(s) pinned)",
            report.entries.len()
        );
    } else {
        println!(
            "dry-run: {} artifact(s) resolved, lockfile untouched",
            report.entries.len()
        );
    }
    Ok(())
}

/// `fluxor workspace publish` — build + publish every workspace member
/// whose input digests differ from its published artifacts, in
/// dependency order.
fn cmd_workspace_publish(dry_run: bool) -> Result<()> {
    let outcomes =
        store_sync::workspace_publish(dry_run).map_err(|e| Error::Config(e.to_string()))?;
    for (name, outcome) in &outcomes {
        match outcome {
            fluxor_tools::store_sync::MemberOutcome::UpToDate => {
                println!("{name}: up to date");
            }
            fluxor_tools::store_sync::MemberOutcome::WouldPublish(dirty) => {
                println!("{name}: would publish ({})", dirty.join(", "));
            }
            fluxor_tools::store_sync::MemberOutcome::Published(tags) => {
                println!("{name}: published {} tag(s)", tags.len());
                for t in tags {
                    println!("  {t}");
                }
            }
        }
    }
    Ok(())
}

// ── CLI definitions + command impls, split for navigability ─────────────────
// Flat `include!` scope (repo SDK-file convention) — `mod` decls above and
// `fn main()` stay in the binary root; these files compile as if inlined here.
include!("cli/args.rs"); // Cli / Commands / *Action clap definitions
include!("cli/commands_a.rs"); // decode/info/generate/combine/image/pack
include!("cli/commands_b.rs"); // validate/target/inspect/diff/mktable
include!("cli/commands_c.rs"); // build/run/flash/sign/lint/modules/ci
