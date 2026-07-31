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

mod abi_pin;
mod add_subgraph;
mod agent_cli;
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
mod store_cli;
mod sync;
pub mod target;
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

fn main() {
    // Busybox multi-call dispatch (rfc_cli_execution.md §5.3): invoked
    // through a symlink whose basename isn't `fluxor`, dispatch as
    // `fluxor exec <basename> -- <args…>` BEFORE clap sees argv (clap would
    // try to parse argv[1] as a subcommand). argv[0] and argv[1] are on
    // different axes, so applet names never shadow real subcommands.
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
        Commands::AbiRegen { check } => cmd_abi_regen(check),
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
        Commands::Exec { name, args } => workload_src::exec_applet(&name, &args, verbose),
        Commands::Install { bundle, name, link } => {
            workload_src::install_applet(&bundle, name.as_deref(), link.as_deref(), verbose)
        }
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
        Commands::Keygen { key, force } => cmd_keygen(&key, force),
        Commands::Monitor {
            port,
            baud,
            refresh_ms,
            net,
        } => cmd_monitor_dispatch(&port, baud, refresh_ms, net.as_deref()),
        Commands::Agent(args) => agent_cli::dispatch(args),
        Commands::Rig(args) => rig::cli::dispatch(args),
        Commands::Inspect { config, json } => cmd_inspect(config.as_deref(), json),
        Commands::Lint { action } => match action {
            LintAction::Hygiene { project_root, json } => {
                cmd_lint_hygiene(project_root.as_deref(), json)
            }
            LintAction::Observability {
                project_root,
                json,
                strict,
            } => cmd_lint_observability(project_root.as_deref(), json, strict),
            LintAction::Presentation { project_root } => {
                cmd_lint_presentation(project_root.as_deref())
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
            ModulesAction::Publish {
                store,
                target,
                module,
                tag,
                published,
                pin,
                project_root,
            } => store_cli::cmd_modules_publish(
                store.as_deref(),
                target.as_deref(),
                module.as_deref(),
                tag.as_deref(),
                published,
                pin,
                project_root.as_deref(),
            ),
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
        Commands::Store(args) => store_cli::dispatch_store(args),
        Commands::Bundle(args) => match args.command {
            store_cli::BundleCommand::Publish {
                bundle_dir,
                store,
                tag,
                published,
            } => store_cli::cmd_bundle_publish(
                &bundle_dir,
                store.as_deref(),
                tag.as_deref(),
                published,
            ),
        },
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {e}");
        std::process::exit(1);
    }
}

// ── CLI definitions + command impls, split for navigability ─────────────────
// Flat `include!` scope (repo SDK-file convention) — `mod` decls above and
// `fn main()` stay in the binary root; these files compile as if inlined here.
include!("cli/args.rs"); // Cli / Commands / *Action clap definitions
include!("cli/commands_a.rs"); // decode/info/generate/combine/slot/pack
include!("cli/commands_b.rs"); // validate/target/inspect/diff/mktable
include!("cli/commands_c.rs"); // build/run/flash/sign/lint/modules/ci
