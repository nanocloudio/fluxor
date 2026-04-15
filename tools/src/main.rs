//! Fluxor Config Tool
//!
//! Host-side tools for building and extracting Fluxor firmware configuration.
//!
//! Usage:
//!     fluxor decode firmware.uf2           # Decode config from UF2
//!     fluxor info firmware.uf2             # Show UF2 file info
//!     fluxor generate config.yaml -o config.uf2  # Generate config UF2
//!     fluxor combine firmware.uf2 config.yaml -o combined.uf2
//!     fluxor example blinky                # Show example config
//!     fluxor pack module.o -o module.fmod # Pack ELF into .fmod module

mod board;
mod config;
mod crypto;
mod error;
mod hash;
mod stack_expand;
mod manifest;
mod modules;
mod monitor;
pub mod reconfigure;
mod schema;
pub mod target;
mod uf2;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::config::{decode_config, generate_config_with_caps, ConfigBuilder, ModuleCaps, EXAMPLES};
use crate::error::{Error, Result};
use crate::monitor::cmd_monitor;
use crate::modules::{build_module_table, pack_fmod, parse_modules_from_config, parse_modules_from_config_multi};
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
        /// Override modules directory (default: target/{silicon}/modules)
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
    /// Combine firmware.bin + config + modules into a raw boot image
    PackImage {
        /// Firmware binary image
        firmware: PathBuf,
        /// Config file (YAML or JSON)
        config: PathBuf,
        /// Directory containing built .fmod files (repeatable)
        #[arg(short = 'm', long, action = clap::ArgAction::Append)]
        modules_dir: Vec<PathBuf>,
        /// Output packed image
        #[arg(short, long)]
        output: PathBuf,
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
    /// Build and run a config (Linux or QEMU targets)
    Run {
        /// Config file (YAML)
        config: PathBuf,
    },
    /// Build and flash a config to hardware
    Flash {
        /// Config file (YAML)
        config: PathBuf,
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
        Commands::PackImage {
            firmware,
            config,
            modules_dir,
            output,
        } => cmd_pack_image(&firmware, &config, &modules_dir, &output, verbose),
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
        Commands::MktableConfig { config, modules_dir, output } => {
            cmd_mktable_config(&config, &modules_dir, &output)
        }
        Commands::Diff { old_config, new_config, target } => cmd_diff(&old_config, &new_config, target.as_deref()),
        Commands::Build { path, output } => cmd_build(&path, output.as_deref(), verbose),
        Commands::Run { config } => cmd_run(&config, verbose),
        Commands::Flash { config } => cmd_flash(&config, verbose),
        Commands::Sign { input, key, output } => cmd_sign(&input, &key, output.as_deref(), verbose),
        Commands::Monitor { port, baud, refresh_ms } => cmd_monitor(&port, baud, refresh_ms),
    };

    if let Err(e) = result {
        eprintln!("\x1b[1;31mError:\x1b[0m {}", e);
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
            return Err(error::Error::Config("No config found at expected address".into()));
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
    let min_addr = *memory.keys().min().ok_or_else(|| error::Error::Config("Empty memory".into()))?;
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

fn cmd_info_fmod(file: &PathBuf) -> Result<()> {
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
    println!("  type: {} ({}), size: {} bytes", type_str, m.module_type, m.data.len());
    println!("  mailbox_safe: {}, in_place_writer: {}", m.mailbox_safe, m.in_place_writer);
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
    println!("Address range: 0x{:08x} - 0x{:08x}", min_addr, max_addr);
    println!("Segments: {}", segments.len());

    for (i, (start, end)) in segments.iter().enumerate() {
        let size = end - start + 1;
        println!("  [{}] 0x{:08x} - 0x{:08x} ({} bytes)", i, start, end, size);
    }

    // Check for trailer
    println!();
    if let Ok((trailer_addr, modules_addr, config_addr)) = find_trailer(&memory) {
        println!("Trailer: Present at 0x{:08x}", trailer_addr);
        if modules_addr != 0 {
            println!("  Modules: 0x{:08x}", modules_addr);
        } else {
            println!("  Modules: None");
        }
        println!("  Config:  0x{:08x}", config_addr);

        // Check config magic
        if let Some(header_data) = uf2::extract_region(&memory, config_addr, 4) {
            let magic = u32::from_le_bytes([header_data[0], header_data[1], header_data[2], header_data[3]]);
            if magic == config::MAGIC_CONFIG {
                println!("  Config magic: Valid (0x{:08x})", magic);
            } else {
                println!("  Config magic: Invalid (0x{:08x})", magic);
            }
        }

        // Parse and display module table
        if modules_addr != 0 {
            if let Some(table_header) = uf2::extract_region(&memory, modules_addr, modules::TABLE_HEADER_SIZE) {
                let table_magic = u32::from_le_bytes([table_header[0], table_header[1], table_header[2], table_header[3]]);
                if table_magic == modules::MODULE_TABLE_MAGIC {
                    let module_count = table_header[5] as usize;
                    println!("\nModules: {} embedded", module_count);

                    // Read entries
                    let entries_start = modules_addr + modules::TABLE_HEADER_SIZE as u32;
                    for i in 0..module_count {
                        let entry_addr = entries_start + (i as u32 * modules::ENTRY_SIZE as u32);
                        if let Some(entry) = uf2::extract_region(&memory, entry_addr, modules::ENTRY_SIZE) {
                            let name_hash = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                            let fmod_offset = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                            let fmod_size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
                            let mod_type = entry[12];

                            let fmod_addr = modules_addr + fmod_offset;
                            if let Some(fmod_header) = uf2::extract_region(&memory, fmod_addr, modules::MODULE_HEADER_SIZE) {
                                // Extract name from header (offset 28, 32 bytes)
                                let name_bytes = &fmod_header[28..60];
                                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
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

                                println!("\n  [{}] {} (hash=0x{:08x})", i, name, name_hash);
                                println!("      type: {} ({}), abi: v{}, size: {} bytes", type_str, mod_type, abi, fmod_size);

                                // Read manifest from fmod (ABI v2)
                                if abi >= 2 {
                                    let code_size = u32::from_le_bytes([fmod_header[8], fmod_header[9], fmod_header[10], fmod_header[11]]) as usize;
                                    let data_size = u32::from_le_bytes([fmod_header[12], fmod_header[13], fmod_header[14], fmod_header[15]]) as usize;
                                    let export_count = u16::from_le_bytes([fmod_header[24], fmod_header[25]]) as usize;
                                    let schema_size = u16::from_le_bytes([fmod_header[62], fmod_header[63]]) as usize;
                                    let manifest_size = u16::from_le_bytes([fmod_header[64], fmod_header[65]]) as usize;

                                    let manifest_offset = modules::MODULE_HEADER_SIZE + code_size + data_size + export_count * 8 + schema_size;
                                    let manifest_addr = fmod_addr + manifest_offset as u32;

                                    if manifest_size > 0 {
                                        if let Some(manifest_data) = uf2::extract_region(&memory, manifest_addr, manifest_size) {
                                            match manifest::Manifest::from_bytes(&manifest_data) {
                                                Ok(m) => println!("{}", m.display()),
                                                Err(e) => println!("      manifest: error: {}", e),
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
        let end = rest.find('}').ok_or_else(|| {
            crate::error::Error::Config("Unclosed ${} in config".to_string())
        })?;

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

        match std::env::var(var_name) {
            Ok(val) => out.push_str(&val),
            Err(_) => {
                if let Some(def) = default {
                    out.push_str(def);
                } else {
                    return Err(crate::error::Error::Config(format!(
                        "Environment variable '{}' is not set (referenced in config). \
                         Use ${{{}:-default}} to provide a fallback.",
                        var_name, var_name,
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

fn cmd_generate(config_path: &PathBuf, output: Option<&std::path::Path>, modules_dir_override: Option<&std::path::Path>, binary: bool) -> Result<()> {
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
    let target_desc = resolve_target(&config, None)?;
    let project_root = std::env::current_dir().unwrap_or_default();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let builder = ConfigBuilder::new();
    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config.get("hardware").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
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
    let modules_dir_default = format!("target/{}/modules", target_desc.id);
    let modules_dir = modules_dir_override.unwrap_or(std::path::Path::new(&modules_dir_default));

    // Derive extra module search path from the config file's directory.
    // If config is at /project/configs/foo.yaml, search /project/modules/ for manifests.
    let config_parent = config_path.parent().and_then(|p| p.parent());
    let extra_modules_dir = config_parent.map(|p| p.join("modules"));
    let extra_dirs: Vec<&std::path::Path> = extra_modules_dir.iter().map(|p| p.as_path()).collect();

    let binary_data = config::generate_config_ext(
        &config, &builder, &[], modules_dir, &extra_dirs,
        target_desc.max_pin + 1, target_desc.pio_count,
    )?;

    eprintln!("Config size: {} bytes", binary_data.len());
    eprintln!("Note: Use 'combine' command to create a complete UF2 with trailer");

    if let Some(output_path) = output {
        if binary {
            std::fs::write(output_path, &binary_data)?;
            println!("Wrote binary config to {}", output_path.display());
        } else {
            return Err(error::Error::Config(
                "Standalone config UF2 no longer supported. Use 'combine' command instead.".into()
            ));
        }
    } else {
        // Hex dump to stdout (relative offsets)
        for i in (0..binary_data.len()).step_by(16) {
            let end = (i + 16).min(binary_data.len());
            let hex: String = binary_data[i..end]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            println!("{:04x}: {}", i, hex);
        }
    }

    Ok(())
}

fn cmd_combine(firmware_path: &PathBuf, config_path: &PathBuf, output_path: &PathBuf, verbose: bool) -> Result<()> {
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
    let target_desc = resolve_target(&config, None)?;
    let project_root = std::env::current_dir().unwrap_or_default();
    let stack_added = stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    if verbose && !stack_added.is_empty() {
        eprintln!("Auto-added from platform: {}", stack_added.join(", "));
    }
    if verbose {
        eprintln!("Target: {}", target_desc.display_name());
    }

    // Detect aarch64 targets — they use raw binary output (no UF2).
    // Pi 5 VPU loads kernel as a raw binary to 0x80000.
    let is_aarch64 = target_desc.build.as_ref()
        .map(|b| b.rust_target.starts_with("aarch64"))
        .unwrap_or(false);
    const AARCH64_LOAD_BASE: u32 = 0x0008_0000;

    // Read firmware - keep as UF2 blocks to preserve non-contiguous sections like .end_block
    // Use the target's UF2 family ID so the correct chip accepts the image (e.g. RP2040 vs RP2350).
    let (firmware_data, firmware_max_addr) = if firmware_path.extension().is_some_and(|ext| ext == "bin") {
        let data = std::fs::read(firmware_path)?;
        if is_aarch64 {
            let end = AARCH64_LOAD_BASE + data.len() as u32;
            (data, end) // raw binary, not UF2
        } else {
            let end = XIP_BASE + data.len() as u32;
            let family_id = target_desc.build.as_ref().map(|b| b.uf2_family_id).unwrap_or(UF2_FAMILY_RP2350);
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
        eprintln!("Firmware: {} ends at 0x{:08x}", fmt, firmware_max_addr);
    }

    // Merge board hardware defaults for sections the YAML doesn't specify
    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config.get("hardware").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
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
        eprintln!("  \x1b[1;33mWARNING:\x1b[0m {}", warning);
    }
    if !validation.is_ok() {
        for err in &validation.errors {
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {}", err);
        }
        return Err(error::Error::Config("Config validation failed for target".into()));
    }

    // Parse modules first (needed for in_place_safe caps in config generation)
    let modules_dir_path = format!("target/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);
    let modules = parse_modules_from_config(&config, modules_dir)?;

    // Build module caps for buffer aliasing and manifest validation
    let caps: Vec<ModuleCaps> = modules.iter().map(|m| ModuleCaps {
        name: m.name.clone(),
        mailbox_safe: m.mailbox_safe,
        in_place_writer: m.in_place_writer,
        manifest: m.manifest.clone(),
    }).collect();

    // Generate config binary (with module capabilities for chain detection)
    let builder = ConfigBuilder::new();
    let config_data = generate_config_with_caps(&config, &builder, &caps, modules_dir, target_desc.max_pin + 1, target_desc.pio_count)?;

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
                "Combined image end ({:#010x}) overlaps reserved OTA/store region at {:#010x}. Reduce firmware/config size.",
                config_end, SLOT_A_ADDR
            )));
        }
    }

    if verbose {
        let base_str = if is_aarch64 { AARCH64_LOAD_BASE } else { XIP_BASE };
        eprintln!("Layout:");
        eprintln!("  Firmware:  0x{:08x} - 0x{:08x}", base_str, firmware_max_addr);
        eprintln!("  Trailer:   0x{:08x} (16 bytes)", trailer_addr);
        if let Some(ref mdata) = modules_data {
            eprintln!("  Modules:   0x{:08x} ({} bytes)", modules_addr, mdata.len());
        }
        eprintln!("  Config:    0x{:08x} ({} bytes)", config_addr, config_data.len());
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
                u32::from_le_bytes([firmware_data[28], firmware_data[29], firmware_data[30], firmware_data[31]])
            } else {
                UF2_FAMILY_RP2350
            }
        };

        let modules_uf2 = modules_data.as_ref().map(|mdata| {
            create_uf2_blocks(mdata, modules_addr, firmware_family_id)
        });
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
            output_path.file_name().unwrap_or_default().to_string_lossy(),
            firmware_size / 1024,
            modules_size / 1024,
            config_data.len() / 1024,
            combined.len() / 1024
        );
    }

    Ok(())
}

fn load_config_with_defaults(config_path: &PathBuf, verbose: bool) -> Result<(serde_json::Value, target::TargetDescriptor)> {
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
    let project_root = std::env::current_dir().unwrap_or_default();
    let stack_added = stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
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
        eprintln!("  \x1b[1;33mWARNING:\x1b[0m {}", warning);
    }
    if !validation.is_ok() {
        for err in &validation.errors {
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {}", err);
        }
        return Err(error::Error::Config("Config validation failed for target".into()));
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
    let config_data = generate_config_with_caps(
        config,
        &builder,
        &caps,
        modules_dir,
        target_desc.max_pin + 1,
        target_desc.pio_count,
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
    let project_root = std::env::current_dir().unwrap_or_default();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    if let Some(ref defaults) = target_desc.hardware_defaults {
        let hw = config.get("hardware").cloned().unwrap_or(serde_json::Value::Object(Default::default()));
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
            eprintln!("  \x1b[1;31mERROR:\x1b[0m {}", err);
        }
        return Err(error::Error::Config("Config validation failed for target".into()));
    }

    let modules_dir_path = format!("target/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);
    let (modules_data, config_data) =
        build_packaged_blobs(&config, modules_dir, &[], &target_desc, verbose)?;
    let modules_data = modules_data.ok_or_else(|| {
        error::Error::Config("Slot image requires at least one module".into())
    })?;

    // Lay out the slot: header | pad → 4KB | modules | pad → 256B | config.
    let modules_offset = ((HEADER_SIZE + MODULES_ALIGN - 1) / MODULES_ALIGN) * MODULES_ALIGN;
    let modules_end = modules_offset + modules_data.len();
    let config_offset = ((modules_end + SECTION_ALIGN - 1) / SECTION_ALIGN) * SECTION_ALIGN;
    let config_end = config_offset + config_data.len();
    if config_end > SLOT_SIZE {
        return Err(error::Error::Config(format!(
            "Slot image ({} bytes) exceeds slot size ({} bytes). Reduce modules/config.",
            config_end, SLOT_SIZE
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
            modules_offset, modules_data.len(),
            config_offset, config_data.len(),
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

fn cmd_pack_image(
    firmware_path: &PathBuf,
    config_path: &PathBuf,
    modules_dirs: &[PathBuf],
    output_path: &PathBuf,
    verbose: bool,
) -> Result<()> {
    const IMAGE_ALIGN: u32 = 256;
    const PACKAGE_HEADER_MAGIC: u32 = 0x4B505846; // "FXPK"
    const PACKAGE_HEADER_SIZE: usize = 16;

    let mut firmware = std::fs::read(firmware_path)?;
    if firmware.len() < PACKAGE_HEADER_SIZE {
        return Err(error::Error::Config("firmware image is too small to contain package header".into()));
    }

    let header_offset = firmware.len() - PACKAGE_HEADER_SIZE;
    let magic = u32::from_le_bytes(firmware[header_offset..header_offset + 4].try_into().unwrap());
    if magic != PACKAGE_HEADER_MAGIC {
        return Err(error::Error::Config(format!(
            "firmware image missing package header magic (got 0x{:08x})",
            magic
        )));
    }
    let runtime_end = u32::from_le_bytes(
        firmware[header_offset + 8..header_offset + 12]
            .try_into()
            .unwrap(),
    );
    let trailer_addr = (runtime_end + IMAGE_ALIGN - 1) & !(IMAGE_ALIGN - 1);

    let (config, target_desc) = load_config_with_defaults(config_path, verbose)?;
    let primary_dir = if modules_dirs.is_empty() {
        let p = format!("target/{}/modules", target_desc.id);
        std::path::PathBuf::from(p)
    } else {
        modules_dirs[0].clone()
    };
    let extra_dirs: Vec<&std::path::Path> = modules_dirs.iter().skip(1).map(|p| p.as_path()).collect();
    let (modules_data, config_data) =
        build_packaged_blobs(&config, primary_dir.as_path(), &extra_dirs, &target_desc, verbose)?;

    // Module table must be page-aligned (4096) because aarch64 PIC modules use
    // ADRP for PC-relative rodata access. The table packing aligns code within
    // the blob relative to offset 0, so the blob base must be page-aligned.
    const MODULE_TABLE_ALIGN: u32 = 4096;
    let modules_addr = if modules_data.is_some() {
        (trailer_addr + IMAGE_ALIGN + MODULE_TABLE_ALIGN - 1) & !(MODULE_TABLE_ALIGN - 1)
    } else {
        0
    };
    let config_addr = if let Some(ref mdata) = modules_data {
        let after_modules = modules_addr + mdata.len() as u32;
        (after_modules + IMAGE_ALIGN - 1) & !(IMAGE_ALIGN - 1)
    } else {
        trailer_addr + IMAGE_ALIGN
    };

    // Compute CRC-16/XMODEM over the payload (modules + config) for integrity check
    let payload_crc: u16 = 0; // reserved

    let mut trailer = Vec::with_capacity(16);
    trailer.extend_from_slice(&TRAILER_MAGIC.to_le_bytes());
    trailer.push(TRAILER_VERSION);
    trailer.push(0);
    trailer.extend_from_slice(&payload_crc.to_le_bytes()); // CRC-16 of payload
    trailer.extend_from_slice(&modules_addr.to_le_bytes());
    trailer.extend_from_slice(&config_addr.to_le_bytes());

    let mut package = Vec::new();
    package.extend_from_slice(&trailer);
    // Pad to reach modules_addr (or config_addr if no modules)
    if let Some(ref mdata) = modules_data {
        let target_offset = (modules_addr - trailer_addr) as usize;
        while package.len() < target_offset {
            package.push(0);
        }
        package.extend_from_slice(mdata);
        // Pad to config alignment
        let target_config = (config_addr - trailer_addr) as usize;
        while package.len() < target_config {
            package.push(0);
        }
    } else {
        while package.len() < IMAGE_ALIGN as usize {
            package.push(0);
        }
    }
    package.extend_from_slice(&config_data);

    let runtime_base = trailer_addr;
    let package_size = package.len() as u32;
    firmware[header_offset + 8..header_offset + 12].copy_from_slice(&runtime_base.to_le_bytes());
    firmware[header_offset + 12..header_offset + 16].copy_from_slice(&package_size.to_le_bytes());

    let firmware_size = firmware.len();
    let mut image = firmware;
    image.extend_from_slice(&package);

    if verbose {
        eprintln!("Layout:");
        eprintln!("  Runtime:   0x{:08x}", runtime_base);
        eprintln!("  Trailer:   0x{:08x} (16 bytes)", trailer_addr);
        if let Some(ref mdata) = modules_data {
            eprintln!("  Modules:   0x{:08x} ({} bytes)", modules_addr, mdata.len());
        }
        eprintln!("  Config:    0x{:08x} ({} bytes)", config_addr, config_data.len());
    }

    std::fs::write(output_path, &image)?;

    if verbose {
        println!(
            "\x1b[1;32mSuccess:\x1b[0m Wrote {} ({} bytes)",
            output_path.display(),
            image.len()
        );
    } else {
        let modules_size = modules_data.as_ref().map(|m| m.len()).unwrap_or(0);
        println!(
            "\x1b[1;32mSuccess\x1b[0m {} fw={}K mod={}K cfg={}K total={}K",
            output_path.file_name().unwrap_or_default().to_string_lossy(),
            firmware_size / 1024,
            modules_size / 1024,
            config_data.len() / 1024,
            image.len() / 1024
        );
    }

    Ok(())
}

fn cmd_example(name: &str) -> Result<()> {
    if let Some(example) = EXAMPLES.get(name) {
        println!("{}", serde_json::to_string_pretty(example)?);
        Ok(())
    } else {
        let available: Vec<_> = EXAMPLES.keys().copied().collect();
        println!("Available examples: {}", available.join(", "));
        Err(error::Error::Config(format!("Unknown example: {}", name)))
    }
}

fn cmd_pack(
    input: &PathBuf,
    output: &PathBuf,
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
    let result = pack_fmod(input, output, &module_name, module_type, manifest_path)?;

    if verbose {
        println!("\x1b[1;32mPacked module:\x1b[0m {}", output.display());
        println!("  Name: {}", result.name);
        println!("  Code size: {} bytes", result.code_size);
        println!("  Data size: {} bytes", result.data_size);
        println!("  BSS size: {} bytes", result.bss_size);
        println!("  Init offset: 0x{:x}", result.init_offset);
        println!("  Exports: {}", result.exports.len());
        for (name, offset, hash) in &result.exports {
            println!("    {}: 0x{:x} (hash: 0x{:08x})", name, offset, hash);
        }
        println!("  Total size: {} bytes", result.total_size);
    } else {
        // Concise single-line output: name code+data+bss=total
        println!(
            "\x1b[1;32mSuccess\x1b[0m {} {}+{}+{}={} bytes",
            result.name,
            result.code_size,
            result.data_size,
            result.bss_size,
            result.total_size
        );
    }

    Ok(())
}

/// Resolve target from CLI override or config YAML `target:` field.
fn resolve_target(config: &serde_json::Value, cli_override: Option<&str>) -> Result<target::TargetDescriptor> {
    let name = cli_override
        .or_else(|| config.get("target").and_then(|t| t.as_str()))
        .unwrap_or("pico2w");
    let root = std::env::current_dir()?;
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
    let project_root = std::env::current_dir().unwrap_or_default();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    println!(
        "Validating {} against target '{}'...",
        config_path.display(),
        target_desc.display_name()
    );

    let result = board::validate_config(&config, &target_desc)?;

    // Print warnings (yellow)
    for warning in &result.warnings {
        println!("  \x1b[1;33mWARNING:\x1b[0m {}", warning);
    }

    // Print errors (red)
    for error in &result.errors {
        println!("  \x1b[1;31mERROR:\x1b[0m {}", error);
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
    let root = std::env::current_dir()?;
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
                    "Unknown field '{}'. Available: rust_target, cargo_features, uf2_family_id, \
                     module_target, max_pin, family, id, pio_count, spi_count, i2c_count, dma_channels",
                    field
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
    let root = std::env::current_dir()?;
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
                println!("  {:20} (error loading)", name);
            }
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

fn cmd_mktable_config(config_path: &PathBuf, modules_dirs: &[PathBuf], output: &PathBuf) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let primary_dir = if modules_dirs.is_empty() {
        return Err(Error::Module("--modules-dir is required".into()));
    } else {
        &modules_dirs[0]
    };
    let extra_dirs: Vec<&std::path::Path> = modules_dirs.iter().skip(1).map(|p| p.as_path()).collect();
    let modules = parse_modules_from_config_multi(&config, primary_dir, &extra_dirs)?;
    if modules.is_empty() {
        return Err(Error::Module("No modules referenced in config".into()));
    }

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
    let modules_dir_path = format!("target/{}/modules", target_desc.id);
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
/// e.g. `examples/pico2w/blinky.yaml` -> "pico2w", otherwise empty string.
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
    let content = match substitute_env_vars(&std::fs::read_to_string(yaml_path)?) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };
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
    let project_root = std::env::current_dir().unwrap_or_default();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    let family = target_desc.family.clone();
    let silicon_id = target_desc.id.clone();
    let board_id = target_desc.board_id.clone();

    // Derive output path
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
                let mut p = PathBuf::from(format!("target/{}/uf2", silicon_id));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{}.uf2", name));
                p
            }
            "bcm" => {
                let mut p = PathBuf::from(format!("target/{}/images", silicon_id));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{}.img", name));
                p
            }
            "linux" => {
                let mut p = PathBuf::from(format!("target/linux/{}", name));
                // Linux produces two files; the "output_path" is the directory
                p.push("config.bin");
                p
            }
            _ => {
                return Err(Error::Config(format!(
                    "Unsupported target family '{}' for build",
                    family
                )));
            }
        }
    };

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match family.as_str() {
        "rp2" => {
            // RP family: combine firmware + config + modules -> UF2
            let firmware_path = PathBuf::from(format!("target/{}/firmware.bin", silicon_id));
            if !firmware_path.exists() {
                return Err(Error::Config(format!(
                    "Firmware not found at {}. Run 'make firmware' first.",
                    firmware_path.display()
                )));
            }
            let modules_dir = PathBuf::from(format!("target/{}/modules", silicon_id));
            if !modules_dir.exists() {
                return Err(Error::Config(format!(
                    "Modules not found at {}. Run 'make modules' first.",
                    modules_dir.display()
                )));
            }
            cmd_combine(&firmware_path, &yaml_path.to_path_buf(), &output_path, verbose)?;
        }
        "bcm" => {
            // BCM family: pack-image firmware + config + modules -> img
            let firmware_path = PathBuf::from(format!("target/{}/firmware.bin", silicon_id));
            if !firmware_path.exists() {
                return Err(Error::Config(format!(
                    "Firmware not found at {}. Run 'make firmware' first.",
                    firmware_path.display()
                )));
            }
            let modules_dir = PathBuf::from(format!("target/{}/modules", silicon_id));
            if !modules_dir.exists() {
                return Err(Error::Config(format!(
                    "Modules not found at {}. Run 'make modules' first.",
                    modules_dir.display()
                )));
            }
            cmd_pack_image(
                &firmware_path,
                &yaml_path.to_path_buf(),
                &[modules_dir],
                &output_path,
                verbose,
            )?;
        }
        "linux" => {
            // Linux: generate config.bin + modules.bin in output directory
            let out_dir = output_path
                .parent()
                .unwrap_or(std::path::Path::new("target/linux"));
            std::fs::create_dir_all(out_dir)?;

            let config_bin_path = out_dir.join("config.bin");
            let modules_bin_path = out_dir.join("modules.bin");

            // Use bcm2712 modules for linux (aarch64 compatible).
            // Search both the standard path and config-relative path.
            let modules_dir = PathBuf::from("target/bcm2712/modules");
            let mut fmod_dirs: Vec<PathBuf> = Vec::new();
            if modules_dir.exists() {
                fmod_dirs.push(modules_dir.clone());
            }
            // Also search relative to the config file's project root
            // (e.g., config at /project/configs/foo.yaml → /project/deps/fluxor/target/bcm2712/modules/)
            if let Some(config_parent) = yaml_path.parent().and_then(|p| p.parent()) {
                let ext_modules = config_parent.join("deps/fluxor/target/bcm2712/modules");
                if ext_modules.exists() {
                    fmod_dirs.push(ext_modules);
                }
            }
            if fmod_dirs.is_empty() {
                return Err(Error::Config(
                    "Modules not found. Run 'make modules TARGET=bcm2712' first.".into()
                ));
            }

            // Generate modules.bin (mktable-config)
            cmd_mktable_config(
                &yaml_path.to_path_buf(),
                &fmod_dirs,
                &modules_bin_path,
            )?;

            // Generate config.bin (binary config)
            cmd_generate(
                &yaml_path.to_path_buf(),
                Some(config_bin_path.as_path()),
                Some(modules_dir.as_path()),
                true,
            )?;
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{}' for build",
                family
            )));
        }
    }

    Ok(BuildResult {
        output_path,
        family,
        board_id,
    })
}

fn cmd_build(path: &PathBuf, output: Option<&std::path::Path>, verbose: bool) -> Result<()> {
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
                    eprintln!(
                        "\x1b[1;33mWarn:\x1b[0m {} -- {}",
                        yaml.display(),
                        e
                    );
                    failed += 1;
                }
            }
        }

        println!(
            "\nBuilt {}/{} configs ({} failed)",
            built, total, failed
        );
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
            } else if p.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
                out.push(p);
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
                    "fluxor-linux exited with status {}",
                    status
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
                let modules_dir = PathBuf::from(format!("target/{}/modules", target_desc.id));
                if !modules_dir.exists() {
                    return Err(Error::Config(format!(
                        "Modules not found at {}. Run 'make modules TARGET={}' first.",
                        modules_dir.display(),
                        target_desc.id
                    )));
                }
                let (modules_data, config_data) =
                    build_packaged_blobs(&config, modules_dir.as_path(), &[], &target_desc, verbose)?;
                let modules_data = modules_data.ok_or_else(|| {
                    Error::Config("QEMU bare-metal run requires at least one module blob".into())
                })?;
                std::fs::write(&config_blob, &config_data)?;
                std::fs::write(&modules_blob, &modules_data)?;

                // Extract HTTP port from config YAML for QEMU port forwarding
                let yaml_text = std::fs::read_to_string(config_path)?;
                let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_text)
                    .map_err(|e| Error::Config(format!("YAML parse: {}", e)))?;
                let guest_port = yaml.get("modules")
                    .and_then(|m| m.as_sequence())
                    .and_then(|mods| mods.iter().find(|m| {
                        m.get("name").and_then(|n| n.as_str()) == Some("http")
                    }))
                    .and_then(|http| http.get("port"))
                    .and_then(|p| p.as_u64())
                    .unwrap_or(80);
                let host_port = if guest_port < 1024 { guest_port + 18000 } else { guest_port };
                let hostfwd = format!("user,id=net0,hostfwd=tcp::{}-:{}", host_port, guest_port);

                eprintln!("Running: qemu-system-aarch64 -kernel {}", elf_path.display());
                eprintln!("  Port forward: host {} -> guest {}", host_port, guest_port);
                eprintln!(
                    "  Side-load: config={} @ 0x{:08x}, modules={} @ 0x{:08x}",
                    config_blob.display(),
                    QEMU_CONFIG_BLOB_ADDR,
                    modules_blob.display(),
                    QEMU_MODULES_BLOB_ADDR
                );

                let mut qemu_args: Vec<&str> = vec![
                    "-machine", "virt",
                    "-cpu", "cortex-a76",
                    "-smp", "1",
                    "-m", "256M",
                    "-nographic",
                ];
                qemu_args.extend_from_slice(&[
                    "-device", "virtio-net-device,netdev=net0,mac=52:54:00:12:34:56",
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
                    "-netdev", hostfwd_ref,
                    "-device", config_loader.as_str(),
                    "-device", modules_loader.as_str(),
                    "-kernel",
                ]);

                let status = std::process::Command::new("qemu-system-aarch64")
                    .args(&qemu_args)
                    .arg(&elf_path)
                    .status()?;

                if !status.success() {
                    return Err(Error::Config(format!(
                        "QEMU exited with status {}",
                        status
                    )));
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

fn cmd_flash(config_path: &PathBuf, verbose: bool) -> Result<()> {
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
                let dest = mp.join(
                    result
                        .output_path
                        .file_name()
                        .unwrap_or_default(),
                );
                eprintln!(
                    "Copying {} -> {}",
                    result.output_path.display(),
                    dest.display()
                );
                std::fs::copy(&result.output_path, &dest)?;
                println!(
                    "\x1b[1;32mFlashed\x1b[0m {}",
                    result.output_path.file_name().unwrap_or_default().to_string_lossy()
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
                            result.output_path.file_name().unwrap_or_default().to_string_lossy()
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
fn cmd_sign(input: &PathBuf, key_path: &PathBuf, output: Option<&std::path::Path>, verbose: bool) -> Result<()> {
    use std::fs;

    let seed_bytes = fs::read(key_path)
        .map_err(|e| Error::Module(format!("read key {}: {}", key_path.display(), e)))?;
    if seed_bytes.len() != 32 {
        return Err(Error::Module(format!(
            "key must be exactly 32 bytes, got {}", seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let fmod = fs::read(input)
        .map_err(|e| Error::Module(format!("read {}: {}", input.display(), e)))?;
    if fmod.len() < 68 {
        return Err(Error::Module("fmod file too small".into()));
    }

    // Locate the manifest section from the module header.
    let code_size = u32::from_le_bytes([fmod[8], fmod[9], fmod[10], fmod[11]]) as usize;
    let data_size = u32::from_le_bytes([fmod[12], fmod[13], fmod[14], fmod[15]]) as usize;
    let export_count = u16::from_le_bytes([fmod[24], fmod[25]]) as usize;
    let export_table_size = export_count * 8;
    let schema_size = u16::from_le_bytes([fmod[62], fmod[63]]) as usize;
    let manifest_size = u16::from_le_bytes([fmod[64], fmod[65]]) as usize;

    const MODULE_HEADER_SIZE: usize = 68;
    let manifest_offset = MODULE_HEADER_SIZE + code_size + data_size + export_table_size + schema_size;
    if manifest_offset + manifest_size > fmod.len() {
        return Err(Error::Module("fmod truncated before manifest".into()));
    }

    let mut manifest = manifest::Manifest::from_bytes(&fmod[manifest_offset..manifest_offset + manifest_size])?;

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
        for &x in b { s.push_str(&format!("{:02x}", x)); }
        s
    }

    if verbose {
        println!("Signed {} ({} bytes)", out_path.display(), out_bytes.len());
        println!("  pubkey:    {}", hex(&pk));
        println!("  signer_fp: {}", hex(&signer_fp));
    } else {
        let full = hex(&pk);
        println!("\x1b[1;32mSigned\x1b[0m {} pubkey={}...{}",
                 out_path.display(), &full[..8], &full[full.len() - 8..]);
    }

    Ok(())
}
