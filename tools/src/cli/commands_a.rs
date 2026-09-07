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
    // Packed-header `required_caps` (bytes 66..74) — the value the KERNEL
    // reads and the capability gate enforces at runtime. This is distinct
    // from the manifest-derived mask in the `manifest:` block below: the
    // latter is recomputed from `[[resources]]`, the former is what was
    // actually written into the header at pack time. They should match; a
    // mismatch (header 0x0 while the manifest declares contracts) means the
    // module was packed without its header caps populated, and every
    // `provider_call` to a declared contract will return ENOSYS at runtime.
    if m.data.len() >= 74 {
        let mut caps_bytes = [0u8; 8];
        caps_bytes.copy_from_slice(&m.data[66..74]);
        let header_caps = u64::from_le_bytes(caps_bytes);
        println!("  header required_caps (runtime-enforced): 0x{header_caps:016x}");
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

pub(crate) fn substitute_env_vars(input: &str) -> Result<String> {
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
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = crate::project::root_for_config(config_path);
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
    let modules_dir_default = crate::modules_build::modules_dir_for(&target_desc);
    let modules_dir = modules_dir_override.unwrap_or(modules_dir_default.as_path());

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
        &crate::project::root_for_config(config_path),
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
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = crate::project::root_for_config(config_path);
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
    let modules_dir_path = crate::modules_build::modules_dir_for(&target_desc);
    let modules_dir = modules_dir_path.as_path();
    let search_paths = config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
    // Config-anchored root so packaging reads the CONFIG's fluxor.lock pins,
    // symmetric with the manifest resolver.
    let store_fb = store_cli::lock_store_resolver(
        &crate::project::root_for_config(config_path),
        &target_desc.id,
        None,
    );
    let modules = parse_modules_from_config_multi(
        &config,
        modules_dir,
        &extra_dirs,
        store_fb.as_deref().map(|f| f as _),
    )?;

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
        &crate::project::root_for_config(config_path),
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
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = crate::project::root_for_config(config_path);
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
    project_root: &std::path::Path,
) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
    // `project_root` is config-anchored by the caller: fmod packaging and
    // pinned-manifest resolution must consult the same fluxor.lock.
    let store_fb = store_cli::lock_store_resolver(project_root, &target_desc.id, None);
    let modules = parse_modules_from_config_multi(
        config,
        modules_dir,
        extra_dirs,
        store_fb.as_deref().map(|f| f as _),
    )?;

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
        project_root,
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

/// Emit a graph image: 256-byte header + modules table + static config,
/// padded to the slot size. Layout mirrors `abi::graph_slot`.
///
/// The header records the epoch, the in-image offsets and sizes of the
/// modules and config regions, and a SHA-256 over their concatenation.
/// `graph_slot::ACTIVATE` recomputes the hash from flash and rejects
/// mismatches.
fn cmd_graph_image(
    config_path: &PathBuf,
    output_path: &PathBuf,
    target_override: Option<&str>,
    epoch: u64,
    modules_dir_override: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    // Image layout constants mirror modules/sdk/abi.rs :: graph_slot
    // (the RP flash A/B slot holds exactly this graph-image format).
    const HEADER_SIZE: usize = 256;
    const MODULES_ALIGN: usize = 4096;
    const SECTION_ALIGN: usize = 256;
    const MAGIC: u32 = 0x4C53_5846; // "FXSL"
    const VERSION: u8 = 1;
    /// RP flash A/B aperture (`GRAPH_SLOT_SIZE`) — the image fills it.
    const FLASH_SLOT_SIZE: usize = 0x0008_0000;
    /// RAM-staged image ceiling for targets without a flash aperture
    /// (Pi 5 OTA staging region; mirrors the kernel's
    /// `MAX_MODULES_BLOB_SIZE` reasoning).
    const RAM_IMAGE_SIZE: usize = 8 * 1024 * 1024;

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
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = crate::project::root_for_config(config_path);
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

    let modules_dir_path = crate::modules_build::modules_dir_for(&target_desc);
    let modules_dir = modules_dir_override.unwrap_or(modules_dir_path.as_path());
    let (modules_data, config_data) =
        build_packaged_blobs(
            &config,
            modules_dir,
            &[],
            &target_desc,
            verbose,
            &crate::project::root_for_config(config_path),
        )?;
    let modules_data = modules_data
        .ok_or_else(|| error::Error::Config("A graph image requires at least one module".into()))?;

    // Image geometry is per-target: RP targets fill their fixed flash
    // A/B slot aperture (padded to size, 0xFF like erased flash);
    // everything else is a RAM-staged image — same header, bounded by
    // the staging ceiling, emitted unpadded so the wire artifact is
    // only as big as its payload.
    let flash_slot = matches!(target_desc.id.as_str(), "rp2040" | "rp2350");
    let image_size = if flash_slot {
        FLASH_SLOT_SIZE
    } else {
        RAM_IMAGE_SIZE
    };

    // Lay out the image: header | pad → 4KB | modules | pad → 256B | config.
    let modules_offset = HEADER_SIZE.div_ceil(MODULES_ALIGN) * MODULES_ALIGN;
    let modules_end = modules_offset + modules_data.len();
    let config_offset = modules_end.div_ceil(SECTION_ALIGN) * SECTION_ALIGN;
    let config_end = config_offset + config_data.len();
    if config_end > image_size {
        return Err(error::Error::Config(format!(
            "Graph image ({config_end} bytes) exceeds the size ceiling ({image_size} bytes). Reduce modules/config."
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

    // Compose the final image (flash builds pad to the slot aperture).
    let emit_len = if flash_slot { image_size } else { config_end };
    let mut out = vec![0xFFu8; emit_len];
    // Header.
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4] = VERSION;
    out[8..16].copy_from_slice(&epoch.to_le_bytes());
    out[16..20].copy_from_slice(&(modules_offset as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(modules_data.len() as u32).to_le_bytes());
    out[24..28].copy_from_slice(&(config_offset as u32).to_le_bytes());
    out[28..32].copy_from_slice(&(config_data.len() as u32).to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    // ABI-surface pin (header 64..96): the wire-surface digest of the
    // substrate this image was built against (`hash::abi_surface_digest`).
    // The RP boot slot selector and the OTA staging commit both enforce
    // it: an image built for an incompatible kernel fails closed (to the
    // other flash slot, or with -EACCES at commit) instead of loading
    // modules with stale hardcoded wire values.
    out[64..96].copy_from_slice(&hash::abi_surface_digest());
    // Payload.
    out[modules_offset..modules_offset + modules_data.len()].copy_from_slice(&modules_data);
    out[config_offset..config_offset + config_data.len()].copy_from_slice(&config_data);

    std::fs::write(output_path, &out)?;
    if verbose {
        eprintln!(
            "graph image: modules_off=0x{:x} ({} bytes), config_off=0x{:x} ({} bytes), epoch={}",
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
        emit_len / 1024,
        epoch,
    );
    Ok(())
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
        // Standalone CLI pack has no build-target context: per-target
        // capacity tables resolve via their `default` key.
        modules::pack_fmod_wasm(
            input,
            output,
            &module_name,
            module_type,
            manifest_path,
            None,
            None,
        )?
    } else {
        pack_fmod(
            input,
            output,
            &module_name,
            module_type,
            manifest_path,
            None,
            None,
        )?
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

