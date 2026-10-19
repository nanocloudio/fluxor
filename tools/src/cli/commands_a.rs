fn cmd_decode(file: &PathBuf, format: &str) -> Result<()> {
    let content = std::fs::read(file)?;
    let memory = parse_uf2(&content)?;

    // Read trailer to find config address
    let config_addr = read_trailer_config_addr(&memory)?;

    // The contiguous region from the config address; the decoder reads only
    // as far as the blob's own section sizes say.
    let config_data = {
        let mut data = Vec::new();
        let mut addr = config_addr;
        while let Some(&byte) = memory.get(&addr) {
            data.push(byte);
            match addr.checked_add(1) {
                Some(next) => addr = next,
                None => break,
            }
        }
        if data.len() < 64 {
            return Err(error::Error::Config(
                "No config found at expected address".into(),
            ));
        }
        data
    };

    let config = decode_config(&config_data)?;

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
            // The tools' `MAGIC_FXWR` is the kernel's own `MAGIC_CONFIG`: the
            // config blob a booting image carries.
            match magic {
                config::MAGIC_FXWR => println!("  Config magic: Valid (0x{magic:08x}, FXWR)"),
                _ => println!("  Config magic: Invalid (0x{magic:08x})"),
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

                                // Read the manifest the fmod carries (a header abi of 2 or more)
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

/// Substitute `${VAR}` and `${VAR:-default}` with environment values on
/// every graph read. The pass itself lives in the library
/// ([`fluxor_tools::env_subst`]) because the service-bundle renderer runs
/// it too, ahead of parameter substitution.
pub(crate) fn substitute_env_vars(input: &str) -> Result<String> {
    fluxor_tools::env_subst::substitute(input).map_err(crate::error::Error::Config)
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

/// The module root a build for `desc` reads `.fmod` artefacts from: the
/// explicit `--module-root`, else `$FLUXOR_MODULE_ROOT`, else the project's
/// `target/fluxor/<abi>/modules` (see `modules_build::select_module_root`).
fn target_module_root(
    explicit: Option<&std::path::Path>,
    project_root: &std::path::Path,
    desc: &crate::target::TargetDescriptor,
) -> Result<PathBuf> {
    crate::modules_build::select_module_root(
        explicit,
        project_root.join(crate::modules_build::modules_dir_for(desc)),
    )
}

fn cmd_generate(
    config_path: &Path,
    output: Option<&std::path::Path>,
    module_root: Option<&std::path::Path>,
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
    let modules_dir = target_module_root(module_root, &project_root, &target_desc)?;

    // Manifest search paths: explicit `module_search_paths:` from the
    // YAML plus the implicit <config-parent>/../modules default. See
    // `config::extract_module_search_paths` for ordering.
    let search_paths = config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();

    let binary_data = config::generate_config_ext(
        &config,
        &builder,
        &[],
        &modules_dir,
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
                "A config UF2 is only produced combined with a firmware image: \
                 use `--emit=combined --firmware <UF2>`, or `--emit=bin` for the \
                 raw config binary."
                    .into(),
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

/// Refuse a module whose code is over the loader's ceiling for the target.
///
/// The loader refuses it at boot ("code too large"), which on a board is a
/// graph that never starts, found after a flash. The ceiling is the silicon's
/// `module_code_kb`; a target that states none is not checked.
fn check_code_ceiling(
    modules: &[modules::ModuleInfo],
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    let Some(ceiling_kb) = target.module_code_kb else {
        return Ok(());
    };
    let ceiling = ceiling_kb as usize * 1024;
    let over: Vec<String> = modules
        .iter()
        .filter(|m| m.code_size() > ceiling)
        .map(|m| format!("{} ({} B)", m.name, m.code_size()))
        .collect();
    if over.is_empty() {
        return Ok(());
    }
    Err(error::Error::Config(format!(
        "{} over {}'s module code ceiling of {} B (module_code_kb in targets/silicon/{}.toml): the loader would refuse it at boot",
        over.join(", "),
        target.id,
        ceiling,
        target.id
    )))
}

/// Charge a graph's modules against the target's state arena and REFUSE an
/// over-budget image.
///
/// Each `.fmod` carries the resident-state figure `pack` read from the SDK's
/// `declare_module_state_bytes!` static, so this is a sum of measurements rather
/// than of estimates. The kernel refuses arena exhaustion at module load; that
/// is correct but late — it presents as a board that boots with modules missing,
/// on a die with no console guarantee. Doing the arithmetic here turns it into a
/// build error with the numbers shown.
///
/// Modules that publish no figure are counted and named. On a target without
/// an MMU — a microcontroller, where the arena is the die's RAM and nothing
/// traps an overrun — an unknown figure is refused: a sum with a hole in it
/// admits nothing. Elsewhere a partial sum is reported as partial and the
/// budget is not enforced.
fn check_state_budget(
    modules: &[modules::ModuleInfo],
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    if modules.is_empty() {
        return Ok(());
    }
    let arena = target.state_arena_kb as u64 * 1024;
    let mut total = 0u64;
    let mut unknown: Vec<&str> = Vec::new();
    let mut rows: Vec<(String, u64)> = Vec::new();
    // A gated module on an MPU target takes its whole private region — its
    // stack, state and heap as one allocation the planner shapes — from the
    // state arena, so that is what it is charged.
    let mpu = target
        .isolation
        .planner_model()
        .filter(|m| !matches!(m, fluxor_contracts::isolation::RegionModel::Pages));
    let levels = module_levels(config, target);
    let default = graph_default_level(config, target);
    for m in modules {
        let state = m.manifest.state_bytes_64 as u64 * 64;
        let gated = levels.get(&m.name).copied().unwrap_or(default).is_gated();
        let bytes = match mpu {
            Some(model) if gated && state != 0 => crate::protection::private_region_bytes(
                m.manifest.stack_bytes_64 as u64 * 64,
                state,
                m.manifest.arena_bytes as u64,
                target.isolation.exception_frame_bytes as u64,
                model,
            ),
            _ => state,
        };
        if bytes == 0 {
            unknown.push(m.name.as_str());
        } else {
            total += bytes;
        }
        rows.push((m.name.clone(), bytes));
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1));

    println!("State arena ({}): {} B", target.id, arena);
    for (name, bytes) in &rows {
        if *bytes == 0 {
            println!("  {name:<20} unknown");
        } else {
            println!("  {name:<20} {bytes:>9}");
        }
    }
    let pct = if arena > 0 { total * 100 / arena } else { 0 };
    if total > arena {
        println!("  {:<20} {total:>9}  OVER by {}", "total", total - arena);
    } else {
        println!(
            "  {:<20} {total:>9}  {pct}% of {arena}, slack {}",
            "total",
            arena - total
        );
    }

    if !unknown.is_empty() {
        if !target.has_mmu {
            return Err(Error::Config(format!(
                "{} publish(es) no state size, and {} admits a graph only on a complete \
                 sum. Add `declare_module_state_bytes!(<state type>)` beside each \
                 module's `module_state_size`.",
                unknown.join(", "),
                target.id,
            )));
        }
        println!(
            "  note: {} module(s) publish no state size ({}), so this is a PARTIAL sum \
             and the budget is not enforced",
            unknown.len(),
            unknown.join(", ")
        );
        return Ok(());
    }
    if total > arena {
        return Err(Error::Config(format!(
            "graph needs {total} B of module state but {}'s arena is {arena} B — over by {} B. \
             Drop a module, select a smaller variant, or raise state_arena_kb in \
             targets/silicon/{}.toml (which costs the buffer arena and the stack).",
            target.id,
            total - arena,
            target.id,
        )));
    }
    Ok(())
}

/// The largest config blob the target's kernel parses — the mirror of
/// `kernel::boot::config::MAX_CONFIG_SIZE`, which is keyed on the compile
/// target: 512 KiB on Linux, wasm32 and aarch64 (bcm2712), 32 KiB on the
/// microcontrollers. A config past it is refused at boot before the logger
/// runs, so a board would halt without saying why; refuse it here, by name.
fn kernel_max_config_size(target: &crate::target::TargetDescriptor) -> usize {
    // A target with no kernel build of its own is hosted (Linux, wasm).
    let Some(build) = target.build.as_ref() else {
        return 512 * 1024;
    };
    let t = build.rust_target.as_str();
    if t.starts_with("aarch64") || t.contains("linux") || t.starts_with("wasm32") {
        512 * 1024
    } else {
        32 * 1024
    }
}

/// Refuse a packed config the target's kernel would refuse at boot.
fn check_config_size(len: usize, target: &crate::target::TargetDescriptor) -> Result<()> {
    let max = kernel_max_config_size(target);
    if len > max {
        return Err(Error::Config(format!(
            "config blob is {len} bytes; the {} kernel parses at most {max} \
             (MAX_CONFIG_SIZE) and would refuse this graph at boot. Trim module \
             params or split the graph.",
            target.id
        )));
    }
    Ok(())
}

/// Admit each module's stack depth against the stack it will run on.
///
/// Every `.fmod` carries the worst-case depth its build measured from the call
/// graph (or its author declared where the graph has no bound). A module steps
/// on the kernel stack unless it is isolated on an MMU target, which gives it
/// its own; the kernel stack is shared one module at a time, so the DEEPEST
/// module on it — a maximum, not a sum — must fit what the kernel leaves
/// (`TargetDescriptor::module_stack_limit`). A module with no figure is
/// refused on a target without an MMU, where nothing traps an overrun.
fn check_stack_budget(
    modules: &[modules::ModuleInfo],
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    let levels = module_levels(config, target);
    let mut rows: Vec<(&str, u64, u64, &'static str)> = Vec::new();
    for m in modules {
        let level = levels
            .get(&m.name)
            .copied()
            .unwrap_or_else(|| graph_default_level(config, target));
        let Some((limit, what)) = target.module_stack_limit(level) else {
            continue;
        };
        rows.push((
            m.name.as_str(),
            m.manifest.stack_bytes_64 as u64 * 64,
            limit,
            what,
        ));
    }
    if rows.is_empty() {
        return Ok(());
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1));

    let mut stacks: Vec<(u64, &'static str)> = rows.iter().map(|r| (r.2, r.3)).collect();
    stacks.sort();
    stacks.dedup();
    for (limit, what) in &stacks {
        println!("Module stack ({}): {limit} B, {what}", target.id);
        for (name, bytes, l, _) in rows.iter().filter(|r| r.2 == *limit) {
            let _ = l;
            if *bytes == 0 {
                println!("  {name:<20} unknown");
            } else {
                println!("  {name:<20} {bytes:>9}");
            }
        }
    }

    let unknown: Vec<&str> = rows.iter().filter(|r| r.1 == 0).map(|r| r.0).collect();
    if !unknown.is_empty() && !target.has_mmu {
        return Err(Error::Config(format!(
            "{} carr(ies) no stack depth, and {} steps every module on one unguarded \
             stack. Rebuild with `fluxor modules build`, which measures it, or declare \
             it with `declare_module_stack_bytes!` where the build cannot.",
            unknown.join(", "),
            target.id,
        )));
    }
    let over: Vec<String> = rows
        .iter()
        .filter(|r| r.1 > r.2)
        .map(|(name, bytes, limit, what)| format!("{name} ({bytes} B > {what}, {limit} B)"))
        .collect();
    if !over.is_empty() {
        return Err(Error::Config(format!(
            "{} go(es) deeper than the stack it runs on on {}. Shorten the path \
             (`fluxor modules build -v` names it) or run the module where the stack \
             is larger.",
            over.join(", "),
            target.id,
        )));
    }
    Ok(())
}

/// Admit the graph's gated modules (`contained`, `isolated`) against what the
/// target and the gateway can give them, and print the level every gated
/// module gets.
///
/// Refused: more isolated modules than the target has slots for; a gated
/// module holding any permission that reaches past the gateway (raw
/// peripherals, DMA, flash, graph reconfiguration, the fault monitor,
/// cross-domain dispatch, PCIe, USB host, backing providers); a gated module
/// that provides a contract, whose other modules' calls would run its code
/// privileged.
fn check_gated_admission(
    modules: &[modules::ModuleInfo],
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    let levels = module_levels(config, target);
    let default = graph_default_level(config, target);
    let gated: Vec<(&modules::ModuleInfo, crate::protection::Level)> = modules
        .iter()
        .map(|m| (m, levels.get(&m.name).copied().unwrap_or(default)))
        .filter(|(_, l)| l.is_gated())
        .collect();
    if gated.is_empty() {
        return Ok(());
    }
    println!("Protection ({}):", target.id);
    let mpu = target
        .isolation
        .planner_model()
        .filter(|m| !matches!(m, fluxor_contracts::isolation::RegionModel::Pages));
    for (m, l) in &gated {
        match mpu {
            Some(model) => println!(
                "  {:<20} {:<9} private region {} B",
                m.name,
                l.name(),
                crate::protection::private_region_bytes(
                    m.manifest.stack_bytes_64 as u64 * 64,
                    m.manifest.state_bytes_64 as u64 * 64,
                    m.manifest.arena_bytes as u64,
                    target.isolation.exception_frame_bytes as u64,
                    model,
                ),
            ),
            None => println!("  {:<20} {}", m.name, l.name()),
        }
    }

    let entries: Vec<crate::protection::Gated<'_>> = gated
        .iter()
        .map(|(m, l)| crate::protection::Gated {
            name: m.name.as_str(),
            level: *l,
            permissions: m.manifest.permissions.bits,
            provides: &m.manifest.provides,
            code: m.code_size() as u64,
        })
        .collect();
    let model = target.isolation.planner_model();
    let refusals = crate::protection::gated_refusals(
        &entries,
        target.isolation.isolated_slots,
        &target.id,
        model,
    );
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "gated admission on {}: {}",
            target.id,
            refusals.join("; ")
        )))
    }
}

/// The protection level each module type in the graph is given on `target`
/// (the strongest over its instances). A module the resolver refuses is left
/// out; the validator reports it.
fn module_levels(
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> std::collections::BTreeMap<String, crate::protection::Level> {
    let mut out = std::collections::BTreeMap::new();
    for (ty, m) in crate::protection::module_entries(config) {
        if let Ok(r) = crate::protection::resolve(m, config, &target.isolation.levels) {
            let e = out.entry(ty).or_insert(r.provided);
            if r.provided > *e {
                *e = r.provided;
            }
        }
    }
    out
}

/// The level a module the graph does not list (one a stack inserts) is given:
/// the graph's own defaults.
fn graph_default_level(
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> crate::protection::Level {
    crate::protection::resolve(&serde_json::json!({}), config, &target.isolation.levels)
        .map(|r| r.provided)
        .unwrap_or(crate::protection::Level::None)
}

fn cmd_combine(
    firmware_path: &PathBuf,
    config_path: &PathBuf,
    output_path: &PathBuf,
    module_root: Option<&Path>,
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
    // Pi 5 VPU loads kernel as a raw binary to 0x80000. A `uefi` image runs
    // where its target says (`[memory] ram_base`): the loader places it there.
    let is_aarch64 = target_desc
        .build
        .as_ref()
        .map(|b| b.rust_target.starts_with("aarch64"))
        .unwrap_or(false);
    let aarch64_load_base: u32 = match (target_desc.runtime(), target_desc.memory.as_ref()) {
        ("uefi", Some(m)) => m.ram_base,
        _ => 0x0008_0000,
    };

    // Read firmware - keep as UF2 blocks to preserve non-contiguous sections like .end_block
    // Use the target's UF2 family ID so the correct chip accepts the image (e.g. RP2040 vs RP2350).
    let (firmware_data, firmware_max_addr) =
        if firmware_path.extension().is_some_and(|ext| ext == "bin") {
            let data = std::fs::read(firmware_path)?;
            if is_aarch64 {
                let end = aarch64_load_base + data.len() as u32;
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
    let modules_dir_path = target_module_root(module_root, &project_root, &target_desc)?;
    let modules_dir = modules_dir_path.as_path();
    let search_paths = config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
    // Config-anchored root so packaging reads the CONFIG's fluxor.lock pins,
    // symmetric with the manifest resolver.
    let store_fb = store_cli::lock_store_resolver(
        &crate::project::root_for_config(config_path),
        target_desc.module_abi(),
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

    check_code_ceiling(&modules, &target_desc)?;
    check_state_budget(&modules, &config, &target_desc)?;
    check_stack_budget(&modules, &config, &target_desc)?;
    check_gated_admission(&modules, &config, &target_desc)?;
    let programs = crate::modules::collect_programs(&config)?;

    let modules_data = if !modules.is_empty() || !programs.is_empty() {
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
        Some(crate::modules::build_module_table_with_programs(
            &modules, &programs,
        )?)
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

    // Ensure the combined image ends below the regions the board's flash is
    // partitioned into above it: the two graph slots and the parameter
    // store, which start at slot A (`flash_layout::graph_flash`, from the
    // board's flash size). Only applies to flash-based targets.
    if let Some(layout) = target_desc.graph_flash() {
        let slot_a_addr = XIP_BASE + layout.slot_a;
        let config_end = config_addr + config_data.len() as u32;
        if config_end > slot_a_addr {
            return Err(error::Error::Config(format!(
                "Combined image end ({config_end:#010x}) overlaps the graph slots and parameter store from {slot_a_addr:#010x} (a {} KiB flash). Reduce firmware/config size.",
                layout.flash_size / 1024
            )));
        }
    }

    if verbose {
        let base_str = if is_aarch64 {
            aarch64_load_base
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
        let base = aarch64_load_base;
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
    target_desc: &crate::target::TargetDescriptor,
    verbose: bool,
    project_root: &std::path::Path,
) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
    // `project_root` is config-anchored by the caller: fmod packaging and
    // pinned-manifest resolution must consult the same fluxor.lock.
    let store_fb = store_cli::lock_store_resolver(project_root, target_desc.module_abi(), None);
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

    check_config_size(config_data.len(), target_desc)?;
    check_code_ceiling(&modules, target_desc)?;
    check_state_budget(&modules, config, target_desc)?;
    check_stack_budget(&modules, config, target_desc)?;
    check_gated_admission(&modules, config, target_desc)?;
    let programs = crate::modules::collect_programs(config)?;

    let modules_data = if !modules.is_empty() || !programs.is_empty() {
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
        Some(crate::modules::build_module_table_with_programs(
            &modules, &programs,
        )?)
    } else {
        None
    };

    Ok((modules_data, config_data))
}

/// `fluxor build <graph> --emit=workload -o <dir>` — a workload image: the
/// graph's one `workloads:` entry as the artefacts a node needs to run it as
/// a workload that brings its own modules (`SOURCE_FMOD_PACK`):
///
/// ```text
/// <dir>/graph.flxa            the subgraph (FLXA), as the kernel admits it
/// <dir>/modules/<name>.fmod   every module it names, byte for byte
/// <dir>/workload-image.json   name, target, module ABI, ABI-surface pin,
///                             and each module's name_hash and sha256
/// ```
///
/// A module's sha256 is the pin the kernel admits it by, and the digest the
/// module's layer has once published (`fluxor publish workload <dir>`).
pub fn cmd_workload_image(
    config_path: &Path,
    output_dir: &Path,
    module_root: Option<&Path>,
    verbose: bool,
) -> error::Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let mut config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let target_desc = resolve_target(&config, None)?;
    let project_root = crate::project::root_for_config(config_path);
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    let module_root = target_module_root(module_root, &project_root, &target_desc)?;
    let abi = target_desc.module_abi();

    let workloads_yaml = config
        .get("workloads")
        .and_then(|w| w.as_array())
        .cloned()
        .unwrap_or_default();
    if workloads_yaml.len() != 1 {
        return Err(error::Error::Config(format!(
            "a workload image is one workload: {} declares {} under `workloads:`",
            config_path.display(),
            workloads_yaml.len()
        )));
    }
    // Only the workload: the base graph's modules are the node's, not this
    // workload's.
    let mut only = config.clone();
    only["modules"] = serde_json::Value::Array(Vec::new());
    let loc = crate::schema::ModuleLocation {
        dir: module_root.as_path(),
        abi,
        project_root: project_root.as_path(),
    };
    let workloads = crate::config::build_workloads(&only, loc, &[])?;
    let flxa = crate::add_subgraph::encode_add_subgraph(&workloads[0]).map_err(error::Error::Config)?;
    let store_fb = store_cli::lock_store_resolver(&project_root, abi, None);
    let modules = parse_modules_from_config_multi(
        &only,
        &module_root,
        &[],
        store_fb.as_deref().map(|f| f as _),
    )?;
    if modules.is_empty() {
        return Err(error::Error::Config("a workload image needs at least one module".into()));
    }

    let mods_dir = output_dir.join("modules");
    std::fs::create_dir_all(&mods_dir)?;
    std::fs::write(output_dir.join("graph.flxa"), &flxa)?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let sha = |b: &[u8]| {
        use sha2::Digest;
        hex(&sha2::Sha256::digest(b))
    };
    let mut entries = Vec::new();
    for m in &modules {
        std::fs::write(mods_dir.join(format!("{}.fmod", m.name)), &m.data)?;
        entries.push(serde_json::json!({
            "name": m.name,
            "name_hash": m.name_hash,
            "sha256": sha(&m.data),
            "size": m.data.len(),
        }));
    }
    let name = workloads_yaml[0]
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| config_path.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .unwrap_or_else(|| "workload".into());
    let doc = serde_json::json!({
        "name": name,
        "target": target_desc.id,
        "module_abi": abi,
        "abi_surface": hex(&hash::abi_surface_digest()),
        "flxa_sha256": sha(&flxa),
        "modules": entries,
    });
    std::fs::write(
        output_dir.join("workload-image.json"),
        serde_json::to_string_pretty(&doc)?,
    )?;
    if verbose {
        println!("workload image {name}: {} module(s), FLXA {} bytes", modules.len(), flxa.len());
    }
    println!("{}", output_dir.display());
    Ok(())
}

/// Emit a graph image: a 256-byte header, the module table (with the
/// graph's program section after it) from the first 4 KiB boundary, and the
/// static config from the next 256-byte boundary. An RP image is padded with
/// 0xFF to the flash slot size; any other is as long as its payload. The
/// header layout is `flash_layout::GRAPH_SLOT_*`.
///
/// The header records the epoch, the in-image offsets and sizes of the
/// modules and config regions, a SHA-256 over their concatenation, and the
/// ABI-surface pin; with `sign_key`, an Ed25519 signature over those bytes.
/// `graph_slot`'s ACTIVATE and the OTA staging commit recompute the digest
/// before they accept the image, and the RP boot selector does too on a
/// kernel built with a slot root.
fn cmd_graph_image(
    config_path: &PathBuf,
    output_path: &PathBuf,
    target_override: Option<&str>,
    epoch: u64,
    sign_key: Option<&std::path::Path>,
    module_root: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    // The graph-image header, as the kernel and `graph_slot` read it
    // (`modules/sdk/platform/rp/flash_layout.rs`, `GRAPH_SLOT_*`; an RP
    // flash A/B slot holds exactly this format).
    use crate::modules::sdk_layout::flash_layout as fl;
    const HEADER_SIZE: usize = fl::GRAPH_SLOT_HEADER_SIZE;
    const MODULES_ALIGN: usize = 4096;
    const SECTION_ALIGN: usize = 256;
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

    let modules_dir_path = target_module_root(module_root, &project_root, &target_desc)?;
    let modules_dir = modules_dir_path.as_path();
    let (modules_data, config_data) = build_packaged_blobs(
        &config,
        modules_dir,
        &[],
        &target_desc,
        verbose,
        &crate::project::root_for_config(config_path),
    )?;
    let modules_data = modules_data
        .ok_or_else(|| error::Error::Config("A graph image requires at least one module".into()))?;

    // Image geometry is per-target: an RP image is bounded by the board's
    // graph slot (`flash_layout::graph_flash`, from its flash size), and
    // everything else by the RAM staging ceiling. Either way it is emitted
    // only as long as its payload: the header says where the payload ends,
    // which is where `ota_ingest` stops reading, so no padding crosses the
    // wire.
    let flash_slot = target_desc.graph_flash();
    let image_size = match flash_slot {
        Some(layout) if layout.slot_size == 0 => return Err(error::Error::Config(format!(
            "{} has no graph slots: its {} KiB of flash leave no room for two beside the kernel",
            target_desc.board_id.as_deref().unwrap_or(&target_desc.id),
            layout.flash_size / 1024
        ))),
        Some(layout) => layout.slot_size as usize,
        None => RAM_IMAGE_SIZE,
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

    // Compose the final image. A flash image ends on a whole page, which is
    // what `graph_slot` programs.
    let emit_len = if flash_slot.is_some() {
        config_end.div_ceil(256) * 256
    } else {
        config_end
    };
    let mut out = vec![0xFFu8; emit_len];
    // Header.
    out[0..4].copy_from_slice(&fl::GRAPH_SLOT_MAGIC.to_le_bytes());
    out[4] = fl::GRAPH_SLOT_VERSION;
    out[8..16].copy_from_slice(&epoch.to_le_bytes());
    out[16..20].copy_from_slice(&(modules_offset as u32).to_le_bytes());
    out[20..24].copy_from_slice(&(modules_data.len() as u32).to_le_bytes());
    out[24..28].copy_from_slice(&(config_offset as u32).to_le_bytes());
    out[28..32].copy_from_slice(&(config_data.len() as u32).to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    // ABI-surface pin (header 64..96): the wire-surface digest of the
    // substrate this image was built against (`hash::abi_surface_digest`).
    // The RP boot slot selector, `graph_slot` and the OTA staging commit
    // all enforce it: an image built for an incompatible kernel fails
    // closed (to the other flash slot, or with -EACCES) instead of loading
    // modules with stale hardcoded wire values.
    let pin = fl::GRAPH_SLOT_ABI_SURFACE_OFFSET;
    out[pin..pin + 32].copy_from_slice(&hash::abi_surface_digest());
    // Signature record (header 96..168): "SIG1", the key id (the first
    // four bytes of SHA-256 of the public key), and Ed25519 over the
    // header's first 96 bytes, which bind the payload through its digest.
    // Left erased when no key is given: an unsigned image, which only a
    // device built without a slot root accepts.
    let signed = match sign_key {
        Some(key_path) => Some(sign_graph_image_header(
            &mut out[..HEADER_SIZE],
            &read_signing_seed(key_path)?,
        )),
        None => None,
    };
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
        "\x1b[1;32mSuccess\x1b[0m {} modules={}K config={}K size={}K epoch={} {}",
        output_path.display(),
        modules_data.len() / 1024,
        config_data.len() / 1024,
        emit_len / 1024,
        epoch,
        match signed {
            Some(pk) => format!("signed by {}", hash::hex(&pk)),
            None => "unsigned".to_string(),
        },
    );
    Ok(())
}

/// Sign a graph-image header in place: the signature record
/// (`flash_layout::GRAPH_SLOT_SIGNATURE_*`) over the signed bytes before it.
/// Answers the signer's public key.
fn sign_graph_image_header(header: &mut [u8], seed: &[u8; 32]) -> [u8; 32] {
    use crate::modules::sdk_layout::flash_layout as fl;
    let (pk, sig) = crate::crypto::sign(seed, &header[..fl::GRAPH_SLOT_SIGNED_LEN]);
    let key_id = {
        use sha2::Digest;
        sha2::Sha256::digest(pk)
    };
    let at = fl::GRAPH_SLOT_SIGNATURE_OFFSET;
    header[at..at + 4].copy_from_slice(&fl::GRAPH_SLOT_SIGNATURE_MAGIC.to_le_bytes());
    header[at + 4..at + 8].copy_from_slice(&key_id[..4]);
    header[at + 8..at + fl::GRAPH_SLOT_SIGNATURE_LEN].copy_from_slice(&sig);
    pk
}

#[cfg(test)]
mod graph_image_signature_tests {
    use super::sign_graph_image_header;
    use crate::modules::sdk_layout::flash_layout as fl;

    /// The record lands where the kernel reads it, names the key, and
    /// verifies over exactly the signed bytes: changing the epoch breaks it,
    /// and the bytes after the record are not covered.
    #[test]
    fn a_signed_header_verifies_over_its_signed_bytes() {
        let mut h = vec![0xFFu8; fl::GRAPH_SLOT_HEADER_SIZE];
        h[0..4].copy_from_slice(&fl::GRAPH_SLOT_MAGIC.to_le_bytes());
        h[8..16].copy_from_slice(&3u64.to_le_bytes());
        let pk = sign_graph_image_header(&mut h, &[9u8; 32]);
        let at = fl::GRAPH_SLOT_SIGNATURE_OFFSET;
        assert_eq!(&h[at..at + 4], b"SIG1");
        let id = {
            use sha2::Digest;
            sha2::Sha256::digest(pk)
        };
        assert_eq!(&h[at + 4..at + 8], &id[..4]);
        let sig: [u8; 64] = h[at + 8..at + 72].try_into().unwrap();
        assert!(crate::crypto::verify(
            &pk,
            &h[..fl::GRAPH_SLOT_SIGNED_LEN],
            &sig
        ));
        let mut raised = h.clone();
        raised[8] = 4;
        assert!(!crate::crypto::verify(
            &pk,
            &raised[..fl::GRAPH_SLOT_SIGNED_LEN],
            &sig
        ));
        assert!(h[at + fl::GRAPH_SLOT_SIGNATURE_LEN..]
            .iter()
            .all(|&b| b == 0xFF));
    }
}

/// The 32-byte Ed25519 seed at `path` (`fluxor modules keygen` writes one).
/// Errors name the file, never its bytes.
fn read_signing_seed(path: &std::path::Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Config(format!("--sign-key {}: {e}", path.display())))?;
    bytes.as_slice().try_into().map_err(|_| {
        Error::Config(format!(
            "--sign-key {}: {} bytes, not a 32-byte Ed25519 seed",
            path.display(),
            bytes.len()
        ))
    })
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
            modules::PackContext::default(),
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
