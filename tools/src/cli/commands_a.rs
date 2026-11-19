fn cmd_decode(file: &PathBuf, format: &str) -> Result<()> {
    let content = std::fs::read(file)?;
    let memory = parse_uf2(&content)?;

    // The config the graph image after the kernel names.
    let (at, header) = find_graph_image(&memory)?;
    let config_data = uf2::extract_region(
        &memory,
        at + header.config_offset,
        header.config_size as usize,
    )
    .ok_or_else(|| error::Error::Config("the graph image's config is not in the file".into()))?;

    let config = decode_config(&config_data)?;

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&config)?),
        _ => println!("{}", serde_yaml::to_string(&config)?),
    }

    Ok(())
}

/// The graph image a firmware image carries after the kernel: the first
/// 256-byte aligned address holding a header the codec reads whose regions
/// the file holds. Answers its address and header.
fn find_graph_image(
    memory: &std::collections::BTreeMap<u32, u8>,
) -> Result<(u32, fluxor_abi::wire::graph_image::Header)> {
    use fluxor_abi::wire::graph_image::{Header, HEADER_SIZE, MAGIC};
    let min_addr = *memory
        .keys()
        .min()
        .ok_or_else(|| error::Error::Config("Empty memory".into()))?;
    let max_addr = *memory.keys().max().unwrap();
    let mut addr = min_addr.div_ceil(256) * 256;
    while addr <= max_addr {
        if let Some(bytes) = uf2::extract_region(memory, addr, HEADER_SIZE) {
            let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if magic == MAGIC {
                if let Ok(h) = Header::decode(&bytes, u64::from(max_addr - addr) + 1) {
                    let held = |off: u32, len: u32| {
                        uf2::extract_region(memory, addr + off, len as usize).is_some()
                    };
                    if held(h.modules_offset, h.modules_size) && held(h.config_offset, h.config_size) {
                        return Ok((addr, h));
                    }
                }
            }
        }
        addr += 256;
    }
    Err(error::Error::Config("No graph image found".into()))
}

fn cmd_info_fmod(file: &Path) -> Result<()> {
    let m = modules::ModuleInfo::from_file(file)?;
    let type_str = match m.module_type {
        1 => "Source",
        2 => "Transformer",
        3 => "Sink",
        4 => "EventHandler",
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

    // The graph image after the kernel.
    println!();
    if let Ok((image_addr, header)) = find_graph_image(&memory) {
        let modules_addr = image_addr + header.modules_offset;
        let config_addr = image_addr + header.config_offset;
        println!(
            "Graph image: header at 0x{image_addr:08x}, epoch {}, {}",
            header.epoch,
            if fluxor_abi::wire::graph_image::signature(
                &uf2::extract_region(&memory, image_addr, fluxor_abi::wire::graph_image::HEADER_SIZE)
                    .unwrap_or_default()
            )
            .is_some()
            {
                "signed"
            } else {
                "unsigned"
            }
        );
        println!("  Modules: 0x{modules_addr:08x} ({} bytes)", header.modules_size);
        println!("  Config:  0x{config_addr:08x} ({} bytes)", header.config_size);

        // Check config magic
        if let Some(header_data) = uf2::extract_region(&memory, config_addr, 4) {
            let magic = u32::from_le_bytes([
                header_data[0],
                header_data[1],
                header_data[2],
                header_data[3],
            ]);
            // The boot config's magic, the codec's own constant.
            match magic {
                fluxor_contracts::boot_config::MAGIC => {
                    println!("  Config magic: Valid (0x{magic:08x}, FXCF)");
                }
                _ => println!("  Config magic: Invalid (0x{magic:08x})"),
            }
        }

        // Parse and display module table
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
                let module_count = u16::from_le_bytes([table_header[6], table_header[7]]) as usize;
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

                        let fmod_addr = modules_addr + fmod_offset;
                        if let Some(fmod_header) =
                            uf2::extract_region(&memory, fmod_addr, modules::MODULE_HEADER_SIZE)
                        {
                            let Some(h) =
                                fluxor_abi::wire::fmod::header::Header::read(&fmod_header)
                            else {
                                continue;
                            };
                            let name = String::from_utf8_lossy(h.name_bytes());
                            let mod_type = h.module_type;
                            let abi = h.abi_version;

                            let type_str = match mod_type {
                                1 => "Source",
                                2 => "Transformer",
                                3 => "Sink",
                                4 => "EventHandler",
                                _ => "Unknown",
                            };

                            println!("\n  [{i}] {name} (hash=0x{name_hash:08x})");
                            println!(
                                "      type: {type_str} ({mod_type}), abi: v{abi}, size: {fmod_size} bytes"
                            );

                            // Read the manifest the fmod carries (a header abi of 2 or more)
                            if abi >= 2 {
                                let code_size = h.code_size as usize;
                                let data_size = h.data_size as usize;
                                let export_count = h.export_count as usize;
                                let schema_size = h.schema_size as usize;
                                let manifest_size = h.manifest_size as usize;

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
    } else {
        println!("Graph image: Not present");
    }

    Ok(())
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
    let binary_data = generate_config_bytes(config_path, module_root)?;
    eprintln!("Config size: {} bytes", binary_data.len());
    eprintln!("Note: Use 'combine' command to create a complete UF2 with the graph image");

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

/// The boot config a hosted build (Linux, wasm) compiles from the graph at
/// `config_path`, its rings charged against the target's buffer arena.
fn generate_config_bytes(
    config_path: &Path,
    module_root: Option<&std::path::Path>,
) -> Result<Vec<u8>> {
    let config: serde_json::Value =
        stack_expand::load_graph(config_path, &crate::project::root_for_config(config_path))?;

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

    // The hosted builds (Linux, wasm) compile their config here: charge its
    // rings against the target's buffer arena, as an image build does.
    check_ring_demand_unbuilt(
        &config,
        &binary_data,
        &modules_dir,
        &extra_dirs,
        &target_desc,
        &project_root,
        false,
    )?;

    Ok(binary_data)
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
/// `module_facts!` static, so this is a sum of measurements rather
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
    config_data: &[u8],
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    if modules.is_empty() {
        return Ok(());
    }
    let Some(state_arena_kb) = target.state_arena_kb else {
        return Err(Error::Config(format!(
            "{} has no kernel, so it has no state arena to admit a graph against",
            target.id
        )));
    };
    let by_hash: std::collections::HashMap<u32, &modules::ModuleInfo> =
        modules.iter().map(|m| (m.name_hash, m)).collect();
    let instances = crate::config::module_entries(config_data)?;
    // Where the kernel carves a heap whole at instantiation, the instance's cap
    // (params tag 0xEF, else the type's declared arena) comes out of the state
    // arena beside its state.
    let commits_heaps = crate::capacity::kernel_commits_heaps(target.runtime());
    // The arena the kernel will give this graph: the target's planning figure,
    // or what the graph's envelope places (`capacity::planned_state_arena`).
    let (arena, envelope) = crate::capacity::planned_state_arena(
        target.runtime(),
        state_arena_kb as u64 * 1024,
        target.buffer_arena_kb.map(|kb| kb as u64 * 1024),
        config.get("capacity"),
    );
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
    for (hash, params) in instances {
        // A built-in instance has no .fmod: the kernel holds its state.
        let Some(m) = by_hash.get(&hash) else {
            continue;
        };
        let state = m.manifest.state_bytes_64 as u64 * 64;
        let heap = crate::config::heap_cap_offset(params)
            .map(|at| u32::from_le_bytes([params[at], params[at + 1], params[at + 2], params[at + 3]]))
            .unwrap_or(m.manifest.arena_bytes) as u64;
        let gated = levels.get(&m.name).copied().unwrap_or(default).is_gated();
        let bytes = match mpu {
            Some(model) if gated && state != 0 => crate::protection::private_region_bytes(
                m.manifest.stack_bytes_64 as u64 * 64,
                state,
                heap,
                target.isolation.exception_frame_bytes as u64,
                model,
            ),
            _ if state == 0 => 0,
            _ if commits_heaps => state + heap,
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

    println!(
        "State arena ({}{}): {} B",
        target.id,
        if envelope { ", capacity envelope" } else { "" },
        arena
    );
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
                 sum. Rebuild them: every module states its facts \
                 (`fluxor_rt::module_facts!`).",
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
        let by = if envelope {
            " (as its capacity envelope places it)"
        } else {
            ""
        };
        let remedy = if crate::capacity::kernel_places_arenas(target.runtime()) {
            format!(
                "give the state arena more: `capacity: {{ state_arena }}`, or state_arena_kb \
                 in targets/silicon/{}.toml (either is taken from the kernel's static pool, \
                 which costs the buffer arena and the stack)",
                target.id
            )
        } else {
            format!("{}'s kernel fixes the size of its state arena", target.id)
        };
        return Err(Error::Config(format!(
            "graph needs {total} B of module state but {}'s arena is {arena} B{by} — over by \
             {} B. Drop a module or select a smaller variant; {remedy}.",
            target.id,
            total - arena,
        )));
    }
    Ok(())
}

/// Charge a compiled graph's channel rings against the target's buffer arena
/// and REFUSE an image whose rings do not fit (`ring_demand`).
///
/// `modules` are the `.fmod`s the image carries: the loader holds exactly
/// their manifests, so a module the kernel runs built in sizes none of its
/// ports. The source manifests only name the ports in the table.
fn check_ring_demand(
    config: &serde_json::Value,
    config_data: &[u8],
    modules: &[modules::ModuleInfo],
    target: &crate::target::TargetDescriptor,
    extra_dirs: &[&std::path::Path],
    project_root: &std::path::Path,
) -> Result<()> {
    let facts: std::collections::HashMap<u32, crate::ring_demand::ModuleFacts<'_>> = modules
        .iter()
        .map(|m| {
            (
                m.name_hash,
                crate::ring_demand::ModuleFacts {
                    manifest: &m.manifest,
                    mailbox_safe: m.mailbox_safe,
                },
            )
        })
        .collect();
    let manifests = config::load_module_manifests_with_extra_for_target(
        &config["modules"],
        extra_dirs,
        Some(target.id.as_str()),
        project_root,
    );
    crate::ring_demand::check(config, config_data, &facts, &manifests, target)
}

/// The 16 MiB alignment `.bss` starts on in a RAM-loaded aarch64 image
/// (`linker/memory-bcm2712.x`, `linker/memory-uefi.x`): the graph image's
/// header, module table and config sit between the end of its file-backed
/// sections and that boundary, which `_start` zeroes from.
const AARCH64_BSS_ALIGN: u32 = 0x0100_0000;

/// Where the payload window of a RAM-loaded aarch64 image ends: `__bss_start`,
/// the first 16 MiB boundary at or past the image's file-backed end. The
/// kernel bounds the graph image by the same address
/// (`kernel::boot::config::firmware_image_window`), so an image that reaches
/// it is refused here, by name, rather than erased in part by the boot's
/// `.bss` clear and refused before the logger runs.
fn aarch64_payload_window_end(firmware_end: u32) -> u64 {
    (firmware_end as u64).div_ceil(AARCH64_BSS_ALIGN as u64) * AARCH64_BSS_ALIGN as u64
}

/// Refuse a graph image whose config, the last of its regions, is placed at
/// `config_addr` in a RAM-loaded aarch64 image whose file-backed sections end
/// at `firmware_end`, unless the whole blob, `total_len` bytes as its header
/// states, ends below `__bss_start`: the header, module table and config then
/// all lie in the window. A blob that ends at the boundary or past it is
/// refused: `.bss` starts there.
fn check_aarch64_payload_window(config_addr: u32, config: &[u8], firmware_end: u32) -> Result<()> {
    let cfg = fluxor_contracts::boot_config::decode(config)
        .map_err(|e| error::Error::Config(format!("boot config refused: {e}")))?;
    let window_end = aarch64_payload_window_end(firmware_end);
    let config_end = u64::from(config_addr) + cfg.total_len() as u64;
    if config_end >= window_end {
        return Err(error::Error::Config(format!(
            "Combined image payload ends at {config_end:#x}, reaching the payload window's end \
             at {window_end:#x} where the kernel's .bss begins (the graph image's header, module \
             table and config must all end below it). Shrink the module set or config."
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
             it with `module_facts!`'s `stack:` where the build cannot.",
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

/// Print every module's grants, then admit the graph's gated modules
/// (`contained`, `isolated`) against what the target and the gateway can give
/// them, and print the level every gated module gets.
///
/// Refused: more isolated modules than the target has slots for; a gated
/// module holding any grant that reaches past the gateway (the registry's
/// `reach = "kernel"`: raw peripherals, DMA, flash, graph reconfiguration,
/// the fault monitor, cross-domain dispatch, PCIe, USB host); a gated module
/// that provides a contract, whose other modules' calls would run its code
/// privileged.
fn check_gated_admission(
    modules: &[modules::ModuleInfo],
    config: &serde_json::Value,
    target: &crate::target::TargetDescriptor,
) -> Result<()> {
    // What each module may call, as the kernel will check it.
    let granted: Vec<&modules::ModuleInfo> = modules
        .iter()
        .filter(|m| m.manifest.grants != [0, 0])
        .collect();
    if !granted.is_empty() {
        println!("Grants:");
        for m in granted {
            println!(
                "  {:<20} {}",
                m.name,
                crate::manifest::grant_names(m.manifest.grants).join(", ")
            );
        }
    }
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
            grants: m.manifest.grants,
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
        .unwrap_or(crate::protection::Level::Privileged)
}

fn cmd_combine(
    firmware_path: &PathBuf,
    config_path: &Path,
    output_path: &PathBuf,
    module_root: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    // Read the graph as every build reads it: includes expanded, params
    // rendered.
    let config: serde_json::Value =
        stack_expand::load_graph(config_path, &crate::project::root_for_config(config_path))?;

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
    let (mut firmware_data, firmware_max_addr) =
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

    // The signing root: written into the kernel image here, after link, so
    // the build never bakes one in and the image admits exactly the modules
    // signed by its key.
    let root = crate::signing::root(&project_root)?;
    crate::signing::write_root(
        &mut firmware_data,
        root,
        &firmware_path.display().to_string(),
    )?;
    match root {
        Some(r) => eprintln!("Signing root: {}", crate::signing::root_id(&r)),
        None => eprintln!("Signing root: none (the image verifies no signature)"),
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
    check_state_budget(&modules, &config, &config_data, &target_desc)?;
    check_ring_demand(
        &config,
        &config_data,
        &modules,
        &target_desc,
        &extra_dirs,
        &crate::project::root_for_config(config_path),
    )?;
    check_stack_budget(&modules, &config, &target_desc)?;
    check_gated_admission(&modules, &config, &target_desc)?;
    let programs = crate::modules::collect_programs(&config)?;

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
    let modules_data = crate::modules::build_module_table_with_programs(&modules, &programs)?;

    // The graph image goes right after the firmware: its header on the next
    // 256-byte boundary (a UF2 block's payload), where the kernel looks for
    // it, and the module table and config where `graph_image::place` puts
    // them from there.
    let image_addr = firmware_max_addr.div_ceil(256) * 256;
    let header = crate::graph_image::header(
        u64::from(image_addr),
        &modules_data,
        &config_data,
        0,
    )?;
    let modules_addr = image_addr + header.modules_offset;
    let config_addr = image_addr + header.config_offset;
    let image_end = u64::from(image_addr) + header.end();

    // A RAM-loaded aarch64 image carries its graph image below `.bss`: past
    // that boundary `_start` zeroes it before the kernel reads it.
    if is_aarch64 {
        check_aarch64_payload_window(config_addr, &config_data, firmware_max_addr)?;
    }

    // Ensure the combined image ends below the regions the board's flash is
    // partitioned into above it: the two graph slots, the data store and the
    // parameter store, which start at slot A (`flash_layout::graph_flash`,
    // from the board's flash size). Only applies to flash-based targets.
    if let Some(layout) = target_desc.graph_flash() {
        let slot_a_addr = u64::from(XIP_BASE + layout.slot_a);
        if image_end > slot_a_addr {
            return Err(error::Error::Config(format!(
                "Combined image end ({image_end:#010x}) overlaps the graph slots and parameter store from {slot_a_addr:#010x} (a {} KiB flash). Reduce firmware/config size.",
                layout.flash_size / 1024
            )));
        }
    }

    // A kernel image with a signing root admits only a graph image signed by
    // it, so the header is signed with the key whose public key the root is.
    // A root this workspace holds no key for would leave the image unable to
    // boot its own graph: refused here.
    let seed = crate::signing::seed(None, &project_root)?;
    if let Some(r) = root {
        if seed.map(|s| crate::signing::public_key(&s)) != Some(r) {
            return Err(error::Error::Config(format!(
                "the image's signing root {} is not the public key of this workspace's signing \
                 key, which signs the graph it carries: the kernel would refuse its own graph",
                crate::signing::root_id(&r)
            )));
        }
    }
    let header_bytes = crate::graph_image::header_bytes(&header, seed.as_ref());

    if verbose {
        let base_str = if is_aarch64 {
            aarch64_load_base
        } else {
            XIP_BASE
        };
        eprintln!("Layout:");
        eprintln!("  Firmware:  0x{base_str:08x} - 0x{firmware_max_addr:08x}");
        eprintln!("  Header:    0x{image_addr:08x} (256 bytes)");
        eprintln!(
            "  Modules:   0x{:08x} ({} bytes)",
            modules_addr,
            modules_data.len()
        );
        eprintln!(
            "  Config:    0x{:08x} ({} bytes)",
            config_addr,
            config_data.len()
        );
    }

    // Build the combined image.
    // aarch64: raw binary (firmware + padding + header + modules + config)
    // RP:      UF2 container with blocks for each section
    let (combined, firmware_size) = if is_aarch64 {
        let base = aarch64_load_base;
        let mut raw = firmware_data; // already raw bytes for aarch64
        let fw_size = raw.len();
        for (addr, bytes) in [
            (image_addr, &header_bytes[..]),
            (modules_addr, &modules_data[..]),
            (config_addr, &config_data[..]),
        ] {
            let off = (addr - base) as usize;
            if off > raw.len() {
                raw.resize(off, 0);
            }
            raw.extend_from_slice(bytes);
        }
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

        let firmware_size = firmware_data.len();
        let mut combined = firmware_data;
        combined.extend_from_slice(&create_uf2_blocks(
            &header_bytes,
            image_addr,
            firmware_family_id,
        ));
        combined.extend_from_slice(&create_uf2_blocks(
            &modules_data,
            modules_addr,
            firmware_family_id,
        ));
        combined.extend_from_slice(&create_uf2_blocks(
            &config_data,
            config_addr,
            firmware_family_id,
        ));
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
        let modules_size = modules_data.len();
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
    config_path: &Path,
    verbose: bool,
) -> Result<(serde_json::Value, target::TargetDescriptor)> {
    let config: serde_json::Value =
        stack_expand::load_graph(config_path, &crate::project::root_for_config(config_path))?;

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

    check_code_ceiling(&modules, target_desc)?;
    check_state_budget(&modules, config, &config_data, target_desc)?;
    check_ring_demand(
        config,
        &config_data,
        &modules,
        target_desc,
        extra_dirs,
        project_root,
    )?;
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
///                             each module's name_hash and sha256, and the
///                             environment its params are bound to
/// ```
///
/// The workload's modules and `wiring:` are written as a base graph's:
/// `module.port` ends resolved against the manifests, and the platform's
/// `linux_net` (undeclared) for the node's network, each module wired to it
/// a lane of its own (`config::workload_edges`). A graph's modules and
/// wiring move under `workloads:` as they are, but for the platform's entry.
///
/// A module param written `{env: NAME}` (with an optional `default:` or
/// `required: false`) is packed as an env bind record (`schema::env_bind`):
/// the node fills it from the CREATE's `env`/`var` entries. `env` in the
/// json lists each binding — `name`, `module`, `param`, `required` — so the
/// orchestrator can refuse a pod that does not give a required name before
/// it asks the node.
///
/// A module's sha256 is the pin the kernel admits it by, and the digest the
/// module's layer has once published (`fluxor publish workload <dir>`).
pub fn cmd_workload_image(
    config_path: &Path,
    output_dir: &Path,
    module_root: Option<&Path>,
    verbose: bool,
) -> error::Result<()> {
    let mut config: serde_json::Value =
        stack_expand::load_graph(config_path, &crate::project::root_for_config(config_path))?;
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
    let (workloads, env_binds) = crate::schema::with_env_binds(|| {
        crate::config::build_workloads(&only, loc, &[], &target_desc.id)
    });
    let workloads = workloads?;
    let flxa =
        crate::add_subgraph::encode_add_subgraph(&workloads[0]).map_err(error::Error::Config)?;
    let store_fb = store_cli::lock_store_resolver(&project_root, abi, None);
    let modules = parse_modules_from_config_multi(
        &only,
        &module_root,
        &[],
        store_fb.as_deref().map(|f| f as _),
    )?;
    if modules.is_empty() {
        return Err(error::Error::Config(
            "a workload image needs at least one module".into(),
        ));
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
        .or_else(|| {
            config_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "workload".into());
    let doc = serde_json::json!({
        "name": name,
        "target": target_desc.id,
        "module_abi": abi,
        "abi_surface": hex(&hash::abi_surface_digest()),
        "flxa_sha256": sha(&flxa),
        "modules": entries,
        "env": env_binds
            .iter()
            .map(|b| serde_json::json!({
                "name": b.name,
                "module": b.module,
                "param": b.param,
                "required": b.required,
            }))
            .collect::<Vec<_>>(),
    });
    std::fs::write(
        output_dir.join("workload-image.json"),
        serde_json::to_string_pretty(&doc)?,
    )?;
    if verbose {
        println!(
            "workload image {name}: {} module(s), FLXA {} bytes",
            modules.len(),
            flxa.len()
        );
    }
    println!("{}", output_dir.display());
    Ok(())
}

/// Emit a graph image: a 256-byte header, the module table (with the
/// graph's program section after it) from the first 4 KiB boundary, and the
/// static config from the next 256-byte boundary. An RP image ends on a
/// whole flash page; any other is as long as its payload. The header is
/// `wire::graph_image`'s, written by `graph_image::compose`.
///
/// The header records the epoch, the in-image offsets and sizes of the
/// modules and config regions, a SHA-256 over their concatenation, and the
/// ABI-surface pin; with `sign_key`, an Ed25519 signature over those bytes.
/// `graph_slot`'s ACTIVATE and the OTA staging commit recompute the digest
/// before they accept the image, and the RP boot selector does too on a
/// kernel image with a signing root.
fn cmd_graph_image(
    config_path: &Path,
    output_path: &PathBuf,
    target_override: Option<&str>,
    epoch: u64,
    sign_key: Option<&std::path::Path>,
    module_root: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    /// RAM-staged image ceiling for targets without a flash aperture
    /// (Pi 5 OTA staging region; mirrors the kernel's `STAGE_CAPACITY`).
    const RAM_IMAGE_SIZE: usize = 8 * 1024 * 1024;

    // Parse config (reusing the same path as cmd_combine).
    let mut config: serde_json::Value =
        stack_expand::load_graph(config_path, &crate::project::root_for_config(config_path))?;

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
        Some(layout) if layout.slot_size == 0 => {
            return Err(error::Error::Config(format!(
            "{} has no graph slots: its {} KiB of flash leave no room for two beside the kernel",
            target_desc.board_id.as_deref().unwrap_or(&target_desc.id),
            layout.flash_size / 1024
        )))
        }
        Some(layout) => layout.slot_size as usize,
        None => RAM_IMAGE_SIZE,
    };

    // Header, module table, config, laid out and hashed by the one writer;
    // with a key, signed over the header's signed bytes. Without one the
    // image is unsigned, which only a device with a rootless kernel image
    // accepts.
    let seed = sign_key.map(read_signing_seed).transpose()?;
    let mut out = crate::graph_image::compose(&modules_data, &config_data, epoch, seed.as_ref())?;
    let header = crate::graph_image::read(&out, "the graph image")?;
    let (modules_offset, config_offset) = (header.modules_offset, header.config_offset);
    if out.len() > image_size {
        return Err(error::Error::Config(format!(
            "Graph image ({} bytes) exceeds the size ceiling ({image_size} bytes). Reduce modules/config.",
            out.len()
        )));
    }
    // A flash image ends on a whole page, which is what `graph_slot`
    // programs.
    if flash_slot.is_some() {
        out.resize(out.len().div_ceil(256) * 256, 0xFF);
    }
    let emit_len = out.len();
    let signed = seed.map(|s| crate::signing::public_key(&s));

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

#[cfg(test)]
mod state_budget_tests {
    use super::check_state_budget;
    use crate::manifest::Manifest;
    use crate::modules::ModuleInfo;
    use serde_json::json;

    fn module(name: &str, state: u64) -> ModuleInfo {
        module_with_heap(name, state, 0)
    }

    fn module_with_heap(name: &str, state: u64, arena: u32) -> ModuleInfo {
        let manifest = Manifest {
            state_bytes_64: (state / 64) as _,
            arena_bytes: arena,
            ..Default::default()
        };
        ModuleInfo {
            name: name.into(),
            name_hash: crate::hash::fnv1a_hash(name.as_bytes()),
            module_type: 0,
            mailbox_safe: false,
            in_place_writer: false,
            drain_capable: false,
            schema: None,
            manifest,
            data: Vec::new(),
        }
    }

    /// A built config holding one module record per instance:
    /// `(type, params TLV)`.
    fn image(instances: &[(&str, &[u8])]) -> Vec<u8> {
        use fluxor_contracts::boot_config::{encode, BootConfigSpec, DomainRecord, ModuleRecord};
        let modules: Vec<ModuleRecord<'_>> = instances
            .iter()
            .zip(0u16..)
            .map(|(&(ty, params), id)| ModuleRecord {
                name_hash: crate::hash::fnv1a_hash(ty.as_bytes()),
                id,
                domain: 0,
                pre_pass: false,
                params,
            })
            .collect();
        encode(&BootConfigSpec {
            modules: &modules,
            domains: &[DomainRecord::default()],
            ..BootConfigSpec::default()
        })
        .expect("encodes")
    }

    fn pico2w() -> crate::target::TargetDescriptor {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        crate::target::load_target("pico2w", &root).expect("pico2w target")
    }

    /// On RP the envelope places the arenas: a larger `buffer_arena` takes
    /// its growth from the state arena, and a `state_arena` entry is the
    /// arena's size. The verdict follows the arena the kernel will give.
    #[test]
    fn an_rp_envelope_moves_the_state_arena() {
        let target = pico2w();
        let default = target.state_arena_kb.expect("an RP arena") as u64 * 1024;
        let buffer = target.buffer_arena_kb.expect("rp buffer arena") as u64 * 1024;
        // Fits the default split with 16 KiB to spare.
        let mods = [module("a", default - 16 * 1024)];
        let one = image(&[("a", &[])]);
        check_state_budget(&mods, &json!({}), &one, &target).expect("fits the default arena");
        // A buffer arena 32 KiB larger leaves the state arena 32 KiB smaller.
        let cfg = json!({"capacity": {"buffer_arena": buffer + 32 * 1024}});
        let e = check_state_budget(&mods, &cfg, &one, &target)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!("arena is {} B", default - 32 * 1024))
                && e.contains("capacity envelope")
                && e.contains("over by 16384 B"),
            "{e}"
        );
        // A state-arena entry is the size the kernel guarantees.
        let cfg = json!({"capacity": {"state_arena": default - 32 * 1024}});
        check_state_budget(&mods, &cfg, &one, &target).expect_err("a smaller state arena");
        let big = [module("a", default + 8 * 1024)];
        check_state_budget(&big, &json!({}), &one, &target).expect_err("past the default");
        let cfg = json!({"capacity": {"state_arena": default + 8 * 1024}});
        check_state_budget(&big, &cfg, &one, &target).expect("the entry places a larger arena");
    }

    /// Every instance takes its own state, so two instances of one type are
    /// charged twice.
    #[test]
    fn each_instance_is_charged() {
        let target = pico2w();
        let default = target.state_arena_kb.expect("an RP arena") as u64 * 1024;
        let mods = [module("a", default / 2 + 1024)];
        check_state_budget(&mods, &json!({}), &image(&[("a", &[])]), &target)
            .expect("one instance fits");
        check_state_budget(&mods, &json!({}), &image(&[("a", &[]), ("a", &[])]), &target)
            .expect_err("two instances do not");
    }

    /// RP commits a heap whole at instantiation, so the cap is charged beside
    /// the state: the type's declared arena, or the instance's own cap (params
    /// tag 0xEF) where the graph set one.
    #[test]
    fn a_committed_heap_is_charged_at_its_cap() {
        let target = pico2w();
        let default = target.state_arena_kb.expect("an RP arena") as u64 * 1024;
        let state = default - 16 * 1024;
        let mods = [module_with_heap("a", state, 32 * 1024)];
        check_state_budget(&mods, &json!({}), &image(&[("a", &[])]), &target)
            .expect_err("the declared heap does not fit beside the state");
        let small_cap: &[u8] = &[0xFE, 0x01, 8, 0, 0xEF, 4, 0x00, 0x20, 0x00, 0x00, 0xFF, 0x00];
        check_state_budget(&mods, &json!({}), &image(&[("a", small_cap)]), &target)
            .expect("an 8 KiB instance cap fits");
    }
}

#[cfg(test)]
mod payload_window_tests {
    use super::{aarch64_payload_window_end, check_aarch64_payload_window};
    use fluxor_contracts::boot_config::{encode, BootConfigSpec, DomainRecord};

    /// The window is bounded by the blob's own `total_len`: a config ending
    /// exactly at `__bss_start` is refused, one ending 8 bytes below it is
    /// accepted.
    #[test]
    fn a_config_must_end_below_bss_start() {
        let blob = encode(&BootConfigSpec {
            domains: &[DomainRecord::default()],
            ..BootConfigSpec::default()
        })
        .expect("encodes");
        let firmware_end = 0x0023_0000u32;
        let bss = aarch64_payload_window_end(firmware_end);
        assert_eq!(bss, 0x0100_0000);
        let len = blob.len() as u64;

        let at_boundary = u32::try_from(bss - len).unwrap();
        let err = check_aarch64_payload_window(at_boundary, &blob, firmware_end)
            .expect_err("ends at __bss_start");
        assert!(err.to_string().contains(".bss"), "{err}");

        let below = u32::try_from(bss - len - 8).unwrap();
        check_aarch64_payload_window(below, &blob, firmware_end).expect("ends 8 bytes below");

        // Bytes past `total_len` are not the blob's: a trailing pad does
        // not move where it ends.
        let mut padded = blob.clone();
        padded.extend_from_slice(&[0u8; 64]);
        check_aarch64_payload_window(below, &padded, firmware_end).expect("same blob");
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
        println!("  Exports: {}", result.exports.len());
        for (name, offset, hash) in &result.exports {
            println!("    {name}: 0x{offset:x} (hash: 0x{hash:08x})");
        }
        println!("  Total size: {} bytes", result.total_size);
    } else {
        // Concise single-line output: name code+data=total
        println!(
            "\x1b[1;32mSuccess\x1b[0m {} {}+{}={} bytes",
            result.name, result.code_size, result.data_size, result.total_size
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
