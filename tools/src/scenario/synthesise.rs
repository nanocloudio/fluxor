// ============================================================================
// PR 2: real synthesiser + binding route merger + re-validation
// ============================================================================

/// Construct the synthesised host graph as a `serde_json::Value`
/// equivalent to what a human would write in
/// `examples/serve_wasm/linux.yaml`. Returns `None` when the scenario
/// has no `host:` block (every binding has explicit `on:`).
///
/// The returned Value is the same shape `tools::board::validate_config`
/// consumes, so the caller can round-trip it through validation before
/// printing or spawning.
pub fn synthesise_host_config(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<serde_json::Value>> {
    let Some(host) = &scenario.host else {
        return Ok(None);
    };
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;

    let routes = synthesise_host_routes(scenario, base, scenario_path)?;
    // `http` — Wave's HTTP protocol module. The synthesised serving host
    // names it directly; in workspace/sync mode it resolves from wave.
    let http_module = serde_json::json!({
        "name": "http",
        "port": host.port,
        "host_tcp": 1,
        "routes": routes,
    });

    let config = serde_json::json!({
        "target": "linux",
        "platform": { "net": {} },
        // The http <-> linux_net wiring is the canonical 2-cycle
        // every linux http example carries. The scheduler has no typed
        // feedback edge, so it rejects the graph at `prepare_graph` time
        // unless the synthesised host opts explicitly into cycle
        // acceptance, which is what it does here. The cycle is
        // bidirectional and safe — each module just pumps its
        // respective channel.
        "scheduler": { "accept_cycles": true },
        "modules": [http_module],
        "wiring": [
            { "from": "linux_net.net_out", "to": "http.net_in" },
            { "from": "http.net_out", "to": "linux_net.net_in" },
        ],
    });

    Ok(Some(config))
}

/// Canonical wasm runtime shell — the HTML page and JS shim that
/// every wasm bundle is served alongside. **Baked into
/// `fluxor-tools` at compile time** via `include_str!` because they
/// are shared infrastructure (byte-identical across every wasm
/// scenario in the tree), not per-scenario data.
///
/// Partition principle: per-scenario things go in the `.wasm`
/// bundle (assets, PIC modules, config blob); shared infra lives
/// in the orchestrator. The shell is the browser-side analog of
/// `target/wasm/firmware.wasm` — built once into the orchestrator,
/// served once per scenario. Same shape as how `fluxor-linux`
/// hosts countless `bcm2712` configs without those configs
/// shipping their own kernel.
///
/// Edits to either file rebuild `fluxor-tools` automatically —
/// `include_str!` registers the file as a build dependency.
const CANONICAL_RUNTIME_HTML_RAW: &str = include_str!("../../../src/platform/wasm/host/runtime.html");
const CANONICAL_HOST_SHIMS_JS_RAW: &str =
    include_str!("../../../src/platform/wasm/host/host_shims.js");
/// Emulation Worker (?worker=1): runs the kernel + step pump off the main thread.
/// importScripts'es the canonical host_shims.js; reused across every scenario.
const CANONICAL_WORKER_JS_RAW: &str = include_str!("../../../src/platform/wasm/host/fluxor-worker.js");
/// Generic browser-overlay renderer (`presentation.shell`). Inlined
/// into the served runtime.html (rather than a separate route) so it
/// costs no slot against the kernel's `MAX_ROUTES = 8`. Defines
/// `window.FluxorOverlay`; dormant until a scenario carries a
/// `presentation.shell` block.
const CANONICAL_OVERLAY_JS_RAW: &str =
    include_str!("../../../src/platform/wasm/host/browser_overlay_runtime.js");
/// Marker in runtime.html where the overlay `<script>` is injected.
const OVERLAY_MARKER: &str = "<!--FLUXOR_OVERLAY_RUNTIME-->";

/// Escape every `${` so the config-load env-var substitutor passes
/// the content through verbatim. The shell HTML / JS contains lots
/// of JS template literals (`${msg}`, `${n}`, `${assetUrl}`, etc.)
/// that look like env-var refs but aren't; the substitutor's
/// existing `$${...}` escape syntax (see `substitute_env_vars`)
/// then collapses our `$${` back to literal `${` so the browser
/// sees the original source.
fn escape_for_env_substitution(s: &str) -> String {
    s.replace("${", "$${")
}

fn canonical_runtime_html_body() -> String {
    // Inline the overlay renderer at its marker before env-escaping, so
    // any `${` in the JS is escaped alongside the rest of the document.
    // If the marker is absent (older runtime.html), this is a no-op.
    let html = CANONICAL_RUNTIME_HTML_RAW.replace(
        OVERLAY_MARKER,
        &format!("<script>\n{CANONICAL_OVERLAY_JS_RAW}\n</script>"),
    );
    escape_for_env_substitution(&html)
}

fn canonical_host_shims_js_body() -> String {
    escape_for_env_substitution(CANONICAL_HOST_SHIMS_JS_RAW)
}

/// Walk a `list:` directory and build the `fluxor-manifest.json` entries
/// the wasm `storage.namespace` provider fetches at boot — one
/// `{ key, size, mtime, etag }` per file. Browsers can't `readdir` an
/// HTTP origin, so this synth-time directory snapshot is how a runtime
/// `storage.namespace` LIST enumerates shipped content. `key` is the
/// object key the `storage.object` provider fetches *as a URL*, so it
/// must equal the path the file is served at — `<path_prefix>/<relpath>`
/// with forward slashes and no leading slash, matching the `list:`
/// `path:` mount. `formats` (if non-empty) restricts to those extensions.
fn fluxor_manifest_entries(
    dir: &Path,
    path_prefix: &str,
    formats: &[String],
) -> Vec<serde_json::Value> {
    let prefix = path_prefix.trim_matches('/');
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if !formats.is_empty() {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !formats
                .iter()
                .any(|f| f.trim_start_matches('.').eq_ignore_ascii_case(&ext))
            {
                continue;
            }
        }
        let rel = match p.strip_prefix(dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut rel_str = String::new();
        for (i, comp) in rel.components().enumerate() {
            if i > 0 {
                rel_str.push('/');
            }
            rel_str.push_str(&comp.as_os_str().to_string_lossy());
        }
        let key = if prefix.is_empty() {
            rel_str
        } else {
            format!("{prefix}/{rel_str}")
        };
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size = md.len();
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(serde_json::json!({
            "key": key,
            "size": size,
            "mtime": mtime,
            "etag": format!("{size:x}-{mtime:x}"),
        }));
    }
    out.sort_by(|a, b| {
        a["key"]
            .as_str()
            .unwrap_or("")
            .cmp(b["key"].as_str().unwrap_or(""))
    });
    out
}

/// Build the `routes:` array for the synthesised host. Mounts the
/// canonical wasm runtime assets + bundle + scenario metadata, plus
/// any user `serve:` host_page override and `list:` binding-injected
/// gallery routes.
///
/// Route plan:
///   - `/`              → `serve:` host_page OR canonical runtime.html
///   - `/fluxor.wasm`   → built bundle (from `serve:` component or default)
///   - `/host_shims.js` → canonical JS shim
///   - `/scenario.json` → inline JSON (presentation + playlist source)
///   - `/api/list`...   → `list:` bindings (dual-mode listing + file-serve)
///
/// Five routes baseline + N `list:` bindings, well under
/// `MAX_ROUTES = 8` (PR 10).
fn synthesise_host_routes(
    scenario: &Scenario,
    base: &Path,
    scenario_path: &Path,
) -> Result<Vec<serde_json::Value>> {
    let mut routes = Vec::new();

    // ── Track the active `serve:` binding so we can synthesise the
    //    `/`, `/fluxor.wasm`, and `/scenario.json` routes coherently.
    //    Multiple `serve:` bindings (one wasm + multiple host-page
    //    overrides) are not supported on the synth host today —
    //    the first one wins; subsequent ones would need explicit
    //    `on:` targets to mount elsewhere.
    //
    // The default page is the embedded canonical runtime shell
    // (`canonical_runtime_html_body`). A `host_page:` override on
    // the component swaps in a user-provided file via fs_path.
    let mut serve_component: Option<&str> = None;
    let mut runtime_prefix: String = "/".to_string();
    let mut bundle_route_url: String = "/fluxor.wasm".to_string();
    let mut runtime_override_fs_path: Option<PathBuf> = None;
    // Accumulated `fluxor-manifest.json` entries across all `list:`
    // bindings — the directory snapshot a runtime `storage.namespace`
    // LIST enumerates (browsers can't readdir an HTTP origin).
    let mut manifest_entries: Vec<serde_json::Value> = Vec::new();

    for binding in &scenario.bindings {
        match binding {
            Binding::Serve(serve) if serve.on.is_none() => {
                if serve_component.is_some() {
                    return Err(Error::Config(format!(
                        "scenario {}: multiple `serve:` bindings without `on:` are not \
                         supported on the synthesised host (each one would try to mount \
                         a different page at `/`). Give all but one an explicit `on:` target.",
                        scenario_path.display()
                    )));
                }
                serve_component = Some(serve.serve.as_str());
                runtime_prefix = serve.prefix.clone();
                bundle_route_url = if serve.prefix == "/" {
                    "/fluxor.wasm".to_string()
                } else {
                    format!("{}/fluxor.wasm", serve.prefix.trim_end_matches('/'))
                };
                let comp = scenario.components.get(&serve.serve).ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings reference undefined component `{}`",
                        scenario_path.display(),
                        serve.serve
                    ))
                })?;
                // host_page is OPTIONAL: when unset, the synth host
                // serves the canonical runtime shell embedded in
                // fluxor-tools. Custom shells (test harness,
                // research prototypes) still set
                // `host_page: my_shell.html` to override with an
                // on-disk file.
                if let Some(host_page) = &comp.host_page {
                    runtime_override_fs_path = Some(absolute_or_join(base, host_page));
                }
                let desc = format!("serve: {} (host_page)", serve.serve);

                // ── /  → host page (canonical embedded shell OR
                //    user fs_path override).
                if let Some(ref override_path) = runtime_override_fs_path {
                    check_fs_path_length(override_path, 0, &desc, scenario_path)?;
                    routes.push(serde_json::json!({
                        "path": runtime_prefix,
                        "fs_path": override_path.display().to_string(),
                        "content_type": "text/html",
                    }));
                } else {
                    routes.push(serde_json::json!({
                        "path": runtime_prefix,
                        "body": canonical_runtime_html_body(),
                        "content_type": "text/html",
                    }));
                }

                // ── /fluxor.wasm → built bundle for this component.
                //    Stays as fs_path — per-scenario artifact, often
                //    multi-MB, not appropriate for inlining.
                let bundle_path = bundle_path_for(scenario_path, &serve.serve, comp)?;
                check_fs_path_length(&bundle_path, 0, &desc, scenario_path)?;
                routes.push(serde_json::json!({
                    "path": bundle_route_url,
                    "fs_path": bundle_path.display().to_string(),
                    "content_type": "application/wasm",
                }));
            }
            Binding::List(list) if list.on.is_none() => {
                let dir = absolute_or_join(base, &list.list);
                let desc = format!("list: {}", list.list.display());
                check_fs_path_length(&dir, 0, &desc, scenario_path)?;
                let mut entry = serde_json::Map::new();
                entry.insert("path".into(), serde_json::Value::String(list.path.clone()));
                entry.insert(
                    "fs_list".into(),
                    serde_json::Value::String(dir.display().to_string()),
                );
                if !list.formats.is_empty() {
                    entry.insert(
                        "fs_filter".into(),
                        serde_json::Value::String(list.formats.join(",")),
                    );
                }
                routes.push(serde_json::Value::Object(entry));
                // Snapshot the directory into the manifest so a runtime
                // `storage.namespace` LIST can enumerate it in-browser.
                manifest_entries.extend(fluxor_manifest_entries(&dir, &list.path, &list.formats));
            }
            _ => {}
        }
    }

    // ── /fluxor-manifest.json → directory snapshot for the wasm
    //    `storage.namespace` provider (fetched once at boot). Only
    //    emitted when there's at least one `list:` binding.
    if !manifest_entries.is_empty() {
        let manifest_url = if runtime_prefix == "/" {
            "/fluxor-manifest.json".to_string()
        } else {
            format!(
                "{}/fluxor-manifest.json",
                runtime_prefix.trim_end_matches('/')
            )
        };
        routes.push(serde_json::json!({
            "path": manifest_url,
            "body": serde_json::Value::Array(manifest_entries).to_string(),
            "content_type": "application/json",
        }));
    }

    // ── /host_shims.js → canonical JS shim (always mounted).
    //    Embedded in fluxor-tools at compile time — required by
    //    runtime.html AND by any user-written shell, since the wasm
    //    kernel imports 20+ `host_*` extern fns and the shim
    //    provides them all. There is no per-scenario host_shims.js;
    //    the kernel ABI is fixed across every wasm bundle.
    let shims_url = if runtime_prefix == "/" {
        "/host_shims.js".to_string()
    } else {
        format!("{}/host_shims.js", runtime_prefix.trim_end_matches('/'))
    };
    // Served as a FILE (fs_path), not an inline body: at ~90 KiB it dominates the
    // config arena (256 KiB), leaving no room for runtime.html to grow. The browser
    // fetches it by URL either way; this just keeps it out of the config blob.
    {
        let work_dir = scenario_work_dir(scenario);
        fs::create_dir_all(&work_dir).map_err(|e| {
            Error::Config(format!(
                "scenario {}: cannot create work dir {}: {}",
                scenario_path.display(),
                work_dir.display(),
                e
            ))
        })?;
        let shims_path = work_dir.join("host_shims.js");
        // Served from disk as raw bytes (fs_path route) — no config
        // loader ever substitutes this file, so write it UNESCAPED.
        fs::write(&shims_path, CANONICAL_HOST_SHIMS_JS_RAW).map_err(|e| {
            Error::Config(format!(
                "scenario {}: cannot write {}: {}",
                scenario_path.display(),
                shims_path.display(),
                e
            ))
        })?;
        routes.push(serde_json::json!({
            "path": shims_url,
            "fs_path": shims_path.display().to_string(),
            "content_type": "application/javascript",
        }));
    }

    // ── /fluxor-worker.js → emulation Worker (?worker=1 opt-in). Runs the kernel
    //    off the main thread; importScripts'es the host_shims.js route above. Served
    //    as a FILE (fs_path), not an inline body: the config arena (256 KiB) is
    //    already near full with runtime.html + host_shims.js, so an inline body
    //    overflows it. Harmless when ?worker=1 is not used — simply never fetched.
    {
        let work_dir = scenario_work_dir(scenario);
        fs::create_dir_all(&work_dir).map_err(|e| {
            Error::Config(format!(
                "scenario {}: cannot create work dir {}: {}",
                scenario_path.display(),
                work_dir.display(),
                e
            ))
        })?;
        let worker_path = work_dir.join("fluxor-worker.js");
        fs::write(&worker_path, CANONICAL_WORKER_JS_RAW).map_err(|e| {
            Error::Config(format!(
                "scenario {}: cannot write {}: {}",
                scenario_path.display(),
                worker_path.display(),
                e
            ))
        })?;
        let worker_url = if runtime_prefix == "/" {
            "/fluxor-worker.js".to_string()
        } else {
            format!("{}/fluxor-worker.js", runtime_prefix.trim_end_matches('/'))
        };
        routes.push(serde_json::json!({
            "path": worker_url,
            "fs_path": worker_path.display().to_string(),
            "content_type": "application/javascript",
        }));
    }

    // ── /scenario.json → inline static body with the wasm component's
    //    presentation block + playlist source + bundle URL. The shell
    //    fetches this before instantiating; it's how runtime.html
    //    knows what surfaces to compose and where the gallery lives.
    let scenario_json_url = if runtime_prefix == "/" {
        "/scenario.json".to_string()
    } else {
        format!("{}/scenario.json", runtime_prefix.trim_end_matches('/'))
    };
    let scenario_json_body =
        build_scenario_json(scenario, scenario_path, serve_component, &bundle_route_url)?;
    routes.push(serde_json::json!({
        "path": scenario_json_url,
        "body": scenario_json_body,
        "content_type": "application/json",
    }));

    Ok(routes)
}

/// Emit the JSON body the wasm runtime shell fetches at boot. Shape:
///
/// ```json
/// {
///   "scenario": "image_viewer",
///   "bundle":   "/fluxor.wasm",
///   "playlist": { "source": "/api/list", "filter": "image" },
///   "presentation": { ... }   // verbatim from the wasm component graph
/// }
/// ```
///
/// The `playlist` field is derived from the first `list:` binding
/// whose `on:` is unset (the gallery). The `presentation` field is
/// pulled verbatim from the active wasm component's graph YAML if
/// the component declares one; otherwise we synthesise a sensible
/// default based on which display/audio modules the graph wires.
fn build_scenario_json(
    scenario: &Scenario,
    scenario_path: &Path,
    serve_component: Option<&str>,
    bundle_route_url: &str,
) -> Result<String> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "scenario".into(),
        serde_json::Value::String(scenario.name.clone()),
    );
    obj.insert(
        "bundle".into(),
        serde_json::Value::String(bundle_route_url.to_string()),
    );

    // playlist: first list: binding on the synth host.
    for binding in &scenario.bindings {
        if let Binding::List(list) = binding {
            if list.on.is_none() {
                let filter = playlist_filter_for_formats(&list.formats);
                let mut pl = serde_json::Map::new();
                pl.insert(
                    "source".into(),
                    serde_json::Value::String(list.path.clone()),
                );
                pl.insert("filter".into(), serde_json::Value::String(filter.into()));
                obj.insert("playlist".into(), serde_json::Value::Object(pl));
                break;
            }
        }
    }

    // presentation: verbatim from the component's graph YAML, or a
    // synthesised default. We read the graph file to find the
    // `presentation:` block.
    let presentation = serve_component
        .and_then(|c| {
            read_component_presentation(scenario, scenario_path, c)
                .ok()
                .flatten()
        })
        .unwrap_or_else(default_presentation);
    obj.insert("presentation".into(), presentation);

    serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| Error::Config(format!("serialise scenario.json: {e}")))
}

/// Map a `list:` binding's `formats:` extension list to a coarse
/// content class the runtime shell uses to filter the playlist.
fn playlist_filter_for_formats(formats: &[String]) -> &'static str {
    let mut has_image = false;
    let mut has_audio = false;
    for f in formats {
        let f = f.to_ascii_lowercase();
        if matches!(
            f.as_str(),
            ".png" | ".jpg" | ".jpeg" | ".gif" | ".bmp" | ".webp"
        ) {
            has_image = true;
        }
        if matches!(f.as_str(), ".wav" | ".mp3" | ".aac" | ".ogg" | ".flac") {
            has_audio = true;
        }
    }
    match (has_image, has_audio) {
        (true, false) => "image",
        (false, true) => "audio",
        _ => "any",
    }
}

/// Read the named component's graph YAML and extract its top-level
/// `presentation:` block, if any. Returns the block as a JSON Value
/// so it can be embedded verbatim in `/scenario.json`.
fn read_component_presentation(
    scenario: &Scenario,
    scenario_path: &Path,
    comp_name: &str,
) -> Result<Option<serde_json::Value>> {
    let comp = scenario
        .components
        .get(comp_name)
        .ok_or_else(|| Error::Config(format!("undefined component `{comp_name}`")))?;
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let Some(graph_path) = &comp.graph else {
        return Ok(None);
    };
    let resolved = base.join(graph_path);
    let text = fs::read_to_string(&resolved)
        .map_err(|e| Error::Config(format!("read {}: {}", resolved.display(), e)))?;
    let value: serde_json::Value = serde_yaml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {}", resolved.display(), e)))?;
    Ok(value.get("presentation").cloned())
}

/// Default presentation for wasm graphs that don't declare one
/// explicitly. Picks a single display surface — the safe choice for
/// the image-viewer-style canonical, and a placeholder for graphs
/// that wire `wasm_browser_audio` but never set up a player UI.
fn default_presentation() -> serde_json::Value {
    serde_json::json!({
        "layout": "stacked",
        "surfaces": [
            { "id": "main", "role": "display", "module": "display" }
        ]
    })
}

/// Resolve a path relative to `base`, then canonicalise if possible.
/// Falls back to the joined path on canonicalise failure (target/wasm
/// artefacts won't exist until the build runs in PR 3).
fn absolute_or_join(base: &Path, p: &Path) -> PathBuf {
    let joined = base.join(p);
    joined.canonicalize().unwrap_or(joined)
}

/// Where the built wasm bundle for a component will live.  The
/// scenario runner pins this to `target/wasm/<stem>.wasm` (and passes
/// the same path to `build_one()` as `output_override` at spawn time)
/// so the synthesised host's `fs_path:` route and the actual build
/// artefact agree byte-for-byte.
fn bundle_path_for(
    _scenario_path: &Path,
    comp_name: &str,
    comp: &ComponentSpec,
) -> Result<PathBuf> {
    let rel = wasm_bundle_target_path(comp_name, comp)?;
    let mut abs = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    abs.push(rel);
    Ok(abs)
}

/// Render a `serde_json::Value` graph as a YAML document with a
/// human-readable header banner.  Used by `--print-synthesised` and
/// `--print-merged`.
fn render_value_as_yaml(value: &serde_json::Value, banner: &str) -> Result<String> {
    let body = serde_yaml::to_string(value)
        .map_err(|e| Error::Config(format!("serialise synthesised graph: {e}")))?;
    Ok(format!("{banner}\n{body}"))
}

/// Emit the synthesised host graph YAML to stdout (or anywhere — the
/// caller decides).  PR 2 builds a real `serde_json::Value` and
/// serialises it through `serde_yaml`, so the output round-trips
/// through `tools::board::validate_config`.
///
/// Returns `None` when the scenario has no synthesised host (every
/// binding has explicit `on:`); the caller should report "no
/// synthesised host" rather than printing an empty file.
pub fn render_synthesised_host(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<String>> {
    let Some(config) = synthesise_host_config(scenario, scenario_path)? else {
        return Ok(None);
    };
    let banner = format!(
        "# Synthesised by `fluxor run --print-synthesised {}` from\n\
         # the scenario's `host:` block + bindings whose `on:` is unset.\n\
         # This is a real Fluxor graph — freeze it as a linux YAML if you\n\
         # outgrow what the scenario primitive exposes.\n",
        scenario_path.display()
    );
    Ok(Some(render_value_as_yaml(&config, &banner)?))
}

// ----------------------------------------------------------------------------
// Binding route merger
// ----------------------------------------------------------------------------

/// Load a component's graph YAML and merge any bindings that target it
/// into its http module's `routes:` array.  Returns the augmented
/// `serde_json::Value` — exactly the config the kernel will see at
/// spawn time (PR 3).
///
/// Conflict detection: if a binding mounts at a `path:` already
/// declared by the component, the error names the binding, cites the
/// conflicting route's `path:`, and suggests the fix.
///
/// Host-FS gate: if the target component's effective target is not
/// linux (i.e. a pi5 graph without `runtime_override: linux`), the
/// merger refuses to inject `fs_path:`/`fs_list:` routes.
pub fn merge_bindings_for_component(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<serde_json::Value> {
    let comp = scenario.components.get(comp_name).ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: --print-merged references undefined component `{}`.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let graph_path = comp.graph.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: component `{}` has no `graph:` to merge into.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let resolved_graph = base.join(graph_path);
    let text = fs::read_to_string(&resolved_graph).map_err(|e| {
        Error::Config(format!(
            "scenario {}: reading {} for merge: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;
    let mut config: serde_json::Value = serde_yaml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "scenario {}: parsing {} for merge: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;

    // Apply runtime_override into the loaded config so the eventual
    // target validator runs against the effective target (§8 — though
    // the actual rebuild is PR 5).
    let effective_target = effective_target_for(comp);
    if let Some(target) = &effective_target {
        config["target"] = serde_json::Value::String(target.clone());

        // When a pi5/pico/rp graph is run through `runtime_override:
        // linux` the stack expander swaps the silicon-side network
        // modules (`rp1_gem`, `ip`, `wifi`, `cyw43`) for `linux_net`,
        // but it doesn't touch the user's hand-written wiring. A
        // graph that says `from: ip.net_out` still references `ip`
        // after expansion — and `ip` is no longer in the module list,
        // so config validation fails with
        //   `no manifest found for module 'ip'`.
        //
        // The two modules expose the same `net_in`/`net_out` ports
        // with the same `NetProto` content_type, so a name-level
        // rewrite is sufficient: replace `ip.X` with `linux_net.X`
        // in both endpoints of every wiring edge. We do this once,
        // immediately after the target flip so the rest of the
        // pipeline sees a self-consistent config.
        if target == "linux" || target == "qemu-virt" {
            rewrite_wiring_module(&mut config, "ip", "linux_net");
        }
    }

    // Host-FS gate: binding-injected fs_path routes work
    // only when the effective target has a host filesystem accessible
    // to the kernel.  Linux + qemu-virt (with -hda or virtfs) qualify; pi5
    // silicon without override does not.
    let target_str = config
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let has_bindings_for_us = scenario
        .bindings
        .iter()
        .any(|b| binding_targets(b, comp_name));
    if has_bindings_for_us && !target_supports_host_fs(&target_str) {
        return Err(Error::Config(format!(
            "scenario {}: binding(s) target `{}.<http>` but `{}`'s effective target is `{}`, \
             which has no shared host filesystem reachable from a static fs_path: route. \
             Either add `runtime_override: linux` (or qemu-virt) to the component, or stage the \
             asset onto the silicon's actual filesystem and write the route explicitly in \
             {}.",
            scenario_path.display(),
            comp_name,
            comp_name,
            target_str,
            graph_path.display(),
        )));
    }

    // Inject every binding whose `on:` targets this component into the
    // named http module's `routes:` table.
    for (idx, binding) in scenario.bindings.iter().enumerate() {
        let (target_module, new_routes) = match binding {
            Binding::Serve(s) if binding_targets(binding, comp_name) => {
                let on = s.on.as_ref().unwrap(); // gated by binding_targets
                let (_c, m) = on.split_once('.').ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings[{}] `on: {}` must be `<component>.<module>`",
                        scenario_path.display(),
                        idx,
                        on
                    ))
                })?;
                (
                    m.to_string(),
                    serve_binding_routes(s, scenario, base, scenario_path)?,
                )
            }
            Binding::List(l) if binding_targets(binding, comp_name) => {
                let on = l.on.as_ref().unwrap();
                let (_c, m) = on.split_once('.').ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings[{}] `on: {}` must be `<component>.<module>`",
                        scenario_path.display(),
                        idx,
                        on
                    ))
                })?;
                (m.to_string(), vec![list_binding_route(l, base)?])
            }
            _ => continue,
        };

        inject_routes_into_module(
            &mut config,
            &target_module,
            new_routes,
            comp_name,
            &resolved_graph,
            idx,
            binding,
            scenario_path,
        )?;
    }

    Ok(config)
}

fn binding_targets(b: &Binding, comp_name: &str) -> bool {
    let on = match b {
        Binding::Serve(s) => s.on.as_deref(),
        Binding::List(l) => l.on.as_deref(),
    };
    match on {
        Some(s) => s.split_once('.').map(|(c, _)| c) == Some(comp_name),
        None => false,
    }
}

fn effective_target_for(comp: &ComponentSpec) -> Option<String> {
    comp.runtime_override.clone()
}

/// Rewrite `from:` / `to:` strings in the config's `wiring:` array
/// that reference `<old_name>.<port>` to `<new_name>.<port>`.
///
/// Used at the runtime_override pivot: when a silicon graph
/// references the silicon-side net module by name (`ip`) but the
/// expanded linux stack provides `linux_net` with the same port
/// surface (`net_in`/`net_out` carrying `NetProto`), we patch the
/// user's wiring so it points at the module the linux stack
/// actually exports. No-op when neither endpoint references
/// `old_name`.
///
/// Only the leading `<name>.` segment is rewritten; ports are
/// untouched. Wiring entries that aren't of the canonical
/// `"module.port"` shape are left alone.
fn rewrite_wiring_module(config: &mut serde_json::Value, old_name: &str, new_name: &str) {
    let Some(wiring) = config.get_mut("wiring").and_then(|w| w.as_array_mut()) else {
        return;
    };
    let prefix = format!("{old_name}.");
    let replacement = format!("{new_name}.");
    for edge in wiring {
        for field in ["from", "to"] {
            let Some(val) = edge.get_mut(field) else {
                continue;
            };
            let Some(s) = val.as_str() else { continue };
            if let Some(rest) = s.strip_prefix(&prefix) {
                *val = serde_json::Value::String(format!("{replacement}{rest}"));
            }
        }
    }
}

fn target_supports_host_fs(target: &str) -> bool {
    matches!(target, "linux" | "qemu-virt")
}

/// Per-target ceiling on a route's `fs_path:` byte length.  Must
/// agree with `modules/sdk/config.rs::http::MAX_FS_PATH` for the
/// effective target — over-length paths get silently truncated by
/// the http module's route table, causing `linux_fs_dispatch::OPEN`
/// to operate on the wrong filename (typically creating an empty
/// file via `O_CREAT`) and surfacing as 200-OK-with-0-byte-body
/// responses.  Discovered while bringing PR 6's image_viewer
/// scenario end-to-end.
const MAX_FS_PATH_HOST: usize = 256;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
const MAX_FS_PATH_EMBEDDED: usize = 64;

fn check_fs_path_length(
    fs_path: &Path,
    binding_idx: usize,
    binding_desc: &str,
    scenario_path: &Path,
) -> Result<()> {
    let len = fs_path.as_os_str().as_encoded_bytes().len();
    if len > MAX_FS_PATH_HOST {
        return Err(Error::Config(format!(
            "scenario {}: bindings[{}] `{}` resolves to {} ({} bytes), which exceeds the \
             host http module's MAX_FS_PATH ceiling of {}. Move the asset under a \
             shorter path, or extend `modules/sdk/config.rs::http::MAX_FS_PATH`.",
            scenario_path.display(),
            binding_idx,
            binding_desc,
            fs_path.display(),
            len,
            MAX_FS_PATH_HOST,
        )));
    }
    Ok(())
}

fn serve_binding_routes(
    s: &ServeBinding,
    scenario: &Scenario,
    base: &Path,
    scenario_path: &Path,
) -> Result<Vec<serde_json::Value>> {
    let comp = scenario.components.get(&s.serve).ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: bindings reference undefined component `{}`",
            scenario_path.display(),
            s.serve
        ))
    })?;
    // host_page is OPTIONAL — when omitted, the canonical wasm
    // runtime shell embedded in fluxor-tools is mounted instead.
    // Custom shells (test harness, bespoke research UIs) still set
    // `host_page:` explicitly to override with an on-disk file.
    let override_page_path: Option<PathBuf> =
        comp.host_page.as_ref().map(|hp| absolute_or_join(base, hp));
    let bundle_path = bundle_path_for(scenario_path, &s.serve, comp)?;
    let bundle_url = if s.prefix == "/" {
        "/fluxor.wasm".to_string()
    } else {
        format!("{}/fluxor.wasm", s.prefix.trim_end_matches('/'))
    };
    let desc = format!("serve: {}", s.serve);
    if let Some(ref p) = override_page_path {
        check_fs_path_length(p, 0, &desc, scenario_path)?;
    }
    check_fs_path_length(&bundle_path, 0, &desc, scenario_path)?;

    // /<prefix>/host_shims.js — canonical wasm host shim. Embedded
    // in fluxor-tools at compile time so the orchestrator is
    // self-contained; same kernel ABI as the synth host's root
    // /host_shims.js route.
    let shims_url = if s.prefix == "/" {
        "/host_shims.js".to_string()
    } else {
        format!("{}/host_shims.js", s.prefix.trim_end_matches('/'))
    };
    let scenario_json_url = if s.prefix == "/" {
        "/scenario.json".to_string()
    } else {
        format!("{}/scenario.json", s.prefix.trim_end_matches('/'))
    };
    let scenario_json_body =
        build_scenario_json(scenario, scenario_path, Some(&s.serve), &bundle_url)?;

    // Serve the page at BOTH `<prefix>` and `<prefix>/`. The http
    // module's route matcher is exact-only for non-trailing-slash
    // routes (and prefix-only for trailing-slash routes), so a
    // browser navigating to `/viewer/` (the natural folder-style
    // URL the user types) would 404 against a `/viewer` route, and
    // vice versa. Two routes is the simplest fix; route table has
    // headroom (MAX_ROUTES=8, this binding uses 5 — page+slash-page
    // +wasm+shims+scenario).
    let prefix_no_slash = s.prefix.trim_end_matches('/').to_string();
    let prefix_with_slash = if prefix_no_slash.is_empty() {
        "/".to_string()
    } else {
        format!("{prefix_no_slash}/")
    };
    // Build the page-route value (embedded body OR override fs_path).
    let make_page_route = |path: String| -> serde_json::Value {
        if let Some(ref override_path) = override_page_path {
            serde_json::json!({
                "path": path,
                "fs_path": override_path.display().to_string(),
                "content_type": "text/html",
            })
        } else {
            serde_json::json!({
                "path": path,
                "body": canonical_runtime_html_body(),
                "content_type": "text/html",
            })
        }
    };
    let mut routes = vec![make_page_route(if prefix_no_slash.is_empty() {
        "/".to_string()
    } else {
        prefix_no_slash.clone()
    })];
    if prefix_with_slash != prefix_no_slash && prefix_no_slash != "/" && !prefix_no_slash.is_empty()
    {
        routes.push(make_page_route(prefix_with_slash));
    }
    routes.push(serde_json::json!({
        "path": bundle_url,
        "fs_path": bundle_path.display().to_string(),
        "content_type": "application/wasm",
    }));
    routes.push(serde_json::json!({
        "path": shims_url,
        "body": canonical_host_shims_js_body(),
        "content_type": "application/javascript",
    }));
    routes.push(serde_json::json!({
        "path": scenario_json_url,
        "body": scenario_json_body,
        "content_type": "application/json",
    }));
    Ok(routes)
}

fn list_binding_route(l: &ListBinding, base: &Path) -> Result<serde_json::Value> {
    let dir = absolute_or_join(base, &l.list);
    let desc = format!("list: {}", l.list.display());
    check_fs_path_length(&dir, 0, &desc, base)?;
    let mut entry = serde_json::Map::new();
    entry.insert("path".into(), serde_json::Value::String(l.path.clone()));
    entry.insert(
        "fs_list".into(),
        serde_json::Value::String(dir.display().to_string()),
    );
    if !l.formats.is_empty() {
        entry.insert(
            "fs_filter".into(),
            serde_json::Value::String(l.formats.join(",")),
        );
    }
    Ok(serde_json::Value::Object(entry))
}

#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
fn inject_routes_into_module(
    config: &mut serde_json::Value,
    module_name: &str,
    new_routes: Vec<serde_json::Value>,
    comp_name: &str,
    comp_path: &Path,
    binding_idx: usize,
    binding: &Binding,
    scenario_path: &Path,
) -> Result<()> {
    let modules = config
        .get_mut("modules")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: component `{}` graph {} has no `modules:` array",
                scenario_path.display(),
                comp_name,
                comp_path.display()
            ))
        })?;

    let module = modules
        .iter_mut()
        .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(module_name))
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: bindings[{}] `on: {}.{}` — component `{}`'s graph ({}) has no \
                 module named `{}`.",
                scenario_path.display(),
                binding_idx,
                comp_name,
                module_name,
                comp_name,
                comp_path.display(),
                module_name,
            ))
        })?;

    let existing_paths: HashSet<String> = module
        .get("routes")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for new_route in &new_routes {
        let new_path = new_route
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        if existing_paths.contains(new_path) {
            let binding_desc = match binding {
                Binding::Serve(s) => format!("serve: {}", s.serve),
                Binding::List(l) => format!("list: {}", l.list.display()),
            };
            let suggested_prefix = match binding {
                Binding::Serve(s) => format!(
                    " Disambiguate by adding `prefix: /{}` to the binding.",
                    s.serve
                ),
                Binding::List(_) => " Disambiguate with a different `path:` on the binding.".into(),
            };
            return Err(Error::Config(format!(
                "scenario {}: binding `{}` cannot mount at {:?} on {}.{} — that route is \
                 already declared in {}. {}",
                scenario_path.display(),
                binding_desc,
                new_path,
                comp_name,
                module_name,
                comp_path.display(),
                suggested_prefix,
            )));
        }
    }

    let routes_array = module
        .as_object_mut()
        .unwrap()
        .entry("routes")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: module `{}.{}` has a non-array `routes:` field — graph YAML \
                 is malformed.",
                scenario_path.display(),
                comp_name,
                module_name
            ))
        })?;
    routes_array.extend(new_routes);
    Ok(())
}

/// Render a merged component config as YAML with a banner header
/// pointing back at the scenario.  Used by `--print-merged`.
pub fn render_merged_component(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<String> {
    let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
    let banner = format!(
        "# Merged config for component `{}` of scenario {}.\n\
         # Synthesised by `fluxor run --print-merged {}`.\n\
         # Original graph YAML augmented with binding-injected routes.\n",
        comp_name,
        scenario_path.display(),
        comp_name,
    );
    render_value_as_yaml(&merged, &banner)
}

// ----------------------------------------------------------------------------
// PR 3 helpers: spawn-side support (build artefact paths, URL,
// synthesised-host YAML on disk)
// ----------------------------------------------------------------------------

/// Working directory for build artefacts derived from a scenario.
/// Lives under `target/scenarios/<name>/` so multiple scenarios on
/// the same machine don't trample each other's synthesised host YAML
/// or config.bin output.
pub fn scenario_work_dir(scenario: &Scenario) -> PathBuf {
    PathBuf::from(format!("target/scenarios/{}", scenario.name))
}

/// Write the synthesised host graph to disk as a real YAML file so
/// the existing `build_one()` path can consume it.  Returns the path.
/// Returns `Ok(None)` when the scenario has no synthesised host.
pub fn write_synthesised_host_yaml(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<PathBuf>> {
    let Some(config) = synthesise_host_config(scenario, scenario_path)? else {
        return Ok(None);
    };
    let work_dir = scenario_work_dir(scenario);
    fs::create_dir_all(&work_dir).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot create work dir {}: {}",
            scenario_path.display(),
            work_dir.display(),
            e
        ))
    })?;
    let banner = format!(
        "# Auto-generated by `fluxor run {}` from the scenario's `host:` block.\n\
         # DO NOT EDIT — overwritten on every run.\n",
        scenario_path.display()
    );
    let yaml = render_value_as_yaml(&config, &banner)?;
    let host_path = work_dir.join("host.yaml");
    fs::write(&host_path, yaml).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot write {}: {}",
            scenario_path.display(),
            host_path.display(),
            e
        ))
    })?;
    Ok(Some(host_path))
}

/// URL of the synthesised host (`http://localhost:<port>/`), if any.
pub fn synthesised_host_url(scenario: &Scenario) -> Option<String> {
    scenario
        .host
        .as_ref()
        .map(|h| format!("http://localhost:{}/", h.port))
}

/// Port the synthesised host listens on, if any.
pub fn synthesised_host_port(scenario: &Scenario) -> Option<u16> {
    scenario.host.as_ref().map(|h| h.port)
}

/// Where the wasm bundle for a component should land on disk.  The
/// scenario runner passes this to `build_one()` as an explicit
/// `output_override` so the synthesised host's `fs_path:` route and
/// the actual build artefact agree byte-for-byte.
pub fn wasm_bundle_target_path(comp_name: &str, comp: &ComponentSpec) -> Result<PathBuf> {
    let graph = comp
        .graph
        .as_ref()
        .ok_or_else(|| Error::Config(format!("component `{comp_name}` has no `graph:`")))?;
    let stem = graph.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        Error::Config(format!(
            "component `{comp_name}` graph has no filename stem"
        ))
    })?;
    Ok(PathBuf::from(format!("target/wasm/{stem}.wasm")))
}

/// True when this scenario has exactly one component. Kept for
/// introspection / future fast-path dispatch; PR 4's spawn path
/// handles single-component scenarios as a degenerate case of the
/// generic multi-component flow.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub fn is_single_component(scenario: &Scenario) -> bool {
    scenario.components.len() == 1
}

/// Effective target for a component: the `runtime_override:` (if set)
/// wins, otherwise the graph's declared `target:`. Used by PR 4 to
/// classify components as wasm (passive, build-bundle-only) vs.
/// linux/qemu-virt/pi5 (active, spawn-a-kernel).
pub fn effective_target(scenario_path: &Path, comp: &ComponentSpec) -> String {
    if let Some(ovr) = &comp.runtime_override {
        return ovr.clone();
    }
    let Some(base) = scenario_path.parent() else {
        return String::new();
    };
    let Some(graph) = &comp.graph else {
        return String::new();
    };
    sniff_graph_target(&base.join(graph)).unwrap_or_default()
}

/// Find the http module's `port:` in a parsed component config.
/// Returns `None` for graphs that have no http module or no port —
/// such components are still legal in PR 4 (e.g. headless capturers),
/// but the readiness probe falls back to "child has exited" instead
/// of "child bound a listener".
pub fn extract_http_port(config: &serde_json::Value) -> Option<u16> {
    config.get("modules")?.as_array()?.iter().find_map(|m| {
        // Any module that binds an HTTP listener. `http` is Wave's protocol
        // module, which downstream graphs name directly and which exposes
        // `port`. A scenario naming its listener anything else needs an
        // explicit port hint in the schema.
        let name = m.get("name").and_then(|n| n.as_str())?;
        if name != "http" {
            return None;
        }
        m.get("port")
            .and_then(|p| p.as_u64())
            .and_then(|p| u16::try_from(p).ok())
    })
}

/// Write a merged-config YAML to disk under
/// `target/scenarios/<name>/<component>.yaml` so PR 4's spawn path
/// can hand it straight to `build_one()`.
pub fn write_merged_component_yaml(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<PathBuf> {
    let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
    let work_dir = scenario_work_dir(scenario);
    fs::create_dir_all(&work_dir).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot create work dir {}: {}",
            scenario_path.display(),
            work_dir.display(),
            e
        ))
    })?;
    let banner = format!(
        "# Auto-generated by `fluxor run {}` — merged config for component `{}`.\n\
         # Original graph YAML augmented with binding-injected routes.\n\
         # DO NOT EDIT — overwritten on every run.\n",
        scenario_path.display(),
        comp_name,
    );
    let yaml = render_value_as_yaml(&merged, &banner)?;
    let path = work_dir.join(format!("{comp_name}.yaml"));
    fs::write(&path, yaml).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot write {}: {}",
            scenario_path.display(),
            path.display(),
            e
        ))
    })?;
    Ok(path)
}

// ----------------------------------------------------------------------------
// PR 5: module hardware_targets validation against effective target
// ----------------------------------------------------------------------------

/// Per-effective-target aliases — which manifest `hardware_targets:`
/// strings the runtime accepts.
///
/// Delegates to the `targets/` registry: a module is placeable when its
/// `hardware_targets` names the target's module silicon, or the host
/// token itself for host targets (linux fluxor-linux reuses bcm2712 PIC
/// modules, so `["bcm2712"]` is legal under `runtime_override: linux`).
/// Boards never appear in `hardware_targets` — a board id there is the
/// level error this validator exists to catch
/// (standards/target_consolidation.md §2 rule 1).
fn target_aliases(target: &str) -> Vec<String> {
    match crate::target::load_target(target, &crate::project::root()) {
        Ok(desc) => desc.accepted_hardware_targets(),
        Err(_) => Vec::new(),
    }
}

/// Standard module-search directories: the one tier list
/// (`manifest::MODULE_TIERS`), so the scenario validator sees exactly
/// the manifests the builder and config resolution see.
const STANDARD_MANIFEST_DIRS: &[&str] = crate::manifest::MODULE_TIERS;

/// Slim toml schema for `validate_module_targets`. We re-parse the
/// manifest here (rather than going through `tools::manifest::Manifest`)
/// because the parsed `Manifest` struct lossy-encodes hardware_targets
/// into a u16 RP-family mask — losing the original strings we need to
/// cite back to the user.
#[derive(Deserialize)]
struct ManifestTargetsOnly {
    hardware_targets: Option<Vec<String>>,
}

/// PR 5: walk every component's graph and check that each declared
/// module's `manifest.toml` carries the effective target string (with
/// the alias map). Errors cite the manifest path so the user can
/// `grep` the line.
///
/// Called from `revalidate_all` so `--validate-only` catches mask
/// mismatches at scenario-load time, before any build runs.
pub fn validate_module_targets(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let project_root = crate::project::root();

    for (comp_name, comp) in &scenario.components {
        let target = effective_target(scenario_path, comp);
        if target.is_empty() {
            continue;
        }
        let Some(graph_rel) = &comp.graph else {
            continue;
        };
        let graph_abs = base.join(graph_rel);
        let yaml: serde_json::Value = match fs::read_to_string(&graph_abs)
            .ok()
            .and_then(|t| serde_yaml::from_str(&t).ok())
        {
            Some(v) => v,
            None => continue, // graph existence already checked by validate()
        };
        let modules = match yaml.get("modules").and_then(|m| m.as_array()) {
            Some(m) => m,
            None => continue,
        };
        let aliases = target_aliases(&target);
        for module in modules {
            let module_name = module
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed>");
            let type_name = module
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or(module_name);
            let Some(manifest_path) = find_manifest_for(type_name, &project_root) else {
                // Not finding a manifest is not a PR 5 concern — the
                // build path catches it with a clearer error.  Skip.
                continue;
            };
            let manifest_targets = match read_manifest_hardware_targets(&manifest_path) {
                Ok(v) => v,
                Err(_) => continue, // unparseable manifest — build path will report.
            };
            // Empty hardware_targets in the manifest is permissive
            // ("works everywhere"), which some built-ins rely on.
            // Don't reject; the build path will catch any real
            // mismatch.
            if manifest_targets.is_empty() {
                continue;
            }
            if !manifest_targets
                .iter()
                .any(|m| aliases.iter().any(|a| a == m))
            {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` uses module `{}` (type `{}`) — its \
                     manifest at {} declares hardware_targets = {:?}, which does not \
                     match the component's effective target `{}` (accepted aliases: {:?}). \
                     Either remove `runtime_override:`, or pick a different module type, \
                     or extend the manifest's hardware_targets list.",
                    scenario_path.display(),
                    comp_name,
                    module_name,
                    type_name,
                    manifest_path.display(),
                    manifest_targets,
                    target,
                    aliases,
                )));
            }
        }
    }
    Ok(())
}

fn find_manifest_for(type_name: &str, project_root: &Path) -> Option<PathBuf> {
    for dir in STANDARD_MANIFEST_DIRS {
        let candidate = project_root.join(dir).join(type_name).join("manifest.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn read_manifest_hardware_targets(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {}", path.display(), e)))?;
    let parsed: ManifestTargetsOnly = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {}", path.display(), e)))?;
    Ok(parsed.hardware_targets.unwrap_or_default())
}

// ----------------------------------------------------------------------------
// Re-validation
// ----------------------------------------------------------------------------

/// Re-validate every component config (synthesised host + every
/// merged component graph) using the existing
/// `tools::board::validate_config` machinery. This catches
/// binding-induced misconfigurations at scenario-load time rather than
/// at kernel-load time with worse error messages.
///
/// Errors aggregate across components; the caller sees one Err per
/// validation pass.
pub fn revalidate_all(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    use crate::target::load_target;
    let project_root = crate::project::root();

    // PR 5: module hardware_targets ↔ effective_target consistency,
    // checked before any expensive validation downstream.
    validate_module_targets(scenario, scenario_path)?;

    // Synthesised host first, if present.
    if let Some(mut host_cfg) = synthesise_host_config(scenario, scenario_path)? {
        let target_desc = load_target("linux", &project_root)?;
        let _ = &mut host_cfg; // future: stack_expand may mutate
        let result = crate::board::validate_config(&host_cfg, &target_desc)?;
        if !result.is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: synthesised host failed re-validation: {}",
                scenario_path.display(),
                result.errors.join("; ")
            )));
        }
    }

    // Each component that receives at least one binding gets its
    // merged config re-validated against the effective target.
    let mut touched: HashSet<&str> = HashSet::new();
    for b in &scenario.bindings {
        let on = match b {
            Binding::Serve(s) => s.on.as_deref(),
            Binding::List(l) => l.on.as_deref(),
        };
        if let Some(on) = on {
            if let Some((c, _)) = on.split_once('.') {
                touched.insert(c);
            }
        }
    }
    for comp_name in touched {
        let comp = scenario.components.get(comp_name).unwrap();
        let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
        let effective = effective_target_for(comp)
            .or_else(|| {
                merged
                    .get("target")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "linux".to_string());
        let target_desc = match load_target(&effective, &project_root) {
            Ok(d) => d,
            Err(_) => {
                // Unknown target name — skip the validate step but
                // warn.  Can happen for board IDs the registry doesn't
                // yet know about; PR 5 will tighten the override path.
                eprintln!(
                    "warning: scenario {}: no target descriptor for `{}`; skipping \
                     merged-config re-validation for component `{}`.",
                    scenario_path.display(),
                    effective,
                    comp_name
                );
                continue;
            }
        };
        let result = crate::board::validate_config(&merged, &target_desc)?;
        if !result.is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: merged config for component `{}` failed re-validation: {}",
                scenario_path.display(),
                comp_name,
                result.errors.join("; ")
            )));
        }
    }
    Ok(())
}

// ============================================================================
// `--list`
// ============================================================================

/// Enumerate every runnable scenario in a directory (non-recursive).
/// Kind is detected from file content (`kind: scenario` line), not
/// from filename — the legacy `*.scenario.yaml` infix is gone.
///
/// Two kinds of runnable orchestration:
///   1. standalone `kind: scenario` file (multi-graph harness).
///   2. graph YAML carrying an inline `scenario:` block.
///
/// Returns `(path, name)` pairs — `name` is the scenario's `name:`
/// field, or the file stem if `name:` is missing.
pub fn list_scenarios(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    if !dir.is_dir() {
        return Err(Error::Config(format!(
            "--list: {} is not a directory",
            dir.display()
        )));
    }
    let mut out = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| Error::Config(format!("--list: read_dir({}): {}", dir.display(), e)))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !(name.ends_with(".yaml") || name.ends_with(".yml")) {
            continue;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        let display_name = if is_scenario_file(&path) {
            // Standalone scenario — best-effort parse. A file that
            // fails to parse still gets listed with an error tag so
            // the user can see it's there.
            match parse(&path) {
                Ok(s) => s.name,
                Err(_) => format!(
                    "{} (parse error)",
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or("?")
                ),
            }
        } else {
            // Inline-scenario probe: only list the graph when it
            // actually carries a `scenario:` block. Plain graphs
            // (e.g. the thin viewer half of a split) aren't
            // standalone-runnable and don't belong in --list.
            match synthesize_from_graph(&path) {
                Ok(Some(s)) => s.name,
                Ok(None) => continue,
                Err(_) => format!(
                    "{} (parse error)",
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or("?")
                ),
            }
        };
        out.push((path, display_name));
    }
    Ok(out)
}

// ============================================================================
// `--graph` (Graphviz DOT)
// ============================================================================

/// Emit a Graphviz DOT representation of a scenario: nodes are
/// components (plus an implicit `host` node if `host:` is set), edges
/// are bindings.  Intentionally tiny — `dot -Tpng` is the consumer.
pub fn render_graphviz(scenario: &Scenario) -> String {
    let mut out = String::new();
    out.push_str(&format!("digraph \"{}\" {{\n", scenario.name));
    out.push_str("  rankdir=LR;\n  node [shape=box, style=rounded];\n");
    if scenario.host.is_some() {
        out.push_str("  host [shape=box, style=\"rounded,filled\", fillcolor=\"#eef\", label=\"host\\n(synthesised)\"];\n");
    }
    let mut nodes: HashSet<&str> = scenario.components.keys().map(String::as_str).collect();
    for name in &nodes {
        out.push_str(&format!("  \"{name}\" [label=\"{name}\"];\n"));
    }
    nodes.clear();
    for binding in &scenario.bindings {
        match binding {
            Binding::Serve(s) => {
                let dst =
                    s.on.as_deref()
                        .and_then(|on| on.split_once('.'))
                        .map(|(c, _)| c.to_string())
                        .unwrap_or_else(|| "host".to_string());
                out.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"serve\"];\n",
                    s.serve, dst
                ));
            }
            Binding::List(l) => {
                let dst =
                    l.on.as_deref()
                        .and_then(|on| on.split_once('.'))
                        .map(|(c, _)| c.to_string())
                        .unwrap_or_else(|| "host".to_string());
                out.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"list {}\"];\n",
                    l.list.display(),
                    dst,
                    l.path
                ));
            }
        }
    }
    out.push_str("}\n");
    out
}

