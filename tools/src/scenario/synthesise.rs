// ============================================================================
// Host synthesis, the document root and re-validation
// ============================================================================

/// The bound name the synthesised host includes for its file server. The
/// project the scenario belongs to binds it under `[uses.stacks]`; the
/// interface a bound stack must fit is `docs/architecture/wasm_browser_host.md`
/// § Serving: params `port` (integer) and `root` (string, an absolute
/// directory), exports `net_in` / `net_out` (`NetProto`).
pub const FILE_SERVER: &str = "file_server";

/// The instance name the host includes [`FILE_SERVER`] as.
const HOST_INCLUDE_AS: &str = "web";

/// Construct the synthesised host graph as a `serde_json::Value`: a linux
/// graph that includes `@file_server` and points it at the scenario's
/// document root ([`write_document_root`], written here). Returns `None`
/// when the scenario has no `host:` block.
///
/// The graph names no module: what serves the files is the stack the
/// scenario's project binds. Its includes are unexpanded, as a hand-written
/// graph's are; the build and [`revalidate_all`] expand them against the
/// scenario's project.
pub fn synthesise_host_config(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<serde_json::Value>> {
    let Some(host) = &scenario.host else {
        return Ok(None);
    };
    let root = write_document_root(scenario, scenario_path)?;
    let net_in = format!("{HOST_INCLUDE_AS}.net_in");
    let net_out = format!("{HOST_INCLUDE_AS}.net_out");
    let config = serde_json::json!({
        "target": "linux",
        // Fluxor's own network: `linux_net` on Linux.
        "platform": { "net": {} },
        // The net_in/net_out pair with `linux_net` is a 2-cycle; the
        // scheduler refuses a cycle the graph does not accept, and a stack
        // carries no `scheduler:`, so the host graph accepts it.
        "scheduler": { "accept_cycles": true },
        "include": [{
            "stack": format!("@{FILE_SERVER}"),
            "as": HOST_INCLUDE_AS,
            "params": {
                "port": host.port,
                "root": root.display().to_string(),
            },
        }],
        "wiring": [
            { "from": "linux_net.net_out", "to": net_in },
            { "from": net_out, "to": "linux_net.net_in" },
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
const CANONICAL_RUNTIME_HTML_RAW: &str =
    include_str!("../../../src/platform/wasm/host/runtime.html");
const CANONICAL_HOST_SHIMS_JS_RAW: &str =
    include_str!("../../../src/platform/wasm/host/host_shims.js");
/// Emulation Worker (?worker=1): runs the kernel + step pump off the main thread.
/// importScripts'es the canonical host_shims.js; reused across every scenario.
const CANONICAL_WORKER_JS_RAW: &str =
    include_str!("../../../src/platform/wasm/host/fluxor-worker.js");
/// Generic browser-overlay renderer (`presentation.shell`). Inlined
/// into the served page, so the shell stays one document. Defines
/// `window.FluxorOverlay`; dormant until a scenario carries a
/// `presentation.shell` block.
const CANONICAL_OVERLAY_JS_RAW: &str =
    include_str!("../../../src/platform/wasm/host/browser_overlay_runtime.js");
/// Marker in runtime.html where the overlay `<script>` is injected.
const OVERLAY_MARKER: &str = "<!--FLUXOR_OVERLAY_RUNTIME-->";

/// The canonical runtime shell, with the overlay renderer inlined at its
/// marker (a no-op when the marker is absent).
fn canonical_runtime_html() -> String {
    CANONICAL_RUNTIME_HTML_RAW.replace(
        OVERLAY_MARKER,
        &format!("<script>\n{CANONICAL_OVERLAY_JS_RAW}\n</script>"),
    )
}

/// Write the scenario's document root, `<work dir>/root`, afresh, and
/// return its absolute path. Under each `serve:` binding's `prefix` (the
/// root itself for `/`) it holds:
///
/// - `index.html`: the canonical shell, or a link to the component's
///   `host_page`;
/// - `fluxor.wasm`: a link to the component's bundle, which the run builds
///   there;
/// - `host_shims.js`, `fluxor-worker.js`;
/// - `scenario.json`, and `fluxor-manifest.json` when there is a `list:`
///   binding;
/// - each `list:` binding's directory, linked at its `path`.
///
/// With no `serve:` binding the root holds the files other than
/// `index.html` and `fluxor.wasm`. A manifest key is `<path>/<relpath>`:
/// relative to the page, so a key fetched as a URL resolves to the file
/// under whichever prefix serves the page. Every name is placed once: a
/// prefix, a list path or a file landing where another already is, or
/// inside a linked directory, is refused rather than written into the
/// linked tree.
pub fn write_document_root(scenario: &Scenario, scenario_path: &Path) -> Result<PathBuf> {
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let at = |what: String, e: std::io::Error| {
        Error::Config(format!("scenario {}: {what}: {e}", scenario_path.display()))
    };
    let work_dir = scenario_work_dir(scenario, scenario_path);
    let root = work_dir.join("root");
    // A link inside is removed as a link: its target is never touched.
    if root.symlink_metadata().is_ok() {
        fs::remove_dir_all(&root)
            .map_err(|e| at(format!("cannot clear {}", root.display()), e))?;
    }
    fs::create_dir_all(&root).map_err(|e| at(format!("cannot create {}", root.display()), e))?;

    let mut manifest: Vec<serde_json::Value> = Vec::new();
    let mut lists: Vec<(&ListBinding, PathBuf)> = Vec::new();
    for binding in &scenario.bindings {
        if let Binding::List(list) = binding {
            let target = absolute_or_join(base, &list.list);
            manifest.extend(fluxor_manifest_entries(&target, &list.path, &list.formats));
            lists.push((list, target));
        }
    }
    let manifest = (!lists.is_empty()).then(|| {
        manifest.sort_by(|a, b| {
            a["key"]
                .as_str()
                .unwrap_or("")
                .cmp(b["key"].as_str().unwrap_or(""))
        });
        serde_json::Value::Array(manifest).to_string()
    });

    let serves: Vec<&ServeBinding> = scenario
        .bindings
        .iter()
        .filter_map(|b| match b {
            Binding::Serve(s) => Some(s),
            Binding::List(_) => None,
        })
        .collect();
    let sites: Vec<(Option<&ServeBinding>, &str)> = if serves.is_empty() {
        vec![(None, "/")]
    } else {
        serves.iter().map(|s| (Some(*s), s.prefix.as_str())).collect()
    };
    for (serve, prefix) in sites {
        let dir = place(&root, prefix, scenario_path)?;
        if dir
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Error::Config(format!(
                "scenario {}: `prefix: {prefix}` is where the document root links a `list:` \
                 binding's directory — give the `serve:` another `prefix`",
                scenario_path.display(),
            )));
        }
        if dir.join("scenario.json").symlink_metadata().is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: two `serve:` bindings share `prefix: {prefix}` — every \
                 `serve:` lands on the host, so give each a distinct `prefix`",
                scenario_path.display(),
            )));
        }
        fs::create_dir_all(&dir).map_err(|e| at(format!("cannot create {}", dir.display()), e))?;
        let mut files: Vec<(&str, String)> = vec![
            ("host_shims.js", CANONICAL_HOST_SHIMS_JS_RAW.to_string()),
            ("fluxor-worker.js", CANONICAL_WORKER_JS_RAW.to_string()),
        ];
        let bundle_url = format!("{}/fluxor.wasm", prefix.trim_end_matches('/'));
        if let Some(serve) = serve {
            let comp = scenario.components.get(&serve.serve).ok_or_else(|| {
                Error::Config(format!(
                    "scenario {}: bindings reference undefined component `{}`",
                    scenario_path.display(),
                    serve.serve
                ))
            })?;
            match &comp.host_page {
                Some(page) => link(&absolute_or_join(base, page), &dir.join("index.html"))
                    .map_err(|e| at(format!("cannot link {}", page.display()), e))?,
                None => files.push(("index.html", canonical_runtime_html())),
            }
            let bundle = wasm_bundle_target_path(scenario_path, &serve.serve, comp)?;
            link(&bundle, &dir.join("fluxor.wasm"))
                .map_err(|e| at(format!("cannot link {}", bundle.display()), e))?;
        }
        files.push((
            "scenario.json",
            build_scenario_json(
                scenario,
                scenario_path,
                serve.map(|s| s.serve.as_str()),
                &bundle_url,
            )?,
        ));
        if let Some(m) = &manifest {
            files.push(("fluxor-manifest.json", m.clone()));
        }
        for (name, contents) in files {
            let path = dir.join(name);
            if path.symlink_metadata().is_ok() {
                return Err(Error::Config(format!(
                    "scenario {}: `prefix: {prefix}` places {name} where the document root \
                     already holds it — give the `serve:` another `prefix`",
                    scenario_path.display(),
                )));
            }
            fs::write(&path, contents)
                .map_err(|e| at(format!("cannot write {}", path.display()), e))?;
        }
        for (list, target) in &lists {
            let at_path = place(&dir, &list.path, scenario_path)?;
            if at_path.symlink_metadata().is_ok() {
                return Err(Error::Config(format!(
                    "scenario {}: `list: {}` is placed at `{}` under `prefix: {prefix}`, which \
                     the document root already holds — give the binding another `path:`",
                    scenario_path.display(),
                    list.list.display(),
                    list.path
                )));
            }
            if let Some(parent) = at_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| at(format!("cannot create {}", parent.display()), e))?;
            }
            link(target, &at_path)
                .map_err(|e| at(format!("cannot link {}", target.display()), e))?;
        }
    }
    Ok(root)
}

/// Where URL path `url` lands under `base`, refusing a path through a
/// linked directory (a `list:` binding's): writing there would write into
/// the linked tree. `base` is the document root or a directory the root
/// holds, never a link.
fn place(base: &Path, url: &str, scenario_path: &Path) -> Result<PathBuf> {
    let mut at = base.to_path_buf();
    for part in url.split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." {
            return Err(Error::Config(format!(
                "scenario {}: `{url}` must not contain `.` or `..` segments",
                scenario_path.display()
            )));
        }
        if at
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Error::Config(format!(
                "scenario {}: `{url}` lies inside a `list:` binding's directory — give it a \
                 path of its own",
                scenario_path.display()
            )));
        }
        at.push(part);
    }
    Ok(at)
}

/// Link `target` at `at`: the file server follows symbolic links, so a
/// bundle the run builds later, a `host_page`, or a `list:` directory is
/// served from where it lives.
fn link(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

/// Walk a `list:` directory and build the `fluxor-manifest.json` entries
/// the wasm `storage.namespace` provider fetches at boot — one
/// `{ key, size, mtime, etag }` per file. Browsers can't `readdir` an
/// HTTP origin, so this synth-time directory snapshot is how a runtime
/// `storage.namespace` LIST enumerates shipped content. `key` is the
/// object key the `storage.object` provider fetches *as a URL*, so it
/// must be the file's path relative to the page — `<path_prefix>/<relpath>`
/// with forward slashes and no leading slash, matching where
/// [`write_document_root`] links the `list:` directory beside the page.
/// `formats` (if non-empty) restricts to those extensions.
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
/// The `playlist` field names the first `list:` binding's `path` (the
/// gallery); the shell reads its entries from `fluxor-manifest.json`, the
/// keys under that path. The `presentation` field is
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

    // playlist: the first list: binding.
    if let Some(list) = scenario.bindings.iter().find_map(|b| match b {
        Binding::List(l) => Some(l),
        Binding::Serve(_) => None,
    }) {
        let filter = playlist_filter_for_formats(&list.formats);
        let mut pl = serde_json::Map::new();
        pl.insert(
            "source".into(),
            serde_json::Value::String(list.path.clone()),
        );
        pl.insert("filter".into(), serde_json::Value::String(filter.into()));
        obj.insert("playlist".into(), serde_json::Value::Object(pl));
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
/// content class the runtime shell uses to filter the playlist. An
/// extension is written with or without its leading `.`, as the manifest
/// takes it.
fn playlist_filter_for_formats(formats: &[String]) -> &'static str {
    let mut has_image = false;
    let mut has_audio = false;
    for f in formats {
        let f = f.trim_start_matches('.').to_ascii_lowercase();
        if matches!(f.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp") {
            has_image = true;
        }
        if matches!(f.as_str(), "wav" | "mp3" | "aac" | "ogg" | "flac") {
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
/// so it can be embedded verbatim in `scenario.json`.
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
/// Falls back to the joined path on canonicalise failure (a `target/wasm`
/// artefact does not exist until the scenario's build runs).
fn absolute_or_join(base: &Path, p: &Path) -> PathBuf {
    let joined = base.join(p);
    joined.canonicalize().unwrap_or(joined)
}

/// Render a `serde_json::Value` graph as a YAML document with a
/// human-readable header banner.  Used by `--print-synthesised` and
/// `--print-merged`.
fn render_value_as_yaml(value: &serde_json::Value, banner: &str) -> Result<String> {
    let body = serde_yaml::to_string(value)
        .map_err(|e| Error::Config(format!("serialise synthesised graph: {e}")))?;
    Ok(format!("{banner}\n{body}"))
}

/// Emit the synthesised host graph YAML, its includes unexpanded: what
/// `@file_server` resolves to is the scenario's project's binding, which
/// printing does not need. Writes the document root the graph names.
///
/// Returns `None` when the scenario has no `host:` block; the caller
/// should report "no synthesised host" rather than printing an empty
/// file.
pub fn render_synthesised_host(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<String>> {
    let Some(config) = synthesise_host_config(scenario, scenario_path)? else {
        return Ok(None);
    };
    let banner = format!(
        "# Synthesised by `fluxor run --print-synthesised {}` from\n\
         # the scenario's `host:` block and bindings. `@file_server` is the\n\
         # stack the scenario's project binds under [uses.stacks].\n",
        scenario_path.display()
    );
    Ok(Some(render_value_as_yaml(&config, &banner)?))
}

// ----------------------------------------------------------------------------
// Component config
// ----------------------------------------------------------------------------

/// Load a component's graph YAML as the run builds it: its
/// `runtime_override:`, if any, sets its target, and a silicon graph
/// overridden to linux or qemu-virt has its wiring to `ip` moved onto
/// `linux_net`. A scenario adds nothing else to a component's graph; a
/// component that serves its own routes writes them in that graph.
pub fn component_config(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<serde_json::Value> {
    let comp = scenario.components.get(comp_name).ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: no component `{}`.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let graph_path = comp.graph.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: component `{}` has no `graph:`.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let resolved_graph = base.join(graph_path);
    let text = fs::read_to_string(&resolved_graph).map_err(|e| {
        Error::Config(format!(
            "scenario {}: reading {}: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;
    let mut config: serde_json::Value = serde_yaml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "scenario {}: parsing {}: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;

    if let Some(target) = &comp.runtime_override {
        config["target"] = serde_json::Value::String(target.clone());
        // The linux stack provides `linux_net` where a silicon graph wires
        // `ip`; the two expose the same `net_in` / `net_out` ports carrying
        // `NetProto`, so a name-level rewrite of the graph's own edges keeps
        // the config self-consistent.
        if target == "linux" || target == "qemu-virt" {
            rewrite_wiring_module(&mut config, "ip", "linux_net");
        }
    }
    Ok(config)
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

/// Render a component's config ([`component_config`]) as YAML with a
/// banner header pointing back at the scenario.  Used by `--print-merged`.
pub fn render_merged_component(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<String> {
    let config = component_config(comp_name, scenario, scenario_path)?;
    let banner = format!(
        "# Config for component `{}` of scenario {}, as the run builds it.\n\
         # Printed by `fluxor run --print-merged {}`.\n",
        comp_name,
        scenario_path.display(),
        comp_name,
    );
    render_value_as_yaml(&config, &banner)
}

// ----------------------------------------------------------------------------
// Spawn-side support: build artefact paths, URL, synthesised-host YAML
// on disk
// ----------------------------------------------------------------------------

/// Working directory for build artefacts derived from a scenario:
/// `target/scenarios/<name>/` under the scenario's project root, from any
/// working directory. The host graph written there belongs to that
/// project, so its `@file_server` resolves against that project's
/// `fluxor.toml` and `fluxor.lock`; scenarios do not trample each other's
/// host graph, document root or config.bin output.
pub fn scenario_work_dir(scenario: &Scenario, scenario_path: &Path) -> PathBuf {
    crate::project::root_for_config(scenario_path)
        .join("target/scenarios")
        .join(&scenario.name)
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
    let work_dir = scenario_work_dir(scenario, scenario_path);
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

/// Where the wasm bundle for a component lands: `target/wasm/<stem>.wasm`
/// under the scenario's project root. The run builds it there and the
/// document root links `fluxor.wasm` to it.
pub fn wasm_bundle_target_path(
    scenario_path: &Path,
    comp_name: &str,
    comp: &ComponentSpec,
) -> Result<PathBuf> {
    let graph = comp
        .graph
        .as_ref()
        .ok_or_else(|| Error::Config(format!("component `{comp_name}` has no `graph:`")))?;
    let stem = graph.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        Error::Config(format!(
            "component `{comp_name}` graph has no filename stem"
        ))
    })?;
    Ok(crate::project::root_for_config(scenario_path)
        .join("target/wasm")
        .join(format!("{stem}.wasm")))
}

/// Effective target for a component: the `runtime_override:` (if set)
/// wins, otherwise the graph's declared `target:`. The spawn path uses
/// it to classify components as wasm (passive, build-bundle-only) vs.
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

/// Write a component's config ([`component_config`]) to
/// `<work dir>/<component>.yaml` so the spawn path can hand it straight to
/// `build_one()`.
pub fn write_component_yaml(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<PathBuf> {
    let config = component_config(comp_name, scenario, scenario_path)?;
    let work_dir = scenario_work_dir(scenario, scenario_path);
    fs::create_dir_all(&work_dir).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot create work dir {}: {}",
            scenario_path.display(),
            work_dir.display(),
            e
        ))
    })?;
    let banner = format!(
        "# Auto-generated by `fluxor run {}` — config for component `{}`.\n\
         # DO NOT EDIT — overwritten on every run.\n",
        scenario_path.display(),
        comp_name,
    );
    let yaml = render_value_as_yaml(&config, &banner)?;
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
// Module hardware_targets validation against the effective target
// ----------------------------------------------------------------------------

/// Per-effective-target aliases — which manifest `hardware_targets:`
/// strings the runtime accepts.
///
/// Delegates to the `targets/` registry: a module is placeable when its
/// `hardware_targets` names the target's runtime (`crate::runtime_abi`).
/// Sharing a module ABI is not enough — bare-metal `["bcm2712"]` modules
/// do not run under `linux`. Boards never appear in `hardware_targets` — a
/// board id there is the level error this validator exists to catch.
fn target_aliases(target: &str) -> Vec<String> {
    match crate::target::load_target(target, &crate::project::root()) {
        Ok(desc) => vec![desc.runtime().to_string()],
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

/// Walk every component's graph and check that each declared
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
                // A missing manifest is not this check's concern — the
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

/// Re-validate what the run would build, before any build runs: every
/// component's modules against its effective target
/// ([`validate_module_targets`]), and the synthesised host graph with its
/// includes expanded against the scenario's project — so an unbound
/// `@file_server`, a bound stack the lock does not pin, or one whose params
/// or exports do not fit the host's include is reported here — then through
/// `tools::board::validate_config`.
pub fn revalidate_all(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    use crate::target::load_target;
    let project_root = crate::project::root();

    validate_module_targets(scenario, scenario_path)?;

    if let Some(mut host_cfg) = synthesise_host_config(scenario, scenario_path)? {
        let host_project = crate::project::root_for_config(scenario_path);
        let work_dir = scenario_work_dir(scenario, scenario_path);
        crate::stack::expand_includes(
            &mut host_cfg,
            &crate::stack::IncludeContext {
                graph_dir: &work_dir,
                project_root: &host_project,
                store_root: None,
                params: &BTreeMap::new(),
            },
        )
        .map_err(|e| {
            Error::Config(format!(
                "scenario {}: synthesised host: {e}",
                scenario_path.display()
            ))
        })?;
        let target_desc = load_target("linux", &project_root)?;
        let result = crate::board::validate_config(&host_cfg, &target_desc)?;
        if !result.is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: synthesised host failed re-validation: {}",
                scenario_path.display(),
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
/// from the filename.
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
                out.push_str(&format!(
                    "  \"{}\" -> \"host\" [label=\"serve {}\"];\n",
                    s.serve, s.prefix
                ));
            }
            Binding::List(l) => {
                out.push_str(&format!(
                    "  \"{}\" -> \"host\" [label=\"list {}\"];\n",
                    l.list.display(),
                    l.path
                ));
            }
        }
    }
    out.push_str("}\n");
    out
}
