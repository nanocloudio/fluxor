// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a temp scenario tree, a project of its own so the work dir
    /// lands inside it:
    ///   <tmp>/fluxor.toml, <tmp>/.fluxor
    ///   <tmp>/scenario.yaml
    ///   <tmp>/viewer/graph.yaml        target: wasm
    ///   <tmp>/viewer/viewer.html
    ///   <tmp>/assets/                  (an empty dir)
    /// Returns `(TempDir, scenario_path)` — the caller must hold the
    /// `TempDir` for the lifetime of the test so the on-disk tree is
    /// cleaned up automatically when the test ends.
    fn make_temp_tree(name: &str, scenario_yaml: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("fluxor_scenario_test_{name}_"))
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path();
        fs::write(
            dir.join("fluxor.toml"),
            "[project]\nname = \"scn\"\nversion = \"0\"\n",
        )
        .unwrap();
        fs::write(dir.join(".fluxor"), b"").unwrap();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        fs::create_dir_all(dir.join("assets")).unwrap();
        let graph = dir.join("viewer/graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/viewer.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(fs::File::create(&scenario).unwrap(), "{scenario_yaml}").unwrap();
        (tmp, scenario)
    }

    #[test]
    fn minimal_wasm_scenario_round_trips() {
        let (_tmp, path) = make_temp_tree(
            "round_trip",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png, .jpg]
",
        );
        let s = parse(&path).unwrap();
        assert_eq!(s.kind, "scenario");
        assert_eq!(s.name, "viewer");
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.bindings.len(), 2);
        validate(&s, &path).unwrap();
    }

    #[test]
    fn wasm_without_origin_is_rejected() {
        let (_tmp, path) = make_temp_tree(
            "no_origin",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("`host:`") || msg.contains("origin"),
            "expected host-missing error, got: {msg}"
        );
    }

    /// A sequential scenario runs each component to completion in turn, so
    /// it takes no host — which also rules out bindings and wasm — and a
    /// wasm component takes no `duration:` (it is served, not spawned).
    #[test]
    fn sequential_takes_no_host_and_wasm_takes_no_duration() {
        let (_tmp, path) = make_temp_tree(
            "seq_host",
            "\
kind: scenario
name: viewer
sequential: true
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let e = validate(&parse(&path).unwrap(), &path).unwrap_err().to_string();
        assert!(e.contains("a sequential scenario takes no `host:` block"), "{e}");

        let (_tmp, path) = make_temp_tree(
            "seq_wasm",
            "kind: scenario\nname: viewer\nsequential: true\ncomponents:\n  viewer:\n    \
             graph: viewer/graph.yaml\n",
        );
        let e = validate(&parse(&path).unwrap(), &path).unwrap_err().to_string();
        assert!(e.contains("a sequential scenario takes no `host:` block"), "{e}");

        let (_tmp, path) = make_temp_tree(
            "wasm_duration",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    duration: 30
host:
  port: 9876
",
        );
        let e = validate(&parse(&path).unwrap(), &path).unwrap_err().to_string();
        assert!(e.contains("declares `duration:`, but it targets wasm"), "{e}");
    }

    #[test]
    fn runtime_override_wasm_is_rejected() {
        let (_tmp, path) = make_temp_tree(
            "override_wasm",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    runtime_override: wasm
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("runtime_override") && msg.contains("wasm"),
            "expected runtime_override: wasm rejection, got: {msg}"
        );
    }

    #[test]
    fn missing_kind_is_rejected_with_helpful_message() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mk_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let path = dir.join("not_a_scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "target: linux\nmodules: []\n"
        )
        .unwrap();
        let err = parse(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("graph YAML") || msg.contains("kind"),
            "expected helpful kind: error, got: {msg}"
        );
    }

    #[test]
    fn missing_graph_file_is_rejected() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_nograph_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: x
components:
  viewer:
    graph: missing/graph.yaml
host:
  port: 9876
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist") && msg.contains("missing"),
            "expected missing-graph error, got: {msg}"
        );
    }

    #[test]
    fn print_synthesised_includes_the_bound_file_server() {
        let _g = cwd_lock();
        let (tmp, path) = make_temp_tree(
            "synth",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png, .jpg]
",
        );
        let s = parse(&path).unwrap();
        let yaml = render_synthesised_host(&s, &path).unwrap().unwrap();
        assert!(yaml.contains("target: linux"), "{yaml}");
        assert!(yaml.contains("stack: '@file_server'"), "{yaml}");
        assert!(yaml.contains("port: 9876"), "{yaml}");
        let root = tmp
            .path()
            .canonicalize()
            .unwrap()
            .join("target/scenarios/viewer/root");
        assert!(yaml.contains(&format!("root: {}", root.display())), "{yaml}");
        // No module, route or listing handler of any provider's.
        for absent in ["http", "routes", "fs_list", "fs_path", "modules"] {
            assert!(!yaml.contains(absent), "`{absent}` in {yaml}");
        }
    }

    #[test]
    fn render_synthesised_returns_none_without_host() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_nosynth_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        fs::create_dir_all(dir.join("decoder")).unwrap();
        write!(
            fs::File::create(dir.join("decoder/graph.yaml")).unwrap(),
            "target: linux\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: headless
components:
  decoder:
    graph: decoder/graph.yaml
    port: 8080
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        assert_eq!(s.components["decoder"].port, Some(8080));
        assert!(render_synthesised_host(&s, &path).unwrap().is_none());
    }

    #[test]
    fn a_binding_takes_no_on_key() {
        let (_tmp, path) = make_temp_tree(
            "on_gone",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        assert!(parse(&path).is_err());
    }

    #[test]
    fn list_scenarios_finds_and_filters() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_list_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        // A real scenario.
        write!(
            fs::File::create(dir.join("foo.scenario.yaml")).unwrap(),
            "kind: scenario\nname: foo\ncomponents:\n  x:\n    graph: x.yaml\nhost:\n  port: 80\n"
        )
        .unwrap();
        // Another, with .yml extension.
        write!(
            fs::File::create(dir.join("bar.scenario.yml")).unwrap(),
            "kind: scenario\nname: bar\ncomponents:\n  x:\n    graph: x.yaml\nhost:\n  port: 80\n"
        )
        .unwrap();
        // A plain YAML — should NOT show up.
        writeln!(
            fs::File::create(dir.join("not_a_scenario.yaml")).unwrap(),
            "target: linux"
        )
        .unwrap();
        // A graph YAML carrying an inline `scenario:` block — listed
        // under the inline block's name.
        write!(
            fs::File::create(dir.join("inline.yaml")).unwrap(),
            "target: linux\nscenario:\n  name: inline_baz\n  host:\n    port: 80\n  bindings:\n    - serve: main\n"
        )
        .unwrap();
        // A scenario with a parse error — still listed.
        write!(
            fs::File::create(dir.join("broken.scenario.yaml")).unwrap(),
            "kind: scenario\nname: [["
        )
        .unwrap();
        let mut out = list_scenarios(dir).unwrap();
        out.sort();
        let names: Vec<&str> = out.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"inline_baz"));
        assert!(names.iter().any(|n| n.contains("parse error")));
        assert!(!names.iter().any(|n| n.contains("not_a_scenario")));
    }

    // -------------------------------------------------------------
    // Synthesiser shape and the document root.
    // -------------------------------------------------------------

    fn make_split_tree(
        name: &str,
        decoder_yaml: &str,
        scenario_yaml: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("fluxor_scenario_test_{name}_"))
            .tempdir()
            .unwrap();
        let dir = tmp.path();
        fs::write(
            dir.join("fluxor.toml"),
            "[project]\nname = \"scn\"\nversion = \"0\"\n",
        )
        .unwrap();
        fs::write(dir.join(".fluxor"), b"").unwrap();
        fs::create_dir_all(dir.join("decoder")).unwrap();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        write!(
            fs::File::create(dir.join("decoder/graph.yaml")).unwrap(),
            "{decoder_yaml}"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/viewer.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(fs::File::create(&scenario).unwrap(), "{scenario_yaml}").unwrap();
        (tmp, scenario)
    }

    #[test]
    fn synthesised_host_opts_into_accept_cycles() {
        // The synthesised host's `web <-> linux_net` wiring is a
        // 2-cycle the scheduler rejects unless the graph attests to it,
        // so the synthesiser sets `scheduler.accept_cycles: true`.
        let _g = cwd_lock();
        let (_tmp, path) = make_temp_tree(
            "synth_accept_cycles",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let config = synthesise_host_config(&s, &path).unwrap().unwrap();
        let scheduler = config.get("scheduler").expect("scheduler block missing");
        let accept = scheduler
            .get("accept_cycles")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(
            accept,
            "synthesised host must opt into accept_cycles, got: {scheduler:?}"
        );
    }

    #[test]
    fn synthesised_host_has_canonical_shape() {
        let _g = cwd_lock();
        let (_tmp, path) = make_temp_tree(
            "synth_shape",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let config = synthesise_host_config(&s, &path).unwrap().unwrap();
        assert_eq!(config["target"], "linux");
        assert!(config["platform"]["net"].is_object());
        assert!(config.get("modules").is_none());
        let include = config["include"].as_array().unwrap();
        assert_eq!(include.len(), 1);
        assert_eq!(include[0]["stack"], "@file_server");
        assert_eq!(include[0]["as"], "web");
        assert_eq!(include[0]["params"]["port"], 9876);
        let root = PathBuf::from(include[0]["params"]["root"].as_str().unwrap());
        assert!(root.is_absolute() && root.is_dir(), "{}", root.display());
        let wiring: Vec<(&str, &str)> = config["wiring"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| (w["from"].as_str().unwrap(), w["to"].as_str().unwrap()))
            .collect();
        assert_eq!(
            wiring,
            [
                ("linux_net.net_out", "web.net_in"),
                ("web.net_out", "linux_net.net_in")
            ]
        );
    }

    /// The document root holds every file the host serves: the shell, the
    /// bundle link, the shims, `scenario.json`, and for a `list:` binding
    /// `fluxor-manifest.json` plus the directory linked at its `path`.
    #[test]
    fn the_document_root_holds_what_the_host_serves() {
        let _g = cwd_lock();
        let (tmp, path) = make_temp_tree(
            "docroot",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png]
",
        );
        fs::write(tmp.path().join("assets/a.png"), b"png").unwrap();
        fs::write(tmp.path().join("assets/b.txt"), b"txt").unwrap();
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let root = write_document_root(&s, &path).unwrap();
        let project = tmp.path().canonicalize().unwrap();
        assert_eq!(root, project.join("target/scenarios/viewer/root"));
        let index = fs::read_to_string(root.join("index.html")).unwrap();
        assert!(!index.contains(OVERLAY_MARKER), "overlay not inlined");
        assert!(index.contains("window.FluxorOverlay"));
        assert_eq!(
            fs::read_link(root.join("fluxor.wasm")).unwrap(),
            project.join("target/wasm/graph.wasm")
        );
        assert_eq!(
            fs::read_to_string(root.join("host_shims.js")).unwrap(),
            CANONICAL_HOST_SHIMS_JS_RAW
        );
        assert!(root.join("fluxor-worker.js").is_file());
        let scenario: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("scenario.json")).unwrap()).unwrap();
        assert_eq!(scenario["bundle"], "/fluxor.wasm");
        assert_eq!(scenario["playlist"]["source"], "/api/list");
        assert_eq!(scenario["playlist"]["filter"], "image");
        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("fluxor-manifest.json")).unwrap(),
        )
        .unwrap();
        let keys: Vec<&str> = manifest
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["key"].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["api/list/a.png"]);
        // The key is the URL the file is served at.
        assert_eq!(fs::read(root.join(keys[0])).unwrap(), b"png");

        // Rewritten afresh: a run never serves a stale file, and clearing
        // the root never reaches through a link.
        fs::write(root.join("stale"), b"x").unwrap();
        write_document_root(&s, &path).unwrap();
        assert!(!root.join("stale").exists());
        assert!(tmp.path().join("assets/a.png").is_file());
    }

    /// Every `serve:` lands on the host: each prefix is a directory of the
    /// root holding that component's page, and two prefixes must differ.
    #[test]
    fn serve_bindings_land_under_distinct_prefixes() {
        let _g = cwd_lock();
        let yaml = |second: &str| {
            format!(
                "\
kind: scenario
name: two
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
  other:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
    prefix: /viewer
  - serve: other
    prefix: {second}
"
            )
        };
        let (tmp, path) = make_temp_tree("prefixes", &yaml("/"));
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let root = write_document_root(&s, &path).unwrap();
        assert_eq!(
            fs::read_link(root.join("viewer/index.html")).unwrap(),
            tmp.path().canonicalize().unwrap().join("viewer/viewer.html")
        );
        let scenario: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("viewer/scenario.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(scenario["bundle"], "/viewer/fluxor.wasm");
        assert!(root.join("index.html").is_file());

        let (_tmp, path) = make_temp_tree("prefixes_same", &yaml("/viewer/"));
        let s = parse(&path).unwrap();
        let e = validate(&s, &path).unwrap_err().to_string();
        assert!(e.contains("both serve at `prefix: /viewer/`"), "{e}");
        let e = write_document_root(&s, &path).unwrap_err().to_string();
        assert!(e.contains("share `prefix: /viewer/`"), "{e}");
    }

    /// A `list:` directory is linked beside every served page, so a manifest
    /// key — relative to the page — resolves under any `prefix`; a prefix
    /// landing on a linked directory is refused rather than written into it.
    #[test]
    fn list_keys_resolve_beside_the_page_under_any_prefix() {
        let _g = cwd_lock();
        let yaml = |prefix: &str| {
            format!(
                "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
    prefix: {prefix}
  - list: assets
    path: /media
"
            )
        };
        let (tmp, path) = make_temp_tree("list_prefix", &yaml("/viewer"));
        fs::write(tmp.path().join("assets/a.png"), b"png").unwrap();
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let root = write_document_root(&s, &path).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("viewer/fluxor-manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest[0]["key"], "media/a.png");
        assert_eq!(fs::read(root.join("viewer/media/a.png")).unwrap(), b"png");
        assert!(!root.join("media").exists());

        // Two components, the second's prefix on the first's linked list.
        let (tmp, path) = make_temp_tree(
            "list_prefix_clash",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
  other:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
  - serve: other
    prefix: /media
  - list: assets
    path: /media
",
        );
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let e = write_document_root(&s, &path).unwrap_err().to_string();
        assert!(
            e.contains("`prefix: /media` is where the document root links a `list:`")
                || e.contains("`list: assets` is placed at `/media`"),
            "{e}"
        );
        assert!(!tmp.path().join("assets/scenario.json").exists());
        assert!(!tmp.path().join("assets/host_shims.js").exists());
    }

    /// A name placed inside a linked `list:` directory is refused rather
    /// than written into the user's tree.
    #[test]
    fn nothing_is_placed_through_a_list_link() {
        let _g = cwd_lock();
        let (tmp, path) = make_temp_tree(
            "through_link",
            "\
kind: scenario
name: nested
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - list: assets
    path: /media
  - list: viewer
    path: /media/inner
",
        );
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let e = write_document_root(&s, &path).unwrap_err().to_string();
        assert!(e.contains("lies inside a `list:` binding's directory"), "{e}");
        assert!(!tmp.path().join("assets/inner").exists());
    }

    #[test]
    fn bindings_or_wasm_need_a_host_and_wasm_takes_no_port() {
        let (_tmp, path) = make_temp_tree(
            "need_host",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
",
        );
        let e = validate(&parse(&path).unwrap(), &path).unwrap_err().to_string();
        assert!(e.contains("declares a wasm component but no `host:`"), "{e}");

        let (_tmp, path) = make_temp_tree(
            "wasm_port",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    port: 9000
host:
  port: 9876
",
        );
        let e = validate(&parse(&path).unwrap(), &path).unwrap_err().to_string();
        assert!(e.contains("declares `port:`, but it targets wasm"), "{e}");
    }

    /// `@file_server` resolves against the scenario's project: unbound, the
    /// error names the line to add; bound, the include expands onto the
    /// stack's exports.
    #[test]
    fn the_host_include_resolves_through_the_scenarios_project() {
        let _g = cwd_lock();
        let (tmp, path) = make_temp_tree(
            "bound_host",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let e = revalidate_all(&s, &path).unwrap_err().to_string();
        assert!(
            e.contains("include 'web' (`@file_server`): `file_server` is not bound — add \
                        `file_server = \"<stack>\"` under [uses.stacks]"),
            "{e}"
        );

        fs::write(
            tmp.path().join("fluxor.toml"),
            "[project]\nname = \"scn\"\nversion = \"0\"\n\n[uses.stacks]\n\
             file_server = \"fixture_files\"\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("packaging/stack")).unwrap();
        fs::write(
            tmp.path().join("packaging/stack/fixture_files.yaml"),
            "\
stack: fixture_files
version: 0.1.0
params:
  port: { type: integer, required: true, example: 8080 }
  root: { type: string, required: true, example: /srv }
  index: { type: string, default: index.html }
exports:
  net_in: srv.net_in
  net_out: srv.net_out
modules:
  - name: srv
    type: fixture_server
    port: ${param:port}
    root: ${param:root}
    index: ${param:index}
",
        )
        .unwrap();
        let mut host = synthesise_host_config(&s, &path).unwrap().unwrap();
        let project = crate::project::root_for_config(&path);
        crate::stack::expand_includes(
            &mut host,
            &crate::stack::IncludeContext {
                graph_dir: &scenario_work_dir(&s, &path),
                project_root: &project,
                store_root: None,
                params: &BTreeMap::new(),
            },
        )
        .unwrap();
        let srv = &host["modules"][0];
        assert_eq!(srv["name"], "web_srv");
        assert_eq!(srv["type"], "fixture_server");
        assert_eq!(srv["port"], 9876);
        assert!(srv["root"]
            .as_str()
            .unwrap()
            .ends_with("target/scenarios/viewer/root"));
        let wiring: Vec<(&str, &str)> = host["wiring"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| (w["from"].as_str().unwrap(), w["to"].as_str().unwrap()))
            .collect();
        assert!(wiring.contains(&("linux_net.net_out", "web_srv.net_in")));
        assert!(wiring.contains(&("web_srv.net_out", "linux_net.net_in")));
    }

    /// A component's config is its graph with its `runtime_override:`
    /// applied; the scenario adds nothing else.
    #[test]
    fn component_config_applies_the_runtime_override_only() {
        let (_tmp, path) = make_split_tree(
            "comp_config",
            "\
target: pi5
modules:
  - name: ip
  - name: web
wiring:
  - from: ip.net_out
    to: web.net_in
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
    runtime_override: linux
    port: 8080
",
        );
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        let config = component_config("decoder", &s, &path).unwrap();
        assert_eq!(config["target"], "linux");
        assert_eq!(config["wiring"][0]["from"], "linux_net.net_out");
        assert_eq!(config["modules"].as_array().unwrap().len(), 2);
    }

    // -------------------------------------------------------------
    // effective_target, write_component_yaml.
    // -------------------------------------------------------------

    #[test]
    fn effective_target_honours_runtime_override() {
        let (_tmp, path) = make_split_tree(
            "et_override",
            "target: pi5\nmodules: []\nwiring: []\n",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
    runtime_override: linux
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let decoder = s.components.get("decoder").unwrap();
        let viewer = s.components.get("viewer").unwrap();
        assert_eq!(effective_target(&path, decoder), "linux");
        assert_eq!(effective_target(&path, viewer), "wasm");
    }

    /// The crate's one lock for the process working directory.
    ///
    /// The working directory is process-global: a test that changes it moves
    /// it for every other test running at that moment, and a test that writes
    /// or reads a relative path — `target/scenarios/…`, `modules/…` — lands
    /// wherever the last change left it. So every test that changes it AND
    /// every test that depends on it hold the same lock. A lock of its own in
    /// one module would exclude that module's tests from each other and from
    /// nothing else: a change made under `project`'s lock would still move the
    /// directory out from under a test here, and that surfaced as a merged YAML
    /// written into a temporary root another test had just removed.
    fn cwd_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::project::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn write_component_yaml_lands_under_the_scenarios_project() {
        // The component YAML lands under `target/scenarios/<name>/` of the
        // scenario's project, whatever the working directory.
        let _g = cwd_lock();
        let (tmp, path) = make_split_tree(
            "wc_yaml",
            "target: linux\nmodules:\n  - name: srv\n",
            "\
kind: scenario
name: write_component_test
components:
  decoder:
    graph: decoder/graph.yaml
",
        );
        let s = parse(&path).unwrap();
        let out = write_component_yaml("decoder", &s, &path).unwrap();
        assert_eq!(
            out,
            tmp.path()
                .canonicalize()
                .unwrap()
                .join("target/scenarios/write_component_test/decoder.yaml")
        );
        let parsed: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(parsed["target"], "linux");
    }

    // -------------------------------------------------------------
    // target_aliases, manifest hardware_targets check.
    // -------------------------------------------------------------

    #[test]
    fn target_aliases_table_is_sensible() {
        let aliases = |t: &str| target_aliases(t);
        // A target places exactly the modules that name its runtime: the
        // linux host shares bcm2712's module ABI, not its contracts, so a
        // bare-metal `["bcm2712"]` module is not placed under it.
        assert_eq!(aliases("linux"), vec!["linux".to_string()]);
        // A board resolves to its silicon's runtime; the board id itself is
        // NOT a legal `hardware_targets` token.
        assert_eq!(aliases("pi5"), vec!["bcm2712".to_string()]);
        assert_eq!(aliases("qemu-virt"), vec!["bcm2712".to_string()]);
        assert_eq!(aliases("pico2w"), vec!["rp2350".to_string()]);
        assert_eq!(aliases("wasm"), vec!["wasm".to_string()]);
        // Unknown target → empty (no aliases means strict
        // never-matches; the build path will surface this with its
        // own error).
        assert!(target_aliases("definitely-not-a-real-target").is_empty());
    }

    #[test]
    fn read_manifest_hardware_targets_walks_real_manifests() {
        // Sanity-check against an actual repo manifest so a refactor
        // of `ManifestTargetsOnly` is caught early.
        let _g = cwd_lock();
        let path = std::env::current_dir()
            .unwrap()
            .join("../modules/foundation/http/manifest.toml");
        if !path.is_file() {
            // Test runner cwd ≠ repo root in some environments;
            // skip rather than fail.
            eprintln!("skipping: {} not found", path.display());
            return;
        }
        let targets = read_manifest_hardware_targets(&path).unwrap();
        assert!(targets.iter().any(|t| t == "bcm2712" || t == "rp2350"));
    }

    #[test]
    fn validate_module_targets_rejects_silicon_mismatch_with_actionable_error() {
        // A real linux scenario that lists a rp2350-only module —
        // should be rejected. We use `wifi` (CYW43-only RP module)
        // because its hardware_targets manifest definitely doesn't
        // include linux or bcm2712.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mask_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let graph = dir.join("graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: linux\nmodules:\n  - name: wifi\nwiring: []\n"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(
            fs::File::create(&scenario).unwrap(),
            "kind: scenario\nname: test\ncomponents:\n  c:\n    graph: graph.yaml\n"
        )
        .unwrap();
        let s = parse(&scenario).unwrap();

        // Must run from the repo root so find_manifest_for can locate
        // wifi's manifest under modules/foundation/wifi/manifest.toml.
        let _g = cwd_lock();
        let repo_root = std::env::current_dir().unwrap();
        let project_root = if repo_root.ends_with("tools") {
            repo_root.parent().unwrap().to_path_buf()
        } else {
            repo_root.clone()
        };
        // Swap CWD so find_manifest_for picks up the real tree.
        std::env::set_current_dir(&project_root).unwrap();
        let res = validate_module_targets(&s, &scenario);
        std::env::set_current_dir(&repo_root).unwrap();

        let err = match res {
            Ok(()) => {
                // If wifi's manifest isn't in this tree, we can't
                // exercise the check — skip without failing.
                let manifest = project_root.join("modules/foundation/wifi/manifest.toml");
                if !manifest.is_file() {
                    eprintln!("skipping: {} not present", manifest.display());
                    return;
                }
                panic!("expected mismatch error, got Ok");
            }
            Err(e) => format!("{e}"),
        };
        assert!(
            err.contains("hardware_targets") && err.contains("effective target"),
            "expected helpful mask error, got: {err}"
        );
        assert!(
            err.contains("modules/foundation/wifi/manifest.toml") || err.contains("wifi"),
            "expected manifest path / module name cited, got: {err}"
        );
    }

    #[test]
    fn validate_module_targets_accepts_bcm2712_under_runtime_override_linux() {
        // The split-decoder pattern: a pi5 graph using foundation/http
        // (hardware_targets = ["rp2350", "bcm2712"]) coerced to linux
        // — should pass because target_aliases("linux") includes
        // "bcm2712".
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mask_ok_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let graph = dir.join("graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: pi5\nmodules:\n  - name: http\n    port: 9090\nwiring: []\n"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(
            fs::File::create(&scenario).unwrap(),
            "kind: scenario\nname: test\ncomponents:\n  c:\n    graph: graph.yaml\n    runtime_override: linux\n"
        )
        .unwrap();
        let s = parse(&scenario).unwrap();

        let _g = cwd_lock();
        let repo_root = std::env::current_dir().unwrap();
        let project_root = if repo_root.ends_with("tools") {
            repo_root.parent().unwrap().to_path_buf()
        } else {
            repo_root.clone()
        };
        std::env::set_current_dir(&project_root).unwrap();
        let res = validate_module_targets(&s, &scenario);
        std::env::set_current_dir(&repo_root).unwrap();

        match res {
            Ok(()) => {}
            Err(e) => panic!("expected pass under runtime_override: linux, got: {e}"),
        }
    }
}
