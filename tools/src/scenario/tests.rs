// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a temp scenario tree:
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
    fn print_synthesised_emits_host_routes() {
        let (_tmp, path) = make_temp_tree(
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
        assert!(yaml.contains("target: linux"));
        assert!(yaml.contains("port: 9876"));
        assert!(yaml.contains("/fluxor.wasm"));
        assert!(yaml.contains("viewer.html"));
        assert!(yaml.contains("fs_list"));
        assert!(yaml.contains(".png,.jpg"));
    }

    #[test]
    fn render_synthesised_returns_none_without_host() {
        // A scenario whose only binding has explicit `on:` and no
        // `host:` section — render_synthesised_host returns None.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_nosynth_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        fs::create_dir_all(dir.join("decoder")).unwrap();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        write!(
            fs::File::create(dir.join("decoder/graph.yaml")).unwrap(),
            "target: linux\nmodules: []\nwiring: []\n"
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
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        assert!(render_synthesised_host(&s, &path).unwrap().is_none());
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
    // PR 2 tests: synthesiser shape, route merger, conflict
    // detection, host-FS gate.
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
        // PR 6: the synthesised host's `http <-> linux_net` wiring is
        // a 2-cycle that the v1 scheduler would otherwise reject.
        // The synthesiser sets `scheduler.accept_cycles: true` so the
        // kernel's prepare_graph accepts it under the explicit
        // attestation.
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
        let (_tmp, path) = make_temp_tree(
            "synth_shape",
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
        let config = synthesise_host_config(&s, &path).unwrap().unwrap();
        // Top-level shape mirrors what `examples/serve_wasm/linux.yaml` carries.
        assert_eq!(config["target"], "linux");
        assert!(config["platform"]["net"].is_object());
        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        // The synthesised serving host names wave's `http` protocol module,
        // which downstream graphs resolve from the workspace / registry.
        assert_eq!(modules[0]["name"], "http");
        assert_eq!(modules[0]["port"], 9876);
        assert_eq!(modules[0]["host_tcp"], 1);
        let routes = modules[0]["routes"].as_array().unwrap();
        // serve binding contributes /, /fluxor.wasm (2 routes);
        // synthesiser auto-mounts /host_shims.js + /fluxor-worker.js +
        // /scenario.json (3 more); list binding contributes /api/list
        // (1 more). Total = 6.
        assert_eq!(routes.len(), 6);
        let paths: Vec<&str> = routes.iter().map(|r| r["path"].as_str().unwrap()).collect();
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/fluxor.wasm"));
        assert!(paths.contains(&"/host_shims.js"));
        assert!(paths.contains(&"/fluxor-worker.js"));
        assert!(paths.contains(&"/scenario.json"));
        assert!(paths.contains(&"/api/list"));
        // wiring is the canonical 2-edge linux net loop
        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 2);
    }

    #[test]
    fn merger_injects_routes_into_named_module() {
        let (_tmp, path) = make_split_tree(
            "merge_inject",
            "\
target: linux
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let merged = merge_bindings_for_component("decoder", &s, &path).unwrap();
        let routes = merged["modules"][0]["routes"].as_array().unwrap();
        // Original /api/list + 4 binding-injected routes (page,
        // bundle, host_shims.js, scenario.json — commit 1c).
        assert_eq!(routes.len(), 5);
        let paths: Vec<&str> = routes.iter().map(|r| r["path"].as_str().unwrap()).collect();
        assert!(paths.contains(&"/api/list"));
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/fluxor.wasm"));
        assert!(paths.contains(&"/host_shims.js"));
        assert!(paths.contains(&"/scenario.json"));
    }

    #[test]
    fn merger_detects_route_conflict_with_helpful_error() {
        let (_tmp, path) = make_split_tree(
            "merge_conflict",
            "\
target: linux
modules:
  - name: http
    port: 9090
    routes:
      - path: /
        fs_path: /existing.html
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        // Per RFC §7 the error must name the binding, cite the file,
        // and suggest a `prefix:` value.
        assert!(
            msg.contains("serve: viewer"),
            "should name the binding, got: {msg}"
        );
        assert!(
            msg.contains("decoder/graph.yaml"),
            "should cite the file, got: {msg}"
        );
        assert!(
            msg.contains("prefix:"),
            "should suggest a prefix, got: {msg}"
        );
    }

    #[test]
    fn merger_blocks_binding_on_silicon_without_override() {
        let (_tmp, path) = make_split_tree(
            "merge_silicon",
            "\
target: pi5
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("host filesystem") && msg.contains("runtime_override"),
            "should explain host-FS gate (RFC §16 Q9), got: {msg}"
        );
    }

    #[test]
    fn runtime_override_flips_effective_target_in_merged_config() {
        let (_tmp, path) = make_split_tree(
            "merge_override",
            "\
target: pi5
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
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
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let merged = merge_bindings_for_component("decoder", &s, &path).unwrap();
        assert_eq!(merged["target"], "linux");
    }

    #[test]
    fn binding_targeting_missing_module_errors_clearly() {
        let (_tmp, path) = make_split_tree(
            "merge_no_module",
            "\
target: linux
modules:
  - name: NOT_http
    port: 9090
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no module named") && msg.contains("http"),
            "should name the missing module clearly, got: {msg}"
        );
    }

    // -------------------------------------------------------------
    // PR 4 tests: effective_target, extract_http_port,
    // write_merged_component_yaml.
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
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let decoder = s.components.get("decoder").unwrap();
        let viewer = s.components.get("viewer").unwrap();
        assert_eq!(effective_target(&path, decoder), "linux");
        assert_eq!(effective_target(&path, viewer), "wasm");
    }

    #[test]
    fn extract_http_port_walks_modules() {
        let v: serde_json::Value = serde_yaml::from_str(
            "modules:\n  - name: ws\n    type: ws_stream\n  - name: http\n    port: 9090\n",
        )
        .unwrap();
        assert_eq!(extract_http_port(&v), Some(9090));
        let v_no_http: serde_json::Value =
            serde_yaml::from_str("modules:\n  - name: ws\n    type: ws_stream\n").unwrap();
        assert_eq!(extract_http_port(&v_no_http), None);
    }

    #[test]
    fn write_merged_component_yaml_lands_under_target_scenarios() {
        let (_tmp, path) = make_split_tree(
            "wmc_yaml",
            "\
target: linux
modules:
  - name: http
    port: 9090
",
            "\
kind: scenario
name: write_merge_test
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let out = write_merged_component_yaml("decoder", &s, &path).unwrap();
        assert!(out.is_file(), "merged yaml not written: {}", out.display());
        let content = fs::read_to_string(&out).unwrap();
        assert!(content.contains("/fluxor.wasm"));
        // Bonus: the on-disk YAML must parse back as a valid config Value.
        let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed["target"], "linux");
        // Cleanup
        let _ = fs::remove_dir_all(scenario_work_dir(&s));
    }

    // -------------------------------------------------------------
    // PR 5 tests: target_aliases, manifest hardware_targets check.
    // -------------------------------------------------------------

    /// Process-wide mutex serialising tests that mutate
    /// `std::env::set_current_dir`. Without this they race against
    /// each other and against tests that read CWD (e.g.
    /// `wasm_bundle_target_path` via `std::env::current_dir`),
    /// surfacing as `cargo test`-only intermittent failures.
    /// `validate_module_targets`'s manifest lookup walks
    /// `std::env::current_dir().join("modules/...")`, so the test
    /// has to pin CWD to the project root.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn target_aliases_table_is_sensible() {
        let has = |t: &str, want: &str| target_aliases(t).iter().any(|a| a == want);
        // Linux reuses bcm2712 PIC modules — that's the whole point
        // of `runtime_override: linux` working for pi5 graphs.
        assert!(has("linux", "bcm2712"));
        assert!(has("linux", "linux"));
        // pi5 board uses bcm2712 silicon; the board id itself is NOT
        // a legal `hardware_targets` token (§2 rule 1).
        assert!(has("pi5", "bcm2712"));
        assert!(!has("pi5", "pi5"));
        assert!(has("qemu-virt", "bcm2712"));
        assert!(has("pico2w", "rp2350"));
        // wasm is wasm — no aliasing.
        assert_eq!(target_aliases("wasm"), vec!["wasm".to_string()]);
        // Unknown target → empty (no aliases means strict
        // never-matches; the build path will surface this with its
        // own error).
        assert!(target_aliases("definitely-not-a-real-target").is_empty());
    }

    #[test]
    fn read_manifest_hardware_targets_walks_real_manifests() {
        // Sanity-check against an actual repo manifest so a refactor
        // of `ManifestTargetsOnly` is caught early.
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
        let _g = CWD_LOCK.lock().unwrap();
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

        let _g = CWD_LOCK.lock().unwrap();
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

    #[test]
    fn binding_cycle_is_caught() {
        // Two components, each whose serve-binding points at the
        // other's http — degenerate, but the dependency graph forms
        // a cycle.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_cycle_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        write!(
            fs::File::create(dir.join("a/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("b/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("a/page.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("b/page.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: cycle
components:
  a:
    graph: a/graph.yaml
    host_page: a/page.html
  b:
    graph: b/graph.yaml
    host_page: b/page.html
bindings:
  - serve: a
    on: b.http
  - serve: b
    on: a.http
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cyclic"), "expected cycle error, got: {msg}");
    }
}
