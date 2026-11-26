/// A resolver over the throwaway project `project`, its modules on `search`
/// (each inside it), with no module ABI, no catalog and an empty store.
#[cfg(test)]
fn test_resolver(
    project: &std::path::Path,
    search: &[&std::path::Path],
) -> crate::module_resolver::ModuleResolver {
    crate::module_resolver::ModuleResolver::new(crate::module_resolver::ResolverSpec {
        project_root: project.to_path_buf(),
        abi: crate::module_resolver::Abi::Unplaced,
        shelf: None,
        search_paths: search.iter().map(|p| p.to_path_buf()).collect(),
        install_root: None,
        store_dir: Some(project.join("store")),
    })
    .expect("test resolver")
}

/// Fluxor's own project, whose target registry names every target.
#[cfg(test)]
fn fluxor_root() -> &'static std::path::Path {
    std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

/// Fluxor's own modules, resolved with no module ABI: their manifests, and
/// no builds.
#[cfg(test)]
fn fluxor_resolver() -> crate::module_resolver::ModuleResolver {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    crate::module_resolver::ModuleResolver::for_project(
        &root,
        crate::module_resolver::Abi::Unplaced,
        None,
    )
    .expect("fluxor's resolver")
}

/// A throwaway project whose tree holds `types` as plain PIC modules (a
/// version and the hosts they place on), and its resolver.
#[cfg(test)]
fn stub_resolver(types: &[&str]) -> (tempfile::TempDir, crate::module_resolver::ModuleResolver) {
    let dir = tempfile::tempdir().expect("tempdir");
    for ty in types {
        let m = dir.path().join("modules/app").join(ty);
        std::fs::create_dir_all(&m).expect("mkdir");
        std::fs::write(
            m.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\", \"linux\"]\n",
        )
        .expect("write manifest");
    }
    let r = test_resolver(dir.path(), &[]);
    (dir, r)
}

/// Shared test helpers for env-mutating tests.
///
/// Multiple test modules in this file (`scheduler_validation_tests`
/// and `module_discovery_tests`) mutate `FLUXOR_PROJECT_ROOT` /
/// `FLUXOR_INSTALL_ROOT`. Cargo runs tests inside one binary in
/// parallel by default, and `project::root()` reads the env
/// dynamically — so without a shared lock, parallel tests see each
/// other's mid-test state.
///
/// The lock + guard live here, sibling to both test modules; each
/// uses them via `super::test_env::*`.
#[cfg(test)]
pub(crate) mod test_env {
    /// Process-global env-mutating tests serialise through a single
    /// mutex. The mutex itself lives in `project::tests` (which is
    /// reachable from both lib and bin test targets) so independent
    /// test modules can't accidentally race against each other.
    pub fn lock() -> crate::project::tests::EnvLockGuard {
        match crate::project::tests::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// RAII guard: takes the file-scope env lock, snapshots a set of
    /// env vars, applies overrides, and restores the originals on
    /// drop — so a panic inside a test does not leak mutated state
    /// to subsequent tests.
    pub struct EnvGuard {
        _lock: crate::project::tests::EnvLockGuard,
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        /// Acquire the lock, save current values of `vars`, then set
        /// each to its override.
        pub fn set(vars: &[(&'static str, &std::path::Path)]) -> Self {
            let _lock = lock();
            let mut saved = Vec::with_capacity(vars.len());
            for (k, _) in vars {
                saved.push((*k, std::env::var(k).ok()));
            }
            for (k, v) in vars {
                // SAFETY: process-global env mutation serialised by
                // the file-scope `ENV_LOCK` held in `_lock` for the
                // lifetime of this guard.
                unsafe {
                    std::env::set_var(k, v);
                }
            }
            Self { _lock, saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                // SAFETY: same lock as `set`; runs on drop (incl.
                // panic unwind) so callers never leak overrides.
                unsafe {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod scheduler_validation_tests {
    use super::*;

    // ---- resolve_domain_id: hard-fail on unknown domain ----

    #[test]
    fn unknown_domain_name_is_a_hard_error() {
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "audio", "tick_us": 1000},
                    {"name": "control", "tick_us": 10000}
                ]
            }
        });
        let module = json!({"name": "synth", "type": "x", "domain": "audoi"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("audoi") && msg.contains("audio") && msg.contains("control"),
            "expected error to name typo and known domains, got: {msg}"
        );
    }

    // ---- Adaptive-tick checks read params from top-level OR nested `params:` ----

    #[test]
    fn module_param_u64_reads_top_level_and_nested() {
        // Top-level style `voter_count: 3` (the normal/packed form).
        let top = json!({"name": "r", "type": "raft_engine", "voter_count": 3});
        assert_eq!(module_param_u64(&top, "voter_count"), Some(3));
        // Nested `params: { voter_count: 3 }`.
        let nested = json!({"name": "r", "params": {"voter_count": 3}});
        assert_eq!(module_param_u64(&nested, "voter_count"), Some(3));
        // Absent → None (callers default appropriately).
        assert_eq!(module_param_u64(&json!({"name": "r"}), "voter_count"), None);
        // Top-level wins when both are present.
        let both = json!({"name": "r", "voter_count": 5, "params": {"voter_count": 9}});
        assert_eq!(module_param_u64(&both, "voter_count"), Some(5));
    }

    #[test]
    fn d10_catches_top_level_voter_count_on_adaptive_raft() {
        // raft_engine on an adaptive domain with TOP-LEVEL voter_count > 1 must
        // be rejected by the multi-node raft check, whichever form it is in.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}
        ]}});
        let modules = vec![json!({"name": "raft", "type": "raft_engine", "voter_count": 3})];
        let manifests = std::collections::HashMap::new();
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("multi-node raft on an adaptive domain must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("multi-node") && msg.contains("raft_engine"),
            "expected the multi-node raft rejection, got: {msg}"
        );
    }

    // ---- A malformed manifest is refused before any gate reads it ----

    #[test]
    fn a_malformed_manifest_is_refused_before_any_gate_reads_it() {
        // A typo in `timer_class` must never read as "no manifest" and pass
        // the adaptive gate: the graph's modules resolve strictly, and a
        // manifest that does not parse refuses the graph, naming the module.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("typo_mod");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ntimer_class = \"tikc_counted\"\n",
        )
        .expect("write manifest");
        let modules = vec![json!({"name": "typo_mod", "type": "typo_mod"})];
        let err = match test_resolver(dir.path(), &[dir.path()]).graph_modules(&modules) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a malformed manifest must refuse the graph"),
        };
        assert!(
            err.contains("typo_mod") && err.contains("rejected") && err.contains("tikc_counted"),
            "expected the refusal naming the module and its cause, got: {err}"
        );
    }

    // ---- A rejected manifest is reported as rejected, where it was found ----

    #[test]
    fn a_rejected_manifest_is_refused_naming_its_path_and_cause() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("net_driver");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        // A NetProto output with no `max_record`: found, and rejected.
        let manifest = mod_dir.join("manifest.toml");
        std::fs::write(
            &manifest,
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\n\n\
             [[ports]]\nname = \"net_out\"\ndirection = \"output\"\n\
             content_type = \"NetProto\"\n",
        )
        .expect("write manifest");
        let r = test_resolver(dir.path(), &[dir.path()]);
        let err = match r.graph_modules(&[json!({"name": "uplink", "type": "net_driver"})]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a found but rejected manifest refuses the graph"),
        };
        assert!(
            err.contains("module 'uplink' (type 'net_driver')")
                && err.contains("was found at")
                && err.contains(&mod_dir.display().to_string())
                && err.contains("max_record")
                && !err.contains("no manifest found"),
            "{err}"
        );

        // A module found nowhere is refused too, naming where it was sought.
        let absent = r
            .graph_modules(&[json!({"name": "elsewhere", "type": "not_on_any_path"})])
            .err()
            .expect("an absent module refuses the graph")
            .to_string();
        assert!(absent.contains("resolves nowhere"), "{absent}");
    }

    #[test]
    fn a_misspelled_module_in_wiring_offers_the_declared_name() {
        let names = vec!["linux_net".to_string(), "ip".to_string()];
        let manifests = std::collections::HashMap::new();
        let typo = resolve_port_spec("linux_nte.net_out", true, &manifests, &names).unwrap_err();
        assert!(typo.contains("Did you mean 'linux_net'?"), "{typo}");
    }

    // ---- High-1: timer-class admission is fail-closed for mechanism (b) ----

    #[test]
    fn a_module_with_no_manifest_is_refused_on_every_domain() {
        // A module directory with no manifest.toml attests nothing — no
        // timer class, no ports — so the graph's modules refuse it before any
        // domain's gate is consulted, naming where it was looked for.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("no_manifest_mod")).expect("mkdir");
        let modules = vec![json!({"name": "no_manifest_mod", "type": "no_manifest_mod"})];
        let err = match test_resolver(dir.path(), &[dir.path()]).graph_modules(&modules) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a module with no manifest must refuse the graph"),
        };
        assert!(
            err.contains("no_manifest_mod") && err.contains("resolves nowhere"),
            "expected the absence refusal, got: {err}"
        );
    }

    #[test]
    fn unattested_manifest_blocked_on_cadence_b_domain() {
        // A module WITH a manifest but NO timer_class field defaults to Unattested
        // → blocked on a (b) domain. The map carries the parsed (Unattested) manifest.
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("plain".to_string(), Manifest::default()); // timer_class=Unattested
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 3,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let modules = vec![json!({"name": "plain", "type": "plain"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("an unattested manifest must be blocked on a (b) domain");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("positively attest") && msg.contains("plain"),
            "expected positive-attestation diagnostic, got: {msg}"
        );
    }

    #[test]
    fn adaptive_burst_floor_honours_explicit_deadline_override() {
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2,
             "tick_min_us": 1750, "tick_max_us": 3500}
        ]}});
        // The implicit burst (12_000 * 8) exceeds 16 * tick_min, while the
        // explicitly bounded 28 ms burst fits exactly. The adaptive validator
        // must use the same effective deadline as config packing/runtime.
        let modules = vec![json!({
            "name": "wal", "type": "wal", "step_deadline_us": 12_000,
            "step_deadline_burst_us": 28_000
        })];
        let mut manifests = std::collections::HashMap::new();
        manifests.insert(
            "wal".to_string(),
            Manifest {
                timer_class: TimerClass::WallClock,
                ..Manifest::default()
            },
        );
        let names = vec!["main".to_string()];
        let ticks = vec![3500u16];
        validate_adaptive_tick(
            &cfg,
            &modules,
            3500,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect("explicit burst deadline should govern adaptive floor admission");
    }

    #[test]
    fn attested_module_passes_on_cadence_b_domain() {
        // wall_clock and explicit agnostic both positively attest → admitted on (b).
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 3,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let modules = vec![json!({"name": "ok", "type": "ok"})];
        for tc in [TimerClass::WallClock, TimerClass::Agnostic] {
            let man = Manifest {
                timer_class: tc,
                ..Manifest::default()
            };
            let mut manifests = std::collections::HashMap::new();
            manifests.insert("ok".to_string(), man);
            validate_adaptive_tick(
                &cfg,
                &modules,
                100,
                &names,
                &ticks,
                &manifests,
                None,
                fluxor_root(),
            )
            .unwrap_or_else(|e| panic!("{} must pass on a (b) domain, got: {e:?}", tc.as_str()));
        }
    }

    #[test]
    fn step_period_ticks_blocked_on_cadence_b_unless_wallclock() {
        // A non-zero step_period_ticks is tick-counted, so it is blocked on a
        // (b) domain unless the module is wall_clock (agnostic does NOT
        // override it).
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 3,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let modules = vec![json!({"name": "periodic", "type": "periodic"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];

        // agnostic + step_period_ticks=5 → blocked.
        let blocked = Manifest {
            timer_class: TimerClass::Agnostic,
            step_period_ticks: 5,
            ..Manifest::default()
        };
        let mut m_blocked = std::collections::HashMap::new();
        m_blocked.insert("periodic".to_string(), blocked);
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &m_blocked,
            None,
            fluxor_root(),
        )
        .expect_err("step_period_ticks!=0 on (b) must be blocked unless wall_clock");
        assert!(
            format!("{err:?}").contains("step_period_ticks"),
            "expected step_period_ticks diagnostic, got: {err:?}"
        );

        // wall_clock + step_period_ticks=5 → passes (re-derives from real time).
        let ok = Manifest {
            timer_class: TimerClass::WallClock,
            step_period_ticks: 5,
            ..Manifest::default()
        };
        let mut m_ok = std::collections::HashMap::new();
        m_ok.insert("periodic".to_string(), ok);
        validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &m_ok,
            None,
            fluxor_root(),
        )
        .expect("a wall_clock step-period module must pass on a (b) domain");
    }

    #[test]
    fn replicated_clock_blocked_on_cadence_b_without_replica_agreement() {
        // A replicated_clock module self-reads wall-clock time
        // (so it passes the timer-class attestation gate), but mechanism (b) changing
        // the emission cadence shifts replicated expiry. Blocked on (b) unless the
        // domain asserts replica-agreed emission cadence.
        let modules = vec![json!({"name": "ttl", "type": "ttl_scheduler"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let man = Manifest {
            timer_class: TimerClass::ReplicatedClock,
            ..Manifest::default()
        };

        // Without the assertion → blocked.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ttl".to_string(), man.clone());
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("replicated_clock on (b) must be blocked without replica agreement");
        assert!(
            format!("{err:?}").contains("replicated_clock")
                && format!("{err:?}").contains("replica_agreed_cadence"),
            "expected the replicated-clock diagnostic naming the field that admits it, \
             got: {err:?}"
        );

        // With replica_agreed_cadence: true → passes (single node).
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000, "replica_agreed_cadence": true}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect("replicated_clock on (b) must pass once replica agreement is asserted");
    }

    #[test]
    fn replicated_clock_multi_node_blocked_even_with_assertion() {
        // A multi-node cluster cannot agree on emission rate under
        // independent per-node pacing — blocked on (b) regardless of the assertion.
        let modules = vec![json!({"name": "ttl", "type": "ttl_scheduler", "voter_count": 3})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let man = Manifest {
            timer_class: TimerClass::ReplicatedClock,
            ..Manifest::default()
        };
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000, "replica_agreed_cadence": true}]}});
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ttl".to_string(), man);
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("replicated_clock on (b) multi-node must be blocked");
        assert!(
            format!("{err:?}").contains("multi-node"),
            "expected multi-node diagnostic, got: {err:?}"
        );
    }

    #[test]
    fn many_resident_workloads_need_no_pacer_table_gate() {
        // The kernel holds a pacer instance and a resident-graph entry per
        // owner slot and execution domain, sized at boot with the owner table,
        // so a node graph plus forty single-domain workloads — past any fixed
        // table — passes the adaptive-tick gates, adaptive or fixed-tick. The
        // owner pool's bound is the boot plan's (`capacity::check_boot_plan`).
        let modules = vec![json!({"name": "m", "type": "passthrough"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let manifests = std::collections::HashMap::new();
        let adaptive = json!({
            "name": "main", "adaptive_flags": 1,
            "tick_min_us": 100, "tick_max_us": 8000
        });
        let fixed = json!({"name": "main"});
        let workloads: Vec<_> = (0..40)
            .map(|i| json!({"modules": [{"name": format!("p{i}"), "type": "passthrough", "domain": 0}]}))
            .collect();
        for domain in [adaptive, fixed] {
            let cfg = json!({"execution": {"domains": [domain]}, "workloads": workloads.clone()});
            // resolved_target None ⇒ event-driven (Linux): the bcm wake-policy
            // gate does not apply.
            validate_adaptive_tick(
                &cfg,
                &modules,
                100,
                &names,
                &ticks,
                &manifests,
                None,
                fluxor_root(),
            )
            .expect("forty resident workloads need no pacer-table admission");
        }
    }

    #[test]
    fn multi_graph_interrupt_mode_workload_rejected() {
        // A workload module placed in an interrupt-mode domain must be rejected
        // at emit time — a workload's graph carries no ISR metadata and workload admission
        // runs after ISR registration, so it would never execute.
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        // Domain 1 is `exec: timer`; domain 0 is `exec: tick`.
        let cfg_isr = json!({
            "execution": {"domains": [
                {"name": "coop"},
                {"name": "isrd", "exec": "timer", "rate_hz": 1000}
            ]},
            "workloads": [{"modules": [{"name": "p", "type": "workload_pic_mod", "domain": "isrd"}]}]
        });
        let err = build_workload_section(&cfg_isr, &r)
            .expect_err("an interrupt-mode workload placement must be rejected");
        assert!(
            format!("{err:?}").contains("`exec: timer` domain"),
            "expected the interrupt-mode workload rejection diagnostic, got: {err:?}"
        );

        // Same module in the cooperative domain is accepted (reaches schema/emit).
        let cfg_ok = json!({
            "execution": {"domains": [
                {"name": "coop"},
                {"name": "isrd", "exec": "timer", "rate_hz": 1000}
            ]},
            "workloads": [{"modules": [{"name": "p", "type": "workload_pic_mod", "domain": "coop"}]}]
        });
        build_workload_section(&cfg_ok, &r)
            .expect("a cooperative-domain workload placement must be accepted");
    }

    #[test]
    fn multi_graph_duplicate_workload_local_name_rejected() {
        // Two modules sharing a workload-local name would silently overwrite the
        // wiring map (`name_to_local`) and mis-route edges. Must be rejected.
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let cfg = json!({
            "execution": {"domains": [{"name": "coop"}]},
            "workloads": [{"modules": [
                {"name": "dup", "type": "workload_pic_mod", "domain": "coop"},
                {"name": "dup", "type": "workload_pic_mod2", "domain": "coop"}
            ]}]
        });
        let err = build_workload_section(&cfg, &r)
            .expect_err("duplicate workload-local module names must be rejected");
        assert!(
            format!("{err:?}").contains("duplicate module name"),
            "expected the duplicate-name diagnostic, got: {err:?}"
        );
    }

    /// A static graph is explicit about what its workloads listen on: each
    /// workload's `endpoints:` become its owner's grants, carried in its boot
    /// record, and a workload declaring none is granted none, so every
    /// listen it makes is refused where it runs.
    #[test]
    fn a_workloads_declared_endpoints_are_its_grants_and_none_is_none() {
        use fluxor_abi::contracts::net::net_proto::grant;
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let cfg = json!({
            "execution": {"domains": [{"name": "coop"}]},
            "workloads": [
                {
                    "modules": [{"name": "a", "type": "workload_pic_mod", "domain": "coop"}],
                    "endpoints": [
                        {"protocol": "tcp", "port": 8080},
                        {"name": "dns", "protocol": "udp", "port": 5353}
                    ]
                },
                {"modules": [{"name": "b", "type": "workload_pic_mod2", "domain": "coop"}]}
            ]
        });
        let w = build_workloads(&cfg, &r, "linux").expect("composes");
        assert_eq!(
            w[0].endpoints,
            vec![
                [grant::PROTO_TCP, 0x90, 0x1F],
                [grant::PROTO_UDP, 0xE9, 0x14]
            ]
        );
        assert!(w[1].endpoints.is_empty(), "none declared, none granted");

        // Carried in the boot record, as the kernel admits them.
        let records: Vec<(Vec<u8>, Vec<u8>)> = w
            .iter()
            .map(|w| {
                (
                    w.endpoints.concat(),
                    crate::add_subgraph::encode_workload(w).unwrap(),
                )
            })
            .collect();
        let wr: Vec<fluxor_contracts::boot_config::WorkloadRecord<'_>> = records
            .iter()
            .map(|(e, b)| fluxor_contracts::boot_config::WorkloadRecord {
                idle_safe: false,
                endpoints: e,
                blob: b,
            })
            .collect();
        let blob = fluxor_contracts::boot_config::encode(
            &fluxor_contracts::boot_config::BootConfigSpec {
                tick_us: 1000,
                workloads: Some(&wr),
                ..Default::default()
            },
        )
        .expect("encodes");
        let v = crate::config::decode_config(&blob).expect("decodes");
        assert_eq!(
            v["workloads"][0]["endpoints"],
            json!([{"protocol": 6, "port": 8080}, {"protocol": 17, "port": 5353}])
        );
        assert_eq!(v["workloads"][1]["endpoints"], json!([]));
    }

    /// What a workload may declare: tcp or udp, a nonzero port, each once,
    /// at most the admitted bound, and one owner's per endpoint across the
    /// graph's workloads.
    #[test]
    fn a_workloads_endpoints_are_refused_unless_well_formed_and_its_own() {
        use fluxor_abi::contracts::net::net_proto::grant;
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let with = |a: Value, b: Value| {
            let cfg = json!({
                "execution": {"domains": [{"name": "coop"}]},
                "workloads": [
                    {"modules": [{"name": "a", "type": "workload_pic_mod", "domain": "coop"}],
                     "endpoints": a},
                    {"modules": [{"name": "b", "type": "workload_pic_mod2", "domain": "coop"}],
                     "endpoints": b}
                ]
            });
            build_workloads(&cfg, &r, "linux")
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        };
        let tcp = |port: u64| json!({"protocol": "tcp", "port": port});
        assert!(with(json!([tcp(80)]), json!([tcp(81)])).is_ok());
        for (a, b, why) in [
            (json!([tcp(80)]), json!([tcp(80)]), "workload 0's"),
            (json!([tcp(0)]), json!([]), "port 0 is an ephemeral source"),
            (json!([tcp(70000)]), json!([]), "`port` is 1..=65535"),
            (
                json!([{"protocol": "sctp", "port": 80}]),
                json!([]),
                "`protocol` is tcp or udp",
            ),
            (json!([tcp(80), tcp(80)]), json!([]), "declared twice"),
            (
                json!([{"protocol": "tcp", "port": 80, "host": "x"}]),
                json!([]),
                "unknown key `host`",
            ),
            (json!({"protocol": "tcp"}), json!([]), "is a list"),
        ] {
            let e = with(a.clone(), b).expect_err(why);
            assert!(e.contains(why), "{a}: {e}");
        }
        let many: Vec<Value> = (0..=grant::MAX_ADMITTED_ENDPOINTS as u64)
            .map(|i| tcp(1000 + i))
            .collect();
        let e = with(json!(many), json!([])).expect_err("past the bound");
        assert!(e.contains("at most"), "{e}");
    }

    /// On a metal node every module a workload brings runs unprivileged: a
    /// provider runs in a workload only as a type the node vouches for
    /// (`workload_instantiable`); the Linux runtime runs a workload's modules
    /// in its process and admits any; a metal target with no protection
    /// backend admits no workload.
    #[test]
    fn a_metal_workload_composes_a_provider_only_as_a_workload_instantiable_type() {
        let r = fluxor_resolver();
        let with = |ty: &str| {
            json!({
                "execution": {"domains": [{"name": "coop"}]},
                "workloads": [{"modules": [
                    {"name": "w", "type": ty, "domain": "coop"},
                    {"name": "probe", "type": "churn_probe", "domain": "coop"}
                ]}]
            })
        };
        // `key_vault` provides and is not workload_instantiable.
        let e = build_workloads(&with("key_vault"), &r, "pi5")
            .expect_err("an unvouched provider in a metal workload")
            .to_string();
        assert!(e.contains("workload_instantiable"), "{e}");
        // `fs_object` is vouched for.
        build_workloads(&with("fs_object"), &r, "pi5").expect("a vouched provider composes");
        // The Linux runtime runs both in its process.
        assert_eq!(
            super::workload_gating(Some("linux"), fluxor_root()),
            super::WorkloadGating::Host
        );
        assert_eq!(
            super::workload_gating(Some("bcm2712"), fluxor_root()),
            super::WorkloadGating::Gated
        );
        // No protection backend: no workload at all.
        assert_eq!(
            super::workload_gating(Some("uefi"), fluxor_root()),
            super::WorkloadGating::Unavailable
        );
        let e = build_workloads(&with("fs_object"), &r, "uefi")
            .expect_err("a workload on a node with no protection backend")
            .to_string();
        assert!(e.contains("no protection backend"), "{e}");
    }

    /// A workload's vault kept under its owner's key is given the creator's
    /// lane into `seal_in`, keyed from 7 down; a node graph's vault cannot
    /// be kept so, and no graph writes a `Caller` edge of its own.
    #[test]
    fn a_workloads_owner_sealed_vault_takes_its_key_over_the_creators_lane() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let vault = Manifest::from_toml_for_target(
            &root.join("modules/foundation/key_vault/manifest.toml"),
            Some("linux"),
        )
        .expect("key_vault manifest");
        let names: Vec<String> = ["v", "plain", "u"].iter().map(|s| s.to_string()).collect();
        let manifests: HashMap<String, Manifest> =
            names.iter().map(|n| (n.clone(), vault.clone())).collect();
        let entries = vec![
            json!({"name": "v", "type": "key_vault", "seal": "owner"}),
            json!({"name": "plain", "type": "key_vault", "seal": "none"}),
            json!({"name": "u", "type": "key_vault", "seal": 2}),
        ];
        let lanes = super::owner_key_lanes(0, &entries, &names, &manifests, &[]).unwrap();
        let got: Vec<_> = lanes.iter().map(|e| (e.from, e.to, e.to_port, e.to_ctrl)).collect();
        assert_eq!(
            got,
            vec![
                (graph::Endpoint::Caller(7), graph::Endpoint::New(0), 1, false),
                (graph::Endpoint::Caller(6), graph::Endpoint::New(2), 1, false),
            ],
            "seal_in is input 1, keys from 7 down, none for `seal: none`"
        );
        // A key another edge holds is passed over.
        let held = [graph::EdgeRecord {
            from: graph::Endpoint::New(1),
            to: graph::Endpoint::Caller(7),
            ..graph::EdgeRecord::default()
        }];
        let lanes = super::owner_key_lanes(0, &entries, &names, &manifests, &held).unwrap();
        assert_eq!(lanes[0].from, graph::Endpoint::Caller(6));
        assert_eq!(lanes[1].from, graph::Endpoint::Caller(5));

        // A hand-written lane end is refused, as a name or as a record.
        let name_to_local: HashMap<String, u8> =
            names.iter().enumerate().map(|(i, n)| (n.clone(), i as u8)).collect();
        for end in [json!("caller.0"), json!({"caller": 7})] {
            let wiring = vec![json!({"from": end, "to": "v.seal_in"})];
            let e = super::workload_edges(0, &wiring, &name_to_local, &names, &manifests)
                .expect_err("a hand-authored Caller edge")
                .to_string();
            assert!(e.contains("the composer's to wire"), "{e}");
        }

        // A node graph's vault is never kept under an owner's key.
        let mut m = HashMap::new();
        m.insert(
            "vault".to_string(),
            Manifest {
                provides: vec!["key_vault".to_string()],
                ..Manifest::default()
            },
        );
        let g = json!({"modules": [{"name": "vault", "seal": "owner"}]});
        let e = validate_key_vault(&g, &["vault".to_string()], &m, Some("linux"), "linux")
            .expect_err("seal: owner in a node graph")
            .to_string();
        assert!(e.contains("only a workload's vault has"), "{e}");
    }

    /// A workload module's YAML step budget reaches its module record.
    #[test]
    fn workload_module_step_budget_rides_the_module_record() {
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let cfg = json!({
            "execution": {"domains": [{"name": "coop", "tick_us": 1000}]},
            "workloads": [{"modules": [
                {"name": "kv", "type": "workload_pic_mod", "domain": "coop",
                 "step_deadline_us": 12000, "step_deadline_burst_us": 16000,
                 "fault_policy": "skip"},
                {"name": "plain", "type": "workload_pic_mod2", "domain": "coop"}
            ]}]
        });
        let w = build_workloads(&cfg, &r, "linux").expect("admitted budget builds");
        let m = &w[0].graph.modules;
        assert_eq!(
            m[0].budget,
            crate::add_subgraph::StepBudget {
                deadline_us: 12_000,
                burst_us: 16_000,
                fault_policy: FaultPolicy::Skip,
            }
        );
        assert_eq!(m[1].budget, crate::add_subgraph::StepBudget::default());
        let blob = crate::add_subgraph::encode_workload(&w[0]).unwrap();
        let g = graph::decode(&blob).expect("the codec takes it");
        let r = g.modules().next().unwrap();
        assert_eq!((r.step_deadline_us, r.burst_us), (12_000, 16_000));
        assert_eq!(r.fault_policy, FaultPolicy::Skip);
    }

    /// A workload's modules reach only providers of their own, the node's
    /// workload layers and the platform providers that serve workloads, so a
    /// workload's claims are checked against its own providers, as a graph's
    /// are against its own. The host fs is the node's alone: a workload that
    /// names it (`platform`) is refused.
    #[test]
    fn workload_claims_are_checked_against_the_workloads_providers() {
        let r = fluxor_resolver();
        let build = |volume: Value| {
            let cfg = json!({"workloads": [{
                "modules": [
                    {"name": "disk", "type": "file_block", "path": "d.img", "volume": volume},
                    {"name": "fs", "type": "fat32"},
                ],
                "wiring": [{"from": "disk", "to": "fs"}],
            }]});
            build_workloads(&cfg, &r, "linux")
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let e = build(Value::Null).unwrap_err();
        assert!(
            e.contains("workload 0: `disk`'s `fs` claim leaves its `volume` param")
                && e.contains("which it feeds (`disk` → `fs`)"),
            "{e}"
        );
        let e = build(json!("nvme0")).unwrap_err();
        assert!(
            e.contains("names volume `nvme0`") && e.contains("declared: none"),
            "{e}"
        );
        let e = build(json!("platform")).unwrap_err();
        assert!(
            e.contains("names volume `platform`")
                && e.contains("on linux answers no `fs` call of a workload's modules"),
            "{e}"
        );
    }

    /// A workload's `mount` table names volumes of the workload's own.
    #[test]
    fn a_workload_mount_table_names_the_workloads_volumes() {
        let r = fluxor_resolver();
        let build = |mounts: &str| {
            let cfg = json!({"workloads": [{
                "modules": [
                    {"name": "data", "type": "fat32", "volume": "nvme0"},
                    {"name": "mount", "type": "mount", "mounts": mounts},
                ],
            }]});
            build_workloads(&cfg, &r, "linux")
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        build("/data=nvme0").expect("the workload's own volume");
        let e = build("/data=sd0").unwrap_err();
        assert!(
            e.contains("workload 0: `mount`'s `fs` claim mounts `/data` on volume `sd0`"),
            "{e}"
        );
    }

    /// The edges a workload's `wiring:` resolves to, composed, or why it is
    /// refused.
    fn workload_wiring(
        modules: Value,
        wiring: Value,
    ) -> std::result::Result<Vec<graph::EdgeRecord>, String> {
        let r = fluxor_resolver();
        let cfg = json!({"workloads": [{"modules": modules, "wiring": wiring}]});
        build_workloads(&cfg, &r, "linux")
            .map(|mut w| w.remove(0).graph.edges)
            .map_err(|e| e.to_string())
    }

    fn port_index(module: &str, port: &str) -> u8 {
        fluxor_resolver()
            .require(module, module, None)
            .unwrap()
            .manifest
            .find_port_by_name(port)
            .unwrap_or_else(|| panic!("{module}.{port}"))
            .1
    }

    /// A workload's wiring is a graph's: `module.port` ends resolve
    /// against the manifests, and `linux_net` is the node's network — each
    /// module wired to it a lane of its own, keyed in the order the wiring
    /// first names it.
    #[test]
    fn a_workload_wires_named_ports_and_the_node_network_as_a_graph_does() {
        let edges = workload_wiring(
            json!([
                {"name": "front", "type": "tls"},
                {"name": "link", "type": "remote_channel"},
                {"name": "back", "type": "tls"},
            ]),
            json!([
                {"from": "front.cipher_out", "to": "linux_net.net_in", "buffer_bytes": 4096},
                {"from": "linux_net.net_out", "to": "front.cipher_in"},
                {"from": "front.clear_out", "to": "link.transport_in"},
                {"from": "link.transport_out", "to": "front.clear_in"},
                {"from": "linux_net", "to": "back.cipher_in"},
                {"from": "back.cipher_out", "to": "linux_net"},
            ]),
        )
        .unwrap();
        let shape: Vec<_> = edges
            .iter()
            .map(|e| (e.from, e.from_port, e.to, e.to_port, e.buffer_bytes))
            .collect();
        let l = graph::Endpoint::New;
        let n = |key| graph::Endpoint::Lane {
            key,
            target: fluxor_abi::wire::fnv1a32(b"linux_net"),
        };
        assert_eq!(
            shape,
            vec![
                (l(0), port_index("tls", "cipher_out"), n(0), 0, 4096),
                (n(0), 0, l(0), port_index("tls", "cipher_in"), 0),
                (
                    l(0),
                    port_index("tls", "clear_out"),
                    l(1),
                    port_index("remote_channel", "transport_in"),
                    0
                ),
                (
                    l(1),
                    port_index("remote_channel", "transport_out"),
                    l(0),
                    port_index("tls", "clear_in"),
                    0
                ),
                (n(1), 0, l(2), port_index("tls", "cipher_in"), 0),
                (l(2), port_index("tls", "cipher_out"), n(1), 0, 0),
            ]
        );
        // Not every port is the first of its direction: the names matter.
        assert_ne!(port_index("tls", "clear_out"), 0);
        // A control input rides the edge's control flag.
        let edges = workload_wiring(
            json!([{"name": "a", "type": "fs_bank"}, {"name": "b", "type": "fs_bank"}]),
            json!([{"from": "a.notify", "to": "b.commands"}]),
        )
        .unwrap();
        assert_eq!(edges[0].from_port, port_index("fs_bank", "notify"));
        assert_eq!(
            (edges[0].to_ctrl, edges[0].to_port),
            (true, port_index("fs_bank", "commands"))
        );
    }

    /// What a workload's wiring cannot say is refused, naming the edge.
    #[test]
    fn a_workload_wiring_refuses_what_it_cannot_carry() {
        let tls = json!([{"name": "front", "type": "tls"}]);
        let refused =
            |modules: &Value, wiring: Value| match workload_wiring(modules.clone(), wiring) {
                Ok(_) => panic!("refused"),
                Err(e) => e,
            };
        let lane = |extra: Value| {
            let mut w = vec![
                json!({"from": "front.cipher_out", "to": "linux_net.net_in"}),
                json!({"from": "linux_net.net_out", "to": "front.cipher_in"}),
            ];
            w.push(extra);
            Value::Array(w)
        };
        // The numeric forms are gone.
        let e = refused(
            &tls,
            json!([{"from": "front", "to": "front", "from_port": 1}]),
        );
        assert!(
            e.contains("wiring 0: `from_port` is not a wiring key"),
            "{e}"
        );
        let e = refused(&tls, json!([{"from": "net:0", "to": "front"}]));
        assert!(
            e.contains("`net:0`: the node's network is the platform's `linux_net`"),
            "{e}"
        );
        // An unknown port, with what the manifest has.
        let e = refused(
            &tls,
            json!([{"from": "front.clear_ot", "to": "linux_net.net_in"}]),
        );
        assert!(
            e.contains("wiring 0: from `front.clear_ot`")
                && e.contains("Did you mean 'clear_out'?"),
            "{e}"
        );
        // A port used the wrong way round.
        let e = refused(
            &tls,
            json!([{"from": "front.cipher_in", "to": "linux_net.net_in"}]),
        );
        assert!(e.contains("used in 'from:'"), "{e}");
        // An unknown module.
        let e = refused(
            &tls,
            json!([{"from": "frnt.cipher_out", "to": "linux_net.net_in"}]),
        );
        assert!(
            e.contains("unknown module `frnt`. Did you mean 'front'?"),
            "{e}"
        );
        // The network is reached through the lane alone.
        let e = refused(
            &tls,
            json!([{"from": "front.cipher_out", "to": "linux_net.net_out"}]),
        );
        assert!(e.contains("through its lane alone"), "{e}");
        // A lane is one edge each way.
        let e = refused(
            &tls,
            json!([{"from": "front.cipher_out", "to": "linux_net.net_in"}]),
        );
        assert!(
            e.contains(
                "`front` is wired to the node's network 1 time(s) toward it and 0 time(s) from it"
            ),
            "{e}"
        );
        let e = refused(
            &tls,
            lane(json!({"from": "front.clear_out", "to": "linux_net.net_in"})),
        );
        assert!(
            e.contains("2 time(s) toward it and 1 time(s) from it"),
            "{e}"
        );
        let e = refused(
            &tls,
            lane(json!({"from": "linux_net.net_out", "to": "linux_net.net_in"})),
        );
        assert!(e.contains("not to itself"), "{e}");
        // The network is not a module of the workload.
        let e = refused(
            &json!([{"name": "linux_net"}, {"name": "front", "type": "tls"}]),
            lane(json!({"from": "front.clear_out", "to": "front.clear_in"})),
        );
        assert!(
            e.contains("`linux_net` is the node's network, not a module of the workload"),
            "{e}"
        );
        workload_wiring(
            tls.clone(),
            lane(json!({"from": "front.clear_out", "to": "front.clear_in"})),
        )
        .expect("one lane, one loop");
    }

    /// A workload's caps are its composed graph's: its fans are modules and
    /// their joining edges edges. Seventeen modules each feeding every later
    /// one compose to 47 modules (15 tees, 15 merges) and 166 edges, under
    /// `MAX_ADD_MODULES` (64) and `MAX_ADD_EDGES` (192). Six more, each
    /// feeding every later one and four of them a second time, add 14
    /// modules and 27 edges: 193, refused. An eighteenth module in the first
    /// would wire one output to seventeen inputs, past a fan's sixteen ports.
    #[test]
    fn a_workload_builds_up_to_the_subgraph_caps_fans_included() {
        use crate::add_subgraph::{encode_workload, MAX_ADD_EDGES, MAX_ADD_MODULES};
        assert_eq!((MAX_ADD_MODULES, MAX_ADD_EDGES), (64, 192));
        let r = fluxor_resolver();
        let dag = |prefix: &str, n: usize, again: &[(usize, usize)]| -> (Vec<Value>, Vec<Value>) {
            let modules = (0..n)
                .map(|i| json!({"name": format!("{prefix}{i}"), "type": "churn_probe"}))
                .collect();
            let wiring = (0..n)
                .flat_map(|i| (i + 1..n).map(move |j| (i, j)))
                .chain(again.iter().copied())
                .map(|(a, b)| {
                    json!({"from": format!("{prefix}{a}.data_out"), "to": format!("{prefix}{b}.data_in")})
                })
                .collect();
            (modules, wiring)
        };
        let build = |parts: &[(Vec<Value>, Vec<Value>)]| {
            let modules: Vec<Value> = parts.iter().flat_map(|p| p.0.clone()).collect();
            let wiring: Vec<Value> = parts.iter().flat_map(|p| p.1.clone()).collect();
            let cfg = json!({"workloads": [{"modules": modules, "wiring": wiring}]});
            build_workloads(&cfg, &r, "linux").map_err(|e| e.to_string())
        };
        let fits = build(&[dag("a", 17, &[])]).expect("the workload resolves");
        let g = &fits[0].graph;
        assert_eq!(
            (g.modules.len(), g.fans.len(), g.edges.len()),
            (47, 30, 166)
        );
        let blob = encode_workload(&fits[0]).expect("166 edges encode");
        // The composed header's counts: modules at byte 6, edges at 8.
        assert_eq!(u16::from_le_bytes([blob[6], blob[7]]), 47);
        assert_eq!(u16::from_le_bytes([blob[8], blob[9]]), 166);
        let over = build(&[
            dag("a", 17, &[]),
            dag("b", 6, &[(1, 2), (1, 3), (2, 3), (2, 4)]),
        ])
        .expect("the workload resolves");
        let g = &over[0].graph;
        assert_eq!(
            (g.modules.len(), g.fans.len(), g.edges.len()),
            (61, 38, 193)
        );
        let e = encode_workload(&over[0]).unwrap_err();
        assert!(
            e.contains(
                "workload has 193 edges (38 of them joining fans), exceeds MAX_ADD_EDGES (192)"
            ),
            "{e}"
        );
        let e = build(&[dag("a", 18, &[])]).unwrap_err();
        assert!(
            e.contains("a0.data_out is wired to 17 ports, and the fan that joins them has 16"),
            "{e}"
        );
    }
    /// What the kernel refuses a workload, the build refuses first: a
    /// policy that reaches past the module, and a deadline over 16 × the
    /// domain's shortest tick.
    #[test]
    fn workload_module_step_budget_refusals() {
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let build = |module: Value, domain: Value| {
            let cfg = json!({
                "execution": {"domains": [domain]},
                "workloads": [{"modules": [module]}]
            });
            build_workloads(&cfg, &r, "linux")
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        };
        let dom = json!({"name": "coop", "tick_us": 1000});
        let m = |extra: Value| {
            let mut base = json!({"name": "kv", "type": "workload_pic_mod", "domain": "coop"});
            for (k, v) in extra.as_object().unwrap() {
                base[k] = v.clone();
            }
            base
        };
        for policy in ["restart", "tolerate"] {
            let err = build(m(json!({"fault_policy": policy})), dom.clone()).unwrap_err();
            assert!(err.contains("not available to a workload module"), "{err}");
        }
        let err = build(m(json!({"fault_policy": "restart_graph"})), dom.clone()).unwrap_err();
        assert!(err.contains("'restart_graph' is not a policy"), "{err}");
        build(m(json!({"fault_policy": "skip"})), dom.clone()).expect("skip is admitted");
        let err = build(m(json!({"fault_policy": "forever"})), dom.clone()).unwrap_err();
        assert!(err.contains("is invalid"), "{err}");
        let err = build(
            m(json!({"step_deadline_us": 20000, "step_deadline_burst_us": 16000})),
            dom.clone(),
        )
        .unwrap_err();
        assert!(
            err.contains("step_deadline_us = 20000 exceeds the 16000 us"),
            "{err}"
        );
        // No explicit burst: 3000 × 8 = 24 ms is over.
        let err = build(m(json!({"step_deadline_us": 3000})), dom.clone()).unwrap_err();
        assert!(err.contains("burst deadline 24000 us"), "{err}");
        let err = build(m(json!({"step_deadline_us": -1})), dom.clone()).unwrap_err();
        assert!(err.contains("must be a non-negative integer"), "{err}");
        // On an adaptive-cadence domain the ceiling follows tick_min_us.
        let adaptive = json!({"name": "coop", "tick_us": 1000,
                              "adaptive_flags": 2, "tick_min_us": 500, "tick_max_us": 1000});
        let err = build(
            m(json!({"step_deadline_us": 1000, "step_deadline_burst_us": 12000})),
            adaptive.clone(),
        )
        .unwrap_err();
        assert!(err.contains("exceeds the 8000 us"), "{err}");
        build(
            m(json!({"step_deadline_us": 1000, "step_deadline_burst_us": 8000})),
            adaptive,
        )
        .expect("within 16 × tick_min_us");
        // The hard cap holds on a slow domain: 16 × 50 ms is still 100 ms.
        let slow = json!({"name": "coop", "tick_us": 50000});
        let err = build(
            m(json!({"step_deadline_us": 50000, "step_deadline_burst_us": 150000})),
            slow,
        )
        .unwrap_err();
        assert!(err.contains("exceeds the 100000 us"), "{err}");
    }

    /// A workload module may not declare what a node graph turns into a node
    /// tag; the heap flags and its step budget stay available.
    #[test]
    fn workload_module_node_keys_refused() {
        let (_stub, r) = stub_resolver(&["workload_pic_mod", "workload_pic_mod2"]);
        let build = |extra: Value| {
            let mut m = json!({"name": "kv", "type": "workload_pic_mod", "domain": "coop"});
            for (k, v) in extra.as_object().unwrap() {
                m[k] = v.clone();
            }
            let cfg = json!({
                "execution": {"domains": [{"name": "coop"}]},
                "workloads": [{"modules": [m]}]
            });
            build_workloads(&cfg, &r, "linux")
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        };
        for (key, v) in [
            ("trust_class", json!("platform")),
            ("protection", json!("isolated")),
            ("device_window", json!("uart0")),
            ("isr_budget_cycles", json!(1000)),
            ("irq", json!(33)),
            ("quarantine_partner", json!("other")),
            ("quarantine_partner_idx", json!(0)),
            ("max_restarts", json!(3)),
            ("restart_backoff_ms", json!(10)),
            ("voices", json!(["lead"])),
        ] {
            let err = build(json!({ key: v })).unwrap_err();
            assert!(
                err.contains(&format!("`{key}` is not available to a workload module")),
                "{key}: {err}"
            );
        }
        build(json!({"heap": {"zero_on_free": true, "canary_enabled": true}}))
            .expect("heap flags act on the module's own heap");
        let err = build(json!({"heap": {"zero_on_fre": true}})).unwrap_err();
        assert!(err.contains("unknown heap key"), "{err}");
    }

    /// The heap flags reach a workload module's params as the node graph
    /// encodes them, inside the TLV, before its end marker.
    #[test]
    fn workload_heap_flags_join_the_params_tlv() {
        let m = json!({"heap": {"zero_on_free": true, "alloc_failure_policy": "fault",
                                "canary_enabled": true}});
        // No schema params: a TLV of their own.
        let p = insert_heap_tags(Vec::new(), &m, "kv", None, &HeapPlan::default()).unwrap();
        assert_eq!(
            p,
            vec![0xFE, 0x01, 11, 0, 0xF8, 1, 1, 0xF9, 1, 1, 0xFA, 1, 1, 0xFF, 0x00]
        );
        // Schema params: the flags go before the end marker, the length grows.
        let schema_tlv = vec![0xFE, 0x01, 5, 0, 1, 1, 7, 0xFF, 0x00];
        let p = insert_heap_tags(schema_tlv, &m, "kv", None, &HeapPlan::default()).unwrap();
        assert_eq!(&p[..7], &[0xFE, 0x01, 14, 0, 1, 1, 7]);
        assert_eq!(&p[7..16], &[0xF8, 1, 1, 0xF9, 1, 1, 0xFA, 1, 1]);
        assert_eq!(&p[16..], &[0xFF, 0x00]);
        assert_eq!(crate::add_subgraph::params_node_tag(&p), None);
        // No heap key: untouched.
        let p =
            insert_heap_tags(vec![1, 2, 3], &json!({}), "kv", None, &HeapPlan::default()).unwrap();
        assert_eq!(p, vec![1, 2, 3]);
    }

    /// `heap.arena_bytes` is this instance's heap cap: tag 0xEF, a u32 LE,
    /// in the node graph's entry and in a workload module's params alike.
    #[test]
    fn heap_arena_bytes_packs_as_tag_0xef() {
        // Workload path.
        let m = json!({"heap": {"arena_bytes": 2 * 1024 * 1024}});
        let p = insert_heap_tags(Vec::new(), &m, "kv", None, &HeapPlan::default()).unwrap();
        assert_eq!(
            p,
            vec![0xFE, 0x01, 8, 0, 0xEF, 4, 0x00, 0x00, 0x20, 0x00, 0xFF, 0x00]
        );
        assert_eq!(crate::add_subgraph::params_node_tag(&p), None);

        // Node graph path: no schema source, so the entry's params are the
        // TLV the kernel tags open themselves.
        let manifests = HashMap::new();
        let module = json!({"name": "reader", "type": "reader",
                            "heap": {"arena_bytes": 65536, "zero_on_free": true}});
        let entry = build_module_entry(
            "reader",
            &module,
            0,
            None,
            &json!({}),
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &manifests,
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("emit module entry");
        let params = &entry.params;
        let at = params
            .windows(6)
            .position(|w| w == [0xEF, 4, 0x00, 0x00, 0x01, 0x00])
            .expect("tag 0xEF carries 65536");
        let end = params.iter().rposition(|&b| b == 0xFF).expect("end marker");
        assert!(at < end, "the cap rides before the TLV end marker");

        // Validation: a positive integer that fits a u32.
        for bad in [
            json!(0),
            json!(16),
            json!("4MiB"),
            json!(-1),
            json!(1u64 << 33),
        ] {
            let m = json!({"heap": {"arena_bytes": bad.clone()}});
            let err = validate_heap_subtree(&m, "reader").unwrap_err();
            assert!(
                format!("{err:?}").contains("heap.arena_bytes"),
                "{bad}: {err:?}"
            );
        }
        validate_heap_subtree(&json!({"heap": {"arena_bytes": 4194304}}), "reader")
            .expect("4 MiB is a cap");
    }

    /// `variant:` selects a `[[variant]]` build by name. A number selects no
    /// build and is no param either, so it is refused rather than dropped from
    /// the image; the error points a param of that name at `params:`.
    #[test]
    fn a_variant_that_is_not_a_name_is_refused() {
        let e = validate_variant_key(&json!({"name": "emit", "variant": 8}), "emit")
            .unwrap_err()
            .to_string();
        assert!(e.contains("params: { variant: 8 }"), "{e}");
        validate_variant_key(&json!({"name": "codec", "variant": "audio"}), "codec")
            .expect("a variant name");
        validate_variant_key(&json!({"name": "emit", "params": {"variant": 8}}), "emit")
            .expect("a param called variant");
    }

    #[test]
    fn replicated_clock_idle_clamp_enforced() {
        // Demand-driven idle must not widen tick_max_us past the
        // tick emission interval, else committed expiry stalls.
        let modules = vec![json!({"name": "ttl", "type": "ttl_scheduler", "tick_interval_ms": 50})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let man = Manifest {
            timer_class: TimerClass::ReplicatedClock,
            ..Manifest::default()
        };
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ttl".to_string(), man);

        // idle-only (bit 0), tick_max_us=50000 ≥ 50 ms (=50000 us) interval → blocked.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 50000}]}});
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("idle widen past the emission interval must be blocked");
        assert!(
            format!("{err:?}").contains("emission interval"),
            "expected emission-interval clamp diagnostic, got: {err:?}"
        );

        // tick_max_us=8000 < 50 ms → passes.
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect("idle within the emission interval must pass");
    }

    #[test]
    fn guaranteed_blocked_on_cadence_b_unless_revalidated() {
        // A guaranteed-WCET module's budget shrinks when (b)
        // lowers the tick — blocked unless the domain asserts WCET re-validation
        // at tick_min_us.
        let modules = vec![json!({"name": "ctl", "type": "ctl", "step_deadline_us": 50})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let man = Manifest {
            timer_class: TimerClass::Guaranteed,
            ..Manifest::default()
        };
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ctl".to_string(), man);

        // Without the assertion → blocked.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2,
             "tick_min_us": 1000, "tick_max_us": 8000}]}});
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect_err("guaranteed on (b) must be blocked without WCET re-validation");
        assert!(
            format!("{err:?}").contains("guaranteed_wcet_revalidated"),
            "expected the WCET re-validation diagnostic, got: {err:?}"
        );

        // With the assertion → passes (burst-at-floor still enforced: 50×8=400 ≤ 16×1000).
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2, "tick_min_us": 1000,
             "tick_max_us": 8000, "guaranteed_wcet_revalidated": true}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            None,
            fluxor_root(),
        )
        .expect("guaranteed on (b) must pass once WCET re-validation is asserted");
    }

    #[test]
    fn domain0_unbounded_tick_max_accepted_in_multi_domain() {
        // Pass counts are per domain and periodic dues are wall clock, so an
        // adaptive domain 0 with no `tick_max_us` in a multi-domain config
        // couples nothing: the shape the composer once refused on a bcm2712
        // or Linux target is accepted there, as on rp2350.
        let modules = vec![json!({"name": "m", "type": "m"})];
        let names = vec!["d0".to_string(), "d1".to_string()];
        let ticks = vec![100u16, 100u16];
        let manifests = std::collections::HashMap::new();

        // Two domains, domain 0 adaptive with NO tick_max_us. bcm idle still
        // states its wake policy, which is a rule of its own.
        let cfg = json!({"execution": {
            "bcm_wake_policy": "clamp",
            "domains": [
                {"name": "d0", "adaptive_flags": 1, "tick_min_us": 100},
                {"name": "d1"}]}});
        validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            Some("bcm2712"),
            fluxor_root(),
        )
        .expect("unbounded domain-0 adaptive in a multi-domain bcm2712 config is accepted");
        validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            Some("linux"),
            fluxor_root(),
        )
        .expect("unbounded domain-0 adaptive in a multi-domain linux config is accepted");

        // Bounded tick_max_us on domain 0 → passes.
        let cfg_bounded = json!({"execution": {
            "bcm_wake_policy": "clamp",
            "domains": [
                {"name": "d0", "adaptive_flags": 1, "tick_min_us": 100,
                 "tick_max_us": 8000},
                {"name": "d1"}]}});
        validate_adaptive_tick(
            &cfg_bounded,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            Some("bcm2712"),
            fluxor_root(),
        )
        .expect("bounded domain-0 adaptive must pass");

        // rp2350, without the bcm wake-policy statement, as before.
        let cfg_rp = json!({"execution": {"domains": [
            {"name": "d0", "adaptive_flags": 1, "tick_min_us": 100},
            {"name": "d1"}]}});
        validate_adaptive_tick(
            &cfg_rp,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            Some("rp2350"),
            fluxor_root(),
        )
        .expect("rp2350 accepts unbounded domain-0 adaptive");
    }

    #[test]
    fn adaptive_domain_sharing_a_core_with_strict_domain_is_rejected() {
        // An adaptive domain sharing a core with a timing-strict domain (here
        // raft liveness) is rejected: the adaptive domain's pacing would warp
        // the strict domain's cadence. Which domains share a core is the
        // target's: one core for every domain on rp, Linux and wasm, a core
        // per domain on bcm2712 and uefi.
        let names = vec!["main".to_string(), "rt".to_string()];
        let ticks = vec![100u16, 100u16];
        let manifests = std::collections::HashMap::new();
        let modules = vec![json!({"name": "raft_engine", "type": "raft_engine", "domain": "rt"})];
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "adaptive_flags": 2, "tick_min_us": 100, "tick_max_us": 8000},
            {"name": "rt"}]}});

        // One core for both domains → reject, on rp and with no target.
        for target in [Some("rp2350"), None] {
            let err = validate_adaptive_tick(
                &cfg,
                &modules,
                100,
                &names,
                &ticks,
                &manifests,
                target,
                fluxor_root(),
            )
            .expect_err("adaptive + strict on the same core must be rejected");
            assert!(
                format!("{err:?}").contains("shares a core"),
                "expected shared-core diagnostic, got: {err:?}"
            );
        }

        // Each domain on its own core → no overlap → passes.
        validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            Some("bcm2712"),
            fluxor_root(),
        )
        .expect("strict domain on its own core must pass");
    }

    #[test]
    fn module_without_domain_resolves_to_default_zero() {
        let cfg = json!({
            "execution": {
                "domains": [{"name": "audio", "tick_us": 1000}]
            }
        });
        let module = json!({"name": "m", "type": "x"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 0);
    }

    #[test]
    fn known_domain_resolves_to_its_index() {
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "audio", "tick_us": 1000},
                    {"name": "control", "tick_us": 10000}
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "control"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 1);
    }

    #[test]
    fn resolve_rejects_module_targeting_fifth_or_later_domain() {
        // Defense-in-depth: even if a caller bypasses the
        // `generate_config_impl` top-level rejection of >4
        // domains, `resolve_domain_id` must refuse to return an
        // out-of-range domain id. A `domain_id >= MAX_DOMAINS`
        // can't be encoded in the 4-entry domain metadata + the
        // kernel's `domain_count` clamp would make the runtime
        // behaviour undefined.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "d0"},
                    {"name": "d1"},
                    {"name": "d2"},
                    {"name": "d3"},
                    {"name": "d4"}   // 5th domain — index 4
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "d4"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("at most 4") || msg.contains("index 4"),
            "expected out-of-range domain diagnostic, got: {msg}"
        );
    }

    #[test]
    fn resolve_accepts_module_targeting_fourth_domain() {
        // Boundary: index 3 (the 4th domain) IS valid — the cap
        // is `MAX_DOMAINS = 4` total, so indices 0..=3 are legal.
        // Catches an off-by-one regression where the bound
        // accidentally goes `> MAX_DOMAINS` instead of `>=`.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "d0"},
                    {"name": "d1"},
                    {"name": "d2"},
                    {"name": "d3"}
                ]
            }
        });
        let module = json!({"name": "m", "type": "x", "domain": "d3"});
        assert_eq!(resolve_domain_id(&module, &cfg).unwrap(), 3);
    }

    #[test]
    fn domain_named_without_any_execution_domains_section_errors() {
        // Catches the case where a module asks for a domain but the
        // YAML forgot to declare `execution.domains` at all.
        let cfg = json!({});
        let module = json!({"name": "m", "type": "x", "domain": "audio"});
        let err = resolve_domain_id(&module, &cfg).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("execution.domains is missing"),
            "expected missing-section error, got: {msg}"
        );
    }

    // ---- validate_scheduler_budgets ----

    #[test]
    fn declared_burst_over_100ms_hard_caps() {
        // step_deadline_us=20_000 × BURST_MULTIPLIER(8) = 160 ms > 100 ms hard cap.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![json!({
            "name": "heavy",
            "type": "x",
            "step_deadline_us": 20_000
        })];
        let err = validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("absolute cap") && msg.contains("heavy"),
            "expected absolute-cap error naming the module, got: {msg}"
        );
    }

    #[test]
    fn declared_burst_over_16x_tick_hard_caps() {
        // step_deadline_us=3000 × 8 = 24_000 us. With tick_us=1000,
        // domain budget × 16 = 16_000 us < 24_000 us → hard fail.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![json!({
            "name": "spikey",
            "type": "x",
            "step_deadline_us": 3000
        })];
        let err = validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("16 \u{00d7} domain tick_us") || msg.contains("16 × domain tick_us"),
            "expected 16×-tick error, got: {msg}"
        );
    }

    #[test]
    fn undeclared_deadlines_skip_budget_validation() {
        // Three modules all using the kernel default deadline should
        // not trip the validator — the default is a fault threshold,
        // not a budget claim.
        let cfg = json!({"execution": {"domains": []}});
        let modules = vec![
            json!({"name": "a", "type": "x"}),
            json!({"name": "b", "type": "x"}),
            json!({"name": "c", "type": "x"}),
        ];
        validate_scheduler_budgets(&cfg, &modules, 1000, &[], &[]).unwrap();
    }

    // ---- parse_domain_exec ----

    fn exec_of(dom: serde_json::Value) -> Result<DomainExec> {
        parse_domain_exec(&dom, "d")
    }

    #[test]
    fn exec_spellings_map_to_the_dense_modes() {
        use fluxor_contracts::boot_config::ExecMode;
        for (s, mode, byte) in [
            ("tick", ExecMode::Tick, 0u8),
            ("poll", ExecMode::Poll, 1),
            ("irq", ExecMode::Irq, 3),
        ] {
            let e = exec_of(json!({"exec": s})).unwrap();
            assert_eq!(e.mode, mode);
            assert_eq!(e.mode as u8, byte);
            assert_eq!(e.timer_period_us, 0);
        }
        let e = exec_of(json!({"exec": "timer", "rate_hz": 20000})).unwrap();
        assert_eq!(e.mode, ExecMode::Timer);
        assert_eq!(e.mode as u8, 2);
        assert_eq!(e.timer_period_us, 50);
    }

    #[test]
    fn exec_defaults_to_tick() {
        let e = exec_of(json!({"name": "d"})).unwrap();
        assert_eq!(e.mode, fluxor_contracts::boot_config::ExecMode::Tick);
    }

    #[test]
    fn retired_mode_keys_are_unknown_keys_naming_exec() {
        for dom in [
            json!({"tier": "1a"}),
            json!({"tier": 0}),
            json!({"exec_mode": "poll"}),
            json!({"exec": "tick", "tier": "0"}),
        ] {
            let e = format!("{}", exec_of(dom).unwrap_err());
            assert!(e.contains("unknown key") && e.contains("`exec:`"), "{e}");
        }
    }

    #[test]
    fn cores_is_an_unknown_domain_key() {
        for dom in [json!({"cores": [1]}), json!({"exec": "poll", "cores": []})] {
            let e = format!("{}", exec_of(dom).unwrap_err());
            assert!(
                e.contains("unknown key `cores`") && e.contains("core d"),
                "{e}"
            );
        }
    }

    #[test]
    fn exec_refuses_every_other_spelling() {
        for v in [
            json!("cooperative"),
            json!("high_rate"),
            json!("isr_timer"),
            json!("isr_owned"),
            json!("1a"),
            json!("1b"),
            json!("Tick"),
            json!(0),
        ] {
            let e = format!("{}", exec_of(json!({"exec": v})).unwrap_err());
            assert!(e.contains("not an execution mode"), "{e}");
        }
    }

    #[test]
    fn timer_rate_is_required_whole_and_fits_the_record() {
        let err = |dom| format!("{}", exec_of(dom).unwrap_err());
        assert!(err(json!({"exec": "timer"})).contains("rate_hz"));
        assert!(err(json!({"exec": "timer", "rate_hz": 0})).contains("positive"));
        assert!(err(json!({"exec": "timer", "rate_hz": 3000})).contains("whole number"));
        // 1 Hz is a 1 s period, past the u16 µs record field.
        assert!(err(json!({"exec": "timer", "rate_hz": 1})).contains("longer than"));
        assert!(
            err(json!({"exec": "timer", "rate_hz": 1000, "tick_us": 1000}))
                .contains("not `tick_us`")
        );
        assert_eq!(
            exec_of(json!({"exec": "timer", "rate_hz": 1_000_000}))
                .unwrap()
                .timer_period_us,
            1
        );
        assert_eq!(
            exec_of(json!({"exec": "timer", "rate_hz": 16}))
                .unwrap()
                .timer_period_us,
            62_500
        );
    }

    #[test]
    fn rate_hz_belongs_to_timer_domains_only() {
        for mode in ["tick", "poll", "irq"] {
            let e = format!(
                "{}",
                exec_of(json!({"exec": mode, "rate_hz": 1000})).unwrap_err()
            );
            assert!(e.contains("`exec: timer`"), "{e}");
        }
        let e = format!("{}", exec_of(json!({"rate_hz": 1000})).unwrap_err());
        assert!(e.contains("`exec: tick`"), "{e}");
    }

    #[test]
    fn pre_pass_is_admitted_only_in_tick_domains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("drainer");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\npre_pass = true\n",
        )
        .expect("write manifest");
        let modules = vec![json!({"name": "drainer", "type": "drainer", "domain": "d"})];
        let manifests = test_resolver(dir.path(), &[dir.path()])
            .graph_modules(&modules)
            .expect("resolves")
            .manifests();
        let run = |dom: serde_json::Value| {
            let cfg = json!({"execution": {"domains": [dom]}});
            validate_pre_pass_admission(&cfg, &modules, &manifests)
        };
        run(json!({"name": "d"})).expect("a tick domain admits a pre-pass module");
        run(json!({"name": "d", "exec": "tick", "tick_us": 250}))
            .expect("a tick domain with its own tick admits a pre-pass module");
        for dom in [
            json!({"name": "d", "exec": "poll"}),
            json!({"name": "d", "exec": "timer", "rate_hz": 1000}),
            json!({"name": "d", "exec": "irq"}),
        ] {
            let e = format!("{}", run(dom).unwrap_err());
            assert!(
                e.contains("`pre_pass = true`") && e.contains("`exec: tick`"),
                "{e}"
            );
        }
    }

    #[test]
    fn superseded_manifest_keys_are_refused_by_name() {
        let head = "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\n";
        for (key, new) in [
            ("isr_safe", "interrupt_safe"),
            ("pre_tick_drain", "pre_pass"),
        ] {
            let e = crate::manifest::Manifest::from_toml_str_for_target(
                &format!("{head}{key} = true\n"),
                None,
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains(key) && e.contains(new), "{e}");
        }
    }

    #[test]
    fn a_timer_domain_writes_its_period_into_the_record() {
        let config = json!({
            "tick_us": 1000,
            "execution": {"domains": [
                {"name": "main"},
                {"name": "pwm", "exec": "timer", "rate_hz": 20000},
                {"name": "net", "exec": "poll", "tick_us": 500}
            ]},
            "modules": [],
            "wiring": []
        });
        let blob = generate_config_ext(
            &config,
            &ConfigBuilder::new(),
            &[],
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            0,
            0,
            None,
        )
        .expect("generates");
        let v = decode_config(&blob).expect("decodes");
        assert_eq!(v["domains"][0]["exec"], "tick");
        assert_eq!(v["domains"][0]["tick_us"], 0);
        assert_eq!(v["domains"][1]["exec"], "timer");
        assert_eq!(v["domains"][1]["tick_us"], 50);
        assert_eq!(v["domains"][2]["exec"], "poll");
        assert_eq!(v["domains"][2]["tick_us"], 500);
    }

    // ---- validate_interrupt_admission ----
    //
    // These tests exercise the validator directly with synthetic
    // manifests. Going through the full `fluxor build` path would
    // require a populated modules tree; the validator's contract is
    // narrow enough to test in isolation.

    /// Interrupt-mode admission of `modules`, each resolved in the project
    /// at `project` (else the first of `extras`) with `extras` as its
    /// search paths: a module resolved nowhere reaches the validator with no
    /// manifest.
    fn admit(
        config: &serde_json::Value,
        modules: &[serde_json::Value],
        project: Option<&std::path::Path>,
        extras: &[&std::path::Path],
    ) -> Result<()> {
        let root = project
            .or_else(|| extras.first().copied())
            .unwrap_or(std::path::Path::new("/nonexistent"));
        let r = test_resolver(root, extras);
        let mut manifests = HashMap::new();
        let mut found = HashMap::new();
        for m in modules {
            let Some((name, ty, variant)) = crate::module_resolver::entry_identity(m) else {
                continue;
            };
            if let Some(a) = r.resolve(ty, variant)? {
                manifests.insert(name.to_string(), a.manifest.clone());
                found.insert(name.to_string(), a);
            }
        }
        validate_interrupt_admission(
            config,
            modules,
            &manifests,
            &|name| found.get(name).map_or(Ok(false), |a| a.exports_isr_entry()),
            None,
            r.project_root(),
        )
    }

    fn run_admission(config: serde_json::Value, modules: Vec<serde_json::Value>) -> Result<()> {
        // Resolved in Fluxor's own project, which holds none of these
        // modules' types: each reaches the validator with no manifest, and
        // the target's interrupt controller comes from Fluxor's targets.
        // The cases that need a manifest plant one in a tempdir (`admit`).
        let fluxor = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        admit(&config, &modules, Some(&fluxor), &[])
    }

    #[test]
    fn admission_passes_when_no_interrupt_domains_present() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "exec": "tick", "tick_us": 250}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        run_admission(cfg, modules).expect("cooperative graph admits");
    }

    #[test]
    fn admission_refuses_a_retired_mode_key() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1c"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown key `tier`") && msg.contains("`exec:`"),
            "expected the unknown-key diagnostic naming `exec:`, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_irq_beyond_gic_intid_range() {
        // GIC-400 INTIDs are 0..=1019; an `irq:` past that would index the
        // distributor's enable/priority/target banks out of range on silicon.
        let cfg = json!({
            "target": "pi5",
            "execution": {"domains": [{"name": "isr", "exec": "irq"}]}
        });
        let modules = vec![json!({"name": "probe", "type": "probe", "domain": "isr", "irq": 1100})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("0..=1019") && msg.contains("GIC-400"),
            "expected a GIC INTID-range diagnostic, got: {msg}"
        );
    }

    #[test]
    fn admission_allows_sgi_irq_on_gic() {
        // SGI 15 is a legitimate `irq` owner (the `irq_probe` SGI path); the
        // range check must NOT reject it. Any other error (missing manifest,
        // etc.) is fine here — just not the range diagnostic.
        let cfg = json!({
            "target": "pi5",
            "execution": {"domains": [{"name": "isr", "exec": "irq"}]}
        });
        let modules = vec![json!({"name": "probe", "type": "probe", "domain": "isr", "irq": 15})];
        if let Err(e) = run_admission(cfg, modules) {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("0..=1019"),
                "SGI 15 must not trip the GIC range check, got: {msg}"
            );
        }
    }

    #[test]
    fn admission_rejects_irq_beyond_rp2350_nvic_range() {
        // RP2350 NVIC tops out at SWI_IRQ_5 = 52 (0..=52); a far-larger value
        // would unmask a non-existent line and index NVIC registers out of
        // bounds. (Tests pass no resolved_target, so Rule 0 falls back to
        // config.target.)
        let cfg = json!({
            "target": "rp2350",
            "execution": {"domains": [{"name": "isr", "exec": "irq"}]}
        });
        let modules = vec![json!({"name": "probe", "type": "probe", "domain": "isr", "irq": 1100})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("0..=52") && msg.contains("RP2350"),
            "expected an RP2350 NVIC range diagnostic, got: {msg}"
        );
    }

    #[test]
    fn admission_allows_valid_rp2350_edge_irq() {
        // SWI_IRQ_5 = 52 is the highest valid RP2350 line and must NOT trip the
        // range check; any other error (missing manifest, etc.) is fine — just
        // not the range.
        let cfg = json!({
            "target": "rp2350",
            "execution": {"domains": [{"name": "isr", "exec": "irq"}]}
        });
        let modules = vec![json!({"name": "probe", "type": "probe", "domain": "isr", "irq": 52})];
        if let Err(e) = run_admission(cfg, modules) {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("only has interrupt lines"),
                "valid RP2350 edge IRQ 52 must not trip the range check, got: {msg}"
            );
        }
    }

    #[test]
    fn admission_allows_valid_rp2040_swi_irq() {
        // SWI_IRQ_5 = 31 is the highest valid RP2040 line and must pass the
        // range check.
        let cfg = json!({
            "target": "rp2040",
            "execution": {"domains": [{"name": "isr", "exec": "irq"}]}
        });
        let modules = vec![json!({"name": "probe", "type": "probe", "domain": "isr", "irq": 31})];
        if let Err(e) = run_admission(cfg, modules) {
            let msg = format!("{e:?}");
            assert!(
                !msg.contains("only has interrupt lines"),
                "valid RP2040 SWI IRQ 31 must not trip the range check, got: {msg}"
            );
        }
    }

    #[test]
    fn admission_rejects_timer_module_without_interrupt_safe_manifest() {
        // `timer` is admitted as of 2026-05-26 — but only for modules
        // that declare `interrupt_safe = true` in their manifest. A module
        // without the attestation must be rejected with a precise
        // diagnostic pointing at the offending manifest path.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("unflagged");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\ninterrupt_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "exec": "timer", "rate_hz": 1000}]}
        });
        let modules =
            vec![json!({"name": "unflagged", "type": "unflagged", "domain": "audio_isr"})];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = admit(&cfg, &modules, None, &extras)
            .expect_err("unflagged module in `timer` domain must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("interrupt_safe = true") && msg.contains("unflagged"),
            "diagnostic must name the missing attestation + the module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_timer_module_with_no_resolvable_manifest() {
        // An interrupt-mode module that does not resolve to a manifest (typo
        // in `type:`, missing module dir, build-tree not on the search
        // path) must be refused by `validate_interrupt_admission` itself,
        // not left to `validate_wiring_types`. That validator enforces
        // content types only when **both** endpoints have manifests, so
        // a `timer` module with no edges (or bare/default ports) passes
        // it untouched and lands in the graph without ever running
        // through the `interrupt_safe` check.
        //
        // Hard-error here so the operator gets a single, focused
        // diagnostic naming the unresolved module rather than a
        // silent admission followed by a runtime trap.
        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "exec": "timer", "rate_hz": 1000}]}
        });
        let modules = vec![json!({
            "name": "ghost_module",
            "type": "definitely_not_a_real_module_type_xyz",
            "domain": "audio_isr",
        })];
        let extras: Vec<&std::path::Path> = Vec::new();
        let err = admit(&cfg, &modules, None, &extras)
            .expect_err("`timer` module with no resolvable manifest must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("ghost_module") && msg.contains("manifest"),
            "diagnostic must name the unresolved module + the missing manifest, got: {msg}"
        );
    }

    #[test]
    fn a_type_in_a_layer_and_on_a_search_path_is_refused_naming_both() {
        // Two sources of one type in one project: a module layer
        // (`modules/foundation/coll`, exporting `module_isr_entry`) and a
        // `module_search_paths` entry (`override/coll`, exporting none).
        // `fluxor modules build` shelves the layer's alone, so no order
        // between them can pair one copy's manifest with the bytes that
        // load: the type is refused as ambiguous, naming both.
        let project = tempfile::tempdir().expect("tempdir-project");
        let manifest =
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n";
        let std_dir = project.path().join("modules/foundation/coll");
        std::fs::create_dir_all(std_dir.join("src")).expect("mkdir std");
        std::fs::write(std_dir.join("manifest.toml"), manifest).expect("write std manifest");
        std::fs::write(
            std_dir.join("src/lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write std src");
        let override_root = project.path().join("override");
        let ovr_dir = override_root.join("coll");
        std::fs::create_dir_all(ovr_dir.join("src")).expect("mkdir override");
        std::fs::write(ovr_dir.join("manifest.toml"), manifest).expect("write override manifest");
        std::fs::write(
            ovr_dir.join("src/lib.rs"),
            "fn module_step(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write override src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "exec": "irq"}]}
        });
        let modules = vec![json!({
            "name": "coll",
            "type": "coll",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let err = admit(
            &cfg,
            &modules,
            Some(project.path()),
            &[override_root.as_path()],
        )
        .expect_err("a type with two sources in one project is ambiguous");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("ambiguous")
                && msg.contains("modules/foundation/coll")
                && msg.contains("override/coll"),
            "the refusal names both sources, got: {msg}"
        );
    }

    #[test]
    fn admission_accepts_irq_module_with_isr_entry_export() {
        // An `exec: irq` module declaring
        // `interrupt_safe = true`, an `irq:`, and a real `module_isr_entry`
        // export is admitted.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "exec": "irq"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        admit(&cfg, &modules, None, &extras)
            .expect("`irq` module exporting module_isr_entry must be admitted");
    }

    #[test]
    fn admission_rejects_irq_module_without_isr_entry_export() {
        // an `irq` module that declares `interrupt_safe = true` + `irq:` but
        // whose source exports no `module_isr_entry` is rejected: the
        // kernel would refuse to dispatch its cooperative `module_step`
        // from IRQ context, so surface the gap loudly at build time.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        // Source has no `fn module_isr_entry` definition.
        std::fs::write(
            src.join("lib.rs"),
            "fn module_step(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "exec": "irq"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = admit(&cfg, &modules, None, &extras)
            .expect_err("`irq` module without module_isr_entry must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("module_isr_entry") && msg.contains("irq_driver"),
            "diagnostic must name the missing export + the offending module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_irq_module_without_irq() {
        // an `irq` module that has the ISR entry but no `irq:` field is
        // rejected by Rule 3 — the kernel has no IRQ vector to bind.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "exec": "irq"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
        })];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = admit(&cfg, &modules, None, &extras)
            .expect_err("`irq` module without irq: must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("irq") && msg.contains("irq_driver"),
            "diagnostic must name the missing irq field + the module, got: {msg}"
        );
    }

    #[test]
    fn admission_isr_entry_check_finds_standard_tree_modules_too() {
        // The source checks must find a module's src root wherever its
        // manifest resolved from, `standard_module_dirs()` included. A
        // lookup searching only `modules_dir + extra_module_dirs` would
        // never run the `module_isr_entry` export check against a module
        // under `modules/drivers/<name>`, which would then pass admission
        // silently. This test plants an `interrupt_safe = true` `irq` module with
        // no ISR entry in a fake project root and asserts the check sees it.
        let project = tempfile::tempdir().expect("tempdir");
        // `standard_module_dirs()` reads `$FLUXOR_PROJECT_ROOT`
        // dynamically. Use the shared file-scope env lock + Drop
        // guard so this test (a) does not race the sibling
        // `module_discovery_tests` (which also mutates this var)
        // and (b) restores the original value even on panic.
        let _env = super::test_env::EnvGuard::set(&[("FLUXOR_PROJECT_ROOT", project.path())]);
        let drivers = project.path().join("modules/drivers/entryless_isr_module");
        let src = drivers.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            drivers.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            "fn module_step(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "exec": "irq"}]}
        });
        let modules = vec![json!({
            "name": "entryless_isr_module",
            "type": "entryless_isr_module",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let extras: Vec<&std::path::Path> = Vec::new();
        let err = admit(&cfg, &modules, Some(project.path()), &extras)
            .expect_err("a standard-tree `irq` module without module_isr_entry must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("module_isr_entry") && msg.contains("entryless_isr_module"),
            "diagnostic must name the missing export + the offending module, got: {msg}"
        );
        // `_env` drops here, restoring `FLUXOR_PROJECT_ROOT` and
        // releasing the file-scope env lock.
    }

    #[test]
    fn build_module_entry_emits_pre_pass_bit_from_extra_dir_manifest() {
        // `build_module_entry` reads the manifest the graph's resolver
        // resolved, so a module on a `module_search_paths` entry carries its
        // pre-pass flag into its record, and stays in
        // `domain_pre_pass_order`.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("ext_drainer");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\n\
             pre_pass = true\n",
        )
        .expect("write manifest");

        let modules_value = json!([{
            "name": "ext_drainer",
            "type": "ext_drainer",
        }]);
        let r = test_resolver(dir.path(), &[dir.path()]);
        let manifests = r
            .graph_modules(modules_value.as_array().unwrap())
            .expect("resolves")
            .manifests();
        assert!(
            manifests.get("ext_drainer").is_some_and(|m| m.pre_pass),
            "the search-path manifest resolves with pre_pass = true"
        );

        let config = json!({});
        let module = json!({"name": "ext_drainer", "type": "ext_drainer"});
        let entry = build_module_entry(
            "ext_drainer",
            &module,
            0,
            None,
            &config,
            &r,
            &manifests,
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("emit module entry");
        assert!(
            entry.pre_pass,
            "the module record's pre-pass flag must be SET when the resolved \
             manifest has pre_pass = true"
        );
        assert_eq!(
            entry.domain, 0,
            "the domain should be 0 (no domain assigned in YAML)"
        );
    }

    #[test]
    fn target_aware_manifest_loader_resolves_the_targets_abi_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("sized_stream");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\", \"linux\"]\n\
             [[ports]]\nname = \"stream_out\"\ndirection = \"output\"\n\
             content_type = \"OctetStream\"\n\
             buffer_size = { default = 2048, aarch64 = 8192 }\n",
        )
        .expect("write manifest");

        // The registry resolves each target to its module ABI: bcm2712 and
        // the linux host both load the aarch64 value.
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let resolver = |abi: crate::module_resolver::Abi| {
            crate::module_resolver::ModuleResolver::new(crate::module_resolver::ResolverSpec {
                project_root: dir.path().to_path_buf(),
                abi,
                shelf: None,
                search_paths: vec![dir.path().to_path_buf()],
                install_root: None,
                store_dir: Some(dir.path().join("store")),
            })
            .unwrap()
        };
        let size = |r: crate::module_resolver::ModuleResolver| {
            r.require("sized_stream", "sized_stream", None)
                .unwrap()
                .manifest
                .ports[0]
                .buffer_size
        };
        assert_eq!(size(resolver(crate::module_resolver::Abi::Unplaced)), 2048);
        for target in ["bcm2712", "linux"] {
            let abi = crate::target::load_target(target, &repo)
                .unwrap()
                .module_abi()
                .to_string();
            assert_eq!(
                size(resolver(crate::module_resolver::Abi::Module(abi))),
                8192,
                "{target}"
            );
        }
    }

    #[test]
    fn admission_accepts_timer_module_with_interrupt_safe_manifest() {
        // Mirror of the rejection case: when the manifest declares
        // `interrupt_safe = true`, the `timer` admission path lets the module
        // through. This pins the lift that happened on 2026-05-26.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("attested_isr");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "exec": "timer", "rate_hz": 1000}]}
        });
        let modules = vec![json!({
            "name": "attested_isr",
            "type": "attested_isr",
            "domain": "audio_isr",
        })];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        admit(&cfg, &modules, None, &extras)
            .expect("interrupt_safe = true module in `timer` domain must be admitted");
    }

    #[test]
    fn admission_rejects_any_edge_touching_interrupt_module() {
        // v1 reality (2026-05-26): ANY edge with an interrupt-mode
        // endpoint is rejected at validation. The kernel-side
        // bridge mechanism is wired (and tested via direct test
        // fixtures), but PIC modules in v1 have no documented way
        // to read/write their own bridge slots from inside
        // `module_step`. Admitting an edge that the ISR module
        // can't consume is silently broken; surface it loudly.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("attested_isr");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        let producer_dir = dir.path().join("plain_producer");
        std::fs::create_dir_all(&producer_dir).expect("mkdir");
        std::fs::write(
            producer_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = false\n",
        )
        .expect("write manifest");

        // Even an untagged (`local`) edge into a `timer` module is
        // rejected — the bridge ABI gap is independent of edge_class.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "main", "exec": "tick"},
                    {"name": "audio_isr", "exec": "timer", "rate_hz": 1000},
                ]
            },
            "wiring": [
                {
                    "from": "plain_producer.out",
                    "to": "attested_isr.in",
                    // No edge_class tag = local; still rejected.
                }
            ]
        });
        let modules = vec![
            json!({"name": "plain_producer", "type": "plain_producer", "domain": "main"}),
            json!({
                "name": "attested_isr",
                "type": "attested_isr",
                "domain": "audio_isr",
            }),
        ];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = admit(&cfg, &modules, None, &extras)
            .expect_err("untagged edge into `timer` module must still be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("interrupt-mode endpoint")
                && msg.contains("module-facing API")
                && msg.contains("attested_isr"),
            "diagnostic must name the gap + the offending module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_dma_owned_edge_into_interrupt_module_too() {
        // The catch-all rejection above subsumes the previous
        // edge_class-specific check; pin the diagnostic still
        // surfaces clearly when the operator added an explicit
        // `dma_owned` tag.
        let dir = tempfile::tempdir().expect("tempdir");
        let isr_dir = dir.path().join("attested_isr");
        std::fs::create_dir_all(&isr_dir).expect("mkdir");
        std::fs::write(
            isr_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = true\n",
        )
        .expect("write manifest");
        let prod_dir = dir.path().join("plain_producer");
        std::fs::create_dir_all(&prod_dir).expect("mkdir");
        std::fs::write(
            prod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ninterrupt_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [
                {"name": "main", "exec": "tick"},
                {"name": "audio_isr", "exec": "timer", "rate_hz": 1000},
            ]},
            "wiring": [{
                "from": "plain_producer.out",
                "to": "attested_isr.in",
                "edge_class": "dma_owned",
            }]
        });
        let modules = vec![
            json!({"name": "plain_producer", "type": "plain_producer", "domain": "main"}),
            json!({"name": "attested_isr", "type": "attested_isr", "domain": "audio_isr"}),
        ];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        admit(&cfg, &modules, None, &extras)
            .expect_err("dma_owned edge into `timer` module rejected (subsumed by ISR-edge rule)");
    }

    #[test]
    fn admission_accepts_tick_domain_with_interrupt_safe_field_present() {
        // Cooperative modes (tick, poll) are unaffected by the
        // `timer`/`irq` admission gate — the `interrupt_safe` manifest flag is
        // simply ignored for non-interrupt-mode domains. Catches a
        // regression where the gate goes too broad.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("plain_mod");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\ninterrupt_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "main", "exec": "tick", "tick_us": 250}]}
        });
        let modules = vec![json!({"name": "plain_mod", "type": "plain_mod", "domain": "main"})];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        admit(&cfg, &modules, None, &extras)
            .expect("cooperative mode with interrupt_safe=false on its modules is fine");
    }

    #[test]
    fn declared_deadlines_within_budget_pass() {
        // Two modules in domain 0 with declared deadlines summing to
        // 1500 us, tick_us 1000 → declared sum < 4×tick = 4000 → ok.
        let cfg = json!({"execution": {"domains": [{"name": "d0", "tick_us": 1000}]}});
        let modules = vec![
            json!({"name": "a", "type": "x", "step_deadline_us": 800}),
            json!({"name": "b", "type": "x", "step_deadline_us": 700}),
        ];
        validate_scheduler_budgets(&cfg, &modules, 1000, &["d0".to_string()], &[1000]).unwrap();
    }
}

#[cfg(test)]
mod continuity_tests {
    //! Tests for the `continuity` block validator: continuity classes as
    //! a validated graph property.

    use super::*;
    use crate::manifest::{ClaimSelector, ResourceClaim};

    /// The node's own modules on a Linux host, whose platform answers `fs`.
    fn linux() -> ProviderReach<'static> {
        ProviderReach {
            runtime: Some("linux"),
            caller: ProviderCaller::Node,
            project: fluxor_root(),
        }
    }

    fn man(caps: &[&str]) -> Manifest {
        Manifest {
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            ..Manifest::default()
        }
    }

    fn prov(provides: &[&str]) -> Manifest {
        Manifest {
            provides: provides.iter().map(|s| s.to_string()).collect(),
            ..Manifest::default()
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Well-formed edge_anchored graph: anchor + one worker.
    fn edge_graph() -> (Vec<String>, HashMap<String, Manifest>) {
        let mut manifests = HashMap::new();
        manifests.insert("anc".to_string(), man(&["transport.anchor.stream"]));
        manifests.insert(
            "wkr".to_string(),
            man(&["session.worker", "session.handoff"]),
        );
        (names(&["anc", "wkr"]), manifests)
    }

    #[test]
    fn continuity_absent_block_is_fine() {
        let (n, m) = edge_graph();
        validate_continuity(&json!({}), &n, &m).unwrap();
    }

    #[test]
    fn continuity_rejects_unknown_class_and_duplicate_id() {
        let (n, m) = edge_graph();
        let cfg = json!({"continuity": [{"id": "x", "class": "bogus"}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("invalid"), "got: {e:?}");

        let cfg = json!({"continuity": [
            {"id": "x", "class": "drain_only"},
            {"id": "x", "class": "drain_only"}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("duplicate"), "got: {e:?}");
    }

    /// `fault_policy: restart` resumes the module's existing state after
    /// releasing its handles and flushing its channels. A module that has
    /// not attested it can survive that must not be able to select it.
    #[test]
    fn fault_policy_restart_requires_the_manifest_attestation() {
        let cfg = json!({"modules": [{"name": "a", "fault_policy": "restart"}]});

        let mut m = HashMap::new();
        m.insert("a".to_string(), man(&[]));
        let e = validate_fault_policy(&cfg, &names(&["a"]), &m).unwrap_err();
        let msg = format!("{e:?}");
        assert!(msg.contains("resume_after_fault"), "got: {msg}");
        assert!(
            msg.contains("does NOT re-instantiate"),
            "the diagnostic must say what the policy actually does; got: {msg}"
        );

        // With the attestation the same graph passes.
        let mut m = HashMap::new();
        m.insert(
            "a".to_string(),
            Manifest {
                resume_after_fault: true,
                ..Manifest::default()
            },
        );
        validate_fault_policy(&cfg, &names(&["a"]), &m).unwrap();
    }

    /// A provider's layer and handlers are among what a restart releases and
    /// nothing registers them again, so no attestation lets it take `restart`.
    #[test]
    fn fault_policy_restart_is_refused_to_a_provider_even_when_attested() {
        let cfg = json!({"modules": [{"name": "a", "fault_policy": "restart"}]});
        let mut m = HashMap::new();
        m.insert(
            "a".to_string(),
            Manifest {
                resume_after_fault: true,
                provides: vec!["storage.block".to_string()],
                ..Manifest::default()
            },
        );
        let e = validate_fault_policy(&cfg, &names(&["a"]), &m).unwrap_err();
        let msg = format!("{e:?}");
        assert!(
            msg.contains("storage.block"),
            "names what it provides: {msg}"
        );
        assert!(
            msg.contains("skip") && msg.contains("to terminate it"),
            "offers the alternative: {msg}"
        );

        // The other policies stay open to it.
        for policy in ["skip", "tolerate"] {
            let cfg = json!({"modules": [{"name": "a", "fault_policy": policy}]});
            validate_fault_policy(&cfg, &names(&["a"]), &m).unwrap();
        }
    }

    /// `fault_policy: restart` is refused to an instance that declares store
    /// subscriptions or their events — by its own `demand:`, or by its
    /// type's rule counted from its params — and admitted to one that
    /// declares none.
    #[test]
    fn restart_is_refused_to_an_instance_that_subscribes() {
        use super::dynamic_capacity_tests::tlv_of;
        let probe = Manifest {
            resume_after_fault: true,
            demand_from_params: vec![crate::manifest::DemandFromParams {
                pool: "store_subs".into(),
                tags: vec![5],
                split: ",".into(),
            }],
            ..Manifest::default()
        };
        let integers = [(5u8, 1u32)];
        let demand_of = |module: &Value, tlv: &[u8]| InstanceDemand {
            name: "module 'probe'".into(),
            figures: instance_demand(module, "probe", Some(&probe), tlv, &integers).unwrap(),
            heap_per_demand: None,
        };
        let restart = json!({"name": "probe", "fault_policy": "restart"});
        // Unset, the param's default (1) subscribes.
        let d = demand_of(&restart, &tlv_of(&[]));
        let msg = refuse_restart_of_subscribers(&json!([restart.clone()]), &[d])
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("`store_subs`") && msg.contains("`fault_policy: \"skip\"`"),
            "{msg}"
        );
        // `subscribe: 0` declares none: restart is admitted.
        let d = demand_of(&restart, &tlv_of(&[(5, &[0])]));
        refuse_restart_of_subscribers(&json!([restart.clone()]), &[d]).unwrap();
        // The graph's own figure counts the same way.
        let declared = json!({"name": "probe", "fault_policy": "restart", "demand": {"events": 1}});
        let d = demand_of(&declared, &tlv_of(&[(5, &[0])]));
        assert!(refuse_restart_of_subscribers(&json!([declared]), &[d]).is_err());
        // Another policy is untouched.
        let skip = json!({"name": "probe", "fault_policy": "skip"});
        let d = demand_of(&skip, &tlv_of(&[]));
        refuse_restart_of_subscribers(&json!([skip]), &[d]).unwrap();
    }

    /// An integer param counts by its value, its schema default when unset;
    /// a string param by its entries.
    #[test]
    fn demand_from_params_counts_an_integer_by_value() {
        use super::dynamic_capacity_tests::tlv_of;
        let rule = crate::manifest::DemandFromParams {
            pool: "store_subs".into(),
            tags: vec![5, 6, 2],
            split: ",".into(),
        };
        let integers = [(5u8, 1u32), (6, 0)];
        assert_eq!(rule.declared_count(&tlv_of(&[]), &integers), 1, "defaults");
        let tlv = tlv_of(&[(5, &[3]), (6, &[0x10, 0x01]), (2, b"/a/,/b/")]);
        assert_eq!(rule.declared_count(&tlv, &integers), 3 + 0x110 + 2);
    }

    fn claim(class: u8, optional: bool, active_when: &[&str]) -> ResourceClaim {
        ResourceClaim {
            device_class: class,
            access_mode: 0,
            instance: 0xFF,
            selector: ClaimSelector::Default,
            active_when_params: names(active_when),
            optional,
            variants: Vec::new(),
            when: Vec::new(),
            claim: ResourceClaim::claim_byte(optional, !active_when.is_empty()),
        }
    }

    /// The schema a test instance is packed against: `tls`'s and `dns`'s
    /// params at their own tags, any other module's claim params as `str`
    /// (a number in the graph as `u32`), tagged in name order.
    fn test_schema(ty: &str, m: &Manifest, entry: &Value) -> crate::schema::ParamSchema {
        use crate::schema::{ParamSchema, ParamType, SchemaParam};
        let p = |tag: u8, ptype: ParamType, name: &str| SchemaParam {
            tag,
            ptype,
            name: name.to_string(),
            default: 0,
            min: 0,
            max: fluxor_abi::wire::param_schema::type_ceiling(ptype as u8),
            enums: HashMap::new(),
        };
        let params = match ty {
            "tls" => vec![
                p(1, ParamType::U8, "mode"),
                p(6, ParamType::Str, "cert_file"),
                p(7, ParamType::Str, "key_file"),
                p(16, ParamType::Str, "trust"),
                p(19, ParamType::Str, "identity_label"),
            ],
            "dns" => vec![
                p(9, ParamType::Str, "update_zone"),
                p(11, ParamType::StrChunked, "update_allow"),
            ],
            _ => {
                let mut names: Vec<&str> = m
                    .resources
                    .iter()
                    .flat_map(|r| r.active_when_params.iter().map(String::as_str))
                    .collect();
                names.sort_unstable();
                names.dedup();
                names
                    .into_iter()
                    .enumerate()
                    .map(|(i, n)| {
                        let numeric = entry.get(n).is_some_and(Value::is_number);
                        p(
                            i as u8 + 1,
                            if numeric { ParamType::U32 } else { ParamType::Str },
                            n,
                        )
                    })
                    .collect()
            }
        };
        ParamSchema::from_params(params)
    }

    /// Each instance's claims as the composer decides them: its params
    /// packed against [`test_schema`], a credential given `${file:..}`
    /// embedded under its extended tag as the builder embeds it.
    fn test_claims(graph: &Value, m: &HashMap<String, Manifest>) -> HashMap<String, Vec<InstanceClaim>> {
        let mut out = HashMap::new();
        for entry in graph["modules"].as_array().into_iter().flatten() {
            let name = entry["name"].as_str().unwrap();
            let ty = entry.get("type").and_then(Value::as_str).unwrap_or(name);
            let Some(man) = m.get(name) else {
                continue;
            };
            let schema = test_schema(ty, man, entry);
            let mut basic = entry.clone();
            let mut ext: Vec<u8> = Vec::new();
            for key in ["cert_file", "key_file", "trust"] {
                let embedded = entry
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(crate::trust_anchors::file_source)
                    .is_some();
                if embedded {
                    basic.as_object_mut().unwrap().remove(key);
                    let tag = crate::trust_anchors::embedded_tags(key)[0];
                    ext.extend_from_slice(&[tag, 0, 0, 1, 0x30]);
                }
            }
            let mut params = vec![0u8; 4096];
            let n = crate::schema::build_params_from_schema(&basic, &schema, &mut params, 0, None, ty)
                .expect("pack");
            params.truncate(n);
            params.extend_from_slice(&ext);
            let claims = instance_claims(man, &schema, crate::hash::fnv1a_hash(ty.as_bytes()), &params)
                .expect("claims");
            out.insert(name.to_string(), claims);
        }
        out
    }

    fn refusals(target: &str, graph: &Value, m: &HashMap<String, Manifest>) -> Vec<String> {
        let mut module_names: Vec<String> = m.keys().cloned().collect();
        module_names.sort();
        let found = required_contract_refusals(
            graph,
            &module_names,
            m,
            &test_claims(graph, m),
            ProviderReach {
                runtime: Some(target),
                caller: ProviderCaller::Node,
                project: fluxor_root(),
            },
        );
        found.into_iter().map(|r| r.message).collect()
    }

    /// The key vault is a module provider, not the kernel's: an exercised
    /// `key_vault` claim with no `key_vault` in the graph is refused on every
    /// target, one the instance's params never exercise is not, and the
    /// vault composed beside it answers it.
    #[test]
    fn a_key_vault_claim_needs_a_vault_in_the_graph() {
        let caller = Manifest {
            resources: vec![claim(
                fluxor_abi::registry::key_vault::ID as u8,
                false,
                &["key_file"],
            )],
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("tls".to_string(), caller);
        let exercised = json!({"modules": [{"name": "tls", "key_file": "/k.der"}]});
        for target in ["linux", "bcm2712", "rp2350", "rp2040"] {
            let found = refusals(target, &exercised, &m);
            assert!(
                found.len() == 1 && found[0].contains("`tls` requires `key_vault`"),
                "{target}: {found:?}"
            );
        }
        let idle = json!({"modules": [{"name": "tls"}]});
        assert!(refusals("linux", &idle, &m).is_empty());
        m.insert(
            "key_vault".to_string(),
            Manifest {
                provides: vec!["key_vault".to_string()],
                ..Manifest::default()
            },
        );
        let composed = json!({"modules": [
            {"name": "tls", "key_file": "/k.der"},
            {"name": "key_vault"},
        ]});
        assert!(refusals("linux", &composed, &m).is_empty());
    }

    /// The real `tls` manifest and `key_vault`'s `provides`, keyed as a graph
    /// names them.
    fn tls_and_vault(target: &str, vault: bool) -> HashMap<String, Manifest> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut m = HashMap::new();
        m.insert(
            "tls".to_string(),
            Manifest::from_toml_for_target(
                &root.join("modules/foundation/tls/manifest.toml"),
                Some(target),
            )
            .expect("tls manifest"),
        );
        if vault {
            m.insert(
                "key_vault".to_string(),
                Manifest {
                    provides: vec!["key_vault".to_string()],
                    ..Manifest::default()
                },
            );
        }
        m
    }

    /// An identity the builder embeds (`${file:}`) is not read through `fs`,
    /// but its key is still the vault's to take: on every target a `tls`
    /// naming one is refused without `key_vault`, and is not held to `fs`.
    #[test]
    fn an_embedded_identity_needs_a_vault_on_every_target() {
        let embedded = json!({"modules": [{
            "name": "tls",
            "mode": 1,
            "cert_file": "${file:server.der}",
            "key_file": "${file:server.key.der}",
        }]});
        for target in ["linux", "bcm2712", "rp2350"] {
            let found = refusals(target, &embedded, &tls_and_vault(target, false));
            assert!(
                found.iter().any(|f| f.contains("`tls` requires `key_vault`")),
                "{target}: {found:?}"
            );
            assert!(
                !found.iter().any(|f| f.contains("requires `fs`")),
                "{target}: an embedded credential is not read through fs: {found:?}"
            );
            let with_vault = json!({"modules": [
                embedded["modules"][0].clone(),
                {"name": "key_vault"},
            ]});
            assert!(
                refusals(target, &with_vault, &tls_and_vault(target, true)).is_empty(),
                "{target}"
            );
        }
        // A key read at runtime through `fs` exercises both claims; rp2350
        // serves no `fs` to the node.
        let by_path = json!({"modules": [
            {"name": "tls", "mode": 1, "cert_file": "/c.der", "key_file": "/k.der"},
            {"name": "key_vault"},
        ]});
        let found = refusals("rp2350", &by_path, &tls_and_vault("rp2350", true));
        assert!(
            found.len() == 1 && found[0].contains("`tls` requires `fs`"),
            "{found:?}"
        );
    }

    /// `fluxor exec` gives a client `tls` of an applet that names no identity
    /// the operator's, whose key the vault takes: in an applet's build such an
    /// instance needs `key_vault`, and the refusal says why. A server, one
    /// that names its own identity's source, and any graph built outside an
    /// applet are not held to it.
    #[test]
    fn an_applets_client_tls_needs_the_vault_exec_gives_its_identity_to() {
        let m = tls_and_vault("linux", false);
        let client = json!({"modules": [{"name": "tls"}]});
        let explicit_client = json!({"modules": [{"name": "tls", "mode": 0}]});
        let server = json!({"modules": [{"name": "tls", "mode": 1}]});
        let typed = json!({"modules": [{"name": "dial", "type": "tls"}]});
        let mut typed_m = HashMap::new();
        typed_m.insert("dial".to_string(), m["tls"].clone());

        assert!(refusals("linux", &client, &m).is_empty(), "not an applet");
        crate::packaging::with_applet("tool", || {
            for g in [&client, &explicit_client] {
                let found = refusals("linux", g, &m);
                assert!(
                    found.len() == 1
                        && found[0].contains("`tls` requires `key_vault`")
                        && found[0].contains("client `tls` of applet 'tool'")
                        && found[0].contains("fluxor exec"),
                    "{found:?}"
                );
            }
            let found = refusals("linux", &typed, &typed_m);
            assert!(
                found.len() == 1 && found[0].contains("`dial` requires `key_vault`"),
                "a `tls` named otherwise: {found:?}"
            );
            assert!(refusals("linux", &server, &m).is_empty(), "a server");
            // An identity the graph names is its own: the usual refusal.
            let labelled = json!({"modules": [{"name": "tls", "identity_label": "me"}]});
            let found = refusals("linux", &labelled, &m);
            assert!(
                found.len() == 1
                    && found[0].contains("`tls` requires `key_vault`")
                    && !found[0].contains("fluxor exec"),
                "{found:?}"
            );
            let composed = json!({"modules": [{"name": "tls"}, {"name": "key_vault"}]});
            assert!(refusals("linux", &composed, &tls_and_vault("linux", true)).is_empty());
        });
    }

    /// A param set to a list (dns's `update_allow: [..]`) or another
    /// non-string value exercises a claim gated on it, as a string does; an
    /// empty list does not.
    #[test]
    fn a_list_valued_param_exercises_its_claim() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let dns = Manifest::from_toml_for_target(
            &root.join("modules/foundation/dns/manifest.toml"),
            Some("linux"),
        )
        .expect("dns manifest");
        let mut m = HashMap::new();
        m.insert("dns".to_string(), dns);
        let listed = json!({"modules": [{
            "name": "dns",
            "update_zone": "example.org",
            "update_allow": ["k1=host.example.org,A"],
        }]});
        let found = refusals("linux", &listed, &m);
        assert!(
            found.iter().any(|f| f.contains("`dns` requires `key_vault`")),
            "{found:?}"
        );
        let in_params = json!({"modules": [{
            "name": "dns",
            "params": {"update_allow": ["k1=host.example.org,A"]},
        }]});
        assert!(refusals("linux", &in_params, &m)
            .iter()
            .any(|f| f.contains("`dns` requires `key_vault`")));
        let empty = json!({"modules": [{"name": "dns", "update_allow": []}]});
        assert!(!refusals("linux", &empty, &m)
            .iter()
            .any(|f| f.contains("key_vault")));
        let numeric = Manifest {
            resources: vec![claim(
                fluxor_abi::registry::key_vault::ID as u8,
                false,
                &["slots"],
            )],
            ..Manifest::default()
        };
        let mut n = HashMap::new();
        n.insert("m".to_string(), numeric);
        let set = json!({"modules": [{"name": "m", "slots": 4}]});
        assert!(refusals("linux", &set, &n)
            .iter()
            .any(|f| f.contains("`m` requires `key_vault`")));
    }

    /// The modules are listed in construction order: each provider before
    /// the modules whose exercised claims it answers, the graph's own order
    /// otherwise; a workload-scoped layer answers no node module; a provider
    /// and a claimant that each need the other first are refused, naming the
    /// cycle.
    #[test]
    fn providers_are_constructed_before_the_modules_that_call_them() {
        let vault = fluxor_abi::registry::key_vault::ID as u8;
        let fs = fluxor_abi::registry::fs::ID as u8;
        let provides = |c: &str| Manifest {
            provides: vec![c.to_string()],
            ..Manifest::default()
        };
        let calls = |class: u8| Manifest {
            resources: vec![claim(class, false, &[])],
            ..Manifest::default()
        };
        let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let graph = |n: &[&str]| {
            json!({"modules": n.iter().map(|m| json!({"name": m})).collect::<Vec<_>>()})
        };
        let mut m = HashMap::new();
        m.insert("minter".to_string(), calls(vault));
        m.insert("plain".to_string(), Manifest::default());
        m.insert("key_vault".to_string(), provides("key_vault"));
        let order = |n: &[&str], m: &HashMap<String, Manifest>| {
            construction_order(&graph(n), &names(n), m)
        };
        // The vault, listed last, is pulled forward to just before the
        // minter; the rest keep their places.
        assert_eq!(
            order(&["minter", "plain", "key_vault"], &m).unwrap(),
            vec![2, 0, 1]
        );
        // Only the provider moves: modules a graph orders to break a cycle
        // between them (`accept_cycles`, e.g. a tls client and the volume
        // it carries) keep the order written.
        assert_eq!(
            order(&["minter", "volume", "plain", "key_vault"], &m).unwrap(),
            vec![3, 0, 1, 2]
        );
        assert_eq!(
            order(&["key_vault", "plain", "minter"], &m).unwrap(),
            vec![0, 1, 2],
            "already in order"
        );
        // A claim the instance's params never exercise orders nothing.
        m.insert(
            "minter".to_string(),
            Manifest {
                resources: vec![claim(vault, false, &["key_file"])],
                ..Manifest::default()
            },
        );
        assert_eq!(
            order(&["minter", "plain", "key_vault"], &m).unwrap(),
            vec![0, 1, 2]
        );
        // A workload-scoped layer serves no node module.
        let mut scoped = provides("fs");
        scoped.workload_scope = true;
        m.insert("owner_fs".to_string(), scoped);
        m.insert("reader".to_string(), calls(fs));
        assert_eq!(
            order(&["reader", "owner_fs"], &m).unwrap(),
            vec![0, 1]
        );
        // Each calls what the other provides: no order serves both.
        let mut a = provides("key_vault");
        a.resources = vec![claim(fs, false, &[])];
        let mut b = provides("fs");
        b.resources = vec![claim(vault, false, &[])];
        m.insert("a".to_string(), a);
        m.insert("b".to_string(), b);
        let e = order(&["plain", "a", "b"], &m).unwrap_err().to_string();
        assert!(e.contains("no construction order serves this graph"), "{e}");
        assert!(
            e.contains("`a` calls `fs` on `b` calls `key_vault` on `a`"),
            "{e}"
        );
    }

    /// A graph not built as an applet's that names `${applet:data_dir}` is
    /// refused when it is composed, naming the placeholder and why.
    #[test]
    fn a_graph_built_outside_an_applet_cannot_name_its_data_dir() {
        let g = json!({"modules": [{"name": "store", "dir": "${applet:data_dir}/store"}]});
        let e = crate::packaging::check_applet_placeholders(&g).unwrap_err();
        assert!(e.contains("${applet:data_dir}/store"), "{e}");
        assert!(e.contains("not built as one"), "{e}");
        crate::packaging::with_applet("tool", || {
            assert!(crate::packaging::check_applet_placeholders(&g).is_ok());
        });
    }

    /// A claim nothing answers is refused, naming module, contract and target;
    /// the kernel's own contracts, the target's `[providers]` and a module in
    /// the graph each answer it.
    #[test]
    fn a_required_contract_must_be_answered_by_kernel_platform_or_module() {
        let fs_user = Manifest {
            resources: vec![
                claim(fluxor_abi::registry::fs::ID as u8, false, &[]),
                claim(fluxor_abi::registry::channel::ID as u8, false, &[]),
            ],
            ..Manifest::default()
        };
        let graph = json!({"modules": [{"name": "user"}]});
        let alone: HashMap<String, Manifest> = [("user".to_string(), fs_user.clone())].into();
        // uefi answers no `fs`; `channel` is the kernel's.
        let r = refusals("uefi", &graph, &alone);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(
            r[0].contains("`user` requires `fs`") && r[0].contains("uefi"),
            "{r:?}"
        );
        // linux's platform answers `fs`.
        assert!(refusals("linux", &graph, &alone).is_empty());
        // A module in the graph that provides `file.data` answers `fs`.
        let with_fat: HashMap<String, Manifest> = [
            ("user".to_string(), fs_user),
            ("fat32".to_string(), prov(&["file.data"])),
        ]
        .into();
        let graph = json!({"modules": [{"name": "user"}, {"name": "fat32"}]});
        assert!(refusals("uefi", &graph, &with_fat).is_empty());
    }

    /// An optional claim and an unexercised one are never refused, and a
    /// value the builder embeds (`${file:…}`) exercises nothing at run time.
    #[test]
    fn optional_unexercised_and_embedded_claims_are_not_refused() {
        let m: HashMap<String, Manifest> = [(
            "tls".to_string(),
            Manifest {
                resources: vec![
                    claim(fluxor_abi::registry::trust::ID as u8, true, &[]),
                    claim(fluxor_abi::registry::fs::ID as u8, false, &["cert_file"]),
                ],
                ..Manifest::default()
            },
        )]
        .into();
        let unset = json!({"modules": [{"name": "tls"}]});
        assert!(refusals("bcm2712", &unset, &m).is_empty());
        let embedded = json!({"modules": [{"name": "tls", "cert_file": "${file:pki/c.der}"}]});
        assert!(refusals("bcm2712", &embedded, &m).is_empty());
        let path = json!({"modules": [{"name": "tls", "cert_file": "/etc/c.der"}]});
        let r = refusals("bcm2712", &path, &m);
        assert_eq!(r.len(), 1, "a runtime path reads through `fs`: {r:?}");
    }

    /// Any refusal fails the build, and the error names every one.
    #[test]
    fn every_refusal_fails_the_build_and_is_named() {
        enforce_required_contracts(Vec::new(), "").unwrap();
        let refusal = |module: &str, contract: &'static str| ProviderRefusal {
            module: module.to_string(),
            contract,
            message: format!("`{module}` requires `{contract}`"),
        };
        let e = enforce_required_contracts(
            vec![refusal("a", "fs"), refusal("b", "spi")],
            "workload 0: ",
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("workload 0: `a` requires `fs`")
                && e.contains("workload 0: `b` requires `spi`"),
            "{e}"
        );
    }

    /// A claim keyed to `route_<n>_*` params is read as the packer expands a
    /// `routes:` list: only a route that serves files exercises it.
    #[test]
    fn a_routes_list_exercises_a_claim_only_through_its_file_routes() {
        let m: HashMap<String, Manifest> = [(
            "http".to_string(),
            Manifest {
                resources: vec![claim(
                    fluxor_abi::registry::fs::ID as u8,
                    false,
                    &["fs_root", "route_0_fs_path"],
                )],
                ..Manifest::default()
            },
        )]
        .into();
        let inline = json!({"modules": [{"name": "http",
            "routes": [{"path": "/", "body": "<h1>hi</h1>"}]}]});
        assert!(refusals("uefi", &inline, &m).is_empty());
        let files = json!({"modules": [{"name": "http",
            "routes": [{"path": "/", "fs_path": "/web/index.html"}]}]});
        assert_eq!(refusals("uefi", &files, &m).len(), 1);
    }

    /// A claim counts only under the variant it names and when its `when`
    /// conditions hold for the instance, schema defaults included.
    #[test]
    fn a_claim_counts_only_under_its_variant_and_when() {
        // The instance's effective `update_durability` is `durable` only
        // when set so: its default is not.
        let durable = |_: &str, entry: &Value, param: &str, values: &[String]| {
            assert_eq!(param, "update_durability");
            let v = entry
                .get(param)
                .and_then(Value::as_str)
                .unwrap_or("default");
            Ok(Some(Some(values.iter().any(|w| w == v))))
        };
        let mut disk_only = claim(fluxor_abi::registry::fs::ID as u8, false, &[]);
        disk_only.variants = names(&["disk"]);
        let mut durable_only = claim(fluxor_abi::registry::fs::ID as u8, false, &[]);
        durable_only.when = vec![("update_durability".to_string(), names(&["durable"]))];
        let man = |variant: &str| Manifest {
            resources: vec![disk_only.clone(), durable_only.clone()],
            selected_variant: Some(variant.to_string()),
            ..Manifest::default()
        };
        let kept = |variant: &str, entry: Value| {
            let m: HashMap<String, Manifest> = [("d".to_string(), man(variant))].into();
            crate::config::exercised_claims(&[entry], &m, durable).unwrap()["d"]
                .resources
                .len()
        };
        assert_eq!(
            kept(
                "disk",
                json!({"name": "d", "type": "dns", "update_durability": "durable"})
            ),
            2
        );
        assert_eq!(
            kept(
                "volatile",
                json!({"name": "d", "type": "dns", "update_durability": "durable"})
            ),
            1
        );
        assert_eq!(
            kept(
                "disk",
                json!({"name": "d", "type": "dns", "update_durability": "volatile"})
            ),
            1
        );
        // Unset: the schema default (not `durable`) stands in.
        assert_eq!(kept("volatile", json!({"name": "d", "type": "dns"})), 0);
    }

    /// `variants` must name declared variants, and `when` parses as in
    /// `[[requires_when]]`.
    #[test]
    fn claim_variants_and_when_parse() {
        let head = "version = \"0.1.0\"\n[[variant]]\nname = \"disk\"\nfeatures = []\ndefault = true\n[[variant]]\nname = \"volatile\"\nfeatures = [\"volatile\"]\n";
        let ok = format!(
            "{head}[[resources]]\nrequires_contract = \"fs\"\naccess = \"write\"\nvariants = [\"disk\"]\nwhen = {{ persist = \"fs\" }}\n"
        );
        let m = Manifest::from_toml_str_for_target(&ok, None).unwrap();
        assert_eq!(m.resources[0].variants, names(&["disk"]));
        assert_eq!(
            m.resources[0].when,
            vec![("persist".to_string(), names(&["fs"]))]
        );
        assert_eq!(m.selected_variant.as_deref(), Some("disk"));
        let bad = format!(
            "{head}[[resources]]\nrequires_contract = \"fs\"\naccess = \"write\"\nvariants = [\"dsk\"]\n"
        );
        let e = Manifest::from_toml_str_for_target(&bad, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("`dsk`"), "{e}");
    }

    /// bcm2712's platform answers neither `fs` nor `storage.*` to anyone: the
    /// node composes its providers, and a workload's `fs` is the node's workload
    /// layer, checked when the workload is admitted rather than in its graph.
    #[test]
    fn the_target_table_separates_node_and_workload_callers() {
        let m: HashMap<String, Manifest> = [(
            "w".to_string(),
            Manifest {
                resources: vec![
                    claim(fluxor_abi::registry::fs::ID as u8, false, &[]),
                    claim(fluxor_abi::registry::storage_object::ID as u8, false, &[]),
                ],
                ..Manifest::default()
            },
        )]
        .into();
        let graph = json!({"modules": [{"name": "w"}]});
        let node = refusals("bcm2712", &graph, &m);
        assert!(
            node.len() == 2
                && node.iter().any(|r| r.contains("`fs`"))
                && node.iter().any(|r| r.contains("`storage.object`")),
            "{node:?}"
        );
        let workload = required_contract_refusals(
            &graph,
            &names(&["w"]),
            &m,
            &test_claims(&graph, &m),
            ProviderReach {
                runtime: Some("bcm2712"),
                caller: ProviderCaller::Workload,
                project: fluxor_root(),
            },
        );
        assert!(
            workload.len() == 1 && workload[0].contract == "storage.object",
            "{workload:?}"
        );
    }

    /// A module provider and every module it serves share a domain; on a node
    /// that admits live-added workloads the provider sits in the primary one.
    #[test]
    fn a_provider_and_its_callers_share_a_domain() {
        use crate::manifest::ResourceClaim;
        let caller = Manifest {
            resources: vec![ResourceClaim {
                device_class: fluxor_abi::registry::storage_namespace::ID as u8,
                access_mode: 0,
                instance: 0xFF,
                selector: crate::manifest::ClaimSelector::Default,
                active_when_params: Vec::new(),
                optional: false,
                variants: Vec::new(),
                when: Vec::new(),
                claim: fluxor_abi::wire::fmod::claim::REQUIRED,
            }],
            ..Manifest::default()
        };
        let store = prov(&["storage.namespace"]);
        let m: HashMap<String, Manifest> =
            [("store".to_string(), store), ("watch".to_string(), caller)].into();
        let domains = json!({"domains": [{"name": "main"}, {"name": "io"}]});
        let graph = |store_dom: Option<&str>, watch_dom: Option<&str>, capacity: Value| {
            let entry = |n: &str, d: Option<&str>| match d {
                Some(d) => json!({"name": n, "domain": d}),
                None => json!({"name": n}),
            };
            json!({
                "execution": domains,
                "capacity": capacity,
                "modules": [entry("store", store_dom), entry("watch", watch_dom)],
            })
        };
        let check = |cfg: &Value, target: &str| {
            let list = cfg["modules"].as_array().unwrap().clone();
            validate_provider_domains(cfg, &list, &m, target)
        };
        // Together in the primary domain, or together elsewhere on a node that
        // takes no workloads: fine.
        check(&graph(None, Some("main"), json!({})), "linux").unwrap();
        check(
            &graph(Some("io"), Some("io"), json!({"owners": 0})),
            "linux",
        )
        .unwrap();
        // Split: refused, naming both modules and domains.
        let e = check(&graph(None, Some("io"), json!({})), "linux")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("'watch' (domain 'io')")
                && e.contains("'store'")
                && e.contains("storage.namespace"),
            "{e}"
        );
        // Outside the primary domain where workloads may be live-added.
        let e = check(&graph(Some("io"), Some("io"), json!({})), "linux")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("primary domain") && e.contains("live-added"),
            "{e}"
        );
        // A node that keeps no owner reserve (RP's default) admits no
        // live-added workload.
        check(&graph(Some("io"), Some("io"), json!({})), "rp2350").unwrap();
    }

    /// `ip` serves `net.policy` to `pkt_filter`: a provider call runs `ip`'s
    /// code on the caller's core, so a graph splitting them across domains is
    /// refused at build, and `ip`'s tables are only ever touched from its own.
    #[test]
    fn ip_and_the_enforcer_it_serves_share_a_domain() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let load = |n: &str| {
            Manifest::from_toml_for_target(
                &root.join(format!("modules/foundation/{n}/manifest.toml")),
                Some("bcm2712"),
            )
            .expect("manifest")
        };
        let m: HashMap<String, Manifest> = [
            ("ip".to_string(), load("ip")),
            ("pkt_filter".to_string(), load("pkt_filter")),
        ]
        .into();
        let cfg = |filter_dom: &str| {
            json!({
                "execution": {"domains": [{"name": "main"}, {"name": "nic"}]},
                "capacity": {"owners": 0},
                "modules": [
                    {"name": "ip"},
                    {"name": "pkt_filter", "domain": filter_dom, "table": "t"},
                ],
            })
        };
        let check = |c: &Value| {
            let list = c["modules"].as_array().unwrap().clone();
            validate_provider_domains(c, &list, &m, "bcm2712")
        };
        check(&cfg("main")).unwrap();
        let e = check(&cfg("nic")).unwrap_err().to_string();
        assert!(e.contains("'pkt_filter'") && e.contains("net_policy"), "{e}");
    }

    /// Every other policy, and a graph with no policy at all, is
    /// unaffected — the gate is specific to the resuming one.
    #[test]
    fn fault_policy_gate_ignores_the_other_policies() {
        let mut m = HashMap::new();
        m.insert("a".to_string(), man(&[]));
        let n = names(&["a"]);
        validate_fault_policy(&json!({}), &n, &m).unwrap();
        for policy in ["skip", "tolerate"] {
            let cfg = json!({"modules": [{"name": "a", "fault_policy": policy}]});
            validate_fault_policy(&cfg, &n, &m).unwrap();
        }
        // A module with no manifest in the resolved set is not gated,
        // matching every other validator in this file.
        let cfg = json!({"modules": [{"name": "a", "fault_policy": "restart"}]});
        validate_fault_policy(&cfg, &n, &HashMap::new()).unwrap();
    }

    /// A workload node's network stack has one `addr_ctl` writer, the
    /// kernel: a coordinator wired into it is refused there, and allowed in a
    /// graph that creates no workloads.
    /// On a node with a workload creator the creator is the one writer of
    /// `addr_ctl`: a coordinator wired into it is refused, and a creator that
    /// writes addresses must reach every `addr_ctl` the graph serves, since
    /// the kernel installs none. A creator whose workloads take no address,
    /// and a node with no creator, wire what they like.
    #[test]
    fn the_workload_creator_is_the_one_addr_ctl_writer() {
        let net = Manifest {
            ports: vec![named_port("addr_ctl", 0, "NetProto")],
            ..Manifest::default()
        };
        let writes_addresses = Manifest {
            ports: vec![named_port("addr_ctl_out", 1, "NetProto")],
            grants: [0, 1u64 << fluxor_abi::registry::grant::WORKLOAD_CREATE],
            ..Manifest::default()
        };
        let creates_only = Manifest {
            grants: [0, 1u64 << fluxor_abi::registry::grant::WORKLOAD_CREATE],
            ..Manifest::default()
        };
        let fence = Manifest {
            ports: vec![named_port("addr_ctl_out", 1, "NetProto")],
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("net".to_string(), net);
        m.insert("fence".to_string(), fence);
        m.insert("effect".to_string(), writes_addresses);
        m.insert("driver".to_string(), creates_only);
        let fence_wired = json!({"wiring": [{"from": "fence.addr_ctl_out", "to": "net.addr_ctl"}]});
        let effect_wired =
            json!({"wiring": [{"from": "effect.addr_ctl_out", "to": "net.addr_ctl"}]});
        let nothing = json!({"wiring": []});

        // No creator: a coordinator writes, or nobody does.
        validate_net_identity_writers(&fence_wired, &names(&["net", "fence"]), &m)
            .expect("no creator: the coordinator is the writer");
        validate_net_identity_writers(&nothing, &names(&["net"]), &m)
            .expect("no creator, no writer");

        // A creator: it is the one writer.
        validate_net_identity_writers(&effect_wired, &names(&["net", "effect"]), &m)
            .expect("the creator writes addr_ctl");
        let e = validate_net_identity_writers(&fence_wired, &names(&["net", "fence", "effect"]), &m)
            .unwrap_err();
        assert!(e.to_string().contains("one writer"), "{e}");
        let both = json!({"wiring": [
            {"from": "effect.addr_ctl_out", "to": "net.addr_ctl"},
            {"from": "fence.addr_ctl_out", "to": "net.addr_ctl"}
        ]});
        assert!(
            validate_net_identity_writers(&both, &names(&["net", "fence", "effect"]), &m).is_err(),
            "a second writer beside the creator"
        );

        // The creator's edge is required: the kernel installs nothing.
        let e = validate_net_identity_writers(&nothing, &names(&["net", "effect"]), &m)
            .unwrap_err();
        assert!(e.to_string().contains("effect.addr_ctl_out"), "{e}");

        // A creator whose workloads take no address writes nothing there.
        validate_net_identity_writers(&nothing, &names(&["net", "driver"]), &m)
            .expect("a creator without an address port");
        assert!(
            validate_net_identity_writers(&fence_wired, &names(&["net", "fence", "driver"]), &m)
                .is_err(),
            "and still admits no other writer"
        );
    }

    /// The composer and the kernel decide a claim with one evaluator: over
    /// a corpus of manifests and instance params, what `instance_claims`
    /// says is required is what `fmod::claim_required` says over the packed
    /// manifest's own records and conditions block, as the loader reads them.
    #[test]
    fn the_composer_and_the_kernel_agree_on_a_shared_corpus() {
        use fluxor_abi::wire::fmod::{
            claim_required, validate_conditions, ManifestLayout, FLAG_CONDITIONS,
            MANIFEST_FLAGS_AT, MANIFEST_HEADER_SIZE,
        };
        use fluxor_abi::wire::param_schema::{encode_into, encoded_len, ty, Entry};
        let entries = [
            Entry { tag: 1, ptype: ty::U8, default: 0, min: 0, max: 255, name: "mode", enums: &[] },
            Entry {
                tag: 3,
                ptype: ty::U8,
                default: 0,
                min: 0,
                max: 1,
                name: "custody",
                enums: &[("software", 0), ("token", 1)],
            },
            Entry { tag: 6, ptype: ty::STR, default: 0, min: 0, max: 255, name: "cert_file", enums: &[] },
            Entry { tag: 9, ptype: ty::STR, default: 0, min: 0, max: 255, name: "persist", enums: &[] },
            Entry { tag: 11, ptype: ty::STR, default: 0, min: 0, max: 255, name: "routes_prefix", enums: &[] },
        ];
        let mut schema_bytes = vec![0u8; encoded_len(&entries)];
        encode_into(&entries, &mut schema_bytes);
        let schema = schema::ParamSchema::from_bytes(&schema_bytes).expect("schema");
        let manifest = r#"
version = "1.0.0"

[[resources]]
requires_contract = "key_custody"
access = "write"
when = { custody = ["token"] }

[[resources]]
requires_contract = "fs"
access = "read"
active_when_params = ["cert_file"]

[[resources]]
requires_contract = "key_vault"
access = "write"
active_when_params = ["cert_file"]

[[resources]]
requires_contract = "storage.namespace"
access = "read"
when = { persist = ["fs", "kv"] }
active_when_params = ["routes_prefix"]

[[resources]]
requires_contract = "trust"
access = "read"
optional = true

[[resources]]
requires_contract = "timer"
access = "read"
"#;
        let mut m = Manifest::from_toml_str_for_target(manifest, None).expect("manifest");
        m.resolve_conditions(&schema_bytes).expect("resolve");
        let bytes = m.to_bytes();
        let at = MANIFEST_HEADER_SIZE + bytes[5] as usize * 4;
        let records = &bytes[at..at + bytes[6] as usize * 4];
        let from = ManifestLayout::read(&bytes).expect("layout").conditions;
        assert_ne!(bytes[MANIFEST_FLAGS_AT] & FLAG_CONDITIONS, 0);
        let n = validate_conditions(records, Some(&bytes[from..])).expect("the loader's check");
        let block = &bytes[from..from + n];
        let tlv = |basic: &[(u8, &[u8])], ext: &[(u8, &[u8])]| {
            let mut v = vec![0xFE, 0x01, 0, 0];
            for (t, b) in basic {
                v.extend_from_slice(&[*t, b.len() as u8]);
                v.extend_from_slice(b);
            }
            v.extend_from_slice(&[0xFF, 0]);
            for (t, b) in ext {
                v.extend_from_slice(&[*t, 0, 0, b.len() as u8]);
                v.extend_from_slice(b);
            }
            v
        };
        let corpus = [
            tlv(&[], &[]),
            tlv(&[(3, &[1])], &[]),
            tlv(&[(3, &[0]), (6, b"/c.der")], &[]),
            tlv(&[], &[(crate::trust_anchors::TAG_CERT, b"der")]),
            tlv(&[(9, b"kv"), (11, b"/r/")], &[]),
            tlv(&[(9, b"kv")], &[]),
            tlv(&[(11, b"/r/")], &[]),
            tlv(&[(9, b"mem"), (11, b"/r/")], &[]),
            tlv(&[(11, b"")], &[]),
        ];
        for params in &corpus {
            let kernel: Vec<bool> = records
                .chunks_exact(4)
                .enumerate()
                .map(|(i, r)| claim_required(r, i as u8, block, params))
                .collect();
            let tools: Vec<bool> = instance_claims(&m, &schema, 0, params)
                .expect("claims")
                .iter()
                .map(|c| c.required)
                .collect();
            assert_eq!(kernel, tools, "params {params:02x?}");
        }
        // The corpus exercises each claim both ways but the timer's, which
        // is required, and trust's, which never is.
        let req = |p: &[u8]| instance_claims(&m, &schema, 0, p).unwrap();
        assert!(req(&corpus[0]).iter().map(|c| c.required).eq([false, false, false, false, false, true]));
        assert!(req(&corpus[4])[3].required && !req(&corpus[5])[3].required);
        assert!(!req(&corpus[7])[3].required, "`persist` is neither fs nor kv");
        assert!(!req(&corpus[3])[1].required && req(&corpus[3])[2].required);
    }

    /// One writer per `addr_ctl` in any graph: two coordinators on one
    /// stack's port reach it as one channel, under one owner tag, and are
    /// refused at build, naming both; one writer per stack is admitted.
    #[test]
    fn a_second_addr_ctl_writer_is_refused_in_any_graph() {
        let net = Manifest {
            ports: vec![named_port("addr_ctl", 0, "NetProto")],
            ..Manifest::default()
        };
        let coordinator = Manifest {
            ports: vec![named_port("addr_ctl_out", 1, "NetProto")],
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("net".to_string(), net.clone());
        m.insert("net2".to_string(), net);
        m.insert("vip".to_string(), coordinator.clone());
        m.insert("fence".to_string(), coordinator);
        let two = json!({"wiring": [
            {"from": "vip.addr_ctl_out", "to": "net.addr_ctl"},
            {"from": "fence.addr_ctl_out", "to": "net.addr_ctl"}
        ]});
        let e = validate_net_identity_writers(&two, &names(&["net", "vip", "fence"]), &m)
            .unwrap_err()
            .to_string();
        assert!(e.contains("`vip`") && e.contains("`fence`"), "{e}");
        let one_each = json!({"wiring": [
            {"from": "vip.addr_ctl_out", "to": "net.addr_ctl"},
            {"from": "fence.addr_ctl_out", "to": "net2.addr_ctl"}
        ]});
        validate_net_identity_writers(&one_each, &names(&["net", "net2", "vip", "fence"]), &m)
            .expect("one writer per stack");
    }

    #[test]
    fn a_key_vault_is_held_to_its_target_seal_its_store_and_its_handles() {
        let vault = Manifest {
            provides: vec!["key_vault".to_string()],
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("vault".to_string(), vault);
        let n = names(&["vault"]);
        let check = |g: serde_json::Value, rt: &str, target: &str| {
            validate_key_vault(&g, &n, &m, Some(rt), target)
        };
        // The default seal derives from the platform key: refused where
        // there is none, admitted where there is.
        let plain = json!({"modules": [{"name": "vault", "type": "key_vault"}]});
        let e = check(plain.clone(), "uefi", "qemu-uefi-arm64").unwrap_err();
        assert!(e.to_string().contains("no sealing key"), "{e}");
        let e = check(plain.clone(), "rp2040", "pico").unwrap_err();
        assert!(e.to_string().contains("`seal: none`"), "{e}");
        check(plain.clone(), "bcm2712", "pi5").expect("bcm2712 seals");
        check(plain, "linux", "linux").expect("linux seals");
        for seal in [json!("none"), json!(1)] {
            let g = json!({"modules": [{"name": "vault", "type": "key_vault", "seal": seal}]});
            check(g, "uefi", "qemu-uefi-arm64").expect("needs no platform key");
        }
        // `seal: owner` is a workload's vault alone: a node graph's is refused
        // whatever the target
        // (`a_workloads_owner_sealed_vault_takes_its_key_over_the_creators_lane`).
        let g = json!({"modules": [{"name": "vault", "type": "key_vault", "seal": "owner"}]});
        assert!(check(g, "uefi", "qemu-uefi-arm64").is_err());
        let bad = json!({"modules": [{"name": "vault", "seal": "otp"}]});
        assert!(check(bad, "linux", "linux").is_err());

        // A token holds identity keys only where the vault build carries
        // the `key_custody` client: never on RP.
        for custody in [json!("token"), json!(1)] {
            let g = json!({"modules": [{"name": "vault", "seal": "none", "custody": custody}]});
            for (rt, target) in [("rp2040", "pico"), ("rp2350", "pico2w")] {
                let e = check(g.clone(), rt, target).unwrap_err();
                assert!(e.to_string().contains("no token client"), "{rt}: {e}");
            }
            check(g.clone(), "linux", "linux").expect("linux carries the client");
            check(g, "bcm2712", "pi5").expect("the aarch64 build carries the client");
        }
        let soft = json!({"modules": [{
            "name": "vault", "seal": "none", "params": {"custody": "software"},
        }]});
        check(soft, "rp2040", "pico").expect("software custody on RP");

        // A wired store needs a slot size in whole sectors; an image with no
        // store is heap for nothing.
        let wired = |image: serde_json::Value| {
            json!({
                "modules": [{"name": "vault", "image": image}],
                "wiring": [{"from": "disk.blocks", "to": "vault.blocks"}],
            })
        };
        check(wired(json!(8192)), "linux", "linux").expect("8 KiB slots");
        for image in [json!(0), json!(100), json!(1000)] {
            let e = check(wired(image), "linux", "linux").unwrap_err();
            assert!(e.to_string().contains("not a slot size"), "{e}");
        }
        let unwired = json!({"modules": [{"name": "vault", "image": 4096}]});
        let e = check(unwired, "linux", "linux").unwrap_err();
        assert!(e.to_string().contains("nothing is wired"), "{e}");

        // Each key is a routed handle: an RP node reserves 16.
        let many = json!({"modules": [{"name": "vault", "slots": 32}]});
        let e = check(many.clone(), "rp2350", "pico2w").unwrap_err();
        assert!(e.to_string().contains("handles: 32"), "{e}");
        let raised = json!({
            "modules": [{"name": "vault", "slots": 32}],
            "capacity": {"handles": 32},
        });
        check(raised, "rp2350", "pico2w").expect("raised pool");
        check(many, "linux", "linux").expect("128 on linux");
    }

    /// A workload-scoped layer (`owner_fs`) is no provider of a node module,
    /// as the kernel's `layer_visible` has it: a node module that feeds
    /// `owner_fs.ctl` and claims `fs` does not reach `owner_fs` (no cycle),
    /// and on a target whose node has no `fs` of its own the claim is
    /// refused saying the only provider is not visible to it.
    #[test]
    fn a_workload_scoped_layer_is_no_provider_of_a_node_module() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let owner_fs = Manifest::from_toml_for_target(
            &root.join("modules/foundation/owner_fs/manifest.toml"),
            Some("bcm2712"),
        )
        .expect("owner_fs manifest");
        assert!(owner_fs.workload_scope);
        let mut wl = Manifest {
            resources: vec![claim(fluxor_abi::registry::fs::ID as u8, false, &[])],
            ..Manifest::default()
        };
        wl.ports = owner_fs
            .ports
            .iter()
            .filter(|p| p.name.as_deref() == Some("ctl"))
            .cloned()
            .map(|mut p| {
                p.name = Some("fs_ctl".to_string());
                p.direction = 1;
                p
            })
            .collect();
        let mut m = HashMap::new();
        m.insert("owner_fs".to_string(), owner_fs);
        m.insert("wl".to_string(), wl);
        let cfg = json!({
            "modules": [{"name": "wl"}, {"name": "owner_fs"}],
            "wiring": [{"from": "wl.fs_ctl", "to": "owner_fs.ctl"}],
        });
        let n = names(&["wl", "owner_fs"]);
        validate_single_provider(&cfg, &n, &m, linux()).expect("no cycle through owner_fs");
        // Construction order: owner_fs orders nothing for a node module.
        assert_eq!(construction_order(&cfg, &n, &m).unwrap(), vec![0, 1]);
        // Linux answers the node's `fs` itself; bcm2712 does not, and
        // owner_fs is not visible to the node.
        assert!(refusals("linux", &cfg, &m).is_empty());
        let found = refusals("bcm2712", &cfg, &m);
        assert!(
            found.iter().any(|f| f.contains("`wl` requires `fs`")
                && f.contains("`owner_fs` provides it to workloads only")),
            "{found:?}"
        );
    }

    #[test]
    fn single_provider_allows_distinct_and_absent_providers() {
        // A graph with no `provides` anywhere is unaffected.
        let mut m = HashMap::new();
        m.insert("a".to_string(), man(&[]));
        validate_single_provider(&json!({}), &names(&["a"]), &m, linux()).unwrap();

        // Two modules providing DIFFERENT surfaces coexist: a block
        // driver under a filesystem is the normal storage stack.
        let mut m = HashMap::new();
        m.insert("nvme".to_string(), prov(&["storage.block"]));
        m.insert(
            "fat32".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        validate_single_provider(&json!({}), &names(&["nvme", "fat32"]), &m, linux()).unwrap();
    }

    /// A host lane serving a contract is its default provider, as a module
    /// that declares it is: a Linux graph composing `ip` (which provides
    /// `net_route` and `net_policy` on every target) and the host network
    /// provider has two, and is refused naming both. Either alone composes.
    #[test]
    fn a_host_lane_serving_a_contract_counts_as_its_provider() {
        use crate::manifest::{ManifestParam, ManifestParamType};
        let lane = Manifest {
            builtin: true,
            params: vec![ManifestParam {
                tag: 14,
                name: "serves".into(),
                ptype: ManifestParamType::Str,
                default_num: 0,
                default_str: String::new(),
                enum_values: Vec::new(),
                range: None,
                required: false,
            }],
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("ip".to_string(), prov(&["net_route", "net_policy"]));
        m.insert("net".to_string(), lane);
        let cfg = json!({"modules": [
            {"name": "ip"},
            {"name": "net", "serves": "net_route,net_policy"},
        ]});
        let e = validate_single_provider(&cfg, &names(&["ip", "net"]), &m, linux()).unwrap_err();
        let s = format!("{e:?}");
        assert!(s.contains("`ip`") && s.contains("`net`"), "names both: {s}");
        assert!(s.contains("host provider"), "says why: {s}");
        validate_single_provider(&cfg, &names(&["net"]), &m, linux()).expect("the lane alone");
        validate_single_provider(&cfg, &names(&["ip"]), &m, linux()).expect("ip alone");
        let other = json!({"modules": [{"name": "net", "serves": "key_custody"}]});
        validate_single_provider(&other, &names(&["ip", "net"]), &m, linux())
            .expect("a lane serving another contract");
    }

    /// A built-in a host provider serves (`linux_net`) is the default
    /// provider of the contracts its manifest names only where no other
    /// module of the graph provides them: beside `ip` it serves its sockets
    /// alone, and the graph composes; two of it both serve them, and are
    /// refused.
    #[test]
    fn a_host_provider_serves_only_what_no_other_module_provides() {
        let net = Manifest {
            builtin: true,
            host_provider: Some(crate::manifest::HostProvider {
                runtime: "fluxor-provider-net".into(),
                serves: vec!["net_route".into(), "net_policy".into()],
            }),
            ..Manifest::default()
        };
        let mut m = HashMap::new();
        m.insert("ip".to_string(), prov(&["net_route", "net_policy"]));
        m.insert("linux_net".to_string(), net.clone());
        m.insert("second_net".to_string(), net);
        assert!(host_provider_serves("linux_net", &names(&["ip", "linux_net"]), &m).is_empty());
        assert_eq!(
            host_provider_serves("linux_net", &names(&["linux_net"]), &m),
            vec!["net_route".to_string(), "net_policy".to_string()]
        );
        let cfg = json!({"modules": [{"name": "ip"}, {"name": "linux_net"}]});
        validate_single_provider(&cfg, &names(&["ip", "linux_net"]), &m, linux())
            .expect("ip serves the routes, linux_net its sockets");
        let two = json!({"modules": [{"name": "linux_net"}, {"name": "second_net"}]});
        let e = validate_single_provider(&two, &names(&["linux_net", "second_net"]), &m, linux())
            .unwrap_err();
        assert!(format!("{e:?}").contains("host provider"), "{e:?}");
    }

    #[test]
    fn single_provider_rejects_two_fat32_volumes() {
        // Two fat32 instances both provide file.data + storage.namespace;
        // at runtime the higher-indexed one shadows the other and its
        // drive is unreachable. Must fail validation, naming both.
        let mut m = HashMap::new();
        m.insert(
            "fat32_a".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        m.insert(
            "fat32_b".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        let e = validate_single_provider(&json!({}), &names(&["fat32_a", "fat32_b"]), &m, linux())
            .unwrap_err();
        let s = format!("{e:?}");
        assert!(
            s.contains("fat32_a") && s.contains("fat32_b"),
            "must name both modules, got: {s}"
        );
        assert!(
            s.contains("`fat32_b` silently shadows `fat32_a`"),
            "the later module shadows the earlier, got: {s}"
        );
    }

    #[test]
    fn single_provider_allows_two_block_drivers() {
        // `storage.block` is not class-byte dispatched (a source is the
        // channel wired to its consumer), so two block devices in one graph
        // do NOT shadow.
        let mut m = HashMap::new();
        m.insert("sd".to_string(), prov(&["storage.block"]));
        m.insert("nvme".to_string(), prov(&["storage.block"]));
        validate_single_provider(&json!({}), &names(&["sd", "nvme"]), &m, linux()).unwrap();
    }

    #[test]
    fn single_provider_module_may_list_a_surface_without_self_shadowing() {
        // The same module appearing once with a surface is not a
        // duplicate against itself.
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), prov(&["file.data", "file.data"]));
        validate_single_provider(&json!({}), &names(&["fat32"]), &m, linux()).unwrap();
    }

    #[test]
    fn single_provider_allows_distinct_volume_selectors() {
        // Two fat32 backends with distinct `volume:` params coexist — a
        // `mount` module binds each and routes paths between them.
        let mut m = HashMap::new();
        m.insert(
            "fat32_boot".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        m.insert(
            "fat32_data".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        m.insert(
            "mount".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        let cfg = json!({"modules": [
            {"name": "mount", "type": "mount"},
            {"name": "fat32_boot", "type": "fat32", "params": {"volume": "sd0"}},
            {"name": "fat32_data", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        validate_single_provider(
            &cfg,
            &names(&["mount", "fat32_boot", "fat32_data"]),
            &m,
            linux(),
        )
        .unwrap();
    }

    #[test]
    fn single_provider_rejects_same_volume_selector() {
        // Two backends declaring the SAME volume still collide.
        let mut m = HashMap::new();
        m.insert("a".to_string(), prov(&["file.data"]));
        m.insert("b".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "a", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "b", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        let e = validate_single_provider(&cfg, &names(&["a", "b"]), &m, linux()).unwrap_err();
        let s = format!("{e:?}");
        assert!(s.contains("nvme0") && s.contains("collide"), "got: {s}");
    }

    /// A manifest claiming `fs` the given way.
    fn fs_consumer(selector: ClaimSelector) -> Manifest {
        Manifest {
            resources: vec![ResourceClaim {
                device_class: fluxor_abi::registry::fs::ID as u8,
                access_mode: 1,
                instance: 0xFF,
                selector,
                active_when_params: Vec::new(),
                optional: false,
                variants: Vec::new(),
                when: Vec::new(),
                claim: fluxor_abi::wire::fmod::claim::REQUIRED,
            }],
            ..Manifest::default()
        }
    }

    #[test]
    fn single_provider_rejects_keyed_backends_with_no_router() {
        // Distinct selectors, but nothing provides the surface unkeyed, and
        // a consumer that names no volume takes the class-byte path: the
        // kernel answers it from the target's own provider or with ENOSYS,
        // never from these volumes.
        let mut m = HashMap::new();
        m.insert("boot".to_string(), prov(&["file.data"]));
        m.insert("data".to_string(), prov(&["file.data"]));
        m.insert("app".to_string(), fs_consumer(ClaimSelector::Default));
        let cfg = json!({"modules": [
            {"name": "boot", "type": "fat32", "params": {"volume": "sd0"}},
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "app", "type": "fs_tap"},
        ]});
        let e = validate_single_provider(&cfg, &names(&["boot", "data", "app"]), &m, linux())
            .unwrap_err();
        let s = format!("{e:?}");
        assert!(
            s.contains("`app`'s `fs` claim names no volume")
                && s.contains("`boot` (volume `sd0`)")
                && s.contains("`data` (volume `nvme0`)"),
            "got: {s}"
        );
    }

    #[test]
    fn single_provider_refuses_one_keyed_backend_without_a_router() {
        // A single keyed backend needs a router too, for a consumer that
        // names no volume: `volume:` moves it off the class-byte path
        // whether or not it has siblings.
        let mut m = HashMap::new();
        m.insert("only".to_string(), prov(&["file.data"]));
        m.insert("app".to_string(), fs_consumer(ClaimSelector::Default));
        let cfg = json!({"modules": [
            {"name": "only", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "app", "type": "fs_tap"},
        ]});
        let e = validate_single_provider(&cfg, &names(&["only", "app"]), &m, linux()).unwrap_err();
        assert!(
            format!("{e:?}").contains("every provider of `fs` in the graph is instance-keyed"),
            "got: {e:?}"
        );
    }

    #[test]
    fn keyed_only_providers_pass_with_no_consumer() {
        // Nothing takes the class-byte path, so nothing is misrouted.
        let mut m = HashMap::new();
        m.insert("boot".to_string(), prov(&["file.data"]));
        m.insert("data".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "boot", "type": "fat32", "params": {"volume": "sd0"}},
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        validate_single_provider(&cfg, &names(&["boot", "data"]), &m, linux())
            .expect("no consumer");
    }

    #[test]
    fn keyed_only_providers_pass_with_a_runtime_selector_consumer() {
        // The consumer names its volume at runtime (`provider_call_sel`),
        // which the composer cannot check and does not refuse.
        let mut m = HashMap::new();
        m.insert("data".to_string(), prov(&["file.data"]));
        m.insert("relop".to_string(), fs_consumer(ClaimSelector::Runtime));
        let cfg = json!({"modules": [
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "relop", "type": "relop"},
        ]});
        validate_single_provider(&cfg, &names(&["data", "relop"]), &m, linux()).expect("runtime");
    }

    #[test]
    fn a_fixed_selector_needs_a_provider_of_that_volume() {
        let mut m = HashMap::new();
        m.insert("data".to_string(), prov(&["file.data"]));
        m.insert(
            "app".to_string(),
            fs_consumer(ClaimSelector::Fixed("nvme0".into())),
        );
        let cfg = json!({"modules": [
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "app", "type": "fs_tap"},
        ]});
        validate_single_provider(&cfg, &names(&["data", "app"]), &m, linux()).expect("declared");

        m.insert(
            "app".to_string(),
            fs_consumer(ClaimSelector::Fixed("sd0".into())),
        );
        let e = validate_single_provider(&cfg, &names(&["data", "app"]), &m, linux()).unwrap_err();
        let s = format!("{e:?}");
        assert!(
            s.contains("`app`'s `fs` claim names volume `sd0` (`selector`), which no provider")
                && s.contains("declared: `nvme0`"),
            "got: {s}"
        );
    }

    #[test]
    fn a_selector_param_names_the_volume_or_the_default() {
        // Empty or absent: the default provider, refused against keyed-only
        // providers. Set: that volume.
        let mut m = HashMap::new();
        m.insert("data".to_string(), prov(&["file.data"]));
        m.insert(
            "img".to_string(),
            fs_consumer(ClaimSelector::Param("volume".into())),
        );
        let keyed_only = |img: serde_json::Value| {
            json!({"modules": [
                {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
                img,
            ]})
        };
        let e = validate_single_provider(
            &keyed_only(json!({"name": "img", "type": "file_block", "params": {"volume": ""}})),
            &names(&["data", "img"]),
            &m,
            linux(),
        )
        .unwrap_err();
        assert!(format!("{e:?}").contains("`img`'s `fs` claim leaves its `volume` param"));
        let e = validate_single_provider(
            &keyed_only(json!({"name": "img", "type": "file_block"})),
            &names(&["data", "img"]),
            &m,
            linux(),
        )
        .unwrap_err();
        assert!(format!("{e:?}").contains("`img`'s `fs` claim leaves its `volume` param"));
        validate_single_provider(
            &keyed_only(
                json!({"name": "img", "type": "file_block", "params": {"volume": "nvme0"}}),
            ),
            &names(&["data", "img"]),
            &m,
            linux(),
        )
        .expect("a set volume");
        validate_single_provider(
            &keyed_only(json!({"name": "img", "type": "file_block", "volume": "platform"})),
            &names(&["data", "img"]),
            &m,
            linux(),
        )
        .expect("platform is the target's own provider");
    }

    #[test]
    fn a_provider_cannot_reach_through_its_own_volume_param() {
        // `volume` names the volume the provider registers as; it cannot
        // also name the volume the provider reaches.
        let mut m = HashMap::new();
        let mut router = prov(&["file.data"]);
        router.resources = fs_consumer(ClaimSelector::Param("volume".into())).resources;
        m.insert("router".to_string(), router);
        let cfg = json!({"modules": [{"name": "router", "type": "mount"}]});
        let e = validate_single_provider(&cfg, &names(&["router"]), &m, linux()).unwrap_err();
        assert!(
            e.to_string()
                .contains("names the volume it reaches with `selector_param = \"volume\"`"),
            "got: {e:?}"
        );

        // A param of its own is checked as a consumer's is.
        let mut cache = prov(&["file.data"]);
        cache.resources = fs_consumer(ClaimSelector::Param("backend".into())).resources;
        m.insert("cache".to_string(), cache);
        m.insert("data".to_string(), prov(&["file.data"]));
        let graph = |backend: &str| {
            json!({"modules": [
                {"name": "cache", "type": "fs_cache", "params": {"volume": "fast", "backend": backend}},
                {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            ]})
        };
        validate_single_provider(&graph("nvme0"), &names(&["cache", "data"]), &m, linux())
            .expect("a declared backend");
        let e = validate_single_provider(&graph("sd0"), &names(&["cache", "data"]), &m, linux())
            .unwrap_err();
        assert!(
            e.to_string()
                .contains("names volume `sd0` through its `backend` param"),
            "{e}"
        );
    }

    #[test]
    fn every_volume_a_mount_table_names_is_provided() {
        let mut m = HashMap::new();
        let mut router = prov(&["file.data"]);
        router.resources = fs_consumer(ClaimSelector::Table("mounts".into())).resources;
        m.insert("mount".to_string(), router);
        m.insert("data".to_string(), prov(&["file.data"]));
        let names = names(&["mount", "data"]);
        let graph = |mounts: &str| {
            json!({"modules": [
                {"name": "mount", "type": "mount", "params": {"mounts": mounts}},
                {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            ]})
        };
        let check =
            |mounts: &str, reach| validate_single_provider(&graph(mounts), &names, &m, reach);
        check("/data=nvme0;/host=platform;", linux()).expect("both provided on Linux");
        let e = check("/data=nvme0;/logs=nvme1", linux())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("`mount`'s `fs` claim mounts `/logs` on volume `nvme1`")
                && e.contains("declared: `nvme0`"),
            "{e}"
        );
        let pi5 = ProviderReach {
            runtime: Some("bcm2712"),
            caller: ProviderCaller::Node,
            project: fluxor_root(),
        };
        let e = check("/host=platform", pi5).unwrap_err().to_string();
        assert!(e.contains("mounts `/host` on volume `platform`"), "{e}");
        let e = check("/data=nvme0;/boot", linux()).unwrap_err().to_string();
        assert!(
            e.contains("`mount`'s `mounts` entry `/boot` is not `prefix=volume`"),
            "{e}"
        );
    }

    #[test]
    fn a_selector_param_is_read_as_the_packer_reads_it() {
        // A bare key on the entry wins over `params:`, and a value naming a
        // `data:` entry stands for its content.
        let mut m = HashMap::new();
        m.insert("data".to_string(), prov(&["file.data"]));
        m.insert(
            "img".to_string(),
            fs_consumer(ClaimSelector::Param("volume".into())),
        );
        let names = names(&["data", "img"]);
        let cfg = json!({"modules": [
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
            {"name": "img", "type": "file_block", "volume": "nvme0", "params": {"volume": "sd0"}},
        ]});
        validate_single_provider(&cfg, &names, &m, linux()).expect("the bare key wins");
        let cfg = json!({
            "data": {"disk": {"content": "nvme0"}},
            "modules": [
                {"name": "data", "type": "fat32", "volume": "disk"},
                {"name": "img", "type": "file_block", "volume": "disk"},
            ]
        });
        validate_single_provider(&cfg, &names, &m, linux()).expect("both resolve through data:");
    }

    #[test]
    fn platform_is_reached_only_where_the_target_answers_it() {
        let mut m = HashMap::new();
        m.insert(
            "img".to_string(),
            fs_consumer(ClaimSelector::Param("volume".into())),
        );
        let cfg = json!({"modules": [
            {"name": "img", "type": "file_block", "params": {"volume": "platform"}},
        ]});
        let reach = |runtime, caller| ProviderReach {
            runtime: Some(runtime),
            caller,
            project: fluxor_root(),
        };
        let check = |r| validate_single_provider(&cfg, &names(&["img"]), &m, r);
        check(linux()).expect("Linux answers fs from the host");
        let e = check(reach("bcm2712", ProviderCaller::Workload)).unwrap_err();
        assert!(
            e.to_string()
                .contains("on bcm2712 answers no `fs` call of a workload's modules"),
            "a workload's `fs` is the workload layer, never the platform's: {e}"
        );
        let e = check(reach("bcm2712", ProviderCaller::Node)).unwrap_err();
        assert!(
            e.to_string()
                .contains("on bcm2712 answers no `fs` call of the node's own modules"),
            "{e}"
        );
        assert!(check(reach("rp2350", ProviderCaller::Node)).is_err());
        check(ProviderReach {
            runtime: None,
            caller: ProviderCaller::Node,
            project: fluxor_root(),
        })
        .expect("an unknown target is not checked");
    }

    #[test]
    fn a_consumer_cannot_reach_the_default_provider_it_feeds() {
        // A file-backed device under the graph's own filesystem: the image's
        // open reaches that filesystem, which mounts only once the image
        // serves it.
        let mut m = HashMap::new();
        m.insert("fs".to_string(), prov(&["file.data"]));
        let mut disk = prov(&["storage.block"]);
        disk.resources = fs_consumer(ClaimSelector::Param("volume".into())).resources;
        m.insert("disk".to_string(), disk);
        m.insert("seal".to_string(), prov(&["storage.block"]));
        let graph = |volume: Value| {
            json!({
                "modules": [
                    {"name": "disk", "type": "file_block", "path": "data.img", "volume": volume},
                    {"name": "seal", "type": "crypt_block"},
                    {"name": "fs", "type": "fat32"},
                ],
                "wiring": [
                    {"from": "disk.blocks", "to": "seal.lower"},
                    {"from": "seal.blocks", "to": "fs.blocks"},
                ]
            })
        };
        let names = names(&["disk", "seal", "fs"]);
        let e = validate_single_provider(&graph(Value::Null), &names, &m, linux()).unwrap_err();
        assert!(
            e.to_string()
                .contains("which it feeds (`disk` → `seal` → `fs`)"),
            "{e}"
        );
        validate_single_provider(&graph(json!("platform")), &names, &m, linux())
            .expect("the image on the host's filesystem");
    }

    /// A store fed commands by a request pipeline answers its calls whatever
    /// has arrived on its command input (`gates_readiness = false`), so a
    /// claimant upstream of that input is admitted; the same wiring into a
    /// port the store waits on is still refused, and so is a path through
    /// another provider of the contract that waits on its own input.
    #[test]
    fn only_a_gating_input_makes_a_feed_a_deadlock() {
        let obj = crate::manifest::contract_id_from_name("storage.object").unwrap();
        let claimant = |name: &str| {
            let mut m = prov(&[]);
            m.ports = vec![named_port("record_out", 1, "OctetStream")];
            m.resources = vec![ResourceClaim {
                device_class: obj,
                access_mode: 2,
                instance: 0xFF,
                selector: ClaimSelector::Default,
                active_when_params: Vec::new(),
                optional: false,
                variants: Vec::new(),
                when: Vec::new(),
                claim: fluxor_abi::wire::fmod::claim::REQUIRED,
            }];
            (name.to_string(), m)
        };
        let store = |commands_gate: bool| {
            let mut m = prov(&["storage.object"]);
            let mut commands = named_port("commands", 0, "OctetStream");
            commands.gates_readiness = commands_gate;
            m.ports = vec![commands, named_port("snapshot_import", 0, "OctetStream")];
            m
        };
        let mut router = prov(&[]);
        router.ports = vec![
            named_port("request_in", 0, "OctetStream"),
            named_port("kv_out", 1, "OctetStream"),
        ];
        let manifests = |store: Manifest, mid: Option<Manifest>| {
            let mut m: HashMap<String, Manifest> = HashMap::from([
                claimant("http_chain"),
                ("router".to_string(), router.clone()),
                ("store".to_string(), store),
            ]);
            if let Some(mid) = mid {
                m.insert("mid".to_string(), mid);
            }
            m
        };
        let graph = |into: &str| {
            json!({
                "modules": [
                    {"name": "http_chain", "type": "http_chain"},
                    {"name": "router", "type": "kv_request_router"},
                    {"name": "store", "type": "kv_state_worker_store"},
                ],
                "wiring": [
                    {"from": "http_chain.record_out", "to": "router.request_in"},
                    {"from": "router.kv_out", "to": into},
                ]
            })
        };
        let mods = names(&["http_chain", "router", "store"]);
        validate_single_provider(
            &graph("store.commands"),
            &mods,
            &manifests(store(false), None),
            linux(),
        )
        .expect("the store answers whatever its command input has carried");
        let e = validate_single_provider(
            &graph("store.commands"),
            &mods,
            &manifests(store(true), None),
            linux(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("which it feeds (`http_chain` → `router` → `store`)"),
            "{e}"
        );
        // Defaults stay conservative: an undeclared port, or an endpoint
        // naming no port, gates.
        for into in ["store.snapshot_import", "store"] {
            let e = validate_single_provider(
                &graph(into),
                &mods,
                &manifests(store(false), None),
                linux(),
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("which it feeds"), "{into}: {e}");
        }

        // Through another provider of the contract that waits on its
        // input: refused, whichever port of the store the path then enters.
        let mut mid = prov(&["storage.object"]);
        mid.ports = vec![
            named_port("in", 0, "OctetStream"),
            named_port("out", 1, "OctetStream"),
        ];
        let mut through = graph("mid.in");
        through["modules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "mid", "type": "cache", "volume": "c"}));
        through["wiring"]
            .as_array_mut()
            .unwrap()
            .push(json!({"from": "mid.out", "to": "store.commands"}));
        let names3 = names(&["http_chain", "router", "mid", "store"]);
        let e = validate_single_provider(
            &through,
            &names3,
            &manifests(store(false), Some(mid.clone())),
            linux(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("which it feeds (`http_chain` → `router` → `mid` → `store`)"),
            "{e}"
        );
        // The same intermediate entered through a port it does not wait on
        // is just another hop.
        mid.ports[0].gates_readiness = false;
        validate_single_provider(
            &through,
            &names3,
            &manifests(store(false), Some(mid)),
            linux(),
        )
        .expect("no provider on the path waits on what it hears");
    }

    /// A claim with `active_when_params` counts only for an instance that
    /// sets one of them: a consumer whose table params are all unset makes
    /// no call, so it reaches no provider and feeds none it could deadlock
    /// on; set one, and the same graph is refused as before.
    #[test]
    fn an_unexercised_claim_reaches_no_provider() {
        let mut m = HashMap::new();
        m.insert("fs".to_string(), prov(&["file.data"]));
        let mut disk = prov(&["storage.block"]);
        let mut claims = fs_consumer(ClaimSelector::Param("volume".into())).resources;
        claims[0].active_when_params = names(&["routes_prefix", "sessions_prefix"]);
        disk.resources = claims;
        m.insert("disk".to_string(), disk);
        let graph = |params: Value| {
            let mut disk = json!({"name": "disk", "type": "file_block"});
            for (k, v) in params.as_object().unwrap() {
                disk[k] = v.clone();
            }
            json!({
                "modules": [disk, {"name": "fs", "type": "fat32"}],
                "wiring": [{"from": "disk.blocks", "to": "fs.blocks"}],
            })
        };
        let names = names(&["disk", "fs"]);
        validate_single_provider(&graph(json!({})), &names, &m, linux())
            .expect("no table param set: the claim is never exercised");
        validate_single_provider(&graph(json!({"routes_prefix": ""})), &names, &m, linux())
            .expect("an empty value sets nothing");
        for set in [
            json!({"routes_prefix": "/dataplane/edge/"}),
            json!({"params": {"sessions_prefix": "/s/"}}),
        ] {
            let e = validate_single_provider(&graph(set.clone()), &names, &m, linux())
                .unwrap_err()
                .to_string();
            assert!(e.contains("which it feeds (`disk` → `fs`)"), "{set}: {e}");
        }
        // A param resolved through `data:` counts by its content.
        let mut g = graph(json!({"routes_prefix": "routes"}));
        g["data"] = json!({"routes": {"content": ""}});
        validate_single_provider(&g, &names, &m, linux()).expect("data entry with empty content");
        g["data"] = json!({"routes": {"content": "/r/"}});
        assert!(validate_single_provider(&g, &names, &m, linux()).is_err());
    }

    /// The domain rule follows the same claims: a caller in another domain
    /// that never exercises its claim on a module provider makes no call
    /// into it.
    #[test]
    fn an_unexercised_claim_places_no_caller_beside_its_provider() {
        let mut m = HashMap::new();
        m.insert("store".to_string(), prov(&["storage.namespace"]));
        let mut http = prov(&[]);
        http.resources = vec![ResourceClaim {
            device_class: crate::manifest::contract_id_from_name("storage.namespace").unwrap(),
            access_mode: 1,
            instance: 0xFF,
            selector: ClaimSelector::Default,
            active_when_params: names(&["routes_prefix"]),
            optional: false,
            variants: Vec::new(),
            when: Vec::new(),
            claim: fluxor_abi::wire::fmod::claim::REQUIRED,
        }];
        m.insert("http".to_string(), http);
        let config = |routes: Value| {
            json!({
                "execution": {"domains": [{"name": "main"}, {"name": "net"}]},
                "capacity": {"owners": 0},
                "modules": [
                    {"name": "store", "type": "kv"},
                    {"name": "http", "type": "http", "domain": "net", "routes_prefix": routes},
                ],
            })
        };
        let check = |c: &Value| {
            let modules = c["modules"].as_array().unwrap().clone();
            validate_provider_domains(c, &modules, &m, "linux")
        };
        check(&config(Value::Null)).expect("http never calls the store");
        let e = check(&config(json!("/dataplane/edge/")))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("module 'http' (domain 'net') requires `storage.namespace`"),
            "{e}"
        );
    }

    /// A port of `module`'s manifest, by name and content type.
    fn named_port(name: &str, direction: u8, content_type: &str) -> crate::manifest::PortSpec {
        crate::manifest::PortSpec {
            direction,
            content_type: fluxor_contracts::CONTENT_TYPES
                .iter()
                .position(|s| *s == content_type)
                .unwrap_or_else(|| panic!("unknown content type '{content_type}'"))
                as u8,
            flags: 0,
            name: Some(name.to_string()),
            index: 0,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: std::collections::BTreeMap::new(),
            fact_params: std::collections::BTreeMap::new(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    #[test]
    fn a_shared_net_provider_does_not_join_its_connections() {
        // An S3 front and an outbound TLS link to a remote node share the
        // host's net provider. The front's socket and the link's socket
        // are different connections, so the front does not feed what sits
        // behind the link — even when that is the provider the front's
        // claim reaches. `net` is the platform's own net module: it has no
        // manifest here, so only its peers' ports say the edges are
        // `NetProto`.
        let mut m = HashMap::new();
        let mut front = fs_consumer(ClaimSelector::Default);
        front.ports = vec![
            named_port("net_out", 1, "NetProto"),
            named_port("net_in", 0, "NetProto"),
        ];
        m.insert("front".to_string(), front);
        let mut link = prov(&[]);
        link.ports = vec![
            named_port("cipher_in", 0, "NetProto"),
            named_port("cipher_out", 1, "NetProto"),
            named_port("clear_out", 1, "OctetStream"),
        ];
        m.insert("link".to_string(), link);
        m.insert("fs".to_string(), prov(&["file.data"]));
        let graph = json!({
            "modules": [
                {"name": "front", "type": "front"},
                {"name": "link", "type": "tls"},
                {"name": "fs", "type": "fat32"},
            ],
            "wiring": [
                {"from": "front.net_out", "to": "net.net_in"},
                {"from": "net.net_out", "to": "front.net_in"},
                {"from": "link.cipher_out", "to": "net.net_in"},
                {"from": "net.net_out", "to": "link.cipher_in"},
                {"from": "link.clear_out", "to": "fs.blocks"},
            ]
        });
        let names = names(&["front", "link", "fs"]);
        validate_single_provider(&graph, &names, &m, linux())
            .expect("two connections through one net provider are not a data path");

        // The same front wired to the provider directly does feed it.
        let mut direct = graph.clone();
        direct["wiring"]
            .as_array_mut()
            .unwrap()
            .push(json!({"from": "front.net_out", "to": "fs.blocks"}));
        let e = validate_single_provider(&direct, &names, &m, linux()).unwrap_err();
        assert!(
            e.to_string().contains("which it feeds (`front` → `fs`)"),
            "{e}"
        );
    }

    #[test]
    fn single_provider_refuses_the_reserved_platform_selector() {
        // `platform` names the platform's own provider beneath the graph; a
        // module registered under it would capture that path, and the kernel
        // refuses the registration, so the build refuses it first.
        let mut m = HashMap::new();
        m.insert("mount".to_string(), prov(&["file.data"]));
        m.insert("vol".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "mount", "type": "mount"},
            {"name": "vol", "type": "fat32", "params": {"volume": "platform"}},
        ]});
        let e = validate_single_provider(&cfg, &names(&["mount", "vol"]), &m, linux()).unwrap_err();
        let s = format!("{e:?}");
        assert!(s.contains("`vol`") && s.contains("reserved"), "got: {s}");

        // A block source naming `platform` as the fs its image lives on is a
        // consumer of that provider, not a registration: allowed.
        let mut m = HashMap::new();
        m.insert("file_block".to_string(), prov(&["storage.block"]));
        m.insert("fat32".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "file_block", "params": {"volume": "platform"}},
            {"name": "fat32"},
        ]});
        validate_single_provider(&cfg, &names(&["file_block", "fat32"]), &m, linux()).unwrap();
    }

    #[test]
    fn continuity_edge_anchored_requires_anchor_capability() {
        let (n, m) = edge_graph();
        // Worker posing as anchor → rejected.
        let cfg = json!({"continuity": [
            {"id": "x", "class": "edge_anchored", "anchor": "wkr", "workers": ["wkr"]}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("transport.anchor"), "got: {e:?}");
        // Proper anchor passes.
        let cfg = json!({"continuity": [
            {"id": "x", "class": "edge_anchored", "anchor": "anc", "workers": ["wkr"]}]});
        validate_continuity(&cfg, &n, &m).unwrap();
    }

    #[test]
    fn continuity_edge_anchored_multi_worker_requires_handoff() {
        let mut manifests = HashMap::new();
        manifests.insert("anc".to_string(), man(&["transport.anchor.stream"]));
        manifests.insert(
            "w1".to_string(),
            man(&["session.worker", "session.handoff"]),
        );
        manifests.insert("w2".to_string(), man(&["session.worker"])); // no handoff
        let n = names(&["anc", "w1", "w2"]);
        let cfg = json!({"continuity": [
            {"id": "x", "class": "edge_anchored", "anchor": "anc",
             "workers": ["w1", "w2"]}]});
        let e = validate_continuity(&cfg, &n, &manifests).unwrap_err();
        assert!(format!("{e:?}").contains("session.handoff"), "got: {e:?}");
    }

    #[test]
    fn continuity_resumable_needs_resume_provider() {
        let (n, m) = edge_graph();
        let cfg = json!({"continuity": [
            {"id": "x", "class": "resumable", "workers": ["wkr"]}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("session.resume"), "got: {e:?}");

        let mut m2 = HashMap::new();
        m2.insert(
            "wkr".to_string(),
            man(&["session.worker", "session.resume"]),
        );
        validate_continuity(&cfg, &names(&["wkr"]), &m2).unwrap();
    }

    #[test]
    fn continuity_mechanism_only_on_transport_migratable() {
        let (n, m) = edge_graph();
        let cfg = json!({"continuity": [
            {"id": "x", "class": "edge_anchored", "anchor": "anc",
             "workers": ["wkr"], "mechanism": "native_primitive"}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("only valid"), "got: {e:?}");
    }

    /// The quic module's capabilities as its manifest declares them: the mux
    /// transport and the anchor over it.
    const QUIC_CAPS: &[&str] = &[
        "transport.anchor.mux",
        "transport.mux.quic",
        "session.resume",
    ];

    /// A graph with a quic server instance `edge` and a worker behind it.
    fn native_graph(anchor_caps: &[&str]) -> (Vec<String>, HashMap<String, Manifest>) {
        let mut manifests = HashMap::new();
        manifests.insert("edge".to_string(), man(anchor_caps));
        manifests.insert("wkr".to_string(), man(&["session.worker"]));
        (names(&["edge", "wkr"]), manifests)
    }

    fn native_cfg(edge: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
        let mut entry = json!({"id": "mqtt", "class": "transport_migratable",
                               "mechanism": "native_primitive", "anchor": "edge"});
        for (k, v) in extra.as_object().unwrap() {
            entry[k] = v.clone();
        }
        json!({"modules": [edge, {"name": "wkr", "type": "worker"}],
               "continuity": [entry]})
    }

    fn quic_server() -> serde_json::Value {
        json!({"name": "edge", "type": "quic", "mode": 1, "port": 4443})
    }

    /// A quic-anchored graph is admitted with no directory, fence or
    /// reservation, on a hosted target as on bare metal: the connection
    /// state that follows the peer is the quic module's, not the kernel's.
    #[test]
    fn continuity_native_primitive_admits_a_quic_anchor() {
        let (n, m) = native_graph(QUIC_CAPS);
        let cfg = native_cfg(quic_server(), json!({}));
        for target in [Some("bcm2712"), Some("linux"), None] {
            validate_continuity_on(&cfg, &n, &m, target).unwrap();
        }
        // `mode` defaults to server when the graph leaves it out.
        let cfg = native_cfg(json!({"name": "edge", "type": "quic"}), json!({}));
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
    }

    #[test]
    fn continuity_native_primitive_needs_a_mux_provider() {
        let (n, m) = native_graph(&["transport.anchor.mux"]);
        let cfg = native_cfg(quic_server(), json!({}));
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(
            format!("{e:?}").contains("no module in the graph provides"),
            "got: {e:?}"
        );
    }

    /// A TLS or TCP anchor carries no mux, and a mux elsewhere in the graph
    /// does not lend it one: migration lives in the connection state of the
    /// module that carries it.
    #[test]
    fn continuity_native_primitive_refuses_a_stream_anchor() {
        for anchor_cap in ["transport.anchor.stream.secure", "transport.anchor.stream"] {
            let (mut n, mut m) = native_graph(&[anchor_cap]);
            m.insert("quic".to_string(), man(QUIC_CAPS));
            n.push("quic".to_string());
            let cfg = native_cfg(json!({"name": "edge", "type": "tls"}), json!({}));
            let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
            let msg = format!("{e:?}");
            assert!(
                msg.contains("anchor `edge` does not carry"),
                "{anchor_cap}: {msg}"
            );
        }
    }

    #[test]
    fn continuity_native_primitive_needs_an_anchor_that_owns_the_transport() {
        let (n, m) = native_graph(&["transport.mux.quic"]);
        let cfg = native_cfg(quic_server(), json!({}));
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(
            format!("{e:?}").contains("transport.anchor.mux"),
            "got: {e:?}"
        );

        let (n, m) = native_graph(QUIC_CAPS);
        let mut cfg = native_cfg(quic_server(), json!({}));
        cfg["continuity"][0]
            .as_object_mut()
            .unwrap()
            .remove("anchor");
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(
            format!("{e:?}").contains("requires an `anchor`"),
            "got: {e:?}"
        );
    }

    /// The instance, not only its type, decides whether the wire offers
    /// migration.
    #[test]
    fn continuity_native_primitive_refuses_an_anchor_configured_against_it() {
        let (n, m) = native_graph(QUIC_CAPS);
        let client = json!({"name": "edge", "type": "quic", "mode": 0});
        let e = validate_continuity_on(&native_cfg(client, json!({})), &n, &m, Some("bcm2712"))
            .unwrap_err();
        assert!(format!("{e:?}").contains("client"), "got: {e:?}");

        for disabled in [json!(1), json!(true)] {
            let edge = json!({"name": "edge", "type": "quic", "disable_migration": disabled});
            let e = validate_continuity_on(&native_cfg(edge, json!({})), &n, &m, Some("bcm2712"))
                .unwrap_err();
            assert!(
                format!("{e:?}").contains("disable_active_migration"),
                "got: {e:?}"
            );
        }
        let edge = json!({"name": "edge", "type": "quic", "disable_migration": 0});
        validate_continuity_on(&native_cfg(edge, json!({})), &n, &m, Some("bcm2712")).unwrap();
    }

    /// The terms of a takeover are refused by name rather than ignored.
    #[test]
    fn continuity_native_primitive_refuses_takeover_terms() {
        let (mut n, mut m) = native_graph(QUIC_CAPS);
        m.insert("dir".to_string(), man(&["session.directory"]));
        n.push("dir".to_string());
        for extra in [
            json!({"aead": "on_wire_sequence"}),
            json!({"directory": "dir"}),
            json!({"failover_budget_ms": 8000}),
            json!({"client_keepalive_ms": 20000}),
        ] {
            let field = extra.as_object().unwrap().keys().next().unwrap().clone();
            let e =
                validate_continuity_on(&native_cfg(quic_server(), extra), &n, &m, Some("bcm2712"))
                    .unwrap_err();
            let msg = format!("{e:?}");
            assert!(
                msg.contains(&format!(
                    "`{field}` is not valid with mechanism native_primitive"
                )) && msg.contains("platform_replicated_state"),
                "{field}: {msg}"
            );
        }
    }

    fn quic_manifest() -> Manifest {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        Manifest::from_toml_for_target(
            &root.join("modules/foundation/quic/manifest.toml"),
            Some("bcm2712"),
        )
        .expect("quic manifest")
    }

    /// The quic module's own manifest satisfies both halves of the rule, and
    /// still satisfies platform_replicated_state's anchor role.
    #[test]
    fn the_quic_manifest_is_a_native_primitive_anchor() {
        let quic = quic_manifest();
        let has = |want: &str| quic.capabilities.iter().any(|c| cap_satisfies(c, want));
        assert!(
            has("transport.mux") && has("transport.anchor.mux"),
            "{:?}",
            quic.capabilities
        );
        let mut m = HashMap::new();
        m.insert("edge".to_string(), quic);
        m.insert("wkr".to_string(), man(&["session.worker"]));
        validate_continuity_on(
            &native_cfg(quic_server(), json!({})),
            &names(&["edge", "wkr"]),
            &m,
            Some("bcm2712"),
        )
        .unwrap();

        // The same manifest anchoring a platform-replicated-state graph: a
        // standby takeover stays that mechanism's, on the anchor's own
        // `aead` fact.
        let (n, mut m) = prs_graph_with("transport.anchor.mux");
        m.insert("anc".to_string(), quic_manifest());
        m.get_mut("dir")
            .unwrap()
            .capabilities
            .push("session.reservation".to_string());
        validate_continuity_on(&prs_cfg(prs_entry()), &n, &m, Some("bcm2712")).unwrap();
        let e = validate_continuity_on(&prs_cfg(prs_entry()), &n, &m, Some("linux")).unwrap_err();
        assert!(format!("{e:?}").contains("bare-metal"), "got: {e:?}");
    }

    /// A manifest declaring capabilities and one `capability_facts` row.
    fn man_facts(caps: &[&str], cap: &str, fact: &str, value: &str) -> Manifest {
        let mut m = man(caps);
        let mut row = std::collections::BTreeMap::new();
        row.insert(fact.to_string(), value.to_string());
        m.capability_facts.insert(cap.to_string(), row);
        m
    }

    /// Full platform-replicated-state graph with every required provider:
    /// the ip stack (local fence, reach decided by the target) and an
    /// out-of-band fence agent declaring the wire.
    fn prs_graph_with(anchor_cap: &str) -> (Vec<String>, HashMap<String, Manifest>) {
        prs_graph_with_terms(
            anchor_cap,
            &[("aead", aead_of(anchor_cap)), ("horizon", "exact")],
        )
    }

    /// The AEAD class each anchor role is carried on, as its manifest would
    /// state it: TLS records count in lockstep; datagram and mux anchors
    /// carry their sequence on the wire.
    fn aead_of(anchor_cap: &str) -> &'static str {
        if anchor_cap == "transport.anchor.stream.secure" {
            "implicit_counter"
        } else {
            "on_wire_sequence"
        }
    }

    /// `prs_graph_with`, the anchor declaring exactly `terms` as its
    /// `transport.anchor` facts.
    fn prs_graph_with_terms(
        anchor_cap: &str,
        terms: &[(&str, &str)],
    ) -> (Vec<String>, HashMap<String, Manifest>) {
        let mut manifests = HashMap::new();
        let mut anc = man(&[anchor_cap, "session.reservation"]);
        if !terms.is_empty() {
            let row: std::collections::BTreeMap<String, String> = terms
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            anc.capability_facts.insert(anchor_cap.to_string(), row);
        }
        manifests.insert("anc".to_string(), anc);
        manifests.insert(
            "wkr".to_string(),
            man(&["session.worker", "session.handoff"]),
        );
        manifests.insert(
            "dir".to_string(),
            man(&["session.directory", "security.key_wrap", "durable.rpo_zero"]),
        );
        manifests.insert(
            "ip".to_string(),
            man_facts(
                &["fence.enforceable"],
                "fence.enforceable",
                "cutoff",
                "ring_handoff",
            ),
        );
        manifests.insert(
            "pdu".to_string(),
            man_facts(
                &["fence.enforceable"],
                "fence.enforceable",
                "cutoff",
                "wire",
            ),
        );
        (names(&["anc", "wkr", "dir", "ip", "pdu"]), manifests)
    }

    fn prs_graph() -> (Vec<String>, HashMap<String, Manifest>) {
        prs_graph_with("transport.anchor.datagram")
    }

    fn prs_entry() -> serde_json::Value {
        json!({"id": "game", "class": "transport_migratable",
               "mechanism": "platform_replicated_state",
               "aead": "on_wire_sequence",
               "anchor": "anc", "workers": ["wkr"], "directory": "dir",
               "failover_budget_ms": 8000, "client_keepalive_ms": 20000})
    }

    /// The config the graph above is declared in: instance types are what
    /// the validator identifies the ip stack by, and `node` is what places
    /// the fence agent outside the anchor's failure domain.
    fn prs_cfg(entry: serde_json::Value) -> serde_json::Value {
        json!({"modules": [
            {"name": "anc", "type": "anchor"},
            {"name": "wkr", "type": "worker"},
            {"name": "dir", "type": "session_directory", "node": "cluster"},
            {"name": "ip", "type": "ip"},
            {"name": "pdu", "type": "fence_agent", "node": "bench"}],
            "continuity": [entry]})
    }

    /// The same graph with the fence agent instantiated on the anchor's own
    /// node.
    fn prs_cfg_fence_on_node(entry: serde_json::Value) -> serde_json::Value {
        let mut cfg = prs_cfg(entry);
        cfg["modules"][4] = json!({"name": "pdu", "type": "fence_agent"});
        cfg
    }

    #[test]
    fn continuity_prs_out_of_band_fence_must_be_placed_off_node() {
        // A module declaring `cutoff = "wire"` on the anchor's own node is
        // inside the failure domain: it cannot prove that node quiet, so
        // it is not out-of-band evidence, however it labels itself.
        let (n, m) = prs_graph();
        let cfg = prs_cfg_fence_on_node(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        let msg = format!("{e:?}");
        assert!(msg.contains("failure domain"), "got: {msg}");
        assert!(msg.contains("`pdu`"), "got: {msg}");
        assert!(msg.contains("node"), "got: {msg}");
    }

    #[test]
    fn continuity_prs_places_only_the_fence_of_necessity() {
        // A directory is usually a cluster service, but a graph that
        // resolves one locally satisfies the class just as well: it is
        // the fence, and only the fence, whose evidence depends on being
        // somewhere else.
        let (n, m) = prs_graph();
        let mut cfg = prs_cfg(prs_entry());
        cfg["modules"][2] = json!({"name": "dir", "type": "session_directory"});
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
    }

    #[test]
    fn continuity_prs_anchor_is_never_remote() {
        // The anchor owns this node's transport; a placement elsewhere is
        // a declaration about a graph the validator is not looking at.
        let (n, m) = prs_graph();
        let mut cfg = prs_cfg(prs_entry());
        cfg["modules"][0] = json!({"name": "anc", "type": "anchor", "node": "elsewhere"});
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("anchor"), "got: {e:?}");
        assert!(format!("{e:?}").contains("node"), "got: {e:?}");
    }

    #[test]
    fn continuity_platform_replicated_state_full_graph_passes() {
        let (n, m) = prs_graph();
        let cfg = prs_cfg(prs_entry());
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
    }

    #[test]
    fn continuity_prs_stream_anchor_is_bare_metal_only() {
        // A TLS-terminating anchor owns its transport on bcm2712 …
        let (n, m) = prs_graph_with("transport.anchor.stream.secure");
        let mut entry = prs_entry();
        entry["aead"] = json!("implicit_counter");
        let cfg = prs_cfg(entry);
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
        // … and not on a hosted platform, where TCP is the host kernel's.
        let e = validate_continuity_on(&cfg, &n, &m, Some("linux")).unwrap_err();
        assert!(format!("{e:?}").contains("bare-metal"), "got: {e:?}");
        // Without a target the ownership cannot be proven.
        let e = validate_continuity_on(&cfg, &n, &m, None).unwrap_err();
        assert!(format!("{e:?}").contains("resolved target"), "got: {e:?}");
        // A mux anchor follows the same rule.
        let (n, m) = prs_graph_with("transport.anchor.mux");
        let cfg = prs_cfg(prs_entry());
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
        // A plain stream anchor is not a transport Fluxor may migrate.
        let (n, m) = prs_graph_with("transport.anchor.stream");
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("declares none of"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_fence_needs_both_halves() {
        // The ip module's reach is a target fact: rp2350's driver does not
        // drain on request, so its fence stops at the ring hand-off.
        let (n, m) = prs_graph();
        let cfg = prs_cfg(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("rp2350")).unwrap_err();
        assert!(format!("{e:?}").contains("wire"), "got: {e:?}");
        assert!(format!("{e:?}").contains("rp2350"), "got: {e:?}");
        // Local evidence alone is never enough.
        let (n, mut m) = prs_graph();
        m.insert("pdu".to_string(), man(&["session.worker"]));
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("out-of-band"), "got: {e:?}");
        // An out-of-band provider that does not declare its cutoff is not
        // evidence either.
        let (n, mut m) = prs_graph();
        m.insert("pdu".to_string(), man(&["fence.enforceable"]));
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("out-of-band"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_implicit_counter_needs_an_exact_horizon() {
        // An implicit-contiguous AEAD counter cannot skip forward, so it
        // reaches transport_migratable only through an anchor whose mirror
        // keeps an exact horizon. Without that term the honest ceiling is
        // resumable …
        let cap = "transport.anchor.stream.secure";
        let mut entry = prs_entry();
        entry["aead"] = json!("implicit_counter");
        let cfg = prs_cfg(entry);
        for terms in [
            &[("aead", "implicit_counter")][..],
            &[("aead", "implicit_counter"), ("horizon", "cut")][..],
        ] {
            let (n, m) = prs_graph_with_terms(cap, terms);
            let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
            assert!(
                format!("{e:?}").contains("resumable"),
                "terms {terms:?}: got {e:?}"
            );
            assert!(
                format!("{e:?}").contains("exact"),
                "terms {terms:?}: got {e:?}"
            );
        }
        // … and with it the class is admitted.
        let (n, m) =
            prs_graph_with_terms(cap, &[("aead", "implicit_counter"), ("horizon", "exact")]);
        validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap();
    }

    #[test]
    fn continuity_prs_aead_must_match_the_anchors_terms() {
        // The declaration names the anchor's AEAD class; it does not choose
        // it. A TLS anchor declared on_wire_sequence is a misstatement …
        let cap = "transport.anchor.stream.secure";
        let (n, m) = prs_graph_with(cap);
        let cfg = prs_cfg(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("misdeclares"), "got: {e:?}");
        assert!(format!("{e:?}").contains("implicit_counter"), "got: {e:?}");
        // … and so is a datagram anchor declared implicit_counter.
        let (n, m) = prs_graph();
        let mut entry = prs_entry();
        entry["aead"] = json!("implicit_counter");
        let cfg = prs_cfg(entry);
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("misdeclares"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_anchor_must_state_its_aead() {
        // An anchor with no `aead` fact offers no terms to admit the class
        // on; the manifest must say what protects its records.
        let (n, m) = prs_graph_with_terms("transport.anchor.datagram", &[]);
        let cfg = prs_cfg(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(
            format!("{e:?}").contains("declares no `aead` fact"),
            "got: {e:?}"
        );
    }

    #[test]
    fn continuity_prs_requires_every_capability() {
        // Dropping the fence provider must fail with the missing
        // capability named.
        let (n, mut m) = prs_graph();
        m.remove("pdu");
        m.remove("ip");
        let n: Vec<String> = n.into_iter().filter(|x| x != "pdu" && x != "ip").collect();
        let cfg = prs_cfg(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("fence.enforceable"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_requires_directory_role() {
        let (n, mut m) = prs_graph();
        // Directory module present but without the capability.
        m.insert(
            "dir".to_string(),
            man(&["security.key_wrap", "durable.rpo_zero"]),
        );
        let cfg = prs_cfg(prs_entry());
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("session.directory"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_budget_must_fit_under_keepalive() {
        let (n, m) = prs_graph();
        let mut entry = prs_entry();
        entry["failover_budget_ms"] = json!(20000);
        let cfg = prs_cfg(entry);
        let e = validate_continuity_on(&cfg, &n, &m, Some("bcm2712")).unwrap_err();
        assert!(format!("{e:?}").contains("strictly below"), "got: {e:?}");
    }

    #[test]
    fn cap_satisfies_parent_matches_child_not_reverse() {
        assert!(cap_satisfies("transport.anchor.stream", "transport.anchor"));
        assert!(cap_satisfies("transport.anchor", "transport.anchor"));
        assert!(!cap_satisfies(
            "transport.anchor",
            "transport.anchor.stream"
        ));
        // Prefix without a dot boundary must not match.
        assert!(!cap_satisfies("transport.anchorx", "transport.anchor"));
    }
}

/// Coverage for `resolve_edge_rate_class`'s priority order:
/// per-edge `rate:` override, else
/// consumer's `rate_class_default`, else producer's
/// `rate_class_default`, else consumer's content-type default, else
/// producer's, else `control`.
#[cfg(test)]
mod rate_class_resolution_tests {
    use super::*;

    fn content_type_index(name: &str) -> u8 {
        fluxor_contracts::CONTENT_TYPES
            .iter()
            .position(|s| *s == name)
            .unwrap_or_else(|| panic!("unknown content type '{name}'")) as u8
    }

    fn port(content_type: &str) -> manifest::PortSpec {
        manifest::PortSpec {
            direction: 0,
            content_type: content_type_index(content_type),
            flags: 0,
            name: None,
            index: 0,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: std::collections::BTreeMap::new(),
            fact_params: std::collections::BTreeMap::new(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    fn with_default(
        mut p: manifest::PortSpec,
        class: fluxor_contracts::RateClass,
    ) -> manifest::PortSpec {
        p.rate_class_default = Some(class);
        p
    }

    #[test]
    fn per_edge_override_wins_over_everything() {
        let from = with_default(port("NetProto"), fluxor_contracts::RateClass::Bulk);
        let to = with_default(port("NetProto"), fluxor_contracts::RateClass::Bulk);
        let entry = json!({"rate": "control"});
        let class = resolve_edge_rate_class(Some(&entry), Some(&from), Some(&to)).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Control);
    }

    #[test]
    fn unknown_rate_override_is_a_config_error() {
        let entry = json!({"rate": "ludicrous"});
        let err = resolve_edge_rate_class(Some(&entry), None, None).unwrap_err();
        assert!(
            format!("{err:?}").contains("unknown rate class"),
            "got: {err:?}"
        );
    }

    #[test]
    fn consumer_rate_class_default_wins_over_content_type_default() {
        // NetProto's content-type default is `audio`; a consumer that
        // declares `transaction` overrides that default without
        // needing a per-edge `rate:` line.
        let from = port("NetProto");
        let to = with_default(port("NetProto"), fluxor_contracts::RateClass::Transaction);
        let class = resolve_edge_rate_class(None, Some(&from), Some(&to)).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Transaction);
    }

    #[test]
    fn producer_rate_class_default_used_when_consumer_declares_none() {
        // An `http_ingress.net_out → linux_net.net_in` edge: the consumer
        // (a fluxor native module) declares no default, so the producer's own
        // `rate_class_default` is what applies.
        let from = with_default(port("NetProto"), fluxor_contracts::RateClass::Transaction);
        let to = port("NetProto"); // no rate_class_default — e.g. linux_net.net_in
        let class = resolve_edge_rate_class(None, Some(&from), Some(&to)).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Transaction);
    }

    #[test]
    fn falls_back_to_consumer_content_type_default_when_neither_port_declares_one() {
        let from = port("OctetStream"); // Control by content type
        let to = port("NetProto"); // Audio by content type
        let class = resolve_edge_rate_class(None, Some(&from), Some(&to)).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Audio);
    }

    #[test]
    fn falls_back_to_producer_content_type_default_when_consumer_spec_is_absent() {
        let from = port("VideoRaster"); // Audio by content type (see contracts note)
        let class = resolve_edge_rate_class(None, Some(&from), None).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Audio);
    }

    #[test]
    fn falls_back_to_control_when_nothing_resolves() {
        let class = resolve_edge_rate_class(None, None, None).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Control);
    }

    /// `http_ingress.net_out` declares `rate_class_max = transaction`;
    /// without a `rate_class_default` the edge resolves to `audio`
    /// (NetProto's content-type default) via the consumer
    /// (`linux_net.net_in`), which exceeds the cap and fails
    /// `fluxor build --check`. Declaring `rate_class_default = transaction`
    /// on the producer satisfies the cap without touching every
    /// consuming config's wiring.
    #[test]
    fn http_ingress_style_producer_cap_is_satisfied_by_its_own_default() {
        let mut from = with_default(
            port("OctetStream"),
            fluxor_contracts::RateClass::Transaction,
        );
        from.rate_class_max = Some(fluxor_contracts::RateClass::Transaction);
        let to = port("NetProto"); // linux_net.net_in / ip.net_in — no default of its own
        let class = resolve_edge_rate_class(None, Some(&from), Some(&to)).unwrap();
        assert_eq!(class, fluxor_contracts::RateClass::Transaction);
        assert!(!class.exceeds(from.rate_class_max.unwrap()));

        // Without the producer's default, the same edge resolves to
        // `audio` and DOES exceed the cap.
        let mut from_no_default = port("OctetStream");
        from_no_default.rate_class_max = Some(fluxor_contracts::RateClass::Transaction);
        let class_no_default =
            resolve_edge_rate_class(None, Some(&from_no_default), Some(&to)).unwrap();
        assert_eq!(class_no_default, fluxor_contracts::RateClass::Audio);
        assert!(class_no_default.exceeds(from_no_default.rate_class_max.unwrap()));
    }
}

/// `RateClass::severity()` / `exceeds()`. `RateClass` deliberately
/// does not derive `Ord`; these tests pin the intended severity order
/// directly so a regression (e.g. someone adding `#[derive(Ord)]`) is
/// caught here rather than rediscovered via a config validation
/// failure.
#[cfg(test)]
mod rate_class_severity_tests {
    use fluxor_contracts::RateClass;

    #[test]
    fn severity_order_is_control_transaction_audio_video_bulk() {
        let ordered = [
            RateClass::Control,
            RateClass::Transaction,
            RateClass::Audio,
            RateClass::Video,
            RateClass::Bulk,
        ];
        for pair in ordered.windows(2) {
            assert!(
                pair[0].severity() < pair[1].severity(),
                "{:?} should be less severe than {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn transaction_does_not_exceed_itself_or_anything_above_it() {
        assert!(!RateClass::Transaction.exceeds(RateClass::Transaction));
        assert!(!RateClass::Transaction.exceeds(RateClass::Audio));
        assert!(!RateClass::Transaction.exceeds(RateClass::Video));
        assert!(!RateClass::Transaction.exceeds(RateClass::Bulk));
    }

    #[test]
    fn transaction_exceeds_only_control() {
        assert!(RateClass::Transaction.exceeds(RateClass::Control));
    }

    #[test]
    fn audio_exceeds_transaction_despite_declaration_order() {
        // Exactly the case a derived `Ord` would get wrong: `Audio`
        // is declared before `Transaction` in the enum, but is the
        // more demanding class.
        assert!(RateClass::Audio.exceeds(RateClass::Transaction));
        assert!(!RateClass::Transaction.exceeds(RateClass::Audio));
    }

    #[test]
    fn bulk_exceeds_every_other_class() {
        for other in [
            RateClass::Control,
            RateClass::Transaction,
            RateClass::Audio,
            RateClass::Video,
        ] {
            assert!(RateClass::Bulk.exceeds(other));
        }
        assert!(!RateClass::Bulk.exceeds(RateClass::Bulk));
    }
}

#[cfg(test)]
mod capacity_envelope_tests {
    use super::*;
    use serde_json::json;

    /// `capacity:` map → envelope records carrying the contract pool ids and
    /// the asked n.
    #[test]
    fn capacity_map_emits_envelope_records() {
        let cfg = json!({"capacity": {"events": 4, "tls_unknown_not_here": null}});
        // Unknown pool must error, not silently skip.
        let err = build_capacity_envelope(&cfg, Some("linux"))
            .expect_err("unknown pool name is a config error");
        assert!(format!("{err:?}").contains("unknown pool"));

        let cfg = json!({"capacity": {"events": 4, "timers": 2}});
        let sec = build_capacity_envelope(&cfg, Some("linux")).expect("valid envelope");
        // Map order is serde_json's (insertion-preserving) — events (0x0005)
        // then timers (0x0006).
        assert_eq!(
            sec,
            [
                boot_config::PoolEntry { pool: 0x0005, n: 4 },
                boot_config::PoolEntry { pool: 0x0006, n: 2 },
            ]
        );
    }

    /// An entry is a reserve (a size, for a pool the config cannot derive),
    /// and a table pool's reserve may be zero where an arena's size may not.
    /// Whether the kernel can hold it is the boot plan's question
    /// (`boot_plan_tests`), not the envelope's.
    #[test]
    fn an_entry_is_a_reserve_or_an_arena_size() {
        for target in ["wasm", "rp2350", "linux", "pi5"] {
            let cfg = json!({"capacity": {"events": 33}});
            build_capacity_envelope(&cfg, Some(target)).expect("every kernel has an event table");
        }
        let cfg = json!({"capacity": {"module_slots": 3000}});
        build_capacity_envelope(&cfg, Some("linux")).expect("a reserve, not a ceiling");

        let cfg = json!({"capacity": {"events": 0}});
        build_capacity_envelope(&cfg, Some("linux")).expect("a zero reserve is a choice");
        let cfg = json!({"capacity": {"buffer_arena": 0}});
        let err = build_capacity_envelope(&cfg, Some("linux")).expect_err("an empty arena");
        assert!(format!("{err:?}").contains("positive"));
    }

    /// A pool the target's kernel has no table for — host-process sandboxes
    /// off Linux — is refused by name: the entry would bound nothing. A
    /// module-served pool (`store_subs`) is no kernel table, and its entry is
    /// the reserve its providers' heap takes on every target.
    #[test]
    fn an_entry_for_a_pool_the_kernel_lacks_is_refused() {
        assert!(build_capacity_envelope(&json!({"capacity": {"store_subs": 4}}), Some("rp2350"))
            .is_ok());
        for (target, pool) in [
            ("wasm", "sandboxes"),
            ("pi5", "sandboxes"),
            ("pi5", "tty_sessions"),
        ] {
            let cfg = json!({"capacity": {pool: 4}});
            let err = build_capacity_envelope(&cfg, Some(target))
                .expect_err("no such table")
                .to_string();
            assert!(
                err.contains(&format!("has no '{pool}' table")),
                "{target}: {err}"
            );
        }
        for (target, pool) in [("linux", "sandboxes"), ("pi5", "store_subs")] {
            let cfg = json!({"capacity": {pool: 4}});
            build_capacity_envelope(&cfg, Some(target)).expect("the kernel has this table");
        }
        // The store's read, write and grant tables are its own params, and a
        // workload's store is a module like any other: no pool names them.
        for pool in [
            "store_reads",
            "store_writes",
            "store_grants",
            "owner_store_subs",
            "owner_store_reads",
            "owner_store_writes",
        ] {
            let cfg = json!({"capacity": {pool: 4}});
            let err = build_capacity_envelope(&cfg, Some("linux"))
                .expect_err("no such pool")
                .to_string();
            assert!(err.contains(&format!("unknown pool '{pool}'")), "{err}");
        }
    }

    /// `config_arena` is observed, never allocated (module params are
    /// borrowed from the config blob in place), so an envelope entry for it
    /// would bound nothing and is refused by name on every target.
    #[test]
    fn config_arena_cannot_be_sized() {
        for target in ["linux", "pi5", "wasm", "rp2350"] {
            let cfg = json!({"capacity": {"config_arena": 4096}});
            let err = build_capacity_envelope(&cfg, Some(target))
                .expect_err("config_arena holds no allocation to bound");
            assert!(
                format!("{err:?}").contains("config_arena"),
                "{target}: {err:?}"
            );
        }
    }

    /// No `capacity:` block ⇒ no envelope records ⇒ no `ENVL` section.
    #[test]
    fn absent_capacity_block_emits_nothing() {
        let sec = build_capacity_envelope(&json!({}), Some("linux")).expect("ok");
        assert!(sec.is_empty());
    }

    /// RP arena asks aren't validated host-side (silicon-TOML-owned); the
    /// envelope still carries them — the kernel refuses an over-ask at boot.
    #[test]
    fn rp_arena_ask_passes_through_for_the_kernel_to_check() {
        let cfg = json!({"capacity": {"state_arena": 65536}});
        let sec = build_capacity_envelope(&cfg, Some("rp2350")).expect("encodes");
        assert_eq!(
            sec,
            [boot_config::PoolEntry {
                pool: 0x0001,
                n: 65536
            }],
            "an arena's entry below 2 GiB is exact bytes"
        );
    }

    /// An arena entry is exact bytes below 2 GiB — a byte-precise budget stays
    /// exact — and KiB (rounded up, with the KiB bit) past it, so an arena past
    /// 4 GiB (a large board's state arena) still fits; a table's is in its own
    /// unit.
    #[test]
    fn arena_entries_are_exact_bytes_and_reach_past_4_gib() {
        let cfg = json!({"capacity": {"state_arena": 6u64 << 30, "buffer_arena": 1025}});
        let sec = build_capacity_envelope(&cfg, Some("pi5")).expect("encodes");
        let entries: Vec<(u16, u32)> = sec.iter().map(|e| (e.pool, e.n)).collect();
        let kib = crate::capacity::ENTRY_KIB;
        assert!(entries.contains(&(0x0001, (6 << 20) | kib)), "{entries:?}");
        assert!(
            entries.contains(&(0x0002, 1025)),
            "1025 B stays exact: {entries:?}"
        );
        let cfg = json!({"capacity": {"events": 40}});
        let sec = build_capacity_envelope(&cfg, Some("pi5")).expect("encodes");
        assert_eq!(sec[0].n, 40);
    }
}

/// Graph-sized capacity: module params have no ceiling, the composer reads
/// the kernel's pool sizes as profile data and runs its boot plan, the Linux
/// and bcm2712 edge tables are sized at boot, and the graph's declared demand
/// rides the `DMND` section.
#[cfg(test)]
mod dynamic_capacity_tests {
    use super::*;
    use serde_json::json;

    /// A schema with one blob param, `payload` (tag 1).
    fn blob_schema() -> schema::ParamSchema {
        let mut b = vec![0x53, 0x50, 1, 1];
        b.extend_from_slice(&schema::raw_param(1, 5, 0, "payload"));
        schema::ParamSchema::from_bytes(&b).expect("schema")
    }

    /// 600 KiB of params pack into one entry — the buffer grows to fit
    /// — and every byte is there, in order.
    #[test]
    fn six_hundred_kib_of_params_pack_whole() {
        const BLOB: usize = 61440;
        let blobs: Vec<Vec<u8>> = (0..10u8)
            .map(|i| (0..BLOB).map(|j| (j as u8).wrapping_mul(31) ^ i).collect())
            .collect();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let module =
            json!({"payload": blobs.iter().map(|b| json!({"hex": hex(b)})).collect::<Vec<_>>()});
        let params = pack_params_growing(&module, &blob_schema(), None, "probe").expect("packs");
        assert!(params.len() > 600 * 1024, "{} bytes", params.len());
        // Walk the TLV and reassemble the blobs.
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut off = 4;
        let mut want = 0usize;
        while off + 2 <= params.len() && params[off] != 0xFF {
            let (tag, len) = (params[off], params[off + 1] as usize);
            assert_eq!(tag, 1);
            let mut d = &params[off + 2..off + 2 + len];
            if want == 0 {
                want = u16::from_le_bytes([d[0], d[1]]) as usize;
                d = &d[2..];
                got.push(Vec::new());
            }
            got.last_mut().unwrap().extend_from_slice(d);
            want -= d.len();
            off += 2 + len;
        }
        assert_eq!(got, blobs, "every blob arrives whole and in order");
    }

    #[test]
    fn pool_sizes_are_the_kernel_profiles_data() {
        use crate::capacity::{
            kernel_has_pool, kernel_max_edges, kernel_max_modules, kernel_max_owners,
            kernel_pool_default_reserve, kernel_pool_static_size,
        };
        assert!(!crate::capacity::edge_tables_sized_at_boot("rp2350"));
        assert_eq!(kernel_pool_static_size("pi5", "events"), None);
        assert_eq!(kernel_pool_static_size("pi5", "channels"), None);
        assert_eq!(kernel_pool_static_size("rp2350", "events"), None);
        assert_eq!(kernel_pool_static_size("rp2350", "owners"), None);
        assert_eq!(kernel_pool_static_size("wasm", "events"), Some(32));
        assert_eq!(kernel_pool_default_reserve("rp2350", "events"), Some(32));
        assert_eq!(
            kernel_max_edges("rp2350"),
            128,
            "RP's channel table is sized from the graph within its compiled 128 edges"
        );
        assert_eq!(kernel_pool_static_size("linux", "events"), None);
        assert_eq!(kernel_pool_default_reserve("linux", "events"), Some(32));
        assert_eq!(
            kernel_pool_default_reserve("linux", "store_subs"),
            None,
            "a module-served pool has no kernel row"
        );
        assert_eq!(kernel_pool_default_reserve("pi5", "events"), Some(32));
        assert_eq!(
            kernel_pool_default_reserve("pi5", "module_slots"),
            Some(256)
        );
        assert_eq!(kernel_max_modules("linux"), 4096);
        assert_eq!(kernel_max_modules("pi5"), 1024);
        // One owner-slot range on every kernel.
        for t in ["linux", "pi5", "rp2040", "rp2350", "wasm"] {
            assert_eq!(kernel_max_owners(t), 4096, "{t}");
        }
        assert!(kernel_has_pool("linux", "tty_sessions"));
        assert!(!kernel_has_pool("pi5", "store_reads"));
        assert!(kernel_has_pool("rp2350", "state_arena"));
        // Store subscriptions are module-served: no kernel has a table for them.
        for t in ["linux", "pi5", "rp2350"] {
            assert!(!kernel_has_pool(t, "store_subs"), "{t}");
        }
        // uefi: bare-metal aarch64 like bcm2712, with no store-subscription reserve.
        for t in ["uefi", "qemu-uefi-arm64", "ec2-arm64"] {
            assert_eq!(crate::capacity::kernel_profile(t), "profile_uefi");
            assert!(crate::capacity::edge_tables_sized_at_boot(t));
            assert_eq!(kernel_max_modules(t), 1024);
            assert_eq!(kernel_max_owners(t), 4096);
            assert_eq!(kernel_pool_default_reserve(t, "module_slots"), Some(256));
            assert_eq!(
                kernel_pool_default_reserve(t, "state_arena"),
                Some(512 * 1024 * 1024)
            );
            assert!(kernel_has_pool(t, "lends"));
            assert!(!kernel_has_pool(t, "store_subs"));
            assert!(!kernel_has_pool(t, "store_reads"));
        }
    }

    #[test]
    fn edge_tables_sized_at_boot_take_the_kernels_bound() {
        use crate::capacity::{kernel_max_edges, BOOT_SIZED_MAX_EDGES};
        for t in ["linux", "pi5", "uefi"] {
            assert_eq!(kernel_max_edges(t), BOOT_SIZED_MAX_EDGES, "{t}");
        }
        assert_eq!(
            kernel_max_edges("rp2350"),
            128,
            "a static profile keeps its count"
        );
    }

    /// Each instance's demand, as the composer counts it: no params, no
    /// `demand:` of its own.
    fn demand_of(names: &[String], manifests: &HashMap<String, Manifest>) -> Vec<InstanceDemand> {
        names
            .iter()
            .map(|n| InstanceDemand {
                name: n.clone(),
                figures: instance_demand(&json!({}), n, manifests.get(n), &[], &[]).unwrap(),
                heap_per_demand: manifests.get(n).and_then(|m| m.heap_per_demand.clone()),
            })
            .collect()
    }

    /// The graph's store consumers declare their subscriptions; the
    /// composer sums them into one `DMND` entry for the kernel.
    #[test]
    fn declared_subscriptions_ride_the_demand_section() {
        let mut manifests = HashMap::new();
        for (name, n) in [("watch_a", 7u32), ("watch_b", 5), ("plain", 0)] {
            let mut m = Manifest::default();
            if n > 0 {
                m.capacities.insert("store_subscriptions".into(), n);
            }
            manifests.insert(name.to_string(), m);
        }
        let names: Vec<String> = ["watch_a", "watch_b", "plain"].map(String::from).to_vec();
        let demand = demand_of(&names, &manifests);
        let declared = declared_demand(&demand).expect("declared");
        assert_eq!(declared, vec![("store_subs", 0x0100, 12)]);
        assert!(declared_demand(&demand[2..]).unwrap().is_empty());
    }

    /// A subscriber's `store_subscribers` demand counts against the events
    /// pool: each one is woken through an event it holds.
    #[test]
    fn store_subscribers_declare_events() {
        let mut m = Manifest::default();
        m.capacities.insert("store_subscribers".into(), 1);
        m.capacities.insert("store_subscriptions".into(), 3);
        let manifests: HashMap<String, Manifest> = [("a", m.clone()), ("b", m)]
            .map(|(n, m)| (n.to_string(), m))
            .into();
        let names: Vec<String> = ["a", "b"].map(String::from).to_vec();
        let demand = demand_of(&names, &manifests);
        let declared = declared_demand(&demand).unwrap();
        assert_eq!(
            declared,
            vec![("store_subs", 0x0100, 6), ("events", 0x0005, 2)]
        );
    }

    /// A params TLV of `entries` `(tag, value)`.
    pub(super) fn tlv_of(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut t = vec![0xFE, 0x01, 0, 0];
        for (tag, v) in entries {
            t.push(*tag);
            t.push(v.len() as u8);
            t.extend_from_slice(v);
        }
        t.extend_from_slice(&[0xFF, 0]);
        t
    }

    /// `demand_from_params` counts an instance's comma-split param entries in
    /// place of the type's constant; the graph's own `demand:` wins.
    #[test]
    fn demand_from_params_counts_entries_and_an_explicit_figure_wins() {
        let rule = crate::manifest::DemandFromParams {
            pool: "store_subs".into(),
            tags: vec![2, 5],
            split: ",".into(),
        };
        let mut m = Manifest::default();
        m.capacities.insert("store_subscriptions".into(), 2);
        m.demand_from_params = vec![rule.clone()];
        // `prefix` (tag 2) names three, `watch` (tag 5) one; tag 9 is not
        // counted, nor are blank entries.
        let tlv = tlv_of(&[(2, b"/a/,/b/, /c/,"), (9, b"/x/,/y/"), (5, b"/w/")]);
        assert_eq!(rule.declared_count(&tlv, &[]), 4);
        assert_eq!(
            instance_demand(&json!({}), "src", Some(&m), &tlv, &[]).unwrap(),
            vec![("store_subs", 4)]
        );
        // A chunked param's chunks are one value.
        let tlv = tlv_of(&[(2, b"/a/,/b"), (2, b"/,/c/")]);
        assert_eq!(rule.declared_count(&tlv, &[]), 3);
        // Empty params declare none: the rule, not the constant, counts the
        // pool.
        assert!(
            instance_demand(&json!({}), "src", Some(&m), &tlv_of(&[]), &[])
                .unwrap()
                .is_empty()
        );
        // The graph's figure wins.
        let module = json!({"demand": {"store_subs": 9}});
        assert_eq!(
            instance_demand(&module, "src", Some(&m), &tlv, &[]).unwrap(),
            vec![("store_subs", 9)]
        );
        // Without a rule the type's constant stands.
        m.demand_from_params.clear();
        assert_eq!(
            instance_demand(&json!({}), "src", Some(&m), &tlv, &[]).unwrap(),
            vec![("store_subs", 2)]
        );
        // A pool nothing declares demand on is refused, named.
        let e = instance_demand(
            &json!({"demand": {"channels": 1}}),
            "src",
            Some(&m),
            &tlv,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("'channels'") && e.contains("store_subs"), "{e}");
    }

    /// A store provider's manifest with a `heap_per_demand` rule.
    fn per_demand_store(bytes_each: u32, base: Option<u32>) -> Manifest {
        Manifest {
            provides: vec!["storage.namespace".into()],
            heap_per_demand: Some(crate::manifest::HeapPerDemand {
                pool: "store_subs".into(),
                bytes_each,
                base,
            }),
            ..Manifest::default()
        }
    }

    /// `heap_per_demand` adds `bytes_each` × the pool's planned ceiling to
    /// the instance's heap figure — summed with `heap_from_params` — and an
    /// explicit `arena_bytes` below the derived figure is refused, naming
    /// both.
    #[test]
    fn heap_per_demand_is_summed_and_a_smaller_explicit_cap_refused() {
        let plan = HeapPlan {
            ceilings: [("store_subs".to_string(), 100u64)].into(),
            counting: false,
        };
        // Base-only form: base + 64 × 100.
        let m = per_demand_store(64, Some(4096));
        let module = json!({"name": "kv"});
        assert_eq!(
            instance_heap_cap("kv", &module, Some(&m), &tlv_of(&[]), &plan).unwrap(),
            Some(4096 + 6400)
        );
        // While the demand is counted the type's own figure is the
        // placeholder, always emitted so the plan can replace it.
        assert_eq!(
            instance_heap_cap("kv", &module, Some(&m), &tlv_of(&[]), &HeapPlan::counting())
                .unwrap(),
            Some(4096)
        );
        // A plan without a ceiling for the pool adds nothing.
        assert_eq!(
            instance_heap_cap("kv", &module, Some(&m), &tlv_of(&[]), &HeapPlan::default()).unwrap(),
            None
        );
        // Summed with heap_from_params: its derived cap (base 1000 grown by
        // 50 bytes past `included` 10), plus the per-demand bytes.
        let mut m = per_demand_store(64, None);
        m.heap_from_params = Some(crate::manifest::HeapFromParams {
            tags: vec![2],
            base: 1000,
            included: 10,
        });
        let tlv = tlv_of(&[(2, &[b'x'; 60])]);
        assert_eq!(
            instance_heap_cap("kv", &module, Some(&m), &tlv, &plan).unwrap(),
            Some(1050 + 6400)
        );
        // Params within `included`: the rule's base, plus the bytes.
        assert_eq!(
            instance_heap_cap("kv", &module, Some(&m), &tlv_of(&[]), &plan).unwrap(),
            Some(1000 + 6400)
        );
        // An explicit cap at or above the figure wins.
        let big = json!({"name": "kv", "heap": {"arena_bytes": 20000}});
        assert_eq!(
            instance_heap_cap("kv", &big, Some(&m), &tlv, &plan).unwrap(),
            Some(20000)
        );
        // Below it: refused, naming both figures.
        let small = json!({"name": "kv", "heap": {"arena_bytes": 2000}});
        let e = instance_heap_cap("kv", &small, Some(&m), &tlv, &plan)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("arena_bytes = 2000") && e.contains("7450 B") && e.contains("store_subs"),
            "{e}"
        );
    }

    /// `heap_per_param` adds `bytes_each` × the instance's own count param to
    /// the type's figure: the param's value when the graph sets it, its
    /// schema default when not; an explicit `arena_bytes` below the derived
    /// figure is refused, naming it.
    #[test]
    fn heap_per_param_sizes_the_heap_from_the_instances_count() {
        let m = Manifest {
            heap_per_param: Some(crate::manifest::HeapPerParam {
                params: vec![
                    crate::manifest::HeapParamTerm {
                        tag: 3,
                        default: 2,
                        bytes_each: 1000,
                    },
                    crate::manifest::HeapParamTerm {
                        tag: 5,
                        default: 0,
                        bytes_each: 10,
                    },
                ],
                base: Some(4096),
            }),
            ..Manifest::default()
        };
        let module = json!({"name": "tc"});
        let plan = HeapPlan::default();
        // Unset: the default count.
        assert_eq!(
            instance_heap_cap("tc", &module, Some(&m), &tlv_of(&[]), &plan).unwrap(),
            Some(4096 + 2000)
        );
        // Set (a u16 param, little-endian): that count.
        let tlv = tlv_of(&[(3, &512u16.to_le_bytes())]);
        assert_eq!(
            instance_heap_cap("tc", &module, Some(&m), &tlv, &plan).unwrap(),
            Some(4096 + 512_000)
        );
        // Zero units: the type's own cap stands, nothing emitted.
        let none = tlv_of(&[(3, &[0])]);
        assert_eq!(
            instance_heap_cap("tc", &module, Some(&m), &none, &plan).unwrap(),
            None
        );
        // Every counted param adds its own table's bytes.
        let both = tlv_of(&[(3, &512u16.to_le_bytes()), (5, &[7])]);
        assert_eq!(
            instance_heap_cap("tc", &module, Some(&m), &both, &plan).unwrap(),
            Some(4096 + 512_000 + 70)
        );
        // Below the derived figure: refused, naming the count.
        let small = json!({"name": "tc", "heap": {"arena_bytes": 8192}});
        let e = instance_heap_cap("tc", &small, Some(&m), &tlv, &plan)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("arena_bytes = 8192")
                && e.contains("516096 B")
                && e.contains("512 × 1000 B of params tag 3 + 0 × 10 B of params tag 5")
                && e.contains("heap_per_param"),
            "{e}"
        );
    }

    /// The graph is packed once: a `heap_per_demand` instance carries the
    /// counting pass's placeholder cap, and the plan's figure is written over
    /// it in place — in a node-graph entry and in a workload module's params.
    #[test]
    fn the_planned_cap_is_written_over_the_counting_placeholder() {
        let manifests: HashMap<String, Manifest> =
            [("kv".to_string(), per_demand_store(64, Some(4096)))].into();
        let module = json!({"name": "kv", "type": "kv"});
        let entry = build_module_entry(
            "kv",
            &module,
            0,
            None,
            &json!({}),
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &manifests,
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::counting(),
        )
        .expect("entry");
        let cap_of = |tlv: &[u8]| {
            let off = heap_cap_offset(tlv).expect("a heap cap tag");
            u32::from_le_bytes(tlv[off..off + 4].try_into().unwrap())
        };
        assert_eq!(cap_of(&entry.params), 4096, "placeholder");
        let len = entry.params.len();

        let workload_params = insert_heap_tags(
            Vec::new(),
            &module,
            "kv",
            manifests.get("kv"),
            &HeapPlan::counting(),
        )
        .unwrap();
        assert_eq!(cap_of(&workload_params), 4096, "workload placeholder");
        let mut workloads = vec![crate::add_subgraph::Workload {
            graph: crate::add_subgraph::Composition {
                modules: vec![crate::add_subgraph::ComposedModule {
                    params: workload_params,
                    ..Default::default()
                }],
                order: vec![0],
                ..Default::default()
            },
            ..Default::default()
        }];

        let mut entries = vec![entry];
        let heaps: Vec<PlannedHeap> = [ParamsAt::Base(0), ParamsAt::Workload(0, 0)]
            .map(|at| PlannedHeap {
                at,
                name: "kv".into(),
                module: module.clone(),
                manifest: manifests["kv"].clone(),
            })
            .to_vec();
        let plan = HeapPlan {
            ceilings: [("store_subs".to_string(), 100u64)].into(),
            counting: false,
        };
        apply_heap_plan(&plan, &heaps, &mut entries, &mut workloads).unwrap();
        assert_eq!(cap_of(&entries[0].params), 4096 + 6400);
        assert_eq!(entries[0].params.len(), len, "written in place");
        assert_eq!(cap_of(&workloads[0].graph.modules[0].params), 4096 + 6400);

        // A ceiling of nothing keeps the placeholder: the type's own figure.
        let empty = HeapPlan::default();
        let mut entries = vec![entries.remove(0)];
        let off = heap_cap_offset(&entries[0].params).unwrap();
        entries[0].params[off..off + 4].copy_from_slice(&4096u32.to_le_bytes());
        apply_heap_plan(&empty, &heaps[..1], &mut entries, &mut []).unwrap();
        assert_eq!(cap_of(&entries[0].params), 4096);
    }

    /// The plan's ceiling for a `heap_per_demand` pool is the graph's whole
    /// declared demand plus the reserve: the `capacity:` entry, else none,
    /// since a module-served pool has no kernel default.
    #[test]
    fn the_heap_plan_takes_the_full_planned_ceiling() {
        let demand = vec![
            InstanceDemand {
                name: "store".into(),
                figures: vec![],
                heap_per_demand: per_demand_store(64, Some(4096)).heap_per_demand,
            },
            InstanceDemand {
                name: "watch".into(),
                figures: vec![("store_subs", 15)],
                heap_per_demand: None,
            },
        ];
        let plan = heap_plan("linux", &json!({"capacity": {"store_subs": 5}}), &demand);
        assert_eq!(plan.ceilings.get("store_subs"), Some(&20));
        assert_eq!(
            crate::capacity::kernel_pool_default_reserve("linux", "store_subs"),
            None,
            "no kernel row for a module-served pool"
        );
        let plan = heap_plan("linux", &json!({}), &demand);
        assert_eq!(plan.ceilings.get("store_subs"), Some(&15));
        let line = heap_per_demand_report(&plan, &demand, &[]).expect("a figure to print");
        assert!(
            line.contains("store +") && line.contains("heap caps"),
            "{line}"
        );
    }

    /// The subscription demand is the module pool's whoever serves it: the
    /// `DMND` entry the kernel reports `store_subs` against, a keyed
    /// provider or an unkeyed one alike, and no host table takes it.
    #[test]
    fn the_subscription_demand_is_the_module_pools() {
        let mut watch = Manifest::default();
        watch.capacities.insert("store_subscriptions".into(), 4);
        watch.capacities.insert("store_subscribers".into(), 1);
        let manifests: HashMap<String, Manifest> = [
            ("store".to_string(), per_demand_store(64, Some(4096))),
            ("watch".to_string(), watch),
        ]
        .into();
        let names: Vec<String> = ["store", "watch"].map(String::from).to_vec();
        let demand = demand_of(&names, &manifests);
        assert_eq!(
            declared_demand(&demand).unwrap(),
            vec![("store_subs", 0x0100, 4), ("events", 0x0005, 1)]
        );
        assert_eq!(crate::capacity::module_pool_contract("store_subs"), Some("storage.namespace"));
    }

    /// A module's id is its index among the records, which has a full-width
    /// count: the module at index 3000 decodes back as built.
    #[test]
    fn a_module_index_past_ten_bits_round_trips() {
        let module = json!({"name": "m", "type": "m", "domain": "b"});
        let config = json!({"execution": {"domains": [{"name": "a"}, {"name": "b"}]}});
        let entry = build_module_entry(
            "m",
            &module,
            3000,
            None,
            &config,
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &HashMap::new(),
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("entry");
        assert_eq!((entry.id, entry.domain), (3000, 1));
        let mut records = vec![graph::ModuleRecord::default(); 3000];
        records.push(graph::ModuleRecord {
            name_hash: entry.name_hash,
            domain: entry.domain,
            params: &entry.params,
            ..graph::ModuleRecord::default()
        });
        let order: Vec<u16> = (0..records.len() as u16).collect();
        let blob = boot_config::encode(&boot_config::BootConfigSpec {
            graph: graph::GraphSpec {
                order: &order,
                modules: &records,
                ..graph::GraphSpec::default()
            },
            domains: &[boot_config::DomainRecord::default(); 2],
            ..boot_config::BootConfigSpec::default()
        })
        .expect("encodes");
        let cfg = boot_config::decode(&blob).expect("decodes");
        let m = cfg
            .graph()
            .composed()
            .modules()
            .nth(3000)
            .expect("module 3000");
        assert_eq!((m.name_hash, m.domain), (fnv1a_hash(b"m"), 1));
        assert_eq!(m.params, &entry.params[..]);
    }

    /// A module's step deadline, burst deadline and fault policy ride its
    /// record: its params carry none of them.
    #[test]
    fn a_module_s_step_budget_rides_its_record_not_its_params() {
        let module = json!({"name": "m", "type": "m", "step_deadline_us": 1500,
                            "step_deadline_burst_us": 9000, "fault_policy": "tolerate",
                            "max_restarts": 3});
        let entry = build_module_entry(
            "m",
            &module,
            0,
            None,
            &json!({}),
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &HashMap::new(),
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("entry");
        assert_eq!(
            entry.budget,
            crate::add_subgraph::StepBudget {
                deadline_us: 1500,
                burst_us: 9000,
                fault_policy: FaultPolicy::Tolerate,
            }
        );
        // The entries before the end marker, after the TLV header when the
        // module has schema params to head.
        let p = &entry.params;
        let mut tags = Vec::new();
        let mut at = if p.first() == Some(&0xFE) { 4 } else { 0 };
        while at + 2 <= p.len() && p[at] != 0xFF {
            tags.push(p[at]);
            at += 2 + usize::from(p[at + 1]);
        }
        assert!(
            tags.contains(&0xF2),
            "the restart count stays a tag: {tags:x?}"
        );
        for gone in [0xF0, 0xF1, 0xF6] {
            assert!(!tags.contains(&gone), "tag {gone:#x} in {tags:x?}");
        }
        // `restart_graph` names no policy.
        let e = yaml_step_budget(&json!({"fault_policy": "restart_graph"}), "m").unwrap_err();
        assert!(
            e.to_string().contains("'restart_graph' is not a policy"),
            "{e}"
        );
    }

    /// `heap.raw_arena` (or the type's `[capacities] raw_arena`) is params
    /// tag 0xEE, which the kernel reads to commit the arena at instantiation.
    #[test]
    fn raw_arena_use_is_tag_0xee() {
        let module = json!({"name": "kv", "type": "kv", "heap": {"raw_arena": true}});
        let entry = build_module_entry(
            "kv",
            &module,
            0,
            None,
            &json!({}),
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &HashMap::new(),
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("entry");
        assert!(
            entry.params.windows(3).any(|w| w == [0xEE, 1, 1]),
            "tag 0xEE emitted"
        );
        let mut manifests = HashMap::new();
        let mut m = Manifest::default();
        m.capacities.insert("raw_arena".into(), 1);
        manifests.insert("kv".to_string(), m);
        let module = json!({"name": "kv", "type": "kv"});
        let entry = build_module_entry(
            "kv",
            &module,
            0,
            None,
            &json!({}),
            &test_resolver(std::path::Path::new("/nonexistent"), &[]),
            &manifests,
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .expect("entry");
        assert!(
            entry.params.windows(3).any(|w| w == [0xEE, 1, 1]),
            "declared by the type"
        );
    }
}

/// Port-level `requires_capability`: the consumer half of the capability
/// registry, checked against the peer on the actual edge.
#[cfg(test)]
mod port_capability_tests {
    use super::*;
    use crate::manifest::{Manifest, PortSpec};
    use std::collections::{BTreeMap, HashMap};

    /// A module with one named port that requires `wanted` and writes
    /// records of at most `max_record` bytes.
    fn consumer(port: &str, wanted: &str, max_record: u32) -> Manifest {
        Manifest {
            ports: vec![PortSpec {
                name: Some(port.to_string()),
                max_record,
                requires_capability: Some(wanted.to_string()),
                contract: None,
                serves: None,
                contract_optional: false,
                ..port_default()
            }],
            ..Manifest::default()
        }
    }

    /// A provider declaring `caps`, optionally with a `max_payload` fact on
    /// the first of them.
    fn provider(caps: &[&str], max_payload: Option<u32>) -> Manifest {
        let mut facts = BTreeMap::new();
        if let (Some(cap), Some(limit)) = (caps.first(), max_payload) {
            let mut table = BTreeMap::new();
            table.insert("max_payload".to_string(), limit.to_string());
            facts.insert((*cap).to_string(), table);
        }
        Manifest {
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            capability_facts: facts,
            ..Manifest::default()
        }
    }

    /// A `capability_facts` table declaring one payload ceiling.
    fn facts(cap: &str, max_payload: u32) -> BTreeMap<String, BTreeMap<String, String>> {
        let mut inner = BTreeMap::new();
        inner.insert("max_payload".to_string(), max_payload.to_string());
        let mut outer = BTreeMap::new();
        outer.insert(cap.to_string(), inner);
        outer
    }

    fn port_default() -> PortSpec {
        PortSpec {
            direction: 0,
            content_type: 0,
            flags: 0,
            name: None,
            index: 0,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: std::collections::BTreeMap::new(),
            fact_params: std::collections::BTreeMap::new(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    fn edge() -> Value {
        json!({"wiring": [{"from": "pump.request_out", "to": "sink.request_in"}]})
    }

    /// A module whose `provides` lists `surfaces`.
    fn surface_provider(surfaces: &[&str]) -> Manifest {
        Manifest {
            provides: surfaces.iter().map(|s| s.to_string()).collect(),
            ..Manifest::default()
        }
    }

    fn block_graph(edges: &[(&str, &str)]) -> Value {
        let wiring: Vec<Value> = edges
            .iter()
            .map(|(from, to)| json!({"from": from, "to": to}))
            .collect();
        json!({ "wiring": wiring })
    }

    #[test]
    fn a_surface_requirement_is_met_by_a_provider_of_it() {
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), consumer("blocks", "storage.block", 0));
        m.insert("nvme".to_string(), surface_provider(&["storage.block"]));
        let g = block_graph(&[("nvme.blocks", "fat32.blocks")]);
        validate_port_capabilities(&g, &m).unwrap();
    }

    #[test]
    fn a_surface_requirement_refuses_a_module_that_does_not_provide_it() {
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), consumer("blocks", "storage.block", 0));
        m.insert("flash_rp".to_string(), surface_provider(&[]));
        let g = block_graph(&[("flash_rp.stream", "fat32.blocks")]);
        let msg = format!("{:?}", validate_port_capabilities(&g, &m).unwrap_err());
        assert!(
            msg.contains("storage.block") && msg.contains("flash_rp"),
            "got: {msg}"
        );
    }

    /// A block source answers on the one channel wired to its consumer, so a
    /// second source into the same input could never be reached.
    #[test]
    fn a_surface_requirement_takes_exactly_one_source() {
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), consumer("blocks", "storage.block", 0));
        m.insert("nvme".to_string(), surface_provider(&["storage.block"]));
        m.insert("sd".to_string(), surface_provider(&["storage.block"]));
        let g = block_graph(&[
            ("nvme.blocks", "fat32.blocks"),
            ("sd.blocks", "fat32.blocks"),
        ]);
        let msg = format!("{:?}", validate_port_capabilities(&g, &m).unwrap_err());
        assert!(msg.contains("exactly one source"), "got: {msg}");
    }

    /// One block source wired to two consumers is a tee: the stream reaches
    /// both, the requests only one, so the second waits for ever. A vault
    /// beside a filesystem on one disk is the case that bit.
    #[test]
    fn a_block_source_feeding_two_consumers_is_refused() {
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), consumer("blocks", "storage.block", 0));
        m.insert("vault".to_string(), consumer("blocks", "storage.block", 0));
        m.insert("nvme".to_string(), surface_provider(&["storage.block"]));
        let g = block_graph(&[
            ("nvme.blocks", "fat32.blocks"),
            ("nvme.blocks", "vault.blocks"),
        ]);
        let msg = format!("{:?}", validate_port_capabilities(&g, &m).unwrap_err());
        assert!(
            msg.contains("`nvme.blocks` is a `storage.block` source")
                && msg.contains("fat32.blocks")
                && msg.contains("vault.blocks")
                && msg.contains("tee"),
            "got: {msg}"
        );

        // Also when the second edge goes to a port with no requirement: it
        // is still a tee on the source's channel.
        m.insert("tap".to_string(), Manifest::default());
        let g = block_graph(&[("nvme.blocks", "fat32.blocks"), ("nvme.blocks", "tap.in")]);
        let msg = format!("{:?}", validate_port_capabilities(&g, &m).unwrap_err());
        assert!(msg.contains("tee"), "got: {msg}");
    }

    /// Two block consumers, each on its own source, are two independent
    /// edges.
    #[test]
    fn two_block_consumers_each_take_their_own_source() {
        let mut m = HashMap::new();
        m.insert(
            "fat32_a".to_string(),
            consumer("blocks", "storage.block", 0),
        );
        m.insert(
            "fat32_b".to_string(),
            consumer("blocks", "storage.block", 0),
        );
        m.insert("nvme".to_string(), surface_provider(&["storage.block"]));
        m.insert("sd".to_string(), surface_provider(&["storage.block"]));
        let g = block_graph(&[
            ("nvme.blocks", "fat32_a.blocks"),
            ("sd.blocks", "fat32_b.blocks"),
        ]);
        validate_port_capabilities(&g, &m).unwrap();
    }

    #[test]
    fn accepts_a_peer_declaring_the_capability() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("request_out", "stream.publish", 0),
        );
        m.insert("sink".to_string(), provider(&["stream.publish"], None));
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// The whole point: a graph that wires the requiring port to the wrong
    /// module fails, where a module-presence check would have passed it.
    #[test]
    fn rejects_a_peer_without_the_capability() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("request_out", "stream.publish", 0),
        );
        m.insert("sink".to_string(), provider(&["telemetry.sink"], None));
        let e = validate_port_capabilities(&edge(), &m).unwrap_err();
        let msg = format!("{e:?}");
        assert!(msg.contains("stream.publish"), "got: {msg}");
        assert!(msg.contains("sink"), "got: {msg}");
    }

    /// A declared child satisfies a wanted parent, never the reverse.
    #[test]
    fn parent_matches_child_but_not_the_reverse() {
        let mut m = HashMap::new();
        m.insert("pump".to_string(), consumer("request_out", "stream", 0));
        m.insert("sink".to_string(), provider(&["stream.publish"], None));
        validate_port_capabilities(&edge(), &m).unwrap();

        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("request_out", "stream.publish", 0),
        );
        m.insert("sink".to_string(), provider(&["stream"], None));
        validate_port_capabilities(&edge(), &m).unwrap_err();
    }

    /// A producer that declares it sends more than the provider's backend
    /// takes fails the build rather than collecting runtime 413 refusals.
    #[test]
    fn rejects_a_payload_larger_than_the_providers_ceiling() {
        let mut m = HashMap::new();
        let mut pump = consumer("request_out", "stream.publish", 8192);
        pump.capability_facts = facts("stream.publish", 8192);
        m.insert("pump".to_string(), pump);
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(1900)),
        );
        let e = validate_port_capabilities(&edge(), &m).unwrap_err();
        let msg = format!("{e:?}");
        assert!(msg.contains("8192") && msg.contains("1900"), "got: {msg}");
    }

    #[test]
    fn accepts_a_payload_within_the_ceiling() {
        let mut m = HashMap::new();
        let mut pump = consumer("request_out", "stream.publish", 8192);
        pump.capability_facts = facts("stream.publish", 1600);
        m.insert("pump".to_string(), pump);
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(1900)),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// A port's `max_record` is never the quantity compared against a
    /// provider's `max_payload`: `max_record` bounds one whole record — on the
    /// exchange surface the record prefix, the head's fixed fields and the
    /// target — while `max_payload` is the body alone, which a provider may
    /// collect across many records. A pump whose port takes 8192-byte records,
    /// sending 4096-byte payloads into a sink that accepts 4096, is correctly
    /// configured, so confusing the two would fail it.
    #[test]
    fn a_record_sized_port_does_not_fail_against_an_equal_payload_ceiling() {
        let mut m = HashMap::new();
        let mut pump = consumer("request_out", "stream.publish", 8192);
        pump.capability_facts = facts("stream.publish", 4096);
        m.insert("pump".to_string(), pump);
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(4096)),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// A producer whose payload ceiling is per-target, as a module that sizes
    /// its buffers by state arena declares it.
    const PER_TARGET_PUMP: &str = "version = \"0.1.0\"\n\
        hardware_targets = [\"bcm2712\", \"rp2350\", \"rp2040\"]\n\n\
        [[ports]]\nname = \"request_out\"\ndirection = \"output\"\n\
        content_type = \"OctetStream\"\nrequires_capability = \"stream.publish\"\n\n\
        [capability_facts.\"stream.publish\"]\n\
        max_payload = { aarch64 = 8192, thumbv8m = 4096, thumbv6m = 512 }\n";

    /// The composer checks the value for the graph's target: the same pump
    /// fits a 1024-byte backend on thumbv6m and is refused by it on aarch64.
    #[test]
    fn a_per_target_payload_is_checked_for_the_graphs_target() {
        let graph = |silicon: &str| {
            let mut m = HashMap::new();
            m.insert(
                "pump".to_string(),
                Manifest::from_toml_str_for_target(PER_TARGET_PUMP, Some(silicon)).expect("parse"),
            );
            m.insert(
                "sink".to_string(),
                provider(&["stream.publish"], Some(1024)),
            );
            validate_port_capabilities(&edge(), &m)
        };
        graph("thumbv6m").expect("512 fits a 1024-byte ceiling");
        let msg = format!("{:?}", graph("aarch64").unwrap_err());
        assert!(msg.contains("8192") && msg.contains("1024"), "got: {msg}");
        let msg = format!("{:?}", graph("thumbv8m").unwrap_err());
        assert!(msg.contains("4096"), "got: {msg}");
    }

    /// A producer that states no payload fact is unvalidated, not assumed
    /// to fit: the honest position, and the reason declaring it is worth it.
    #[test]
    fn an_undeclared_producer_payload_is_unchecked() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("request_out", "stream.publish", 8192),
        );
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(1900)),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// A pinned store artifact may carry no manifest layer at all. Refusing
    /// to build in that case would break every graph composing a
    /// sibling-owned provider by digest, so the check fails open.
    #[test]
    fn fails_open_on_an_unresolvable_peer_manifest() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("request_out", "stream.publish", 8192),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// An undeclared requirement is unchecked: a port opts in by naming a
    /// capability, and silence is not an implicit `request.http`.
    #[test]
    fn a_port_without_a_requirement_is_unchecked() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            Manifest {
                ports: vec![PortSpec {
                    name: Some("request_out".to_string()),
                    ..port_default()
                }],
                ..Manifest::default()
            },
        );
        m.insert("sink".to_string(), provider(&["telemetry.sink"], None));
        validate_port_capabilities(&edge(), &m).unwrap();
    }
}

/// A param given an asset is one its module declares it opens as one.
#[cfg(test)]
mod asset_param_tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::schema::{ParamSchema, ParamType, SchemaParam};

    fn pic(body: &str) -> Manifest {
        Manifest::from_toml_str_for_target(&format!("version = \"0.1.0\"\n{body}"), None)
            .expect("manifest parses")
    }

    fn schema() -> ParamSchema {
        let p = |tag, name: &str, ptype| SchemaParam {
            tag,
            ptype,
            name: name.to_string(),
            default: 0,
            min: 0,
            max: u32::MAX,
            enums: std::collections::HashMap::new(),
        };
        ParamSchema::from_params(vec![
            p(1, "fonts", ParamType::Str),
            p(2, "document", ParamType::StrChunked),
            p(3, "scale", ParamType::U8),
        ])
    }

    const VIEW: &str = "[[params]]\nname = \"fonts\"\nasset = true\n\n\
                        [[params]]\nname = \"document\"\nasset = true\n";

    #[test]
    fn a_declared_asset_param_is_accepted() {
        let m = pic(VIEW);
        assert_eq!(m.asset_params, ["fonts", "document"]);
        assert!(m.params.is_empty(), "a PIC manifest states no schema");
        let entry = json!({"name": "v", "type": "view", "fonts": "program:0",
                           "document": "asset://page.doc", "asset_params": ["document", "fonts"]});
        check_asset_params(&entry, "v", "view", Some(&m), Some(&schema())).unwrap();
        // Without the built schema the manifest's word stands.
        check_asset_params(&entry, "v", "view", Some(&m), None).unwrap();
        // An entry that names no asset asks nothing.
        check_asset_params(
            &json!({"name": "v", "fonts": "/a/path"}),
            "v",
            "view",
            None,
            None,
        )
        .unwrap();
    }

    /// On every family: the value is a URL, a path or a program reference,
    /// and a module that does not open it as an asset would misread it.
    #[test]
    fn an_asset_in_a_param_not_declared_one_is_refused() {
        let entry = json!({"name": "v", "type": "view", "title": "/p/target/assets/k/page.doc",
                           "asset_params": ["title"]});
        for manifest in [Some(pic(VIEW)), Some(pic("")), None] {
            let e = check_asset_params(&entry, "v", "view", manifest.as_ref(), None)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("module 'v'")
                    && e.contains("`title`")
                    && e.contains("module type 'view'")
                    && e.contains("asset = true"),
                "{e}"
            );
        }
    }

    #[test]
    fn a_declared_asset_param_the_module_does_not_have_as_a_string_is_refused() {
        let m = pic(
            "[[params]]\nname = \"scale\"\nasset = true\n\n[[params]]\nname = \"gone\"\nasset = true\n",
        );
        for param in ["scale", "gone"] {
            let entry = json!({"name": "v", "asset_params": [param]});
            let e = check_asset_params(&entry, "v", "view", Some(&m), Some(&schema()))
                .unwrap_err()
                .to_string();
            assert!(e.contains(param) && e.contains("no string param"), "{e}");
        }
    }

    /// A PIC manifest's `[[params]]` marks asset params and states nothing
    /// else; a native module's schema marks a `str` param.
    #[test]
    fn the_manifest_states_asset_params_in_their_place() {
        let bad = |body: &str| {
            Manifest::from_toml_str_for_target(&format!("version = \"0.1.0\"\n{body}"), None)
                .unwrap_err()
                .to_string()
        };
        assert!(bad("[[params]]\nname = \"fonts\"\n").contains("define_params!"));
        assert!(
            bad("[[params]]\nname = \"fonts\"\nasset = true\ntag = 7\ntype = \"str\"\n")
                .contains("state nothing else")
        );
        let native = "builtin = true\n[[params]]\nname = \"path\"\ntag = 10\ntype = \"str\"\nasset = true\n\n\
                      [[params]]\nname = \"rate\"\ntag = 11\ntype = \"u32\"\ndefault = 1\n";
        let m = pic(native);
        assert_eq!(m.asset_params, ["path"]);
        assert_eq!(m.params.len(), 2);
        assert!(bad(
            "builtin = true\n[[params]]\nname = \"rate\"\ntag = 11\ntype = \"u32\"\nasset = true\n"
        )
        .contains("marks a `str` param"));
        assert!(
            bad("builtin = true\n[[params]]\nname = \"rate\"\ntag = 11\n")
                .contains("missing `type`")
        );
    }
}

/// Modules in a domain a core other than 0 runs: the kernel hands their
/// primary-core ops (flash, the key vault, a change of the graph) to core 0,
/// so the composer places them like any other module.
#[cfg(test)]
mod secondary_core_tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    /// Compose `config` for the Pico 2 W against the built rp2350 modules.
    fn compose(config: &Value) -> Result<Vec<u8>> {
        let root = root();
        let dir = root.join("target/fluxor/thumbv8m/modules");
        let r = crate::module_resolver::ModuleResolver::for_project(
            &root,
            crate::module_resolver::Abi::Module("thumbv8m".into()),
            Some(dir),
        )?;
        generate_config_ext(config, &ConfigBuilder::new(), &[], &r, 0, 0, Some("pico2w"))
    }

    /// The flash driver and a module writing flash, both on core 1: the
    /// driver serves the writer from its own domain, and every erase,
    /// program and BOOTSEL read is core 0's to run.
    #[test]
    fn flash_modules_compose_on_core_1() {
        let config = json!({
            "target": "pico2w",
            "execution": {"domains": [{"name": "main"}, {"name": "compute", "exec": "poll"}]},
            "modules": [
                {"name": "flash_rp", "domain": "compute"},
                {"name": "writer", "type": "core_probe", "domain": "compute",
                 "mode": "flash", "sector": 0x3FA000, "period_ms": 500, "count": 4, "tag": 119},
            ],
            "wiring": [],
        });
        compose(&config).expect("a core-1 domain holding flash composes");
    }
}

/// `[ports.facts]` on encoded ports: parsed against the surface's schema,
/// compared across each edge, and fan-in refused.
#[cfg(test)]
mod port_fact_tests {
    use super::*;
    use crate::manifest::Manifest;
    use std::collections::HashMap;

    fn manifest(ports: &str) -> Manifest {
        Manifest::from_toml_str_for_target(&format!("version = \"0.1.0\"\n\n{ports}"), None)
            .expect("manifest parses")
    }

    fn out_port(facts: &str) -> Manifest {
        manifest(&format!(
            "[[ports]]\nname = \"media_out\"\ndirection = \"output\"\ncontent_type = \"AudioEncoded\"\n\
             [ports.facts]\n{facts}\n"
        ))
    }

    fn in_port(facts: &str) -> Manifest {
        manifest(&format!(
            "[[ports]]\nname = \"media_in\"\ndirection = \"input\"\ncontent_type = \"AudioEncoded\"\n\
             [ports.facts]\n{facts}\n"
        ))
    }

    fn graph(pairs: &[(&str, Manifest)], wiring: Value) -> (Value, HashMap<String, Manifest>) {
        let m = pairs
            .iter()
            .map(|(n, man)| ((*n).to_string(), man.clone()))
            .collect();
        (json!({ "wiring": wiring }), m)
    }

    /// No fact of these graphs is bound to a param.
    fn no_bound_params(_: &Value, _: &str) -> Result<BoundParam> {
        Ok(BoundParam::NoSchema)
    }

    /// A port of content type `ct` named `p`, with `facts`.
    fn port(direction: &str, ct: &str, facts: &str) -> Manifest {
        manifest(&format!(
            "[[ports]]\nname = \"p\"\ndirection = \"{direction}\"\ncontent_type = \"{ct}\"\n\
             [ports.facts]\n{facts}\n"
        ))
    }

    /// One edge `a.p -> b.p` of content type `ct` between ports declaring
    /// `sent` and `taken`.
    fn edge_of(ct: &str, sent: &str, taken: &str) -> Result<()> {
        let (cfg, m) = graph(
            &[
                ("a", port("output", ct, sent)),
                ("b", port("input", ct, taken)),
            ],
            json!([{"from": "a.p", "to": "b.p"}]),
        );
        validate_port_facts(&cfg, &m, &no_bound_params)
    }

    /// A floor: the consumer's refresh must not exceed what the producer
    /// sustains.
    #[test]
    fn a_floor_fact_refuses_a_consumer_above_the_producer() {
        let e = edge_of("VideoDraw", "refresh_mhz = 40000", "refresh_mhz = 45000")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("at least 45000") && e.contains("sustains 40000") && e.contains("a.p"),
            "{e}"
        );
        edge_of("VideoDraw", "refresh_mhz = 60000", "refresh_mhz = 45000").unwrap();
        edge_of("VideoDraw", "refresh_mhz = 45000", "refresh_mhz = 45000").unwrap();
    }

    /// Every ceiling fact: the producer above the consumer is refused, at or
    /// below it accepted.
    #[test]
    fn each_ceiling_fact_refuses_a_producer_above_the_consumer() {
        for (ct, fact) in [
            ("AccessibilityTree", "max_nodes"),
            ("VideoRaster", "width"),
            ("VideoRaster", "height"),
            ("VideoDraw", "max_depth"),
            ("VideoDraw", "max_resources"),
            ("VideoDraw", "resource_bytes"),
            ("VideoDraw", "frame_bytes"),
            ("VideoDraw", "surfaces"),
            ("AudioEncoded", "max_payload"),
        ] {
            let e = edge_of(ct, &format!("{fact} = 2048"), &format!("{fact} = 1024"))
                .expect_err(fact)
                .to_string();
            assert!(
                e.contains("goes up to 2048")
                    && e.contains("at most 1024")
                    && e.contains(fact)
                    && !e.contains(" bytes"),
                "{e}"
            );
            edge_of(ct, &format!("{fact} = 1024"), &format!("{fact} = 2048")).expect(fact);
            edge_of(ct, &format!("{fact} = 1024"), &format!("{fact} = 1024")).expect(fact);
        }
    }

    /// Every numeric fact a port may declare is compared by a rule this
    /// suite exercises: a fact added to the vocabulary without a row here
    /// fails.
    #[test]
    fn every_numeric_fact_rule_has_a_composer_test() {
        use fluxor_contracts::vocabulary::{FactRule, NUMERIC_FACT_RULES};
        const CEILINGS: &[&str] = &[
            "max_nodes",
            "width",
            "height",
            "max_depth",
            "max_resources",
            "resource_bytes",
            "frame_bytes",
            "surfaces",
            "max_payload",
            // Judged by the banding rule on an edge.
            "band_rows",
        ];
        const FLOORS: &[&str] = &["refresh_mhz"];
        for (fact, rule) in NUMERIC_FACT_RULES {
            match rule {
                FactRule::Ceiling => assert!(CEILINGS.contains(fact), "ceiling `{fact}` untested"),
                FactRule::Floor => assert!(FLOORS.contains(fact), "floor `{fact}` untested"),
                FactRule::Exact | FactRule::Subset => {}
            }
        }
    }

    /// The banding rule: a consumer that retains no frame takes only a
    /// banded stream, in bands no taller than its own; one that retains
    /// frames takes any stream. It is judged whether or not the producer
    /// declares `band_rows`.
    #[test]
    fn a_consumer_retaining_no_frame_takes_only_bands_within_its_own() {
        let retains_nothing = "frame_bytes = 0\nband_rows = 16";
        // Unbanded producers: undeclared, and declared 0.
        for sent in ["max_depth = 4", "band_rows = 0", "frame_bytes = 4096"] {
            let e = edge_of("VideoDraw", sent, retains_nothing)
                .expect_err(sent)
                .to_string();
            assert!(
                e.contains("retains no frame") && e.contains("band_rows") && e.contains("a.p"),
                "{e}"
            );
        }
        // Bands taller than the consumer's.
        let e = edge_of("VideoDraw", "band_rows = 32", retains_nothing)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("producer declares 32") && e.contains("consumer declares 16"),
            "{e}"
        );
        // Bands within it; the producer's frame size is not held to a
        // consumer that retains none.
        edge_of(
            "VideoDraw",
            "band_rows = 16\nframe_bytes = 4096",
            retains_nothing,
        )
        .unwrap();
        edge_of("VideoDraw", "band_rows = 8", retains_nothing).unwrap();
        // A consumer that retains nothing and states no band height takes
        // any banded stream.
        edge_of("VideoDraw", "band_rows = 64", "frame_bytes = 0").unwrap();
        // A consumer that retains frames bands for itself: any stream, and
        // its own `band_rows` is no ceiling on the producer's.
        edge_of(
            "VideoDraw",
            "band_rows = 64",
            "frame_bytes = 8192\nband_rows = 16",
        )
        .unwrap();
        edge_of(
            "VideoDraw",
            "max_depth = 4",
            "frame_bytes = 8192\nband_rows = 16",
        )
        .unwrap();
        edge_of("VideoDraw", "band_rows = 64", "band_rows = 16").unwrap();
    }

    /// The fan-in refusal names the input as a record stream, whatever its
    /// content type.
    #[test]
    fn fan_in_onto_any_record_stream_input_is_refused() {
        for ct in [
            "VideoDraw",
            "VideoRaster",
            "TextEvents",
            "AccessibilityTree",
        ] {
            let (cfg, m) = graph(
                &[
                    (
                        "a",
                        manifest(&format!(
                            "[[ports]]\nname = \"p\"\ndirection = \"output\"\ncontent_type = \"{ct}\"\n"
                        )),
                    ),
                    (
                        "b",
                        manifest(&format!(
                            "[[ports]]\nname = \"p\"\ndirection = \"output\"\ncontent_type = \"{ct}\"\n"
                        )),
                    ),
                    (
                        "rx",
                        manifest(&format!(
                            "[[ports]]\nname = \"p\"\ndirection = \"input\"\ncontent_type = \"{ct}\"\n"
                        )),
                    ),
                ],
                json!([{"from": "a.p", "to": "rx.p"}, {"from": "b.p", "to": "rx.p"}]),
            );
            let e = validate_port_facts(&cfg, &m, &no_bound_params)
                .expect_err(ct)
                .to_string();
            assert!(
                e.contains("record-stream input")
                    && e.contains("2 producers")
                    && !e.contains("encoded"),
                "{e}"
            );
        }
    }

    /// A fact bound to a param takes each instance's value: the graph's, or
    /// the schema default.
    #[test]
    fn a_param_bound_fact_is_read_per_instance() {
        use crate::schema::{ParamSchema, ParamType, SchemaParam};
        let panel = port(
            "input",
            "VideoDraw",
            "refresh_mhz = { param = \"refresh_mhz\" }",
        );
        assert_eq!(
            panel.ports[0]
                .fact_params
                .get("refresh_mhz")
                .map(String::as_str),
            Some("refresh_mhz")
        );
        assert!(!panel.ports[0].facts.contains_key("refresh_mhz"));
        let schema = ParamSchema::from_params(vec![
            SchemaParam {
                tag: 1,
                ptype: ParamType::U32,
                name: "refresh_mhz".to_string(),
                default: 40000,
                min: 0,
                max: u32::MAX,
                enums: HashMap::new(),
            },
            SchemaParam {
                tag: 2,
                ptype: ParamType::Str,
                name: "label".to_string(),
                default: 0,
                min: 0,
                max: u32::MAX,
                enums: HashMap::new(),
            },
        ]);
        let param_of = |entry: &Value, param: &str| -> Result<BoundParam> {
            Ok(bound_param_in(entry, &schema, param))
        };
        let run = |modules: Value| {
            let m: HashMap<String, Manifest> = [
                ("src", port("output", "VideoDraw", "refresh_mhz = 45000")),
                ("slow", panel.clone()),
                ("fast", panel.clone()),
            ]
            .into_iter()
            .map(|(n, man)| (n.to_string(), man))
            .collect();
            let cfg = json!({
                "modules": modules,
                "wiring": [{"from": "src.p", "to": "slow.p"}],
            });
            let slow = validate_port_facts(&cfg, &m, &param_of);
            let cfg = json!({
                "modules": cfg["modules"],
                "wiring": [{"from": "src.p", "to": "fast.p"}],
            });
            (slow, validate_port_facts(&cfg, &m, &param_of))
        };
        // `slow` runs at its default (40 Hz, within the producer's 45);
        // `fast` is set to 60 Hz, past it.
        let (slow, fast) = run(json!([
            {"name": "src"},
            {"name": "slow", "type": "panel"},
            {"name": "fast", "type": "panel", "refresh_mhz": 60000},
        ]));
        slow.unwrap();
        let e = fast.unwrap_err().to_string();
        assert!(e.contains("at least 60000") && e.contains("fast.p"), "{e}");
        // Set under `params:`, the same.
        let (slow, fast) = run(json!([
            {"name": "slow", "params": {"refresh_mhz": 50000}},
            {"name": "fast", "params": {"refresh_mhz": 45000}},
        ]));
        assert!(slow.unwrap_err().to_string().contains("at least 50000"));
        fast.unwrap();

        // A binding to a param the module does not declare as an integer.
        for bad in ["label", "absent"] {
            let m: HashMap<String, Manifest> = [
                ("src", port("output", "VideoDraw", "refresh_mhz = 45000")),
                (
                    "sink",
                    port(
                        "input",
                        "VideoDraw",
                        &format!("refresh_mhz = {{ param = \"{bad}\" }}"),
                    ),
                ),
            ]
            .into_iter()
            .map(|(n, man)| (n.to_string(), man))
            .collect();
            let cfg = json!({
                "modules": [{"name": "sink"}],
                "wiring": [{"from": "src.p", "to": "sink.p"}],
            });
            let e = validate_port_facts(&cfg, &m, &param_of)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains(bad) && e.contains("integer param") && e.contains("sink.p"),
                "{e}"
            );
        }
        // A module whose schema is not at hand leaves the fact undeclared.
        let m: HashMap<String, Manifest> = [
            ("src", port("output", "VideoDraw", "refresh_mhz = 1")),
            ("sink", panel.clone()),
        ]
        .into_iter()
        .map(|(n, man)| (n.to_string(), man))
        .collect();
        let cfg = json!({"wiring": [{"from": "src.p", "to": "sink.p"}]});
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
    }

    /// A capability fact bound to a param takes each instance's value, the
    /// same way a port fact does: `interval_ms: 1000` on the entry is the
    /// instance's `sensor.sample` `period_ms`, and an instance that leaves
    /// it unset states the schema default.
    #[test]
    fn a_param_bound_capability_fact_is_read_per_instance() {
        use crate::schema::{ParamSchema, ParamType, SchemaParam};
        let sensor = manifest(
            "capabilities = [\"sensor.sample\"]\n\n\
             [capability_facts.\"sensor.sample\"]\nquantity = \"temperature\"\n\
             period_ms = { param = \"interval_ms\" }\nmax_payload = 24\n",
        );
        let schema = ParamSchema::from_params(vec![SchemaParam {
            tag: 1,
            ptype: ParamType::U32,
            name: "interval_ms".to_string(),
            default: 5000,
            min: 0,
            max: u32::MAX,
            enums: HashMap::new(),
        }]);
        let param_of = |entry: &Value, param: &str| -> Result<BoundParam> {
            Ok(bound_param_in(entry, &schema, param))
        };
        let modules = vec![
            json!({"name": "fast", "type": "temp_sensor", "interval_ms": 1000}),
            json!({"name": "set", "type": "temp_sensor", "params": {"interval_ms": 250}}),
            json!({"name": "idle", "type": "temp_sensor"}),
        ];
        let mut m: HashMap<String, Manifest> = ["fast", "set", "idle"]
            .into_iter()
            .map(|n| (n.to_string(), sensor.clone()))
            .collect();
        bind_capability_facts(&modules, &mut m, &param_of).unwrap();
        for (name, want) in [("fast", "1000"), ("set", "250"), ("idle", "5000")] {
            let facts = &m[name].capability_facts["sensor.sample"];
            assert_eq!(facts["period_ms"], want, "{name}");
            assert_eq!(facts["max_payload"], "24", "{name}");
        }

        // A binding to a param the schema does not hold as an integer is
        // refused per instance.
        let mut m: HashMap<String, Manifest> = [("fast".to_string(), sensor.clone())].into();
        let none = |_: &Value, _: &str| -> Result<BoundParam> { Ok(BoundParam::NotAnInteger) };
        let e = bind_capability_facts(&modules, &mut m, &none)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("fact `period_ms` is bound to param `interval_ms`"),
            "{e}"
        );
    }

    /// Only a numeric fact binds to a param, and the table names the param
    /// and nothing else.
    #[test]
    fn a_fact_binding_is_checked_at_parse() {
        let bad = |facts: &str, ct: &str| {
            Manifest::from_toml_str_for_target(
                &format!(
                    "version = \"0.1.0\"\n\n[[ports]]\nname = \"p\"\ndirection = \"input\"\n\
                     content_type = \"{ct}\"\n[ports.facts]\n{facts}\n"
                ),
                None,
            )
            .unwrap_err()
            .to_string()
        };
        assert!(bad("refresh_mhz = { param = 3 }", "VideoDraw").contains("{ param ="));
        assert!(bad("refresh_mhz = { param = \"\" }", "VideoDraw").contains("{ param ="));
        assert!(
            bad("refresh_mhz = { param = \"a\", scale = 2 }", "VideoDraw").contains("{ param =")
        );
        assert!(bad("ops = { param = \"a\" }", "VideoDraw").contains("string"));
        // Every numeric port fact binds the same way.
        let m = port("output", "VideoRaster", "width = { param = \"w\" }");
        assert_eq!(
            m.ports[0].fact_params.get("width").map(String::as_str),
            Some("w")
        );
    }

    #[test]
    fn a_producer_whose_codecs_the_consumer_takes_is_accepted() {
        let (cfg, m) = graph(
            &[
                ("enc", out_port("codec = \"pcmu\"")),
                ("tx", in_port("codec = [\"pcmu\", \"opus\"]")),
            ],
            json!([{"from": "enc.media_out", "to": "tx.media_in"}]),
        );
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
    }

    /// Subset, not intersection: a demuxer that MAY emit MP3 must not bind an
    /// AAC-only decoder just because they share AAC.
    #[test]
    fn a_producer_that_may_send_an_untaken_codec_is_refused() {
        let (cfg, m) = graph(
            &[
                ("demux", out_port("codec = [\"aac\", \"mp3\"]")),
                ("dec", in_port("codec = \"aac\"")),
            ],
            json!([{"from": "demux.media_out", "to": "dec.media_in"}]),
        );
        let e = validate_port_facts(&cfg, &m, &no_bound_params)
            .unwrap_err()
            .to_string();
        assert!(e.contains("mp3") && e.contains("demux.media_out"), "{e}");
    }

    #[test]
    fn exact_and_ceiling_facts_are_compared() {
        let (cfg, m) = graph(
            &[
                ("a", out_port("clock_rate = 8000")),
                ("b", in_port("clock_rate = 48000")),
            ],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        assert!(validate_port_facts(&cfg, &m, &no_bound_params).is_err());
        let (cfg, m) = graph(
            &[
                ("a", out_port("max_payload = 2048")),
                ("b", in_port("max_payload = 1200")),
            ],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        assert!(validate_port_facts(&cfg, &m, &no_bound_params).is_err());
        let (cfg, m) = graph(
            &[
                ("a", out_port("max_payload = 1000")),
                ("b", in_port("max_payload = 1200")),
            ],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
    }

    #[test]
    fn a_fact_one_end_leaves_undeclared_is_unconstrained() {
        let (cfg, m) = graph(
            &[
                ("a", out_port("codec = \"opus\"")),
                ("b", in_port("channels = 2")),
            ],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
    }

    #[test]
    fn fan_in_onto_an_encoded_input_is_refused() {
        let (cfg, m) = graph(
            &[
                ("a", out_port("codec = \"pcmu\"")),
                ("b", out_port("codec = \"pcmu\"")),
                ("rx", in_port("codec = \"pcmu\"")),
            ],
            json!([{"from": "a.media_out", "to": "rx.media_in"}, {"from": "b.media_out", "to": "rx.media_in"}]),
        );
        let e = validate_port_facts(&cfg, &m, &no_bound_params)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("rx.media_in") && e.contains("2 producers"),
            "{e}"
        );
    }

    #[test]
    fn port_facts_are_checked_at_parse() {
        let bad = |facts: &str, ct: &str| {
            Manifest::from_toml_str_for_target(
                &format!(
                    "version = \"0.1.0\"\n\n[[ports]]\nname = \"p\"\ndirection = \"input\"\n\
                     content_type = \"{ct}\"\n[ports.facts]\n{facts}\n"
                ),
                None,
            )
            .unwrap_err()
            .to_string()
        };
        assert!(bad("codec = \"h264\"", "AudioEncoded").contains("not admitted"));
        assert!(bad("packing = \"annexb\"", "AudioEncoded").contains("not admitted"));
        assert!(bad("codec = []", "AudioEncoded").contains("empty set"));
        assert!(bad("codec = [\"aac\", \"aac\"]", "AudioEncoded").contains("twice"));
        assert!(bad("clock_rate = \"8000\"", "AudioEncoded").contains("integer"));
        assert!(bad("codc = \"aac\"", "AudioEncoded").contains("Did you mean `codec`"));
        assert!(bad("channels = 2", "VideoEncoded").contains("unknown fact"));
        assert!(bad("codec = \"aac\"", "OctetStream").contains("port-scoped"));
    }

    /// Stream facts live on the port; the module-level table refuses them.
    #[test]
    fn module_level_encoded_facts_are_refused() {
        let e = Manifest::from_toml_str_for_target(
            "version = \"0.1.0\"\ncapabilities = [\"audio.encoded\"]\n\n\
             [capability_facts.\"audio.encoded\"]\ncodec = \"aac\"\n",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("[ports.facts]"), "{e}");
    }

    fn exchange_port(name: &str, direction: &str, facts: &str) -> Manifest {
        let table = if facts.is_empty() {
            String::new()
        } else {
            format!("[ports.facts]\n{facts}\n")
        };
        manifest(&format!(
            "[[ports]]\nname = \"{name}\"\ndirection = \"{direction}\"\n\
             content_type = \"ExchangeRequest\"\n{table}"
        ))
    }

    /// The exchange `binding` fact: a requester sending a binding's verbs
    /// binds only a provider that declares the binding, and undeclared on
    /// the provider is none, not unconstrained.
    #[test]
    fn an_exchange_requester_needs_a_provider_speaking_its_binding() {
        let edge = json!([{"from": "req.request_out", "to": "prov.request_in"}]);
        let speaks = || exchange_port("request_in", "input", "binding = [\"http\"]");
        let (cfg, m) = graph(
            &[
                (
                    "req",
                    exchange_port("request_out", "output", "binding = \"http\""),
                ),
                ("prov", speaks()),
            ],
            edge.clone(),
        );
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();

        let (cfg, m) = graph(
            &[
                (
                    "req",
                    exchange_port("request_out", "output", "binding = \"http\""),
                ),
                ("prov", exchange_port("request_in", "input", "")),
            ],
            edge.clone(),
        );
        let e = validate_port_facts(&cfg, &m, &no_bound_params)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("http") && e.contains("req.request_out") && e.contains("binding"),
            "{e}"
        );

        // A requester that sends verb 0 binds any provider.
        for prov in [speaks(), exchange_port("request_in", "input", "")] {
            let (cfg, m) = graph(
                &[
                    ("req", exchange_port("request_out", "output", "")),
                    ("prov", prov),
                ],
                edge.clone(),
            );
            validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
        }
    }

    /// Exchange requests are whole records: several requesters may share a
    /// provider's input, unlike an encoded stream.
    #[test]
    fn exchange_requesters_may_fan_into_one_provider() {
        let (cfg, m) = graph(
            &[
                (
                    "a",
                    exchange_port("request_out", "output", "binding = \"http\""),
                ),
                ("b", exchange_port("request_out", "output", "")),
                (
                    "prov",
                    exchange_port("request_in", "input", "binding = \"http\""),
                ),
            ],
            json!([
                {"from": "a.request_out", "to": "prov.request_in"},
                {"from": "b.request_out", "to": "prov.request_in"}
            ]),
        );
        validate_port_facts(&cfg, &m, &no_bound_params).unwrap();
    }

    #[test]
    fn exchange_binding_facts_are_checked_at_parse() {
        let e = Manifest::from_toml_str_for_target(
            "version = \"0.1.0\"\n\n[[ports]]\nname = \"p\"\ndirection = \"input\"\n\
             content_type = \"ExchangeRequest\"\n[ports.facts]\nbinding = \"grpc\"\n",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not admitted"), "{e}");
        let e = Manifest::from_toml_str_for_target(
            "version = \"0.1.0\"\n\n[[ports]]\nname = \"p\"\ndirection = \"output\"\n\
             content_type = \"ExchangeResponse\"\n[ports.facts]\nbinding = \"http\"\n",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("port-scoped"), "{e}");
    }

    /// A pipeline-shaped manifest whose `max_payload` fact is written `fact`.
    fn per_target_fact_manifest(fact: &str) -> String {
        format!(
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\", \"rp2350\", \"rp2040\"]\n\
             capabilities = [\"stream.ordered_ack.sink\"]\n\n\
             [capability_facts.\"stream.ordered_ack.sink\"]\nack = \"transport\"\n{fact}\n"
        )
    }

    fn resolved_fact(src: &str, silicon: Option<&str>) -> std::result::Result<String, String> {
        Manifest::from_toml_str_for_target(src, silicon)
            .map(|m| m.capability_facts["stream.ordered_ack.sink"]["max_payload"].clone())
            .map_err(|e| e.to_string())
    }

    /// Each target resolves its own entry; a flat fact beside it is untouched.
    #[test]
    fn a_per_target_fact_resolves_for_each_target() {
        let src = per_target_fact_manifest(
            "max_payload = { aarch64 = 8192, thumbv8m = 4096, thumbv6m = 512 }",
        );
        for (silicon, want) in [
            ("aarch64", "8192"),
            ("thumbv8m", "4096"),
            ("thumbv6m", "512"),
        ] {
            assert_eq!(
                resolved_fact(&src, Some(silicon)).unwrap(),
                want,
                "{silicon}"
            );
        }
        let m = Manifest::from_toml_str_for_target(&src, Some("thumbv6m")).unwrap();
        assert_eq!(
            m.capability_facts["stream.ordered_ack.sink"]["ack"],
            "transport"
        );
    }

    /// An explicit `default` answers for every target the table does not
    /// name, including a load for no target.
    #[test]
    fn a_per_target_fact_takes_its_explicit_default() {
        let src = per_target_fact_manifest("max_payload = { default = 8192, thumbv6m = 512 }");
        assert_eq!(resolved_fact(&src, Some("thumbv6m")).unwrap(), "512");
        assert_eq!(resolved_fact(&src, Some("thumbv8m")).unwrap(), "8192");
        assert_eq!(resolved_fact(&src, Some("aarch64")).unwrap(), "8192");
        assert_eq!(resolved_fact(&src, None).unwrap(), "8192");
    }

    /// Plain integer and string facts keep their meaning.
    #[test]
    fn flat_facts_stay_valid() {
        let src = per_target_fact_manifest("max_payload = 8192");
        assert_eq!(resolved_fact(&src, Some("thumbv6m")).unwrap(), "8192");
        let src = per_target_fact_manifest("max_payload = \"8192\"");
        assert_eq!(resolved_fact(&src, None).unwrap(), "8192");
    }

    /// Malformed and partial per-target tables are refused, whichever target
    /// is loaded, and never resolve to some other entry.
    #[test]
    fn a_malformed_per_target_fact_is_refused() {
        let refused = |fact: &str, silicon: Option<&str>| {
            resolved_fact(&per_target_fact_manifest(fact), silicon).unwrap_err()
        };
        // Partial: thumbv6m is a hardware target with no entry and no default,
        // refused even when loading for a target the table does name.
        let e = refused(
            "max_payload = { aarch64 = 8192, thumbv8m = 4096 }",
            Some("aarch64"),
        );
        assert!(
            e.contains("no value for thumbv6m") && e.contains("no `default`"),
            "{e}"
        );
        // Complete for the module's targets, but a load for no target has
        // nothing to resolve.
        let e = refused(
            "max_payload = { aarch64 = 8192, thumbv8m = 4096, thumbv6m = 512 }",
            None,
        );
        assert!(e.contains("no entry for target \"<none>\""), "{e}");
        let e = refused("max_payload = {}", Some("thumbv6m"));
        assert!(e.contains("empty table"), "{e}");
        let e = refused(
            "max_payload = { default = 8192, rp2O40 = 512 }",
            Some("thumbv6m"),
        );
        assert!(e.contains("unknown target `rp2O40`"), "{e}");
        // Every entry is schema-checked, not only the resolved one.
        let e = refused(
            "max_payload = { default = 8192, thumbv6m = \"small\" }",
            Some("aarch64"),
        );
        assert!(e.contains("takes a u32, got `small`"), "{e}");
        let e = refused(
            "max_payload = { default = 8192, thumbv6m = -1 }",
            Some("aarch64"),
        );
        assert!(e.contains("negative"), "{e}");
        let e = refused(
            "max_payload = { default = 8192, thumbv6m = true }",
            Some("aarch64"),
        );
        assert!(e.contains("must be a string, an integer"), "{e}");
        let e = refused(
            "max_payload = { default = { thumbv6m = 512 } }",
            Some("thumbv6m"),
        );
        assert!(e.contains("got a table"), "{e}");
        let e = refused("max_payload = [512, 4096]", Some("thumbv6m"));
        assert!(e.contains("got a array"), "{e}");
    }

    /// A mistyped port key is an error, not a silently ignored table.
    #[test]
    fn unknown_port_keys_are_refused() {
        let e = Manifest::from_toml_str_for_target(
            "version = \"0.1.0\"\n\n[[ports]]\ndirection = \"input\"\n\
             content_type = \"AudioEncoded\"\n[ports.stream]\ncodec = \"aac\"\n",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("stream"), "{e}");
    }
}

#[cfg(test)]
mod gated_edge_tests {
    use super::*;

    fn names() -> Vec<String> {
        ["src", "mid", "sink"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// An auto-assigned group touching a gated module is dropped whole, so
    /// the kernel never sees a zero-copy edge at one.
    #[test]
    fn an_auto_group_at_a_gated_module_is_dropped_whole() {
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8), (1, 2, 0, 0, 0)];
        let mut groups = vec![1u8, 1];
        ungroup_gated_edges(
            &edges,
            &mut groups,
            &[false, false],
            &[true, false, false],
            &names(),
        )
        .expect("an auto group is dropped, not refused");
        assert_eq!(
            groups,
            vec![0, 0],
            "the edge beyond the gated module leaves the group too"
        );
    }

    #[test]
    fn a_written_group_at_a_gated_module_is_refused() {
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8)];
        let mut groups = vec![3u8];
        let e = ungroup_gated_edges(
            &edges,
            &mut groups,
            &[true],
            &[false, true, false],
            &names(),
        )
        .expect_err("a written zero-copy edge at a gated module");
        assert!(e.to_string().contains("'mid'"), "names the module: {e}");
    }

    #[test]
    fn groups_away_from_gated_modules_are_kept() {
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8), (1, 2, 0, 0, 0)];
        let mut groups = vec![2u8, 2];
        ungroup_gated_edges(
            &edges,
            &mut groups,
            &[false, true],
            &[false, false, false],
            &names(),
        )
        .unwrap();
        assert_eq!(groups, vec![2, 2]);
    }
}

#[cfg(test)]
mod framed_edge_tests {
    use super::*;
    use crate::manifest::{Manifest, PortSpec};
    use serde_json::json;

    fn content_type(name: &str) -> u8 {
        fluxor_contracts::CONTENT_TYPES
            .iter()
            .position(|t| *t == name)
            .expect("a content type the table names") as u8
    }

    fn port(direction: u8, index: u8, ty: &str, flags: u8) -> PortSpec {
        PortSpec {
            direction,
            content_type: content_type(ty),
            flags,
            name: None,
            index,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: std::collections::BTreeMap::new(),
            fact_params: std::collections::BTreeMap::new(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    /// A requester with an exchange pair and a byte stream out, and a
    /// provider with the matching inputs.
    fn manifests() -> HashMap<String, Manifest> {
        let mut m = HashMap::new();
        m.insert(
            "req".to_string(),
            Manifest {
                ports: vec![
                    port(1, 0, "ExchangeRequest", 0),
                    port(1, 1, "OctetStream", 0),
                    port(1, 2, "OctetStream", 0x02),
                ],
                ..Manifest::default()
            },
        );
        m.insert(
            "prov".to_string(),
            Manifest {
                ports: vec![
                    port(0, 0, "ExchangeRequest", 0),
                    port(0, 1, "OctetStream", 0),
                    port(0, 2, "OctetStream", 0),
                ],
                ..Manifest::default()
            },
        );
        m
    }

    fn names() -> Vec<String> {
        vec!["req".to_string(), "prov".to_string()]
    }

    fn groups(config: &Value) -> Vec<Option<u64>> {
        config["wiring"]
            .as_array()
            .expect("wiring")
            .iter()
            .map(|e| e.get("buffer_group").and_then(|v| v.as_u64()))
            .collect()
    }

    /// A framed edge the wiring leaves ungrouped gets a mailbox group of its
    /// own; a byte-stream edge stays a FIFO.
    #[test]
    fn a_framed_edge_without_a_group_is_given_one() {
        let config = json!({"wiring": [
            {"from": "req.request_out", "to": "prov.request_in"},
            {"from": "req.bytes", "to": "prov.bytes"},
        ]});
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8), (0, 1, 0, 1, 1)];
        let out = group_framed_edges(&config, &edges, &names(), &manifests()).unwrap();
        assert_eq!(groups(&out), vec![Some(31), None]);
    }

    /// A port declaring `framed = true` over a streamed type is a framed edge
    /// too, and every framed edge gets a group nobody else holds.
    #[test]
    fn each_framed_edge_gets_a_distinct_group_clear_of_written_ones() {
        let config = json!({"wiring": [
            {"from": "req.request_out", "to": "prov.request_in"},
            {"from": "req.records", "to": "prov.records"},
            {"from": "req.bytes", "to": "prov.bytes", "buffer_group": 30},
        ]});
        let edges = [
            (0u16, 1u16, 0u8, 0u8, 0u8),
            (0, 1, 0, 2, 2),
            (0, 1, 0, 1, 1),
        ];
        let out = group_framed_edges(&config, &edges, &names(), &manifests()).unwrap();
        assert_eq!(groups(&out), vec![Some(31), Some(29), Some(30)]);
    }

    /// A group the wiring names is kept as written.
    #[test]
    fn a_written_group_on_a_framed_edge_is_kept() {
        let config = json!({"wiring": [
            {"from": "req.request_out", "to": "prov.request_in", "buffer_group": 4},
        ]});
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8)];
        let out = group_framed_edges(&config, &edges, &names(), &manifests()).unwrap();
        assert_eq!(groups(&out), vec![Some(4)]);
    }
}

#[cfg(test)]
mod config_decode_tests {
    use crate::config::decode_config;
    use fluxor_contracts::boot_config::{
        encode, BootConfigSpec, DomainRecord, ExecMode, PoolEntry, WorkloadRecord,
    };
    use fluxor_contracts::graph::{
        EdgeClass, EdgeRecord, Endpoint, FaultPolicy, GraphSpec, ModuleRecord,
    };

    /// A blob as `generate_config_impl` writes one: two modules, two edges,
    /// a stepping order, one domain, an RP hardware payload with two GPIO
    /// entries and a UART, a resident workload, an envelope and a demand
    /// entry.
    fn blob() -> Vec<u8> {
        let params = [0xAAu8; 3];
        let modules = [
            ModuleRecord {
                name_hash: 0x1111_1111,
                domain: 0,
                pre_pass: false,
                step_deadline_us: 1500,
                burst_us: 9000,
                fault_policy: FaultPolicy::Tolerate,
                params: &params,
            },
            ModuleRecord {
                name_hash: 0x2222_2222,
                domain: 1,
                pre_pass: true,
                params: &[],
                ..ModuleRecord::default()
            },
        ];
        let edges = [
            EdgeRecord {
                from: Endpoint::New(0),
                to: Endpoint::New(1),
                from_port: 2,
                to_port: 1,
                to_ctrl: true,
                class: EdgeClass::DmaOwned,
                buffer_group: 3,
                rate_class: 4,
                wake_on_write: true,
                retains_send: false,
                buffer_bytes: 1024,
            },
            EdgeRecord {
                from: Endpoint::New(1),
                to: Endpoint::New(0),
                ..EdgeRecord::default()
            },
        ];
        let domains = [DomainRecord {
            tick_us: 1000,
            tick_min_us: 250,
            tick_max_us: 8000,
            exec_mode: ExecMode::Tick,
            adaptive_flags: 3,
        }];
        // Hardware header: spi, i2c, gpio, pio, reserved, uart.
        let mut hw = vec![0, 0, 2, 0, 0, 1];
        hw.extend_from_slice(&[0u8; 2 * 5 + 8]);
        encode(&BootConfigSpec {
            tick_us: 1000,
            graph_sample_rate: 48_000,
            graph: GraphSpec {
                order: &[1, 0],
                modules: &modules,
                edges: &edges,
                ..GraphSpec::default()
            },
            domains: &domains,
            hardware: Some(&hw),
            workloads: Some(&[WorkloadRecord {
                idle_safe: true,
                endpoints: &[],
                blob: &[1, 2, 3, 4],
            }]),
            envelope: Some(&[PoolEntry { pool: 5, n: 40 }]),
            demand: Some(&[PoolEntry { pool: 10, n: 3 }]),
        })
        .expect("encodes")
    }

    /// Every field a built blob carries comes back where the encoder put it.
    #[test]
    fn a_built_blob_decodes_field_for_field() {
        let b = blob();
        let v = decode_config(&b).expect("decodes");
        assert_eq!(v["total_len"], b.len());
        assert_eq!(v["tick_us"], 1000);
        assert_eq!(v["graph_sample_rate"], 48_000);
        assert_eq!(v["modules"].as_array().unwrap().len(), 2);
        assert_eq!(v["modules"][0]["name_hash"], "0x11111111");
        assert_eq!(v["modules"][0]["param_bytes"], 3);
        assert_eq!(v["modules"][0]["step_deadline_us"], 1500);
        assert_eq!(v["modules"][0]["step_deadline_burst_us"], 9000);
        assert_eq!(v["modules"][0]["fault_policy"], "tolerate");
        assert_eq!(v["modules"][1]["id"], 1);
        assert_eq!(v["modules"][1]["domain_id"], 1);
        assert_eq!(v["modules"][1]["pre_pass"], true);
        assert_eq!(v["order"], serde_json::json!([1, 0]));
        let e = &v["graph"][0];
        assert_eq!((e["from"].clone(), e["to"].clone()), (0.into(), 1.into()));
        assert_eq!(e["to_port"], "ctrl");
        assert_eq!(e["edge_class"], "dma_owned");
        assert_eq!(e["buffer_group"], 3);
        assert_eq!(
            (e["from_port_index"].clone(), e["to_port_index"].clone()),
            (2.into(), 1.into())
        );
        assert_eq!(e["buffer_bytes"], 1024);
        assert_eq!(e["rate"], "transaction");
        assert_eq!(e["wake"], true);
        assert_eq!(v["graph"].as_array().unwrap().len(), 2);
        assert_eq!(v["domains"].as_array().unwrap().len(), 1);
        assert_eq!(v["domains"][0]["tick_us"], 1000);
        assert_eq!(v["domains"][0]["tick_min_us"], 250);
        assert_eq!(v["domains"][0]["tick_max_us"], 8000);
        assert_eq!(v["domains"][0]["exec"], "tick");
        assert_eq!(v["hardware"]["gpio"], 2);
        assert_eq!(v["hardware"]["uart"], 1);
        assert_eq!(v["workloads"][0]["idle_safe"], true);
        assert_eq!(v["workloads"][0]["blob_bytes"], 4);
        assert_eq!(v["envelope"][0]["pool"], 5);
        assert_eq!(v["envelope"][0]["n"], 40);
        assert_eq!(v["demand"][0]["n"], 3);
    }

    /// Every prefix of a blob is refused with an error, never a panic.
    #[test]
    fn every_truncation_is_an_error() {
        let full = blob();
        for len in 0..full.len() {
            assert!(
                decode_config(&full[..len]).is_err(),
                "prefix of {len} bytes"
            );
        }
    }

    /// A wrong magic, a flipped byte under the checksum and a module record
    /// whose length leaves its section are refused, naming what the codec
    /// found.
    #[test]
    fn foreign_magics_corruption_and_entry_lengths_are_refused() {
        let mut d = blob();
        d[..4].copy_from_slice(b"FXWR");
        assert!(decode_config(&d)
            .unwrap_err()
            .to_string()
            .contains("bad magic"));
        let mut d = blob();
        let last = d.len() - 1;
        d[last] ^= 0x01;
        assert!(decode_config(&d)
            .unwrap_err()
            .to_string()
            .contains("checksum"));
        // The first module record's length, after the 16-byte header, the
        // GRPH section head, the graph header, its one domain record, and the
        // composed graph's header and order; the checksum re-computed so the
        // length check is what refuses it.
        let mut d = blob();
        let at = 16 + 8 + 8 + 8 + 40;
        assert_eq!(
            u16::from_le_bytes([d[at], d[at + 1]]),
            23,
            "the first record's length"
        );
        d[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        let crc = fluxor_contracts::boot_config::crc32(&d[12..]);
        d[8..12].copy_from_slice(&crc.to_le_bytes());
        assert!(decode_config(&d)
            .unwrap_err()
            .to_string()
            .contains("module record at 40 runs past the graph"));
    }
}

#[cfg(test)]
mod edge_buffer_bytes_tests {
    use super::*;

    #[test]
    fn buffer_bytes_is_carried_as_written_and_refused_over_the_ceiling() {
        let max = fluxor_contracts::ring_size::MAX_RING_BYTES as u64;
        let cfg = json!({"wiring": [
            {"from": "a.out", "to": "b.in"},
            {"from": "a.out", "to": "b.in", "buffer_bytes": 10},
            {"from": "a.out", "to": "b.in", "buffer_bytes": max},
        ]});
        // Below the floor too: the kernel's rule raises it, not the encoder.
        assert_eq!(
            resolve_edge_buffer_bytes(&cfg).unwrap(),
            vec![0, 10, max as u32]
        );
        let cfg = json!({"wiring": [{"from": "a.out", "to": "b.in", "buffer_bytes": max + 1}]});
        let e = resolve_edge_buffer_bytes(&cfg).unwrap_err().to_string();
        assert!(e.contains("over the 4194304 B ceiling"), "{e}");
    }
}

/// A module type's `[capacities] heap_from_params` sizes an instance's heap
/// cap (params tag 0xEF) from the bytes its params declare, unless the graph
/// sets `heap.arena_bytes`, which wins.
#[cfg(test)]
mod heap_from_params_tests {
    use super::*;
    use serde_json::json;

    /// A schema with one chunked string param, `body` (tag 2).
    fn body_schema() -> schema::ParamSchema {
        let mut b = vec![0x53, 0x50, 1, 1];
        b.extend_from_slice(&schema::raw_param(2, 6, 0, "body"));
        schema::ParamSchema::from_bytes(&b).expect("schema")
    }

    /// A rule of http's shape: tags 2 and 11, a type default of `BASE`
    /// holding `INCLUDED` body bytes.
    const BASE: u32 = 23_063_552;
    const INCLUDED: u32 = 262_144;

    fn manifest() -> Manifest {
        let toml = format!(
            "version = \"1.0.0\"\n[capacities]\nheap_from_params = \
             {{ tags = [2, 11], base = {BASE}, included = {INCLUDED} }}\n"
        );
        Manifest::from_toml_str_for_target(&toml, Some("aarch64")).expect("manifest")
    }

    /// The 0xEF value a params TLV carries, if any.
    fn tag_0xef(tlv: &[u8]) -> Option<u32> {
        let mut off = 4;
        while off + 2 <= tlv.len() && tlv[off] != 0xFF {
            let len = tlv[off + 1] as usize;
            if tlv[off] == 0xEF && len == 4 {
                return Some(u32::from_le_bytes(
                    tlv[off + 2..off + 6].try_into().unwrap(),
                ));
            }
            off += 2 + len;
        }
        None
    }

    /// 600 KiB of body bytes: the cap is the type's default grown by exactly
    /// the bytes past what it holds, with no `heap:` key in the graph.
    #[test]
    fn six_hundred_kib_of_body_derives_the_heap_cap() {
        let len = 600 * 1024;
        let module = json!({"body": "x".repeat(len)});
        let params = pack_params_growing(&module, &body_schema(), None, "http").expect("packs");
        let m = manifest();
        let rule = m.heap_from_params.as_ref().unwrap();
        assert_eq!(rule.declared_bytes(&params), len as u64);

        let p = insert_heap_tags(
            params.clone(),
            &module,
            "http",
            Some(&m),
            &HeapPlan::default(),
        )
        .unwrap();
        let want = BASE + (len as u32 - INCLUDED);
        assert_eq!(tag_0xef(&p), Some(want));
        assert_eq!(
            instance_heap_cap("http", &module, Some(&m), &params, &HeapPlan::default()).unwrap(),
            Some(want)
        );
        // Without the rule, nothing is derived.
        let p = insert_heap_tags(params, &module, "http", None, &HeapPlan::default()).unwrap();
        assert_eq!(tag_0xef(&p), None);
    }

    /// Bodies the type's default cap already holds emit no cap tag: the
    /// module keeps its own figure. The heap is still marked for a whole-cap
    /// commit (0xEE, three bytes), as every instance of a type that sizes its
    /// heap from its params is.
    #[test]
    fn bodies_within_the_default_emit_no_tag() {
        let m = manifest();
        for len in [0usize, 1, INCLUDED as usize] {
            let module = if len == 0 {
                json!({})
            } else {
                json!({"body": "x".repeat(len)})
            };
            let params = pack_params_growing(&module, &body_schema(), None, "http").expect("packs");
            let p = insert_heap_tags(
                params.clone(),
                &module,
                "http",
                Some(&m),
                &HeapPlan::default(),
            )
            .unwrap();
            assert_eq!(tag_0xef(&p), None, "{len} B: no cap tag");
            assert_eq!(
                p.len(),
                params.len() + 3,
                "{len} B: only the 0xEE mark joined"
            );
            assert!(
                p.windows(3).any(|w| w == [0xEE, 1, 1]),
                "{len} B: marked 0xEE"
            );
        }
    }

    /// An explicit `heap.arena_bytes` wins over the derived cap, whether it
    /// is larger or smaller (a smaller one is warned, not overridden).
    #[test]
    fn explicit_arena_bytes_wins() {
        let m = manifest();
        let body = "x".repeat(600 * 1024);
        for explicit in [64u32 << 20, 1 << 20] {
            let module = json!({"body": body, "heap": {"arena_bytes": explicit}});
            let params = pack_params_growing(&module, &body_schema(), None, "http").expect("packs");
            let p = insert_heap_tags(
                params.clone(),
                &module,
                "http",
                Some(&m),
                &HeapPlan::default(),
            )
            .unwrap();
            assert_eq!(tag_0xef(&p), Some(explicit));
            assert_eq!(
                instance_heap_cap("http", &module, Some(&m), &params, &HeapPlan::default())
                    .unwrap(),
                Some(explicit)
            );
        }
    }

    /// Params past 64 KiB: the header's u16 payload length saturates instead
    /// of wrapping to a small, wrong figure, and the basic section's end is
    /// found by walking to the terminator — through the schema packer and the
    /// workload heap-tag insert alike.
    #[test]
    fn params_past_64_kib_never_carry_a_wrapped_length() {
        let len = 600 * 1024;
        let module = json!({"body": "x".repeat(len)});
        let params = pack_params_growing(&module, &body_schema(), None, "http").expect("packs");
        assert!(params.len() > 65_540);
        assert_eq!(&params[2..4], &[0xFF, 0xFF], "saturated, not wrapped");
        assert_eq!(schema::tlv_basic_end(&params), Some(params.len()));

        let m = manifest();
        let p = insert_heap_tags(
            params.clone(),
            &module,
            "http",
            Some(&m),
            &HeapPlan::default(),
        )
        .unwrap();
        assert_eq!(&p[2..4], &[0xFF, 0xFF]);
        assert_eq!(schema::tlv_basic_end(&p), Some(p.len()));
        assert_eq!(
            p.len(),
            params.len() + 6 + 3,
            "the 0xEF entry and the 0xEE mark joined before the end"
        );

        // Under 64 KiB the field stays exact.
        let small = json!({"body": "x".repeat(1000)});
        let params = pack_params_growing(&small, &body_schema(), None, "http").expect("packs");
        let exact = u16::from_le_bytes([params[2], params[3]]) as usize;
        assert_eq!(exact + 4, params.len());
    }

    /// A cap past a heap's u32 size is refused, naming the module.
    #[test]
    fn a_cap_past_u32_is_refused() {
        let toml = "version = \"1.0.0\"\n[capacities]\nheap_from_params = \
                    { tags = [2], base = 4294967000, included = 0 }\n";
        let m = Manifest::from_toml_str_for_target(toml, None).unwrap();
        let module = json!({"body": "x".repeat(1000)});
        let params = pack_params_growing(&module, &body_schema(), None, "http").expect("packs");
        let err = instance_heap_cap("big", &module, Some(&m), &params, &HeapPlan::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("module 'big'") && err.contains("u32"), "{err}");
    }
}

/// The kernel's boot plan, run at build: each pool's ceiling is what the
/// config derives plus its reserve, and a ceiling the target's kernel cannot
/// hold is refused here, naming the pool and by how much, as the kernel
/// refuses it at boot (`size_kernel_tables`).
#[cfg(test)]
mod boot_plan_tests {
    use crate::capacity::{
        check_boot_plan, fan_count, plan_pool, resident_demand, GraphShape, PoolFigures,
    };
    use fluxor_contracts::boot_config::WorkloadRecord;

    fn shape(modules: u64, edges: u64) -> GraphShape {
        GraphShape {
            modules,
            edges,
            ..Default::default()
        }
    }

    fn figures(list: &[(&str, u64)]) -> Vec<(String, u64)> {
        list.iter().map(|&(n, v)| (n.to_string(), v)).collect()
    }

    const NONE: &PoolFigures = &[];

    /// A graph without `capacity:` takes each pool's derived size plus the
    /// profile's default reserve, clamped to what the pool's index range
    /// leaves: a Linux graph of 3900 modules boots on 196 of the 256 default
    /// module slots. An explicit entry is never clamped, so one past the
    /// domain is refused, by how much and with the figure that fits.
    #[test]
    fn a_default_reserve_takes_what_the_domain_leaves() {
        let plan = plan_pool("linux", "module_slots", &shape(3800, 0), NONE, NONE);
        assert_eq!((plan.derived, plan.reserve), (3800, 256));
        let plan = plan_pool("linux", "module_slots", &shape(3900, 0), NONE, NONE);
        assert_eq!((plan.derived, plan.reserve), (3900, 196));
        check_boot_plan("linux", &shape(3900, 0), NONE, NONE).expect("the default is clamped");
        let ask = figures(&[("module_slots", 256)]);
        let e = check_boot_plan("linux", &shape(3900, 0), &ask, NONE).unwrap_err();
        assert!(
            e.contains("pool 'module_slots' to 4156 (derived 3900 + reserve 256 from `capacity:`)")
                && e.contains("module-index range (MAX_MODULES) of 4096")
                && e.contains("over by 60")
                && e.contains("`capacity: { module_slots: 196 }`"),
            "{e}"
        );
        let fit = figures(&[("module_slots", 196)]);
        check_boot_plan("linux", &shape(3900, 0), &fit, NONE).expect("a reserve that fits");
        // A graph past the domain on its own is refused whatever the reserve.
        let e = check_boot_plan("linux", &shape(4200, 0), NONE, NONE).unwrap_err();
        assert!(
            e.contains("derived 4200 + default reserve 0") && e.contains("shrink the graph"),
            "{e}"
        );
    }

    /// The owner-slot range is 4096 and bcm2712's default owner reserve 63:
    /// a resident workload's slot comes beside the default, while a reserve
    /// past the domain is refused.
    #[test]
    fn a_resident_workload_takes_an_owner_slot() {
        let mut s = shape(10, 10);
        s.workloads = 1;
        let plan = plan_pool("pi5", "owners", &s, NONE, NONE);
        assert_eq!((plan.derived, plan.reserve), (2, 63));
        check_boot_plan("pi5", &s, NONE, NONE).expect("the default leaves room");
        let e = check_boot_plan("pi5", &s, &figures(&[("owners", 4095)]), NONE).unwrap_err();
        assert!(
            e.contains("pool 'owners' to 4097 (derived 2 + reserve 4095 from `capacity:`)")
                && e.contains("owner-slot range (MAX_OWNERS) of 4096")
                && e.contains("over by 1"),
            "{e}"
        );
        check_boot_plan("pi5", &s, &figures(&[("owners", 4094)]), NONE).expect("4094 fits");
        check_boot_plan("linux", &s, NONE, NONE).expect("linux owners");
    }

    /// Events, timers and routes name their slot in the handle's index
    /// field, which is their domain.
    #[test]
    fn events_are_held_to_the_handle_index_range() {
        let limit = fluxor_abi::registry::handle::INDEX_LIMIT as u64;
        let ask = figures(&[("events", limit)]);
        check_boot_plan("linux", &shape(1, 0), &ask, NONE).expect("every slot the field names");
        for pool in ["timers", "handles"] {
            let ask = figures(&[(pool, limit + 1)]);
            let e = check_boot_plan("linux", &shape(1, 0), &ask, NONE).unwrap_err();
            assert!(
                e.contains(&format!("pool '{pool}'")) && e.contains("handle index range"),
                "{e}"
            );
        }
    }

    /// A static table (wasm) holds what an envelope asks of it, derived part
    /// included; without an entry the table keeps every slot it has.
    #[test]
    fn a_static_table_binds_an_envelope() {
        let e =
            check_boot_plan("wasm", &shape(2, 1), &figures(&[("events", 33)]), NONE).unwrap_err();
        assert!(
            e.contains("pool 'events' to 33") && e.contains("static table of 32"),
            "{e}"
        );
        check_boot_plan("wasm", &shape(40, 0), NONE, NONE).expect("40 of 48 module slots");
        let e = check_boot_plan(
            "wasm",
            &shape(40, 0),
            &figures(&[("module_slots", 10)]),
            NONE,
        )
        .unwrap_err();
        assert!(
            e.contains("to 50 (derived 40 + reserve 10 from `capacity:`)")
                && e.contains("over by 2"),
            "{e}"
        );
    }

    /// A Linux sandbox is a workload with an owner: the pool's derived part
    /// is the owner table's workload slots. Near the sandbox domain the
    /// default reserve shrinks to what is left; an explicit one does not.
    #[test]
    fn sandboxes_derive_from_the_owner_table() {
        let owners = figures(&[("owners", 4000)]);
        let plan = plan_pool("linux", "sandboxes", &shape(1, 0), NONE, &owners);
        assert_eq!((plan.derived, plan.reserve), (4000, 64));
        let wide = figures(&[("owners", 4095)]);
        let plan = plan_pool("linux", "sandboxes", &shape(1, 0), NONE, &wide);
        assert_eq!((plan.derived, plan.reserve), (4095, 1));
        check_boot_plan("linux", &shape(1, 0), &wide, NONE).expect("the default is clamped");
        let ask = figures(&[("owners", 4095), ("sandboxes", 64)]);
        let e = check_boot_plan("linux", &shape(1, 0), &ask, NONE).unwrap_err();
        assert!(
            e.contains("pool 'sandboxes' to 4159 (derived 4095 + reserve 64 from `capacity:`)")
                && e.contains("sandbox-index range (MAX_SANDBOXES) of 4096"),
            "{e}"
        );
    }

    /// Declared demand adds to the derived part, as `DMND` does in the kernel;
    /// a module-served pool takes no default reserve.
    #[test]
    fn declared_demand_is_derived() {
        let declared = figures(&[("store_subs", 400)]);
        let plan = plan_pool("linux", "store_subs", &shape(1, 0), &declared, NONE);
        assert_eq!((plan.derived, plan.reserve), (400, 0));
        let declared = figures(&[("events", 400)]);
        let plan = plan_pool("linux", "events", &shape(1, 0), &declared, NONE);
        assert_eq!((plan.derived, plan.reserve), (400, 32));
    }

    /// Fans are counted as the kernel counts them: one per port carrying two
    /// or more edges in the same direction.
    #[test]
    fn fans_count_ports_with_two_edges_one_way() {
        // (from_id, to_id, to_port, from_port_index, to_port_index)
        let tee = [(0, 1, 0, 0, 0), (0, 2, 0, 0, 0)];
        assert_eq!(fan_count(&tee), 1);
        let merge = [(1, 0, 0, 0, 0), (2, 0, 0, 0, 0)];
        assert_eq!(fan_count(&merge), 1);
        let ports = [(0, 1, 0, 0, 0), (0, 2, 0, 1, 0), (3, 1, 1, 0, 0)];
        assert_eq!(fan_count(&ports), 0, "distinct ports, data and control");
        let s = GraphShape {
            modules: 3,
            edges: 2,
            fans: fan_count(&tee),
            ..Default::default()
        };
        assert_eq!(
            plan_pool("linux", "module_slots", &s, NONE, NONE).derived,
            4
        );
        assert_eq!(plan_pool("linux", "channels", &s, NONE, NONE).derived, 3);
    }

    /// The resident-workload section is read as the kernel reads it: its
    /// workloads, their modules and their edges.
    #[test]
    fn resident_demand_reads_the_encoded_workloads() {
        use crate::add_subgraph::{encode_workload, ComposedModule, Composition, Workload};
        let workload = |n: usize| Workload {
            owner_uid: [n as u8; 16],
            graph: Composition {
                modules: (0..n)
                    .map(|_| ComposedModule {
                        name_hash: 1,
                        ..Default::default()
                    })
                    .collect(),
                order: (0..n as u16).collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        let blobs = [workload(2), workload(3)].map(|w| encode_workload(&w).expect("blob"));
        let records = blobs.each_ref().map(|blob| WorkloadRecord {
            idle_safe: false,
            endpoints: &[],
            blob,
        });
        assert_eq!(resident_demand(&records), (2, 5, 0));
        assert_eq!(resident_demand(&[]), (0, 0, 0));
        let mut s = shape(4, 0);
        (s.workloads, s.workload_modules, s.workload_edges) = resident_demand(&records);
        assert_eq!(plan_pool("linux", "owners", &s, NONE, NONE).derived, 3);
        // RP plans its owner table from the same demand. wasm's is a static
        // table holding the node owner's slot alone, so the kernel refuses the
        // resident workloads at boot, and so does the composer.
        assert_eq!(plan_pool("rp2350", "owners", &s, NONE, NONE).derived, 3);
        check_boot_plan("rp2350", &s, NONE, NONE).expect("rp plans its owners");
        let e = check_boot_plan("wasm", &s, NONE, NONE).unwrap_err();
        assert!(
            e.contains("pool 'owners' to 3") && e.contains("past its static table of 1"),
            "{e}"
        );
        assert_eq!(
            plan_pool("linux", "module_slots", &s, NONE, NONE).derived,
            9
        );
    }

    /// The state-arena free list is derived from the module-slot ceiling where
    /// it is sized at boot, and is the static list on wasm.
    #[test]
    fn the_free_list_follows_the_module_slots() {
        let plan = plan_pool("linux", "state_free_list", &shape(10, 0), NONE, NONE);
        // (10 + 256 module slots) × (state + arena + 8 heap segments) + 1.
        assert_eq!(plan.derived, 266 * 10 + 1);
        let wasm = plan_pool("wasm", "state_free_list", &shape(10, 0), NONE, NONE);
        assert_eq!((wasm.derived, wasm.ceiling()), (0, 32));
    }
}

#[cfg(test)]
mod check_mode_file_tests {
    use super::*;

    /// tls and quic credentials: a bare path stays a packed param (the
    /// module reads it at runtime, and nothing is read here), an env
    /// binding stays for the schema to pack, and only `${file:<path>}` and
    /// `trust: system` are lifted out to be embedded.
    #[test]
    fn credentials_named_by_path_are_packed_and_never_read() {
        let all = |_: &str| true;
        let module = json!({
            "cert_file": "/run/secrets/tls/tls.crt",
            "key_file": {"env": "TLS_KEY"},
            "trust": "/run/secrets/tls/ca.crt",
        });
        let (validated, packed, sources) =
            lift_credential_sources("srv", module.clone(), all).unwrap();
        assert_eq!(validated, module);
        assert_eq!(packed, module, "every runtime form packs as written");
        assert_eq!(sources, CredentialSources::default(), "nothing to embed");

        let module = json!({
            "cert_file": "${file:/build/cert.pem}",
            "key_file": "/run/key.pem",
            "trust": "system",
        });
        let (_, packed, sources) = lift_credential_sources("srv", module, all).unwrap();
        assert_eq!(packed, json!({"key_file": "/run/key.pem"}));
        assert_eq!(sources.cert.as_deref(), Some("${file:/build/cert.pem}"));
        assert_eq!(sources.key, None);
        assert_eq!(sources.trust.as_deref(), Some("system"));

        // An empty value (a param left at `""`) names nothing.
        let empty = json!({"trust": ""});
        let (_, packed, sources) = lift_credential_sources("srv", empty.clone(), all).unwrap();
        assert_eq!((packed, sources), (empty, CredentialSources::default()));

        // A module whose schema declares none of them is left alone; the
        // param check refuses the key there.
        let undeclared = json!({"trust": "platform"});
        let (_, packed, sources) =
            lift_credential_sources("isr", undeclared.clone(), |_| false).unwrap();
        assert_eq!(
            (packed, sources),
            (undeclared, CredentialSources::default())
        );

        for (bad, says) in [
            (json!({"cert_file": "certs/server.pem"}), "absolute path"),
            (
                json!({"key_file": format!("/{}", "k".repeat(255))}),
                "at most 255",
            ),
            (json!({"trust": "${param:ca}"}), "is not `${file:<path>}`"),
            (json!({"trust": 7}), "an `{env: NAME}` binding"),
        ] {
            let err = lift_credential_sources("srv", bad, all).unwrap_err();
            assert!(format!("{err:?}").contains(says), "{err:?}");
        }
    }

    /// A Linux image never embeds a credential: the build-time form is
    /// refused before any file is read, so a host build (and its check)
    /// reads nothing. Elsewhere it embeds, and a bare path — read at
    /// runtime — is refused where nothing serves `fs`.
    #[test]
    fn credential_forms_follow_the_runtime() {
        for key in ["cert_file", "key_file", "trust"] {
            let m = json!({"name": "srv", "type": "tls", key: "${file:/nonexistent/x.pem}"});
            let err = refuse_credential_forms(&m, Some("linux"), true, "srv").unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("takes its credentials at runtime"), "{msg}");
            assert!(
                msg.contains(&format!("`{key}: /nonexistent/x.pem`")),
                "{msg}"
            );
            refuse_credential_forms(&m, Some("bcm2712"), false, "srv").expect("metal embeds");
            refuse_credential_forms(&m, None, false, "srv").expect("no target: unjudged");

            let bare = json!({"name": "srv", "type": "tls", key: "/nonexistent/x.pem"});
            refuse_credential_forms(&bare, Some("linux"), true, "srv").expect("read at runtime");
            let err = refuse_credential_forms(&bare, Some("rp2350"), false, "srv").unwrap_err();
            let msg = format!("{err:?}");
            assert!(msg.contains("nothing serves `fs`"), "{msg}");
            assert!(msg.contains("${file:/nonexistent/x.pem}"), "{msg}");
            refuse_credential_forms(&bare, Some("rp2350"), true, "srv")
                .expect("a graph with an fs provider reads it");
        }
        let system = json!({"name": "srv", "type": "tls", "trust": "system"});
        refuse_credential_forms(&system, Some("rp2350"), false, "srv").expect("no file");
        assert!(fs_reachable("linux", ProviderCaller::Node, fluxor_root()));
        assert!(fs_reachable(
            "bcm2712",
            ProviderCaller::Workload,
            fluxor_root()
        ));
        assert!(!fs_reachable(
            "bcm2712",
            ProviderCaller::Node,
            fluxor_root()
        ));
        assert!(!fs_reachable("rp2350", ProviderCaller::Node, fluxor_root()));
    }

    /// tls's peer names as its schema declares them (tags 24..=26).
    fn peer_name_schema() -> crate::schema::ParamSchema {
        use crate::schema::{ParamSchema, ParamType, SchemaParam};
        let p = |tag, name: &str| SchemaParam {
            tag,
            ptype: ParamType::Str,
            name: name.into(),
            default: 0,
            min: 0,
            max: u32::MAX,
            enums: std::collections::HashMap::new(),
        };
        ParamSchema::from_params(vec![
            p(24, "verify_hostname"),
            p(25, "verify_uri"),
            p(26, "alpn"),
        ])
    }

    /// The `(tag, value)` entries of a packed params TLV's basic section.
    fn packed_entries(entry: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 4;
        while entry[pos] != 0xFF {
            let len = entry[pos + 1] as usize;
            out.push((entry[pos], entry[pos + 2..pos + 2 + len].to_vec()));
            pos += 2 + len;
        }
        out
    }

    /// `verify_hostname`, `verify_uri` and `alpn` are tls / quic schema
    /// strings: checked under the module's rules, `alpn`'s list joined, and
    /// packed as basic TLVs — nothing past the terminator — so `{env: NAME}`
    /// binds each of them in a workload image.
    #[test]
    fn peer_names_pack_as_schema_strings_and_bind_from_the_environment() {
        let all = |_: &str| true;
        let schema = peer_name_schema();
        let pack = |module: Value| {
            let m = normalize_peer_names("cli", "tls", module, all).unwrap();
            let mut entry = vec![0u8; 512];
            let end =
                crate::schema::build_params_from_schema(&m, &schema, &mut entry, 0, None, "tls")
                    .unwrap();
            assert_eq!(entry[end - 2..end], [0xFF, 0], "no extended entries");
            packed_entries(&entry[..end])
        };
        assert_eq!(
            pack(json!({
                "verify_hostname": "api.cell.example",
                "verify_uri": "spiffe://cell.example/peers/",
                "alpn": ["h2", "http/1.1"],
            })),
            vec![
                (24, b"api.cell.example".to_vec()),
                (25, b"spiffe://cell.example/peers/".to_vec()),
                (26, b"h2,http/1.1".to_vec()),
            ]
        );
        // An empty value names nothing and packs nothing.
        assert_eq!(pack(json!({"verify_hostname": "", "alpn": []})), vec![]);

        // `{env: NAME}`: a bind record in each param's place.
        let module = json!({
            "verify_hostname": {"env": "PEER_HOST"},
            "verify_uri": {"env": "PEER_URI"},
            "alpn": {"env": "PEER_ALPN"},
        });
        let (entries, binds) = crate::schema::with_env_binds(|| pack(module));
        let bind = |target: u8, name: &str| {
            let mut v = vec![
                target,
                crate::schema::env_bind::KIND_STR,
                crate::schema::env_bind::FLAG_REQUIRED,
                name.len() as u8,
            ];
            // The param's bounds: the test schema's 0..=u32::MAX.
            v.extend_from_slice(&[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
            v.extend_from_slice(name.as_bytes());
            (crate::schema::env_bind::BIND_TAG, v)
        };
        assert_eq!(
            entries,
            vec![
                bind(24, "PEER_HOST"),
                bind(25, "PEER_URI"),
                bind(26, "PEER_ALPN"),
            ]
        );
        let names: Vec<&str> = binds.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["PEER_HOST", "PEER_URI", "PEER_ALPN"]);

        // A literal the module would refuse is refused here, with the reason.
        for (bad, says) in [
            (
                json!({"verify_uri": "spiffe://"}),
                "must be scheme://authority/path",
            ),
            (
                json!({"verify_hostname": format!("{}.example", "a".repeat(60))}),
                "over the 64-byte limit",
            ),
            (
                json!({"verify_hostname": 7}),
                "a string or an `{env: NAME}` binding",
            ),
            (json!({"alpn": "h2,,x"}), "alpn name ''"),
        ] {
            let err = normalize_peer_names("cli", "tls", bad, all).unwrap_err();
            assert!(format!("{err:?}").contains(says), "{err:?}");
        }
        // A module whose schema declares none of them is left alone.
        let other = json!({"alpn": ["x"]});
        assert_eq!(
            normalize_peer_names("m", "mqtt", other.clone(), |_| false).unwrap(),
            other
        );
    }

    #[test]
    fn alpn_is_a_name_or_a_list_held_whole() {
        let s = |v: serde_json::Value| alpn_param("m", "tls", Some(&v));
        assert_eq!(s(json!("h2")).unwrap().as_deref(), Some("h2"));
        assert_eq!(
            s(json!(["h2", "http/1.1"])).unwrap().as_deref(),
            Some("h2,http/1.1")
        );
        assert_eq!(
            s(json!("h2,http/1.1")).unwrap().as_deref(),
            Some("h2,http/1.1")
        );
        assert_eq!(alpn_param("m", "tls", None).unwrap(), None);
        // A name tls cannot record whole, an empty one, a space, a comma
        // inside a listed name, a non-string.
        assert!(s(json!("a-protocol-name-17")).is_err());
        assert!(s(json!("h2,,http/1.1")).is_err());
        assert!(s(json!("h2 x")).is_err());
        assert!(s(json!(["h2,http/1.1"])).is_err());
        assert!(s(json!(2)).is_err());
        // quic keeps its 24-byte names.
        assert!(alpn_param("m", "quic", Some(&json!("a-protocol-name-17"))).is_ok());
        assert!(alpn_param("m", "quic", Some(&json!("x".repeat(25)))).is_err());
        assert!(
            s(json!(vec!["abcdefgh"; 8])).is_err(),
            "over 64 bytes in all"
        );
    }
}

/// Record bounds and send retention across an edge
/// (`validate_record_limits`), and the edge flag a retaining consumer puts
/// on the graph.
#[cfg(test)]
mod record_limit_tests {
    use super::*;
    use crate::manifest::{Manifest, PortSpec};
    use std::collections::HashMap;

    fn port(direction: u8, name: &str) -> PortSpec {
        PortSpec {
            direction,
            content_type: crate::manifest::CONTENT_TYPES
                .iter()
                .position(|c| *c == "NetProto")
                .unwrap() as u8,
            flags: 0,
            name: Some(name.to_string()),
            index: 1,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: std::collections::BTreeMap::new(),
            fact_params: std::collections::BTreeMap::new(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    /// A transport writing records of `max_record` on its `net_out`, which
    /// retains for its consumers by `tcp_send_buf` blocks of a
    /// `tcp_send_pool`, and serves `lanes`.
    fn transport(max_record: u32) -> Manifest {
        Manifest {
            ports: vec![PortSpec {
                max_record,
                send_buffer_param: Some("tcp_send_buf".to_string()),
                send_pool_param: Some("tcp_send_pool".to_string()),
                send_pool_lanes_param: Some("lanes".to_string()),
                ..port(1, "net_out")
            }],
            ..Manifest::default()
        }
    }

    fn consumer(accepts_record: u32, retains_send: bool) -> Manifest {
        Manifest {
            ports: vec![PortSpec {
                accepts_record,
                retains_send,
                ..port(0, "net_in")
            }],
            ..Manifest::default()
        }
    }

    fn datagram_consumer() -> Manifest {
        Manifest {
            ports: vec![PortSpec {
                accepts_record: 1483,
                datagram_only: true,
                ..port(0, "net_in")
            }],
            ..Manifest::default()
        }
    }

    /// The `tcp_send_pool` the composer derives for an `ip` entry `ip`
    /// feeding `consumers`, its schema defaulting to two 1460-byte blocks
    /// and no lanes.
    fn derived_pool(ip: serde_json::Value, consumers: Vec<Manifest>) -> Option<u64> {
        let mut manifests = HashMap::new();
        manifests.insert("ip".to_string(), transport(1483));
        let mut names = vec!["ip".to_string()];
        let mut edges = Vec::new();
        for (k, m) in consumers.into_iter().enumerate() {
            let n = format!("c{k}");
            manifests.insert(n.clone(), m);
            names.push(n);
            edges.push((0u16, (k + 1) as u16, 0u8, 1u8, 1u8));
        }
        let mut modules = vec![ip];
        let defaults = |_: &serde_json::Value, param: &str| match param {
            "tcp_send_buf" => Some(1460),
            "tcp_send_pool" => Some(2920),
            "lanes" => Some(0),
            _ => None,
        };
        derive_send_pools(&mut modules, &edges, &names, &manifests, &defaults).unwrap();
        modules[0].get("tcp_send_pool").and_then(|v| v.as_u64())
    }

    fn check(tcp_send_buf: Option<u64>, consumers: &[(u32, bool)]) -> Result<()> {
        let mut manifests = HashMap::new();
        manifests.insert("ip".to_string(), transport(1483));
        let mut names = vec!["ip".to_string()];
        let mut edges = Vec::new();
        let mut from = Vec::new();
        let mut to = Vec::new();
        let mut wiring = Vec::new();
        for (k, &(accepts, retains)) in consumers.iter().enumerate() {
            let n = format!("c{k}");
            manifests.insert(n.clone(), consumer(accepts, retains));
            names.push(n.clone());
            edges.push((0u16, (k + 1) as u16, 0u8, 1u8, 1u8));
            from.push("ip.net_out".to_string());
            to.push(format!("{n}.net_in"));
            wiring.push(serde_json::json!({"from": "ip.net_out", "to": format!("{n}.net_in")}));
        }
        let mut ip = serde_json::json!({"name": "ip"});
        if let Some(v) = tcp_send_buf {
            ip["tcp_send_buf"] = serde_json::json!(v);
        }
        let config = serde_json::json!({"modules": [ip], "wiring": wiring});
        validate_record_limits(&config, &edges, &names, &manifests, &from, &to)
    }

    #[test]
    fn a_producer_record_past_a_consumer_bound_is_refused_fans_included() {
        check(None, &[(1483, false)]).unwrap();
        check(None, &[(2048, false), (1500, true)]).unwrap();
        let e = check(None, &[(2048, false), (1482, true)])
            .unwrap_err()
            .to_string();
        assert!(e.contains("1483") && e.contains("1482"), "{e}");
        // An undeclared bound (a port with no record facts) is not compared.
        check(None, &[(0, false)]).unwrap();
    }

    #[test]
    fn no_send_buffer_needs_every_consumer_to_retain() {
        check(Some(0), &[(1483, true)]).unwrap();
        check(Some(1460), &[(1483, false)]).unwrap();
        check(None, &[(1483, false)]).unwrap();
        let e = check(Some(0), &[(1483, true), (1483, false)])
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("tcp_send_buf: 0") && e.contains("retains_send"),
            "{e}"
        );
    }

    #[test]
    fn a_datagram_only_or_retaining_graph_derives_no_send_pool() {
        let ip = || serde_json::json!({"name": "ip"});
        assert_eq!(derived_pool(ip(), vec![datagram_consumer()]), Some(0));
        assert_eq!(derived_pool(ip(), vec![consumer(1483, true)]), Some(0));
        assert_eq!(derived_pool(ip(), vec![]), Some(0), "nothing consumes it");
        assert_eq!(
            derived_pool(ip(), vec![datagram_consumer(), consumer(1483, false)]),
            Some(2920),
            "one plaintext stream consumer keeps the default pool"
        );
        assert_eq!(
            derived_pool(
                serde_json::json!({"name": "ip", "tcp_send_buf": 4096}),
                vec![consumer(1483, false)]
            ),
            Some(8192),
            "the default pool's blocks, of the instance's size"
        );
        assert_eq!(
            derived_pool(
                serde_json::json!({"name": "ip", "lanes": 2}),
                vec![datagram_consumer()]
            ),
            Some(2920),
            "a workload lane keeps the pool"
        );
        assert_eq!(
            derived_pool(
                serde_json::json!({"name": "ip", "tcp_send_pool": 5840}),
                vec![datagram_consumer()]
            ),
            Some(5840),
            "a pool the graph sets is kept"
        );
    }

    #[test]
    fn no_send_pool_needs_no_plaintext_stream_consumer() {
        let mut manifests = HashMap::new();
        manifests.insert("ip".to_string(), transport(1483));
        manifests.insert("dns".to_string(), datagram_consumer());
        manifests.insert("app".to_string(), consumer(1483, false));
        let names = vec!["ip".to_string(), "dns".to_string(), "app".to_string()];
        let run = |wired: &[&str]| {
            let edges: Vec<_> = wired
                .iter()
                .map(|n| {
                    (
                        0u16,
                        names.iter().position(|x| x == n).unwrap() as u16,
                        0u8,
                        1u8,
                        1u8,
                    )
                })
                .collect();
            let from: Vec<String> = wired.iter().map(|_| "ip.net_out".to_string()).collect();
            let to: Vec<String> = wired.iter().map(|n| format!("{n}.net_in")).collect();
            let config = serde_json::json!({"modules": [{"name": "ip", "tcp_send_pool": 0}]});
            validate_record_limits(&config, &edges, &names, &manifests, &from, &to)
        };
        run(&["dns"]).unwrap();
        let e = run(&["dns", "app"]).unwrap_err().to_string();
        assert!(e.contains("tcp_send_pool: 0"), "{e}");
    }
}

#[cfg(test)]
mod boot_composition_tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    fn generate(config: &Value) -> Result<Vec<u8>> {
        let root = root();
        let dir = root.join("target/fluxor/aarch64/modules");
        let r = crate::module_resolver::ModuleResolver::for_project(
            &root,
            crate::module_resolver::Abi::Module("aarch64".into()),
            Some(dir),
        )?;
        generate_config_ext(config, &ConfigBuilder::new(), &[], &r, 0, 0, Some("linux"))
    }

    /// The composer refuses `${applet:data_dir}` in a graph not built as an
    /// applet's, naming the value and why, before anything else is read.
    #[test]
    fn a_graph_built_outside_an_applet_is_refused_its_data_dir() {
        let g = json!({"target": "linux", "modules": [
            {"name": "store", "dir": "${applet:data_dir}/store"},
        ]});
        let e = generate(&g).unwrap_err().to_string();
        assert!(e.contains("${applet:data_dir}/store"), "{e}");
        assert!(e.contains("not built as one"), "{e}");
    }

    fn probes(names: &[&str]) -> Value {
        names
            .iter()
            .map(|n| json!({"name": n, "type": "churn_probe"}))
            .collect()
    }

    /// The `host_lane` params of the composed module at `i`, by tag.
    fn lane_params(
        g: &graph::ComposedGraph<'_>,
        i: usize,
    ) -> std::collections::BTreeMap<u8, Vec<u8>> {
        let m = g.modules().nth(i).expect("the module");
        assert_eq!(
            m.name_hash,
            fnv1a_hash(b"host_lane"),
            "built as a host lane"
        );
        let mut tags = std::collections::BTreeMap::new();
        fluxor_contracts::params_tlv::walk_declared(m.params, |tag, v| {
            tags.insert(tag, v.to_vec());
        });
        tags
    }

    /// The lane end of a composed edge, `(key, target)`, if it has one.
    fn lane_of(e: &graph::EdgeRecord) -> Option<(u8, u32)> {
        match (e.from, e.to) {
            (graph::Endpoint::Lane { key, target }, _) | (_, graph::Endpoint::Lane { key, target }) => {
                Some((key, target))
            }
            _ => None,
        }
    }

    /// A graph of `n` `conn_sink`s, each wired into `linux_net.net_in` and
    /// back from `linux_net.net_out`, as a node graph's socket consumers
    /// are.
    fn paired_sinks(n: usize) -> Value {
        let mut modules = vec![json!({"name": "linux_net"})];
        let mut wiring = Vec::new();
        for i in 0..n {
            let name = format!("s{i}");
            modules.push(json!({"name": name, "type": "conn_sink", "port": 9000 + i}));
            wiring.push(json!({"from": format!("{name}.net_out"), "to": "linux_net.net_in"}));
            wiring.push(json!({"from": "linux_net.net_out", "to": format!("{name}.net_in")}));
        }
        json!({
            "modules": modules,
            "wiring": wiring,
            "scheduler": {"accept_cycles": true},
        })
    }

    /// `linux_net` is built as the `host_lane` that runs its host provider:
    /// its one static pair address control, and every socket consumer a
    /// lane of its own — keyed in wiring order, its events back to its
    /// producer, no tee and no merge — reached by the `linux_net` lane
    /// target, which serves them beside its workload lanes. The provider is
    /// told the instance's sizes and the contracts it serves, and nothing of
    /// lanes or pairs.
    #[test]
    fn linux_net_is_a_host_lane_and_each_producer_a_lane_of_its_own() {
        let config = json!({
            "modules": [
                {"name": "linux_net", "max_conns": 200},
                {"name": "a", "type": "conn_sink", "port": 9001},
                {"name": "b", "type": "conn_sink", "port": 9002},
            ],
            "wiring": [
                {"from": "a.net_out", "to": "linux_net.net_in"},
                {"from": "b.net_out", "to": "linux_net.net_in"},
                {"from": "linux_net.net_out", "to": "b.net_in"},
                {"from": "linux_net.net_out", "to": "a.net_in"},
            ],
            "scheduler": {"accept_cycles": true},
        });
        let blob = generate(&config).expect("generates");
        let cfg = boot_config::decode(&blob).expect("decodes");
        let g = cfg.graph().composed();
        assert_eq!(g.modules().count(), 3, "no tee and no merge");
        let target = fluxor_abi::wire::fnv1a32(b"linux_net");
        let lane = |key| graph::Endpoint::Lane { key, target };
        let ends: Vec<(graph::Endpoint, graph::Endpoint)> =
            g.edges().map(|e| (e.from, e.to)).collect();
        assert_eq!(
            ends,
            vec![
                (graph::Endpoint::New(1), lane(0)),
                (graph::Endpoint::New(2), lane(1)),
                (lane(1), graph::Endpoint::New(2)),
                (lane(0), graph::Endpoint::New(1)),
            ],
            "lane k for the k-th producer; each consumer reads its own lane"
        );
        let t = lane_params(&g, 0);
        let s = |tag: u8| String::from_utf8(t[&tag].clone()).unwrap();
        assert_eq!(s(10), "fluxor-provider-net");
        assert_eq!(s(11), "NetProto:tlv16:265", "the static pair is address control alone");
        assert_eq!(
            s(12),
            "max_conns=200 write_buf_kib=128 listen_backlog=128 serves=net_route,net_policy"
        );
        assert_eq!(t[&13], vec![0], "a full lane holds its producer");
        assert_eq!(s(14), "net_route,net_policy");
        assert_eq!(s(15), "linux_net");
        assert_eq!(t[&16], vec![32 + 2], "its workload lanes and the graph's two");
    }

    /// Eight producers, and forty — far past what any static table carried
    /// — each get a lane of their own, and the lane target serves them all.
    #[test]
    fn eight_and_forty_producers_each_get_a_lane_of_their_own() {
        for n in [8usize, 40] {
            let blob = generate(&paired_sinks(n)).expect("generates");
            let cfg = boot_config::decode(&blob).expect("decodes");
            let g = cfg.graph().composed();
            assert_eq!(g.modules().count(), 1 + n, "{n}: no tee and no merge");
            for k in 0..n {
                let producer = graph::Endpoint::New(1 + k as u16);
                let into: Vec<_> = g.edges().filter(|e| e.from == producer).collect();
                let out: Vec<_> = g.edges().filter(|e| e.to == producer).collect();
                assert_eq!((into.len(), out.len()), (1, 1), "{n}: one edge each way");
                assert_eq!(lane_of(&into[0]).map(|l| l.0), Some(k as u8), "{n}: lane {k}");
                assert_eq!(
                    lane_of(&out[0]).map(|l| l.0),
                    Some(k as u8),
                    "{n}: lane {k}'s events to its producer"
                );
            }
            assert_eq!(lane_params(&g, 0)[&16], vec![(32 + n) as u8]);
        }
    }

    /// The shape `connlanes` takes: two producers marked `edge_class:
    /// merge` share one lane through a merge, and its events reach every
    /// `net_out` consumer through a tee — the shared lane's producers, and
    /// one producing into none.
    #[test]
    fn merged_producers_share_one_lane_with_a_merge_and_a_tee() {
        let config = json!({
            "modules": [
                {"name": "linux_net"},
                {"name": "a", "type": "conn_sink", "port": 9001},
                {"name": "b", "type": "conn_sink", "port": 9002},
                {"name": "c", "type": "conn_sink", "port": 9003},
            ],
            "wiring": [
                {"from": "a.net_out", "to": "linux_net.net_in", "edge_class": "merge"},
                {"from": "b.net_out", "to": "linux_net.net_in", "edge_class": "merge"},
                {"from": "linux_net.net_out", "to": "c.net_in"},
                {"from": "linux_net.net_out", "to": "a.net_in"},
                {"from": "linux_net.net_out", "to": "b.net_in"},
            ],
            "scheduler": {"accept_cycles": true},
        });
        let blob = generate(&config).expect("generates");
        let cfg = boot_config::decode(&blob).expect("decodes");
        let g = cfg.graph().composed();
        let target = fluxor_abi::wire::fnv1a32(b"linux_net");
        let lane = graph::Endpoint::Lane { key: 0, target };
        let mut fans: Vec<u32> = g.modules().skip(4).map(|m| m.name_hash).collect();
        fans.sort_unstable();
        let mut want = vec![graph::TEE_NAME_HASH, graph::MERGE_NAME_HASH];
        want.sort_unstable();
        assert_eq!(fans, want, "a merge into the lane and a tee out of it");
        assert_eq!(g.edges().filter(|e| e.to == lane).count(), 1, "one commands edge");
        assert_eq!(g.edges().filter(|e| e.from == lane).count(), 1, "one events edge");
        assert!(
            g.edges().all(|e| lane_of(&e).is_none_or(|(k, _)| k == 0)),
            "one lane"
        );
        assert_eq!(lane_params(&g, 0)[&16], vec![33]);
    }

    /// A consumer of `net_out` that produces into no lane of its own reads
    /// the shared lane; address-control events leave the static pair.
    #[test]
    fn a_consumer_of_no_lane_reads_the_shared_lane() {
        let config = json!({
            "modules": [
                {"name": "linux_net"},
                {"name": "a", "type": "conn_sink", "port": 9001},
                {"name": "b", "type": "conn_sink", "port": 9002},
            ],
            "wiring": [
                {"from": "a.net_out", "to": "linux_net.net_in", "edge_class": "merge"},
                {"from": "linux_net.net_out", "to": "a.net_in"},
                {"from": "linux_net.net_out", "to": "b.net_in"},
                {"from": "linux_net.addr_evt", "to": "b.net_in"},
            ],
            "scheduler": {"accept_cycles": true},
        });
        let blob = generate(&config).expect("generates");
        let cfg = boot_config::decode(&blob).expect("decodes");
        let g = cfg.graph().composed();
        let target = fluxor_abi::wire::fnv1a32(b"linux_net");
        let lane = graph::Endpoint::Lane { key: 0, target };
        assert_eq!(g.edges().filter(|e| e.from == lane).count(), 1, "the lane's events, teed");
        let static_out: Vec<u8> = g
            .edges()
            .filter(|e| e.from.new_index() == Some(0))
            .map(|e| e.from_port)
            .collect();
        assert_eq!(static_out, vec![0], "the address events leave pair 0");
        assert!(
            g.edges().all(|e| e.to.new_index() != Some(0)),
            "nothing reaches a static input pair"
        );
    }

    /// A producer into `net_in` whose lane's events nobody reads is refused,
    /// naming it: its connections' events would have nowhere to go.
    #[test]
    fn a_producer_whose_lane_nobody_reads_is_refused() {
        let config = json!({
            "modules": [
                {"name": "linux_net"},
                {"name": "a", "type": "conn_sink", "port": 9001},
                {"name": "b", "type": "conn_sink", "port": 9002},
            ],
            "wiring": [
                {"from": "a.net_out", "to": "linux_net.net_in"},
                {"from": "linux_net.net_out", "to": "a.net_in"},
                {"from": "b.net_out", "to": "linux_net.net_in"},
            ],
            "scheduler": {"accept_cycles": true},
        });
        let e = generate(&config).unwrap_err().to_string();
        assert!(e.contains("`b` produces into `linux_net.net_in` and nothing reads"), "{e}");
    }

    /// Wiring that leaves a lane's events no one place to go is refused at
    /// build: a module producing into one target twice, or both alone and
    /// in the shared lane; a consumer with no lane to read; and `merge` on
    /// an edge that reaches no lane.
    #[test]
    fn an_ambiguous_lane_is_refused() {
        let with = |wiring: Value| {
            json!({
                "modules": [
                    {"name": "linux_net"},
                    {"name": "a", "type": "conn_sink", "port": 9001},
                    {"name": "b", "type": "conn_sink", "port": 9002},
                    {"name": "c", "type": "conn_sink", "port": 9003},
                ],
                "wiring": wiring,
                "scheduler": {"accept_cycles": true},
            })
        };
        let twice = with(json!([
            {"from": "a.net_out", "to": "linux_net.net_in"},
            {"from": "a.net_out", "to": "linux_net.net_in"},
            {"from": "linux_net.net_out", "to": "a.net_in"},
        ]));
        let e = generate(&twice).unwrap_err().to_string();
        assert!(e.contains("`a` already produces into a lane of `linux_net`"), "{e}");
        let both = with(json!([
            {"from": "a.net_out", "to": "linux_net.net_in", "edge_class": "merge"},
            {"from": "a.net_out", "to": "linux_net.net_in"},
            {"from": "linux_net.net_out", "to": "a.net_in"},
        ]));
        let e = generate(&both).unwrap_err().to_string();
        assert!(e.contains("`a` already produces into a lane of `linux_net`"), "{e}");
        let unread = with(json!([
            {"from": "a.net_out", "to": "linux_net.net_in"},
            {"from": "linux_net.net_out", "to": "a.net_in"},
            {"from": "linux_net.net_out", "to": "c.net_in"},
        ]));
        let e = generate(&unread).unwrap_err().to_string();
        assert!(e.contains("`c` reads `linux_net`'s events but produces into no lane"), "{e}");
        let stray = with(json!([
            {"from": "a.net_out", "to": "linux_net.net_in"},
            {"from": "linux_net.net_out", "to": "a.net_in"},
            {"from": "b.net_out", "to": "c.net_in", "edge_class": "merge"},
        ]));
        let e = generate(&stray).unwrap_err().to_string();
        assert!(e.contains("this edge reaches no lane"), "{e}");
    }

    /// The lanes a target serves, its workloads' and the node graph's
    /// together, are at most what a lane key names (255): more are refused
    /// at build, naming both.
    #[test]
    fn more_than_255_lanes_are_refused() {
        let mut config = paired_sinks(6);
        config["modules"][0]["lanes"] = json!(250);
        let e = generate(&config).unwrap_err().to_string();
        assert!(
            e.contains("serves 250 workload lane(s) (`lanes`) and the node's graph wires 6"),
            "{e}"
        );
        assert!(e.contains("256, past the 255"), "{e}");
        config["modules"][0]["lanes"] = json!(249);
        assert!(generate(&config).is_ok(), "255 lanes are served");
    }

    /// A static `host_lane` pair carries fixed-role channels alone: one that
    /// states socket traffic is refused at build.
    #[test]
    fn socket_traffic_on_a_static_pair_is_refused() {
        let config = json!({
            "modules": [{
                "name": "carrier",
                "type": "host_lane",
                "runtime": "fluxor-provider-net",
                "channels": "NetProto:tlv16:265;NetProto:tlv16:65538",
            }],
            "wiring": [],
        });
        let e = generate(&config).unwrap_err().to_string();
        assert!(e.contains("socket traffic on its static pair 1"), "{e}");
    }

    /// A `host_lane` of an image to run pins its provider binary (tag 17); a
    /// check composes it the same and pins nothing, so no runtime runs its
    /// image; a composition to run inside a check pins again.
    #[test]
    fn a_check_composes_host_lanes_without_a_provider_pin() {
        let config = json!({
            "modules": [{
                "name": "carrier",
                "type": "host_lane",
                "runtime": "fluxor-provider-net",
                "channels": "NetProto:tlv16:265",
            }],
            "wiring": [],
        });
        let pin = |blob: Vec<u8>| {
            let cfg = boot_config::decode(&blob).expect("decodes");
            let modules: Vec<_> = cfg.graph().composed().modules().collect();
            let mut digest = None;
            fluxor_contracts::params_tlv::walk_declared(modules[0].params, |tag, v| {
                if tag == 17 {
                    digest = Some(v.to_vec());
                }
            });
            digest
        };
        let run = pin(generate(&config).expect("an image to run composes"));
        assert_eq!(run.map(|d| d.len()), Some(64), "the run pins the provider");
        let check = compose_as_check(|| generate(&config)).expect("a check composes");
        assert_eq!(pin(check), None, "a check pins nothing");
        let inner = compose_as_check(|| compose_to_run(|| generate(&config)))
            .expect("a run inside a check composes");
        assert!(pin(inner).is_some(), "a run inside a check pins");
        let mut stated = config.clone();
        stated["modules"][0]["runtime_digest"] = json!("00");
        let e = compose_as_check(|| generate(&stated)).unwrap_err().to_string();
        assert!(e.contains("states `runtime_digest`"), "a check refuses as a run does: {e}");
    }

    /// A launch's image pins the provider beside the runtime that launch
    /// runs, not the one its project would build: a rebuilt provider is a
    /// different pin on the next launch's image.
    #[test]
    fn a_launch_pins_the_provider_beside_the_runtime_it_runs() {
        let config = json!({
            "modules": [{
                "name": "carrier",
                "type": "host_lane",
                "runtime": "fluxor-provider-net",
                "channels": "NetProto:tlv16:265",
            }],
            "wiring": [],
        });
        let pin = |blob: Vec<u8>| {
            let cfg = boot_config::decode(&blob).expect("decodes");
            let modules: Vec<_> = cfg.graph().composed().modules().collect();
            let mut digest = None;
            fluxor_contracts::params_tlv::walk_declared(modules[0].params, |tag, v| {
                if tag == 17 {
                    digest = Some(String::from_utf8(v.to_vec()).expect("hex"));
                }
            });
            digest
        };
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("fluxor-linux");
        let provider = dir.path().join("fluxor-provider-net");
        std::fs::write(&runtime, b"runtime").unwrap();
        for bytes in [&b"provider one"[..], &b"provider two"[..]] {
            std::fs::write(&provider, bytes).unwrap();
            let image = compose_on_runtime(&runtime, || generate(&config)).expect("composes");
            assert_eq!(
                pin(image),
                Some(crate::hash::hex(&crate::crypto::sha256(bytes))),
                "the pin is the provider beside the runtime the launch runs"
            );
        }
        let gone = compose_on_runtime(&dir.path().join("elsewhere/fluxor-linux"), || {
            generate(&config)
        })
        .unwrap_err()
        .to_string();
        assert!(gone.contains("elsewhere/fluxor-provider-net"), "{gone}");
    }

    /// The node graph arrives composed: an output wired to two inputs gets a
    /// tee, a module of the graph after the declared ones, whose params name
    /// its records per step and scratch — the largest ring beside it, the
    /// producer declaring no `max_record` — and the heap the tee's type derives for that scratch; the
    /// joining edge follows the declared ones, and the order steps the tee
    /// between its producer and consumers.
    #[test]
    fn a_fanned_output_boots_with_a_tee_module() {
        let config = json!({
            "modules": probes(&["src", "a", "b"]),
            "wiring": [
                {"from": "src.data_out", "to": "a.data_in"},
                {"from": "src.data_out", "to": "b.data_in", "buffer_bytes": 16384},
            ],
        });
        let blob = generate(&config).expect("generates");
        let cfg = boot_config::decode(&blob).expect("decodes");
        let g = cfg.graph().composed();
        let modules: Vec<_> = g.modules().collect();
        assert_eq!(modules.len(), 4);
        assert_eq!(modules[3].name_hash, graph::TEE_NAME_HASH);
        let mut tags = std::collections::BTreeMap::new();
        fluxor_contracts::params_tlv::walk_declared(modules[3].params, |tag, v| {
            tags.insert(tag, v.to_vec());
        });
        assert_eq!(tags[&plan::fan_param::FRAMES_PER_STEP], 64u16.to_le_bytes());
        assert_eq!(
            tags[&plan::fan_param::SCRATCH_BYTES],
            16384u32.to_le_bytes()
        );
        // The tee's `heap_per_param`: base 64 + one byte per scratch byte.
        assert_eq!(tags[&0xEF], (64u32 + 16384).to_le_bytes());
        let edges: Vec<_> = g.edges().collect();
        assert_eq!(edges.len(), 3);
        assert_eq!(
            (edges[2].from, edges[2].to),
            (graph::Endpoint::New(0), graph::Endpoint::New(3))
        );
        assert_eq!(
            (edges[0].from, edges[1].from),
            (graph::Endpoint::New(3), graph::Endpoint::New(3))
        );
        assert_eq!(g.order().collect::<Vec<_>>(), [0, 3, 1, 2]);
        assert_eq!(fan_types(&blob).unwrap(), ["tee"]);
    }

    /// A cycle the graph does not accept is refused naming its members, as
    /// the kernel would refuse the graph; `scheduler: accept_cycles` steps
    /// them in declaration order after the rest.
    #[test]
    fn a_cycle_needs_accept_cycles() {
        let mut config = json!({
            "modules": probes(&["a", "b"]),
            "wiring": [
                {"from": "a.data_out", "to": "b.data_in"},
                {"from": "b.data_out", "to": "a.data_in"},
            ],
        });
        let e = generate(&config).unwrap_err().to_string();
        assert!(
            e.contains("cycle through a, b") && e.contains("accept_cycles"),
            "{e}"
        );
        config["scheduler"] = json!({"accept_cycles": true});
        let blob = generate(&config).expect("an accepted cycle generates");
        let cfg = boot_config::decode(&blob).unwrap();
        assert_eq!(cfg.graph().composed().order().collect::<Vec<_>>(), [0, 1]);
    }

    /// A step budget reaches the module's record; `restart_graph` is refused.
    #[test]
    fn a_base_module_s_budget_is_in_its_record() {
        let mut config = json!({
            "modules": [{"name": "a", "type": "churn_probe", "step_deadline_us": 900,
                         "step_deadline_burst_us": 4000, "fault_policy": "tolerate"}],
            "wiring": [],
        });
        let blob = generate(&config).expect("generates");
        let cfg = boot_config::decode(&blob).unwrap();
        let m = cfg.graph().composed().modules().next().unwrap();
        assert_eq!((m.step_deadline_us, m.burst_us), (900, 4000));
        assert_eq!(m.fault_policy, FaultPolicy::Tolerate);
        config["modules"][0]["fault_policy"] = json!("restart_graph");
        let e = generate(&config).unwrap_err().to_string();
        assert!(e.contains("'restart_graph' is not a policy"), "{e}");
    }
}

#[cfg(test)]
mod pinned_variant_tests {
    //! A project that pins a module only under its variant's artefact name
    //! (`http-exchange`, as a stack binding wave's `http` pins it) builds a
    //! graph naming that variant: its manifest, its schema and its bytes all
    //! come from the one pin.
    use super::*;
    use fluxor_abi::wire::fmod::header::{Header, NAME_LEN};

    const VARIANTS: &str = "version = \"0.1.0\"\nhardware_targets = [\"linux\"]\n\n\
        [[ports]]\nname = \"request_in\"\ndirection = \"input\"\ncontent_type = \"OctetStream\"\n\n\
        [[ports]]\nname = \"full_only\"\ndirection = \"input\"\ncontent_type = \"OctetStream\"\n\n\
        [[variant]]\nname = \"full\"\ndefault = true\nfeatures = []\n\n\
        [[variant]]\nname = \"exchange\"\nfeatures = []\nomit_ports = [\"full_only\"]\n";
    const FEEDER: &str = "version = \"0.1.0\"\nhardware_targets = [\"linux\"]\n\n\
        [[ports]]\nname = \"data_out\"\ndirection = \"output\"\ncontent_type = \"OctetStream\"\n";

    /// A packed module with no code and `schema` as its params schema.
    fn fmod(name: &str, schema: &[u8]) -> Vec<u8> {
        let mut n = [0u8; NAME_LEN];
        n[..name.len()].copy_from_slice(name.as_bytes());
        let h = Header {
            magic: crate::modules::MODULE_MAGIC,
            version: 1,
            abi_version: 1,
            module_type: 0,
            flags: 0,
            code_size: 0,
            data_size: 0,
            export_count: 0,
            schema_size: schema.len() as u16,
            manifest_size: 0,
            step_period: 0,
            step_phase: 0,
            name: n,
        };
        let mut out = h.to_bytes().to_vec();
        out.extend_from_slice(schema);
        out
    }

    /// The project at `<dir>/project`, pinning `http-exchange` and `feeder`
    /// from a store at `<dir>/store`, and its resolver.
    fn project() -> (tempfile::TempDir, crate::module_resolver::ModuleResolver) {
        use fluxor_tools::oci_store::{publish_module, ModulePublish, OciStore, PROVENANCE_LOCAL};
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let store = OciStore::open(dir.path().join("store")).unwrap();
        // One U16 param, tag 1, `port`, default 80.
        let mut schema = vec![0x53, 0x50, 1, 1];
        schema.extend_from_slice(&schema::raw_param(1, 1, 80, "port"));
        let mut lock = String::new();
        for (name, toml, bytes) in [
            ("http-exchange", VARIANTS, fmod("http", &schema)),
            ("feeder", FEEDER, fmod("feeder", &[])),
        ] {
            let reference = format!("aarch64/{name}:0.0.1");
            let d = publish_module(
                &store,
                &ModulePublish {
                    name,
                    target: "aarch64",
                    fmod_bytes: &bytes,
                    manifest_toml: Some(toml),
                    provenance: PROVENANCE_LOCAL,
                    source_rev: None,
                    ref_name: &reference,
                },
            )
            .unwrap();
            lock.push_str(&format!(
                "[[artifact]]\nkind = \"module\"\nname = \"{name}\"\nproject = \"wave\"\n\
                 target = \"aarch64\"\ndigest = \"{}\"\nreference = \"{reference}\"\n\n",
                d.digest
            ));
        }
        std::fs::write(project.join("fluxor.lock"), lock).unwrap();
        let r = ModuleResolver::new(crate::module_resolver::ResolverSpec {
            project_root: project,
            abi: crate::module_resolver::Abi::Module("aarch64".into()),
            shelf: None,
            search_paths: Vec::new(),
            install_root: None,
            store_dir: Some(dir.path().join("store")),
        })
        .unwrap();
        (dir, r)
    }

    /// The graph builds, its wire to the variant's port resolves, and the
    /// instance's params pack against the pinned schema.
    fn builds_whole(config: &Value, r: &ModuleResolver, instance: &str) {
        generate_config_ext(config, &ConfigBuilder::new(), &[], r, 0, 0, None)
            .expect("the graph builds against the pinned variant");
        let entry = config["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == instance)
            .unwrap();
        let built = build_module_entry(
            instance,
            entry,
            0,
            None,
            config,
            r,
            &HashMap::new(),
            crate::capacity::kernel_max_modules("linux"),
            &crate::target::IsolationFacts::default(),
            &HeapPlan::default(),
        )
        .unwrap();
        assert!(
            built.params.windows(4).any(|w| w == [1, 2, 0x90, 0x1F]),
            "port 8080 packed from the pinned schema: {:?}",
            built.params
        );
    }

    #[test]
    fn a_variant_pinned_only_under_its_artefact_name_resolves_whole() {
        let (_dir, r) = project();
        let config = json!({
            "modules": [
                {"name": "feeder"},
                {"name": "http", "variant": "exchange", "port": 8080},
            ],
            "wiring": [{"from": "feeder.data_out", "to": "http.request_in"}],
        });
        builds_whole(&config, &r, "http");
        let table = r
            .graph_modules(config["modules"].as_array().unwrap())
            .unwrap()
            .artifacts()
            .iter()
            .map(|a| a.artifact.clone())
            .collect::<Vec<_>>();
        assert_eq!(table, ["feeder", "http-exchange"]);
    }

    #[test]
    fn a_variant_pinned_only_under_its_artefact_name_resolves_whole_through_a_stack() {
        let (dir, r) = project();
        let project = dir.path().join("project");
        std::fs::write(
            project.join("http_client.yaml"),
            "stack: http_client\nversion: 0.1.0\nexports:\n  request_in: http.request_in\n\
             modules:\n  - name: http\n    type: http\n    variant: exchange\n    port: 8080\n",
        )
        .unwrap();
        let graph = project.join("graph.yaml");
        std::fs::write(
            &graph,
            "modules:\n  - name: feeder\ninclude:\n  - stack: http_client.yaml\n    as: http_tls\n\
             wiring:\n  - from: feeder.data_out\n    to: http_tls.request_in\n",
        )
        .unwrap();
        let config = crate::stack_expand::load_graph(&graph, &project).expect("expands");
        let instance = config["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["type"] == "http")
            .and_then(|m| m["name"].as_str())
            .expect("the stack's http instance")
            .to_string();
        assert_ne!(instance, "http", "the include renames the instance");
        builds_whole(&config, &r, &instance);
    }
}
