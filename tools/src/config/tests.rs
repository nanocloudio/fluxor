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
    pub fn lock() -> std::sync::MutexGuard<'static, ()> {
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
        _lock: std::sync::MutexGuard<'static, ()>,
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

    // ---- F2: D9/D10 must read params from top-level OR nested `params:` ----

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
        // be rejected (D10) — the bypass the nested-only read used to miss.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}
        ]}});
        let modules = vec![json!({"name": "raft", "type": "raft_engine", "voter_count": 3})];
        let manifests = std::collections::HashMap::new();
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("D10 must reject multi-node raft on an adaptive domain");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("multi-node") && msg.contains("raft_engine"),
            "expected the multi-node raft rejection, got: {msg}"
        );
    }

    // ---- F3: malformed manifest must FAIL CLOSED on an adaptive domain ----

    #[test]
    fn malformed_manifest_fails_closed_on_adaptive_domain() {
        // `load_module_manifests_with_extra` only warns and OMITS a manifest that
        // fails to parse, so a typo in `timer_class` would downgrade to "no
        // manifest" and fail OPEN through the gate's `Some(man)` check. A
        // malformed manifest on an adaptive domain must instead fail CLOSED — we
        // cannot verify its timer_class.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("typo_mod");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        // Otherwise-valid manifest with an INVALID timer_class value → from_toml
        // errors → the loader would warn + omit it from the parsed map.
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\ntimer_class = \"tikc_counted\"\n",
        )
        .expect("write manifest");

        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}
        ]}});
        let modules = vec![json!({"name": "typo_mod", "type": "typo_mod"})];
        // Empty parsed map simulates the loader's warn-and-omit of the bad file.
        let manifests = std::collections::HashMap::new();
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = validate_adaptive_tick(
            &cfg, &modules, 100, &names, &ticks, &manifests, &extras, None,
        )
        .expect_err("a malformed manifest on an adaptive domain must fail closed");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("failed to parse") && msg.contains("typo_mod"),
            "expected fail-closed parse diagnostic naming the module, got: {msg}"
        );
    }

    // ---- High-1: timer-class admission is fail-closed for mechanism (b) ----

    #[test]
    fn manifestless_module_passes_on_idle_a_domain_but_blocks_on_cadence_b() {
        // (a)-only domain (flags=1): a genuinely manifest-less module is ADMITTED
        // — the lenient gate, since idle-relax alone doesn't warp a running module
        // (the per-timer-class gates below cover (a)'s hazards). (b) domain
        // (flags=3): the SAME module is BLOCKED — a module with no attested
        // timer class defaults to step_counted, which (b) would warp.
        let dir = tempfile::tempdir().expect("tempdir");
        // A resolvable module DIRECTORY with NO manifest.toml — the realistic
        // "genuinely manifest-less" case.
        std::fs::create_dir_all(dir.path().join("no_manifest_mod")).expect("mkdir");
        let modules = vec![json!({"name": "no_manifest_mod", "type": "no_manifest_mod"})];
        let manifests = std::collections::HashMap::new();
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let extras: Vec<&std::path::Path> = vec![dir.path()];

        let cfg_a = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        validate_adaptive_tick(
            &cfg_a, &modules, 100, &names, &ticks, &manifests, &extras, None,
        )
        .expect("manifest-less module must pass on a mechanism-(a)-only domain");

        let cfg_b = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 3,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let err = validate_adaptive_tick(
            &cfg_b, &modules, 100, &names, &ticks, &manifests, &extras, None,
        )
        .expect_err("manifest-less (unattested) module must be blocked on a (b) domain");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no manifest") && msg.contains("no_manifest_mod"),
            "expected unattested-block diagnostic, got: {msg}"
        );
    }

    #[test]
    fn unattested_manifest_blocked_on_cadence_b_domain() {
        // A module WITH a manifest but NO timer_class field defaults to Unattested
        // → blocked on a (b) domain. The map carries the parsed (Unattested) manifest.
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("plain".to_string(), Manifest::default()); // timer_class=Unattested
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 3,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let modules = vec![json!({"name": "plain", "type": "plain"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
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
            {"name": "main", "cores": [0], "adaptive_flags": 2,
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
        validate_adaptive_tick(&cfg, &modules, 3500, &names, &ticks, &manifests, &[], None)
            .expect("explicit burst deadline should govern adaptive floor admission");
    }

    #[test]
    fn attested_module_passes_on_cadence_b_domain() {
        // wall_clock and explicit agnostic both positively attest → admitted on (b).
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 3,
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
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .unwrap_or_else(|e| {
                    panic!("{} must pass on a (b) domain, got: {e:?}", tc.as_str())
                });
        }
    }

    #[test]
    fn step_period_ticks_blocked_on_cadence_b_unless_wallclock() {
        // A non-zero step_period_ticks is tick-counted, so it is blocked on a
        // (b) domain unless the module is wall_clock (agnostic does NOT
        // override it).
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 3,
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
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &m_blocked, &[], None)
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
        validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &m_ok, &[], None)
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
            {"name": "main", "cores": [0], "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ttl".to_string(), man.clone());
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("replicated_clock on (b) must be blocked without replica agreement");
        assert!(
            format!("{err:?}").contains("replicated_clock")
                && format!("{err:?}").contains("replica_agreed_cadence"),
            "expected the replicated-clock diagnostic naming the field that admits it, \
             got: {err:?}"
        );

        // With replica_agreed_cadence: true → passes (single node).
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000, "replica_agreed_cadence": true}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
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
            {"name": "main", "cores": [0], "adaptive_flags": 2,
             "tick_min_us": 100, "tick_max_us": 8000, "replica_agreed_cadence": true}]}});
        let mut manifests = std::collections::HashMap::new();
        manifests.insert("ttl".to_string(), man);
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("replicated_clock on (b) multi-node must be blocked");
        assert!(
            format!("{err:?}").contains("multi-node"),
            "expected multi-node diagnostic, got: {err:?}"
        );
    }

    #[test]
    fn multi_graph_pods_exceeding_pacer_table_rejected() {
        // Resident graphs (base + `pods:`) × domains must fit the kernel's
        // static GRAPH_PACERS table (16 slots). A base
        // graph (1 domain) plus 16 single-domain pods = 17 instances → reject.
        let modules = vec![json!({"name": "m", "type": "passthrough"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let manifests = std::collections::HashMap::new();
        let domain = json!({
            "name": "main", "cores": [0], "adaptive_flags": 1,
            "tick_min_us": 100, "tick_max_us": 8000
        });
        let pods_over: Vec<_> = (0..16)
            .map(|i| json!({"modules": [{"name": format!("p{i}"), "type": "passthrough", "domain": 0}]}))
            .collect();
        let cfg_over = json!({"execution": {"domains": [domain.clone()]}, "pods": pods_over});
        // resolved_target None ⇒ event-driven (Linux); skips the bcm wake-policy
        // gate so this isolates the pacer-table gate.
        let err = validate_adaptive_tick(
            &cfg_over,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
        )
        .expect_err("17 (graph,domain) pacer instances must exceed the 16-slot table");
        assert!(
            format!("{err:?}").contains("pacer table")
                && format!("{err:?}").contains("MAX_GRAPH_PACERS"),
            "expected the pacer-table overflow diagnostic, got: {err:?}"
        );

        // 3 pods → 1 (base) + 3 = 4 instances → fits.
        let pods_ok: Vec<_> = (0..3)
            .map(|i| json!({"modules": [{"name": format!("p{i}"), "type": "passthrough", "domain": 0}]}))
            .collect();
        let cfg_ok = json!({"execution": {"domains": [domain]}, "pods": pods_ok});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
        )
        .expect("4 (graph,domain) pacer instances must fit the 16-slot table");
    }

    #[test]
    fn multi_graph_pods_overflow_rejected_without_adaptive_flags() {
        // The pacer-table gate must run even when NO domain sets adaptive_flags:
        // the runtime keys/steps the resident-graph table for any multi-graph
        // config (fixed-tick too), so an overflowing `pods:` set with no adaptive
        // flags must still be rejected, not silently dropped at runtime.
        let modules = vec![json!({"name": "m", "type": "passthrough"})];
        let names = vec!["main".to_string()];
        let ticks = vec![100u16];
        let manifests = std::collections::HashMap::new();
        // domain with NO adaptive_flags (fixed-tick).
        let domain = json!({"name": "main", "cores": [0]});
        let pods_over: Vec<_> = (0..16)
            .map(|i| json!({"modules": [{"name": format!("p{i}"), "type": "passthrough", "domain": 0}]}))
            .collect();
        let cfg_over = json!({"execution": {"domains": [domain.clone()]}, "pods": pods_over});
        let err = validate_adaptive_tick(
            &cfg_over,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
        )
        .expect_err("17 fixed-tick pacer instances must still exceed the 16-slot table");
        assert!(
            format!("{err:?}").contains("pacer table")
                && format!("{err:?}").contains("MAX_GRAPH_PACERS"),
            "expected the pacer-table overflow diagnostic even with no adaptive \
             flags, got: {err:?}"
        );

        // 2 fixed-tick pods → 1 + 2 = 3 instances → fits.
        let pods_ok: Vec<_> = (0..2)
            .map(|i| json!({"modules": [{"name": format!("p{i}"), "type": "passthrough", "domain": 0}]}))
            .collect();
        let cfg_ok = json!({"execution": {"domains": [domain]}, "pods": pods_ok});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
        )
        .expect("3 fixed-tick pacer instances must fit the 16-slot table");
    }

    #[test]
    fn multi_graph_isr_tier_pod_rejected() {
        // A pod module placed in an ISR-tier domain (tier 1b/2) must be rejected
        // at emit time — the FLXA codec carries no ISR metadata and pod admission
        // runs after ISR registration, so it would never execute.
        let tmp = std::env::temp_dir();
        // Domain 1 is tier 1b (isr_timer, exec_mode 2); domain 0 cooperative.
        let cfg_isr = json!({
            "execution": {"domains": [
                {"name": "coop", "cores": [0]},
                {"name": "isrd", "cores": [1], "tier": "1b"}
            ]},
            "pods": [{"modules": [{"name": "p", "type": "pod_pic_mod", "domain": "isrd"}]}]
        });
        let err = build_pod_section(&cfg_isr, &tmp, &[])
            .expect_err("an ISR-tier pod placement must be rejected");
        assert!(
            format!("{err:?}").contains("ISR-tier"),
            "expected the ISR-tier pod rejection diagnostic, got: {err:?}"
        );

        // Same module in the cooperative domain is accepted (reaches schema/emit).
        let cfg_ok = json!({
            "execution": {"domains": [
                {"name": "coop", "cores": [0]},
                {"name": "isrd", "cores": [1], "tier": "1b"}
            ]},
            "pods": [{"modules": [{"name": "p", "type": "pod_pic_mod", "domain": "coop"}]}]
        });
        build_pod_section(&cfg_ok, &tmp, &[])
            .expect("a cooperative-domain pod placement must be accepted");
    }

    #[test]
    fn multi_graph_duplicate_pod_local_name_rejected() {
        // Two modules sharing a pod-local name would silently overwrite the
        // wiring map (`name_to_local`) and mis-route edges. Must be rejected.
        let tmp = std::env::temp_dir();
        let cfg = json!({
            "execution": {"domains": [{"name": "coop", "cores": [0]}]},
            "pods": [{"modules": [
                {"name": "dup", "type": "pod_pic_mod", "domain": "coop"},
                {"name": "dup", "type": "pod_pic_mod2", "domain": "coop"}
            ]}]
        });
        let err = build_pod_section(&cfg, &tmp, &[])
            .expect_err("duplicate pod-local module names must be rejected");
        assert!(
            format!("{err:?}").contains("duplicate module name"),
            "expected the duplicate-name diagnostic, got: {err:?}"
        );
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
            {"name": "main", "cores": [0], "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 50000}]}});
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("idle widen past the emission interval must be blocked");
        assert!(
            format!("{err:?}").contains("emission interval"),
            "expected emission-interval clamp diagnostic, got: {err:?}"
        );

        // tick_max_us=8000 < 50 ms → passes.
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 1,
             "tick_min_us": 100, "tick_max_us": 8000}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
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
            {"name": "main", "cores": [0], "adaptive_flags": 2,
             "tick_min_us": 1000, "tick_max_us": 8000}]}});
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("guaranteed on (b) must be blocked without WCET re-validation");
        assert!(
            format!("{err:?}").contains("guaranteed_wcet_revalidated"),
            "expected the WCET re-validation diagnostic, got: {err:?}"
        );

        // With the assertion → passes (burst-at-floor still enforced: 50×8=400 ≤ 16×1000).
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 2, "tick_min_us": 1000,
             "tick_max_us": 8000, "guaranteed_wcet_revalidated": true}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
        )
        .expect("guaranteed on (b) must pass once WCET re-validation is asserted");
    }

    #[test]
    fn domain0_unbounded_tick_max_blocked_in_multi_domain() {
        // Domain 0 alone advances the shared DBG_TICK; in a
        // multi-domain config on a DBG_TICK-backed target, an unbounded
        // (tick_max_us=0) adaptive domain 0 stalls sibling-domain tick reads.
        let modules = vec![json!({"name": "m", "type": "m"})];
        let names = vec!["d0".to_string(), "d1".to_string()];
        let ticks = vec![100u16, 100u16];
        let manifests = std::collections::HashMap::new();

        // Two domains, domain 0 adaptive with NO tick_max_us → blocked on bcm2712.
        let cfg = json!({"execution": {"domains": [
            {"name": "d0", "cores": [0], "adaptive_flags": 1, "tick_min_us": 100},
            {"name": "d1", "cores": [1]}]}});
        let err = validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            Some("bcm2712"),
        )
        .expect_err("unbounded domain-0 adaptive in a multi-domain bcm2712 config must be blocked");
        assert!(
            format!("{err:?}").contains("domain 0") && format!("{err:?}").contains("tick_max_us"),
            "expected the unbounded domain-0 diagnostic, got: {err:?}"
        );

        // Bounded tick_max_us on domain 0 → passes.
        // bcm idle requires an execution-level `bcm_wake_policy` declaration.
        let cfg_ok = json!({"execution": {
            "bcm_wake_policy": "clamp",
            "domains": [
                {"name": "d0", "cores": [0], "adaptive_flags": 1, "tick_min_us": 100,
                 "tick_max_us": 8000},
                {"name": "d1", "cores": [1]}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            Some("bcm2712"),
        )
        .expect("bounded domain-0 adaptive must pass");

        // rp2350 is exempt (wall-clock HAL) — unbounded passes there.
        validate_adaptive_tick(
            &cfg,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            Some("rp2350"),
        )
        .expect("rp2350 is exempt from the DBG_TICK domain-0 gate");
    }

    #[test]
    fn adaptive_domain_sharing_runner_with_strict_domain_is_rejected() {
        // An adaptive domain sharing a core with a timing-strict domain (here
        // raft liveness) is rejected: the adaptive domain's pacing would warp
        // the strict domain's cadence, so sharing a runner is refused.
        let names = vec!["main".to_string(), "rt".to_string()];
        let ticks = vec![100u16, 100u16];
        let manifests = std::collections::HashMap::new();
        let modules = vec![json!({"name": "raft_engine", "type": "raft_engine", "domain": "rt"})];

        // Both on core 0 → shared runner → reject.
        let cfg = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 2, "tick_min_us": 100, "tick_max_us": 8000},
            {"name": "rt", "cores": [0]}]}});
        let err =
            validate_adaptive_tick(&cfg, &modules, 100, &names, &ticks, &manifests, &[], None)
                .expect_err("adaptive + strict on the same core must be rejected");
        assert!(
            format!("{err:?}").contains("shares a runner"),
            "expected shared-runner diagnostic, got: {err:?}"
        );

        // Strict domain on its own core (1) → no overlap → passes.
        let cfg_ok = json!({"execution": {"domains": [
            {"name": "main", "cores": [0], "adaptive_flags": 2, "tick_min_us": 100, "tick_max_us": 8000},
            {"name": "rt", "cores": [1]}]}});
        validate_adaptive_tick(
            &cfg_ok,
            &modules,
            100,
            &names,
            &ticks,
            &manifests,
            &[],
            None,
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
        // can't be encoded in the 4-slot domain metadata + the
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

    // ---- parse_domain_tier_to_exec_mode ----

    #[test]
    fn tier_friendly_strings_map_to_exec_mode_bytes() {
        // The byte mapping is wire-stable — adding tiers must preserve
        // existing values. This test pins the {0,1,2,3,4} table.
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "cooperative"})),
            Some(0)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "1a"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "1b"})),
            Some(2),
            "Tier 1b → exec_mode 2"
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "3"})),
            Some(3)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"tier": "2"})),
            Some(4),
            "Tier 2 → exec_mode 4 — the byte order deliberately does not \
             follow the tier names"
        );
    }

    #[test]
    fn legacy_exec_mode_field_still_parses() {
        // `exec_mode:` is an accepted alias spelling of `tier:`, with its
        // own synonym set (`tier1a`, `high_rate`, `poll`, …). Both keys
        // resolve to the same exec_mode bytes.
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "tier1a"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "high_rate"})),
            Some(1)
        );
        assert_eq!(
            parse_domain_tier_to_exec_mode(&json!({"exec_mode": "poll"})),
            Some(3)
        );
    }

    #[test]
    fn unknown_tier_string_returns_none() {
        // Caller is responsible for hard-failing on a None when the
        // YAML actually had a `tier` / `exec_mode` field — silent
        // fall-through to Tier 0 would mask typos.
        assert!(parse_domain_tier_to_exec_mode(&json!({"tier": "1c"})).is_none());
        assert!(parse_domain_tier_to_exec_mode(&json!({"exec_mode": "real-time"})).is_none());
    }

    #[test]
    fn no_tier_field_returns_none_for_default() {
        assert!(parse_domain_tier_to_exec_mode(&json!({"name": "d"})).is_none());
    }

    #[test]
    fn exec_mode_wire_bytes_locked_against_rfc_d5_table() {
        // The FULL `(string → byte)` mapping, pinned. These bytes are a
        // wire contract: a `.cfg.bin` blob carries the byte, and the kernel
        // reads it back through `scheduler::exec_mode::*`, so a changed
        // mapping silently mis-routes domains. Failing this test means the
        // table or one of its synonyms moved, which needs a coordinated
        // kernel + tools + docs change.
        let pairs: &[(&str, u8)] = &[
            ("cooperative", 0),
            ("0", 0),
            ("1a", 1),
            ("high_rate", 1),
            ("tier1a", 1),
            ("1b", 2),
            ("isr_timer", 2),
            ("tier1b", 2),
            ("3", 3),
            ("poll", 3),
            ("tier3", 3),
            ("2", 4),
            ("isr_owned", 4),
            ("tier2", 4),
        ];
        for (s, expected) in pairs {
            assert_eq!(
                parse_domain_tier_to_exec_mode(&json!({"tier": s})),
                Some(*expected),
                "WIRE-FORMAT BREAK: tier `{s}` must map to byte \
                 {expected}. These bytes are a locked wire contract and \
                 can only be changed in lockstep with the kernel-side \
                 `scheduler::exec_mode::*` constants."
            );
        }
    }

    #[test]
    fn exec_mode_bare_numeric_only_accepts_zero() {
        // Numeric form is intentionally narrow (YAML can't
        // distinguish `tier: 1` from a 1a vs 1b string). Only `0`
        // resolves; everything else must return None so the operator
        // sees a hard error instead of a silent fall-through.
        assert_eq!(parse_domain_tier_to_exec_mode(&json!({"tier": 0})), Some(0));
        for n in [1u64, 2, 3, 4, 5, 7, 100] {
            assert_eq!(
                parse_domain_tier_to_exec_mode(&json!({"tier": n})),
                None,
                "bare numeric tier {n} must NOT silently parse — \
                 only the friendly-string form is allowed for non-zero \
                 tiers."
            );
        }
    }

    // ---- validate_isr_tier_admission ----
    //
    // These tests exercise the validator directly with synthetic
    // manifests. Going through the full `fluxor build` path would
    // require a populated modules tree; the validator's contract is
    // narrow enough to test in isolation.

    fn run_admission(config: serde_json::Value, modules: Vec<serde_json::Value>) -> Result<()> {
        // Use a path that surely doesn't exist so `load_module_
        // manifests_with_extra` finds nothing. The validator handles
        // the missing-manifest case by skipping the isr_safe check
        // (the wiring/manifest validator surfaces missing-manifest
        // errors separately), so for the unknown-tier-and-typed-edge
        // tests we don't need a real manifest. The cases that DO
        // need a manifest plant fake ones via an `extra_module_dirs`
        // tempdir — see the dedicated tests below.
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = Vec::new();
        validate_isr_tier_admission(&config, &modules, modules_dir, &extras, None, modules_dir)
    }

    #[test]
    fn admission_passes_when_no_isr_tier_domains_present() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1a"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        run_admission(cfg, modules).expect("cooperative graph admits");
    }

    #[test]
    fn admission_rejects_unknown_tier_string() {
        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1c"}]}
        });
        let modules = vec![json!({"name": "m", "type": "x", "domain": "main"})];
        let err = run_admission(cfg, modules).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unknown tier") && msg.contains("1a/high_rate"),
            "expected unknown-tier diagnostic naming valid values, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_tier2_irq_beyond_gic_intid_range() {
        // GIC-400 INTIDs are 0..=1019; an `irq:` past that would index the
        // distributor's enable/priority/target banks out of range on silicon.
        let cfg = json!({
            "target": "pi5",
            "execution": {"domains": [{"name": "isr", "tier": "2"}]}
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
    fn admission_allows_tier2_sgi_irq_on_gic() {
        // SGI 15 is a legitimate Tier-2 owner (the `tier2_probe` SGI path); the
        // range check must NOT reject it. Any other error (missing manifest,
        // etc.) is fine here — just not the range diagnostic.
        let cfg = json!({
            "target": "pi5",
            "execution": {"domains": [{"name": "isr", "tier": "2"}]}
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
    fn admission_rejects_tier2_irq_beyond_rp2350_nvic_range() {
        // RP2350 NVIC tops out at SWI_IRQ_5 = 52 (0..=52); a far-larger value
        // would unmask a non-existent line and index NVIC registers out of
        // bounds. (Tests pass no resolved_target, so Rule 0 falls back to
        // config.target.)
        let cfg = json!({
            "target": "rp2350",
            "execution": {"domains": [{"name": "isr", "tier": "2"}]}
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
            "execution": {"domains": [{"name": "isr", "tier": "2"}]}
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
            "execution": {"domains": [{"name": "isr", "tier": "2"}]}
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
    fn admission_rejects_tier_1b_module_without_isr_safe_manifest() {
        // Tier 1b is admitted as of 2026-05-26 — but only for modules
        // that declare `isr_safe = true` in their manifest. A module
        // without the attestation must be rejected with a precise
        // diagnostic pointing at the offending manifest path.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("unflagged");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\nisr_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules =
            vec![json!({"name": "unflagged", "type": "unflagged", "domain": "audio_isr"})];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("unflagged module in Tier 1b domain must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("isr_safe = true") && msg.contains("unflagged"),
            "diagnostic must name the missing attestation + the module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_tier_1b_module_with_no_resolvable_manifest() {
        // An ISR-tier module that does not resolve to a manifest (typo
        // in `type:`, missing module dir, build-tree not on the search
        // path) must be refused by `validate_isr_tier_admission` itself,
        // not left to `validate_wiring_types`. That validator enforces
        // content types only when **both** endpoints have manifests, so
        // a Tier 1b module with no edges (or bare/default ports) passes
        // it untouched and lands in the graph without ever running
        // through the `isr_safe` check or the NEON-import lint.
        //
        // Hard-error here so the operator gets a single, focused
        // diagnostic naming the unresolved module rather than a
        // silent admission followed by a runtime trap.
        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules = vec![json!({
            "name": "ghost_module",
            "type": "definitely_not_a_real_module_type_xyz",
            "domain": "audio_isr",
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = Vec::new();
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("Tier 1b module with no resolvable manifest must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("ghost_module") && msg.contains("manifest"),
            "diagnostic must name the unresolved module + the missing manifest, got: {msg}"
        );
    }

    #[test]
    fn admission_priority_module_search_paths_extra_dir_shadows_standard_tree() {
        // `extract_module_search_paths` returns a *priority-ordered*
        // list with explicit YAML `module_search_paths:` entries
        // first, and the manifest loader
        // (`load_module_manifests_with_extra`) and the ISR NEON-lint
        // must both honour that order. Were either to search
        // `standard_module_dirs()` first, a config-declared override
        // colliding with a bundled module of the same `type:` would
        // have ISR admission read `isr_safe` and scan source from the
        // bundled copy — silently admitting a module the operator had
        // explicitly redirected to a vetted vendor tree.
        //
        // This test plants the *same* type name twice:
        //   - standard tree (`<project>/modules/foundation/coll/`)
        //     declares `isr_safe = true` and a NEON-free src tree.
        //   - extra dir (`<override>/coll/`) declares
        //     `isr_safe = true` but imports NEON in its src.
        //
        // If standard wins, admission passes (wrong). If the
        // extra dir wins, the NEON lint fires.
        let project = tempfile::tempdir().expect("tempdir-project");
        let extra = tempfile::tempdir().expect("tempdir-extra");
        let _env = super::test_env::EnvGuard::set(&[("FLUXOR_PROJECT_ROOT", project.path())]);

        let std_dir = project.path().join("modules/foundation/coll");
        let std_src = std_dir.join("src");
        std::fs::create_dir_all(&std_src).expect("mkdir std");
        std::fs::write(
            std_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write std manifest");
        std::fs::write(std_src.join("lib.rs"), "fn unused() {}\n").expect("write std src");

        let ovr_dir = extra.path().join("coll");
        let ovr_src = ovr_dir.join("src");
        std::fs::create_dir_all(&ovr_src).expect("mkdir override");
        std::fs::write(
            ovr_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write override manifest");
        std::fs::write(
            ovr_src.join("lib.rs"),
            "use core::arch::aarch64::*;\nfn unused() {}\n",
        )
        .expect("write override src");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules = vec![json!({
            "name": "coll",
            "type": "coll",
            "domain": "audio_isr",
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![extra.path()];
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("extras-first lookup must surface the NEON-importing override");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("NEON") && msg.contains("coll"),
            "extras must shadow the standard tree — NEON lint should fire on the override, got: {msg}"
        );
    }

    #[test]
    fn admission_accepts_tier_2_module_with_isr_entry_export() {
        // A Tier 2 (`tier: 2` / `isr_owned`) module declaring
        // `isr_safe = true`, an `irq:`, and a real `module_isr_entry`
        // export is admitted.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "tier": "2"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect("Tier 2 module exporting module_isr_entry must be admitted");
    }

    #[test]
    fn admission_rejects_tier_2_module_without_isr_entry_export() {
        // A Tier 2 module that declares `isr_safe = true` + `irq:` but
        // whose source exports no `module_isr_entry` is rejected: the
        // kernel would refuse to dispatch its cooperative `module_step`
        // from IRQ context, so surface the gap loudly at build time.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        // Source has no `fn module_isr_entry` definition.
        std::fs::write(
            src.join("lib.rs"),
            "fn module_step(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "tier": "2"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
            "irq": 42,
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("Tier 2 module without module_isr_entry must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("module_isr_entry") && msg.contains("irq_driver"),
            "diagnostic must name the missing export + the offending module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_tier_2_module_without_irq() {
        // A Tier 2 module that has the ISR entry but no `irq:` field is
        // rejected by Rule 3 — the kernel has no IRQ vector to bind.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("irq_driver");
        let src = mod_dir.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            "#[no_mangle]\npub extern \"C\" fn module_isr_entry(_s: *mut u8) -> i32 { 0 }\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "irq_owner", "tier": "2"}]}
        });
        let modules = vec![json!({
            "name": "irq_driver",
            "type": "irq_driver",
            "domain": "irq_owner",
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("Tier 2 module without irq: must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("irq") && msg.contains("irq_driver"),
            "diagnostic must name the missing irq field + the module, got: {msg}"
        );
    }

    #[test]
    fn admission_neon_lint_finds_standard_tree_modules_too() {
        // The NEON-import lint must find a module's src root wherever
        // its manifest resolved from, `standard_module_dirs()`
        // included. A lint searching only `modules_dir +
        // extra_module_dirs` would never run `check_isr_safe_no_neon`
        // against a module under `modules/drivers/<name>`, which would
        // then pass admission silently. This test plants an
        // `isr_safe = true` module with a NEON import in a fake
        // project root and asserts the lint catches it.
        let project = tempfile::tempdir().expect("tempdir");
        // `standard_module_dirs()` reads `$FLUXOR_PROJECT_ROOT`
        // dynamically. Use the shared file-scope env lock + Drop
        // guard so this test (a) does not race the sibling
        // `module_discovery_tests` (which also mutates this var)
        // and (b) restores the original value even on panic.
        let _env = super::test_env::EnvGuard::set(&[("FLUXOR_PROJECT_ROOT", project.path())]);
        // Plant a driver under modules/drivers/<name>/ with both a
        // manifest and a NEON-importing src tree.
        let drivers = project.path().join("modules/drivers/neon_isr_module");
        let src = drivers.join("src");
        std::fs::create_dir_all(&src).expect("mkdir");
        std::fs::write(
            drivers.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        std::fs::write(
            src.join("lib.rs"),
            // The lint scans .rs files for marker substrings.
            "use core::arch::aarch64::*;\nfn unused() {}\n",
        )
        .expect("write src");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules = vec![json!({
            "name": "neon_isr_module",
            "type": "neon_isr_module",
            "domain": "audio_isr",
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = Vec::new();
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("standard-tree NEON-importing ISR module must be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("NEON")
                && (msg.contains("neon_isr_module") || msg.contains("core::arch::aarch64")),
            "diagnostic must name NEON + the offending module/source, got: {msg}"
        );
        // `_env` drops here, restoring `FLUXOR_PROJECT_ROOT` and
        // releasing the file-scope env lock.
    }

    #[test]
    fn build_module_entry_emits_pre_tick_bit_from_extra_dir_manifest() {
        // `build_module_entry` must read the manifest it was given,
        // not re-find one. Resolving through `Manifest::from_source_tree`
        // — which searches a hard-coded `SOURCE_DIRS` list relative to
        // the process cwd — would let a manifest living in
        // `extra_module_dirs` (an installed driver, say) pass validation
        // and still emit a config blob with byte-9 bit 4 clear, silently
        // demoting the module out of `domain_pre_tick_order`.
        //
        // This test plants a `pre_tick_drain = true` manifest in a
        // tempdir, feeds the dir as an extra, and asserts the bit
        // lands in the emitted module entry.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("ext_drainer");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\n\
             pre_tick_drain = true\n",
        )
        .expect("write manifest");

        let modules_value = json!([{
            "name": "ext_drainer",
            "type": "ext_drainer",
        }]);
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let manifests = load_module_manifests_with_extra(&modules_value, &extras, dir.path());
        assert!(
            manifests
                .get("ext_drainer")
                .is_some_and(|m| m.pre_tick_drain),
            "loader must find the extra-dir manifest with pre_tick_drain = true"
        );

        let config = json!({});
        let module = json!({"name": "ext_drainer", "type": "ext_drainer"});
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let entry = build_module_entry(
            "ext_drainer",
            &module,
            0,
            None,
            &config,
            modules_dir,
            &manifests,
            crate::capacity::kernel_max_modules("linux"),
        )
        .expect("emit module entry");
        // Entry layout (see `parse_module_entry`): bytes 0-3 =
        // length, bytes 4-7 = name_hash, byte 8 = id, byte 9 = the
        // multiplexed domain/pre-tick byte (bits 0-2 = domain_id,
        // bit 4 = pre_tick_drain).
        let byte9 = entry[9];
        assert_eq!(
            byte9 & 0x10,
            0x10,
            "byte-9 bit 4 (pre_tick_drain) must be SET when the resolved \
             manifest has pre_tick_drain = true (got byte9 = 0x{byte9:02x})"
        );
        assert_eq!(
            byte9 & 0x07,
            0,
            "byte-9 bits 0-2 (domain_id) should be 0 (no domain assigned in YAML)"
        );
    }

    #[test]
    fn target_aware_manifest_loader_resolves_silicon_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("sized_stream");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\n\
             [[ports]]\nname = \"stream_out\"\ndirection = \"output\"\n\
             content_type = \"OctetStream\"\n\
             buffer_size = { default = 2048, bcm2712 = 8192 }\n",
        )
        .expect("write manifest");

        let modules = json!([{"name": "sized_stream", "type": "sized_stream"}]);
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let default_manifest = load_module_manifests_with_extra(&modules, &extras, dir.path());
        let bcm_manifest = load_module_manifests_with_extra_for_target(
            &modules,
            &extras,
            Some("bcm2712"),
            dir.path(),
        );

        assert_eq!(default_manifest["sized_stream"].ports[0].buffer_size, 2048);
        assert_eq!(bcm_manifest["sized_stream"].ports[0].buffer_size, 8192);
    }

    #[test]
    fn admission_accepts_tier_1b_module_with_isr_safe_manifest() {
        // Mirror of the rejection case: when the manifest declares
        // `isr_safe = true`, the Tier 1b admission path lets the module
        // through. This pins the lift that happened on 2026-05-26.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("attested_isr");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "audio_isr", "tier": "1b"}]}
        });
        let modules = vec![json!({
            "name": "attested_isr",
            "type": "attested_isr",
            "domain": "audio_isr",
        })];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect("isr_safe = true module in Tier 1b domain must be admitted");
    }

    #[test]
    fn admission_rejects_any_edge_touching_isr_tier_module() {
        // v1 reality (2026-05-26): ANY edge with an ISR-tier
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
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        let producer_dir = dir.path().join("plain_producer");
        std::fs::create_dir_all(&producer_dir).expect("mkdir");
        std::fs::write(
            producer_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = false\n",
        )
        .expect("write manifest");

        // Even an untagged (`local`) edge into a Tier 1b module is
        // rejected — the bridge ABI gap is independent of edge_class.
        let cfg = json!({
            "execution": {
                "domains": [
                    {"name": "main", "tier": "0"},
                    {"name": "audio_isr", "tier": "1b"},
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
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        let err = validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("untagged edge into Tier 1b module must still be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("ISR-tier endpoint")
                && msg.contains("module-facing API")
                && msg.contains("attested_isr"),
            "diagnostic must name the gap + the offending module, got: {msg}"
        );
    }

    #[test]
    fn admission_rejects_dma_owned_edge_into_isr_tier_module_too() {
        // The catch-all rejection above subsumes the previous
        // edge_class-specific check; pin the diagnostic still
        // surfaces clearly when the operator added an explicit
        // `dma_owned` tag.
        let dir = tempfile::tempdir().expect("tempdir");
        let isr_dir = dir.path().join("attested_isr");
        std::fs::create_dir_all(&isr_dir).expect("mkdir");
        std::fs::write(
            isr_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = true\n",
        )
        .expect("write manifest");
        let prod_dir = dir.path().join("plain_producer");
        std::fs::create_dir_all(&prod_dir).expect("mkdir");
        std::fs::write(
            prod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"bcm2712\"]\nisr_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [
                {"name": "main", "tier": "0"},
                {"name": "audio_isr", "tier": "1b"},
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
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect_err("dma_owned edge into Tier 1b module rejected (subsumed by ISR-edge rule)");
    }

    #[test]
    fn admission_accepts_tier_1a_cooperative_with_isr_safe_field_present() {
        // Cooperative tiers (0/1a/3) are unaffected by the
        // Tier 1b/2 admission gate — the `isr_safe` manifest flag is
        // simply ignored for non-ISR-tier domains. Catches a
        // regression where the gate goes too broad.
        let dir = tempfile::tempdir().expect("tempdir");
        let mod_dir = dir.path().join("plain_mod");
        std::fs::create_dir_all(&mod_dir).expect("mkdir");
        std::fs::write(
            mod_dir.join("manifest.toml"),
            "version = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\nisr_safe = false\n",
        )
        .expect("write manifest");

        let cfg = json!({
            "execution": {"domains": [{"name": "main", "tier": "1a"}]}
        });
        let modules = vec![json!({"name": "plain_mod", "type": "plain_mod", "domain": "main"})];
        let modules_dir = std::path::Path::new("/nonexistent/modules");
        let extras: Vec<&std::path::Path> = vec![dir.path()];
        validate_isr_tier_admission(&cfg, &modules, modules_dir, &extras, None, modules_dir)
            .expect("cooperative tier with isr_safe=false on its modules is fine");
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
#[allow(
    clippy::undocumented_unsafe_blocks,
    reason = "test scaffolding wraps std::env::{set_var, remove_var} which became `unsafe fn` in Rust 2024; safety is identical at every call site — the tests serialise on the module-level mutex"
)]
mod module_discovery_tests {
    //! Tests for the dual-root module manifest discovery added on
    //! top of the project/install root resolver. Verifies that
    //! `load_module_manifests_with_extra` finds modules under the
    //! install root when the project root lacks them (the
    //! "external user project pulls bundled modules" path), and
    //! that the project root wins on duplicate names (the "user
    //! overrides bundled" path).

    use super::*;

    /// Shared env-var lock — the project resolver reads
    /// `$FLUXOR_PROJECT_ROOT` / `$FLUXOR_INSTALL_ROOT` and these
    /// tests mutate both. The lock itself lives at file scope (see
    /// `super::test_env`) so the sibling `scheduler_validation_tests`
    /// module — which also mutates `$FLUXOR_PROJECT_ROOT` — shares
    /// the same mutex and we do not race across modules.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        super::test_env::lock()
    }

    /// Set up a tree under `root` with a manifest at
    /// `root/modules/foundation/<name>/manifest.toml`. Used to
    /// synthesise both project and install roots for these tests
    /// without depending on the real source tree.
    fn plant_manifest(root: &std::path::Path, name: &str, isr_safe: bool) {
        let dir = root.join("modules/foundation").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let body = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\nhardware_targets = [\"rp2350\"]\nisr_safe = {isr_safe}\n",
        );
        std::fs::write(dir.join("manifest.toml"), body).unwrap();
    }

    /// Install the `.fluxor` marker + a stub `targets/` + `stacks/`
    /// so `discover()` and `install_root()` accept the path.
    fn mark_project(root: &std::path::Path) {
        std::fs::write(root.join(".fluxor"), b"").unwrap();
    }

    fn mark_install(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("stacks")).unwrap();
        std::fs::create_dir_all(root.join("targets")).unwrap();
    }

    #[test]
    fn finds_module_in_install_root_when_project_lacks_it() {
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        // Only the install root has the manifest.
        plant_manifest(install.path(), "bundled_mod", true);

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        let modules = json!([{"name": "bundled_mod", "type": "bundled_mod"}]);
        let manifests = load_module_manifests_with_extra(&modules, &[], install.path());
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }
        let m = manifests
            .get("bundled_mod")
            .expect("install-root manifest must be discoverable");
        assert!(m.isr_safe, "manifest content round-trips");
    }

    #[test]
    fn project_root_module_shadows_install_root_module() {
        // Both roots carry the manifest under the same name. The
        // project root's version must win — `isr_safe = true` in
        // project, `false` in install. After loading, the result
        // must reflect the project version.
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        plant_manifest(project.path(), "shared_mod", true);
        plant_manifest(install.path(), "shared_mod", false);

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        let modules = json!([{"name": "shared_mod", "type": "shared_mod"}]);
        let manifests = load_module_manifests_with_extra(&modules, &[], install.path());
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }
        let m = manifests.get("shared_mod").expect("must find shared_mod");
        assert!(
            m.isr_safe,
            "expected project-root manifest (isr_safe=true) to shadow install-root manifest, got isr_safe=false"
        );
    }

    #[test]
    fn extract_module_search_paths_includes_install_root_modules() {
        let _g = env_lock();
        let project = tempfile::tempdir().unwrap();
        let install = tempfile::tempdir().unwrap();
        mark_project(project.path());
        mark_install(install.path());
        // Create a `modules/` dir in install so the returned path
        // canonicalises to an existing location.
        std::fs::create_dir_all(install.path().join("modules")).unwrap();

        unsafe {
            std::env::set_var(crate::project::ENV_PROJECT_ROOT, project.path());
            std::env::set_var(crate::project::ENV_INSTALL_ROOT, install.path());
        }
        // Place the config inside the project tree so the
        // <config-parent>/../modules default doesn't accidentally
        // land at a path that masks the install/modules entry.
        let cfg_path = project.path().join("cfg/dummy.yaml");
        std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
        let cfg = json!({});
        let paths = extract_module_search_paths(&cfg, &cfg_path);
        unsafe {
            std::env::remove_var(crate::project::ENV_PROJECT_ROOT);
            std::env::remove_var(crate::project::ENV_INSTALL_ROOT);
        }

        let install_modules = install.path().join("modules").canonicalize().unwrap();
        assert!(
            paths.contains(&install_modules),
            "install-root modules dir must appear in the search-paths surface; got {paths:?}"
        );
    }
}

#[cfg(test)]
mod continuity_tests {
    //! Tests for the `continuity` block validator: continuity classes as
    //! a validated graph property.

    use super::*;

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

    /// Every other policy, and a graph with no policy at all, is
    /// unaffected — the gate is specific to the resuming one.
    #[test]
    fn fault_policy_gate_ignores_the_other_policies() {
        let mut m = HashMap::new();
        m.insert("a".to_string(), man(&[]));
        let n = names(&["a"]);
        validate_fault_policy(&json!({}), &n, &m).unwrap();
        for policy in ["skip", "restart_graph", "tolerate"] {
            let cfg = json!({"modules": [{"name": "a", "fault_policy": policy}]});
            validate_fault_policy(&cfg, &n, &m).unwrap();
        }
        // A module with no manifest in the resolved set is not gated,
        // matching every other validator in this file.
        let cfg = json!({"modules": [{"name": "a", "fault_policy": "restart"}]});
        validate_fault_policy(&cfg, &n, &HashMap::new()).unwrap();
    }

    #[test]
    fn single_provider_allows_distinct_and_absent_providers() {
        // A graph with no `provides` anywhere is unaffected.
        let mut m = HashMap::new();
        m.insert("a".to_string(), man(&[]));
        validate_single_provider(&json!({}), &names(&["a"]), &m).unwrap();

        // Two modules providing DIFFERENT surfaces coexist: a block
        // driver under a filesystem is the normal storage stack.
        let mut m = HashMap::new();
        m.insert("nvme".to_string(), prov(&["storage.block"]));
        m.insert(
            "fat32".to_string(),
            prov(&["file.data", "storage.namespace"]),
        );
        validate_single_provider(&json!({}), &names(&["nvme", "fat32"]), &m).unwrap();
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
        let e = validate_single_provider(&json!({}), &names(&["fat32_a", "fat32_b"]), &m)
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
        // `storage.block` is not class-byte dispatched (block drivers wire by
        // port name), so two block providers do NOT shadow — an SD card + a
        // flash blob store is a legitimate composition, not an error.
        let mut m = HashMap::new();
        m.insert("sd".to_string(), prov(&["storage.block"]));
        m.insert("flash_rp".to_string(), prov(&["storage.block"]));
        validate_single_provider(&json!({}), &names(&["sd", "flash_rp"]), &m).unwrap();
    }

    #[test]
    fn single_provider_module_may_list_a_surface_without_self_shadowing() {
        // The same module appearing once with a surface is not a
        // duplicate against itself.
        let mut m = HashMap::new();
        m.insert("fat32".to_string(), prov(&["file.data", "file.data"]));
        validate_single_provider(&json!({}), &names(&["fat32"]), &m).unwrap();
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
        m.insert("mount".to_string(), prov(&["file.data", "storage.namespace"]));
        let cfg = json!({"modules": [
            {"name": "mount", "type": "mount"},
            {"name": "fat32_boot", "type": "fat32", "params": {"volume": "sd0"}},
            {"name": "fat32_data", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        validate_single_provider(&cfg, &names(&["mount", "fat32_boot", "fat32_data"]), &m).unwrap();
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
        let e = validate_single_provider(&cfg, &names(&["a", "b"]), &m).unwrap_err();
        let s = format!("{e:?}");
        assert!(s.contains("nvme0") && s.contains("collide"), "got: {s}");
    }

    #[test]
    fn single_provider_rejects_keyed_backends_with_no_router() {
        // Distinct selectors, but nothing provides the surface unkeyed. The
        // class-byte path every `requires_contract` consumer uses would
        // resolve to nothing and the kernel would answer ENOSYS.
        let mut m = HashMap::new();
        m.insert("boot".to_string(), prov(&["file.data"]));
        m.insert("data".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "boot", "type": "fat32", "params": {"volume": "sd0"}},
            {"name": "data", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        let e = validate_single_provider(&cfg, &names(&["boot", "data"]), &m).unwrap_err();
        let s = format!("{e:?}");
        assert!(
            s.contains("none is the default") && s.contains("boot") && s.contains("data"),
            "got: {s}"
        );
    }

    #[test]
    fn single_provider_allows_one_keyed_backend_with_a_router() {
        // A single keyed backend still needs the router: `volume:` moves it
        // off the class-byte path whether or not it has siblings.
        let mut m = HashMap::new();
        m.insert("only".to_string(), prov(&["file.data"]));
        let cfg = json!({"modules": [
            {"name": "only", "type": "fat32", "params": {"volume": "nvme0"}},
        ]});
        let e = validate_single_provider(&cfg, &names(&["only"]), &m).unwrap_err();
        assert!(format!("{e:?}").contains("none is the default"), "got: {e:?}");
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

    #[test]
    fn continuity_native_primitive_needs_mux_transport() {
        let (n, m) = edge_graph();
        let cfg = json!({"continuity": [
            {"id": "x", "class": "transport_migratable",
             "mechanism": "native_primitive"}]});
        let e = validate_continuity(&cfg, &n, &m).unwrap_err();
        assert!(format!("{e:?}").contains("transport.mux"), "got: {e:?}");

        let mut m2 = HashMap::new();
        m2.insert("quic".to_string(), man(&["transport.mux.quic"]));
        validate_continuity(&cfg, &names(&["quic"]), &m2).unwrap();
    }

    /// A manifest declaring capabilities and one `capability_facts` row.
    fn man_facts(caps: &[&str], cap: &str, fact: &str, value: &str) -> Manifest {
        let mut m = man(caps);
        let mut row = std::collections::BTreeMap::new();
        row.insert(fact.to_string(), value.to_string());
        m.capability_facts.insert(cap.to_string(), row);
        m
    }

    /// Full platform-replicated-state graph with every R1–R5 provider:
    /// the ip stack (local fence, reach decided by the target) and an
    /// out-of-band fence agent declaring the wire.
    fn prs_graph_with(anchor_cap: &str) -> (Vec<String>, HashMap<String, Manifest>) {
        prs_graph_with_terms(anchor_cap, &[("aead", aead_of(anchor_cap)), ("horizon", "exact")])
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
            man_facts(&["fence.enforceable"], "fence.enforceable", "cutoff", "ring_handoff"),
        );
        manifests.insert(
            "pdu".to_string(),
            man_facts(&["fence.enforceable"], "fence.enforceable", "cutoff", "wire"),
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
            assert!(format!("{e:?}").contains("resumable"), "terms {terms:?}: got {e:?}");
            assert!(format!("{e:?}").contains("exact"), "terms {terms:?}: got {e:?}");
        }
        // … and with it the class is admitted.
        let (n, m) = prs_graph_with_terms(cap, &[("aead", "implicit_counter"), ("horizon", "exact")]);
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
        assert!(format!("{e:?}").contains("declares no `aead` fact"), "got: {e:?}");
    }

    #[test]
    fn continuity_prs_requires_every_r_capability() {
        // Dropping the fence provider (R3) must fail with the missing
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
            facts: std::collections::BTreeMap::new(),
        }
    }

    fn with_default(mut p: manifest::PortSpec, class: fluxor_contracts::RateClass) -> manifest::PortSpec {
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
        assert!(format!("{err:?}").contains("unknown rate class"), "got: {err:?}");
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
        // (a fluxor builtin) declares no default, so the producer's own
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
        let mut from = with_default(port("OctetStream"), fluxor_contracts::RateClass::Transaction);
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

    /// `capacity:` map → FXEV section appended; entries carry the contract
    /// pool ids and the asked n.
    #[test]
    fn capacity_map_emits_fxev_section() {
        let cfg = json!({"capacity": {"events": 4, "tls_unknown_not_here": null}});
        // Unknown pool must error, not silently skip.
        let err = build_capacity_envelope(&cfg, Some("linux"))
            .expect_err("unknown pool name is a config error");
        assert!(format!("{err:?}").contains("unknown pool"));

        let cfg = json!({"capacity": {"events": 4, "timers": 2}});
        let sec = build_capacity_envelope(&cfg, Some("linux")).expect("valid envelope");
        assert_eq!(&sec[0..4], &0x4658_4556u32.to_le_bytes(), "FXEV magic");
        let section_len = u32::from_le_bytes(sec[4..8].try_into().unwrap()) as usize;
        assert_eq!(section_len, sec.len());
        let count = u16::from_le_bytes(sec[10..12].try_into().unwrap());
        assert_eq!(count, 2);
        // Entries are (pool u16, n u32); map order is serde_json's
        // (insertion-preserving) — events (0x0005) then timers (0x0006).
        assert_eq!(u16::from_le_bytes(sec[12..14].try_into().unwrap()), 0x0005);
        assert_eq!(u32::from_le_bytes(sec[14..18].try_into().unwrap()), 4);
        assert_eq!(u16::from_le_bytes(sec[18..20].try_into().unwrap()), 0x0006);
        assert_eq!(u32::from_le_bytes(sec[20..24].try_into().unwrap()), 2);
    }

    /// Over-asking a pool whose compiled capacity is known host-side is a
    /// compose-time error (the envelope only sizes DOWN), and zero is
    /// rejected (0 is the kernel's "unset" sentinel).
    #[test]
    fn over_ask_and_zero_are_config_errors() {
        let cfg = json!({"capacity": {"events": 33}});
        let err = build_capacity_envelope(&cfg, Some("linux"))
            .expect_err("events=33 exceeds the compiled 32");
        assert!(format!("{err:?}").contains("exceeds"));

        let cfg = json!({"capacity": {"events": 0}});
        let err = build_capacity_envelope(&cfg, Some("linux"))
            .expect_err("zero is not a capacity");
        assert!(format!("{err:?}").contains("positive"));
    }

    /// No `capacity:` block ⇒ no section ⇒ byte-identical config blobs.
    #[test]
    fn absent_capacity_block_emits_nothing() {
        let sec = build_capacity_envelope(&json!({}), Some("linux")).expect("ok");
        assert!(sec.is_empty());
    }

    /// RP arena asks aren't validated host-side (silicon-TOML-owned); the
    /// section still encodes them — the kernel clamps at boot.
    #[test]
    fn rp_arena_ask_passes_through_for_kernel_clamp() {
        let cfg = json!({"capacity": {"state_arena": 65536}});
        let sec = build_capacity_envelope(&cfg, Some("rp2350")).expect("encodes");
        assert_eq!(u16::from_le_bytes(sec[12..14].try_into().unwrap()), 0x0001);
        assert_eq!(u32::from_le_bytes(sec[14..18].try_into().unwrap()), 65536);
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
            facts: std::collections::BTreeMap::new(),
        }
    }

    fn edge() -> Value {
        json!({"wiring": [{"from": "pump.publish_out", "to": "sink.publish_in"}]})
    }

    #[test]
    fn accepts_a_peer_declaring_the_capability() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("publish_out", "stream.publish", 0),
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
            consumer("publish_out", "stream.publish", 0),
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
        m.insert("pump".to_string(), consumer("publish_out", "stream", 0));
        m.insert("sink".to_string(), provider(&["stream.publish"], None));
        validate_port_capabilities(&edge(), &m).unwrap();

        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("publish_out", "stream.publish", 0),
        );
        m.insert("sink".to_string(), provider(&["stream"], None));
        validate_port_capabilities(&edge(), &m).unwrap_err();
    }

    /// A producer that declares it sends more than the provider's backend
    /// takes fails the build rather than collecting runtime OVERSIZE refusals.
    #[test]
    fn rejects_a_payload_larger_than_the_providers_ceiling() {
        let mut m = HashMap::new();
        let mut pump = consumer("publish_out", "stream.publish", 8717);
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
        let mut pump = consumer("publish_out", "stream.publish", 8717);
        pump.capability_facts = facts("stream.publish", 1600);
        m.insert("pump".to_string(), pump);
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(1900)),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// A port's `max_record` is never the quantity compared against a
    /// provider's `max_payload`: `max_record` frames a whole record —
    /// correlation id, flags, key, length prefixes — while `max_payload` is
    /// the payload alone, and on the ordered-ack surface they differ by 525
    /// bytes. This is the shape of the real graph — a pump whose port takes
    /// an 8717-byte frame, sending 8192-byte payloads, into a sink that
    /// accepts 8192 — so confusing the two would fail every correctly
    /// configured producer.
    #[test]
    fn a_frame_sized_port_does_not_fail_against_an_equal_payload_ceiling() {
        let mut m = HashMap::new();
        let mut pump = consumer("publish_out", "stream.publish", 8717);
        pump.capability_facts = facts("stream.publish", 8192);
        m.insert("pump".to_string(), pump);
        m.insert(
            "sink".to_string(),
            provider(&["stream.publish"], Some(8192)),
        );
        validate_port_capabilities(&edge(), &m).unwrap();
    }

    /// A producer that states no payload fact is unvalidated, not assumed
    /// to fit: the honest position, and the reason declaring it is worth it.
    #[test]
    fn an_undeclared_producer_payload_is_unchecked() {
        let mut m = HashMap::new();
        m.insert(
            "pump".to_string(),
            consumer("publish_out", "stream.publish", 8717),
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
            consumer("publish_out", "stream.publish", 8192),
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
                    name: Some("publish_out".to_string()),
                    ..port_default()
                }],
                ..Manifest::default()
            },
        );
        m.insert("sink".to_string(), provider(&["telemetry.sink"], None));
        validate_port_capabilities(&edge(), &m).unwrap();
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

    #[test]
    fn a_producer_whose_codecs_the_consumer_takes_is_accepted() {
        let (cfg, m) = graph(
            &[("enc", out_port("codec = \"pcmu\"")), ("tx", in_port("codec = [\"pcmu\", \"opus\"]"))],
            json!([{"from": "enc.media_out", "to": "tx.media_in"}]),
        );
        validate_port_facts(&cfg, &m).unwrap();
    }

    /// Subset, not intersection: a demuxer that MAY emit MP3 must not bind an
    /// AAC-only decoder just because they share AAC.
    #[test]
    fn a_producer_that_may_send_an_untaken_codec_is_refused() {
        let (cfg, m) = graph(
            &[("demux", out_port("codec = [\"aac\", \"mp3\"]")), ("dec", in_port("codec = \"aac\""))],
            json!([{"from": "demux.media_out", "to": "dec.media_in"}]),
        );
        let e = validate_port_facts(&cfg, &m).unwrap_err().to_string();
        assert!(e.contains("mp3") && e.contains("demux.media_out"), "{e}");
    }

    #[test]
    fn exact_and_ceiling_facts_are_compared() {
        let (cfg, m) = graph(
            &[("a", out_port("clock_rate = 8000")), ("b", in_port("clock_rate = 48000"))],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        assert!(validate_port_facts(&cfg, &m).is_err());
        let (cfg, m) = graph(
            &[("a", out_port("max_payload = 2048")), ("b", in_port("max_payload = 1200"))],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        assert!(validate_port_facts(&cfg, &m).is_err());
        let (cfg, m) = graph(
            &[("a", out_port("max_payload = 1000")), ("b", in_port("max_payload = 1200"))],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        validate_port_facts(&cfg, &m).unwrap();
    }

    #[test]
    fn a_fact_one_end_leaves_undeclared_is_unconstrained() {
        let (cfg, m) = graph(
            &[("a", out_port("codec = \"opus\"")), ("b", in_port("channels = 2"))],
            json!([{"from": "a.media_out", "to": "b.media_in"}]),
        );
        validate_port_facts(&cfg, &m).unwrap();
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
        let e = validate_port_facts(&cfg, &m).unwrap_err().to_string();
        assert!(e.contains("rx.media_in") && e.contains("2 producers"), "{e}");
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
