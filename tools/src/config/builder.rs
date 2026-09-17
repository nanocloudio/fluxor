// =============================================================================
// Graph Config (Version 3+)
// =============================================================================

/// Graph edge size in bytes (12 = 4-byte fixed header + 4-byte
/// `buffer_bytes` u32 LE override + rate_class u8 + 3 reserved).
/// Mirrors `kernel::config::GRAPH_EDGE_SIZE`; the layout is
/// documented there.
const GRAPH_EDGE_SIZE: usize = 12;
/// Maximum number of graph edges. 128 is sized to hold the Quantum
/// graph (114 edges) with headroom.
const MAX_GRAPH_EDGES: usize = 128;
/// Per-domain metadata: 4 domains × DOMAIN_META_ENTRY_SIZE.
/// Entry = `tick_us:u16 | exec_mode:u8 | adaptive_flags:u8` = 4 bytes. The
/// adaptive-tick `tick_min_us`/`tick_max_us` bounds are NOT in this entry; they
/// live in the unchecksummed post-body tail (see ADAPTIVE_POST_SIZE) so the
/// checksummed `body_size` is unchanged. Mirrors
/// `kernel::config::{DOMAIN_META_ENTRY_SIZE, DOMAIN_META_SIZE}`.
const DOMAIN_META_ENTRY_SIZE: usize = 4;
const DOMAIN_META_SIZE: usize = 4 * DOMAIN_META_ENTRY_SIZE;
/// Graph section size (header + edges + domain metadata)
const GRAPH_SECTION_SIZE: usize = 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE + DOMAIN_META_SIZE;


/// Module entry header size (entry_length:u32 + name_hash:u32 + id:u8 + reserved:u8).
/// `entry_length` is a u32 so a single module's params can exceed
/// 64 KiB — needed by synth host's http module when both halves of a
/// split scenario inline the canonical wasm shell as body routes
/// (~95 KiB combined). Coordinated with `src/kernel/boot/config.rs`'s
/// `parse_module_entry`, which reads matching field widths.
const MODULE_ENTRY_HEADER_SIZE: usize = 10;

/// Maximum module params size. 256 KiB accommodates the
/// wasm-scenario synth host's http module, which inlines the
/// canonical browser shell (runtime.html ~83 KiB after scenario
/// substitution + host_shims.js ~56 KiB + scenario.json) as `body:`
/// routes per the shared-infra-in-orchestrator partition principle.
/// A 128 KiB cap truncates the later route bodies silently (clipped
/// JS / empty scenario.json in the browser). Kept in lockstep with the
/// runtime `MAX_CONFIG_SIZE` / http `DEFAULT_BODY_POOL_SIZE` host caps.
/// Generation runs host-side, so this is a sanity bound, not a memory
/// constraint. Wavetables and large sequences fit comfortably within.
const MAX_MODULE_PARAMS_SIZE: usize = 256 * 1024;

/// Param base offset within a module entry (= header size = 8)
const P: usize = MODULE_ENTRY_HEADER_SIZE;

/// Parse a waveform string into its numeric ID.
/// Used by synth, monosynth, and other oscillator-based modules.
/// Parse UUID string (with or without dashes) to 16 bytes. Returns [0; 16] on error.
fn parse_uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut out = [0u8; 16];
    if hex.len() != 32 {
        return out;
    }
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    out
}

/// Parse IPv4 address string to u32 (network byte order).
fn parse_ipv4(s: &str) -> u32 {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return 0;
    }
    let a = parts[0].parse::<u8>().unwrap_or(0);
    let b = parts[1].parse::<u8>().unwrap_or(0);
    let c = parts[2].parse::<u8>().unwrap_or(0);
    let d = parts[3].parse::<u8>().unwrap_or(0);
    u32::from_be_bytes([a, b, c, d])
}

/// Parse "host:port" string. Returns (ip_u32, port).
fn parse_broker_addr(s: &str) -> (u32, u16) {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let ip = parse_ipv4(parts.first().unwrap_or(&""));
    let port = parts
        .get(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(1883);
    (ip, port)
}

/// Default step deadline in microseconds — mirrors
/// `kernel::step_guard::DEFAULT_STEP_DEADLINE_US`. Kept duplicated
/// rather than imported so this tool stays independent of the kernel
/// crate's `no_std` feature set; the silicon-config drift guard in
/// `tools/tests/silicon_toml_shape.rs` pattern can be extended to
/// pin this if it ever needs to change.
const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// Maximum number of scheduling domains the kernel supports.
/// Mirrors `src/platform/bcm2712/multicore.rs::MAX_DOMAINS = 4` and
/// the scheduler's `MAX_DOMAINS` constant. The config writer
/// serialises exactly 4 domain-metadata entries; the wire format
/// has no slot for a 5th. Locked at the wire layer by
/// `tests/harness/tests/abi_wire_surface.rs` (the kernel-side
/// constant is exercised there); the tools side hardcodes the same
/// value here with a comment so a future bump touches both
/// together.
const MAX_DOMAINS: usize = 4;

/// Bounded graph/domain pacer-instance table size. One pacer per
/// (graph_instance, domain); with a single resident graph this equals
/// `MAX_DOMAINS`. The build rejects adaptive configs that would
/// need more resident pacer instances than this — the scheduler never allocates
/// pacer state on a hot path.
const MAX_PACER_INSTANCES: usize = MAX_DOMAINS;

/// Bounded MULTI-graph pacer-instance table size — mirrors the kernel's
/// `scheduler::MAX_GRAPH_PACERS`. When more than one resident graph is admitted
/// (a base graph plus `pods:`), the live pacer instances are the
/// `(graph_instance, domain)` pairs across all resident graphs, capped by this
/// static table.
const MAX_GRAPH_PACER_INSTANCES: usize = 16;

/// Burst-mode deadline multiplier — mirrors
/// `kernel::step_guard::BURST_MULTIPLIER`.
const BURST_DEADLINE_MULTIPLIER: u32 = 8;

/// Adaptive-tick per-domain enable bits — mirror
/// `kernel::scheduler::ADAPTIVE_FLAG_{IDLE,CADENCE}`.
const ADAPTIVE_FLAG_IDLE: u8 = 0x01;
const ADAPTIVE_FLAG_CADENCE: u8 = 0x02;
/// Valid per-domain tick bounds (µs), mirrors the kernel `tick_us` range.
const TICK_US_MIN: u32 = 100;
const TICK_US_MAX: u32 = 50_000;
/// Default raft `heartbeat_interval_ms` when the module doesn't override it
/// (150 ms — a common Raft liveness-gate default).
const DEFAULT_HEARTBEAT_MS: u64 = 150;

/// Effective tick_us when the config doesn't set one anywhere. Mirrors
/// the platform main-loop fallback (`tick_period_us = 1000` when
/// `cfg_header_tick_us == 0`).
const DEFAULT_TICK_US: u32 = 1000;

/// Hard absolute cap on a single module's burst deadline. The burst
/// path uses `step_deadline_us * BURST_MULTIPLIER` as its extended
/// timeout; capping the product at 100 ms keeps Tier 1a loops
/// responsive even when a misconfigured module runs through its full
/// burst budget. 100 ms is the conservative side of "no human-
/// perceivable jitter" for audio/video pipelines; raise this only
/// alongside a measured rationale.
const HARD_BURST_CAP_US: u32 = 100_000;

/// Soft warning threshold for the **declared** deadline sum on a
/// single domain, expressed as a multiple of the domain's tick_us.
/// Crossing this means the domain's modules collectively claim more
/// budget than the tick allots — if any sustained run hits its
/// declared deadline the loop slips. The threshold is a multiple
/// because per-module deadlines are *fault thresholds*, not expected
/// runtimes; most modules complete well inside their declared budget.
const DECLARED_DEADLINE_BUDGET_FACTOR: u32 = 4;

/// Cross-check that **explicitly declared** `step_deadline_us` values
/// fit inside the domain budgets. Modules that don't declare a
/// deadline silently use the kernel default
/// (`DEFAULT_STEP_DEADLINE_US = 2000`); that default is a fault
/// threshold, not a steady-state budget, and is intentionally bigger
/// than typical tick_us values — so it's excluded from the sum-vs-tick
/// invariant. Only opt-in deadlines are scored, because declaring a
/// deadline is the config author saying "I expect this module to
/// occasionally take this long, treat it as a real budget."
///
/// Rules enforced:
///   1. Per-module hard cap: declared `step_deadline_us *
///      BURST_MULTIPLIER` must not exceed `HARD_BURST_CAP_US` —
///      otherwise the burst path silently authorises a multi-tick
///      stall that starves every sibling module in the domain.
///   2. Per-module hard cap: `step_deadline_us * BURST_MULTIPLIER`
///      must not exceed `domain_tick_us * 16`. The burst guardrail
///      is meant to absorb spike workloads, not authorise unbounded
///      runaway loops.
///   3. Per-domain warning: when the **sum of declared deadlines**
///      exceeds `domain_tick_us * DECLARED_DEADLINE_BUDGET_FACTOR`,
///      emit a warning. Each module is making a deadline claim and
///      the domain can't keep all promises simultaneously.
///
/// `tick_us == 0` (graph-level) means "use platform default";
/// `domain_tick_us[i] == 0` means "use the graph-level tick".
fn validate_scheduler_budgets(
    config: &Value,
    module_list: &[Value],
    tick_us: u16,
    domain_names: &[String],
    domain_tick_us: &[u16],
) -> Result<()> {
    let effective_tick = |dtick: u16| -> u32 {
        if dtick > 0 {
            dtick as u32
        } else if tick_us > 0 {
            tick_us as u32
        } else {
            DEFAULT_TICK_US
        }
    };

    // Sum of **declared** deadlines per domain; modules that don't
    // declare are not scored.
    let mut per_domain_sum: std::collections::HashMap<u8, u32> = std::collections::HashMap::new();

    for module in module_list {
        let name = module
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let domain = resolve_domain_id(module, config)?;
        let dtick = domain_tick_us.get(domain as usize).copied().unwrap_or(0);
        let domain_budget = effective_tick(dtick);

        let declared_deadline = module
            .get("step_deadline_us")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        // An explicit `step_deadline_burst_us` overrides the implicit
        // `step_deadline_us * BURST_MULTIPLIER` ceiling at runtime.
        // The validator must check the EFFECTIVE burst deadline —
        // otherwise a config with
        // `step_deadline_us: 1000, step_deadline_burst_us: 1_000_000`
        // would pass (because 1000 × 16 = 16ms is under the 100ms
        // cap) while authorising a 1-second runtime burst. Read the
        // override here and prefer it; fall back to the multiplier
        // math when no override is declared.
        //
        // The raw YAML value is type- and range-checked explicitly.
        // A u64 silently cast to u32 would wrap at 0x_0000_0001_0000_0000
        // → 0; non-numeric values (e.g. a typo like
        // `step_deadline_burst_us: "very_long"`) would otherwise become
        // `None` via `as_u64` and silently disable the override.
        let declared_burst_raw = module.get("step_deadline_burst_us");
        let declared_burst: Option<u32> = match declared_burst_raw {
            None => None,
            Some(v) if v.is_null() => None,
            Some(v) => match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => Some(n as u32),
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us = {n} exceeds u32::MAX \
                         ({})",
                        u32::MAX
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            },
        };

        // Suppress the unused-binding lint on the kernel default —
        // surfacing it keeps the const linked to its kernel mirror;
        // future readers will see they need to update both sides if
        // it changes.
        let _ = DEFAULT_STEP_DEADLINE_US;

        // A module with no declared `step_deadline_us` but an
        // explicit `step_deadline_burst_us` still has to honour the
        // per-domain burst ceiling — the burst budget must fit even
        // when the typical deadline isn't declared.
        let deadline = match declared_deadline {
            Some(0) | None => {
                if declared_burst.is_some() {
                    // Use the kernel's default step deadline for the
                    // "typical" budget when validating burst alone;
                    // the runtime treats `step_deadline_us == 0` as
                    // "use default", so this matches behaviour.
                    DEFAULT_STEP_DEADLINE_US
                } else {
                    continue;
                }
            }
            Some(d) => d,
        };

        // Effective runtime burst = explicit override if set, else
        // the multiplier math. The same per-module / per-domain caps
        // apply to either path.
        let burst = declared_burst
            .filter(|b| *b > 0)
            .unwrap_or_else(|| deadline.saturating_mul(BURST_DEADLINE_MULTIPLIER));

        // Rule 1 — absolute burst cap.
        if burst > HARD_BURST_CAP_US {
            return Err(Error::Config(format!(
                "module '{name}': step_deadline_us={deadline} → burst deadline {burst} us \
                 (× BURST_MULTIPLIER={BURST_DEADLINE_MULTIPLIER}) exceeds the {HARD_BURST_CAP_US} us absolute cap. \
                 A single module cannot authorise stalling the scheduler \
                 this long."
            )));
        }

        // Rule 2 — burst budget relative to the domain tick. Bursts
        // can span multiple ticks but capping at 16 × tick keeps the
        // guardrail meaningful.
        let burst_cap_for_domain = domain_budget.saturating_mul(16);
        if burst > burst_cap_for_domain {
            let domain_label = domain_names
                .get(domain as usize)
                .map(String::as_str)
                .unwrap_or("default");
            return Err(Error::Config(format!(
                "module '{name}' in domain '{domain_label}': burst deadline {burst} us \
                 (step_deadline_us={deadline} × {BURST_DEADLINE_MULTIPLIER}) exceeds 16 × domain tick_us \
                 ({burst_cap_for_domain} us). Bursts are guardrails, not licences to monopolise \
                 the domain."
            )));
        }

        *per_domain_sum.entry(domain).or_insert(0) += deadline;
    }

    // Rule 3 — per-domain warning for the declared-deadline sum.
    for (domain, sum) in per_domain_sum {
        let dtick = domain_tick_us.get(domain as usize).copied().unwrap_or(0);
        let domain_budget = effective_tick(dtick);
        let budget_ceiling = domain_budget.saturating_mul(DECLARED_DEADLINE_BUDGET_FACTOR);
        if sum > budget_ceiling {
            let domain_label = domain_names
                .get(domain as usize)
                .map(String::as_str)
                .unwrap_or("default");
            eprintln!(
                "warning: domain '{domain_label}' declared step_deadline_us sum = {sum} exceeds \
                 {DECLARED_DEADLINE_BUDGET_FACTOR}× tick_us ({budget_ceiling} us). If every module hits its declared deadline \
                 the loop slips. Lower a declared deadline, raise tick_us, or \
                 split modules across additional domains."
            );
        }
    }

    Ok(())
}

/// Validate the adaptive-tick per-domain config.
///
/// Runs only when at least one domain sets `adaptive_flags` — an unconfigured
/// graph is untouched (byte-identical). Enforces:
///   * **Range**: per adaptive domain, non-zero `tick_min_us`/`tick_max_us` ∈
///     `[100, 50000]` and `tick_min ≤ tick_max` (0 = "use tick_us"). Warns when
///     `tick_min == tick_max` (adaptive enabled but no range ⇒ no-op).
///   * **Burst-at-floor**: for a mechanism-(b) domain, each module's
///     `step_deadline_us × BURST` must fit `16 × tick_min_us` — the smallest
///     cadence the domain can reach.
///   * **Liveness**: demand-driven idle (bit 0) on a domain hosting a
///     liveness module (`raft_engine`) requires `tick_max_us <
///     heartbeat_interval_ms × 1000`, else an idle leader misses heartbeats →
///     spurious elections.
///   * **Multi-node raft**: a `raft_engine` on an adaptive domain in a
///     multi-node cluster (`voter_count`/`peer_count > 1`) is rejected — the
///     raft-owning domain must be fixed cadence (both mechanisms off).
///
///   * **Timer-class attestation**: on a mechanism-(b) domain every
///     admitted module must POSITIVELY attest cadence tolerance (`wall_clock` or
///     explicit `agnostic`); an unattested module (no `timer_class` / no
///     manifest) defaults to step_counted and is blocked (fail closed). A
///     non-zero `step_period_ticks` (manifest → ABI header byte 1) is blocked on
///     (b) unless `wall_clock`. On an (a)-only domain the gate is lenient (only
///     `tick_counted`/`guaranteed` rejected).
///
///   * **Replicated-clock**: a `replicated_clock`-class module (ttl/lease) is
///     blocked on (b) unless the domain asserts
///     `replica_agreed_cadence: true` (and never on a multi-node cluster);
///     mechanism (a) idle is clamped so `tick_max_us` stays below the tick
///     emission interval.
///   * **Guaranteed-tier WCET**: a `guaranteed`-class module is blocked on (b)
///     unless the domain asserts `guaranteed_wcet_revalidated: true` (the
///     operator re-ran WCET/budget schedulability at `tick_min_us`).
///   * **Domain-0 `DBG_TICK` rate-coupling**: on a DBG_TICK-backed target with
///     ≥2 domains, an adaptive domain 0 must set a finite `tick_max_us` so its
///     variable pacing can't stall sibling-domain `tick_count()` reads (the
///     `*-TICKS` drain/quarantine/backoff windows are wall-clocked, so only the
///     DBG_TICK advance rate couples the domains).
///   * **`tick_count()`-as-milliseconds**: no gate is needed here — the
///     bcm2712/Linux HAL `tick_count` is wall-clock-backed and timer FDs use
///     `hal::now_millis`; a module that counts ticks as time declares
///     `tick_counted` and is rejected by the timer-class gate above.
///
/// Read a numeric module param from EITHER the top-level entry (`voter_count: 3`)
/// OR a nested `params:` map (`params: { voter_count: 3 }`). The TLV packer
/// accepts both styles (schema.rs:298-335), so the raft liveness and multi-node
/// gates must read both too — otherwise the normal top-level style silently
/// bypasses them.
/// Resident-graph (pod) pacer-table admission. Counts the base graph's
/// domains plus each `pods:` entry's distinct module domains and rejects configs
/// that would exceed the kernel's static `GRAPH_PACERS` table. Runs regardless of
/// `adaptive_flags` — the runtime keys/steps the resident-graph table for ANY
/// multi-graph config (fixed-tick included), and an overflow is silently dropped
/// at runtime, so it must fail the build.
fn validate_resident_workload_table(config: &Value, domain_count: usize) -> Result<()> {
    let Some(pods) = config.get("pods").and_then(|p| p.as_array()) else {
        return Ok(());
    };
    let mut total = domain_count.max(1);
    for pod in pods.iter() {
        // A pod's pacer instances = the number of distinct module domains it
        // declares (a self-contained subgraph), default 1.
        let mut seen = [false; MAX_DOMAINS];
        let mut pod_domains = 0usize;
        let mods = pod
            .get("modules")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_else(|| vec![pod.clone()]);
        for m in &mods {
            // Domain resolved by NAME against execution.domains (hard-errors on an
            // undeclared domain, like base modules); numeric/absent ⇒ domain 0.
            let d = resolve_domain_id(m, config)? as usize;
            if !seen[d] {
                seen[d] = true;
                pod_domains += 1;
            }
        }
        total += pod_domains.max(1);
    }
    if total > MAX_GRAPH_PACER_INSTANCES {
        return Err(Error::Config(format!(
            "{} resident graph(s) need {total} (graph, domain) pacer instances, \
             exceeding the kernel's static pacer table ({MAX_GRAPH_PACER_INSTANCES}, \
             scheduler::MAX_GRAPH_PACERS). The runtime never allocates pacer state on \
             a hot path, so resident graphs are statically capped. Reduce the number \
             of pods, or the number of distinct domains they place modules in.",
            pods.len() + 1
        )));
    }
    Ok(())
}

fn module_param_u64(m: &Value, key: &str) -> Option<u64> {
    m.get(key).and_then(|v| v.as_u64()).or_else(|| {
        m.get("params")
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_u64())
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "validation context is threaded positionally to match the other \
              validate_* helpers; bundling into a struct would not improve clarity"
)]
fn validate_adaptive_tick(
    config: &Value,
    module_list: &[Value],
    tick_us: u16,
    domain_names: &[String],
    domain_tick_us: &[u16],
    manifests: &HashMap<String, Manifest>,
    extra_module_dirs: &[&std::path::Path],
    resolved_target: Option<&str>,
) -> Result<()> {
    // Read RAW u64 values (not `as u16`/`as u8`) so out-of-range inputs are
    // caught BEFORE the wire cast silently wraps them (e.g. tick_max_us=200000
    // would wrap to 3392 in a u16 and slip past the range check).
    let mut flags = [0u64; MAX_DOMAINS];
    let mut tmin = [0u64; MAX_DOMAINS];
    let mut tmax = [0u64; MAX_DOMAINS];
    // Per-domain operator attestations, the two escape hatches:
    //  * `guaranteed_wcet_revalidated` — the operator asserts the domain's
    //    WCET/budget schedulability was re-run at `tick_min_us`, permitting a
    //    `guaranteed`-class module on a mechanism-(b) domain.
    //  * `replica_agreed_cadence` — the operator asserts every replica paces
    //    the replicated-tick emission identically, permitting a
    //    `replicated_clock`-class module on a (single-node) (b) domain.
    let mut guar_reval = [false; MAX_DOMAINS];
    let mut replica_agreed = [false; MAX_DOMAINS];
    // Per-domain core bitmask (shared-runner detection). A domain that
    // pins `cores: [N, ...]` runs on those cores; a domain with no `cores`
    // shares the cooperative runner (modelled as core 0 — true on single-core
    // Linux/rp/wasm, and the default lane on bcm2712). Two domains whose
    // bitmasks overlap share a physical runner.
    let mut core_mask = [0u64; MAX_DOMAINS];
    // Per-domain "hosts a timing-strict module" (Guaranteed WCET, replicated
    // clock, or raft liveness) — the shared-runner co-residency check rejects an
    // adaptive domain sharing a runner with one of these.
    let mut has_strict = [false; MAX_DOMAINS];
    let mut domain_count = 0usize;
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
        domain_count = domains.len();
        for (i, dom) in domains.iter().take(MAX_DOMAINS).enumerate() {
            flags[i] = dom
                .get("adaptive_flags")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            tmin[i] = dom.get("tick_min_us").and_then(|v| v.as_u64()).unwrap_or(0);
            tmax[i] = dom.get("tick_max_us").and_then(|v| v.as_u64()).unwrap_or(0);
            guar_reval[i] = dom
                .get("guaranteed_wcet_revalidated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            replica_agreed[i] = dom
                .get("replica_agreed_cadence")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            match dom.get("cores").and_then(|v| v.as_array()) {
                Some(arr) if !arr.is_empty() => {
                    for c in arr {
                        if let Some(n) = c.as_u64() {
                            core_mask[i] |= 1u64 << (n & 63);
                        }
                    }
                }
                // No (or empty) `cores` ⇒ the shared cooperative runner (core 0).
                _ => core_mask[i] = 1,
            }
            // Tier-0-vs-Tier-3 warning: adaptive cadence (a Tier-0
            // latency/efficiency mode) on a domain explicitly declared poll-mode
            // (Tier 3 = continuous stepping, no relaxation) is contradictory —
            // Tier 3 is the "use the whole core" mode. Recommend picking one.
            if flags[i] != 0 {
                let tier = dom.get("tier").and_then(|v| v.as_str()).unwrap_or("");
                let exec = dom.get("exec_mode").and_then(|v| v.as_str()).unwrap_or("");
                if tier == "3" || exec == "poll" {
                    eprintln!(
                        "warning: domain '{}' sets adaptive_flags={:#x} but is declared \
                         Tier 3 / poll-mode. Tier 0 adaptive reduces idle work; Tier 3 \
                         saturates the core continuously — they are mutually exclusive \
                         intents. Use Tier 3 for full-CPU/poll workloads and drop \
                         adaptive_flags, or use Tier 0 adaptive and drop the poll tier.",
                        dom.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                        flags[i]
                    );
                }
            }
        }
    }
    // Multi-graph pacer-table admission runs BEFORE the adaptive-only early
    // return: resident pods are admitted and the resident-graph table is
    // keyed/stepped regardless of `adaptive_flags`
    // (fixed-tick multi-graph still uses it), so an overflowing `pods:` set must
    // be rejected at build time even with no adaptive domain — otherwise a
    // graph/domain instance would just be silently dropped at runtime.
    validate_resident_workload_table(config, domain_count)?;

    // Unconfigured ⇒ nothing more to check (byte-identical path).
    if flags.iter().all(|&f| f == 0) {
        return Ok(());
    }

    // The domain-0 coupling rule below is scoped to platforms whose HAL
    // `tick_count` is `DBG_TICK`-backed — bcm2712 and Linux. rp2350/pico read
    // `tick_count` from a wall-clock `Instant` and drive timer FDs off
    // `hal::now_millis`, so nothing on those targets reads a shared tick
    // counter for time and they are immune.
    let silicon = resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str()));
    let dbg_tick_backed = silicon.is_none_or(|s| {
        let s = s.to_ascii_lowercase();
        !(s.contains("rp2") || s.contains("pico") || s.contains("rp1") || s.contains("wasm"))
    });

    let eff = |d: usize| -> u32 {
        let dt = domain_tick_us.get(d).copied().unwrap_or(0);
        if dt > 0 {
            dt as u32
        } else if tick_us > 0 {
            tick_us as u32
        } else {
            DEFAULT_TICK_US
        }
    };
    let label = |d: usize| -> &str { domain_names.get(d).map(String::as_str).unwrap_or("default") };

    for d in 0..MAX_DOMAINS {
        if flags[d] == 0 {
            continue;
        }
        let allowed = (ADAPTIVE_FLAG_IDLE | ADAPTIVE_FLAG_CADENCE) as u64;
        if flags[d] & !allowed != 0 {
            return Err(Error::Config(format!(
                "domain '{}': adaptive_flags={:#x} sets reserved bits; only bit 0 \
                 (demand-driven idle) and bit 1 (adaptive cadence) are defined.",
                label(d),
                flags[d]
            )));
        }
        for (name, v) in [("tick_min_us", tmin[d]), ("tick_max_us", tmax[d])] {
            if v != 0 && !((TICK_US_MIN as u64)..=(TICK_US_MAX as u64)).contains(&v) {
                return Err(Error::Config(format!(
                    "domain '{}': {name}={v} out of range [{TICK_US_MIN}, {TICK_US_MAX}].",
                    label(d)
                )));
            }
        }
        let emin = if tmin[d] > 0 { tmin[d] } else { eff(d) as u64 };
        let emax = if tmax[d] > 0 { tmax[d] } else { eff(d) as u64 };
        if emin > emax {
            return Err(Error::Config(format!(
                "domain '{}': tick_min_us ({emin}) > tick_max_us ({emax}).",
                label(d)
            )));
        }
        if emin == emax {
            eprintln!(
                "warning: domain '{}' sets adaptive_flags={:#x} but tick_min_us == \
                 tick_max_us ({emin}) — adaptive tick has no range to move in (no-op). \
                 Set tick_min_us < tick_max_us.",
                label(d),
                flags[d]
            );
        }
    }

    // Domain-0 DBG_TICK rate-coupling on a multi-domain bcm2712 node.
    // `DBG_TICK` is advanced ONLY by domain 0, and every domain
    // reads it for `tick_count()`. If domain 0 paces variably (b) or idle-sleeps
    // to tick_max_us (a), the shared logical clock re-times for ALL domains.
    // The `*-TICKS` drain/quarantine/backoff windows are wall-clocked, so they
    // are immune. The residual coupling is the DBG_TICK *advance rate* feeding
    // sibling-domain `tick_count()` reads: bound it by requiring domain 0 to
    // declare a finite `tick_max_us` (no unbounded idle widen) whenever it
    // enables adaptive tick alongside sibling domains. An unbounded
    // (`tick_max_us == 0` ⇒ platform default, but bit-0 idle can widen the
    // programmed deadline arbitrarily) domain-0 widen maximally stalls sibling
    // tick reads.
    if dbg_tick_backed && domain_count >= 2 && flags[0] != 0 && tmax[0] == 0 {
        return Err(Error::Config(format!(
            "domain '{}' (domain 0) enables adaptive_flags={:#x} in a multi-domain \
             configuration ({} domains) on a DBG_TICK-backed target ({}), but does \
             not set a finite tick_max_us. Domain 0 alone advances the shared \
             DBG_TICK that every sibling domain reads via tick_count(); an unbounded \
             idle/cadence widen on domain 0 stalls sibling-domain timing. Set an \
             explicit tick_max_us on domain 0 to bound the coupling, or disable \
             adaptive tick on domain 0.",
            label(0),
            flags[0],
            domain_count,
            silicon.unwrap_or("unknown"),
        )));
    }

    // Bounded pacer-table admission. Each (graph_instance, domain) owns one
    // pacer instance; the target declares a
    // static maximum and the build rejects configs that exceed it (no scheduler
    // hot path may allocate or resize pacer state). With a single resident
    // graph the instance count is the number of adaptive execution domains and
    // the bound is `MAX_DOMAINS` (one pacer per domain); with multiple resident
    // graphs it is `graphs × domains` against the declared table size.
    if domain_count > MAX_PACER_INSTANCES {
        return Err(Error::Config(format!(
            "adaptive tick: configuration declares {domain_count} execution domains, \
             exceeding the target's bounded pacer table ({MAX_PACER_INSTANCES} \
             graph/domain pacer instances). The scheduler never allocates pacer \
             state on a hot path, so the resident pacer count is statically capped. \
             Reduce the domain count or raise the target's pacer-table bound."
        )));
    }

    // BCM2712 wake-policy declaration (required statement). On bcm2712 (pi5),
    // demand-driven idle (mechanism (a), bit 0) is NOT fully event-driven —
    // Tier-0/1a idle uses WFI, which software SEV does not break — so every
    // adaptive-idle config MUST declare how it bounds first-wake latency:
    // `clamp` (the default), `doorbell` (a software-generated inter-processor
    // interrupt that kicks the idle core, opt-in), or `wfe` (only where the
    // platform contract proves it safe). The declaration
    // forces the deployment to acknowledge "bounded idle polling", not
    // "event-driven idle". rp/Linux/wasm are event-driven and exempt.
    // Registry-resolved: bcm2712 silicon (pi5, qemu-virt, raw bcm2712),
    // NOT the linux host (event-driven, exempt) — no substring matching.
    let is_bcm = silicon
        .and_then(|s| crate::target::load_target(s, &crate::project::root()).ok())
        .is_some_and(|d| !d.is_host() && d.id == "bcm2712");
    let any_idle = (0..MAX_DOMAINS).any(|d| flags[d] & ADAPTIVE_FLAG_IDLE as u64 != 0);
    if is_bcm && any_idle {
        let policy = config
            .get("execution")
            .and_then(|e| e.get("bcm_wake_policy"))
            .and_then(|v| v.as_str());
        match policy {
            Some("clamp") | Some("doorbell") | Some("wfe") => {}
            Some(other) => {
                return Err(Error::Config(format!(
                    "execution.bcm_wake_policy = \"{other}\" is not recognised; bcm2712 \
                     adaptive idle must declare one of \"clamp\", \"doorbell\", or \
                     \"wfe\"."
                )));
            }
            None => {
                return Err(Error::Config(
                    "bcm2712 (pi5) adaptive idle (adaptive_flags bit 0) requires an \
                     explicit `execution.bcm_wake_policy` of \"clamp\", \"doorbell\", \
                     or \"wfe\". bcm2712 idle is WFI-based and not fully event-driven, \
                     so the deployment must declare how first-wake latency is bounded \
                     (clamp = bounded idle polling, the default; doorbell = a \
                     software-generated inter-processor interrupt that kicks the idle \
                     core; wfe = only where proven safe)."
                        .to_string(),
                ));
            }
        }
    }

    // Multi-node detection: any module declaring voter_count/peer_count > 1,
    // in EITHER the top-level or nested `params:` style (both packed).
    let multi_node = module_list.iter().any(|m| {
        ["voter_count", "peer_count"]
            .iter()
            .any(|k| module_param_u64(m, k).unwrap_or(1) > 1)
    });

    for m in module_list {
        let mtype = m
            .get("type")
            .or_else(|| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mname = m.get("name").and_then(|v| v.as_str()).unwrap_or(mtype);
        let d = resolve_domain_id(m, config)? as usize;
        if d >= MAX_DOMAINS || flags[d] == 0 {
            continue;
        }

        // Timer-class attestation: a module that counts scheduler ticks as
        // time (`tick_counted`) or needs a fixed-cadence WCET
        // (`guaranteed`) cannot run on an adaptive-tick domain — a variable
        // cadence warps its timers / breaks its real-time guarantee. We read from
        // the RESOLVED manifest map (`load_module_manifests_with_extra`, keyed by
        // instance name, incl. extra_module_dirs) — NOT the narrower
        // `from_source_tree`, which would miss external/project modules.
        //
        // The policy is SCOPED TO THE MECHANISM:
        //  * Mechanism (b) (variable cadence): every admitted module must
        //    POSITIVELY attest cadence tolerance (`wall_clock` or explicit
        //    `agnostic`). An Unattested module (no timer_class / no manifest)
        //    defaults to step_counted and is BLOCKED until attested — fail closed.
        //    A non-zero `step_period_ticks` is also blocked unless `wall_clock`.
        //  * Mechanism (a)-only: the lenient gate — only the hard-unsafe classes
        //    (`tick_counted`/`guaranteed`) are rejected; idle-relax alone doesn't
        //    warp a running module, and the type-specific gates below (the
        //    replicated-clock and raft heartbeat idle clamps) cover it.
        let cadence = flags[d] & ADAPTIVE_FLAG_CADENCE as u64 != 0;
        let idle = flags[d] & ADAPTIVE_FLAG_IDLE as u64 != 0;
        if let Some(man) = manifests.get(mname) {
            // Replicated clock under mechanism (a): demand-driven idle must not
            // stall the committed-tick emitter long enough to delay replicated
            // expiry. Same clamp as the raft liveness gate below — it applies
            // whenever idle is enabled, independent of the cadence flag.
            if idle && man.timer_class.is_replicated_clock() {
                let interval_ms = module_param_u64(m, "tick_interval_ms")
                    .or_else(|| module_param_u64(m, "heartbeat_interval_ms"))
                    .unwrap_or(DEFAULT_HEARTBEAT_MS);
                let interval_us = interval_ms.saturating_mul(1000);
                let emax = if tmax[d] > 0 { tmax[d] } else { eff(d) as u64 };
                if emax >= interval_us {
                    return Err(Error::Config(format!(
                        "module '{mname}' (timer_class=replicated_clock) on adaptive \
                         domain '{}': demand-driven idle (adaptive_flags bit 0) with \
                         tick_max_us={emax} ≥ tick emission interval ({interval_ms} ms \
                         = {interval_us} us). An idle domain would stop stepping the \
                         tick emitter, so committed/replicated expiry stalls until the \
                         backstop fires. Set tick_max_us < {interval_us}, or clear \
                         bit 0 on this domain.",
                        label(d),
                    )));
                }
            }
            if cadence {
                // Replicated clock under mechanism (b): a committed clock
                // self-reads wall-clock time (so it passes the attestation gate
                // above), but varying the *emission cadence* shifts expiry timing.
                // Independent per-node pacing cannot agree, so it is blocked
                // outright on a multi-node cluster; on a single node it is allowed
                // only when the operator asserts replica-agreed emission cadence.
                if man.timer_class.is_replicated_clock() {
                    if multi_node {
                        return Err(Error::Config(format!(
                            "module '{mname}' (timer_class=replicated_clock) cannot run \
                             on mechanism-(b) domain '{}' of a multi-node cluster \
                             (voter_count/peer_count > 1): independent per-node pacing \
                             changes the replicated-tick emission rate, so replicas \
                             diverge on expiry order. Pin the replicated-clock-owning \
                             domain to fixed cadence (clear adaptive_flags bit 1).",
                            label(d),
                        )));
                    }
                    if !replica_agreed[d] {
                        return Err(Error::Config(format!(
                            "module '{mname}' (timer_class=replicated_clock) cannot run \
                             on mechanism-(b) (variable-cadence) domain '{}' unless the \
                             config asserts that all replicas pace the replicated-tick \
                             emission identically. Set `replica_agreed_cadence: true` on \
                             the domain only if that holds, else pin the domain to fixed \
                             cadence.",
                            label(d),
                        )));
                    }
                } else if man.timer_class == TimerClass::Guaranteed {
                    // Guaranteed WCET under mechanism (b): (b) lowers the tick
                    // and the domain budget IS the tick, so the module's
                    // schedulability — proven at a fixed tick — can be silently
                    // shrunk. Allowed only when the operator asserts the WCET/budget
                    // schedulability was re-validated at the worst-case `tick_min_us`.
                    // (The burst-at-floor rule below enforces the per-step bound at
                    // tick_min; the full schedulability re-run is the operator's
                    // attestation.)
                    if !guar_reval[d] {
                        return Err(Error::Config(format!(
                            "module '{mname}' (timer_class=guaranteed) cannot run on \
                             mechanism-(b) (variable-cadence) domain '{}': mechanism (b) \
                             can drive the tick down to tick_min_us, shrinking the domain \
                             budget below the value its WCET schedulability was proven \
                             at. Re-validate the domain's WCET/budget schedulability at \
                             tick_min_us and set `guaranteed_wcet_revalidated: true`, or \
                             move it to a fixed-cadence domain.",
                            label(d),
                        )));
                    }
                } else if !man.timer_class.tolerates_variable_cadence() {
                    return Err(Error::Config(format!(
                        "module '{mname}' (timer_class={}) cannot run on mechanism-(b) \
                         (variable-cadence) domain '{}': it must positively attest \
                         `timer_class = \"wall_clock\"` (or `\"agnostic\"` if it is \
                         genuinely cadence-independent). An unattested module defaults \
                         to step_counted and is blocked on (b) until attested.",
                        man.timer_class.as_str(),
                        label(d),
                    )));
                }
                // A coarse step period counts TICKS, so the
                // wall-clock period (step_period_ticks × domain_tick_us) warps as
                // the pacer moves — blocked unless the module reads real time.
                if man.step_period_ticks != 0 && man.timer_class != TimerClass::WallClock {
                    return Err(Error::Config(format!(
                        "module '{mname}' (step_period_ticks={}) cannot run on \
                         mechanism-(b) domain '{}': its period counts scheduler ticks, \
                         so the wall-clock cadence (step_period_ticks × domain_tick_us) \
                         warps as the pacer moves. Declare `timer_class = \"wall_clock\"` \
                         only if it re-derives its period from real time, else move it \
                         to a fixed-cadence domain.",
                        man.step_period_ticks,
                        label(d),
                    )));
                }
                // `tick_count()`-as-milliseconds needs no gate of its own: on
                // the DBG_TICK-backed HALs (bcm2712/Linux) the HAL
                // `tick_count` op is wall-clock-backed
                // (`bcm_now_millis`/`elapsed_micros`), matching rp's `Instant` HAL,
                // and timer FDs derive deadlines from `hal::now_millis`
                // (`fd.rs`). A module that *itself* counts scheduler ticks as time
                // declares `tick_counted` and is already rejected above by the
                // attestation gate, on every platform. So no residual graph shape
                // is left for the validator to reject here.
                // `dbg_tick_backed`/`silicon` remain in scope for the domain-0
                // DBG_TICK gate above.
            } else if man.timer_class.forbids_adaptive() {
                return Err(Error::Config(format!(
                    "module '{mname}' (timer_class={}) cannot run on adaptive-tick \
                     domain '{}': a {} module's timekeeping does not tolerate a \
                     variable scheduler cadence. Move it to a fixed-cadence \
                     domain (adaptive_flags=0) or correct its timer_class.",
                    man.timer_class.as_str(),
                    label(d),
                    man.timer_class.as_str(),
                )));
            }
        } else if let Some(root) = resolve_module_root(mtype, extra_module_dirs) {
            // Not in the parsed map: either a malformed manifest (omitted by the
            // loader's warn-and-skip) or genuinely manifest-less.
            let manifest_path = root.join("manifest.toml");
            if manifest_path.exists() {
                // A malformed manifest is a hard error on ANY adaptive domain — its
                // timer_class can't be verified, so fail closed (a typo must not
                // downgrade to "no manifest" and pass).
                if let Err(e) = Manifest::from_toml(&manifest_path) {
                    return Err(Error::Config(format!(
                        "module '{mname}' is placed on adaptive-tick domain '{}' but \
                         its manifest {} failed to parse, so its timer_class cannot \
                         be verified: {e}. Fix the manifest — a malformed \
                         timer_class must not silently downgrade to 'no manifest' \
                         and pass adaptive admission.",
                        label(d),
                        manifest_path.display(),
                    )));
                }
                // Parses but absent from the map (shouldn't happen) — leave it;
                // the lenient/strict checks above only apply via the map.
            } else if cadence {
                // Genuinely manifest-less on a mechanism-(b) domain: unattested ⇒
                // blocked. On an (a)-only domain it is still admitted (lenient).
                return Err(Error::Config(format!(
                    "module '{mname}' has no manifest, so it cannot attest a \
                     timer_class, and an unattested module cannot run on \
                     mechanism-(b) (variable-cadence) domain '{}'. Add a manifest \
                     declaring `timer_class = \"wall_clock\"` or `\"agnostic\"`, or \
                     move it to a fixed-cadence domain.",
                    label(d),
                )));
            }
        } else if cadence {
            // Module root unresolvable AND on a (b) domain ⇒ cannot attest ⇒ block.
            return Err(Error::Config(format!(
                "module '{mname}' could not be resolved to a manifest, so its \
                 timer_class cannot be verified; an unattested module cannot run on \
                 mechanism-(b) domain '{}'.",
                label(d),
            )));
        }

        // Burst-at-floor: for a (b) domain, the burst deadline must fit the
        // SMALLEST cadence the domain can reach (tick_min).
        if flags[d] & ADAPTIVE_FLAG_CADENCE as u64 != 0 {
            if let Some(dl) = m.get("step_deadline_us").and_then(|v| v.as_u64()) {
                // Match validate_module_step_deadlines and the runtime: an
                // explicit burst ceiling overrides the multiplier-derived
                // default. Ignoring it here would make an otherwise valid
                // adaptive graph impossible to express, and would let the two
                // validators reach contradictory verdicts.
                let burst = m
                    .get("step_deadline_burst_us")
                    .and_then(|v| v.as_u64())
                    .filter(|v| *v > 0)
                    .unwrap_or_else(|| dl.saturating_mul(BURST_DEADLINE_MULTIPLIER as u64));
                let floor_tick = if tmin[d] > 0 { tmin[d] } else { eff(d) as u64 };
                if burst > floor_tick.saturating_mul(16) {
                    return Err(Error::Config(format!(
                        "module '{mname}' in adaptive (cadence) domain '{}': burst deadline \
                         {burst} us (step_deadline_us={dl} × {BURST_DEADLINE_MULTIPLIER}) exceeds \
                         16 × tick_min_us ({}). Mechanism (b) can drive the tick down to \
                         tick_min_us, so the burst guardrail must fit there. Lower \
                         step_deadline_us or raise tick_min_us.",
                        label(d),
                        floor_tick.saturating_mul(16)
                    )));
                }
            }
        }

        // Liveness / multi-node raft gates apply to raft_engine.
        if mtype != "raft_engine" {
            continue;
        }
        // A raft-owning domain on a multi-node cluster must be fixed cadence.
        if multi_node {
            return Err(Error::Config(format!(
                "raft_engine '{mname}' is on adaptive domain '{}' of a multi-node cluster \
                 (voter_count/peer_count > 1). Per-node-variable pacing de-syncs heartbeat/\
                 election timing across nodes → cross election timeouts. Pin the raft-owning \
                 domain to fixed cadence (remove adaptive_flags) — every node must pace \
                 heartbeat and election timing identically.",
                label(d)
            )));
        }
        // Demand-driven idle on a liveness domain requires the backstop to
        // fire before a heartbeat is due.
        if flags[d] & ADAPTIVE_FLAG_IDLE as u64 != 0 {
            let hb_ms =
                module_param_u64(m, "heartbeat_interval_ms").unwrap_or(DEFAULT_HEARTBEAT_MS);
            let hb_us = hb_ms.saturating_mul(1000);
            let emax = if tmax[d] > 0 { tmax[d] } else { eff(d) as u64 };
            if emax >= hb_us {
                return Err(Error::Config(format!(
                    "raft_engine '{mname}' on adaptive domain '{}': demand-driven idle \
                     (adaptive_flags bit 0) with tick_max_us={emax} ≥ heartbeat_interval \
                     ({hb_ms} ms = {hb_us} us). An idle leader would stop emitting heartbeats \
                     for up to tick_max_us while followers count toward election timeout → \
                     spurious elections. Set tick_max_us < {hb_us}, or clear bit 0 on this \
                     domain.",
                    label(d)
                )));
            }
        }
    }

    // Shared-runner co-residency gate (reject-by-default). Populate `has_strict`
    // across ALL domains — a timing-strict module (Guaranteed WCET,
    // replicated clock, raft liveness) usually sits on a NON-adaptive domain, so
    // the adaptive-only module loop above doesn't see it.
    for m in module_list {
        let mtype = m
            .get("type")
            .or_else(|| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mname = m.get("name").and_then(|v| v.as_str()).unwrap_or(mtype);
        let d = resolve_domain_id(m, config)? as usize;
        if d >= MAX_DOMAINS {
            continue;
        }
        let strict = mtype == "raft_engine"
            || manifests
                .get(mname)
                .map(|man| {
                    matches!(
                        man.timer_class,
                        TimerClass::Guaranteed | TimerClass::ReplicatedClock
                    )
                })
                .unwrap_or(false);
        if strict {
            has_strict[d] = true;
        }
    }
    // An adaptive domain sharing a physical runner (overlapping core mask) with
    // a timing-strict domain is rejected: a variable-cadence sibling can delay
    // the strict domain's deadline/emission/wake, and proving the bound under
    // worst-case adaptive load is intractable, so the gate rejects by default.
    // The fix is placement — a dedicated runner / ISR tier — not a
    // schedulability proof.
    for a in 0..MAX_DOMAINS {
        if flags[a] == 0 {
            continue; // `a` is not adaptive
        }
        for b in 0..MAX_DOMAINS {
            if a == b || !has_strict[b] {
                continue;
            }
            if core_mask[a] & core_mask[b] != 0 {
                return Err(Error::Config(format!(
                    "adaptive domain '{}' shares a runner (overlapping cores) with \
                     timing-strict domain '{}' (a guaranteed-WCET, replicated-clock, \
                     or raft-liveness module). A variable-cadence sibling can delay \
                     the strict domain's deadline/emission/wake, and the bound cannot \
                     be proven under worst-case adaptive load. Pin the strict domain \
                     to its own core or an ISR tier, or remove adaptive_flags from \
                     '{}'.",
                    label(a),
                    label(b),
                    label(a),
                )));
            }
        }
    }

    Ok(())
}

/// Build-time admission gate for Tier 1b/Tier 2 (ISR) domains.
///
/// Rules enforced:
///
/// 1. **`isr_safe` attestation is mandatory.** Every module assigned
///    to a domain with `tier: 1b` (`exec_mode == 2`) or `tier: 2`
///    (`exec_mode == 4`) must declare `isr_safe = true` in its
///    manifest. Modules without the flag are rejected at build time
///    with a message naming the module, the domain, and the manifest
///    path so the author knows exactly where to add the attestation.
///    Bridge routing has no fall-back: if the kernel admitted a
///    non-ISR-safe module into an ISR domain it would deadlock on
///    `provider_call` from interrupt context. For Tier 2 modules this
///    rule also requires a `module_isr_entry` export in the source —
///    the IRQ dispatches into it, not the cooperative `module_step`.
///
/// 2. **No edges touching ISR-tier endpoints.** ANY YAML edge with at
///    least one Tier 1b/2 endpoint is rejected, regardless of
///    `edge_class`. The kernel-side bridge wiring
///    (`scheduler::wire_isr_bridges` + `pump_isr_bridges`) and the
///    module-facing surface (`bridge::SELF_BRIDGES` enumerates a
///    module's own bridge fds; the bridge `WRITE`/`READ`/`POLL`/`INFO`
///    ops are exempt from the ISR syscall deny-list, being lock-free
///    rings) both exist, but the end-to-end YAML-edge → bridge-fd
///    wiring is not silicon-validated, so the edge gate stays strict:
///    admitting a config that might silently mis-wire at runtime is
///    worse than rejecting it loudly. Tests exercise the kernel-side
///    bridge mechanism via `install_static_config` +
///    `set_domain_exec_mode`.
///
/// A module that lands in an ISR-tier domain without a resolvable
/// manifest is a **hard error**. `validate_wiring_types` only
/// enforces content-type compatibility when both edge endpoints
/// have manifests, so a Tier 1b module with no wiring (or bare /
/// default ports) would otherwise slip through both this gate and
/// the wiring check unchecked. The diagnostic names the module +
/// the directory it should live under.
fn validate_isr_tier_admission(
    config: &Value,
    module_list: &[Value],
    modules_dir: &std::path::Path,
    extra_module_dirs: &[&std::path::Path],
    resolved_target: Option<&str>,
    project_root: &std::path::Path,
) -> Result<()> {
    // Per-domain exec_mode for the four supported domains.
    let mut domain_exec_mode: [u8; 4] = [0; 4];
    let mut domain_names_local: [Option<String>; 4] = [None, None, None, None];
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
        for (i, dom) in domains.iter().take(4).enumerate() {
            if let Some(name) = dom.get("name").and_then(|n| n.as_str()) {
                domain_names_local[i] = Some(name.to_string());
            }
            match parse_domain_tier_to_exec_mode(dom) {
                Some(m) => domain_exec_mode[i] = m,
                None => {
                    // Unknown tier specifier — surface it. Silent
                    // fall-through to Tier 0 cooperative would let a
                    // typo (`tier: 1c`) silently downgrade the
                    // execution discipline.
                    if dom.get("tier").is_some() || dom.get("exec_mode").is_some() {
                        let label = domain_names_local[i]
                            .clone()
                            .unwrap_or_else(|| format!("domains[{i}]"));
                        return Err(Error::Config(format!(
                            "execution.domains entry '{label}' has an unknown tier/exec_mode \
                             value. Valid: 0/cooperative, 1a/high_rate, 1b/isr_timer, \
                             3/poll, 2/isr_owned."
                        )));
                    }
                }
            }
        }
    }

    // Tier 2 (per-IRQ) admission: a Tier 2 module is dispatched from
    // its `module_isr_entry` export (resolved by the kernel loader into
    // `DynamicModule::isr_entry_fn()` and routed through
    // `register_tier2_module`). Rules 1/3 below require every Tier 2
    // module to declare `isr_safe = true`, an `irq:` field, and an
    // actual `module_isr_entry` export in its source.

    // Helper: does this exec_mode require ISR-safe modules?
    let is_isr_tier = |m: u8| -> bool { m == 2 || m == 4 };

    // Helper: friendly tier label for error messages.
    let tier_label = |m: u8| -> &'static str {
        match m {
            2 => "1b (isr_timer)",
            4 => "2 (isr_owned)",
            _ => "unknown",
        }
    };

    let manifests = load_module_manifests_with_extra(
        &Value::Array(module_list.to_vec()),
        extra_module_dirs,
        project_root,
    );

    // ── Rule 0: Tier-2 IRQ range (structural, target-specific) ──────────
    // Validate the declared `irq:` against the resolved silicon's interrupt
    // controller BEFORE the manifest/export checks, so a bad IRQ value is
    // rejected regardless of manifest state. The bound is the interrupt
    // controller's maximum valid line number; a larger value would index the
    // controller's enable/priority/target registers out of range on silicon.
    // The runtime `irq_bind` on each platform enforces the same bound as a
    // backstop.
    //
    //   - GIC-400 (bcm2712): INTIDs 0..=1019. 1020..=1023 are
    //     reserved/special (e.g. 1023 = spurious). SGIs (0-15), PPIs (16-31) and
    //     SPIs (32-1019) are all valid Tier-2 owners (the `tier2_probe` example
    //     legitimately owns SGI 15).
    //   - RP2350 (Cortex-M33/Hazard3 NVIC): highest line is SWI_IRQ_5 = 52, so
    //     0..=52 (rp-pac `rp235x::Interrupt`). SWI lines are real NVIC lines and
    //     valid to unmask; the bound exists only to keep the ISER/ICER index in
    //     range.
    //   - RP2040 (Cortex-M0+ NVIC): highest line is SWI_IRQ_5 = 31, so 0..=31
    //     (rp-pac `rp2040::Interrupt`).
    //
    // `resolved_target` (the CLI target) is authoritative; a `target:` in
    // the YAML is the fallback. Board names resolve to silicon through the
    // `targets/` registry (the only board→silicon mapping); the IRQ bound
    // is then keyed on the exact silicon id. Host targets (linux/wasm)
    // and unknown names keep the u16 bound.
    {
        let target_name = resolved_target
            .or_else(|| config.get("target").and_then(|t| t.as_str()))
            .map(|s| s.to_ascii_lowercase());
        // (max_valid_intid, controller_label) for the resolved silicon, if known.
        let irq_bound: Option<(u64, &str)> = target_name.as_deref().and_then(|t| {
            let desc = crate::target::load_target(t, &crate::project::root()).ok()?;
            if desc.is_host() {
                return None;
            }
            match desc.id.as_str() {
                "bcm2712" => Some((1019, "GIC-400 (bcm2712)")),
                "rp2040" => Some((31, "RP2040 NVIC")),
                "rp2350" => Some((52, "RP2350 NVIC")),
                _ => None,
            }
        });
        if let Some((max_intid, label)) = irq_bound {
            for module in module_list {
                let name = match module.get("name").and_then(|n| n.as_str()) {
                    Some(n) => n,
                    None => continue,
                };
                let domain = resolve_domain_id(module, config)?;
                let exec_mode = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
                if exec_mode != 4 {
                    continue;
                }
                if let Some(irq) = module.get("irq").and_then(|v| v.as_u64()) {
                    if irq > max_intid {
                        return Err(Error::Config(format!(
                            "module '{name}' declares Tier 2 `irq: {irq}`, but the {label} on \
                             this target only has interrupt lines 0..={max_intid}. Pick a valid \
                             IRQ number for the silicon (out-of-range values index the interrupt \
                             controller's registers out of bounds)."
                        )));
                    }
                }
            }
        }
    }

    // ── Rule 1: isr_safe attestation ────────────────────────────
    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let domain = resolve_domain_id(module, config)?;
        let exec_mode = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
        if !is_isr_tier(exec_mode) {
            continue;
        }
        let domain_label = domain_names_local
            .get(domain as usize)
            .and_then(|n| n.clone())
            .unwrap_or_else(|| format!("domain {domain}"));

        // ISR-tier admission requires a manifest — we cannot
        // certify `isr_safe = true` (or run the NEON-import lint)
        // without one. Don't defer to `validate_wiring_types`: that
        // pass only enforces content-type compatibility when both
        // endpoints have manifests, so a Tier 1b module with no
        // edges or bare/default ports would slip through silently.
        let manifest = match manifests.get(name) {
            Some(m) => m,
            None => {
                let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') is assigned to domain \
                     '{domain_label}' (tier {tier}) but no manifest was found. \
                     ISR-tier admission requires a manifest declaring `isr_safe = true`; \
                     add `manifest.toml` under the module's source tree (`modules/<area>/<type>/`) \
                     or list a containing directory in the config's top-level \
                     `module_search_paths:`. Run `fluxor inspect` to see the active search list.",
                    tier = tier_label(exec_mode)
                )));
            }
        };
        if !manifest.isr_safe {
            let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') is assigned to domain '{domain_label}' \
                 (tier {tier}) but its manifest does not declare `isr_safe = true`. \
                 Add `isr_safe = true` to the module's manifest.toml, or move the module \
                 to a cooperative domain.",
                tier = tier_label(exec_mode)
            )));
        }
        // ISR-tier modules are scalar-only by contract.
        // NEON registers are not preserved across a Tier 1b/Tier 2
        // ISR — a module that pulls in `core::arch::aarch64` SIMD
        // intrinsics from inside its ISR entry would corrupt the
        // preempted cooperative thread's NEON file. Run the
        // source-static lint on the module's `src/` tree; if it
        // finds NEON markers, reject the placement.
        //
        // The lookup goes through `resolve_module_root` so the
        // search order is identical to the manifest loader's: an
        // explicit YAML `module_search_paths:` entry shadowing a
        // bundled module wins for both `isr_safe` and the NEON
        // lint, instead of one reader trusting the bundled copy
        // and the other trusting the override.
        let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
        if let Some(root) = resolve_module_root(module_type, extra_module_dirs) {
            if let Err(e) = crate::manifest::check_isr_safe_no_neon(&root) {
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') admitted to domain \
                     '{domain_label}' (tier {tier}) but its source declares NEON: {e}",
                    tier = tier_label(exec_mode)
                )));
            }
            // Tier 2 (IRQ-owned) modules are dispatched from hardware-IRQ
            // context through their `module_isr_entry` export, NOT the
            // cooperative `module_step`. The authoritative gate is the
            // packer (ELF symtab → `.fmod` isr_module bit) + the loader
            // (`isr_entry_fn = None` → admission fail-closes at runtime).
            // This source-static check is the early, build-time mirror
            // so a Tier 2 module missing the entry point fails the graph
            // build instead of getting refused on the rig. (Tier 1b —
            // `exec_mode == 2` — dispatches the cooperative step from a
            // polled timer and needs no ISR entry. `module_isr_init` is
            // a reserved ABI symbol with no consumer today — Tier 2
            // construction goes through the normal cooperative
            // `module_new`, same as Tier 1b — so it is intentionally not
            // required here.)
            if exec_mode == 4 {
                if let Err(e) = crate::manifest::check_module_exports_isr_entry(&root) {
                    return Err(Error::Config(format!(
                        "module '{name}' (type '{module_type}') is assigned to domain \
                         '{domain_label}' (tier {tier}) but {e}. A Tier 2 module must \
                         export `module_isr_entry` (an `extern \"C\" fn(*mut u8) -> i32`) \
                         — the hardware IRQ dispatches into it, not the cooperative \
                         `module_step`.",
                        tier = tier_label(exec_mode)
                    )));
                }
            }
        } else if exec_mode == 4 {
            // No resolvable source root for a Tier 2 module means we
            // can't certify the ISR entry export exists. The manifest
            // check (Rule 1, above) already hard-errors a Tier 2 module
            // with no manifest, so reaching here implies a manifest with
            // no co-located `src/` tree — still unsafe to admit.
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') is assigned to a Tier 2 \
                 (isr_owned) domain but its source tree could not be resolved to \
                 verify the required `module_isr_entry` export. Place the module's \
                 `src/` tree alongside its manifest, or move it to a cooperative domain."
            )));
        }
    }

    // Build module name → exec_mode lookup (used by Rules 2 and 3).
    let mut module_exec_mode: std::collections::HashMap<String, u8> =
        std::collections::HashMap::new();
    for module in module_list {
        if let Some(name) = module.get("name").and_then(|n| n.as_str()) {
            let domain = resolve_domain_id(module, config)?;
            let m = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
            module_exec_mode.insert(name.to_string(), m);
        }
    }

    // ── Rule 3 (runs BEFORE Rule 2 so wireless graphs still check):
    // Tier 2 `irq:` requirement + duplicate check. (The target-specific IRQ
    // range is validated structurally in Rule 0, above, before manifests.)
    let mut seen_irq: Vec<(u16, String)> = Vec::new();
    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let m = module_exec_mode.get(name).copied().unwrap_or(0);
        if m != 4 {
            continue;
        }
        let irq = match module.get("irq").and_then(|v| v.as_u64()) {
            Some(n) if n < u16::MAX as u64 => n as u16,
            Some(_) | None => {
                return Err(Error::Config(format!(
                    "module '{name}' is in a Tier 2 (isr_owned) domain but does not \
                     declare an `irq:` field (or its value is out of u16 range). Add \
                     `irq: N` on the module, where N is the hardware IRQ number the \
                     module owns."
                )));
            }
        };
        if let Some((_, prev_name)) = seen_irq.iter().find(|(i, _)| *i == irq) {
            return Err(Error::Config(format!(
                "Tier 2 IRQ {irq} declared by both module '{prev_name}' and \
                 module '{name}'. Two modules sharing one hardware IRQ produce \
                 undefined dispatch ordering — the kernel's \
                 `isr_tier2_trampoline` is a single-handler-per-IRQ table. Give \
                 each Tier 2 module a distinct IRQ number."
            )));
        }
        seen_irq.push((irq, name.to_string()));
    }

    // ── Rule 2: edges touching ISR-tier modules are rejected ────
    //
    // v1 reality: the kernel-side bridge wiring works — `wire_isr_bridges`
    // + `pump_isr_bridges` shuttle bytes
    // between cooperative PIPE channels and bridge rings — but PIC
    // modules have NO documented way to read their own bridge slot
    // indices from inside `module_step`, and the ISR syscall gate
    // denies `provider_call` (which the SDK's `bridge_dispatch`
    // helper rides on). So an ISR-endpoint edge would get a bridge
    // slot allocated, the kernel would drain bytes into the ring,
    // and the ISR module would have no supported way to read them.
    //
    // Until the module-facing bridge ABI lands (see
    // `docs/architecture/scheduler.md` §"ISR-tier I/O contract"),
    // reject ANY YAML edge with an ISR-tier endpoint. Tests that
    // bypass YAML (e.g. `tests/harness/tests/scheduler_isr_bridges.rs`)
    // continue to exercise the kernel-side mechanism through
    // `install_static_config` + `set_domain_exec_mode`, but a real
    // graph can't admit a configuration that would silently
    // not-work at runtime.
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Ok(()),
    };
    for (i, edge) in wiring.iter().enumerate() {
        let from_mod = edge
            .get("from")
            .and_then(|v| v.as_str())
            .and_then(|s| s.split('.').next())
            .unwrap_or("");
        let to_mod = edge
            .get("to")
            .and_then(|v| v.as_str())
            .and_then(|s| s.split('.').next())
            .unwrap_or("");
        let from_isr = module_exec_mode
            .get(from_mod)
            .copied()
            .map(is_isr_tier)
            .unwrap_or(false);
        let to_isr = module_exec_mode
            .get(to_mod)
            .copied()
            .map(is_isr_tier)
            .unwrap_or(false);
        if from_isr || to_isr {
            return Err(Error::Config(format!(
                "wiring[{i}] (from '{from_mod}' to '{to_mod}'): an edge touching an \
                 ISR-tier endpoint cannot be wired in v1 — PIC modules have no \
                 module-facing API to read/write their bridge slots from inside \
                 `module_step`. The kernel-side bridge mechanism is wired and \
                 tested, but the SDK surface is not. Drop the edge from your YAML \
                 (Tier 1b modules in v1 do private-state work only), or move both \
                 endpoints to cooperative tiers. Track \
                 `docs/architecture/scheduler.md` §\"ISR-tier I/O contract\" \
                 for the lift."
            )));
        }
        // Past this point both endpoints are cooperative. Any
        // explicit `edge_class` (DmaOwned/CrossCore/NicRing) on a
        // cooperative-only edge is the operator's choice and the
        // existing wiring path handles it.
    }

    // Bonus diagnostic: warn if an ISR-tier domain has no modules
    // assigned. A misnamed `domain:` field on a module is a common
    // typo (the hard-error `resolve_domain_id` already catches
    // it), but a correctly-named domain with no members is also a
    // bug. Check by **domain id**, not by exec_mode: two domains
    // at the same tier would otherwise mask each other (every
    // module's exec_mode would be 2, satisfying the check for
    // BOTH Tier 1b domains regardless of which they actually
    // belong to).
    //
    // Tier 1b admission is live (gated on `isr_safe = true` +
    // NEON-import lint); Tier 2 admission is live too (additionally
    // gated on an `irq:` field + a `module_isr_entry` export). This
    // check stays honest for both tiers — an empty ISR-tier domain is
    // still a bug.
    let mut per_domain_member_count: [usize; 4] = [0; 4];
    for module in module_list {
        let d = resolve_domain_id(module, config)?;
        if (d as usize) < per_domain_member_count.len() {
            per_domain_member_count[d as usize] += 1;
        }
    }
    for d in 0..4 {
        if !is_isr_tier(domain_exec_mode[d]) {
            continue;
        }
        if per_domain_member_count[d] > 0 {
            continue;
        }
        let label = domain_names_local[d]
            .clone()
            .unwrap_or_else(|| format!("domains[{d}]"));
        eprintln!(
            "warning: execution.domains entry '{label}' is tier {tier} but has no \
             modules assigned to it. Did you forget a `domain: {label}` on a module?",
            tier = tier_label(domain_exec_mode[d])
        );
    }

    let _ = modules_dir; // reserved for future use (per-domain budget files)
    Ok(())
}

/// Reject placement of a `pre_tick_drain` module into any domain
/// whose tier isn't cooperative (Tier 0 or Tier 1a). Pre-tick
/// modules run in cooperative context with the full kernel API;
/// admitting one into a Tier 1b/2 (ISR) or Tier 3 (poll) domain
/// would either run it from interrupt context (where its
/// `provider_call`/heap usage is undefined) or never run it at all
/// (Tier 3 has no `domain_exec_order` to inject the pre-tick slot
/// into). A module declares `pre_tick_drain = true` in its
/// manifest; this validator is what keeps that declaration and the
/// domain's tier consistent.
fn validate_pre_tick_drain_admission(
    config: &Value,
    module_list: &[Value],
    extra_module_dirs: &[&std::path::Path],
    project_root: &std::path::Path,
) -> Result<()> {
    // Per-domain exec_mode for the four supported domains.
    let mut domain_exec_mode: [u8; 4] = [0; 4];
    let mut domain_names_local: [Option<String>; 4] = [None, None, None, None];
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
        for (i, dom) in domains.iter().take(4).enumerate() {
            if let Some(name) = dom.get("name").and_then(|n| n.as_str()) {
                domain_names_local[i] = Some(name.to_string());
            }
            if let Some(m) = parse_domain_tier_to_exec_mode(dom) {
                domain_exec_mode[i] = m;
            }
        }
    }

    let manifests = load_module_manifests_with_extra(
        &Value::Array(module_list.to_vec()),
        extra_module_dirs,
        project_root,
    );

    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let manifest = match manifests.get(name) {
            Some(m) => m,
            None => continue,
        };
        if !manifest.pre_tick_drain {
            continue;
        }
        let domain = resolve_domain_id(module, config)?;
        let exec_mode = *domain_exec_mode.get(domain as usize).unwrap_or(&0);
        // Tier 0 (0) and Tier 1a (1) are the only valid hosts for
        // pre-tick modules. Tier 1b (2) / Tier 2 (4) are ISR; Tier 3
        // (3) is poll-mode with no exec_order to drain alongside.
        if exec_mode != 0 && exec_mode != 1 {
            let domain_label = domain_names_local
                .get(domain as usize)
                .and_then(|n| n.clone())
                .unwrap_or_else(|| format!("domain {domain}"));
            let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
            let tier_name = match exec_mode {
                2 => "1b (isr_timer)",
                3 => "3 (poll)",
                4 => "2 (isr_owned)",
                _ => "non-cooperative",
            };
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') declares \
                 `pre_tick_drain = true` but is assigned to domain '{domain_label}' \
                 (tier {tier_name}). Pre-tick modules run cooperatively at the start \
                 of every scheduler pass — they must live in a Tier 0 or Tier 1a \
                 domain. Move the module to a cooperative domain, or drop \
                 `pre_tick_drain` from its manifest."
            )));
        }
    }

    Ok(())
}

/// Translate a domain's YAML tier specifier into the kernel's
/// `domain_exec_mode` wire byte. Accepts the preferred friendly form
/// (`tier: 1a`) and the `exec_mode:` alias, which spells the same
/// tiers by their long names. Returns `None` when both fields are
/// absent so the caller can default to Tier 0 (cooperative) without confusing
/// "tier omitted" with "tier explicitly set to 0".
///
/// Wire encoding (fixed — adding a tier here MUST keep the existing
/// values intact; this byte is what every `.cfg.bin` blob carries):
///
/// | Tier (friendly)       | exec_mode byte |
/// |-----------------------|----------------|
/// | `0` / `cooperative`   | 0              |
/// | `1a` / `high_rate`    | 1              |
/// | `1b` / `isr_timer`    | 2 (Tier 1b)    |
/// | `3` / `poll`          | 3              |
/// | `2` / `isr_owned`     | 4 (Tier 2)     |
///
/// The Tier 1b → 2 / Tier 2 → 4 mapping is asymmetric: the wire byte
/// is an opaque encoding, not the tier's name, and {0, 1, 3} are taken
/// by Tier 0 / 1a / 3. Reshuffling it would invalidate every built
/// `.cfg.bin` blob.
///
/// **Returned `Err` only on explicit unknown values** — silently
/// dropping a typo'd tier (e.g. `tier: 1c`) would route the domain
/// to Tier 0 cooperative without warning: an ISR-tier module would
/// then run cooperatively with none of the ISR gates applied.
pub(crate) fn parse_domain_tier_to_exec_mode(domain: &Value) -> Option<u8> {
    // `tier:` is the preferred friendly form.
    if let Some(raw) = domain.get("tier") {
        if let Some(s) = raw.as_str() {
            return match s {
                "0" | "cooperative" => Some(0),
                "1a" | "high_rate" | "tier1a" => Some(1),
                "1b" | "isr_timer" | "tier1b" => Some(2),
                "3" | "poll" | "tier3" => Some(3),
                "2" | "isr_owned" | "tier2" => Some(4),
                _ => None,
            };
        }
        if let Some(n) = raw.as_u64() {
            // Bare numeric `tier: 0` only resolves to cooperative;
            // numeric form is intentionally narrow because it's
            // ambiguous for Tier 1a/1b/Tier 2.
            return match n {
                0 => Some(0),
                _ => None,
            };
        }
    }
    // `exec_mode:` is an accepted alias for `tier:`, taking the long
    // names only (no `1a`/`1b` short forms).
    if let Some(m) = domain.get("exec_mode").and_then(|m| m.as_str()) {
        return match m {
            "cooperative" => Some(0),
            "high_rate" | "tier1a" => Some(1),
            "isr_timer" | "tier1b" => Some(2),
            "poll" | "tier3" => Some(3),
            "isr_owned" | "tier2" => Some(4),
            _ => None,
        };
    }
    None
}

/// Resolve a module's domain assignment to a numeric domain ID.
///
/// Looks up the module's `domain` field (string) in the
/// `execution.domains` list. Returns 0 (default domain) when no domain
/// is specified. **Hard error** when a domain is named but not present
/// in `execution.domains` — silently falling back to domain 0 lets a
/// typo'd domain name (or a stale config referencing a removed domain)
/// silently route modules to the default partition, hiding capacity
/// and budget mismatches the rest of the validator counts on.
fn resolve_domain_id(module: &Value, config: &Value) -> Result<u8> {
    let domain_name = match module.get("domain").and_then(|d| d.as_str()) {
        Some(name) => name,
        None => return Ok(0),
    };

    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            for (i, domain) in domains.iter().enumerate() {
                if let Some(name) = domain.get("name").and_then(|n| n.as_str()) {
                    if name == domain_name {
                        // Defense in depth: even though
                        // `generate_config_impl` hard-rejects
                        // `execution.domains.len() > MAX_DOMAINS`
                        // at the top of validation, this lookup is
                        // also reached directly by unit tests +
                        // callers that bypass that gate. Reject
                        // here too so a module that *resolves* to
                        // an out-of-range domain id can never slip
                        // into the rest of the pipeline.
                        if i >= MAX_DOMAINS {
                            return Err(Error::Config(format!(
                                "module references domain '{domain_name}' at index {i}, but \
                                 the kernel supports at most {MAX_DOMAINS} domains. The 5th+ \
                                 entry in `execution.domains` is invalid — drop it or merge \
                                 the modules into an existing domain."
                            )));
                        }
                        return Ok(i as u8);
                    }
                }
            }
            // Build a name list for the error message so the user can
            // spot the typo without grepping the YAML.
            let known: Vec<String> = domains
                .iter()
                .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect();
            return Err(Error::Config(format!(
                "module references unknown domain '{}'; execution.domains declares [{}]",
                domain_name,
                known.join(", ")
            )));
        }
    }

    Err(Error::Config(format!(
        "module references domain '{domain_name}' but execution.domains is missing or empty"
    )))
}

/// Load a built-in module's manifest from the source tree and
/// synthesize a `ParamSchema` from its `[[params]]` declarations.
/// Returns `None` when the manifest doesn't exist, isn't marked
/// built-in, or declares no params. Repeated lookups share a
/// per-process cache via `Manifest::from_source_tree`.
fn load_builtin_param_schema(
    module_type: &str,
) -> Option<(crate::manifest::Manifest, schema::ParamSchema)> {
    let m = crate::manifest::Manifest::from_source_tree(module_type).ok()??;
    if !m.builtin {
        return None;
    }
    let s = schema::ParamSchema::from_manifest(&m)?;
    Some((m, s))
}

/// Reject any YAML key on a built-in module entry that the schema doesn't
/// know about. PIC modules currently silently ignore unknown keys; here we
/// hard-fail because the manifest is the contract and a typo will otherwise
/// silently use the default. Skips structural metadata (name, type, …).
/// Top-level YAML keys that are structural metadata, not module params.
/// Mirrors `schema.rs::SKIP_KEYS` plus the protection/policy/trust tier
/// fields that `build_module_entry` writes as reserved TLV tags
/// (0xF0..0xF5) and a few other cross-cutting fields that the config
/// generator injects.
const NON_PARAM_KEYS: &[&str] = &[
    "name",
    "type",
    // `[[variant]]` selection — consumed by fmod resolution
    // (`parse_modules_from_config_multi`) and the manifest loader,
    // never a wire param.
    "variant",
    "wiring",
    "preset",
    "presets",
    "voices",
    "routes",
    "step_deadline_us",
    "fault_policy",
    "max_restarts",
    "restart_backoff_ms",
    "trust_tier",
    "protection",
    "cert_file",
    "key_file",
    "trust_cert_file",
    "verify_hostname",
    "verify_uri", // URI SAN required under peer_auth: ca_uri, extended TLV tag 15
    "alpn", // RFC 7301 ALPN list, emitted as extended TLV tag 14
    "domain",
    "sample_rate", // injected by graph_sample_rate
    // Protection-control keys emitted as TLV tags by
    // `build_module_entry`. These are top-level module entries, not
    // schema params, so the allow-list lets `validate_yaml_params`
    // pass them through to the dedicated emitter.
    "step_deadline_burst_us",
    "quarantine_partner",     // name form, resolved at wiring pass
    "quarantine_partner_idx", // numeric form passed straight through
    "heap",                   // nested object: { zero_on_free,
                              //   alloc_failure_policy, canary_enabled }
    // Provenance recorded by stack expansion, not authored and not
    // emitted: which stack injected this module entry and which of its
    // params that stack set. Read only to explain a catalog/module skew
    // (see `stack_param_skew`) — a param a live stack asks for that a
    // pinned module does not have.
    "_from_stack",
    "_stack_params",
];

/// Reject any YAML key on a module entry that the schema doesn't know
/// about. Hard-fails for both `.fmod` modules (schema embedded in the
/// .fmod) and built-ins (schema in `manifest.toml [[params]]`).
///
/// The candidate-name check mirrors `build_params_from_schema`'s
/// flattening: nested objects expand to dotted/underscored variants,
/// and outer keys ending in a `GROUPING_SUFFIXES` entry can also resolve
/// to suffix-stripped names. Anything the packer would actually consume
/// passes; only keys that have no path to any schema param fail here.
/// Structural validator for the optional `heap:` subtree. Runs on every
/// module entry regardless of whether the module has a schema source —
/// schema-gated validation would otherwise let a `heap.alloc_failure_policy:
/// "fualt"` typo on a no-schema driver pass silently and disable fault
/// recovery without diagnostic. The emitter at `build_module_entry`
/// reads each subkey through `.as_bool()` / `.as_str()` and drops
/// unrecognised entries with no error; this validator catches the typo
/// at the YAML boundary instead.
fn validate_heap_subtree(module: &Value, module_name: &str) -> Result<()> {
    let Some(value) = module.get("heap") else {
        return Ok(());
    };
    let heap_obj = value.as_object().ok_or_else(|| {
        Error::Config(format!(
            "module '{module_name}': `heap` must be an object \
             (with `zero_on_free` / `alloc_failure_policy` / `canary_enabled`)"
        ))
    })?;
    const HEAP_KEYS: &[&str] = &["zero_on_free", "alloc_failure_policy", "canary_enabled"];
    for (subkey, subval) in heap_obj {
        if !HEAP_KEYS.contains(&subkey.as_str()) {
            return Err(Error::Config(format!(
                "module '{module_name}': unknown heap key 'heap.{subkey}' (valid: {})",
                HEAP_KEYS.join(", "),
            )));
        }
        // `alloc_failure_policy` is the only string-valued key; the
        // others are bool. A type mismatch on either would otherwise
        // leave the tag at its default — the canonical typo case is
        // `true`/`false` misspelled as `"yes"`/`"flase"`.
        match subkey.as_str() {
            "alloc_failure_policy" => {
                let s = subval.as_str().ok_or_else(|| {
                    Error::Config(format!(
                        "module '{module_name}': heap.alloc_failure_policy must be a \
                         string (\"return_null\" or \"fault\")"
                    ))
                })?;
                if s != "return_null" && s != "fault" {
                    return Err(Error::Config(format!(
                        "module '{module_name}': heap.alloc_failure_policy = '{s}' is \
                         invalid (use \"return_null\" or \"fault\")"
                    )));
                }
            }
            _ => {
                if subval.as_bool().is_none() {
                    return Err(Error::Config(format!(
                        "module '{module_name}': heap.{subkey} must be a boolean (true/false)"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Explain an unknown param that a STACK put there, not the author.
///
/// `stacks/` and `targets/` are read live from the fluxor checkout, while
/// the modules they configure are resolved from digests pinned in
/// `fluxor.lock`. Nothing pins the catalog, so the two halves move
/// independently: adding a parameter to a module and referencing it from
/// a stack in the same commit is coherent in the source tree and
/// incoherent for every consumer until that consumer rebuilds or
/// republishes that target's modules.
///
/// When that happens the author is told their graph has an unknown
/// param. Their graph does not mention it — the shorthand they wrote
/// expands to it — so the message names a line they never wrote, in a
/// file they may not have, about a module they did not pin by hand. Say
/// what actually disagrees instead.
fn stack_param_skew(module: &Value, module_name: &str, param: &str) -> Option<String> {
    let obj = module.as_object()?;
    let stack = obj.get("_from_stack")?.as_str()?;
    let owned = obj
        .get("_stack_params")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .any(|p| p == param || param.strip_prefix("params.") == Some(p));
    if !owned {
        return None;
    }
    Some(format!(
        "module '{module_name}': the '{stack}' stack sets parameter '{param}', which \
         this build's '{module_name}' does not have. This is a catalog/module skew, \
         not an error in your config — the stack is read from the fluxor checkout \
         while the module comes from the digest pinned in fluxor.lock, and nothing \
         pins the two together. Rebuild this target's modules (`fluxor modules build \
         --target <target>`), or if you consume fluxor as a dependency, republish and \
         `fluxor update`."
    ))
}

fn validate_yaml_params(
    module: &Value,
    schema: &schema::ParamSchema,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    for (key, value) in obj {
        if NON_PARAM_KEYS.contains(&key.as_str()) {
            if key == "heap" {
                validate_heap_subtree(module, module_name)?;
                let _ = value;
            }
            continue;
        }
        if schema::SKIP_KEYS.contains(&key.as_str()) {
            continue;
        }

        if let Some(inner_obj) = value.as_object() {
            // `params: { ... }` is a transparent wrapper (see
            // `schema::build_params_from_schema`): inner keys map to
            // schema params with no prefix.
            let transparent = key == "params";
            for (inner_key, _) in inner_obj {
                let candidates: Vec<String> = if transparent {
                    let mut c = vec![inner_key.clone()];
                    if inner_key.contains('.') {
                        c.push(inner_key.replace('.', "_"));
                    }
                    c
                } else {
                    nested_key_candidates(key, inner_key)
                };
                if !candidates.iter().any(|c| schema.find(c).is_some()) {
                    let display = if transparent {
                        format!("params.{inner_key}")
                    } else {
                        format!("{key}.{inner_key}")
                    };
                    if let Some(msg) = stack_param_skew(module, module_name, &display) {
                        return Err(Error::Config(msg));
                    }
                    let suggestion = candidates
                        .iter()
                        .filter_map(|c| closest_param_name(c, schema))
                        .next();
                    return Err(Error::Config(format!(
                        "module '{}': unknown param '{}'{}",
                        module_name,
                        display,
                        format_hint(suggestion, schema),
                    )));
                }
            }
            continue;
        }

        // Scalar: same-name lookup, with dotted-to-underscored fallback.
        let mut candidates = vec![key.clone()];
        if key.contains('.') {
            candidates.push(key.replace('.', "_"));
        }
        if !candidates.iter().any(|c| schema.find(c).is_some()) {
            if let Some(msg) = stack_param_skew(module, module_name, key) {
                return Err(Error::Config(msg));
            }
            let suggestion = candidates
                .iter()
                .filter_map(|c| closest_param_name(c, schema))
                .next();
            return Err(Error::Config(format!(
                "module '{}': unknown param '{}'{}",
                module_name,
                key,
                format_hint(suggestion, schema),
            )));
        }
    }
    Ok(())
}

/// Produce the candidate schema-key names a nested YAML pair would
/// resolve to. Mirrors the flattening logic in
/// `schema::build_params_from_schema`: dotted, fully underscored, and
/// (when the outer key ends with a grouping suffix) suffix-stripped.
fn nested_key_candidates(outer: &str, inner: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    let dotted = format!("{outer}.{inner}");
    out.push(dotted.replace('.', "_"));
    out.push(dotted);
    for suffix in schema::GROUPING_SUFFIXES {
        if let Some(prefix) = outer.strip_suffix(suffix) {
            out.push(format!("{prefix}_{inner}"));
        }
    }
    out
}

fn format_hint(suggestion: Option<&str>, schema: &schema::ParamSchema) -> String {
    if let Some(s) = suggestion {
        format!(" — did you mean '{s}'?")
    } else {
        let valid: Vec<&str> = schema.params.iter().map(|p| p.name.as_str()).collect();
        format!(" — valid params: {}", valid.join(", "))
    }
}

/// Fail the build if any param flagged `required = true` is missing or
/// empty in the YAML entry. Counts both the top-level form
/// (`path: ...`) and the transparent `params: { path: ... }` wrapper.
/// "Empty" means the YAML supplied a string that's `""` — for required
/// string params there is no useful fallback, and silently passing the
/// empty value through to the runtime would defeat the point of the
/// flag (e.g. `host_asset_source.path = ""` would land at
/// `File::open("")`). Defaults aren't a fallback for required params
/// — by definition there isn't one.
fn validate_required_params(
    module: &Value,
    manifest: &crate::manifest::Manifest,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    let inner = obj.get("params").and_then(|v| v.as_object());
    for p in &manifest.params {
        if !p.required {
            continue;
        }
        let value = obj
            .get(&p.name)
            .or_else(|| inner.and_then(|i| i.get(&p.name)));
        let Some(v) = value else {
            return Err(Error::Config(format!(
                "module '{}': required param '{}' is missing from YAML",
                module_name, p.name,
            )));
        };
        // Strings (including the enum default representation) must
        // be non-empty — an empty string here is the same failure
        // shape as omission, just spelled differently.
        if let Some(s) = v.as_str() {
            if s.is_empty() {
                return Err(Error::Config(format!(
                    "module '{}': required param '{}' is empty",
                    module_name, p.name,
                )));
            }
        }
    }
    Ok(())
}

/// Range-check numeric params against the manifest's `range = [min, max]`.
/// Honors both top-level placement and the transparent `params: {...}`
/// wrapper so the check stays in lock-step with the packer's view.
fn validate_param_ranges(
    module: &Value,
    manifest: &crate::manifest::Manifest,
    module_name: &str,
) -> Result<()> {
    let obj = match module.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };
    let inner = obj.get("params").and_then(|v| v.as_object());
    for p in &manifest.params {
        let Some((min, max)) = p.range else {
            continue;
        };
        let Some(v) = obj
            .get(&p.name)
            .or_else(|| inner.and_then(|i| i.get(&p.name)))
            .and_then(|v| v.as_u64())
        else {
            continue;
        };
        if (v as u32) < min || (v as u32) > max {
            return Err(Error::Config(format!(
                "module '{}': param '{}'={} is outside [{}, {}]",
                module_name, p.name, v, min, max,
            )));
        }
    }
    Ok(())
}

/// Clone the YAML module entry and fill in any manifest-declared
/// default that the YAML didn't supply. Honours the transparent
/// `params: { ... }` wrapper — values inside it are picked up first.
/// Result: every declared param has a value (YAML override or default),
/// so the packer emits a TLV entry for each one and built-ins don't
/// need to re-encode defaults in code.
fn inject_manifest_defaults(module: &Value, manifest: &crate::manifest::Manifest) -> Value {
    let mut clone = module.clone();
    let Some(obj) = clone.as_object_mut() else {
        return clone;
    };
    let inner_present: std::collections::HashSet<String> = obj
        .get("params")
        .and_then(|p| p.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for p in &manifest.params {
        // Already supplied — top-level form or in the params: wrapper.
        if obj.contains_key(&p.name) || inner_present.contains(&p.name) {
            continue;
        }
        if p.required {
            // Required params have no default to inject;
            // `validate_required_params` raises the user-facing error.
            continue;
        }
        let val = match p.ptype {
            crate::manifest::ManifestParamType::U8
            | crate::manifest::ManifestParamType::U16
            | crate::manifest::ManifestParamType::U32 => json!(p.default_num),
            crate::manifest::ManifestParamType::Str => json!(p.default_str),
            crate::manifest::ManifestParamType::Enum => {
                // Enums pack from string→u8 via the schema, so put the
                // default name on the YAML side and let the packer
                // resolve it.
                json!(p.default_str)
            }
        };
        obj.insert(p.name.clone(), val);
    }
    clone
}

/// Levenshtein-light: pick the schema param name with the smallest edit
/// distance to `key`, returning it only if the distance is plausibly a typo
/// (≤ 2 edits, or up to half the key length for short names).
/// "Did you mean…?" lookup for param names. Threshold is dynamic —
/// `(key.len() / 2).clamp(2, 4)` — because param names vary widely
/// in length and a fixed cap would be too strict for long names
/// (`encryption_passphrase` deserves more typo tolerance than `iv`).
///
/// Delegates the actual Levenshtein walk to the shared
/// `crate::text_distance::closest_match` helper used across every
/// other "did you mean" surface. Single source of truth — a future
/// improvement to the Levenshtein implementation (or a switch to
/// Damerau-Levenshtein etc.) takes effect uniformly.
fn closest_param_name<'a>(key: &str, schema: &'a schema::ParamSchema) -> Option<&'a str> {
    let threshold = (key.len() / 2).clamp(2, 4);
    let candidates: Vec<String> = schema.params.iter().map(|p| p.name.clone()).collect();
    crate::text_distance::closest_match(key, &candidates, threshold).and_then(|name| {
        // closest_match returns an owned String; map back to the
        // borrowed `&'a str` the caller expects by looking up
        // the schema entry that matched.
        schema
            .params
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.name.as_str())
    })
}

/// Expand compound YAML fields that don't map 1:1 to schema params,
/// returning a clone with the flat fields in place. Pure YAML-level
/// rewrite — schema lookup runs unchanged afterwards.
///
/// Currently handles:
///   - mqtt `broker: "host:port"` → `broker_ip: u32` + `broker_port: u16`
///   - mqtt derived `subscribe_topic` from top-level `device_uuid` if
///     the YAML didn't set one explicitly
///
/// Modules whose params can already be expressed as schema entries
/// (or where `params: { ... }` covers the grouping) don't need an
/// entry here.
fn expand_compound_yaml_fields(type_name: &str, module: &Value, config: &Value) -> Value {
    let mut clone = module.clone();
    if type_name == "mqtt" {
        if let Some(obj) = clone.as_object_mut() {
            // Pull `broker:` out (singular form) and expand into
            // `broker_ip` / `broker_port` if neither is already set.
            if let Some(broker) = obj.get("broker").and_then(|v| v.as_str()) {
                let (ip, port) = parse_broker_addr(broker);
                if !obj.contains_key("broker_ip") {
                    obj.insert("broker_ip".into(), json!(ip));
                }
                if !obj.contains_key("broker_port") {
                    obj.insert("broker_port".into(), json!(port));
                }
                obj.remove("broker");
            }
            // Derive subscribe_topic from top-level device_uuid if the
            // YAML didn't set one explicitly. mesh-aware mqtt brokers
            // listen on `fluxor/{device_hex}/objects/+/commands`.
            if !obj.contains_key("subscribe_topic") {
                if let Some(uuid_str) = config.get("device_uuid").and_then(|v| v.as_str()) {
                    let uuid = parse_uuid_bytes(uuid_str);
                    if uuid != [0u8; 16] {
                        let hex: String = uuid.iter().map(|b| format!("{b:02x}")).collect();
                        obj.insert(
                            "subscribe_topic".into(),
                            json!(format!("fluxor/{}/objects/+/commands", hex)),
                        );
                    }
                }
            }
        }
    }
    clone
}

#[allow(
    clippy::too_many_arguments,
    reason = "module-entry compilation threads the resolved graph context (config, manifests, modules_dir); splitting it into a context struct is a larger refactor than the argument count warrants"
)]
fn build_module_entry(
    name: &str,
    module: &Value,
    id: u8,
    data_section: Option<&Value>,
    config: &Value,
    modules_dir: &Path,
    manifests: &HashMap<String, Manifest>,
    max_modules: usize,
) -> Result<Vec<u8>> {
    // Start with max possible size, will truncate to actual used size
    let mut entry = vec![0u8; MODULE_ENTRY_HEADER_SIZE + MAX_MODULE_PARAMS_SIZE];

    // Leave bytes 0-1 for entry_length (filled at end)

    // Module type: explicit "type" field or falls back to "name"
    let type_name = module["type"].as_str().unwrap_or(name);

    // Name hash (bytes 2-5) — hash the type name so the kernel can find the .fmod.
    // This allows multiple instances: name: seq_kick, type: sequencer
    let name_hash = fnv1a_hash(type_name.as_bytes());
    // Header layout (10 bytes total):
    //   bytes 0-3: entry_length (u32, patched in below at line ~1953)
    //   bytes 4-7: name_hash (u32)
    //   byte 8:    module id
    //   byte 9:    bits 0-2 = domain_id (0..7), bit 4 = pre_tick_drain
    //              (Tier 1c opt-in). Mirrored from
    //              `manifest.pre_tick_drain`. Kept on the module entry
    //              (not the .fmod manifest) so the kernel reads it
    //              during `prepare_graph` without a second loader pass.
    entry[4..8].copy_from_slice(&name_hash.to_le_bytes());
    entry[8] = id;
    let domain_id = resolve_domain_id(module, config)?;
    if domain_id > 7 {
        return Err(Error::Config(format!(
            "module `{name}` resolves to domain_id={domain_id}, exceeds wire-format max of 7"
        )));
    }
    // `manifests` was populated by `load_module_manifests_with_extra`
    // against the SAME resolver chain that admission validation
    // uses (project root, install root, caller-supplied extras).
    // The previous version called `Manifest::from_source_tree`
    // here, which used a hard-coded `SOURCE_DIRS` list — modules
    // outside that list (e.g. an installed driver with
    // `pre_tick_drain = true`) would pass admission but emit a
    // config blob with the bit clear, silently demoting the module
    // out of `domain_pre_tick_order` at runtime.
    let pre_tick_drain = manifests.get(name).is_some_and(|m| m.pre_tick_drain);
    entry[9] = domain_id | (if pre_tick_drain { 0x10 } else { 0 });

    // Track actual params length used
    let params_len: usize;

    // Some modules accept compound YAML fields that don't map 1:1 to
    // schema params (e.g. `broker: "host:port"` in mqtt). Expand them
    // into the flat fields the schema knows about before packing.
    let normalized_module = expand_compound_yaml_fields(type_name, module, config);
    let module = &normalized_module;

    // The `heap:` subtree is structurally orthogonal to the schema
    // (it's emitted as protection TLV tags, not schema params), so
    // its validator runs unconditionally — modules with no schema
    // source must still surface a `heap.alloc_failure_policy` typo
    // at build time rather than letting it silently drop at runtime.
    validate_heap_subtree(module, type_name)?;

    // PIC modules embed their schema in the `.fmod`; built-ins declare
    // it in `modules/platform/<platform>/<name>/manifest.toml`. Both
    // paths produce a `ParamSchema` and feed the same TLV packer, so
    // the wire format is identical at the kernel boundary.
    //
    // `?` propagates only the pinned-but-unresolvable case, which is a hard
    // error (sibling of `assert_pinned_manifests_resolvable`). "No `.fmod`
    // schema" stays `Ok(None)` and falls through to the built-in path — a
    // built-in is never pinned and has no `.fmod`.
    if let Some(param_schema) = schema::load_schema_for_module(type_name, modules_dir)? {
        validate_yaml_params(module, &param_schema, type_name)?;
        params_len = schema::build_params_from_schema(
            module,
            &param_schema,
            &mut entry,
            P,
            data_section,
            type_name,
        )
        .map_err(Error::Config)?;
    } else if let Some((manifest, param_schema)) = load_builtin_param_schema(type_name) {
        validate_yaml_params(module, &param_schema, type_name)?;
        validate_param_ranges(module, &manifest, type_name)?;
        validate_required_params(module, &manifest, type_name)?;
        // Inject manifest defaults into a YAML clone so every declared
        // param produces a TLV entry. The built-in's step function
        // reads values straight off the wire, with no defaults
        // duplicated in Rust.
        let module_with_defaults = inject_manifest_defaults(module, &manifest);
        params_len = schema::build_params_from_schema(
            &module_with_defaults,
            &param_schema,
            &mut entry,
            P,
            data_section,
            type_name,
        )
        .map_err(Error::Config)?;
    } else {
        // Module type with no schema source — typically a misnamed
        // YAML entry. Emit an empty params section; downstream
        // resource and capability checks raise the user-facing error.
        params_len = 0;
    }

    // Append protection / fault-policy params as reserved TLV tags
    // (0xF0..0xFA). Parsed by the kernel scheduler during
    // instantiation via `parse_protection_config`.
    //
    // The schema packer writes a `0xFF 0x00` TLV end-marker at the
    // tail of `params_len`, and the kernel parser stops on
    // `tag == 0xFF`. Protection tags therefore have to land BEFORE
    // that marker — strip it by rewinding `params_len` by 2 when the
    // trailing bytes are `0xFF 0x00`, append the protection tags,
    // then re-write the end marker at the new tail. Modules with no
    // schema source (`params_len == 0`) don't have an end marker to
    // strip; one is added here only if at least one protection tag
    // fires, so a module declaring no policy stays at `params_len == 0`.
    let mut extra_len = 0usize;
    let had_end_marker = params_len >= 2
        && entry
            .get(MODULE_ENTRY_HEADER_SIZE + params_len - 2)
            .copied()
            == Some(0xFF)
        && entry
            .get(MODULE_ENTRY_HEADER_SIZE + params_len - 1)
            .copied()
            == Some(0x00);
    let base = if had_end_marker {
        MODULE_ENTRY_HEADER_SIZE + params_len - 2
    } else {
        MODULE_ENTRY_HEADER_SIZE + params_len
    };

    // The on-device renderers (presentation_resolver, content_controls) process
    // a fixed `MAX_SHELL_CONTROLS` controls; a shell with more would silently
    // drop the overflow. Reject it at build time so config, resolver, and
    // content_controls agree on capacity.
    if type_name == "presentation_resolver" || type_name == "content_controls" {
        let n = crate::presentation_resolver::shell_control_count(config);
        let max = crate::presentation_resolver::MAX_SHELL_CONTROLS;
        if n > max {
            return Err(Error::Config(format!(
                "module '{name}': presentation.shell declares {n} controls, exceeding the \
                 on-device limit of {max} ({type_name} would silently drop the rest) — \
                 reduce the control count",
            )));
        }
    }

    // The resolver stores its capacity policy in u16/u8 fields, so a value that
    // overflows would WRAP on silicon (content_capacity: 65536 → 0, hiding every
    // control). Reject out-of-range values rather than silently truncating.
    if type_name == "presentation_resolver" {
        for (k, max) in [
            ("physical_buttons", u8::MAX as u64),
            ("content_capacity", u16::MAX as u64),
            ("chrome_capacity", u16::MAX as u64),
        ] {
            if let Some(v) = module.get(k).and_then(|v| v.as_u64()) {
                if v > max {
                    return Err(Error::Config(format!(
                        "module '{name}': {k} = {v} exceeds the on-device maximum {max} \
                         (it would wrap to a smaller value on silicon)",
                    )));
                }
            }
        }
    }

    // The on-device `presentation_resolver` can't parse `presentation.shell`,
    // so inject the serialized control-intent table as its `intents` blob (TLV
    // tag 1) directly from the config — the same intents the host lint resolves.
    // One TLV entry (≤255 bytes); a larger shell would need chunking (not v1).
    if type_name == "presentation_resolver" {
        let intents = crate::presentation_resolver::intents_from_shell(config);
        if !intents.is_empty() {
            if intents.len() > 255 {
                return Err(Error::Config(format!(
                    "module '{name}': presentation.shell serializes to {} intent bytes, \
                     exceeding the 255-byte single-TLV limit — reduce controls",
                    intents.len()
                )));
            }
            if base + extra_len + 2 + intents.len() < entry.len() {
                entry[base + extra_len] = 1; // tag 1 = intents
                entry[base + extra_len + 1] = intents.len() as u8;
                entry[base + extra_len + 2..base + extra_len + 2 + intents.len()]
                    .copy_from_slice(&intents);
                extra_len += 2 + intents.len();
            }
        }
    }

    // `content_controls` renders the shell's content-plane controls: inject the
    // control-descriptor table (icon + verb-hash per control, declaration order)
    // as its `controls` blob (TLV tag 4) so its controls line up 1:1 with the
    // resolver's `intents`/layout. Absent a shell, the module keeps its built-in
    // prev/play/next transport.
    if type_name == "content_controls" {
        // content_controls only actuates tappable transport controls; reject a
        // shell control it would render as a dead/wrong button (H2).
        if let Some((id, why)) = crate::presentation_resolver::content_controls_unrenderable(config)
        {
            return Err(Error::Config(format!(
                "module '{name}': control `{id}` {why} — content_controls renders only \
                 button/toggle transport controls; move it to a chrome/browser surface or a \
                 richer content renderer",
            )));
        }
        let descriptors = crate::presentation_resolver::content_descriptors_from_shell(config);
        if !descriptors.is_empty() {
            if descriptors.len() > 255 {
                return Err(Error::Config(format!(
                    "module '{name}': presentation.shell serializes to {} descriptor bytes, \
                     exceeding the 255-byte single-TLV limit — reduce controls",
                    descriptors.len()
                )));
            }
            if base + extra_len + 2 + descriptors.len() < entry.len() {
                entry[base + extra_len] = 4; // tag 4 = controls
                entry[base + extra_len + 1] = descriptors.len() as u8;
                entry[base + extra_len + 2..base + extra_len + 2 + descriptors.len()]
                    .copy_from_slice(&descriptors);
                extra_len += 2 + descriptors.len();
            }
        }
    }

    // Every numeric protection field below is range-checked. Typos
    // and overflows produce explicit `Error::Config` at build time
    // rather than silent `as u32` / `as u16` truncation; the
    // non-numeric case (string typos like `"forever"`) also rejects
    // explicitly so a malformed YAML value can't disable the field.

    // Tag 0xF0: step_deadline_us (u32, 4 bytes)
    if let Some(v) = module.get("step_deadline_us") {
        if !v.is_null() {
            let deadline = match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => n as u32,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_us = {n} exceeds u32::MAX"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 6 < entry.len() {
                entry[base + extra_len] = 0xF0;
                entry[base + extra_len + 1] = 4;
                let bytes = deadline.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&bytes);
                extra_len += 6;
            }
        }
    }

    // Tag 0xF1: fault_policy (u8: 0=skip, 1=restart, 2=restart_graph).
    // Unknown policy strings error explicitly; the accepted set
    // mirrors the kernel-side `FaultPolicy` enum.
    if let Some(v) = module.get("fault_policy") {
        if !v.is_null() {
            let policy_str = v.as_str().ok_or_else(|| {
                Error::Config(format!(
                    "module '{name}': fault_policy must be a string \
                     (\"skip\" | \"restart\" | \"restart_graph\" | \"tolerate\"); got {v}"
                ))
            })?;
            let policy_val: u8 = match policy_str {
                "skip" => 0,
                "restart" => 1,
                "restart_graph" => 2,
                // Overruns recorded but never fatal — for storage
                // modules whose synchronous device ops have a
                // legitimate heavy tail. Step errors still fault.
                "tolerate" => 3,
                _ => {
                    return Err(Error::Config(format!(
                        "module '{name}': fault_policy = '{policy_str}' is invalid \
                         (use \"skip\", \"restart\", \"restart_graph\", or \"tolerate\")"
                    )));
                }
            };
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF1;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = policy_val;
                extra_len += 3;
            }
        }
    }

    // Tag 0xF2: max_restarts (u16, 2 bytes)
    if let Some(v) = module.get("max_restarts") {
        if !v.is_null() {
            let max_r = match v.as_u64() {
                Some(n) if n <= u16::MAX as u64 => n as u16,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': max_restarts = {n} exceeds u16::MAX (65535)"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': max_restarts must be a non-negative integer \
                         (got {v})"
                    )));
                }
            };
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xF2;
                entry[base + extra_len + 1] = 2;
                let bytes = max_r.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
                extra_len += 4;
            }
        }
    }

    // Tag 0xF3: restart_backoff_ms (u16, 2 bytes)
    if let Some(v) = module.get("restart_backoff_ms") {
        if !v.is_null() {
            let backoff = match v.as_u64() {
                Some(n) if n <= u16::MAX as u64 => n as u16,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': restart_backoff_ms = {n} exceeds u16::MAX (65535)"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': restart_backoff_ms must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xF3;
                entry[base + extra_len + 1] = 2;
                let bytes = backoff.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
                extra_len += 4;
            }
        }
    }

    // Tag 0xF4: trust_tier (u8: 0=platform, 1=verified, 2=community, 3=unsigned).
    // Per-module field wins; `default_trust_tier` at the top level or under
    // `graph:` applies to any module that omits it. Defaults to `platform`
    // (most permissive) for first-party builds.
    let tier_str = module
        .get("trust_tier")
        .and_then(|v| v.as_str())
        .or_else(|| {
            config
                .get("default_trust_tier")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    config
                        .get("graph")
                        .and_then(|g| g.get("default_trust_tier"))
                        .and_then(|v| v.as_str())
                })
        })
        .unwrap_or("platform");
    let tier_val: u8 = match tier_str {
        "platform" => 0,
        "verified" => 1,
        "community" => 2,
        "unsigned" => 3,
        _ => 0,
    };
    if base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xF4;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = tier_val;
        extra_len += 3;
    }

    // Tag 0xF5: protection level (u8: 0=none, 1=guarded, 2=isolated).
    // An explicit `protection:` on the module (or the graph) wins; otherwise
    // derive from the trust tier:
    //   platform  -> none
    //   verified  -> guarded
    //   community -> isolated
    //   unsigned  -> isolated (signature enforcement refuses the load elsewhere)
    let explicit_prot = module
        .get("protection")
        .and_then(|v| v.as_str())
        .or_else(|| {
            config
                .get("protection")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    config
                        .get("graph")
                        .and_then(|g| g.get("protection"))
                        .and_then(|v| v.as_str())
                })
        });
    let prot_val: u8 = match explicit_prot {
        Some("none") => 0,
        Some("guarded") => 1,
        Some("isolated") => 2,
        _ => match tier_val {
            0 => 0, // platform -> none
            1 => 1, // verified -> guarded
            _ => 2, // community/unsigned -> isolated
        },
    };
    if base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xF5;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = prot_val;
        extra_len += 3;
    }

    // Extended-protection tags — emit when the module YAML declares
    // them. The kernel-side parser at `parse_protection_config`
    // reads each tag and routes to the appropriate setter. All tags
    // are optional; omit when the field isn't declared so module
    // graphs that opt out see no change.

    // Tag 0xF6: step_deadline_burst_us (u32 LE, 4 bytes). Range-
    // check the YAML value as u32 explicitly and reject non-numeric
    // values. `validate_scheduler_budgets` also rejects out-of-range
    // values, but `build_module_entry` runs in paths that bypass the
    // validator (e.g. built-in packing tests); enforcing here too
    // keeps the wire tag from ever being silently wrapped.
    if let Some(v) = module.get("step_deadline_burst_us") {
        if !v.is_null() {
            let burst_us = match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => n as u32,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us = {n} exceeds u32::MAX"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': step_deadline_burst_us must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            let burst = burst_us.to_le_bytes();
            if base + extra_len + 6 < entry.len() {
                entry[base + extra_len] = 0xF6;
                entry[base + extra_len + 1] = 4;
                entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&burst);
                extra_len += 6;
            }
        }
    }

    // Tag 0xF7: quarantine_partner (u8 module index, 0xFF = none).
    // Accepts either the partner's index directly (`quarantine_partner:
    // 3`) or its name (`quarantine_partner: "tls_handshake"`). Name
    // resolution happens in the wiring pass once the module-name →
    // index map is built; what reaches `build_module_entry` is always
    // the numeric form.
    if let Some(v) = module.get("quarantine_partner_idx") {
        if !v.is_null() {
            // Reject non-numeric values explicitly: a string like
            // `quarantine_partner_idx: "3"` would otherwise return
            // `None` from `as_u64()` and silently omit the tag.
            let partner = match v.as_u64() {
                Some(n) => n,
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': quarantine_partner_idx must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if partner >= max_modules as u64 {
                return Err(Error::Config(format!(
                    "module '{name}': quarantine_partner_idx {partner} out of range \
                     (max {})",
                    max_modules - 1
                )));
            }
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF7;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = partner as u8;
                extra_len += 3;
            }
        }
    }

    // Tag 0xF8: heap.zero_on_free (u8 bool)
    if let Some(heap) = module.get("heap") {
        if let Some(v) = heap.get("zero_on_free").and_then(|v| v.as_bool()) {
            if base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF8;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = if v { 1 } else { 0 };
                extra_len += 3;
            }
        }

        // Tag 0xF9: heap.alloc_failure_policy
        //   "return_null" (default) → tag NOT emitted
        //   "fault" → tag emitted with value 1
        // The value space is validated by `validate_heap_subtree`; only
        // `"fault"` produces a tag here.
        if let Some(s) = heap.get("alloc_failure_policy").and_then(|v| v.as_str()) {
            if s == "fault" && base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xF9;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = 1;
                extra_len += 3;
            }
        }

        // Tag 0xFA: heap.canary_enabled
        if let Some(v) = heap.get("canary_enabled").and_then(|v| v.as_bool()) {
            if v && base + extra_len + 3 < entry.len() {
                entry[base + extra_len] = 0xFA;
                entry[base + extra_len + 1] = 1;
                entry[base + extra_len + 2] = 1;
                extra_len += 3;
            }
        }
    }

    // Tag 0xFB: isr_budget_cycles (u32 LE, 4 bytes). Per-module
    // Tier 1b/2 cycle budget override: the ISR budget guard trips a
    // module whose handler exceeds it. Default `0` falls back to the
    // kernel's `DEFAULT_ISR_BUDGET_CYCLES`.
    if let Some(v) = module.get("isr_budget_cycles") {
        if !v.is_null() {
            let cycles = match v.as_u64() {
                Some(n) if n <= u32::MAX as u64 => n as u32,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': isr_budget_cycles = {n} exceeds u32::MAX"
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': isr_budget_cycles must be a non-negative \
                         integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 6 < entry.len() {
                entry[base + extra_len] = 0xFB;
                entry[base + extra_len + 1] = 4;
                let bytes = cycles.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&bytes);
                extra_len += 6;
            }
        }
    }

    // Tag 0xFC: irq (u16 LE, 2 bytes). Per-module hardware IRQ
    // number for Tier 2 admission. Required for Tier 2 modules
    // (`validate_isr_tier_admission` enforces); the kernel passes
    // it to `register_tier2_module` at admission time.
    if let Some(v) = module.get("irq") {
        if !v.is_null() {
            let irq_num = match v.as_u64() {
                Some(n) if n < u16::MAX as u64 => n as u16,
                Some(n) => {
                    return Err(Error::Config(format!(
                        "module '{name}': irq = {n} exceeds u16 range \
                         (max = {} — u16::MAX reserved as 'unset' sentinel)",
                        u16::MAX - 1
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "module '{name}': irq must be a non-negative integer (got {v})"
                    )));
                }
            };
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xFC;
                entry[base + extra_len + 1] = 2;
                let bytes = irq_num.to_le_bytes();
                entry[base + extra_len + 2..base + extra_len + 4].copy_from_slice(&bytes);
                extra_len += 4;
            }
        }
    }

    // Emit the schema-section end marker `0xFF 0x00` here, after the
    // protection tags (0xF0-0xFA) but BEFORE any extended cert/key
    // blobs. The schema SDK parser walks until it hits 0xFF and
    // ignores everything after; cert/key extended tags reuse low
    // tag numbers (10/11/12/13) that collide with real schema tags
    // — notably QUIC's `trace_sample_permille` at tag 11 and
    // `disable_migration` at tag 12 — so they must live AFTER this
    // marker. The TLS-module extended-TLV scanner independently walks
    // the full params region looking for the `[tag, 0x00, hi, lo,
    // payload]` extended pattern and picks them up there. Without this
    // split, a cert-bearing QUIC config would silently reset those
    // params to their defaults.
    if base + extra_len + 1 < entry.len() {
        entry[base + extra_len] = 0xFF;
        entry[base + extra_len + 1] = 0x00;
        extra_len += 2;
        // Also update the schema TLV header's payload_len (u16 LE at
        // bytes 2-3 of the schema TLV) so it reflects the new end-marker
        // position. Without this update, the TLS extended scanner
        // (which uses the header's payload_len to find `basic_end`)
        // would start mid-protection-tag and either false-match or skip
        // legitimate cert/key tags.
        //
        // payload_len is measured from byte 4 (past the TLV header) to
        // the byte AFTER the end marker. With the schema's original
        // end marker overwritten, the new end-marker position relative
        // to byte 4 is `base + extra_len - (MODULE_ENTRY_HEADER_SIZE + 4)`.
        let header_pos = MODULE_ENTRY_HEADER_SIZE;
        if entry.len() >= header_pos + 4 && entry[header_pos] == 0xFE {
            let new_payload_len = (base + extra_len) - (header_pos + 4);
            if new_payload_len <= u16::MAX as usize {
                let bytes = (new_payload_len as u16).to_le_bytes();
                entry[header_pos + 2] = bytes[0];
                entry[header_pos + 3] = bytes[1];
            }
        }
    }

    // Tag 10: cert_file (DER blob, extended TLV for > 255 bytes)
    if let Some(cert_path) = module.get("cert_file").and_then(|v| v.as_str()) {
        match std::fs::read(cert_path) {
            Ok(cert_data) => {
                let n = cert_data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 10; // tag
                    entry[base + extra_len + 1] = 0x00; // extended length marker
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n]
                        .copy_from_slice(&cert_data);
                    extra_len += 4 + n;
                    eprintln!("  cert_file: {cert_path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: cert_file: could not read '{cert_path}': {e}"),
        }
    }

    // Tag 11: key_file (DER blob, extended TLV for > 255 bytes)
    if let Some(key_path) = module.get("key_file").and_then(|v| v.as_str()) {
        match std::fs::read(key_path) {
            Ok(key_data) => {
                let n = key_data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 11; // tag
                    entry[base + extra_len + 1] = 0x00; // extended length marker
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n]
                        .copy_from_slice(&key_data);
                    extra_len += 4 + n;
                    eprintln!("  key_file: {key_path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: key_file: could not read '{key_path}': {e}"),
        }
    }

    // Tag 12: trust_cert_file (DER blob, extended TLV).
    if let Some(path) = module.get("trust_cert_file").and_then(|v| v.as_str()) {
        match std::fs::read(path) {
            Ok(data) => {
                let n = data.len();
                if n > 0 && base + extra_len + 4 + n < entry.len() {
                    entry[base + extra_len] = 12;
                    entry[base + extra_len + 1] = 0x00;
                    entry[base + extra_len + 2] = (n >> 8) as u8;
                    entry[base + extra_len + 3] = n as u8;
                    entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(&data);
                    extra_len += 4 + n;
                    eprintln!("  trust_cert_file: {path} ({n} bytes)");
                }
            }
            Err(e) => eprintln!("  warn: trust_cert_file: could not read '{path}': {e}"),
        }
    }

    // Tag 13: verify_hostname (ASCII string, extended TLV).
    if let Some(name) = module.get("verify_hostname").and_then(|v| v.as_str()) {
        let bytes = name.as_bytes();
        let n = bytes.len();
        if n > 0 && n < 256 && base + extra_len + 4 + n < entry.len() {
            entry[base + extra_len] = 13;
            entry[base + extra_len + 1] = 0x00;
            entry[base + extra_len + 2] = (n >> 8) as u8;
            entry[base + extra_len + 3] = n as u8;
            entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(bytes);
            extra_len += 4 + n;
            eprintln!("  verify_hostname: {name}");
        }
    }

    // Tag 15: verify_uri (ASCII URI, extended TLV). The name a peer leaf's
    // URI SAN must equal under the tls module's `ca_uri` peer-auth profile
    // — the SPIFFE case. Separate from `verify_hostname` because a URI is
    // matched byte-for-byte where a hostname has wildcard and label rules;
    // one key feeding both would apply whichever rule the code reached
    // first.
    if let Some(uri) = module.get("verify_uri").and_then(|v| v.as_str()) {
        let bytes = uri.as_bytes();
        let n = bytes.len();
        // The module drops an over-long value rather than truncate it — a
        // prefix of a SPIFFE ID is another valid SPIFFE ID — so refuse
        // here instead, where the operator can still see why.
        const VERIFY_URI_MAX: usize = 256;
        if n > VERIFY_URI_MAX {
            return Err(Error::Config(format!(
                "verify_uri is {n} bytes, over the {VERIFY_URI_MAX}-byte limit: \
                 truncating it would authenticate a different identity"
            )));
        }
        if n > 0 && base + extra_len + 4 + n < entry.len() {
            entry[base + extra_len] = 15;
            entry[base + extra_len + 1] = 0x00;
            entry[base + extra_len + 2] = (n >> 8) as u8;
            entry[base + extra_len + 3] = n as u8;
            entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(bytes);
            extra_len += 4 + n;
            eprintln!("  verify_uri: {uri}");
        }
    }

    // Tag 14: alpn (RFC 7301 ALPN list, comma-separated ASCII tokens
    // like "mqtt,h3", extended TLV). Consumed by modules that negotiate
    // ALPN (e.g. quic) to pick the offered protocol; selection is
    // server-preference, first-configured-token-the-client-offered.
    if let Some(alpn) = module.get("alpn").and_then(|v| v.as_str()) {
        let bytes = alpn.as_bytes();
        let n = bytes.len();
        // The module stores the ALPN list in a fixed buffer and each
        // selected token in a fixed per-token slot. Truncating a token
        // would negotiate a protocol the peer never offered, so reject an
        // over-capacity list at config time rather than silently clip it.
        // (Mirrors the quic module: MAX_ALPN_CFG = 64, MAX_ALPN = 24.)
        const ALPN_LIST_MAX: usize = 64;
        const ALPN_TOKEN_MAX: usize = 24;
        if n > ALPN_LIST_MAX {
            return Err(Error::Config(format!(
                "module '{name}': alpn list is {n} bytes, exceeds the {ALPN_LIST_MAX}-byte limit"
            )));
        }
        if let Some(tok) = alpn.split(',').find(|t| t.len() > ALPN_TOKEN_MAX) {
            return Err(Error::Config(format!(
                "module '{name}': alpn token '{tok}' exceeds the {ALPN_TOKEN_MAX}-byte limit"
            )));
        }
        if n > 0 {
            // The TLV body spans `[base + extra_len .. base + extra_len + 4 + n)`,
            // so the highest index written is `base + extra_len + 4 + n - 1`;
            // the write fits iff `base + extra_len + 4 + n <= entry.len()`
            // (note `<=`, so an exact fill is valid). An explicit `alpn` is a
            // hard requirement — silently omitting it here would fall the
            // module back to non-ALPN QUIC, which the operator did not ask
            // for — so a buffer that can't hold it is a config error, not a
            // silent drop.
            let end = base + extra_len + 4 + n;
            if end <= entry.len() {
                entry[base + extra_len] = 14;
                entry[base + extra_len + 1] = 0x00;
                entry[base + extra_len + 2] = (n >> 8) as u8;
                entry[base + extra_len + 3] = n as u8;
                entry[base + extra_len + 4..end].copy_from_slice(bytes);
                extra_len += 4 + n;
                eprintln!("  alpn: {alpn}");
            } else {
                return Err(Error::Config(format!(
                    "module '{name}': alpn list ({n} bytes) does not fit the module \
                     params buffer (needs {} more bytes); enlarge the params buffer \
                     or shorten the alpn list",
                    end - entry.len()
                )));
            }
        }
    }

    // Calculate total entry length and write to header. The
    // extended cert/key bytes were written past the end marker and
    // are accounted for in `extra_len`. The 2-byte original schema
    // end marker, if any, was overwritten and re-emitted by the
    // inserted-end-marker block above:
    //   * had_end_marker == true:  base = orig_params_len - 2; the
    //     original `0xFF 0x00` was overwritten and re-emitted
    //     (counted in `extra_len`). Total = MODULE_ENTRY_HEADER_SIZE
    //     + (params_len - 2) + extra_len.
    //   * had_end_marker == false: base = orig_params_len; the end
    //     marker was appended (counted in extra_len). Total =
    //     MODULE_ENTRY_HEADER_SIZE + params_len + extra_len.
    let payload_total = if had_end_marker {
        params_len.saturating_sub(2) + extra_len
    } else {
        params_len + extra_len
    };
    let entry_len = MODULE_ENTRY_HEADER_SIZE + payload_total;
    entry[0..4].copy_from_slice(&(entry_len as u32).to_le_bytes());

    // Truncate to actual size
    entry.truncate(entry_len);

    Ok(entry)
}


fn parse_modules_map(
    modules: &Value,
    data_section: Option<&Value>,
    config: &Value,
    modules_dir: &Path,
    manifests: &HashMap<String, Manifest>,
    max_modules: usize,
) -> Result<(Vec<Vec<u8>>, Vec<String>)> {
    let mut entries = Vec::new();
    let mut names = Vec::new();

    let list = modules.as_array().ok_or_else(|| {
        Error::Config("modules must be a list of module configs (each with a 'name' field)".into())
    })?;

    // Pre-pass: collect module names so a `quarantine_partner:
    // "name"` (string form) resolves to an index regardless of
    // declaration order. Forward and backward partner references both
    // resolve here. Modules using `quarantine_partner_idx: N`
    // (numeric form) bypass this entirely.
    let mut name_to_idx: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    for (idx, m) in list.iter().enumerate() {
        if idx >= max_modules {
            break;
        }
        if let Some(n) = m.get("name").and_then(|v| v.as_str()) {
            name_to_idx.entry(n.to_string()).or_insert(idx as u8);
        }
    }

    for (idx, module) in list.iter().enumerate() {
        if idx >= max_modules {
            return Err(Error::Config(format!(
                "Too many modules: {} > {} (the target profile's kernel MAX_MODULES)",
                idx + 1,
                max_modules
            )));
        }
        let name = module["name"]
            .as_str()
            .ok_or_else(|| Error::Config(format!("Module at index {idx} missing 'name' field")))?;
        // Duplicate-name detector. Names are used as keys in
        // manifests / wiring lookup / scheduler module table, so
        // two modules sharing a name silently makes every name
        // reference ambiguous (the later one wins in some places,
        // the earlier in others — neither is right). Catch at
        // parse time and name the conflicting index pair so the
        // user can find both occurrences in the YAML.
        if let Some(prev_idx) = names.iter().position(|n| n == name) {
            return Err(Error::Config(format!(
                "Duplicate module name '{name}' at index {idx}; first declared at index \
                 {prev_idx}. Every module needs a unique `name:` — rename one (the wiring \
                 still uses the rename, the manifest's `type:` stays the same)."
            )));
        }

        // Resolve `quarantine_partner` (string or numeric form) →
        // `quarantine_partner_idx: N` so `build_module_entry` reads
        // only the numeric form. Both spellings route to the same
        // `_idx` field. The module Value is cloned to avoid mutating
        // the borrowed input; the clone is cheap relative to the
        // rest of the build.
        let mut module_owned = module.clone();
        let partner_val = module.get("quarantine_partner");
        let resolved_idx: Option<u8> = match partner_val {
            Some(v) if v.is_string() => {
                let partner_name = v.as_str().unwrap();
                let idx = name_to_idx.get(partner_name).copied().ok_or_else(|| {
                    Error::Config(format!(
                        "module '{name}': quarantine_partner '{partner_name}' is not a declared module"
                    ))
                })?;
                Some(idx)
            }
            Some(v) if v.is_u64() => {
                let n = v.as_u64().unwrap();
                if n >= max_modules as u64 {
                    return Err(Error::Config(format!(
                        "module '{name}': quarantine_partner index {n} out of range (max {})",
                        max_modules - 1
                    )));
                }
                Some(n as u8)
            }
            Some(_) => {
                return Err(Error::Config(format!(
                    "module '{name}': quarantine_partner must be a module name (string) \
                     or index (number)"
                )));
            }
            None => None,
        };
        if let Some(idx) = resolved_idx {
            if let Some(obj) = module_owned.as_object_mut() {
                obj.insert(
                    "quarantine_partner_idx".to_string(),
                    serde_json::Value::Number((idx as u64).into()),
                );
            }
        }

        let id = idx as u8;
        let entry = build_module_entry(
            name,
            &module_owned,
            id,
            data_section,
            config,
            modules_dir,
            manifests,
            max_modules,
        )?;
        entries.push(entry);
        names.push(name.to_string());
    }

    Ok((entries, names))
}

