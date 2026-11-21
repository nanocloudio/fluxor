// =============================================================================
// Graph Config
// =============================================================================

/// One module of the graph as the composer builds it: the fields of the
/// codec's `ModuleRecord` with the params owned. [`ModuleEntry::record`]
/// lends it to the encoder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ModuleEntry {
    /// FNV-1a of the module's type name, the `.fmod` it loads.
    pub name_hash: u32,
    /// The module's index in the graph: its position in `modules:`.
    pub id: u16,
    /// The execution domain it runs in.
    pub domain: u8,
    /// It runs in its domain's pre-pass (`pre_pass` in its manifest).
    pub pre_pass: bool,
    /// Its step deadline, burst deadline and fault policy.
    pub budget: crate::add_subgraph::StepBudget,
    /// Its params TLV.
    pub params: Vec<u8>,
}

/// What a module entry's params buffer starts at before it grows to fit:
/// most modules' params are a few hundred bytes, and a module's params are
/// bounded only by what its YAML says (the kernel borrows them from the config
/// blob in place). A buffer the entry might not have fit is doubled and the
/// entry rebuilt (`build_module_entry`).
const PARAMS_BUFFER_START: usize = 64 * 1024;
/// Free room an entry must leave in its buffer to prove nothing was dropped:
/// the packer and the reserved-tag emitters skip a TLV that does not fit
/// rather than fail, and none of those TLVs is larger than this.
const PARAMS_BUFFER_HEADROOM: usize = 64 * 1024;

/// A starting params buffer for `module`: room for its YAML several times
/// over (a hex or byte-array blob packs smaller than it is written), so an
/// entry rarely needs a second pass.
fn params_buffer_for(module: &Value, data_section: Option<&Value>) -> usize {
    let text = |v: &Value| serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0);
    PARAMS_BUFFER_START + 2 * text(module) + data_section.map_or(0, text)
}

/// Pack `module`'s schema params into a buffer that grows to fit them.
pub(crate) fn pack_params_growing(
    module: &Value,
    param_schema: &schema::ParamSchema,
    data_section: Option<&Value>,
    module_name: &str,
) -> Result<Vec<u8>> {
    let mut cap = params_buffer_for(module, data_section);
    loop {
        let mut buf = vec![0u8; cap];
        match schema::build_params_from_schema(
            module,
            param_schema,
            &mut buf,
            0,
            data_section,
            module_name,
        ) {
            Ok(plen) if cap - plen >= PARAMS_BUFFER_HEADROOM => {
                buf.truncate(plen);
                return Ok(buf);
            }
            Ok(_) => {}
            Err(e) if e.contains("does not fit") => {}
            Err(e) => return Err(Error::Config(e)),
        }
        cap = cap.checked_mul(2).ok_or_else(|| {
            Error::Config(format!("module '{module_name}': params too large to pack"))
        })?;
    }
}

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
/// pin this if it ever needs to change. The kernel's QEMU virt build uses
/// ten times this (emulation is that much slower); the hardware figure is
/// the conservative one for the burst-only validation below, so it stands.
const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// Maximum number of scheduling domains the kernel supports.
/// Mirrors the scheduler's `MAX_DOMAINS` constant
/// (`src/kernel/exec/scheduler/mod.rs`): the config carries one domain
/// record per declared domain, and the kernel refuses a config declaring
/// more than it has.
const MAX_DOMAINS: usize = 4;

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
/// the platform domain-loop fallback (`tick_period_us = 1000` when
/// `cfg_header_tick_us == 0`).
const DEFAULT_TICK_US: u32 = 1000;

/// Hard absolute cap on a single module's burst deadline. The burst
/// path uses `step_deadline_us * BURST_MULTIPLIER` as its extended
/// timeout; capping the product at 100 ms keeps `tick` loops
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
///   * **Guaranteed-class WCET**: a `guaranteed`-class module is blocked on (b)
///     unless the domain asserts `guaranteed_wcet_revalidated: true` (the
///     operator re-ran WCET/budget schedulability at `tick_min_us`).
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
fn module_param_u64(m: &Value, key: &str) -> Option<u64> {
    m.get(key).and_then(|v| v.as_u64()).or_else(|| {
        m.get("params")
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_u64())
    })
}

/// Whether `target`'s kernel runs each execution domain on a core of its own
/// (domain `d` on core `d`): the SMP kernels, bcm2712 and uefi. Every other
/// target (rp, Linux, wasm) and an unresolved one runs all domains' loops on
/// one thread.
fn domains_have_own_cores(target: Option<&str>) -> bool {
    let Some(name) = target else {
        return false;
    };
    crate::target::load_target(&name.to_ascii_lowercase(), &crate::project::root())
        .is_ok_and(|desc| matches!(desc.id.as_str(), "bcm2712" | "uefi"))
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
    // Per-domain core bitmask (shared-core detection). On a target whose
    // kernel runs domain `d` on core `d` every domain has its own core; on
    // the others (rp, Linux, wasm) every domain's loop runs on one thread.
    // Two domains whose bitmasks overlap share a core.
    let own_cores = domains_have_own_cores(
        resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str())),
    );
    let mut core_mask = [0u64; MAX_DOMAINS];
    // Per-domain "hosts a timing-strict module" (Guaranteed WCET, replicated
    // clock, or raft liveness) — the co-residency check rejects an
    // adaptive domain sharing a domain loop with one of these.
    let mut has_strict = [false; MAX_DOMAINS];
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
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
            core_mask[i] = if own_cores { 1u64 << i } else { 1 };
            // Adaptive cadence reduces a tick domain's idle work; a poll
            // domain steps back to back and never relaxes. Declaring both is
            // contradictory intent.
            if flags[i] != 0 && dom.get("exec").and_then(Value::as_str) == Some("poll") {
                eprintln!(
                    "warning: domain '{}' sets adaptive_flags={:#x} but is `exec: poll`. \
                     Adaptive cadence reduces a tick domain's idle work; a poll domain \
                     saturates its core continuously. Use `exec: poll` for full-CPU \
                     workloads and drop adaptive_flags, or use an adaptive `exec: tick` \
                     domain.",
                    dom.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    flags[i]
                );
            }
        }
    }
    // Pacers need no admission gate. The node graph has one per execution
    // domain, and `execution.domains` past `MAX_DOMAINS` is refused before
    // this runs. Resident graphs have one per owner slot and execution
    // domain, sized at boot with the owner table, so every workload the owner
    // pool seats is paced; the owner pool's own bound is the boot plan's
    // (`capacity::check_boot_plan`).

    // Unconfigured ⇒ nothing more to check (byte-identical path).
    if flags.iter().all(|&f| f == 0) {
        return Ok(());
    }

    let silicon = resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str()));

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

    // BCM2712 wake-policy declaration (required statement). On bcm2712 (pi5),
    // demand-driven idle (mechanism (a), bit 0) is NOT fully event-driven —
    // `tick` idle uses WFI, which software SEV does not break — so every
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
                // `tick_count()`-as-milliseconds needs no gate of its own:
                // every HAL's `tick_count` op is wall-clock-backed, and timer FDs derive deadlines from `hal::now_millis`
                // (`fd.rs`). A module that *itself* counts scheduler ticks as time
                // declares `tick_counted` and is already rejected above by the
                // attestation gate, on every platform. So no residual graph shape
                // is left for the validator to reject here.
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

    // Shared-domain-loop co-residency gate (reject-by-default). Populate `has_strict`
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
    // An adaptive domain sharing a core (overlapping core mask) with a
    // timing-strict domain is rejected: a variable-cadence sibling can delay
    // the strict domain's deadline/emission/wake, and proving the bound under
    // worst-case adaptive load is intractable, so the gate rejects by default.
    // The fix is placement — a domain on its own core, or an interrupt mode
    // — not a schedulability proof.
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
                    "adaptive domain '{}' shares a core with timing-strict domain '{}' \
                     (a guaranteed-WCET, replicated-clock, or raft-liveness module). A \
                     variable-cadence sibling can delay the strict domain's \
                     deadline/emission/wake, and the bound cannot be proven under \
                     worst-case adaptive load. On this target every domain shares one \
                     core; move the strict module to an interrupt mode or to a target \
                     that runs each domain on its own core, or remove adaptive_flags \
                     from '{}'.",
                    label(a),
                    label(b),
                    label(a),
                )));
            }
        }
    }

    Ok(())
}

/// Build-time admission gate for interrupt-mode (`timer`, `irq`) domains.
///
/// Rules enforced:
///
/// 1. **`interrupt_safe` attestation is mandatory.** Every module assigned
///    to an `exec: timer` or `exec: irq` domain must declare
///    `interrupt_safe = true` in its manifest. Modules without the flag are rejected at build time
///    with a message naming the module, the domain, and the manifest
///    path so the author knows exactly where to add the attestation.
///    Bridge routing has no fall-back: if the kernel admitted a
///    non-ISR-safe module into an ISR domain it would deadlock on
///    `provider_call` from interrupt context. For `irq` modules this
///    rule also requires a `module_isr_entry` export in the source —
///    the IRQ dispatches into it, not the cooperative `module_step`.
///
/// 2. **No edges touching interrupt-mode endpoints.** ANY YAML edge with at
///    least one `timer`/`irq` endpoint is rejected, regardless of
///    `edge_class`. The kernel-side bridge wiring
///    (`scheduler::wire_isr_bridges` + `pump_isr_bridges`) and the
///    module-facing surface (`bridge::SELF_BRIDGE` hands a module a
///    handle to each of its own bridges; the bridge `WRITE`/`READ`/`POLL`/`INFO`
///    ops are exempt from the ISR syscall deny-list, being lock-free
///    rings) both exist, but the end-to-end YAML-edge → bridge-fd
///    wiring is not silicon-validated, so the edge gate stays strict:
///    admitting a config that might silently mis-wire at runtime is
///    worse than rejecting it loudly. Tests exercise the kernel-side
///    bridge mechanism via `install_static_config` +
///    `set_domain_exec_mode`.
///
/// A module that lands in an interrupt-mode domain without a resolvable
/// manifest is a **hard error**. `validate_wiring_types` only
/// enforces content-type compatibility when both edge endpoints
/// have manifests, so a `timer` module with no wiring (or bare /
/// default ports) would otherwise slip through both this gate and
/// the wiring check unchecked. The diagnostic names the module +
/// the directory it should live under.
fn validate_interrupt_admission(
    config: &Value,
    module_list: &[Value],
    modules_dir: &std::path::Path,
    extra_module_dirs: &[&std::path::Path],
    resolved_target: Option<&str>,
    project_root: &std::path::Path,
) -> Result<()> {
    use boot_config::ExecMode;
    // Per-domain execution mode for the four supported domains.
    let mut domain_exec_mode = [ExecMode::Tick; 4];
    let mut domain_names_local: [Option<String>; 4] = [None, None, None, None];
    for (i, (label, exec)) in parse_domain_execs(config)?.into_iter().take(4).enumerate() {
        domain_exec_mode[i] = exec.mode;
        domain_names_local[i] = Some(label);
    }

    // `irq` admission: an `irq` module is dispatched from its
    // `module_isr_entry` export (resolved by the kernel loader into
    // `DynamicModule::isr_entry_fn()` and routed through
    // `irq::register_module`). Rules 1/3 below require every `irq`
    // module to declare `interrupt_safe = true`, an `irq:` field, and an
    // actual `module_isr_entry` export in its source.

    // Resolved for the graph's own target, as config generation resolves
    // them: a module pinned per silicon binds that target's pin.
    let manifests = load_module_manifests_with_extra_for_target(
        &Value::Array(module_list.to_vec()),
        extra_module_dirs,
        resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str())),
        project_root,
    );

    // ── Rule 0: `irq` line range (structural, target-specific) ──────────
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
    //     SPIs (32-1019) are all valid `irq` owners (the `irq_probe` example
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
                let exec_mode = domain_exec_mode
                    .get(domain as usize)
                    .copied()
                    .unwrap_or_default();
                if exec_mode != ExecMode::Irq {
                    continue;
                }
                if let Some(irq) = module.get("irq").and_then(|v| v.as_u64()) {
                    if irq > max_intid {
                        return Err(Error::Config(format!(
                            "module '{name}' declares `irq: {irq}`, but the {label} on \
                             this target only has interrupt lines 0..={max_intid}. Pick a valid \
                             IRQ number for the silicon (out-of-range values index the interrupt \
                             controller's registers out of bounds)."
                        )));
                    }
                }
            }
        }
    }

    // ── Rule 1: interrupt_safe attestation ────────────────────────────
    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let domain = resolve_domain_id(module, config)?;
        let exec_mode = domain_exec_mode
            .get(domain as usize)
            .copied()
            .unwrap_or_default();
        if !exec_mode.is_interrupt() {
            continue;
        }
        let domain_label = domain_names_local
            .get(domain as usize)
            .and_then(|n| n.clone())
            .unwrap_or_else(|| format!("domain {domain}"));

        // Interrupt-mode admission requires a manifest — we cannot
        // certify `interrupt_safe = true` (or run the NEON-import lint)
        // without one. Don't defer to `validate_wiring_types`: that
        // pass only enforces content-type compatibility when both
        // endpoints have manifests, so a `timer` module with no
        // edges or bare/default ports would slip through silently.
        let manifest = match manifests.get(name) {
            Some(m) => m,
            None => {
                let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') is assigned to domain \
                     '{domain_label}' (exec: {mode}) but no manifest was found. \
                     Interrupt-mode admission requires a manifest declaring `interrupt_safe = true`; \
                     add `manifest.toml` under the module's source tree (`modules/<area>/<type>/`) \
                     or list a containing directory in the config's top-level \
                     `module_search_paths:`. Run `fluxor inspect` to see the active search list.",
                    mode = exec_mode.name()
                )));
            }
        };
        if !manifest.interrupt_safe {
            let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') is assigned to domain '{domain_label}' \
                 (exec: {mode}) but its manifest does not declare `interrupt_safe = true`. \
                 Add `interrupt_safe = true` to the module's manifest.toml, or move the module \
                 to a cooperative domain.",
                mode = exec_mode.name()
            )));
        }
        // The lookup goes through `resolve_module_root` so the search order
        // is identical to the manifest loader's: an explicit YAML
        // `module_search_paths:` entry shadowing a bundled module wins for
        // both `interrupt_safe` and the export check, instead of one reader
        // trusting the bundled copy and the other trusting the override.
        let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
        if let Some(root) = resolve_module_root(module_type, extra_module_dirs) {
            // `irq` modules are dispatched from hardware-IRQ
            // context through their `module_isr_entry` export, NOT the
            // cooperative `module_step`. The authoritative gate is the
            // packer (ELF symtab → `.fmod` isr_module bit) + the loader
            // (`isr_entry_fn = None` → admission fail-closes at runtime).
            // This source-static check is the early, build-time mirror
            // so an `irq` module missing the entry point fails the graph
            // build instead of getting refused on the rig. (A `timer`
            // module's cooperative step is dispatched from the timer and
            // needs no ISR entry; `irq` construction goes through the
            // normal cooperative `module_new`, as `timer` does.)
            if exec_mode == ExecMode::Irq {
                if let Err(e) = crate::manifest::check_module_exports_isr_entry(&root) {
                    return Err(Error::Config(format!(
                        "module '{name}' (type '{module_type}') is assigned to domain \
                         '{domain_label}' (exec: {mode}) but {e}. An `irq` module must \
                         export `module_isr_entry` (an `extern \"C\" fn(*mut u8) -> i32`) \
                         — the hardware IRQ dispatches into it, not the cooperative \
                         `module_step`.",
                        mode = exec_mode.name()
                    )));
                }
            }
        } else if exec_mode == ExecMode::Irq {
            // No resolvable source root for an `irq` module means we
            // can't certify the ISR entry export exists. The manifest
            // check (Rule 1, above) already hard-errors an `irq` module
            // with no manifest, so reaching here implies a manifest with
            // no co-located `src/` tree — still unsafe to admit.
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') is assigned to an \
                 `exec: irq` domain but its source tree could not be resolved to \
                 verify the required `module_isr_entry` export. Place the module's \
                 `src/` tree alongside its manifest, or move it to a cooperative domain."
            )));
        }
    }

    // Build module name → exec_mode lookup (used by Rules 2 and 3).
    let mut module_exec_mode: std::collections::HashMap<String, ExecMode> =
        std::collections::HashMap::new();
    for module in module_list {
        if let Some(name) = module.get("name").and_then(|n| n.as_str()) {
            let domain = resolve_domain_id(module, config)?;
            let m = domain_exec_mode
                .get(domain as usize)
                .copied()
                .unwrap_or_default();
            module_exec_mode.insert(name.to_string(), m);
        }
    }

    // ── Rule 3 (runs BEFORE Rule 2 so wireless graphs still check):
    // `irq:` requirement + duplicate check for `irq` modules. (The target-specific IRQ
    // range is validated structurally in Rule 0, above, before manifests.)
    let mut seen_irq: Vec<(u16, String)> = Vec::new();
    for module in module_list {
        let name = match module.get("name").and_then(|n| n.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let m = module_exec_mode.get(name).copied().unwrap_or_default();
        if m != ExecMode::Irq {
            continue;
        }
        let irq = match module.get("irq").and_then(|v| v.as_u64()) {
            Some(n) if n < u16::MAX as u64 => n as u16,
            Some(_) | None => {
                return Err(Error::Config(format!(
                    "module '{name}' is in an `exec: irq` domain but does not \
                     declare an `irq:` field (or its value is out of u16 range). Add \
                     `irq: N` on the module, where N is the hardware IRQ number the \
                     module owns."
                )));
            }
        };
        if let Some((_, prev_name)) = seen_irq.iter().find(|(i, _)| *i == irq) {
            return Err(Error::Config(format!(
                "IRQ {irq} declared by both module '{prev_name}' and \
                 module '{name}'. Two modules sharing one hardware IRQ produce \
                 undefined dispatch ordering — the kernel's \
                 `irq_trampoline` is a single-handler-per-IRQ table. Give \
                 each `irq` module a distinct IRQ number."
            )));
        }
        seen_irq.push((irq, name.to_string()));
    }

    // ── Rule 2: edges touching interrupt-mode modules are rejected ────
    //
    // The kernel-side bridge wiring works — `wire_isr_bridges`
    // + `pump_isr_bridges` shuttle bytes
    // between cooperative PIPE channels and bridge rings — but PIC
    // modules have NO documented way to read their own bridge slot
    // indices from inside `module_step`, and the ISR syscall gate
    // denies `provider_call` (which the SDK's `bridge_dispatch`
    // helper rides on). So an ISR-endpoint edge would get a bridge
    // slot allocated, the kernel would drain bytes into the ring,
    // and the ISR module would have no supported way to read them.
    //
    // With no module-facing bridge ABI (see
    // `docs/architecture/scheduler.md` §"interrupt-mode I/O contract"), the
    // build rejects ANY YAML edge with an interrupt-mode endpoint. Tests that
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
            .map(ExecMode::is_interrupt)
            .unwrap_or(false);
        let to_isr = module_exec_mode
            .get(to_mod)
            .copied()
            .map(ExecMode::is_interrupt)
            .unwrap_or(false);
        if from_isr || to_isr {
            return Err(Error::Config(format!(
                "wiring[{i}] (from '{from_mod}' to '{to_mod}'): an edge touching an \
                 interrupt-mode endpoint cannot be wired — PIC modules have no \
                 module-facing API to read/write their bridge slots from inside \
                 `module_step`. The kernel-side bridge mechanism is wired and \
                 tested, but the SDK surface is not. Drop the edge from your YAML \
                 (`timer` modules do private-state work only), or move both \
                 endpoints to cooperative domains. See \
                 `docs/architecture/scheduler.md` §\"interrupt-mode I/O contract\"."
            )));
        }
        // Past this point both endpoints are cooperative. Any
        // explicit `edge_class` (DmaOwned/CrossCore/NicRing) on a
        // cooperative-only edge is the operator's choice and the
        // existing wiring path handles it.
    }

    // Diagnostic: warn if an interrupt-mode domain has no modules
    // assigned. A misnamed `domain:` field on a module is a common
    // typo (the hard-error `resolve_domain_id` already catches
    // it), but a correctly-named domain with no members is also a
    // bug. Check by **domain id**, not by mode: two domains in the
    // same mode would otherwise mask each other.
    let mut per_domain_member_count: [usize; 4] = [0; 4];
    for module in module_list {
        let d = resolve_domain_id(module, config)?;
        if (d as usize) < per_domain_member_count.len() {
            per_domain_member_count[d as usize] += 1;
        }
    }
    for d in 0..4 {
        if !domain_exec_mode[d].is_interrupt() {
            continue;
        }
        if per_domain_member_count[d] > 0 {
            continue;
        }
        let label = domain_names_local[d]
            .clone()
            .unwrap_or_else(|| format!("domains[{d}]"));
        eprintln!(
            "warning: execution.domains entry '{label}' is `exec: {mode}` but has no \
             modules assigned to it. Did you forget a `domain: {label}` on a module?",
            mode = domain_exec_mode[d].name()
        );
    }

    let _ = modules_dir; // reserved for future use (per-domain budget files)
    Ok(())
}

/// Reject placement of a `pre_pass` module into any domain that is not
/// `exec: tick`. Pre-pass modules run in cooperative context with the full
/// kernel API at the start of each pass; an interrupt-mode (`timer`, `irq`)
/// domain would run them from interrupt context (where `provider_call` and
/// heap use are undefined), and a `poll` domain has no pass start to run
/// them ahead of. A module declares `pre_pass = true` in its manifest; this
/// validator keeps that declaration and the domain's mode consistent.
fn validate_pre_pass_admission(
    config: &Value,
    module_list: &[Value],
    extra_module_dirs: &[&std::path::Path],
    resolved_target: Option<&str>,
    project_root: &std::path::Path,
) -> Result<()> {
    let domains = parse_domain_execs(config)?;

    // Resolved for the graph's own target, as config generation resolves
    // them: a module pinned per silicon binds that target's pin.
    let manifests = load_module_manifests_with_extra_for_target(
        &Value::Array(module_list.to_vec()),
        extra_module_dirs,
        resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str())),
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
        if !manifest.pre_pass {
            continue;
        }
        let domain = resolve_domain_id(module, config)?;
        let (domain_label, mode) = domains.get(domain as usize).map_or_else(
            || (format!("domain {domain}"), boot_config::ExecMode::Tick),
            |(label, exec)| (label.clone(), exec.mode),
        );
        if mode != boot_config::ExecMode::Tick {
            let module_type = module.get("type").and_then(|t| t.as_str()).unwrap_or(name);
            return Err(Error::Config(format!(
                "module '{name}' (type '{module_type}') declares `pre_pass = true` but is \
                 assigned to domain '{domain_label}' (exec: {}). The pre-pass runs \
                 cooperatively at the start of every scheduler pass, so a pre-pass module \
                 lives in an `exec: tick` domain. Move the module to a tick domain, or drop \
                 `pre_pass` from its manifest.",
                mode.name()
            )));
        }
    }

    Ok(())
}

/// A domain's execution mode and, for a `timer` domain, its period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainExec {
    pub mode: boot_config::ExecMode,
    /// A `timer` domain's period in µs (`1_000_000 / rate_hz`); 0 otherwise.
    pub timer_period_us: u16,
}

/// The execution mode an `execution.domains[]` entry declares with `exec:`
/// (`tick` when omitted). A `timer` domain declares its cadence as
/// `rate_hz`, a whole number of µs per period that fits the domain record's
/// u16 `tick_us`; no other mode takes `rate_hz`, and a `timer` domain takes
/// no `tick_us`. `tier:`, `exec_mode:` and `cores:` are not keys: a domain's
/// index is its core on a kernel that runs domains on their own cores, and
/// every domain shares one core elsewhere.
pub(crate) fn parse_domain_exec(domain: &Value, label: &str) -> Result<DomainExec> {
    use boot_config::ExecMode;
    if domain.get("cores").is_some() {
        return Err(Error::Config(format!(
            "execution.domains entry '{label}': unknown key `cores`; domain d runs on core d \
             where the kernel gives each domain its own core (bcm2712, uefi), and every \
             domain shares one core elsewhere"
        )));
    }
    for key in ["tier", "exec_mode"] {
        if domain.get(key).is_some() {
            return Err(Error::Config(format!(
                "execution.domains entry '{label}': unknown key `{key}`; a domain names its \
                 execution mode with `exec:` (tick | poll | timer | irq)"
            )));
        }
    }
    let mode = match domain.get("exec") {
        None => ExecMode::Tick,
        Some(v) => v.as_str().and_then(ExecMode::from_name).ok_or_else(|| {
            Error::Config(format!(
                "execution.domains entry '{label}': `exec: {v}` is not an execution mode \
                     (tick | poll | timer | irq)"
            ))
        })?,
    };
    let rate = domain.get("rate_hz");
    if mode != ExecMode::Timer {
        if rate.is_some() {
            return Err(Error::Config(format!(
                "execution.domains entry '{label}': `rate_hz` is the cadence of an \
                 `exec: timer` domain; this domain is `exec: {}`",
                mode.name()
            )));
        }
        return Ok(DomainExec {
            mode,
            timer_period_us: 0,
        });
    }
    if domain.get("tick_us").is_some() {
        return Err(Error::Config(format!(
            "execution.domains entry '{label}': an `exec: timer` domain's cadence is \
             `rate_hz`, not `tick_us`"
        )));
    }
    let rate_hz = match rate {
        None => {
            return Err(Error::Config(format!(
                "execution.domains entry '{label}': an `exec: timer` domain declares its \
                 cadence as `rate_hz`"
            )))
        }
        Some(v) => v.as_u64().filter(|&r| r > 0).ok_or_else(|| {
            Error::Config(format!(
                "execution.domains entry '{label}': `rate_hz: {v}` must be a positive integer"
            ))
        })?,
    };
    if 1_000_000 % rate_hz != 0 {
        return Err(Error::Config(format!(
            "execution.domains entry '{label}': `rate_hz: {rate_hz}` is not a whole number \
             of microseconds per period; pick a rate that divides 1000000"
        )));
    }
    let timer_period_us = u16::try_from(1_000_000 / rate_hz).map_err(|_| {
        Error::Config(format!(
            "execution.domains entry '{label}': `rate_hz: {rate_hz}` gives a period of {} µs, \
             longer than the domain record's {} µs",
            1_000_000 / rate_hz,
            u16::MAX
        ))
    })?;
    Ok(DomainExec {
        mode,
        timer_period_us,
    })
}

/// Every declared domain's [`DomainExec`], in domain-id order, labelled by
/// name (or `domains[i]`) for diagnostics.
pub(crate) fn parse_domain_execs(config: &Value) -> Result<Vec<(String, DomainExec)>> {
    let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    domains
        .iter()
        .enumerate()
        .map(|(i, dom)| {
            let label = dom
                .get("name")
                .and_then(Value::as_str)
                .map_or_else(|| format!("domains[{i}]"), str::to_string);
            let exec = parse_domain_exec(dom, &label)?;
            Ok((label, exec))
        })
        .collect()
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

/// Any YAML key on a built-in module entry that the schema does not know
/// is rejected: a PIC module ignores a key it does not know, so the
/// manifest is the contract and a typo would otherwise silently use the
/// default. Structural metadata (name, type, …) is skipped.
///
/// Top-level YAML keys that are structural metadata, not module params.
/// Mirrors `schema.rs::SKIP_KEYS` plus the step budget the module record
/// carries, the restart and protection fields that `build_module_entry`
/// writes as reserved TLV tags (0xF2..0xF5) and a few other cross-cutting
/// fields that the config generator injects.
const NON_PARAM_KEYS: &[&str] = &[
    "name",
    "type",
    // `[[variant]]` selection — consumed by fmod resolution
    // (`parse_modules_from_config_multi`) and the manifest loader,
    // never a wire param.
    "variant",
    // Program blobs the module instance owns: packed into the image's
    // program section (`modules::collect_programs`), never a wire param.
    "program",
    "programs",
    "wiring",
    "preset",
    "presets",
    "voices",
    "routes",
    "step_deadline_us",
    "fault_policy",
    "max_restarts",
    "restart_backoff_ms",
    "trust_class",
    "protection",
    "device_window",
    // `cert_file`, `key_file` and `trust` are NOT here: they are schema
    // parameters of tls and quic, validated like any other key, and their
    // build-time forms are lifted out before packing by
    // `lift_credential_sources`. Nor are `verify_hostname`, `verify_uri`
    // and `alpn`: schema strings too, checked and put in their packed
    // form by `normalize_peer_names`.
    "domain",
    "sample_rate", // injected by graph_sample_rate
    // The burst deadline rides the module record and the quarantine
    // partner a TLV tag of `build_module_entry`'s. These are top-level
    // module entries, not schema params, so the allow-list lets
    // `validate_yaml_params` pass them through.
    "step_deadline_burst_us",
    "quarantine_partner",     // name form, resolved at wiring pass
    "quarantine_partner_idx", // numeric form passed straight through
    // `heap`: nested object { zero_on_free, alloc_failure_policy, canary_enabled,
    // arena_bytes, raw_arena }
    "heap",
    // `demand`: { <pool>: n } — the instance's own declared demand, which
    // wins over its type's `[capacities]` figure (`instance_demand`).
    "demand",
    // Provenance recorded by stack expansion, not authored and not
    // emitted: which stack injected this module entry and which of its
    // params that stack set. Read only to explain a catalog/module skew
    // (see `stack_param_skew`) — a param a live stack asks for that a
    // pinned module does not have.
    "_from_stack",
    "_stack_params",
    // A member of an included stack (`fluxor_tools::stack::STACK_MEMBER_KEY`).
    "_stack_member",
];

/// A module entry's `variant:` names one of the type's `[[variant]]` builds,
/// so it is a string. Any other value selects no variant and is not a param
/// either (`variant` is never one), so it would vanish from the image without
/// a word; a module param of that name goes under `params:`.
fn validate_variant_key(module: &Value, module_name: &str) -> Result<()> {
    match module.get("variant") {
        None | Some(Value::String(_)) => Ok(()),
        Some(other) => Err(Error::Config(format!(
            "module '{module_name}': `variant: {other}` must name a `[[variant]]` build of the \
             module; a module param called `variant` goes under `params: {{ variant: {other} }}`"
        ))),
    }
}

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
             (with `zero_on_free` / `alloc_failure_policy` / `canary_enabled` / `arena_bytes` / \
             `raw_arena`)"
        ))
    })?;
    const HEAP_KEYS: &[&str] = &[
        "zero_on_free",
        "alloc_failure_policy",
        "canary_enabled",
        "arena_bytes",
        "raw_arena",
    ];
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
            "arena_bytes" => {
                heap_arena_bytes(subval).map_err(|why| {
                    Error::Config(format!("module '{module_name}': heap.arena_bytes {why}"))
                })?;
            }
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

/// Whether an instance uses its heap arena raw: its `heap.raw_arena`, else
/// its module type's `[capacities] raw_arena`.
fn declares_raw_arena(module: &Value, manifest: Option<&Manifest>) -> bool {
    module
        .get("heap")
        .and_then(|h| h.get("raw_arena"))
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            manifest.is_some_and(|m| m.capacities.get("raw_arena").is_some_and(|&v| v != 0))
        })
}

/// What the composer knows of a graph's plan when it sizes heap caps: the
/// full planned ceiling (derived + declared + reserve) of each pool a
/// `[capacities] heap_per_demand` rule names.
///
/// The ceilings follow from the graph's declared demand, which is counted
/// from every instance's packed params, so the graph is packed once under a
/// `counting` plan: an instance of a `heap_per_demand` type then carries a
/// placeholder cap tag — its type's figure without the per-demand bytes —
/// and prints nothing, and [`patch_heap_cap`] writes the planned figure
/// over it once the demand is counted. Nothing is packed twice.
#[derive(Debug, Default, Clone)]
pub(crate) struct HeapPlan {
    pub(crate) ceilings: std::collections::BTreeMap<String, u64>,
    pub(crate) counting: bool,
}

impl HeapPlan {
    /// The plan while the graph is packed and its demand counted.
    pub(crate) fn counting() -> Self {
        Self {
            ceilings: std::collections::BTreeMap::new(),
            counting: true,
        }
    }

    /// `(extra bytes, pool, ceiling)` a `heap_per_demand` rule adds to an
    /// instance of `manifest`'s type under this plan; `None` without a rule
    /// or without a ceiling for its pool.
    pub(crate) fn per_demand(&self, manifest: Option<&Manifest>) -> Option<(u64, String, u64)> {
        let rule = manifest?.heap_per_demand.as_ref()?;
        let ceiling = *self.ceilings.get(&rule.pool)?;
        Some((rule.extra_for(ceiling), rule.pool.clone(), ceiling))
    }
}

/// This instance's heap cap (params tag 0xEF), or `None` to leave the module
/// type's own. The graph's `heap.arena_bytes` wins; failing that, the cap is
/// derived from the type's rules:
///
/// - `[capacities] heap_from_params` derives it from the bytes the params TLV
///   `tlv` declares under the rule's tags — a declared input, so a large
///   inline value needs no hand-written cap;
/// - `[capacities] heap_per_demand` adds `bytes_each` × the planned ceiling
///   of its pool (`plan`) to that figure — or to the rule's own `base`, for a
///   type with no heap rule. The two are summed.
///
/// An explicit cap below what the params need is kept, and warned: the module
/// will refuse its params. One below a figure that includes per-demand bytes
/// is refused, naming both: the pool is planned to a ceiling the instance
/// could not serve. Under a `counting` plan a `heap_per_demand` type always
/// answers a cap — the placeholder [`patch_heap_cap`] replaces — and is
/// silent.
fn instance_heap_cap(
    name: &str,
    module: &Value,
    manifest: Option<&Manifest>,
    tlv: &[u8],
    plan: &HeapPlan,
) -> Result<Option<u32>> {
    let explicit = module
        .get("heap")
        .and_then(|h| h.get("arena_bytes"))
        .and_then(|v| heap_arena_bytes(v).ok());
    let rule = manifest.and_then(|m| m.heap_from_params.as_ref());
    let bytes = rule.map_or(0, |r| r.declared_bytes(tlv));
    // The type's figure before any per-demand bytes: the heap rule's (its
    // `base` while the params fit `included`), else `heap_per_demand.base`.
    let type_figure = || {
        rule.map(|r| r.derived_cap(bytes).unwrap_or(u64::from(r.base)))
            .or_else(|| {
                let m = manifest?;
                m.heap_per_demand
                    .as_ref()
                    .and_then(|r| r.base)
                    .or_else(|| m.heap_per_param.as_ref().and_then(|r| r.base))
                    .map(u64::from)
            })
    };
    let to_cap = |cap: u64| {
        u32::try_from(cap).map_err(|_| {
            Error::Config(format!(
                "module '{name}': its derived heap cap of {cap} B is past a heap's u32 size"
            ))
        })
    };
    if plan.counting && manifest.is_some_and(|m| m.heap_per_demand.is_some()) {
        return match explicit {
            Some(n) => Ok(Some(n)),
            None => type_figure().map(to_cap).transpose(),
        };
    }
    // The bytes a per-unit rule adds, and what they are for: a pool's planned
    // ceiling (`heap_per_demand`), or the instance's own count param
    // (`heap_per_param`). A type states at most one.
    let per_unit: Option<(u64, String, &str)> = plan
        .per_demand(manifest)
        .map(|(extra, pool, ceiling)| {
            (
                extra,
                format!("`{pool}` planned to {ceiling}"),
                "heap_per_demand",
            )
        })
        .or_else(|| {
            let r = manifest?.heap_per_param.as_ref()?;
            let (extra, terms) = r.extra_for(tlv);
            let what = terms
                .iter()
                .map(|(tag, count, each)| format!("{count} × {each} B of params tag {tag}"))
                .collect::<Vec<_>>()
                .join(" + ");
            Some((extra, what, "heap_per_param"))
        })
        .filter(|&(extra, ..)| extra > 0);
    if rule.is_none() && per_unit.is_none() {
        return Ok(explicit);
    }
    // The figure the rules derive, `None` while the type's own cap holds it.
    let derived = match &per_unit {
        None => rule.and_then(|r| r.derived_cap(bytes)),
        Some((extra, ..)) => type_figure().map(|f| f + extra),
    };
    if let Some(n) = explicit {
        if let (Some((extra, what, key)), Some(need)) = (&per_unit, derived) {
            if u64::from(n) < need {
                return Err(Error::Config(format!(
                    "module '{name}': heap.arena_bytes = {n} is below the {need} B its type \
                     derives — {extra} B of it for {what} (`[capacities] {key}`). The \
                     instance could not hold what it is declared for. Raise it to at least \
                     {need}, or drop it to let the composer size it."
                )));
            }
        } else if let Some(r) = rule {
            let need = r.need_for(bytes);
            if bytes > 0 && u64::from(n) < need {
                eprintln!(
                    "warning: module '{name}': heap.arena_bytes = {n} is below the {need} B its \
                     {bytes} B of declared params need (`[capacities] heap_from_params`); the \
                     module will refuse them. Raise it, or drop it to let the composer size it."
                );
            }
        }
        return Ok(Some(n));
    }
    let Some(cap) = derived else {
        return Ok(None);
    };
    let cap = to_cap(cap)?;
    match &per_unit {
        Some((extra, what, _)) => {
            eprintln!("  heap: '{name}' cap {cap} B, {extra} B of it for {what}")
        }
        None => eprintln!("  heap: '{name}' cap {cap} B, sized from {bytes} B of declared params"),
    }
    Ok(Some(cap))
}

/// The offset of the heap cap's value (params tag 0xEF, u32 LE) in a params
/// TLV, walked as the kernel walks it: entries from byte 4 to the first
/// 0xFF tag.
pub(crate) fn heap_cap_offset(tlv: &[u8]) -> Option<usize> {
    let mut off = 4usize;
    while off + 2 <= tlv.len() {
        let (tag, len) = (tlv[off], tlv[off + 1] as usize);
        off += 2;
        if tag == 0xFF {
            break;
        }
        if tag == 0xEF && len == 4 && off + 4 <= tlv.len() {
            return Some(off);
        }
        off += len;
    }
    None
}

/// Write `name`'s planned heap cap over the placeholder a `counting` plan
/// left in its params TLV `tlv` ([`instance_heap_cap`] under `plan`). A cap
/// the plan leaves at the type's own figure keeps the placeholder, which is
/// that figure.
fn patch_heap_cap(
    name: &str,
    module: &Value,
    manifest: Option<&Manifest>,
    tlv: &mut [u8],
    plan: &HeapPlan,
) -> Result<()> {
    let Some(cap) = instance_heap_cap(name, module, manifest, tlv, plan)? else {
        return Ok(());
    };
    let off = heap_cap_offset(tlv).ok_or_else(|| {
        Error::Config(format!(
            "module '{name}': its params carry no heap cap for the plan's figure to replace"
        ))
    })?;
    tlv[off..off + 4].copy_from_slice(&cap.to_le_bytes());
    Ok(())
}

/// The smallest heap cap the kernel can make a heap of: one block header and
/// one minimum allocation (`kernel::mem::heap`).
const MIN_HEAP_ARENA_BYTES: u64 = 24;

/// A module entry's `heap.arena_bytes`: this instance's heap cap, in bytes,
/// overriding the module type's declared arena. It travels as params tag
/// 0xEF (u32 LE), which the kernel reads before it sizes the heap.
fn heap_arena_bytes(v: &Value) -> std::result::Result<u32, String> {
    let n = v
        .as_u64()
        .ok_or_else(|| format!("must be a positive integer number of bytes (got {v})"))?;
    if n < MIN_HEAP_ARENA_BYTES {
        return Err(format!(
            "= {n} is below the {MIN_HEAP_ARENA_BYTES} bytes a heap needs for one allocation"
        ));
    }
    u32::try_from(n).map_err(|_| format!("= {n} exceeds a heap's u32 size"))
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

/// Reject any YAML key on a module entry that the schema doesn't know
/// about. Hard-fails for both `.fmod` modules (schema embedded in the
/// .fmod) and built-ins (schema in `manifest.toml [[params]]`).
///
/// The candidate-name check mirrors `build_params_from_schema`'s
/// flattening: nested objects expand to dotted/underscored variants,
/// and outer keys ending in a `GROUPING_SUFFIXES` entry can also resolve
/// to suffix-stripped names. Anything the packer would actually consume
/// passes; only keys that have no path to any schema param fail here.
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

        // A blob param's inline `{hex: …}` / `{bytes: […]}` entry is its one
        // value, not a group of nested params (see
        // `schema::build_params_from_schema`).
        if value.is_object()
            && schema
                .find(key)
                .is_some_and(|p| p.ptype == schema::ParamType::Blob)
        {
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
        let Some(raw) = obj
            .get(&p.name)
            .or_else(|| inner.and_then(|i| i.get(&p.name)))
        else {
            continue;
        };
        // The value as the packer will read it, never truncated to the
        // param's width first: 4294967298 is not 2.
        let v: Option<i128> = if let Some(n) = raw.as_u64() {
            Some(i128::from(n))
        } else if let Some(n) = raw.as_i64() {
            Some(i128::from(n))
        } else if let Some(t) = raw.as_str() {
            if p.enum_values.iter().any(|(name, _)| name == t) {
                continue;
            }
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => i128::from_str_radix(h, 16).ok(),
                None => t.parse::<i128>().ok(),
            }
        } else {
            None
        };
        let Some(v) = v else {
            return Err(Error::Config(format!(
                "module '{}': param '{}'={} is not an integer in [{}, {}]",
                module_name, p.name, raw, min, max,
            )));
        };
        if v < i128::from(min) || v > i128::from(max) {
            return Err(Error::Config(format!(
                "module '{}': param '{}'={} is outside [{}, {}]",
                module_name, p.name, raw, min, max,
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

/// The build-time sources of a tls / quic instance's credentials: what
/// [`lift_credential_sources`] took out of the packed module.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CredentialSources {
    /// `cert_file: "${file:<path>}"`: the chain embedded as extended tag 10.
    pub cert: Option<String>,
    /// `key_file: "${file:<path>}"`: the key embedded as extended tag 11.
    pub key: Option<String>,
    /// `trust: "${file:<path>}"` (embedded as extended tag 12), or
    /// `trust: system` (extended tag 17).
    pub trust: Option<String>,
}

/// The credential parameters of tls and quic. Each is one of: an absolute
/// path the module reads at runtime through the `fs` contract (packed as
/// the schema's string param, so `{env: NAME}` binds it too); the
/// build-time `${file:<path>}`, read here and embedded; or, for `trust`,
/// `system`.
pub(crate) const CREDENTIAL_KEYS: [&str; 3] = ["cert_file", "key_file", "trust"];

/// Separate the build-time credential sources from the keys that pack as
/// TLVs, for the `CREDENTIAL_KEYS` `schema` declares.
///
/// Returns the module as validated (every key present, so the schema check
/// sees it), the module as packed (the build-time forms removed: they are
/// embedded as extended TLVs instead), and those forms. A runtime path is
/// left to pack, and must be absolute: the module resolves it on the file
/// surface it runs on, and a relative path names nothing there.
pub(crate) fn lift_credential_sources(
    name: &str,
    module: Value,
    declares: impl Fn(&str) -> bool,
) -> Result<(Value, Value, CredentialSources)> {
    let validated = module;
    let mut packed = validated.clone();
    let mut sources = CredentialSources::default();
    let Some(obj) = validated.as_object() else {
        return Ok((validated, packed, sources));
    };
    for key in CREDENTIAL_KEYS {
        if !declares(key) {
            continue;
        }
        let spec = match obj.get(key) {
            None => continue,
            // `{env: NAME}`: the schema packs the binding, and the node
            // writes the path in at CREATE.
            Some(v) if v.as_object().is_some_and(|o| o.contains_key("env")) => continue,
            // An empty value names nothing (a param left at `""`): the
            // module takes no credential from it.
            Some(Value::String(spec)) if spec.is_empty() => continue,
            Some(Value::String(spec)) => spec.clone(),
            Some(_) => {
                return Err(Error::Config(format!(
                    "module '{name}': {key} must be an absolute path read at runtime, \
                     `${{file:<path>}}` to embed the file at build{}, or an `{{env: NAME}}` binding",
                    if key == "trust" { ", `system`" } else { "" }
                )));
            }
        };
        let lifted = if key == "trust" && spec == crate::trust_anchors::SYSTEM_SPEC {
            true
        } else if spec.starts_with("${") {
            if crate::trust_anchors::file_source(&spec).is_none() {
                return Err(Error::Config(format!(
                    "module '{name}': {key} '{spec}' is not `${{file:<path>}}`"
                )));
            }
            true
        } else {
            if !spec.starts_with('/') || spec.len() > RUNTIME_CREDENTIAL_PATH_MAX {
                return Err(Error::Config(format!(
                    "module '{name}': {key} '{spec}' is read at runtime, so it must be an \
                     absolute path of at most {RUNTIME_CREDENTIAL_PATH_MAX} bytes (write \
                     `${{file:<path>}}` to embed a build-host file instead)"
                )));
            }
            false
        };
        if lifted {
            if let Some(p) = packed.as_object_mut() {
                p.remove(key);
            }
            let slot = match key {
                "cert_file" => &mut sources.cert,
                "key_file" => &mut sources.key,
                _ => &mut sources.trust,
            };
            *slot = Some(spec);
        }
    }
    Ok((validated, packed, sources))
}

/// The peer-name keys of tls and quic: schema strings, so a workload binds
/// any of them from its environment (`{env: NAME}`) like any other string.
pub(crate) const PEER_NAME_KEYS: [&str; 3] = ["verify_hostname", "verify_uri", "alpn"];

/// The longest `verify_hostname` tls and quic hold (`MAX_EXPECTED_DNS`,
/// quic's field): a longer one is refused rather than truncated, since a
/// truncated name authenticates a different host.
const VERIFY_HOSTNAME_MAX: usize = 64;

/// Check the [`PEER_NAME_KEYS`] a module's schema declares under the
/// module's own rules, and put each in the form it packs as: `alpn`'s list
/// joined with commas, an empty value dropped (it names nothing). An
/// `{env: NAME}` binding is left for the node to fill at `CREATE`, where
/// the module holds the value to the same rule and refuses to construct
/// on one that breaks it.
pub(crate) fn normalize_peer_names(
    name: &str,
    type_name: &str,
    mut module: Value,
    declares: impl Fn(&str) -> bool,
) -> Result<Value> {
    let Some(obj) = module.as_object_mut() else {
        return Ok(module);
    };
    for key in PEER_NAME_KEYS {
        if !declares(key) {
            continue;
        }
        let Some(v) = obj.get(key) else {
            continue;
        };
        if v.as_object().is_some_and(|o| o.contains_key("env")) {
            continue;
        }
        let packed = match key {
            "alpn" => alpn_param(name, type_name, Some(v))?,
            _ => {
                let Some(text) = v.as_str() else {
                    return Err(Error::Config(format!(
                        "module '{name}': {key} is a string or an `{{env: NAME}}` binding"
                    )));
                };
                if text.is_empty() {
                    None
                } else if key == "verify_uri" {
                    check_verify_uri(text)
                        .map_err(|e| Error::Config(format!("module '{name}': {e}")))?;
                    Some(text.to_string())
                } else if text.len() > VERIFY_HOSTNAME_MAX {
                    return Err(Error::Config(format!(
                        "module '{name}': verify_hostname is {} bytes, over the \
                         {VERIFY_HOSTNAME_MAX}-byte limit: a truncated name would \
                         authenticate a different host",
                        text.len()
                    )));
                } else {
                    Some(text.to_string())
                }
            }
        };
        match packed {
            Some(text) => {
                obj.insert(key.to_string(), Value::String(text));
            }
            None => {
                obj.remove(key);
            }
        }
    }
    Ok(module)
}

/// The longest runtime credential path: the module's `CRED_PATH_MAX`, one
/// basic TLV string.
const RUNTIME_CREDENTIAL_PATH_MAX: usize = 255;

/// Expand compound YAML fields that don't map 1:1 to schema params,
/// returning a clone with the flat fields in place. Pure YAML-level
/// rewrite — schema lookup runs unchanged afterwards.
///
/// Handles:
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

/// A module's u32 YAML setting (`step_deadline_us`,
/// `step_deadline_burst_us`): `None` when absent or null, else the value
/// range-checked as a u32. A non-integer or an overflowing value is an
/// error, never a silent wrap or omission. Shared by the node-graph module
/// entry and the workload module record, so both read a setting the same
/// way.
fn yaml_u32_setting(module: &Value, key: &str, name: &str) -> Result<Option<u32>> {
    let Some(v) = module.get(key) else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    match v.as_u64() {
        Some(n) if n <= u32::MAX as u64 => Ok(Some(n as u32)),
        Some(n) => Err(Error::Config(format!(
            "module '{name}': {key} = {n} exceeds u32::MAX"
        ))),
        None => Err(Error::Config(format!(
            "module '{name}': {key} must be a non-negative integer (got {v})"
        ))),
    }
}

/// A module's `fault_policy`, or `None` when absent or null.
/// `restart_graph` is refused: a module's fault is the module's, and no
/// policy reaches past it to the graph (SCH-08).
fn yaml_fault_policy(module: &Value, name: &str) -> Result<Option<FaultPolicy>> {
    let Some(v) = module.get("fault_policy") else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let policy_str = v.as_str().ok_or_else(|| {
        Error::Config(format!(
            "module '{name}': fault_policy must be a string \
             (\"skip\" | \"restart\" | \"tolerate\"); got {v}"
        ))
    })?;
    match policy_str {
        "skip" => Ok(Some(FaultPolicy::Skip)),
        "restart" => Ok(Some(FaultPolicy::Restart)),
        // Overruns recorded but never fatal — for storage modules whose
        // synchronous device ops have a legitimate heavy tail. Step errors
        // still fault.
        "tolerate" => Ok(Some(FaultPolicy::Tolerate)),
        "restart_graph" => Err(Error::Config(format!(
            "module '{name}': fault_policy = 'restart_graph' is not a policy: a module's \
             fault is its own, and no policy tears down the graph around it. Use \"skip\" \
             to terminate the module, \"restart\" to run it again, or \"tolerate\" to \
             record overruns without faulting"
        ))),
        _ => Err(Error::Config(format!(
            "module '{name}': fault_policy = '{policy_str}' is invalid \
             (use \"skip\", \"restart\", or \"tolerate\")"
        ))),
    }
}

/// A module's step budget as its YAML declares it, unchecked against any
/// ceiling: the deadline, the burst deadline and the fault policy (`skip`
/// when undeclared).
fn yaml_step_budget(module: &Value, name: &str) -> Result<crate::add_subgraph::StepBudget> {
    Ok(crate::add_subgraph::StepBudget {
        deadline_us: yaml_u32_setting(module, "step_deadline_us", name)?.unwrap_or(0),
        burst_us: yaml_u32_setting(module, "step_deadline_burst_us", name)?.unwrap_or(0),
        fault_policy: yaml_fault_policy(module, name)?.unwrap_or_default(),
    })
}

/// The step budget a workload module declares, admitted as the node's
/// kernel admits it (`scheduler::live::admit_step_budget`), so an image
/// that builds is one a node with the graph's domains takes:
///
///   * `fault_policy` is `skip`, the one policy whose whole effect stays on
///     the faulting module: it terminates the module. `restart` releases the
///     module's provider layers and flushes its channels, which other owners
///     may hold. `tolerate` records an overrun and lets the module run on, so
///     the domain's other modules pay for every late step and the deadline it
///     was admitted under never binds it. A workload is refused both.
///   * A declared `step_deadline_us` and the effective burst deadline
///     (`step_deadline_burst_us`, else `step_deadline_us ×
///     BURST_MULTIPLIER`) each fit `16 ×` the domain's shortest tick
///     (`tick_min_us` on an adaptive-cadence domain) and the absolute
///     `HARD_BURST_CAP_US`. The burst rule is the node graph's
///     (`validate_scheduler_budgets`); the step deadline is held to the
///     same ceiling because the kernel holds a workload to it.
///
/// The node checks again against its own ticks: the domains this image was
/// built against are the author's, not necessarily the node's.
pub(crate) fn workload_step_budget(
    module: &Value,
    config: &Value,
    label: &str,
) -> Result<crate::add_subgraph::StepBudget> {
    let budget = yaml_step_budget(module, label)?;
    if budget.fault_policy != FaultPolicy::Skip {
        return Err(Error::Config(format!(
            "{label}: fault_policy {} is not available to a workload module; a node admits a \
             workload only \"skip\", which terminates the faulting module and touches nothing \
             else. restart releases the module's provider layers and flushes its channels, \
             which other owners may hold. tolerate records an overrun and lets the module run \
             on, so the domain's other modules pay for every late step and the deadline it was \
             admitted under never binds it.",
            module
                .get("fault_policy")
                .map(|v| v.to_string())
                .unwrap_or_default()
        )));
    }
    if !budget.declares_deadline() {
        return Ok(budget);
    }
    let domain = resolve_domain_id(module, config)? as usize;
    let domains = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array());
    let dom = domains.and_then(|d| d.get(domain));
    let graph_tick = config
        .get("tick_us")
        .or_else(|| config.get("execution").and_then(|e| e.get("tick_us")))
        .and_then(|v| v.as_u64())
        .filter(|t| *t > 0)
        .unwrap_or(DEFAULT_TICK_US as u64);
    let domain_tick = dom
        .and_then(|d| d.get("tick_us"))
        .and_then(|v| v.as_u64())
        .filter(|t| *t > 0)
        .unwrap_or(graph_tick);
    let cadence = dom
        .and_then(|d| d.get("adaptive_flags"))
        .and_then(|v| v.as_u64())
        .is_some_and(|f| f & ADAPTIVE_FLAG_CADENCE as u64 != 0);
    let floor_tick = if cadence {
        dom.and_then(|d| d.get("tick_min_us"))
            .and_then(|v| v.as_u64())
            .filter(|t| *t > 0)
            .unwrap_or(domain_tick)
    } else {
        domain_tick
    };
    let ceiling = floor_tick.saturating_mul(16).min(HARD_BURST_CAP_US as u64);
    if budget.deadline_us as u64 > ceiling {
        return Err(Error::Config(format!(
            "{label}: step_deadline_us = {} exceeds the {ceiling} us a workload module may \
             declare in its domain (16 × its shortest tick of {floor_tick} us, at most \
             {HARD_BURST_CAP_US} us)",
            budget.deadline_us
        )));
    }
    let burst_eff = budget.effective_burst_us();
    if burst_eff as u64 > ceiling {
        return Err(Error::Config(format!(
            "{label}: burst deadline {burst_eff} us (step_deadline_burst_us, else \
             step_deadline_us × {BURST_DEADLINE_MULTIPLIER}) exceeds the {ceiling} us a workload \
             module may declare in its domain (16 × its shortest tick of {floor_tick} us, at \
             most {HARD_BURST_CAP_US} us). Declare step_deadline_burst_us explicitly, or lower \
             step_deadline_us."
        )));
    }
    Ok(budget)
}

#[allow(
    clippy::too_many_arguments,
    reason = "module-entry compilation threads the resolved graph context (config, manifests, modules_dir); splitting it into a context struct is a larger refactor than the argument count warrants"
)]
fn build_module_entry(
    name: &str,
    module: &Value,
    id: u16,
    data_section: Option<&Value>,
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    manifests: &HashMap<String, Manifest>,
    max_modules: usize,
    isolation: &crate::target::IsolationFacts,
    plan: &HeapPlan,
) -> Result<ModuleEntry> {
    // The params buffer grows to fit the entry: an entry that ran out of room,
    // or left too little to prove nothing was skipped, is rebuilt in a buffer
    // twice the size. There is no params ceiling.
    let mut cap = params_buffer_for(module, data_section);
    loop {
        let mut out_of_room = false;
        let built = build_module_entry_in(
            cap,
            &mut out_of_room,
            name,
            module,
            id,
            data_section,
            config,
            loc,
            manifests,
            max_modules,
            isolation,
            plan,
        );
        match built {
            Ok(entry) if cap - entry.params.len() >= PARAMS_BUFFER_HEADROOM => {
                return Ok(entry);
            }
            Ok(_) => {}
            Err(_) if out_of_room => {}
            Err(e) => return Err(e),
        }
        cap = cap
            .checked_mul(2)
            .ok_or_else(|| Error::Config(format!("module '{name}': params too large to pack")))?;
    }
}

/// The packer's error, noting when it was only this pass's buffer that was too
/// small (the packer refuses a blob that does not fit with "does not fit").
fn out_of_room_or(out_of_room: &mut bool, e: String) -> Error {
    if e.contains("does not fit") {
        *out_of_room = true;
    }
    Error::Config(e)
}

/// [`build_module_entry`] over a params buffer of `cap` bytes. Sets
/// `out_of_room` when it failed only because `cap` was too small.
#[expect(
    clippy::too_many_arguments,
    reason = "build_module_entry's arguments plus the buffer it is building in"
)]
fn build_module_entry_in(
    cap: usize,
    out_of_room: &mut bool,
    name: &str,
    module: &Value,
    id: u16,
    data_section: Option<&Value>,
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    manifests: &HashMap<String, Manifest>,
    max_modules: usize,
    isolation: &crate::target::IsolationFacts,
    plan: &HeapPlan,
) -> Result<ModuleEntry> {
    // Room for this pass's params; truncated to what the entry used.
    let mut entry = vec![0u8; cap];

    // Module type: explicit "type" field or falls back to "name"
    let type_name = module["type"].as_str().unwrap_or(name);

    // The type name's hash, so the kernel can find the .fmod. This allows
    // multiple instances: name: seq_kick, type: sequencer
    let name_hash = fnv1a_hash(type_name.as_bytes());
    let domain = resolve_domain_id(module, config)?;
    // `manifests` was populated by `load_module_manifests_with_extra`
    // against the same resolver chain that admission validation uses
    // (project root, install root, caller-supplied extras), so a module
    // admission finds — an installed driver among them — carries its
    // `pre_pass` flag here too. It rides the module record (not the
    // .fmod manifest) so the kernel reads it during `prepare_graph` without
    // a second loader pass.
    let pre_pass = manifests.get(name).is_some_and(|m| m.pre_pass);

    // Track actual params length used
    let mut params_len: usize;

    // Some modules accept compound YAML fields that don't map 1:1 to
    // schema params (e.g. `broker: "host:port"` in mqtt). Expand them
    // into the flat fields the schema knows about before packing.
    let normalized_module = expand_compound_yaml_fields(type_name, module, config);
    // PIC modules embed their schema in the `.fmod`; built-ins declare
    // it in `modules/platform/<platform>/<name>/manifest.toml`. Both
    // paths produce a `ParamSchema` and feed the same TLV packer, so
    // the wire format is identical at the kernel boundary.
    //
    // `?` propagates only the pinned-but-unresolvable case, which is a hard
    // error (sibling of `assert_pinned_manifests_resolvable`). "No `.fmod`
    // schema" stays `Ok(None)` and falls through to the built-in path — a
    // built-in is never pinned and has no `.fmod`.
    let pic_schema = schema::load_schema_for_entry(module, type_name, loc)?;
    // On a module whose schema declares `trust` (tls, quic) the key is a
    // trust-anchor source spec: validated against the schema with the
    // other keys, then lifted out, since its value is resolved to an anchor bundle
    // (extended tag 12 below) and never packed as a string TLV. On any
    // other module `trust` keeps whatever meaning that module gives it —
    // an interrupt-mode module's `trust: platform` is a trust LEVEL, read by
    // `board::validate_config`, and is left exactly as written.
    let declares = |key: &str| pic_schema.as_ref().is_some_and(|s| s.find(key).is_some());
    let normalized_module = normalize_peer_names(name, type_name, normalized_module, declares)?;
    let (normalized_module, packed_module, sources) =
        lift_credential_sources(name, normalized_module, declares)?;
    let trust_spec = sources.trust.clone();
    let module = &normalized_module;
    let packed_module = &packed_module;

    // The `heap:` subtree is structurally orthogonal to the schema
    // (it's emitted as protection TLV tags, not schema params), so
    // its validator runs unconditionally — modules with no schema
    // source must still surface a `heap.alloc_failure_policy` typo
    // at build time rather than letting it silently drop at runtime.
    validate_heap_subtree(module, type_name)?;
    validate_variant_key(module, type_name)?;

    if let Some(param_schema) = pic_schema {
        validate_yaml_params(module, &param_schema, type_name)?;
        params_len = schema::build_params_from_schema(
            packed_module,
            &param_schema,
            &mut entry,
            0,
            data_section,
            type_name,
        )
        .map_err(|e| out_of_room_or(out_of_room, e))?;
    } else if let Some((manifest, param_schema)) = load_builtin_param_schema(type_name) {
        validate_yaml_params(module, &param_schema, type_name)?;
        validate_param_ranges(module, &manifest, type_name)?;
        validate_required_params(module, &manifest, type_name)?;
        // Inject manifest defaults into a YAML clone so every declared
        // param produces a TLV entry. The built-in's step function
        // reads values straight off the wire, with no defaults
        // duplicated in Rust.
        let module_with_defaults = inject_manifest_defaults(packed_module, &manifest);
        params_len = schema::build_params_from_schema(
            &module_with_defaults,
            &param_schema,
            &mut entry,
            0,
            data_section,
            type_name,
        )
        .map_err(|e| out_of_room_or(out_of_room, e))?;
    } else {
        // Module type with no schema source — typically a misnamed
        // YAML entry. Emit an empty params section; downstream
        // resource and capability checks raise the user-facing error.
        params_len = 0;
    }

    // Append restart and protection params as reserved TLV tags
    // (0xF2..0xFA). Parsed by the kernel scheduler during
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
    // Params with no schema TLV of their own start one, so the tags below
    // sit after the same header every params blob has.
    if params_len == 0 && entry.len() >= 4 {
        entry[..4].copy_from_slice(&[0xFE, 0x01, 0, 0]);
        params_len = 4;
    }
    let mut extra_len = 0usize;
    let had_end_marker = params_len >= 2
        && entry.get(params_len - 2).copied() == Some(0xFF)
        && entry.get(params_len - 1).copied() == Some(0x00);
    let base = if had_end_marker {
        params_len - 2
    } else {
        params_len
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
    // One TLV entry (≤255 bytes); a larger shell is refused, since the
    // resolver takes no chunked table.
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
        // shell control it would render as a dead or wrong button.
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

    // The step budget rides the module record, never the params.
    let budget = yaml_step_budget(module, name)?;

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

    // Tag 0xF5 (protection level), from the one resolution the validator
    // admitted (`protection::resolve`), which a trust class implies: the level
    // emitted is the level the target PROVIDES — a `contained` request on a
    // target that implements only `isolated` is sent as `isolated` — so the
    // kernel enforces what the composer printed. A request the target cannot
    // meet was refused by the validator; it never reaches here.
    let resolved = crate::protection::resolve(module, config, &isolation.levels)
        .map_err(|e| Error::Config(format!("module '{name}': {e}")))?;
    if base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xF5;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = resolved.provided as u8;
        extra_len += 3;
    }

    // Extended-protection tags — emit when the module YAML declares
    // them. The kernel-side parser at `parse_protection_config`
    // reads each tag and routes to the appropriate setter. All tags
    // are optional; omit when the field isn't declared so module
    // graphs that opt out see no change.

    // Tag 0xF7: quarantine_partner (u16 LE module index).
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
            if base + extra_len + 4 < entry.len() {
                entry[base + extra_len] = 0xF7;
                entry[base + extra_len + 1] = 2;
                entry[base + extra_len + 2..base + extra_len + 4]
                    .copy_from_slice(&(partner as u16).to_le_bytes());
                extra_len += 4;
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

    // Tag 0xEF (u32 LE): this instance's heap cap, overriding the module
    // type's declared arena — the graph's `heap.arena_bytes` (validated by
    // `validate_heap_subtree`), else what the type's `[capacities]
    // heap_from_params` and `heap_per_demand` rules derive (`instance_heap_cap`).
    if let Some(n) = instance_heap_cap(name, module, manifests.get(name), &entry[..base], plan)? {
        if base + extra_len + 6 < entry.len() {
            entry[base + extra_len] = 0xEF;
            entry[base + extra_len + 1] = 4;
            entry[base + extra_len + 2..base + extra_len + 6].copy_from_slice(&n.to_le_bytes());
            extra_len += 6;
        }
    }

    // Tag 0xEE: raw arena use — the module reads its heap arena raw
    // (`ARENA_GET`), so the kernel commits the whole cap at instantiation
    // rather than on whichever step first asks. Declared per instance
    // (`heap.raw_arena: true`) or by the module type (`[capacities]
    // raw_arena = 1`).
    if declares_raw_arena(module, manifests.get(name)) && base + extra_len + 3 < entry.len() {
        entry[base + extra_len] = 0xEE;
        entry[base + extra_len + 1] = 1;
        entry[base + extra_len + 2] = 1;
        extra_len += 3;
    }

    // Tag 0xFB: isr_budget_cycles (u32 LE, 4 bytes). Per-module
    // `timer`/`irq` cycle budget override: the ISR budget guard trips a
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
    // number for `irq` admission. Required for `irq` modules
    // (`validate_interrupt_admission` enforces); the kernel passes
    // it to `irq::register_module` at admission time.
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

    // Tag 0xFD: device window (u64 base LE, u32 size LE): the peripheral
    // block the graph grants a gated driver by name, resolved against the
    // target's grantable blocks. The kernel maps it into the module's domain;
    // the module reads its base from the same tag in its params.
    if let Some((wb, wz)) = crate::protection::device_window(module, &isolation.device_ranges)
        .map_err(|e| Error::Config(format!("module '{name}': {e}")))?
    {
        if base + extra_len + 14 < entry.len() {
            entry[base + extra_len] = 0xFD;
            entry[base + extra_len + 1] = 12;
            entry[base + extra_len + 2..base + extra_len + 10].copy_from_slice(&wb.to_le_bytes());
            entry[base + extra_len + 10..base + extra_len + 14].copy_from_slice(&wz.to_le_bytes());
            extra_len += 14;
        }
    }

    // Emit the schema-section end marker `0xFF 0x00` here, after the
    // protection tags (0xF2-0xFA) but BEFORE any extended cert/key
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
        // position. The field is advisory — every reader, the extended
        // scanners included, walks to the terminator — but it is kept
        // honest, saturating rather than wrapping past 64 KiB.
        //
        // payload_len is measured from byte 4 (past the TLV header) to
        // the byte AFTER the end marker: `base + extra_len - 4`.
        if entry.len() >= 4 && entry[0] == 0xFE {
            // Saturating past 64 KiB: readers walk to the terminator.
            let new_payload_len = (base + extra_len) - 4;
            let bytes = schema::tlv_payload_len_field(new_payload_len);
            entry[2] = bytes[0];
            entry[3] = bytes[1];
        }
    }

    // Tags 10 and 11: the instance's own certificate and private key in
    // their build-time form, `cert_file` / `key_file: "${file:<path>}"`,
    // each PEM or DER, embedded as DER. A file that cannot be read, decoded
    // or carried fails the build: an instance run without the identity it
    // was given would fail later, further from the cause. A bare path is
    // the module's to read at runtime and was packed as its string param.
    for (key, tag, labels, spec) in [
        (
            "cert_file",
            10u8,
            crate::trust_anchors::CERT_LABELS,
            sources.cert.as_deref(),
        ),
        (
            "key_file",
            11u8,
            crate::trust_anchors::KEY_LABELS,
            sources.key.as_deref(),
        ),
    ] {
        let Some(path) = spec.and_then(crate::trust_anchors::file_source) else {
            continue;
        };
        let der = if let Some(n) = check_stand_in(path, key) {
            vec![0u8; n]
        } else {
            crate::trust_anchors::read_der_file(Path::new(path), labels)
                .map_err(|e| Error::Config(format!("module '{name}': {key}: {e}")))?
        };
        let n = der.len();
        if n > u16::MAX as usize {
            return Err(Error::Config(format!(
                "module '{name}': {key} '{path}' ({n} bytes) exceeds the extended TLV's 64 KiB"
            )));
        }
        if base + extra_len + 4 + n >= entry.len() {
            *out_of_room = true;
            return Err(Error::Config(format!(
                "module '{name}': {key} '{path}' ({n} bytes) does not fit in the module entry"
            )));
        }
        entry[base + extra_len] = tag;
        entry[base + extra_len + 1] = 0x00; // extended length marker
        entry[base + extra_len + 2] = (n >> 8) as u8;
        entry[base + extra_len + 3] = n as u8;
        entry[base + extra_len + 4..base + extra_len + 4 + n].copy_from_slice(&der);
        extra_len += 4 + n;
        eprintln!("  {key}: {path} ({n} bytes)");
    }

    // Tag 12: the deployment's trust anchors in their build-time form —
    // `trust: "${file:<path>}"`, one certificate or a bundle, embedded as
    // concatenated DER. A file
    // that cannot be read, holds no certificate, or holds more than the
    // module's table fails the build here, naming the file and the
    // instance: an anchor set is a decision, and an instance is not run
    // on a decision that did not load.
    if trust_spec.as_deref() == Some(crate::trust_anchors::SYSTEM_SPEC) {
        // `trust: "system"`: one byte saying so, and no anchors, because
        // there are none to carry. The platform verifies and answers; the
        // module asks it rather than holding a set of its own.
        let blob = crate::trust_anchors::encode_ext(
            crate::trust_anchors::TAG_TRUST_SYSTEM,
            core::slice::from_ref(&vec![1u8]),
        );
        if base + extra_len + blob.len() >= entry.len() {
            *out_of_room = true;
            return Err(Error::Config(format!(
                "module '{name}': trust marker does not fit in the module entry"
            )));
        }
        entry[base + extra_len..base + extra_len + blob.len()].copy_from_slice(&blob);
        extra_len += blob.len();
        eprintln!("  trust: the platform's own store (verified by contract)");
    } else if let Some(spec) = trust_spec.as_deref() {
        let path = crate::trust_anchors::file_source(spec).ok_or_else(|| {
            Error::Config(format!(
                "module '{name}': trust must be `system` or a `${{file:<path>}}` source spec, got '{spec}'"
            ))
        })?;
        let anchors = if let Some(n) = check_stand_in(path, "trust") {
            vec![vec![0u8; n]]
        } else {
            crate::trust_anchors::load_bundle(Path::new(path))
                .map_err(|e| Error::Config(format!("module '{name}': trust: {e}")))?
        };
        let blob = crate::trust_anchors::encode_ext(crate::trust_anchors::TAG_TRUST, &anchors);
        if base + extra_len + blob.len() >= entry.len() {
            *out_of_room = true;
            return Err(Error::Config(format!(
                "module '{name}': trust bundle '{path}' does not fit in the module entry"
            )));
        }
        entry[base + extra_len..base + extra_len + blob.len()].copy_from_slice(&blob);
        extra_len += blob.len();
        eprintln!(
            "  trust: {path} ({} anchor(s), {} bytes)",
            anchors.len(),
            blob.len() - 4
        );
    }

    // The params' length. The extended cert/key bytes were written past
    // the end marker and are accounted for in `extra_len`. The 2-byte
    // original schema end marker, if any, was overwritten and re-emitted by
    // the inserted-end-marker block above:
    //   * had_end_marker == true:  base = orig_params_len - 2; the
    //     original `0xFF 0x00` was overwritten and re-emitted
    //     (counted in `extra_len`). Total = (params_len - 2) + extra_len.
    //   * had_end_marker == false: base = orig_params_len; the end
    //     marker was appended (counted in extra_len). Total =
    //     params_len + extra_len.
    let payload_total = if had_end_marker {
        params_len.saturating_sub(2) + extra_len
    } else {
        params_len + extra_len
    };
    crate::protection::params_fit(resolved.provided, payload_total)
        .map_err(|e| Error::Config(format!("module '{name}': {e}")))?;
    entry.truncate(payload_total);

    Ok(ModuleEntry {
        name_hash,
        id,
        domain,
        pre_pass,
        budget,
        params: entry,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "build_module_entry's graph context, threaded through for every entry"
)]
pub(crate) fn parse_modules_map(
    modules: &Value,
    data_section: Option<&Value>,
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    manifests: &HashMap<String, Manifest>,
    max_modules: usize,
    isolation: &crate::target::IsolationFacts,
    plan: &HeapPlan,
) -> Result<(Vec<ModuleEntry>, Vec<String>)> {
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
    let mut name_to_idx: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
    for (idx, m) in list.iter().enumerate() {
        if idx >= max_modules {
            break;
        }
        if let Some(n) = m.get("name").and_then(|v| v.as_str()) {
            name_to_idx.entry(n.to_string()).or_insert(idx as u16);
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
        let resolved_idx: Option<u16> = match partner_val {
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
                Some(n as u16)
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

        let id = idx as u16;
        let entry = build_module_entry(
            name,
            &module_owned,
            id,
            data_section,
            config,
            loc,
            manifests,
            max_modules,
            isolation,
            plan,
        )?;
        entries.push(entry);
        names.push(name.to_string());
    }

    Ok((entries, names))
}

/// The `alpn` parameter of a module of type `type_name`, comma-joined:
/// a string (`"h2"`, `"h2,http/1.1"`) or a list of names. `None` when the
/// module names none. A name the module could not hold whole is refused
/// here, not clipped: a truncated name negotiates a protocol nobody
/// configured. The module stores the list in a fixed buffer and each
/// selected name in a fixed slot — 64 bytes in all for both, and a name of
/// at most 24 bytes for quic (`MAX_ALPN`) or 16 for tls (its
/// `ALPN_NAME_MAX`, the width a session's negotiated protocol is kept and
/// checkpointed at).
fn alpn_param(name: &str, type_name: &str, v: Option<&Value>) -> Result<Option<String>> {
    const ALPN_LIST_MAX: usize = 64;
    let token_max: usize = if type_name == "tls" { 16 } else { 24 };
    let alpn = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => {
            let mut names = Vec::with_capacity(items.len());
            for it in items {
                let Some(s) = it.as_str() else {
                    return Err(Error::Config(format!(
                        "module '{name}': alpn is a protocol name or a list of them"
                    )));
                };
                if s.contains(',') {
                    return Err(Error::Config(format!(
                        "module '{name}': alpn name '{s}' holds a comma; list the names apart"
                    )));
                }
                names.push(s);
            }
            names.join(",")
        }
        Some(_) => {
            return Err(Error::Config(format!(
                "module '{name}': alpn is a protocol name or a list of them"
            )))
        }
    };
    let n = alpn.len();
    if n > ALPN_LIST_MAX {
        return Err(Error::Config(format!(
            "module '{name}': alpn list is {n} bytes, exceeds the {ALPN_LIST_MAX}-byte limit"
        )));
    }
    if n == 0 {
        return Ok(None);
    }
    for tok in alpn.split(',') {
        if tok.is_empty() || !tok.bytes().all(|c| (0x21..0x7F).contains(&c)) {
            return Err(Error::Config(format!(
                "module '{name}': alpn name '{tok}' must be 1 or more printable ASCII bytes \
                 with no space"
            )));
        }
        if tok.len() > token_max {
            return Err(Error::Config(format!(
                "module '{name}': alpn token '{tok}' exceeds the {token_max}-byte limit"
            )));
        }
    }
    Ok(Some(alpn))
}

/// The longest `verify_uri` the tls module accepts: its `PEER_PRINCIPAL_MAX`,
/// the longest principal a session reports. A peer is never accepted under
/// a URI its session could not report, so a longer expectation could never
/// be satisfied.
const VERIFY_URI_MAX: usize = 128;

/// Bytes a certificate, a private key, or one trust anchor is checked at
/// when `fluxor build --check` finds its file absent: a P-256 or RSA-2048
/// certificate and a PKCS#8 key fit, so a check still answers whether an
/// instance's identity and anchors fit its module entry.
const CHECK_NOMINAL_CERT: usize = 1024;
const CHECK_NOMINAL_KEY: usize = 256;

/// Under `fluxor build --check` (`params::checking`), the nominal size a
/// module's `key` file (`cert_file`, `key_file`, `trust`) at `path` is
/// checked at because it is not there; `None` when it is there, which is
/// then decoded as a build decodes it, and always outside a check, where a
/// missing file fails the build.
pub(crate) fn check_stand_in(path: &str, key: &str) -> Option<usize> {
    let n = stand_in_size(fluxor_tools::params::checking(), path, key)?;
    eprintln!("  {key}: {path} is not here; checked at a nominal {n} bytes");
    Some(n)
}

/// [`check_stand_in`]'s decision, with whether this is a check given.
fn stand_in_size(checking: bool, path: &str, key: &str) -> Option<usize> {
    if !checking || Path::new(path).exists() {
        return None;
    }
    Some(if key == "key_file" {
        CHECK_NOMINAL_KEY
    } else {
        CHECK_NOMINAL_CERT
    })
}

/// The tls module's rule for a `verify_uri` (its `uri_well_formed`): at most
/// [`VERIFY_URI_MAX`] bytes of RFC 3986 unreserved characters, sub-delims,
/// `:`, `@` and `/` — no percent-encoding, query or fragment, which would
/// give one identity several spellings — shaped `scheme://authority/path`
/// with a non-empty scheme and authority. A bare `spiffe://` names no
/// authority, and is refused rather than read as every URI of the scheme.
fn check_verify_uri(uri: &str) -> std::result::Result<(), String> {
    let b = uri.as_bytes();
    if b.is_empty() {
        return Err("verify_uri is empty: under ca_uri the URI is the whole authorisation".into());
    }
    if b.len() > VERIFY_URI_MAX {
        return Err(format!(
            "verify_uri is {} bytes, over the {VERIFY_URI_MAX}-byte limit: no peer \
             could be accepted under it, and truncating it would authenticate a \
             different identity",
            b.len()
        ));
    }
    if let Some(c) = uri
        .chars()
        .find(|&c| !(c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@/".contains(c)))
    {
        return Err(format!(
            "verify_uri '{uri}' contains '{c}': only RFC 3986 unreserved characters, \
             sub-delims, ':', '@' and '/' are matched (no percent-encoding, query or fragment)"
        ));
    }
    let shape = || {
        format!(
            "verify_uri '{uri}' must be scheme://authority/path (an exact URI, or a \
             path prefix ending in '/'), e.g. spiffe://example.org/peers/"
        )
    };
    let (scheme, rest) = uri.split_once("://").ok_or_else(shape)?;
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    if !scheme_ok || scheme.contains(':') {
        return Err(shape());
    }
    match rest.find('/') {
        Some(slash) if slash > 0 => Ok(()),
        _ => Err(shape()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ranged built-in param is checked at the value the packer reads:
    /// past `u32` it is not wrapped into range, a numeric string (what a
    /// stack's `user:` source resolves to) is checked like a number, and a
    /// negative or non-numeric value is refused.
    #[test]
    fn a_ranged_param_is_checked_at_its_whole_value() {
        let (manifest, _) = load_builtin_param_schema("linux_net").expect("linux_net manifest");
        let check =
            |v: Value| validate_param_ranges(&json!({ "max_conns": v }), &manifest, "linux_net");
        for ok in [json!(2), json!(65535), json!("128"), json!("0x80")] {
            assert!(check(ok.clone()).is_ok(), "{ok}");
        }
        for bad in [
            json!(1),
            json!(65536),
            json!(4_294_967_298u64),
            json!(-1),
            json!("100000"),
            json!("4294967298"),
            json!("lots"),
            json!(2.5),
        ] {
            assert!(check(bad.clone()).is_err(), "{bad} accepted");
        }
        let wrapped = validate_param_ranges(
            &json!({ "params": { "max_conns": 70000 } }),
            &manifest,
            "linux_net",
        );
        assert!(wrapped.is_err(), "the params: wrapper is checked too");
    }

    /// A one-param schema as an `.fmod` embeds it: `decision`, a blob (tag 15).
    fn blob_param_schema() -> schema::ParamSchema {
        let mut b = vec![b'S', b'P', 1, 1, 15, 5, 0, 0, 0, 0, 8];
        b.extend_from_slice(b"decision");
        b.push(0); // no enum values
        schema::ParamSchema::from_bytes(&b).expect("schema bytes")
    }

    /// A blob param's inline `{hex: …}` entry is its value, not a group of
    /// nested params named `decision.hex`; any other mapping still has to name
    /// a param.
    #[test]
    fn an_inline_blob_entry_is_the_params_value() {
        let schema = blob_param_schema();
        let ok = serde_json::json!({ "name": "s", "decision": { "hex": "00" } });
        assert!(validate_yaml_params(&ok, &schema, "store_big").is_ok());
        let unknown = serde_json::json!({ "name": "s", "verdict": { "hex": "00" } });
        assert!(validate_yaml_params(&unknown, &schema, "store_big").is_err());
    }

    /// `verify_uri` is held to the tls module's URI rule at build: a bare
    /// scheme, an encoded or query-bearing URI, and one no session could
    /// report are refused with the reason; a SPIFFE ID or a path prefix
    /// ending in `/` is taken.
    #[test]
    fn verify_uri_is_checked_under_the_modules_rule() {
        for ok in [
            "spiffe://example.org/peers/",
            "spiffe://example.org/workload/a",
            "spiffe://cluster.test/owner/peers/device/",
        ] {
            assert!(check_verify_uri(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "spiffe://",
            "spiffe://example.org",
            "spiffe:///peers/",
            "://example.org/peers/",
            "1spiffe://example.org/x",
            "spiffe://example.org/a%2Fb",
            "spiffe://example.org/a?x=1",
            "spiffe://example.org/a#frag",
            "spiffe://example.org/a b",
        ] {
            assert!(check_verify_uri(bad).is_err(), "{bad:?} was taken");
        }
        let long = format!("spiffe://example.org/{}", "a".repeat(VERIFY_URI_MAX));
        let err = check_verify_uri(&long).unwrap_err();
        assert!(err.contains("128"), "the limit is named: {err}");
    }
}
