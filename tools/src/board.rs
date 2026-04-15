//! Board validation using target descriptors.
//!
//! Validates a configuration against the resolved target's constraints:
//! pin ranges, reserved pins, valid peripheral pin combinations, and conflicts.

use std::collections::HashSet;

use serde_json::Value;

use crate::error::Result;
use crate::target::TargetDescriptor;

/// Validation result with warnings and errors
#[derive(Default)]
pub struct ValidationResult {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    pub fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Validate a complete configuration against target constraints.
pub fn validate_config(config: &Value, target: &TargetDescriptor) -> Result<ValidationResult> {
    let mut result = ValidationResult::default();
    let mut used_pins: HashSet<u8> = HashSet::new();

    // Validate hardware section if present
    if let Some(hardware) = config.get("hardware") {
        validate_hardware_section(hardware, target, &mut result, &mut used_pins)?;
    }

    // Validate sources for pin usage
    if let Some(sources) = config.get("sources").and_then(|s| s.as_array()) {
        for (i, src) in sources.iter().enumerate() {
            validate_source_pins(src, i, target, &mut result, &mut used_pins);
        }
    }

    // Validate sinks for pin usage
    if let Some(sinks) = config.get("sinks").and_then(|s| s.as_array()) {
        for (i, sink) in sinks.iter().enumerate() {
            validate_sink_pins(sink, i, target, &mut result, &mut used_pins);
        }
    }

    // Validate reconfigure section if present
    if let Some(reconfig) = config.get("reconfigure")
        .or_else(|| config.get("graph").and_then(|g| g.get("reconfigure")))
    {
        validate_reconfigure_section(reconfig, config, &mut result);
    }

    // Validate bridges section if present
    if let Some(bridges) = config.get("bridges").and_then(|b| b.as_array()) {
        validate_bridges(bridges, config, &mut result);
    }

    // Validate ISR module declarations if present
    if let Some(modules) = config.get("modules").and_then(|m| m.as_array()) {
        validate_isr_modules(modules, target, &mut result);
    }

    // Validate isolation settings if present
    validate_isolation(config, target, &mut result);

    // Validate paged arena settings if present
    validate_paged_arenas(config, target, &mut result);

    Ok(result)
}

/// Validate bridge channel declarations.
fn validate_bridges(bridges: &[Value], config: &Value, result: &mut ValidationResult) {
    let module_names: Vec<String> = config.get("modules")
        .and_then(|m| m.as_array())
        .map(|arr| arr.iter().filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from)).collect())
        .unwrap_or_default();

    let valid_types = ["snapshot", "ring", "command"];

    for (i, bridge) in bridges.iter().enumerate() {
        let prefix = format!("bridges[{}]", i);

        // Required: type
        let btype = bridge.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if !valid_types.contains(&btype) {
            result.add_error(format!("{}: invalid type '{}' (must be snapshot, ring, or command)", prefix, btype));
        }

        // Required: from and to (module.port format)
        for field in &["from", "to"] {
            if let Some(spec) = bridge.get(*field).and_then(|v| v.as_str()) {
                let module_name = spec.split('.').next().unwrap_or("");
                if !module_names.contains(&module_name.to_string()) {
                    result.add_error(format!("{}.{}: module '{}' not found", prefix, field, module_name));
                }
            } else {
                result.add_error(format!("{}: missing '{}'", prefix, field));
            }
        }

        // Type-specific validation
        match btype {
            "snapshot" => {
                let size = bridge.get("data_size").and_then(|v| v.as_u64()).unwrap_or(0);
                if size == 0 || size > 56 {
                    result.add_error(format!("{}: data_size must be 1-56 (got {})", prefix, size));
                }
            }
            "ring" => {
                let elem = bridge.get("elem_size").and_then(|v| v.as_u64()).unwrap_or(0);
                if elem == 0 || elem > 56 {
                    result.add_error(format!("{}: elem_size must be 1-56 (got {})", prefix, elem));
                }
            }
            "command" => {
                let size = bridge.get("data_size").and_then(|v| v.as_u64()).unwrap_or(0);
                if size == 0 || size > 56 {
                    result.add_error(format!("{}: data_size must be 1-56 (got {})", prefix, size));
                }
            }
            _ => {} // already flagged as invalid type
        }

        // Direction validation: command bridges are thread→ISR only
        if btype == "command" {
            // from should be Tier 0 (cooperative), to should be Tier 1/2 (ISR)
            // For now, just validate the declaration exists — tier assignment is Epic 7b/c
        }
    }

    if bridges.len() > 16 {
        result.add_error(format!("bridges: too many bridges ({}, max 16)", bridges.len()));
    }
}

/// Validate ISR module declarations.
///
/// Checks that modules declaring `tier: "1b"` or `tier: "2"` have:
/// - A valid `trust` level ("platform" required for ISR execution)
/// - A `max_cycles` budget that fits within the declared `rate_hz` period
/// - Combined Tier 1b + Tier 2 ISR budget does not exceed configurable limit
fn validate_isr_modules(modules: &[Value], _target: &TargetDescriptor, result: &mut ValidationResult) {
    // Default to 150MHz (RP2350). Config can override via execution.clock_hz.
    let clock_hz: u64 = 150_000_000;

    let mut total_tier1b_budget: u64 = 0;
    let mut tier1b_period_us: u64 = 0;
    let mut isr_module_count: usize = 0;

    for (i, module) in modules.iter().enumerate() {
        let tier = module.get("tier").and_then(|t| t.as_str()).unwrap_or("0");
        if tier != "1b" && tier != "2" {
            continue;
        }

        isr_module_count += 1;
        let prefix = format!("modules[{}]", i);
        let name = module.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");

        // Trust level validation
        let trust = module.get("trust").and_then(|t| t.as_str()).unwrap_or("");
        if trust != "platform" {
            result.add_error(format!(
                "{} ({}): ISR tier '{}' requires trust: \"platform\" (got '{}')",
                prefix, name, tier, trust
            ));
        }

        // Cycle budget validation
        let max_cycles = module.get("max_cycles").and_then(|c| c.as_u64()).unwrap_or(0);
        if max_cycles == 0 {
            result.add_error(format!(
                "{} ({}): ISR tier '{}' requires max_cycles declaration",
                prefix, name, tier
            ));
            continue;
        }

        if tier == "1b" {
            let rate_hz = module.get("rate_hz").and_then(|r| r.as_u64()).unwrap_or(0);
            if rate_hz > 0 {
                let period_cycles = clock_hz / rate_hz;
                if max_cycles > period_cycles {
                    result.add_error(format!(
                        "{} ({}): max_cycles ({}) exceeds period ({} cycles at {} Hz)",
                        prefix, name, max_cycles, period_cycles, rate_hz
                    ));
                }
                // Track period for combined budget check (all Tier 1b share the same timer)
                let this_period_us = 1_000_000 / rate_hz;
                if tier1b_period_us == 0 {
                    tier1b_period_us = this_period_us;
                } else if this_period_us != tier1b_period_us {
                    result.add_warning(format!(
                        "{} ({}): Tier 1b rate_hz ({}) implies different period than other Tier 1b modules",
                        prefix, name, rate_hz
                    ));
                }
            }
            total_tier1b_budget += max_cycles;

            // FPU usage warning
            if module.get("uses_fpu").and_then(|f| f.as_bool()).unwrap_or(false) {
                result.add_warning(format!(
                    "{} ({}): FPU in Tier 1b ISR adds 33 cycle lazy stacking overhead on Cortex-M33",
                    prefix, name
                ));
            }
        }

        if tier == "2" {
            let irq = module.get("irq").and_then(|i| i.as_u64());
            if irq.is_none() {
                result.add_error(format!(
                    "{} ({}): Tier 2 module requires 'irq' field",
                    prefix, name
                ));
            }
        }
    }

    // Combined budget check: Tier 1b budget should be < 50% of period
    if tier1b_period_us > 0 && total_tier1b_budget > 0 {
        let period_cycles = (tier1b_period_us * clock_hz) / 1_000_000;
        let max_budget = period_cycles / 2; // 50% limit
        if total_tier1b_budget > max_budget {
            result.add_error(format!(
                "ISR budget: combined Tier 1b budget ({} cycles) exceeds 50% of period ({} cycles)",
                total_tier1b_budget, period_cycles
            ));
        }
    }

    // Slot count check
    if isr_module_count > 8 {
        result.add_error(format!(
            "ISR modules: too many ({}, max 4 Tier 1b + 4 Tier 2)",
            isr_module_count
        ));
    }
}

/// Validate reconfigure section parameters.
fn validate_reconfigure_section(
    reconfig: &Value,
    config: &Value,
    result: &mut ValidationResult,
) {
    // Validate mode
    if let Some(mode) = reconfig.get("mode").and_then(|m| m.as_str()) {
        match mode {
            "live" | "atomic" => {}
            _ => result.add_error(format!(
                "reconfigure.mode: invalid value '{}' (must be 'live' or 'atomic')", mode
            )),
        }
    }

    // Validate drain_timeout_ms range
    let global_timeout = reconfig.get("drain_timeout_ms")
        .or_else(|| reconfig.get("drain_timeout"))
        .and_then(|t| t.as_u64());

    if let Some(timeout) = global_timeout {
        if timeout < 100 {
            result.add_error(format!(
                "reconfigure.drain_timeout_ms: {} too low (minimum 100ms)", timeout
            ));
        }
        if timeout > 30000 {
            result.add_error(format!(
                "reconfigure.drain_timeout_ms: {} too high (maximum 30000ms)", timeout
            ));
        }
    }

    // Validate per-module drain settings
    let is_live = reconfig.get("mode").and_then(|m| m.as_str()) == Some("live");

    if let Some(modules) = config.get("modules").and_then(|m| m.as_array()) {
        for module in modules {
            if let Some(drain) = module.get("drain") {
                let module_name = module.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");

                // Validate per-module drain timeout <= global
                if let Some(per_timeout) = drain.get("timeout").and_then(|t| t.as_u64()) {
                    if let Some(global) = global_timeout {
                        if per_timeout > global {
                            result.add_error(format!(
                                "module '{}' drain.timeout ({}) exceeds global drain_timeout_ms ({})",
                                module_name, per_timeout, global
                            ));
                        }
                    }
                }

                // Validate policy value
                if let Some(policy) = drain.get("policy").and_then(|p| p.as_str()) {
                    match policy {
                        "graceful" | "immediate" => {}
                        _ => result.add_error(format!(
                            "module '{}' drain.policy: invalid value '{}' (must be 'graceful' or 'immediate')",
                            module_name, policy
                        )),
                    }
                }
            }
        }
    }

    // Warning: live mode with no drain-capable modules has no benefit
    if is_live {
        // This is a warning, not an error — the config is valid but pointless
        result.add_warning(
            "reconfigure.mode=live: ensure at least one module exports module_drain, \
             otherwise live mode provides no benefit over atomic".to_string()
        );
    }
}

/// Validate hardware section
fn validate_hardware_section(
    hardware: &Value,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
    used_pins: &mut HashSet<u8>,
) -> Result<()> {
    // Validate SPI configs
    if let Some(spi_configs) = hardware.get("spi").and_then(|s| s.as_array()) {
        for (i, spi) in spi_configs.iter().enumerate() {
            let bus = spi["bus"].as_u64().unwrap_or(0) as u8;
            let miso = spi["miso"].as_u64().unwrap_or(16) as u8;
            let mosi = spi["mosi"].as_u64().unwrap_or(19) as u8;
            let sck = spi["sck"].as_u64().unwrap_or(18) as u8;

            // Check bus exists on target
            if bus >= target.spi_count {
                result.add_error(format!(
                    "hardware.spi[{}]: SPI{} does not exist on {} (has {} SPI buses)",
                    i, bus, target.id, target.spi_count
                ));
                continue;
            }

            // Check pin range, reserved, conflicts
            for &pin in &[miso, mosi, sck] {
                check_pin_range(pin, &format!("hardware.spi[{}]", i), target, result);
                check_reserved_pin(pin, &format!("hardware.spi[{}]", i), target, result);
                check_pin_conflict(pin, &format!("hardware.spi[{}]", i), used_pins, result);
            }

            // Check valid SPI pin combination
            if !target.is_valid_spi_pins(bus, miso, mosi, sck) {
                result.add_error(format!(
                    "hardware.spi[{}]: Invalid SPI{} pin combination (miso={}, mosi={}, sck={}) for {}",
                    i, bus, miso, mosi, sck, target.id
                ));
            }
        }
    }

    // Validate I2C configs
    if let Some(i2c_configs) = hardware.get("i2c").and_then(|s| s.as_array()) {
        for (i, i2c) in i2c_configs.iter().enumerate() {
            let bus = i2c["bus"].as_u64().unwrap_or(0) as u8;
            let sda = i2c["sda"].as_u64().unwrap_or(4) as u8;
            let scl = i2c["scl"].as_u64().unwrap_or(5) as u8;

            // Check bus exists on target
            if bus >= target.i2c_count {
                result.add_error(format!(
                    "hardware.i2c[{}]: I2C{} does not exist on {} (has {} I2C buses)",
                    i, bus, target.id, target.i2c_count
                ));
                continue;
            }

            // Check pin range, reserved, conflicts
            for &pin in &[sda, scl] {
                check_pin_range(pin, &format!("hardware.i2c[{}]", i), target, result);
                check_reserved_pin(pin, &format!("hardware.i2c[{}]", i), target, result);
                check_pin_conflict(pin, &format!("hardware.i2c[{}]", i), used_pins, result);
            }

            // Check valid I2C pin combination
            if !target.is_valid_i2c_pins(bus, sda, scl) {
                result.add_error(format!(
                    "hardware.i2c[{}]: Invalid I2C{} pin combination (sda={}, scl={}) for {}",
                    i, bus, sda, scl, target.id
                ));
            }
        }
    }

    // Validate GPIO configs
    if let Some(gpio_configs) = hardware.get("gpio").and_then(|s| s.as_array()) {
        for (i, gpio) in gpio_configs.iter().enumerate() {
            let pin = gpio["pin"].as_u64().unwrap_or(0) as u8;
            check_pin_range(pin, &format!("hardware.gpio[{}]", i), target, result);
            check_reserved_pin(pin, &format!("hardware.gpio[{}]", i), target, result);
            check_pin_conflict(pin, &format!("hardware.gpio[{}]", i), used_pins, result);
        }
    }

    // Validate PIO configs
    if let Some(pio_configs) = hardware.get("pio").and_then(|s| s.as_array()) {
        for (i, pio) in pio_configs.iter().enumerate() {
            if let Some(idx) = pio["pio_idx"].as_u64() {
                if idx as u8 >= target.pio_count {
                    result.add_error(format!(
                        "hardware.pio[{}]: PIO{} does not exist on {} (has {} PIO blocks)",
                        i, idx, target.id, target.pio_count
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Check if a pin is within the target's GPIO range.
fn check_pin_range(
    pin: u8,
    context: &str,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
) {
    if pin > target.max_pin {
        result.add_error(format!(
            "{}: Pin {} out of range (max {} for {})",
            context, pin, target.max_pin, target.id
        ));
    }
}

/// Check if a pin is reserved on the target board.
fn check_reserved_pin(
    pin: u8,
    context: &str,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
) {
    if let Some(reason) = target.is_reserved_pin(pin) {
        result.add_warning(format!(
            "{}: Pin {} is reserved on {} ({})",
            context,
            pin,
            target.board_description.as_deref().unwrap_or(&target.description),
            reason
        ));
    }
}

/// Check for pin conflicts (same pin used twice).
fn check_pin_conflict(
    pin: u8,
    context: &str,
    used_pins: &mut HashSet<u8>,
    result: &mut ValidationResult,
) {
    if !used_pins.insert(pin) {
        result.add_error(format!(
            "{}: Pin {} is already used by another peripheral",
            context, pin
        ));
    }
}

/// Validate pins used by sources
fn validate_source_pins(
    src: &Value,
    index: usize,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
    used_pins: &mut HashSet<u8>,
) {
    let type_name = src["type"].as_str().unwrap_or("");

    match type_name.to_lowercase().as_str() {
        "gpioinput" | "gpio_input" => {
            if let Some(pin) = src["pin"].as_u64() {
                let pin = pin as u8;
                check_pin_range(pin, &format!("sources[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sources[{}]", index), target, result);
                check_pin_conflict(pin, &format!("sources[{}].pin", index), used_pins, result);
            }
        }
        "spiread" | "spi_read" => {
            if let Some(cs_pin) = src["cs_pin"].as_u64() {
                let pin = cs_pin as u8;
                check_pin_range(pin, &format!("sources[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sources[{}]", index), target, result);
                check_pin_conflict(
                    pin,
                    &format!("sources[{}].cs_pin", index),
                    used_pins,
                    result,
                );
            }
        }
        _ => {}
    }
}

/// Validate pins used by sinks
fn validate_sink_pins(
    sink: &Value,
    index: usize,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
    used_pins: &mut HashSet<u8>,
) {
    let type_name = sink["type"].as_str().unwrap_or("");

    match type_name.to_lowercase().as_str() {
        "gpiooutput" | "gpio_output" | "gpio" => {
            if let Some(pin) = sink["pin"].as_u64() {
                let pin = pin as u8;
                check_pin_range(pin, &format!("sinks[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sinks[{}]", index), target, result);
                check_pin_conflict(pin, &format!("sinks[{}].pin", index), used_pins, result);
            }
        }
        "i2soutput" | "i2s_output" | "i2s" => {
            if let Some(data_pin) = sink["data_pin"].as_u64() {
                let pin = data_pin as u8;
                check_pin_range(pin, &format!("sinks[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sinks[{}]", index), target, result);
                check_pin_conflict(
                    pin,
                    &format!("sinks[{}].data_pin", index),
                    used_pins,
                    result,
                );
            }
            if let Some(clock_base) = sink["clock_pin_base"].as_u64() {
                let pin = clock_base as u8;
                check_pin_range(pin, &format!("sinks[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sinks[{}]", index), target, result);
                check_pin_conflict(
                    pin,
                    &format!("sinks[{}].clock_pin_base", index),
                    used_pins,
                    result,
                );
                let pin2 = pin + 1;
                check_pin_range(pin2, &format!("sinks[{}]", index), target, result);
                check_reserved_pin(pin2, &format!("sinks[{}]", index), target, result);
                check_pin_conflict(
                    pin2,
                    &format!("sinks[{}].clock_pin_base+1", index),
                    used_pins,
                    result,
                );
            }
        }
        "spiwrite" | "spi_write" => {
            if let Some(cs_pin) = sink["cs_pin"].as_u64() {
                let pin = cs_pin as u8;
                check_pin_range(pin, &format!("sinks[{}]", index), target, result);
                check_reserved_pin(pin, &format!("sinks[{}]", index), target, result);
                check_pin_conflict(
                    pin,
                    &format!("sinks[{}].cs_pin", index),
                    used_pins,
                    result,
                );
            }
        }
        _ => {}
    }
}

/// Validate isolation settings against target capabilities.
///
/// Checks that `protection: isolated` is only set on targets that have
/// an MPU (RP2350, 8 regions) or MMU (BCM2712). RP2040 (Cortex-M0+) has
/// no MPU and cannot support hardware isolation.
fn validate_isolation(
    config: &Value,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
) {
    // Check for protection setting in config (can be at top level or in graph)
    let protection = config
        .get("protection")
        .or_else(|| config.get("graph").and_then(|g| g.get("protection")))
        .and_then(|v| v.as_str());

    if let Some(mode) = protection {
        if mode == "isolated" {
            let has_isolation = target.mpu_regions >= 8 || target.has_mmu;
            if !has_isolation {
                result.add_error(format!(
                    "protection: isolated requires MPU or MMU, but target '{}' has \
                     {} MPU regions and has_mmu={}. RP2040 (Cortex-M0+) does not \
                     support hardware isolation.",
                    target.id, target.mpu_regions, target.has_mmu,
                ));
            }
        }
    }

    // Per-module `trust_tier` and `protection` cross-checks.
    //   trust_tier: platform | verified | community | unsigned
    //   protection: none     | guarded  | isolated
    // When `protection` is omitted it defaults from the tier:
    //   platform -> none,  verified -> guarded,  community/unsigned -> isolated.
    let valid_tiers = ["platform", "verified", "community", "unsigned"];
    let valid_prot = ["none", "guarded", "isolated"];
    if let Some(modules) = config.get("modules").and_then(|m| m.as_array()) {
        let has_isolation = target.mpu_regions >= 8 || target.has_mmu;
        for (i, m) in modules.iter().enumerate() {
            if let Some(t) = m.get("trust_tier").and_then(|v| v.as_str()) {
                if !valid_tiers.contains(&t) {
                    result.add_error(format!(
                        "modules[{i}]: invalid trust_tier '{t}' (expected one of {valid_tiers:?})",
                    ));
                }
            }
            if let Some(p) = m.get("protection").and_then(|v| v.as_str()) {
                if !valid_prot.contains(&p) {
                    result.add_error(format!(
                        "modules[{i}]: invalid protection '{p}' (expected one of {valid_prot:?})",
                    ));
                } else if p == "isolated" && !has_isolation {
                    result.add_error(format!(
                        "modules[{i}]: protection: isolated requires MPU or MMU, target '{}' lacks both",
                        target.id,
                    ));
                }
            }
            // A community/unsigned tier without an explicit protection override
            // implies isolation — catch targets that can't provide it.
            let tier = m.get("trust_tier").and_then(|v| v.as_str()).unwrap_or("platform");
            let explicit_prot = m.get("protection").and_then(|v| v.as_str());
            if explicit_prot.is_none()
                && (tier == "community" || tier == "unsigned")
                && !has_isolation
            {
                result.add_error(format!(
                    "modules[{i}]: trust_tier '{tier}' implies protection: isolated, \
                     but target '{}' has no MPU/MMU. Either set protection explicitly \
                     or deploy to a target with isolation.",
                    target.id,
                ));
            }
        }
    }
}

/// Validate paged_arena settings against target capabilities.
///
/// Checks that paged_arena is only used on targets with MMU support (BCM2712).
/// Validates resident_max_mb sum fits within reasonable pool limits.
fn validate_paged_arenas(
    config: &Value,
    target: &TargetDescriptor,
    result: &mut ValidationResult,
) {
    let modules = match config.get("modules").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return,
    };

    let mut total_resident_mb: u64 = 0;
    let mut has_paged_arena = false;

    for (i, module) in modules.iter().enumerate() {
        let pa = match module.get("paged_arena") {
            Some(pa) => pa,
            None => continue,
        };
        has_paged_arena = true;

        let name = module.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
        let prefix = format!("modules[{}] ({})", i, name);

        // Validate virtual_size_mb
        let virtual_mb = pa.get("virtual_size_mb").and_then(|v| v.as_u64()).unwrap_or(0);
        if virtual_mb == 0 {
            result.add_error(format!(
                "{}: paged_arena.virtual_size_mb must be > 0", prefix
            ));
        }
        if virtual_mb > 4096 {
            result.add_error(format!(
                "{}: paged_arena.virtual_size_mb {} exceeds 4GB limit", prefix, virtual_mb
            ));
        }

        // Validate resident_max_mb
        let resident_mb = pa.get("resident_max_mb").and_then(|v| v.as_u64()).unwrap_or(1);
        if resident_mb > virtual_mb {
            result.add_warning(format!(
                "{}: paged_arena.resident_max_mb ({}) > virtual_size_mb ({}), clamped",
                prefix, resident_mb, virtual_mb
            ));
        }
        total_resident_mb += resident_mb;

        // Validate backing type
        let backing = pa.get("backing").and_then(|v| v.as_str()).unwrap_or("ramdisk");
        match backing {
            "ramdisk" | "nvme" => {}
            _ => {
                result.add_error(format!(
                    "{}: paged_arena.backing '{}' must be 'ramdisk' or 'nvme'",
                    prefix, backing
                ));
            }
        }

        // Validate writeback policy
        let writeback = pa.get("writeback").and_then(|v| v.as_str()).unwrap_or("deferred");
        match writeback {
            "deferred" | "write_through" => {}
            _ => {
                result.add_error(format!(
                    "{}: paged_arena.writeback '{}' must be 'deferred' or 'write_through'",
                    prefix, writeback
                ));
            }
        }
    }

    // Check target has MMU
    if has_paged_arena && !target.has_mmu {
        result.add_error(format!(
            "paged_arena requires MMU support (target '{}' has_mmu=false). \
             Only BCM2712/CM5 targets support demand paging.",
            target.id
        ));
    }

    // Check total resident fits in reasonable pool (256 pages = 1MB for RAM-disk testing)
    if total_resident_mb > 1 {
        result.add_warning(format!(
            "Total paged_arena resident_max across all modules is {}MB. \
             Ensure pool is sized accordingly (default 1MB for testing).",
            total_resident_mb
        ));
    }
}
