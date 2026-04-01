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

    Ok(result)
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
