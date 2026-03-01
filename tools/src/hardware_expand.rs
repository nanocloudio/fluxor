//! Hardware section expansion — maps hardware declarations to module + wiring templates.
//!
//! Phase 3 of the capability surface architecture (docs/architecture/capability_surface.md).
//! Currently supports: hardware.network
//!
//! The expansion is a YAML-to-YAML pre-processing step: it mutates the parsed config Value
//! to inject module entries and wiring edges before the normal config pipeline runs.
//! Zero changes to binary format, kernel, or module code.

use serde_json::{json, Value};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

struct TemplateModule {
    name: &'static str,
    /// Keys to copy from the hardware subsection into the module's param object.
    param_keys: &'static [&'static str],
}

struct TemplateEdge {
    from: &'static str,
    to: &'static str,
}

struct NetworkTemplate {
    modules: Vec<TemplateModule>,
    wiring: Vec<TemplateEdge>,
}

fn wifi_cyw43_template() -> NetworkTemplate {
    NetworkTemplate {
        modules: vec![
            TemplateModule { name: "cyw43", param_keys: &[] },
            TemplateModule {
                name: "wifi",
                param_keys: &["ssid", "password", "security"],
            },
            TemplateModule { name: "ip", param_keys: &["use_dhcp"] },
        ],
        wiring: vec![
            TemplateEdge { from: "wifi.wifi_ctrl", to: "cyw43.wifi_ctrl" },
            TemplateEdge { from: "cyw43.status", to: "wifi.status" },
            TemplateEdge { from: "cyw43.frames_rx", to: "ip.frames_rx" },
            TemplateEdge { from: "ip.frames_tx", to: "cyw43.frames_tx" },
        ],
    }
}

fn ethernet_enc28j60_template() -> NetworkTemplate {
    NetworkTemplate {
        modules: vec![
            TemplateModule {
                name: "enc28j60",
                param_keys: &["spi_bus", "cs_pin", "int_pin"],
            },
            TemplateModule { name: "ip", param_keys: &["use_dhcp"] },
        ],
        wiring: vec![
            TemplateEdge { from: "enc28j60.frames_rx", to: "ip.frames_rx" },
            TemplateEdge { from: "ip.frames_tx", to: "enc28j60.frames_tx" },
        ],
    }
}

fn ethernet_ch9120_template() -> NetworkTemplate {
    NetworkTemplate {
        modules: vec![TemplateModule {
            name: "ch9120",
            param_keys: &["ip", "gateway", "mode", "baud"],
        }],
        wiring: vec![],
    }
}

fn lookup_network_template(net_type: &str, driver: &str) -> Result<NetworkTemplate> {
    match (net_type, driver) {
        ("wifi", "cyw43") => Ok(wifi_cyw43_template()),
        ("ethernet", "enc28j60") => Ok(ethernet_enc28j60_template()),
        ("ethernet", "ch9120") => Ok(ethernet_ch9120_template()),
        _ => Err(Error::Config(format!(
            "hardware.network: unsupported combination (type: '{}', driver: '{}'). \
             Supported: (wifi, cyw43), (ethernet, enc28j60), (ethernet, ch9120)",
            net_type, driver
        ))),
    }
}

// ---------------------------------------------------------------------------
// Expansion logic
// ---------------------------------------------------------------------------

/// Expand `hardware.network` (and future subsections) into module + wiring entries.
///
/// Mutates `config["modules"]` and `config["wiring"]` in-place. Returns the list
/// of auto-added module names for diagnostic output.
///
/// Idempotent: if `hardware.network` is absent, does nothing.
/// Safe: if the user already declares a module, it is not added again.
pub fn expand_hardware_section(config: &mut Value) -> Result<Vec<String>> {
    let mut auto_added = Vec::new();

    // Check for hardware.network
    let network = match config.get("hardware").and_then(|h| h.get("network")) {
        Some(n) => n.clone(),
        None => return Ok(auto_added),
    };

    // Reject array form (future: multiple interfaces)
    if network.is_array() {
        return Err(Error::Config(
            "hardware.network: array form (multiple interfaces) is not yet supported. \
             Declare additional network modules in the modules: section."
                .into(),
        ));
    }

    let net_type = network["type"].as_str().ok_or_else(|| {
        Error::Config(
            "hardware.network: 'type' field is required (wifi or ethernet)".into(),
        )
    })?;
    let driver = network["driver"].as_str().ok_or_else(|| {
        Error::Config(
            "hardware.network: 'driver' field is required (cyw43, enc28j60, ch9120)".into(),
        )
    })?;

    let template = lookup_network_template(net_type, driver)?;

    // --- Collect existing module names ---
    let existing_names = collect_module_names(config);

    // --- Ensure config["modules"] and config["wiring"] exist as arrays ---
    if config.get("modules").is_none() {
        config["modules"] = json!([]);
    }
    if config.get("wiring").is_none() {
        config["wiring"] = json!([]);
    }

    // --- Inject modules (prepend, so auto-added get lower IDs) ---
    // Build entries in reverse order so prepending produces correct order.
    let mut to_prepend = Vec::new();
    for tm in &template.modules {
        if existing_names.contains(tm.name) {
            continue;
        }

        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), json!(tm.name));

        // Copy param keys from hardware.network into the module entry
        for &key in tm.param_keys {
            if let Some(val) = network.get(key) {
                entry.insert(key.into(), val.clone());
            }
        }

        to_prepend.push(Value::Object(entry));
        auto_added.push(tm.name.to_string());
    }

    if let Some(modules_arr) = config["modules"].as_array_mut() {
        // Prepend: insert at position 0 in order
        for (i, entry) in to_prepend.into_iter().enumerate() {
            modules_arr.insert(i, entry);
        }
    }

    // --- Inject wiring edges (prepend) ---
    let mut wiring_to_prepend = Vec::new();
    for te in &template.wiring {
        let edge = json!({
            "from": te.from,
            "to": te.to,
        });
        wiring_to_prepend.push(edge);
    }

    if let Some(wiring_arr) = config["wiring"].as_array_mut() {
        for (i, edge) in wiring_to_prepend.into_iter().enumerate() {
            wiring_arr.insert(i, edge);
        }
    }

    Ok(auto_added)
}

/// Collect all module names from config["modules"] (handles both array and map formats).
fn collect_module_names(config: &Value) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();

    if let Some(arr) = config["modules"].as_array() {
        for entry in arr {
            if let Some(name) = entry.as_str() {
                names.insert(name.to_string());
            } else if let Some(name) = entry["name"].as_str() {
                names.insert(name.to_string());
            }
        }
    } else if let Some(map) = config["modules"].as_object() {
        for key in map.keys() {
            names.insert(key.clone());
        }
    }

    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_no_hardware_section() {
        let mut config = json!({
            "modules": [{"name": "http_server"}],
            "wiring": []
        });
        let result = expand_hardware_section(&mut config).unwrap();
        assert!(result.is_empty());
        // Modules unchanged
        assert_eq!(config["modules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_wifi_cyw43_expansion() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "wifi",
                    "driver": "cyw43",
                    "ssid": "TestNet",
                    "password": "secret",
                    "security": "wpa3"
                }
            },
            "modules": [{"name": "http_server", "port": 80}],
            "wiring": [{"from": "fat32.out", "to": "http_server.in"}]
        });

        let added = expand_hardware_section(&mut config).unwrap();
        assert_eq!(added, vec!["cyw43", "wifi", "ip"]);

        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 4); // 3 auto + 1 user
        assert_eq!(modules[0]["name"], "cyw43");
        assert_eq!(modules[1]["name"], "wifi");
        assert_eq!(modules[1]["ssid"], "TestNet");
        assert_eq!(modules[1]["password"], "secret");
        assert_eq!(modules[1]["security"], "wpa3");
        assert_eq!(modules[2]["name"], "ip");
        assert_eq!(modules[3]["name"], "http_server");

        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 5); // 4 auto + 1 user
        assert_eq!(wiring[0]["from"], "wifi.wifi_ctrl");
        assert_eq!(wiring[0]["to"], "cyw43.wifi_ctrl");
    }

    #[test]
    fn test_dedup_existing_modules() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "wifi",
                    "driver": "cyw43",
                    "ssid": "TestNet",
                    "password": "secret"
                }
            },
            "modules": [
                {"name": "cyw43"},
                {"name": "http_server"}
            ],
            "wiring": []
        });

        let added = expand_hardware_section(&mut config).unwrap();
        // cyw43 already exists, only wifi and ip added
        assert_eq!(added, vec!["wifi", "ip"]);

        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 4); // wifi + ip prepended, cyw43 + http_server kept
        assert_eq!(modules[0]["name"], "wifi");
        assert_eq!(modules[1]["name"], "ip");
        assert_eq!(modules[2]["name"], "cyw43");

        // Wiring still added (references existing cyw43)
        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 4);
    }

    #[test]
    fn test_ethernet_enc28j60() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "ethernet",
                    "driver": "enc28j60",
                    "spi_bus": 1,
                    "cs_pin": 9
                }
            },
            "modules": [],
            "wiring": []
        });

        let added = expand_hardware_section(&mut config).unwrap();
        assert_eq!(added, vec!["enc28j60", "ip"]);

        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules[0]["name"], "enc28j60");
        assert_eq!(modules[0]["spi_bus"], 1);
        assert_eq!(modules[0]["cs_pin"], 9);

        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 2);
    }

    #[test]
    fn test_ethernet_ch9120() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "ethernet",
                    "driver": "ch9120",
                    "ip": "192.168.1.42",
                    "gateway": "192.168.1.1"
                }
            },
            "modules": [],
            "wiring": []
        });

        let added = expand_hardware_section(&mut config).unwrap();
        assert_eq!(added, vec!["ch9120"]);

        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules[0]["name"], "ch9120");
        assert_eq!(modules[0]["ip"], "192.168.1.42");
        assert_eq!(modules[0]["gateway"], "192.168.1.1");

        // No wiring (ch9120 provides sockets directly)
        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 0);
    }

    #[test]
    fn test_unknown_driver_error() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "wifi",
                    "driver": "esp32"
                }
            }
        });
        let err = expand_hardware_section(&mut config).unwrap_err();
        assert!(err.to_string().contains("unsupported combination"));
    }

    #[test]
    fn test_missing_type_error() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "driver": "cyw43"
                }
            }
        });
        let err = expand_hardware_section(&mut config).unwrap_err();
        assert!(err.to_string().contains("'type' field is required"));
    }

    #[test]
    fn test_array_form_rejected() {
        let mut config = json!({
            "hardware": {
                "network": [
                    {"type": "wifi", "driver": "cyw43"},
                    {"type": "ethernet", "driver": "enc28j60"}
                ]
            }
        });
        let err = expand_hardware_section(&mut config).unwrap_err();
        assert!(err.to_string().contains("not yet supported"));
    }

    #[test]
    fn test_no_modules_section_created() {
        let mut config = json!({
            "hardware": {
                "network": {
                    "type": "wifi",
                    "driver": "cyw43",
                    "ssid": "test",
                    "password": "test"
                }
            }
        });
        // No modules or wiring key at all
        let added = expand_hardware_section(&mut config).unwrap();
        assert_eq!(added.len(), 3);
        assert!(config["modules"].is_array());
        assert!(config["wiring"].is_array());
    }
}
