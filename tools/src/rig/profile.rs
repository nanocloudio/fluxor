//! Private rig profile — `~/.config/fluxor/labs/<lab>/rigs/<rig>.toml`.
//!
//! RFC §9. Site-specific binding between the public contract (capabilities
//! declared on a board) and one physical bench (which TTY, which smart
//! plug, which TFTP root). Never checked in.
//!
//! The loader eagerly resolves every string field through [`secret::resolve`]
//! so `${env:…}` and `${file:…}` indirections are bound before a plan or
//! run is constructed. Unresolved references are fatal at load time —
//! matching the "unresolved references are fatal" invariant in §9.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::rig::secret::{resolve, Secret};
use crate::rig::vocab::{Capability, Surface};

/// Parsed, fully-resolved private profile.
#[derive(Debug, Clone)]
pub struct RigProfile {
    pub path: PathBuf,
    pub rig: RigMeta,
    pub power: Option<BindingTable>,
    pub deploy: BTreeMap<Capability, BindingTable>,
    pub console: BTreeMap<Capability, BindingTable>,
    pub telemetry: BTreeMap<Capability, BindingTable>,
    pub observe: BTreeMap<Capability, BindingTable>,
    pub secrets: BindingTable,
}

#[derive(Debug, Clone)]
pub struct RigMeta {
    pub id: String,
    pub board: String,
    pub tags: Vec<String>,
}

/// A flat table of adapter-specific fields. Keys are TOML field names; values
/// are either scalars or secrets. Adapters fish out the fields they need at
/// initialisation time and report missing/invalid fields themselves.
#[derive(Debug, Clone, Default)]
pub struct BindingTable {
    fields: BTreeMap<String, BindingValue>,
}

#[derive(Debug, Clone)]
pub enum BindingValue {
    Secret(Secret),
    Int(i64),
    Bool(bool),
}

impl BindingTable {
    pub fn get(&self, key: &str) -> Option<&BindingValue> {
        self.fields.get(key)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &BindingValue)> {
        self.fields.iter()
    }
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Borrow the resolved real value of a string field. Returns an error
    /// if the key is missing or isn't a string.
    pub fn require_string(&self, key: &str, section: &str) -> Result<&str> {
        match self.fields.get(key) {
            Some(BindingValue::Secret(s)) => Ok(s.expose()),
            Some(other) => Err(Error::Config(format!(
                "profile: [{section}].{key} expected string, got {other:?}"
            ))),
            None => Err(Error::Config(format!(
                "profile: [{section}].{key} is required"
            ))),
        }
    }

    pub fn optional_string(&self, key: &str) -> Option<&str> {
        match self.fields.get(key) {
            Some(BindingValue::Secret(s)) => Some(s.expose()),
            _ => None,
        }
    }

    pub fn require_int(&self, key: &str, section: &str) -> Result<i64> {
        match self.fields.get(key) {
            Some(BindingValue::Int(n)) => Ok(*n),
            Some(other) => Err(Error::Config(format!(
                "profile: [{section}].{key} expected integer, got {other:?}"
            ))),
            None => Err(Error::Config(format!(
                "profile: [{section}].{key} is required"
            ))),
        }
    }

    pub fn optional_int(&self, key: &str) -> Option<i64> {
        match self.fields.get(key) {
            Some(BindingValue::Int(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn optional_bool(&self, key: &str) -> Option<bool> {
        match self.fields.get(key) {
            Some(BindingValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

// ── TOML deserialization ────────────────────────────────────────────────────
//
// The profile has a mostly-fixed top-level shape (rig/secrets) plus four
// surface maps whose keys are capability names. We deserialise into
// `toml::Value` at the section level, then walk it to resolve secrets and
// enforce the capability vocabulary.

#[derive(Deserialize)]
struct ProfileFile {
    rig: RigMetaToml,
    power: Option<toml::Table>,
    #[serde(default)]
    deploy: toml::Table,
    #[serde(default)]
    console: toml::Table,
    #[serde(default)]
    telemetry: toml::Table,
    #[serde(default)]
    observe: toml::Table,
    #[serde(default)]
    secrets: toml::Table,
}

#[derive(Deserialize)]
struct RigMetaToml {
    id: String,
    board: String,
    #[serde(default)]
    tags: Vec<String>,
}

pub fn load_profile(path: &Path) -> Result<RigProfile> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("rig: reading profile {}: {}", path.display(), e))
    })?;
    parse_profile_str(&raw, path)
}

pub fn parse_profile_str(raw: &str, path: &Path) -> Result<RigProfile> {
    let ctx = path.display().to_string();
    let f: ProfileFile = toml::from_str(raw)?;

    let rig = RigMeta {
        id: f.rig.id,
        board: f.rig.board,
        tags: f.rig.tags,
    };

    let power = f
        .power
        .map(|t| load_binding(t, &format!("{ctx} [power]")))
        .transpose()?;

    let deploy = load_surface_map(f.deploy, Surface::Deploy, &ctx)?;
    let console = load_surface_map(f.console, Surface::Console, &ctx)?;
    let telemetry = load_surface_map(f.telemetry, Surface::Telemetry, &ctx)?;
    let observe = load_surface_map(f.observe, Surface::Observe, &ctx)?;
    let secrets = load_binding(f.secrets, &format!("{ctx} [secrets]"))?;

    Ok(RigProfile {
        path: path.to_path_buf(),
        rig,
        power,
        deploy,
        console,
        telemetry,
        observe,
        secrets,
    })
}

/// Turn a surface-keyed table (`[deploy.netboot_tftp]`, `[deploy.uf2_mount]`,
/// …) into a map keyed by `Capability`. Keys are validated against the
/// vocabulary and against the surface they're nested under.
fn load_surface_map(
    table: toml::Table,
    expected: Surface,
    ctx: &str,
) -> Result<BTreeMap<Capability, BindingTable>> {
    let mut out = BTreeMap::new();
    for (key, value) in table {
        let qualified = format!("{}.{key}", expected.as_str());
        let cap = Capability::parse(&qualified).map_err(|e| {
            Error::Config(format!(
                "{ctx} [{}.{key}]: {e}",
                expected.as_str()
            ))
        })?;
        let inner = match value {
            toml::Value::Table(t) => t,
            other => {
                return Err(Error::Config(format!(
                    "{ctx} [{qualified}]: expected a table, got {}",
                    type_of(&other)
                )))
            }
        };
        let binding = load_binding(inner, &format!("{ctx} [{qualified}]"))?;
        out.insert(cap, binding);
    }
    Ok(out)
}

fn load_binding(table: toml::Table, ctx: &str) -> Result<BindingTable> {
    let mut fields = BTreeMap::new();
    for (key, value) in table {
        let field_ctx = format!("{ctx}.{key}");
        let v = match value {
            toml::Value::String(s) => BindingValue::Secret(resolve(&s, &field_ctx)?),
            toml::Value::Integer(n) => BindingValue::Int(n),
            toml::Value::Boolean(b) => BindingValue::Bool(b),
            toml::Value::Float(_)
            | toml::Value::Datetime(_)
            | toml::Value::Array(_)
            | toml::Value::Table(_) => {
                return Err(Error::Config(format!(
                    "{field_ctx}: unsupported value type {}; only string/int/bool allowed",
                    type_of(&value)
                )));
            }
        };
        fields.insert(key, v);
    }
    Ok(BindingTable { fields })
}

fn type_of(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

/// Compute the canonical directory a profile would live under, given the
/// active lab namespace and rig id. RFC §9.
pub fn default_profile_path(lab: &str, rig_id: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(
        home.join(".config")
            .join("fluxor")
            .join("labs")
            .join(lab)
            .join("rigs")
            .join(format!("{rig_id}.toml")),
    )
}

/// Walk a directory and return candidate rig ids — for "when exactly one rig
/// is configured, `--rig` is optional" per §10.2.
pub fn enumerate_rigs(lab: &str) -> Result<Vec<String>> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(Vec::new());
    };
    let dir = home
        .join(".config")
        .join("fluxor")
        .join("labs")
        .join(lab)
        .join("rigs");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "toml").unwrap_or(false) {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                ids.push(stem.to_string());
            }
        }
    }
    ids.sort();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"
        [rig]
        id = "pi5-a"
        board = "cm5"
        tags = ["nvme", "bench-a"]

        [power]
        backend = "uhubctl"
        location = "1-1"
        port = 4

        [deploy.netboot_tftp]
        root = "/srv/tftp/fluxor/pi5-a"
        interface = "enp2s0"
        journal_unit = "dnsmasq"

        [console.serial]
        device = "/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A10XYZ-if00-port0"
        baud = 115200

        [observe.netboot_fetch]
        match_serial = "4f3c2a11"

        [secrets]
        kasa_alias = "lamp-1"
    "#;

    #[test]
    fn parses_example_profile() {
        let p = parse_profile_str(PROFILE, Path::new("/tmp/pi5-a.toml")).unwrap();
        assert_eq!(p.rig.id, "pi5-a");
        assert_eq!(p.rig.board, "cm5");
        assert_eq!(p.rig.tags, vec!["nvme", "bench-a"]);

        let power = p.power.as_ref().unwrap();
        assert_eq!(power.require_string("backend", "power").unwrap(), "uhubctl");
        assert_eq!(power.require_int("port", "power").unwrap(), 4);

        let deploy_cap = Capability::parse("deploy.netboot_tftp").unwrap();
        let nbt = p.deploy.get(&deploy_cap).unwrap();
        assert_eq!(
            nbt.require_string("root", "deploy.netboot_tftp").unwrap(),
            "/srv/tftp/fluxor/pi5-a"
        );

        let console_cap = Capability::parse("console.serial").unwrap();
        let ser = p.console.get(&console_cap).unwrap();
        assert_eq!(ser.require_int("baud", "console.serial").unwrap(), 115200);

        assert!(p.secrets.contains_key("kasa_alias"));
    }

    #[test]
    fn rejects_unknown_capability_key() {
        let src = r#"
            [rig]
            id = "x"
            board = "cm5"

            [deploy.rocket_launcher]
            foo = "bar"
        "#;
        let err = parse_profile_str(src, Path::new("/tmp/x.toml")).unwrap_err();
        assert!(format!("{err}").contains("rocket_launcher"));
    }

    #[test]
    fn env_indirection_resolves_and_redacts() {
        std::env::set_var("FLUXOR_PROFILE_TEST", "topsecret");
        let src = r#"
            [rig]
            id = "x"
            board = "cm5"

            [power]
            backend = "kasa_local"
            password = "${env:FLUXOR_PROFILE_TEST}"
        "#;
        let p = parse_profile_str(src, Path::new("/tmp/x.toml")).unwrap();
        let power = p.power.unwrap();
        assert_eq!(
            power.require_string("password", "power").unwrap(),
            "topsecret"
        );
        // Display redacts.
        let dbg = format!("{:?}", power.get("password").unwrap());
        assert!(dbg.contains("***"), "{dbg}");
        assert!(!dbg.contains("topsecret"), "{dbg}");
        std::env::remove_var("FLUXOR_PROFILE_TEST");
    }

    #[test]
    fn missing_env_indirection_is_fatal_at_load() {
        std::env::remove_var("FLUXOR_PROFILE_MISSING");
        let src = r#"
            [rig]
            id = "x"
            board = "cm5"

            [secrets]
            v = "${env:FLUXOR_PROFILE_MISSING}"
        "#;
        assert!(parse_profile_str(src, Path::new("/tmp/x.toml")).is_err());
    }

    #[test]
    fn rejects_float_and_array_values() {
        let src = r#"
            [rig]
            id = "x"
            board = "cm5"

            [power]
            weight = 1.5
        "#;
        assert!(parse_profile_str(src, Path::new("/tmp/x.toml")).is_err());
    }
}
