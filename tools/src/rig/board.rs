//! Public board contract — the `[rig]` section of a board descriptor.
//!
//! RFC §7. Lives in `targets/boards/{id}.toml`. Every field is public
//! (board-level facts, never bench-level facts). The loader enforces that
//! capability-valued fields use the exact vocabulary from `rig::vocab` and
//! that `preferred_*` selections are members of the matching list.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::rig::vocab::{validate_artifact_class, Capability, Surface};

/// Parsed `[rig]` section from a board descriptor.
#[derive(Debug, Clone, Default)]
pub struct BoardRig {
    pub artifact: Option<String>,
    pub deploy: Vec<Capability>,
    pub preferred_deploy: Option<Capability>,
    pub console: Vec<Capability>,
    pub preferred_console: Option<Capability>,
    pub telemetry: Vec<Capability>,
    pub preferred_telemetry: Option<Capability>,
    pub observe: Vec<Capability>,
    pub power: Vec<Capability>,
    pub default_timeout_s: Option<u32>,
}

impl BoardRig {
    /// True if the board declares this capability under any relevant surface.
    pub fn supports(&self, cap: Capability) -> bool {
        let list = match cap.surface() {
            Surface::Deploy => &self.deploy,
            Surface::Console => &self.console,
            Surface::Telemetry => &self.telemetry,
            Surface::Observe => &self.observe,
            Surface::Power => &self.power,
            // Coordination is provided by the harness, not the board.
            Surface::Rig => return true,
        };
        list.contains(&cap)
    }
}

// ── TOML deserialization ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BoardFile {
    rig: Option<BoardRigToml>,
}

#[derive(Deserialize)]
struct BoardRigToml {
    artifact: Option<String>,
    deploy: Option<Vec<String>>,
    preferred_deploy: Option<String>,
    console: Option<Vec<String>>,
    preferred_console: Option<String>,
    telemetry: Option<Vec<String>>,
    preferred_telemetry: Option<String>,
    observe: Option<Vec<String>>,
    power: Option<Vec<String>>,
    default_timeout_s: Option<u32>,
}

/// Load the `[rig]` section from a board descriptor file.
///
/// Returns `Ok(None)` if the file has no `[rig]` table — some boards may not
/// yet declare one. Returns `Err` for malformed capability names or artifact
/// classes so contract drift surfaces at load time, not at run time.
pub fn load_board_rig(path: &Path) -> Result<Option<BoardRig>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("rig: reading {}: {}", path.display(), e)))?;
    parse_board_rig_str(&raw, &path.display().to_string())
}

/// Parse a `[rig]` section from raw TOML text, using `ctx` as the location
/// string in error messages. Exposed for tests and callers that already have
/// TOML in memory.
pub fn parse_board_rig_str(raw: &str, ctx: &str) -> Result<Option<BoardRig>> {
    let file: BoardFile = toml::from_str(raw)?;
    let Some(t) = file.rig else {
        return Ok(None);
    };
    Ok(Some(parse_rig(t, ctx)?))
}

/// Default board descriptors compiled into fluxor-tools so the rig
/// harness works when invoked from a sibling project without its own
/// `targets/boards/` tree. The list is deliberately small and
/// authoritative — user overrides and project-local copies always win
/// over these.
///
/// Paths are relative to this file (`tools/src/rig/board.rs`) and reach
/// up to the repo's `targets/boards/` directory at build time.
const EMBEDDED_BOARDS: &[(&str, &str)] = &[
    ("cm5", include_str!("../../../targets/boards/cm5.toml")),
    ("linux", include_str!("../../../targets/boards/linux.toml")),
    ("pico", include_str!("../../../targets/boards/pico.toml")),
    (
        "pico2w",
        include_str!("../../../targets/boards/pico2w.toml"),
    ),
    ("picow", include_str!("../../../targets/boards/picow.toml")),
    (
        "qemu-virt",
        include_str!("../../../targets/boards/qemu-virt.toml"),
    ),
    (
        "waveshare-lcd4",
        include_str!("../../../targets/boards/waveshare-lcd4.toml"),
    ),
];

/// Describes where a resolved board descriptor came from — useful for
/// `--plan` output and for tracking which layer a change hit.
#[derive(Debug, Clone)]
pub enum BoardSource {
    UserOverride(PathBuf),
    Project(PathBuf),
    Embedded(&'static str),
}

impl BoardSource {
    pub fn display(&self) -> String {
        match self {
            BoardSource::UserOverride(p) => format!("user: {}", p.display()),
            BoardSource::Project(p) => format!("project: {}", p.display()),
            BoardSource::Embedded(id) => format!("embedded: {id}"),
        }
    }
}

/// Resolve a board id through the RFC §15.1 layered lookup:
///
///   1. user override at `$XDG_CONFIG_HOME/fluxor/boards/<id>.toml`
///      (falling back to `$HOME/.config/fluxor/boards/<id>.toml`),
///   2. project-local `<project_root>/targets/boards/<id>.toml`, when a
///      project root was located upward from the scenario,
///   3. embedded defaults shipped with `fluxor-tools`.
///
/// The first hit wins; later layers are ignored. Returns the parsed
/// `BoardRig` (or `None` when the descriptor exists but has no `[rig]`
/// section) and the source that was used.
pub fn resolve_board_rig(
    board_id: &str,
    project_root: Option<&Path>,
) -> Result<(Option<BoardRig>, BoardSource)> {
    if let Some(user) = user_override_board_path(board_id) {
        if user.is_file() {
            let rig = load_board_rig(&user)?;
            return Ok((rig, BoardSource::UserOverride(user)));
        }
    }
    if let Some(root) = project_root {
        let project_path = root
            .join("targets")
            .join("boards")
            .join(format!("{board_id}.toml"));
        if project_path.is_file() {
            let rig = load_board_rig(&project_path)?;
            return Ok((rig, BoardSource::Project(project_path)));
        }
    }
    for (id, src) in EMBEDDED_BOARDS {
        if *id == board_id {
            let rig = parse_board_rig_str(src, &format!("<embedded:{id}>"))?;
            return Ok((rig, BoardSource::Embedded(id)));
        }
    }
    Err(Error::Config(format!(
        "rig: no board descriptor for '{board_id}' — checked user override \
         ({}), project targets/boards/, and embedded defaults ({:?}). \
         Add one to ~/.config/fluxor/boards/, to the project's \
         targets/boards/, or pick a supported target.",
        user_override_board_path(board_id)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unresolved $HOME>".to_string()),
        EMBEDDED_BOARDS
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
    )))
}

fn user_override_board_path(board_id: &str) -> Option<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
    };
    base.map(|b| {
        b.join("fluxor")
            .join("boards")
            .join(format!("{board_id}.toml"))
    })
}

fn parse_rig(t: BoardRigToml, ctx: &str) -> Result<BoardRig> {
    if let Some(a) = &t.artifact {
        validate_artifact_class(a)
            .map_err(|e| Error::Config(format!("{ctx}: [rig].artifact: {e}")))?;
    }

    let deploy = parse_cap_list(t.deploy, Surface::Deploy, ctx, "deploy")?;
    let console = parse_cap_list(t.console, Surface::Console, ctx, "console")?;
    let telemetry = parse_cap_list(t.telemetry, Surface::Telemetry, ctx, "telemetry")?;
    let observe = parse_cap_list(t.observe, Surface::Observe, ctx, "observe")?;
    let power = parse_cap_list(t.power, Surface::Power, ctx, "power")?;

    let preferred_deploy = parse_preferred(
        t.preferred_deploy,
        &deploy,
        Surface::Deploy,
        ctx,
        "preferred_deploy",
    )?;
    let preferred_console = parse_preferred(
        t.preferred_console,
        &console,
        Surface::Console,
        ctx,
        "preferred_console",
    )?;
    let preferred_telemetry = parse_preferred(
        t.preferred_telemetry,
        &telemetry,
        Surface::Telemetry,
        ctx,
        "preferred_telemetry",
    )?;

    Ok(BoardRig {
        artifact: t.artifact,
        deploy,
        preferred_deploy,
        console,
        preferred_console,
        telemetry,
        preferred_telemetry,
        observe,
        power,
        default_timeout_s: t.default_timeout_s,
    })
}

fn parse_cap_list(
    values: Option<Vec<String>>,
    expect: Surface,
    ctx: &str,
    field: &str,
) -> Result<Vec<Capability>> {
    let Some(values) = values else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(values.len());
    for (i, s) in values.iter().enumerate() {
        let cap = Capability::parse(s)
            .map_err(|e| Error::Config(format!("{ctx}: [rig].{field}[{i}]: {e}")))?;
        if cap.surface() != expect {
            return Err(Error::Config(format!(
                "{ctx}: [rig].{field}[{i}]: '{s}' is a '{}' capability, expected '{}'",
                cap.surface().as_str(),
                expect.as_str(),
            )));
        }
        out.push(cap);
    }
    Ok(out)
}

fn parse_preferred(
    value: Option<String>,
    allowed: &[Capability],
    expect: Surface,
    ctx: &str,
    field: &str,
) -> Result<Option<Capability>> {
    let Some(s) = value else {
        return Ok(None);
    };
    let cap =
        Capability::parse(&s).map_err(|e| Error::Config(format!("{ctx}: [rig].{field}: {e}")))?;
    if cap.surface() != expect {
        return Err(Error::Config(format!(
            "{ctx}: [rig].{field}: '{s}' is a '{}' capability, expected '{}'",
            cap.surface().as_str(),
            expect.as_str(),
        )));
    }
    if !allowed.contains(&cap) {
        return Err(Error::Config(format!(
            "{ctx}: [rig].{field}: '{s}' must also appear in the '{}' list",
            expect.as_str(),
        )));
    }
    Ok(Some(cap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_cm5_shape() {
        let toml_src = r#"
            [rig]
            artifact = "boot_bundle"
            deploy = ["deploy.netboot_tftp", "deploy.bootfs_copy"]
            preferred_deploy = "deploy.netboot_tftp"
            console = ["console.serial"]
            preferred_console = "console.serial"
            telemetry = ["telemetry.monitor_udp"]
            preferred_telemetry = "telemetry.monitor_udp"
            observe = ["observe.console_regex", "observe.netboot_fetch"]
            power = ["power.cycle"]
            default_timeout_s = 30
        "#;
        let rig = parse_board_rig_str(toml_src, "cm5.toml").unwrap().unwrap();
        assert_eq!(rig.artifact.as_deref(), Some("boot_bundle"));
        assert_eq!(rig.deploy.len(), 2);
        assert_eq!(rig.default_timeout_s, Some(30));
        assert!(rig.supports(Capability::parse("deploy.netboot_tftp").unwrap()));
        assert!(!rig.supports(Capability::parse("deploy.uf2_mount").unwrap()));
    }

    #[test]
    fn missing_rig_section_returns_none() {
        assert!(parse_board_rig_str("[board]\nid = \"x\"\n", "x.toml")
            .unwrap()
            .is_none());
    }

    #[test]
    fn wrong_surface_in_list_is_rejected() {
        let src = r#"[rig]
               deploy = ["console.serial"]
            "#;
        let err = parse_board_rig_str(src, "x.toml").unwrap_err();
        assert!(format!("{err}").contains("expected 'deploy'"));
    }

    #[test]
    fn preferred_must_be_in_list() {
        let src = r#"[rig]
               deploy = ["deploy.netboot_tftp"]
               preferred_deploy = "deploy.bootfs_copy"
            "#;
        let err = parse_board_rig_str(src, "x.toml").unwrap_err();
        assert!(format!("{err}").contains("must also appear"));
    }

    #[test]
    fn unknown_artifact_class_rejected() {
        let src = r#"[rig]
               artifact = "docker_image"
            "#;
        assert!(parse_board_rig_str(src, "x.toml").is_err());
    }

    // ── resolve_board_rig / layered lookup ────────────────────────────────

    /// Guard that scopes env-var writes used by the resolver tests. Drop
    /// restores the previous values so parallel tests don't leak into
    /// each other.
    struct EnvGuard {
        keys: Vec<(String, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| (k.to_string(), std::env::var_os(k)))
                .collect();
            Self { keys: saved }
        }
        fn set(&self, k: &str, v: &str) {
            std::env::set_var(k, v);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.keys {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn resolve_falls_back_to_embedded_when_no_project_or_user_override() {
        let g = EnvGuard::new(&["XDG_CONFIG_HOME", "HOME"]);
        let empty = crate::rig::test_utils::unique_tmp_dir("board-resolve-empty");
        g.set("XDG_CONFIG_HOME", empty.to_str().unwrap());
        g.set("HOME", empty.to_str().unwrap());

        let (rig, source) = resolve_board_rig("cm5", None).unwrap();
        assert!(rig.is_some(), "embedded cm5 must carry a [rig] section");
        match source {
            BoardSource::Embedded(id) => assert_eq!(id, "cm5"),
            other => panic!("expected Embedded, got {other:?}"),
        }
        std::fs::remove_dir_all(&empty).ok();
    }

    #[test]
    fn resolve_project_wins_over_embedded() {
        let g = EnvGuard::new(&["XDG_CONFIG_HOME", "HOME"]);
        let empty = crate::rig::test_utils::unique_tmp_dir("board-resolve-empty");
        g.set("XDG_CONFIG_HOME", empty.to_str().unwrap());
        g.set("HOME", empty.to_str().unwrap());

        let project = crate::rig::test_utils::unique_tmp_dir("board-resolve-project");
        let project_boards = project.join("targets").join("boards");
        std::fs::create_dir_all(&project_boards).unwrap();
        std::fs::write(
            project_boards.join("cm5.toml"),
            r#"[rig]
artifact = "kernel8_img"
deploy = ["deploy.bootfs_copy"]
preferred_deploy = "deploy.bootfs_copy"
console = ["console.serial"]
observe = ["observe.netboot_fetch"]
power = ["power.cycle"]
default_timeout_s = 7
"#,
        )
        .unwrap();

        let (rig, source) = resolve_board_rig("cm5", Some(&project)).unwrap();
        let rig = rig.expect("project descriptor has [rig]");
        // `default_timeout_s = 7` is unique to the project override; the
        // embedded descriptor would give a different value.
        assert_eq!(rig.default_timeout_s, Some(7));
        match source {
            BoardSource::Project(p) => assert_eq!(p, project_boards.join("cm5.toml")),
            other => panic!("expected Project source, got {other:?}"),
        }
        std::fs::remove_dir_all(&empty).ok();
        std::fs::remove_dir_all(&project).ok();
    }

    #[test]
    fn resolve_user_override_wins_over_project_and_embedded() {
        let g = EnvGuard::new(&["XDG_CONFIG_HOME", "HOME"]);

        let xdg = crate::rig::test_utils::unique_tmp_dir("board-resolve-xdg");
        let user_boards = xdg.join("fluxor").join("boards");
        std::fs::create_dir_all(&user_boards).unwrap();
        std::fs::write(
            user_boards.join("cm5.toml"),
            r#"[rig]
artifact = "kernel8_img"
deploy = ["deploy.netboot_tftp"]
console = ["console.serial"]
observe = ["observe.netboot_fetch"]
power = ["power.cycle"]
default_timeout_s = 999
"#,
        )
        .unwrap();
        g.set("XDG_CONFIG_HOME", xdg.to_str().unwrap());
        // Point HOME at an unrelated directory so the `$HOME/.config`
        // fallback can't find the user override by accident.
        g.set("HOME", std::env::temp_dir().to_str().unwrap());

        let project = crate::rig::test_utils::unique_tmp_dir("board-resolve-project-alt");
        let project_boards = project.join("targets").join("boards");
        std::fs::create_dir_all(&project_boards).unwrap();
        std::fs::write(
            project_boards.join("cm5.toml"),
            r#"[rig]
artifact = "kernel8_img"
deploy = ["deploy.bootfs_copy"]
console = ["console.serial"]
power = ["power.cycle"]
default_timeout_s = 42
"#,
        )
        .unwrap();

        let (rig, source) = resolve_board_rig("cm5", Some(&project)).unwrap();
        let rig = rig.expect("[rig] section");
        // `999` is unique to the user override.
        assert_eq!(rig.default_timeout_s, Some(999));
        match source {
            BoardSource::UserOverride(p) => assert_eq!(p, user_boards.join("cm5.toml")),
            other => panic!("expected UserOverride, got {other:?}"),
        }
        std::fs::remove_dir_all(&xdg).ok();
        std::fs::remove_dir_all(&project).ok();
    }

    #[test]
    fn resolve_unknown_board_errors_with_list_of_embedded() {
        let g = EnvGuard::new(&["XDG_CONFIG_HOME", "HOME"]);
        let empty = crate::rig::test_utils::unique_tmp_dir("board-resolve-unknown");
        g.set("XDG_CONFIG_HOME", empty.to_str().unwrap());
        g.set("HOME", empty.to_str().unwrap());

        let err = resolve_board_rig("definitely-not-a-board", None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("definitely-not-a-board"), "{msg}");
        assert!(msg.contains("cm5"), "{msg}");
        std::fs::remove_dir_all(&empty).ok();
    }
}
