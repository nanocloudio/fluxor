//! Shared publish helpers.
//!
//! The publish verb itself lives in `store_publish`
//! (`fluxor_tools::store_publish::publish_project_to_store` — the
//! single store-write path). This module carries the small project
//! helpers the store publisher needs.

use std::path::Path;

use crate::error::{Error, Result};
use crate::project::{self, ProjectIdentity};

pub(crate) fn require_project_identity(project_root: &Path) -> Result<ProjectIdentity> {
    let identity = project::project_identity(project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!(
                "no [project] table in {}/fluxor.toml — publish requires `[project].name`",
                project_root.display()
            ))
        })?;
    Ok(identity)
}

/// Detect the host target triple — used to locate runtime binaries
/// under `target/<triple>/release/`. Read from rustc's print output
/// since cargo doesn't surface it via env at runtime.
pub(crate) fn detect_host_target() -> Result<String> {
    let out = std::process::Command::new("rustc")
        .args(["-Vv"])
        .output()
        .map_err(|e| Error::Config(format!("spawn rustc -Vv: {e}")))?;
    if !out.status.success() {
        return Err(Error::Config(format!(
            "rustc -Vv failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("host: ") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(Error::Config("rustc -Vv output had no `host:` line".into()))
}
