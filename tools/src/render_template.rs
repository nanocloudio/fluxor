//! Placeholder substitution on YAML config templates.
//!
//! Deployment configs that ship as templates carry `__KEY__` markers
//! where a per-replica value (replica id, listen port, peer ports)
//! lands at render time. This module is the canonical substitution
//! engine — both `fluxor render-template` (the developer-facing
//! command) and `fluxor up` (the multi-replica spawner) call into it.
//!
//! Placeholder convention:
//! - Each placeholder is `__KEY__` (double underscore prefix and
//!   suffix). Keys are uppercase ASCII letters, digits, and
//!   underscores.
//! - Values come from `(key, value)` pairs, typed as strings; the
//!   caller picks the formatting (decimal port numbers, hex epochs,
//!   etc.).
//! - After substitution the engine fails closed if any unresolved
//!   `__KEY__` remains in the output — silent typos are the most
//!   common failure mode and worth catching at render time, not at
//!   `fluxor run` parse time.

use crate::error::{Error, Result};
use std::path::Path;

/// Substitute `__KEY__` markers in `template` with the supplied
/// `(key, value)` pairs. Returns the rendered text.
///
/// Fails if any `__KEY__` placeholder remains after substitution.
pub fn render(template: &str, vars: &[(String, String)]) -> Result<String> {
    let mut out = template.to_string();
    for (key, value) in vars {
        let needle = format!("__{key}__");
        out = out.replace(&needle, value);
    }
    if let Some(leftover) = find_unresolved_placeholder(&out) {
        return Err(Error::Config(format!(
            "unresolved placeholder `__{leftover}__` after substitution"
        )));
    }
    Ok(out)
}

/// Render a template file to a string.
pub fn render_file(template_path: &Path, vars: &[(String, String)]) -> Result<String> {
    let body = std::fs::read_to_string(template_path).map_err(|e| {
        Error::Config(format!(
            "failed to read template {}: {}",
            template_path.display(),
            e
        ))
    })?;
    render(&body, vars)
}

/// Parse `KEY=VALUE` strings from the CLI into the form `render`
/// expects. Keys must be uppercase + digits + underscores; values
/// are arbitrary.
pub fn parse_vars(input: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(input.len());
    for raw in input {
        let (key, value) = raw.split_once('=').ok_or_else(|| {
            Error::Config(format!("invalid --var {raw:?}: expected `KEY=VALUE` form"))
        })?;
        if key.is_empty() {
            return Err(Error::Config(format!("--var {raw:?}: key is empty")));
        }
        if !key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(Error::Config(format!(
                "--var {raw:?}: key must be uppercase ASCII letters, digits, and underscores"
            )));
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

/// Scan `text` for an unresolved `__KEY__` placeholder. Returns the
/// key (without the underscores) on the first match. Used as a
/// post-substitution sanity check; the engine fails closed on any
/// leftover marker so silent template/var typos surface at render
/// time.
fn find_unresolved_placeholder(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] == b'_' && bytes[i + 1] == b'_' {
            // Walk to the closing `__`. Keep the body alphanumeric +
            // underscore so we don't trip on prose comments.
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() {
                let b = bytes[end];
                if b == b'_' && end + 1 < bytes.len() && bytes[end + 1] == b'_' {
                    // Matched; only treat as a placeholder if the
                    // body is non-empty and uppercase-friendly. This
                    // avoids flagging double-underscore strings in
                    // unrelated comment prose.
                    let body = &text[start..end];
                    if !body.is_empty()
                        && body
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                    {
                        return Some(body.to_string());
                    }
                    break;
                }
                if !b.is_ascii_uppercase() && !b.is_ascii_digit() && b != b'_' {
                    break;
                }
                end += 1;
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// `fluxor render-template` dispatcher. Reads the template, applies
/// substitutions, and writes either to stdout or to `output_path`.
pub fn cmd_render_template(
    template_path: &Path,
    vars: &[String],
    output_path: Option<&Path>,
) -> Result<()> {
    let parsed = parse_vars(vars)?;
    let rendered = render_file(template_path, &parsed)?;
    match output_path {
        None => {
            print!("{rendered}");
        }
        Some(p) => {
            std::fs::write(p, &rendered)
                .map_err(|e| Error::Config(format!("failed to write {}: {}", p.display(), e)))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_known_keys() {
        let out = render(
            "self=__SELF_ID__ port=__LISTEN_PORT__",
            &[
                ("SELF_ID".into(), "0".into()),
                ("LISTEN_PORT".into(), "9090".into()),
            ],
        )
        .unwrap();
        assert_eq!(out, "self=0 port=9090");
    }

    #[test]
    fn fails_on_leftover_placeholder() {
        let err = render(
            "self=__SELF_ID__ port=__LISTEN_PORT__",
            &[("SELF_ID".into(), "0".into())],
        )
        .unwrap_err();
        assert!(err.to_string().contains("LISTEN_PORT"), "{}", err);
    }

    #[test]
    fn ignores_prose_double_underscores() {
        // Comments like `__main__` in prose shouldn't false-trip the
        // unresolved-placeholder detector, because the body has
        // lowercase letters.
        let out = render("python __main__ guard", &[]).unwrap();
        assert_eq!(out, "python __main__ guard");
    }

    #[test]
    fn parse_vars_rejects_lowercase_keys() {
        let err = parse_vars(&["self_id=0".to_string()]).unwrap_err();
        assert!(err.to_string().contains("uppercase"), "{}", err);
    }

    #[test]
    fn parse_vars_round_trips() {
        let vars = parse_vars(&["SELF_ID=0".to_string(), "LISTEN_PORT=9090".to_string()]).unwrap();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0], ("SELF_ID".to_string(), "0".to_string()));
        assert_eq!(vars[1], ("LISTEN_PORT".to_string(), "9090".to_string()));
    }
}
