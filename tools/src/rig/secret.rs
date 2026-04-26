//! Secret indirection for private rig profiles — RFC §9.
//!
//! Any string field in a profile may use one of three indirection forms
//! instead of embedding the value directly:
//!
//! * `${env:NAME}` — resolved from the process environment.
//! * `${file:/path}` — resolved from an absolute file (UTF-8 contents
//!   with a single trailing newline trimmed).
//! * `${keychain:svc/acct}` — reserved for a future OS-keychain
//!   integration; currently returns an error so profiles using this
//!   syntax fail loudly.
//!
//! The resolver preserves the distinction between values that came from an
//! indirection (treated as secrets — redacted in plan output, run logs,
//! and profile hashes) and values that were written as plain literals.
//!
//! Callers pull real values out via [`Secret::expose`] when a backend needs
//! them; anything else — `Display`, `Debug`, serialization — returns the
//! `***` sentinel for resolved secrets.

use std::fmt;

use crate::error::{Error, Result};

/// A profile value. Either a plain literal or the result of resolving a
/// `${env:…}` / `${file:…}` / `${keychain:…}` indirection.
#[derive(Clone)]
pub enum Secret {
    Plain(String),
    Resolved(String),
}

impl Secret {
    /// Real value, for use by the backend that needs it. Callers must not
    /// write the returned string to logs or plan output.
    pub fn expose(&self) -> &str {
        match self {
            Self::Plain(s) | Self::Resolved(s) => s,
        }
    }

    /// True if this value came from an indirection and must be redacted.
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }

    /// Value to use in hashes and serialized records per RFC §10.6 —
    /// secrets are replaced by the sentinel so a profile with a removed
    /// secret does not hash-equal one with a secret still present.
    pub fn for_hash(&self) -> &str {
        match self {
            Self::Plain(s) => s,
            Self::Resolved(_) => REDACTED,
        }
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(s) => f.write_str(s),
            Self::Resolved(_) => f.write_str(REDACTED),
        }
    }
}

// `Debug` must also redact — otherwise `{:?}` in a log line leaks the value.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(s) => write!(f, "Plain({s:?})"),
            Self::Resolved(_) => f.write_str("Resolved(***)"),
        }
    }
}

/// Sentinel used wherever a secret value would otherwise be serialized.
pub const REDACTED: &str = "***";

/// Resolve one field's raw string. Plain strings pass through; indirection
/// syntax is resolved against the environment or filesystem.
///
/// `ctx` is a human-readable location string used in error messages, e.g.
/// `"~/.config/fluxor/labs/default/rigs/pi5-a.toml [power].kasa_password"`.
pub fn resolve(raw: &str, ctx: &str) -> Result<Secret> {
    let Some(inner) = strip_indirection(raw) else {
        return Ok(Secret::Plain(raw.to_string()));
    };

    let Some((scheme, arg)) = inner.split_once(':') else {
        return Err(Error::Config(format!(
            "{ctx}: secret indirection '{raw}' is missing a scheme \
             (expected '${{env:NAME}}', '${{file:/path}}', or '${{keychain:svc/acct}}')"
        )));
    };

    match scheme {
        "env" => resolve_env(arg, ctx, raw),
        "file" => resolve_file(arg, ctx, raw),
        "keychain" => Err(Error::Config(format!(
            "{ctx}: ${{keychain:…}} is reserved for a future platform-specific \
             backend and is not yet supported (got '{raw}')"
        ))),
        other => Err(Error::Config(format!(
            "{ctx}: secret indirection '{raw}' uses unknown scheme '{other}' \
             (valid: env, file, keychain)"
        ))),
    }
}

/// Strip the surrounding `${...}` if present. Returns `None` for plain
/// literals so the caller can skip indirection processing entirely.
fn strip_indirection(raw: &str) -> Option<&str> {
    let s = raw.strip_prefix("${")?;
    s.strip_suffix('}')
}

fn resolve_env(name: &str, ctx: &str, raw: &str) -> Result<Secret> {
    if name.is_empty() {
        return Err(Error::Config(format!(
            "{ctx}: empty env var name in '{raw}'"
        )));
    }
    match std::env::var(name) {
        Ok(v) => Ok(Secret::Resolved(v)),
        Err(_) => Err(Error::Config(format!(
            "{ctx}: env var '{name}' required by '{raw}' is not set"
        ))),
    }
}

fn resolve_file(path: &str, ctx: &str, raw: &str) -> Result<Secret> {
    if !std::path::Path::new(path).is_absolute() {
        return Err(Error::Config(format!(
            "{ctx}: ${{file:…}} requires an absolute path (got '{path}' in '{raw}')"
        )));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("{ctx}: reading '{path}' for '{raw}': {e}")))?;
    // Trim a single trailing newline — a `.token` file typically has one.
    let trimmed = contents
        .strip_suffix('\n')
        .unwrap_or(&contents)
        .strip_suffix('\r')
        .unwrap_or_else(|| contents.strip_suffix('\n').unwrap_or(&contents))
        .to_string();
    Ok(Secret::Resolved(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_literal_is_not_secret() {
        let s = resolve("uhubctl", "x").unwrap();
        assert_eq!(s.expose(), "uhubctl");
        assert!(!s.is_secret());
        assert_eq!(format!("{s}"), "uhubctl");
        assert_eq!(s.for_hash(), "uhubctl");
    }

    #[test]
    fn env_indirection_redacts() {
        std::env::set_var("FLUXOR_TEST_SECRET", "hunter2");
        let s = resolve("${env:FLUXOR_TEST_SECRET}", "x").unwrap();
        assert_eq!(s.expose(), "hunter2");
        assert!(s.is_secret());
        assert_eq!(format!("{s}"), "***");
        assert_eq!(format!("{s:?}"), "Resolved(***)");
        assert_eq!(s.for_hash(), "***");
        std::env::remove_var("FLUXOR_TEST_SECRET");
    }

    #[test]
    fn missing_env_var_fails_clearly() {
        std::env::remove_var("FLUXOR_TEST_ABSENT");
        let err = resolve("${env:FLUXOR_TEST_ABSENT}", "ctx").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("FLUXOR_TEST_ABSENT"));
        assert!(msg.contains("ctx"));
    }

    #[test]
    fn file_indirection_reads_and_trims_newline() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("fluxor-rig-secret-{}.tok", std::process::id()));
        std::fs::write(&path, "abc123\n").unwrap();
        let raw = format!("${{file:{}}}", path.display());
        let s = resolve(&raw, "x").unwrap();
        assert_eq!(s.expose(), "abc123");
        assert!(s.is_secret());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_indirection_requires_absolute_path() {
        let err = resolve("${file:relative/path}", "x").unwrap_err();
        assert!(format!("{err}").contains("absolute path"));
    }

    #[test]
    fn keychain_not_yet_supported() {
        let err = resolve("${keychain:svc/acct}", "x").unwrap_err();
        assert!(format!("{err}").contains("keychain"));
    }

    #[test]
    fn unknown_scheme_rejected() {
        let err = resolve("${bogus:x}", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown scheme"));
    }

    #[test]
    fn malformed_indirection_rejected() {
        // '${noscheme}' is missing the colon — it's not a valid indirection.
        let err = resolve("${noscheme}", "x").unwrap_err();
        assert!(format!("{err}").contains("missing a scheme"));
    }

    #[test]
    fn partial_indirection_is_plain() {
        // A string that looks like indirection but isn't wrapped is plain.
        let s = resolve("env:KASA_PASSWORD", "x").unwrap();
        assert_eq!(s.expose(), "env:KASA_PASSWORD");
        assert!(!s.is_secret());
    }
}
