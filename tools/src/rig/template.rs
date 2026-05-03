//! Build-command template substitution.
//!
//! Project recipes live in `~/.config/fluxor/projects/<name>/rig.toml`
//! and supply the argv that builds the on-disk artifact. The recipe
//! may reference scenario-derived values via `${scenario.*}` so the
//! same recipe can build different workloads for different scenarios.
//!
//! The placeholder syntax matches `${env:…}` / `${file:…}` from
//! `secret.rs` so the visual grammar is consistent across all
//! rig-touched TOML files.
//!
//! # Supported placeholders
//!
//! | Placeholder           | Resolves to                                            |
//! |-----------------------|--------------------------------------------------------|
//! | `${scenario.config}`  | Absolute path of the scenario's `config` field         |
//!
//! Unknown placeholders are a hard error at substitution time so a
//! misconfigured recipe fails at plan-build rather than after spawning
//! a build with a literal `${scenario.bogus}` on the command line.
//!
//! # Shell-injection guard
//!
//! Substitution is raw text replacement, which is safe only when the
//! placeholder lands as its own argv element:
//!
//! ```toml
//! command = ["fluxor", "combine", "fw.bin", "${scenario.config}", "-o", "out.img"]
//! ```
//!
//! The kernel hands the value to the executable as one `argv[i]` with
//! no further parsing. Substituting into a shell-script string is
//! unsafe — bash would reparse the value, splitting on spaces and
//! interpreting `;`, `&&`, `$(…)`, or backticks. The supported safe
//! pattern in a shell recipe is the standard "extra positional +
//! `\"$1\"`" form:
//!
//! ```toml
//! command = [
//!     "bash", "-c",
//!     "fluxor combine fw.bin \"$1\" -o out.img",
//!     "_",
//!     "${scenario.config}",
//! ]
//! ```
//!
//! `bash` receives `${scenario.config}` as `argv[1]`, so the script
//! sees it as a single properly-quoted parameter regardless of its
//! contents. `substitute_command` refuses to substitute a placeholder
//! into the `<script>` slot of a `<shell> -c <script> [args…]`
//! invocation and points the operator at the safe pattern.

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::rig::scenario::Scenario;

/// Substitute `${scenario.*}` placeholders in every element of a build
/// command's argv. Returns a fresh vector; the input is not modified.
///
/// Unknown placeholders return an `Error::Config` with the offending
/// token so misconfigured project recipes fail loud at plan time, not
/// after spawning a build with a literal `${…}` on the command line.
///
/// Substitution into a shell-interpreted script slot (`<shell> -c
/// <script>`) is a hard error — the safe pattern is to pass the value
/// as a separate argv positional and dereference `"$1"` inside the
/// script. See the module docs for the rationale.
pub fn substitute_command(command: &[String], scenario: &Scenario) -> Result<Vec<String>> {
    let shell_script_indices = identify_shell_script_args(command);
    command
        .iter()
        .enumerate()
        .map(|(i, arg)| substitute_arg(arg, scenario, shell_script_indices.contains(&i)))
        .collect()
}

/// Identify argv indices that hold a `<shell> -c <script>` script
/// string. A placeholder substituted into one of these would be
/// re-parsed by the shell, so we refuse it.
fn identify_shell_script_args(command: &[String]) -> HashSet<usize> {
    let mut out = HashSet::new();
    for i in 1..command.len() {
        if command[i] != "-c" {
            continue;
        }
        // Need a previous arg (the shell binary) and a following arg
        // (the script text).
        if i + 1 >= command.len() {
            continue;
        }
        if is_shell_binary(&command[i - 1]) {
            out.insert(i + 1);
        }
    }
    out
}

/// Recognise common POSIX-shell binaries whose `-c` argument is
/// shell-script source. Matched on basename so absolute paths
/// (`/bin/bash`) and bare names (`bash`) both work.
fn is_shell_binary(arg: &str) -> bool {
    let basename = arg.rsplit('/').next().unwrap_or(arg);
    matches!(basename, "bash" | "sh" | "zsh" | "ksh" | "dash" | "ash")
}

fn substitute_arg(arg: &str, scenario: &Scenario, in_shell_script: bool) -> Result<String> {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        let end = after_open.find('}').ok_or_else(|| {
            Error::Config(format!(
                "rig: unterminated `${{` in build recipe argument {arg:?}"
            ))
        })?;
        let placeholder = &after_open[..end];
        if in_shell_script {
            return Err(Error::Config(format!(
                "rig: refusing to substitute `${{{placeholder}}}` into a shell-script \
                 argument — the substituted value would be re-parsed by the shell, \
                 so a path with a space or any of `; & | $ \\` `( )` would break or \
                 inject. Pass the value as a separate argv positional and reference \
                 `\"$1\"` inside the script:\n  \
                 [\"bash\", \"-c\", \"... \\\"$1\\\" ...\", \"_\", \"${{{placeholder}}}\"]\n  \
                 (the `\"_\"` slot is `$0`; `${{{placeholder}}}` becomes `$1`)."
            )));
        }
        out.push_str(&resolve_placeholder(placeholder, scenario)?);
        rest = &after_open[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_placeholder(placeholder: &str, scenario: &Scenario) -> Result<String> {
    match placeholder {
        "scenario.config" => Ok(scenario.config.display().to_string()),
        other => Err(Error::Config(format!(
            "rig: unknown build-recipe placeholder `${{{other}}}` — \
             known placeholders: ${{scenario.config}}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::scenario::parse_scenario_str;
    use std::path::Path;

    fn fixture_scenario() -> Scenario {
        let raw = r#"
name = "demo"
target = "cm5"
config = "../../examples/cm5/https_server.yaml"
"#;
        parse_scenario_str(raw, Path::new("/repo/tests/hardware"), "fixture").unwrap()
    }

    fn scenario_with_path(path: &str) -> Scenario {
        let raw = format!(
            r#"
name = "demo"
target = "cm5"
config = "{path}"
"#
        );
        parse_scenario_str(&raw, Path::new("/repo/tests/hardware"), "fixture").unwrap()
    }

    #[test]
    fn substitutes_into_plain_argv_element() {
        let scenario = fixture_scenario();
        let cmd = vec![
            "fluxor".to_string(),
            "combine".to_string(),
            "fw.bin".to_string(),
            "${scenario.config}".to_string(),
            "-o".to_string(),
            "packed.img".to_string(),
        ];
        let out = substitute_command(&cmd, &scenario).unwrap();
        // Path lands in its own argv slot; no shell involved.
        assert_eq!(
            out[3],
            "/repo/tests/hardware/../../examples/cm5/https_server.yaml"
        );
    }

    #[test]
    fn passthrough_when_no_placeholder() {
        let scenario = fixture_scenario();
        let cmd = vec!["make".to_string(), "firmware".to_string()];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(out, cmd);
    }

    #[test]
    fn handles_multiple_placeholders_in_one_arg() {
        let scenario = fixture_scenario();
        // Use a non-shell-script arg so the substitution rule allows
        // multiple expansions in the same string. (A `bash -c` script
        // arg would be rejected before the count even mattered.)
        let cmd = vec!["${scenario.config}:${scenario.config}".to_string()];
        let out = substitute_command(&cmd, &scenario).unwrap();
        let p = scenario.config.display().to_string();
        assert_eq!(out[0], format!("{p}:{p}"));
    }

    #[test]
    fn passthrough_when_recipe_uses_no_placeholders() {
        // Captures today's behaviour for the rest of the project's
        // recipes (rp2350 / picow / waveshare-lcd4) — they don't
        // template anything, and substitution should be a no-op.
        let scenario = fixture_scenario();
        let cmd = vec![
            "make".to_string(),
            "firmware".to_string(),
            "modules".to_string(),
            "TARGET=picow".to_string(),
        ];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(out, cmd);
    }

    #[test]
    fn unknown_placeholder_is_an_error() {
        let scenario = fixture_scenario();
        let cmd = vec!["${scenario.bogus}".to_string()];
        let err = substitute_command(&cmd, &scenario).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown"), "msg was: {msg}");
        assert!(msg.contains("scenario.bogus"), "msg was: {msg}");
    }

    #[test]
    fn unterminated_placeholder_is_an_error() {
        let scenario = fixture_scenario();
        let cmd = vec!["${scenario.config".to_string()];
        let err = substitute_command(&cmd, &scenario).unwrap_err();
        assert!(format!("{err}").contains("unterminated"));
    }

    // ── Shell-injection guard ─────────────────────────────────────────

    #[test]
    fn rejects_inline_placeholder_in_bash_dash_c() {
        let scenario = fixture_scenario();
        let cmd = vec![
            "bash".to_string(),
            "-c".to_string(),
            "fluxor combine fw.bin ${scenario.config} -o out.img".to_string(),
        ];
        let err = substitute_command(&cmd, &scenario).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("shell-script"), "msg was: {msg}");
        // Hint must point at the safe pattern.
        assert!(msg.contains("\"$1\""), "msg was: {msg}");
        assert!(msg.contains("scenario.config"), "msg was: {msg}");
    }

    #[test]
    fn rejects_inline_placeholder_in_sh_dash_c() {
        let scenario = fixture_scenario();
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo ${scenario.config}".to_string(),
        ];
        assert!(substitute_command(&cmd, &scenario).is_err());
    }

    #[test]
    fn rejects_inline_placeholder_with_absolute_shell_path() {
        // Operators sometimes spell out `/bin/bash` instead of `bash`.
        // Detection runs on basename so both shapes are caught.
        let scenario = fixture_scenario();
        let cmd = vec![
            "/usr/bin/bash".to_string(),
            "-c".to_string(),
            "tool ${scenario.config}".to_string(),
        ];
        assert!(substitute_command(&cmd, &scenario).is_err());
    }

    #[test]
    fn allows_placeholder_as_positional_after_dash_c() {
        // The supported safe shape: `${scenario.config}` is its own
        // argv element AFTER the script. The script slot itself
        // contains no placeholder; substitution into the positional
        // argument is a plain-argv substitution and proceeds normally.
        let scenario = scenario_with_path("/abs/path/with spaces/cfg.yaml");
        let cmd = vec![
            "bash".to_string(),
            "-c".to_string(),
            "fluxor combine fw.bin \"$1\" -o out.img".to_string(),
            "_".to_string(),
            "${scenario.config}".to_string(),
        ];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(out[2], "fluxor combine fw.bin \"$1\" -o out.img");
        assert_eq!(out[3], "_");
        // Path with spaces is preserved verbatim — the shell will not
        // re-parse it because it arrives as one positional parameter.
        assert_eq!(out[4], "/abs/path/with spaces/cfg.yaml");
    }

    #[test]
    fn allows_path_with_shell_metacharacters_via_positional() {
        // The whole point of the positional pattern: even paths
        // containing characters bash treats specially are passed
        // through untouched. (No real scenario should have such a
        // path, but the substitutor should not become the limiting
        // factor.)
        let scenario = scenario_with_path("/tmp/x;rm -rf $(echo bad).yaml");
        let cmd = vec![
            "bash".to_string(),
            "-c".to_string(),
            "echo \"$1\"".to_string(),
            "_".to_string(),
            "${scenario.config}".to_string(),
        ];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(out[4], "/tmp/x;rm -rf $(echo bad).yaml");
    }

    #[test]
    fn does_not_treat_dash_c_after_non_shell_as_script() {
        // `cargo -c` (hypothetical) or any non-shell binary that
        // happens to take a `-c` flag should not trigger the shell
        // guard. The detection requires the previous arg to be a
        // known POSIX shell.
        let scenario = fixture_scenario();
        let cmd = vec![
            "make".to_string(),
            "-c".to_string(),
            "${scenario.config}".to_string(),
        ];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(
            out[2],
            "/repo/tests/hardware/../../examples/cm5/https_server.yaml"
        );
    }

    #[test]
    fn dash_c_at_end_of_argv_does_not_panic() {
        // Defensive: if `-c` is the last arg and no script follows,
        // there's no script slot to guard. Substitution should still
        // succeed (or fail cleanly on its own merits).
        let scenario = fixture_scenario();
        let cmd = vec!["bash".to_string(), "-c".to_string()];
        let out = substitute_command(&cmd, &scenario).unwrap();
        assert_eq!(out, cmd);
    }
}
