//! The environment pass every graph read goes through.
//!
//! `${VAR}` and `${VAR:-default}` are replaced with environment values;
//! `$${` is the escape for a literal `${`. Only a POSIX-shaped name
//! (`[A-Za-z_][A-Za-z0-9_]*`) participates: anything else inside `${...}`
//! passes through literally, so a graph can embed JS template-literal
//! source, and a service bundle's `${param:<name>}` placeholders survive
//! this pass untouched for the separate parameter pass
//! ([`crate::service_params`]).

/// True iff `s` is a POSIX-valid environment variable identifier.
fn is_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Run the environment pass over `input`.
pub fn substitute(input: &str) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(pos) = rest.find("${") {
        // Escape: `$${` is a literal `${`.
        if pos > 0 && rest.as_bytes()[pos - 1] == b'$' {
            out.push_str(&rest[..pos - 1]);
            out.push_str("${");
            rest = &rest[pos + 2..];
            continue;
        }

        out.push_str(&rest[..pos]);
        rest = &rest[pos + 2..];

        let end = rest
            .find('}')
            .ok_or_else(|| "Unclosed ${} in config".to_string())?;

        let expr = &rest[..end];
        if expr.is_empty() {
            return Err("Empty variable name in ${}".to_string());
        }

        let (var_name, default) = match expr.find(":-") {
            Some(sep) => (&expr[..sep], Some(&expr[sep + 2..])),
            None => (expr, None),
        };

        // A non-POSIX name (dots, spaces, hyphens, a `param:` prefix) is
        // not an environment reference: emit it back unchanged. Only
        // well-formed names participate, so an unset variable still errors
        // loudly.
        if !is_env_var_name(var_name) {
            out.push_str("${");
            out.push_str(expr);
            out.push('}');
            rest = &rest[end + 1..];
            continue;
        }

        match std::env::var(var_name) {
            Ok(val) => out.push_str(&val),
            Err(_) => match default {
                Some(def) => out.push_str(def),
                None => {
                    return Err(format!(
                        "Environment variable '{var_name}' is not set (referenced in config). \
                         Use ${{{var_name}:-default}} to provide a fallback.",
                    ));
                }
            },
        }

        rest = &rest[end + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

/// Make `text` an identity for [`substitute`]: every `${` becomes `$${`.
///
/// Applied to a graph that has ALREADY had its environment pass, so the
/// pass the build runs on it again changes nothing — a value substituted
/// into the graph can never be read as an environment reference.
pub fn escape(text: &str) -> String {
    text.replace("${", "$${")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_placeholders_pass_through_untouched() {
        let s = "port: ${param:port}\nhost: \"a=${param:answer}\"\n";
        assert_eq!(substitute(s).unwrap(), s);
    }

    #[test]
    fn escape_makes_the_pass_an_identity() {
        for text in ["a ${HOME} b", "$${x}", "x$", "${a.b} and $${c}", "plain"] {
            assert_eq!(substitute(&escape(text)).unwrap(), text, "{text}");
        }
    }

    #[test]
    fn defaults_and_unset_names() {
        assert_eq!(
            substitute("${FLUXOR_SURELY_UNSET_VAR:-7}").unwrap(),
            "7".to_string()
        );
        assert!(substitute("${FLUXOR_SURELY_UNSET_VAR}").is_err());
        assert!(substitute("${}").is_err());
        assert!(substitute("${OPEN").is_err());
    }
}
