//! A module that calls a module-provided contract claims it.
//!
//! The composer refuses a graph whose exercised claim has no provider, so a
//! claim is what makes "no vault" a compose-time refusal rather than an
//! `ENOSYS` at the first call. That only holds if every caller carries the
//! claim: this lint reads each module's sources for an import of a claimed
//! contract's op surface and fails a module whose manifest has no
//! `[[resources]] requires_contract` for it.
//!
//! A caller is recognised by its import path: the contract module itself
//! (`use abi::contracts::key_vault as kv;`, `contracts::key_vault::{SIGN,
//! ..}`, `contracts::key_vault::SIGN`). A path into one of the contract's
//! lower-case submodules (`contracts::key_vault::usage`) imports constants
//! another contract's records share, not an op, and is no call.

use std::path::Path;

/// Contracts whose callers must claim them.
pub const CLAIMED_CONTRACTS: &[&str] = &["key_vault"];

/// Whether `src` imports `contract`'s op surface (see the module docs).
pub fn imports_ops(src: &str, contract: &str) -> bool {
    let needle = format!("contracts::{contract}");
    let mut rest = src;
    while let Some(at) = rest.find(&needle) {
        let after = &rest[at + needle.len()..];
        rest = after;
        // `contracts::key_vault_x` is another name.
        if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let Some(tail) = after.strip_prefix("::") else {
            // `as kv`, `;`, `,` or `}`: the contract module itself.
            return true;
        };
        // A path into a lower-case submodule is constants, not ops.
        if tail.starts_with(|c: char| c.is_ascii_lowercase()) {
            continue;
        }
        return true;
    }
    false
}

/// `module_dir`'s manifest claims or provides `contract`.
fn manifest_claims(manifest: &toml::Value, contract: &str) -> bool {
    let named = |v: &toml::Value| v.as_str() == Some(contract);
    let provides = ["provides", "provider_contracts"].iter().any(|k| {
        manifest
            .get(k)
            .and_then(toml::Value::as_array)
            .is_some_and(|a| a.iter().any(named))
    });
    let claims = manifest
        .get("resources")
        .and_then(toml::Value::as_array)
        .is_some_and(|rs| {
            rs.iter()
                .any(|r| r.get("requires_contract").is_some_and(named))
        });
    provides || claims
}

/// Every module under `modules_root` (a directory holding `manifest.toml`)
/// whose sources import a [`CLAIMED_CONTRACTS`] contract its manifest does
/// not claim, as `"<module dir>: <contract>"`, sorted.
pub fn unclaimed_callers(modules_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(modules_root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_name() == "manifest.toml")
    {
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(manifest) = toml::from_str::<toml::Table>(&text).map(toml::Value::Table) else {
            continue;
        };
        // The module's own sources: the files beside its manifest.
        let sources: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect();
        for &contract in CLAIMED_CONTRACTS {
            if sources.iter().any(|s| imports_ops(s, contract))
                && !manifest_claims(&manifest, contract)
            {
                let rel = dir.strip_prefix(modules_root).unwrap_or(dir);
                out.push(format!("{}: {contract}", rel.display()));
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_op_surface_is_an_import_and_a_constants_submodule_is_not() {
        assert!(imports_ops(
            "use abi::contracts::key_vault as kv;",
            "key_vault"
        ));
        assert!(imports_ops(
            "use abi::contracts::key_vault::{SIGN, OPEN};",
            "key_vault"
        ));
        assert!(imports_ops(
            "x(abi::contracts::key_vault::SIGN)",
            "key_vault"
        ));
        assert!(!imports_ops(
            "use abi::contracts::key_vault::usage;",
            "key_vault"
        ));
        assert!(!imports_ops(
            "use abi::contracts::key_vaults as k;",
            "key_vault"
        ));
        assert!(!imports_ops("use abi::contracts::fs as f;", "key_vault"));
    }

    #[test]
    fn a_caller_without_the_claim_is_named_and_one_with_it_is_not() {
        let root = tempfile::tempdir().expect("tempdir");
        let module = |name: &str, manifest: &str, src: &str| {
            let d = root.path().join("foundation").join(name);
            std::fs::create_dir_all(&d).expect("dir");
            std::fs::write(d.join("manifest.toml"), manifest).expect("manifest");
            std::fs::write(d.join("mod.rs"), src).expect("src");
        };
        let call = "use abi::contracts::key_vault as kv;\n";
        module("bare", "version = \"1.0.0\"\n", call);
        module(
            "claims",
            "version = \"1.0.0\"\n[[resources]]\nrequires_contract = \"key_vault\"\naccess = \"write\"\n",
            call,
        );
        module(
            "vault",
            "version = \"1.0.0\"\nprovider_contracts = [\"key_vault\"]\n",
            call,
        );
        module(
            "consts",
            "version = \"1.0.0\"\n",
            "use abi::contracts::key_vault::usage;\n",
        );
        assert_eq!(
            unclaimed_callers(root.path()),
            vec!["foundation/bare: key_vault".to_string()]
        );
    }
}
