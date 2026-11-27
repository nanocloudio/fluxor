// =============================================================================
// Module packs and pins a param names by module
// =============================================================================

/// The placeholder a param value names a module pack by:
/// `${module_pack:<type>[,<type>…]}`.
const MODULE_PACK_PLACEHOLDER: &str = "${module_pack:";

/// The placeholder a param value names a module's pin by:
/// `${module_pin:<type>}`.
const MODULE_PIN_PLACEHOLDER: &str = "${module_pin:";

/// One module-bytes placeholder, parsed.
#[derive(Debug, PartialEq, Eq)]
enum ModuleBytesRef<'a> {
    /// A module pack: an FXMT module table of these types, in this order.
    Pack(Vec<&'a str>),
    /// The pin of one type: the SHA-256 of its `.fmod` bytes.
    Pin(&'a str),
}

/// The module-bytes placeholder `s` is, `Ok(None)` when it names none. A
/// placeholder is the whole value: one inside other text, an empty or
/// repeated type, and a pin of more than one type are refused.
fn module_bytes_ref(s: &str) -> std::result::Result<Option<ModuleBytesRef<'_>>, String> {
    let (opener, pack) = if s.contains(MODULE_PACK_PLACEHOLDER) {
        (MODULE_PACK_PLACEHOLDER, true)
    } else if s.contains(MODULE_PIN_PLACEHOLDER) {
        (MODULE_PIN_PLACEHOLDER, false)
    } else {
        return Ok(None);
    };
    let Some(types) = s.strip_prefix(opener).and_then(|r| r.strip_suffix('}')) else {
        return Err(format!(
            "{s:?}: `{opener}…}}` stands alone as the whole value, as a module's bytes \
             are not text to interpolate"
        ));
    };
    let types: Vec<&str> = types.split(',').map(str::trim).collect();
    for (i, ty) in types.iter().enumerate() {
        if !fluxor_tools::workload::is_module_name(ty) {
            return Err(format!("{s:?}: '{ty}' is not a module type name"));
        }
        if types[..i].contains(ty) {
            return Err(format!("{s:?}: names module type '{ty}' twice"));
        }
    }
    if pack {
        return Ok(Some(ModuleBytesRef::Pack(types)));
    }
    match types.as_slice() {
        [one] => Ok(Some(ModuleBytesRef::Pin(one))),
        _ => Err(format!("{s:?}: a pin is one module's; name one type")),
    }
}

/// Lowercase hex, the form a string param carries bytes in.
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A module instance's values with every `${module_pack:…}` and
/// `${module_pin:…}` rendered from the modules this build resolves (`r`,
/// the graph's resolver, so for its target and module ABI), as lowercase
/// hex: a pack as the FXMT module table `fluxor build --emit=table` packs
/// for a graph of exactly those modules, a pin as the SHA-256 of the
/// module's `.fmod` — what a `SOURCE_FMOD_PACK` CREATE carries. Each build
/// renders them from the build it reads, so a graph never holds a module's
/// bytes or digest and none goes stale. A type that is native or not built
/// is refused, naming it.
pub(crate) fn render_module_bytes(name: &str, module: Value, r: &ModuleResolver) -> Result<Value> {
    fn walk(v: &mut Value, name: &str, r: &ModuleResolver) -> Result<()> {
        match v {
            Value::String(s) => {
                let rendered = match module_bytes_ref(s)
                    .map_err(|e| Error::Config(format!("module '{name}': {e}")))?
                {
                    None => return Ok(()),
                    Some(ModuleBytesRef::Pack(types)) => {
                        let infos = types
                            .iter()
                            .map(|ty| built_module(name, ty, r))
                            .collect::<Result<Vec<_>>>()?;
                        lower_hex(&crate::modules::build_module_table(&infos)?)
                    }
                    Some(ModuleBytesRef::Pin(ty)) => {
                        use sha2::{Digest, Sha256};
                        lower_hex(&Sha256::digest(&built_module(name, ty, r)?.data))
                    }
                };
                *s = rendered;
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, name, r)?;
                }
            }
            Value::Object(map) => {
                for item in map.values_mut() {
                    walk(item, name, r)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut module = module;
    walk(&mut module, name, r)?;
    Ok(module)
}

/// The built `.fmod` of module type `ty`, as `r` resolves it, for the
/// placeholder of instance `name`.
fn built_module(name: &str, ty: &str, r: &ModuleResolver) -> Result<crate::modules::ModuleInfo> {
    let artifact = r.require(ty, ty, None)?;
    match artifact.module_info()? {
        Some(info) => Ok(info.clone()),
        None => Err(Error::Config(format!(
            "module '{name}': names module '{ty}' by its bytes, but it is native: it has no \
             .fmod to pack or pin"
        ))),
    }
}

#[cfg(test)]
mod module_pack_tests {
    use super::*;

    #[test]
    fn a_placeholder_names_its_modules_as_the_whole_value() {
        assert_eq!(module_bytes_ref("plain"), Ok(None));
        assert_eq!(
            module_bytes_ref("${module_pack:a, b}"),
            Ok(Some(ModuleBytesRef::Pack(vec!["a", "b"])))
        );
        assert_eq!(
            module_bytes_ref("${module_pin:a}"),
            Ok(Some(ModuleBytesRef::Pin("a")))
        );
        for (bad, why) in [
            ("x${module_pack:a}", "stands alone"),
            ("${module_pin:a}x", "stands alone"),
            ("${module_pack:}", "not a module type name"),
            ("${module_pack:a,a}", "twice"),
            ("${module_pin:a,b}", "name one type"),
            ("${module_pin:a/b}", "not a module type name"),
        ] {
            let e = module_bytes_ref(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }
}
