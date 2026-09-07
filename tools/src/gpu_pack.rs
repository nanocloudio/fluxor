//! Offline GPU program packs: build, inspect, validate.
//!
//! A pack is the only way an executable reaches a GPU provider, and every
//! provider refuses one whose identity, target, bindings or requirements it
//! cannot honour. That refusal arrives at load time, on a device, in a graph —
//! which is a slow place to discover that a binding declared 32-byte alignment
//! against a device whose granularity is 64.
//!
//! These three commands move that discovery to the build. They share the
//! device's own decoder (`modules/sdk/cores/gpu_pack.rs`), so a pack this
//! tool accepts is a pack that provider accepts, rather than one that passes a
//! second implementation of the same rules.
//!
//! `validate` checks against a capability record the device actually
//! published — the 152 bytes of an `OUT_CAPS` reply — rather than against
//! flags describing a device from memory. A hand-written description of a GPU
//! is exactly the thing that goes stale.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::gpu_contract::{
    decode, encode, encoded_len, pack_limits_from_caps, pack_reason_name, validate, PackBinding,
    PackSpec, ARITH_TYPE_COUNT, BIND_ACCESS_READ, BIND_ACCESS_WRITE, BIND_INDEX, BIND_SAMPLER,
    BIND_STORAGE, BIND_TEXTURE, BIND_UNIFORM, BIND_VERTEX, CAPS_LEN, MAX_BINDINGS, TARGET_NONE,
    TARGET_REPLAY, TARGET_SPIRV, TARGET_V3D_QPU, TARGET_WGSL,
};

/// One `--binding slot:kind:access:min_size:align` argument.
///
/// Positional rather than a nested key/value syntax because the five fields
/// are all mandatory: a binding with an unstated alignment is not a binding
/// with a default, it is a binding whose author has not decided.
fn parse_binding(spec: &str) -> Result<PackBinding> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 5 {
        return Err(Error::Config(format!(
            "binding `{spec}`: expected slot:kind:access:min_size:align"
        )));
    }
    let field = |i: usize, name: &str| -> Result<u32> {
        parts[i]
            .parse::<u32>()
            .map_err(|_| Error::Config(format!("binding `{spec}`: {name} is not a number")))
    };
    let slot = field(0, "slot")?;
    if slot > u32::from(u16::MAX) {
        return Err(Error::Config(format!(
            "binding `{spec}`: slot out of range"
        )));
    }
    let kind = match parts[1] {
        "storage" => BIND_STORAGE,
        "uniform" => BIND_UNIFORM,
        "texture" => BIND_TEXTURE,
        "sampler" => BIND_SAMPLER,
        "vertex" => BIND_VERTEX,
        "index" => BIND_INDEX,
        other => {
            return Err(Error::Config(format!(
                "binding `{spec}`: unknown kind `{other}` \
                 (storage|uniform|texture|sampler|vertex|index)"
            )))
        }
    };
    let access = match parts[2] {
        "r" => BIND_ACCESS_READ,
        "w" => BIND_ACCESS_WRITE,
        "rw" => BIND_ACCESS_READ | BIND_ACCESS_WRITE,
        other => {
            return Err(Error::Config(format!(
                "binding `{spec}`: unknown access `{other}` (r|w|rw)"
            )))
        }
    };
    Ok(PackBinding {
        slot: slot as u16,
        kind,
        access,
        min_size: field(3, "min_size")?,
        align: field(4, "align")?,
    })
}

/// The binding rules the decoder enforces, checked here so a mistake in the
/// command line is reported as one.
///
/// The decoder would catch every one of these anyway. Repeating them is not
/// duplicated logic but duplicated *timing*: without this, a duplicate slot
/// reaches the user as "the built pack does not decode", which reads as a
/// tool defect rather than as the typo it is.
fn check_binding_set(bindings: &[PackBinding]) -> Result<()> {
    for (i, b) in bindings.iter().enumerate() {
        if b.align == 0 || !b.align.is_power_of_two() {
            return Err(Error::Config(format!(
                "binding slot {}: alignment {} is not a power of two",
                b.slot, b.align
            )));
        }
        if matches!(
            b.kind,
            BIND_UNIFORM | BIND_SAMPLER | BIND_VERTEX | BIND_INDEX
        ) && b.access & BIND_ACCESS_WRITE != 0
        {
            return Err(Error::Config(format!(
                "binding slot {}: a {} binding cannot be written",
                b.slot,
                kind_name(b.kind)
            )));
        }
        if let Some(dup) = bindings[..i].iter().find(|o| o.slot == b.slot) {
            // Two claims on one slot have no single meaning; picking one
            // silently would bind the wrong buffer.
            return Err(Error::Config(format!(
                "binding slot {} declared twice ({} and {})",
                b.slot,
                kind_name(dup.kind),
                kind_name(b.kind)
            )));
        }
    }
    Ok(())
}

fn parse_target(name: &str) -> Result<u32> {
    match name {
        "wgsl" => Ok(TARGET_WGSL),
        "spirv" => Ok(TARGET_SPIRV),
        "v3d" => Ok(TARGET_V3D_QPU),
        "replay" => Ok(TARGET_REPLAY),
        other => Err(Error::Config(format!(
            "unknown target `{other}` (wgsl|spirv|v3d|replay)"
        ))),
    }
}

fn target_name(isa: u32) -> &'static str {
    match isa {
        TARGET_WGSL => "wgsl",
        TARGET_SPIRV => "spirv",
        TARGET_V3D_QPU => "v3d",
        TARGET_REPLAY => "replay",
        TARGET_NONE => "none",
        _ => "unknown",
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        BIND_STORAGE => "storage",
        BIND_UNIFORM => "uniform",
        BIND_TEXTURE => "texture",
        BIND_SAMPLER => "sampler",
        BIND_VERTEX => "vertex",
        BIND_INDEX => "index",
        _ => "unknown",
    }
}

fn access_name(access: u8) -> &'static str {
    match (
        access & BIND_ACCESS_READ != 0,
        access & BIND_ACCESS_WRITE != 0,
    ) {
        (true, true) => "rw",
        (true, false) => "r",
        (false, true) => "w",
        (false, false) => "none",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 16-byte toolchain identity from hex, or hash a free-text label
/// into one.
///
/// Two forms because both are honest answers to "which compiler produced
/// this": a build system that already has a toolchain digest passes it; a
/// human passes the version string they invoked, and the hash of that string
/// is at least a stable identity for that exact spelling. What is not offered
/// is leaving it zero by default while pretending it means something.
fn parse_toolchain(spec: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    if spec.len() == 32 && spec.chars().all(|c| c.is_ascii_hexdigit()) {
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&spec[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::Config(format!("toolchain `{spec}`: bad hex")))?;
        }
        return Ok(id);
    }
    let digest = crate::gpu_contract::sha256(spec.as_bytes());
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

/// `fluxor gpu pack` — build a program pack from an artifact and a manifest
/// described on the command line.
#[allow(
    clippy::too_many_arguments,
    reason = "these are the manifest's fields; a struct here would exist only \
              to be destructured at the one call site"
)]
pub fn cmd_pack(
    artifact_path: &Path,
    output: &Path,
    entry: &str,
    target: &str,
    target_rev: u32,
    toolchain: Option<&str>,
    workgroup: &str,
    min_align: u32,
    bindings: &[String],
    budget_resident: u64,
    budget_scratch: u64,
) -> Result<()> {
    let artifact = std::fs::read(artifact_path)?;
    if artifact.is_empty() {
        return Err(Error::Config(format!(
            "{}: artifact is empty",
            artifact_path.display()
        )));
    }
    let wg: Vec<u32> = workgroup
        .split(['x', ','])
        .map(|d| d.trim().parse::<u32>())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Config(format!("workgroup `{workgroup}`: expected e.g. 64x1x1")))?;
    if wg.len() != 3 {
        return Err(Error::Config(format!(
            "workgroup `{workgroup}`: expected three dimensions, e.g. 64x1x1"
        )));
    }
    if bindings.len() > MAX_BINDINGS {
        return Err(Error::Config(format!(
            "{} bindings declared; the envelope allows {MAX_BINDINGS}",
            bindings.len()
        )));
    }
    let parsed: Vec<PackBinding> = bindings
        .iter()
        .map(|b| parse_binding(b))
        .collect::<Result<_>>()?;
    check_binding_set(&parsed)?;

    let mut spec = PackSpec::wgsl();
    spec.target_isa = parse_target(target)?;
    spec.target_rev = target_rev;
    spec.workgroup = [wg[0], wg[1], wg[2]];
    spec.min_align = min_align;
    spec.budget_resident = budget_resident;
    spec.budget_scratch = budget_scratch;
    spec.toolchain = parse_toolchain(toolchain.unwrap_or("unrecorded"))?;

    let mut out = vec![0u8; encoded_len(entry, parsed.len(), artifact.len())];
    let n = encode(&mut out, &spec, entry, &parsed, &artifact).ok_or_else(|| {
        Error::Config(
            "the manifest does not describe a valid pack — check the entry \
             point, the workgroup shape and that alignment is a power of two"
                .into(),
        )
    })?;
    out.truncate(n);

    // Round-trip before writing. Every user-caused refusal was already named
    // above, so anything the decoder still objects to is a defect in this
    // tool — and saying which kind it is beats leaving the reader to guess.
    let pack = decode(&out).map_err(|e| {
        Error::Config(format!(
            "internal: the built pack does not decode ({}) — this is a bug in \
             `fluxor gpu pack`, not in the inputs",
            pack_reason_name(e)
        ))
    })?;

    std::fs::write(output, &out)?;
    println!("wrote {} ({} bytes)", output.display(), out.len());
    println!("  artifact digest {}", hex(&pack.artifact_digest));
    println!("  pack identity   {}", hex(&pack.identity()));
    Ok(())
}

/// `fluxor gpu caps` — write the capability record of a provider that is
/// always available.
///
/// Validating a pack needs a device's published facts, and the null/replay
/// provider is the one device every checkout has. Emitting its record lets a
/// build gate check every pack it produces without a GPU — and, because the
/// record comes from the same `encode_caps` the running provider answers
/// with, without a second description of it either.
pub fn cmd_caps(provider: &str, output: &Path) -> Result<()> {
    if provider != "replay" {
        return Err(Error::Config(format!(
            "unknown provider `{provider}`: only `replay` has facts this tool \
             can state without a device present. For any other backend, \
             capture the `OUT_CAPS` record its provider answers with."
        )));
    }
    let caps = crate::gpu_contract::replay_caps();
    std::fs::write(output, caps)?;
    println!(
        "wrote {} ({} bytes) — the replay provider's published facts",
        output.display(),
        CAPS_LEN
    );
    Ok(())
}

/// `fluxor gpu inspect` — print a pack's manifest.
pub fn cmd_inspect(path: &Path, json: bool) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let pack = decode(&bytes).map_err(|e| {
        Error::Config(format!(
            "{}: not a valid pack ({})",
            path.display(),
            pack_reason_name(e)
        ))
    })?;

    if json {
        let bindings: Vec<serde_json::Value> = (0..pack.binding_count)
            .filter_map(|i| pack.binding(i))
            .map(|b| {
                serde_json::json!({
                    "slot": b.slot,
                    "kind": kind_name(b.kind),
                    "access": access_name(b.access),
                    "min_size": b.min_size,
                    "align": b.align,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": path.display().to_string(),
                "bytes": bytes.len(),
                "target": target_name(pack.target_isa),
                "target_rev": pack.target_rev,
                "entry": String::from_utf8_lossy(pack.entry()),
                "artifact_bytes": pack.artifact().len(),
                "artifact_digest": hex(&pack.artifact_digest),
                "pack_identity": hex(&pack.identity()),
                "toolchain": hex(&pack.toolchain),
                "workgroup": pack.workgroup,
                "min_align": pack.min_align,
                "feature_req": pack.feature_req,
                "arith_ops_req": pack.arith_ops_req,
                "arith_types_req": pack.arith_types_req,
                "arith_native_req": pack.arith_native_req,
                "budget_resident": pack.budget_resident,
                "budget_scratch": pack.budget_scratch,
                "bindings": bindings,
            }))?
        );
        return Ok(());
    }

    println!("{} ({} bytes)", path.display(), bytes.len());
    println!(
        "  target        {} rev {}",
        target_name(pack.target_isa),
        pack.target_rev
    );
    println!("  entry         {}", String::from_utf8_lossy(pack.entry()));
    println!("  artifact      {} bytes", pack.artifact().len());
    println!("  digest        {}", hex(&pack.artifact_digest));
    // Two digests, never one: the artifact digest is content identity, the
    // pack identity is what a pipeline cache is keyed on. Packs sharing bytes
    // but declaring different binding access are different programs.
    println!("  identity      {}", hex(&pack.identity()));
    println!("  toolchain     {}", hex(&pack.toolchain));
    println!(
        "  workgroup     {}x{}x{}  align {}",
        pack.workgroup[0], pack.workgroup[1], pack.workgroup[2], pack.min_align
    );
    if pack.feature_req != 0 || pack.arith_ops_req != 0 {
        println!(
            "  requires      features {:#010x}  ops {:#010x}",
            pack.feature_req, pack.arith_ops_req
        );
    }
    if pack.arith_types_req != 0 || pack.arith_native_req != 0 {
        // Printed apart because they are different demands: "this type must
        // work" and "this type must not be emulated".
        println!(
            "  arithmetic    computes {:#06x}  natively {:#06x}",
            pack.arith_types_req, pack.arith_native_req
        );
    }
    if pack.budget_resident != 0 || pack.budget_scratch != 0 {
        println!(
            "  budget        resident {} B  scratch {} B",
            pack.budget_resident, pack.budget_scratch
        );
    }
    println!("  bindings      {}", pack.binding_count);
    for i in 0..pack.binding_count {
        if let Some(b) = pack.binding(i) {
            println!(
                "    slot {:<3} {:<8} {:<4} min {:<8} align {}",
                b.slot,
                kind_name(b.kind),
                access_name(b.access),
                b.min_size,
                b.align
            );
        }
    }
    Ok(())
}

/// `fluxor gpu validate` — check a pack against a device's published facts.
pub fn cmd_validate(path: &Path, caps_path: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let caps = std::fs::read(caps_path)?;
    if caps.len() < CAPS_LEN {
        return Err(Error::Config(format!(
            "{}: a capability record is {CAPS_LEN} bytes, this file is {}",
            caps_path.display(),
            caps.len()
        )));
    }
    let limits = pack_limits_from_caps(&caps)
        .ok_or_else(|| Error::Config(format!("{}: unreadable", caps_path.display())))?;

    // Structure first, always. A device check on an unvalidated header would
    // be reading offsets the pack chose.
    let pack = decode(&bytes).map_err(|e| {
        Error::Config(format!(
            "{}: not a valid pack ({})",
            path.display(),
            pack_reason_name(e)
        ))
    })?;
    validate(&pack, &limits).map_err(|e| {
        Error::Config(format!(
            "{} is not acceptable to this device: {}",
            path.display(),
            explain(e, &pack, &limits)
        ))
    })?;

    println!(
        "{}: acceptable — target {} rev {}, {} binding(s), workgroup {}x{}x{}",
        path.display(),
        target_name(pack.target_isa),
        pack.target_rev,
        pack.binding_count,
        pack.workgroup[0],
        pack.workgroup[1],
        pack.workgroup[2],
    );
    // Offline acceptance is a pre-check, not admission. Say so, so nobody
    // reads this line as "the device will run it".
    println!("  (a pre-check against published facts; the provider still validates at load)");
    Ok(())
}

/// Turn a refusal into the specific fact that caused it.
///
/// A bare reason name sends the reader to the source; naming the value the
/// device published beside the value the pack asked for ends the question.
fn explain(
    reason: u16,
    pack: &crate::gpu_contract::Pack<'_>,
    limits: &crate::gpu_contract::PackLimits,
) -> String {
    let base = pack_reason_name(reason);
    match reason {
        crate::gpu_contract::PACK_BAD_TARGET => {
            let accepted: Vec<&str> = limits
                .targets
                .iter()
                .filter(|t| **t != TARGET_NONE)
                .map(|t| target_name(*t))
                .collect();
            format!(
                "{base} — pack targets {}, device accepts [{}]",
                target_name(pack.target_isa),
                accepted.join(", ")
            )
        }
        crate::gpu_contract::PACK_BAD_BINDING => {
            if pack.min_align < limits.min_align {
                format!(
                    "{base} — pack declares {}-byte alignment, device granularity is {}",
                    pack.min_align, limits.min_align
                )
            } else if pack.binding_count as u32 > limits.max_bindings {
                format!(
                    "{base} — {} bindings declared, device supports {}",
                    pack.binding_count, limits.max_bindings
                )
            } else {
                format!("{base} — a binding's slot or alignment is outside the device's limits")
            }
        }
        crate::gpu_contract::PACK_UNSUPPORTED => {
            let missing_features = pack.feature_req & !limits.features;
            let missing_ops = pack.arith_ops_req & !limits.arith_ops;
            let mut emulated = Vec::new();
            for t in 0..ARITH_TYPE_COUNT {
                let bit = 1u32 << t;
                if pack.arith_native_req & bit != 0
                    && limits.arith_types[t] & crate::gpu_contract::ARITH_NATIVE == 0
                {
                    emulated.push(t);
                }
            }
            format!(
                "{base} — missing features {missing_features:#010x}, missing ops \
                 {missing_ops:#010x}, non-native types {emulated:?}"
            )
        }
        crate::gpu_contract::PACK_OVER_LIMIT => format!(
            "{base} — workgroup {}x{}x{} against {}x{}x{} (max {} invocations), \
             budget {} B against {} B",
            pack.workgroup[0],
            pack.workgroup[1],
            pack.workgroup[2],
            limits.max_workgroup[0],
            limits.max_workgroup[1],
            limits.max_workgroup[2],
            limits.max_workgroup_invocations,
            pack.budget_resident,
            limits.max_resident_bytes,
        ),
        _ => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_spec_parses_its_five_mandatory_fields() {
        let b = parse_binding("3:storage:rw:256:64").expect("parses");
        assert_eq!(b.slot, 3);
        assert_eq!(b.kind, BIND_STORAGE);
        assert_eq!(b.access, BIND_ACCESS_READ | BIND_ACCESS_WRITE);
        assert_eq!(b.min_size, 256);
        assert_eq!(b.align, 64);
    }

    #[test]
    fn a_malformed_binding_spec_says_what_was_expected() {
        for spec in ["0:storage:r:64", "0:storage:r:64:64:8", "x:storage:r:64:64"] {
            assert!(parse_binding(spec).is_err(), "{spec} should not parse");
        }
        let err = parse_binding("0:buffer:r:64:64").unwrap_err().to_string();
        assert!(err.contains("unknown kind"), "{err}");
        let err = parse_binding("0:storage:x:64:64").unwrap_err().to_string();
        assert!(err.contains("unknown access"), "{err}");
    }

    #[test]
    fn the_binding_set_is_checked_before_the_pack_is_built() {
        // Each of these would be caught by the decoder too. Catching them here
        // is what makes the message name the typo instead of the tool.
        let dup = [
            parse_binding("0:storage:r:0:64").unwrap(),
            parse_binding("0:storage:w:0:64").unwrap(),
        ];
        assert!(check_binding_set(&dup)
            .unwrap_err()
            .to_string()
            .contains("declared twice"));

        let bad_align = [parse_binding("0:storage:r:0:96").unwrap()];
        assert!(check_binding_set(&bad_align)
            .unwrap_err()
            .to_string()
            .contains("power of two"));

        let writable_uniform = [parse_binding("0:uniform:w:0:64").unwrap()];
        assert!(check_binding_set(&writable_uniform)
            .unwrap_err()
            .to_string()
            .contains("cannot be written"));

        let fine = [
            parse_binding("0:storage:r:64:64").unwrap(),
            parse_binding("1:storage:w:64:64").unwrap(),
        ];
        assert!(check_binding_set(&fine).is_ok());
    }

    #[test]
    fn a_toolchain_is_recorded_either_way_but_never_silently_zero() {
        let from_hex = parse_toolchain("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(from_hex[0], 0);
        assert_eq!(from_hex[15], 0x0f);
        let hashed = parse_toolchain("naga-0.20").unwrap();
        assert_ne!(hashed, [0u8; 16]);
        // The same spelling is the same identity, or a pack could not be
        // traced back to the compiler that produced it.
        assert_eq!(hashed, parse_toolchain("naga-0.20").unwrap());
        assert_ne!(hashed, parse_toolchain("naga-0.21").unwrap());
    }

    #[test]
    fn the_replay_caps_record_round_trips_into_validator_limits() {
        let caps = crate::gpu_contract::replay_caps();
        assert_eq!(caps.len(), CAPS_LEN);
        let limits = pack_limits_from_caps(&caps).expect("readable");
        // The one target it accepts, and nothing else — a validator built from
        // this record refuses a WGSL pack for the same reason the device does.
        assert_eq!(limits.targets[0], TARGET_REPLAY);
        assert_eq!(limits.targets[1], TARGET_NONE);
        assert!(limits.min_align > 0);
        assert!(limits.max_bindings > 0);
    }

    #[test]
    fn a_pack_built_here_validates_against_the_provider_it_targets() {
        let dir = std::env::temp_dir().join("fluxor-gpu-pack-test");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("kernel.bin");
        std::fs::write(&artifact, b"replay-fixture-artifact").unwrap();
        let out = dir.join("kernel.fxgp");
        cmd_pack(
            &artifact,
            &out,
            "main",
            "replay",
            0,
            Some("test-toolchain"),
            "64x1x1",
            64,
            &[
                "0:storage:r:64:64".to_string(),
                "1:storage:w:64:64".to_string(),
            ],
            4096,
            0,
        )
        .expect("packs");

        let caps_path = dir.join("replay.caps");
        cmd_caps("replay", &caps_path).expect("caps");
        cmd_validate(&out, &caps_path).expect("the pack targets the device it was built for");

        // …and the same artifact declared for a target the device does not
        // accept is refused, naming both sides.
        let wgsl = dir.join("wgsl.fxgp");
        cmd_pack(
            &artifact,
            &wgsl,
            "main",
            "wgsl",
            0,
            None,
            "64x1x1",
            64,
            &[],
            0,
            0,
        )
        .expect("packs");
        let err = cmd_validate(&wgsl, &caps_path).unwrap_err().to_string();
        assert!(err.contains("pack targets wgsl"), "{err}");
        assert!(err.contains("device accepts [replay]"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_provider_is_refused_rather_than_guessed_at() {
        let err = cmd_caps("wgpu_native", &std::env::temp_dir().join("unused.caps"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("capture the `OUT_CAPS` record"), "{err}");
    }
}
