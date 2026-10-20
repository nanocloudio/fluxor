//! Rig capability vocabulary — the canonical list of surfaces and capability
//! names for a hardware rig.
//!
//! Boards declare which capabilities they can support; scenarios declare which
//! capabilities they require. The vocabulary is fixed: adding a new capability
//! is a vocabulary change, not a user-extensible plugin.
//!
//! Capability-valued fields use fully qualified names everywhere
//! (`deploy.netboot_tftp`, `console.serial`, `power.cycle`). No alias mapping,
//! no fuzzy matching — validation is exact string membership.

use crate::error::{Error, Result};

/// Rig surfaces. Three kinds:
///   - actuation / transport: power, deploy, console, telemetry
///   - evaluation:            observe
///   - coordination:          rig (rig.claim / rig.release / rig.lock),
///     which the harness provides to every board
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Surface {
    Power,
    Deploy,
    Console,
    Telemetry,
    Observe,
    Rig,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Power => "power",
            Self::Deploy => "deploy",
            Self::Console => "console",
            Self::Telemetry => "telemetry",
            Self::Observe => "observe",
            Self::Rig => "rig",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "power" => Some(Self::Power),
            "deploy" => Some(Self::Deploy),
            "console" => Some(Self::Console),
            "telemetry" => Some(Self::Telemetry),
            "observe" => Some(Self::Observe),
            "rig" => Some(Self::Rig),
            _ => None,
        }
    }

    /// Capabilities defined under this surface.
    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Power => &["power.on", "power.off", "power.cycle"],
            Self::Deploy => &[
                "deploy.uf2_mount",
                "deploy.picotool",
                "deploy.swd",
                "deploy.sd_image_writer",
                "deploy.bootfs_copy",
                "deploy.netboot_tftp",
                "deploy.ssh_stage_reboot",
                // A UEFI disk image becomes an AMI (EBS snapshot, then
                // RegisterImage); the machine is the next `power.on`.
                "deploy.ec2_ami",
                // A hosted bundle disk becomes an EBS snapshot that the
                // instance mounts beside a stock Linux image.
                "deploy.ec2_hosted",
                // A UEFI disk image gets a per-run qcow2 overlay for QEMU.
                "deploy.qemu_disk",
            ],
            Self::Console => &[
                "console.serial",
                "console.usb_cdc",
                "console.netconsole",
                // The EC2 serial console, over SSH with a per-run key.
                "console.ec2_serial",
                // A QEMU serial chardev's logfile, from its first byte.
                "console.qemu_serial",
            ],
            Self::Telemetry => &[
                "telemetry.monitor_udp",
                // The telemetry ring over a QEMU virtio-console chardev.
                "telemetry.qemu_virtio",
            ],
            Self::Observe => &[
                "observe.console_regex",
                "observe.monitor_stream",
                "observe.netboot_fetch",
                "observe.udp_capture",
                "observe.usb_enumeration",
                "observe.https_load",
                // The protocol-agnostic load probe, beside
                // `observe.https_load`. The backend picks the protocol
                // (h1 / h2c / ws / grpc, plaintext or TLS) from its
                // profile binding, so a scenario can assert on any protocol
                // a project owns without this vocabulary growing a name per
                // protocol. The probe lives with whoever owns the
                // protocols: a backend is an executable on the discovery
                // path.
                "observe.proto_load",
                // The transport probe, as distinct from `proto_load`'s
                // protocol probes. Every protocol arrives through a stack
                // that includes somebody else's module, so when a protocol
                // scenario fails its output cannot say whether the fault is
                // in the transport or above it. This one carries no
                // protocol at all — it drives QUIC streams against a
                // `mux_echo` and asserts only what a transport owes its
                // application.
                "observe.quic_mux",
                // TLS 1.3 handshakes and an echo above them, nothing else,
                // so a change of identity (an RSA key) is measured as the
                // handshake it changes.
                "observe.tls_load",
                // A packet capture delivered into `run_dir/network/`. Who
                // captures (a bench host, the emulator's own tap) is the
                // backend's business.
                "observe.pcap",
            ],
            Self::Rig => &["rig.claim", "rig.release", "rig.lock"],
        }
    }
}

/// A fully qualified capability identifier, e.g. `deploy.netboot_tftp`.
///
/// The parser rejects unknown surfaces, unknown capabilities, and unqualified
/// names (`"cycle"` rather than `"power.cycle"`). Capabilities have a total
/// order derived from their string name for use as map keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability {
    surface: Surface,
    name: &'static str,
}

impl Capability {
    pub fn parse(s: &str) -> Result<Self> {
        let (surface_str, _rest) = s.split_once('.').ok_or_else(|| {
            Error::Config(format!(
                "rig capability '{s}' is not fully qualified (expected 'surface.name', \
                 e.g. 'power.cycle' or 'deploy.netboot_tftp')"
            ))
        })?;
        let surface = Surface::parse(surface_str).ok_or_else(|| {
            Error::Config(format!(
                "rig capability '{s}': unknown surface '{surface_str}' \
                 (valid: power, deploy, console, telemetry, observe, rig)"
            ))
        })?;
        for &cap in surface.capabilities() {
            if cap == s {
                return Ok(Self { surface, name: cap });
            }
        }
        Err(Error::Config(format!(
            "rig capability '{s}': unknown under surface '{}' (valid: {:?})",
            surface.as_str(),
            surface.capabilities()
        )))
    }

    pub fn surface(self) -> Surface {
        self.surface
    }

    pub fn as_str(self) -> &'static str {
        self.name
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// Valid artifact shapes a board can declare in `[rig].artifact`.
///
/// Kept as a closed set for the same reason capabilities are closed: a board
/// that produces something genuinely new should extend this list, not invent
/// a private string convention.
pub const ARTIFACT_CLASSES: &[&str] = &[
    "uf2",
    "kernel8_img",
    "boot_bundle",
    // A GPT disk image with one FAT ESP: the UEFI loader and the packed
    // kernel image. What a cloud or an emulator boots.
    "uefi_disk",
    // A small FAT disk image carrying a hosted runtime, its config and
    // modules, for a machine that already runs an OS.
    "hosted_bundle",
];

/// Every class but `boot_bundle` is one file; a recipe that produces a
/// directory can only serve a bundle class.
pub fn artifact_class_is_single_file(class: &str) -> bool {
    class != "boot_bundle"
}

pub fn validate_artifact_class(s: &str) -> Result<()> {
    if ARTIFACT_CLASSES.contains(&s) {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "rig artifact '{s}' is not a known class (valid: {ARTIFACT_CLASSES:?})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_and_emulator_names_are_in_the_vocabulary() {
        for name in [
            "deploy.ec2_ami",
            "deploy.ec2_hosted",
            "deploy.qemu_disk",
            "console.ec2_serial",
            "console.qemu_serial",
            "telemetry.qemu_virtio",
            "observe.pcap",
        ] {
            let c = Capability::parse(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(c.as_str(), name);
        }
        for class in ["uefi_disk", "hosted_bundle"] {
            validate_artifact_class(class).unwrap();
            assert!(artifact_class_is_single_file(class));
        }
        assert!(!artifact_class_is_single_file("boot_bundle"));
    }

    #[test]
    fn parse_known_capability() {
        let c = Capability::parse("deploy.netboot_tftp").unwrap();
        assert_eq!(c.surface(), Surface::Deploy);
        assert_eq!(c.as_str(), "deploy.netboot_tftp");
    }

    #[test]
    fn unqualified_rejected() {
        assert!(Capability::parse("cycle").is_err());
    }

    #[test]
    fn unknown_surface_rejected() {
        assert!(Capability::parse("bogus.op").is_err());
    }

    #[test]
    fn unknown_capability_rejected() {
        assert!(Capability::parse("power.hammer").is_err());
    }

    #[test]
    fn no_fuzzy_match() {
        // No alias mapping: 'uart' is not 'console.serial'.
        assert!(Capability::parse("console.uart").is_err());
        assert!(Capability::parse("uart").is_err());
    }

    #[test]
    fn every_listed_capability_parses() {
        for surface in [
            Surface::Power,
            Surface::Deploy,
            Surface::Console,
            Surface::Telemetry,
            Surface::Observe,
            Surface::Rig,
        ] {
            for &name in surface.capabilities() {
                let c = Capability::parse(name).expect(name);
                assert_eq!(c.surface(), surface);
                assert_eq!(c.as_str(), name);
            }
        }
    }

    #[test]
    fn artifact_classes() {
        assert!(validate_artifact_class("uf2").is_ok());
        assert!(validate_artifact_class("boot_bundle").is_ok());
        assert!(validate_artifact_class("exe").is_err());
    }
}
