//! Hardware-rig contract — types, parsers, validators, and the backend
//! subprocess dispatcher per `.context/rfc_hardware_rig.md`.
//!
//! Layout:
//!
//! * `vocab`    — capability catalog (fixed)
//! * `board`    — public board contract (`[rig]` in targets/boards/*.toml)
//! * `scenario` — public scenario contract (`tests/hardware/*.toml`)
//! * `profile`  — private rig profile (`~/.config/fluxor/labs/…`)
//! * `project`  — project build descriptor (`rig.toml` under
//!   `$XDG_CONFIG_HOME/fluxor/projects/<name>/`, or an in-tree
//!   `.fluxor-rig.toml`)
//! * `secret`   — `${env:…}` / `${file:…}` / `${keychain:…}` resolution
//! * `validate` — cross-schema validator
//! * `plan`     — resolved, side-effect-free lifecycle description
//! * `lock`     — rig lockfile contract
//! * `record`   — run record (hashes + verdict)
//! * `events`   — in-process event types consumed by the matcher
//! * `matcher`  — pass/fail rule engine
//! * `backend`  — subprocess protocol (discovery, actuator, transport);
//!   every concrete mechanism (kasa, uhubctl, netboot, termios, …) is
//!   an external executable, so this crate carries none of that knowledge.
//! * `run`      — orchestrator that speaks `backend` to execute a plan.
//! * `cli`      — `fluxor rig …` subcommand entry points.

pub mod backend;
pub mod board;
pub mod cli;
pub mod events;
pub mod lock;
pub mod matcher;
pub mod plan;
pub mod profile;
pub mod project;
pub mod record;
pub mod run;
pub mod scenario;
pub mod secret;
pub mod validate;
pub mod vocab;

#[cfg(test)]
pub(crate) mod test_utils;

pub use board::{
    load_board_rig, parse_board_rig_str, resolve_board_rig, BoardRig, BoardSource,
};
pub use events::{DeployEvent, RunEvent};
pub use lock::{
    acquire as acquire_lock, default_lock_path, AcquireOutcome, LockConflict, LockGuard, LockOwner,
};
pub use plan::{build_plan, ArtifactPlan, Plan, PlanInputs};
pub use profile::{
    default_profile_path, enumerate_rigs, load_profile, parse_profile_str, BindingTable,
    BindingValue, RigMeta, RigProfile,
};
pub use project::{BuildOutput, BuildRecipe, ProjectDescriptor, PROJECT_DESCRIPTOR};
pub use record::{canonical_profile, hash_artifact_bundle, hash_artifact_file, hash_profile, RunRecord, Verdict};
pub use scenario::{load_scenario, parse_scenario_str, ObservationRule, Scenario};
pub use secret::{resolve as resolve_secret, Secret, REDACTED};
pub use validate::{validate_scenario_against_board, validate_tags, RigValidation};
pub use vocab::{validate_artifact_class, Capability, Surface, ARTIFACT_CLASSES};
