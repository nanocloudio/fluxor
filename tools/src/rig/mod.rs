//! Hardware-rig contract — types, parsers, validators, and the backend
//! subprocess dispatcher.
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
//! * `secret`   — `${env:…}` / `${file:…}` resolution
//! * `validate` — cross-schema validators
//! * `plan`     — resolved, side-effect-free lifecycle description
//! * `lock`     — rig lockfile and teardown marker
//! * `record`   — run record (hashes + verdict + reports + teardown)
//! * `events`   — in-process event types consumed by the matcher
//! * `matcher`  — pass/fail/expect rule engine
//! * `backend`  — subprocess protocol (discovery, actuator, transport);
//!   every concrete mechanism (a smart plug, a USB hub, a TFTP root, a
//!   tty, a cloud) is an external executable, so this crate carries none
//!   of that knowledge.
//! * `run`      — orchestrator that speaks `backend` to execute a plan,
//!   and tears a rig down whatever happened.
//! * `cli`      — `fluxor rig …` subcommand entry points.
//!
//! Test doubles for the backends live in `testdata/` and are never
//! installed.

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
pub mod template;
pub mod validate;
pub mod vocab;

#[cfg(test)]
pub(crate) mod test_utils;

pub use board::{load_board_rig, parse_board_rig_str, resolve_board_rig, BoardRig, BoardSource};
pub use events::{DeployEvent, RunEvent};
pub use lock::{
    acquire as acquire_lock, default_lock_path, ensure_state_dir, marker_path_for, rig_state_root,
    state_dir_for, AcquireOutcome, LockConflict, LockGuard, LockOwner, TeardownMarker,
};
pub use plan::{build_plan, ArtifactPlan, Plan, PlanInputs};
pub use profile::{
    default_profile_path, enumerate_labs, enumerate_rigs, is_secret_key, load_profile,
    parse_profile_str, BindingTable, BindingValue, RigMeta, RigProfile,
};
pub use project::{BuildOutput, BuildRecipe, ProjectDescriptor, PROJECT_DESCRIPTOR};
pub use record::{
    canonical_profile, hash_artifact_bundle, hash_artifact_file, hash_profile, ActuatorRecord,
    GitIdentity, Reports, RunRecord, TeardownRecord, Verdict,
};
pub use scenario::{load_scenario, parse_scenario_str, ExpectRule, ObservationRule, Scenario};
pub use secret::{resolve as resolve_secret, Secret, REDACTED};
pub use validate::{
    check_profile_against_board, validate_scenario_against_board, validate_tags, RigValidation,
};
pub use vocab::{validate_artifact_class, Capability, Surface, ARTIFACT_CLASSES};
