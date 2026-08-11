// SPDX-License-Identifier: GPL-3.0-or-later

//! Job state/result constants mirroring openQA's [`OpenQA::Jobs::Constants`],
//! pinned to revision `e72ffeb28b6f77bde9bfcb96f490dd3d7049bf6d`. Kept in one
//! place so consumers don't each hardcode "these are the running states" on
//! their own.
//!
//! `Unknown` (via `#[serde(other)]`) absorbs any state/result a newer server
//! introduces, so deserializing a response never breaks on an unrecognized
//! value; the original string is not preserved.
//!
//! Deliberately not ported from upstream:
//!
//! - `TAG_ID_COLUMN` — a SQL fragment for the server's own queries,
//!   meaningless to an API client.
//! - `TEST_NAME_ALLOWED_CHARS`, `TEST_NAME_ALLOWED_CHARS_PLUS_MINUS`,
//!   `TEST_NAME_REGEX` — server-side input validation expressed in Perl
//!   regex syntax; porting it would need a `regex` dependency to duplicate a
//!   check the server performs anyway.
//!
//! [`SCENARIO_KEYS`] and [`SCENARIO_WITH_MACHINE_KEYS`] have no
//! `OpenQA::Jobs::Constants` counterpart — they come from openQA's Python
//! client and are kept as-is.
//!
//! [`OpenQA::Jobs::Constants`]: https://github.com/os-autoinst/openQA/blob/e72ffeb28b6f77bde9bfcb96f490dd3d7049bf6d/lib/OpenQA/Jobs/Constants.pm

use serde::{Deserialize, Serialize};

/// The lifecycle state of an openQA job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobState {
    /// Queued, waiting for a worker.
    Scheduled,
    /// Assigned to a worker, not yet set up.
    Assigned,
    /// The worker is setting up the test environment.
    Setup,
    /// The test is executing.
    Running,
    /// The test finished; results are being uploaded.
    Uploading,
    /// The job was cancelled before it finished.
    Cancelled,
    /// The job finished (see [`JobResult`] for the verdict).
    Done,
    /// A state this crate doesn't recognize yet.
    #[serde(other)]
    Unknown,
}

impl JobState {
    /// Returns the wire representation of this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Assigned => "assigned",
            Self::Setup => "setup",
            Self::Running => "running",
            Self::Uploading => "uploading",
            Self::Cancelled => "cancelled",
            Self::Done => "done",
            Self::Unknown => "unknown",
        }
    }
}

/// All known job states, in lifecycle order.
pub const STATES: &[&str] = &[
    "scheduled",
    "assigned",
    "setup",
    "running",
    "uploading",
    "done",
    "cancelled",
];
/// States a job passes through before it's finished.
pub const PENDING_STATES: &[&str] = &["scheduled", "assigned", "setup", "running", "uploading"];
/// States in which a job is actively executing (as opposed to merely queued).
pub const EXECUTION_STATES: &[&str] = &["assigned", "setup", "running", "uploading"];
/// States before a job starts executing.
pub const PRE_EXECUTION_STATES: &[&str] = &["scheduled"];
/// States in which no worker has reported any updates or results yet.
pub const PRISTINE_STATES: &[&str] = &["scheduled", "assigned"];
/// States a job does not leave once reached.
pub const FINAL_STATES: &[&str] = &["done", "cancelled"];

/// Meta state for [`PRE_EXECUTION_STATES`].
pub const PRE_EXECUTION: &str = "pre_execution";
/// Meta state for [`EXECUTION_STATES`].
pub const EXECUTION: &str = "execution";
/// Meta state for [`FINAL_STATES`].
pub const FINAL: &str = "final";
/// The three meta states every job state falls into. See [`meta_state`].
pub const META_STATES: &[&str] = &[PRE_EXECUTION, EXECUTION, FINAL];

/// The outcome of a finished openQA job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobResult {
    /// No result yet (the job hasn't finished).
    None,
    /// The test passed.
    Passed,
    /// The test passed with soft failures.
    Softfailed,
    /// The test failed.
    Failed,
    /// The job didn't run to completion (e.g. a worker crashed).
    Incomplete,
    /// The job was skipped, e.g. due to a dependency failure.
    Skipped,
    /// The job was superseded by a newer one for the same scenario.
    Obsoleted,
    /// A parallel job this one depended on failed.
    ParallelFailed,
    /// A parallel job this one depended on was restarted.
    ParallelRestarted,
    /// A user cancelled the job.
    UserCancelled,
    /// A user restarted the job.
    UserRestarted,
    /// The job exceeded its configured timeout.
    TimeoutExceeded,
    /// A result this crate doesn't recognize yet.
    #[serde(other)]
    Unknown,
}

impl JobResult {
    /// Returns the wire representation of this result.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Passed => "passed",
            Self::Softfailed => "softfailed",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Skipped => "skipped",
            Self::Obsoleted => "obsoleted",
            Self::ParallelFailed => "parallel_failed",
            Self::ParallelRestarted => "parallel_restarted",
            Self::UserCancelled => "user_cancelled",
            Self::UserRestarted => "user_restarted",
            Self::TimeoutExceeded => "timeout_exceeded",
            Self::Unknown => "unknown",
        }
    }
}

/// All known job results.
pub const RESULTS: &[&str] = &[
    "none",
    "passed",
    "softfailed",
    "failed",
    "incomplete",
    "skipped",
    "obsoleted",
    "parallel_failed",
    "parallel_restarted",
    "user_cancelled",
    "user_restarted",
    "timeout_exceeded",
];
/// Results of a job that ran to completion, whatever the verdict.
pub const COMPLETE_RESULTS: &[&str] = &["passed", "softfailed", "failed"];
/// Results of a job that did not run to completion.
pub const NOT_COMPLETE_RESULTS: &[&str] = &["incomplete", "timeout_exceeded"];
/// Results of a job that was aborted rather than run to a verdict.
pub const ABORTED_RESULTS: &[&str] = &[
    "skipped",
    "obsoleted",
    "parallel_failed",
    "parallel_restarted",
    "user_cancelled",
    "user_restarted",
];
/// Results considered "not OK": `NOT_COMPLETE_RESULTS` + `ABORTED_RESULTS` + `failed`.
pub const NOT_OK_RESULTS: &[&str] = &[
    "failed",
    "incomplete",
    "timeout_exceeded",
    "skipped",
    "obsoleted",
    "parallel_failed",
    "parallel_restarted",
    "user_cancelled",
    "user_restarted",
];
/// Results considered "OK".
pub const OK_RESULTS: &[&str] = &["passed", "softfailed"];

/// Meta result for [`COMPLETE_RESULTS`].
pub const COMPLETE: &str = "complete";
/// Meta result for [`NOT_COMPLETE_RESULTS`].
pub const NOT_COMPLETE: &str = "not_complete";
/// Meta result for [`ABORTED_RESULTS`].
pub const ABORTED: &str = "aborted";
/// Meta result for [`OK_RESULTS`].
pub const OK: &str = "ok";
/// Meta result for [`NOT_OK_RESULTS`].
pub const NOT_OK: &str = "not_ok";
/// The five meta results used to group job results for presentation.
pub const META_RESULTS: &[&str] = &[COMPLETE, NOT_COMPLETE, ABORTED, OK, NOT_OK];

/// Maps each meta state to the job states it groups.
///
/// This is the presentation grouping from `META_MAPPING->{state}`; it agrees
/// with [`meta_state`] (every job state appears under exactly one meta
/// state, and both agree on which).
pub const META_MAPPING_STATE: &[(&str, &[&str])] = &[
    (PRE_EXECUTION, PRE_EXECUTION_STATES),
    (EXECUTION, EXECUTION_STATES),
    (FINAL, FINAL_STATES),
];
/// Maps each meta result to the job results it groups for presentation.
///
/// This is `META_MAPPING->{result}`, a *different* table from the one
/// backing [`meta_result`]: here every entry of [`COMPLETE_RESULTS`] is
/// grouped under `COMPLETE`, but `meta_result` maps each of those results to
/// itself instead. Do not use this table to implement `meta_result`.
pub const META_MAPPING_RESULT: &[(&str, &[&str])] = &[
    (COMPLETE, COMPLETE_RESULTS),
    (NOT_COMPLETE, NOT_COMPLETE_RESULTS),
    (ABORTED, ABORTED_RESULTS),
    (OK, OK_RESULTS),
    (NOT_OK, NOT_OK_RESULTS),
];

/// Result priority order for the overview page (worst first).
pub const OVERVIEW_STATUS_PRIORITY: &[&str] = &[
    "failed",
    "not_complete",
    "softfailed",
    "running",
    "scheduled",
    "passed",
    "aborted",
];
/// Result priority order for status aggregation (worst first).
pub const STATUS_PRIORITY: &[&str] = &[
    "failed",
    "not_complete",
    "softfailed",
    "aborted",
    "running",
    "scheduled",
    "none",
];
/// Default priority assigned to new jobs.
pub const DEFAULT_JOB_PRIORITY: u32 = 50;

/// Result log files expected in every job.
pub const COMMON_RESULT_LOG_FILES: &[&str] = &[
    "autoinst-log.txt",
    "worker-log.txt",
    "worker_packages.txt",
    "sut_packages.txt",
];
/// [`COMMON_RESULT_LOG_FILES`] plus `vars.json`.
pub const COMMON_RESULT_FILES: &[&str] = &[
    "autoinst-log.txt",
    "worker-log.txt",
    "worker_packages.txt",
    "sut_packages.txt",
    "vars.json",
];
/// Result files handled by log cleanup: [`COMMON_RESULT_LOG_FILES`] plus the
/// serial console and video-timing logs.
pub const RESULT_CLEANUP_LOG_FILES: &[&str] = &[
    "autoinst-log.txt",
    "worker-log.txt",
    "worker_packages.txt",
    "sut_packages.txt",
    "serial0.txt",
    "serial_terminal.txt",
    "serial_terminal_user.txt",
    "video_time.vtt",
];

/// The outcome of a single job module, as opposed to the overall job.
///
/// This overlaps [`JobState`] values (`Cancelled`, `Running`) as well as
/// [`JobResult`] values, so it is its own enum rather than a subset of
/// either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ModuleResult {
    /// The module was cancelled.
    Cancelled,
    /// The module failed.
    Failed,
    /// The module has no result yet.
    None,
    /// The module passed.
    Passed,
    /// The module is running.
    Running,
    /// The module was skipped.
    Skipped,
    /// The module passed with soft failures.
    Softfailed,
    /// A module result this crate doesn't recognize yet.
    #[serde(other)]
    Unknown,
}

impl ModuleResult {
    /// Returns the wire representation of this module result.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::None => "none",
            Self::Passed => "passed",
            Self::Running => "running",
            Self::Skipped => "skipped",
            Self::Softfailed => "softfailed",
            Self::Unknown => "unknown",
        }
    }
}

/// All known module results.
pub const MODULE_RESULTS: &[&str] = &[
    "cancelled",
    "failed",
    "none",
    "passed",
    "running",
    "skipped",
    "softfailed",
];

/// Classifies a job state into its meta state.
///
/// `scheduled` maps to [`PRE_EXECUTION`]; `assigned`/`setup`/`running`/
/// `uploading` map to [`EXECUTION`]; `done`/`cancelled` map to [`FINAL`].
/// An unrecognized state falls back to `"none"` — a [`JobResult`] constant
/// being reused as the fallback, matching upstream.
#[must_use]
pub fn meta_state(state: &str) -> &'static str {
    match state {
        "scheduled" => PRE_EXECUTION,
        "assigned" | "setup" | "running" | "uploading" => EXECUTION,
        "done" | "cancelled" => FINAL,
        _ => "none",
    }
}

/// Classifies a job result into its meta result.
///
/// Unlike [`META_MAPPING_RESULT`], entries of [`COMPLETE_RESULTS`] map to
/// **themselves** (`passed` → `passed`, not `passed` → `complete`).
/// [`NOT_COMPLETE_RESULTS`] map to [`NOT_COMPLETE`] and [`ABORTED_RESULTS`]
/// map to [`ABORTED`]. Everything else, including `"none"` itself, falls
/// back to `"none"`.
#[must_use]
pub fn meta_result(result: &str) -> &'static str {
    match result {
        "passed" => "passed",
        "softfailed" => "softfailed",
        "failed" => "failed",
        "incomplete" | "timeout_exceeded" => NOT_COMPLETE,
        "skipped" | "obsoleted" | "parallel_failed" | "parallel_restarted" | "user_cancelled"
        | "user_restarted" => ABORTED,
        _ => "none",
    }
}

/// Returns whether `result` is one of [`OK_RESULTS`].
#[must_use]
pub fn is_ok_result(result: &str) -> bool {
    OK_RESULTS.contains(&result)
}

/// Job settings keys that together identify a test scenario.
pub const SCENARIO_KEYS: &[&str] = &["DISTRI", "VERSION", "FLAVOR", "ARCH", "TEST"];
/// `SCENARIO_KEYS` plus `MACHINE`.
pub const SCENARIO_WITH_MACHINE_KEYS: &[&str] =
    &["DISTRI", "VERSION", "FLAVOR", "ARCH", "TEST", "MACHINE"];

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! roundtrip {
        ($name:ident, $ty:ty, $variant:expr, $str:expr) => {
            #[test]
            fn $name() {
                let value: $ty = $variant;
                assert_eq!(value.as_str(), $str);
                assert_eq!(
                    serde_json::to_value(value).unwrap(),
                    serde_json::json!($str)
                );
                let de: $ty = serde_json::from_value(serde_json::json!($str)).unwrap();
                assert_eq!(de, value);
            }
        };
    }

    roundtrip!(state_scheduled, JobState, JobState::Scheduled, "scheduled");
    roundtrip!(state_assigned, JobState, JobState::Assigned, "assigned");
    roundtrip!(state_setup, JobState, JobState::Setup, "setup");
    roundtrip!(state_running, JobState, JobState::Running, "running");
    roundtrip!(state_uploading, JobState, JobState::Uploading, "uploading");
    roundtrip!(state_cancelled, JobState, JobState::Cancelled, "cancelled");
    roundtrip!(state_done, JobState, JobState::Done, "done");

    roundtrip!(result_none, JobResult, JobResult::None, "none");
    roundtrip!(result_passed, JobResult, JobResult::Passed, "passed");
    roundtrip!(
        result_softfailed,
        JobResult,
        JobResult::Softfailed,
        "softfailed"
    );
    roundtrip!(result_failed, JobResult, JobResult::Failed, "failed");
    roundtrip!(
        result_incomplete,
        JobResult,
        JobResult::Incomplete,
        "incomplete"
    );
    roundtrip!(result_skipped, JobResult, JobResult::Skipped, "skipped");
    roundtrip!(
        result_obsoleted,
        JobResult,
        JobResult::Obsoleted,
        "obsoleted"
    );
    roundtrip!(
        result_parallel_failed,
        JobResult,
        JobResult::ParallelFailed,
        "parallel_failed"
    );
    roundtrip!(
        result_parallel_restarted,
        JobResult,
        JobResult::ParallelRestarted,
        "parallel_restarted"
    );
    roundtrip!(
        result_user_cancelled,
        JobResult,
        JobResult::UserCancelled,
        "user_cancelled"
    );
    roundtrip!(
        result_user_restarted,
        JobResult,
        JobResult::UserRestarted,
        "user_restarted"
    );
    roundtrip!(
        result_timeout_exceeded,
        JobResult,
        JobResult::TimeoutExceeded,
        "timeout_exceeded"
    );

    #[test]
    fn unrecognized_state_deserializes_to_unknown() {
        let de: JobState = serde_json::from_value(serde_json::json!("brand_new_state")).unwrap();
        assert_eq!(de, JobState::Unknown);
    }

    #[test]
    fn unrecognized_result_deserializes_to_unknown() {
        let de: JobResult = serde_json::from_value(serde_json::json!("brand_new_result")).unwrap();
        assert_eq!(de, JobResult::Unknown);
    }

    // Matches openQA's `const.py` tuples byte-for-byte.
    #[test]
    fn state_groups_match_openqa() {
        assert_eq!(
            STATES,
            [
                "scheduled",
                "assigned",
                "setup",
                "running",
                "uploading",
                "done",
                "cancelled"
            ]
        );
        assert_eq!(
            PENDING_STATES,
            ["scheduled", "assigned", "setup", "running", "uploading"]
        );
        assert_eq!(
            EXECUTION_STATES,
            ["assigned", "setup", "running", "uploading"]
        );
        assert_eq!(PRE_EXECUTION_STATES, ["scheduled"]);
        assert_eq!(PRISTINE_STATES, ["scheduled", "assigned"]);
        assert_eq!(FINAL_STATES, ["done", "cancelled"]);
        assert_eq!(META_STATES, ["pre_execution", "execution", "final"]);
    }

    #[test]
    fn result_groups_match_openqa() {
        assert_eq!(
            RESULTS,
            [
                "none",
                "passed",
                "softfailed",
                "failed",
                "incomplete",
                "skipped",
                "obsoleted",
                "parallel_failed",
                "parallel_restarted",
                "user_cancelled",
                "user_restarted",
                "timeout_exceeded",
            ]
        );
        assert_eq!(COMPLETE_RESULTS, ["passed", "softfailed", "failed"]);
        assert_eq!(NOT_COMPLETE_RESULTS, ["incomplete", "timeout_exceeded"]);
        assert_eq!(
            ABORTED_RESULTS,
            [
                "skipped",
                "obsoleted",
                "parallel_failed",
                "parallel_restarted",
                "user_cancelled",
                "user_restarted",
            ]
        );
        assert_eq!(
            NOT_OK_RESULTS,
            [
                "failed",
                "incomplete",
                "timeout_exceeded",
                "skipped",
                "obsoleted",
                "parallel_failed",
                "parallel_restarted",
                "user_cancelled",
                "user_restarted",
            ]
        );
        assert_eq!(OK_RESULTS, ["passed", "softfailed"]);
        assert_eq!(
            META_RESULTS,
            ["complete", "not_complete", "aborted", "ok", "not_ok"]
        );
        assert_eq!(
            MODULE_RESULTS,
            [
                "cancelled",
                "failed",
                "none",
                "passed",
                "running",
                "skipped",
                "softfailed",
            ]
        );
    }

    #[test]
    fn priority_and_result_files_match_openqa() {
        assert_eq!(
            OVERVIEW_STATUS_PRIORITY,
            [
                "failed",
                "not_complete",
                "softfailed",
                "running",
                "scheduled",
                "passed",
                "aborted",
            ]
        );
        assert_eq!(
            STATUS_PRIORITY,
            [
                "failed",
                "not_complete",
                "softfailed",
                "aborted",
                "running",
                "scheduled",
                "none",
            ]
        );
        assert_eq!(DEFAULT_JOB_PRIORITY, 50);
        assert_eq!(
            COMMON_RESULT_LOG_FILES,
            [
                "autoinst-log.txt",
                "worker-log.txt",
                "worker_packages.txt",
                "sut_packages.txt",
            ]
        );
        assert!(COMMON_RESULT_FILES.starts_with(COMMON_RESULT_LOG_FILES));
        assert_eq!(COMMON_RESULT_FILES.last(), Some(&"vars.json"));
        assert!(RESULT_CLEANUP_LOG_FILES.starts_with(COMMON_RESULT_LOG_FILES));
        assert_eq!(
            &RESULT_CLEANUP_LOG_FILES[COMMON_RESULT_LOG_FILES.len()..],
            [
                "serial0.txt",
                "serial_terminal.txt",
                "serial_terminal_user.txt",
                "video_time.vtt",
            ]
        );
    }

    #[test]
    fn meta_mapping_covers_every_state_and_result() {
        for state in STATES {
            let groups: Vec<_> = META_MAPPING_STATE
                .iter()
                .filter(|(_, states)| states.contains(state))
                .collect();
            assert_eq!(groups.len(), 1, "{state} should be in exactly one group");
        }
        for result in RESULTS {
            if *result == "none" {
                continue;
            }
            let groups: Vec<_> = [COMPLETE_RESULTS, NOT_COMPLETE_RESULTS, ABORTED_RESULTS]
                .iter()
                .filter(|group| group.contains(result))
                .collect();
            assert_eq!(groups.len(), 1, "{result} should be in exactly one group");
        }
    }

    #[test]
    fn meta_state_agrees_with_mapping() {
        for state in STATES {
            let (key, _) = META_MAPPING_STATE
                .iter()
                .find(|(_, states)| states.contains(state))
                .unwrap();
            assert_eq!(meta_state(state), *key);
        }
    }

    #[test]
    fn meta_result_maps_complete_results_to_themselves() {
        assert_eq!(meta_result("passed"), "passed");
        assert_eq!(meta_result("softfailed"), "softfailed");
        assert_eq!(meta_result("failed"), "failed");
    }

    #[test]
    fn meta_result_classifies_the_remaining_results() {
        for result in NOT_COMPLETE_RESULTS {
            assert_eq!(meta_result(result), NOT_COMPLETE);
        }
        for result in ABORTED_RESULTS {
            assert_eq!(meta_result(result), ABORTED);
        }
    }

    #[test]
    fn unknown_values_fall_back_to_none() {
        assert_eq!(meta_state("brand_new"), "none");
        assert_eq!(meta_result("brand_new"), "none");
        assert_eq!(meta_result("none"), "none");
    }

    #[test]
    fn is_ok_result_matches_ok_results() {
        for result in OK_RESULTS {
            assert!(is_ok_result(result));
        }
        for result in NOT_OK_RESULTS {
            assert!(!is_ok_result(result));
        }
        assert!(!is_ok_result("none"));
    }

    roundtrip!(
        module_result_cancelled,
        ModuleResult,
        ModuleResult::Cancelled,
        "cancelled"
    );
    roundtrip!(
        module_result_failed,
        ModuleResult,
        ModuleResult::Failed,
        "failed"
    );
    roundtrip!(module_result_none, ModuleResult, ModuleResult::None, "none");
    roundtrip!(
        module_result_passed,
        ModuleResult,
        ModuleResult::Passed,
        "passed"
    );
    roundtrip!(
        module_result_running,
        ModuleResult,
        ModuleResult::Running,
        "running"
    );
    roundtrip!(
        module_result_skipped,
        ModuleResult,
        ModuleResult::Skipped,
        "skipped"
    );
    roundtrip!(
        module_result_softfailed,
        ModuleResult,
        ModuleResult::Softfailed,
        "softfailed"
    );

    #[test]
    fn unrecognized_module_result_deserializes_to_unknown() {
        let de: ModuleResult =
            serde_json::from_value(serde_json::json!("brand_new_module_result")).unwrap();
        assert_eq!(de, ModuleResult::Unknown);
    }

    #[test]
    fn scenario_keys_match_openqa() {
        assert_eq!(
            SCENARIO_KEYS,
            ["DISTRI", "VERSION", "FLAVOR", "ARCH", "TEST"]
        );
        assert_eq!(
            SCENARIO_WITH_MACHINE_KEYS,
            ["DISTRI", "VERSION", "FLAVOR", "ARCH", "TEST", "MACHINE"]
        );
    }
}
