// SPDX-License-Identifier: GPL-3.0-or-later

//! Job state/result constants duplicated from openQA, mirroring the Python
//! client's `const.py`. Kept in one place so consumers don't each hardcode
//! "these are the running states" on their own.
//!
//! `Unknown` (via `#[serde(other)]`) absorbs any state/result a newer server
//! introduces, so deserializing a response never breaks on an unrecognized
//! value; the original string is not preserved.

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

/// All known job states.
pub const STATES: &[&str] = &[
    "scheduled",
    "setup",
    "running",
    "cancelled",
    "done",
    "uploading",
    "assigned",
];
/// States a job passes through before it's finished.
pub const PENDING_STATES: &[&str] = &["scheduled", "assigned", "setup", "running", "uploading"];
/// States in which a job is actively executing (as opposed to merely queued).
pub const EXECUTION_STATES: &[&str] = &["assigned", "setup", "running", "uploading"];
/// States before a job starts executing.
pub const PRE_EXECUTION_STATES: &[&str] = &["scheduled"];
/// States a job does not leave once reached.
pub const FINAL_STATES: &[&str] = &["done", "cancelled"];

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

    // Matches openqa_async.const's Python tuples byte-for-byte.
    #[test]
    fn state_groups_match_python() {
        assert_eq!(
            STATES,
            [
                "scheduled",
                "setup",
                "running",
                "cancelled",
                "done",
                "uploading",
                "assigned"
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
        assert_eq!(FINAL_STATES, ["done", "cancelled"]);
    }

    #[test]
    fn result_groups_match_python() {
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
    }

    #[test]
    fn scenario_keys_match_python() {
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
