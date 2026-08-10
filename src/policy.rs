// SPDX-License-Identifier: GPL-3.0-or-later

//! Timeout and retry-policy value types.

use std::collections::HashSet;
use std::num::IntErrorKind;
use std::time::{Duration, SystemTime};

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Method, StatusCode};

/// Per-request timeout knobs.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Time allowed to establish the TCP/TLS connection.
    pub connect: Duration,
    /// Per-read inactivity timeout.
    pub read: Duration,
    /// Whole-request timeout, including the body.
    pub total: Duration,
    /// How long an idle pooled connection is kept alive.
    pub pool_idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            total: Duration::from_mins(1),
            pool_idle: Duration::from_secs(90),
        }
    }
}

impl Timeouts {
    /// Sets the connect timeout.
    #[must_use]
    pub fn connect(mut self, connect: Duration) -> Self {
        self.connect = connect;
        self
    }

    /// Sets the per-read inactivity timeout.
    #[must_use]
    pub fn read(mut self, read: Duration) -> Self {
        self.read = read;
        self
    }

    /// Sets the whole-request timeout.
    #[must_use]
    pub fn total(mut self, total: Duration) -> Self {
        self.total = total;
        self
    }

    /// Sets the idle-connection pool timeout.
    #[must_use]
    pub fn pool_idle(mut self, pool_idle: Duration) -> Self {
        self.pool_idle = pool_idle;
        self
    }
}

/// A source of randomness for backoff jitter, injectable so tests can be
/// deterministic.
pub trait Rng: std::fmt::Debug {
    /// Returns a duration uniformly distributed in `[0, max]`.
    fn uniform(&mut self, max: Duration) -> Duration;
}

/// Default jitter source: a small xorshift64* PRNG, not cryptographically
/// secure but sufficient for spreading out retries.
#[derive(Debug, Clone, Copy)]
pub struct DefaultRng(u64);

impl DefaultRng {
    /// Builds a `DefaultRng` from `seed`. A zero seed is remapped to a fixed
    /// nonzero constant, since a zero xorshift64* state never changes.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

impl Default for DefaultRng {
    fn default() -> Self {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self::from_seed(seed)
    }
}

impl Rng for DefaultRng {
    fn uniform(&mut self, max: Duration) -> Duration {
        if max.is_zero() {
            return Duration::ZERO;
        }
        // Top 53 bits give a uniform double in [0, 1); precision loss below
        // 2^-53 is inherent to the technique, not a bug.
        #[allow(clippy::cast_precision_loss)]
        let frac = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        max.mul_f64(frac)
    }
}

/// Retry behaviour: which requests get retried, how many times, and with
/// what backoff.
#[derive(Debug)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the initial try.
    pub max_retries: u32,
    /// Backoff before the first retry.
    pub initial_backoff: Duration,
    /// Growth factor applied to the backoff on each subsequent retry. Must
    /// be finite and `>= 1.0`; [`ClientBuilder::build`](crate::ClientBuilder::build)
    /// rejects anything else.
    pub multiplier: f64,
    /// Upper bound on the (pre-jitter) backoff.
    pub max_backoff: Duration,
    /// A budget for the whole `Client::execute` call: every attempt, every
    /// backoff sleep, and every redirect hop, on top of `max_retries`. A
    /// request still in flight when it expires is aborted with
    /// [`crate::Error::DeadlineExceeded`]. Response-body streaming happens
    /// after `execute` returns and is bounded by `Timeouts`, not by this.
    pub deadline: Option<Duration>,
    /// Whether to honor a `Retry-After` response header over computed backoff.
    pub honor_retry_after: bool,
    /// Cap on a `Retry-After` value, to defend against a hostile/absurd header.
    pub max_retry_after: Duration,
    /// HTTP status codes that trigger a retry.
    pub retry_statuses: HashSet<StatusCode>,
    /// HTTP methods safe to replay, and so eligible for retry on a
    /// transport error or a retryable status.
    pub idempotent_methods: HashSet<Method>,
    /// Opts methods outside `idempotent_methods` into both transport and
    /// status retries. Only set this if every write this client sends is
    /// safe to replay: unlike [`Client::execute`](crate::Client::execute)'s
    /// per-call override, this cannot be locally disabled.
    pub retry_non_idempotent: bool,
    rng: Box<dyn Rng + Send>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 4,
            initial_backoff: Duration::from_millis(500),
            multiplier: 2.0,
            max_backoff: Duration::from_secs(30),
            deadline: Some(Duration::from_mins(2)),
            honor_retry_after: true,
            max_retry_after: Duration::from_mins(1),
            retry_statuses: [408, 413, 429, 444, 500, 502, 503, 504, 509, 521, 522, 599]
                .into_iter()
                .map(StatusCode::from_u16)
                .map(Result::unwrap)
                .collect(),
            idempotent_methods: [
                Method::GET,
                Method::HEAD,
                Method::OPTIONS,
                Method::PUT,
                Method::DELETE,
            ]
            .into(),
            retry_non_idempotent: false,
            rng: Box::new(DefaultRng::default()),
        }
    }
}

impl RetryPolicy {
    /// A more lenient retry profile: 5 retries, 10 s initial backoff, 60 s
    /// cap, no overall deadline.
    #[must_use]
    pub fn upstream_compat() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_mins(1),
            deadline: None,
            ..Self::default()
        }
    }

    /// Sets the maximum number of retry attempts.
    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the initial backoff.
    #[must_use]
    pub fn initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    /// Sets the backoff growth factor. Must be finite and `>= 1.0`;
    /// [`ClientBuilder::build`](crate::ClientBuilder::build) rejects
    /// anything else.
    #[must_use]
    pub fn multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Sets the backoff cap.
    #[must_use]
    pub fn max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Sets the whole-`Client::execute` deadline: every attempt, every
    /// backoff sleep, and every redirect hop, on top of `max_retries`. A
    /// request still in flight when it expires is aborted with
    /// [`crate::Error::DeadlineExceeded`]. Response-body streaming happens
    /// after `execute` returns and is bounded by `Timeouts`, not by this.
    #[must_use]
    pub fn deadline(mut self, deadline: Option<Duration>) -> Self {
        self.deadline = deadline;
        self
    }

    /// Sets whether a `Retry-After` response header is honored.
    #[must_use]
    pub fn honor_retry_after(mut self, honor_retry_after: bool) -> Self {
        self.honor_retry_after = honor_retry_after;
        self
    }

    /// Sets the cap applied to a `Retry-After` value.
    #[must_use]
    pub fn max_retry_after(mut self, max_retry_after: Duration) -> Self {
        self.max_retry_after = max_retry_after;
        self
    }

    /// Sets the HTTP status codes that trigger a retry.
    #[must_use]
    pub fn retry_statuses(mut self, retry_statuses: HashSet<StatusCode>) -> Self {
        self.retry_statuses = retry_statuses;
        self
    }

    /// Sets the HTTP methods safe to replay, and so eligible for retry on a
    /// transport error or a retryable status.
    #[must_use]
    pub fn idempotent_methods(mut self, idempotent_methods: HashSet<Method>) -> Self {
        self.idempotent_methods = idempotent_methods;
        self
    }

    /// Opts methods outside `idempotent_methods` into both transport and
    /// status retries. Only set this if every write this client sends is
    /// safe to replay: unlike [`Client::execute`](crate::Client::execute)'s
    /// per-call override, this cannot be locally disabled.
    #[must_use]
    pub fn retry_non_idempotent(mut self, retry_non_idempotent: bool) -> Self {
        self.retry_non_idempotent = retry_non_idempotent;
        self
    }

    /// Overrides the jitter source, e.g. with a fixed-seed `DefaultRng` for
    /// deterministic tests.
    #[must_use]
    pub fn rng(mut self, rng: impl Rng + Send + 'static) -> Self {
        self.rng = Box::new(rng);
        self
    }

    /// Exponential backoff for `attempt` (0-based), capped at `max_backoff`
    /// and jittered uniformly over `[0, backoff]`.
    #[must_use]
    pub fn backoff_for(&mut self, attempt: u32) -> Duration {
        let exp = i32::try_from(attempt).unwrap_or(i32::MAX);
        let secs = self.initial_backoff.as_secs_f64() * self.multiplier.powi(exp);
        // A growth curve that overflows f64 or Duration saturates at the cap it
        // would have hit anyway; this is also the last line of defence for a
        // hand-built policy that never went through `ClientBuilder::build`.
        let backoff = Duration::try_from_secs_f64(secs)
            .unwrap_or(self.max_backoff)
            .min(self.max_backoff);
        self.rng.uniform(backoff)
    }

    /// Validates fields that would otherwise let [`Self::backoff_for`] panic
    /// or misbehave. Called from
    /// [`ClientBuilder::build`](crate::ClientBuilder::build).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidRetryPolicy`] if `multiplier` is not
    /// finite and `>= 1.0`.
    #[allow(clippy::result_large_err)] // `Error`'s size is a phase-1 decision; not this fn's to fix.
    pub(crate) fn validate(&self) -> crate::Result<()> {
        if !self.multiplier.is_finite() || self.multiplier < 1.0 {
            return Err(crate::Error::InvalidRetryPolicy {
                field: "multiplier",
                reason: "must be a finite number >= 1.0",
            });
        }
        Ok(())
    }

    /// Returns `None` if `honor_retry_after` is false, or if the header is
    /// absent or unparsable. Otherwise parses a `Retry-After` header:
    /// integer seconds or an HTTP-date, clamped to `>= 0` and to
    /// `max_retry_after`.
    #[must_use]
    pub fn parse_retry_after(&self, headers: &HeaderMap) -> Option<Duration> {
        if !self.honor_retry_after {
            return None;
        }
        Some(retry_after_value(headers)?.min(self.max_retry_after))
    }
}

/// Whether a retryable `status` means the server rejected the request
/// without acting on it, making a replay safe even for a non-idempotent
/// method: `429`/`503` carrying a parsable `Retry-After`. Independent of
/// `honor_retry_after`, which governs the delay, not the signal.
pub(crate) fn is_backpressure(status: StatusCode, headers: &HeaderMap) -> bool {
    matches!(status.as_u16(), 429 | 503) && retry_after_value(headers).is_some()
}

/// Parses a `Retry-After` header — integer seconds or an HTTP-date, clamped
/// to `>= 0` — with no `honor_retry_after` or `max_retry_after` handling.
fn retry_after_value(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();

    Some(match value.parse::<u64>() {
        Ok(secs) => Duration::from_secs(secs),
        Err(e) if *e.kind() == IntErrorKind::PosOverflow => Duration::MAX,
        Err(_) => {
            let when = httpdate::parse_http_date(value).ok()?;
            when.duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_defaults() {
        let t = Timeouts::default();
        assert_eq!(t.connect, Duration::from_secs(10));
        assert_eq!(t.read, Duration::from_secs(30));
        assert_eq!(t.total, Duration::from_mins(1));
        assert_eq!(t.pool_idle, Duration::from_secs(90));
    }

    #[test]
    fn retry_policy_defaults() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 4);
        assert_eq!(p.initial_backoff, Duration::from_millis(500));
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert_eq!(p.deadline, Some(Duration::from_mins(2)));
        assert!(p.honor_retry_after);
        assert!(p.retry_statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
        assert!(!p.idempotent_methods.contains(&Method::POST));
        assert!(p.idempotent_methods.contains(&Method::GET));
    }

    #[test]
    fn upstream_compat_values() {
        let p = RetryPolicy::upstream_compat();
        assert_eq!(p.max_retries, 5);
        assert_eq!(p.initial_backoff, Duration::from_secs(10));
        assert_eq!(p.max_backoff, Duration::from_mins(1));
        assert_eq!(p.deadline, None);
    }

    #[test]
    fn backoff_growth_and_cap_with_fixed_seed() {
        let mut p = RetryPolicy::default().rng(DefaultRng::from_seed(42));
        // With a fixed seed the jittered value never exceeds the un-jittered
        // backoff, and the un-jittered backoff caps at max_backoff.
        for attempt in 0..10 {
            let uncapped = p
                .initial_backoff
                .mul_f64(p.multiplier.powi(attempt))
                .min(p.max_backoff);
            let jittered = p.backoff_for(attempt.try_into().unwrap());
            assert!(
                jittered <= uncapped,
                "attempt {attempt}: {jittered:?} > {uncapped:?}"
            );
        }
    }

    #[test]
    fn backoff_is_deterministic_for_a_given_seed() {
        let mut a = RetryPolicy::default().rng(DefaultRng::from_seed(7));
        let mut b = RetryPolicy::default().rng(DefaultRng::from_seed(7));
        for attempt in 0..5 {
            assert_eq!(a.backoff_for(attempt), b.backoff_for(attempt));
        }
    }

    #[test]
    fn backoff_for_saturates_instead_of_panicking() {
        let mut p = RetryPolicy::default().multiplier(1e300);
        let backoff = p.backoff_for(1000);
        assert!(backoff <= p.max_backoff);
    }

    #[test]
    fn validate_accepts_sane_multipliers() {
        assert!(RetryPolicy::default().multiplier(1.0).validate().is_ok());
        assert!(RetryPolicy::default().multiplier(2.0).validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_multipliers() {
        for bad in [f64::NAN, f64::INFINITY, 0.5, -1.0] {
            let err = RetryPolicy::default()
                .multiplier(bad)
                .validate()
                .unwrap_err();
            assert!(matches!(
                err,
                crate::Error::InvalidRetryPolicy {
                    field: "multiplier",
                    ..
                }
            ));
        }
    }

    #[test]
    fn retry_after_integer_seconds() {
        let p = RetryPolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "5".parse().unwrap());
        assert_eq!(p.parse_retry_after(&headers), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_http_date_future() {
        let p = RetryPolicy::default();
        let future = SystemTime::now() + Duration::from_secs(30);
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            httpdate::fmt_http_date(future).parse().unwrap(),
        );
        let parsed = p.parse_retry_after(&headers).unwrap();
        // Allow a little slack for the HTTP-date's 1-second resolution.
        assert!(parsed >= Duration::from_secs(28) && parsed <= Duration::from_secs(30));
    }

    #[test]
    fn retry_after_past_date_clamps_to_zero() {
        let p = RetryPolicy::default();
        let past = SystemTime::now() - Duration::from_hours(1);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, httpdate::fmt_http_date(past).parse().unwrap());
        assert_eq!(p.parse_retry_after(&headers), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_garbage_is_none() {
        let p = RetryPolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "not-a-duration".parse().unwrap());
        assert_eq!(p.parse_retry_after(&headers), None);
    }

    #[test]
    fn retry_after_absurdly_large_is_capped() {
        let p = RetryPolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "99999999999999999999999999".parse().unwrap());
        assert_eq!(p.parse_retry_after(&headers), Some(p.max_retry_after));
    }

    #[test]
    fn retry_after_missing_header_is_none() {
        let p = RetryPolicy::default();
        let headers = HeaderMap::new();
        assert_eq!(p.parse_retry_after(&headers), None);
    }

    #[test]
    fn retry_after_ignored_when_disabled() {
        let p = RetryPolicy::default().honor_retry_after(false);
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "5".parse().unwrap());
        assert_eq!(p.parse_retry_after(&headers), None);
    }

    #[test]
    fn is_backpressure_requires_retry_after() {
        let mut with_retry_after = HeaderMap::new();
        with_retry_after.insert(RETRY_AFTER, "5".parse().unwrap());
        let empty = HeaderMap::new();
        let mut garbage_retry_after = HeaderMap::new();
        garbage_retry_after.insert(RETRY_AFTER, "banana".parse().unwrap());

        assert!(is_backpressure(
            StatusCode::TOO_MANY_REQUESTS,
            &with_retry_after
        ));
        assert!(!is_backpressure(StatusCode::TOO_MANY_REQUESTS, &empty));
        assert!(is_backpressure(
            StatusCode::SERVICE_UNAVAILABLE,
            &with_retry_after
        ));
        assert!(!is_backpressure(StatusCode::SERVICE_UNAVAILABLE, &empty));
        assert!(!is_backpressure(
            StatusCode::INTERNAL_SERVER_ERROR,
            &with_retry_after
        ));
        assert!(!is_backpressure(
            StatusCode::TOO_MANY_REQUESTS,
            &garbage_retry_after
        ));
    }

    #[test]
    fn is_backpressure_ignores_honor_retry_after() {
        // `is_backpressure` is a free function with no `RetryPolicy`, and so
        // no `honor_retry_after` to consult — the presence of `Retry-After`
        // is evidence about the server's intent regardless of whether the
        // caller wants its duration honored.
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "5".parse().unwrap());
        let disabled = RetryPolicy::default().honor_retry_after(false);
        assert_eq!(disabled.parse_retry_after(&headers), None);
        assert!(is_backpressure(StatusCode::TOO_MANY_REQUESTS, &headers));
    }
}
