// SPDX-License-Identifier: GPL-3.0-or-later

//! Timeout and retry-policy value types. See the master plan for why these
//! defaults diverge from the Python client's.

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
    #[must_use]
    pub fn connect(mut self, connect: Duration) -> Self {
        self.connect = connect;
        self
    }

    #[must_use]
    pub fn read(mut self, read: Duration) -> Self {
        self.read = read;
        self
    }

    #[must_use]
    pub fn total(mut self, total: Duration) -> Self {
        self.total = total;
        self
    }

    #[must_use]
    pub fn pool_idle(mut self, pool_idle: Duration) -> Self {
        self.pool_idle = pool_idle;
        self
    }
}

/// A source of randomness for backoff jitter, injectable so tests can be
/// deterministic (mirrors the Python client's `self._rng`).
pub trait Rng: std::fmt::Debug {
    /// Returns a duration uniformly distributed in `[0, max]`.
    fn uniform(&mut self, max: Duration) -> Duration;
}

/// Default jitter source: a small xorshift64* PRNG, not cryptographically
/// secure but sufficient for spreading out retries.
#[derive(Debug, Clone, Copy)]
pub struct DefaultRng(u64);

impl DefaultRng {
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
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub multiplier: f64,
    pub max_backoff: Duration,
    /// Whole-retry-loop deadline, on top of `max_retries`.
    pub deadline: Option<Duration>,
    /// Whether to honor a `Retry-After` response header over computed backoff.
    pub honor_retry_after: bool,
    /// Cap on a `Retry-After` value, to defend against a hostile/absurd header.
    pub max_retry_after: Duration,
    pub retry_statuses: HashSet<StatusCode>,
    pub retry_methods: HashSet<Method>,
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
            retry_methods: [
                Method::GET,
                Method::HEAD,
                Method::OPTIONS,
                Method::PUT,
                Method::DELETE,
            ]
            .into(),
            rng: Box::new(DefaultRng::default()),
        }
    }
}

impl RetryPolicy {
    /// Reproduces the Python client's defaults: 5 retries, 10 s initial
    /// backoff, 60 s cap, no overall deadline.
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

    #[must_use]
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    #[must_use]
    pub fn initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    #[must_use]
    pub fn multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    #[must_use]
    pub fn max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    #[must_use]
    pub fn deadline(mut self, deadline: Option<Duration>) -> Self {
        self.deadline = deadline;
        self
    }

    #[must_use]
    pub fn honor_retry_after(mut self, honor_retry_after: bool) -> Self {
        self.honor_retry_after = honor_retry_after;
        self
    }

    #[must_use]
    pub fn max_retry_after(mut self, max_retry_after: Duration) -> Self {
        self.max_retry_after = max_retry_after;
        self
    }

    #[must_use]
    pub fn retry_statuses(mut self, retry_statuses: HashSet<StatusCode>) -> Self {
        self.retry_statuses = retry_statuses;
        self
    }

    #[must_use]
    pub fn retry_methods(mut self, retry_methods: HashSet<Method>) -> Self {
        self.retry_methods = retry_methods;
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
        let backoff = self
            .initial_backoff
            .mul_f64(self.multiplier.powi(attempt.try_into().unwrap_or(i32::MAX)))
            .min(self.max_backoff);
        self.rng.uniform(backoff)
    }

    /// Parses a `Retry-After` header: integer seconds or an HTTP-date,
    /// clamped to `>= 0` and to `max_retry_after`. Returns `None` if the
    /// header is absent or unparsable.
    #[must_use]
    pub fn parse_retry_after(&self, headers: &HeaderMap) -> Option<Duration> {
        let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();

        let duration = match value.parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(e) if *e.kind() == IntErrorKind::PosOverflow => Duration::MAX,
            Err(_) => {
                let when = httpdate::parse_http_date(value).ok()?;
                when.duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO)
            }
        };

        Some(duration.min(self.max_retry_after))
    }
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
        assert!(!p.retry_methods.contains(&Method::POST));
        assert!(p.retry_methods.contains(&Method::GET));
    }

    #[test]
    fn upstream_compat_matches_python() {
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
}
