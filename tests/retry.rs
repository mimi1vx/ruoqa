// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises the retry loop in `src/client.rs` (phase-4 step 9) against a
//! `wiremock` server: transient-status retries, transport-error retry
//! eligibility by method, `Retry-After` honouring, and the overall deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use reqwest::Method;
use ruoqa::policy::RetryPolicy;
use ruoqa::secret::{ApiKey, ApiSecret};
use ruoqa::{ClientBuilder, Error};
use tracing_test::traced_test;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A jitter source that always returns the un-jittered maximum, so
/// backoff-vs-deadline comparisons in tests are deterministic.
#[derive(Debug)]
struct MaxJitter;

impl ruoqa::policy::Rng for MaxJitter {
    fn uniform(&mut self, max: Duration) -> Duration {
        max
    }
}

/// A retry policy tuned for fast, deterministic tests: small fixed backoff,
/// no jitter surprises to worry about since we only assert bounds.
fn fast_retry(max_retries: u32) -> RetryPolicy {
    RetryPolicy::default()
        .max_retries(max_retries)
        .initial_backoff(Duration::from_millis(5))
        .max_backoff(Duration::from_millis(20))
}

#[tokio::test]
async fn retries_503_twice_then_succeeds() {
    let mock_server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_mock = attempts.clone();

    Mock::given(method("GET"))
        .and(path("/jobs"))
        .respond_with(move |_req: &Request| {
            if attempts_in_mock.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(5))
        .build()
        .unwrap();

    let value = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect("should succeed after two retries");
    assert_eq!(value, serde_json::json!({"ok": true}));
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn exhausting_retries_on_500_returns_request_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(2))
        .build()
        .unwrap();

    let err = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect_err("500 should exhaust retries and surface as an error");
    match err {
        Error::Request { status, body, .. } => {
            assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            assert!(body.contains("boom"));
        }
        other => panic!("expected Error::Request, got {other:?}"),
    }
}

#[tokio::test]
#[traced_test]
async fn post_transport_error_is_not_retried_but_get_is() {
    // Nothing listens here; connections fail immediately.
    let client = ClientBuilder::new()
        .server("127.0.0.1:1")
        .scheme("http")
        .retry(fast_retry(2))
        .build()
        .unwrap();

    let post_err = client
        .request(Method::POST, "/jobs", None)
        .await
        .expect_err("connection should fail");
    assert!(matches!(post_err, Error::Connection { .. }));
    assert!(!logs_contain(
        "retrying openQA request after a transport error"
    ));

    let get_err = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect_err("connection should fail");
    assert!(matches!(get_err, Error::Connection { .. }));
    assert!(logs_contain(
        "retrying openQA request after a transport error"
    ));
}

#[tokio::test]
async fn retry_after_header_is_honoured() {
    let mock_server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_mock = attempts.clone();

    Mock::given(method("GET"))
        .respond_with(move |_req: &Request| {
            if attempts_in_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).insert_header("Retry-After", "1")
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    // Un-jittered backoff would be ~5ms; Retry-After: 1s must dominate.
    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(3))
        .build()
        .unwrap();

    let start = Instant::now();
    client
        .request(Method::GET, "/jobs", None)
        .await
        .expect("should succeed after honouring Retry-After");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "elapsed {elapsed:?} should be at least ~1s"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "elapsed {elapsed:?} should not be excessive"
    );
}

#[tokio::test]
async fn deadline_aborts_the_loop_early() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let retry = RetryPolicy::default()
        .max_retries(20)
        .initial_backoff(Duration::from_millis(100))
        .multiplier(1.0)
        .max_backoff(Duration::from_millis(100))
        .deadline(Some(Duration::from_millis(500)))
        .rng(MaxJitter);

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(retry)
        .build()
        .unwrap();

    let start = Instant::now();
    let err = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect_err("503 should still be an error once the deadline aborts retries");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "deadline should abort well before 20 retries elapse: took {elapsed:?}"
    );
    assert!(matches!(
        err,
        Error::Request {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ..
        }
    ));
}

#[tokio::test]
async fn x_api_hash_differs_between_retry_attempts() {
    let mock_server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_mock = attempts.clone();

    Mock::given(method("GET"))
        .respond_with(move |_req: &Request| {
            if attempts_in_mock.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .retry(fast_retry(5))
        .build()
        .unwrap();

    client
        .request(Method::GET, "/jobs", None)
        .await
        .expect("should eventually succeed");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 3);
    let hashes: Vec<&str> = received
        .iter()
        .map(|r| r.headers.get("x-api-hash").unwrap().to_str().unwrap())
        .collect();
    assert_ne!(hashes[0], hashes[1], "signature must be fresh per attempt");
    assert_ne!(hashes[1], hashes[2], "signature must be fresh per attempt");
}

#[tokio::test]
async fn deadline_aborts_transport_error_retries_and_surfaces_last_error() {
    // Nothing listens here; connections fail immediately, and a fixed
    // (non-jittered) 1s backoff can never fit inside a 300ms deadline.
    let retry = RetryPolicy::default()
        .max_retries(10)
        .initial_backoff(Duration::from_secs(1))
        .deadline(Some(Duration::from_millis(300)))
        .rng(MaxJitter);

    let client = ClientBuilder::new()
        .server("127.0.0.1:1")
        .scheme("http")
        .retry(retry)
        .build()
        .unwrap();

    let start = Instant::now();
    let err = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect_err("connection should fail");
    let elapsed = start.elapsed();

    assert!(matches!(err, Error::Connection { .. }));
    assert!(
        elapsed < Duration::from_millis(900),
        "the deadline should abort before the 1s backoff sleep: took {elapsed:?}"
    );
}

#[tokio::test]
async fn deadline_cuts_off_an_in_flight_request() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&mock_server)
        .await;

    let retry = RetryPolicy::default()
        .max_retries(0)
        .deadline(Some(Duration::from_millis(300)));

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(retry)
        .build()
        .unwrap();

    let start = Instant::now();
    let err = client
        .request(Method::GET, "/jobs", None)
        .await
        .expect_err("a request slower than the deadline must be aborted");
    let elapsed = start.elapsed();

    assert!(matches!(err, Error::DeadlineExceeded { .. }));
    assert!(
        elapsed < Duration::from_secs(2),
        "the deadline should abort well before the 3s response delay: took {elapsed:?}"
    );
}

#[tokio::test]
async fn deadline_spans_redirect_hops() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "/b")
                .set_delay(Duration::from_millis(300)),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "/c")
                .set_delay(Duration::from_millis(300)),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/c"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let retry = RetryPolicy::default()
        .max_retries(0)
        .deadline(Some(Duration::from_millis(500)));

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(retry)
        .build()
        .unwrap();

    let start = Instant::now();
    let err = client
        .request(Method::GET, "/a", None)
        .await
        .expect_err("the deadline must span every redirect hop, not restart per hop");
    let elapsed = start.elapsed();

    assert!(matches!(err, Error::DeadlineExceeded { .. }));
    assert!(
        elapsed < Duration::from_secs(2),
        "today each hop restarts the clock and this would succeed at ~900ms: took {elapsed:?}"
    );
}

#[tokio::test]
async fn post_503_without_retry_after_is_not_retried() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/isos"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(3))
        .build()
        .unwrap();

    let err = client
        .request_form(Method::POST, "/isos", &[("ISO", "x.iso")])
        .await
        .expect_err("a bare 503 must not be replayed for a POST");
    assert!(matches!(
        err,
        Error::Request {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ..
        }
    ));
    assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn post_429_with_retry_after_is_retried() {
    let mock_server = MockServer::start().await;
    let attempts_429 = Arc::new(AtomicUsize::new(0));
    let attempts_429_in_mock = attempts_429.clone();
    Mock::given(method("POST"))
        .and(path("/isos"))
        .respond_with(move |_req: &Request| {
            if attempts_429_in_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(429).insert_header("Retry-After", "0")
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let attempts_503 = Arc::new(AtomicUsize::new(0));
    let attempts_503_in_mock = attempts_503.clone();
    Mock::given(method("POST"))
        .and(path("/other-isos"))
        .respond_with(move |_req: &Request| {
            if attempts_503_in_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).insert_header("Retry-After", "0")
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(3))
        .build()
        .unwrap();

    client
        .request_form(Method::POST, "/isos", &[("ISO", "x.iso")])
        .await
        .expect("429 + Retry-After should be retried and succeed");
    assert_eq!(attempts_429.load(Ordering::SeqCst), 2);

    client
        .request_form(Method::POST, "/other-isos", &[("ISO", "x.iso")])
        .await
        .expect("503 + Retry-After should be retried and succeed");
    assert_eq!(attempts_503.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn post_500_is_retried_when_policy_opts_in() {
    let mock_server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_mock = attempts.clone();
    Mock::given(method("POST"))
        .and(path("/isos"))
        .respond_with(move |_req: &Request| {
            if attempts_in_mock.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(2).retry_non_idempotent(true))
        .build()
        .unwrap();

    client
        .request_form(Method::POST, "/isos", &[("ISO", "x.iso")])
        .await
        .expect("retry_non_idempotent(true) should retry a POST 500");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn post_500_is_retried_when_execute_opts_in() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/isos"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(2))
        .build()
        .unwrap();

    let prepared = client
        .prepare_form(Method::POST, "/isos", &[("ISO", "x.iso")])
        .unwrap();
    client
        .execute(&prepared, true)
        .await
        .expect("execute(&prepared, true) should retry a POST 500");
    assert_eq!(mock_server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn honor_retry_after_false_ignores_the_header() {
    let mock_server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_in_mock = attempts.clone();

    Mock::given(method("GET"))
        .respond_with(move |_req: &Request| {
            if attempts_in_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(503).insert_header("Retry-After", "5")
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            }
        })
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .retry(fast_retry(3).honor_retry_after(false))
        .build()
        .unwrap();

    let start = Instant::now();
    client
        .request(Method::GET, "/jobs", None)
        .await
        .expect("should succeed after the computed backoff, ignoring Retry-After");
    let elapsed = start.elapsed();

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(
        elapsed < Duration::from_secs(1),
        "Retry-After: 5 must be ignored: took {elapsed:?}"
    );
}
