// SPDX-License-Identifier: GPL-3.0-or-later

//! Sub-path deployment integration test (issue 9): a `server` carrying a
//! path (`{mock}/openqa`) must survive into every request, sign the full
//! wire path, follow a same-origin redirect that stays inside the prefix,
//! and reject one that escapes it.

use reqwest::Method;
use ruoqa::secret::{ApiKey, ApiSecret};
use ruoqa::{ClientBuilder, Error};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn request_path_survives_the_base_path_prefix() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openqa/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(format!("{}/openqa", mock_server.uri()))
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .config_paths(vec![])
        .build()
        .unwrap();

    let value = client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("the sub-path prefix should survive into the request");
    assert_eq!(value, serde_json::json!({"ok": true}));

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].url.path(), "/openqa/api/v1/jobs");
}

/// Recomputes the HMAC from the target the mock server actually received
/// (mirrors `tests/signing_wire.rs`), pinning that the signed string is the
/// full wire path, prefix included — matching `OpenQA::UserAgent::_path_query`.
#[tokio::test]
async fn signed_hash_covers_the_full_prefixed_wire_path() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(format!("{}/openqa", mock_server.uri()))
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .config_paths(vec![])
        .build()
        .unwrap();

    client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("request should succeed");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    assert_eq!(req.url.path(), "/openqa/api/v1/jobs");

    let ts = req
        .headers
        .get("x-api-microtime")
        .expect("X-API-Microtime header present")
        .to_str()
        .unwrap();
    let expected_hash = req
        .headers
        .get("x-api-hash")
        .expect("X-API-Hash header present")
        .to_str()
        .unwrap();
    let hash = ruoqa::auth::sign(req.url.path(), ts, &ApiSecret::new("SECRET"));
    assert_eq!(hash, expected_hash);
}

#[tokio::test]
async fn same_origin_redirect_inside_the_prefix_is_followed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openqa/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/openqa/api/v1/jobs/1"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/openqa/api/v1/jobs/1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(format!("{}/openqa", mock_server.uri()))
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .config_paths(vec![])
        .build()
        .unwrap();

    let value = client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("a redirect that stays inside the prefix should be followed");
    assert_eq!(value, serde_json::json!({"ok": true}));

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
}

#[tokio::test]
async fn same_origin_redirect_outside_the_prefix_is_rejected() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openqa/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/elsewhere"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(format!("{}/openqa", mock_server.uri()))
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .config_paths(vec![])
        .build()
        .unwrap();

    let err = client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect_err("a redirect outside the base URL path must be refused");
    assert!(matches!(err, Error::OutsideBaseUrlPath { .. }));

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "only the original request should have been sent"
    );
}
