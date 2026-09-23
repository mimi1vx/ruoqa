// SPDX-License-Identifier: GPL-3.0-or-later

//! Personal-access-token (Bearer) auth: `ClientBuilder::username` switches a
//! client from HMAC signing to `Authorization: Bearer user:key:secret`, per
//! `OpenQA::Shared::Controller::Auth::_token_auth`.

use reqwest::Method;
use ruoqa::secret::{ApiKey, ApiSecret, Username};
use ruoqa::{ClientBuilder, Error};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bearer_client(uri: &str) -> ruoqa::Client {
    ClientBuilder::new()
        .server(uri)
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .username(Username::new("alice"))
        .config_paths(vec![])
        .build()
        .unwrap()
}

#[tokio::test]
async fn bearer_request_carries_authorization_and_no_hmac_headers() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = bearer_client(&mock_server.uri());
    client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("request should succeed");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let req = &received[0];
    assert_eq!(
        req.headers.get("authorization").unwrap(),
        "Bearer alice:KEY:SECRET"
    );
    assert!(!req.headers.contains_key("x-api-key"));
    assert!(!req.headers.contains_key("x-api-hash"));
    assert!(!req.headers.contains_key("x-api-microtime"));
}

#[tokio::test]
async fn bearer_survives_retry_and_same_origin_redirect() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/new"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = bearer_client(&mock_server.uri());
    client
        .request(Method::GET, "/old", None)
        .await
        .expect("same-origin redirect should be followed");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "both hops should have been requested");
    for req in &received {
        assert_eq!(
            req.headers.get("authorization").unwrap(),
            "Bearer alice:KEY:SECRET"
        );
    }
}

#[tokio::test]
async fn bearer_cross_origin_redirect_errors_and_leaks_no_token() {
    let origin_server = MockServer::start().await;
    let other_origin_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/other", other_origin_server.uri())),
        )
        .mount(&origin_server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&other_origin_server)
        .await;

    let client = bearer_client(&origin_server.uri());
    let err = client
        .request(Method::GET, "/old", None)
        .await
        .expect_err("cross-origin redirect must be refused");
    assert!(matches!(err, Error::CrossOriginRedirect { .. }));

    let other_origin_requests = other_origin_server.received_requests().await.unwrap();
    assert!(
        other_origin_requests.is_empty(),
        "no request (and therefore no token) should ever reach the other origin"
    );
}

#[test]
fn client_debug_never_contains_the_token() {
    let client = ClientBuilder::new()
        .server("localhost:9526")
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SUPERSECRETVALUE"))
        .username(Username::new("alice"))
        .config_paths(vec![])
        .build()
        .unwrap();
    let debug = format!("{client:?}");
    assert!(!debug.contains("SUPERSECRETVALUE"));
    assert!(!debug.contains("Bearer"));
    assert!(debug.contains("alice"));
}

#[test]
fn username_without_credentials_is_incomplete_credentials() {
    let err = ClientBuilder::new()
        .server("localhost:9526")
        .username(Username::new("alice"))
        .config_paths(vec![])
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        Error::IncompleteCredentials {
            present: "username",
            ..
        }
    ));
}

#[test]
fn username_containing_colon_is_invalid_credentials() {
    let err = ClientBuilder::new()
        .server("localhost:9526")
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .username(Username::new("ali:ce"))
        .config_paths(vec![])
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentials { .. }));
}

#[test]
fn username_over_plaintext_http_to_non_loopback_host_is_rejected() {
    let err = ClientBuilder::new()
        .server("http://openqa.example.com")
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .username(Username::new("alice"))
        .config_paths(vec![])
        .build()
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentials { .. }));
}

#[test]
fn username_over_loopback_http_is_accepted() {
    ClientBuilder::new()
        .server("http://localhost:9526")
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .username(Username::new("alice"))
        .config_paths(vec![])
        .build()
        .unwrap();
}
