// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises the same-origin request guard in `src/client.rs`: a caller
//! cannot send openQA credentials to a foreign origin, whether that origin
//! comes from an untrusted `path` (`Client::join`, via `request`/`prepare`)
//! or a hand-built [`PreparedRequest`] passed straight to [`Client::execute`]
//! (the public-fields bypass `Client::join` never sees).

use reqwest::Method;
use reqwest::header::HeaderMap;
use ruoqa::secret::{ApiKey, ApiSecret};
use ruoqa::{ClientBuilder, Error, PreparedRequest};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(uri: &str) -> ruoqa::Client {
    ClientBuilder::new()
        .server(uri)
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .build()
        .unwrap()
}

#[tokio::test]
async fn cross_origin_path_errors_before_any_request_is_sent() {
    let victim = MockServer::start().await;
    let attacker = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&attacker)
        .await;

    let client = client_for(&victim.uri());
    let err = client
        .request(Method::GET, &format!("{}/steal", attacker.uri()), None)
        .await
        .expect_err("an absolute cross-origin path must be refused");
    assert!(matches!(err, Error::CrossOriginRequest { .. }));

    assert!(
        attacker.received_requests().await.unwrap().is_empty(),
        "the attacker server must never see a request"
    );
}

#[tokio::test]
async fn hand_built_cross_origin_prepared_request_errors_before_execute_sends_it() {
    let victim = MockServer::start().await;
    let attacker = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&attacker)
        .await;

    let client = client_for(&victim.uri());
    let prepared = PreparedRequest {
        method: Method::GET,
        url: format!("{}/steal", attacker.uri()).parse().unwrap(),
        headers: HeaderMap::new(),
        body: None,
    };
    let err = client
        .execute(&prepared, false)
        .await
        .expect_err("a hand-built cross-origin PreparedRequest must be refused");
    assert!(matches!(err, Error::CrossOriginRequest { .. }));

    assert!(
        attacker.received_requests().await.unwrap().is_empty(),
        "the attacker server must never see a request"
    );
}

#[tokio::test]
async fn same_origin_prepared_request_with_userinfo_errors_and_reaches_no_server() {
    let victim = MockServer::start().await;
    let attacker = MockServer::start().await;

    let client = client_for(&victim.uri());
    let victim_uri = victim.uri();
    let victim_host = victim_uri.strip_prefix("http://").unwrap();
    let prepared = PreparedRequest {
        method: Method::GET,
        url: format!("http://user:pass@{victim_host}/api/v1/jobs")
            .parse()
            .unwrap(),
        headers: HeaderMap::new(),
        body: None,
    };
    let err = client
        .execute(&prepared, false)
        .await
        .expect_err("a same-origin URL carrying userinfo must be refused");
    assert!(matches!(err, Error::UnsupportedRequestUrl { .. }));

    assert!(victim.received_requests().await.unwrap().is_empty());
    assert!(attacker.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn control_normal_relative_path_still_succeeds() {
    let victim = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&victim)
        .await;

    let client = client_for(&victim.uri());
    let value = client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("a normal relative path must still succeed");
    assert_eq!(value, serde_json::json!({"ok": true}));
}
