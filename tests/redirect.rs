// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises the manual redirect following in `src/client.rs` (phase-4 step
//! 10): same-origin hops are re-signed, cross-origin hops error without ever
//! sending a request off-origin, a chain longer than `max_redirects` errors,
//! and method/body/header handling on a hop follows
//! `Mojo::UserAgent::Transactor::redirect`: `301`/`302`/`303` downgrade a
//! `POST` to a bodyless `GET` and drop `content-*` headers, `307`/`308`
//! replay the method, body, and headers verbatim, and a non-`http`(s)
//! `Location` is treated as final rather than followed.

use reqwest::Method;
use ruoqa::secret::{ApiKey, ApiSecret};
use ruoqa::{ClientBuilder, Error};
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
async fn same_origin_redirect_is_followed_and_resigned() {
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

    let client = client_for(&mock_server.uri());
    let value = client
        .request(Method::GET, "/old", None)
        .await
        .expect("same-origin redirect should be followed");
    assert_eq!(value, serde_json::json!({"ok": true}));

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "both hops should have been requested");
    let hashes: Vec<&str> = received
        .iter()
        .map(|r| r.headers.get("x-api-hash").unwrap().to_str().unwrap())
        .collect();
    assert_ne!(
        hashes[0], hashes[1],
        "the redirected request must be re-signed, not replayed"
    );
}

#[tokio::test]
async fn cross_origin_redirect_errors_and_leaks_no_auth_header() {
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

    let client = client_for(&origin_server.uri());
    let err = client
        .request(Method::GET, "/old", None)
        .await
        .expect_err("cross-origin redirect must be refused");
    assert!(matches!(err, Error::CrossOriginRedirect { .. }));

    let other_origin_requests = other_origin_server.received_requests().await.unwrap();
    assert!(
        other_origin_requests.is_empty(),
        "no request (and therefore no auth header) should ever reach the other origin"
    );
}

#[tokio::test]
async fn chain_longer_than_max_redirects_errors() {
    let mock_server = MockServer::start().await;
    for (from, to) in [
        ("/r0", "/r1"),
        ("/r1", "/r2"),
        ("/r2", "/r3"),
        ("/r3", "/r4"),
    ] {
        Mock::given(method("GET"))
            .and(path(from))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", to))
            .mount(&mock_server)
            .await;
    }

    // Default max_redirects is 3; this chain requires 4 hops.
    let client = client_for(&mock_server.uri());
    let err = client
        .request(Method::GET, "/r0", None)
        .await
        .expect_err("a 4-hop chain should exceed max_redirects = 3");
    assert!(matches!(err, Error::TooManyRedirects { max: 3 }));

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        4,
        "r0, r1, r2, r3 should be requested; r4 never should be"
    );
}

#[tokio::test]
async fn see_other_redirect_converts_to_get_and_drops_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/old"))
        .respond_with(ResponseTemplate::new(303).insert_header("Location", "/new"))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    client
        .request(Method::POST, "/old", Some(&serde_json::json!({"a": 1})))
        .await
        .expect("303 should be followed as a GET");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].method, Method::GET);
    assert!(
        received[1].body.is_empty(),
        "303 must drop the original body"
    );
    assert!(
        !received[1].headers.contains_key("content-type"),
        "303 must drop content-type along with the body"
    );
    assert!(
        received[1].headers.contains_key("x-api-key"),
        "a 303's header reset must not drop auth: x-api-key"
    );
    assert!(
        received[1].headers.contains_key("x-api-hash"),
        "a 303's header reset must not drop auth: x-api-hash"
    );
}

#[tokio::test]
async fn permanent_and_found_redirects_downgrade_post_to_get() {
    for status in [301, 302] {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/old"))
            .respond_with(ResponseTemplate::new(status).insert_header("Location", "/new"))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/new"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let client = client_for(&mock_server.uri());
        client
            .request(Method::POST, "/old", Some(&serde_json::json!({"a": 1})))
            .await
            .unwrap_or_else(|e| panic!("{status} should be followed as a GET: {e}"));

        let received = mock_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2, "status {status}");
        assert_eq!(received[1].method, Method::GET, "status {status}");
        assert!(
            received[1].body.is_empty(),
            "{status} must drop the original body"
        );
        assert!(
            !received[1].headers.contains_key("content-type"),
            "{status} must drop content-type along with the body"
        );
    }
}

#[tokio::test]
async fn temporary_redirect_replays_the_stored_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/old"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", "/new"))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    client
        .request(Method::POST, "/old", Some(&serde_json::json!({"a": 1})))
        .await
        .expect("307 should replay the original body");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].method, Method::POST);
    assert_eq!(
        received[1].body_json::<serde_json::Value>().unwrap(),
        serde_json::json!({"a": 1})
    );
}

#[tokio::test]
async fn permanent_redirect_replays_the_stored_body() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/old"))
        .respond_with(ResponseTemplate::new(308).insert_header("Location", "/new"))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    client
        .request(Method::POST, "/old", Some(&serde_json::json!({"a": 1})))
        .await
        .expect("308 should replay the original body");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].method, Method::POST);
    assert_eq!(
        received[1].headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(
        received[1].body_json::<serde_json::Value>().unwrap(),
        serde_json::json!({"a": 1})
    );
}

#[tokio::test]
async fn non_http_location_is_not_followed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "mailto:admin@example.com"),
        )
        .mount(&mock_server)
        .await;

    let client = client_for(&mock_server.uri());
    let resp = client
        .send_raw(Method::GET, "/old", None)
        .await
        .expect("a non-http(s) Location must not error");
    assert_eq!(resp.status(), 302);

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "only the original request should have been sent"
    );
}
