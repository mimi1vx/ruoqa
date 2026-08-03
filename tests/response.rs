// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises response handling in `src/client.rs` (phase-4 step 11): JSON
//! and YAML parsing, `204`, non-2xx -> `Error::Request`, the response-size
//! cap, and a YAML alias bomb rejected by the parser's budget rather than
//! exhausting memory.

use reqwest::Method;
use ruoqa::{ClientBuilder, Error};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn json_response_is_parsed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 1})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let value = client.request(Method::GET, "/jobs", None).await.unwrap();
    assert_eq!(value, serde_json::json!({"id": 1}));
}

#[tokio::test]
async fn yaml_response_is_parsed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("id: 1\nname: foo\n", "text/yaml"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let value = client.request(Method::GET, "/jobs", None).await.unwrap();
    assert_eq!(value, serde_json::json!({"id": 1, "name": "foo"}));
}

#[tokio::test]
async fn no_content_response_is_null() {
    let mock_server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/jobs/1"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let value = client
        .request(Method::DELETE, "/jobs/1", None)
        .await
        .unwrap();
    assert_eq!(value, serde_json::Value::Null);
}

#[tokio::test]
async fn not_found_becomes_request_error_with_method_url_status() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not here"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let err = client
        .request(Method::GET, "/missing", None)
        .await
        .unwrap_err();
    match err {
        Error::Request {
            method,
            url,
            status,
            body,
        } => {
            assert_eq!(method, Method::GET);
            assert_eq!(url.path(), "/missing");
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert!(body.contains("not here"));
        }
        other => panic!("expected Error::Request, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_body_fails_with_body_too_large() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024)))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .max_response_bytes(16)
        .build()
        .unwrap();
    let err = client.request(Method::GET, "/big", None).await.unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge { limit: 16 }));
}

/// A classic "billion laughs" alias bomb: each of the nine `&`-anchored
/// lists references the previous one nine times, so the fully expanded
/// document would have roughly 9^9 (~387 million) leaf entries despite the
/// input being under a kilobyte. `yaml_options()`'s tightened budget must
/// reject this well before that expansion completes.
const YAML_ALIAS_BOMB: &str = r#"
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
"#;

#[tokio::test]
async fn yaml_alias_bomb_is_rejected_by_budget_not_oom() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bomb"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(YAML_ALIAS_BOMB, "text/yaml"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let err = client
        .request(Method::GET, "/bomb", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Parse(_)),
        "expected a budget-rejected parse error, got {err:?}"
    );
}
