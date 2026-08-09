// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises `Client::request_form` end-to-end: an
//! `application/x-www-form-urlencoded` body against openQA's
//! `POST /api/v1/isos`-shaped endpoint.

use reqwest::Method;
use ruoqa::{ApiResponse, ClientBuilder};
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn form_body_is_urlencoded_and_response_parsed() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/isos"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string("DISTRI=opensuse&VERSION=Tumbleweed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 42})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();
    let value = client
        .request_form(
            Method::POST,
            "/api/v1/isos",
            &[("DISTRI", "opensuse"), ("VERSION", "Tumbleweed")],
        )
        .await
        .unwrap();
    assert_eq!(value, serde_json::json!({"id": 42}));
}

/// openQA's mutex/barrier lock routes answer a form POST with `render(text
/// => 'ack')`, i.e. `200 text/html`, not JSON.
#[tokio::test]
async fn form_post_answered_with_text_is_a_string() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/barriers/foo"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("ack", "text/html"))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .build()
        .unwrap();

    let typed = client
        .request_form_typed(Method::POST, "/api/v1/barriers/foo", &[("action", "lock")])
        .await
        .unwrap();
    assert_eq!(typed, ApiResponse::Text("ack".to_owned()));

    let value = client
        .request_form(Method::POST, "/api/v1/barriers/foo", &[("action", "lock")])
        .await
        .unwrap();
    assert_eq!(value, serde_json::json!("ack"));
}
