// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises `Client::request_form` end-to-end: an
//! `application/x-www-form-urlencoded` body against openQA's
//! `POST /api/v1/isos`-shaped endpoint.

use reqwest::Method;
use ruoqa::ClientBuilder;
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
