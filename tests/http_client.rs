// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises `ClientBuilder::http_client`: an injected `reqwest::Client`
//! must still receive `ruoqa`'s `Accept`/`X-API-Key`/`User-Agent` headers,
//! since those normally ride on `default_headers`/`.user_agent()`, which are
//! unreachable once the caller builds the `reqwest::Client` themselves.

use reqwest::Method;
use ruoqa::ClientBuilder;
use ruoqa::secret::{ApiKey, ApiSecret};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn injected_client_still_gets_ruoqa_headers() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
        .unwrap();

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .http_client(http_client)
        .config_paths(vec![])
        .build()
        .unwrap();

    client
        .request(Method::GET, "/api/v1/jobs", None)
        .await
        .expect("request through the injected client should succeed");

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let headers = &received[0].headers;
    assert_eq!(headers.get("x-api-key").unwrap(), "KEY");
    assert!(headers.contains_key("x-api-hash"));
    assert!(headers.contains_key("x-api-microtime"));
    assert_eq!(headers.get("accept").unwrap(), "application/json");
    assert!(
        headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("ruoqa/"),
        "expected a ruoqa/* user-agent, got {:?}",
        headers.get("user-agent")
    );
}
