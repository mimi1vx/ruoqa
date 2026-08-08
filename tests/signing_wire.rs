// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire-vs-signature regression guard: recomputes the HMAC from the target
//! the mock server actually received (the same thing the openQA server's
//! `_valid_hmac` does) and checks it against the `X-API-Hash` `ruoqa` sent.
//! This catches drift between what `signing_string` signs and what lands on
//! the wire that unit tests on `signing_string` alone cannot see.

use ruoqa::ClientBuilder;
use ruoqa::secret::{ApiKey, ApiSecret};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn signed_hash_matches_received_target() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .server(mock_server.uri())
        .api_key(ApiKey::new("KEY"))
        .api_secret(ApiSecret::new("SECRET"))
        .config_paths(vec![])
        .build()
        .unwrap();

    for path in [
        "/api/v1/jobs?u=~name",
        "/api/v1/assets/iso/foo bar.iso?q=a b",
    ] {
        client
            .request(reqwest::Method::GET, path, None)
            .await
            .expect("request should succeed");
    }

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);

    // Sanity-check the reconstructed target still shows the wire form we
    // expect, so the hash comparison below isn't vacuous if wiremock's URL
    // reparsing normalizes something out from under us.
    let targets: Vec<String> = received
        .iter()
        .map(|req| reconstruct_target(&req.url))
        .collect();
    assert!(targets.iter().any(|t| t.contains("u=~name")));
    assert!(targets.iter().any(|t| t.contains("foo%20bar.iso")));

    for req in &received {
        let target = reconstruct_target(&req.url);
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

        let secret = ApiSecret::new("SECRET");
        let hash = ruoqa::auth::sign(&target, ts, &secret);
        assert_eq!(hash, expected_hash, "hash mismatch for target {target}");
    }
}

/// What the server signs: `path[?query]`, with `%20`->`+` applied to the
/// query only. Mirrors `ruoqa::auth::signing_string`, but built from the
/// received (already-reparsed) request URL instead of the one `ruoqa` sent.
fn reconstruct_target(url: &url::Url) -> String {
    let mut out = url.path().to_owned();
    if let Some(query) = url.query().filter(|q| !q.is_empty()) {
        out.push('?');
        out.push_str(&query.replace("%20", "+"));
    }
    out
}
