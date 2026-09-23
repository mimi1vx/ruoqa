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

    let paths = [
        "/api/v1/jobs?u=~name",
        "/api/v1/assets/iso/foo bar.iso?q=a b",
        "/api/v1/jobs?BUILD=:123:kernel",
        "/api/v1/jobs?ASSET_URL=https://x/y",
        "/api/v1/jobs?a&b=1",
        "/api/v1/jobs?x=%c3%a9",
        "/api/v1/jobs?t=a+b%2Bc",
    ];
    for path in paths {
        client
            .request(reqwest::Method::GET, path, None)
            .await
            .expect("request should succeed");
    }

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), paths.len());

    // Sanity-check the reconstructed target still shows the wire form we
    // expect, so the hash comparison below isn't vacuous if wiremock's URL
    // reparsing normalizes something out from under us.
    let targets: Vec<String> = received
        .iter()
        .map(|req| reconstruct_target(&req.url))
        .collect();
    assert!(targets.iter().any(|t| t.contains("u=%7Ename")));
    assert!(targets.iter().any(|t| t.contains("foo%20bar.iso")));
    assert!(targets.iter().any(|t| t.contains("BUILD=%3A123%3Akernel")));
    assert!(
        targets
            .iter()
            .any(|t| t.contains("ASSET_URL=https%3A%2F%2Fx%2Fy"))
    );
    assert!(targets.iter().any(|t| t.contains("a=&b=1")));
    assert!(targets.iter().any(|t| t.contains("x=%C3%A9")));
    assert!(targets.iter().any(|t| t.contains("t=a+b%2Bc")));

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

/// What the server signs: `path[?query]`, with the query re-serialized in
/// Mojo's canonical form (`Mojo::Parameters::to_string`). Built from the
/// received (already-reparsed) request URL instead of the one `ruoqa` sent,
/// and deliberately an independent implementation rather than a call into
/// `ruoqa::auth::canonical_query` — the point of this test is to catch drift
/// between the two, not to exercise the same code twice.
fn reconstruct_target(url: &url::Url) -> String {
    let mut out = url.path().to_owned();
    if let Some(query) = url.query() {
        let canonical = mojo_reserialize(query);
        if !canonical.is_empty() {
            out.push('?');
            out.push_str(&canonical);
        }
    }
    out
}

/// Independent re-implementation of `Mojo::Parameters::to_string`: each
/// `name[=value]` pair is percent-decoded (`+` -> space, `%XX` -> byte) then
/// re-encoded with the unreserved set `A-Za-z0-9*-._` (space -> `+`,
/// everything else `%XX` uppercase hex).
fn mojo_reserialize(query: &str) -> String {
    query
        .split('&')
        .filter(|piece| !piece.is_empty())
        .map(|piece| {
            let mut parts = piece.splitn(2, '=');
            let name = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            format!("{}={}", mojo_encode(name), mojo_encode(value))
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn mojo_decode_bytes(raw: &str) -> Vec<u8> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(u8::try_from(hi * 16 + lo).expect("hex digit product fits a byte"));
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn mojo_encode(raw: &str) -> String {
    let unreserved = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_');
    mojo_decode_bytes(raw)
        .into_iter()
        .map(|b| {
            if b == b' ' {
                "+".to_owned()
            } else if unreserved(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
