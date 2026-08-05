// SPDX-License-Identifier: GPL-3.0-or-later

//! Userinfo in a URL must never reach a `Display` site: `Error::Request`,
//! `Error::Connection`, and `Error::CrossOriginRedirect` (both `from` and
//! `to`) all redact via `RedactedUrl` (see `plans/url-userinfo-redaction.md`).

use reqwest::{Method, StatusCode, Url};
use ruoqa::Error;

const CREDENTIALED: &str = "https://alice:s3cret@openqa.example.com/p";

async fn connection_error() -> reqwest::Error {
    // Nothing listens here; the connection is refused immediately, no
    // network required.
    reqwest::Client::new()
        .get("http://127.0.0.1:1")
        .send()
        .await
        .expect_err("connection should fail")
}

#[test]
fn request_error_redacts_url() {
    let err = Error::Request {
        method: Method::GET,
        url: Url::parse(CREDENTIALED).unwrap(),
        status: StatusCode::NOT_FOUND,
        body: String::new(),
    };
    let message = err.to_string();
    assert!(!message.contains("s3cret"));
    assert!(!message.contains("alice"));
    assert!(message.contains("openqa.example.com"));
}

#[tokio::test]
async fn connection_error_redacts_url() {
    let err = Error::Connection {
        url: Url::parse(CREDENTIALED).unwrap(),
        source: connection_error().await,
    };
    let message = err.to_string();
    assert!(!message.contains("s3cret"));
    assert!(!message.contains("alice"));
    assert!(message.contains("openqa.example.com"));
}

#[test]
fn cross_origin_redirect_redacts_both_urls() {
    let err = Error::CrossOriginRedirect {
        from: Url::parse(CREDENTIALED).unwrap(),
        to: Url::parse("https://bob:h4x@evil.example.com/q").unwrap(),
    };
    let message = err.to_string();
    assert!(!message.contains("s3cret"));
    assert!(!message.contains("alice"));
    assert!(!message.contains("h4x"));
    assert!(!message.contains("bob"));
    assert!(message.contains("openqa.example.com"));
    assert!(message.contains("evil.example.com"));
}
