// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure, I/O-free HMAC-SHA1 request signing, matching openQA's server-side
//! verification (`hmac_sha1_sum($req->url->to_string . $remote_timestamp, $secret)`).

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sha1::Sha1;
use url::Url;

use crate::secret::ApiSecret;

type HmacSha1 = Hmac<Sha1>;

/// The string that gets signed: `path` plus `?query` (if a non-empty query
/// exists), with the `%20`->`+` and `~`->`%7E` fixups applied to match the
/// Python client's `requests`-based `path_url` signing byte-for-byte.
#[must_use]
pub fn signing_string(url: &Url) -> String {
    let mut raw = url.path().to_owned();
    if let Some(query) = url.query().filter(|q| !q.is_empty()) {
        raw.push('?');
        raw.push_str(query);
    }
    raw.replace("%20", "+").replace('~', "%7E")
}

/// Lowercase hex HMAC-SHA1 of `signing_string` concatenated with `ts`.
///
/// # Panics
///
/// Never in practice: HMAC accepts a key of any length.
#[must_use]
pub fn sign(signing_string: &str, ts: &str, secret: &ApiSecret) -> String {
    let mut mac =
        HmacSha1::new_from_slice(secret.as_str().as_bytes()).expect("HMAC accepts any key size");
    mac.update(signing_string.as_bytes());
    mac.update(ts.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Seconds since the epoch as a decimal with a fractional part. Python sends
/// a float, Perl an integer; the server does a numeric `abs()` comparison, so
/// both parse — this matches Python for testability against its test suite.
///
/// # Panics
///
/// Never in practice: only if the system clock reads before the Unix epoch.
#[must_use]
pub fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the epoch");
    format!("{}.{:06}", now.as_secs(), now.subsec_micros())
}

/// Sets `X-API-Microtime` and `X-API-Hash` on `headers`. No-op when `secret`
/// is `None` (unauthenticated GET).
///
/// # Panics
///
/// Never in practice: the timestamp and hex hash are both ASCII and valid
/// header values.
pub fn apply(headers: &mut HeaderMap, url: &Url, secret: Option<&ApiSecret>) {
    let Some(secret) = secret else {
        return;
    };
    let ts = timestamp();
    let hash = sign(&signing_string(url), &ts, secret);
    headers.insert(
        HeaderName::from_static("x-api-microtime"),
        HeaderValue::from_str(&ts).expect("timestamp is valid header value"),
    );
    headers.insert(
        HeaderName::from_static("x-api-hash"),
        HeaderValue::from_str(&hash).expect("hex hash is valid header value"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector from `tests/test_auth.py::test_known_value_hmac`.
    #[test]
    fn known_value_hmac() {
        let url = Url::parse("https://openqa.example/api/v1/jobs").unwrap();
        let secret = ApiSecret::new("SECRET01");
        let hash = sign(&signing_string(&url), "1234567890.0", &secret);
        assert_eq!(hash, "5dd9172343c3695b1213e78d2a635f31ca475831");
    }

    /// Vector from `tests/test_auth.py::test_path_fixups_space_and_tilde`.
    #[test]
    fn path_fixups_space_and_tilde() {
        let url = Url::parse("https://openqa.example/api/v1/jobs?test=foo bar&u=~name").unwrap();
        let signing = signing_string(&url);
        assert_eq!(signing, "/api/v1/jobs?test=foo+bar&u=%7Ename");

        let secret = ApiSecret::new("SECRET02");
        let hash = sign(&signing, "1700000000.0", &secret);
        assert_eq!(hash, "6cd9bba9e451c1371f77070fa2ddd0ed4444fd1b");
    }

    #[test]
    fn signing_string_omits_empty_query() {
        let url = Url::parse("https://openqa.example/api/v1/jobs").unwrap();
        assert_eq!(signing_string(&url), "/api/v1/jobs");
    }

    #[test]
    fn no_secret_adds_no_headers() {
        let url = Url::parse("https://openqa.example/api/v1/jobs").unwrap();
        let mut headers = HeaderMap::new();
        apply(&mut headers, &url, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn with_secret_adds_headers() {
        let url = Url::parse("https://openqa.example/api/v1/jobs").unwrap();
        let secret = ApiSecret::new("SECRET01");
        let mut headers = HeaderMap::new();
        apply(&mut headers, &url, Some(&secret));
        assert!(headers.contains_key("x-api-microtime"));
        assert!(headers.contains_key("x-api-hash"));
    }
}
