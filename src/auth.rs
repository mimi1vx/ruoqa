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

/// The string that gets signed: `path` plus `?query` in openQA's canonical
/// query form (see [`canonical_query`]), omitted entirely when the query is
/// empty. The path is passed through unchanged: the server's `REST` plugin
/// re-parses and re-serializes the query before `_valid_hmac` hashes it
/// (`Mojo::Parameters::to_string`), but never touches the path.
#[must_use]
pub fn signing_string(url: &Url) -> String {
    let mut out = url.path().to_owned();
    if let Some(query) = url.query() {
        let canonical = canonical_query(query);
        if !canonical.is_empty() {
            out.push('?');
            out.push_str(&canonical);
        }
    }
    out
}

/// Re-serializes a raw wire query the way `Mojo::Parameters::to_string`
/// does: split on `&` (empty pieces dropped), each piece split on the first
/// `=` (a bare key gets an empty value), percent-decoded (`+` -> space),
/// then re-encoded with Mojo's unreserved set (`A-Za-z0-9*-._`), space ->
/// `+`, everything else `%XX` uppercase hex, joined back with `&`.
/// Operates on raw bytes throughout — never through a `String` — so an
/// invalid percent sequence or non-UTF-8 byte round-trips unchanged.
#[must_use]
pub fn canonical_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut first = true;
    for piece in query.split('&').filter(|p| !p.is_empty()) {
        if !first {
            out.push('&');
        }
        first = false;
        let bytes = piece.as_bytes();
        let (name, value): (&[u8], &[u8]) = match bytes.iter().position(|&b| b == b'=') {
            Some(i) => (&bytes[..i], &bytes[i + 1..]),
            None => (bytes, &[]),
        };
        encode_canonical(&mut out, name);
        out.push('=');
        encode_canonical(&mut out, value);
    }
    out
}

/// Percent-decodes `raw` (`+` -> space) and re-encodes each decoded byte per
/// [`canonical_query`]'s rules.
fn encode_canonical(out: &mut String, raw: &[u8]) {
    let mut i = 0;
    while i < raw.len() {
        let byte = match raw[i] {
            b'+' => {
                i += 1;
                b' '
            }
            b'%' if i + 2 < raw.len()
                && hex_val(raw[i + 1]).is_some()
                && hex_val(raw[i + 2]).is_some() =>
            {
                let decoded = hex_val(raw[i + 1]).unwrap() * 16 + hex_val(raw[i + 2]).unwrap();
                i += 3;
                decoded
            }
            b => {
                i += 1;
                b
            }
        };
        match byte {
            b' ' => out.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(byte as char);
            }
            _ => write!(out, "%{byte:02X}").expect("writing to a String cannot fail"),
        }
    }
}

/// Decodes one ASCII hex digit, case-insensitively.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
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

/// Seconds since the epoch as a decimal with a fractional part. The server
/// does a numeric `abs()` comparison, so an integer or float both parse.
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

    /// The query is re-serialized in openQA's canonical form: a literal `~`
    /// is not in the unreserved set, so it comes out `%7E`.
    #[test]
    fn query_space_becomes_plus_tilde_is_percent_encoded() {
        let url = Url::parse("https://openqa.example/api/v1/jobs?test=foo bar&u=~name").unwrap();
        let signing = signing_string(&url);
        assert_eq!(signing, "/api/v1/jobs?test=foo+bar&u=%7Ename");

        let secret = ApiSecret::new("SECRET02");
        let hash = sign(&signing, "1700000000.0", &secret);
        assert_eq!(hash, "6cd9bba9e451c1371f77070fa2ddd0ed4444fd1b");
    }

    /// A space in a path segment stays `%20` (the path is never
    /// re-serialized); only the query's spaces become `+`.
    #[test]
    fn path_space_stays_percent_20() {
        let url = Url::parse("https://openqa.example/api/v1/assets/iso/foo bar.iso?q=a b").unwrap();
        assert_eq!(
            signing_string(&url),
            "/api/v1/assets/iso/foo%20bar.iso?q=a+b"
        );
    }

    #[test]
    fn canonical_query_matches_the_server_table() {
        let cases = [
            ("u=~name", "u=%7Ename"),
            ("q=a%20b", "q=a+b"),
            (
                "BUILD=:123:kernel&ASSET_URL=https://x/y",
                "BUILD=%3A123%3Akernel&ASSET_URL=https%3A%2F%2Fx%2Fy",
            ),
            ("a&b=1", "a=&b=1"),
            ("x=%c3%a9", "x=%C3%A9"),
            ("t=a+b%2Bc", "t=a+b%2Bc"),
            ("", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(canonical_query(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn canonical_query_is_idempotent() {
        for query in ["u=~name", "BUILD=:123:kernel", "a&b=1", "x=%c3%a9", ""] {
            let once = canonical_query(query);
            let twice = canonical_query(&once);
            assert_eq!(once, twice, "input: {query:?}");
        }
    }

    /// A caller-supplied literal `%7E` in the path is neither encoded nor decoded.
    #[test]
    fn path_percent_7e_passes_through_unchanged() {
        let url = Url::parse("https://openqa.example/api/v1/%7Ename/jobs").unwrap();
        assert_eq!(signing_string(&url), "/api/v1/%7Ename/jobs");
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
