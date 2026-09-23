// SPDX-License-Identifier: GPL-3.0-or-later

//! Redacted wrappers for API credentials.

use std::fmt;

use reqwest::header::HeaderValue;
use url::Url;
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

/// The openQA API key. Not secret, but an identifier that should not leak
/// into logs by accident.
#[derive(Clone)]
pub struct ApiKey(Box<str>);

impl ApiKey {
    /// Wraps `key` as an [`ApiKey`].
    pub fn new(key: impl Into<Box<str>>) -> Self {
        Self(key.into())
    }

    /// Returns the key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiKey").field(&"***").finish()
    }
}

/// The openQA API secret. Zeroized on drop and never printed.
#[derive(ZeroizeOnDrop)]
pub struct ApiSecret(Box<str>);

impl ApiSecret {
    /// Wraps `secret` as an [`ApiSecret`].
    pub fn new(secret: impl Into<Box<str>>) -> Self {
        Self(secret.into())
    }

    /// Returns the secret as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiSecret").field(&"***").finish()
    }
}

/// The openQA username paired with an API key/secret to authenticate via a
/// Bearer personal access token instead of HMAC signing. Not secret — it is
/// the identity a token belongs to, not the token itself — so unlike
/// [`ApiKey`]/[`ApiSecret`] its `Debug` is not redacted.
#[derive(Debug, Clone)]
pub struct Username(Box<str>);

impl Username {
    /// Wraps `username` as a [`Username`].
    pub fn new(username: impl Into<Box<str>>) -> Self {
        Self(username.into())
    }

    /// Returns the username as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A complete openQA credential pair. The key and the secret are always
/// resolved together and from a single source: a key without a secret
/// cannot sign, and a key from one source paired with a secret from
/// another only ever produces a 403.
#[derive(Debug)]
pub(crate) struct Credentials {
    pub(crate) key: ApiKey,
    pub(crate) secret: ApiSecret,
}

impl Credentials {
    /// Pairs `key` with `secret`, rejecting a half-supplied pair. `names` is
    /// `(key_name, secret_name)` as the caller's source spells them, used
    /// only for the error message.
    pub(crate) fn from_parts(
        key: Option<ApiKey>,
        secret: Option<ApiSecret>,
        source: &'static str,
        names: (&'static str, &'static str),
    ) -> Result<Option<Self>> {
        match (key, secret) {
            (Some(key), Some(secret)) => Ok(Some(Self { key, secret })),
            (None, None) => Ok(None),
            (Some(_), None) => Err(Error::IncompleteCredentials {
                origin: source,
                present: names.0,
                missing: names.1,
            }),
            (None, Some(_)) => Err(Error::IncompleteCredentials {
                origin: source,
                present: names.1,
                missing: names.0,
            }),
        }
    }

    /// Builds the `Authorization: Bearer <user>:<key>:<secret>` header value
    /// openQA's `_token_auth` expects, marked sensitive so it never surfaces
    /// through header-logging middleware. Built fresh at sign time rather
    /// than cached on `Client`, so the secret's only header-shaped copy is
    /// the one in flight.
    ///
    /// # Panics
    ///
    /// Never in practice: [`ClientBuilder::build`](crate::ClientBuilder::build)
    /// already rejects a `username`/key/secret combination that would fail
    /// to become a valid header value.
    pub(crate) fn bearer_value(&self, user: &Username) -> HeaderValue {
        let mut value = HeaderValue::from_str(&format!(
            "Bearer {}:{}:{}",
            user.as_str(),
            self.key.as_str(),
            self.secret.as_str(),
        ))
        .expect("ClientBuilder::build already validated this combination");
        value.set_sensitive(true);
        value
    }
}

/// Wraps a [`Url`] so `Display`/`Debug` never carry its userinfo. Renders
/// `scheme://***@host…` when a username or password is present, otherwise
/// the URL unchanged — an `@` in the path or query is untouched, since only
/// [`Url::username`]/[`Url::password`] are consulted, not the rendered
/// string.
pub(crate) struct RedactedUrl<'a>(pub &'a Url);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = self.0;
        if url.username().is_empty() && url.password().is_none() {
            return fmt::Display::fmt(url, f);
        }
        let mut redacted = url.clone();
        let _ = redacted.set_password(None);
        let _ = redacted.set_username("***");
        fmt::Display::fmt(&redacted, f)
    }
}

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = ApiSecret::new("supersecretvalue");
        let debug = format!("{secret:?}");
        assert_eq!(debug, r#"ApiSecret("***")"#);
        assert!(!debug.contains(secret.as_str()));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = ApiKey::new("1234567890ABCDEF");
        let debug = format!("{key:?}");
        assert_eq!(debug, r#"ApiKey("***")"#);
        assert!(!debug.contains(key.as_str()));
        assert!(!debug.contains("1234"));
    }

    #[test]
    fn credentialed_url_redacts_username_and_password() {
        let url = Url::parse("https://alice:s3cret@openqa.example.com/tests").unwrap();
        let display = RedactedUrl(&url).to_string();
        assert!(!display.contains("alice"));
        assert!(!display.contains("s3cret"));
        assert_eq!(display, "https://***@openqa.example.com/tests");
        assert_eq!(format!("{:?}", RedactedUrl(&url)), display);
    }

    #[test]
    fn clean_url_is_unchanged() {
        let url = Url::parse("https://openqa.example.com/tests?a=1").unwrap();
        assert_eq!(RedactedUrl(&url).to_string(), url.as_str());
    }

    #[test]
    fn at_sign_in_path_is_not_mistaken_for_userinfo() {
        let url = Url::parse("https://openqa.example.com/users/me@example.com").unwrap();
        assert_eq!(RedactedUrl(&url).to_string(), url.as_str());
    }

    #[test]
    fn credentials_debug_is_redacted() {
        let credentials = Credentials::from_parts(
            Some(ApiKey::new("1234567890ABCDEF")),
            Some(ApiSecret::new("supersecretvalue")),
            "test",
            ("key", "secret"),
        )
        .unwrap()
        .unwrap();
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("1234567890ABCDEF"));
        assert!(!debug.contains("supersecretvalue"));
    }

    #[test]
    fn credentials_from_parts_both_present_pairs() {
        let credentials = Credentials::from_parts(
            Some(ApiKey::new("K")),
            Some(ApiSecret::new("S")),
            "test",
            ("key", "secret"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(credentials.key.as_str(), "K");
        assert_eq!(credentials.secret.as_str(), "S");
    }

    #[test]
    fn credentials_from_parts_both_absent_is_none() {
        let credentials = Credentials::from_parts(None, None, "test", ("key", "secret")).unwrap();
        assert!(credentials.is_none());
    }

    #[test]
    fn credentials_from_parts_key_only_errors() {
        let err = Credentials::from_parts(Some(ApiKey::new("K")), None, "test", ("key", "secret"))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                origin: "test",
                present: "key",
                missing: "secret"
            }
        ));
    }

    #[test]
    fn bearer_value_has_expected_format_and_is_sensitive() {
        let credentials = Credentials::from_parts(
            Some(ApiKey::new("KEY")),
            Some(ApiSecret::new("SECRET")),
            "test",
            ("key", "secret"),
        )
        .unwrap()
        .unwrap();
        let value = credentials.bearer_value(&Username::new("alice"));
        assert_eq!(value.to_str().unwrap(), "Bearer alice:KEY:SECRET");
        assert!(value.is_sensitive());
    }

    #[test]
    fn credentials_from_parts_secret_only_errors() {
        let err =
            Credentials::from_parts(None, Some(ApiSecret::new("S")), "test", ("key", "secret"))
                .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                origin: "test",
                present: "secret",
                missing: "key"
            }
        ));
    }
}
