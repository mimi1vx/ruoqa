// SPDX-License-Identifier: GPL-3.0-or-later

//! Redacted wrappers for API credentials.

use std::fmt;

use url::Url;
use zeroize::ZeroizeOnDrop;

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
}
