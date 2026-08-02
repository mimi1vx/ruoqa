// SPDX-License-Identifier: GPL-3.0-or-later

//! Redacted wrappers for API credentials.

use std::fmt;

use zeroize::ZeroizeOnDrop;

/// The openQA API key. Not secret, but an identifier that should not leak
/// into logs by accident.
#[derive(Clone)]
pub struct ApiKey(Box<str>);

impl ApiKey {
    pub fn new(key: impl Into<Box<str>>) -> Self {
        Self(key.into())
    }

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
    pub fn new(secret: impl Into<Box<str>>) -> Self {
        Self(secret.into())
    }

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
}
