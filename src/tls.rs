// SPDX-License-Identifier: GPL-3.0-or-later

//! TLS verification modes for outbound connections.

use reqwest::ClientBuilder;
use reqwest::tls::{Certificate, Version};

/// How TLS certificate verification should behave.
#[derive(Debug, Default)]
pub enum TlsMode {
    /// Use the OS trust store (reqwest's default): enterprise/internal CAs
    /// installed system-wide just work.
    #[default]
    PlatformVerifier,
    /// Trust a custom CA bundle, built from `Certificate::from_pem_bundle` /
    /// `from_pem` / `from_der`. `replace_roots = true` pins to *only* the
    /// supplied CA, discarding the platform roots.
    CustomCa {
        /// The CA certificate(s) to trust.
        certs: Vec<Certificate>,
        /// If `true`, trust *only* `certs`, discarding the platform roots.
        replace_roots: bool,
    },
    /// Disable certificate verification entirely. Dangerous: applying this
    /// mode logs a `tracing::warn!`, however it was constructed.
    DangerAcceptInvalid,
}

impl TlsMode {
    /// Builds a [`TlsMode::DangerAcceptInvalid`]. Named loudly so it cannot
    /// be enabled by accident; applying it warns via `tracing::warn!` when
    /// the client is built.
    #[must_use]
    pub fn danger_accept_invalid_certs() -> Self {
        Self::DangerAcceptInvalid
    }

    /// Applies this mode to `builder`, plus a TLS 1.2 floor.
    pub fn apply(self, builder: ClientBuilder) -> ClientBuilder {
        let builder = builder.tls_version_min(Version::TLS_1_2);
        match self {
            Self::PlatformVerifier => builder,
            Self::CustomCa {
                certs,
                replace_roots: true,
            } => builder.tls_certs_only(certs),
            Self::CustomCa {
                certs,
                replace_roots: false,
            } => builder.tls_certs_merge(certs),
            Self::DangerAcceptInvalid => {
                tracing::warn!(
                    "TLS certificate verification is disabled: connections are not \
                     protected against man-in-the-middle attacks"
                );
                builder.tls_danger_accept_invalid_certs(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    fn default_is_platform_verifier() {
        assert!(matches!(TlsMode::default(), TlsMode::PlatformVerifier));
    }

    #[test]
    fn platform_verifier_builds() {
        let _ = TlsMode::PlatformVerifier.apply(ClientBuilder::new());
    }

    #[test]
    fn custom_ca_merge_builds() {
        let mode = TlsMode::CustomCa {
            certs: vec![],
            replace_roots: false,
        };
        let _ = mode.apply(ClientBuilder::new());
    }

    #[test]
    fn custom_ca_replace_builds() {
        let mode = TlsMode::CustomCa {
            certs: vec![],
            replace_roots: true,
        };
        let _ = mode.apply(ClientBuilder::new());
    }

    #[test]
    fn danger_accept_invalid_builds() {
        let _ = TlsMode::danger_accept_invalid_certs().apply(ClientBuilder::new());
    }

    #[test]
    #[traced_test]
    fn applying_the_danger_variant_directly_warns() {
        let _ = TlsMode::DangerAcceptInvalid.apply(ClientBuilder::new());
        assert!(logs_contain("TLS certificate verification is disabled"));
    }

    #[test]
    #[traced_test]
    fn constructing_the_danger_variant_does_not_warn() {
        let _ = TlsMode::danger_accept_invalid_certs();
        assert!(!logs_contain("TLS certificate verification is disabled"));
    }

    #[test]
    #[traced_test]
    fn safe_modes_do_not_warn() {
        let _ = TlsMode::PlatformVerifier.apply(ClientBuilder::new());
        let _ = TlsMode::CustomCa {
            certs: vec![],
            replace_roots: false,
        }
        .apply(ClientBuilder::new());
        assert!(!logs_contain("TLS certificate verification is disabled"));
    }
}
