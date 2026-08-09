// SPDX-License-Identifier: GPL-3.0-or-later

//! Error types returned by `ruoqa`.

use std::time::Duration;

use thiserror::Error;

use crate::secret::RedactedUrl;

/// The error type for all fallible `ruoqa` operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The server responded with a non-success HTTP status.
    #[error("{method} {} returned {status}", RedactedUrl(url))]
    Request {
        /// The HTTP method that was sent.
        method: reqwest::Method,
        /// The URL that returned the error.
        url: url::Url,
        /// The response's HTTP status code.
        status: reqwest::StatusCode,
        /// A truncated preview of the response body.
        body: String,
    },

    /// The request could not reach the server.
    #[error("failed to connect to {}", RedactedUrl(url))]
    Connection {
        /// The URL the connection attempt targeted.
        url: url::Url,
        /// The underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// `client.conf` could not be located or parsed.
    #[error("configuration error: {0}")]
    Config(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// TLS setup failed.
    #[error("TLS error: {0}")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The response body could not be parsed as JSON or YAML.
    #[error("failed to parse response body: {0}")]
    Parse(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The response body exceeded the configured size limit.
    #[error("response body exceeded the {limit}-byte limit")]
    BodyTooLarge {
        /// The configured `max_response_bytes` limit that was exceeded.
        limit: usize,
    },

    /// The request was redirected more times than allowed.
    #[error("exceeded the maximum of {max} redirects")]
    TooManyRedirects {
        /// The configured `max_redirects` limit that was exceeded.
        max: usize,
    },

    /// A redirect pointed at a different origin than the original request.
    #[error(
        "refusing to follow redirect from {} to a different origin {}",
        RedactedUrl(from),
        RedactedUrl(to)
    )]
    CrossOriginRedirect {
        /// The URL that issued the redirect.
        from: url::Url,
        /// The cross-origin `Location` it pointed to.
        to: url::Url,
    },

    /// A request URL's origin does not match the client's base URL.
    #[error(
        "refusing to send {} to a different origin than the base URL {}",
        RedactedUrl(url),
        RedactedUrl(base)
    )]
    CrossOriginRequest {
        /// The client's configured base URL.
        base: url::Url,
        /// The request URL that resolved to a different origin.
        url: url::Url,
    },

    /// A request URL is structurally rejected independent of its origin,
    /// e.g. a non-relative `path` or userinfo in a resolved URL.
    #[error("unsupported request URL {}: {reason}", RedactedUrl(url))]
    UnsupportedRequestUrl {
        /// The rejected URL.
        url: url::Url,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The overall retry deadline elapsed before the request succeeded.
    /// `elapsed` is measured from the start of the `Client::execute` call,
    /// not from the current redirect hop. This does **not** imply the
    /// server did not process the request: an aborted in-flight write may
    /// already have been committed.
    #[error("deadline exceeded after {elapsed:?}")]
    DeadlineExceeded {
        /// How long the retry loop ran before giving up.
        elapsed: Duration,
    },

    /// A request path could not be resolved against the client's base URL.
    #[error("invalid request path {path:?}: {source}")]
    InvalidPath {
        /// The path that failed to resolve.
        path: String,
        /// The underlying URL-parsing error.
        #[source]
        source: url::ParseError,
    },

    /// `http_client` was combined with a builder option the injected
    /// client owns itself.
    #[error(
        "`http_client` cannot be combined with `{option}`: the injected reqwest::Client owns its own TLS and timeout configuration"
    )]
    IncompatibleHttpClient {
        /// The conflicting builder option (`"tls"` or `"timeouts"`).
        option: &'static str,
    },

    /// A credential source supplied a key without a secret, or vice versa.
    #[error("incomplete openQA credentials from {origin}: {present} is set but {missing} is not")]
    IncompleteCredentials {
        /// Where the partial pair came from, e.g. `"the environment"`.
        origin: &'static str,
        /// The name of the credential half that was supplied.
        present: &'static str,
        /// The name of the credential half that was missing.
        missing: &'static str,
    },
}

/// A specialized [`Result`](std::result::Result) using [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync_static<T: Send + Sync + 'static>() {}

    #[test]
    fn error_is_send_sync_static() {
        assert_send_sync_static::<Error>();
    }
}
