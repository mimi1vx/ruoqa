// SPDX-License-Identifier: GPL-3.0-or-later

//! The async openQA API client: builder, retry loop, restricted redirects,
//! and capped response parsing.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::policy::{RetryPolicy, Timeouts};
use crate::secret::{ApiKey, ApiSecret};
use crate::tls::TlsMode;
use crate::{auth, config};

/// 32 MiB: generous for JSON/YAML API responses, wrong for asset downloads
/// (use [`Client::send_raw`] for those).
const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// How many redirect hops [`Client`] will follow before giving up.
const DEFAULT_MAX_REDIRECTS: usize = 3;

/// How much of a non-2xx response body to keep for [`Error::Request`]'s
/// message: enough to be useful, not enough to blow up logs.
const ERROR_BODY_PREVIEW_BYTES: usize = 8 * 1024;

const X_API_KEY: &str = "x-api-key";

/// Builds a [`Client`]. See the crate docs for the full option list.
pub struct ClientBuilder {
    server: String,
    scheme: String,
    api_key: Option<ApiKey>,
    api_secret: Option<ApiSecret>,
    timeouts: Timeouts,
    retry: RetryPolicy,
    tls: TlsMode,
    max_response_bytes: usize,
    max_redirects: usize,
    user_agent: String,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("server", &self.server)
            .field("scheme", &self.scheme)
            .field("api_key", &self.api_key)
            .field("api_secret", &self.api_secret)
            .field("timeouts", &self.timeouts)
            .field("retry", &self.retry)
            .field("tls", &self.tls)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_redirects", &self.max_redirects)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            server: String::new(),
            scheme: String::new(),
            api_key: None,
            api_secret: None,
            timeouts: Timeouts::default(),
            retry: RetryPolicy::default(),
            tls: TlsMode::default(),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            user_agent: format!("ruoqa/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl ClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The openQA host, e.g. `openqa.example.com` or a full `http(s)://` URL.
    /// Empty uses `client.conf`'s first section, or `localhost`.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.server = server.into();
        self
    }

    /// Empty infers `http` for loopback hosts, `https` otherwise (or is taken
    /// from `server` when it already carries a scheme).
    #[must_use]
    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Overrides the API key from `client.conf`, if any.
    #[must_use]
    pub fn api_key(mut self, api_key: ApiKey) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Overrides the API secret from `client.conf`, if any.
    #[must_use]
    pub fn api_secret(mut self, api_secret: ApiSecret) -> Self {
        self.api_secret = Some(api_secret);
        self
    }

    #[must_use]
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    #[must_use]
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub fn tls(mut self, tls: TlsMode) -> Self {
        self.tls = tls;
        self
    }

    #[must_use]
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    #[must_use]
    pub fn max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Resolves `client.conf`, builds the underlying `reqwest::Client`, and
    /// returns a ready-to-use [`Client`].
    ///
    /// Automatic redirects and retries are disabled on the underlying
    /// `reqwest::Client` (`redirect::Policy::none()`,
    /// `reqwest::retry::never()`): [`Client`] implements both itself, since
    /// they must re-sign every attempt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `client.conf` fails to parse, or
    /// [`Error::Tls`] if the underlying HTTP client fails to build (usually a
    /// bad custom CA bundle).
    #[allow(clippy::result_large_err)] // `Error`'s size is a phase-1 decision; not this fn's to fix.
    pub fn build(self) -> Result<Client> {
        let resolved = config::resolve(&config::default_paths(), &self.server, &self.scheme)?;
        let api_key = self.api_key.or(resolved.api_key);
        let api_secret = self.api_secret.or(resolved.api_secret);
        let base_url = resolved.base_url;

        if (api_key.is_some() || api_secret.is_some())
            && base_url.scheme() == "http"
            && !is_loopback_host(&base_url)
        {
            tracing::warn!(
                url = %base_url,
                "sending openQA API credentials over plaintext http to a non-loopback host"
            );
        }

        let mut default_headers = HeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        if let Some(key) = &api_key {
            default_headers.insert(
                HeaderName::from_static(X_API_KEY),
                HeaderValue::from_str(key.as_str()).map_err(|e| Error::Config(Box::new(e)))?,
            );
        }

        let mut builder = reqwest::ClientBuilder::new()
            .user_agent(self.user_agent)
            .default_headers(default_headers)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(self.timeouts.connect)
            .read_timeout(self.timeouts.read)
            .timeout(self.timeouts.total)
            .pool_idle_timeout(self.timeouts.pool_idle);
        builder = self.tls.apply(builder);

        let http = builder.build().map_err(|e| Error::Tls(Box::new(e)))?;

        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base_url,
                api_key,
                api_secret,
                max_response_bytes: self.max_response_bytes,
                max_redirects: self.max_redirects,
                retry: Mutex::new(self.retry),
            }),
        })
    }
}

/// `true` for `localhost` and loopback IPs; matches the loopback set used by
/// [`config::resolve`]'s scheme defaulting.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

struct Inner {
    http: reqwest::Client,
    base_url: Url,
    api_key: Option<ApiKey>,
    api_secret: Option<ApiSecret>,
    max_response_bytes: usize,
    max_redirects: usize,
    retry: Mutex<RetryPolicy>,
}

/// An async openQA API client. Cheaply cloneable (an `Arc` internally), like
/// `reqwest::Client`.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl fmt::Debug for Client {
    /// Deliberately does not delegate to the inner `reqwest::Client`'s
    /// `Debug` impl, which would print the `X-API-Key` default header in the
    /// clear. `ApiKey`/`ApiSecret` redact themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.inner.base_url)
            .field("api_key", &self.inner.api_key)
            .field("api_secret", &self.inner.api_secret)
            .field("max_response_bytes", &self.inner.max_response_bytes)
            .field("max_redirects", &self.inner.max_redirects)
            .finish_non_exhaustive()
    }
}

/// Everything needed to build a fresh, freshly-signed `reqwest::Request` on
/// every attempt: the server's 300 s HMAC tolerance means a signature
/// computed before a long backoff would be rejected, so signing happens at
/// send time, not once up front.
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

impl Client {
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.inner.base_url
    }

    /// Resolves `path` against the client's base URL and, for `body`,
    /// serializes it as a JSON request body (`Content-Type: application/json`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPath`] if `path` cannot be joined onto the
    /// base URL, or [`Error::Parse`] if `body` cannot be serialized.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub fn prepare(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<PreparedRequest> {
        let url = self
            .inner
            .base_url
            .join(path)
            .map_err(|source| Error::InvalidPath {
                path: path.to_owned(),
                source,
            })?;

        let mut headers = HeaderMap::new();
        let body = match body {
            Some(value) => {
                let bytes = serde_json::to_vec(value).map_err(|e| Error::Parse(Box::new(e)))?;
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                Some(Bytes::from(bytes))
            }
            None => None,
        };

        Ok(PreparedRequest {
            method,
            url,
            headers,
            body,
        })
    }

    /// Sends `method path` with an optional JSON `body` and parses the
    /// response as JSON or YAML (see [`Client::send_raw`] to bypass parsing
    /// and the response-size cap).
    ///
    /// # Errors
    ///
    /// See [`Client::execute`] and the module docs for the full error list.
    pub async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let prepared = self.prepare(method, path, body)?;
        let mut resp = self.execute(&prepared, false).await?;
        self.handle_response(&prepared, &mut resp).await
    }

    /// Like [`Client::request`], deserializing into `T` instead of a generic
    /// [`Value`].
    ///
    /// # Errors
    ///
    /// See [`Client::request`].
    pub async fn request_as<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T> {
        let value = self.request(method, path, body).await?;
        serde_json::from_value(value).map_err(|e| Error::Parse(Box::new(e)))
    }

    /// Sends `method path` and returns the raw `reqwest::Response`, bypassing
    /// the response-size cap and body parsing entirely. Intended for large
    /// asset downloads.
    ///
    /// # Errors
    ///
    /// See [`Client::execute`].
    pub async fn send_raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response> {
        let prepared = self.prepare(method, path, body)?;
        self.execute(&prepared, false).await
    }

    /// Executes `prepared`, retrying transient failures and following
    /// same-origin redirects, and returns the raw response (still subject to
    /// non-2xx status: the caller is responsible for turning that into an
    /// error, as [`Client::request`] does internally).
    ///
    /// `retry_non_idempotent` opts a non-idempotent method (e.g. `POST`) into
    /// transport-error retries, which are otherwise restricted to
    /// [`RetryPolicy::retry_methods`].
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] on an unretried transport failure,
    /// [`Error::CrossOriginRedirect`] on a cross-origin redirect, or
    /// [`Error::TooManyRedirects`] past `max_redirects`.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub async fn execute(
        &self,
        prepared: &PreparedRequest,
        retry_non_idempotent: bool,
    ) -> Result<reqwest::Response> {
        let mut current = prepared.clone();
        let mut redirects_followed = 0usize;
        loop {
            let resp = self
                .send_with_retries(&current, retry_non_idempotent)
                .await?;
            match redirect_target(&current, &resp)? {
                Some(next) => {
                    redirects_followed += 1;
                    if redirects_followed > self.inner.max_redirects {
                        return Err(Error::TooManyRedirects {
                            max: self.inner.max_redirects,
                        });
                    }
                    current = next;
                }
                None => return Ok(resp),
            }
        }
    }

    /// The retry loop proper (mirrors `aclient.py::do_request`): retries
    /// transport errors and retryable statuses with jittered, capped
    /// backoff, honoring `Retry-After` and the overall deadline.
    async fn send_with_retries(
        &self,
        prepared: &PreparedRequest,
        retry_non_idempotent: bool,
    ) -> Result<reqwest::Response> {
        let loop_start = Instant::now();
        let (max_retries, deadline) = {
            let policy = self.inner.retry.lock().unwrap();
            (policy.max_retries, policy.deadline)
        };

        for attempt in 0..=max_retries {
            let start = Instant::now();
            let req = self.sign(prepared);

            match self.inner.http.execute(req).await {
                Ok(resp) => {
                    let status = resp.status();
                    let retryable = self
                        .inner
                        .retry
                        .lock()
                        .unwrap()
                        .retry_statuses
                        .contains(&status);
                    if !retryable || attempt >= max_retries {
                        return Ok(resp);
                    }

                    let retry_after = {
                        let policy = self.inner.retry.lock().unwrap();
                        policy.parse_retry_after(resp.headers())
                    };
                    let backoff = self.inner.retry.lock().unwrap().backoff_for(attempt);
                    let delay = retry_after.map_or(backoff, |ra| ra.max(backoff));

                    if let Some(deadline) = deadline
                        && loop_start.elapsed() + delay >= deadline
                    {
                        return Ok(resp);
                    }

                    tracing::debug!(
                        attempt,
                        %status,
                        ?delay,
                        elapsed = ?start.elapsed(),
                        "retrying openQA request"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(source) => {
                    let eligible = retry_non_idempotent
                        || self
                            .inner
                            .retry
                            .lock()
                            .unwrap()
                            .retry_methods
                            .contains(&prepared.method);
                    if !eligible || attempt >= max_retries {
                        return Err(Error::Connection {
                            url: prepared.url.clone(),
                            source,
                        });
                    }

                    let backoff = self.inner.retry.lock().unwrap().backoff_for(attempt);
                    if let Some(deadline) = deadline
                        && loop_start.elapsed() + backoff >= deadline
                    {
                        return Err(Error::Connection {
                            url: prepared.url.clone(),
                            source,
                        });
                    }

                    tracing::debug!(
                        attempt,
                        error = %source,
                        ?backoff,
                        elapsed = ?start.elapsed(),
                        "retrying openQA request after a transport error"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        unreachable!("the loop above always returns on or before attempt == max_retries")
    }

    /// Builds a fresh `reqwest::Request` from `prepared`, signing it (fresh
    /// timestamp and hash) right before sending.
    fn sign(&self, prepared: &PreparedRequest) -> reqwest::Request {
        let mut headers = prepared.headers.clone();
        auth::apply(&mut headers, &prepared.url, self.inner.api_secret.as_ref());

        let mut req = reqwest::Request::new(prepared.method.clone(), prepared.url.clone());
        *req.headers_mut() = headers;
        if let Some(body) = &prepared.body {
            *req.body_mut() = Some(reqwest::Body::from(body.clone()));
        }
        req
    }

    /// Mirrors `_handle_response`'s branch order: non-2xx errors first
    /// (with a truncated body for the error message), then `204`, then
    /// content-type-driven JSON/YAML parsing.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    async fn handle_response(
        &self,
        prepared: &PreparedRequest,
        resp: &mut reqwest::Response,
    ) -> Result<Value> {
        let status = resp.status();

        if !status.is_success() {
            let body = read_truncated(resp, ERROR_BODY_PREVIEW_BYTES).await;
            return Err(Error::Request {
                method: prepared.method.clone(),
                url: resp.url().clone(),
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }

        if status == StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();

        let bytes = read_capped(resp, self.inner.max_response_bytes).await?;

        if content_type.starts_with("text/yaml") {
            parse_yaml(&bytes)
        } else {
            serde_json::from_slice(&bytes).map_err(|e| Error::Parse(Box::new(e)))
        }
    }
}

/// `Some(next)` if `resp` is a same-origin redirect to follow; `Ok(None)`
/// for a non-redirect (or a redirect without a usable `Location`, which is
/// treated as final rather than guessed at). Never forwards
/// `X-API-Key`/`X-API-Hash` off-origin: a cross-origin `Location` errors
/// before any request to it is ever built.
#[allow(clippy::result_large_err)] // see `ClientBuilder::build`
fn redirect_target(
    current: &PreparedRequest,
    resp: &reqwest::Response,
) -> Result<Option<PreparedRequest>> {
    let status = resp.status();
    if !matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        return Ok(None);
    }

    let Some(location) = resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Ok(next_url) = current.url.join(location) else {
        return Ok(None);
    };

    if current.url.origin() != next_url.origin() {
        return Err(Error::CrossOriginRedirect {
            from: current.url.clone(),
            to: next_url,
        });
    }

    let (method, body, headers) = if status == StatusCode::SEE_OTHER {
        (Method::GET, None, HeaderMap::new())
    } else {
        (
            current.method.clone(),
            current.body.clone(),
            current.headers.clone(),
        )
    };

    Ok(Some(PreparedRequest {
        method,
        url: next_url,
        headers,
        body,
    }))
}

/// Streams the response body via `Response::chunk()`, bailing with
/// [`Error::BodyTooLarge`] as soon as `limit` would be exceeded (rather than
/// buffering the whole thing first).
async fn read_capped(resp: &mut reqwest::Response, limit: usize) -> Result<Bytes> {
    let mut buf = BytesMut::new();
    while let Some(chunk) = resp.chunk().await.map_err(|source| Error::Connection {
        url: resp.url().clone(),
        source,
    })? {
        if buf.len() + chunk.len() > limit {
            return Err(Error::BodyTooLarge { limit });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// Best-effort read of up to `limit` bytes, for error-message previews.
/// Never fails: a transport error while reading an already-failed response's
/// body just means a shorter (or empty) preview.
async fn read_truncated(resp: &mut reqwest::Response, limit: usize) -> Bytes {
    let mut buf = BytesMut::new();
    while buf.len() < limit {
        match resp.chunk().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            _ => break,
        }
    }
    buf.truncate(limit);
    buf.freeze()
}

/// Conservative YAML parsing options (see the phase-4 plan's "Watch for"
/// section): exact `true`/`false` only (no YAML 1.1 `yes`/`no`/`on`/`off`
/// inference, a deliberate divergence from the Python client's `PyYAML` use),
/// non-finite floats rejected rather than silently stringified (already the
/// crate default), and a tighter-than-default alias/event budget since a
/// response body is at most a few tens of MiB, never the crate's 256 MiB
/// reader default.
fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        budget: serde_saphyr::budget! {
            max_documents: 1,
            max_events: 100_000,
            max_nodes: 20_000,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: 50_000,
        },
    }
}

#[allow(clippy::result_large_err)] // see `ClientBuilder::build`
fn parse_yaml(bytes: &[u8]) -> Result<Value> {
    serde_saphyr::from_slice_with_options(bytes, yaml_options())
        .map_err(|e| Error::Parse(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    fn builder_defaults() {
        let builder = ClientBuilder::new();
        assert_eq!(builder.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(builder.max_redirects, DEFAULT_MAX_REDIRECTS);
        assert!(builder.user_agent.starts_with("ruoqa/"));
    }

    #[test]
    fn build_with_explicit_credentials_and_disabled_verification() {
        let client = ClientBuilder::new()
            .server("localhost:9526")
            .api_key(ApiKey::new("KEY"))
            .api_secret(ApiSecret::new("SECRET"))
            .tls(TlsMode::danger_accept_invalid_certs())
            .build()
            .unwrap();
        assert_eq!(client.inner.api_key.as_ref().unwrap().as_str(), "KEY");
        assert_eq!(client.inner.api_secret.as_ref().unwrap().as_str(), "SECRET");
    }

    #[test]
    fn client_debug_redacts_key_and_secret() {
        let client = ClientBuilder::new()
            .server("localhost:9526")
            .api_key(ApiKey::new("SUPERSECRETKEY"))
            .api_secret(ApiSecret::new("SUPERSECRETVALUE"))
            .build()
            .unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains("SUPERSECRETKEY"));
        assert!(!debug.contains("SUPERSECRETVALUE"));
    }

    #[test]
    #[traced_test]
    fn warns_for_plaintext_http_creds_to_non_loopback_host() {
        ClientBuilder::new()
            .server("http://openqa.example.com")
            .api_key(ApiKey::new("KEY"))
            .api_secret(ApiSecret::new("SECRET"))
            .build()
            .unwrap();
        assert!(logs_contain(
            "sending openQA API credentials over plaintext http"
        ));
    }

    #[test]
    #[traced_test]
    fn no_warning_for_loopback_http_creds() {
        ClientBuilder::new()
            .server("http://localhost:9526")
            .api_key(ApiKey::new("KEY"))
            .api_secret(ApiSecret::new("SECRET"))
            .build()
            .unwrap();
        assert!(!logs_contain("plaintext"));
    }

    #[test]
    #[traced_test]
    fn no_warning_without_credentials() {
        ClientBuilder::new()
            .server("http://openqa.example.com")
            .build()
            .unwrap();
        assert!(!logs_contain("plaintext"));
    }

    #[test]
    fn is_loopback_host_matches_localhost_and_loopback_ips() {
        assert!(is_loopback_host(&Url::parse("http://localhost").unwrap()));
        assert!(is_loopback_host(&Url::parse("http://127.0.0.1").unwrap()));
        assert!(is_loopback_host(&Url::parse("http://[::1]").unwrap()));
        assert!(!is_loopback_host(
            &Url::parse("http://openqa.example.com").unwrap()
        ));
    }
}
