// SPDX-License-Identifier: GPL-3.0-or-later

//! The async openQA API client: builder, retry loop, restricted redirects,
//! and capped response parsing.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use reqwest::header::{
    ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION, USER_AGENT,
};
use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::policy;
use crate::policy::{RetryPolicy, Timeouts};
use crate::secret::{ApiKey, ApiSecret, Credentials, RedactedUrl};
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
    timeouts: Option<Timeouts>,
    retry: RetryPolicy,
    tls: Option<TlsMode>,
    http_client: Option<reqwest::Client>,
    max_response_bytes: usize,
    max_redirects: usize,
    user_agent: String,
    config_paths: Option<Vec<PathBuf>>,
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
            .field("http_client", &self.http_client.is_some())
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_redirects", &self.max_redirects)
            .field("user_agent", &self.user_agent)
            .field("config_paths", &self.config_paths)
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
            timeouts: None,
            retry: RetryPolicy::default(),
            tls: None,
            http_client: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            user_agent: format!("ruoqa/{}", env!("CARGO_PKG_VERSION")),
            config_paths: None,
        }
    }
}

impl ClientBuilder {
    /// Creates a builder with default settings; see the setters below to
    /// override them.
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

    /// Sets the API key, taking precedence over
    /// `$OPENQA_API_KEY`/`$OPENQA_API_SECRET` and `client.conf`. Must be
    /// paired with [`ClientBuilder::api_secret`]: setting only one is a
    /// [`ClientBuilder::build`] error.
    #[must_use]
    pub fn api_key(mut self, api_key: ApiKey) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Sets the API secret, taking precedence over
    /// `$OPENQA_API_KEY`/`$OPENQA_API_SECRET` and `client.conf`. Must be
    /// paired with [`ClientBuilder::api_key`]: setting only one is a
    /// [`ClientBuilder::build`] error.
    #[must_use]
    pub fn api_secret(mut self, api_secret: ApiSecret) -> Self {
        self.api_secret = Some(api_secret);
        self
    }

    /// Overrides the connect/read/total/pool-idle timeouts.
    ///
    /// Mutually exclusive with [`ClientBuilder::http_client`]: an injected
    /// `reqwest::Client` owns its own timeout configuration, so combining
    /// the two is a [`ClientBuilder::build`] error.
    #[must_use]
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Overrides the retry behaviour.
    #[must_use]
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Overrides TLS certificate verification behaviour.
    ///
    /// Mutually exclusive with [`ClientBuilder::http_client`]: an injected
    /// `reqwest::Client` owns its own TLS configuration, so combining the
    /// two is a [`ClientBuilder::build`] error.
    #[must_use]
    pub fn tls(mut self, tls: TlsMode) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Overrides the maximum response body size accepted by
    /// [`Client::request`]/[`Client::request_as`].
    #[must_use]
    pub fn max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Overrides the maximum number of redirects followed.
    #[must_use]
    pub fn max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Overrides the `User-Agent` header.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Supplies a pre-built `reqwest::Client` instead of letting
    /// [`ClientBuilder::build`] construct one, e.g. to share a connection
    /// pool or proxy configuration with the rest of your application.
    ///
    /// `Accept: application/json`, `X-API-Key`, and `User-Agent` are still
    /// injected by `ruoqa` (as insert-if-absent headers on every outgoing
    /// request), so [`ClientBuilder::user_agent`] and credentials keep
    /// working on an injected client.
    ///
    /// The caller **must** configure `client` with:
    /// - `redirect::Policy::none()` — `ruoqa` follows redirects itself and
    ///   refuses cross-origin hops; reqwest does **not** strip custom
    ///   `X-API-*` headers on a cross-origin redirect, so leaving reqwest's
    ///   redirect policy on would leak credentials off-origin.
    /// - `retry::never()` — `ruoqa` re-signs every attempt; a reqwest-level
    ///   retry replays a stale signature (the server's tolerance is 300 s)
    ///   and can duplicate non-idempotent writes.
    ///
    /// Mutually exclusive with [`ClientBuilder::tls`] and
    /// [`ClientBuilder::timeouts`]: the injected client owns its own TLS and
    /// timeout configuration, so combining either with `http_client` is a
    /// [`ClientBuilder::build`] error.
    #[must_use]
    pub fn http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    /// Overrides the `client.conf` search path used by [`ClientBuilder::build`].
    ///
    /// Unset (the default) searches [`config::default_paths`]. An empty
    /// `vec![]` reads no `client.conf` at all, rather than falling back to
    /// the default search.
    #[must_use]
    pub fn config_paths(mut self, config_paths: Vec<PathBuf>) -> Self {
        self.config_paths = Some(config_paths);
        self
    }

    /// Resolves `client.conf`, builds the underlying `reqwest::Client` (or
    /// takes the one from [`ClientBuilder::http_client`]), and returns a
    /// ready-to-use [`Client`].
    ///
    /// Automatic redirects and retries are disabled on a
    /// `reqwest::Client` built here (`redirect::Policy::none()`,
    /// `reqwest::retry::never()`): [`Client`] implements both itself, since
    /// they must re-sign every attempt. An injected `http_client` must
    /// configure the same, per its docs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `client.conf` fails to parse, or the
    /// `User-Agent`/API key contain characters invalid in a header value;
    /// [`Error::Tls`] if the underlying HTTP client fails to build (usually
    /// a bad custom CA bundle); or [`Error::IncompatibleHttpClient`] if
    /// [`ClientBuilder::http_client`] is combined with
    /// [`ClientBuilder::tls`] or [`ClientBuilder::timeouts`].
    #[allow(clippy::result_large_err)] // `Error`'s size is a phase-1 decision; not this fn's to fix.
    pub fn build(self) -> Result<Client> {
        if self.http_client.is_some() {
            if self.tls.is_some() {
                return Err(Error::IncompatibleHttpClient { option: "tls" });
            }
            if self.timeouts.is_some() {
                return Err(Error::IncompatibleHttpClient { option: "timeouts" });
            }
        }

        let config_paths = self.config_paths.unwrap_or_else(config::default_paths);
        let resolved = config::resolve(&config_paths, &self.server, &self.scheme)?;
        let credentials = resolve_credentials(
            Credentials::from_parts(
                self.api_key,
                self.api_secret,
                "ClientBuilder",
                ("api_key", "api_secret"),
            )?,
            config::env_credentials()?,
            Credentials::from_parts(
                resolved.api_key,
                resolved.api_secret,
                "client.conf",
                ("key", "secret"),
            )?,
        );
        let base_url = resolved.base_url;

        if credentials.is_some() && base_url.scheme() == "http" && !is_loopback_host(&base_url) {
            tracing::warn!(
                url = %RedactedUrl(&base_url),
                "sending openQA API credentials over plaintext http to a non-loopback host"
            );
        }

        let mut base_headers = HeaderMap::new();
        base_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        base_headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent).map_err(|e| Error::Config(Box::new(e)))?,
        );
        if let Some(credentials) = &credentials {
            base_headers.insert(
                HeaderName::from_static(X_API_KEY),
                HeaderValue::from_str(credentials.key.as_str())
                    .map_err(|e| Error::Config(Box::new(e)))?,
            );
        }

        let http = if let Some(http_client) = self.http_client {
            http_client
        } else {
            let timeouts = self.timeouts.unwrap_or_default();
            let mut builder = reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(timeouts.connect)
                .read_timeout(timeouts.read)
                .timeout(timeouts.total)
                .pool_idle_timeout(timeouts.pool_idle);
            builder = self.tls.unwrap_or_default().apply(builder);
            builder.build().map_err(|e| Error::Tls(Box::new(e)))?
        };

        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base_url,
                credentials,
                max_response_bytes: self.max_response_bytes,
                max_redirects: self.max_redirects,
                retry: Mutex::new(self.retry),
                base_headers,
            }),
        })
    }
}

/// Explicit builder values, then `$OPENQA_API_KEY`/`$OPENQA_API_SECRET`, then
/// `client.conf`: the first source with a complete pair wins outright.
/// Sources are deliberately never mixed, unlike upstream's
/// `OpenQA::UserAgent`, which resolves key and secret independently.
fn resolve_credentials(
    explicit: Option<Credentials>,
    env: Option<Credentials>,
    conf: Option<Credentials>,
) -> Option<Credentials> {
    explicit.or(env).or(conf)
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
    credentials: Option<Credentials>,
    max_response_bytes: usize,
    max_redirects: usize,
    retry: Mutex<RetryPolicy>,
    /// `Accept`, `User-Agent`, and `X-API-Key`, injected insert-if-absent at
    /// sign time rather than via `reqwest::ClientBuilder::default_headers`,
    /// so they still apply when the caller supplies their own
    /// `reqwest::Client` via [`ClientBuilder::http_client`].
    base_headers: HeaderMap,
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
    /// clear. `Credentials` redacts itself, and `base_url` is redacted here
    /// via `RedactedUrl`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &RedactedUrl(&self.inner.base_url))
            .field("credentials", &self.inner.credentials)
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
    /// The HTTP method to send.
    pub method: Method,
    /// The fully resolved request URL.
    pub url: Url,
    /// Headers to send, excluding the per-attempt auth headers `sign` adds.
    pub headers: HeaderMap,
    /// The request body, if any.
    pub body: Option<Bytes>,
}

/// A successful response body, classified by content type rather than
/// assumed to be JSON. openQA answers several routes (`/api/v1/auth`, the
/// mutex/barrier lock routes, artefact and status uploads) with
/// `render(text => …)`, which is `ok`/`ack`/`OK` under `Content-Type:
/// text/html`, not JSON. [`Client::request`] and [`Client::request_form`]
/// flatten this into a [`Value`] via [`ApiResponse::into_value`];
/// [`Client::request_typed`] and [`Client::request_form_typed`] return it
/// directly for callers who must distinguish a JSON string `"ok"` from a
/// text body `ok`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ApiResponse {
    /// A JSON body.
    Json(Value),
    /// A YAML body, decoded with the budget-limited parser.
    Yaml(Value),
    /// A non-JSON, non-YAML body, e.g. openQA's `ok`/`ack`/`OK` replies.
    /// Decoded with [`String::from_utf8_lossy`], so a text route with a
    /// stray non-UTF-8 byte still succeeds rather than erroring.
    Text(String),
    /// `204 No Content`, or any 2xx with an empty body (including `HEAD`).
    Empty,
}

impl ApiResponse {
    /// Flattens `self` into a generic [`Value`]: `Text(s)` becomes
    /// `Value::String(s)` and `Empty` becomes `Value::Null`. Used by
    /// [`Client::request`] and [`Client::request_form`] so a text body no
    /// longer fails a call that otherwise succeeded — at the cost of making
    /// it indistinguishable from a JSON string; use [`Client::request_typed`]
    /// when that distinction matters.
    #[must_use]
    pub fn into_value(self) -> Value {
        match self {
            Self::Json(v) | Self::Yaml(v) => v,
            Self::Text(s) => Value::String(s),
            Self::Empty => Value::Null,
        }
    }
}

impl Client {
    /// The base URL this client was built with.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.inner.base_url
    }

    /// Resolves `path` against the client's base URL. `path` must be a
    /// relative reference resolving to the same origin as the base URL: an
    /// absolute URL or network-path reference (`//host/...`) is rejected
    /// even when it happens to resolve to that origin, so a caller cannot
    /// accidentally rely on the origin check alone.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    fn join(&self, path: &str) -> Result<Url> {
        let url = self
            .inner
            .base_url
            .join(path)
            .map_err(|source| Error::InvalidPath {
                path: path.to_owned(),
                source,
            })?;

        guard_request_url(&self.inner.base_url, &url)?;

        let relative = RELATIVE_GUARD
            .join(path)
            .map_err(|source| Error::InvalidPath {
                path: path.to_owned(),
                source,
            })?;
        if relative.origin() != RELATIVE_GUARD.origin() {
            return Err(Error::UnsupportedRequestUrl {
                url,
                reason: "request paths must be relative to the base URL",
            });
        }

        Ok(url)
    }

    /// Resolves `path` against the client's base URL and, for `body`,
    /// serializes it as a JSON request body (`Content-Type: application/json`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPath`] if `path` cannot be joined onto the
    /// base URL, [`Error::UnsupportedRequestUrl`] if `path` is not a
    /// relative reference or the resolved URL carries userinfo,
    /// [`Error::CrossOriginRequest`] if it resolves to a different origin
    /// than the base URL, or [`Error::Parse`] if `body` cannot be
    /// serialized.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub fn prepare(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<PreparedRequest> {
        let url = self.join(path)?;

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

    /// Resolves `path` against the client's base URL and encodes `form` as
    /// an `application/x-www-form-urlencoded` request body, the content type
    /// openQA's `POST /api/v1/isos` (and other write endpoints) expect
    /// instead of JSON.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPath`] if `path` cannot be joined onto the
    /// base URL, [`Error::UnsupportedRequestUrl`] if `path` is not a
    /// relative reference or the resolved URL carries userinfo, or
    /// [`Error::CrossOriginRequest`] if it resolves to a different origin
    /// than the base URL.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub fn prepare_form(
        &self,
        method: Method,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<PreparedRequest> {
        let url = self.join(path)?;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        Ok(PreparedRequest {
            method,
            url,
            headers,
            body: Some(Bytes::from(body)),
        })
    }

    /// Sends `method path` with an optional JSON `body` and parses the
    /// response as JSON or YAML (see [`Client::send_raw`] to bypass parsing
    /// and the response-size cap). A non-JSON, non-YAML body — e.g. openQA's
    /// `ok`/`ack`/`OK` text routes — arrives as a JSON string instead of an
    /// error; use [`Client::request_typed`] if you need to tell that apart
    /// from an actual JSON string response.
    ///
    /// # Errors
    ///
    /// See [`Client::execute`] and the module docs for the full error list.
    pub async fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        Ok(self.request_typed(method, path, body).await?.into_value())
    }

    /// Like [`Client::request`], sending `form` as an
    /// `application/x-www-form-urlencoded` body via [`Client::prepare_form`]
    /// instead of a JSON one.
    ///
    /// Unlike [`Client::request`], a non-idempotent method (e.g. `POST`) is
    /// retried neither on a transport error nor on a retryable status:
    /// openQA's form-encoded write endpoints (e.g. `POST /api/v1/isos`) are
    /// not idempotent, and retrying a request whose response was lost could
    /// schedule duplicate jobs. The exceptions are a server signalling
    /// deliberate backpressure (`429`/`503` with `Retry-After`) or opting in
    /// via [`RetryPolicy::retry_non_idempotent`]. Use [`Client::prepare_form`]
    /// with [`Client::execute`] directly for a per-call opt-in.
    ///
    /// # Errors
    ///
    /// See [`Client::request`].
    pub async fn request_form(
        &self,
        method: Method,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Value> {
        Ok(self
            .request_form_typed(method, path, form)
            .await?
            .into_value())
    }

    /// Like [`Client::request`], returning the classified [`ApiResponse`]
    /// instead of flattening it into a [`Value`]. Needed to tell a genuine
    /// JSON string response apart from a text response such as openQA's
    /// `GET /api/v1/auth` (`ok`) or the mutex/barrier lock routes (`ack`):
    ///
    /// ```no_run
    /// # use ruoqa::{ApiResponse, ClientBuilder};
    /// # async fn run() -> ruoqa::Result<()> {
    /// let client = ClientBuilder::new().server("openqa.opensuse.org").build()?;
    /// match client
    ///     .request_typed(reqwest::Method::GET, "/api/v1/auth", None)
    ///     .await?
    /// {
    ///     ApiResponse::Text(body) => println!("text response: {body}"),
    ///     other => println!("{other:?}"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// See [`Client::execute`] and the module docs for the full error list.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub async fn request_typed(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<ApiResponse> {
        let prepared = self.prepare(method, path, body)?;
        let mut resp = self.execute(&prepared, false).await?;
        self.handle_response(&prepared, &mut resp).await
    }

    /// Like [`Client::request_typed`], sending `form` as an
    /// `application/x-www-form-urlencoded` body via [`Client::prepare_form`]
    /// instead of a JSON one.
    ///
    /// Unlike [`Client::request_typed`], a non-idempotent method (e.g.
    /// `POST`) is retried neither on a transport error nor on a retryable
    /// status: openQA's form-encoded write endpoints (e.g.
    /// `POST /api/v1/isos`) are not idempotent, and retrying a request whose
    /// response was lost could schedule duplicate jobs. The exceptions are a
    /// server signalling deliberate backpressure (`429`/`503` with
    /// `Retry-After`) or opting in via [`RetryPolicy::retry_non_idempotent`].
    /// Use [`Client::prepare_form`] with [`Client::execute`] directly for a
    /// per-call opt-in.
    ///
    /// # Errors
    ///
    /// See [`Client::request_typed`].
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub async fn request_form_typed(
        &self,
        method: Method,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<ApiResponse> {
        let prepared = self.prepare_form(method, path, form)?;
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
    /// both transport-error and retryable-status retries, which are
    /// otherwise restricted to [`RetryPolicy::idempotent_methods`]. It ORs
    /// with [`RetryPolicy::retry_non_idempotent`] and cannot turn that flag
    /// off: setting either is a "this write is safe to replay" statement,
    /// widening eligibility only ever makes sense in one direction.
    /// Eligibility is evaluated per redirect hop against that hop's method,
    /// so a `POST` downgraded to a bodyless `GET` by a `301`/`302`/`303` is
    /// retryable on the following hop even though the original request was
    /// not.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] on an unretried transport failure,
    /// [`Error::CrossOriginRequest`] or [`Error::UnsupportedRequestUrl`] if
    /// `prepared.url` (a public field a caller can set directly) fails the
    /// same-origin check, [`Error::CrossOriginRedirect`] on a cross-origin
    /// redirect, [`Error::TooManyRedirects`] past `max_redirects`, or
    /// [`Error::DeadlineExceeded`] if [`RetryPolicy::deadline`] elapses
    /// while a request is in flight, waiting for backoff, or following a
    /// redirect.
    ///
    /// # Panics
    ///
    /// Never in practice: only if the retry-policy mutex is poisoned by an
    /// earlier panic elsewhere in the client.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    pub async fn execute(
        &self,
        prepared: &PreparedRequest,
        retry_non_idempotent: bool,
    ) -> Result<reqwest::Response> {
        let mut current = prepared.clone();
        let mut redirects_followed = 0usize;
        let started = Instant::now();
        // Snapshotted once so a mutating caller cannot extend the budget of
        // a running `execute` call by re-locking the policy per hop.
        let deadline = self
            .inner
            .retry
            .lock()
            .unwrap()
            .deadline
            .map(|d| started + d);
        loop {
            guard_request_url(&self.inner.base_url, &current.url)?;
            let resp = self
                .send_with_retries(&current, retry_non_idempotent, started, deadline)
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

    /// Whether `method` may be replayed: idempotent by default, or opted in
    /// per call (`Client::execute`) or per client (`RetryPolicy`).
    fn method_retryable(&self, method: &Method, opt_in: bool) -> bool {
        let policy = self.inner.retry.lock().unwrap();
        opt_in || policy.retry_non_idempotent || policy.idempotent_methods.contains(method)
    }

    /// Whether `status` on `prepared` should be replayed: it must be in
    /// `retry_statuses`, and either the method is retryable or the response
    /// signals deliberate backpressure. Logs when a retryable status is
    /// withheld solely because of the method, so the missing retry doesn't
    /// read as a bug.
    fn status_retryable(
        &self,
        prepared: &PreparedRequest,
        status: StatusCode,
        headers: &HeaderMap,
        retry_non_idempotent: bool,
    ) -> bool {
        let retryable = self
            .inner
            .retry
            .lock()
            .unwrap()
            .retry_statuses
            .contains(&status);
        let eligible = retryable
            && (self.method_retryable(&prepared.method, retry_non_idempotent)
                || policy::is_backpressure(status, headers));
        if retryable && !eligible {
            tracing::debug!(
                method = %prepared.method,
                %status,
                "not retrying a retryable status for a non-idempotent method"
            );
        }
        eligible
    }

    /// The retry loop proper (mirrors `aclient.py::do_request`): retries
    /// transport errors and retryable statuses with jittered, capped
    /// backoff, honoring `Retry-After` and the overall deadline.
    async fn send_with_retries(
        &self,
        prepared: &PreparedRequest,
        retry_non_idempotent: bool,
        started: Instant,
        deadline: Option<Instant>,
    ) -> Result<reqwest::Response> {
        let max_retries = self.inner.retry.lock().unwrap().max_retries;

        for attempt in 0..=max_retries {
            let start = Instant::now();
            let req = self.sign(prepared);

            let outcome = match deadline {
                None => self.inner.http.execute(req).await,
                Some(at) => {
                    let Some(remaining) = at
                        .checked_duration_since(Instant::now())
                        .filter(|r| !r.is_zero())
                    else {
                        return Err(Error::DeadlineExceeded {
                            elapsed: started.elapsed(),
                        });
                    };
                    match tokio::time::timeout(remaining, self.inner.http.execute(req)).await {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            return Err(Error::DeadlineExceeded {
                                elapsed: started.elapsed(),
                            });
                        }
                    }
                }
            };

            match outcome {
                Ok(resp) => {
                    let status = resp.status();
                    let eligible = self.status_retryable(
                        prepared,
                        status,
                        resp.headers(),
                        retry_non_idempotent,
                    );
                    if !eligible || attempt >= max_retries {
                        return Ok(resp);
                    }

                    let retry_after = {
                        let policy = self.inner.retry.lock().unwrap();
                        policy.parse_retry_after(resp.headers())
                    };
                    let backoff = self.inner.retry.lock().unwrap().backoff_for(attempt);
                    let delay = retry_after.map_or(backoff, |ra| ra.max(backoff));

                    if let Some(at) = deadline
                        && at
                            .checked_duration_since(Instant::now())
                            .is_none_or(|remaining| delay >= remaining)
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
                    let eligible = self.method_retryable(&prepared.method, retry_non_idempotent);
                    if !eligible || attempt >= max_retries {
                        return Err(Error::Connection {
                            url: prepared.url.clone(),
                            source,
                        });
                    }

                    let backoff = self.inner.retry.lock().unwrap().backoff_for(attempt);
                    if let Some(at) = deadline
                        && at
                            .checked_duration_since(Instant::now())
                            .is_none_or(|remaining| backoff >= remaining)
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
        auth::apply(
            &mut headers,
            &prepared.url,
            self.inner.credentials.as_ref().map(|c| &c.secret),
        );
        for (name, value) in &self.inner.base_headers {
            if !headers.contains_key(name) {
                headers.insert(name.clone(), value.clone());
            }
        }

        let mut req = reqwest::Request::new(prepared.method.clone(), prepared.url.clone());
        *req.headers_mut() = headers;
        if let Some(body) = &prepared.body {
            *req.body_mut() = Some(reqwest::Body::from(body.clone()));
        }
        req
    }

    /// Non-2xx errors first (with a truncated body for the error message),
    /// then `204`, then a content-type-driven, total classification of the
    /// body into [`ApiResponse`]. Deliberately diverges from the openQA
    /// Python client's `_handle_response`, which ends in `resp.json()`
    /// unconditionally: that fails on the server's own `ok`/`ack`/`OK` text
    /// routes, which this does not.
    #[allow(clippy::result_large_err)] // see `ClientBuilder::build`
    async fn handle_response(
        &self,
        prepared: &PreparedRequest,
        resp: &mut reqwest::Response,
    ) -> Result<ApiResponse> {
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
            return Ok(ApiResponse::Empty);
        }

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();

        let kind = classify(&content_type);
        let bytes = read_capped(resp, self.inner.max_response_bytes).await?;

        // Not derived from `Content-Length`: a chunked 2xx has none, and an
        // empty `HEAD` response must still classify as `Empty`.
        if bytes.is_empty() {
            return Ok(ApiResponse::Empty);
        }

        match kind {
            BodyKind::Yaml => parse_yaml(&bytes).map(ApiResponse::Yaml),
            BodyKind::Json => serde_json::from_slice(&bytes)
                .map(ApiResponse::Json)
                .map_err(|e| Error::Parse(Box::new(e))),
            BodyKind::Text => Ok(ApiResponse::Text(
                String::from_utf8_lossy(&bytes).into_owned(),
            )),
        }
    }
}

/// Resolving `path` against a base that can never be the configured server
/// isolates what `path` itself contributes: any origin change came from the
/// path supplying its own scheme or authority, not from the base.
static RELATIVE_GUARD: LazyLock<Url> = LazyLock::new(|| {
    Url::parse("https://ruoqa-guard.invalid/").expect("static URL literal parses")
});

/// Rejects `url` if it does not share `base`'s origin, or if it carries
/// userinfo (which would inject HTTP basic-auth credentials into an openQA
/// request). Origin equality is the complete same-origin invariant only
/// because `base_url` never carries a path (`config::netloc` discards it);
/// if sub-path deployments are ever supported, this must also check that
/// `url`'s path is prefixed by `base`'s.
#[allow(clippy::result_large_err)] // see `ClientBuilder::build`
fn guard_request_url(base: &Url, url: &Url) -> Result<()> {
    if base.origin() != url.origin() {
        return Err(Error::CrossOriginRequest {
            base: base.clone(),
            url: url.clone(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::UnsupportedRequestUrl {
            url: url.clone(),
            reason: "request URL must not contain userinfo",
        });
    }
    Ok(())
}

/// `Some(next)` if `resp` is a same-origin redirect to follow; `Ok(None)`
/// for a non-redirect, a redirect without a usable `Location`, or a
/// `Location` that is not `http`/`https` or has no host (all treated as
/// final rather than guessed at, matching `Mojo::UserAgent::Transactor`'s
/// `redirect`). Never forwards `X-API-Key`/`X-API-Hash` off-origin: a
/// cross-origin `Location` errors before any request to it is ever built.
///
/// Method/body/header handling follows `Mojo::UserAgent::Transactor::redirect`:
/// `307`/`308` replay the method, body, and headers verbatim; every other
/// redirected status drops the body and every `content-*` header, and
/// downgrades the method to `GET` for a `303` or an original `POST` (other
/// methods, e.g. `PUT`/`DELETE`, keep their method but lose the body). Two
/// intentional deviations from Mojo: the draft `QUERY` method has no special
/// case (`reqwest::Method` has no constant for it and openQA does not route
/// it), and non-`content-*` headers are kept on a downgraded hop rather than
/// stripped, because Mojo strips them to protect credentials on cross-origin
/// hops, while `ruoqa` refuses cross-origin hops outright.
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

    if !matches!(next_url.scheme(), "http" | "https") || !next_url.has_host() {
        return Ok(None);
    }

    if current.url.origin() != next_url.origin() {
        return Err(Error::CrossOriginRedirect {
            from: current.url.clone(),
            to: next_url,
        });
    }

    let (method, body, headers) = if matches!(
        status,
        StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT
    ) {
        (
            current.method.clone(),
            current.body.clone(),
            current.headers.clone(),
        )
    } else {
        let method = if status == StatusCode::SEE_OTHER || current.method == Method::POST {
            Method::GET
        } else {
            current.method.clone()
        };
        (method, None, without_content_headers(&current.headers))
    };

    Ok(Some(PreparedRequest {
        method,
        url: next_url,
        headers,
        body,
    }))
}

/// Mojo removes every `content-*` header on a redirect that drops the body.
fn without_content_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if !name.as_str().starts_with("content-") {
            out.append(name.clone(), value.clone());
        }
    }
    out
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

/// Conservative YAML parsing options: exact `true`/`false` only (no YAML 1.1
/// `yes`/`no`/`on`/`off` inference), non-finite floats rejected rather than
/// silently stringified (already the crate default), and a tighter-than-default
/// alias/event budget since a response body is at most a few tens of MiB, never
/// the crate's 256 MiB reader default.
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

/// How [`Client::handle_response`] parses a non-empty body, decided purely by
/// `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Json,
    Yaml,
    Text,
}

/// Classifies a `Content-Type` header value into a [`BodyKind`], ignoring any
/// `;`-separated parameters and comparing case-insensitively. An absent or
/// unparseable header (passed in as `""`) maps to `Text`: Mojolicious always
/// sets a content type, so a missing one means a non-openQA intermediary,
/// and `Text` is the only classification that never fails to parse.
fn classify(content_type: &str) -> BodyKind {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        return BodyKind::Json;
    }
    if matches!(
        media_type.as_str(),
        "text/yaml" | "application/yaml" | "application/x-yaml" | "text/x-yaml"
    ) {
        return BodyKind::Yaml;
    }
    BodyKind::Text
}

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    fn test_client() -> Client {
        ClientBuilder::new()
            .server("localhost:9526")
            .config_paths(vec![])
            .build()
            .unwrap()
    }

    fn origin_test_client() -> Client {
        ClientBuilder::new()
            .server("https://openqa.example.com")
            .config_paths(vec![])
            .build()
            .unwrap()
    }

    #[test]
    fn join_rejects_cross_origin_paths() {
        let client = origin_test_client();
        let cases = [
            "https://attacker.example/api",
            "http://openqa.example.com/api",
            "https://openqa.example.com:8443/api",
            "//attacker.example/api",
            "\\\\attacker.example/api",
            "/\\attacker.example/api",
            " //attacker.example/api",
            "/\u{9}/attacker.example/api",
        ];
        for path in cases {
            let err = client
                .join(path)
                .expect_err(&format!("{path:?} should be rejected"));
            assert!(
                matches!(err, Error::CrossOriginRequest { .. }),
                "{path:?}: expected CrossOriginRequest, got {err:?}"
            );
        }
    }

    #[test]
    fn join_rejects_unsupported_urls() {
        let client = origin_test_client();
        let cases = [
            "https://openqa.example.com/api/v1/jobs",
            "//user:pass@openqa.example.com/api",
        ];
        for path in cases {
            let err = client
                .join(path)
                .expect_err(&format!("{path:?} should be rejected"));
            assert!(
                matches!(err, Error::UnsupportedRequestUrl { .. }),
                "{path:?}: expected UnsupportedRequestUrl, got {err:?}"
            );
        }
    }

    #[test]
    fn join_accepts_relative_paths_unchanged() {
        let client = origin_test_client();
        let cases = [
            "api/v1/jobs",
            "/api/v1/jobs",
            "/api/v1/jobs?scope=relevant&limit=1",
            "/api/../api/v1/jobs",
        ];
        for path in cases {
            client
                .join(path)
                .unwrap_or_else(|e| panic!("{path:?} should be accepted: {e}"));
        }
    }

    #[test]
    fn classify_matches_the_media_type_table() {
        let cases = [
            ("application/json", BodyKind::Json),
            ("application/json; charset=utf-8", BodyKind::Json),
            ("Application/JSON", BodyKind::Json),
            ("application/hal+json", BodyKind::Json),
            ("text/yaml", BodyKind::Yaml),
            ("Text/YAML; charset=utf-8", BodyKind::Yaml),
            ("application/x-yaml", BodyKind::Yaml),
            ("text/html;charset=UTF-8", BodyKind::Text),
            ("text/plain", BodyKind::Text),
            ("", BodyKind::Text),
        ];
        for (content_type, expected) in cases {
            assert_eq!(
                classify(content_type),
                expected,
                "content_type: {content_type:?}"
            );
        }
    }

    #[test]
    fn prepare_form_sets_urlencoded_content_type_and_body() {
        let client = test_client();
        let prepared = client
            .prepare_form(
                Method::POST,
                "/api/v1/isos",
                &[("DISTRI", "opensuse"), ("VERSION", "Tumbleweed")],
            )
            .unwrap();
        assert_eq!(
            prepared.headers.get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            prepared.body.unwrap().as_ref(),
            b"DISTRI=opensuse&VERSION=Tumbleweed".as_slice()
        );
    }

    #[test]
    fn prepare_form_percent_encodes_values() {
        let client = test_client();
        let prepared = client
            .prepare_form(
                Method::POST,
                "/api/v1/isos",
                &[("A", "a b"), ("B", "a&b"), ("C", "a~b")],
            )
            .unwrap();
        assert_eq!(
            prepared.body.unwrap().as_ref(),
            b"A=a+b&B=a%26b&C=a%7Eb".as_slice()
        );
    }

    #[test]
    fn prepare_form_preserves_duplicate_keys_in_order() {
        let client = test_client();
        let prepared = client
            .prepare_form(Method::POST, "/api/v1/isos", &[("k", "1"), ("k", "2")])
            .unwrap();
        assert_eq!(prepared.body.unwrap().as_ref(), b"k=1&k=2".as_slice());
    }

    #[test]
    fn prepare_form_with_empty_slice_sends_empty_body_with_content_type() {
        let client = test_client();
        let prepared = client
            .prepare_form(Method::POST, "/api/v1/isos", &[])
            .unwrap();
        assert_eq!(
            prepared.headers.get(CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(prepared.body.unwrap().as_ref(), b"".as_slice());
    }

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
            .config_paths(vec![])
            .build()
            .unwrap();
        let credentials = client.inner.credentials.as_ref().unwrap();
        assert_eq!(credentials.key.as_str(), "KEY");
        assert_eq!(credentials.secret.as_str(), "SECRET");
    }

    #[test]
    fn client_debug_redacts_key_and_secret() {
        let client = ClientBuilder::new()
            .server("localhost:9526")
            .api_key(ApiKey::new("SUPERSECRETKEY"))
            .api_secret(ApiSecret::new("SUPERSECRETVALUE"))
            .config_paths(vec![])
            .build()
            .unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains("SUPERSECRETKEY"));
        assert!(!debug.contains("SUPERSECRETVALUE"));
    }

    /// Regression guard for the `Debug` impl's redaction, independent of
    /// `config::resolve`'s userinfo strip: even a `base_url` built with
    /// userinfo (bypassing `resolve` entirely) must not leak it here.
    #[test]
    fn client_debug_redacts_base_url_userinfo() {
        let client = Client {
            inner: Arc::new(Inner {
                http: reqwest::Client::new(),
                base_url: Url::parse("https://alice:s3cret@openqa.example.com/").unwrap(),
                credentials: None,
                max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
                max_redirects: DEFAULT_MAX_REDIRECTS,
                retry: Mutex::new(RetryPolicy::default()),
                base_headers: HeaderMap::new(),
            }),
        };
        let debug = format!("{client:?}");
        assert!(!debug.contains("s3cret"));
        assert!(!debug.contains("alice"));
    }

    #[test]
    #[traced_test]
    fn warns_for_plaintext_http_creds_to_non_loopback_host() {
        ClientBuilder::new()
            .server("http://openqa.example.com")
            .api_key(ApiKey::new("KEY"))
            .api_secret(ApiSecret::new("SECRET"))
            .config_paths(vec![])
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
            .config_paths(vec![])
            .build()
            .unwrap();
        assert!(!logs_contain("plaintext"));
    }

    #[test]
    #[traced_test]
    fn no_warning_without_credentials() {
        ClientBuilder::new()
            .server("http://openqa.example.com")
            .config_paths(vec![])
            .build()
            .unwrap();
        assert!(!logs_contain("plaintext"));
    }

    #[test]
    fn http_client_with_tls_is_incompatible() {
        let err = ClientBuilder::new()
            .server("localhost:9526")
            .http_client(reqwest::Client::new())
            .tls(TlsMode::danger_accept_invalid_certs())
            .config_paths(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompatibleHttpClient { option: "tls" }
        ));
    }

    #[test]
    fn http_client_with_timeouts_is_incompatible() {
        let err = ClientBuilder::new()
            .server("localhost:9526")
            .http_client(reqwest::Client::new())
            .timeouts(Timeouts::default())
            .config_paths(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompatibleHttpClient { option: "timeouts" }
        ));
    }

    #[test]
    fn http_client_alone_builds_ok() {
        ClientBuilder::new()
            .server("localhost:9526")
            .http_client(reqwest::Client::new())
            .config_paths(vec![])
            .build()
            .unwrap();
    }

    fn prepared(method: Method, body: Option<&'static str>, headers: HeaderMap) -> PreparedRequest {
        PreparedRequest {
            method,
            url: Url::parse("https://openqa.example.com/old").unwrap(),
            headers,
            body: body.map(|b| Bytes::from_static(b.as_bytes())),
        }
    }

    fn redirect_response(status: u16, location: &str) -> reqwest::Response {
        http::Response::builder()
            .status(status)
            .header("location", location)
            .body("")
            .unwrap()
            .into()
    }

    #[test]
    fn redirect_decision_matrix() {
        // (status, method in) -> (method out, body dropped?)
        let cases: &[(u16, Method, Method, bool)] = &[
            (301, Method::GET, Method::GET, true),
            (301, Method::HEAD, Method::HEAD, true),
            (301, Method::POST, Method::GET, true),
            (301, Method::PUT, Method::PUT, true),
            (301, Method::DELETE, Method::DELETE, true),
            (302, Method::GET, Method::GET, true),
            (302, Method::HEAD, Method::HEAD, true),
            (302, Method::POST, Method::GET, true),
            (302, Method::PUT, Method::PUT, true),
            (302, Method::DELETE, Method::DELETE, true),
            (303, Method::GET, Method::GET, true),
            (303, Method::HEAD, Method::GET, true),
            (303, Method::POST, Method::GET, true),
            (303, Method::PUT, Method::GET, true),
            (303, Method::DELETE, Method::GET, true),
            (307, Method::GET, Method::GET, false),
            (307, Method::HEAD, Method::HEAD, false),
            (307, Method::POST, Method::POST, false),
            (307, Method::PUT, Method::PUT, false),
            (307, Method::DELETE, Method::DELETE, false),
            (308, Method::GET, Method::GET, false),
            (308, Method::HEAD, Method::HEAD, false),
            (308, Method::POST, Method::POST, false),
            (308, Method::PUT, Method::PUT, false),
            (308, Method::DELETE, Method::DELETE, false),
        ];

        for (status, method_in, method_out, body_dropped) in cases.iter().cloned() {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let current = prepared(method_in.clone(), Some("{}"), headers);
            let resp = redirect_response(status, "/new");

            let next = redirect_target(&current, &resp)
                .unwrap_or_else(|e| panic!("{status} {method_in}: unexpected error {e}"))
                .unwrap_or_else(|| panic!("{status} {method_in}: expected a redirect"));

            assert_eq!(next.method, method_out, "{status} {method_in}: method");
            assert_eq!(
                next.body.is_none(),
                body_dropped,
                "{status} {method_in}: body"
            );
        }
    }

    #[test]
    fn downgraded_hop_keeps_custom_header_but_drops_content_type() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            HeaderName::from_static("x-api-jobtoken"),
            HeaderValue::from_static("tok"),
        );
        let current = prepared(Method::POST, Some("{}"), headers);
        let resp = redirect_response(302, "/new");

        let next = redirect_target(&current, &resp).unwrap().unwrap();
        assert!(!next.headers.contains_key(CONTENT_TYPE));
        assert_eq!(next.headers.get("x-api-jobtoken").unwrap(), "tok");
    }

    #[test]
    fn temporary_redirect_keeps_content_type_and_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let current = prepared(Method::POST, Some("{}"), headers);
        let resp = redirect_response(307, "/new");

        let next = redirect_target(&current, &resp).unwrap().unwrap();
        assert_eq!(next.headers.get(CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(next.body.unwrap().as_ref(), b"{}".as_slice());
    }

    #[test]
    fn non_http_location_is_treated_as_final() {
        let current = prepared(Method::GET, None, HeaderMap::new());
        let resp = redirect_response(302, "mailto:admin@example.com");
        assert!(redirect_target(&current, &resp).unwrap().is_none());
    }

    #[test]
    fn cross_origin_location_still_errors_after_scheme_check() {
        let current = prepared(Method::GET, None, HeaderMap::new());
        let resp = redirect_response(302, "https://attacker.example/x");
        assert!(matches!(
            redirect_target(&current, &resp),
            Err(Error::CrossOriginRedirect { .. })
        ));
    }

    fn dummy_credentials(key: &'static str) -> Credentials {
        Credentials::from_parts(
            Some(ApiKey::new(key)),
            Some(ApiSecret::new(key)),
            "test",
            ("key", "secret"),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn resolve_credentials_precedence() {
        let explicit = dummy_credentials("explicit");
        let env = dummy_credentials("env");
        let conf = dummy_credentials("conf");

        assert_eq!(
            resolve_credentials(Some(dummy_credentials("explicit")), Some(env), Some(conf))
                .unwrap()
                .key
                .as_str(),
            explicit.key.as_str()
        );
        assert_eq!(
            resolve_credentials(
                None,
                Some(dummy_credentials("env")),
                Some(dummy_credentials("conf"))
            )
            .unwrap()
            .key
            .as_str(),
            "env"
        );
        assert_eq!(
            resolve_credentials(None, None, Some(dummy_credentials("conf")))
                .unwrap()
                .key
                .as_str(),
            "conf"
        );
        assert!(resolve_credentials(None, None, None).is_none());
    }

    #[test]
    fn builder_api_key_without_secret_is_incomplete_credentials() {
        let err = ClientBuilder::new()
            .server("localhost:9526")
            .api_key(ApiKey::new("KEY"))
            .config_paths(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                origin: "ClientBuilder",
                present: "api_key",
                missing: "api_secret",
            }
        ));
    }

    #[test]
    fn builder_api_secret_without_key_is_incomplete_credentials() {
        let err = ClientBuilder::new()
            .server("localhost:9526")
            .api_secret(ApiSecret::new("SECRET"))
            .config_paths(vec![])
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                origin: "ClientBuilder",
                present: "api_secret",
                missing: "api_key",
            }
        ));
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
