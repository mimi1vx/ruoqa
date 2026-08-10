# ruoqa

<img src="https://raw.githubusercontent.com/mimi1vx/ruoqa/main/docs/assets/logo.svg"
     align="right" width="130" alt="ruoqa logo">

An async [openQA](https://open.qa/) REST API client, built on
[`reqwest`](https://docs.rs/reqwest). It provides HMAC-SHA1 request signing,
`client.conf` discovery, and a YAML-response fallback, aimed at wire
compatibility with the openQA server.

## Usage

```rust,no_run
use ruoqa::ClientBuilder;

# async fn run() -> ruoqa::Result<()> {
let client = ClientBuilder::new()
    .server("openqa.opensuse.org")
    .build()?;

let jobs = client
    .request(reqwest::Method::GET, "/api/v1/jobs?limit=10", None)
    .await?;
println!("{jobs}");
# Ok(())
# }
```

Responses are classified by content type, not assumed to be JSON: a JSON media
type (`application/json`, or an `application/…+json` suffix) is decoded as
JSON, a YAML media type (`text/yaml`, `application/yaml`, `application/x-yaml`,
`text/x-yaml`) is decoded with a budget-limited YAML parser (rejecting alias
bombs rather than exhausting memory), a `204 No Content` or any other 2xx with
an empty body becomes `Value::Null`, and everything else — including openQA's
`ok`/`ack`/`OK` text routes such as `GET /api/v1/auth` and the mutex/barrier
lock routes, served as `text/html` — arrives as a JSON string instead of an
error. Non-2xx responses become `Error::Request`; use [`Client::send_raw`] to
bypass parsing and the response-size cap (e.g. for asset downloads),
[`Client::request_as`] to deserialize into your own type instead of a generic
`serde_json::Value`, and [`Client::request_typed`] to get an [`ApiResponse`]
back when a JSON string and a text body must be told apart.

openQA's `isos` endpoint, the main way to schedule jobs, expects
`application/x-www-form-urlencoded` rather than JSON — use
[`Client::request_form`] for that:

```rust,no_run
use ruoqa::ClientBuilder;

# async fn run() -> ruoqa::Result<()> {
let client = ClientBuilder::new()
    .server("openqa.opensuse.org")
    .build()?;

let scheduled = client
    .request_form(
        reqwest::Method::POST,
        "/api/v1/isos",
        &[("DISTRI", "opensuse"), ("VERSION", "Tumbleweed")],
    )
    .await?;
println!("{scheduled}");
# Ok(())
# }
```

## Configuration

Credentials are read from INI-style `client.conf` files, searched in three
tiers, in order:

1. `$OPENQA_CONFIG` (only when set and non-empty)
2. `$XDG_CONFIG_HOME/openqa` (only when `$XDG_CONFIG_HOME` is set and
   absolute), else `~/.config/openqa`
3. `/etc/openqa`, then `/usr/etc/openqa`

**The first tier that has any file wins outright** — a user `client.conf`
now replaces `/etc/openqa/client.conf` instead of merging with it, and later
tiers are not read at all. Within a tier, each directory contributes its
`client.conf` (if present) followed by its `client.conf.d/*.conf` drop-ins,
sorted by name, later files winning; a directory with only drop-ins does not
stop the scan of the tier's remaining directories.

Two deliberate divergences from upstream: `$XDG_CONFIG_HOME` is a ruoqa
extension inside tier 2 (upstream hardcodes `~/.config/openqa`), and a
`client.conf` that fails to parse is always [`Error::Config`] rather than
being silently skipped.

[`ClientBuilder::config_paths`] overrides this whole search with an explicit
path list, e.g. to point at a fixture in tests; the list is read in plain
order with no tiering, and an empty list skips reading `client.conf`
entirely.

Each section is keyed by the server host (or full base URL) and provides the
API `key`/`secret`:

```ini
[openqa.opensuse.org]
key = YOUR_API_KEY
secret = YOUR_API_SECRET
```

The lookup tries the bare `server` section first, then the full base URL
section; both `key` and `secret` must be present in a section for it to
count. When present, requests are HMAC-SHA1 signed and the `X-API-Key`
header is sent. Without credentials only unauthenticated `GET` requests are
possible.

Credentials are resolved in three tiers: explicit
`ClientBuilder::api_key`/`api_secret` calls, then
`$OPENQA_API_KEY`/`$OPENQA_API_SECRET`, then `client.conf`. The first tier
that supplies a **complete** key+secret pair wins outright; sources are
never mixed, and a half-set pair from any tier (e.g. only `api_key`, or only
`$OPENQA_API_KEY`) is a [`ClientBuilder::build`] error. Empty environment
values count as unset. This is a deliberate divergence from upstream's
`OpenQA::UserAgent`, which resolves the key and the secret independently and
so permits mismatched pairs.

**Scheme defaulting:** the scheme defaults to `https`, except for loopback
hosts (`localhost`, `127.0.0.1`, `::1`, and any of these with a port, e.g.
`localhost:9526`), which default to `http`. You can also pass a
fully-qualified server such as `http://openqa.internal`.

## TLS

[`TlsMode`] controls certificate verification:

- `TlsMode::PlatformVerifier` (default) — uses the OS trust store, so
  enterprise/internal CAs installed system-wide just work.
- `TlsMode::CustomCa { certs, replace_roots }` — trusts a specific CA bundle.
  `replace_roots: true` pins to *only* that CA, discarding the platform
  roots; `false` merges it with them.
- `TlsMode::danger_accept_invalid_certs()` — disables certificate
  verification entirely.

> **Security warning:** `TlsMode::danger_accept_invalid_certs()` disables
> TLS certificate verification and exposes the connection to
> man-in-the-middle attacks. Use it only against trusted instances on
> trusted networks; prefer `TlsMode::CustomCa` with the internal CA bundle
> instead. Building a client with this mode logs a `tracing::warn!`.

A warning is also logged via `tracing::warn!` if credentials would be sent
over plaintext `http` to a non-loopback host.

## Bring your own `reqwest::Client`

[`ClientBuilder::http_client`] takes a pre-built `reqwest::Client` instead of
letting `ruoqa` construct one, e.g. to share a connection pool or proxy
configuration with the rest of your application. `Accept: application/json`,
`X-API-Key`, and `User-Agent` are still injected by `ruoqa` on every
outgoing request.

```rust,no_run
use ruoqa::ClientBuilder;

# async fn run() -> ruoqa::Result<()> {
let http_client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .retry(reqwest::retry::never())
    .build()
    .expect("reqwest::Client should build");

let client = ClientBuilder::new()
    .server("openqa.opensuse.org")
    .http_client(http_client)
    .build()?;
# let _ = client;
# Ok(())
# }
```

The injected client **must** disable reqwest's own redirects and retries:

- `redirect::Policy::none()` — `ruoqa` follows redirects itself and refuses
  cross-origin hops; reqwest does **not** strip custom `X-API-*` headers on a
  cross-origin redirect, so leaving reqwest's redirect policy on would leak
  credentials off-origin.
- `retry::never()` — `ruoqa` re-signs every attempt; a reqwest-level retry
  replays a stale signature (the server's tolerance is 300 s) and can
  duplicate non-idempotent writes.

[`ClientBuilder::tls`]/[`ClientBuilder::timeouts`] are the caller's
responsibility on an injected client, so calling either alongside
`http_client` is a `build()` error.

## Defaults

| [`Timeouts`] | Value |
|---|---|
| `connect` | 10 s |
| `read` (per-read inactivity) | 30 s |
| `total` (whole request, incl. body) | 60 s |
| `pool_idle` | 90 s |

| [`RetryPolicy`] | Value |
|---|---|
| `max_retries` | 4 |
| `initial_backoff` | 500 ms |
| `multiplier` | 2.0 |
| `max_backoff` | 30 s |
| `deadline` | 120 s |
| `honor_retry_after` | true |
| `max_retry_after` | 60 s |
| `retry_statuses` | 408, 413, 429, 444, 500, 502, 503, 504, 509, 521, 522, 599 |
| `idempotent_methods` | GET, HEAD, OPTIONS, PUT, DELETE (not POST) |
| `retry_non_idempotent` | false |

`multiplier` must be finite and `>= 1.0`; [`ClientBuilder::build`] rejects
anything else. Backoff is exponential with full jitter (`uniform(0, backoff)`). Call
[`RetryPolicy::upstream_compat`] for the `openQA-python-client`'s numbers
(5 retries, 10 s initial backoff, 60 s cap, no deadline); the jitter, method
restriction, and `Retry-After` handling are `ruoqa`'s own hardening, not
that client's. `deadline` is a budget for the
whole [`Client::execute`] call — every attempt, every backoff, and every
redirect hop — and a request still in flight when it expires is aborted with
[`Error::DeadlineExceeded`]; the response body is then read under
[`Timeouts`], not the deadline. A retryable status is only replayed for a
method in `idempotent_methods`, unless the server signalled backpressure
(`429`/`503` with `Retry-After`) or `retry_non_idempotent` is set; the same
rule governs transport errors and statuses alike.

## Behaviour

- **Async only.** No synchronous/blocking facade; bring your own
  `tokio::runtime::Handle::block_on` if you need one.
- **`Accept: application/json`** on every request — openQA's text routes
  (`ok`/`ack`/`OK`) ignore it and answer `text/html` regardless.
- **Restricted, same-origin redirects** (default cap of 3 hops, configurable
  via [`ClientBuilder::max_redirects`]); a cross-origin redirect is an error
  rather than silently dropping `X-API-Key`/`X-API-Hash` or (worse)
  forwarding them off-origin. Redirect method/body handling follows
  Mojolicious (openQA's own client): `301`/`302`/`303` turn a `POST` into a
  bodyless `GET`, and only `307`/`308` replay the original method and body.
- **Sub-path deployments** (`server` given as e.g. `openqa.example.com/openqa`)
  are supported: `base_url` keeps the path and gains a trailing slash. A
  leading `/` on a request path means "relative to the base URL", not
  "origin root" — `/api/v1/jobs` and `api/v1/jobs` resolve identically, both
  landing inside the configured prefix. `client.conf` sections stay keyed by
  host (`[openqa.example.com]`), matching upstream; a section named after the
  path is never matched. Note the upstream caveat: the openQA server signs
  `global.base_url`'s path plus the request it receives, so a sub-path
  deployment only authenticates correctly if `base_url` matches what the
  reverse proxy actually strips.
- **Request paths must be relative and stay within the base URL's path**,
  and every request URL — including one in a caller-built
  [`PreparedRequest`] — is checked against `base_url`'s origin and path
  before signing, so untrusted input in a path can never send credentials to
  another origin or escape a sub-path prefix.
- **No typed openQA response models** — responses are `serde_json::Value`
  (or your own type via [`Client::request_as`]), classified generically via
  [`ApiResponse`].
- **No CLI binary.**
- Response bodies are capped (32 MiB by default, configurable via
  [`ClientBuilder::max_response_bytes`]) unless read via
  [`Client::send_raw`].
- URLs are userinfo-redacted wherever they appear in errors or logs.
- [`Error::DeadlineExceeded`] does not mean the server did not act on the
  request — an aborted in-flight write may already have been committed.
- A `POST` answered with 500/502/504 (or a bare 503) is surfaced, not
  replayed — openQA's write routes are not idempotent and the write may
  already have committed.

## Versioning

While `ruoqa` is at `0.1.x`, the **minor** version is the breaking bump:
`0.1.x` → `0.2.0` for anything the [Cargo SemVer
reference](https://doc.rust-lang.org/cargo/reference/semver.html) calls a
major change (removing a public item, adding a variant to a non-`#[non_exhaustive]`
enum, adding a non-defaulted trait item, …). Patch releases (`0.1.x`) are
additive/fixes only. `Error`, `JobState`, `JobResult`, and `ModuleResult` are
marked `#[non_exhaustive]` so the server adding new states or job results
doesn't force a breaking release.

## License

GPL-3.0-or-later. See [COPYING](https://github.com/mimi1vx/ruoqa/blob/main/COPYING).

[`Client::send_raw`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.send_raw
[`Client::request_as`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_as
[`Client::request_form`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_form
[`Client::request_typed`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_typed
[`Client::execute`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.execute
[`Error::DeadlineExceeded`]: https://docs.rs/ruoqa/latest/ruoqa/error/enum.Error.html#variant.DeadlineExceeded
[`Error::Config`]: https://docs.rs/ruoqa/latest/ruoqa/error/enum.Error.html#variant.Config
[`ApiResponse`]: https://docs.rs/ruoqa/latest/ruoqa/client/enum.ApiResponse.html
[`TlsMode`]: https://docs.rs/ruoqa/latest/ruoqa/tls/enum.TlsMode.html
[`Timeouts`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.Timeouts.html
[`RetryPolicy`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.RetryPolicy.html
[`RetryPolicy::upstream_compat`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.RetryPolicy.html#method.upstream_compat
[`ClientBuilder::max_redirects`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.max_redirects
[`ClientBuilder::max_response_bytes`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.max_response_bytes
[`ClientBuilder::config_paths`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.config_paths
[`ClientBuilder::http_client`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.http_client
[`ClientBuilder::tls`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.tls
[`ClientBuilder::timeouts`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.timeouts
[`ClientBuilder::build`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.ClientBuilder.html#method.build
