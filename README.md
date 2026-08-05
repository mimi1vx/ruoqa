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

Responses are parsed automatically: a `text/yaml` body is decoded with a
budget-limited YAML parser (rejecting alias bombs rather than exhausting
memory), a `204 No Content` becomes `Value::Null`, and everything else is
decoded as JSON. Non-2xx responses become `Error::Request`; use
[`Client::send_raw`] to bypass parsing and the response-size cap (e.g. for
asset downloads), and [`Client::request_as`] to deserialize into your own
type instead of a generic `serde_json::Value`.

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

Credentials are read from INI-style `client.conf` files, searched in order:

1. `/etc/openqa/client.conf`
2. `$XDG_CONFIG_HOME/openqa/client.conf` (only when `$XDG_CONFIG_HOME` is set
   and absolute), else `~/.config/openqa/client.conf`

If `$OPENQA_CONFIG` is set, it is a directory that **exclusively overrides**
this search: only `$OPENQA_CONFIG/client.conf` is read, and `/etc` and the
user config dir are not consulted.

[`ClientBuilder::config_paths`] overrides this whole search with an explicit
path list, e.g. to point at a fixture in tests; an empty list skips reading
`client.conf` entirely.

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
possible. Explicit `ClientBuilder::api_key`/`api_secret` calls override
whatever `client.conf` provides.

**Scheme defaulting:** the scheme defaults to `https`, except for loopback
hosts (`localhost`, `127.0.0.1`, `::1`), which default to `http`. You can
also pass a fully-qualified server such as `http://openqa.internal`.

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
> instead.

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
| `retry_methods` | GET, HEAD, OPTIONS, PUT, DELETE (not POST) |

Backoff is exponential with full jitter (`uniform(0, backoff)`). Call
[`RetryPolicy::upstream_compat`] for a more lenient profile (5 retries,
10 s initial backoff, 60 s cap, no deadline).

## Behaviour

- **Async only.** No synchronous/blocking facade; bring your own
  `tokio::runtime::Handle::block_on` if you need one.
- **`Accept: application/json`** on every request.
- **Restricted, same-origin redirects** (default cap of 3 hops, configurable
  via [`ClientBuilder::max_redirects`]); a cross-origin redirect is an error
  rather than silently dropping `X-API-Key`/`X-API-Hash` or (worse)
  forwarding them off-origin.
- **No sub-path** (`base_url` with a path component) deployments — a
  deliberate non-goal.
- **No typed openQA response models** — responses are `serde_json::Value`
  (or your own type via [`Client::request_as`]).
- **No CLI binary.**
- Response bodies are capped (32 MiB by default, configurable via
  [`ClientBuilder::max_response_bytes`]) unless read via
  [`Client::send_raw`].
- URLs are userinfo-redacted wherever they appear in errors or logs.

## Versioning

While `ruoqa` is at `0.1.x`, the **minor** version is the breaking bump:
`0.1.x` → `0.2.0` for anything the [Cargo SemVer
reference](https://doc.rust-lang.org/cargo/reference/semver.html) calls a
major change (removing a public item, adding a variant to a non-`#[non_exhaustive]`
enum, adding a non-defaulted trait item, …). Patch releases (`0.1.x`) are
additive/fixes only. `Error`, `JobState`, and `JobResult` are marked
`#[non_exhaustive]` so the server adding new states or job results doesn't
force a breaking release.

## License

GPL-3.0-or-later. See [COPYING](https://github.com/mimi1vx/ruoqa/blob/main/COPYING).

[`Client::send_raw`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.send_raw
[`Client::request_as`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_as
[`Client::request_form`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_form
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
