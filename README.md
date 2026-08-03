# ruoqa

An async [openQA](https://open.qa/) REST API client, built on
[`reqwest`](https://docs.rs/reqwest). It is a partial Rust port of
[`openqa-async`](https://github.com/mimi1vx/openqa-async): HMAC-SHA1 request
signing, `client.conf` discovery, and a YAML-response fallback, aimed at
wire compatibility with the openQA server rather than byte-for-byte parity
with the Python client.

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

## Configuration

Credentials are read from INI-style `client.conf` files, searched in order:

1. `/etc/openqa/client.conf`
2. `~/.config/openqa/client.conf`

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
[`RetryPolicy::upstream_compat`] for the Python client's own defaults (5
retries, 10 s initial backoff, 60 s cap, no deadline).

## Differences from `openqa-async`

- **Async only.** No synchronous/blocking facade; bring your own
  `tokio::runtime::Handle::block_on` if you need one.
- **Better retry/timeout defaults**, not Python parity — see the table
  above. Use [`RetryPolicy::upstream_compat`] for the old behaviour.
- **`Accept: application/json`**, not the Python client's literal `Accept: json`.
- **Restricted, same-origin redirects** (default cap of 3 hops); a
  cross-origin redirect is an error rather than silently dropping
  `X-API-Key`/`X-API-Hash` or (worse) forwarding them off-origin.
- **No `$OPENQA_CONFIG` or `$XDG_CONFIG_HOME` support**, and no sub-path
  (`base_url` with a path component) deployments — deliberate non-goals.
- **No typed openQA response models** — responses are `serde_json::Value`
  (or your own type via [`Client::request_as`]).
- **No CLI binary.**
- Response bodies are capped (32 MiB by default) unless read via
  [`Client::send_raw`].

## License

GPL-3.0-or-later. See [COPYING](https://github.com/mimi1vx/ruoqa/blob/main/COPYING).

This is a derivative of
[`mimi1vx/openqa-async`](https://github.com/mimi1vx/openqa-async)
(GPL-2.0-or-later); its "or later" clause permits distributing this port
under GPL-3.0-or-later.

[`Client::send_raw`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.send_raw
[`Client::request_as`]: https://docs.rs/ruoqa/latest/ruoqa/client/struct.Client.html#method.request_as
[`TlsMode`]: https://docs.rs/ruoqa/latest/ruoqa/tls/enum.TlsMode.html
[`Timeouts`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.Timeouts.html
[`RetryPolicy`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.RetryPolicy.html
[`RetryPolicy::upstream_compat`]: https://docs.rs/ruoqa/latest/ruoqa/policy/struct.RetryPolicy.html#method.upstream_compat
