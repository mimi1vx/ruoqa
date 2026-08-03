# AGENTS.md

`ruoqa` — async openQA REST API client. Single-crate Rust library (no binary),
edition 2024, MSRV **1.96**. Partial port of the Python `openqa-async` client.

## Verification (match CI, in this order)

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings   # warnings ARE errors
cargo test --locked
cargo check --locked --all-targets                   # MSRV: pin toolchain 1.96
cargo deny check                                      # license allow-list gate
```

- `[lints.clippy] pedantic = "warn"` in Cargo.toml, but CI runs clippy with
  `-D warnings` — treat any pedantic lint as a hard failure.
- `unsafe_code = "forbid"` (crate-wide `#![forbid(unsafe_code)]`) — never add unsafe.
- `#![warn(missing_docs)]` — every public item needs a doc comment.
- Every source file starts with `// SPDX-License-Identifier: GPL-3.0-or-later`.

## Run a single test

```sh
cargo test --test retry                    # one integration test file (tests/*.rs)
cargo test --test retry -- some_test_name  # one test fn
```

Integration tests live in `tests/` and use `wiremock` (HTTP mocking) and
`rcgen`/`tokio-rustls` (TLS tests) — no external services or network required.

## Repo-specific gotchas

- **Auth golden vectors:** `tests/vectors.json` was generated once from the
  Python `openqa_async._auth.OpenQAAuth`. `tests/auth_vectors.rs` asserts
  byte-for-byte reproduction of HMAC-SHA1 signing. Do NOT edit the vectors to
  make a test pass — a diff there means the signing logic (`src/auth.rs`)
  regressed against wire compatibility.
- **cargo-deny is license-only** (`deny.toml`): allow-list is permissive licenses
  only; `ruoqa` itself is the sole GPL exception. A new dep with a copyleft/
  GPL-incompatible license fails CI by design — don't add it to `exceptions`.
- **README is the crate docs:** `src/lib.rs` uses `#![doc = include_str!("../README.md")]`.
  Doc-test snippets in README.md run under `cargo test`; keep them compiling.
- `src/consts.rs` mirrors openQA's `const.py`; enums are `#[non_exhaustive]`
  with `#[serde(other)] Unknown` so unknown server values never fail to deserialize.

## Layout

`src/`: `client.rs` (Client/ClientBuilder), `auth.rs` (HMAC-SHA1 signing),
`config.rs` (`client.conf` discovery), `policy.rs` (retry/timeout), `tls.rs`,
`secret.rs` (zeroized key/secret), `error.rs`, `consts.rs`.

`plans/` holds the port design docs (background only, not build instructions).
