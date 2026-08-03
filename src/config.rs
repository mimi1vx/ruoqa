// SPDX-License-Identifier: GPL-3.0-or-later

//! `client.conf` discovery and base URL derivation, matching
//! `_OpenQAClientBase.__init__`'s config-parsing behaviour.

use std::path::{Path, PathBuf};

use ini::Ini;
use url::Url;

use crate::error::{Error, Result};
use crate::secret::{ApiKey, ApiSecret};

/// Resolved server configuration: base URL and (optional) credentials.
///
/// `base_url` is a full [`Url`] (so it carries a trailing `/`); the
/// scheme+host section-header form is `base_url.origin().ascii_serialization()`.
#[derive(Debug)]
pub struct Config {
    /// The resolved base URL, scheme included.
    pub base_url: Url,
    /// The API key, if `client.conf` (or an override) provided one.
    pub api_key: Option<ApiKey>,
    /// The API secret, if `client.conf` (or an override) provided one.
    pub api_secret: Option<ApiSecret>,
}

/// The default `client.conf` search path: `/etc/openqa/client.conf` then
/// `~/.config/openqa/client.conf`. `$HOME` is read directly; there is no
/// `$OPENQA_CONFIG` or `XDG_CONFIG_HOME` support (deliberate non-goals).
#[must_use]
pub fn default_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/openqa/client.conf")];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(Path::new(&home).join(".config/openqa/client.conf"));
    }
    paths
}

/// Read and merge `client.conf` files in order (later file's keys win, per
/// `configparser.read([a, b])`), then derive the base URL and credentials
/// for `server`.
///
/// An empty `server` uses the first section of the merged config, or
/// `localhost` if there is none. An empty `scheme` is inferred from
/// `server`.
///
/// # Errors
///
/// Returns [`Error::Config`] if a `client.conf` fails to parse or the
/// derived base URL is invalid.
#[allow(clippy::result_large_err)] // `Error`'s size is a phase-1 decision; not this fn's to fix.
pub fn resolve(paths: &[impl AsRef<Path>], server: &str, scheme: &str) -> Result<Config> {
    let merged = load_merged(paths)?;

    let mut server = server.to_owned();
    if server.is_empty() {
        server = merged
            .sections()
            .flatten()
            .next()
            .map_or_else(|| "localhost".to_owned(), str::to_owned);
    }

    let mut scheme = scheme.to_owned();
    if server.starts_with("http")
        && let Ok(parsed) = Url::parse(&server)
    {
        if scheme.is_empty() {
            parsed.scheme().clone_into(&mut scheme);
        }
        server = netloc(&parsed);
    }

    if scheme.is_empty() {
        if matches!(server.as_str(), "localhost" | "127.0.0.1" | "::1") {
            "http"
        } else {
            "https"
        }
        .clone_into(&mut scheme);
    }

    let base_url =
        Url::parse(&format!("{scheme}://{server}")).map_err(|e| Error::Config(Box::new(e)))?;

    let base_url_section = base_url.origin().ascii_serialization();
    let (api_key, api_secret) = lookup_credentials(&merged, &server, &base_url_section);

    Ok(Config {
        base_url,
        api_key,
        api_secret,
    })
}

/// `host[:port]`.
fn netloc(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

fn parse_option() -> ini::ParseOption {
    ini::ParseOption {
        enabled_escape: false,
        ..ini::ParseOption::default()
    }
}

#[allow(clippy::result_large_err)] // see `resolve`
fn load_merged(paths: &[impl AsRef<Path>]) -> Result<Ini> {
    let mut merged = Ini::new();
    for path in paths {
        let path = path.as_ref();
        if !path.exists() {
            continue;
        }
        let ini = Ini::load_from_file_opt(path, parse_option())
            .map_err(|e| Error::Config(Box::new(e)))?;
        for (section, props) in &ini {
            for (key, value) in props {
                merged.set_to(section.map(str::to_owned), key.to_owned(), value.to_owned());
            }
        }
    }
    Ok(merged)
}

/// Credential lookup: `server`'s section first, then the `base_url` section.
/// Both `key` and `secret` must be present in a section for it to count,
/// matching upstream's all-or-nothing `except configparser.Error` fallback.
fn lookup_credentials(
    config: &Ini,
    server: &str,
    base_url_section: &str,
) -> (Option<ApiKey>, Option<ApiSecret>) {
    section_credentials(config, server)
        .or_else(|| section_credentials(config, base_url_section))
        .map_or((None, None), |(key, secret)| {
            (Some(ApiKey::new(key)), Some(ApiSecret::new(secret)))
        })
}

/// `key`/`secret` from a section, trailing-whitespace stripped (a real-world
/// footgun worth fixing here).
fn section_credentials(config: &Ini, section_name: &str) -> Option<(String, String)> {
    let section = config.section(Some(section_name))?;
    let key = section.get("key")?.trim_end().to_owned();
    let secret = section.get("secret")?.trim_end().to_owned();
    Some((key, secret))
}
