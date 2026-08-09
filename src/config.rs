// SPDX-License-Identifier: GPL-3.0-or-later

//! `client.conf` discovery and base URL derivation, matching
//! `_OpenQAClientBase.__init__`'s config-parsing behaviour.

use std::path::{Path, PathBuf};

use ini::Ini;
use url::Url;

use crate::error::{Error, Result};
use crate::secret::{ApiKey, ApiSecret, Credentials};

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

/// The default `client.conf` search path.
///
/// When `$OPENQA_CONFIG` is set (and non-empty) it is an **exclusive
/// override**: the only path searched is `$OPENQA_CONFIG/client.conf`, and
/// `/etc` and the user config dir are not consulted. Otherwise the search is
/// `/etc/openqa/client.conf` then the user config dir's `openqa/client.conf`,
/// where the user config dir is `$XDG_CONFIG_HOME` when set, non-empty, and
/// absolute, else `$HOME/.config`. This is a deliberate divergence from the
/// Python client's fixed two-path merge.
#[must_use]
pub fn default_paths() -> Vec<PathBuf> {
    paths_from_env(
        std::env::var("OPENQA_CONFIG").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// Pure helper behind [`default_paths`]; see its docs for the semantics.
/// Empty strings are treated as unset.
fn paths_from_env(
    openqa_config: Option<&str>,
    xdg: Option<&str>,
    home: Option<&str>,
) -> Vec<PathBuf> {
    if let Some(dir) = non_empty(openqa_config) {
        return vec![Path::new(dir).join("client.conf")];
    }

    let mut paths = vec![PathBuf::from("/etc/openqa/client.conf")];
    match non_empty(xdg).filter(|x| Path::new(x).is_absolute()) {
        Some(xdg) => paths.push(Path::new(xdg).join("openqa/client.conf")),
        None => {
            if let Some(home) = non_empty(home) {
                paths.push(Path::new(home).join(".config/openqa/client.conf"));
            }
        }
    }
    paths
}

/// Treats an empty string as unset, as the Python client's `os.environ.get`
/// callers do here.
fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

/// The credential environment variables `OpenQA::UserAgent` reads.
const API_KEY_ENV: &str = "OPENQA_API_KEY";
const API_SECRET_ENV: &str = "OPENQA_API_SECRET";

/// Credentials from `$OPENQA_API_KEY`/`$OPENQA_API_SECRET`, as upstream's
/// `OpenQA::UserAgent::new` reads them. Empty values count as unset.
///
/// # Errors
///
/// [`Error::IncompleteCredentials`] when exactly one of the two is set.
#[allow(clippy::result_large_err)] // see `resolve`
pub(crate) fn env_credentials() -> Result<Option<Credentials>> {
    credentials_from_env(
        std::env::var(API_KEY_ENV).ok().as_deref(),
        std::env::var(API_SECRET_ENV).ok().as_deref(),
    )
}

/// Pure helper behind [`env_credentials`]; empty strings are unset.
#[allow(clippy::result_large_err)] // see `resolve`
fn credentials_from_env(key: Option<&str>, secret: Option<&str>) -> Result<Option<Credentials>> {
    Credentials::from_parts(
        non_empty(key).map(ApiKey::new),
        non_empty(secret).map(ApiSecret::new),
        "the environment",
        (API_KEY_ENV, API_SECRET_ENV),
    )
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

    let mut base_url =
        Url::parse(&format!("{scheme}://{server}")).map_err(|e| Error::Config(Box::new(e)))?;

    // `netloc()` above already drops userinfo for the `http…`-prefixed form;
    // this covers the bare-authority form (e.g. `alice:s3cret@host`), which
    // skips `netloc()` and reaches `Url::parse` untouched. Never echoes the
    // credentials: userinfo never authenticated a ruoqa request (see
    // plans/url-userinfo-redaction.md), so there's nothing sensitive to
    // withhold, but no reason to print it either.
    if !base_url.username().is_empty() || base_url.password().is_some() {
        tracing::warn!("dropping userinfo from server URL: it does not authenticate requests");
        let _ = base_url.set_username("");
        let _ = base_url.set_password(None);
    }

    let base_url_section = base_url.origin().ascii_serialization();
    let (api_key, api_secret) = lookup_credentials(&merged, &server, &base_url_section);

    Ok(Config {
        base_url,
        api_key,
        api_secret,
    })
}

/// `host[:port]`. Unlike Python's `urlparse().netloc`, which includes
/// userinfo, this deliberately drops it — userinfo is dead weight here (see
/// the strip in [`resolve`] for the other, bare-authority path it can arrive
/// by), not a feature to restore.
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

#[cfg(test)]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    fn userinfo_in_bare_authority_server_is_stripped() {
        let no_paths: [PathBuf; 0] = [];
        let config = resolve(&no_paths, "alice:s3cret@openqa.example.com", "").unwrap();
        assert!(config.base_url.username().is_empty());
        assert!(config.base_url.password().is_none());
        assert_eq!(config.base_url.host_str(), Some("openqa.example.com"));
    }

    #[test]
    fn userinfo_in_config_section_name_is_stripped() {
        let dir =
            std::env::temp_dir().join(format!("ruoqa-config-userinfo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.conf");
        std::fs::write(
            &path,
            "[alice:s3cret@openqa.example.com]\nkey = AAAAAAAA\nsecret = BBBBBBBB\n",
        )
        .unwrap();
        let config = resolve(&[&path], "", "").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(config.base_url.username().is_empty());
        assert!(config.base_url.password().is_none());
    }

    #[test]
    #[traced_test]
    fn stripping_userinfo_warns_without_echoing_it() {
        let no_paths: [PathBuf; 0] = [];
        resolve(&no_paths, "alice:s3cret@openqa.example.com", "").unwrap();
        assert!(logs_contain("dropping userinfo"));
        assert!(!logs_contain("s3cret"));
    }

    #[test]
    #[traced_test]
    fn no_warning_without_userinfo() {
        let no_paths: [PathBuf; 0] = [];
        resolve(&no_paths, "openqa.example.com", "").unwrap();
        assert!(!logs_contain("userinfo"));
    }

    #[test]
    fn default_search_order() {
        let paths = paths_from_env(None, None, Some("/home/u"));
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/openqa/client.conf"),
                PathBuf::from("/home/u/.config/openqa/client.conf"),
            ]
        );
    }

    #[test]
    fn openqa_config_is_exclusive() {
        let paths = paths_from_env(Some("/tmp/x"), None, Some("/home/u"));
        assert_eq!(paths, vec![PathBuf::from("/tmp/x/client.conf")]);
    }

    #[test]
    fn openqa_config_wins_over_xdg_and_home() {
        let paths = paths_from_env(Some("/tmp/x"), Some("/tmp/cfg"), Some("/home/u"));
        assert_eq!(paths, vec![PathBuf::from("/tmp/x/client.conf")]);
    }

    #[test]
    fn absolute_xdg_replaces_home() {
        let paths = paths_from_env(None, Some("/tmp/cfg"), Some("/home/u"));
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/openqa/client.conf"),
                PathBuf::from("/tmp/cfg/openqa/client.conf"),
            ]
        );
    }

    #[test]
    fn relative_xdg_falls_back_to_home() {
        let paths = paths_from_env(None, Some("relative/cfg"), Some("/home/u"));
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/openqa/client.conf"),
                PathBuf::from("/home/u/.config/openqa/client.conf"),
            ]
        );
    }

    #[test]
    fn empty_xdg_falls_back_to_home() {
        let paths = paths_from_env(None, Some(""), Some("/home/u"));
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/openqa/client.conf"),
                PathBuf::from("/home/u/.config/openqa/client.conf"),
            ]
        );
    }

    #[test]
    fn empty_openqa_config_is_unset() {
        let paths = paths_from_env(Some(""), None, Some("/home/u"));
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/openqa/client.conf"),
                PathBuf::from("/home/u/.config/openqa/client.conf"),
            ]
        );
    }

    #[test]
    fn no_home_yields_single_etc_entry() {
        let paths = paths_from_env(None, None, None);
        assert_eq!(paths, vec![PathBuf::from("/etc/openqa/client.conf")]);
    }

    #[test]
    fn credentials_from_env_both_set_pairs() {
        let credentials = credentials_from_env(Some("KEY"), Some("SECRET"))
            .unwrap()
            .unwrap();
        assert_eq!(credentials.key.as_str(), "KEY");
        assert_eq!(credentials.secret.as_str(), "SECRET");
    }

    #[test]
    fn credentials_from_env_both_unset_is_none() {
        assert!(credentials_from_env(None, None).unwrap().is_none());
    }

    #[test]
    fn credentials_from_env_both_empty_is_none() {
        assert!(credentials_from_env(Some(""), Some("")).unwrap().is_none());
    }

    #[test]
    fn credentials_from_env_key_only_errors() {
        let err = credentials_from_env(Some("topvalue123"), None).unwrap_err();
        let message = err.to_string();
        assert!(message.contains(API_KEY_ENV));
        assert!(message.contains(API_SECRET_ENV));
        assert!(!message.contains("topvalue123"));
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                present: API_KEY_ENV,
                missing: API_SECRET_ENV,
                ..
            }
        ));
    }

    #[test]
    fn credentials_from_env_secret_only_errors() {
        let err = credentials_from_env(None, Some("topvalue456")).unwrap_err();
        let message = err.to_string();
        assert!(message.contains(API_SECRET_ENV));
        assert!(!message.contains("topvalue456"));
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                present: API_SECRET_ENV,
                missing: API_KEY_ENV,
                ..
            }
        ));
    }

    #[test]
    fn credentials_from_env_empty_key_with_secret_is_half_set() {
        let err = credentials_from_env(Some(""), Some("SECRET")).unwrap_err();
        assert!(matches!(
            err,
            Error::IncompleteCredentials {
                present: API_SECRET_ENV,
                missing: API_KEY_ENV,
                ..
            }
        ));
    }
}
