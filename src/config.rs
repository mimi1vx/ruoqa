// SPDX-License-Identifier: GPL-3.0-or-later

//! `client.conf` discovery and base URL derivation, matching
//! `_OpenQAClientBase.__init__`'s config-parsing behaviour.

use std::net::Ipv6Addr;
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

/// The default `client.conf` search path, matching `OpenQA::Config`'s
/// tiered lookup (`_config_dirs` + `lookup_config_files`).
///
/// There are three tiers, searched in order, and the **first tier that
/// yields any file wins outright** — later tiers are not read at all, so a
/// user `client.conf` replaces `/etc/openqa/client.conf` rather than merging
/// with it:
///
/// 1. `$OPENQA_CONFIG` (only when set and non-empty; a ruoqa extension is
///    that an empty tier — no `client.conf` and no drop-ins — falls through
///    to tier 2 instead of being an exclusive override).
/// 2. The user config dir: `$XDG_CONFIG_HOME/openqa` when that variable is
///    set, non-empty, and absolute, else `$HOME/.config/openqa`
///    (`$XDG_CONFIG_HOME` is a ruoqa extension; upstream hardcodes
///    `~/.config/openqa`).
/// 3. `/etc/openqa`, then `/usr/etc/openqa`.
///
/// Within a tier, each directory contributes its `client.conf` (if present)
/// followed by its `client.conf.d/*.conf` drop-ins, sorted by name, with
/// later files winning; a directory with only drop-ins does not stop the
/// scan, so a later directory's `client.conf` in the same tier still lands
/// (and outranks the earlier drop-ins).
///
/// The return value is the list of files that actually exist, in merge
/// order — not a fixed candidate list.
#[must_use]
pub fn default_paths() -> Vec<PathBuf> {
    let tiers = config_dirs_from_env(
        std::env::var("OPENQA_CONFIG").ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    );
    let files = lookup_config_files(&tiers, "client.conf");
    tracing::debug!(?files, "resolved client.conf search list");
    files
}

/// The tiered `client.conf` directories behind [`default_paths`]; see its
/// docs for the semantics. Empty strings are treated as unset.
pub(crate) fn config_dirs_from_env(
    openqa_config: Option<&str>,
    xdg: Option<&str>,
    home: Option<&str>,
) -> Vec<Vec<PathBuf>> {
    let mut tiers = Vec::new();

    if let Some(dir) = non_empty(openqa_config) {
        tiers.push(vec![PathBuf::from(dir)]);
    }

    let user_dir = match non_empty(xdg).filter(|x| Path::new(x).is_absolute()) {
        Some(xdg) => Some(Path::new(xdg).join("openqa")),
        None => non_empty(home).map(|home| Path::new(home).join(".config/openqa")),
    };
    if let Some(dir) = user_dir {
        tiers.push(vec![dir]);
    }

    tiers.push(vec![
        PathBuf::from("/etc/openqa"),
        PathBuf::from("/usr/etc/openqa"),
    ]);

    tiers
}

/// Transcription of upstream's `lookup_config_files`: within each tier, each
/// directory contributes its `name` file (if present) followed by its
/// `name.d/*.conf` drop-ins, sorted; a directory with only drop-ins does not
/// stop the scan of the tier's remaining directories. Returns the first
/// tier's file list that isn't empty, or an empty `Vec` if none is.
pub(crate) fn lookup_config_files(tiers: &[Vec<PathBuf>], name: &str) -> Vec<PathBuf> {
    for tier in tiers {
        let mut out = Vec::new();
        for dir in tier {
            let main = dir.join(name);
            let has_main = main.is_file();
            if has_main {
                out.push(main);
            }
            out.extend(drop_ins(&dir.join(format!("{name}.d"))));
            if has_main {
                break;
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    Vec::new()
}

/// `*.conf` files directly in `dir`, sorted by path. A missing or
/// unreadable directory yields no drop-ins, matching upstream's outcome for
/// the missing case (`glob` on a nonexistent directory is empty).
fn drop_ins(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "conf"))
        .collect();
    files.sort();
    files
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
        // Carries the path forward (e.g. `/openqa`) instead of discarding
        // it, so a sub-path deployment survives; ports and further parsing
        // are left to the final `Url::parse` below.
        server = format!("{}{}", netloc(&parsed), parsed.path());
    } else if let Ok(ip) = server.parse::<Ipv6Addr>() {
        // A bare IPv6 literal (`::1`) is not a valid authority on its own;
        // bracket it so the final `Url::parse` accepts it.
        server = format!("[{ip}]");
    }

    if scheme.is_empty() {
        // Probe-parsed only to classify the host as loopback or not: the
        // authoritative parse (ports, paths) remains the one below.
        let loopback =
            Url::parse(&format!("http://{server}")).is_ok_and(|url| is_loopback_host(&url));
        if loopback { "http" } else { "https" }.clone_into(&mut scheme);
    }

    let mut base_url =
        Url::parse(&format!("{scheme}://{server}")).map_err(|e| Error::Config(Box::new(e)))?;

    // Never echoes the credentials: userinfo never authenticated a ruoqa
    // request (see plans/url-userinfo-redaction.md), so there's nothing
    // sensitive to withhold, but no reason to print it either.
    if !base_url.username().is_empty() || base_url.password().is_some() {
        tracing::warn!("dropping userinfo from server URL: it does not authenticate requests");
        let _ = base_url.set_username("");
        let _ = base_url.set_password(None);
    }

    // Makes `Url::join` treat a sub-path prefix as a directory rather than a
    // file to replace; a no-op for the path-less default (`Url::parse`
    // already yields `/`).
    if !base_url.path().ends_with('/') {
        let path = format!("{}/", base_url.path());
        base_url.set_path(&path);
    }

    let authority = netloc(&base_url);
    let origin = base_url.origin().ascii_serialization();
    let bare_host = base_url.host_str().unwrap_or_default();
    let (api_key, api_secret) = lookup_credentials(&merged, &authority, &origin, bare_host);

    Ok(Config {
        base_url,
        api_key,
        api_secret,
    })
}

/// `host[:port]`, path-free — matching upstream's section-key convention
/// (`OpenQA::Command::client`, `OpenQA::Worker::WebUIConnection`: bare host,
/// no port, no path). Unlike Python's `urlparse().netloc`, which includes
/// userinfo, this deliberately drops it — userinfo is dead weight here (see
/// the strip in [`resolve`] for the bare-authority path it can arrive by),
/// not a feature to restore.
fn netloc(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// `true` for `localhost` and loopback IPs; used by [`resolve`]'s scheme
/// defaulting and by [`crate::client`]'s plaintext-credentials warning.
pub(crate) fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
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

/// Credential lookup: the `host[:port]` authority's section first, then the
/// `base_url` origin's, then the bare host's (matching `openqa-cli`'s
/// `api => $url->host` for parity with upstream, which only ever fires when
/// the first two miss). Both `key` and `secret` must be present in a
/// section for it to count, matching upstream's all-or-nothing
/// `except configparser.Error` fallback.
fn lookup_credentials(
    config: &Ini,
    authority: &str,
    origin: &str,
    bare_host: &str,
) -> (Option<ApiKey>, Option<ApiSecret>) {
    section_credentials(config, authority)
        .or_else(|| section_credentials(config, origin))
        .or_else(|| section_credentials(config, bare_host))
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
    fn is_loopback_host_matches_localhost_and_loopback_ips() {
        assert!(is_loopback_host(&Url::parse("http://localhost").unwrap()));
        assert!(is_loopback_host(&Url::parse("http://127.0.0.1").unwrap()));
        assert!(is_loopback_host(&Url::parse("http://[::1]").unwrap()));
        assert!(!is_loopback_host(
            &Url::parse("http://openqa.example.com").unwrap()
        ));
    }

    /// `/etc/openqa`, `/usr/etc/openqa` — tier 3 is always present.
    fn etc_tier() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/openqa"),
            PathBuf::from("/usr/etc/openqa"),
        ]
    }

    #[test]
    fn default_search_order() {
        let tiers = config_dirs_from_env(None, None, Some("/home/u"));
        assert_eq!(
            tiers,
            vec![vec![PathBuf::from("/home/u/.config/openqa")], etc_tier()]
        );
    }

    #[test]
    fn openqa_config_is_the_first_tier_not_an_override() {
        let tiers = config_dirs_from_env(Some("/tmp/x"), None, Some("/home/u"));
        assert_eq!(
            tiers,
            vec![
                vec![PathBuf::from("/tmp/x")],
                vec![PathBuf::from("/home/u/.config/openqa")],
                etc_tier(),
            ]
        );
    }

    #[test]
    fn openqa_config_wins_over_xdg_and_home() {
        let tiers = config_dirs_from_env(Some("/tmp/x"), Some("/tmp/cfg"), Some("/home/u"));
        assert_eq!(tiers[0], vec![PathBuf::from("/tmp/x")]);
    }

    #[test]
    fn absolute_xdg_replaces_home() {
        let tiers = config_dirs_from_env(None, Some("/tmp/cfg"), Some("/home/u"));
        assert_eq!(
            tiers,
            vec![vec![PathBuf::from("/tmp/cfg/openqa")], etc_tier()]
        );
    }

    #[test]
    fn relative_xdg_falls_back_to_home() {
        let tiers = config_dirs_from_env(None, Some("relative/cfg"), Some("/home/u"));
        assert_eq!(
            tiers,
            vec![vec![PathBuf::from("/home/u/.config/openqa")], etc_tier()]
        );
    }

    #[test]
    fn empty_xdg_falls_back_to_home() {
        let tiers = config_dirs_from_env(None, Some(""), Some("/home/u"));
        assert_eq!(
            tiers,
            vec![vec![PathBuf::from("/home/u/.config/openqa")], etc_tier()]
        );
    }

    #[test]
    fn empty_openqa_config_is_unset() {
        let tiers = config_dirs_from_env(Some(""), None, Some("/home/u"));
        assert_eq!(
            tiers,
            vec![vec![PathBuf::from("/home/u/.config/openqa")], etc_tier()]
        );
    }

    #[test]
    fn no_home_yields_etc_tier_only() {
        let tiers = config_dirs_from_env(None, None, None);
        assert_eq!(tiers, vec![etc_tier()]);
    }

    /// A fresh, empty temp directory for one `lookup_config_files` test.
    /// Mirrors the `std::env::temp_dir()` fixture already used by
    /// `userinfo_in_config_section_name_is_stripped`.
    fn tempdir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ruoqa-config-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lookup_first_tier_with_a_file_wins() {
        let base = tempdir("first-tier-wins");
        let tier1 = base.join("tier1");
        let tier2 = base.join("tier2");
        std::fs::create_dir_all(&tier1).unwrap();
        std::fs::create_dir_all(&tier2).unwrap();
        std::fs::write(tier1.join("client.conf"), "").unwrap();
        std::fs::write(tier2.join("client.conf"), "").unwrap();

        let files = lookup_config_files(&[vec![tier1.clone()], vec![tier2]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(files, vec![tier1.join("client.conf")]);
    }

    #[test]
    fn lookup_tier_without_file_or_dropins_falls_through() {
        let base = tempdir("empty-tier-falls-through");
        let tier1 = base.join("tier1");
        let tier2 = base.join("tier2");
        std::fs::create_dir_all(&tier1).unwrap();
        std::fs::create_dir_all(&tier2).unwrap();
        std::fs::write(tier2.join("client.conf"), "").unwrap();

        let files = lookup_config_files(&[vec![tier1], vec![tier2.clone()]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(files, vec![tier2.join("client.conf")]);
    }

    #[test]
    fn lookup_dropins_are_appended_after_main_sorted_conf_only() {
        let base = tempdir("dropins-sorted");
        let dropins = base.join("client.conf.d");
        std::fs::create_dir_all(&dropins).unwrap();
        std::fs::write(base.join("client.conf"), "").unwrap();
        std::fs::write(dropins.join("20-b.conf"), "").unwrap();
        std::fs::write(dropins.join("10-a.conf"), "").unwrap();
        std::fs::write(dropins.join("README.md"), "").unwrap();
        std::fs::write(dropins.join("10-x.txt"), "").unwrap();

        let files = lookup_config_files(&[vec![base.clone()]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(
            files,
            vec![
                base.join("client.conf"),
                dropins.join("10-a.conf"),
                dropins.join("20-b.conf"),
            ]
        );
    }

    #[test]
    fn lookup_dropins_alone_win_and_dont_stop_the_directory_scan() {
        let base = tempdir("dropins-dont-stop-scan");
        let dir1 = base.join("dir1");
        let dir2 = base.join("dir2");
        let dropins1 = dir1.join("client.conf.d");
        std::fs::create_dir_all(&dropins1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dropins1.join("10-a.conf"), "").unwrap();
        std::fs::write(dir2.join("client.conf"), "").unwrap();

        let files = lookup_config_files(&[vec![dir1, dir2.clone()]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(
            files,
            vec![dropins1.join("10-a.conf"), dir2.join("client.conf")]
        );
    }

    #[test]
    fn lookup_missing_dropins_dir_is_not_an_error() {
        let base = tempdir("missing-dropins-dir");
        std::fs::write(base.join("client.conf"), "").unwrap();

        let files = lookup_config_files(&[vec![base.clone()]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert_eq!(files, vec![base.join("client.conf")]);
    }

    #[test]
    fn lookup_all_tiers_empty_yields_empty_vec() {
        let base = tempdir("all-tiers-empty");
        let tier1 = base.join("tier1");
        std::fs::create_dir_all(&tier1).unwrap();

        let files = lookup_config_files(&[vec![tier1]], "client.conf");

        std::fs::remove_dir_all(&base).unwrap();
        assert!(files.is_empty());
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
