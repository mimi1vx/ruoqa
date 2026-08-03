// SPDX-License-Identifier: GPL-3.0-or-later

//! `client.conf` discovery scenarios, driven over an injectable path list so
//! no test touches the real `$HOME` or `/etc/openqa` and the suite stays
//! parallel-safe.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use ruoqa::config::resolve;

/// A throwaway directory, removed on drop. Avoids a `tempfile`
/// dev-dependency for the handful of `client.conf` fixtures below.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruoqa-config-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

fn write_conf(dir: &Path, contents: &str) -> PathBuf {
    let path = dir.join("client.conf");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    path
}

/// The scheme+host string (no trailing `/`).
fn base_url_str(config: &ruoqa::config::Config) -> String {
    config.base_url.origin().ascii_serialization()
}

/// `test_key_secret_resolved_from_server_section`
#[test]
fn key_secret_resolved_from_server_section() {
    let dir = tempdir();
    let path = write_conf(
        &dir,
        "[openqa.example.com]\nkey = AAAAAAAA\nsecret = BBBBBBBB\n",
    );
    let config = resolve(&[path], "openqa.example.com", "").unwrap();
    assert_eq!(base_url_str(&config), "https://openqa.example.com");
    assert_eq!(config.api_key.unwrap().as_str(), "AAAAAAAA");
    assert_eq!(config.api_secret.unwrap().as_str(), "BBBBBBBB");
}

/// `test_key_secret_resolved_from_baseurl_section`
#[test]
fn key_secret_resolved_from_baseurl_section() {
    let dir = tempdir();
    let path = write_conf(
        &dir,
        "[https://openqa.example.com]\nkey = CCCCCCCC\nsecret = DDDDDDDD\n",
    );
    let config = resolve(&[path], "openqa.example.com", "").unwrap();
    assert_eq!(config.api_key.unwrap().as_str(), "CCCCCCCC");
    assert_eq!(config.api_secret.unwrap().as_str(), "DDDDDDDD");
}

/// `test_scheme_defaults_localhost_to_http`
#[test]
fn scheme_defaults_localhost_to_http() {
    let no_paths: [PathBuf; 0] = [];
    let config = resolve(&no_paths, "localhost", "").unwrap();
    assert_eq!(base_url_str(&config), "http://localhost");
    let config = resolve(&no_paths, "127.0.0.1", "").unwrap();
    assert_eq!(base_url_str(&config), "http://127.0.0.1");
}

/// `test_scheme_defaults_remote_to_https`
#[test]
fn scheme_defaults_remote_to_https() {
    let no_paths: [PathBuf; 0] = [];
    let config = resolve(&no_paths, "openqa.example.com", "").unwrap();
    assert_eq!(base_url_str(&config), "https://openqa.example.com");
}

/// `test_scheme_taken_from_http_prefixed_server`
#[test]
fn scheme_taken_from_http_prefixed_server() {
    let no_paths: [PathBuf; 0] = [];
    let config = resolve(&no_paths, "http://openqa.example.com", "").unwrap();
    assert_eq!(base_url_str(&config), "http://openqa.example.com");
}

/// `test_no_key_means_get_only_mode`
#[test]
fn no_key_means_get_only_mode() {
    let no_paths: [PathBuf; 0] = [];
    let config = resolve(&no_paths, "openqa.example.com", "").unwrap();
    assert!(config.api_key.is_none());
    assert!(config.api_secret.is_none());
}

/// `test_empty_server_defaults_to_first_config_section`
#[test]
fn empty_server_defaults_to_first_config_section() {
    let dir = tempdir();
    let path = write_conf(
        &dir,
        "[openqa.first.com]\nkey = AAAAAAAA\nsecret = BBBBBBBB\n\
         [openqa.second.com]\nkey = CCCCCCCC\nsecret = DDDDDDDD\n",
    );
    let config = resolve(&[path], "", "").unwrap();
    assert_eq!(base_url_str(&config), "https://openqa.first.com");
    assert_eq!(config.api_key.unwrap().as_str(), "AAAAAAAA");
    assert_eq!(config.api_secret.unwrap().as_str(), "BBBBBBBB");
}

/// `test_empty_server_no_config_defaults_to_localhost`
#[test]
fn empty_server_no_config_defaults_to_localhost() {
    let no_paths: [PathBuf; 0] = [];
    let config = resolve(&no_paths, "", "").unwrap();
    assert_eq!(base_url_str(&config), "http://localhost");
    assert!(config.api_secret.is_none());
}

/// Later files override earlier ones per-key.
#[test]
fn later_path_wins_per_key() {
    let dir = tempdir();
    let etc = write_conf(
        &dir,
        "[openqa.example.com]\nkey = FIRST\nsecret = FIRST_SECRET\n",
    );
    let home_dir = dir.join("home");
    std::fs::create_dir_all(&home_dir).unwrap();
    let home = write_conf(&home_dir, "[openqa.example.com]\nkey = SECOND\n");
    let config = resolve(&[etc, home], "openqa.example.com", "").unwrap();
    assert_eq!(config.api_key.unwrap().as_str(), "SECOND");
    assert_eq!(config.api_secret.unwrap().as_str(), "FIRST_SECRET");
}

/// Trailing whitespace on values is stripped.
#[test]
fn trailing_whitespace_on_values_is_stripped() {
    let dir = tempdir();
    let path = write_conf(
        &dir,
        "[openqa.example.com]\nkey = AAAAAAAA \nsecret = BBBBBBBB \n",
    );
    let config = resolve(&[path], "openqa.example.com", "").unwrap();
    assert_eq!(config.api_key.unwrap().as_str(), "AAAAAAAA");
    assert_eq!(config.api_secret.unwrap().as_str(), "BBBBBBBB");
}
