// SPDX-License-Identifier: GPL-3.0-or-later

//! Reproduces `tests/vectors.json`, generated once from the Python
//! `openqa_async._auth.OpenQAAuth` implementation. See that file's
//! `provenance` field for how it was produced.

use ruoqa::secret::ApiSecret;
use serde_json::Value;

#[test]
fn golden_vectors_reproduce_byte_for_byte() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json"))
        .expect("tests/vectors.json is readable");
    let file: Value = serde_json::from_str(&raw).expect("tests/vectors.json is valid JSON");
    let vectors = file["vectors"].as_array().expect("vectors is an array");
    assert!(!vectors.is_empty());

    for vector in vectors {
        let url_str = vector["url"].as_str().expect("url is a string");
        let timestamp = vector["timestamp"].as_str().expect("timestamp is a string");
        let expected_signing = vector["signing_string"]
            .as_str()
            .expect("signing_string is a string");
        let expected_hash = vector["hash"].as_str().expect("hash is a string");
        let secret = vector["secret"].as_str().expect("secret is a string");

        let url = url::Url::parse(url_str).expect("vector URL parses");
        let signing = ruoqa::auth::signing_string(&url);
        assert_eq!(signing, expected_signing, "signing_string for {url_str}");

        let hash = ruoqa::auth::sign(&signing, timestamp, &ApiSecret::new(secret));
        assert_eq!(hash, expected_hash, "hash for {url_str}");
    }
}
