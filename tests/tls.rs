// SPDX-License-Identifier: GPL-3.0-or-later

//! Exercises `TlsMode` end-to-end against a real TLS listener (phase-5 step
//! 12): a local server presents a self-signed leaf certificate for
//! `127.0.0.1`, chained to a locally generated CA, and each `TlsMode`
//! variant is checked for the accept/reject behaviour it promises.

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use reqwest::Method;
use ruoqa::tls::TlsMode;
use ruoqa::{ClientBuilder, Error};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A self-signed CA usable to sign leaf certificates.
fn make_ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    CertifiedIssuer::self_signed(params, key).unwrap()
}

/// A leaf certificate for `127.0.0.1`, signed by `ca`.
fn make_leaf(ca: &CertifiedIssuer<'static, KeyPair>) -> (CertificateDer<'static>, KeyPair) {
    let params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca).unwrap();
    (cert.der().clone(), key)
}

/// Starts a TLS listener presenting (`cert`, `key`) and returns its address.
/// Every accepted connection gets a single canned `200 application/json {}`
/// response, enough for `Client::request` to complete a full round trip.
async fn spawn_tls_server(cert: CertificateDer<'static>, key: KeyPair) -> SocketAddr {
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\n\
                          content-type: application/json\r\n\
                          content-length: 2\r\n\
                          connection: close\r\n\r\n\
                          {}",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });

    addr
}

/// A client pointed at `addr` with a low retry budget, so a rejected TLS
/// handshake fails fast instead of exhausting the default retry policy.
fn client_for(addr: SocketAddr, tls: TlsMode) -> ruoqa::Client {
    ClientBuilder::new()
        .server(format!("https://{addr}"))
        .tls(tls)
        .retry(ruoqa::policy::RetryPolicy::default().max_retries(0))
        .build()
        .unwrap()
}

#[tokio::test]
async fn platform_verifier_rejects_self_signed_cert() {
    let ca = make_ca();
    let (leaf, key) = make_leaf(&ca);
    let addr = spawn_tls_server(leaf, key).await;

    let client = client_for(addr, TlsMode::PlatformVerifier);
    let err = client.request(Method::GET, "/", None).await.unwrap_err();
    assert!(
        matches!(err, Error::Connection { .. }),
        "expected a TLS-rejected connection error, got {err:?}"
    );
}

#[tokio::test]
async fn custom_ca_accepts_the_matching_cert() {
    let ca = make_ca();
    let (leaf, key) = make_leaf(&ca);
    let addr = spawn_tls_server(leaf, key).await;

    let ca_cert = reqwest::tls::Certificate::from_der(ca.der()).unwrap();
    let client = client_for(
        addr,
        TlsMode::CustomCa {
            certs: vec![ca_cert],
            replace_roots: false,
        },
    );
    let value = client.request(Method::GET, "/", None).await.unwrap();
    assert_eq!(value, serde_json::json!({}));
}

#[tokio::test]
async fn custom_ca_replace_roots_rejects_a_different_ca() {
    let ca = make_ca();
    let (leaf, key) = make_leaf(&ca);
    let addr = spawn_tls_server(leaf, key).await;

    let other_ca = make_ca();
    let other_ca_cert = reqwest::tls::Certificate::from_der(other_ca.der()).unwrap();
    let client = client_for(
        addr,
        TlsMode::CustomCa {
            certs: vec![other_ca_cert],
            replace_roots: true,
        },
    );
    let err = client.request(Method::GET, "/", None).await.unwrap_err();
    assert!(
        matches!(err, Error::Connection { .. }),
        "expected a TLS-rejected connection error, got {err:?}"
    );
}

#[tokio::test]
async fn danger_accept_invalid_certs_accepts_the_self_signed_cert() {
    let ca = make_ca();
    let (leaf, key) = make_leaf(&ca);
    let addr = spawn_tls_server(leaf, key).await;

    let client = client_for(addr, TlsMode::danger_accept_invalid_certs());
    let value = client.request(Method::GET, "/", None).await.unwrap();
    assert_eq!(value, serde_json::json!({}));
}
