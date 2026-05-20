//! TLS setup: load PEM cert chain + private key and build a rustls
//! [`ServerConfig`].

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

/// Build a rustls [`ServerConfig`] from PEM-encoded certificate and private-key files.
///
/// Accepts PKCS#8, PKCS#1, and SEC1 private keys. When `client_ca_path` is
/// Some, configures mTLS — every client must present a certificate chained to
/// one of the bundled CAs.
///
/// When `require_pq_kex` is true, the server's offered key-exchange groups
/// are restricted to the X25519MLKEM768 post-quantum hybrid group; clients
/// that cannot negotiate it are refused at handshake.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    require_pq_kex: bool,
) -> io::Result<ServerConfig> {
    let cert_chain = load_certs(cert_path)?;
    if cert_chain.is_empty() {
        return Err(io::Error::other(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    let key = load_private_key(key_path)?;

    let provider = build_provider(require_pq_kex)?;

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls protocol versions: {e}")))?;
    let builder = match client_ca_path {
        Some(ca) => {
            let roots = load_client_roots(ca)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| io::Error::other(format!("client verifier: {e}")))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    builder
        .with_single_cert(cert_chain, key)
        .map_err(|e| io::Error::other(format!("rustls config: {e}")))
}

/// Build a [`CryptoProvider`] backed by `aws-lc-rs`. When `require_pq_kex`
/// is true, the provider's `kx_groups` list is replaced with the single
/// X25519MLKEM768 hybrid group, so handshakes that can't agree on PQ key
/// exchange are rejected.
fn build_provider(require_pq_kex: bool) -> io::Result<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    if require_pq_kex {
        let pq = aws_lc_rs::kx_group::X25519MLKEM768;
        // Sanity check: confirm the provider actually advertises the PQ group
        // before we narrow the offered list to it. Guards against a future
        // aws-lc-rs build that drops the group.
        if !provider.kx_groups.iter().any(|g| g.name() == pq.name()) {
            return Err(io::Error::other(
                "aws-lc-rs provider does not advertise X25519MLKEM768; rebuild with a newer rustls/aws-lc-rs",
            ));
        }
        provider.kx_groups = vec![pq];
    }
    Ok(provider)
}

fn load_client_roots(path: &Path) -> io::Result<RootCertStore> {
    let certs = load_certs(path)?;
    if certs.is_empty() {
        return Err(io::Error::other(format!(
            "no CA certificates found in {}",
            path.display()
        )));
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::other(format!("add client CA: {e}")))?;
    }
    Ok(roots)
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path)
            .map_err(|e| io::Error::new(e.kind(), format!("open cert {}: {e}", path.display())))?,
    );
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path)
            .map_err(|e| io::Error::new(e.kind(), format!("open key {}: {e}", path.display())))?,
    );
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::other(format!(
            "no PKCS#8, PKCS#1, or SEC1 private key found in {}",
            path.display()
        ))
    })
}
