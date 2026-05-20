//! TLS setup: load PEM cert chain + private key and build a rustls
//! [`ServerConfig`].

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

/// Build a rustls [`ServerConfig`] from PEM-encoded certificate and private-key files.
///
/// Accepts PKCS#8, PKCS#1, and SEC1 private keys. When `client_ca_path` is
/// Some, configures mTLS — every client must present a certificate chained to
/// one of the bundled CAs.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> io::Result<ServerConfig> {
    let cert_chain = load_certs(cert_path)?;
    if cert_chain.is_empty() {
        return Err(io::Error::other(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    let key = load_private_key(key_path)?;

    let builder = ServerConfig::builder();
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
