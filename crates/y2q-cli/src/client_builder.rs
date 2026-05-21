//! Helpers that turn an [`Alias`] into a [`ClientConfig`] / [`Y2qClient`],
//! including reading TLS material from disk.

use std::fs;
use std::path::Path;

use y2q_client::{ClientConfig, TlsOptions, Y2qClient};
use y2q_config::Alias;
use zeroize::Zeroizing;

use crate::error::CliError;

/// Build a [`ClientConfig`] from an alias entry, attaching the optional bearer
/// token and any TLS material referenced by the alias.
pub fn client_config_from_alias(
    alias: &Alias,
    token: Option<Zeroizing<String>>,
) -> Result<ClientConfig, CliError> {
    let mut tls = TlsOptions {
        insecure: alias.insecure,
        ..TlsOptions::default()
    };
    if let Some(path) = &alias.ca_cert_path {
        tls.ca_cert_pem = Some(read_pem(path, "CA certificate")?);
    }
    match (&alias.client_cert_path, &alias.client_key_path) {
        (Some(cert), Some(key)) => {
            let mut bundle = read_pem(cert, "client certificate")?;
            bundle.push(b'\n');
            bundle.extend_from_slice(&read_pem(key, "client key")?);
            tls.client_identity_pem = Some(Zeroizing::new(bundle));
        }
        (None, None) => {}
        _ => {
            return Err(CliError::Other(
                "client_cert_path and client_key_path must both be set or both unset".into(),
            ));
        }
    }
    Ok(ClientConfig {
        base_url: alias.url.clone(),
        token,
        tls,
    })
}

/// Build a [`Y2qClient`] from an alias entry + optional token.
pub fn client_from_alias(
    alias: &Alias,
    token: Option<Zeroizing<String>>,
) -> Result<Y2qClient, CliError> {
    let cfg = client_config_from_alias(alias, token)?;
    Y2qClient::new(cfg).map_err(CliError::from)
}

fn read_pem(path: &str, label: &str) -> Result<Vec<u8>, CliError> {
    fs::read(Path::new(path)).map_err(|e| CliError::Other(format!("read {label} from {path}: {e}")))
}
