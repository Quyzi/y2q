mod admin;
mod auth;
mod listing;
mod objects;
mod trace;
mod users;

use std::sync::Arc;

use reqwest::{RequestBuilder, Response, Url};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore};
use zeroize::Zeroizing;

use crate::error::ClientError;

#[derive(Default, Clone)]
pub struct TlsOptions {
    /// Skip server certificate verification entirely. Dangerous — use only
    /// for self-signed dev/staging endpoints.
    pub insecure: bool,
    /// Extra root CA (PEM bytes) to trust when verifying the server cert.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client identity (PEM bytes containing cert chain + private key
    /// concatenated) for mutual TLS.
    pub client_identity_pem: Option<Zeroizing<Vec<u8>>>,
}

pub struct ClientConfig {
    pub base_url: String,
    pub token: Option<Zeroizing<String>>,
    pub tls: TlsOptions,
}

impl ClientConfig {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            token: None,
            tls: TlsOptions::default(),
        }
    }
}

#[derive(Clone)]
pub struct Y2qClient {
    pub(crate) inner: reqwest::Client,
    pub(crate) base_url: Url,
    pub(crate) token: Option<Zeroizing<String>>,
}

impl Y2qClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let base_url = Url::parse(&config.base_url).map_err(|e| ClientError::BadRequest {
            message: format!("invalid server URL: {e}"),
        })?;
        let rustls_cfg = build_rustls_client_config(&config.tls)?;
        let inner = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(rustls_cfg)
            .build()?;
        Ok(Self {
            inner,
            base_url,
            token: config.token,
        })
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(Zeroizing::new(token.into()));
        self
    }

    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = Some(Zeroizing::new(token.into()));
    }

    pub fn inner_client(&self) -> &reqwest::Client {
        &self.inner
    }

    pub(crate) fn url(&self, path: &str) -> Url {
        self.base_url.join(path).expect("path join failed")
    }

    pub(crate) fn authed(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t.as_str()),
            None => rb,
        }
    }

    pub(crate) async fn check_status(resp: Response) -> Result<Response, ClientError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let message = match resp.json::<serde_json::Value>().await {
            Ok(v) => v["error"].as_str().unwrap_or("unknown error").to_owned(),
            Err(_) => status
                .canonical_reason()
                .unwrap_or("unknown error")
                .to_owned(),
        };
        Err(match status.as_u16() {
            401 => ClientError::Unauthenticated,
            404 => ClientError::NotFound { message },
            409 => ClientError::Conflict { message },
            400 => ClientError::BadRequest { message },
            code => ClientError::ServerError {
                status: code,
                message,
            },
        })
    }
}

/// Build a rustls [`ClientConfig`] backed by `aws-lc-rs` (so X25519MLKEM768
/// post-quantum hybrid key exchange is available) and apply the caller's
/// [`TlsOptions`]: optional extra CA bundle, optional client identity for
/// mutual TLS, and an `insecure` mode that disables peer verification.
///
/// Roots default to the bundled `webpki-roots`.
fn build_rustls_client_config(tls: &TlsOptions) -> Result<RustlsClientConfig, ClientError> {
    let provider = Arc::new(aws_lc_rs::default_provider());

    let builder = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::BadRequest {
            message: format!("rustls protocol versions: {e}"),
        })?;

    let configured = if tls.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier {
                provider: provider.clone(),
            }))
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = &tls.ca_cert_pem {
            let mut cursor: &[u8] = pem;
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert = cert.map_err(|e| ClientError::BadRequest {
                    message: format!("invalid CA bundle: {e}"),
                })?;
                roots.add(cert).map_err(|e| ClientError::BadRequest {
                    message: format!("add CA cert: {e}"),
                })?;
            }
        }
        builder.with_root_certificates(roots)
    };

    let rustls_cfg = match &tls.client_identity_pem {
        Some(pem) => {
            let (chain, key) = parse_client_identity(pem)?;
            configured
                .with_client_auth_cert(chain, key)
                .map_err(|e| ClientError::BadRequest {
                    message: format!("client identity: {e}"),
                })?
        }
        None => configured.with_no_client_auth(),
    };

    Ok(rustls_cfg)
}

fn parse_client_identity(
    pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ClientError> {
    let mut cursor: &[u8] = pem;
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    let mut key: Option<PrivateKeyDer<'static>> = None;
    for item in rustls_pemfile::read_all(&mut cursor) {
        let item = item.map_err(|e| ClientError::BadRequest {
            message: format!("invalid client identity: {e}"),
        })?;
        match item {
            rustls_pemfile::Item::X509Certificate(der) => chain.push(der),
            rustls_pemfile::Item::Pkcs1Key(k) => key = Some(PrivateKeyDer::Pkcs1(k)),
            rustls_pemfile::Item::Pkcs8Key(k) => key = Some(PrivateKeyDer::Pkcs8(k)),
            rustls_pemfile::Item::Sec1Key(k) => key = Some(PrivateKeyDer::Sec1(k)),
            _ => {}
        }
    }
    if chain.is_empty() {
        return Err(ClientError::BadRequest {
            message: "client identity: no certificate found".into(),
        });
    }
    let key = key.ok_or_else(|| ClientError::BadRequest {
        message: "client identity: no private key found".into(),
    })?;
    Ok((chain, key))
}

#[derive(Debug)]
struct NoVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
