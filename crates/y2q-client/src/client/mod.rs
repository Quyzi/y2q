mod admin;
mod auth;
mod listing;
mod objects;
mod trace;
mod users;

use reqwest::{Certificate, Identity, RequestBuilder, Response, Url};
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
        let mut builder = reqwest::ClientBuilder::new();
        if config.tls.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(ca_pem) = &config.tls.ca_cert_pem {
            for cert in
                Certificate::from_pem_bundle(ca_pem).map_err(|e| ClientError::BadRequest {
                    message: format!("invalid CA bundle: {e}"),
                })?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        if let Some(ident_pem) = &config.tls.client_identity_pem {
            let identity = Identity::from_pem(ident_pem).map_err(|e| ClientError::BadRequest {
                message: format!("invalid client identity: {e}"),
            })?;
            builder = builder.identity(identity);
        }
        let inner = builder.build()?;
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
