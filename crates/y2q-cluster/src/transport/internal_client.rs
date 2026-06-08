//! HTTP client for node-to-node RPC.
//!
//! Wraps a reqwest client configured with the same PQ-TLS stack the daemon
//! serves (`aws-lc-rs`, X25519MLKEM768), with optional mutual TLS and an
//! optional shared-secret header. Used by the raft network and (later) the data
//! plane to talk to peers' `/internal/v1` endpoints.

use std::sync::Arc;

use reqwest::RequestBuilder;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// Header carrying the cluster shared secret on every internal request.
pub const CLUSTER_AUTH_HEADER: &str = "X-Y2Q-Cluster-Auth";

/// Errors from node-to-node transport.
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    /// Failed to build the HTTP/TLS client.
    #[error("build internal client: {0}")]
    Build(String),
    /// The request could not be sent or the connection failed.
    #[error("internal request to {url}: {error}")]
    Request {
        /// Target URL.
        url: String,
        /// Underlying reqwest error rendered as text.
        error: String,
    },
    /// The peer returned a non-success status.
    #[error("peer returned status {status}: {message}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Response body (best-effort).
        message: String,
    },
    /// The response body could not be decoded.
    #[error("decode response from {url}: {error}")]
    Decode {
        /// Target URL.
        url: String,
        /// Decode error text.
        error: String,
    },
}

/// TLS options for the internal client (mirrors the daemon's server TLS).
#[derive(Default, Clone)]
pub struct InternalTlsOptions {
    /// Skip server certificate verification. Dev/staging only.
    pub insecure: bool,
    /// Extra root CA (PEM) to trust — typically the cluster CA.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client identity (PEM: cert chain + key) for mutual TLS.
    pub client_identity_pem: Option<Zeroizing<Vec<u8>>>,
}

/// A reqwest-backed client for peer RPC.
#[derive(Clone)]
pub struct InternalClient {
    http: reqwest::Client,
    secret: Option<Zeroizing<String>>,
}

impl InternalClient {
    /// Build a client with the given TLS options and optional shared secret.
    pub fn new(tls: &InternalTlsOptions, secret: Option<String>) -> Result<Self, TransportError> {
        let rustls_cfg = build_rustls_client_config(tls)?;
        let http = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(rustls_cfg)
            .build()
            .map_err(|e| TransportError::Build(e.to_string()))?;
        Ok(Self {
            http,
            secret: secret.map(Zeroizing::new),
        })
    }

    /// Attach the shared-secret header if configured.
    fn auth(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.secret {
            Some(s) => rb.header(CLUSTER_AUTH_HEADER, s.as_str()),
            None => rb,
        }
    }

    /// POST `body` as JSON to `url` and decode the JSON response.
    pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        url: &str,
        body: &Req,
    ) -> Result<Resp, TransportError> {
        let rb = self.auth(self.http.post(url).json(body));
        let resp = rb.send().await.map_err(|e| TransportError::Request {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        self.decode(url, resp).await
    }

    /// POST a streaming `body` to `url` with extra `headers` and decode the JSON
    /// response. Used by the data plane to relay a ciphertext envelope to the
    /// next chain member without buffering it.
    pub async fn post_stream<Resp: DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: reqwest::Body,
    ) -> Result<Resp, TransportError> {
        let mut rb = self.http.post(url).body(body);
        for (name, value) in headers {
            rb = rb.header(*name, value);
        }
        let rb = self.auth(rb);
        let resp = rb.send().await.map_err(|e| TransportError::Request {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        self.decode(url, resp).await
    }

    /// POST a body streamed from `rx` (each `Bytes` becomes a body chunk) to `url`
    /// with extra `headers`, and decode the JSON response. Lets callers in crates
    /// without a `reqwest` dependency stream a request body via a channel.
    pub async fn post_stream_rx<Resp: DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, String)],
        rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    ) -> Result<Resp, TransportError> {
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|b| (Ok::<bytes::Bytes, std::io::Error>(b), rx))
        });
        self.post_stream(url, headers, reqwest::Body::wrap_stream(stream))
            .await
    }

    /// GET `url` and decode the JSON response.
    pub async fn get_json<Resp: DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<Resp, TransportError> {
        let rb = self.auth(self.http.get(url));
        let resp = rb.send().await.map_err(|e| TransportError::Request {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        self.decode(url, resp).await
    }

    /// GET `url` with URL-encoded query `params` and decode the JSON response.
    /// `reqwest` percent-encodes each pair, so values may contain `/`, `&`, etc.
    pub async fn get_json_query<Resp: DeserializeOwned>(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<Resp, TransportError> {
        let rb = self.auth(self.http.get(url).query(params));
        let resp = rb.send().await.map_err(|e| TransportError::Request {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        self.decode(url, resp).await
    }

    /// GET `url` with query `params` and return the raw response body plus the
    /// plaintext object size advertised in the `X-Y2Q-Size` header. Used by the
    /// apportioned read path to fetch a committed ciphertext envelope from a
    /// peer (the chain TAIL) for local decryption. A `404` is surfaced as
    /// [`TransportError::Status`] with status `404` so the caller can map it to
    /// not-found.
    pub async fn fetch_object(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<(bytes::Bytes, u64), TransportError> {
        let rb = self.auth(self.http.get(url).query(params));
        let resp = rb.send().await.map_err(|e| TransportError::Request {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        let status = resp.status();
        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(TransportError::Status {
                status: status.as_u16(),
                message,
            });
        }
        let size = resp
            .headers()
            .get("x-y2q-size")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = resp.bytes().await.map_err(|e| TransportError::Decode {
            url: url.to_string(),
            error: e.to_string(),
        })?;
        Ok((bytes, size))
    }

    async fn decode<Resp: DeserializeOwned>(
        &self,
        url: &str,
        resp: reqwest::Response,
    ) -> Result<Resp, TransportError> {
        let status = resp.status();
        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(TransportError::Status {
                status: status.as_u16(),
                message,
            });
        }
        resp.json::<Resp>()
            .await
            .map_err(|e| TransportError::Decode {
                url: url.to_string(),
                error: e.to_string(),
            })
    }
}

/// Build a rustls client config backed by `aws-lc-rs` (PQ-hybrid KX available),
/// applying the caller's [`InternalTlsOptions`].
fn build_rustls_client_config(
    tls: &InternalTlsOptions,
) -> Result<RustlsClientConfig, TransportError> {
    let provider = Arc::new(aws_lc_rs::default_provider());

    let builder = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Build(format!("rustls protocol versions: {e}")))?;

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
                let cert =
                    cert.map_err(|e| TransportError::Build(format!("invalid CA bundle: {e}")))?;
                roots
                    .add(cert)
                    .map_err(|e| TransportError::Build(format!("add CA cert: {e}")))?;
            }
        }
        builder.with_root_certificates(roots)
    };

    let rustls_cfg = match &tls.client_identity_pem {
        Some(pem) => {
            let (chain, key) = parse_client_identity(pem)?;
            configured
                .with_client_auth_cert(chain, key)
                .map_err(|e| TransportError::Build(format!("client identity: {e}")))?
        }
        None => configured.with_no_client_auth(),
    };

    Ok(rustls_cfg)
}

fn parse_client_identity(
    pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    let mut cursor: &[u8] = pem;
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    let mut key: Option<PrivateKeyDer<'static>> = None;
    for item in rustls_pemfile::read_all(&mut cursor) {
        let item =
            item.map_err(|e| TransportError::Build(format!("invalid client identity: {e}")))?;
        match item {
            rustls_pemfile::Item::X509Certificate(der) => chain.push(der),
            rustls_pemfile::Item::Pkcs1Key(k) => key = Some(PrivateKeyDer::Pkcs1(k)),
            rustls_pemfile::Item::Pkcs8Key(k) => key = Some(PrivateKeyDer::Pkcs8(k)),
            rustls_pemfile::Item::Sec1Key(k) => key = Some(PrivateKeyDer::Sec1(k)),
            _ => {}
        }
    }
    if chain.is_empty() {
        return Err(TransportError::Build(
            "client identity: no certificate found".to_string(),
        ));
    }
    let key = key.ok_or_else(|| {
        TransportError::Build("client identity: no private key found".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_insecure_client() {
        let tls = InternalTlsOptions {
            insecure: true,
            ..Default::default()
        };
        assert!(InternalClient::new(&tls, Some("secret".to_string())).is_ok());
    }

    #[test]
    fn builds_default_root_client() {
        let client = InternalClient::new(&InternalTlsOptions::default(), None);
        assert!(client.is_ok());
    }
}
