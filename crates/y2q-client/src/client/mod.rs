mod admin;
mod auth;
mod listing;
mod objects;
mod personas;
mod trace;
mod users;

use std::sync::Arc;

use reqwest::{RequestBuilder, Response, Url};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::pem::PemObject;
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

/// Parse a server base URL, accepting only what the client can build request
/// URLs from: an `http`/`https` URL with a host.
///
/// `Url::parse` alone also accepts `mailto:x`, `data:…`, `file:///x` and even
/// `localhost:8080` (scheme `localhost`); the first request would then panic in
/// [`Y2qClient::url`] / [`Y2qClient::object_url`]. The URL itself is not echoed
/// in errors: it may carry credentials.
pub(crate) fn parse_base_url(s: &str) -> Result<Url, ClientError> {
    let url = Url::parse(s).map_err(|e| ClientError::BadRequest {
        message: format!("invalid server URL: {e}; expected an http:// or https:// URL"),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ClientError::BadRequest {
            message: format!(
                "invalid server URL: unsupported scheme `{}`; expected an http:// or https:// URL",
                url.scheme()
            ),
        });
    }
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(ClientError::BadRequest {
            message: "invalid server URL: missing host; expected an http:// or https:// URL".into(),
        });
    }
    Ok(url)
}

/// Check that `s` is usable as a server base URL (`http`/`https` with a host),
/// the same rule [`Y2qClient::new`] enforces. For validating user input early,
/// e.g. when an alias is saved.
pub fn validate_base_url(s: &str) -> Result<(), ClientError> {
    parse_base_url(s).map(drop)
}

#[derive(Clone)]
pub struct Y2qClient {
    pub(crate) inner: reqwest::Client,
    pub(crate) base_url: Url,
    pub(crate) token: Option<Zeroizing<String>>,
}

impl Y2qClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let base_url = parse_base_url(&config.base_url)?;
        let rustls_cfg = build_rustls_client_config(&config.tls)?;
        let inner = reqwest::ClientBuilder::new()
            .use_preconfigured_tls(rustls_cfg)
            // reqwest strips `Authorization` on host/port/scheme changes, but a
            // 307/308 would still replay the login body (username + password)
            // to `Location`, and same-origin redirects keep the bearer token.
            // The configured server URL is the only origin the operator vetted,
            // so 3xx is surfaced as `ClientError::Redirect`, never followed.
            .redirect(reqwest::redirect::Policy::none())
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
        // `base_url` is an http(s) URL that can be a base (see `parse_base_url`),
        // so joining a relative path onto it cannot fail.
        self.base_url.join(path).expect("path join failed")
    }

    /// Build the URL for an object operation on `bucket`/`key`.
    ///
    /// Unlike [`Self::url`], this does **not** go through `Url::join` on a
    /// `format!`-interpolated string: `join` performs RFC 3986 dot-segment
    /// resolution and strips `#`/`?` as a fragment/query, so a `key`
    /// containing `../`, `#`, or `?` would silently escape the intended
    /// bucket or truncate before reaching the server. Object keys are
    /// otherwise unrestricted (they may contain any character, including
    /// embedded `/`), so those cases are realistic, not just adversarial.
    /// Pushing each already-decoded path segment via
    /// [`Url::path_segments_mut`] instead percent-encodes `#`/`?` as literal
    /// key bytes, matching the server's `/{bucket}/{tail}*` route, which
    /// reconstructs the key from every segment after `bucket` including
    /// embedded slashes.
    ///
    /// A `.`/`..` path component is rejected outright rather than passed
    /// through: `path_segments_mut` silently *drops* (not resolves, not
    /// encodes) any segment equal to `.` or `..`, so letting one through
    /// would silently request a different key than the caller asked for.
    pub(crate) fn object_url(&self, bucket: &str, key: &str) -> Result<Url, ClientError> {
        let mut url = self.base_url.clone();
        {
            let mut segs = url
                .path_segments_mut()
                .expect("base_url is not a cannot-be-a-base URL");
            segs.push(bucket);
            for part in key.split('/') {
                if part == "." || part == ".." {
                    return Err(ClientError::BadRequest {
                        message: format!(
                            "invalid object key {key:?}: \".\" and \"..\" path components are not allowed"
                        ),
                    });
                }
                segs.push(part);
            }
        }
        Ok(url)
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
        if status.is_redirection() {
            return Err(redirect_error(&resp));
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

/// Build the redirect error without reading the (untrusted) response body.
/// `Location` is resolved against the request URL and reduced to
/// scheme/host/port/path: userinfo, query and fragment are dropped so
/// credentials embedded in the target are never echoed. Non-http(s) targets
/// are not echoed at all.
fn redirect_error(resp: &Response) -> ClientError {
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|l| resp.url().join(l).ok())
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .map(|mut u| {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        });
    ClientError::Redirect {
        status: resp.status().as_u16(),
        location,
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
            for cert in CertificateDer::pem_slice_iter(pem) {
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
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| ClientError::BadRequest {
            message: format!("invalid client identity: {e}"),
        })?;
    if chain.is_empty() {
        return Err(ClientError::BadRequest {
            message: "client identity: no certificate found".into(),
        });
    }
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|e| ClientError::BadRequest {
        message: format!("invalid client identity: {e}"),
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

    fn client() -> Y2qClient {
        // reqwest (built here with `rustls-tls-no-provider`) needs a process-wide
        // rustls crypto provider installed before any `Client` can be built;
        // ignore the error from a second test installing it after the first.
        let _ = aws_lc_rs::default_provider().install_default();
        Y2qClient {
            inner: reqwest::Client::new(),
            base_url: Url::parse("https://y2q.example/").unwrap(),
            token: None,
        }
    }

    #[test]
    fn object_url_rejects_dot_dot_instead_of_letting_it_escape_or_vanish() {
        // `Url::join` on a naively-formatted string would resolve `..` away
        // and escape `bucket` entirely. `path_segments_mut` doesn't do that,
        // but it also doesn't preserve `..` as a literal segment — it
        // silently drops it. Neither behavior is acceptable, so this must be
        // a loud, explicit error instead.
        assert!(
            client()
                .object_url("bucket", "../other-bucket/secret")
                .is_err()
        );
        assert!(client().object_url("bucket", "a/../b").is_err());
        assert!(client().object_url("bucket", ".").is_err());
    }

    #[test]
    fn object_url_keeps_hash_and_question_mark_as_literal_key_bytes() {
        // `Url::join` treats `#`/`?` as the start of a fragment/query, which
        // are not sent to the server at all — silently truncating the key.
        let url = client().object_url("bucket", "report#2.txt").unwrap();
        assert_eq!(url.path(), "/bucket/report%232.txt");
        assert!(url.fragment().is_none());

        let url = client().object_url("bucket", "a?b=c").unwrap();
        assert_eq!(url.path(), "/bucket/a%3Fb=c");
        assert!(url.query().is_none());
    }

    #[test]
    fn object_url_preserves_embedded_slashes_as_separate_segments() {
        let url = client()
            .object_url("bucket", "nested/path/to/file.txt")
            .unwrap();
        assert_eq!(url.path(), "/bucket/nested/path/to/file.txt");
    }

    #[test]
    fn base_url_rejects_everything_that_cannot_carry_http_requests() {
        // All of these parse with `Url::parse`; before validation the first
        // request panicked in `url()` / `object_url()`.
        for bad in [
            "mailto:ops@example.com",
            "data:text/plain,x",
            "localhost:8080",
            "file:///tmp/x",
            "ftp://example.com/",
            "ws://example.com/",
            "",
            "notaurl",
        ] {
            assert!(
                matches!(
                    Y2qClient::new(ClientConfig::new(bad.to_owned())),
                    Err(ClientError::BadRequest { .. })
                ),
                "{bad:?} must be rejected by Y2qClient::new"
            );
            assert!(validate_base_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn base_url_accepts_http_and_https_forms() {
        for ok in [
            "http://127.0.0.1:8080",
            "https://y2q.example/",
            "https://y2q.example/prefix/",
            "HTTPS://Y2Q.EXAMPLE",
            "http://[::1]:9000",
            "https://user@y2q.example",
        ] {
            let url = parse_base_url(ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
            // The invariant `url()` / `object_url()` rely on.
            assert!(!url.cannot_be_a_base(), "{ok:?}");
            url.join("api/v1/users").expect("join");
        }
    }

    #[test]
    fn base_url_error_does_not_echo_credentials() {
        let err = validate_base_url("ftp://user:s3cret@example.com/").unwrap_err();
        assert!(!err.to_string().contains("s3cret"), "{err}");
    }
}
