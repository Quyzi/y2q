mod admin;
mod auth;
mod listing;
mod objects;
mod users;

use reqwest::{RequestBuilder, Response, Url};
use zeroize::Zeroizing;

use crate::error::ClientError;

pub struct ClientConfig {
    pub base_url: String,
    pub token: Option<Zeroizing<String>>,
}

pub struct Y2qClient {
    pub(crate) inner: reqwest::Client,
    pub(crate) base_url: Url,
    pub(crate) token: Option<Zeroizing<String>>,
}

impl Y2qClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let base_url = Url::parse(&config.base_url)
            .map_err(|e| ClientError::BadRequest { message: format!("invalid server URL: {e}") })?;
        let inner = reqwest::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self { inner, base_url, token: config.token })
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(Zeroizing::new(token.into()));
        self
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
            Ok(v) => v["error"]
                .as_str()
                .unwrap_or("unknown error")
                .to_owned(),
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
            code => ClientError::ServerError { status: code, message },
        })
    }
}
