use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{ChangePasswordRequest, LoginRequest, TokenResponse};

impl Y2qClient {
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        ttl_seconds: Option<u64>,
    ) -> Result<TokenResponse, ClientError> {
        let url = self.url("api/v1/auth/login");
        let body = LoginRequest {
            username: username.to_owned(),
            password: password.to_owned(),
            ttl_seconds,
        };
        let resp = self.inner.post(url).json(&body).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<TokenResponse>().await?)
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        let url = self.url("api/v1/auth/logout");
        let resp = self.authed(self.inner.post(url)).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    pub async fn refresh(&self) -> Result<TokenResponse, ClientError> {
        let url = self.url("api/v1/auth/refresh");
        let resp = self.authed(self.inner.post(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<TokenResponse>().await?)
    }

    pub async fn change_password(&self, current: &str, new: &str) -> Result<(), ClientError> {
        let url = self.url("api/v1/auth/password");
        let body = ChangePasswordRequest {
            current: current.to_owned(),
            new: new.to_owned(),
        };
        let resp = self.authed(self.inner.post(url)).json(&body).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }
}
