use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{AddUserRequest, ListUsersResponse, ResetIdentityResponse, UserView};

impl Y2qClient {
    /// Create a user. `role` is `"admin"`, `"user"`, or `None` to let the
    /// server default to `user`.
    pub async fn add_user(
        &self,
        username: &str,
        password: &str,
        role: Option<&str>,
    ) -> Result<(), ClientError> {
        let url = self.url("api/v1/users/add");
        let body = AddUserRequest {
            username: username.to_owned(),
            password: password.to_owned(),
            role: role.map(str::to_owned),
        };
        let resp = self.authed(self.inner.put(url)).json(&body).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserView>, ClientError> {
        let url = self.url("api/v1/users");
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        let body = resp.json::<ListUsersResponse>().await?;
        Ok(body.users)
    }

    /// Delete a user. `force` bypasses the server's guard against stranding
    /// a bucket this user owns (see `?force=true` on the endpoint).
    pub async fn delete_user(&self, username: &str, force: bool) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/users/{username}"));
        let req = self.authed(self.inner.delete(url));
        let req = if force {
            req.query(&[("force", "true")])
        } else {
            req
        };
        let resp = req.send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// Change a user's global role (`admin`/`user`/`readonly`/`writeonly`/
    /// `auditor`/`disabled`). Takes effect immediately (revokes their sessions).
    pub async fn set_user_role(&self, username: &str, role: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/users/{username}/role"));
        let body = serde_json::json!({ "role": role });
        let resp = self.authed(self.inner.put(url)).json(&body).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// Reset a user's identity keypair (all four credential slots) and
    /// scrub every bucket-key grant they held. Restores login under the new
    /// password; does not restore access.
    pub async fn reset_identity(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ResetIdentityResponse, ClientError> {
        let url = self.url(&format!("api/v1/users/{username}/reset-identity"));
        let body = serde_json::json!({ "password": password });
        let resp = self.authed(self.inner.post(url)).json(&body).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<ResetIdentityResponse>().await?)
    }
}
