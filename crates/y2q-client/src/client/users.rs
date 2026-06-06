use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{AddUserRequest, ListUsersResponse, UserView};

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

    pub async fn delete_user(&self, username: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/users/{username}"));
        let resp = self.authed(self.inner.delete(url)).send().await?;
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
}
