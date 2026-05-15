use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{AddUserRequest, ListUsersResponse, UserView};

impl Y2qClient {
    pub async fn add_user(&self, username: &str, password: &str) -> Result<(), ClientError> {
        let url = self.url("api/v1/users/add");
        let body = AddUserRequest {
            username: username.to_owned(),
            password: password.to_owned(),
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
}
