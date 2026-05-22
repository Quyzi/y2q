use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{ListBucketsResponse, ListOptions, ListPage};

impl Y2qClient {
    pub async fn list_buckets(&self) -> Result<Vec<String>, ClientError> {
        let url = self.url("/");
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        let body = resp.json::<ListBucketsResponse>().await?;
        Ok(body.buckets)
    }

    /// Create a bucket. Returns `true` if newly created, `false` if it already
    /// existed.
    pub async fn create_bucket(&self, bucket: &str) -> Result<bool, ClientError> {
        let url = self.url(&format!("{bucket}/"));
        let resp = self.authed(self.inner.put(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        let body = resp.json::<serde_json::Value>().await?;
        Ok(body["created"].as_bool().unwrap_or(false))
    }

    /// Delete a bucket and all of its objects. Returns the number of objects
    /// removed.
    pub async fn delete_bucket(&self, bucket: &str) -> Result<u64, ClientError> {
        let url = self.url(&format!("{bucket}/"));
        let resp = self.authed(self.inner.delete(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        let body = resp.json::<serde_json::Value>().await?;
        Ok(body["objects_removed"].as_u64().unwrap_or(0))
    }

    /// Fetch a bucket's configuration (quota / default-SSE / CORS).
    pub async fn get_bucket_config(
        &self,
        bucket: &str,
    ) -> Result<crate::model::BucketConfig, ClientError> {
        let url = self.url(&format!("api/v1/buckets/{bucket}/config"));
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// Replace a bucket's configuration.
    pub async fn set_bucket_config(
        &self,
        bucket: &str,
        config: &crate::model::BucketConfig,
    ) -> Result<crate::model::BucketConfig, ClientError> {
        let url = self.url(&format!("api/v1/buckets/{bucket}/config"));
        let resp = self.authed(self.inner.put(url)).json(config).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        options: &ListOptions,
    ) -> Result<ListPage, ClientError> {
        let url = self.url(&format!("{bucket}/"));
        let mut req = self.authed(self.inner.get(url));

        if let Some(ref p) = options.prefix {
            req = req.query(&[("prefix", p.as_str())]);
        }
        if let Some(ref a) = options.after {
            req = req.query(&[("after", a.as_str())]);
        }
        if let Some(lim) = options.limit {
            req = req.query(&[("limit", lim.to_string())]);
        }

        let resp = req.send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<ListPage>().await?)
    }
}
