use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{
    ClearStaleLocksResponse, RebuildStatus, RekeyStatus, RotateKeyResponse, StaleLockEntry,
};

impl Y2qClient {
    pub async fn rebuild_start(&self) -> Result<(), ClientError> {
        let url = self.url("api/v1/rebuild");
        let resp = self.authed(self.inner.post(url)).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    pub async fn rebuild_status(&self) -> Result<RebuildStatus, ClientError> {
        let url = self.url("api/v1/rebuild");
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<RebuildStatus>().await?)
    }

    pub async fn locks_list(&self, older_than: &str) -> Result<Vec<StaleLockEntry>, ClientError> {
        let url = self.url("api/v1/locks");
        let resp = self
            .authed(self.inner.get(url))
            .query(&[("older_than", older_than)])
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<Vec<StaleLockEntry>>().await?)
    }

    pub async fn locks_clear(&self, older_than: &str) -> Result<u64, ClientError> {
        let url = self.url("api/v1/locks");
        let resp = self
            .authed(self.inner.delete(url))
            .query(&[("older_than", older_than)])
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let body = resp.json::<ClearStaleLocksResponse>().await?;
        Ok(body.removed)
    }

    /// Create a new bucket key epoch (`POST /api/v1/buckets/{bucket}/rotate-key`).
    pub async fn rotate_bucket_key(&self, bucket: &str) -> Result<RotateKeyResponse, ClientError> {
        let url = self.url(&format!("api/v1/buckets/{bucket}/rotate-key"));
        let resp = self.authed(self.inner.post(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<RotateKeyResponse>().await?)
    }

    /// Start a bucket rekey (`POST /api/v1/buckets/{bucket}/rekey`).
    pub async fn rekey_start(&self, bucket: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/buckets/{bucket}/rekey"));
        let resp = self.authed(self.inner.post(url)).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// Query a bucket's rekey status (`GET /api/v1/buckets/{bucket}/rekey`).
    pub async fn rekey_status(&self, bucket: &str) -> Result<RekeyStatus, ClientError> {
        let url = self.url(&format!("api/v1/buckets/{bucket}/rekey"));
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<RekeyStatus>().await?)
    }

    /// Fetch the raw Prometheus scrape body from `/metrics/prometheus`.
    pub async fn prometheus_metrics(&self) -> Result<String, ClientError> {
        let url = self.url("metrics/prometheus");
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.text().await?)
    }
}
