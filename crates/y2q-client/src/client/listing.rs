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
