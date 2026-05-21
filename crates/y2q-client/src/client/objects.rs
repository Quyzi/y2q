use std::collections::BTreeMap;

use futures::TryStreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::ObjectHead;

impl Y2qClient {
    /// Stream GET body to `writer`. Returns total bytes written.
    pub async fn get_to_writer<W>(
        &self,
        bucket: &str,
        key: &str,
        writer: &mut W,
    ) -> Result<u64, ClientError>
    where
        W: AsyncWrite + Unpin,
    {
        let url = self.url(&format!("{bucket}/{key}"));
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;

        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        let mut reader = StreamReader::new(stream);
        let n = tokio::io::copy(&mut reader, writer).await?;
        Ok(n)
    }

    /// Stream `reader` as PUT body. Returns `true` if object was newly created (201).
    pub async fn put_from_reader<R>(
        &self,
        bucket: &str,
        key: &str,
        reader: R,
        content_length: Option<u64>,
        labels: &BTreeMap<String, String>,
        sync: Option<&str>,
    ) -> Result<bool, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        let url = self.url(&format!("{bucket}/{key}"));
        let stream = ReaderStream::new(reader);
        let body = reqwest::Body::wrap_stream(stream);

        let mut rb = self.authed(self.inner.put(url)).body(body);
        if let Some(len) = content_length {
            rb = rb.header("Content-Length", len);
        }
        for (k, v) in labels {
            rb = rb.header(format!("X-Y2Q-{k}"), v);
        }
        if let Some(s) = sync {
            rb = rb.header("X-Y2Q-Sync", s);
        }

        let resp = rb.send().await?;
        let status = resp.status();
        Self::check_status(resp).await?;
        Ok(status.as_u16() == 201)
    }

    pub async fn delete(&self, bucket: &str, key: &str) -> Result<(), ClientError> {
        let url = self.url(&format!("{bucket}/{key}"));
        let resp = self.authed(self.inner.delete(url)).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    pub async fn head(&self, bucket: &str, key: &str) -> Result<ObjectHead, ClientError> {
        let url = self.url(&format!("{bucket}/{key}"));
        let resp = self.authed(self.inner.head(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        let headers = resp.headers();

        fn hdr(h: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
            h.get(name)?.to_str().ok().map(|s| s.to_owned())
        }
        fn hdr_u64(h: &reqwest::header::HeaderMap, name: &str) -> Option<u64> {
            hdr(h, name)?.parse().ok()
        }
        fn hdr_u16(h: &reqwest::header::HeaderMap, name: &str) -> Option<u16> {
            hdr(h, name)?.parse().ok()
        }

        let mut labels = BTreeMap::new();
        for (name, value) in headers {
            let name_str = name.as_str();
            if let Some(label) = name_str.strip_prefix("x-y2q-").filter(|s| {
                !matches!(
                    *s,
                    "created"
                        | "modified"
                        | "checksum-gxhash"
                        | "cipher-size"
                        | "cipher-sha256"
                        | "kem-alg"
                        | "aead-alg"
                        | "envelope-version"
                )
            }) && let Ok(v) = value.to_str()
            {
                labels.insert(label.to_owned(), v.to_owned());
            }
        }

        Ok(ObjectHead {
            size: hdr_u64(headers, "x-y2q-size")
                .or_else(|| hdr_u64(headers, "content-length"))
                .unwrap_or(0),
            created: hdr_u64(headers, "x-y2q-created").unwrap_or(0),
            modified: hdr_u64(headers, "x-y2q-modified").unwrap_or(0),
            checksum_gxhash: hdr(headers, "x-y2q-checksum-gxhash").unwrap_or_default(),
            labels,
            cipher_size: hdr_u64(headers, "x-y2q-cipher-size"),
            cipher_sha256: hdr(headers, "x-y2q-cipher-sha256"),
            kem_alg: hdr(headers, "x-y2q-kem-alg"),
            aead_alg: hdr(headers, "x-y2q-aead-alg"),
            envelope_version: hdr_u16(headers, "x-y2q-envelope-version"),
        })
    }
}
