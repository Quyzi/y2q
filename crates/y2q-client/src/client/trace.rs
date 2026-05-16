use std::pin::Pin;

use futures::{Stream, StreamExt};
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::io::StreamReader;

use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::TraceEvent;

impl Y2qClient {
    /// Connect to the server's live trace stream.
    ///
    /// Returns a stream that yields one `TraceEvent` per request the server
    /// handles. The stream ends when the connection is closed (server restart,
    /// network drop, etc.). Authenticate with a valid Bearer token first.
    pub async fn connect_trace(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = TraceEvent> + Send + '_>>, ClientError> {
        let url = self.url("api/v1/trace");
        let resp = self
            .authed(self.inner.get(url))
            .header("Accept", "text/event-stream")
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;

        let byte_stream =
            resp.bytes_stream().map(|r| r.map_err(std::io::Error::other));
        let reader = StreamReader::new(byte_stream);
        let lines = FramedRead::new(reader, LinesCodec::new());

        let event_stream = lines.filter_map(|line_result| async move {
            let line = line_result.ok()?;
            let json = line.strip_prefix("data: ")?;
            serde_json::from_str::<TraceEvent>(json).ok()
        });

        Ok(Box::pin(event_stream))
    }
}
