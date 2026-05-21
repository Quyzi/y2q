use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::path::RemotePath;

pub async fn run(path: String, bytes: u64) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let key = remote.key.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into())
    })?;

    let client = make_client(&remote.alias).await?;

    // GET into a duplex pipe, then read up to `bytes` from the read side. When
    // the writer is dropped after the limit is reached the GET task aborts.
    let (mut reader, mut writer) = tokio::io::duplex(64 * 1024);
    let bucket = bucket.to_owned();
    let key = key.to_owned();
    let task = tokio::spawn(async move {
        // Ignore broken-pipe errors when the reader drops early.
        let _ = client.get_to_writer(&bucket, &key, &mut writer).await;
    });

    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 8 * 1024];
    let mut remaining = bytes;
    while remaining > 0 {
        let cap = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = reader.read(&mut buf[..cap]).await.map_err(CliError::Io)?;
        if n == 0 {
            break;
        }
        stdout.write_all(&buf[..n]).await.map_err(CliError::Io)?;
        remaining -= n as u64;
    }
    drop(reader);
    let _ = task.await;
    stdout.flush().await.map_err(CliError::Io)?;
    Ok(())
}
