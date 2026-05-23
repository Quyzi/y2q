use tokio::io::AsyncWriteExt;

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

    let mut stdout = tokio::io::stdout();
    if bytes == 0 {
        stdout.flush().await.map_err(CliError::Io)?;
        return Ok(());
    }

    let client = make_client(&remote.alias).await?;

    // Ranged GET for the first `bytes` octets only (HTTP byte ranges are
    // inclusive). The server decrypts just the requested range instead of
    // streaming the whole object.
    client
        .get_range_to_writer(bucket, key, 0, bytes - 1, &mut stdout)
        .await?;
    stdout.flush().await.map_err(CliError::Io)?;
    Ok(())
}
