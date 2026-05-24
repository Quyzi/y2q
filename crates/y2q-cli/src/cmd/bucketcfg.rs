//! `quota` and `encrypt` — per-bucket configuration via read-modify-write of
//! the bucket config endpoint.

use crate::cli::{EncryptCmd, QuotaCmd};
use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::RemotePath;

fn bucket_of(target: &str) -> Result<(RemotePath, String), CliError> {
    let remote = RemotePath::parse(target)?;
    let bucket = remote
        .bucket
        .clone()
        .ok_or_else(|| CliError::InvalidPath(target.to_owned(), "expected alias/bucket".into()))?;
    if remote.key.is_some() {
        return Err(CliError::InvalidPath(
            target.to_owned(),
            "expected alias/bucket, not a key".into(),
        ));
    }
    Ok((remote, bucket))
}

fn parse_size(s: &str) -> Result<u64, CliError> {
    crate::ops::buckets::parse_size(s).map_err(CliError::Other)
}

pub async fn run_quota(cmd: QuotaCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        QuotaCmd::Set { target, size } => {
            let (remote, bucket) = bucket_of(&target)?;
            let bytes = parse_size(&size)?;
            let client = make_client(&remote.alias).await?;
            let mut cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            cfg.quota_bytes = Some(bytes);
            let cfg = crate::ops::buckets::set_config(&client, &bucket, &cfg).await?;
            if mode == OutputMode::Json {
                print_json(
                    &serde_json::json!({ "bucket": target, "quota_bytes": cfg.quota_bytes }),
                );
            } else {
                println!("Quota for {target} set to {}", fmt_bytes(bytes));
            }
        }
        QuotaCmd::Clear { target } => {
            let (remote, bucket) = bucket_of(&target)?;
            let client = make_client(&remote.alias).await?;
            let mut cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            cfg.quota_bytes = None;
            crate::ops::buckets::set_config(&client, &bucket, &cfg).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "bucket": target, "quota_bytes": null }));
            } else {
                println!("Quota cleared for {target}");
            }
        }
        QuotaCmd::Info { target } => {
            let (remote, bucket) = bucket_of(&target)?;
            let client = make_client(&remote.alias).await?;
            let cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            if mode == OutputMode::Json {
                print_json(
                    &serde_json::json!({ "bucket": target, "quota_bytes": cfg.quota_bytes }),
                );
            } else {
                match cfg.quota_bytes {
                    Some(b) => println!("{target}: quota {}", fmt_bytes(b)),
                    None => println!("{target}: no quota set"),
                }
            }
        }
    }
    Ok(())
}

pub async fn run_encrypt(cmd: EncryptCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        EncryptCmd::Set { target, algo } => {
            let (remote, bucket) = bucket_of(&target)?;
            let algo = algo.unwrap_or_else(|| "aes256-gcm".to_owned());
            let client = make_client(&remote.alias).await?;
            let mut cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            cfg.default_sse = Some(algo.clone());
            crate::ops::buckets::set_config(&client, &bucket, &cfg).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "bucket": target, "default_sse": algo }));
            } else {
                println!(
                    "Default SSE for {target} recorded as `{algo}` (note: y2q always encrypts; this is informational)"
                );
            }
        }
        EncryptCmd::Info { target } => {
            let (remote, bucket) = bucket_of(&target)?;
            let client = make_client(&remote.alias).await?;
            let cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            if mode == OutputMode::Json {
                print_json(
                    &serde_json::json!({ "bucket": target, "default_sse": cfg.default_sse }),
                );
            } else {
                match cfg.default_sse {
                    Some(a) => println!("{target}: default SSE `{a}`"),
                    None => println!(
                        "{target}: no default SSE configured (objects encrypted regardless)"
                    ),
                }
            }
        }
        EncryptCmd::Clear { target } => {
            let (remote, bucket) = bucket_of(&target)?;
            let client = make_client(&remote.alias).await?;
            let mut cfg = crate::ops::buckets::get_config(&client, &bucket).await?;
            cfg.default_sse = None;
            crate::ops::buckets::set_config(&client, &bucket, &cfg).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "bucket": target, "default_sse": null }));
            } else {
                println!("Default SSE cleared for {target}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("100").unwrap(), 100);
        assert_eq!(parse_size("100B").unwrap(), 100);
        assert_eq!(parse_size("1K").unwrap(), 1_000);
        assert_eq!(parse_size("1KiB").unwrap(), 1_024);
        assert_eq!(parse_size("2 MB").unwrap(), 2_000_000);
        assert_eq!(parse_size("1Mi").unwrap(), 1_048_576);
        assert_eq!(parse_size("3GB").unwrap(), 3_000_000_000);
        assert_eq!(parse_size("1GiB").unwrap(), 1_073_741_824);
        assert_eq!(parse_size("1TB").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_size("1TiB").unwrap(), 1_024u64.pow(4));
    }

    #[test]
    fn parse_size_rejects_bad() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("12XY").is_err());
        assert!(parse_size("").is_err());
    }

    #[test]
    fn parse_size_saturates_on_overflow() {
        // 1e19 fits in u64 but * 1 TiB overflows -> saturates to u64::MAX.
        assert_eq!(parse_size("10000000000000000000TiB").unwrap(), u64::MAX);
        // A value too large for u64 itself is a parse error, not a saturation.
        assert!(parse_size("99999999999999999999").is_err());
    }

    #[test]
    fn bucket_of_parses_alias_bucket() {
        let (_, bucket) = bucket_of("alias/mybucket").unwrap();
        assert_eq!(bucket, "mybucket");
    }

    #[test]
    fn bucket_of_rejects_missing_bucket_or_with_key() {
        assert!(bucket_of("alias").is_err());
        assert!(bucket_of("alias/bucket/key").is_err());
    }
}
