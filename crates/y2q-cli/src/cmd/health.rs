//! `ping` and `ready` — liveness/readiness probes.
//!
//! `ping` repeats a cheap authenticated GET against the alias root (the
//! `list_buckets` endpoint) and prints per-request timing. `ready` is a single
//! ping whose exit status reflects success.

use std::time::{Duration, Instant};

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};

pub async fn ping(
    alias: &str,
    count: u32,
    interval_ms: u64,
    error_only: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let client = make_client(alias).await?;
    let mut ok = 0u32;
    let mut errs = 0u32;
    let mut total_latency = Duration::ZERO;
    let mut min_latency: Option<Duration> = None;
    let mut max_latency: Option<Duration> = None;

    for i in 1..=count {
        let start = Instant::now();
        let result = client.list_buckets().await;
        let latency = start.elapsed();
        let success = result.is_ok();
        if success {
            ok += 1;
            total_latency += latency;
            min_latency = Some(min_latency.map_or(latency, |m| m.min(latency)));
            max_latency = Some(max_latency.map_or(latency, |m| m.max(latency)));
        } else {
            errs += 1;
        }

        if !error_only || !success {
            let latency_ms = latency.as_secs_f64() * 1000.0;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "seq": i,
                    "alias": alias,
                    "ok": success,
                    "latency_ms": latency_ms,
                    "error": result.as_ref().err().map(|e| e.to_string()),
                }));
            } else {
                let status = match &result {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("ERR: {e}"),
                };
                println!("{alias} seq={i} latency={latency_ms:.2}ms {status}");
            }
        }

        if i < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    let avg_ms = if ok > 0 {
        (total_latency.as_secs_f64() * 1000.0) / ok as f64
    } else {
        0.0
    };
    let min_ms = min_latency.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0);
    let max_ms = max_latency.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0);

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "alias": alias,
            "sent": count,
            "ok": ok,
            "err": errs,
            "min_ms": min_ms,
            "avg_ms": avg_ms,
            "max_ms": max_ms,
        }));
    } else {
        println!(
            "--- {alias} ping statistics ---\n{count} sent, {ok} ok, {errs} err — min/avg/max = {min_ms:.2}/{avg_ms:.2}/{max_ms:.2} ms"
        );
    }

    if errs > 0 {
        return Err(CliError::Other(format!("{errs}/{count} ping(s) failed")));
    }
    Ok(())
}

pub async fn ready(alias: &str, mode: OutputMode) -> Result<(), CliError> {
    let client = make_client(alias).await?;
    match crate::ops::health::probe(&client).await {
        Ok(latency) => {
            let latency_ms = latency.as_secs_f64() * 1000.0;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "alias": alias,
                    "ready": true,
                    "latency_ms": latency_ms,
                }));
            } else {
                println!("{alias}: ready ({latency_ms:.2}ms)");
            }
            Ok(())
        }
        Err(e) => {
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "alias": alias,
                    "ready": false,
                    "error": e.to_string(),
                }));
            } else {
                println!("{alias}: NOT ready — {e}");
            }
            Err(CliError::Client(e))
        }
    }
}
