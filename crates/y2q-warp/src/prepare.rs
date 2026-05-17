use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use y2q_client::{ListOptions, Y2qClient};

use crate::config::ObjSize;
use crate::display::DisplayMsg;
use crate::error::WarpError;
use crate::generator::BoundedRepeatReader;

pub async fn prepare(
    client: &Y2qClient,
    bucket: &str,
    run_id: &str,
    objects: u32,
    obj_size: &ObjSize,
    concurrent: usize,
    progress_tx: Option<mpsc::Sender<DisplayMsg>>,
) -> Result<Vec<String>, WarpError> {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrent.min(64)));
    let prepared = Arc::new(AtomicU32::new(0));
    let progress_tx = Arc::new(progress_tx);
    let mut tasks: JoinSet<Result<String, String>> = JoinSet::new();
    let mut rng = rand::thread_rng();

    for n in 0..objects {
        let key = format!("warp/{run_id}/{n:08}");
        let size = obj_size.sample(&mut rng);
        let client = client.clone();
        let bucket = bucket.to_owned();
        let sem = sem.clone();
        let prepared = prepared.clone();
        let progress_tx = progress_tx.clone();
        let key_clone = key.clone();

        tasks.spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            use std::collections::BTreeMap;
            let reader = BoundedRepeatReader::new(size);
            client
                .put_from_reader(&bucket, &key_clone, reader, Some(size), &BTreeMap::new(), None)
                .await
                .map_err(|e| e.to_string())?;
            let done = prepared.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(ref tx) = *progress_tx {
                let _ = tx.try_send(DisplayMsg::Preparing { done, total: objects });
            } else if done % 100 == 0 || done == objects {
                eprintln!("  prepared {done}/{objects} objects");
            }
            Ok(key_clone)
        });
    }

    let mut keys = Vec::with_capacity(objects as usize);
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(key)) => keys.push(key),
            Ok(Err(e)) => eprintln!("  prepare error: {e}"),
            Err(e) => eprintln!("  prepare task panicked: {e}"),
        }
    }

    if progress_tx.is_none() {
        eprintln!("prepare complete: {} objects in bucket {bucket}", keys.len());
    }
    Ok(keys)
}

pub async fn cleanup(
    client: &Y2qClient,
    bucket: &str,
    prefix: &str,
    concurrent: usize,
) -> Result<u64, WarpError> {
    eprintln!("cleaning up objects with prefix {prefix} in bucket {bucket}...");
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrent.min(64)));
    let mut deleted = 0u64;
    let mut after = None;

    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions { prefix: Some(prefix.to_owned()), after: after.clone(), limit: Some(1000) },
            )
            .await?;

        if page.items.is_empty() {
            break;
        }

        let mut tasks: JoinSet<bool> = JoinSet::new();
        for item in &page.items {
            let client = client.clone();
            let bucket = bucket.to_owned();
            let key = item.key.clone();
            let sem = sem.clone();
            tasks.spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                client.delete(&bucket, &key).await.is_ok()
            });
        }

        while let Some(res) = tasks.join_next().await {
            if res.unwrap_or(false) {
                deleted += 1;
            }
        }

        after = page.next;
        if after.is_none() {
            break;
        }
    }

    eprintln!("cleanup complete: {deleted} objects removed");
    Ok(deleted)
}
