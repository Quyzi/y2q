use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;
use rand::SeedableRng;
use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::config::{MixedWeights, RunConfig};
use crate::generator::ObjectPool;
use crate::metrics::OpRecord;
use crate::ops::{OpKind, delete, get, list, put, stat};

pub async fn run_worker(
    config: Arc<RunConfig>,
    client: y2q_client::Y2qClient,
    raw_http: reqwest::Client,
    token_rx: watch::Receiver<Zeroizing<String>>,
    tx: mpsc::Sender<OpRecord>,
    shutdown: watch::Receiver<bool>,
    put_seq: Arc<AtomicU64>,
    pool: Option<Arc<ObjectPool>>,
) {
    let mut client = client;
    let shutdown = shutdown;
    let mut rng = StdRng::from_entropy();

    loop {
        // Check shutdown
        if *shutdown.borrow() {
            break;
        }

        // Update token if refreshed
        if token_rx.has_changed().unwrap_or(false) {
            let tok = token_rx.borrow().clone();
            client.set_token(tok.as_str());
        }

        let Some(record) = execute_op(
            &config,
            &client,
            &raw_http,
            &token_rx,
            &put_seq,
            pool.as_deref(),
            &mut rng,
        )
        .await
        else {
            // Pool was empty for this op kind; yield and retry.
            tokio::task::yield_now().await;
            continue;
        };

        if tx.send(record).await.is_err() {
            break;
        }
    }
}

async fn execute_op(
    config: &RunConfig,
    client: &y2q_client::Y2qClient,
    raw_http: &reqwest::Client,
    token_rx: &watch::Receiver<Zeroizing<String>>,
    put_seq: &AtomicU64,
    pool: Option<&ObjectPool>,
    rng: &mut impl Rng,
) -> Option<OpRecord> {
    let op = pick_op(
        &config.workload.op,
        config.workload.mixed_weights.as_ref(),
        rng,
    );
    let bucket = &config.bucket;
    let run_id = &config.workload.run_id;

    Some(match op {
        OpKind::Put => {
            let seq = put_seq.fetch_add(1, Ordering::Relaxed);
            let key = format!("warp/{run_id}/{seq:08}");
            let size = config.obj_size.sample(rng);
            let rec = put::put_op(client, bucket, &key, size, run_id).await;
            if rec.error.is_none() {
                if let Some(p) = pool {
                    p.on_put_success(key).await;
                }
            }
            rec
        }
        OpKind::Get => {
            let key = match pool {
                Some(p) => match p.pick_for_get().await {
                    Some(k) => k,
                    None => return None,
                },
                None => return None,
            };
            let token = token_rx.borrow().clone();
            get::get_op(
                raw_http,
                &config.base_url,
                token.as_str(),
                bucket,
                &key,
                run_id,
            )
            .await
        }
        OpKind::Delete => {
            let key = match pool {
                Some(p) => match p.take_for_delete().await {
                    Some(k) => k,
                    None => return None,
                },
                None => return None,
            };
            let rec = delete::delete_op(client, bucket, &key, run_id).await;
            if rec.error.is_some() {
                if let Some(p) = pool {
                    p.return_key(key).await;
                }
            }
            rec
        }
        OpKind::Stat => {
            let key = match pool {
                Some(p) => match p.pick_for_get().await {
                    Some(k) => k,
                    None => return None,
                },
                None => return None,
            };
            stat::stat_op(client, bucket, &key, run_id).await
        }
        OpKind::List => list::list_op(client, bucket, run_id).await,
    })
}

fn pick_op(op: &OpKind, weights: Option<&MixedWeights>, rng: &mut impl Rng) -> OpKind {
    if *op != OpKind::Put || weights.is_some() {
        if let Some(w) = weights {
            let ops = [OpKind::Get, OpKind::Put, OpKind::Delete, OpKind::Stat];
            let ws = [w.get, w.put, w.delete, w.stat];
            let dist = WeightedIndex::new(ws).expect("valid weights");
            return ops[dist.sample(rng)];
        }
    }
    *op
}
