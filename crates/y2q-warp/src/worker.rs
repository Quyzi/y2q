use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;
use rand::distr::Distribution;
use rand::distr::weighted::WeightedIndex;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::config::{MixedWeights, RunConfig};
use crate::generator::ObjectPool;
use crate::metrics::OpRecord;
use crate::ops::{OpKind, delete, get, list, put, stat};

/// One worker is pinned to one cluster node (round-robin assigned by the caller).
/// `node_url` is that node's base URL (used for the raw GET path) and `node_label`
/// tags each record so per-node latency can be analyzed alongside the aggregate.
#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    config: Arc<RunConfig>,
    client: y2q_client::Y2qClient,
    raw_http: reqwest::Client,
    token_rx: watch::Receiver<Zeroizing<String>>,
    tx: mpsc::Sender<OpRecord>,
    shutdown: watch::Receiver<bool>,
    put_seq: Arc<AtomicU64>,
    pool: Option<Arc<ObjectPool>>,
    node_url: String,
    node_label: String,
) {
    let mut client = client;
    let shutdown = shutdown;
    let mut rng: StdRng = rand::make_rng();

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

        let Some(mut record) = execute_op(
            &config,
            &client,
            &raw_http,
            &node_url,
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

        record.node = node_label.clone();
        if tx.send(record).await.is_err() {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_op(
    config: &RunConfig,
    client: &y2q_client::Y2qClient,
    raw_http: &reqwest::Client,
    node_url: &str,
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
            if rec.error.is_none()
                && let Some(p) = pool
            {
                p.on_put_success(key).await;
            }
            rec
        }
        OpKind::Get => {
            let p = pool?;
            let key = p.pick_for_get().await?;
            let token = token_rx.borrow().clone();
            let rec = get::get_op(raw_http, node_url, token.as_str(), bucket, &key, run_id).await;
            p.release_read(&key).await;
            rec
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
            if rec.error.is_some()
                && let Some(p) = pool
            {
                p.return_key(key).await;
            }
            rec
        }
        OpKind::Stat => {
            let p = pool?;
            let key = p.pick_for_get().await?;
            let rec = stat::stat_op(client, bucket, &key, run_id).await;
            p.release_read(&key).await;
            rec
        }
        OpKind::List => list::list_op(client, bucket, run_id).await,
    })
}

fn pick_op(op: &OpKind, weights: Option<&MixedWeights>, rng: &mut impl Rng) -> OpKind {
    if (*op != OpKind::Put || weights.is_some())
        && let Some(w) = weights
    {
        let ops = [OpKind::Get, OpKind::Put, OpKind::Delete, OpKind::Stat];
        let ws = [w.get, w.put, w.delete, w.stat];
        let dist = WeightedIndex::new(ws).expect("valid weights");
        return ops[dist.sample(rng)];
    }
    *op
}
