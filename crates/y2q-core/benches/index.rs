//! Microbenchmarks for the redb-backed [`MetadataIndex`].
//!
//! Measures single-upsert latency, point-lookup latency, and full-bucket scan
//! time as the index grows from 100 to 10 000 rows. All three operations are
//! exercised without a MEK so results reflect plaintext key encoding; the
//! encrypted path adds one HMAC per string field (negligible vs. redb I/O).
//!
//! ## Running
//!
//! ```bash
//! cargo bench -p y2q-core --bench index
//! ```

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use y2q_core::{Metadata, MetadataIndex};

fn make_meta(bucket: &str, key: &str) -> Metadata {
    Metadata {
        created: 0,
        modified: 0,
        size: 4096,
        checksum_md5: "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
        checksum_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        disk_path: PathBuf::from("/tmp/dummy"),
        url_path: format!("{bucket}/{key}"),
        labels: BTreeMap::new(),
        cipher_size: None,
        cipher_sha256: None,
        kem_alg: None,
        aead_alg: None,
        envelope_version: None,
    }
}

fn open_index() -> (MetadataIndex, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let idx = MetadataIndex::open(&dir.path().join("idx.redb")).unwrap();
    (idx, dir)
}

fn populate(rt: &Runtime, idx: &MetadataIndex, bucket: &str, n: usize) {
    for i in 0..n {
        let key = format!("key-{i:08}");
        rt.block_on(idx.upsert(&make_meta(bucket, &key))).unwrap();
    }
}

fn bench_upsert(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let mut group = c.benchmark_group("index_upsert");

    for n in [100usize, 1_000, 10_000] {
        let (idx, _dir) = open_index();
        populate(&rt, &idx, "bench", n);

        let seq = Arc::new(std::sync::atomic::AtomicUsize::new(n));
        let rt_outer = Arc::clone(&rt);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, move |b, _| {
            b.to_async(&*rt_outer).iter(|| {
                let idx = idx.clone();
                let i = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let key = format!("key-{i:08}");
                async move { idx.upsert(&make_meta("bench", &key)).await.unwrap() }
            });
        });
    }
    group.finish();
}

fn bench_lookup(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let mut group = c.benchmark_group("index_lookup");

    for n in [100usize, 1_000, 10_000] {
        let (idx, _dir) = open_index();
        populate(&rt, &idx, "bench", n);
        let target = format!("key-{:08}", n / 2);
        let rt_outer = Arc::clone(&rt);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, move |b, _| {
            b.to_async(&*rt_outer).iter(|| {
                let idx = idx.clone();
                let key = target.clone();
                async move { idx.lookup_by_key("bench", &key).await.unwrap() }
            });
        });
    }
    group.finish();
}

fn bench_scan(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let mut group = c.benchmark_group("index_scan");

    for n in [100usize, 1_000, 10_000] {
        if n >= 10_000 {
            group.sample_size(20);
        }
        let (idx, _dir) = open_index();
        populate(&rt, &idx, "bench", n);
        let rt_outer = Arc::clone(&rt);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, move |b, _n| {
            b.to_async(&*rt_outer).iter(|| {
                let idx = idx.clone();
                async move { idx.scan_objects("bench", None, None, *_n).await.unwrap() }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_upsert, bench_lookup, bench_scan);
criterion_main!(benches);
