//! Throughput benchmarks for [`y2q_core::FilesystemStorage`] and
//! [`y2q_core::UringStorage`].
//!
//! Both backends are exercised via `AnyStorage` so the same per-iteration
//! body works for either. The uring variant is `#[cfg]`-gated on
//! `target_os = "linux" + feature = "uring"` — without the feature flag,
//! only the filesystem backend is benched.
//!
//! ## Running
//!
//! ```bash
//! # Default sweep ({1 KiB, 1 MiB, 16 MiB}; ~tens of seconds)
//! cargo bench --features uring -p y2q-core
//!
//! # Full sweep from the plan ({1 KiB, 1 MiB, 256 MiB, 2 GiB}; minutes)
//! Y2Q_BENCH_FULL=1 cargo bench --features uring -p y2q-core
//!
//! # Point at a specific disk for clean perf numbers
//! Y2Q_BENCH_PATH=/mnt/nvme/y2q-bench cargo bench --features y2qd/uring -p y2q-core
//! ```
//!
//! Scratch dirs default to `$WORKSPACE/target/y2q-bench-tmp/<rand>/` and
//! are removed when the bench process exits (TempDir drop).

use bytes::Bytes;
use core::range::RangeInclusive;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{path::PathBuf, sync::{Arc, OnceLock}, time::Duration};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use y2q_core::{AnyStorage, FilesystemStorage, Object, PutOptions, Storage, SyncLevel};

#[cfg(all(target_os = "linux", feature = "uring"))]
use y2q_core::{UringStorage, storage::uring::UringConfig};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// Object size sweep for `put`/`get` benches. Defaults to a cheap mix; set
/// `Y2Q_BENCH_FULL=1` to run the larger sizes from the plan.
fn sizes() -> Vec<usize> {
    if std::env::var_os("Y2Q_BENCH_FULL").is_some() {
        vec![KIB, MIB, 256 * MIB, 2 * 1024 * MIB]
    } else {
        vec![KIB, MIB, 16 * MIB]
    }
}

/// Locate a disk-backed scratch directory. `Y2Q_BENCH_PATH` overrides;
/// otherwise the workspace `target/y2q-bench-tmp/`.
fn scratch_dir() -> TempDir {
    let parent: PathBuf = std::env::var_os("Y2Q_BENCH_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target")
                .join("y2q-bench-tmp")
        });
    std::fs::create_dir_all(&parent).expect("create bench scratch parent");
    tempfile::Builder::new()
        .prefix("y2q-bench-")
        .tempdir_in(&parent)
        .expect("tempdir_in scratch parent")
}

/// One backend ready for benching. `_dir` is held to keep the scratch
/// directory alive for the entire bench process lifetime.
struct Backend {
    name: &'static str,
    storage: Arc<AnyStorage>,
    _dir: TempDir,
}

// Safety: TempDir is Send+Sync; AnyStorage is Send+Sync via Arc.
unsafe impl Sync for Backend {}

static BACKENDS: OnceLock<Vec<Backend>> = OnceLock::new();

/// Return the shared set of backends, initialising it once.
///
/// All bench functions share one set to avoid spinning up duplicate uring
/// worker pools (each pool pins locked memory for its io_uring rings).
fn backends() -> &'static [Backend] {
    BACKENDS.get_or_init(|| {
        let mut out = Vec::new();

        let fs_dir = scratch_dir();
        let fs_base = fs_dir.path().to_path_buf();
        let fs = FilesystemStorage::new(&fs_base, fs_base.join("idx.redb"))
            .expect("init FilesystemStorage");
        out.push(Backend {
            name: "filesystem",
            storage: Arc::new(AnyStorage::Filesystem(fs)),
            _dir: fs_dir,
        });

        #[cfg(all(target_os = "linux", feature = "uring"))]
        {
            let u_dir = scratch_dir();
            let u_base = u_dir.path().to_path_buf();
            let u = UringStorage::new(&u_base, u_base.join("idx.redb"), UringConfig::default())
                .expect("init UringStorage");
            out.push(Backend {
                name: "uring",
                storage: Arc::new(AnyStorage::Uring(u)),
                _dir: u_dir,
            });
        }

        out
    })
}

/// Tighten criterion's sample budget for sizes that take long enough per
/// iteration that the default 100-sample / 5s window can't fit them.
fn configure_for_size(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    size: usize,
) {
    if size >= 64 * MIB {
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(30));
    }
}

fn bench_put(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let backends = backends();
    let mut group = c.benchmark_group("put");

    for size in sizes() {
        group.throughput(Throughput::Bytes(size as u64));
        configure_for_size(&mut group, size);
        let body = Bytes::from(vec![0u8; size]);

        for backend in backends {
            // Overwrite the same key on every iteration. Keeps disk usage
            // bounded (~one file per (backend, size)) at the cost of a tiny
            // overwrite-path read overhead — the same on both backends, so
            // the comparison stays fair.
            let key = format!("k-{size}");
            let storage = Arc::clone(&backend.storage);
            let body_outer = body.clone();
            let rt_outer = Arc::clone(&rt);

            group.bench_with_input(BenchmarkId::new(backend.name, size), &size, move |b, _| {
                b.to_async(&*rt_outer).iter(|| {
                    let storage = Arc::clone(&storage);
                    let body = body_outer.clone();
                    let key = key.clone();
                    async move {
                        storage
                            .put("bench", &key, Object::new(body), PutOptions::default())
                            .await
                            .expect("put");
                    }
                });
            });
        }
    }
    group.finish();
}

fn bench_put_best_effort(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let backends = backends();
    let mut group = c.benchmark_group("put_best_effort");

    for size in sizes() {
        group.throughput(Throughput::Bytes(size as u64));
        configure_for_size(&mut group, size);
        let body = Bytes::from(vec![0u8; size]);

        for backend in backends {
            let key = format!("k-be-{size}");
            let storage = Arc::clone(&backend.storage);
            let body_outer = body.clone();
            let rt_outer = Arc::clone(&rt);

            group.bench_with_input(BenchmarkId::new(backend.name, size), &size, move |b, _| {
                b.to_async(&*rt_outer).iter(|| {
                    let storage = Arc::clone(&storage);
                    let body = body_outer.clone();
                    let key = key.clone();
                    async move {
                        storage
                            .put(
                                "bench",
                                &key,
                                Object::new(body),
                                PutOptions {
                                    sync: SyncLevel::BestEffort,
                                    ..PutOptions::default()
                                },
                            )
                            .await
                            .expect("put");
                    }
                });
            });
        }
    }
    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let rt = Arc::new(Runtime::new().unwrap());
    let backends = backends();
    let mut group = c.benchmark_group("get");

    for size in sizes() {
        group.throughput(Throughput::Bytes(size as u64));
        configure_for_size(&mut group, size);
        let body = Bytes::from(vec![0u8; size]);

        for backend in backends {
            let key = format!("k-{size}");
            // Pre-populate one object per (backend, size).
            rt.block_on(backend.storage.put(
                "bench",
                &key,
                Object::new(body.clone()),
                PutOptions::default(),
            ))
            .expect("pre-populate");

            let storage = Arc::clone(&backend.storage);
            let rt_outer = Arc::clone(&rt);
            group.bench_with_input(BenchmarkId::new(backend.name, size), &size, move |b, _| {
                b.to_async(&*rt_outer).iter(|| {
                    let storage = Arc::clone(&storage);
                    let key = key.clone();
                    async move {
                        let _ = storage.get("bench", &key).await.expect("get");
                    }
                });
            });
        }
    }
    group.finish();
}

fn bench_get_range(c: &mut Criterion) {
    // Tests the random-slice path against a fixed object size, varying nothing
    // but the backend. 4 KiB slice from a 16 MiB object — small enough that
    // syscall + decode overhead dominates, big enough to be one aligned read.
    let rt = Arc::new(Runtime::new().unwrap());
    let backends = backends();
    let object_size = 16 * MIB;
    let slice_len = 4 * KIB;
    let body = Bytes::from(vec![0u8; object_size]);

    let mut group = c.benchmark_group("get_range");
    group.throughput(Throughput::Bytes(slice_len as u64));

    for backend in backends {
        rt.block_on(backend.storage.put(
            "bench",
            "rng",
            Object::new(body.clone()),
            PutOptions::default(),
        ))
        .expect("pre-populate");

        let storage = Arc::clone(&backend.storage);
        let rt_outer = Arc::clone(&rt);
        group.bench_function(backend.name, move |b| {
            // Walk a sliding window so the bench doesn't all hit the same
            // page-cache-warm offset; modular so we never go past EOF.
            let stride = slice_len as u64;
            let upper = (object_size - slice_len) as u64;
            let start = Arc::new(std::sync::atomic::AtomicU64::new(0));
            b.to_async(&*rt_outer).iter(|| {
                let storage = Arc::clone(&storage);
                let s = start.fetch_add(stride, std::sync::atomic::Ordering::Relaxed) % upper;
                let r = RangeInclusive {
                    start: s,
                    last: s + (slice_len as u64) - 1,
                };
                async move {
                    let _ = storage
                        .get_range("bench", "rng", r)
                        .await
                        .expect("get_range");
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_put, bench_put_best_effort, bench_get, bench_get_range);
criterion_main!(benches);
