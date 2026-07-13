//! Microbenchmarks for the y2q-core crypto hot path.
//!
//! Covers the isolated primitives called on every PUT (KEM encap, HKDF, AES-GCM
//! encrypt) and every GET (KEM decap, HKDF, AES-GCM decrypt), plus full v2
//! (chunked) envelope round-trips at typical object sizes to show combined
//! cost. The v2 envelope streams to a [`StreamingSink`], so unlike the
//! isolated-primitive benchmarks above, the envelope round-trip numbers
//! include temp-file I/O, not crypto alone.
//!
//! ## Running
//!
//! ```bash
//! cargo bench -p y2q-core --bench crypto
//! ```

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hkdf::Hkdf;
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait,
};
use rand::Rng;
use sha2::Sha256;
use std::hint::black_box;
use y2q_core::crypto::envelope::{DEFAULT_CHUNK_SIZE_BYTES, EncryptSession, decrypt};
use y2q_core::storage::streaming_sink::StreamingSink;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const HKDF_INFO: &[u8] = b"y2q/v1/content-key";

fn bench_kem_encap(c: &mut Criterion) {
    let (pk, _sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();

    c.bench_function("kem_encap", |b| {
        b.iter(|| {
            let pk = mlkem768::PublicKey::from_bytes(black_box(&pk_bytes)).unwrap();
            let (ss, ct) = mlkem768::encapsulate(&pk);
            black_box((ss, ct));
        });
    });
}

fn bench_kem_decap(c: &mut Criterion) {
    let (pk, sk) = mlkem768::keypair();
    let sk_bytes = sk.as_bytes().to_vec();
    let (_ss, kem_ct) = mlkem768::encapsulate(&pk);
    let kem_ct_bytes = kem_ct.as_bytes().to_vec();

    c.bench_function("kem_decap", |b| {
        b.iter(|| {
            let sk = mlkem768::SecretKey::from_bytes(black_box(&sk_bytes)).unwrap();
            let ct = mlkem768::Ciphertext::from_bytes(black_box(&kem_ct_bytes)).unwrap();
            let ss = mlkem768::decapsulate(&ct, &sk);
            black_box(ss);
        });
    });
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let mut ss = [0u8; 32];
    let mut salt = [0u8; 1088]; // same length as ML-KEM-768 ciphertext
    rand::rng().fill_bytes(&mut ss);
    rand::rng().fill_bytes(&mut salt);

    c.bench_function("hkdf_derive", |b| {
        b.iter(|| {
            let hk = Hkdf::<Sha256>::new(Some(black_box(&salt)), black_box(&ss));
            let mut key = [0u8; 32];
            hk.expand(HKDF_INFO, &mut key).unwrap();
            black_box(key);
        });
    });
}

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut key_bytes);
    rand::rng().fill_bytes(&mut nonce_bytes);
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("aes_gcm_encrypt");
    for size in [4 * KIB, 256 * KIB, MIB] {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let cipher = Aes256Gcm::new((&key_bytes).into());
            let nonce = &aes_gcm::Nonce::from(nonce_bytes);
            b.iter(|| {
                let ct = cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: black_box(&plaintext),
                            aad,
                        },
                    )
                    .unwrap();
                black_box(ct);
            });
        });
    }
    group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut key_bytes);
    rand::rng().fill_bytes(&mut nonce_bytes);
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("aes_gcm_decrypt");
    for size in [4 * KIB, 256 * KIB, MIB] {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0u8; size];

        let cipher = Aes256Gcm::new((&key_bytes).into());
        let nonce = &aes_gcm::Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let cipher = Aes256Gcm::new((&key_bytes).into());
            let nonce = &aes_gcm::Nonce::from(nonce_bytes);
            b.iter(|| {
                let pt = cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: black_box(&ciphertext),
                            aad,
                        },
                    )
                    .unwrap();
                black_box(pt);
            });
        });
    }
    group.finish();
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
}

async fn tempfile_sink() -> (std::path::PathBuf, StreamingSink) {
    let path = std::env::temp_dir().join(format!("y2q_bench_{}.env", rand_u64()));
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .await
        .unwrap();
    (path, StreamingSink::Tokio(file))
}

async fn read_and_remove(path: &std::path::Path, sink: StreamingSink) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let StreamingSink::Tokio(mut f) = sink else {
        unreachable!("bench sinks are always Tokio-backed")
    };
    f.seek(std::io::SeekFrom::Start(0)).await.unwrap();
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).await.unwrap();
    drop(f);
    let _ = tokio::fs::remove_file(path).await;
    buf
}

fn bench_envelope_v2_encrypt(c: &mut Criterion) {
    let (pk, _sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("envelope_v2_encrypt");
    for size in [MIB, 16 * MIB] {
        if size >= 16 * MIB {
            group.sample_size(10);
        }
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xABu8; size];

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let (path, sink) = tempfile_sink().await;
                let mut session = EncryptSession::new(
                    sink,
                    black_box(&pk_bytes),
                    "bucket",
                    "key",
                    0,
                    DEFAULT_CHUNK_SIZE_BYTES,
                )
                .await
                .unwrap();
                session.feed(black_box(&plaintext)).await.unwrap();
                let (sink, info) = session.finish().await.unwrap();
                drop(sink);
                let _ = tokio::fs::remove_file(&path).await;
                black_box(info);
            });
        });
    }
    group.finish();
}

fn bench_envelope_v2_decrypt(c: &mut Criterion) {
    let (pk, sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("envelope_v2_decrypt");
    for size in [MIB, 16 * MIB] {
        if size >= 16 * MIB {
            group.sample_size(10);
        }
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xABu8; size];
        let envelope = rt.block_on(async {
            let (path, sink) = tempfile_sink().await;
            let mut session = EncryptSession::new(
                sink,
                &pk_bytes,
                "bucket",
                "key",
                0,
                DEFAULT_CHUNK_SIZE_BYTES,
            )
            .await
            .unwrap();
            session.feed(&plaintext).await.unwrap();
            let (sink, _) = session.finish().await.unwrap();
            read_and_remove(&path, sink).await
        });

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let pt =
                    decrypt(black_box(&sk_bytes), black_box(&envelope), "bucket", "key").unwrap();
                black_box(pt);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_kem_encap,
    bench_kem_decap,
    bench_hkdf_derive,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_envelope_v2_encrypt,
    bench_envelope_v2_decrypt,
);
criterion_main!(benches);
