//! Microbenchmarks for the y2q-core crypto hot path.
//!
//! Covers the isolated primitives called on every PUT (KEM encap, HKDF, AES-GCM
//! encrypt) and every GET (KEM decap, HKDF, AES-GCM decrypt), plus full v1
//! envelope round-trips at typical object sizes to show combined cost.
//!
//! v2 (chunked streaming) uses the same KEM/HKDF/AES-GCM primitives as v1 —
//! only the I/O path differs. Isolating I/O from crypto is the purpose of these
//! microbenchmarks, so v1 is the representative proxy here.
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
use rand::RngCore;
use sha2::Sha256;
use std::hint::black_box;
use y2q_core::crypto::envelope::{decrypt, encrypt};

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
    rand::rngs::OsRng.fill_bytes(&mut ss);
    rand::rngs::OsRng.fill_bytes(&mut salt);

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
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("aes_gcm_encrypt");
    for size in [4 * KIB, 256 * KIB, MIB] {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0u8; size];

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let cipher = Aes256Gcm::new((&key_bytes).into());
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            b.iter(|| {
                let ct = cipher
                    .encrypt(nonce, Payload { msg: black_box(&plaintext), aad })
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
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let aad = b"bench-aad";

    let mut group = c.benchmark_group("aes_gcm_decrypt");
    for size in [4 * KIB, 256 * KIB, MIB] {
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0u8; size];

        let cipher = Aes256Gcm::new((&key_bytes).into());
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &plaintext, aad })
            .unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let cipher = Aes256Gcm::new((&key_bytes).into());
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            b.iter(|| {
                let pt = cipher
                    .decrypt(nonce, Payload { msg: black_box(&ciphertext), aad })
                    .unwrap();
                black_box(pt);
            });
        });
    }
    group.finish();
}

fn bench_envelope_v1_encrypt(c: &mut Criterion) {
    let (pk, _sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();

    let mut group = c.benchmark_group("envelope_v1_encrypt");
    for size in [MIB, 16 * MIB] {
        if size >= 16 * MIB {
            group.sample_size(10);
        }
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xABu8; size];

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let (env, info) = encrypt(black_box(&pk_bytes), black_box(&plaintext)).unwrap();
                black_box((env, info));
            });
        });
    }
    group.finish();
}

fn bench_envelope_v1_decrypt(c: &mut Criterion) {
    let (pk, sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();

    let mut group = c.benchmark_group("envelope_v1_decrypt");
    for size in [MIB, 16 * MIB] {
        if size >= 16 * MIB {
            group.sample_size(10);
        }
        group.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0xABu8; size];
        let (envelope, _) = encrypt(&pk_bytes, &plaintext).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let pt = decrypt(black_box(&sk_bytes), black_box(&envelope)).unwrap();
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
    bench_envelope_v1_encrypt,
    bench_envelope_v1_decrypt,
);
criterion_main!(benches);
