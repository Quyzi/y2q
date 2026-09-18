//! Regression proof for session identity-key residency.
//!
//! `y2qd` is a binary-only crate (no library target), so this lives as an
//! in-process test module rather than a `tests/` integration binary — the
//! technique (self-scan every readable, private, non-file-backed region of
//! `/proc/self/mem` for a needle byte pattern) is identical either way,
//! since it only cares about this process's own address space.
//!
//! Pre-fix (a session row holding `Zeroizing<Vec<u8>>` directly), this test
//! fails: the identity key sits in the `DashMap` row in plaintext. Post-fix
//! (the row holds [`y2q_core::secmem::SealedSecret`] ciphertext), it passes.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use y2q_core::crypto::Role;
use y2q_core::secmem::SecretVec;
use zeroize::Zeroize;

use crate::auth::session::{NewSession, SessionStore};

/// Length of the needle pattern scanned for. Large enough that a chance
/// collision in unrelated heap data is astronomically unlikely.
const NEEDLE_LEN: usize = 2400;

/// Deterministic, recomputed-on-the-fly needle byte at position `i`. Never
/// materialized as a standalone comparison buffer — the scanner recomputes
/// it inline so there is no second live copy of the needle anywhere for it
/// to trivially "find".
fn expected(i: usize) -> u8 {
    (i as u8).wrapping_mul(37) ^ 0xA5
}

/// Serializes the two tests below: both scan the *whole* process's memory,
/// so they must not run concurrently with each other (the positive
/// control's still-live needle would otherwise be visible to the negative
/// test running in a sibling thread).
static SCAN_LOCK: Mutex<()> = Mutex::new(());

/// Count `NEEDLE_LEN`-byte windows matching [`expected`] across every
/// readable, private, non-file-backed region of this process's own address
/// space (heap, stacks, anonymous mmaps — where a plaintext `Vec<u8>` would
/// live; guarded [`y2q_core::secmem`] pages are `PROT_NONE` at rest and so
/// are unreadable and skipped like any other inaccessible region).
fn scan_for_needle() -> usize {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
    let mut mem = std::fs::File::open("/proc/self/mem").expect("open /proc/self/mem");
    let mut matches = 0usize;

    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        let _offset = parts.next();
        let _dev = parts.next();
        let inode = parts.next().unwrap_or("0");
        let pathname = parts.next().unwrap_or("");

        if !perms.starts_with('r') {
            continue; // unreadable (e.g. a guarded PROT_NONE region)
        }
        if perms.as_bytes().get(3) != Some(&b'p') {
            continue; // shared, not private
        }
        // The needle can only ever live in this process's own
        // heap/stack/anonymous mappings, never in a mapped file's backing
        // pages (shared libraries, the binary's own text/rodata).
        let file_backed = inode != "0" && !pathname.is_empty() && !pathname.starts_with('[');
        if file_backed {
            continue;
        }

        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start_s, 16),
            usize::from_str_radix(end_s, 16),
        ) else {
            continue;
        };
        if end <= start || end - start < NEEDLE_LEN {
            continue;
        }

        let mut buf = vec![0u8; end - start];
        if mem.seek(SeekFrom::Start(start as u64)).is_err() {
            continue;
        }
        // A region can legitimately fail to read in full (e.g. a hole, or
        // one that raced a munmap between listing and reading) — skip it
        // rather than failing the whole scan.
        if mem.read_exact(&mut buf).is_err() {
            continue;
        }

        for window in buf.windows(NEEDLE_LEN) {
            if window.iter().enumerate().all(|(i, &b)| b == expected(i)) {
                matches += 1;
            }
        }
        buf.zeroize();
    }
    matches
}

#[test]
fn scanner_finds_a_live_plaintext_needle() {
    let _guard = SCAN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Positive control: a live `Vec<u8>` filled with the needle pattern
    // must be found — proves the scanner actually works before trusting a
    // zero result from the negative test below.
    let mut needle: Vec<u8> = (0..NEEDLE_LEN).map(expected).collect();
    assert!(
        scan_for_needle() >= 1,
        "scanner failed to find its own positive-control needle"
    );
    needle.zeroize();
    drop(needle);
}

#[test]
fn sealed_session_identity_key_never_appears_in_plaintext() {
    let _guard = SCAN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let store = SessionStore::new().expect("session store");

    // The needle never exists as a plain array: it's written directly into
    // a guarded `SecretVec` in place.
    let mut sk = SecretVec::zeroed(NEEDLE_LEN).expect("guarded allocation");
    for (i, b) in sk.as_mut_slice().iter_mut().enumerate() {
        *b = expected(i);
    }

    let token = store
        .insert(NewSession {
            username: "residency-test".to_owned(),
            role: Role::User,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
            persona: 0,
            revoke_other_sessions: false,
            identity_sk: sk,
        })
        .expect("insert session");

    // The sealed row now holds only AES-256-GCM ciphertext; the needle must
    // not be found anywhere in this process's readable memory.
    assert_eq!(
        scan_for_needle(),
        0,
        "found the plaintext session identity key outside guarded memory"
    );

    // Functional half: the sealed key still opens and matches.
    let info = store.get_active(&token.hash()).expect("active session");
    let byte7 = info.with_identity_sk(|sk| sk[7]).expect("open identity sk");
    assert_eq!(byte7, expected(7));
}
