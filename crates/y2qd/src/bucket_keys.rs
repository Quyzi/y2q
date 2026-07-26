//! Per-bucket key material: creating epochs, resolving a bucket secret key
//! from a session's identity, and persisting grants.
//!
//! A [`BucketKeyVersion`] holds one epoch of a bucket's ML-KEM-768 keypair.
//! Its secret half is never stored directly — it's wrapped under a 32-byte
//! bucket wrap key (BWK) that's generated fresh per epoch and never
//! persisted itself: instead, the BWK is sealed once per credential slot of
//! every grantee, so a grantee's identity secret key opens their sealed copy
//! and recovers the BWK, which then unwraps `sk_blob` into the real bucket
//! secret key.
//!
//! Every grant carries exactly [`CREDENTIAL_SLOTS`] sealed entries per user
//! — real BWK ciphertext for an authorized persona, 32 freshly-generated
//! random bytes for an unauthorized one — so the stored bytes never reveal
//! which of a user's personas hold access, nor how many personas are real.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait};
use rand::Rng;
use std::collections::BTreeMap;
use y2q_core::crypto::{
    CREDENTIAL_SLOTS, bucket_grant_aad, bucket_sk_wrap_aad, open_sealed, seal_to, unwrap_with_key,
    wrap_with_key,
};
use y2q_core::{BucketConfig, BucketKeyVersion, Error};
use zeroize::Zeroizing;

/// Hard cap on retained [`BucketConfig::keys`] epochs. `rotate-key` refuses
/// with [`Error::TooManyBucketKeyEpochs`] at this count; `rekey` prunes every
/// epoch below the newest back down to one. Bounds how large the
/// Raft-replicated bucket config (clustered) or sidecar (single-node) can
/// grow from repeated rotation without an intervening rekey.
pub const MAX_RETAINED_EPOCHS: usize = 8;

/// Which of a grantee's credential slots (personas) may open a bucket key
/// version: `authorized[i]` is `true` when persona `i` is authorized, and
/// must line up positionally with `identity_pks_b64[i]`.
#[derive(Debug, Clone)]
pub struct GranteeSlots {
    /// This user's four persona identity public keys, standard-base64, in
    /// slot order — the same order as
    /// [`UserRecord::slots`](y2q_core::crypto::UserRecord::slots).
    pub identity_pks_b64: Vec<String>,
    /// Per-slot authorization; always `CREDENTIAL_SLOTS` entries.
    pub authorized: Vec<bool>,
}

/// Create a fresh bucket key epoch: a new ML-KEM-768 keypair, a fresh 32-byte
/// BWK wrapping its secret half, and one sealed grant entry per credential
/// slot of every grantee in `grantees`.
///
/// Returns the populated [`BucketKeyVersion`] (ready to push onto
/// [`BucketConfig::keys`]) alongside the freshly-generated BWK — the caller
/// needs the BWK only transiently, e.g. to grant a slot added later via
/// [`put_grant_slot`] without regenerating the whole epoch.
pub fn new_bucket_key_version(
    epoch: u32,
    bucket: &str,
    grantees: &[(String, GranteeSlots)],
) -> Result<(BucketKeyVersion, Zeroizing<[u8; 32]>), Error> {
    let (pk, sk) = mlkem768::keypair();
    let mut bwk = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *bwk);

    let sk_aad = bucket_sk_wrap_aad(bucket, epoch);
    let sk_blob = wrap_with_key(sk.as_bytes(), &bwk, &sk_aad)
        .map_err(|e| crypto_err(bucket, "new_bucket_key", e))?;

    let mut grants = BTreeMap::new();
    for (username, slots) in grantees {
        let sealed = seal_grant_slots(bucket, epoch, username, slots, &bwk)?;
        grants.insert(username.clone(), sealed);
    }

    Ok((
        BucketKeyVersion {
            epoch,
            public_key_b64: STANDARD.encode(pk.as_bytes()),
            sk_blob,
            grants,
        },
        bwk,
    ))
}

/// Build the `grantees` list for a `rotate-key` call: real access for
/// `caller_username` at `caller_persona` (whatever slot they're actually
/// authenticated as — this is the only way to guarantee the *caller's own*
/// access survives the rotation, since a bucket owner's real persona is
/// whichever slot originally claimed it, not necessarily slot 0), plus real
/// access at credential slot 0 for the bucket owner (if different from the
/// caller) and every other username with a read-implying ACL grant —
/// matching the slot-0 convention `set_acl`'s `reseal_grantee` already uses
/// for third-party grants. Unknown usernames (a stale ACL entry for a
/// deleted user) are silently skipped, same as `reseal_grantee`.
///
/// This is necessarily a *reconstruction* from the cleartext ACL/owner
/// fields, not a read of who currently holds real access on the bucket's
/// existing epoch: the server can never tell a real sealed grant from a
/// decoy without that grantee's own identity secret key (the whole point of
/// the deniability property), so there is no way to losslessly carry
/// forward "the current real grantee set" bit-for-bit across a rotation.
pub fn current_grantees(
    user_store: &y2q_core::crypto::UserStore,
    config: &BucketConfig,
    bucket: &str,
    caller_username: &str,
    caller_persona: u8,
) -> Result<Vec<(String, GranteeSlots)>, Error> {
    let mut usernames: std::collections::BTreeSet<String> =
        crate::handlers::acl::read_implying_grantees(&config.acl);
    if let Some(owner) = &config.owner {
        usernames.insert(owner.clone());
    }
    usernames.insert(caller_username.to_owned());

    let mut grantees = Vec::with_capacity(usernames.len());
    for username in usernames {
        let Some(rec) = user_store
            .get(&username)
            .map_err(|e| crypto_err(bucket, "rotate_key", e))?
        else {
            continue;
        };
        let identity_pks_b64: Vec<String> = rec
            .slots
            .iter()
            .map(|s| s.identity_pk_b64.clone())
            .collect();
        let mut authorized = vec![false; CREDENTIAL_SLOTS];
        if username == caller_username {
            authorized[caller_persona as usize] = true;
        } else {
            authorized[0] = true;
        }
        grantees.push((
            username,
            GranteeSlots {
                identity_pks_b64,
                authorized,
            },
        ));
    }
    Ok(grantees)
}

/// Seal `bwk` (real, for authorized slots) or a fresh random decoy
/// (unauthorized slots) to every one of `slots`'s [`CREDENTIAL_SLOTS`]
/// identity keys, producing the sealed-grant row stored under
/// `BucketKeyVersion::grants[username]`.
fn seal_grant_slots(
    bucket: &str,
    epoch: u32,
    username: &str,
    slots: &GranteeSlots,
    bwk: &[u8; 32],
) -> Result<Vec<y2q_core::crypto::SealedKey>, Error> {
    if slots.identity_pks_b64.len() != CREDENTIAL_SLOTS
        || slots.authorized.len() != CREDENTIAL_SLOTS
    {
        return Err(Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "bucket-key-grant".to_owned(),
            message: format!(
                "expected {CREDENTIAL_SLOTS} credential slots for {username}, found a mismatched count"
            ),
        });
    }
    let mut sealed = Vec::with_capacity(CREDENTIAL_SLOTS);
    for (slot, (pk_b64, &authorized)) in slots
        .identity_pks_b64
        .iter()
        .zip(slots.authorized.iter())
        .enumerate()
    {
        let identity_pk = STANDARD
            .decode(pk_b64)
            .map_err(|_| crypto_decode_err(bucket, "identity public key"))?;
        let aad = bucket_grant_aad(bucket, epoch, username, slot);
        let payload: [u8; 32] = if authorized {
            *bwk
        } else {
            let mut decoy = [0u8; 32];
            rand::rng().fill_bytes(&mut decoy);
            decoy
        };
        sealed.push(
            seal_to(&identity_pk, &payload, &aad)
                .map_err(|e| crypto_err(bucket, "seal-grant", e))?,
        );
    }
    Ok(sealed)
}

/// Add or replace one grantee's full grant row (all [`CREDENTIAL_SLOTS`]
/// entries) on `kv` in place, sealing `bwk` to the authorized slots of
/// `slots` and decoys to the rest. Used both for a brand-new grantee and to
/// re-seal an existing grantee's row (e.g. adding a persona's access via
/// `set_acl`, or a duress persona re-sharing its own access — phase 5).
pub fn put_grant_slot(
    kv: &mut BucketKeyVersion,
    bucket: &str,
    username: &str,
    slots: &GranteeSlots,
    bwk: &[u8; 32],
) -> Result<(), Error> {
    let sealed = seal_grant_slots(bucket, kv.epoch, username, slots, bwk)?;
    kv.grants.insert(username.to_owned(), sealed);
    Ok(())
}

/// Open the bucket wrap key (BWK) for `bucket` at `epoch`, using
/// `identity_sk` (the caller's persona secret key, at credential slot
/// `slot`) to open their sealed grant. The BWK is what a grantor needs to
/// seal a *new* grantee's slot ([`put_grant_slot`]) — unlike the bucket
/// secret key itself, it is never persisted, so adding a grant later
/// requires recovering it fresh from an existing grantee's own sealed copy.
///
/// Every failure path — missing bucket key config, missing epoch, missing
/// grant entry for this user, an out-of-range slot, or an AEAD open failure
/// — returns the same [`Error::Forbidden`]; see [`read_key`]'s docs for why.
pub fn open_bwk(
    config: &BucketConfig,
    bucket: &str,
    epoch: u32,
    username: &str,
    slot: usize,
    identity_sk: &[u8],
) -> Result<[u8; 32], Error> {
    let kv = config
        .keys
        .iter()
        .find(|k| k.epoch == epoch)
        .ok_or_else(|| forbidden(bucket))?;
    let sealed_slots = kv.grants.get(username).ok_or_else(|| forbidden(bucket))?;
    if sealed_slots.len() != CREDENTIAL_SLOTS {
        return Err(Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "bucket-key-grant".to_owned(),
            message: format!(
                "expected {CREDENTIAL_SLOTS} credential slots for {username}, found {}",
                sealed_slots.len()
            ),
        });
    }
    let sealed = sealed_slots.get(slot).ok_or_else(|| forbidden(bucket))?;
    let grant_aad = bucket_grant_aad(bucket, epoch, username, slot);
    let bwk = open_sealed(identity_sk, sealed, &grant_aad).map_err(|_| forbidden(bucket))?;
    bwk.as_slice().try_into().map_err(|_| forbidden(bucket))
}

/// Recover the bucket secret key for `bucket` at `epoch`, using `identity_sk`
/// (the caller's persona secret key, at credential slot `slot`) to open their
/// sealed BWK grant.
///
/// Every failure path here — missing bucket key config, missing epoch,
/// missing grant entry for this user, an out-of-range slot, or an AEAD open
/// failure on either the grant or the wrapped secret key — returns the same
/// [`Error::Forbidden`], so a caller (an unauthorized user, an admin with no
/// grant, or a tampered/relocated blob) cannot distinguish "you have no
/// grant" from "you have a grant but it's for a different persona" from
/// "someone tampered with the ciphertext". Only a structurally corrupt
/// grants row (wrong slot count) is a distinguishable [`Error::InternalError`],
/// since that can only happen from an on-disk bug, never from an
/// unauthorized caller's actions.
pub fn read_key(
    config: &BucketConfig,
    bucket: &str,
    epoch: u32,
    username: &str,
    slot: usize,
    identity_sk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kv = config
        .keys
        .iter()
        .find(|k| k.epoch == epoch)
        .ok_or_else(|| forbidden(bucket))?;
    let bwk = open_bwk(config, bucket, epoch, username, slot, identity_sk)?;
    let sk_aad = bucket_sk_wrap_aad(bucket, epoch);
    let sk_bytes = unwrap_with_key(&kv.sk_blob, &bwk, &sk_aad).map_err(|_| forbidden(bucket))?;
    Ok(Zeroizing::new(sk_bytes))
}

/// Return the newest (highest-epoch) key version, if any exist.
pub fn current_key(config: &BucketConfig) -> Option<&BucketKeyVersion> {
    config.keys.last()
}

/// Resolve the bucket secret key for `(bucket, epoch)` on behalf of
/// `session`'s persona, consulting the session's bucket-key cache first and
/// populating it on a miss. Cheap to call repeatedly for the same
/// `(bucket, epoch)` within one session — later calls (e.g. GET after a
/// visibility check already resolved the same epoch) hit the cache instead
/// of paying for another AEAD open.
pub fn resolve_read_key(
    session: &crate::auth::session::SessionInfo,
    config: &BucketConfig,
    bucket: &str,
    epoch: u32,
) -> Result<std::sync::Arc<Zeroizing<Vec<u8>>>, Error> {
    if let Some(cached) = session.cached_bucket_key(bucket, epoch) {
        return Ok(cached);
    }
    let sk = read_key(
        config,
        bucket,
        epoch,
        &session.username,
        session.persona as usize,
        &session.identity_sk,
    )?;
    let sk = std::sync::Arc::new(sk);
    session.cache_bucket_key(bucket.to_owned(), epoch, std::sync::Arc::clone(&sk));
    Ok(sk)
}

/// Whether `session`'s persona currently holds a *usable* (real, not decoy)
/// grant on `bucket`'s newest key epoch.
///
/// This is the crypto-layer visibility check: it actually attempts the
/// AEAD open (not just checking whether a grant row exists — that would be
/// true for every persona of every user ever granted access, real or
/// decoy), so a duress persona whose slot was sealed with a decoy correctly
/// reports `false` even though its row is structurally present. Returns
/// `false` (not an error) for a bucket with no key material yet, since
/// there is nothing to be granted to.
pub fn is_visible(
    session: &crate::auth::session::SessionInfo,
    config: &BucketConfig,
    bucket: &str,
) -> bool {
    match current_key(config) {
        Some(kv) => resolve_read_key(session, config, bucket, kv.epoch).is_ok(),
        None => false,
    }
}

/// Build the epoch-0 [`BucketKeyVersion`] for a brand-new bucket being
/// claimed by `session`'s persona: real access for the persona that issued
/// the claiming request, decoy access sealed to that same user's other real
/// identity keys for every other slot (so that user's other personas —
/// including future duress ones — cannot see this bucket unless explicitly
/// granted later).
pub fn new_owner_key(
    user_store: &y2q_core::crypto::UserStore,
    bucket: &str,
    session: &crate::auth::session::SessionInfo,
) -> Result<BucketKeyVersion, Error> {
    let rec = user_store
        .get(&session.username)
        .map_err(|e| crypto_err(bucket, "claim_ownership", e))?
        .ok_or_else(|| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "claim_ownership".to_owned(),
            message: "claiming user's record vanished".to_owned(),
        })?;
    let identity_pks_b64: Vec<String> = rec
        .slots
        .iter()
        .map(|s| s.identity_pk_b64.clone())
        .collect();
    let authorized: Vec<bool> = (0..CREDENTIAL_SLOTS)
        .map(|i| i == session.persona as usize)
        .collect();
    let slots = GranteeSlots {
        identity_pks_b64,
        authorized,
    };
    let (kv, _bwk) = new_bucket_key_version(0, bucket, &[(session.username.clone(), slots)])?;
    Ok(kv)
}

/// The bucket's current (newest) key epoch and public key, standard-base64
/// decoded, for encrypting a new PUT. Errors with [`Error::InternalError`] if
/// the bucket has no key material yet — callers must create it first (see
/// [`new_owner_key`] via `authorize_bucket`'s `Decision::ClaimOwnership`, or
/// the explicit bucket-create endpoint).
pub fn resolve_write_key(config: &BucketConfig, bucket: &str) -> Result<(u32, Vec<u8>), Error> {
    let kv = current_key(config).ok_or_else(|| Error::InternalError {
        bucket: bucket.to_owned(),
        key: String::new(),
        operation: "resolve_write_key".to_owned(),
        message: "bucket has no key material".to_owned(),
    })?;
    let pk = STANDARD
        .decode(&kv.public_key_b64)
        .map_err(|_| crypto_decode_err(bucket, "bucket public key"))?;
    Ok((kv.epoch, pk))
}

fn forbidden(bucket: &str) -> Error {
    Error::Forbidden {
        bucket: bucket.to_owned(),
    }
}

fn crypto_err(bucket: &str, operation: &str, e: y2q_core::crypto::CryptoError) -> Error {
    Error::InternalError {
        bucket: bucket.to_owned(),
        key: String::new(),
        operation: operation.to_owned(),
        message: e.to_string(),
    }
}

fn crypto_decode_err(bucket: &str, what: &'static str) -> Error {
    Error::InternalError {
        bucket: bucket.to_owned(),
        key: String::new(),
        operation: "bucket-key-grant".to_owned(),
        message: format!("malformed {what}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots_for(pks: &[String], authorized_idx: &[usize]) -> GranteeSlots {
        GranteeSlots {
            identity_pks_b64: pks.to_vec(),
            authorized: (0..CREDENTIAL_SLOTS)
                .map(|i| authorized_idx.contains(&i))
                .collect(),
        }
    }

    fn identity(_seed: u8) -> (String, Vec<u8>) {
        let (pk, sk) = mlkem768::keypair();
        (STANDARD.encode(pk.as_bytes()), sk.as_bytes().to_vec())
    }

    #[test]
    fn authorized_slot_recovers_the_same_key_across_epochs() {
        let (alice_pk0, alice_sk0) = identity(0);
        // A slot needs a real (decodable) placeholder pk even when unused —
        // use throwaway keys for the unauthorized slots.
        let (junk1, _) = identity(1);
        let (junk2, _) = identity(2);
        let (junk3, _) = identity(3);
        let pks = vec![alice_pk0, junk1, junk2, junk3];

        let (kv, _bwk) =
            new_bucket_key_version(0, "b", &[("alice".to_owned(), slots_for(&pks, &[0]))]).unwrap();

        let mut cfg = BucketConfig::default();
        cfg.keys.push(kv);

        let recovered = read_key(&cfg, "b", 0, "alice", 0, &alice_sk0).unwrap();
        // Decodes as a real ML-KEM-768 secret key — the round trip through
        // seal/wrap/unwrap/open preserved the exact bytes.
        assert!(mlkem768::SecretKey::from_bytes(&recovered).is_ok());
    }

    #[test]
    fn unauthorized_slot_cannot_open_the_grant() {
        let (alice_pk0, alice_sk0) = identity(0);
        let (junk1, _) = identity(1);
        let (junk2, _) = identity(2);
        let (junk3, _) = identity(3);
        let pks = vec![alice_pk0, junk1, junk2, junk3];

        // Nobody authorized.
        let (kv, _bwk) =
            new_bucket_key_version(0, "b", &[("alice".to_owned(), slots_for(&pks, &[]))]).unwrap();
        let mut cfg = BucketConfig::default();
        cfg.keys.push(kv);

        assert!(matches!(
            read_key(&cfg, "b", 0, "alice", 0, &alice_sk0),
            Err(Error::Forbidden { .. })
        ));
    }

    #[test]
    fn unknown_user_is_forbidden_not_missing() {
        let cfg = BucketConfig::default();
        let (_, sk) = identity(0);
        assert!(matches!(
            read_key(&cfg, "b", 0, "nobody", 0, &sk),
            Err(Error::Forbidden { .. })
        ));
    }

    #[test]
    fn wrong_slot_of_the_same_user_is_forbidden() {
        let (alice_pk0, alice_sk0) = identity(0);
        let (alice_pk1, _alice_sk1) = identity(1);
        let (junk2, _) = identity(2);
        let (junk3, _) = identity(3);
        let pks = vec![alice_pk0, alice_pk1, junk2, junk3];

        // Only slot 1 is authorized.
        let (kv, _bwk) =
            new_bucket_key_version(0, "b", &[("alice".to_owned(), slots_for(&pks, &[1]))]).unwrap();
        let mut cfg = BucketConfig::default();
        cfg.keys.push(kv);

        // Slot 0's real secret key exists but its slot isn't authorized.
        assert!(matches!(
            read_key(&cfg, "b", 0, "alice", 0, &alice_sk0),
            Err(Error::Forbidden { .. })
        ));
    }

    #[test]
    fn put_grant_slot_adds_a_new_grantee_to_an_existing_epoch() {
        let (alice_pk0, _) = identity(0);
        let (j1, _) = identity(1);
        let (j2, _) = identity(2);
        let (j3, _) = identity(3);
        let alice_pks = vec![alice_pk0, j1, j2, j3];
        let (mut kv, bwk) =
            new_bucket_key_version(0, "b", &[("alice".to_owned(), slots_for(&alice_pks, &[0]))])
                .unwrap();

        let (bob_pk0, bob_sk0) = identity(4);
        let (j5, _) = identity(5);
        let (j6, _) = identity(6);
        let (j7, _) = identity(7);
        let bob_pks = vec![bob_pk0, j5, j6, j7];
        put_grant_slot(&mut kv, "b", "bob", &slots_for(&bob_pks, &[0]), &bwk).unwrap();

        let mut cfg = BucketConfig::default();
        cfg.keys.push(kv);
        assert!(read_key(&cfg, "b", 0, "bob", 0, &bob_sk0).is_ok());
    }

    #[test]
    fn grant_row_is_byte_shape_uniform_across_authorized_and_decoy_slots() {
        // Deniability property: a grant row always carries exactly
        // CREDENTIAL_SLOTS sealed entries, real and decoy alike, all the
        // same ciphertext length - nothing on disk should reveal how many
        // of a grantee's personas actually hold access.
        let (alice_pk0, _) = identity(0);
        let (j1, _) = identity(1);
        let (j2, _) = identity(2);
        let (j3, _) = identity(3);
        let pks = vec![alice_pk0, j1, j2, j3];
        // Only slot 0 is authorized - slots 1..3 are decoys.
        let (kv, _bwk) =
            new_bucket_key_version(0, "b", &[("alice".to_owned(), slots_for(&pks, &[0]))]).unwrap();

        let sealed = kv.grants.get("alice").unwrap();
        assert_eq!(sealed.len(), CREDENTIAL_SLOTS);
        let lens: Vec<usize> = sealed.iter().map(|s| s.ct_b64.len()).collect();
        assert!(
            lens.iter().all(|&l| l == lens[0]),
            "sealed grant lengths differ: {lens:?}"
        );
    }
}
