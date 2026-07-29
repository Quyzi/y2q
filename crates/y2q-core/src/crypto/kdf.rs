//! Argon2id wrap/unwrap of credential-slot payloads.
//!
//! Each user record stores exactly [`CREDENTIAL_SLOTS`] slots; a slot's
//! [`SlotPayload`] (a persona's identity secret key, role, and duress flag)
//! is wrapped under a key derived from that slot's password via Argon2id.
//! All four slots on one record share a single [`Argon2Params`] (same costs,
//! same salt), which is what lets login pay for the Argon2 derivation once
//! and then try all four AEAD opens — see [`slot_wrap_aad`] for why a shared
//! salt is safe here.
//!
//! Wrap envelope: AES-256-GCM with the slot's KEK as the key, a fresh random
//! 12-byte nonce, and an AAD built by [`slot_wrap_aad`] that binds the
//! ciphertext to its owning username *and* slot position, so a wrapped blob
//! cannot be relocated to a different slot or a different user's record.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;
use super::user_store::{CREDENTIAL_SLOTS, CredentialSlot, Role, SlotPayload};

/// Argon2id parameters, persisted per user record.
///
/// Defaults follow OWASP's "second-tier" recommendation (m=64 MiB, t=3,
/// p=4) — slow enough on commodity hardware that a single login takes
/// hundreds of milliseconds, which acts as natural brute-force friction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB. Argon2's `m_cost`.
    pub m_cost_kib: u32,
    /// Time cost (iteration count). Argon2's `t_cost`.
    pub t_cost: u32,
    /// Parallelism (lanes). Argon2's `p_cost`.
    pub p_cost: u32,
    /// 16-byte salt, stored alongside the wrapped key.
    #[serde(with = "salt_b64")]
    pub salt: [u8; 16],
}

/// AES-256-GCM ciphertext (with 16-byte tag appended) of a slot payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedSk {
    /// 12-byte AEAD nonce.
    #[serde(with = "nonce_b64")]
    pub nonce: [u8; 12],
    /// Ciphertext + 16-byte GCM tag.
    #[serde(with = "ct_b64")]
    pub ciphertext: Vec<u8>,
}

/// Default Argon2id parameters used for newly added users.
pub fn default_argon2_params() -> Argon2Params {
    Argon2Params::with_random_salt(64 * 1024, 3, 4)
}

impl Argon2Params {
    /// Build a params struct with `m`/`t`/`p` and a freshly generated
    /// random salt.
    pub fn with_random_salt(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>, CryptoError> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| CryptoError::Kdf(format!("invalid params: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Run Argon2id over `password` to derive a 32-byte KEK.
    ///
    /// The returned buffer is the *raw* derived key — keep its lifetime
    /// short and zeroize when done.
    pub fn derive_kek(&self, password: &[u8]) -> Result<[u8; 32], CryptoError> {
        let argon2 = self.argon2()?;
        let mut kek = [0u8; 32];
        argon2
            .hash_password_into(password, &self.salt, &mut kek)
            .map_err(|e| CryptoError::Kdf(format!("hash: {e}")))?;
        Ok(kek)
    }
}

/// Build the AAD binding a wrapped slot to its owner and position:
/// `b"y2q/v3/slot-wrap" || u32_be(slot) || u32_be(username.len()) || username`.
///
/// A shared per-user Argon2 salt (see [`UserRecord::kdf`](super::user_store::UserRecord::kdf))
/// is safe here because a salt's job is to stop cross-*user* precomputation;
/// two slots of the *same* user sharing a salt only matters if they also
/// share a password, which the persona-creation endpoint (phase 5) rejects
/// outright. Binding the AAD to `(username, slot)` is what stops a wrapped
/// blob from being relocated to a different slot or a different user's
/// record even though the KEK derivation is shared.
pub fn slot_wrap_aad(username: &str, slot: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + 4 + username.len());
    aad.extend_from_slice(b"y2q/v3/slot-wrap");
    aad.extend_from_slice(&(slot as u32).to_be_bytes());
    aad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    aad.extend_from_slice(username.as_bytes());
    aad
}

/// Wrap `payload` (a [`SlotPayload`]'s [`to_bytes`](SlotPayload::to_bytes)
/// output) under a key derived from `password` with `params`.
pub fn wrap_slot(
    payload: &[u8],
    password: &[u8],
    params: &Argon2Params,
    aad: &[u8],
) -> Result<WrappedSk, CryptoError> {
    let mut kek = params.derive_kek(password)?;
    let result = wrap_with_key(payload, &kek, aad);
    kek.zeroize();
    result
}

/// Unwrap a previously wrapped slot payload.
///
/// Takes the already-derived KEK, not the password — this is what lets
/// login pay for the Argon2 derivation once per record and then try all
/// four AEAD opens cheaply.
pub fn unwrap_slot(
    wrapped: &WrappedSk,
    kek: &[u8; 32],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    unwrap_with_key(wrapped, kek, aad).map(Zeroizing::new)
}

/// Generate a persona: a fresh ML-KEM-768 identity keypair, whose
/// [`SlotPayload`] (holding the secret half, `role`, and
/// `revoke_other_sessions`) is wrapped under `password`. Returns the
/// populated slot for `slots[slot]`.
pub fn new_slot(
    username: &str,
    slot: usize,
    password: &[u8],
    params: &Argon2Params,
    role: Role,
    revoke_other_sessions: bool,
) -> Result<CredentialSlot, CryptoError> {
    let (pk, sk) = mlkem768::keypair();
    let payload = SlotPayload {
        identity_sk_b64: STANDARD.encode(sk.as_bytes()),
        role,
        revoke_other_sessions,
    };
    let payload_bytes = payload.to_bytes()?;
    let aad = slot_wrap_aad(username, slot);
    let wrapped = wrap_slot(&payload_bytes, password, params, &aad)?;
    Ok(CredentialSlot {
        identity_pk_b64: STANDARD.encode(pk.as_bytes()),
        wrapped,
    })
}

/// A slot nobody can open: a real ML-KEM-768 keypair, whose `SlotPayload` is
/// wrapped under 32 freshly-generated random bytes that are immediately
/// discarded. Byte-shape identical to a live slot — same identity-key
/// length, same wrapped-payload length (see
/// [`SlotPayload::to_bytes`](super::user_store::SlotPayload::to_bytes) for
/// why the payload encoding is fixed-width).
pub fn decoy_slot(
    username: &str,
    slot: usize,
    params: &Argon2Params,
) -> Result<CredentialSlot, CryptoError> {
    let (pk, sk) = mlkem768::keypair();
    let payload = SlotPayload {
        identity_sk_b64: STANDARD.encode(sk.as_bytes()),
        role: Role::User,
        revoke_other_sessions: false,
    };
    let payload_bytes = payload.to_bytes()?;
    let mut discarded_password = [0u8; 32];
    rand::rng().fill_bytes(&mut discarded_password);
    let aad = slot_wrap_aad(username, slot);
    let wrapped = wrap_slot(&payload_bytes, &discarded_password, params, &aad)?;
    discarded_password.zeroize();
    Ok(CredentialSlot {
        identity_pk_b64: STANDARD.encode(pk.as_bytes()),
        wrapped,
    })
}

/// Build `CREDENTIAL_SLOTS` decoy slots for positions `start..CREDENTIAL_SLOTS`.
pub fn decoy_slots_from(
    username: &str,
    start: usize,
    params: &Argon2Params,
) -> Result<Vec<CredentialSlot>, CryptoError> {
    (start..CREDENTIAL_SLOTS)
        .map(|i| decoy_slot(username, i, params))
        .collect()
}

/// Build a fresh `CREDENTIAL_SLOTS`-length slot array for a brand-new
/// identity, with the real (password-opened) slot placed at a position
/// chosen uniformly at random rather than a fixed index. Returns the slots
/// plus which index won, so the caller can record it in
/// [`UserRecord::primary_slot`](super::user_store::UserRecord::primary_slot)
/// for later grant routing.
///
/// This is what stops "the real login is always slot N" from ever being a
/// usable heuristic: previously slot 0 was hardcoded, so a technical
/// coercer who queried `GET /api/v1/personas/me` directly (bypassing
/// whatever a victim's CLI told them) could read the slot number straight
/// off the response and know with certainty whether they'd been handed the
/// real password or an alternate/duress one. With placement randomized per
/// account and never returned by any API, that shortcut is gone — the only
/// route left to distinguish slots is cracking each one's password
/// independently, exactly as hard as it already is for a genuine decoy.
pub fn new_slots_random(
    username: &str,
    password: &[u8],
    params: &Argon2Params,
    role: Role,
    revoke_other_sessions: bool,
) -> Result<(Vec<CredentialSlot>, usize), CryptoError> {
    let real_slot = rand::rng().random_range(0..CREDENTIAL_SLOTS);
    let slots = (0..CREDENTIAL_SLOTS)
        .map(|i| {
            if i == real_slot {
                new_slot(username, i, password, params, role, revoke_other_sessions)
            } else {
                decoy_slot(username, i, params)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((slots, real_slot))
}

/// Wrap `payload` directly under `key` (no password derivation) — used for
/// values already sealed to a random key, e.g. a bucket secret key under its
/// bucket wrap key. `slot_wrap`/`unwrap_slot` build on this internally.
pub fn wrap_with_key(payload: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<WrappedSk, CryptoError> {
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(key.into());
    let ct = cipher
        .encrypt(
            &aes_gcm::Nonce::from(nonce_bytes),
            Payload { msg: payload, aad },
        )
        .map_err(|_| CryptoError::Aead("wrap encrypt"))?;
    Ok(WrappedSk {
        nonce: nonce_bytes,
        ciphertext: ct,
    })
}

/// Unwrap `wrapped` directly under `key` (no password derivation). Inverse
/// of [`wrap_with_key`].
pub fn unwrap_with_key(
    wrapped: &WrappedSk,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            &aes_gcm::Nonce::from(wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

mod salt_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 16 {
            return Err(serde::de::Error::custom("salt must be 16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod nonce_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 12 {
            return Err(serde::de::Error::custom("nonce must be 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod ct_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> Argon2Params {
        Argon2Params::with_random_salt(8 * 1024, 1, 1)
    }

    #[test]
    fn new_slot_round_trips_through_login_shaped_unwrap() {
        let params = fast_params();
        let slot = new_slot(
            "alice",
            0,
            b"correct horse battery staple",
            &params,
            Role::Admin,
            true,
        )
        .unwrap();
        let kek = params.derive_kek(b"correct horse battery staple").unwrap();
        let aad = slot_wrap_aad("alice", 0);
        let recovered = unwrap_slot(&slot.wrapped, &kek, &aad).unwrap();
        let payload = SlotPayload::from_bytes(&recovered).unwrap();
        assert_eq!(payload.role, Role::Admin);
        assert!(payload.revoke_other_sessions);
    }

    #[test]
    fn wrong_password_fails() {
        let params = fast_params();
        let slot = new_slot("alice", 0, b"right", &params, Role::User, false).unwrap();
        let kek = params.derive_kek(b"wrong").unwrap();
        let aad = slot_wrap_aad("alice", 0);
        assert!(matches!(
            unwrap_slot(&slot.wrapped, &kek, &aad),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn wrong_slot_position_fails_even_with_the_right_password() {
        // A blob wrapped for slot 0 must not open when checked against slot 1's
        // AAD — this is exactly what stops a wrapped blob being relocated to a
        // different slot on the same record.
        let params = fast_params();
        let slot = new_slot("alice", 0, b"pw", &params, Role::User, false).unwrap();
        let kek = params.derive_kek(b"pw").unwrap();
        let wrong_aad = slot_wrap_aad("alice", 1);
        assert!(matches!(
            unwrap_slot(&slot.wrapped, &kek, &wrong_aad),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn wrong_username_fails_even_with_the_right_password() {
        let params = fast_params();
        let slot = new_slot("alice", 0, b"pw", &params, Role::User, false).unwrap();
        let kek = params.derive_kek(b"pw").unwrap();
        let wrong_aad = slot_wrap_aad("bob", 0);
        assert!(matches!(
            unwrap_slot(&slot.wrapped, &kek, &wrong_aad),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn decoy_slot_opens_under_no_password() {
        let params = fast_params();
        let decoy = decoy_slot("alice", 1, &params).unwrap();
        let aad = slot_wrap_aad("alice", 1);
        // Try a handful of candidate passwords; none can possibly match the
        // discarded random bytes it was actually wrapped under.
        for pw in [&b""[..], b"password", b"correct horse battery staple"] {
            let kek = params.derive_kek(pw).unwrap();
            assert!(unwrap_slot(&decoy.wrapped, &kek, &aad).is_err());
        }
    }

    #[test]
    fn live_and_decoy_slots_are_byte_shape_identical() {
        let params = fast_params();
        let live = new_slot("alice", 0, b"pw", &params, Role::Admin, true).unwrap();
        let decoy = decoy_slot("alice", 1, &params).unwrap();
        assert_eq!(
            live.identity_pk_b64.len(),
            decoy.identity_pk_b64.len(),
            "identity public keys must be the same length"
        );
        assert_eq!(
            live.wrapped.ciphertext.len(),
            decoy.wrapped.ciphertext.len(),
            "wrapped payload ciphertext must be the same length regardless of role/flags"
        );
    }

    #[test]
    fn decoy_slots_from_fills_the_remaining_width() {
        let params = fast_params();
        let decoys = decoy_slots_from("alice", 1, &params).unwrap();
        assert_eq!(decoys.len(), CREDENTIAL_SLOTS - 1);
    }

    #[test]
    fn params_serialize_roundtrip() {
        let params = fast_params();
        let slot = new_slot("alice", 0, b"pw", &params, Role::User, false).unwrap();
        let json = serde_json::to_string(&(&params, &slot.wrapped)).unwrap();
        let (params2, wrapped2): (Argon2Params, WrappedSk) = serde_json::from_str(&json).unwrap();
        let kek = params2.derive_kek(b"pw").unwrap();
        let aad = slot_wrap_aad("alice", 0);
        let recovered = unwrap_slot(&wrapped2, &kek, &aad).unwrap();
        assert!(SlotPayload::from_bytes(&recovered).is_ok());
    }

    #[test]
    fn nonce_changes_each_wrap() {
        let params = fast_params();
        let a = new_slot("alice", 0, b"pw", &params, Role::User, false).unwrap();
        let b = new_slot("alice", 0, b"pw", &params, Role::User, false).unwrap();
        assert_ne!(a.wrapped.nonce, b.wrapped.nonce);
        assert_ne!(a.wrapped.ciphertext, b.wrapped.ciphertext);
    }

    #[test]
    fn new_slots_random_places_the_real_slot_correctly_and_pads_the_rest() {
        let params = fast_params();
        let (slots, real_slot) =
            new_slots_random("alice", b"pw", &params, Role::Admin, true).unwrap();
        assert_eq!(slots.len(), CREDENTIAL_SLOTS);
        assert!(real_slot < CREDENTIAL_SLOTS);

        let kek = params.derive_kek(b"pw").unwrap();
        let opened: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(i, s)| unwrap_slot(&s.wrapped, &kek, &slot_wrap_aad("alice", *i)).is_ok())
            .map(|(i, _)| i)
            .collect();
        // The password opens exactly the reported real slot, and nothing else.
        assert_eq!(opened, vec![real_slot]);

        // Byte shape stays uniform across the real slot and every decoy.
        let lens: Vec<usize> = slots.iter().map(|s| s.wrapped.ciphertext.len()).collect();
        assert!(lens.iter().all(|&l| l == lens[0]));
    }

    #[test]
    fn new_slots_random_does_not_always_pick_the_same_slot() {
        // Statistical, not a correctness proof: with CREDENTIAL_SLOTS = 4 and
        // 200 draws, the odds every single one lands on slot 0 are
        // (1/4)^200 - if this ever fails, `real_slot` stopped being random.
        let params = fast_params();
        let seen: std::collections::HashSet<usize> = (0..200)
            .map(|_| {
                new_slots_random("alice", b"pw", &params, Role::User, false)
                    .unwrap()
                    .1
            })
            .collect();
        assert!(
            seen.len() > 1,
            "expected multiple distinct real-slot positions across 200 draws, got {seen:?}"
        );
    }
}
