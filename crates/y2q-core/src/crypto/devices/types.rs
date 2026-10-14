//! Pure data types, validators and traits for the device registry.
//!
//! Nothing here names a hardware crate: this module compiles on every target
//! and feature set, so the ungated `unlock` / `sweep_now` stubs and the
//! daemon's `From<&DevicesConfig> for DevicePolicy` can name these types.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::super::CryptoError;
use crate::secmem::SecretBuf;

/// Registry format version this build reads and writes.
pub const DEVICES_FORMAT_VERSION: u16 = 1;
/// Number of one-time emergency slots in every registry.
pub const EMERGENCY_SLOTS: usize = 10;
/// Length of a device id in raw bytes.
pub const DEVICE_ID_LEN: usize = 16;
/// Longest accepted device label, in bytes.
pub const MAX_LABEL_LEN: usize = 64;
/// Shortest away-grant period accepted (seconds).
pub const MIN_AWAY_GRANT_SECONDS: u32 = 60;
/// Longest away-grant period accepted (seconds): 30 days.
pub const MAX_AWAY_GRANT_SECONDS: u32 = 2_592_000;
/// Default away-grant period (seconds): 12 hours.
pub const DEFAULT_AWAY_GRANT_SECONDS: u32 = 43_200;

/// A 32-byte secret that zeroizes on drop.
pub type Key32 = Zeroizing<[u8; 32]>;

/// Which kind of hardware a record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// TPM 2.0 home device.
    Tpm2,
    /// FIDO2/CTAP2 `hmac-secret` away device.
    Fido2,
}

/// An AES-256-GCM ciphertext of a 32-byte secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrap {
    /// base64(standard) of the 12-byte nonce.
    pub nonce_b64: String,
    /// base64(standard) of the 48-byte ciphertext (32 bytes + 16-byte tag).
    pub ct_b64: String,
}

/// A time-boxed wrap of RMK under an away device's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Attested unix second after which this grant is dead. Bound into its own
    /// AAD, so it cannot be extended by editing; extending it only breaks the unwrap.
    pub not_after_unix: u64,
    /// Attested unix second of the home unlock that minted it. Audit only.
    pub issued_at_unix: u64,
    /// The ciphertext.
    pub wrap: Wrap,
}

/// Sealed TPM object parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tpm2Params {
    /// base64(standard) of the raw `TPM2B_PRIVATE` value.
    pub private_b64: String,
    /// base64(standard) of the marshalled `TPM2B_PUBLIC`.
    pub public_b64: String,
    /// PCR indices the sealing policy is bound to.
    pub pcr_slots: Vec<u8>,
    /// PCR bank; only `"sha256"` is supported.
    pub pcr_bank: String,
}

/// FIDO2 credential parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2Params {
    /// Relying-party id the credential was created under.
    pub rp_id: String,
    /// base64(standard) of the credential id.
    pub credential_id_b64: String,
    /// base64(standard) of the 32-byte public hmac-secret salt.
    pub hmac_salt_b64: String,
    /// Whether the device requires user verification (PIN) on every unlock.
    pub uv_required: bool,
}

/// One registered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    /// 16 CSPRNG bytes as 32 lowercase hex chars; the raw bytes go into every AAD.
    pub id: String,
    /// 1..=64 bytes, every byte in 0x20..=0x7e, unique case-insensitively.
    pub label: String,
    /// Hardware kind.
    pub kind: DeviceKind,
    /// Host-clock unix second of enrollment. Audit only.
    pub added_at_unix: u64,
    /// Permanent AES-256-GCM(KEK_device, RMK). Present for every `Tpm2` record, and for a
    /// `Fido2` record only in a `permanent_away` registry with zero home devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap: Option<Wrap>,
    /// Time-boxed AES-256-GCM(KEK_device, RMK) minted by a home unlock. Away records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
    /// TPM parameters, `Tpm2` records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm2: Option<Tpm2Params>,
    /// FIDO2 parameters, `Fido2` records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fido2: Option<Fido2Params>,
    /// Highest authenticator signature counter ever accepted. Away records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_count_last: Option<u32>,
    /// AES-256-GCM(KEK_CACHE_KEY, KEK_device). Away records only; never erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_wrap: Option<Wrap>,
    /// Raw bytes of `id`, filled by `load`.
    // Read only by the DEV-GATE registry modules.
    #[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
    #[serde(skip)]
    pub(crate) id_bytes: [u8; 16],
}

/// One emergency slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencySlot {
    /// 0..=9, zero-based; printed to the operator as index + 1.
    pub index: u8,
    /// Wrap of RMK under the code's KEK; `None` once burned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap: Option<Wrap>,
    /// Host-clock unix second of the burn. Audit only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burned_at_unix: Option<u64>,
}

/// The on-disk registry (`devices.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistryFile {
    /// Format version; must equal [`DEVICES_FORMAT_VERSION`].
    pub format_version: u16,
    /// base64(standard) of the 32-byte emergency-set commitment ESC.
    pub esc_b64: String,
    /// Registry policy, fixed at init, bound into `nk_wrap_aad` and every `grant_aad`.
    /// Bounds: 60 ..= 2_592_000.
    pub away_grant_seconds: u32,
    /// True exactly when the registry has zero home devices and devices are present.
    pub permanent_away: bool,
    /// AES-256-GCM(NK_WRAP_KEY, NK). The only ciphertext a node-key rotation rewrites.
    pub nk_wrap: Wrap,
    /// base64(standard) of the 32-byte state MAC over every mutable field.
    pub state_mac_b64: String,
    /// Registered devices, in file order.
    pub devices: Vec<DeviceRecord>,
    /// The ten emergency slots.
    pub emergency_slots: Vec<EmergencySlot>,
    /// Decoded ESC, filled by `load`.
    // Read only by the DEV-GATE registry modules.
    #[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
    #[serde(skip)]
    pub(crate) esc: [u8; 32],
}

/// A Roughtime server the operator trusts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoughtimeServer {
    /// Operator-chosen label, used only in errors and logs.
    pub name: String,
    /// "host:port" of the server's UDP endpoint.
    pub addr: String,
    /// base64(standard) of the server's 32-byte Ed25519 long-term public key.
    pub public_key_b64: String,
}

/// Roughtime client configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoughtimeConfig {
    /// Trusted servers.
    pub servers: Vec<RoughtimeServer>,
    /// Per-server query timeout; bounds 200 ..= 30_000.
    pub timeout_ms: u64,
    /// Minimum number of agreeing servers; bounds 2 ..= 16.
    pub min_responses: u8,
}

impl Default for RoughtimeConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout_ms: 3000,
            min_responses: 2,
        }
    }
}

impl RoughtimeConfig {
    /// Validate bounds and per-server shape. Messages are shared with the
    /// daemon's `validate_devices` and the CLI's flag parser.
    pub fn validate(&self) -> Result<(), String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        if !(200..=30_000).contains(&self.timeout_ms) {
            return Err(
                "[crypto.devices.roughtime] timeout_ms must be between 200 and 30000".into(),
            );
        }
        if !(2..=16).contains(&self.min_responses) {
            return Err("[crypto.devices.roughtime] min_responses must be between 2 and 16".into());
        }
        if !self.servers.is_empty() && usize::from(self.min_responses) > self.servers.len() {
            return Err(
                "[crypto.devices.roughtime] min_responses exceeds the number of configured servers"
                    .into(),
            );
        }
        let mut names = std::collections::HashSet::new();
        let mut keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for s in &self.servers {
            let host_port_ok = s
                .addr
                .rsplit_once(':')
                .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok());
            if !host_port_ok {
                return Err(format!(
                    "[crypto.devices.roughtime] server {}: addr must be host:port",
                    s.name
                ));
            }
            let key = STANDARD
                .decode(s.public_key_b64.trim())
                .ok()
                .filter(|k| k.len() == 32);
            let Some(key) = key else {
                return Err(format!(
                    "[crypto.devices.roughtime] server {}: public_key_b64 must decode to 32 bytes",
                    s.name
                ));
            };
            if !names.insert(s.name.clone()) {
                return Err("[crypto.devices.roughtime] server names must be unique".into());
            }
            if !keys.insert(key) {
                return Err(format!(
                    "[crypto.devices.roughtime] server {}: public_key_b64 duplicates another server's key",
                    s.name
                ));
            }
        }
        Ok(())
    }
}

/// How to reach the hardware and the time source.
#[derive(Debug, Clone)]
pub struct DevicePolicy {
    /// TCTI string for the TPM, e.g. `device:/dev/tpmrm0`.
    pub tpm_tcti: String,
    /// Roughtime configuration.
    pub roughtime: RoughtimeConfig,
}

/// Which authority opened the registry. Threaded into every mutating operation.
#[derive(Debug, Clone)]
pub enum Authority {
    /// A home (TPM) device.
    Home {
        /// Device id (hex).
        id: String,
        /// Device label.
        label: String,
    },
    /// An away (FIDO2) device.
    Away {
        /// Device id (hex).
        id: String,
        /// Device label.
        label: String,
        /// Deadline of the grant used, `None` for a permanent wrap.
        not_after_unix: Option<u64>,
    },
    /// A one-time emergency code.
    Emergency {
        /// Zero-based slot index.
        index: u8,
    },
}

impl Authority {
    /// Human-readable rendering used in `DeviceAuthorityInsufficient::by`.
    pub fn describe(&self) -> String {
        match self {
            Authority::Home { .. } => "a home device".to_owned(),
            Authority::Away { label, .. } => format!("away device '{label}'"),
            Authority::Emergency { .. } => "an emergency code".to_owned(),
        }
    }
}

/// Result of a successful registry unlock.
pub struct UnlockOutcome {
    /// The node key.
    pub node_key: Zeroizing<[u8; 32]>,
    /// Every mutating operation needs it, and HKDF is one-way, so the state key cannot substitute.
    pub registry_master_key: Zeroizing<[u8; 32]>,
    /// HKDF(RMK, "y2q/v1/registry-state-key"). The daemon's grant sweeper needs exactly this.
    pub registry_state_key: Zeroizing<[u8; 32]>,
    /// The loaded, MAC-verified registry, so a CLI caller can mutate and persist it
    /// without a second `load` that would race its own write.
    pub registry: DeviceRegistryFile,
    /// Which authority opened it.
    pub authority: Authority,
    /// Grants minted by this unlock.
    pub grants_issued: usize,
    /// Grants erased by this unlock.
    pub grants_erased: usize,
    /// Emergency slots still unburned.
    pub emergency_slots_unused: usize,
}

/// Hardware enrollment result, ready to be wrapped into the registry.
pub struct NewDevice {
    /// Device label.
    pub label: String,
    /// Hardware kind.
    pub kind: DeviceKind,
    /// TPM parameters (`Tpm2` only).
    pub tpm2: Option<Tpm2Params>,
    /// FIDO2 parameters (`Fido2` only).
    pub fido2: Option<Fido2Params>,
    /// 32-byte device secret the hardware just produced.
    pub secret: SecretBuf,
    /// Authenticator signature counter at enrollment; 0 for TPM.
    pub sign_count: u32,
}

/// Supplies an authenticator PIN on demand. Ungated so `y2qd` can implement it.
pub trait PinProvider: Send + Sync {
    /// `label` is the device's registry label, for the prompt.
    fn pin(&self, label: &str) -> Result<Zeroizing<String>, CryptoError>;
}

/// A trustworthy lower bound on the current time. Ungated so `y2qd` and tests can implement it.
pub trait TimeSource: Send + Sync {
    /// Unix seconds. MUST NOT fall back to the host clock.
    fn attested_now(&self) -> Result<u64, CryptoError>;
}

/// Result of a normal (device) unlock path.
pub struct Unlock {
    /// The node key.
    pub nk: Key32,
    /// The registry master key.
    pub rmk: Key32,
    /// Grants minted.
    pub grants_issued: usize,
    /// Grants erased.
    pub grants_erased: usize,
}

/// Result of an emergency-code unlock.
pub struct EmergencyUnlock {
    /// The node key.
    pub nk: Key32,
    /// The registry master key.
    pub rmk: Key32,
    /// Zero-based slot index that opened.
    pub slot: u8,
}
