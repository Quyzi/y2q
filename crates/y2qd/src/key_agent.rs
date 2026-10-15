//! Socket-activated one-shot key helper.
//!
//! No resident process holds RMK. A systemd socket unit (`Accept=yes`) spawns a
//! fresh `y2qd --key-serve` per connection, with the accepted unix socket as
//! stdin, running as the key-owner uid (the one with TPM / hidraw access and
//! ownership of `devices.json`). The helper serves exactly one request and
//! exits, so RMK and the registry state key only ever exist inside short-lived
//! processes. The wire protocol, framing and clients live in
//! [`y2q_core::crypto::devices::keyrpc`].
//!
//! Two requests exist:
//!
//! * **arm** (peer uid must be `key_agent_arm_uid`, default root): stores
//!   one-time authorization material (passcode, FIDO2 PIN, emergency code) in
//!   `<key_agent_state_dir>/armed` (tmpfs, dir `0700`, file `0600`, owned by
//!   the key uid). Unattended hosts arm with empty authorization from
//!   `ExecStartPre=+` before every daemon start; attended hosts arm
//!   interactively with `y2qd --key-arm --prompt-*`, which sends the secrets
//!   over the socket instead of an environment variable or a file.
//! * **fetch** (peer uid must be `key_agent_peer_uid`, the daemon uid): the
//!   helper consumes the armed file (every attempt deletes it, success or
//!   failure), runs the registry unlock using that material, and returns the
//!   node key plus non-secret metadata once. A fetch without a prior arm is
//!   refused, and a refused peer never consumes the armed file. A compromised
//!   daemon uid can therefore connect but cannot re-fetch NK or RMK: it cannot
//!   arm.
//!
//! `y2qd --key-sweep` is the grant refresh / sweep run from a systemd timer:
//! a one-shot [`y2q_core::crypto::devices::unlock_home`] with a provider that
//! supplies nothing, so a home device that needs a second factor is skipped
//! (logged, exit 0); grants of such hosts are refreshed at arm+boot unlocks and
//! by `y2q admin device refresh`.
//!
//! The helper still hands the daemon one transient raw node-key copy at boot
//! (the daemon needs it for the keystore load and key derivation); the daemon
//! never receives RMK or any TPM / registry authority. Root on the live host
//! defeats this entirely.
//!
//! The arm client ([`run_arm`]) needs no hardware crate and is present in
//! every Linux build; `--key-serve` and `--key-sweep` need the `devices`
//! feature.

use std::path::Path;
use std::time::Duration;

use y2q_core::crypto::devices::keyrpc;
use zeroize::Zeroizing;

#[cfg(all(target_os = "linux", feature = "devices"))]
use std::io::Read;
#[cfg(all(target_os = "linux", feature = "devices"))]
use std::os::fd::{BorrowedFd, RawFd};
#[cfg(all(target_os = "linux", feature = "devices"))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(all(target_os = "linux", feature = "devices"))]
use std::os::unix::net::UnixStream;
#[cfg(all(target_os = "linux", feature = "devices"))]
use std::path::PathBuf;
#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::crypto::CryptoError;
#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::crypto::devices::{
    self, Authority, DeviceKind, DevicePolicy, PinProvider, roughtime::RoughtimeTimeSource,
};
#[cfg(all(target_os = "linux", feature = "devices"))]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// How long the helper waits for the client's request.
#[cfg(all(target_os = "linux", feature = "devices"))]
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on writing a reply.
#[cfg(all(target_os = "linux", feature = "devices"))]
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Name of the armed-authorization file inside the state dir.
#[cfg(all(target_os = "linux", feature = "devices"))]
const ARMED_FILE: &str = "armed";
#[cfg(all(target_os = "linux", feature = "devices"))]
const ARMED_TMP: &str = "armed.tmp";
#[cfg(all(target_os = "linux", feature = "devices"))]
const ARMED_TAKING: &str = "armed.taking";

/// Refusal text for a fetch without a prior arm. The daemon matches on the
/// substring `not armed` to add its hint.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub const NOT_ARMED: &str =
    "key agent is not armed; run `y2qd --key-arm` as root before starting the daemon";

// ---------------------------------------------------------------------------
// Arm client (every Linux build)
// ---------------------------------------------------------------------------

/// Which secrets `y2qd --key-arm` prompts for. With none set it arms with
/// empty authorization.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArmFlags {
    pub passcode: bool,
    pub pin: bool,
    pub emergency_code: bool,
}

/// `y2qd --key-arm`: prompt on `/dev/tty` and send one `arm` request to
/// `[crypto.devices] key_agent_socket`. Secrets are never echoed or logged.
pub fn run_arm(cfg: &crate::config::Config, flags: ArmFlags) -> std::io::Result<()> {
    let dev = &cfg.crypto.devices;
    if dev.key_agent_socket.is_empty() {
        return Err(std::io::Error::other(
            "--key-arm requires [crypto.devices] key_agent_socket",
        ));
    }
    let prompt = |text: &str| -> std::io::Result<Zeroizing<String>> {
        rpassword::prompt_password(text).map(Zeroizing::new)
    };
    let mut req = keyrpc::ArmRequest::default();
    if flags.passcode {
        req.passcode = Some(prompt("Home-device passcode: ")?);
    }
    if flags.pin {
        req.fido2_pin = Some(prompt("FIDO2 PIN: ")?);
    }
    if flags.emergency_code {
        req.emergency_code = Some(prompt("Emergency code: ")?);
    }
    keyrpc::arm(
        Path::new(&dev.key_agent_socket),
        &req,
        Duration::from_secs(dev.key_agent_timeout_seconds),
    )
    .map_err(|e| std::io::Error::other(e.to_string()))?;
    println!("armed: next key fetch uses the supplied authorization");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper side (DEV-GATE)
// ---------------------------------------------------------------------------

/// Everything one helper invocation needs from the config.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub struct ServeCtx {
    pub keystore_dir: PathBuf,
    pub state_dir: PathBuf,
    /// Only this uid may arm.
    pub arm_uid: u32,
    /// Only this uid may fetch. `None` refuses every fetch.
    pub peer_uid: Option<u32>,
    pub policy: DevicePolicy,
}

#[cfg(all(target_os = "linux", feature = "devices"))]
impl ServeCtx {
    pub fn from_config(cfg: &crate::config::Config) -> Self {
        let dev = &cfg.crypto.devices;
        Self {
            keystore_dir: PathBuf::from(&cfg.crypto.keystore_dir),
            state_dir: PathBuf::from(&dev.key_agent_state_dir),
            arm_uid: dev.key_agent_arm_uid,
            peer_uid: dev.key_agent_peer_uid,
            policy: dev.into(),
        }
    }
}

/// The armed authorization as stored on disk. Zeroized on drop.
#[cfg(all(target_os = "linux", feature = "devices"))]
#[derive(serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ArmedFile {
    passcode: Option<String>,
    fido2_pin: Option<String>,
    emergency_code: Option<String>,
}

/// Supplies the one-time armed material to the unlock. There is no
/// environment or terminal fallback: the helper has no terminal and must not
/// read the process environment for secrets.
#[cfg(all(target_os = "linux", feature = "devices"))]
struct ArmedAuth(ArmedFile);

#[cfg(all(target_os = "linux", feature = "devices"))]
impl PinProvider for ArmedAuth {
    fn pin(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        self.0
            .fido2_pin
            .as_ref()
            .map(|s| Zeroizing::new(s.clone()))
            .ok_or_else(|| {
                CryptoError::DeviceBackend(format!(
                    "fido2: away device '{label}' requires a PIN but none was armed: run \
                     `y2qd --key-arm --prompt-pin` as root before starting the daemon"
                ))
            })
    }

    fn passcode(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        self.0
            .passcode
            .as_ref()
            .map(|s| Zeroizing::new(s.clone()))
            .ok_or_else(|| {
                CryptoError::DeviceBackend(format!(
                    "home device '{label}' requires a passcode but none was armed: run \
                     `y2qd --key-arm --prompt-passcode` as root before starting the daemon"
                ))
            })
    }

    fn emergency_code(&self) -> Result<Option<Zeroizing<String>>, CryptoError> {
        Ok(self
            .0
            .emergency_code
            .as_ref()
            .map(|s| Zeroizing::new(s.clone())))
    }
}

/// Provider for the unattended sweep: supplies no secret of any kind.
#[cfg(all(target_os = "linux", feature = "devices"))]
struct NoAuth;

#[cfg(all(target_os = "linux", feature = "devices"))]
impl PinProvider for NoAuth {
    fn pin(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        Err(CryptoError::DeviceBackend(format!(
            "device '{label}' needs a PIN; an unattended sweep cannot supply one"
        )))
    }

    fn passcode(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        Err(CryptoError::DeviceBackend(format!(
            "home device '{label}' needs a passcode; an unattended sweep cannot supply one"
        )))
    }

    fn emergency_code(&self) -> Result<Option<Zeroizing<String>>, CryptoError> {
        Ok(None)
    }
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The state dir must exist, be a real directory (not a symlink), be owned by
/// the current uid and carry no group/other permission bits.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn check_state_dir(dir: &Path) -> Result<(), String> {
    let md = std::fs::symlink_metadata(dir).map_err(|e| {
        format!(
            "key agent state dir {} is not usable: {e}; create it mode 0700 owned by the \
             key-agent uid (systemd: RuntimeDirectory=y2q-keyd, RuntimeDirectoryMode=0700)",
            dir.display()
        )
    })?;
    if !md.is_dir() {
        return Err(format!(
            "key agent state dir {} is not a directory",
            dir.display()
        ));
    }
    if md.uid() != euid() {
        return Err(format!(
            "key agent state dir {} is owned by uid {}, not the key-agent uid {}",
            dir.display(),
            md.uid(),
            euid()
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "key agent state dir {} has mode {:04o}; it must have no group or other access (0700)",
            dir.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Atomically write the armed file: tmp + rename, mode 0600.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn write_armed(dir: &Path, armed: &ArmedFile) -> std::io::Result<()> {
    let tmp = dir.join(ARMED_TMP);
    let _ = std::fs::remove_file(&tmp);
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        serde_json::to_writer(&mut f, armed).map_err(std::io::Error::other)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, dir.join(ARMED_FILE)).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Consume the armed file. It is renamed aside first (atomic, so two
/// concurrent fetches cannot both read it), read, and deleted whatever the
/// outcome. `Ok(None)` means nothing was armed.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn take_armed(dir: &Path) -> Result<Option<ArmedFile>, String> {
    check_state_dir(dir)?;
    let taking = dir.join(ARMED_TAKING);
    match std::fs::rename(dir.join(ARMED_FILE), &taking) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot consume the armed file: {e}")),
    }
    let parsed = read_taking(&taking);
    // Fail closed: if the secrets cannot be erased, the fetch does not proceed.
    std::fs::remove_file(&taking)
        .map_err(|e| format!("cannot erase the consumed armed file: {e}"))?;
    parsed.map(Some)
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn read_taking(path: &Path) -> Result<ArmedFile, String> {
    let md = std::fs::symlink_metadata(path).map_err(|e| format!("armed file: {e}"))?;
    if !md.file_type().is_file() {
        return Err("armed file is not a regular file".to_owned());
    }
    if md.uid() != euid() || md.mode() & 0o077 != 0 {
        return Err("armed file is not owned by the key-agent uid with mode 0600".to_owned());
    }
    let cap = keyrpc::MAX_REQUEST_BYTES + 1024;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    std::fs::File::open(path)
        .and_then(|f| f.take(cap as u64).read_to_end(&mut buf))
        .map_err(|e| format!("armed file: {e}"))?;
    serde_json::from_slice::<ArmedFile>(&buf).map_err(|e| format!("armed file is corrupt: {e}"))
}

/// Describe an unlock for the daemon, with no key material.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn meta_for(outcome: &devices::UnlockOutcome) -> keyrpc::FetchMeta {
    match &outcome.authority {
        Authority::Home { id, label } => keyrpc::FetchMeta {
            kind: kind_name(DeviceKind::Tpm2).to_owned(),
            label: label.clone(),
            device_id: id.clone(),
            grants_issued: outcome.grants_issued,
            grants_erased: outcome.grants_erased,
            slot: None,
            emergency_slots_unused: outcome.emergency_slots_unused,
        },
        Authority::Away { id, label, .. } => keyrpc::FetchMeta {
            kind: kind_name(DeviceKind::Fido2).to_owned(),
            label: label.clone(),
            device_id: id.clone(),
            grants_issued: outcome.grants_issued,
            grants_erased: outcome.grants_erased,
            slot: None,
            emergency_slots_unused: outcome.emergency_slots_unused,
        },
        Authority::Emergency { index } => keyrpc::FetchMeta {
            kind: "emergency".to_owned(),
            label: String::new(),
            device_id: String::new(),
            grants_issued: 0,
            grants_erased: 0,
            slot: Some(*index),
            emergency_slots_unused: outcome.emergency_slots_unused,
        },
    }
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn kind_name(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Tpm2 => "tpm2",
        DeviceKind::Fido2 => "fido2",
    }
}

/// Unlock the registry with `armed`, holding the registry lock for the unlock
/// only.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn unlock_for_fetch(
    ctx: &ServeCtx,
    armed: ArmedFile,
) -> Result<(Zeroizing<[u8; 32]>, keyrpc::FetchMeta), CryptoError> {
    let auth = ArmedAuth(armed);
    let time = RoughtimeTimeSource::new(ctx.policy.roughtime.clone());
    let lock = devices::registry::lock_registry(&ctx.keystore_dir)?;
    let unlocked = devices::unlock(
        &ctx.keystore_dir,
        &ctx.policy,
        &auth,
        &time,
        devices::now_unix(),
    );
    drop(lock);
    let outcome = unlocked?;
    let meta = meta_for(&outcome);
    // `outcome` (node key, RMK, state key, registry) and `auth` zeroize on drop.
    Ok((outcome.node_key, meta))
}

/// Serve exactly one request on `stream`. Refusals are reported to the peer and
/// return `Ok`; `Err` means the exchange itself failed.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub fn serve_stream(mut stream: UnixStream, ctx: &ServeCtx) -> Result<(), std::io::Error> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let peer = keyrpc::peer_uid(&stream)?;
    let request = match keyrpc::read_request(&mut stream, READ_TIMEOUT) {
        Ok(r) => r,
        Err(e) => {
            let _ = keyrpc::write_error(&mut stream, &e.to_string());
            return Err(std::io::Error::other(e.to_string()));
        }
    };
    match request {
        keyrpc::Request::Arm(req) => serve_arm(&mut stream, ctx, peer, &req),
        keyrpc::Request::Fetch => serve_fetch(&mut stream, ctx, peer),
    }
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn serve_arm(
    stream: &mut UnixStream,
    ctx: &ServeCtx,
    peer: u32,
    req: &keyrpc::ArmRequest,
) -> std::io::Result<()> {
    if peer != ctx.arm_uid {
        tracing::warn!(peer_uid = peer, "key agent: arm refused for peer uid");
        return keyrpc::write_error(stream, "arm refused: peer uid is not permitted to arm");
    }
    if let Err(msg) = check_state_dir(&ctx.state_dir) {
        tracing::error!(error = %msg, "key agent: arm refused");
        return keyrpc::write_error(stream, &msg);
    }
    let armed = ArmedFile {
        passcode: req.passcode.as_ref().map(|s| s.to_string()),
        fido2_pin: req.fido2_pin.as_ref().map(|s| s.to_string()),
        emergency_code: req.emergency_code.as_ref().map(|s| s.to_string()),
    };
    if let Err(e) = write_armed(&ctx.state_dir, &armed) {
        tracing::error!(error = %e, "key agent: cannot store the armed authorization");
        return keyrpc::write_error(
            stream,
            &format!("cannot store the armed authorization: {e}"),
        );
    }
    tracing::info!(
        passcode = armed.passcode.is_some(),
        fido2_pin = armed.fido2_pin.is_some(),
        emergency_code = armed.emergency_code.is_some(),
        "key agent: armed"
    );
    keyrpc::write_arm_ok(stream)
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn serve_fetch(stream: &mut UnixStream, ctx: &ServeCtx, peer: u32) -> std::io::Result<()> {
    if ctx.peer_uid != Some(peer) {
        tracing::warn!(peer_uid = peer, "key agent: fetch refused for peer uid");
        let msg = if ctx.peer_uid.is_none() {
            "fetch refused: [crypto.devices] key_agent_peer_uid is not configured"
        } else {
            "fetch refused: peer uid is not permitted to fetch"
        };
        return keyrpc::write_error(stream, msg);
    }
    let armed = match take_armed(&ctx.state_dir) {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::warn!("key agent: fetch refused: not armed");
            return keyrpc::write_error(stream, NOT_ARMED);
        }
        Err(msg) => {
            tracing::error!(error = %msg, "key agent: fetch refused");
            return keyrpc::write_error(stream, &msg);
        }
    };
    match unlock_for_fetch(ctx, armed) {
        Ok((nk, meta)) => {
            tracing::info!(peer_uid = peer, kind = %meta.kind, "key agent: node key handed off");
            keyrpc::write_fetch_ok(stream, &nk, &meta)
        }
        Err(e) => {
            tracing::error!(error = %e, "key agent: unlock failed");
            keyrpc::write_error(stream, &e.to_string())
        }
    }
}

/// Wrap `fd` as a unix stream socket after checking it really is one
/// (`AF_UNIX`, `SOCK_STREAM`). The fd is duplicated, never taken over.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn unix_stream_from_fd(fd: RawFd) -> std::io::Result<UnixStream> {
    let not_socket = |what: &str| {
        std::io::Error::other(format!(
            "--key-serve: standard input is not a unix stream socket ({what}); it must be the \
             connection socket systemd passes to an Accept=yes socket unit"
        ))
    };
    // SAFETY: the caller passes an fd that stays open for this call (fd 0 of
    // the process, or a test fd it owns).
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let getsockopt_int = |opt: libc::c_int| -> std::io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid for writes of the sizes passed and
        // the fd is borrowed for the duration of the call.
        let rc = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&borrowed),
                libc::SOL_SOCKET,
                opt,
                (&raw mut value).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        if rc == 0 {
            Ok(value)
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    let ty = getsockopt_int(libc::SO_TYPE).map_err(|e| not_socket(&e.to_string()))?;
    if ty != libc::SOCK_STREAM {
        return Err(not_socket("socket type is not SOCK_STREAM"));
    }
    let domain = getsockopt_int(libc::SO_DOMAIN).map_err(|e| not_socket(&e.to_string()))?;
    if domain != libc::AF_UNIX {
        return Err(not_socket("socket domain is not AF_UNIX"));
    }
    Ok(UnixStream::from(borrowed.try_clone_to_owned()?))
}

/// `y2qd --key-serve`: serve exactly one connection from stdin.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub fn run_serve(cfg: &crate::config::Config) -> std::io::Result<()> {
    let stream = unix_stream_from_fd(0)?;
    serve_stream(stream, &ServeCtx::from_config(cfg))
}

/// `y2qd --key-serve` without the `devices` feature.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn run_serve(_cfg: &crate::config::Config) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "--key-serve requires a Linux build with the `devices` feature; this y2qd has no \
         TPM 2.0 or FIDO2 support",
    ))
}

/// `y2qd --key-sweep`: one grant sweep / re-mint through an unattended home
/// unlock. A home device that needs a second factor cannot be unlocked here:
/// that is logged and exits 0 (its grants are refreshed at arm+boot unlocks and
/// by `y2q admin device refresh`). Registry contention is not an error either.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub fn run_sweep(cfg: &crate::config::Config) -> std::io::Result<()> {
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);
    let policy: DevicePolicy = (&cfg.crypto.devices).into();
    let lock = match devices::registry::try_lock_registry(&keystore_dir) {
        Ok(Some(l)) => l,
        Ok(None) => {
            tracing::info!("key sweep: registry is busy; skipping this run");
            return Ok(());
        }
        Err(e) => return Err(std::io::Error::other(format!("key sweep: {e}"))),
    };
    let time = RoughtimeTimeSource::new(policy.roughtime.clone());
    let result = devices::unlock_home(&keystore_dir, &policy, &NoAuth, &time, devices::now_unix());
    drop(lock);
    match result {
        Ok(outcome) => {
            tracing::info!(
                issued = outcome.grants_issued,
                erased = outcome.grants_erased,
                "key sweep: away grants updated"
            );
            Ok(())
        }
        Err(CryptoError::DeviceUnlockUnavailable(reason)) => {
            tracing::warn!(
                %reason,
                "key sweep: no home device could be unlocked unattended (a home device with a \
                 second factor cannot be); grants not refreshed"
            );
            Ok(())
        }
        Err(e) => Err(std::io::Error::other(format!("key sweep: {e}"))),
    }
}

/// `y2qd --key-sweep` without the `devices` feature.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn run_sweep(_cfg: &crate::config::Config) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "--key-sweep requires a Linux build with the `devices` feature; this y2qd has no \
         TPM 2.0 or FIDO2 support",
    ))
}

#[cfg(all(test, target_os = "linux", feature = "devices"))]
mod tests {
    use super::*;
    use crate::node_unlock::TEST_ENV_LOCK as LOCK;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use y2q_core::crypto::devices::{EMERGENCY_KEY_ENV_VAR, NewDevice, Tpm2Params, emergency};
    use y2q_core::secmem::SecretBuf;

    const T: Duration = Duration::from_secs(10);

    fn clear_env() {
        // SAFETY: serialized on the shared test env lock.
        unsafe {
            std::env::remove_var(EMERGENCY_KEY_ENV_VAR);
            std::env::remove_var("Y2QD_NODE_KEY");
            std::env::remove_var("Y2QD_FIDO2_PIN");
        }
    }

    fn my_uid() -> u32 {
        euid()
    }

    struct Fixture {
        ks: tempfile::TempDir,
        _st: tempfile::TempDir,
        run: tempfile::TempDir,
        nk: [u8; 32],
        code: String,
    }

    impl Fixture {
        fn sock(&self) -> PathBuf {
            self.run.path().join("agent.sock")
        }

        fn state_dir(&self) -> PathBuf {
            let d = self.run.path().join("state");
            if !d.exists() {
                std::fs::create_dir(&d).unwrap();
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            d
        }

        fn ctx(&self, arm_uid: u32, peer_uid: u32) -> ServeCtx {
            let mut cfg = self.cfg(arm_uid, peer_uid);
            cfg.crypto.devices.key_agent_state_dir = self.state_dir().display().to_string();
            ServeCtx::from_config(&cfg)
        }

        fn cfg(&self, arm_uid: u32, peer_uid: u32) -> crate::config::Config {
            use figment::providers::{Format, Toml};
            let toml = format!(
                "[server]\nhost = \"127.0.0.1\"\nport = 0\n[storage]\nbase_path = \"{}\"\n\
                 [crypto]\nkeystore_dir = \"{}\"\n[crypto.devices]\n\
                 tpm_tcti = \"device:/nonexistent-tpm\"\nkey_agent_socket = \"{}\"\n\
                 key_agent_peer_uid = {peer_uid}\nkey_agent_arm_uid = {arm_uid}\n\
                 key_agent_state_dir = \"{}\"\n[auth]\n",
                self._st.path().display(),
                self.ks.path().display(),
                self.sock().display(),
                self.state_dir().display(),
            );
            figment::Figment::new()
                .merge(Toml::string(&toml))
                .extract()
                .expect("test config parses")
        }

        fn armed_path(&self) -> PathBuf {
            self.state_dir().join(ARMED_FILE)
        }
    }

    fn fixture() -> Fixture {
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let device = NewDevice {
            label: "home-test".to_owned(),
            kind: DeviceKind::Tpm2,
            tpm2: Some(Tpm2Params {
                private_b64: "AA==".to_owned(),
                public_b64: "AA==".to_owned(),
                pcr_slots: vec![7],
                pcr_bank: "sha256".to_owned(),
            }),
            fido2: None,
            secret: SecretBuf::random(32).unwrap(),
            sign_count: 0,
        };
        let mut printed: Vec<u8> = Vec::new();
        let init = emergency::init_registry(
            ks.path(),
            device,
            devices::DEFAULT_AWAY_GRANT_SECONDS,
            false,
            devices::now_unix(),
            None,
            &mut printed,
        )
        .expect("registry init");
        let code = String::from_utf8(printed)
            .unwrap()
            .lines()
            .find_map(|l| {
                let (n, code) = l.trim().split_once(": ")?;
                n.trim().parse::<u8>().ok()?;
                Some(code.trim().to_owned())
            })
            .expect("a printed code");
        let mut nk = [0u8; 32];
        nk.copy_from_slice(&init.node_key[..]);
        Fixture {
            ks,
            _st: st,
            run,
            nk,
            code,
        }
    }

    /// Serve exactly one connection on `sock` in a thread.
    fn serve_once(
        sock: &Path,
        ctx: ServeCtx,
    ) -> (UnixListener, std::thread::JoinHandle<std::io::Result<()>>) {
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock).unwrap();
        let l2 = listener.try_clone().unwrap();
        let h = std::thread::spawn(move || {
            let (conn, _) = l2.accept()?;
            serve_stream(conn, &ctx)
        });
        (listener, h)
    }

    fn arm_with(fx: &Fixture, ctx: ServeCtx, req: &keyrpc::ArmRequest) -> Result<(), CryptoError> {
        let (_l, h) = serve_once(&fx.sock(), ctx);
        let res = keyrpc::arm(&fx.sock(), req, T);
        h.join().unwrap().unwrap();
        res
    }

    fn fetch_with(fx: &Fixture, ctx: ServeCtx) -> Result<keyrpc::Fetched, CryptoError> {
        let (_l, h) = serve_once(&fx.sock(), ctx);
        let res = keyrpc::fetch(&fx.sock(), Duration::from_secs(2), T);
        h.join().unwrap().unwrap();
        res
    }

    fn arm_code(fx: &Fixture) -> keyrpc::ArmRequest {
        keyrpc::ArmRequest {
            emergency_code: Some(Zeroizing::new(fx.code.clone())),
            ..Default::default()
        }
    }

    fn err_text<T>(r: Result<T, CryptoError>) -> String {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn arm_then_fetch_returns_the_exact_key_and_metadata() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        arm_with(&fx, fx.ctx(my_uid(), my_uid()), &arm_code(&fx)).expect("arm");
        let got = fetch_with(&fx, fx.ctx(my_uid(), my_uid())).expect("fetch");
        assert_eq!(&got.node_key[..], &fx.nk[..]);
        assert_eq!(got.meta.kind, "emergency");
        assert_eq!(got.meta.slot, Some(0));
        assert_eq!(got.meta.emergency_slots_unused, 9);
        assert!(!fx.armed_path().exists(), "armed file is consumed");
        assert!(!fx.state_dir().join(ARMED_TAKING).exists());
    }

    #[test]
    fn fetch_without_arm_is_refused_and_second_fetch_too() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let text = err_text(fetch_with(&fx, fx.ctx(my_uid(), my_uid())));
        assert!(text.contains("not armed"), "{text}");

        arm_with(&fx, fx.ctx(my_uid(), my_uid()), &arm_code(&fx)).expect("arm");
        fetch_with(&fx, fx.ctx(my_uid(), my_uid())).expect("first fetch");
        let text = err_text(fetch_with(&fx, fx.ctx(my_uid(), my_uid())));
        assert!(text.contains("not armed"), "{text}");
        assert!(text.contains("y2qd --key-arm"), "{text}");
    }

    #[test]
    fn armed_file_is_consumed_even_when_the_unlock_fails() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        // Empty authorization: the emergency path is skipped and the (absent)
        // TPM cannot open the registry.
        arm_with(
            &fx,
            fx.ctx(my_uid(), my_uid()),
            &keyrpc::ArmRequest::default(),
        )
        .expect("arm");
        assert!(fx.armed_path().exists());
        let text = err_text(fetch_with(&fx, fx.ctx(my_uid(), my_uid())));
        assert!(text.contains("no registered device"), "{text}");
        assert!(!fx.armed_path().exists());
    }

    #[test]
    fn armed_file_is_0600_with_the_three_fields() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        arm_with(&fx, fx.ctx(my_uid(), my_uid()), &arm_code(&fx)).expect("arm");
        let md = std::fs::metadata(fx.armed_path()).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fx.armed_path()).unwrap()).unwrap();
        assert!(v["passcode"].is_null());
        assert!(v["fido2_pin"].is_null());
        assert_eq!(v["emergency_code"].as_str(), Some(fx.code.as_str()));
    }

    #[test]
    fn arm_from_a_non_permitted_uid_is_refused() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let text = err_text(arm_with(
            &fx,
            fx.ctx(my_uid() + 1, my_uid()),
            &arm_code(&fx),
        ));
        assert!(text.contains("not permitted to arm"), "{text}");
        assert!(!fx.armed_path().exists());
    }

    #[test]
    fn fetch_from_a_non_permitted_uid_does_not_consume_the_armed_file() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        arm_with(&fx, fx.ctx(my_uid(), my_uid()), &arm_code(&fx)).expect("arm");
        let text = err_text(fetch_with(&fx, fx.ctx(my_uid(), my_uid() + 1)));
        assert!(text.contains("not permitted to fetch"), "{text}");
        assert!(fx.armed_path().exists(), "a refused peer must not consume");
        // The permitted peer still gets the key.
        let got = fetch_with(&fx, fx.ctx(my_uid(), my_uid())).expect("fetch");
        assert_eq!(&got.node_key[..], &fx.nk[..]);
    }

    #[test]
    fn state_dir_with_group_or_other_bits_is_refused() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let dir = fx.state_dir();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let text = err_text(arm_with(&fx, fx.ctx(my_uid(), my_uid()), &arm_code(&fx)));
        assert!(text.contains("0700"), "{text}");
        assert!(!fx.armed_path().exists());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn missing_state_dir_is_refused_with_a_clear_error() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let mut ctx = fx.ctx(my_uid(), my_uid());
        ctx.state_dir = fx.run.path().join("absent");
        let text = err_text(arm_with(&fx, ctx, &arm_code(&fx)));
        assert!(text.contains("not usable"), "{text}");
    }

    #[test]
    fn run_arm_without_prompt_flags_arms_with_empty_authorization() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let cfg = fx.cfg(my_uid(), my_uid());
        let (_l, h) = serve_once(&fx.sock(), fx.ctx(my_uid(), my_uid()));
        run_arm(&cfg, ArmFlags::default()).expect("arm client");
        h.join().unwrap().unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fx.armed_path()).unwrap()).unwrap();
        assert!(
            v["passcode"].is_null() && v["fido2_pin"].is_null() && v["emergency_code"].is_null()
        );
    }

    #[test]
    fn sweep_with_no_usable_home_is_ok() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let fx = fixture();
        let cfg = fx.cfg(my_uid(), my_uid());
        run_sweep(&cfg).expect("an unusable home is not an error");
    }

    #[test]
    fn sweep_skips_when_the_registry_is_busy() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fx = fixture();
        let cfg = fx.cfg(my_uid(), my_uid());
        let held = devices::registry::lock_registry(fx.ks.path()).unwrap();
        run_sweep(&cfg).expect("busy registry is not an error");
        drop(held);
    }

    #[test]
    fn stdin_check_rejects_non_stream_sockets_and_non_sockets() {
        use std::os::fd::AsRawFd;
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(unix_stream_from_fd(a.as_raw_fd()).is_ok());

        let (d, _e) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let err = unix_stream_from_fd(d.as_raw_fd()).err().unwrap();
        assert!(err.to_string().contains("SOCK_STREAM"), "{err}");

        let f = std::fs::File::open("/dev/null").unwrap();
        let err = unix_stream_from_fd(f.as_raw_fd()).err().unwrap();
        assert!(
            err.to_string().contains("not a unix stream socket"),
            "{err}"
        );
    }
}
