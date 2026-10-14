//! `y2q admin device …` and `y2q admin emergency-keys`: local keystore surgery
//! on the device registry (`devices.json`). No alias, no HTTP.
//!
//! The real implementation exists only under DEV-GATE
//! (`target_os = "linux"` + the `devices` feature); every other build gets the
//! single "no device support" error.

#[cfg(all(target_os = "linux", feature = "devices"))]
pub use imp::{emergency_keys, run};

#[cfg(not(all(target_os = "linux", feature = "devices")))]
use crate::cli::DeviceCmd;
#[cfg(not(all(target_os = "linux", feature = "devices")))]
use crate::error::CliError;
#[cfg(not(all(target_os = "linux", feature = "devices")))]
use crate::output::OutputMode;

#[cfg(not(all(target_os = "linux", feature = "devices")))]
const NO_DEVICE_SUPPORT: &str =
    "this y2q build has no device support; rebuild with --features devices on Linux";

/// Unavailable in this build.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn run(_cmd: DeviceCmd, _mode: OutputMode) -> Result<(), CliError> {
    Err(CliError::Other(NO_DEVICE_SUPPORT.to_owned()))
}

/// Unavailable in this build.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn emergency_keys(_keystore_dir: &std::path::Path, _mode: OutputMode) -> Result<(), CliError> {
    Err(CliError::Other(NO_DEVICE_SUPPORT.to_owned()))
}

#[cfg(all(target_os = "linux", feature = "devices"))]
mod imp {
    use std::fs::File;
    use std::path::Path;
    use std::time::Duration;

    use y2q_core::crypto::CryptoError;
    use y2q_core::crypto::devices::{
        self, Authority, DeviceKind, DevicePolicy, DeviceRecord, DeviceRegistryFile, HomeFactor,
        PinProvider, RoughtimeConfig, RoughtimeServer, TimeSource, UnlockOutcome, fido2, now_unix,
        registry, roughtime, tpm2,
    };
    use y2q_core::crypto::devices::{MAX_AWAY_GRANT_SECONDS, MIN_AWAY_GRANT_SECONDS};
    use y2q_core::crypto::{keystore, node_key};
    use y2q_core::secmem::{self, Policy};
    use zeroize::Zeroizing;

    use crate::cli::{DeviceCmd, RoughtimeArgs};
    use crate::error::CliError;
    use crate::output::{OutputMode, print_json, print_table};

    const ATTESTATION_REFUSAL: &str = "a home device implies away grants, which require attested time: no Roughtime server answered — configure servers and verify with `y2q admin device check-time` first";

    fn cerr(e: CryptoError) -> CliError {
        match e {
            CryptoError::DeviceRegistryIo(msg) if msg.contains("Permission denied") => {
                CliError::Other(format!(
                    "device registry io: {msg}; device commands must run as the registry owner (the user that owns devices.json, normally the key-agent user, e.g. `sudo -u y2q-keyd y2q admin device ...`)"
                ))
            }
            e => CliError::Other(e.to_string()),
        }
    }

    fn harden() -> Result<(), CliError> {
        secmem::harden_process(Policy::BestEffort)
            .map_err(|e| CliError::Other(format!("secmem: {e}")))
    }

    /// Exclusive keystore lock, held until the returned `File` drops.
    fn lock(dir: &Path) -> Result<File, CliError> {
        keystore::acquire_lock(dir).map_err(|e| {
            CliError::Other(format!(
                "{e}; stop the daemon first (systemctl stop y2qd) — device changes need exclusive access to the keystore"
            ))
        })
    }

    /// Exclusive registry lock (`.devices.lock`), held until the returned `File` drops.
    /// The key agent's periodic sweep takes the same lock, so neither side can
    /// overwrite the other's changes.
    fn registry_lock(dir: &Path) -> Result<File, CliError> {
        registry::lock_registry(dir).map_err(|e| match e {
            CryptoError::DeviceRegistryIo(msg) if msg.contains("busy") => CliError::Other(format!(
                "{msg}; retry in a moment (the key agent holds the lock only for a few seconds per sweep) or check for another running y2q device command"
            )),
            e => cerr(e),
        })
    }

    /// Decide whether a PCR-7 policy may be sealed. PCR 7 only separates a trusted boot
    /// chain from any other bootable medium when Secure Boot is enforcing.
    fn secure_boot_decision(
        state: tpm2::SecureBootState,
        pcrs: &[u8],
        allow_off: bool,
    ) -> Result<(), String> {
        if !pcrs.contains(&7) || allow_off {
            return Ok(());
        }
        let what = match state {
            tpm2::SecureBootState::Enabled => return Ok(()),
            tpm2::SecureBootState::Disabled => "Secure Boot is disabled",
            tpm2::SecureBootState::Unknown => {
                "the Secure Boot state is unknown (non-UEFI boot, or efivarfs is unavailable)"
            }
        };
        Err(format!(
            "refusing to bind the TPM policy to PCR 7: {what}. PCR 7 only separates a trusted boot chain from any other bootable medium when Secure Boot is enforcing, so without it anyone who can boot another OS on this host can unseal the key. Enable Secure Boot, or pass --allow-secure-boot-off to accept a PCR-7 policy that any bootable medium can satisfy (test rigs only)"
        ))
    }

    fn secure_boot_precheck(pcrs: &[u8], allow_off: bool) -> Result<(), CliError> {
        let state = if pcrs.contains(&7) && !allow_off {
            tpm2::secure_boot_state()
        } else {
            tpm2::SecureBootState::Enabled
        };
        secure_boot_decision(state, pcrs, allow_off).map_err(CliError::Other)
    }

    /// PIN and passcode prompts on the controlling terminal; never from a flag or
    /// the environment. Emergency codes keep the trait default (environment).
    struct CliPins;

    impl PinProvider for CliPins {
        fn pin(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
            crate::cmd::auth::prompt_password(&format!("PIN for away device '{label}': "))
                .map_err(|e| CryptoError::DeviceBackend(format!("pin prompt: {e}")))
        }

        fn passcode(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
            crate::cmd::auth::prompt_password(&format!("Passcode for home device '{label}': "))
                .map_err(|e| CryptoError::DeviceBackend(format!("passcode prompt: {e}")))
        }
    }

    fn roughtime_cfg(a: &RoughtimeArgs) -> Result<RoughtimeConfig, CliError> {
        let cfg = RoughtimeConfig {
            servers: a
                .roughtime_server
                .iter()
                .map(|s| RoughtimeServer {
                    name: s.name.clone(),
                    addr: s.addr.clone(),
                    public_key_b64: s.public_key_b64.clone(),
                })
                .collect(),
            timeout_ms: a.roughtime_timeout_ms,
            min_responses: a.roughtime_min_responses,
        };
        cfg.validate().map_err(CliError::Other)?;
        Ok(cfg)
    }

    fn kind_str(k: DeviceKind) -> &'static str {
        match k {
            DeviceKind::Tpm2 => "tpm2",
            DeviceKind::Fido2 => "fido2",
        }
    }

    fn fmt_ts(unix: u64) -> String {
        i64::try_from(unix)
            .ok()
            .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_else(|| "-".to_owned())
    }

    /// Advisory remaining time against the host clock, prefixed `~`.
    fn fmt_remaining(not_after: u64, now: u64) -> String {
        match not_after.checked_sub(now) {
            Some(left) if left > 0 => {
                format!("~{}", humantime::format_duration(Duration::from_secs(left)))
            }
            _ => "~expired".to_owned(),
        }
    }

    fn access_of(d: &DeviceRecord) -> &'static str {
        match d.kind {
            DeviceKind::Tpm2 => "permanent",
            DeviceKind::Fido2 if d.wrap.is_some() => "permanent",
            DeviceKind::Fido2 if d.grant.is_some() => "granted",
            DeviceKind::Fido2 => "none",
        }
    }

    /// The `FACTOR` column: `-` (none), `passcode`, or `fido2:<label of the away
    /// record>` (the raw id when that record is no longer registered).
    fn factor_column<'a>(
        factor: Option<&HomeFactor>,
        label_of: &dyn Fn(&str) -> Option<&'a str>,
    ) -> String {
        match factor {
            None => "-".to_owned(),
            Some(HomeFactor::Passcode { .. }) => "passcode".to_owned(),
            Some(HomeFactor::Fido2 { device_id }) => {
                format!("fido2:{}", label_of(device_id).unwrap_or(device_id))
            }
        }
    }

    fn inventory_row(d: &DeviceRecord, reg: &DeviceRegistryFile, now: u64) -> Vec<String> {
        let (valid_until, remaining) = match &d.grant {
            Some(g) => (
                fmt_ts(g.not_after_unix),
                fmt_remaining(g.not_after_unix, now),
            ),
            None => ("-".to_owned(), "-".to_owned()),
        };
        vec![
            d.id.clone(),
            d.label.clone(),
            kind_str(d.kind).to_owned(),
            factor_column(d.home_factor.as_ref(), &|id| {
                find_record(reg, id).map(|r| r.label.as_str())
            }),
            access_of(d).to_owned(),
            valid_until,
            remaining,
            d.sign_count_last
                .map_or_else(|| "-".to_owned(), |c| c.to_string()),
            d.tpm2.as_ref().map_or_else(
                || "-".to_owned(),
                |t| {
                    t.pcr_slots
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                },
            ),
            d.fido2.as_ref().map_or_else(
                || "-".to_owned(),
                |f| if f.uv_required { "yes" } else { "no" }.to_owned(),
            ),
            fmt_ts(d.added_at_unix),
        ]
    }

    const INVENTORY_HEADERS: [&str; 11] = [
        "ID",
        "LABEL",
        "KIND",
        "FACTOR",
        "ACCESS",
        "VALID-UNTIL",
        "REMAINING",
        "SIGNCOUNT",
        "PCRS",
        "UV",
        "ADDED",
    ];

    fn print_inventory(reg: &DeviceRegistryFile, mode: OutputMode) {
        let now = now_unix();
        if mode == OutputMode::Json {
            let rows: Vec<_> = reg
                .devices
                .iter()
                .map(|d| {
                    let r = inventory_row(d, reg, now);
                    let mut m = serde_json::Map::new();
                    for (h, v) in INVENTORY_HEADERS.iter().zip(r) {
                        m.insert(h.to_lowercase(), serde_json::Value::String(v));
                    }
                    serde_json::Value::Object(m)
                })
                .collect();
            print_json(&rows);
        } else if reg.devices.is_empty() {
            println!("No devices registered; only the emergency codes can unlock this deployment");
        } else {
            let rows: Vec<Vec<String>> = reg
                .devices
                .iter()
                .map(|d| inventory_row(d, reg, now))
                .collect();
            print_table(&INVENTORY_HEADERS, &rows);
        }
    }

    fn unused_slots(reg: &DeviceRegistryFile) -> usize {
        reg.emergency_slots
            .iter()
            .filter(|s| s.wrap.is_some())
            .count()
    }

    pub fn emergency_keys(keystore_dir: &Path, mode: OutputMode) -> Result<(), CliError> {
        let reg = registry::load(keystore_dir).map_err(cerr)?;
        let unused = unused_slots(&reg);
        if mode == OutputMode::Json {
            let slots: Vec<_> = reg
                .emergency_slots
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "slot": u32::from(s.index) + 1,
                        "status": if s.wrap.is_some() { "unused" } else { "used" },
                    })
                })
                .collect();
            print_json(&serde_json::json!({
                "slots": slots,
                "unused": unused,
                "total": reg.emergency_slots.len(),
            }));
        } else {
            let rows: Vec<Vec<String>> = reg
                .emergency_slots
                .iter()
                .map(|s| {
                    vec![
                        (u32::from(s.index) + 1).to_string(),
                        if s.wrap.is_some() { "unused" } else { "used" }.to_owned(),
                    ]
                })
                .collect();
            print_table(&["SLOT", "STATUS"], &rows);
            println!("{unused} of {} unused", reg.emergency_slots.len());
        }
        Ok(())
    }

    /// The `check-time` routine: probe every server once, optionally print each
    /// result, then combine. Returns `(attested_unix, agreeing, total)`.
    fn attest(cfg: &RoughtimeConfig, print: bool) -> Result<(u64, usize, usize), CryptoError> {
        if cfg.servers.is_empty() {
            return Err(CryptoError::RoughtimeNotConfigured);
        }
        let probes = roughtime::probe_all(cfg);
        let mut pairs = Vec::new();
        let mut failures = Vec::new();
        for p in &probes {
            match &p.outcome {
                Ok(ok) => {
                    if print {
                        println!(
                            "{}  {}  ok  lower={} upper={} radi={}",
                            p.name, p.addr, ok.lower, ok.upper, ok.radi
                        );
                    }
                    pairs.push((ok.lower, ok.upper));
                }
                Err(reason) => {
                    if print {
                        println!("{}  {}  FAILED  {reason}", p.name, p.addr);
                    }
                    failures.push(format!("{}: {reason}", p.name));
                }
            }
        }
        let t = roughtime::combine_intervals(&pairs, cfg.min_responses, &failures.join("; "))?;
        Ok((t, pairs.len(), probes.len()))
    }

    fn check_time(cfg: &RoughtimeConfig) -> Result<(), CliError> {
        let (t, agreed, total) = attest(cfg, true).map_err(cerr)?;
        println!(
            "attested time: {t} ({}), {agreed} of {total} servers agreed",
            fmt_ts(t)
        );
        Ok(())
    }

    /// Everything a mutating command holds while it works. Field order is drop order:
    /// the registry lock is released before the keystore lock.
    struct Session {
        _reg_lock: File,
        _lock: File,
        out: UnlockOutcome,
        policy: DevicePolicy,
        time: roughtime::RoughtimeTimeSource,
    }

    fn open(dir: &Path, tcti: &str, rt: &RoughtimeArgs) -> Result<Session, CliError> {
        let cfg = roughtime_cfg(rt)?;
        let _lock = lock(dir)?;
        let _reg_lock = registry_lock(dir)?;
        harden()?;
        let policy = DevicePolicy {
            tpm_tcti: tcti.to_owned(),
            roughtime: cfg.clone(),
        };
        let time = roughtime::RoughtimeTimeSource::new(cfg);
        let out = devices::unlock(dir, &policy, &CliPins, &time, now_unix()).map_err(|e| match e {
            CryptoError::DeviceUnlockUnavailable(reason) => CliError::Other(format!(
                "cannot modify the registry: no registered device could unlock it; set Y2QD_EMERGENCY_KEY to one of the ten codes printed at `device init` and retry (reason: {reason})"
            )),
            e => cerr(e),
        })?;
        Ok(Session {
            _lock,
            _reg_lock,
            out,
            policy,
            time,
        })
    }

    fn insufficient(operation: &str, required: &str, by: &Authority) -> CliError {
        cerr(CryptoError::DeviceAuthorityInsufficient {
            operation: operation.to_owned(),
            required: required.to_owned(),
            by: by.describe(),
        })
    }

    fn persist(dir: &Path, out: &mut UnlockOutcome) -> Result<(), CliError> {
        registry::persist(dir, &mut out.registry, &out.registry_state_key).map_err(cerr)
    }

    pub fn run(cmd: DeviceCmd, mode: OutputMode) -> Result<(), CliError> {
        match cmd {
            DeviceCmd::Init {
                keystore_dir,
                tpm,
                fido2,
                label,
                tpm_tcti,
                pcrs,
                no_uv,
                hid_path,
                away_grant_seconds,
                permanent_away,
                adopt_existing_node_key,
                node_key_file,
                allow_secure_boot_off,
                roughtime,
            } => init(InitArgs {
                dir: &keystore_dir,
                tpm,
                fido2,
                label,
                tcti: &tpm_tcti,
                pcrs: &pcrs,
                no_uv,
                hid_path: hid_path.as_deref(),
                away_grant_seconds,
                permanent_away,
                adopt: adopt_existing_node_key,
                node_key_file: node_key_file.as_deref(),
                allow_secure_boot_off,
                roughtime: &roughtime,
            }),
            DeviceCmd::AddTpm {
                keystore_dir,
                label,
                tpm_tcti,
                pcrs,
                allow_secure_boot_off,
                roughtime,
            } => add_tpm(
                &keystore_dir,
                label,
                &tpm_tcti,
                &pcrs,
                allow_secure_boot_off,
                &roughtime,
            ),
            DeviceCmd::AddFido2 {
                keystore_dir,
                label,
                no_uv,
                hid_path,
                tpm_tcti,
                roughtime,
            } => add_fido2(
                &keystore_dir,
                label,
                no_uv,
                hid_path.as_deref(),
                &tpm_tcti,
                &roughtime,
            ),
            DeviceCmd::List { keystore_dir } => {
                let reg = registry::load(&keystore_dir).map_err(cerr)?;
                print_inventory(&reg, mode);
                Ok(())
            }
            DeviceCmd::Remove {
                keystore_dir,
                selector,
                tpm_tcti,
                roughtime,
            } => remove(&keystore_dir, &selector, &tpm_tcti, &roughtime),
            DeviceCmd::ResealTpm {
                keystore_dir,
                id,
                tpm_tcti,
                allow_secure_boot_off,
                roughtime,
            } => reseal(
                &keystore_dir,
                &id,
                &tpm_tcti,
                allow_secure_boot_off,
                &roughtime,
            ),
            DeviceCmd::SetHomeFactor {
                keystore_dir,
                selector,
                tpm_tcti,
                passcode,
                fido2,
                none: _,
                passcode_m_cost_kib,
                passcode_t_cost,
                passcode_p_cost,
                roughtime,
            } => set_home_factor(SetFactorArgs {
                dir: &keystore_dir,
                selector: &selector,
                tcti: &tpm_tcti,
                passcode,
                fido2: fido2.as_deref(),
                m_cost_kib: passcode_m_cost_kib,
                t_cost: passcode_t_cost,
                p_cost: passcode_p_cost,
                rt: &roughtime,
            }),
            DeviceCmd::Refresh {
                keystore_dir,
                tpm_tcti,
                roughtime,
            } => refresh(&keystore_dir, &tpm_tcti, &roughtime),
            DeviceCmd::SetGrantPeriod {
                keystore_dir,
                seconds,
                tpm_tcti,
                roughtime,
            } => set_grant_period(&keystore_dir, seconds, &tpm_tcti, &roughtime),
            DeviceCmd::RepairState {
                keystore_dir,
                tpm_tcti,
                allow_away_repair,
                accept_current_inventory,
            } => repair_state(
                &keystore_dir,
                &tpm_tcti,
                allow_away_repair,
                accept_current_inventory,
                mode,
            ),
            DeviceCmd::CheckTime { roughtime } => check_time(&roughtime_cfg(&roughtime)?),
        }
    }

    struct InitArgs<'a> {
        dir: &'a Path,
        tpm: bool,
        fido2: bool,
        label: Option<String>,
        tcti: &'a str,
        pcrs: &'a [u8],
        no_uv: bool,
        hid_path: Option<&'a str>,
        away_grant_seconds: u32,
        permanent_away: bool,
        adopt: bool,
        node_key_file: Option<&'a Path>,
        allow_secure_boot_off: bool,
        roughtime: &'a RoughtimeArgs,
    }

    fn init(a: InitArgs<'_>) -> Result<(), CliError> {
        use std::io::Write as _;

        if !a.tpm && !a.fido2 {
            return Err(CliError::Other(
                "`device init` requires a first device: pass --tpm or --fido2".to_owned(),
            ));
        }
        if !(MIN_AWAY_GRANT_SECONDS..=MAX_AWAY_GRANT_SECONDS).contains(&a.away_grant_seconds) {
            return Err(cerr(CryptoError::DeviceGrantPeriodInvalid {
                seconds: a.away_grant_seconds,
            }));
        }
        if a.tpm {
            secure_boot_precheck(a.pcrs, a.allow_secure_boot_off)?;
        }
        let rt_cfg = roughtime_cfg(a.roughtime)?;
        let _lock = lock(a.dir)?;
        let _reg_lock = registry_lock(a.dir)?;
        harden()?;
        if registry::exists(a.dir) {
            return Err(cerr(CryptoError::DeviceRegistryExists(
                devices::devices_path(a.dir).display().to_string(),
            )));
        }
        if a.fido2 && !a.permanent_away {
            return Err(cerr(CryptoError::DevicePermanentAwayMismatch {
                kind: DeviceKind::Fido2,
            }));
        }
        let keystore_exists = a.dir.join("keystore.json").exists();
        if keystore_exists && !a.adopt {
            return Err(CliError::Other(format!(
                "{} already contains keystore.json; a fresh registry would generate a new node key that cannot read existing data — re-run with --adopt-existing-node-key to wrap the key this deployment already uses",
                a.dir.display()
            )));
        }
        let adopted = if a.adopt {
            let file = a
                .node_key_file
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let nk = node_key::load_node_key(&file).map_err(cerr)?;
            if keystore_exists {
                keystore::verify_node_key(a.dir, &nk).map_err(cerr)?;
            }
            Some(nk)
        } else {
            None
        };
        if a.tpm && attest(&rt_cfg, false).is_err() {
            return Err(CliError::Other(ATTESTATION_REFUSAL.to_owned()));
        }

        let first = if a.tpm {
            let label = a.label.unwrap_or_else(|| "home-tpm".to_owned());
            tpm2::enroll(label, a.tcti, a.pcrs).map_err(cerr)?
        } else {
            let label = a.label.unwrap_or_else(|| "away-fido2".to_owned());
            fido2::enroll(label, !a.no_uv, &CliPins, a.hid_path).map_err(cerr)?
        };
        let (label, kind) = (first.label.clone(), first.kind);

        println!("registry: {}", devices::devices_path(a.dir).display());
        println!("away_grant_seconds: {}", a.away_grant_seconds);
        let mut stdout = std::io::stdout().lock();
        let outcome = devices::emergency::init_registry(
            a.dir,
            first,
            a.away_grant_seconds,
            a.permanent_away,
            now_unix(),
            adopted.as_deref(),
            &mut stdout,
        )
        .map_err(cerr)?;
        stdout.flush()?;
        drop(stdout);

        let id = outcome
            .registry
            .devices
            .first()
            .map(|d| d.id.clone())
            .unwrap_or_default();
        println!("device: {label} ({}) id {id}", kind_str(kind));
        if a.adopt {
            println!(
                "the operator-supplied node key still unlocks this deployment and takes precedence over devices; while it remains set the daemon never runs the device path, so away grants are never minted — remove it from the environment and config to rely on devices alone"
            );
        }
        Ok(())
    }

    fn away_wraps(reg: &DeviceRegistryFile) -> usize {
        reg.devices
            .iter()
            .filter(|d| d.kind == DeviceKind::Fido2 && d.wrap.is_some())
            .count()
    }

    fn grants(reg: &DeviceRegistryFile) -> usize {
        reg.devices.iter().filter(|d| d.grant.is_some()).count()
    }

    fn add_tpm(
        dir: &Path,
        label: String,
        tcti: &str,
        pcrs: &[u8],
        allow_secure_boot_off: bool,
        rt: &RoughtimeArgs,
    ) -> Result<(), CliError> {
        secure_boot_precheck(pcrs, allow_secure_boot_off)?;
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let operation = "add-tpm";
        let required = "a home device, or an away device with no home devices";
        match &out.authority {
            Authority::Emergency { .. } => {
                return Err(insufficient(operation, required, &out.authority));
            }
            Authority::Away { .. } if registry::home_count(&out.registry) > 0 => {
                return Err(insufficient(operation, required, &out.authority));
            }
            _ => {}
        }
        let first_home = registry::home_count(&out.registry) == 0;
        if first_home && attest(&policy.roughtime, false).is_err() {
            return Err(CliError::Other(ATTESTATION_REFUSAL.to_owned()));
        }
        let wraps_before = away_wraps(&out.registry);
        let new = tpm2::enroll(label, tcti, pcrs).map_err(cerr)?;
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        let id = registry::enroll_device(
            dir,
            &mut out.registry,
            new,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        println!("registered TPM home device {id}");
        if first_home {
            println!(
                "{wraps_before} away record(s) lost their permanent wrap; {} grant(s) minted",
                grants(&out.registry)
            );
        }
        Ok(())
    }

    fn add_fido2(
        dir: &Path,
        label: String,
        no_uv: bool,
        hid_path: Option<&str>,
        tcti: &str,
        rt: &RoughtimeArgs,
    ) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let blocked = match &out.authority {
            Authority::Emergency { .. } => true,
            Authority::Away { .. } => registry::home_count(&out.registry) > 0,
            Authority::Home { .. } => false,
        };
        if blocked {
            return Err(insufficient(
                "add-fido2",
                "a home device, or an away device with no home devices",
                &out.authority,
            ));
        }
        let new = fido2::enroll(label, !no_uv, &CliPins, hid_path).map_err(cerr)?;
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        let id = registry::enroll_device(
            dir,
            &mut out.registry,
            new,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        println!("registered FIDO2 away device {id}");
        if matches!(out.authority, Authority::Home { .. }) {
            println!(
                "no grant was minted: run `y2q admin device refresh` (or boot the daemon on the home device) to make it usable"
            );
        }
        Ok(())
    }

    fn remove(dir: &Path, selector: &str, tcti: &str, rt: &RoughtimeArgs) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        registry::remove_device(
            dir,
            &mut out.registry,
            selector,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        println!("removed device '{selector}'");
        Ok(())
    }

    fn find_record<'a>(reg: &'a DeviceRegistryFile, selector: &str) -> Option<&'a DeviceRecord> {
        reg.devices.iter().find(|d| d.id == selector).or_else(|| {
            reg.devices
                .iter()
                .find(|d| d.label.eq_ignore_ascii_case(selector))
        })
    }

    fn reseal(
        dir: &Path,
        selector: &str,
        tcti: &str,
        allow_secure_boot_off: bool,
        rt: &RoughtimeArgs,
    ) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let rec = find_record(&out.registry, selector)
            .ok_or_else(|| cerr(CryptoError::DeviceNotFound(selector.to_owned())))?;
        let id = rec.id.clone();
        let pcrs = rec.tpm2.as_ref().map(|t| {
            (
                t.pcr_slots
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                t.pcr_bank.clone(),
            )
        });
        // The check follows the record's STORED selection: resealing to PCR 7 is as
        // weak as sealing to it when Secure Boot is not enforcing.
        let stored_slots: &[u8] = rec.tpm2.as_ref().map_or(&[], |t| &t.pcr_slots);
        secure_boot_precheck(stored_slots, allow_secure_boot_off)?;
        if let Some((slots, bank)) = &pcrs {
            println!(
                "resealing '{}' to the current values of PCRs [{slots}] (bank {bank}); check this against the intended selection",
                rec.label
            );
        }
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        registry::reseal_device(
            dir,
            &mut out.registry,
            &id,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        println!("resealed device {id}");
        Ok(())
    }

    /// A passcode entered twice must match and must not be empty.
    fn check_passcode_pair(first: &str, second: &str) -> Result<(), String> {
        if first.is_empty() {
            return Err("the passcode must not be empty".to_owned());
        }
        if first != second {
            return Err("the two passcodes do not match".to_owned());
        }
        Ok(())
    }

    struct SetFactorArgs<'a> {
        dir: &'a Path,
        selector: &'a str,
        tcti: &'a str,
        passcode: bool,
        fido2: Option<&'a str>,
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
        rt: &'a RoughtimeArgs,
    }

    /// Install (`--passcode`, `--fido2`) or clear (neither) the second factor of a
    /// TPM home device.
    fn set_home_factor(a: SetFactorArgs<'_>) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(a.dir, a.tcti, a.rt)?;
        let rec = find_record(&out.registry, a.selector)
            .ok_or_else(|| cerr(CryptoError::DeviceNotFound(a.selector.to_owned())))?;
        let (home_id, home_label) = (rec.id.clone(), rec.label.clone());
        let Some(tpm_params) = rec.tpm2.clone().filter(|_| rec.kind == DeviceKind::Tpm2) else {
            return Err(CliError::Other(format!(
                "device '{home_label}' is not a home (TPM) device; only a home device carries a second factor"
            )));
        };
        let old = factor_column(rec.home_factor.as_ref(), &|id| {
            find_record(&out.registry, id).map(|r| r.label.as_str())
        });

        let tpm_secret = tpm2::unseal(&tpm_params, a.tcti).map_err(cerr)?;
        let tpm_guard = tpm_secret.unlock().map_err(|e| cerr(e.into()))?;

        let new = if a.passcode {
            let first = crate::cmd::auth::prompt_password(&format!(
                "New passcode for home device '{home_label}': "
            ))?;
            let second = crate::cmd::auth::prompt_password("Repeat the passcode: ")?;
            check_passcode_pair(&first, &second).map_err(CliError::Other)?;
            Some(
                registry::new_passcode_factor(&first, a.m_cost_kib, a.t_cost, a.p_cost)
                    .map_err(cerr)?,
            )
        } else if let Some(sel) = a.fido2 {
            let away = find_record(&out.registry, sel)
                .ok_or_else(|| cerr(CryptoError::DeviceNotFound(sel.to_owned())))?;
            let params = away
                .fido2
                .clone()
                .filter(|_| away.kind == DeviceKind::Fido2)
                .ok_or_else(|| {
                    CliError::Other(format!(
                        "device '{}' is not a FIDO2 away device; the second factor must be a registered away device",
                        away.label
                    ))
                })?;
            let (away_id, away_label) = (away.id.clone(), away.label.clone());
            let (secret, _) = fido2::hmac_secret(&params, &away_label, &CliPins).map_err(cerr)?;
            Some(devices::NewHomeFactor {
                factor: devices::HomeFactor::Fido2 { device_id: away_id },
                secret,
            })
        } else {
            None
        };
        let has_factor = new.is_some();

        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        registry::set_home_factor(
            a.dir,
            &mut out.registry,
            &home_id,
            new,
            &tpm_guard,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(a.dir, &mut out)?;

        let new_label = find_record(&out.registry, &home_id).map_or_else(
            || "-".to_owned(),
            |r| {
                factor_column(r.home_factor.as_ref(), &|id| {
                    find_record(&out.registry, id).map(|x| x.label.as_str())
                })
            },
        );
        println!("home device '{home_label}' ({home_id}): second factor {old} -> {new_label}");
        if has_factor {
            println!(
                "warning: the node can no longer boot unattended. Arm each start with `y2qd --key-arm --prompt-passcode` or `--prompt-pin`. The grant sweep timer can no longer re-mint away grants for this home device: grants refresh at attended boots and with `y2q admin device refresh`."
            );
        }
        Ok(())
    }

    fn refresh(dir: &Path, tcti: &str, rt: &RoughtimeArgs) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        let n = registry::refresh_grants(
            dir,
            &mut out.registry,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        let until = out
            .registry
            .devices
            .iter()
            .filter_map(|d| d.grant.as_ref().map(|g| g.not_after_unix))
            .max();
        match until {
            Some(t) => println!("issued {n} grant(s), valid until {}", fmt_ts(t)),
            None => println!("issued {n} grant(s)"),
        }
        Ok(())
    }

    fn set_grant_period(
        dir: &Path,
        seconds: u32,
        tcti: &str,
        rt: &RoughtimeArgs,
    ) -> Result<(), CliError> {
        let Session {
            _lock,
            _reg_lock,
            mut out,
            policy,
            time,
        } = open(dir, tcti, rt)?;
        let old = out.registry.away_grant_seconds;
        let ctx = registry::Ctx {
            time: &time as &dyn TimeSource,
            now_host: now_unix(),
            policy: &policy,
            pins: &CliPins,
        };
        registry::set_grant_period(
            dir,
            &mut out.registry,
            seconds,
            &out.node_key,
            &out.registry_master_key,
            &out.authority,
            &ctx,
        )
        .map_err(cerr)?;
        persist(dir, &mut out)?;
        println!("away_grant_seconds: {old} -> {seconds}");
        println!(
            "every existing grant was dropped; grants are re-minted only under home authority ({} now held)",
            grants(&out.registry)
        );
        Ok(())
    }

    fn repair_state(
        dir: &Path,
        tcti: &str,
        allow_away_repair: bool,
        accept: bool,
        mode: OutputMode,
    ) -> Result<(), CliError> {
        let _lock = lock(dir)?;
        let _reg_lock = registry_lock(dir)?;
        harden()?;
        let reg = registry::load(dir).map_err(cerr)?;
        println!("repair-state will apply these rules:");
        println!("  - every away grant is dropped; no grant is ever minted");
        println!(
            "  - sign_count_last is kept as found (compare with a pre-incident `device list`)"
        );
        println!("  - emergency slots are left as found, except a slot this repair burns itself");
        println!("  - record identity is re-signed as found:");
        print_inventory(&reg, mode);
        println!("emergency slots (printed sheet is one-based):");
        for s in &reg.emergency_slots {
            println!(
                "  slot {}: {}",
                u32::from(s.index) + 1,
                if s.wrap.is_some() { "unused" } else { "used" }
            );
        }
        let policy = DevicePolicy {
            tpm_tcti: tcti.to_owned(),
            roughtime: RoughtimeConfig {
                servers: vec![],
                timeout_ms: 3000,
                min_responses: 2,
            },
        };
        let authority = registry::repair_state_entry(
            dir,
            now_unix(),
            &policy,
            &CliPins,
            allow_away_repair,
            accept,
        )
        .map_err(cerr)?;
        println!(
            "registry state repaired under {}; all grants dropped",
            authority.describe()
        );
        println!(
            "run `y2q admin device remove` then `add-fido2` for every away record: a lowered signature counter cannot be restored"
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::cli::parse_roughtime_server;

        #[test]
        fn server_flag_keeps_trailing_equals_of_base64() {
            let s = parse_roughtime_server("a=127.0.0.1:2002=AAAA/BBBB+CCCC=").unwrap();
            assert_eq!(s.name, "a");
            assert_eq!(s.addr, "127.0.0.1:2002");
            assert_eq!(s.public_key_b64, "AAAA/BBBB+CCCC=");
        }

        #[test]
        fn server_flag_rejects_malformed() {
            assert!(parse_roughtime_server("only-name").is_err());
            assert!(parse_roughtime_server("a=b").is_err());
            assert!(parse_roughtime_server("a==key").is_err());
        }

        #[test]
        fn roughtime_flags_run_core_validation() {
            let key = "A".repeat(43) + "=";
            let mk = |names: [&str; 2], keys: [&str; 2]| RoughtimeArgs {
                roughtime_server: vec![
                    parse_roughtime_server(&format!("{}=h:1={}", names[0], keys[0])).unwrap(),
                    parse_roughtime_server(&format!("{}=h:2={}", names[1], keys[1])).unwrap(),
                ],
                roughtime_min_responses: 2,
                roughtime_timeout_ms: 3000,
            };
            let other = "Q".repeat(43) + "=";
            assert!(roughtime_cfg(&mk(["a", "b"], [&key, &other])).is_ok());
            assert!(roughtime_cfg(&mk(["a", "a"], [&key, &other])).is_err());
            assert!(roughtime_cfg(&mk(["a", "b"], [&key, &key])).is_err());
            assert!(roughtime_cfg(&mk(["a", "b"], ["short", &key])).is_err());
        }

        #[test]
        fn secure_boot_decision_matrix() {
            use tpm2::SecureBootState::{Disabled, Enabled, Unknown};
            for state in [Enabled, Disabled, Unknown] {
                for pcrs in [&[7u8][..], &[0, 4, 7][..], &[0, 4][..]] {
                    for allow in [false, true] {
                        let refused = secure_boot_decision(state, pcrs, allow).is_err();
                        let expect = state != Enabled && pcrs.contains(&7) && !allow;
                        assert_eq!(refused, expect, "{state:?} {pcrs:?} allow={allow}");
                    }
                }
            }
            let msg = secure_boot_decision(Disabled, &[7], false).unwrap_err();
            assert!(msg.contains("disabled") && msg.contains("--allow-secure-boot-off"));
            let msg = secure_boot_decision(Unknown, &[7], false).unwrap_err();
            assert!(msg.contains("unknown"));
        }

        #[test]
        fn remaining_and_timestamps() {
            assert_eq!(fmt_remaining(100, 100), "~expired");
            assert_eq!(fmt_remaining(50, 100), "~expired");
            assert_eq!(fmt_remaining(130, 100), "~30s");
            assert_eq!(fmt_ts(0), "1970-01-01T00:00:00Z");
        }

        #[test]
        fn reseal_precheck_uses_stored_slots() {
            use tpm2::SecureBootState::{Disabled, Enabled, Unknown};
            // A record sealed to PCR 7 is refused when Secure Boot is not enforcing...
            assert!(secure_boot_decision(Disabled, &[7], false).is_err());
            assert!(secure_boot_decision(Unknown, &[0, 4, 7], false).is_err());
            // ...unless explicitly allowed, or Secure Boot is on.
            assert!(secure_boot_decision(Disabled, &[7], true).is_ok());
            assert!(secure_boot_decision(Enabled, &[7], false).is_ok());
            // A record that never bound PCR 7 is never refused, whatever the state.
            assert!(secure_boot_decision(Disabled, &[0, 4], false).is_ok());
            // The precheck the command runs: stored slots, with the state probe skipped
            // when the selection does not include PCR 7.
            assert!(secure_boot_precheck(&[0, 4], false).is_ok());
            assert!(secure_boot_precheck(&[7], true).is_ok());
        }

        #[test]
        fn factor_column_formats() {
            let lookup = |id: &str| (id == "aa").then_some("away-key1");
            assert_eq!(factor_column(None, &lookup), "-");
            let pass = HomeFactor::Passcode {
                salt_b64: String::new(),
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            };
            assert_eq!(factor_column(Some(&pass), &lookup), "passcode");
            let f = HomeFactor::Fido2 {
                device_id: "aa".to_owned(),
            };
            assert_eq!(factor_column(Some(&f), &lookup), "fido2:away-key1");
            let gone = HomeFactor::Fido2 {
                device_id: "bb".to_owned(),
            };
            assert_eq!(factor_column(Some(&gone), &lookup), "fido2:bb");
        }

        #[test]
        fn passcode_confirmation_rules() {
            assert!(check_passcode_pair("correct horse", "correct horse").is_ok());
            assert!(check_passcode_pair("a", "b").is_err());
            assert!(check_passcode_pair("", "").is_err());
        }

        #[test]
        fn cli_defaults_match_core_passcode_costs() {
            use clap::Parser as _;
            let cli = crate::cli::Cli::try_parse_from([
                "y2q",
                "admin",
                "device",
                "set-home-factor",
                "--keystore-dir",
                "/k",
                "home",
                "--passcode",
            ])
            .unwrap();
            let Some(crate::cli::Commands::Admin {
                cmd:
                    crate::cli::AdminCmd::Device {
                        cmd:
                            DeviceCmd::SetHomeFactor {
                                passcode_m_cost_kib,
                                passcode_t_cost,
                                passcode_p_cost,
                                ..
                            },
                    },
            }) = cli.command
            else {
                panic!("not set-home-factor");
            };
            assert_eq!(passcode_m_cost_kib, registry::DEFAULT_PASSCODE_M_COST_KIB);
            assert_eq!(passcode_t_cost, registry::DEFAULT_PASSCODE_T_COST);
            assert_eq!(passcode_p_cost, registry::DEFAULT_PASSCODE_P_COST);
        }

        #[test]
        fn set_home_factor_flags_are_exclusive() {
            use clap::Parser as _;
            let parse = |extra: &[&str]| {
                let mut args = vec![
                    "y2q",
                    "admin",
                    "device",
                    "set-home-factor",
                    "--keystore-dir",
                    "/k",
                    "home",
                ];
                args.extend_from_slice(extra);
                crate::cli::Cli::try_parse_from(args)
            };
            assert!(parse(&["--passcode"]).is_ok());
            assert!(parse(&["--fido2", "away-key1"]).is_ok());
            assert!(parse(&["--none"]).is_ok());
            assert!(parse(&[]).is_err());
            assert!(parse(&["--passcode", "--none"]).is_err());
            assert!(parse(&["--passcode", "--fido2", "k"]).is_err());
            assert!(parse(&["--fido2", "k", "--none"]).is_err());
            assert!(parse(&["--none", "--passcode-t-cost", "2"]).is_err());
            assert!(parse(&["--fido2", "k", "--passcode-m-cost-kib", "8"]).is_err());
            assert!(parse(&["--passcode", "--passcode-t-cost", "2"]).is_ok());
        }
    }
}
