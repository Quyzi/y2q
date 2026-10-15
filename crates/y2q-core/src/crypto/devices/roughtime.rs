//! Attested time from Roughtime (RFC 10049) servers.
//!
//! The only time input to a grant decision. There is no host-clock fallback:
//! if too few servers answer, or the answers are inconsistent, the caller gets
//! an error and the away unlock fails.
//!
//! Trust chain is Ed25519 (RFC 10049 §9.5), which is not quantum resistant;
//! it binds freshness only, never at-rest confidentiality.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use roughenough_client::Client;
use roughenough_protocol::tags::pubk::PublicKey;

use super::types::*;
use crate::crypto::CryptoError;

/// Largest RADI (seconds) a response may carry and still be used. A conservative
/// cap of our own (RFC 10049 sets none); it bounds the expiry slack at 2 × 60 s.
pub(crate) const MAX_RADIUS_S: u32 = 60;

/// RFC 10049 §5.2.5 forbids radius 0; radii above [`MAX_RADIUS_S`] are too loose.
pub(crate) fn usable_radius(radius_s: u32) -> bool {
    radius_s != 0 && radius_s <= MAX_RADIUS_S
}

/// A verified measurement from one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOk {
    pub lower: u64,
    pub upper: u64,
    pub radi: u32,
}

/// Result of querying one configured server.
#[derive(Debug, Clone)]
pub struct ServerProbe {
    pub name: String,
    pub addr: String,
    /// `Err` carries the resolution, key, query or radius failure reason.
    pub outcome: Result<ProbeOk, String>,
}

fn probe_one(
    server: &RoughtimeServer,
    timeout: Duration,
    seen: &mut HashMap<SocketAddr, String>,
) -> Result<ProbeOk, String> {
    let resolved = server
        .addr
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", server.addr))?
        .next()
        .ok_or_else(|| format!("{} resolved to no address", server.addr))?;
    if let Some(earlier) = seen.get(&resolved) {
        return Err(format!(
            "address {resolved} duplicates server '{earlier}'; two entries for one endpoint are not independent sources"
        ));
    }
    seen.insert(resolved, server.name.clone());

    let decoded = STANDARD
        .decode(server.public_key_b64.trim())
        .map_err(|e| format!("public_key_b64 is not valid base64: {e}"))?;
    let key = <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| format!("public key is {} bytes, expected 32", decoded.len()))?;

    let client = Client::builder(resolved)
        .hostname(&server.name)
        .public_key(PublicKey::from(&key[..]))
        .timeout(timeout)
        .build();
    let m = client.query().map_err(|e| format!("query failed: {e}"))?;
    let radi = m.radius();
    if !usable_radius(radi) {
        return Err(format!(
            "radius {radi}s outside the usable range 1..={MAX_RADIUS_S}s"
        ));
    }
    Ok(ProbeOk {
        lower: m.lower_bound(),
        upper: m.upper_bound(),
        radi,
    })
}

/// Query every configured server once, sequentially, in configuration order.
/// Returns one entry per server. Never returns early on a per-server failure.
pub fn probe_all(cfg: &RoughtimeConfig) -> Vec<ServerProbe> {
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let mut seen: HashMap<SocketAddr, String> = HashMap::new();
    cfg.servers
        .iter()
        .map(|s| {
            let outcome = probe_one(s, timeout, &mut seen);
            if let Err(reason) = &outcome {
                tracing::warn!(server = %s.name, reason = %reason, "roughtime measurement rejected");
            }
            ServerProbe {
                name: s.name.clone(),
                addr: s.addr.clone(),
                outcome,
            }
        })
        .collect()
}

/// Probe every server once and combine the answers: the `check-time` routine.
/// `on_probe` sees each server's result as it is evaluated. Returns
/// `(attested_unix, agreeing, total)`; an empty server list is
/// [`CryptoError::RoughtimeNotConfigured`].
pub fn attest_with(
    cfg: &RoughtimeConfig,
    on_probe: &mut dyn FnMut(&ServerProbe),
) -> Result<(u64, usize, usize), CryptoError> {
    if cfg.servers.is_empty() {
        return Err(CryptoError::RoughtimeNotConfigured);
    }
    let probes = probe_all(cfg);
    let mut pairs = Vec::new();
    let mut failures = Vec::new();
    for p in &probes {
        on_probe(p);
        match &p.outcome {
            Ok(ok) => pairs.push((ok.lower, ok.upper)),
            Err(reason) => failures.push(format!("{}: {reason}", p.name)),
        }
    }
    let t = combine_intervals(&pairs, cfg.min_responses, &failures.join("; "))?;
    Ok((t, pairs.len(), probes.len()))
}

/// Quorum, consistency and `max(L)` rules over surviving `(lower, upper)` pairs.
pub fn combine_intervals(
    intervals: &[(u64, u64)],
    min_responses: u8,
    failures: &str,
) -> Result<u64, CryptoError> {
    if intervals.len() < usize::from(min_responses) {
        return Err(CryptoError::AttestedTimeUnavailable(format!(
            "{} of {} required servers answered{}{}",
            intervals.len(),
            min_responses,
            if failures.is_empty() { "" } else { ": " },
            failures
        )));
    }
    let low = intervals.iter().map(|&(l, _)| l).max();
    let high = intervals.iter().map(|&(_, u)| u).min();
    match (low, high) {
        (Some(low), Some(high)) if low <= high => Ok(low),
        (Some(low), Some(high)) => Err(CryptoError::AttestedTimeInconsistent { low, high }),
        // Empty set with min_responses == 0: nothing was attested.
        _ => Err(CryptoError::AttestedTimeUnavailable(
            "no measurements".to_owned(),
        )),
    }
}

/// Production [`TimeSource`]: Roughtime quorum over UDP.
pub struct RoughtimeTimeSource {
    cfg: RoughtimeConfig,
}

impl RoughtimeTimeSource {
    pub fn new(cfg: RoughtimeConfig) -> Self {
        Self { cfg }
    }
}

impl TimeSource for RoughtimeTimeSource {
    fn attested_now(&self) -> Result<u64, CryptoError> {
        if self.cfg.servers.is_empty() {
            return Err(CryptoError::RoughtimeNotConfigured);
        }
        let probes = probe_all(&self.cfg);
        let mut pairs = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for p in &probes {
            match &p.outcome {
                Ok(ok) => pairs.push((ok.lower, ok.upper)),
                Err(e) => failures.push(format!("{}: {e}", p.name)),
            }
        }
        combine_intervals(&pairs, self.cfg.min_responses, &failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    fn server(name: &str, addr: &str, key: &[u8]) -> RoughtimeServer {
        RoughtimeServer {
            name: name.to_owned(),
            addr: addr.to_owned(),
            public_key_b64: STANDARD.encode(key),
        }
    }

    fn cfg(servers: Vec<RoughtimeServer>) -> RoughtimeConfig {
        RoughtimeConfig {
            servers,
            timeout_ms: 300,
            min_responses: 2,
        }
    }

    #[test]
    fn attest_with_no_servers_is_not_configured() {
        let mut seen = 0;
        let e = attest_with(&cfg(vec![]), &mut |_| seen += 1).unwrap_err();
        assert!(matches!(e, CryptoError::RoughtimeNotConfigured));
        assert_eq!(seen, 0);
    }

    #[test]
    fn combine_too_few() {
        let e = combine_intervals(&[(1, 5)], 2, "a: down").unwrap_err();
        assert!(matches!(&e, CryptoError::AttestedTimeUnavailable(s) if s.contains("a: down")));
    }

    #[test]
    fn combine_inconsistent() {
        let e = combine_intervals(&[(10, 12), (20, 30)], 2, "").unwrap_err();
        assert!(matches!(
            e,
            CryptoError::AttestedTimeInconsistent { low: 20, high: 12 }
        ));
    }

    #[test]
    fn combine_success_and_boundary() {
        assert_eq!(combine_intervals(&[(10, 40), (20, 30)], 2, "").unwrap(), 20);
        assert_eq!(combine_intervals(&[(10, 20), (20, 30)], 2, "").unwrap(), 20);
    }

    #[test]
    fn radius_bounds() {
        assert!(!usable_radius(0));
        assert!(usable_radius(1));
        assert!(usable_radius(60));
        assert!(!usable_radius(61));
    }

    #[test]
    fn empty_servers() {
        let src = RoughtimeTimeSource::new(cfg(vec![]));
        assert!(matches!(
            src.attested_now(),
            Err(CryptoError::RoughtimeNotConfigured)
        ));
    }

    #[test]
    fn short_key_is_failure_not_panic() {
        let probes = probe_all(&cfg(vec![server("s", "127.0.0.1:9", &[7u8; 31])]));
        assert_eq!(probes.len(), 1);
        let e = probes[0].outcome.as_ref().unwrap_err();
        assert!(e.contains("31 bytes"), "{e}");
    }

    #[test]
    fn duplicate_address_is_failure() {
        let probes = probe_all(&cfg(vec![
            server("first", "127.0.0.1:9", &[7u8; 31]),
            server("second", "127.0.0.1:9", &[8u8; 32]),
        ]));
        let e = probes[1].outcome.as_ref().unwrap_err();
        assert!(e.contains("duplicates server 'first'"), "{e}");
    }

    fn server_bin() -> Option<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let mut candidates: Vec<std::path::PathBuf> = std::env::var_os("PATH")
            .map(|paths| {
                std::env::split_paths(&paths)
                    .map(|d| d.join("roughenough_server"))
                    .collect()
            })
            .unwrap_or_default();
        if let Some(home) = std::env::var_os("HOME") {
            candidates
                .push(std::path::Path::new(&home).join(".cache/y2q-rt/bin/roughenough_server"));
        }
        candidates.push("/tmp/y2q-rt/bin/roughenough_server".into());
        // `/tmp` may be mounted noexec; a file that cannot be run counts as absent.
        candidates.into_iter().find(|p| {
            p.metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
                && Command::new(p)
                    .arg("--help")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok()
        })
    }

    struct Spawned(Child);
    impl Drop for Spawned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_server(bin: &std::path::Path, seed: &std::path::Path, port: u16) -> (Spawned, String) {
        let mut child = Command::new(bin)
            .args(["--seed-file"])
            .arg(seed)
            .args(["-i", "127.0.0.1", "-p", &port.to_string(), "-j", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn roughenough_server");
        // The key line may land on either stream; merge by scanning both.
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        for r in [
            Box::new(out) as Box<dyn std::io::Read + Send>,
            Box::new(err),
        ] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(r).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        let spawned = Spawned(child);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(line) = rx.recv_timeout(Duration::from_millis(100))
                && let Some(i) = line.find("PUBK(")
            {
                let hex: String = line[i + 5..]
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                assert_eq!(hex.len(), 64, "unexpected key line: {line}");
                let bytes: Vec<u8> = (0..32)
                    .map(|k| u8::from_str_radix(&hex[2 * k..2 * k + 2], 16).unwrap())
                    .collect();
                // Keep draining so the child never blocks on a full pipe.
                std::thread::spawn(move || while rx.recv().is_ok() {});
                return (spawned, STANDARD.encode(bytes));
            }
        }
        panic!("roughenough_server did not print its public key");
    }

    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn attested_now_against_local_servers() {
        let Some(bin) = server_bin() else {
            eprintln!("skipping roughtime e2e: roughenough_server not installed");
            return;
        };
        let dir = std::env::temp_dir().join(format!("y2q-rt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut servers = Vec::new();
        let mut guards = Vec::new();
        for (i, seed_hex) in ["11".repeat(32), "22".repeat(32)].iter().enumerate() {
            let seed = dir.join(format!("seed{i}"));
            {
                use std::io::Write as _;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&seed)
                    .unwrap();
                f.write_all(seed_hex.as_bytes()).unwrap();
            }
            let port = free_udp_port();
            let (g, key_b64) = spawn_server(&bin, &seed, port);
            guards.push(g);
            servers.push(RoughtimeServer {
                name: format!("local-{i}"),
                addr: format!("127.0.0.1:{port}"),
                public_key_b64: key_b64,
            });
        }
        let src = RoughtimeTimeSource::new(RoughtimeConfig {
            servers,
            timeout_ms: 3000,
            min_responses: 2,
        });
        let got = src.attested_now();
        let _ = std::fs::remove_dir_all(&dir);
        let now = super::super::now_unix();
        let got = got.expect("attested_now");
        assert!(got.abs_diff(now) <= 10, "attested {got} vs host {now}");
    }
}
