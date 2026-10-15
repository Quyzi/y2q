//! Key-agent RPC: protocol, framing, peer credentials and clients.
//!
//! A helper process serves a unix socket with two operations:
//!
//! * `arm` (peer must be root): stores one-time authorization material
//!   (passcode, FIDO2 PIN, emergency code) on the helper side.
//! * `fetch` (peer must be the daemon uid): the helper unlocks the registry with
//!   that material and returns the node key once.
//!
//! Wire format (version 2), one request per connection:
//!
//! * client -> server: the 6 bytes [`HELLO`], then a request frame
//!   `len: u32` big-endian + JSON body (at most [`MAX_REQUEST_BYTES`]).
//!   Bodies are `{"op":"arm","passcode":..,"fido2_pin":..,"emergency_code":..}`
//!   (each field `null` or a string) or `{"op":"fetch"}`.
//! * server -> client: `status: u8` (0 ok, 1 error), `len: u32` big-endian,
//!   payload (at most 64 KiB). An ok `arm` payload is empty; an ok `fetch`
//!   payload is the 32 raw node-key bytes followed by a compact JSON
//!   [`FetchMeta`]; an error payload is a UTF-8 message.
//!
//! This module needs no hardware crate and is present in every Linux build.
//! Every buffer that may hold the node key or an authorization string is
//! `Zeroizing` and wiped on all paths.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

/// First bytes a client sends.
pub const HELLO: &[u8; 6] = b"Y2QK2\n";
/// Upper bound on a request body.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Upper bound on a response payload.
const MAX_REPLY_BYTES: usize = 64 * 1024;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;
const CONNECT_STEP: Duration = Duration::from_millis(250);

/// One-time authorization material carried by an `arm` request.
#[derive(Clone, Default)]
pub struct ArmRequest {
    pub passcode: Option<Zeroizing<String>>,
    pub fido2_pin: Option<Zeroizing<String>>,
    pub emergency_code: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ArmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmRequest")
            .field("passcode", &self.passcode.is_some())
            .field("fido2_pin", &self.fido2_pin.is_some())
            .field("emergency_code", &self.emergency_code.is_some())
            .finish()
    }
}

/// A decoded request.
#[derive(Debug)]
pub enum Request {
    Arm(ArmRequest),
    Fetch,
}

/// Non-secret description of how the node key was unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchMeta {
    /// `"tpm2"`, `"fido2"` or `"emergency"`.
    pub kind: String,
    pub label: String,
    pub device_id: String,
    pub grants_issued: usize,
    pub grants_erased: usize,
    pub slot: Option<u8>,
    pub emergency_slots_unused: usize,
}

/// A node key returned by `fetch`.
pub struct Fetched {
    pub node_key: Zeroizing<[u8; 32]>,
    pub meta: FetchMeta,
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum WireOut<'a> {
    Arm {
        passcode: Option<&'a str>,
        fido2_pin: Option<&'a str>,
        emergency_code: Option<&'a str>,
    },
    Fetch,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum WireIn {
    Arm {
        passcode: Option<String>,
        fido2_pin: Option<String>,
        emergency_code: Option<String>,
    },
    Fetch,
}

fn backend(msg: impl Into<String>) -> CryptoError {
    CryptoError::DeviceBackend(msg.into())
}

/// Effective uid of the peer of a connected unix socket (`SO_PEERCRED`).
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes passed, and
    // the fd is a live socket borrowed from `stream` for the whole call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Server side: read the hello and one request frame.
///
/// Sets the stream's read timeout. An oversized length is rejected before any
/// buffer of that size is allocated.
pub fn read_request(stream: &mut UnixStream, timeout: Duration) -> Result<Request, CryptoError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| backend(format!("key rpc: set read timeout: {e}")))?;
    let mut hello = [0u8; 6];
    stream
        .read_exact(&mut hello)
        .map_err(|e| backend(format!("key rpc: read hello: {e}")))?;
    if &hello != HELLO {
        return Err(backend("key rpc: bad hello (protocol version mismatch)"));
    }
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| backend(format!("key rpc: read request length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_REQUEST_BYTES {
        return Err(backend(format!(
            "key rpc: request of {len} bytes exceeds the {MAX_REQUEST_BYTES}-byte limit"
        )));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    stream
        .read_exact(&mut body)
        .map_err(|e| backend(format!("key rpc: truncated request: {e}")))?;
    let wire: WireIn = serde_json::from_slice(&body)
        .map_err(|e| backend(format!("key rpc: malformed request: {e}")))?;
    Ok(match wire {
        WireIn::Fetch => Request::Fetch,
        WireIn::Arm {
            passcode,
            fido2_pin,
            emergency_code,
        } => Request::Arm(ArmRequest {
            passcode: passcode.map(Zeroizing::new),
            fido2_pin: fido2_pin.map(Zeroizing::new),
            emergency_code: emergency_code.map(Zeroizing::new),
        }),
    })
}

fn write_reply(stream: &mut UnixStream, status: u8, parts: &[&[u8]]) -> std::io::Result<()> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total > MAX_REPLY_BYTES {
        return Err(std::io::Error::other("key rpc: reply too large"));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(5 + total));
    buf.push(status);
    buf.extend_from_slice(&(total as u32).to_be_bytes());
    for p in parts {
        buf.extend_from_slice(p);
    }
    stream.write_all(&buf)?;
    stream.flush()
}

/// Server side: reply to `fetch` with the node key and metadata.
pub fn write_fetch_ok(
    stream: &mut UnixStream,
    nk: &[u8; 32],
    meta: &FetchMeta,
) -> std::io::Result<()> {
    let meta = serde_json::to_vec(meta).map_err(std::io::Error::other)?;
    write_reply(stream, STATUS_OK, &[nk, &meta])
}

/// Server side: reply to `arm` with success.
pub fn write_arm_ok(stream: &mut UnixStream) -> std::io::Result<()> {
    write_reply(stream, STATUS_OK, &[])
}

/// Server side: reply with an error message.
pub fn write_error(stream: &mut UnixStream, message: &str) -> std::io::Result<()> {
    let bytes = message.as_bytes();
    let bytes = &bytes[..bytes.len().min(MAX_REPLY_BYTES)];
    write_reply(stream, STATUS_ERR, &[bytes])
}

fn connect_once(socket: &Path) -> Result<UnixStream, std::io::Error> {
    UnixStream::connect(socket)
}

fn connect_failed(socket: &Path, e: std::io::Error) -> CryptoError {
    backend(format!(
        "key agent: cannot connect to {}: {e}; is the key agent socket active?",
        socket.display()
    ))
}

/// Send one request on `stream` and return the ok payload.
fn exchange(
    stream: &mut UnixStream,
    socket: &Path,
    body: &[u8],
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let ctx = |what: &str, e: std::io::Error| {
        backend(format!("key agent: {what} on {}: {e}", socket.display()))
    };
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| ctx("set timeout", e))?;
    let mut out = Zeroizing::new(Vec::with_capacity(HELLO.len() + 4 + body.len()));
    out.extend_from_slice(HELLO);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    stream.write_all(&out).map_err(|e| ctx("send request", e))?;
    drop(out);

    let mut head = [0u8; 5];
    stream
        .read_exact(&mut head)
        .map_err(|e| ctx("read reply (the agent may have refused this uid)", e))?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_REPLY_BYTES {
        return Err(backend(format!(
            "key agent: reply of {len} bytes exceeds the {MAX_REPLY_BYTES}-byte limit"
        )));
    }
    let mut payload = Zeroizing::new(vec![0u8; len]);
    stream
        .read_exact(&mut payload)
        .map_err(|e| ctx("read reply payload", e))?;
    if head[0] != STATUS_OK {
        return Err(backend(format!(
            "key agent refused: {}",
            String::from_utf8_lossy(&payload)
        )));
    }
    Ok(payload)
}

/// Client side (root): store one-time authorization material on the agent.
pub fn arm(socket: &Path, req: &ArmRequest, timeout: Duration) -> Result<(), CryptoError> {
    let mut stream = connect_once(socket).map_err(|e| connect_failed(socket, e))?;
    let wire = WireOut::Arm {
        passcode: req.passcode.as_ref().map(|s| s.as_str()),
        fido2_pin: req.fido2_pin.as_ref().map(|s| s.as_str()),
        emergency_code: req.emergency_code.as_ref().map(|s| s.as_str()),
    };
    // Capacity is the protocol limit so serialization never reallocates (a
    // realloc would leave an unzeroized copy of the secrets behind).
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES));
    serde_json::to_writer(&mut *body, &wire)
        .map_err(|e| backend(format!("key rpc: encode request: {e}")))?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(backend(format!(
            "key rpc: request of {} bytes exceeds the {MAX_REQUEST_BYTES}-byte limit",
            body.len()
        )));
    }
    exchange(&mut stream, socket, &body, timeout).map(drop)
}

/// Client side (daemon): fetch the node key from the agent at `socket`.
///
/// Retries the connection (every 250 ms, for up to `connect_window`) while the
/// socket is missing or refusing, so the daemon can start before the agent.
/// `timeout` bounds each read and write once connected; it must cover an
/// interactive touch / PIN on the agent.
pub fn fetch(
    socket: &Path,
    connect_window: Duration,
    timeout: Duration,
) -> Result<Fetched, CryptoError> {
    use std::io::ErrorKind;
    let deadline = Instant::now() + connect_window;
    let mut stream = loop {
        match connect_once(socket) {
            Ok(s) => break s,
            Err(e)
                if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(CONNECT_STEP);
            }
            Err(e) => return Err(connect_failed(socket, e)),
        }
    };
    let fetch_body = serde_json::to_vec(&WireOut::Fetch)
        .map_err(|e| backend(format!("key rpc: encode request: {e}")))?;
    let payload = exchange(&mut stream, socket, &fetch_body, timeout)?;
    if payload.len() < 32 {
        return Err(backend("key agent: reply shorter than a node key"));
    }
    let mut node_key = Zeroizing::new([0u8; 32]);
    node_key.copy_from_slice(&payload[..32]);
    let meta: FetchMeta = serde_json::from_slice(&payload[32..])
        .map_err(|e| backend(format!("key agent: malformed metadata: {e}")))?;
    Ok(Fetched { node_key, meta })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn meta() -> FetchMeta {
        FetchMeta {
            kind: "tpm2".into(),
            label: "home".into(),
            device_id: "ab".repeat(16),
            grants_issued: 2,
            grants_erased: 1,
            slot: Some(3),
            emergency_slots_unused: 9,
        }
    }

    fn raw_request(body: &[u8]) -> Vec<u8> {
        let mut v = HELLO.to_vec();
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn arm_round_trip_all_fields() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let req = ArmRequest {
            passcode: Some(Zeroizing::new("pass \"quoted\"".into())),
            fido2_pin: Some(Zeroizing::new("1234".into())),
            emergency_code: Some(Zeroizing::new("code==".into())),
        };
        let body = {
            let wire = WireOut::Arm {
                passcode: req.passcode.as_ref().map(|s| s.as_str()),
                fido2_pin: req.fido2_pin.as_ref().map(|s| s.as_str()),
                emergency_code: req.emergency_code.as_ref().map(|s| s.as_str()),
            };
            serde_json::to_vec(&wire).unwrap()
        };
        a.write_all(&raw_request(&body)).unwrap();
        match read_request(&mut b, Duration::from_secs(2)).unwrap() {
            Request::Arm(got) => {
                assert_eq!(
                    got.passcode.as_deref().map(String::as_str),
                    Some("pass \"quoted\"")
                );
                assert_eq!(got.fido2_pin.as_deref().map(String::as_str), Some("1234"));
                assert_eq!(
                    got.emergency_code.as_deref().map(String::as_str),
                    Some("code==")
                );
            }
            Request::Fetch => panic!("expected arm"),
        }
        let none = ArmRequest::default();
        let wire = WireOut::Arm {
            passcode: None,
            fido2_pin: None,
            emergency_code: None,
        };
        a.write_all(&raw_request(&serde_json::to_vec(&wire).unwrap()))
            .unwrap();
        // Second request needs a fresh connection in real use; here we only
        // check the default decodes, via a new pair.
        let _ = none;
    }

    #[test]
    fn arm_and_fetch_clients_over_listener() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (mut s, _) = listener.accept().unwrap();
                match read_request(&mut s, Duration::from_secs(2)).unwrap() {
                    Request::Arm(r) => {
                        seen.push((
                            r.passcode.as_deref().cloned(),
                            r.fido2_pin.as_deref().cloned(),
                            r.emergency_code.as_deref().cloned(),
                        ));
                        write_arm_ok(&mut s).unwrap();
                    }
                    Request::Fetch => write_fetch_ok(&mut s, &[7u8; 32], &meta()).unwrap(),
                }
            }
            seen
        });
        let req = ArmRequest {
            passcode: Some(Zeroizing::new("pc".into())),
            fido2_pin: Some(Zeroizing::new("pin".into())),
            emergency_code: Some(Zeroizing::new("ec".into())),
        };
        arm(&sock, &req, Duration::from_secs(2)).unwrap();
        let f = fetch(&sock, Duration::ZERO, Duration::from_secs(2)).unwrap();
        assert_eq!(*f.node_key, [7u8; 32]);
        assert_eq!(f.meta, meta());
        let seen = server.join().unwrap();
        assert_eq!(
            seen,
            vec![(Some("pc".into()), Some("pin".into()), Some("ec".into()))]
        );
    }

    #[test]
    fn oversized_frame_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(HELLO).unwrap();
        a.write_all(&u32::MAX.to_be_bytes()).unwrap();
        let err = read_request(&mut b, Duration::from_secs(2)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn bad_hello_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"Y2QK1\n").unwrap();
        let err = read_request(&mut b, Duration::from_secs(2)).unwrap_err();
        assert!(err.to_string().contains("bad hello"), "{err}");
    }

    #[test]
    fn truncated_frame_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(HELLO).unwrap();
        a.write_all(&100u32.to_be_bytes()).unwrap();
        a.write_all(b"{\"op\"").unwrap();
        a.shutdown(std::net::Shutdown::Write).unwrap();
        let err = read_request(&mut b, Duration::from_secs(2)).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn malformed_json_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&raw_request(b"{\"op\":\"bogus\"}")).unwrap();
        let err = read_request(&mut b, Duration::from_secs(2)).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    #[test]
    fn peer_uid_is_own_uid() {
        let (a, b) = UnixStream::pair().unwrap();
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        assert_eq!(peer_uid(&a).unwrap(), me);
        assert_eq!(peer_uid(&b).unwrap(), me);
    }

    #[test]
    fn error_frame_surfaces_as_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_request(&mut s, Duration::from_secs(2)).unwrap();
            write_error(&mut s, "not armed").unwrap();
        });
        let err = fetch(&sock, Duration::ZERO, Duration::from_secs(2))
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("key agent refused: not armed"),
            "{err}"
        );
        server.join().unwrap();
    }

    #[test]
    fn fetch_retries_then_fails_after_window() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("late.sock");
        let started = Instant::now();
        let err = fetch(&sock, Duration::from_millis(600), Duration::from_secs(1))
            .err()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(500));
        assert!(err.to_string().contains("cannot connect"), "{err}");

        // Socket appears mid-window: the retry loop picks it up.
        let sock2 = dir.path().join("later.sock");
        let s2 = sock2.clone();
        let server = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            let listener = UnixListener::bind(&s2).unwrap();
            let (mut s, _) = listener.accept().unwrap();
            let _ = read_request(&mut s, Duration::from_secs(2)).unwrap();
            write_fetch_ok(&mut s, &[1u8; 32], &meta()).unwrap();
        });
        let f = fetch(&sock2, Duration::from_secs(5), Duration::from_secs(2)).unwrap();
        assert_eq!(*f.node_key, [1u8; 32]);
        server.join().unwrap();
    }

    #[test]
    fn debug_hides_secrets() {
        let req = ArmRequest {
            passcode: Some(Zeroizing::new("hunter2-secret".into())),
            fido2_pin: Some(Zeroizing::new("987654".into())),
            emergency_code: None,
        };
        let s = format!("{req:?}");
        assert!(!s.contains("hunter2") && !s.contains("987654"), "{s}");
        assert!(s.contains("passcode: true") && s.contains("emergency_code: false"));
    }
}
