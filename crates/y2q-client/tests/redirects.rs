//! `Y2qClient` must surface 3xx responses as `ClientError::Redirect` and never
//! follow them (a followed 307/308 would replay the login body).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use y2q_client::{ClientConfig, ClientError, Y2qClient};

type Seen = Arc<Mutex<Vec<String>>>;
type Responder = Arc<dyn Fn(SocketAddr) -> String + Send + Sync>;

/// One-connection-per-request HTTP/1.1 responder. Reads headers plus the full
/// `Content-Length` body, records the raw request, then answers.
async fn spawn_server(respond: Responder) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let respond = respond.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + len {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = sock.write_all(respond(addr).as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, seen)
}

fn fixed(resp: &'static str) -> Responder {
    Arc::new(move |_| resp.to_owned())
}

fn redirect_to(status: &'static str, location: String) -> Responder {
    Arc::new(move |_| {
        format!(
            "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    })
}

fn client(addr: SocketAddr) -> Y2qClient {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Y2qClient::new(ClientConfig::new(format!("http://{addr}"))).unwrap()
}

const OK_EMPTY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]";

#[tokio::test]
async fn login_does_not_follow_307_and_does_not_leak_password() {
    let (target, target_seen) = spawn_server(fixed(OK_EMPTY)).await;
    let (origin, _) = spawn_server(redirect_to(
        "307 Temporary Redirect",
        format!("http://{target}/api/v1/auth/login"),
    ))
    .await;

    let err = timeout(
        Duration::from_secs(5),
        client(origin).login("root", "hunter2", None),
    )
    .await
    .unwrap()
    .unwrap_err();

    assert!(
        matches!(err, ClientError::Redirect { status: 307, .. }),
        "{err:?}"
    );
    assert!(target_seen.lock().unwrap().is_empty());
    let text = err.to_string();
    assert!(text.contains(&target.to_string()), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

#[tokio::test]
async fn bearer_request_not_replayed_on_same_origin_redirect() {
    // Same origin, different path: reqwest would keep the bearer token and
    // issue a second request. With redirects disabled there is exactly one.
    let (origin, seen) = spawn_server(Arc::new(|addr| {
        format!(
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: http://{addr}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }))
    .await;

    let err = timeout(
        Duration::from_secs(5),
        client(origin).with_token("tok-secret").list_buckets(),
    )
    .await
    .unwrap()
    .unwrap_err();

    assert!(
        matches!(err, ClientError::Redirect { status: 308, .. }),
        "{err:?}"
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "redirect was followed: {seen:?}");
    assert!(!seen[0].contains("/elsewhere"));
}

#[tokio::test]
async fn statuses_map_as_expected() {
    // (status line, extra headers, expected location or None, expect Redirect status)
    let redirects: [(u16, &str, Option<&str>); 7] = [
        (301, "", None),
        (302, "Location: /new/path\r\n", Some("/new/path")),
        (
            303,
            "Location: http://other.example/p\r\n",
            Some("http://other.example/p"),
        ),
        (
            307,
            "Location: http://user:pw@other.example/p?token=abc#frag\r\n",
            Some("http://other.example/p"),
        ),
        (308, "Location: ftp://other.example/p\r\n", None),
        (307, "Location: javascript:alert(1)\r\n", None),
        (304, "", None),
    ];
    for (status, headers, want) in redirects {
        let resp = format!(
            "HTTP/1.1 {status} X\r\n{headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (origin, _) = spawn_server(Arc::new(move |_| resp.clone())).await;
        let err = timeout(Duration::from_secs(5), client(origin).list_buckets())
            .await
            .unwrap()
            .unwrap_err();
        let want = want.map(|w| {
            if w.starts_with('/') {
                format!("http://{origin}{w}")
            } else {
                w.to_owned()
            }
        });
        match &err {
            ClientError::Redirect {
                status: s,
                location,
            } => {
                assert_eq!(*s, status);
                assert_eq!(*location, want, "status {status}");
            }
            other => panic!("status {status}: {other:?}"),
        }
        let text = err.to_string();
        for secret in ["pw", "token", "frag", "alert"] {
            assert!(!text.contains(secret), "{text}");
        }
    }

    // Non-3xx mapping must not be shadowed by the redirect branch.
    type Check = fn(&ClientError) -> bool;
    let cases: [(u16, Check); 3] = [
        (401, |e| matches!(e, ClientError::Unauthenticated)),
        (404, |e| matches!(e, ClientError::NotFound { .. })),
        (500, |e| {
            matches!(e, ClientError::ServerError { status: 500, .. })
        }),
    ];
    for (status, check) in cases {
        let resp = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (origin, _) = spawn_server(Arc::new(move |_| resp.clone())).await;
        let err = timeout(Duration::from_secs(5), client(origin).list_buckets())
            .await
            .unwrap()
            .unwrap_err();
        assert!(check(&err), "status {status}: {err:?}");
    }
}
