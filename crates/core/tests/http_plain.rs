//! Offline tests against a local plain-HTTP server: request headers as they
//! reach the server, redirects, per-request options, proxies in absolute
//! form, connection reuse.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Method;
use koon_core::client::Body;
use koon_core::{Chrome, Client, Error, Firefox, RequestOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A request as the server saw it.
#[derive(Clone, Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Local HTTP/1.1 server with keep-alive that records every request.
///
/// Routes: `/redirect` → 302 to `/final`, `/see-other` → 303 to `/final`,
/// `/303?to=URL` and `/307?to=URL` → that redirect to URL, `/slow` →
/// responds after 2 s, `/cookie` → sets a cookie, anything else → 200 "ok".
struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<Mutex<usize>>,
}

impl Server {
    async fn start() -> Server {
        Server::serve_on(TcpListener::bind("127.0.0.1:0").await.unwrap())
    }

    /// Serve on a port that was reserved earlier, from synchronous code
    /// inside the runtime (a request hook).
    fn start_on_port(port: u16) -> Server {
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        Server::serve_on(TcpListener::from_std(listener).unwrap())
    }

    fn serve_on(listener: TcpListener) -> Server {
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(0));
        let (s, c) = (seen.clone(), connections.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                *c.lock().unwrap() += 1;
                tokio::spawn(serve(stream, s.clone()));
            }
        });
        Server {
            port,
            seen,
            connections,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn last(&self) -> Seen {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a request")
    }

    fn all(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn serve(mut stream: TcpStream, seen: Arc<Mutex<Vec<Seen>>>) {
    let mut buf = Vec::new();
    loop {
        // Read one request head.
        let head_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
        let request_line = lines.next().unwrap_or_default().to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        buf.drain(..head_end);
        let chunked = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v == "chunked");
        let body = if chunked {
            match read_chunked(&mut stream, &mut buf).await {
                Some(body) => body,
                None => return,
            }
        } else {
            let length: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            while buf.len() < length {
                if !fill(&mut stream, &mut buf).await {
                    return;
                }
            }
            buf.drain(..length).collect()
        };

        let path = request_line.split(' ').nth(1).unwrap_or("/").to_string();
        seen.lock().unwrap().push(Seen {
            request_line,
            headers,
            body,
        });

        let redirect_to = ["/303?to=", "/307?to="]
            .iter()
            .find_map(|prefix| path.strip_prefix(prefix).map(|to| (&prefix[1..4], to)));
        let dynamic;
        let response: &[u8] = if let Some((status, to)) = redirect_to {
            dynamic = format!(
                "HTTP/1.1 {status} Redirect\r\nlocation: {to}\r\ncontent-length: 0\r\n\r\n"
            );
            dynamic.as_bytes()
        } else if path.ends_with("/redirect") {
            b"HTTP/1.1 302 Found\r\nlocation: /final\r\ncontent-length: 0\r\n\r\n"
        } else if path.ends_with("/see-other") {
            b"HTTP/1.1 303 See Other\r\nlocation: /final\r\ncontent-length: 0\r\n\r\n"
        } else if path.ends_with("/cookie") {
            b"HTTP/1.1 200 OK\r\nset-cookie: sid=abc; Path=/\r\ncontent-length: 2\r\n\r\nok"
        } else if path.ends_with("/slow") {
            tokio::time::sleep(Duration::from_secs(2)).await;
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
        } else {
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
        };
        if stream.write_all(response).await.is_err() {
            return;
        }
    }
}

/// Read more bytes into `buf`; false at EOF.
async fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    match stream.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

/// Decode a chunked request body from `buf` and `stream`.
async fn read_chunked(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                break pos;
            }
            if !fill(stream, buf).await {
                return None;
            }
        };
        let size = usize::from_str_radix(std::str::from_utf8(&buf[..line_end]).ok()?, 16).ok()?;
        buf.drain(..line_end + 2);
        while buf.len() < size + 2 {
            if !fill(stream, buf).await {
                return None;
            }
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
        if size == 0 {
            return Some(body);
        }
    }
}

fn names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(k, _)| k.as_str()).collect()
}

#[tokio::test]
async fn request_headers_match_the_wire() {
    let server = Server::start().await;
    let client = Client::new(Firefox::latest()).unwrap();
    let resp = client
        .send(
            Method::GET,
            &server.url("/"),
            None,
            RequestOptions {
                headers: vec![
                    ("X-Zeta".into(), "1".into()),
                    ("X-Alpha".into(), "2".into()),
                ],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let seen = server.last();
    assert_eq!(seen.request_line, "GET / HTTP/1.1");
    assert_eq!(resp.request_headers, seen.headers);
    assert_eq!(seen.headers[0].0, "Host");
    // Loopback is a secure context: fetch metadata stays.
    assert!(names(&seen.headers).contains(&"Sec-Fetch-Mode"));
    let pos = |n: &str| names(&seen.headers).iter().position(|k| *k == n).unwrap();
    assert!(pos("X-Zeta") < pos("X-Alpha"));
}

/// A header value with UTF-8 goes out as its bytes, as in browsers.
#[tokio::test]
async fn utf8_header_values_go_out_as_bytes() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let options = RequestOptions {
        headers: vec![("X-Note".into(), "caf\u{e9}".into())],
        ..RequestOptions::default()
    };
    let resp = client
        .send(Method::GET, &server.url("/"), Body::empty(), options)
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let seen = server.last();
    let note = seen.headers.iter().find(|(k, _)| k == "X-Note").unwrap();
    assert_eq!(note.1, "caf\u{e9}");
}

#[tokio::test]
async fn redirects_follow_and_can_be_stopped_per_request() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();

    let resp = client.get(&server.url("/redirect")).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.url.ends_with("/final"));

    let resp = client
        .send(
            Method::GET,
            &server.url("/redirect"),
            None,
            RequestOptions {
                follow_redirects: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 302);

    let resp = client
        .send(
            Method::GET,
            &server.url("/redirect"),
            None,
            RequestOptions {
                on_redirect: Some(Arc::new(|status, url, _| {
                    assert_eq!(status, 302);
                    assert!(url.ends_with("/final"));
                    Ok(false)
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 302);

    let err = client
        .send(
            Method::GET,
            &server.url("/redirect"),
            None,
            RequestOptions {
                max_redirects: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::TooManyRedirects));
}

/// The error a hook returns fails the request with it: a failing
/// `on_request` before anything is sent, `on_response` after the head (its
/// cookies stored), `on_redirect` instead of following. Never retried.
#[tokio::test]
async fn a_failing_hook_fails_the_request_with_its_error() {
    #[derive(Debug)]
    struct Refused(&'static str);
    impl std::fmt::Display for Refused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Refused {}
    let hook_error = |err: Error| match err {
        Error::Hook(inner) => inner.downcast::<Refused>().expect("the hook's own error").0,
        other => panic!("expected the hook's error, got {other}"),
    };

    let server = Server::start().await;
    let client = Client::builder(Chrome::latest())
        .max_retries(2)
        .on_request(|_, url| {
            if url.split('?').next().unwrap().ends_with("/blocked") {
                return Err(Error::Hook(Box::new(Refused("blocked"))));
            }
            Ok(())
        })
        .build()
        .unwrap();
    let err = client.get(&server.url("/blocked")).await.unwrap_err();
    assert_eq!(err.code(), "HOOK_ERROR");
    assert_eq!(hook_error(err), "blocked");
    assert!(server.all().is_empty(), "nothing was sent");
    // A redirect to a blocked URL is not followed either.
    let err = client
        .get(&server.url("/307?to=/blocked"))
        .await
        .unwrap_err();
    assert_eq!(hook_error(err), "blocked");
    assert_eq!(server.all().len(), 1);

    let err = client
        .send(
            Method::GET,
            &server.url("/cookie"),
            None,
            RequestOptions {
                on_response: Some(Arc::new(|_, _, _| {
                    Err(Error::Hook(Box::new(Refused("response"))))
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(hook_error(err), "response");
    assert_eq!(server.all().len(), 2, "sent once, not retried");
    assert_eq!(client.cookie_params()[0].name, "sid");

    let err = client
        .send(
            Method::GET,
            &server.url("/redirect"),
            None,
            RequestOptions {
                on_redirect: Some(Arc::new(|_, _, _| {
                    Err(Error::Hook(Box::new(Refused("redirect"))))
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(hook_error(err), "redirect");
    let paths: Vec<String> = server.all().into_iter().map(|s| s.request_line).collect();
    assert_eq!(paths.last().unwrap(), "GET /redirect HTTP/1.1", "{paths:?}");
}

#[tokio::test]
async fn post_redirect_switches_to_get_and_drops_body_headers() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let resp = client
        .send(
            Method::POST,
            &server.url("/see-other"),
            Some(b"a=1".to_vec()),
            RequestOptions {
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let seen = server.all();
    assert_eq!(seen[0].request_line, "POST /see-other HTTP/1.1");
    assert_eq!(seen[0].body, b"a=1");
    let last = seen.last().unwrap();
    assert_eq!(last.request_line, "GET /final HTTP/1.1");
    assert!(last.body.is_empty());
    assert!(
        !names(&last.headers)
            .iter()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
    );
}

#[tokio::test]
async fn connections_are_reused() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let first = client.get(&server.url("/a")).await.unwrap();
    let second = client.get(&server.url("/b")).await.unwrap();
    assert!(!first.connection_reused);
    assert!(second.connection_reused);
    assert_eq!(*server.connections.lock().unwrap(), 1);
}

#[tokio::test]
async fn per_request_timeout_covers_the_whole_request() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let err = client
        .send(
            Method::GET,
            &server.url("/slow"),
            None,
            RequestOptions {
                timeout: Some(Duration::from_millis(200)),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout));
}

#[tokio::test]
async fn cookies_round_trip_over_plain_http() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    client.get(&server.url("/cookie")).await.unwrap();
    client.get(&server.url("/next")).await.unwrap();
    let seen = server.last();
    let cookie = seen
        .headers
        .iter()
        .find(|(k, _)| k == "Cookie")
        .map(|(_, v)| v.as_str());
    assert_eq!(cookie, Some("sid=abc"));
}

#[tokio::test]
async fn http_proxy_gets_plain_requests_in_absolute_form() {
    // The recording server acts as the proxy: it answers every request.
    let proxy = Server::start().await;
    let client = Client::builder(Chrome::latest())
        .proxy(&format!("http://user:pass@127.0.0.1:{}", proxy.port))
        .unwrap()
        .build()
        .unwrap();
    let resp = client.get("http://example.test/x?y=1").await.unwrap();
    assert_eq!(resp.status, 200);
    let seen = proxy.last();
    assert_eq!(seen.request_line, "GET http://example.test/x?y=1 HTTP/1.1");
    // Chrome 153 through an HTTP proxy to an http:// site (not a secure
    // context): no client hints, no fetch metadata, no Priority, no
    // Brotli/Zstandard; Proxy-Connection instead of Connection.
    assert_eq!(
        names(&seen.headers),
        vec![
            "Host",
            "Proxy-Connection",
            "Proxy-Authorization",
            "Upgrade-Insecure-Requests",
            "User-Agent",
            "Accept",
            "Accept-Encoding",
            "Accept-Language"
        ]
    );
    assert_eq!(seen.headers[0].1, "example.test");
    assert_eq!(seen.headers[2].1, "Basic dXNlcjpwYXNz");
    assert_eq!(seen.headers[6].1, "gzip, deflate");
    assert_eq!(resp.request_headers, seen.headers);
}

#[tokio::test]
async fn firefox_plain_http_through_proxy() {
    let proxy = Server::start().await;
    let client = Client::builder(Firefox::latest())
        .proxy(&format!("http://127.0.0.1:{}", proxy.port))
        .unwrap()
        .build()
        .unwrap();
    client.get("http://example.test/").await.unwrap();
    // Firefox 156 captured through a proxy: Connection stays, Priority stays.
    assert_eq!(
        names(&proxy.last().headers),
        vec![
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "Upgrade-Insecure-Requests",
            "Priority"
        ]
    );
}

/// A port nothing listens on (yet).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A server that reads one request per connection and closes the connection
/// without answering. Counts the requests it read.
async fn black_hole() -> (u16, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(Mutex::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                *c.lock().unwrap() += 1;
            });
        }
    });
    (port, count)
}

/// A server that closes every connection right away, so a TLS handshake
/// with it fails before any request is sent.
async fn closer() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    port
}

/// A server whose connections answer their first request and close on the
/// second one without an answer, like a server that closes an idle
/// keep-alive connection just as a request arrives. Records the request
/// lines, with the number of the connection.
async fn one_shot() -> (u16, Arc<Mutex<Vec<(usize, String)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<(usize, String)>>> = Arc::default();
    let s = seen.clone();
    tokio::spawn(async move {
        let mut connection = 0;
        while let Ok((mut stream, _)) = listener.accept().await {
            connection += 1;
            let (s, id) = (s.clone(), connection);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                for answered in [true, false] {
                    let end = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if !fill(&mut stream, &mut buf).await {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < end + length {
                        if !fill(&mut stream, &mut buf).await {
                            return;
                        }
                    }
                    buf.drain(..end + length);
                    let line = head.lines().next().unwrap_or_default().to_string();
                    s.lock().unwrap().push((id, line));
                    if !answered {
                        return;
                    }
                    let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                    if stream.write_all(ok).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, seen)
}

/// A request on a pooled keep-alive connection that closes before any
/// response byte is sent again on a new connection, POST included, as in
/// Chrome: without retries configured.
#[tokio::test]
async fn a_reused_connection_closed_before_the_response_resends() {
    let (port, seen) = one_shot().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let url = format!("http://127.0.0.1:{port}/");
    assert_eq!(client.get(&url).await.unwrap().status, 200);
    let resp = client.post(&url, Some(b"a=1".to_vec())).await.unwrap();
    assert_eq!(resp.status, 200);
    assert!(!resp.connection_reused);
    let lines: Vec<(usize, String)> = seen.lock().unwrap().clone();
    assert_eq!(
        lines,
        [
            (1, "GET / HTTP/1.1".to_string()),
            (1, "POST / HTTP/1.1".to_string()),
            (2, "POST / HTTP/1.1".to_string()),
        ]
    );
}

fn posts(server: &Server) -> usize {
    server
        .all()
        .iter()
        .filter(|s| s.request_line.starts_with("POST"))
        .count()
}

#[tokio::test]
async fn a_retry_after_a_redirect_resends_only_the_failed_hop() {
    let server = Server::start().await;
    let port = free_port();
    let target = format!("http://127.0.0.1:{port}/final");
    let late: Arc<Mutex<Option<Server>>> = Arc::new(Mutex::new(None));
    let attempts = Arc::new(Mutex::new(0));
    let (l, a, t) = (late.clone(), attempts.clone(), target.clone());
    let client = Client::builder(Chrome::latest())
        .max_retries(1)
        .build()
        .unwrap();
    let resp = client
        .send(
            Method::POST,
            &server.url(&format!("/303?to={target}")),
            Some(b"a=1".to_vec()),
            RequestOptions {
                on_request: Some(Arc::new(move |_, url| {
                    if url == t {
                        let mut n = a.lock().unwrap();
                        *n += 1;
                        // The first GET finds the port closed (a failure
                        // before sending); its retry finds a server.
                        if *n == 2 {
                            *l.lock().unwrap() = Some(Server::start_on_port(port));
                        }
                    }
                    Ok(())
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.url, target);
    assert_eq!(posts(&server), 1, "the POST that got its 303 is not resent");
    assert_eq!(*attempts.lock().unwrap(), 2);
    let late = late
        .lock()
        .unwrap()
        .take()
        .expect("retry started the server");
    assert_eq!(late.all().len(), 1);
    assert_eq!(late.last().request_line, "GET /final HTTP/1.1");
}

#[tokio::test]
async fn a_non_idempotent_hop_is_retried_only_before_it_was_sent() {
    let server = Server::start().await;
    let client = Client::builder(Chrome::latest())
        .max_retries(2)
        .build()
        .unwrap();

    // 307 keeps the POST. It reaches the server, which drops the
    // connection: the POST may have been processed and is not repeated.
    let (hole, received) = black_hole().await;
    let err = client
        .post(
            &server.url(&format!("/307?to=http://127.0.0.1:{hole}/x")),
            Some(b"a=1".to_vec()),
        )
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(*received.lock().unwrap(), 1);
    assert_eq!(posts(&server), 1);

    // A TLS handshake failure happens before the request leaves: the POST
    // hop is retried, the POST that got the 307 is not.
    let closed = closer().await;
    let attempts = Arc::new(Mutex::new(0));
    let a = attempts.clone();
    let err = client
        .send(
            Method::POST,
            &server.url(&format!("/307?to=https://127.0.0.1:{closed}/x")),
            Some(b"a=1".to_vec()),
            RequestOptions {
                on_request: Some(Arc::new(move |_, url| {
                    if url.starts_with("https://") {
                        *a.lock().unwrap() += 1;
                    }
                    Ok(())
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(err.is_tls_error(), "{err}");
    assert_eq!(*attempts.lock().unwrap(), 3);
    assert_eq!(posts(&server), 2);
}

#[tokio::test]
async fn a_redirect_to_an_unsupported_scheme_is_not_retried() {
    let server = Server::start().await;
    let client = Client::builder(Chrome::latest())
        .max_retries(3)
        .build()
        .unwrap();
    let err = client
        .post(
            &server.url("/303?to=ftp://example.test/"),
            Some(b"a".to_vec()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedScheme(_)), "{err}");
    assert_eq!(posts(&server), 1);
}

/// A stream of `parts`, as a request body.
fn parts(
    parts: &[&'static str],
) -> impl futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static {
    let parts: Vec<std::io::Result<bytes::Bytes>> = parts
        .iter()
        .map(|p| Ok(bytes::Bytes::from_static(p.as_bytes())))
        .collect();
    futures_util::stream::iter(parts)
}

#[tokio::test]
async fn stream_bodies_are_framed_like_byte_bodies() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();

    client.post(&server.url("/a"), "hello world").await.unwrap();
    let bytes = server.last();
    client
        .post(
            &server.url("/b"),
            Body::sized_stream(parts(&["hello", " ", "world"]), 11),
        )
        .await
        .unwrap();
    let sized = server.last();
    client
        .post(
            &server.url("/c"),
            Body::stream(parts(&["hello", "", " world"])),
        )
        .await
        .unwrap();
    let chunked = server.last();

    for seen in [&bytes, &sized, &chunked] {
        assert_eq!(seen.body, b"hello world");
    }
    // A known length is sent like a byte body: same headers, same order.
    assert_eq!(bytes.headers, sized.headers);
    // Without one, Transfer-Encoding takes Content-Length's place.
    let position =
        |headers: &[(String, String)], name: &str| headers.iter().position(|(k, _)| k == name);
    assert_eq!(
        position(&chunked.headers, "Transfer-Encoding"),
        position(&bytes.headers, "Content-Length")
    );
    assert!(!names(&chunked.headers).contains(&"Content-Length"));
    assert_eq!(bytes.headers.len(), chunked.headers.len());
}

#[tokio::test]
async fn a_stream_body_of_the_wrong_length_fails() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let err = client
        .post(&server.url("/"), Body::sized_stream(parts(&["abc"]), 5))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Body(..)), "{err}");
}

#[tokio::test]
async fn a_stream_body_is_retried_only_before_it_was_read() {
    // The first attempt finds the port closed (before the body was read),
    // the retry a server: the whole body arrives.
    let port = free_port();
    let target = format!("http://127.0.0.1:{port}/upload");
    let late: Arc<Mutex<Option<Server>>> = Arc::new(Mutex::new(None));
    let attempts = Arc::new(Mutex::new(0));
    let (l, a, t) = (late.clone(), attempts.clone(), target.clone());
    let client = Client::builder(Chrome::latest())
        .max_retries(1)
        .build()
        .unwrap();
    let resp = client
        .send(
            Method::PUT,
            &target,
            Body::stream(parts(&["streamed ", "body"])),
            RequestOptions {
                on_request: Some(Arc::new(move |_, url| {
                    if url == t {
                        let mut n = a.lock().unwrap();
                        *n += 1;
                        if *n == 2 {
                            *l.lock().unwrap() = Some(Server::start_on_port(port));
                        }
                    }
                    Ok(())
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(*attempts.lock().unwrap(), 2);
    let late = late.lock().unwrap().take().unwrap();
    assert_eq!(late.last().body, b"streamed body");

    // Once read, it cannot be sent again: an idempotent PUT whose
    // connection dies after sending is not retried.
    let (hole, received) = black_hole().await;
    let err = client
        .put(
            &format!("http://127.0.0.1:{hole}/upload"),
            Body::stream(parts(&["abc"])),
        )
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    assert_eq!(*received.lock().unwrap(), 1);
}

#[tokio::test]
async fn redirects_of_a_stream_body_follow_fetch() {
    let server = Server::start().await;
    let client = Client::new(Chrome::latest()).unwrap();
    let final_url = server.url("/final");

    // 307 would have to send the stream again: a network error.
    let err = client
        .post(
            &server.url(&format!("/307?to={final_url}")),
            Body::stream(parts(&["abc"])),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Body(..)), "{err}");

    // 303 turns it into a GET without a body.
    let resp = client
        .post(
            &server.url(&format!("/303?to={final_url}")),
            Body::stream(parts(&["abc"])),
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    let seen = server.all();
    assert_eq!(seen.last().unwrap().request_line, "GET /final HTTP/1.1");
    assert_eq!(posts(&server), 2, "each POST went out once");
}

/// After the closing handshake, the client closes its connection as a
/// browser does, instead of leaving it half-open until the socket is
/// dropped: a server waiting for the end of the connection (Node's
/// `server.close()`) would wait forever.
#[tokio::test]
async fn a_closed_websocket_closes_its_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            assert!(fill(&mut stream, &mut buf).await, "handshake cut off");
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let key = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .expect("a Sec-WebSocket-Key")
            .trim()
            .to_string();
        let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        // The client's masked Close frame: opcode, length, mask, code.
        let mut frame = [0u8; 8];
        stream.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame[0], 0x88, "a Close frame");
        // Answer it, and end our side as servers do.
        stream.write_all(&[0x88, 2, 0x03, 0xe8]).await.unwrap();
        stream.shutdown().await.unwrap();
        // The client now closes its side: the read ends.
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut rest))
            .await
            .expect("the client closed the connection")
            .unwrap();
    });

    let client = Client::new(Chrome::latest()).unwrap();
    let ws = client
        .websocket(&format!("ws://127.0.0.1:{port}/"))
        .await
        .unwrap();
    ws.close(Some(1000), None).await.unwrap();
    assert!(ws.receive().await.unwrap().is_none());
    // `ws` is still alive: the connection ended because the handshake did.
    server.await.unwrap();
    let late = ws.send_text("late").await.unwrap_err();
    assert_eq!(late.code(), "WEBSOCKET_ERROR");
    assert!(ws.receive().await.unwrap().is_none());
    ws.close(Some(1000), None).await.unwrap();
}
