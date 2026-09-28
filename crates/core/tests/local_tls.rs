//! Offline tests against a local HTTP/2 server: streamed request bodies
//! and flow-control backpressure.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use koon_core::client::Body;
use koon_core::{Chrome, Client};
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;

/// A Chrome client that accepts the local servers' certificates.
fn client() -> Client {
    let mut profile = Chrome::latest();
    profile.tls.danger_accept_invalid_certs = true;
    Client::new(profile).unwrap()
}

/// A request an upload server received: its Content-Length header and the
/// body bytes.
type Received = Arc<Mutex<Vec<(Option<String>, Vec<u8>)>>>;

/// An HTTP/2 server that reads each request body once `release` is true
/// and answers with the number of bytes it read.
async fn h2_server(release: watch::Receiver<bool>) -> (u16, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Received = Arc::default();
    let (cert, key) = common::leaf("127.0.0.1");
    let acceptor = common::h2_acceptor(&cert, &key);
    let seen = received.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            let (seen, release) = (seen.clone(), release.clone());
            tokio::spawn(async move {
                Pin::new(&mut tls).accept().await.unwrap();
                let mut h2 = http2::server::handshake(tls).await.unwrap();
                // Accepting drives the connection: requests run beside it.
                while let Some(Ok((request, mut respond))) = h2.accept().await {
                    let (seen, mut release) = (seen.clone(), release.clone());
                    tokio::spawn(async move {
                        let _ = release.wait_for(|go| *go).await;
                        let length = request
                            .headers()
                            .get("content-length")
                            .map(|v| v.to_str().unwrap().to_string());
                        let mut body = request.into_body();
                        let mut data = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            let _ = body.flow_control().release_capacity(chunk.len());
                            data.extend_from_slice(&chunk);
                        }
                        let answer = data.len().to_string();
                        seen.lock().unwrap().push((length, data));
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from(answer), true).unwrap();
                    });
                }
            });
        }
    });
    (port, received)
}

/// `count` chunks of 64 KiB; `pulled` counts the bytes taken from the
/// stream.
fn counted_chunks(
    count: usize,
    pulled: Arc<AtomicUsize>,
) -> impl futures_util::Stream<Item = std::io::Result<Bytes>> + Send + 'static {
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    futures_util::stream::iter(0..count).map(move |_| {
        pulled.fetch_add(chunk.len(), Ordering::SeqCst);
        Ok(chunk.clone())
    })
}

#[tokio::test]
async fn http2_streams_the_body_as_flow_control_allows() {
    let (release_tx, release) = watch::channel(false);
    let (port, received) = h2_server(release).await;
    let client = client();
    let url = format!("https://127.0.0.1:{port}/upload");

    let pulled = Arc::new(AtomicUsize::new(0));
    let upload = client.post(&url, Body::stream(counted_chunks(64, pulled.clone())));
    let observe = async {
        // The server reads nothing yet: the client may only take what the
        // flow-control window (64 KiB) lets it send.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before_release = pulled.load(Ordering::SeqCst);
        release_tx.send(true).unwrap();
        before_release
    };
    let (response, before_release) = tokio::join!(upload, observe);
    let response = response.unwrap();
    assert_eq!(response.version, "h2");
    assert!(
        before_release <= 2 * 64 * 1024,
        "pulled {before_release} bytes before the server read any"
    );
    assert_eq!(response.text(), (64 * 64 * 1024).to_string());
    let (length, data) = received.lock().unwrap().pop().unwrap();
    assert_eq!(
        length, None,
        "no Content-Length for a stream of unknown length"
    );
    assert_eq!(data.len(), 64 * 64 * 1024);

    // A known length is announced.
    let body = Body::sized_stream(counted_chunks(3, Arc::default()), 3 * 64 * 1024);
    let response = client.put(&url, body).await.unwrap();
    assert_eq!(response.text(), (3 * 64 * 1024).to_string());
    let (length, _) = received.lock().unwrap().pop().unwrap();
    assert_eq!(length.as_deref(), Some("196608"));
}

/// An HTTP/2 server that sets a cookie with a UTF-8 value and answers every
/// request with the raw bytes of its `x-note` and `cookie` headers. Counts
/// its connections.
async fn echo_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let (cert, key) = common::leaf("127.0.0.1");
    let acceptor = common::h2_acceptor(&cert, &key);
    let count = connections.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            tokio::spawn(async move {
                Pin::new(&mut tls).accept().await.unwrap();
                let mut h2 = http2::server::handshake(tls).await.unwrap();
                while let Some(Ok((request, mut respond))) = h2.accept().await {
                    let mut echo = Vec::new();
                    for name in ["x-note", "cookie"] {
                        for value in request.headers().get_all(name) {
                            echo.extend_from_slice(value.as_bytes());
                            echo.push(b'|');
                        }
                    }
                    let cookie = http::HeaderValue::from_bytes(
                        "greeting=gr\u{fc}\u{df}e; Path=/".as_bytes(),
                    )
                    .unwrap();
                    let response = http::Response::builder()
                        .status(200)
                        .header("set-cookie", cookie)
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from(echo), true).unwrap();
                }
            });
        }
    });
    (port, connections)
}

/// An HTTP/2 server whose first connection refuses its first stream
/// (REFUSED_STREAM); everything else is answered. Counts its connections.
async fn refusing_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let (cert, key) = common::leaf("127.0.0.1");
    let acceptor = common::h2_acceptor(&cert, &key);
    let count = connections.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let mut first = count.fetch_add(1, Ordering::SeqCst) == 0;
            let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
            let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            tokio::spawn(async move {
                Pin::new(&mut tls).accept().await.unwrap();
                let mut h2 = http2::server::handshake(tls).await.unwrap();
                while let Some(Ok((_, mut respond))) = h2.accept().await {
                    if std::mem::take(&mut first) {
                        respond.send_reset(http2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                }
            });
        }
    });
    (port, connections)
}

/// A stream a new HTTP/2 connection refuses was not processed: the request
/// goes out again on another new connection, POST included (Chrome retries
/// ERR_HTTP2_SERVER_REFUSED_STREAM), without retries configured.
#[tokio::test]
async fn refused_stream_on_a_new_connection_is_retried() {
    let (port, connections) = refusing_server().await;
    let client = client();
    let url = format!("https://127.0.0.1:{port}/");
    let response = client.post(&url, "x").await.unwrap();
    assert_eq!((response.status, response.version.as_str()), (200, "h2"));
    assert_eq!(response.body, b"ok");
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// Header values and cookies with UTF-8 go out as their bytes (browsers
/// send them so), on one connection.
#[tokio::test]
async fn http2_sends_utf8_header_values_as_bytes() {
    let (port, connections) = echo_server().await;
    let client = client();
    let url = format!("https://127.0.0.1:{port}/");
    let options = koon_core::RequestOptions {
        headers: vec![("x-note".into(), "caf\u{e9}".into())],
        ..koon_core::RequestOptions::default()
    };
    let first = client
        .send(http::Method::GET, &url, Body::empty(), options.clone())
        .await
        .unwrap();
    assert_eq!(first.version, "h2");
    assert_eq!(first.body, "caf\u{e9}|".as_bytes());
    // The jar now holds the UTF-8 cookie; the next request sends it back.
    let second = client
        .send(http::Method::GET, &url, Body::empty(), options)
        .await
        .unwrap();
    assert_eq!(
        second.body,
        "caf\u{e9}|greeting=gr\u{fc}\u{df}e|".as_bytes()
    );
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}
