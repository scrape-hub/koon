//! The routes every server of the option matrix (`options_matrix.rs`) answers, over HTTP/1.1,
//! HTTP/2 and HTTP/3 alike, and the TLS server for the first two.

use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long a slow route stalls: far past the timeouts the tests set.
pub const STALL: Duration = Duration::from_secs(3);

/// A response, and when it goes out.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Waited before the head.
    pub head_delay: Duration,
    /// Waited between the head and the body.
    pub body_delay: Duration,
}

/// The reply to a request for `path` with these headers and body:
/// - `/ok`: `ok`
/// - `/slow-head`, `/slow-body`: the head or the body comes after [`STALL`]
/// - `/big`: 4096 bytes
/// - `/gzip`: 1 MiB of zeros, gzipped to about a kilobyte
/// - `/set-cookie`: sets `matrix=1`
/// - `/echo`: the request headers as `name: value` lines, then the body
/// - `/redirect/N`: a 302 to `/redirect/N-1`; `/redirect/0` answers `end`
pub fn answer(path: &str, headers: &[(String, String)], body: &[u8]) -> Reply {
    let mut reply = Reply {
        status: 200,
        headers: Vec::new(),
        body: b"ok".to_vec(),
        head_delay: Duration::ZERO,
        body_delay: Duration::ZERO,
    };
    match path {
        "/ok" => {}
        "/slow-head" => reply.head_delay = STALL,
        "/slow-body" => reply.body_delay = STALL,
        "/big" => reply.body = vec![b'x'; 4096],
        "/gzip" => {
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            gzip.write_all(&vec![0; 1 << 20]).unwrap();
            reply.body = gzip.finish().unwrap();
            reply
                .headers
                .push(("content-encoding".into(), "gzip".into()));
        }
        "/set-cookie" => {
            reply
                .headers
                .push(("set-cookie".into(), "matrix=1; Path=/".into()));
        }
        "/echo" => {
            let mut echo: Vec<u8> = headers
                .iter()
                .flat_map(|(k, v)| format!("{}: {v}\n", k.to_ascii_lowercase()).into_bytes())
                .collect();
            echo.push(b'\n');
            echo.extend_from_slice(body);
            reply.body = echo;
        }
        _ => match path
            .strip_prefix("/redirect/")
            .and_then(|n| n.parse::<u32>().ok())
        {
            Some(0) => reply.body = b"end".to_vec(),
            Some(n) => {
                reply.status = 302;
                reply
                    .headers
                    .push(("location".into(), format!("/redirect/{}", n - 1)));
            }
            None => reply.status = 404,
        },
    }
    reply
}

/// The protocol a matrix server speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    H1,
    H2,
    H3,
}

impl Proto {
    /// `HttpResponse::version` of a response over this protocol.
    pub fn version(self) -> &'static str {
        match self {
            Self::H1 => "HTTP/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

/// A TLS server on 127.0.0.1 for `host` answering [`answer`] over HTTP/1.1 or HTTP/2, as ALPN
/// picks for `proto`; with `alt_svc`, every response offers HTTP/3 on that port. Returns its port.
pub async fn tcp_server(host: &str, proto: Proto, alt_svc: Option<u16>) -> u16 {
    let (cert, key) = super::leaf(host);
    let mut builder = super::tls_acceptor_builder(&cert, &key);
    let alpn: &'static [u8] = if proto == Proto::H1 {
        b"\x08http/1.1"
    } else {
        b"\x02h2"
    };
    builder.set_alpn_select_callback(move |_, offered| {
        btls::ssl::select_next_proto(alpn, offered).ok_or(btls::ssl::AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let alt_svc = alt_svc.map(|port| format!("h3=\":{port}\"; ma=86400"));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, alt_svc) = (acceptor.clone(), alt_svc.clone());
            tokio::spawn(async move {
                let ssl = btls::ssl::Ssl::new(acceptor.context()).unwrap();
                let mut tls = tokio_btls::SslStream::new(ssl, tcp).unwrap();
                if Pin::new(&mut tls).accept().await.is_err() {
                    return;
                }
                if tls.ssl().selected_alpn_protocol() == Some(b"h2") {
                    serve_h2(tls, alt_svc).await;
                } else {
                    serve_h1(tls, alt_svc).await;
                }
            });
        }
    });
    port
}

/// The reply's headers, with Alt-Svc when there is one to offer.
fn reply_headers(reply: &Reply, alt_svc: Option<&str>) -> Vec<(String, String)> {
    let mut headers = reply.headers.clone();
    if let Some(alt_svc) = alt_svc {
        headers.push(("alt-svc".into(), alt_svc.into()));
    }
    headers
}

async fn serve_h1<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut io: S,
    alt_svc: Option<String>,
) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&request[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("/")
        .to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = request[head_end + 4..].to_vec();
    while body.len() < length {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let reply = answer(&path, &headers, &body);
    tokio::time::sleep(reply.head_delay).await;
    let mut out = format!("HTTP/1.1 {} X\r\n", reply.status);
    for (k, v) in reply_headers(&reply, alt_svc.as_deref()) {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        reply.body.len()
    ));
    if io.write_all(out.as_bytes()).await.is_err() || io.flush().await.is_err() {
        return;
    }
    tokio::time::sleep(reply.body_delay).await;
    let _ = io.write_all(&reply.body).await;
    let _ = io.shutdown().await;
}

async fn serve_h2<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    io: S,
    alt_svc: Option<String>,
) {
    let Ok(mut h2) = http2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((request, mut respond))) = h2.accept().await {
        let alt_svc = alt_svc.clone();
        tokio::spawn(async move {
            let path = request.uri().path().to_string();
            let headers: Vec<(String, String)> = request
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let mut stream = request.into_body();
            let mut body = Vec::new();
            while let Some(Ok(data)) = stream.data().await {
                let _ = stream.flow_control().release_capacity(data.len());
                body.extend_from_slice(&data);
            }
            let reply = answer(&path, &headers, &body);
            tokio::time::sleep(reply.head_delay).await;
            let mut response = http::Response::builder().status(reply.status);
            for (k, v) in reply_headers(&reply, alt_svc.as_deref()) {
                response = response.header(k, v);
            }
            let Ok(mut send) = respond.send_response(response.body(()).unwrap(), false) else {
                return;
            };
            tokio::time::sleep(reply.body_delay).await;
            let _ = send.send_data(Bytes::from(reply.body), true);
        });
    }
}
