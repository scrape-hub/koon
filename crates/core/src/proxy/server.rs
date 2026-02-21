use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use boring2::ssl::{SslAcceptor, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::client::Client;
use crate::error::Error;
use crate::profile::BrowserProfile;

use super::ca::CertAuthority;

/// Header handling mode for the MITM proxy.
#[derive(Debug, Clone, Copy, Default)]
pub enum HeaderMode {
    /// Replace client headers with browser profile headers (TLS + H2 + headers fingerprinted).
    #[default]
    Impersonate,
    /// Pass through client headers as-is, only TLS and H2 are fingerprinted.
    Passthrough,
}

/// Configuration for the MITM proxy server.
pub struct ProxyServerConfig {
    /// Address to listen on. Default: `"127.0.0.1:0"` (random port).
    pub listen_addr: String,
    /// Browser profile for fingerprinting outgoing connections.
    pub profile: BrowserProfile,
    /// How to handle HTTP headers from the client.
    pub header_mode: HeaderMode,
    /// Directory for CA certificate storage. Default: `~/.koon/ca/`.
    pub ca_dir: Option<String>,
    /// Request timeout in seconds. Default: 30.
    pub timeout_secs: u64,
}

impl Default for ProxyServerConfig {
    fn default() -> Self {
        ProxyServerConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            profile: crate::profile::Chrome::latest(),
            header_mode: HeaderMode::default(),
            ca_dir: None,
            timeout_secs: 30,
        }
    }
}

/// A local MITM proxy server that intercepts HTTPS traffic and re-sends it
/// using koon's fingerprinted TLS/HTTP2 stack.
pub struct ProxyServer {
    local_addr: SocketAddr,
    ca: Arc<CertAuthority>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl ProxyServer {
    /// Start the proxy server.
    ///
    /// Binds to the configured address and spawns an accept loop.
    /// Returns immediately with the server handle.
    pub async fn start(config: ProxyServerConfig) -> Result<Self, Error> {
        let ca_dir = match config.ca_dir {
            Some(dir) => PathBuf::from(dir),
            None => {
                let home = dirs_default_ca_dir();
                PathBuf::from(home)
            }
        };

        let ca = Arc::new(CertAuthority::load_or_generate(ca_dir)?);

        let client = Client::builder(config.profile.clone())
            .timeout(Duration::from_secs(config.timeout_secs))
            .follow_redirects(false)
            .cookie_jar(false)
            .build()?;
        let client = Arc::new(client);

        let listener = TcpListener::bind(&config.listen_addr)
            .await
            .map_err(Error::Io)?;
        let local_addr = listener.local_addr().map_err(Error::Io)?;

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let header_mode = config.header_mode;

        tokio::spawn(accept_loop(
            listener,
            ca.clone(),
            client,
            header_mode,
            shutdown_rx,
        ));

        Ok(ProxyServer {
            local_addr,
            ca,
            shutdown_tx,
        })
    }

    /// The port the proxy is listening on.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// The proxy URL (e.g. `http://127.0.0.1:12345`).
    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// The local address the proxy is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Path to the CA certificate PEM file.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca.ca_cert_path()
    }

    /// CA certificate as PEM bytes.
    pub fn ca_cert_pem(&self) -> Result<Vec<u8>, Error> {
        self.ca.ca_cert_pem()
    }

    /// Shut down the proxy server.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Default CA directory: ~/.koon/ca/
fn dirs_default_ca_dir() -> String {
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
    {
        let mut path = PathBuf::from(home);
        path.push(".koon");
        path.push("ca");
        path.to_string_lossy().to_string()
    } else {
        ".koon/ca".to_string()
    }
}

/// Accept loop: listens for incoming connections and spawns handlers.
async fn accept_loop(
    listener: TcpListener,
    ca: Arc<CertAuthority>,
    client: Arc<Client>,
    header_mode: HeaderMode,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let ca = ca.clone();
                        let client = client.clone();
                        tokio::spawn(async move {
                            if let Err(_e) = handle_connection(stream, ca, client, header_mode).await {
                                // Connection errors are expected (client disconnect, etc.)
                            }
                        });
                    }
                    Err(_) => continue,
                }
            }
            _ = shutdown_rx.changed() => {
                return;
            }
        }
    }
}

/// Handle a single incoming proxy connection.
///
/// Reads the first request to determine if it's a CONNECT tunnel or plain HTTP.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    ca: Arc<CertAuthority>,
    client: Arc<Client>,
    header_mode: HeaderMode,
) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // Read until we have the full request headers
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await.map_err(Error::Io)?;
        if n == 0 {
            return Ok(()); // Client disconnected
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > 65536 {
            return Err(Error::Proxy("Request headers too large".into()));
        }
    }

    // Parse the request
    let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut parsed_headers);
    let parse_result = req
        .parse(&buf[..header_end + 4])
        .map_err(|e| Error::Proxy(format!("Failed to parse proxy request: {e}")))?;

    if parse_result.is_partial() {
        return Err(Error::Proxy("Incomplete proxy request".into()));
    }

    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS CONNECT tunnel
        let (host, port) = parse_connect_target(path)?;
        handle_connect(stream, &host, port, ca, client, header_mode).await
    } else {
        // Plain HTTP request (absolute URL)
        let headers: Vec<(String, String)> = req
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_lowercase(),
                    String::from_utf8_lossy(h.value).to_string(),
                )
            })
            .collect();

        let body_start = header_end + 4;
        let body = if body_start < buf.len() {
            Some(buf[body_start..].to_vec())
        } else {
            None
        };

        handle_plain_http(
            &mut stream,
            method,
            path,
            &headers,
            body,
            client,
            header_mode,
        )
        .await
    }
}

/// Parse CONNECT target `host:port`.
fn parse_connect_target(target: &str) -> Result<(String, u16), Error> {
    if let Some(colon) = target.rfind(':') {
        let host = &target[..colon];
        let port: u16 = target[colon + 1..]
            .parse()
            .map_err(|_| Error::Proxy(format!("Invalid CONNECT port: {target}")))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

/// Handle an HTTPS CONNECT tunnel.
///
/// 1. Send 200 Connection Established
/// 2. TLS-accept with leaf cert for the target domain
/// 3. Read HTTP requests from the decrypted stream
/// 4. Forward them via koon's fingerprinted client
/// 5. Write responses back to the client
async fn handle_connect(
    mut stream: tokio::net::TcpStream,
    host: &str,
    port: u16,
    ca: Arc<CertAuthority>,
    client: Arc<Client>,
    header_mode: HeaderMode,
) -> Result<(), Error> {
    // 1. Send 200 Connection Established
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(Error::Io)?;

    // 2. Build SslAcceptor with leaf cert for this domain
    let (cert, key) = ca.get_or_create_leaf(host)?;
    let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| Error::Proxy(format!("SslAcceptor builder failed: {e}")))?;
    acceptor_builder
        .set_certificate(&cert)
        .map_err(|e| Error::Proxy(format!("set_certificate failed: {e}")))?;
    acceptor_builder
        .set_private_key(&key)
        .map_err(|e| Error::Proxy(format!("set_private_key failed: {e}")))?;
    let acceptor = acceptor_builder.build();

    // 3. TLS accept
    let ssl = boring2::ssl::Ssl::new(acceptor.context())
        .map_err(|e| Error::Proxy(format!("Ssl::new failed: {e}")))?;
    let mut tls_stream = tokio_boring2::SslStream::new(ssl, stream)
        .map_err(|e| Error::Proxy(format!("SslStream::new failed: {e}")))?;

    Pin::new(&mut tls_stream)
        .accept()
        .await
        .map_err(|e| Error::Proxy(format!("TLS accept failed: {e}")))?;

    // 4. Request loop: read requests from client, forward via koon, respond
    let default_authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    loop {
        match read_proxy_request(&mut tls_stream).await {
            Ok(Some(proxy_req)) => {
                let url = format!("https://{}{}", default_authority, proxy_req.path);

                let response = match header_mode {
                    HeaderMode::Impersonate => {
                        let method: http::Method = proxy_req
                            .method
                            .parse()
                            .unwrap_or(http::Method::GET);
                        client.request(method, &url, proxy_req.body).await
                    }
                    HeaderMode::Passthrough => {
                        let method: http::Method = proxy_req
                            .method
                            .parse()
                            .unwrap_or(http::Method::GET);
                        client
                            .request_with_raw_headers(
                                method,
                                &url,
                                proxy_req.headers,
                                proxy_req.body,
                            )
                            .await
                    }
                };

                match response {
                    Ok(resp) => {
                        if write_proxy_response(&mut tls_stream, &resp).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        let error_body = format!("Proxy error: {e}");
                        let error_resp = format!(
                            "HTTP/1.1 502 Bad Gateway\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            error_body.len(),
                            error_body
                        );
                        let _ = tls_stream.write_all(error_resp.as_bytes()).await;
                        return Ok(());
                    }
                }
            }
            Ok(None) => return Ok(()), // Client disconnected
            Err(_) => return Ok(()),
        }
    }
}

/// Handle a plain HTTP request (non-CONNECT).
async fn handle_plain_http(
    stream: &mut tokio::net::TcpStream,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
    client: Arc<Client>,
    header_mode: HeaderMode,
) -> Result<(), Error> {
    let parsed_method: http::Method = method.parse().unwrap_or(http::Method::GET);

    let response = match header_mode {
        HeaderMode::Impersonate => client.request(parsed_method, url, body).await,
        HeaderMode::Passthrough => {
            client
                .request_with_raw_headers(parsed_method, url, headers.to_vec(), body)
                .await
        }
    };

    match response {
        Ok(resp) => {
            let mut buf = format!("HTTP/1.1 {} OK\r\n", resp.status);
            for (name, value) in &resp.headers {
                buf.push_str(&format!("{name}: {value}\r\n"));
            }
            if !resp.headers.iter().any(|(k, _)| k == "content-length") {
                buf.push_str(&format!("content-length: {}\r\n", resp.body.len()));
            }
            buf.push_str("\r\n");
            stream.write_all(buf.as_bytes()).await.map_err(Error::Io)?;
            stream.write_all(&resp.body).await.map_err(Error::Io)?;
            stream.flush().await.map_err(Error::Io)?;
        }
        Err(e) => {
            let error_body = format!("Proxy error: {e}");
            let error_resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\ncontent-length: {}\r\n\r\n{}",
                error_body.len(),
                error_body
            );
            stream
                .write_all(error_resp.as_bytes())
                .await
                .map_err(Error::Io)?;
        }
    }

    Ok(())
}

/// A parsed HTTP request from the proxy client.
struct ProxyRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

/// Read a single HTTP/1.1 request from a stream.
/// Returns `Ok(None)` on EOF (client disconnect).
async fn read_proxy_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<Option<ProxyRequest>, Error> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // Read until we have the full request headers
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await.map_err(Error::Io)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > 65536 {
            return Err(Error::Proxy("Request headers too large".into()));
        }
    }

    let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut parsed_headers);
    let parse_result = req
        .parse(&buf[..header_end + 4])
        .map_err(|e| Error::Proxy(format!("Failed to parse request: {e}")))?;

    if parse_result.is_partial() {
        return Err(Error::Proxy("Incomplete request".into()));
    }

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();

    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_lowercase(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect();

    // Read body based on content-length
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.trim().parse().ok());

    let body_start = header_end + 4;
    let already_read = &buf[body_start..];

    let body = if let Some(len) = content_length {
        if len == 0 {
            None
        } else {
            let mut body = Vec::with_capacity(len);
            body.extend_from_slice(already_read);

            while body.len() < len {
                let n = stream.read(&mut tmp).await.map_err(Error::Io)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(len);
            Some(body)
        }
    } else if !already_read.is_empty() {
        Some(already_read.to_vec())
    } else {
        None
    };

    Ok(Some(ProxyRequest {
        method,
        path,
        headers,
        body,
    }))
}

/// Write an HTTP/1.1 response back to the proxy client.
async fn write_proxy_response<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    resp: &crate::client::HttpResponse,
) -> Result<(), Error> {
    let reason = status_reason(resp.status);
    let mut buf = format!("HTTP/1.1 {} {reason}\r\n", resp.status);

    // Write response headers, skipping transfer-encoding (we send content-length)
    let mut has_content_length = false;
    for (name, value) in &resp.headers {
        let lower = name.to_lowercase();
        if lower == "transfer-encoding" {
            continue; // We'll use content-length instead
        }
        if lower == "content-length" {
            has_content_length = true;
        }
        buf.push_str(&format!("{name}: {value}\r\n"));
    }

    // Add content-length if missing
    if !has_content_length {
        buf.push_str(&format!("content-length: {}\r\n", resp.body.len()));
    }

    buf.push_str("\r\n");
    stream.write_all(buf.as_bytes()).await.map_err(Error::Io)?;
    stream.write_all(&resp.body).await.map_err(Error::Io)?;
    stream.flush().await.map_err(Error::Io)?;

    Ok(())
}

/// Get HTTP status reason phrase.
fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}
