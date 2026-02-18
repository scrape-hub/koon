use std::pin::Pin;
use std::time::Duration;

use boring2::ssl::SslConnector;
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use tokio::net::TcpStream;
use tokio_boring2::SslStream;

use crate::error::Error;
use crate::http2::config::{PseudoHeader, SettingId};
use crate::profile::BrowserProfile;
use crate::proxy::{ProxyConfig, ProxyKind};
use crate::tls::TlsConnector;

/// HTTP response with body.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub version: String,
    pub url: String,
}

/// The main HTTP client with browser fingerprint impersonation.
///
/// The TLS connector is built once and cached for reuse across connections.
pub struct Client {
    profile: BrowserProfile,
    tls_connector: SslConnector,
    proxy: Option<ProxyConfig>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
}

impl Client {
    /// Create a new client with the given browser profile.
    ///
    /// Builds the TLS connector once (Phase 1) for reuse across connections.
    pub fn new(profile: BrowserProfile) -> Result<Self, Error> {
        let tls_connector = TlsConnector::build_connector(&profile.tls)?;
        Ok(Client {
            profile,
            tls_connector,
            proxy: None,
            timeout: Duration::from_secs(30),
            custom_headers: Vec::new(),
        })
    }

    /// Set a proxy for all requests.
    pub fn with_proxy(mut self, proxy_url: &str) -> Result<Self, Error> {
        self.proxy = Some(ProxyConfig::parse(proxy_url)?);
        Ok(self)
    }

    /// Set the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Add custom headers that override profile defaults.
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.custom_headers = headers;
        self
    }

    /// Perform an HTTP GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, Error> {
        self.request(Method::GET, url, None).await
    }

    /// Perform an HTTP POST request.
    pub async fn post(&self, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse, Error> {
        self.request(Method::POST, url, body).await
    }

    /// Perform an HTTP request with the given method.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        let uri: Uri = url.parse().map_err(|_| Error::Url(url::ParseError::EmptyHost))?;
        let host = uri.host().ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
        let is_https = uri.scheme_str() == Some("https");

        // Connect TCP (directly or via proxy)
        let tcp = self.connect_tcp(host, port).await?;

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        // Perform TLS handshake with fingerprinted config (Phase 2)
        let tls_stream = self.tls_connect(tcp, host).await?;

        // Send HTTP/2 request
        self.send_h2_request(tls_stream, method, &uri, body).await
    }

    /// Establish TCP connection, optionally through a proxy.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        match &self.proxy {
            None => {
                let addr = format!("{host}:{port}");
                let stream = tokio::time::timeout(
                    self.timeout,
                    TcpStream::connect(&addr),
                )
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(Error::Io)?;

                // Set TCP_NODELAY for lower latency
                stream.set_nodelay(true).ok();
                Ok(stream)
            }
            Some(proxy) => {
                self.connect_via_proxy(proxy, host, port).await
            }
        }
    }

    /// Connect through a proxy.
    async fn connect_via_proxy(
        &self,
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, Error> {
        match proxy.kind {
            #[cfg(feature = "socks")]
            ProxyKind::Socks5 => {
                let proxy_addr = format!("{}:{}", proxy.host(), proxy.port());
                let target = format!("{target_host}:{target_port}");

                let stream = if let Some(auth) = &proxy.auth {
                    tokio_socks::tcp::Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        target.as_str(),
                        &auth.username,
                        &auth.password,
                    )
                    .await
                    .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}")))?
                } else {
                    tokio_socks::tcp::Socks5Stream::connect(
                        proxy_addr.as_str(),
                        target.as_str(),
                    )
                    .await
                    .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}")))?
                };

                Ok(stream.into_inner())
            }
            ProxyKind::Http | ProxyKind::Https => {
                // HTTP CONNECT tunnel
                let proxy_addr = format!("{}:{}", proxy.host(), proxy.port());
                let stream = TcpStream::connect(&proxy_addr)
                    .await
                    .map_err(|e| Error::Proxy(format!("Failed to connect to proxy: {e}")))?;

                // Send CONNECT request
                let connect_req = format!(
                    "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
                     Host: {target_host}:{target_port}\r\n\
                     \r\n"
                );

                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = stream;
                stream.write_all(connect_req.as_bytes()).await.map_err(Error::Io)?;

                // Read response (simple parsing, just check for 200)
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.map_err(Error::Io)?;
                let response = String::from_utf8_lossy(&buf[..n]);

                if !response.contains("200") {
                    return Err(Error::Proxy(format!(
                        "CONNECT tunnel failed: {response}"
                    )));
                }

                Ok(stream)
            }
            #[cfg(not(feature = "socks"))]
            ProxyKind::Socks5 => {
                Err(Error::Proxy("SOCKS5 support not compiled in".into()))
            }
        }
    }

    /// Perform TLS handshake with browser fingerprint (Phase 2).
    async fn tls_connect(
        &self,
        tcp: TcpStream,
        host: &str,
    ) -> Result<SslStream<TcpStream>, Error> {
        let ssl = TlsConnector::configure_connection(
            &self.tls_connector,
            &self.profile.tls,
            host,
        )?;

        let mut stream = tokio_boring2::SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TLS handshake failed: {e}")))?;

        Ok(stream)
    }

    /// Send an HTTP/2 request over a TLS connection.
    async fn send_h2_request(
        &self,
        tls_stream: SslStream<TcpStream>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        let h2_config = &self.profile.http2;

        // Build h2 client with fingerprinted settings
        let mut h2_builder = http2::client::Builder::new();

        if let Some(hts) = h2_config.header_table_size {
            h2_builder.header_table_size(hts);
        }
        if let Some(ep) = h2_config.enable_push {
            h2_builder.enable_push(ep);
        }
        if let Some(mcs) = h2_config.max_concurrent_streams {
            h2_builder.max_concurrent_streams(mcs);
        }
        h2_builder.initial_window_size(h2_config.initial_window_size);
        h2_builder.initial_connection_window_size(h2_config.initial_conn_window_size);
        if let Some(mfs) = h2_config.max_frame_size {
            h2_builder.max_frame_size(mfs);
        }
        if let Some(mhls) = h2_config.max_header_list_size {
            h2_builder.max_header_list_size(mhls);
        }

        // Settings order
        if !h2_config.settings_order.is_empty() {
            let mut order = http2::frame::SettingsOrder::builder();
            for setting_id in &h2_config.settings_order {
                let id = match setting_id {
                    SettingId::HeaderTableSize => http2::frame::SettingId::HeaderTableSize,
                    SettingId::EnablePush => http2::frame::SettingId::EnablePush,
                    SettingId::MaxConcurrentStreams => http2::frame::SettingId::MaxConcurrentStreams,
                    SettingId::InitialWindowSize => http2::frame::SettingId::InitialWindowSize,
                    SettingId::MaxFrameSize => http2::frame::SettingId::MaxFrameSize,
                    SettingId::MaxHeaderListSize => http2::frame::SettingId::MaxHeaderListSize,
                    SettingId::EnableConnectProtocol => http2::frame::SettingId::EnableConnectProtocol,
                    SettingId::NoRfc7540Priorities => http2::frame::SettingId::NoRfc7540Priorities,
                };
                order = order.push(id);
            }
            h2_builder.settings_order(order.build());
        }

        // Pseudo-header order
        if !h2_config.pseudo_header_order.is_empty() {
            let mut pseudo = http2::frame::PseudoOrder::builder();
            for ph in &h2_config.pseudo_header_order {
                let id = match ph {
                    PseudoHeader::Method => http2::frame::PseudoId::Method,
                    PseudoHeader::Authority => http2::frame::PseudoId::Authority,
                    PseudoHeader::Scheme => http2::frame::PseudoId::Scheme,
                    PseudoHeader::Path => http2::frame::PseudoId::Path,
                    PseudoHeader::Status => http2::frame::PseudoId::Status,
                    PseudoHeader::Protocol => http2::frame::PseudoId::Protocol,
                };
                pseudo = pseudo.push(id);
            }
            h2_builder.headers_pseudo_order(pseudo.build());
        }

        // Stream dependency for HEADERS frame
        if let Some(dep) = &h2_config.headers_stream_dependency {
            h2_builder.headers_stream_dependency(http2::frame::StreamDependency::new(
                http2::frame::StreamId::from(dep.stream_id),
                dep.weight,
                dep.exclusive,
            ));
        }

        // Perform the HTTP/2 handshake
        let (mut client, h2_conn) = h2_builder
            .handshake::<_, bytes::Bytes>(tls_stream)
            .await
            .map_err(Error::Http2)?;

        // Spawn a task to drive the HTTP/2 connection
        tokio::spawn(async move {
            if let Err(e) = h2_conn.await {
                eprintln!("HTTP/2 connection error: {e}");
            }
        });

        // Build the request with headers in the correct order.
        // h2 crate needs the full URI to extract :scheme and :authority pseudo-headers.
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}").parse().map_err(|_| {
            Error::InvalidHeader("Failed to build H2 URI".into())
        })?;

        let req_builder = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2);

        let mut req = req_builder.body(()).map_err(|e| {
            Error::InvalidHeader(format!("Failed to build request: {e}"))
        })?;

        // Add headers in profile order
        let headers = req.headers_mut();

        for (name, value) in &self.profile.headers {
            let lower = name.to_lowercase();
            if lower == "host" {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Apply custom headers (override profile defaults)
        for (name, value) in &self.custom_headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Send the request
        let has_body = body.is_some();
        let (response_future, mut send_stream) = client
            .send_request(req, !has_body)
            .map_err(Error::Http2)?;

        // Send body if present
        if let Some(body_bytes) = body {
            send_stream
                .send_data(body_bytes.into(), true)
                .map_err(Error::Http2)?;
        }

        // Await the response
        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();

        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        // Read body
        let mut body_data = Vec::new();
        let mut recv_stream = response.into_body();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.map_err(Error::Http2)?;
            body_data.extend_from_slice(&chunk);
            // Acknowledge received data for flow control
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }

        // Decompress body based on Content-Encoding header
        let content_encoding = resp_headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(body_data, content_encoding)?;

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
            version: "h2".to_string(),
            url: uri.to_string(),
        })
    }
}

/// Decompress response body based on Content-Encoding header.
fn decompress_body(data: Vec<u8>, encoding: Option<&str>) -> Result<Vec<u8>, Error> {
    match encoding {
        Some("gzip") => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("deflate") => {
            use std::io::Read;
            let mut decoder = flate2::read::DeflateDecoder::new(&data[..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        Some("br") => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(&data), &mut out)
                .map_err(Error::Io)?;
            Ok(out)
        }
        Some("zstd") => {
            use std::io::Read;
            let mut decoder = zstd::Decoder::new(&data[..]).map_err(Error::Io)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(Error::Io)?;
            Ok(out)
        }
        _ => Ok(data),
    }
}
