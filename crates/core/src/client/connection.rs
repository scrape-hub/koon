use std::pin::Pin;

use tokio::net::TcpStream;
use tokio_boring2::SslStream;

use crate::error::Error;
use crate::proxy::ProxyKind;
use crate::tls::TlsConnector;

impl super::Client {
    /// Establish TCP connection, optionally through a proxy.
    /// When DoH is enabled, resolves hostname via encrypted DNS first.
    pub(super) async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        match &self.proxy {
            None => {
                #[cfg(feature = "doh")]
                if let Some(resolver) = &self.doh_resolver {
                    // Resolve via DoH, then connect to IP directly
                    let addrs = resolver.resolve(host).await?;
                    let addr = std::net::SocketAddr::new(addrs[0], port);
                    let stream =
                        tokio::time::timeout(self.timeout, TcpStream::connect(addr))
                            .await
                            .map_err(|_| Error::Timeout)?
                            .map_err(Error::Io)?;
                    stream.set_nodelay(true).ok();
                    return Ok(stream);
                }

                // Fallback: OS DNS resolution
                let addr = format!("{host}:{port}");
                let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(Error::Io)?;

                // Set TCP_NODELAY for lower latency
                stream.set_nodelay(true).ok();
                Ok(stream)
            }
            Some(proxy) => self.connect_via_proxy(proxy, host, port).await,
        }
    }

    /// Connect through a proxy.
    async fn connect_via_proxy(
        &self,
        proxy: &crate::proxy::ProxyConfig,
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
                stream
                    .write_all(connect_req.as_bytes())
                    .await
                    .map_err(Error::Io)?;

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
            ProxyKind::Socks5 => Err(Error::Proxy("SOCKS5 support not compiled in".into())),
        }
    }

    /// Perform TLS handshake with browser fingerprint (Phase 2).
    pub(super) async fn tls_connect(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<SslStream<TcpStream>, Error> {
        self.tls_connect_inner(tcp, host, port, false).await
    }

    /// Perform TLS handshake for WebSocket (HTTP/1.1 only ALPN).
    pub(super) async fn tls_connect_ws(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<SslStream<TcpStream>, Error> {
        self.tls_connect_inner(tcp, host, port, true).await
    }

    async fn tls_connect_inner(
        &self,
        tcp: TcpStream,
        host: &str,
        port: u16,
        force_h1_only: bool,
    ) -> Result<SslStream<TcpStream>, Error> {
        // ECH config from DNS HTTPS record (when DoH is available)
        let ech_config = self.get_ech_config(host).await;

        let ssl = TlsConnector::configure_connection(
            &self.tls_connector,
            &self.profile.tls,
            host,
            force_h1_only,
            self.session_cache.as_ref(),
            ech_config.as_deref(),
        )?;

        let mut stream = tokio_boring2::SslStream::new(ssl, tcp)?;
        match Pin::new(&mut stream).connect().await {
            Ok(()) => Ok(stream),
            Err(e) => {
                // ECH retry: if ECH was used, check for retry configs from the server
                if ech_config.is_some() {
                    if let Some(retry_configs) = stream.ssl().get_ech_retry_configs() {
                        let retry_configs: Vec<u8> = retry_configs.to_vec();
                        return self
                            .tls_connect_ech_retry(host, port, force_h1_only, &retry_configs)
                            .await;
                    }
                }
                Err(Error::ConnectionFailed(format!(
                    "TLS handshake failed: {e}"
                )))
            }
        }
    }

    /// Retry TLS connection with ECH retry configs from the server.
    /// Called once after an ECH rejection — no loop to prevent infinite retries.
    async fn tls_connect_ech_retry(
        &self,
        host: &str,
        port: u16,
        force_h1_only: bool,
        retry_configs: &[u8],
    ) -> Result<SslStream<TcpStream>, Error> {
        let tcp = self.connect_tcp(host, port).await?;

        let ssl = TlsConnector::configure_connection(
            &self.tls_connector,
            &self.profile.tls,
            host,
            force_h1_only,
            self.session_cache.as_ref(),
            Some(retry_configs),
        )?;

        let mut stream = tokio_boring2::SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!("TLS ECH retry handshake failed: {e}"))
            })?;

        Ok(stream)
    }

    /// Get ECH config from DNS HTTPS record if DoH is available.
    async fn get_ech_config(&self, _host: &str) -> Option<Vec<u8>> {
        #[cfg(feature = "doh")]
        {
            if let Some(resolver) = &self.doh_resolver {
                if let Ok(Some(record)) = resolver.query_https_record(_host).await {
                    return record.ech_config_list;
                }
            }
        }
        None
    }
}
