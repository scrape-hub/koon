use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::net::{TcpSocket, TcpStream};
use tokio_btls::SslStream;

use super::IpVersion;
use crate::error::Error;
use crate::proxy::ProxyKind;
use crate::tls::TlsConnector;

impl super::Client {
    /// Resolve DNS and filter by IP version preference.
    async fn resolve_addr(
        &self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> Result<SocketAddr, Error> {
        let mut addrs = tokio::net::lookup_host(addr).await.map_err(Error::Io)?;

        match self.ip_version {
            Some(IpVersion::V4) => addrs.find(|a| a.is_ipv4()),
            Some(IpVersion::V6) => addrs.find(|a| a.is_ipv6()),
            None => addrs.next(),
        }
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                match self.ip_version {
                    Some(IpVersion::V4) => "No IPv4 address found",
                    Some(IpVersion::V6) => "No IPv6 address found",
                    None => "DNS resolution returned no addresses",
                },
            ))
        })
    }

    /// Connect a TCP stream, optionally binding to a local address.
    async fn tcp_connect(&self, addr: impl tokio::net::ToSocketAddrs) -> Result<TcpStream, Error> {
        match self.local_address {
            Some(local_ip) => {
                let remote = self.resolve_addr(addr).await?;

                let socket = match local_ip {
                    IpAddr::V4(_) => TcpSocket::new_v4(),
                    IpAddr::V6(_) => TcpSocket::new_v6(),
                }
                .map_err(Error::Io)?;

                socket
                    .bind(SocketAddr::new(local_ip, 0))
                    .map_err(Error::Io)?;
                socket.connect(remote).await.map_err(Error::Io)
            }
            None => {
                if self.ip_version.is_some() {
                    let remote = self.resolve_addr(addr).await?;
                    TcpStream::connect(remote).await.map_err(Error::Io)
                } else {
                    TcpStream::connect(addr).await.map_err(Error::Io)
                }
            }
        }
    }

    /// Establish TCP connection, optionally through a proxy.
    /// Uses `select_proxy()` to pick the proxy (rotation > single > none).
    /// When DoH is enabled, resolves hostname via encrypted DNS first.
    pub(super) async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        let (_idx, proxy) = self.select_proxy();
        self.connect_tcp_via(host, port, proxy).await
    }

    /// Establish TCP connection through an explicitly specified proxy (or direct).
    /// Called by `execute_single_request` which pre-selects the proxy for the request.
    pub(super) async fn connect_tcp_via(
        &self,
        host: &str,
        port: u16,
        proxy: Option<&crate::proxy::ProxyConfig>,
    ) -> Result<TcpStream, Error> {
        match proxy {
            None => {
                #[cfg(feature = "doh")]
                if let Some(resolver) = &self.doh_resolver {
                    // Resolve via DoH, then connect to IP directly
                    let addrs = resolver.resolve(host).await?;
                    let addr = match self.ip_version {
                        Some(IpVersion::V4) => addrs.iter().find(|a| a.is_ipv4()),
                        Some(IpVersion::V6) => addrs.iter().find(|a| a.is_ipv6()),
                        None => addrs.first(),
                    }
                    .ok_or_else(|| {
                        Error::Io(std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            "No matching IP address from DoH",
                        ))
                    })?;
                    let addr = SocketAddr::new(*addr, port);
                    let stream = tokio::time::timeout(self.timeout, self.tcp_connect(addr))
                        .await
                        .map_err(|_| Error::Timeout)?;
                    let stream = stream?;
                    stream.set_nodelay(true).ok();
                    return Ok(stream);
                }

                // Fallback: OS DNS resolution
                let addr = format!("{host}:{port}");
                let stream = tokio::time::timeout(self.timeout, self.tcp_connect(addr.as_str()))
                    .await
                    .map_err(|_| Error::Timeout)?;
                let stream = stream?;

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
                    tokio_socks::tcp::Socks5Stream::connect(proxy_addr.as_str(), target.as_str())
                        .await
                        .map_err(|e| Error::Proxy(format!("SOCKS5 error: {e}")))?
                };

                Ok(stream.into_inner())
            }
            ProxyKind::Http | ProxyKind::Https => {
                // HTTP CONNECT tunnel
                let proxy_addr = format!("{}:{}", proxy.host(), proxy.port());
                let stream = self
                    .tcp_connect(proxy_addr.as_str())
                    .await
                    .map_err(|e| Error::Proxy(format!("Failed to connect to proxy: {e}")))?;

                // Send CONNECT request with proxy auth and optional proxy headers
                let mut connect_req = format!(
                    "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
                     Host: {target_host}:{target_port}\r\n"
                );

                // Auto-inject Proxy-Authorization from URL credentials unless
                // the caller already set one via proxy_headers
                let has_manual_auth = self
                    .proxy_headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"));
                if !has_manual_auth {
                    if let Some(auth) = &proxy.auth {
                        use base64::Engine;
                        let encoded = base64::engine::general_purpose::STANDARD
                            .encode(format!("{}:{}", auth.username, auth.password));
                        connect_req.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
                    }
                }

                for (name, value) in &self.proxy_headers {
                    connect_req.push_str(&format!("{name}: {value}\r\n"));
                }
                connect_req.push_str("\r\n");

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
                    return Err(Error::Proxy(format!("CONNECT tunnel failed: {response}")));
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

        let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
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

        let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TLS ECH retry handshake failed: {e}")))?;

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
