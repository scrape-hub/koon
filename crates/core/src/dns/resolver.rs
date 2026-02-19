use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use boring2::ssl::{SslConnector, SslMethod, SslVerifyMode};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::record_data::RData;
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_boring2::SslStream;

use crate::Error;

const DNS_CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// DNS-over-HTTPS server configuration.
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// DoH server IP (no DNS needed to reach the resolver itself).
    pub server_ip: IpAddr,
    /// TLS hostname for certificate verification.
    pub server_hostname: String,
    /// Server port (typically 443).
    pub server_port: u16,
}

/// HTTPS DNS record data (RR type 65).
#[derive(Debug, Clone)]
pub struct HttpsRecord {
    /// ECHConfigList bytes (SvcParam key=5).
    pub ech_config_list: Option<Vec<u8>>,
    /// ALPN protocols (SvcParam key=1).
    pub alpn: Vec<String>,
}

struct DnsCacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

struct HttpsCacheEntry {
    record: Option<HttpsRecord>,
    expires: Instant,
}

/// DNS-over-HTTPS resolver.
///
/// Makes encrypted DNS queries via HTTPS POST to a trusted resolver
/// (Cloudflare or Google). This prevents DNS fingerprinting and enables
/// HTTPS record queries for ECH support.
pub struct DohResolver {
    config: DohConfig,
    tls_connector: SslConnector,
    ip_cache: Mutex<HashMap<String, DnsCacheEntry>>,
    https_cache: Mutex<HashMap<String, HttpsCacheEntry>>,
}

impl DohResolver {
    /// Create a resolver using Cloudflare's DoH service (1.1.1.1).
    pub fn with_cloudflare() -> Result<Self, Error> {
        Self::new(DohConfig {
            server_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            server_hostname: "cloudflare-dns.com".into(),
            server_port: 443,
        })
    }

    /// Create a resolver using Google's DoH service (8.8.8.8).
    pub fn with_google() -> Result<Self, Error> {
        Self::new(DohConfig {
            server_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            server_hostname: "dns.google".into(),
            server_port: 443,
        })
    }

    /// Create a resolver with custom DoH config.
    pub fn new(config: DohConfig) -> Result<Self, Error> {
        // Minimal TLS config — NOT the browser fingerprint.
        // This is just for the DoH connection, not for user traffic.
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_verify(SslVerifyMode::PEER);

        // Load root certs
        use boring2::x509::store::X509StoreBuilder;
        use boring2::x509::X509;
        let mut store_builder = X509StoreBuilder::new()?;
        for cert_der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            if let Ok(x509) = X509::from_der(cert_der.as_ref()) {
                let _ = store_builder.add_cert(x509);
            }
        }
        builder.set_verify_cert_store(store_builder.build())?;

        let tls_connector = builder.build();

        Ok(DohResolver {
            config,
            tls_connector,
            ip_cache: Mutex::new(HashMap::new()),
            https_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve a hostname to IP addresses via DoH (A + AAAA queries).
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, Error> {
        // Check cache first
        {
            let cache = self.ip_cache.lock().unwrap();
            if let Some(entry) = cache.get(hostname) {
                if entry.expires > Instant::now() {
                    return Ok(entry.addrs.clone());
                }
            }
        }

        // Query A and AAAA in parallel
        let fqdn = ensure_fqdn(hostname);

        let (a_result, aaaa_result) = tokio::join!(
            self.doh_query(&fqdn, RecordType::A),
            self.doh_query(&fqdn, RecordType::AAAA),
        );

        let mut addrs = Vec::new();

        if let Ok(msg) = a_result {
            for record in msg.answers() {
                if let RData::A(a) = record.data() {
                    addrs.push(IpAddr::V4(a.0));
                }
            }
        }

        if let Ok(msg) = aaaa_result {
            for record in msg.answers() {
                if let RData::AAAA(aaaa) = record.data() {
                    addrs.push(IpAddr::V6(aaaa.0));
                }
            }
        }

        if addrs.is_empty() {
            return Err(Error::Dns(format!("No addresses found for {hostname}")));
        }

        // Cache results
        {
            let mut cache = self.ip_cache.lock().unwrap();
            cache.insert(
                hostname.to_string(),
                DnsCacheEntry {
                    addrs: addrs.clone(),
                    expires: Instant::now() + DNS_CACHE_TTL,
                },
            );
        }

        Ok(addrs)
    }

    /// Query HTTPS DNS record (type 65) for ECH config and ALPN info.
    pub async fn query_https_record(
        &self,
        hostname: &str,
    ) -> Result<Option<HttpsRecord>, Error> {
        // Check cache first
        {
            let cache = self.https_cache.lock().unwrap();
            if let Some(entry) = cache.get(hostname) {
                if entry.expires > Instant::now() {
                    return Ok(entry.record.clone());
                }
            }
        }

        let fqdn = ensure_fqdn(hostname);
        let msg = self.doh_query(&fqdn, RecordType::HTTPS).await?;

        let mut result: Option<HttpsRecord> = None;

        for record in msg.answers() {
            let svcb = match record.data() {
                RData::HTTPS(https) => &https.0,
                _ => continue,
            };

            // Skip AliasMode records (priority 0)
            if svcb.svc_priority() == 0 {
                continue;
            }

            let mut alpn = Vec::new();
            let mut ech_config_list = None;

            for (key, value) in svcb.svc_params() {
                match (key, value) {
                    (SvcParamKey::Alpn, SvcParamValue::Alpn(a)) => {
                        alpn = a.0.clone();
                    }
                    (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                        ech_config_list = Some(e.0.clone());
                    }
                    _ => {}
                }
            }

            result = Some(HttpsRecord {
                ech_config_list,
                alpn,
            });
            break; // Use first ServiceMode record
        }

        // Cache results
        {
            let mut cache = self.https_cache.lock().unwrap();
            cache.insert(
                hostname.to_string(),
                HttpsCacheEntry {
                    record: result.clone(),
                    expires: Instant::now() + DNS_CACHE_TTL,
                },
            );
        }

        Ok(result)
    }

    /// Send a single DoH query and return the parsed response.
    async fn doh_query(&self, fqdn: &str, rtype: RecordType) -> Result<Message, Error> {
        let wire = build_dns_wire(fqdn, rtype)?;
        let response_bytes = self.doh_post(&wire).await?;
        Message::from_bytes(&response_bytes)
            .map_err(|e| Error::Dns(format!("Failed to parse DNS response: {e}")))
    }

    /// Perform DoH POST: TCP → TLS → HTTP/1.1 POST /dns-query.
    async fn doh_post(&self, dns_wire: &[u8]) -> Result<Vec<u8>, Error> {
        let addr = format!("{}:{}", self.config.server_ip, self.config.server_port);

        // TCP connect directly to IP (no DNS needed for the resolver itself)
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Dns("DoH connection timed out".into()))?
            .map_err(|e| Error::Dns(format!("DoH TCP connect failed: {e}")))?;

        tcp.set_nodelay(true).ok();

        // Minimal TLS handshake
        let cfg = self.tls_connector.configure()?;
        let ssl = cfg.into_ssl(&self.config.server_hostname)?;
        let mut stream = SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| Error::Dns(format!("DoH TLS handshake failed: {e}")))?;

        // HTTP/1.1 POST request
        let req = format!(
            "POST /dns-query HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            self.config.server_hostname,
            dns_wire.len(),
        );

        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| Error::Dns(format!("DoH write failed: {e}")))?;
        stream
            .write_all(dns_wire)
            .await
            .map_err(|e| Error::Dns(format!("DoH write body failed: {e}")))?;

        // Read response
        let mut buf = Vec::with_capacity(4096);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| Error::Dns(format!("DoH read failed: {e}")))?;

        // Parse HTTP response: find \r\n\r\n header/body separator
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| Error::Dns("DoH: invalid HTTP response".into()))?;

        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        if !header_str.starts_with("HTTP/1.1 200") && !header_str.starts_with("HTTP/1.0 200") {
            return Err(Error::Dns(format!(
                "DoH HTTP error: {}",
                header_str.lines().next().unwrap_or("unknown")
            )));
        }

        let body = buf[header_end + 4..].to_vec();
        Ok(body)
    }
}

/// Build DNS wire-format query message.
fn build_dns_wire(fqdn: &str, rtype: RecordType) -> Result<Vec<u8>, Error> {
    let name = Name::from_str(fqdn)
        .map_err(|e| Error::Dns(format!("Invalid DNS name '{fqdn}': {e}")))?;

    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::query(name, rtype);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);

    // EDNS for larger payloads
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    *msg.extensions_mut() = Some(edns);

    msg.to_bytes()
        .map_err(|e| Error::Dns(format!("Failed to encode DNS query: {e}")))
}

/// Ensure hostname ends with '.' for DNS FQDN.
fn ensure_fqdn(hostname: &str) -> String {
    if hostname.ends_with('.') {
        hostname.to_string()
    } else {
        format!("{hostname}.")
    }
}
