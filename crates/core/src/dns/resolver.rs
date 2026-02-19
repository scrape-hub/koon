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
///
/// Uses a persistent HTTP/2 connection to the DoH server, multiplexing
/// all queries on a single TCP+TLS connection for efficiency.
pub struct DohResolver {
    config: DohConfig,
    tls_connector: SslConnector,
    ip_cache: Mutex<HashMap<String, DnsCacheEntry>>,
    https_cache: Mutex<HashMap<String, HttpsCacheEntry>>,
    /// Persistent H2 connection to the DoH server (lazily created, auto-reconnects).
    h2_sender: tokio::sync::Mutex<Option<http2::client::SendRequest<bytes::Bytes>>>,
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
            h2_sender: tokio::sync::Mutex::new(None),
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
        let response_bytes = self.doh_h2_post(&wire).await?;
        Message::from_bytes(&response_bytes)
            .map_err(|e| Error::Dns(format!("Failed to parse DNS response: {e}")))
    }

    /// Get or create a persistent H2 connection to the DoH server.
    async fn get_or_connect_h2(
        &self,
    ) -> Result<http2::client::SendRequest<bytes::Bytes>, Error> {
        let mut guard = self.h2_sender.lock().await;

        // Try to reuse existing sender
        if let Some(ref sender) = *guard {
            match sender.clone().ready().await {
                Ok(_) => return Ok(sender.clone()),
                Err(_) => {
                    *guard = None;
                }
            }
        }

        // Create new TCP+TLS+H2 connection
        let addr = format!("{}:{}", self.config.server_ip, self.config.server_port);

        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Dns("DoH connection timed out".into()))?
            .map_err(|e| Error::Dns(format!("DoH TCP connect failed: {e}")))?;

        tcp.set_nodelay(true).ok();

        // TLS handshake with h2 ALPN
        let mut cfg = self.tls_connector.configure()?;
        cfg.set_alpn_protos(b"\x02h2")?;
        let ssl = cfg.into_ssl(&self.config.server_hostname)?;
        let mut stream = SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| Error::Dns(format!("DoH TLS handshake failed: {e}")))?;

        // H2 handshake
        let (sender, conn) = http2::client::Builder::new()
            .handshake::<_, bytes::Bytes>(stream)
            .await
            .map_err(|e| Error::Dns(format!("DoH H2 handshake failed: {e}")))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("DoH H2 connection error: {e}");
            }
        });

        *guard = Some(sender.clone());
        Ok(sender)
    }

    /// Perform DoH POST over persistent H2 connection.
    async fn doh_h2_post(&self, dns_wire: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sender = self.get_or_connect_h2().await?;

        sender
            .clone()
            .ready()
            .await
            .map_err(|e| Error::Dns(format!("DoH H2 not ready: {e}")))?;

        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://{}/dns-query", self.config.server_hostname))
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| Error::Dns(format!("DoH request build failed: {e}")))?;

        let (response, mut send_stream) = sender
            .send_request(req, false)
            .map_err(|e| Error::Dns(format!("DoH H2 send failed: {e}")))?;

        send_stream
            .send_data(bytes::Bytes::copy_from_slice(dns_wire), true)
            .map_err(|e| Error::Dns(format!("DoH H2 send data failed: {e}")))?;

        let response = response
            .await
            .map_err(|e| Error::Dns(format!("DoH H2 response failed: {e}")))?;

        if response.status() != http::StatusCode::OK {
            return Err(Error::Dns(format!(
                "DoH HTTP error: {}",
                response.status()
            )));
        }

        let mut body = Vec::new();
        let mut recv_stream = response.into_body();
        while let Some(chunk) = recv_stream.data().await {
            let chunk =
                chunk.map_err(|e| Error::Dns(format!("DoH H2 body read failed: {e}")))?;
            body.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }

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
