use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use btls::ssl::{SslConnector, SslMethod, SslVerifyMode};
use btls::x509::X509;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::record_data::RData;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::TcpStream;
use tokio_btls::SslStream;

use super::cache::HttpsRecordCache;
use crate::Error;

/// Upper bound for connecting to the DoH server: TCP, TLS and HTTP/2.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for sending the query and reading the full response on an already-connected H2
/// session: guards a peer that accepts the request but then stalls or trickles the response.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A DNS-over-HTTPS response is a DNS message, bounded like one over TCP (RFC 1035 §4.2.2);
/// nothing legitimate is anywhere near this large.
const MAX_DOH_BODY: usize = 65_535;

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

/// DoH providers known by name: name, server IP, TLS hostname.
const PROVIDERS: &[(&str, Ipv4Addr, &str)] = &[
    (
        "cloudflare",
        Ipv4Addr::new(1, 1, 1, 1),
        "cloudflare-dns.com",
    ),
    ("google", Ipv4Addr::new(8, 8, 8, 8), "dns.google"),
];

impl FromStr for DohConfig {
    type Err = Error;

    /// A DoH provider by name: `"cloudflare"` or `"google"`, ignoring case.
    fn from_str(name: &str) -> Result<Self, Error> {
        PROVIDERS
            .iter()
            .find(|(provider, ..)| provider.eq_ignore_ascii_case(name))
            .map(|&(_, ip, hostname)| Self {
                server_ip: IpAddr::V4(ip),
                server_hostname: hostname.into(),
                server_port: 443,
            })
            .ok_or_else(|| {
                Error::InvalidArgument(
                    format!("Unknown DoH provider: '{name}'. Supported: cloudflare, google"),
                    None,
                )
            })
    }
}

/// HTTPS DNS record data (RR type 65).
#[derive(Debug, Clone)]
pub struct HttpsRecord {
    /// ECHConfigList bytes (SvcParam key=5).
    pub ech_config_list: Option<Vec<u8>>,
    /// ALPN protocols (SvcParam key=1).
    pub alpn: Vec<String>,
    /// Target port (SvcParam key=3); `None` means the connection's own port, as most records leave
    /// it (RFC 9460 §7.2).
    pub port: Option<u16>,
    /// `ipv4hint` (SvcParam key=4), in record order.
    pub ipv4hint: Vec<Ipv4Addr>,
    /// `ipv6hint` (SvcParam key=6), in record order.
    pub ipv6hint: Vec<Ipv6Addr>,
}

impl HttpsRecord {
    /// The address hints (`ipv6hint` before `ipv4hint`, as most dual-stack clients try IPv6 first),
    /// for a client that skips its own A/AAAA lookup in favor of them — Safari does (arXiv
    /// 2403.15672), falling back to a normal lookup when a record carries neither.
    pub fn hint_addresses(&self) -> Vec<IpAddr> {
        self.ipv6hint
            .iter()
            .copied()
            .map(IpAddr::V6)
            .chain(self.ipv4hint.iter().copied().map(IpAddr::V4))
            .collect()
    }
}

/// DNS-over-HTTPS resolver: encrypted queries via HTTPS POST to a trusted resolver (Cloudflare or
/// Google), over a persistent, auto-reconnecting HTTP/2 connection. Addresses are not cached here
/// (the client caches them); HTTPS records are, in an `HttpsRecordCache` shared with
/// [`super::NativeHttpsResolver`]'s.
pub struct DohResolver {
    config: DohConfig,
    tls_connector: SslConnector,
    https_cache: HttpsRecordCache,
    /// Persistent H2 connection to the DoH server (lazily created, auto-reconnects).
    h2_sender: Mutex<Option<http2::client::SendRequest<bytes::Bytes>>>,
}

impl DohResolver {
    /// Create a resolver using Cloudflare's DoH service (1.1.1.1).
    ///
    /// # Errors
    /// Returns an error if the TLS connector cannot be built.
    pub fn with_cloudflare() -> Result<Self, Error> {
        Self::new("cloudflare".parse()?)
    }

    /// Create a resolver using Google's DoH service (8.8.8.8).
    ///
    /// # Errors
    /// Returns an error if the TLS connector cannot be built.
    pub fn with_google() -> Result<Self, Error> {
        Self::new("google".parse()?)
    }

    /// Create a resolver with custom DoH config.
    ///
    /// # Errors
    /// Returns an error if the TLS connector cannot be built.
    pub fn new(config: DohConfig) -> Result<Self, Error> {
        Self::build(config, &[])
    }

    /// Creates a resolver that additionally trusts the certificates of the PEM bundle `pem` for its
    /// own DoH connection — for a local DoH server in a test, whose certificate koon's built-in
    /// root store does not cover.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if `pem` holds no certificate or an invalid one.
    pub fn with_extra_roots(config: DohConfig, pem: &[u8]) -> Result<Self, Error> {
        let certs = X509::stack_from_pem(pem).map_err(|e| {
            let message = format!("Invalid DoH CA certificate PEM: {e}");
            Error::InvalidArgument(message, crate::error::boxed(e))
        })?;
        if certs.is_empty() {
            return Err(Error::InvalidArgument(
                "No certificate found in the DoH CA PEM".into(),
                None,
            ));
        }
        Self::build(config, &certs)
    }

    /// Shared by [`new`](Self::new) and [`with_extra_roots`](Self::with_extra_roots).
    fn build(config: DohConfig, extra_roots: &[X509]) -> Result<Self, Error> {
        // Minimal TLS config for the DoH connection itself, not the browser fingerprint.
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::PEER);
        if extra_roots.is_empty() {
            crate::tls::root_store::load(&mut builder)?;
        } else {
            builder.set_verify_cert_store(crate::tls::root_store::with_extra(extra_roots)?)?;
        }
        crate::tls::keylog::install(&mut builder);
        let tls_connector = builder.build();

        Ok(Self {
            config,
            tls_connector,
            https_cache: HttpsRecordCache::default(),
            h2_sender: Mutex::new(None),
        })
    }

    /// Resolve a hostname to IP addresses via DoH (A and AAAA queries in parallel).
    ///
    /// # Errors
    /// [`Error::Dns`] if neither query succeeds or none has an address.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, Error> {
        let fqdn = ensure_fqdn(hostname);
        let (a, aaaa) = tokio::join!(
            self.doh_query(&fqdn, RecordType::A),
            self.doh_query(&fqdn, RecordType::AAAA),
        );
        let addrs: Vec<IpAddr> = [&a, &aaaa]
            .into_iter()
            .flatten()
            .flat_map(Message::answers)
            .filter_map(|record| match record.data() {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect();
        if !addrs.is_empty() {
            return Ok(addrs);
        }
        match (a, aaaa) {
            (Err(a), Err(aaaa)) => {
                let message = format!("resolving {hostname}: A: {a}; AAAA: {aaaa}");
                Err(Error::Dns(message, crate::error::boxed(a)))
            }
            (Err(e), Ok(_)) | (Ok(_), Err(e)) => {
                let message = format!("resolving {hostname}: {e}");
                Err(Error::Dns(message, crate::error::boxed(e)))
            }
            (Ok(_), Ok(_)) => Err(Error::Dns(
                format!("No addresses found for {hostname}"),
                None,
            )),
        }
    }

    /// Query HTTPS DNS record (type 65) for ECH config, ALPN (HTTP/3 discovery) and port info: the
    /// ServiceMode answer with the lowest SvcPriority.
    ///
    /// # Errors
    /// [`Error::Dns`] if the query fails or the response cannot be parsed.
    pub async fn query_https_record(&self, hostname: &str) -> Result<Option<HttpsRecord>, Error> {
        super::first_https_record(|| self.query_https_records(hostname)).await
    }

    /// Every ServiceMode HTTPS record of `hostname`, lowest SvcPriority first, for a client that
    /// skips some of them (Chromium: those on another port).
    pub(crate) async fn query_https_records(
        &self,
        hostname: &str,
    ) -> Result<Vec<HttpsRecord>, Error> {
        self.https_cache
            .get_or_insert_with(hostname, || async {
                let fqdn = ensure_fqdn(hostname);
                let msg = self.doh_query(&fqdn, RecordType::HTTPS).await?;
                Ok(parse_https_answers(&msg))
            })
            .await
    }

    /// Send a single DoH query and return the parsed response.
    async fn doh_query(&self, fqdn: &str, rtype: RecordType) -> Result<Message, Error> {
        let wire = build_dns_wire(fqdn, rtype)?;
        let response_bytes = self.doh_h2_post(&wire).await?;
        Message::from_bytes(&response_bytes).map_err(|e| {
            let message = format!("Failed to parse DNS response: {e}");
            Error::Dns(message, crate::error::boxed(e))
        })
    }

    /// The persistent H2 connection to the DoH server, connecting when there is none or it broke.
    /// Queries racing for a new connection may each open one; the last one stays.
    async fn get_or_connect_h2(&self) -> Result<http2::client::SendRequest<bytes::Bytes>, Error> {
        let current = crate::util::lock_recover(&self.h2_sender).clone();
        if let Some(sender) = current {
            if let Ok(sender) = sender.ready().await {
                return Ok(sender);
            }
        }
        let sender = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_h2())
            .await
            .map_err(|_| Error::Dns("DoH connection timed out".into(), None))??;
        *crate::util::lock_recover(&self.h2_sender) = Some(sender.clone());
        Ok(sender)
    }

    /// A new TCP, TLS and HTTP/2 connection to the DoH server.
    async fn connect_h2(&self) -> Result<http2::client::SendRequest<bytes::Bytes>, Error> {
        let addr = (self.config.server_ip, self.config.server_port);
        let tcp = TcpStream::connect(addr).await.map_err(|e| {
            let message = format!("DoH TCP connect failed: {e}");
            Error::Dns(message, crate::error::boxed(e))
        })?;
        tcp.set_nodelay(true).ok();

        let mut cfg = self.tls_connector.configure()?;
        cfg.set_alpn_protos(b"\x02h2")?;
        let ssl = cfg.into_ssl(&self.config.server_hostname)?;
        let mut stream = SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream).connect().await.map_err(|e| {
            let message = format!("DoH TLS handshake failed: {e}");
            Error::Dns(message, crate::error::boxed(e))
        })?;

        let (sender, conn) = http2::client::Builder::new()
            .handshake::<_, bytes::Bytes>(stream)
            .await
            .map_err(|e| {
                let message = format!("DoH H2 handshake failed: {e}");
                Error::Dns(message, crate::error::boxed(e))
            })?;
        // Errors surface on the queries that use the connection.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }

    /// Perform DoH POST over persistent H2 connection: send the query and read the full response,
    /// under one overall timeout, once the connection itself is established
    /// ([`get_or_connect_h2`](Self::get_or_connect_h2) has its own for that).
    async fn doh_h2_post(&self, dns_wire: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sender = self.get_or_connect_h2().await?;

        tokio::time::timeout(RESPONSE_TIMEOUT, async {
            sender.clone().ready().await.map_err(|e| {
                let message = format!("DoH H2 not ready: {e}");
                Error::Dns(message, crate::error::boxed(e))
            })?;

            let req = http::Request::builder()
                .method("POST")
                .uri(format!("https://{}/dns-query", self.config.server_hostname))
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", dns_wire.len().to_string())
                .body(())
                .map_err(|e| {
                    let message = format!("DoH request build failed: {e}");
                    Error::Dns(message, crate::error::boxed(e))
                })?;

            let (response, mut send_stream) = sender.send_request(req, false).map_err(|e| {
                let message = format!("DoH H2 send failed: {e}");
                Error::Dns(message, crate::error::boxed(e))
            })?;

            send_stream
                .send_data(bytes::Bytes::copy_from_slice(dns_wire), true)
                .map_err(|e| {
                    let message = format!("DoH H2 send data failed: {e}");
                    Error::Dns(message, crate::error::boxed(e))
                })?;

            let response = response.await.map_err(|e| {
                let message = format!("DoH H2 response failed: {e}");
                Error::Dns(message, crate::error::boxed(e))
            })?;

            if response.status() != http::StatusCode::OK {
                return Err(Error::Dns(
                    format!("DoH HTTP error: {}", response.status()),
                    None,
                ));
            }

            let mut body = Vec::new();
            let mut recv_stream = response.into_body();
            while let Some(chunk) = recv_stream.data().await {
                let chunk = chunk.map_err(|e| {
                    let message = format!("DoH H2 body read failed: {e}");
                    Error::Dns(message, crate::error::boxed(e))
                })?;
                if body.len() + chunk.len() > MAX_DOH_BODY {
                    return Err(Error::Dns("DoH response body too large".into(), None));
                }
                body.extend_from_slice(&chunk);
                let _ = recv_stream.flow_control().release_capacity(chunk.len());
            }
            Ok(body)
        })
        .await
        .map_err(|_| Error::Dns("DoH request timed out".into(), None))?
    }
}

/// Parse the HTTPS records from a DNS response: the alpn, ECHConfigList, port and address hints of
/// each ServiceMode answer, lowest SvcPriority first (RFC 9460 §2.4.1: answers may come in any
/// order), shared by the DoH and the native (plain) query. AliasMode answers (priority 0) are
/// skipped.
pub(super) fn parse_https_answers(msg: &Message) -> Vec<HttpsRecord> {
    let mut services: Vec<&SVCB> = msg
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::HTTPS(https) => Some(&https.0),
            _ => None,
        })
        .filter(|svcb| svcb.svc_priority() != 0)
        .collect();
    // Stable: answers of equal priority keep their order.
    services.sort_by_key(|svcb| svcb.svc_priority());
    services.into_iter().map(https_record).collect()
}

/// The parameters of one ServiceMode answer.
fn https_record(svcb: &SVCB) -> HttpsRecord {
    let mut alpn = Vec::new();
    let mut ech_config_list = None;
    let mut port = None;
    let mut ipv4hint = Vec::new();
    let mut ipv6hint = Vec::new();

    for (key, value) in svcb.svc_params() {
        match (key, value) {
            (SvcParamKey::Alpn, SvcParamValue::Alpn(a)) => {
                alpn = a.0.clone();
            }
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => {
                ech_config_list = Some(e.0.clone());
            }
            (SvcParamKey::Port, SvcParamValue::Port(p)) => {
                port = Some(*p);
            }
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hint)) => {
                ipv4hint = hint.0.iter().map(|a| a.0).collect();
            }
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(hint)) => {
                ipv6hint = hint.0.iter().map(|a| a.0).collect();
            }
            _ => {}
        }
    }

    HttpsRecord {
        ech_config_list,
        alpn,
        port,
        ipv4hint,
        ipv6hint,
    }
}

/// Build DNS wire-format query message.
pub(super) fn build_dns_wire(fqdn: &str, rtype: RecordType) -> Result<Vec<u8>, Error> {
    let name = Name::from_str(fqdn).map_err(|e| {
        let message = format!("Invalid DNS name '{fqdn}': {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;

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

    msg.to_bytes().map_err(|e| {
        let message = format!("Failed to encode DNS query: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })
}

/// Ensure hostname ends with '.' for DNS FQDN.
pub(super) fn ensure_fqdn(hostname: &str) -> String {
    if hostname.ends_with('.') {
        hostname.to_string()
    } else {
        format!("{hostname}.")
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::rdata::svcb::{Alpn, SVCB};

    use super::*;

    fn https(priority: u16, alpn: &[&str]) -> Record {
        let params = vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(alpn.iter().map(|p| p.to_string()).collect())),
        )];
        Record::from_rdata(
            Name::from_str("quic.example.").unwrap(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(priority, Name::root(), params))),
        )
    }

    #[test]
    fn service_mode_answers_come_lowest_priority_first() {
        let mut msg = Message::new();
        msg.add_answer(https(0, &[]));
        msg.add_answer(https(2, &["http/1.1"]));
        msg.add_answer(https(1, &["h3"]));
        let alpns: Vec<Vec<String>> = parse_https_answers(&msg)
            .into_iter()
            .map(|record| record.alpn)
            .collect();
        assert_eq!(alpns, [vec!["h3"], vec!["http/1.1"]]);

        let mut alias_only = Message::new();
        alias_only.add_answer(https(0, &[]));
        assert!(parse_https_answers(&alias_only).is_empty());
    }
}
