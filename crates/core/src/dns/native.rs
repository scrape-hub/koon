use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::OnceCell;

use super::HttpsRecord;
use super::cache::HttpsRecordCache;
use super::resolver::{build_dns_wire, ensure_fqdn, parse_https_answers};
use crate::Error;

const QUERY_TIMEOUT: Duration = Duration::from_millis(250);

const TCP_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// Queries HTTPS DNS records via a plain UDP query to the system's configured nameserver, the way a
/// browser's own default (non-DoH) configuration does. Address resolution is unaffected: it keeps
/// going through the OS resolver ([`tokio::net::lookup_host`]) as before, and this only adds the
/// HTTP/3-discovery and ECH information `getaddrinfo` cannot return.
#[derive(Default)]
pub struct NativeHttpsResolver {
    nameserver: OnceCell<Option<SocketAddr>>,
    https_cache: HttpsRecordCache,
}

impl NativeHttpsResolver {
    pub(crate) fn shared() -> std::sync::Arc<Self> {
        static SHARED: std::sync::OnceLock<std::sync::Arc<NativeHttpsResolver>> =
            std::sync::OnceLock::new();
        SHARED.get_or_init(std::sync::Arc::default).clone()
    }

    /// Queries `nameserver` directly instead of discovering the system's configured one: for a
    /// sandbox where that read is unavailable or wrong, or to point the query at a specific (e.g.
    /// local test) server.
    pub fn with_nameserver(nameserver: SocketAddr) -> Self {
        let cell = OnceCell::new();
        let _ = cell.set(Some(nameserver));
        Self {
            nameserver: cell,
            https_cache: HttpsRecordCache::default(),
        }
    }

    /// Query the HTTPS DNS record for `hostname` (the ServiceMode answer with the lowest
    /// SvcPriority); `Ok(None)` when the system's nameserver could not be found, did not answer in
    /// time, or answered without a usable record: the caller falls back to Alt-Svc, same as a
    /// browser without this capability.
    ///
    /// # Errors
    /// [`Error::Dns`] if the query cannot be built or the response cannot be parsed.
    pub async fn query_https_record(&self, hostname: &str) -> Result<Option<HttpsRecord>, Error> {
        super::first_https_record(|| self.query_https_records(hostname)).await
    }

    pub(crate) async fn query_https_records(
        &self,
        hostname: &str,
    ) -> Result<Vec<HttpsRecord>, Error> {
        self.https_cache
            .get_or_insert_with(hostname, || self.fetch_https_records(hostname))
            .await
    }

    async fn fetch_https_records(&self, hostname: &str) -> Result<Vec<HttpsRecord>, Error> {
        let Some(server) = self.nameserver().await else {
            return Ok(Vec::new());
        };

        let fqdn = ensure_fqdn(hostname);
        let wire = build_dns_wire(&fqdn, RecordType::HTTPS)?;
        let msg = tokio::time::timeout(QUERY_TIMEOUT, query_udp(server, &wire))
            .await
            .ok()
            .and_then(Result::ok);
        let msg = match msg {
            Some(msg) if msg.truncated() => {
                tokio::time::timeout(TCP_QUERY_TIMEOUT, query_tcp(server, &wire))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .or(Some(msg))
            }
            other => other,
        };
        Ok(msg.map(|msg| parse_https_answers(&msg)).unwrap_or_default())
    }

    async fn nameserver(&self) -> Option<SocketAddr> {
        *self
            .nameserver
            .get_or_init(|| async {
                tokio::task::spawn_blocking(|| {
                    let (config, _opts) = hickory_resolver::system_conf::read_system_conf().ok()?;
                    config.name_servers().first().map(|ns| ns.socket_addr)
                })
                .await
                .ok()
                .flatten()
            })
            .await
    }
}

fn validate_response(msg: &Message, wire: &[u8]) -> Result<(), Error> {
    let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
    if msg.id() != expected_id || msg.message_type() != MessageType::Response {
        return Err(Error::Dns(
            format!(
                "DNS response id/type mismatch (expected id {expected_id}, got {} {:?})",
                msg.id(),
                msg.message_type()
            ),
            None,
        ));
    }
    Ok(())
}

async fn query_udp(server: SocketAddr, wire: &[u8]) -> Result<hickory_proto::op::Message, Error> {
    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        let message = format!("binding UDP socket for DNS query: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    socket.connect(server).await.map_err(|e| {
        let message = format!("connecting UDP socket to {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    socket.send(wire).await.map_err(|e| {
        let message = format!("sending DNS query to {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    let mut buf = [0u8; 4096];
    let n = socket.recv(&mut buf).await.map_err(|e| {
        let message = format!("receiving DNS response from {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    let msg = hickory_proto::op::Message::from_bytes(&buf[..n]).map_err(|e| {
        let message = format!("parsing DNS response from {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    validate_response(&msg, wire)?;
    Ok(msg)
}

async fn query_tcp(server: SocketAddr, wire: &[u8]) -> Result<Message, Error> {
    let mut stream = TcpStream::connect(server).await.map_err(|e| {
        let message = format!("connecting TCP socket to {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    let len = u16::try_from(wire.len()).map_err(|e| {
        Error::Dns(
            "DNS query too long for the TCP length prefix".into(),
            crate::error::boxed(e),
        )
    })?;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| {
        let message = format!("sending DNS query length to {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    stream.write_all(wire).await.map_err(|e| {
        let message = format!("sending DNS query to {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        let message = format!("receiving DNS response length from {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream.read_exact(&mut body).await.map_err(|e| {
        let message = format!("receiving DNS response from {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    let msg = Message::from_bytes(&body).map_err(|e| {
        let message = format!("parsing DNS response from {server}: {e}");
        Error::Dns(message, crate::error::boxed(e))
    })?;
    validate_response(&msg, wire)?;
    Ok(msg)
}
