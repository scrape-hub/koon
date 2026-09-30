//! Plain (non-DoH) HTTPS DNS record queries: the discovery Chromium and Firefox do by default when
//! no secure DNS is configured (`kUseDnsHttpsSvcb`; Firefox's `network.dns.native_https_query`).
//!
//! `getaddrinfo` has no way to ask for record type 65, so this issues its own minimal UDP query to
//! the system's configured nameserver, sharing its wire format and answer parsing with
//! [`super::DohResolver`]. A truncated answer retries once over TCP (RFC 1035 §4.2.2) rather than
//! trusting a possibly-incomplete one.

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

/// Upper bound for the UDP round trip to the system's nameserver.
const QUERY_TIMEOUT: Duration = Duration::from_millis(250);

/// Upper bound for the TCP retry after a truncated UDP answer: its own connection setup on top of
/// the UDP round trip already spent.
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
    /// Queries `nameserver` directly instead of discovering the system's configured one: for a
    /// sandbox where that read is unavailable or wrong, or to point the query at a specific (e.g.
    /// local test) server.
    pub fn with_nameserver(nameserver: SocketAddr) -> Self {
        let cell = OnceCell::new();
        // Infallible: nothing else can have raced this brand new cell.
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

    /// Every ServiceMode HTTPS record of `hostname`, lowest SvcPriority first; none in the cases
    /// [`query_https_record`](Self::query_https_record) answers `None`.
    pub(crate) async fn query_https_records(
        &self,
        hostname: &str,
    ) -> Result<Vec<HttpsRecord>, Error> {
        self.https_cache
            .get_or_insert_with(hostname, || self.fetch_https_records(hostname))
            .await
    }

    /// The plain-DNS fetch behind [`query_https_records`](Self::query_https_records)'s cache.
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
        // A truncated answer (`TC` bit) may be missing SvcParams: retry over TCP instead of
        // parsing it as is.
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

    /// The first nameserver the OS is configured to use, discovered once per process (a
    /// registry/file read, so kept off the async runtime's worker threads).
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

/// Reject a response whose transaction ID does not match the query's, or that is not marked as a
/// response (RFC 5452 §5.1): the second half of spoofing resistance a `connect()`ed UDP socket's
/// source-address filter does not give on its own, and a sanity check TCP's connection-oriented
/// transport does not need but costs nothing to also apply.
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

/// Send `wire` to `server` over UDP and parse the response as a DNS message.
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

/// Send `wire` to `server` over TCP (RFC 1035 §4.2.2: a 2-byte big-endian length before the
/// message, on both sides) and parse the response: the retry after a truncated UDP answer.
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

#[cfg(test)]
mod tests {
    use hickory_proto::op::OpCode;
    use hickory_proto::serialize::binary::BinEncodable;
    use tokio::net::TcpListener;

    use super::*;

    /// A UDP responder that answers the first datagram it receives with a message carrying `id`
    /// and `message_type` instead of echoing back what the query actually asked for.
    async fn spoofed_udp_responder(id: u16, message_type: MessageType) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_, from)) = socket.recv_from(&mut buf).await {
                let mut response = Message::new();
                response.set_id(id);
                response.set_message_type(message_type);
                response.set_op_code(OpCode::Query);
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, from).await;
                }
            }
        });
        addr
    }

    /// A TCP responder that answers the first length-prefixed query with a length-prefixed
    /// message carrying `id` and `message_type` instead of echoing back what the query actually
    /// asked for.
    async fn spoofed_tcp_responder(id: u16, message_type: MessageType) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
                if stream.read_exact(&mut body).await.is_err() {
                    return;
                }
                let mut response = Message::new();
                response.set_id(id);
                response.set_message_type(message_type);
                response.set_op_code(OpCode::Query);
                let Ok(bytes) = response.to_bytes() else {
                    return;
                };
                let len = (bytes.len() as u16).to_be_bytes();
                let _ = stream.write_all(&len).await;
                let _ = stream.write_all(&bytes).await;
            }
        });
        addr
    }

    /// A spoofed or racing response with the right source address but the wrong transaction ID
    /// must not be accepted as the answer (RFC 5452): this is what `validate_response` closes,
    /// since a `connect()`ed UDP socket's source-address filter alone does not check it.
    #[tokio::test]
    async fn query_udp_rejects_a_response_with_the_wrong_transaction_id() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server =
            spoofed_udp_responder(expected_id.wrapping_add(1), MessageType::Response).await;
        assert!(query_udp(server, &wire).await.is_err());
    }

    #[tokio::test]
    async fn query_udp_rejects_a_response_that_is_not_marked_as_one() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server = spoofed_udp_responder(expected_id, MessageType::Query).await;
        assert!(query_udp(server, &wire).await.is_err());
    }

    #[tokio::test]
    async fn query_udp_accepts_a_response_with_the_right_id_and_type() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server = spoofed_udp_responder(expected_id, MessageType::Response).await;
        assert!(query_udp(server, &wire).await.is_ok());
    }

    #[tokio::test]
    async fn query_tcp_rejects_a_response_with_the_wrong_transaction_id() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server =
            spoofed_tcp_responder(expected_id.wrapping_add(1), MessageType::Response).await;
        assert!(query_tcp(server, &wire).await.is_err());
    }

    #[tokio::test]
    async fn query_tcp_rejects_a_response_that_is_not_marked_as_one() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server = spoofed_tcp_responder(expected_id, MessageType::Query).await;
        assert!(query_tcp(server, &wire).await.is_err());
    }

    #[tokio::test]
    async fn query_tcp_accepts_a_response_with_the_right_id_and_type() {
        let wire = build_dns_wire("example.com.", RecordType::HTTPS).unwrap();
        let expected_id = u16::from_be_bytes([wire[0], wire[1]]);
        let server = spoofed_tcp_responder(expected_id, MessageType::Response).await;
        assert!(query_tcp(server, &wire).await.is_ok());
    }
}
