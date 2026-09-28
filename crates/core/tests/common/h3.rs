//! A local HTTP/3 server (quinn with quinn-btls, h3) and a UDP relay in
//! front of it that records what clients send.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use btls::pkey::{PKey, Private};
use btls::x509::X509;
use bytes::Bytes;
use h3_quinn::quinn;
use quinn_btls::{QuicSslContext, ServerConfig};
use tokio::net::UdpSocket;

/// One-way delay of the server's datagrams through the relay.
const PATH_DELAY: Duration = Duration::from_millis(40);

/// A local HTTP/3 server answering every request with `200 ok`.
pub struct H3Server {
    pub addr: SocketAddr,
    /// Requests the HTTP/3 layer received.
    pub requests: Arc<AtomicUsize>,
    /// How the client connections ended, in the order they did.
    pub closes: Arc<Mutex<Vec<quinn::ConnectionError>>>,
    /// The connections the server accepted, in order.
    pub connections: Arc<Mutex<Vec<quinn::Connection>>>,
}

impl H3Server {
    /// Wait until `n` connections have ended, and return how.
    pub async fn closes(&self, n: usize) -> Vec<quinn::ConnectionError> {
        for _ in 0..200 {
            let closes = self.closes.lock().unwrap().clone();
            if closes.len() >= n {
                return closes;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{:?}", self.closes.lock().unwrap());
    }

    /// The connection the server accepted last.
    pub fn last_connection(&self) -> quinn::Connection {
        self.connections.lock().unwrap().last().unwrap().clone()
    }
}

/// Every server gets TLS session ticket keys of its own, so it cannot
/// resume another one's sessions.
pub fn h3_server(cert: X509, key: PKey<Private>) -> H3Server {
    h3_server_with_versions(cert, key, None)
}

/// An HTTP/3 server that accepts the QUIC `versions` (quinn-btls's by
/// default); one that lists version 2 first switches the connections that
/// offer it to version 2 (RFC 9368).
pub fn h3_server_with_versions(
    cert: X509,
    key: PKey<Private>,
    versions: Option<Vec<u32>>,
) -> H3Server {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    h3_server_inner(cert, key, socket, versions, None)
}

/// An HTTP/3 server that sends `alps` as its ALPS data for `h3`, under the
/// codepoint Chrome uses, to clients that offer ALPS. The data may be set
/// after the server started.
pub fn h3_server_with_alps(cert: X509, key: PKey<Private>, alps: Arc<Mutex<Vec<u8>>>) -> H3Server {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    h3_server_inner(cert, key, socket, None, Some(alps))
}

/// An HTTP/3 server on a UDP socket the caller already bound — for a test
/// that needs the server's port picked before it starts (matching a TCP
/// port already bound elsewhere: pick that one first with `:0`, since
/// Windows never excludes it there, then bind UDP to the same number and
/// retry on a fresh TCP port if that fails; Hyper-V/WSL reserve some TCP
/// ranges — `netsh int ipv4 show excludedportrange protocol=tcp` — and
/// binding UDP first risked landing on one).
pub fn h3_server_with_socket(
    cert: X509,
    key: PKey<Private>,
    socket: std::net::UdpSocket,
) -> H3Server {
    h3_server_inner(cert, key, socket, None, None)
}

mod alps {
    //! Server-side ALPS through BoringSSL's early callback, which quinn-btls
    //! leaves free (its ALPN callback is taken).

    use std::collections::HashMap;
    use std::ffi::{c_int, c_void};
    use std::sync::{Arc, Mutex, OnceLock};

    unsafe extern "C" {
        fn SSL_CTX_set_select_certificate_cb(
            ctx: *mut c_void,
            cb: Option<unsafe extern "C" fn(*const ClientHello) -> c_int>,
        );
        fn SSL_get_SSL_CTX(ssl: *const c_void) -> *mut c_void;
        fn SSL_set_alps_use_new_codepoint(ssl: *mut c_void, use_new: c_int);
        fn SSL_add_application_settings(
            ssl: *mut c_void,
            proto: *const u8,
            proto_len: usize,
            settings: *const u8,
            settings_len: usize,
        ) -> c_int;
    }

    /// The start of BoringSSL's `SSL_CLIENT_HELLO`.
    #[repr(C)]
    pub struct ClientHello {
        ssl: *mut c_void,
    }

    /// ALPS data by SSL_CTX address.
    fn data() -> &'static Mutex<HashMap<usize, Arc<Mutex<Vec<u8>>>>> {
        static DATA: OnceLock<Mutex<HashMap<usize, Arc<Mutex<Vec<u8>>>>>> = OnceLock::new();
        DATA.get_or_init(Mutex::default)
    }

    unsafe extern "C" fn select(hello: *const ClientHello) -> c_int {
        // SAFETY: BoringSSL passes a live client hello and its SSL.
        unsafe {
            let ssl = (*hello).ssl;
            let ctx = SSL_get_SSL_CTX(ssl) as usize;
            let alps = data().lock().unwrap().get(&ctx).cloned();
            if let Some(alps) = alps {
                let alps = alps.lock().unwrap().clone();
                SSL_set_alps_use_new_codepoint(ssl, 1);
                SSL_add_application_settings(ssl, b"h3".as_ptr(), 2, alps.as_ptr(), alps.len());
            }
        }
        1 // ssl_select_cert_success
    }

    /// Send `alps` from the SSL_CTX at `ctx`.
    pub fn install(ctx: *mut c_void, alps: Arc<Mutex<Vec<u8>>>) {
        data().lock().unwrap().insert(ctx as usize, alps);
        // SAFETY: `ctx` is a live SSL_CTX the server config owns.
        unsafe { SSL_CTX_set_select_certificate_cb(ctx, Some(select)) };
    }
}

fn h3_server_inner(
    cert: X509,
    key: PKey<Private>,
    socket: std::net::UdpSocket,
    versions: Option<Vec<u32>>,
    alps: Option<Arc<Mutex<Vec<u8>>>>,
) -> H3Server {
    let mut crypto = ServerConfig::new().unwrap();
    crypto.ctx_mut().set_certificate(cert).unwrap();
    crypto.ctx_mut().set_private_key(key).unwrap();
    if let Some(alps) = alps {
        // In the foreign-types pattern, &SslContextRef is the SSL_CTX
        // pointer.
        let ctx: &mut btls::ssl::SslContextRef = crypto.ctx_mut();
        alps::install(
            ctx as *mut btls::ssl::SslContextRef as *mut std::ffi::c_void,
            alps,
        );
    }
    let config = quinn_btls::helpers::server_config(Arc::new(crypto)).unwrap();
    let mut endpoint_config = quinn_btls::helpers::default_endpoint_config();
    if let Some(versions) = versions {
        endpoint_config.supported_versions(versions);
    }
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(config),
        socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let closes: Arc<Mutex<Vec<quinn::ConnectionError>>> = Arc::default();
    let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::default();
    let (count, ended, accepted) = (requests.clone(), closes.clone(), connections.clone());
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let (count, ended, accepted) = (count.clone(), ended.clone(), accepted.clone());
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                accepted.lock().unwrap().push(connection.clone());
                let watched = connection.clone();
                let (recorded, is_recorded) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let reason = watched.closed().await;
                    ended.lock().unwrap().push(reason);
                    let _ = recorded.send(());
                });
                let Ok(mut h3) = h3::server::builder()
                    .build::<_, Bytes>(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let count = count.clone();
                    tokio::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        count.fetch_add(1, Ordering::SeqCst);
                        // With `x-reject`: reject the request unprocessed.
                        if request.headers().contains_key("x-reject") {
                            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                            return;
                        }
                        // With `x-early-hints`: read the whole request body,
                        // then answer 103 Early Hints before the response.
                        if request.headers().contains_key("x-early-hints") {
                            while let Ok(Some(_)) = stream.recv_data().await {}
                            let hints = http::Response::builder()
                                .status(103)
                                .header("link", "</style.css>; rel=preload; as=style")
                                .body(())
                                .unwrap();
                            let _ = stream.send_response(hints).await;
                        }
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                        let _ = stream.finish().await;
                    });
                }
                // Dropping the session closes the connection, and quinn then
                // reports that close instead of the client's.
                let _ = tokio::time::timeout(Duration::from_secs(1), is_recorded).await;
                drop(h3);
            });
        }
    });
    H3Server {
        addr,
        requests,
        closes,
        connections,
    }
}

/// What the relay saw of one client socket.
#[derive(Clone, Default)]
pub struct ClientSocket {
    pub addr: Option<SocketAddr>,
    /// Bytes of 0-RTT packets.
    pub zero_rtt: usize,
    /// The datagrams that start with a long-header packet, in order.
    pub long_header_datagrams: Vec<Vec<u8>>,
    /// Bytes the server has sent this client so far — a test waits for this
    /// to stop growing to know the server has nothing more in flight (its
    /// session ticket included), instead of guessing how long that takes.
    pub server_bytes: usize,
}

impl ClientSocket {
    /// The QUIC versions of the long-header datagrams, in order.
    pub fn versions(&self) -> Vec<u32> {
        self.long_header_datagrams
            .iter()
            .map(|d| u32::from_be_bytes([d[1], d[2], d[3], d[4]]))
            .collect()
    }
}

/// A UDP relay in front of the servers. It forwards each new client socket
/// to the current server, delays the server's datagrams like a real path
/// does (so the client has something to send in 0-RTT before the handshake
/// completes), and records what each client socket sends.
pub struct Relay {
    pub addr: SocketAddr,
    /// Where new client sockets are forwarded to.
    backend: Arc<Mutex<SocketAddr>>,
    /// The client sockets in the order they appeared.
    clients: Arc<Mutex<Vec<ClientSocket>>>,
}

impl Relay {
    pub async fn start(backend: SocketAddr) -> Relay {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let backend = Arc::new(Mutex::new(backend));
        let clients: Arc<Mutex<Vec<ClientSocket>>> = Arc::default();
        let (current, seen) = (backend.clone(), clients.clone());
        tokio::spawn(async move {
            let mut backs: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65_536];
            while let Ok((n, client)) = front.recv_from(&mut buf).await {
                let datagram = &buf[..n];
                {
                    let mut seen = seen.lock().unwrap();
                    let entry = match seen.iter().position(|c| c.addr == Some(client)) {
                        Some(i) => &mut seen[i],
                        None => {
                            seen.push(ClientSocket {
                                addr: Some(client),
                                ..ClientSocket::default()
                            });
                            seen.last_mut().unwrap()
                        }
                    };
                    entry.zero_rtt += zero_rtt_bytes(datagram);
                    if datagram.len() > 5 && datagram[0] & 0x80 != 0 {
                        entry.long_header_datagrams.push(datagram.to_vec());
                    }
                }
                let back = match backs.get(&client) {
                    Some(back) => back.clone(),
                    None => {
                        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        let server = *current.lock().unwrap();
                        back.connect(server).await.unwrap();
                        let (from, to) = (back.clone(), front.clone());
                        let (delayed, mut due) = tokio::sync::mpsc::unbounded_channel();
                        let seen = seen.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65_536];
                            while let Ok(n) = from.recv(&mut buf).await {
                                if let Some(entry) = seen
                                    .lock()
                                    .unwrap()
                                    .iter_mut()
                                    .find(|c| c.addr == Some(client))
                                {
                                    entry.server_bytes += n;
                                }
                                let at = tokio::time::Instant::now() + PATH_DELAY;
                                let _ = delayed.send((at, buf[..n].to_vec()));
                            }
                        });
                        tokio::spawn(async move {
                            while let Some((at, datagram)) = due.recv().await {
                                tokio::time::sleep_until(at).await;
                                let _ = to.send_to(&datagram, client).await;
                            }
                        });
                        backs.insert(client, back.clone());
                        back
                    }
                };
                let _ = back.send(datagram).await;
            }
        });
        Relay {
            addr,
            backend,
            clients,
        }
    }

    pub fn switch_to(&self, server: SocketAddr) {
        *self.backend.lock().unwrap() = server;
    }

    /// What the latest client socket sent.
    pub fn last_client(&self) -> ClientSocket {
        self.clients
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    /// Wait until the last client socket stops receiving bytes from the
    /// server for two consecutive 20 ms polls (at most 2 s) — the server may
    /// still have data in flight after a response completes (a session
    /// ticket, for instance), with no explicit signal for it landing; a
    /// quiet relay is the closest thing to "done".
    pub async fn wait_until_quiet(&self) {
        let mut last = self.last_client().server_bytes;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now = self.last_client().server_bytes;
            if now == last {
                return;
            }
            last = now;
        }
    }
}

fn varint(buf: &[u8], p: &mut usize) -> Option<u64> {
    let first = *buf.get(*p)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(*p..*p + len)?;
    let mut value = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        value = (value << 8) | u64::from(*b);
    }
    *p += len;
    Some(value)
}

/// QUIC version 2 (RFC 9369).
pub const QUIC_V2: u32 = 0x6b33_43cf;

/// Bytes of the 0-RTT packets among the long-header packets of a datagram,
/// of QUIC version 1 or 2 (whose long header types differ, RFC 9369 §3.2).
pub fn zero_rtt_bytes(mut datagram: &[u8]) -> usize {
    let mut count = 0;
    while datagram.len() > 6 && datagram[0] & 0x80 != 0 {
        let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
        let (initial, zero_rtt) = if version == QUIC_V2 { (1, 2) } else { (0, 1) };
        let kind = (datagram[0] >> 4) & 0x03;
        let mut p = 5;
        let Some(dcid) = datagram.get(p).map(|l| usize::from(*l)) else {
            break;
        };
        p += 1 + dcid;
        let Some(scid) = datagram.get(p).map(|l| usize::from(*l)) else {
            break;
        };
        p += 1 + scid;
        if kind == initial {
            let Some(token) = varint(datagram, &mut p) else {
                break;
            };
            p += token as usize;
        }
        let Some(length) = varint(datagram, &mut p) else {
            break;
        };
        p += length as usize;
        if kind == zero_rtt {
            count += p;
        }
        if p >= datagram.len() {
            break;
        }
        datagram = &datagram[p..];
    }
    count
}
