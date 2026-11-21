use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::AbortHandle;

use crate::error::Error;
use crate::proxy::ProxyConfig;

const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_AUTH_NONE: u8 = 0;
const SOCKS5_AUTH_USERPASS: u8 = 2;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 3;
const SOCKS5_ATYP_V4: u8 = 1;
const SOCKS5_ATYP_DOMAIN: u8 = 3;
const SOCKS5_ATYP_V6: u8 = 4;
const STACK_SEND_BUF: usize = 2048;
const MAX_UDP_PACKET: usize = 65_535 + 22;

#[derive(Debug)]
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An RFC 1928 §7 SOCKS5 `UDP ASSOCIATE` socket implementing [`quinn::AsyncUdpSocket`].
///
/// Holds the SOCKS5 TCP control connection alive in a background watcher task; dropping this
/// socket aborts the watcher and closes the TCP control stream, terminating the association at
/// the proxy.
pub(crate) struct Socks5UdpSocket {
    udp: UdpSocket,
    relay_addr: SocketAddr,
    local_addr: SocketAddr,
    control_closed: Arc<AtomicBool>,
    recv_waker: Arc<Mutex<Option<Waker>>>,
    recv_buf: Mutex<Box<[u8]>>,
    _control_watcher: AbortOnDrop,
}

impl std::fmt::Debug for Socks5UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UdpSocket")
            .field("local_addr", &self.local_addr)
            .field("relay_addr", &self.relay_addr)
            .field(
                "control_closed",
                &self.control_closed.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Socks5UdpSocket {
    /// Complete an RFC 1928 SOCKS5 `UDP ASSOCIATE` handshake over `tcp` and bind the local UDP
    /// socket used to exchange framed datagrams with the proxy's relay endpoint.
    pub(crate) async fn associate(
        tcp: TcpStream,
        proxy: &ProxyConfig,
        local_address: Option<IpAddr>,
    ) -> Result<Self, Error> {
        tokio::time::timeout(
            ASSOCIATE_TIMEOUT,
            Self::associate_inner(tcp, proxy, local_address),
        )
        .await
        .map_err(|_| Error::Proxy("SOCKS5 UDP ASSOCIATE timed out".into(), None))?
    }

    async fn associate_inner(
        mut tcp: TcpStream,
        proxy: &ProxyConfig,
        local_address: Option<IpAddr>,
    ) -> Result<Self, Error> {
        let proxy_peer = tcp.peer_addr().map_err(|e| {
            Error::Proxy(
                format!("SOCKS5 proxy peer address unavailable: {e}"),
                crate::error::boxed(e),
            )
        })?;
        let proxy_io = |what: &'static str| {
            move |e: io::Error| {
                Error::Proxy(format!("SOCKS5 UDP {what}: {e}"), crate::error::boxed(e))
            }
        };

        // 1. Method negotiation (RFC 1928 §3 + RFC 1929 user/pass).
        match &proxy.auth {
            Some(auth) => {
                tcp.write_all(&[SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS])
                    .await
                    .map_err(proxy_io("greeting write"))?;
                let mut resp = [0u8; 2];
                tcp.read_exact(&mut resp)
                    .await
                    .map_err(proxy_io("greeting read"))?;
                if resp[0] != SOCKS5_VERSION {
                    return Err(Error::Proxy(
                        format!("SOCKS5 invalid version {} in greeting", resp[0]),
                        None,
                    ));
                }
                match resp[1] {
                    SOCKS5_AUTH_NONE => {}
                    SOCKS5_AUTH_USERPASS => {
                        let user = auth.username.as_bytes();
                        let pass = auth.password.as_bytes();
                        let ulen = u8::try_from(user.len()).map_err(|_| {
                            Error::Proxy("SOCKS5 username exceeds 255 bytes".into(), None)
                        })?;
                        let plen = u8::try_from(pass.len()).map_err(|_| {
                            Error::Proxy("SOCKS5 password exceeds 255 bytes".into(), None)
                        })?;
                        let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
                        msg.push(1);
                        msg.push(ulen);
                        msg.extend_from_slice(user);
                        msg.push(plen);
                        msg.extend_from_slice(pass);
                        tcp.write_all(&msg).await.map_err(proxy_io("auth write"))?;
                        let mut auth_resp = [0u8; 2];
                        tcp.read_exact(&mut auth_resp)
                            .await
                            .map_err(proxy_io("auth read"))?;
                        if auth_resp != [1, 0] {
                            return Err(Error::Proxy(
                                format!("SOCKS5 authentication failed (status {})", auth_resp[1]),
                                None,
                            ));
                        }
                    }
                    method => {
                        return Err(Error::Proxy(
                            format!("SOCKS5 proxy rejected auth methods (0x{method:02x})"),
                            None,
                        ));
                    }
                }
            }
            None => {
                tcp.write_all(&[SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE])
                    .await
                    .map_err(proxy_io("greeting write"))?;
                let mut resp = [0u8; 2];
                tcp.read_exact(&mut resp)
                    .await
                    .map_err(proxy_io("greeting read"))?;
                if resp != [SOCKS5_VERSION, SOCKS5_AUTH_NONE] {
                    return Err(Error::Proxy(
                        format!(
                            "SOCKS5 proxy rejected no-auth (ver={}, method=0x{:02x})",
                            resp[0], resp[1]
                        ),
                        None,
                    ));
                }
            }
        }

        // 2. UDP ASSOCIATE request (RFC 1928 §4, DST.ADDR = 0, DST.PORT = 0).
        if proxy_peer.is_ipv6() {
            let mut req = [0u8; 22];
            req[0] = SOCKS5_VERSION;
            req[1] = SOCKS5_CMD_UDP_ASSOCIATE;
            req[3] = SOCKS5_ATYP_V6;
            tcp.write_all(&req)
                .await
                .map_err(proxy_io("associate write"))?;
        } else {
            tcp.write_all(&[
                SOCKS5_VERSION,
                SOCKS5_CMD_UDP_ASSOCIATE,
                0,
                SOCKS5_ATYP_V4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .map_err(proxy_io("associate write"))?;
        }

        // 3. Parse UDP ASSOCIATE reply.
        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr)
            .await
            .map_err(proxy_io("associate reply header"))?;
        if hdr[0] != SOCKS5_VERSION {
            return Err(Error::Proxy(
                format!("SOCKS5 invalid version {} in UDP ASSOCIATE reply", hdr[0]),
                None,
            ));
        }
        if hdr[1] != 0 {
            return Err(Error::Proxy(
                format!("SOCKS5 UDP ASSOCIATE failed (reply code {})", hdr[1]),
                None,
            ));
        }

        let raw_relay = match hdr[3] {
            SOCKS5_ATYP_V4 => {
                let mut body = [0u8; 6];
                tcp.read_exact(&mut body)
                    .await
                    .map_err(proxy_io("associate IPv4 reply"))?;
                let ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
                let port = u16::from_be_bytes([body[4], body[5]]);
                SocketAddr::from((ip, port))
            }
            SOCKS5_ATYP_V6 => {
                let mut body = [0u8; 18];
                tcp.read_exact(&mut body)
                    .await
                    .map_err(proxy_io("associate IPv6 reply"))?;
                let octets: [u8; 16] = body[..16]
                    .try_into()
                    .expect("16-byte slice fits IPv6 octets");
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([body[16], body[17]]);
                SocketAddr::from((ip, port))
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                tcp.read_exact(&mut len_buf)
                    .await
                    .map_err(proxy_io("associate domain length"))?;
                let dlen = usize::from(len_buf[0]);
                let mut body = vec![0u8; dlen + 2];
                tcp.read_exact(&mut body)
                    .await
                    .map_err(proxy_io("associate domain body"))?;
                let host = std::str::from_utf8(&body[..dlen]).map_err(|_| {
                    Error::Proxy("SOCKS5 UDP ASSOCIATE returned non-UTF8 domain".into(), None)
                })?;
                let port = u16::from_be_bytes([body[dlen], body[dlen + 1]]);
                let want_v4 = proxy_peer.is_ipv4();
                let mut resolved = tokio::net::lookup_host((host, port))
                    .await
                    .map_err(proxy_io("relay DNS"))?;
                let mut fallback = None;
                let mut matched = None;
                for candidate in &mut resolved {
                    if candidate.is_ipv4() == want_v4 {
                        matched = Some(candidate);
                        break;
                    }
                    if fallback.is_none() {
                        fallback = Some(candidate);
                    }
                }
                matched.or(fallback).ok_or_else(|| {
                    Error::Proxy(
                        format!("SOCKS5 UDP relay domain {host} resolved to no address"),
                        None,
                    )
                })?
            }
            atyp => {
                return Err(Error::Proxy(
                    format!("SOCKS5 UDP ASSOCIATE unknown address type {atyp}"),
                    None,
                ));
            }
        };

        if raw_relay.port() == 0 {
            return Err(Error::Proxy(
                "SOCKS5 UDP ASSOCIATE returned port 0".into(),
                None,
            ));
        }
        let relay_addr = if raw_relay.ip().is_unspecified() {
            SocketAddr::new(proxy_peer.ip(), raw_relay.port())
        } else {
            raw_relay
        };

        // 4. Bind the local UDP socket in the same family as the relay.
        let bind_addr = if relay_addr.ip().is_loopback() {
            if relay_addr.is_ipv6() {
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
            } else {
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
            }
        } else if let Some(local) = local_address.filter(|ip| ip.is_ipv4() == relay_addr.is_ipv4())
        {
            SocketAddr::new(local, 0)
        } else if relay_addr.is_ipv6() {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };

        let udp = UdpSocket::bind(bind_addr).await.map_err(|e| {
            Error::Quic(
                format!("Failed to bind SOCKS5 UDP socket on {bind_addr}: {e}"),
                crate::error::boxed(e),
            )
        })?;
        // Prime Tokio's epoll write-readiness so Quinn's first try_send succeeds immediately.
        let _ = udp.writable().await;
        let local_addr = udp.local_addr().map_err(|e| {
            Error::Quic(
                format!("Failed to read SOCKS5 UDP local address: {e}"),
                crate::error::boxed(e),
            )
        })?;

        // 5. Hold the TCP control connection open and wake Quinn immediately if it closes.
        let control_closed = Arc::new(AtomicBool::new(false));
        let recv_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let closed_flag = control_closed.clone();
        let waker_slot = recv_waker.clone();
        let watcher = tokio::spawn(async move {
            let mut drain = [0u8; 16];
            loop {
                match tcp.read(&mut drain).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            closed_flag.store(true, Ordering::Release);
            if let Some(waker) = crate::util::lock_recover(&waker_slot).take() {
                waker.wake();
            }
        });

        Ok(Self {
            udp,
            relay_addr,
            local_addr,
            control_closed,
            recv_waker,
            recv_buf: Mutex::new(vec![0u8; MAX_UDP_PACKET].into_boxed_slice()),
            _control_watcher: AbortOnDrop(watcher.abort_handle()),
        })
    }

    pub(crate) const fn local_socket_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn send_one(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let canonical = SocketAddr::new(dst.ip().to_canonical(), dst.port());
        let hdr_len = match canonical {
            SocketAddr::V4(_) => 10,
            SocketAddr::V6(_) => 22,
        };
        let total = hdr_len + payload.len();
        if total <= STACK_SEND_BUF {
            let mut buf = [0u8; STACK_SEND_BUF];
            encode_udp_header(canonical, &mut buf[..hdr_len]);
            buf[hdr_len..total].copy_from_slice(payload);
            self.udp.try_send_to(&buf[..total], self.relay_addr)?;
        } else {
            let mut buf = vec![0u8; total];
            encode_udp_header(canonical, &mut buf[..hdr_len]);
            buf[hdr_len..total].copy_from_slice(payload);
            self.udp.try_send_to(&buf, self.relay_addr)?;
        }
        Ok(())
    }
}

fn encode_udp_header(dst: SocketAddr, out: &mut [u8]) {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    match dst {
        SocketAddr::V4(v4) => {
            out[3] = SOCKS5_ATYP_V4;
            out[4..8].copy_from_slice(&v4.ip().octets());
            out[8..10].copy_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out[3] = SOCKS5_ATYP_V6;
            out[4..20].copy_from_slice(&v6.ip().octets());
            out[20..22].copy_from_slice(&v6.port().to_be_bytes());
        }
    }
}

fn decode_udp_packet(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    match packet[3] {
        SOCKS5_ATYP_V4 => {
            if packet.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((SocketAddr::from((ip, port)), &packet[10..]))
        }
        SOCKS5_ATYP_V6 => {
            if packet.len() < 22 {
                return None;
            }
            let octets: [u8; 16] = packet[4..20].try_into().ok()?;
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            Some((SocketAddr::from((ip, port)), &packet[22..]))
        }
        _ => None,
    }
}

fn control_closed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "SOCKS5 UDP control connection closed",
    )
}

#[derive(Debug)]
struct Socks5UdpPoller {
    socket: Arc<Socks5UdpSocket>,
}

impl UdpPoller for Socks5UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.socket.control_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(control_closed_error()));
        }
        self.socket.udp.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5UdpPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.control_closed.load(Ordering::Acquire) {
            return Err(control_closed_error());
        }
        if let Some(seg) = transmit
            .segment_size
            .filter(|&s| s > 0 && s < transmit.contents.len())
        {
            for chunk in transmit.contents.chunks(seg) {
                self.send_one(transmit.destination, chunk)?;
            }
            Ok(())
        } else {
            self.send_one(transmit.destination, transmit.contents)
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.control_closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(control_closed_error()));
        }
        *crate::util::lock_recover(&self.recv_waker) = Some(cx.waker().clone());

        let expected_relay_ip = self.relay_addr.ip().to_canonical();
        loop {
            if self.control_closed.load(Ordering::Acquire) {
                return Poll::Ready(Err(control_closed_error()));
            }
            ready!(self.udp.poll_recv_ready(cx))?;
            let mut scratch = crate::util::lock_recover(&self.recv_buf);
            let (n, from) = match self.udp.try_recv_from(&mut scratch) {
                Ok(pair) => pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if from.ip().to_canonical() != expected_relay_ip {
                continue;
            }
            let Some((mut src_addr, payload)) = decode_udp_packet(&scratch[..n]) else {
                continue;
            };
            if payload.len() > bufs[0].len() {
                continue;
            }
            if self.local_addr.is_ipv6() {
                if let SocketAddr::V4(v4) = src_addr {
                    src_addr = SocketAddr::V6(SocketAddrV6::new(
                        v4.ip().to_ipv6_mapped(),
                        v4.port(),
                        0,
                        0,
                    ));
                }
            }
            bufs[0][..payload.len()].copy_from_slice(payload);
            meta[0] = RecvMeta {
                addr: src_addr,
                len: payload.len(),
                stride: payload.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn encode_and_decode_socks5_udp_v4_and_v6() {
        let v4: SocketAddr = "172.66.0.227:443".parse().unwrap();
        let mut pkt = [0u8; 32];
        encode_udp_header(v4, &mut pkt[..10]);
        pkt[10..14].copy_from_slice(b"quic");
        let (addr, payload) = decode_udp_packet(&pkt[..14]).unwrap();
        assert_eq!(addr, v4);
        assert_eq!(payload, b"quic");

        let v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
        let mut pkt6 = [0u8; 32];
        encode_udp_header(v6, &mut pkt6[..22]);
        pkt6[22..26].copy_from_slice(b"h3v6");
        let (addr6, payload6) = decode_udp_packet(&pkt6[..26]).unwrap();
        assert_eq!(addr6, v6);
        assert_eq!(payload6, b"h3v6");

        // Fragmented packets (FRAG != 0) must be dropped.
        pkt[2] = 1;
        assert!(decode_udp_packet(&pkt[..14]).is_none());
    }

    #[tokio::test]
    async fn associate_roundtrips_datagrams_and_detects_control_close() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_tcp.local_addr().unwrap();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut ctl, _) = proxy_tcp.accept().await.unwrap();
            let mut hdr = [0u8; 2];
            ctl.read_exact(&mut hdr).await.unwrap();
            let mut methods = vec![0u8; usize::from(hdr[1])];
            ctl.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&SOCKS5_AUTH_USERPASS));
            ctl.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_USERPASS])
                .await
                .unwrap();

            let mut uver = [0u8; 2];
            ctl.read_exact(&mut uver).await.unwrap();
            let mut user = vec![0u8; usize::from(uver[1])];
            ctl.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            ctl.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; usize::from(plen[0])];
            ctl.read_exact(&mut pass).await.unwrap();
            assert_eq!(user, b"alice");
            assert_eq!(pass, b"secret");
            ctl.write_all(&[1, 0]).await.unwrap();

            let mut req = [0u8; 10];
            ctl.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0, 1]);

            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let SocketAddr::V4(v4) = relay_addr else {
                unreachable!()
            };
            let mut reply = [0u8; 10];
            reply[0] = SOCKS5_VERSION;
            reply[3] = SOCKS5_ATYP_V4;
            reply[4..8].copy_from_slice(&v4.ip().octets());
            reply[8..10].copy_from_slice(&v4.port().to_be_bytes());
            ctl.write_all(&reply).await.unwrap();

            let mut buf = [0u8; 2048];
            let (n, client_udp) = relay.recv_from(&mut buf).await.unwrap();
            let (dest, payload) = decode_udp_packet(&buf[..n]).unwrap();
            let out = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            out.send_to(payload, dest).await.unwrap();
            let (rn, rsrc) = out.recv_from(&mut buf).await.unwrap();
            let mut wrapped = vec![0u8; 10 + rn];
            encode_udp_header(rsrc, &mut wrapped[..10]);
            wrapped[10..].copy_from_slice(&buf[..rn]);
            relay.send_to(&wrapped, client_udp).await.unwrap();

            let _ = close_rx.await;
            drop(ctl);
        });

        let proxy = ProxyConfig::parse(&format!("socks5h://alice:secret@{proxy_addr}")).unwrap();
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let sock = Arc::new(Socks5UdpSocket::associate(tcp, &proxy, None).await.unwrap());

        let quic_initial = vec![0xC3u8; 1250];
        let transmit = Transmit {
            destination: echo_addr,
            ecn: None,
            contents: &quic_initial,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = sock.clone().create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
        sock.try_send(&transmit).unwrap();

        let mut recv_storage = vec![0u8; 2048];
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut recv_storage)];
            sock.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(meta[0].addr, echo_addr);
        assert_eq!(meta[0].len, quic_initial.len());
        assert_eq!(&recv_storage[..meta[0].len], quic_initial.as_slice());

        // Closing the proxy's TCP control connection must wake and fail poll_recv immediately.
        let _ = close_tx.send(());
        let err = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut recv_storage)];
                sock.poll_recv(cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
