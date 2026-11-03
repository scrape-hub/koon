use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use h3::error::{Code, StreamError};
use h3::fingerprint::ConnectionClose;
use h3_quinn::quinn;
use http::{Method, Request, Uri, Version};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::Error;
use crate::http2::config::PseudoHeader;
use crate::pool::{ConnInfo, H3Sender, Mux, PoolKey};
use crate::quic::transport::QuicSetup;

use super::body::{
    BodyStream, ExchangeError, Http3Body, MuxFailure, ResponseParts, Upload, UploadOr, with_upload,
};
use super::h2::{header_map, response_headers, with_pseudo_headers};
use super::request_body::{Body, ByteStream, LengthCheck, already_sent, stream_error};
use super::response::estimate_headers_size;

const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const SHUTDOWN_WAIT: Duration = Duration::from_millis(300);

const SHUTDOWN_YIELDS: u32 = 64;

const SETTINGS_WAIT: Duration = Duration::from_millis(1);

pub(super) struct NewH3 {
    pub conn: H3Conn,
    pub info: ConnInfo,
    pub id: Option<u64>,
}

fn h3_connection_failed(e: &StreamError) -> bool {
    !matches!(
        e,
        StreamError::StreamError { .. }
            | StreamError::RemoteTerminate { .. }
            | StreamError::HeaderTooBig { .. }
    )
}

fn stream_failed(what: &str, e: StreamError) -> MuxFailure {
    let connection_failed = h3_connection_failed(&e);
    let rejected = matches!(&e, StreamError::RemoteTerminate { code, .. } if *code == Code::H3_REQUEST_REJECTED);
    let message = format!("{what}: {e}");
    let error = Error::Http3(message, crate::error::boxed(e));
    MuxFailure {
        connection_failed,
        error: if rejected {
            ExchangeError::NotSent(error)
        } else {
            ExchangeError::Sent(error)
        },
    }
}

fn may_send_early(method: &Method, body: &Body) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) && !body.is_stream()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Early {
    Pending,
    Done { accepted: bool },
    Failed,
}

#[derive(Clone)]
pub(crate) struct H3Conn(Arc<H3Shared>);

struct H3Shared {
    sender: Mutex<H3Sender>,
    early: watch::Receiver<Early>,
    connection: quinn::Connection,
    setup: Arc<QuicSetup>,
    host: String,
    port: u16,
    settings_remembered: AtomicBool,
    open_requests: AtomicUsize,
}

impl Drop for H3Shared {
    fn drop(&mut self) {
        let confirmed = matches!(*self.early.borrow(), Early::Done { .. });
        self.setup.remember_rtt(
            &self.host,
            self.port,
            confirmed.then(|| self.connection.rtt()),
        );
        if self.setup.http3().close_on_drop == ConnectionClose::IdleTimeout
            && self.connection.close_reason().is_none()
        {
            self.connection.abandon();
        }
    }
}

impl H3Conn {
    fn new(
        sender: H3Sender,
        early: watch::Receiver<Early>,
        connection: quinn::Connection,
        setup: Arc<QuicSetup>,
        target: &Target<'_>,
    ) -> Self {
        Self(Arc::new(H3Shared {
            sender: Mutex::new(sender),
            early,
            connection,
            setup,
            host: target.host.to_string(),
            port: target.port,
            settings_remembered: AtomicBool::new(false),
            open_requests: AtomicUsize::new(0),
        }))
    }

    fn current(&self) -> H3Sender {
        crate::util::lock_recover(&self.0.sender).clone()
    }

    async fn sender(&self, early_ok: bool) -> Result<(H3Sender, bool), Error> {
        if let Some(reason) = self.0.connection.close_reason() {
            let message = format!("QUIC connection closed: {reason}");
            return Err(Error::Quic(message, crate::error::boxed(reason)));
        }
        let mut early = self.0.early.clone();
        if *early.borrow() == Early::Pending {
            if early_ok {
                return Ok((self.current(), true));
            }
            let _ = early.wait_for(|s| *s != Early::Pending).await;
        }
        let state = *early.borrow();
        match state {
            Early::Done { .. } => Ok((self.current(), false)),
            Early::Pending | Early::Failed => {
                Err(Error::Quic("QUIC handshake failed".into(), None))
            }
        }
    }

    async fn resend_after_rejection(&self) -> Option<H3Sender> {
        let mut early = self.0.early.clone();
        let _ = early.wait_for(|s| *s != Early::Pending).await;
        let state = *early.borrow();
        (state == Early::Done { accepted: false }).then(|| self.current())
    }

    pub(crate) fn accept_ch(&self) -> Option<Arc<[(String, String)]>> {
        if *self.0.early.borrow() == Early::Pending {
            return None;
        }
        let data = self
            .0
            .connection
            .handshake_data()?
            .downcast::<quinn_btls::HandshakeData>()
            .ok()?;
        let alps = data.peer_application_settings.as_deref()?;
        Some(super::client_hints::alps_accept_ch(alps, true).into())
    }

    fn resumed(&self) -> bool {
        self.0
            .connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn_btls::HandshakeData>().ok())
            .is_some_and(|data| data.session_reused)
    }

    fn remember_peer_settings(&self) {
        if self.0.settings_remembered.load(Ordering::Relaxed) {
            return;
        }
        if let Some(settings) = self.current().peer_settings() {
            self.0.setup.remember_peer_settings(&self.0.host, settings);
            self.0.settings_remembered.store(true, Ordering::Relaxed);
        }
    }

    fn pseudo_header_order(&self) -> &[PseudoHeader] {
        self.0.setup.pseudo_header_order()
    }

    fn fields_on_the_wire(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        if !self.0.setup.splits_cookies() {
            return headers.to_vec();
        }
        let mut fields = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            if name != "cookie" {
                fields.push((name.clone(), value.clone()));
                continue;
            }
            for (i, crumb) in value.split(';').enumerate() {
                let crumb = if i > 0 {
                    crumb.strip_prefix(' ').unwrap_or(crumb)
                } else {
                    crumb
                };
                fields.push(("cookie".to_string(), crumb.to_string()));
            }
        }
        fields
    }
}

pub(crate) struct H3Lease(H3Conn);

impl H3Lease {
    fn new(conn: &H3Conn) -> Self {
        conn.0.open_requests.fetch_add(1, Ordering::SeqCst);
        Self(conn.clone())
    }
}

impl Drop for H3Lease {
    fn drop(&mut self) {
        self.0.0.open_requests.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
pub(crate) struct H3Connections(Mutex<Vec<Weak<H3Shared>>>);

impl H3Connections {
    fn add(&self, conn: &H3Conn) {
        let mut live = crate::util::lock_recover(&self.0);
        live.retain(|conn| conn.strong_count() > 0);
        live.push(Arc::downgrade(&conn.0));
    }

    pub(crate) fn close_all(&self, close: &ConnectionClose) {
        crate::util::lock_recover(&self.0).retain(|conn| {
            let Some(conn) = conn.upgrade() else {
                return false;
            };
            if conn.connection.close_reason().is_some() {
                return false;
            }
            if conn.open_requests.load(Ordering::SeqCst) > 0 {
                return true;
            }
            close_quic(&conn.connection, close);
            false
        });
    }

    fn close_all_now(&self, close: &ConnectionClose) -> Vec<(quinn::Connection, u64)> {
        let live = std::mem::take(&mut *crate::util::lock_recover(&self.0));
        let mut closing = Vec::new();
        for conn in live.iter().filter_map(Weak::upgrade) {
            let connection = conn.connection.clone();
            if connection.close_reason().is_some() || *close == ConnectionClose::IdleTimeout {
                continue;
            }
            let hold = connection.hold_transmit();
            let sent = connection.stats().udp_tx.datagrams;
            close_quic(&connection, close);
            drop(hold);
            closing.push((connection, sent));
        }
        closing
    }
}

fn close_quic(connection: &quinn::Connection, close: &ConnectionClose) {
    let varint = |v: u64| quinn::VarInt::from_u64(v).unwrap_or(quinn::VarInt::MAX);
    match close {
        ConnectionClose::IdleTimeout => {}
        ConnectionClose::Application { code, reason } => {
            connection.close(varint(u64::from(*code)), reason.as_bytes());
        }
        ConnectionClose::Transport {
            code,
            frame_type,
            reason,
        } => match transport_error_code(*code) {
            Some(code) => {
                connection.close_transport(code, frame_type.map(varint), reason.as_bytes())
            }
            None => connection.close(varint(u64::from(Code::H3_NO_ERROR)), reason.as_bytes()),
        },
        _ => {}
    }
}

fn transport_error_code(code: u64) -> Option<quinn::TransportErrorCode> {
    quinn::VarInt::from_u64(code)
        .ok()
        .map(quinn::TransportErrorCode::from)
}

impl super::Client {
    pub(super) fn close_h3(&self) {
        if let Some(setup) = self.quic_setup.get() {
            self.h3_connections
                .close_all(&setup.http3().close_on_shutdown);
        }
    }

    pub(super) fn shutdown_h3(&self) -> impl Future<Output = ()> + use<> {
        let closing = match self.quic_setup.get() {
            Some(setup) => self
                .h3_connections
                .close_all_now(&setup.http3().close_on_shutdown),
            None => Vec::new(),
        };
        async move {
            let deadline = tokio::time::Instant::now() + SHUTDOWN_WAIT;
            let mut yields = 0;
            for (connection, sent) in closing {
                while connection.stats().udp_tx.datagrams <= sent {
                    if tokio::time::Instant::now() >= deadline {
                        return;
                    }
                    if yields < SHUTDOWN_YIELDS {
                        yields += 1;
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
        }
    }

    fn quic_setup(&self) -> Result<Arc<QuicSetup>, Error> {
        if let Some(setup) = self.quic_setup.get() {
            return Ok(setup.clone());
        }
        let quic = self
            .profile
            .quic
            .as_ref()
            .ok_or_else(|| Error::Quic("no QUIC config in profile".into(), None))?;
        let setup = Arc::new(QuicSetup::new(
            quic,
            &self.profile.tls,
            self.session_cache.is_some(),
        )?);
        let _ = self.quic_setup.set(setup);
        Ok(self
            .quic_setup
            .get()
            .expect("QUIC setup was just set")
            .clone())
    }

    pub(super) async fn start_h3(
        &self,
        key: &PoolKey,
        h3_port: u16,
    ) -> JoinHandle<Result<NewH3, Error>> {
        let setup = async {
            let setup = self.quic_setup()?;
            let (addrs, ech_config_list) = tokio::join!(self.resolve(&key.host, h3_port), async {
                if self.skips_ech() {
                    None
                } else {
                    self.get_ech_config(&key.host, key.port).await
                }
            });
            let addr = *addrs
                .map_err(|e| {
                    let message = format!("resolving {}: {e}", key.host);
                    Error::Quic(message, crate::error::boxed(e))
                })?
                .first()
                .ok_or_else(|| Error::Quic(format!("no address for {}", key.host), None))?;
            let bind = match self.local_address {
                Some(local) => SocketAddr::new(local, 0),
                None if addr.is_ipv6() => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                None => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            };
            let endpoint = setup.endpoint(bind)?;
            Ok::<_, Error>((setup, endpoint, addr, ech_config_list))
        }
        .await;

        let (pool, alt_svc, key) = (self.pool.clone(), self.alt_svc.clone(), key.clone());
        let connections = self.h3_connections.clone();
        tokio::spawn(async move {
            let broken = {
                let (alt_svc, key) = (alt_svc.clone(), key.clone());
                move || crate::util::lock_recover(&alt_svc).mark_broken(&key.host, key.port)
            };
            let connected = match setup {
                Ok((setup, endpoint, addr, ech_config_list)) => {
                    let target = Target {
                        addr,
                        host: &key.host,
                        port: key.port,
                        alt_used: alt_used(&key.host, h3_port),
                        ech_config_list,
                    };
                    connect_h3(setup, endpoint, target, broken.clone()).await
                }
                Err(e) => Err(e),
            };
            match connected {
                Ok((conn, info)) => {
                    crate::util::lock_recover(&alt_svc).confirm(&key.host, key.port);
                    connections.add(&conn);
                    let id = pool.put_mux(key, Mux::H3(conn.clone()), info.clone());
                    Ok(NewH3 { conn, info, id })
                }
                Err(e) => {
                    broken();
                    Err(e)
                }
            }
        })
    }

    pub(super) async fn send_h3(
        &self,
        conn: H3Conn,
        ctx: SendContext<'_>,
        body: &Body,
    ) -> Result<ResponseParts, MuxFailure> {
        let SendContext {
            info,
            reused,
            method,
            uri,
            headers,
        } = ctx;
        let (sender, early) = conn
            .sender(may_send_early(method, body) && conn.0.setup.sends_early_requests())
            .await
            .map_err(|e| MuxFailure {
                error: ExchangeError::NotSent(e),
                connection_failed: true,
            })?;
        let request = Exchange {
            conn: &conn,
            info: &info,
            reused,
            method,
            uri,
            headers: &headers,
            body,
        };
        let mut result = request.run(sender).await;
        if early && result.is_err() {
            if let Some(sender) = conn.resend_after_rejection().await {
                result = request.run(sender).await;
            }
        }
        let mut parts = result?;
        parts.info.tls_resumed = conn.resumed();
        conn.remember_peer_settings();
        Ok(parts)
    }
}

fn alt_used(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

pub(super) struct SendContext<'a> {
    pub info: ConnInfo,
    pub reused: bool,
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: Vec<(String, String)>,
}

struct Exchange<'a> {
    conn: &'a H3Conn,
    info: &'a ConnInfo,
    reused: bool,
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a [(String, String)],
    body: &'a Body,
}

struct SentRequest {
    lease: H3Lease,
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    upload: Option<Upload>,
    request_headers: Vec<(String, String)>,
    bytes_sent: u64,
}

impl Exchange<'_> {
    async fn run(&self, sender: H3Sender) -> Result<ResponseParts, MuxFailure> {
        self.send(sender).await?.read_response(self).await
    }

    async fn send(&self, mut sender: H3Sender) -> Result<SentRequest, MuxFailure> {
        let Exchange {
            conn,
            method,
            uri,
            headers,
            body,
            ..
        } = *self;
        let request_failed = |e: Error| MuxFailure {
            error: ExchangeError::Invalid(e),
            connection_failed: false,
        };
        let lease = H3Lease::new(conn);
        let mut request = Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .version(Version::HTTP_3)
            .body(())
            .map_err(|e| {
                let message = e.to_string();
                request_failed(Error::InvalidHeader(message, crate::error::boxed(e)))
            })?;
        *request.headers_mut() = header_map(headers).map_err(request_failed)?;

        let request_headers = with_pseudo_headers(
            conn.pseudo_header_order(),
            method,
            uri,
            conn.fields_on_the_wire(headers),
        );
        let bytes_sent =
            estimate_headers_size(&request_headers) + body.content_length().unwrap_or(0);

        let bodyless = !body.is_stream() && body.bytes().is_none_or(|bytes| bytes.is_empty());
        let stream = if bodyless {
            sender.send_request_and_finish(request).await
        } else {
            sender.send_request(request).await
        };
        let stream = stream.map_err(|e| {
            let connection_failed = h3_connection_failed(&e);
            let header_too_big = matches!(e, StreamError::HeaderTooBig { .. });
            let message = format!("sending request: {e}");
            let error = Error::Http3(message, crate::error::boxed(e));
            MuxFailure {
                connection_failed,
                error: if header_too_big {
                    ExchangeError::Invalid(error)
                } else {
                    ExchangeError::NotSent(error)
                },
            }
        })?;
        let (send, recv) = stream.split();
        let mut send = H3Send {
            stream: send,
            finished: bodyless,
        };
        let mut upload = None;
        if bodyless {
        } else if body.is_stream() {
            let stream = body.take_stream().ok_or_else(|| MuxFailure {
                error: ExchangeError::Sent(already_sent()),
                connection_failed: false,
            })?;
            upload = Some(Upload::spawn(pipe_h3(send, stream, body.content_length())));
        } else {
            if let Some(bytes) = body.bytes() {
                send.stream
                    .send_data(bytes.clone())
                    .await
                    .map_err(|e| stream_failed("sending body", e))?;
            }
            send.finish()
                .await
                .map_err(|e| stream_failed("finishing request", e))?;
        }

        Ok(SentRequest {
            lease,
            recv,
            upload,
            request_headers,
            bytes_sent,
        })
    }
}

impl SentRequest {
    async fn read_response(self, exchange: &Exchange<'_>) -> Result<ResponseParts, MuxFailure> {
        let Self {
            lease,
            mut recv,
            mut upload,
            request_headers,
            bytes_sent,
        } = self;
        let response = loop {
            let response = with_upload(recv.recv_response(), &mut upload)
                .await
                .map_err(|e| match e {
                    UploadOr::Upload(e) => MuxFailure {
                        error: ExchangeError::Sent(e),
                        connection_failed: false,
                    },
                    UploadOr::Response(e) => stream_failed("receiving response", e),
                })?;
            if !response.status().is_informational() {
                break response;
            }
        };
        let status = response.status().as_u16();
        let resp_headers = response_headers(response.headers());
        let head_bytes = estimate_headers_size(&resp_headers);
        let body = if *exchange.method == Method::HEAD {
            BodyStream::Empty
        } else {
            BodyStream::Http3(Box::new(Http3Body {
                stream: recv,
                _upload: upload,
                _conn: lease,
            }))
        };

        Ok(ResponseParts {
            status,
            headers: resp_headers,
            version: "h3",
            request_headers,
            info: exchange.info.clone(),
            connection_reused: exchange.reused,
            bytes_sent,
            head_bytes,
            body,
        })
    }
}

struct H3Send {
    stream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    finished: bool,
}

impl H3Send {
    async fn finish(&mut self) -> Result<(), StreamError> {
        self.stream.finish().await?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for H3Send {
    fn drop(&mut self) {
        if !self.finished {
            self.stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }
}

async fn pipe_h3(mut send: H3Send, mut body: ByteStream, length: Option<u64>) -> Result<(), Error> {
    let mut check = LengthCheck::new(length);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(stream_error)?;
        if chunk.is_empty() {
            continue;
        }
        check.chunk(chunk.len())?;
        send.stream.send_data(chunk).await.map_err(|e| {
            let message = format!("sending body: {e}");
            Error::Http3(message, crate::error::boxed(e))
        })?;
    }
    check.end()?;
    send.finish().await.map_err(|e| {
        let message = format!("finishing request: {e}");
        Error::Http3(message, crate::error::boxed(e))
    })
}

struct Target<'a> {
    addr: SocketAddr,
    host: &'a str,
    port: u16,
    alt_used: String,
    ech_config_list: Option<Vec<u8>>,
}

type H3Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;

async fn h3_session(
    setup: &QuicSetup,
    quic: h3_quinn::Connection,
    remembered: Option<h3::fingerprint::PeerSettings>,
) -> Result<(H3Driver, H3Sender), Error> {
    let mut builder = h3::client::builder();
    builder.fingerprint(setup.http3().clone());
    if let Some(settings) = remembered {
        builder.zero_rtt_settings(settings);
    }
    builder.build(quic).await.map_err(|e| {
        let message = format!("H3 handshake failed: {e}");
        Error::Http3(message, crate::error::boxed(e))
    })
}

fn drive(mut driver: H3Driver) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    })
}

async fn connect_h3(
    setup: Arc<QuicSetup>,
    endpoint: quinn::Endpoint,
    target: Target<'_>,
    broken: impl FnOnce() + Send + 'static,
) -> Result<(H3Conn, ConnInfo), Error> {
    let connecting = endpoint
        .connect_with(
            setup.client_config(target.host, target.port, target.ech_config_list.as_deref())?,
            target.addr,
            target.host,
        )
        .map_err(|e| {
            let message = format!("QUIC connect error: {e}");
            Error::Quic(message, crate::error::boxed(e))
        })?;
    let info = ConnInfo {
        peer_addr: Some(target.addr.ip().to_string()),
        alt_used: Some(target.alt_used.clone()),
        ..ConnInfo::default()
    };

    match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            let hold = connection.hold_transmit();
            let (quic, zero_rtt) = h3_quinn::Connection::new_0rtt(connection.clone(), accepted);
            let remembered = setup.peer_settings(target.host);
            let (driver, sender) =
                tokio::time::timeout(QUIC_CONNECT_TIMEOUT, h3_session(&setup, quic, remembered))
                    .await
                    .map_err(|_| Error::Quic("QUIC handshake timed out".into(), None))??;
            drop(hold);
            let (state, early) = watch::channel(Early::Pending);
            let conn = H3Conn::new(sender, early, connection.clone(), setup.clone(), &target);
            tokio::spawn(settle_early_data(
                Arc::downgrade(&conn.0),
                connection,
                zero_rtt,
                drive(driver),
                setup,
                state,
                broken,
            ));
            Ok((conn, info))
        }
        Err(connecting) => {
            let connection = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| Error::Quic("QUIC handshake timed out".into(), None))?
                .map_err(|e| {
                    let message = format!("QUIC connection failed: {e}");
                    Error::Quic(message, crate::error::boxed(e))
                })?;
            let quic = h3_quinn::Connection::new(connection.clone());
            let (driver, sender) = h3_session(&setup, quic, None).await?;
            drive(driver);
            server_settings(&sender).await;
            let (_, early) = watch::channel(Early::Done { accepted: false });
            Ok((H3Conn::new(sender, early, connection, setup, &target), info))
        }
    }
}

async fn server_settings(sender: &H3Sender) {
    let deadline = Instant::now() + SETTINGS_WAIT;
    std::future::poll_fn(|cx| match sender.poll_peer_settings(cx) {
        Poll::Ready(_) => Poll::Ready(()),
        Poll::Pending if Instant::now() >= deadline => Poll::Ready(()),
        Poll::Pending => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

async fn settle_early_data(
    conn: Weak<H3Shared>,
    connection: quinn::Connection,
    zero_rtt: h3_quinn::ZeroRtt,
    driver: JoinHandle<()>,
    setup: Arc<QuicSetup>,
    state: watch::Sender<Early>,
    broken: impl FnOnce(),
) {
    let fail = |connection: &quinn::Connection| {
        connection.close(quinn::VarInt::from_u32(0), b"");
        broken();
        let _ = state.send(Early::Failed);
    };
    let accepted = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, zero_rtt.accepted()).await;
    let accepted = match (accepted, connection.close_reason()) {
        (Ok(accepted), None) => accepted,
        (Ok(_), Some(quinn::ConnectionError::LocallyClosed)) => {
            let _ = state.send(Early::Failed);
            return;
        }
        _ => return fail(&connection),
    };
    if !accepted {
        let _ = driver.await;
        let quic = h3_quinn::Connection::new(connection.clone());
        let Ok((driver, sender)) = h3_session(&setup, quic, None).await else {
            return fail(&connection);
        };
        match conn.upgrade() {
            Some(conn) => *crate::util::lock_recover(&conn.sender) = sender,
            None => return,
        }
        drive(driver);
    }
    let _ = state.send(Early::Done { accepted });
}
