//! Opening `WebSockets` over the transport the profile's browser picks: an HTTP/1.1 upgrade or an
//! extended CONNECT on an HTTP/2 connection (see [`crate::websocket`]).

use http::Uri;

use crate::error::Error;
use crate::pool::{ConnInfo, Mux, PoolKey};
use crate::proxy::ProxyConfig;
use crate::websocket::{self, H2Close, OverH2, WebSocket};

use super::H2Conn;
use super::body::{ExchangeError, MuxFailure};
use super::connection::{AlpnMode, BoxedIo};
use super::headers;

/// A socket that opens, and the response headers of its handshake.
type Opened = (WebSocket, Vec<(String, String)>);

/// A WebSocket to open.
pub(super) struct WsTarget<'a> {
    /// The `ws://` or `wss://` URL.
    pub uri: &'a Uri,
    /// Its `http://` or `https://` equivalent: Origin, cookies and the extended CONNECT's
    /// `:scheme`, `:authority` and `:path`.
    pub http_uri: &'a Uri,
    pub host: &'a str,
    pub port: u16,
    pub secure: bool,
    pub proxy: Option<&'a ProxyConfig>,
    /// The jar's cookies for the origin.
    pub cookie: Option<&'a str>,
    pub extra_headers: &'a [(String, String)],
}

impl WsTarget<'_> {
    /// The pool key of the origin's connections: those of requests, or Firefox's for `WebSockets`.
    fn pool_key(&self, for_websockets: bool) -> PoolKey {
        PoolKey {
            secure: self.secure,
            host: self.host.to_string(),
            port: self.port,
            proxy: self.proxy.map(|p| p.url.to_string()),
            for_websockets,
        }
    }
}

/// Whether an extended CONNECT failed before the server saw it, so that the socket may be opened
/// another way.
fn not_sent(failure: &MuxFailure) -> bool {
    matches!(failure.error, ExchangeError::NotSent(_))
}

impl super::Client {
    /// Open `target` as the profile's browser would (see [`crate::websocket`]).
    pub(super) async fn websocket_handshake(&self, target: &WsTarget<'_>) -> Result<Opened, Error> {
        let policy = websocket::policy(&self.profile);
        if target.secure {
            match policy.over_h2 {
                OverH2::ExistingConnection => {
                    if let Some(opened) = self.chromium_websocket_h2(target, policy.close).await? {
                        return Ok(opened);
                    }
                }
                OverH2::OwnConnections => {
                    return self.firefox_websocket(target, policy.close).await;
                }
                OverH2::Never => {}
            }
        }
        self.websocket_h1(target, AlpnMode::Http11Only).await
    }

    /// Chromium: an extended CONNECT on the HTTP/2 connection the client has to the origin, if its
    /// server enabled it (`SpdySessionPool::FindAvailableSession` with `support_websocket()`).
    /// `None` when there is none, or it was gone before the request left.
    async fn chromium_websocket_h2(
        &self,
        target: &WsTarget<'_>,
        close: H2Close,
    ) -> Result<Option<Opened>, Error> {
        let key = target.pool_key(false);
        let Some(pooled) = self.pool.get_mux(&key) else {
            return Ok(None);
        };
        let Mux::H2(conn) = pooled.mux else {
            return Ok(None);
        };
        if !conn.extended_connect() {
            return Ok(None);
        }
        match self.websocket_h2(conn, target, close).await {
            Ok(opened) => Ok(Some(opened)),
            Err(failure) => {
                if failure.connection_failed {
                    self.pool.remove_mux(&key, pooled.id);
                }
                if not_sent(&failure) {
                    Ok(None)
                } else {
                    Err(failure.error.into_error())
                }
            }
        }
    }

    /// Firefox: the HTTP/2 connection of the origin's `WebSockets`, opened with the profile's ALPN
    /// if there is none. Once its server's SETTINGS arrived, the socket goes over it if they enable
    /// extended CONNECT, else over a new connection that offers only http/1.1
    /// (`nsHttpConnectionMgr::TryDispatchExtendedCONNECTransaction`). A new connection that
    /// negotiates http/1.1 carries the upgrade itself.
    async fn firefox_websocket(
        &self,
        target: &WsTarget<'_>,
        close: H2Close,
    ) -> Result<Opened, Error> {
        let key = target.pool_key(true);
        // A pooled connection that turns out dead is dropped, and a new one opened once.
        for _ in 0..2 {
            let gate = self.pool.connect_gate(&key).await;
            let (mut conn, id) = match self.pool.get_mux(&key) {
                Some(pooled) => {
                    if let Mux::H2(conn) = pooled.mux {
                        (conn, Some(pooled.id))
                    } else {
                        break;
                    }
                }
                None => {
                    let (tls, peer_addr) = self
                        .connect_tls(target.host, target.port, target.proxy, AlpnMode::Profile)
                        .await?;
                    if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
                        drop(gate);
                        return self.websocket_upgrade(Box::new(tls), target).await;
                    }
                    let info = ConnInfo {
                        peer_addr,
                        tls_resumed: tls.ssl().session_reused(),
                        ..ConnInfo::default()
                    };
                    let conn = self.h2_handshake(tls).await?;
                    let id = self.pool.put_mux(key.clone(), Mux::H2(conn.clone()), info);
                    (conn, id)
                }
            };
            drop(gate);

            let remove = |id: Option<u64>| {
                if let Some(id) = id {
                    self.pool.remove_mux(&key, id);
                }
            };
            if conn.remote_settings().await.is_err() {
                remove(id);
                continue;
            }
            if !conn.extended_connect() {
                break;
            }
            match self.websocket_h2(conn, target, close).await {
                Ok(opened) => return Ok(opened),
                Err(failure) => {
                    if failure.connection_failed {
                        remove(id);
                    }
                    if !not_sent(&failure) {
                        return Err(failure.error.into_error());
                    }
                }
            }
        }
        self.websocket_h1(target, AlpnMode::Http11Only).await
    }

    /// The upgrade on a new connection: TLS with `alpn` for `wss://`.
    async fn websocket_h1(&self, target: &WsTarget<'_>, alpn: AlpnMode) -> Result<Opened, Error> {
        let conn: BoxedIo = if target.secure {
            let (tls, _) = self
                .connect_tls(target.host, target.port, target.proxy, alpn)
                .await?;
            Box::new(tls)
        } else {
            self.open_stream(target.host, target.port, target.proxy, true)
                .await?
                .io
        };
        self.websocket_upgrade(conn, target).await
    }

    /// The HTTP/1.1 upgrade on `conn`.
    async fn websocket_upgrade(
        &self,
        conn: BoxedIo,
        target: &WsTarget<'_>,
    ) -> Result<Opened, Error> {
        let key = tungstenite::handshake::client::generate_key();
        let mut headers = headers::build_websocket(
            &self.profile,
            target.uri,
            target.http_uri,
            &key,
            target.cookie,
            &self.custom_headers,
            target.extra_headers,
        );
        self.farble_websocket_accept_language(&mut headers, target);
        websocket::connect(conn, target.uri, headers, &key).await
    }

    /// Brave's Accept-Language farbling on a WebSocket handshake (captured there too), for the site
    /// of the page the socket belongs to: its Origin, else the socket's own URL.
    fn farble_websocket_accept_language(
        &self,
        headers: &mut [(String, String)],
        target: &WsTarget<'_>,
    ) {
        if !self.profile.farble_accept_language {
            return;
        }
        let caller_sets = |name: &str| {
            headers::header_value(&self.custom_headers, name).is_some()
                || headers::header_value(target.extra_headers, name).is_some()
        };
        if caller_sets("accept-language") {
            return;
        }
        let origin =
            headers::header_value(headers, "origin").and_then(|o| o.parse::<http::Uri>().ok());
        let site = origin.as_ref().unwrap_or(target.http_uri);
        headers::farble_accept_language(headers, &self.client_hints, site);
    }

    /// The extended CONNECT on `conn`.
    async fn websocket_h2(
        &self,
        conn: H2Conn,
        target: &WsTarget<'_>,
        close: H2Close,
    ) -> Result<Opened, MuxFailure> {
        let mut headers = headers::build_websocket_h2(
            &self.profile,
            target.uri,
            target.http_uri,
            target.cookie,
            &self.custom_headers,
            target.extra_headers,
        );
        self.farble_websocket_accept_language(&mut headers, target);
        let (response, send, recv) = self
            .open_h2_websocket(conn, target.http_uri, &headers)
            .await?;
        websocket::connect_h2(response, send, recv, &headers, close)
            .await
            .map_err(|error| MuxFailure {
                error: ExchangeError::Sent(error),
                connection_failed: false,
            })
    }
}
