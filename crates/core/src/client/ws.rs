use http::Uri;

use crate::error::Error;
use crate::pool::{ConnInfo, Mux, PoolKey};
use crate::proxy::ProxyConfig;
use crate::websocket::{self, H2Close, OverH2, WebSocket};

use super::H2Conn;
use super::body::{ExchangeError, MuxFailure};
use super::connection::{AlpnMode, BoxedIo};
use super::headers;

type Opened = (WebSocket, Vec<(String, String)>);

pub(super) struct WsTarget<'a> {
    pub uri: &'a Uri,
    pub http_uri: &'a Uri,
    pub host: &'a str,
    pub port: u16,
    pub secure: bool,
    pub proxy: Option<&'a ProxyConfig>,
    pub cookie: Option<&'a str>,
    pub extra_headers: &'a [(String, String)],
}

impl WsTarget<'_> {
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

fn not_sent(failure: &MuxFailure) -> bool {
    matches!(failure.error, ExchangeError::NotSent(_))
}

impl super::Client {
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

    async fn firefox_websocket(
        &self,
        target: &WsTarget<'_>,
        close: H2Close,
    ) -> Result<Opened, Error> {
        let key = target.pool_key(true);
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
