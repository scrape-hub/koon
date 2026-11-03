use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http::{Method, Uri};
use tokio::sync::OwnedMutexGuard;
use tokio::time::Instant;

use crate::error::{Error, Phase};
use crate::pool::{ConnInfo, Mux, PoolKey, PooledMux};
use crate::proxy::{ProxyConfig, ProxyKind};
use crate::streaming::StreamingResponse;

use super::RequestOptions;
use super::alt_svc::{is_redirect, resolve_redirect};
use super::body::{ExchangeError, MuxFailure, ResponseParts};
use super::connection::{AlpnMode, BoxedIo, is_idle_and_open, strip_brackets};
use super::h1::SendContext as H1SendContext;
use super::h3::{NewH3, SendContext};
use super::headers::{self, HeaderInput, Protocol, header_value};
use super::request_body::{Body, Length};
use super::response::{HttpResponse, decompress_body};

const MAX_REDIRECT_BODY: usize = 64 * 1024;

const BLOCKING_DECODE: usize = 1024 * 1024;

const QUIC_HEAD_START: Duration = Duration::from_millis(300);

const MAX_UNPROCESSED_RETRIES: usize = 2;

const REQUEST_BODY_HEADERS: &[&str] = &[
    "content-encoding",
    "content-language",
    "content-location",
    "content-type",
    "content-length",
];

fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

fn is_cross_origin(a: &Uri, b: &Uri) -> bool {
    fn origin(u: &Uri) -> (Option<&str>, Option<&str>, u16) {
        let scheme = u.scheme_str();
        let port = u
            .port_u16()
            .unwrap_or(if scheme == Some("https") { 443 } else { 80 });
        (scheme, u.host(), port)
    }
    origin(a) != origin(b)
}

fn strip_sensitive_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "proxy-authorization"
        )
    });
}

fn strip_body_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| !REQUEST_BODY_HEADERS.contains(&name.to_ascii_lowercase().as_str()));
}

pub(crate) fn parse_url(url: &str) -> Result<Uri, Error> {
    let mut parsed = url::Url::parse(url.trim())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(Error::UnsupportedScheme(format!(
            "'{}' in {url}: only http and https",
            parsed.scheme()
        )));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(Error::Url(url::ParseError::EmptyHost));
    }
    parsed.set_fragment(None);
    parsed
        .as_str()
        .parse()
        .map_err(|_| Error::Url(url::ParseError::InvalidDomainCharacter))
}

pub(crate) fn validate_headers(headers: &[(String, String)]) -> Result<(), Error> {
    for (name, value) in headers {
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(Error::InvalidHeader(
                format!("invalid header name: {name:?}"),
                None,
            ));
        }
        if http::HeaderValue::from_bytes(value.as_bytes()).is_err() {
            return Err(Error::InvalidHeader(
                format!("invalid value for header {name}"),
                None,
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) enum HeaderSource {
    Profile,
    Raw(Vec<(String, String)>),
}

fn pool_key(url: &Uri, proxy: Option<&ProxyConfig>) -> Result<PoolKey, ExchangeError> {
    let secure = url.scheme_str() == Some("https");
    let host = strip_brackets(url.host().ok_or(ExchangeError::NotSent(Error::Url(
        url::ParseError::EmptyHost,
    )))?)
    .to_string();
    let port = url.port_u16().unwrap_or(if secure { 443 } else { 80 });
    Ok(PoolKey {
        secure,
        host,
        port,
        proxy: proxy.map(|p| p.url.to_string()),
        for_websockets: false,
    })
}

fn request_target(url: &Uri, absolute: bool) -> String {
    if absolute {
        url.to_string()
    } else {
        url.path_and_query()
            .map_or("/".to_string(), |pq| pq.as_str().to_string())
    }
}

struct Hop {
    method: Method,
    url: Uri,
    body: Body,
    client_headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    source: HeaderSource,
    cross_site_redirect: bool,
    redirected_from: Vec<Uri>,
}

impl Hop {
    fn replay(&self) -> Option<Self> {
        let body = match self.body.length() {
            Length::None => Body::empty(),
            _ => Body::from(self.body.bytes()?.clone()),
        };
        Some(Self {
            method: self.method.clone(),
            url: self.url.clone(),
            body,
            client_headers: self.client_headers.clone(),
            request_headers: self.request_headers.clone(),
            source: self.source.clone(),
            cross_site_redirect: self.cross_site_redirect,
            redirected_from: self.redirected_from.clone(),
        })
    }

    fn redirect(&mut self, status: u16, next: Uri) -> Result<(), Error> {
        if status != 303 && self.body.is_stream() {
            return Err(Error::Body(
                format!("cannot follow a {status} redirect: the request body is a stream"),
                None,
            ));
        }
        if is_cross_origin(&self.url, &next) {
            strip_sensitive_headers(&mut self.client_headers);
            strip_sensitive_headers(&mut self.request_headers);
            if let HeaderSource::Raw(raw) = &mut self.source {
                strip_sensitive_headers(raw);
            }
        }
        let to_get = (status == 303 && self.method != Method::HEAD)
            || (matches!(status, 301 | 302) && self.method == Method::POST);
        if to_get && self.method != Method::GET {
            self.method = Method::GET;
            self.body = Body::empty();
            strip_body_headers(&mut self.client_headers);
            strip_body_headers(&mut self.request_headers);
            if let HeaderSource::Raw(raw) = &mut self.source {
                strip_body_headers(raw);
            }
        }
        let hosts = (self.url.host(), next.host());
        if let (Some(from), Some(to)) = hosts {
            self.cross_site_redirect |= !crate::util::same_site(from, to);
        }
        self.redirected_from
            .push(std::mem::replace(&mut self.url, next));
        Ok(())
    }
}

fn unknown_length(headers: &mut Vec<(String, String)>, protocol: Protocol) {
    let Some(pos) = headers
        .iter()
        .position(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    else {
        return;
    };
    if protocol == Protocol::Http1 {
        let name = if headers[pos].0.starts_with('C') {
            "Transfer-Encoding"
        } else {
            "transfer-encoding"
        };
        headers[pos] = (name.to_string(), "chunked".to_string());
    } else {
        headers.remove(pos);
    }
}

const H1_CONNECTIONS_PER_HOST: usize = 6;

struct Outgoing<'a> {
    hop: &'a Hop,
    context: &'a headers::RequestContext,
    cookie: Option<&'a str>,
    restarted: bool,
    progress: &'a Progress,
}

#[derive(Default)]
struct Progress {
    sending: AtomicBool,
    received: AtomicBool,
}

enum Fresh {
    Mux(Mux, ConnInfo, Option<u64>),
    H1(BoxedIo, ConnInfo),
}

enum HopOutcome {
    Redirect(ResponseParts, Uri),
    Restart(ResponseParts, String),
    Final(ResponseParts, Option<Vec<u8>>),
}

impl super::Client {
    fn effective_timeout(&self, options: &RequestOptions) -> Duration {
        match options.timeout {
            Some(t) if t.is_zero() => super::NO_TIMEOUT,
            Some(t) => t.min(super::NO_TIMEOUT),
            None => self.timeout,
        }
    }

    /// Send a request and buffer the response body. `body` is anything that converts into a
    /// [`Body`]: bytes, a string, a stream, or `None`. `options` override client settings for this
    /// request; the timeout covers connecting, every redirect and reading the body. A failed hop
    /// (never one that already got its response) is retried per
    /// [`max_retries`](super::ClientBuilder::max_retries), any retryable error for an idempotent
    /// method, else only before the request left: with the rotation's next proxy and a fresh
    /// timeout. Fails as [`request`](Self::request) does, also with
    /// [`Error::InvalidHeader`]/[`Error::Proxy`] for an invalid `options`.
    pub async fn send(
        &self,
        method: Method,
        url: &str,
        body: impl Into<Body>,
        options: RequestOptions,
    ) -> Result<HttpResponse, Error> {
        self.send_with_source(method, url, body.into(), options, HeaderSource::Profile)
            .await
    }

    pub(crate) async fn send_with_source(
        &self,
        method: Method,
        url: &str,
        body: Body,
        options: RequestOptions,
        source: HeaderSource,
    ) -> Result<HttpResponse, Error> {
        let (parts, final_url, raw) = self.run(method, url, body, &options, source, true).await?;
        let raw = raw.unwrap_or_default();
        self.track_bytes(0, raw.len() as u64);
        let bytes_received = parts.head_bytes + raw.len() as u64;
        let encoding = header_value(&parts.headers, "content-encoding").map(str::to_string);
        let max = self.max_response_body;
        let body = if raw.len() > BLOCKING_DECODE && encoding.is_some() {
            tokio::task::spawn_blocking(move || decompress_body(raw, encoding.as_deref(), max))
                .await
                .map_err(|e| Error::Io(std::io::Error::other(e)))
                .and_then(|decoded| decoded)
        } else {
            decompress_body(raw, encoding.as_deref(), max)
        }
        .map_err(|e| e.in_phase(Phase::Body))?;
        Ok(HttpResponse {
            status: parts.status,
            headers: parts.headers,
            body,
            version: parts.version.to_string(),
            url: final_url.to_string(),
            bytes_sent: parts.bytes_sent,
            bytes_received,
            tls_resumed: parts.info.tls_resumed,
            connection_reused: parts.connection_reused,
            remote_address: parts.info.peer_addr,
            request_headers: parts.request_headers,
        })
    }

    /// Send a request and return as soon as the response head arrives; the body is read with
    /// [`StreamingResponse::next_chunk`]. Redirects and retries work as for [`send`](Self::send);
    /// the timeout covers everything up to the head, then each body-chunk wait. Fails as
    /// [`send`](Self::send) does, up to the response head.
    pub async fn send_streaming(
        &self,
        method: Method,
        url: &str,
        body: impl Into<Body>,
        options: RequestOptions,
    ) -> Result<StreamingResponse, Error> {
        self.send_streaming_with_source(method, url, body.into(), options, HeaderSource::Profile)
            .await
    }

    pub(crate) async fn send_streaming_with_source(
        &self,
        method: Method,
        url: &str,
        body: Body,
        options: RequestOptions,
        source: HeaderSource,
    ) -> Result<StreamingResponse, Error> {
        let (parts, final_url, _) = self.run(method, url, body, &options, source, false).await?;
        Ok(StreamingResponse::new(
            parts,
            final_url.to_string(),
            self.effective_timeout(&options),
            self.total_bytes_received.clone(),
            self.max_response_body,
        ))
    }

    fn pick_proxy<'a>(&'a self, request_proxy: Option<&'a ProxyConfig>) -> Option<&'a ProxyConfig> {
        request_proxy.or_else(|| self.select_proxy())
    }

    async fn run(
        &self,
        method: Method,
        url: &str,
        body: Body,
        options: &RequestOptions,
        source: HeaderSource,
        collect: bool,
    ) -> Result<(ResponseParts, Uri, Option<Vec<u8>>), Error> {
        let url = parse_url(url)?;
        validate_headers(&options.headers)?;
        let proxy_override = options
            .proxy
            .as_deref()
            .map(ProxyConfig::parse)
            .transpose()?;
        let timeout = self.effective_timeout(options);
        let max_redirects = options.max_redirects.unwrap_or(self.max_redirects);

        let mut hop = Hop {
            method,
            url,
            body,
            client_headers: self.custom_headers.clone(),
            request_headers: options.headers.clone(),
            source,
            cross_site_redirect: false,
            redirected_from: Vec::new(),
        };
        let first = hop.replay();
        let mut proxy = self.pick_proxy(proxy_override.as_ref());
        let mut deadline = Instant::now() + timeout;
        let mut retries_left = self.max_retries;
        let mut redirects: u32 = 0;
        let mut restarted = std::collections::HashSet::new();

        loop {
            let progress = Progress::default();
            let attempt = tokio::time::timeout_at(
                deadline,
                Box::pin(self.attempt_hop(&hop, options, proxy, collect, &restarted, &progress)),
            )
            .await
            .unwrap_or_else(|_| {
                Err(if progress.received.load(Ordering::Relaxed) {
                    ExchangeError::Received(Error::Timeout)
                } else if progress.sending.load(Ordering::Relaxed) {
                    ExchangeError::Sent(Error::Timeout)
                } else {
                    ExchangeError::Sent(Error::Timeout.in_phase(Phase::Connect))
                })
            });

            match attempt {
                Ok(HopOutcome::Final(parts, body)) => return Ok((parts, hop.url, body)),
                Ok(HopOutcome::Restart(parts, origin)) => {
                    restarted.insert(origin);
                    let _ = tokio::time::timeout_at(deadline, self.discard_body(parts)).await;
                    if let Some(first) = first.as_ref().and_then(Hop::replay) {
                        hop = first;
                    }
                }
                Ok(HopOutcome::Redirect(parts, next)) => {
                    redirects += 1;
                    if redirects > max_redirects {
                        return Err(Error::TooManyRedirects);
                    }
                    let status = parts.status;
                    let _ = tokio::time::timeout_at(deadline, self.discard_body(parts)).await;
                    hop.redirect(status, next)?;
                }
                Err(e) => {
                    let retry =
                        retries_left > 0 && e.error().is_retryable() && Self::may_resend(&e, &hop);
                    if !retry {
                        return Err(e.into_phased_error());
                    }
                    retries_left -= 1;
                    proxy = self.pick_proxy(proxy_override.as_ref());
                    deadline = Instant::now() + timeout;
                }
            }
        }
    }

    async fn attempt_hop(
        &self,
        hop: &Hop,
        options: &RequestOptions,
        proxy: Option<&ProxyConfig>,
        collect: bool,
        restarted: &std::collections::HashSet<String>,
        progress: &Progress,
    ) -> Result<HopOutcome, ExchangeError> {
        self.fire_on_request(options, hop.method.as_str(), &hop.url)
            .map_err(ExchangeError::Invalid)?;
        let (client, request) = match &hop.source {
            HeaderSource::Raw(raw) => (&[][..], raw.as_slice()),
            HeaderSource::Profile => (&hop.client_headers[..], &hop.request_headers[..]),
        };
        let context = headers::RequestContext::new(
            headers::Family::of(&self.profile),
            &hop.method,
            &hop.url,
            client,
            request,
            &hop.redirected_from,
            None,
        );
        let cookie_context = self.cookie_jar.is_some().then(|| {
            headers::cookie_context(
                headers::cookie_rules(&self.profile),
                &context,
                &hop.method,
                &hop.url,
                hop.cross_site_redirect,
            )
        });
        let cookie = self
            .cookie_jar
            .as_ref()
            .zip(cookie_context.as_ref())
            .and_then(|(jar, context)| {
                crate::util::lock_recover(jar).cookie_header_for(&hop.url, context)
            });

        let mut parts = self
            .exchange(
                &Outgoing {
                    hop,
                    context: &context,
                    cookie: cookie.as_deref(),
                    restarted: !restarted.is_empty(),
                    progress,
                },
                proxy,
            )
            .await?;
        progress.received.store(true, Ordering::Relaxed);
        self.track_bytes(parts.bytes_sent, parts.head_bytes);
        if let (Some(jar), Some(context)) = (&self.cookie_jar, &cookie_context) {
            crate::util::lock_recover(jar).store_from_response_in(
                &hop.url,
                &parts.headers,
                context,
            );
        }
        self.fire_on_response(options, parts.status, &hop.url, &parts.headers)
            .map_err(ExchangeError::Invalid)?;

        let navigation = matches!(hop.source, HeaderSource::Profile) && context.navigation();
        if navigation {
            if let Some(origin) = self
                .learn_client_hints(&hop.url, &parts, restarted)
                .filter(|_| hop.body.replayable())
            {
                return Ok(HopOutcome::Restart(parts, origin));
            }
        }

        let follow = options.follow_redirects.unwrap_or(self.follow_redirects);
        if follow && is_redirect(parts.status) {
            if let Some(location) = header_value(&parts.headers, "location") {
                let next = resolve_redirect(&hop.url, location).map_err(ExchangeError::Received)?;
                if self
                    .fire_on_redirect(options, parts.status, &next, &parts.headers)
                    .map_err(ExchangeError::Invalid)?
                {
                    return Ok(HopOutcome::Redirect(parts, next));
                }
            }
        }
        let body = if collect {
            let size_hint = parts.content_length();
            Some(
                parts
                    .body
                    .collect(size_hint, self.max_response_body)
                    .await
                    .map_err(ExchangeError::Received)?,
            )
        } else {
            None
        };
        Ok(HopOutcome::Final(parts, body))
    }

    async fn discard_body(&self, mut parts: ResponseParts) {
        let mut read = 0usize;
        while let Ok(Some(chunk)) = parts.body.next().await {
            read += chunk.len();
            self.track_bytes(0, chunk.len() as u64);
            if read > MAX_REDIRECT_BODY {
                return;
            }
        }
    }

    async fn exchange(
        &self,
        out: &Outgoing<'_>,
        proxy: Option<&ProxyConfig>,
    ) -> Result<ResponseParts, ExchangeError> {
        let url = &out.hop.url;
        let key = pool_key(url, proxy)?;
        let parts = self.exchange_on(out, proxy, &key).await?;
        if key.secure && proxy.is_none() && self.follows_alt_svc() {
            self.record_alt_svc(&key.host, key.port, &parts.headers);
        }
        Ok(parts)
    }

    async fn exchange_on(
        &self,
        out: &Outgoing<'_>,
        proxy: Option<&ProxyConfig>,
        key: &PoolKey,
    ) -> Result<ResponseParts, ExchangeError> {
        let url = &out.hop.url;
        if let Some(pooled) = self.pool.get_mux(key) {
            if let Some(parts) = self.send_pooled(out, key, pooled).await? {
                return Ok(parts);
            }
        }
        loop {
            let slot = self.h1_slot(key).await;
            let Some((mut conn, info)) = self.pool.take_h1(key) else {
                break;
            };
            if !is_idle_and_open(&mut conn) {
                continue;
            }
            let proxy_headers = if info.absolute_form {
                proxy.map(|p| self.proxy_request_headers(p))
            } else {
                None
            };
            let headers =
                self.request_headers(out, Protocol::Http1, proxy_headers.as_deref(), &info);
            let target = request_target(url, info.absolute_form);
            match self
                .send_h1(
                    conn,
                    H1SendContext {
                        info,
                        reused: true,
                        pool_key: key.clone(),
                        method: &out.hop.method,
                        target: &target,
                        headers,
                        slot,
                    },
                    &out.hop.body,
                )
                .await
            {
                Ok(parts) => return Ok(parts),
                Err(e @ ExchangeError::NotSent(_)) => Self::retry_decision(e, out.hop)?,
                Err(e) => {
                    Self::retry_decision(e, out.hop)?;
                    break;
                }
            }
        }

        let mut reuse = true;
        loop {
            #[allow(clippy::significant_drop_tightening)]
            let gate = self.pool.connect_gate(key).await;
            if gate.is_some() && reuse {
                if let Some(pooled) = self.pool.get_mux(key) {
                    drop(gate);
                    reuse = false;
                    match self.send_pooled(out, key, pooled).await? {
                        Some(parts) => return Ok(parts),
                        None => continue,
                    }
                }
            }
            return self.exchange_on_new_connection(out, proxy, key, gate).await;
        }
    }

    async fn send_pooled(
        &self,
        out: &Outgoing<'_>,
        key: &PoolKey,
        pooled: PooledMux,
    ) -> Result<Option<ResponseParts>, ExchangeError> {
        match Box::pin(self.send_mux(pooled.mux, pooled.info, true, out)).await {
            Ok(parts) => Ok(Some(parts)),
            Err(failure) => {
                if failure.connection_failed {
                    self.pool.remove_mux(key, pooled.id);
                }
                Self::retry_decision(failure.error, out.hop)?;
                Ok(None)
            }
        }
    }

    async fn send_mux(
        &self,
        mux: Mux,
        info: ConnInfo,
        reused: bool,
        out: &Outgoing<'_>,
    ) -> Result<ResponseParts, MuxFailure> {
        let hop = out.hop;
        match mux {
            Mux::H2(conn) => {
                let headers = self.request_headers(out, Protocol::Http2, None, &info);
                self.send_h2(
                    conn,
                    SendContext {
                        info,
                        reused,
                        method: &hop.method,
                        uri: &hop.url,
                        headers,
                    },
                    &hop.body,
                )
                .await
            }
            Mux::H3(conn) => {
                let mut info = info;
                if info.accept_ch.is_none() {
                    info.accept_ch = conn.accept_ch();
                }
                let headers = self.request_headers(out, Protocol::Http3, None, &info);
                self.send_h3(
                    conn,
                    SendContext {
                        info,
                        reused,
                        method: &hop.method,
                        uri: &hop.url,
                        headers,
                    },
                    &hop.body,
                )
                .await
            }
        }
    }

    async fn h1_slot(&self, key: &PoolKey) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let limit = match headers::Family::of(&self.profile) {
            headers::Family::Chromium | headers::Family::Firefox | headers::Family::Safari => {
                H1_CONNECTIONS_PER_HOST
            }
            _ => return None,
        };
        if self.pool.is_multiplexed(key) {
            return None;
        }
        self.pool.h1_slot(key, limit).await
    }

    fn may_resend(e: &ExchangeError, hop: &Hop) -> bool {
        let resend = match e {
            ExchangeError::NotSent(_) => true,
            ExchangeError::Sent(_) => is_idempotent(&hop.method),
            ExchangeError::Received(_) | ExchangeError::Invalid(_) => false,
        };
        resend && hop.body.replayable()
    }

    fn retry_decision(e: ExchangeError, hop: &Hop) -> Result<(), ExchangeError> {
        if Self::may_resend(&e, hop) {
            Ok(())
        } else {
            Err(e)
        }
    }

    async fn exchange_on_new_connection(
        &self,
        out: &Outgoing<'_>,
        proxy: Option<&ProxyConfig>,
        key: &PoolKey,
        gate: Option<OwnedMutexGuard<()>>,
    ) -> Result<ResponseParts, ExchangeError> {
        let hop = out.hop;
        let direct_secure = key.secure && proxy.is_none();
        let mut h3_port = if direct_secure && self.follows_alt_svc() {
            self.alt_svc_h3_port(&key.host, key.port)
        } else {
            None
        };
        let mut h3_via_https_rr = false;
        if h3_port.is_none()
            && direct_secure
            && self.follows_https_rr()
            && !self.h3_broken(&key.host, key.port)
        {
            let (port, ()) = tokio::join!(
                self.https_rr_h3_port(&key.host, key.port),
                self.prefetch_addresses(&key.host, key.port)
            );
            h3_port = port;
            h3_via_https_rr = h3_port.is_some();
        }
        let direct_quic = h3_via_https_rr && self.quic_stack_is_apple();
        let mut gate = gate;
        let mut retries = 0;
        let mut quic_failed = false;

        let parts = loop {
            let slot = if direct_quic {
                None
            } else {
                self.h1_slot(key).await
            };
            let fresh = match h3_port {
                Some(h3_port) if direct_quic => self.connect_direct_quic(key, h3_port).await,
                Some(h3_port) => Box::pin(self.connect_racing_quic(key, h3_port)).await,
                None => self.connect_tcp(key, proxy).await,
            }
            .map_err(ExchangeError::NotSent)?;
            drop(gate.take());

            let error = match fresh {
                Fresh::Mux(mux, info, id) => {
                    drop(slot);
                    let is_h3 = matches!(mux, Mux::H3(_));
                    match Box::pin(self.send_mux(mux, info, false, out)).await {
                        Ok(parts) => break parts,
                        Err(failure) => {
                            if failure.connection_failed {
                                if let Some(id) = id {
                                    self.pool.remove_mux(key, id);
                                }
                            }
                            if is_h3 {
                                if failure.connection_failed {
                                    self.mark_alt_svc_broken(&key.host, key.port);
                                } else {
                                    quic_failed = true;
                                }
                                Self::retry_decision(failure.error, hop)?;
                                h3_port = None;
                                continue;
                            }
                            failure.error
                        }
                    }
                }
                Fresh::H1(io, info) => {
                    let proxy_headers = if info.absolute_form {
                        proxy.map(|p| self.proxy_request_headers(p))
                    } else {
                        None
                    };
                    let headers =
                        self.request_headers(out, Protocol::Http1, proxy_headers.as_deref(), &info);
                    let target = request_target(&hop.url, info.absolute_form);
                    match self
                        .send_h1(
                            io,
                            H1SendContext {
                                info,
                                reused: false,
                                pool_key: key.clone(),
                                method: &hop.method,
                                target: &target,
                                headers,
                                slot,
                            },
                            &hop.body,
                        )
                        .await
                    {
                        Ok(parts) => break parts,
                        Err(e) => e,
                    }
                }
            };
            if matches!(error, ExchangeError::NotSent(_)) && retries < MAX_UNPROCESSED_RETRIES {
                retries += 1;
                Self::retry_decision(error, hop)?;
                continue;
            }
            return Err(error);
        };

        if quic_failed {
            self.mark_alt_svc_broken(&key.host, key.port);
        }
        Ok(parts)
    }

    async fn connect_tcp(
        &self,
        key: &PoolKey,
        proxy: Option<&ProxyConfig>,
    ) -> Result<Fresh, Error> {
        if key.secure {
            let (tls, peer_addr) = self
                .connect_tls(&key.host, key.port, proxy, AlpnMode::Profile)
                .await?;
            let info = ConnInfo {
                peer_addr,
                tls_resumed: tls.ssl().session_reused(),
                accept_ch: crate::tls::connector::peer_application_settings(tls.ssl())
                    .map(|alps| super::client_hints::alps_accept_ch(&alps, false).into()),
                ..ConnInfo::default()
            };
            if tls.ssl().selected_alpn_protocol() == Some(b"h2") {
                let conn = self.h2_handshake(tls).await?;
                let id = self
                    .pool
                    .put_mux(key.clone(), Mux::H2(conn.clone()), info.clone());
                return Ok(Fresh::Mux(Mux::H2(conn), info, id));
            }
            self.pool.set_multiplexed(key, false);
            return Ok(Fresh::H1(Box::new(tls), info));
        }
        let absolute = proxy.is_some_and(|p| matches!(p.kind, ProxyKind::Http | ProxyKind::Https));
        let opened = self.open_stream(&key.host, key.port, proxy, false).await?;
        Ok(Fresh::H1(
            opened.io,
            ConnInfo {
                peer_addr: opened.peer_addr,
                absolute_form: absolute,
                ..ConnInfo::default()
            },
        ))
    }

    async fn connect_racing_quic(&self, key: &PoolKey, h3_port: u16) -> Result<Fresh, Error> {
        let h3 = |new: NewH3| Fresh::Mux(Mux::H3(new.conn), new.info, new.id);
        let mut quic = self.start_h3(key, h3_port).await;
        match tokio::time::timeout(QUIC_HEAD_START, &mut quic).await {
            Ok(Ok(Ok(new))) => return Ok(h3(new)),
            Ok(_) => return self.connect_tcp(key, None).await,
            Err(_) => {}
        }
        let tcp = self.connect_tcp(key, None);
        tokio::pin!(tcp);
        tokio::select! {
            result = &mut quic => match result {
                Ok(Ok(new)) => Ok(h3(new)),
                _ => tcp.await,
            },
            result = &mut tcp => match result {
                Ok(fresh) => Ok(fresh),
                Err(e) => match quic.await {
                    Ok(Ok(new)) => Ok(h3(new)),
                    _ => Err(e),
                },
            },
        }
    }

    async fn connect_direct_quic(&self, key: &PoolKey, h3_port: u16) -> Result<Fresh, Error> {
        match self.start_h3(key, h3_port).await.await {
            Ok(Ok(new)) => Ok(Fresh::Mux(Mux::H3(new.conn), new.info, new.id)),
            _ => self.connect_tcp(key, None).await,
        }
    }

    fn request_headers(
        &self,
        out: &Outgoing<'_>,
        protocol: Protocol,
        proxy_headers: Option<&[(String, String)]>,
        info: &ConnInfo,
    ) -> Vec<(String, String)> {
        out.progress.sending.store(true, Ordering::Relaxed);
        let hop = out.hop;
        let length = hop.body.length();
        match &hop.source {
            HeaderSource::Profile => {
                let mut headers = headers::build(&HeaderInput {
                    profile: &self.profile,
                    protocol,
                    method: &hop.method,
                    uri: &hop.url,
                    body_len: match length {
                        Length::None => None,
                        Length::Known(len) => Some(len as usize),
                        Length::Unknown => Some(0),
                    },
                    client_headers: &hop.client_headers,
                    request_headers: &hop.request_headers,
                    cookie: out.cookie,
                    proxy_headers,
                    alt_used: info.alt_used.as_deref(),
                    client_hints: Some(&self.client_hints),
                    accept_ch_frame: info.accept_ch_for(&super::client_hints::origin_of(&hop.url)),
                    restarted: out.restarted,
                    context: Some(out.context),
                });
                if length == Length::Unknown {
                    unknown_length(&mut headers, protocol);
                }
                headers
            }
            HeaderSource::Raw(raw) => headers::build_raw(raw, protocol, &hop.url, proxy_headers),
        }
    }
}
