use std::time::Duration;

use http::{Method, Uri};
use tokio::sync::OwnedMutexGuard;
use tokio::time::Instant;

use crate::error::Error;
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

/// Most bytes read from a redirect response's body to keep its connection reusable; a longer body
/// is abandoned with its connection.
const MAX_REDIRECT_BODY: usize = 64 * 1024;

/// Encoded bodies larger than this are decoded on tokio's blocking pool, not on a runtime thread.
const BLOCKING_DECODE: usize = 1024 * 1024;

/// How long a QUIC connection attempt runs alone before TCP races it.
const QUIC_HEAD_START: Duration = Duration::from_millis(300);

/// How often a request a new connection did not process (a refused HTTP/2 stream, one above a
/// GOAWAY's last stream ID, a rejected HTTP/3 request) is sent again on another new connection:
/// Chrome's `HttpNetworkTransaction` `kMaxRetryAttempts`.
const MAX_UNPROCESSED_RETRIES: usize = 2;

/// Request-body headers a redirect that switches to GET removes (Fetch Standard, HTTP-redirect
/// fetch step 12).
const REQUEST_BODY_HEADERS: &[&str] = &[
    "content-encoding",
    "content-language",
    "content-location",
    "content-type",
    "content-length",
];

/// Whether a method is idempotent per RFC 9110 §9.2.2 — safe to retry automatically. POST and PATCH
/// are excluded: retrying them after the request was sent risks a duplicate submission.
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

/// Two URLs are cross-origin if their scheme, host, or port differ.
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

/// Remove headers that must not be forwarded to a different origin after a redirect. Browsers strip
/// these on cross-origin hops so a caller's `Authorization` (or a manual `Cookie`) can't leak to a
/// foreign host.
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

/// Parse a request URL the way a browser does (WHATWG URL: IDNA, percent- encoding of spaces and
/// non-ASCII). Only http and https are accepted; the fragment is never sent.
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

/// Reject header names or values that cannot be sent (CR/LF injection, invalid characters) instead
/// of silently dropping them. Values may contain any byte but controls and DEL (RFC 9110 §5.5, RFC
/// 9113 §8.2.1): UTF-8 goes out as its bytes, as in browsers.
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

/// Where the headers of a request come from.
#[derive(Clone)]
pub(crate) enum HeaderSource {
    /// Built from the browser profile (the normal case).
    Profile,
    /// Taken verbatim from a proxied client (MITM passthrough mode).
    Raw(Vec<(String, String)>),
}

/// The pool key of a request to `url` through `proxy`.
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

/// Target of a request line: the path, or the absolute URL when talking to an HTTP proxy (RFC 9112
/// §3.2.2).
fn request_target(url: &Uri, absolute: bool) -> String {
    if absolute {
        url.to_string()
    } else {
        url.path_and_query()
            .map_or("/".to_string(), |pq| pq.as_str().to_string())
    }
}

/// The request of one redirect hop.
struct Hop {
    method: Method,
    url: Uri,
    body: Body,
    /// Caller headers may carry secrets (Authorization, a manual Cookie): copies, so they can be
    /// stripped once a redirect crosses origin.
    client_headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    source: HeaderSource,
}

impl Hop {
    /// A copy to send again later; `None` for a stream body.
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
        })
    }

    /// Turn this hop into the request that follows its `status` redirect to `next`.
    fn redirect(&mut self, status: u16, next: Uri) -> Result<(), Error> {
        // Fetch Standard, HTTP-redirect fetch step 11: a stream body cannot be sent again, so only
        // a 303 (which drops it) can be followed.
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
        // Fetch Standard: 303 turns anything but HEAD into GET; 301/302 only turn POST into GET.
        // 307/308 keep method and body.
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
        self.url = next;
        Ok(())
    }
}

/// Frame a body of unknown length: on HTTP/1.1 `Transfer-Encoding: chunked` takes the place of
/// Content-Length (as in Chromium's network stack), on HTTP/2 and HTTP/3 the DATA frames need no
/// header.
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

/// One hop's request as it goes out, with the jar's cookies of the moment.
struct Outgoing<'a> {
    hop: &'a Hop,
    cookie: Option<&'a str>,
    /// A Critical-CH restarted the request (see [`HeaderInput::restarted`]).
    restarted: bool,
}

/// A connection opened for a request.
enum Fresh {
    /// HTTP/2 or HTTP/3, with its pool ID if it was pooled.
    Mux(Mux, ConnInfo, Option<u64>),
    H1(BoxedIo, ConnInfo),
}

/// How one attempt at a hop ended.
enum HopOutcome {
    /// A redirect to follow; its body is still unread.
    Redirect(ResponseParts, Uri),
    /// A navigation Critical-CH asks to send again, with the client hints its origin (the second
    /// field) now asked for; its body is unread.
    Restart(ResponseParts, String),
    /// The final response, with its body when it was collected.
    Final(ResponseParts, Option<Vec<u8>>),
}

impl super::Client {
    fn effective_timeout(&self, options: &RequestOptions) -> Duration {
        match options.timeout {
            Some(t) if t.is_zero() => super::NO_TIMEOUT,
            // Longer ones would overflow the deadline arithmetic.
            Some(t) => t.min(super::NO_TIMEOUT),
            None => self.timeout,
        }
    }

    /// Send a request and buffer the response body. `body` is anything that converts into a
    /// [`Body`]: bytes, a string, a stream, or `None`. `options` override client settings for this
    /// request; the timeout covers connecting, every redirect and reading the body. A failed hop
    /// (never one that already got its response) is retried per
    /// [`max_retries`](super::ClientBuilder::max_retries) — any retryable error for an idempotent
    /// method, else only before the request left — with the rotation's next proxy and a fresh
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
                .map_err(|e| Error::Io(std::io::Error::other(e)))??
        } else {
            decompress_body(raw, encoding.as_deref(), max)?
        };
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

    /// The proxy for one attempt: the per-request override, or the next one of the client's
    /// rotation.
    fn pick_proxy<'a>(&'a self, request_proxy: Option<&'a ProxyConfig>) -> Option<&'a ProxyConfig> {
        request_proxy.or_else(|| self.select_proxy())
    }

    /// Run a request: follow its redirects and retry failed hops (see [`send`](Self::send)).
    /// Returns the final response and URL; with `collect`, the body is read as part of the final
    /// hop and returned too, otherwise it is left unread.
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
        };
        // Where a Critical-CH restart starts over; a stream body cannot be sent again, which leaves
        // the current hop to repeat.
        let first = hop.replay();
        let mut proxy = self.pick_proxy(proxy_override.as_ref());
        let mut deadline = Instant::now() + timeout;
        let mut retries_left = self.max_retries;
        let mut redirects: u32 = 0;
        // Origins whose Critical-CH already restarted this request.
        let mut restarted = std::collections::HashSet::new();

        loop {
            // Boxed so this loop's future does not carry the size of the whole
            // send/exchange/connect call chain below it.
            let attempt = tokio::time::timeout_at(
                deadline,
                Box::pin(self.attempt_hop(&hop, options, proxy, collect, &restarted)),
            )
            .await
            .unwrap_or(Err(ExchangeError::Sent(Error::Timeout)));

            match attempt {
                Ok(HopOutcome::Final(parts, body)) => return Ok((parts, hop.url, body)),
                // Chromium restarts the navigation from its first URL, once per origin
                // (`CriticalClientHintsThrottle` resets the URL).
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
                        return Err(e.into_error());
                    }
                    retries_left -= 1;
                    proxy = self.pick_proxy(proxy_override.as_ref());
                    deadline = Instant::now() + timeout;
                }
            }
        }
    }

    /// One attempt at one hop: send it and, if it is the final one and `collect` is set, read its
    /// body. `restarted` names the origins whose Critical-CH restarted the request already.
    async fn attempt_hop(
        &self,
        hop: &Hop,
        options: &RequestOptions,
        proxy: Option<&ProxyConfig>,
        collect: bool,
        restarted: &std::collections::HashSet<String>,
    ) -> Result<HopOutcome, ExchangeError> {
        self.fire_on_request(options, hop.method.as_str(), &hop.url)
            .map_err(ExchangeError::Invalid)?;
        let cookie = self
            .cookie_jar
            .as_ref()
            .and_then(|jar| crate::util::lock_recover(jar).cookie_header(&hop.url));

        let mut parts = self
            .exchange(
                &Outgoing {
                    hop,
                    cookie: cookie.as_deref(),
                    restarted: !restarted.is_empty(),
                },
                proxy,
            )
            .await?;
        self.track_bytes(parts.bytes_sent, parts.head_bytes);
        if let Some(jar) = &self.cookie_jar {
            crate::util::lock_recover(jar).store_from_response(&hop.url, &parts.headers);
        }
        // A failing hook ends the request here; the response is dropped unread. Hook errors are
        // never retried.
        self.fire_on_response(options, parts.status, &hop.url, &parts.headers)
            .map_err(ExchangeError::Invalid)?;

        // A navigation response teaches the client hints of its origin. Restarting resends the
        // request from its first URL, which needs a replayable body: a stream this attempt already
        // took (`Hop::replay` then returns `None`) can't go out again, so the response is just
        // returned as final instead of failing — the same rule a redirect already applies, and what
        // a browser does too (it can't resend a consumed body either).
        let navigation = matches!(hop.source, HeaderSource::Profile)
            && headers::builds_navigation(&hop.method, &hop.client_headers, &hop.request_headers);
        if navigation {
            if let Some(origin) = self
                .learn_client_hints(&hop.url, &parts, restarted)
                .filter(|_| hop.body.replayable())
            {
                return Ok(HopOutcome::Restart(parts, origin));
            }
        }

        let follow = options.follow_redirects.unwrap_or(self.follow_redirects);
        // Like browsers, a redirect status without Location is just a response.
        if follow && is_redirect(parts.status) {
            if let Some(location) = header_value(&parts.headers, "location") {
                let next = resolve_redirect(&hop.url, location).map_err(ExchangeError::Sent)?;
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
                    .map_err(ExchangeError::Sent)?,
            )
        } else {
            None
        };
        Ok(HopOutcome::Final(parts, body))
    }

    /// Read a redirect's body so its connection can be reused; past a small limit the body is
    /// abandoned, closing (HTTP/1.1) or resetting (HTTP/2) its stream.
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

    /// One request/response exchange: reuse a pooled connection when possible (HTTP/2 or HTTP/3,
    /// then an idle HTTP/1.1 one), else open a new connection. A failure on a reused connection is
    /// replayed on a new one only if the request was not sent, or is idempotent.
    async fn exchange(
        &self,
        out: &Outgoing<'_>,
        proxy: Option<&ProxyConfig>,
    ) -> Result<ResponseParts, ExchangeError> {
        let url = &out.hop.url;
        let key = pool_key(url, proxy)?;
        let parts = self.exchange_on(out, proxy, &key).await?;
        // Chrome learns Alt-Svc from every response of a secure origin.
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
        while let Some((mut conn, info)) = self.pool.take_h1(key) {
            // The server may have closed it while it sat in the pool.
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
                    },
                    &out.hop.body,
                )
                .await
            {
                Ok(parts) => return Ok(parts),
                // Closed before it saw the request: try the next idle one.
                Err(e @ ExchangeError::NotSent(_)) => Self::retry_decision(e, out.hop)?,
                Err(e) => {
                    Self::retry_decision(e, out.hop)?;
                    break;
                }
            }
        }

        // For an origin known to speak HTTP/2 or HTTP/3, one request at a time opens a connection;
        // the others wait for it and share it, as in Chrome. A connection that fails for the
        // waiting request is tried only once; after that, it waits for its own turn.
        let mut reuse = true;
        loop {
            // Single-flight-connect: `gate` must stay held until the connection attempt starts
            // (`exchange_on_new_connection`), not just until this block ends — dropping it early
            // would reintroduce the thundering herd the gate exists to prevent.
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

    /// Send on a pooled HTTP/2 or HTTP/3 connection. A connection-level failure removes the
    /// connection from the pool; a single failed stream does not. Returns `None` when the request
    /// may be replayed elsewhere.
    async fn send_pooled(
        &self,
        out: &Outgoing<'_>,
        key: &PoolKey,
        pooled: PooledMux,
    ) -> Result<Option<ResponseParts>, ExchangeError> {
        // Boxed so `exchange_on`'s future does not carry `send_mux`'s.
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

    /// Send one request on an HTTP/2 or HTTP/3 connection.
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
                // The ALPS data of a QUIC connection, once its handshake is complete.
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

    /// Whether a request may go out again after it failed with `e`: when it did not leave or its
    /// method is idempotent, and its body can be sent again. A request that could not be built
    /// never goes out.
    fn may_resend(e: &ExchangeError, hop: &Hop) -> bool {
        let resend = match e {
            ExchangeError::NotSent(_) => true,
            ExchangeError::Sent(_) => is_idempotent(&hop.method),
            ExchangeError::Invalid(_) => false,
        };
        resend && hop.body.replayable()
    }

    /// Whether a failed exchange may be replayed on another connection (see
    /// [`may_resend`](Self::may_resend)); returns the error when it may not.
    fn retry_decision(e: ExchangeError, hop: &Hop) -> Result<(), ExchangeError> {
        if Self::may_resend(&e, hop) {
            Ok(())
        } else {
            Err(e)
        }
    }

    /// Open a new connection and send the request on it. `gate` (see
    /// [`ConnectionPool::connect_gate`](crate::pool::ConnectionPool::connect_gate)) is released as
    /// soon as the connection is up.
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
        // Nothing cached from Alt-Svc yet: a browser whose profile follows DNS HTTPS records still
        // reaches HTTP/3 on the very first connection to a host, not only from the second one on.
        let mut h3_via_https_rr = false;
        if h3_port.is_none()
            && direct_secure
            && self.follows_https_rr()
            && !self.h3_broken(&key.host, key.port)
        {
            h3_port = self.https_rr_h3_port(&key.host, key.port).await;
            h3_via_https_rr = h3_port.is_some();
        }
        // Safari opens straight on QUIC from the record, no parallel TCP attempt (captured on
        // macOS): Chrome and Firefox instead race it, like an Alt-Svc-advertised alternative
        // (`connect_racing_quic`).
        let direct_quic = h3_via_https_rr && self.quic_stack_is_apple();
        let mut gate = gate;
        let mut retries = 0;
        // The request failed on a new HTTP/3 connection and went over TCP.
        let mut quic_failed = false;

        let parts = loop {
            // Nothing is sent before the connection is up.
            let fresh = match h3_port {
                Some(h3_port) if direct_quic => self.connect_direct_quic(key, h3_port).await,
                // Boxed: this races `quic` against `tcp`, so both their states stay live at once.
                Some(h3_port) => Box::pin(self.connect_racing_quic(key, h3_port)).await,
                None => self.connect_tcp(key, proxy).await,
            }
            .map_err(ExchangeError::NotSent)?;
            drop(gate.take());

            let error = match fresh {
                Fresh::Mux(mux, info, id) => {
                    let is_h3 = matches!(mux, Mux::H3(_));
                    // Boxed so `exchange_on_new_connection`'s future does not carry `send_mux`'s.
                    match Box::pin(self.send_mux(mux, info, false, out)).await {
                        Ok(parts) => break parts,
                        Err(failure) => {
                            if failure.connection_failed {
                                if let Some(id) = id {
                                    self.pool.remove_mux(key, id);
                                }
                            }
                            if is_h3 {
                                // Chrome retries a request that failed on QUIC before its head over
                                // TCP, marking the alternative broken at once if the connection
                                // broke, else once TCP worked
                                // (`retry_without_alt_svc_on_quic_errors`).
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
            // A new connection that did not process the request: try another.
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

    /// Open a TCP connection for `key`: TLS with the profile's ALPN for https, and the HTTP/2
    /// handshake when the server picks h2. A new HTTP/2 connection is pooled right away.
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
            // HTTP/1.1 now: requests to this origin connect in parallel again.
            self.pool.set_multiplexed(key, false);
            return Ok(Fresh::H1(Box::new(tls), info));
        }
        // Plain HTTP. Through an HTTP proxy the request goes to the proxy in absolute form, as
        // browsers do; a SOCKS proxy tunnels.
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

    /// Connect to an origin with a known HTTP/3 alternative. QUIC gets a head start, then TCP races
    /// it and the first connection wins, as in Chrome. When TCP wins, the QUIC attempt finishes in
    /// the background (see [`start_h3`](Self::start_h3)).
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

    /// Connect to an origin purely over QUIC, as Safari does when its DNS HTTPS record says a host
    /// speaks h3: no parallel TCP attempt or head start, unlike
    /// [`connect_racing_quic`](Self::connect_racing_quic) for an Alt-Svc-style alternative. Only an
    /// outright QUIC failure falls back.
    async fn connect_direct_quic(&self, key: &PoolKey, h3_port: u16) -> Result<Fresh, Error> {
        match self.start_h3(key, h3_port).await.await {
            Ok(Ok(new)) => Ok(Fresh::Mux(Mux::H3(new.conn), new.info, new.id)),
            _ => self.connect_tcp(key, None).await,
        }
    }

    /// The headers of one request on `protocol` over the connection `info` describes, in wire order
    /// and casing.
    fn request_headers(
        &self,
        out: &Outgoing<'_>,
        protocol: Protocol,
        proxy_headers: Option<&[(String, String)]>,
        info: &ConnInfo,
    ) -> Vec<(String, String)> {
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
                        // Placed like a length, then replaced below.
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
