use http::{Method, Uri};

use crate::error::Error;
use crate::http3;
use crate::streaming::StreamingResponse;

use super::alt_svc::{is_redirect, resolve_redirect};
use super::response::HttpResponse;

impl super::Client {
    /// Perform an HTTP request with extra headers (e.g. multipart content-type).
    /// These headers are injected after custom_headers and override them.
    /// Automatically follows redirects and manages cookies if enabled.
    ///
    /// When `max_retries > 0`, retries the entire request (including redirects)
    /// on retryable transport errors. With proxy rotation, each retry uses the
    /// next proxy.
    pub async fn request_with_headers(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpResponse, Error> {
        let mut last_error = None;
        for attempt in 0..=self.max_retries {
            match self
                .do_request_with_redirects(method.clone(), url, body.clone(), extra_headers.clone())
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_retryable() && attempt < self.max_retries => {
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_error.unwrap())
    }

    /// Inner redirect-following loop. Called by `request_with_headers` (possibly
    /// multiple times when retries are enabled).
    async fn do_request_with_redirects(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpResponse, Error> {
        let mut current_url: Uri = url
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost))?;
        let mut current_method = method;
        let mut current_body = body;
        let mut redirect_count: u32 = 0;

        loop {
            // Fire on_request hook
            self.fire_on_request(current_method.as_str(), &current_url.to_string());

            // Inject cookies into request headers
            let cookie_header = self
                .cookie_jar
                .as_ref()
                .and_then(|jar| jar.lock().unwrap().cookie_header(&current_url));

            let response = self
                .execute_single_request(
                    current_method.clone(),
                    &current_url,
                    current_body.clone(),
                    cookie_header.as_deref(),
                    &extra_headers,
                )
                .await?;

            // Track bandwidth
            self.track_bytes(response.bytes_sent, response.bytes_received);

            // Fire on_response hook
            self.fire_on_response(response.status, &current_url.to_string(), &response.headers);

            // Store cookies from response
            if let Some(jar) = &self.cookie_jar {
                jar.lock()
                    .unwrap()
                    .store_from_response(&current_url, &response.headers);
            }

            // Check for redirect
            if !self.follow_redirects || !is_redirect(response.status) {
                return Ok(HttpResponse {
                    url: current_url.to_string(),
                    ..response
                });
            }

            // Extract Location header
            let location = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| {
                    Error::ConnectionFailed("Redirect without Location header".into())
                })?;

            // Resolve relative URL against current URL
            let resolved_url = resolve_redirect(&current_url, &location)?;

            // Fire on_redirect hook — return 3xx response if hook says stop
            if !self.fire_on_redirect(
                response.status,
                &resolved_url.to_string(),
                &response.headers,
            ) {
                return Ok(HttpResponse {
                    url: current_url.to_string(),
                    ..response
                });
            }

            redirect_count += 1;
            if redirect_count > self.max_redirects {
                return Err(Error::TooManyRedirects);
            }

            current_url = resolved_url;

            // 307/308: preserve method and body. Otherwise: POST -> GET, drop body.
            match response.status {
                307 | 308 => {}
                _ => {
                    if current_method != Method::GET && current_method != Method::HEAD {
                        current_method = Method::GET;
                        current_body = None;
                    }
                }
            }
        }
    }

    /// Execute a single HTTP request without redirect following.
    /// Uses the connection pool to reuse existing connections.
    /// Supports HTTP/3, HTTP/2, and HTTP/1.1.
    ///
    /// Protocol selection order:
    /// 1. Existing pooled H3 connection
    /// 2. Existing pooled H2 connection
    /// 3. Existing pooled H1.1 connection
    /// 4. New connection: if Alt-Svc cache says H3 is available and no proxy → try H3
    /// 5. Fallback: TCP → TLS → H2/H1 via ALPN
    async fn execute_single_request(
        &self,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let is_https = uri.scheme_str() == Some("https");

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        // Select proxy once for this request (rotation picks the next one)
        let (proxy_idx, proxy_ref) = self.select_proxy();

        // 1. Try cached H3 connection from pool
        if let Some(mut sender) = self.pool.try_get_h3(host, port, proxy_idx) {
            match http3::send_request(
                &mut sender,
                method.clone(),
                uri,
                &self.profile,
                &self.custom_headers,
                body.clone(),
                cookie_header,
            )
            .await
            {
                Ok(response) => {
                    let mut response = self.decompress_response(response)?;
                    response.connection_reused = true;
                    return Ok(response);
                }
                Err(_) => {
                    self.pool.remove(host, port, proxy_idx);
                }
            }
        }

        // 2. Try cached H2 connection from pool
        if let Some(mut sender) = self.pool.try_get_h2(host, port, proxy_idx) {
            match self
                .send_on_h2(
                    &mut sender,
                    method.clone(),
                    uri,
                    body.clone(),
                    cookie_header,
                    extra_headers,
                )
                .await
            {
                Ok(mut response) => {
                    response.connection_reused = true;
                    return Ok(response);
                }
                Err(e) => {
                    self.pool.remove(host, port, proxy_idx);
                    // GOAWAY: retry on a fresh connection
                    if e.is_h2_goaway() {
                        return self
                            .new_connection_request(
                                method,
                                uri,
                                body,
                                cookie_header,
                                host,
                                port,
                                extra_headers,
                                proxy_idx,
                                proxy_ref,
                            )
                            .await;
                    }
                }
            }
        }

        // 3. Try cached H1.1 connection from pool
        if let Some(mut stream) = self.pool.try_take_h1(host, port, proxy_idx) {
            if let Ok((mut response, keep_alive)) = self
                .send_on_h1(
                    &mut stream,
                    method.clone(),
                    uri,
                    body.clone(),
                    cookie_header,
                    extra_headers,
                )
                .await
            {
                if keep_alive {
                    self.pool.insert_h1(host, port, proxy_idx, stream);
                }
                response.connection_reused = true;
                return Ok(response);
            }
        }

        self.new_connection_request(
            method,
            uri,
            body,
            cookie_header,
            host,
            port,
            extra_headers,
            proxy_idx,
            proxy_ref,
        )
        .await
    }

    /// Open a new connection (H3 or TCP→TLS→H2/H1) and send a request.
    /// Extracted from `execute_single_request` steps 4+5 to allow GOAWAY retry.
    #[allow(clippy::too_many_arguments)]
    async fn new_connection_request(
        &self,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        host: &str,
        port: u16,
        extra_headers: &[(String, String)],
        proxy_idx: Option<usize>,
        proxy: Option<&crate::proxy::ProxyConfig>,
    ) -> Result<HttpResponse, Error> {
        // 4. Try HTTP/3 if: no proxy, profile has QuicConfig, and Alt-Svc cache says H3 is available
        let has_proxy = proxy.is_some();
        let has_quic = self.profile.quic.is_some();
        let h3_port = if !has_proxy && has_quic {
            self.get_alt_svc_h3_port(host, port)
        } else {
            None
        };

        if let Some(h3_port) = h3_port {
            match self
                .try_h3_connection(
                    host,
                    h3_port,
                    method.clone(),
                    uri,
                    body.clone(),
                    cookie_header,
                )
                .await
            {
                Ok(response) => {
                    let response = self.decompress_response(response)?;
                    return Ok(response);
                }
                Err(_) => {
                    // H3 failed — remove Alt-Svc entry and fall through to H2/H1
                    self.remove_alt_svc(host, port);
                }
            }
        }

        // 5. New connection: TCP → TLS → H2/H1
        let tcp = self.connect_tcp_via(host, port, proxy).await?;
        let tls_stream = self.tls_connect(tcp, host, port).await?;

        let alpn = tls_stream.ssl().selected_alpn_protocol();
        let is_h2 = matches!(alpn, Some(b"h2"));
        let tls_resumed = tls_stream.ssl().session_reused();

        let mut response = if is_h2 {
            let mut sender = self.h2_handshake(tls_stream).await?;
            let response = self
                .send_on_h2(&mut sender, method, uri, body, cookie_header, extra_headers)
                .await?;
            self.pool.insert_h2(host, port, proxy_idx, sender);
            response
        } else {
            let mut stream = tls_stream;
            let (response, keep_alive) = self
                .send_on_h1(&mut stream, method, uri, body, cookie_header, extra_headers)
                .await?;
            if keep_alive {
                self.pool.insert_h1(host, port, proxy_idx, stream);
            }
            response
        };

        response.tls_resumed = tls_resumed;

        // Parse Alt-Svc header for future H3 discovery
        if !has_proxy && has_quic {
            self.parse_alt_svc_from_response(host, port, &response.headers);
        }

        Ok(response)
    }

    /// Perform a streaming HTTP request.
    ///
    /// Unlike [`request()`](super::Client::request), the response body is not buffered.
    /// Instead, chunks are delivered via [`StreamingResponse::next_chunk()`].
    ///
    /// Streaming responses do **not** follow redirects — the caller must handle
    /// 3xx responses manually (similar to `fetch(redirect: 'manual')`).
    ///
    /// Decompression is **not** applied to streaming responses.
    ///
    /// When `max_retries > 0`, retries on retryable transport errors.
    pub async fn request_streaming(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<StreamingResponse, Error> {
        self.request_streaming_with_headers(method, url, body, Vec::new())
            .await
    }

    /// Perform a streaming HTTP request with additional per-request headers.
    ///
    /// When `max_retries > 0`, retries on retryable transport errors.
    pub async fn request_streaming_with_headers(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<StreamingResponse, Error> {
        let mut last_error = None;
        for attempt in 0..=self.max_retries {
            match self
                .do_request_streaming(method.clone(), url, body.clone(), extra_headers.clone())
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) if e.is_retryable() && attempt < self.max_retries => {
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_error.unwrap())
    }

    /// Inner streaming request logic (no retry).
    async fn do_request_streaming(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<StreamingResponse, Error> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost))?;

        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let is_https = uri.scheme_str() == Some("https");

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        // Fire on_request hook
        self.fire_on_request(method.as_str(), url);

        let cookie_header = self
            .cookie_jar
            .as_ref()
            .and_then(|jar| jar.lock().unwrap().cookie_header(&uri));

        let (proxy_idx, proxy_ref) = self.select_proxy();

        // Try pooled H2 connection first
        if let Some(mut sender) = self.pool.try_get_h2(host, port, proxy_idx) {
            match self
                .send_on_h2_streaming(
                    &mut sender,
                    method.clone(),
                    &uri,
                    body.clone(),
                    cookie_header.as_deref(),
                    &extra_headers,
                )
                .await
            {
                Ok(resp) => {
                    // Fire on_response hook
                    self.fire_on_response(resp.status, url, &resp.headers);
                    // Keep H2 connection in pool (it's multiplexed)
                    self.pool.insert_h2(host, port, proxy_idx, sender);
                    return Ok(resp);
                }
                Err(e) => {
                    self.pool.remove(host, port, proxy_idx);
                    if !e.is_h2_goaway() {
                        return Err(e);
                    }
                    // GOAWAY: fall through to new connection
                }
            }
        }

        // New connection: TCP → TLS → H2/H1
        let tcp = self.connect_tcp_via(host, port, proxy_ref).await?;
        let tls_stream = self.tls_connect(tcp, host, port).await?;

        let alpn = tls_stream.ssl().selected_alpn_protocol();
        let is_h2 = matches!(alpn, Some(b"h2"));

        if is_h2 {
            let mut sender = self.h2_handshake(tls_stream).await?;
            let resp = self
                .send_on_h2_streaming(
                    &mut sender,
                    method,
                    &uri,
                    body,
                    cookie_header.as_deref(),
                    &extra_headers,
                )
                .await?;
            // Fire on_response hook
            self.fire_on_response(resp.status, url, &resp.headers);
            self.pool.insert_h2(host, port, proxy_idx, sender);
            Ok(resp)
        } else {
            let resp = self
                .send_on_h1_streaming(
                    tls_stream,
                    method,
                    &uri,
                    body,
                    cookie_header.as_deref(),
                    &extra_headers,
                )
                .await?;
            // Fire on_response hook
            self.fire_on_response(resp.status, url, &resp.headers);
            Ok(resp)
        }
    }

    /// Perform an HTTP request using the client's fingerprinted TLS/H2 connection,
    /// but with raw caller-supplied headers instead of profile headers.
    ///
    /// Used by the MITM proxy in passthrough mode: TLS + H2 settings are fingerprinted,
    /// but the actual HTTP headers come from the proxy client.
    pub(crate) async fn request_with_raw_headers(
        &self,
        method: Method,
        url: &str,
        raw_headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        // Fire on_request hook
        self.fire_on_request(method.as_str(), url);

        let uri: Uri = url
            .parse()
            .map_err(|_| Error::Url(url::ParseError::EmptyHost))?;

        let host = uri
            .host()
            .ok_or(Error::ConnectionFailed("No host in URL".into()))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let is_https = uri.scheme_str() == Some("https");

        if !is_https {
            return Err(Error::ConnectionFailed(
                "Only HTTPS is supported (HTTP would leak fingerprint)".into(),
            ));
        }

        let (proxy_idx, proxy_ref) = self.select_proxy();

        // Try pooled H2 connection first
        if let Some(mut sender) = self.pool.try_get_h2(host, port, proxy_idx) {
            match self
                .send_on_h2_raw(
                    &mut sender,
                    method.clone(),
                    &uri,
                    body.clone(),
                    &raw_headers,
                )
                .await
            {
                Ok(mut response) => {
                    response.connection_reused = true;
                    // Fire on_response hook
                    self.fire_on_response(response.status, url, &response.headers);
                    self.pool.insert_h2(host, port, proxy_idx, sender);
                    return Ok(response);
                }
                Err(e) => {
                    self.pool.remove(host, port, proxy_idx);
                    if !e.is_h2_goaway() {
                        return Err(e);
                    }
                }
            }
        }

        // New connection
        let tcp = self.connect_tcp_via(host, port, proxy_ref).await?;
        let tls_stream = self.tls_connect(tcp, host, port).await?;

        let alpn = tls_stream.ssl().selected_alpn_protocol();
        let is_h2 = matches!(alpn, Some(b"h2"));
        let tls_resumed = tls_stream.ssl().session_reused();

        let mut response = if is_h2 {
            let mut sender = self.h2_handshake(tls_stream).await?;
            let response = self
                .send_on_h2_raw(&mut sender, method, &uri, body, &raw_headers)
                .await?;
            self.pool.insert_h2(host, port, proxy_idx, sender);
            response
        } else {
            let mut stream = tls_stream;
            let (response, keep_alive) = self
                .send_on_h1_raw(&mut stream, method, &uri, body, &raw_headers)
                .await?;
            if keep_alive {
                self.pool.insert_h1(host, port, proxy_idx, stream);
            }
            response
        };

        response.tls_resumed = tls_resumed;

        // Track bandwidth
        self.track_bytes(response.bytes_sent, response.bytes_received);

        // Fire on_response hook
        self.fire_on_response(response.status, url, &response.headers);

        Ok(response)
    }
}
