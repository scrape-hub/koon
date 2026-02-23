use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_boring2::SslStream;

use crate::error::Error;
use crate::http2::config::{PseudoHeader, SettingId};
use crate::streaming::StreamingResponse;

use super::headers;
use super::response::{HttpResponse, decompress_body, estimate_headers_size};

impl super::Client {
    /// Perform the HTTP/2 handshake over a TLS connection.
    /// Configures H2 settings from the browser profile and spawns the connection driver task.
    /// Returns a SendRequest handle that can be cloned and reused for multiple requests.
    pub(super) async fn h2_handshake(
        &self,
        tls_stream: SslStream<TcpStream>,
    ) -> Result<http2::client::SendRequest<bytes::Bytes>, Error> {
        let h2_config = &self.profile.http2;

        // Build h2 client with fingerprinted settings
        let mut h2_builder = http2::client::Builder::new();

        if let Some(hts) = h2_config.header_table_size {
            h2_builder.header_table_size(hts);
        }
        if let Some(ep) = h2_config.enable_push {
            h2_builder.enable_push(ep);
        }
        if let Some(mcs) = h2_config.max_concurrent_streams {
            h2_builder.max_concurrent_streams(mcs);
        }
        h2_builder.initial_window_size(h2_config.initial_window_size);
        h2_builder.initial_connection_window_size(h2_config.initial_conn_window_size);
        if let Some(mfs) = h2_config.max_frame_size {
            h2_builder.max_frame_size(mfs);
        }
        if let Some(mhls) = h2_config.max_header_list_size {
            h2_builder.max_header_list_size(mhls);
        }

        // Settings order
        if !h2_config.settings_order.is_empty() {
            let mut order = http2::frame::SettingsOrder::builder();
            for setting_id in &h2_config.settings_order {
                let id = match setting_id {
                    SettingId::HeaderTableSize => http2::frame::SettingId::HeaderTableSize,
                    SettingId::EnablePush => http2::frame::SettingId::EnablePush,
                    SettingId::MaxConcurrentStreams => {
                        http2::frame::SettingId::MaxConcurrentStreams
                    }
                    SettingId::InitialWindowSize => http2::frame::SettingId::InitialWindowSize,
                    SettingId::MaxFrameSize => http2::frame::SettingId::MaxFrameSize,
                    SettingId::MaxHeaderListSize => http2::frame::SettingId::MaxHeaderListSize,
                    SettingId::EnableConnectProtocol => {
                        http2::frame::SettingId::EnableConnectProtocol
                    }
                    SettingId::NoRfc7540Priorities => http2::frame::SettingId::NoRfc7540Priorities,
                };
                order = order.push(id);
            }
            h2_builder.settings_order(order.build());
        }

        // Pseudo-header order
        if !h2_config.pseudo_header_order.is_empty() {
            let mut pseudo = http2::frame::PseudoOrder::builder();
            for ph in &h2_config.pseudo_header_order {
                let id = match ph {
                    PseudoHeader::Method => http2::frame::PseudoId::Method,
                    PseudoHeader::Authority => http2::frame::PseudoId::Authority,
                    PseudoHeader::Scheme => http2::frame::PseudoId::Scheme,
                    PseudoHeader::Path => http2::frame::PseudoId::Path,
                    PseudoHeader::Status => http2::frame::PseudoId::Status,
                    PseudoHeader::Protocol => http2::frame::PseudoId::Protocol,
                };
                pseudo = pseudo.push(id);
            }
            h2_builder.headers_pseudo_order(pseudo.build());
        }

        // Stream dependency for HEADERS frame
        if let Some(dep) = &h2_config.headers_stream_dependency {
            h2_builder.headers_stream_dependency(http2::frame::StreamDependency::new(
                http2::frame::StreamId::from(dep.stream_id),
                dep.weight,
                dep.exclusive,
            ));
        }

        // PRIORITY frames (Firefox sends these, Chrome/Safari disable them)
        if !h2_config.priorities.is_empty() {
            let mut prio_builder = http2::frame::Priorities::builder();
            for pf in &h2_config.priorities {
                let dep = http2::frame::StreamDependency::new(
                    http2::frame::StreamId::from(pf.dependency),
                    pf.weight,
                    pf.exclusive,
                );
                let priority =
                    http2::frame::Priority::new(http2::frame::StreamId::from(pf.stream_id), dep);
                prio_builder = prio_builder.push(priority);
            }
            h2_builder.priorities(prio_builder.build());
        }

        // RFC 7540 Priorities deaktivieren (Chrome 131+, Safari 18.3)
        if let Some(val) = h2_config.no_rfc7540_priorities {
            h2_builder.no_rfc7540_priorities(val);
        }

        // CONNECT protocol (Safari 18.3)
        if let Some(val) = h2_config.enable_connect_protocol {
            h2_builder.enable_connect_protocol(val);
        }

        // NOTE: Do NOT set h2_builder.headers_order() here.
        // headers_order is per-connection and would force navigation header order
        // on ALL requests (including CORS/fetch). Instead, we rely on the HeaderMap
        // iteration order from sort_headers_chromium_cors() / sort_headers_by_profile()
        // which correctly handles both navigation and CORS header ordering.

        // Perform the HTTP/2 handshake
        let (client, h2_conn) = h2_builder
            .handshake::<_, bytes::Bytes>(tls_stream)
            .await
            .map_err(Error::Http2)?;

        // Spawn a task to drive the HTTP/2 connection
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        Ok(client)
    }

    /// Send an HTTP/2 request on an existing SendRequest handle.
    pub(super) async fn send_on_h2(
        &self,
        sender: &mut http2::client::SendRequest<bytes::Bytes>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        sender.clone().ready().await.map_err(Error::Http2)?;

        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}")
            .parse()
            .map_err(|_| Error::InvalidHeader("Failed to build H2 URI".into()))?;

        let mut req = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| Error::InvalidHeader(format!("Failed to build request: {e}")))?;

        *req.headers_mut() = headers::build_request_headers(
            &self.profile.headers,
            &self.custom_headers,
            extra_headers,
            cookie_header,
            &["host", "cookie"],
            None,
            false,
            Some(uri),
        );

        // Estimate bytes_sent: request headers + body
        let req_headers_vec: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let req_header_size = estimate_headers_size(&req_headers_vec);
        let body_len = body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let bytes_sent = req_header_size + body_len;

        // Send the request
        let has_body = body.is_some();
        let (response_future, mut send_stream) =
            sender.send_request(req, !has_body).map_err(Error::Http2)?;

        if let Some(body_bytes) = body {
            send_stream
                .send_data(body_bytes.into(), true)
                .map_err(Error::Http2)?;
        }

        // Await the response
        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // Read body
        let mut body_data = Vec::new();
        let mut recv_stream = response.into_body();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.map_err(Error::Http2)?;
            body_data.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }

        // bytes_received = raw body (pre-decompression) + header estimate
        let raw_body_len = body_data.len() as u64;
        let resp_header_size = estimate_headers_size(&resp_headers);
        let bytes_received = raw_body_len + resp_header_size;

        let content_encoding = resp_headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(body_data, content_encoding)?;

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
            version: "h2".to_string(),
            url: uri.to_string(),
            bytes_sent,
            bytes_received,
            tls_resumed: false,
            connection_reused: false,
        })
    }

    /// Send an H2 request and return a streaming response.
    pub(super) async fn send_on_h2_streaming(
        &self,
        sender: &mut http2::client::SendRequest<bytes::Bytes>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        cookie_header: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<StreamingResponse, Error> {
        sender.clone().ready().await.map_err(Error::Http2)?;

        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}")
            .parse()
            .map_err(|_| Error::InvalidHeader("Failed to build H2 URI".into()))?;

        let mut req = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| Error::InvalidHeader(format!("Failed to build request: {e}")))?;

        *req.headers_mut() = headers::build_request_headers(
            &self.profile.headers,
            &self.custom_headers,
            extra_headers,
            cookie_header,
            &["host", "cookie"],
            None,
            false,
            Some(uri),
        );

        // Estimate bytes_sent
        let req_headers_vec: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let req_header_size = estimate_headers_size(&req_headers_vec);
        let body_len = body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let bytes_sent = req_header_size + body_len;

        let has_body = body.is_some();
        let (response_future, mut send_stream) =
            sender.send_request(req, !has_body).map_err(Error::Http2)?;

        if let Some(body_bytes) = body {
            send_stream
                .send_data(body_bytes.into(), true)
                .map_err(Error::Http2)?;
        }

        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let resp_header_size = estimate_headers_size(&resp_headers);

        let mut recv_stream = response.into_body();
        let (tx, rx) = mpsc::channel(16);

        // Track header bytes + request bytes immediately
        let bytes_received_counter = self.bytes_received_counter();
        bytes_received_counter.fetch_add(resp_header_size, std::sync::atomic::Ordering::Relaxed);
        self.bytes_sent_counter()
            .fetch_add(bytes_sent, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            while let Some(chunk) = recv_stream.data().await {
                match chunk {
                    Ok(data) => {
                        let _ = recv_stream.flow_control().release_capacity(data.len());
                        if tx.send(Ok(data.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Error::Http2(e))).await;
                        return;
                    }
                }
            }
        });

        Ok(StreamingResponse::new(
            status,
            resp_headers,
            "h2".to_string(),
            uri.to_string(),
            rx,
            bytes_sent,
            bytes_received_counter,
        ))
    }

    /// Send an H2 request with raw (passthrough) headers.
    pub(super) async fn send_on_h2_raw(
        &self,
        sender: &mut http2::client::SendRequest<bytes::Bytes>,
        method: Method,
        uri: &Uri,
        body: Option<Vec<u8>>,
        raw_headers: &[(String, String)],
    ) -> Result<HttpResponse, Error> {
        sender.clone().ready().await.map_err(Error::Http2)?;

        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = uri.scheme_str().unwrap_or("https");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let h2_uri: Uri = format!("{scheme}://{authority}{path}")
            .parse()
            .map_err(|_| Error::InvalidHeader("Failed to build H2 URI".into()))?;

        let mut req = Request::builder()
            .method(method.clone())
            .uri(h2_uri)
            .version(Version::HTTP_2)
            .body(())
            .map_err(|e| Error::InvalidHeader(format!("Failed to build request: {e}")))?;

        let headers = req.headers_mut();
        for (name, value) in raw_headers {
            let lower = name.to_lowercase();
            if lower == "host" || lower == "connection" || lower == "transfer-encoding" {
                continue; // H2 pseudo-headers handle these
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(hn, hv);
            }
        }

        // Estimate bytes_sent for raw headers
        let bytes_sent =
            estimate_headers_size(raw_headers) + body.as_ref().map(|b| b.len() as u64).unwrap_or(0);

        let has_body = body.is_some();
        let (response_future, mut send_stream) =
            sender.send_request(req, !has_body).map_err(Error::Http2)?;

        if let Some(body_bytes) = body {
            send_stream
                .send_data(body_bytes.into(), true)
                .map_err(Error::Http2)?;
        }

        let response = tokio::time::timeout(self.timeout, response_future)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Http2)?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let mut body_data = Vec::new();
        let mut recv_stream = response.into_body();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.map_err(Error::Http2)?;
            body_data.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }

        let raw_body_len = body_data.len() as u64;
        let resp_header_size = estimate_headers_size(&resp_headers);
        let bytes_received = raw_body_len + resp_header_size;

        let content_encoding = resp_headers
            .iter()
            .find(|(k, _)| k == "content-encoding")
            .map(|(_, v)| v.as_str());
        let body = decompress_body(body_data, content_encoding)?;

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
            version: "h2".to_string(),
            url: uri.to_string(),
            bytes_sent,
            bytes_received,
            tls_resumed: false,
            connection_reused: false,
        })
    }
}
