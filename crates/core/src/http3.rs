use bytes::{Buf, Bytes};
use h3_quinn::quinn;
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};

use crate::client::HttpResponse;
use crate::error::Error;
use crate::profile::BrowserProfile;
use crate::quic;

/// Perform an HTTP/3 request over an existing QUIC connection.
pub(crate) async fn send_request(
    connection: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    method: Method,
    uri: &Uri,
    profile: &BrowserProfile,
    custom_headers: &[(String, String)],
    body: Option<Vec<u8>>,
    cookie_header: Option<&str>,
) -> Result<HttpResponse, Error> {
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
    let scheme = uri.scheme_str().unwrap_or("https");
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let h3_uri: Uri = format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|_| Error::InvalidHeader("Failed to build H3 URI".into()))?;

    let mut req_builder = Request::builder()
        .method(method.clone())
        .uri(h3_uri)
        .version(Version::HTTP_3);

    // Add profile headers
    for (name, value) in &profile.headers {
        let lower = name.to_lowercase();
        if lower == "host" || lower == "cookie" {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            req_builder = req_builder.header(hn, hv);
        }
    }

    // Custom headers
    for (name, value) in custom_headers {
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            req_builder = req_builder.header(hn, hv);
        }
    }

    // Cookie header
    if let Some(cookie_val) = cookie_header {
        if let Ok(hv) = HeaderValue::from_str(cookie_val) {
            req_builder = req_builder.header(http::header::COOKIE, hv);
        }
    }

    let req = req_builder
        .body(())
        .map_err(|e| Error::Http3(format!("Failed to build H3 request: {e}")))?;

    // Send request
    let mut stream = connection
        .send_request(req)
        .await
        .map_err(|e| Error::Http3(format!("Failed to send H3 request: {e}")))?;

    // Send body if present
    if let Some(body_bytes) = body {
        stream
            .send_data(Bytes::from(body_bytes))
            .await
            .map_err(|e| Error::Http3(format!("Failed to send H3 body: {e}")))?;
    }

    // Finish sending
    stream
        .finish()
        .await
        .map_err(|e| Error::Http3(format!("Failed to finish H3 stream: {e}")))?;

    // Receive response
    let response = stream
        .recv_response()
        .await
        .map_err(|e| Error::Http3(format!("Failed to receive H3 response: {e}")))?;

    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Read body
    let mut body_data = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Http3(format!("Failed to read H3 body: {e}")))?
    {
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            body_data.extend_from_slice(bytes);
            let len = bytes.len();
            chunk.advance(len);
        }
    }

    Ok(HttpResponse {
        status,
        headers: resp_headers,
        body: body_data,
        version: "h3".to_string(),
        url: uri.to_string(),
    })
}

/// Establish a new HTTP/3 connection to a host.
pub(crate) async fn connect(
    endpoint: &quinn::Endpoint,
    host: &str,
    port: u16,
    profile: &BrowserProfile,
) -> Result<
    (
        h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        h3::client::Connection<h3_quinn::Connection, Bytes>,
    ),
    Error,
> {
    // Build client config with QUIC transport parameters from profile
    let quic_config = profile
        .quic
        .as_ref()
        .ok_or_else(|| Error::Quic("No QuicConfig in profile".into()))?;
    let client_config = quic::transport::build_client_config(quic_config)?;

    // Resolve address
    let addr = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| Error::Quic(format!("DNS resolution failed: {e}")))?
        .next()
        .ok_or_else(|| Error::Quic("No addresses found".into()))?;

    // Connect via QUIC
    let connection = endpoint
        .connect_with(client_config, addr, host)
        .map_err(|e| Error::Quic(format!("QUIC connect error: {e}")))?
        .await
        .map_err(|e| Error::Quic(format!("QUIC connection failed: {e}")))?;

    // Build HTTP/3 connection
    let quinn_conn = h3_quinn::Connection::new(connection);
    let (driver, send_request) = h3::client::new(quinn_conn)
        .await
        .map_err(|e| Error::Http3(format!("H3 handshake failed: {e}")))?;

    Ok((send_request, driver))
}
