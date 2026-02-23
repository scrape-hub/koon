use std::fmt;

/// All errors that can occur when using the koon HTTP client.
#[derive(Debug)]
pub enum Error {
    /// BoringSSL TLS handshake or session error.
    Tls(boring2::ssl::Error),
    /// BoringSSL internal error stack.
    TlsStack(boring2::error::ErrorStack),
    /// HTTP/2 protocol error (stream reset, flow control, etc.).
    Http2(http2::Error),
    /// QUIC transport error.
    Quic(String),
    /// HTTP/3 protocol error.
    Http3(String),
    /// OS-level I/O error (TCP connect, read, write).
    Io(std::io::Error),
    /// URL parsing error.
    Url(url::ParseError),
    /// Proxy connection or authentication error.
    Proxy(String),
    /// Invalid HTTP header name or value.
    InvalidHeader(String),
    /// TCP connection failed (DNS resolution, refused, etc.).
    ConnectionFailed(String),
    /// JSON serialization or deserialization error.
    Json(serde_json::Error),
    /// WebSocket protocol error.
    WebSocket(Box<tungstenite::error::Error>),
    /// DNS-over-HTTPS resolution error.
    #[cfg(feature = "doh")]
    Dns(String),
    /// Request timed out.
    Timeout,
    /// Redirect limit exceeded.
    TooManyRedirects,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tls(e) => write!(f, "TLS error: {e}"),
            Error::TlsStack(e) => write!(f, "TLS stack error: {e}"),
            Error::Http2(e) => write!(f, "HTTP/2 error: {e}"),
            Error::Quic(e) => write!(f, "QUIC error: {e}"),
            Error::Http3(e) => write!(f, "HTTP/3 error: {e}"),
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Url(e) => write!(f, "URL parse error: {e}"),
            Error::Proxy(e) => write!(f, "Proxy error: {e}"),
            Error::InvalidHeader(e) => write!(f, "Invalid header: {e}"),
            Error::ConnectionFailed(e) => write!(f, "Connection failed: {e}"),
            Error::Json(e) => write!(f, "JSON error: {e}"),
            Error::WebSocket(e) => write!(f, "WebSocket error: {e}"),
            #[cfg(feature = "doh")]
            Error::Dns(e) => write!(f, "DNS error: {e}"),
            Error::Timeout => write!(f, "Request timed out"),
            Error::TooManyRedirects => write!(f, "Too many redirects"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Machine-readable error code string for programmatic error handling.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Tls(_) | Error::TlsStack(_) => "TLS_ERROR",
            Error::Http2(_) => "HTTP2_ERROR",
            Error::Quic(_) => "QUIC_ERROR",
            Error::Http3(_) => "HTTP3_ERROR",
            Error::Io(_) => "IO_ERROR",
            Error::Url(_) => "INVALID_URL",
            Error::Proxy(_) => "PROXY_ERROR",
            Error::InvalidHeader(_) => "INVALID_HEADER",
            Error::ConnectionFailed(_) => "CONNECTION_FAILED",
            Error::Json(_) => "JSON_ERROR",
            Error::WebSocket(_) => "WEBSOCKET_ERROR",
            #[cfg(feature = "doh")]
            Error::Dns(_) => "DNS_ERROR",
            Error::Timeout => "TIMEOUT",
            Error::TooManyRedirects => "TOO_MANY_REDIRECTS",
        }
    }

    /// Check if this is a timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout)
    }

    /// Check if this is a proxy error.
    pub fn is_proxy_error(&self) -> bool {
        matches!(self, Error::Proxy(_))
    }

    /// Check if this is a TLS error.
    pub fn is_tls_error(&self) -> bool {
        matches!(self, Error::Tls(_) | Error::TlsStack(_))
    }

    /// Check if this is a connection error.
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Error::ConnectionFailed(_))
    }

    /// Check if this error is an HTTP/2 GOAWAY from the remote peer.
    pub fn is_h2_goaway(&self) -> bool {
        match self {
            Error::Http2(e) => e.is_go_away() && e.is_remote(),
            _ => false,
        }
    }

    /// Check if this error is retryable (transport-level failures).
    ///
    /// Retryable: connection failures, TLS errors, I/O errors, timeouts,
    /// proxy errors, QUIC/H3 errors.
    ///
    /// NOT retryable: HTTP/2 stream errors, redirect limits, URL parse errors,
    /// JSON errors, WebSocket errors.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::ConnectionFailed(_)
                | Error::Tls(_)
                | Error::TlsStack(_)
                | Error::Io(_)
                | Error::Timeout
                | Error::Proxy(_)
                | Error::Quic(_)
                | Error::Http3(_)
        )
    }
}

impl From<boring2::ssl::Error> for Error {
    fn from(e: boring2::ssl::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<boring2::error::ErrorStack> for Error {
    fn from(e: boring2::error::ErrorStack) -> Self {
        Error::TlsStack(e)
    }
}

impl From<http2::Error> for Error {
    fn from(e: http2::Error) -> Self {
        Error::Http2(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::Url(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<tungstenite::error::Error> for Error {
    fn from(e: tungstenite::error::Error) -> Self {
        Error::WebSocket(Box::new(e))
    }
}
