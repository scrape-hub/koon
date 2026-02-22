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
    /// Check if this error is an HTTP/2 GOAWAY from the remote peer.
    pub fn is_h2_goaway(&self) -> bool {
        match self {
            Error::Http2(e) => e.is_go_away() && e.is_remote(),
            _ => false,
        }
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
