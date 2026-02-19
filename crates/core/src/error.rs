use std::fmt;

#[derive(Debug)]
pub enum Error {
    Tls(boring2::ssl::Error),
    TlsStack(boring2::error::ErrorStack),
    Http2(http2::Error),
    Quic(String),
    Http3(String),
    Io(std::io::Error),
    Url(url::ParseError),
    Proxy(String),
    InvalidHeader(String),
    ConnectionFailed(String),
    Json(serde_json::Error),
    WebSocket(tungstenite::error::Error),
    Timeout,
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
            Error::Timeout => write!(f, "Request timed out"),
            Error::TooManyRedirects => write!(f, "Too many redirects"),
        }
    }
}

impl std::error::Error for Error {}

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
        Error::WebSocket(e)
    }
}
