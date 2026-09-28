/// A source error boxed behind `Error + Send + Sync`, the shape every variant below uses for the
/// concrete cause it was built from (when one exists).
type Source = Box<dyn std::error::Error + Send + Sync>;

/// Boxes a concrete error to use as a variant's `#[source]` while its `Display` message (already
/// rendered with `format!("...: {e}")` by the caller) stays the public string. Kept as one helper
/// instead of a constructor per variant so call sites stay a small, uniform diff.
pub(crate) fn boxed<E: std::error::Error + Send + Sync + 'static>(e: E) -> Option<Source> {
    Some(Box::new(e))
}

/// All errors that can occur when using the koon HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `BoringSSL` TLS handshake or session error.
    #[error("TLS error: {0}")]
    Tls(#[from] btls::ssl::Error),
    /// `BoringSSL` internal error stack.
    #[error("TLS stack error: {0}")]
    TlsStack(#[from] btls::error::ErrorStack),
    /// HTTP/2 protocol error (stream reset, flow control, etc.).
    #[error("HTTP/2 error: {0}")]
    Http2(#[from] http2::Error),
    /// QUIC transport error.
    #[error("QUIC error: {0}")]
    Quic(String, #[source] Option<Source>),
    /// HTTP/3 protocol error.
    #[error("HTTP/3 error: {0}")]
    Http3(String, #[source] Option<Source>),
    /// OS-level I/O error (TCP connect, read, write).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// URL parsing error.
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    /// A URL with a scheme koon does not speak: a request URL other than http/https, a redirect to
    /// e.g. `ftp:`, a WebSocket URL other than ws/wss.
    #[error("Unsupported URL scheme {0}")]
    UnsupportedScheme(String),
    /// Proxy connection or authentication error.
    #[error("Proxy error: {0}")]
    Proxy(String, #[source] Option<Source>),
    /// Invalid HTTP header name or value.
    #[error("Invalid header: {0}")]
    InvalidHeader(String, #[source] Option<Source>),
    /// The request body stream failed, did not match its announced length, or cannot be sent again
    /// (a redirect other than 303 of a request with a stream body).
    #[error("Request body error: {0}")]
    Body(String, #[source] Option<Source>),
    /// TCP connection failed (DNS resolution, refused, etc.).
    #[error("Connection failed: {0}")]
    ConnectionFailed(String, #[source] Option<Source>),
    /// The server sent a malformed HTTP message (bad framing, invalid chunk size, conflicting
    /// Content-Length).
    #[error("HTTP protocol error: {0}")]
    Protocol(String, #[source] Option<Source>),
    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// WebSocket protocol error.
    #[error("WebSocket error: {0}")]
    WebSocket(Box<tungstenite::error::Error>),
    /// DNS-over-HTTPS resolution error.
    #[cfg(feature = "doh")]
    #[error("DNS error: {0}")]
    Dns(String, #[source] Option<Source>),
    /// Invalid browser profile configuration (unknown cipher, curve, or signature algorithm name).
    #[error("Invalid profile configuration: {0}")]
    Config(String, #[source] Option<Source>),
    /// Request timed out.
    #[error("Request timed out")]
    Timeout,
    /// Redirect limit exceeded.
    #[error("Too many redirects")]
    TooManyRedirects,
    /// Cookie operations were requested on a client with its cookie jar disabled.
    #[error("Cookie jar is disabled")]
    CookieJarDisabled,
    /// A [`CookieParams`](crate::CookieParams) converted on its own (with `Cookie::try_from`) is
    /// invalid or unsupported; the bulk import methods report such cookies as skipped instead.
    /// Always built from a validation message, not a concrete underlying error.
    #[error("Invalid cookie: {0}")]
    InvalidCookie(String),
    /// A name or value that does not denote a supported option: an unknown browser profile or OS,
    /// an HTTP method, a header mode, an IP version or a `DoH` provider.
    #[error("{0}")]
    InvalidArgument(String, #[source] Option<Source>),
    /// A request hook (`on_request`, `on_response`, `on_redirect`) failed: the error it returned,
    /// which the request fails with. Never retried.
    #[error("Hook failed: {0}")]
    Hook(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<tungstenite::error::Error> for Error {
    fn from(e: tungstenite::error::Error) -> Self {
        Self::WebSocket(Box::new(e))
    }
}

impl Error {
    /// Machine-readable error code string for programmatic error handling.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Tls(_) | Self::TlsStack(_) => "TLS_ERROR",
            Self::Http2(_) => "HTTP2_ERROR",
            Self::Quic(..) => "QUIC_ERROR",
            Self::Http3(..) => "HTTP3_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Url(_) | Self::UnsupportedScheme(_) => "INVALID_URL",
            Self::Proxy(..) => "PROXY_ERROR",
            Self::InvalidHeader(..) => "INVALID_HEADER",
            Self::Body(..) => "BODY_ERROR",
            Self::ConnectionFailed(..) => "CONNECTION_FAILED",
            Self::Protocol(..) => "PROTOCOL_ERROR",
            Self::Json(_) => "JSON_ERROR",
            Self::WebSocket(_) => "WEBSOCKET_ERROR",
            #[cfg(feature = "doh")]
            Self::Dns(..) => "DNS_ERROR",
            Self::Config(..) => "CONFIG_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::TooManyRedirects => "TOO_MANY_REDIRECTS",
            Self::CookieJarDisabled => "COOKIE_JAR_DISABLED",
            Self::InvalidCookie(_) => "INVALID_COOKIE",
            Self::InvalidArgument(..) => "INVALID_ARGUMENT",
            Self::Hook(_) => "HOOK_ERROR",
        }
    }

    /// Check if this is a timeout error.
    pub const fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// Check if this is a proxy error.
    pub const fn is_proxy_error(&self) -> bool {
        matches!(self, Self::Proxy(..))
    }

    /// Check if this is a TLS error.
    pub const fn is_tls_error(&self) -> bool {
        matches!(self, Self::Tls(_) | Self::TlsStack(_))
    }

    /// Check if this is a connection error.
    pub const fn is_connection_error(&self) -> bool {
        matches!(self, Self::ConnectionFailed(..))
    }

    /// Check if this error is an HTTP/2 GOAWAY from the remote peer.
    pub fn is_h2_goaway(&self) -> bool {
        match self {
            Self::Http2(e) => e.is_go_away() && e.is_remote(),
            _ => false,
        }
    }

    /// Whether this error provably occurred before any request was sent (during DNS/TCP, the TLS
    /// handshake, or a proxy CONNECT) — safe to retry even for a non-idempotent method like POST.
    pub const fn is_pre_send(&self) -> bool {
        matches!(
            self,
            Self::ConnectionFailed(..) | Self::Tls(_) | Self::TlsStack(_) | Self::Proxy(..)
        )
    }

    /// Whether this is a retryable transport-level failure (connection, TLS, I/O, HTTP/2 GOAWAY,
    /// timeout, proxy, protocol, QUIC/H3 errors). Unless [`is_pre_send`](Self::is_pre_send), only
    /// idempotent requests retry.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http2(e) => e.is_io() || e.is_go_away(),
            _ => matches!(
                self,
                Self::ConnectionFailed(..)
                    | Self::Tls(_)
                    | Self::TlsStack(_)
                    | Self::Io(_)
                    | Self::Timeout
                    | Self::Proxy(..)
                    | Self::Protocol(..)
                    | Self::Quic(..)
                    | Self::Http3(..)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_source_is_populated_from_the_wrapped_error() {
        let io_err = std::io::Error::other("boom");
        let err = Error::ConnectionFailed(
            format!("DNS lookup for example.com: {io_err}"),
            boxed(io_err),
        );

        assert_eq!(
            err.to_string(),
            "Connection failed: DNS lookup for example.com: boom"
        );
        let source = std::error::Error::source(&err).expect("source must be populated");
        assert_eq!(source.to_string(), "boom");
    }

    #[test]
    fn variant_without_a_concrete_error_has_no_source() {
        let err = Error::Proxy("SOCKS5 support not compiled in".into(), None);
        assert!(std::error::Error::source(&err).is_none());
    }
}
