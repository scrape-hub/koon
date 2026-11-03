/// A source error boxed behind `Error + Send + Sync`, the shape every variant below uses for the
/// concrete cause it was built from (when one exists).
type Source = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn boxed<E: std::error::Error + Send + Sync + 'static>(e: E) -> Option<Source> {
    Some(Box::new(e))
}

/// All errors that can occur when using the koon HTTP client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// The response body, decoded, went past the client's cap of this many bytes
    /// ([`ClientBuilder::max_response_body`](crate::client::ClientBuilder::max_response_body)).
    /// Its code is `BODY_ERROR`, as for [`Error::Body`].
    #[error("Response body exceeded {0} bytes")]
    ResponseTooLarge(u64),
    /// TCP connection failed (refused, unreachable, etc.).
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
    /// Resolving a host name failed, through the system resolver or DNS-over-HTTPS.
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
    /// A request's transport failure with the phase it happened in ([`Error::phase`]); its message,
    /// code and source are the inner error's, which [`Error::kind`] returns to match on.
    #[error(transparent)]
    InPhase(PhasedError),
}

/// How far a request got before it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Nothing was sent: resolving the host, connecting, the TLS handshake or a proxy's CONNECT
    /// failed. Sending the request again cannot repeat it.
    Connect,
    /// The request was sent, or was being sent, and no response head arrived.
    Request,
    /// The response head arrived and reading or decoding the body failed.
    Body,
}

impl Phase {
    /// `"connect"`, `"request"` or `"body"`, as the bindings report it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Request => "request",
            Self::Body => "body",
        }
    }
}

/// The error and phase of [`Error::InPhase`].
#[derive(Debug)]
pub struct PhasedError {
    pub phase: Phase,
    pub error: Box<Error>,
}

impl std::fmt::Display for PhasedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for PhasedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl From<tungstenite::error::Error> for Error {
    fn from(e: tungstenite::error::Error) -> Self {
        Self::WebSocket(Box::new(e))
    }
}

impl Error {
    /// The phase of the request this error failed, for a transport failure of a request.
    pub const fn phase(&self) -> Option<Phase> {
        match self {
            Self::InPhase(phased) => Some(phased.phase),
            _ => None,
        }
    }

    /// The error without its phase, to match on.
    pub fn kind(&self) -> &Self {
        match self {
            Self::InPhase(phased) => &phased.error,
            other => other,
        }
    }

    /// The error without its phase, owned.
    pub fn into_kind(self) -> Self {
        match self {
            Self::InPhase(phased) => *phased.error,
            other => other,
        }
    }

    pub(crate) fn in_phase(self, phase: Phase) -> Self {
        match self {
            Self::InPhase(_) => self,
            error => Self::InPhase(PhasedError {
                phase,
                error: Box::new(error),
            }),
        }
    }

    /// Machine-readable error code string for programmatic error handling.
    pub fn code(&self) -> &'static str {
        match self.kind() {
            Self::Tls(_) | Self::TlsStack(_) => "TLS_ERROR",
            Self::Http2(_) => "HTTP2_ERROR",
            Self::Quic(..) => "QUIC_ERROR",
            Self::Http3(..) => "HTTP3_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Url(_) | Self::UnsupportedScheme(_) => "INVALID_URL",
            Self::Proxy(..) => "PROXY_ERROR",
            Self::InvalidHeader(..) => "INVALID_HEADER",
            Self::Body(..) | Self::ResponseTooLarge(_) => "BODY_ERROR",
            Self::ConnectionFailed(..) => "CONNECTION_FAILED",
            Self::Protocol(..) => "PROTOCOL_ERROR",
            Self::Json(_) => "JSON_ERROR",
            Self::WebSocket(_) => "WEBSOCKET_ERROR",
            Self::Dns(..) => "DNS_ERROR",
            Self::Config(..) => "CONFIG_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::TooManyRedirects => "TOO_MANY_REDIRECTS",
            Self::CookieJarDisabled => "COOKIE_JAR_DISABLED",
            Self::InvalidCookie(_) => "INVALID_COOKIE",
            Self::InvalidArgument(..) => "INVALID_ARGUMENT",
            Self::Hook(_) => "HOOK_ERROR",
            Self::InPhase(phased) => phased.error.code(),
        }
    }

    /// Check if this is a timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind(), Self::Timeout)
    }

    /// Check if this is a proxy error.
    pub fn is_proxy_error(&self) -> bool {
        matches!(self.kind(), Self::Proxy(..))
    }

    /// Check if this is a TLS error.
    pub fn is_tls_error(&self) -> bool {
        matches!(self.kind(), Self::Tls(_) | Self::TlsStack(_))
    }

    /// Check if this is a connection error: the host did not resolve or the connection failed.
    pub fn is_connection_error(&self) -> bool {
        matches!(self.kind(), Self::Dns(..) | Self::ConnectionFailed(..))
    }

    /// Check if this error is an HTTP/2 GOAWAY from the remote peer.
    pub fn is_h2_goaway(&self) -> bool {
        match self.kind() {
            Self::Http2(e) => e.is_go_away() && e.is_remote(),
            _ => false,
        }
    }

    /// Whether this error provably occurred before any request was sent (during DNS/TCP, the TLS
    /// handshake, or a proxy CONNECT): safe to retry even for a non-idempotent method like POST.
    pub fn is_pre_send(&self) -> bool {
        matches!(
            self.kind(),
            Self::Dns(..)
                | Self::ConnectionFailed(..)
                | Self::Tls(_)
                | Self::TlsStack(_)
                | Self::Proxy(..)
        )
    }

    /// Whether this is a retryable transport-level failure (DNS, connection, TLS, I/O, HTTP/2
    /// GOAWAY, timeout, proxy, protocol, QUIC/H3 errors). Unless
    /// [`is_pre_send`](Self::is_pre_send), only idempotent requests retry.
    pub fn is_retryable(&self) -> bool {
        match self.kind() {
            Self::Http2(e) => e.is_io() || e.is_go_away(),
            kind => matches!(
                kind,
                Self::Dns(..)
                    | Self::ConnectionFailed(..)
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
