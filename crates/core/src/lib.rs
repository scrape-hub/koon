pub mod client;
pub mod cookie;
#[cfg(feature = "doh")]
pub mod dns;
pub mod error;
pub(crate) mod http1;
pub mod http2;
pub mod multipart;
pub mod options;
pub(crate) mod pool;
pub mod profile;
pub mod proxy;
pub mod quic;
pub mod streaming;
pub mod tls;
pub(crate) mod util;
pub mod verify;
pub mod websocket;

pub use client::{
    Body, Client, ClientBuilder, ConnectionOptions, ContentDecoder, HttpResponse, IpVersion,
    OnRedirectHook, OnRequestHook, OnResponseHook, RequestOptions, SessionExport, blocked_by,
    decode_body_text, parse_method,
};
pub use cookie::{Cookie, CookieJar, CookieParams, PartitionKey, SameSite, SkippedCookie};
pub use error::{Error, Phase, PhasedError};
pub use multipart::{BoundaryStyle, Multipart, Part};
pub use profile::{
    Brave, Browser, BrowserProfile, Chrome, DEFAULT_OS, Edge, Firefox, HeaderFamily,
    LanguageSource, NetworkQuality, OkHttp, Opera, OperaMobile, Os, ProfileName, SAFARI_VERSIONS,
    Safari, SafariVersion, Samsung, ServerPadding, UaClientHints, UiTable,
};
#[cfg(feature = "test-util")]
pub use proxy::CertAuthority;
pub use proxy::{HeaderMode, ProxyServer, ProxyServerAuth, ProxyServerConfig};
pub use quic::{QuicConfig, QuicStack};
pub use streaming::StreamingResponse;
pub use websocket::{Message as WsMessage, WebSocket};
