//! HTTP client that reproduces a real browser's TLS, HTTP/2, HTTP/3 and header fingerprint byte for
//! byte.
//!
//! [`Client`]/[`ClientBuilder`] build a client for a [`profile::BrowserProfile`] (Chrome, Firefox,
//! Safari, Edge, Opera, Brave, Samsung Internet or OkHttp); [`cookie::CookieJar`] and [`multipart`]
//! cover request-side state, and [`proxy::ProxyServer`] runs a MITM proxy that impersonates the
//! same profile on already-established connections. [`tls`], [`quic`] and [`http2`] hold the
//! per-layer configuration a profile assembles from.

pub mod client;
pub mod cookie;
#[cfg(feature = "doh")]
pub mod dns;
pub mod error;
pub(crate) mod http1;
pub mod http2;
pub mod multipart;
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
    OnRedirectHook, OnRequestHook, OnResponseHook, RequestOptions, SessionExport, decode_body_text,
    parse_method,
};
pub use cookie::{Cookie, CookieJar, CookieParams, SameSite, SkippedCookie};
pub use error::Error;
pub use multipart::{BoundaryStyle, Multipart, Part};
pub use profile::{
    Brave, Browser, BrowserProfile, Chrome, DEFAULT_OS, Edge, Firefox, HeaderFamily,
    NetworkQuality, OkHttp, Opera, OperaMobile, Os, ProfileName, SAFARI_VERSIONS, Safari,
    SafariVersion, Samsung, ServerPadding, UaClientHints,
};
#[cfg(feature = "test-util")]
pub use proxy::CertAuthority;
pub use proxy::{HeaderMode, ProxyServer, ProxyServerAuth, ProxyServerConfig};
pub use quic::{QuicConfig, QuicStack};
pub use streaming::StreamingResponse;
pub use websocket::{Message as WsMessage, WebSocket};
