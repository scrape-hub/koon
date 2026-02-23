pub mod client;
pub mod cookie;
#[cfg(feature = "doh")]
pub mod dns;
pub mod error;
pub(crate) mod http1;
pub mod http2;
pub(crate) mod http3;
pub mod multipart;
pub mod pool;
pub mod profile;
pub mod proxy;
pub mod quic;
pub mod streaming;
pub mod tls;
pub mod websocket;

pub use client::{
    Client, ClientBuilder, HttpResponse, OnRequestHook, OnResponseHook, SessionExport,
};
pub use cookie::{Cookie, CookieJar, SameSite};
pub use error::Error;
pub use multipart::{Multipart, Part};
pub use profile::{BrowserProfile, Chrome, Edge, Firefox, Opera, Safari};
pub use proxy::{CertAuthority, HeaderMode, ProxyRotation, ProxyServer, ProxyServerConfig};
pub use quic::QuicConfig;
pub use streaming::StreamingResponse;
pub use tls::{SessionCache, SessionCacheExport};
pub use websocket::{Message as WsMessage, WebSocket};
