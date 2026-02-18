pub mod tls;
pub mod http2;
pub(crate) mod http1;
pub mod profile;
pub mod client;
pub mod cookie;
pub mod error;
pub mod pool;
pub mod proxy;
pub mod websocket;

pub use client::{Client, ClientBuilder};
pub use cookie::CookieJar;
pub use error::Error;
pub use profile::{BrowserProfile, Chrome, Edge, Firefox, Safari};
pub use websocket::{WebSocket, Message as WsMessage};
