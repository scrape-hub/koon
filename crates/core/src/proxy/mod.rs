mod ca;
mod config;
mod server;

// A live handle that can mint a certificate for any hostname using the CA's private key; no
// caller outside this crate's own tests needs it (every public thing a caller can do with a CA
// — get its cert path, get its cert as PEM — has a `ProxyServer` method already, and `server.rs`
// reaches the type itself via `super::ca::CertAuthority`, not through this re-export). Public
// only under "test-util", the crate's own dev-dependency feature for its integration tests.
#[cfg(feature = "test-util")]
pub use ca::CertAuthority;
pub(crate) use config::{ProxyConfig, ProxyKind, ProxyRotation};
pub use server::{HeaderMode, ProxyServer, ProxyServerAuth, ProxyServerConfig};

impl std::str::FromStr for HeaderMode {
    type Err = crate::Error;

    /// `"impersonate"` or `"passthrough"`, ignoring case.
    fn from_str(s: &str) -> Result<Self, crate::Error> {
        if s.eq_ignore_ascii_case("impersonate") {
            Ok(HeaderMode::Impersonate)
        } else if s.eq_ignore_ascii_case("passthrough") {
            Ok(HeaderMode::Passthrough)
        } else {
            Err(crate::Error::InvalidArgument(
                format!("Unknown header mode: '{s}'. Expected 'impersonate' or 'passthrough'"),
                None,
            ))
        }
    }
}
