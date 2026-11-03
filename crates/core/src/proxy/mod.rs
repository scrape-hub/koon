mod ca;
mod config;
mod server;

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
