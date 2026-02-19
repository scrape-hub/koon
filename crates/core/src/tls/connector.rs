use boring2::ssl::{
    NameType, Ssl, SslConnector, SslMethod, SslOptions, SslSessionCacheMode, SslVerifyMode,
    SslVersion,
};

use super::cert_compression::{BrotliCertCompressor, ZlibCertCompressor, ZstdCertCompressor};
use super::config::{AlpnProtocol, CertCompression, TlsConfig, TlsVersion};
use super::session_cache::SessionCache;
use crate::Error;

/// Two-phase TLS connector for browser fingerprint impersonation.
///
/// Phase 1 (`build_connector`): Creates a reusable `SslConnector` with all
/// context-level settings (ciphers, curves, ALPN, cert compression, etc.).
///
/// Phase 2 (`configure_connection`): Creates a per-connection `Ssl` object
/// with connection-level settings (ECH GREASE, ALPS, SNI).
pub struct TlsConnector;

impl TlsConnector {
    /// Phase 1: Build a reusable SslConnector (once per Client).
    ///
    /// Sets all context-level TLS parameters that affect the JA3/JA4 fingerprint.
    /// The returned `SslConnector` can be reused across multiple connections.
    pub fn build_connector(
        config: &TlsConfig,
        session_cache: Option<SessionCache>,
    ) -> Result<SslConnector, Error> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;

        // === Cipher suites (directly affects JA3 hash) ===
        builder.set_cipher_list(&config.cipher_list)?;

        // === Curves / Supported Groups ===
        builder.set_curves_list(&config.curves)?;

        // === Signature algorithms ===
        builder.set_sigalgs_list(&config.sigalgs)?;

        // === TLS version bounds ===
        builder.set_min_proto_version(Some(to_ssl_version(config.min_version)))?;
        builder.set_max_proto_version(Some(to_ssl_version(config.max_version)))?;

        // === ALPN (Application-Layer Protocol Negotiation) ===
        let alpn_wire = build_alpn_wire(&config.alpn);
        builder.set_alpn_protos(&alpn_wire)?;

        // === GREASE (Chrome-like random extensions) ===
        builder.set_grease_enabled(config.grease);

        // === Extension permutation (Chrome 110+) ===
        builder.set_permute_extensions(config.permute_extensions);

        // === OCSP stapling ===
        if config.ocsp_stapling {
            builder.enable_ocsp_stapling();
        }

        // === Signed Certificate Timestamps ===
        if config.signed_cert_timestamps {
            builder.enable_signed_cert_timestamps();
        }

        // === Pre-shared key ===
        if !config.pre_shared_key {
            builder.set_options(SslOptions::NO_PSK_DHE_KE);
        }

        // === Session tickets ===
        if !config.session_ticket {
            builder.set_options(SslOptions::NO_TICKET);
        }

        // === Key shares limit ===
        if let Some(limit) = config.key_shares_limit {
            builder.set_key_shares_limit(limit);
        }

        // === Certificate compression (RFC 8879) ===
        for algo in &config.cert_compression {
            match algo {
                CertCompression::Brotli => {
                    builder.add_certificate_compression_algorithm(BrotliCertCompressor)?;
                }
                CertCompression::Zlib => {
                    builder.add_certificate_compression_algorithm(ZlibCertCompressor)?;
                }
                CertCompression::Zstd => {
                    builder.add_certificate_compression_algorithm(ZstdCertCompressor)?;
                }
            }
        }

        // === Delegated credentials ===
        if let Some(ref dc_sigalgs) = config.delegated_credentials {
            builder.set_delegated_credentials(dc_sigalgs)?;
        }

        // === Record size limit (RFC 8449) ===
        if let Some(limit) = config.record_size_limit {
            builder.set_record_size_limit(limit);
        }

        // === Certificate verification ===
        if config.danger_accept_invalid_certs {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder.set_verify(SslVerifyMode::PEER);
            load_root_certs(&mut builder)?;
        }

        // === Session resumption ===
        if let Some(cache) = session_cache {
            builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            builder.set_new_session_callback(move |ssl, session| {
                if let Some(hostname) = ssl.servername(NameType::HOST_NAME) {
                    cache.insert(hostname, session);
                }
            });
        }

        Ok(builder.build())
    }

    /// Phase 2: Configure a per-connection SSL object.
    ///
    /// Applies connection-level settings (ECH GREASE, ALPS) and returns
    /// an `Ssl` object ready for the TLS handshake.
    pub fn configure_connection(
        connector: &SslConnector,
        config: &TlsConfig,
        host: &str,
        force_h1_only: bool,
        session_cache: Option<&SessionCache>,
        ech_config_list: Option<&[u8]>,
    ) -> Result<Ssl, Error> {
        let mut cfg = connector.configure()?;

        // ALPN: for WebSocket, only advertise http/1.1 (no h2)
        if force_h1_only {
            let alpn_wire = build_alpn_wire(&[AlpnProtocol::Http11]);
            cfg.set_alpn_protos(&alpn_wire)?;
        } else {
            let alpn_wire = build_alpn_wire(&config.alpn);
            cfg.set_alpn_protos(&alpn_wire)?;
        }

        // ECH: real ECH from DNS HTTPS record, or fallback to GREASE
        if let Some(ech_bytes) = ech_config_list {
            cfg.set_ech_config_list(ech_bytes)
                .map_err(|e| Error::ConnectionFailed(format!("ECH config failed: {e}")))?;
        } else {
            cfg.set_enable_ech_grease(config.ech_grease);
        }

        // ALPS (h2-specific, skip when forcing h1)
        if !force_h1_only {
            if config.alps.is_some() {
                cfg.set_alps_use_new_codepoint(config.alps_use_new_codepoint);
                cfg.add_application_settings(b"h2")?;
            }
        }

        // Disable hostname verification for testing
        if config.danger_accept_invalid_certs {
            cfg.set_verify_hostname(false);
        }

        let mut ssl = cfg.into_ssl(host)?;

        // Session resumption: set cached session before handshake
        if let Some(cache) = session_cache {
            if let Some(session) = cache.get(host) {
                unsafe { ssl.set_session(&session)?; }
            }
        }

        Ok(ssl)
    }
}

/// Load Mozilla's root CA certificates into the SSL context.
///
/// Uses the `webpki-root-certs` crate (same approach as wreq) which embeds
/// Mozilla's trusted root CA bundle. This works reliably on all platforms,
/// unlike BoringSSL's `set_default_verify_paths()` which fails on Windows.
fn load_root_certs(
    builder: &mut boring2::ssl::SslConnectorBuilder,
) -> Result<(), Error> {
    use boring2::x509::X509;
    use boring2::x509::store::X509StoreBuilder;

    let mut store_builder = X509StoreBuilder::new()?;

    for cert_der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(x509) = X509::from_der(cert_der.as_ref()) {
            let _ = store_builder.add_cert(x509);
        }
    }

    builder.set_verify_cert_store(store_builder.build())?;
    Ok(())
}

fn to_ssl_version(v: TlsVersion) -> SslVersion {
    match v {
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

/// Build the ALPN wire format: each protocol is preceded by its length byte.
fn build_alpn_wire(protocols: &[AlpnProtocol]) -> Vec<u8> {
    let mut wire = Vec::new();
    for proto in protocols {
        let name = match proto {
            AlpnProtocol::Http2 => b"h2" as &[u8],
            AlpnProtocol::Http11 => b"http/1.1",
        };
        wire.push(name.len() as u8);
        wire.extend_from_slice(name);
    }
    wire
}
