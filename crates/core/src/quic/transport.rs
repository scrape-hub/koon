use std::sync::Arc;
use std::time::Duration;

use btls::ssl::{SslContextBuilder, SslMethod, SslOptions, SslVerifyMode};
use quinn::{ClientConfig, Endpoint, TransportConfig, VarInt};
use quinn_btls::ClientConfig as QuicBtlsConfig;

use super::config::QuicConfig;
use crate::error::Error;
use crate::tls::cert_compression::{BrotliCertCompressor, ZlibCertCompressor, ZstdCertCompressor};
use crate::tls::config::{CertCompression, TlsConfig};

/// Build a Quinn `Endpoint` configured for client-side QUIC connections.
/// Takes a `QuicConfig` for endpoint-level settings like `grease_quic_bit`.
pub(crate) fn build_endpoint(quic_config: &QuicConfig) -> Result<Endpoint, Error> {
    let mut endpoint_config = quinn_btls::helpers::default_endpoint_config();
    endpoint_config.grease_quic_bit(quic_config.grease_quic_bit);
    endpoint_config
        .max_udp_payload_size(quic_config.max_udp_payload_size)
        .map_err(|e| Error::Quic(format!("Invalid max_udp_payload_size: {e}")))?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Quic(format!("Failed to bind UDP socket: {e}")))?;

    let endpoint = Endpoint::new(
        endpoint_config,
        None, // no server config
        socket,
        quinn::default_runtime().ok_or_else(|| Error::Quic("No async runtime available".into()))?,
    )
    .map_err(|e| Error::Quic(format!("Failed to create QUIC endpoint: {e}")))?;

    Ok(endpoint)
}

/// Build a Quinn `ClientConfig` with BoringSSL crypto and per-browser TLS
/// fingerprint matching the H2 path.
///
/// Uses quinn-btls `Config::from_builder()` with a pre-configured SslContextBuilder
/// that carries the browser's cipher list, curves, sigalgs, cert compression, etc.
/// This ensures the QUIC TLS ClientHello matches the browser profile — Firefox H3
/// gets Firefox TLS, Chrome H3 gets Chrome TLS.
pub(crate) fn build_client_config(
    quic_config: &QuicConfig,
    tls_config: &TlsConfig,
) -> Result<ClientConfig, Error> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;

    // === TLS 1.3 cipher order preservation ===
    // Must be called BEFORE set_cipher_list() to take effect.
    if tls_config.preserve_tls13_cipher_order {
        builder.set_preserve_tls13_cipher_list(true);
    }

    // === Cipher suites (directly affects JA3/JA4 hash) ===
    builder.set_cipher_list(&tls_config.cipher_list)?;

    // === Curves / Supported Groups ===
    builder.set_curves_list(&tls_config.curves)?;

    // === Signature algorithms ===
    builder.set_sigalgs_list(&tls_config.sigalgs)?;

    // === GREASE (Chrome-like random extensions) ===
    builder.set_grease_enabled(tls_config.grease);

    // === Extension permutation (Chrome 110+) ===
    builder.set_permute_extensions(tls_config.permute_extensions);

    // === OCSP stapling ===
    if tls_config.ocsp_stapling {
        builder.enable_ocsp_stapling();
    }

    // === Signed Certificate Timestamps ===
    if tls_config.signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }

    // === Pre-shared key ===
    if !tls_config.pre_shared_key {
        builder.set_options(SslOptions::NO_PSK_DHE_KE);
    }

    // === Certificate compression (RFC 8879) ===
    for algo in &tls_config.cert_compression {
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
    if let Some(ref dc_sigalgs) = tls_config.delegated_credentials {
        builder.set_delegated_credentials(dc_sigalgs)?;
    }

    // === Record size limit (RFC 8449) ===
    if let Some(limit) = tls_config.record_size_limit {
        builder.set_record_size_limit(limit);
    }

    // === Certificate verification via webpki-root-certs ===
    // BoringSSL's set_default_verify_paths() finds no CAs on Windows.
    // We inject Mozilla's root CA bundle directly.
    if tls_config.danger_accept_invalid_certs {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
        load_root_certs(&mut builder)?;
    }

    // Build quinn-btls config from our pre-configured builder.
    // from_builder() enforces TLS 1.3 and applies QUIC method/callbacks/session cache.
    let quic_crypto = QuicBtlsConfig::from_builder(builder)
        .map_err(|e| Error::Quic(format!("QUIC crypto error: {e}")))?;

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));

    // Apply transport parameters from the browser profile
    let mut transport = TransportConfig::default();

    transport.max_idle_timeout(Some(
        VarInt::from_u64(quic_config.max_idle_timeout_ms)
            .unwrap_or(VarInt::from_u32(30000))
            .into(),
    ));

    // initial_mtu controls the initial max UDP payload size before MTU discovery
    transport.initial_mtu(quic_config.max_udp_payload_size);

    transport.receive_window(
        VarInt::from_u64(quic_config.initial_max_data).unwrap_or(VarInt::from_u32(15728640)),
    );

    transport.stream_receive_window(
        VarInt::from_u64(quic_config.initial_max_stream_data_bidi_local)
            .unwrap_or(VarInt::from_u32(6291456)),
    );

    transport.max_concurrent_bidi_streams(
        VarInt::from_u64(quic_config.initial_max_streams_bidi).unwrap_or(VarInt::from_u32(100)),
    );

    transport.max_concurrent_uni_streams(
        VarInt::from_u64(quic_config.initial_max_streams_uni).unwrap_or(VarInt::from_u32(100)),
    );

    // Keep-alive to maintain the connection
    transport.keep_alive_interval(Some(Duration::from_secs(15)));

    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Load Mozilla's root CA certificates into the SSL context builder.
fn load_root_certs(builder: &mut SslContextBuilder) -> Result<(), Error> {
    use btls::x509::X509;
    use btls::x509::store::X509StoreBuilder;

    let mut store_builder = X509StoreBuilder::new()?;

    for cert_der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(x509) = X509::from_der(cert_der.as_ref()) {
            let _ = store_builder.add_cert(x509);
        }
    }

    builder.set_verify_cert_store(store_builder.build())?;
    Ok(())
}
