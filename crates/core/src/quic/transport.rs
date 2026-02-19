use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig, VarInt};

use super::config::QuicConfig;
use crate::error::Error;

/// Build a Quinn `Endpoint` configured for client-side QUIC connections.
/// Takes a `QuicConfig` for endpoint-level settings like `grease_quic_bit`.
pub(crate) fn build_endpoint(quic_config: &QuicConfig) -> Result<Endpoint, Error> {
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.grease_quic_bit(quic_config.grease_quic_bit);
    endpoint_config.max_udp_payload_size(quic_config.max_udp_payload_size)
        .map_err(|e| Error::Quic(format!("Invalid max_udp_payload_size: {e}")))?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Quic(format!("Failed to bind UDP socket: {e}")))?;

    let endpoint = Endpoint::new(
        endpoint_config,
        None, // no server config
        socket,
        quinn::default_runtime()
            .ok_or_else(|| Error::Quic("No async runtime available".into()))?,
    )
    .map_err(|e| Error::Quic(format!("Failed to create QUIC endpoint: {e}")))?;

    Ok(endpoint)
}

/// Build a Quinn `ClientConfig` with transport parameters matching a browser profile.
pub(crate) fn build_client_config(quic_config: &QuicConfig) -> Result<ClientConfig, Error> {
    let crypto = rustls::ClientConfig::builder()
        .with_webpki_verifier(
            rustls::client::WebPkiServerVerifier::builder(Arc::new(
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            ))
            .build()
            .map_err(|e| Error::Quic(format!("Failed to build verifier: {e}")))?,
        )
        .with_no_client_auth();

    let quic_crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Quic(format!("Failed to build QUIC crypto: {e}")))?;

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
        VarInt::from_u64(quic_config.initial_max_data)
            .unwrap_or(VarInt::from_u32(15728640)),
    );

    transport.stream_receive_window(
        VarInt::from_u64(quic_config.initial_max_stream_data_bidi_local)
            .unwrap_or(VarInt::from_u32(6291456)),
    );

    transport.max_concurrent_bidi_streams(
        VarInt::from_u64(quic_config.initial_max_streams_bidi)
            .unwrap_or(VarInt::from_u32(100)),
    );

    transport.max_concurrent_uni_streams(
        VarInt::from_u64(quic_config.initial_max_streams_uni)
            .unwrap_or(VarInt::from_u32(100)),
    );

    // Keep-alive to maintain the connection
    transport.keep_alive_interval(Some(Duration::from_secs(15)));

    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}
