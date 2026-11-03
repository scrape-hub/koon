use std::borrow::Cow;

use crate::quic::{QuicConfig, QuicStack};
use crate::tls::config::{TlsConfig, TrustAnchorOrder};

const CHROMIUM_QUIC_SIGALGS: &str = "\
ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512:\
rsa_pkcs1_sha1";

pub fn chromium_quic(tls: &TlsConfig) -> QuicConfig {
    let trust_anchor_order = match tls.trust_anchor_order {
        TrustAnchorOrder::ShuffledPerClient => TrustAnchorOrder::ShuffledPerConnection,
        order => order,
    };
    QuicConfig {
        stack: QuicStack::Chromium,
        quic_v2: false,
        reset_stream_at: false,
        tls: Some(TlsConfig {
            grease: false,
            grease_sigalgs: false,
            sigalgs: Cow::Borrowed(CHROMIUM_QUIC_SIGALGS),
            ocsp_stapling: false,
            signed_cert_timestamps: false,
            trust_anchor_order,
            ..tls.clone()
        }),
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: Some(1472),
        initial_max_data: 15_728_640,
        initial_max_stream_data_bidi_local: 6_291_456,
        initial_max_stream_data_bidi_remote: 6_291_456,
        initial_max_stream_data_uni: 6_291_456,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 103,
        max_ack_delay_ms: None,
        active_connection_id_limit: None,
        max_datagram_frame_size: Some(65_536),
        max_datagram_size: 1250,
        keep_alive_ms: Some(15_000),
        qpack_max_table_capacity: 65_536,
        qpack_blocked_streams: 100,
        max_field_section_size: Some(262_144),
        extra_transport_parameters: Vec::new(),
        session_resumption: true,
        alt_svc: true,
        https_rr: true,
        https_rr_doh_only: false,
    }
}
