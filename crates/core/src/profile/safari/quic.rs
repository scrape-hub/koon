//! Safari's QUIC/HTTP-3 fingerprint.

use crate::quic::{QuicConfig, QuicStack};

use super::{APPLE_PRIVATE_PARAMETER, Quic};

/// Whether the iOS profile queries the DNS HTTPS record: derived from macOS of the same stack
/// generation, no per-release device capture exists.
pub(super) const IOS_QUERIES_HTTPS_RECORDS: bool = true;

/// Apple's QUIC stack shared by every release; what differs is in [`Quic`]. `ios` selects
/// [`IOS_QUERIES_HTTPS_RECORDS`] for [`QuicConfig::https_rr`].
pub(super) fn safari_quic(quic: Quic, ios: bool) -> QuicConfig {
    QuicConfig {
        stack: QuicStack::Apple,
        quic_v2: false,
        reset_stream_at: false,
        tls: None,
        max_idle_timeout_ms: quic.idle_timeout_ms,
        max_udp_payload_size: None,
        initial_max_data: 16_777_216,
        initial_max_stream_data_bidi_local: 2_097_152,
        initial_max_stream_data_bidi_remote: 2_097_152,
        initial_max_stream_data_uni: 2_097_152,
        initial_max_streams_bidi: quic.streams_bidi,
        initial_max_streams_uni: quic.streams_uni,
        max_ack_delay_ms: None,
        active_connection_id_limit: Some(64),
        max_datagram_frame_size: None,
        max_datagram_size: 1200,
        keep_alive_ms: None,
        qpack_max_table_capacity: 16383,
        qpack_blocked_streams: 100,
        max_field_section_size: None,
        extra_transport_parameters: quic
            .private_parameter
            .map(|value| (APPLE_PRIVATE_PARAMETER, vec![value]))
            .into_iter()
            .collect(),
        session_resumption: quic.resumption,
        alt_svc: quic.alt_svc,
        https_rr: if ios { IOS_QUERIES_HTTPS_RECORDS } else { true },
        https_rr_doh_only: false,
    }
}
