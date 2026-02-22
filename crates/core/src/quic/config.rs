use serde::{Deserialize, Serialize};

/// QUIC transport and HTTP/3 configuration for browser fingerprinting.
///
/// Controls QUIC transport parameters (RFC 9000) and HTTP/3 settings
/// (RFC 9114) that anti-bot systems use for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    // === QUIC Transport Parameters (RFC 9000) ===

    /// Connection-level flow control limit.
    pub initial_max_data: u64,
    /// Stream-level flow control limit for locally-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Stream-level flow control limit for remotely-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Stream-level flow control limit for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Maximum number of bidirectional streams the peer may initiate.
    pub initial_max_streams_bidi: u64,
    /// Maximum number of unidirectional streams the peer may initiate.
    pub initial_max_streams_uni: u64,
    /// Idle timeout in milliseconds.
    pub max_idle_timeout_ms: u64,
    /// Maximum UDP payload size (typically 1350).
    pub max_udp_payload_size: u16,
    /// ACK delay exponent for decoding ACK frames.
    pub ack_delay_exponent: u8,
    /// Maximum ACK delay in milliseconds.
    pub max_ack_delay_ms: u64,
    /// Maximum number of connection IDs the peer may store.
    pub active_connection_id_limit: u64,
    /// Disable active connection migration.
    pub disable_active_migration: bool,
    /// Randomly set the QUIC bit (greasing).
    pub grease_quic_bit: bool,

    // === HTTP/3 SETTINGS (RFC 9114) ===

    /// QPACK dynamic table capacity.
    pub qpack_max_table_capacity: u64,
    /// Maximum number of streams that can be blocked on QPACK.
    pub qpack_blocked_streams: u64,
    /// Maximum size of a header field section.
    pub max_field_section_size: Option<u64>,
}

impl Default for QuicConfig {
    fn default() -> Self {
        // Generic defaults (Chrome-ish)
        QuicConfig {
            initial_max_data: 15728640,
            initial_max_stream_data_bidi_local: 6291456,
            initial_max_stream_data_bidi_remote: 6291456,
            initial_max_stream_data_uni: 6291456,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_idle_timeout_ms: 30000,
            max_udp_payload_size: 1350,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            active_connection_id_limit: 4,
            disable_active_migration: true,
            grease_quic_bit: true,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: None,
        }
    }
}
