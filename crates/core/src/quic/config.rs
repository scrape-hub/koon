use serde::{Deserialize, Serialize};

/// QUIC transport and HTTP/3 configuration for browser fingerprinting.
///
/// Controls QUIC transport parameters (RFC 9000) and HTTP/3 settings
/// (RFC 9114) that anti-bot systems use for fingerprinting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    // === QUIC Transport Parameters (RFC 9000) ===
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u16,
    pub ack_delay_exponent: u8,
    pub max_ack_delay_ms: u64,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
    pub grease_quic_bit: bool,

    // === HTTP/3 SETTINGS (RFC 9114) ===
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
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
