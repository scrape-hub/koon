//! The QUIC and HTTP/3 fingerprint of a browser profile.
//!
//! [`QuicStack`] selects the wire behaviour (packet numbers, padding, transport parameter order,
//! SETTINGS layout, …), which `quic::transport` derives from it; this module holds only the numbers
//! a profile sends on top of that. koon's forks of quinn, quinn-btls and h3 apply all of it.

use serde::{Deserialize, Serialize};

use crate::tls::config::TlsConfig;

/// QUIC and HTTP/3 fingerprint of a profile. A profile without one does not use HTTP/3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    /// The QUIC and HTTP/3 stack whose wire behaviour the connections reproduce.
    pub stack: QuicStack,

    /// Offers QUIC version 2 (RFC 9369) besides version 1 in version_information, and follows a
    /// server that switches to it (RFC 9368). Only the Neqo stack does, from Firefox 155 on; the
    /// other stacks speak version 1 whatever this says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quic_v2: bool,

    /// Sends the empty reset_stream_at transport parameter (0x1d,
    /// draft-ietf-quic-reliable-stream-reset). Only the Neqo stack does, from Firefox 155 on
    /// (neqo's `reliable_stream_reset`, on by default); the other stacks never send it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_stream_at: bool,

    /// The TLS ClientHello inside QUIC, which browsers configure apart from their TCP one (Chrome
    /// sends no GREASE and other signature algorithms in QUIC, Firefox permutes its extensions).
    /// `None` uses the profile's TCP [`tls`](crate::profile::BrowserProfile::tls). Either way ALPN
    /// is `h3` and only TLS 1.3 is offered; `alpn`, `min_version`, `max_version` and the TLS 1.2
    /// part of `cipher_list` do not apply, and `alps` announces `h3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    // Transport parameters (RFC 9000 §18). `None` omits one; a value equal to the RFC default is
    // not sent either.
    /// max_idle_timeout (0x01), milliseconds; also the connection's idle timeout.
    pub max_idle_timeout_ms: u64,
    /// max_udp_payload_size (0x03). Independent of the size of the datagrams the client sends (see
    /// [`max_datagram_size`](Self::max_datagram_size)).
    #[serde(default)]
    pub max_udp_payload_size: Option<u64>,
    /// initial_max_data (0x04).
    pub initial_max_data: u64,
    /// initial_max_stream_data_bidi_local (0x05): the receive window of requests.
    pub initial_max_stream_data_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote (0x06).
    pub initial_max_stream_data_bidi_remote: u64,
    /// initial_max_stream_data_uni (0x07).
    pub initial_max_stream_data_uni: u64,
    /// initial_max_streams_bidi (0x08).
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni (0x09).
    pub initial_max_streams_uni: u64,
    /// max_ack_delay (0x0b), milliseconds; also the client's own ACK delay. `None` is the RFC
    /// default of 25 ms.
    #[serde(default)]
    pub max_ack_delay_ms: Option<u64>,
    /// active_connection_id_limit (0x0e): how many connection IDs of the server the client stores.
    /// Not sent by the Chromium stack, whose own connection IDs are empty. `None` is quinn's 5.
    #[serde(default)]
    pub active_connection_id_limit: Option<u64>,
    /// max_datagram_frame_size (0x20, RFC 9221).
    #[serde(default)]
    pub max_datagram_frame_size: Option<u64>,

    /// Size of the Initial datagrams, and of every datagram: the stacks do no path MTU discovery.
    /// Browsers stay at 1250 (Chrome) or 1252 (Firefox) bytes, which fits paths whose MTU is well
    /// below Ethernet's.
    pub max_datagram_size: u16,
    /// Interval of the PINGs that keep a connection with a request in progress alive, milliseconds;
    /// `None` sends none. Like the browsers, the stacks let a connection without requests end
    /// silently at its idle timeout.
    pub keep_alive_ms: Option<u64>,

    // HTTP/3 SETTINGS values. The stack decides which other settings it sends and in which order.
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): the client's QPACK decoder table. 0 is not sent.
    pub qpack_max_table_capacity: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07). 0 is not sent.
    pub qpack_blocked_streams: u64,
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06); `None` is not sent.
    #[serde(default)]
    pub max_field_section_size: Option<u64>,

    /// Transport parameters the stack does not write itself, `(id, value)` with the value as sent,
    /// after the stack's own ones: Safari's private `0xff080808` (macOS 15.4 to 26.3, iOS 18.4 to
    /// 26.3.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_transport_parameters: Vec<(u64, Vec<u8>)>,
    /// Offers the TLS session of an earlier connection to the server, with 0-RTT data where its
    /// ticket allows; also needs the client's session resumption. Safari before macOS and iOS 26
    /// offers none.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub session_resumption: bool,
    /// Switches to HTTP/3 when a server advertises it with Alt-Svc. Safari on macOS 15.1 and 15.2
    /// and iOS 18.0 to 18.2 ignores Alt-Svc entirely.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub alt_svc: bool,

    /// Queries the host's DNS HTTPS record before the first connection and, when its `alpn`
    /// includes `h3`, treats that like an Alt-Svc advertisement already on that connection.
    /// Independent of [`alt_svc`](Self::alt_svc): Safari on macOS 15.1/15.2 has this on and
    /// `alt_svc` off, reaching HTTP/3 only this way. Needs a
    /// [`DohResolver`](crate::dns::DohResolver) or the native resolver to reach the record.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub https_rr: bool,

    /// Queries the HTTPS record only over DNS-over-HTTPS, never the system resolver (Firefox up to
    /// 150 on macOS). No effect without [`https_rr`](Self::https_rr).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub https_rr_doh_only: bool,
}

fn enabled() -> bool {
    true
}

fn is_enabled(value: &bool) -> bool {
    *value
}

/// A browser's QUIC and HTTP/3 implementation. See `quic::transport` for everything it decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicStack {
    /// quiche in Chromium's network stack: Chrome, Edge, Opera. A connection the pool lets go of is
    /// discarded without sending anything, as Chromium tears down a session silently; the server
    /// notices at its idle timeout. At shutdown every connection is closed with NO_ERROR and
    /// "70:net error".
    Chromium,
    /// neqo: Firefox. A connection it gives up, or has at shutdown, is closed with H3_NO_ERROR.
    Neqo,
    /// Apple's QUIC and HTTP/3 stack: Safari from macOS 14 and iOS 17 on. A connection the pool
    /// lets go of ends at its idle timeout; at shutdown every connection is closed with
    /// H3_NO_ERROR.
    Apple,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_of_koon_0_8_is_rejected() {
        let json = r#"{
            "initial_max_data": 12582912,
            "initial_max_stream_data_bidi_local": 1048576,
            "initial_max_stream_data_bidi_remote": 1048576,
            "initial_max_stream_data_uni": 1048576,
            "initial_max_streams_bidi": 16,
            "initial_max_streams_uni": 16,
            "max_idle_timeout_ms": 30000,
            "max_udp_payload_size": 1472,
            "ack_delay_exponent": 3,
            "max_ack_delay_ms": 25,
            "active_connection_id_limit": 2,
            "disable_active_migration": false,
            "grease_quic_bit": false,
            "qpack_max_table_capacity": 0,
            "qpack_blocked_streams": 0,
            "max_field_section_size": null
        }"#;
        let err = serde_json::from_str::<QuicConfig>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `ack_delay_exponent`"),
            "{err}"
        );
    }

    #[test]
    fn roundtrips() {
        let config = crate::profile::Firefox::latest().quic.unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""stack":"neqo""#), "{json}");
        let back: QuicConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }
}
