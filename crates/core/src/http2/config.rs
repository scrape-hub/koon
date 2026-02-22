use serde::{Deserialize, Serialize};

/// HTTP/2 fingerprint configuration.
///
/// Controls the HTTP/2 connection-level parameters that anti-bot systems
/// use for fingerprinting (Akamai H2 fingerprint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    /// SETTINGS: HEADER_TABLE_SIZE
    pub header_table_size: Option<u32>,

    /// SETTINGS: ENABLE_PUSH
    pub enable_push: Option<bool>,

    /// SETTINGS: MAX_CONCURRENT_STREAMS
    pub max_concurrent_streams: Option<u32>,

    /// SETTINGS: INITIAL_WINDOW_SIZE (stream-level)
    pub initial_window_size: u32,

    /// SETTINGS: MAX_FRAME_SIZE
    pub max_frame_size: Option<u32>,

    /// SETTINGS: MAX_HEADER_LIST_SIZE
    pub max_header_list_size: Option<u32>,

    /// Connection-level initial window size (WINDOW_UPDATE on stream 0).
    pub initial_conn_window_size: u32,

    /// Pseudo-header order: e.g. [:method, :authority, :scheme, :path] for Chrome.
    pub pseudo_header_order: Vec<PseudoHeader>,

    /// Settings frame parameter order.
    pub settings_order: Vec<SettingId>,

    /// Stream dependency for HEADERS frame.
    pub headers_stream_dependency: Option<StreamDep>,

    /// PRIORITY frames to send after connection establishment.
    pub priorities: Vec<PriorityFrame>,

    /// Disable RFC 7540 priorities (Chrome 131+).
    pub no_rfc7540_priorities: Option<bool>,

    /// Enable CONNECT protocol.
    pub enable_connect_protocol: Option<bool>,
}

/// HTTP/2 pseudo-header field.
///
/// The order of pseudo-headers in the HEADERS frame is part of the
/// Akamai HTTP/2 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PseudoHeader {
    /// `:method`
    Method,
    /// `:authority`
    Authority,
    /// `:scheme`
    Scheme,
    /// `:path`
    Path,
    /// `:status` (response only).
    Status,
    /// `:protocol` (extended CONNECT).
    Protocol,
}

/// HTTP/2 SETTINGS parameter identifier.
///
/// The order in which settings are sent is part of the Akamai fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingId {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1).
    HeaderTableSize,
    /// SETTINGS_ENABLE_PUSH (0x2).
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3).
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4).
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (0x5).
    MaxFrameSize,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6).
    MaxHeaderListSize,
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8).
    EnableConnectProtocol,
    /// SETTINGS_NO_RFC7540_PRIORITIES (0x9).
    NoRfc7540Priorities,
}

/// Stream dependency for the HEADERS frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamDep {
    /// The stream ID this stream depends on.
    pub stream_id: u32,
    /// Weight (1–256).
    pub weight: u8,
    /// Exclusive dependency flag.
    pub exclusive: bool,
}

/// An HTTP/2 PRIORITY frame sent after connection establishment.
///
/// Firefox uses these to build a priority tree. Chrome does not send them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityFrame {
    /// The stream ID this priority applies to.
    pub stream_id: u32,
    /// The stream ID this stream depends on.
    pub dependency: u32,
    /// Weight (1–256).
    pub weight: u8,
    /// Exclusive dependency flag.
    pub exclusive: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Http2Config {
            header_table_size: None,
            enable_push: None,
            max_concurrent_streams: None,
            initial_window_size: 65535,
            max_frame_size: None,
            max_header_list_size: None,
            initial_conn_window_size: 65535,
            pseudo_header_order: vec![
                PseudoHeader::Method,
                PseudoHeader::Authority,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
            ],
            settings_order: Vec::new(),
            headers_stream_dependency: None,
            priorities: Vec::new(),
            no_rfc7540_priorities: None,
            enable_connect_protocol: None,
        }
    }
}
