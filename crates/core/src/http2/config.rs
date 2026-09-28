use serde::{Deserialize, Serialize};

/// HTTP/2 settings of a profile: what the Akamai HTTP/2 fingerprint and similar checks see.
/// SETTINGS parameters left `None` are not sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http2Config {
    /// SETTINGS_HEADER_TABLE_SIZE.
    pub header_table_size: Option<u32>,

    /// SETTINGS_ENABLE_PUSH.
    pub enable_push: Option<bool>,

    /// SETTINGS_MAX_CONCURRENT_STREAMS.
    pub max_concurrent_streams: Option<u32>,

    /// SETTINGS_INITIAL_WINDOW_SIZE: each stream's initial receive window.
    pub initial_window_size: u32,

    /// SETTINGS_MAX_FRAME_SIZE.
    pub max_frame_size: Option<u32>,

    /// SETTINGS_MAX_HEADER_LIST_SIZE.
    pub max_header_list_size: Option<u32>,

    /// Receive window of the connection (WINDOW_UPDATE on stream 0).
    pub initial_conn_window_size: u32,

    /// Order of the pseudo-header fields in request HEADERS frames.
    pub pseudo_header_order: Vec<PseudoHeader>,

    /// Order of the SETTINGS parameters; unlisted ones follow in ID order.
    pub settings_order: Vec<SettingId>,

    /// Priority block of each request's HEADERS frame; `None` sends none.
    /// [`headers_priority`](Self::headers_priority) replaces it per request.
    pub headers_stream_dependency: Option<StreamDep>,

    /// PRIORITY frames sent before the first request.
    pub priorities: Vec<PriorityFrame>,

    /// SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218).
    pub no_rfc7540_priorities: Option<bool>,

    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441).
    pub enable_connect_protocol: Option<bool>,

    /// ID of the first stream, odd (an even one is ignored); `None` for 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_stream_id: Option<u32>,

    /// Derives each request's HEADERS priority block from the request, as the named browser does.
    /// `None`: every request carries
    /// [`headers_stream_dependency`](Self::headers_stream_dependency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers_priority: Option<HeadersPriority>,

    /// Receive window of each stream: when larger than
    /// [`initial_window_size`](Self::initial_window_size), a WINDOW_UPDATE right after the stream's
    /// HEADERS frame raises it. `None`: `initial_window_size`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_stream_window_size: Option<u32>,

    /// When a stream's receive window is topped up. `None`: once the data consumed reaches half of
    /// the window the server still has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_window_update: Option<WindowUpdateRule>,

    /// When the connection's receive window is topped up. `None`: the same default as for streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_window_update: Option<WindowUpdateRule>,

    /// HPACK encoder to imitate; `None`: the http2 crate's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_compression: Option<HeaderCompression>,

    /// Writes each frame with a write call, and so a TLS record, of its own. The connection preface
    /// shares one with the SETTINGS and the connection WINDOW_UPDATE (unless
    /// [`write_preface_alone`](Self::write_preface_alone)), a HEADERS frame with its CONTINUATION
    /// frames and its stream's WINDOW_UPDATE. `false` (the default) puts all frames queued at a
    /// time into one record.
    #[serde(default)]
    pub write_frames_individually: bool,

    /// With [`write_frames_individually`](Self::write_frames_individually): the connection preface
    /// goes out in a record of its own, and so do the SETTINGS and the connection WINDOW_UPDATE
    /// after it (OkHttp flushes each).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write_preface_alone: bool,

    /// With [`write_frames_individually`](Self::write_frames_individually): the first DATA frame of
    /// a request body shares the record of the request's HEADERS (OkHttp flushes the HEADERS of a
    /// request with a body only with the body).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub write_data_with_headers: bool,

    /// Largest payload of the HEADERS and CONTINUATION frames a request's header block is split
    /// into, when the server allows larger frames. `None`: the server's SETTINGS_MAX_FRAME_SIZE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_header_frame_size: Option<u32>,

    /// When the client sends PING frames. `None`: never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping: Option<ConnectionPing>,

    /// Sends GOAWAY(NO_ERROR) before closing an idle connection. Defaults to `true`.
    #[serde(default = "default_true")]
    pub goaway_on_close: bool,

    /// Sends a TLS close_notify alert before the TCP FIN when closing a connection. Defaults to
    /// `true`.
    #[serde(default = "default_true")]
    pub close_notify: bool,
}

fn default_true() -> bool {
    true
}

/// How each request's HEADERS priority block is derived from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HeadersPriority {
    /// Firefox: non-exclusive on stream 0, weighted by `sec-fetch-dest`: `document` 42, `image` 12,
    /// `font` 32, anything else 22.
    Firefox,
    /// Chromium: exclusive, weighted by the urgency of the request's `priority` header (u=0 256,
    /// u=1 220, u=2 183, u=3 or none 147, u=4 110, u=5 74), on the most recently opened stream
    /// still open among those with the lowest weight not below its own, else on stream 0.
    Chromium,
    /// Safari on macOS 14 and iOS 17: non-exclusive on stream 0, weighted by `sec-fetch-dest`:
    /// `document` 255, `style` and `script` 24, `image` 8; other requests (fetch(), WebSockets)
    /// carry no priority block.
    SafariSonoma,
    /// Safari on macOS 15 and iOS 18: as [`SafariSonoma`](Self::SafariSonoma) with the weights
    /// `document` 256, `style` and `script` 64, `image` 4.
    SafariSequoia,
}

/// When a receive window is topped up with a WINDOW_UPDATE frame, which returns all data consumed
/// since the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowUpdateRule {
    /// Updates once this many bytes were consumed.
    pub threshold: u32,
    /// Also updates once the window the server has is down to this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_window: Option<u32>,
    /// Also updates when data is consumed at least this many milliseconds after the previous update
    /// (or after the window opened).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,
}

/// HPACK encoder that request header blocks follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HeaderCompression {
    /// Firefox's `Http2Compressor`.
    Firefox,
    /// Chromium's (quiche) `HpackEncoder`.
    Chromium,
    /// Safari's (CFNetwork): cookies as never-indexed crumbs, `:path` and `content-length` not
    /// indexed, every other field indexed.
    Safari,
}

/// When the client sends PING frames on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "when", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionPing {
    /// Firefox: after `idle_ms` without reads, a PING with eight zero bytes; the connection closes
    /// when nothing arrives within `timeout_ms`.
    Idle {
        /// Time without reads before the PING, in milliseconds.
        idle_ms: u64,
        /// Time allowed for the reply, in milliseconds.
        timeout_ms: u64,
    },
    /// Chromium: the first request after `idle_ms` without reads is followed by a PING right after
    /// its HEADERS frame, with a counter from 1 as payload; the connection closes when nothing
    /// arrives within `timeout_ms`.
    BeforeRequest {
        /// Time without reads, in milliseconds, before a request brings one.
        idle_ms: u64,
        /// Time allowed for the reply, in milliseconds.
        timeout_ms: u64,
    },
}

/// HTTP/2 pseudo-header field.
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

/// HTTP/2 SETTINGS parameter.
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

/// Priority block of a HEADERS frame (RFC 7540 §5.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDep {
    /// Stream this one depends on.
    pub stream_id: u32,
    /// Weight minus one, as on the wire: 0–255 for weights 1–256.
    pub weight: u8,
    /// Makes the dependency exclusive.
    pub exclusive: bool,
}

/// PRIORITY frame sent once a connection is established. None of the built-in profiles sends them;
/// older Firefox releases did.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityFrame {
    /// Stream the priority applies to; a frame for stream 0 is not sent.
    pub stream_id: u32,
    /// Stream it depends on.
    pub dependency: u32,
    /// Weight minus one, as on the wire: 0–255 for weights 1–256.
    pub weight: u8,
    /// Makes the dependency exclusive.
    pub exclusive: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
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
            initial_stream_id: None,
            headers_priority: None,
            initial_stream_window_size: None,
            stream_window_update: None,
            connection_window_update: None,
            header_compression: None,
            write_frames_individually: false,
            write_preface_alone: false,
            write_data_with_headers: false,
            max_header_frame_size: None,
            ping: None,
            goaway_on_close: true,
            close_notify: true,
        }
    }
}
