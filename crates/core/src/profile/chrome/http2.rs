//! Chromium-family HTTP/2 fingerprint (Chrome, Edge, Opera and derived browsers).
//!
//! Same Akamai fingerprint hash across Chrome 131-145. Frame-level behaviour captured from Chrome
//! 153 and read from Chromium's net/spdy and quiche's HPACK encoder.

use crate::http2::config::{
    ConnectionPing, HeaderCompression, HeadersPriority, Http2Config, PseudoHeader, SettingId,
    StreamDep, WindowUpdateRule,
};

/// Stream receive window (`kSpdyStreamMaxRecvWindowSize`, 6 MB).
const CHROMIUM_STREAM_WINDOW: u32 = 6 * 1024 * 1024;

/// Connection receive window (`kSpdySessionMaxRecvWindowSize`, 15 MB).
const CHROMIUM_SESSION_WINDOW: u32 = 15 * 1024 * 1024;

/// Chromium returns consumed data once more than half of a window is unacknowledged, or when data
/// is consumed 5 s (`kDefaultTimeToBufferSmallWindowUpdates`) after the last update
/// (`SpdyStream::IncreaseRecvWindowSize`, `SpdySession::IncreaseRecvWindowSize`).
const fn chromium_window_update(window: u32) -> WindowUpdateRule {
    WindowUpdateRule {
        threshold: window / 2 + 1,
        low_window: None,
        interval_ms: Some(5_000),
    }
}

pub fn chrome_http2() -> Http2Config {
    Http2Config {
        header_table_size: Some(65536),
        enable_push: Some(false),
        max_concurrent_streams: None,
        initial_window_size: 6_291_456,
        max_frame_size: None,
        max_header_list_size: Some(262_144),
        initial_conn_window_size: 15_728_640,
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ],
        settings_order: vec![
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
        ],
        headers_stream_dependency: Some(StreamDep {
            stream_id: 0,
            weight: 255,
            exclusive: true,
        }),
        priorities: Vec::new(),
        // Chrome sends no_rfc7540_priorities via ALPS; its SETTINGS carry only 1, 2, 4 and 6.
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
        initial_stream_id: None,
        // Weight from the request's priority (256/220/183/147 for u=0/1/2/3), dependency chained to
        // the open streams.
        headers_priority: Some(HeadersPriority::Chromium),
        initial_stream_window_size: None,
        stream_window_update: Some(chromium_window_update(CHROMIUM_STREAM_WINDOW)),
        connection_window_update: Some(chromium_window_update(CHROMIUM_SESSION_WINDOW)),
        header_compression: Some(HeaderCompression::Chromium),
        // One TLS record per frame after [preface, SETTINGS, WINDOW_UPDATE].
        write_frames_individually: true,
        write_preface_alone: false,
        write_data_with_headers: false,
        // quiche's SpdyFramer caps HEADERS and CONTINUATION frames at
        // `kHttp2MaxControlFrameSendSize` (16383 bytes with the 9-byte frame header), whatever the
        // server allows.
        max_header_frame_size: Some(16_383 - 9),
        // `SpdySession::MaybeSendPrefacePing`: a PING (id from 1) with the first HEADERS after
        // `kSpdyDefaultConnectionAtRiskOfLossSeconds` (10 s) without reads; `kHungIntervalSeconds`
        // (10 s) for the answer.
        ping: Some(ConnectionPing::BeforeRequest {
            idle_ms: 10_000,
            timeout_ms: 10_000,
        }),
        // "Don't GOAWAY on a graceful or idle close" (`DoDrainSession`), and no TLS close_notify: a
        // plain FIN.
        goaway_on_close: false,
        close_notify: false,
    }
}
