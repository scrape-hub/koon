use crate::http2::config::{
    ConnectionPing, HeaderCompression, HeadersPriority, Http2Config, PseudoHeader, SettingId,
    StreamDep, WindowUpdateRule,
};

const CHROMIUM_STREAM_WINDOW: u32 = 6 * 1024 * 1024;

const CHROMIUM_SESSION_WINDOW: u32 = 15 * 1024 * 1024;

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
        no_rfc7540_priorities: None,
        enable_connect_protocol: None,
        initial_stream_id: None,
        headers_priority: Some(HeadersPriority::Chromium),
        initial_stream_window_size: None,
        stream_window_update: Some(chromium_window_update(CHROMIUM_STREAM_WINDOW)),
        connection_window_update: Some(chromium_window_update(CHROMIUM_SESSION_WINDOW)),
        header_compression: Some(HeaderCompression::Chromium),
        write_frames_individually: true,
        write_preface_alone: false,
        write_data_with_headers: false,
        max_header_frame_size: Some(16_383 - 9),
        ping: Some(ConnectionPing::BeforeRequest {
            idle_ms: 10_000,
            timeout_ms: 10_000,
        }),
        goaway_on_close: false,
        close_notify: false,
    }
}
