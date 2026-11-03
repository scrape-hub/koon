use crate::http2::config::{
    HeaderCompression, HeadersPriority, Http2Config, PseudoHeader, SettingId,
};

use super::{Release, Stack};

pub(super) fn safari_http2(release: Release, ios: bool) -> Http2Config {
    let base = Http2Config {
        enable_push: release.http2_enable_push.then_some(false),
        max_concurrent_streams: Some(100),
        header_compression: Some(HeaderCompression::Safari),
        ..Http2Config::default()
    };
    match release.http {
        Stack::Sonoma => {
            let mut settings_order = Vec::new();
            if release.http2_enable_push {
                settings_order.push(SettingId::EnablePush);
            }
            settings_order.push(SettingId::InitialWindowSize);
            settings_order.push(SettingId::MaxConcurrentStreams);
            Http2Config {
                initial_window_size: if ios { 2_097_152 } else { 4_194_304 },
                initial_conn_window_size: 10_485_760 + 65_535,
                pseudo_header_order: vec![
                    PseudoHeader::Method,
                    PseudoHeader::Scheme,
                    PseudoHeader::Path,
                    PseudoHeader::Authority,
                ],
                settings_order,
                headers_priority: Some(HeadersPriority::SafariSonoma),
                ..base
            }
        }
        Stack::Sequoia | Stack::Tahoe => {
            let mut settings_order = vec![
                SettingId::EnablePush,
                SettingId::MaxConcurrentStreams,
                SettingId::InitialWindowSize,
            ];
            if release.connect_protocol {
                settings_order.push(SettingId::EnableConnectProtocol);
            }
            settings_order.push(SettingId::NoRfc7540Priorities);
            Http2Config {
                initial_window_size: 2_097_152,
                initial_conn_window_size: 10_485_760,
                pseudo_header_order: vec![
                    PseudoHeader::Method,
                    PseudoHeader::Scheme,
                    PseudoHeader::Authority,
                    PseudoHeader::Path,
                ],
                settings_order,
                no_rfc7540_priorities: Some(true),
                enable_connect_protocol: release.connect_protocol.then_some(true),
                headers_priority: (release.http == Stack::Sequoia)
                    .then_some(HeadersPriority::SafariSequoia),
                ..base
            }
        }
    }
}
