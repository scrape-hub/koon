//! WebSocket handshake header construction.

use http::Uri;

use super::Family;
use super::fetch_metadata::{
    compute_fetch_site, insecure_accept_encoding, is_potentially_trustworthy, serialized_origin,
};
use super::order::host_header;
use super::util::{cookie_header, header_value, merge_caller_headers};
use crate::profile::BrowserProfile;

/// Headers of a WebSocket upgrade request, in the client's order. `ws_uri` is the socket URL,
/// `http_uri` its http(s) equivalent, used for Origin and fetch metadata. Caller headers replace
/// handshake headers of the same name in place; others are appended.
///
/// `Sec-WebSocket-Extensions: permessage-deflate` is not offered: the frame codec cannot
/// decompress, and a server accepting it would send frames koon then rejects.
pub fn build_websocket(
    profile: &BrowserProfile,
    ws_uri: &Uri,
    http_uri: &Uri,
    key: &str,
    cookie: Option<&str>,
    client_headers: &[(String, String)],
    request_headers: &[(String, String)],
) -> Vec<(String, String)> {
    let family = Family::of(profile);
    let secure = is_potentially_trustworthy(ws_uri);
    let caller = merge_caller_headers(client_headers, request_headers);
    let profile_value = |name: &str| {
        header_value(&profile.headers, name)
            .unwrap_or("")
            .to_string()
    };
    let accept_encoding = match insecure_accept_encoding(family) {
        Some(encoding) if !secure => encoding.to_string(),
        _ => profile_value("accept-encoding"),
    };
    let origin = header_value(&caller, "origin")
        .map(str::to_string)
        .unwrap_or_else(|| serialized_origin(http_uri));
    let cookie = cookie_header(client_headers, request_headers, cookie);

    let mut h: Vec<(String, String)> = Vec::with_capacity(18);
    let mut push = |name: &str, value: String| h.push((name.to_string(), value));
    match family {
        Family::Firefox => {
            push("Host", host_header(ws_uri));
            push("User-Agent", profile_value("user-agent"));
            push("Accept", "*/*".into());
            push("Accept-Language", profile_value("accept-language"));
            push("Accept-Encoding", accept_encoding);
            push("Sec-WebSocket-Version", "13".into());
            push("Origin", origin.clone());
            push("Sec-WebSocket-Key", key.into());
            push("Connection", "Upgrade".into());
            if let Some(c) = cookie {
                push("Cookie", c);
            }
            if secure {
                push("Sec-Fetch-Dest", "empty".into());
                push("Sec-Fetch-Mode", "websocket".into());
                push(
                    "Sec-Fetch-Site",
                    compute_fetch_site(http_uri, &origin).into(),
                );
            }
            push("Pragma", "no-cache".into());
            push("Cache-Control", "no-cache".into());
            push("Upgrade", "websocket".into());
        }
        Family::OkHttp => {
            // RealWebSocket.connect() sets the upgrade headers after the application's,
            // BridgeInterceptor adds the rest (OkHttp 5.5.0). No Origin unless the application sets
            // one.
            push("Upgrade", "websocket".into());
            push("Connection", "Upgrade".into());
            push("Sec-WebSocket-Key", key.into());
            push("Sec-WebSocket-Version", "13".into());
            push("Host", host_header(ws_uri));
            push("Accept-Encoding", accept_encoding);
            if let Some(c) = cookie {
                push("Cookie", c);
            }
            push("User-Agent", profile_value("user-agent"));
        }
        Family::Safari => {
            let layout = crate::profile::SafariLayout::of(profile);
            let protocol = header_value(&caller, "sec-websocket-protocol").map(str::to_string);
            // macOS 14 offers no Brotli in the upgrade (captured).
            let accept_encoding = match layout.stack {
                crate::profile::SafariStack::Sonoma => "gzip, deflate".to_string(),
                _ => accept_encoding,
            };
            for &name in
                safari_websocket_order(layout.stack, layout.fetch_metadata, protocol.is_some())
            {
                let value = match name {
                    "Host" => host_header(ws_uri),
                    "Origin" => origin.clone(),
                    "Pragma" | "Cache-Control" => "no-cache".into(),
                    "Accept" => "*/*".into(),
                    "Accept-Language" => profile_value("accept-language"),
                    "Accept-Encoding" => accept_encoding.clone(),
                    "User-Agent" => profile_value("user-agent"),
                    "Sec-WebSocket-Key" => key.into(),
                    "Sec-WebSocket-Version" => "13".into(),
                    "Connection" => "Upgrade".into(),
                    "Upgrade" => "websocket".into(),
                    "Priority" => "u=3, i".into(),
                    "Sec-Fetch-Site" if secure => compute_fetch_site(http_uri, &origin).into(),
                    "Sec-Fetch-Mode" | "Sec-Fetch-Dest" if secure => "websocket".into(),
                    "Sec-WebSocket-Protocol" => match &protocol {
                        Some(protocol) => protocol.clone(),
                        None => continue,
                    },
                    "Cookie" => match &cookie {
                        Some(cookie) => cookie.clone(),
                        None => continue,
                    },
                    _ => continue,
                };
                push(name, value);
            }
        }
        _ => {
            push("Host", host_header(ws_uri));
            push("Connection", "Upgrade".into());
            push("Pragma", "no-cache".into());
            push("Cache-Control", "no-cache".into());
            push("User-Agent", profile_value("user-agent"));
            push("Upgrade", "websocket".into());
            push("Origin", origin);
            push("Sec-WebSocket-Version", "13".into());
            push("Accept-Encoding", accept_encoding);
            push("Accept-Language", profile_value("accept-language"));
            if let Some(c) = cookie {
                push("Cookie", c);
            }
            push("Sec-WebSocket-Key", key.into());
        }
    }

    // The handshake's own protocol headers can't be overridden.
    const FIXED: &[&str] = &[
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "cookie",
    ];
    let caller = caller.into_iter().filter(|(name, _)| {
        let lower = name.to_ascii_lowercase();
        // A browser's Origin already has its slot.
        !FIXED.contains(&lower.as_str()) && (family == Family::OkHttp || lower != "origin")
    });
    if family == Family::OkHttp {
        // The application's headers come first; those it sets replace the ones OkHttp would add.
        let caller: Vec<(String, String)> = caller.collect();
        h.retain(|(k, _)| header_value(&caller, k).is_none());
        return caller.into_iter().chain(h).collect();
    }
    for (name, value) in caller {
        match h.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&name)) {
            Some(slot) => slot.1 = value,
            // Firefox sets the subprotocols right after Origin
            // (`WebSocketChannel::AsyncOpenNative`); Chromium appends them.
            None if family == Family::Firefox
                && name.eq_ignore_ascii_case("sec-websocket-protocol") =>
            {
                let origin = h
                    .iter()
                    .position(|(k, _)| k.eq_ignore_ascii_case("origin"))
                    .map_or(h.len(), |i| i + 1);
                h.insert(origin, (name, value));
            }
            None => h.push((name, value)),
        }
    }
    h
}

/// Headers of a WebSocket's extended CONNECT over HTTP/2 (RFC 8441): those of the HTTP/1.1
/// handshake, lowercase, without Host, Connection, Upgrade and `Sec-WebSocket-Key` (Firefox also
/// drops `te`).
pub fn build_websocket_h2(
    profile: &BrowserProfile,
    ws_uri: &Uri,
    http_uri: &Uri,
    cookie: Option<&str>,
    client_headers: &[(String, String)],
    request_headers: &[(String, String)],
) -> Vec<(String, String)> {
    const DROPPED: &[&str] = &[
        "host",
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "te",
        "sec-websocket-key",
    ];
    build_websocket(
        profile,
        ws_uri,
        http_uri,
        "",
        cookie,
        client_headers,
        request_headers,
    )
    .into_iter()
    .map(|(name, value)| (name.to_ascii_lowercase(), value))
    .filter(|(name, _)| !DROPPED.contains(&name.as_str()))
    .collect()
}

/// Safari's WebSocket upgrade order, without the `Sec-WebSocket-Extensions` koon does not offer. Up
/// to macOS 15 it is a hash order that a subprotocol changes; from macOS 26 on the extended CONNECT
/// over HTTP/2 has the same order without Host, the key, Connection and Upgrade. Before fetch
/// metadata (macOS 12/13, iOS 16.0/16.1, `fetch_metadata: false`) the handshake carries no
/// `Sec-Fetch-*` at all and the remaining headers hash to their own order: captured from macOS
/// 12.6 (real Safari 16.0) and the iOS 16.0 simulator.
fn safari_websocket_order(
    stack: crate::profile::SafariStack,
    fetch_metadata: bool,
    protocol: bool,
) -> &'static [&'static str] {
    use crate::profile::SafariStack;
    if stack == SafariStack::Sonoma && !fetch_metadata {
        return if protocol {
            &[
                "Host",
                "Pragma",
                "Accept",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Version",
                "Sec-WebSocket-Protocol",
                "Cache-Control",
                "Accept-Language",
                "Origin",
                "User-Agent",
                "Connection",
                "Accept-Encoding",
                "Upgrade",
                "Cookie",
            ]
        } else {
            &[
                "Host",
                "Pragma",
                "Accept",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Version",
                "Accept-Language",
                "Cache-Control",
                "Accept-Encoding",
                "Origin",
                "User-Agent",
                "Connection",
                "Upgrade",
                "Cookie",
            ]
        };
    }
    match (stack, protocol) {
        (SafariStack::Sonoma, false) => &[
            "Host",
            "Pragma",
            "Accept",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Cache-Control",
            "Sec-Fetch-Mode",
            "Accept-Language",
            "Origin",
            "User-Agent",
            "Connection",
            "Accept-Encoding",
            "Upgrade",
            "Sec-Fetch-Dest",
            "Cookie",
        ],
        (SafariStack::Sonoma, true) => &[
            "Host",
            "Pragma",
            "Accept",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-Fetch-Mode",
            "Cache-Control",
            "Origin",
            "User-Agent",
            "Connection",
            "Accept-Language",
            "Accept-Encoding",
            "Upgrade",
            "Sec-Fetch-Dest",
            "Cookie",
        ],
        (SafariStack::Sequoia, false) => &[
            "Host",
            "Upgrade",
            "Pragma",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Cache-Control",
            "Sec-Fetch-Mode",
            "Origin",
            "User-Agent",
            "Connection",
            "Sec-Fetch-Dest",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
        ],
        (SafariStack::Sequoia, true) => &[
            "Host",
            "Upgrade",
            "Pragma",
            "Sec-WebSocket-Key",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-Fetch-Mode",
            "Cache-Control",
            "Origin",
            "User-Agent",
            "Connection",
            "Sec-Fetch-Dest",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
        ],
        (SafariStack::Tahoe, _) => &[
            "Host",
            "Origin",
            "Pragma",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Version",
            "Sec-Fetch-Mode",
            "User-Agent",
            "Cache-Control",
            "Sec-Fetch-Dest",
            "Accept",
            "Accept-Language",
            "Priority",
            "Accept-Encoding",
            "Cookie",
            "Sec-WebSocket-Key",
            "Connection",
            "Upgrade",
        ],
    }
}
