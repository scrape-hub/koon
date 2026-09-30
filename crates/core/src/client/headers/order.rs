//! Sort request headers into a client's wire order and finalize casing.

use http::{Method, Uri};

use super::order_tables::{
    CHROMIUM_NAV, CHROMIUM_NETWORK_TAIL, CUSTOM, FIREFOX_CORS, FIREFOX_NAV, OKHTTP,
    OKHTTP_IF_ABSENT, SAFARI_BODY, SAFARI_BODY_SITE_FIRST, SAFARI_CORS_GET, SAFARI_GET,
    SAFARI_HTTP_BODY, SAFARI_HTTP_FORM, SAFARI_HTTP_GET, SAFARI_HTTP_NAVIGATE,
    SAFARI_HTTP_NAVIGATE_REFERER, SAFARI_PREFLIGHT, SAFARI_SONOMA_BODY, SAFARI_SONOMA_GET,
    SAFARI_SONOMA_GET_REFERER, SAFARI_SONOMA_H3_BODY, SAFARI_SONOMA_H3_GET,
    SAFARI_SONOMA_H3_GET_REFERER, SAFARI_SONOMA_LEGACY_BODY, SAFARI_SONOMA_LEGACY_FIRST,
    SAFARI_SONOMA_LEGACY_GET, SAFARI_SONOMA_LEGACY_GET_REFERER,
};
use super::util::{header_value, is_get_or_head};
use super::{AddedHints, Family, HeaderInput, Mode, Protocol};
use crate::client::client_hints;

/// Headers that belong to the connection, not to the request; never sent on HTTP/2 or HTTP/3 (RFC
/// 9113 §8.2.2).
const CONNECTION_SPECIFIC: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// The header order of a Safari request: by the network stack of its profile
/// ([`SafariLayout`](crate::profile::SafariLayout)) and the kind of request, plus (up to macOS
/// 14/iOS 17 only) the header set and protocol: HTTP/3 differs there; macOS 15+ uses the HTTP/2
/// layouts for both, but plain http gets its own layouts only from macOS 15 on.
pub(super) fn safari_order(
    layout: crate::profile::SafariLayout,
    protocol: Protocol,
    method: &Method,
    mode: Mode,
    secure: bool,
    headers: &[(String, String)],
) -> &'static [&'static str] {
    use crate::profile::SafariStack;
    let get = is_get_or_head(method);
    let has = |name: &str| header_value(headers, name).is_some();
    if layout.stack == SafariStack::Sonoma {
        if !layout.fetch_metadata {
            // No fetch metadata at all (macOS 12/13, iOS 16.0/16.1): a different hash order,
            // identical over HTTP/2 and HTTP/3 (this header set never gains a `priority` field, the
            // one thing that changed the order by transport above).
            return match (get, has("referer"), has("cookie")) {
                (false, ..) => SAFARI_SONOMA_LEGACY_BODY,
                (true, true, _) => SAFARI_SONOMA_LEGACY_GET_REFERER,
                (true, false, true) => SAFARI_SONOMA_LEGACY_GET,
                (true, false, false) => SAFARI_SONOMA_LEGACY_FIRST,
            };
        }
        let h3 = protocol == Protocol::Http3;
        return match (get, has("referer"), h3) {
            (false, _, false) => SAFARI_SONOMA_BODY,
            (true, true, false) => SAFARI_SONOMA_GET_REFERER,
            (true, false, false) => SAFARI_SONOMA_GET,
            (false, _, true) => SAFARI_SONOMA_H3_BODY,
            (true, true, true) => SAFARI_SONOMA_H3_GET_REFERER,
            (true, false, true) => SAFARI_SONOMA_H3_GET,
        };
    }
    if !secure {
        return match mode {
            Mode::Navigate if has("referer") => SAFARI_HTTP_NAVIGATE_REFERER,
            Mode::Navigate => SAFARI_HTTP_NAVIGATE,
            Mode::FormNavigate => SAFARI_HTTP_FORM,
            Mode::Cors if get => SAFARI_HTTP_GET,
            Mode::Cors => SAFARI_HTTP_BODY,
        };
    }
    let own_origin = header_value(headers, "sec-fetch-site").is_none_or(|s| s == "same-origin");
    if *method == Method::OPTIONS {
        SAFARI_PREFLIGHT
    } else if get && has("origin") {
        SAFARI_CORS_GET
    } else if get {
        SAFARI_GET
    } else if layout.ios || !own_origin {
        SAFARI_BODY_SITE_FIRST
    } else {
        SAFARI_BODY
    }
}

/// Sort `headers` (stably) into `order`, unlisted ones at [`CUSTOM`]. `headers`' keys are already
/// lowercase (the invariant `build()` establishes), so `order` (itself all lowercase) can be
/// matched directly.
pub(super) fn sort_into(headers: &mut [(String, String)], order: &[&str]) {
    let custom = order
        .iter()
        .position(|k| *k == CUSTOM)
        .unwrap_or(order.len());
    headers.sort_by_cached_key(|(k, _)| {
        order
            .iter()
            .position(|n| *n == k.as_str())
            .unwrap_or(custom)
    });
}

/// Header order per client and request kind; `None` for clients without captured data.
fn canonical_order(family: Family, mode: Mode) -> Option<&'static [&'static str]> {
    match (family, mode) {
        (Family::Chromium, Mode::Navigate | Mode::FormNavigate) => Some(CHROMIUM_NAV),
        (Family::Firefox, Mode::Navigate | Mode::FormNavigate) => Some(FIREFOX_NAV),
        (Family::Firefox, Mode::Cors) => Some(FIREFOX_CORS),
        (Family::OkHttp, _) => Some(OKHTTP),
        _ => None,
    }
}

/// Order the headers like the client. For families without captured data the template order is
/// kept, with content-length first and cookie last. A Chromium `fetch()` or subresource request
/// takes the layout of [`chromium_blink_order`]. `element_cors` marks a Chromium CORS load of an
/// element, whose Origin Blink sets itself in its header map, following `accept`. `restarted` moves
/// every client hint behind `accept`, in Chromium's hint order: a navigation
/// `CriticalClientHintsThrottle` started over carries its other headers first and gets the hints
/// added anew.
pub(super) fn order_headers(
    headers: &mut [(String, String)],
    family: Family,
    mode: Mode,
    caller: &[(String, String)],
    hints: &AddedHints,
    element_cors: bool,
    restarted: bool,
) {
    if family == Family::Chromium && mode == Mode::Cors {
        let order = chromium_blink_order(headers, caller, element_cors);
        let order: Vec<&str> = order.iter().map(String::as_str).collect();
        sort_into(headers, &order);
        return;
    }
    let order = canonical_order(family, mode);
    let custom = order.map(|order| {
        order
            .iter()
            .position(|k| *k == CUSTOM)
            .unwrap_or(order.len())
    });
    // Ranks are doubled so a header can be placed right before another.
    let rank = |lower: &str| -> usize {
        let (Some(order), Some(custom)) = (order, custom) else {
            return match lower {
                "content-length" => 0,
                "cookie" => 4,
                _ => 2,
            };
        };
        let position = |name: &str| order.iter().position(|k| *k == name);
        let caller_owned = family == Family::OkHttp
            && OKHTTP_IF_ABSENT.contains(&lower)
            && header_value(caller, lower).is_some();
        if caller_owned {
            2 * custom
        } else if restarted && client_hints::Hint::from_header(lower).is_some() {
            position("accept").map_or(2 * custom, |p| 2 * p + 1)
        } else if hints.appended.contains(&lower) {
            // Chromium appends the hints of an ACCEPT_CH frame to the request it restarts, after
            // its last header, `accept`.
            position("accept").map_or(2 * custom, |p| 2 * p + 1)
        } else {
            2 * position(lower).unwrap_or(custom)
        }
    };
    // Hints moved behind `accept` keep Chromium's hint order among themselves.
    let hint_order = |lower: &str| -> usize {
        match order {
            Some(order) if restarted && client_hints::Hint::from_header(lower).is_some() => {
                order.iter().position(|k| *k == lower).unwrap_or(0)
            }
            _ => 0,
        }
    };
    // Stable sort: headers sharing a rank (the caller's custom headers, or the template of an
    // unknown family) keep their order. `headers`' keys are already lowercase.
    headers.sort_by_cached_key(|(k, _)| (rank(k), hint_order(k)));
}

/// The layout of a Chromium `fetch()` or subresource request: Content-Length, the headers of
/// Blink's header map in its iteration order (see
/// [`blink_header_map`](crate::client::blink_header_map)), then those of [`CHROMIUM_NETWORK_TAIL`].
/// Blink populates the map in this order, which decides where colliding names land: `fetch()`'s own
/// header list (sorted by name), an element CORS load's Origin, the client hints, the User-Agent.
/// An Accept other than `*/*` counts as `fetch()`'s own when the request is one (no
/// `sec-fetch-dest`, or `empty`); a subresource's goes where Blink appends its default.
fn chromium_blink_order(
    headers: &[(String, String)],
    caller: &[(String, String)],
    element_cors: bool,
) -> Vec<String> {
    // Already lowercase (the invariant `build()` establishes): no need to re-derive the names.
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let fetch =
        header_value(caller, "sec-fetch-dest").is_none_or(|d| d.eq_ignore_ascii_case("empty"));
    let in_map = |name: &str| match name {
        "content-length" => false,
        "origin" => element_cors,
        // `*/*` is the Accept Blink gives fetch() itself: a caller replaying a fetch() passes it,
        // which then goes where Blink appends it.
        "accept" => fetch && header_value(caller, "accept").is_some_and(|a| a.trim() != "*/*"),
        _ => !CHROMIUM_NETWORK_TAIL.contains(&name),
    };
    let is_hint = |name: &str| client_hints::Hint::from_header(name).is_some();
    let mut listed: Vec<&str> = names
        .iter()
        .copied()
        .filter(|&n| {
            in_map(n)
                && n != "origin"
                && n != "user-agent"
                && !is_hint(n)
                && header_value(caller, n).is_some()
        })
        .collect();
    listed.sort_unstable();
    let mut sequence = listed;
    if element_cors && names.contains(&"origin") {
        sequence.push("origin");
    }
    for hint in client_hints::Hint::BLINK_ORDER {
        if names.contains(&hint.header()) {
            sequence.push(hint.header());
        }
    }
    if names.contains(&"user-agent") {
        sequence.push("user-agent");
    }
    // Anything else of the map (a profile's own headers) last.
    for &name in &names {
        if in_map(name) && !sequence.contains(&name) {
            sequence.push(name);
        }
    }
    let mut order = vec!["content-length".to_string()];
    order.extend(
        crate::client::blink_header_map::iteration_order(sequence)
            .into_iter()
            .map(str::to_string),
    );
    order.extend(
        CHROMIUM_NETWORK_TAIL
            .iter()
            .filter(|n| !order.iter().any(|o| o == *n))
            .map(|n| n.to_string())
            .collect::<Vec<_>>(),
    );
    order
}

/// HTTP/1.1: Host (and Connection) first, browser casing. Safari puts Connection last.
/// `custom_casing` names the caller-supplied headers whose casing `build()`'s merge loop couldn't
/// keep in `headers` itself (which holds the lowercase, matching key throughout); everything else
/// here can compare `headers`' keys directly instead of re-lowercasing them.
pub(super) fn finalize_http1(
    family: Family,
    input: &HeaderInput,
    custom_casing: &[(String, String)],
    headers: &mut Vec<(String, String)>,
) {
    if family == Family::Safari {
        let connection = header_value(headers, "connection")
            .unwrap_or("keep-alive")
            .to_string();
        headers.retain(|(k, _)| k != "host" && k != "connection" && k != "proxy-connection");
        let mut out = vec![("host".to_string(), host_header(input.uri))];
        out.extend(input.proxy_headers.unwrap_or(&[]).iter().cloned());
        out.append(headers);
        out.push(("connection".into(), connection));
        *headers = out;
    } else if family != Family::OkHttp {
        let connection_value = header_value(headers, "connection")
            .unwrap_or("keep-alive")
            .to_string();
        headers.retain(|(k, _)| {
            k != "host"
                && k != "proxy-connection"
                // Firefox has a Connection slot of its own (see FIREFOX_NAV).
                && (family == Family::Firefox || k != "connection")
                // Firefox only sends `te: trailers` on HTTP/2 and HTTP/3; Chrome only sends
                // Priority there.
                && !(family == Family::Firefox && k == "te")
                && !(family == Family::Chromium && k == "priority")
        });

        let proxy_headers = input.proxy_headers.unwrap_or(&[]);
        let mut out: Vec<(String, String)> = Vec::with_capacity(headers.len() + 4);
        out.push(("host".into(), host_header(input.uri)));
        if family == Family::Firefox {
            out.extend(proxy_headers.iter().cloned());
        } else {
            // Chromium: Host, Connection (Proxy-Connection when talking to an HTTP proxy directly),
            // Content-Length, proxy authorization, rest.
            let name = if input.proxy_headers.is_some() && family == Family::Chromium {
                "proxy-connection"
            } else {
                "connection"
            };
            out.push((name.into(), connection_value));
            if let Some(pos) = headers.iter().position(|(k, _)| k == "content-length") {
                out.push(headers.remove(pos));
            }
            out.extend(proxy_headers.iter().cloned());
        }
        out.append(headers);
        *headers = out;
    }
    // OkHttp's Host and Connection are part of its order (see `build`). A known browser header
    // (`HTTP1_NAMES`) gets its canonical casing; a caller-supplied one (`custom_casing`) keeps its
    // own; anything else (a client hint) stays lowercase, as it already is.
    for (name, _) in headers.iter_mut() {
        if let Some(&(_, cased)) = HTTP1_NAMES.iter().find(|(lower, _)| lower == name) {
            *name = cased.to_string();
        } else if let Some((_, cased)) = custom_casing
            .iter()
            .find(|(lower, _)| lower.as_str() == name.as_str())
        {
            *name = cased.clone();
        }
    }
}

/// HTTP/2 and HTTP/3: no connection-specific headers. `headers`' keys are already lowercase.
pub(super) fn finalize_multiplexed(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, v)| {
        !CONNECTION_SPECIFIC.contains(&k.as_str())
            && (k != "te" || v.eq_ignore_ascii_case("trailers"))
    });
}

/// Value of the Host header: the authority without userinfo, and without a default port.
pub fn host_header(uri: &Uri) -> String {
    let host = uri.host().unwrap_or("");
    let default_port = match uri.scheme_str() {
        Some("http" | "ws") => 80,
        _ => 443,
    };
    match uri.port_u16() {
        Some(port) if port != default_port => format!("{host}:{port}"),
        _ => host.to_string(),
    }
}

/// HTTP/1.1 casing of the headers the client generates, lowercase -> wire. Browsers and `OkHttp`
/// write these in canonical Title-Case; Client Hints, which Chromium defines in lowercase, and
/// caller-supplied names keep theirs.
const HTTP1_NAMES: &[(&str, &str)] = &[
    ("host", "Host"),
    ("connection", "Connection"),
    ("proxy-connection", "Proxy-Connection"),
    ("content-length", "Content-Length"),
    ("content-type", "Content-Type"),
    ("cache-control", "Cache-Control"),
    ("pragma", "Pragma"),
    ("upgrade-insecure-requests", "Upgrade-Insecure-Requests"),
    ("user-agent", "User-Agent"),
    ("accept", "Accept"),
    ("accept-encoding", "Accept-Encoding"),
    ("accept-language", "Accept-Language"),
    ("origin", "Origin"),
    ("referer", "Referer"),
    ("cookie", "Cookie"),
    ("priority", "Priority"),
    ("te", "TE"),
    ("sec-fetch-site", "Sec-Fetch-Site"),
    ("sec-fetch-mode", "Sec-Fetch-Mode"),
    ("sec-fetch-user", "Sec-Fetch-User"),
    ("sec-fetch-dest", "Sec-Fetch-Dest"),
    ("sec-fetch-storage-access", "Sec-Fetch-Storage-Access"),
    ("sec-gpc", "Sec-GPC"),
];
