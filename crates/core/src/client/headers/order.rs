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

const CONNECTION_SPECIFIC: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "host",
];

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

fn canonical_order(family: Family, mode: Mode) -> Option<&'static [&'static str]> {
    match (family, mode) {
        (Family::Chromium, Mode::Navigate | Mode::FormNavigate) => Some(CHROMIUM_NAV),
        (Family::Firefox, Mode::Navigate | Mode::FormNavigate) => Some(FIREFOX_NAV),
        (Family::Firefox, Mode::Cors) => Some(FIREFOX_CORS),
        (Family::OkHttp, _) => Some(OKHTTP),
        _ => None,
    }
}

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
            position("accept").map_or(2 * custom, |p| 2 * p + 1)
        } else {
            2 * position(lower).unwrap_or(custom)
        }
    };
    let hint_order = |lower: &str| -> usize {
        match order {
            Some(order) if restarted && client_hints::Hint::from_header(lower).is_some() => {
                order.iter().position(|k| *k == lower).unwrap_or(0)
            }
            _ => 0,
        }
    };
    headers.sort_by_cached_key(|(k, _)| (rank(k), hint_order(k)));
}

fn chromium_blink_order(
    headers: &[(String, String)],
    caller: &[(String, String)],
    element_cors: bool,
) -> Vec<String> {
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let fetch =
        header_value(caller, "sec-fetch-dest").is_none_or(|d| d.eq_ignore_ascii_case("empty"));
    let in_map = |name: &str| match name {
        "content-length" => false,
        "origin" => element_cors,
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
                && (family == Family::Firefox || k != "connection")
                && !(family == Family::Firefox && k == "te")
                && !(family == Family::Chromium && k == "priority")
        });

        let proxy_headers = input.proxy_headers.unwrap_or(&[]);
        let mut out: Vec<(String, String)> = Vec::with_capacity(headers.len() + 4);
        out.push(("host".into(), host_header(input.uri)));
        if family == Family::Firefox {
            out.extend(proxy_headers.iter().cloned());
        } else {
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

pub(super) fn finalize_multiplexed(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, v)| {
        !CONNECTION_SPECIFIC.contains(&k.as_str())
            && (k != "te" || v.eq_ignore_ascii_case("trailers"))
    });
}

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
