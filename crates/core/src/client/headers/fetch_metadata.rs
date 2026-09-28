//! Fetch metadata, navigation detection and origin/site comparisons.

use http::{Method, Uri};

use super::order::host_header;
use super::util::{header_value, is_get_or_head, merge_caller_headers, remove, set};
use super::{Family, Mode};

/// The kind of request a browser would make with this method and these caller headers.
pub(super) fn detect_mode(
    method: &Method,
    origin: Option<&str>,
    content_type: Option<&str>,
    accept: Option<&str>,
) -> Mode {
    let ct = content_type.unwrap_or("").trim().to_ascii_lowercase();
    if !is_get_or_head(method) {
        // An HTML form submits with POST and a form encoding; any other unsafe method comes from
        // fetch().
        let form = ct.starts_with("application/x-www-form-urlencoded")
            || ct.starts_with("multipart/form-data");
        return if form && *method == Method::POST {
            Mode::FormNavigate
        } else {
            Mode::Cors
        };
    }
    // A navigation carries the browser's own Accept (lists text/html); any other Accept, a
    // Content-Type or an Origin mark a fetch().
    let navigation_accept = accept.is_none_or(|a| a.to_ascii_lowercase().contains("text/html"));
    if !ct.is_empty() || origin.is_some() || !navigation_accept {
        Mode::Cors
    } else {
        Mode::Navigate
    }
}

/// Whether [`build`](super::build) builds a navigation for this method and these client- and
/// request-level headers: `sec-fetch-mode` set by the caller decides, else [`detect_mode`].
pub fn builds_navigation(
    method: &Method,
    client: &[(String, String)],
    request: &[(String, String)],
) -> bool {
    let caller = merge_caller_headers(client, request);
    match header_value(&caller, "sec-fetch-mode") {
        Some(mode) => mode.eq_ignore_ascii_case("navigate"),
        None => is_navigation(method, &caller),
    }
}

/// Whether a request with this method and these caller headers is built as a navigation (see
/// [`detect_mode`]).
pub fn is_navigation(method: &Method, headers: &[(String, String)]) -> bool {
    matches!(
        detect_mode(
            method,
            header_value(headers, "origin"),
            header_value(headers, "content-type"),
            header_value(headers, "accept"),
        ),
        Mode::Navigate | Mode::FormNavigate
    )
}

/// Adapt the navigation template's fetch metadata to the request. `initiator` is the origin of the
/// page the request comes from, if any: the browser derives `sec-fetch-site` from it. `dest` is the
/// caller's `sec-fetch-dest`, which sets a subresource's priority.
pub(super) fn apply_mode(
    headers: &mut Vec<(String, String)>,
    family: Family,
    mode: Mode,
    uri: &Uri,
    initiator: Option<&str>,
    caller_sets_accept: bool,
    dest: Option<&str>,
) {
    if let Some(initiator) = initiator {
        set(
            headers,
            "sec-fetch-site",
            compute_fetch_site(uri, initiator),
        );
    }
    match mode {
        Mode::Navigate => {}
        Mode::FormNavigate => {
            // Chrome revalidates on form submissions.
            if family == Family::Chromium && !headers.iter().any(|(k, _)| k == "cache-control") {
                headers.push(("cache-control".into(), "max-age=0".into()));
            }
        }
        Mode::Cors => {
            set(headers, "sec-fetch-mode", "cors");
            set(headers, "sec-fetch-dest", "empty");
            if initiator.is_none() {
                set(headers, "sec-fetch-site", "same-origin");
            }
            remove(headers, "sec-fetch-user");
            remove(headers, "upgrade-insecure-requests");
            if !caller_sets_accept {
                set(headers, "accept", "*/*");
            }
            match subresource_priority(family, dest) {
                Some(priority) => set(headers, "priority", priority),
                None => remove(headers, "priority"),
            }
        }
    }
}

/// The `priority` header of a request that is not a navigation, by its destination; `None` for
/// none. Each browser has its own urgency mapping (Chrome 153, Firefox 156, Safari from macOS
/// 15/iOS 18, and over HTTP/3 from macOS 14/iOS 17); see the match arms for the exact values.
pub(super) fn subresource_priority(family: Family, dest: Option<&str>) -> Option<&'static str> {
    match family {
        Family::Safari => match dest {
            Some("style" | "script") => Some("u=1, i"),
            Some("image") => Some("u=5, i"),
            _ => Some("u=3, i"),
        },
        Family::Firefox => match dest {
            Some("style") => Some("u=2"),
            Some("image") => Some("u=5, i"),
            Some("script" | "font") => None,
            _ => Some("u=4"),
        },
        Family::Chromium => match dest {
            Some("style" | "font") => Some("u=0"),
            Some("script") => Some("u=1"),
            Some("image") => Some("i"),
            _ => Some("u=1, i"),
        },
        _ => Some("u=1, i"),
    }
}

/// Accept-Encoding of a browser outside a secure context, where it does not advertise Brotli or
/// Zstandard. `None` for other clients.
pub(super) fn insecure_accept_encoding(family: Family) -> Option<&'static str> {
    matches!(family, Family::Chromium | Family::Firefox | Family::Safari).then_some("gzip, deflate")
}

/// A plain-http origin that is not localhost is not a secure context: browsers drop fetch metadata
/// and client hints and don't advertise Brotli/Zstandard there.
pub(super) fn apply_insecure_context(headers: &mut Vec<(String, String)>, family: Family) {
    headers.retain(|(k, _)| !k.starts_with("sec-fetch-"));
    if family == Family::Chromium {
        headers.retain(|(k, _)| !k.starts_with("sec-ch-") && k != "priority");
    }
    if let Some(encoding) = insecure_accept_encoding(family) {
        set(headers, "accept-encoding", encoding);
    }
}

/// Whether the URL is a potentially trustworthy origin (W3C Secure Contexts §3.1): https, or a
/// loopback host.
pub fn is_potentially_trustworthy(uri: &Uri) -> bool {
    match uri.scheme_str() {
        Some("https" | "wss") => true,
        _ => {
            let host = crate::client::connection::strip_brackets(uri.host().unwrap_or(""));
            host == "localhost"
                || host.ends_with(".localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
    }
}

/// The ASCII serialization of the URL's origin (`https://example.com:8443`), as it goes into an
/// Origin header.
pub(super) fn serialized_origin(uri: &Uri) -> String {
    format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("https"),
        host_header(uri)
    )
}

/// The sec-fetch-site value ("same-origin"/"same-site"/"cross-site") for `request_url`, comparing
/// it with the origin of the page it comes from.
pub(super) fn compute_fetch_site(request_url: &Uri, origin_value: &str) -> &'static str {
    let Ok(origin_uri) = origin_value.parse::<Uri>() else {
        return "cross-site";
    };

    let req_scheme = request_url.scheme_str().unwrap_or("");
    let req_host = request_url.host().unwrap_or("");
    let req_port = request_url
        .port_u16()
        .unwrap_or(if req_scheme == "https" { 443 } else { 80 });

    let origin_scheme = origin_uri.scheme_str().unwrap_or("");
    let origin_host = origin_uri.host().unwrap_or("");
    let origin_port = origin_uri
        .port_u16()
        .unwrap_or(if origin_scheme == "https" { 443 } else { 80 });

    if req_scheme == origin_scheme && req_host == origin_host && req_port == origin_port {
        return "same-origin";
    }
    if req_scheme == origin_scheme && same_site(req_host, origin_host) {
        return "same-site";
    }
    "cross-site"
}

/// Whether two hosts share a registrable domain (eTLD+1, Public Suffix List).
pub(super) fn same_site(host1: &str, host2: &str) -> bool {
    let site = |host: &str| {
        let host = host.to_ascii_lowercase();
        psl::domain_str(&host).map(str::to_string).unwrap_or(host)
    };
    site(host1) == site(host2)
}
