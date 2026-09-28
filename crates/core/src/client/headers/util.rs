//! Small header-list utilities shared across the `headers` submodules.

use http::{Method, Uri};

use super::Family;

/// Case-insensitive lookup of a header value.
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Combine client- and request-level headers: a later value replaces an earlier one of the same
/// name, which keeps its position.
pub(super) fn merge_caller_headers(
    client: &[(String, String)],
    request: &[(String, String)],
) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for (name, value) in client.iter().chain(request) {
        match merged
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            Some(slot) => slot.1 = value.clone(),
            None => merged.push((name.clone(), value.clone())),
        }
    }
    merged
}

/// The Cookie header: the caller's cookies (client-level, then request-level, which win pairwise)
/// followed by the jar's other ones.
pub(super) fn cookie_header(
    client: &[(String, String)],
    request: &[(String, String)],
    jar: Option<&str>,
) -> Option<String> {
    merge_cookies(
        header_value(client, "cookie")
            .into_iter()
            .chain(header_value(request, "cookie")),
        jar,
    )
}

/// Merge manually supplied Cookie header values with the jar's. Manual cookies come first and win
/// over jar cookies with the same name.
pub(super) fn merge_cookies<'a>(
    manual: impl Iterator<Item = &'a str>,
    jar: Option<&str>,
) -> Option<String> {
    let mut pairs: Vec<&str> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for value in manual {
        for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let name = pair.split('=').next().unwrap_or(pair);
            if let Some(i) = names.iter().position(|n| *n == name) {
                pairs[i] = pair;
            } else {
                names.push(name);
                pairs.push(pair);
            }
        }
    }
    if let Some(jar) = jar {
        for pair in jar.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let name = pair.split('=').next().unwrap_or(pair);
            if !names.contains(&name) {
                pairs.push(pair);
            }
        }
    }
    (!pairs.is_empty()).then(|| pairs.join("; "))
}

pub(super) fn is_get_or_head(method: &Method) -> bool {
    *method == Method::GET || *method == Method::HEAD
}

/// Content-Length of the request. A body always carries its length. Without a body, Chromium sends
/// `0` for POST and PUT (Firefox sends nothing), and `OkHttp`, which requires a body for POST, PUT
/// and PATCH, sends the length of an empty one.
pub(super) fn content_length(
    family: Family,
    method: &Method,
    body_len: Option<usize>,
) -> Option<String> {
    if let Some(len) = body_len {
        return Some(len.to_string());
    }
    let empty_body = match family {
        Family::Chromium => *method == Method::POST || *method == Method::PUT,
        Family::OkHttp => {
            *method == Method::POST || *method == Method::PUT || *method == Method::PATCH
        }
        // Safari's CORS preflight (captured).
        Family::Safari => *method == Method::OPTIONS,
        _ => false,
    };
    empty_body.then(|| "0".to_string())
}

pub(super) fn set(headers: &mut [(String, String)], name: &str, value: &str) {
    if let Some(slot) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        slot.1 = value.to_string();
    }
}

pub(super) fn remove(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
}

/// `value` as the URL of a page, if it is an absolute http(s) URL.
pub(super) fn page_url(value: &str) -> Option<Uri> {
    value
        .parse::<Uri>()
        .ok()
        .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some())
}
