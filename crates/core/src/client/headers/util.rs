use http::{Method, Uri};

use super::Family;

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

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

pub(super) fn page_url(value: &str) -> Option<Uri> {
    value
        .parse::<Uri>()
        .ok()
        .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")) && uri.host().is_some())
}
