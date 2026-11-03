use http::{Method, Uri};

use super::order::host_header;
use super::util::{header_value, is_get_or_head, remove, set};
use super::{Family, Mode, RequestContext};
use crate::cookie::{CookieContext, CookieRules, SameSiteRules, ThirdPartyCookies, top_level_site};
use crate::profile::{BrowserProfile, SafariLayout, SafariStack};
use crate::util::same_site;

pub(super) fn detect_mode(
    method: &Method,
    origin: Option<&str>,
    content_type: Option<&str>,
    accept: Option<&str>,
) -> Mode {
    let ct = content_type.unwrap_or("").trim().to_ascii_lowercase();
    if !is_get_or_head(method) {
        let form = ct.starts_with("application/x-www-form-urlencoded")
            || ct.starts_with("multipart/form-data");
        return if form && *method == Method::POST {
            Mode::FormNavigate
        } else {
            Mode::Cors
        };
    }
    let navigation_accept = accept.is_none_or(|a| a.to_ascii_lowercase().contains("text/html"));
    if !ct.is_empty() || origin.is_some() || !navigation_accept {
        Mode::Cors
    } else {
        Mode::Navigate
    }
}

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

pub(crate) fn cookie_context(
    rules: CookieRules,
    context: &RequestContext,
    method: &Method,
    uri: &Uri,
    cross_site_redirect: bool,
) -> CookieContext {
    let top_level_navigation = context.navigation();
    let page = context.page();
    let same_site = context.initiator.as_deref().is_none_or(|initiator| {
        if rules.same_site == SameSiteRules::Chromium {
            compute_fetch_site(uri, initiator) != "cross-site"
        } else {
            page.as_ref()
                .and_then(|page| Some(same_site(page.host()?, uri.host()?)))
                .unwrap_or(false)
        }
    }) && !(cross_site_redirect && rules.same_site != SameSiteRules::Chromium);
    let top_level = page
        .as_ref()
        .filter(|_| !top_level_navigation)
        .unwrap_or(uri);
    let third_party = top_level
        .host()
        .zip(uri.host())
        .is_some_and(|(top, host)| !crate::util::same_site(top, host))
        || (rules.redirect_is_third_party && cross_site_redirect && !top_level_navigation);
    CookieContext {
        same_site,
        top_level_navigation,
        safe_method: matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE"),
        rules,
        top_level_site: top_level_site(top_level),
        third_party,
    }
}

pub(crate) fn cookie_rules(profile: &BrowserProfile) -> CookieRules {
    match Family::of(profile) {
        Family::Chromium => CookieRules {
            same_site: SameSiteRules::Chromium,
            third_party: ThirdPartyCookies::Allowed,
            chips: true,
            redirect_is_third_party: false,
        },
        Family::Firefox => CookieRules {
            same_site: SameSiteRules::UnspecifiedIsNone,
            third_party: ThirdPartyCookies::Partitioned,
            chips: true,
            redirect_is_third_party: false,
        },
        Family::Safari => {
            let layout = SafariLayout::of(profile);
            CookieRules {
                same_site: SameSiteRules::UnspecifiedIsNone,
                third_party: ThirdPartyCookies::Blocked,
                chips: layout.chips,
                redirect_is_third_party: layout.stack != SafariStack::Tahoe,
            }
        }
        _ => CookieRules::NONE,
    }
}

pub(super) fn fetch_site(
    family: Family,
    mode: Mode,
    uri: &Uri,
    redirect_chain: &[Uri],
    initiator: Option<&str>,
) -> Option<&'static str> {
    let initiator = initiator?;
    let chain = if family == Family::Safari && mode != Mode::Cors {
        &[]
    } else {
        redirect_chain
    };
    chain
        .iter()
        .chain([uri])
        .map(|url| compute_fetch_site(url, initiator))
        .max_by_key(|site| {
            ["same-origin", "same-site", "cross-site"]
                .iter()
                .position(|s| s == site)
        })
}

pub(super) fn apply_mode(
    headers: &mut Vec<(String, String)>,
    family: Family,
    mode: Mode,
    fetch_site: Option<&str>,
    caller_sets_accept: bool,
    dest: Option<&str>,
) {
    if let Some(site) = fetch_site {
        set(headers, "sec-fetch-site", site);
    }
    match mode {
        Mode::Navigate => {}
        Mode::FormNavigate => {
            if family == Family::Chromium && !headers.iter().any(|(k, _)| k == "cache-control") {
                headers.push(("cache-control".into(), "max-age=0".into()));
            }
        }
        Mode::Cors => {
            set(headers, "sec-fetch-mode", "cors");
            set(headers, "sec-fetch-dest", "empty");
            if fetch_site.is_none() {
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

pub(super) fn insecure_accept_encoding(family: Family) -> Option<&'static str> {
    matches!(family, Family::Chromium | Family::Firefox | Family::Safari).then_some("gzip, deflate")
}

pub(super) fn apply_insecure_context(headers: &mut Vec<(String, String)>, family: Family) {
    headers.retain(|(k, _)| !k.starts_with("sec-fetch-"));
    if family == Family::Chromium {
        headers.retain(|(k, _)| !k.starts_with("sec-ch-") && k != "priority");
    }
    if let Some(encoding) = insecure_accept_encoding(family) {
        set(headers, "accept-encoding", encoding);
    }
}

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

pub(super) fn serialized_origin(uri: &Uri) -> String {
    format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("https"),
        host_header(uri)
    )
}

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
