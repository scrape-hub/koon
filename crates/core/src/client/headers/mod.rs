mod context;
mod fetch_metadata;
mod order;
mod order_tables;
mod safari_map;
mod util;
mod websocket;

use http::{Method, Uri};

use super::cf_header_dict::HeaderDict;
use super::client_hints::{self, ClientHintsState};
use crate::profile::BrowserProfile;
pub use crate::profile::HeaderFamily as Family;
pub use context::RequestContext;
pub use fetch_metadata::is_potentially_trustworthy;
use fetch_metadata::{apply_insecure_context, apply_mode};
pub(crate) use fetch_metadata::{cookie_context, cookie_rules, redirect_referrer};
pub use order::host_header;
use order::{finalize_http1, finalize_multiplexed, order_headers, sonoma_order, sort_into};
pub use util::header_value;
use util::{content_length, cookie_header, merge_caller_headers, remove};
pub use websocket::{build_websocket, build_websocket_h2};

impl Family {
    pub(crate) fn of(profile: &BrowserProfile) -> Self {
        profile
            .header_family
            .unwrap_or_else(|| Self::detect(profile))
    }

    pub(crate) fn is_browser(self) -> bool {
        matches!(self, Self::Chromium | Self::Firefox | Self::Safari)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Navigate,
    FormNavigate,
    Cors,
}

pub struct HeaderInput<'a> {
    pub profile: &'a BrowserProfile,
    pub protocol: Protocol,
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub body_len: Option<usize>,
    pub client_headers: &'a [(String, String)],
    pub request_headers: &'a [(String, String)],
    pub cookie: Option<&'a str>,
    pub proxy_headers: Option<&'a [(String, String)]>,
    pub alt_used: Option<&'a str>,
    pub client_hints: Option<&'a ClientHintsState>,
    pub accept_ch_frame: Option<&'a str>,
    pub restarted: bool,
    pub context: Option<&'a RequestContext>,
    pub safari_dict: Option<&'a HeaderDict>,
}

pub(crate) fn build(input: &HeaderInput) -> (Vec<(String, String)>, Option<HeaderDict>) {
    let family = Family::of(input.profile);
    let caller = merge_caller_headers(input.client_headers, input.request_headers);
    let caller_value = |name: &str| header_value(&caller, name);

    let mut headers: Vec<(String, String)> = input
        .profile
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let safari_layout =
        (family == Family::Safari).then(|| crate::profile::SafariLayout::of(input.profile));
    if safari_layout
        .is_some_and(|l| l.stack == crate::profile::SafariStack::Sonoma && l.fetch_metadata)
        && input.protocol == Protocol::Http3
        && header_value(&headers, "priority").is_none()
    {
        headers.push(("priority".into(), "u=0, i".into()));
    }

    let derived;
    let context = match input.context {
        Some(context) => context,
        None => {
            derived = RequestContext::new(
                family,
                input.method,
                input.uri,
                input.client_headers,
                input.request_headers,
                &[],
                None,
            );
            &derived
        }
    };
    let mode = context.mode;

    if family.is_browser() {
        apply_mode(
            &mut headers,
            family,
            mode,
            context.fetch_site,
            caller_value("accept").is_some(),
            caller_value("sec-fetch-dest"),
        );
    }
    if safari_layout.is_some_and(|l| l.stack == crate::profile::SafariStack::Tahoe)
        && context.origin_from_redirect
    {
        headers.retain(|(k, _)| !k.starts_with("sec-fetch-"));
    }

    let secure = is_potentially_trustworthy(input.uri);
    if !secure {
        apply_insecure_context(&mut headers, family);
        if family == Family::Safari && mode != Mode::Cors {
            headers.push(("upgrade-insecure-requests".into(), "1".into()));
        }
    }

    let mut hints = AddedHints::default();
    if let (Family::Chromium, true, Some(state)) = (family, secure, input.client_hints) {
        hints = add_client_hints(
            &mut headers,
            input,
            state,
            mode,
            context.initiator.as_deref(),
        );
    }

    let mut custom_casing: Vec<(String, String)> = Vec::new();
    for (name, value) in caller.iter().cloned() {
        let lower = name.to_ascii_lowercase();
        if lower == "cookie" || lower == "content-length" {
            continue;
        }
        match headers.iter().position(|(k, _)| *k == lower) {
            Some(i) if family == Family::OkHttp => {
                headers.remove(i);
                headers.push((lower.clone(), value));
                if name != lower {
                    custom_casing.push((lower, name));
                }
            }
            Some(i) => headers[i].1 = value,
            None => {
                headers.push((lower.clone(), value));
                if name != lower {
                    custom_casing.push((lower, name));
                }
            }
        }
    }
    if family == Family::Safari && mode == Mode::Cors {
        safari_map::add_fetch_headers(&mut headers, &caller);
    }
    if let Some(origin) = &context.own_origin {
        headers.push(("origin".into(), origin.clone()));
    }
    if let Some(length) = content_length(family, input.method, input.body_len) {
        headers.push(("content-length".into(), length));
    }
    if let Some(cookie) = cookie_header(input.client_headers, input.request_headers, input.cookie) {
        headers.push(("cookie".into(), cookie));
    }
    if let (true, None, Some(state)) = (
        input.profile.farble_accept_language,
        caller_value("accept-language"),
        input.client_hints,
    ) {
        let page = (mode == Mode::Cors).then(|| context.page()).flatten();
        let site = page.as_ref().unwrap_or(input.uri);
        farble_accept_language(&mut headers, state, site);
    }

    if family == Family::OkHttp {
        apply_okhttp_quirks(&mut headers, input, &caller, &mut custom_casing);
    }
    if family == Family::Firefox {
        apply_firefox_quirks(&mut headers, input, &caller);
    }

    let restarted = input.restarted && hints.any && mode != Mode::Cors;
    order_headers(&mut headers, family, context, &caller, &hints, restarted);
    let mut safari_dict = None;
    if let Some(layout) = safari_layout {
        if layout.stack == crate::profile::SafariStack::Sonoma {
            let order = sonoma_order(layout, input.protocol, input.method, &headers);
            sort_into(&mut headers, order);
        } else {
            let (order, dict) = safari_map::order(&safari_map::SafariRequest {
                headers: &headers,
                caller: &caller,
                method: input.method,
                uri: input.uri,
                mode,
                secure,
                body: input.body_len.is_some(),
                ios: layout.ios,
                version: layout.version,
                previous: input.safari_dict,
            });
            let order: Vec<&str> = order.iter().map(String::as_str).collect();
            sort_into(&mut headers, &order);
            safari_dict = Some(dict);
        }
    }
    match input.protocol {
        Protocol::Http1 => finalize_http1(family, input, &custom_casing, &mut headers),
        Protocol::Http2 | Protocol::Http3 => finalize_multiplexed(&mut headers),
    }
    (headers, safari_dict)
}

fn apply_okhttp_quirks(
    headers: &mut Vec<(String, String)>,
    input: &HeaderInput,
    caller: &[(String, String)],
    custom_casing: &mut Vec<(String, String)>,
) {
    let caller_value = |name: &str| header_value(caller, name);
    if caller_value("range").is_some() && caller_value("accept-encoding").is_none() {
        remove(headers, "accept-encoding");
    }
    if input.protocol == Protocol::Http1 {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        headers.push(("host".into(), host_header(input.uri)));
        if caller_value("connection").is_none() {
            headers.push(("connection".into(), "Keep-Alive".into()));
        }
        for (name, value) in input.proxy_headers.unwrap_or(&[]) {
            let lower = name.to_ascii_lowercase();
            if *name != lower {
                custom_casing.push((lower.clone(), name.clone()));
            }
            headers.push((lower, value.clone()));
        }
    }
}

fn apply_firefox_quirks(
    headers: &mut Vec<(String, String)>,
    input: &HeaderInput,
    caller: &[(String, String)],
) {
    let caller_value = |name: &str| header_value(caller, name);
    if input.protocol == Protocol::Http1 && caller_value("connection").is_none() {
        headers.push(("connection".into(), "keep-alive".into()));
    }
    if input.protocol == Protocol::Http3 {
        if let (Some(alt_used), None) = (input.alt_used, caller_value("alt-used")) {
            headers.push(("alt-used".into(), alt_used.to_string()));
        }
        if caller_value("te").is_none() {
            remove(headers, "te");
        }
    }
}

pub fn farble_accept_language(
    headers: &mut [(String, String)],
    state: &ClientHintsState,
    site: &Uri,
) {
    const FAKE_Q_VALUES: [&str; 5] = [";q=0.5", ";q=0.6", ";q=0.7", ";q=0.8", ";q=0.9"];
    let domain = crate::util::site(site.host().unwrap_or(""));
    let q = FAKE_Q_VALUES[state.farbling_index(&domain, FAKE_Q_VALUES.len())];
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
    {
        value.push_str(q);
    }
}

pub fn build_raw(
    raw: &[(String, String)],
    protocol: Protocol,
    uri: &Uri,
    proxy_headers: Option<&[(String, String)]>,
) -> Vec<(String, String)> {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "proxy-authorization",
        "te",
    ];
    let mut out: Vec<(String, String)> = raw
        .iter()
        .filter(|(k, _)| !HOP_BY_HOP.contains(&k.to_ascii_lowercase().as_str()))
        .cloned()
        .collect();
    match protocol {
        Protocol::Http1 => {
            let mut head = vec![
                ("Host".to_string(), host_header(uri)),
                ("Connection".to_string(), "keep-alive".to_string()),
            ];
            head.extend(proxy_headers.unwrap_or(&[]).iter().cloned());
            head.append(&mut out);
            head
        }
        Protocol::Http2 | Protocol::Http3 => {
            for (name, _) in out.iter_mut() {
                name.make_ascii_lowercase();
            }
            out
        }
    }
}

#[derive(Default)]
struct AddedHints {
    any: bool,
    appended: Vec<&'static str>,
}

fn add_client_hints(
    headers: &mut Vec<(String, String)>,
    input: &HeaderInput,
    state: &ClientHintsState,
    mode: Mode,
    page: Option<&str>,
) -> AddedHints {
    let target = client_hints::origin_of(input.uri);
    let (persisted, alps) = match mode {
        Mode::Navigate | Mode::FormNavigate => (
            state.persisted(&target),
            input
                .accept_ch_frame
                .and_then(client_hints::parse_accept_ch)
                .unwrap_or_default(),
        ),
        Mode::Cors => {
            let same_origin = page
                .and_then(|page| page.parse::<Uri>().ok())
                .is_none_or(|page| client_hints::origin_of(&page) == target);
            let hints = if same_origin {
                state.persisted(&target)
            } else {
                Vec::new()
            };
            (hints, Vec::new())
        }
    };
    let host = input.uri.host().unwrap_or("");
    let mut added = AddedHints::default();
    for hint in persisted
        .iter()
        .chain(alps.iter().filter(|h| !persisted.contains(h)))
    {
        if hint.by_default() || header_value(headers, hint.header()).is_some() {
            continue;
        }
        let navigation = mode != Mode::Cors;
        let Some(value) = client_hints::hint_value(*hint, input.profile, state, host, navigation)
        else {
            continue;
        };
        headers.push((hint.header().to_string(), value));
        added.any = true;
        if !persisted.contains(hint) {
            added.appended.push(hint.header());
        }
    }
    added
}
