//! Request header construction: starts from the profile's navigation template and adapts it per
//! request (fetch vs. navigation, secure vs. insecure, protocol, cookies, body, caller headers),
//! keeping every header at the real browser's position. Output: an ordered list with wire casing
//! (browser casing on HTTP/1.1, lowercase on HTTP/2 and HTTP/3).

mod fetch_metadata;
mod order;
mod order_tables;
mod util;
mod websocket;

#[cfg(test)]
mod tests;

use http::{Method, Uri};

use super::client_hints::{self, ClientHintsState};
use crate::profile::BrowserProfile;
pub use crate::profile::HeaderFamily as Family;
use fetch_metadata::{apply_insecure_context, apply_mode, detect_mode, serialized_origin};
pub use fetch_metadata::{builds_navigation, is_navigation, is_potentially_trustworthy};
pub use order::host_header;
use order::{finalize_http1, finalize_multiplexed, order_headers, safari_order, sort_into};
pub use util::header_value;
use util::{content_length, cookie_header, is_get_or_head, merge_caller_headers, page_url, remove};
pub use websocket::{build_websocket, build_websocket_h2};

impl Family {
    /// The family of `profile`: its own, which a client sets when it is built, else detected from
    /// its headers.
    pub(crate) fn of(profile: &BrowserProfile) -> Self {
        profile
            .header_family
            .unwrap_or_else(|| Self::detect(profile))
    }

    /// Browsers follow the Fetch standard (Origin, fetch metadata, secure contexts); `OkHttp` and
    /// unknown clients do not.
    fn is_browser(self) -> bool {
        matches!(self, Self::Chromium | Self::Firefox | Self::Safari)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

/// What kind of request the browser would be making.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Top-level navigation (the profile template).
    Navigate,
    /// HTML form submission: a navigation with a body and an Origin.
    FormNavigate,
    /// fetch()/XMLHttpRequest.
    Cors,
}

/// Inputs for building one request's headers.
pub struct HeaderInput<'a> {
    pub profile: &'a BrowserProfile,
    pub protocol: Protocol,
    pub method: &'a Method,
    pub uri: &'a Uri,
    /// Length of the request body, if there is one.
    pub body_len: Option<usize>,
    /// Client-level headers, in the caller's order.
    pub client_headers: &'a [(String, String)],
    /// Request-level headers, in the caller's order. Override client-level ones.
    pub request_headers: &'a [(String, String)],
    /// Cookie header value from the jar.
    pub cookie: Option<&'a str>,
    /// Plain HTTP through an HTTP proxy: the request goes to the proxy in absolute form and carries
    /// these proxy headers.
    pub proxy_headers: Option<&'a [(String, String)]>,
    /// The connection goes to this Alt-Svc alternative (`host[:port]`).
    pub alt_used: Option<&'a str>,
    /// The hints origins asked for with `Accept-CH`; `None` sends only the profile's default client
    /// hints.
    pub client_hints: Option<&'a ClientHintsState>,
    /// The `ACCEPT_CH` value the connection's ALPS data carries for the request's origin.
    pub accept_ch_frame: Option<&'a str>,
    /// The navigation started over for a `Critical-CH`: Chromium then sends every client hint after
    /// `accept`.
    pub restarted: bool,
}

/// Build the request headers, in wire order and casing.
pub fn build(input: &HeaderInput) -> Vec<(String, String)> {
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
    // Safari on macOS 14/iOS 17 (fetch metadata, Safari 16.4+) sends `priority` only over HTTP/3;
    // before fetch metadata (macOS 12/13, iOS 16.0/16.1) it never sends one at all, on either
    // transport.
    if safari_layout
        .is_some_and(|l| l.stack == crate::profile::SafariStack::Sonoma && l.fetch_metadata)
        && input.protocol == Protocol::Http3
        && header_value(&headers, "priority").is_none()
    {
        headers.push(("priority".into(), "u=0, i".into()));
    }

    // Navigation vs. fetch, detected unless the caller sets sec-fetch-mode.
    let mode = match caller_value("sec-fetch-mode") {
        Some(m) if m.eq_ignore_ascii_case("navigate") => Mode::Navigate,
        Some(_) => Mode::Cors,
        None => detect_mode(
            input.method,
            caller_value("origin"),
            caller_value("content-type"),
            caller_value("accept"),
        ),
    };

    // The page the request comes from, as the caller's Referer names it.
    let referer_origin = caller_value("referer")
        .and_then(page_url)
        .map(|page| serialized_origin(&page));

    // Browsers send an Origin on every non-GET/HEAD request (Fetch standard), from the caller's
    // Referer page if any, else the request's own origin. Blink also sets one on CORS-mode element
    // loads, same-origin included, where fetch() only gets one when cross-origin or unsafe.
    let element_cors = family == Family::Chromium
        && caller_value("sec-fetch-mode").is_some_and(|m| m.eq_ignore_ascii_case("cors"))
        && caller_value("sec-fetch-dest").is_some_and(|d| !d.eq_ignore_ascii_case("empty"));
    let own_origin = (family.is_browser()
        && caller_value("origin").is_none()
        && (!is_get_or_head(input.method) || element_cors))
        .then(|| {
            referer_origin
                .clone()
                .unwrap_or_else(|| serialized_origin(input.uri))
        });
    let origin = caller_value("origin").or(own_origin.as_deref());

    // Every real browser adjusts Accept/Origin/sec-fetch-* for the request kind, whether or not it
    // sends fetch metadata on the wire: `set()` only replaces a header already in the template, so a
    // profile without `sec-fetch-*` there (Safari before 16.4) leaves those untouched while still
    // getting Accept's Cors-mode override. OkHttp and an unrecognized profile have no Accept in
    // their template either, so this is a no-op for them.
    if family.is_browser() {
        // A navigation or GET fetch() carries no Origin; sec-fetch-site still derives from the page
        // it comes from.
        let initiator = origin.or(referer_origin.as_deref());
        apply_mode(
            &mut headers,
            family,
            mode,
            input.uri,
            initiator,
            caller_value("accept").is_some(),
            caller_value("sec-fetch-dest"),
        );
    }

    let secure = is_potentially_trustworthy(input.uri);
    if !secure {
        apply_insecure_context(&mut headers, family);
        // WebKit upgrades navigations/form submissions to http URLs only, never https (Safari).
        if family == Family::Safari && mode != Mode::Cors {
            headers.push(("upgrade-insecure-requests".into(), "1".into()));
        }
    }

    // The client hints the origin asked for; caller values below replace them in place.
    let mut hints = AddedHints::default();
    if let (Family::Chromium, true, Some(state)) = (family, secure, input.client_hints) {
        let page = origin.or(referer_origin.as_deref());
        hints = add_client_hints(&mut headers, input, state, mode, page);
    }

    // Caller values replace template values in place; other caller headers follow in the caller's
    // order (Cookie and Content-Length handled below). `headers` always keeps the lowercase,
    // matching key from here on so every later step can compare it directly instead of
    // re-lowercasing; a caller's own casing is kept only for output, in `custom_casing`
    // (`finalize_http1` looks it up there once, instead of every step guessing at the invariant).
    let mut custom_casing: Vec<(String, String)> = Vec::new();
    for (name, value) in caller.iter().cloned() {
        let lower = name.to_ascii_lowercase();
        if lower == "cookie" || lower == "content-length" {
            continue;
        }
        match headers.iter().position(|(k, _)| *k == lower) {
            // OkHttp keeps the application's headers where it put them.
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
    if let Some(origin) = own_origin {
        headers.push(("origin".into(), origin));
    }
    if let Some(length) = content_length(family, input.method, input.body_len) {
        headers.push(("content-length".into(), length));
    }
    if let Some(cookie) = cookie_header(input.client_headers, input.request_headers, input.cookie) {
        headers.push(("cookie".into(), cookie));
    }
    // Brave's Accept-Language takes a q value per site: the navigation's own, else the page it
    // comes from.
    if let (true, None, Some(state)) = (
        input.profile.farble_accept_language,
        caller_value("accept-language"),
        input.client_hints,
    ) {
        let page = (mode == Mode::Cors)
            .then(|| caller_value("referer").and_then(page_url))
            .flatten();
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
    order_headers(
        &mut headers,
        family,
        mode,
        &caller,
        &hints,
        element_cors,
        restarted,
    );
    if let Some(layout) = safari_layout {
        let order = safari_order(layout, input.protocol, input.method, mode, secure, &headers);
        sort_into(&mut headers, order);
    }
    match input.protocol {
        Protocol::Http1 => finalize_http1(family, input, &custom_casing, &mut headers),
        Protocol::Http2 | Protocol::Http3 => finalize_multiplexed(&mut headers),
    }
    // Chrome's QPACK encoder sends each cookie as a field of its own (see
    // `QuicSetup::splits_cookies`).
    headers
}

/// `OkHttp`'s Accept-Encoding and HTTP/1.1 Host/Connection quirks (see [`build`]).
fn apply_okhttp_quirks(
    headers: &mut Vec<(String, String)>,
    input: &HeaderInput,
    caller: &[(String, String)],
    custom_casing: &mut Vec<(String, String)>,
) {
    let caller_value = |name: &str| header_value(caller, name);
    // BridgeInterceptor asks for gzip only when neither Accept-Encoding nor a Range is set.
    if caller_value("range").is_some() && caller_value("accept-encoding").is_none() {
        remove(headers, "accept-encoding");
    }
    if input.protocol == Protocol::Http1 {
        // OkHttp adds Host and Connection itself, within its order.
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("host"));
        headers.push(("host".into(), host_header(input.uri)));
        if caller_value("connection").is_none() {
            headers.push(("connection".into(), "Keep-Alive".into()));
        }
        // Proxy headers keep `headers` lowercase like everything else; their own casing (e.g.
        // `Proxy-Authorization`) is kept in `custom_casing`, same as a caller header would be.
        for (name, value) in input.proxy_headers.unwrap_or(&[]) {
            let lower = name.to_ascii_lowercase();
            if *name != lower {
                custom_casing.push((lower.clone(), name.clone()));
            }
            headers.push((lower, value.clone()));
        }
    }
}

/// Firefox's Connection slot and HTTP/3 Alt-Used/`te` quirks (see [`build`]).
fn apply_firefox_quirks(
    headers: &mut Vec<(String, String)>,
    input: &HeaderInput,
    caller: &[(String, String)],
) {
    let caller_value = |name: &str| header_value(caller, name);
    if input.protocol == Protocol::Http1 && caller_value("connection").is_none() {
        // Firefox writes Connection in the middle of its headers, as part of the canonical order.
        headers.push(("connection".into(), "keep-alive".into()));
    }
    if input.protocol == Protocol::Http3 {
        // Firefox names the Alt-Svc alternative a connection goes to and sends no `te: trailers`
        // over HTTP/3.
        if let (Some(alt_used), None) = (input.alt_used, caller_value("alt-used")) {
            headers.push(("alt-used".into(), alt_used.to_string()));
        }
        if caller_value("te").is_none() {
            remove(headers, "te");
        }
    }
}

/// Brave's farbling of Accept-Language (`FarbleAcceptLanguageHeader`): appends one of
/// `;q=0.5`-`;q=0.9`, fixed per client and site (registrable domain), drawn from the client's
/// farbling seed.
pub fn farble_accept_language(
    headers: &mut [(String, String)],
    state: &ClientHintsState,
    site: &Uri,
) {
    const FAKE_Q_VALUES: [&str; 5] = [";q=0.5", ";q=0.6", ";q=0.7", ";q=0.8", ";q=0.9"];
    let host = site.host().unwrap_or("").to_ascii_lowercase();
    let domain = psl::domain_str(&host).unwrap_or(&host).to_string();
    let q = FAKE_Q_VALUES[state.farbling_index(&domain, FAKE_Q_VALUES.len())];
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("accept-language"))
    {
        value.push_str(q);
    }
}

/// Headers for passthrough mode (MITM proxy): the proxied client's own headers without hop-by-hop
/// ones, with Host and Connection on HTTP/1.1. Content-Length is recomputed from the body when it
/// is written.
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

/// The client hints a request got beyond the profile's default ones.
#[derive(Default)]
struct AddedHints {
    /// Any hint at all: a navigation restarted for a Critical-CH then carries them behind `accept`.
    any: bool,
    /// Hints an `ACCEPT_CH` frame added to a navigation, which Chromium appends to the request it
    /// restarts (see [`CHROMIUM_NAV`](order_tables::CHROMIUM_NAV)).
    appended: Vec<&'static str>,
}

/// Add the client hints of a Chromium request to a secure origin. A navigation carries the
/// `Accept-CH` hints plus any an `ACCEPT_CH` frame adds (appended, as Chromium's restart does); a
/// `fetch()` carries its page's hints only when same-origin, else only the defaults.
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
