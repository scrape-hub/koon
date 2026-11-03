//! What a hop's request is, as the browser sees it.

use http::{Method, Uri};

use super::fetch_metadata::{detect_mode, fetch_site, serialized_origin};
use super::util::{header_value, is_get_or_head, merge_caller_headers, page_url};
use super::{Family, Mode};

/// What one hop's request is, as the browser sees it: derived once from the caller's headers, and
/// read by the header builder, the cookie jar, client hints and Brave's Accept-Language alike.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub(super) mode: Mode,
    /// The origin of the page the request comes from: the caller's Origin, else the one the
    /// browser adds ([`own_origin`](Self::own_origin)), else the caller's Referer page. `None` for
    /// a request from no page (a typed URL).
    pub(crate) initiator: Option<String>,
    /// The Origin the browser adds where the caller set none: on every request but GET and HEAD
    /// (Fetch standard), from the Referer page, else the request's own; Blink also on CORS-mode
    /// element loads, same-origin included.
    pub(super) own_origin: Option<String>,
    /// `sec-fetch-site` over the whole redirect chain; `None` for a request from no page.
    pub(super) fetch_site: Option<&'static str>,
    /// A Chromium element load in CORS mode (`sec-fetch-mode: cors` with a destination).
    pub(super) element_cors: bool,
}

impl RequestContext {
    /// The context of a request with these client- and request-level headers to `uri`, after
    /// `redirect_chain`; `navigation` overrides what the headers say (a WebSocket handshake is
    /// none).
    pub fn new(
        family: Family,
        method: &Method,
        uri: &Uri,
        client: &[(String, String)],
        request: &[(String, String)],
        redirect_chain: &[Uri],
        navigation: Option<bool>,
    ) -> Self {
        let caller = merge_caller_headers(client, request);
        let caller_value = |name: &str| header_value(&caller, name);
        let mode = match (navigation, caller_value("sec-fetch-mode")) {
            (Some(false), _) => Mode::Cors,
            (_, Some(m)) if m.eq_ignore_ascii_case("navigate") => Mode::Navigate,
            (_, Some(_)) => Mode::Cors,
            (_, None) => detect_mode(
                method,
                caller_value("origin"),
                caller_value("content-type"),
                caller_value("accept"),
            ),
        };
        let referer_origin = caller_value("referer")
            .and_then(page_url)
            .map(|page| serialized_origin(&page));
        let element_cors = family == Family::Chromium
            && caller_value("sec-fetch-mode").is_some_and(|m| m.eq_ignore_ascii_case("cors"))
            && caller_value("sec-fetch-dest").is_some_and(|d| !d.eq_ignore_ascii_case("empty"));
        let own_origin = (family.is_browser()
            && caller_value("origin").is_none()
            && (!is_get_or_head(method) || element_cors))
            .then(|| {
                referer_origin
                    .clone()
                    .unwrap_or_else(|| serialized_origin(uri))
            });
        let initiator = caller_value("origin")
            .map(str::to_string)
            .or_else(|| own_origin.clone())
            .or(referer_origin);
        let fetch_site = fetch_site(family, mode, uri, redirect_chain, initiator.as_deref());
        Self {
            mode,
            initiator,
            own_origin,
            fetch_site,
            element_cors,
        }
    }

    /// The request is a top-level navigation (a link, a typed URL or a form submission).
    pub(crate) fn navigation(&self) -> bool {
        self.mode != Mode::Cors
    }

    /// The page the request comes from, as a URL to compare sites with.
    pub(crate) fn page(&self) -> Option<Uri> {
        self.initiator.as_deref()?.parse().ok()
    }
}
