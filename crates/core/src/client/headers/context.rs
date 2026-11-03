use http::{Method, Uri};

use super::fetch_metadata::{detect_mode, fetch_site, serialized_origin};
use super::util::{header_value, is_get_or_head, merge_caller_headers, page_url};
use super::{Family, Mode};

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub(super) mode: Mode,
    pub(crate) initiator: Option<String>,
    pub(super) own_origin: Option<String>,
    pub(super) fetch_site: Option<&'static str>,
    pub(super) element_cors: bool,
}

impl RequestContext {
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

    pub(crate) fn navigation(&self) -> bool {
        self.mode != Mode::Cors
    }

    pub(crate) fn page(&self) -> Option<Uri> {
        self.initiator.as_deref()?.parse().ok()
    }
}
