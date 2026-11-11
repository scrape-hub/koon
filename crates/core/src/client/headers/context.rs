use http::{Method, Uri};

use super::fetch_metadata::{detect_mode, fetch_site, navigate_mode, serialized_origin};
use super::util::{header_value, is_get_or_head, merge_caller_headers, page_url};
use super::{Family, Mode};

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub(super) mode: Mode,
    pub(crate) initiator: Option<String>,
    pub(super) own_origin: Option<String>,
    pub(super) fetch_site: Option<&'static str>,
    pub(super) element_cors: bool,
    pub(super) redirected: bool,
    pub(super) origin_from_redirect: bool,
}

impl RequestContext {
    pub fn new(
        family: Family,
        method: &Method,
        uri: &Uri,
        client: &[(String, String)],
        request: &[(String, String)],
        redirect_chain: &[Uri],
        mode: Option<Mode>,
    ) -> Self {
        let caller = merge_caller_headers(client, request);
        let caller_value = |name: &str| header_value(&caller, name);
        let mode = match (mode, caller_value("sec-fetch-mode")) {
            (Some(mode), _) => mode,
            (None, Some(m)) if m.eq_ignore_ascii_case("navigate") => {
                navigate_mode(method, caller_value("content-type"))
            }
            (None, Some(_)) => Mode::Cors,
            (None, None) => detect_mode(
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
        let request_origin = caller_value("origin")
            .map(str::to_string)
            .or_else(|| referer_origin.clone());
        let cors = mode == Mode::Cors
            && caller_value("sec-fetch-mode").is_none_or(|m| m.eq_ignore_ascii_case("cors"));
        let tainted = cors
            && request_origin
                .as_deref()
                .is_some_and(|origin| taints(redirect_chain, uri, origin));
        let cross_origin = cors
            && request_origin
                .as_deref()
                .is_some_and(|origin| origin != serialized_origin(uri));
        let own_origin = (family.is_browser()
            && caller_value("origin").is_none()
            && (!is_get_or_head(method) || element_cors || cross_origin || tainted))
            .then(|| {
                if tainted {
                    "null".to_string()
                } else {
                    referer_origin
                        .clone()
                        .unwrap_or_else(|| serialized_origin(uri))
                }
            });
        let origin_from_redirect = !redirect_chain.is_empty()
            && is_get_or_head(method)
            && !element_cors
            && own_origin.is_some();
        let initiator = request_origin.or_else(|| own_origin.clone());
        let fetch_site = fetch_site(family, mode, uri, redirect_chain, initiator.as_deref());
        Self {
            mode,
            initiator,
            own_origin,
            fetch_site,
            element_cors,
            redirected: !redirect_chain.is_empty(),
            origin_from_redirect,
        }
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn origin(
        &self,
        client: &[(String, String)],
        request: &[(String, String)],
    ) -> Option<String> {
        header_value(&merge_caller_headers(client, request), "origin")
            .map(str::to_string)
            .or_else(|| self.own_origin.clone())
    }

    pub(crate) fn navigation(&self) -> bool {
        self.mode != Mode::Cors
    }

    pub(crate) fn page(&self) -> Option<Uri> {
        self.initiator.as_deref()?.parse().ok()
    }
}

fn taints(redirect_chain: &[Uri], uri: &Uri, origin: &str) -> bool {
    redirect_chain
        .iter()
        .zip(redirect_chain.iter().skip(1).chain([uri]))
        .any(|(from, to)| {
            let from = serialized_origin(from);
            from != serialized_origin(to) && from != origin
        })
}
