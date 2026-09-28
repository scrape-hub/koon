//! Shared helpers for the `headers` test modules: the one place that builds a [`HeaderInput`] with
//! sensible defaults, and the header-name projection every module's assertions compare against.

use http::{Method, Uri};

use crate::client::client_hints::ClientHintsState;
use crate::client::headers::{HeaderInput, Protocol, build};
use crate::profile::BrowserProfile;

/// The header names, in order.
pub(crate) fn names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(k, _)| k.as_str()).collect()
}

/// One request's headers, built with sensible defaults; override only the fields a test needs, e.g.
/// `Request { cookie: Some("a=1"), ..Request::new(&profile, Method::GET, url) }`.
pub(crate) struct Request<'a> {
    pub profile: &'a BrowserProfile,
    pub protocol: Protocol,
    pub method: Method,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub cookie: Option<&'a str>,
    pub body_len: Option<usize>,
    pub alt_used: Option<&'a str>,
    pub client_hints: Option<&'a ClientHintsState>,
    pub accept_ch_frame: Option<&'a str>,
    pub restarted: bool,
}

impl<'a> Request<'a> {
    pub(crate) fn new(profile: &'a BrowserProfile, method: Method, url: &'a str) -> Self {
        Request {
            profile,
            protocol: Protocol::Http2,
            method,
            url,
            headers: &[],
            cookie: None,
            body_len: None,
            alt_used: None,
            client_hints: None,
            accept_ch_frame: None,
            restarted: false,
        }
    }

    pub(crate) fn build(&self) -> Vec<(String, String)> {
        let uri: Uri = self.url.parse().unwrap();
        let headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        build(&HeaderInput {
            profile: self.profile,
            protocol: self.protocol,
            method: &self.method,
            uri: &uri,
            body_len: self.body_len,
            client_headers: &[],
            request_headers: &headers,
            cookie: self.cookie,
            proxy_headers: None,
            alt_used: self.alt_used,
            client_hints: self.client_hints,
            accept_ch_frame: self.accept_ch_frame,
            restarted: self.restarted,
        })
    }
}
