use extendr_api::prelude::*;
use koon_core::dns::DohResolver;
use koon_core::profile::BrowserProfile;
use koon_core::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Convert an HttpResponse to an R list with status, ok, headers, body, version, url, text.
fn response_to_list(resp: koon_core::HttpResponse) -> List {
    let ok = resp.status >= 200 && resp.status < 300;

    let content_type: Robj = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| -> Robj { v.into() })
        .unwrap_or_else(|| ().into());

    let ct_str = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    let text = koon_core::decode_body_text(&resp.body, ct_str);

    let header_names: Vec<String> = resp.headers.iter().map(|(n, _)| n.clone()).collect();
    let header_values: Vec<String> = resp.headers.iter().map(|(_, v)| v.clone()).collect();
    let headers_df = data_frame!(name = header_names, value = header_values);

    let remote_address: Robj = match resp.remote_address {
        Some(ref addr) => addr.into(),
        None => ().into(),
    };

    list!(
        status = resp.status as i32,
        status_code = resp.status as i32,
        ok = ok,
        version = resp.version,
        url = resp.url,
        body = Raw::from_bytes(&resp.body),
        text = text,
        content_type = content_type,
        headers = headers_df,
        bytes_sent = resp.bytes_sent as f64,
        bytes_received = resp.bytes_received as f64,
        tls_resumed = resp.tls_resumed,
        connection_reused = resp.connection_reused,
        remote_address = remote_address
    )
}

/// Parse a named character vector from R into Vec<(String, String)>.
fn parse_headers_robj(robj: &Robj) -> Vec<(String, String)> {
    let mut result = Vec::new();
    if robj.is_null() {
        return result;
    }
    if let Some(names) = robj.names() {
        let names: Vec<String> = names.map(|n| n.to_string()).collect();
        if let Some(values) = robj.as_str_vector() {
            for (name, value) in names.into_iter().zip(values.into_iter()) {
                result.push((name, value.to_string()));
            }
        }
    }
    result
}

/// Extract body bytes from an Robj that can be either a character string or raw vector.
fn extract_body_robj(robj: &Robj) -> Option<Vec<u8>> {
    if robj.is_null() {
        return None;
    }
    if let Some(s) = robj.as_str() {
        Some(s.as_bytes().to_vec())
    } else if let Ok(raw) = <Raw as TryFrom<&Robj>>::try_from(robj) {
        Some(raw.as_slice().to_vec())
    } else {
        panic!("body must be a character string or raw vector");
    }
}

/// Wrapper to make Robj Send+Sync for use in Core hooks.
/// Safe because block_on runs the future on the R thread (same thread that owns the Robj).
struct UnsafeSendRobj(Robj);
unsafe impl Send for UnsafeSendRobj {}
unsafe impl Sync for UnsafeSendRobj {}

/// The main Koon HTTP client with browser fingerprint impersonation.
///
/// @details
/// Creates an HTTP client that impersonates a real browser's TLS, HTTP/2,
/// and HTTP/3 fingerprints. All requests are synchronous (blocking).
///
/// @export
#[extendr]
struct Koon {
    client: Arc<Client>,
    runtime: Runtime,
    on_request: Option<Robj>,
    on_response: Option<Robj>,
}

impl Koon {
    fn fire_on_request_r(&self, method: &str, url: &str) {
        if let Some(ref f) = self.on_request {
            let _ = f.call(pairlist!(method, url));
        }
    }

    fn fire_on_response_r(&self, resp: &koon_core::HttpResponse) {
        if let Some(ref f) = self.on_response {
            let header_names: Vec<String> = resp.headers.iter().map(|(n, _)| n.clone()).collect();
            let header_values: Vec<String> = resp.headers.iter().map(|(_, v)| v.clone()).collect();
            let headers_df = data_frame!(name = header_names, value = header_values);
            let _ = f.call(pairlist!(resp.status as i32, &resp.url, headers_df));
        }
    }
}

#[extendr]
impl Koon {
    /// Create a new Koon client.
    ///
    /// @param browser Character string specifying the browser profile
    ///   (e.g. "chrome145", "firefox148", "safari183", "chromemobile145",
    ///   "firefoxmobile148", "safarimobile183", "okhttp4").
    /// @param proxy Optional proxy URL (e.g. "socks5://127.0.0.1:1080").
    /// @param proxies Optional character vector of proxy URLs for round-robin rotation.
    ///   Takes priority over `proxy`.
    /// @param timeout Request timeout in seconds (default: 30).
    /// @param randomize Logical; randomize fingerprint slightly (default: FALSE).
    /// @param headers Optional named character vector of custom headers.
    /// @param local_address Optional local IP address to bind outgoing connections to.
    /// @param on_request Optional function(method, url) called before each request.
    /// @param on_response Optional function(status, url, headers) called after each response.
    /// @param on_redirect Optional function(status, url, headers) called before following a redirect.
    ///   Return FALSE to stop redirecting and return the 3xx response.
    /// @param retries Number of automatic retries on transport errors (default: 0).
    /// @param locale Optional locale string (e.g. "fr-FR", "de") to generate a matching
    ///   Accept-Language header for the proxy's geography.
    /// @param proxy_headers Optional named character vector of headers for the HTTP CONNECT
    ///   tunnel request (e.g. session IDs, geo-targeting for Bright Data / Oxylabs).
    /// @param ip_version Optional integer (4 or 6) to restrict DNS resolution to IPv4 or IPv6.
    /// @param follow_redirects Logical; follow redirects automatically (default: TRUE).
    /// @param max_redirects Maximum number of redirects to follow (default: 10).
    /// @param cookie_jar Logical; enable built-in cookie jar (default: TRUE).
    /// @param session_resumption Logical; enable TLS session resumption (default: TRUE).
    /// @param ignore_tls_errors Logical; skip TLS certificate verification (default: FALSE).
    /// @param doh Optional DNS-over-HTTPS provider ("cloudflare" or "google").
    /// @return A new Koon client object.
    fn new(browser: &str, proxy: Nullable<String>, proxies: Robj, timeout: Nullable<i32>, randomize: Nullable<bool>, headers: Robj, local_address: Nullable<String>, on_request: Robj, on_response: Robj, on_redirect: Robj, retries: Nullable<i32>, locale: Nullable<String>, proxy_headers: Robj, ip_version: Nullable<i32>, follow_redirects: Nullable<bool>, max_redirects: Nullable<i32>, cookie_jar: Nullable<bool>, session_resumption: Nullable<bool>, ignore_tls_errors: Nullable<bool>, doh: Nullable<String>) -> Self {
        let mut profile = BrowserProfile::resolve(browser)
            .unwrap_or_else(|e| panic!("Unknown browser profile '{}': {}", browser, e));

        if let NotNull(true) = randomize {
            profile.randomize();
        }

        if let NotNull(true) = ignore_tls_errors {
            profile.tls.danger_accept_invalid_certs = true;
        }

        let timeout_s = match timeout {
            NotNull(t) => t as u64,
            Null => 30,
        };

        let custom_headers = parse_headers_robj(&headers);

        let do_follow = match follow_redirects { NotNull(v) => v, Null => true };
        let max_redir = match max_redirects { NotNull(v) => v as u32, Null => 10 };
        let do_cookies = match cookie_jar { NotNull(v) => v, Null => true };
        let do_session = match session_resumption { NotNull(v) => v, Null => true };

        let mut builder = Client::builder(profile)
            .timeout(Duration::from_secs(timeout_s))
            .headers(custom_headers)
            .follow_redirects(do_follow)
            .max_redirects(max_redir)
            .cookie_jar(do_cookies)
            .session_resumption(do_session);

        if let NotNull(ref loc) = locale {
            builder = builder.locale(loc);
        }

        let proxy_hdrs = parse_headers_robj(&proxy_headers);
        if !proxy_hdrs.is_empty() {
            builder = builder.proxy_headers(proxy_hdrs);
        }

        if let NotNull(ip_ver) = ip_version {
            let version = match ip_ver {
                4 => koon_core::IpVersion::V4,
                6 => koon_core::IpVersion::V6,
                other => panic!("Invalid ip_version: {other}. Must be 4 or 6."),
            };
            builder = builder.ip_version(version);
        }

        if !proxies.is_null() {
            if let Some(urls) = proxies.as_str_vector() {
                let refs: Vec<&str> = urls.iter().copied().collect();
                builder = builder
                    .proxies(&refs)
                    .unwrap_or_else(|e| panic!("Invalid proxies: {}", e));
            }
        } else if let NotNull(proxy_url) = proxy {
            builder = builder
                .proxy(&proxy_url)
                .unwrap_or_else(|e| panic!("Invalid proxy URL '{}': {}", proxy_url, e));
        }

        if let NotNull(addr_str) = local_address {
            let addr: std::net::IpAddr = addr_str
                .parse()
                .unwrap_or_else(|e| panic!("Invalid local_address '{}': {}", addr_str, e));
            builder = builder.local_address(addr);
        }

        if on_redirect.is_function() {
            let send_robj = Arc::new(UnsafeSendRobj(on_redirect.clone()));
            builder = builder.on_redirect(
                move |status: u16, url: &str, headers: &[(String, String)]| {
                    let header_names: Vec<String> = headers.iter().map(|(n, _)| n.clone()).collect();
                    let header_values: Vec<String> = headers.iter().map(|(_, v)| v.clone()).collect();
                    let headers_df = data_frame!(name = header_names, value = header_values);
                    match send_robj.0.call(pairlist!(status as i32, url, headers_df)) {
                        Ok(result) => {
                            // R FALSE → stop, anything else → continue
                            result.as_logical().map(|l| l.is_true()).unwrap_or(true)
                        }
                        Err(_) => true,
                    }
                },
            );
        }

        if let NotNull(n) = retries {
            if n > 0 {
                builder = builder.max_retries(n as u32);
            }
        }

        if let NotNull(ref doh_provider) = doh {
            let resolver = match doh_provider.as_str() {
                "cloudflare" => DohResolver::with_cloudflare(),
                "google" => DohResolver::with_google(),
                other => panic!("Unknown doh provider: '{}'. Use 'cloudflare' or 'google'.", other),
            };
            builder = builder.doh(
                resolver.unwrap_or_else(|e| panic!("Failed to create DoH resolver: {}", e))
            );
        }

        let client = builder
            .build()
            .unwrap_or_else(|e| panic!("Failed to build client: {}", e));

        let runtime = Runtime::new().expect("Failed to create tokio runtime");

        let on_req = if on_request.is_function() { Some(on_request) } else { None };
        let on_resp = if on_response.is_function() { Some(on_response) } else { None };

        Koon {
            client: Arc::new(client),
            runtime,
            on_request: on_req,
            on_response: on_resp,
        }
    }

    /// Perform an HTTP GET request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn get(&self, url: &str, headers: Robj) -> List {
        self.fire_on_request_r("GET", url);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("GET".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Perform an HTTP POST request.
    ///
    /// @param url The URL to request.
    /// @param body Optional character string or raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn post(&self, url: &str, body: Robj, headers: Robj) -> List {
        self.fire_on_request_r("POST", url);
        let body_bytes = extract_body_robj(&body);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("POST".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Perform an HTTP PUT request.
    ///
    /// @param url The URL to request.
    /// @param body Optional character string or raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn put(&self, url: &str, body: Robj, headers: Robj) -> List {
        self.fire_on_request_r("PUT", url);
        let body_bytes = extract_body_robj(&body);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("PUT".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Perform an HTTP DELETE request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn delete(&self, url: &str, headers: Robj) -> List {
        self.fire_on_request_r("DELETE", url);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("DELETE".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Perform an HTTP PATCH request.
    ///
    /// @param url The URL to request.
    /// @param body Optional character string or raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn patch(&self, url: &str, body: Robj, headers: Robj) -> List {
        self.fire_on_request_r("PATCH", url);
        let body_bytes = extract_body_robj(&body);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("PATCH".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Perform an HTTP HEAD request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn head(&self, url: &str, headers: Robj) -> List {
        self.fire_on_request_r("HEAD", url);
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("HEAD".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("{e}"));
        self.fire_on_response_r(&resp);
        response_to_list(resp)
    }

    /// Save the current session (cookies + TLS sessions) as a JSON string.
    ///
    /// @return A character string containing the session JSON.
    fn save_session(&self) -> String {
        self.client
            .save_session()
            .unwrap_or_else(|e| panic!("Failed to save session: {}", e))
    }

    /// Load a session (cookies + TLS sessions) from a JSON string.
    ///
    /// @param json A character string with session JSON (from save_session).
    fn load_session(&self, json: &str) {
        self.client
            .load_session(json)
            .unwrap_or_else(|e| panic!("Failed to load session: {}", e));
    }

    /// Export the current browser profile as a JSON string.
    ///
    /// @return A character string containing the profile JSON.
    fn export_profile(&self) -> String {
        self.client
            .profile()
            .to_json_pretty()
            .unwrap_or_else(|e| panic!("Failed to export profile: {}", e))
    }

    /// Get the total number of bytes sent across all requests.
    ///
    /// @return A numeric value (double) with the total bytes sent.
    fn total_bytes_sent(&self) -> f64 {
        self.client.total_bytes_sent() as f64
    }

    /// Get the total number of bytes received across all requests.
    ///
    /// @return A numeric value (double) with the total bytes received.
    fn total_bytes_received(&self) -> f64 {
        self.client.total_bytes_received() as f64
    }

    /// Reset both cumulative byte counters to zero.
    fn reset_counters(&self) {
        self.client.reset_counters();
    }

    /// Get the User-Agent string from the browser profile.
    ///
    /// @return A character string with the User-Agent, or NULL if not set.
    fn user_agent(&self) -> Nullable<String> {
        match self.client.user_agent() {
            Some(ua) => NotNull(ua.to_string()),
            None => Null,
        }
    }

    /// Clear all cookies from the cookie jar.
    ///
    /// Keeps TLS sessions, connection pool, and all other client state intact.
    fn clear_cookies(&self) {
        self.client.clear_cookies();
    }
}

/// List all available browser profile names.
///
/// @return A character vector of browser profile names.
/// @export
#[extendr]
fn koon_browsers() -> Vec<String> {
    let mut names = Vec::new();

    // Chrome 131-145
    for v in 131..=145 {
        names.push(format!("chrome{v}"));
    }
    // Chrome Mobile 131-145 (Android)
    for v in 131..=145 {
        names.push(format!("chromemobile{v}"));
    }
    // Firefox 135-148
    for v in 135..=148 {
        names.push(format!("firefox{v}"));
    }
    // Firefox Mobile 135-148 (Android)
    for v in 135..=148 {
        names.push(format!("firefoxmobile{v}"));
    }
    // Safari (macOS)
    for tag in &["156", "160", "170", "180", "183"] {
        names.push(format!("safari{tag}"));
    }
    // Safari Mobile (iOS)
    for tag in &["156", "160", "170", "180", "183"] {
        names.push(format!("safarimobile{tag}"));
    }
    // Edge 131-145
    for v in 131..=145 {
        names.push(format!("edge{v}"));
    }
    // Opera 124-127
    for v in 124..=127 {
        names.push(format!("opera{v}"));
    }
    // OkHttp (Android)
    names.push("okhttp4".to_string());
    names.push("okhttp5".to_string());

    names
}

extendr_module! {
    mod koon;
    impl Koon;
    fn koon_browsers;
}
