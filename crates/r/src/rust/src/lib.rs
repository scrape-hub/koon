use extendr_api::prelude::*;
use koon_core::profile::BrowserProfile;
use koon_core::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Convert an HttpResponse to an R list with status, ok, headers, body, version, url, text.
fn response_to_list(resp: koon_core::HttpResponse) -> List {
    let ok = resp.status >= 200 && resp.status < 300;
    let text = String::from_utf8_lossy(&resp.body).into_owned();

    let header_names: Vec<String> = resp.headers.iter().map(|(n, _)| n.clone()).collect();
    let header_values: Vec<String> = resp.headers.iter().map(|(_, v)| v.clone()).collect();
    let headers_df = data_frame!(name = header_names, value = header_values);

    list!(
        status = resp.status as i32,
        ok = ok,
        version = resp.version,
        url = resp.url,
        body = Raw::from_bytes(&resp.body),
        text = text,
        headers = headers_df
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
}

#[extendr]
impl Koon {
    /// Create a new Koon client.
    ///
    /// @param browser Character string specifying the browser profile
    ///   (e.g. "chrome145", "firefox147", "safari183").
    /// @param proxy Optional proxy URL (e.g. "socks5://127.0.0.1:1080").
    /// @param proxies Optional character vector of proxy URLs for round-robin rotation.
    ///   Takes priority over `proxy`.
    /// @param timeout Request timeout in milliseconds (default: 30000).
    /// @param randomize Logical; randomize fingerprint slightly (default: FALSE).
    /// @param headers Optional named character vector of custom headers.
    /// @param local_address Optional local IP address to bind outgoing connections to.
    /// @return A new Koon client object.
    fn new(browser: &str, proxy: Nullable<String>, proxies: Robj, timeout: Nullable<i32>, randomize: Nullable<bool>, headers: Robj, local_address: Nullable<String>) -> Self {
        let mut profile = BrowserProfile::resolve(browser)
            .unwrap_or_else(|e| panic!("Unknown browser profile '{}': {}", browser, e));

        if let NotNull(true) = randomize {
            profile.randomize();
        }

        let timeout_ms = match timeout {
            NotNull(t) => t as u64,
            Null => 30000,
        };

        let custom_headers = parse_headers_robj(&headers);

        let mut builder = Client::builder(profile)
            .timeout(Duration::from_millis(timeout_ms))
            .headers(custom_headers)
            .follow_redirects(true)
            .max_redirects(10)
            .cookie_jar(true)
            .session_resumption(true);

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

        let client = builder
            .build()
            .unwrap_or_else(|e| panic!("Failed to build client: {}", e));

        let runtime = Runtime::new().expect("Failed to create tokio runtime");

        Koon {
            client: Arc::new(client),
            runtime,
        }
    }

    /// Perform an HTTP GET request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn get(&self, url: &str, headers: Robj) -> List {
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("GET".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("GET {} failed: {}", url, e));
        response_to_list(resp)
    }

    /// Perform an HTTP POST request.
    ///
    /// @param url The URL to request.
    /// @param body Optional raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn post(&self, url: &str, body: Nullable<Raw>, headers: Robj) -> List {
        let body_bytes = match body {
            NotNull(r) => Some(r.as_slice().to_vec()),
            Null => None,
        };
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("POST".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("POST {} failed: {}", url, e));
        response_to_list(resp)
    }

    /// Perform an HTTP PUT request.
    ///
    /// @param url The URL to request.
    /// @param body Optional raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn put(&self, url: &str, body: Nullable<Raw>, headers: Robj) -> List {
        let body_bytes = match body {
            NotNull(r) => Some(r.as_slice().to_vec()),
            Null => None,
        };
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("PUT".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("PUT {} failed: {}", url, e));
        response_to_list(resp)
    }

    /// Perform an HTTP DELETE request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn delete(&self, url: &str, headers: Robj) -> List {
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("DELETE".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("DELETE {} failed: {}", url, e));
        response_to_list(resp)
    }

    /// Perform an HTTP PATCH request.
    ///
    /// @param url The URL to request.
    /// @param body Optional raw vector with the request body.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn patch(&self, url: &str, body: Nullable<Raw>, headers: Robj) -> List {
        let body_bytes = match body {
            NotNull(r) => Some(r.as_slice().to_vec()),
            Null => None,
        };
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("PATCH".parse().unwrap(), url, body_bytes, extra))
            .unwrap_or_else(|e| panic!("PATCH {} failed: {}", url, e));
        response_to_list(resp)
    }

    /// Perform an HTTP HEAD request.
    ///
    /// @param url The URL to request.
    /// @param headers Optional named character vector of per-request headers.
    /// @return A list with components: status, version, url, body (raw), text, headers (data.frame).
    fn head(&self, url: &str, headers: Robj) -> List {
        let extra = parse_headers_robj(&headers);
        let resp = self
            .runtime
            .block_on(self.client.request_with_headers("HEAD".parse().unwrap(), url, None, extra))
            .unwrap_or_else(|e| panic!("HEAD {} failed: {}", url, e));
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
    // Firefox 135-147
    for v in 135..=147 {
        names.push(format!("firefox{v}"));
    }
    // Safari
    for tag in &["156", "160", "170", "180", "183"] {
        names.push(format!("safari{tag}"));
    }
    // Edge 131-145
    for v in 131..=145 {
        names.push(format!("edge{v}"));
    }
    // Opera 124-127
    for v in 124..=127 {
        names.push(format!("opera{v}"));
    }

    names
}

extendr_module! {
    mod koon;
    impl Koon;
    fn koon_browsers;
}
