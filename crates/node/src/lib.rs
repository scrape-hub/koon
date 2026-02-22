use napi::bindgen_prelude::*;
use napi_derive::napi;
use koon_core::dns::DohResolver;
use koon_core::multipart::Multipart;
use koon_core::profile::BrowserProfile;
use koon_core::{Client, HeaderMode, ProxyServer, ProxyServerConfig};
use std::collections::HashMap;
use std::time::Duration;

/// Supported browser profiles for impersonation.
///
/// Format: `{browser}{version?}{os?}`
/// - browser: chrome, firefox, safari, edge, opera
/// - version: optional version number (e.g. 145, 147)
/// - os: optional OS suffix (windows, macos, linux)
///
/// Examples: "chrome", "chrome145", "chrome145windows", "firefox147macos"
#[napi(string_enum = "lowercase")]
pub enum Browser {
    // Chrome
    Chrome,
    Chrome131, Chrome131Windows, Chrome131Macos, Chrome131Linux,
    Chrome132, Chrome132Windows, Chrome132Macos, Chrome132Linux,
    Chrome133, Chrome133Windows, Chrome133Macos, Chrome133Linux,
    Chrome134, Chrome134Windows, Chrome134Macos, Chrome134Linux,
    Chrome135, Chrome135Windows, Chrome135Macos, Chrome135Linux,
    Chrome136, Chrome136Windows, Chrome136Macos, Chrome136Linux,
    Chrome137, Chrome137Windows, Chrome137Macos, Chrome137Linux,
    Chrome138, Chrome138Windows, Chrome138Macos, Chrome138Linux,
    Chrome139, Chrome139Windows, Chrome139Macos, Chrome139Linux,
    Chrome140, Chrome140Windows, Chrome140Macos, Chrome140Linux,
    Chrome141, Chrome141Windows, Chrome141Macos, Chrome141Linux,
    Chrome142, Chrome142Windows, Chrome142Macos, Chrome142Linux,
    Chrome143, Chrome143Windows, Chrome143Macos, Chrome143Linux,
    Chrome144, Chrome144Windows, Chrome144Macos, Chrome144Linux,
    Chrome145, Chrome145Windows, Chrome145Macos, Chrome145Linux,
    // Firefox
    Firefox,
    Firefox135, Firefox135Windows, Firefox135Macos, Firefox135Linux,
    Firefox136, Firefox136Windows, Firefox136Macos, Firefox136Linux,
    Firefox137, Firefox137Windows, Firefox137Macos, Firefox137Linux,
    Firefox138, Firefox138Windows, Firefox138Macos, Firefox138Linux,
    Firefox139, Firefox139Windows, Firefox139Macos, Firefox139Linux,
    Firefox140, Firefox140Windows, Firefox140Macos, Firefox140Linux,
    Firefox141, Firefox141Windows, Firefox141Macos, Firefox141Linux,
    Firefox142, Firefox142Windows, Firefox142Macos, Firefox142Linux,
    Firefox143, Firefox143Windows, Firefox143Macos, Firefox143Linux,
    Firefox144, Firefox144Windows, Firefox144Macos, Firefox144Linux,
    Firefox145, Firefox145Windows, Firefox145Macos, Firefox145Linux,
    Firefox146, Firefox146Windows, Firefox146Macos, Firefox146Linux,
    Firefox147, Firefox147Windows, Firefox147Macos, Firefox147Linux,
    // Safari
    Safari,
    Safari156, Safari156Macos,
    Safari160, Safari160Macos,
    Safari170, Safari170Macos,
    Safari180, Safari180Macos,
    Safari183, Safari183Macos,
    // Opera
    Opera,
    Opera124, Opera124Windows, Opera124Macos, Opera124Linux,
    Opera125, Opera125Windows, Opera125Macos, Opera125Linux,
    Opera126, Opera126Windows, Opera126Macos, Opera126Linux,
    Opera127, Opera127Windows, Opera127Macos, Opera127Linux,
    // Edge
    Edge,
    Edge131, Edge131Windows, Edge131Macos,
    Edge132, Edge132Windows, Edge132Macos,
    Edge133, Edge133Windows, Edge133Macos,
    Edge134, Edge134Windows, Edge134Macos,
    Edge135, Edge135Windows, Edge135Macos,
    Edge136, Edge136Windows, Edge136Macos,
    Edge137, Edge137Windows, Edge137Macos,
    Edge138, Edge138Windows, Edge138Macos,
    Edge139, Edge139Windows, Edge139Macos,
    Edge140, Edge140Windows, Edge140Macos,
    Edge141, Edge141Windows, Edge141Macos,
    Edge142, Edge142Windows, Edge142Macos,
    Edge143, Edge143Windows, Edge143Macos,
    Edge144, Edge144Windows, Edge144Macos,
    Edge145, Edge145Windows, Edge145Macos,
}

/// Convert a Browser enum variant to its napi lowercase string representation.
fn browser_to_name(browser: &Browser) -> &'static str {
    match browser {
        Browser::Chrome => "chrome",
        Browser::Chrome131 => "chrome131", Browser::Chrome131Windows => "chrome131windows",
        Browser::Chrome131Macos => "chrome131macos", Browser::Chrome131Linux => "chrome131linux",
        Browser::Chrome132 => "chrome132", Browser::Chrome132Windows => "chrome132windows",
        Browser::Chrome132Macos => "chrome132macos", Browser::Chrome132Linux => "chrome132linux",
        Browser::Chrome133 => "chrome133", Browser::Chrome133Windows => "chrome133windows",
        Browser::Chrome133Macos => "chrome133macos", Browser::Chrome133Linux => "chrome133linux",
        Browser::Chrome134 => "chrome134", Browser::Chrome134Windows => "chrome134windows",
        Browser::Chrome134Macos => "chrome134macos", Browser::Chrome134Linux => "chrome134linux",
        Browser::Chrome135 => "chrome135", Browser::Chrome135Windows => "chrome135windows",
        Browser::Chrome135Macos => "chrome135macos", Browser::Chrome135Linux => "chrome135linux",
        Browser::Chrome136 => "chrome136", Browser::Chrome136Windows => "chrome136windows",
        Browser::Chrome136Macos => "chrome136macos", Browser::Chrome136Linux => "chrome136linux",
        Browser::Chrome137 => "chrome137", Browser::Chrome137Windows => "chrome137windows",
        Browser::Chrome137Macos => "chrome137macos", Browser::Chrome137Linux => "chrome137linux",
        Browser::Chrome138 => "chrome138", Browser::Chrome138Windows => "chrome138windows",
        Browser::Chrome138Macos => "chrome138macos", Browser::Chrome138Linux => "chrome138linux",
        Browser::Chrome139 => "chrome139", Browser::Chrome139Windows => "chrome139windows",
        Browser::Chrome139Macos => "chrome139macos", Browser::Chrome139Linux => "chrome139linux",
        Browser::Chrome140 => "chrome140", Browser::Chrome140Windows => "chrome140windows",
        Browser::Chrome140Macos => "chrome140macos", Browser::Chrome140Linux => "chrome140linux",
        Browser::Chrome141 => "chrome141", Browser::Chrome141Windows => "chrome141windows",
        Browser::Chrome141Macos => "chrome141macos", Browser::Chrome141Linux => "chrome141linux",
        Browser::Chrome142 => "chrome142", Browser::Chrome142Windows => "chrome142windows",
        Browser::Chrome142Macos => "chrome142macos", Browser::Chrome142Linux => "chrome142linux",
        Browser::Chrome143 => "chrome143", Browser::Chrome143Windows => "chrome143windows",
        Browser::Chrome143Macos => "chrome143macos", Browser::Chrome143Linux => "chrome143linux",
        Browser::Chrome144 => "chrome144", Browser::Chrome144Windows => "chrome144windows",
        Browser::Chrome144Macos => "chrome144macos", Browser::Chrome144Linux => "chrome144linux",
        Browser::Chrome145 => "chrome145", Browser::Chrome145Windows => "chrome145windows",
        Browser::Chrome145Macos => "chrome145macos", Browser::Chrome145Linux => "chrome145linux",
        Browser::Firefox => "firefox",
        Browser::Firefox135 => "firefox135", Browser::Firefox135Windows => "firefox135windows",
        Browser::Firefox135Macos => "firefox135macos", Browser::Firefox135Linux => "firefox135linux",
        Browser::Firefox136 => "firefox136", Browser::Firefox136Windows => "firefox136windows",
        Browser::Firefox136Macos => "firefox136macos", Browser::Firefox136Linux => "firefox136linux",
        Browser::Firefox137 => "firefox137", Browser::Firefox137Windows => "firefox137windows",
        Browser::Firefox137Macos => "firefox137macos", Browser::Firefox137Linux => "firefox137linux",
        Browser::Firefox138 => "firefox138", Browser::Firefox138Windows => "firefox138windows",
        Browser::Firefox138Macos => "firefox138macos", Browser::Firefox138Linux => "firefox138linux",
        Browser::Firefox139 => "firefox139", Browser::Firefox139Windows => "firefox139windows",
        Browser::Firefox139Macos => "firefox139macos", Browser::Firefox139Linux => "firefox139linux",
        Browser::Firefox140 => "firefox140", Browser::Firefox140Windows => "firefox140windows",
        Browser::Firefox140Macos => "firefox140macos", Browser::Firefox140Linux => "firefox140linux",
        Browser::Firefox141 => "firefox141", Browser::Firefox141Windows => "firefox141windows",
        Browser::Firefox141Macos => "firefox141macos", Browser::Firefox141Linux => "firefox141linux",
        Browser::Firefox142 => "firefox142", Browser::Firefox142Windows => "firefox142windows",
        Browser::Firefox142Macos => "firefox142macos", Browser::Firefox142Linux => "firefox142linux",
        Browser::Firefox143 => "firefox143", Browser::Firefox143Windows => "firefox143windows",
        Browser::Firefox143Macos => "firefox143macos", Browser::Firefox143Linux => "firefox143linux",
        Browser::Firefox144 => "firefox144", Browser::Firefox144Windows => "firefox144windows",
        Browser::Firefox144Macos => "firefox144macos", Browser::Firefox144Linux => "firefox144linux",
        Browser::Firefox145 => "firefox145", Browser::Firefox145Windows => "firefox145windows",
        Browser::Firefox145Macos => "firefox145macos", Browser::Firefox145Linux => "firefox145linux",
        Browser::Firefox146 => "firefox146", Browser::Firefox146Windows => "firefox146windows",
        Browser::Firefox146Macos => "firefox146macos", Browser::Firefox146Linux => "firefox146linux",
        Browser::Firefox147 => "firefox147", Browser::Firefox147Windows => "firefox147windows",
        Browser::Firefox147Macos => "firefox147macos", Browser::Firefox147Linux => "firefox147linux",
        Browser::Safari => "safari",
        Browser::Safari156 | Browser::Safari156Macos => "safari156",
        Browser::Safari160 | Browser::Safari160Macos => "safari160",
        Browser::Safari170 | Browser::Safari170Macos => "safari170",
        Browser::Safari180 | Browser::Safari180Macos => "safari180",
        Browser::Safari183 | Browser::Safari183Macos => "safari183",
        Browser::Opera => "opera",
        Browser::Opera124 => "opera124", Browser::Opera124Windows => "opera124windows",
        Browser::Opera124Macos => "opera124macos", Browser::Opera124Linux => "opera124linux",
        Browser::Opera125 => "opera125", Browser::Opera125Windows => "opera125windows",
        Browser::Opera125Macos => "opera125macos", Browser::Opera125Linux => "opera125linux",
        Browser::Opera126 => "opera126", Browser::Opera126Windows => "opera126windows",
        Browser::Opera126Macos => "opera126macos", Browser::Opera126Linux => "opera126linux",
        Browser::Opera127 => "opera127", Browser::Opera127Windows => "opera127windows",
        Browser::Opera127Macos => "opera127macos", Browser::Opera127Linux => "opera127linux",
        Browser::Edge => "edge",
        Browser::Edge131 => "edge131", Browser::Edge131Windows => "edge131windows", Browser::Edge131Macos => "edge131macos",
        Browser::Edge132 => "edge132", Browser::Edge132Windows => "edge132windows", Browser::Edge132Macos => "edge132macos",
        Browser::Edge133 => "edge133", Browser::Edge133Windows => "edge133windows", Browser::Edge133Macos => "edge133macos",
        Browser::Edge134 => "edge134", Browser::Edge134Windows => "edge134windows", Browser::Edge134Macos => "edge134macos",
        Browser::Edge135 => "edge135", Browser::Edge135Windows => "edge135windows", Browser::Edge135Macos => "edge135macos",
        Browser::Edge136 => "edge136", Browser::Edge136Windows => "edge136windows", Browser::Edge136Macos => "edge136macos",
        Browser::Edge137 => "edge137", Browser::Edge137Windows => "edge137windows", Browser::Edge137Macos => "edge137macos",
        Browser::Edge138 => "edge138", Browser::Edge138Windows => "edge138windows", Browser::Edge138Macos => "edge138macos",
        Browser::Edge139 => "edge139", Browser::Edge139Windows => "edge139windows", Browser::Edge139Macos => "edge139macos",
        Browser::Edge140 => "edge140", Browser::Edge140Windows => "edge140windows", Browser::Edge140Macos => "edge140macos",
        Browser::Edge141 => "edge141", Browser::Edge141Windows => "edge141windows", Browser::Edge141Macos => "edge141macos",
        Browser::Edge142 => "edge142", Browser::Edge142Windows => "edge142windows", Browser::Edge142Macos => "edge142macos",
        Browser::Edge143 => "edge143", Browser::Edge143Windows => "edge143windows", Browser::Edge143Macos => "edge143macos",
        Browser::Edge144 => "edge144", Browser::Edge144Windows => "edge144windows", Browser::Edge144Macos => "edge144macos",
        Browser::Edge145 => "edge145", Browser::Edge145Windows => "edge145windows", Browser::Edge145Macos => "edge145macos",
    }
}

/// Resolve a Browser enum to a BrowserProfile via core's resolve().
fn resolve_browser(browser: &Browser) -> Result<BrowserProfile> {
    BrowserProfile::resolve(browser_to_name(browser))
        .map_err(napi::Error::from_reason)
}

/// Options for creating a Koon client.
#[napi(object)]
#[derive(Default)]
pub struct KoonOptions {
    /// Browser to impersonate.
    /// @default 'chrome' (latest Chrome on Windows)
    pub browser: Option<Browser>,

    /// Custom browser profile as JSON string.
    /// Overrides the `browser` option when provided.
    /// Use `exportProfile()` to get a profile template.
    pub profile_json: Option<String>,

    /// Proxy URL (http://, https://, socks5://).
    /// Supports authentication: socks5://user:pass@host:port
    pub proxy: Option<String>,

    /// Request timeout in milliseconds.
    /// @default 30000
    pub timeout: Option<u32>,

    /// Skip TLS certificate verification.
    /// @default false
    pub ignore_tls_errors: Option<bool>,

    /// Additional headers to send with every request.
    /// These override browser profile defaults.
    #[napi(ts_type = "Record<string, string>")]
    pub headers: Option<std::collections::HashMap<String, String>>,

    /// Follow redirects automatically.
    /// @default true
    pub follow_redirects: Option<bool>,

    /// Maximum number of redirects to follow.
    /// @default 10
    pub max_redirects: Option<u32>,

    /// Enable built-in cookie jar.
    /// @default true
    pub cookie_jar: Option<bool>,

    /// Randomize the browser fingerprint slightly (UA build, accept-language q-val, H2 window jitter).
    /// @default false
    pub randomize: Option<bool>,

    /// Enable TLS session resumption for faster subsequent connections.
    /// @default true
    pub session_resumption: Option<bool>,

    /// DNS-over-HTTPS provider for encrypted DNS and ECH support.
    /// Supported values: 'cloudflare', 'google'.
    pub doh: Option<String>,
}

/// A single HTTP header (name-value pair).
/// Using an array instead of a map preserves duplicate headers like Set-Cookie.
#[derive(Clone)]
#[napi(object)]
pub struct KoonHeader {
    /// Header name (lowercase).
    pub name: String,
    /// Header value.
    pub value: String,
}

/// Response from an HTTP request.
#[napi(object)]
pub struct KoonResponse {
    /// HTTP status code.
    pub status: u32,

    /// Response headers as an array of name-value pairs.
    /// Preserves duplicate headers (e.g. multiple Set-Cookie).
    pub headers: Vec<KoonHeader>,

    /// Response body as a Buffer.
    pub body: Buffer,

    /// HTTP version used (e.g. "h2").
    pub version: String,

    /// Final URL after redirects.
    pub url: String,
}

/// A field in a multipart/form-data request.
/// Provide either `value` (text field) or `fileData` (file upload).
#[napi(object)]
pub struct KoonMultipartField {
    /// Field name.
    pub name: String,
    /// Text value (for text fields).
    pub value: Option<String>,
    /// File content (for file uploads, mutually exclusive with `value`).
    pub file_data: Option<Buffer>,
    /// Filename for file uploads.
    pub filename: Option<String>,
    /// Content-Type for file uploads.
    /// @default "application/octet-stream"
    pub content_type: Option<String>,
}

/// The main Koon HTTP client with browser fingerprint impersonation.
///
/// @example
/// ```ts
/// import { Koon } from 'koon';
///
/// // Use a built-in profile
/// const client = new Koon({ browser: 'chrome' });
/// const response = await client.get('https://tls.peet.ws/api/all');
/// console.log(response.status);
/// console.log(Buffer.from(response.body).toString());
///
/// // Or load a custom JSON profile
/// const custom = new Koon({ profile_json: fs.readFileSync('my-chrome.json', 'utf8') });
/// ```
#[napi]
pub struct Koon {
    client: Client,
}

#[napi]
impl Koon {
    #[napi(constructor)]
    pub fn new(options: Option<KoonOptions>) -> Result<Self> {
        let opts = options.unwrap_or_default();

        let mut profile = if let Some(ref json) = opts.profile_json {
            BrowserProfile::from_json(json).map_err(|e| {
                napi::Error::from_reason(format!("Invalid profile JSON: {e}"))
            })?
        } else {
            match opts.browser {
                Some(ref b) => resolve_browser(b)?,
                None => BrowserProfile::resolve("chrome").unwrap(),
            }
        };

        if opts.ignore_tls_errors.unwrap_or(false) {
            profile.tls.danger_accept_invalid_certs = true;
        }

        if opts.randomize.unwrap_or(false) {
            profile.randomize();
        }

        let timeout = Duration::from_millis(opts.timeout.unwrap_or(30000) as u64);

        let custom_headers: Vec<(String, String)> = opts
            .headers
            .unwrap_or_default()
            .into_iter()
            .collect();

        let mut builder = Client::builder(profile)
            .timeout(timeout)
            .headers(custom_headers)
            .follow_redirects(opts.follow_redirects.unwrap_or(true))
            .max_redirects(opts.max_redirects.unwrap_or(10))
            .cookie_jar(opts.cookie_jar.unwrap_or(true))
            .session_resumption(opts.session_resumption.unwrap_or(true));

        if let Some(ref proxy_url) = opts.proxy {
            builder = builder.proxy(proxy_url).map_err(|e| {
                napi::Error::from_reason(format!("Invalid proxy: {e}"))
            })?;
        }

        if let Some(ref doh_provider) = opts.doh {
            let resolver = match doh_provider.to_lowercase().as_str() {
                "cloudflare" => DohResolver::with_cloudflare(),
                "google" => DohResolver::with_google(),
                other => {
                    return Err(napi::Error::from_reason(format!(
                        "Unknown DoH provider: '{other}'. Supported: 'cloudflare', 'google'"
                    )));
                }
            }
            .map_err(|e| napi::Error::from_reason(format!("Failed to create DoH resolver: {e}")))?;
            builder = builder.doh(resolver);
        }

        let client = builder.build().map_err(|e| {
            napi::Error::from_reason(format!("Failed to create client: {e}"))
        })?;

        Ok(Koon { client })
    }

    /// Export the current browser profile as a JSON string.
    /// Useful for customizing and reloading profiles.
    #[napi]
    pub fn export_profile(&self) -> Result<String> {
        self.client.profile().to_json_pretty().map_err(|e| {
            napi::Error::from_reason(format!("Failed to export profile: {e}"))
        })
    }

    /// Perform an HTTP GET request.
    #[napi]
    pub async fn get(&self, url: String) -> Result<KoonResponse> {
        self.request("GET".to_string(), url, None).await
    }

    /// Perform an HTTP POST request.
    #[napi]
    pub async fn post(&self, url: String, body: Option<Buffer>) -> Result<KoonResponse> {
        self.request("POST".to_string(), url, body).await
    }

    /// Perform an HTTP PUT request.
    #[napi]
    pub async fn put(&self, url: String, body: Option<Buffer>) -> Result<KoonResponse> {
        self.request("PUT".to_string(), url, body).await
    }

    /// Perform an HTTP DELETE request.
    #[napi]
    pub async fn delete(&self, url: String) -> Result<KoonResponse> {
        self.request("DELETE".to_string(), url, None).await
    }

    /// Perform an HTTP PATCH request.
    #[napi]
    pub async fn patch(&self, url: String, body: Option<Buffer>) -> Result<KoonResponse> {
        self.request("PATCH".to_string(), url, body).await
    }

    /// Perform an HTTP HEAD request.
    #[napi]
    pub async fn head(&self, url: String) -> Result<KoonResponse> {
        self.request("HEAD".to_string(), url, None).await
    }

    /// Perform an HTTP request with a custom method.
    #[napi]
    pub async fn request(
        &self,
        method: String,
        url: String,
        body: Option<Buffer>,
    ) -> Result<KoonResponse> {
        let method = method.parse().map_err(|_| {
            napi::Error::from_reason(format!("Invalid HTTP method: {method}"))
        })?;

        let body_bytes = body.map(|b| b.to_vec());

        let response = self
            .client
            .request(method, &url, body_bytes)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Request failed: {e}")))?;

        let headers: Vec<KoonHeader> = response
            .headers
            .into_iter()
            .map(|(name, value)| KoonHeader { name, value })
            .collect();

        Ok(KoonResponse {
            status: response.status as u32,
            headers,
            body: response.body.into(),
            version: response.version,
            url: response.url,
        })
    }

    /// Perform an HTTP POST request with multipart/form-data body.
    ///
    /// @example
    /// ```ts
    /// const response = await client.postMultipart('https://httpbin.org/post', [
    ///   { name: 'field', value: 'hello' },
    ///   { name: 'file', fileData: Buffer.from('content'), filename: 'test.txt', contentType: 'text/plain' },
    /// ]);
    /// ```
    #[napi]
    pub async fn post_multipart(
        &self,
        url: String,
        fields: Vec<KoonMultipartField>,
    ) -> Result<KoonResponse> {
        let mut mp = Multipart::new();
        for field in fields {
            if let Some(file_data) = field.file_data {
                mp = mp.file(
                    field.name,
                    field.filename.unwrap_or_else(|| "file".to_string()),
                    field.content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                    file_data.to_vec(),
                );
            } else if let Some(value) = field.value {
                mp = mp.text(field.name, value);
            }
        }

        let response = self
            .client
            .post_multipart(&url, mp)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Request failed: {e}")))?;

        let headers: Vec<KoonHeader> = response
            .headers
            .into_iter()
            .map(|(name, value)| KoonHeader { name, value })
            .collect();

        Ok(KoonResponse {
            status: response.status as u32,
            headers,
            body: response.body.into(),
            version: response.version,
            url: response.url,
        })
    }

    /// Perform a streaming HTTP request.
    /// The response body is delivered in chunks via `nextChunk()`.
    /// Does NOT follow redirects — handle 3xx responses manually.
    ///
    /// @example
    /// ```ts
    /// const resp = await client.requestStreaming('GET', 'https://example.com/large-file');
    /// let chunk;
    /// while ((chunk = await resp.nextChunk()) !== null) {
    ///   process(chunk);
    /// }
    /// ```
    #[napi]
    pub async fn request_streaming(
        &self,
        method: String,
        url: String,
        body: Option<Buffer>,
    ) -> Result<KoonStreamingResponse> {
        let method = method.parse().map_err(|_| {
            napi::Error::from_reason(format!("Invalid HTTP method: {method}"))
        })?;
        let body_bytes = body.map(|b| b.to_vec());

        let resp = self
            .client
            .request_streaming(method, &url, body_bytes)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Request failed: {e}")))?;

        let headers: Vec<KoonHeader> = resp
            .headers
            .iter()
            .map(|(name, value)| KoonHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();

        Ok(KoonStreamingResponse {
            status_val: resp.status as u32,
            headers_val: headers,
            version_val: resp.version.clone(),
            url_val: resp.url.clone(),
            inner: tokio::sync::Mutex::new(Some(resp)),
        })
    }

    /// Save the current session (cookies + TLS sessions) as a JSON string.
    /// The returned string can later be passed to `loadSession()` to restore state.
    ///
    /// @example
    /// ```ts
    /// const json = client.saveSession();
    /// fs.writeFileSync('session.json', json);
    /// ```
    #[napi]
    pub fn save_session(&self) -> Result<String> {
        self.client
            .save_session()
            .map_err(|e| napi::Error::from_reason(format!("Failed to save session: {e}")))
    }

    /// Load a session (cookies + TLS sessions) from a JSON string.
    ///
    /// @example
    /// ```ts
    /// const json = fs.readFileSync('session.json', 'utf8');
    /// client.loadSession(json);
    /// ```
    #[napi]
    pub fn load_session(&self, json: String) -> Result<()> {
        self.client
            .load_session(&json)
            .map_err(|e| napi::Error::from_reason(format!("Failed to load session: {e}")))
    }

    /// Save the current session to a file.
    #[napi]
    pub fn save_session_to_file(&self, path: String) -> Result<()> {
        self.client
            .save_session_to_file(&path)
            .map_err(|e| napi::Error::from_reason(format!("Failed to save session to file: {e}")))
    }

    /// Load a session from a file.
    #[napi]
    pub fn load_session_from_file(&self, path: String) -> Result<()> {
        self.client
            .load_session_from_file(&path)
            .map_err(|e| napi::Error::from_reason(format!("Failed to load session from file: {e}")))
    }

    /// Open a WebSocket connection to a wss:// URL.
    ///
    /// @example
    /// ```ts
    /// const ws = await client.websocket('wss://echo.websocket.events');
    /// await ws.send('Hello');
    /// const msg = await ws.receive();
    /// console.log(Buffer.from(msg.data).toString()); // "Hello"
    /// await ws.close(1000, 'done');
    /// ```
    #[napi]
    pub async fn websocket(
        &self,
        url: String,
        headers: Option<HashMap<String, String>>,
    ) -> Result<KoonWebSocket> {
        let extra_headers: Vec<(String, String)> = headers
            .unwrap_or_default()
            .into_iter()
            .collect();

        let ws = self
            .client
            .websocket_with_headers(&url, extra_headers)
            .await
            .map_err(|e| napi::Error::from_reason(format!("WebSocket connect failed: {e}")))?;

        Ok(KoonWebSocket {
            inner: tokio::sync::Mutex::new(Some(ws)),
        })
    }
}

/// A streaming HTTP response that delivers the body in chunks.
#[napi]
pub struct KoonStreamingResponse {
    inner: tokio::sync::Mutex<Option<koon_core::StreamingResponse>>,
    status_val: u32,
    headers_val: Vec<KoonHeader>,
    version_val: String,
    url_val: String,
}

#[napi]
impl KoonStreamingResponse {
    /// HTTP status code.
    #[napi(getter)]
    pub fn status(&self) -> u32 {
        self.status_val
    }

    /// Response headers.
    #[napi(getter)]
    pub fn headers(&self) -> Vec<KoonHeader> {
        self.headers_val.clone()
    }

    /// HTTP version used.
    #[napi(getter)]
    pub fn version(&self) -> String {
        self.version_val.clone()
    }

    /// Request URL.
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url_val.clone()
    }

    /// Get the next body chunk. Returns null when the body is complete.
    #[napi]
    pub async fn next_chunk(&self) -> Result<Option<Buffer>> {
        let mut guard = self.inner.lock().await;
        let resp = guard
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("Stream already consumed"))?;

        match resp.next_chunk().await {
            Some(Ok(data)) => Ok(Some(data.into())),
            Some(Err(e)) => Err(napi::Error::from_reason(format!("Stream error: {e}"))),
            None => Ok(None),
        }
    }

    /// Collect the entire remaining body into a single Buffer.
    /// Consumes the streaming response.
    #[napi]
    pub async fn collect(&self) -> Result<Buffer> {
        let mut guard = self.inner.lock().await;
        let resp = guard
            .take()
            .ok_or_else(|| napi::Error::from_reason("Stream already consumed"))?;

        let body = resp
            .collect_body()
            .await
            .map_err(|e| napi::Error::from_reason(format!("Stream error: {e}")))?;

        Ok(body.into())
    }
}

/// A WebSocket message received from the server.
#[napi(object)]
pub struct KoonWsMessage {
    /// Whether the message is text (true) or binary (false).
    pub is_text: bool,
    /// The message payload.
    pub data: Buffer,
}

/// A WebSocket connection with browser-fingerprinted TLS.
#[napi]
pub struct KoonWebSocket {
    inner: tokio::sync::Mutex<Option<koon_core::websocket::WebSocket>>,
}

#[napi]
impl KoonWebSocket {
    /// Send a text or binary message.
    /// Pass a string for text, or a Buffer for binary.
    #[napi]
    pub async fn send(&self, data: Either<String, Buffer>) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let ws = guard
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("WebSocket is closed"))?;

        match data {
            Either::A(text) => ws.send_text(&text).await,
            Either::B(buf) => ws.send_binary(&buf).await,
        }
        .map_err(|e| napi::Error::from_reason(format!("WebSocket send failed: {e}")))
    }

    /// Receive the next message from the server.
    /// Returns null if the connection is closed.
    #[napi]
    pub async fn receive(&self) -> Result<Option<KoonWsMessage>> {
        let mut guard = self.inner.lock().await;
        let ws = guard
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("WebSocket is closed"))?;

        match ws.receive().await {
            Ok(Some(koon_core::websocket::Message::Text(t))) => Ok(Some(KoonWsMessage {
                is_text: true,
                data: Buffer::from(t.as_bytes().to_vec()),
            })),
            Ok(Some(koon_core::websocket::Message::Binary(b))) => Ok(Some(KoonWsMessage {
                is_text: false,
                data: Buffer::from(b),
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(napi::Error::from_reason(format!(
                "WebSocket receive failed: {e}"
            ))),
        }
    }

    /// Close the WebSocket connection.
    #[napi]
    pub async fn close(&self, code: Option<u32>, reason: Option<String>) -> Result<()> {
        let mut guard = self.inner.lock().await;
        let ws = guard
            .as_mut()
            .ok_or_else(|| napi::Error::from_reason("WebSocket is already closed"))?;

        ws.close(code.map(|c| c as u16), reason)
            .await
            .map_err(|e| napi::Error::from_reason(format!("WebSocket close failed: {e}")))?;

        // Consume the WebSocket so it can't be used again
        *guard = None;
        Ok(())
    }
}

/// Options for creating a MITM proxy server.
#[napi(object)]
#[derive(Default)]
pub struct KoonProxyOptions {
    /// Browser to impersonate for outgoing connections.
    /// @default 'chrome'
    pub browser: Option<Browser>,

    /// Custom browser profile as JSON string. Overrides `browser`.
    pub profile_json: Option<String>,

    /// Address to listen on.
    /// @default '127.0.0.1:0' (random port)
    pub listen_addr: Option<String>,

    /// Header handling mode: 'impersonate' or 'passthrough'.
    /// - impersonate: Replace client headers with profile headers (default).
    /// - passthrough: Pass client headers through, only TLS/H2 fingerprinted.
    /// @default 'impersonate'
    pub header_mode: Option<String>,

    /// Directory for CA certificate storage.
    /// @default '~/.koon/ca/'
    pub ca_dir: Option<String>,

    /// Request timeout in milliseconds.
    /// @default 30000
    pub timeout: Option<u32>,

    /// Randomize the browser fingerprint slightly.
    /// @default false
    pub randomize: Option<bool>,
}

/// A local MITM proxy server that intercepts HTTPS traffic and forwards it
/// using koon's fingerprinted TLS/HTTP2 stack.
///
/// @example
/// ```ts
/// import { KoonProxy } from 'koon';
///
/// const proxy = await KoonProxy.start({ browser: 'chrome' });
/// console.log(`Proxy listening on ${proxy.url}`);
/// console.log(`Install CA cert from: ${proxy.caCertPath}`);
///
/// // Use with Playwright:
/// // const browser = await chromium.launch({
/// //   args: [`--proxy-server=${proxy.url}`, '--ignore-certificate-errors']
/// // });
///
/// // When done:
/// proxy.shutdown();
/// ```
#[napi]
pub struct KoonProxy {
    inner: tokio::sync::Mutex<Option<ProxyServer>>,
    port_val: u16,
    url_val: String,
    ca_cert_path_val: String,
}

#[napi]
impl KoonProxy {
    /// Start a new MITM proxy server.
    #[napi(factory)]
    pub async fn start(options: Option<KoonProxyOptions>) -> Result<Self> {
        let opts = options.unwrap_or_default();

        let mut profile = if let Some(ref json) = opts.profile_json {
            BrowserProfile::from_json(json).map_err(|e| {
                napi::Error::from_reason(format!("Invalid profile JSON: {e}"))
            })?
        } else {
            match opts.browser {
                Some(ref b) => resolve_browser(b)?,
                None => BrowserProfile::resolve("chrome").unwrap(),
            }
        };

        if opts.randomize.unwrap_or(false) {
            profile.randomize();
        }

        let header_mode = match opts.header_mode.as_deref() {
            Some("passthrough") => HeaderMode::Passthrough,
            _ => HeaderMode::Impersonate,
        };

        let config = ProxyServerConfig {
            listen_addr: opts.listen_addr.unwrap_or_else(|| "127.0.0.1:0".to_string()),
            profile,
            header_mode,
            ca_dir: opts.ca_dir,
            timeout_secs: (opts.timeout.unwrap_or(30000) / 1000) as u64,
        };

        let server = ProxyServer::start(config)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Failed to start proxy: {e}")))?;

        let port_val = server.port();
        let url_val = server.url();
        let ca_cert_path_val = server.ca_cert_path().to_string_lossy().to_string();

        Ok(KoonProxy {
            inner: tokio::sync::Mutex::new(Some(server)),
            port_val,
            url_val,
            ca_cert_path_val,
        })
    }

    /// The port the proxy is listening on.
    #[napi(getter)]
    pub fn port(&self) -> u32 {
        self.port_val as u32
    }

    /// The proxy URL (e.g. 'http://127.0.0.1:12345').
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url_val.clone()
    }

    /// Path to the CA certificate PEM file.
    /// Install this in your browser/system to trust the proxy.
    #[napi(getter)]
    pub fn ca_cert_path(&self) -> String {
        self.ca_cert_path_val.clone()
    }

    /// CA certificate as PEM bytes.
    #[napi]
    pub fn ca_cert_pem(&self) -> Result<Buffer> {
        let guard = self.inner.blocking_lock();
        let server = guard
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("Proxy is shut down"))?;
        let pem = server
            .ca_cert_pem()
            .map_err(|e| napi::Error::from_reason(format!("Failed to get CA cert: {e}")))?;
        Ok(pem.into())
    }

    /// Shut down the proxy server.
    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        let mut guard = self.inner.lock().await;
        if let Some(server) = guard.take() {
            server.shutdown();
        }
        Ok(())
    }
}
