use napi::bindgen_prelude::*;
use napi_derive::napi;
use koon_core::dns::DohResolver;
use koon_core::profile::{BrowserProfile, Chrome, Edge, Firefox, Opera, Safari};
use koon_core::Client;
use std::collections::HashMap;
use std::time::Duration;

/// Supported browser profiles for impersonation.
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

fn resolve_browser(browser: &Browser) -> BrowserProfile {
    match browser {
        // Chrome — version-specific
        Browser::Chrome131Windows => Chrome::v131_windows(),
        Browser::Chrome131Macos => Chrome::v131_macos(),
        Browser::Chrome131Linux => Chrome::v131_linux(),
        Browser::Chrome131 => Chrome::v131_windows(),
        Browser::Chrome132Windows => Chrome::v132_windows(),
        Browser::Chrome132Macos => Chrome::v132_macos(),
        Browser::Chrome132Linux => Chrome::v132_linux(),
        Browser::Chrome132 => Chrome::v132_windows(),
        Browser::Chrome133Windows => Chrome::v133_windows(),
        Browser::Chrome133Macos => Chrome::v133_macos(),
        Browser::Chrome133Linux => Chrome::v133_linux(),
        Browser::Chrome133 => Chrome::v133_windows(),
        Browser::Chrome134Windows => Chrome::v134_windows(),
        Browser::Chrome134Macos => Chrome::v134_macos(),
        Browser::Chrome134Linux => Chrome::v134_linux(),
        Browser::Chrome134 => Chrome::v134_windows(),
        Browser::Chrome135Windows => Chrome::v135_windows(),
        Browser::Chrome135Macos => Chrome::v135_macos(),
        Browser::Chrome135Linux => Chrome::v135_linux(),
        Browser::Chrome135 => Chrome::v135_windows(),
        Browser::Chrome136Windows => Chrome::v136_windows(),
        Browser::Chrome136Macos => Chrome::v136_macos(),
        Browser::Chrome136Linux => Chrome::v136_linux(),
        Browser::Chrome136 => Chrome::v136_windows(),
        Browser::Chrome137Windows => Chrome::v137_windows(),
        Browser::Chrome137Macos => Chrome::v137_macos(),
        Browser::Chrome137Linux => Chrome::v137_linux(),
        Browser::Chrome137 => Chrome::v137_windows(),
        Browser::Chrome138Windows => Chrome::v138_windows(),
        Browser::Chrome138Macos => Chrome::v138_macos(),
        Browser::Chrome138Linux => Chrome::v138_linux(),
        Browser::Chrome138 => Chrome::v138_windows(),
        Browser::Chrome139Windows => Chrome::v139_windows(),
        Browser::Chrome139Macos => Chrome::v139_macos(),
        Browser::Chrome139Linux => Chrome::v139_linux(),
        Browser::Chrome139 => Chrome::v139_windows(),
        Browser::Chrome140Windows => Chrome::v140_windows(),
        Browser::Chrome140Macos => Chrome::v140_macos(),
        Browser::Chrome140Linux => Chrome::v140_linux(),
        Browser::Chrome140 => Chrome::v140_windows(),
        Browser::Chrome141Windows => Chrome::v141_windows(),
        Browser::Chrome141Macos => Chrome::v141_macos(),
        Browser::Chrome141Linux => Chrome::v141_linux(),
        Browser::Chrome141 => Chrome::v141_windows(),
        Browser::Chrome142Windows => Chrome::v142_windows(),
        Browser::Chrome142Macos => Chrome::v142_macos(),
        Browser::Chrome142Linux => Chrome::v142_linux(),
        Browser::Chrome142 => Chrome::v142_windows(),
        Browser::Chrome143Windows => Chrome::v143_windows(),
        Browser::Chrome143Macos => Chrome::v143_macos(),
        Browser::Chrome143Linux => Chrome::v143_linux(),
        Browser::Chrome143 => Chrome::v143_windows(),
        Browser::Chrome144Windows => Chrome::v144_windows(),
        Browser::Chrome144Macos => Chrome::v144_macos(),
        Browser::Chrome144Linux => Chrome::v144_linux(),
        Browser::Chrome144 => Chrome::v144_windows(),
        Browser::Chrome145Windows => Chrome::v145_windows(),
        Browser::Chrome145Macos => Chrome::v145_macos(),
        Browser::Chrome145Linux => Chrome::v145_linux(),
        Browser::Chrome145 => Chrome::v145_windows(),
        Browser::Chrome => Chrome::latest(),
        // Firefox — version-specific
        Browser::Firefox135Windows => Firefox::v135_windows(),
        Browser::Firefox135Macos => Firefox::v135_macos(),
        Browser::Firefox135Linux => Firefox::v135_linux(),
        Browser::Firefox135 => Firefox::v135_windows(),
        Browser::Firefox136Windows => Firefox::v136_windows(),
        Browser::Firefox136Macos => Firefox::v136_macos(),
        Browser::Firefox136Linux => Firefox::v136_linux(),
        Browser::Firefox136 => Firefox::v136_windows(),
        Browser::Firefox137Windows => Firefox::v137_windows(),
        Browser::Firefox137Macos => Firefox::v137_macos(),
        Browser::Firefox137Linux => Firefox::v137_linux(),
        Browser::Firefox137 => Firefox::v137_windows(),
        Browser::Firefox138Windows => Firefox::v138_windows(),
        Browser::Firefox138Macos => Firefox::v138_macos(),
        Browser::Firefox138Linux => Firefox::v138_linux(),
        Browser::Firefox138 => Firefox::v138_windows(),
        Browser::Firefox139Windows => Firefox::v139_windows(),
        Browser::Firefox139Macos => Firefox::v139_macos(),
        Browser::Firefox139Linux => Firefox::v139_linux(),
        Browser::Firefox139 => Firefox::v139_windows(),
        Browser::Firefox140Windows => Firefox::v140_windows(),
        Browser::Firefox140Macos => Firefox::v140_macos(),
        Browser::Firefox140Linux => Firefox::v140_linux(),
        Browser::Firefox140 => Firefox::v140_windows(),
        Browser::Firefox141Windows => Firefox::v141_windows(),
        Browser::Firefox141Macos => Firefox::v141_macos(),
        Browser::Firefox141Linux => Firefox::v141_linux(),
        Browser::Firefox141 => Firefox::v141_windows(),
        Browser::Firefox142Windows => Firefox::v142_windows(),
        Browser::Firefox142Macos => Firefox::v142_macos(),
        Browser::Firefox142Linux => Firefox::v142_linux(),
        Browser::Firefox142 => Firefox::v142_windows(),
        Browser::Firefox143Windows => Firefox::v143_windows(),
        Browser::Firefox143Macos => Firefox::v143_macos(),
        Browser::Firefox143Linux => Firefox::v143_linux(),
        Browser::Firefox143 => Firefox::v143_windows(),
        Browser::Firefox144Windows => Firefox::v144_windows(),
        Browser::Firefox144Macos => Firefox::v144_macos(),
        Browser::Firefox144Linux => Firefox::v144_linux(),
        Browser::Firefox144 => Firefox::v144_windows(),
        Browser::Firefox145Windows => Firefox::v145_windows(),
        Browser::Firefox145Macos => Firefox::v145_macos(),
        Browser::Firefox145Linux => Firefox::v145_linux(),
        Browser::Firefox145 => Firefox::v145_windows(),
        Browser::Firefox146Windows => Firefox::v146_windows(),
        Browser::Firefox146Macos => Firefox::v146_macos(),
        Browser::Firefox146Linux => Firefox::v146_linux(),
        Browser::Firefox146 => Firefox::v146_windows(),
        Browser::Firefox147Windows => Firefox::v147_windows(),
        Browser::Firefox147Macos => Firefox::v147_macos(),
        Browser::Firefox147Linux => Firefox::v147_linux(),
        Browser::Firefox147 => Firefox::v147_windows(),
        Browser::Firefox => Firefox::latest(),
        // Safari
        Browser::Safari156Macos | Browser::Safari156 => Safari::v15_6_macos(),
        Browser::Safari160Macos | Browser::Safari160 => Safari::v16_0_macos(),
        Browser::Safari170Macos | Browser::Safari170 => Safari::v17_0_macos(),
        Browser::Safari180Macos | Browser::Safari180 => Safari::v18_0_macos(),
        Browser::Safari183Macos | Browser::Safari183 => Safari::v18_3_macos(),
        Browser::Safari => Safari::latest(),
        // Opera — version-specific
        Browser::Opera124Windows => Opera::v124_windows(),
        Browser::Opera124Macos => Opera::v124_macos(),
        Browser::Opera124Linux => Opera::v124_linux(),
        Browser::Opera124 => Opera::v124_windows(),
        Browser::Opera125Windows => Opera::v125_windows(),
        Browser::Opera125Macos => Opera::v125_macos(),
        Browser::Opera125Linux => Opera::v125_linux(),
        Browser::Opera125 => Opera::v125_windows(),
        Browser::Opera126Windows => Opera::v126_windows(),
        Browser::Opera126Macos => Opera::v126_macos(),
        Browser::Opera126Linux => Opera::v126_linux(),
        Browser::Opera126 => Opera::v126_windows(),
        Browser::Opera127Windows => Opera::v127_windows(),
        Browser::Opera127Macos => Opera::v127_macos(),
        Browser::Opera127Linux => Opera::v127_linux(),
        Browser::Opera127 => Opera::v127_windows(),
        Browser::Opera => Opera::latest(),
        // Edge — version-specific
        Browser::Edge131Windows => Edge::v131_windows(),
        Browser::Edge131Macos => Edge::v131_macos(),
        Browser::Edge131 => Edge::v131_windows(),
        Browser::Edge132Windows => Edge::v132_windows(),
        Browser::Edge132Macos => Edge::v132_macos(),
        Browser::Edge132 => Edge::v132_windows(),
        Browser::Edge133Windows => Edge::v133_windows(),
        Browser::Edge133Macos => Edge::v133_macos(),
        Browser::Edge133 => Edge::v133_windows(),
        Browser::Edge134Windows => Edge::v134_windows(),
        Browser::Edge134Macos => Edge::v134_macos(),
        Browser::Edge134 => Edge::v134_windows(),
        Browser::Edge135Windows => Edge::v135_windows(),
        Browser::Edge135Macos => Edge::v135_macos(),
        Browser::Edge135 => Edge::v135_windows(),
        Browser::Edge136Windows => Edge::v136_windows(),
        Browser::Edge136Macos => Edge::v136_macos(),
        Browser::Edge136 => Edge::v136_windows(),
        Browser::Edge137Windows => Edge::v137_windows(),
        Browser::Edge137Macos => Edge::v137_macos(),
        Browser::Edge137 => Edge::v137_windows(),
        Browser::Edge138Windows => Edge::v138_windows(),
        Browser::Edge138Macos => Edge::v138_macos(),
        Browser::Edge138 => Edge::v138_windows(),
        Browser::Edge139Windows => Edge::v139_windows(),
        Browser::Edge139Macos => Edge::v139_macos(),
        Browser::Edge139 => Edge::v139_windows(),
        Browser::Edge140Windows => Edge::v140_windows(),
        Browser::Edge140Macos => Edge::v140_macos(),
        Browser::Edge140 => Edge::v140_windows(),
        Browser::Edge141Windows => Edge::v141_windows(),
        Browser::Edge141Macos => Edge::v141_macos(),
        Browser::Edge141 => Edge::v141_windows(),
        Browser::Edge142Windows => Edge::v142_windows(),
        Browser::Edge142Macos => Edge::v142_macos(),
        Browser::Edge142 => Edge::v142_windows(),
        Browser::Edge143Windows => Edge::v143_windows(),
        Browser::Edge143Macos => Edge::v143_macos(),
        Browser::Edge143 => Edge::v143_windows(),
        Browser::Edge144Windows => Edge::v144_windows(),
        Browser::Edge144Macos => Edge::v144_macos(),
        Browser::Edge144 => Edge::v144_windows(),
        Browser::Edge145Windows => Edge::v145_windows(),
        Browser::Edge145Macos => Edge::v145_macos(),
        Browser::Edge145 => Edge::v145_windows(),
        Browser::Edge => Edge::latest(),
    }
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
                Some(ref b) => resolve_browser(b),
                None => Chrome::latest(),
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
