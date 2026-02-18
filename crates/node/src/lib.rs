use napi::bindgen_prelude::*;
use napi_derive::napi;
use koon_core::profile::{BrowserProfile, Chrome, Edge, Firefox, Safari};
use koon_core::Client;
use std::collections::HashMap;
use std::time::Duration;

/// Supported browser profiles for impersonation.
#[napi(string_enum = "lowercase")]
pub enum Browser {
    Chrome,
    Chrome131,
    Chrome131Windows,
    Chrome131Macos,
    Chrome131Linux,
    Chrome145,
    Chrome145Windows,
    Chrome145Macos,
    Chrome145Linux,
    Firefox,
    Firefox135,
    Firefox135Windows,
    Firefox135Macos,
    Firefox135Linux,
    Safari,
    Safari183,
    Safari183Macos,
    Edge,
    Edge131,
    Edge131Windows,
    Edge131Macos,
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
                Some(Browser::Chrome131Windows) => Chrome::v131_windows(),
                Some(Browser::Chrome131Macos) => Chrome::v131_macos(),
                Some(Browser::Chrome131Linux) => Chrome::v131_linux(),
                Some(Browser::Chrome131) => Chrome::v131_windows(),
                Some(Browser::Chrome145Windows) => Chrome::v145_windows(),
                Some(Browser::Chrome145Macos) => Chrome::v145_macos(),
                Some(Browser::Chrome145Linux) => Chrome::v145_linux(),
                Some(Browser::Chrome145) => Chrome::v145_windows(),
                Some(Browser::Firefox135Windows) => Firefox::v135_windows(),
                Some(Browser::Firefox135Macos) => Firefox::v135_macos(),
                Some(Browser::Firefox135Linux) => Firefox::v135_linux(),
                Some(Browser::Firefox135) | Some(Browser::Firefox) => Firefox::latest(),
                Some(Browser::Safari183Macos) | Some(Browser::Safari183) | Some(Browser::Safari) => Safari::latest(),
                Some(Browser::Edge131Windows) => Edge::v131_windows(),
                Some(Browser::Edge131Macos) => Edge::v131_macos(),
                Some(Browser::Edge131) | Some(Browser::Edge) => Edge::latest(),
                Some(Browser::Chrome) | None => Chrome::latest(),
            }
        };

        if opts.ignore_tls_errors.unwrap_or(false) {
            profile.tls.danger_accept_invalid_certs = true;
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
            .cookie_jar(opts.cookie_jar.unwrap_or(true));

        if let Some(ref proxy_url) = opts.proxy {
            builder = builder.proxy(proxy_url).map_err(|e| {
                napi::Error::from_reason(format!("Invalid proxy: {e}"))
            })?;
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
