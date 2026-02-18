use napi::bindgen_prelude::*;
use napi_derive::napi;
use koon_core::profile::{BrowserProfile, Chrome};
use koon_core::Client;
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
}

/// Response from an HTTP request.
#[napi(object)]
pub struct KoonResponse {
    /// HTTP status code.
    pub status: u32,

    /// Response headers.
    pub headers: std::collections::HashMap<String, String>,

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
    profile: BrowserProfile,
    proxy: Option<String>,
    timeout: Duration,
    custom_headers: Vec<(String, String)>,
    ignore_tls_errors: bool,
}

#[napi]
impl Koon {
    #[napi(constructor)]
    pub fn new(options: Option<KoonOptions>) -> Result<Self> {
        let opts = options.unwrap_or_default();

        let profile = if let Some(ref json) = opts.profile_json {
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
                Some(Browser::Chrome) | None => Chrome::latest(),
            }
        };

        let timeout = Duration::from_millis(opts.timeout.unwrap_or(30000) as u64);

        let custom_headers: Vec<(String, String)> = opts
            .headers
            .unwrap_or_default()
            .into_iter()
            .collect();

        Ok(Koon {
            profile,
            proxy: opts.proxy,
            timeout,
            custom_headers,
            ignore_tls_errors: opts.ignore_tls_errors.unwrap_or(false),
        })
    }

    /// Export the current browser profile as a JSON string.
    /// Useful for customizing and reloading profiles.
    #[napi]
    pub fn export_profile(&self) -> Result<String> {
        self.profile.to_json_pretty().map_err(|e| {
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

    /// Perform an HTTP request with a custom method.
    #[napi]
    pub async fn request(
        &self,
        method: String,
        url: String,
        body: Option<Buffer>,
    ) -> Result<KoonResponse> {
        let mut profile = self.profile.clone();
        if self.ignore_tls_errors {
            profile.tls.danger_accept_invalid_certs = true;
        }

        let mut client = Client::new(profile).map_err(|e| {
            napi::Error::from_reason(format!("Failed to create client: {e}"))
        })?;

        client = client
            .with_timeout(self.timeout)
            .with_headers(self.custom_headers.clone());

        if let Some(ref proxy_url) = self.proxy {
            client = client.with_proxy(proxy_url).map_err(|e| {
                napi::Error::from_reason(format!("Invalid proxy: {e}"))
            })?;
        }

        let method = method.parse().map_err(|_| {
            napi::Error::from_reason(format!("Invalid HTTP method: {method}"))
        })?;

        let body_bytes = body.map(|b| b.to_vec());

        let response = client
            .request(method, &url, body_bytes)
            .await
            .map_err(|e| napi::Error::from_reason(format!("Request failed: {e}")))?;

        let headers: std::collections::HashMap<String, String> =
            response.headers.into_iter().collect();

        Ok(KoonResponse {
            status: response.status as u32,
            headers,
            body: response.body.into(),
            version: response.version,
            url: response.url,
        })
    }
}
