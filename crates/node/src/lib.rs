use koon_core::dns::DohResolver;
use koon_core::multipart::Multipart;
use koon_core::profile::BrowserProfile;
use koon_core::{Client, HeaderMode, ProxyServer, ProxyServerConfig};
use napi::NapiRaw;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadSafeCallContext, ThreadsafeFunction};
use napi_derive::napi;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout as tokio_timeout;

/// Options for creating a Koon client.
#[napi(object)]
#[derive(Default)]
pub struct KoonOptions {
    /// Browser to impersonate (e.g. "chrome", "firefox148-macos", "safari-mobile183").
    /// Accepts any format supported by BrowserProfile::resolve().
    /// @default 'chrome' (latest Chrome on Windows)
    pub browser: Option<String>,

    /// Custom browser profile as JSON string.
    /// Overrides the `browser` option when provided.
    /// Use `exportProfile()` to get a profile template.
    pub profile_json: Option<String>,

    /// Proxy URL (http://, https://, socks5://).
    /// Supports authentication: socks5://user:pass@host:port
    pub proxy: Option<String>,

    /// Array of proxy URLs for round-robin rotation.
    /// Each request uses the next proxy in order. Takes priority over `proxy`.
    pub proxies: Option<Vec<String>>,

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

    /// Bind outgoing connections to a specific local IP address.
    /// Useful for servers with multiple IPs or IP rotation without a proxy.
    pub local_address: Option<String>,

    /// Number of automatic retries on transport errors (connection, TLS, timeout).
    /// With proxy rotation, each retry uses the next proxy.
    /// @default 0
    pub retries: Option<u32>,

    /// Locale for Accept-Language header generation.
    /// Overrides the profile's Accept-Language to match proxy geography.
    /// Examples: "fr-FR", "de", "ja-JP", "en-US".
    pub locale: Option<String>,

    /// Custom headers to send in the HTTP CONNECT tunnel request.
    /// Useful for proxy session IDs, geo-targeting, or authentication.
    #[napi(ts_type = "Record<string, string>")]
    pub proxy_headers: Option<std::collections::HashMap<String, String>>,

    /// Restrict DNS resolution to IPv4 (4) or IPv6 (6).
    /// Useful when residential proxies only support IPv4.
    pub ip_version: Option<u32>,
}

/// Per-request options (headers, timeout).
/// These override constructor-level defaults for a single request.
#[napi(object)]
#[derive(Default)]
pub struct KoonRequestOptions {
    /// Additional headers for this request.
    /// These override constructor-level headers (case-insensitive).
    #[napi(ts_type = "Record<string, string>")]
    pub headers: Option<HashMap<String, String>>,

    /// Per-request timeout in milliseconds.
    /// Overrides the constructor-level timeout for this request only.
    pub timeout: Option<u32>,
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
///
/// @example
/// ```ts
/// const resp = await client.get('https://httpbin.org/json');
/// console.log(resp.ok);           // true
/// console.log(resp.text());       // '{"key": "value"}'
/// console.log(resp.json());       // { key: 'value' }
/// console.log(resp.header('content-type')); // 'application/json'
/// ```
#[napi]
pub struct KoonResponse {
    status_val: u32,
    headers_val: Vec<KoonHeader>,
    body_val: Vec<u8>,
    version_val: String,
    url_val: String,
    bytes_sent_val: u32,
    bytes_received_val: u32,
    tls_resumed_val: bool,
    connection_reused_val: bool,
    remote_address_val: Option<String>,
}

#[napi]
impl KoonResponse {
    /// HTTP status code.
    #[napi(getter)]
    pub fn status(&self) -> u32 {
        self.status_val
    }

    /// Response headers as an array of name-value pairs.
    /// Preserves duplicate headers (e.g. multiple Set-Cookie).
    #[napi(getter)]
    pub fn headers(&self) -> Vec<KoonHeader> {
        self.headers_val.clone()
    }

    /// Response body as a Buffer.
    #[napi(getter)]
    pub fn body(&self) -> Buffer {
        Buffer::from(self.body_val.clone())
    }

    /// HTTP version used (e.g. "h2").
    #[napi(getter)]
    pub fn version(&self) -> String {
        self.version_val.clone()
    }

    /// Final URL after redirects.
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url_val.clone()
    }

    /// Whether the response status is 2xx (success).
    #[napi(getter)]
    pub fn ok(&self) -> bool {
        self.status_val >= 200 && self.status_val < 300
    }

    /// Decode the response body as a UTF-8 string.
    #[napi]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body_val).into_owned()
    }

    /// Parse the response body as JSON (via `JSON.parse()`).
    #[napi(ts_return_type = "any")]
    pub fn json(&self, env: Env) -> Result<napi::JsUnknown> {
        let text = String::from_utf8_lossy(&self.body_val);
        let json_str = env.create_string(text.as_ref())?;
        let global = env.get_global()?;
        let json_obj: napi::JsObject = global.get_named_property("JSON")?;
        let parse_fn: napi::JsFunction = json_obj.get_named_property("parse")?;
        parse_fn.call(None, &[json_str])
    }

    /// Look up a response header by name (case-insensitive).
    /// Returns the first matching header value, or null if not found.
    #[napi]
    pub fn header(&self, name: String) -> Option<String> {
        let name_lower = name.to_lowercase();
        self.headers_val
            .iter()
            .find(|h| h.name.to_lowercase() == name_lower)
            .map(|h| h.value.clone())
    }

    /// Approximate bytes sent for this request (headers + body).
    #[napi(getter)]
    pub fn bytes_sent(&self) -> u32 {
        self.bytes_sent_val
    }

    /// Approximate bytes received for this response (headers + body, pre-decompression).
    #[napi(getter)]
    pub fn bytes_received(&self) -> u32 {
        self.bytes_received_val
    }

    /// Whether TLS session resumption was used for this connection.
    #[napi(getter)]
    pub fn tls_resumed(&self) -> bool {
        self.tls_resumed_val
    }

    /// Whether an existing pooled connection was reused.
    #[napi(getter)]
    pub fn connection_reused(&self) -> bool {
        self.connection_reused_val
    }

    /// Remote IP address of the peer (e.g. "1.2.3.4" or "::1"), or null for H3/QUIC.
    #[napi(getter)]
    pub fn remote_address(&self) -> Option<String> {
        self.remote_address_val.clone()
    }
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

/// Convert a koon_core::Error to a napi::Error with structured error code.
fn koon_napi_error(e: koon_core::Error) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {}", e.code(), e))
}

/// Convert a core HttpResponse to a napi KoonResponse.
fn response_to_napi(response: koon_core::HttpResponse) -> KoonResponse {
    let headers: Vec<KoonHeader> = response
        .headers
        .into_iter()
        .map(|(name, value)| KoonHeader { name, value })
        .collect();
    KoonResponse {
        status_val: response.status as u32,
        headers_val: headers,
        body_val: response.body,
        version_val: response.version,
        url_val: response.url,
        bytes_sent_val: response.bytes_sent as u32,
        bytes_received_val: response.bytes_received as u32,
        tls_resumed_val: response.tls_resumed,
        connection_reused_val: response.connection_reused,
        remote_address_val: response.remote_address,
    }
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
    /// Create a new Koon client.
    ///
    /// The `raw_options` parameter is typed as `napi::JsObject` to allow extracting
    /// both plain options and JsFunction hooks from a single object.
    /// The TypeScript signature is declared in `index.d.ts`.
    #[napi(constructor, ts_args_type = "options?: KoonOptions")]
    pub fn new(env: Env, raw_options: Option<napi::JsObject>) -> Result<Self> {
        // Extract KoonOptions fields from the raw JS object via FromNapiValue
        let opts: KoonOptions = match raw_options {
            Some(ref obj) => unsafe {
                <KoonOptions as FromNapiValue>::from_napi_value(env.raw(), obj.raw())?
            },
            None => KoonOptions::default(),
        };

        let mut profile = if let Some(ref json) = opts.profile_json {
            BrowserProfile::from_json(json)
                .map_err(|e| napi::Error::from_reason(format!("Invalid profile JSON: {e}")))?
        } else {
            match opts.browser {
                Some(ref b) => BrowserProfile::resolve(b).map_err(napi::Error::from_reason)?,
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

        let custom_headers: Vec<(String, String)> =
            opts.headers.unwrap_or_default().into_iter().collect();

        let mut builder = Client::builder(profile)
            .timeout(timeout)
            .headers(custom_headers)
            .follow_redirects(opts.follow_redirects.unwrap_or(true))
            .max_redirects(opts.max_redirects.unwrap_or(10))
            .cookie_jar(opts.cookie_jar.unwrap_or(true))
            .session_resumption(opts.session_resumption.unwrap_or(true));

        if let Some(ref proxy_urls) = opts.proxies {
            let refs: Vec<&str> = proxy_urls.iter().map(|s| s.as_str()).collect();
            builder = builder
                .proxies(&refs)
                .map_err(|e| napi::Error::from_reason(format!("Invalid proxies: {e}")))?;
        } else if let Some(ref proxy_url) = opts.proxy {
            builder = builder
                .proxy(proxy_url)
                .map_err(|e| napi::Error::from_reason(format!("Invalid proxy: {e}")))?;
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

        if let Some(ref addr_str) = opts.local_address {
            let addr: std::net::IpAddr = addr_str.parse().map_err(|e| {
                napi::Error::from_reason(format!("Invalid localAddress '{addr_str}': {e}"))
            })?;
            builder = builder.local_address(addr);
        }

        if let Some(retries) = opts.retries {
            builder = builder.max_retries(retries);
        }

        if let Some(ref locale) = opts.locale {
            builder = builder.locale(locale);
        }

        if let Some(ref proxy_hdrs) = opts.proxy_headers {
            let hdrs: Vec<(String, String)> = proxy_hdrs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            builder = builder.proxy_headers(hdrs);
        }

        if let Some(ip_ver) = opts.ip_version {
            let version = match ip_ver {
                4 => koon_core::IpVersion::V4,
                6 => koon_core::IpVersion::V6,
                other => {
                    return Err(napi::Error::from_reason(format!(
                        "Invalid ipVersion: {other}. Must be 4 or 6."
                    )));
                }
            };
            builder = builder.ip_version(version);
        }

        // Wire up hooks: JsFunction → ThreadsafeFunction → Arc closure
        if let Some(ref obj) = raw_options {
            // onRedirect: returns bool, uses Blocking call mode + sync_channel
            if let Ok(val) = obj.get_named_property::<napi::JsUnknown>("onRedirect") {
                if val.get_type()? == napi::ValueType::Function {
                    let js_fn = unsafe { val.cast::<JsFunction>() };
                    // Store reference to prevent GC
                    let js_fn_ref = env.create_reference(js_fn)?;

                    // Wrapper to make Ref Send+Sync (only accessed on JS thread inside TSFN callback)
                    struct SendRef(napi::Ref<()>);
                    unsafe impl Send for SendRef {}
                    unsafe impl Sync for SendRef {}
                    let send_ref = Arc::new(SendRef(js_fn_ref));

                    // Noop function as TSFN target — we call the real function manually in the callback
                    let noop = env.create_function_from_closure("noop", |_ctx| Ok(()))?;

                    type RedirectData = (
                        u16,
                        String,
                        Vec<(String, String)>,
                        std::sync::mpsc::SyncSender<bool>,
                    );
                    let tsfn = noop.create_threadsafe_function(
                        0,
                        move |ctx: ThreadSafeCallContext<RedirectData>| {
                            let (status, url, headers, tx) = ctx.value;

                            // Get real JS function from ref
                            let js_fn: JsFunction = ctx.env.get_reference_value(&send_ref.0)?;

                            // Build arguments
                            let js_status = ctx.env.create_uint32(status as u32)?;
                            let js_url = ctx.env.create_string(&url)?;
                            let mut js_headers = ctx.env.create_array_with_length(headers.len())?;
                            for (i, (name, value)) in headers.iter().enumerate() {
                                let mut obj = ctx.env.create_object()?;
                                obj.set_named_property("name", ctx.env.create_string(name)?)?;
                                obj.set_named_property("value", ctx.env.create_string(value)?)?;
                                js_headers.set_element(i as u32, obj)?;
                            }

                            // Call the real function
                            let result = js_fn.call(
                                None,
                                &[
                                    js_status.into_unknown(),
                                    js_url.into_unknown(),
                                    js_headers.coerce_to_object()?.into_unknown(),
                                ],
                            )?;

                            // Extract boolean return value (default true if not boolean)
                            let follow = match result.get_type()? {
                                napi::ValueType::Boolean => {
                                    unsafe { result.cast::<napi::JsBoolean>() }.get_value()?
                                }
                                _ => true,
                            };
                            let _ = tx.send(follow);

                            // Return empty vec — noop doesn't need args
                            Ok(Vec::<napi::JsUnknown>::new())
                        },
                    )?;

                    let tsfn: Arc<ThreadsafeFunction<RedirectData, ErrorStrategy::Fatal>> =
                        Arc::new(tsfn);
                    builder = builder.on_redirect(
                        move |status: u16, url: &str, headers: &[(String, String)]| {
                            let (tx, rx) = std::sync::mpsc::sync_channel(1);
                            tsfn.call(
                                (status, url.to_string(), headers.to_vec(), tx),
                                napi::threadsafe_function::ThreadsafeFunctionCallMode::Blocking,
                            );
                            rx.recv().unwrap_or(true)
                        },
                    );
                }
            }
            // Check if onRequest is a function (not undefined/null)
            if let Ok(val) = obj.get_named_property::<napi::JsUnknown>("onRequest") {
                if val.get_type()? == napi::ValueType::Function {
                    let js_fn = unsafe { val.cast::<JsFunction>() };
                    let tsfn = js_fn.create_threadsafe_function(
                        0,
                        |ctx: ThreadSafeCallContext<(String, String)>| {
                            let method = ctx.env.create_string(&ctx.value.0)?;
                            let url = ctx.env.create_string(&ctx.value.1)?;
                            Ok(vec![method, url])
                        },
                    )?;
                    let tsfn: Arc<ThreadsafeFunction<(String, String), ErrorStrategy::Fatal>> =
                        Arc::new(tsfn);
                    builder = builder.on_request(move |method: &str, url: &str| {
                        tsfn.call(
                            (method.to_string(), url.to_string()),
                            napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                        );
                    });
                }
            }

            // Check if onResponse is a function (not undefined/null)
            if let Ok(val) = obj.get_named_property::<napi::JsUnknown>("onResponse") {
                if val.get_type()? == napi::ValueType::Function {
                    let js_fn = unsafe { val.cast::<JsFunction>() };
                    let tsfn = js_fn.create_threadsafe_function(
                        0,
                        |ctx: ThreadSafeCallContext<(u16, String, Vec<(String, String)>)>| {
                            let status = ctx.env.create_uint32(ctx.value.0 as u32)?;
                            let url = ctx.env.create_string(&ctx.value.1)?;
                            let mut arr = ctx.env.create_array_with_length(ctx.value.2.len())?;
                            for (i, (name, value)) in ctx.value.2.iter().enumerate() {
                                let mut obj = ctx.env.create_object()?;
                                obj.set_named_property("name", ctx.env.create_string(name)?)?;
                                obj.set_named_property("value", ctx.env.create_string(value)?)?;
                                arr.set_element(i as u32, obj)?;
                            }
                            Ok(vec![
                                status.into_unknown(),
                                url.into_unknown(),
                                arr.coerce_to_object()?.into_unknown(),
                            ])
                        },
                    )?;
                    let tsfn: Arc<
                        ThreadsafeFunction<
                            (u16, String, Vec<(String, String)>),
                            ErrorStrategy::Fatal,
                        >,
                    > = Arc::new(tsfn);
                    builder = builder.on_response(
                        move |status: u16, url: &str, headers: &[(String, String)]| {
                            tsfn.call(
                                (status, url.to_string(), headers.to_vec()),
                                napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
                            );
                        },
                    );
                }
            }
        }

        let client = builder.build().map_err(koon_napi_error)?;

        Ok(Koon { client })
    }

    /// The User-Agent string from the browser profile.
    /// Useful for setting in Puppeteer/Playwright.
    #[napi(getter)]
    pub fn user_agent(&self) -> Option<String> {
        self.client.user_agent().map(|s| s.to_string())
    }

    /// Export the current browser profile as a JSON string.
    /// Useful for customizing and reloading profiles.
    #[napi]
    pub fn export_profile(&self) -> Result<String> {
        self.client
            .profile()
            .to_json_pretty()
            .map_err(|e| napi::Error::from_reason(format!("Failed to export profile: {e}")))
    }

    /// Perform an HTTP GET request.
    #[napi]
    pub async fn get(
        &self,
        url: String,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("GET".to_string(), url, None, options).await
    }

    /// Perform an HTTP POST request.
    #[napi]
    pub async fn post(
        &self,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("POST".to_string(), url, body, options).await
    }

    /// Perform an HTTP PUT request.
    #[napi]
    pub async fn put(
        &self,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("PUT".to_string(), url, body, options).await
    }

    /// Perform an HTTP DELETE request.
    #[napi]
    pub async fn delete(
        &self,
        url: String,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("DELETE".to_string(), url, None, options).await
    }

    /// Perform an HTTP PATCH request.
    #[napi]
    pub async fn patch(
        &self,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("PATCH".to_string(), url, body, options).await
    }

    /// Perform an HTTP HEAD request.
    #[napi]
    pub async fn head(
        &self,
        url: String,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        self.request("HEAD".to_string(), url, None, options).await
    }

    /// Perform an HTTP request with a custom method.
    #[napi]
    pub async fn request(
        &self,
        method: String,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        let method = method
            .parse()
            .map_err(|_| napi::Error::from_reason(format!("Invalid HTTP method: {method}")))?;

        let body_bytes = body.map(|b| match b {
            Either::A(s) => s.into_bytes(),
            Either::B(buf) => buf.to_vec(),
        });
        let opts = options.unwrap_or_default();
        let extra_headers: Vec<(String, String)> =
            opts.headers.unwrap_or_default().into_iter().collect();

        let future = self
            .client
            .request_with_headers(method, &url, body_bytes, extra_headers);

        let response = if let Some(timeout_ms) = opts.timeout {
            tokio_timeout(Duration::from_millis(timeout_ms as u64), future)
                .await
                .map_err(|_| napi::Error::from_reason("Request timed out"))?
                .map_err(koon_napi_error)?
        } else {
            future.await.map_err(koon_napi_error)?
        };

        Ok(response_to_napi(response))
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
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        let mut mp = Multipart::new();
        for field in fields {
            if let Some(file_data) = field.file_data {
                mp = mp.file(
                    field.name,
                    field.filename.unwrap_or_else(|| "file".to_string()),
                    field
                        .content_type
                        .unwrap_or_else(|| "application/octet-stream".to_string()),
                    file_data.to_vec(),
                );
            } else if let Some(value) = field.value {
                mp = mp.text(field.name, value);
            }
        }

        let (body, content_type) = mp.build();
        let opts = options.unwrap_or_default();
        let mut extra_headers: Vec<(String, String)> =
            opts.headers.unwrap_or_default().into_iter().collect();
        extra_headers.push(("content-type".into(), content_type));

        let future = self.client.request_with_headers(
            "POST".parse().unwrap(),
            &url,
            Some(body),
            extra_headers,
        );

        let response = if let Some(timeout_ms) = opts.timeout {
            tokio_timeout(Duration::from_millis(timeout_ms as u64), future)
                .await
                .map_err(|_| napi::Error::from_reason("Request timed out"))?
                .map_err(koon_napi_error)?
        } else {
            future.await.map_err(koon_napi_error)?
        };

        Ok(response_to_napi(response))
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
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonStreamingResponse> {
        let method = method
            .parse()
            .map_err(|_| napi::Error::from_reason(format!("Invalid HTTP method: {method}")))?;
        let body_bytes = body.map(|b| match b {
            Either::A(s) => s.into_bytes(),
            Either::B(buf) => buf.to_vec(),
        });
        let opts = options.unwrap_or_default();
        let extra_headers: Vec<(String, String)> =
            opts.headers.unwrap_or_default().into_iter().collect();

        let future =
            self.client
                .request_streaming_with_headers(method, &url, body_bytes, extra_headers);

        let resp = if let Some(timeout_ms) = opts.timeout {
            tokio_timeout(Duration::from_millis(timeout_ms as u64), future)
                .await
                .map_err(|_| napi::Error::from_reason("Request timed out"))?
                .map_err(koon_napi_error)?
        } else {
            future.await.map_err(koon_napi_error)?
        };

        let headers: Vec<KoonHeader> = resp
            .headers
            .iter()
            .map(|(name, value)| KoonHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();

        let bytes_sent = resp.bytes_sent() as u32;
        let remote_addr = resp.remote_address.clone();
        Ok(KoonStreamingResponse {
            status_val: resp.status as u32,
            headers_val: headers,
            version_val: resp.version.clone(),
            url_val: resp.url.clone(),
            bytes_sent_val: bytes_sent,
            remote_address_val: remote_addr,
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

    /// Get the total number of bytes sent across all requests.
    #[napi]
    pub fn total_bytes_sent(&self) -> BigInt {
        BigInt::from(self.client.total_bytes_sent())
    }

    /// Get the total number of bytes received across all requests.
    #[napi]
    pub fn total_bytes_received(&self) -> BigInt {
        BigInt::from(self.client.total_bytes_received())
    }

    /// Reset both cumulative byte counters to zero.
    #[napi]
    pub fn reset_counters(&self) {
        self.client.reset_counters();
    }

    /// Clear all cookies from the cookie jar.
    /// Keeps TLS sessions, connection pool, and all other client state intact.
    #[napi]
    pub fn clear_cookies(&self) {
        self.client.clear_cookies();
    }

    /// Close all pooled connections and release resources.
    /// Call this when you're done with the client to prevent resource leaks.
    /// The client can still be used after this — new connections will be opened as needed.
    #[napi]
    pub fn close(&self) {
        self.client.close();
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
        let extra_headers: Vec<(String, String)> =
            headers.unwrap_or_default().into_iter().collect();

        let ws = self
            .client
            .websocket_with_headers(&url, extra_headers)
            .await
            .map_err(koon_napi_error)?;

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
    bytes_sent_val: u32,
    remote_address_val: Option<String>,
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

    /// Approximate bytes sent for this request.
    #[napi(getter)]
    pub fn bytes_sent(&self) -> u32 {
        self.bytes_sent_val
    }

    /// Remote IP address of the peer (e.g. "1.2.3.4" or "::1"), or null for H3/QUIC.
    #[napi(getter)]
    pub fn remote_address(&self) -> Option<String> {
        self.remote_address_val.clone()
    }

    /// Approximate bytes received so far (headers + body chunks consumed).
    #[napi]
    pub fn bytes_received(&self) -> u32 {
        let guard = self.inner.blocking_lock();
        guard
            .as_ref()
            .map(|r| r.bytes_received() as u32)
            .unwrap_or(0)
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
        .map_err(koon_napi_error)
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
            Err(e) => Err(koon_napi_error(e)),
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
            .map_err(koon_napi_error)?;

        // Consume the WebSocket so it can't be used again
        *guard = None;
        Ok(())
    }
}

/// Options for creating a MITM proxy server.
#[napi(object)]
#[derive(Default)]
pub struct KoonProxyOptions {
    /// Browser to impersonate for outgoing connections (e.g. "chrome", "firefox148-macos").
    /// @default 'chrome'
    pub browser: Option<String>,

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
            BrowserProfile::from_json(json)
                .map_err(|e| napi::Error::from_reason(format!("Invalid profile JSON: {e}")))?
        } else {
            match opts.browser {
                Some(ref b) => BrowserProfile::resolve(b).map_err(napi::Error::from_reason)?,
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
            listen_addr: opts
                .listen_addr
                .unwrap_or_else(|| "127.0.0.1:0".to_string()),
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
