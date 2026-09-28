use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use http::Method;
use indexmap::IndexMap;
use koon_core::dns::DohConfig;
use koon_core::multipart::Multipart;
use koon_core::profile::BrowserProfile;
use koon_core::{
    Body, BoundaryStyle, Client, ClientBuilder, CookieParams, Error as KoonError, HeaderFamily,
    IpVersion, ProxyServer, ProxyServerAuth, ProxyServerConfig, SkippedCookie, WsMessage,
};
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{JsFunction, JsObject, JsString, JsUnknown, NapiValue, Ref, Status, ValueType};
use napi_derive::napi;

/// Install a panic hook that logs to stderr before aborting.
/// This captures Rust panics that would otherwise silently crash the Node.js process.
#[napi::module_init]
fn init_module() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Box<dyn Any>".to_string()
        };
        let location = info.location().map_or_else(
            || "<unknown>".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );

        eprintln!("\n[koon] PANIC in thread '{thread_name}' at {location}:");
        eprintln!("[koon]   {payload}");
        eprintln!(
            "[koon] backtrace:\n{}",
            std::backtrace::Backtrace::force_capture()
        );
    }));
}

// ---------------------------------------------------------------------------
// Errors and argument conversion
// ---------------------------------------------------------------------------

/// A core error as a JS error. The code goes into the message as a `[CODE]`
/// prefix, which index.js copies into `err.code`: napi-rs sets `code` to its
/// own status name, and an async function can only reject with that. A
/// hook's error becomes `[HOOK_ERROR] #id`, for which index.js rejects with
/// the value the hook threw (see [`hook_outcome`]).
fn koon_napi_error(error: KoonError) -> napi::Error {
    napi::Error::from_reason(match error {
        KoonError::Hook(inner) => match inner.downcast::<ThrownByHook>() {
            Ok(thrown) => format!("[HOOK_ERROR] #{}", thrown.0),
            Err(other) => format!("[HOOK_ERROR] {other}"),
        },
        error => format!("[{}] {error}", error.code()),
    })
}

/// A hook threw: index.js keeps the thrown value under this id until the
/// request it failed rejects with it.
#[derive(Debug)]
struct ThrownByHook(u64);

impl std::fmt::Display for ThrownByHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hook error #{}", self.0)
    }
}

impl std::error::Error for ThrownByHook {}

/// An argument the binding rejects itself, with the core's `INVALID_ARGUMENT` code.
fn invalid_argument(message: impl std::fmt::Display) -> napi::Error {
    koon_napi_error(KoonError::InvalidArgument(message.to_string(), None))
}

/// A timeout in seconds from JS; 0 means no timeout (the core's convention).
/// Taken as a number rather than napi's `u32`, whose `ToUint32` conversion
/// turns 0.5 into 0 (no timeout) and -1 into 4294967295.
fn timeout(secs: f64) -> Result<Duration> {
    Duration::try_from_secs_f64(secs).map_err(|_| {
        invalid_argument(format!(
            "timeout must be a finite number of seconds >= 0, got {secs}"
        ))
    })
}

/// A whole number >= 0 from JS, for the same reason as [`timeout`]: napi's
/// `ToUint32` would wrap -1 to 4294967295 and truncate 1.5 to 1.
fn whole_number<T: TryFrom<u64>>(name: &str, value: f64) -> Result<T> {
    if !(value >= 0.0 && value.fract() == 0.0) {
        return Err(invalid_argument(format!(
            "{name} must be a whole number >= 0, got {value}"
        )));
    }
    // `as` saturates, so a value beyond u64 comes back different.
    let whole = value as u64;
    match T::try_from(whole) {
        Ok(number) if whole as f64 == value => Ok(number),
        _ => Err(invalid_argument(format!("{name} is too large: {value}"))),
    }
}

fn ip_version(value: f64) -> Result<IpVersion> {
    IpVersion::try_from(whole_number::<u8>("ipVersion", value)?).map_err(koon_napi_error)
}

/// A browser profile from a custom JSON profile, else by name.
fn resolve_profile(browser: Option<&str>, profile_json: Option<&str>) -> Result<BrowserProfile> {
    BrowserProfile::from_name_or_json(browser.unwrap_or("chrome"), profile_json)
        .map_err(koon_napi_error)
}

/// The method and body of a request, as the core takes them.
fn method_and_body(method: &str, body: Option<Either<String, Buffer>>) -> Result<(Method, Body)> {
    let method = koon_core::parse_method(method).map_err(koon_napi_error)?;
    let body = match body {
        None => Body::empty(),
        Some(Either::A(text)) => text.into(),
        // Copied: the JS side may change or release the Buffer while the
        // request is still being sent.
        Some(Either::B(buffer)) => Vec::from(buffer).into(),
    };
    Ok((method, body))
}

/// Headers from JS, in order: an object (insertion order) or an array of
/// `[name, value]` pairs, which may repeat a name. index.js turns other
/// iterables of pairs (a `Map`, a fetch `Headers`) into an array.
#[derive(Default)]
pub struct Headers(Vec<(String, String)>);

impl TypeName for Headers {
    fn type_name() -> &'static str {
        "Headers"
    }

    fn value_type() -> ValueType {
        ValueType::Object
    }
}

impl ValidateNapiValue for Headers {}

impl FromNapiValue for Headers {
    unsafe fn from_napi_value(
        env: napi::sys::napi_env,
        value: napi::sys::napi_value,
    ) -> Result<Self> {
        let mut is_array = false;
        // SAFETY: `env` and `value` come from napi-rs, which calls this
        // with the environment of the current call.
        unsafe {
            napi::check_status!(napi::sys::napi_is_array(env, value, &mut is_array))?;
            if !is_array {
                let map = IndexMap::<String, String>::from_napi_value(env, value)?;
                return Ok(Self(map.into_iter().collect()));
            }
            let pairs = Vec::<Vec<String>>::from_napi_value(env, value).map_err(|_| {
                invalid_argument("headers must be an object or an array of [name, value] pairs")
            })?;
            pairs
                .into_iter()
                .enumerate()
                .map(|(index, pair)| match <[String; 2]>::try_from(pair) {
                    Ok([name, value]) => Ok((name, value)),
                    Err(_) => Err(invalid_argument(format!(
                        "headers[{index}] must be a [name, value] pair of strings"
                    ))),
                })
                .collect::<Result<_>>()
                .map(Headers)
        }
    }
}

fn headers(headers: Option<Headers>) -> Vec<(String, String)> {
    headers.unwrap_or_default().0
}

fn to_koon_headers(headers: &[(String, String)]) -> Vec<KoonHeader> {
    headers
        .iter()
        .map(|(name, value)| KoonHeader {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

/// The value of the first header named `name`, ignoring ASCII case.
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

// ---------------------------------------------------------------------------
// Values built once per object
// ---------------------------------------------------------------------------

fn to_js<T: ToNapiValue>(env: Env, value: T) -> Result<JsUnknown> {
    // SAFETY: `env` is the environment of the current call, and the raw
    // value was just created in it.
    unsafe {
        let raw = T::to_napi_value(env.raw(), value)?;
        Ok(JsUnknown::from_raw_unchecked(env.raw(), raw))
    }
}

/// A JS value converted from Rust data on first access and then kept for the
/// lifetime of its owner, so a getter returns the same object every time:
/// `resp.headers[i]` in a loop does not rebuild the array on each access,
/// and a body's memory is handed to a single Buffer (V8 refuses a second
/// external buffer over the same memory).
#[derive(Default)]
struct JsCache(OnceLock<Ref<()>>);

impl JsCache {
    fn get_or_init<T: ToNapiValue>(&self, env: Env, init: impl FnOnce() -> T) -> Result<JsUnknown> {
        if let Some(reference) = self.0.get() {
            return env.get_reference_value(reference);
        }
        let reference = env.create_reference(to_js(env, init())?)?;
        // Getters run on the JS thread only, so the cell is still empty.
        env.get_reference_value(self.0.get_or_init(|| reference))
    }

    /// Release the value, so it is garbage-collected along with its owner.
    fn release(self, env: Env) -> Result<()> {
        match self.0.into_inner() {
            Some(mut reference) => reference.unref(env).map(drop),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

type RequestHookFn = ThreadsafeFunction<(String, String), ErrorStrategy::Fatal>;
type ResponseHookFn = ThreadsafeFunction<(u16, String, Vec<KoonHeader>), ErrorStrategy::Fatal>;

// With `ErrorStrategy::Fatal`, a hook that throws aborts the process, and so
// does a return value that fails to convert. index.js wraps every hook so
// that it never throws and returns what `hook_outcome` reads.

/// What a hook's wrapper (`safeHook` in index.js) returned: `true` to go
/// on, `false` to stop a redirect, or the id under which it keeps the value
/// the hook threw. That fails the request with [`KoonError::Hook`], and its
/// promise rejects with the thrown value (see [`koon_napi_error`]).
fn hook_outcome(value: JsUnknown) -> std::result::Result<bool, KoonError> {
    match value.get_type() {
        Ok(ValueType::Boolean) => Ok(value
            .coerce_to_bool()
            .and_then(|b| b.get_value())
            .unwrap_or(true)),
        Ok(ValueType::Number) => {
            let id = value.coerce_to_number().and_then(|n| n.get_double());
            Err(KoonError::Hook(Box::new(ThrownByHook(
                id.unwrap_or_default() as u64,
            ))))
        }
        _ => Ok(true),
    }
}

/// Call a hook on the JS thread and wait for its outcome. The core calls
/// hooks synchronously from inside an async task, so the JS call is waited
/// on with a blocking channel receive; `block_in_place` moves the worker's
/// other tasks elsewhere meanwhile. A call that cannot be made (the
/// environment is shutting down) goes on as without a hook.
fn call_hook<T: 'static>(
    tsfn: &ThreadsafeFunction<T, ErrorStrategy::Fatal>,
    args: T,
) -> std::result::Result<bool, KoonError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let queued = tsfn.call_with_return_value(
        args,
        ThreadsafeFunctionCallMode::Blocking,
        move |returned: JsUnknown| {
            let _ = tx.send(hook_outcome(returned));
            Ok(())
        },
    );
    if queued != Status::Ok {
        return Ok(true);
    }
    tokio::task::block_in_place(|| rx.recv().unwrap_or(Ok(true)))
}

fn on_request_hook(
    tsfn: RequestHookFn,
) -> impl Fn(&str, &str) -> std::result::Result<(), KoonError> + Send + Sync + 'static {
    move |method: &str, url: &str| call_hook(&tsfn, (method.to_string(), url.to_string())).map(drop)
}

fn on_response_hook(
    tsfn: ResponseHookFn,
) -> impl Fn(u16, &str, &[(String, String)]) -> std::result::Result<(), KoonError> + Send + Sync + 'static
{
    move |status: u16, url: &str, headers: &[(String, String)]| {
        call_hook(&tsfn, (status, url.to_string(), to_koon_headers(headers))).map(drop)
    }
}

/// Follows the redirect unless the hook returned exactly `false`.
fn on_redirect_hook(
    tsfn: ResponseHookFn,
) -> impl Fn(u16, &str, &[(String, String)]) -> std::result::Result<bool, KoonError>
+ Send
+ Sync
+ 'static {
    move |status: u16, url: &str, headers: &[(String, String)]| {
        call_hook(&tsfn, (status, url.to_string(), to_koon_headers(headers)))
    }
}

/// A hook kept by a client for its whole lifetime must not keep the Node.js
/// event loop (and so the process) alive after the client is gone.
fn unref<T: 'static>(
    env: Env,
    mut tsfn: ThreadsafeFunction<T, ErrorStrategy::Fatal>,
) -> Result<ThreadsafeFunction<T, ErrorStrategy::Fatal>> {
    tsfn.unref(&env)?;
    Ok(tsfn)
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for creating a Koon client (documented in index.d.ts).
///
/// `object_to_js = false`: only ever read from JS, never returned to it; the
/// hook fields hold `ThreadsafeFunction`, which only converts from JS.
#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct KoonOptions {
    pub browser: Option<String>,
    pub profile_json: Option<String>,
    pub proxy: Option<String>,
    pub proxies: Option<Vec<String>>,
    pub timeout: Option<f64>,
    pub ignore_tls_errors: Option<bool>,
    pub proxy_ca_certs: Option<Either<String, Buffer>>,
    pub ignore_proxy_tls_errors: Option<bool>,
    pub headers: Option<Headers>,
    pub follow_redirects: Option<bool>,
    pub max_redirects: Option<f64>,
    pub cookie_jar: Option<bool>,
    pub session_resumption: Option<bool>,
    pub doh: Option<String>,
    pub local_address: Option<String>,
    pub retries: Option<f64>,
    pub locale: Option<String>,
    pub proxy_headers: Option<Headers>,
    pub ip_version: Option<f64>,
    pub resolve: Option<Vec<String>>,
    /// Maximum response body size in bytes, decompressed; 0 disables it. Default: 100 MiB.
    pub max_response_body: Option<f64>,
    /// Pins Chrome/Edge/Opera >=151's server-padding field trial group instead of drawing it:
    /// "none", or the bytes of padding the group asks for. Default: drawn per client.
    pub server_padding: Option<String>,
    pub on_request: Option<RequestHookFn>,
    pub on_response: Option<ResponseHookFn>,
    pub on_redirect: Option<ResponseHookFn>,
}

/// Per-request settings; unset fields fall back to the client's.
#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct KoonRequestOptions {
    pub headers: Option<Headers>,
    pub timeout: Option<f64>,
    pub proxy: Option<String>,
    pub follow_redirects: Option<bool>,
    pub max_redirects: Option<f64>,
    pub on_request: Option<RequestHookFn>,
    pub on_response: Option<ResponseHookFn>,
    pub on_redirect: Option<ResponseHookFn>,
}

/// The connection-to-origins-and-proxies fields `KoonOptions` and
/// `KoonProxyOptions` both declare (napi objects map a flat JS shape, so
/// neither can nest this struct as a field), collected once here so their
/// application logic lives in `connection_builder` alone instead of twice.
struct ConnectionOptions {
    ignore_tls_errors: Option<bool>,
    proxy: Option<String>,
    proxies: Option<Vec<String>>,
    proxy_ca_certs: Option<Either<String, Buffer>>,
    ignore_proxy_tls_errors: Option<bool>,
    proxy_headers: Option<Headers>,
    session_resumption: Option<bool>,
    doh: Option<String>,
    local_address: Option<String>,
    retries: Option<f64>,
    locale: Option<String>,
    ip_version: Option<f64>,
    resolve: Option<Vec<String>>,
    max_response_body: Option<f64>,
    server_padding: Option<String>,
}

/// A core client builder for `profile` with the shared connection options.
/// Unset options keep the core's defaults.
fn connection_builder(profile: BrowserProfile, opts: ConnectionOptions) -> Result<ClientBuilder> {
    let proxy_ca_certs = opts.proxy_ca_certs.map(|pem| match pem {
        Either::A(text) => text.into_bytes(),
        Either::B(buffer) => buffer.to_vec(),
    });
    let local_address = opts
        .local_address
        .as_deref()
        .map(|address| {
            address
                .parse::<IpAddr>()
                .map_err(|e| invalid_argument(format!("Invalid localAddress '{address}': {e}")))
        })
        .transpose()?;
    let doh = opts
        .doh
        .as_deref()
        .map(|provider| provider.parse::<DohConfig>().map_err(koon_napi_error))
        .transpose()?;
    let ip_version = opts.ip_version.map(ip_version).transpose()?;
    let retries = opts
        .retries
        .map(|r| whole_number::<u32>("retries", r))
        .transpose()?
        .unwrap_or(0);
    let max_response_body = opts
        .max_response_body
        .map(|max| whole_number::<u64>("maxResponseBody", max))
        .transpose()?
        .unwrap_or_else(|| koon_core::ConnectionOptions::default().max_response_body);
    let server_padding = opts
        .server_padding
        .as_deref()
        .map(|padding| {
            padding
                .parse::<koon_core::ServerPadding>()
                .map_err(koon_napi_error)
        })
        .transpose()?;

    let connection = koon_core::ConnectionOptions {
        ignore_tls_errors: opts.ignore_tls_errors.unwrap_or(false),
        proxy: opts.proxy,
        proxies: opts.proxies.unwrap_or_default(),
        proxy_ca_certs,
        ignore_proxy_tls_errors: opts.ignore_proxy_tls_errors.unwrap_or(false),
        proxy_headers: headers(opts.proxy_headers),
        session_resumption: opts.session_resumption.unwrap_or(true),
        doh,
        local_address,
        retries,
        locale: opts.locale,
        ip_version,
        resolve: opts.resolve.unwrap_or_default(),
        max_response_body,
        server_padding,
    };
    connection.apply(profile).map_err(koon_napi_error)
}

/// A core client builder for every option but the hooks, which need the
/// `Env` (`Koon` adds them); `KoonProxy` builds its upstream client with
/// `connection_builder` directly instead, since it has no headers, redirect
/// or cookie-jar options of its own.
fn client_builder(opts: KoonOptions) -> Result<ClientBuilder> {
    let KoonOptions {
        browser,
        profile_json,
        proxy,
        proxies,
        timeout: timeout_secs,
        ignore_tls_errors,
        proxy_ca_certs,
        ignore_proxy_tls_errors,
        headers: headers_opt,
        follow_redirects,
        max_redirects,
        cookie_jar,
        session_resumption,
        doh,
        local_address,
        retries,
        locale,
        proxy_headers,
        ip_version,
        resolve,
        max_response_body,
        server_padding,
        ..
    } = opts;

    let profile = resolve_profile(browser.as_deref(), profile_json.as_deref())?;
    let connection = ConnectionOptions {
        ignore_tls_errors,
        proxy,
        proxies,
        proxy_ca_certs,
        ignore_proxy_tls_errors,
        proxy_headers,
        session_resumption,
        doh,
        local_address,
        retries,
        locale,
        ip_version,
        resolve,
        max_response_body,
        server_padding,
    };
    let mut builder = connection_builder(profile, connection)?.headers(headers(headers_opt));
    if let Some(secs) = timeout_secs {
        builder = builder.timeout(timeout(secs)?);
    }
    if let Some(follow) = follow_redirects {
        builder = builder.follow_redirects(follow);
    }
    if let Some(max) = max_redirects {
        builder = builder.max_redirects(whole_number("maxRedirects", max)?);
    }
    if let Some(enabled) = cookie_jar {
        builder = builder.cookie_jar(enabled);
    }
    Ok(builder)
}

/// Core request options. The hooks are not unref'd: they live only as long
/// as this one call, which keeps the process alive anyway.
fn request_options(options: Option<KoonRequestOptions>) -> Result<koon_core::RequestOptions> {
    let Some(opts) = options else {
        return Ok(koon_core::RequestOptions::default());
    };
    Ok(koon_core::RequestOptions {
        headers: headers(opts.headers),
        proxy: opts.proxy,
        timeout: opts.timeout.map(timeout).transpose()?,
        follow_redirects: opts.follow_redirects,
        max_redirects: opts
            .max_redirects
            .map(|n| whole_number("maxRedirects", n))
            .transpose()?,
        on_request: opts
            .on_request
            .map(|f| Arc::new(on_request_hook(f)) as koon_core::OnRequestHook),
        on_response: opts
            .on_response
            .map(|f| Arc::new(on_response_hook(f)) as koon_core::OnResponseHook),
        on_redirect: opts
            .on_redirect
            .map(|f| Arc::new(on_redirect_hook(f)) as koon_core::OnRedirectHook),
    })
}

// ---------------------------------------------------------------------------
// Plain objects
// ---------------------------------------------------------------------------

/// A cookie in the Playwright/CDP shape; converted by the core's
/// [`CookieParams`].
#[napi(object)]
pub struct KoonCookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub expires: Option<f64>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub host_only: Option<bool>,
    /// CDP's partition key object or Playwright's string; any value other
    /// than `null` marks a partitioned cookie.
    pub partition_key: Option<JsUnknown>,
    pub partition_key_opaque: Option<bool>,
}

impl From<KoonCookie> for CookieParams {
    fn from(cookie: KoonCookie) -> Self {
        let has_partition_key = cookie
            .partition_key
            .is_some_and(|key| !matches!(key.get_type(), Ok(ValueType::Null)));
        Self {
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            url: cookie.url,
            expires: cookie.expires,
            http_only: cookie.http_only.unwrap_or(false),
            secure: cookie.secure.unwrap_or(false),
            same_site: cookie.same_site,
            host_only: cookie.host_only,
            partitioned: has_partition_key || cookie.partition_key_opaque == Some(true),
        }
    }
}

impl From<CookieParams> for KoonCookie {
    fn from(cookie: CookieParams) -> Self {
        Self {
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            url: cookie.url,
            expires: cookie.expires,
            secure: Some(cookie.secure),
            http_only: Some(cookie.http_only),
            same_site: cookie.same_site,
            host_only: cookie.host_only,
            partition_key: None,
            partition_key_opaque: None,
        }
    }
}

/// A cookie `setCookies()` did not import: its position in the array given
/// (0-based), its name and why.
#[napi(object, object_from_js = false)]
pub struct KoonSkippedCookie {
    pub index: u32,
    pub name: String,
    pub reason: String,
}

impl From<SkippedCookie> for KoonSkippedCookie {
    fn from(skipped: SkippedCookie) -> Self {
        Self {
            // A JS array has fewer than 2^32 elements.
            index: skipped.index as u32,
            name: skipped.name,
            reason: skipped.reason,
        }
    }
}

/// A header as a name-value object; an array of these keeps duplicates.
#[napi(object)]
pub struct KoonHeader {
    pub name: String,
    pub value: String,
}

/// A field of a multipart/form-data request: `value` or `fileData`.
#[napi(object)]
pub struct KoonMultipartField {
    pub name: String,
    pub value: Option<String>,
    pub file_data: Option<Buffer>,
    pub filename: Option<String>,
    pub content_type: Option<String>,
}

fn build_multipart(fields: Vec<KoonMultipartField>) -> Result<Multipart> {
    let mut multipart = Multipart::new();
    for field in fields {
        multipart = if let Some(data) = field.file_data {
            multipart.file(
                field.name,
                field.filename.unwrap_or_else(|| "file".to_string()),
                field
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                data.into(),
            )
        } else if let Some(value) = field.value {
            multipart.text(field.name, value)
        } else {
            return Err(invalid_argument(format!(
                "multipart field '{}' has neither value nor fileData",
                field.name
            )));
        };
    }
    Ok(multipart)
}

/// A multipart/form-data body with its Content-Type (`koonFetch` sends a
/// `FormData` this way).
#[napi(object, object_from_js = false)]
pub struct KoonEncodedBody {
    pub body: Buffer,
    pub content_type: String,
}

/// A WebSocket message.
#[napi(object)]
pub struct KoonWsMessage {
    pub is_text: bool,
    pub data: Buffer,
}

// ---------------------------------------------------------------------------
// KoonResponse
// ---------------------------------------------------------------------------

/// A response with its body read completely.
#[napi(custom_finalize)]
pub struct KoonResponse {
    #[napi(readonly)]
    pub status: u16,
    #[napi(readonly)]
    pub version: String,
    #[napi(readonly)]
    pub url: String,
    #[napi(readonly)]
    pub bytes_sent: f64,
    #[napi(readonly)]
    pub bytes_received: f64,
    #[napi(readonly)]
    pub tls_resumed: bool,
    #[napi(readonly)]
    pub connection_reused: bool,
    #[napi(readonly)]
    pub remote_address: Option<String>,
    headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    /// Shared with the `body` Buffer once that is created, without a copy.
    body: Buffer,
    headers_js: JsCache,
    request_headers_js: JsCache,
    body_js: JsCache,
}

impl From<koon_core::HttpResponse> for KoonResponse {
    fn from(response: koon_core::HttpResponse) -> Self {
        Self {
            status: response.status,
            version: response.version,
            url: response.url,
            bytes_sent: response.bytes_sent as f64,
            bytes_received: response.bytes_received as f64,
            tls_resumed: response.tls_resumed,
            connection_reused: response.connection_reused,
            remote_address: response.remote_address,
            headers: response.headers,
            request_headers: response.request_headers,
            body: response.body.into(),
            headers_js: JsCache::default(),
            request_headers_js: JsCache::default(),
            body_js: JsCache::default(),
        }
    }
}

impl ObjectFinalize for KoonResponse {
    fn finalize(self, env: Env) -> Result<()> {
        let headers = self.headers_js.release(env);
        let request_headers = self.request_headers_js.release(env);
        let body = self.body_js.release(env);
        headers.and(request_headers).and(body)
    }
}

#[napi]
impl KoonResponse {
    /// Alias for `status`.
    #[napi(getter)]
    pub const fn status_code(&self) -> u16 {
        self.status
    }

    #[napi(getter)]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    #[napi(getter)]
    pub fn headers(&self, env: Env) -> Result<JsUnknown> {
        self.headers_js
            .get_or_init(env, || to_koon_headers(&self.headers))
    }

    #[napi(getter)]
    pub fn request_headers(&self, env: Env) -> Result<JsUnknown> {
        self.request_headers_js
            .get_or_init(env, || to_koon_headers(&self.request_headers))
    }

    #[napi(getter)]
    pub fn body(&self, env: Env) -> Result<JsUnknown> {
        self.body_js.get_or_init(env, || self.body.clone())
    }

    #[napi(getter)]
    pub fn content_type(&self) -> Option<String> {
        header_value(&self.headers, "content-type").map(str::to_string)
    }

    #[napi]
    pub fn header(&self, name: String) -> Option<String> {
        header_value(&self.headers, &name).map(str::to_string)
    }

    /// The body decoded with the charset of its Content-Type, else UTF-8.
    #[napi]
    pub fn text(&self, env: Env) -> Result<JsString> {
        env.create_string(&koon_core::decode_body_text(
            &self.body,
            header_value(&self.headers, "content-type"),
        ))
    }

    /// `JSON.parse()` of `text()`.
    #[napi]
    pub fn json(&self, env: Env) -> Result<JsUnknown> {
        let text = self.text(env)?;
        let json: JsObject = env.get_global()?.get_named_property("JSON")?;
        let parse: JsFunction = json.get_named_property("parse")?;
        parse.call(None, &[text])
    }
}

// ---------------------------------------------------------------------------
// Koon
// ---------------------------------------------------------------------------

/// The HTTP client with browser fingerprint impersonation.
#[napi]
pub struct Koon {
    /// Shared with the requests `_fetch` starts as tasks of their own.
    client: Arc<Client>,
}

#[napi]
impl Koon {
    #[napi(constructor)]
    pub fn new(env: Env, options: Option<KoonOptions>) -> Result<Self> {
        let mut opts = options.unwrap_or_default();
        let on_request = opts.on_request.take();
        let on_response = opts.on_response.take();
        let on_redirect = opts.on_redirect.take();

        let mut builder = client_builder(opts)?;
        if let Some(tsfn) = on_request {
            builder = builder.on_request(on_request_hook(unref(env, tsfn)?));
        }
        if let Some(tsfn) = on_response {
            builder = builder.on_response(on_response_hook(unref(env, tsfn)?));
        }
        if let Some(tsfn) = on_redirect {
            builder = builder.on_redirect(on_redirect_hook(unref(env, tsfn)?));
        }

        let client = builder.build().map_err(koon_napi_error)?;
        Ok(Self {
            client: Arc::new(client),
        })
    }

    #[napi(getter)]
    pub fn user_agent(&self) -> Option<String> {
        self.client.user_agent().map(str::to_string)
    }

    #[napi]
    pub fn export_profile(&self) -> Result<String> {
        self.client
            .profile()
            .to_json_pretty()
            .map_err(|e| koon_napi_error(KoonError::Json(e)))
    }

    /// The verbs (get, post, ...) are defined on top of this in index.js.
    #[napi]
    pub async fn request(
        &self,
        method: String,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        let (method, body) = method_and_body(&method, body)?;
        let response = self
            .client
            .send(method, &url, body, request_options(options)?)
            .await
            .map_err(koon_napi_error)?;
        Ok(response.into())
    }

    #[napi]
    pub async fn post_multipart(
        &self,
        url: String,
        fields: Vec<KoonMultipartField>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonResponse> {
        let response = self
            .client
            .post_multipart(&url, build_multipart(fields)?, request_options(options)?)
            .await
            .map_err(koon_napi_error)?;
        Ok(response.into())
    }

    #[napi]
    pub async fn request_streaming(
        &self,
        method: String,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonStreamingResponse> {
        let (method, body) = method_and_body(&method, body)?;
        let response = self
            .client
            .send_streaming(method, &url, body, request_options(options)?)
            .await
            .map_err(koon_napi_error)?;
        Ok(response.into())
    }

    /// Start a streaming request for `koonFetch` (fetch.js) as a task of its
    /// own: `response()` of the result waits for the response head, and
    /// `abort()` cancels the request before it arrives.
    #[napi(js_name = "_fetch")]
    pub fn fetch(
        &self,
        method: String,
        url: String,
        body: Option<Either<String, Buffer>>,
        options: Option<KoonRequestOptions>,
    ) -> Result<KoonPendingResponse> {
        let (method, body) = method_and_body(&method, body)?;
        let options = request_options(options)?;
        let client = self.client.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task = spawn(async move {
            let _ = sender.send(client.send_streaming(method, &url, body, options).await);
        });
        Ok(KoonPendingResponse {
            receiver: std::sync::Mutex::new(Some(receiver)),
            task: task.abort_handle(),
        })
    }

    /// A multipart/form-data body with the boundary of the profile's
    /// browser, as `postMultipart()` sends it (for a `FormData` in koonFetch).
    #[napi(js_name = "_encodeMultipart")]
    pub fn encode_multipart(&self, fields: Vec<KoonMultipartField>) -> Result<KoonEncodedBody> {
        let profile = self.client.profile();
        let family = profile
            .header_family
            .unwrap_or_else(|| HeaderFamily::detect(profile));
        let style = match family {
            HeaderFamily::Firefox => BoundaryStyle::Gecko,
            _ => BoundaryStyle::WebKit,
        };
        let (body, content_type) = build_multipart(fields)?.build_with(style);
        Ok(KoonEncodedBody {
            body: body.into(),
            content_type,
        })
    }

    #[napi]
    pub fn save_session(&self) -> Result<String> {
        self.client.save_session().map_err(koon_napi_error)
    }

    #[napi]
    pub fn load_session(&self, json: String) -> Result<()> {
        self.client.load_session(&json).map_err(koon_napi_error)
    }

    #[napi]
    pub fn save_session_to_file(&self, path: String) -> Result<()> {
        self.client
            .save_session_to_file(&path)
            .map_err(koon_napi_error)
    }

    #[napi]
    pub fn load_session_from_file(&self, path: String) -> Result<()> {
        self.client
            .load_session_from_file(&path)
            .map_err(koon_napi_error)
    }

    #[napi]
    pub fn total_bytes_sent(&self) -> f64 {
        self.client.total_bytes_sent() as f64
    }

    #[napi]
    pub fn total_bytes_received(&self) -> f64 {
        self.client.total_bytes_received() as f64
    }

    #[napi]
    pub fn reset_counters(&self) {
        self.client.reset_counters();
    }

    #[napi]
    pub fn clear_cookies(&self) {
        self.client.clear_cookies();
    }

    /// Returns the cookies that were not imported.
    #[napi]
    pub fn set_cookies(&self, cookies: Vec<KoonCookie>) -> Result<Vec<KoonSkippedCookie>> {
        let skipped = self
            .client
            .set_cookie_params(cookies.into_iter().map(CookieParams::from).collect())
            .map_err(koon_napi_error)?;
        Ok(skipped.into_iter().map(KoonSkippedCookie::from).collect())
    }

    #[napi]
    pub fn cookies(&self) -> Vec<KoonCookie> {
        self.client
            .cookie_params()
            .into_iter()
            .map(KoonCookie::from)
            .collect()
    }

    /// Every built-in profile name, as `BrowserProfile::names` lists them.
    #[napi]
    pub fn browsers() -> Vec<String> {
        BrowserProfile::names()
            .map(|profile| profile.name)
            .collect()
    }

    #[napi]
    pub fn close(&self) {
        self.client.close();
    }

    #[napi]
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }

    #[napi]
    pub async fn websocket(&self, url: String, headers: Option<Headers>) -> Result<KoonWebSocket> {
        let socket = self
            .client
            .websocket_with_headers(&url, self::headers(headers))
            .await
            .map_err(koon_napi_error)?;
        Ok(KoonWebSocket { socket })
    }
}

// ---------------------------------------------------------------------------
// KoonStreamingResponse
// ---------------------------------------------------------------------------

/// Reading a streaming body after `collect()` read it or `cancel()`
/// dropped it: the core's `BODY_ERROR`, as in the Python binding.
fn stream_consumed() -> napi::Error {
    koon_napi_error(KoonError::Body(
        "the response body was already read by collect() or cancelled".into(),
        None,
    ))
}

type StreamingResult = std::result::Result<koon_core::StreamingResponse, KoonError>;

/// A request `Koon._fetch` started: its response head, or an abort.
#[napi]
pub struct KoonPendingResponse {
    receiver: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<StreamingResult>>>,
    task: tokio::task::AbortHandle,
}

#[napi]
impl KoonPendingResponse {
    /// The response once its head has arrived. Rejects with `BODY_ERROR` when
    /// the request was aborted or this was called before.
    #[napi]
    pub async fn response(&self) -> Result<KoonStreamingResponse> {
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| {
                koon_napi_error(KoonError::Body("response() was called before".into(), None))
            })?;
        match receiver.await {
            Ok(response) => response.map(Into::into).map_err(koon_napi_error),
            Err(_) => Err(koon_napi_error(KoonError::Body(
                "the request was aborted".into(),
                None,
            ))),
        }
    }

    /// Cancel the request; nothing happens once its head has arrived.
    #[napi]
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// A response whose body is read in chunks.
///
/// Its plain values are getter functions rather than `#[napi(readonly)]`
/// fields: napi-derive's field getter borrows the object mutably, while a
/// pending `nextChunk()` holds a shared borrow on a tokio thread.
#[napi(custom_finalize)]
pub struct KoonStreamingResponse {
    status: u16,
    headers: Vec<(String, String)>,
    request_headers: Vec<(String, String)>,
    version: String,
    url: String,
    remote_address: Option<String>,
    tls_resumed: bool,
    connection_reused: bool,
    bytes_sent: u64,
    /// Updated after each chunk, so `bytesReceived()` does not wait for the
    /// lock a pending `nextChunk()`/`collect()` holds.
    bytes_received: AtomicU64,
    headers_js: JsCache,
    request_headers_js: JsCache,
    /// Set by `cancel()`; a pending `nextChunk()` then drops the body.
    cancelled: tokio::sync::watch::Sender<bool>,
    inner: tokio::sync::Mutex<Option<koon_core::StreamingResponse>>,
}

impl From<koon_core::StreamingResponse> for KoonStreamingResponse {
    fn from(mut response: koon_core::StreamingResponse) -> Self {
        Self {
            status: response.status,
            // Cloned: `decode_content()` reads the core response's headers.
            headers: response.headers.clone(),
            request_headers: std::mem::take(&mut response.request_headers),
            version: std::mem::take(&mut response.version),
            url: std::mem::take(&mut response.url),
            remote_address: response.remote_address.take(),
            tls_resumed: response.tls_resumed,
            connection_reused: response.connection_reused,
            bytes_sent: response.bytes_sent(),
            bytes_received: AtomicU64::new(response.bytes_received()),
            headers_js: JsCache::default(),
            request_headers_js: JsCache::default(),
            cancelled: tokio::sync::watch::Sender::new(false),
            inner: tokio::sync::Mutex::new(Some(response)),
        }
    }
}

impl ObjectFinalize for KoonStreamingResponse {
    fn finalize(self, env: Env) -> Result<()> {
        let headers = self.headers_js.release(env);
        headers.and(self.request_headers_js.release(env))
    }
}

#[napi]
impl KoonStreamingResponse {
    #[napi(getter)]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Alias for `status`.
    #[napi(getter)]
    pub const fn status_code(&self) -> u16 {
        self.status
    }

    #[napi(getter)]
    pub fn headers(&self, env: Env) -> Result<JsUnknown> {
        self.headers_js
            .get_or_init(env, || to_koon_headers(&self.headers))
    }

    #[napi(getter)]
    pub fn request_headers(&self, env: Env) -> Result<JsUnknown> {
        self.request_headers_js
            .get_or_init(env, || to_koon_headers(&self.request_headers))
    }

    #[napi(getter)]
    pub fn version(&self) -> String {
        self.version.clone()
    }

    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[napi(getter)]
    pub fn remote_address(&self) -> Option<String> {
        self.remote_address.clone()
    }

    #[napi(getter)]
    pub const fn tls_resumed(&self) -> bool {
        self.tls_resumed
    }

    #[napi(getter)]
    pub const fn connection_reused(&self) -> bool {
        self.connection_reused
    }

    #[napi(getter)]
    pub const fn bytes_sent(&self) -> f64 {
        self.bytes_sent as f64
    }

    #[napi]
    pub fn bytes_received(&self) -> f64 {
        self.bytes_received.load(Ordering::Relaxed) as f64
    }

    /// The next body chunk, or null when the body is complete.
    #[napi]
    pub async fn next_chunk(&self) -> Result<Option<Buffer>> {
        let mut cancelled = self.cancelled.subscribe();
        let mut guard = self.inner.lock().await;
        let read = {
            let response = guard.as_mut().ok_or_else(stream_consumed)?;
            tokio::select! {
                chunk = response.next_chunk() => Some(chunk),
                _ = cancelled.wait_for(|cancelled| *cancelled) => None,
            }
        };
        let Some(chunk) = read else {
            guard.take();
            return Err(stream_consumed());
        };
        let chunk = chunk.transpose().map_err(koon_napi_error)?;
        if let Some(response) = guard.as_ref() {
            self.bytes_received
                .store(response.bytes_received(), Ordering::Relaxed);
        }
        Ok(chunk.map(Buffer::from))
    }

    /// Decode the body's Content-Encoding from now on, before the first
    /// read (koonFetch). Returns whether there is anything to decode; the
    /// headers stay as received.
    #[napi(js_name = "_decodeContent")]
    pub fn decode_content(&self) -> Result<bool> {
        let mut guard = self.inner.try_lock().map_err(|_| {
            koon_napi_error(KoonError::Body(
                "the response body is being read".into(),
                None,
            ))
        })?;
        let response = guard.as_mut().ok_or_else(stream_consumed)?;
        Ok(response.decode_content())
    }

    /// Drop the rest of the body without reading it: the stream is closed
    /// (HTTP/1.1) or reset (HTTP/2, HTTP/3), a pending `nextChunk()` and
    /// every later read reject with `BODY_ERROR`. `for await` calls it when
    /// the loop is left early; koonFetch when its body is cancelled.
    #[napi]
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
        if let Ok(mut guard) = self.inner.try_lock() {
            guard.take();
        }
    }

    /// The rest of the body as one Buffer. Consumes the stream.
    #[napi]
    pub async fn collect(&self) -> Result<Buffer> {
        let mut cancelled = self.cancelled.subscribe();
        let mut response = self.inner.lock().await.take().ok_or_else(stream_consumed)?;
        let body = tokio::select! {
            body = response.collect_body() => body.map_err(koon_napi_error)?,
            _ = cancelled.wait_for(|cancelled| *cancelled) => return Err(stream_consumed()),
        };
        self.bytes_received
            .store(response.bytes_received(), Ordering::Relaxed);
        Ok(body.into())
    }
}

// ---------------------------------------------------------------------------
// KoonWebSocket
// ---------------------------------------------------------------------------

/// A WebSocket connection. The core socket reads and writes under separate
/// locks, so a pending `receive()` does not block `send()` or `close()`.
#[napi]
pub struct KoonWebSocket {
    socket: koon_core::WebSocket,
}

#[napi]
impl KoonWebSocket {
    /// Send a string as a text message or a Buffer as a binary message.
    #[napi]
    pub async fn send(&self, data: Either<String, Buffer>) -> Result<()> {
        match data {
            Either::A(text) => self.socket.send_text(&text).await,
            Either::B(buffer) => self.socket.send_binary(&buffer).await,
        }
        .map_err(koon_napi_error)
    }

    /// The next message, or null once the connection is closed.
    #[napi]
    pub async fn receive(&self) -> Result<Option<KoonWsMessage>> {
        let message = self.socket.receive().await.map_err(koon_napi_error)?;
        Ok(message.map(|message| match message {
            WsMessage::Text(text) => KoonWsMessage {
                is_text: true,
                data: text.into_bytes().into(),
            },
            WsMessage::Binary(data) => KoonWsMessage {
                is_text: false,
                data: data.into(),
            },
        }))
    }

    #[napi]
    pub async fn close(&self, code: Option<f64>, reason: Option<String>) -> Result<()> {
        let code = code.map(|code| whole_number("code", code)).transpose()?;
        self.socket
            .close(code, reason)
            .await
            .map_err(koon_napi_error)
    }
}

// ---------------------------------------------------------------------------
// KoonProxy
// ---------------------------------------------------------------------------

/// Options for starting a MITM proxy server (documented in index.d.ts).
#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct KoonProxyOptions {
    pub browser: Option<String>,
    pub profile_json: Option<String>,
    pub listen_addr: Option<String>,
    pub header_mode: Option<String>,
    pub ca_dir: Option<String>,
    pub timeout: Option<f64>,
    /// Allow `listen_addr` to bind a non-loopback address (an open relay
    /// through koon's fingerprinted TLS/HTTP2 stack unless `auth` is also
    /// set). Default: `false`.
    pub allow_non_loopback: Option<bool>,
    /// `Proxy-Authorization: Basic` credentials required of every client.
    pub auth: Option<KoonProxyAuth>,
    /// Connections accepted at once; further ones wait for a slot to free up.
    pub max_connections: Option<f64>,
    // The upstream client's connection options, as in `KoonOptions`.
    pub proxy: Option<String>,
    pub proxies: Option<Vec<String>>,
    pub ignore_tls_errors: Option<bool>,
    pub proxy_ca_certs: Option<Either<String, Buffer>>,
    pub ignore_proxy_tls_errors: Option<bool>,
    pub proxy_headers: Option<Headers>,
    pub session_resumption: Option<bool>,
    pub doh: Option<String>,
    pub local_address: Option<String>,
    pub retries: Option<f64>,
    pub locale: Option<String>,
    pub ip_version: Option<f64>,
    pub resolve: Option<Vec<String>>,
    pub max_response_body: Option<f64>,
    pub server_padding: Option<String>,
}

/// `Proxy-Authorization: Basic` credentials a `KoonProxy` requires of its clients.
#[napi(object)]
pub struct KoonProxyAuth {
    pub username: String,
    pub password: String,
}

impl From<KoonProxyAuth> for ProxyServerAuth {
    fn from(auth: KoonProxyAuth) -> Self {
        Self {
            username: auth.username,
            password: auth.password,
        }
    }
}

/// A local MITM proxy that forwards intercepted traffic with koon's
/// fingerprinted TLS/HTTP2 stack.
#[napi]
pub struct KoonProxy {
    #[napi(readonly)]
    pub port: u16,
    #[napi(readonly)]
    pub url: String,
    #[napi(readonly)]
    pub ca_cert_path: String,
    ca_cert_pem: Vec<u8>,
    server: std::sync::Mutex<Option<ProxyServer>>,
}

#[napi]
impl KoonProxy {
    #[napi(factory)]
    pub async fn start(options: Option<KoonProxyOptions>) -> Result<Self> {
        let KoonProxyOptions {
            browser,
            profile_json,
            listen_addr,
            header_mode,
            ca_dir,
            timeout: timeout_secs,
            allow_non_loopback,
            auth,
            max_connections,
            proxy,
            proxies,
            ignore_tls_errors,
            proxy_ca_certs,
            ignore_proxy_tls_errors,
            proxy_headers,
            session_resumption,
            doh,
            local_address,
            retries,
            locale,
            ip_version,
            resolve,
            max_response_body,
            server_padding,
        } = options.unwrap_or_default();

        let profile = resolve_profile(browser.as_deref(), profile_json.as_deref())?;
        // The upstream client takes the same connection options as a `Koon`
        // client does; the proxy turns redirects and the cookie jar off.
        let connection = ConnectionOptions {
            ignore_tls_errors,
            proxy,
            proxies,
            proxy_ca_certs,
            ignore_proxy_tls_errors,
            proxy_headers,
            session_resumption,
            doh,
            local_address,
            retries,
            locale,
            ip_version,
            resolve,
            max_response_body,
            server_padding,
        };
        let mut client = connection_builder(profile, connection)?;
        if let Some(secs) = timeout_secs {
            client = client.timeout(timeout(secs)?);
        }
        let mut config = ProxyServerConfig {
            ca_dir,
            client,
            ..ProxyServerConfig::default()
        };
        if let Some(address) = listen_addr {
            config.listen_addr = address;
        }
        if let Some(mode) = &header_mode {
            config.header_mode = mode.parse().map_err(koon_napi_error)?;
        }
        if let Some(allow) = allow_non_loopback {
            config.allow_non_loopback = allow;
        }
        if let Some(auth) = auth {
            config.auth = Some(auth.into());
        }
        if let Some(max) = max_connections {
            config.max_connections = whole_number("maxConnections", max)?;
        }

        let server = ProxyServer::start(config).await.map_err(koon_napi_error)?;
        Ok(Self {
            port: server.port(),
            url: server.url(),
            ca_cert_path: server.ca_cert_path().to_string_lossy().into_owned(),
            ca_cert_pem: server.ca_cert_pem().map_err(koon_napi_error)?,
            server: std::sync::Mutex::new(Some(server)),
        })
    }

    #[napi]
    pub fn ca_cert_pem(&self) -> Buffer {
        self.ca_cert_pem.clone().into()
    }

    /// Stop accepting and close every open connection. Idempotent. A
    /// promise, like `Koon.shutdown()` and Python's `KoonProxy.shutdown()`.
    #[napi]
    pub async fn shutdown(&self) {
        let server = self
            .server
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(server) = server {
            server.shutdown();
        }
    }
}

/// The fingerprint self-test of `koon_core::verify` for one profile, as the
/// report's JSON; index.js parses it for `Koon.verify()`.
#[napi]
pub async fn verify_json(browser: String, proxy: Option<String>) -> Result<String> {
    koon_core::verify::verify(&browser, proxy.as_deref())
        .await
        .map(|report| report.to_json())
        .map_err(koon_napi_error)
}
