//! Python binding for koon, a thin wrapper around `koon_core`.
//!
//! `Koon` (async) and `KoonSync` (blocking) are Python subclasses of the
//! native `_Client` (see `python/koon/__init__.py`). Every request goes
//! through `_Client._request`, which returns an awaitable or blocks.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pyo3::IntoPyObjectExt;
use pyo3::call::PyCallArgs;
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyDict, PyList, PyMapping, PyString};

use koon_core::{
    Body, BoundaryStyle, BrowserProfile, ClientBuilder, CookieParams, HeaderFamily, HeaderMode,
    IpVersion, Multipart, OnRedirectHook, OnRequestHook, OnResponseHook, ProxyServer,
    ProxyServerConfig, RequestOptions, SkippedCookie, WsMessage,
};

/// How often a blocking request checks for Ctrl+C.
const SIGNAL_CHECK_INTERVAL: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Structured error raised by every failing koon operation.
///
/// Carries a machine-readable `.code` (e.g. `"TIMEOUT"`, `"TLS_ERROR"`,
/// `"INVALID_COOKIE"`) alongside the usual exception message, which has the
/// form `"[CODE] description"`. Picklable: the code is parsed back from the
/// message.
#[pyclass(extends = PyRuntimeError, subclass, frozen, module = "koon")]
struct KoonError {
    #[pyo3(get)]
    code: String,
}

#[pymethods]
impl KoonError {
    #[new]
    fn new(message: &str) -> Self {
        let code = message
            .strip_prefix('[')
            .and_then(|rest| rest.split_once(']'))
            .map_or("UNKNOWN", |(code, _)| code);
        Self {
            code: code.to_string(),
        }
    }
}

const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";

// `class KoonInvalidArgument(KoonError, ValueError)` in `koon/__init__.py`:
// a pyclass cannot have two bases, a Python class can. Imported lazily, when
// the first such error is raised.
pyo3::import_exception!(koon, KoonInvalidArgument);

/// A [`KoonError`] with an explicit code, for failures detected here.
/// `INVALID_ARGUMENT` is raised as `KoonInvalidArgument`, which is also a
/// `ValueError`.
fn koon_err(code: &str, message: impl std::fmt::Display) -> PyErr {
    let message = format!("[{code}] {message}");
    if code == INVALID_ARGUMENT {
        PyErr::new::<KoonInvalidArgument, _>(message)
    } else {
        PyErr::new::<KoonError, _>(message)
    }
}

/// A `koon_core::Error` as a [`KoonError`], keeping its code. A hook's
/// error is the exception the hook raised (see [`call_hook`]).
fn to_koon_err(e: koon_core::Error) -> PyErr {
    match e {
        koon_core::Error::Hook(inner) => match inner.downcast::<PyErr>() {
            Ok(raised) => *raised,
            Err(other) => koon_err("HOOK_ERROR", other),
        },
        e => koon_err(e.code(), e),
    }
}

// ---------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------

/// Headers in order: a dict, any other mapping (read via `items()`), or an
/// iterable of `(name, value)` pairs, which may repeat a name.
#[derive(Default)]
struct Headers(Vec<(String, String)>);

impl<'py> FromPyObject<'_, 'py> for Headers {
    type Error = PyErr;

    fn extract(obj: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(dict) = obj.cast::<PyDict>() {
            return dict
                .iter()
                .map(|(name, value)| Ok((name.extract()?, value.extract()?)))
                .collect::<PyResult<_>>()
                .map(Headers);
        }
        let pairs = match obj.cast::<PyMapping>() {
            Ok(mapping) => mapping.items()?.into_any(),
            Err(_) => obj.to_owned(),
        };
        pairs
            .try_iter()?
            .map(|pair| pair?.extract())
            .collect::<PyResult<_>>()
            .map(Headers)
    }
}

/// A request body or WebSocket message: `str` or `bytes`.
#[derive(FromPyObject, IntoPyObject)]
enum Payload {
    Text(String),
    Bytes(Vec<u8>),
}

impl From<Payload> for Body {
    fn from(payload: Payload) -> Self {
        match payload {
            Payload::Text(text) => text.into(),
            Payload::Bytes(bytes) => bytes.into(),
        }
    }
}

/// One field of `post_multipart`: `name` plus either `value` (text) or
/// `file_data` (bytes) with an optional `filename` and `content_type`.
#[derive(FromPyObject)]
#[pyo3(from_item_all)]
struct FormField {
    name: String,
    #[pyo3(default)]
    value: Option<String>,
    #[pyo3(default)]
    file_data: Option<Vec<u8>>,
    #[pyo3(default)]
    filename: Option<String>,
    #[pyo3(default)]
    content_type: Option<String>,
}

/// Extract a list of dicts (cookies, form fields). A missing required key
/// is `INVALID_ARGUMENT` (a `ValueError`) rather than a bare `KeyError`.
fn extract_dicts<'py, T>(items: Vec<Bound<'py, PyAny>>, what: &str) -> PyResult<Vec<T>>
where
    T: for<'a> FromPyObject<'a, 'py, Error = PyErr>,
{
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.extract::<T>().map_err(|e: PyErr| {
                if e.is_instance_of::<PyKeyError>(item.py()) {
                    let key = e.value(item.py());
                    koon_err(
                        INVALID_ARGUMENT,
                        format!("{what} {index} is missing the required key {key}"),
                    )
                } else {
                    e
                }
            })
        })
        .collect()
}

fn build_multipart(fields: Vec<Bound<'_, PyAny>>) -> PyResult<Multipart> {
    extract_dicts::<FormField>(fields, "form field")?
        .into_iter()
        .try_fold(Multipart::new(), |form, field| {
            match (field.file_data, field.value) {
                (Some(data), _) => Ok(form.file(
                    field.name,
                    field.filename.unwrap_or_else(|| "file".into()),
                    field
                        .content_type
                        .unwrap_or_else(|| "application/octet-stream".into()),
                    data,
                )),
                (None, Some(value)) => Ok(form.text(field.name, value)),
                (None, None) => Err(koon_err(
                    INVALID_ARGUMENT,
                    format!(
                        "form field '{}' must have either 'value' (text) or 'file_data' (bytes)",
                        field.name
                    ),
                )),
            }
        })
}

/// A Playwright/CDP cookie dict as `set_cookies()` takes it; the core's
/// [`CookieParams`] interprets it. Keys it does not know are ignored.
#[derive(FromPyObject)]
#[pyo3(from_item_all, rename_all = "camelCase")]
struct CookieDict {
    name: String,
    value: String,
    #[pyo3(default)]
    domain: Option<String>,
    #[pyo3(default)]
    path: Option<String>,
    #[pyo3(default)]
    url: Option<String>,
    #[pyo3(default)]
    expires: Option<f64>,
    #[pyo3(default)]
    http_only: Option<bool>,
    #[pyo3(default)]
    secure: Option<bool>,
    #[pyo3(default)]
    same_site: Option<String>,
    #[pyo3(default)]
    host_only: Option<bool>,
    #[pyo3(default)]
    partition_key: Option<Py<PyAny>>,
    #[pyo3(default)]
    partition_key_opaque: Option<bool>,
}

impl From<CookieDict> for CookieParams {
    fn from(c: CookieDict) -> Self {
        Self {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            url: c.url,
            expires: c.expires,
            http_only: c.http_only.unwrap_or(false),
            secure: c.secure.unwrap_or(false),
            same_site: c.same_site,
            host_only: c.host_only,
            partitioned: c.partition_key.is_some() || c.partition_key_opaque == Some(true),
        }
    }
}

/// A cookie as `cookies()` returns it, in the shape `set_cookies()` takes.
#[derive(IntoPyObject)]
#[pyo3(rename_all = "camelCase")]
struct ExportedCookie {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    expires: Option<f64>,
    http_only: bool,
    secure: bool,
    same_site: Option<String>,
    host_only: Option<bool>,
}

impl From<CookieParams> for ExportedCookie {
    fn from(c: CookieParams) -> Self {
        Self {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            expires: c.expires,
            http_only: c.http_only,
            secure: c.secure,
            same_site: c.same_site,
            host_only: c.host_only,
        }
    }
}

/// A cookie `set_cookies()` did not import, as the dict it returns: its
/// position in the list given (0-based), its name and why.
#[derive(IntoPyObject)]
struct SkippedCookieDict {
    index: usize,
    name: String,
    reason: String,
}

impl From<SkippedCookie> for SkippedCookieDict {
    fn from(skipped: SkippedCookie) -> Self {
        Self {
            index: skipped.index,
            name: skipped.name,
            reason: skipped.reason,
        }
    }
}

/// The options for the connections to origins and proxies, which a client
/// and the upstream client of a `KoonProxy` share.
struct ConnectionOptions<'a> {
    proxy: Option<&'a str>,
    proxies: Option<Vec<String>>,
    ignore_tls_errors: bool,
    proxy_ca_certs: Option<Payload>,
    ignore_proxy_tls_errors: bool,
    session_resumption: bool,
    doh: Option<&'a str>,
    local_address: Option<IpAddr>,
    retries: u32,
    locale: Option<&'a str>,
    proxy_headers: Option<Headers>,
    ip_version: Option<IpVersion>,
    resolve: Option<Vec<String>>,
    max_response_body: u64,
    server_padding: Option<&'a str>,
}

impl ConnectionOptions<'_> {
    /// A client builder for `profile` with these options.
    fn client_builder(self, profile: BrowserProfile) -> PyResult<ClientBuilder> {
        let proxy_ca_certs = self.proxy_ca_certs.map(|pem| match pem {
            Payload::Text(text) => text.into_bytes(),
            Payload::Bytes(bytes) => bytes,
        });
        let doh = self
            .doh
            .map(|provider| provider.parse().map_err(to_koon_err))
            .transpose()?;
        let server_padding = self
            .server_padding
            .map(|padding| padding.parse().map_err(to_koon_err))
            .transpose()?;
        let connection = koon_core::ConnectionOptions {
            ignore_tls_errors: self.ignore_tls_errors,
            proxy: self.proxy.map(str::to_string),
            proxies: self.proxies.unwrap_or_default(),
            proxy_ca_certs,
            ignore_proxy_tls_errors: self.ignore_proxy_tls_errors,
            proxy_headers: self.proxy_headers.unwrap_or_default().0,
            session_resumption: self.session_resumption,
            doh,
            local_address: self.local_address,
            retries: self.retries,
            locale: self.locale.map(str::to_string),
            ip_version: self.ip_version,
            resolve: self.resolve.unwrap_or_default(),
            max_response_body: self.max_response_body,
            server_padding,
        };
        connection.apply(profile).map_err(to_koon_err)
    }
}

/// A timeout in seconds; `0` means no timeout.
fn timeout_duration(secs: f64) -> PyResult<Duration> {
    Duration::try_from_secs_f64(secs).map_err(|_| {
        koon_err(
            INVALID_ARGUMENT,
            format!("Invalid timeout: {secs}. Must be a finite number of seconds >= 0"),
        )
    })
}

/// The client timeout: `None` keeps the default of 30 seconds, as an unset
/// timeout does in the other bindings.
fn client_timeout(secs: Option<f64>) -> PyResult<Duration> {
    secs.map_or(Ok(Duration::from_secs(30)), timeout_duration)
}

/// A whole number in the range of `T`, e.g. `max_redirects`: a negative or
/// too large value is `KoonInvalidArgument` rather than an `OverflowError`.
fn whole_number<T: TryFrom<i64>>(name: &str, value: i64) -> PyResult<T> {
    T::try_from(value).map_err(|_| {
        koon_err(
            INVALID_ARGUMENT,
            format!("Invalid {name}: {value}. Must be a whole number >= 0 in range"),
        )
    })
}

fn ip_version(version: Option<i64>) -> PyResult<Option<IpVersion>> {
    version
        .map(|v| {
            let version = u8::try_from(v).unwrap_or(0);
            IpVersion::try_from(version).map_err(|_| {
                koon_err(
                    INVALID_ARGUMENT,
                    format!("Invalid IP version: {v}. Must be 4 or 6"),
                )
            })
        })
        .transpose()
}

/// `local_address`: an IP address as a string or an `ipaddress` object.
fn local_address(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<IpAddr>> {
    let Some(value) = value else {
        return Ok(None);
    };
    value.extract::<IpAddr>().map(Some).map_err(|e| {
        if e.is_instance_of::<PyValueError>(value.py()) {
            koon_err(
                INVALID_ARGUMENT,
                format!("Invalid local_address {value}: not an IP address"),
            )
        } else {
            e
        }
    })
}

fn load_profile(browser: &str, profile_json: Option<&str>) -> PyResult<BrowserProfile> {
    BrowserProfile::from_name_or_json(browser, profile_json).map_err(to_koon_err)
}

// ---------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------

type HookResult<T> = Result<T, koon_core::Error>;

/// Call a hook. An exception it raises fails the request: it travels through
/// the core as `Error::Hook`, and the call that sent the request raises that
/// very exception (see [`to_koon_err`]).
fn call_hook<'py>(
    py: Python<'py>,
    callback: &Py<PyAny>,
    args: impl PyCallArgs<'py>,
) -> HookResult<Bound<'py, PyAny>> {
    callback
        .bind(py)
        .call1(args)
        .map_err(|e| koon_core::Error::Hook(Box::new(e)))
}

fn request_hook(
    callback: Py<PyAny>,
) -> impl Fn(&str, &str) -> HookResult<()> + Send + Sync + 'static {
    move |method: &str, url: &str| {
        Python::attach(|py| call_hook(py, &callback, (method, url)).map(drop))
    }
}

fn response_hook(
    callback: Py<PyAny>,
) -> impl Fn(u16, &str, &[(String, String)]) -> HookResult<()> + Send + Sync + 'static {
    move |status: u16, url: &str, headers: &[(String, String)]| {
        Python::attach(|py| call_hook(py, &callback, (status, url, headers)).map(drop))
    }
}

/// Only an explicit `False` stops the redirect; `None` and any other value
/// follow it.
fn redirect_hook(
    callback: Py<PyAny>,
) -> impl Fn(u16, &str, &[(String, String)]) -> HookResult<bool> + Send + Sync + 'static {
    move |status: u16, url: &str, headers: &[(String, String)]| {
        Python::attach(|py| {
            call_hook(py, &callback, (status, url, headers))
                .map(|result| !matches!(result.extract::<bool>(), Ok(false)))
        })
    }
}

// ---------------------------------------------------------------------
// Running requests
// ---------------------------------------------------------------------

/// Block on `fut` with the GIL released. Every `SIGNAL_CHECK_INTERVAL` the
/// GIL is taken back briefly to run signal handlers, so Ctrl+C (or a Jupyter
/// kernel interrupt) raises `KeyboardInterrupt` and drops the future, which
/// aborts the request.
fn block_on<F>(py: Python<'_>, fut: F) -> PyResult<F::Output>
where
    F: Future + Send,
    F::Output: Send,
{
    let runtime = pyo3_async_runtimes::tokio::get_runtime();
    let mut fut = std::pin::pin!(fut);
    loop {
        // The timer must be created inside the runtime.
        let polled = py.detach(|| {
            runtime.block_on(async { tokio::time::timeout(SIGNAL_CHECK_INTERVAL, &mut fut).await })
        });
        match polled {
            Ok(output) => return Ok(output),
            Err(_elapsed) => py.check_signals()?,
        }
    }
}

/// Run a core operation: blocking for `KoonSync`, as an awaitable for
/// `Koon`. The result is converted to Python once, under the GIL
/// pyo3-async-runtimes takes to complete the awaitable.
fn run<F, T>(py: Python<'_>, blocking: bool, fut: F) -> PyResult<Py<PyAny>>
where
    F: Future<Output = Result<T, koon_core::Error>> + Send + 'static,
    T: for<'py> IntoPyObject<'py> + Send + 'static,
{
    if blocking {
        block_on(py, fut)?.map_err(to_koon_err)?.into_py_any(py)
    } else {
        pyo3_async_runtimes::tokio::future_into_py(
            py,
            async move { fut.await.map_err(to_koon_err) },
        )
        .map(Bound::unbind)
    }
}

// ---------------------------------------------------------------------
// _Client
// ---------------------------------------------------------------------

/// How `_Client._request` returns: an awaitable response (`Koon`), the
/// response itself (`KoonSync`), an awaitable `KoonStreamingResponse`, or a
/// `KoonSyncStreamingResponse` once its head has arrived.
#[pyclass(frozen, eq, eq_int, from_py_object, module = "koon", name = "_Mode")]
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Await,
    Block,
    Stream,
    BlockStream,
}

/// The native client behind `Koon` (async) and `KoonSync` (blocking).
#[pyclass(subclass, frozen, module = "koon", name = "_Client")]
struct NativeClient {
    client: Arc<koon_core::Client>,
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (browser="chrome", *, profile_json=None, proxy=None, proxies=None, timeout=30.0, ignore_tls_errors=false, proxy_ca_certs=None, ignore_proxy_tls_errors=false, headers=None, follow_redirects=true, max_redirects=10, cookie_jar=true, session_resumption=true, doh=None, local_address=None, on_request=None, on_response=None, on_redirect=None, retries=0, locale=None, proxy_headers=None, ip_version=None, resolve=None, max_response_body=None, server_padding=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        browser: &str,
        profile_json: Option<&str>,
        proxy: Option<&str>,
        proxies: Option<Vec<String>>,
        timeout: Option<f64>,
        ignore_tls_errors: bool,
        proxy_ca_certs: Option<Payload>,
        ignore_proxy_tls_errors: bool,
        headers: Option<Headers>,
        follow_redirects: bool,
        max_redirects: i64,
        cookie_jar: bool,
        session_resumption: bool,
        doh: Option<&str>,
        local_address: Option<&Bound<'_, PyAny>>,
        on_request: Option<Py<PyAny>>,
        on_response: Option<Py<PyAny>>,
        on_redirect: Option<Py<PyAny>>,
        retries: i64,
        locale: Option<&str>,
        proxy_headers: Option<Headers>,
        ip_version: Option<i64>,
        resolve: Option<Vec<String>>,
        max_response_body: Option<i64>,
        server_padding: Option<&str>,
    ) -> PyResult<Self> {
        let connection = ConnectionOptions {
            proxy,
            proxies,
            ignore_tls_errors,
            proxy_ca_certs,
            ignore_proxy_tls_errors,
            session_resumption,
            doh,
            local_address: self::local_address(local_address)?,
            retries: whole_number("retries", retries)?,
            locale,
            proxy_headers,
            ip_version: self::ip_version(ip_version)?,
            resolve,
            max_response_body: max_response_body
                .map(|n| whole_number("max_response_body", n))
                .transpose()?
                .unwrap_or_else(|| koon_core::ConnectionOptions::default().max_response_body),
            server_padding,
        };
        let mut builder = connection
            .client_builder(load_profile(browser, profile_json)?)?
            .timeout(client_timeout(timeout)?)
            .headers(headers.unwrap_or_default().0)
            .follow_redirects(follow_redirects)
            .max_redirects(whole_number("max_redirects", max_redirects)?)
            .cookie_jar(cookie_jar);
        if let Some(callback) = on_request {
            builder = builder.on_request(request_hook(callback));
        }
        if let Some(callback) = on_response {
            builder = builder.on_response(response_hook(callback));
        }
        if let Some(callback) = on_redirect {
            builder = builder.on_redirect(redirect_hook(callback));
        }
        Ok(Self {
            client: Arc::new(builder.build().map_err(to_koon_err)?),
        })
    }

    /// The User-Agent string from the browser profile.
    #[getter]
    fn user_agent(&self) -> Option<&str> {
        self.client.user_agent()
    }

    /// Export the current browser profile as a JSON string.
    fn export_profile(&self) -> PyResult<String> {
        self.client
            .profile()
            .to_json_pretty()
            .map_err(|e| to_koon_err(e.into()))
    }

    /// Save the current session (cookies + TLS sessions) as a JSON string.
    fn save_session(&self) -> PyResult<String> {
        self.client.save_session().map_err(to_koon_err)
    }

    /// Load a session (cookies + TLS sessions) from a JSON string.
    fn load_session(&self, json: &str) -> PyResult<()> {
        self.client.load_session(json).map_err(to_koon_err)
    }

    /// Save the current session to a file.
    fn save_session_to_file(&self, path: &str) -> PyResult<()> {
        self.client.save_session_to_file(path).map_err(to_koon_err)
    }

    /// Load a session from a file.
    fn load_session_from_file(&self, path: &str) -> PyResult<()> {
        self.client
            .load_session_from_file(path)
            .map_err(to_koon_err)
    }

    /// Get the total number of bytes sent across all requests.
    fn total_bytes_sent(&self) -> u64 {
        self.client.total_bytes_sent()
    }

    /// Get the total number of bytes received across all requests.
    fn total_bytes_received(&self) -> u64 {
        self.client.total_bytes_received()
    }

    /// Reset both cumulative byte counters to zero.
    fn reset_counters(&self) {
        self.client.reset_counters();
    }

    /// Clear all cookies from the cookie jar.
    fn clear_cookies(&self) {
        self.client.clear_cookies();
    }

    /// Insert or replace cookies from a list of Playwright/CDP-style dicts.
    /// Imports the valid ones; returns the skipped ones as dicts with
    /// `index`, `name` and `reason`.
    fn set_cookies(&self, cookies: Vec<Bound<'_, PyAny>>) -> PyResult<Vec<SkippedCookieDict>> {
        let cookies = extract_dicts::<CookieDict>(cookies, "cookie")?;
        let skipped = self
            .client
            .set_cookie_params(cookies.into_iter().map(CookieParams::from).collect())
            .map_err(to_koon_err)?;
        Ok(skipped.into_iter().map(SkippedCookieDict::from).collect())
    }

    /// Every cookie in the jar, as Playwright/CDP-style dicts that feed
    /// straight back into `set_cookies`.
    fn cookies(&self) -> Vec<ExportedCookie> {
        self.client
            .cookie_params()
            .into_iter()
            .map(ExportedCookie::from)
            .collect()
    }

    /// Close all pooled connections, without waiting. The client stays
    /// usable; new connections open as needed.
    fn close(&self) {
        self.client.close();
    }

    /// Shut the client down as a browser does (`Client::shutdown`): an
    /// awaitable for `Koon`, blocking for `KoonSync`.
    #[pyo3(name = "_shutdown")]
    fn shutdown(&self, py: Python<'_>, mode: Mode) -> PyResult<Py<PyAny>> {
        let client = self.client.clone();
        run(py, mode == Mode::Block, async move {
            client.shutdown().await;
            Ok::<_, koon_core::Error>(())
        })
    }

    /// Send a request; `mode` decides how it returns. `form` (a list of
    /// field dicts) sends a multipart form. The verbs forward their keyword
    /// arguments here, so everything that is not a request option is
    /// positional-only: passing it by keyword is a `TypeError`.
    #[pyo3(name = "_request", signature = (mode, method, url, body=None, form=None, /, *, headers=None, timeout=None, proxy=None, follow_redirects=None, max_redirects=None, on_request=None, on_response=None, on_redirect=None))]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        mode: Mode,
        method: &str,
        url: String,
        body: Option<Payload>,
        form: Option<Vec<Bound<'py, PyAny>>>,
        headers: Option<Headers>,
        timeout: Option<f64>,
        proxy: Option<String>,
        follow_redirects: Option<bool>,
        max_redirects: Option<i64>,
        on_request: Option<Py<PyAny>>,
        on_response: Option<Py<PyAny>>,
        on_redirect: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let method = koon_core::parse_method(method).map_err(to_koon_err)?;
        let body = body.map_or_else(Body::empty, Body::from);
        let form = form.map(build_multipart).transpose()?;
        let options = RequestOptions {
            headers: headers.unwrap_or_default().0,
            proxy,
            timeout: timeout.map(timeout_duration).transpose()?,
            follow_redirects,
            max_redirects: max_redirects
                .map(|n| whole_number("max_redirects", n))
                .transpose()?,
            on_request: on_request.map(|cb| Arc::new(request_hook(cb)) as OnRequestHook),
            on_response: on_response.map(|cb| Arc::new(response_hook(cb)) as OnResponseHook),
            on_redirect: on_redirect.map(|cb| Arc::new(redirect_hook(cb)) as OnRedirectHook),
        };
        let client = self.client.clone();
        if matches!(mode, Mode::Stream | Mode::BlockStream) {
            return run(py, mode == Mode::BlockStream, async move {
                let response = client.send_streaming(method, &url, body, options).await?;
                Ok(Streaming {
                    response,
                    blocking: mode == Mode::BlockStream,
                })
            });
        }
        run(py, mode == Mode::Block, async move {
            let resp = match form {
                Some(form) => client.post_multipart(&url, form, options).await?,
                None => client.send(method, &url, body, options).await?,
            };
            Ok(Response(resp))
        })
    }

    /// A multipart/form-data body of `post_multipart` fields, as the
    /// profile's browser builds it (its boundary and name escaping):
    /// `(body, content_type)`. The httpx and requests adapters send the
    /// uploads of `files=` this way.
    #[pyo3(name = "_encode_multipart")]
    fn encode_multipart(&self, fields: Vec<Bound<'_, PyAny>>) -> PyResult<(Vec<u8>, String)> {
        let profile = self.client.profile();
        let style = match profile
            .header_family
            .unwrap_or_else(|| HeaderFamily::detect(profile))
        {
            HeaderFamily::Firefox => BoundaryStyle::Gecko,
            _ => BoundaryStyle::WebKit,
        };
        Ok(build_multipart(fields)?.build_with(style))
    }

    /// Open a WebSocket connection (awaitable).
    #[pyo3(name = "_websocket", signature = (url, headers=None))]
    fn websocket(
        &self,
        py: Python<'_>,
        url: String,
        headers: Option<Headers>,
    ) -> PyResult<Py<PyAny>> {
        let client = self.client.clone();
        let headers = headers.unwrap_or_default().0;
        run(py, false, async move {
            let ws = client.websocket_with_headers(&url, headers).await?;
            Ok(KoonWebSocket { ws: Arc::new(ws) })
        })
    }
}

// ---------------------------------------------------------------------
// KoonResponse
// ---------------------------------------------------------------------

/// A core response on its way to Python: converted into a [`KoonResponse`]
/// under the GIL, where the body becomes a `bytes` object once.
struct Response(koon_core::HttpResponse);

impl<'py> IntoPyObject<'py> for Response {
    type Target = KoonResponse;
    type Output = Bound<'py, KoonResponse>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        let r = self.0;
        let blocked_by = r.blocked_by();
        Bound::new(
            py,
            KoonResponse {
                blocked_by,
                status: r.status,
                headers: HeaderList::new(r.headers),
                body: PyBytes::new(py, &r.body).unbind(),
                version: r.version,
                url: r.url,
                bytes_sent: r.bytes_sent,
                bytes_received: r.bytes_received,
                tls_resumed: r.tls_resumed,
                connection_reused: r.connection_reused,
                remote_address: r.remote_address,
                request_headers: HeaderList::new(r.request_headers),
                text: PyOnceLock::new(),
            },
        )
    }
}

/// Headers as Python sees them, a list of `(name, value)` tuples: built on
/// first access and then returned as the same object, like the Node
/// binding's arrays.
struct HeaderList {
    headers: Vec<(String, String)>,
    list: PyOnceLock<Py<PyList>>,
}

impl HeaderList {
    const fn new(headers: Vec<(String, String)>) -> Self {
        Self {
            headers,
            list: PyOnceLock::new(),
        }
    }

    fn get<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.list
            .get_or_try_init(py, || PyList::new(py, &self.headers).map(Bound::unbind))
            .map(|list| list.bind(py).clone())
    }

    /// The value of the first header named `name`, ignoring ASCII case.
    fn value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// HTTP response from a koon request.
#[pyclass(frozen, module = "koon")]
struct KoonResponse {
    /// HTTP status code (e.g. 200, 404).
    #[pyo3(get)]
    status: u16,
    headers: HeaderList,
    /// Response body as bytes.
    #[pyo3(get)]
    body: Py<PyBytes>,
    /// HTTP version used (e.g. "h2", "HTTP/1.1", "h3").
    #[pyo3(get)]
    version: String,
    /// The final URL after redirects.
    #[pyo3(get)]
    url: String,
    /// Approximate bytes sent for this request (headers + body).
    #[pyo3(get)]
    bytes_sent: u64,
    /// Approximate bytes received for this response (headers + body, pre-decompression).
    #[pyo3(get)]
    bytes_received: u64,
    /// Whether TLS session resumption was used for this connection.
    #[pyo3(get)]
    tls_resumed: bool,
    /// Whether an existing pooled connection was reused.
    #[pyo3(get)]
    connection_reused: bool,
    /// Remote IP address of the peer (the proxy when one is used).
    #[pyo3(get)]
    remote_address: Option<String>,
    /// The bot protection that answered instead of the page, or None for
    /// the page itself. A plain error status gives None.
    #[pyo3(get)]
    blocked_by: Option<&'static str>,
    request_headers: HeaderList,
    text: PyOnceLock<Py<PyString>>,
}

#[pymethods]
impl KoonResponse {
    /// Response headers as a list of (name, value) tuples, in wire order.
    /// The same list on every access.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.headers.get(py)
    }

    /// Headers of the final request as sent, in wire order and casing. The
    /// same list on every access.
    #[getter]
    fn request_headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.request_headers.get(py)
    }

    /// Alias for `status` (compatibility with requests/httpx conventions).
    #[getter]
    const fn status_code(&self) -> u16 {
        self.status
    }

    /// Whether the response status is 2xx (success).
    #[getter]
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Content-Type header value, or None if absent.
    #[getter]
    fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Response body decoded as text, by the charset of the Content-Type
    /// header (UTF-8 without one). Decoded once.
    #[getter]
    fn text<'py>(&self, py: Python<'py>) -> &Bound<'py, PyString> {
        self.text
            .get_or_init(py, || {
                let body = self.body.bind(py).as_bytes();
                let text = koon_core::decode_body_text(body, self.header("content-type"));
                PyString::new(py, &text).unbind()
            })
            .bind(py)
    }

    /// Parse the response body as JSON (with `json.loads`).
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        static LOADS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
        LOADS.import(py, "json", "loads")?.call1((self.text(py),))
    }

    /// Look up a response header by name (case-insensitive).
    /// Returns the first matching value, or None.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.value(name)
    }

    fn __repr__(&self) -> String {
        format!("<KoonResponse status={} url='{}'>", self.status, self.url)
    }
}

// ---------------------------------------------------------------------
// KoonStreamingResponse, KoonSyncStreamingResponse
// ---------------------------------------------------------------------

type SharedStream = Arc<tokio::sync::Mutex<Option<koon_core::StreamingResponse>>>;

/// What both streaming responses share: the response head and the body.
/// `KoonStreamingResponse` reads the body with coroutines,
/// `KoonSyncStreamingResponse` blocking.
#[pyclass(subclass, frozen, module = "koon", name = "_StreamingResponse")]
struct StreamingBase {
    /// HTTP status code (e.g. 200, 404).
    #[pyo3(get)]
    status: u16,
    headers: HeaderList,
    /// HTTP version used (e.g. "h2", "HTTP/1.1", "h3").
    #[pyo3(get)]
    version: String,
    /// The final URL after redirects.
    #[pyo3(get)]
    url: String,
    /// Approximate bytes sent for this request.
    #[pyo3(get)]
    bytes_sent: u64,
    /// Remote IP address of the peer (the proxy when one is used).
    #[pyo3(get)]
    remote_address: Option<String>,
    /// Whether TLS session resumption was used for this connection.
    #[pyo3(get)]
    tls_resumed: bool,
    /// Whether an existing pooled connection was reused.
    #[pyo3(get)]
    connection_reused: bool,
    request_headers: HeaderList,
    /// Bytes received so far, updated with every chunk.
    received: Arc<AtomicU64>,
    /// `None` once `collect()` consumed the body or `close()` dropped it.
    stream: SharedStream,
    /// Set by `close()`: a read still pending then drops the body at once.
    closed: tokio::sync::watch::Sender<bool>,
}

/// Reading the body after `collect()` or `close()`: the core's `BODY_ERROR`,
/// as in the Node binding.
fn stream_consumed() -> PyErr {
    to_koon_err(koon_core::Error::Body(
        "the response body was already read by collect() or closed".into(),
        None,
    ))
}

/// A core streaming response on its way to Python, as the class the mode
/// asks for.
struct Streaming {
    response: koon_core::StreamingResponse,
    blocking: bool,
}

impl<'py> IntoPyObject<'py> for Streaming {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> PyResult<Self::Output> {
        let base = PyClassInitializer::from(StreamingBase::new(self.response));
        if self.blocking {
            Bound::new(py, base.add_subclass(KoonSyncStreamingResponse)).map(Bound::into_any)
        } else {
            Bound::new(py, base.add_subclass(KoonStreamingResponse)).map(Bound::into_any)
        }
    }
}

impl StreamingBase {
    fn new(mut resp: koon_core::StreamingResponse) -> Self {
        Self {
            status: resp.status,
            // Cloned: `decode_content()` reads the core response's headers.
            headers: HeaderList::new(resp.headers.clone()),
            version: std::mem::take(&mut resp.version),
            url: std::mem::take(&mut resp.url),
            bytes_sent: resp.bytes_sent(),
            remote_address: resp.remote_address.take(),
            tls_resumed: resp.tls_resumed,
            connection_reused: resp.connection_reused,
            request_headers: HeaderList::new(std::mem::take(&mut resp.request_headers)),
            received: Arc::new(AtomicU64::new(resp.bytes_received())),
            stream: Arc::new(tokio::sync::Mutex::new(Some(resp))),
            closed: tokio::sync::watch::Sender::new(false),
        }
    }

    /// Read the next chunk (`None` at the end of the body). `close()` ends
    /// a pending read with `BODY_ERROR` and drops the body.
    fn read_chunk(&self) -> impl Future<Output = PyResult<Option<Vec<u8>>>> + Send + 'static {
        let (stream, received) = (self.stream.clone(), self.received.clone());
        let mut closed = self.closed.subscribe();
        async move {
            let mut guard = stream.lock().await;
            let read = {
                let resp = guard.as_mut().ok_or_else(stream_consumed)?;
                tokio::select! {
                    chunk = resp.next_chunk() => Some(chunk),
                    _ = closed.wait_for(|closed| *closed) => None,
                }
            };
            let Some(chunk) = read else {
                guard.take();
                return Err(stream_consumed());
            };
            let chunk = chunk.transpose().map_err(to_koon_err)?;
            if let Some(resp) = guard.as_ref() {
                received.store(resp.bytes_received(), Ordering::Relaxed);
            }
            Ok(chunk)
        }
    }

    /// Read the rest of the body; consumes the stream.
    fn collect_body(&self) -> impl Future<Output = PyResult<Vec<u8>>> + Send + 'static {
        let (stream, received) = (self.stream.clone(), self.received.clone());
        let mut closed = self.closed.subscribe();
        async move {
            let mut resp = stream.lock().await.take().ok_or_else(stream_consumed)?;
            let body = tokio::select! {
                body = resp.collect_body() => body,
                _ = closed.wait_for(|closed| *closed) => return Err(stream_consumed()),
            };
            received.store(resp.bytes_received(), Ordering::Relaxed);
            body.map_err(to_koon_err)
        }
    }

    /// Drop the rest of the body (see `close()`).
    fn close_stream(&self) {
        self.closed.send_replace(true);
        if let Ok(mut guard) = self.stream.try_lock() {
            guard.take();
        }
    }
}

#[pymethods]
impl StreamingBase {
    /// Alias for `status` (compatibility with requests/httpx conventions).
    #[getter]
    const fn status_code(&self) -> u16 {
        self.status
    }

    /// Response headers as a list of (name, value) tuples, in wire order.
    /// The same list on every access.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.headers.get(py)
    }

    /// Headers of the final request as sent, in wire order and casing. The
    /// same list on every access.
    #[getter]
    fn request_headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.request_headers.get(py)
    }

    /// Approximate bytes received so far (headers + body chunks read).
    #[getter]
    fn bytes_received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// Decode the body's Content-Encoding from now on, before the first
    /// read (the httpx and requests adapters). Returns whether there is
    /// anything to decode; the headers stay as received.
    #[pyo3(name = "_decode_content")]
    fn decode_content(&self) -> PyResult<bool> {
        let mut guard = self.stream.try_lock().map_err(|_| {
            to_koon_err(koon_core::Error::Body(
                "the response body is being read".into(),
                None,
            ))
        })?;
        let resp = guard.as_mut().ok_or_else(stream_consumed)?;
        Ok(resp.decode_content())
    }

    /// Drop the rest of the body without reading it: the stream is closed
    /// (HTTP/1.1) or reset (HTTP/2, HTTP/3). A read still pending and every
    /// later one raise `BODY_ERROR`. Closing again does nothing.
    fn close(&self) {
        self.close_stream();
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let this = slf.get();
        Ok(format!(
            "<{} status={} url='{}'>",
            slf.get_type().name()?,
            this.status,
            this.url
        ))
    }
}

/// A streaming HTTP response whose body is read with coroutines.
#[pyclass(extends = StreamingBase, frozen, module = "koon")]
struct KoonStreamingResponse;

#[pymethods]
impl KoonStreamingResponse {
    /// Get the next body chunk. Returns None when the body is complete.
    fn next_chunk<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let read = slf.as_super().get().read_chunk();
        pyo3_async_runtimes::tokio::future_into_py(slf.py(), read)
    }

    /// Collect the remaining body into bytes. Consumes the stream.
    fn collect<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let body = slf.as_super().get().collect_body();
        pyo3_async_runtimes::tokio::future_into_py(slf.py(), body)
    }

    /// Support async iteration: `async for chunk in resp:`
    const fn __aiter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Async iterator next: the next chunk, or `StopAsyncIteration`.
    fn __anext__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let chunk = slf.as_super().get().read_chunk();
        pyo3_async_runtimes::tokio::future_into_py(slf.py(), async move {
            chunk
                .await?
                .ok_or_else(|| PyStopAsyncIteration::new_err("end of stream"))
        })
    }

    /// `close()` as a coroutine, as `contextlib.aclosing()` calls it.
    fn aclose<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        slf.as_super().get().close_stream();
        pyo3_async_runtimes::tokio::future_into_py(slf.py(), async { Ok(()) })
    }

    /// Support `async with`: returns the response.
    fn __aenter__(slf: Py<Self>, py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    /// Support `async with`: closes the response (`close()`) on exit.
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        slf: &Bound<'py, Self>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        slf.as_super().get().close_stream();
        pyo3_async_runtimes::tokio::future_into_py(slf.py(), async { Ok(false) })
    }
}

/// A streaming HTTP response whose body is read blocking, from
/// `KoonSync.request_streaming()`.
#[pyclass(extends = StreamingBase, frozen, module = "koon")]
struct KoonSyncStreamingResponse;

#[pymethods]
impl KoonSyncStreamingResponse {
    /// Get the next body chunk, blocking with the GIL released. Returns None
    /// when the body is complete.
    fn next_chunk(slf: &Bound<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let read = slf.as_super().get().read_chunk();
        block_on(slf.py(), read)?
    }

    /// Collect the remaining body into bytes, blocking. Consumes the stream.
    fn collect(slf: &Bound<'_, Self>) -> PyResult<Vec<u8>> {
        let body = slf.as_super().get().collect_body();
        block_on(slf.py(), body)?
    }

    /// Support iteration: `for chunk in resp:`
    const fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Iterator next: the next chunk, or `StopIteration`.
    fn __next__(slf: &Bound<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        Self::next_chunk(slf)
    }

    /// Support `with`: returns the response.
    const fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Support `with`: closes the response (`close()`) on exit.
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        slf: &Bound<'_, Self>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        slf.as_super().get().close_stream();
        false
    }
}

// ---------------------------------------------------------------------
// KoonWebSocket
// ---------------------------------------------------------------------

/// A received WebSocket message: `{"type": "text" | "binary", "data": ...}`.
#[derive(IntoPyObject)]
struct WsFrame {
    #[pyo3(item("type"))]
    kind: &'static str,
    data: Payload,
}

/// A WebSocket connection with browser-fingerprinted TLS.
///
/// Send, receive and close can run concurrently: the core WebSocket keeps
/// independent locks for its read and write halves, so a pending `receive()`
/// never blocks a `send()`.
#[pyclass(frozen, module = "koon")]
struct KoonWebSocket {
    ws: Arc<koon_core::WebSocket>,
}

#[pymethods]
impl KoonWebSocket {
    /// Send a text (str) or binary (bytes) message.
    fn send<'py>(&self, py: Python<'py>, data: Payload) -> PyResult<Bound<'py, PyAny>> {
        let ws = self.ws.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match data {
                Payload::Text(text) => ws.send_text(&text).await,
                Payload::Bytes(bytes) => ws.send_binary(&bytes).await,
            }
            .map_err(to_koon_err)
        })
    }

    /// Receive the next message: a dict with 'type' and 'data', or None
    /// once the connection is closed.
    fn receive<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let ws = self.ws.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let message = ws.receive().await.map_err(to_koon_err)?;
            Ok(message.map(|message| match message {
                WsMessage::Text(text) => WsFrame {
                    kind: "text",
                    data: Payload::Text(text),
                },
                WsMessage::Binary(bytes) => WsFrame {
                    kind: "binary",
                    data: Payload::Bytes(bytes),
                },
            }))
        })
    }

    /// Close the WebSocket connection.
    #[pyo3(signature = (code=None, reason=None))]
    fn close<'py>(
        &self,
        py: Python<'py>,
        code: Option<i64>,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let code = code.map(|c| whole_number::<u16>("code", c)).transpose()?;
        let ws = self.ws.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            ws.close(code, reason).await.map_err(to_koon_err)
        })
    }

    /// Support `async with`: returns self.
    fn __aenter__(slf: Py<Self>, py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    /// Support `async with`: closes the connection on exit.
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let ws = self.ws.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let _ = ws.close(Some(1000), Some("closing".to_string())).await;
            Ok(false)
        })
    }
}

// ---------------------------------------------------------------------
// KoonProxy
// ---------------------------------------------------------------------

/// A local MITM proxy server with browser fingerprinting.
#[pyclass(frozen, module = "koon")]
struct KoonProxy {
    server: Arc<tokio::sync::Mutex<Option<ProxyServer>>>,
    /// The port the proxy server is listening on.
    #[pyo3(get)]
    port: u16,
    /// The proxy URL (e.g. "<http://127.0.0.1:8080>").
    #[pyo3(get)]
    url: String,
    /// Path to the generated CA certificate file.
    #[pyo3(get)]
    ca_cert_path: String,
    ca_cert_pem: Vec<u8>,
}

#[pymethods]
impl KoonProxy {
    /// Start a new MITM proxy server.
    #[staticmethod]
    #[pyo3(signature = (*, browser="chrome", profile_json=None, listen_addr=None, header_mode=None, ca_dir=None, timeout=30.0, allow_non_loopback=false, auth=None, max_connections=None, proxy=None, proxies=None, ignore_tls_errors=false, proxy_ca_certs=None, ignore_proxy_tls_errors=false, session_resumption=true, doh=None, local_address=None, retries=0, locale=None, proxy_headers=None, ip_version=None, resolve=None, max_response_body=None, server_padding=None))]
    #[allow(clippy::too_many_arguments)]
    fn start<'py>(
        py: Python<'py>,
        browser: &str,
        profile_json: Option<&str>,
        listen_addr: Option<String>,
        header_mode: Option<&str>,
        ca_dir: Option<String>,
        timeout: Option<f64>,
        allow_non_loopback: bool,
        auth: Option<(String, String)>,
        max_connections: Option<i64>,
        proxy: Option<&str>,
        proxies: Option<Vec<String>>,
        ignore_tls_errors: bool,
        proxy_ca_certs: Option<Payload>,
        ignore_proxy_tls_errors: bool,
        session_resumption: bool,
        doh: Option<&str>,
        local_address: Option<&Bound<'py, PyAny>>,
        retries: i64,
        locale: Option<&str>,
        proxy_headers: Option<Headers>,
        ip_version: Option<i64>,
        resolve: Option<Vec<String>>,
        max_response_body: Option<i64>,
        server_padding: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // The upstream client takes the connection options as a client
        // does; the proxy turns redirects and the cookie jar off.
        let connection = ConnectionOptions {
            proxy,
            proxies,
            ignore_tls_errors,
            proxy_ca_certs,
            ignore_proxy_tls_errors,
            session_resumption,
            doh,
            local_address: self::local_address(local_address)?,
            retries: whole_number("retries", retries)?,
            locale,
            proxy_headers,
            ip_version: self::ip_version(ip_version)?,
            resolve,
            max_response_body: max_response_body
                .map(|n| whole_number("max_response_body", n))
                .transpose()?
                .unwrap_or_else(|| koon_core::ConnectionOptions::default().max_response_body),
            server_padding,
        };
        let client = connection
            .client_builder(load_profile(browser, profile_json)?)?
            .timeout(client_timeout(timeout)?);
        let mut config = ProxyServerConfig {
            listen_addr: listen_addr.unwrap_or_else(|| "127.0.0.1:0".to_string()),
            header_mode: header_mode
                .map(str::parse::<HeaderMode>)
                .transpose()
                .map_err(to_koon_err)?
                .unwrap_or_default(),
            ca_dir,
            client,
            allow_non_loopback,
            auth: auth
                .map(|(username, password)| koon_core::ProxyServerAuth { username, password }),
            ..ProxyServerConfig::default()
        };
        if let Some(max) = max_connections {
            config.max_connections = whole_number("max_connections", max)?;
        }
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = ProxyServer::start(config).await.map_err(to_koon_err)?;
            Ok(Self {
                port: server.port(),
                url: server.url(),
                ca_cert_path: server.ca_cert_path().to_string_lossy().into_owned(),
                ca_cert_pem: server.ca_cert_pem().map_err(to_koon_err)?,
                server: Arc::new(tokio::sync::Mutex::new(Some(server))),
            })
        })
    }

    /// CA certificate as PEM bytes (still available after `shutdown()`).
    fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// Shut down the proxy server.
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let server = self.server.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = server.lock().await.take();
            if let Some(server) = server {
                server.shutdown();
            }
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        format!("<KoonProxy url='{}'>", self.url)
    }
}

/// Every built-in browser profile name, e.g. "chrome154-windows",
/// "safari266-ios" or "okhttp5".
#[pyfunction]
fn browsers() -> Vec<String> {
    BrowserProfile::names()
        .map(|profile| profile.name)
        .collect()
}

/// The fingerprint self-test of `koon_core::verify` for one profile, as the
/// report's JSON (`koon.verify` parses it). Blocks with the GIL released.
#[pyfunction]
#[pyo3(signature = (browser, proxy=None))]
fn _verify(py: Python<'_>, browser: &str, proxy: Option<&str>) -> PyResult<String> {
    block_on(py, koon_core::verify::verify(browser, proxy))?
        .map(|report| report.to_json())
        .map_err(to_koon_err)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(browsers, m)?)?;
    m.add_function(wrap_pyfunction!(_verify, m)?)?;
    m.add_class::<NativeClient>()?;
    m.add_class::<Mode>()?;
    m.add_class::<KoonResponse>()?;
    m.add_class::<KoonStreamingResponse>()?;
    m.add_class::<KoonSyncStreamingResponse>()?;
    m.add_class::<KoonWebSocket>()?;
    m.add_class::<KoonProxy>()?;
    m.add_class::<KoonError>()?;
    Ok(())
}
