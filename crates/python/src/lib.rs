//! Python binding for koon, a thin wrapper around `koon_core`.
//!
//! `Koon` (async) and `KoonSync` (blocking) are Python subclasses of the
//! native `_Client` (see `python/koon/__init__.py`). Every request goes
//! through `_Client._request`, which returns an awaitable or blocks.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pyo3::IntoPyObjectExt;
use pyo3::call::PyCallArgs;
use pyo3::exceptions::{PyKeyError, PyStopAsyncIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{
    PyBool, PyByteArray, PyBytes, PyDict, PyFloat, PyInt, PyList, PyMapping, PyMemoryView, PyString,
};

use koon_core::options::{Hook, Kind, OptionError, Options, Scope, Target, Value};
use koon_core::{
    Body, BrowserProfile, CookieParams, Multipart, PartitionKey, ProxyServer, SkippedCookie,
    WsMessage,
};

/// How often a blocking request checks for Ctrl+C.
const SIGNAL_CHECK_INTERVAL: Duration = Duration::from_millis(100);

const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";

pyo3::import_exception!(koon, KoonError);
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

/// A `koon_core::Error` as a [`KoonError`], keeping its code and, for a
/// request's transport failure, its `phase`. A hook's error is the
/// exception the hook raised (see [`call_hook`]).
fn to_koon_err(e: koon_core::Error) -> PyErr {
    let phase = e.phase();
    match e.into_kind() {
        koon_core::Error::Hook(inner) => match inner.downcast::<PyErr>() {
            Ok(raised) => *raised,
            Err(other) => koon_err("HOOK_ERROR", other),
        },
        e => {
            let err = koon_err(e.code(), e);
            if let Some(phase) = phase {
                let _ = Python::attach(|py| err.value(py).setattr("phase", phase.as_str()));
            }
            err
        }
    }
}

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
                (Some(_), Some(_)) => Err(koon_err(
                    INVALID_ARGUMENT,
                    format!(
                        "form field '{}' must have either 'value' (text) or 'file_data' (bytes), not both",
                        field.name
                    ),
                )),
                (Some(data), None) => Ok(form.file(
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
    partition_key: Option<PartitionKeyArg>,
    #[pyo3(item("_crHasCrossSiteAncestor"), default)]
    cr_has_cross_site_ancestor: Option<bool>,
    #[pyo3(default)]
    partition_key_opaque: Option<bool>,
}

/// A partition key as Playwright (the top-level site) or CDP (an object)
/// gives it.
#[derive(FromPyObject)]
enum PartitionKeyArg {
    Site(String),
    Cdp(CdpPartitionKey),
}

#[derive(FromPyObject)]
#[pyo3(from_item_all, rename_all = "camelCase")]
struct CdpPartitionKey {
    top_level_site: String,
    #[pyo3(default)]
    has_cross_site_ancestor: Option<bool>,
}

impl From<CookieDict> for CookieParams {
    fn from(c: CookieDict) -> Self {
        let partition_key = if c.partition_key_opaque == Some(true) {
            Some(PartitionKey::Opaque)
        } else {
            c.partition_key.map(|key| {
                let (top_level_site, cross_site_ancestor) = match key {
                    PartitionKeyArg::Site(site) => (site, c.cr_has_cross_site_ancestor),
                    PartitionKeyArg::Cdp(key) => (key.top_level_site, key.has_cross_site_ancestor),
                };
                PartitionKey::Site {
                    top_level_site,
                    cross_site_ancestor: cross_site_ancestor.unwrap_or(false),
                }
            })
        };
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
            partition_key,
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
    partition_key: Option<String>,
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
            partition_key: c.partition_key.and_then(|key| match key {
                PartitionKey::Site { top_level_site, .. } => Some(top_level_site),
                PartitionKey::Opaque => None,
            }),
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

/// A whole number in the range of `T`, e.g. a WebSocket close code: a
/// negative or too large value is `KoonInvalidArgument` rather than an
/// `OverflowError`.
fn whole_number<T: TryFrom<i64>>(name: &str, value: i64) -> PyResult<T> {
    T::try_from(value).map_err(|_| {
        koon_err(
            INVALID_ARGUMENT,
            format!("Invalid {name}: {value}. Must be a whole number >= 0 in range"),
        )
    })
}

/// Keyword options as the core's [`Options`] for `scope`: every name is checked against the
/// option table, and `None` keeps the default.
fn read_options(scope: Scope, options: Option<&Bound<'_, PyDict>>) -> PyResult<Options> {
    let mut read = Options::new(scope, Target::Python);
    for (key, value) in options.into_iter().flatten() {
        let key: String = key.extract()?;
        set_option(&mut read, &key, &value)?;
    }
    Ok(read)
}

fn set_option(options: &mut Options, key: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
    let spec = options.spec(key).map_err(option_error)?;
    let value = py_value(value, spec.kind)?;
    options.set_option(spec, value).map_err(option_error)
}

/// An unknown option or a value of the wrong type is a `TypeError`, as for
/// a Python function's arguments; an invalid value keeps the core's code.
fn option_error(error: OptionError) -> PyErr {
    match error {
        OptionError::Unknown(message) | OptionError::Type(message) => PyTypeError::new_err(message),
        OptionError::Invalid(error) => to_koon_err(error),
    }
}

/// A Python value as the core's option [`Value`]; a value no option takes is
/// [`Value::Other`], which the core reports with the type it expected.
fn py_value(value: &Bound<'_, PyAny>, kind: Kind) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    match kind {
        Kind::Hook(hook) if value.is_callable() => {
            let callback = value.clone().unbind();
            return Ok(match hook {
                Hook::Request => Value::RequestHook(Arc::new(request_hook(callback))),
                Hook::Response => Value::ResponseHook(Arc::new(response_hook(callback))),
                Hook::Redirect => Value::RedirectHook(Arc::new(redirect_hook(callback))),
            });
        }
        Kind::Headers if !value.is_instance_of::<PyString>() => {
            return Ok(Value::Pairs(value.extract::<Headers>()?.0));
        }
        _ => {}
    }
    Ok(if let Ok(flag) = value.cast::<PyBool>() {
        Value::Bool(flag.is_true())
    } else if value.is_instance_of::<PyInt>() {
        value.extract::<i64>().map_or(Value::Other, Value::Int)
    } else if value.is_instance_of::<PyFloat>() {
        Value::Float(value.extract()?)
    } else if let Ok(text) = value.cast::<PyString>() {
        Value::Text(text.to_str()?.to_owned())
    } else if value.is_instance_of::<PyBytes>()
        || value.is_instance_of::<PyByteArray>()
        || value.is_instance_of::<PyMemoryView>()
    {
        let bytes = value.py().get_type::<PyBytes>().call1((value,))?;
        Value::Bytes(bytes.cast::<PyBytes>()?.as_bytes().to_vec())
    } else if value.get_type().module()?.to_str()? == "ipaddress" {
        Value::Text(value.str()?.to_str()?.to_owned())
    } else if let Ok(mapping) = value.cast::<PyMapping>() {
        mapping
            .items()?
            .extract::<Vec<(String, String)>>()
            .map_or(Value::Other, Value::Pairs)
    } else {
        value
            .extract::<Vec<String>>()
            .map_or(Value::Other, Value::Texts)
    })
}

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

/// Run `f` with the GIL. A hook runs on a runtime worker, and waiting there for the GIL would stall
/// the other tasks queued on that worker (the HTTP/2 connections of other requests), so the worker
/// hands them off first, as the Node and R bindings do. `KoonSync` runs on the multi-thread
/// runtime's `block_on`, where this is allowed too.
fn with_gil<T>(f: impl for<'py> FnOnce(Python<'py>) -> T) -> T {
    tokio::task::block_in_place(|| Python::attach(f))
}

fn request_hook(
    callback: Py<PyAny>,
) -> impl Fn(&str, &str) -> HookResult<()> + Send + Sync + 'static {
    move |method: &str, url: &str| with_gil(|py| call_hook(py, &callback, (method, url)).map(drop))
}

fn response_hook(
    callback: Py<PyAny>,
) -> impl Fn(u16, &str, &[(String, String)]) -> HookResult<()> + Send + Sync + 'static {
    move |status: u16, url: &str, headers: &[(String, String)]| {
        with_gil(|py| call_hook(py, &callback, (status, url, headers)).map(drop))
    }
}

/// Only an explicit `False` stops the redirect; `None` and any other value
/// follow it.
fn redirect_hook(
    callback: Py<PyAny>,
) -> impl Fn(u16, &str, &[(String, String)]) -> HookResult<bool> + Send + Sync + 'static {
    move |status: u16, url: &str, headers: &[(String, String)]| {
        with_gil(|py| {
            call_hook(py, &callback, (status, url, headers))
                .map(|result| !matches!(result.extract::<bool>(), Ok(false)))
        })
    }
}

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
    #[pyo3(signature = (browser=None, **options))]
    fn new(
        browser: Option<&Bound<'_, PyAny>>,
        options: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let mut read = read_options(Scope::Client, options)?;
        if let Some(browser) = browser {
            set_option(&mut read, "browser", browser)?;
        }
        let builder = read.client_builder().map_err(to_koon_err)?;
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
    /// `index`, `name` and `reason`. A cookie whose `expires` is in the past
    /// deletes the stored one with the same name, domain and path instead.
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
    /// field dicts) sends a multipart form; `redirect`, the `_redirect` of
    /// a streaming response, makes the request the next hop of that
    /// redirect (the httpx and requests adapters). The verbs forward their
    /// keyword arguments here, so everything that is not a request option
    /// is positional-only: passing it by keyword is a `TypeError`.
    #[pyo3(
        name = "_request",
        signature = (mode, method, url, body=None, form=None, redirect=None, /, **options)
    )]
    #[allow(clippy::too_many_arguments)]
    fn request<'py>(
        &self,
        py: Python<'py>,
        mode: Mode,
        method: &str,
        url: String,
        body: Option<Payload>,
        form: Option<Vec<Bound<'py, PyAny>>>,
        redirect: Option<PyRef<'py, Redirect>>,
        options: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        let method = koon_core::parse_method(method).map_err(to_koon_err)?;
        let body = body.map_or_else(Body::empty, Body::from);
        let form = form.map(build_multipart).transpose()?;
        let streaming = matches!(mode, Mode::Stream | Mode::BlockStream);
        let options = read_options(
            if streaming {
                Scope::Stream
            } else {
                Scope::Request
            },
            options,
        )?;
        let decode = options.decode();
        let mut options = options.request_options();
        options.redirect = redirect.map(|r| r.0.clone());
        let client = self.client.clone();
        if streaming {
            return run(py, mode == Mode::BlockStream, async move {
                let mut response = client.send_streaming(method, &url, body, options).await?;
                if decode {
                    response.decode_content();
                }
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
        Ok(build_multipart(fields)?.build_with(self.client.boundary_style()))
    }

    /// Open a WebSocket connection: an awaitable `KoonWebSocket` for
    /// `Koon`, a `KoonSyncWebSocket` for `KoonSync`.
    #[pyo3(name = "_websocket", signature = (mode, url, headers=None))]
    fn websocket(
        &self,
        py: Python<'_>,
        mode: Mode,
        url: String,
        headers: Option<Headers>,
    ) -> PyResult<Py<PyAny>> {
        let client = self.client.clone();
        let headers = headers.unwrap_or_default().0;
        let connect = async move { client.websocket_with_headers(&url, headers).await };
        if mode == Mode::Block {
            let ws = block_on(py, connect)?.map_err(to_koon_err)?;
            return KoonSyncWebSocket { ws: Arc::new(ws) }.into_py_any(py);
        }
        run(py, false, async move {
            Ok(KoonWebSocket {
                ws: Arc::new(connect.await?),
            })
        })
    }
}

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
    /// The redirect the response asks for, if the client did not follow it.
    redirect: Option<koon_core::Redirect>,
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
            headers: HeaderList::new(resp.headers.clone()),
            version: std::mem::take(&mut resp.version),
            url: std::mem::take(&mut resp.url),
            bytes_sent: resp.bytes_sent(),
            remote_address: resp.remote_address.take(),
            tls_resumed: resp.tls_resumed,
            connection_reused: resp.connection_reused,
            request_headers: HeaderList::new(std::mem::take(&mut resp.request_headers)),
            redirect: resp.redirect.take(),
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

    /// The redirect this response asks for when the client did not follow
    /// it, to send its next hop with (`_Client._request`), else `None`.
    #[getter(_redirect)]
    fn redirect(&self) -> Option<Redirect> {
        self.redirect.clone().map(Redirect)
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

/// A redirect a streaming response asks for (`_redirect`), which the
/// httpx and requests adapters pass back with the request that follows it.
#[pyclass(frozen, module = "koon", name = "_Redirect")]
struct Redirect(koon_core::Redirect);

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

/// A WebSocket connection of `KoonSync`: the methods of `KoonWebSocket`,
/// blocking with the GIL released; Ctrl+C interrupts a pending `receive()`.
#[pyclass(frozen, module = "koon")]
struct KoonSyncWebSocket {
    ws: Arc<koon_core::WebSocket>,
}

#[pymethods]
impl KoonSyncWebSocket {
    /// Send a text (str) or binary (bytes) message.
    fn send(&self, py: Python<'_>, data: Payload) -> PyResult<()> {
        let ws = self.ws.clone();
        block_on(py, async move {
            match data {
                Payload::Text(text) => ws.send_text(&text).await,
                Payload::Bytes(bytes) => ws.send_binary(&bytes).await,
            }
        })?
        .map_err(to_koon_err)
    }

    /// Receive the next message: a dict with 'type' and 'data', or None
    /// once the connection is closed.
    fn receive(&self, py: Python<'_>) -> PyResult<Option<WsFrame>> {
        let ws = self.ws.clone();
        let message = block_on(py, async move { ws.receive().await })?.map_err(to_koon_err)?;
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
    }

    /// Close the WebSocket connection.
    #[pyo3(signature = (code=None, reason=None))]
    fn close(&self, py: Python<'_>, code: Option<i64>, reason: Option<String>) -> PyResult<()> {
        let code = code.map(|c| whole_number::<u16>("code", c)).transpose()?;
        let ws = self.ws.clone();
        block_on(py, async move { ws.close(code, reason).await })?.map_err(to_koon_err)
    }

    /// Support `with`: returns self.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Support `with`: closes the connection on exit.
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<bool> {
        let ws = self.ws.clone();
        let _ = block_on(py, async move {
            ws.close(Some(1000), Some("closing".to_string())).await
        })?;
        Ok(false)
    }
}

type RunningProxy = Arc<tokio::sync::Mutex<Option<ProxyServer>>>;

/// Every proxy started and not shut down yet: a server stops once dropped,
/// and a `KoonProxy` Python collects must not take its server with it.
static RUNNING_PROXIES: std::sync::Mutex<Vec<RunningProxy>> = std::sync::Mutex::new(Vec::new());

/// A local MITM proxy server with browser fingerprinting.
#[pyclass(frozen, module = "koon")]
struct KoonProxy {
    server: RunningProxy,
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
    #[pyo3(signature = (**options))]
    fn start<'py>(
        py: Python<'py>,
        options: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let config = read_options(Scope::Proxy, options)?
            .proxy_config()
            .map_err(to_koon_err)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = ProxyServer::start(config).await.map_err(to_koon_err)?;
            let proxy = Self {
                port: server.port(),
                url: server.url(),
                ca_cert_path: server.ca_cert_path().to_string_lossy().into_owned(),
                ca_cert_pem: server.ca_cert_pem().map_err(to_koon_err)?,
                server: Arc::new(tokio::sync::Mutex::new(Some(server))),
            };
            RUNNING_PROXIES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(proxy.server.clone());
            Ok(proxy)
        })
    }

    /// CA certificate as PEM bytes (still available after `shutdown()`).
    fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// Shut down the proxy server.
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let server = self.server.clone();
        RUNNING_PROXIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|running| !Arc::ptr_eq(running, &server));
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
#[pyo3(signature = (browser, **options))]
fn _verify(
    py: Python<'_>,
    browser: &Bound<'_, PyAny>,
    options: Option<&Bound<'_, PyDict>>,
) -> PyResult<String> {
    let mut read = read_options(Scope::Verify, options)?;
    set_option(&mut read, "browser", browser)?;
    block_on(py, koon_core::verify::verify_options(read))?
        .map(|report| report.to_json())
        .map_err(to_koon_err)
}

/// `koon_core::blocked_by` for `koon.blocked_by`, which takes the status,
/// headers and URL from the response it is given.
#[pyfunction]
fn _blocked_by(
    status: u16,
    headers: Vec<(String, String)>,
    body: &[u8],
    url: &str,
) -> Option<&'static str> {
    koon_core::blocked_by(status, &headers, body, url)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(browsers, m)?)?;
    m.add_function(wrap_pyfunction!(_verify, m)?)?;
    m.add_function(wrap_pyfunction!(_blocked_by, m)?)?;
    m.add_class::<NativeClient>()?;
    m.add_class::<Mode>()?;
    m.add_class::<KoonResponse>()?;
    m.add_class::<KoonStreamingResponse>()?;
    m.add_class::<KoonSyncStreamingResponse>()?;
    m.add_class::<KoonWebSocket>()?;
    m.add_class::<KoonSyncWebSocket>()?;
    m.add_class::<KoonProxy>()?;
    Ok(())
}
