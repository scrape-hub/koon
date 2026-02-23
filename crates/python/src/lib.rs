use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use koon_core::dns::DohResolver;
use koon_core::multipart::Multipart;
use koon_core::profile::BrowserProfile;
use koon_core::{Client, HeaderMode, ProxyServer, ProxyServerConfig, WsMessage};

/// Convert any Display error to a Python RuntimeError.
fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())
}

/// Run a future with an optional per-request timeout.
async fn run_with_timeout<F>(
    future: F,
    timeout_ms: Option<u32>,
) -> PyResult<koon_core::HttpResponse>
where
    F: Future<Output = Result<koon_core::HttpResponse, koon_core::Error>>,
{
    if let Some(ms) = timeout_ms {
        tokio::time::timeout(Duration::from_millis(ms as u64), future)
            .await
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyTimeoutError, _>("Request timed out"))?
            .map_err(to_py_err)
    } else {
        future.await.map_err(to_py_err)
    }
}

/// Resolve a browser name string to a BrowserProfile.
fn resolve_profile(browser: &str) -> PyResult<BrowserProfile> {
    BrowserProfile::resolve(browser).map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)
}

/// Helper enum for WebSocket send data (resolved before entering async block).
enum WsData {
    Text(String),
    Binary(Vec<u8>),
}

/// The main Koon HTTP client with browser fingerprint impersonation.
#[pyclass]
struct Koon {
    client: Arc<Client>,
}

#[pymethods]
impl Koon {
    /// Create a new Koon HTTP client with browser fingerprint impersonation.
    ///
    /// Args:
    ///     browser: Browser to impersonate (e.g. "chrome", "firefox147", "safari18.3").
    ///     profile_json: Custom browser profile as JSON string (overrides `browser`).
    ///     proxy: Proxy URL (http://, https://, socks5://).
    ///     timeout: Request timeout in milliseconds.
    ///     ignore_tls_errors: Skip TLS certificate verification.
    ///     headers: Additional headers as {name: value} dict.
    ///     follow_redirects: Automatically follow HTTP redirects.
    ///     max_redirects: Maximum number of redirects to follow.
    ///     cookie_jar: Enable automatic cookie storage.
    ///     randomize: Randomize UA build number, accept-language q-values, and H2 window sizes.
    ///     session_resumption: Enable TLS session resumption.
    ///     doh: DNS-over-HTTPS provider ("cloudflare" or "google").
    ///     local_address: Bind outgoing connections to a specific local IP address.
    ///     proxies: List of proxy URLs for round-robin rotation (takes priority over `proxy`).
    #[new]
    #[pyo3(signature = (browser="chrome", *, profile_json=None, proxy=None, proxies=None, timeout=30000, ignore_tls_errors=false, headers=None, follow_redirects=true, max_redirects=10, cookie_jar=true, randomize=false, session_resumption=true, doh=None, local_address=None, on_request=None, on_response=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        browser: &str,
        profile_json: Option<&str>,
        proxy: Option<&str>,
        proxies: Option<Vec<String>>,
        timeout: u32,
        ignore_tls_errors: bool,
        headers: Option<HashMap<String, String>>,
        follow_redirects: bool,
        max_redirects: u32,
        cookie_jar: bool,
        randomize: bool,
        session_resumption: bool,
        doh: Option<&str>,
        local_address: Option<&str>,
        on_request: Option<Py<PyAny>>,
        on_response: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        let mut profile = if let Some(json) = profile_json {
            BrowserProfile::from_json(json).map_err(to_py_err)?
        } else {
            resolve_profile(browser)?
        };

        if ignore_tls_errors {
            profile.tls.danger_accept_invalid_certs = true;
        }

        if randomize {
            profile.randomize();
        }

        let custom_headers: Vec<(String, String)> =
            headers.unwrap_or_default().into_iter().collect();

        let mut builder = Client::builder(profile)
            .timeout(Duration::from_millis(timeout as u64))
            .headers(custom_headers)
            .follow_redirects(follow_redirects)
            .max_redirects(max_redirects)
            .cookie_jar(cookie_jar)
            .session_resumption(session_resumption);

        if let Some(proxy_urls) = proxies {
            let refs: Vec<&str> = proxy_urls.iter().map(|s| s.as_str()).collect();
            builder = builder.proxies(&refs).map_err(to_py_err)?;
        } else if let Some(proxy_url) = proxy {
            builder = builder.proxy(proxy_url).map_err(to_py_err)?;
        }

        if let Some(doh_provider) = doh {
            let resolver = match doh_provider.to_lowercase().as_str() {
                "cloudflare" => DohResolver::with_cloudflare(),
                "google" => DohResolver::with_google(),
                other => {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                        "Unknown DoH provider: '{other}'. Supported: 'cloudflare', 'google'"
                    )));
                }
            }
            .map_err(to_py_err)?;
            builder = builder.doh(resolver);
        }

        if let Some(addr_str) = local_address {
            let addr: std::net::IpAddr = addr_str.parse().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid local_address '{addr_str}': {e}"
                ))
            })?;
            builder = builder.local_address(addr);
        }

        if let Some(callback) = on_request {
            builder = builder.on_request(move |method: &str, url: &str| {
                Python::attach(|py| {
                    let _ = callback.call1(py, (method, url));
                });
            });
        }

        if let Some(callback) = on_response {
            builder = builder.on_response(
                move |status: u16, url: &str, headers: &[(String, String)]| {
                    Python::attach(|py| {
                        let headers_list: Vec<(&str, &str)> = headers
                            .iter()
                            .map(|(n, v)| (n.as_str(), v.as_str()))
                            .collect();
                        let _ = callback.call1(py, (status, url, headers_list));
                    });
                },
            );
        }

        let client = builder.build().map_err(to_py_err)?;

        Ok(Koon {
            client: Arc::new(client),
        })
    }

    /// Export the current browser profile as a JSON string.
    fn export_profile(&self) -> PyResult<String> {
        self.client.profile().to_json_pretty().map_err(to_py_err)
    }

    /// Save the current session (cookies + TLS sessions) as a JSON string.
    fn save_session(&self) -> PyResult<String> {
        self.client.save_session().map_err(to_py_err)
    }

    /// Load a session (cookies + TLS sessions) from a JSON string.
    fn load_session(&self, json: &str) -> PyResult<()> {
        self.client.load_session(json).map_err(to_py_err)
    }

    /// Save the current session to a file.
    fn save_session_to_file(&self, path: &str) -> PyResult<()> {
        self.client.save_session_to_file(path).map_err(to_py_err)
    }

    /// Load a session from a file.
    fn load_session_from_file(&self, path: &str) -> PyResult<()> {
        self.client.load_session_from_file(path).map_err(to_py_err)
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

    /// Perform an HTTP GET request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, *, headers=None, timeout=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("GET".parse().unwrap(), &url, None, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP POST request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     body: Optional request body as bytes.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, body=None, *, headers=None, timeout=None))]
    fn post<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("POST".parse().unwrap(), &url, body, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP PUT request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     body: Optional request body as bytes.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, body=None, *, headers=None, timeout=None))]
    fn put<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("PUT".parse().unwrap(), &url, body, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP DELETE request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, *, headers=None, timeout=None))]
    fn delete<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("DELETE".parse().unwrap(), &url, None, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP PATCH request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     body: Optional request body as bytes.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, body=None, *, headers=None, timeout=None))]
    fn patch<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("PATCH".parse().unwrap(), &url, body, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP HEAD request.
    ///
    /// Args:
    ///     url: The URL to request.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (url, *, headers=None, timeout=None))]
    fn head<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let future = client.request_with_headers("HEAD".parse().unwrap(), &url, None, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP request with a custom method.
    ///
    /// Args:
    ///     method: HTTP method string (e.g. "GET", "POST").
    ///     url: The URL to request.
    ///     body: Optional request body as bytes.
    ///     headers: Optional dict of per-request headers.
    ///     timeout: Optional per-request timeout in milliseconds.
    #[pyo3(signature = (method, url, body=None, *, headers=None, timeout=None))]
    fn request<'py>(
        &self,
        py: Python<'py>,
        method: String,
        url: String,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let extra: Vec<(String, String)> = headers.unwrap_or_default().into_iter().collect();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let method: http::Method = method.parse().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid HTTP method: {method}"
                ))
            })?;
            let future = client.request_with_headers(method, &url, body, extra);
            let resp = run_with_timeout(future, timeout).await?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP POST request with multipart/form-data body.
    ///
    /// Each field is a dict with 'name' (required), plus either 'value' (text)
    /// or 'file_data' (bytes) + optional 'filename' and 'content_type'.
    fn post_multipart<'py>(
        &self,
        py: Python<'py>,
        url: String,
        fields: Vec<HashMap<String, Py<PyAny>>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Build Multipart from field dicts while we still have the GIL
        let mut parts = Vec::new();
        for field in fields {
            let name: String = field
                .get("name")
                .ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "Each field must have a 'name' key",
                    )
                })?
                .extract(py)?;

            if let Some(file_data_obj) = field.get("file_data") {
                let data: Vec<u8> = file_data_obj.extract(py)?;
                let filename: String = field
                    .get("filename")
                    .map(|v| v.extract(py))
                    .transpose()?
                    .unwrap_or_else(|| "file".to_string());
                let content_type: String = field
                    .get("content_type")
                    .map(|v| v.extract(py))
                    .transpose()?
                    .unwrap_or_else(|| "application/octet-stream".to_string());
                parts.push((name, filename, content_type, data));
            } else if let Some(value_obj) = field.get("value") {
                let value: String = value_obj.extract(py)?;
                parts.push((name, value, String::new(), Vec::new()));
            }
        }

        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut mp = Multipart::new();
            for (name, second, third, data) in parts {
                if data.is_empty() && third.is_empty() {
                    // Text field: second = value
                    mp = mp.text(name, second);
                } else {
                    // File field: second = filename, third = content_type
                    mp = mp.file(name, second, third, data);
                }
            }
            let resp = client.post_multipart(&url, mp).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform a streaming HTTP request.
    /// Returns a KoonStreamingResponse. Does NOT follow redirects.
    #[pyo3(signature = (method, url, body=None))]
    fn request_streaming<'py>(
        &self,
        py: Python<'py>,
        method: String,
        url: String,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let method: http::Method = method.parse().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid HTTP method: {method}"
                ))
            })?;
            let resp = client
                .request_streaming(method, &url, body)
                .await
                .map_err(to_py_err)?;

            let bytes_sent = resp.bytes_sent();
            Ok(KoonStreamingResponse {
                status: resp.status,
                headers_vec: resp.headers.clone(),
                version: resp.version.clone(),
                url: resp.url.clone(),
                bytes_sent,
                inner: Arc::new(tokio::sync::Mutex::new(Some(resp))),
            })
        })
    }

    /// Open a WebSocket connection to a wss:// URL.
    #[pyo3(signature = (url, headers=None))]
    fn websocket<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let extra_headers: Vec<(String, String)> =
                headers.unwrap_or_default().into_iter().collect();
            let ws = client
                .websocket_with_headers(&url, extra_headers)
                .await
                .map_err(to_py_err)?;
            Ok(KoonWebSocket {
                inner: Arc::new(tokio::sync::Mutex::new(Some(ws))),
            })
        })
    }
}

/// HTTP response from a koon request.
#[pyclass(frozen)]
struct KoonResponse {
    /// HTTP status code (e.g. 200, 404).
    #[pyo3(get)]
    status: u16,
    headers_vec: Vec<(String, String)>,
    body_bytes: Vec<u8>,
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
}

impl KoonResponse {
    fn from_core(resp: koon_core::client::HttpResponse) -> Self {
        KoonResponse {
            status: resp.status,
            headers_vec: resp.headers,
            body_bytes: resp.body,
            version: resp.version,
            url: resp.url,
            bytes_sent: resp.bytes_sent,
            bytes_received: resp.bytes_received,
        }
    }
}

#[pymethods]
impl KoonResponse {
    /// Whether the response status is 2xx (success).
    #[getter]
    fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Response headers as a list of (name, value) tuples.
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers_vec.clone()
    }

    /// Response body as bytes.
    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body_bytes)
    }

    /// Response body decoded as UTF-8 text.
    #[getter]
    fn text(&self) -> PyResult<String> {
        String::from_utf8(self.body_bytes.clone()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Response body is not valid UTF-8: {e}"
            ))
        })
    }

    /// Parse response body as JSON (delegates to Python's json.loads).
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let json_mod = py.import("json")?;
        let text = self.text()?;
        json_mod.call_method1("loads", (text,))
    }

    /// Look up a response header by name (case-insensitive).
    /// Returns the first matching header value, or None if not found.
    #[pyo3(signature = (name,))]
    fn header(&self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        self.headers_vec
            .iter()
            .find(|(n, _)| n.to_lowercase() == name_lower)
            .map(|(_, v)| v.clone())
    }

    fn __repr__(&self) -> String {
        format!("<KoonResponse status={} url='{}'>", self.status, self.url)
    }
}

/// A streaming HTTP response that delivers the body in chunks.
#[pyclass]
struct KoonStreamingResponse {
    /// HTTP status code (e.g. 200, 404).
    #[pyo3(get)]
    status: u16,
    headers_vec: Vec<(String, String)>,
    /// HTTP version used (e.g. "h2", "HTTP/1.1", "h3").
    #[pyo3(get)]
    version: String,
    /// The request URL.
    #[pyo3(get)]
    url: String,
    /// Approximate bytes sent for this request.
    #[pyo3(get)]
    bytes_sent: u64,
    inner: Arc<tokio::sync::Mutex<Option<koon_core::StreamingResponse>>>,
}

#[pymethods]
impl KoonStreamingResponse {
    /// Response headers as a list of (name, value) tuples.
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers_vec.clone()
    }

    /// Approximate bytes received so far (headers + body chunks consumed).
    #[getter]
    fn bytes_received(&self) -> u64 {
        let guard = self.inner.blocking_lock();
        guard.as_ref().map(|r| r.bytes_received()).unwrap_or(0)
    }

    /// Get the next body chunk. Returns None when the body is complete.
    fn next_chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let resp = guard.as_mut().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Stream already consumed")
            })?;
            match resp.next_chunk().await {
                Some(Ok(data)) => Python::attach(|py| -> PyResult<Py<PyAny>> {
                    Ok(PyBytes::new(py, &data).into_any().unbind())
                }),
                Some(Err(e)) => Err(to_py_err(e)),
                None => Ok(Python::attach(|py| py.None())),
            }
        })
    }

    /// Collect the entire remaining body into bytes.
    fn collect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let resp = guard.take().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Stream already consumed")
            })?;
            let body = resp.collect_body().await.map_err(to_py_err)?;
            Python::attach(|py| -> PyResult<Py<PyAny>> {
                Ok(PyBytes::new(py, &body).into_any().unbind())
            })
        })
    }

    /// Support async iteration: `async for chunk in resp:`
    fn __aiter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Async iterator next — returns bytes or raises StopAsyncIteration.
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let resp = guard.as_mut().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Stream already consumed")
            })?;
            match resp.next_chunk().await {
                Some(Ok(data)) => Python::attach(|py| -> PyResult<Py<PyAny>> {
                    Ok(PyBytes::new(py, &data).into_any().unbind())
                }),
                Some(Err(e)) => Err(to_py_err(e)),
                None => Err(PyErr::new::<pyo3::exceptions::PyStopAsyncIteration, _>(
                    "end of stream",
                )),
            }
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "<KoonStreamingResponse status={} url='{}'>",
            self.status, self.url
        )
    }
}

/// A WebSocket connection with browser-fingerprinted TLS.
#[pyclass]
struct KoonWebSocket {
    inner: Arc<tokio::sync::Mutex<Option<koon_core::WebSocket>>>,
}

#[pymethods]
impl KoonWebSocket {
    /// Send a text (str) or binary (bytes) message.
    fn send<'py>(&self, py: Python<'py>, data: Py<PyAny>) -> PyResult<Bound<'py, PyAny>> {
        // Resolve type while we have the GIL
        let msg = if let Ok(s) = data.extract::<String>(py) {
            WsData::Text(s)
        } else if let Ok(b) = data.extract::<Vec<u8>>(py) {
            WsData::Binary(b)
        } else {
            return Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected str or bytes",
            ));
        };

        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("WebSocket is closed")
            })?;
            match msg {
                WsData::Text(t) => ws.send_text(&t).await.map_err(to_py_err)?,
                WsData::Binary(b) => ws.send_binary(&b).await.map_err(to_py_err)?,
            }
            Ok(())
        })
    }

    /// Receive the next message. Returns dict with 'type' and 'data', or None if closed.
    fn receive<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let ws = guard.as_mut().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("WebSocket is closed")
            })?;

            match ws.receive().await {
                Ok(Some(msg)) => {
                    let (is_text, data) = match msg {
                        WsMessage::Text(t) => (true, t.into_bytes()),
                        WsMessage::Binary(b) => (false, b),
                    };
                    // Acquire GIL to create Python dict
                    Python::attach(|py| -> PyResult<Py<PyAny>> {
                        let dict = PyDict::new(py);
                        if is_text {
                            dict.set_item("type", "text")?;
                            dict.set_item("data", String::from_utf8_lossy(&data).as_ref())?;
                        } else {
                            dict.set_item("type", "binary")?;
                            dict.set_item("data", PyBytes::new(py, &data))?;
                        }
                        Ok(dict.into_any().unbind())
                    })
                }
                Ok(None) => Ok(Python::attach(|py| py.None())),
                Err(e) => Err(to_py_err(e)),
            }
        })
    }

    /// Close the WebSocket connection.
    #[pyo3(signature = (code=None, reason=None))]
    fn close<'py>(
        &self,
        py: Python<'py>,
        code: Option<u16>,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(mut ws) = guard.take() {
                ws.close(code, reason).await.map_err(to_py_err)?;
            }
            Ok(())
        })
    }

    /// Support `async with` - returns self.
    fn __aenter__(slf: Py<Self>, py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    /// Support `async with` - closes the connection on exit.
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: Option<&Bound<'py, PyAny>>,
        _exc_val: Option<&Bound<'py, PyAny>>,
        _exc_tb: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(mut ws) = guard.take() {
                let _ = ws.close(Some(1000), Some("closing".to_string())).await;
            }
            Ok(false)
        })
    }
}

/// A local MITM proxy server with browser fingerprinting.
#[pyclass]
struct KoonProxy {
    inner: Arc<tokio::sync::Mutex<Option<ProxyServer>>>,
    /// The port the proxy server is listening on.
    #[pyo3(get)]
    port: u16,
    /// The proxy URL (e.g. "http://127.0.0.1:8080").
    #[pyo3(get)]
    url: String,
    /// Path to the generated CA certificate file.
    #[pyo3(get)]
    ca_cert_path: String,
}

#[pymethods]
impl KoonProxy {
    /// Start a new MITM proxy server.
    #[staticmethod]
    #[pyo3(signature = (*, browser="chrome", profile_json=None, listen_addr=None, header_mode=None, ca_dir=None, timeout=30000, randomize=false))]
    #[allow(clippy::too_many_arguments)]
    fn start<'py>(
        py: Python<'py>,
        browser: &str,
        profile_json: Option<&str>,
        listen_addr: Option<String>,
        header_mode: Option<&str>,
        ca_dir: Option<String>,
        timeout: u32,
        randomize: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut profile = if let Some(json) = profile_json {
            BrowserProfile::from_json(json).map_err(to_py_err)?
        } else {
            resolve_profile(browser)?
        };

        if randomize {
            profile.randomize();
        }

        let hm = match header_mode {
            Some("passthrough") => HeaderMode::Passthrough,
            _ => HeaderMode::Impersonate,
        };

        let config = ProxyServerConfig {
            listen_addr: listen_addr.unwrap_or_else(|| "127.0.0.1:0".to_string()),
            profile,
            header_mode: hm,
            ca_dir,
            timeout_secs: (timeout / 1000) as u64,
        };

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = ProxyServer::start(config).await.map_err(to_py_err)?;
            let port = server.port();
            let url = server.url();
            let ca_cert_path = server.ca_cert_path().to_string_lossy().to_string();

            Ok(KoonProxy {
                inner: Arc::new(tokio::sync::Mutex::new(Some(server))),
                port,
                url,
                ca_cert_path,
            })
        })
    }

    /// CA certificate as PEM bytes.
    fn ca_cert_pem<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let guard = self.inner.blocking_lock();
        let server = guard.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Proxy is shut down")
        })?;
        let pem = server.ca_cert_pem().map_err(to_py_err)?;
        Ok(PyBytes::new(py, &pem))
    }

    /// Shut down the proxy server.
    fn shutdown<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(server) = guard.take() {
                server.shutdown();
            }
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        format!("<KoonProxy url='{}'>", self.url)
    }
}

/// Python module registration.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Koon>()?;
    m.add_class::<KoonResponse>()?;
    m.add_class::<KoonStreamingResponse>()?;
    m.add_class::<KoonWebSocket>()?;
    m.add_class::<KoonProxy>()?;
    Ok(())
}
