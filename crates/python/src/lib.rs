use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use koon_core::dns::DohResolver;
use koon_core::multipart::Multipart;
use koon_core::profile::{BrowserProfile, Chrome, Edge, Firefox, Opera, Safari};
use koon_core::{Client, WsMessage};

/// Convert any Display error to a Python RuntimeError.
fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())
}

/// Resolve a browser name string to a BrowserProfile.
fn resolve_profile(browser: &str) -> PyResult<BrowserProfile> {
    match browser.to_lowercase().as_str() {
        // Chrome — latest
        "chrome" => Ok(Chrome::latest()),
        // Chrome 131–145
        "chrome131" | "chrome131windows" => Ok(Chrome::v131_windows()),
        "chrome131macos" => Ok(Chrome::v131_macos()),
        "chrome131linux" => Ok(Chrome::v131_linux()),
        "chrome132" | "chrome132windows" => Ok(Chrome::v132_windows()),
        "chrome132macos" => Ok(Chrome::v132_macos()),
        "chrome132linux" => Ok(Chrome::v132_linux()),
        "chrome133" | "chrome133windows" => Ok(Chrome::v133_windows()),
        "chrome133macos" => Ok(Chrome::v133_macos()),
        "chrome133linux" => Ok(Chrome::v133_linux()),
        "chrome134" | "chrome134windows" => Ok(Chrome::v134_windows()),
        "chrome134macos" => Ok(Chrome::v134_macos()),
        "chrome134linux" => Ok(Chrome::v134_linux()),
        "chrome135" | "chrome135windows" => Ok(Chrome::v135_windows()),
        "chrome135macos" => Ok(Chrome::v135_macos()),
        "chrome135linux" => Ok(Chrome::v135_linux()),
        "chrome136" | "chrome136windows" => Ok(Chrome::v136_windows()),
        "chrome136macos" => Ok(Chrome::v136_macos()),
        "chrome136linux" => Ok(Chrome::v136_linux()),
        "chrome137" | "chrome137windows" => Ok(Chrome::v137_windows()),
        "chrome137macos" => Ok(Chrome::v137_macos()),
        "chrome137linux" => Ok(Chrome::v137_linux()),
        "chrome138" | "chrome138windows" => Ok(Chrome::v138_windows()),
        "chrome138macos" => Ok(Chrome::v138_macos()),
        "chrome138linux" => Ok(Chrome::v138_linux()),
        "chrome139" | "chrome139windows" => Ok(Chrome::v139_windows()),
        "chrome139macos" => Ok(Chrome::v139_macos()),
        "chrome139linux" => Ok(Chrome::v139_linux()),
        "chrome140" | "chrome140windows" => Ok(Chrome::v140_windows()),
        "chrome140macos" => Ok(Chrome::v140_macos()),
        "chrome140linux" => Ok(Chrome::v140_linux()),
        "chrome141" | "chrome141windows" => Ok(Chrome::v141_windows()),
        "chrome141macos" => Ok(Chrome::v141_macos()),
        "chrome141linux" => Ok(Chrome::v141_linux()),
        "chrome142" | "chrome142windows" => Ok(Chrome::v142_windows()),
        "chrome142macos" => Ok(Chrome::v142_macos()),
        "chrome142linux" => Ok(Chrome::v142_linux()),
        "chrome143" | "chrome143windows" => Ok(Chrome::v143_windows()),
        "chrome143macos" => Ok(Chrome::v143_macos()),
        "chrome143linux" => Ok(Chrome::v143_linux()),
        "chrome144" | "chrome144windows" => Ok(Chrome::v144_windows()),
        "chrome144macos" => Ok(Chrome::v144_macos()),
        "chrome144linux" => Ok(Chrome::v144_linux()),
        "chrome145" | "chrome145windows" => Ok(Chrome::v145_windows()),
        "chrome145macos" => Ok(Chrome::v145_macos()),
        "chrome145linux" => Ok(Chrome::v145_linux()),
        // Firefox — latest
        "firefox" => Ok(Firefox::latest()),
        // Firefox 135–147
        "firefox135" | "firefox135windows" => Ok(Firefox::v135_windows()),
        "firefox135macos" => Ok(Firefox::v135_macos()),
        "firefox135linux" => Ok(Firefox::v135_linux()),
        "firefox136" | "firefox136windows" => Ok(Firefox::v136_windows()),
        "firefox136macos" => Ok(Firefox::v136_macos()),
        "firefox136linux" => Ok(Firefox::v136_linux()),
        "firefox137" | "firefox137windows" => Ok(Firefox::v137_windows()),
        "firefox137macos" => Ok(Firefox::v137_macos()),
        "firefox137linux" => Ok(Firefox::v137_linux()),
        "firefox138" | "firefox138windows" => Ok(Firefox::v138_windows()),
        "firefox138macos" => Ok(Firefox::v138_macos()),
        "firefox138linux" => Ok(Firefox::v138_linux()),
        "firefox139" | "firefox139windows" => Ok(Firefox::v139_windows()),
        "firefox139macos" => Ok(Firefox::v139_macos()),
        "firefox139linux" => Ok(Firefox::v139_linux()),
        "firefox140" | "firefox140windows" => Ok(Firefox::v140_windows()),
        "firefox140macos" => Ok(Firefox::v140_macos()),
        "firefox140linux" => Ok(Firefox::v140_linux()),
        "firefox141" | "firefox141windows" => Ok(Firefox::v141_windows()),
        "firefox141macos" => Ok(Firefox::v141_macos()),
        "firefox141linux" => Ok(Firefox::v141_linux()),
        "firefox142" | "firefox142windows" => Ok(Firefox::v142_windows()),
        "firefox142macos" => Ok(Firefox::v142_macos()),
        "firefox142linux" => Ok(Firefox::v142_linux()),
        "firefox143" | "firefox143windows" => Ok(Firefox::v143_windows()),
        "firefox143macos" => Ok(Firefox::v143_macos()),
        "firefox143linux" => Ok(Firefox::v143_linux()),
        "firefox144" | "firefox144windows" => Ok(Firefox::v144_windows()),
        "firefox144macos" => Ok(Firefox::v144_macos()),
        "firefox144linux" => Ok(Firefox::v144_linux()),
        "firefox145" | "firefox145windows" => Ok(Firefox::v145_windows()),
        "firefox145macos" => Ok(Firefox::v145_macos()),
        "firefox145linux" => Ok(Firefox::v145_linux()),
        "firefox146" | "firefox146windows" => Ok(Firefox::v146_windows()),
        "firefox146macos" => Ok(Firefox::v146_macos()),
        "firefox146linux" => Ok(Firefox::v146_linux()),
        "firefox147" | "firefox147windows" => Ok(Firefox::v147_windows()),
        "firefox147macos" => Ok(Firefox::v147_macos()),
        "firefox147linux" => Ok(Firefox::v147_linux()),
        // Safari
        "safari" => Ok(Safari::latest()),
        "safari156" | "safari156macos" => Ok(Safari::v15_6_macos()),
        "safari160" | "safari160macos" => Ok(Safari::v16_0_macos()),
        "safari170" | "safari170macos" => Ok(Safari::v17_0_macos()),
        "safari180" | "safari180macos" => Ok(Safari::v18_0_macos()),
        "safari183" | "safari183macos" => Ok(Safari::v18_3_macos()),
        // Opera
        "opera" => Ok(Opera::latest()),
        "opera124" | "opera124windows" => Ok(Opera::v124_windows()),
        "opera124macos" => Ok(Opera::v124_macos()),
        "opera124linux" => Ok(Opera::v124_linux()),
        "opera125" | "opera125windows" => Ok(Opera::v125_windows()),
        "opera125macos" => Ok(Opera::v125_macos()),
        "opera125linux" => Ok(Opera::v125_linux()),
        "opera126" | "opera126windows" => Ok(Opera::v126_windows()),
        "opera126macos" => Ok(Opera::v126_macos()),
        "opera126linux" => Ok(Opera::v126_linux()),
        "opera127" | "opera127windows" => Ok(Opera::v127_windows()),
        "opera127macos" => Ok(Opera::v127_macos()),
        "opera127linux" => Ok(Opera::v127_linux()),
        // Edge — latest
        "edge" => Ok(Edge::latest()),
        // Edge 131–145
        "edge131" | "edge131windows" => Ok(Edge::v131_windows()),
        "edge131macos" => Ok(Edge::v131_macos()),
        "edge132" | "edge132windows" => Ok(Edge::v132_windows()),
        "edge132macos" => Ok(Edge::v132_macos()),
        "edge133" | "edge133windows" => Ok(Edge::v133_windows()),
        "edge133macos" => Ok(Edge::v133_macos()),
        "edge134" | "edge134windows" => Ok(Edge::v134_windows()),
        "edge134macos" => Ok(Edge::v134_macos()),
        "edge135" | "edge135windows" => Ok(Edge::v135_windows()),
        "edge135macos" => Ok(Edge::v135_macos()),
        "edge136" | "edge136windows" => Ok(Edge::v136_windows()),
        "edge136macos" => Ok(Edge::v136_macos()),
        "edge137" | "edge137windows" => Ok(Edge::v137_windows()),
        "edge137macos" => Ok(Edge::v137_macos()),
        "edge138" | "edge138windows" => Ok(Edge::v138_windows()),
        "edge138macos" => Ok(Edge::v138_macos()),
        "edge139" | "edge139windows" => Ok(Edge::v139_windows()),
        "edge139macos" => Ok(Edge::v139_macos()),
        "edge140" | "edge140windows" => Ok(Edge::v140_windows()),
        "edge140macos" => Ok(Edge::v140_macos()),
        "edge141" | "edge141windows" => Ok(Edge::v141_windows()),
        "edge141macos" => Ok(Edge::v141_macos()),
        "edge142" | "edge142windows" => Ok(Edge::v142_windows()),
        "edge142macos" => Ok(Edge::v142_macos()),
        "edge143" | "edge143windows" => Ok(Edge::v143_windows()),
        "edge143macos" => Ok(Edge::v143_macos()),
        "edge144" | "edge144windows" => Ok(Edge::v144_windows()),
        "edge144macos" => Ok(Edge::v144_macos()),
        "edge145" | "edge145windows" => Ok(Edge::v145_windows()),
        "edge145macos" => Ok(Edge::v145_macos()),
        other => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unknown browser: '{other}'. Supported: chrome/chrome131-145, \
             firefox/firefox135-147, safari/safari156-183, opera/opera124-127, edge/edge131-145"
        ))),
    }
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
    #[new]
    #[pyo3(signature = (browser="chrome", *, profile_json=None, proxy=None, timeout=30000, ignore_tls_errors=false, headers=None, follow_redirects=true, max_redirects=10, cookie_jar=true, randomize=false, session_resumption=true, doh=None))]
    fn new(
        browser: &str,
        profile_json: Option<&str>,
        proxy: Option<&str>,
        timeout: u32,
        ignore_tls_errors: bool,
        headers: Option<HashMap<String, String>>,
        follow_redirects: bool,
        max_redirects: u32,
        cookie_jar: bool,
        randomize: bool,
        session_resumption: bool,
        doh: Option<&str>,
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

        if let Some(proxy_url) = proxy {
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

        let client = builder.build().map_err(to_py_err)?;

        Ok(Koon {
            client: Arc::new(client),
        })
    }

    /// Export the current browser profile as a JSON string.
    fn export_profile(&self) -> PyResult<String> {
        self.client.profile().to_json_pretty().map_err(to_py_err)
    }

    /// Perform an HTTP GET request.
    fn get<'py>(&self, py: Python<'py>, url: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.get(&url).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP POST request.
    #[pyo3(signature = (url, body=None))]
    fn post<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.post(&url, body).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP PUT request.
    #[pyo3(signature = (url, body=None))]
    fn put<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.put(&url, body).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP DELETE request.
    fn delete<'py>(&self, py: Python<'py>, url: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.delete(&url).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP PATCH request.
    #[pyo3(signature = (url, body=None))]
    fn patch<'py>(
        &self,
        py: Python<'py>,
        url: String,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.patch(&url, body).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP HEAD request.
    fn head<'py>(&self, py: Python<'py>, url: String) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resp = client.head(&url).await.map_err(to_py_err)?;
            Ok(KoonResponse::from_core(resp))
        })
    }

    /// Perform an HTTP request with a custom method.
    #[pyo3(signature = (method, url, body=None))]
    fn request<'py>(
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
            let resp = client.request(method, &url, body).await.map_err(to_py_err)?;
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

            Ok(KoonStreamingResponse {
                status: resp.status,
                headers_vec: resp.headers.clone(),
                version: resp.version.clone(),
                url: resp.url.clone(),
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
    #[pyo3(get)]
    status: u16,
    headers_vec: Vec<(String, String)>,
    body_bytes: Vec<u8>,
    #[pyo3(get)]
    version: String,
    #[pyo3(get)]
    url: String,
}

impl KoonResponse {
    fn from_core(resp: koon_core::client::HttpResponse) -> Self {
        KoonResponse {
            status: resp.status,
            headers_vec: resp.headers,
            body_bytes: resp.body,
            version: resp.version,
            url: resp.url,
        }
    }
}

#[pymethods]
impl KoonResponse {
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

    fn __repr__(&self) -> String {
        format!("<KoonResponse status={} url='{}'>", self.status, self.url)
    }
}

/// A streaming HTTP response that delivers the body in chunks.
#[pyclass]
struct KoonStreamingResponse {
    #[pyo3(get)]
    status: u16,
    headers_vec: Vec<(String, String)>,
    #[pyo3(get)]
    version: String,
    #[pyo3(get)]
    url: String,
    inner: Arc<tokio::sync::Mutex<Option<koon_core::StreamingResponse>>>,
}

#[pymethods]
impl KoonStreamingResponse {
    /// Response headers as a list of (name, value) tuples.
    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers_vec.clone()
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
                            dict.set_item(
                                "data",
                                String::from_utf8_lossy(&data).as_ref(),
                            )?;
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

/// Python module registration.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Koon>()?;
    m.add_class::<KoonResponse>()?;
    m.add_class::<KoonStreamingResponse>()?;
    m.add_class::<KoonWebSocket>()?;
    Ok(())
}
