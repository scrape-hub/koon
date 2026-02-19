use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use koon_core::profile::{BrowserProfile, Chrome, Edge, Firefox, Safari};
use koon_core::{Client, WsMessage};

/// Convert any Display error to a Python RuntimeError.
fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())
}

/// Resolve a browser name string to a BrowserProfile.
fn resolve_profile(browser: &str) -> PyResult<BrowserProfile> {
    match browser.to_lowercase().as_str() {
        "chrome" | "chrome145" | "chrome145windows" => Ok(Chrome::v145_windows()),
        "chrome145macos" => Ok(Chrome::v145_macos()),
        "chrome145linux" => Ok(Chrome::v145_linux()),
        "chrome131" | "chrome131windows" => Ok(Chrome::v131_windows()),
        "chrome131macos" => Ok(Chrome::v131_macos()),
        "chrome131linux" => Ok(Chrome::v131_linux()),
        "firefox" | "firefox147" | "firefox147windows" => Ok(Firefox::v147_windows()),
        "firefox147macos" => Ok(Firefox::v147_macos()),
        "firefox147linux" => Ok(Firefox::v147_linux()),
        "firefox135" | "firefox135windows" => Ok(Firefox::v135_windows()),
        "firefox135macos" => Ok(Firefox::v135_macos()),
        "firefox135linux" => Ok(Firefox::v135_linux()),
        "safari" | "safari183" | "safari183macos" => Ok(Safari::latest()),
        "edge" | "edge131" | "edge131windows" => Ok(Edge::v131_windows()),
        "edge131macos" => Ok(Edge::v131_macos()),
        other => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "Unknown browser: '{other}'. Use: chrome, chrome131, chrome145, \
             firefox, firefox135, firefox147, safari, safari183, edge, edge131"
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
    #[pyo3(signature = (browser="chrome", *, profile_json=None, proxy=None, timeout=30000, ignore_tls_errors=false, headers=None, follow_redirects=true, max_redirects=10, cookie_jar=true))]
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
    ) -> PyResult<Self> {
        let mut profile = if let Some(json) = profile_json {
            BrowserProfile::from_json(json).map_err(to_py_err)?
        } else {
            resolve_profile(browser)?
        };

        if ignore_tls_errors {
            profile.tls.danger_accept_invalid_certs = true;
        }

        let custom_headers: Vec<(String, String)> =
            headers.unwrap_or_default().into_iter().collect();

        let mut builder = Client::builder(profile)
            .timeout(Duration::from_millis(timeout as u64))
            .headers(custom_headers)
            .follow_redirects(follow_redirects)
            .max_redirects(max_redirects)
            .cookie_jar(cookie_jar);

        if let Some(proxy_url) = proxy {
            builder = builder.proxy(proxy_url).map_err(to_py_err)?;
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
    m.add_class::<KoonWebSocket>()?;
    Ok(())
}
