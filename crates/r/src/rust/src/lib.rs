//! R binding for koon: a thin extendr wrapper around `koon_core::Client`.
//!
//! Errors never unwind or longjmp through Rust frames. With extendr's
//! `result_condition` feature, a method returning `Err(RError)` hands R an
//! `extendr_error` condition whose `value` describes the failure, and
//! `koon_unwrap()` in `R/koon.R` raises it as a classed R condition.

use extendr_api::prelude::*;
use koon_core::dns::DohConfig;
use koon_core::{
    decode_body_text, parse_method, BrowserProfile, Client, CookieParams, HttpResponse, IpVersion,
    RequestOptions,
};
use std::borrow::Cow;
use std::net::IpAddr;
use std::os::raw::{c_int, c_void};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::{JoinError, JoinHandle};

/// How often a running request checks for Ctrl-C / Esc.
const INTERRUPT_POLL: Duration = Duration::from_millis(100);

/// Shared tokio runtime for every `Koon` client in this R session.
///
/// Requests are I/O-bound and the R thread drives one at a time, so two
/// workers suffice (the default would start one per CPU core). It must stay
/// multi-threaded: the `on_redirect` bridge blocks a worker with
/// `tokio::task::block_in_place`, which a current-thread runtime rejects.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("koon-r")
            .enable_all()
            .build()
            .expect("failed to start the tokio runtime")
    })
}

// --- Errors ------------------------------------------------------------------

type RResult<T> = std::result::Result<T, RError>;

/// Why a call failed. Becomes the `value` of the condition R receives, which
/// `koon_unwrap()` in `R/koon.R` raises.
enum RError {
    /// A koon error: its code (`koon_core::Error::code()`, `INVALID_ARGUMENT`
    /// for bad arguments) and message.
    Koon { code: &'static str, message: String },
    /// The condition an R callback raised; R re-raises it unchanged.
    Callback(Robj),
    /// The user pressed Ctrl-C / Esc during a request; R delivers the
    /// interrupt once every Rust frame has returned.
    Interrupt,
}

impl RError {
    fn invalid(message: impl Into<String>) -> Self {
        RError::Koon {
            code: "INVALID_ARGUMENT",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        RError::Koon {
            code: "INTERNAL_ERROR",
            message: message.into(),
        }
    }
}

impl From<koon_core::Error> for RError {
    fn from(e: koon_core::Error) -> Self {
        RError::Koon {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

impl From<RError> for Robj {
    fn from(e: RError) -> Robj {
        match e {
            RError::Koon { code, message } => list!(code = code, message = message).into(),
            RError::Callback(condition) => list!(condition = condition).into(),
            RError::Interrupt => list!(interrupt = true).into(),
        }
    }
}

// --- Interrupts ----------------------------------------------------------------
//
// `R_CheckUserInterrupt` longjmps when an interrupt is pending, which must not
// cross Rust frames. `R_ToplevelExec` runs it in a fresh top-level context
// that catches the jump and reports it through its return value instead.
// R resets its pending-interrupt flag while doing so, so the interrupt is
// consumed: `raise_interrupt()` raises it again with `Rf_onintr()` (as Rcpp
// and rlang do) once the request's Rust frames have all returned.

extern "C" {
    fn R_ToplevelExec(fun: Option<unsafe extern "C" fn(*mut c_void)>, data: *mut c_void) -> c_int;
    fn R_CheckUserInterrupt();
    fn Rf_onintr();
}

unsafe extern "C" fn check_user_interrupt(_data: *mut c_void) {
    unsafe { R_CheckUserInterrupt() }
}

/// True if the user pressed Ctrl-C / Esc since the last check.
fn interrupt_pending() -> bool {
    // FALSE (0): the check jumped out, i.e. an interrupt was pending.
    unsafe { R_ToplevelExec(Some(check_user_interrupt), std::ptr::null_mut()) == 0 }
}

/// Raise the user interrupt that stopped a request.
/// @noRd
#[extendr]
fn raise_interrupt() {
    // Jumps to R's top level (or a `tryCatch(interrupt = )`) like Ctrl-C.
    // Nothing in this frame or extendr's wrapper needs dropping, so jumping
    // over them is sound. Returns only if a handler resumed the interrupt.
    unsafe { Rf_onintr() }
}

// --- Arguments -----------------------------------------------------------------

/// An optional scalar argument; `NULL` (or `NA`) is `None`.
fn opt<T>(x: &Robj, name: &str, expected: &str) -> RResult<Option<T>>
where
    for<'a> Option<T>: TryFrom<&'a Robj>,
{
    Option::<T>::try_from(x).map_err(|_| RError::invalid(format!("`{name}` must be {expected}")))
}

fn opt_string(x: &Robj, name: &str) -> RResult<Option<String>> {
    opt(x, name, "a single string")
}

fn opt_bool(x: &Robj, name: &str) -> RResult<Option<bool>> {
    opt(x, name, "TRUE or FALSE")
}

fn opt_count(x: &Robj, name: &str) -> RResult<Option<u32>> {
    opt(x, name, "a whole number >= 0")
}

fn string(x: &Robj, name: &str) -> RResult<String> {
    opt_string(x, name)?.ok_or_else(|| RError::invalid(format!("`{name}` must be a single string")))
}

/// A timeout in seconds. `0` means no timeout, as in the core.
fn opt_timeout(x: &Robj) -> RResult<Option<Duration>> {
    opt::<f64>(x, "timeout", "a number of seconds")?
        .map(|secs| {
            Duration::try_from_secs_f64(secs).map_err(|_| {
                RError::invalid(format!(
                    "Invalid timeout: {secs}. Must be a finite number of seconds >= 0 (0 means no timeout)"
                ))
            })
        })
        .transpose()
}

/// A character vector without `NA`s.
fn strings(x: &Robj, name: &str) -> RResult<Vec<String>> {
    let invalid = || RError::invalid(format!("`{name}` must be a character vector without NA"));
    Strings::try_from(x)
        .map_err(|_| invalid())?
        .iter()
        .map(|s| {
            if s.is_na() {
                Err(invalid())
            } else {
                Ok(s.to_string())
            }
        })
        .collect()
}

/// Headers as a named character vector, e.g. `c(Accept = "text/html")`,
/// or a named list of single strings, e.g. `list(Accept = "text/html")`,
/// kept in order: header order is part of a browser's fingerprint. A name
/// may repeat; the last value is sent.
fn headers(x: &Robj, name: &str) -> RResult<Vec<(String, String)>> {
    if x.is_null() {
        return Ok(Vec::new());
    }
    let invalid = || {
        RError::invalid(format!(
            "`{name}` must be a named character vector or a named list of strings, \
             e.g. c(Accept = \"text/html\")"
        ))
    };
    let values: Vec<String> = if let Ok(list) = List::try_from(x) {
        list.values()
            .map(|value| match <&str>::try_from(&value) {
                Ok(text) if !value.is_na() => Ok(text.to_string()),
                _ => Err(invalid()),
            })
            .collect::<RResult<_>>()?
    } else {
        let strings = Strings::try_from(x).map_err(|_| invalid())?;
        strings
            .iter()
            .map(|value| {
                if value.is_na() {
                    Err(invalid())
                } else {
                    Ok(value.to_string())
                }
            })
            .collect::<RResult<_>>()?
    };
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let names = x.names().ok_or_else(invalid)?;
    names
        .zip(values)
        .map(|(name, value)| {
            if name.is_empty() || name.is_na() {
                Err(invalid())
            } else {
                Ok((name.to_string(), value))
            }
        })
        .collect()
}

/// A request body: a single string or a raw vector.
fn body(x: &Robj) -> RResult<Option<Vec<u8>>> {
    if x.is_null() {
        return Ok(None);
    }
    if let Some(bytes) = x.as_raw_slice() {
        return Ok(Some(bytes.to_vec()));
    }
    <&str>::try_from(x)
        .map(|s| Some(s.as_bytes().to_vec()))
        .map_err(|_| RError::invalid("`body` must be a single string or a raw vector"))
}

/// PEM text: a character vector, joined by newlines (so `readLines()` of a
/// PEM file works), or a raw vector.
fn opt_pem(x: &Robj, name: &str) -> RResult<Option<Vec<u8>>> {
    if x.is_null() {
        return Ok(None);
    }
    if let Some(bytes) = x.as_raw_slice() {
        return Ok(Some(bytes.to_vec()));
    }
    let lines = strings(x, name).map_err(|_| {
        RError::invalid(format!(
            "`{name}` must be PEM text (a character vector) or a raw vector"
        ))
    })?;
    Ok(Some(lines.join("\n").into_bytes()))
}

/// `4`, `6`, or a string the core parses (`"v4"`, `"ipv6"`, ...).
fn opt_ip_version(x: &Robj) -> RResult<Option<IpVersion>> {
    if x.is_null() {
        return Ok(None);
    }
    if let Ok(s) = <&str>::try_from(x) {
        return Ok(Some(s.parse()?));
    }
    let version = u8::try_from(x).map_err(|_| RError::invalid("`ip_version` must be 4 or 6"))?;
    Ok(Some(IpVersion::try_from(version)?))
}

/// A DNS-over-HTTPS provider name the core parses (`"cloudflare"`, `"google"`, ...).
fn opt_doh(x: &Robj) -> RResult<Option<DohConfig>> {
    Ok(opt_string(x, "doh")?
        .map(|provider| provider.parse::<DohConfig>())
        .transpose()?)
}

/// A local IP address to bind outgoing connections to.
fn opt_local_address(x: &Robj) -> RResult<Option<IpAddr>> {
    let Some(addr) = opt_string(x, "local_address")? else {
        return Ok(None);
    };
    addr.parse::<IpAddr>()
        .map(Some)
        .map_err(|e| RError::invalid(format!("Invalid local_address '{addr}': {e}")))
}

/// A response-body size cap in bytes; `0` disables it, `NULL` keeps the core's default (100 MiB).
fn opt_max_response_body(x: &Robj) -> RResult<u64> {
    Ok(opt::<u64>(x, "max_response_body", "a whole number >= 0")?
        .unwrap_or_else(|| koon_core::ConnectionOptions::default().max_response_body))
}

/// A pinned server-padding field trial group the core parses (`"none"`, or a number of bytes).
fn opt_server_padding(x: &Robj) -> RResult<Option<koon_core::ServerPadding>> {
    Ok(opt_string(x, "server_padding")?
        .map(|padding| padding.parse::<koon_core::ServerPadding>())
        .transpose()?)
}

/// A character vector, or an empty one for `NULL` (unset means "no proxies"/"no resolve
/// entries", not "an empty list of proxies", which the core would reject as invalid).
fn strings_or_empty(x: &Robj, name: &str) -> RResult<Vec<String>> {
    if x.is_null() {
        Ok(Vec::new())
    } else {
        strings(x, name)
    }
}

fn callback(x: Robj, name: &str) -> RResult<Option<Robj>> {
    if x.is_null() {
        Ok(None)
    } else if x.is_function() {
        Ok(Some(x))
    } else {
        Err(RError::invalid(format!(
            "`{name}` must be a function or NULL"
        )))
    }
}

/// A list's element by name.
fn field(list: &List, name: &str) -> Option<Robj> {
    list.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, value)| value)
}

/// The value of a data frame column in one row (0-based). A column that is
/// itself a data frame (what `jsonlite::fromJSON()` makes of CDP's
/// `partitionKey` objects) gives a named list of its columns' values.
fn cell(column: &Robj, row: usize) -> Option<Robj> {
    if column.inherits("data.frame") {
        let columns = List::try_from(column).ok()?;
        let names: Vec<&str> = columns.iter().map(|(name, _)| name).collect();
        let values = columns
            .values()
            .map(|nested| cell(&nested, row))
            .collect::<Option<Vec<Robj>>>()?;
        return List::from_names_and_values(names, values)
            .ok()
            .map(Robj::from);
    }
    column.index((row + 1) as i32).ok()
}

/// The rows of a data frame: the length of any of its columns, or of the
/// row names of a nested one.
fn row_count(column: &Robj) -> usize {
    if column.inherits("data.frame") {
        List::try_from(column)
            .ok()
            .and_then(|columns| columns.values().next())
            .map_or(0, |first| row_count(&first))
    } else {
        column.len()
    }
}

/// Whether a `partitionKey` field holds a key: anything with a value other
/// than `NULL` or `NA`, looking into lists (a CDP key object, or a nested
/// data frame row whose fields are all `NA` when the cookie has none).
fn has_partition_key(value: &Robj) -> bool {
    if value.is_null() || value.is_na() {
        return false;
    }
    match List::try_from(value) {
        Ok(list) => list.values().any(|item| has_partition_key(&item)),
        Err(_) => true,
    }
}

/// Cookies in the Playwright/CDP shape: a data frame with one row per cookie
/// (e.g. `jsonlite::fromJSON()` of Playwright's `cookies()`), or a list of
/// named lists. Fields the core does not know are ignored.
fn cookie_params(cookies: &Robj) -> RResult<Vec<CookieParams>> {
    let shape = || {
        RError::invalid(
            "`cookies` must be a data frame or a list of named lists with Playwright cookie fields",
        )
    };
    let list = List::try_from(cookies).map_err(|_| shape())?;
    if cookies.inherits("data.frame") {
        let rows = list.values().next().map_or(0, |column| row_count(&column));
        (0..rows)
            .map(|row| {
                cookie(row, |name| {
                    field(&list, name)
                        .map(|column| cell(&column, row).ok_or_else(shape))
                        .transpose()
                })
            })
            .collect()
    } else {
        list.values()
            .enumerate()
            .map(|(index, record)| {
                let record = List::try_from(&record).map_err(|_| shape())?;
                cookie(index, |name| Ok(field(&record, name)))
            })
            .collect()
    }
}

/// One cookie, reading its fields with `get`. `index` (0-based, like the
/// core's own cookie errors) names it in error messages.
fn cookie(index: usize, get: impl Fn(&str) -> RResult<Option<Robj>>) -> RResult<CookieParams> {
    let invalid = |name: &str, expected: &str| RError::Koon {
        code: "INVALID_COOKIE",
        message: format!("cookie {index}: `{name}` must be {expected}"),
    };
    let text = |name: &str| -> RResult<Option<String>> {
        get(name)?
            .map_or(Ok(None), |x| Option::<String>::try_from(&x))
            .map_err(|_| invalid(name, "a string"))
    };
    let flag = |name: &str| -> RResult<Option<bool>> {
        get(name)?
            .map_or(Ok(None), |x| Option::<bool>::try_from(&x))
            .map_err(|_| invalid(name, "TRUE or FALSE"))
    };
    let required = |name: &str| text(name)?.ok_or_else(|| invalid(name, "given"));
    Ok(CookieParams {
        name: required("name")?,
        value: required("value")?,
        domain: text("domain")?,
        path: text("path")?,
        url: text("url")?,
        expires: get("expires")?
            .map_or(Ok(None), |x| Option::<f64>::try_from(&x))
            .map_err(|_| invalid("expires", "a number"))?,
        http_only: flag("httpOnly")?.unwrap_or(false),
        secure: flag("secure")?.unwrap_or(false),
        same_site: text("sameSite")?,
        host_only: flag("hostOnly")?,
        partitioned: get("partitionKey")?.is_some_and(|key| has_partition_key(&key))
            || flag("partitionKeyOpaque")? == Some(true),
    })
}

// --- Responses -------------------------------------------------------------------

fn headers_data_frame(headers: &[(String, String)]) -> Robj {
    let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    let values: Vec<&str> = headers.iter().map(|(_, v)| v.as_str()).collect();
    data_frame!(name = names, value = values)
}

/// Media types whose bodies are never text.
fn is_binary_media_type(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    if subtype.ends_with("+xml") || subtype.ends_with("+json") {
        return false; // image/svg+xml and friends
    }
    matches!(kind, "image" | "audio" | "video" | "font")
        || matches!(
            essence.as_str(),
            "application/octet-stream"
                | "application/pdf"
                | "application/zip"
                | "application/gzip"
                | "application/wasm"
        )
}

/// The body as text, decoded with the Content-Type charset. `None` for a
/// binary body: a binary media type, or a NUL character, which an R string
/// cannot hold.
fn body_text<'a>(body: &'a [u8], content_type: Option<&str>) -> Option<Cow<'a, str>> {
    if content_type.is_some_and(is_binary_media_type) {
        return None;
    }
    let text = decode_body_text(body, content_type);
    (!text.contains('\0')).then_some(text)
}

fn string_or_null(value: Option<&str>) -> Robj {
    value.map_or_else(|| ().into(), Robj::from)
}

fn response_to_list(resp: HttpResponse) -> List {
    let content_type = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    let text = string_or_null(body_text(&resp.body, content_type).as_deref());
    let content_type = string_or_null(content_type);
    list!(
        status = resp.status as i32,
        status_code = resp.status as i32,
        ok = (200..300).contains(&resp.status),
        version = resp.version.as_str(),
        url = resp.url.as_str(),
        body = Raw::from_bytes(&resp.body),
        text = text,
        content_type = content_type,
        headers = headers_data_frame(&resp.headers),
        request_headers = headers_data_frame(&resp.request_headers),
        bytes_sent = resp.bytes_sent as f64,
        bytes_received = resp.bytes_received as f64,
        tls_resumed = resp.tls_resumed,
        connection_reused = resp.connection_reused,
        remote_address = string_or_null(resp.remote_address.as_deref())
    )
}

// --- Callbacks -------------------------------------------------------------------

/// A callback event raised from a core hook (on a tokio worker thread) and
/// run on the R main thread. Each carries a reply channel: the core waits
/// for the callback before it goes on, so that a failing `on_request` stops
/// the request before it is sent. A reply that never comes (the callback
/// failed, the user interrupted) fails the request.
enum CallbackEvent {
    Request {
        method: String,
        url: String,
        reply: mpsc::Sender<()>,
    },
    Response {
        status: u16,
        url: String,
        headers: Vec<(String, String)>,
        reply: mpsc::Sender<()>,
    },
    Redirect {
        status: u16,
        url: String,
        headers: Vec<(String, String)>,
        reply: mpsc::Sender<bool>,
    },
}

/// What a core hook fails with when its R callback failed: the R side keeps
/// the condition and raises it, so this only ends the request.
#[derive(Debug)]
struct CallbackFailed;

impl std::fmt::Display for CallbackFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an R callback failed")
    }
}

impl std::error::Error for CallbackFailed {}

/// Send `event` to the R thread and wait for its reply.
fn run_on_r_thread<T>(
    tx: &UnboundedSender<CallbackEvent>,
    event: impl FnOnce(mpsc::Sender<T>) -> CallbackEvent,
) -> std::result::Result<T, koon_core::Error> {
    let (reply, answer) = mpsc::channel();
    tx.send(event(reply))
        .ok()
        .and_then(|()| tokio::task::block_in_place(|| answer.recv().ok()))
        .ok_or_else(|| koon_core::Error::Hook(Box::new(CallbackFailed)))
}

/// What woke the R thread while a request runs.
enum Step<T> {
    Event(Option<CallbackEvent>),
    Done(std::result::Result<T, JoinError>),
    Tick,
}

/// The R callbacks of a client or of one request.
#[derive(Clone, Default)]
struct Callbacks {
    on_request: Option<Robj>,
    on_response: Option<Robj>,
    on_redirect: Option<Robj>,
}

impl Callbacks {
    fn new(on_request: Robj, on_response: Robj, on_redirect: Robj) -> RResult<Self> {
        Ok(Callbacks {
            on_request: callback(on_request, "on_request")?,
            on_response: callback(on_response, "on_response")?,
            on_redirect: callback(on_redirect, "on_redirect")?,
        })
    }

    /// These callbacks, each falling back to `client`'s.
    fn or(self, client: &Callbacks) -> Callbacks {
        Callbacks {
            on_request: self.on_request.or_else(|| client.on_request.clone()),
            on_response: self.on_response.or_else(|| client.on_response.clone()),
            on_redirect: self.on_redirect.or_else(|| client.on_redirect.clone()),
        }
    }

    fn is_empty(&self) -> bool {
        self.on_request.is_none() && self.on_response.is_none() && self.on_redirect.is_none()
    }

    /// Register these callbacks as per-request core hooks. The hooks forward
    /// plain owned data through `tx` only: R values may only be touched on
    /// the R main thread.
    fn wire(&self, options: &mut RequestOptions, tx: &UnboundedSender<CallbackEvent>) {
        if self.on_request.is_some() {
            let tx = tx.clone();
            options.on_request = Some(Arc::new(move |method: &str, url: &str| {
                run_on_r_thread(&tx, |reply| CallbackEvent::Request {
                    method: method.to_string(),
                    url: url.to_string(),
                    reply,
                })
            }));
        }
        if self.on_response.is_some() {
            let tx = tx.clone();
            options.on_response = Some(Arc::new(
                move |status: u16, url: &str, headers: &[(String, String)]| {
                    run_on_r_thread(&tx, |reply| CallbackEvent::Response {
                        status,
                        url: url.to_string(),
                        headers: headers.to_vec(),
                        reply,
                    })
                },
            ));
        }
        if self.on_redirect.is_some() {
            let tx = tx.clone();
            options.on_redirect = Some(Arc::new(
                move |status: u16, url: &str, headers: &[(String, String)]| {
                    run_on_r_thread(&tx, |reply| CallbackEvent::Redirect {
                        status,
                        url: url.to_string(),
                        headers: headers.to_vec(),
                        reply,
                    })
                },
            ));
        }
    }
}

/// `koon_run_callback()` from the package namespace, which runs an R
/// callback and returns `list(value = ...)` or the condition that stopped it.
fn callback_runner() -> RResult<Robj> {
    let namespace = find_namespace("koon")
        .map_err(|e| RError::internal(format!("koon namespace not found: {e}")))?;
    namespace
        .local(sym!(koon_run_callback))
        .ok()
        .filter(Robj::is_function)
        .ok_or_else(|| RError::internal("koon_run_callback() not found"))
}

/// Runs the callbacks of one request on the R main thread.
struct CallbackRunner {
    callbacks: Callbacks,
    runner: Robj,
}

impl CallbackRunner {
    /// Run the R callback `f` with `args` through `koon_run_callback()`.
    fn run(&self, f: &Robj, args: &[Robj]) -> RResult<Robj> {
        let call_args = std::iter::once(f).chain(args).map(|arg| ("", arg.clone()));
        let result = self
            .runner
            .call(Pairlist::from_pairs(call_args.collect::<Vec<_>>()))
            .map_err(|e| RError::internal(format!("an R callback could not be run: {e}")))?;
        if result.inherits("interrupt") {
            return Err(RError::Interrupt);
        }
        if result.inherits("error") {
            return Err(RError::Callback(result));
        }
        List::try_from(&result)
            .ok()
            .and_then(|list| list.elt(0).ok())
            .ok_or_else(|| RError::internal("an R callback returned an unexpected result"))
    }

    /// Run the R callback matching `event` and reply to the waiting hook.
    /// On failure the reply channel is dropped unanswered, which fails the
    /// request in the core.
    fn dispatch(&self, event: CallbackEvent) -> RResult<()> {
        match event {
            CallbackEvent::Request { method, url, reply } => {
                if let Some(f) = &self.callbacks.on_request {
                    self.run(f, &[method.into(), url.into()])?;
                }
                // The hook is gone if the request already failed (e.g.
                // timed out); nothing is waiting for the answer then.
                let _ = reply.send(());
            }
            CallbackEvent::Response {
                status,
                url,
                headers,
                reply,
            } => {
                if let Some(f) = &self.callbacks.on_response {
                    let args = [
                        (status as i32).into(),
                        url.into(),
                        headers_data_frame(&headers),
                    ];
                    self.run(f, &args)?;
                }
                let _ = reply.send(());
            }
            CallbackEvent::Redirect {
                status,
                url,
                headers,
                reply,
            } => {
                let mut follow = true;
                if let Some(f) = &self.callbacks.on_redirect {
                    let args = [
                        (status as i32).into(),
                        url.into(),
                        headers_data_frame(&headers),
                    ];
                    // Only FALSE stops: NULL (e.g. from a logging function),
                    // NA and anything else follow, as in Node and Python.
                    let answer = self.run(f, &args)?;
                    follow = !matches!(bool::try_from(&answer), Ok(false));
                }
                let _ = reply.send(follow);
            }
        }
        Ok(())
    }
}

/// The main Koon HTTP client with browser fingerprint impersonation. The R
/// documentation lives in `R/koon.R`.
#[extendr]
struct Koon {
    client: Arc<Client>,
    callbacks: Callbacks,
}

/// Drive `handle` to completion on the R main thread, running callbacks as
/// their events arrive and checking for Ctrl-C / Esc every
/// [`INTERRUPT_POLL`]. On an interrupt or a failing callback the task is
/// aborted and `rx` dropped with the events still queued in it, so no
/// callback runs after that and a waiting hook returns.
fn poll_until_done<T: Send + 'static>(
    mut handle: JoinHandle<T>,
    mut rx: UnboundedReceiver<CallbackEvent>,
    callbacks: Option<CallbackRunner>,
) -> RResult<T> {
    let mut events_open = true;
    let mut next_check = Instant::now() + INTERRUPT_POLL;
    loop {
        // Callbacks run outside `block_on`: one may start a request of
        // its own, which calls `block_on` again.
        let step = runtime().block_on(async {
            tokio::select! {
                // Events first: those sent before the task finished run
                // before its result is returned.
                biased;
                event = rx.recv(), if events_open => Step::Event(event),
                joined = &mut handle => Step::Done(joined),
                () = tokio::time::sleep_until(next_check.into()) => Step::Tick,
            }
        });
        match step {
            Step::Done(joined) => {
                return joined
                    .map_err(|e| RError::internal(format!("the request task failed: {e}")));
            }
            Step::Event(Some(event)) => {
                let dispatched = match &callbacks {
                    Some(runner) => runner.dispatch(event),
                    None => Ok(()),
                };
                if let Err(e) = dispatched {
                    handle.abort();
                    return Err(e);
                }
            }
            Step::Event(None) => events_open = false,
            Step::Tick => {}
        }
        if Instant::now() >= next_check {
            if interrupt_pending() {
                handle.abort();
                return Err(RError::Interrupt);
            }
            next_check = Instant::now() + INTERRUPT_POLL;
        }
    }
}

#[extendr]
impl Koon {
    #[allow(clippy::too_many_arguments)]
    fn new(
        #[default = "\"chrome\""] browser: Robj,
        #[default = "NULL"] profile_json: Robj,
        #[default = "NULL"] proxy: Robj,
        #[default = "NULL"] proxies: Robj,
        #[default = "NULL"] timeout: Robj,
        #[default = "NULL"] headers: Robj,
        #[default = "NULL"] local_address: Robj,
        #[default = "NULL"] on_request: Robj,
        #[default = "NULL"] on_response: Robj,
        #[default = "NULL"] on_redirect: Robj,
        #[default = "NULL"] retries: Robj,
        #[default = "NULL"] locale: Robj,
        #[default = "NULL"] proxy_headers: Robj,
        #[default = "NULL"] ip_version: Robj,
        #[default = "NULL"] follow_redirects: Robj,
        #[default = "NULL"] max_redirects: Robj,
        #[default = "NULL"] cookie_jar: Robj,
        #[default = "NULL"] session_resumption: Robj,
        #[default = "NULL"] ignore_tls_errors: Robj,
        #[default = "NULL"] proxy_ca_certs: Robj,
        #[default = "NULL"] ignore_proxy_tls_errors: Robj,
        #[default = "NULL"] doh: Robj,
        #[default = "NULL"] resolve: Robj,
        #[default = "NULL"] max_response_body: Robj,
        #[default = "NULL"] server_padding: Robj,
    ) -> RResult<Self> {
        let profile = BrowserProfile::from_name_or_json(
            &string(&browser, "browser")?,
            opt_string(&profile_json, "profile_json")?.as_deref(),
        )?;

        let connection = koon_core::ConnectionOptions {
            ignore_tls_errors: opt_bool(&ignore_tls_errors, "ignore_tls_errors")?.unwrap_or(false),
            proxy: opt_string(&proxy, "proxy")?,
            proxies: strings_or_empty(&proxies, "proxies")?,
            proxy_ca_certs: opt_pem(&proxy_ca_certs, "proxy_ca_certs")?,
            ignore_proxy_tls_errors: opt_bool(&ignore_proxy_tls_errors, "ignore_proxy_tls_errors")?
                .unwrap_or(false),
            proxy_headers: self::headers(&proxy_headers, "proxy_headers")?,
            session_resumption: opt_bool(&session_resumption, "session_resumption")?
                .unwrap_or(true),
            doh: opt_doh(&doh)?,
            local_address: opt_local_address(&local_address)?,
            retries: opt_count(&retries, "retries")?.unwrap_or(0),
            locale: opt_string(&locale, "locale")?,
            ip_version: opt_ip_version(&ip_version)?,
            resolve: strings_or_empty(&resolve, "resolve")?,
            max_response_body: opt_max_response_body(&max_response_body)?,
            server_padding: opt_server_padding(&server_padding)?,
        };

        // Unset (NULL) options keep the core's defaults.
        let mut builder = connection
            .apply(profile)?
            .headers(self::headers(&headers, "headers")?);
        if let Some(timeout) = opt_timeout(&timeout)? {
            builder = builder.timeout(timeout);
        }
        if let Some(follow) = opt_bool(&follow_redirects, "follow_redirects")? {
            builder = builder.follow_redirects(follow);
        }
        if let Some(max) = opt_count(&max_redirects, "max_redirects")? {
            builder = builder.max_redirects(max);
        }
        if let Some(enabled) = opt_bool(&cookie_jar, "cookie_jar")? {
            builder = builder.cookie_jar(enabled);
        }

        // The callbacks are wired per request (see `Callbacks::wire`), never
        // registered on the builder: they may only run on the R thread.
        Ok(Koon {
            client: Arc::new(builder.build()?),
            callbacks: Callbacks::new(on_request, on_response, on_redirect)?,
        })
    }

    /// Send a request and wait for the response, interruptibly. The HTTP
    /// verbs (`get`, `post`, ...) are defined on top of this in R/koon.R.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        method: Robj,
        url: Robj,
        #[default = "NULL"] body: Robj,
        #[default = "NULL"] headers: Robj,
        #[default = "NULL"] timeout: Robj,
        #[default = "NULL"] proxy: Robj,
        #[default = "NULL"] follow_redirects: Robj,
        #[default = "NULL"] max_redirects: Robj,
        #[default = "NULL"] on_request: Robj,
        #[default = "NULL"] on_response: Robj,
        #[default = "NULL"] on_redirect: Robj,
    ) -> RResult<List> {
        let method = parse_method(&string(&method, "method")?)?;
        let url = string(&url, "url")?;
        let body = self::body(&body)?;
        // Unset (NULL) options fall back to the client's settings.
        let mut options = RequestOptions {
            headers: self::headers(&headers, "headers")?,
            timeout: opt_timeout(&timeout)?,
            proxy: opt_string(&proxy, "proxy")?,
            follow_redirects: opt_bool(&follow_redirects, "follow_redirects")?,
            max_redirects: opt_count(&max_redirects, "max_redirects")?,
            ..Default::default()
        };
        let callbacks = Callbacks::new(on_request, on_response, on_redirect)?.or(&self.callbacks);

        let (tx, rx) = unbounded_channel();
        callbacks.wire(&mut options, &tx);
        drop(tx);
        let runner = if callbacks.is_empty() {
            None
        } else {
            Some(CallbackRunner {
                callbacks,
                runner: callback_runner()?,
            })
        };

        let client = Arc::clone(&self.client);
        let handle = runtime().spawn(async move { client.send(method, &url, body, options).await });
        let response = poll_until_done(handle, rx, runner)??;
        Ok(response_to_list(response))
    }

    fn save_session(&self) -> RResult<String> {
        Ok(self.client.save_session()?)
    }

    /// `json` may also be the lines of a saved file, as `readLines()` gives
    /// them.
    fn load_session(&self, json: Robj) -> RResult<()> {
        Ok(self
            .client
            .load_session(&strings(&json, "json")?.join("\n"))?)
    }

    /// Import cookies in the Playwright/CDP shape; see `cookie_params()`.
    /// Returns the skipped ones as a data frame: `index` (the row or element
    /// of `cookies`, 1-based), `name` and `reason`.
    fn set_cookies(&self, cookies: Robj) -> RResult<Robj> {
        let skipped = self.client.set_cookie_params(cookie_params(&cookies)?)?;
        Ok(data_frame!(
            index = skipped
                .iter()
                .map(|s| i32::try_from(s.index + 1).unwrap_or(i32::MAX))
                .collect::<Vec<i32>>(),
            name = skipped
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<&str>>(),
            reason = skipped
                .iter()
                .map(|s| s.reason.as_str())
                .collect::<Vec<&str>>()
        ))
    }

    /// Every stored cookie as a data frame with Playwright's field names,
    /// which `set_cookies()` takes back.
    fn cookies(&self) -> Robj {
        let cookies = self.client.cookie_params();
        let text = |get: fn(&CookieParams) -> Option<&str>| -> Vec<&str> {
            cookies.iter().map(|c| get(c).unwrap_or_default()).collect()
        };
        data_frame!(
            name = text(|c| Some(&c.name)),
            value = text(|c| Some(&c.value)),
            domain = text(|c| c.domain.as_deref()),
            path = text(|c| c.path.as_deref()),
            expires = cookies
                .iter()
                .map(|c| c.expires.unwrap_or(-1.0))
                .collect::<Vec<f64>>(),
            httpOnly = cookies.iter().map(|c| c.http_only).collect::<Vec<bool>>(),
            secure = cookies.iter().map(|c| c.secure).collect::<Vec<bool>>(),
            sameSite = text(|c| c.same_site.as_deref()),
            hostOnly = cookies
                .iter()
                .map(|c| c.host_only.unwrap_or(false))
                .collect::<Vec<bool>>()
        )
    }

    fn export_profile(&self) -> RResult<String> {
        self.client
            .profile()
            .to_json_pretty()
            .map_err(|e| koon_core::Error::from(e).into())
    }

    fn total_bytes_sent(&self) -> f64 {
        self.client.total_bytes_sent() as f64
    }

    fn total_bytes_received(&self) -> f64 {
        self.client.total_bytes_received() as f64
    }

    fn reset_counters(&self) {
        self.client.reset_counters();
    }

    fn user_agent(&self) -> Option<String> {
        self.client.user_agent().map(str::to_string)
    }

    fn clear_cookies(&self) {
        self.client.clear_cookies();
    }

    /// Close the pooled connections without waiting; the client stays
    /// usable.
    fn close(&self) {
        self.client.close();
    }

    fn shutdown(&self) {
        runtime().block_on(self.client.shutdown());
    }
}

/// List all available browser profile names
///
/// One name per profile: every browser version on every OS it has a profile
/// for, e.g. `"chrome154-windows"`, `"safari266-ios"` or `"okhttp5"`. Names
/// without a version select the latest one (`"chrome-macos"`); without an
/// OS, desktop profiles impersonate Windows, Safari macOS (`"firefox154"`).
///
/// @return A character vector of browser profile names.
/// @export
#[extendr]
fn koon_browsers() -> Vec<String> {
    BrowserProfile::names()
        .map(|profile| profile.name)
        .collect()
}

extendr_module! {
    mod koon;
    impl Koon;
    fn koon_browsers;
    fn raise_interrupt;
}
