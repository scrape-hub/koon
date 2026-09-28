#' @include extendr-wrappers.R
NULL

#' @title Browser-Impersonating HTTP Client
#'
#' @description
#' An HTTP client that impersonates real browser TLS, HTTP/2, and HTTP/3
#' fingerprints. Supports Chrome, Firefox, Safari, Edge, Opera, Brave, Samsung Internet, Opera for Android, mobile browser,
#' and OkHttp (Android app) profiles.
#'
#' Create a client with `Koon$new(...)` and call its methods with `$`, e.g.
#' `client$get(url)`.
#'
#' @section Constructor arguments:
#' `Koon$new()` takes the following arguments. Any left `NULL` keeps koon's
#' default.
#' \describe{
#'   \item{`browser`}{Browser profile name, see [koon_browsers()]. Without a
#'     version the latest one is used, without an OS suffix desktop profiles
#'     impersonate Windows, Safari macOS: `"chrome"`, `"firefox154"`,
#'     `"chrome-macos"`, `"safarimobile"`, `"okhttp4"`. Default `"chrome"`.}
#'   \item{`profile_json`}{A custom browser profile as a JSON string (e.g. from
#'     `$export_profile()`). Overrides `browser`. Malformed JSON is a
#'     `koon_json_error`.}
#'   \item{`proxy`}{Proxy URL: `http://`, `https://` or `socks5://`, optionally
#'     with `user:pass@`. An `https://` proxy is reached over TLS and its
#'     certificate is verified (see `proxy_ca_certs`).}
#'   \item{`proxies`}{Character vector of proxy URLs used in rotation, one per
#'     request. Takes priority over `proxy`.}
#'   \item{`timeout`}{Timeout of a whole request in seconds, fractions allowed
#'     (default 30); `0` means no timeout.}
#'   \item{`headers`}{Headers sent with every request, in order: a named
#'     character vector, e.g. `c("Accept-Language" = "de-DE")`, or a named
#'     list of single strings, e.g. `list("Accept-Language" = "de-DE")`. They
#'     replace the profile's header of the same name at its browser position.
#'     A name given twice is sent once, with the last value.}
#'   \item{`local_address`}{Local IP address to bind outgoing connections to.}
#'   \item{`on_request`}{`function(method, url)`, called before each request,
#'     including each redirect hop. An error it raises fails the request
#'     before it is sent.}
#'   \item{`on_response`}{`function(status, url, headers)`, called after each
#'     response, including each redirect hop. `headers` is a data frame like
#'     the response's. An error it raises fails the request.}
#'   \item{`on_redirect`}{`function(status, url, headers)`, called before a
#'     redirect is followed. Return `FALSE` to stop and get the 3xx response;
#'     any other value (`TRUE`, `NULL` from a logging function, `NA`, ...)
#'     follows it. An error it raises fails the request.}
#'   \item{`retries`}{Number of automatic retries on transport errors
#'     (default 0). Requests that may already have reached the server are
#'     only retried for idempotent methods.}
#'   \item{`locale`}{Locale such as `"fr-FR"` or `"de"`, used for a matching
#'     `Accept-Language` header (e.g. for the proxy's geography).}
#'   \item{`proxy_headers`}{Headers for the HTTP CONNECT request to the proxy
#'     (session IDs, geo-targeting), in the same forms as `headers`.}
#'   \item{`ip_version`}{`4` or `6` to resolve hosts to IPv4 or IPv6 only.}
#'   \item{`follow_redirects`}{Follow redirects (default `TRUE`).}
#'   \item{`max_redirects`}{Maximum number of redirects to follow (default 10).}
#'   \item{`cookie_jar`}{Keep cookies across requests (default `TRUE`).}
#'   \item{`session_resumption`}{Resume TLS sessions (default `TRUE`).}
#'   \item{`ignore_tls_errors`}{Skip TLS certificate verification of origins
#'     (default `FALSE`). Dangerous; for testing only. `https://` proxies are
#'     still verified (see `ignore_proxy_tls_errors`).}
#'   \item{`proxy_ca_certs`}{Certificates (PEM, one or more) trusted for the
#'     TLS connection to `https://` proxies, in addition to the built-in
#'     roots, like curl's `--proxy-cacert`: for a proxy with a self-signed
#'     certificate or one from a private CA. PEM text, e.g.
#'     `readLines("proxy-ca.pem")`, or a raw vector. Origins are still
#'     verified against the built-in roots only.}
#'   \item{`ignore_proxy_tls_errors`}{Skip certificate verification of
#'     `https://` proxies (default `FALSE`), like curl's `--proxy-insecure`.
#'     The connection stays encrypted, but anyone on the way to the proxy can
#'     pose as it and read the proxy credentials and the hosts requested.
#'     Origins are still verified. Prefer `proxy_ca_certs`.}
#'   \item{`doh`}{DNS-over-HTTPS provider: `"cloudflare"` or `"google"`.}
#'   \item{`resolve`}{Character vector of entries in curl's `--resolve`
#'     format, `"host:port:address[,address...]"` (IPv6 in brackets):
#'     requests to that host and port connect to the address instead of
#'     resolving the host. TLS server name, Host header and cookies stay the
#'     host's.}
#'   \item{`max_response_body`}{Maximum response body size in bytes,
#'     decompressed (default 100 MiB): past it, a response fails with a
#'     `koon_body_error` instead of growing the buffer further (also covers
#'     a compressed body that decodes past the cap). `0` disables it.}
#'   \item{`server_padding`}{Pins Chrome/Edge/Opera 151+'s
#'     `PqcBandwidthExperiment` server-padding field trial group instead of
#'     drawing one when the client is built: `"none"` (not in the study,
#'     like 94% of real Chrome) or the bytes of padding the group asks for
#'     (e.g. `"6000"`). No effect on a profile that does not run the trial.
#'     Default: drawn per client.}
#' }
#'
#' @section Methods:
#' \describe{
#'   \item{`$get(url, ...)`, `$head(url, ...)`, `$delete(url, ...)`}{Send a
#'     request without a body. `...` takes the options of `$request()`.}
#'   \item{`$post(url, body = NULL, ...)`, `$put(...)`, `$patch(...)`}{Send a
#'     request with a body.}
#'   \item{`$request(method, url, body = NULL, headers = NULL, timeout = NULL,
#'     proxy = NULL, follow_redirects = NULL, max_redirects = NULL, on_request =
#'     NULL, on_response = NULL, on_redirect = NULL)`}{Send a request with any
#'     method. `body` is a single string or a raw vector. `headers` are headers
#'     for this request only, in the forms the constructor takes. The other
#'     options, callbacks included, override the client's setting of the same
#'     name for this request; `NULL` keeps it.}
#'   \item{`$save_session()`, `$load_session(json)`}{Save the cookies and TLS
#'     sessions as a JSON string, and restore them. `json` may also be the
#'     lines of a saved session file, as `readLines()` returns them.}
#'   \item{`$cookies()`}{All stored cookies as a data frame with Playwright's
#'     field names: `name`, `value`, `domain` (with a leading dot for domain
#'     cookies), `path`, `expires` (Unix seconds, -1 for session cookies),
#'     `httpOnly`, `secure`, `sameSite`, `hostOnly`.}
#'   \item{`$set_cookies(cookies)`}{Import cookies, e.g. from a browser via
#'     Playwright or CDP: a data frame like the one `$cookies()` returns
#'     (`jsonlite::fromJSON()` of Playwright's `cookies()` gives one) or a list
#'     of named lists. Each cookie needs `name`, `value` and either `domain`
#'     (optionally with `path`) or `url`; `expires`, `httpOnly`, `secure`,
#'     `sameSite` and `hostOnly` are optional. Every valid cookie is
#'     imported; the others are skipped, e.g. one with an invalid value or
#'     domain, and so are partitioned (CHIPS) cookies: those with a
#'     `partitionKey` holding anything but `NULL` or `NA` (a string, CDP's key
#'     object, or a row of the nested data frame `jsonlite::fromJSON()` makes
#'     of such objects) or with `partitionKeyOpaque = TRUE`; browsers send them
#'     only in a third-party context. Returns the skipped cookies invisibly,
#'     as a data frame with `index` (their row or element in `cookies`),
#'     `name` and `reason`, with no rows when all were imported. A field of
#'     the wrong type (e.g. a non-numeric `expires`) is an error.}
#'   \item{`$clear_cookies()`}{Remove all cookies.}
#'   \item{`$export_profile()`}{The browser profile as a JSON string.}
#'   \item{`$user_agent()`}{The profile's User-Agent, or `NULL`.}
#'   \item{`$total_bytes_sent()`, `$total_bytes_received()`,
#'     `$reset_counters()`}{Cumulative traffic of this client.}
#'   \item{`$close()`}{Close the pooled connections without waiting. The
#'     client can still be used afterwards; new connections open as needed.
#'     Idle HTTP/3 connections end as the browser ends them at shutdown; one
#'     with a response still being read ends once the response is done:
#'     Chrome-family profiles discard it without sending anything, as
#'     Chromium does; Firefox profiles close it with H3_NO_ERROR.}
#'   \item{`$shutdown()`}{End the client's connections as a browser does
#'     when it shuts down, e.g. before the R session ends: every HTTP/3
#'     connection closes at once with the browser's close, and the call
#'     returns once the closes have been sent (at most 300 ms). The client can
#'     still be used afterwards.}
#' }
#'
#' @section Responses:
#' A response is a list with these components:
#' \describe{
#'   \item{`status`, `status_code`}{Integer HTTP status code (e.g. 200).}
#'   \item{`ok`}{`TRUE` when the status is 2xx.}
#'   \item{`version`}{HTTP version: `"HTTP/1.1"`, `"h2"` or `"h3"`.}
#'   \item{`url`}{Final URL after redirects.}
#'   \item{`body`}{Raw vector with the body bytes.}
#'   \item{`text`}{The body as a string, decoded with the charset of the
#'     Content-Type (UTF-8 if none), or `NULL` for a binary body: a binary
#'     media type (image, audio, video, font, `application/octet-stream`,
#'     ...) or a body with NUL characters, which R strings cannot hold.}
#'   \item{`content_type`}{The Content-Type header, or `NULL`.}
#'   \item{`headers`}{Data frame with `name` and `value` columns.}
#'   \item{`request_headers`}{Data frame with `name` and `value` columns: the
#'     final request's headers as sent, in wire order (HTTP/2 and HTTP/3
#'     pseudo-headers first).}
#'   \item{`bytes_sent`, `bytes_received`}{Approximate bytes on the wire
#'     (headers and body, before decompression).}
#'   \item{`tls_resumed`}{`TRUE` if the TLS session was resumed.}
#'   \item{`connection_reused`}{`TRUE` if a pooled connection was reused.}
#'   \item{`remote_address`}{IP address of the peer (the proxy when one is
#'     used), or `NULL`.}
#' }
#'
#' @section Errors and interrupts:
#' Failures raise conditions of class `c("koon_<code>", "koon_error",
#' "error", "condition")`, where `<code>` is the lower-case error code, which
#' is also in the condition's `code` field: `"TIMEOUT"`,
#' `"CONNECTION_FAILED"`, `"TLS_ERROR"`, `"PROXY_ERROR"`, `"INVALID_URL"`,
#' `"TOO_MANY_REDIRECTS"`, `"INVALID_ARGUMENT"`, `"INVALID_COOKIE"`,
#' `"JSON_ERROR"`, ... An error raised by a callback fails the request and is
#' re-raised unchanged: the same condition object, with its own classes.
#'
#' Requests block, but Ctrl-C / Esc stops them and raises an ordinary R
#' interrupt, which `tryCatch(error = )` does not catch.
#'
#' @examples
#' \dontrun{
#' library(koon)
#'
#' # Latest Chrome on Windows
#' client <- Koon$new("chrome")
#'
#' resp <- client$get("https://httpbin.org/get")
#' resp$status   # 200
#' resp$ok       # TRUE
#' resp$text     # response body as string
#'
#' # Per-request headers and options
#' resp <- client$get("https://httpbin.org/get",
#'   headers = c(Authorization = "Bearer token"), timeout = 10)
#'
#' # POST a string (or a raw vector)
#' resp <- client$post("https://httpbin.org/post", '{"key": "value"}',
#'   headers = c("Content-Type" = "application/json"))
#' data <- jsonlite::fromJSON(resp$text)
#'
#' # Handle errors by class
#' tryCatch(
#'   client$get("https://httpbin.org/delay/10", timeout = 2),
#'   koon_timeout = function(e) message("timed out: ", conditionMessage(e)),
#'   koon_error = function(e) message("failed with ", e$code)
#' )
#'
#' # Cookies persist across requests, and can be exported and imported
#' client$get("https://httpbin.org/cookies/set/name/value")
#' cookies <- client$cookies()
#' client2 <- Koon$new("chrome")
#' client2$set_cookies(cookies)
#'
#' # Session save/load (cookies + TLS sessions)
#' json <- client$save_session()
#' client2$load_session(json)
#'
#' # Stop redirects that lead to a captcha
#' client <- Koon$new("chrome",
#'   on_redirect = function(status, url, headers) !grepl("captcha", url))
#'
#' # Log the hops of one request
#' client$get("https://httpbin.org/redirect/2",
#'   on_response = function(status, url, headers) message(status, " ", url))
#'
#' # Connect to a given address, like curl --resolve
#' client <- Koon$new("chrome", resolve = "example.com:443:93.184.215.14")
#'
#' # Proxy rotation with automatic retries
#' client <- Koon$new("firefox",
#'   proxies = c("socks5://a:1080", "socks5://b:1080"), retries = 3)
#'
#' # Other platforms and clients
#' client <- Koon$new("chrome-macos")
#' client <- Koon$new("chromemobile")   # Chrome on Android
#' client <- Koon$new("safarimobile")   # Safari on iOS
#' client <- Koon$new("okhttp4")        # Android app
#'
#' # The headers actually sent, in wire order
#' client$get("https://httpbin.org/get")$request_headers
#'
#' koon_browsers()
#' }
#'
#' @name Koon
#' @export Koon
NULL

# ---- Internals ---------------------------------------------------------------

# A Rust method returns its value or, on failure, the `extendr_error`
# condition of extendr's `result_condition` feature, whose `value` is one of
#   list(code = , message = )   a koon error
#   list(condition = )          the condition an R callback raised
#   list(interrupt = TRUE)      Ctrl-C / Esc stopped the request
# koon_unwrap() raises the matching R condition. The Rust side never raises
# R errors itself: that would longjmp through Rust frames.
koon_unwrap <- function(x) {
  if (!inherits(x, "extendr_error")) {
    return(if (is.null(x)) invisible(x) else x)
  }
  err <- x$value
  if (!is.null(err$condition)) {
    stop(err$condition)
  }
  if (isTRUE(err$interrupt)) {
    raise_interrupt()
    # Only reached when a calling handler resumed the interrupt.
    err <- list(code = "INTERRUPTED", message = "Request interrupted")
  }
  stop(koon_error(err$code, err$message))
}

koon_error <- function(code, message) {
  structure(
    class = c(paste0("koon_", tolower(code)), "koon_error", "error", "condition"),
    list(message = sprintf("[%s] %s", code, message), call = NULL, code = code)
  )
}

# Runs an R callback for the Rust side: list(value = <result>), or the
# condition that stopped it, an error or a user interrupt.
koon_run_callback <- function(f, ...) {
  tryCatch(list(value = f(...)), error = identity, interrupt = identity)
}

# Route the generated methods' results through koon_unwrap(). Their
# signatures stay those extendr generates from the Rust source.
local({
  for (name in names(Koon)) {
    method <- Koon[[name]]
    body(method) <- call("koon_unwrap", body(method))
    Koon[[name]] <- method
  }
})

# $set_cookies() returns the skipped cookies, usually none: invisibly.
body(Koon$set_cookies) <- call("invisible", body(Koon$set_cookies))

# HTTP verbs on top of $request(); `...` takes its options.
Koon$get <- function(url, ...) self$request("GET", url, NULL, ...)
Koon$head <- function(url, ...) self$request("HEAD", url, NULL, ...)
Koon$delete <- function(url, ...) self$request("DELETE", url, NULL, ...)
Koon$post <- function(url, body = NULL, ...) self$request("POST", url, body, ...)
Koon$put <- function(url, body = NULL, ...) self$request("PUT", url, body, ...)
Koon$patch <- function(url, body = NULL, ...) self$request("PATCH", url, body, ...)
