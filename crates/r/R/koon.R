#' @include extendr-wrappers.R
NULL

# BEGIN GENERATED docs (crates/core/tests/generated.rs)
#' @section Constructor arguments:
#' `Koon$new()` takes the following arguments. Any left `NULL` keeps its
#' default.
#' \describe{
#'   \item{`browser`}{Browser profile to impersonate, such as `chrome`,
#'     `firefox154`, `chrome-macos`, `safari-mobile266` or `okhttp5`. Without a
#'     version it is the newest one, without an OS desktop browsers impersonate
#'     Windows and Safari macOS. Default `"chrome"`.}
#'   \item{`profile_json`}{A custom browser profile as JSON, as
#'     `$export_profile()` returns it. Overrides `browser`. Malformed JSON fails
#'     with `koon_json_error`.}
#'   \item{`proxy`}{Proxy URL: `http://`, `https://`, `socks5://` or
#'     `socks5h://` (the same: the proxy resolves the host name), optionally
#'     with `user:pass@`. An `https://` proxy is reached over TLS and its
#'     certificate is verified (see `proxy_ca_certs`).}
#'   \item{`proxies`}{Proxy URLs to rotate through: each request, and each
#'     retry, takes the next one. Takes priority over `proxy`.}
#'   \item{`timeout`}{Timeout of a whole request in seconds, fractions
#'     allowed: connecting, redirects and the body. `0` means no timeout.
#'     Default 30.}
#'   \item{`headers`}{Headers sent with every request, in order. They replace
#'     the profile's header of the same name at its browser position; a name
#'     given twice is sent once, with the last value. A named character vector
#'     or a named list of single strings, e.g. `c("Accept-Language" =
#'     "de-DE")`.}
#'   \item{`local_address`}{Local IP address outgoing connections are bound
#'     to.}
#'   \item{`on_request`}{Called before each request, including each redirect
#'     hop, with the method and URL. An error it raises fails the request before
#'     it is sent. A `function(method, url)`.}
#'   \item{`on_response`}{Called after each response, including each redirect
#'     hop, once its cookies are stored, with the status, URL and headers. An
#'     error it raises fails the request. A `function(status, url, headers)`,
#'     `headers` a data frame like the response's.}
#'   \item{`on_redirect`}{Called before a redirect is followed, with the
#'     status, URL and headers. Return `FALSE` to stop and get the 3xx response;
#'     any other value follows it. An error it raises fails the request. A
#'     `function(status, url, headers)`, `headers` a data frame like the
#'     response's.}
#'   \item{`retries`}{Automatic retries on transport errors. With `proxies`,
#'     each retry takes the next proxy. A request that may already have reached
#'     the server is retried only for idempotent methods. Default 0.}
#'   \item{`locale`}{The user's language, such as `de-AT`, to match the
#'     proxy's country. The Accept-Language header becomes what the profile's
#'     browser sends for it: Chrome the list of the UI language it picks
#'     (`de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7`), Safari `de-DE,de;q=0.9`.}
#'   \item{`proxy_headers`}{Headers of the HTTP CONNECT request to the proxy,
#'     in order: session IDs, geo-targeting, authentication. A named character
#'     vector or a named list of single strings, e.g. `c("Accept-Language" =
#'     "de-DE")`.}
#'   \item{`ip_version`}{Resolve hosts to IPv4 (`4`) or IPv6 (`6`) only, e.g.
#'     for a proxy that speaks IPv4 alone. `v4`, `ipv6` and the like work too.}
#'   \item{`follow_redirects`}{Follow redirects. Default `TRUE`.}
#'   \item{`max_redirects`}{Maximum number of redirects to follow. Default
#'     10.}
#'   \item{`cookie_jar`}{Keep cookies across requests. Default `TRUE`.}
#'   \item{`session_resumption`}{Resume TLS sessions. Default `TRUE`.}
#'   \item{`ignore_tls_errors`}{Skip certificate verification of origins.
#'     `https://` proxies are still verified (see `ignore_proxy_tls_errors`).
#'     Default `FALSE`.}
#'   \item{`proxy_ca_certs`}{Certificates (PEM, one or more) trusted for the
#'     TLS connection to `https://` proxies in addition to the built-in roots,
#'     like curl's `--proxy-cacert`: for a proxy with a self-signed certificate
#'     or one from a private CA. Origins are still verified against the built-in
#'     roots only. Invalid PEM fails with `koon_invalid_argument`. PEM text,
#'     e.g. `readLines("proxy-ca.pem")`, or a raw vector.}
#'   \item{`ignore_proxy_tls_errors`}{Skip certificate verification of
#'     `https://` proxies, like curl's `--proxy-insecure`. The connection stays
#'     encrypted, but anyone on the way to the proxy can pose as it and read the
#'     proxy credentials and the hosts requested. Origins are still verified.
#'     Prefer `proxy_ca_certs`. Default `FALSE`.}
#'   \item{`doh`}{DNS-over-HTTPS provider, any case: `cloudflare` or
#'     `google`.}
#'   \item{`resolve`}{Entries in curl's `--resolve` format,
#'     `host:port:address[,address...]` (IPv6 in brackets): requests to that
#'     host and port connect to the address instead of resolving the host. The
#'     TLS server name, Host header and cookies stay the host's. An invalid
#'     entry fails with `koon_invalid_argument`.}
#'   \item{`max_response_body`}{Maximum response body size in bytes,
#'     decompressed: past it, a response fails with `koon_body_error` instead of
#'     growing the buffer further, also when a compressed body decodes past it.
#'     Reading a streaming response chunk by chunk without decoding it is not
#'     capped. `0` disables it. Default 100 MiB.}
#'   \item{`server_padding`}{Pins Chrome 151+'s `PqcBandwidthExperiment`
#'     server-padding field trial group instead of drawing one when the client
#'     is built: `none` (not in the study) or the bytes of padding the group
#'     asks for (e.g. `6000`). The study ended on 2026-10-30, so a client no
#'     longer draws one. No effect on a profile without the trial.}
#' }
#'
#' @section Request options:
#' `$request()` and the verbs (`$get()`, `$post()`, ...) take these options for
#' one request. Any left `NULL` keeps the client's setting.
#' \describe{
#'   \item{`headers`}{Headers of this request, in order. They replace client
#'     and profile headers of the same name, which keep their browser position.
#'     A named character vector or a named list of single strings, e.g.
#'     `c("Accept-Language" = "de-DE")`.}
#'   \item{`timeout`}{Timeout of this request in seconds, fractions allowed; a
#'     streaming request times the response head and then each wait for the
#'     body. `0` means no timeout.}
#'   \item{`proxy`}{Proxy URL for this request, in place of the client's
#'     proxies.}
#'   \item{`follow_redirects`}{Follow redirects in this request.}
#'   \item{`max_redirects`}{Maximum number of redirects this request follows.}
#'   \item{`on_request`}{Called before each request of this call, including
#'     each redirect hop, in place of the client's. A `function(method, url)`.}
#'   \item{`on_response`}{Called after each response of this call, including
#'     each redirect hop, in place of the client's. A `function(status, url,
#'     headers)`, `headers` a data frame like the response's.}
#'   \item{`on_redirect`}{Called before a redirect of this call is followed,
#'     in place of the client's. Return `FALSE` to stop. A `function(status,
#'     url, headers)`, `headers` a data frame like the response's.}
#' }
#' @name Koon
#' @rdname Koon
NULL
# END GENERATED docs

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
#' @section Methods:
#' \describe{
#'   \item{`$get(url, ...)`, `$head(url, ...)`, `$delete(url, ...)`}{Send a
#'     request without a body. `...` takes the options of `$request()`.}
#'   \item{`$post(url, body = NULL, ...)`, `$put(...)`, `$patch(...)`}{Send a
#'     request with a body.}
#'   \item{`$request(method, url, body = NULL, ...)`}{Send a request with any
#'     method. `body` is a single string or a raw vector. `...` takes the
#'     request options above.}
#'   \item{`$post_multipart(url, fields, ...)`}{Send a multipart/form-data
#'     POST as the profile's browser builds it. `fields` is a list of named
#'     lists, each with `name` and either `value` (text) or `file_data` (a raw
#'     vector, e.g. `readBin(path, "raw", file.size(path))`) with an optional
#'     `filename` and `content_type`. `...` takes the request options above.}
#'   \item{`$request_streaming(method, url, body = NULL, ..., decode = NULL)`}{Send
#'     a request and return once its head has arrived: a list like a
#'     response without `body` and `text`, whose `stream` reads the body.
#'     `$stream$next_chunk()` gives the next chunk as a raw vector, `NULL` at
#'     the end; `$stream$collect()` the rest at once; `$stream$cancel()` drops
#'     it. The body is decoded (Content-Encoding) as it is read unless
#'     `decode = FALSE`. `...` takes the request options above.}
#'   \item{`$websocket(url, headers = NULL)`}{Open a WebSocket connection.
#'     Its `$send(data)` sends a single string as a text message or a raw
#'     vector as a binary one, `$receive()` returns the next message as
#'     `list(type = "text" or "binary", data = ...)`, `NULL` once the
#'     connection is closed, and `$close(code = NULL, reason = NULL)` closes
#'     it.}
#'   \item{`$save_session()`, `$load_session(json)`}{Save the cookies and TLS
#'     sessions as a JSON string, and restore them. `json` may also be the
#'     lines of a saved session file, as `readLines()` returns them.}
#'   \item{`$save_session_to_file(path)`, `$load_session_from_file(path)`}{The
#'     same with a file.}
#'   \item{`$cookies()`}{All stored cookies as a data frame with Playwright's
#'     field names: `name`, `value`, `domain` (with a leading dot for domain
#'     cookies), `path`, `expires` (Unix seconds, -1 for session cookies),
#'     `httpOnly`, `secure`, `sameSite` (`NA` for a cookie without one),
#'     `hostOnly`, `partitionKey` (the top-level site of a partitioned cookie,
#'     `NA` for others).}
#'   \item{`$set_cookies(cookies)`}{Import cookies, e.g. from a browser via
#'     Playwright or CDP: a data frame like the one `$cookies()` returns
#'     (`jsonlite::fromJSON()` of Playwright's `cookies()` gives one) or a list
#'     of named lists. Each cookie needs `name`, `value` and either `domain`
#'     (optionally with `path`) or `url`; `expires`, `httpOnly`, `secure`,
#'     `sameSite` and `hostOnly` are optional. Every valid cookie is
#'     imported; the others are skipped, e.g. one with an invalid value or
#'     domain. A partitioned (CHIPS) cookie keeps its partition and goes only
#'     with requests from pages of its top-level site; its `partitionKey` is
#'     Playwright's top-level site (`"https://example.com"`) or CDP's key
#'     object (a list with `topLevelSite` and `hasCrossSiteAncestor`, or a row
#'     of the nested data frame `jsonlite::fromJSON()` makes of those).
#'     Cookies with a cross-site ancestor (`hasCrossSiteAncestor` or
#'     Playwright's `_crHasCrossSiteAncestor`) or with
#'     `partitionKeyOpaque = TRUE` are skipped: browsers send those only in
#'     frames below another site. Returns the skipped cookies invisibly,
#'     as a data frame with `index` (their row or element in `cookies`),
#'     `name` and `reason`, with no rows when all were imported. A cookie
#'     whose `expires` is in the past deletes the stored cookie with the same
#'     `name`, `domain` and `path` instead, as in browsers; it is not reported
#'     as skipped. A field of the wrong type (e.g. a non-numeric `expires`) is
#'     an error.}
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
#'   \item{`blocked_by`}{The bot protection that answered instead of the page
#'     (`"cloudflare"`, `"akamai"`, `"datadome"`, `"perimeterx"`, `"aws-waf"`,
#'     `"imperva"`, `"kasada"`, `"baleen"`, `"google"`, `"amazon"`,
#'     `"javascript"`, `"block-page"` or `"consent"`), or `NULL` for the page
#'     itself. A plain error status gives `NULL`.}
#' }
#'
#' @section Errors and interrupts:
#' Failures raise conditions of class `c("koon_<code>", "koon_error",
#' "error", "condition")`, where `<code>` is the lower-case error code, which
#' is also in the condition's `code` field: `"TIMEOUT"`, `"DNS_ERROR"`,
#' `"CONNECTION_FAILED"`, `"TLS_ERROR"`, `"PROXY_ERROR"`, `"INVALID_URL"`,
#' `"TOO_MANY_REDIRECTS"`, `"INVALID_ARGUMENT"`, `"INVALID_COOKIE"`,
#' `"JSON_ERROR"`, ... A request's transport failure has a `phase` field too:
#' `"connect"` (nothing was sent, so sending it again cannot repeat it),
#' `"request"` (no response head yet) or `"body"`; other errors have none
#' (`NULL`). An error raised by a callback fails the request and is
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
  stop(koon_error(err$code, err$message, err$phase))
}

koon_error <- function(code, message, phase = NULL) {
  structure(
    class = c(paste0("koon_", tolower(code)), "koon_error", "error", "condition"),
    list(message = sprintf("[%s] %s", code, message), call = NULL, code = code, phase = phase)
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
  for (class in list(Koon, KoonStream, KoonWebSocket, KoonProxy)) {
    for (name in names(class)) {
      method <- class[[name]]
      body(method) <- call("koon_unwrap", body(method))
      class[[name]] <- method
    }
  }
})

# The functions that take options pass them to Rust as one named list.
# BEGIN GENERATED functions (crates/core/tests/generated.rs)
Koon$new <- function(
  browser = "chrome",
  profile_json = NULL,
  proxy = NULL,
  proxies = NULL,
  timeout = NULL,
  headers = NULL,
  local_address = NULL,
  on_request = NULL,
  on_response = NULL,
  on_redirect = NULL,
  retries = NULL,
  locale = NULL,
  proxy_headers = NULL,
  ip_version = NULL,
  follow_redirects = NULL,
  max_redirects = NULL,
  cookie_jar = NULL,
  session_resumption = NULL,
  ignore_tls_errors = NULL,
  proxy_ca_certs = NULL,
  ignore_proxy_tls_errors = NULL,
  doh = NULL,
  resolve = NULL,
  max_response_body = NULL,
  server_padding = NULL
) {
  koon_unwrap(.Call(
    wrap__Koon__new,
    browser,
    list(
      profile_json = profile_json,
      proxy = proxy,
      proxies = proxies,
      timeout = timeout,
      headers = headers,
      local_address = local_address,
      on_request = on_request,
      on_response = on_response,
      on_redirect = on_redirect,
      retries = retries,
      locale = locale,
      proxy_headers = proxy_headers,
      ip_version = ip_version,
      follow_redirects = follow_redirects,
      max_redirects = max_redirects,
      cookie_jar = cookie_jar,
      session_resumption = session_resumption,
      ignore_tls_errors = ignore_tls_errors,
      proxy_ca_certs = proxy_ca_certs,
      ignore_proxy_tls_errors = ignore_proxy_tls_errors,
      doh = doh,
      resolve = resolve,
      max_response_body = max_response_body,
      server_padding = server_padding
    )
  ))
}

Koon$request <- function(
  method,
  url,
  body = NULL,
  headers = NULL,
  timeout = NULL,
  proxy = NULL,
  follow_redirects = NULL,
  max_redirects = NULL,
  on_request = NULL,
  on_response = NULL,
  on_redirect = NULL
) {
  koon_unwrap(.Call(
    wrap__Koon__request,
    self,
    method,
    url,
    body,
    list(
      headers = headers,
      timeout = timeout,
      proxy = proxy,
      follow_redirects = follow_redirects,
      max_redirects = max_redirects,
      on_request = on_request,
      on_response = on_response,
      on_redirect = on_redirect
    )
  ))
}

Koon$post_multipart <- function(
  url,
  fields,
  headers = NULL,
  timeout = NULL,
  proxy = NULL,
  follow_redirects = NULL,
  max_redirects = NULL,
  on_request = NULL,
  on_response = NULL,
  on_redirect = NULL
) {
  koon_unwrap(.Call(
    wrap__Koon__post_multipart,
    self,
    url,
    fields,
    list(
      headers = headers,
      timeout = timeout,
      proxy = proxy,
      follow_redirects = follow_redirects,
      max_redirects = max_redirects,
      on_request = on_request,
      on_response = on_response,
      on_redirect = on_redirect
    )
  ))
}

Koon$request_streaming <- function(
  method,
  url,
  body = NULL,
  headers = NULL,
  timeout = NULL,
  proxy = NULL,
  follow_redirects = NULL,
  max_redirects = NULL,
  on_request = NULL,
  on_response = NULL,
  on_redirect = NULL,
  decode = NULL
) {
  koon_unwrap(.Call(
    wrap__Koon__request_streaming,
    self,
    method,
    url,
    body,
    list(
      headers = headers,
      timeout = timeout,
      proxy = proxy,
      follow_redirects = follow_redirects,
      max_redirects = max_redirects,
      on_request = on_request,
      on_response = on_response,
      on_redirect = on_redirect,
      decode = decode
    )
  ))
}

KoonProxy$start <- function(
  browser = NULL,
  profile_json = NULL,
  proxy = NULL,
  proxies = NULL,
  ignore_tls_errors = NULL,
  proxy_ca_certs = NULL,
  ignore_proxy_tls_errors = NULL,
  session_resumption = NULL,
  doh = NULL,
  local_address = NULL,
  retries = NULL,
  locale = NULL,
  proxy_headers = NULL,
  ip_version = NULL,
  resolve = NULL,
  max_response_body = NULL,
  server_padding = NULL,
  listen_addr = NULL,
  header_mode = NULL,
  ca_dir = NULL,
  timeout = NULL,
  allow_non_loopback = NULL,
  auth = NULL,
  max_connections = NULL
) {
  koon_unwrap(.Call(
    wrap__KoonProxy__start,
    list(
      browser = browser,
      profile_json = profile_json,
      proxy = proxy,
      proxies = proxies,
      ignore_tls_errors = ignore_tls_errors,
      proxy_ca_certs = proxy_ca_certs,
      ignore_proxy_tls_errors = ignore_proxy_tls_errors,
      session_resumption = session_resumption,
      doh = doh,
      local_address = local_address,
      retries = retries,
      locale = locale,
      proxy_headers = proxy_headers,
      ip_version = ip_version,
      resolve = resolve,
      max_response_body = max_response_body,
      server_padding = server_padding,
      listen_addr = listen_addr,
      header_mode = header_mode,
      ca_dir = ca_dir,
      timeout = timeout,
      allow_non_loopback = allow_non_loopback,
      auth = auth,
      max_connections = max_connections
    )
  ))
}
# END GENERATED functions

# BEGIN GENERATED proxy docs (crates/core/tests/generated.rs)
#' @section Start arguments:
#' `KoonProxy$start()` takes the following arguments. Any left `NULL` keeps
#' its default.
#' \describe{
#'   \item{`browser`}{Browser profile to impersonate, such as `chrome`,
#'     `firefox154`, `chrome-macos`, `safari-mobile266` or `okhttp5`. Without a
#'     version it is the newest one, without an OS desktop browsers impersonate
#'     Windows and Safari macOS. Default `"chrome"`.}
#'   \item{`profile_json`}{A custom browser profile as JSON, as
#'     `$export_profile()` returns it. Overrides `browser`. Malformed JSON fails
#'     with `koon_json_error`.}
#'   \item{`proxy`}{Proxy URL: `http://`, `https://`, `socks5://` or
#'     `socks5h://` (the same: the proxy resolves the host name), optionally
#'     with `user:pass@`. An `https://` proxy is reached over TLS and its
#'     certificate is verified (see `proxy_ca_certs`).}
#'   \item{`proxies`}{Proxy URLs to rotate through: each request, and each
#'     retry, takes the next one. Takes priority over `proxy`.}
#'   \item{`ignore_tls_errors`}{Skip certificate verification of origins.
#'     `https://` proxies are still verified (see `ignore_proxy_tls_errors`).
#'     Default `FALSE`.}
#'   \item{`proxy_ca_certs`}{Certificates (PEM, one or more) trusted for the
#'     TLS connection to `https://` proxies in addition to the built-in roots,
#'     like curl's `--proxy-cacert`: for a proxy with a self-signed certificate
#'     or one from a private CA. Origins are still verified against the built-in
#'     roots only. Invalid PEM fails with `koon_invalid_argument`. PEM text,
#'     e.g. `readLines("proxy-ca.pem")`, or a raw vector.}
#'   \item{`ignore_proxy_tls_errors`}{Skip certificate verification of
#'     `https://` proxies, like curl's `--proxy-insecure`. The connection stays
#'     encrypted, but anyone on the way to the proxy can pose as it and read the
#'     proxy credentials and the hosts requested. Origins are still verified.
#'     Prefer `proxy_ca_certs`. Default `FALSE`.}
#'   \item{`session_resumption`}{Resume TLS sessions. Default `TRUE`.}
#'   \item{`doh`}{DNS-over-HTTPS provider, any case: `cloudflare` or
#'     `google`.}
#'   \item{`local_address`}{Local IP address outgoing connections are bound
#'     to.}
#'   \item{`retries`}{Automatic retries on transport errors. With `proxies`,
#'     each retry takes the next proxy. A request that may already have reached
#'     the server is retried only for idempotent methods. Default 0.}
#'   \item{`locale`}{The user's language, such as `de-AT`, to match the
#'     proxy's country. The Accept-Language header becomes what the profile's
#'     browser sends for it: Chrome the list of the UI language it picks
#'     (`de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7`), Safari `de-DE,de;q=0.9`.}
#'   \item{`proxy_headers`}{Headers of the HTTP CONNECT request to the proxy,
#'     in order: session IDs, geo-targeting, authentication. A named character
#'     vector or a named list of single strings, e.g. `c("Accept-Language" =
#'     "de-DE")`.}
#'   \item{`ip_version`}{Resolve hosts to IPv4 (`4`) or IPv6 (`6`) only, e.g.
#'     for a proxy that speaks IPv4 alone. `v4`, `ipv6` and the like work too.}
#'   \item{`resolve`}{Entries in curl's `--resolve` format,
#'     `host:port:address[,address...]` (IPv6 in brackets): requests to that
#'     host and port connect to the address instead of resolving the host. The
#'     TLS server name, Host header and cookies stay the host's. An invalid
#'     entry fails with `koon_invalid_argument`.}
#'   \item{`max_response_body`}{Maximum response body size in bytes,
#'     decompressed: past it, a response fails with `koon_body_error` instead of
#'     growing the buffer further, also when a compressed body decodes past it.
#'     Reading a streaming response chunk by chunk without decoding it is not
#'     capped. `0` disables it. Default 100 MiB.}
#'   \item{`server_padding`}{Pins Chrome 151+'s `PqcBandwidthExperiment`
#'     server-padding field trial group instead of drawing one when the client
#'     is built: `none` (not in the study) or the bytes of padding the group
#'     asks for (e.g. `6000`). The study ended on 2026-10-30, so a client no
#'     longer draws one. No effect on a profile without the trial.}
#'   \item{`listen_addr`}{Address to listen on; port `0` picks a free one.
#'     Default `"127.0.0.1:0"`.}
#'   \item{`header_mode`}{How the headers of the proxy's clients are sent on,
#'     any case: `impersonate` sends them as the profile's browser does, with
#'     its identity headers in place of the client's (its Accept-Language from
#'     `locale`), `passthrough` as they came, only TLS and HTTP/2 fingerprinted.
#'     Default `"impersonate"`.}
#'   \item{`ca_dir`}{Directory of the proxy's CA certificate. Default
#'     `"~/.koon/ca"`.}
#'   \item{`timeout`}{Timeout in seconds, fractions allowed, of a forwarded
#'     request's response head and of each wait for its body. `0` means no
#'     timeout. Default 30.}
#'   \item{`allow_non_loopback`}{Allow `listen_addr` to be a non-loopback
#'     address. The proxy has no transport encryption of its own between it and
#'     its clients, so on a reachable interface it is an open relay for anyone
#'     who can reach the port, unless `auth` is set too. Default `FALSE`.}
#'   \item{`auth`}{`Proxy-Authorization: Basic` credentials every client of
#'     the proxy must send. `c(user, password)`.}
#'   \item{`max_connections`}{Connections accepted at once; further ones wait
#'     for a slot to free up. Default 512.}
#' }
#' @name KoonProxy
#' @rdname KoonProxy
NULL
# END GENERATED proxy docs

#' @title Local MITM Proxy
#'
#' @description
#' A local proxy that forwards the requests of other programs (a browser
#' automation tool, a script in another language) with koon's fingerprint.
#' Start one with `KoonProxy$start(...)`; it runs until `$shutdown()` or the
#' end of the R session.
#'
#' The forwarded requests connect as those of a `Koon` client do; the proxy
#' follows no redirects and keeps no cookies, the proxied client does both
#' itself. A client reaches `https://` sites through it by trusting its CA
#' certificate.
#'
#' @section Methods:
#' \describe{
#'   \item{`$url()`, `$port()`}{The proxy's URL (`"http://127.0.0.1:PORT"`)
#'     and port.}
#'   \item{`$ca_cert_path()`, `$ca_cert_pem()`}{Its CA certificate: the file,
#'     and the PEM as a raw vector.}
#'   \item{`$shutdown()`}{Stop accepting and close every open connection.
#'     Calling it again does nothing.}
#' }
#'
#' @examples
#' \dontrun{
#' proxy <- KoonProxy$start(browser = "firefox")
#' proxy$url()
#' proxy$shutdown()
#' }
#' @name KoonProxy
#' @export KoonProxy
NULL

# BEGIN GENERATED koon_verify (crates/core/tests/generated.rs)
#' Check koon's fingerprint against the real browser
#'
#' Connects to tls.browserleaks.com (tls.peet.ws as fallback) and, where a QUIC
#' reference exists, over HTTP/3 to quic.browserleaks.com, and compares JA4,
#' JA3N, JA3, the Akamai HTTP/2 fingerprint and the QUIC JA4 with the values
#' captured from the real browser. Through a proxy, HTTP/3 is not used.
#'
#' @param browser A built-in profile name, e.g. `"chrome"` or
#'   `"firefox154-windows"`.
#' @param proxy Proxy URL: `http://`, `https://`, `socks5://` or `socks5h://`
#'   (the same: the proxy resolves the host name), optionally with `user:pass@`.
#'   An `https://` proxy is reached over TLS and its certificate is verified
#'   (see `proxy_ca_certs`).
#' @param proxies Proxy URLs to rotate through: each request, and each retry,
#'   takes the next one. Takes priority over `proxy`.
#' @param timeout Timeout of a whole request in seconds, fractions allowed:
#'   connecting, redirects and the body. `0` means no timeout. Default 30.
#' @param ignore_tls_errors Skip certificate verification of origins.
#'   `https://` proxies are still verified (see `ignore_proxy_tls_errors`).
#'   Default `FALSE`.
#' @param proxy_ca_certs Certificates (PEM, one or more) trusted for the TLS
#'   connection to `https://` proxies in addition to the built-in roots, like
#'   curl's `--proxy-cacert`: for a proxy with a self-signed certificate or one
#'   from a private CA. Origins are still verified against the built-in roots
#'   only. Invalid PEM fails with `koon_invalid_argument`. PEM text, e.g.
#'   `readLines("proxy-ca.pem")`, or a raw vector.
#' @param ignore_proxy_tls_errors Skip certificate verification of `https://`
#'   proxies, like curl's `--proxy-insecure`. The connection stays encrypted,
#'   but anyone on the way to the proxy can pose as it and read the proxy
#'   credentials and the hosts requested. Origins are still verified. Prefer
#'   `proxy_ca_certs`. Default `FALSE`.
#' @param session_resumption Resume TLS sessions. Default `TRUE`.
#' @param doh DNS-over-HTTPS provider, any case: `cloudflare` or `google`.
#' @param local_address Local IP address outgoing connections are bound to.
#' @param retries Automatic retries on transport errors. With `proxies`, each
#'   retry takes the next proxy. A request that may already have reached the
#'   server is retried only for idempotent methods. Default 0.
#' @param locale The user's language, such as `de-AT`, to match the proxy's
#'   country. The Accept-Language header becomes what the profile's browser
#'   sends for it: Chrome the list of the UI language it picks
#'   (`de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7`), Safari `de-DE,de;q=0.9`.
#' @param proxy_headers Headers of the HTTP CONNECT request to the proxy, in
#'   order: session IDs, geo-targeting, authentication. A named character vector
#'   or a named list of single strings, e.g. `c("Accept-Language" = "de-DE")`.
#' @param ip_version Resolve hosts to IPv4 (`4`) or IPv6 (`6`) only, e.g. for
#'   a proxy that speaks IPv4 alone. `v4`, `ipv6` and the like work too.
#' @param resolve Entries in curl's `--resolve` format,
#'   `host:port:address[,address...]` (IPv6 in brackets): requests to that host
#'   and port connect to the address instead of resolving the host. The TLS
#'   server name, Host header and cookies stay the host's. An invalid entry
#'   fails with `koon_invalid_argument`.
#' @param max_response_body Maximum response body size in bytes, decompressed:
#'   past it, a response fails with `koon_body_error` instead of growing the
#'   buffer further, also when a compressed body decodes past it. Reading a
#'   streaming response chunk by chunk without decoding it is not capped. `0`
#'   disables it. Default 100 MiB.
#' @param server_padding Pins Chrome 151+'s `PqcBandwidthExperiment`
#'   server-padding field trial group instead of drawing one when the client is
#'   built: `none` (not in the study) or the bytes of padding the group asks for
#'   (e.g. `6000`). The study ended on 2026-10-30, so a client no longer draws
#'   one. No effect on a profile without the trial.
#' @return The report as a named list: `profile`, `koon_version`, `outcome`
#'   (`"match"`, `"mismatch"`, `"no_reference"` or `"unreachable"`),
#'   `references`, `service`, `http3_service`, `fields` (one list per field
#'   with its `status`) and `errors` (the services that failed). An unknown
#'   profile is a `koon_invalid_argument` error; unreachable services are part
#'   of the report.
#' @export
koon_verify <- function(
  browser = "chrome",
  proxy = NULL,
  proxies = NULL,
  timeout = NULL,
  ignore_tls_errors = NULL,
  proxy_ca_certs = NULL,
  ignore_proxy_tls_errors = NULL,
  session_resumption = NULL,
  doh = NULL,
  local_address = NULL,
  retries = NULL,
  locale = NULL,
  proxy_headers = NULL,
  ip_version = NULL,
  resolve = NULL,
  max_response_body = NULL,
  server_padding = NULL
) {
  koon_unwrap(.Call(
    wrap__verify_report,
    browser,
    list(
      proxy = proxy,
      proxies = proxies,
      timeout = timeout,
      ignore_tls_errors = ignore_tls_errors,
      proxy_ca_certs = proxy_ca_certs,
      ignore_proxy_tls_errors = ignore_proxy_tls_errors,
      session_resumption = session_resumption,
      doh = doh,
      local_address = local_address,
      retries = retries,
      locale = locale,
      proxy_headers = proxy_headers,
      ip_version = ip_version,
      resolve = resolve,
      max_response_body = max_response_body,
      server_padding = server_padding
    )
  ))
}
# END GENERATED koon_verify

#' Which bot protection answered a response
#'
#' The `blocked_by` of a response, for a response whose body the caller
#' reads: a streaming response (the chunks read, or `$stream$collect()`).
#' `body` is the decoded body or its first 400 KB, which are all that is
#' looked at; with an empty one only the headers and the URL count.
#'
#' @param response A response list: its `status`, `headers` and `url` are
#'   read.
#' @param body The body: a raw vector or a single string.
#' @return The name of the bot protection (`"cloudflare"`, `"akamai"`, ...)
#'   or `NULL`.
#' @export
koon_blocked_by <- function(response, body) {
  headers <- response$headers
  if (is.data.frame(headers)) {
    headers <- structure(as.character(headers$value), names = as.character(headers$name))
  }
  koon_unwrap(blocked_by_parts(response$status, headers, body, response$url))
}

# $set_cookies() returns the skipped cookies, usually none: invisibly.
body(Koon$set_cookies) <- call("invisible", body(Koon$set_cookies))

# HTTP verbs on top of $request(); `...` takes its options.
Koon$get <- function(url, ...) self$request("GET", url, NULL, ...)
Koon$head <- function(url, ...) self$request("HEAD", url, NULL, ...)
Koon$delete <- function(url, ...) self$request("DELETE", url, NULL, ...)
Koon$post <- function(url, body = NULL, ...) self$request("POST", url, body, ...)
Koon$put <- function(url, body = NULL, ...) self$request("PUT", url, body, ...)
Koon$patch <- function(url, body = NULL, ...) self$request("PATCH", url, body, ...)
