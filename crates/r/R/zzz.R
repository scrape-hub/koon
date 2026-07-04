#' @useDynLib koon, .registration = TRUE
NULL

.onLoad <- function(libname, pkgname) {
  # Replace extendr-generated functions with versions that have default values.
  # extendr doesn't generate defaults for Nullable<T> params.
  # The functions reference `self` (injected by $.Koon) and wrap__* symbols
  # (resolved from package DLL via useDynLib).
  # Signatures must stay in sync with the #[extendr] methods in src/rust/src/lib.rs.
  Koon$new <- function(browser = "chrome", profile_json = NULL, proxy = NULL,
                        proxies = NULL, timeout = NULL, randomize = NULL,
                        headers = NULL, local_address = NULL, on_request = NULL,
                        on_response = NULL, on_redirect = NULL,
                        retries = NULL, locale = NULL, proxy_headers = NULL,
                        ip_version = NULL, follow_redirects = NULL,
                        max_redirects = NULL, cookie_jar = NULL,
                        session_resumption = NULL, ignore_tls_errors = NULL,
                        doh = NULL)
    .Call(wrap__Koon__new, browser, profile_json, proxy, proxies, timeout,
          randomize, headers, local_address, on_request, on_response,
          on_redirect, retries, locale, proxy_headers, ip_version,
          follow_redirects, max_redirects, cookie_jar, session_resumption,
          ignore_tls_errors, doh)

  Koon$get <- function(url, headers = NULL, timeout = NULL) .Call(wrap__Koon__get, self, url, headers, timeout)
  Koon$post <- function(url, body = NULL, headers = NULL, timeout = NULL) .Call(wrap__Koon__post, self, url, body, headers, timeout)
  Koon$put <- function(url, body = NULL, headers = NULL, timeout = NULL) .Call(wrap__Koon__put, self, url, body, headers, timeout)
  Koon$delete <- function(url, headers = NULL, timeout = NULL) .Call(wrap__Koon__delete, self, url, headers, timeout)
  Koon$patch <- function(url, body = NULL, headers = NULL, timeout = NULL) .Call(wrap__Koon__patch, self, url, body, headers, timeout)
  Koon$head <- function(url, headers = NULL, timeout = NULL) .Call(wrap__Koon__head, self, url, headers, timeout)
  Koon$request <- function(method, url, body = NULL, headers = NULL, timeout = NULL) .Call(wrap__Koon__request, self, method, url, body, headers, timeout)
}
