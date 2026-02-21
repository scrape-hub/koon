#' @title Browser-Impersonating HTTP Client
#'
#' @description
#' An HTTP client that impersonates real browser TLS, HTTP/2, and HTTP/3
#' fingerprints. Supports Chrome, Firefox, Safari, Edge, and Opera profiles.
#'
#' @details
#' All requests are synchronous (blocking). Cookies persist across requests.
#' The response is an R list with components:
#' \describe{
#'   \item{status}{Integer HTTP status code (e.g. 200)}
#'   \item{version}{Character HTTP version (e.g. "HTTP/2.0")}
#'   \item{url}{Character final URL after redirects}
#'   \item{body}{Raw vector with response body bytes}
#'   \item{text}{Character response body as UTF-8 string}
#'   \item{headers}{Data frame with \code{name} and \code{value} columns}
#' }
#'
#' @examples
#' \dontrun{
#' library(koon)
#'
#' # Create client with Chrome 145 profile
#' client <- Koon$new("chrome145")
#'
#' # GET request
#' resp <- client$get("https://httpbin.org/get")
#' resp$status   # 200
#' resp$text     # response body as string
#'
#' # POST request with body
#' resp <- client$post("https://httpbin.org/post", charToRaw("hello"))
#'
#' # Parse JSON response
#' data <- jsonlite::fromJSON(resp$text)
#'
#' # Cookies persist across requests
#' client$get("https://httpbin.org/cookies/set/name/value")
#' resp <- client$get("https://httpbin.org/cookies")
#'
#' # Session save/load
#' json <- client$save_session()
#' client2 <- Koon$new("chrome145")
#' client2$load_session(json)
#'
#' # List available browsers
#' koon_browsers()
#' }
#'
#' @name Koon
NULL
