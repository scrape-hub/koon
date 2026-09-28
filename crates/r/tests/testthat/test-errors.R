test_that("failures are classed conditions with a code", {
  base <- test_server_url()
  client <- Koon$new(timeout = 0.5)
  err <- expect_koon_error(client$get(paste0(base, "/slow?s=3")), "TIMEOUT")
  expect_match(conditionMessage(err), "timed out")
  expect_koon_error(Koon$new(timeout = 10)$get("http://127.0.0.1:1/"), "CONNECTION_FAILED")
  expect_koon_error(client$get("notaurl"), "INVALID_URL")
  expect_koon_error(client$get(paste0(base, "/slow?s=3"), timeout = 0.3), "TIMEOUT")
  # tryCatch by class
  hit <- tryCatch(client$get(paste0(base, "/slow?s=3")), koon_timeout = function(e) "timeout")
  expect_identical(hit, "timeout")
  # timeout = 0 means no timeout
  expect_identical(Koon$new(timeout = 0)$get(paste0(base, "/slow?s=1"))$text, "slow done")
  expect_identical(client$get(paste0(base, "/slow?s=1"), timeout = 0)$text, "slow done")
  expect_koon_error(Koon$new(max_redirects = 1)$get(paste0(base, "/redirect/3")), "TOO_MANY_REDIRECTS")
})

test_that("bad client arguments are INVALID_ARGUMENT errors", {
  expect_koon_error(Koon$new("netscape4"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new("chrome999"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(timeout = -1), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(timeout = "5"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(headers = c("X-A: 1")), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(headers = list(A = 1)), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(headers = list(A = c("1", "2"))), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(headers = list("1")), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(headers = c(A = NA_character_)), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(on_request = "print"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(proxies = 1), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(proxies = c("http://a:1", NA)), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(ip_version = 5), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(doh = "quad9"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(max_redirects = -1), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(retries = 1.5), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(local_address = "nope"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(profile_json = "{"), "JSON_ERROR")
  expect_koon_error(Koon$new(resolve = "example.com:443"), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(resolve = 1), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(max_response_body = -1), "INVALID_ARGUMENT")
  expect_koon_error(Koon$new(server_padding = "bogus"), "INVALID_ARGUMENT")
  expect_s3_class(Koon$new(server_padding = "none"), "Koon")
  expect_s3_class(Koon$new(server_padding = "9000"), "Koon")
  expect_s3_class(Koon$new(ip_version = 4), "Koon")
  expect_s3_class(Koon$new(ip_version = "v6"), "Koon")
  expect_s3_class(Koon$new("chrome152-windows", doh = "Cloudflare"), "Koon")
})

test_that("bad request arguments are INVALID_ARGUMENT errors", {
  # Rejected before anything is sent: no server needed.
  client <- Koon$new()
  url <- "http://127.0.0.1:1/get"
  expect_koon_error(client$get(url, timeout = -1), "INVALID_ARGUMENT")
  expect_koon_error(client$get(url, headers = c("X-A: 1")), "INVALID_ARGUMENT")
  expect_koon_error(client$post(url, body = 1), "INVALID_ARGUMENT")
  expect_koon_error(client$post(url, body = c("a", "b")), "INVALID_ARGUMENT")
  expect_koon_error(client$request("GE T", url), "INVALID_ARGUMENT")
  expect_koon_error(client$get(url, max_redirects = -2), "INVALID_ARGUMENT")
  expect_koon_error(client$get(url, on_request = "print"), "INVALID_ARGUMENT")
  expect_error(client$get(url, timeoutt = 1), class = "simpleError")
})

test_that("an interrupt result raises a real R interrupt", {
  # The Rust side reports Ctrl-C as list(interrupt = TRUE); koon_unwrap()
  # must raise an interrupt condition, which tryCatch(error =) does not see.
  cond <- structure(class = c("extendr_error", "error", "condition"),
                    list(message = "extendr_err", value = list(interrupt = TRUE)))
  outcome <- tryCatch(
    tryCatch(koon:::koon_unwrap(cond), error = function(e) "error"),
    interrupt = function(i) "interrupt"
  )
  expect_identical(outcome, "interrupt")
})
