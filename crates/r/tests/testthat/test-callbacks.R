test_that("callbacks run per hop, promptly", {
  base <- test_server_url()
  seen <- character()
  client <- Koon$new(
    on_request = function(method, url) seen <<- c(seen, paste("req", method, url)),
    on_response = function(status, url, headers) {
      stopifnot(is.data.frame(headers))
      seen <<- c(seen, paste("resp", status))
    },
    on_redirect = function(status, url, headers) TRUE
  )
  resp <- client$get(paste0(base, "/redirect/2"))
  expect_identical(resp$text, "arrived")
  expect_identical(sum(startsWith(seen, "req GET")), 3L)
  expect_identical(seen[grepl("^resp", seen)], c("resp 302", "resp 302", "resp 200"))

  # on_redirect latency: 10 hops used to take >= 1 s (100 ms per hop).
  hooked <- Koon$new(on_redirect = function(status, url, headers) TRUE)
  hooked$get(paste0(base, "/redirect/1"))
  elapsed <- system.time(for (i in 1:3) hooked$get(paste0(base, "/redirect/10")))[["elapsed"]]
  expect_lt(elapsed / 3, 0.5)
})

test_that("on_redirect stops only on FALSE", {
  base <- test_server_url()
  stopper <- Koon$new(on_redirect = function(status, url, headers) FALSE)
  expect_identical(stopper$get(paste0(base, "/redirect/2"))$status, 302L)

  # NULL (a logging function), NA or anything else follows.
  for (answer in list(NULL, NA, "yes", 0, c(FALSE, FALSE))) {
    follows <- Koon$new(on_redirect = function(status, url, headers) answer)
    expect_identical(follows$get(paste0(base, "/redirect/2"))$text, "arrived")
  }
  logging <- Koon$new(on_redirect = function(status, url, headers) invisible(NULL))
  expect_identical(logging$get(paste0(base, "/redirect/1"))$status, 200L)
})

test_that("a failing callback fails the request with its own condition", {
  base <- test_server_url()
  failing <- Koon$new(on_redirect = function(status, url, headers) {
    stop(structure(class = c("my_error", "error", "condition"),
                   list(message = "no redirects today", call = NULL)))
  })
  err <- tryCatch(failing$get(paste0(base, "/redirect/2")), my_error = identity)
  expect_s3_class(err, "my_error")
  expect_identical(conditionMessage(err), "no redirects today")
  # The client stays usable, and the aborted request did not hang.
  expect_identical(failing$get(paste0(base, "/get"))$status, 200L)

  resp_fail <- Koon$new(on_response = function(...) stop("boom"))
  expect_error(resp_fail$get(paste0(base, "/get")), "boom")

  # The condition a callback raises is re-raised as it is.
  original <- structure(class = c("my_error", "error", "condition"),
                        list(message = "the original", call = NULL, extra = 42))
  err <- tryCatch(Koon$new(on_request = function(...) stop(original))$get(paste0(base, "/get")),
                  error = identity)
  expect_identical(err, original)

  # A failing on_request sends nothing.
  before <- as.integer(Koon$new()$get(paste0(base, "/hits"))$text)
  expect_error(Koon$new(on_request = function(...) stop("blocked"))$get(paste0(base, "/counted")),
               "blocked")
  after <- as.integer(Koon$new()$get(paste0(base, "/hits"))$text)
  expect_identical(after, before)
  # A failing on_redirect does not follow.
  expect_error(Koon$new(on_redirect = function(...) stop("stop"))$get(paste0(base, "/redirect/1")),
               "stop")
})

test_that("a callback may make a request with the same client", {
  base <- test_server_url()
  nested <- NULL
  reentrant <- Koon$new(on_redirect = function(status, url, headers) {
    nested <<- reentrant$get(paste0(base, "/get"))$status
    TRUE
  })
  expect_identical(reentrant$get(paste0(base, "/redirect/1"))$text, "arrived")
  expect_identical(nested, 200L)
})

test_that("per-request callbacks override the client's", {
  base <- test_server_url()
  seen <- character()
  client <- Koon$new(on_request = function(method, url) seen <<- c(seen, "client"))
  client$get(paste0(base, "/get"))
  client$get(paste0(base, "/get"), on_request = function(method, url) seen <<- c(seen, "request"))
  expect_identical(seen, c("client", "request"))

  plain <- Koon$new()
  hops <- 0L
  resp <- plain$get(paste0(base, "/redirect/2"),
                    on_response = function(status, url, headers) hops <<- hops + 1L,
                    on_redirect = function(status, url, headers) FALSE)
  expect_identical(resp$status, 302L)
  expect_identical(hops, 1L)
  expect_error(plain$get(paste0(base, "/get"), on_response = function(...) stop("per request")),
               "per request")
  # The client's own (none) apply again afterwards.
  expect_identical(plain$get(paste0(base, "/redirect/1"))$status, 200L)
})
