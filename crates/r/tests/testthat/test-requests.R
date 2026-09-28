test_that("GET returns a complete response", {
  base <- test_server_url()
  client <- Koon$new()
  resp <- client$get(paste0(base, "/get"))
  expect_identical(resp$status, 200L)
  expect_identical(resp$status_code, 200L)
  expect_true(resp$ok)
  expect_identical(resp$version, "HTTP/1.1")
  expect_identical(resp$url, paste0(base, "/get"))
  expect_identical(resp$content_type, "application/json")
  expect_s3_class(resp$headers, "data.frame")
  expect_named(resp$headers, c("name", "value"))
  expect_s3_class(resp$request_headers, "data.frame")
  expect_identical(json(resp)$method, "GET")
  expect_identical(resp$remote_address, "127.0.0.1")
  expect_type(resp$body, "raw")
  expect_true(resp$bytes_received > 0)
})

test_that("headers keep their order and verbs work", {
  base <- test_server_url()
  client <- Koon$new(headers = c("X-Client-B" = "b", "X-Client-A" = "a"))
  resp <- client$get(paste0(base, "/get"), headers = c("X-Req-Z" = "z", "X-Req-Y" = "y"))
  names <- header_names(resp)
  expect_lt(match("X-Client-B", names), match("X-Client-A", names))
  expect_lt(match("X-Req-Z", names), match("X-Req-Y", names))
  sent <- resp$request_headers$name
  expect_lt(match("x-req-z", tolower(sent)), match("x-req-y", tolower(sent)))

  # Positional headers after the URL still work (old signature).
  resp <- client$get(paste0(base, "/get"), c("X-Positional" = "1"))
  expect_true("X-Positional" %in% header_names(resp))

  expect_identical(json(client$post(paste0(base, "/post"), "hello"))$body, "hello")
  expect_identical(json(client$post(paste0(base, "/post"), charToRaw("raw")))$body, "raw")
  expect_identical(json(client$put(paste0(base, "/echo"), "p"))$method, "PUT")
  expect_identical(json(client$patch(paste0(base, "/echo"), "p"))$method, "PATCH")
  expect_identical(json(client$delete(paste0(base, "/echo")))$method, "DELETE")
  expect_identical(json(client$request("options", paste0(base, "/echo")))$method, "OPTIONS")
  head <- client$head(paste0(base, "/get"))
  expect_identical(head$status, 200L)
  expect_identical(length(head$body), 0L)
})

test_that("headers may be a named list, and keep their order", {
  base <- test_server_url()
  client <- Koon$new(headers = list("X-Client-B" = "b", "X-Client-A" = "a"))
  resp <- client$get(paste0(base, "/get"), headers = list("X-Req-Z" = "z", "X-Req-Y" = "y"))
  names <- header_names(resp)
  expect_lt(match("X-Client-B", names), match("X-Client-A", names))
  expect_lt(match("X-Req-Z", names), match("X-Req-Y", names))
  expect_identical(json(client$get(paste0(base, "/get"), headers = list()))$method, "GET")
})

test_that("binary bodies have no text, text bodies are decoded", {
  base <- test_server_url()
  client <- Koon$new()
  png <- client$get(paste0(base, "/png"))
  expect_null(png$text)
  expect_identical(png$body[1:4], as.raw(c(0x89, 0x50, 0x4e, 0x47)))
  expect_null(client$get(paste0(base, "/nul-text"))$text)
  expect_null(client$get(paste0(base, "/binary-noct"))$text)
  expect_identical(client$get(paste0(base, "/latin1"))$text, "Grüße aus Köln")
  expect_identical(client$get(paste0(base, "/sjis"))$text, "こんにちは")
})

test_that("resolve connects to the given address", {
  port <- test_server_port()
  client <- Koon$new(resolve = sprintf("koon.test:%s:127.0.0.1", port))
  resp <- client$get(sprintf("http://koon.test:%s/get", port))
  expect_identical(resp$status, 200L)
  hosts <- Filter(function(h) h[[1]] == "Host", json(resp)$headers)
  expect_identical(hosts[[1]][[2]], paste0("koon.test:", port))
})

test_that("max_response_body caps the response", {
  base <- test_server_url()
  body <- strrep("x", 2000)
  err <- expect_koon_error(
    Koon$new(max_response_body = 100)$post(paste0(base, "/post"), body),
    "BODY_ERROR"
  )
  expect_match(conditionMessage(err), "100 bytes")
  expect_identical(Koon$new()$post(paste0(base, "/post"), body)$status, 200L)
  expect_identical(Koon$new(max_response_body = 0)$post(paste0(base, "/post"), body)$status, 200L)
})

test_that("close() does not wait and keeps the client usable", {
  base <- test_server_url()
  client <- Koon$new()
  expect_identical(client$get(paste0(base, "/get"))$status, 200L)
  expect_null(client$close())
  expect_identical(client$get(paste0(base, "/get"))$status, 200L)
  expect_null(client$shutdown())
})
