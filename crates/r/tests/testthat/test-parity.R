test_that("post_multipart sends text fields and files", {
  base <- test_server_url()
  client <- Koon$new()
  resp <- client$post_multipart(paste0(base, "/echo"), list(
    list(name = "greeting", value = "hello"),
    list(
      name = "upload", file_data = as.raw(c(0x61, 0x62)), filename = "a.bin",
      content_type = "application/x-test"
    )
  ))
  expect_identical(resp$status, 200L)
  expect_match(resp$text, 'name=\\"greeting\\"', fixed = TRUE)
  expect_match(resp$text, 'filename=\\"a.bin\\"', fixed = TRUE)
  expect_match(resp$text, "application/x-test")
  sent <- resp$request_headers
  expect_match(sent$value[tolower(sent$name) == "content-type"], "^multipart/form-data")
  expect_koon_error(client$post_multipart(paste0(base, "/echo"), list(list(name = "x"))), "INVALID_ARGUMENT")
  expect_koon_error(
    client$post_multipart(paste0(base, "/echo"), list(list(name = "x", value = "a", file_data = raw(1)))),
    "INVALID_ARGUMENT"
  )
})

test_that("request_streaming reads the body chunk by chunk, decoded", {
  base <- test_server_url()
  client <- Koon$new()
  resp <- client$request_streaming("GET", paste0(base, "/gzip"))
  expect_identical(resp$status, 200L)
  chunks <- list()
  while (!is.null(chunk <- resp$stream$next_chunk())) chunks[[length(chunks) + 1]] <- chunk
  expect_identical(rawToChar(do.call(c, chunks)), "compressed text")
  raw <- client$request_streaming("GET", paste0(base, "/gzip"), decode = FALSE)$stream$collect()
  expect_identical(raw[1:2], as.raw(c(0x1f, 0x8b)))
  resp <- client$request_streaming("GET", paste0(base, "/png"))
  resp$stream$cancel()
  expect_koon_error(resp$stream$next_chunk(), "BODY_ERROR")
  err <- expect_koon_error(
    Koon$new(timeout = 0.5)$request_streaming("GET", paste0(base, "/slow?s=3")),
    "TIMEOUT"
  )
  expect_identical(err$phase, "request")
})

test_that("a WebSocket sends and receives text and binary messages", {
  base <- test_server_url()
  ws <- Koon$new()$websocket(sub("^http", "ws", paste0(base, "/ws")))
  ws$send("hello")
  expect_identical(ws$receive(), list(type = "text", data = "hello"))
  ws$send(as.raw(c(0, 1, 255)))
  expect_identical(ws$receive(), list(type = "binary", data = as.raw(c(0, 1, 255))))
  expect_koon_error(ws$send(1), "INVALID_ARGUMENT")
  expect_koon_error(ws$close(70000), "INVALID_ARGUMENT")
  ws$close()
})

test_that("sessions are saved to and loaded from a file", {
  base <- test_server_url()
  client <- Koon$new()
  client$get(paste0(base, "/set-cookie"))
  path <- tempfile(fileext = ".json")
  on.exit(unlink(path))
  client$save_session_to_file(path)
  other <- Koon$new()
  other$load_session_from_file(path)
  expect_match(other$get(paste0(base, "/cookies"))$text, "session=abc123")
  expect_koon_error(other$load_session_from_file(file.path(tempdir(), "missing", "s.json")), "IO_ERROR")
})

test_that("a KoonProxy forwards requests until it is shut down", {
  base <- test_server_url()
  proxy <- KoonProxy$start(ca_dir = file.path(tempdir(), "koon-ca"))
  on.exit(proxy$shutdown())
  expect_match(proxy$url(), "^http://127\\.0\\.0\\.1:[0-9]+$")
  expect_identical(proxy$url(), paste0("http://127.0.0.1:", proxy$port()))
  expect_true(file.exists(proxy$ca_cert_path()))
  expect_match(rawToChar(proxy$ca_cert_pem()), "BEGIN CERTIFICATE")
  resp <- Koon$new(proxy = proxy$url())$get(paste0(base, "/get"))
  expect_identical(resp$status, 200L)
  proxy$shutdown()
  proxy$shutdown()
  expect_koon_error(KoonProxy$start(header_mode = "mirror"), "INVALID_ARGUMENT")
})

test_that("koon_verify rejects an unknown profile", {
  expect_koon_error(koon_verify("netscape4"), "INVALID_ARGUMENT")
})

test_that("koon_blocked_by reads a response and a body", {
  challenge <- list(
    status = 403L,
    headers = data.frame(name = "cf-mitigated", value = "challenge"),
    url = "https://example.com/"
  )
  expect_identical(koon_blocked_by(challenge, raw(0)), "cloudflare")
  page <- list(
    status = 200L,
    headers = data.frame(name = "content-type", value = "text/html"),
    url = "https://example.com/"
  )
  expect_null(koon_blocked_by(page, "<html><body>hello</body></html>"))
})
