test_that("cookies round-trip in the Playwright shape", {
  base <- test_server_url()
  client <- Koon$new()
  client$get(paste0(base, "/set-cookie"))
  cookies <- client$cookies()
  expect_s3_class(cookies, "data.frame")
  expect_named(cookies, c("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite", "hostOnly"))
  expect_setequal(cookies$name, c("session", "theme"))
  expect_true(cookies$httpOnly[cookies$name == "session"])
  expect_identical(cookies$expires[cookies$name == "session"], -1)
  expect_gt(cookies$expires[cookies$name == "theme"], as.numeric(Sys.time()))

  other <- Koon$new()
  expect_identical(nrow(other$set_cookies(cookies)), 0L)
  expect_setequal(other$cookies()$name, c("session", "theme"))
  expect_match(other$get(paste0(base, "/cookies"))$text, "session=abc123")

  # Playwright JSON via jsonlite, and a list of named lists
  via_json <- Koon$new()
  via_json$set_cookies(jsonlite::fromJSON(jsonlite::toJSON(cookies)))
  expect_setequal(via_json$cookies()$name, c("session", "theme"))
  listed <- Koon$new()
  listed$set_cookies(list(
    list(name = "a", value = "1", url = paste0(base, "/")),
    list(name = "b", value = "2", domain = "127.0.0.1", path = "/", httpOnly = TRUE, sameSite = "Strict")
  ))
  expect_match(listed$get(paste0(base, "/cookies"))$text, "a=1")
  expect_match(listed$get(paste0(base, "/cookies"))$text, "b=2")

  listed$clear_cookies()
  expect_identical(nrow(listed$cookies()), 0L)
})

test_that("set_cookies() reports the skipped cookies invisibly", {
  client <- Koon$new("chrome")
  # A list of named lists: one valid, one invalid value, one partitioned.
  visible <- withVisible(client$set_cookies(list(
    list(name = "ok", value = "1", domain = "example.com"),
    list(name = "bad", value = "a;b", domain = "example.com"),
    list(name = "chips", value = "1", domain = "example.com", partitionKey = "https://example.com")
  )))
  expect_false(visible$visible)
  skipped <- visible$value
  expect_s3_class(skipped, "data.frame")
  expect_named(skipped, c("index", "name", "reason"))
  expect_identical(skipped$index, c(2L, 3L))
  expect_identical(skipped$name, c("bad", "chips"))
  expect_match(skipped$reason[[2]], "partitioned")
  expect_identical(client$cookies()$name, "ok")

  # A data frame, as jsonlite::fromJSON() of Playwright's cookies() gives it.
  frame <- data.frame(
    name = c("a", "b"),
    value = c("1", "2"),
    domain = c("example.org", "com"),
    hostOnly = c(TRUE, FALSE)
  )
  skipped <- client$set_cookies(frame)
  expect_identical(skipped$index, 2L)
  expect_match(skipped$reason, "public suffix")
  expect_identical(nrow(client$set_cookies(client$cookies())), 0L)

  # Cookies the core cannot import are skipped and reported, not errors.
  expect_identical(client$set_cookies(list(list(name = "c", value = "3")))$name, "c")
  expect_identical(
    client$set_cookies(list(list(name = "c", value = "3", domain = "x.test", partitionKey = "https://x.test")))$name,
    "c"
  )
})

test_that("partitioned cookies are skipped, also as nested data frame columns", {
  # jsonlite makes a nested data frame of CDP's partition key objects.
  cdp <- jsonlite::fromJSON('[
    {"name": "kept", "value": "1", "domain": "x.test", "partitionKey": null},
    {"name": "keyed", "value": "2", "domain": "x.test",
     "partitionKey": {"topLevelSite": "https://x.test", "hasCrossSiteAncestor": false}},
    {"name": "opaque", "value": "3", "domain": "x.test", "partitionKeyOpaque": true},
    {"name": "also_kept", "value": "4", "domain": "x.test", "partitionKeyOpaque": false}
  ]')
  expect_true(is.data.frame(cdp$partitionKey))
  importer <- Koon$new()
  skipped <- importer$set_cookies(cdp)
  expect_identical(skipped$name, c("keyed", "opaque"))
  expect_identical(skipped$index, c(2L, 3L))
  expect_setequal(importer$cookies()$name, c("kept", "also_kept"))

  as_list <- Koon$new()
  skipped <- as_list$set_cookies(list(
    list(name = "a", value = "1", domain = "x.test", partitionKeyOpaque = TRUE),
    list(name = "b", value = "2", domain = "x.test", partitionKey = list(topLevelSite = "https://x.test"))
  ))
  expect_identical(skipped$name, c("a", "b"))
})

test_that("malformed cookie input is an error", {
  client <- Koon$new()
  expect_koon_error(client$set_cookies(list(list(value = "3", domain = "x.test"))), "INVALID_COOKIE")
  expect_koon_error(client$set_cookies(list(list(name = "c", value = 3, domain = "x.test"))), "INVALID_COOKIE")
  expect_koon_error(client$set_cookies("nope"), "INVALID_ARGUMENT")
  cookies <- data.frame(name = "a", value = "1", domain = "example.com")
  expect_koon_error(Koon$new(cookie_jar = FALSE)$set_cookies(cookies), "COOKIE_JAR_DISABLED")
  expect_identical(nrow(Koon$new()$cookies()), 0L)
})
