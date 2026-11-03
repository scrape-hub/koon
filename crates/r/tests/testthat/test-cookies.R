test_that("cookies round-trip in the Playwright shape", {
  base <- test_server_url()
  client <- Koon$new()
  client$get(paste0(base, "/set-cookie"))
  cookies <- client$cookies()
  expect_s3_class(cookies, "data.frame")
  expect_named(
    cookies,
    c("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite", "hostOnly", "partitionKey")
  )
  expect_setequal(cookies$name, c("session", "theme"))
  expect_true(cookies$httpOnly[cookies$name == "session"])
  expect_identical(cookies$expires[cookies$name == "session"], -1)
  expect_gt(cookies$expires[cookies$name == "theme"], as.numeric(Sys.time()))
  # Set-Cookie without SameSite: NA, which set_cookies() reads back as none.
  expect_true(all(is.na(cookies$sameSite)))

  other <- Koon$new()
  expect_identical(nrow(other$set_cookies(cookies)), 0L)
  expect_setequal(other$cookies()$name, c("session", "theme"))
  expect_true(all(is.na(other$cookies()$sameSite)))
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
  # A list of named lists: one valid, one invalid value, one partitioned in a frame below another site.
  visible <- withVisible(client$set_cookies(list(
    list(name = "ok", value = "1", domain = "example.com"),
    list(name = "bad", value = "a;b", domain = "example.com"),
    list(name = "chips", value = "1", domain = "example.com", partitionKey = "https://other.com",
         `_crHasCrossSiteAncestor` = TRUE)
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
    client$set_cookies(list(list(name = "c", value = "3", domain = "x.test", partitionKeyOpaque = TRUE)))$name,
    "c"
  )
})

test_that("partitioned cookies keep their top-level site", {
  # jsonlite makes a nested data frame of CDP's partition key objects.
  cdp <- jsonlite::fromJSON('[
    {"name": "plain", "value": "1", "domain": "x.test", "partitionKey": null},
    {"name": "own", "value": "2", "domain": "x.test",
     "partitionKey": {"topLevelSite": "https://x.test", "hasCrossSiteAncestor": false}},
    {"name": "other", "value": "3", "domain": "x.test",
     "partitionKey": {"topLevelSite": "https://y.test", "hasCrossSiteAncestor": false}},
    {"name": "ancestor", "value": "4", "domain": "x.test",
     "partitionKey": {"topLevelSite": "https://x.test", "hasCrossSiteAncestor": true}},
    {"name": "opaque", "value": "5", "domain": "x.test", "partitionKeyOpaque": true},
    {"name": "not_opaque", "value": "6", "domain": "x.test", "partitionKeyOpaque": false}
  ]')
  expect_true(is.data.frame(cdp$partitionKey))
  importer <- Koon$new()
  skipped <- importer$set_cookies(cdp)
  expect_identical(skipped$name, c("ancestor", "opaque"))
  expect_identical(skipped$index, c(4L, 5L))
  expect_match(skipped$reason, "partitioned")
  cookies <- importer$cookies()
  expect_identical(
    cookies$partitionKey[match(c("plain", "own", "other", "not_opaque"), cookies$name)],
    c(NA, "https://x.test", "https://y.test", NA)
  )
  copy <- Koon$new()
  copy$set_cookies(cookies)
  expect_identical(copy$cookies(), cookies)

  # Playwright's shape: the top-level site as a string, its ancestor flag beside it.
  playwright <- Koon$new()
  skipped <- playwright$set_cookies(list(
    list(name = "own", value = "1", domain = ".x.test", partitionKey = "https://x.test"),
    list(name = "ancestor", value = "2", domain = "x.test", partitionKey = "https://x.test",
         `_crHasCrossSiteAncestor` = TRUE),
    list(name = "listed", value = "3", domain = "x.test", partitionKey = list(topLevelSite = "https://x.test"))
  ))
  expect_identical(skipped$name, "ancestor")
  expect_setequal(playwright$cookies()$name, c("own", "listed"))
})

test_that("malformed cookie input is an error", {
  client <- Koon$new()
  expect_koon_error(client$set_cookies(list(list(value = "3", domain = "x.test"))), "INVALID_ARGUMENT")
  expect_koon_error(client$set_cookies(list(list(name = "c", value = 3, domain = "x.test"))), "INVALID_ARGUMENT")
  expect_koon_error(client$set_cookies("nope"), "INVALID_ARGUMENT")
  cookies <- data.frame(name = "a", value = "1", domain = "example.com")
  expect_koon_error(Koon$new(cookie_jar = FALSE)$set_cookies(cookies), "COOKIE_JAR_DISABLED")
  expect_identical(nrow(Koon$new()$cookies()), 0L)
})
