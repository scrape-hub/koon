# Pre-release test: R
cat("\n=== R ===\n\n")

passed <- 0L
failed <- 0L
skipped <- 0L

ok <- function(label, condition) {
  if (isTRUE(condition)) {
    cat(sprintf("  [PASS] %s\n", label))
    passed <<- passed + 1L
  } else {
    cat(sprintf("  [FAIL] %s\n", label))
    failed <<- failed + 1L
  }
}

skip_test <- function(label) {
  cat(sprintf("  [SKIP] %s\n", label))
  skipped <<- skipped + 1L
}

library(koon)

# ── Response Properties ──────────────────────────────────────────
cat("-- Response Properties --\n")
client <- Koon$new("chrome145", timeout = 30L)
resp <- client$get("https://httpbin.org/get")
ok("status=200", resp$status == 200L)
ok("status_code alias", resp$status_code == 200L)
ok("ok is TRUE", isTRUE(resp$ok))
ok("text is character", is.character(resp$text) && grepl("url", resp$text))
ok("body is raw", is.raw(resp$body) && length(resp$body) > 0)
ok("content_type", is.character(resp$content_type) && grepl("json", resp$content_type))
ok("headers is data.frame", is.data.frame(resp$headers) && nrow(resp$headers) > 0)
ok("bytes_sent > 0", resp$bytes_sent > 0)
ok("bytes_received > 0", resp$bytes_received > 0)

# ── Browser Profiles ─────────────────────────────────────────────
cat("-- Browser Profiles --\n")
for (profile in c("chrome145", "firefox148", "safari183")) {
  c2 <- Koon$new(profile, timeout = 30L)
  r <- c2$get("https://httpbin.org/get")
  ok(sprintf("%s GET status=200", profile), r$status == 200L)
}

# ── HTTP Methods ─────────────────────────────────────────────────
cat("-- HTTP Methods --\n")
resp <- client$post("https://httpbin.org/post", "r body test")
ok("POST status=200", resp$status == 200L)
data <- jsonlite::fromJSON(resp$text)
ok("POST body echoed", grepl("r body test", data$data))

resp <- client$head("https://httpbin.org/get")
ok("HEAD status=200", resp$status == 200L)

# ── Per-Request Headers ──────────────────────────────────────────
cat("-- Per-Request Headers --\n")
resp <- client$get("https://httpbin.org/headers",
  headers = c(`X-Koon-Test` = "r-test"))
data <- jsonlite::fromJSON(resp$text)
ok("custom header sent", data$headers$`X-Koon-Test` == "r-test")

# ── Cookies ──────────────────────────────────────────────────────
cat("-- Cookies --\n")
invisible(client$get("https://httpbin.org/cookies/set/rkey/rval"))
resp <- client$get("https://httpbin.org/cookies")
cookies <- jsonlite::fromJSON(resp$text)$cookies
ok("cookie persisted", cookies$rkey == "rval")

session <- client$save_session()
ok("save_session returns string", is.character(session) && nchar(session) > 10)

client2 <- Koon$new("chrome145", timeout = 30L)
client2$load_session(session)
resp2 <- client2$get("https://httpbin.org/cookies")
cookies2 <- jsonlite::fromJSON(resp2$text)$cookies
ok("load_session restores cookies", cookies2$rkey == "rval")

client$clear_cookies()
resp <- client$get("https://httpbin.org/cookies")
cookies3 <- jsonlite::fromJSON(resp$text)$cookies
ok("clear_cookies works", is.null(cookies3$rkey))

# ── Redirect ─────────────────────────────────────────────────────
cat("-- Redirect --\n")
resp <- client$get("https://httpbin.org/redirect/3")
ok("redirect followed", resp$status == 200L && !grepl("redirect", resp$url))

# ── Proxy ─────────────────────────────────────────────────────────
cat("-- Proxy --\n")
proxy <- Sys.getenv("KOON_TEST_PROXY", "")
if (nchar(proxy) > 0) {
  tryCatch({
    c3 <- Koon$new("chrome145", proxy = proxy, timeout = 30L)
    r <- c3$get("https://httpbin.org/ip")
    ok("constructor proxy works", r$status == 200L)
  }, error = function(e) ok(sprintf("constructor proxy (%s)", e$message), FALSE))
} else {
  skip_test("proxy (KOON_TEST_PROXY not set)")
}

# ── WAF Smoke ─────────────────────────────────────────────────────
cat("-- WAF Smoke (soft-fail) --\n")
for (site in list(
  list(url = "https://nowsecure.nl", name = "Cloudflare"),
  list(url = "https://www.nike.com", name = "Akamai")
)) {
  tryCatch({
    r <- client$get(site$url)
    if (r$status == 200L) {
      cat(sprintf("  [PASS] %s -> 200\n", site$name))
      passed <<- passed + 1L
    } else {
      cat(sprintf("  [WARN] %s -> %d\n", site$name, r$status))
    }
  }, error = function(e) {
    cat(sprintf("  [WARN] %s -> %s\n", site$name, e$message))
  })
}

# ── List Browsers ─────────────────────────────────────────────────
cat("-- Utility --\n")
browsers <- koon_browsers()
ok("koon_browsers() returns list", length(browsers) > 50)

# ── Summary ──────────────────────────────────────────────────────
total <- passed + failed
msg <- sprintf("\n=== r: %d/%d passed", passed, total)
if (failed > 0) msg <- paste0(msg, sprintf(", %d FAILED", failed))
if (skipped > 0) msg <- paste0(msg, sprintf(", %d skipped", skipped))
msg <- paste0(msg, " ===\n")
cat(msg)
if (failed > 0) quit(status = 1)
