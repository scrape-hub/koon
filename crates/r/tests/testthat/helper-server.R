# The local HTTP server most tests talk to: testserver.py, run with Python.
# setup-server.R starts it once for the whole run; tests call
# test_server_url(), which skips them when it could not be started.
#
# KOON_TEST_PYTHON names the Python interpreter to use; otherwise the first
# of python3, python and py that runs is used.

find_python <- function() {
  candidates <- c(Sys.getenv("KOON_TEST_PYTHON"), "python3", "python", "py")
  for (candidate in candidates[nzchar(candidates)]) {
    path <- Sys.which(candidate)
    if (!nzchar(path)) next
    # The Windows Store stub for python3 is on the PATH but does not run.
    works <- tryCatch(
      processx::run(path, "--version", timeout = 10, error_on_status = FALSE)$status == 0,
      error = function(e) FALSE
    )
    if (works) return(unname(path))
  }
  NULL
}

# Start testserver.py on a free port. Returns list(process, url), or NULL
# when there is no Python (or processx) to run it with.
start_test_server <- function() {
  if (!requireNamespace("processx", quietly = TRUE)) return(NULL)
  python <- find_python()
  if (is.null(python)) return(NULL)
  process <- processx::process$new(
    python, c("-u", test_path("testserver.py"), "0"),
    stdout = "|", stderr = "|", cleanup = TRUE
  )
  deadline <- Sys.time() + 15
  while (Sys.time() < deadline && process$is_alive()) {
    process$poll_io(500)
    line <- grep("^listening on [0-9]+$", process$read_output_lines(), value = TRUE)
    if (length(line) > 0) {
      port <- sub("^listening on ", "", line[[1]])
      return(list(process = process, url = paste0("http://127.0.0.1:", port)))
    }
  }
  process$kill()
  NULL
}

# The base URL of the local test server; skips the test without one.
test_server_url <- function() {
  url <- getOption("koon.test_server_url", "")
  skip_if_not(nzchar(url), "no Python to run the local test server (set KOON_TEST_PYTHON)")
  url
}

# The port of the local test server.
test_server_port <- function() {
  sub("^.*:", "", test_server_url())
}

json <- function(resp) jsonlite::fromJSON(resp$text, simplifyVector = FALSE)

header_names <- function(resp) vapply(json(resp)$headers, `[[`, "", 1)

# `expr` fails with a koon condition of error code `code`; returns it.
expect_koon_error <- function(expr, code) {
  err <- tryCatch(expr, error = identity)
  expect_s3_class(err, c(paste0("koon_", tolower(code)), "koon_error", "error", "condition"), exact = TRUE)
  expect_identical(err$code, code)
  expect_match(conditionMessage(err), paste0("^\\[", code, "\\] "))
  invisible(err)
}
