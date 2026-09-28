# Runs the tests in tests/testthat with R CMD check. Most of them need the
# local test server (tests/testthat/testserver.py), which needs Python; they
# are skipped without it (see helper-server.R).
library(testthat)
library(koon)

test_check("koon")
