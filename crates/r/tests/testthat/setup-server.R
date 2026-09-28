# Start the local test server for the whole run (see helper-server.R) and
# stop it afterwards.
local({
  server <- start_test_server()
  if (!is.null(server)) {
    withr::defer(server$process$kill(), envir = teardown_env())
    withr::local_options(koon.test_server_url = server$url, .local_envir = teardown_env())
  }
})
