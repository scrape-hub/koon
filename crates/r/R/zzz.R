#' @useDynLib koon, .registration = TRUE
NULL

.onLoad <- function(libname, pkgname) {
  # Nothing needed — extendr handles registration via entrypoint.c
}
