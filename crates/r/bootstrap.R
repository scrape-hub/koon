# Copies crates/core into src/rust/vendor/koon-core, so that a source package
# built from crates/r contains koon-core. Runs before pkgbuild builds one and
# before every in-tree install; in an unpacked source package it does nothing.
# Only changed files are copied: cargo rebuilds a path dependency whose files
# are newer.

core <- file.path("..", "core")
workspace <- file.path("..", "..", "Cargo.toml")
dest <- file.path("src", "rust", "vendor", "koon-core")

if (file.exists(file.path(core, "Cargo.toml")) && file.exists(workspace)) {
  write_if_changed <- function(lines, path) {
    if (!file.exists(path) || !identical(readLines(path, warn = FALSE), lines)) {
      dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE)
      writeLines(lines, path)
    }
  }

  from <- list.files(file.path(core, "src"), recursive = TRUE, all.files = TRUE)
  to <- list.files(file.path(dest, "src"), recursive = TRUE, all.files = TRUE)
  unlink(file.path(dest, "src", setdiff(to, from)))
  for (f in from) {
    src <- file.path(core, "src", f)
    dst <- file.path(dest, "src", f)
    if (!file.exists(dst) || unname(tools::md5sum(src)) != unname(tools::md5sum(dst))) {
      dir.create(dirname(dst), recursive = TRUE, showWarnings = FALSE)
      file.copy(src, dst, overwrite = TRUE, copy.date = TRUE)
    }
  }

  # The copy is a crate of its own: it gets the values koon-core inherits from the workspace
  ws <- readLines(workspace, warn = FALSE)
  start <- grep("^\\[workspace\\.package\\]", ws)
  tables <- grep("^\\[", ws)
  end <- min(c(tables[tables > start], length(ws) + 1)) - 1
  pkg <- grep("^[a-z-]+ *= *", ws[(start + 1):end], value = TRUE)
  values <- setNames(sub("^[a-z-]+ *= *", "", pkg), sub(" *=.*", "", pkg))

  manifest <- readLines(file.path(core, "Cargo.toml"), warn = FALSE)
  for (key in names(values)) {
    manifest <- sub(sprintf("^%s\\.workspace *= *true", key), sprintf("%s = %s", key, values[[key]]), manifest)
  }
  stopifnot(!any(grepl("^[a-z-]+\\.workspace *= *true", manifest)))
  # [lints] workspace = true: lint levels only matter for koon's own CI
  lints <- grep("^\\[lints\\]", manifest)
  if (length(lints) == 1 && grepl("^workspace *= *true", manifest[lints + 1])) {
    manifest <- manifest[-c(lints, lints + 1)]
  }
  write_if_changed(manifest, file.path(dest, "Cargo.toml"))
}
