# Keeps a copy of koon-core in src/rust/vendor/koon-core, where the Rust crate expects it.
#
# In the repository koon-core lives in crates/core, outside this package, so a
# source package built from here (remotes::install_github(), pak, devtools)
# would not contain it. pkgbuild runs this script before it builds the source
# package (Config/build/bootstrap in DESCRIPTION), and src/Makevars and
# src/Makevars.win run it before every in-tree `R CMD INSTALL crates/r`.
# Outside the repository, in an unpacked source package, there is nothing to
# copy and the vendored copy is used as it is.
#
# Only files that differ are copied: cargo decides by modification time
# whether a path dependency changed, and a fresh copy on every install would
# rebuild koon-core every time.
#
# koon-core takes its version, edition, rust-version and license from the
# workspace (Cargo.toml at the repository root). The copy is a crate of its
# own, so those values are written into its manifest.

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

  # src/: copy new and changed files, remove the ones koon-core no longer has
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

  # [workspace.package] of the root manifest: key = "value" lines up to the next table
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
