# koon

An R client that impersonates real browsers at the TLS, HTTP/2, and HTTP/3
fingerprint level: Chrome, Firefox, Safari, Edge, Opera, Brave, Samsung
Internet and OkHttp. See the [project README](https://github.com/scrape-hub/koon)
for the full feature list and profile tables; this page covers only what's
specific to installing and building the R package.

## Install

R has no prebuilt binary for koon, so installing builds the Rust core from
source:

```r
# install.packages("remotes")
remotes::install_github("scrape-hub/koon", subdir = "crates/r")
```

**Requirements:**
- Rust 1.85+
- CMake
- NASM (Windows, optional: without it BoringSSL is built from portable C, which is slower)
- C compiler: MSVC (Windows), GCC or Clang (Linux/macOS)
- GNU make

A full build (BoringSSL included) takes a few minutes the first time;
subsequent installs from the same machine are faster.

## Usage

```r
library(koon)

client <- Koon$new("chrome")
resp <- client$get("https://httpbin.org/json")
resp$ok      # TRUE
resp$text    # body as string
```

See `vignette("getting-started")`, `vignette("advanced-usage")` and
`vignette("sessions-and-cookies")` for more, or the "R" section of the
[project README](https://github.com/scrape-hub/koon#r).

## License

[MIT](LICENSE)
