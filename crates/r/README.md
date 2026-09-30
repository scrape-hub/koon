# koon

An R client that impersonates real browsers at the TLS, HTTP/2, and HTTP/3
fingerprint level: Chrome, Firefox, Safari, Edge, Opera, Brave, Samsung
Internet and OkHttp. See the [project README](https://github.com/scrape-hub/koon)
for the full feature list and profile tables; this page covers only what's
specific to installing and building the R package.

## Install

On Windows and on macOS with Apple silicon, with R 4.6, install the prebuilt
package of the release, no Rust needed:

```r
install.packages("https://github.com/scrape-hub/koon/releases/download/v1.1.0/koon_1.1.0.zip", repos = NULL)  # Windows
install.packages("https://github.com/scrape-hub/koon/releases/download/v1.1.0/koon_1.1.0.tgz", repos = NULL)  # macOS
```

Everywhere else the package builds from source:

```r
# install.packages("remotes")
remotes::install_github("scrape-hub/koon", subdir = "crates/r")
```

That needs Rust 1.85+, CMake and GNU make, on Windows also Rtools, LLVM and
`rustup target add x86_64-pc-windows-gnu`. The first build takes a few
minutes, later ones are faster.

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
