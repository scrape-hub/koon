use bytes::Bytes;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{ArgAction, Args, Parser, Subcommand};
use futures_util::Stream;
use http::Method;
use koon_core::dns::DohConfig;
use koon_core::{
    Body, BoundaryStyle, Browser, BrowserProfile, Chrome, Client, ClientBuilder, DEFAULT_OS,
    HeaderFamily, HeaderMode, IpVersion, Multipart, Os, ProxyServer, ProxyServerAuth,
    ProxyServerConfig, RequestOptions, StreamingResponse, decode_body_text, parse_method,
};
use serde_json::json;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::net::IpAddr;
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncReadExt;

mod verify;

const AFTER_HELP: &str = "\
Examples:
  koon https://example.com
  koon -b firefox https://example.com
  koon -b chrome-macos -v https://httpbin.org/get
  koon -X POST -d '{\"key\":\"val\"}' https://httpbin.org/post
  koon -d @body.json -H \"Content-Type: application/json\" https://api.example.com
  koon -F name=value -F file=@photo.png https://httpbin.org/post
  koon -I https://example.com
  koon -o page.html -f https://example.com
  koon --resolve example.com:443:127.0.0.1 https://example.com
  koon --proxy socks5://127.0.0.1:1080 https://example.com
  koon --save-session s.json https://example.com/login
  koon --load-session s.json https://example.com/dashboard
  koon --json https://httpbin.org/get
  koon --export-profile chrome
  koon --list-browsers
  koon proxy -b chrome --listen 127.0.0.1:8080
  koon verify -b chrome firefox --json

curl's -L, -s, -S and --compressed are accepted and change nothing: koon
follows redirects (see --no-follow), shows no progress meter and always
decompresses.

Exit codes (curl's, where one fits):
  0   success                      20  fingerprint mismatch (koon verify)
  1   other error                  22  HTTP error with --fail
  2   invalid option or value      28  timeout
  3   invalid URL                  35  TLS error
  6   DNS-over-HTTPS lookup failed 47  too many redirects
  7   connection failed            56  network I/O error
  8   malformed HTTP response      95  HTTP/3 or QUIC error
  16  HTTP/2 error                 97  proxy error";

/// `-d @file` bodies up to this size are read into memory, as curl does;
/// larger ones are streamed from disk. A streamed body cannot be sent again,
/// so a 307/308 redirect of it cannot be followed.
const STREAM_UPLOAD_THRESHOLD: u64 = 16 * 1024 * 1024;

/// Exit code of `--fail` for an HTTP error, curl's.
const HTTP_ERROR_EXIT: u8 = 22;

#[derive(Parser)]
#[command(
    name = "koon",
    about = "Browser-impersonating HTTP client",
    long_about = "HTTP client that impersonates real browser TLS, HTTP/2, and HTTP/3 fingerprints.\nPasses Akamai, Cloudflare, and other bot detection systems.",
    version,
    after_help = AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// URL to request
    url: Option<String>,

    /// HTTP method [default: GET, HEAD with --head, POST with --data or --form]
    #[arg(short = 'X', long = "request", value_parser = parse_method_arg)]
    method: Option<Method>,

    /// Browser profile: chrome, firefox154, chrome-macos, safari-mobile, ...
    /// (see --list-browsers; without an OS: Windows, Safari macOS)
    #[arg(short = 'b', long = "browser", default_value = "chrome")]
    browser: String,

    /// Request body; @FILE sends a file (streamed from disk above 16 MiB)
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Multipart form field (repeatable): name=value, name=@FILE (upload,
    /// with ;type=MIME and ;filename=NAME), name=<FILE (text from a file)
    #[arg(
        short = 'F',
        long = "form",
        value_name = "NAME=CONTENT",
        value_parser = parse_form_field,
        conflicts_with = "data"
    )]
    form: Vec<FormField>,

    /// Custom header (repeatable, format: "Key: Value")
    #[arg(short = 'H', long = "header", value_parser = parse_header)]
    headers: Vec<(String, String)>,

    #[command(flatten)]
    connection: ConnectionArgs,

    /// Request timeout in seconds, fractions allowed (0: no timeout)
    #[arg(long, default_value = "30", value_parser = parse_timeout)]
    timeout: Duration,

    /// Output file (write response body to file)
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Send a HEAD request and output the response headers only
    #[arg(short = 'I', long = "head", conflicts_with_all = ["data", "form", "json_output"])]
    head: bool,

    /// Include the status line and response headers in the output
    #[arg(short = 'i', long = "include", conflicts_with = "json_output")]
    include: bool,

    /// Fail on HTTP errors (status 400 and above): no output, exit code 22
    #[arg(short = 'f', long = "fail")]
    fail: bool,

    /// Verbose output (show request/response headers)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Structured JSON output
    #[arg(long = "json")]
    json_output: bool,

    // curl options that change nothing in koon, accepted (also repeated, as
    // curl takes them) so that copied curl command lines work.
    /// curl's --location: koon follows redirects anyway (see --no-follow)
    #[arg(short = 'L', long = "location", hide = true, action = ArgAction::Count)]
    _location: u8,

    /// curl's --silent: koon shows no progress meter anyway
    #[arg(short = 's', long = "silent", hide = true, action = ArgAction::Count)]
    _silent: u8,

    /// curl's --show-error: koon always reports errors
    #[arg(short = 'S', long = "show-error", hide = true, action = ArgAction::Count)]
    _show_error: u8,

    /// curl's --compressed: koon always decompresses
    #[arg(long = "compressed", hide = true, action = ArgAction::Count)]
    _compressed: u8,

    /// Don't follow redirects
    #[arg(long = "no-follow")]
    no_follow: bool,

    /// Maximum number of redirects
    #[arg(long, default_value = "10")]
    max_redirects: u32,

    /// Custom profile from JSON file
    #[arg(long = "profile")]
    profile_json: Option<String>,

    /// Disable cookie jar
    #[arg(long)]
    no_cookies: bool,

    /// Save session (cookies + TLS) to file after request
    #[arg(long = "save-session")]
    save_session: Option<String>,

    /// Load session from file before request
    #[arg(long = "load-session")]
    load_session: Option<String>,

    /// Export a browser profile as JSON and exit
    #[arg(long = "export-profile")]
    export_profile: Option<String>,

    /// List all available browser profiles and exit
    #[arg(long = "list-browsers")]
    list_browsers: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Start a local MITM proxy server
    Proxy(ProxyArgs),
    #[command(after_help = verify::VERIFY_HELP)]
    Verify(verify::VerifyArgs),
}

#[derive(Args)]
struct ProxyArgs {
    /// Browser profile
    #[arg(short = 'b', long = "browser", default_value = "chrome")]
    browser: String,

    /// Custom profile from JSON file
    #[arg(long = "profile")]
    profile_json: Option<String>,

    /// Listen address (ip:port)
    #[arg(long = "listen", default_value = "127.0.0.1:0")]
    listen_addr: String,

    /// Header mode: send the profile's browser headers, or the client's
    #[arg(
        long = "header-mode",
        default_value = "impersonate",
        value_parser = core_value::<HeaderMode>(&["impersonate", "passthrough"])
    )]
    header_mode: HeaderMode,

    /// CA certificate directory
    #[arg(long = "ca-dir")]
    ca_dir: Option<String>,

    /// Timeout in seconds, fractions allowed, for a forwarded request's
    /// response head and each wait for its body (0: no timeout)
    #[arg(long, default_value = "30", value_parser = parse_timeout)]
    timeout: Duration,

    /// Allow --listen to bind a non-loopback address (an open relay through
    /// koon's fingerprinted TLS/HTTP2 stack unless --auth is also set)
    #[arg(long)]
    allow_non_loopback: bool,

    /// Require "USER:PASS" as Proxy-Authorization from every client
    #[arg(long, value_name = "USER:PASS", value_parser = parse_proxy_auth)]
    auth: Option<ProxyServerAuth>,

    /// Connections accepted at once; further ones wait for a slot to free up
    /// (unset keeps the core's own default)
    #[arg(long)]
    max_connections: Option<usize>,

    /// How the forwarded requests connect: upstream proxy, DNS, TLS, ...
    #[command(flatten)]
    connection: ConnectionArgs,
}

/// Parses `--auth`'s "USER:PASS" into a [`ProxyServerAuth`].
fn parse_proxy_auth(value: &str) -> Result<ProxyServerAuth, String> {
    value
        .split_once(':')
        .map(|(username, password)| ProxyServerAuth {
            username: username.to_string(),
            password: password.to_string(),
        })
        .ok_or_else(|| format!("invalid --auth '{value}': expected USER:PASS"))
}

/// Options for the connections to origins and proxies: those of a request,
/// and of the upstream client of `koon proxy`.
#[derive(Args)]
struct ConnectionArgs {
    /// Proxy URL (http://, https://, socks5://)
    #[arg(long)]
    proxy: Option<String>,

    /// Multiple proxy URLs for round-robin rotation (comma-separated)
    #[arg(long, value_delimiter = ',')]
    proxies: Vec<String>,

    /// Custom header for HTTP CONNECT tunnel (repeatable, format: "Key: Value")
    #[arg(long = "proxy-header", value_parser = parse_header)]
    proxy_headers: Vec<(String, String)>,

    /// DNS-over-HTTPS provider
    #[arg(long, value_parser = core_value::<DohConfig>(&["cloudflare", "google"]))]
    doh: Option<DohConfig>,

    /// Disable TLS session resumption
    #[arg(long)]
    no_session_resumption: bool,

    /// Skip TLS certificate verification of origins (an https:// proxy is
    /// still verified, see --ignore-proxy-tls-errors)
    #[arg(long = "ignore-tls-errors", short = 'k')]
    ignore_tls_errors: bool,

    /// Trust the certificates in this PEM file for an https:// proxy, in
    /// addition to the built-in roots
    #[arg(long = "proxy-cacert", value_name = "FILE")]
    proxy_cacert: Option<String>,

    /// Skip certificate verification of an https:// proxy (like curl's
    /// --proxy-insecure)
    #[arg(long = "ignore-proxy-tls-errors")]
    ignore_proxy_tls_errors: bool,

    /// Number of automatic retries on transport errors
    #[arg(long, default_value = "0")]
    retries: u32,

    /// Locale for Accept-Language header (e.g. "de-DE", "fr-FR", "ja-JP")
    #[arg(long)]
    locale: Option<String>,

    /// Bind outgoing connections to a specific local IP address
    #[arg(long = "local-address")]
    local_address: Option<IpAddr>,

    /// Restrict DNS to IPv4 or IPv6
    #[arg(long = "ip-version", value_parser = core_value::<IpVersion>(&["4", "6"]))]
    ip_version: Option<IpVersion>,

    /// Connect to ADDR instead of resolving HOST for PORT, like curl
    /// (repeatable; several addresses comma-separated, IPv6 in brackets)
    #[arg(long = "resolve", value_name = "HOST:PORT:ADDR")]
    resolve: Vec<String>,

    /// Maximum response body size in bytes, decompressed; 0 disables it
    /// (unset keeps the core's default of 100 MiB). Applies to -o and piped
    /// downloads too: koon counts each chunk as it arrives and aborts once
    /// it crosses the limit, like curl's --max-filesize for a body of
    /// unknown length. As curl does, an aborted download's partial output
    /// file is left on disk.
    #[arg(long = "max-response-body", value_name = "BYTES")]
    max_response_body: Option<u64>,

    /// Pin Chrome/Edge/Opera >=151's `PqcBandwidthExperiment` server-padding
    /// field trial group instead of drawing it per client: `none` (not in
    /// the study, like 94% of real Chrome) or the bytes of padding the
    /// group asks for (0, 6000, 9000, 12000, 14000, 16000) [default: drawn
    /// per client]. No effect on a profile that does not run the trial.
    #[arg(long = "server-padding", value_name = "none|BYTES", value_parser = parse_server_padding)]
    server_padding: Option<koon_core::ServerPadding>,
}

/// Parses `--server-padding`'s `"none"` or a byte count into a [`koon_core::ServerPadding`].
fn parse_server_padding(value: &str) -> Result<koon_core::ServerPadding, String> {
    value.parse().map_err(|e: koon_core::Error| e.to_string())
}

impl ConnectionArgs {
    /// `--max-response-body`, or the core's own default when unset.
    fn resolved_max_response_body(&self) -> u64 {
        self.max_response_body
            .unwrap_or_else(|| koon_core::ConnectionOptions::default().max_response_body)
    }

    /// A client builder for `profile` with these options.
    fn client_builder(&self, profile: BrowserProfile) -> Result<ClientBuilder, CliError> {
        let proxy_ca_certs = self.proxy_cacert.as_deref().map(read_file).transpose()?;
        let options = koon_core::ConnectionOptions {
            ignore_tls_errors: self.ignore_tls_errors,
            proxy: self.proxy.clone(),
            proxies: self.proxies.clone(),
            proxy_ca_certs,
            ignore_proxy_tls_errors: self.ignore_proxy_tls_errors,
            proxy_headers: self.proxy_headers.clone(),
            session_resumption: !self.no_session_resumption,
            doh: self.doh.clone(),
            local_address: self.local_address,
            retries: self.retries,
            locale: self.locale.clone(),
            ip_version: self.ip_version,
            resolve: self.resolve.clone(),
            max_response_body: self.resolved_max_response_body(),
            server_padding: self.server_padding,
        };
        Ok(options.apply(profile)?)
    }

    /// Report the options set to stderr, one `* ` line each, with proxy
    /// credentials masked.
    fn print_settings(&self) {
        if !self.proxies.is_empty() {
            let proxies: Vec<_> = self.proxies.iter().map(|p| redact_proxy_url(p)).collect();
            eprintln!("* Proxies: {} (round-robin)", proxies.join(", "));
        } else if let Some(proxy) = &self.proxy {
            eprintln!("* Proxy: {}", redact_proxy_url(proxy));
        }
        if let Some(config) = &self.doh {
            eprintln!("* DoH: {}", config.server_hostname);
        }
        if let Some(locale) = &self.locale {
            eprintln!("* Locale: {locale}");
        }
        if let Some(addr) = self.local_address {
            eprintln!("* Local address: {addr}");
        }
        if let Some(version) = self.ip_version {
            let version = match version {
                IpVersion::V4 => "IPv4",
                IpVersion::V6 => "IPv6",
            };
            eprintln!("* IP version: {version}");
        }
        for entry in &self.resolve {
            eprintln!("* Resolve: {entry}");
        }
        if self.retries > 0 {
            eprintln!("* Retries: {}", self.retries);
        }
        if self.ignore_tls_errors {
            eprintln!("* TLS verification: disabled");
        }
        if let Some(path) = &self.proxy_cacert {
            eprintln!("* Proxy CA certificates: {path}");
        }
        if self.ignore_proxy_tls_errors {
            eprintln!("* Proxy TLS verification: disabled");
        }
        if let Some(max) = self.max_response_body {
            if max == 0 {
                eprintln!("* Max response body: unlimited");
            } else {
                eprintln!("* Max response body: {max} bytes");
            }
        }
        if let Some(padding) = self.server_padding {
            match padding {
                koon_core::ServerPadding::None => eprintln!("* Server padding: none"),
                koon_core::ServerPadding::Bytes(bytes) => {
                    eprintln!("* Server padding: {bytes} bytes");
                }
            }
        }
    }
}

/// A clap value parser that offers `names` (listed by `--help`, checked by
/// clap) and turns the chosen one into a value with the core's parser.
fn core_value<T>(names: &'static [&'static str]) -> impl TypedValueParser<Value = T>
where
    T: FromStr<Err = koon_core::Error> + Clone + Send + Sync + 'static,
{
    PossibleValuesParser::new(names.iter().copied())
        .map(|name| name.parse().expect("every offered name parses"))
}

fn parse_method_arg(method: &str) -> Result<Method, String> {
    parse_method(method).map_err(|e| e.to_string())
}

/// Parse a `"Key: Value"` header argument.
fn parse_header(header: &str) -> Result<(String, String), String> {
    header
        .split_once(':')
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .ok_or_else(|| format!("invalid header '{header}': expected \"Key: Value\""))
}

/// Parse a timeout in seconds, fractions allowed; 0 means no timeout.
fn parse_timeout(secs: &str) -> Result<Duration, String> {
    secs.trim()
        .parse::<f64>()
        .ok()
        .and_then(|value| Duration::try_from_secs_f64(value).ok())
        .ok_or_else(|| format!("'{secs}' is not a number of seconds >= 0"))
}

/// A `-F` field, as curl takes it.
#[derive(Clone, Debug, PartialEq)]
enum FormField {
    /// `name=value`.
    Text { name: String, value: String },
    /// `name=<path`: a text field with the content of a file.
    TextFile { name: String, path: String },
    /// `name=@path[;type=mime][;filename=name]`: a file upload.
    File {
        name: String,
        path: String,
        content_type: Option<String>,
        filename: Option<String>,
    },
}

fn parse_form_field(field: &str) -> Result<FormField, String> {
    let (name, content) = field
        .split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .ok_or_else(|| format!("invalid form field '{field}': expected NAME=CONTENT"))?;
    let name = name.to_string();
    if let Some(path) = content.strip_prefix('<') {
        return Ok(FormField::TextFile {
            name,
            path: path.to_string(),
        });
    }
    let Some(spec) = content.strip_prefix('@') else {
        return Ok(FormField::Text {
            name,
            value: content.to_string(),
        });
    };
    let mut parts = spec.split(';');
    let path = parts.next().unwrap_or_default().to_string();
    if path.is_empty() {
        return Err(format!("invalid form field '{field}': no file after '@'"));
    }
    let (mut content_type, mut filename) = (None, None);
    for part in parts {
        match part.split_once('=') {
            Some(("type", value)) => content_type = Some(value.to_string()),
            Some(("filename", value)) => filename = Some(value.to_string()),
            _ => {
                return Err(format!(
                    "invalid form field '{field}': unsupported ';{part}' (use ;type= or ;filename=)"
                ));
            }
        }
    }
    Ok(FormField::File {
        name,
        path,
        content_type,
        filename,
    })
}

/// The content type curl gives an uploaded file by its extension.
fn content_type_for(path: &str) -> &'static str {
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("gif") => "image/gif",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("pdf") => "application/pdf",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|e| CliError::other(format!("Failed to read '{path}': {e}")))
}

/// The multipart body of the `-F` fields, with the boundary style of the
/// client's browser, and its Content-Type.
fn form_body(fields: &[FormField], client: &Client) -> Result<(Vec<u8>, String), CliError> {
    let mut form = Multipart::new();
    for field in fields {
        form = match field {
            FormField::Text { name, value } => form.text(name, value),
            FormField::TextFile { name, path } => {
                let text = String::from_utf8(read_file(path)?)
                    .map_err(|_| CliError::other(format!("'{path}' is not UTF-8 text")))?;
                form.text(name, text)
            }
            FormField::File {
                name,
                path,
                content_type,
                filename,
            } => {
                let filename = filename.clone().unwrap_or_else(|| {
                    Path::new(path)
                        .file_name()
                        .map_or_else(|| path.clone(), |n| n.to_string_lossy().into_owned())
                });
                let content_type = content_type
                    .clone()
                    .unwrap_or_else(|| content_type_for(path).to_string());
                form.file(name, filename, content_type, read_file(path)?)
            }
        };
    }
    // As `Client::post_multipart`: Firefox's boundary, or Chromium's.
    let style = match client.profile().header_family {
        Some(HeaderFamily::Firefox) => BoundaryStyle::Gecko,
        _ => BoundaryStyle::WebKit,
    };
    Ok(form.build_with(style))
}

/// The chunks of a file, read as the request sends them.
fn file_stream(file: tokio::fs::File) -> impl Stream<Item = std::io::Result<Bytes>> + Send {
    futures_util::stream::try_unfold(file, |mut file| async move {
        let mut chunk = vec![0; 64 * 1024];
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        chunk.truncate(read);
        Ok(Some((Bytes::from(chunk), file)))
    })
}

/// The body of `-d`: the argument itself, or with `@path` the file, read
/// into memory up to [`STREAM_UPLOAD_THRESHOLD`] and streamed above.
async fn data_body(data: &str) -> Result<Body, CliError> {
    let Some(path) = data.strip_prefix('@') else {
        return Ok(data.as_bytes().to_vec().into());
    };
    let error = |e: std::io::Error| CliError::other(format!("Failed to read '{path}': {e}"));
    let file = tokio::fs::File::open(path).await.map_err(error)?;
    let length = file.metadata().await.map_err(error)?.len();
    if length <= STREAM_UPLOAD_THRESHOLD {
        return Ok(read_file(path)?.into());
    }
    Ok(Body::sized_stream(file_stream(file), length))
}

/// An error and the exit code it ends the process with.
#[derive(Debug)]
struct CliError {
    message: String,
    exit_code: u8,
}

impl CliError {
    /// A failure outside the network request, e.g. reading a file.
    fn other(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }
}

impl From<koon_core::Error> for CliError {
    fn from(e: koon_core::Error) -> Self {
        Self {
            exit_code: exit_code(e.code()),
            message: e.to_string(),
        }
    }
}

/// A koon error with what was being done, keeping its exit code.
fn failed(action: &'static str) -> impl FnOnce(koon_core::Error) -> CliError {
    move |e| CliError {
        exit_code: exit_code(e.code()),
        message: format!("{action}: {e}"),
    }
}

/// Exit code for a koon error code, following curl's where one fits (see
/// `AFTER_HELP`).
fn exit_code(code: &str) -> u8 {
    match code {
        "INVALID_ARGUMENT" | "INVALID_HEADER" => 2,
        "INVALID_URL" => 3,
        "DNS_ERROR" => 6,
        "CONNECTION_FAILED" => 7,
        "PROTOCOL_ERROR" => 8,
        "HTTP2_ERROR" => 16,
        "TIMEOUT" => 28,
        "TLS_ERROR" => 35,
        "TOO_MANY_REDIRECTS" => 47,
        // An HTTP error status of a fingerprint service (`koon verify`).
        "HTTP_ERROR" => HTTP_ERROR_EXIT,
        "IO_ERROR" => 56,
        "HTTP3_ERROR" | "QUIC_ERROR" => 95,
        "PROXY_ERROR" => 97,
        _ => 1,
    }
}

/// A proxy URL for display, with its credentials (`user:pass@`) masked:
/// like curl, never echo them.
fn redact_proxy_url(url: &str) -> Cow<'_, str> {
    let authority_start = url.find("://").map_or(0, |i| i + 3);
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    match url[authority_start..authority_end].rfind('@') {
        Some(at) => Cow::Owned(format!(
            "{}***@{}",
            &url[..authority_start],
            &url[authority_start + at + 1..]
        )),
        None => Cow::Borrowed(url),
    }
}

/// A section of `--list-browsers`: the profiles one name prefix reaches.
struct Section {
    label: String,
    prefix: String,
    /// The version as names spell it (`266`) and as it reads (`26.6`),
    /// oldest first.
    versions: Vec<(String, String)>,
    platforms: Vec<Os>,
    /// The OS of a name without one.
    bare_os: Os,
}

/// The text of `--list-browsers`, derived from the core's profile list.
fn list_browsers() -> String {
    // A browser's desktop profiles, then its Android and iOS ones under the
    // `-mobile` alias; OkHttp by release.
    let mut sections: Vec<Section> = Vec::new();
    let mut okhttp = Vec::new();
    for profile in BrowserProfile::names() {
        let browser = profile.browser;
        if browser == Browser::OkHttp {
            okhttp.push(profile.name);
            continue;
        }
        // Browsers of one mobile OS (Samsung Internet) list under their
        // own name.
        let mobile_alias =
            matches!(profile.os, Os::Android | Os::Ios) && browser.default_os() != profile.os;
        let (label, prefix, bare_os) = if mobile_alias {
            let label = format!("{} Mobile", browser.label());
            (label, format!("{browser}-mobile"), profile.os)
        } else {
            let label = browser.label().to_string();
            (label, browser.to_string(), browser.default_os())
        };
        let tag = profile.name[browser.name().len()..]
            .split('-')
            .next()
            .unwrap_or_default()
            .to_string();
        let index = match sections.iter().position(|s| s.prefix == prefix) {
            Some(index) => index,
            None => {
                sections.push(Section {
                    label,
                    prefix,
                    versions: Vec::new(),
                    platforms: Vec::new(),
                    bare_os,
                });
                sections.len() - 1
            }
        };
        let section = &mut sections[index];
        if !section.platforms.contains(&profile.os) {
            section.platforms.push(profile.os);
        }
        if !section.versions.iter().any(|(t, _)| *t == tag) {
            section.versions.push((tag, profile.version));
        }
    }

    let mut out = String::from("Available browser profiles:\n");
    for section in sections {
        let Section {
            label,
            prefix,
            versions,
            platforms,
            bare_os,
        } = section;
        let platforms: Vec<&str> = platforms.iter().map(|os| os.name()).collect();
        let platforms = platforms.join(", ");
        let (oldest, latest) = (&versions[0].1, &versions[versions.len() - 1].1);
        let _ = writeln!(out, "\n  {label} ({oldest}-{latest}; {platforms}):");
        let _ = writeln!(out, "    {prefix:<22}{label} {latest} on {bare_os}");
        for (tag, version) in &versions {
            let name = format!("{prefix}{tag}");
            let _ = writeln!(out, "    {name:<22}{label} {version}");
        }
    }

    let _ = writeln!(out, "\n  OkHttp (Android apps):");
    let latest = okhttp.last().cloned().unwrap_or_default();
    for (name, profile_name) in std::iter::once(("okhttp".to_string(), latest))
        .chain(okhttp.into_iter().map(|name| (name.clone(), name)))
    {
        let profile = BrowserProfile::resolve(&profile_name).expect("a listed profile");
        let release = profile.user_agent().unwrap_or_default().to_string();
        let _ = writeln!(out, "    {name:<22}{release}");
    }

    let _ = writeln!(
        out,
        "\n  OS suffix: -windows, -macos, -linux (e.g. chrome{}-macos, firefox-linux).\n  Without one, desktop profiles impersonate {DEFAULT_OS}, Safari {}.",
        Chrome::LATEST_VERSION,
        Browser::Safari.default_os()
    );
    out
}

/// Write bytes to stdout. A `BrokenPipe` (e.g. piping into `head`) means
/// the reader simply stopped listening, not a failure.
fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = Sink::Stdout(std::io::stdout());
    stdout.write(bytes)?;
    stdout.finish(false)
}

/// Where the response goes: stdout, or the `-o` file.
enum Sink {
    Stdout(std::io::Stdout),
    File {
        file: std::io::BufWriter<std::fs::File>,
        path: String,
        written: u64,
    },
}

impl Sink {
    fn open(output: Option<&str>) -> Result<Self, CliError> {
        let Some(path) = output else {
            return Ok(Self::Stdout(std::io::stdout()));
        };
        let file = std::fs::File::create(path)
            .map_err(|e| CliError::other(format!("Failed to write '{path}': {e}")))?;
        Ok(Self::File {
            file: std::io::BufWriter::new(file),
            path: path.to_string(),
            written: 0,
        })
    }

    /// Write bytes. `false` once stdout's reader went away (e.g. piping into
    /// `head`): nothing more needs to be read then, and it is no failure.
    fn write(&mut self, bytes: &[u8]) -> Result<bool, CliError> {
        match self {
            Self::Stdout(stdout) => match stdout.write_all(bytes) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(false),
                Err(e) => Err(CliError::other(format!("Failed to write to stdout: {e}"))),
            },
            Self::File {
                file,
                path,
                written,
            } => {
                file.write_all(bytes)
                    .map_err(|e| CliError::other(format!("Failed to write '{path}': {e}")))?;
                *written += bytes.len() as u64;
                Ok(true)
            }
        }
    }

    /// Flush the output. Prints a confirmation to stderr in verbose mode
    /// when writing to a file.
    fn finish(self, verbose: bool) -> Result<(), CliError> {
        match self {
            Self::Stdout(mut stdout) => match stdout.flush() {
                Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                    Err(CliError::other(format!("Failed to write to stdout: {e}")))
                }
                _ => Ok(()),
            },
            Self::File {
                mut file,
                path,
                written,
            } => {
                file.flush()
                    .map_err(|e| CliError::other(format!("Failed to write '{path}': {e}")))?;
                if verbose {
                    eprintln!("* Written {written} bytes to {path}");
                }
                Ok(())
            }
        }
    }
}

/// The status line and headers as curl's `-i` prints them.
fn response_head(response: &StreamingResponse) -> String {
    let version = match response.version.as_str() {
        "h2" => "HTTP/2",
        "h3" => "HTTP/3",
        other => other,
    };
    let mut head = format!("{version} {}\r\n", response.status);
    for (name, value) in &response.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");
    head
}

fn header<'a>(response: &'a StreamingResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The `--json` envelope around a response and its body.
fn json_envelope(
    response: &StreamingResponse,
    body: &[u8],
    blocked: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    // Keeps header order (serde_json's "preserve_order") and groups
    // repeated names (e.g. Set-Cookie) into an array under one key.
    let mut headers = serde_json::Map::new();
    for (name, value) in &response.headers {
        headers
            .entry(name.as_str())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("only ever inserted as an array above")
            .push(json!(value));
    }
    let text = decode_body_text(body, header(response, "content-type"));
    let envelope = json!({
        "status": response.status,
        "headers": headers,
        "body": text.as_ref(),
        "version": response.version,
        "url": response.url,
        "blocked_by": blocked,
    });
    let mut bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| CliError::other(format!("Failed to serialize JSON: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// What `-o`/stdout gets: with `--json` the envelope, on a terminal the
/// decoded text, else the body's bytes as they arrive; with `-i`/`-I` the
/// response head first.
async fn write_response(cli: &Cli, response: &mut StreamingResponse) -> Result<(), CliError> {
    let output = cli.output.as_deref();
    let head = (cli.include || cli.head).then(|| response_head(response));
    if cli.json_output || (output.is_none() && std::io::stdout().is_terminal()) {
        let body = response
            .collect_body()
            .await
            .map_err(failed("Request failed"))?;
        let blocked = report_blocked(cli, response, &body);
        let bytes = if cli.json_output {
            json_envelope(response, &body, blocked)?
        } else {
            // A Windows console rejects bytes that are not UTF-8, so a
            // Latin-1, Shift_JIS or binary body would abort mid-output: a
            // terminal gets the body decoded with its charset.
            let text = decode_body_text(&body, header(response, "content-type"));
            (head.unwrap_or_default() + &text).into_bytes()
        };
        let mut sink = Sink::open(output)?;
        sink.write(&bytes)?;
        return sink.finish(cli.verbose);
    }
    // Pipes and files get the bytes, written as they arrive: --max-response-body still applies,
    // counted chunk by chunk, since the CLI is the caller the core's own doc comment leaves this
    // to (`ClientBuilder::max_response_body`'s "the caller already controls how much of it to
    // read"). A chunk that would cross the cap is never written, matching what `collect_body`
    // does for the other output modes above; the file or pipe keeps whatever was written before
    // it, as curl leaves a partial download on disk past `--max-filesize`.
    let max_response_body = cli.connection.resolved_max_response_body();
    let mut received: u64 = 0;
    let mut first_part = Vec::new();
    let mut sink = Sink::open(output)?;
    let mut open = sink.write(head.unwrap_or_default().as_bytes())?;
    while open {
        match response.next_chunk().await {
            Some(chunk) => {
                let chunk = chunk.map_err(failed("Request failed"))?;
                if cli.verbose && first_part.len() < BLOCK_SCAN_BYTES {
                    let take = chunk.len().min(BLOCK_SCAN_BYTES - first_part.len());
                    first_part.extend_from_slice(&chunk[..take]);
                }
                received += chunk.len() as u64;
                if max_response_body != 0 && received > max_response_body {
                    return Err(koon_core::Error::Body(
                        format!("response body exceeded {max_response_body} bytes"),
                        None,
                    )
                    .into());
                }
                open = sink.write(&chunk)?;
            }
            None => break,
        }
    }
    report_blocked(cli, response, &first_part);
    sink.finish(cli.verbose)
}

// As much of a streamed body as `blocked_by` looks at
const BLOCK_SCAN_BYTES: usize = 400_000;

/// Which bot protection answered instead of the page; `-v` says so on stderr.
fn report_blocked(cli: &Cli, response: &StreamingResponse, body: &[u8]) -> Option<&'static str> {
    let blocked = koon_core::blocked_by(response.status, &response.headers, body, &response.url);
    if let (true, Some(by)) = (cli.verbose, blocked) {
        eprintln!("* The site answered with a bot protection page: {by}");
    }
    blocked
}

fn load_profile(browser: &str, profile_json: Option<&str>) -> Result<BrowserProfile, CliError> {
    match profile_json {
        Some(path) => BrowserProfile::from_file(path)
            .map_err(|e| CliError::other(format!("Failed to load profile: {e}"))),
        None => Ok(BrowserProfile::resolve(browser)?),
    }
}

async fn run_request(cli: Cli) -> Result<(), CliError> {
    let url = cli.url.as_deref().ok_or_else(|| CliError {
        message: "No URL provided. Use --help for usage.".into(),
        exit_code: 2,
    })?;

    let profile = load_profile(&cli.browser, cli.profile_json.as_deref())?;

    let client = cli
        .connection
        .client_builder(profile)?
        .follow_redirects(!cli.no_follow)
        .max_redirects(cli.max_redirects)
        .timeout(cli.timeout)
        .cookie_jar(!cli.no_cookies)
        .headers(cli.headers.clone())
        .build()
        .map_err(failed("Client build failed"))?;

    if let Some(path) = &cli.load_session {
        client
            .load_session_from_file(path)
            .map_err(|e| CliError::other(format!("Failed to load session: {e}")))?;
        if cli.verbose {
            eprintln!("* Loaded session from {path}");
        }
    }

    let method = cli.method.clone().unwrap_or_else(|| {
        if cli.head {
            Method::HEAD
        } else if cli.data.is_some() || !cli.form.is_empty() {
            Method::POST
        } else {
            Method::GET
        }
    });
    let mut options = RequestOptions::default();
    let body = if !cli.form.is_empty() {
        let (body, content_type) = form_body(&cli.form, &client)?;
        options.headers.push(("Content-Type".into(), content_type));
        body.into()
    } else if let Some(data) = &cli.data {
        data_body(data).await?
    } else {
        Body::empty()
    };

    if cli.verbose {
        eprintln!("* {method} {url}");
        cli.connection.print_settings();
    }

    let mut response = client
        .send_streaming(method, url, body, options)
        .await
        .map_err(failed("Request failed"))?;
    // Decompressed like a buffered response.
    response.decode_content();

    if let Some(path) = &cli.save_session {
        client
            .save_session_to_file(path)
            .map_err(|e| CliError::other(format!("Failed to save session: {e}")))?;
        if cli.verbose {
            eprintln!("* Saved session to {path}");
        }
    }

    // Verbose diagnostics go to stderr regardless of --json or -o, like `curl -v`.
    if cli.verbose {
        for (k, v) in &response.request_headers {
            eprintln!("> {k}: {v}");
        }
        eprintln!(">");
        eprintln!("< {} {}", response.version, response.status);
        for (k, v) in &response.headers {
            eprintln!("< {k}: {v}");
        }
        eprintln!("<");
    }

    let written = if cli.fail && response.status >= 400 {
        Err(CliError {
            message: format!("The requested URL returned error: {}", response.status),
            exit_code: HTTP_ERROR_EXIT,
        })
    } else {
        write_response(&cli, &mut response).await
    };
    drop(response);
    // End the connections as the browser does when it exits, before the
    // process ends and takes the unsent closes with it.
    client.shutdown().await;
    written
}

async fn run_proxy(args: ProxyArgs) -> Result<(), CliError> {
    let profile = load_profile(&args.browser, args.profile_json.as_deref())?;

    let client = args
        .connection
        .client_builder(profile)?
        .timeout(args.timeout);
    let auth_required = args.auth.is_some();
    let mut config = ProxyServerConfig {
        listen_addr: args.listen_addr,
        header_mode: args.header_mode,
        ca_dir: args.ca_dir,
        client,
        allow_non_loopback: args.allow_non_loopback,
        auth: args.auth,
        ..ProxyServerConfig::default()
    };
    if let Some(max_connections) = args.max_connections {
        config.max_connections = max_connections;
    }
    let server = ProxyServer::start(config)
        .await
        .map_err(failed("Failed to start proxy"))?;

    eprintln!("koon proxy running on {}", server.url());
    eprintln!("CA certificate: {}", server.ca_cert_path().display());
    if auth_required {
        eprintln!("* Proxy-Authorization required");
    }
    args.connection.print_settings();
    eprintln!("Press Ctrl+C to stop.");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| CliError::other(format!("Signal error: {e}")))?;

    eprintln!("\nShutting down...");
    server.shutdown();
    Ok(())
}

async fn run(cli: Cli) -> Result<(), CliError> {
    if cli.list_browsers {
        return write_stdout(list_browsers().as_bytes());
    }
    if let Some(name) = &cli.export_profile {
        let json = BrowserProfile::resolve(name)?
            .to_json_pretty()
            .map_err(|e| CliError::other(format!("Failed to serialize profile: {e}")))?;
        return write_stdout(format!("{json}\n").as_bytes());
    }
    match cli.command {
        Some(Command::Proxy(args)) => run_proxy(args).await,
        Some(Command::Verify(args)) => verify::run_verify(args).await,
        None => run_request(cli).await,
    }
}

/// `#[tokio::main]` would poll the whole CLI's future (every subcommand's
/// call chain, request through TLS/HTTP2/HTTP3, several requests deep with
/// `koon verify`) on the thread that calls it, not a runtime worker thread:
/// on Windows that is the process's main thread, whose default 1 MiB stack
/// an unoptimized (debug) build of that call chain overflows (release
/// builds inline and elide enough of it to fit; `cargo test`/`cargo run`
/// without `--release` do not). A dedicated thread with a larger stack
/// avoids that without changing the call chain itself.
fn main() -> ExitCode {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to start the tokio runtime")
                .block_on(async_main())
        })
        .expect("failed to spawn the main thread")
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

async fn async_main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e.message);
            ExitCode::from(e.exit_code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn redacts_proxy_credentials() {
        assert_eq!(
            redact_proxy_url("http://user:pass@proxy.example:8080"),
            "http://***@proxy.example:8080"
        );
        assert_eq!(
            redact_proxy_url("socks5://u:p%40ss@10.0.0.1:1080/"),
            "socks5://***@10.0.0.1:1080/"
        );
        assert_eq!(redact_proxy_url("user:pass@host:3128"), "***@host:3128");
        assert_eq!(
            redact_proxy_url("http://proxy.example:8080"),
            "http://proxy.example:8080"
        );
        // An @ after the authority is not a credential separator.
        assert_eq!(
            redact_proxy_url("http://proxy.example:8080/a@b"),
            "http://proxy.example:8080/a@b"
        );
    }

    #[test]
    fn parses_headers() {
        assert_eq!(
            parse_header("X-Test:  a: b "),
            Ok(("X-Test".to_string(), "a: b".to_string()))
        );
        assert!(parse_header("no colon").is_err());
    }

    #[test]
    fn maps_error_codes_to_curl_exit_codes() {
        assert_eq!(exit_code(koon_core::Error::Timeout.code()), 28);
        let refused = koon_core::Error::ConnectionFailed("refused".into(), None);
        assert_eq!(exit_code(refused.code()), 7);
        let bad_url = koon_core::Error::UnsupportedScheme("ftp".into());
        assert_eq!(exit_code(bad_url.code()), 3);
        assert_eq!(exit_code("TLS_ERROR"), 35);
        assert_eq!(exit_code("HTTP_ERROR"), 22);
        let unknown_browser = BrowserProfile::resolve("netscape").unwrap_err();
        assert_eq!(exit_code(unknown_browser.code()), 2);
        assert_eq!(exit_code("COOKIE_JAR_DISABLED"), 1);
    }

    #[test]
    fn value_parsers_use_the_core() {
        let cli = Cli::try_parse_from(["koon", "--doh", "google", "--ip-version", "6", "u"])
            .expect("valid arguments");
        assert_eq!(
            cli.connection.doh.map(|c| c.server_hostname),
            Some("dns.google".into())
        );
        assert_eq!(cli.connection.ip_version, Some(IpVersion::V6));
        assert_eq!(cli.method, None);

        let cli = Cli::try_parse_from(["koon", "-X", "patch", "u"]).expect("valid arguments");
        assert_eq!(cli.method, Some(Method::PATCH));

        for args in [
            &["koon", "--doh", "quad9", "u"][..],
            &["koon", "--ip-version", "5", "u"],
            &["koon", "-H", "no colon", "u"],
            &["koon", "--local-address", "nope", "u"],
            &["koon", "-X", "GE T", "u"],
            &["koon", "proxy", "--header-mode", "mirror"],
        ] {
            let err = Cli::try_parse_from(args).err().expect("rejected");
            assert_eq!(err.exit_code(), 2, "{args:?}");
        }
    }

    #[test]
    fn parses_proxy_tls_options() {
        let cli = Cli::try_parse_from(["koon", "u"]).expect("valid arguments");
        assert_eq!(cli.connection.proxy_cacert, None);
        assert!(!cli.connection.ignore_proxy_tls_errors);
        let cli = Cli::try_parse_from([
            "koon",
            "--proxy-cacert",
            "ca.pem",
            "--ignore-proxy-tls-errors",
            "u",
        ])
        .expect("valid arguments");
        assert_eq!(cli.connection.proxy_cacert.as_deref(), Some("ca.pem"));
        assert!(cli.connection.ignore_proxy_tls_errors);
    }

    #[test]
    fn proxy_takes_the_connection_options_of_a_request() {
        let cli = Cli::try_parse_from([
            "koon",
            "proxy",
            "--proxy",
            "http://user:pass@upstream:8080",
            "--locale",
            "de-DE",
            "--doh",
            "cloudflare",
            "--local-address",
            "127.0.0.1",
            "--retries",
            "2",
            "--ip-version",
            "4",
            "-k",
        ])
        .expect("valid arguments");
        let Some(Command::Proxy(args)) = cli.command else {
            panic!("expected the proxy command");
        };
        let connection = &args.connection;
        assert_eq!(
            connection.proxy.as_deref(),
            Some("http://user:pass@upstream:8080")
        );
        assert_eq!(connection.locale.as_deref(), Some("de-DE"));
        assert!(connection.doh.is_some());
        assert_eq!(connection.local_address, Some([127, 0, 0, 1].into()));
        assert_eq!(connection.retries, 2);
        assert_eq!(connection.ip_version, Some(IpVersion::V4));
        assert!(connection.ignore_tls_errors);
        assert!(connection.client_builder(Chrome::latest()).is_ok());
    }

    #[test]
    fn proxies_takes_priority_over_proxy() {
        // A valid `--proxy` alongside an invalid `--proxies` entry must still
        // fail: `proxies` is the one actually applied, not `proxy`.
        let cli = Cli::try_parse_from([
            "koon",
            "--proxy",
            "http://127.0.0.1:1",
            "--proxies",
            "not a url",
            "u",
        ])
        .expect("valid arguments");
        let err = cli
            .connection
            .client_builder(Chrome::latest())
            .err()
            .expect("the invalid --proxies entry must be rejected");
        assert_eq!(err.exit_code, 97, "{}", err.message);
    }

    #[test]
    fn server_padding_pins_the_profile_through_client_builder() {
        let cli = Cli::try_parse_from(["koon", "--server-padding", "none", "u"]).unwrap();
        assert_eq!(
            cli.connection.server_padding,
            Some(koon_core::ServerPadding::None)
        );
        let client = cli.connection.client_builder(Chrome::latest()).unwrap();
        let client = client.build().unwrap();
        assert_eq!(client.profile().tls.server_padding, None);

        let cli = Cli::try_parse_from(["koon", "--server-padding", "9000", "u"]).unwrap();
        assert_eq!(
            cli.connection.server_padding,
            Some(koon_core::ServerPadding::Bytes(9000))
        );
        let client = cli
            .connection
            .client_builder(Chrome::latest())
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(client.profile().tls.server_padding, Some(9000));

        assert!(Cli::try_parse_from(["koon", "--server-padding", "x", "u"]).is_err());
    }

    #[test]
    fn parses_proxy_listener_options() {
        let cli = Cli::try_parse_from([
            "koon",
            "proxy",
            "--allow-non-loopback",
            "--auth",
            "user:pass",
            "--max-connections",
            "5",
        ])
        .expect("valid arguments");
        let Some(Command::Proxy(args)) = cli.command else {
            panic!("expected the proxy command");
        };
        assert!(args.allow_non_loopback);
        let auth = args.auth.expect("auth must be set");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
        assert_eq!(args.max_connections, Some(5));

        for bad in ["nocolon", ""] {
            let err = Cli::try_parse_from(["koon", "proxy", "--auth", bad])
                .err()
                .expect("rejected");
            assert_eq!(err.exit_code(), 2, "{bad}");
        }
    }

    #[test]
    fn lists_browsers_from_the_core() {
        let listing = list_browsers();
        assert!(listing.contains(&format!("Chrome {} on windows", Chrome::LATEST_VERSION)));
        assert!(listing.contains("desktop profiles impersonate windows, Safari macos."));
        assert!(listing.contains(&format!(
            "Safari {} on macos",
            koon_core::SAFARI_VERSIONS.last().unwrap().version
        )));
        assert!(listing.contains(&format!("opera{}", koon_core::Opera::LATEST_VERSION)));
        assert!(listing.contains(&format!("brave-mobile{}", koon_core::Brave::LATEST_VERSION)));
        assert!(listing.contains(&format!("edge-mobile{}", koon_core::Edge::LATEST_VERSION)));
        assert!(listing.contains(&format!("samsung{}", koon_core::Samsung::LATEST_VERSION)));
        assert!(listing.contains(&format!(
            "opera-mobile{}",
            koon_core::OperaMobile::LATEST_VERSION
        )));
        assert!(listing.contains("safari-mobile266"));
        assert!(listing.contains("okhttp/5."));
        for line in listing.lines().filter(|l| l.starts_with("    ")) {
            let name = line.split_whitespace().next().expect("a profile name");
            assert!(
                BrowserProfile::resolve(name).is_ok(),
                "{name} does not resolve"
            );
        }
    }

    #[test]
    fn timeouts_take_fractions() {
        assert_eq!(parse_timeout("2.5"), Ok(Duration::from_millis(2500)));
        assert_eq!(parse_timeout("0"), Ok(Duration::ZERO));
        for bad in ["-1", "nan", "inf", "soon", ""] {
            assert!(parse_timeout(bad).is_err(), "{bad}");
        }
        let cli = Cli::try_parse_from(["koon", "--timeout", "0.25", "u"]).expect("valid");
        assert_eq!(cli.timeout, Duration::from_millis(250));
        let cli = Cli::try_parse_from(["koon", "proxy", "--timeout", "1.5"]).expect("valid");
        let Some(Command::Proxy(args)) = cli.command else {
            panic!("expected the proxy command");
        };
        assert_eq!(args.timeout, Duration::from_millis(1500));
        let err = Cli::try_parse_from(["koon", "--timeout", "-1", "u"])
            .err()
            .unwrap();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn form_fields_parse_like_curl() {
        assert_eq!(
            parse_form_field("a=b=c"),
            Ok(FormField::Text {
                name: "a".into(),
                value: "b=c".into()
            })
        );
        assert_eq!(
            parse_form_field("note=<notes.txt"),
            Ok(FormField::TextFile {
                name: "note".into(),
                path: "notes.txt".into()
            })
        );
        assert_eq!(
            parse_form_field("f=@dir/photo.png;type=image/webp;filename=x.webp"),
            Ok(FormField::File {
                name: "f".into(),
                path: "dir/photo.png".into(),
                content_type: Some("image/webp".into()),
                filename: Some("x.webp".into()),
            })
        );
        for bad in ["novalue", "=value", "f=@", "f=@a.txt;headers=X-A: 1"] {
            assert!(parse_form_field(bad).is_err(), "{bad}");
        }
        assert_eq!(content_type_for("a/B.JPG"), "image/jpeg");
        assert_eq!(content_type_for("data.bin"), "application/octet-stream");
    }

    #[test]
    fn curl_options_parse() {
        let cli = Cli::try_parse_from([
            "koon",
            "-L",
            "-s",
            "-S",
            "-sSL",
            "--compressed",
            "-i",
            "-f",
            "-F",
            "a=1",
            "--resolve",
            "example.com:443:127.0.0.1",
            "u",
        ])
        .expect("valid arguments");
        assert!(cli.include && cli.fail && !cli.head);
        assert_eq!(cli.form.len(), 1);
        assert_eq!(cli.connection.resolve, ["example.com:443:127.0.0.1"]);
        assert!(cli.connection.client_builder(Chrome::latest()).is_ok());
        assert!(
            Cli::try_parse_from(["koon", "-I", "u"])
                .expect("valid")
                .head
        );

        for args in [
            &["koon", "-I", "-d", "x", "u"][..],
            &["koon", "-F", "a=1", "-d", "x", "u"],
            &["koon", "-i", "--json", "u"],
            &["koon", "-F", "novalue", "u"],
        ] {
            let err = Cli::try_parse_from(args).err().expect("rejected");
            assert_eq!(err.exit_code(), 2, "{args:?}");
        }
        let cli = Cli::try_parse_from(["koon", "--resolve", "nonsense", "u"]).expect("parses");
        let err = cli
            .connection
            .client_builder(Chrome::latest())
            .err()
            .expect("an invalid entry");
        assert_eq!(err.exit_code, 2);
    }
}
