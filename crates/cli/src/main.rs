use clap::{Parser, Subcommand};
use http::Method;
use koon_core::{
    BrowserProfile, Client, HeaderMode, ProxyServer, ProxyServerConfig, dns::DohResolver,
};
use serde_json::json;
use std::collections::HashMap;
use std::process;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "koon",
    about = "Browser-impersonating HTTP client",
    long_about = "HTTP client that impersonates real browser TLS, HTTP/2, and HTTP/3 fingerprints.\nPasses Akamai, Cloudflare, and other bot detection systems.",
    version,
    after_help = "\x1b[1mExamples:\x1b[0m
  koon https://example.com
  koon -b firefox147 https://example.com
  koon -b chrome145-macos -v https://httpbin.org/get
  koon -X POST -d '{\"key\":\"val\"}' https://httpbin.org/post
  koon -d @body.json -H \"Content-Type: application/json\" https://api.example.com
  koon --proxy socks5://127.0.0.1:1080 https://example.com
  koon --doh cloudflare --randomize https://example.com
  koon --save-session s.json https://example.com/login
  koon --load-session s.json https://example.com/dashboard
  koon --json https://httpbin.org/get
  koon --export-profile chrome145
  koon --list-browsers
  koon proxy -b chrome145 --listen 127.0.0.1:8080"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// URL to request
    url: Option<String>,

    /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD)
    #[arg(short = 'X', long = "request")]
    method: Option<String>,

    /// Browser profile (chrome, chrome145, firefox147-linux, safari, edge, opera, ...)
    #[arg(short = 'b', long = "browser", default_value = "chrome")]
    browser: String,

    /// Request body (use @filename to read from file)
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Custom header (repeatable, format: "Key: Value")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Proxy URL (http://, socks5://)
    #[arg(long)]
    proxy: Option<String>,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u32,

    /// Output file (write response body to file)
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Verbose output (show request/response headers)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Structured JSON output
    #[arg(long = "json")]
    json_output: bool,

    /// Don't follow redirects
    #[arg(long = "no-follow")]
    no_follow: bool,

    /// Maximum number of redirects
    #[arg(long, default_value = "10")]
    max_redirects: u32,

    /// Randomize fingerprint slightly
    #[arg(long)]
    randomize: bool,

    /// DNS-over-HTTPS provider (cloudflare, google)
    #[arg(long)]
    doh: Option<String>,

    /// Custom profile from JSON file
    #[arg(long = "profile")]
    profile_json: Option<String>,

    /// Disable cookie jar
    #[arg(long)]
    no_cookies: bool,

    /// Disable TLS session resumption
    #[arg(long)]
    no_session_resumption: bool,

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
    Proxy {
        /// Browser profile
        #[arg(short = 'b', long = "browser", default_value = "chrome")]
        browser: String,

        /// Custom profile from JSON file
        #[arg(long = "profile")]
        profile_json: Option<String>,

        /// Listen address (ip:port)
        #[arg(long = "listen", default_value = "127.0.0.1:0")]
        listen_addr: String,

        /// Header mode: impersonate or passthrough
        #[arg(long = "header-mode", default_value = "impersonate")]
        header_mode: String,

        /// CA certificate directory
        #[arg(long = "ca-dir")]
        ca_dir: Option<String>,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u32,

        /// Randomize fingerprint slightly
        #[arg(long)]
        randomize: bool,
    },
}

/// Resolve a browser name string to a BrowserProfile.
/// Delegates to `BrowserProfile::resolve()` in koon-core.
fn resolve_profile(name: &str) -> Result<BrowserProfile, String> {
    BrowserProfile::resolve(name)
}

fn list_browsers() {
    println!("Available browser profiles:\n");

    println!("  Chrome (131-145):");
    println!("    chrome              Chrome latest (145, Windows)");
    for v in 131..=145 {
        println!("    chrome{v}           Chrome {v} (Windows/macOS/Linux)");
    }

    println!("\n  Firefox (135-147):");
    println!("    firefox             Firefox latest (147, Windows)");
    for v in 135..=147 {
        println!("    firefox{v}          Firefox {v} (Windows/macOS/Linux)");
    }

    println!("\n  Safari (15.6-18.3, macOS only):");
    println!("    safari              Safari latest (18.3)");
    for (tag, ver) in [
        ("156", "15.6"),
        ("160", "16.0"),
        ("170", "17.0"),
        ("180", "18.0"),
        ("183", "18.3"),
    ] {
        println!("    safari{tag}           Safari {ver} (macOS)");
    }

    println!("\n  Edge (131-145, Windows/macOS):");
    println!("    edge                Edge latest (145, Windows)");
    for v in 131..=145 {
        println!("    edge{v}             Edge {v} (Windows/macOS)");
    }

    println!("\n  Opera (124-127):");
    println!("    opera               Opera latest (127, Windows)");
    for v in 124..=127 {
        println!("    opera{v}            Opera {v} (Windows/macOS/Linux)");
    }

    println!("\n  OS suffix: -windows, -macos, -linux (e.g. chrome145-macos)");
}

fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|h| {
            let (key, value) = h.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn load_profile(browser: &str, profile_json: &Option<String>) -> Result<BrowserProfile, String> {
    if let Some(path) = profile_json {
        BrowserProfile::from_file(path).map_err(|e| format!("Failed to load profile: {e}"))
    } else {
        resolve_profile(browser)
    }
}

async fn run_request(cli: Cli) -> Result<(), String> {
    let url = cli
        .url
        .as_deref()
        .ok_or("No URL provided. Use --help for usage.")?;

    let mut profile = load_profile(&cli.browser, &cli.profile_json)?;
    if cli.randomize {
        profile.randomize();
    }

    let mut builder = Client::builder(profile);
    builder = builder
        .follow_redirects(!cli.no_follow)
        .max_redirects(cli.max_redirects)
        .timeout(Duration::from_secs(cli.timeout as u64))
        .cookie_jar(!cli.no_cookies)
        .session_resumption(!cli.no_session_resumption);

    if let Some(ref proxy_url) = cli.proxy {
        builder = builder
            .proxy(proxy_url)
            .map_err(|e| format!("Invalid proxy: {e}"))?;
    }

    let extra_headers = parse_headers(&cli.headers);
    if !extra_headers.is_empty() {
        builder = builder.headers(extra_headers.clone());
    }

    if let Some(ref doh_provider) = cli.doh {
        let resolver = match doh_provider.as_str() {
            "cloudflare" => DohResolver::with_cloudflare(),
            "google" => DohResolver::with_google(),
            _ => {
                return Err(format!(
                    "Unknown DoH provider: '{doh_provider}'. Use 'cloudflare' or 'google'."
                ));
            }
        };
        builder = builder.doh(resolver.map_err(|e| format!("DoH init failed: {e}"))?);
    }

    let client = builder
        .build()
        .map_err(|e| format!("Client build failed: {e}"))?;

    // Load session if requested
    if let Some(ref path) = cli.load_session {
        client
            .load_session_from_file(path)
            .map_err(|e| format!("Failed to load session: {e}"))?;
        if cli.verbose {
            eprintln!("* Loaded session from {path}");
        }
    }

    // Determine method
    let method_str =
        cli.method
            .as_deref()
            .unwrap_or(if cli.data.is_some() { "POST" } else { "GET" });
    let method = Method::from_bytes(method_str.to_uppercase().as_bytes())
        .map_err(|_| format!("Invalid HTTP method: '{method_str}'"))?;

    // Determine body
    let body = match cli.data {
        Some(ref data) if data.starts_with('@') => {
            let path = &data[1..];
            Some(std::fs::read(path).map_err(|e| format!("Failed to read '{path}': {e}"))?)
        }
        Some(ref data) => Some(data.as_bytes().to_vec()),
        None => None,
    };

    if cli.verbose {
        eprintln!("* {method} {url}");
        if let Some(ref proxy_url) = cli.proxy {
            eprintln!("* Proxy: {proxy_url}");
        }
        if let Some(ref doh) = cli.doh {
            eprintln!("* DoH: {doh}");
        }
    }

    let response = client
        .request(method, url, body)
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    // Save session if requested
    if let Some(ref path) = cli.save_session {
        client
            .save_session_to_file(path)
            .map_err(|e| format!("Failed to save session: {e}"))?;
        if cli.verbose {
            eprintln!("* Saved session to {path}");
        }
    }

    // Output
    if cli.json_output {
        let headers_map: HashMap<&str, Vec<&str>> =
            response
                .headers
                .iter()
                .fold(HashMap::new(), |mut map, (k, v)| {
                    map.entry(k.as_str()).or_default().push(v.as_str());
                    map
                });
        let body_text = String::from_utf8_lossy(&response.body);
        let output = json!({
            "status": response.status,
            "headers": headers_map,
            "body": body_text,
            "version": response.version,
            "url": response.url,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else if cli.verbose {
        eprintln!("< {} {}", response.version, response.status);
        for (k, v) in &response.headers {
            eprintln!("< {k}: {v}");
        }
        eprintln!();

        if let Some(ref path) = cli.output {
            std::fs::write(path, &response.body)
                .map_err(|e| format!("Failed to write '{path}': {e}"))?;
            eprintln!("* Written {} bytes to {path}", response.body.len());
        } else {
            let body = String::from_utf8_lossy(&response.body);
            print!("{body}");
        }
    } else if let Some(ref path) = cli.output {
        std::fs::write(path, &response.body)
            .map_err(|e| format!("Failed to write '{path}': {e}"))?;
    } else {
        let body = String::from_utf8_lossy(&response.body);
        print!("{body}");
    }

    Ok(())
}

async fn run_proxy(
    browser: String,
    profile_json: Option<String>,
    listen_addr: String,
    header_mode: String,
    ca_dir: Option<String>,
    timeout: u32,
    randomize: bool,
) -> Result<(), String> {
    let mut profile = load_profile(&browser, &profile_json)?;
    if randomize {
        profile.randomize();
    }

    let mode = match header_mode.as_str() {
        "impersonate" => HeaderMode::Impersonate,
        "passthrough" => HeaderMode::Passthrough,
        _ => {
            return Err(format!(
                "Unknown header-mode: '{header_mode}'. Use 'impersonate' or 'passthrough'."
            ));
        }
    };

    let config = ProxyServerConfig {
        listen_addr,
        profile,
        header_mode: mode,
        ca_dir,
        timeout_secs: timeout as u64,
    };

    let server = ProxyServer::start(config)
        .await
        .map_err(|e| format!("Failed to start proxy: {e}"))?;

    eprintln!("koon proxy running on {}", server.url());
    eprintln!("CA certificate: {}", server.ca_cert_path().display());
    eprintln!("Press Ctrl+C to stop.");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("Signal error: {e}"))?;

    eprintln!("\nShutting down...");
    server.shutdown();

    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle info flags (exit immediately)
    if cli.list_browsers {
        list_browsers();
        return;
    }

    if let Some(ref name) = cli.export_profile {
        match resolve_profile(name) {
            Ok(profile) => match profile.to_json_pretty() {
                Ok(json) => {
                    println!("{json}");
                }
                Err(e) => {
                    eprintln!("Error serializing profile: {e}");
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
        return;
    }

    // Handle subcommands
    let result = match cli.command {
        Some(Command::Proxy {
            browser,
            profile_json,
            listen_addr,
            header_mode,
            ca_dir,
            timeout,
            randomize,
        }) => {
            run_proxy(
                browser,
                profile_json,
                listen_addr,
                header_mode,
                ca_dir,
                timeout,
                randomize,
            )
            .await
        }
        None => run_request(cli).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
