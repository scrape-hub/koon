use clap::{Parser, Subcommand};
use http::Method;
use koon_core::{
    dns::DohResolver, BrowserProfile, Chrome, Client, Edge, Firefox, HeaderMode, Opera,
    ProxyServer, ProxyServerConfig, Safari,
};
use serde_json::json;
use std::collections::HashMap;
use std::process;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "koon", about = "Browser-impersonating HTTP client", version)]
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

    /// Skip TLS certificate verification (not yet supported, placeholder)
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

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
///
/// Supports: chrome, chrome145, chrome145-macos, firefox, firefox147-linux, safari, edge, opera, etc.
/// Case-insensitive. Without OS suffix, defaults to Windows (or macOS for Safari).
fn resolve_profile(name: &str) -> Result<BrowserProfile, String> {
    let name = name.to_lowercase();
    let (browser, os) = if let Some(pos) = name.rfind('-') {
        let suffix = &name[pos + 1..];
        if matches!(suffix, "windows" | "macos" | "linux") {
            (&name[..pos], Some(suffix.to_string()))
        } else {
            (name.as_str(), None)
        }
    } else {
        (name.as_str(), None)
    };

    // Helper to pick os-specific variant
    macro_rules! pick_os {
        ($win:expr, $mac:expr, $lin:expr) => {
            match os.as_deref() {
                Some("macos") => $mac,
                Some("linux") => $lin,
                _ => $win, // default to windows
            }
        };
    }

    macro_rules! pick_os_no_linux {
        ($win:expr, $mac:expr) => {
            match os.as_deref() {
                Some("macos") => $mac,
                Some("linux") => return Err(format!("No Linux variant for '{name}'")),
                _ => $win,
            }
        };
    }

    let profile = match browser {
        // Chrome generic
        "chrome" => pick_os!(Chrome::latest(), Chrome::v145_macos(), Chrome::v145_linux()),

        // Chrome versioned
        "chrome131" => pick_os!(Chrome::v131_windows(), Chrome::v131_macos(), Chrome::v131_linux()),
        "chrome132" => pick_os!(Chrome::v132_windows(), Chrome::v132_macos(), Chrome::v132_linux()),
        "chrome133" => pick_os!(Chrome::v133_windows(), Chrome::v133_macos(), Chrome::v133_linux()),
        "chrome134" => pick_os!(Chrome::v134_windows(), Chrome::v134_macos(), Chrome::v134_linux()),
        "chrome135" => pick_os!(Chrome::v135_windows(), Chrome::v135_macos(), Chrome::v135_linux()),
        "chrome136" => pick_os!(Chrome::v136_windows(), Chrome::v136_macos(), Chrome::v136_linux()),
        "chrome137" => pick_os!(Chrome::v137_windows(), Chrome::v137_macos(), Chrome::v137_linux()),
        "chrome138" => pick_os!(Chrome::v138_windows(), Chrome::v138_macos(), Chrome::v138_linux()),
        "chrome139" => pick_os!(Chrome::v139_windows(), Chrome::v139_macos(), Chrome::v139_linux()),
        "chrome140" => pick_os!(Chrome::v140_windows(), Chrome::v140_macos(), Chrome::v140_linux()),
        "chrome141" => pick_os!(Chrome::v141_windows(), Chrome::v141_macos(), Chrome::v141_linux()),
        "chrome142" => pick_os!(Chrome::v142_windows(), Chrome::v142_macos(), Chrome::v142_linux()),
        "chrome143" => pick_os!(Chrome::v143_windows(), Chrome::v143_macos(), Chrome::v143_linux()),
        "chrome144" => pick_os!(Chrome::v144_windows(), Chrome::v144_macos(), Chrome::v144_linux()),
        "chrome145" => pick_os!(Chrome::v145_windows(), Chrome::v145_macos(), Chrome::v145_linux()),

        // Firefox generic
        "firefox" => pick_os!(Firefox::latest(), Firefox::v147_macos(), Firefox::v147_linux()),

        // Firefox versioned
        "firefox135" => pick_os!(Firefox::v135_windows(), Firefox::v135_macos(), Firefox::v135_linux()),
        "firefox136" => pick_os!(Firefox::v136_windows(), Firefox::v136_macos(), Firefox::v136_linux()),
        "firefox137" => pick_os!(Firefox::v137_windows(), Firefox::v137_macos(), Firefox::v137_linux()),
        "firefox138" => pick_os!(Firefox::v138_windows(), Firefox::v138_macos(), Firefox::v138_linux()),
        "firefox139" => pick_os!(Firefox::v139_windows(), Firefox::v139_macos(), Firefox::v139_linux()),
        "firefox140" => pick_os!(Firefox::v140_windows(), Firefox::v140_macos(), Firefox::v140_linux()),
        "firefox141" => pick_os!(Firefox::v141_windows(), Firefox::v141_macos(), Firefox::v141_linux()),
        "firefox142" => pick_os!(Firefox::v142_windows(), Firefox::v142_macos(), Firefox::v142_linux()),
        "firefox143" => pick_os!(Firefox::v143_windows(), Firefox::v143_macos(), Firefox::v143_linux()),
        "firefox144" => pick_os!(Firefox::v144_windows(), Firefox::v144_macos(), Firefox::v144_linux()),
        "firefox145" => pick_os!(Firefox::v145_windows(), Firefox::v145_macos(), Firefox::v145_linux()),
        "firefox146" => pick_os!(Firefox::v146_windows(), Firefox::v146_macos(), Firefox::v146_linux()),
        "firefox147" => pick_os!(Firefox::v147_windows(), Firefox::v147_macos(), Firefox::v147_linux()),

        // Safari (macOS only)
        "safari" => Safari::latest(),
        "safari156" | "safari15.6" => Safari::v15_6_macos(),
        "safari160" | "safari16.0" => Safari::v16_0_macos(),
        "safari170" | "safari17.0" => Safari::v17_0_macos(),
        "safari180" | "safari18.0" => Safari::v18_0_macos(),
        "safari183" | "safari18.3" => Safari::v18_3_macos(),

        // Edge (Windows + macOS only)
        "edge" => pick_os_no_linux!(Edge::latest(), Edge::v145_macos()),

        "edge131" => pick_os_no_linux!(Edge::v131_windows(), Edge::v131_macos()),
        "edge132" => pick_os_no_linux!(Edge::v132_windows(), Edge::v132_macos()),
        "edge133" => pick_os_no_linux!(Edge::v133_windows(), Edge::v133_macos()),
        "edge134" => pick_os_no_linux!(Edge::v134_windows(), Edge::v134_macos()),
        "edge135" => pick_os_no_linux!(Edge::v135_windows(), Edge::v135_macos()),
        "edge136" => pick_os_no_linux!(Edge::v136_windows(), Edge::v136_macos()),
        "edge137" => pick_os_no_linux!(Edge::v137_windows(), Edge::v137_macos()),
        "edge138" => pick_os_no_linux!(Edge::v138_windows(), Edge::v138_macos()),
        "edge139" => pick_os_no_linux!(Edge::v139_windows(), Edge::v139_macos()),
        "edge140" => pick_os_no_linux!(Edge::v140_windows(), Edge::v140_macos()),
        "edge141" => pick_os_no_linux!(Edge::v141_windows(), Edge::v141_macos()),
        "edge142" => pick_os_no_linux!(Edge::v142_windows(), Edge::v142_macos()),
        "edge143" => pick_os_no_linux!(Edge::v143_windows(), Edge::v143_macos()),
        "edge144" => pick_os_no_linux!(Edge::v144_windows(), Edge::v144_macos()),
        "edge145" => pick_os_no_linux!(Edge::v145_windows(), Edge::v145_macos()),

        // Opera
        "opera" => pick_os!(Opera::latest(), Opera::v127_macos(), Opera::v127_linux()),

        "opera124" => pick_os!(Opera::v124_windows(), Opera::v124_macos(), Opera::v124_linux()),
        "opera125" => pick_os!(Opera::v125_windows(), Opera::v125_macos(), Opera::v125_linux()),
        "opera126" => pick_os!(Opera::v126_windows(), Opera::v126_macos(), Opera::v126_linux()),
        "opera127" => pick_os!(Opera::v127_windows(), Opera::v127_macos(), Opera::v127_linux()),

        _ => return Err(format!("Unknown browser profile: '{name}'")),
    };

    Ok(profile)
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
    for (tag, ver) in [("156", "15.6"), ("160", "16.0"), ("170", "17.0"), ("180", "18.0"), ("183", "18.3")] {
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

fn load_profile(cli: &Cli) -> Result<BrowserProfile, String> {
    if let Some(ref path) = cli.profile_json {
        BrowserProfile::from_file(path).map_err(|e| format!("Failed to load profile: {e}"))
    } else {
        resolve_profile(&cli.browser)
    }
}

fn load_profile_proxy(
    browser: &str,
    profile_json: &Option<String>,
) -> Result<BrowserProfile, String> {
    if let Some(path) = profile_json {
        BrowserProfile::from_file(path).map_err(|e| format!("Failed to load profile: {e}"))
    } else {
        resolve_profile(browser)
    }
}

async fn run_request(cli: Cli) -> Result<(), String> {
    let url = cli.url.as_deref().ok_or("No URL provided. Use --help for usage.")?;

    let mut profile = load_profile(&cli)?;
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
        builder = builder.proxy(proxy_url).map_err(|e| format!("Invalid proxy: {e}"))?;
    }

    let extra_headers = parse_headers(&cli.headers);
    if !extra_headers.is_empty() {
        builder = builder.headers(extra_headers.clone());
    }

    if let Some(ref doh_provider) = cli.doh {
        let resolver = match doh_provider.as_str() {
            "cloudflare" => DohResolver::with_cloudflare(),
            "google" => DohResolver::with_google(),
            _ => return Err(format!("Unknown DoH provider: '{doh_provider}'. Use 'cloudflare' or 'google'.")),
        };
        builder = builder.doh(resolver.map_err(|e| format!("DoH init failed: {e}"))?);
    }

    let client = builder.build().map_err(|e| format!("Client build failed: {e}"))?;

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
    let method_str = cli
        .method
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
            response.headers.iter().fold(HashMap::new(), |mut map, (k, v)| {
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
    let mut profile = load_profile_proxy(&browser, &profile_json)?;
    if randomize {
        profile.randomize();
    }

    let mode = match header_mode.as_str() {
        "impersonate" => HeaderMode::Impersonate,
        "passthrough" => HeaderMode::Passthrough,
        _ => {
            return Err(format!(
                "Unknown header-mode: '{header_mode}'. Use 'impersonate' or 'passthrough'."
            ))
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
