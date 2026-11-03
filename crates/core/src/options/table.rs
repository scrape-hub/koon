//! The option table. Docs use the markup of [`super::render`]; the default is documented apart.

use super::{CliFlag, CliForm, DefaultValue, Hook, Kind, OptionSpec, Scope};

const CLIENT: &[Scope] = &[Scope::Client];
const CLIENT_PROXY: &[Scope] = &[Scope::Client, Scope::Proxy];
const CONNECTION: &[Scope] = &[Scope::Client, Scope::Proxy, Scope::Verify];
const CLIENT_VERIFY: &[Scope] = &[Scope::Client, Scope::Verify];
const REQUEST: &[Scope] = &[Scope::Request, Scope::Stream];
const PROXY: &[Scope] = &[Scope::Proxy];
const STREAM: &[Scope] = &[Scope::Stream];

const fn flag(long: &'static str, value_name: &'static str, form: CliForm) -> Option<CliFlag> {
    Some(CliFlag {
        long,
        short: None,
        value_name,
        form,
    })
}

const fn short_flag(
    short: char,
    long: &'static str,
    value_name: &'static str,
    form: CliForm,
) -> Option<CliFlag> {
    Some(CliFlag {
        long,
        short: Some(short),
        value_name,
        form,
    })
}

/// Every option, in the order the docs list them.
pub static OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        name: "browser",
        kind: Kind::Browser,
        scopes: CONNECTION,
        default: Some(DefaultValue::Text("chrome")),
        doc: "Browser profile to impersonate, such as `chrome`, `firefox154`, `chrome-macos`, \
              `safari-mobile266` or `okhttp5`. Without a version it is the newest one, without \
              an OS desktop browsers impersonate Windows and Safari macOS.",
        cli: short_flag('b', "browser", "NAME", CliForm::Value),
    },
    OptionSpec {
        name: "profile_json",
        kind: Kind::ProfileJson,
        scopes: CLIENT_PROXY,
        default: None,
        doc: "A custom browser profile as JSON, as {fn:export_profile} returns it. Overrides \
              {browser}. Malformed JSON fails with {error:JSON_ERROR}.",
        cli: flag("profile", "FILE", CliForm::File),
    },
    OptionSpec {
        name: "proxy",
        kind: Kind::Text,
        scopes: CONNECTION,
        default: None,
        doc: "Proxy URL: `http://`, `https://`, `socks5://` or `socks5h://` (the same: the \
              proxy resolves the host name), optionally with `user:pass@`. An `https://` proxy \
              is reached over TLS and its certificate is verified (see {proxy_ca_certs}).",
        cli: flag("proxy", "URL", CliForm::Value),
    },
    OptionSpec {
        name: "proxies",
        kind: Kind::Texts,
        scopes: CONNECTION,
        default: None,
        doc: "Proxy URLs to rotate through: each request, and each retry, takes the next one. \
              Takes priority over {proxy}.",
        cli: flag("proxies", "URLS", CliForm::List),
    },
    OptionSpec {
        name: "timeout",
        kind: Kind::Seconds,
        scopes: CLIENT_VERIFY,
        default: Some(DefaultValue::Number("30")),
        doc: "Timeout of a whole request in seconds, fractions allowed: connecting, redirects \
              and the body. `0` means no timeout.",
        cli: flag("timeout", "SECONDS", CliForm::Value),
    },
    OptionSpec {
        name: "ignore_tls_errors",
        kind: Kind::Bool,
        scopes: CONNECTION,
        default: Some(DefaultValue::Bool(false)),
        doc: "Skip certificate verification of origins. `https://` proxies are still verified \
              (see {ignore_proxy_tls_errors}).",
        cli: short_flag('k', "ignore-tls-errors", "", CliForm::Switch),
    },
    OptionSpec {
        name: "proxy_ca_certs",
        kind: Kind::Pem,
        scopes: CONNECTION,
        default: None,
        doc: "Certificates (PEM, one or more) trusted for the TLS connection to `https://` \
              proxies in addition to the built-in roots, like curl's `--proxy-cacert`: for a \
              proxy with a self-signed certificate or one from a private CA. Origins are still \
              verified against the built-in roots only. Invalid PEM fails with \
              {error:INVALID_ARGUMENT}.",
        cli: flag("proxy-cacert", "FILE", CliForm::File),
    },
    OptionSpec {
        name: "ignore_proxy_tls_errors",
        kind: Kind::Bool,
        scopes: CONNECTION,
        default: Some(DefaultValue::Bool(false)),
        doc: "Skip certificate verification of `https://` proxies, like curl's \
              `--proxy-insecure`. The connection stays encrypted, but anyone on the way to the \
              proxy can pose as it and read the proxy credentials and the hosts requested. \
              Origins are still verified. Prefer {proxy_ca_certs}.",
        cli: flag("ignore-proxy-tls-errors", "", CliForm::Switch),
    },
    OptionSpec {
        name: "headers",
        kind: Kind::Headers,
        scopes: CLIENT,
        default: None,
        doc: "Headers sent with every request, in order. They replace the profile's header of \
              the same name at its browser position; a name given twice is sent once, with the \
              last value.",
        cli: short_flag('H', "header", "NAME: VALUE", CliForm::Repeated),
    },
    OptionSpec {
        name: "headers",
        kind: Kind::Headers,
        scopes: REQUEST,
        default: None,
        doc: "Headers of this request, in order. They replace client and profile headers of \
              the same name, which keep their browser position.",
        cli: None,
    },
    OptionSpec {
        name: "follow_redirects",
        kind: Kind::Bool,
        scopes: CLIENT,
        default: Some(DefaultValue::Bool(true)),
        doc: "Follow redirects.",
        cli: flag("no-follow", "", CliForm::Off("Don't follow redirects")),
    },
    OptionSpec {
        name: "max_redirects",
        kind: Kind::Count,
        scopes: CLIENT,
        default: Some(DefaultValue::Number("10")),
        doc: "Maximum number of redirects to follow.",
        cli: flag("max-redirects", "N", CliForm::Value),
    },
    OptionSpec {
        name: "cookie_jar",
        kind: Kind::Bool,
        scopes: CLIENT,
        default: Some(DefaultValue::Bool(true)),
        doc: "Keep cookies across requests.",
        cli: flag("no-cookies", "", CliForm::Off("Disable the cookie jar")),
    },
    OptionSpec {
        name: "session_resumption",
        kind: Kind::Bool,
        scopes: CONNECTION,
        default: Some(DefaultValue::Bool(true)),
        doc: "Resume TLS sessions.",
        cli: flag(
            "no-session-resumption",
            "",
            CliForm::Off("Don't resume TLS sessions"),
        ),
    },
    OptionSpec {
        name: "doh",
        kind: Kind::Doh,
        scopes: CONNECTION,
        default: None,
        doc: "DNS-over-HTTPS provider, any case: `cloudflare` or `google`.",
        cli: flag("doh", "PROVIDER", CliForm::Value),
    },
    OptionSpec {
        name: "local_address",
        kind: Kind::Address,
        scopes: CONNECTION,
        default: None,
        doc: "Local IP address outgoing connections are bound to.",
        cli: flag("local-address", "ADDR", CliForm::Value),
    },
    OptionSpec {
        name: "on_request",
        kind: Kind::Hook(Hook::Request),
        scopes: CLIENT,
        default: None,
        doc: "Called before each request, including each redirect hop, with the method and URL. \
              An error it raises fails the request before it is sent.",
        cli: None,
    },
    OptionSpec {
        name: "on_response",
        kind: Kind::Hook(Hook::Response),
        scopes: CLIENT,
        default: None,
        doc: "Called after each response, including each redirect hop, once its cookies are \
              stored, with the status, URL and headers. An error it raises fails the request.",
        cli: None,
    },
    OptionSpec {
        name: "on_redirect",
        kind: Kind::Hook(Hook::Redirect),
        scopes: CLIENT,
        default: None,
        doc: "Called before a redirect is followed, with the status, URL and headers. Return \
              {false} to stop and get the 3xx response; any other value follows it. An error it \
              raises fails the request.",
        cli: None,
    },
    OptionSpec {
        name: "retries",
        kind: Kind::Count,
        scopes: CONNECTION,
        default: Some(DefaultValue::Number("0")),
        doc: "Automatic retries on transport errors. With {proxies}, each retry takes the next \
              proxy. A request that may already have reached the server is retried only for \
              idempotent methods.",
        cli: flag("retries", "N", CliForm::Value),
    },
    OptionSpec {
        name: "locale",
        kind: Kind::Text,
        scopes: CONNECTION,
        default: None,
        doc: "The user's language, such as `de-AT`, to match the proxy's country. The \
              Accept-Language header becomes what the profile's browser sends for it: Chrome \
              the list of the UI language it picks (`de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7`), \
              Safari `de-DE,de;q=0.9`.",
        cli: flag("locale", "LANG", CliForm::Value),
    },
    OptionSpec {
        name: "proxy_headers",
        kind: Kind::Headers,
        scopes: CONNECTION,
        default: None,
        doc: "Headers of the HTTP CONNECT request to the proxy, in order: session IDs, \
              geo-targeting, authentication.",
        cli: flag("proxy-header", "NAME: VALUE", CliForm::Repeated),
    },
    OptionSpec {
        name: "ip_version",
        kind: Kind::IpVersion,
        scopes: CONNECTION,
        default: None,
        doc: "Resolve hosts to IPv4 (`4`) or IPv6 (`6`) only, e.g. for a proxy that speaks \
              IPv4 alone. `v4`, `ipv6` and the like work too.",
        cli: flag("ip-version", "VERSION", CliForm::Value),
    },
    OptionSpec {
        name: "resolve",
        kind: Kind::Texts,
        scopes: CONNECTION,
        default: None,
        doc: "Entries in curl's `--resolve` format, `host:port:address[,address...]` (IPv6 in \
              brackets): requests to that host and port connect to the address instead of \
              resolving the host. The TLS server name, Host header and cookies stay the host's. \
              An invalid entry fails with {error:INVALID_ARGUMENT}.",
        cli: flag("resolve", "HOST:PORT:ADDR", CliForm::Repeated),
    },
    OptionSpec {
        name: "max_response_body",
        kind: Kind::Size,
        scopes: CONNECTION,
        default: Some(DefaultValue::Words("100 MiB")),
        doc: "Maximum response body size in bytes, decompressed: past it, a response fails with \
              {error:BODY_ERROR} instead of growing the buffer further, also when a compressed \
              body decodes past it. Reading a streaming response chunk by chunk without decoding \
              it is not capped. `0` disables it.",
        cli: flag("max-response-body", "BYTES", CliForm::Value),
    },
    OptionSpec {
        name: "server_padding",
        kind: Kind::ServerPadding,
        scopes: CONNECTION,
        default: None,
        doc: "Pins Chrome 151+'s `PqcBandwidthExperiment` server-padding field trial group \
              instead of drawing one when the client is built: `none` (not in the study) or the \
              bytes of padding the group asks for (e.g. `6000`). The study ended on 2026-10-30, \
              so a client no longer draws one. No effect on a profile without the trial.",
        cli: flag("server-padding", "none|BYTES", CliForm::Value),
    },
    OptionSpec {
        name: "timeout",
        kind: Kind::Seconds,
        scopes: REQUEST,
        default: None,
        doc: "Timeout of this request in seconds, fractions allowed; a streaming request times \
              the response head and then each wait for the body. `0` means no timeout.",
        cli: None,
    },
    OptionSpec {
        name: "proxy",
        kind: Kind::Text,
        scopes: REQUEST,
        default: None,
        doc: "Proxy URL for this request, in place of the client's proxies.",
        cli: None,
    },
    OptionSpec {
        name: "follow_redirects",
        kind: Kind::Bool,
        scopes: REQUEST,
        default: None,
        doc: "Follow redirects in this request.",
        cli: None,
    },
    OptionSpec {
        name: "max_redirects",
        kind: Kind::Count,
        scopes: REQUEST,
        default: None,
        doc: "Maximum number of redirects this request follows.",
        cli: None,
    },
    OptionSpec {
        name: "on_request",
        kind: Kind::Hook(Hook::Request),
        scopes: REQUEST,
        default: None,
        doc: "Called before each request of this call, including each redirect hop, in place \
              of the client's.",
        cli: None,
    },
    OptionSpec {
        name: "on_response",
        kind: Kind::Hook(Hook::Response),
        scopes: REQUEST,
        default: None,
        doc: "Called after each response of this call, including each redirect hop, in place \
              of the client's.",
        cli: None,
    },
    OptionSpec {
        name: "on_redirect",
        kind: Kind::Hook(Hook::Redirect),
        scopes: REQUEST,
        default: None,
        doc: "Called before a redirect of this call is followed, in place of the client's. \
              Return {false} to stop.",
        cli: None,
    },
    OptionSpec {
        name: "decode",
        kind: Kind::Bool,
        scopes: STREAM,
        default: Some(DefaultValue::Bool(true)),
        doc: "Decode the body's Content-Encoding (gzip, deflate, br, zstd and stacked codings) \
              as it is read; a coding koon does not know arrives as it is. {false} gives the \
              bytes as sent. The headers stay as received either way, Content-Encoding and \
              Content-Length included.",
        cli: None,
    },
    OptionSpec {
        name: "listen_addr",
        kind: Kind::Text,
        scopes: PROXY,
        default: Some(DefaultValue::Text("127.0.0.1:0")),
        doc: "Address to listen on; port `0` picks a free one.",
        cli: flag("listen", "ADDR", CliForm::Value),
    },
    OptionSpec {
        name: "header_mode",
        kind: Kind::HeaderMode,
        scopes: PROXY,
        default: Some(DefaultValue::Text("impersonate")),
        doc: "How the headers of the proxy's clients are sent on, any case: `impersonate` sends \
              them as the profile's browser does, with its identity headers in place of the \
              client's (its Accept-Language from {locale}), `passthrough` as they came, only \
              TLS and HTTP/2 fingerprinted.",
        cli: flag("header-mode", "MODE", CliForm::Value),
    },
    OptionSpec {
        name: "ca_dir",
        kind: Kind::Text,
        scopes: PROXY,
        default: Some(DefaultValue::Text("~/.koon/ca")),
        doc: "Directory of the proxy's CA certificate.",
        cli: flag("ca-dir", "DIR", CliForm::Value),
    },
    OptionSpec {
        name: "timeout",
        kind: Kind::Seconds,
        scopes: PROXY,
        default: Some(DefaultValue::Number("30")),
        doc: "Timeout in seconds, fractions allowed, of a forwarded request's response head and \
              of each wait for its body. `0` means no timeout.",
        cli: flag("timeout", "SECONDS", CliForm::Value),
    },
    OptionSpec {
        name: "allow_non_loopback",
        kind: Kind::Bool,
        scopes: PROXY,
        default: Some(DefaultValue::Bool(false)),
        doc: "Allow {listen_addr} to be a non-loopback address. The proxy has no transport \
              encryption of its own between it and its clients, so on a reachable interface it \
              is an open relay for anyone who can reach the port, unless {auth} is set too.",
        cli: flag("allow-non-loopback", "", CliForm::Switch),
    },
    OptionSpec {
        name: "auth",
        kind: Kind::Auth,
        scopes: PROXY,
        default: None,
        doc: "`Proxy-Authorization: Basic` credentials every client of the proxy must send.",
        cli: flag("auth", "USER:PASS", CliForm::Value),
    },
    OptionSpec {
        name: "max_connections",
        kind: Kind::Size,
        scopes: PROXY,
        default: Some(DefaultValue::Number("512")),
        doc: "Connections accepted at once; further ones wait for a slot to free up.",
        cli: flag("max-connections", "N", CliForm::Value),
    },
];
