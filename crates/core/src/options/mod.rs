//! Every option the bindings and the CLI take, described once in [`OPTIONS`]: name, kind, scopes,
//! default and documentation. A binding turns its native values into [`Value`]s and hands them to
//! [`Options`], which checks them, applies the defaults and builds the client, request or proxy
//! configuration; the type stubs, the binding docs and the CLI flags come from [`OPTIONS`] too.

mod doc;
mod table;

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

pub use doc::render;
pub use table::OPTIONS;

#[cfg(feature = "doh")]
use crate::dns::DohConfig;
use crate::error::Error;
use crate::profile::{BrowserProfile, ServerPadding};
use crate::proxy::{HeaderMode, ProxyServerAuth, ProxyServerConfig};
use crate::{
    ClientBuilder, ConnectionOptions, IpVersion, OnRedirectHook, OnRequestHook, OnResponseHook,
    RequestOptions,
};

/// Where an option applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// A client's constructor.
    Client,
    /// One request (every verb and `post_multipart`).
    Request,
    /// One streaming request.
    Stream,
    /// The MITM proxy's constructor.
    Proxy,
    /// `verify`, which builds a client of its own.
    Verify,
}

/// The value an option takes; it decides the [`Value`]s accepted and the type in each binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A browser profile name.
    Browser,
    /// A browser profile as JSON.
    ProfileJson,
    Bool,
    /// A whole number >= 0 that fits `u32`.
    Count,
    /// A number of bytes >= 0.
    Size,
    /// A number of seconds >= 0, fractions allowed.
    Seconds,
    Text,
    /// A list of strings; a single string is a list of one.
    Texts,
    /// Header name and value pairs, in order.
    Headers,
    /// PEM text or bytes; a list of strings is joined line by line.
    Pem,
    /// An IP address.
    Address,
    /// `4` or `6`, or a name such as `"v4"` or `"ipv6"`.
    IpVersion,
    /// A DNS-over-HTTPS provider by name.
    Doh,
    /// The MITM proxy's header mode by name.
    HeaderMode,
    /// `"none"` or a number of bytes.
    ServerPadding,
    /// A user name and password.
    Auth,
    /// A callback, which the binding wraps itself.
    Hook(Hook),
}

/// The callback an option of [`Kind::Hook`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Request,
    Response,
    Redirect,
}

/// An option's documented default, written as each binding writes such a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    Bool(bool),
    /// A number, as written in docs and CLI defaults (`"30"`).
    Number(&'static str),
    Text(&'static str),
    /// A size in words (`"100 MiB"`), documented but not a CLI default.
    Words(&'static str),
}

/// How the CLI takes an option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliForm {
    /// `--name VALUE`.
    Value,
    /// `--name` sets the option to true.
    Switch,
    /// `--no-name` sets the option to false; the help text, since the option's doc describes it
    /// on.
    Off(&'static str),
    /// `--name VALUE`, repeatable.
    Repeated,
    /// `--name A,B`, repeatable.
    List,
    /// `--name FILE`: the option is the file's content.
    File,
}

/// An option's CLI flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CliFlag {
    /// The long flag without its dashes.
    pub long: &'static str,
    pub short: Option<char>,
    /// The placeholder in `--help`; empty for switches.
    pub value_name: &'static str,
    pub form: CliForm,
}

/// One option in the scopes it applies to. A name may appear more than once, with disjoint scopes,
/// where its meaning differs between them.
#[derive(Debug)]
pub struct OptionSpec {
    /// The option's name, snake case.
    pub name: &'static str,
    pub kind: Kind,
    pub scopes: &'static [Scope],
    pub default: Option<DefaultValue>,
    /// The documentation, in the markup [`render`] takes; its first sentence is the summary.
    pub doc: &'static str,
    pub cli: Option<CliFlag>,
}

impl OptionSpec {
    /// The option's name as `target` writes it.
    pub fn key(&self, target: Target) -> Cow<'static, str> {
        match target {
            Target::Node => Cow::Owned(camel_case(self.name)),
            Target::Python | Target::R => Cow::Borrowed(self.name),
            Target::Cli => Cow::Owned(self.cli.map_or_else(
                || format!("--{}", self.name.replace('_', "-")),
                |flag| format!("--{}", flag.long),
            )),
        }
    }

    /// Whether the option applies in `scope`.
    pub fn applies(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
}

/// The options of `scope`, in table order.
pub fn options_in(scope: Scope) -> impl Iterator<Item = &'static OptionSpec> {
    OPTIONS.iter().filter(move |spec| spec.applies(scope))
}

/// The front end an option is named, documented and reported for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Node,
    Python,
    R,
    Cli,
}

impl Target {
    /// `true`/`false` as the target writes them.
    pub(crate) const fn bool_literal(self, value: bool) -> &'static str {
        match (self, value) {
            (Self::Python, true) => "True",
            (Self::Python, false) => "False",
            (Self::R, true) => "TRUE",
            (Self::R, false) => "FALSE",
            (_, true) => "true",
            (_, false) => "false",
        }
    }
}

fn camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper = false;
    for c in snake.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.push(c.to_ascii_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// An option value as a binding hands it over, before it is checked against the option's kind.
pub enum Value {
    /// Unset (JS `undefined`/`null`, Python `None`, R `NULL`/`NA`): the default applies.
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Texts(Vec<String>),
    Bytes(Vec<u8>),
    /// Name and value pairs, in order: headers, or `username`/`password` for [`Kind::Auth`].
    Pairs(Vec<(String, String)>),
    RequestHook(OnRequestHook),
    ResponseHook(OnResponseHook),
    RedirectHook(OnRedirectHook),
    /// A value no option takes, such as a function where no hook is expected: it fails with
    /// [`OptionError::Type`] for every option.
    Other,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Int(n) => write!(f, "Int({n})"),
            Self::Float(n) => write!(f, "Float({n})"),
            Self::Text(s) => write!(f, "Text({s:?})"),
            Self::Texts(v) => write!(f, "Texts({v:?})"),
            Self::Bytes(b) => write!(f, "Bytes({} bytes)", b.len()),
            Self::Pairs(p) => write!(f, "Pairs({p:?})"),
            Self::RequestHook(_) | Self::ResponseHook(_) | Self::RedirectHook(_) => {
                f.write_str("Hook")
            }
            Self::Other => f.write_str("Other"),
        }
    }
}

/// Why an option was not taken.
#[derive(Debug)]
pub enum OptionError {
    /// No option of this name in the scope (Python reports it as a `TypeError`, as for an
    /// unexpected keyword argument).
    Unknown(String),
    /// A value of the wrong type.
    Type(String),
    /// A value of the right type that is not valid, with the core's error and code.
    Invalid(Error),
}

impl fmt::Display for OptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(message) | Self::Type(message) => f.write_str(message),
            Self::Invalid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OptionError {}

impl From<OptionError> for Error {
    fn from(error: OptionError) -> Self {
        match error {
            OptionError::Unknown(message) | OptionError::Type(message) => {
                Self::InvalidArgument(message, None)
            }
            OptionError::Invalid(error) => error,
        }
    }
}

fn invalid(message: String) -> OptionError {
    OptionError::Invalid(Error::InvalidArgument(message, None))
}

/// The options of one constructor or call, collected from a binding's values and checked one by
/// one: [`set`](Self::set) fails for an unknown name, a value of the wrong type and an invalid
/// value; the parts that need the others (proxy URLs, `resolve` entries, the PEM bundle) are
/// checked when the client is built. An option left unset keeps the core's default.
pub struct Options {
    scope: Scope,
    target: Target,
    browser: Option<String>,
    profile_json: Option<String>,
    connection: ConnectionOptions,
    timeout: Option<Duration>,
    headers: Option<Vec<(String, String)>>,
    proxy: Option<String>,
    follow_redirects: Option<bool>,
    max_redirects: Option<u32>,
    cookie_jar: Option<bool>,
    on_request: Option<OnRequestHook>,
    on_response: Option<OnResponseHook>,
    on_redirect: Option<OnRedirectHook>,
    decode: Option<bool>,
    listen_addr: Option<String>,
    header_mode: Option<HeaderMode>,
    ca_dir: Option<String>,
    allow_non_loopback: Option<bool>,
    auth: Option<ProxyServerAuth>,
    max_connections: Option<usize>,
}

impl Options {
    /// No options yet, for `scope`, named and reported as `target` writes them.
    pub fn new(scope: Scope, target: Target) -> Self {
        Self {
            scope,
            target,
            browser: None,
            profile_json: None,
            connection: ConnectionOptions::default(),
            timeout: None,
            headers: None,
            proxy: None,
            follow_redirects: None,
            max_redirects: None,
            cookie_jar: None,
            on_request: None,
            on_response: None,
            on_redirect: None,
            decode: None,
            listen_addr: None,
            header_mode: None,
            ca_dir: None,
            allow_non_loopback: None,
            auth: None,
            max_connections: None,
        }
    }

    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// The option `key` names in this scope (`maxRedirects` for Node, `max_redirects` for Python
    /// and R), or [`OptionError::Unknown`], which suggests the target's spelling of a name given
    /// in another binding's.
    pub fn spec(&self, key: &str) -> Result<&'static OptionSpec, OptionError> {
        let scope = self.scope;
        if let Some(spec) = options_in(scope).find(|spec| spec.key(self.target) == key) {
            return Ok(spec);
        }
        let hint = options_in(scope)
            .find(|spec| spec.name == key || camel_case(spec.name) == key)
            .map(|spec| format!(" (did you mean '{}'?)", spec.key(self.target)))
            .unwrap_or_default();
        Err(OptionError::Unknown(format!(
            "unknown option '{key}'{hint}"
        )))
    }

    /// Sets the option `key` names; [`Value::Null`] leaves it unset.
    pub fn set(&mut self, key: &str, value: Value) -> Result<(), OptionError> {
        let spec = self.spec(key)?;
        self.set_option(spec, value)
    }

    /// Sets `spec`, an option of this scope; [`Value::Null`] leaves it unset.
    pub fn set_option(
        &mut self,
        spec: &'static OptionSpec,
        value: Value,
    ) -> Result<(), OptionError> {
        debug_assert!(spec.applies(self.scope), "{} outside its scopes", spec.name);
        if matches!(value, Value::Null) {
            return Ok(());
        }
        let key = spec.key(self.target);
        let check = Check {
            key: &key,
            target: self.target,
        };
        match spec.name {
            "browser" => self.browser = Some(check.text(value)?),
            "profile_json" => self.profile_json = Some(check.text(value)?),
            "proxy" if self.scope == Scope::Request || self.scope == Scope::Stream => {
                self.proxy = Some(check.text(value)?);
            }
            "proxy" => self.connection.proxy = Some(check.text(value)?),
            "proxies" => self.connection.proxies = check.texts(value)?,
            "timeout" => self.timeout = Some(check.seconds(value)?),
            "ignore_tls_errors" => self.connection.ignore_tls_errors = check.bool(value)?,
            "proxy_ca_certs" => self.connection.proxy_ca_certs = Some(check.pem(value)?),
            "ignore_proxy_tls_errors" => {
                self.connection.ignore_proxy_tls_errors = check.bool(value)?;
            }
            "headers" => self.headers = Some(check.headers(value)?),
            "follow_redirects" => self.follow_redirects = Some(check.bool(value)?),
            "max_redirects" => self.max_redirects = Some(check.count(value)?),
            "cookie_jar" => self.cookie_jar = Some(check.bool(value)?),
            "session_resumption" => self.connection.session_resumption = check.bool(value)?,
            "doh" => self.set_doh(&check, value)?,
            "local_address" => self.connection.local_address = Some(check.address(value)?),
            "on_request" => self.on_request = Some(check.request_hook(value)?),
            "on_response" => self.on_response = Some(check.response_hook(value)?),
            "on_redirect" => self.on_redirect = Some(check.redirect_hook(value)?),
            "retries" => self.connection.retries = check.count(value)?,
            "locale" => self.connection.locale = Some(check.text(value)?),
            "proxy_headers" => self.connection.proxy_headers = check.headers(value)?,
            "ip_version" => self.connection.ip_version = Some(check.ip_version(value)?),
            "resolve" => self.connection.resolve = check.texts(value)?,
            "max_response_body" => self.connection.max_response_body = check.size(value)?,
            "server_padding" => self.connection.server_padding = Some(check.server_padding(value)?),
            "decode" => self.decode = Some(check.bool(value)?),
            "listen_addr" => self.listen_addr = Some(check.text(value)?),
            "header_mode" => self.header_mode = Some(check.parsed(value)?),
            "ca_dir" => self.ca_dir = Some(check.text(value)?),
            "allow_non_loopback" => self.allow_non_loopback = Some(check.bool(value)?),
            "auth" => self.auth = Some(check.auth(value)?),
            "max_connections" => {
                self.max_connections =
                    Some(usize::try_from(check.size(value)?).unwrap_or(usize::MAX));
            }
            other => unreachable!("option {other} has no setter"),
        }
        Ok(())
    }

    #[cfg(feature = "doh")]
    fn set_doh(&mut self, check: &Check<'_>, value: Value) -> Result<(), OptionError> {
        self.connection.doh = Some(check.parsed::<DohConfig>(value)?);
        Ok(())
    }

    #[cfg(not(feature = "doh"))]
    fn set_doh(&mut self, check: &Check<'_>, value: Value) -> Result<(), OptionError> {
        check.text(value)?;
        Err(invalid(format!(
            "{} needs koon built with the doh feature",
            check.key
        )))
    }

    /// The timeout given, else the table's default for this scope; none for a request, which keeps
    /// its client's.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.or_else(|| {
            options_in(self.scope)
                .find(|spec| spec.name == "timeout")
                .and_then(|spec| match spec.default {
                    Some(DefaultValue::Number(secs)) => {
                        secs.parse().ok().map(Duration::from_secs_f64)
                    }
                    _ => None,
                })
        })
    }

    /// The response body cap given, else the default.
    pub const fn max_response_body(&self) -> u64 {
        self.connection.max_response_body
    }

    /// The browser profile name given, else `"chrome"`.
    pub fn browser(&self) -> &str {
        self.browser.as_deref().unwrap_or("chrome")
    }

    /// The client hooks given; a binding that runs them itself takes them out before building.
    pub fn take_hooks(
        &mut self,
    ) -> (
        Option<OnRequestHook>,
        Option<OnResponseHook>,
        Option<OnRedirectHook>,
    ) {
        (
            self.on_request.take(),
            self.on_response.take(),
            self.on_redirect.take(),
        )
    }

    /// A client builder with every option of a [`Scope::Client`] or [`Scope::Verify`] call.
    pub fn client_builder(self) -> Result<ClientBuilder, Error> {
        let profile =
            BrowserProfile::from_name_or_json(self.browser(), self.profile_json.as_deref())?;
        let mut builder = self.connection.apply(profile)?;
        if let Some(headers) = self.headers {
            builder = builder.headers(headers);
        }
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(follow) = self.follow_redirects {
            builder = builder.follow_redirects(follow);
        }
        if let Some(max) = self.max_redirects {
            builder = builder.max_redirects(max);
        }
        if let Some(enabled) = self.cookie_jar {
            builder = builder.cookie_jar(enabled);
        }
        if let Some(hook) = self.on_request {
            builder = builder.on_request(move |method, url| hook(method, url));
        }
        if let Some(hook) = self.on_response {
            builder = builder.on_response(move |status, url, headers| hook(status, url, headers));
        }
        if let Some(hook) = self.on_redirect {
            builder = builder.on_redirect(move |status, url, headers| hook(status, url, headers));
        }
        Ok(builder)
    }

    /// Whether a [`Scope::Stream`] request decodes its body; true unless `decode` was false.
    pub fn decode(&self) -> bool {
        self.decode.unwrap_or(true)
    }

    /// The request options of a [`Scope::Request`] or [`Scope::Stream`] call.
    pub fn request_options(self) -> RequestOptions {
        RequestOptions {
            headers: self.headers.unwrap_or_default(),
            proxy: self.proxy,
            timeout: self.timeout,
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            on_request: self.on_request,
            on_response: self.on_response,
            on_redirect: self.on_redirect,
        }
    }

    /// The MITM proxy configuration of a [`Scope::Proxy`] call.
    pub fn proxy_config(self) -> Result<ProxyServerConfig, Error> {
        let defaults = ProxyServerConfig::default();
        let profile =
            BrowserProfile::from_name_or_json(self.browser(), self.profile_json.as_deref())?;
        let mut client = self.connection.apply(profile)?;
        if let Some(timeout) = self.timeout {
            client = client.timeout(timeout);
        }
        Ok(ProxyServerConfig {
            listen_addr: self.listen_addr.unwrap_or(defaults.listen_addr),
            header_mode: self.header_mode.unwrap_or(defaults.header_mode),
            ca_dir: self.ca_dir,
            client,
            allow_non_loopback: self
                .allow_non_loopback
                .unwrap_or(defaults.allow_non_loopback),
            auth: self.auth,
            max_connections: self.max_connections.unwrap_or(defaults.max_connections),
        })
    }
}

/// Checks one value against the kind its option takes, naming the option as the target does.
struct Check<'a> {
    key: &'a str,
    target: Target,
}

impl Check<'_> {
    fn wrong_type(&self, expected: &str) -> OptionError {
        OptionError::Type(format!("{} must be {expected}", self.key))
    }

    fn text(&self, value: Value) -> Result<String, OptionError> {
        match value {
            Value::Text(text) => Ok(text),
            Value::Texts(mut texts) if texts.len() == 1 => Ok(texts.remove(0)),
            _ => Err(self.wrong_type("a string")),
        }
    }

    fn texts(&self, value: Value) -> Result<Vec<String>, OptionError> {
        match value {
            Value::Texts(texts) => Ok(texts),
            Value::Text(text) => Ok(vec![text]),
            _ => Err(self.wrong_type("a list of strings")),
        }
    }

    fn bool(&self, value: Value) -> Result<bool, OptionError> {
        match value {
            Value::Bool(b) => Ok(b),
            _ => Err(self.wrong_type(&format!(
                "{} or {}",
                self.target.bool_literal(true),
                self.target.bool_literal(false)
            ))),
        }
    }

    /// A whole number >= 0 that fits `u64`; a float must be whole and below 2^53.
    fn whole(&self, value: Value) -> Result<u64, OptionError> {
        let expected = "a whole number >= 0";
        match value {
            Value::Int(n) => u64::try_from(n)
                .map_err(|_| invalid(format!("{} must be {expected}, not {n}", self.key))),
            Value::Float(n) => {
                if !(n >= 0.0 && n.fract() == 0.0) {
                    return Err(invalid(format!("{} must be {expected}, not {n}", self.key)));
                }
                if n > 9_007_199_254_740_992.0 {
                    return Err(invalid(format!("{} is too large: {n}", self.key)));
                }
                // Whole and below 2^53, so exact.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(n as u64)
            }
            _ => Err(self.wrong_type(expected)),
        }
    }

    fn count(&self, value: Value) -> Result<u32, OptionError> {
        let whole = self.whole(value)?;
        u32::try_from(whole).map_err(|_| invalid(format!("{} is too large: {whole}", self.key)))
    }

    fn size(&self, value: Value) -> Result<u64, OptionError> {
        self.whole(value)
    }

    fn seconds(&self, value: Value) -> Result<Duration, OptionError> {
        #[allow(clippy::cast_precision_loss)]
        let secs = match value {
            Value::Int(n) => n as f64,
            Value::Float(n) => n,
            _ => return Err(self.wrong_type("a number of seconds")),
        };
        Duration::try_from_secs_f64(secs).map_err(|_| {
            invalid(format!(
                "{} must be a finite number of seconds >= 0 (0 means no timeout), not {secs}",
                self.key
            ))
        })
    }

    fn headers(&self, value: Value) -> Result<Vec<(String, String)>, OptionError> {
        match value {
            Value::Pairs(pairs) => Ok(pairs),
            Value::Texts(texts) if texts.is_empty() => Ok(Vec::new()),
            _ => Err(self.wrong_type("headers: name and value pairs")),
        }
    }

    fn pem(&self, value: Value) -> Result<Vec<u8>, OptionError> {
        match value {
            Value::Text(text) => Ok(text.into_bytes()),
            Value::Bytes(bytes) => Ok(bytes),
            Value::Texts(lines) => Ok(lines.join("\n").into_bytes()),
            _ => Err(self.wrong_type("PEM text or bytes")),
        }
    }

    fn address(&self, value: Value) -> Result<IpAddr, OptionError> {
        let text = self
            .text(value)
            .map_err(|_| self.wrong_type("an IP address"))?;
        text.trim()
            .parse()
            .map_err(|_| invalid(format!("{} must be an IP address, not '{text}'", self.key)))
    }

    fn ip_version(&self, value: Value) -> Result<IpVersion, OptionError> {
        match value {
            Value::Int(_) | Value::Float(_) => {
                let version = self.whole(value)?;
                IpVersion::try_from(u8::try_from(version).unwrap_or(0))
                    .map_err(OptionError::Invalid)
            }
            Value::Text(_) | Value::Texts(_) => self.parsed(value),
            _ => Err(self.wrong_type("4 or 6")),
        }
    }

    fn server_padding(&self, value: Value) -> Result<ServerPadding, OptionError> {
        match value {
            Value::Int(_) | Value::Float(_) => {
                let bytes = self.whole(value)?;
                u16::try_from(bytes).map(ServerPadding::Bytes).map_err(|_| {
                    invalid(format!(
                        "{} must be 'none' or a number of bytes (0-65535), not {bytes}",
                        self.key
                    ))
                })
            }
            _ => self.parsed(value),
        }
    }

    /// A string the core parses (a DoH provider, a header mode, ...).
    fn parsed<T: std::str::FromStr<Err = Error>>(&self, value: Value) -> Result<T, OptionError> {
        self.text(value)?.parse().map_err(OptionError::Invalid)
    }

    fn auth(&self, value: Value) -> Result<ProxyServerAuth, OptionError> {
        let expected = "a user name and password";
        let (username, password) = match value {
            Value::Texts(texts) if texts.len() == 2 => {
                let mut texts = texts.into_iter();
                (
                    texts.next().unwrap_or_default(),
                    texts.next().unwrap_or_default(),
                )
            }
            Value::Text(text) => match text.split_once(':') {
                Some((user, pass)) => (user.to_string(), pass.to_string()),
                None => return Err(invalid(format!("{} must be USER:PASS", self.key))),
            },
            Value::Pairs(pairs) => {
                let field = |name: &str| {
                    pairs
                        .iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, v)| v.clone())
                };
                match (field("username"), field("password")) {
                    (Some(user), Some(pass)) if pairs.len() == 2 => (user, pass),
                    _ => return Err(self.wrong_type("{ username, password }")),
                }
            }
            _ => return Err(self.wrong_type(expected)),
        };
        Ok(ProxyServerAuth { username, password })
    }

    fn request_hook(&self, value: Value) -> Result<OnRequestHook, OptionError> {
        match value {
            Value::RequestHook(hook) => Ok(hook),
            _ => Err(self.wrong_type("a function")),
        }
    }

    fn response_hook(&self, value: Value) -> Result<OnResponseHook, OptionError> {
        match value {
            Value::ResponseHook(hook) => Ok(hook),
            _ => Err(self.wrong_type("a function")),
        }
    }

    fn redirect_hook(&self, value: Value) -> Result<OnRedirectHook, OptionError> {
        match value {
            Value::RedirectHook(hook) => Ok(hook),
            _ => Err(self.wrong_type("a function")),
        }
    }
}

#[cfg(test)]
mod tests;
