//! The option docs and types of the bindings, generated from `koon_core::options::OPTIONS`.
//! The test fails when a generated part is out of date; `KOON_BLESS=1` rewrites it.

use std::path::{Path, PathBuf};

use koon_core::options::{DefaultValue, Hook, Kind, OptionSpec, Scope, Target, options_in, render};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Replaces the lines between the markers `begin` and `end` of `path` with `generated`; the
/// error names the file when it differs and `KOON_BLESS` is not set.
fn update(path: &str, begin: &str, end: &str, generated: &str) -> Result<(), String> {
    let file = repo().join(path);
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{path}: {e}"))?;
    let missing = |marker: &str| format!("{path}: no marker {marker}");
    let begin_at = text.find(begin).ok_or_else(|| missing(begin))?;
    // From the line after `begin` to the start of the line of `end`.
    let start = begin_at + text[begin_at..].find('\n').ok_or_else(|| missing(begin))? + 1;
    let end_at = start + text[start..].find(end).ok_or_else(|| missing(end))?;
    let stop = text[..end_at].rfind('\n').map_or(0, |n| n + 1).max(start);
    let updated = format!("{}{generated}{}", &text[..start], &text[stop..]);
    if updated == text {
        return Ok(());
    }
    if std::env::var_os("KOON_BLESS").is_some() {
        std::fs::write(&file, updated).map_err(|e| format!("{path}: {e}"))?;
        return Ok(());
    }
    Err(format!("{path} is out of date"))
}

/// `text` wrapped at `width` columns, each line after `indent`.
fn wrap(text: &str, width: usize, indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && indent.len() + line.len() + 1 + word.len() > width {
            lines.push(format!("{indent}{line}"));
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(format!("{indent}{line}"));
    }
    lines
}

fn default_text(default: Option<DefaultValue>, target: Target) -> Option<String> {
    Some(match default? {
        DefaultValue::Bool(b) => match target {
            Target::Python => format!("``{}``", if b { "True" } else { "False" }),
            Target::R => format!("`{}`", if b { "TRUE" } else { "FALSE" }),
            _ => format!("`{b}`"),
        },
        DefaultValue::Number(n) => n.to_string(),
        DefaultValue::Text(t) => match target {
            Target::Python => format!("``\"{t}\"``"),
            _ => format!("`\"{t}\"`"),
        },
        DefaultValue::Words(w) => w.to_string(),
    })
}

/// The doc of `spec` with its default, as `target` writes it.
fn doc_with_default(spec: &OptionSpec, target: Target) -> String {
    let doc = render(spec.doc, target);
    match default_text(spec.default, target) {
        Some(default) => format!("{doc} Default: {default}."),
        None => doc,
    }
}

// --- Node ---------------------------------------------------------------------------------------

const NODE_WIDTH: usize = 100;

fn ts_type(kind: Kind) -> &'static str {
    match kind {
        Kind::Browser => "Browser",
        Kind::Bool => "boolean",
        Kind::Count | Kind::Size | Kind::Seconds => "number",
        Kind::ProfileJson | Kind::Text | Kind::Address | Kind::Doh => "string",
        Kind::Texts => "string[]",
        Kind::Headers => "KoonHeadersInit",
        Kind::Pem => "string | Buffer",
        Kind::IpVersion => "4 | 6 | string",
        Kind::HeaderMode => "'impersonate' | 'passthrough'",
        Kind::ServerPadding => "string | number",
        Kind::Auth => "KoonProxyAuth",
        Kind::Hook(Hook::Request) => "OnRequestHook",
        Kind::Hook(Hook::Response) => "OnResponseHook",
        Kind::Hook(Hook::Redirect) => "OnRedirectHook",
    }
}

fn ts_doc(out: &mut String, indent: &str, text: &str) {
    let single = format!("{indent}/** {text} */");
    if single.len() <= NODE_WIDTH {
        out.push_str(&single);
        out.push('\n');
        return;
    }
    out.push_str(&format!("{indent}/**\n"));
    for line in wrap(text, NODE_WIDTH, &format!("{indent} * ")) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!("{indent} */\n"));
}

fn ts_interface(
    out: &mut String,
    name: &str,
    doc: Option<&str>,
    extends: Option<(&str, Scope)>,
    scope: Scope,
) {
    if let Some(doc) = doc {
        ts_doc(out, "", doc);
    }
    match extends {
        Some((parent, _)) => {
            out.push_str(&format!("export interface {name} extends {parent} {{\n"))
        }
        None => out.push_str(&format!("export interface {name} {{\n")),
    }
    for spec in options_in(scope) {
        if extends.is_some_and(|(_, parent)| spec.applies(parent)) {
            continue;
        }
        ts_doc(out, "  ", &doc_with_default(spec, Target::Node));
        out.push_str(&format!(
            "  {}?: {};\n",
            spec.key(Target::Node),
            ts_type(spec.kind)
        ));
    }
    out.push_str("}\n");
}

fn node() -> Result<(), String> {
    let mut out = String::new();
    ts_interface(
        &mut out,
        "KoonOptions",
        Some("Options of `new Koon()`."),
        None,
        Scope::Client,
    );
    out.push('\n');
    ts_interface(
        &mut out,
        "KoonRequestOptions",
        Some(
            "Options of one request (every verb, `postMultipart()`, `requestStreaming()`); unset \
             ones fall back to the client's.",
        ),
        None,
        Scope::Request,
    );
    out.push('\n');
    ts_interface(
        &mut out,
        "KoonStreamingOptions",
        None,
        Some(("KoonRequestOptions", Scope::Request)),
        Scope::Stream,
    );
    out.push('\n');
    ts_interface(
        &mut out,
        "KoonProxyOptions",
        Some(
            "Options of `KoonProxy.start()`. The forwarded requests connect as those of a `Koon` \
             client do; the proxy follows no redirects and keeps no cookies, the proxied client \
             does both itself.",
        ),
        None,
        Scope::Proxy,
    );
    out.push('\n');
    ts_interface(
        &mut out,
        "KoonVerifyOptions",
        Some("Options of `Koon.verify()`: how its client connects to the fingerprint services."),
        None,
        Scope::Verify,
    );
    update(
        "crates/node/index.d.ts",
        "// BEGIN GENERATED options",
        "// END GENERATED options",
        &out,
    )
}

// --- Python -------------------------------------------------------------------------------------

const PYTHON_WIDTH: usize = 88;
const PYI: &str = "crates/python/python/koon/__init__.pyi";

fn py_type(kind: Kind) -> &'static str {
    match kind {
        Kind::Browser | Kind::ProfileJson | Kind::Text | Kind::Doh | Kind::HeaderMode => "str",
        Kind::Bool => "bool",
        Kind::Count | Kind::Size => "int",
        Kind::Seconds => "float",
        Kind::Texts => "Sequence[str]",
        Kind::Headers => "HeaderInput",
        Kind::Pem => "Union[str, bytes]",
        Kind::Address => "LocalAddress",
        Kind::IpVersion => "Union[int, str]",
        Kind::ServerPadding => "Union[str, int]",
        Kind::Auth => "Tuple[str, str]",
        Kind::Hook(Hook::Request) => "Callable[[str, str], None]",
        Kind::Hook(Hook::Response) => "Callable[[int, str, Sequence[Tuple[str, str]]], None]",
        Kind::Hook(Hook::Redirect) => {
            "Callable[[int, str, Sequence[Tuple[str, str]]], Optional[bool]]"
        }
    }
}

/// The default a Python signature shows: the value itself where Python can write it.
fn py_default(spec: &OptionSpec) -> String {
    match spec.default {
        Some(DefaultValue::Bool(b)) => (if b { "True" } else { "False" }).to_string(),
        Some(DefaultValue::Number(n)) => n.to_string(),
        Some(DefaultValue::Text(t)) => format!("\"{t}\""),
        Some(DefaultValue::Words(_)) | None => "None".to_string(),
    }
}

fn py_params(out: &mut String, indent: &str, scope: Scope, skip: &[&str]) {
    for spec in options_in(scope) {
        if skip.contains(&spec.name) {
            continue;
        }
        out.push_str(&format!(
            "{indent}{}: Optional[{}] = {},\n",
            spec.name,
            py_type(spec.kind),
            py_default(spec)
        ));
    }
}

/// The `Args:` section of a docstring for the options of `scope`.
fn py_args(out: &mut String, indent: &str, scope: Scope) {
    out.push_str(&format!("{indent}Args:\n"));
    for spec in options_in(scope) {
        let text = format!("{}: {}", spec.name, doc_with_default(spec, Target::Python));
        let lines = wrap(&text, PYTHON_WIDTH, &format!("{indent}        "));
        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                out.push_str(&format!("{indent}    {}\n", line.trim_start()));
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
}

fn py_paragraph(out: &mut String, indent: &str, text: &str) {
    for line in wrap(text, PYTHON_WIDTH, indent) {
        out.push_str(&line);
        out.push('\n');
    }
}

/// A TypedDict of the options of `scope`, without those of `parent` and the `params` of the
/// function it is unpacked into.
fn py_typed_dict(
    out: &mut String,
    name: &str,
    base: &str,
    doc: &str,
    scope: Scope,
    parent: Option<Scope>,
    params: &[&str],
) {
    out.push_str(&format!("class {name}({base}, total=False):\n"));
    out.push_str("    \"\"\"");
    let lines = wrap(doc, PYTHON_WIDTH, "    ");
    out.push_str(lines.join("\n").trim_start());
    out.push_str("\"\"\"\n\n");
    for spec in options_in(scope) {
        if parent.is_some_and(|parent| spec.applies(parent)) || params.contains(&spec.name) {
            continue;
        }
        out.push_str(&format!(
            "    {}: Optional[{}]\n",
            spec.name,
            py_type(spec.kind)
        ));
    }
}

const PY_OPTIONS_NOTE: &str = "An option left ``None`` keeps its default. An invalid value raises \
                               ``KoonInvalidArgument``, an unknown option or a value of the wrong \
                               type ``TypeError``.";

fn python() -> Result<(), String> {
    let mut dicts = String::new();
    py_typed_dict(
        &mut dicts,
        "RequestOptions",
        "TypedDict",
        "Per-request keyword options every verb (``get`` through ``request_streaming``) accepts; \
         unset ones fall back to the client's. See ``Koon.__init__`` for what each one does.",
        Scope::Request,
        None,
        &[],
    );
    dicts.push('\n');
    py_typed_dict(
        &mut dicts,
        "StreamingOptions",
        "RequestOptions",
        "The keyword options of ``request_streaming``: those of every request, and ``decode``.",
        Scope::Stream,
        Some(Scope::Request),
        &[],
    );
    dicts.push('\n');
    py_typed_dict(
        &mut dicts,
        "VerifyOptions",
        "TypedDict",
        "The keyword options of ``verify``: how its client connects to the fingerprint services, \
         as for ``Koon``.",
        Scope::Verify,
        None,
        &["browser"],
    );

    let mut init = String::new();
    init.push_str("    def __init__(\n        self,\n        browser: Optional[str] = \"chrome\",\n        *,\n");
    py_params(&mut init, "        ", Scope::Client, &["browser"]);
    init.push_str("    ) -> None:\n");
    init.push_str(
        "        \"\"\"Create a new Koon HTTP client with browser fingerprint impersonation.\n\n",
    );
    py_paragraph(&mut init, "        ", PY_OPTIONS_NOTE);
    init.push('\n');
    py_args(&mut init, "        ", Scope::Client);
    init.push_str("        \"\"\"\n        ...\n");

    let mut sync_init = String::new();
    sync_init.push_str("    def __init__(\n        self,\n        browser: Optional[str] = \"chrome\",\n        *,\n");
    py_params(&mut sync_init, "        ", Scope::Client, &["browser"]);
    sync_init.push_str("    ) -> None: ...\n");

    let mut start = String::new();
    start.push_str("    @staticmethod\n    async def start(\n        *,\n");
    py_params(&mut start, "        ", Scope::Proxy, &[]);
    start.push_str("    ) -> \"KoonProxy\":\n");
    start.push_str("        \"\"\"Start a new MITM proxy server.\n\n");
    py_paragraph(
        &mut start,
        "        ",
        "The forwarded requests connect as those of a ``Koon`` client do; the proxy follows no \
         redirects and keeps no cookies, the proxied client does both itself. ",
    );
    start.push('\n');
    py_paragraph(&mut start, "        ", PY_OPTIONS_NOTE);
    start.push('\n');
    py_args(&mut start, "        ", Scope::Proxy);
    start.push_str("        \"\"\"\n        ...\n");

    let parts = [
        (
            "# BEGIN GENERATED option dicts",
            "# END GENERATED option dicts",
            dicts,
        ),
        (
            "    # BEGIN GENERATED Koon.__init__",
            "    # END GENERATED Koon.__init__",
            init,
        ),
        (
            "    # BEGIN GENERATED KoonSync.__init__",
            "    # END GENERATED KoonSync.__init__",
            sync_init,
        ),
        (
            "    # BEGIN GENERATED KoonProxy.start",
            "    # END GENERATED KoonProxy.start",
            start,
        ),
    ];
    parts
        .iter()
        .try_for_each(|(begin, end, text)| update(PYI, begin, end, text))
}

// --- R ------------------------------------------------------------------------------------------

const R_WIDTH: usize = 80;
const KOON_R: &str = "crates/r/R/koon.R";

/// The constructor's arguments in the order `Koon$new()` took them before the option table, so an
/// argument given by position stays where it was; the others follow in table order.
const R_CLIENT_ORDER: &[&str] = &[
    "browser",
    "profile_json",
    "proxy",
    "proxies",
    "timeout",
    "headers",
    "local_address",
    "on_request",
    "on_response",
    "on_redirect",
    "retries",
    "locale",
    "proxy_headers",
    "ip_version",
    "follow_redirects",
    "max_redirects",
    "cookie_jar",
    "session_resumption",
    "ignore_tls_errors",
    "proxy_ca_certs",
    "ignore_proxy_tls_errors",
    "doh",
    "resolve",
    "max_response_body",
    "server_padding",
];

fn r_options(scope: Scope, order: &[&str]) -> Vec<&'static OptionSpec> {
    let mut specs: Vec<_> = options_in(scope).collect();
    specs.sort_by_key(|spec| {
        order
            .iter()
            .position(|name| *name == spec.name)
            .unwrap_or(usize::MAX)
    });
    specs
}

/// What R takes for a kind, where the doc does not say it.
fn r_note(kind: Kind) -> Option<&'static str> {
    Some(match kind {
        Kind::Headers => {
            "A named character vector or a named list of single strings, e.g. \
             `c(\"Accept-Language\" = \"de-DE\")`."
        }
        Kind::Pem => "PEM text, e.g. `readLines(\"proxy-ca.pem\")`, or a raw vector.",
        Kind::Hook(Hook::Request) => "A `function(method, url)`.",
        Kind::Hook(Hook::Response | Hook::Redirect) => {
            "A `function(status, url, headers)`, `headers` a data frame like the response's."
        }
        Kind::Auth => "`c(user, password)`.",
        _ => return None,
    })
}

fn r_items(out: &mut String, specs: &[&OptionSpec]) {
    out.push_str("#' \\describe{\n");
    for spec in specs {
        let mut text = render(spec.doc, Target::R);
        if let Some(note) = r_note(spec.kind) {
            text = format!("{text} {note}");
        }
        if let Some(default) = default_text(spec.default, Target::R) {
            text = format!("{text} Default {default}.");
        }
        let item = format!("\\item{{`{}`}}{{{text}}}", spec.name);
        for (i, line) in wrap(&item, R_WIDTH, "#'     ").into_iter().enumerate() {
            if i == 0 {
                out.push_str(&format!("#'   {}\n", &line["#'     ".len()..]));
            } else {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    out.push_str("#' }\n");
}

/// An R function `name` that passes `fixed` and the options of `specs` as a named list to the
/// native `symbol`, after `before` (such as `self`).
fn r_function(
    out: &mut String,
    name: &str,
    fixed: &[(&str, Option<&str>)],
    symbol: &str,
    before: &[&str],
    specs: &[&OptionSpec],
) {
    out.push_str(&format!("{name} <- function(\n"));
    let params: Vec<String> = fixed
        .iter()
        .map(|(param, default)| match default {
            Some(default) => format!("{param} = {default}"),
            None => (*param).to_string(),
        })
        .chain(specs.iter().map(|spec| format!("{} = NULL", spec.name)))
        .collect();
    out.push_str(&format!("  {}\n", params.join(",\n  ")));
    out.push_str(") {\n  koon_unwrap(.Call(\n");
    for arg in std::iter::once(symbol)
        .chain(before.iter().copied())
        .chain(fixed.iter().map(|(param, _)| *param))
    {
        out.push_str(&format!("    {arg},\n"));
    }
    out.push_str("    list(\n");
    let entries: Vec<String> = specs
        .iter()
        .map(|spec| format!("      {0} = {0}", spec.name))
        .collect();
    out.push_str(&entries.join(",\n"));
    out.push_str("\n    )\n  ))\n}\n");
}

fn r() -> Result<(), String> {
    let client: Vec<_> = r_options(Scope::Client, R_CLIENT_ORDER);
    let request: Vec<_> = r_options(Scope::Request, &[]);

    let mut docs = String::new();
    docs.push_str("#' @section Constructor arguments:\n");
    docs.push_str(
        "#' `Koon$new()` takes the following arguments. Any left `NULL` keeps its\n#' default.\n",
    );
    r_items(&mut docs, &client);
    docs.push_str("#'\n#' @section Request options:\n");
    docs.push_str(
        "#' `$request()` and the verbs (`$get()`, `$post()`, ...) take these options for\n\
         #' one request. Any left `NULL` keeps the client's setting.\n",
    );
    r_items(&mut docs, &request);
    docs.push_str("#' @name Koon\n#' @rdname Koon\nNULL\n");

    let mut functions = String::new();
    let browser = client.iter().position(|spec| spec.name == "browser");
    let options: Vec<_> = client
        .iter()
        .enumerate()
        .filter(|(i, _)| Some(*i) != browser)
        .map(|(_, spec)| *spec)
        .collect();
    r_function(
        &mut functions,
        "Koon$new",
        &[("browser", Some("\"chrome\""))],
        "wrap__Koon__new",
        &[],
        &options,
    );
    functions.push('\n');
    r_function(
        &mut functions,
        "Koon$request",
        &[("method", None), ("url", None), ("body", Some("NULL"))],
        "wrap__Koon__request",
        &["self"],
        &request,
    );

    update(
        KOON_R,
        "# BEGIN GENERATED docs",
        "# END GENERATED docs",
        &docs,
    )?;
    update(
        KOON_R,
        "# BEGIN GENERATED functions",
        "# END GENERATED functions",
        &functions,
    )
}

#[test]
fn generated_files_are_current() {
    let stale: Vec<String> = [node(), python(), r()]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    assert!(
        stale.is_empty(),
        "{}; run `KOON_BLESS=1 cargo test -p koon-core --test generated`",
        stale.join(", ")
    );
}
