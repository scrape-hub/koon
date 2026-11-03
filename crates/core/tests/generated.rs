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

#[test]
fn generated_files_are_current() {
    let stale: Vec<String> = [node()].into_iter().filter_map(Result::err).collect();
    assert!(
        stale.is_empty(),
        "{}; run `KOON_BLESS=1 cargo test -p koon-core --test generated`",
        stale.join(", ")
    );
}
