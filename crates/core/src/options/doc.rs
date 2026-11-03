//! The markup of option docs, rendered for each front end.

use super::{OPTIONS, Target};

/// `doc` as `target` writes it. The markup: `{name}` refers to the option `name`,
/// `{fn:export_profile}` to a client method, `{error:CODE}` to an error, `{true}` and `{false}`
/// are the boolean literals, and backticks mark code.
pub fn render(doc: &str, target: Target) -> String {
    let mut out = String::with_capacity(doc.len() + 16);
    let mut rest = doc;
    while let Some(start) = rest.find(['{', '`']) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let (open, close) = if tail.starts_with('{') {
            ('{', '}')
        } else {
            ('`', '`')
        };
        let Some(len) = tail[1..].find(close) else {
            out.push_str(tail);
            return out;
        };
        let inner = &tail[1..=len];
        if open == '{' {
            out.push_str(&reference(inner, target));
        } else {
            out.push_str(&code(inner, target));
        }
        rest = &tail[len + 2..];
    }
    out.push_str(rest);
    out
}

/// A code span.
fn code(text: &str, target: Target) -> String {
    match target {
        Target::Node | Target::R => format!("`{text}`"),
        Target::Python => format!("``{text}``"),
        Target::Cli => text.to_string(),
    }
}

/// A `{...}` reference.
fn reference(inner: &str, target: Target) -> String {
    if let Some(method) = inner.strip_prefix("fn:") {
        let name = match target {
            Target::Node => format!("{}()", super::camel_case(method)),
            Target::Python => format!("{method}()"),
            Target::R => format!("${method}()"),
            Target::Cli => format!("--{}", method.replace('_', "-")),
        };
        return code(&name, target);
    }
    if let Some(error) = inner.strip_prefix("error:") {
        return match target {
            Target::Python if error == "INVALID_ARGUMENT" => code("KoonInvalidArgument", target),
            Target::Python => format!(
                "{} (code {})",
                code("KoonError", target),
                code(error, target)
            ),
            Target::R => code(&format!("koon_{}", error.to_ascii_lowercase()), target),
            Target::Node | Target::Cli => code(error, target),
        };
    }
    match inner {
        "true" => return code(target.bool_literal(true), target),
        "false" => return code(target.bool_literal(false), target),
        _ => {}
    }
    let spec = OPTIONS
        .iter()
        .find(|spec| spec.name == inner)
        .unwrap_or_else(|| panic!("option docs refer to an unknown option {{{inner}}}"));
    code(&spec.key(target), target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_renders_for_each_target() {
        let doc = "See {proxy_ca_certs} and {fn:export_profile}; return {false}. `0` means none. \
                   Fails with {error:BODY_ERROR}.";
        assert_eq!(
            render(doc, Target::Node),
            "See `proxyCaCerts` and `exportProfile()`; return `false`. `0` means none. Fails \
             with `BODY_ERROR`."
        );
        assert_eq!(
            render(doc, Target::Python),
            "See ``proxy_ca_certs`` and ``export_profile()``; return ``False``. ``0`` means \
             none. Fails with ``KoonError`` (code ``BODY_ERROR``)."
        );
        assert_eq!(
            render(doc, Target::R),
            "See `proxy_ca_certs` and `$export_profile()`; return `FALSE`. `0` means none. \
             Fails with `koon_body_error`."
        );
        assert_eq!(
            render(doc, Target::Cli),
            "See --proxy-cacert and --export-profile; return false. 0 means none. Fails with \
             BODY_ERROR."
        );
    }

    #[test]
    fn every_reference_in_the_table_resolves() {
        for spec in OPTIONS {
            for target in [Target::Node, Target::Python, Target::R, Target::Cli] {
                let rendered = render(spec.doc, target);
                assert!(!rendered.contains(['{', '}']), "{}: {rendered}", spec.name);
            }
        }
    }
}
