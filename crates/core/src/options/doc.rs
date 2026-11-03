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

fn code(text: &str, target: Target) -> String {
    match target {
        Target::Node | Target::R => format!("`{text}`"),
        Target::Python => format!("``{text}``"),
        Target::Cli => text.to_string(),
    }
}

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
