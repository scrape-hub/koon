use http::{Method, Uri};

use super::Mode;
use super::fetch_metadata::serialized_origin;
use super::util::{header_value, is_get_or_head};
use crate::client::cf_header_dict::{HeaderDict, ipc_order};

const WEBKIT_NAMES: &[&str] = &[
    "Accept",
    "Accept-Charset",
    "Accept-Language",
    "Accept-Encoding",
    "Accept-Ranges",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Age",
    "Authorization",
    "Cache-Control",
    "Clear-Site-Data",
    "Connection",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Location",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Content-Type",
    "Content-Range",
    "Cookie",
    "Cookie2",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Embedder-Policy-Report-Only",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Opener-Policy-Report-Only",
    "Cross-Origin-Resource-Policy",
    "Date",
    "DNT",
    "Default-Style",
    "ETag",
    "Expect",
    "Expires",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Keep-Alive",
    "Last-Event-ID",
    "Last-Modified",
    "Link",
    "Location",
    "Origin",
    "Ping-From",
    "Ping-To",
    "Pragma",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "Referrer-Policy",
    "Refresh",
    "Report-To",
    "Reporting-Endpoints",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Site",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Version",
    "Server-Timing",
    "Service-Worker",
    "Service-Worker-Allowed",
    "Service-Worker-Navigation-Preload",
    "Set-Cookie",
    "Set-Cookie2",
    "SourceMap",
    "TE",
    "Timing-Allow-Origin",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "Vary",
    "Via",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-SourceMap",
    "X-XSS-Protection",
    "X-Temp-Tablet",
    "Icy-MetaInt",
    "Icy-Metadata",
];

const SAFARI_18_NAMES: &[&str] = &["Purpose", "X-DNS-Prefetch-Control"];

const ADDED_NAMES: &[((u32, u32), &[&str])] = &[
    (
        (26, 0),
        &[
            "Integrity-Policy",
            "Integrity-Policy-Report-Only",
            "Sec-Purpose",
        ],
    ),
    ((26, 2), &["Sec-Speculation-Tags", "Speculation-Rules"]),
    ((27, 0), &["Origin-Agent-Cluster", "Sec-GPC"]),
];

const BROWSER_SET: &[&str] = &[
    "referer",
    "origin",
    "user-agent",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "upgrade-insecure-requests",
    "access-control-request-method",
    "access-control-request-headers",
    "content-length",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
    "host",
    "connection",
];

const CFNETWORK_TAIL: &[&str] = &[
    "accept",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

const CONDITIONAL: &[&str] = &[
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "if-match",
    "if-range",
];

pub(super) fn add_fetch_headers(headers: &mut Vec<(String, String)>, caller: &[(String, String)]) {
    let caller_has = |name: &str| header_value(caller, name).is_some();
    if CONDITIONAL.iter().any(|name| caller_has(name)) {
        for name in ["pragma", "cache-control"] {
            if header_value(headers, name).is_none() {
                headers.push((name.into(), "no-cache".into()));
            }
        }
    }
    if caller_has("range") && !caller_has("accept-encoding") {
        headers.retain(|(k, _)| k != "accept-encoding");
        headers.push(("accept-encoding".into(), "identity".into()));
    }
}

pub(super) struct SafariRequest<'h> {
    pub headers: &'h [(String, String)],
    pub caller: &'h [(String, String)],
    pub method: &'h Method,
    pub uri: &'h Uri,
    pub mode: Mode,
    pub secure: bool,
    pub body: bool,
    pub ios: bool,
    pub version: (u32, u32),
    pub previous: Option<&'h HeaderDict>,
}

#[derive(Clone, Copy)]
enum Step {
    Carry,
    Rebuild,
}

use Step::{Carry, Rebuild};

pub(super) fn order(request: &SafariRequest) -> (Vec<String>, HeaderDict) {
    let headers = request.headers;
    let version = request.version;
    let present = |name: &str| header_value(headers, name).is_some();
    let spelled = |name: &str| -> String {
        common_name(name, version)
            .map(str::to_string)
            .or_else(|| {
                request
                    .caller
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(k, _)| k.clone())
            })
            .unwrap_or_else(|| name.to_string())
    };
    let script: Vec<String> = request
        .caller
        .iter()
        .filter(|(k, v)| {
            let lower = k.to_ascii_lowercase();
            !BROWSER_SET.contains(&lower.as_str())
                && !(lower == "accept" && v.trim() == "*/*")
                && present(&lower)
        })
        .map(|(k, _)| spelled(k))
        .collect();
    let mut map: Vec<String> = Vec::new();
    let mut late: Vec<String> = Vec::new();
    let add = |map: &mut Vec<String>, name: &str| {
        if present(name) && !map.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            map.push(spelled(name));
        }
    };

    let (mut dict, steps): (HeaderDict, &[Step]) =
        if *request.method == Method::OPTIONS && present("access-control-request-method") {
            let preflight = [
                "origin",
                "access-control-request-method",
                "referer",
                "access-control-request-headers",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "sec-fetch-site",
                "user-agent",
            ];
            for name in preflight
                .into_iter()
                .chain(script.iter().map(String::as_str))
            {
                add(&mut map, name);
            }
            let steps: &[Step] = if request.ios { &[Carry] } else { &[] };
            (HeaderDict::with(map.iter().map(String::as_str)), steps)
        } else if request.mode == Mode::Cors {
            let cross_origin = header_value(headers, "origin")
                .is_some_and(|o| o != serialized_origin(request.uri));
            let (common, others): (Vec<&String>, Vec<&String>) = script
                .iter()
                .partition(|name| common_name(name, version).is_some());
            for name in common {
                add(&mut map, name);
            }
            if cross_origin {
                add(&mut map, "origin");
            }
            for name in [
                "referer",
                "accept",
                "origin",
                "sec-fetch-dest",
                "sec-fetch-mode",
                "sec-fetch-site",
                "user-agent",
            ] {
                add(&mut map, name);
            }
            if CONDITIONAL
                .iter()
                .any(|name| header_value(request.caller, name).is_some())
            {
                add(&mut map, "pragma");
                add(&mut map, "cache-control");
            }
            if header_value(request.caller, "range").is_some() {
                add(&mut map, "accept-encoding");
            }
            for name in others {
                add(&mut map, name);
            }
            let steps: &[Step] = match (request.ios, request.secure) {
                (true, true) => &[Carry, Rebuild, Rebuild],
                (true, false) => &[Carry, Rebuild],
                _ if !request.body => &[],
                _ if cross_origin => &[Carry, Rebuild],
                _ => &[Carry],
            };
            (HeaderDict::with(map.iter().map(String::as_str)), steps)
        } else {
            let form = request.mode == Mode::FormNavigate && !is_get_or_head(request.method);
            let early: &[&str] = if form {
                &["referer", "origin", "content-type", "user-agent", "accept"]
            } else {
                &["referer", "user-agent", "accept"]
            };
            for name in early
                .iter()
                .copied()
                .chain(script.iter().map(String::as_str))
            {
                add(&mut map, name);
            }
            let late_names: &[&str] = if request.secure {
                &["sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"]
            } else {
                &["upgrade-insecure-requests"]
            };
            for name in late_names {
                add(&mut late, name);
            }
            let mut dict = HeaderDict::with(&map);
            let names: Vec<String> = split(dict.order(), version)
                .into_iter()
                .map(str::to_string)
                .chain(late)
                .collect();
            dict.rebuild(names);
            let typed = !present("referer");
            let steps: &[Step] = match (request.ios, form, request.secure) {
                (true, false, true) => &[Carry, Rebuild, Rebuild],
                (true, false, false) => &[Carry, Carry],
                (true, true, true) => &[Carry, Rebuild],
                (true, true, false) => &[Carry],
                _ if typed && version == (27, 0) => &[Carry, Carry],
                _ if typed || request.secure || request.body => &[Carry],
                _ => &[],
            };
            (dict, steps)
        };

    for step in steps {
        let names: Vec<String> = match step {
            Carry => ipc_order(&dict.order()),
            Rebuild => split(dict.order(), version),
        }
        .into_iter()
        .map(str::to_string)
        .collect();
        match step {
            Carry => dict = HeaderDict::with(names),
            Rebuild => dict.rebuild(names),
        }
    }
    if present("content-length") {
        dict.set("Content-Length");
    }
    if let Some(previous) = request.previous {
        let mut names: Vec<String> = dict.order().into_iter().map(str::to_string).collect();
        names.extend(
            ["accept-language", "priority"]
                .into_iter()
                .filter(|name| present(name))
                .map(spelled),
        );
        dict = redirect(previous, &names, version);
    }
    let mut order: Vec<String> = dict
        .order()
        .iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    for (name, _) in headers {
        if !order.contains(name) && !CFNETWORK_TAIL.contains(&name.as_str()) {
            order.push(name.clone());
        }
    }
    for &name in CFNETWORK_TAIL {
        if present(name) && !order.iter().any(|n| n == name) {
            order.push(name.to_string());
        }
    }
    (order, dict)
}

fn redirect(previous: &HeaderDict, names: &[String], version: (u32, u32)) -> HeaderDict {
    let common = |name: &str| common_name(name, version).is_some();
    let is = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    let named = |name: &str| names.iter().any(|n| is(n, name));
    let mut dict = previous.clone();
    let held: Vec<String> = dict.order().into_iter().map(str::to_string).collect();
    for name in held.iter().filter(|name| !named(name)) {
        dict.remove(name);
    }
    let held: Vec<String> = dict.order().into_iter().map(str::to_string).collect();
    let accept_language = dict.home("accept-language");
    let zone: Vec<&String> = held
        .iter()
        .filter(|name| !common(name) && !is(name, "priority") && dict.home(name) >= accept_language)
        .collect();
    let reset: Vec<&String> = if zone.is_empty() {
        ["referer", "authorization"]
            .iter()
            .filter_map(|wanted| held.iter().find(|name| is(name, wanted)))
            .collect()
    } else {
        let referer = held
            .iter()
            .find(|name| is(name, "referer"))
            .filter(|referer| {
                zone.iter()
                    .any(|name| dict.home(name) == dict.home(referer))
            });
        referer.into_iter().chain(zone).collect()
    };
    for name in &reset {
        dict.remove(name);
    }
    let has = |dict: &HeaderDict, name: &str| dict.order().iter().any(|n| is(n, name));
    let new: Vec<&String> = names
        .iter()
        .filter(|name| !has(&dict, name) && !reset.iter().any(|r| is(r, name)))
        .collect();
    let (new_common, new_others): (Vec<&String>, Vec<&String>) =
        new.into_iter().partition(|name| common(name));
    let mut first: Vec<&String> = new_common
        .iter()
        .copied()
        .filter(|name| is(name, "accept-language"))
        .chain(
            new_common
                .iter()
                .copied()
                .filter(|name| !is(name, "accept-language")),
        )
        .collect();
    let mut later: Vec<&String> = reset
        .iter()
        .copied()
        .filter(|name| !common(name))
        .chain(new_others)
        .collect();
    first.extend(reset.iter().copied().filter(|name| common(name)));
    later.sort_by_key(|name| (dict.home(name), is(name, "priority")));
    for name in first.into_iter().chain(later) {
        dict.set(name);
    }
    dict
}

fn common_name(name: &str, version: (u32, u32)) -> Option<&'static str> {
    let added = ADDED_NAMES
        .iter()
        .filter(|(since, _)| version >= *since)
        .flat_map(|(_, names)| names.iter());
    let dropped = SAFARI_18_NAMES.iter().filter(|_| version < (26, 0));
    WEBKIT_NAMES
        .iter()
        .chain(added)
        .chain(dropped)
        .find(|n| n.eq_ignore_ascii_case(name))
        .copied()
}

fn split(order: Vec<&str>, version: (u32, u32)) -> Vec<&str> {
    let (mut common, others): (Vec<&str>, Vec<&str>) = order
        .into_iter()
        .partition(|name| common_name(name, version).is_some());
    common.extend(others);
    common
}
