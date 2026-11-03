use super::headers::header_value;

const SCAN_BYTES: usize = 400_000;
const SMALL_PAGE: usize = 50_000;

const BLOCK_TITLES: &[&str] = &[
    "just a moment...",
    "attention required! | cloudflare",
    "access denied",
    "client challenge",
    "pardon our interruption",
    "bot or not?",
];

const SMALL_PAGE_TITLE_WORDS: &[&str] = &[
    "captcha",
    "security check",
    "verifying connection",
    "human verification",
    "are you human",
    "access denied",
    "access to this page has been denied",
    "too many requests",
    "permission denied",
];

/// The bot protection that answered instead of the page, or `None` for the page itself.
///
/// Values: `cloudflare`, `akamai`, `datadome`, `perimeterx`, `aws-waf`, `imperva`, `kasada`,
/// `baleen`, `google`, `amazon`, `javascript` (a JavaScript challenge of no known vendor),
/// `block-page` (a block page of no known vendor) and `consent` (a cookie consent page). A plain
/// error status without such a page gives `None`. `body` is the decoded body; for a streaming
/// response, its first part.
#[must_use]
pub fn blocked_by(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    url: &str,
) -> Option<&'static str> {
    let header = |name: &str| header_value(headers, name).map(str::to_ascii_lowercase);
    if header("cf-mitigated").as_deref() == Some("challenge") {
        return Some("cloudflare");
    }
    if matches!(
        header("x-amzn-waf-action").as_deref(),
        Some("challenge" | "captcha")
    ) {
        return Some("aws-waf");
    }
    let parsed = url::Url::parse(url).ok();
    let host = parsed
        .as_ref()
        .and_then(url::Url::host_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let path = parsed
        .as_ref()
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    if ["consent.google.", "consent.yahoo.", "guce.yahoo."]
        .iter()
        .any(|h| host.starts_with(h))
    {
        return Some("consent");
    }
    if path.starts_with("/sorry/") && crate::util::site(&host).starts_with("google.") {
        return Some("google");
    }
    let content_type = header("content-type");
    if !is_text(content_type.as_deref(), body) {
        return None;
    }

    let b = String::from_utf8_lossy(&body[..body.len().min(SCAN_BYTES)]).to_ascii_lowercase();
    let size = body.len();
    let title = title(&b);
    let has = |s: &str| b.contains(s);
    let html = match content_type.as_deref() {
        Some(ct) => ct.contains("html"),
        None => b.trim_start().starts_with('<'),
    };

    if has("cf_chl_opt") {
        return Some("cloudflare");
    }
    if has("captcha-delivery.com") && size < 60_000 {
        return Some("datadome");
    }
    if (has("px-captcha") || has("access to this page has been denied")) && size < SMALL_PAGE {
        return Some("perimeterx");
    }
    if has("sec-if-cpt") || has("bm-verify") || has("/_sec/cp_challenge") {
        return Some("akamai");
    }
    if status == 202 && (has("awswaf") || has("challenge.js")) {
        return Some("aws-waf");
    }
    if title.contains("pardon our interruption")
        || has("incapsula incident")
        || (has("_incapsula_resource") && size < 20_000)
    {
        return Some("imperva");
    }
    if status == 429 && (has("kpsdk") || has("ips.js")) {
        return Some("kasada");
    }
    if has("\"request_fate\":\"challengejs\"") || (has("__blnchallengestore") && size < SMALL_PAGE)
    {
        return Some("baleen");
    }
    if (has("unusual traffic from your computer") && size < SMALL_PAGE)
        || has("/httpservice/retry/enablejs")
    {
        return Some("google");
    }
    if has("/errors/validatecaptcha") || has("to discuss automated access") {
        return Some("amazon");
    }
    if (size < 20_000 && has("<form hidden"))
        || (size < 10_000 && title.is_empty() && b.matches("_0x").count() > 20)
        || (status == 202 && html && size < 5_000)
    {
        return Some("javascript");
    }
    if (size < 30_000 && has("experiencing high demand"))
        || (path.contains("captcha") && html && size < SMALL_PAGE)
        || BLOCK_TITLES.contains(&title.as_str())
        || title.contains("prove your humanity")
        || (size < SMALL_PAGE && SMALL_PAGE_TITLE_WORDS.iter().any(|w| title.contains(w)))
    {
        return Some("block-page");
    }
    None
}

fn is_text(content_type: Option<&str>, body: &[u8]) -> bool {
    if body.starts_with(b"%PDF-") {
        return false;
    }
    match content_type {
        None => true,
        Some(ct) => ["html", "text", "xml", "json", "javascript"]
            .iter()
            .any(|t| ct.contains(t)),
    }
}

fn title(lowercase_html: &str) -> String {
    let Some(start) = lowercase_html.find("<title") else {
        return String::new();
    };
    let rest = &lowercase_html[start..];
    let Some(open) = rest.find('>') else {
        return String::new();
    };
    let inner = &rest[open + 1..];
    let end = inner.find("</title>").unwrap_or(inner.len());
    inner[..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
