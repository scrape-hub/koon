//! Recognises the pages bot protection answers with in place of the requested page.

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

// Words a real page may carry in its title too: only small pages count
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
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    if ["consent.google.", "consent.yahoo.", "guce.yahoo."]
        .iter()
        .any(|h| path.contains(h))
    {
        return Some("consent");
    }
    if path.contains("/sorry/") {
        return Some("google");
    }
    if !is_text(header("content-type").as_deref(), body) {
        return None;
    }

    let b = String::from_utf8_lossy(&body[..body.len().min(SCAN_BYTES)]).to_ascii_lowercase();
    let size = body.len();
    let title = title(&b);
    let has = |s: &str| b.contains(s);

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
        || (status == 202 && size < 5_000)
    {
        return Some("javascript");
    }
    if (size < 30_000 && has("experiencing high demand"))
        || path.contains("captcha")
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

#[cfg(test)]
mod tests {
    use super::blocked_by;

    fn html(status: u16, body: &str) -> Option<&'static str> {
        let headers = vec![(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )];
        blocked_by(status, &headers, body.as_bytes(), "https://example.com/")
    }

    fn page(title: &str, filler: usize) -> String {
        format!(
            "<html><head><title>{title}</title></head><body>{}</body></html>",
            "<p>content</p>".repeat(filler)
        )
    }

    #[test]
    fn vendor_challenges() {
        assert_eq!(
            html(403, "<html><script>window._cf_chl_opt={}</script></html>"),
            Some("cloudflare")
        );
        let cf = vec![("cf-mitigated".to_string(), "challenge".to_string())];
        assert_eq!(
            blocked_by(403, &cf, b"", "https://example.com/"),
            Some("cloudflare")
        );
        assert_eq!(
            html(
                403,
                "<script src=\"https://ct.captcha-delivery.com/c.js\"></script>"
            ),
            Some("datadome")
        );
        assert_eq!(
            html(403, "<div id=\"px-captcha\"></div>"),
            Some("perimeterx")
        );
        assert_eq!(
            html(
                200,
                "<script src=\"/_sec/cp_challenge/sec-cpt-if.js\"></script>"
            ),
            Some("akamai")
        );
        assert_eq!(
            html(
                202,
                "<script src=\"https://x.token.awswaf.com/challenge.js\"></script>"
            ),
            Some("aws-waf")
        );
        assert_eq!(
            html(200, &page("Pardon Our Interruption", 1)),
            Some("imperva")
        );
        assert_eq!(
            html(
                429,
                "<script src=\"/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39/ips.js\"></script>"
            ),
            Some("kasada")
        );
        assert_eq!(
            html(200, "<script>var __blnChallengeStore={}</script>"),
            Some("baleen")
        );
        assert_eq!(
            html(
                429,
                "Our systems have detected unusual traffic from your computer network."
            ),
            Some("google")
        );
        assert_eq!(
            html(
                503,
                "To discuss automated access to Amazon data please contact us."
            ),
            Some("amazon")
        );
    }

    #[test]
    fn generic_pages() {
        assert_eq!(
            html(
                200,
                "<form hidden method=\"GET\" action=\"/r/programming/\"></form><script>document.forms[0].submit()</script>"
            ),
            Some("javascript")
        );
        assert_eq!(html(202, "<html></html>"), Some("javascript"));
        assert_eq!(html(403, &page("Access Denied", 1)), Some("block-page"));
        assert_eq!(
            html(200, &page("Reddit - Prove your humanity", 10_000)),
            Some("block-page")
        );
        let headers = vec![];
        assert_eq!(
            blocked_by(
                200,
                &headers,
                b"<html></html>",
                "https://consent.google.com/ml?continue=x"
            ),
            Some("consent")
        );
    }

    #[test]
    fn real_pages_are_not_blocks() {
        assert_eq!(html(200, &page("Example Domain", 5)), None);
        assert_eq!(html(403, &page("403 Forbidden", 1)), None);
        assert_eq!(html(404, &page("Page not found", 1)), None);
        assert_eq!(html(200, &page("CAPTCHA - Wikipedia", 5_000)), None);
        let pdf = vec![("content-type".to_string(), "application/pdf".to_string())];
        assert_eq!(
            blocked_by(
                200,
                &pdf,
                b"%PDF-1.7 captcha-delivery.com",
                "https://example.com/a.pdf"
            ),
            None
        );
    }
}
