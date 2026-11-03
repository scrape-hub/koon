pub(super) const CUSTOM: &str = "<custom>";

pub(super) const CHROMIUM_NAV: &[&str] = &[
    "content-length",
    "cache-control",
    CUSTOM,
    "device-memory",
    "sec-ch-device-memory",
    "dpr",
    "sec-ch-dpr",
    "viewport-width",
    "sec-ch-viewport-width",
    "sec-ch-viewport-height",
    "rtt",
    "downlink",
    "ect",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-full-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-model",
    "sec-ch-ua-bitness",
    "sec-ch-ua-wow64",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-form-factors",
    "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-reduced-transparency",
    "upgrade-insecure-requests",
    "content-type",
    "user-agent",
    "origin",
    "accept",
    "sec-gpc",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
];

pub(super) const CHROMIUM_NETWORK_TAIL: &[&str] = &[
    "accept",
    "sec-gpc",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "cookie",
    "priority",
];

pub(super) const FIREFOX_NAV: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "alt-used",
    "content-type",
    "content-length",
    "origin",
    "referer",
    CUSTOM,
    "connection",
    "cookie",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "priority",
    "te",
];

pub(super) const FIREFOX_CORS: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "alt-used",
    "referer",
    CUSTOM,
    "content-type",
    "content-length",
    "origin",
    "connection",
    "cookie",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "priority",
    "te",
];

pub(super) const OKHTTP: &[&str] = &[
    CUSTOM,
    "content-type",
    "content-length",
    "host",
    "connection",
    "accept-encoding",
    "cookie",
    "user-agent",
];

pub(super) const OKHTTP_IF_ABSENT: &[&str] = &["connection", "accept-encoding", "user-agent"];

pub(super) const SAFARI_SONOMA_GET: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "accept-encoding",
    "sec-fetch-mode",
    "user-agent",
    "accept-language",
    "sec-fetch-dest",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_GET_REFERER: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "sec-fetch-dest",
    "accept-language",
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "accept-encoding",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_BODY: &[&str] = &[
    "content-type",
    "accept",
    "sec-fetch-site",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "origin",
    "user-agent",
    "referer",
    "content-length",
    "sec-fetch-dest",
    "cookie",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_H3_GET: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "cookie",
    "priority",
    "sec-fetch-mode",
    "user-agent",
    "accept-language",
    "sec-fetch-dest",
    "accept-encoding",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_H3_GET_REFERER: &[&str] = &[
    "accept",
    "sec-fetch-site",
    "priority",
    "accept-encoding",
    "sec-fetch-mode",
    "accept-language",
    "user-agent",
    "referer",
    "cookie",
    "sec-fetch-dest",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_H3_BODY: &[&str] = &[
    "content-type",
    "accept",
    "sec-fetch-site",
    "priority",
    "accept-language",
    "accept-encoding",
    "sec-fetch-mode",
    "origin",
    "user-agent",
    "referer",
    "content-length",
    "sec-fetch-dest",
    "cookie",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_LEGACY_FIRST: &[&str] = &[
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_LEGACY_GET: &[&str] = &[
    "cookie",
    "accept",
    "user-agent",
    "accept-language",
    "accept-encoding",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_LEGACY_GET_REFERER: &[&str] = &[
    "cookie",
    "accept",
    "accept-encoding",
    "user-agent",
    "accept-language",
    "referer",
    CUSTOM,
];

pub(super) const SAFARI_SONOMA_LEGACY_BODY: &[&str] = &[
    "accept",
    "content-type",
    "origin",
    "cookie",
    "content-length",
    "accept-language",
    "user-agent",
    "referer",
    "accept-encoding",
    CUSTOM,
];

pub(super) const SAFARI_GET: &[&str] = &[
    "sec-fetch-dest",
    "user-agent",
    "accept",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_CORS_GET: &[&str] = &[
    "sec-fetch-site",
    "accept",
    "origin",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_BODY: &[&str] = &[
    "accept",
    "content-type",
    "origin",
    "sec-fetch-site",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_BODY_SITE_FIRST: &[&str] = &[
    "accept",
    "content-type",
    "sec-fetch-site",
    "origin",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_PREFLIGHT: &[&str] = &[
    "origin",
    "sec-fetch-site",
    "access-control-request-method",
    "access-control-request-headers",
    CUSTOM,
    "sec-fetch-mode",
    "user-agent",
    "referer",
    "sec-fetch-dest",
    "content-length",
    "accept",
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_HTTP_NAVIGATE: &[&str] = &[
    "user-agent",
    "upgrade-insecure-requests",
    "accept",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_HTTP_NAVIGATE_REFERER: &[&str] = &[
    "user-agent",
    "accept",
    "upgrade-insecure-requests",
    "referer",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_HTTP_GET: &[&str] = &[
    "referer",
    "accept",
    "user-agent",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_HTTP_BODY: &[&str] = &[
    "user-agent",
    "accept",
    "content-type",
    "referer",
    "origin",
    "content-length",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];

pub(super) const SAFARI_HTTP_FORM: &[&str] = &[
    "accept",
    "origin",
    "content-type",
    "upgrade-insecure-requests",
    "user-agent",
    "referer",
    "content-length",
    CUSTOM,
    "accept-language",
    "priority",
    "accept-encoding",
    "cookie",
];
