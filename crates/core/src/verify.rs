//! Fingerprint self-test: compares a profile's TLS/HTTP2/QUIC fingerprint with the [`Reference`]
//! captured from the real browser, using public fingerprinting services ([`TLS_SERVICES`],
//! [`QUIC_SERVICE`]). [`verify`] fetches and checks every field; a profile outside the captured
//! version ranges ([`references_for`]) has no reference and is reported as such.

use std::fmt;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::{Browser, BrowserProfile, Client, Error, Os, ProfileName};

// Reference fingerprints

/// Fingerprint values of a real browser, as the services report them. A field without a value is
/// not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Reference {
    /// Short name, e.g. `chromium-mldsa-trust-anchors`.
    pub id: &'static str,
    /// Which browsers and captures the values come from.
    pub source: &'static str,
    /// JA4 of the TCP `ClientHello`.
    pub ja4: Option<&'static str>,
    /// JA3N (JA3 with sorted extensions), for browsers whose JA3N koon matches exactly.
    pub ja3n_hash: Option<&'static str>,
    /// Exact JA3, only for browsers with a fixed extension order: JA4 and JA3N sort the extensions
    /// and miss order bugs.
    pub ja3_hash: Option<&'static str>,
    /// MD5 of the Akamai HTTP/2 fingerprint.
    pub akamai_hash: Option<&'static str>,
    /// Akamai HTTP/2 fingerprint: SETTINGS, `WINDOW_UPDATE`, PRIORITY, pseudo-header order.
    pub akamai_text: Option<&'static str>,
    /// JA4 of the QUIC `ClientHello` of an HTTP/3 connection.
    pub quic_ja4: Option<&'static str>,
}

impl Reference {
    /// The value of `field`, if the reference has one.
    #[must_use]
    pub fn get(&self, field: Field) -> Option<&'static str> {
        match field {
            Field::Ja4 => self.ja4,
            Field::Ja3nHash => self.ja3n_hash,
            Field::Ja3Hash => self.ja3_hash,
            Field::AkamaiHash => self.akamai_hash,
            Field::AkamaiText => self.akamai_text,
            Field::QuicJa4 => self.quic_ja4,
        }
    }
}

#[rustfmt::skip]
pub(crate) mod references;

use references::{COVERAGE, SERVER_PADDING_VARIANTS};

/// A version as `(major, minor)`: `154` -> `(154, 0)`, `26.6` -> `(26, 6)`.
type Version = (u32, u32);

fn parse_version(version: &str) -> Option<Version> {
    let (major, minor) = version.split_once('.').unwrap_or((version, "0"));
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Where a reference applies: a browser's versions `from..=to` on `os`. `references::COVERAGE`
/// lists them for every browser but Safari (its `SAFARI_VERSIONS` table carries its own references,
/// one per release). Ranges end at the last version whose fingerprint was verified, so a newly added
/// browser version has no reference until its fingerprint is captured and the range extended (the
/// unit tests list every profile without one). A client in the `PqcBandwidthExperiment` field trial
/// is compared with `references::SERVER_PADDING_VARIANTS` instead.
struct Coverage {
    browser: Browser,
    from: Version,
    to: Version,
    os: &'static [Os],
    reference: &'static Reference,
}

/// The references of the real browser a profile impersonates: one for its TLS and HTTP/2
/// fingerprint, and one for its QUIC `ClientHello` where that was captured. Empty when no capture
/// covers the profile.
#[must_use]
pub fn references_for(profile: &ProfileName) -> Vec<&'static Reference> {
    if profile.browser == Browser::Safari {
        return crate::SAFARI_VERSIONS
            .iter()
            .find(|v| v.version == profile.version)
            .map(|entry| entry.references(profile.os))
            .unwrap_or_default();
    }
    let Some(version) = parse_version(&profile.version) else {
        return Vec::new();
    };
    COVERAGE
        .iter()
        .filter(|c| {
            c.browser == profile.browser
                && c.os.contains(&profile.os)
                && (c.from..=c.to).contains(&version)
        })
        .map(|c| c.reference)
        .collect()
}

/// The profiles checked against the services before a release (`cargo test --test fingerprint --
/// --ignored`): the first and last version of every range a reference covers, plus versions in
/// between whose `ClientHello` changes without changing the hashes.
pub const CHECKPOINTS: &[&str] = &[
    "chrome131-windows",
    "chrome134-windows",
    "chrome135-windows",
    "chrome140-windows",
    "chrome141-windows",
    "chrome145-windows",
    "chrome149-windows",
    "chrome150-windows",
    "chrome152-windows",
    "chrome153-windows",
    "chrome154-windows",
    "chrome155-windows",
    "chrome157-windows",
    "chrome134-android",
    "chrome135-android",
    "chrome141-android",
    "chrome149-android",
    "chrome150-android",
    "chrome151-android",
    "chrome152-android",
    "chrome155-android",
    "chrome157-android",
    "firefox135-windows",
    "firefox147-windows",
    "firefox150-windows",
    "firefox151-windows",
    "firefox153-windows",
    "firefox154-windows",
    "firefox155-windows",
    "firefox156-windows",
    "firefox157-windows",
    "firefox158-windows",
    "firefox159-windows",
    "firefox146-android",
    "firefox150-android",
    "firefox151-android",
    "firefox153-android",
    "firefox154-android",
    "firefox155-android",
    "firefox156-android",
    "firefox157-android",
    "firefox158-android",
    "firefox159-android",
    "safari15.6-macos",
    "safari16.0-macos",
    "safari16.1-macos",
    "safari16.6-macos",
    "safari17.0-macos",
    "safari17.6-macos",
    "safari18.0-macos",
    "safari18.1-macos",
    "safari18.2-macos",
    "safari18.3-macos",
    "safari18.4-macos",
    "safari18.5-macos",
    "safari18.6-macos",
    "safari26.0-macos",
    "safari26.1-macos",
    "safari27.0-macos",
    "safari16.0-ios",
    "safari16.1-ios",
    "safari17.0-ios",
    "safari18.0-ios",
    "safari18.1-ios",
    "safari18.2-ios",
    "safari18.3-ios",
    "safari18.4-ios",
    "safari18.5-ios",
    "safari26.0-ios",
    "safari26.5-ios",
    "safari27.0-ios",
    "edge131-windows",
    "edge134-windows",
    "edge135-windows",
    "edge145-windows",
    "edge149-windows",
    "edge150-windows",
    "edge151-windows",
    "edge152-windows",
    "edge153-windows",
    "edge154-windows",
    "edge156-windows",
    "edge153-android",
    "brave153-windows",
    "brave154-windows",
    "brave154-android",
    "brave156-windows",
    "samsung29-android",
    "samsung30-android",
    "opera-mobile102-android",
    "opera124-windows",
    "opera125-windows",
    "opera133-windows",
    "opera134-windows",
    "opera135-windows",
    "opera136-windows",
    "opera139-windows",
    "okhttp4",
    "okhttp5",
];

// Fields and comparison

/// A fingerprint field the services report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// JA4 of the TCP `ClientHello`.
    Ja4,
    /// JA3N hash (JA3 with sorted extensions).
    Ja3nHash,
    /// JA3 hash.
    Ja3Hash,
    /// MD5 of the Akamai HTTP/2 fingerprint.
    AkamaiHash,
    /// Akamai HTTP/2 fingerprint.
    AkamaiText,
    /// JA4 of the QUIC `ClientHello` (HTTP/3).
    QuicJa4,
}

impl Field {
    /// Every field, in report order.
    pub const ALL: [Self; 6] = [
        Self::Ja4,
        Self::Ja3nHash,
        Self::Ja3Hash,
        Self::AkamaiHash,
        Self::AkamaiText,
        Self::QuicJa4,
    ];

    /// The name in reports and JSON (`ja4`, `ja3n_hash`, `quic_ja4`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ja4 => "ja4",
            Self::Ja3nHash => "ja3n_hash",
            Self::Ja3Hash => "ja3_hash",
            Self::AkamaiHash => "akamai_hash",
            Self::AkamaiText => "akamai_text",
            Self::QuicJa4 => "quic_ja4",
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The fingerprint a service reported; `None` where it reported nothing. The fields mirror
/// [`Reference`]'s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Observed {
    pub ja4: Option<String>,
    pub ja3n_hash: Option<String>,
    pub ja3_hash: Option<String>,
    pub akamai_hash: Option<String>,
    pub akamai_text: Option<String>,
    pub quic_ja4: Option<String>,
}

impl Observed {
    /// The reported value of `field`.
    #[must_use]
    pub fn get(&self, field: Field) -> Option<&str> {
        match field {
            Field::Ja4 => self.ja4.as_deref(),
            Field::Ja3nHash => self.ja3n_hash.as_deref(),
            Field::Ja3Hash => self.ja3_hash.as_deref(),
            Field::AkamaiHash => self.akamai_hash.as_deref(),
            Field::AkamaiText => self.akamai_text.as_deref(),
            Field::QuicJa4 => self.quic_ja4.as_deref(),
        }
    }

    /// The TLS and HTTP/2 fields of a service's JSON: tls.browserleaks.com's flat object (`ja4`,
    /// `ja3_hash`, `ja3n_hash`, `akamai_hash`, `akamai_text`) or tls.peet.ws's nested one
    /// (`tls.ja4`, `tls.ja3_hash`, `http2.akamai_fingerprint`, `http2.akamai_fingerprint_hash`).
    /// `None` if it holds neither a JA4 nor an Akamai fingerprint.
    pub fn from_tls_json(json: &Value) -> Option<Self> {
        let text = |value: Option<&Value>| {
            value
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let observed = match (json.get("tls"), json.get("http2")) {
            (Some(tls), http2) if tls.is_object() => Self {
                ja4: text(tls.get("ja4")),
                ja3n_hash: text(tls.get("ja3n_hash")),
                ja3_hash: text(tls.get("ja3_hash")),
                akamai_hash: text(http2.and_then(|h| h.get("akamai_fingerprint_hash"))),
                akamai_text: text(http2.and_then(|h| h.get("akamai_fingerprint"))),
                quic_ja4: None,
            },
            _ => Self {
                ja4: text(json.get("ja4")),
                ja3n_hash: text(json.get("ja3n_hash")),
                ja3_hash: text(json.get("ja3_hash")),
                akamai_hash: text(json.get("akamai_hash")),
                akamai_text: text(json.get("akamai_text")),
                quic_ja4: None,
            },
        };
        (observed.ja4.is_some() || observed.akamai_text.is_some()).then_some(observed)
    }

    /// The QUIC JA4 of quic.browserleaks.com's JSON (`ja4`, starting with `q`), if it holds one.
    pub fn quic_ja4_from_json(json: &Value) -> Option<String> {
        json.get("ja4")
            .and_then(Value::as_str)
            .filter(|ja4| ja4.starts_with('q'))
            .map(str::to_string)
    }
}

/// Why a field was not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotChecked {
    /// The real browser's value is not known for this field, or the profile has no reference at
    /// all.
    NoReference,
    /// The service that answered does not report this field.
    NotReported,
    /// The request did not go over HTTP/3 (UDP blocked, a proxy, or TCP won the race).
    NoHttp3,
    /// The HTTP/3 check was turned off ([`Services::quic`] is `None`).
    Skipped,
    /// No service answered.
    Unreachable,
}

impl NotChecked {
    /// A short explanation for reports.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NoReference => "no reference value",
            Self::NotReported => "not reported by the service",
            Self::NoHttp3 => "HTTP/3 not used (UDP blocked or proxy)",
            Self::Skipped => "HTTP/3 check skipped",
            Self::Unreachable => "service unreachable",
        }
    }
}

/// The result of one field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Check {
    /// The service saw the real browser's value.
    Match { value: String },
    /// The service saw another value than the real browser's.
    Mismatch { expected: String, actual: String },
    /// Not compared.
    NotChecked {
        reason: NotChecked,
        #[serde(skip_serializing_if = "Option::is_none")]
        actual: Option<String>,
    },
}

/// The result of one field of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldCheck {
    pub field: Field,
    #[serde(flatten)]
    pub check: Check,
}

/// Compare one field: `expected` from the references, `actual` from the service; `missing` is the
/// reason to report when the service reported no value.
pub(crate) fn compare(expected: Option<&str>, actual: Option<&str>, missing: NotChecked) -> Check {
    match (expected, actual) {
        (None, actual) => Check::NotChecked {
            reason: NotChecked::NoReference,
            actual: actual.map(str::to_string),
        },
        (Some(_), None) => Check::NotChecked {
            reason: missing,
            actual: None,
        },
        (Some(expected), Some(actual)) if expected == actual => Check::Match {
            value: actual.to_string(),
        },
        (Some(expected), Some(actual)) => Check::Mismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        },
    }
}

// Report

/// The overall result of a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every checked field matches the real browser.
    Match,
    /// At least one field differs from the real browser.
    Mismatch,
    /// No capture covers the profile; the fields show what the service saw.
    NoReference,
    /// No TLS fingerprint service answered.
    Unreachable,
}

/// A service that did not deliver a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceFailure {
    pub service: String,
    /// An [`Error::code`] (`CONNECTION_FAILED`, `TIMEOUT`, `PROXY_ERROR`, ...), `HTTP_ERROR` for a
    /// status other than 200 or `PROTOCOL_ERROR` for an answer without a fingerprint.
    pub code: &'static str,
    pub message: String,
}

/// A reference in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceInfo {
    /// [`Reference::id`].
    pub id: &'static str,
    /// [`Reference::source`].
    pub source: &'static str,
}

/// The result of [`verify`] for one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    /// The profile checked, as [`BrowserProfile::names`] lists it (`chrome154-macos`).
    pub profile: String,
    /// The koon version that produced the fingerprint.
    pub koon_version: &'static str,
    /// The overall result.
    pub outcome: Outcome,
    /// The references compared with; empty for [`Outcome::NoReference`].
    pub references: Vec<ReferenceInfo>,
    /// The TLS fingerprint service that answered.
    pub service: Option<String>,
    /// The HTTP/3 service that answered over HTTP/3.
    pub http3_service: Option<String>,
    /// Every [`Field`], in [`Field::ALL`] order.
    pub fields: Vec<FieldCheck>,
    /// Services that failed, in the order they were tried.
    pub errors: Vec<ServiceFailure>,
}

impl VerifyReport {
    /// Whether every checked field matches (also when none was checked).
    #[must_use]
    pub fn is_match(&self) -> bool {
        !self
            .fields
            .iter()
            .any(|f| matches!(f.check, Check::Mismatch { .. }))
    }

    /// The report as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a report serializes")
    }

    /// The report as indented JSON.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("a report serializes")
    }
}

/// Compose a report from what the services delivered: `tls` is the TLS fingerprint (`None`: no
/// service answered), `quic` the QUIC JA4 or why there is none.
fn report(
    profile: &ProfileName,
    references: &[Reference],
    tls: Option<(String, Observed)>,
    quic: Result<(String, String), NotChecked>,
    errors: Vec<ServiceFailure>,
) -> VerifyReport {
    let expected = |field| references.iter().find_map(|r| r.get(field));
    let tls_missing = if tls.is_some() {
        NotChecked::NotReported
    } else {
        NotChecked::Unreachable
    };
    let (quic_actual, quic_missing) = match &quic {
        Ok((_, ja4)) => (Some(ja4.as_str()), NotChecked::NotReported),
        Err(reason) => (None, *reason),
    };
    let fields: Vec<FieldCheck> = Field::ALL
        .into_iter()
        .map(|field| {
            let check = if field == Field::QuicJa4 {
                compare(expected(field), quic_actual, quic_missing)
            } else {
                let actual = tls.as_ref().and_then(|(_, o)| o.get(field));
                compare(expected(field), actual, tls_missing)
            };
            FieldCheck { field, check }
        })
        .collect();
    let mismatch = fields
        .iter()
        .any(|f| matches!(f.check, Check::Mismatch { .. }));
    let outcome = if mismatch {
        Outcome::Mismatch
    } else if tls.is_none() {
        Outcome::Unreachable
    } else if references.is_empty() {
        Outcome::NoReference
    } else {
        Outcome::Match
    };
    VerifyReport {
        profile: profile.name.clone(),
        koon_version: env!("CARGO_PKG_VERSION"),
        outcome,
        references: references
            .iter()
            .map(|r| ReferenceInfo {
                id: r.id,
                source: r.source,
            })
            .collect(),
        service: tls.map(|(service, _)| service),
        http3_service: quic.ok().map(|(service, _)| service),
        fields,
        errors,
    }
}

// Services

/// The TLS and HTTP/2 fingerprint services, tried in order. tls.peet.ws reports no JA3N.
pub const TLS_SERVICES: &[&str] = &[
    "https://tls.browserleaks.com/json",
    "https://tls.peet.ws/api/all",
];

/// The service that reports the QUIC JA4 of a request over HTTP/3. Over TCP it answers with an
/// Alt-Svc header only, so the check sends up to [`QUIC_ATTEMPTS`] requests.
pub const QUIC_SERVICE: &str = "https://quic.browserleaks.com/?minify=1";

/// Requests to [`QUIC_SERVICE`]: one over TCP that learns the Alt-Svc, then retries while the TCP
/// connection wins the race against QUIC.
pub const QUIC_ATTEMPTS: usize = 3;

/// Timeout of each request of [`verify`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The services a check asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Services {
    /// TLS and HTTP/2 fingerprint services, tried in order until one answers; each returns
    /// browserleaks' or tls.peet.ws's JSON.
    pub tls: Vec<String>,
    /// The HTTP/3 service (quic.browserleaks.com's JSON), or `None` to skip the QUIC check.
    pub quic: Option<String>,
}

impl Default for Services {
    fn default() -> Self {
        Self {
            tls: TLS_SERVICES.iter().map(|s| s.to_string()).collect(),
            quic: Some(QUIC_SERVICE.to_string()),
        }
    }
}

/// Retries of a request that failed before it was sent: browserleaks resets some handshakes when
/// many clients connect at once.
const PRE_SEND_RETRIES: u32 = 2;

/// GET `url` and parse its JSON.
async fn fetch_json(client: &Client, url: &str) -> Result<(Value, String), ServiceFailure> {
    let failure = |code, message: String| ServiceFailure {
        service: url.to_string(),
        code,
        message,
    };
    let mut attempt = 0;
    let response = loop {
        match client.get(url).await {
            Ok(response) => break response,
            Err(e) if e.is_pre_send() && attempt < PRE_SEND_RETRIES => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
            }
            Err(e) => return Err(failure(e.code(), e.to_string())),
        }
    };
    if response.status != 200 {
        return Err(failure(
            "HTTP_ERROR",
            format!("answered HTTP {}", response.status),
        ));
    }
    let json = serde_json::from_slice(&response.body)
        .map_err(|e| failure("PROTOCOL_ERROR", format!("no JSON in the answer: {e}")))?;
    Ok((json, response.version))
}

/// The TLS fingerprint from the first service that answers, and the failures of those before it.
async fn fetch_tls(
    client: &Client,
    services: &[String],
    errors: &mut Vec<ServiceFailure>,
) -> Option<(String, Observed)> {
    for service in services {
        match fetch_json(client, service).await {
            Ok((json, _)) => match Observed::from_tls_json(&json) {
                Some(observed) => return Some((service.clone(), observed)),
                None => errors.push(ServiceFailure {
                    service: service.clone(),
                    code: "PROTOCOL_ERROR",
                    message: "no JA4 or Akamai fingerprint in the answer".into(),
                }),
            },
            Err(failure) => errors.push(failure),
        }
    }
    None
}

/// The QUIC JA4 from `service`, requested until a response comes over HTTP/3.
async fn fetch_quic(
    client: &Client,
    service: &str,
    errors: &mut Vec<ServiceFailure>,
) -> Result<(String, String), NotChecked> {
    for _ in 0..QUIC_ATTEMPTS {
        let (json, version) = fetch_json(client, service).await.map_err(|failure| {
            errors.push(failure);
            NotChecked::Unreachable
        })?;
        if version != "h3" {
            continue;
        }
        return Observed::quic_ja4_from_json(&json)
            .map(|ja4| (service.to_string(), ja4))
            .ok_or(NotChecked::NotReported);
    }
    Err(NotChecked::NoHttp3)
}

/// Check the fingerprint `client` produces against the real browser of `profile`.
///
/// The client must be built from that profile, fresh: a resumed TLS session changes the
/// `ClientHello`.
///
/// Every field is compared with the profile's [`references_for`] (a client drawn into server
/// padding uses their padded counterparts instead). The QUIC JA4 is fetched only when a reference
/// has one and the profile speaks HTTP/3. A service that fails is reported in
/// [`VerifyReport::errors`]; when no TLS service answers the outcome is [`Outcome::Unreachable`].
pub async fn verify_with(
    profile: &ProfileName,
    client: &Client,
    services: &Services,
) -> VerifyReport {
    let references = client_references(profile, client.profile());
    let mut errors = Vec::new();
    let tls = fetch_tls(client, &services.tls, &mut errors).await;
    let quic = if !references.iter().any(|r| r.quic_ja4.is_some()) {
        Err(NotChecked::NoReference)
    } else if !client
        .profile()
        .quic
        .as_ref()
        .is_some_and(|q| q.alt_svc || q.https_rr)
    {
        Err(NotChecked::NoHttp3)
    } else if let Some(service) = &services.quic {
        fetch_quic(client, service, &mut errors).await
    } else {
        Err(NotChecked::Skipped)
    };
    report(profile, &references, tls, quic, errors)
}

/// The references of `profile` for a client whose built profile is `built`: with a server padding
/// drawn, a reference is replaced by its padded counterpart in [`SERVER_PADDING_VARIANTS`], or
/// loses its TLS hashes and QUIC JA4 where no padded `ClientHello` was captured.
fn client_references(profile: &ProfileName, built: &BrowserProfile) -> Vec<Reference> {
    let quic_tls = built.quic.as_ref().and_then(|q| q.tls.as_ref());
    let padding =
        built.tls.server_padding.is_some() || quic_tls.is_some_and(|t| t.server_padding.is_some());
    references_for(profile)
        .into_iter()
        .map(|reference| {
            if !padding {
                return *reference;
            }
            SERVER_PADDING_VARIANTS
                .iter()
                .find(|(plain, _)| plain.id == reference.id)
                .map_or(
                    Reference {
                        ja4: None,
                        ja3n_hash: None,
                        ja3_hash: None,
                        quic_ja4: None,
                        ..*reference
                    },
                    |(_, padded)| **padded,
                )
        })
        .collect()
}

/// [`verify`] for the options of a [`Scope::Verify`](crate::options::Scope::Verify) call: the
/// built-in profile its browser names, checked with a new client built from its connection
/// options and timeout.
pub async fn verify_options(options: crate::options::Options) -> Result<VerifyReport, Error> {
    let profile = BrowserProfile::resolve_name(options.browser())?;
    let client = options.client_builder()?.build()?;
    let report = verify_with(&profile, &client, &Services::default()).await;
    client.shutdown().await;
    Ok(report)
}

/// Check the built-in profile `name` (`chrome`, `firefox154-windows`, ...) against the real
/// browser, with a new client (timeout [`DEFAULT_TIMEOUT`]) that connects through `proxy` if one is
/// given.
///
/// Fails only for a name that is no built-in profile or an invalid proxy URL; unreachable services
/// are part of the report.
pub async fn verify(name: &str, proxy: Option<&str>) -> Result<VerifyReport, Error> {
    let profile = BrowserProfile::resolve_name(name)?;
    let mut builder = Client::builder(BrowserProfile::resolve(name)?).timeout(DEFAULT_TIMEOUT);
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy)?;
    }
    let client = builder.build()?;
    let report = verify_with(&profile, &client, &Services::default()).await;
    client.shutdown().await;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const CHROMIUM_AKAMAI_HASH: &str = "52d84b11737d980aef856699f885ca86";
    const CHROMIUM_AKAMAI_TEXT: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

    /// The profiles without a reference, as prefixes of their names: which real browsers have no
    /// capture. Update when a capture is added.
    const WITHOUT_REFERENCE: &[&str] = &[
        // Firefox on Android before 146: no capture of these releases.
        "firefox135-android",
        "firefox136-android",
        "firefox137-android",
        "firefox138-android",
        "firefox139-android",
        "firefox140-android",
        "firefox141-android",
        "firefox142-android",
        "firefox143-android",
        "firefox144-android",
        "firefox145-android",
        // Safari releases without a capture of their own, which take the values of another captured
        // one.
        "safari166-ios",
        "safari176-ios",
        "safari186-ios",
        "safari266-ios",
    ];

    fn name(name: &str) -> ProfileName {
        BrowserProfile::resolve_name(name).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    /// Every built-in profile either has a TLS/HTTP/2 reference or is listed in
    /// `WITHOUT_REFERENCE`, and no two references of a profile give the same field.
    #[test]
    fn every_profile_has_a_reference_or_is_listed_without() {
        let mut without = Vec::new();
        for profile in BrowserProfile::names() {
            let references = references_for(&profile);
            let tls = references
                .iter()
                .filter(|r| r.akamai_text.is_some() || r.ja4.is_some())
                .count();
            assert!(tls <= 1, "{}: {tls} TLS references", profile.name);
            if references.is_empty() {
                without.push(profile.name.clone());
            }
            for field in Field::ALL {
                let values = references.iter().filter(|r| r.get(field).is_some()).count();
                assert!(values <= 1, "{}: {field} given twice", profile.name);
            }
            if tls == 0 {
                assert!(references.is_empty(), "{}: QUIC only", profile.name);
            }
        }
        assert_eq!(without, WITHOUT_REFERENCE);
    }

    /// A Safari profile has a reference exactly when its release was captured, and a QUIC reference
    /// exactly when its transport parameters were and it reaches HTTP/3 at all: through Alt-Svc
    /// or, on macOS 15.1 and 15.2, only through the DNS HTTPS record.
    #[test]
    fn safari_references_follow_the_captures() {
        for profile in BrowserProfile::names().filter(|p| p.browser == Browser::Safari) {
            let entry = crate::SAFARI_VERSIONS
                .iter()
                .find(|v| v.version == profile.version)
                .unwrap();
            let references = references_for(&profile);
            assert_eq!(
                references.is_empty(),
                entry.captured(profile.os).is_none(),
                "{}",
                profile.name
            );
            let reaches_http3 = BrowserProfile::resolve(&profile.name)
                .unwrap()
                .quic
                .is_some_and(|q| q.alt_svc || q.https_rr);
            assert_eq!(
                references.iter().any(|r| r.quic_ja4.is_some()),
                entry.captured_quic(profile.os).is_some() && reaches_http3,
                "{}",
                profile.name
            );
        }
    }

    /// The defaults of `koon verify` all have a reference.
    #[test]
    fn default_profiles() {
        for browser in [
            "chrome",
            "firefox",
            "edge",
            "opera",
            "brave",
            "samsung",
            "opera-mobile",
            "okhttp",
        ] {
            assert!(!references_for(&name(browser)).is_empty(), "{browser}");
        }
        let safari: Vec<&str> = references_for(&name("safari"))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(safari, ["safari-26", "safari-quic"]);
        let chrome: Vec<&str> = references_for(&name("chrome"))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(chrome, ["chromium-mldsa-trust-anchors", "chrome-quic"]);
        let firefox: Vec<&str> = references_for(&name("firefox"))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(firefox, ["firefox-156", "firefox-quic"]);
        let edge: Vec<&str> = references_for(&name("edge")).iter().map(|r| r.id).collect();
        assert_eq!(edge, ["chromium-mldsa", "chromium-quic-no-trust-anchors"]);
    }

    #[test]
    fn references_follow_version_and_os() {
        let id = |profile: &str| -> Vec<&str> {
            references_for(&name(profile))
                .iter()
                .map(|r| r.id)
                .collect()
        };
        assert_eq!(
            id("chrome134-linux"),
            ["chromium-old-alps", "chrome-quic-old-alps"]
        );
        assert_eq!(
            id("chrome135-android"),
            ["chromium-new-alps", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(
            id("chrome141-macos"),
            ["chromium-new-alps", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(
            id("chrome150-windows"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        // Android: trust_anchors from 152 on, over TCP and QUIC.
        assert_eq!(
            id("chrome134-android"),
            ["chromium-old-alps", "chrome-quic-old-alps"]
        );
        assert_eq!(
            id("chrome149-android"),
            ["chromium-new-alps", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(
            id("chrome151-android"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(
            id("chrome152-android"),
            ["chromium-mldsa-trust-anchors", "chrome-quic"]
        );
        assert_eq!(
            id("chrome155-android"),
            ["chromium-mldsa-trust-anchors", "chrome-quic"]
        );
        assert_eq!(
            id("chrome155-macos"),
            ["chromium-mldsa-trust-anchors", "chrome-quic"]
        );
        assert_eq!(id("edge134-macos"), ["chromium-old-alps"]);
        assert_eq!(id("edge149-windows"), ["chromium-new-alps"]);
        assert_eq!(id("edge150-windows"), ["chromium-mldsa"]);
        assert_eq!(
            id("edge153-windows"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(id("opera133-linux"), ["chromium-new-alps"]);
        assert_eq!(id("opera135-windows"), ["chromium-mldsa"]);
        assert_eq!(
            id("opera136-macos"),
            ["chromium-mldsa-trust-anchors", "chrome-quic"]
        );
        assert_eq!(
            id("edge153-android"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(id("edge140-android"), ["chromium-new-alps"]);
        assert_eq!(
            id("brave154-linux"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(
            id("brave-mobile153"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        // Samsung Internet 29 and 30 (Chromium 136, 143) have no HTTP/3.
        assert_eq!(id("samsung"), ["chromium-new-alps"]);
        assert_eq!(id("samsung29"), ["chromium-new-alps"]);
        assert_eq!(
            id("opera-mobile"),
            ["opera-mobile", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(id("firefox150-linux"), ["firefox-135"]);
        assert_eq!(id("firefox153-windows"), ["firefox-151"]);
        assert_eq!(id("firefox155-macos"), ["firefox-154", "firefox-quic"]);
        assert_eq!(id("firefox156-linux"), ["firefox-156", "firefox-156-quic"]);
        assert_eq!(id("firefox157-windows"), ["firefox-156", "firefox-quic"]);
        assert_eq!(
            id("edge154-macos"),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert_eq!(id("safari16.0-macos"), ["safari-macos12-13"]);
        assert_eq!(
            id("safari16.6-macos"),
            ["safari-macos12-13", "safari-quic-sha1"]
        );
        assert!(id("safari16.6-ios").is_empty());
        assert_eq!(id("safari17.0"), ["safari-macos14", "safari-quic-sha1"]);
        assert_eq!(
            id("safari17.6-macos"),
            ["safari-macos14", "safari-quic-sha1"]
        );
        assert!(id("safari17.6-ios").is_empty());
        // macOS 15.0 still sends the network stack of macOS 14.
        assert_eq!(
            id("safari18.0-macos"),
            ["safari-macos14", "safari-quic-sha1"]
        );
        assert_eq!(
            id("safari-mobile17.0"),
            ["safari-ios17", "safari-quic-sha1"]
        );
        assert_eq!(id("safari16.0-ios"), ["safari-ios16", "safari-quic-sha1"]);
        assert_eq!(id("safari16.1-ios"), ["safari-ios16", "safari-quic-sha1"]);
        // macOS 15.1/15.2 reach HTTP/3 via the DNS record, so both carry a QUIC reference too.
        assert_eq!(id("safari18.1-macos"), ["safari-15.1", "safari-quic-sha1"]);
        assert_eq!(id("safari18.2-macos"), ["safari-15.2", "safari-quic"]);
        assert_eq!(id("safari18.3-macos"), ["safari-15.2", "safari-quic"]);
        assert_eq!(id("safari18.4-macos"), ["safari-15.4", "safari-quic"]);
        assert_eq!(id("safari18.6-macos"), ["safari-15.4", "safari-quic"]);
        assert!(id("safari18.6-ios").is_empty());
        assert_eq!(id("safari-mobile18.0"), ["safari-15.1"]);
        assert_eq!(id("safari-mobile18.3"), ["safari-15.2", "safari-quic"]);
        assert_eq!(id("safari-mobile18.5"), ["safari-15.4", "safari-quic"]);
        assert_eq!(id("safari26.0-macos"), ["safari-26", "safari-quic"]);
        assert_eq!(id("safari26.1-macos"), ["safari-26", "safari-quic"]);
        assert_eq!(id("safari26.3-macos"), ["safari-26", "safari-quic"]);
        assert_eq!(id("safari26.4"), ["safari-26", "safari-quic"]);
        assert_eq!(id("safari-mobile26.4"), ["safari-26", "safari-quic"]);
        assert!(id("safari-mobile26.6").is_empty());
        assert_eq!(id("okhttp4"), ["okhttp4"]);
        assert_eq!(id("okhttp"), ["okhttp5"]);
        assert!(id("firefox-mobile145").is_empty());
        assert_eq!(
            id("firefox-mobile150"),
            ["firefox-android-146", "firefox-quic"]
        );
        assert_eq!(
            id("firefox-mobile153"),
            ["firefox-android-151", "firefox-quic"]
        );
        assert_eq!(
            id("firefox-mobile156"),
            ["firefox-android-156", "firefox-156-quic"]
        );
        assert_eq!(
            id("firefox-mobile"),
            ["firefox-android-156", "firefox-quic"]
        );
    }

    /// The checkpoints are built-in profiles with a reference, include both ends of every range,
    /// and are listed once.
    #[test]
    fn checkpoints_cover_every_range_edge() {
        let checkpoints: Vec<ProfileName> = CHECKPOINTS.iter().map(|n| name(n)).collect();
        let unique: HashSet<&str> = checkpoints.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            unique.len(),
            checkpoints.len(),
            "a checkpoint is listed twice"
        );
        for profile in &checkpoints {
            assert!(
                !references_for(profile).is_empty(),
                "{} has no reference",
                profile.name
            );
        }
        for coverage in COVERAGE {
            for edge in [coverage.from, coverage.to] {
                let found = checkpoints.iter().any(|p| {
                    p.browser == coverage.browser
                        && coverage.os.contains(&p.os)
                        && parse_version(&p.version) == Some(edge)
                });
                assert!(
                    found,
                    "no checkpoint for {} {edge:?} ({})",
                    coverage.browser, coverage.reference.id
                );
            }
        }
    }

    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("154"), Some((154, 0)));
        assert_eq!(parse_version("26.6"), Some((26, 6)));
        assert_eq!(parse_version("x"), None);
    }

    #[test]
    fn compares_fields() {
        let missing = NotChecked::NotReported;
        assert_eq!(
            compare(Some("a"), Some("a"), missing),
            Check::Match { value: "a".into() }
        );
        assert_eq!(
            compare(Some("a"), Some("b"), missing),
            Check::Mismatch {
                expected: "a".into(),
                actual: "b".into()
            }
        );
        assert_eq!(
            compare(None, Some("b"), missing),
            Check::NotChecked {
                reason: NotChecked::NoReference,
                actual: Some("b".into())
            }
        );
        assert_eq!(
            compare(Some("a"), None, NotChecked::Unreachable),
            Check::NotChecked {
                reason: NotChecked::Unreachable,
                actual: None
            }
        );
    }

    fn browserleaks(ja4: &str) -> Value {
        serde_json::json!({
            "user_agent": "x",
            "ja4": ja4,
            "ja3_hash": "9ca2569240e510d5cde6f8e7a0c3bd38",
            "ja3n_hash": "bd4930bd9b000ee684830e44bab76fdf",
            "akamai_hash": CHROMIUM_AKAMAI_HASH,
            "akamai_text": CHROMIUM_AKAMAI_TEXT,
        })
    }

    #[test]
    fn parses_both_service_formats() {
        let observed = Observed::from_tls_json(&browserleaks("t13d")).unwrap();
        assert_eq!(observed.ja4.as_deref(), Some("t13d"));
        assert_eq!(
            observed.ja3n_hash.as_deref(),
            Some("bd4930bd9b000ee684830e44bab76fdf")
        );
        assert_eq!(observed.akamai_text.as_deref(), Some(CHROMIUM_AKAMAI_TEXT));

        let peet = serde_json::json!({
            "http_version": "h2",
            "tls": {"ja3": "771,...", "ja3_hash": "360549ce", "ja4": "t13d1516h2_x"},
            "http2": {
                "akamai_fingerprint": CHROMIUM_AKAMAI_TEXT,
                "akamai_fingerprint_hash": CHROMIUM_AKAMAI_HASH,
            },
        });
        let observed = Observed::from_tls_json(&peet).unwrap();
        assert_eq!(observed.ja4.as_deref(), Some("t13d1516h2_x"));
        assert_eq!(observed.ja3_hash.as_deref(), Some("360549ce"));
        assert_eq!(observed.ja3n_hash, None);
        assert_eq!(observed.akamai_hash.as_deref(), Some(CHROMIUM_AKAMAI_HASH));

        // An HTTP/1.1 answer of browserleaks has empty Akamai fields.
        let h1 = serde_json::json!({"ja4": "t13d", "akamai_hash": "", "akamai_text": ""});
        assert_eq!(Observed::from_tls_json(&h1).unwrap().akamai_text, None);
        assert!(Observed::from_tls_json(&serde_json::json!({"message": "x"})).is_none());

        let quic = serde_json::json!({"ja4": "q13d0312h3_55b375c5d22e_178839b6cec1"});
        assert!(Observed::quic_ja4_from_json(&quic).is_some());
        let tcp = serde_json::json!({"protocol": "HTTP/1.1", "message": "Try reloading"});
        assert!(Observed::quic_ja4_from_json(&tcp).is_none());
    }

    fn owned(profile: &ProfileName) -> Vec<Reference> {
        references_for(profile).into_iter().copied().collect()
    }

    /// A client in `PqcBandwidthExperiment` is compared with the padded ClientHellos; without a
    /// padded capture the TLS hashes and the QUIC JA4 are not checked, the HTTP/2 values still are.
    #[test]
    fn padded_clients_use_the_padded_references() {
        let ids = |name_: &str, padding: Option<u16>| -> Vec<Reference> {
            let mut built = BrowserProfile::resolve(name_).unwrap();
            built.tls.server_padding_trial = None;
            built.tls.server_padding = padding;
            if let Some(tls) = built.quic.as_mut().and_then(|q| q.tls.as_mut()) {
                tls.server_padding_trial = None;
                tls.server_padding = padding;
            }
            client_references(&name(name_), &built)
        };
        let id = |references: &[Reference]| references.iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(
            id(&ids("chrome155-windows", None)),
            ["chromium-mldsa-trust-anchors", "chrome-quic"]
        );
        let padded = ids("chrome155-windows", Some(0));
        assert_eq!(
            id(&padded),
            ["chrome-server-padding", "chrome-quic-server-padding"]
        );
        assert_eq!(padded[0].ja4, Some("t13d1518h2_8daaf6152771_4980c97edce0"));
        assert_eq!(
            id(&ids("chrome152-android", Some(6000))),
            ["chrome-server-padding", "chrome-quic-server-padding"]
        );
        let unknown = ids("chrome151-android", Some(16000));
        assert_eq!(
            id(&unknown),
            ["chromium-mldsa", "chromium-quic-no-trust-anchors"]
        );
        assert!(
            unknown
                .iter()
                .all(|r| r.ja4.is_none() && r.ja3n_hash.is_none() && r.quic_ja4.is_none())
        );
        assert_eq!(unknown[0].akamai_hash, Some(CHROMIUM_AKAMAI_HASH));
    }

    fn tls_of(json: Value) -> Option<(String, Observed)> {
        Some(("svc".into(), Observed::from_tls_json(&json).unwrap()))
    }

    #[test]
    fn outcomes() {
        let chrome = name("chrome154-windows");
        let references = owned(&chrome);
        let good = "t13d1517h2_8daaf6152771_cb7bf5808d99";
        let quic = Ok((
            "q".to_string(),
            "q13d0312h3_55b375c5d22e_178839b6cec1".to_string(),
        ));

        let report_ok = report(
            &chrome,
            &references,
            tls_of(browserleaks(good)),
            quic.clone(),
            Vec::new(),
        );
        assert_eq!(report_ok.outcome, Outcome::Match);
        assert!(report_ok.is_match());
        let status = |r: &VerifyReport, field: Field| {
            r.fields
                .iter()
                .find(|f| f.field == field)
                .unwrap()
                .check
                .clone()
        };
        assert!(matches!(
            status(&report_ok, Field::Ja3Hash),
            Check::NotChecked {
                reason: NotChecked::NoReference,
                actual: Some(_)
            }
        ));
        assert!(matches!(
            status(&report_ok, Field::QuicJa4),
            Check::Match { .. }
        ));

        let bad = report(
            &chrome,
            &references,
            tls_of(browserleaks("t13d1516h2_8daaf6152771_806a8c22fdea")),
            Err(NotChecked::NoHttp3),
            Vec::new(),
        );
        assert_eq!(bad.outcome, Outcome::Mismatch);
        assert!(!bad.is_match());
        assert!(matches!(
            status(&bad, Field::QuicJa4),
            Check::NotChecked {
                reason: NotChecked::NoHttp3,
                ..
            }
        ));

        let down = ServiceFailure {
            service: "https://tls.browserleaks.com/json".into(),
            code: "CONNECTION_FAILED",
            message: "refused".into(),
        };
        let unreachable = report(
            &chrome,
            &references,
            None,
            Err(NotChecked::Unreachable),
            vec![down],
        );
        assert_eq!(unreachable.outcome, Outcome::Unreachable);
        assert!(unreachable.is_match(), "nothing was compared");
        assert!(matches!(
            status(&unreachable, Field::Ja4),
            Check::NotChecked {
                reason: NotChecked::Unreachable,
                actual: None
            }
        ));

        let unreferenced = name("firefox-mobile140");
        let none = report(
            &unreferenced,
            &owned(&unreferenced),
            tls_of(browserleaks("t13d2014h2_a09f3c656075_14788d8d241b")),
            Err(NotChecked::NoReference),
            Vec::new(),
        );
        assert_eq!(none.outcome, Outcome::NoReference);
        assert!(none.fields.iter().all(|f| matches!(
            f.check,
            Check::NotChecked {
                reason: NotChecked::NoReference,
                ..
            }
        )));
    }

    #[test]
    fn report_json_shape() {
        let chrome = name("chrome");
        let report = report(
            &chrome,
            &owned(&chrome),
            tls_of(browserleaks("t13d1516h2_8daaf6152771_806a8c22fdea")),
            Err(NotChecked::NoHttp3),
            Vec::new(),
        );
        let json: Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(json["profile"], chrome.name.as_str());
        assert_eq!(json["outcome"], "mismatch");
        assert_eq!(json["references"][0]["id"], "chromium-mldsa-trust-anchors");
        assert_eq!(json["fields"][0]["field"], "ja4");
        assert_eq!(json["fields"][0]["status"], "mismatch");
        assert_eq!(
            json["fields"][0]["expected"],
            "t13d1517h2_8daaf6152771_cb7bf5808d99"
        );
        assert_eq!(json["fields"][2]["status"], "not_checked");
        assert_eq!(json["fields"][2]["reason"], "no_reference");
        assert_eq!(json["fields"][5]["reason"], "no_http3");
        assert!(json["fields"][5].get("actual").is_none());
        assert_eq!(json["koon_version"], env!("CARGO_PKG_VERSION"));
    }
}
