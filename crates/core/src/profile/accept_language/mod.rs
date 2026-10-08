//! The Accept-Language header a browser derives from the user's language.

mod tables;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use super::{BrowserProfile, FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION};
use tables::{CHROMIUM, CHROMIUM_ANDROID_EXTRA, EDGE, FIREFOX, OPERA};

/// How a browser derives its Accept-Language header from the user's language, the BCP 47 tag
/// [`ClientBuilder::locale`](crate::ClientBuilder::locale) takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageSource {
    /// The list of the UI locale the language selects (Chrome, Opera and Brave; Edge on Windows
    /// and Linux).
    UiTable(UiTable),
    /// The language before that list (Edge on macOS).
    LanguageThenTable(UiTable),
    /// The device languages merged into that list (Chromium on Android,
    /// `TranslateBridge::PrependToAcceptLanguagesIfNecessary`).
    DeviceThenTable(UiTable),
    /// The list of the app locale the language selects (`locale_service_default_accept_languages`).
    Firefox {
        /// The Firefox version, whose lists and weights changed over time.
        version: u32,
    },
    /// The device languages alone (Firefox on Android, GeckoView's `computeAcceptLanguages`).
    Device,
    /// The first system language with the fallbacks the OS adds (Safari).
    Apple {
        /// iOS rather than macOS.
        ios: bool,
    },
    /// The language, its base language, then `en-us` and `en` (Opera for Android).
    OperaAndroid,
    /// The language, its base language, then `en-US` and `en`, unweighted (Samsung Internet).
    Samsung,
}

/// The UI locales a Chromium browser ships, each with its built-in list (`IDS_ACCEPT_LANGUAGES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTable {
    /// Chrome's and Brave's.
    Chromium,
    /// Chromium's on Android, whose additional locales list `en-US,en`.
    ChromiumAndroid,
    /// Opera's, a subset of Chromium's.
    Opera,
    /// Edge's.
    Edge,
}

/// A locale and its list.
type Entry = (&'static str, &'static str);

/// Languages Chromium maps to another UI locale (`iw` is Hebrew's old code, `tl` Filipino's).
const CHROMIUM_ALIASES: &[(&str, &str)] = &[
    ("en", "en-US"),
    ("iw", "he"),
    ("nn", "nb"),
    ("no", "nb"),
    ("pt", "pt-BR"),
    ("tl", "fil"),
    ("zh", "zh-CN"),
];
/// Edge's: Chromium's without the bare `zh`, which Edge does not resolve.
const EDGE_ALIASES: &[(&str, &str)] = &[
    ("en", "en-US"),
    ("iw", "he"),
    ("nn", "nb"),
    ("no", "nb"),
    ("pt", "pt-BR"),
    ("tl", "fil"),
];

/// The build a user of these languages downloads: Firefox ships them only with a region, or in
/// several.
const FIREFOX_ALIASES: &[(&str, &str)] = &[
    ("en", "en-US"),
    ("es", "es-ES"),
    ("fy", "fy-NL"),
    ("ga", "ga-IE"),
    ("gu", "gu-IN"),
    ("hi", "hi-IN"),
    ("hy", "hy-AM"),
    ("nb", "nb-NO"),
    ("ne", "ne-NP"),
    ("nn", "nn-NO"),
    ("no", "nb-NO"),
    ("pa", "pa-IN"),
    ("pt", "pt-BR"),
    ("sv", "sv-SE"),
    ("zh", "zh-CN"),
];

/// Lists that differed before [`FIREFOX`]'s: up to 145 the language packs', 146-151 those of
/// Firefox's first built-in table.
const FIREFOX_EARLIER: &[(Range<u32>, &str, &str)] = &[
    (0..146, "pt-PT", "pt-PT,pt,en,en-US"),
    (0..146, "ro", "ro-RO,ro,en-US,en-GB,en"),
    (0..146, "uz", "uz,ru,en,en-US"),
    (146..152, "lt", "lt,ru,pl,en-US,en"),
];

/// Safari's localizations and the region it gives every tag of that language (`de-AT` becomes
/// `de-DE`).
const APPLE_REGIONS: &[(&str, &str)] = &[
    ("ca", "ES"),
    ("cs", "CZ"),
    ("da", "DK"),
    ("de", "DE"),
    ("el", "GR"),
    ("fi", "FI"),
    ("he", "IL"),
    ("hi", "IN"),
    ("hr", "HR"),
    ("hu", "HU"),
    ("id", "ID"),
    ("it", "IT"),
    ("ko", "KR"),
    ("ms", "MY"),
    ("nb", "NO"),
    ("nl", "NL"),
    ("pl", "PL"),
    ("ro", "RO"),
    ("sk", "SK"),
    ("sv", "SE"),
    ("th", "TH"),
    ("tr", "TR"),
    ("uk", "UA"),
    ("vi", "VN"),
];

/// The Accept-Language header `profile` sends for the user's language `locale`; a profile without
/// a [`LanguageSource`] sends the tag as given.
pub(crate) fn accept_language(profile: &BrowserProfile, locale: &str) -> String {
    let Some(source) = profile.language_source else {
        return locale.to_string();
    };
    let languages = source.languages(&[locale]);
    if profile.farble_accept_language {
        // Brave's Shields: the first language and its base language; the q value follows per site.
        let first = &languages[0];
        return match first.split_once('-') {
            Some((base, _)) => format!("{first},{base}"),
            None => first.clone(),
        };
    }
    weigh(&languages, source.weights())
}

impl LanguageSource {
    /// The languages the browser sends, in order, for the user's languages (the device's on
    /// Android, the first one elsewhere).
    fn languages(self, user: &[&str]) -> Vec<String> {
        let first = user.first().copied().unwrap_or_default();
        match self {
            Self::UiTable(table) => expand_language_list(&split(table.list(first))),
            Self::LanguageThenTable(table) => {
                let mut languages = vec![first.to_string()];
                languages.extend(split(table.list(first)).into_iter().filter(|l| l != first));
                expand_language_list(&languages)
            }
            Self::DeviceThenTable(table) => {
                expand_language_list(&prepend_to_accept_languages(user, table.list(first)))
            }
            Self::Firefox { version } => split(firefox_list(first, version)),
            Self::Device => user
                .iter()
                .map(|tag| Tag::parse(tag).language_region())
                .collect(),
            Self::Apple { ios } => apple_languages(&Tag::parse(first), ios),
            Self::OperaAndroid => {
                let mut languages: Vec<String> = Vec::new();
                for language in [first, "en-us", "en"] {
                    if !languages.iter().any(|l| l.eq_ignore_ascii_case(language)) {
                        languages.push(language.to_string());
                    }
                }
                expand_language_list(&languages)
            }
            Self::Samsung if first.eq_ignore_ascii_case("en-US") => split("en-US,en"),
            Self::Samsung => {
                let mut languages = vec![first.to_string()];
                if let Some((base, _)) = first.split_once('-') {
                    languages.push(base.to_string());
                }
                languages.extend(["en-US".to_string(), "en".to_string()]);
                languages
            }
        }
    }

    fn weights(self) -> Weights {
        match self {
            Self::Firefox { version } if version < FIREFOX_WEIGHTED_ACCEPT_LANGUAGE_VERSION => {
                Weights::EvenSplit
            }
            Self::Samsung => Weights::None,
            _ => Weights::Decrement,
        }
    }
}

impl UiTable {
    /// The list of the UI locale the browser picks for `language`, en-US's if it picks none.
    fn list(self, language: &str) -> &'static str {
        let aliases = match self {
            Self::Edge => EDGE_ALIASES,
            _ => CHROMIUM_ALIASES,
        };
        negotiate(&Tag::parse(language), |locale| self.entry(locale), aliases)
            .map_or("en-US,en", |(_, list)| list)
    }

    fn entry(self, locale: &str) -> Option<Entry> {
        let chromium = || find(CHROMIUM, locale);
        match self {
            Self::Chromium => chromium(),
            Self::ChromiumAndroid => chromium().or_else(|| {
                CHROMIUM_ANDROID_EXTRA
                    .iter()
                    .find(|extra| extra.eq_ignore_ascii_case(locale))
                    .map(|&extra| (extra, "en-US,en"))
            }),
            Self::Opera => chromium().filter(|(name, _)| OPERA.contains(name)),
            Self::Edge => find(EDGE, locale),
        }
    }
}

fn find(table: &'static [Entry], locale: &str) -> Option<Entry> {
    table
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(locale))
        .copied()
}

/// The locale a browser picks for `tag` among those `entry` knows: the tag itself; for Chinese the
/// locale of its script, for English, Spanish and Portuguese that of its region's variety (CLDR's
/// parent locales); else the language's alias, or the language itself.
fn negotiate(
    tag: &Tag,
    entry: impl Fn(&str) -> Option<Entry>,
    aliases: &[(&str, &str)],
) -> Option<Entry> {
    if let Some(found) = entry(&tag.to_string()) {
        return Some(found);
    }
    // A script the locales lack (`sr-Latn` against Cyrillic `sr`) matches nothing.
    if tag.script.is_some() && tag.language != "zh" {
        return None;
    }
    if let Some(found) = tag.variety().and_then(&entry) {
        return Some(found);
    }
    let language = aliases
        .iter()
        .find(|(from, _)| *from == tag.language)
        .map_or(tag.language.as_str(), |&(_, to)| to);
    entry(language)
}

/// Firefox's list for the app locale it ships for `language`, en-US's if it ships none.
fn firefox_list(language: &str, version: u32) -> &'static str {
    let (locale, list) = negotiate(
        &Tag::parse(language),
        |locale| find(FIREFOX, locale),
        FIREFOX_ALIASES,
    )
    .unwrap_or(("en-US", "en-US,en"));
    FIREFOX_EARLIER
        .iter()
        .find(|(versions, earlier, _)| versions.contains(&version) && *earlier == locale)
        .map_or(list, |&(_, _, list)| list)
}

/// Safari's languages for the first system language, as CFNetwork maps it.
fn apple_languages(tag: &Tag, ios: bool) -> Vec<String> {
    let language = tag.language.as_str();
    let region = tag.region.as_deref();
    let with_base = |tag: String| vec![tag, language.to_string()];
    match (language, region) {
        ("ar" | "ja" | "ru", _) => vec![language.to_string()],
        ("zh", _) => {
            let traditional = tag.is_traditional_chinese();
            let region = match region {
                Some(region @ ("TW" | "HK")) => region,
                _ if traditional => "TW",
                _ => "CN",
            };
            let script = if traditional { "Hant" } else { "Hans" };
            vec![format!("zh-{region}"), format!("zh-{script}")]
        }
        ("en", None | Some("US")) => split("en-US,en"),
        ("en", Some("CA")) => split("en-CA,en-US,en"),
        ("en", Some("IN")) if ios => split("en-IN,en"),
        ("en", Some("IN")) => split("en-IN,en-GB,en"),
        ("en", Some(region @ ("GB" | "AU"))) => with_base(format!("en-{region}")),
        ("en", Some(_)) => split("en-GB,en"),
        ("es", None | Some("ES")) => split("es-ES,es"),
        ("es", Some(region @ ("MX" | "US"))) => split(&format!("es-{region},es-419,es")),
        ("es", Some(_)) => split("es-419,es"),
        ("pt", None | Some("BR")) => split("pt-BR,pt"),
        ("pt", Some(_)) => split("pt-PT,pt"),
        ("fr", Some("CA")) => split("fr-CA,fr"),
        ("fr", _) => split("fr-FR,fr"),
        _ => match APPLE_REGIONS.iter().find(|(l, _)| *l == language) {
            Some((_, region)) => with_base(format!("{language}-{region}")),
            // A language the OS is not localized in.
            None => vec![language.to_string(), "en-US".into(), "en".into()],
        },
    }
}

/// Chromium on Android: the device languages before the UI locale's list, duplicates (by language
/// and region) dropped, each bare language moved after the last tag of that language
/// (`TranslateBridge::PrependToAcceptLanguagesIfNecessary`).
fn prepend_to_accept_languages(device: &[&str], list: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let unique: Vec<(String, Option<String>)> = device
        .iter()
        .copied()
        .chain(list.split(','))
        .map(|tag| {
            let tag = Tag::parse(tag);
            (tag.language, tag.region)
        })
        .filter(|pair| seen.insert(pair.clone()))
        .collect();
    let mut seen_languages = HashSet::new();
    let mut languages = Vec::new();
    for (language, region) in unique.iter().rev() {
        if seen_languages.insert(language) {
            languages.push(language.clone());
        }
        if let Some(region) = region {
            languages.push(format!("{language}-{region}"));
        }
    }
    languages.reverse();
    languages
}

/// Chromium's `net::HttpUtil::ExpandLanguageList`: after each language whose successor has another
/// base language, its base language too (`de-DE,fr` becomes `de-DE,de,fr`), without duplicates.
fn expand_language_list(languages: &[String]) -> Vec<String> {
    let mut expanded: Vec<String> = Vec::new();
    let mut add = |language: &str| {
        if !expanded.iter().any(|l| l == language) {
            expanded.push(language.to_string());
        }
    };
    for (i, language) in languages.iter().enumerate() {
        add(language);
        let base = base_language(language);
        // RFC 5646 reserves `x` and `i` as primary subtags.
        if base != "x"
            && base != "i"
            && languages
                .get(i + 1)
                .is_none_or(|next| base_language(next) != base)
        {
            add(base);
        }
    }
    expanded
}

fn base_language(language: &str) -> &str {
    language.split('-').next().unwrap_or(language)
}

/// How a browser weights the languages of its header.
#[derive(Debug, Clone, Copy)]
enum Weights {
    /// Chromium, Safari and Firefox 147+: 0.9, 0.8, ... down to 0.1.
    Decrement,
    /// Firefox up to 146: the weights divide 1.0 evenly (`en-US,en;q=0.5`).
    EvenSplit,
    /// Samsung Internet: none.
    None,
}

fn weigh(languages: &[String], weights: Weights) -> String {
    let n = languages.len();
    languages
        .iter()
        .enumerate()
        .map(|(i, language)| {
            let q = match weights {
                _ if i == 0 => return language.clone(),
                Weights::None => return language.clone(),
                Weights::Decrement => (10 - i.min(9)) as f64 / 10.0,
                // q = 1 - i/n, rounded to one decimal.
                Weights::EvenSplit => ((1.0 - i as f64 / n as f64) * 10.0).round() / 10.0,
            };
            format!("{language};q={q:.1}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn split(list: &str) -> Vec<String> {
    list.split(',').map(str::to_string).collect()
}

/// A language tag's language, script and region, cased as BCP 47 writes them (`zh-Hant-TW`);
/// variants and extensions are dropped.
#[derive(Debug)]
struct Tag {
    language: String,
    script: Option<String>,
    region: Option<String>,
}

impl Tag {
    fn parse(tag: &str) -> Self {
        let mut subtags = tag.split(['-', '_']);
        let language = subtags.next().unwrap_or_default().to_ascii_lowercase();
        let (mut script, mut region) = (None, None);
        for subtag in subtags {
            let alphabetic = subtag.bytes().all(|b| b.is_ascii_alphabetic());
            match subtag.len() {
                4 if alphabetic && script.is_none() && region.is_none() => {
                    let (first, rest) = subtag.split_at(1);
                    script = Some(first.to_ascii_uppercase() + &rest.to_ascii_lowercase());
                }
                2 if alphabetic && region.is_none() => region = Some(subtag.to_ascii_uppercase()),
                3 if subtag.bytes().all(|b| b.is_ascii_digit()) && region.is_none() => {
                    region = Some(subtag.to_string());
                }
                _ => break,
            }
        }
        Self {
            language,
            script,
            region,
        }
    }

    fn is_traditional_chinese(&self) -> bool {
        self.script.as_deref() == Some("Hant")
            || matches!(self.region.as_deref(), Some("TW" | "HK" | "MO"))
    }

    /// The tag without its script (`zh-Hans-CN` becomes `zh-CN`).
    fn language_region(&self) -> String {
        match &self.region {
            Some(region) => format!("{}-{region}", self.language),
            None => self.language.clone(),
        }
    }

    /// The locale of the tag's script (Chinese) or of its region's variety (English, Spanish,
    /// Portuguese).
    fn variety(&self) -> Option<&'static str> {
        let region = self.region.as_deref();
        match self.language.as_str() {
            "zh" if self.is_traditional_chinese() => Some("zh-TW"),
            "zh" if self.script.is_some() || region.is_some() => Some("zh-CN"),
            "en" => region.map(|region| if region == "US" { "en-US" } else { "en-GB" }),
            "es" => region.filter(|&region| region != "ES").map(|_| "es-419"),
            "pt" => region.filter(|&region| region != "BR").map(|_| "pt-PT"),
            _ => None,
        }
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.language)?;
        if let Some(script) = &self.script {
            write!(f, "-{script}")?;
        }
        if let Some(region) = &self.region {
            write!(f, "-{region}")?;
        }
        Ok(())
    }
}
