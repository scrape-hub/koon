//! Every value here was captured from the real browser, unless a test says otherwise.

use super::*;
use crate::profile::{Brave, BrowserProfile, Os};

fn header(source: LanguageSource, user: &[&str]) -> String {
    weigh(&source.languages(user), source.weights())
}

fn check(source: LanguageSource, rows: &[(&str, &str)]) {
    for &(language, expected) in rows {
        assert_eq!(
            header(source, &[language]),
            expected,
            "{source:?} {language}"
        );
    }
}

/// Android rows: the app's languages followed by the device's (`de-DE`), as the captures set them.
fn check_device(source: LanguageSource, rows: &[(&[&str], &str)]) {
    for &(user, expected) in rows {
        assert_eq!(header(source, user), expected, "{source:?} {user:?}");
    }
}

/// What a Chromium browser falls back to for a language it has no UI locale for. The captures ran
/// on a German Windows, whose display language was the fallback there.
const CHROMIUM_FALLBACK: &str = "en-US,en;q=0.9";

#[test]
fn chrome_desktop() {
    // Chrome 155 on Windows with `--lang`; Linux and macOS (152) send the same tables.
    check(
        LanguageSource::UiTable(UiTable::Chromium),
        &[
            ("es", "es-ES,es;q=0.9"),
            ("de", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh-CN", "zh-CN,zh;q=0.9"),
            ("en-GB", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("lt", "lt,en-US;q=0.9,en;q=0.8,ru;q=0.7,pl;q=0.6"),
            ("fil", "fil,fil-PH;q=0.9,tl;q=0.8,en-US;q=0.7,en;q=0.6"),
            ("es-MX", "es-419,es;q=0.9"),
            ("es-AR", "es-419,es;q=0.9"),
            ("es-US", "es-419,es;q=0.9"),
            ("en-AU", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("en-CA", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("en-IN", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("en-NZ", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("en-ZA", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("en-IE", "en-GB,en-US;q=0.9,en;q=0.8"),
            ("pt", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("pt-AO", "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh", "zh-CN,zh;q=0.9"),
            ("zh-HK", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh-TW", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh-SG", "zh-CN,zh;q=0.9"),
            ("zh-Hant", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh-Hans", "zh-CN,zh;q=0.9"),
            ("de-AT", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("de-CH", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("fr-CH", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("fr-CA", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("fr-BE", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("nl-BE", "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("it-CH", "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7"),
            (
                "no",
                "nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5",
            ),
            (
                "nb-NO",
                "nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5",
            ),
            (
                "nn",
                "nb-NO,nb;q=0.9,no;q=0.8,nn;q=0.7,en-US;q=0.6,en;q=0.5",
            ),
            ("he", "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("iw", "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("tl", "fil,fil-PH;q=0.9,tl;q=0.8,en-US;q=0.7,en;q=0.6"),
            ("sw-KE", "sw,en-GB;q=0.9,en;q=0.8"),
            ("af-ZA", "en-US,en;q=0.9"),
            ("sr-Latn-RS", CHROMIUM_FALLBACK),
            ("xx-YY", CHROMIUM_FALLBACK),
            // macOS, from AppleLanguages.
            ("de-DE", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("fr-FR", "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("zh-Hans-CN", "zh-CN,zh;q=0.9"),
        ],
    );
}

#[test]
fn opera_desktop() {
    // Opera 136 on Windows.
    check(
        LanguageSource::UiTable(UiTable::Opera),
        &[
            ("de", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            ("es", "es-ES,es;q=0.9"),
            ("zh-CN", "zh-CN,zh;q=0.9"),
        ],
    );
}

#[test]
fn edge_desktop() {
    // Edge 154 on Windows with `--lang`; Linux sends the same.
    let es_419 = "es-419,es;q=0.9,es-ES;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5";
    let en_gb = "en-GB,en;q=0.9,en-US;q=0.8";
    let zh_tw = "zh-TW,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6";
    let zh_cn = "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6";
    let de = "de,de-DE;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6";
    let fr = "fr,fr-FR;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6";
    let fr_ca = "fr-CA,fr;q=0.9,fr-FR;q=0.8,en-CA;q=0.7,en;q=0.6,en-US;q=0.5,en-GB;q=0.4";
    let pt_pt = "pt-PT,pt;q=0.9,pt-BR;q=0.8,en;q=0.7,en-US;q=0.6,en-GB;q=0.5";
    let nb = "nb,no;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6";
    let he = "he,en;q=0.9,en-GB;q=0.8,en-US;q=0.7";
    check(
        LanguageSource::UiTable(UiTable::Edge),
        &[
            ("de", de),
            ("zh-CN", zh_cn),
            (
                "bn-IN",
                "bn-IN,bn;q=0.9,en-IN;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5",
            ),
            ("pt-PT", pt_pt),
            ("fr-CA", fr_ca),
            ("en-GB", en_gb),
            ("es-MX", es_419),
            ("es-AR", es_419),
            ("es-US", es_419),
            ("en-AU", en_gb),
            ("en-CA", en_gb),
            ("en-IN", en_gb),
            ("en-NZ", en_gb),
            ("en-ZA", en_gb),
            ("en-IE", en_gb),
            ("pt", "pt-BR,pt;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
            ("pt-AO", pt_pt),
            ("zh-HK", zh_tw),
            ("zh-TW", zh_tw),
            ("zh-SG", zh_cn),
            ("zh-Hant", zh_tw),
            ("zh-Hans", zh_cn),
            ("de-AT", de),
            ("de-CH", de),
            ("fr-CH", fr),
            ("fr-BE", fr),
            ("nl-BE", "nl,en;q=0.9,en-GB;q=0.8,en-US;q=0.7"),
            ("it-CH", "it,it-IT;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
            (
                "sr-Latn-RS",
                "sr-Latn-RS,sr-Cyrl-RS;q=0.9,sr;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5",
            ),
            ("no", nb),
            ("nb-NO", nb),
            (
                "nn",
                "nn,nb;q=0.9,no;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5",
            ),
            ("he", he),
            ("iw", he),
            ("tl", "fil,en;q=0.9,en-US;q=0.8"),
            ("af-ZA", "af,en-ZA;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
            ("zh", CHROMIUM_FALLBACK),
            ("sw-KE", CHROMIUM_FALLBACK),
            ("xx-YY", CHROMIUM_FALLBACK),
        ],
    );
}

#[test]
fn edge_macos_puts_the_language_first() {
    // Edge 152 on macOS, from AppleLanguages.
    check(
        LanguageSource::LanguageThenTable(UiTable::Edge),
        &[
            ("de-DE", "de-DE,de;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
            (
                "de-AT",
                "de-AT,de;q=0.9,de-DE;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5",
            ),
            ("fr-FR", "fr-FR,fr;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"),
            ("en-GB", "en-GB,en;q=0.9,en-US;q=0.8"),
            (
                "zh-Hans-CN",
                "zh-Hans-CN,zh-CN;q=0.9,zh;q=0.8,en;q=0.7,en-GB;q=0.6,en-US;q=0.5",
            ),
        ],
    );
}

#[test]
fn chrome_android_merges_the_device_languages() {
    // Chrome Beta 156 on Android 17.
    check_device(
        LanguageSource::DeviceThenTable(UiTable::ChromiumAndroid),
        &[
            (&["de-DE"], "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
            (&["en-US", "de-DE"], "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7"),
            (
                &["de-AT", "de-DE"],
                "de-AT,de-DE;q=0.9,de;q=0.8,en-US;q=0.7,en;q=0.6",
            ),
            (
                &["fr-FR", "de-DE"],
                "fr-FR,fr;q=0.9,de-DE;q=0.8,de;q=0.7,en-US;q=0.6,en;q=0.5",
            ),
            (&["zh-CN", "de-DE"], "zh-CN,zh;q=0.9,de-DE;q=0.8,de;q=0.7"),
            (
                &["en-GB", "de-DE"],
                "en-GB,en;q=0.9,de-DE;q=0.8,de;q=0.7,en-US;q=0.6",
            ),
        ],
    );
}

#[test]
fn edge_android_merges_the_device_languages() {
    // Edge 154 on Android 17.
    check_device(
        LanguageSource::DeviceThenTable(UiTable::Edge),
        &[
            (
                &["de-DE"],
                "de-DE,de;q=0.9,en-GB;q=0.8,en-US;q=0.7,en;q=0.6",
            ),
            (&["en-US", "de-DE"], "en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7"),
            (
                &["de-AT", "de-DE"],
                "de-AT,de-DE;q=0.9,de;q=0.8,en-GB;q=0.7,en-US;q=0.6,en;q=0.5",
            ),
            (
                &["fr-FR", "de-DE"],
                "fr-FR,fr;q=0.9,de-DE;q=0.8,de;q=0.7,en-GB;q=0.6,en-US;q=0.5,en;q=0.4",
            ),
            (
                &["zh-CN", "de-DE"],
                "zh-CN,zh;q=0.9,de-DE;q=0.8,de;q=0.7,en-GB;q=0.6,en-US;q=0.5,en;q=0.4",
            ),
            (
                &["en-GB", "de-DE"],
                "en-GB,en;q=0.9,de-DE;q=0.8,de;q=0.7,en-US;q=0.6",
            ),
        ],
    );
}

#[test]
fn opera_android() {
    // Opera 102 for Android: the first language only.
    check_device(
        LanguageSource::OperaAndroid,
        &[
            (&["de-DE"], "de-DE,de;q=0.9,en-us;q=0.8,en;q=0.7"),
            (&["en-US", "de-DE"], "en-US,en;q=0.9"),
            (&["de-AT", "de-DE"], "de-AT,de;q=0.9,en-us;q=0.8,en;q=0.7"),
            (&["fr-FR", "de-DE"], "fr-FR,fr;q=0.9,en-us;q=0.8,en;q=0.7"),
            (&["zh-CN", "de-DE"], "zh-CN,zh;q=0.9,en-us;q=0.8,en;q=0.7"),
            (&["en-GB", "de-DE"], "en-GB,en-us;q=0.9,en;q=0.8"),
            (&["de", "de-DE"], "de,en-us;q=0.9,en;q=0.8"),
        ],
    );
}

#[test]
fn samsung_internet() {
    // Samsung Internet 30 on Android 17: the first language only, unweighted.
    check_device(
        LanguageSource::Samsung,
        &[
            (&["de-DE"], "de-DE,de,en-US,en"),
            (&["en-US", "de-DE"], "en-US,en"),
            (&["de-AT", "de-DE"], "de-AT,de,en-US,en"),
            (&["fr-FR", "de-DE"], "fr-FR,fr,en-US,en"),
            (&["zh-CN", "de-DE"], "zh-CN,zh,en-US,en"),
            (&["en-GB", "de-DE"], "en-GB,en,en-US,en"),
        ],
    );
}

#[test]
fn firefox_android_sends_the_device_languages() {
    // Firefox 157 and 158 for Android.
    check_device(
        LanguageSource::Device,
        &[
            (&["de-DE"], "de-DE"),
            (&["en-US", "de-DE"], "en-US,de-DE;q=0.9"),
            (&["de-AT", "de-DE"], "de-AT,de-DE;q=0.9"),
            (&["fr-FR", "de-DE"], "fr-FR,de-DE;q=0.9"),
            (&["zh-CN", "de-DE"], "zh-CN,de-DE;q=0.9"),
            (&["en-GB", "de-DE"], "en-GB,de-DE;q=0.9"),
            (&["de", "de-DE"], "de,de-DE;q=0.9"),
        ],
    );
}

#[test]
fn brave_sends_the_first_language_and_its_base() {
    // Brave 1.96 on Windows (`--lang`) and 1.97 on Android, without the per-site q value.
    for (os, language, expected) in [
        (Os::Windows, "de", "de-DE,de"),
        (Os::Windows, "es", "es-ES,es"),
        (Os::Windows, "zh-CN", "zh-CN,zh"),
        (Os::Android, "de-DE", "de-DE,de"),
        (Os::Android, "en-US", "en-US,en"),
        (Os::Android, "de-AT", "de-AT,de"),
        (Os::Android, "fr-FR", "fr-FR,fr"),
        (Os::Android, "zh-CN", "zh-CN,zh"),
        (Os::Android, "en-GB", "en-GB,en"),
    ] {
        let profile = Brave::version(154, os).unwrap();
        assert_eq!(
            accept_language(&profile, language),
            expected,
            "{os:?} {language}"
        );
    }
}

#[test]
fn firefox_desktop() {
    // Firefox in that locale's build.
    for (version, language, expected) in [
        (157, "fr", "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7"),
        (157, "lt", "lt,en-US;q=0.9,en;q=0.8,ru;q=0.7,pl;q=0.6"),
        (145, "pt-PT", "pt-PT,pt;q=0.8,en;q=0.5,en-US;q=0.3"),
        (145, "fr", "fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3"),
    ] {
        let source = LanguageSource::Firefox { version };
        assert_eq!(
            header(source, &[language]),
            expected,
            "{version} {language}"
        );
    }
}

#[test]
fn firefox_lists_follow_the_version() {
    // From the source: language packs up to 145, the built-in table of 146-151, then of 152.
    for (version, expected) in [
        (145, "lt,en-US;q=0.8,en;q=0.6,ru;q=0.4,pl;q=0.2"),
        (146, "lt,ru;q=0.8,pl;q=0.6,en-US;q=0.4,en;q=0.2"),
        (151, "lt,ru;q=0.9,pl;q=0.8,en-US;q=0.7,en;q=0.6"),
        (152, "lt,en-US;q=0.9,en;q=0.8,ru;q=0.7,pl;q=0.6"),
    ] {
        let source = LanguageSource::Firefox { version };
        assert_eq!(header(source, &["lt-LT"]), expected, "{version}");
    }
    let source = LanguageSource::Firefox { version: 158 };
    for (language, expected) in [
        ("de-AT", "de,en-US;q=0.9,en;q=0.8"),
        ("es", "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("sv", "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("zh-HK", "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("xx", "en-US,en;q=0.9"),
    ] {
        assert_eq!(header(source, &[language]), expected, "{language}");
    }
}

#[test]
fn safari_macos() {
    // Safari 26.6 on macOS 26, one language in AppleLanguages each.
    check(
        LanguageSource::Apple { ios: false },
        &[
            ("ar", "ar"),
            ("ar-SA", "ar"),
            ("ca", "ca-ES,ca;q=0.9"),
            ("ca-ES", "ca-ES,ca;q=0.9"),
            ("cs", "cs-CZ,cs;q=0.9"),
            ("cs-CZ", "cs-CZ,cs;q=0.9"),
            ("da", "da-DK,da;q=0.9"),
            ("da-DK", "da-DK,da;q=0.9"),
            ("de", "de-DE,de;q=0.9"),
            ("de-AT", "de-DE,de;q=0.9"),
            ("de-CH", "de-DE,de;q=0.9"),
            ("de-DE", "de-DE,de;q=0.9"),
            ("el", "el-GR,el;q=0.9"),
            ("el-GR", "el-GR,el;q=0.9"),
            ("en", "en-US,en;q=0.9"),
            ("en-AU", "en-AU,en;q=0.9"),
            ("en-CA", "en-CA,en-US;q=0.9,en;q=0.8"),
            ("en-IN", "en-IN,en-GB;q=0.9,en;q=0.8"),
            ("en-GB", "en-GB,en;q=0.9"),
            ("en-US", "en-US,en;q=0.9"),
            ("es", "es-ES,es;q=0.9"),
            ("es-ES", "es-ES,es;q=0.9"),
            ("es-MX", "es-MX,es-419;q=0.9,es;q=0.8"),
            ("es-US", "es-US,es-419;q=0.9,es;q=0.8"),
            ("es-419", "es-419,es;q=0.9"),
            ("fi", "fi-FI,fi;q=0.9"),
            ("fi-FI", "fi-FI,fi;q=0.9"),
            ("fr", "fr-FR,fr;q=0.9"),
            ("fr-CA", "fr-CA,fr;q=0.9"),
            ("fr-CH", "fr-FR,fr;q=0.9"),
            ("fr-FR", "fr-FR,fr;q=0.9"),
            ("he", "he-IL,he;q=0.9"),
            ("he-IL", "he-IL,he;q=0.9"),
            ("hi", "hi-IN,hi;q=0.9"),
            ("hi-IN", "hi-IN,hi;q=0.9"),
            ("hr", "hr-HR,hr;q=0.9"),
            ("hr-HR", "hr-HR,hr;q=0.9"),
            ("hu", "hu-HU,hu;q=0.9"),
            ("hu-HU", "hu-HU,hu;q=0.9"),
            ("id", "id-ID,id;q=0.9"),
            ("id-ID", "id-ID,id;q=0.9"),
            ("it", "it-IT,it;q=0.9"),
            ("it-IT", "it-IT,it;q=0.9"),
            ("ja", "ja"),
            ("ja-JP", "ja"),
            ("ko", "ko-KR,ko;q=0.9"),
            ("ko-KR", "ko-KR,ko;q=0.9"),
            ("ms", "ms-MY,ms;q=0.9"),
            ("ms-MY", "ms-MY,ms;q=0.9"),
            ("nb", "nb-NO,nb;q=0.9"),
            ("nb-NO", "nb-NO,nb;q=0.9"),
            ("nl", "nl-NL,nl;q=0.9"),
            ("nl-NL", "nl-NL,nl;q=0.9"),
            ("pl", "pl-PL,pl;q=0.9"),
            ("pl-PL", "pl-PL,pl;q=0.9"),
            ("pt", "pt-BR,pt;q=0.9"),
            ("pt-BR", "pt-BR,pt;q=0.9"),
            ("pt-PT", "pt-PT,pt;q=0.9"),
            ("ro", "ro-RO,ro;q=0.9"),
            ("ro-RO", "ro-RO,ro;q=0.9"),
            ("ru", "ru"),
            ("ru-RU", "ru"),
            ("sk", "sk-SK,sk;q=0.9"),
            ("sk-SK", "sk-SK,sk;q=0.9"),
            ("sv", "sv-SE,sv;q=0.9"),
            ("sv-SE", "sv-SE,sv;q=0.9"),
            ("th", "th-TH,th;q=0.9"),
            ("th-TH", "th-TH,th;q=0.9"),
            ("tr", "tr-TR,tr;q=0.9"),
            ("tr-TR", "tr-TR,tr;q=0.9"),
            ("uk", "uk-UA,uk;q=0.9"),
            ("uk-UA", "uk-UA,uk;q=0.9"),
            ("vi", "vi-VN,vi;q=0.9"),
            ("vi-VN", "vi-VN,vi;q=0.9"),
            ("zh-Hant-TW", "zh-TW,zh-Hant;q=0.9"),
            ("zh-Hant-HK", "zh-HK,zh-Hant;q=0.9"),
            ("zh-Hans", "zh-CN,zh-Hans;q=0.9"),
            ("zh-Hans-CN", "zh-CN,zh-Hans;q=0.9"),
            ("zh-TW", "zh-TW,zh-Hant;q=0.9"),
            ("zh-HK", "zh-HK,zh-Hant;q=0.9"),
            ("zh-CN", "zh-CN,zh-Hans;q=0.9"),
            ("zh", "zh-CN,zh-Hans;q=0.9"),
            ("sw-KE", "sw,en-US;q=0.9,en;q=0.8"),
            ("sw", "sw,en-US;q=0.9,en;q=0.8"),
            ("eu-ES", "eu,en-US;q=0.9,en;q=0.8"),
            ("eu", "eu,en-US;q=0.9,en;q=0.8"),
            ("en-DE", "en-GB,en;q=0.9"),
            ("de-US", "de-DE,de;q=0.9"),
            ("fr-DE", "fr-FR,fr;q=0.9"),
        ],
    );
}

#[test]
fn safari_ios() {
    // Mobile Safari on iOS 26.5; iOS 17.0.1 and 18.1 sent the same for en-US and de-AT.
    check(
        LanguageSource::Apple { ios: true },
        &[
            ("ar", "ar"),
            ("ar-SA", "ar"),
            ("ca", "ca-ES,ca;q=0.9"),
            ("ca-ES", "ca-ES,ca;q=0.9"),
            ("cs", "cs-CZ,cs;q=0.9"),
            ("cs-CZ", "cs-CZ,cs;q=0.9"),
            ("da", "da-DK,da;q=0.9"),
            ("da-DK", "da-DK,da;q=0.9"),
            ("de", "de-DE,de;q=0.9"),
            ("de-AT", "de-DE,de;q=0.9"),
            ("de-CH", "de-DE,de;q=0.9"),
            ("de-DE", "de-DE,de;q=0.9"),
            ("el", "el-GR,el;q=0.9"),
            ("el-GR", "el-GR,el;q=0.9"),
            ("en", "en-US,en;q=0.9"),
            ("en-AU", "en-AU,en;q=0.9"),
            ("en-CA", "en-CA,en-US;q=0.9,en;q=0.8"),
            ("en-IN", "en-IN,en;q=0.9"),
            ("en-GB", "en-GB,en;q=0.9"),
            ("en-US", "en-US,en;q=0.9"),
            ("es", "es-ES,es;q=0.9"),
            ("es-ES", "es-ES,es;q=0.9"),
            ("es-MX", "es-MX,es-419;q=0.9,es;q=0.8"),
            ("es-US", "es-US,es-419;q=0.9,es;q=0.8"),
            ("es-419", "es-419,es;q=0.9"),
            ("fi", "fi-FI,fi;q=0.9"),
            ("fi-FI", "fi-FI,fi;q=0.9"),
            ("fr", "fr-FR,fr;q=0.9"),
            ("fr-CA", "fr-CA,fr;q=0.9"),
            ("fr-CH", "fr-FR,fr;q=0.9"),
            ("fr-FR", "fr-FR,fr;q=0.9"),
            ("he", "he-IL,he;q=0.9"),
            ("he-IL", "he-IL,he;q=0.9"),
            ("hi", "hi-IN,hi;q=0.9"),
            ("hi-IN", "hi-IN,hi;q=0.9"),
            ("hr", "hr-HR,hr;q=0.9"),
            ("hr-HR", "hr-HR,hr;q=0.9"),
            ("hu", "hu-HU,hu;q=0.9"),
            ("hu-HU", "hu-HU,hu;q=0.9"),
            ("id", "id-ID,id;q=0.9"),
            ("id-ID", "id-ID,id;q=0.9"),
            ("it", "it-IT,it;q=0.9"),
            ("it-IT", "it-IT,it;q=0.9"),
            ("ja", "ja"),
            ("ja-JP", "ja"),
            ("ko", "ko-KR,ko;q=0.9"),
            ("ko-KR", "ko-KR,ko;q=0.9"),
            ("ms", "ms-MY,ms;q=0.9"),
            ("ms-MY", "ms-MY,ms;q=0.9"),
            ("nb", "nb-NO,nb;q=0.9"),
            ("nb-NO", "nb-NO,nb;q=0.9"),
            ("nl", "nl-NL,nl;q=0.9"),
            ("nl-NL", "nl-NL,nl;q=0.9"),
            ("pl", "pl-PL,pl;q=0.9"),
            ("pl-PL", "pl-PL,pl;q=0.9"),
            ("pt", "pt-BR,pt;q=0.9"),
            ("pt-BR", "pt-BR,pt;q=0.9"),
            ("pt-PT", "pt-PT,pt;q=0.9"),
            ("ro", "ro-RO,ro;q=0.9"),
            ("ro-RO", "ro-RO,ro;q=0.9"),
            ("ru", "ru"),
            ("ru-RU", "ru"),
            ("sk", "sk-SK,sk;q=0.9"),
            ("sk-SK", "sk-SK,sk;q=0.9"),
            ("sv", "sv-SE,sv;q=0.9"),
            ("sv-SE", "sv-SE,sv;q=0.9"),
            ("th", "th-TH,th;q=0.9"),
            ("th-TH", "th-TH,th;q=0.9"),
            ("tr", "tr-TR,tr;q=0.9"),
            ("tr-TR", "tr-TR,tr;q=0.9"),
            ("uk", "uk-UA,uk;q=0.9"),
            ("uk-UA", "uk-UA,uk;q=0.9"),
            ("vi", "vi-VN,vi;q=0.9"),
            ("vi-VN", "vi-VN,vi;q=0.9"),
            ("zh-Hant-TW", "zh-TW,zh-Hant;q=0.9"),
            ("zh-Hant-HK", "zh-HK,zh-Hant;q=0.9"),
            ("zh-Hans", "zh-CN,zh-Hans;q=0.9"),
            ("zh-Hans-CN", "zh-CN,zh-Hans;q=0.9"),
            ("zh-TW", "zh-TW,zh-Hant;q=0.9"),
            ("zh-HK", "zh-HK,zh-Hant;q=0.9"),
            ("zh-CN", "zh-CN,zh-Hans;q=0.9"),
            ("zh", "zh-CN,zh-Hans;q=0.9"),
            ("sw-KE", "sw,en-US;q=0.9,en;q=0.8"),
            ("sw", "sw,en-US;q=0.9,en;q=0.8"),
            ("eu-ES", "eu,en-US;q=0.9,en;q=0.8"),
            ("eu", "eu,en-US;q=0.9,en;q=0.8"),
            ("en-DE", "en-GB,en;q=0.9"),
            ("de-US", "de-DE,de;q=0.9"),
            ("fr-DE", "fr-FR,fr;q=0.9"),
        ],
    );
}

#[test]
fn chromium_expands_like_http_util() {
    // `net::HttpUtil::ExpandLanguageList`'s behaviour, from its source.
    for (input, expected) in [
        ("en-US", "en-US,en"),
        ("fr", "fr"),
        ("en-US,ja", "en-US,en,ja"),
        ("en-US,fr-FR,ja", "en-US,en,fr-FR,fr,ja"),
        ("en-US,en,fr", "en-US,en,fr"),
        ("en-US,fr,en", "en-US,en,fr"),
        ("x-1,i-1", "x-1,i-1"),
    ] {
        assert_eq!(
            expand_language_list(&split(input)).join(","),
            expected,
            "{input}"
        );
    }
}

#[test]
fn every_profile_defaults_to_its_list_for_en_us() {
    for name in BrowserProfile::names() {
        let profile = BrowserProfile::resolve(&name.name).unwrap();
        let header = profile
            .headers
            .iter()
            .find(|(name, _)| name == "accept-language")
            .map(|(_, value)| value.as_str());
        match header {
            Some(header) => assert_eq!(header, accept_language(&profile, "en-US"), "{}", name.name),
            None => assert!(profile.language_source.is_none(), "{}", name.name),
        }
    }
}

#[test]
fn a_profile_without_a_source_sends_the_language_as_given() {
    let profile = BrowserProfile::resolve("okhttp").unwrap();
    assert_eq!(accept_language(&profile, "de-AT"), "de-AT");
}

#[test]
fn language_sources_serialize_readably() {
    let json = serde_json::to_string(&[
        LanguageSource::UiTable(UiTable::Chromium),
        LanguageSource::Firefox { version: 158 },
        LanguageSource::Samsung,
    ])
    .unwrap();
    assert_eq!(
        json,
        r#"[{"ui_table":"chromium"},{"firefox":{"version":158}},"samsung"]"#
    );
}
