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
    const EMPTY: Self = Self {
        id: "",
        source: "",
        ja4: None,
        ja3n_hash: None,
        ja3_hash: None,
        akamai_hash: None,
        akamai_text: None,
        quic_ja4: None,
    };

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

// Every Chromium-based browser sends the same HTTP/2 fingerprint.
const CHROMIUM_AKAMAI_HASH: &str = "52d84b11737d980aef856699f885ca86";
const CHROMIUM_AKAMAI_TEXT: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
const FIREFOX_AKAMAI_HASH: &str = "6ea73faa8fc5aac76bded7bd238f6433";
const FIREFOX_AKAMAI_TEXT: &str = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s";

/// Chromium up to 134: the old ALPS codepoint 0x4469, no `trust_anchors`.
const CHROMIUM_OLD_ALPS: Reference = Reference {
    id: "chromium-old-alps",
    source: "Chromium 131-134 (ALPS codepoint 0x4469): real Chrome 131-134 captures",
    ja4: Some("t13d1516h2_8daaf6152771_02713d6af862"),
    ja3n_hash: Some("dee19b855b658c6aa0f575eda2525e19"),
    akamai_hash: Some(CHROMIUM_AKAMAI_HASH),
    akamai_text: Some(CHROMIUM_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Chromium 135-149 without `trust_anchors`: the new ALPS codepoint 0x44CD.
const CHROMIUM_NEW_ALPS: Reference = Reference {
    id: "chromium-new-alps",
    source: "Chromium 135-149 (ALPS codepoint 0x44CD): real Chrome 135-140, Chrome 135-149 \
             on Android, Edge and Opera 124-125 captures; Samsung Internet 29 and 30 (Chromium \
             136 and 143) on Android",
    ja4: Some("t13d1516h2_8daaf6152771_d8a2da3f94cd"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    akamai_hash: Some(CHROMIUM_AKAMAI_HASH),
    akamai_text: Some(CHROMIUM_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Chrome 152+ and Opera 136+: ML-DSA signature algorithms and `trust_anchors`.
const CHROMIUM_MLDSA_TRUST_ANCHORS: Reference = Reference {
    id: "chromium-mldsa-trust-anchors",
    source: "Chromium 152+ with trust_anchors (ML-DSA signature algorithms): real Chrome 153 \
             and Opera 136 captures, Chrome 152 and 154 on Android; Chrome 155 from \
             tls.browserleaks.com and a ClientHello capture",
    ja4: Some("t13d1517h2_8daaf6152771_cb7bf5808d99"),
    ja3n_hash: Some("bd4930bd9b000ee684830e44bab76fdf"),
    akamai_hash: Some(CHROMIUM_AKAMAI_HASH),
    akamai_text: Some(CHROMIUM_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Edge on Chromium 150+, Opera 134-135, Chrome 150-151 and Brave: ML-DSA without `trust_anchors`.
const CHROMIUM_MLDSA: Reference = Reference {
    id: "chromium-mldsa",
    source: "Chromium 150+ without trust_anchors (ML-DSA signature algorithms): real Opera \
             134-135 (JA4), Edge 152-154, Edge 153 and Chrome 150-151 on Android (JA4, JA3N, \
             Akamai) captures; desktop Chrome 151 and Edge 151 stable (koon 0.8.1); Brave \
             1.95.104 and 1.96.59 on Windows, 1.96.59 on Android",
    ja4: Some("t13d1516h2_8daaf6152771_806a8c22fdea"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    akamai_hash: Some(CHROMIUM_AKAMAI_HASH),
    akamai_text: Some(CHROMIUM_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Chrome 153's QUIC `ClientHello`, also Opera 136's (Chromium 152).
const CHROME_QUIC: Reference = Reference {
    id: "chrome-quic",
    source: "QUIC JA4 computed from the QUIC ClientHello of a real Chrome 153 \
             (tests/quic_initial.rs); Chrome 154 only sorts its trust anchor IDs; Chrome 155 \
             from quic.browserleaks.com and a QUIC capture; Chrome 154/155 and Opera \
             136.0.6008.52 on Linux and macOS from quic.browserleaks.com",
    quic_ja4: Some("q13d0312h3_55b375c5d22e_178839b6cec1"),
    ..Reference::EMPTY
};

/// Chrome 152+'s `ClientHello` plus `server_padding` (0x12E0), for a client that asks for it (see
/// [`verify_with`]).
const CHROME_SERVER_PADDING: Reference = Reference {
    id: "chrome-server-padding",
    source: "Chrome 152+ with trust_anchors and the server_padding extension of the \
             PqcBandwidthExperiment field trial: real Chrome 153.0.8010.52 and the 154 and 155 \
             betas on a Pixel 9 Pro XL with Android 17 (tls.browserleaks.com and ClientHello \
             captures)",
    ja4: Some("t13d1518h2_8daaf6152771_4980c97edce0"),
    ja3n_hash: Some("a3a3161a080b73bda9cc285fb367fcc0"),
    akamai_hash: Some(CHROMIUM_AKAMAI_HASH),
    akamai_text: Some(CHROMIUM_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Chrome 152+'s QUIC `ClientHello` plus `server_padding`.
const CHROME_QUIC_SERVER_PADDING: Reference = Reference {
    id: "chrome-quic-server-padding",
    source: "QUIC JA4 of real Chrome 153.0.8010.52 and the 152 and 155 betas on Android 17 \
             (quic.browserleaks.com)",
    quic_ja4: Some("q13d0313h3_55b375c5d22e_eb028bd37c08"),
    ..Reference::EMPTY
};

/// Chrome 134's QUIC `ClientHello`: the old ALPS codepoint, no `trust_anchors`.
const CHROME_QUIC_OLD_ALPS: Reference = Reference {
    id: "chrome-quic-old-alps",
    source: "QUIC JA4 of the real Chrome 134 beta on Android 17 (quic.browserleaks.com)",
    quic_ja4: Some("q13d0311h3_55b375c5d22e_5a1f323ef56d"),
    ..Reference::EMPTY
};

/// Opera for Android: Chromium 152 without `trust_anchors`, HTTP/2 `MAX_CONCURRENT_STREAMS` instead
/// of `ENABLE_PUSH`.
const OPERA_MOBILE: Reference = Reference {
    id: "opera-mobile",
    source: "Opera for Android 102.1.5206.90382 (Chromium 152.0.7977.82) on a Pixel 9 Pro XL \
             with Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1516h2_8daaf6152771_806a8c22fdea"),
    ja3n_hash: Some("8e19337e7524d2573be54efb2b0784c9"),
    akamai_hash: Some("4f04edce68a7ecbe689edce7bf5f23f3"),
    akamai_text: Some("1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"),
    ..Reference::EMPTY
};

/// The QUIC `ClientHello` of Chromium 135+ without `trust_anchors`: Chrome 135-151, Edge, Brave and
/// Opera for Android.
const CHROMIUM_QUIC_NO_TRUST_ANCHORS: Reference = Reference {
    id: "chromium-quic-no-trust-anchors",
    source: "QUIC JA4 of the real Chrome 135, 140, 141, 149, 150 and 151 betas on Android 17, \
             Edge 153 and 154 on Windows and macOS (154 also from quic.browserleaks.com), Edge \
             153 on Android and Brave 1.95.104 and 1.96.59 on Windows and 1.96.59 on Android; \
             Opera for Android 102 sent it with pre_shared_key and early_data in its resumed \
             hello (q13d0313h3_55b375c5d22e_226f3f127bbe), its full one was not captured",
    quic_ja4: Some("q13d0311h3_55b375c5d22e_653d80c3fe9d"),
    ..Reference::EMPTY
};

/// The references of a client that asks for server padding, which Chrome's `PqcBandwidthExperiment`
/// decides per client: the extension changes the JA4, the JA3N and the QUIC JA4.
const SERVER_PADDING_VARIANTS: &[(&Reference, &Reference)] = &[
    (&CHROMIUM_MLDSA_TRUST_ANCHORS, &CHROME_SERVER_PADDING),
    (&CHROME_QUIC, &CHROME_QUIC_SERVER_PADDING),
];

/// Firefox 135-150 (identical across these versions).
const FIREFOX_135: Reference = Reference {
    id: "firefox-135",
    source: "Firefox 135-150: real Firefox captures",
    ja4: Some("t13d1717h2_5b57614c22b0_3cbfd9057e0d"),
    ja3n_hash: Some("e4147a4860c1f347354f0a84d8787c02"),
    akamai_hash: Some(FIREFOX_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 151-153: ECDSA AES-128-CBC (0xc009) dropped.
const FIREFOX_151: Reference = Reference {
    id: "firefox-151",
    source: "Firefox 151-153 (without cipher 0xc009): real Firefox captures",
    ja4: Some("t13d1617h2_86a278354501_3cbfd9057e0d"),
    ja3n_hash: Some("8099457c290ccfe8c6d958826c26b023"),
    akamai_hash: Some(FIREFOX_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 154-155: ECDSA AES-256-CBC (0xc00a) dropped as well.
const FIREFOX_154: Reference = Reference {
    id: "firefox-154",
    source: "Firefox 154-155 (without cipher 0xc00a): JA3 and JA3N computed from real \
             Firefox 154.0 and 155.0 ClientHellos",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("1d9334692003212ed6c01718554b1b1c"),
    ja3_hash: Some("424f6d9c8b8928c0a0489a4f1a0f3e89"),
    akamai_hash: Some(FIREFOX_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 156 and 157: no finite-field groups.
const FIREFOX_156: Reference = Reference {
    id: "firefox-156",
    source: "Firefox 156-157 (without ffdhe groups): real Firefox 156.0.1 captures; 157 from \
             the 157.0 beta (ClientHello capture and tls.browserleaks.com)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("f9c6a2c424206e61efb6c1a6325596b5"),
    ja3_hash: Some("9d42e90b0225e779f03141ddcd699df2"),
    akamai_hash: Some(FIREFOX_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox's QUIC `ClientHello` without ML-DSA (155, 157; on Android 146 to 155 and 157).
const FIREFOX_QUIC: Reference = Reference {
    id: "firefox-quic",
    source: "QUIC JA4 of real Firefox 155.0.1 and 157.0 beta QUIC ClientHellos (157 also \
             from quic.browserleaks.com); on Android from the 146.0b9, 147.0b9, 150.0b10, 151.0b10, \
             153.0b13, 154.0b10, 155.0b5 and 157.0b5 betas (quic.browserleaks.com)",
    quic_ja4: Some("q13d0315h3_55b375c5d22e_dc5437974b47"),
    ..Reference::EMPTY
};

/// Firefox 156's QUIC `ClientHello`: ML-DSA signature algorithms.
const FIREFOX_156_QUIC: Reference = Reference {
    id: "firefox-156-quic",
    source: "QUIC JA4 computed from the QUIC ClientHello of a real Firefox 156 \
             (tests/quic_initial.rs); on Android from 156.0.1 and the 156.0b5 beta \
             (quic.browserleaks.com)",
    quic_ja4: Some("q13d0315h3_55b375c5d22e_bb76f32061e3"),
    ..Reference::EMPTY
};

// Firefox on Android: the TLS of desktop Firefox of the same version (up to 154 without
// signed_certificate_timestamp), smaller HTTP/2 windows. Captured on a Pixel 9 Pro XL with Android
// 17.
const FIREFOX_ANDROID_AKAMAI_HASH: &str = "41a06cadb1c6385e6d08c8d0dbbea818";
const FIREFOX_ANDROID_AKAMAI_TEXT: &str = "1:4096;2:0;4:32768;5:16384|12517377|0|m,p,a,s";

/// Firefox 146-150 on Android: desktop's `ClientHello`, without SCT.
const FIREFOX_ANDROID_146: Reference = Reference {
    id: "firefox-android-146",
    source: "Firefox 146-150 on Android (without signed_certificate_timestamp): real 146.0b9, \
             147.0b9 and 150.0b10 betas on Android 17 (tls.browserleaks.com and ClientHello \
             captures)",
    ja4: Some("t13d1716h2_5b57614c22b0_eeeea6562960"),
    ja3n_hash: Some("90634f51dcf65fc506946108904d6913"),
    ja3_hash: Some("2d692a4485ca2f5f2b10ecb2d2909ad3"),
    akamai_hash: Some(FIREFOX_ANDROID_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_ANDROID_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 151-153 on Android: without 0xc009 and without SCT.
const FIREFOX_ANDROID_151: Reference = Reference {
    id: "firefox-android-151",
    source: "Firefox 151-153 on Android (without cipher 0xc009 and signed_certificate_timestamp): \
             real 151.0b10 and 153.0b13 betas on Android 17 (tls.browserleaks.com and ClientHello \
             captures)",
    ja4: Some("t13d1616h2_86a278354501_eeeea6562960"),
    ja3n_hash: Some("9fdfb10f9cb8fce80779f8ffb5a34f4a"),
    ja3_hash: Some("c43da27af379abb70ab285d8ef656f71"),
    akamai_hash: Some(FIREFOX_ANDROID_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_ANDROID_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 154 on Android: 0xc00a dropped as well.
const FIREFOX_ANDROID_154: Reference = Reference {
    id: "firefox-android-154",
    source: "Firefox 154 on Android (without cipher 0xc00a and signed_certificate_timestamp): \
             real 154.0b10 beta on Android 17 (tls.browserleaks.com and ClientHello capture)",
    ja4: Some("t13d1516h2_8daaf6152771_eeeea6562960"),
    ja3n_hash: Some("8c3237398318fb048d0bc301bc804de5"),
    ja3_hash: Some("a1d7243639bf3eccacd288639c620582"),
    akamai_hash: Some(FIREFOX_ANDROID_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_ANDROID_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 155 on Android: `signed_certificate_timestamp`, desktop Firefox 155's `ClientHello`.
const FIREFOX_ANDROID_155: Reference = Reference {
    id: "firefox-android-155",
    source: "Firefox 155 on Android (signed_certificate_timestamp from 155 on): real 155.0b5 \
             beta on Android 17 (tls.browserleaks.com and ClientHello capture)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("1d9334692003212ed6c01718554b1b1c"),
    ja3_hash: Some("424f6d9c8b8928c0a0489a4f1a0f3e89"),
    akamai_hash: Some(FIREFOX_ANDROID_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_ANDROID_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Firefox 156 and 157 on Android: no finite-field groups, desktop Firefox 156's `ClientHello`.
const FIREFOX_ANDROID_156: Reference = Reference {
    id: "firefox-android-156",
    source: "Firefox 156-157 on Android (without ffdhe groups): real 156.0.1, 156.0b5 and \
             157.0b5 on Android 17 (tls.browserleaks.com and ClientHello captures)",
    ja4: Some("t13d1517h2_8daaf6152771_3cbfd9057e0d"),
    ja3n_hash: Some("f9c6a2c424206e61efb6c1a6325596b5"),
    ja3_hash: Some("9d42e90b0225e779f03141ddcd699df2"),
    akamai_hash: Some(FIREFOX_ANDROID_AKAMAI_HASH),
    akamai_text: Some(FIREFOX_ANDROID_AKAMAI_TEXT),
    ..Reference::EMPTY
};

// Safari's fingerprint comes from the OS network stack (see `profile::safari`). Up to macOS 15 and
// iOS 18 JA3 and JA3N, which leave out the signature algorithms, are the same.
const SAFARI_JA3N: &str = "44f7ed5185d22c92b96da72dbe68d307";
const SAFARI_JA3: &str = "773906b0efdefa24a7f2b8eb6985bf37";
// The TLS of macOS 14 and iOS 17, with ecdsa_sha1 (up to macOS 15.1 and iOS 18.1), and of macOS 15
// and iOS 18 without it.
const SAFARI_SHA1_JA4: &str = "t13d2014h2_a09f3c656075_14788d8d241b";
const SAFARI_SEQUOIA_JA4: &str = "t13d2014h2_a09f3c656075_e42f34c56612";
// From macOS 15.4 and iOS 18.4 on.
const SAFARI_AKAMAI_HASH: &str = "c52879e43202aeb92740be6e8c86ea96";
const SAFARI_AKAMAI_TEXT: &str = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p";
// Up to macOS 15.2 and iOS 18.3: ENABLE_CONNECT_PROTOCOL as well.
const SAFARI_CONNECT_AKAMAI_HASH: &str = "d4a2dcbfde511b5040ed5a5190a8d78b";
const SAFARI_CONNECT_AKAMAI_TEXT: &str = "2:0;3:100;4:2097152;8:1;9:1|10420225|0|m,s,a,p";

/// Safari on macOS 12 and 13: the TLS of macOS 14 (same JA4/JA3/JA3N), but no
/// `SETTINGS_ENABLE_PUSH` at all (macOS 14 sends `2:0`).
pub(crate) const SAFARI_MACOS_12_13: Reference = Reference {
    id: "safari-macos12-13",
    source: "Safari on macOS 12 and 13 (ecdsa_sha1, no SETTINGS_ENABLE_PUSH): real Safari \
             15.6 on macOS 12.5, 16.0 (Safari16.0MontereyAuto.pkg, Apple-signed) and 15.6.1 on \
             macOS 12.6, and 16.1 on macOS 13.0",
    ja4: Some(SAFARI_SHA1_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some("dda308d35f4e5db7b52a61720ca1b122"),
    akamai_text: Some("4:4194304;3:100|10485760|0|m,s,p,a"),
    ..Reference::EMPTY
};

/// Safari on macOS 14 and 15.0: TLS 1.0-1.3, `ecdsa_sha1`, 4 MB HTTP/2 window.
pub(crate) const SAFARI_MACOS_14: Reference = Reference {
    id: "safari-macos14",
    source: "Safari on macOS 14 and 15.0 (ecdsa_sha1, 4 MB HTTP/2 window): real Safari 17.6 on \
             macOS 14.6, 18.0 on macOS 14.7 and 15.0, and Safari 26.6 on macOS 14.8.9",
    ja4: Some(SAFARI_SHA1_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some("959a7e813b79b909a1a0b00a38e8bba3"),
    akamai_text: Some("2:0;4:4194304;3:100|10485760|0|m,s,p,a"),
    ..Reference::EMPTY
};

/// Safari on iOS 16.0 and 16.1: the TLS of iOS 17 (ecdsa_sha1, 2 MB HTTP/2 window), but no
/// `SETTINGS_ENABLE_PUSH` at all (like macOS 12 and 13): iOS 17 sends `2:0`.
pub(crate) const SAFARI_IOS_16: Reference = Reference {
    id: "safari-ios16",
    source: "Safari on iOS 16.0 and 16.1 (ecdsa_sha1, no SETTINGS_ENABLE_PUSH): real Safari on \
             the iOS 16.0 (20A360) and 16.1 (20B72) simulators",
    ja4: Some(SAFARI_SHA1_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some("d5fcbdc393757341115a861bf8d23265"),
    akamai_text: Some("4:2097152;3:100|10485760|0|m,s,p,a"),
    ..Reference::EMPTY
};

/// Safari on iOS 17: the TLS of macOS 14, a 2 MB HTTP/2 stream window.
pub(crate) const SAFARI_IOS_17: Reference = Reference {
    id: "safari-ios17",
    source: "Safari on iOS 17 (ecdsa_sha1, 2 MB HTTP/2 window): real Safari on the iOS \
             17.0.1 and 17.5 simulators",
    ja4: Some(SAFARI_SHA1_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some("ad8424af1cc590e09f7b0c499bf7fcdb"),
    akamai_text: Some("2:0;4:2097152;3:100|10485760|0|m,s,p,a"),
    ..Reference::EMPTY
};

/// Safari on macOS 15.1 and iOS 18.0-18.1: macOS 14's TLS, HTTP/2 with `ENABLE_CONNECT_PROTOCOL`.
pub(crate) const SAFARI_15_1: Reference = Reference {
    id: "safari-15.1",
    source: "Safari on macOS 15.1 and iOS 18.0-18.1 (ecdsa_sha1, ENABLE_CONNECT_PROTOCOL): \
             real Safari 18.1.1 on macOS 15.1.1 and the iOS 18.0 and 18.1 simulators",
    ja4: Some(SAFARI_SHA1_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some(SAFARI_CONNECT_AKAMAI_HASH),
    akamai_text: Some(SAFARI_CONNECT_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Safari on macOS 15.2 and iOS 18.2-18.3: without `ecdsa_sha1`, still `ENABLE_CONNECT_PROTOCOL`.
pub(crate) const SAFARI_15_2: Reference = Reference {
    id: "safari-15.2",
    source: "Safari on macOS 15.2 and iOS 18.2-18.3 (ENABLE_CONNECT_PROTOCOL): real Safari \
             18.2 on macOS 15.2 and the iOS 18.2 and 18.3.1 simulators",
    ja4: Some(SAFARI_SEQUOIA_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some(SAFARI_CONNECT_AKAMAI_HASH),
    akamai_text: Some(SAFARI_CONNECT_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Safari on macOS 15.4 to 15.7 and iOS 18.4 and 18.5.
pub(crate) const SAFARI_15_4: Reference = Reference {
    id: "safari-15.4",
    source: "Safari on macOS 15.4-15.8 and iOS 18.4-18.5: real Safari 18.4 and 18.5 on macOS \
             15.4 and 15.5, 18.6 on macOS 15.6.1 and 15.8, 26.0.1 on macOS 15.7, 26.6.1 on macOS \
             15.7.9, and the iOS 18.4 and 18.5 simulators",
    ja4: Some(SAFARI_SEQUOIA_JA4),
    ja3n_hash: Some(SAFARI_JA3N),
    ja3_hash: Some(SAFARI_JA3),
    akamai_hash: Some(SAFARI_AKAMAI_HASH),
    akamai_text: Some(SAFARI_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Safari from macOS/iOS 26 on: X25519MLKEM768, AES-256 first, only TLS 1.2/1.3.
pub(crate) const SAFARI_26: Reference = Reference {
    id: "safari-26",
    source: "Safari on macOS and iOS 26 and 27 (X25519MLKEM768): real Safari 26.1 to 26.5, \
             26.6.2 and 27.0 on macOS 26.1 to 27.0, and the iOS 26.0 to 27.0 simulators",
    ja4: Some("t13d2013h2_a09f3c656075_7f0f34a4126d"),
    ja3n_hash: Some("63eaa93caec132011d68ceb96955c1ee"),
    ja3_hash: Some("ecdf4f49dd59effc439639da29186671"),
    akamai_hash: Some(SAFARI_AKAMAI_HASH),
    akamai_text: Some(SAFARI_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// Safari's QUIC `ClientHello` with `ecdsa_sha1`: macOS 14/15.0 and iOS 17 (and macOS 15.1, reached
/// only through the DNS HTTPS record).
pub(crate) const SAFARI_QUIC_SHA1: Reference = Reference {
    id: "safari-quic-sha1",
    source: "QUIC JA4 of real Safari 17.6 on macOS 14.6, 18.0 on macOS 14.7 and 15.0, and the \
             iOS 17.0.1 and 17.5 simulators",
    quic_ja4: Some("q13d0311h3_55b375c5d22e_0e9637bee5d3"),
    ..Reference::EMPTY
};

/// Safari's QUIC `ClientHello` without `ecdsa_sha1`, from macOS 15.2/iOS 18.3 on.
pub(crate) const SAFARI_QUIC: Reference = Reference {
    id: "safari-quic",
    source: "QUIC JA4 of real Safari on macOS 15.2 to 27.0 and the iOS 18.3.1 to 27.0 \
             simulators",
    quic_ja4: Some("q13d0311h3_55b375c5d22e_f2a83c8e78ae"),
    ..Reference::EMPTY
};

// OkHttp: Conscrypt's ClientHello (fixed extension order, no GREASE, JA3 exact) with OkHttp's
// cipher suites; 4 and 5 differ only in cipher order.
const OKHTTP_JA4: &str = "t13d1513h2_8daaf6152771_eca864cca44a";
const OKHTTP_AKAMAI_HASH: &str = "605a1154008045d7e3cb3c6fb062c0ce";
const OKHTTP_AKAMAI_TEXT: &str = "4:16777216|16711681|0|m,p,a,s";

/// `OkHttp` 4: Conscrypt's cipher order.
const OKHTTP_4: Reference = Reference {
    id: "okhttp4",
    source: "OkHttp 4.12.0 (default OkHttpClient) on a Pixel 9 Pro XL with Android 17 \
             (tls.browserleaks.com and ClientHello captures)",
    ja4: Some(OKHTTP_JA4),
    ja3n_hash: Some("b6c462146270c94ed8e339bcf4fff25f"),
    ja3_hash: Some("f79b6bad2ad0641e1921aef10262856b"),
    akamai_hash: Some(OKHTTP_AKAMAI_HASH),
    akamai_text: Some(OKHTTP_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// `OkHttp` 5: the cipher order of its connection spec.
const OKHTTP_5: Reference = Reference {
    id: "okhttp5",
    source: "OkHttp 5.5.0 (default OkHttpClient) on a Pixel 9 Pro XL with Android 17 \
             (tls.browserleaks.com and ClientHello captures)",
    ja4: Some(OKHTTP_JA4),
    ja3n_hash: Some("ab22845823d9af0946cb87050d0a5679"),
    ja3_hash: Some("1d714db2228763eab228fc28ce7f8e4f"),
    akamai_hash: Some(OKHTTP_AKAMAI_HASH),
    akamai_text: Some(OKHTTP_AKAMAI_TEXT),
    ..Reference::EMPTY
};

/// A version as `(major, minor)`: `154` -> `(154, 0)`, `26.6` -> `(26, 6)`.
type Version = (u32, u32);

fn parse_version(version: &str) -> Option<Version> {
    let (major, minor) = version.split_once('.').unwrap_or((version, "0"));
    Some((major.parse().ok()?, minor.parse().ok()?))
}

const DESKTOP: &[Os] = &[Os::Windows, Os::MacOS, Os::Linux];
const CHROME_OS: &[Os] = &[Os::Windows, Os::MacOS, Os::Linux, Os::Android];
/// Edge's desktop references cover Edge on Android too: Chromium on Android sends the desktop
/// `ClientHello`.
const EDGE_OS: &[Os] = &[Os::Windows, Os::MacOS, Os::Android];
const BRAVE_OS: &[Os] = &[Os::Windows, Os::MacOS, Os::Linux, Os::Android];

/// Where a reference applies: a browser's versions `from..=to` on `os`.
struct Coverage {
    browser: Browser,
    from: Version,
    to: Version,
    os: &'static [Os],
    reference: &'static Reference,
}

const fn covers(
    browser: Browser,
    from: Version,
    to: Version,
    os: &'static [Os],
    reference: &'static Reference,
) -> Coverage {
    Coverage {
        browser,
        from,
        to,
        os,
        reference,
    }
}

/// Which reference applies where, for every browser but Safari (its `SAFARI_VERSIONS` table
/// carries its own references, one per release; see [`references_for`]).
///
/// Ranges end at the last version whose fingerprint was verified, so a newly added browser version
/// has no reference until its fingerprint is captured and the range extended (the unit tests list
/// every profile without one). A client in the `PqcBandwidthExperiment` field trial is compared
/// with [`SERVER_PADDING_VARIANTS`] instead.
const COVERAGE: &[Coverage] = &[
    covers(
        Browser::Chrome,
        (131, 0),
        (134, 0),
        CHROME_OS,
        &CHROMIUM_OLD_ALPS,
    ),
    covers(
        Browser::Chrome,
        (135, 0),
        (149, 0),
        CHROME_OS,
        &CHROMIUM_NEW_ALPS,
    ),
    covers(
        Browser::Chrome,
        (150, 0),
        (151, 0),
        CHROME_OS,
        &CHROMIUM_MLDSA,
    ),
    covers(
        Browser::Chrome,
        (152, 0),
        (155, 0),
        CHROME_OS,
        &CHROMIUM_MLDSA_TRUST_ANCHORS,
    ),
    covers(
        Browser::Chrome,
        (134, 0),
        (134, 0),
        CHROME_OS,
        &CHROME_QUIC_OLD_ALPS,
    ),
    covers(
        Browser::Chrome,
        (135, 0),
        (151, 0),
        CHROME_OS,
        &CHROMIUM_QUIC_NO_TRUST_ANCHORS,
    ),
    covers(Browser::Chrome, (152, 0), (155, 0), CHROME_OS, &CHROME_QUIC),
    covers(Browser::Firefox, (135, 0), (150, 0), DESKTOP, &FIREFOX_135),
    covers(Browser::Firefox, (151, 0), (153, 0), DESKTOP, &FIREFOX_151),
    covers(Browser::Firefox, (154, 0), (155, 0), DESKTOP, &FIREFOX_154),
    covers(Browser::Firefox, (155, 0), (155, 0), DESKTOP, &FIREFOX_QUIC),
    covers(Browser::Firefox, (156, 0), (157, 0), DESKTOP, &FIREFOX_156),
    covers(
        Browser::Firefox,
        (156, 0),
        (156, 0),
        DESKTOP,
        &FIREFOX_156_QUIC,
    ),
    covers(Browser::Firefox, (157, 0), (157, 0), DESKTOP, &FIREFOX_QUIC),
    covers(
        Browser::Firefox,
        (146, 0),
        (150, 0),
        &[Os::Android],
        &FIREFOX_ANDROID_146,
    ),
    covers(
        Browser::Firefox,
        (151, 0),
        (153, 0),
        &[Os::Android],
        &FIREFOX_ANDROID_151,
    ),
    covers(
        Browser::Firefox,
        (154, 0),
        (154, 0),
        &[Os::Android],
        &FIREFOX_ANDROID_154,
    ),
    covers(
        Browser::Firefox,
        (155, 0),
        (155, 0),
        &[Os::Android],
        &FIREFOX_ANDROID_155,
    ),
    covers(
        Browser::Firefox,
        (156, 0),
        (157, 0),
        &[Os::Android],
        &FIREFOX_ANDROID_156,
    ),
    covers(
        Browser::Firefox,
        (146, 0),
        (155, 0),
        &[Os::Android],
        &FIREFOX_QUIC,
    ),
    covers(
        Browser::Firefox,
        (156, 0),
        (156, 0),
        &[Os::Android],
        &FIREFOX_156_QUIC,
    ),
    covers(
        Browser::Firefox,
        (157, 0),
        (157, 0),
        &[Os::Android],
        &FIREFOX_QUIC,
    ),
    covers(
        Browser::Edge,
        (131, 0),
        (134, 0),
        EDGE_OS,
        &CHROMIUM_OLD_ALPS,
    ),
    covers(
        Browser::Edge,
        (135, 0),
        (149, 0),
        EDGE_OS,
        &CHROMIUM_NEW_ALPS,
    ),
    covers(Browser::Edge, (150, 0), (154, 0), EDGE_OS, &CHROMIUM_MLDSA),
    covers(
        Browser::Edge,
        (153, 0),
        (154, 0),
        EDGE_OS,
        &CHROMIUM_QUIC_NO_TRUST_ANCHORS,
    ),
    covers(
        Browser::Opera,
        (124, 0),
        (133, 0),
        DESKTOP,
        &CHROMIUM_NEW_ALPS,
    ),
    covers(Browser::Opera, (134, 0), (135, 0), DESKTOP, &CHROMIUM_MLDSA),
    covers(
        Browser::Opera,
        (136, 0),
        (136, 0),
        DESKTOP,
        &CHROMIUM_MLDSA_TRUST_ANCHORS,
    ),
    covers(Browser::Opera, (136, 0), (136, 0), DESKTOP, &CHROME_QUIC),
    covers(
        Browser::Brave,
        (153, 0),
        (154, 0),
        BRAVE_OS,
        &CHROMIUM_MLDSA,
    ),
    covers(
        Browser::Brave,
        (153, 0),
        (154, 0),
        BRAVE_OS,
        &CHROMIUM_QUIC_NO_TRUST_ANCHORS,
    ),
    covers(
        Browser::Samsung,
        (29, 0),
        (30, 0),
        &[Os::Android],
        &CHROMIUM_NEW_ALPS,
    ),
    covers(
        Browser::OperaMobile,
        (102, 0),
        (102, 0),
        &[Os::Android],
        &OPERA_MOBILE,
    ),
    covers(
        Browser::OperaMobile,
        (102, 0),
        (102, 0),
        &[Os::Android],
        &CHROMIUM_QUIC_NO_TRUST_ANCHORS,
    ),
    covers(Browser::OkHttp, (4, 0), (4, 0), &[Os::Android], &OKHTTP_4),
    covers(Browser::OkHttp, (5, 0), (5, 0), &[Os::Android], &OKHTTP_5),
];

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
    "chrome134-android",
    "chrome135-android",
    "chrome141-android",
    "chrome149-android",
    "chrome150-android",
    "chrome151-android",
    "chrome152-android",
    "chrome155-android",
    "firefox135-windows",
    "firefox147-windows",
    "firefox150-windows",
    "firefox151-windows",
    "firefox153-windows",
    "firefox154-windows",
    "firefox155-windows",
    "firefox156-windows",
    "firefox157-windows",
    "firefox146-android",
    "firefox150-android",
    "firefox151-android",
    "firefox153-android",
    "firefox154-android",
    "firefox155-android",
    "firefox156-android",
    "firefox157-android",
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
    "edge153-android",
    "brave153-windows",
    "brave154-windows",
    "brave154-android",
    "samsung29-android",
    "samsung30-android",
    "opera-mobile102-android",
    "opera124-windows",
    "opera125-windows",
    "opera133-windows",
    "opera134-windows",
    "opera135-windows",
    "opera136-windows",
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
